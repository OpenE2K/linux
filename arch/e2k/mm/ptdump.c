/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/efi.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/ptdump.h>

#include <asm/ptdump.h>
#include <linux/pgtable.h>
#include <asm/pgtable_def.h>
#include <asm/pv_info.h>
#ifdef CONFIG_KASAN
#include <asm/kasan.h>
#endif

#define pt_dump_seq_printf(m, fmt, args...)	\
({						\
	if (m)					\
		seq_printf(m, fmt, ##args);	\
})

#define pt_dump_seq_puts(m, fmt)	\
({					\
	if (m)				\
		seq_printf(m, fmt);	\
})

/*
 * The page dumper groups page table entries of the same type into a single
 * description. It uses pg_state to track the range information while
 * iterating over the pte entries. When the continuity is broken it then
 * dumps out a description of the range.
 */
struct pg_state {
	struct ptdump_state ptdump;
	struct seq_file *seq;
	const struct addr_marker *marker;
	unsigned long start_address;
	unsigned long start_pa;
	unsigned long last_pa;
	int level;
	u64 current_prot;
	bool check_wx;
	unsigned long wx_pages;
};

/* Address marker */
struct addr_marker {
	unsigned long start_address;
	const char *name;
};

/* Private information for debugfs */
struct ptd_mm_info {
	struct mm_struct		*mm;
	const struct addr_marker	*markers;
	unsigned long base_addr;
	unsigned long end;
};

#define MS_NR	1
#define ME_NR	2
#define KIS_NR	3
#define KIE_NR	4
static struct addr_marker address_markers[] = {
	{NATIVE_KERNEL_VIRTUAL_SPACE_BASE, "Kernel address space"},
	[MS_NR] = {0,			"Modules start"},
	[ME_NR] = {0,			"Modules end"},
	[KIS_NR] = {0,			"Kernel Image start"},
	[KIE_NR] = {0,			"Kernel_Image end"},
	{NATIVE_VMALLOC_START,		"vmalloc() area"},
	{NATIVE_VMALLOC_END,		"vmalloc() end"},
	{NATIVE_VMALLOC_END,		"vmemmap start"},
	{NATIVE_VMEMMAP_END,		"vmemmap end"},
#ifdef CONFIG_KASAN
	{KASAN_SHADOW_START, "Kasan shadow start"},
	{KASAN_SHADOW_END, "Kasan shadow end"},
#endif
	{E2K_KERNEL_IO_BIOS_AREAS_BASE, "IO BIOS area start"},
	{E2K_KERNEL_IO_BIOS_AREAS_END,	"IO BIOS area end"},
	{-1, NULL},
};

static struct ptd_mm_info kernel_ptd_info = {
	.mm		= &init_mm,
	.markers	= address_markers,
	.base_addr	= NATIVE_KERNEL_VIRTUAL_SPACE_BASE,
	.end		= KERNEL_VPTB_BASE_ADDR,
};


/* Page Table Entry */
struct prot_bits {
	u64 mask;
	const char *set;
	const char *clear;
};

static struct prot_bits pte_bits[] = {
	{
		.mask = UNI_PAGE_VALID,
		.set = "V",
		.clear = ".",
	}, {
		.mask = UNI_PAGE_DIRTY,
		.set = "D",
		.clear = ".",
	}, {
		.mask = UNI_PAGE_ACCESSED,
		.set = "A",
		.clear = ".",
	}, {
		.mask = UNI_PAGE_PRIV,
		.set = "pP",
		.clear = ",,",
	}, {
		.mask = UNI_PAGE_NWA,
		.set = "nA",
		.clear = ",,",
	}, {
		.mask = UNI_PAGE_NON_EX,
		.set = "nX",
		.clear = ",,",
	}, {
		.mask = UNI_PAGE_WRITE,
		.set = "W",
		.clear = ".",
	}, {
		.mask = UNI_PAGE_PROTECT,
		.set = "pR",
		.clear = ",,",
	}, {
		.mask = UNI_PAGE_PRESENT,
		.set = "P",
		.clear = ".",
	}
};

/* Page Level */
struct pg_level {
	const char *name;
	u64 mask;
};

static struct pg_level pg_level[] = {
	{ /* pgd */
		.name = "PGD",
	}, { /* p4d */
		.name = (CONFIG_PGTABLE_LEVELS > 4) ? "P4D" : "PGD",
	}, { /* pud */
		.name = (CONFIG_PGTABLE_LEVELS > 3) ? "PUD" : "PGD",
	}, { /* pmd */
		.name = (CONFIG_PGTABLE_LEVELS > 2) ? "PMD" : "PGD",
	}, { /* pte */
		.name = "PTE",
	},
};

static void dump_prot(struct pg_state *st)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(pte_bits); i++) {
		const char *s = NULL;

		if ((st->current_prot & pte_bits[i].mask) == pte_bits[i].mask)
			s = pte_bits[i].set;
		else
			s = pte_bits[i].clear;

		if (s)
			pt_dump_seq_printf(st->seq, "%s", s);
	}
}

#define ADDR_FORMAT	"%#016lx"
static void dump_addr(struct pg_state *st, unsigned long addr)
{
	static const char units[] = "KMGTPE";
	const char *unit = units;
	unsigned long delta;

	pt_dump_seq_printf(st->seq, ADDR_FORMAT "-" ADDR_FORMAT "   ",
			   st->start_address, addr);

	pt_dump_seq_printf(st->seq, " " ADDR_FORMAT " ", st->start_pa);
	delta = (addr - st->start_address) >> 10;

	while (!(delta & 1023) && unit[1]) {
		delta >>= 10;
		unit++;
	}

	pt_dump_seq_printf(st->seq, "%9lu%c %s ", delta, *unit,
			   pg_level[st->level].name);
}

static void note_prot_wx(struct pg_state *st, unsigned long addr)
{
	if (!st->check_wx) {
		return;
	}
	if (!(_PAGE_TEST_WRITEABLE(st->current_prot))) {
		return;
	}
	if (_PAGE_TEST_NOT_EXEC(st->current_prot)) {
		return;
	}
	pr_warn("e2k/mm: Found insecure W+X mapping at address %pS. prot = %#llx\n",
		  (void *)st->start_address, st->current_prot);

	st->wx_pages += (addr - st->start_address) / PAGE_SIZE;
}

static void note_page(struct ptdump_state *pt_st, unsigned long addr,
		      int level, u64 val)
{
	struct pg_state *st = container_of(pt_st, struct pg_state, ptdump);
	u64 pa = _PAGE_PFN_TO_PADDR(val);
	u64 prot = 0;

	if (level >= 0)
		prot = val & pg_level[level].mask;

	if (st->level == -1) {
		st->level = level;
		st->current_prot = prot;
		st->start_address = addr;
		st->start_pa = pa;
		st->last_pa = pa;
		pt_dump_seq_printf(st->seq, "---[ %s ]---\n", st->marker->name);
	} else if (prot != st->current_prot ||
		   level != st->level || addr >= st->marker[1].start_address) {
		if (st->current_prot) {
			note_prot_wx(st, addr);
			dump_addr(st, addr);
			dump_prot(st);
			pt_dump_seq_puts(st->seq, "\n");
		}

		while (addr >= st->marker[1].start_address) {
			st->marker++;
			pt_dump_seq_printf(st->seq, "---[ %s ]---\n",
					   st->marker->name);
		}

		st->start_address = addr;
		st->start_pa = pa;
		st->last_pa = pa;
		st->current_prot = prot;
		st->level = level;
	} else {
		st->last_pa = pa;
	}
}

static void ptdump_walk(struct seq_file *s, struct ptd_mm_info *pinfo)
{
	struct pg_state st = {
		.seq = s,
		.marker = pinfo->markers,
		.level = -1,
		.ptdump = {
			.note_page = note_page,
			.range = (struct ptdump_range[]) {
				{pinfo->base_addr, pinfo->end},
				{0, 0}
			}
		}
	};

	ptdump_walk_pgd(&st.ptdump, pinfo->mm, NULL);
}

void ptdump_check_wx(void)
{
	struct pg_state st = {
		.seq = NULL,
		.marker = (struct addr_marker[]) {
			{0, NULL},
			{-1, NULL},
		},
		.level = -1,
		.check_wx = true,
		.ptdump = {
			.note_page = note_page,
			.effective_prot = NULL,
			.range = (struct ptdump_range[]) {
				{NATIVE_KERNEL_VIRTUAL_SPACE_BASE, KERNEL_VPTB_BASE_ADDR},
				{0, 0}
			}
		}
	};

	ptdump_walk_pgd(&st.ptdump, &init_mm, NULL);

	if (st.wx_pages)
		pr_warn("Checked W+X mappings: failed, %lu W+X pages found\n",
			st.wx_pages);
	else
		pr_info("Checked W+X mappings: passed, no W+X pages found\n");
}

static int ptdump_show(struct seq_file *m, void *v)
{
	ptdump_walk(m, m->private);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump);

static int __init ptdump_init(void)
{
	unsigned int i, j;

	/* Just because nitializers are not constants */
	address_markers[MS_NR].start_address = E2K_MODULES_START;
	address_markers[ME_NR].start_address = E2K_MODULES_END;
	address_markers[KIS_NR].start_address = KERNEL_BASE;
	address_markers[KIE_NR].start_address = KERNEL_END;

	pg_level[1].name = pgtable_l5_enabled ? "P4D" : "PGD";
	pg_level[2].name = pgtable_l4_enabled ? "PUD" : "PGD";

	for (j = 0; j < ARRAY_SIZE(pte_bits); j++) {
		switch (pte_bits[j].mask) {
		case UNI_PAGE_VALID:
			pte_bits[j].mask = _PAGE_INIT_VALID;
			break;
		case UNI_PAGE_DIRTY:
			pte_bits[j].mask = _PAGE_INIT_DIRTY;
			break;
		case UNI_PAGE_ACCESSED:
			pte_bits[j].mask = _PAGE_INIT_ACCESSED;
			break;
		case UNI_PAGE_PRIV:
			pte_bits[j].mask = _PAGE_INIT_PRIV;
			break;
		case UNI_PAGE_NWA:
			pte_bits[j].mask = _PAGE_INIT_NWA;
			break;
		case UNI_PAGE_NON_EX:
			pte_bits[j].mask = _PAGE_INIT_NOT_EXEC;
			break;
		case UNI_PAGE_WRITE:
			pte_bits[j].mask = _PAGE_INIT_WRITEABLE;
			break;
		case UNI_PAGE_PROTECT:
			pte_bits[j].mask = _PAGE_INIT_PROTECT;
			break;
		case UNI_PAGE_PRESENT:
			pte_bits[j].mask = _PAGE_INIT_PRESENT;
			break;
		default:
			pr_warn("Unknown pte bit %#llx\n", pte_bits[j].mask);
		}
	}

	for (i = 0; i < ARRAY_SIZE(pg_level); i++)
		for (j = 0; j < ARRAY_SIZE(pte_bits); j++)
			pg_level[i].mask |= pte_bits[j].mask;

	debugfs_create_file("kernel_page_tables", 0400, NULL, &kernel_ptd_info,
			    &ptdump_fops);

	return 0;
}

device_initcall(ptdump_init);
