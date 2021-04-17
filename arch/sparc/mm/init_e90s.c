/*
 *  arch/sparc64/mm/init.c
 *
 *  Copyright (C) 1996-1999 David S. Miller (davem@caip.rutgers.edu)
 *  Copyright (C) 1997-1999 Jakub Jelinek (jj@sunsite.mff.cuni.cz)
 */
 
#include <linux/extable.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/initrd.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/poison.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/cache.h>
#include <linux/sort.h>
#include <linux/percpu.h>
#include <linux/memblock.h>
#include <linux/mmzone.h>
#include <linux/gfp.h>

#include <asm/head.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/oplib.h>
#include <asm/iommu.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/mmu_context.h>
#include <asm/tlbflush.h>
#include <asm/dma.h>
#include <asm/starfire.h>
#include <asm/tlb.h>
#include <asm/spitfire.h>
#include <asm/sections.h>
#include <asm/tsb.h>
#include <asm/hypervisor.h>
#include <asm/prom.h>
#include <asm/mdesc.h>
#include <asm/cpudata.h>
#include <asm/irq.h>
#include <asm/bootinfo.h>
#include <asm/e90s.h>
#include <asm-l/pic.h>


#include "init_64.h"

unsigned long kern_linear_pte_xor[4] __read_mostly;

#ifndef CONFIG_DEBUG_PAGEALLOC
/* A special kernel TSB for 4MB, 256MB, 2GB and 16GB linear mappings.
 * Space is allocated for this right after the trap table in
 * arch/sparc64/kernel/head.S
 */
extern struct tsb swapper_4m_tsb[KERNEL_TSB4M_NENTRIES];
#endif
extern struct tsb swapper_tsb[KERNEL_TSB_NENTRIES];

static unsigned long cpu_pgsz_mask;

/* Kernel physical address base and size in bytes.  */
unsigned long kern_base __read_mostly;
unsigned long kern_size __read_mostly;

/* Initial ramdisk setup */
extern unsigned long sparc_ramdisk_image64;
extern unsigned int sparc_ramdisk_image;
extern unsigned int sparc_ramdisk_size;

struct page *mem_map_zero __read_mostly;
EXPORT_SYMBOL(mem_map_zero);

unsigned int sparc64_highest_unlocked_tlb_ent __read_mostly;

unsigned long sparc64_kern_pri_context __read_mostly;
unsigned long sparc64_kern_pri_nuc_bits __read_mostly;
unsigned long sparc64_kern_sec_context __read_mostly;

int num_kernel_image_mappings;

#ifdef CONFIG_DEBUG_DCFLUSH
atomic_t dcpage_flushes = ATOMIC_INIT(0);
#ifdef CONFIG_SMP
atomic_t dcpage_flushes_xcall = ATOMIC_INIT(0);
#endif
#endif

inline void flush_dcache_page_impl(struct page *page)
{
	BUG_ON(tlb_type == hypervisor);
#ifdef CONFIG_DEBUG_DCFLUSH
	atomic_inc(&dcpage_flushes);
#endif

#ifdef DCACHE_ALIASING_POSSIBLE
	__flush_dcache_page(page_address(page),
			    ((tlb_type == spitfire) &&
			     page_mapping_file(page) != NULL));
#else
	if (page_mapping_file(page) != NULL &&
	    tlb_type == spitfire)
		__flush_icache_page(__pa(page_address(page)));
#endif
}

#define PG_dcache_dirty		PG_arch_1
#define PG_dcache_cpu_shift	32UL
#define PG_dcache_cpu_mask	\
	((1UL<<ilog2(roundup_pow_of_two(NR_CPUS)))-1UL)

#define dcache_dirty_cpu(page) \
	(((page)->flags >> PG_dcache_cpu_shift) & PG_dcache_cpu_mask)

static inline void set_dcache_dirty(struct page *page, int this_cpu)
{
	unsigned long mask = this_cpu;
	unsigned long non_cpu_bits;

	non_cpu_bits = ~(PG_dcache_cpu_mask << PG_dcache_cpu_shift);
	mask = (mask << PG_dcache_cpu_shift) | (1UL << PG_dcache_dirty);

	__asm__ __volatile__("1:\n\t"
			     "ldx	[%2], %%g7\n\t"
			     "and	%%g7, %1, %%g1\n\t"
			     "or	%%g1, %0, %%g1\n\t"
			     "casx	[%2], %%g7, %%g1\n\t"
			     "cmp	%%g7, %%g1\n\t"
#ifdef CONFIG_RMO
			     "membar    #StoreLoad | #StoreStore\n\t"
#endif /* CONFIG_RMO */
			     "bne,pn	%%xcc, 1b\n\t"
			     " nop"
			     : /* no outputs */
			     : "r" (mask), "r" (non_cpu_bits), "r" (&page->flags)
			     : "g1", "g7");
}

static inline void clear_dcache_dirty_cpu(struct page *page, unsigned long cpu)
{
	unsigned long mask = (1UL << PG_dcache_dirty);

	__asm__ __volatile__("! test_and_clear_dcache_dirty\n"
			     "1:\n\t"
			     "ldx	[%2], %%g7\n\t"
			     "srlx	%%g7, %4, %%g1\n\t"
			     "and	%%g1, %3, %%g1\n\t"
			     "cmp	%%g1, %0\n\t"
			     "bne,pn	%%icc, 2f\n\t"
			     " andn	%%g7, %1, %%g1\n\t"
			     "casx	[%2], %%g7, %%g1\n\t"
			     "cmp	%%g7, %%g1\n\t"
#ifdef CONFIG_RMO
			     "membar    #StoreLoad | #StoreStore\n\t"
#endif /* CONFIG_RMO */
			     "bne,pn	%%xcc, 1b\n\t"
			     " nop\n"
			     "2:"
			     : /* no outputs */
			     : "r" (cpu), "r" (mask), "r" (&page->flags),
			       "i" (PG_dcache_cpu_mask),
			       "i" (PG_dcache_cpu_shift)
			     : "g1", "g7");
}

static inline void tsb_insert(struct tsb *ent, unsigned long tag, unsigned long pte)
{
	unsigned long tsb_addr = (unsigned long) ent;

	if (tlb_type == cheetah_plus || tlb_type == hypervisor)
		tsb_addr = __pa(tsb_addr);

	__tsb_insert(tsb_addr, tag, pte);
}

unsigned long _PAGE_ALL_SZ_BITS __read_mostly;

static void flush_dcache(unsigned long pfn)
{
	struct page *page;

	page = pfn_to_page(pfn);
	if (page) {
		unsigned long pg_flags;

		pg_flags = page->flags;
		if (pg_flags & (1UL << PG_dcache_dirty)) {
			int cpu = ((pg_flags >> PG_dcache_cpu_shift) &
				   PG_dcache_cpu_mask);
			int this_cpu = get_cpu();

			/* This is just to optimize away some function calls
			 * in the SMP case.
			 */
			if (cpu == this_cpu)
				flush_dcache_page_impl(page);
			else
				smp_flush_dcache_page_impl(page, cpu);

			clear_dcache_dirty_cpu(page, cpu);

			put_cpu();
		}
	}
}

/* mm->context.lock must be held */
static void __update_mmu_tsb_insert(struct mm_struct *mm, unsigned long tsb_index,
				    unsigned long tsb_hash_shift, unsigned long address,
				    unsigned long tte)
{
	struct tsb *tsb = mm->context.tsb_block[tsb_index].tsb;
	unsigned long tag;

	if (unlikely(!tsb))
		return;

	tsb += ((address >> tsb_hash_shift) &
		(mm->context.tsb_block[tsb_index].tsb_nentries - 1UL));
	tag = (address >> 22UL);
	tsb_insert(tsb, tag, tte);
}

#ifdef CONFIG_HUGETLB_PAGE
static void __init add_huge_page_size(unsigned long size)
{
	unsigned int order;

	if (size_to_hstate(size))
		return;

	order = ilog2(size) - PAGE_SHIFT;
	hugetlb_add_hstate(order);
}

static int __init hugetlbpage_init(void)
{
	add_huge_page_size(1UL << HPAGE_64K_SHIFT);
	add_huge_page_size(1UL << HPAGE_SHIFT);
	add_huge_page_size(1UL << HPAGE_256MB_SHIFT);
	add_huge_page_size(1UL << HPAGE_2GB_SHIFT);

	return 0;
}

arch_initcall(hugetlbpage_init);

static void __init pud_huge_patch(void)
{
	struct pud_huge_patch_entry *p;
	unsigned long addr;

	p = &__pud_huge_patch;
	addr = p->addr;
	*(unsigned int *)addr = p->insn;

	__asm__ __volatile__("flush %0" : : "r" (addr));
}

static int __init setup_hugepagesz(char *string)
{
	unsigned long long hugepage_size;
	unsigned int hugepage_shift;
	unsigned short hv_pgsz_idx;
	unsigned int hv_pgsz_mask;
	int rc = 0;

	hugepage_size = memparse(string, &string);
	hugepage_shift = ilog2(hugepage_size);

	switch (hugepage_shift) {
	case HPAGE_16GB_SHIFT:
		hv_pgsz_mask = HV_PGSZ_MASK_16GB;
		hv_pgsz_idx = HV_PGSZ_IDX_16GB;
		pud_huge_patch();
		break;
	case HPAGE_2GB_SHIFT:
		hv_pgsz_mask = HV_PGSZ_MASK_2GB;
		hv_pgsz_idx = HV_PGSZ_IDX_2GB;
		break;
	case HPAGE_256MB_SHIFT:
		hv_pgsz_mask = HV_PGSZ_MASK_256MB;
		hv_pgsz_idx = HV_PGSZ_IDX_256MB;
		break;
	case HPAGE_SHIFT:
		hv_pgsz_mask = HV_PGSZ_MASK_4MB;
		hv_pgsz_idx = HV_PGSZ_IDX_4MB;
		break;
	case HPAGE_64K_SHIFT:
		hv_pgsz_mask = HV_PGSZ_MASK_64K;
		hv_pgsz_idx = HV_PGSZ_IDX_64K;
		break;
	default:
		hv_pgsz_mask = 0;
	}

	if ((hv_pgsz_mask & cpu_pgsz_mask) == 0U) {
		hugetlb_bad_size();
		pr_err("hugepagesz=%llu not supported by MMU.\n",
			hugepage_size);
		goto out;
	}

	add_huge_page_size(hugepage_size);
	rc = 1;

out:
	return rc;
}
__setup("hugepagesz=", setup_hugepagesz);
#endif	/* CONFIG_HUGETLB_PAGE */

void update_mmu_cache(struct vm_area_struct *vma, unsigned long address, pte_t *ptep)
{
	struct mm_struct *mm;
	unsigned long flags;
	bool is_huge_tsb;
	pte_t pte = *ptep;

	if (tlb_type != hypervisor) {
		unsigned long pfn = pte_pfn(pte);

		if (pfn_valid(pfn))
			flush_dcache(pfn);
	}

	mm = vma->vm_mm;

	/* Don't insert a non-valid PTE into the TSB, we'll deadlock.  */
	if (!pte_accessible(mm, pte))
		return;

	raw_spin_lock_irqsave(&mm->context.lock, flags);

	is_huge_tsb = false;
#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
	if (mm->context.hugetlb_pte_count || mm->context.thp_pte_count) {
		unsigned long hugepage_size = PAGE_SIZE;

		if (is_vm_hugetlb_page(vma))
			hugepage_size = huge_page_size(hstate_vma(vma));

		if (hugepage_size >= PUD_SIZE) {
			unsigned long mask = 0x1ffc00000UL;

			/* Transfer bits [32:22] from address to resolve
			 * at 4M granularity.
			 */
			pte_val(pte) &= ~mask;
			pte_val(pte) |= (address & mask);
		} else if (hugepage_size >= PMD_SIZE) {
			/* We are fabricating 8MB pages using 4MB
			 * real hw pages.
			 */
			pte_val(pte) |= (address & (1UL << REAL_HPAGE_SHIFT));
		}

		if (hugepage_size >= PMD_SIZE) {
			__update_mmu_tsb_insert(mm, MM_TSB_HUGE,
				REAL_HPAGE_SHIFT, address, pte_val(pte));
			is_huge_tsb = true;
		}
	}
#endif
	if (!is_huge_tsb)
		__update_mmu_tsb_insert(mm, MM_TSB_BASE, PAGE_SHIFT,
					address, pte_val(pte));

	raw_spin_unlock_irqrestore(&mm->context.lock, flags);
}

void flush_dcache_page(struct page *page)
{
	struct address_space *mapping;
	int this_cpu;

	if (tlb_type == hypervisor)
		return;

	/* Do not bother with the expensive D-cache flush if it
	 * is merely the zero page.  The 'bigcore' testcase in GDB
	 * causes this case to run millions of times.
	 */
	if (page == ZERO_PAGE(0))
		return;

	this_cpu = get_cpu();

	mapping = page_mapping_file(page);
	if (mapping && !mapping_mapped(mapping)) {
		int dirty = test_bit(PG_dcache_dirty, &page->flags);
		if (dirty) {
			int dirty_cpu = dcache_dirty_cpu(page);

			if (dirty_cpu == this_cpu)
				goto out;
			smp_flush_dcache_page_impl(page, dirty_cpu);
		}
		set_dcache_dirty(page, this_cpu);
	} else {
		/* We could delay the flush for the !page_mapping
		 * case too.  But that case is for exec env/arg
		 * pages and those are %99 certainly going to get
		 * faulted into the tlb (and thus flushed) anyways.
		 */
		flush_dcache_page_impl(page);
	}

out:
	put_cpu();
}
EXPORT_SYMBOL(flush_dcache_page);

void __kprobes flush_icache_range(unsigned long start, unsigned long end)
{
	/* Cheetah and Hypervisor platform cpus have coherent I-cache. */
	if (tlb_type == spitfire) {
		unsigned long kaddr;

		/* This code only runs on Spitfire cpus so this is
		 * why we can assume _PAGE_PADDR_4U.
		 */
		for (kaddr = start; kaddr < end; kaddr += PAGE_SIZE) {
			unsigned long paddr, mask = _PAGE_PADDR_4U;

			if (kaddr >= PAGE_OFFSET)
				paddr = kaddr & mask;
			else {
				pgd_t *pgdp = pgd_offset_k(kaddr);
				pud_t *pudp = pud_offset(pgdp, kaddr);
				pmd_t *pmdp = pmd_offset(pudp, kaddr);
				pte_t *ptep = pte_offset_kernel(pmdp, kaddr);

				paddr = pte_val(*ptep) & mask;
			}
			__flush_icache_page(paddr);
		}
	}
}
EXPORT_SYMBOL(flush_icache_range);

void mmu_info(struct seq_file *m)
{
	static const char *pgsz_strings[] = {
		"8K", "64K", "512K", "4MB", "32MB",
		"256MB", "2GB", "16GB",
	};
	int i, printed;

	if (tlb_type == cheetah)
		seq_printf(m, "MMU Type\t: Cheetah\n");
	else if (tlb_type == cheetah_plus)
		seq_printf(m, "MMU Type\t: Cheetah+\n");
	else if (tlb_type == spitfire)
		seq_printf(m, "MMU Type\t: Spitfire\n");
	else if (tlb_type == hypervisor)
		seq_printf(m, "MMU Type\t: Hypervisor (sun4v)\n");
	else
		seq_printf(m, "MMU Type\t: ???\n");

	seq_printf(m, "MMU PGSZs\t: ");
	printed = 0;
	for (i = 0; i < ARRAY_SIZE(pgsz_strings); i++) {
		if (cpu_pgsz_mask & (1UL << i)) {
			seq_printf(m, "%s%s",
				   printed ? "," : "", pgsz_strings[i]);
			printed++;
		}
	}
	seq_putc(m, '\n');

#ifdef CONFIG_DEBUG_DCFLUSH
	seq_printf(m, "DCPageFlushes\t: %d\n",
		   atomic_read(&dcpage_flushes));
#ifdef CONFIG_SMP
	seq_printf(m, "DCPageFlushesXC\t: %d\n",
		   atomic_read(&dcpage_flushes_xcall));
#endif /* CONFIG_SMP */
#endif /* CONFIG_DEBUG_DCFLUSH */
}

struct linux_prom_translation prom_trans[64] __read_mostly;
unsigned int prom_trans_ents __read_mostly;

unsigned long kern_locked_tte_data;

static int cmp_ptrans(const void *a, const void *b)
{
	const struct linux_prom_translation *x = a, *y = b;

	if (x->virt > y->virt)
		return 1;
	if (x->virt < y->virt)
		return -1;
	return 0;
}

#define BOOT_PAGE_SZ 0x400000
static void __init read_obp_translations(void)
{
	int i, j;
	struct boot_info *b = &bootblock->info;
	for (i = j = 0; i < b->num_of_busy; i++) {
		int n = b->busy[i].size / BOOT_PAGE_SZ, k;
		for (k = 0; k < n; k++) {
			if (WARN_ON(j + k == sizeof(prom_trans)))
				break;
			prom_trans[j + k].virt =
			    b->busy[i].address + k * BOOT_PAGE_SZ;
			prom_trans[j + k].size = BOOT_PAGE_SZ;
			prom_trans[j + k].data = prom_trans[j].virt
			    | _PAGE_VALID | _PAGE_SZ4MB_4U | _PAGE_CP_4U
			    | _PAGE_CV_4U | _PAGE_P_4U | _PAGE_W_4U;
		}
		j += k;
	}
	prom_trans_ents = j;
	sort(prom_trans, j, sizeof(prom_trans[0]), cmp_ptrans, NULL);
	for (i = 0; i < prom_trans_ents; i++) {
		unsigned long low_phys = prom_trans[0].virt;
		/*consider bootloader maps itself linearly */
		prom_trans[i].virt = LOW_OBP_ADDRESS - low_phys
		    + prom_trans[i].virt;
	}
}

static unsigned long kern_large_tte(unsigned long paddr);

static void __init remap_kernel(void)
{
	unsigned long phys_page, tte_vaddr, tte_data;
	int tlb_ent = sparc64_highest_locked_tlbent();

	tte_vaddr = (unsigned long) KERNBASE;
	phys_page = bootblock->info.kernel_base;
	tte_data = kern_large_tte(phys_page);

	kern_locked_tte_data = tte_data;

	sparc64_highest_unlocked_tlb_ent = tlb_ent - num_kernel_image_mappings;

	if (tlb_type == cheetah_plus) {
		sparc64_kern_pri_context = (CTX_CHEETAH_PLUS_CTX0 |
					    CTX_CHEETAH_PLUS_NUC);
		sparc64_kern_pri_nuc_bits = CTX_CHEETAH_PLUS_NUC;
		sparc64_kern_sec_context = CTX_CHEETAH_PLUS_CTX0;
	}
}


static void __init inherit_prom_mappings(void)
{
	/* Now fixup OBP's idea about where we really are mapped. */
	printk("Remapping the kernel... ");
	remap_kernel();
	printk("done.\n");
}

void prom_world(int enter)
{
	if (!enter)
		set_fs(get_fs());

	__asm__ __volatile__("flushw");
}

void __flush_dcache_range(unsigned long start, unsigned long end)
{
	unsigned long va;

	if (tlb_type == spitfire) {
		int n = 0;

		for (va = start; va < end; va += 32) {
			spitfire_put_dcache_tag(va & 0x3fe0, 0x0);
			if (++n >= 512)
				break;
		}
	} else if (tlb_type == cheetah || tlb_type == cheetah_plus) {
		start = __pa(start);
		end = __pa(end);
		for (va = start; va < end; va += 32)
			__asm__ __volatile__("stxa %%g0, [%0] %1\n\t"
					     "membar #Sync"
					     : /* no outputs */
					     : "r" (va),
					       "i" (ASI_DCACHE_INVALIDATE));
	}
}
EXPORT_SYMBOL(__flush_dcache_range);

/* get_new_mmu_context() uses "cache + 1".  */
DEFINE_RAW_SPINLOCK(ctx_alloc_lock);
unsigned long tlb_context_cache = CTX_FIRST_VERSION;
#define MAX_CTX_NR	(1UL << CTX_NR_BITS)
#define CTX_BMAP_SLOTS	BITS_TO_LONGS(MAX_CTX_NR)
DECLARE_BITMAP(mmu_context_bmap, MAX_CTX_NR);
DEFINE_PER_CPU(struct mm_struct *, per_cpu_secondary_mm) = {0};

static void mmu_context_wrap(void)
{
	unsigned long old_ver = tlb_context_cache & CTX_VERSION_MASK;
	unsigned long new_ver, new_ctx, old_ctx;
	struct mm_struct *mm;
	int cpu;

	bitmap_zero(mmu_context_bmap, 1 << CTX_NR_BITS);

	/* Reserve kernel context */
	set_bit(0, mmu_context_bmap);

	new_ver = (tlb_context_cache & CTX_VERSION_MASK) + CTX_FIRST_VERSION;
	if (unlikely(new_ver == 0))
		new_ver = CTX_FIRST_VERSION;
	tlb_context_cache = new_ver;

	/*
	 * Make sure that any new mm that are added into per_cpu_secondary_mm,
	 * are going to go through get_new_mmu_context() path.
	 */
	mb();

	/*
	 * Updated versions to current on those CPUs that had valid secondary
	 * contexts
	 */
	for_each_online_cpu(cpu) {
		/*
		 * If a new mm is stored after we took this mm from the array,
		 * it will go into get_new_mmu_context() path, because we
		 * already bumped the version in tlb_context_cache.
		 */
		mm = per_cpu(per_cpu_secondary_mm, cpu);

		if (unlikely(!mm || mm == &init_mm))
			continue;

		old_ctx = mm->context.sparc64_ctx_val;
		if (likely((old_ctx & CTX_VERSION_MASK) == old_ver)) {
			new_ctx = (old_ctx & ~CTX_VERSION_MASK) | new_ver;
			set_bit(new_ctx & CTX_NR_MASK, mmu_context_bmap);
			mm->context.sparc64_ctx_val = new_ctx;
		}
	}
}
 
/* Caller does TLB context flushing on local CPU if necessary.
 * The caller also ensures that CTX_VALID(mm->context) is false.
 *
 * We must be careful about boundary cases so that we never
 * let the user have CTX 0 (nucleus) or we ever use a CTX
 * version of zero (and thus NO_CONTEXT would not be caught
 * by version mis-match tests in mmu_context.h).
 *
 * Always invoked with interrupts disabled.
 */
void get_new_mmu_context(struct mm_struct *mm)
{
	unsigned long ctx, new_ctx;
	unsigned long orig_pgsz_bits;

	raw_spin_lock(&ctx_alloc_lock);
retry:
	/* wrap might have happened, test again if our context became valid */
	if (unlikely(CTX_VALID(mm->context)))
		goto out;
	orig_pgsz_bits = (mm->context.sparc64_ctx_val & CTX_PGSZ_MASK);
	ctx = (tlb_context_cache + 1) & CTX_NR_MASK;
	new_ctx = find_next_zero_bit(mmu_context_bmap, 1 << CTX_NR_BITS, ctx);
	if (new_ctx >= (1 << CTX_NR_BITS)) {
		new_ctx = find_next_zero_bit(mmu_context_bmap, ctx, 1);
		if (new_ctx >= ctx) {
			mmu_context_wrap();
			goto retry;
		}
	}
	if (mm->context.sparc64_ctx_val)
		cpumask_clear(mm_cpumask(mm));
	mmu_context_bmap[new_ctx>>6] |= (1UL << (new_ctx & 63));
	new_ctx |= (tlb_context_cache & CTX_VERSION_MASK);
	tlb_context_cache = new_ctx;
	mm->context.sparc64_ctx_val = new_ctx | orig_pgsz_bits;
out:
	raw_spin_unlock(&ctx_alloc_lock);
}

#ifdef CONFIG_NUMA
static int numa_enabled = 1;
#else
static int numa_enabled = 0;
#endif
static int numa_debug;

static int __init early_numa(char *p)
{
	if (!p)
		return 0;

	if (strstr(p, "off"))
		numa_enabled = 0;

	if (strstr(p, "debug"))
		numa_debug = 1;

	return 0;
}
early_param("numa", early_numa);

#define numadbg(f, a...) \
do {	if (numa_debug) \
		printk(KERN_INFO f, ## a); \
} while (0)

static void __init find_ramdisk(void)
{
#ifdef CONFIG_BLK_DEV_INITRD
	struct boot_info *bi = &bootblock->info;
	if (bi->ramdisk_size) {
		numadbg("Found ramdisk at physical address 0x%llx, size %llx\n",
			bi->ramdisk_base, bi->ramdisk_size);
		initrd_start = bi->ramdisk_base;
		initrd_end = bi->ramdisk_base + bi->ramdisk_size;
		memblock_reserve(initrd_start, bi->ramdisk_size);
		initrd_start += PAGE_OFFSET;
		initrd_end += PAGE_OFFSET;
	}
#endif
}

#ifdef CONFIG_NUMA
int numa_cpu_lookup_table[NR_CPUS];
EXPORT_SYMBOL(numa_cpu_lookup_table);

cpumask_t numa_cpumask_lookup_table[MAX_NUMNODES];
EXPORT_SYMBOL(numa_cpumask_lookup_table);

struct pglist_data *node_data[MAX_NUMNODES];
EXPORT_SYMBOL(node_data);
#endif

/* This must be invoked after performing all of the necessary
 * memblock_set_node() calls for 'nid'.  We need to be able to get
 * correct data from get_pfn_range_for_nid().
 */
static void __init allocate_node_data(int nid)
{
	struct pglist_data *p;
	unsigned long start_pfn, end_pfn;
#ifdef CONFIG_NEED_MULTIPLE_NODES
	void *a;

	a = memblock_alloc_node(sizeof(struct pglist_data), SMP_CACHE_BYTES, nid);
	if (!a) {
		prom_printf("Cannot allocate pglist_data for nid[%d]\n", nid);
		prom_halt();
	}
	NODE_DATA(nid) = a;
	memset(NODE_DATA(nid), 0, sizeof(struct pglist_data));

	NODE_DATA(nid)->node_id = nid;
#endif

	p = NODE_DATA(nid);

	get_pfn_range_for_nid(nid, &start_pfn, &end_pfn);
	p->node_start_pfn = start_pfn;
	p->node_spanned_pages = end_pfn - start_pfn;
}

static int __init bootmem_init_numa(void)
{
#ifdef CONFIG_NUMA
	unsigned long cpu, node;
	for (cpu = 0; cpu < ARRAY_SIZE(numa_cpu_lookup_table); cpu++) {
		int id;
		if (!cpu_present(cpu)) {
			numa_cpu_lookup_table[cpu] = NUMA_NO_NODE;
			continue;
		}
		id = cpu_physical_id(cpu);
		node = id / e90s_max_nr_node_cpus();
		if (!node_online(node))
			node = 0;
		numa_cpu_lookup_table[cpu] = node;
		cpumask_set_cpu(cpu, &numa_cpumask_lookup_table[node]);
	}
#endif
	return 0;
}

static unsigned long __init bootmem_init(void)
{
	boot_info_t *bi = &bootblock->info;
	int i, nodes = numa_enabled ? L_MAX_MEM_NUMNODES : 1;
	unsigned long end_pfn;
	/* setup resource limits */
	ioport_resource.start = BASE_PCIIO;

	memblock_reserve(kern_base, kern_size);

	for (i = 0; i < bi->num_of_busy; i++)
		memblock_reserve(bi->busy[i].address, bi->busy[i].size);

	find_ramdisk();
	for (i = 0; i < nodes; i++) {
		int j;
		node_banks_t *boot_nodes = bi->nodes_mem + i;
		bank_info_t *banks = boot_nodes->banks;
		if (!(bi->nodes_map & (1 << i)))
			continue;
		node_set_online(i);
		for (j = 0; j < L_MAX_NODE_PHYS_BANKS; j++) {
			bank_info_t *b = &banks[j];
			if (!b->size)
				break;	/* no more banks on i */
			memblock_add_node(b->address, b->size, i);
		}
	}
	memblock_enforce_memory_limit(cmdline_memory_size);

	memblock_allow_resize();
	end_pfn = memblock_end_of_DRAM() >> PAGE_SHIFT;
	max_pfn = max_low_pfn = end_pfn;
	min_low_pfn = memblock_start_of_DRAM() >> PAGE_SHIFT;

	for (i = 0; i < nodes; i++) {
		if (!(bi->nodes_map & (1 << i)))
			continue;
		allocate_node_data(i);
	}
	bootmem_init_numa();

	/* Dump memblock with node info. */
	memblock_dump_all();

	sparse_memory_present_with_active_regions(MAX_NUMNODES);
	sparse_init();

	return end_pfn;
}

static unsigned long max_phys_bits = 40;

bool kern_addr_valid(unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if ((long)addr < 0L) {
		unsigned long pa = __pa(addr);

		if ((pa >> max_phys_bits) != 0UL)
			return false;

		return pfn_valid(pa >> PAGE_SHIFT);
	}

	if (addr >= (unsigned long) KERNBASE &&
	    addr < (unsigned long)&_end)
		return true;

	pgd = pgd_offset_k(addr);
	if (pgd_none(*pgd))
		return 0;

	pud = pud_offset(pgd, addr);
	if (pud_none(*pud))
		return 0;

	if (pud_large(*pud))
		return pfn_valid(pud_pfn(*pud));

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return 0;

	if (pmd_large(*pmd))
		return pfn_valid(pmd_pfn(*pmd));

	pte = pte_offset_kernel(pmd, addr);
	if (pte_none(*pte))
		return 0;

	return pfn_valid(pte_pfn(*pte));
}
EXPORT_SYMBOL(kern_addr_valid);

static unsigned long __ref kernel_map_hugepud(unsigned long vstart,
					      unsigned long vend,
					      pud_t *pud)
{
	const unsigned long mask16gb = (1UL << 34) - 1UL;
	u64 pte_val = vstart;

	/* Each PUD is 8GB */
	if ((vstart & mask16gb) ||
	    (vend - vstart <= mask16gb)) {
		pte_val ^= kern_linear_pte_xor[2];
		pud_val(*pud) = pte_val | _PAGE_PUD_HUGE;

		return vstart + PUD_SIZE;
	}

	pte_val ^= kern_linear_pte_xor[3];
	pte_val |= _PAGE_PUD_HUGE;

	vend = vstart + mask16gb + 1UL;
	while (vstart < vend) {
		pud_val(*pud) = pte_val;

		pte_val += PUD_SIZE;
		vstart += PUD_SIZE;
		pud++;
	}
	return vstart;
}

static bool kernel_can_map_hugepud(unsigned long vstart, unsigned long vend,
				   bool guard)
{
	if (guard && !(vstart & ~PUD_MASK) && (vend - vstart) >= PUD_SIZE)
		return true;

	return false;
}

static unsigned long __ref kernel_map_hugepmd(unsigned long vstart,
					      unsigned long vend,
					      pmd_t *pmd)
{
	const unsigned long mask256mb = (1UL << 28) - 1UL;
	const unsigned long mask2gb = (1UL << 31) - 1UL;
	u64 pte_val = vstart;

	/* Each PMD is 8MB */
	if ((vstart & mask256mb) ||
	    (vend - vstart <= mask256mb)) {
		pte_val ^= kern_linear_pte_xor[0];
		pmd_val(*pmd) = pte_val | _PAGE_PMD_HUGE;

		return vstart + PMD_SIZE;
	}

	if ((vstart & mask2gb) ||
	    (vend - vstart <= mask2gb)) {
		pte_val ^= kern_linear_pte_xor[1];
		pte_val |= _PAGE_PMD_HUGE;
		vend = vstart + mask256mb + 1UL;
	} else {
		pte_val ^= kern_linear_pte_xor[2];
		pte_val |= _PAGE_PMD_HUGE;
		vend = vstart + mask2gb + 1UL;
	}

	while (vstart < vend) {
		pmd_val(*pmd) = pte_val;

		pte_val += PMD_SIZE;
		vstart += PMD_SIZE;
		pmd++;
	}

	return vstart;
}

static bool kernel_can_map_hugepmd(unsigned long vstart, unsigned long vend,
				   bool guard)
{
	if (guard && !(vstart & ~PMD_MASK) && (vend - vstart) >= PMD_SIZE)
		return true;

	return false;
}

static unsigned long __ref kernel_map_range(unsigned long pstart,
					    unsigned long pend, pgprot_t prot,
					    bool use_huge)
{
	unsigned long vstart = PAGE_OFFSET + pstart;
	unsigned long vend = PAGE_OFFSET + pend;
	unsigned long alloc_bytes = 0UL;

	if ((vstart & ~PAGE_MASK) || (vend & ~PAGE_MASK)) {
		prom_printf("kernel_map: Unaligned physmem[%lx:%lx]\n",
			    vstart, vend);
		prom_halt();
	}

	while (vstart < vend) {
		unsigned long this_end, paddr = __pa(vstart);
		pgd_t *pgd = pgd_offset_k(vstart);
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;

		if (pgd_none(*pgd)) {
			pud_t *new;

			new = memblock_alloc_from(PAGE_SIZE, PAGE_SIZE,
						  PAGE_SIZE);
			if (!new)
				goto err_alloc;
			alloc_bytes += PAGE_SIZE;
			pgd_populate(&init_mm, pgd, new);
		}
		pud = pud_offset(pgd, vstart);
		if (pud_none(*pud)) {
			pmd_t *new;

			if (kernel_can_map_hugepud(vstart, vend, use_huge)) {
				vstart = kernel_map_hugepud(vstart, vend, pud);
				continue;
			}
			new = memblock_alloc_from(PAGE_SIZE, PAGE_SIZE,
						  PAGE_SIZE);
			if (!new)
				goto err_alloc;
			alloc_bytes += PAGE_SIZE;
			pud_populate(&init_mm, pud, new);
		}

		pmd = pmd_offset(pud, vstart);
		if (pmd_none(*pmd)) {
			pte_t *new;

			if (kernel_can_map_hugepmd(vstart, vend, use_huge)) {
				vstart = kernel_map_hugepmd(vstart, vend, pmd);
				continue;
			}
			new = memblock_alloc_from(PAGE_SIZE, PAGE_SIZE,
						  PAGE_SIZE);
			if (!new)
				goto err_alloc;
			alloc_bytes += PAGE_SIZE;
			pmd_populate_kernel(&init_mm, pmd, new);
		}

		pte = pte_offset_kernel(pmd, vstart);
		this_end = (vstart + PMD_SIZE) & PMD_MASK;
		if (this_end > vend)
			this_end = vend;

		while (vstart < this_end) {
			pte_val(*pte) = (paddr | pgprot_val(prot));

			vstart += PAGE_SIZE;
			paddr += PAGE_SIZE;
			pte++;
		}
	}

	return alloc_bytes;

err_alloc:
	panic("%s: Failed to allocate %lu bytes align=%lx from=%lx\n",
	      __func__, PAGE_SIZE, PAGE_SIZE, PAGE_SIZE);
	return -ENOMEM;
}

static void __init flush_all_kernel_tsbs(void)
{
	int i;

	for (i = 0; i < KERNEL_TSB_NENTRIES; i++) {
		struct tsb *ent = &swapper_tsb[i];

		ent->tag = (1UL << TSB_TAG_INVALID_BIT);
	}
#ifndef CONFIG_DEBUG_PAGEALLOC
	for (i = 0; i < KERNEL_TSB4M_NENTRIES; i++) {
		struct tsb *ent = &swapper_4m_tsb[i];

		ent->tag = (1UL << TSB_TAG_INVALID_BIT);
	}
#endif
}

extern unsigned int kvmap_linear_patch[1];

static void __init kernel_physical_mapping_init(void)
{
	unsigned long mem_alloced = 0UL;
	bool use_huge = true;
	unsigned long start_pfn, end_pfn;
	int i, nid;

#ifdef CONFIG_DEBUG_PAGEALLOC
	use_huge = false;
#endif
	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid) {
		mem_alloced += kernel_map_range(start_pfn << PAGE_SHIFT,
				end_pfn << PAGE_SHIFT, PAGE_KERNEL, use_huge);
	}

	printk("Allocated %ld bytes for kernel page tables.\n",
	       mem_alloced);

	kvmap_linear_patch[0] = 0x01000000; /* nop */
	flushi(&kvmap_linear_patch[0]);

	flush_all_kernel_tsbs();

	__flush_tlb_all();
}

#ifdef CONFIG_DEBUG_PAGEALLOC
void kernel_map_pages(struct page *page, int numpages, int enable)
{
	unsigned long phys_start = page_to_pfn(page) << PAGE_SHIFT;
	unsigned long phys_end = phys_start + (numpages * PAGE_SIZE);

	kernel_map_range(phys_start, phys_end,
			 (enable ? PAGE_KERNEL : __pgprot(0)), false);

	flush_tsb_kernel_range(PAGE_OFFSET + phys_start,
			       PAGE_OFFSET + phys_end);

	/* we should perform an IPI and flush all tlbs,
	 * but that can deadlock->flush only current cpu.
	 */
	__flush_tlb_kernel_range(PAGE_OFFSET + phys_start,
				 PAGE_OFFSET + phys_end);
}
#endif

unsigned long __init find_ecache_flush_span(unsigned long size)
{
	return ~0UL;
}

/* e90s support a full 64-bit virtual
 * address, so we can use all that our page tables
 * support.
 */
unsigned long sparc64_va_hole_top =    0xfff0000000000000UL;
unsigned long sparc64_va_hole_bottom = 0x0010000000000000UL;

unsigned long PAGE_OFFSET = 0xfff0000000000000UL;
EXPORT_SYMBOL(PAGE_OFFSET);

unsigned long VMALLOC_END = ((0x0010000000000000UL >> 1) +
		       (0x0010000000000000UL >> 2));
EXPORT_SYMBOL(VMALLOC_END);

static void __init tsb_phys_patch(void)
{
	struct tsb_ldquad_phys_patch_entry *pquad;
	struct tsb_phys_patch_entry *p;

	pquad = &__tsb_ldquad_phys_patch;
	while (pquad < &__tsb_ldquad_phys_patch_end) {
		unsigned long addr = pquad->addr;

		if (tlb_type == hypervisor)
			*(unsigned int *) addr = pquad->sun4v_insn;
		else
			*(unsigned int *) addr = pquad->sun4u_insn;
		wmb();
		__asm__ __volatile__("flush	%0"
				     : /* no outputs */
				     : "r" (addr));

		pquad++;
	}

	p = &__tsb_phys_patch;
	while (p < &__tsb_phys_patch_end) {
		unsigned long addr = p->addr;

		*(unsigned int *) addr = p->insn;
		wmb();
		__asm__ __volatile__("flush	%0"
				     : /* no outputs */
				     : "r" (addr));

		p++;
	}
}

/* Don't mark as init, we give this to the Hypervisor.  */
#ifndef CONFIG_DEBUG_PAGEALLOC
#define NUM_KTSB_DESCR	2
#else
#define NUM_KTSB_DESCR	1
#endif

/* The swapper TSBs are loaded with a base sequence of:
 *
 *	sethi	%uhi(SYMBOL), REG1
 *	sethi	%hi(SYMBOL), REG2
 *	or	REG1, %ulo(SYMBOL), REG1
 *	or	REG2, %lo(SYMBOL), REG2
 *	sllx	REG1, 32, REG1
 *	or	REG1, REG2, REG1
 *
 * When we use physical addressing for the TSB accesses, we patch the
 * first four instructions in the above sequence.
 */

static void patch_one_ktsb_phys(unsigned int *start, unsigned int *end, unsigned long pa)
{
	unsigned long high_bits, low_bits;

	high_bits = (pa >> 32) & 0xffffffff;
	low_bits = (pa >> 0) & 0xffffffff;

	while (start < end) {
		unsigned int *ia = (unsigned int *)(unsigned long)*start;

		ia[0] = (ia[0] & ~0x3fffff) | (high_bits >> 10);
		__asm__ __volatile__("flush	%0" : : "r" (ia));

		ia[1] = (ia[1] & ~0x3fffff) | (low_bits >> 10);
		__asm__ __volatile__("flush	%0" : : "r" (ia + 1));

		ia[2] = (ia[2] & ~0x1fff) | (high_bits & 0x3ff);
		__asm__ __volatile__("flush	%0" : : "r" (ia + 2));

		ia[3] = (ia[3] & ~0x1fff) | (low_bits & 0x3ff);
		__asm__ __volatile__("flush	%0" : : "r" (ia + 3));

		start++;
	}
}

static void ktsb_phys_patch(void)
{
	extern unsigned int __swapper_tsb_phys_patch;
	extern unsigned int __swapper_tsb_phys_patch_end;
	unsigned long ktsb_pa;

	ktsb_pa = kern_base + ((unsigned long)&swapper_tsb[0] - KERNBASE);
	patch_one_ktsb_phys(&__swapper_tsb_phys_patch,
			    &__swapper_tsb_phys_patch_end, ktsb_pa);
#ifndef CONFIG_DEBUG_PAGEALLOC
	{
	extern unsigned int __swapper_4m_tsb_phys_patch;
	extern unsigned int __swapper_4m_tsb_phys_patch_end;
	ktsb_pa = (kern_base +
		   ((unsigned long)&swapper_4m_tsb[0] - KERNBASE));
	patch_one_ktsb_phys(&__swapper_4m_tsb_phys_patch,
			    &__swapper_4m_tsb_phys_patch_end, ktsb_pa);
	}
#endif
}

static void __init sun4u_linear_pte_xor_finalize(void)
{
#ifndef CONFIG_DEBUG_PAGEALLOC
	/* This is where we would add Panther support for
	 * 32MB and 256MB pages.
	 */
#endif
}

/* paging_init() sets up the page tables */

static unsigned long last_valid_pfn;

static void sun4u_pgprot_init(void);
static void sun4v_pgprot_init(void);

#define KERNEL_PAGE_SZ	0x400000
void flush_locked_tte(void)
{
	int i;
	unsigned long va;
	for (i = num_kernel_image_mappings; i < 4; i++) {
		va = KERNBASE + i * KERNEL_PAGE_SZ;
		spitfire_flush_dtlb_nucleus_page(va);
		spitfire_flush_itlb_nucleus_page(va);
	}

	for (va = LOW_OBP_ADDRESS; va < HI_OBP_ADDRESS; va += KERNEL_PAGE_SZ) {
		spitfire_flush_dtlb_nucleus_page(va);
		spitfire_flush_itlb_nucleus_page(va);
	}
}

void __init paging_init(void)
{
	unsigned long end_pfn, shift;
	unsigned long real_end;

	/* These build time checkes make sure that the dcache_dirty_cpu()
	 * page->flags usage will work.
	 *
	 * When a page gets marked as dcache-dirty, we store the
	 * cpu number starting at bit 32 in the page->flags.  Also,
	 * functions like clear_dcache_dirty_cpu use the cpu mask
	 * in 13-bit signed-immediate instruction fields.
	 */

	/*
	 * Page flags must not reach into upper 32 bits that are used
	 * for the cpu number
	 */
	BUILD_BUG_ON(NR_PAGEFLAGS > 32);

	/*
	 * The bit fields placed in the high range must not reach below
	 * the 32 bit boundary. Otherwise we cannot place the cpu field
	 * at the 32 bit boundary.
	 */
	BUILD_BUG_ON(SECTIONS_WIDTH + NODES_WIDTH + ZONES_WIDTH +
		ilog2(roundup_pow_of_two(NR_CPUS)) > 32);

	BUILD_BUG_ON(NR_CPUS > 4096);

	kern_base = bootblock->info.kernel_base;
	kern_size = (unsigned long)&_end - (unsigned long)KERNBASE;

	/* Invalidate both kernel TSBs.  */
	memset(swapper_tsb, 0x40, sizeof(swapper_tsb));
#ifndef CONFIG_DEBUG_PAGEALLOC
	memset(swapper_4m_tsb, 0x40, sizeof(swapper_4m_tsb));
#endif

	if (tlb_type == hypervisor)
		sun4v_pgprot_init();
	else
		sun4u_pgprot_init();

	if (tlb_type == cheetah_plus ||
	    tlb_type == hypervisor) {
		tsb_phys_patch();
		ktsb_phys_patch();
	}

	read_obp_translations();

	set_bit(0, mmu_context_bmap);

	shift = kern_base + PAGE_OFFSET - ((unsigned long)KERNBASE);

	real_end = (unsigned long)_end;
	num_kernel_image_mappings = DIV_ROUND_UP(real_end - KERNBASE, 1 << ILOG2_4MB);
	printk("Kernel: Using %d locked TLB entries for main kernel image.\n",
	       num_kernel_image_mappings);

	/* Set kernel pgd to upper alias so physical page computations
	 * work.
	 */
	init_mm.pgd += ((shift) / (sizeof(pgd_t)));
	
	memset(swapper_pg_dir, 0, sizeof(swapper_pg_dir));

	inherit_prom_mappings();
	
	{
		unsigned long impl, ver;

		cpu_pgsz_mask = (HV_PGSZ_MASK_8K | HV_PGSZ_MASK_64K |
				 HV_PGSZ_MASK_512K | HV_PGSZ_MASK_4MB);

		__asm__ __volatile__("rdpr %%ver, %0" : "=r" (ver));
		impl = ((ver >> 32) & 0xffff);
		if (impl == PANTHER_IMPL)
			cpu_pgsz_mask |= (HV_PGSZ_MASK_32MB |
					  HV_PGSZ_MASK_256MB);

		sun4u_linear_pte_xor_finalize();
	}

	flush_locked_tte();

	/* Flush the TLBs and the 4M TSB so that the updated linear
	 * pte XOR settings are realized for all mappings.
	 */
	__flush_tlb_all();
#ifndef CONFIG_DEBUG_PAGEALLOC
	memset(swapper_4m_tsb, 0x40, sizeof(swapper_4m_tsb));
#endif
	__flush_tlb_all();

	/* Setup bootmem... */
	last_valid_pfn = end_pfn = bootmem_init();

	kernel_physical_mapping_init();

	{
		unsigned long max_zone_pfns[MAX_NR_ZONES];

		memset(max_zone_pfns, 0, sizeof(max_zone_pfns));

		max_zone_pfns[ZONE_NORMAL] = end_pfn;

		free_area_init_nodes(max_zone_pfns);
	}

	printk("Booting Linux...\n");
}

static void __init register_page_bootmem_info(void)
{
#ifdef CONFIG_NEED_MULTIPLE_NODES
	int i;

	for_each_online_node(i)
		if (NODE_DATA(i)->node_spanned_pages)
			register_page_bootmem_info_node(NODE_DATA(i));
#endif
}
void __init mem_init(void)
{
	high_memory = __va(last_valid_pfn << PAGE_SHIFT);

	memblock_free_all();

	/*
	 * Must be done after boot memory is put on freelist, because here we
	 * might set fields in deferred struct pages that have not yet been
	 * initialized, and free_all_bootmem() initializes all the reserved
	 * deferred pages for us.
	 */
	register_page_bootmem_info();

	/*
	 * Set up the zero page, mark it reserved, so that page count
	 * is not manipulated when freeing the page from user ptes.
	 */
	mem_map_zero = alloc_pages(GFP_KERNEL|__GFP_ZERO, 0);
	if (mem_map_zero == NULL) {
		prom_printf("paging_init: Cannot alloc zero page.\n");
		prom_halt();
	}
	mark_page_reserved(mem_map_zero);

	totalram_real_pages = get_num_physpages();

	mem_init_print_info(NULL);

}

void free_initmem(void)
{
	unsigned long addr, initend;
	int do_free = 1;

	/* If the physical memory maps were trimmed by kernel command
	 * line options, don't even try freeing this initmem stuff up.
	 * The kernel image could have been in the trimmed out region
	 * and if so the freeing below will free invalid page structs.
	 */
	if (cmdline_memory_size)
		do_free = 0;

	/*
	 * The init section is aligned to 8k in vmlinux.lds. Page align for >8k pagesizes.
	 */
	addr = PAGE_ALIGN((unsigned long)(__init_begin));
	initend = (unsigned long)(__init_end) & PAGE_MASK;
	for (; addr < initend; addr += PAGE_SIZE) {
		unsigned long page;

		page = (addr +
			((unsigned long) __va(kern_base)) -
			((unsigned long) KERNBASE));
		memset((void *)addr, POISON_FREE_INITMEM, PAGE_SIZE);

		if (do_free)
			free_reserved_page(virt_to_page(page));
	}
}

#ifdef CONFIG_BLK_DEV_INITRD
void free_initrd_mem(unsigned long start, unsigned long end)
{
	free_reserved_area((void *)start, (void *)end, POISON_FREE_INITMEM,
			   "initrd");
}
#endif

#define _PAGE_CACHE_4U	(_PAGE_CP_4U | _PAGE_CV_4U)
#define _PAGE_CACHE_4V	(_PAGE_CP_4V | _PAGE_CV_4V)
#define __DIRTY_BITS_4U	 (_PAGE_MODIFIED_4U | _PAGE_WRITE_4U | _PAGE_W_4U)
#define __DIRTY_BITS_4V	 (_PAGE_MODIFIED_4V | _PAGE_WRITE_4V | _PAGE_W_4V)

#define __ACCESS_BITS_4U (_PAGE_ACCESSED_4U | _PAGE_R)
#define __ACCESS_BITS_4V (_PAGE_ACCESSED_4V | _PAGE_READ_4V | _PAGE_R)

pgprot_t PAGE_KERNEL __read_mostly;
EXPORT_SYMBOL(PAGE_KERNEL);

pgprot_t PAGE_KERNEL_LOCKED __read_mostly;
pgprot_t PAGE_COPY __read_mostly;

pgprot_t PAGE_SHARED __read_mostly;
EXPORT_SYMBOL(PAGE_SHARED);

unsigned long pg_iobits __read_mostly;

unsigned long _PAGE_IE __read_mostly;
EXPORT_SYMBOL(_PAGE_IE);

unsigned long _PAGE_E __read_mostly;
EXPORT_SYMBOL(_PAGE_E);

unsigned long _PAGE_CACHE __read_mostly;
EXPORT_SYMBOL(_PAGE_CACHE);

#ifdef CONFIG_SPARSEMEM_VMEMMAP
int __meminit vmemmap_populate(unsigned long vstart, unsigned long vend,
			       int node, struct vmem_altmap *altmap)
{
	unsigned long pte_base;

	pte_base = (_PAGE_VALID | _PAGE_SZ4MB_4U |
		    _PAGE_CP_4U | _PAGE_CV_4U |
		    _PAGE_P_4U | _PAGE_W_4U);

	pte_base |= _PAGE_PMD_HUGE;

	vstart = vstart & PMD_MASK;
	vend = ALIGN(vend, PMD_SIZE);
	for (; vstart < vend; vstart += PMD_SIZE) {
		pgd_t *pgd = vmemmap_pgd_populate(vstart, node);
		unsigned long pte;
		pud_t *pud;
		pmd_t *pmd;

		if (!pgd)
			return -ENOMEM;

		pud = vmemmap_pud_populate(pgd, vstart, node);
		if (!pud)
			return -ENOMEM;

		pmd = pmd_offset(pud, vstart);
		pte = pmd_val(*pmd);
		if (!(pte & _PAGE_VALID)) {
			void *block = vmemmap_alloc_block(PMD_SIZE, node);

			if (!block)
				return -ENOMEM;

			pmd_val(*pmd) = pte_base | __pa(block);
		}
	}

	return 0;
}

void vmemmap_free(unsigned long start, unsigned long end,
		struct vmem_altmap *altmap)
{
}
#endif /* CONFIG_SPARSEMEM_VMEMMAP */

static void prot_init_common(unsigned long page_none,
			     unsigned long page_shared,
			     unsigned long page_copy,
			     unsigned long page_readonly,
			     unsigned long page_exec_bit)
{
	PAGE_COPY = __pgprot(page_copy);
	PAGE_SHARED = __pgprot(page_shared);

	protection_map[0x0] = __pgprot(page_none);
	protection_map[0x1] = __pgprot(page_readonly & ~page_exec_bit);
	protection_map[0x2] = __pgprot(page_copy & ~page_exec_bit);
	protection_map[0x3] = __pgprot(page_copy & ~page_exec_bit);
	protection_map[0x4] = __pgprot(page_readonly);
	protection_map[0x5] = __pgprot(page_readonly);
	protection_map[0x6] = __pgprot(page_copy);
	protection_map[0x7] = __pgprot(page_copy);
	protection_map[0x8] = __pgprot(page_none);
	protection_map[0x9] = __pgprot(page_readonly & ~page_exec_bit);
	protection_map[0xa] = __pgprot(page_shared & ~page_exec_bit);
	protection_map[0xb] = __pgprot(page_shared & ~page_exec_bit);
	protection_map[0xc] = __pgprot(page_readonly);
	protection_map[0xd] = __pgprot(page_readonly);
	protection_map[0xe] = __pgprot(page_shared);
	protection_map[0xf] = __pgprot(page_shared);
}

static void __init sun4u_pgprot_init(void)
{
	unsigned long page_none, page_shared, page_copy, page_readonly;
	unsigned long page_exec_bit;
	int i;

	PAGE_KERNEL = __pgprot (_PAGE_PRESENT_4U | _PAGE_VALID |
				_PAGE_CACHE_4U | _PAGE_P_4U |
				__ACCESS_BITS_4U | __DIRTY_BITS_4U |
				_PAGE_EXEC_4U);
	PAGE_KERNEL_LOCKED = __pgprot (_PAGE_PRESENT_4U | _PAGE_VALID |
				       _PAGE_CACHE_4U | _PAGE_P_4U |
				       __ACCESS_BITS_4U | __DIRTY_BITS_4U |
				       _PAGE_EXEC_4U | _PAGE_L_4U);

	_PAGE_IE = _PAGE_IE_4U;
	_PAGE_E = _PAGE_E_4U;
	_PAGE_CACHE = _PAGE_CACHE_4U;

	pg_iobits = (_PAGE_VALID | _PAGE_PRESENT_4U | __DIRTY_BITS_4U |
		     __ACCESS_BITS_4U | _PAGE_E_4U);

#ifdef CONFIG_DEBUG_PAGEALLOC
	kern_linear_pte_xor[0] = _PAGE_VALID ^ PAGE_OFFSET;
#else
	kern_linear_pte_xor[0] = (_PAGE_VALID | _PAGE_SZ4MB_4U) ^
		PAGE_OFFSET;
#endif
	kern_linear_pte_xor[0] |= (_PAGE_CP_4U | _PAGE_CV_4U |
				   _PAGE_P_4U | _PAGE_W_4U);

	for (i = 1; i < 4; i++)
		kern_linear_pte_xor[i] = kern_linear_pte_xor[0];

	_PAGE_ALL_SZ_BITS =  (_PAGE_SZ4MB_4U | _PAGE_SZ512K_4U |
			      _PAGE_SZ64K_4U | _PAGE_SZ8K_4U |
			      _PAGE_SZ32MB_4U | _PAGE_SZ256MB_4U);

#ifdef CONFIG_NUMA_BALANCING
	page_none = _PAGE_PROTNONE | _PAGE_ACCESSED_4U | _PAGE_CACHE_4U;
#else
	page_none = _PAGE_PRESENT_4U | _PAGE_ACCESSED_4U | _PAGE_CACHE_4U;
#endif
	page_shared = (_PAGE_VALID | _PAGE_PRESENT_4U | _PAGE_CACHE_4U |
		       __ACCESS_BITS_4U | _PAGE_WRITE_4U | _PAGE_EXEC_4U);
	page_copy   = (_PAGE_VALID | _PAGE_PRESENT_4U | _PAGE_CACHE_4U |
		       __ACCESS_BITS_4U | _PAGE_EXEC_4U);
	page_readonly   = (_PAGE_VALID | _PAGE_PRESENT_4U | _PAGE_CACHE_4U |
			   __ACCESS_BITS_4U | _PAGE_EXEC_4U);

	page_exec_bit = _PAGE_EXEC_4U;

	prot_init_common(page_none, page_shared, page_copy, page_readonly,
			 page_exec_bit);
}

static void __init sun4v_pgprot_init(void)
{
	unsigned long page_none, page_shared, page_copy, page_readonly;
	unsigned long page_exec_bit;
	int i;

	PAGE_KERNEL = __pgprot (_PAGE_PRESENT_4V | _PAGE_VALID |
				_PAGE_CACHE_4V | _PAGE_P_4V |
				__ACCESS_BITS_4V | __DIRTY_BITS_4V |
				_PAGE_EXEC_4V);
	PAGE_KERNEL_LOCKED = PAGE_KERNEL;

	_PAGE_IE = _PAGE_IE_4V;
	_PAGE_E = _PAGE_E_4V;
	_PAGE_CACHE = _PAGE_CACHE_4V;

#ifdef CONFIG_DEBUG_PAGEALLOC
	kern_linear_pte_xor[0] = _PAGE_VALID ^ PAGE_OFFSET;
#else
	kern_linear_pte_xor[0] = (_PAGE_VALID | _PAGE_SZ4MB_4V) ^
		PAGE_OFFSET;
#endif
	kern_linear_pte_xor[0] |= (_PAGE_CP_4V | _PAGE_CV_4V |
				   _PAGE_P_4V | _PAGE_W_4V);

	for (i = 1; i < 4; i++)
		kern_linear_pte_xor[i] = kern_linear_pte_xor[0];

	pg_iobits = (_PAGE_VALID | _PAGE_PRESENT_4V | __DIRTY_BITS_4V |
		     __ACCESS_BITS_4V | _PAGE_E_4V);

	_PAGE_ALL_SZ_BITS = (_PAGE_SZ16GB_4V | _PAGE_SZ2GB_4V |
			     _PAGE_SZ256MB_4V | _PAGE_SZ32MB_4V |
			     _PAGE_SZ4MB_4V | _PAGE_SZ512K_4V |
			     _PAGE_SZ64K_4V | _PAGE_SZ8K_4V);

	page_none = _PAGE_PRESENT_4V | _PAGE_ACCESSED_4V | _PAGE_CACHE_4V;
	page_shared = (_PAGE_VALID | _PAGE_PRESENT_4V | _PAGE_CACHE_4V |
		       __ACCESS_BITS_4V | _PAGE_WRITE_4V | _PAGE_EXEC_4V);
	page_copy   = (_PAGE_VALID | _PAGE_PRESENT_4V | _PAGE_CACHE_4V |
		       __ACCESS_BITS_4V | _PAGE_EXEC_4V);
	page_readonly = (_PAGE_VALID | _PAGE_PRESENT_4V | _PAGE_CACHE_4V |
			 __ACCESS_BITS_4V | _PAGE_EXEC_4V);

	page_exec_bit = _PAGE_EXEC_4V;

	prot_init_common(page_none, page_shared, page_copy, page_readonly,
			 page_exec_bit);
}

unsigned long pte_sz_bits(unsigned long sz)
{
	if (tlb_type == hypervisor) {
		switch (sz) {
		case 8 * 1024:
		default:
			return _PAGE_SZ8K_4V;
		case 64 * 1024:
			return _PAGE_SZ64K_4V;
		case 512 * 1024:
			return _PAGE_SZ512K_4V;
		case 4 * 1024 * 1024:
			return _PAGE_SZ4MB_4V;
		}
	} else {
		switch (sz) {
		case 8 * 1024:
		default:
			return _PAGE_SZ8K_4U;
		case 64 * 1024:
			return _PAGE_SZ64K_4U;
		case 512 * 1024:
			return _PAGE_SZ512K_4U;
		case 4 * 1024 * 1024:
			return _PAGE_SZ4MB_4U;
		}
	}
}

pte_t mk_pte_io(unsigned long page, pgprot_t prot, int space, unsigned long page_size)
{
	pte_t pte;

	pte_val(pte)  = page | pgprot_val(pgprot_noncached(prot));
	pte_val(pte) |= (((unsigned long)space) << 32);
	pte_val(pte) |= pte_sz_bits(page_size);

	return pte;
}

static unsigned long kern_large_tte(unsigned long paddr)
{
	unsigned long val;

	val = (_PAGE_VALID | _PAGE_SZ4MB_4U |
	       _PAGE_CP_4U | _PAGE_CV_4U | _PAGE_P_4U |
	       _PAGE_EXEC_4U | _PAGE_L_4U | _PAGE_W_4U);
	if (tlb_type == hypervisor)
		val = (_PAGE_VALID | _PAGE_SZ4MB_4V |
		       _PAGE_CP_4V | _PAGE_CV_4V | _PAGE_P_4V |
		       _PAGE_EXEC_4V | _PAGE_W_4V);

	return val | paddr;
}

/* If not locked, zap it. */
void __flush_tlb_all(void)
{
	unsigned long pstate;
	int i;

	__asm__ __volatile__("flushw\n\t"
			     "rdpr	%%pstate, %0\n\t"
			     "wrpr	%0, %1, %%pstate"
			     : "=r" (pstate)
			     : "i" (PSTATE_IE));
	if (tlb_type == spitfire) {
		for (i = 0; i < 64; i++) {
			/* Spitfire Errata #32 workaround */
			/* NOTE: Always runs on spitfire, so no
			 *       cheetah+ page size encodings.
			 */
			__asm__ __volatile__("stxa	%0, [%1] %2\n\t"
					     "flush	%%g6"
					     : /* No outputs */
					     : "r" (0),
					     "r" (PRIMARY_CONTEXT), "i" (ASI_DMMU));

			if (!(spitfire_get_dtlb_data(i) & _PAGE_L_4U)) {
				__asm__ __volatile__("stxa %%g0, [%0] %1\n\t"
						     "membar #Sync"
						     : /* no outputs */
						     : "r" (TLB_TAG_ACCESS), "i" (ASI_DMMU));
				spitfire_put_dtlb_data(i, 0x0UL);
			}

			/* Spitfire Errata #32 workaround */
			/* NOTE: Always runs on spitfire, so no
			 *       cheetah+ page size encodings.
			 */
			__asm__ __volatile__("stxa	%0, [%1] %2\n\t"
					     "flush	%%g6"
					     : /* No outputs */
					     : "r" (0),
					     "r" (PRIMARY_CONTEXT), "i" (ASI_DMMU));

			if (!(spitfire_get_itlb_data(i) & _PAGE_L_4U)) {
				__asm__ __volatile__("stxa %%g0, [%0] %1\n\t"
						     "membar #Sync"
						     : /* no outputs */
						     : "r" (TLB_TAG_ACCESS), "i" (ASI_IMMU));
				spitfire_put_itlb_data(i, 0x0UL);
			}
		}
	} else if (tlb_type == cheetah || tlb_type == cheetah_plus) {
		cheetah_flush_dtlb_all();
		cheetah_flush_itlb_all();
	}
	__asm__ __volatile__("wrpr	%0, 0, %%pstate"
			     : : "r" (pstate));
}

pte_t *pte_alloc_one_kernel(struct mm_struct *mm)
{
	struct page *page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	pte_t *pte = NULL;

	if (page)
		pte = (pte_t *) page_address(page);

	return pte;
}

pgtable_t pte_alloc_one(struct mm_struct *mm)
{
	struct page *page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		return NULL;
	if (!pgtable_pte_page_ctor(page)) {
		free_unref_page(page);
		return NULL;
	}
	return (pte_t *) page_address(page);
}

void pte_free_kernel(struct mm_struct *mm, pte_t *pte)
{
	free_page((unsigned long)pte);
}

static void __pte_free(pgtable_t pte)
{
	struct page *page = virt_to_page(pte);

	pgtable_pte_page_dtor(page);
	__free_page(page);
}

void pte_free(struct mm_struct *mm, pgtable_t pte)
{
	__pte_free(pte);
}

void pgtable_free(void *table, bool is_page)
{
	if (is_page)
		__pte_free(table);
	else
		kmem_cache_free(pgtable_cache, table);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
void update_mmu_cache_pmd(struct vm_area_struct *vma, unsigned long addr,
			  pmd_t *pmd)
{
	unsigned long pte, flags;
	struct mm_struct *mm;
	pmd_t entry = *pmd;

	if (!pmd_large(entry) || !pmd_young(entry))
		return;

	pte = pmd_val(entry);

	/* Don't insert a non-valid PMD into the TSB, we'll deadlock.  */
	if (!(pte & _PAGE_VALID))
		return;

	/* We are fabricating 8MB pages using 4MB real hw pages.  */
	pte |= (addr & (1UL << REAL_HPAGE_SHIFT));

	mm = vma->vm_mm;

	raw_spin_lock_irqsave(&mm->context.lock, flags);

	if (mm->context.tsb_block[MM_TSB_HUGE].tsb != NULL)
		__update_mmu_tsb_insert(mm, MM_TSB_HUGE, REAL_HPAGE_SHIFT,
					addr, pte);

	raw_spin_unlock_irqrestore(&mm->context.lock, flags);
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
static void context_reload(void *__data)
{
	struct mm_struct *mm = __data;

	if (mm == current->mm)
		load_secondary_context(mm);
}

void hugetlb_setup(struct pt_regs *regs)
{
	struct mm_struct *mm = current->mm;
	struct tsb_config *tp;

	if (faulthandler_disabled() || !mm) {
		const struct exception_table_entry *entry;

		entry = search_exception_tables(regs->tpc);
		if (entry) {
			regs->tpc = entry->fixup;
			regs->tnpc = regs->tpc + 4;
			return;
		}
		pr_alert("Unexpected HugeTLB setup in atomic context.\n");
		die_if_kernel("HugeTSB in atomic", regs);
	}

	tp = &mm->context.tsb_block[MM_TSB_HUGE];
	if (likely(tp->tsb == NULL))
		tsb_grow(mm, MM_TSB_HUGE, 0);

	tsb_context_switch(mm);
	smp_tsb_sync(mm);

	/* On UltraSPARC-III+ and later, configure the second half of
	 * the Data-TLB for huge pages.
	 */
	if (tlb_type == cheetah_plus) {
		unsigned long ctx, flags;
		bool need_context_reload = false;

		raw_spin_lock_irqsave(&ctx_alloc_lock, flags);
		ctx = mm->context.sparc64_ctx_val;
		ctx &= ~CTX_PGSZ_MASK;
		ctx |= CTX_PGSZ_BASE << CTX_PGSZ0_SHIFT;
		ctx |= CTX_PGSZ_HUGE << CTX_PGSZ1_SHIFT;

		if (ctx != mm->context.sparc64_ctx_val) {
			/* When changing the page size fields, we
			 * must perform a context flush so that no
			 * stale entries match.  This flush must
			 * occur with the original context register
			 * settings.
			 */
			do_flush_tlb_mm(mm);

			/* Reload the context register of all processors
			 * also executing in this address space.
			 */
			mm->context.sparc64_ctx_val = ctx;
			need_context_reload = true;
		}
		raw_spin_unlock_irqrestore(&ctx_alloc_lock, flags);

		if (need_context_reload)
			on_each_cpu(context_reload, mm, 0);
	}
}
#endif

#ifdef CONFIG_SMP
#define do_flush_tlb_kernel_range	smp_flush_tlb_kernel_range
#else
#define do_flush_tlb_kernel_range	__flush_tlb_kernel_range
#endif

void flush_tlb_kernel_range(unsigned long start, unsigned long end)
{
	if (start < HI_OBP_ADDRESS && end > LOW_OBP_ADDRESS) {
		if (start < LOW_OBP_ADDRESS) {
			flush_tsb_kernel_range(start, LOW_OBP_ADDRESS);
			do_flush_tlb_kernel_range(start, LOW_OBP_ADDRESS);
		}
		if (end > HI_OBP_ADDRESS) {
			flush_tsb_kernel_range(HI_OBP_ADDRESS, end);
			do_flush_tlb_kernel_range(HI_OBP_ADDRESS, end);
		}
	} else {
		flush_tsb_kernel_range(start, end);
		do_flush_tlb_kernel_range(start, end);
	}
}


void copy_user_highpage(struct page *to, struct page *from,
	unsigned long vaddr, struct vm_area_struct *vma)
{
	char *vfrom, *vto;

	vfrom = kmap_atomic(from);
	vto = kmap_atomic(to);
	copy_user_page(vto, vfrom, vaddr, to);
	kunmap_atomic(vto);
	kunmap_atomic(vfrom);

	/* If this page has ADI enabled, copy over any ADI tags
	 * as well
	 */
	if (vma->vm_flags & VM_SPARC_ADI) {
		unsigned long pfrom, pto, i, adi_tag;

		pfrom = page_to_phys(from);
		pto = page_to_phys(to);

		for (i = pfrom; i < (pfrom + PAGE_SIZE); i += adi_blksize()) {
			asm volatile("ldxa [%1] %2, %0\n\t"
					: "=r" (adi_tag)
					:  "r" (i), "i" (ASI_MCD_REAL));
			asm volatile("stxa %0, [%1] %2\n\t"
					:
					: "r" (adi_tag), "r" (pto),
					  "i" (ASI_MCD_REAL));
			pto += adi_blksize();
		}
		asm volatile("membar #Sync\n\t");
	}
}
EXPORT_SYMBOL(copy_user_highpage);

void copy_highpage(struct page *to, struct page *from)
{
	char *vfrom, *vto;

	vfrom = kmap_atomic(from);
	vto = kmap_atomic(to);
	copy_page(vto, vfrom);
	kunmap_atomic(vto);
	kunmap_atomic(vfrom);

	/* If this platform is ADI enabled, copy any ADI tags
	 * as well
	 */
	if (adi_capable()) {
		unsigned long pfrom, pto, i, adi_tag;

		pfrom = page_to_phys(from);
		pto = page_to_phys(to);

		for (i = pfrom; i < (pfrom + PAGE_SIZE); i += adi_blksize()) {
			asm volatile("ldxa [%1] %2, %0\n\t"
					: "=r" (adi_tag)
					:  "r" (i), "i" (ASI_MCD_REAL));
			asm volatile("stxa %0, [%1] %2\n\t"
					:
					: "r" (adi_tag), "r" (pto),
					  "i" (ASI_MCD_REAL));
			pto += adi_blksize();
		}
		asm volatile("membar #Sync\n\t");
	}
}
EXPORT_SYMBOL(copy_highpage);

int valid_phys_addr_range(unsigned long addr, size_t size)
{
	int i;
	int pfn = PFN_DOWN(addr);
	size = PFN_UP(size);
	for (i = 0; i < size; i++) {
		if (!page_is_ram(pfn + i))
			return 0;
	}
	return 1;
}

static int	mmap_phys_addr_enable = 0;
static int __init mmap_phys_addr_setup(char *str)
{
	mmap_phys_addr_enable = 1;
	return 1;
}
__setup("mmap-devmem-enable", mmap_phys_addr_setup);

int valid_mmap_phys_addr_range(unsigned long pfn, size_t size)
{
	int i;
	if (mmap_phys_addr_enable)
		return 1;

	size = PFN_UP(size);
	for (i = 0; i < size; i++) {
		if (!page_is_ram(pfn + i))
			return 0;
	}
	return 1;
}

static struct resource code_resource = {
	.name	= "Kernel code",
	.flags	= IORESOURCE_BUSY | IORESOURCE_MEM
};

static struct resource data_resource = {
	.name	= "Kernel data",
	.flags	= IORESOURCE_BUSY | IORESOURCE_MEM
};

static struct resource bss_resource = {
	.name	= "Kernel bss",
	.flags	= IORESOURCE_BUSY | IORESOURCE_MEM
};

static inline resource_size_t compute_kern_paddr(void *addr)
{
	return (resource_size_t) (addr - KERNBASE + kern_base);
}

static void __init kernel_lds_init(void)
{
	code_resource.start = compute_kern_paddr(_text);
	code_resource.end   = compute_kern_paddr(_etext - 1);
	data_resource.start = compute_kern_paddr(_etext);
	data_resource.end   = compute_kern_paddr(_edata - 1);
	bss_resource.start  = compute_kern_paddr(__bss_start);
	bss_resource.end    = compute_kern_paddr(_end - 1);
}

/*
 * System memory should not be in /proc/iomem but various tools expect it
 * (eg kdump).
 */
static int __init add_system_ram_resources(void)
{
	struct memblock_region *reg;

	kernel_lds_init();

	for_each_memblock(memory, reg) {
		struct resource *res;
		unsigned long base = reg->base;
		unsigned long size = reg->size;

		res = kzalloc(sizeof(struct resource), GFP_KERNEL);
		if (WARN_ON(!res))
			continue;

		res->name = "System RAM";
		res->start = base;
		res->end = base + size - 1;
		res->flags = IORESOURCE_SYSTEM_RAM | IORESOURCE_BUSY;
		if (WARN_ON(request_resource(&iomem_resource, res) < 0))
			continue;

		if (code_resource.start >= res->start &&
		    code_resource.end <= res->end)
			request_resource(res, &code_resource);
		if (data_resource.start >= res->start &&
		    data_resource.end <= res->end)
			request_resource(res, &data_resource);
		if (bss_resource.start >= res->start &&
		    bss_resource.end <= res->end)
			request_resource(res, &bss_resource);

	}

	return 0;
}
subsys_initcall(add_system_ram_resources);
