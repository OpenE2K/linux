/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/suspend.h>
#include <linux/sort.h>
#include <linux/bsearch.h>

#include <asm/pgalloc.h>
#include <asm/mmu_context.h>
#include <asm/regs_state.h>
#include <asm/page_io.h>
#include <asm/set_memory.h>

#define TAGS_PER_PAGE	(PAGE_SIZE / TAGS_BYTES_PER_PAGE)

struct tags_info {
		void *page[TAGS_PER_PAGE];
		void *tags;
};

struct tag_data {
	struct tags_info tags_info[(PAGE_SIZE - 8) /
				sizeof(struct tags_info)];
	struct tag_data *next;
};

static struct tag_data *e2k_tag_data, *tag_wp;
static unsigned long tag_in_page, tags_info_cnt;
static unsigned long *metadata_pfns, metadata_nr;

/*
 * Free e2k_tag_data list of arrays.
 */
noinline /* To make sure we use stacks restored in restore_image() */
static void free_tag_pages(void)
{
	struct tag_data *pkd;
	int i;
	while (e2k_tag_data) {
		pkd = e2k_tag_data;
		e2k_tag_data = pkd->next;
		for (i = 0; i < ARRAY_SIZE(pkd->tags_info); i++)
			free_page((unsigned long)pkd->tags_info[i].tags);
		free_page((unsigned long)pkd);
	}
	free_pages((unsigned long)metadata_pfns, get_order(
				metadata_nr * sizeof(metadata_pfns)));
}

static int cmplong(const void *a, const void *b)
{
	return *(long *)a - *(long *)b;
}

/*
 * Allocate e2k_tag_data list of arrays.
 */
int alloc_tag_pages(unsigned long pages, unsigned long *tags)
{
	long j, k;
	pages += pages / 100; /* BUG: sometimes pages more, so add 1% */
	metadata_nr = DIV_ROUND_UP(pages, TAGS_PER_PAGE);
	k = get_order(metadata_nr * sizeof(metadata_pfns));
	metadata_pfns = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, k);
	if (!metadata_pfns) {
		free_tag_pages();
		return -ENOMEM;
	}
	k = 1 << k;

	for (j = 0; j < metadata_nr; k++) {
		struct tag_data *pk;
		int i;
		pk = (void *)get_zeroed_page(GFP_KERNEL);
		if (!pk) {
			free_tag_pages();
			return -ENOMEM;
		}
		for (i = 0; i < ARRAY_SIZE(pk->tags_info) &&
				   j < metadata_nr; i++, j++) {
			pk->tags_info[i].tags = (void *)
					__get_free_page(GFP_KERNEL);
			if (!pk->tags_info[i].tags) {
				free_tag_pages();
				return -ENOMEM;
			}
			metadata_pfns[j] = page_to_pfn(virt_to_page(
					pk->tags_info[i].tags));
		}
		pk->next = e2k_tag_data;
		e2k_tag_data = pk;
	}
	sort(metadata_pfns, metadata_nr, sizeof(long), cmplong, NULL);
	tag_wp = e2k_tag_data;
	*tags = metadata_nr + k;

	return 0;
}

/*
 * Save the tags.
 */
void save_tag_for_pfn(unsigned long pfn)
{
	void *to, *r, *from = page_address(pfn_to_page(pfn));
	struct tags_info *t;
	r = bsearch(&pfn, metadata_pfns, metadata_nr, sizeof(long), cmplong);
	if (r)
		return;
	if (WARN_ON_ONCE(!tag_wp)) {
		return;
	}
	t = &tag_wp->tags_info[tags_info_cnt];

	if (!t->tags) {
		tag_wp = tag_wp->next;
		tag_in_page = 0;
		tags_info_cnt = 0;
		if (WARN_ON_ONCE(!tag_wp))
			return;
		t = &tag_wp->tags_info[tags_info_cnt];
		if (WARN_ON_ONCE(!t->tags))
			return;
	}
	to = t->tags + tag_in_page * TAGS_BYTES_PER_PAGE;

	if (!save_tags_from_data(from, to)) {
		/* No tags in the page, skip it when restoring tags */
		return;
	}

	t->page[tag_in_page] = from;
	tag_in_page++;
	if (tag_in_page < ARRAY_SIZE(t->page))
		return;

	tag_in_page = 0;
	tags_info_cnt++;
	if (tags_info_cnt < ARRAY_SIZE(tag_wp->tags_info))
		return;

	tags_info_cnt = 0;
	tag_wp = tag_wp->next;
}

UACCESS_FN_DEFINE2(restore_tags_for_data, u64 *, datap, u8 *, tagp)
{
	int i;

	for (i = 0; i < (int) TAGS_BYTES_PER_PAGE; i++) {
		u64 data_lo = datap[2 * i], data_hi = datap[2 * i + 1];
		u32 tag = (u32) tagp[i];

		store_tagged_dword(&datap[2 * i], data_lo, tag);
		store_tagged_dword(&datap[2 * i + 1], data_hi, tag >> 4);
	}

	return 0;
}

static void restore_tags_info(struct tags_info *t)
{
	unsigned long i;

	/* Kernel image alias in page mapping area is write-protected
	 * on every NUMA node (see mark_linear_kernel_alias_ro()). So
	 * catch possible write page faults and open write access. */
	pagefault_disable();

	for (i = 0; i < ARRAY_SIZE(t->page); i++) {
		void *to = t->page[i];
		void *from = t->tags + i * TAGS_BYTES_PER_PAGE;

		if (unlikely(!to))
			break;

		if (__UACCESS_FN_CALL(restore_tags_for_data, to, from)) {
			int ret;

			set_memory_rw((unsigned long) to, 1);
			ret = __UACCESS_FN_CALL(restore_tags_for_data, to, from);
			set_memory_ro((unsigned long) to, 1);

			if (ret) {
				pr_err("hibernation resume: page fault when restoring tags at 0x%lx\n",
						to);
				print_kernel_address_ptes((unsigned long) to);
				continue;
			}
		}
	}

	pagefault_enable();
}

noinline /* To make sure we use stacks restored in restore_image() */
static void restore_tags(void)
{
	struct tag_data *pk = e2k_tag_data;

	for (pk = e2k_tag_data; pk; pk = pk->next) {
		unsigned long i;
		for (i = 0; i < ARRAY_SIZE(pk->tags_info); i++)
			restore_tags_info(pk->tags_info);
	}
}

/*
 *	pfn_is_nosave - check if given pfn is in the 'nosave' section
 */

int pfn_is_nosave(unsigned long pfn)
{
	unsigned long nosave_begin_pfn = __pa(&__nosave_begin) >> PAGE_SHIFT;
	unsigned long nosave_end_pfn =
			PAGE_ALIGN(__pa(&__nosave_end)) >> PAGE_SHIFT;
	return (pfn >= nosave_begin_pfn) && (pfn < nosave_end_pfn);
}


static struct task_struct	*task_to_recover;
static struct sw_regs		sw_regs_to_recover;

int swsusp_arch_suspend(void)
{
	unsigned long flags;
	BUILD_BUG_ON(sizeof(struct tag_data) > PAGE_SIZE);

	task_to_recover = current;

	raw_all_irq_save(flags);
	NATIVE_SAVE_TASK_REGS_TO_SWITCH(current);
	sw_regs_to_recover = current->thread.sw_regs;
	raw_all_irq_restore(flags);

	return swsusp_save();
}

#define r64(_a)	({						\
		void *_v = (void *)NATIVE_READ_MAS_D(__pa(_a), MAS_LOAD_PA); \
		_v; })
#define w64(_v, _a)	NATIVE_WRITE_MAS_D(__pa(_a), _v, MAS_STORE_PA)

static inline void copy_image(void)
{
	struct pbe *pbe;
	for (pbe = restore_pblist; pbe; pbe = r64(&pbe->next)) {
		u64 *to = r64(&pbe->orig_address);
		u64 *from = r64(&pbe->address);
		int i;

		for (i = 0; i < PAGE_SIZE / sizeof(*to); i++, to++, from++)
			w64(r64(from), to);
	}
}

__used
static void restore_image(pgd_t *resume_pg_dir, struct pbe *restore_pblist)
{
	extern int in_suspend;
	struct task_struct *task;
	struct sw_regs *to, *from;

	set_root_pt(resume_pg_dir);
	native_raw_flush_TLB_all();

	copy_image();

	set_kernel_MMU_state();
	native_raw_flush_TLB_all();

	task = task_to_recover;
	from = &sw_regs_to_recover;
	to = &task->thread.sw_regs;

	*to = *from;

	set_current_thread_info(task_thread_info(task), task);
	if (task->mm != NULL)
		reload_thread(task->mm);

	/*
	 * Restore state registers of current process to enable
	 * switching to the interrupted task as end of recovery of the system
	 */

	NATIVE_RESTORE_TASK_REGS_TO_SWITCH(task);

	/* Start receiving NMIs again */
	raw_local_irq_disable();

	/* tags restoring and freeing can have stack recursions possibly
	 * more than 1 page of safe procedure stack. So move this *after*
	 * hardware stacks are switched back. */
	restore_tags();
	free_tag_pages();

	/*
	* Tell the hibernation core that we've just restored
	* the memory
	*/
	in_suspend = 0;
}

/* Switch to a safe stack so that we don't accidentally SPILL into just
 * restored data.
 *
 * Note that we cannot switch stacks and restore image data in the same
 * function because then SP would be initialized *before* the stack switch.
 *
 * Also note that 1 page for procedure stack is *very* little for e2k
 * (just 128 quadro registers, and one function can use at maximum
 * E2K_MAXSR_q == 112 quadro registers). That's why we use JUMP - to save
 * some registers for callee. */
static int switch_stacks_and_goto_restore_image(pgd_t *resume_pg_dir,
		struct pbe *restore_pblist)
{
	unsigned long chain_stack, proc_stack, data_stack;

	chain_stack = get_safe_page(GFP_ATOMIC);
	proc_stack = get_safe_page(GFP_ATOMIC);
	data_stack = get_safe_page(GFP_ATOMIC);
	if (!chain_stack || !proc_stack || !data_stack)
		return -ENOMEM;

	/* POINT OF NO RETURN
	 *
	 * We have got enough memory and from now on we cannot recover. */

	raw_all_irq_disable(); /* Protect ourselves from NMIs */
	NATIVE_SWITCH_TO_KERNEL_STACK(proc_stack, PAGE_SIZE,
			chain_stack, PAGE_SIZE, data_stack, PAGE_SIZE);

	E2K_JUMP_WITH_ARGUMENTS(restore_image, 2, resume_pg_dir, restore_pblist);
}

static void _copy_pte(pte_t *dst_pte, pte_t *src_pte, unsigned long addr)
{
	pte_t pte = *src_pte;
	if (pte_valid(pte))
		set_pte(dst_pte, pte_mkwrite(pte));
}

static int copy_pte(pmd_t *dst_pmd, pmd_t *src_pmd, unsigned long start,
		    unsigned long end)
{
	pte_t *src_pte;
	pte_t *dst_pte;
	unsigned long addr = start;

	dst_pte = (pte_t *)get_safe_page(GFP_ATOMIC);
	if (!dst_pte)
		return -ENOMEM;
	pmd_populate_kernel(&init_mm, dst_pmd, dst_pte);
	dst_pte = pte_offset_kernel(dst_pmd, start);

	src_pte = pte_offset_kernel(src_pmd, start);
	do {
		_copy_pte(dst_pte, src_pte, addr);
	} while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr != end);

	return 0;
}

#define pmd_table(x) (!kernel_pmd_huge(x))
#define pud_table(x) (!kernel_pud_huge(x))

static int copy_pmd(pud_t *dst_pud, pud_t *src_pud, unsigned long start,
		    unsigned long end)
{
	pmd_t *src_pmd;
	pmd_t *dst_pmd;
	unsigned long next;
	unsigned long addr = start;

	if (pud_none(*dst_pud)) {
		dst_pmd = (pmd_t *)get_safe_page(GFP_ATOMIC);
		if (!dst_pmd)
			return -ENOMEM;
		pud_populate(&init_mm, dst_pud, dst_pmd);
	}
	dst_pmd = pmd_offset(dst_pud, start);

	src_pmd = pmd_offset(src_pud, start);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none(*src_pmd))
			continue;
		if (pmd_table(*src_pmd)) {
			if (copy_pte(dst_pmd, src_pmd, addr, next))
				return -ENOMEM;
		} else {
			set_pmd(dst_pmd, pmd_mkwrite(*src_pmd));
		}
	} while (dst_pmd++, src_pmd++, addr = next, addr != end);

	return 0;
}


#define my_pgd_populate(mm, pgdp, pudp)		(*(pgdp) = mk_pgd_phys_k(pudp))

static int copy_pud(pgd_t *dst_pgd, pgd_t *src_pgd, unsigned long start,
		    unsigned long end)
{
	pud_t *dst_pud;
	pud_t *src_pud;
	unsigned long next;
	unsigned long addr = start;

	if (pgd_none(*dst_pgd)) {
		dst_pud = (pud_t *)get_safe_page(GFP_ATOMIC);
		if (!dst_pud)
			return -ENOMEM;
		my_pgd_populate(&init_mm, dst_pgd, dst_pud);
	}
	dst_pud = pud_offset(dst_pgd, start);

	src_pud = pud_offset(src_pgd, start);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none(*src_pud))
			continue;
		if (pud_table(*(src_pud))) {
			if (copy_pmd(dst_pud, src_pud, addr, next))
				return -ENOMEM;
		} else {
			set_pud(dst_pud, pud_mkwrite(*src_pud));
		}
	} while (dst_pud++, src_pud++, addr = next, addr != end);

	return 0;
}

static int copy_page_tables(pgd_t *dst_pgd, unsigned long start,
			    unsigned long end)
{
	unsigned long next;
	unsigned long addr = start;
	pgd_t *src_pgd = pgd_offset_k(start);

	/* Avoid messing with self-pointing PGD */
	if (end > KERNEL_VPTB_BASE_ADDR)
		end = KERNEL_VPTB_BASE_ADDR;
	/* Manually call PGD constructor since
	 * get_safe_page() did not do it for us. */
	pgd_ctor(&init_mm, numa_node_id(), dst_pgd);

	dst_pgd = dst_pgd + pgd_index(start);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none(*src_pgd))
			continue;
		if (copy_pud(dst_pgd, src_pgd, addr, next))
			return -ENOMEM;
	} while (dst_pgd++, src_pgd++, addr = next, addr != end);

	return 0;
}

int swsusp_arch_resume(void)
{
	int error;
	pgd_t *resume_pg_dir;

	resume_pg_dir = (pgd_t *)get_safe_page(GFP_ATOMIC);
	if (!resume_pg_dir)
		return -ENOMEM;

	error = copy_page_tables(resume_pg_dir, PAGE_OFFSET, E2K_VA_END);
	if (error)
		return error;

	error = switch_stacks_and_goto_restore_image(resume_pg_dir, restore_pblist);
	return error;
}
