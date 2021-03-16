/*
 * E2K Huge TLB page support.
 */

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/sysctl.h>
#include <linux/slab.h>

#include <asm/mman.h>
#include <asm/pgalloc.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>

#undef	DEBUG_HUGETLB_MODE
#undef	DebugHP
#define	DEBUG_HUGETLB_MODE	0	/* Huge pages */
#define DebugHP(...)		DebugPrint(DEBUG_HUGETLB_MODE ,##__VA_ARGS__)

pte_t *
huge_pte_alloc(struct mm_struct *mm, unsigned long addr, unsigned long sz)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, addr);
	pud = pud_alloc(mm, pgd, addr);
	if (pud == NULL) {
		return NULL;
	}
	pmd = pmd_alloc(mm, pud, addr);
	if (pmd == NULL) {
		return NULL;
	}
	pte = (pte_t *)pmd;
 
	/*
	 * Large page pte should point to the first of two pmd's.
	 */
	if (E2K_LARGE_PAGE_SIZE == E2K_4M_PAGE_SIZE) {
		if (pte && pmd_index(addr) % 2)
			pte--;
	}

	BUG_ON(pte && pte_present(*pte) && !pte_huge(*pte));

	return pte;
}

pte_t *
huge_pte_offset(struct mm_struct *mm, unsigned long addr, unsigned long sz)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd))
		return NULL;
	pud = pud_offset(pgd, addr);
	if (pud_none(*pud))
		return NULL;
	pmd = pmd_offset(pud, addr);
	pte = (pte_t *)pmd;

	/*
	 * Large page pte should point to the first of two pmd's.
	 */
	if (E2K_LARGE_PAGE_SIZE == E2K_4M_PAGE_SIZE) {
		if (pte && pmd_index(addr) % 2)
			pte--;
	}

	return pte;
}

void
set_huge_pte_at(struct mm_struct *mm, unsigned long address,
		pte_t *ptep, pte_t entry)
{
	/*
	 * In this case virtual page occupied two sequential entries in
	 * page table on 2-th level (PMD).
	 * All two pte's (pmd's) should be set to identical entries.
	 */
	DebugHP("will set pte 0x%px = 0x%lx\n",
		ptep, pte_val(entry));
	set_pte_at(mm, address, ptep, entry);
	if (E2K_LARGE_PAGE_SIZE == E2K_4M_PAGE_SIZE)
		set_pte_at(mm, address, (++ptep), entry);
}

pte_t
huge_ptep_get_and_clear(struct mm_struct *mm, unsigned long addr,
		pte_t *ptep)
{
	pte_t entry = *ptep;
	huge_pte_clear(mm, addr, ptep,
		       0 /* unused now */);
	return entry;
}

/* Update this if adding upport for ARCH_ENABLE_HUGEPAGE_MIGRATION (see x86) */
int pmd_huge(pmd_t pmd)
{
	return user_pmd_huge(pmd);
}

int pud_huge(pud_t pud)
{
	BUG_ON(user_pud_huge(pud));	/* not implemented for user */
	return 0;
}

#ifdef HAVE_ARCH_HUGETLB_UNMAPPED_AREA
unsigned long
hugetlb_get_unmapped_area(struct file *file, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct hstate *h = hstate_file(file);
	struct vm_unmapped_area_info info;
	unsigned long begin, end;
	unsigned long is_protected = TASK_IS_PROTECTED(current);
	unsigned long is_32bit = (current->thread.flags & E2K_FLAG_32BIT) &&
				 !is_protected;

	if (len & ~huge_page_mask(h))
		return -EINVAL;

	if (len > TASK_SIZE)
		return -ENOMEM;

	if (flags & MAP_FIXED) {
		if (!test_ts_flag(TS_KERNEL_SYSCALL) &&
				(addr >= USER_HW_STACKS_BASE ||
				 addr + len >= USER_HW_STACKS_BASE))
			return -ENOMEM;
		if (prepare_hugepage_range(file, addr, len))
			return -EINVAL;
		return addr;
	}

	begin = (addr) ?: mm->mmap_base;
	if (!test_ts_flag(TS_KERNEL_SYSCALL)) {
		if (is_32bit || is_protected && (flags & MAP_FIRST32))
			end = TASK32_SIZE;
		else
			end = TASK_SIZE;
		end = min(end, USER_HW_STACKS_BASE);
	} else {
		end = TASK_SIZE;
	}

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (TASK_IS_BINCO(current) && ADDR_IN_SS(addr)) {
		end = min(end, SS_ADDR_END);
		/* Lower mremap() address for binary compiler
		 * must be >= ss_rmp_bottom */
		if (current_thread_info()->ss_rmp_bottom > addr)
			begin = current_thread_info()->ss_rmp_bottom;
	}
#endif

	info.flags = 0;
	info.length = len;
	info.low_limit = begin;
	info.high_limit = end;
	info.align_mask = PAGE_MASK & ~huge_page_mask(h);
	info.align_offset = 0;

	return vm_unmapped_area(&info);
}
#endif	/* HAVE_ARCH_HUGETLB_UNMAPPED_AREA */

