/*
 * E2K Huge TLB page support.
 *
 * Copyright (C) 2002 David S. Miller (davem@redhat.com)
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

	if (pmd_none(*pmd)) {
		DebugHP("returns clean pmd 0x%p = "
			"0x%lx\n", pte, pte_val(*pte));
		return pte;
	} else if (pte_huge(*pte)) {
		DebugHP("returns existent pte 0x%p = "
			"0x%lx\n", pte, pte_val(*pte));
		return pte;
	}

	/*
	 * pmd points to unused after unmap() ptes page.
	 * unmap() free all VMA pages but cannot free page tables,
	 * all entries in ptes table should be in this case cleared
	 * so free the ptes page and clear pmd.
	 */
	DebugHP("detects pmd to unused ptes table "
		"0x%p = 0x%lx\n", pte, pte_val(*pte));
	free_one_pmd(pmd);

	DebugHP("returns released pmd 0x%p = "
		"0x%lx\n", pte, pte_val(*pte));
	return pte;
}

pte_t *
huge_pte_offset(struct mm_struct *mm, unsigned long addr)
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

int huge_pmd_unshare(struct mm_struct *mm, unsigned long *addr, pte_t *ptep)
{
	return 0;
}

static void
huge_set_pte(struct mm_struct *mm, unsigned long address, pte_t *page_table,
								    pte_t entry)
{
	/*
	 * In this case virtual page occupied two sequential entries in
	 * page table on 2-th level (PMD).
	 * All two pte's (pmd's) should be set to identical entries.
	 */
	DebugHP("will set pte 0x%p = 0x%lx\n",
		page_table, pte_val(entry));
	set_pte_at(mm, address, page_table, entry);
	if (E2K_LARGE_PAGE_SIZE == E2K_4M_PAGE_SIZE)
		set_pte_at(mm, address, (++page_table), entry);
}

void
set_huge_pte_at(struct mm_struct *mm, unsigned long addr,
		     pte_t *ptep, pte_t entry)
{
	huge_set_pte(mm, addr, ptep, entry);
}

pte_t
huge_ptep_get_and_clear(struct mm_struct *mm, unsigned long addr,
			      pte_t *ptep)
{
	pte_t entry = *ptep;
	huge_pte_clear(mm, addr, ptep);
	return entry;
}

struct page *
follow_huge_addr(struct mm_struct *mm, unsigned long addr, int write)
{
	struct page *page;
	struct vm_area_struct *vma;
	pte_t *pte;

	DebugHP("started with addr 0x%lx\n",
		addr);

	vma = find_vma(mm, addr);
	if (vma == NULL) {
		DebugHP("could not find VMA for addr\n");
		return ERR_PTR(-EINVAL);
	}
	if (!is_vm_hugetlb_page(vma)) {
		DebugHP("VMA 0x%p is not HUGE "
			"PAGES VMA\n", vma);
		return ERR_PTR(-EINVAL);
	}
	DebugHP("VMA 0x%p is huge pages VMA\n", vma);

	pte = huge_pte_offset(mm, addr);

	/* hugetlb should be locked, and hence, prefaulted */
	BUG_ON(!pte || pte_none(*pte));

	page = pte_page(*pte);

	WARN_ON(!PageCompound(page));

	DebugHP("returns page 0x%p\n", page);
	return page;
}

int
pmd_huge(pmd_t pmd)
{
	return 0;
}

int pud_huge(pud_t pud)
{
	return 0;
}

struct page *
follow_huge_pmd(struct mm_struct *mm, unsigned long address, pmd_t *pmd,
		int write)
{
	return NULL;
}


#ifdef HAVE_ARCH_HUGETLB_UNMAPPED_AREA

#ifdef CONFIG_PROTECTED_MODE
extern unsigned long
get_protected_unmapped_area(struct file *filp, unsigned long addr,
			    unsigned long len, unsigned long pgsz);
#endif	/* CONFIG_PROTECTED_MODE */

unsigned long
hugetlb_get_unmapped_area(struct file *file, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long start_addr;

	if (len & ~HPAGE_MASK)
		return -EINVAL;
	if (len > TASK_SIZE)
		return -ENOMEM;

#ifdef CONFIG_PROTECTED_MODE
	if (current->thread.flags & E2K_FLAG_PROTECTED_MODE) {
		return get_protected_unmapped_area(filp, addr, len, HPAGE_SIZE);
	}
#endif	/* CONFIG_PROTECTED_MODE */

	if (addr) {
		addr = ALIGN(addr, HPAGE_SIZE);
		vma = find_vma(mm, addr);
		if (TASK_SIZE - len >= addr &&
				  (!vma || addr + len <= vma->vm_start))
			return addr;
	}

	start_addr = mm->free_area_cache;

	if (len <= mm->cached_hole_size)
		start_addr = TASK_UNMAPPED_BASE;

full_search:
		addr = ALIGN(start_addr, HPAGE_SIZE);

        for (vma = find_vma(mm, addr); ; vma = vma->vm_next) {
		/* At this point:  (!vma || addr < vma->vm_end). */
		if (TASK_SIZE - len < addr) {
                        /*
			 * Start a new search - just in case we missed
			 * some holes.
			 */
			if (start_addr != TASK_UNMAPPED_BASE) {
				start_addr = TASK_UNMAPPED_BASE;
				goto full_search;
			}
			return -ENOMEM;
		}

		if (!vma || addr + len <= vma->vm_start)
			return addr;
		addr = ALIGN(vma->vm_end, HPAGE_SIZE);
	}
}
#endif	/* HAVE_ARCH_HUGETLB_UNMAPPED_AREA */

