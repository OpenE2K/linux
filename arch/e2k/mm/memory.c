/*  $Id: memory.c,v 1.34 2009/12/10 17:34:00 kravtsunov_e Exp $
 *  arch/e2k/mm/memory.c
 *
 * Memory management utilities
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */
 
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/hugetlb.h>
#include <linux/blkdev.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/rmap.h>

#include <asm/types.h>
#include <asm/boot_head.h>
#include <asm/boot_init.h>
#include <asm/boot_phys.h>
#include <asm/head.h>
#include <asm/system.h>
#include <asm/mmu_regs.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <asm/secondary_space.h>

#include <asm/e2k_debug.h>

#undef	DEBUG_PT_MODE
#undef	DebugPT
#define	DEBUG_PT_MODE		0	/* Page table */
#define DebugPT(...)		DebugPrint(DEBUG_PT_MODE ,##__VA_ARGS__)

#undef	DEBUG_MM_MODE
#undef	DebugMM
#define	DEBUG_MM_MODE		0	/* Memory mapping */
#define DebugMM(...)		DebugPrint(DEBUG_MM_MODE ,##__VA_ARGS__)
#define	DebugMMP		DebugMM

#undef	DEBUG_NUMA_MODE
#undef	DebugNUMA
#define	DEBUG_NUMA_MODE		0	/* NUMA supporting */
#define DebugNUMA(...)		DebugPrint(DEBUG_NUMA_MODE ,##__VA_ARGS__)

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT

#define CHECK_PT_LOCKED(mm)					\
do {								\
    if (mm) {							\
        if (unlikely(!spin_is_locked(&mm->page_table_lock)))	\
                BUG();						\
    }								\
} while (0)

/*
 * Allocate page middle directory when SECONDARY_SPACE_SUPPORT enabled.
 * We use such set of "compound pages" for this goal:
 *
 * pmdE2K  pmdE2K  pmdE2K  pmdE2K  pgd_i386 unused unused  unused
 *|-------|-------|-------|-------|-------|*******|*******|*******|
 */
pmd_t *
pmd_alloc_cont(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	unsigned long	ind;
	pmd_t		*pmd = NULL, *pmd1;
	i386_pgd_t	*ipgd;

	DebugSS("pmd_alloc_cont()S:%d pud:%p, add:0x%lx\n",
				IN_INTEL_MODE, pud, address);
	if (pud_present(*pud)) {
		DebugSS("pud_pres!!! :0x%lx\n", pud_val(*pud));
		goto out;
	}
	spin_lock(&mm->page_table_lock);
	if (pud_frozen(*pud)) { /* munmap() occurred */
		unfreeze_pud(pud);
		pmd = (pmd_t *)(pud_page(*pud));
		SET_TBL_ZERO(pmd);
		spin_unlock(&mm->page_table_lock);
		DebugSS("unfreeze_pud:0x%lx pmd:%p\n",
			pud_val(*pud), pmd);
		goto out;
	}
	spin_unlock(&mm->page_table_lock);
	ind = pud_index((address - (SS_ADDR_START &(~PGDIR_MASK))));
	/* Real allocation pmd(s) for mapping secondary space */
	DebugSS("address:0x%lx ind:%ld\n", address, ind);
	if (ind == 0) { /* Alloc of 1st pmd for SECONDARY_SPACE */
		struct page *pmd_page;

		pmd_page = get_i386_pages(SS_PMD_ORDER);
		DebugSS("pmd0:%p\n", pmd_page);
		if (!pmd_page)
			return NULL;
		pmd = (pmd_t *)page_address(pmd_page);
		spin_lock(&mm->page_table_lock);
		/* We dropped the lock, so we should re-check the (*pud) */
		if (pud_present(*pud)) { /* somebody done it */
			spin_unlock(&mm->page_table_lock);
			__free_pages(pmd_page, SS_PMD_ORDER);
			goto out;
		} else {
			pud_populate_sec(mm, pud, pmd);
		}
		BUG_ON((u64)pmd != ((u64)pmd & SS_PMD_MASK));
		ipgd = (i386_pgd_t *)((char *)pmd + PAGE_SIZE*4);
		/* Here we got i386_pgd firstly. Insert it in mm */
		set_secondary_space_page_dir(mm, ipgd);
		/* Is it the first page fault for SS addresses? */
		if (!IN_INTEL_MODE && mm == current->mm) {
			reload_secondary_page_dir(mm); /* Insert it in CR3 */
		}
		DebugSS("pmd_alloc_cont ipgd:%p cr3:0x%lx mm 0x%p sec_pgd:%p\n",
			ipgd, (u64 )get_MMU_CR3_RG(), mm, mm->sec_pgd);
		SET_TBL_ZERO(pmd);
		spin_unlock(&mm->page_table_lock);
	} else {
		pud_t *pud_1st = (pud_t *)(pud - ind);
	/*
	 * It is allocation 2nd or 3rd or 4th pmd for SECONDARY_SPACE.
	 * Is the 1st pmd (of INTEL space) already allocated?
	 */
		spin_lock(&mm->page_table_lock);
		if (pud_none(*pud_1st)) { /* max level of recursion is 2 */
			DebugSS("pmd0 not allocated yet\n");
			spin_unlock(&mm->page_table_lock);
			pmd1 = pmd_alloc_cont(mm, pud_1st, SS_ADDR_START);
			if (!pmd1)
				return NULL;
			spin_lock(&mm->page_table_lock);
			/* We dropped the lock, so we should
			 * re-check the (*pud_1st)
			 */
			if (pud_frozen(*pud_1st)) { /* somebody done it */
			} else {
				mk_pud_frozen(pud_1st); /* It isn't required yet */
				SET_TBL_FREE(pud_page(*pud_1st));
			}
		}
		BUG_ON(pud_none(*pud_1st));
	/*
	 * These PMDs are already allocated, we need calculate addr only.
	 * Bellow we assume, all SECONDARY_SPACE pmd entries reside in
	 * single pud (we can choose SS_ADDR_START so)
	 */

		pmd = (pmd_t *)(pud_page(*pud_1st) + ind*PAGE_SIZE);
		SET_TBL_ZERO(pmd);
		pud_populate_sec(mm, pud, pmd);
		spin_unlock(&mm->page_table_lock);
		DebugSS("pmd2:%p ind:%ld\n", pmd, ind);
	}

 out:
	DebugSS("pmd:%p pud_val:0x%lx\n",
			(pmd_t *)pud_page(*pud), pud_val(*pud));
	return pmd_offset(pud, address);
}

/*
 * Allocate page table directory when SECONDARY_SPACE_SUPPORT enabled.
 * We use such set of "compound pages" for this goal:
 *
 *     pteE2K   pteE2K pte_i386 unused
 *    |-------|-------|-------|*******|
 */
pte_t *
pte_alloc_cont(struct mm_struct *mm, pmd_t *pmd, unsigned long address, 
							spinlock_t **ptlp)
{
	pte_t *pte = NULL, *pte1;

	DebugSS("pte_alloc_cont()S pmd:%p addr:0x%lx\n", pmd, address);
	if (pmd_present(*pmd)){
		DebugSS("pmd_present! 0x%lx\n", pmd_val(*pmd));
		goto out_pr;
	}
	spin_lock(&mm->page_table_lock);
	if (pmd_frozen(*pmd)) {
		unfreeze_pmd(pmd);
		pte = (pte_t *)(pmd_page_kernel(*pmd));
		SET_TBL_ZERO(pte);
		DebugSS("unfreeze_pmd:0x%lx pte:%p\n",
			pmd_val(*pmd), pte);
		goto out;
	}
	spin_unlock(&mm->page_table_lock);
	if (IS_FIRST_PTE(address)) { /* first fom pair */
		struct page	*pte_page;
		i386_pte_t	*ipte;
		i386_pgd_t	*ipgd;
		int		ind, delta = pud_index(address) - 
			 			pud_index(SS_ADDR_START);
		i386_pgd_t	entry;
		u32		val;

		pte_page = get_i386_pages(SS_PTE_ORDER);
		if (!pte_page) {
			return NULL;
		}
		pte = (pte_t *)page_address(pte_page);
		spin_lock(&mm->page_table_lock);
		SET_TBL_ZERO(pte);
		ind = i386_pgd_index(address - SS_ADDR_START);
		DebugSS("pte1:%p pmd:%p addr:0x%lx _ind:%d\n",
			pte, pmd, address, ind);
		/* re-check the (*pmd) due to dropped lock */
		if (pmd_present(*pmd)) {
			spin_unlock(&mm->page_table_lock);
			DebugSS("\npte_alloc_cont() re-check ->free_pages\n");
			__free_pages(pte_page, SS_PTE_ORDER);
			pte = NULL;
			goto out_pr;
		}
		pgtable_page_ctor(pte_page);
		DebugSS("pte page CTOR 0x%p\n", pte_page);
		ipgd = (i386_pgd_t *)((char *)((u64)pmd & PAGE_MASK)
			+ PAGE_SIZE * (4 - delta));
		ipte = (i386_pte_t *)((char *)(pte) + PAGE_SIZE*2);

		DebugSS("ipgd:%p ipte:%p delta:%d\n",
			 ipgd, ipte, delta);
		ipgd += ind;
		val = __pa(ipte) | i386_PAGE_TABLE;
		entry = i386__pgd(val);
		i386_set_pgd(ipgd, entry);
		DebugSS("pte_alloc_cont(*) ipgd:%p entry:ox%x\n", ipgd, val);
	} else { /* second fom pair ( may be already allocated) */
		pmd_t		*pmd_1st = (pmd_t *)(pmd - 1);

		spin_lock(&mm->page_table_lock);
		if (pmd_none(*pmd_1st)) {/* max level of recursion is 2 */
			DebugSS("1st pmd isn't allocated!\n");
			spin_unlock(&mm->page_table_lock);
			pte1 = pte_alloc_cont(mm, pmd_1st, PREV_PMD(address), ptlp);
			if (!pte1)
				return NULL;
			if (ptlp)
				spin_unlock(*ptlp);
			spin_lock(&mm->page_table_lock);
			/* We dropped the lock, so we should
			 * re-check the (*pmd_1st)
			 */
			if (pmd_frozen(*pmd_1st)) { /* somebody done it */
			} else {
				mk_pmd_frozen(pmd_1st); /* It isn't required yet */
				SET_TBL_FREE(pmd_page_kernel(*pmd_1st));
				atomic_long_dec(&mm->nr_ptes);
			}
		}
		BUG_ON(pmd_none(*pmd_1st));
		pte = (pte_t *)(pmd_page_kernel(*pmd_1st) + PAGE_SIZE);
		SET_TBL_ZERO(pte);
		DebugSS("2nd pte:%p\n", pte);
	}
	DebugSS("pmd_populate_sec\n");
	pmd_populate_sec(mm, pmd, pte);
out:
	atomic_long_inc(&mm->nr_ptes);
	spin_unlock(&mm->page_table_lock);
out_pr:
	DebugSS("RES pte:%p pmd:%p pmd_val:0x%lx\n",
			(pte_t *)pmd_page_kernel(*pmd), pmd, pmd_val(*pmd));
	if (ptlp)
		return pte_offset_map_lock(mm, pmd, address, ptlp);

	return pte_offset_map(pmd, address);
}

inline	void
pmd_clear_sec(pmd_t *pmdp)
{
	pmd_t	*pte_tbl = (pmd_t *)pmd_page_kernel(*(pmdp)),
		*pmd_1st, *pm;
	u64	*first_pte_tbl = (u64 *)((u64)pte_tbl & SS_PTE_MASK);
	int	i, ipgd_ind;
	u32	*i386_pgd;

	SET_TBL_FREE(pte_tbl);
	mk_pmd_frozen(pmdp);
	DebugSS("pmd_clear_sec()pmdp:%p pmdv:0x%lx pte_tbl:%p 1st:%p\n",
			pmdp, pmd_val(*pmdp), pte_tbl, first_pte_tbl);
	/*
	 * Here we will determine - are all secondary pte free?
	 * If so we can real clear both pmds & Intel pgd entry.
	 */
	pmd_1st = ((u64)pte_tbl==(u64)first_pte_tbl)?pmdp :(pmd_t *)(pmdp - 1);
	DebugSS("pmd_clear_sec()pmd_1st:%p pmdv:0x%lx\n", pmd_1st,
			pmd_val(*pmd_1st));
	pm = pmd_1st;
	for (i = 0; i < SS_N_PTE; i++) {
		pm = (pmd_t *)(pmd_1st + i);
		if ( !pmd_none(*pm) && !(pmd_frozen(*pm))) {
			DebugSS("+(Nempty)pm:%p v:0x%lx pg[0]:0x%lx\n", pm,
			    pmd_val(*pm), ((u64 *)pmd_page_kernel(*pm))[0]);
			return;
		} else {
			DebugSS("-(empty) pm:%p pmv:0x%lx\n",pm, pmd_val(*pm));
		}	
	}
	for (i = 0; i < SS_N_PTE; i++) {
		pm = (pmd_t *)(pmd_1st + i);
		pmd_clear_kernel(pm);
		DebugSS("pmd_clear_sec pm:%p pmv:0x%lx\n",pm, pmd_val(*pm));
	}
	/* Clear Intel pgd entry */
	i386_pgd = (u32 *)((char *)((u64 )pmdp&SS_PMD_MASK) + 4*PAGE_SIZE);
	ipgd_ind = (int )(((u64 )pmd_1st & (~SS_PMD_MASK)) / (2*sizeof(pmd_t)));
	DebugSS("pmd_clear_sec ipgd:%p ipgd[%d]:0x%x\n",
			i386_pgd, ipgd_ind, i386_pgd[ipgd_ind]);
	i386_pgd[ipgd_ind] = 0;
}

#define PE_SZ	sizeof(pud_t)	/* PUD entry size */

inline void
pud_clear_sec(pud_t *pudp)
{
	pud_t * pud_1st, *tmp;
	u64	p = (u64 )pudp;
	int i;

	SET_TBL_FREE(pud_page(*pudp));
	mk_pud_frozen(pudp);
	pud_1st = (pud_t *)((p & PAGE_MASK) +
		(((p & ~PAGE_MASK)/PE_SZ)&0xffc)*PE_SZ);
	DebugSS("pud_clear_sec()pudp:%p pudv:0x%lx 1st:%p\n",
						pudp, pud_val(*pudp), pud_1st);
	for (i = 0; i < SS_N_PMD; i++) {
		tmp = (pud_t *)(pud_1st + i);
		DebugSS("pud_clear_sec tmp:%p pmv:0x%lx\n",tmp, pud_val(*tmp));
		if (!pud_none(*tmp) && !(pud_frozen(*tmp))) {
			DebugSS("Not all entries are empty\n");
			return;
		}
	}
	for (i = (SS_N_PMD - 1); i >= 0; i--) {
		tmp = (pud_t *)(pud_1st + i);
		pud_clear_kernel(tmp);
		DebugSS("pud*clear_sec tmp:%p pmv:0x%lx\n", tmp, pud_val(*tmp));
	}
	/* Insert empty_sec_pg_dir in mm & CR3 */
	DebugSS("Insert empty_sec_pg_dir in mm & CR3\n");
	reset_secondary_space_page_dir(current->mm);
	DebugSS("EXIT\n");
}

static void do_pte_free(struct mm_struct *mm, pte_t *pte, pgtable_t pte_page)
{
	pte_t *opte;

	free_pte_fast(pte);

	if (TASK_IS_BINCO(current) && is_sec_table(pte) && !IS_UPT_E3S) {
		struct page *another_page, *head_page;
		pte_page =(struct page *)((u64)pte_page & (~TBL_SEC_BIT));
		BUG_ON(!PageCompound(pte_page));
		head_page = compound_head(pte_page);
		DebugSS("pte_page: %p head: %p\n",
			pte_page, head_page);
		if (head_page == pte_page) {
			another_page = head_page + 1;
		} else {
			another_page = head_page;
			BUG_ON(pte_page != head_page + 1);
		}
		DebugSS("tail_page: %p order: %d SS order: %d\n",
			another_page, compound_order(head_page),
			(int)SS_PTE_ORDER);
		opte = page_address(another_page);
		DebugSS("opte[0]:0x%lx\n", ((u64 *)opte)[0]);
		if (TBL_IS_FREE(opte)) {
			DebugSS("BOTH SEC pte are free -> "
				"__free_pages()  REAL FREE !\n ");
			pgtable_page_dtor(head_page);
			__free_pages(head_page, SS_PTE_ORDER);
		} else {
			DebugSS("ANOTHER SEC pte isn't free\n ");
		}
	}
}

void pte_free(struct mm_struct *mm, pgtable_t pte_page)
{
	do_pte_free(mm, page_address(pte_page), pte_page);
}

void pte_free_kernel(struct mm_struct *mm, pte_t *pte)
{
	do_pte_free(mm, pte, virt_to_page(pte));
}

inline void
pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	free_pmd_fast(pmd);

	if (TASK_IS_BINCO(current) && is_sec_table(pmd) && !IS_UPT_E3S) {
		int i;
		pmd_t *pm, *pm1;

		DebugSS("pmd_free pmd:%p\n", pmd);
	/*
	 * Here we will determine - are all secondary pmd free?
	 * If so we can real free pmd tables and clear all(4) puds.
	 */
		pm1 = (pmd_t *)(((u64 )pmd & SS_PMD_MASK) & (~TBL_SEC_BIT));
		for (i = 0; i < SS_N_PMD; i++) {
			pm = (pmd_t *)(pm1 + PTRS_PER_PMD*i);
			DebugSS("pmd_free pm:%p val:0x%lx\n",pm, pmd_val(*pm));
			if (!TBL_IS_FREE(pm)) {
				DebugSS("pmd_free pmd table is NOT free\n");
				return;
			}
		}
		DebugSS("pmd_free -> REAL free_pages(before)\n");
		free_pages((unsigned long)pm1, SS_PMD_ORDER);
		DebugSS("\n==========pmd_free -> REAL free_pages(after)\n");
	}
}

static inline
i386_pgd_t *get_i386_pgd(struct vm_area_struct *vma)
{
        pgd_t		*pgd;
        pud_t		*pud;
        pmd_t		*pmd;
	i386_pgd_t	*i386_pgd  = NULL;

	pgd = pgd_offset(vma->vm_mm, SS_ADDR_START);
	if (pgd_none(*pgd)) {
		DebugSS("pgd_none\n");
		goto out_null;
	}
	pud = pud_offset(pgd, SS_ADDR_START);
	if (pud_none(*pud)) {
		DebugSS("pud_none\n");
		goto out_null;
	}
	pmd = (pmd_t *)(pud_page(*pud));
	if (!pmd) {
		DebugSS("!pmd\n");
		goto out_null;
	}
	i386_pgd = (i386_pgd_t *)((char *)pmd + PAGE_SIZE*4);
out_null:
	return i386_pgd;
}

void set_pte_at_binco(unsigned long addr, pte_t *ptep, pte_t pteval)
{
	if (ADDR_IN_SS(addr) && !IS_UPT_E3S) {
		/*
		 * In this case we should set pte entry for both - E2K&INTEL pte
		 */
		u64		t = (u64)ptep & PTE_MASK;
		i386_pte_t	*iptep;
		u32		val = i386_PAGE_PRESENT | i386_PAGE_USER;
		u32		pfn = ((u32) pte_val(pteval)) & i386_PTE_MASK;
		i386_pte_t	entry;
		
		if (_PAGE_PFN_TO_PADDR(pte_val(pteval)) != pfn) {
			pr_alert("Intel page out of 32 address space pteval = %llx\n",
				pte_val(pteval));
			WARN_ON(1);
		}
		if (pte_val(pteval))
			DebugSS("addr:0x%lx ptep:%p entry:0x%lx\n",
				addr,	ptep, pte_val(pteval));
		t = IS_FIRST_PTE(addr)? (t + PAGE_SIZE * 2) : (t + PAGE_SIZE);
		iptep = (i386_pte_t *)t + i386_pte_index(addr);
		if (!pte_present(pteval)) {
			i386_set_pte(iptep, i386__pte(0));
			return;
		}
		if (pte_write(pteval))
			val |= i386_PAGE_RW;
		if (pte_dirty(pteval))
			val |= i386_PAGE_DIRTY;
		if (pte_young(pteval))
			val |= i386_PAGE_ACCESSED;
		entry = i386__pte(pfn | val);
		i386_set_pte(iptep, entry);
		DebugSS("0x%lx iptep:%p entry:0x%x\n", t, iptep, pfn|val);
	}
}

#if defined(CONFIG_SECONDARY_SPACE_SUPPORT) && !defined(CONFIG_NUMA)
struct page *binco_alloc_pages(gfp_t gfp_mask, unsigned int order,
			       unsigned long addr)
{
	if (TASK_IS_BINCO(current) && !IS_UPT_E3S && ADDR_IN_SS(addr)) {
		gfp_mask &= ~GFP_ZONEMASK;
		gfp_mask |= __GFP_IA32;
	}

	return alloc_pages(gfp_mask, order);
}
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT && ! CONFIG_NUMA */

/* Verbouse variant */
void
verify_SS_addr(e2k_addr_t addr)
{
	i386_pgd_t		*ipgd, *i386_pgd, *cr3_pgd;
	i386_pte_t		*ipte;
	int			ind;
	struct task_struct	*tsk = current;
	struct mm_struct	*mm = tsk->mm;
        pgd_t			*pgd;
        pud_t			*pud;
        pmd_t			*pmd, *pmd_pg;
	pte_t			*pte;
	u32			iaddr = addr - SS_ADDR_START, iptev, pfn;
	u64			ptev;
	u64			*MPT, mpt_word, mpt_addr;

	if (mm == NULL) {
		printk("verify_SS_addr() - mm==NULL\n");
		return;
	}
	if (!ADDR_IN_SS(addr)) {
		printk("verify_SS_addr() -!ADDR_IN_SS\n");
		return;
	}
	printk("verify_SS_addr() mm:%p\n", mm);
	ind = pud_index((addr - (SS_ADDR_START &(~PGDIR_MASK))));
	spin_lock(&mm->page_table_lock);
	pgd = pgd_offset(mm, addr);
	printk("verify_SS_addr() pgd:%p pgd_val:0x%lx \n", pgd, pgd_val(*pgd));
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		spin_unlock(&mm->page_table_lock);
		printk("verify_SS_addr()-pgd_none_bad:0x%lx\n", pgd_val(*pgd));
		return;
	}
	pud = pud_offset(pgd, addr);
	printk("verify_SS_addr() pud:%p pud_val:0x%lx\n", pud, pud_val(*pud));
	if (pud_none(*pud) || pud_bad(*pud)) {
		spin_unlock(&mm->page_table_lock);
		printk("verify_SS_addr()-pud_none_bad:0x%lx\n", pud_val(*pud));
		return;
	}
	pmd_pg = (pmd_t *)(pud_page(*pud));
	printk("verify_SS_addr() pmd_pg:%p\n", pmd_pg);
	if (!pmd_pg || !is_sec_table(pmd_pg)) {
		spin_unlock(&mm->page_table_lock);
		printk("verify_SS_addr() - pmd_pg invalid\n"); 
		return;
	}
	pmd_pg = (pmd_t *)((u64 )pmd_pg & (~TBL_SEC_BIT));
	/* 1st way of getting i386_pgd - via e2k page table tree */
	ipgd = (i386_pgd_t *)((char *)pmd_pg + PAGE_SIZE*(4 - ind));
	printk("verify_SS_addr() ipgd:%p  mm->sec_pgd:%p\n", ipgd, mm->sec_pgd);
	/* 2nd way of getting i386_pgd - via CR3 register */
	cr3_pgd = (i386_pgd_t *)(u64 )get_MMU_CR3_RG();
	printk("verify_SS_addr()  cr3_pgd:%p \n", cr3_pgd);
	if ((u64)(cr3_pgd) != __pa(ipgd)) {
		spin_unlock(&mm->page_table_lock);
		printk("verify_SS_addr() ipgd:%p cr3_pgd:%p mm:%p sec_pgd:%p\n",
 			ipgd, cr3_pgd, mm, mm->sec_pgd);
		return;
	}
	pmd = pmd_offset(pud, addr);
	printk("verify_SS_addr() pmd:%p pmd_val:0x%lx\n", pmd, pmd_val(*pmd));
	if (pmd_none(*pmd) || pmd_bad(*pmd)) {
		spin_unlock(&mm->page_table_lock);
		printk("verify_SS_addr()-pmd_none_bad:0x%lx\n", pmd_val(*pmd));
		return;
	}
	pte = pte_offset_kernel(pmd, addr);
	ptev = pte_val(*pte);
	printk("verify_SS_addr() pte:%p pte_val:0x%lx\n", pte, ptev);
	i386_pgd = ipgd + i386_pgd_index(iaddr);
	printk("verify_SS_addr() i386_pgd:%p\n", i386_pgd);
	if (!i386_pgd_val(*i386_pgd)) {
		spin_unlock(&mm->page_table_lock);
		printk("verify_SS_addr()-!i386_pgd_val\n");
		return;
	}
	ipte = i386_pte_offset_kernel(i386_pgd, iaddr);
	iptev = i386_pte_val(*ipte);
	printk("verify_SS_addr() ipte:%p v:0x%x\n", ipte, iptev);
	/* E2K pte and INTEL pte must point at the same physical page */
	if (_PAGE_PFN_TO_PADDR(ptev) != (iptev & i386_PAGE_MASK)) {
		spin_unlock(&mm->page_table_lock);
		printk("verify_SS_addr()ptev:0x%lx iptev:0x%x\n", ptev, iptev);
		return;
	}
	/* bit # PAGE_PFN in MPT must be 1 */
	pfn = pte_pfn(*pte);
	mpt_addr = get_MMU_MPT_B();
	if (mpt_addr != phys_mpt_base) {
		spin_unlock(&mm->page_table_lock);
		printk("verify_SS_addr() mpt_addr:0x%lx phys_mpt_base:0x%lx\n",
			mpt_addr, phys_mpt_base);
		return;
	}
	MPT = (u64 *)__va(get_MMU_MPT_B());
	mpt_word = MPT[pfn >> 6];
	if (mpt_word != 0xffffffffffffffffUL) {
		spin_unlock(&mm->page_table_lock);
		printk("verify_SS_addr() mpt_word:0x%lx\n", mpt_word);
		return;
	}
	spin_unlock(&mm->page_table_lock);
	printk("verify_SS_addr(0x%lx) OK ptev:0x%lx iptev:0x%x MPT_w:0x%lx\n",
		addr, ptev, iptev, mpt_word);
	print_va_tlb(addr, 0);print_va_tlb(addr -SS_ADDR_START, 0);
}

inline struct page *
get_i386_pages(int order)
{
	u64 res;
	u64 *a;
	int i, max = (order == SS_PMD_ORDER) ? SS_N_PMD : SS_N_PTE;
	struct page * page;

	page = alloc_pages(SS_ALLOC_FLAG, order);
	BUG_ON(!page);
	BUG_ON(((page->flags)&__GFP_COMP) == 0);
	res = (unsigned long) page_address(page);
	BUG_ON(__pa(res) & (~ADDR32_MASK));
	DebugSS(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
	for (i = 0; i < max; i++) {
		a = (u64 *)((char *)res + i*PAGE_SIZE);
		SET_TBL_FREE(a);
		DebugSS("get_i386_pages a:%p a[0]:0x%lx\n", a, *a);
	}
	DebugSS(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
	return page;
}

#if 0
void print_sec()
{
	i386_pgd_t 		*ipgd;
	struct mm_struct	*mm = current->mm;
	int i, j, k;
        pgd_t			*pgd;
        pud_t			*cpud;
        pmd_t			*cpmd;
	pte_t			*cpte;

	if (!IN_INTEL_MODE) {
		printk("\n==EMPTY SECONDARY SPACE==\n");
		return;
	}
	spin_lock(&mm->page_table_lock);
	ipgd = (i386_pgd_t *)__va((u64 )get_MMU_CR3_RG());
	printk("\n================ INTEL pgd ==================\n");
	for (i = 0; i < i386_PTRS_PER_PGD; i++, ipgd++) {
		    if(i386_pgd_val(*ipgd))
			printk("ipgd[%d] = 0x%x\n", i, i386_pgd_val(*ipgd));
	}
	printk("===============================================\n");
	pgd = pgd_offset(mm, SS_ADDR_START);
	if (pgd_none(*pgd)) {
		printk("print_sec() sec pgd_none\n");
		spin_unlock(&mm->page_table_lock);
		return;
	}
	printk("\n================ PRIMARY ADDR pgdv:0x%lx\n", pgd_val(*pgd));
	cpud = pud_offset(pgd, SS_ADDR_START);
	for (i=0; i<4;i++,cpud++) {
	  printk("pud[%d] = 0x%lx\n", i, pud_val(*cpud));
	  if(_PAGE_PFN_TO_PADDR(pud_val(*cpud))){
	    cpmd = (pmd_t *)(pud_page(*cpud));
	    for (j=0; j<PTRS_PER_PMD;j++,cpmd++) {
	      if(_PAGE_PFN_TO_PADDR(pmd_val(*cpmd))){
		printk("    pmd[%d] = 0x%lx\n", j, pmd_val(*cpmd));
		cpte = (pte_t *)pmd_page_kernel(*cpmd);
		for (k=0; k<PTRS_PER_PTE;k++,cpte++) {
		  if(_PAGE_PFN_TO_PADDR(pte_val(*cpte))){
			//printk("        pte[%d] = 0x%lx\n",k,pte_val(*cpte));
		  }
		}
	      }
	    }
	  }
	}
	printk("\n=====================================\n");
	spin_unlock(&mm->page_table_lock);
}

static void verify_pmd(pmd_t *pmdp, pmd_t pmdv, int op);
static void
verify_pmd(pmd_t *pmdp, pmd_t pmdv, int op)
{
	static pmd_t		**ptrs;
	static pmd_t		*vals;
	static int		pte_ind, amnt;
	int			i, mask = GFP_KERNEL|__GFP_ZERO;
	struct mm_struct	*mm = current->mm; 

#define P_PFN(x)	(((u64)pmd_val(x))&_PAGE_PFN)
	pmdp = (pmd_t *)((u64 )pmdp&(~TBL_SEC_BIT));
	CHECK_PT_LOCKED(mm);
	if (op == 0) { /* insert & verify */
		if (!ptrs) {
			ptrs = (pmd_t **)__get_free_pages(mask, 2);
			vals = (pmd_t *) __get_free_pages(mask, 2);
			BUG_ON(	!ptrs || !vals);
		} else if (!amnt) {
			WARN_ON(1);
		}
		for (i = 0; i < pte_ind; i++) {
		    if (P_PFN((pmdv)) == P_PFN(vals[i])) {
			printk("DUP%d pmdv:0x%lx v[i]:0x%lx pmdp:%p p[i]:%p"
				" pte_ind:%d  amnt:%d\n",
			    i, pmd_val(pmdv), pmd_val(vals[i]), pmdp, ptrs[i],
			    pte_ind, amnt);
			BUG();
		    }
		}
		ptrs[pte_ind] = pmdp;
		vals[pte_ind] = pmdv;
		pte_ind++;
		amnt++;
		printk("++ADD%d pmdv:0x%lx v[i]:0x%lx pmdp:%p p[i]:%p"
			" pte_ind:%d  amnt:%d\n", i, pmd_val(pmdv),
			    pmd_val(vals[i]), pmdp, ptrs[i], pte_ind, amnt);
	} else if (op == 1) { /* remove & verify */
		if (!pte_ind)
			BUG();
		for (i = 0; i < pte_ind; i++) {
			if ((u64 )pmdp == (u64 )ptrs[i])
				break;
		}
		if ((u64 )pmdp != (u64 )ptrs[i]) {
		    printk("NO-pmdp%d pmdv:0x%lx v[i]:0x%lx pmdp:%p p[i]:%p"
			   " pte_ind:%d  amnt:%d\n",
			    i, pmd_val(pmdv), pmd_val(vals[i]), pmdp, ptrs[i],
			    pte_ind, amnt);
		    BUG();
		}
		if (P_PFN((pmdv)) != P_PFN(vals[i])) {
		    printk("DIFF-pmdv%d pmdv:0x%lx v[i]:0x%lx pmdp:%p p[i]:%p"
			   " pte_ind:%d  amnt:%d\n",
			    i, pmd_val(pmdv), pmd_val(vals[i]), pmdp, ptrs[i],
			    pte_ind, amnt);
		    BUG();
		}
		ptrs[i] = (pmd_t *)0;
		vals[i] = __pmd(0);
		if (!amnt)
			BUG();
		amnt--;
		if (i == (pte_ind - 1))
			pte_ind--;
		printk("--RM i:%d pmdv:0x%lx v[i]:0x%lx pmdp:%p p[i]:%p"
		       " pte_ind:%d  amnt:%d\n",i,pmd_val(pmdv),
		       pmd_val(vals[i]), pmdp, ptrs[i],pte_ind, amnt);
	} else if (op == 2) { /* free & verify */
		if (amnt)
			BUG();
		free_pages((unsigned long)ptrs, 2);
		free_pages((unsigned long)vals, 2);
		ptrs = NULL;
		vals = NULL;
		pte_ind = 0;
		printk("verify_pmd() - FREE\n");
	} else {
		printk("verify_pmd() - my bug\n");
		BUG();
	}
}
#endif
#else	/* !CONFIG_SECONDARY_SPACE_SUPPORT */
pmd_t *
pmd_alloc_cont(struct mm_struct *mm, pud_t *pud, unsigned long address) {

	return NULL;
}

pte_t *
pte_alloc_cont(struct mm_struct *mm, pmd_t *pmd, unsigned long address, 
							spinlock_t **ptlp) {

	return NULL;
}
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */

void print_va_tlb(e2k_addr_t addr, int large_page)
{
	int set;
	for (set = 0; set < E2K_TLB_SETS_NUM; set ++) {
		tlb_tag_t tlb_tag;
		pte_t tlb_entry;
		tlb_tag = read_DTLB_va_tag_reg(addr, set, large_page);
		pte_val(tlb_entry) = read_DTLB_va_entry_reg(addr, set,
								large_page);
		printk("TLB addr 0x%lx : set #%d tag 0x%016lx entry "
			"0x%016lx\n",
			addr, set, tlb_tag_val(tlb_tag), pte_val(tlb_entry));
	}
}

pte_t *node_pte_alloc_kernel(int nid, pmd_t *pmd, e2k_addr_t address)
{
	struct mm_struct *mm = &init_mm;
	pte_t *new;

	new = node_pte_alloc_one_kernel(nid, mm, address);
	if (!new)
		return NULL;
	spin_lock(&mm->page_table_lock);
	if (!pmd_present(*pmd)) {
		pmd_populate_kernel(mm, pmd, new);
		new = NULL;
	}
	spin_unlock(&mm->page_table_lock);
	if (new)
		node_pte_free_kernel(nid, new);
	return pte_offset_kernel(pmd, address);
}

pmd_t *node_pmd_alloc_kernel(int nid, pud_t *pud, e2k_addr_t address)
{
	struct mm_struct *mm  = &init_mm;
	pmd_t *new;

	new = node_pmd_alloc_one_kernel(nid, mm, address);
	if (!new)
		return NULL;
	spin_lock(&mm->page_table_lock);
	if (!pud_present(*pud)) {
		pud_populate_kernel(mm, pud, new);
		new = NULL;
	}
	spin_unlock(&mm->page_table_lock);
	if (new) {
		node_pmd_free_kernel(nid, new);
	}
	return pmd_offset_kernel(pud, address);
}

pud_t *node_pud_alloc_kernel(int nid, pgd_t *pgd, e2k_addr_t address)
{
	struct mm_struct *mm = &init_mm;
	pud_t *new;

	new = node_pud_alloc_one_kernel(nid, mm, address);
	if (!new)
		return NULL;
	spin_lock(&mm->page_table_lock);
	if (!pgd_present(*pgd)) {
		node_pgd_populate_kernel(nid, mm, pgd, new);
		new = NULL;
	}
	spin_unlock(&mm->page_table_lock);
	if (new) {
		node_pud_free_kernel(nid, new);
	}
	return pud_offset_kernel(pgd, address);
}

pmd_t * pmd_alloc_kernel(struct mm_struct *mm, pud_t *pud,
					e2k_addr_t address)
{
	if (mm != &init_mm)
		BUG();
	return node_pmd_alloc_kernel(numa_node_id(), pud, address);
}

pud_t * pud_alloc_kernel(struct mm_struct *mm, pgd_t *pgd,
					e2k_addr_t address)
{
	if (mm != &init_mm)
		BUG();
	return node_pud_alloc_kernel(numa_node_id(), pgd, address);
}

#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
pgd_t *
node_pgd_offset_kernel(int nid, e2k_addr_t virt_addr)
{
	int node_cpu = node_to_first_present_cpu(nid);

	return the_cpu_pg_dir(node_cpu) + pgd_index(virt_addr);
}

/*
 * Set specified kernel pgd entry to point to next-level page table PUD
 * Need populate the pgd entry into follow root page tables:
 *	- all CPUs of the specified node;
 *	- all CPUs of other nodes which have not own copy of kernel image
 *	  (DUP KERNEL) and use duplicated kernel of this node
 */
void node_pgd_set_k(int the_node, pgd_t *the_pgdp, pud_t *pudp)
{
	pgd_t pgd = mk_pgd_phys_k(pudp);
	pgd_t *pgdp;
	int pgd_index = pgd_to_index(the_pgdp);
	int dup_node;
	int node;
	nodemask_t node_mask;
	int cpu;
	cpumask_t node_cpus;

	if (!THERE_IS_DUP_KERNEL) {
		kernel_root_pt[pgd_index] = pgd;
		DebugNUMA("set kernel root PT pgd "
			"entry 0x%p to pud 0x%p\n",
			&kernel_root_pt[pgd_index], pudp);
		return;
	}

	node_cpus = node_to_present_cpumask(the_node);
	DebugNUMA("node #%d online cpu mask 0x%lx pgd %p == 0x%llx\n",
		the_node, node_cpus.bits[0],
		the_pgdp, pgd_val(*the_pgdp));
	/*
	 * Set pgd entry at root PTs of all CPUs of the node
	 */
	for_each_cpu_of_node(the_node, cpu, node_cpus) {
		pgdp = the_cpu_pg_dir(cpu);
		DebugNUMA("set the node #%d CPU #%d pgd "
			"entry 0x%p to pud 0x%p\n",
			the_node, cpu, &pgdp[pgd_index], pudp);
		if (!pgd_none(pgdp[pgd_index])) {
			E2K_LMS_HALT_OK;
			pr_err("node_pgd_set_k() pgd %p is not empty 0x%lx\n",
				&pgdp[pgd_index], pgd_val(pgdp[pgd_index]));
			BUG();
		}
		pgdp[pgd_index] = pgd;
	}
	if (DUP_KERNEL_NUM >= phys_nodes_num) {
		DebugNUMA("all %d nodes have duplicated "
			"kernel so own root PT\n",
			DUP_KERNEL_NUM);
		return;
	}
	/*
	 * Set pgd entry at root PTs of all CPUs of a node on which
	 * this node has duplicated kernel
	 */
	dup_node = node_dup_kernel_nid(the_node);
	if (dup_node != the_node) {
		for_each_cpu_of_node(dup_node, cpu, node_cpus) {
			pgdp = the_cpu_pg_dir(cpu);
			DebugNUMA("set home node #%d "
				"CPU #%d pgd entry 0x%p to pud 0x%p\n",
				dup_node, cpu, &pgdp[pgd_index], pudp);
			if (!pgd_none(pgdp[pgd_index])) {
				pr_err("node_pgd_set_k() pgd %p is not empty 0x%lx\n",
					&pgdp[pgd_index],
					pgd_val(pgdp[pgd_index]));
				BUG();
			}
			pgdp[pgd_index] = pgd;
		}
	}
	/*
	 * Set pgd entry at root PTs of all CPUs of all other nodes,
	 * which has duplicated kernel on the same node as this node
	 */
	for_each_node_has_not_dup_kernel(node, node_mask) {
		if (node == the_node)
			continue;
		if (node_dup_kernel_nid(node) != dup_node)
			continue;
		for_each_cpu_of_node(node, cpu, node_cpus) {
			pgdp = the_cpu_pg_dir(cpu);
			DebugNUMA("set other node #%d "
				"CPU #%d pgd entry 0x%p to pud 0x%p\n",
				node, cpu, &pgdp[pgd_index], pudp);
			if (!pgd_none(pgdp[pgd_index])) {
				pr_err("node_pgd_set_k() pgd %p is not empty 0x%lx\n",
					&pgdp[pgd_index],
					pgd_val(pgdp[pgd_index]));
				BUG();
			}
			pgdp[pgd_index] = pgd;
		}
	}
}
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

/*
 * Simplistic page force to be valid
 */

#ifdef CONFIG_HUGETLB_PAGE
static int
e2k_make_pte_large_pages_valid(struct vm_area_struct *vma, pmd_t *pmd,
	e2k_addr_t addr, int chprot)
{	
	pte_t *pte = (pte_t *)pmd;
	int set_invalid = 0;

	if (!(pgprot_val(vma->vm_page_prot) & _PAGE_VALID))
		set_invalid = 1;

	DebugPT("started from 0x%lx for "
		"pte 0x%lx\n",
		addr, pte);

	if ((!set_invalid) && pte_valid(*pte)) {
		DebugPT("pte 0x%p "
			"== 0x%lx is valid already\n",
			pte, pte_val(*pte));
		return 0;
	}
	
	if (set_invalid && (!pte_valid(*pte)))
		return 0;

	if (!pmd_none(*pmd)) {
		if (!chprot) {
			printk("e2k_make_pte_large_pages_valid() pte 0x%p "
				"== 0x%lx exists already\n",
				pte, pte_val(*pte));
			BUG();
			return -EINVAL;
		}
		set_pte_at(vma->vm_mm, addr, pte,
				mk_pte_pgprot(*pte, vma->vm_page_prot));
	} else {
		/*  We just set _PAGE_VALID and _PAGE_HUGE here. Do not use
		 *  vm_page_prot to make sure that huge_pte_none() will still
		 *  return true for this pte.
		 */
		set_pte_at(vma->vm_mm, addr, pte,
			   __pte(pte_val(*pte) | _PAGE_VALID | _PAGE_HUGE));
	}
	
	DebugPT("sets pte 0x%p "
		"to not present page 0x%lx for address 0x%lx\n",
		pte, pte_val(*pte), addr);

	return 0;
}
#endif /* CONFIG_HUGETLB_PAGE */

static int
e2k_make_pte_pages_valid(struct vm_area_struct *vma, pmd_t *pmd,
	e2k_addr_t start_addr, e2k_addr_t end, int chprot)
{
	e2k_addr_t	address = start_addr;
	spinlock_t	*ptl;
	pte_t		*pte;

	int set_invalid = 0;

	if (!(pgprot_val(vma->vm_page_prot)&_PAGE_VALID))
		set_invalid = 1;

	DebugPT("started from 0x%lx to 0x%lx\n",
		start_addr, end);
	pte = pte_offset_map_lock(vma->vm_mm, pmd, address, &ptl);
	do {
		if ((!set_invalid) && pte_valid(*pte)) {
			DebugPT("pte 0x%p "
				"== 0x%lx is valid already\n",
				pte, pte_val(*pte));
			continue;
		}
		if (set_invalid && (!pte_valid(*pte)))
			continue;

		if (!pte_none(*pte)) {
			if (!chprot) {
				pte_unmap_unlock(pte, ptl);
				printk("e2k_make_pte_pages_valid() pte 0x%p "
					"== 0x%lx exists already\n",
					pte, pte_val(*pte));
				BUG();
				return -EINVAL;
			}
			
			set_pte_at(vma->vm_mm, address, pte,
				    mk_pte_pgprot(*pte, vma->vm_page_prot));

		} else {
			pte_t ptev = *pte;

			/*
			 * We change _PAGE_VALID only here. Do not use
			 * vm_page_prot to make sure that pte_none()
			 * will still return true for this pte.
			 */
			if (set_invalid)
				ptev = __pte(pte_val(ptev) & !_PAGE_VALID);
			else
				ptev = __pte(pte_val(ptev) | _PAGE_VALID);

			set_pte_at(vma->vm_mm, address, pte, ptev);
		}
		DebugPT("sets pte 0x%p "
			"to not present page 0x%lx for address 0x%lx\n",
			pte, pte_val(*pte), address);
	} while (pte ++, address += PAGE_SIZE, (address < end));
	pte_unmap_unlock(pte - 1, ptl);

	DebugPT("finished OK\n");

	return 0;
}

static int
e2k_make_pmd_pages_valid(struct vm_area_struct *vma, pud_t *pud,
	e2k_addr_t start_addr, e2k_addr_t end, int chprot)
{
	e2k_addr_t	address = start_addr;
	e2k_addr_t	next;
	pmd_t		*pmd;
	int		ret = 0;
	
	DebugPT("started from 0x%lx to 0x%lx\n",
		start_addr, end);
	pmd = pmd_offset(pud, address);
	
	do {
		next = pmd_addr_end(address, end);

#ifdef CONFIG_HUGETLB_PAGE
		if (is_vm_hugetlb_page(vma)) {
			DebugPT("will make pte "
				"range large pages valid from address 0x%lx to"
				" 0x%lx\n",
				address, next);
			ret = e2k_make_pte_large_pages_valid(
						vma, pmd, address, chprot);
			if (ret != 0)
				return ret;
		} else
#endif /* CONFIG_HUGETLB_PAGE */
		if (pmd_none(*pmd)
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
			|| (!IS_UPT_E3S && pmd_frozen(*pmd))
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */
		) {
			DebugPT("will "
				"pte_alloc_map(0x%p) for addr 0x%lx\n",
				pmd, address);
			if (!pte_alloc_map(vma->vm_mm, vma, pmd, address)) {
				DebugPT("could not "
					"alloc pte page for addr 0x%lx\n",
					address);
				return -ENOMEM;
			}
		} else if (pmd_bad(*pmd)) {
			pmd_ERROR(*pmd);
			BUG();
			return -EINVAL;
		}

#ifdef CONFIG_HUGETLB_PAGE
		if (!is_vm_hugetlb_page(vma)) {
#endif /* CONFIG_HUGETLB_PAGE */
			DebugPT("will make pte "
				"range pages valid from address 0x%lx to "
				"0x%lx\n",
				address, next);
			ret = e2k_make_pte_pages_valid(vma, pmd, address,	
								next, chprot);
			if (ret != 0)
				return ret;
#ifdef CONFIG_HUGETLB_PAGE
		}
#endif /* CONFIG_HUGETLB_PAGE */
	} while (pmd ++, address = next, (address < end));

	DebugPT("finished OK\n");

	return 0;
}

static int
e2k_make_pud_pages_valid(struct vm_area_struct *vma, pgd_t *pgd,
	e2k_addr_t start_addr, e2k_addr_t end, int chprot)
{
	e2k_addr_t	address = start_addr;
	e2k_addr_t	next;
	pud_t		*pud;
	int		ret = 0;
	u64		ss_mask =0;

	DebugPT("started from 0x%lx to 0x%lx\n",
		start_addr, end);

	if (TASK_IS_BINCO(current) && ADDR_IN_SS(start_addr) && !IS_UPT_E3S)
		ss_mask = TBL_SEC_BIT;

	pud = pud_offset(pgd, address);
	do {

		next = pud_addr_end(address, end);
		if (pud_none(*pud)
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
			|| (!IS_UPT_E3S && pud_frozen(*pud))
#endif
		) {
			DebugPT("will "
				"pmd_alloc(0x%p) for addr 0x%lx\n",
				pud, address|ss_mask);
			if (!pmd_alloc(vma->vm_mm, pud, address|ss_mask)) {
				DebugPT("could not "
					"alloc pmd for addr 0x%lx\n",
					address);
				return -ENOMEM;
			}
		} else if (pud_bad(*pud)) {
			pud_ERROR(*pud);
			BUG();
			return -EINVAL;
		}

		DebugPT("will make pmd range "
			"pages valid from address 0x%lx to 0x%lx\n",
			address, next);
		ret = e2k_make_pmd_pages_valid(vma, pud, address, next, chprot);
		if (ret != 0)
			return ret;

	} while (pud ++, address = next, (address < end));

	DebugPT("finished OK\n");

	return 0;
}

static int
e2k_make_vma_pages_valid(struct vm_area_struct *vma,
	e2k_addr_t start_addr, e2k_addr_t end_addr, int chprot, int flush)
{
	e2k_addr_t	address = start_addr;
	pgd_t		*pgd;
	e2k_addr_t	next;
	int		ret = 0;

	DebugPT("started from 0x%lx to 0x%lx\n",
		start_addr, end_addr);
	pgd = pgd_offset(vma->vm_mm, address);
	do {
		next = pgd_addr_end(address, end_addr);
		if (pgd_none(*pgd)) {
			DebugPT("will "
				"pud_alloc(0x%p) for addr 0x%lx\n",
				pgd, address);
			if (!pud_alloc(vma->vm_mm, pgd, address)) {
				DebugPT("could not "
					"alloc pud for addr 0x%lx\n",
					address);
				return -ENOMEM;
			}
		} else if (pgd_bad(*pgd)) {
			pgd_ERROR(*pgd);
			BUG();
			return -EINVAL;
		}

		DebugPT("will make pud range pages "
			"valid from address 0x%lx to 0x%lx\n",
			address, next);
		ret = e2k_make_pud_pages_valid(vma, pgd, address, next, chprot);
		if (ret != 0) {
			return ret;
		}

	} while (pgd ++, address = next, (address < end_addr));
	
	/*
	 * Semispeculative requests can access on virtual addresses
	 * from this validated VM area while this addresses were not
	 * exist yet and write invalid TLB entry (valid bit = 0)
	 * So it need flush same TLB entries for all VM area
	 */
	if (flush) {
		DebugPT("flush TLB from 0x%lx "
			"to 0x%lx\n", start_addr, end_addr);
		flush_tlb_range_and_pgtables(vma->vm_mm, start_addr, end_addr);
	}

	DebugPT("finished OK\n");

	return 0;
}

int
e2k_make_pages_valid(unsigned long start_addr, unsigned long end_addr)
{
	struct mm_struct	*mm = current->mm;
	struct vm_area_struct	*vma;
	e2k_addr_t		addr, end;
	int			ret;

	DebugPT("started addr 0x%lx end 0x%lx\n",
		start_addr, end_addr);
	if (start_addr > end_addr) {
		printk("e2k_make_pages_valid() start addr 0x%lx > end 0x%lx\n",
			start_addr, end_addr);
		BUG();
		return -EINVAL;
	} else if (start_addr == end_addr) {
		DebugPT("start addr 0x%lx == end 0x%lx "
			": no any actions\n",
			start_addr, end_addr);
		return 0;
	}
	addr = start_addr;
	down_write(&mm->mmap_sem);
	do {
		vma = find_vma(mm, addr);
		DebugPT("find vma 0x%p for addr 0x%lx\n",
			vma, addr);
		if (vma == NULL || addr < vma->vm_start) {
			printk("e2k_make_pages_valid() could not found VMA "
				"structure for start addr 0x%lx\n",
				addr);
			up_write(&mm->mmap_sem);
			BUG();
			return -EINVAL;
		}
		end = end_addr;
		if (end > vma->vm_end)
			end = vma->vm_end;
		ret = e2k_make_vma_pages_valid(vma, addr, end, 0, 1);
		if (ret != 0) {
			up_write(&mm->mmap_sem);
			return ret;
		}
		addr = end;
	} while (addr < end_addr);
	up_write(&mm->mmap_sem);

	DebugPT("finished OK\n");
	return 0;
}

int
make_vma_pages_valid(struct vm_area_struct *vma,
	unsigned long start_addr, unsigned long end_addr)
{
	int			ret;

	DebugPT("started for VMA 0x%p from start addr "
		"0x%lx to end addr 0x%lx\n",
		vma, start_addr, end_addr);

	ret = e2k_make_vma_pages_valid(vma, start_addr, end_addr, 0, 1);
	if (ret != 0) {
		DebugPT("finished with error %d\n",
			ret);
		return ret;
	}

	DebugPT("finished OK\n");
	return 0;
}

int
make_all_vma_pages_valid(struct vm_area_struct *vma, int chprot, int flush)
{
	int			ret;

	DebugPT("started for VMA 0x%p\n",
		vma);

	DebugPT("will start "
		"e2k_make_vma_pages_valid() from start addr 0x%lx to end "
		"addr 0x%lx\n",
		vma->vm_start, vma->vm_end);
	ret = e2k_make_vma_pages_valid(vma, vma->vm_start, vma->vm_end,
			chprot, flush);
	if (ret != 0) {
		DebugPT("finished with error %d\n",
			ret);
		return ret;
	}

	DebugPT("finished OK\n");

#if DEBUG_SS_MODE
	/* Final verification */
	if (TASK_IS_BINCO(current) && ADDR_IN_SS(vma->vm_start) && 
								!IS_UPT_E3S) {
		i386_pgd_t * ipgd;
		int i;

		spin_lock(&vma->vm_mm->page_table_lock);
		ipgd = get_i386_pgd(vma);
		if (!ipgd) {
			printk("NULL INTEL PGD\n");
			spin_unlock(&vma->vm_mm->page_table_lock);
			BUG();
		}
		DebugSS("===============================================\n");
		DebugSS("%p cr3:0x%lx\n", ipgd, (u64 )get_MMU_CR3_RG());
		for (i = 0; i < i386_PTRS_PER_PGD; i++, ipgd++) {
		    if(i386_pgd_val(*ipgd))
			DebugSS("ipgd[%d] = 0x%x\n", i, i386_pgd_val(*ipgd));
		}
		DebugSS("===============================================\n");
		spin_unlock(&vma->vm_mm->page_table_lock);
	}
#endif /* DEBUG_SS_MODE == 1 */

	return 0;
}

int e2k_set_vmm_cui(struct mm_struct *mm, int cui,
		unsigned long code_base, unsigned long code_end)
{
	struct vm_area_struct	*vma, *prev;
	int 			ret;
	unsigned long		vm_flags;

	down_write(&mm->mmap_sem);
	vma = find_vma_prev(mm, code_base, &prev);
	if (!vma || vma->vm_start > code_base || vma->vm_end < code_end) {
		pr_err("No vma for 0x%lx : 0x%lx (found vma %lx : %lx)\n",
				code_base, code_end, vma ? vma->vm_start : 0,
				vma ? vma->vm_end : 0);
		ret = -EINVAL;
		goto out;
	}
	if (code_base > vma->vm_start)
		prev = vma;
	vm_flags = (vma->vm_flags & ~VM_CUI) | ((u64) cui << VM_CUI_SHIFT);
	ret = mprotect_fixup(vma, &prev, code_base, code_end, vm_flags);

out:
	up_write(&mm->mmap_sem);
	return ret;
}
