/* linux/arch/e2k/mm/fault.c, v 1.7 03/07/2001.
 *
 * Copyright (C) 2001 MCST 
 */

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/hugetlb.h>
#include <linux/mempolicy.h>
#include <linux/module.h>
#include <linux/perf_event.h>
#include <linux/sched/rt.h>
#include <linux/syscalls.h>

#include "../../../mm/internal.h" /* for munlock_vma_pages_range */

#include <asm/cpu_regs_access.h>
#include <asm/mmu_regs.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/siginfo.h>
#include <asm/signal.h>
#include <asm/processor.h>
#include <asm/process.h>
#include <asm/hardirq.h>
#include <asm/pgtable.h>
#include <asm/mmu.h>
#include <asm/sge.h>
#include <asm/traps.h>
#include <asm/uaccess.h>
#include <asm/process.h>
#include <asm/regs_state.h>
#include <asm/e2k_syswork.h>
#include <asm/mlt.h>
#include <asm/e2k_debug.h>
#include <asm/secondary_space.h>

#ifdef CONFIG_SOFTWARE_SWAP_TAGS
#include <asm/tag_mem.h>
#endif
#ifdef CONFIG_PROTECTED_MODE
#include <asm/3p.h>
#endif /* CONFIG_PROTECTED_MODE */
#ifdef	CONFIG_RECOVERY
#include <asm/cnt_point.h>
#endif	/* CONFIG_RECOVERY */

/**************************** DEBUG DEFINES *****************************/

#define	DEBUG_TRAP_CELLAR	0	/* DEBUG_TRAP_CELLAR */
#define DbgTC(...)		DebugPrint(DEBUG_TRAP_CELLAR ,##__VA_ARGS__)
#define	DEBUG_STATE_TC		DEBUG_TRAP_CELLAR	/* DEBUG_TRAP_CELLAR */
#define PrintTC(a, b) \
	if(DEBUG_STATE_TC || DEBUG_CLW_FAULT) print_tc_state(a, b);

#undef	DEBUG_HS_MODE
#undef	DebugHS
#define	DEBUG_HS_MODE		0	/* Hard Stack Clone and Alloc */
#define DebugHS(...)		DebugPrint(DEBUG_HS_MODE ,##__VA_ARGS__)

#undef	DEBUG_CS_MODE
#undef	DebugCS
#define	DEBUG_CS_MODE		0	/* Constrict Hard Stack */
#define DebugCS(...)		DebugPrint(DEBUG_CS_MODE ,##__VA_ARGS__)

#undef	DEBUG_US_EXPAND
#undef	DebugUS
#define	DEBUG_US_EXPAND		0
#define DebugUS(...)		DebugPrint(DEBUG_US_EXPAND ,##__VA_ARGS__)

#define	DEBUG_PF_MODE		0	/* Page fault */
#define DebugPF(...)		DebugPrint(DEBUG_PF_MODE ,##__VA_ARGS__)

#define	DEBUG_NAO_MODE		0	/* Not aligned operation */
#define DebugNAO(...)		DebugPrint(DEBUG_NAO_MODE ,##__VA_ARGS__)

#define	DEBUG_EXEC_MMU_OP	0
#define DbgEXMMU(...)		DebugPrint(DEBUG_EXEC_MMU_OP ,##__VA_ARGS__)

#undef	DEBUG_PGD_MODE
#undef	DebugPGD
#define	DEBUG_PGD_MODE		0	/* CPU PGD populate */
#define DebugPGD(...)		DebugPrint(DEBUG_PGD_MODE ,##__VA_ARGS__)

#undef	DEBUG_UF_MODE
#undef	DebugUF
#define	DEBUG_UF_MODE		0	/* VMA flags update */
#define DebugUF(...)		DebugPrint(DEBUG_UF_MODE ,##__VA_ARGS__)

#undef	DEBUG_CLW_FAULT
#undef	DebugCLW
#define	DEBUG_CLW_FAULT		0
#define DebugCLW(...)		DebugPrint(DEBUG_CLW_FAULT ,##__VA_ARGS__)

#undef	DEBUG_SRP_FAULT
#undef	DebugSRP
#define	DEBUG_SRP_FAULT	        0
#define DebugSRP(...)		DebugPrint(DEBUG_SRP_FAULT ,##__VA_ARGS__)

#undef	DEBUG_SPRs_MODE
#define	DEBUG_SPRs_MODE		0	/* stack pointers registers */

#undef	DEBUG_RPR
#undef	DebugRPR
#define	DEBUG_RPR		0	/* Recovery point register */
#define DebugRPR(...)		DebugPrint(DEBUG_RPR ,##__VA_ARGS__)

#undef	DEBUG_RG_UPDATE
#undef	DebugRG
#define	DEBUG_RG_UPDATE		0
#define DebugRG(...)		DebugPrint(DEBUG_RG_UPDATE ,##__VA_ARGS__)

#undef	DEBUG_MULTI_THREAD_PM
#undef	DebugMT_PM
#define	DEBUG_MULTI_THREAD_PM	0
#define DebugMT_PM(...)		DebugPrint(DEBUG_MULTI_THREAD_PM ,##__VA_ARGS__)

/*
 * Print pt_regs
 */
#define	DEBUG_PtR_MODE		0	/* Print pt_regs */
#define	DebugPtR(str, pt_regs)	\
	if (DEBUG_PtR_MODE) print_pt_regs(str, pt_regs)

#ifdef	CONFIG_CHECK_LOCK_AREAS
#define	CHECK_STACK_LOCK_AREA(start, end, ps_lock_bot, ps_lock_top,	\
							lock_delta)	\
({									\
	if ((start) != (ps_lock_top) && (end) != (ps_lock_bot) -	\
							lock_delta) {	\
		panic("CHECK_STACK_LOCK_AREA() addr to lock HS " 	\
			"start 0x%lx != current top 0x%lx and "		\
			"end 0x%lx != bottom 0x%lx - delta 0x%lx\n",	\
			start, ps_lock_top,				\
			end, ps_lock_bot, lock_delta);			\
	}								\
})
#define	CHECK_STACK_UNLOCK_AREA(start, end, ps_lock_bot, ps_lock_top)	\
({									\
	if ((end) != (ps_lock_top) && (start) != (ps_lock_bot)) {	\
		panic("CHECK_STACK_UNLOCK_AREA() addr to unlock YS "	\
			"start 0x%lx != current bottom 0x%lx and "	\
			"end 0x%lx != top 0x%lx\n",			\
			start, ps_lock_bot, end, ps_lock_top);		\
	}								\
})
#else	/* ! CONFIG_CHECK_LOCK_AREAS */
#define	CHECK_STACK_LOCK_AREA(start, end, ps_lock_bot, ps_lock_top, lock_delta)
#define	CHECK_STACK_UNLOCK_AREA(start, end, ps_lock_bot, ps_lock_top)
#endif	/* CONFIG_CHECK_LOCK_AREAS */

/**************************** END of DEBUG DEFINES ***********************/

/************************* PAGE FAULT DEBUG for users ********************/

int debug_semi_spec = 0;

static int __init semi_spec_setup(char *str)
{
	debug_semi_spec = 1;
	return 1;
}

__setup("debug_semi_spec", semi_spec_setup);


int debug_pagefault = 0;

static int __init pagefault_setup(char *str)
{
	debug_pagefault = 1;
	return 1;
}

__setup("debug_pagefault", pagefault_setup);

#undef  GET_IP
#define GET_IP  ( AS(regs->crs.cr0_hi).ip << E2K_ALIGN_INS )
#define PFDBGPRINT(fmt, ...) \
do { \
	if (debug_pagefault || DEBUG_PF_MODE) { \
		pr_notice("PAGE FAULT. " fmt ": IP=%p %s(pid=%d)\n" \
				,##__VA_ARGS__, (void *) GET_IP, \
				current->comm, current->pid); \
	} \
} while (0)

/********************* END of PAGE FAULT DEBUG for users *****************/

static int execute_mmu_operations(trap_cellar_t *tceller,
			struct pt_regs *regs, int zeroing, e2k_addr_t *addr);
static void calculate_new_rpr(struct pt_regs *regs, e2k_addr_t ip, int str);

int do_update_vm_area_flags(e2k_addr_t start, e2k_size_t len,
		vm_flags_t flags_to_set, vm_flags_t flags_to_clear)
{
	unsigned long nstart, end, tmp;
	struct vm_area_struct * vma, * next;
	int error = 0;

	BUG_ON(flags_to_set & flags_to_clear);

	len = PAGE_ALIGN(len);
	end = start + len;
	if (end < start)
		return -EINVAL;
	if (end == start)
		return 0;
	vma = find_vma(current->mm, start);
	if (vma == NULL) {
		printk(KERN_ERR "Could not find VMA structure of user "
			"virtual memory area: addr 0x%lx\n",
			start);
		BUG();
	}
	if (vma->vm_start > start) {
		printk(KERN_ERR "Invalid VMA structure start address of user "
			"virtual memory area: addr 0x%lx (should be 0x%lx)\n",
			vma->vm_start, start);
		print_mmap(current);
		BUG();
	}
	if (vma->vm_start < start) {
		DebugHS("splitting vma at "
				"(0x%lx, 0x%lx) at 0x%lx\n",
				vma->vm_start, vma->vm_end, start);
		if (split_vma(current->mm, vma, start, 1))
			return -ENOMEM;
	}
	if (vma->vm_end > end) {
		DebugHS("splitting vma at "
				"(0x%lx, 0x%lx) at 0x%lx\n",
				vma->vm_start, vma->vm_end, end);
		if (split_vma(current->mm, vma, end, 0))
			return -ENOMEM;
	}


	for (nstart = start ; ; ) {
		unsigned long newflags;

		/* Here we know that vma->vm_start <= nstart < vma->vm_end. */

		newflags = vma->vm_flags;
		newflags |= flags_to_set;
		newflags &= ~flags_to_clear;

		if (vma->vm_end >= end) {
			if (vma->vm_end > end) {
				DebugHS("splitting "
					"vma at (0x%lx, 0x%lx) at 0x%lx\n",
					vma->vm_start, vma->vm_end, end);
				if (split_vma(current->mm, vma, end, 0))
					return -ENOMEM;
			}
			/*
			 * vm_flags and vm_page_prot are protected by
			 * the mmap_sem held in write mode.
			 */
			vma->vm_flags = newflags;
			break;
		}

		tmp = vma->vm_end;
		next = vma->vm_next;
		/*
		 * vm_flags and vm_page_prot are protected by
		 * the mmap_sem held in write mode.
		 */
		vma->vm_flags = newflags;
		nstart = tmp;
		vma = next;
		if (vma == NULL) {
			printk(KERN_ERR "Could not find VMA structure of user "
				"virtual memory area: addr 0x%lx\n",
				nstart);
			BUG();
		}
		if (vma->vm_start != nstart) {
			printk(KERN_ERR "Invalid VMA structure start address "
				"of user virtual memory area: addr 0x%lx "
				"(should be 0x%lx)\n",
				vma->vm_start, nstart);
			BUG();
		}
	}
	return error;
}
e2k_addr_t
user_address_to_phys(struct task_struct *tsk, e2k_addr_t address)
{
	pgd_t		*pgd;
	pud_t		*pud;
	pmd_t		*pmd;
	pte_t		*pte;
	e2k_addr_t	offset;
        struct vm_area_struct *vma;

	if (address >= TASK_SIZE) {
		printk("Address 0x%016lx is  kernel address \n",
			address);
		return -1;
	}
	vma = find_vma(tsk->mm, address);
	if (vma == NULL) {
		printk("Could not find VMA structure of user "
			"virtual memory area: addr 0x%lx\n",
			address);
		return -1;
	}
	pgd = pgd_offset(vma->vm_mm, address);
	if (pgd_none(*pgd)) {
		printk("PGD  0x%p = 0x%lx none or bad for address 0x%lx\n",
			pgd, pgd_val(*pgd), address);
		return -1;
        }
	pud = pud_offset(pgd, address);
	if (pud_none(*pud)) {
		printk("PUD  0x%p = 0x%lx none or bad for address 0x%lx\n",
			pud, pud_val(*pud), address);
		return -1;
        }
	pmd = pmd_offset(pud, address);
        if (pmd_bad_user(*pmd)) {
		printk("PMD 0x%p = 0x%016lx none or bad for address "
			"0x%016lx\n",
			pmd, pmd_val(*pmd), address);
		return -1;
	}
	/* pte */
	if (!pmd_large(*pmd)) {
		pte = pte_offset_map(pmd, address);
		offset = address & ~PAGE_MASK;
	} else {
		pte = (pte_t *) pmd;
		offset = address & ~LARGE_PAGE_MASK;
	}
	if (pte_none(*pte)) {
		printk("PTE  0x%p = 0x%016lx none for address 0x%016lx\n",
			pte, pte_val(*pte), address);
		return -1;
	}
	return (pte_pfn(*pte) << PAGE_SHIFT) | offset;

}

#ifdef	CONFIG_RECOVERY
e2k_addr_t
cntp_user_address_to_phys(struct task_struct *tsk, e2k_addr_t address)
{
	pgd_t		*pgd;
	pud_t		*pud;
	pmd_t		*pmd;
	pte_t		*pte;
	e2k_addr_t	offset;
	struct vm_area_struct *vma;

	if (address >= TASK_SIZE) {
		printk("Address 0x%016lx is  kernel address \n",
			address);
		return -1;
	}
	vma = cntp_find_vma(tsk, address);
	if (vma == NULL) {
		printk("Could not find VMA structure of user "
			"virtual memory area: addr 0x%lx\n",
			address);
		return -1;
	}
	pgd = cntp_pgd_offset(
			(struct mm_struct *)cntp_va(vma->vm_mm, 0), address);
	if (pgd_none(*pgd)) {
		printk("PGD  0x%p = 0x%lx none or bad for address 0x%lx\n",
			pgd, pgd_val(*pgd), address);
		return -1;
	}
	pud = pud_offset(pgd, address);
	if (pud_none(*pud)) {
		printk("PUD  0x%p = 0x%lx none or bad for address 0x%lx\n",
			pud, pud_val(*pud), address);
		return -1;
	}
	pmd = pmd_offset(pud, address);
        if (pmd_bad_user(*pmd)) {
		printk("PMD 0x%p = 0x%016lx none or bad for address "
			"0x%016lx\n",
			pmd, pmd_val(*pmd), address);
		return -1;
	}
	/* pte */
	if (!pmd_large(*pmd)) {
		pte = pte_offset_map(pmd, address);
		offset = address & ~PAGE_MASK;
	} else {
		pte = (pte_t *) pmd;
		offset = address & ~LARGE_PAGE_MASK;
	}
	if (pte_none(*pte)) {
		printk("PTE  0x%p = 0x%016lx none for address 0x%016lx\n",
			pte, pte_val(*pte), address);
		return -1;
	}
	return (pte_pfn(*pte) << PAGE_SHIFT) | offset;
}
#endif	/* CONFIG_RECOVERY */

/*
 * Convrert kernel virtual address to physical
 * (convertion based on page table lookup)
 */

e2k_addr_t
kernel_address_to_phys(e2k_addr_t address)
{
	pgd_t		*pgd;
	pud_t		*pud;
	pmd_t		*pmd;
	pte_t		*pte;
	e2k_addr_t	offset;

	if (address < TASK_SIZE) {
		pr_alert("Address 0x%016lx is not kernel address to get PFN's\n",
			address);
		return -1;
	}

	pgd = pgd_offset_kernel(address);
	if (pgd_none_or_clear_bad_kernel(pgd)) {
		pr_alert("PGD  0x%p = 0x%016lx none or bad for address 0x%016lx\n",
			pgd, pgd_val(*pgd), address);
		return -1;
	}

	/* pud */
	pud = pud_offset_kernel(pgd, address);
	if (pud_none_or_clear_bad_kernel(pud)) {
		pr_alert("PUD 0x%p = 0x%016lx none or bad for address 0x%016lx\n",
			pud, pud_val(*pud), address);
		return -1;
	}

	/* pmd */
	pmd = pmd_offset_kernel(pud, address);
	if (pmd_none_or_clear_bad_kernel(pmd)) {
		pr_alert("PMD 0x%p = 0x%016lx none or bad for address 0x%016lx\n",
			pmd, pmd_val(*pmd), address);
		return -1;
	}
	/* pte */
	if (!pmd_large(*pmd)) {
		pte = pte_offset_kernel(pmd, address);
		offset = address & ~PAGE_MASK;
	} else {
		pte = (pte_t *) pmd;
		offset = address & ~LARGE_PAGE_MASK;
	}
	if (pte_none(*pte)) {
		pr_alert("PTE  0x%p:0x%016lx none for address 0x%016lx\n",
			pte, pte_val(*pte), address);
		return -1;
	}
	if (!pte_present(*pte)) {
		if (!pte_file(*pte)) {
			pr_alert("PTE  0x%p = 0x%016lx is pte of swaped page for address 0x%016lx\n",
				pte, pte_val(*pte), address);
			return -1;
		}
		pr_alert("PTE  0x%p = 0x%016lx is pte of not present page for address 0x%016lx\n",
			pte, pte_val(*pte), address);
		return -1;
	}
	return (pte_pfn(*pte) << PAGE_SHIFT) | offset;
}

unsigned long node_kernel_address_to_phys(int node, e2k_addr_t addr)
{
	e2k_addr_t phys_addr;
	pgd_t *pgd = node_pgd_offset_kernel(node, addr);
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int is_large_page;

	if (unlikely(pgd_none_or_clear_bad_kernel(pgd))) {
		pr_alert("node_kernel_address_to_phys(): pgd_none\n");
		return -EINVAL;
	}
	pud = pud_offset_kernel(pgd, addr);
	if (unlikely(pud_none_or_clear_bad_kernel(pud))) {
		pr_alert("node_kernel_address_to_phys(): pud_none\n");
		return -EINVAL;
	}
	pmd = pmd_offset_kernel(pud, addr);
	if (unlikely(pmd_none_or_clear_bad_kernel(pmd))) {
		pr_alert("node_kernel_address_to_phys(): pmd_none\n");
		return -EINVAL;
	}

	is_large_page = pmd_large(*pmd);
	if (!is_large_page)
		pte = pte_offset_kernel(pmd, addr);
	else
		pte = (pte_t *) pmd;

	if (unlikely(pte_none(*pte) || !pte_present(*pte))) {
		pr_alert("node_kernel_address_to_phys(): pte_none\n");
		return -EINVAL;
	}

	if (is_large_page) {
		phys_addr = _PAGE_PFN_TO_PADDR(pte_val(*pte))
				+ (addr & ~LARGE_PAGE_MASK);
	} else {
		phys_addr = _PAGE_PFN_TO_PADDR(pte_val(*pte))
				+ (addr & ~PAGE_MASK);
	}

	return phys_addr;
}


#ifdef	CONFIG_RECOVERY
e2k_addr_t
cntp_kernel_address_to_phys(e2k_addr_t address)
{
	pgd_t		*pgd;
	pud_t		*pud;
	pmd_t		*pmd;
	pte_t		*pte;
	e2k_addr_t	offset;

	if (address < TASK_SIZE) {
		printk("Address 0x%016lx is not kernel address to get PFN's\n",
			address);
		return -1;
	}
	pgd = cntp_pgd_offset_kernel(address);
	if (pgd_none_or_clear_bad_kernel(pgd)) {
		printk("PGD  0x%p = 0x%016lx none or bad for address "
			"0x%016lx\n",
			pgd, pgd_val(*pgd), address);
		return -1;
	}

	/* pud */
	pud = pud_offset_kernel(pgd, address);
	if (pud_none_or_clear_bad_kernel(pud)) {
		printk("PUD 0x%p = 0x%016lx none or bad for address "
			"0x%016lx\n",
			pud, pud_val(*pud), address);
		return -1;
	}

	/* pmd */
	pmd = pmd_offset_kernel(pud, address);
	if (pmd_none_or_clear_bad_kernel(pmd)) {
		printk("PMD 0x%p = 0x%016lx none or bad for address "
			"0x%016lx\n",
			pmd, pmd_val(*pmd), address);
		return -1;
	}
	/* pte */
	if (!pmd_large(*pmd)) {
		pte = pte_offset_kernel(pmd, address);
		offset = address & ~PAGE_MASK;
	} else {
		pte = (pte_t *) pmd;
		offset = address & ~LARGE_PAGE_MASK;
	}
	if (pte_none(*pte)) {
		printk("PTE  0x%p:0x%016lx none for address 0x%016lx\n",
			pte, pte_val(*pte), address);
		return -1;
	}
	if (!pte_present(*pte)) {
		if (!pte_file(*pte)) {
			printk("PTE  0x%p = 0x%016lx is pte of swaped page "
				"for address 0x%016lx\n",
				pte, pte_val(*pte), address);
			return -1;
		}
		printk("PTE  0x%p = 0x%016lx is pte of not present page "
			"for address 0x%016lx\n",
			pte, pte_val(*pte), address);
		return -1;
	}
	return (pte_pfn(*pte) << PAGE_SHIFT) | offset;
}
#endif	/* CONFIG_RECOVERY */

static e2k_addr_t
print_address_ptes(pgd_t *pgdp, e2k_addr_t address, int kernel)
{
	pgd_t		pgd = *pgdp;
	pud_t		*pud;
	pmd_t		*pmd;
	pte_t		*pte;
	e2k_addr_t	pa = 0;

	if ((kernel) ? pgd_none_or_clear_bad_kernel(pgdp) :
				pgd_none_or_clear_bad(pgdp)) {
		pr_alert("PGD  0x%p = 0x%016lx none or bad for address "
			"0x%016lx\n",
			pgdp, pgd_val(pgd), address);
		return pa;
	}
	pr_alert("%s PGD  0x%p = 0x%016lx valid for address 0x%016lx\n",
		(kernel) ? "kernel" : "user", pgdp, pgd_val(*pgdp), address);

	/* pud */
	if (kernel) {
		pud = pud_offset_kernel(pgdp, address);
	} else {
		pud = pud_offset(pgdp, address);
	}
	if ((kernel) ? pud_none_or_clear_bad_kernel(pud) :
				pud_none_or_clear_bad(pud)) {
		pr_alert("PUD 0x%p = 0x%016lx none or bad for address 0x%016lx\n",
			pud, pud_val(*pud), address);
		return pa;
	}
	pr_alert("PUD 0x%p = 0x%016lx valid for address 0x%016lx\n",
		pud, pud_val(*pud), address);

	/* pmd */
	if (kernel) {
		pmd = pmd_offset_kernel(pud, address);
	} else {
		pmd = pmd_offset(pud, address);
	}
	if ((kernel) ? pmd_none_or_clear_bad_kernel(pmd) :
				pmd_none_or_clear_bad(pmd)) {
		pr_alert("PMD 0x%p = 0x%016lx none or bad for address 0x%016lx\n",
			pmd, pmd_val(*pmd), address);
		return pa;
	}
	/* pte */
	if (pmd_large(*pmd)) {
		pr_alert("PMD 0x%p = 0x%016lx is PTE of large page\n",
			pmd, pmd_val(*pmd));
		return pa;
	}

	pr_alert("PMD 0x%p = 0x%016lx valid for address 0x%016lx\n",
		pmd, pmd_val(*pmd), address);
	if (kernel) {
		pte = pte_offset_kernel(pmd, address);
	} else {
		pte = pte_offset_map(pmd, address);
	}

	if (pte_none(*pte)) {
		pr_alert("PTE  0x%p = 0x%016lx none for address 0x%016lx\n",
			pte, pte_val(*pte), address);
		return pa;
	}
	if (!pte_present(*pte)) {
		if (!pte_file(*pte)) {
			pr_alert("PTE  0x%p = 0x%016lx is pte of swaped page for address 0x%016lx\n",
				pte, pte_val(*pte), address);
			return pa;
		}
		pr_alert("PTE  0x%p = 0x%016lx is pte of not present page for address 0x%016lx\n",
			pte, pte_val(*pte), address);
		return pa;
	}
	pr_alert("PTE  0x%p = 0x%016lx valid & present for address 0x%016lx\n",
		pte, pte_val(*pte), address);
	pa = _PAGE_PFN_TO_PADDR(pte_val(*pte)) + (address & 0xfff);
	return pa;
}


void print_vma_and_ptes(struct vm_area_struct *vma, e2k_addr_t address)
{
	pgd_t		*pgdp;

	printk("VMA 0x%p : start 0x%016lx, end 0x%016lx, flags 0x%lx, "
		"prot 0x%016lx\n",
		vma, vma->vm_start, vma->vm_end, vma->vm_flags,
		pgprot_val(vma->vm_page_prot));

	pgdp = pgd_offset(vma->vm_mm, address);
	print_address_ptes(pgdp, address, 0);
}

static e2k_addr_t
__print_user_address_ptes(struct mm_struct *mm, e2k_addr_t address)
{
       pgd_t           *pgdp;
       e2k_addr_t      pa = 0;

       if (mm) {
               pgdp = pgd_offset(mm, address);
               print_address_ptes(pgdp, address, 0);
       }
       return pa;
}

static e2k_addr_t
print_user_address_ptes(struct mm_struct *mm, e2k_addr_t address)
{
	if (address >= TASK_SIZE) {
		pr_info("Address 0x%016lx is not user address to print PTE's\n",
			address);
		return 0;
	}
	return __print_user_address_ptes(mm, address);
}

e2k_addr_t print_kernel_address_ptes(e2k_addr_t address)
{
	pgd_t		*pgdp;
	e2k_addr_t	pa = 0;

	if (address < TASK_SIZE) {
		printk("Address 0x%016lx is not kernel address to print PTE's\n",
			address);
		return pa;
	}
	pgdp = pgd_offset_kernel(address);
	pa = print_address_ptes(pgdp, address, 1);
	return pa;
}

int is_kernel_address_valid(e2k_addr_t address)
{
	pgd_t			*pgd;
	pud_t			*pud;
	pmd_t			*pmd;
	pte_t			*pte;
	e2k_addr_t		offset;

	if (address < TASK_SIZE) {
		printk("Address 0x%016lx is not kernel address to get PFN's\n",
			address);
		return 0;
	}
	pgd = pgd_offset_kernel(address);
	if (pgd_none_or_clear_bad_kernel(pgd)) {
		printk("\n============================================================\n");
		printk("PGD  0x%p = 0x%016lx none or bad for address 0x%016lx\n",
			pgd, pgd_val(*pgd), address);
		return 0;
	}

	/* pud */
	pud = pud_offset_kernel(pgd, address);
	if (pud_none_or_clear_bad_kernel(pud)) {
		printk("\n============================================================\n");
		printk("PUD 0x%p = 0x%016lx none or bad for address 0x%016lx\n",
			pud, pud_val(*pud), address);
		return 0;
	}

	/* pmd */
	pmd = pmd_offset_kernel(pud, address);
	if (pmd_none_or_clear_bad_kernel(pmd)) {
		printk("\n============================================================\n");
		printk("PMD 0x%p = 0x%016lx none or bad for address 0x%016lx\n",
			pmd, pmd_val(*pmd), address);
		return 0;
	}

	/* pte */
	if (!pmd_large(*pmd)) {
		pte = pte_offset_kernel(pmd, address);
		offset = address & ~PAGE_MASK;
	} else {
		pte = (pte_t *) pmd;
		offset = address & ~LARGE_PAGE_MASK;
	}
	if (pte_none(*pte)) {
		printk("\n============================================================\n");
		printk("PTE:  0x%p = 0x%016lx <none> for address 0x%016lx\n",
			pte, pte_val(*pte), address);
		return 0;
	}
	if (!pte_present(*pte)) {
		if (!pte_file(*pte)) {
			printk("\n============================================================\n");
			printk("PTE  0x%p = 0x%016lx is pte of swaped page "
				"for address 0x%016lx\n",
				pte, pte_val(*pte), address);
			return 0;
		}
		printk("\n============================================================\n");
		printk("PTE  0x%p = 0x%016lx is pte of not present page "
			"for address 0x%016lx\n",
			pte, pte_val(*pte), address);
		return 0;
	}
	return 1;
}

#if 0
void print_vma_node_ptes(struct vm_area_struct *vma, e2k_addr_t address)
{
	print_vma_and_ptes(vma, address);

#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
	if (THERE_IS_DUP_KERNEL) {
		pgd_t	*pgdp;

		pgdp = cpu_kernel_root_pt + pgd_index(address);
		pr_info("CPU #%d kernel root page table:\n",
			smp_processor_id());
		print_address_ptes(pgdp, address, 0);
	}
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
}
#endif

#ifdef CONFIG_NUMA
static void
print_kernel_address_all_nodes_ptes(e2k_addr_t address)
{
	pgd_t	*pgdp;
	int	cpu;
	int	nid = numa_node_id();

	pgdp = node_pgd_offset_kernel(nid, address);
	pr_info("NODE #%d kernel root page table:\n", nid);
	print_address_ptes(pgdp, address, 1);

	for_each_online_cpu(cpu) {
		pgdp = the_cpu_pg_dir(cpu) + pgd_index(address);
		pr_info("CPU #%d kernel root page table:\n", cpu);
		print_address_ptes(pgdp, address, 1);
	}
}
#else /* !CONFIG_NUMA */
static void
print_kernel_address_all_nodes_ptes(e2k_addr_t address)
{
}
#endif /* CONFIG_NUMA */

struct page *e2k_virt_to_page(const void *kaddrp)
{
	e2k_addr_t kaddr = (e2k_addr_t)kaddrp;
	e2k_addr_t kpaddr;

	if (kaddr < TASK_SIZE) {
		panic("e2k_virt_to_page() address 0x%p is not kernel address\n",
				kaddrp);
	} else if (kaddr >= PAGE_OFFSET && kaddr < PAGE_OFFSET + MAX_PM_SIZE) {
		kpaddr = __pa(kaddrp);
	} else if (kaddr >= KERNEL_BASE && kaddr <= KERNEL_END) {
		kpaddr = kernel_va_to_pa(kaddrp);
	} else {
		panic("e2k_virt_to_page() address 0x%p is invalid kernel "
				"address\n", kaddrp);
	}
	return phys_to_page(kpaddr);
}

EXPORT_SYMBOL(e2k_virt_to_page);

#ifndef	CONFIG_CLW_ENABLE
#define	terminate_CLW_operation(regs)
#else

static int /*inline*/
terminate_CLW_operation(struct pt_regs *regs)
{
	e2k_addr_t us_cl_up = regs->us_cl_up;
	e2k_addr_t us_cl_b = regs->us_cl_b;
	clw_reg_t *us_cl_m = regs->us_cl_m;
	u64 *us_addr;
	int bit_no, mask_word, mask_bit;
	int bmask;

	DebugCLW("started for us_cl_up 0x%lx "
		"us_cl_b 0x%lx\n",
		us_cl_up, us_cl_b);
	for (bmask = 0; bmask < sizeof (regs->us_cl_m) /
					sizeof (*regs->us_cl_m); bmask ++) {
		DebugCLW("    mask[%d] = 0x%016lx\n",
			bmask, us_cl_m[bmask]);
	}
	if (us_cl_up <= us_cl_b) {
		DebugCLW("nothing to clean\n");
		return 0;
	}
	us_addr = (u64 *)us_cl_up;
	while ((e2k_addr_t)us_addr > us_cl_b &&
		(us_cl_up - (e2k_addr_t)us_addr) < CLW_BYTES_PER_MASK) {
		DebugCLW("cuurent US address "
			"0x%p\n", us_addr);
		bit_no = ((unsigned long) us_addr / CLW_BYTES_PER_BIT) & 0xff;
		mask_word = bit_no / (sizeof (*us_cl_m) * 8);
		mask_bit = bit_no % (sizeof (*us_cl_m) * 8);
		DebugCLW("check bit-mask #%d "
			"word %d bit in word %d\n",
			bit_no, mask_word, mask_bit);
		if (!(us_cl_m[mask_word] & (1 << mask_bit))) {
			DebugCLW("will clean stack "
				"area from 0x%lx to 0x%lx\n",
				(e2k_addr_t)us_addr,
				(e2k_addr_t)us_addr + CLW_BYTES_PER_BIT);
			clear_memory_8(us_addr, CLW_BYTES_PER_BIT);
		}
		us_addr -= (CLW_BYTES_PER_BIT / sizeof (*us_addr));
	}
	if ((e2k_addr_t)us_addr <= us_cl_b) {
		DebugCLW("nothing to clean "
			"outside of area covering by bit-mask\n");
		return 0;
	}
	DebugCLW("will clean stack area from 0x%lx "
		"to 0x%lx, 0x%lx bytes\n",
		us_cl_b + CLW_BYTES_PER_BIT, (e2k_addr_t)us_addr + CLW_BYTES_PER_BIT,
		(e2k_addr_t)us_addr - us_cl_b);
	clear_memory_8((u64 *)(us_cl_b + CLW_BYTES_PER_BIT),
						(e2k_addr_t)us_addr - us_cl_b);
	return 0;
}
#endif	/* CONFIG_CLW_ENABLE */

/**
 * calculate_e2k_stack_parameters - get user data stack free area parameters
 * @usd_lo: %usd.lo register
 * @usd_hi: %usd.hi register
 * @sbr: %sbr register
 * @sp: stack pointer will be returned here
 * @stack_size: free area size will be returned here
 */
static void calculate_e2k_stack_parameters(e2k_usd_lo_t usd_lo,
		e2k_usd_hi_t usd_hi, e2k_sbr_t sbr,
		unsigned long *sp, unsigned long *stack_size)
{
#ifdef CONFIG_PROTECTED_MODE
	if (AS(usd_lo).p) {
		e2k_pusd_lo_t	pusd_lo;
		e2k_pusd_hi_t	pusd_hi;
		e2k_addr_t	usbr;

		usbr = sbr & ~E2K_PROTECTED_STACK_BASE_MASK;
		AW(pusd_lo) = AW(usd_lo);
		AW(pusd_hi) = AW(usd_hi);
		*sp = usbr + (AS(pusd_lo).base & ~E2K_ALIGN_PUSTACK_MASK);
		*stack_size = AS(pusd_hi).size & ~E2K_ALIGN_PUSTACK_MASK;
	} else {
#endif
		*sp = AS(usd_lo).base;
		*stack_size = AS(usd_hi).size;
#ifdef CONFIG_PROTECTED_MODE
	}
#endif
}

/**
 * expand_user_data_stack - handles user data stack overflow
 * @regs: pointer to pt_regs
 * @task: task (child if @gdb and current otherwise)
 * @gdb: expansion for the ptraced task
 *
 * On e2k stack handling differs from everyone else for two reasons:
 * 1) All data stack memory must be allocated with 'getsp' prior to accessing;
 * 2) Data stack overflows are controlled with special registers which hold
 * stack boundaries.
 *
 * This means that guard page mechanism used for other architectures
 * isn't needed on e2k: all overflows accounting is done by hardware.
 * To keep changes in architecture-dependent part to the minimum, we
 * will always have one page allocated below (USD.lo.base - USD.hi.size).
 * In do_page_fault() we will have a check for faults on it, in which
 * case we should send the SIGSEGV for non-speculative accesses.
 */
int expand_user_data_stack(struct pt_regs *regs, struct task_struct *task,
		bool gdb)
{
	thread_info_t		*ti = task_thread_info(task);
	struct mm_struct	*mm = task->mm;
	unsigned long		incr;
	e2k_addr_t		sp, new_bottom;
	e2k_size_t		stack_size, new_size;
	struct vm_area_struct	*vma;
	int			ret, num;

	DebugUS("task->pid=%d current->pid=%d started\n",
			task->pid, current->pid);

	calculate_e2k_stack_parameters(regs->stacks.usd_lo, regs->stacks.usd_hi,
				       regs->stacks.sbr, &sp, &stack_size);

	DebugUS("base 0x%lx, size 0x%lx, top 0x%lx, bottom 0x%lx max current size 0x%lx alt_stack %d\n",
		sp, stack_size, ti->u_stk_top, ti->u_stk_base, ti->u_stk_sz,
		ti->alt_stack);

	/*
	 * It can be if signal handler uses alternative stack
	 * and an overflow of this stack occured.
	 */
	if (sp >= ti->u_stk_top || sp < ti->u_stk_base) {
		if (ti->alt_stack) {
			pr_info_ratelimited("expand_user_data_stack(): alt stack overflow\n");
		} else {
			pr_info("expand_user_data_stack(): SP of user data stack 0x%lx points out of main user stack allocated from bottom 0x%lx to top 0x%lx\n",
				sp, ti->u_stk_base, ti->u_stk_top);
		}
		force_sig(SIGSEGV, current);
		return -ENOMEM;
	}

	down_write(&mm->mmap_sem);

	if (gdb)
		incr = PAGE_SIZE;
	else
		incr = USER_C_STACK_BYTE_INCR;

	vma = find_extend_vma(mm, sp - stack_size - incr - PAGE_SIZE);
	if (!vma) {
		up_write(&mm->mmap_sem);
		printk_ratelimited("expand_user_data_stack(): user data stack overflow: stack bottom 0x%lx, top 0x%lx, sp 0x%lx, rest free space size 0x%lx\n",
			ti->u_stk_base, ti->u_stk_top, sp, stack_size);
		force_sig(SIGSEGV, current);
		return -ENOMEM;
	}

	DebugUS("find_extend_vam() returned VMA 0x%p, start 0x%lx, end 0x%lx\n",
		vma, vma->vm_start, vma->vm_end);

	new_bottom = vma->vm_start + PAGE_SIZE;
	new_size = sp - new_bottom;

	up_write(&mm->mmap_sem);

	BUG_ON(new_size < stack_size + incr);

	if (new_size > MAX_USD_HI_SIZE) {
		force_sig(SIGSEGV, current);
		return -ENOMEM;
	}

	/*
	 * Increment user data stack size in the USD register
	 * and in the chain registers (CR1_hi.ussz field)
	 * in all user pt_regs structures of the process.
	 */
	num = fix_all_user_stack_regs(regs, new_size - stack_size);
	if (num == 0) {
		printk("expand_user_data_stack(): no pt_regs structures (USD & CR1_hi.ussz) were corrected to increment user stack sizes\n");
		force_sig(SIGSEGV, current);
		return -EINVAL;
	}
	DebugUS("%d pt_regs structures (USD & CR1_hi.ussz) was corrected to increment user stack sizes\n",
		num);

	/*
	 * Correct cr1_hi.ussz fields for all functions in the PCSP
	 */
	if (gdb) {
		ret = fix_all_stack_sz_for_gdb(
			(e2k_addr_t) GET_PCS_BASE(ti),
			GET_PCS_OFFSET(ti) +
				task->thread.sw_regs.pcsp_hi.PCSP_hi_ind,
			new_size - stack_size,
			0 /* all chains */,
			1 /* user stack*/,
			0 /* increment stack size */,
			task);
	} else {
		ret = fix_all_stack_sz(
			(e2k_addr_t) GET_PCS_BASE(ti),
			GET_PCS_OFFSET(ti) +
				regs->stacks.pcsp_hi.PCSP_hi_ind,
			new_size - stack_size,
			0, /* all chains */
			1, /* user stack*/
			0); /* increment stack size */
	}
	if (ret) {
		printk_ratelimited("expand_user_data_stack(): could not correct user stack sizes in chain stack: ret %d\n",
				ret);
		force_sig(SIGSEGV, current);
		return ret;
	}

	/*
	 * Update user data stack current state info
	 */
	ti->u_stk_base = new_bottom;
	ti->u_stk_sz += new_size - stack_size;

	DebugUS("extended stack: base 0x%lx, size 0x%lx, top 0x%lx, bottom 0x%lx max current size 0x%lx\n",
		sp, new_size, ti->u_stk_top, ti->u_stk_base, ti->u_stk_sz);

	return 0;
}
EXPORT_SYMBOL(expand_user_data_stack);

static int mlock_fixup(struct vm_area_struct *vma, struct vm_area_struct **prev,
		       unsigned long start, unsigned long end, bool lock)
{
	struct mm_struct *mm = vma->vm_mm;
	pgoff_t pgoff;
	int ret = 0;
	vm_flags_t newflags;

	newflags = vma->vm_flags & ~VM_LOCKED;
	if (lock)
		newflags |= VM_LOCKED;

	if (newflags == vma->vm_flags)
		goto out;

	pgoff = vma->vm_pgoff + ((start - vma->vm_start) >> PAGE_SHIFT);
	*prev = vma_merge(mm, *prev, start, end, newflags, vma->anon_vma,
			  vma->vm_file, pgoff, vma_policy(vma));
	if (*prev) {
		vma = *prev;
		goto success;
	}

	if (start != vma->vm_start) {
		ret = split_vma(mm, vma, start, 1);
		if (ret)
			goto out;
	}

	if (end != vma->vm_end) {
		ret = split_vma(mm, vma, end, 0);
		if (ret)
			goto out;
	}

success:
	/*
	 * vm_flags is protected by the mmap_sem held in write mode.
	 * It's okay if try_to_unmap_one unmaps a page just after we
	 * set VM_LOCKED, __mlock_vma_pages_range will bring it back.
	 */

	if (lock)
		vma->vm_flags = newflags;
	else
		munlock_vma_pages_range(vma, start, end);

out:
	*prev = vma;
	return ret;
}

/**
 * do_mlock_hw_stack - same as sys_m[un]lock but without accounting
 * @start - area startig address
 * @len - area length
 *
 * We do not want rlimits to have effect on hardware stacks,
 * so using sys_mlock is out of the question.
 */
int do_mlock_hw_stack(unsigned long start, unsigned long len, bool lock,
			bool populate)
{
	unsigned long nstart, end, tmp;
	struct vm_area_struct *vma, *prev;
	int error = 0;

	set_ts_flag(TS_KERNEL_SYSCALL);

	BUG_ON((start & ~PAGE_MASK) || len != PAGE_ALIGN(len));

	end = start + len;

	down_write(&current->mm->mmap_sem);

	vma = find_vma(current->mm, start);
	if (!vma || vma->vm_start > start) {
		error -ENOMEM;
		goto out_unlock;
	}

	prev = vma->vm_prev;
	if (start > vma->vm_start)
		prev = vma;

	for (nstart = start;;) {
		/* Here we know that  vma->vm_start <= nstart < vma->vm_end. */

		tmp = vma->vm_end;
		if (tmp > end)
			tmp = end;
		error = mlock_fixup(vma, &prev, nstart, tmp, lock);
		if (error)
			break;
		nstart = tmp;
		if (nstart < prev->vm_end)
			nstart = prev->vm_end;
		if (nstart >= end)
			break;

		vma = prev->vm_next;
		if (!vma || vma->vm_start != nstart) {
			error = -ENOMEM;
			break;
		}
	}

out_unlock:
	up_write(&current->mm->mmap_sem);

	if (!error && lock && populate)
		error = __mm_populate(start, len, 0);

	clear_ts_flag(TS_KERNEL_SYSCALL);

	return error;
}

/*
 * The function handles traps on hardware stack overflow or
 * underflow. If stack overflow occured then the hardware stack will be
 * expanded. In the case of stack underflow it will be constricted
 */
static inline int
expand_hardware_stack(e2k_addr_t ps_base, e2k_addr_t stack_addr, long top,
		long new_offset, long new_size,
		long kernel_size, int stack_down,
		long ps_lock_bottom, long ps_lock_top,
		long new_ps_lock_bottom, long new_ps_lock_top)
{
	e2k_addr_t	start_addr_to_lock = 0, end_addr_to_lock = 0,
			start_addr_to_unlock = 0, end_addr_to_unlock = 0,
			start_addr, end_addr, cur_lock_bottom, cur_lock_top,
			new_lock_bottom, new_lock_top;
	long		new_top;
	e2k_size_t	lock_delta = 0;
	int		retval;
	vm_flags_t	lock_flags_to_set, lock_flags_to_clear,
			unlock_flags_to_set, unlock_flags_to_clear,
			lock_mprotect_flags = 0;

	DebugHS("started\n");
	new_top = new_offset + new_size;
	DebugHS("new stack offset 0x%lx size 0x%lx "
		"top 0x%lx kernel stack size: 0x%lx\n",
		new_offset, new_size, new_top, kernel_size);
	DebugHS("current stack locked area bottom "
		"0x%lx top 0x%lx, new bottom 0x%lx top 0x%lx\n",
		ps_lock_bottom, ps_lock_top,
		new_ps_lock_bottom, new_ps_lock_top);
	cur_lock_bottom = ps_base + ps_lock_bottom;
	cur_lock_top = ps_base + ps_lock_top + kernel_size;
	new_lock_bottom = ps_base + new_ps_lock_bottom;
	new_lock_top = ps_base + new_ps_lock_top + kernel_size;

	start_addr = ps_base + new_offset;
	end_addr = ps_base + new_top + kernel_size;
	if (start_addr < new_lock_bottom || end_addr > new_lock_top) {
		printk(KERN_ERR "expand_hardware_stack() stack start address "
			"0x%lx < locked area bottom 0x%lx or stack end address "
			"0x%lx > locked area top 0x%lx\n",
			start_addr, new_lock_bottom, end_addr, new_lock_top);
	}
	if (stack_down) {
		if (new_lock_bottom != cur_lock_bottom) {
			start_addr_to_lock = new_lock_bottom;
			if (cur_lock_bottom > new_lock_top) {
				lock_delta = cur_lock_bottom - new_lock_top;
				end_addr_to_lock = new_lock_top;
			} else {
				end_addr_to_lock = cur_lock_bottom;
			}
		}
		if (new_lock_top != cur_lock_top) {
			if (new_lock_top < cur_lock_bottom)
				start_addr_to_unlock = cur_lock_bottom;
			else
				start_addr_to_unlock = new_lock_top;
			end_addr_to_unlock = cur_lock_top;
		}
		/*
		 * See comment in alloc_user_hard_stack()
		 */
		lock_flags_to_set = VM_DONTCOPY | VM_DONTMIGRATE | VM_HW_STACK;
		lock_flags_to_clear = 0;
		unlock_flags_to_set = 0;
		unlock_flags_to_clear = VM_DONTMIGRATE | VM_HW_STACK;
	} else {
		if (new_lock_bottom != cur_lock_bottom) {
			start_addr_to_unlock = cur_lock_bottom;
			end_addr_to_unlock = new_lock_bottom;
		}
		if (new_lock_top != cur_lock_top) {
			start_addr_to_lock = cur_lock_top;
			end_addr_to_lock = new_lock_top;
		}
		/*
		 * See comment in alloc_user_hard_stack()
		 */
		lock_flags_to_set = VM_DONTMIGRATE | VM_HW_STACK;
		lock_flags_to_clear = VM_DONTEXPAND;
		/*
		 * Since setting VM_READ/VM_WRITE requires doing
		 * additional accounting, we do it with sys_mprotect()
		 * instead of directly setting vm_flags.
		 */
		lock_mprotect_flags = PROT_READ | PROT_WRITE;
		unlock_flags_to_set = 0;
		unlock_flags_to_clear = VM_DONTCOPY | VM_DONTMIGRATE |
					VM_HW_STACK;
	}

	if (end_addr_to_lock > start_addr_to_lock) {
		retval = update_vm_area_flags(start_addr_to_lock,
				end_addr_to_lock - start_addr_to_lock,
				lock_flags_to_set, lock_flags_to_clear);
		DebugHS("set 0x%lx and clear 0x%lx flags from 0x%lx to 0x%lx, retval = %d\n",
				lock_flags_to_set, lock_flags_to_clear,
				start_addr_to_lock, end_addr_to_lock, retval);
		if (retval)
			return retval;

		if (lock_mprotect_flags) {
			set_ts_flag(TS_KERNEL_SYSCALL);
			retval = sys_mprotect(start_addr_to_lock,
					end_addr_to_lock - start_addr_to_lock,
					lock_mprotect_flags);
			clear_ts_flag(TS_KERNEL_SYSCALL);
			if (retval) {
				DebugHS("mprotect ret = %d\n", retval);
				return retval;
			}
		}

		CHECK_STACK_LOCK_AREA(start_addr_to_lock, end_addr_to_lock,
			cur_lock_bottom, cur_lock_top, lock_delta);
		retval = mlock_hw_stack(start_addr_to_lock,
				end_addr_to_lock - start_addr_to_lock, true);
		DebugHS("mlock from 0x%lx to 0x%lx returned %d\n",
				start_addr_to_lock, end_addr_to_lock, retval);
		if (retval)
			return retval;
	}

	if (end_addr_to_unlock > start_addr_to_unlock) {
		retval = update_vm_area_flags(start_addr_to_unlock,
				end_addr_to_unlock - start_addr_to_unlock,
				unlock_flags_to_set, unlock_flags_to_clear);
		DebugHS("set 0x%lx and clear 0x%lx flags from 0x%lx to 0x%lx, retval = %d\n",
			      unlock_flags_to_set, unlock_flags_to_clear,
			      start_addr_to_unlock, end_addr_to_unlock, retval);
		if (retval)
			return retval;

		if (!(current->mm->def_flags & VM_LOCKED)) {
			CHECK_STACK_UNLOCK_AREA(start_addr_to_unlock,
					end_addr_to_unlock, cur_lock_bottom,
					cur_lock_top);
			retval = munlock_hw_stack(start_addr_to_unlock,
				     end_addr_to_unlock - start_addr_to_unlock);
			DebugHS("munlock from 0x%lx to 0x%lx returned %d\n",
					start_addr_to_unlock,
					end_addr_to_unlock, retval);
			if (retval)
				return retval;
		}
	}

	return 0;
}

/**
 * handle_hardware_p_stack_overflow - handles procedure stack overflow
 * @ps_size - stack size from thread_info
 * @ps_offset - stack offset from thread_info
 * @delta_stack - stack increment
 */
static inline int
handle_hardware_p_stack_overflow(s64 ps_size, s64 ps_offset, s64 delta_stack)
{
	if (UHWS_PSEUDO_MODE) {
		struct thread_info	*ti = current_thread_info();
		struct hw_stack_area	*user_psp_stk;
		e2k_size_t		area_size;
		e2k_size_t		present_offset;

		area_size = PAGE_ALIGN_UP(
				max(ps_size + KERNEL_P_STACK_SIZE +
					USER_P_STACK_AREA_SIZE,
				(ps_size + KERNEL_P_STACK_SIZE) * 12 / 10));
		if (get_max_psp_size(area_size) != area_size)
			return -ENOMEM;
		present_offset = ps_offset + delta_stack;

		DebugHS("will allocate user Procedure stack\n");
		user_psp_stk = alloc_user_p_stack(
					area_size, present_offset,
					USER_P_STACK_INIT_SIZE);
		if (!user_psp_stk) {
			DebugHS("could not allocate user Procedure stack\n");
			return -ENOMEM;
		}
		DebugHS("allocated user Procedure stack at 0x%p, size 0x%lx, init size 0x%lx, kernel part size 0x%lx\n",
			user_psp_stk->base, area_size, USER_P_STACK_INIT_SIZE,
			KERNEL_P_STACK_SIZE);

		list_add_tail(&user_psp_stk->list_entry, &ti->ps_list);
		ti->cur_ps = user_psp_stk;
		DebugHS("user Procedure stack area 0x%p was added to user Procedure stack areas list\n",
			user_psp_stk);

		return 0;
	}

	DebugHS("user procedure stack overflow: offset 0x%lx max stack size 0x%lx\n",
		ps_offset, ps_size);
	return -ENOMEM;
}

/**
 * handle_hardware_p_stack_underflow - handles procedure stack underflow
 * @stack_size - stack size from pt_regs
 * @ps_size - stack size from thread_info
 * @ps_offset - stack offset from thread_info
 */
static inline int
handle_hardware_p_stack_underflow(s64 stack_size, s64 ps_size, s64 ps_offset)
{
	if (UHWS_PSEUDO_MODE)
		panic("handle_hardware_p_stack_underflow(): user procedure stack underflow: stack size 0x%lx offset 0x%lx area size 0x%lx\n",
			stack_size, ps_offset, ps_size);
	else
		panic("handle_hardware_p_stack_underflow(): user procedure stack underflow: stack size 0x%lx offset 0x%lx max stack size 0x%lx\n",
			stack_size, ps_offset, ps_size);
	return 0;
}

/**
 * do_expand_hardware_p_stack - handles procedure stack overflow and underflow
 * @stack_addr - stack base address from pt_regs
 * @stack_size - stack size from pt_regs
 * @delta_stack - stack increment
 * @delta_offset - stack offset increment
 * @delta_size - stack size increment
 *
 * If procedure stack overflow occured then the procedure stack will be
 * expanded. In the case of stack underflow it will be constricted.
 */
static inline int
do_expand_hardware_p_stack(e2k_addr_t stack_addr, s64 stack_size,
		s64 delta_stack, s64 *delta_offset, s64 *delta_size)
{
	thread_info_t	*ti = current_thread_info();
	e2k_addr_t	ps_base = (e2k_addr_t) GET_PS_BASE(ti);
	s64		ps_size = GET_PS_SIZE(ti);
	s64		ps_offset = GET_PS_OFFSET(ti);
	s64		ps_top    = GET_PS_TOP(ti);
	s64		new_offset;
	s64		new_size;
	int		stack_down = delta_stack < 0;
	int		retval;

	DebugSPRs("start");
	DebugHS("started to %s procedure stack: stack_addr 0x%lx stack_size 0x%lx kernel part size 0x%lx ps_base 0x%lx ps_size 0x%lx ps_offset 0x%lx ps_top 0x%lx\n",
		(stack_down) ? "constrict" : "expand", stack_addr, stack_size,
		KERNEL_P_STACK_SIZE, ps_base, ps_size, ps_offset, ps_top);

	BUG_ON(stack_addr >= TASK_SIZE);
	BUG_ON(ps_top != ps_offset + stack_size);

	*delta_offset = 0;
	*delta_size = 0;

	if (!stack_down) {
		if (stack_size + ps_offset >= ps_size)
			return handle_hardware_p_stack_overflow(
					ps_size, ps_offset, delta_stack);
		GET_UP_PS_OFFSET_SIZE(stack_size, ps_offset, ps_size,
					delta_stack, new_size, new_offset);
		DebugHS("ps_base 0x%lx new_size 0x%lx new_offset 0x%lx new top 0x%lx\n",
			ps_base, new_size, new_offset, new_offset + new_size);
	} else {
		if (ps_offset <= 0)
			return handle_hardware_p_stack_underflow(
					stack_size, ps_size, ps_offset);
		GET_DOWN_PS_OFFSET_SIZE(stack_size, ps_offset, delta_stack,
					new_size, new_offset);
		DebugHS("ps_base 0x%lx new_size 0x%lx new_offset 0x%lx new top 0x%lx\n",
			ps_base, new_size, new_offset, new_offset + new_size);
	}

	retval = expand_hardware_stack(ps_base, stack_addr, ps_top,
			new_offset, new_size, KERNEL_P_STACK_SIZE, stack_down,
			ps_offset, ps_top, new_offset, new_offset + new_size);
	if (retval)
		return retval;

	*delta_offset = new_offset - ps_offset;
	*delta_size = new_size - stack_size;
	DebugHS("new PS delta state: offset 0x%lx size 0x%lx\n",
		*delta_offset, *delta_size);

	SET_PS_OFFSET(ti, new_offset);
	SET_PS_TOP(ti, new_offset + new_size);

	DebugHS("succeeded\n");
	DebugSPRs("finish");
	return 0;
}

/**
 * handle_hardware_pc_stack_overflow - handles chain stack overflow
 * @pcs_size - stack size from thread_info
 * @pcs_offset - stack offset from thread_info
 * @delta_stack - stack increment
 */
static inline int
handle_hardware_pc_stack_overflow(s64 pcs_size, s64 pcs_offset, s64 delta_stack)
{
	if (UHWS_PSEUDO_MODE) {
		struct thread_info	*ti = current_thread_info();
		struct hw_stack_area	*user_pcsp_stk;
		e2k_size_t		area_size;
		e2k_size_t		present_offset;

		area_size = PAGE_ALIGN_UP(
				max(pcs_size + KERNEL_PC_STACK_SIZE +
					USER_PC_STACK_AREA_SIZE,
				(pcs_size + KERNEL_PC_STACK_SIZE) * 12 / 10));
		if (get_max_pcsp_size(area_size) != area_size)
			return -ENOMEM;
		present_offset = pcs_offset + delta_stack;

		DebugHS("will allocate user Procedure chain stack\n");
		user_pcsp_stk = alloc_user_pc_stack(area_size,
				       present_offset,
				       USER_PC_STACK_INIT_SIZE);
		if (!user_pcsp_stk) {
			DebugHS("could not allocate user Procedure chain stack\n");
			return -ENOMEM;
		}
		DebugHS("allocated user Procedure chain stack at 0x%p, size 0x%lx, init size 0x%lx, kernel part size 0x%lx\n",
			user_pcsp_stk->base, area_size, USER_PC_STACK_INIT_SIZE,
			KERNEL_PC_STACK_SIZE);

		list_add_tail(&user_pcsp_stk->list_entry, &ti->pcs_list);
		ti->cur_pcs = user_pcsp_stk;
		DebugHS("user Procedure chain stack area 0x%p was added to user Procedure chain stack areas list\n",
			user_pcsp_stk);
		return 0;
	}

	DebugHS("user chain stack overflow: offset 0x%lx max stack size 0x%lx\n",
		pcs_offset, pcs_size);
	return -ENOMEM;
}

/**
 * handle_hardware_pc_stack_underflow - handles chain stack underflow
 * @stack_size - stack size from pt_regs
 * @pcs_size - stack size from thread_info
 * @pcs_offset - stack offset from thread_info
 */
static inline int
handle_hardware_pc_stack_underflow(s64 stack_size, s64 pcs_size, s64 pcs_offset)
{
	if (UHWS_PSEUDO_MODE)
		panic("handle_hardware_pc_stack_underflow(): user chain stack underflow: stack size 0x%lx offset 0x%lx area size 0x%lx\n",
			stack_size, pcs_offset, pcs_size);
	else
		panic("handle_hardware_pc_stack_underflow(): user chain stack underflow: stack size 0x%lx offset 0x%lx max stack size 0x%lx\n",
			stack_size, pcs_offset, pcs_size);
	return 0;
}

/**
 * do_expand_hardware_pc_stack - handles chain stack overflow and underflow
 * @stack_addr - stack base address from pt_regs
 * @stack_size - stack size from pt_regs
 * @delta_stack - stack increment
 * @delta_offset - stack offset increment
 * @delta_size - stack size increment
 *
 * If chain stack overflow occured then the chain stack will be
 * expanded. In the case of stack underflow it will be constricted.
 */
static inline int
do_expand_hardware_pc_stack(e2k_addr_t stack_addr, s64 stack_size,
		s64 delta_stack, s64 *delta_offset, s64 *delta_size)
{
	thread_info_t	*ti = current_thread_info();
	e2k_addr_t	pcs_base = (e2k_addr_t) GET_PCS_BASE(ti);
	s64		pcs_size = GET_PCS_SIZE(ti);
	s64		pcs_offset = GET_PCS_OFFSET(ti);
	s64		pcs_top    = GET_PCS_TOP(ti);
	s64		new_offset;
	s64		new_size;
	int		stack_down = delta_stack < 0;
	int		retval;

	DebugSPRs("start");
	DebugHS("started to %s chain stack: stack_addr 0x%lx stack_size 0x%lx kernel part size 0x%lx pcs_base 0x%lx pcs_size 0x%lx pcs_offset 0x%lx pcs_top 0x%lx\n",
		(stack_down) ? "constrict" : "expand", stack_addr, stack_size,
		KERNEL_PC_STACK_SIZE, pcs_base, pcs_size, pcs_offset, pcs_top);

	BUG_ON(stack_addr >= TASK_SIZE);
	BUG_ON(pcs_top != pcs_offset + stack_size);

	*delta_offset = 0;
	*delta_size = 0;

	if (!stack_down) {
		if (stack_size + pcs_offset >= pcs_size)
			return handle_hardware_pc_stack_overflow(
					pcs_size, pcs_offset, delta_stack);
		GET_UP_PCS_OFFSET_SIZE(stack_size, pcs_offset, pcs_size,
				delta_stack, KERNEL_PC_STACK_SIZE, new_size,
				new_offset);
		DebugHS("pcs_base 0x%lx new_size 0x%lx new_offset 0x%lx new top 0x%lx\n",
			pcs_base, new_size, new_offset, new_offset + new_size);
	} else {
		if (pcs_offset <= 0)
			return handle_hardware_pc_stack_underflow(
					stack_size, pcs_size, pcs_offset);
		GET_DOWN_PCS_OFFSET_SIZE(stack_size, pcs_offset, delta_stack,
				KERNEL_PC_STACK_SIZE, new_size, new_offset);
		DebugHS("pcs_base 0x%lx new_size 0x%lx new_offset 0x%lx new top 0x%lx\n",
			pcs_base, new_size, new_offset, new_offset + new_size);
	}
	retval = expand_hardware_stack(pcs_base, stack_addr, pcs_top,
			new_offset, new_size, KERNEL_PC_STACK_SIZE, stack_down,
			pcs_offset, pcs_top, new_offset, new_offset + new_size);
	if (retval)
		return retval;

	*delta_offset = new_offset - pcs_offset;
	*delta_size = new_size - stack_size;
	DebugHS("new PCS delta state: offset 0x%lx size 0x%lx\n",
		*delta_offset, *delta_size);

	SET_PCS_OFFSET(ti, new_offset);
	SET_PCS_TOP(ti, new_offset + new_size);

	DebugHS("succeeded\n");
	DebugSPRs("finish");
	return 0;
}

/*
 * The function constricts hardware procedure stack in the case of 'long jump'
 */

static inline int
constrict_hardware_p_stack(struct pt_regs *regs, struct pt_regs *new_regs)
{
	thread_info_t	*ti = current_thread_info();
	e2k_addr_t	ps_base;
	long		ps_size, offset, new_offset, top,
			stack_size, new_stack_size;
	e2k_addr_t	stack_addr, new_stack_addr;
	int		retval;

	DebugCS("started\n");
	DebugSPRs("start");
	stack_addr = AS_STRUCT(regs->stacks.psp_lo).base;
	stack_size = AS_STRUCT(regs->stacks.psp_hi).size;
	new_stack_addr = AS_STRUCT(new_regs->stacks.psp_lo).base;
	new_stack_size = AS_STRUCT(new_regs->stacks.psp_hi).size;
	DebugCS("current procedure stack addr 0x%lx size 0x%lx ind 0x%x will be constricted to new addr 0x%lx size 0x%lx ind 0x%x\n",
		stack_addr, stack_size, AS_STRUCT(regs->stacks.psp_hi).ind,
		new_stack_addr, new_stack_size,
		AS_STRUCT(new_regs->stacks.psp_hi).ind);
	if (new_stack_addr == stack_addr && new_stack_size == stack_size) {
		DebugCS("is returning: new procedure stack is the same as current\n");
		return 0;
	}
	if (trap_from_kernel(regs)) {
		panic("Kernel Procedure stack cannot be constricted\n");
	}
	ps_base = (e2k_addr_t) GET_PS_BASE(ti);
	ps_size = GET_PS_SIZE(ti);
	offset = GET_PS_OFFSET(ti);
	top = GET_PS_TOP(ti);
	DebugCS("ps_base 0x%lx ps_size 0x%lx current offset 0x%lx current top 0x%lx\n",
		ps_base, ps_size, offset, top);

	if (top != offset + stack_size) {
		if (top != offset + stack_size - KERNEL_P_STACK_SIZE) {
			panic("constrict_hardware_p_stack(): Procedure stack offset 0x%lx + size 0x%lx - kernel size 0x%lx != top 0x%lx\n",
				offset, stack_size, KERNEL_P_STACK_SIZE, top);
		}
		DebugHS("Procedure stack size included kernel part 0x%lx, user part only 0x%lx\n",
			stack_size, stack_size - KERNEL_P_STACK_SIZE);
		stack_size -= KERNEL_P_STACK_SIZE;
	}
	new_offset = new_stack_addr - ps_base;
	GET_DOWN_PS_OFFSET_SIZE(stack_size, offset, new_offset - offset,
					new_stack_size, new_offset);
	DebugCS("new stack offset 0x%lx, size 0x%lx\n",
		new_offset, new_stack_size);

	if (new_offset > offset) {
		DebugCS("invalid user procedure stack offset to constrict (> current)\n");
		force_sig(SIGSEGV, current);
		return -ENOMEM;
	}

	retval = expand_hardware_stack(ps_base, stack_addr, top,
			new_offset, new_stack_size, KERNEL_P_STACK_SIZE, 1,
			offset, top, new_offset, new_offset + new_stack_size);
	if (retval != 0)
		return retval;

	DebugCS("new PSP state: base 0x%lx size 0x%lx ind 0x%x offset 0x%lx\n",
		new_stack_addr, new_stack_size,
		AS_STRUCT(new_regs->stacks.psp_hi).ind, new_offset);
	SET_PS_OFFSET(ti, new_offset);
	SET_PS_TOP(ti, new_offset + new_stack_size);

	DebugCS("succeeded\n");
	DebugSPRs("finish");
	return 0;
}

/*
 * The function constricts hardware procedure chain stack in the case of
 * 'long jump'
 */

static inline int
constrict_hardware_pc_stack(struct pt_regs *regs, struct pt_regs *new_regs)
{
	thread_info_t	*ti = current_thread_info();
	e2k_addr_t	pcs_base;
	long		pcs_size, offset, new_offset,
			stack_size, new_stack_size, top;
	e2k_addr_t	stack_addr, new_stack_addr;
	int		retval;

	DebugCS("started\n");
	DebugSPRs("start");
	stack_addr = AS_STRUCT(regs->stacks.pcsp_lo).base;
	stack_size = AS_STRUCT(regs->stacks.pcsp_hi).size;
	new_stack_addr = AS_STRUCT(new_regs->stacks.pcsp_lo).base;
	new_stack_size = AS_STRUCT(new_regs->stacks.pcsp_hi).size;

	DebugCS("current procedure chain stack addr 0x%lx size 0x%lx ind 0x%x will be constricted to new addr 0x%lx size 0x%lx ind 0x%x\n",
		stack_addr, stack_size, AS_STRUCT(regs->stacks.pcsp_hi).ind,
		new_stack_addr, new_stack_size,
		AS_STRUCT(new_regs->stacks.pcsp_hi).ind);
	if (new_stack_addr == stack_addr && new_stack_size == stack_size) {
		DebugCS("is returning: new procedure chain stack is the same as current\n");
		return 0;
	}
	if (trap_from_kernel(regs)) {
		panic("Kernel Procedure Chain stack cannot be constricted\n");
	}
	pcs_base = (e2k_addr_t) GET_PCS_BASE(ti);
	pcs_size = GET_PCS_SIZE(ti);
	offset = GET_PCS_OFFSET(ti);
	top = GET_PCS_TOP(ti);

	DebugCS("pcs_base 0x%lx pcs_size 0x%lx current offset 0x%lx current top 0x%lx\n",
		pcs_base, pcs_size, offset, top);

	if (top != offset + stack_size) {
		if (top != offset + stack_size - KERNEL_PC_STACK_SIZE) {
			panic("constrict_hardware_pc_stack(): Procedure chain stack offset 0x%lx + size 0x%lx - kernel size 0x%lx != top 0x%lx\n",
				offset, stack_size, KERNEL_PC_STACK_SIZE, top);
		}
		DebugHS("Procedure chain stack size included kernel part 0x%lx, user part only 0x%lx\n",
			stack_size, stack_size - KERNEL_PC_STACK_SIZE);
		stack_size -= KERNEL_PC_STACK_SIZE;
	}
	new_offset = new_stack_addr - pcs_base;
	GET_DOWN_PCS_OFFSET_SIZE(stack_size, offset, new_offset - offset,
					KERNEL_PC_STACK_SIZE,
					new_stack_size, new_offset);
	DebugCS("new stack offset 0x%lx, size 0x%lx\n",
		new_offset, new_stack_size);

	if (new_offset > offset) {
		DebugCS("invalid user procedure chain stack offset to constrict (> current)\n");
		force_sig(SIGSEGV, current);
		return -ENOMEM;
	}

	retval = expand_hardware_stack(pcs_base, stack_addr, top,
			new_offset, new_stack_size, KERNEL_PC_STACK_SIZE, 1,
			offset, top, new_offset, new_offset + new_stack_size);
	if (retval != 0)
		return retval;

	DebugCS("new PCSP state: base 0x%lx size 0x%lx ind 0x%x offset 0x%lx\n",
		new_stack_addr, new_stack_size,
		AS_STRUCT(new_regs->stacks.pcsp_hi).ind, new_offset);
	SET_PCS_OFFSET(ti, new_offset);
	SET_PCS_TOP(ti, new_offset + new_stack_size);

	DebugCS("succeeded\n");
	DebugSPRs("finish");
	return 0;
}

/*
 * The function constricts hardware procedure stack and procedure chain stack
 * in the case of 'long jump'
 */

int
constrict_hardware_stacks(struct pt_regs *regs, struct pt_regs *new_regs)
{
	int ret;

	ret = constrict_hardware_p_stack(regs, new_regs);
	if (ret != 0)
		return ret;
	ret = constrict_hardware_pc_stack(regs, new_regs);
	if (ret != 0)
		return ret;
	return 0;
}

__section(.entry_handlers)
void expand_hw_stacks_in_syscall(struct pt_regs *regs)
{
	e2k_pcsp_hi_t pcsp_hi;
	e2k_psp_hi_t psp_hi;
	s64 delta_offset, delta_size;
	unsigned long flags;
	int ret;

	BUG_ON(irqs_disabled());

	raw_all_irq_save(flags);
	BUG_ON(sge_checking_enabled());
	psp_hi = RAW_READ_PSP_HI_REG();
	pcsp_hi = RAW_READ_PCSP_HI_REG();
	raw_all_irq_restore(flags);

	if (AS(pcsp_hi).ind >= USER_PC_STACK_INIT_SIZE) {
		e2k_pcsp_lo_t pcsp_lo = READ_PCSP_LO_REG();

		ret = do_expand_hardware_pc_stack(AS(pcsp_lo).base,
				AS(pcsp_hi).size, USER_PC_STACK_BYTE_INCR,
				&delta_offset, &delta_size);
		if (ret) {
			pr_info_ratelimited("%d/%s: Could not expand chain stack\n",
					current->pid, current->comm);
			goto fail;
		}

		if (delta_offset || delta_size) {
			raw_all_irq_save(flags);
			switch_to_expanded_pc_stack(delta_offset, delta_size);
			if (regs) {
				AS(regs->stacks.pcsp_lo).base += delta_offset;
				AS(regs->stacks.pcsp_hi).size += delta_size;
				AS(regs->stacks.pcsp_hi).ind -= delta_offset;
			}
			raw_all_irq_restore(flags);
		} else {
			ret = switch_to_next_pc_stack_area();
			if (ret) {
				pr_info_ratelimited("%d/%s: Could not switch to new chain stack\n",
						current->pid, current->comm);
				goto fail;
			}
			if (regs) {
				struct hw_stack_area *cur_u_pcs =
						current_thread_info()->cur_pcs;

				AS(regs->stacks.pcsp_hi).size = cur_u_pcs->top -
						cur_u_pcs->offset +
						KERNEL_PC_STACK_SIZE;
				AS(regs->stacks.pcsp_lo).base =
					(unsigned long) cur_u_pcs->base +
					cur_u_pcs->offset;
				if (UHWS_PSEUDO_MODE)
					AS(regs->stacks.pcsp_hi).ind -=
						       USER_PC_STACK_BYTE_INCR;
				else
					AS(regs->stacks.pcsp_hi).ind +=
						PAGE_SIZE -
						(AS(regs->stacks.pcsp_hi).size -
						 KERNEL_PC_STACK_SIZE);
			}
		}
	}

	if (AS(psp_hi).ind >= USER_P_STACK_INIT_SIZE) {
		e2k_psp_lo_t psp_lo = READ_PSP_LO_REG();

		ret = do_expand_hardware_p_stack(AS(psp_lo).base,
				AS(psp_hi).size, USER_P_STACK_BYTE_INCR,
				&delta_offset, &delta_size);
		if (ret) {
			pr_info_ratelimited("%d/%s: Could not expand procedure stack\n",
					current->pid, current->comm);
			goto fail;
		}

		if (delta_offset || delta_size) {
			raw_all_irq_save(flags);
			switch_to_expanded_p_stack(delta_offset, delta_size);
			if (regs) {
				AS(regs->stacks.psp_lo).base += delta_offset;
				AS(regs->stacks.psp_hi).size += delta_size;
				AS(regs->stacks.psp_hi).ind -= delta_offset;
			}
			raw_all_irq_restore(flags);
		} else {
			ret = switch_to_next_p_stack_area();
			if (ret) {
				pr_info_ratelimited("%d/%s: Could not switch to new procedure stack\n",
						current->pid, current->comm);
				goto fail;
			}
			if (regs) {
				struct hw_stack_area *cur_u_ps =
						current_thread_info()->cur_ps;

				AS(regs->stacks.psp_hi).size = cur_u_ps->top -
						cur_u_ps->offset +
						KERNEL_P_STACK_SIZE;
				AS(regs->stacks.psp_lo).base =
					(unsigned long) cur_u_ps->base +
					cur_u_ps->offset;
				if (UHWS_PSEUDO_MODE)
					AS(regs->stacks.psp_hi).ind -=
						       USER_P_STACK_BYTE_INCR;
				else
					AS(regs->stacks.psp_hi).ind +=
						PAGE_SIZE -
						(AS(regs->stacks.psp_hi).size -
						 KERNEL_P_STACK_SIZE);
			}
		}
	}

	return;

fail:
	do_exit(((-ret) & 0xff) << 8);
}

/*
 * The function handles traps on hardware procedure stack overflow or
 * underflow. If stack overflow occured then the procedure stack will be
 * expanded. In the case of stack underflow it will be constricted
 */
int do_proc_stack_bounds(struct pt_regs *regs)
{
	e2k_psp_lo_t	psp_lo = regs->stacks.psp_lo;
	e2k_psp_hi_t	psp_hi = regs->stacks.psp_hi;
	s64		delta_stack, delta_offset, delta_size;
	long		flags;
	int		ret;

	if (!user_mode(regs))
		AS(psp_hi).size -= KERNEL_P_STACK_SIZE;

	if (psp_hi.PSP_hi_ind > psp_hi.PSP_hi_size / 2)
		delta_stack = USER_P_STACK_BYTE_INCR;
	else
		delta_stack = -USER_P_STACK_BYTE_DECR;
	DebugHS("started with PS: base 0x%llx, ind 0x%x, size 0x%x: to %s at 0x%lx\n",
		psp_lo.PSP_lo_base, psp_hi.PSP_hi_ind, psp_hi.PSP_hi_size,
		((delta_stack < 0) ? "constrict" : "expand"), delta_stack);

	ret = do_expand_hardware_p_stack(psp_lo.PSP_lo_base, psp_hi.PSP_hi_size,
				delta_stack, &delta_offset, &delta_size);
	if (ret) {
		SDBGPRINT("SIGSEGV. Could not expand procedure stack");
		goto out_sigsegv;
	}

	if (delta_offset || delta_size) {
		raw_all_irq_save(flags);
		switch_to_expanded_p_stack(delta_offset, delta_size);
		raw_all_irq_restore(flags);
	} else {
		if (delta_stack > 0)
			ret = switch_to_next_p_stack_area();
		else
			BUG();
		if (ret) {
			SDBGPRINT("SIGSEGV. Could not switch to new procedure stack");
			goto out_sigsegv;
		}
	}

	return 0;

out_sigsegv:
	DebugHS("could not handle stack bounds, error %d\n", ret);
	force_sig(SIGSEGV, current);

	return ret;
}

/*
 * The function handles traps on hardware procedure chaine stack overflow or
 * underflow. If stack overflow occured then the procedure chaine stack will
 * be expanded. In the case of stack underflow it will be constricted
 */

int do_chain_stack_bounds(struct pt_regs *regs)
{
	e2k_pcsp_lo_t	pcsp_lo = regs->stacks.pcsp_lo;
	e2k_pcsp_hi_t	pcsp_hi = regs->stacks.pcsp_hi;
	s64		delta_stack, delta_offset, delta_size;
	long		flags;
	int		ret;

	if (!user_mode(regs))
		AS(pcsp_hi).size -= KERNEL_PC_STACK_SIZE;

	if (pcsp_hi.PCSP_hi_ind > pcsp_hi.PCSP_hi_size / 2)
		delta_stack = USER_PC_STACK_BYTE_INCR;
	else
		delta_stack = -USER_PC_STACK_BYTE_DECR;
	DebugHS("started with PCS: base 0x%llx, ind 0x%x, size 0x%x: to %s at 0x%lx\n",
		pcsp_lo.PCSP_lo_base, pcsp_hi.PCSP_hi_ind, pcsp_hi.PCSP_hi_size,
		((delta_stack < 0) ? "constrict" : "expand"), delta_stack);

	ret = do_expand_hardware_pc_stack(pcsp_lo.PCSP_lo_base,
				pcsp_hi.PCSP_hi_size,
				delta_stack, &delta_offset, &delta_size);
	if (ret) {
		SDBGPRINT("SIGSEGV. Could not expand chine stack");
		goto out_sigsegv;
	}

	if (delta_offset || delta_size) {
		raw_all_irq_save(flags);
		switch_to_expanded_pc_stack(delta_offset, delta_size);
		raw_all_irq_restore(flags);
	} else {
		if (delta_stack > 0)
			ret = switch_to_next_pc_stack_area();
		else
			BUG();
		if (ret) {
			SDBGPRINT("SIGSEGV. Could not switch to new chine stack");
			goto out_sigsegv;
		}
	}

	return 0;

out_sigsegv:
	DebugHS("could not handle stack bounds, error %d\n", ret);
	force_sig(SIGSEGV, current);

	return ret;
}

static inline int
check_srp_operation(struct trap_pt_regs *trap)
{
	instr_hs_t hs;
	instr_ss_t ss;
	instr_syl_t *user_sp;
	e2k_addr_t trap_ip;
	tir_lo_struct_t tir_lo;

	tir_lo.TIR_lo_reg = trap->TIR_lo;
	trap_ip = tir_lo.TIR_lo_ip;

	DbgTC("started for IP 0x%lx\n",
		trap_ip);
	user_sp = &E2K_GET_INSTR_HS(trap_ip);
	__get_user(AS_WORD(hs), user_sp);
	if (!AS_STRUCT(hs).s) {
		DbgTC("command has not Stubs "
			"Syllable: 0x%08x\n", AS_WORD(hs));
		return 0;
	}
	user_sp = &E2K_GET_INSTR_SS(trap_ip);
	__get_user(AS_WORD(ss), user_sp);
	DebugSRP("command has Stubs "
		"Syllable: 0x%08x SRP is %d trap_ip =%lx\n",
		AS_WORD(ss), AS_STRUCT(ss).srp, trap_ip);
	return AS_STRUCT(ss).srp;
}

/*
 * execute_mmu_operations() return values
 */
enum exec_mmu_ret {
	/* Successfully executed, go to the next trap cellar record */
	EXEC_MMU_SUCCESS = 1,
	/* Stop handling trap cellar and exit */
	EXEC_MMU_STOP,
	/* Trap cellar record should be executed again */
	EXEC_MMU_REPEAT
};

/*
 * do_page_fault() return values
 */
enum pf_ret {
	/* Could not handle fault, must return to handle signals */
	PFR_SIGPENDING = 1,
	/* The page fault was handled */
	PFR_SUCCESS,
	/* In some cases kernel addresses can be in Trap Cellar if VLIW command
	 * consisted of a several load/store operations and one of them caused
	 * page fault trap */
	PFR_KERNEL_ADDRESS,
	/* Do not handle speculative access */
	PFR_IGNORE,
	/* Controlled access from kernel to user memory */
	PFR_CONTROLLED_ACCESS,
	/* needs to change SAP to AP for multi_threading of protected mode */
	PFR_AP_THREAD_READ
};

static inline void debug_print_trap_cellar(trap_cellar_t *tcellar,
					   unsigned int tc_count)
{
	unsigned int cnt;
	tc_fault_type_t ftype;
	int chan;

	DbgTC("Counted %d records\n", tc_count);

	if (!(DEBUG_TRAP_CELLAR || DEBUG_STATE_TC))
		return;

	for (cnt = 0; (3 * cnt) < tc_count; cnt++) {
		AW(ftype) = AS(tcellar[cnt].condition).fault_type;
		chan = AS(tcellar[cnt].condition).chan;
		pr_info("do_trap_cellar: cnt %d add 0x%lx ftype %x chan 0x%x\n",
				cnt, tcellar[cnt].address, AW(ftype), chan);
		PrintTC(&tcellar[cnt], cnt);
	}
}

static inline void copy_nested_tc_records(struct pt_regs *regs,
		trap_cellar_t *tcellar, unsigned int tc_count)
{
	struct pt_regs	*pregs = regs->next;
	struct trap_pt_regs *ptrap = pregs->trap;
	tc_cond_t	*pcond, *cond;
	int		i;

	DbgTC("nested exception detected\n");

	if (unlikely(!ptrap))
		panic("do_trap_cellar() previous pt_regs are not from trap\n");

	if (unlikely(!user_mode(pregs) &&
			!current_thread_info()->usr_pfault_jump))
		panic("do_trap_cellar() previous pt_regs are not user's\n");

	/*
	 * We suppose that there could be only one record in
	 * trap cellar because of nested exception in
	 * execute_mmu_operations() plus there could be few
	 * spill/fill records. Other records aren't allowed.
	 */
	for (i = 1; (3 * i) < tc_count; i++) {
		if (!AS(tcellar[i].condition).s_f) {
			print_all_TC(tcellar, tc_count);
			panic("do_trap_cellar() invalid trap cellar content\n");
		}
	}

	/* Modify fault_type */
	cond = &tcellar[0].condition;
	pcond = &ptrap->tcellar[ptrap->curr_cnt].condition;
	AS(*pcond).fault_type = AS(*cond).fault_type;

	ptrap->tcellar[ptrap->curr_cnt].flags |= TC_NESTED_EXC_FLAG;
}

/**
 * tc_record_asynchronous - return true if the record is asynchronous
 * @tcellar: record in question
 *
 * Asynchronous records are the ones that did not originate from wide
 * instruction in user code, i.e. hardware-generated records.
 *
 * In current processor models (and probably in all future ones) only
 * CLW records can mix with synchronous ones.
 */
static inline int tc_record_asynchronous(trap_cellar_t *tcellar)
{
	tc_cond_t cond = tcellar->condition;

	/* We use bitwise OR for performance */
	return AS(cond).mode_80 | AS(cond).s_f | AS(cond).sru | AS(cond).clw;
}

void do_trap_cellar(struct pt_regs *regs, int only_system_tc)
{
	struct trap_pt_regs	*trap = regs->trap;
	trap_cellar_t		*tcellar = trap->tcellar;
	unsigned int		tc_count, cnt;
	tc_fault_type_t 	ftype;
	int			chan, rval;
	/* flag of global_sp operations */
	int			gsp_flag;
	/* number of global_sp records */
	int			global_sp_num;
	int			ignore_request = 0;
	int			nested = 0;
	int			srp_flag = 0, store_flag;
	e2k_addr_t		srp_ip;
	/* store recovery point in RPR */
	int                     rpr_srp_flag;
	long			multithread_addr = 0;
	/* number of multithread_sp */
	int			multithread_sp_num = 0;
	s64 last_store = -1, last_load = -1;

	/* In TRAP_CELLAR we have records that was dropped by MMU when trap 
	 * occured. Each record consist from 3 dword, fist is address (possible
	 * address that cause fault), second is data dword that contain 
	 * information needed to store (stored data), third is a condition word
	 * Maximum records in TRAP_CELLAR is MAX_TC_SIZE (10).
	 * We should do that user signal handler will be run for every
	 * trap if it is needed. So we should continue do_trap_cellar()
	 * after we ret from user's sighandler (see handle_signal in signal.c).
	 */

	DbgTC("tick %ld CPU #%ld trap cellar regs addr 0x%p\n",
		E2K_GET_DSREG(clkr), (long)raw_smp_processor_id(), tcellar);
	DbgTC("regs->CR0.hi ip 0x%lx user_mode %d\n",
		(long)AS_STRUCT(regs->crs.cr0_hi).ip << 3,
		trap_from_user(regs));

	tc_count = trap->tc_count;

	if (trap->curr_cnt == -1) {
		tir_lo_struct_t	tir_lo;

		debug_print_trap_cellar(tcellar, tc_count);

		/*
		 * Check if we are in the nested exception that appeared while
		 * executing execute_mmu_operations()
		 */
		if (unlikely(current->thread.flags & E_MMU_OP)) {
			copy_nested_tc_records(regs, tcellar, tc_count);

			nested = 1;

			/*
			 * Nested exc_data_page or exc_mem_lock appeared, so
			 * one needs to tell execute_mmu_operations() about it.
			 * execute_mmu_operations() will return EXEC_MMU_REPEAT
			 * in this case. do_trap_cellar will analyze this
			 * returned value and repeat execution of current
			 * record with modified data.
			 */
			current->thread.flags |= E_MMU_NESTED_OP;


			/*
			 * We suppose that spill/fill records are
			 * placed at the end of trap cellar
			 */
			trap->curr_cnt = 1;
		}

		if (unlikely(GET_CLW_REQUEST_COUNT(regs))) {
			int clw_first = GET_CLW_FIRST_REQUEST(regs);
			
			DebugCLW("Detected CLW %d request(s)\n",
				GET_CLW_REQUEST_COUNT(regs));
			if (DEBUG_CLW_FAULT) {
				for (cnt = 0; (3 * cnt) < tc_count; cnt++) {
					AW(ftype) = AS(tcellar[cnt].condition).
								fault_type;
					chan = AS(tcellar[cnt].condition).chan;
					printk("do_trap_cellar: cnt %d add 0x%lx ftype %x chan 0x%x\n",
						cnt, tcellar[cnt].address,
						AW(ftype), chan);
					PrintTC(&tcellar[cnt], cnt);
				}
			}
			AW(ftype) = AS(tcellar[clw_first].condition).
								fault_type;
			if (AW(ftype) != 0) {
				DebugCLW("starts do_page_fault() for first CLW request #%d\n",
					clw_first);
				rval = do_page_fault(regs,
					tcellar[clw_first].address,
					&(tcellar[clw_first].condition), 0);
				if (rval == PFR_SIGPENDING) {
					DebugCLW("BAD CLW AREA\n");
					return;
				}
			}
			terminate_CLW_operation(regs);
		}

		if (TASK_IS_BINCO(current)) {
			if (IS_MACHINE_E3M)
				srp_flag = check_srp_operation(trap);
			else
				srp_flag = E2K_GET_DSREG(rpr.hi) >> 63 & 1;
		}
		if (srp_flag)
			trap->srp_flags = SRP_FLAG_PT_REGS;
		else
			trap->srp_flags = 0;

		/*
		 * One should save srp_ip, because trap->TIR_lo could be
		 * differed from current, when do_trap_cellar() is called from
		 * do_sigreturn().
		 */
		tir_lo.TIR_lo_reg = trap->TIR_lo;
		srp_ip = tir_lo.TIR_lo_ip;

		if (!nested)
			trap->curr_cnt = 0;
	} else {
		/*
		 * We continue to do_trap_cellar() after user's sig handler
		 * to work for next trap in trap_cellar.
	 	 * If user's sighandler, for example, do nothing
	 	 * then we should do that call user's sighandler
	 	 * once more for the same trap.
		 * So trap->curr_cnt is here the same for which
	 	 * user's sighandler worked. 
		 */
		if ((3 * trap->curr_cnt) >= tc_count)
			return;
		DbgTC("curr_cnt == %d tc_count / 3 %d\n",
				trap->curr_cnt, tc_count / 3);
		srp_flag = trap->srp_flags & SRP_FLAG_PT_REGS;
	}

	global_sp_num = 0;
	gsp_flag = 0;	/* clear the flag before the loop */

#pragma loop count (3)
	for (cnt = trap->curr_cnt; (3 * cnt) < tc_count;
			cnt++, trap->curr_cnt++) {
		if (tcellar[cnt].flags & TC_DONE_FLAG)
			continue;

		if (unlikely(trap->ignore_user_tc) || only_system_tc) {

			/*
			 * Can get here if:
			 * 1) Kernel wants to handle only system records of
			 * trap cellar.
			 * 2) Controlled access from kernel to user failed.
			 */
			if (!tc_record_asynchronous(&tcellar[cnt]))
				continue;
		}

repeat:
		store_flag = 0;
		rpr_srp_flag = 0;

		AW(ftype) = AS(ACCESS_ONCE(tcellar[cnt].condition)).fault_type;

		DbgTC("ftype == %x address %lx\n",
			AW(ftype), tcellar[cnt].address);

		ignore_request = 0;

		if (AS(tcellar[cnt].condition).clw) {
			DbgTC("found CLW request in : "
				"trap cellar ,cnt %d\n",
				cnt);
			ignore_request = 1;
			rval = PFR_IGNORE;
		} else if (AS(tcellar[cnt].condition).s_f) {
			if (AS(tcellar[cnt].condition).store) {
				DbgTC("found SPILL request "
					"in trap cellar cnt %d\n", cnt);
				rval = PFR_SUCCESS;
			} else if (AS(tcellar[cnt].condition).sru) {
				DbgTC("found FILL chain "
					"stack request in trap cellar "
					"cnt %d\n",
					cnt);
				ignore_request = 1;
				rval = PFR_SUCCESS;
			} else {
				panic("do_trap_cellar(): found FILL procedure "
					"stack request in trap cellar "
					"cnt %d\n",
					cnt);
			}
		} else if (AS(ftype).exc_mem_lock) {
			DbgTC("do_trap_cellar: exc_mem_lock\n");
			if (!trap->from_sigreturn) {
				S_SIG(regs, SIGBUS, exc_mem_lock_num,
					BUS_OBJERR);
				SDBGPRINT("SIGBUS. Memory lock signaled");
				break;
			}
			/*
			 * We can be here only after binary compiler's
			 * SIGBUS handler when handler wants kernel to
			 * complete memory operations from cellar.
			 * Never ignore this request and carry out
			 * execute_mmu_operations.
			 */
			rval = PFR_SUCCESS;
		} else if (TASK_IS_BINCO(current) &&
				srp_flag && AS(tcellar[cnt].condition).store) {
			DebugSRP("found memory store "
				"request with SRP flag in trap cellar "
				"cnt %d\n",
				cnt);
			if (AS(tcellar[cnt].condition).chan == 3)
				rpr_srp_flag = 1;
			rval = do_page_fault(regs, tcellar[cnt].address,
					&(tcellar[cnt].condition), 0);
			store_flag = 1;
		} else {
			unsigned long old_address = tcellar[cnt].address;
			bool same = false,
			     async = tc_record_asynchronous(&tcellar[cnt]);

			if (!async &&
			    !(tcellar[cnt].flags & TC_NESTED_EXC_FLAG)) {
				if (AS(tcellar[cnt].condition).store) {
					if (last_store != -1 &&
					    round_down(tcellar[cnt].address,
								PAGE_SIZE) ==
					    round_down(tcellar[last_store].address,
								PAGE_SIZE)) {
						same = true;
					}
				} else {
					if (last_load != -1 &&
					    round_down(tcellar[cnt].address,
								PAGE_SIZE) ==
					    round_down(tcellar[last_load].address,
								PAGE_SIZE)) {
						same = true;
					}
				}
			}

			if (same) {
				rval = PFR_SUCCESS;
			} else {
				rval = do_page_fault(regs, tcellar[cnt].address,
						&(tcellar[cnt].condition), 0);

				if (rval == PFR_SUCCESS && !async) {
					if (AS(tcellar[cnt].condition).store)
						last_store = cnt;
					else
						last_load = cnt;
				}
			}
			if (rval == PFR_AP_THREAD_READ) {
				multithread_sp_num++;
				if (multithread_addr == 0)
					multithread_addr = old_address;
				DebugMT_PM("do_trap_cellar multithread_sp_num=%d cnt=%d\n",
						multithread_sp_num, cnt);

				rval = PFR_SUCCESS;
			}
		}

		switch (rval) {
		case PFR_SIGPENDING:
			/* 
			 * Either BAD AREA, so SIGSEGV or SIGBUS and maybe
			 * a sighandler, or SIGBUS due to page_bound in lock
			 * trap on load/store, or after invalidating unaligned
			 * MLT entry on lock trap on store PF handling.
			 */
			DbgTC("BAD AREA\n");
			goto out;
		case PFR_CONTROLLED_ACCESS:
			/* Controlled access from kernel to user space,
			 * just invalidate diagnostic tag in reg if load. */
			if (!AS(tcellar[cnt].condition).store)
				execute_mmu_operations(&tcellar[cnt],
						       regs, 1, 0);

			/* No need to execute the following user loads/stores */
			trap->ignore_user_tc = true;
			break;
		case PFR_SUCCESS:
			/* check if the position is valid */
			if (AS(ftype).global_sp || global_sp_num == 1) {
				global_sp_num++;
				DbgTC("Store local to global"
					" #%d\n", global_sp_num);
				if (AS(ftype).global_sp && global_sp_num > 1) {
					pr_info("TC request #%d with global_sp ftype\n",
							global_sp_num);
				}

				/*
				 * This will be executed twice.
				 * First time for the low dword of the SAP
				 * and the second time for high dword.
				 * Actual processsing does happen on the first
				 * pass only.
				 */
				if (global_sp_num > 2) {
					/*
					 * ASSERT: should be only one request
					 * with global SP (2 records in the TC)
					 */
					panic("do_trap_cellar: too many "
						"request with global SP "
						"(should be only one)");
				}
				if (global_sp_num == 1 &&
						(3 * (cnt + 1) >= tc_count)) {
					panic("do_trap_cellar: only one "
						"record for global SP in the "
						"TC (should be two)");
				}

#ifdef CONFIG_PROTECTED_MODE
				if (global_sp_num == 1) {
					/* do nothing on the second pass */
					gsp_flag = do_global_sp(
							regs, &tcellar[cnt]);
				}
#endif /* CONFIG_PROTECTED_MODE */
			}
			if (AS(tcellar[cnt].condition).sru &&
					!AS(tcellar[cnt].condition).s_f) {
				DbgTC("page fault on CU upload"
					" condition: 0x%lx\n",
					AW(tcellar[cnt].condition));
			} else if (!gsp_flag && !ignore_request) {
				e2k_addr_t addr;
				rval = execute_mmu_operations(
						&tcellar[cnt], regs, 0, &addr);

#ifdef CONFIG_PROTECTED_MODE
				/*
				 * We deal with quadro operations and must
				 * correct result after second load
				 */
				if (multithread_sp_num > 0 &&
                                                multithread_sp_num % 2 == 0) {
					/*
					 * If we read this SAP in other thread
					 * than it needs change SAP to AP
					 */
					extern void change_sap(
							int, pt_regs_t *,
							e2k_addr_t, long);
					change_sap(cnt-1, regs, addr,
							multithread_addr);
					multithread_sp_num = 0;
					multithread_addr = 0;
				}
#endif /* CONFIG_PROTECTED_MODE */
				DbgTC("execute_mmu_operations"
					"() finished for cnt %d rval %d "
					"addr=%lx\n",
					cnt, rval, addr);
				if (rval == EXEC_MMU_STOP) {
					goto out;
				} else if (rval == EXEC_MMU_REPEAT) {
					goto repeat;
				}
			}
			break;
		case PFR_KERNEL_ADDRESS:
			if (!ignore_request) {
				DbgTC("kernel address has been detected in Trap Cellar for cnt %d\n",
						cnt);
				rval = execute_mmu_operations(&tcellar[cnt],
							      regs, 0, 0);
				DbgTC("execute_mmu_operations() finished for cnt %d rval %d\n",
						cnt, rval);
				if (rval == EXEC_MMU_STOP)
					goto out;
				if (rval == EXEC_MMU_REPEAT)
					goto repeat;
			}
			break;
		case PFR_IGNORE:
			DbgTC("ignore request in trap cellar "
				"and do not start execute_mmu_operations "
				"for cnt %d\n", cnt);
			break;
		default:
			panic("Unknown do_page_fault return value %d\n", rval);
		}

		/* Do not update RPR when nested exception occured. */
		if (srp_flag && store_flag && !regs->rp_ret)
			calculate_new_rpr(regs, srp_ip, rpr_srp_flag);

		trap->from_sigreturn = 0;
		tcellar[cnt].flags |= TC_DONE_FLAG;
	}

out:
	if (only_system_tc)
		trap->curr_cnt = (nested ? 1 : 0);
}

static void debug_print_page_fault(unsigned long address,
				   struct trap_pt_regs *trap)
{
	struct mm_struct *mm = current->mm;

	print_all_TIRs(trap->TIRs, trap->nr_TIRs);
	print_all_TC(trap->tcellar, trap->tc_count);
	print_mmap(current);
	print_stack(current);
	if (address < TASK_SIZE)
		print_user_address_ptes(mm, address);
	else
		print_kernel_address_ptes(address);
	DebugPF("MMU_ADDR_CONT = 0x%lx\n", read_MMU_reg(MMU_ADDR_CONT));
	if (DEBUG_PF_MODE) {
		print_va_tlb(address, 0);
		print_va_tlb(pte_virt_offset(
				_PAGE_ALIGN_UP(address, PTE_SIZE)), 0);
		print_va_tlb(pmd_virt_offset(
				_PAGE_ALIGN_UP(address, PMD_SIZE)), 0);
		print_va_tlb(pud_virt_offset(
				_PAGE_ALIGN_UP(address, PUD_SIZE)), 0);
		if (address < TASK_SIZE) {
			__print_user_address_ptes(mm, pte_virt_offset(
					_PAGE_ALIGN_UP(address, PTE_SIZE)));
			__print_user_address_ptes(mm, pmd_virt_offset(
					_PAGE_ALIGN_UP(address, PMD_SIZE)));
			__print_user_address_ptes(mm, pud_virt_offset(
					_PAGE_ALIGN_UP(address, PUD_SIZE)));
		} else {
			print_kernel_address_ptes(
				pte_virt_offset(
					_PAGE_ALIGN_UP(address, PTE_SIZE)));
			print_kernel_address_ptes(
				pmd_virt_offset(
					_PAGE_ALIGN_UP(address, PMD_SIZE)));
			print_kernel_address_ptes(
				pud_virt_offset(
					_PAGE_ALIGN_UP(address, PUD_SIZE)));
		}
	}
}

union pf_mode {
	struct {
		u32 write     : 1;
		u32 spec      : 1;
		u32 user      : 1;
		u32 root      : 1;
		u32 num_align : 1;
	};
	u32 word;
};

static int pf_out_of_memory(unsigned long address, struct pt_regs *regs)
{
	up_read(&current->mm->mmap_sem);

	if (!current->mm)
		panic("do_page_fault: kernel_mode out_of_memory. IP = 0x%llx\n",
				AS(regs->crs.cr0_hi).ip << 3);

	pr_info("do_page_fault: out_of_memory. SIGKILL for address %lx. IP = 0x%llx\n",
			address, AS(regs->crs.cr0_hi).ip << 3);

	force_sig(SIGKILL, current);

	return PFR_SIGPENDING;
}

/*
 * Is the operation a semi-speculative load? If yes, the address
 * could be any value. Ignore this record. The needed diagnostic
 * value has been written to the register by hardware.
 */
static int handle_spec_load_fault(unsigned long address, struct pt_regs *regs,
		union pf_mode mode)
{
	if (!mode.spec || mode.write)
		return 0;

#ifdef CONFIG_MAKE_ALL_PAGES_VALID
	if (address < TASK_SIZE) {
		/*
		 * Flush bad pte from TLB which have been written there
		 * by hardware (we must clear "valid" bit from TLB so that
		 * speculative accesses won't trigger a page fault anymnore).
		 */
		DebugPF("will flush bad address TLB\n");
		__flush_tlb_page_and_pgtables(current->mm, address);
	}
#endif

	if (debug_semi_spec)
		pr_notice("PAGE FAULT. ignore invalid LOAD address 0x%lx in speculative mode: IP=%p %s(pid=%d)\n",
			address, (void *) GET_IP, current->comm, current->pid);

	return 1;
}

#if __LCC__ >= 120
static int fixup_exception(struct pt_regs *regs)
{
	const struct exception_table_entry *fixup;
	unsigned long ip, new_ip;
	tir_lo_struct_t tir_lo;

	tir_lo.TIR_lo_reg = regs->trap->TIR_lo;
	ip = tir_lo.TIR_lo_ip;

	fixup = search_exception_tables(ip);
	if (fixup) {
		new_ip = fixup->fixup;

		regs->crs.cr0_hi.fields.ip = new_ip >> 3;
		return 1;
	}

	return 0;
}
#endif /* __LCC__ >= 120 */

static int no_context(unsigned long address, struct pt_regs *regs,
		      union pf_mode mode)
{
#if __LCC__ >= 120
	if (fixup_exception(regs))
		return PFR_CONTROLLED_ACCESS;
#endif

	/* Are we prepared to handle this kernel fault? */
	if (current_thread_info()->usr_pfault_jump) {
		if (current_thread_info()->usr_pfault_jump != PG_JMP) {
			/* This is copy_to(from)_user. */
			AS(regs->crs.cr0_hi).ip =
				(current_thread_info()->usr_pfault_jump >> 3);
		}
		DebugPF("%d do_page_fault: fixup return IP:0x%lx->0x%lx address=0x%lx\n",
			current->pid, AS_STRUCT(regs->crs.cr0_hi).ip << 3,
			current_thread_info()->usr_pfault_jump, address);

		/* Controlled access from kernel to user space,
		 * just invalidate diagnostic tag in reg if load. */
		current_thread_info()->usr_pfault_jump = 0;

		return PFR_CONTROLLED_ACCESS;
	}

	/*
	 * Kernel should not use semi-speculative mode
	 * so we check only user accesses.
	 */
	if (mode.user && handle_spec_load_fault(address, regs, mode))
		return PFR_IGNORE;

	debug_print_page_fault(address, regs->trap);

	/*
	 *  Oops. The kernel tried to access some bad page.
	 */
	if (current->pid <= 1) {
		panic("do_page_fault: no_context on pid %d so will be recursive traps. IP = 0x%llx\n",
			current->pid,
			AS(regs->crs.cr0_hi).ip << 3);
	} else {
		panic("do_page_fault: no_context for address %lx from IP = %llx\n",
			address, AS(regs->crs.cr0_hi).ip << 3);
	}

	return 0;
}

static int vmalloc_fault(unsigned long address, struct pt_regs *regs,
			 tc_fault_type_t ftype, union pf_mode mode)
{
	pgd_t *pgd, *pgd_k;

	DebugPF("kernel address 0x%lx from VMALLOC area ( >= 0x%lx < 0x%lx)\n",
			address, VMALLOC_START, VMALLOC_END);

	WARN_ON_ONCE(in_nmi());

	/*
	 * Synchronize this task's top level page-table
	 * with the "reference" page table from init.
	 */
	pgd = pgd_offset(current->active_mm, address);
	pgd_k = pgd_offset_kernel(address);
	if (!pgd_present(*pgd) && pgd_present(*pgd_k)) {
		pgd_val(*pgd) = pgd_val(*pgd_k);
		return PFR_SUCCESS;
	}
	if (pgd_present(*pgd) && pgd_present(*pgd_k) && AW(ftype) == 0) {
		DbgTC("one more kernel VM load/store request on address 0x%lx\n",
				address);
		return PFR_SUCCESS;
	}

	pr_alert("do_page_fault: could not handle VMALLOC fault\n");
	print_address_ptes(pgd, address, 1);
	print_address_ptes(pgd_k, address, 1);
	print_kernel_address_all_nodes_ptes(address);

	return no_context(address, regs, mode);
}

static int pf_force_sig_info(int si_signo, int si_code, unsigned long address,
			     struct pt_regs *regs, union pf_mode mode)
{
	siginfo_t info;
	struct trap_pt_regs *trap = regs->trap;

	PFDBGPRINT("Signal %d for address 0x%lx", si_signo, address);

	if (debug_pagefault)
		debug_print_page_fault(address, trap);

	info.si_signo = si_signo;
	info.si_errno = SI_EXC;
	info.si_code = si_code;
	info.si_trapno = trap->nr_page_fault_exc;
	info.si_addr = (void __user *)address;

	/* binco must be able to determine x86 sigsegvs */
	if (mode.root && si_signo == SIGSEGV)
		info.si_errno |= SI_SEGV32;

	force_sig_info(si_signo, &info, current);

	return PFR_SIGPENDING;
}

__cold
static int bad_area(unsigned long address, struct pt_regs *regs,
		    union pf_mode mode, int si_code)
{
	up_read(&current->mm->mmap_sem);

	if (!mode.user && address >= TASK_SIZE)
		return no_context(address, regs, mode);

	if (handle_spec_load_fault(address, regs, mode))
		return PFR_IGNORE;

	if (!mode.user)
		return no_context(address, regs, mode);

	return pf_force_sig_info(SIGSEGV, si_code, address, regs, mode);
}

static inline bool load_has_store_semantics(int chan, unsigned int mas,
					    unsigned int mod, int root)
{
	return chan == 0 && (mod == _MAS_MODE_LOAD_OP_WAIT
			|| machine.iset_ver < E2K_ISET_V3 &&
					mod == _MAS_MODE_LOAD_OP_TRAP_ON_LD
			|| root && machine.iset_ver >= E2K_ISET_V3 &&
				((mas & MAS_TRAP_ON_LD_ST_MASK) ==
						MAS_LOAD_SEC_TRAP_ON_LD_ST
				|| mas == MAS_SEC_SLT));
}

static int access_error(struct vm_area_struct *vma, unsigned long address,
			struct pt_regs *regs, union pf_mode mode,
			int instr_page)
{
	if (mode.write) {
		/* Check write permissions */
		if (unlikely(!(vma->vm_flags & VM_WRITE))) {
			PFDBGPRINT("Page is not writable");
			return 1;
		}
	} else if (unlikely(!(vma->vm_flags & (VM_READ | VM_EXEC |
					       VM_WRITE)))) {
		/* Check read permissions */
		PFDBGPRINT("Page is PROT_NONE");
		return 1;
	}

	/* Check exec permissions */
	if (instr_page) {
		if (unlikely(!(vma->vm_flags & VM_EXEC))) {
			PFDBGPRINT("Page is not executable");
			return 1;
		}

#ifdef CUNIT_DEBUG
		if (unlikely(_PAGE_INDEX_FROM_CUNIT(pgprot_val(
				vma->vm_page_prot)) < USER_CODES_START_INDEX)) {
			panic("do_page_fault(): invalid protection 0x%lx CUIR value %ld < start index %d\n",
				pgprot_val(vma->vm_page_prot),
				_PAGE_INDEX_FROM_CUNIT(pgprot_val(
							vma->vm_page_prot)),
				USER_CODES_START_INDEX);
		}
#endif
	}

	/* Check privilege level */
	if (unlikely(vma->vm_flags & VM_PRIVILEGED)) {
		if (!test_ts_flag(TS_KERNEL_SYSCALL)) {
			PFDBGPRINT("Page is privileged");
			return 1;
		}
	}

	return 0;
}

__cold
static int mm_fault_error(unsigned long address, struct pt_regs *regs,
		union pf_mode mode, unsigned int fault)
{
	/*
	 * Pagefault was interrupted by SIGKILL. We have no reason to
	 * continue pagefault.
	 */
	if (fatal_signal_pending(current)) {
		if (!(fault & VM_FAULT_RETRY))
			up_read(&current->mm->mmap_sem);

		return PFR_SIGPENDING;
	}

	if (!(fault & VM_FAULT_ERROR))
		return 0;

	if (fault & VM_FAULT_OOM)
		return pf_out_of_memory(address, regs);

	up_read(&current->mm->mmap_sem);

	if (fault & (VM_FAULT_SIGBUS|VM_FAULT_SIGSEGV)) {
		int signal, si_code;

		/* We cannot guarantee that another thread did not
		 * truncate the file we were reading from, thus we
		 * cannot rely on valid bit being cleared and must
		 * manually check for half-speculative mode. */
		if (handle_spec_load_fault(address, regs, mode))
			return PFR_IGNORE;

		if (fault & VM_FAULT_SIGBUS) {
			signal = SIGBUS;
			si_code = BUS_ADRERR;
		} else {
			signal = SIGSEGV;
			si_code = SEGV_MAPERR;
		}

		return pf_force_sig_info(signal, si_code, address, regs, mode);
	}

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (fault & VM_FAULT_SS) {
		DebugPF("ss fault\n");
		pr_info_ratelimited("SS VM: killing process %s(%d)\n",
				current->comm, current->pid);
		force_sig(SIGKILL, current);

		return PFR_SIGPENDING;
	}
#endif

	BUG();
}

static inline int pf_on_page_boundary(unsigned long address, tc_opcode_t opcode)
{
	unsigned long end_address;
	int format;

	/*
	 * Always manually check for page boundary crossing.
	 * ftype.page_bound field is not reliable enough:
	 *
	 * 1) "ftype" field is present only in the first tcellar entry.
	 * 2) "page_bound" is shadowed by "page_miss", "nwrite_page", etc.
	 * 3) It was removed in iset V3.
	 */

	format = 1 << (AS(opcode).fmt - 1);
	if (format > sizeof(u64))
		format = sizeof(u64);

	DebugNAO("not aligned operation with address 0x%lx fmt %d format %d bytes\n",
			address, AS(opcode).fmt, format);

	end_address = address + format - 1;

	return unlikely(end_address >> PAGE_SHIFT != address >> PAGE_SHIFT);
}

static int handle_kernel_address(unsigned long address, struct pt_regs *regs,
		union pf_mode mode, tc_fault_type_t ftype)
{
	if (mode.user) {
		if (handle_spec_load_fault(address, regs, mode))
			return PFR_IGNORE;

		PFDBGPRINT("On kernel address 0x%lx in user mode", address);
		return pf_force_sig_info(SIGBUS, BUS_ADRERR,
					 address, regs, mode);
	}

	if (address >= VMALLOC_START && address < VMALLOC_END)
		return vmalloc_fault(address, regs, ftype, mode);

	/*
	 * Handle 'page bound' on kernel address: if access
	 * address intersects page boundary then hardware
	 * causes 'page fault' trap (this was removed in iset V3).
	 */
	if (AS(ftype).page_bound) {
		DebugPF("kernel page bound: addr 0x%lx\n",
				address);
		return PFR_SUCCESS;
	}

	/*
	 * Check that it was the kernel address that caused the page fault
	 */
	if (regs->trap->tc_count <= 3 || AW(ftype)) {
		if (current->mm) {
			/* User thread. SIGBUS */
			PFDBGPRINT("On kernel address 0x%lx in kernel mode",
					address);
			return pf_force_sig_info(SIGBUS, BUS_ADRERR,
						 address, regs, mode);
		} else {
			/* Kernel thread */
			return no_context(address, regs, mode);
		}
	}
	DebugPF("kernel address 0x%lx due to user address page fault\n",
			address);

	return PFR_KERNEL_ADDRESS;
}

int do_page_fault(struct pt_regs *const regs, e2k_addr_t address,
		tc_cond_t *const condition, const int instr_page)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	tc_fault_type_t ftype;
	tc_opcode_t opcode;
	union pf_mode mode;
	const unsigned int mas = ASP(condition).mas;
	const unsigned int mod = (mas & MAS_MOD_MASK) >> MAS_MOD_SHIFT;
	const int chan = ASP(condition).chan;
	int ret, addr_num;
	int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

	AW(ftype) = ASP(condition).fault_type;
	AW(opcode) = ASP(condition).opcode;

	mode.word = 0;
	mode.write = ASP(condition).store && (mas != MAS_DCACHE_LINE_FLUSH);
	mode.spec = ASP(condition).spec;
	mode.user = user_mode(regs);
	mode.root = ASP(condition).root;
	mode.num_align = ASP(condition).num_align;

	/*
	 * ftype could be a combination of several fault types. One should
	 * reset all fault types, except illegal_page, if illegal_page
	 * happened. See bug #67315 for detailes.
	 */
	if (AS(ftype).illegal_page) {
		AW(ftype) = 0;
		AS(ftype).illegal_page = 1;
	}

	if (TASK_IS_BINCO(current) && !IS_UPT_E3S && mode.root &&
			ADDR_IN_SS(address + SS_ADDR_START))
		address += SS_ADDR_START;

        CLEAR_DAM;

	DebugPF("started for address 0x%lx, instruction page:"
		"%d fault type:0x%x condition 0x%lx root:%d missl:%d cpu%d"
		" user_mode_fault=%d\n", address, instr_page, AW(ftype),
		AWP(condition), mode.root, ASP(condition).miss_lvl,
		current_thread_info()->cpu, mode.user);

	/*
	 * Some loads have store semantics and cause write protection faults
	 * (see bugs 39795).
	 */
	if (!mode.spec && !mode.write &&
			load_has_store_semantics(chan, mas, mod, mode.root))
		mode.write = 1;

	if (mode.write)
		flags |= FAULT_FLAG_WRITE;

#ifdef CONFIG_MCST_RT
	if ((rts_act_mask & RTS_PGFLT_RTWRN && rt_task(current)) ||
			rts_act_mask & RTS_PGFLT_WRN)
		pr_info("page fault while RTS mode %lx in %d/%s addr=%08lx\n",
			rts_act_mask, current->pid, current->comm, address);
#endif

	if (address >= TASK_SIZE)
		return handle_kernel_address(address, regs, mode, ftype);

	if (!mm || in_atomic() || cur_pf_disabled())
		return no_context(address, regs, mode);

	if (pf_on_page_boundary(address, opcode))
		addr_num = 2;
	else
		addr_num = 1;

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);

retry:
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, address);

	DebugPF("find_vma() returned 0x%p\n", vma);

	if (!vma) {
#ifdef CONFIG_SOFTWARE_SWAP_TAGS
		if (is_tags_area_addr(address)) {
			DebugPF("fault address 0x%lx is from "
				"tags virtual space\n", address);
			vma = create_tags_vma(mm, tag_to_virt(address));
			if (!vma)
				return pf_out_of_memory(address, regs);
		} else 
#endif
		{
			if (!mode.spec)
				PFDBGPRINT("PAGE FAULT. Trap with not speculative load and invalid address");
			return bad_area(address, regs, mode, SEGV_MAPERR);
		}
	}

	if (address < vma->vm_start) {
#ifdef CONFIG_SOFTWARE_SWAP_TAGS
		if (is_tags_area_addr(address)) {
			DebugPF("fault address 0x%lx is from tags virtual space\n",
					address);
			vma = create_tags_vma(mm, tag_to_virt(address));
			if (vma == NULL)
				return pf_out_of_memory(address, regs);
			goto good_area;
		}
#endif

		return bad_area(address, regs, mode, SEGV_MAPERR);
	}

	/*
	 * pgd now should be populated while fault handling.
	 *
	 * This can happen on NUMA when user PGD entries are copied
	 * to per-cpu PGD table. So PGD user entries are updated
	 * only in process's 'mm' and on the CPU on which the
	 * thread which is manipulating page tables executes.
	 *
	 * But if there is another thread active when page table is
	 * updated then it still uses the old copy of PGD. So we have
	 * to update PGD and proceed with the normal handling (in the
	 * case not only PGD is missing but the page in RAM too).
	 */
	if (pgd_populate_cpu_root_pt(mm, pgd_offset(mm, address))) {
		/*
		 * PGD only is populated at CPU root page table
		 * from main user page table mm->pgd
		 */
		DebugPGD("pgd 0x%p = 0x%lx populated on CPU #%d\n",
				pgd_offset(mm, address),
				pgd_val(*pgd_offset(mm, address)),
				smp_processor_id());
	}

#ifdef CONFIG_MAKE_ALL_PAGES_VALID
	/*
	 * Following check only to debug the mode when all pages
	 * should be valid 'CONFIG_MAKE_ALL_PAGES_VALID'
	 */
	if (AW(ftype)) {
		int page_none = (vma->vm_flags &
				 (VM_READ | VM_WRITE | VM_EXEC)) == 0;

		if (instr_page && AS(ftype).illegal_page) {
			PFDBGPRINT("Instruction page protection for valid address");
			return bad_area(address, regs, mode, SEGV_MAPERR);
		}

		if (AS(ftype).illegal_page && !page_none &&
				/* problem with DTLB (see comment below) */
				!(TASK_IS_BINCO(current) && mode.root &&
				  ADDR_IN_SS(address) && !IS_UPT_E3S)) {
			PFDBGPRINT("illegal_page for valid page");
			return bad_area(address, regs, mode, SEGV_MAPERR);
		}

		if (!(AS(ftype).page_miss || AS(ftype).priv_page ||
				AS(ftype).global_sp || AS(ftype).nwrite_page ||
				AS(ftype).page_bound ||
				(AS(ftype).illegal_page && page_none) ||
				/* We should handle previous semi-speculative
				 * load in secondary space. As result of such
				 * load we have DTLB line with VVA == 0.
				 * Now we got illegal_page exception which
				 * is legal page_miss. */
				(TASK_IS_BINCO(current) && mode.root &&
				 ADDR_IN_SS(address) && !IS_UPT_E3S &&
				 AS(ftype).illegal_page))) {
			PFDBGPRINT("trap with bad fault type for valid address ft:0x%x, wr:%d",
					AW(ftype), AS(ftype).nwrite_page);
			return bad_area(address, regs, mode, SEGV_ACCERR);
		}
	}
#endif	/* CONFIG_MAKE_ALL_PAGES_VALID */

	/*
	 * Do not handle faults to user data stack's guard page
	 * (see comment before expand_user_data_stack()).
	 */
	if ((vma->vm_flags & VM_GROWSDOWN) &&
			address < vma->vm_start + PAGE_SIZE) {
		struct vm_area_struct *prev = vma->vm_prev;

		/*
		 * Check vma abutting this one below
		 */
		if (!prev || prev->vm_end != vma->vm_start ||
				!(prev->vm_flags & VM_GROWSDOWN))
			return bad_area(address, regs, mode, SEGV_ACCERR);
	}

	/*
	 * Ok, we have a good vm_area for this memory access, so
	 * we can handle it..
	 */
#ifdef CONFIG_SOFTWARE_SWAP_TAGS
good_area:
#endif
	DebugPF("have good vm_area\n");

	/* We use bitwise OR for performance */
	if (unlikely(AS(ftype).exc_mem_lock | AS(ftype).ph_pr_page |
		     AS(ftype).io_page | AS(ftype).prot_page |
		     AS(ftype).intl_res_bits | AS(ftype).isys_page |
		     AS(ftype).ph_bound)) {
		PFDBGPRINT("Bad fault type 0x%x", AW(ftype));
		goto force_sigbus;
	}

	if (AS(ftype).nwrite_page)
		DebugPF("write protection occured.\n");

	if (instr_page)
		DebugPF("instruction page fault occured.\n");

#ifdef CONFIG_PROTECTED_MODE
	/*
	 * Interpret the stack address in multithreaded protected mode
	 */
	if ((flags & FAULT_FLAG_ALLOW_RETRY) &&
			(current->thread.flags & E2K_FLAG_PROTECTED_MODE) &&
			instr_page == 0 && WAS_MULTITHREADING) {
		DebugPF("WAS_MULTITHREADING=%d address=%lx ip=%lx\n",
				WAS_MULTITHREADING, address, GET_IP);

		ret = interpreted_ap_code(regs, &vma, &address);
		if (!ret)
			return bad_area(address, regs, mode, SEGV_ACCERR);

		if (ret == 1 || ret == 2) {
	                up_read(&mm->mmap_sem);

			return (ret == 2) ? PFR_AP_THREAD_READ : PFR_SUCCESS;
		}
	}
#endif

#pragma loop count (2)
	do {
		int fault;

		if (access_error(vma, address, regs, mode, instr_page))
			return bad_area(address, regs, mode, SEGV_ACCERR);

		DebugPF("will start handle_mm_fault()\n");
		fault = handle_mm_fault(mm, vma, address, flags);
		DebugPF("handle_mm_fault() returned %x\n",
				fault);

		if (unlikely(fault & (VM_FAULT_RETRY|VM_FAULT_ERROR))) {
			ret = mm_fault_error(address, regs, mode, fault);
			if (ret)
				return ret;
		}

		if (fault & VM_FAULT_MAJOR) {
			current->maj_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ,
				      1, regs, address);
		} else {
			/* VM_FAULT_MINOR */
			current->min_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN,
				      1, regs, address);
		}

		if (fault & VM_FAULT_RETRY) {
			flags &= ~FAULT_FLAG_ALLOW_RETRY;
			goto retry;
		}

		--addr_num;
		if (unlikely(addr_num > 0)) {
			address = PAGE_ALIGN(address);

			DebugNAO("not aligned operation will start handle_mm_fault() for next page 0x%lx\n",
					address);

			if (vma->vm_end <= address) {
				vma = vma->vm_next;
				if (!vma || vma->vm_start > address) {
					DebugNAO("end address is not valid (has not VMA)\n");
					PFDBGPRINT("End address is not valid (has not VMA)");
					return bad_area(address, regs, mode,
							SEGV_MAPERR);
				}
			}
		}
	} while (unlikely(addr_num > 0));

	/*
	 * For performance reasons update_mmu_cache flushes only the last
	 * level of page tables. This way we won't needleesly flush pmd,
	 * pud and pgd on every page fault (but at a cost of 1 additional
	 * fault to flush them).
	 *
	 * Note that miss_lvl is set _only_ in the page miss case, and
	 * nwrite_page is set _only_ for the last level of page tables
	 * (3rd or 2nd for large pages).
	 *
	 * For other cases this optimization does not work - we still
	 * will flush all 4 levels of page table.
	 */
	if (ASP(condition).miss_lvl != 3 && !AS(ftype).nwrite_page)
		__flush_tlb_pgtables(vma->vm_mm, address,
				     address + E2K_MAX_FORMAT);

	up_read(&mm->mmap_sem);
	DebugPF("handle_mm_fault() finished\n");

	return PFR_SUCCESS;

force_sigbus:
	up_read(&mm->mmap_sem);

	return pf_force_sig_info(SIGBUS, BUS_ADRERR, address, regs, mode);
}

/*
 * We should recover LOAD operation with MAS == FILL_OPERATION
 * to load the value with tags. In protected mode any value has tag,
 * in unprotected mode
 */
static unsigned int inline
get_recovery_mas(tc_cond_t condition)
{
	unsigned int mas = AS(condition).mas;
	unsigned int mod = (mas & MAS_MOD_MASK) >> MAS_MOD_SHIFT;
	int spec_mode = AS(condition).spec;
	int chan = AS(condition).chan;
	tc_opcode_t opcode;
	int root = AS(condition).root; /* secondary space */
	int store = AS(condition).store;

	AW(opcode) = AS(condition).opcode;

	/*
	 * If LOAD with 'lock wait' MAS type then we should not use MAS
	 * to recover LOAD as regular operation. The real LOAD with real
	 * MAS will be repeated later after return from trap as result
	 * of pair STORE operation with 'wait unlock' MAS
	 */
	if (!spec_mode) {
		if (chan == 0 && (machine.iset_ver < E2K_ISET_V3 || root == 0)
				&& mod == _MAS_MODE_LOAD_OP_WAIT)
			return _MAS_MODE_LOAD_OPERATION;

		if (machine.iset_ver >= E2K_ISET_V3 && root && chan <= 1 &&
				!store && mas == MAS_SEC_SLT)
			return _MAS_MODE_LOAD_OPERATION;
	}


	if ((AS(opcode).fmt == LDST_QWORD_FMT) &&
		((mod == _MAS_MODE_LOAD_OP_UNLOCK) ||
		 (mod == _MAS_MODE_LOAD_OP_CHECK))) {
		return _MAS_MODE_LOAD_OPERATION;
	}

	if (AS(opcode).npsp ||
	    !(current->thread.flags & E2K_FLAG_PROTECTED_MODE)
	   ) {
		return mas;
	}

	/*
	 * If LOAD is protected then we should execute LDRD
	 * to get the value with tags. It is possible only using
	 * the special MAS in nonprotected mode
	 */
	if (mod == 0) {
		return MAS_FILL_OPERATION;
	}
	if (((chan == 0 || chan == 2) &&
		((mod == _MAS_MODE_LOAD_OP_CHECK && !spec_mode)		||
		(mod == _MAS_MODE_LOAD_OP_UNLOCK && !spec_mode)		||
		(mod == _MAS_MODE_LOAD_OP_LOCK_CHECK && spec_mode)	||
		(mod == _MAS_MODE_FILL_OP && !spec_mode)		||
		(mod == _MAS_MODE_LOAD_OP_SPEC_LOCK_CHECK && spec_mode)	||
		(mod == _MAS_MODE_LOAD_OP_SPEC && spec_mode)))		||

		((chan == 1 || chan == 3) &&
		((mod == MAS_MODE_LOAD_OP_CHECK && !spec_mode)		||
		(mod == MAS_MODE_LOAD_OP_UNLOCK && !spec_mode)		||
		(mod == MAS_MODE_LOAD_OP_LOCK_CHECK && spec_mode)	||
		(mod == MAS_MODE_FILL_OP && !spec_mode)			||
		(mod == MAS_MODE_LOAD_OP_SPEC_LOCK_CHECK && spec_mode)	||
		(mod == MAS_MODE_LOAD_OP_SPEC && spec_mode)))) {
		return MAS_FILL_OPERATION;
	} else {
		printk("get_recovery_mas(): we do not know how to recover "
			"protected access with MAS 0x%x\n", mas);
		BUG();
	}

	return mas;
}


static int do_recovery_store(struct pt_regs *regs,
		const trap_cellar_t *tcellar, tc_opcode_t opcode,
		e2k_addr_t address, int size, int chan, int fmt, int rg)
{
	int		offset = address & 0x7;
	ldst_rec_op_t	st_rec_opc, ld_rec_opc;
	u64		data, wr_data, mas, root, flags;
	u32		data_tag;
	u8		*addr;
	int		byte, not_aligned, page_bound, big_endian;
#ifdef	CONFIG_ACCESS_CONTROL
	e2k_upsr_t	upsr_to_save;
#endif	/* CONFIG_ACCESS_CONTROL */

	mas = AS(tcellar->condition).mas;
	root = AS(tcellar->condition).root;

	if (DEBUG_EXEC_MMU_OP) {
		unsigned long	val;
		unsigned int	tag;

		E2K_LOAD_VAL_AND_TAGD(&tcellar->data, val, tag);
		pr_info("do_recovery_store: STRD store from trap "
			"cellar the data 0x%016lx tag 0x%x address "
			"0x%lx offset %d\n",
			val, tag, address, offset);
	}

	/*
	 * #74018 Do not execute store operation if rp_ret != 0
	 */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (unlikely(regs->rp_ret)) {
		DbgEXMMU("do_recovery_store: rp_ret != 0\n");
		return EXEC_MMU_SUCCESS;
	}
#endif

	big_endian = (mas & MAS_ENDIAN_MASK) &&
		     ((mas & MAS_MOD_MASK) != MAS_MODE_STORE_MMU_AAU_SPEC) &&
		     !root;
	page_bound = ((address + size) > PAGE_ALIGN_UP(address + PAGE_SIZE));

	ACCESS_CONTROL_DISABLE_AND_SAVE(upsr_to_save);

	/*
	 * Load data to store from trap cellar
	 */

	AW(ld_rec_opc) = 0;
	AS(ld_rec_opc).prot = 1;
	AS(ld_rec_opc).mas = MAS_BYPASS_ALL_CACHES | MAS_FILL_OPERATION;
	if (big_endian) {
		AS(ld_rec_opc).fmt = fmt;
		AS(ld_rec_opc).index = offset;
	} else {
		AS(ld_rec_opc).fmt = LDST_QWORD_FMT;
		AS(ld_rec_opc).index = 0;
	}

	E2K_LOAD_VAL_AND_TAGD_OPC(&tcellar->data, AW(ld_rec_opc),
				  data, data_tag);

	if (big_endian) {
		wr_data = data;
	} else {
		wr_data = (data >> (offset * 8)) |
			  (data << ((8 - offset) * 8));

		switch (fmt) {
		case 1:
		case 2:
			data_tag = 0;
			break;
		case 3:
			if (offset == 0)
				data_tag = (data_tag & 0x3);
			else if (offset == 4)
				data_tag = (data_tag >> 2);
			break;
		}
	}

	not_aligned = offset & (size - 1);
	if (DEBUG_EXEC_MMU_OP || (DEBUG_NAO_MODE && not_aligned))
		pr_info("do_recovery_store: store(%d) chan = %d address = 0x%lx, data = 0x%llx tag = 0x%x tc_data = 0x%016llx\n",
			size, chan, address, wr_data, data_tag, data);

	/*
	 * Actually re-execute the store operation
	 */

	AW(st_rec_opc) = 0;
	/* Store as little endian. Do not clear the endianness bit
	 * unconditionally as it might mean something completely
	 * different depending on other bits in the trap cellar.*/
	AS(st_rec_opc).mas = (big_endian) ? (mas & ~MAS_ENDIAN_MASK) : mas;
	AS(st_rec_opc).prot = !(AS(opcode).npsp);
	AS(st_rec_opc).fmt = fmt;
	AS(st_rec_opc).root = AS(tcellar->condition).root;
	AS(st_rec_opc).rg = rg;

	if (!page_bound) {
		if (chan == 1) {
			E2K_STORE_TAGGED_WORD(address, wr_data,
					      data_tag, AW(st_rec_opc), 2);
		} else if (chan == 3) {
			E2K_STORE_TAGGED_WORD(address, wr_data,
					      data_tag, AW(st_rec_opc), 5);
		}

		goto out;
	}

	DbgEXMMU("do_recovery_store: operation intersects page bound: address 0x%lx fmt %d size %d bytes\n",
			address, fmt, size);

	AS(st_rec_opc).fmt = 1;

	addr = (u8 *) address;
	for (byte = 0; byte < size; byte++) {
		if (chan == 1) {
			E2K_RECOVERY_STORE(addr, wr_data,
					AW(st_rec_opc), 2);
		} else if (chan == 3) {
			E2K_RECOVERY_STORE(addr, wr_data,
					AW(st_rec_opc), 5);
		}

		wr_data >>= 8;
		++addr;
	}

	if (DEBUG_NAO_MODE) {
		AS(st_rec_opc).mas = 0;
		AS(st_rec_opc).fmt = fmt;
		E2K_LOAD_VAL_AND_TAGD_WITH_OPC(address,
				AW(st_rec_opc), wr_data, 0, data_tag);
	}

out:
	ACCESS_CONTROL_RESTORE(upsr_to_save);

	flags = ACCESS_ONCE(current->thread.flags);

	/* Nested exception appeared while do_recovery_store() */
	if (flags & E_MMU_NESTED_OP) {
		current->thread.flags &= ~E_MMU_NESTED_OP;

		if (fatal_signal_pending(current))
			return EXEC_MMU_STOP;
		else
			return EXEC_MMU_REPEAT;
	}

	return EXEC_MMU_SUCCESS;
}

/**
 * calculate_recovery_load_parameters - calculate the stack address
 *	of the register where the load was done.
 * @dst: trap cellar's "dst" field
 * @greg_num_d: global register number
 * @greg_recovery: was it a load to a global register?
 * @rotatable_greg: was it a rotatable global register?
 * @src_bgr: saved BGR if it was a rotatable global register
 * @radr: address of a "normal" register
 *
 * This function calculates and sets @greg_num_d, @greg_recovery,
 * @rotatable_greg, @src_bgr, @radr.
 *
 * Returns zero on success and value of type exec_mmu_ret on failure.
 */
static int calculate_recovery_load_parameters(struct pt_regs *regs,
		tc_dst_t dst, unsigned dst_addr,
		unsigned *greg_num_d, unsigned *greg_recovery,
		unsigned *rotatable_greg, e2k_bgr_t *src_bgr, u64 **radr)
{
	unsigned	w_base_rnum_d;
	u8		*ps_base = NULL;
	unsigned	rnum_offset_d;
	unsigned	vr = AS(dst).vr;
	unsigned	vl = AS(dst).vl;

	DbgTC("load request vr=%d\n", vr);

	*greg_num_d = -1;
	*greg_recovery = 0;
	*rotatable_greg = 0;

	/*
	 * Calculate register's address
	 */
	if (!vr && !vl) {
		/*
		 * Destination register to load is NULL
		 * We should load the value from address into "air"
		 */
		*radr = NULL;
		DbgEXMMU(""
			"<dst> is NULL register\n");
	} else if (!vl) {
		panic("Invalid destination: 0x%x : vl is 0 %s(%d)\n",
			      (u32)AW(dst), __FILE__, __LINE__);
	} else if (dst_addr >= E2K_MAXNR_d - E2K_MAXGR_d &&
		   dst_addr < E2K_MAXNR_d) {
		/*
		 * Destination register to load is global register
		 * We should only set the global register <dst_addr>
		 * to value from <address>
		 *
		 * WARNING: if kernel will use global registers then
		 * we should save all global registers in pt_regs
		 * structure, write value from <address> to the
		 * appropriate item in the pt_regs.gregs[greg_num_d]
		 */
		*greg_recovery = 1;
		*radr = (u64 *)(-1);
		*greg_num_d = dst_addr - (E2K_MAXNR_d - E2K_MAXGR_d);

		if (*greg_num_d >= E2K_GB_START_REG_NO_d &&
				*greg_num_d < E2K_GB_START_REG_NO_d +
					      E2K_GB_REGS_NUM_d) {
			/*
			 * The global register to recovery is from
			 * rotatable area. We should save current state
			 * of BGR register and set the register to
			 * initial state (as no any rotation), because
			 * <dst_addr> is absolute # in register file
			 * and we can recovery only by absolute # of
			 * global register.
			 */
			*rotatable_greg = 1;
			*src_bgr = read_BGR_reg();
			init_BGR_reg();
			DbgEXMMU("<dst> is global rotatable register: rnum_d = 0x%x (dg%d) BGR 0x%x\n",
				dst_addr, *greg_num_d, AWP(src_bgr));
		} else {
			DbgEXMMU("<dst> is global register: rnum_d = 0x%x (dg%d)\n",
				dst_addr, *greg_num_d);
		}
	} else if (dst_addr < E2K_MAXSR_d) {
#define CHECK_PSHTP
#ifdef CHECK_PSHTP
		register long lo_1, lo_2, hi_1, hi_2;
		register long pshtp_tind_d = AS_STRUCT(regs->pshtp).tind / 8;
		register long wd_base_d = AS_STRUCT(regs->wd).base / 8;

		if (!AS_STRUCT(regs->pshtp).tind)
			return EXEC_MMU_SUCCESS;
#endif

		/*
		 * We can be sure that we search in right window, and we
		 * can be not afraid of nested calls, because we take as
		 * base registers that was save when we entered in trap
		 * handler, this registers pointed to last window before
		 * interrupt.
		 * When we came to interrup we have new window which is
		 * defined by WD (current window register) in double
		 * terms which was saved in regs->wd and we use it:
		 *	w_base_rnum_d = regs->wd;
		 * Window regs file (RF) is loop buffer.
		 * Size == E2K_MAXSR_d. So w_base_rnum_d can be
		 * > or < then num of dist reg (dst_addr):
		 *
		 *	w_base_rnum_d > dst_addr:
		 *
		 * RF 0<----| PREV-WD | TRAP WD |----------->E2K_MAXSR_d
		 *              ^dst_addr
		 *                    ^w_base_rnum_d
		 *
		 *	w_base_rnum_d < dst_addr:
		 *
		 * RF 0<Continue PREV WD | THAP WD |--- |PREV WD>E2K_MAXSR_d
		 *              ^dst_addr
		 *                       ^w_base_rnum_d
		 *
		 * We done E2K_FLUSHCPU and PREV WD is now in psp stack:
		 * --|-----------| PREV WD |--------------
		 *   ^psp.base             ^psp.ind
		 *
		 * First address of first empty byte of psp stack is
		 *      ps_base = base + ind;
		 */

		ps_base = (u8 *)(AS(regs->stacks.psp_hi).ind +
				AS(regs->stacks.psp_lo).base);

		/*
		 *  w_base_rnum_d is address of double reg
		 *  NR_REA_d(regs->wd, 0) is eguivalent to:
		 *  w_base_rnum_d = AS_STRUCT(regs->wd).base / 8;
		 */
		w_base_rnum_d = NR_REA_d(regs->wd, 0);

		/*
		 * Offset from beginning spilled quad-NR for our
		 * dst_addr is
		 *	rnum_offset_d.
		 * We define rnum_offset_d for dst_addr from ps_base
		 * in terms of double.
		 * Note. dst_addr is double too.
		 */
#ifdef CHECK_PSHTP
		if (wd_base_d >= pshtp_tind_d) {
			lo_2 =  wd_base_d - pshtp_tind_d;
			hi_2 = wd_base_d - 1;
			lo_1 = lo_2;
			hi_1 = hi_2;
		} else {
			lo_1 = 0;
			hi_1 = wd_base_d - 1;
			lo_2 = wd_base_d + E2K_MAXSR_d - pshtp_tind_d;
			hi_2 = E2K_MAXSR_d - 1;
		}

		if (dst_addr >= lo_1 && dst_addr <= hi_1) {
			rnum_offset_d = w_base_rnum_d - dst_addr;
		} else if (dst_addr >= lo_2 && dst_addr <= hi_2) {
			rnum_offset_d = w_base_rnum_d + E2K_MAXSR_d - dst_addr;
		} else {
			return EXEC_MMU_SUCCESS;
		}
#else
		if (w_base_rnum_d > dst_addr) {
			rnum_offset_d = w_base_rnum_d - dst_addr;
		} else {
			rnum_offset_d = w_base_rnum_d + E2K_MAXSR_d - dst_addr;
		}
#endif
		/*
		 * Window boundaries are aligned at least to quad-NR.
		 * When windows spill then quad-NR is spilled as minimum.
		 * Also, extantion of regs is spilled too.
		 * So, each spilled quad-NR take 2*quad-NR size == 32 bytes
		 * So, bytes offset for our rnum_offset_d is
		 *	(rnum_offset_d + 1) / 2) * 32
		 * if it was uneven number we should add size of double:
		 *	(rnum_offset_d % 2) * 8
		 * starting from ISET V5 we should add size of quadro.
		 */
		*radr = (u64 *) (ps_base - ((rnum_offset_d + 1) / 2) * 32);
		if (rnum_offset_d % 2)
			*radr += ((machine.iset_ver < E2K_ISET_V5) ? 1 : 2);
		DbgEXMMU("<dst> is window "
			"register: rnum_d = 0x%x offset 0x%x, "
			"PS base 0x%p WD base = 0x%x, radr = 0x%p\n",
			dst_addr, rnum_offset_d, ps_base, w_base_rnum_d, *radr);

		if (((unsigned long) *radr < AS(regs->stacks.psp_lo).base) ||
				((unsigned long) *radr >= (u64)ps_base)) {
			/*
			 * The load operation out of current
			 * register window frame (for example this
			 * load is placed in one long instruction with
			 * return. The load operationb should be ignored
			 */
			DbgEXMMU(""
				"<dst> address of register window points "
				"out of current procedure stack frame "
				"0x%p >= 0x%p, load operation will be "
				"ignored\n",
				radr, ps_base);
			return EXEC_MMU_SUCCESS;
		}
	} else {
		panic("Invalid destination register %d in the trap "
				"cellar %s(%d)\n",
				dst_addr, __FILE__, __LINE__);
	}

	return 0;
}

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
static int is_MLT_mas(ldst_rec_op_t opcode)
{
	if (!AS(opcode).root)
		return 0;

	if (machine.iset_ver >= ELBRUS_2S_ISET) {
		unsigned int mas = AS(opcode).mas;

		if (mas == MAS_LOAD_SEC_TRAP_ON_STORE ||
				mas == MAS_LOAD_SEC_TRAP_ON_LD_ST)
			return 1;
	} else {
		unsigned int mod = (AS(opcode).mas & MAS_MOD_MASK) >>
								MAS_MOD_SHIFT;

		if (mod == _MAS_MODE_LOAD_OP_TRAP_ON_STORE ||
				mod == _MAS_MODE_LOAD_OP_TRAP_ON_LD)
			return 1;
	}

	return 0;
}
#endif

static int do_recovery_load(struct pt_regs *regs, trap_cellar_t *tcellar,
		tc_opcode_t opcode, tc_dst_t dst, int zeroing,
		e2k_addr_t address, int size, u64 *radr, int chan, int fmt,
		unsigned greg_recovery, unsigned greg_num_d, int rg,
		e2k_addr_t *adr)
{
	volatile u64 empty; /* volatile cause it can have tag */
	ldst_rec_op_t	ld_rec_opc;
	unsigned	vr = AS(dst).vr;
#ifdef	CONFIG_ACCESS_CONTROL
	e2k_upsr_t	upsr_to_save;
#endif	/* CONFIG_ACCESS_CONTROL */
	u64		flags;
	bool empt = AS(tcellar->condition).empt;

	if (DEBUG_EXEC_MMU_OP && radr) {
		register unsigned long	val;
		register unsigned int	tag;

		if (greg_recovery) {
			E2K_GET_DGREG_VAL_AND_TAG(greg_num_d, val, tag);
		} else {
			E2K_LOAD_VAL_AND_TAGD(radr, val, tag);
		}

		DbgEXMMU("load from register "
			"file background register value 0x%lx tag 0x%x\n",
			val, tag);
	}

	/*
	 * #74018 Do not execute load operation if rp_ret != 0
	 */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (unlikely(regs->rp_ret)) {
		DbgEXMMU("do_recovery_load: rp_ret != 0\n");
		return EXEC_MMU_SUCCESS;
	}
#endif

	if (unlikely(empt)) {
		DbgEXMMU("\"empt\" record, will not load from user\n");
		E2K_STORE_VALUE_WITH_TAG(&empty, 0ULL, ETAGEWD);
		address = (e2k_addr_t) &empty;
	}

	AW(ld_rec_opc) = 0;
	AS(ld_rec_opc).mas = get_recovery_mas(tcellar->condition);
	AS(ld_rec_opc).prot = !(AS(opcode).npsp);
	AS(ld_rec_opc).fmt = fmt;
	AS(ld_rec_opc).root = AS(tcellar->condition).root;
	AS(ld_rec_opc).rg = rg;

	ACCESS_CONTROL_DISABLE_AND_SAVE(upsr_to_save);

	if (zeroing) {
		if (!greg_recovery && radr)
			E2K_STORE_TAGGED_DWORD(radr, 0);

		return EXEC_MMU_SUCCESS;
	}

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (is_MLT_mas(ld_rec_opc)) {
		struct thread_info *ti = current_thread_info();
		u64 cr0_hi = AS_WORD(regs->crs.cr0_hi);

		WARN_ON(cr0_hi < ti->rp_start || cr0_hi >= ti->rp_end);
		regs->rp_ret = 1;
	}
#endif

#ifdef CONFIG_PROTECTED_MODE
	if (adr)
		*adr = (e2k_addr_t) radr;
#endif

	if (radr == NULL) {
		u64 ld_val;

		if (chan == 0) {
			E2K_RECOVERY_LOAD_TO(address,
					AW(ld_rec_opc), ld_val, 0);
		} else if (chan == 1) {
			E2K_RECOVERY_LOAD_TO(address,
					AW(ld_rec_opc), ld_val, 2);
		} else if (chan == 2) {
			E2K_RECOVERY_LOAD_TO(address,
					AW(ld_rec_opc), ld_val, 3);
		} else if (chan == 3) {
			E2K_RECOVERY_LOAD_TO(address,
					AW(ld_rec_opc), ld_val, 5);
		}
	} else if (!greg_recovery) {
		if (fmt == 5 && cpu_has(CPU_HWBUG_QUADRO_STRD)) {
			/* Interrupts are disabled here so
			 * it is safe to flush cache.
			 *
			 * Make sure no loads will reload
			 * the cache line after the flush */
			E2K_WAIT_LD;
			flush_DCACHE_line((e2k_addr_t)radr);
		}

		if (fmt == 5 && AS(ld_rec_opc).root == 0) {
			/* for protected mode we must copy tags too */
			E2K_MOVE_TAGGED_DWORD(address, radr);
		} else if (chan == 0) {
			if (vr) {
				E2K_MOVE_TAGGED_DWORD_WITH_OPC(address,
					radr, AW(ld_rec_opc), 0);
			} else {
				E2K_MOVE_TAGGED_WORD_WITH_OPC(address,
					radr, AW(ld_rec_opc), 0);
			}
		} else if (chan == 1) {
			if (vr) {
				E2K_MOVE_TAGGED_DWORD_WITH_OPC(address,
					radr, AW(ld_rec_opc), 2);
			} else {
				E2K_MOVE_TAGGED_WORD_WITH_OPC(address,
					radr, AW(ld_rec_opc), 2);
			}
		} else if (chan == 2) {
			if (vr) {
				E2K_MOVE_TAGGED_DWORD_WITH_OPC(address,
					radr, AW(ld_rec_opc), 3);
			} else {
				E2K_MOVE_TAGGED_WORD_WITH_OPC(address,
					radr, AW(ld_rec_opc), 3);
			}
		} else if (chan == 3) {
			if (vr) {
				E2K_MOVE_TAGGED_DWORD_WITH_OPC(address,
					radr, AW(ld_rec_opc), 5);
			} else {
				E2K_MOVE_TAGGED_WORD_WITH_OPC(address,
					radr, AW(ld_rec_opc), 5);
			}
		}
	} else {
		if (fmt == 5 && cpu_has(CPU_HWBUG_QUADRO_STRD)) {
			/* Interrupts are disabled here so
			 * it is safe to flush cache.
			 *
			 * Make sure no loads will reload
			 * the cache line after the flush */
			E2K_WAIT_LD;
			flush_DCACHE_line((e2k_addr_t) address);
		}

		if (chan == 0) {
			if (vr) {
				E2K_RECOVERY_LOAD_TO_A_GREG(address,
					AW(ld_rec_opc), greg_num_d, 0);
			} else {
			E2K_RECOVERY_LOAD_TO_A_GREG_VL(address,
					AW(ld_rec_opc), greg_num_d, 0);
			}
		} else if (chan == 1) {
			if (vr) {
				E2K_RECOVERY_LOAD_TO_A_GREG(address,
					AW(ld_rec_opc), greg_num_d, 2);
			} else {
				E2K_RECOVERY_LOAD_TO_A_GREG_VL(address,
					AW(ld_rec_opc), greg_num_d, 2);
			}
		} else if (chan == 2) {
			if (vr) {
				E2K_RECOVERY_LOAD_TO_A_GREG(address,
					AW(ld_rec_opc), greg_num_d, 3);
			} else {
				E2K_RECOVERY_LOAD_TO_A_GREG_VL(address,
					AW(ld_rec_opc), greg_num_d, 3);
			}
		} else if (chan == 3) {
			if (vr) {
				E2K_RECOVERY_LOAD_TO_A_GREG(address,
					AW(ld_rec_opc), greg_num_d, 5);
			} else {
				E2K_RECOVERY_LOAD_TO_A_GREG_VL(address,
					AW(ld_rec_opc), greg_num_d, 5);
			}
		}

		if (greg_num_d >= 16 && greg_num_d <= 19) {
			void *saved_greg =
				&current_thread_info()->gbase[greg_num_d - 16];

			if (chan == 0) {
				if (!vr)
					E2K_MOVE_TAGGED_WORD_WITH_OPC(
						address, saved_greg,
						AW(ld_rec_opc), 0);
				else
					E2K_MOVE_TAGGED_DWORD_WITH_OPC(
						address, saved_greg,
						AW(ld_rec_opc), 0);
			} else if (chan == 1) {
				if (!vr)
					E2K_MOVE_TAGGED_WORD_WITH_OPC(
						address, saved_greg,
						AW(ld_rec_opc), 2);
				else
					E2K_MOVE_TAGGED_DWORD_WITH_OPC(
						address, saved_greg,
						AW(ld_rec_opc), 2);
			} else if (chan == 2) {
				if (!vr)
					E2K_MOVE_TAGGED_WORD_WITH_OPC(
						address, saved_greg,
						AW(ld_rec_opc), 3);
				else
					E2K_MOVE_TAGGED_DWORD_WITH_OPC(
						address, saved_greg,
						AW(ld_rec_opc), 3);
			} else if (chan == 3) {
				if (!vr)
					E2K_MOVE_TAGGED_WORD_WITH_OPC(
						address, saved_greg,
						AW(ld_rec_opc), 5);
				else
					E2K_MOVE_TAGGED_DWORD_WITH_OPC(
						address, saved_greg,
						AW(ld_rec_opc), 5);
			}

#ifdef CONFIG_E2S_CPU_RF_BUG
			void *e2s_greg = &regs->e2s_gbase[greg_num_d - 16];

			if (chan == 0) {
				E2K_MOVE_TAGGED_DWORD_WITH_OPC(
						saved_greg, e2s_greg,
						AW(ld_rec_opc), 0);
			} else if (chan == 1) {
				E2K_MOVE_TAGGED_DWORD_WITH_OPC(
						saved_greg, e2s_greg,
						AW(ld_rec_opc), 2);
			} else if (chan == 2) {
				E2K_MOVE_TAGGED_DWORD_WITH_OPC(
						saved_greg, e2s_greg,
						AW(ld_rec_opc), 3);
			} else if (chan == 3) {
				E2K_MOVE_TAGGED_DWORD_WITH_OPC(
						saved_greg, e2s_greg,
						AW(ld_rec_opc), 5);
			}
#endif
		}

#ifdef CONFIG_E2S_CPU_RF_BUG
		switch (greg_num_d) {
		case 20: E2K_STORE_TAGGED_DGREG(&regs->e2s_gbase[4], 20); break;
		case 21: E2K_STORE_TAGGED_DGREG(&regs->e2s_gbase[5], 21); break;
		case 22: E2K_STORE_TAGGED_DGREG(&regs->e2s_gbase[6], 22); break;
		case 23: E2K_STORE_TAGGED_DGREG(&regs->e2s_gbase[7], 23); break;
		}
#endif
	}

	ACCESS_CONTROL_RESTORE(upsr_to_save);

	if (DEBUG_EXEC_MMU_OP) {
		register unsigned long	val;
		register unsigned int	tag;

		if (!radr) {
			ACCESS_CONTROL_DISABLE_AND_SAVE(upsr_to_save);
			E2K_RECOVERY_LOAD_TO(address, AW(ld_rec_opc), val, 2);
			ACCESS_CONTROL_RESTORE(upsr_to_save);
		} else if (greg_recovery) {
			E2K_GET_DGREG_VAL_AND_TAG(greg_num_d, val, tag);
		} else {
			E2K_LOAD_VAL_AND_TAGD(radr, val, tag);
		}

		if (!radr || !greg_recovery) {
			pr_info("do_recovery_load: load(%d) chan = %d "
				"address = 0x%lx, radr = 0x%p, rdata = 0x%lx "
				"tag = 0x%x\n",
				size, chan, address, radr, val, tag);
		} else {
			pr_info("do_recovery_load: load(%d) chan = %d "
				"address = 0x%lx, greg = %d, rdata = 0x%lx "
				"tag = 0x%x\n",
				size, chan, address, greg_num_d, val, tag);
		}
	}

	flags = ACCESS_ONCE(current->thread.flags);

	/* Nested exception appeared while do_recovery_load() */
	if (flags & E_MMU_NESTED_OP) {
		current->thread.flags &= ~E_MMU_NESTED_OP;

		if (fatal_signal_pending(current))
			return EXEC_MMU_STOP;
		else
			return EXEC_MMU_REPEAT;
	}

	return EXEC_MMU_SUCCESS;
}

static int
execute_mmu_operations(trap_cellar_t *tcellar, struct pt_regs *regs,
		       int zeroing, e2k_addr_t *adr)
{
	unsigned long flags;
	e2k_pshtp_t pshtp;
	e2k_psp_hi_t psp_hi;
	tc_opcode_t	opcode;
	e2k_addr_t	address = tcellar->address;
	tc_dst_t	dst;
	unsigned	dst_addr;
	int		rg, chan, store, size, fmt, ret;
	e2k_wd_t	wd;

	DbgEXMMU("started\n");

#ifdef CONFIG_PROTECTED_MODE
        /* 
         * for multithreading of protected mode
         * (It needs to know address of register in chaine stack 
         *  to change SAP to AP for other threads)
         */
	if (adr)
                *adr = 0;
#endif /* CONFIG_PROTECTED_MODE */

	current->thread.flags |= E_MMU_OP;

	AW(opcode) = AS(tcellar->condition).opcode;
	fmt = AS(opcode).fmt;
	BUG_ON((unsigned int) fmt > 5 || fmt == 0);

	size = 1 << (fmt - 1);
	if (size > sizeof(u64))
		size = sizeof(u64);

	DbgTC("Entered tick %ld\n",
						E2K_GET_DSREG(clkr));
	DebugPtR("execute_mmu_operations", regs);

	store = AS(tcellar->condition).store;

	if (AS(tcellar->condition).s_f) {
		e2k_addr_t stack_base;
		e2k_size_t stack_ind;

		/*
		 * Not completed SPILL operation should be completed here
		 * by data store
		 * Not completed FILL operation replaced by restore of saved
		 * filling data in trap handler
		 */

		DbgEXMMU("completion of %s %s operation\n",
			(AS(tcellar->condition).sru) ? "PCS" : "PS",
			(store) ? "SPILL" : "FILL");
		if (AS(tcellar->condition).sru) {
			stack_base = regs->stacks.pcsp_lo.PCSP_lo_base;
			stack_ind = regs->stacks.pcsp_hi.PCSP_hi_ind;
		} else {
			stack_base = regs->stacks.psp_lo.PSP_lo_base;
			stack_ind = regs->stacks.psp_hi.PSP_hi_ind;
		}
		if (address < stack_base || address >= stack_base + stack_ind) {
			printk("execute_mmu_operations(): invalid procedure "
				"stack addr 0x%lx < stack base 0x%lx or >= "
				"current stack offset 0x%lx\n",
				address, stack_base, stack_base + stack_ind);
			BUG();
		}
		if (!store && !AS(tcellar->condition).sru) {
			printk("execute_mmu_operations(): not completed "
				"PS FILL operation detected in TC (only "
				"PCS FILL operation can be dropped to TC)\n");
			BUG();
		}
		store = 1;
	}

	AW(dst) = AS(tcellar->condition).dst;
	dst_addr = AS(dst).address;

	chan = AS(tcellar->condition).chan;
	BUG_ON((unsigned int) chan > 3 || store && !(chan & 1));

	if (AS(tcellar->condition).num_align)
		address -= 8;

	/*
	 * Register number in the register file frame can be changed
	 * after a context switch, recalculate it under closed preemption.
	 * All math below is modulo E2K_MAXSR_d.
	 *
	 * WD_before_cs.base - regs->wd.base =
	 *		(PSP_HI.index - regs->psp_hi.index) / 2
	 *
	 * WD_before_cs.base = regs->wd.base +
	 *			(PSP_HI.index - regs->psp_hi.index) / 2
	 *
	 * So we calculate register physical address shift as:
	 *
	 * delta_base = WD_after_cs.base - WD_before_cs.base =
	 *		WD.base - regs->wd.base -
	 *		(PSP_HI.index - regs->psp_hi.index) / 2
	 *
	 * delta_rg = delta_base % E2K_MAXSR_d
	 */
	raw_all_irq_save(flags);
	AW(wd) = E2K_GET_DSREG(wd);
	psp_hi = RAW_READ_PSP_HI_REG();
	pshtp = READ_PSHTP_REG();

	AW(psp_hi) += GET_PSHTP_INDEX(pshtp);

	rg = dst_addr;
	/* Make sure all divisions are signed */
	rg += ((signed int) (AS(wd).base - AS(regs->wd).base -
	       (signed int) (psp_hi.PSP_hi_ind -
			     regs->stacks.psp_hi.PSP_hi_ind) / 2)) / 8;
	rg = rg % E2K_MAXSR_d;
	if (rg < 0)
		rg += E2K_MAXSR_d;

	if (rg != dst_addr) {
		DbgEXMMU("wd.base 0x%x, regs->wd.base 0x%x, psp_hi.index 0x%x, regs->psp_hi.index 0x%x, delta %d (rg %d, dst_addr %d)\n",
			AS(wd).base, AS(regs->wd).base,
			psp_hi.PSP_hi_ind, regs->stacks.psp_hi.PSP_hi_ind,
			rg - dst_addr, rg, dst_addr);
	}

	if (store) {
		/*
		 * Here performs dropped store operation, opcode.fmt contains
		 * size of data that must be stored, address it's address where
		 * data must be stored, data is data ;-) 
		 * As manual says data must be in little endian, in this case
		 * we can entrust conversion operation on compiler.
		 */
		ret = do_recovery_store(regs, tcellar, opcode, address, size,
				chan, fmt, rg);
	} else {
		/* Here we must perform load operation, there is more difficult
		 * then load, we know only the number of register in window of
		 * other process, so we need to SPILL register file in memory
		 * than find in it needed register and only after it perform
		 * operation.
		 */
		unsigned	greg_num_d, greg_recovery, rotatable_greg;
		u64		*radr;
		e2k_bgr_t	src_bgr;

		ret = calculate_recovery_load_parameters(regs, dst, dst_addr,
				&greg_num_d, &greg_recovery,
				&rotatable_greg, &src_bgr, &radr);

		if (!ret) {
			bool load_to_rf = (!greg_recovery && radr);

			if (load_to_rf) {
				E2K_FLUSHR;
				E2K_FLUSH_WAIT;
			}
			ret = do_recovery_load(regs, tcellar, opcode, dst,
					zeroing,
					address, size, radr, chan, fmt,
					greg_recovery, greg_num_d, rg, adr);

			/*
			 * Restore BGR register to recover rotatable state
			 */
			if (rotatable_greg)
				write_BGR_reg(src_bgr);
		}
	}

	raw_all_irq_restore(flags);

	current->thread.flags &= ~(E_MMU_OP | E_MMU_NESTED_OP);

	return ret;
}

/* see 5.4. О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ (PR) */
#define  get_predicate_val(x, N) (((x) >> ((N)*2)) & 0x1) 

/* see C.17.1.2. О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫ */
static int 
calculate_ct_operation(u64 lsr,
                       instr_ss_t instr, u64 pf)
{
        int value;
        ct_struct_t ct_op;
        lsr_struct_t Lsr;
        
        AW(Lsr) = lsr;
        AW(ct_op) =  SS_CTCOND(instr);
        switch(CT_CT(ct_op)){ 
	case 0:
                value = 0;
                break;
	case 1:
                value = 1;
                break;
	case 2:
                value = get_predicate_val(pf,CT_PSRC(ct_op));  
                break;
	case 3:
                value = !get_predicate_val(pf,CT_PSRC(ct_op));
                break;
	case 4:
                value = ls_loop_end(Lsr);
                break;
	case 5:
                value = !ls_loop_end(Lsr);
                break;
	case 6:
                value = ((Lsr.fields.semc || !ls_prlg(Lsr)) &&
                    get_predicate_val(pf,CT_PSRC(ct_op))) || ls_loop_end(Lsr);
                break;
	case 7:
                value = !(((Lsr.fields.semc || !ls_prlg(Lsr)) &&
                    get_predicate_val(pf,CT_PSRC(ct_op))) || ls_loop_end(Lsr));
                break;
	case 8: /* must be changed !!! */
                value = ((!(Lsr.fields.semc || !ls_prlg(Lsr)) &&
                    get_predicate_val(pf,CT_PSRC(ct_op))) || ls_loop_end(Lsr));
                break;
	case 14:
                value = (((Lsr.fields.semc || !ls_prlg(Lsr)) &&
                    !get_predicate_val(pf,CT_PSRC(ct_op))) || ls_loop_end(Lsr));
                break;
	case 15:
                value = !(((Lsr.fields.semc || !ls_prlg(Lsr)) &&
                    !get_predicate_val(pf,CT_PSRC(ct_op))) || ls_loop_end(Lsr));
                break;
	default:
		value = 0;
                printk("calculate_ct_operation  bad ct_op = %d CT_PSRC =%d\n",
                       CT_CT(ct_op), CT_PSRC(ct_op));  
                break;
	}
        return 0;
}
/*
 * abn abp instructions changed fields for RPR 
 * we must restore old values for this fields
 */  
static void 
calculate_new_rpr(struct pt_regs *regs, e2k_addr_t ip, int stp)
{
	instr_hs_t  hs;	
	instr_ss_t  ss;
        rpr_lo_struct_t rpr_lo;
        rpr_hi_struct_t rpr_hi;

	/*
         * calculate new value of RPR
         */  
        AW(rpr_lo) = 0;
        RPR_STP(rpr_lo) = stp;
        RPR_IP(rpr_lo) = ip;
        E2K_SET_DSREG(rpr.lo, AW(rpr_lo));
        
	if (get_user(AW(hs), &E2K_GET_INSTR_HS(ip)) == -EFAULT) {
		DebugRPR("HS does exist\n");
		return;
	}


	/* Check presence of Stub Syllabe */

	if (AW(hs)) {
		DebugRPR("HS does exist\n");
	} else {		
		DebugRPR("SS doesn't exist\n");
		return;
	}

	/* Stub Syllabe encodes different short fragment of command */
	if (get_user(AW(ss), &E2K_GET_INSTR_SS(ip)) == -EFAULT) {
		return;
	}
        if (SS_ABN(ss) || SS_ABP(ss)) { 
                if (calculate_ct_operation(regs->lsr, ss,
                                           AW(regs->crs.cr0_lo))){
                    AW(rpr_hi) = E2K_GET_DSREG(rpr.hi);
                    RPR_BR_CUR(rpr_hi)++;
                    RPR_BR_PCUR(rpr_hi)++;
                    E2K_SET_DSREG(rpr.hi, AW(rpr_hi));
                }    
        }    
}    
