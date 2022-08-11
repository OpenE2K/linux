/*
 *
 * Copyright (C) 2001 MCST 
 */

#include <linux/debugfs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/hugetlb.h>
#include <linux/mempolicy.h>
#include <linux/mman.h>
#include <linux/mmu_context.h>
#include <linux/export.h>
#include <linux/perf_event.h>
#include <linux/sched/rt.h>
#include <linux/syscalls.h>
#include <linux/extable.h>

#include <asm/cpu_regs_access.h>
#include <asm/getsp_adj.h>
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
#include <asm/traps.h>
#include <asm/trap_table.h>
#include <linux/uaccess.h>
#include <asm/copy-hw-stacks.h>
#include <asm/regs_state.h>
#include <asm/e2k_syswork.h>
#include <asm/mlt.h>
#include <asm/e2k_debug.h>
#include <asm/secondary_space.h>
#include <asm/kvm/async_pf.h>
#include <asm/sync_pg_tables.h>
#ifdef CONFIG_SOFTWARE_SWAP_TAGS
#include <asm/tag_mem.h>
#endif
#ifdef CONFIG_PROTECTED_MODE
#include <asm/3p.h>
#endif /* CONFIG_PROTECTED_MODE */

#ifdef CONFIG_MCST_RT
#include <linux/mcst_rt.h>
#endif

#include <asm/trace.h>


/**************************** DEBUG DEFINES *****************************/

#define	fault_dbg		0
#define	DEBUG_TRAP_CELLAR	fault_dbg		/* DEBUG_TRAP_CELLAR */
#define DbgTC(...)		DebugPrint(DEBUG_TRAP_CELLAR, ##__VA_ARGS__)
#define	DEBUG_STATE_TC		DEBUG_TRAP_CELLAR	/* DEBUG_TRAP_CELLAR */
#define PrintTC(a, b) \
	if(DEBUG_STATE_TC || DEBUG_CLW_FAULT) print_tc_state(a, b);

#undef	DEBUG_HS_MODE
#undef	DebugHS
#define	DEBUG_HS_MODE		0	/* Expand Hard Stack */
#define DebugHS(...)		DebugPrint(DEBUG_HS_MODE, ##__VA_ARGS__)

#undef	DEBUG_CS_MODE
#undef	DebugCS
#define	DEBUG_CS_MODE		0	/* Constrict Hard Stack */
#define DebugCS(...)		DebugPrint(DEBUG_CS_MODE, ##__VA_ARGS__)

#undef	DEBUG_US_EXPAND
#undef	DebugUS
#define	DEBUG_US_EXPAND		0	/* User stacks */
#define DebugUS(...)		DebugPrint(DEBUG_US_EXPAND, ##__VA_ARGS__)

#undef	DEBUG_VMA_MODE
#undef	DebugVMA
#define	DEBUG_VMA_MODE		0	/* Hard Stack Clone and Alloc */
#define DebugVMA(...)		DebugPrint(DEBUG_VMA_MODE, ##__VA_ARGS__)

#undef	DEBUG_USER_PTE_MODE
#undef	DebugUPTE
#define	DEBUG_USER_PTE_MODE	0
#define DebugUPTE(...)		DebugPrint(DEBUG_USER_PTE_MODE, ##__VA_ARGS__)

#define	DEBUG_PF_MODE		fault_dbg	/* Page fault */
#define DebugPF(...)		DebugPrint(DEBUG_PF_MODE, ##__VA_ARGS__)

#define	DEBUG_NAO_MODE		0	/* Not aligned operation */
#define DebugNAO(...)		DebugPrint(DEBUG_NAO_MODE, ##__VA_ARGS__)

#define	DEBUG_EXEC_MMU_OP	0
#define DbgEXMMU(...)		DebugPrint(DEBUG_EXEC_MMU_OP, ##__VA_ARGS__)

#undef	DEBUG_PGD_MODE
#undef	DebugPGD
#define	DEBUG_PGD_MODE		0	/* CPU PGD populate */
#define DebugPGD(...)		DebugPrint(DEBUG_PGD_MODE, ##__VA_ARGS__)

#undef	DEBUG_UF_MODE
#undef	DebugUF
#define	DEBUG_UF_MODE		0	/* VMA flags update */
#define DebugUF(...)		DebugPrint(DEBUG_UF_MODE, ##__VA_ARGS__)

#undef	DEBUG_CLW_FAULT
#undef	DebugCLW
#define	DEBUG_CLW_FAULT		0
#define DebugCLW(...)		DebugPrint(DEBUG_CLW_FAULT, ##__VA_ARGS__)

#undef	DEBUG_SRP_FAULT
#undef	DebugSRP
#define	DEBUG_SRP_FAULT	        0
#define DebugSRP(...)		DebugPrint(DEBUG_SRP_FAULT, ##__VA_ARGS__)

#undef	DEBUG_SPRs_MODE
#define	DEBUG_SPRs_MODE		0	/* stack pointers registers */

#undef	DEBUG_RPR
#undef	DebugRPR
#define	DEBUG_RPR		0	/* Recovery point register */
#define DebugRPR(...)		DebugPrint(DEBUG_RPR, ##__VA_ARGS__)

#undef	DEBUG_RG_UPDATE
#undef	DebugRG
#define	DEBUG_RG_UPDATE		0
#define DebugRG(...)		DebugPrint(DEBUG_RG_UPDATE, ##__VA_ARGS__)

#undef	DEBUG_MULTI_THREAD_PM
#undef	DebugMT_PM
#define	DEBUG_MULTI_THREAD_PM	0
#define DebugMT_PM(...)		DebugPrint(DEBUG_MULTI_THREAD_PM, ##__VA_ARGS__)

#undef	DEBUG_KVM_PAGE_FAULT_MODE
#undef	DebugKVMPF
#define	DEBUG_KVM_PAGE_FAULT_MODE	0	/* KVM page fault debugging */
#define	DebugKVMPF(fmt, args...)					\
({									\
	if (DEBUG_KVM_PAGE_FAULT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

/*
 * Print pt_regs
 */
#define	DEBUG_PtR_MODE		0	/* Print pt_regs */
#define	DebugPtR(pt_regs)	\
	do { if (DEBUG_PtR_MODE) print_pt_regs(pt_regs); } while (0)

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

/* abridged version */
static int __init pagef_setup(char *str)
{
	debug_pagefault = 1;
	return 1;
}
__setup("debug_pagef", pagef_setup);

typedef union pf_mode {
	struct {
		u32 write	: 1;
		u32 spec	: 1;
		u32 user	: 1;
		u32 root	: 1;
		u32 empty	: 1;
	};
	u32 word;
} pf_mode_t;

static int pf_force_sig_info(int si_signo, int si_code, unsigned long address,
			     struct pt_regs *regs);

int show_unhandled_signals = 0;

#undef  GET_IP
#define GET_IP  GET_IP_CR0_HI((regs)->crs.cr0_hi)
#define PFDBGPRINT(fmt, ...) \
do { \
	if (debug_pagefault || DEBUG_PF_MODE) { \
		pr_notice("PAGE FAULT. " fmt ": IP=%px %s(pid=%d)\n" \
				,##__VA_ARGS__, (void *) GET_IP, \
				current->comm, current->pid); \
	} \
} while (0)

/********************* END of PAGE FAULT DEBUG for users *****************/

int do_update_vm_area_flags(e2k_addr_t start, e2k_size_t len,
		vm_flags_t flags_to_set, vm_flags_t flags_to_clear)
{
	unsigned long nstart, end, tmp;
	struct vm_area_struct *vma, *next;
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
		DebugVMA("splitting vma at (0x%lx, 0x%lx) at 0x%lx\n",
			vma->vm_start, vma->vm_end, start);
		if (split_vma(current->mm, vma, start, 1))
			return -ENOMEM;
	}
	if (vma->vm_end > end) {
		DebugVMA("splitting vma at "
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
				DebugVMA("splitting vma at (0x%lx, 0x%lx) at 0x%lx\n",
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
			pr_err("Could not find VMA structure of user virtual memory area: addr 0x%lx\n",
				nstart);
			BUG();
		}
		if (vma->vm_start != nstart) {
			pr_err("Invalid VMA structure start address of user virtual memory area: addr 0x%lx (should be 0x%lx)\n",
				vma->vm_start, nstart);
			BUG();
		}
	}
	return error;
}

e2k_addr_t
user_address_to_pva(struct task_struct *tsk, e2k_addr_t address)
{
	pgd_t		*pgd;
	pud_t		*pud;
	pmd_t		*pmd;
	pte_t		*pte;
	e2k_addr_t	offset;
	e2k_addr_t	ret;
	struct vm_area_struct *vma;
	bool already_locked = false;

	ret = check_is_user_address(tsk, address);
	if (ret != 0)
		return ret;

	if (unlikely(IS_GUEST_USER_ADDRESS_TO_PVA(tsk, address))) {
		return guest_user_address_to_pva(tsk, address);
	}

	if (!down_read_trylock(&tsk->mm->mmap_sem))
		already_locked = true;

	vma = find_vma(tsk->mm, address);
	if (vma == NULL) {
		pr_err("Could not find VMA structure of user "
			"virtual memory area: addr 0x%lx\n",
			address);
		goto out;
	}

	pgd = pgd_offset(vma->vm_mm, address);
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		pr_err("PGD  0x%px = 0x%lx none or bad for address 0x%lx\n",
			pgd, pgd_val(*pgd), address);
		goto out;
        }

	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || pud_bad(*pud)) {
		pr_err("PUD  0x%px = 0x%lx none or bad for address 0x%lx\n",
			pud, pud_val(*pud), address);
		goto out;
	}

	pmd = pmd_offset(pud, address);
	if (pmd_huge(*pmd)) {
		pte = (pte_t *) pmd;
		offset = address & (get_pmd_level_page_size() - 1);
	} else {
		if (pmd_none(*pmd) || pmd_bad(*pmd)) {
			pr_err("PMD 0x%px = 0x%016lx none or bad for address 0x%016lx\n",
				pmd, pmd_val(*pmd), address);
			goto out;
		}
		pte = pte_offset_map(pmd, address);
		offset = address & (get_pte_level_page_size() - 1);
	}

	if (pte_none(*pte)) {
		pr_err("PTE  0x%px = 0x%016lx none for address 0x%016lx\n",
			pte, pte_val(*pte), address);
		goto out;
	}

	if (!already_locked)
		up_read(&tsk->mm->mmap_sem);
	return (e2k_addr_t)__va((pte_pfn(*pte) << PAGE_SHIFT) | offset);

out:
	if (!already_locked)
		up_read(&tsk->mm->mmap_sem);
	return -1;
}

pte_t *get_user_address_pte(struct vm_area_struct *vma, e2k_addr_t address)
{
	pgd_t	*pgd;
	pud_t	*pud;
	pmd_t	*pmd;
	pte_t	*pte;

	if (address < vma->vm_start || address >= vma->vm_end) {
		DebugUPTE("User address 0x%lx is  not from VMA start 0x%lx "
			"end 0x%lx\n",
			address, vma->vm_start, vma->vm_end);
		return NULL;
	}
	pgd = pgd_offset(vma->vm_mm, address);
	if (pgd_none(*pgd) && pgd_valid(*pgd)) {
		DebugUPTE("PGD  0x%px = 0x%lx only valid for address 0x%lx\n",
			pgd, pgd_val(*pgd), address);
		return (pte_t *)pgd;
	}
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		DebugUPTE("PGD  0x%px = 0x%lx none or bad for address 0x%lx\n",
			pgd, pgd_val(*pgd), address);
		return NULL;
	}
	pud = pud_offset(pgd, address);
	if (pud_huge(*pud))
		return (pte_t *) pud;
	if (pud_none(*pud) && pud_valid(*pud)) {
		DebugUPTE("PUD  0x%px = 0x%lx only valid for address 0x%lx\n",
			pud, pud_val(*pud), address);
		return (pte_t *)pud;
	}
	if (pud_none(*pud) || pud_bad(*pud)) {
		DebugUPTE("PUD  0x%px = 0x%lx none or bad for address 0x%lx\n",
			pud, pud_val(*pud), address);
		return NULL;
	}
	pmd = pmd_offset(pud, address);
	if (pmd_huge(*pmd))
		return (pte_t *) pmd;
	if (pmd_none(*pmd) && pmd_valid(*pmd)) {
		DebugUPTE("PMD 0x%px = 0x%016lx only valid for address "
			"0x%016lx\n",
			pmd, pmd_val(*pmd), address);
		return (pte_t *)pmd;
	}
	if (pmd_none(*pmd) || pmd_bad(*pmd)) {
		DebugUPTE("PMD 0x%px = 0x%016lx none or bad for address "
			"0x%016lx\n",
			pmd, pmd_val(*pmd), address);
		return NULL;
	}
	/* pte */
	pte = pte_offset_map(pmd, address);
	if (pte_none(*pte)) {
		DebugUPTE("PTE  0x%px = 0x%016lx none for address 0x%016lx\n",
			pte, pte_val(*pte), address);
	}
	return pte;
}

/*
 * Convrert kernel virtual address to physical
 * (convertion based on page table lookup)
 */
e2k_addr_t
kernel_address_to_pva(e2k_addr_t address)
{
	pgd_t		*pgd;
	pud_t		*pud;
	pmd_t		*pmd;
	pte_t		*pte;
	e2k_size_t	page_size;

	if (address < TASK_SIZE) {
		pr_alert("Address 0x%016lx is not kernel address "
			"to get PFN's\n",
			address);
		return -1;
	}
	if (unlikely(IS_GUEST_ADDRESS_TO_HOST(address))) {
		if (address >= KERNEL_BASE && address <= KERNEL_END) {
			return kernel_va_to_pa(address);
		} else {
			pr_alert("Address 0x%016lx is host kernel address\n",
				address);
			return -1;
		}
	}

	pgd = pgd_offset_k(address);
	if (pgd_none_or_clear_bad(pgd)) {
		pr_alert("PGD  0x%px = 0x%016lx none or bad for address 0x%016lx\n",
			pgd, pgd_val(*pgd), address);
		return -1;
	}
	if (kernel_pgd_huge(*pgd)) {
		pte = (pte_t *)pgd;
		page_size = get_pgd_level_page_size();
		goto huge_pte;
	}

	/* pud */
	pud = pud_offset(pgd, address);
	if (kernel_pud_huge(*pud)) {
		pte = (pte_t *)pud;
		page_size = get_pud_level_page_size();
		goto huge_pte;
	}
	if (pud_none_or_clear_bad(pud)) {
		pr_alert("PUD 0x%px = 0x%016lx none or bad for address 0x%016lx\n",
			pud, pud_val(*pud), address);
		return -1;
	}

	/* pmd */
	pmd = pmd_offset(pud, address);
	if (kernel_pmd_huge(*pmd)) {
		pte = (pte_t *)pmd;
		page_size = get_pmd_level_page_size();
		goto huge_pte;
	}
	if (pmd_none_or_clear_bad(pmd)) {
		pr_alert("PMD 0x%px = 0x%016lx none or bad for address 0x%016lx\n",
			pmd, pmd_val(*pmd), address);
		return -1;
	}

	/* pte */
	pte = pte_offset_kernel(pmd, address);
	page_size = get_pte_level_page_size();
huge_pte:
	if (pte_none(*pte)) {
		pr_alert("PTE  0x%px:0x%016lx none for address 0x%016lx\n",
			pte, pte_val(*pte), address);
		return -1;
	}
	if (!pte_present(*pte)) {
		pr_alert("PTE  0x%px = 0x%016lx is pte of swaped page "
			"for address 0x%016lx\n",
			pte, pte_val(*pte), address);
		return -1;
	}
	return (e2k_addr_t)__va((pte_pfn(*pte) << PAGE_SHIFT) |
					(address & (page_size - 1)));
}

unsigned long node_kernel_address_to_phys(int node, e2k_addr_t addr)
{
	e2k_addr_t phys_addr;
	e2k_size_t page_size;
	pgd_t *pgd = node_pgd_offset_kernel(node, addr);
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (unlikely(pgd_none_or_clear_bad(pgd))) {
		pr_alert("node_kernel_address_to_phys(): pgd_none\n");
		return -EINVAL;
	}
	if (kernel_pgd_huge(*pgd)) {
		pte = (pte_t *)pgd;
		page_size = get_pgd_level_page_size();
		goto huge_pte;
	}
	pud = pud_offset(pgd, addr);
	if (kernel_pud_huge(*pud)) {
		pte = (pte_t *)pud;
		page_size = get_pud_level_page_size();
		goto huge_pte;
	}
	if (unlikely(pud_none_or_clear_bad(pud))) {
		pr_alert("node_kernel_address_to_phys(): pud_none\n");
		return -EINVAL;
	}
	pmd = pmd_offset(pud, addr);
	if (kernel_pmd_huge(*pmd)) {
		pte = (pte_t *)pmd;
		page_size = get_pmd_level_page_size();
		goto huge_pte;
	}
	if (unlikely(pmd_none_or_clear_bad(pmd))) {
		pr_alert("node_kernel_address_to_phys(): pmd_none\n");
		return -EINVAL;
	}

	pte = pte_offset_kernel(pmd, addr);
	page_size = get_pte_level_page_size();

huge_pte:
	if (unlikely(pte_none(*pte) || !pte_present(*pte))) {
		pr_alert("node_kernel_address_to_phys(): pte_none\n");
		return -EINVAL;
	}

	phys_addr = _PAGE_PFN_TO_PADDR(pte_val(*pte)) +
					(addr & (page_size - 1));

	return phys_addr;
}

static const char *get_memory_type_string(pte_t pte)
{
	char *memory_types_v6[8] = { "General Cacheable",
			"General nonCacheable", "Reserved-2", "Reserved-3",
			"External Prefetchable", "Reserved-5",
			"External nonPrefetchable", "External Configuration" };

	if (MMU_IS_PT_V6())
		return memory_types_v6[_PAGE_MT_GET_VAL(pte_val(pte))];

	if (!(pte_val(pte) & ~_PAGE_VALID_V2))
		return "";

	if ((pte_val(pte) & _PAGE_CD_MASK_V2) != _PAGE_CD_MASK_V2)
		return "cacheable";

	if ((pte_val(pte) & _PAGE_PWT_V2))
		return "uncacheable";
	else
		return "write_combine";
}

e2k_addr_t print_address_ptes(pgd_t *pgdp, e2k_addr_t address, int kernel)
{
	pgd_t		pgd = *pgdp;
	pud_t		*pud;
	pmd_t		*pmd;
	pte_t		*pte;
	e2k_addr_t	pa = 0;
	e2k_size_t	page_size;

	if (kernel && kernel_pgd_huge(pgd)) {
		pte = (pte_t *)pgdp;
		page_size = get_pgd_level_page_size();
		pr_alert("%s PGD 0x%px = 0x%016lx is PTE of huge page\n",
			(kernel) ? "kernel" : "user", pgdp, pgd_val(pgd));
		goto huge_pte;
	}
	if (pgd_none(pgd) && (kernel || !pgd_valid(pgd)) || pgd_bad(pgd)) {
		pr_alert("%s PGD  0x%px = 0x%016lx none or bad "
			"for address 0x%016lx\n",
			(kernel) ? "kernel" : "user", pgdp, pgd_val(pgd),
			address);
		return pa;
	}
	pr_alert("%s PGD 0x%px = 0x%016lx valid for address 0x%016lx\n",
			(kernel) ? "kernel" : "user", pgdp, pgd_val(pgd),
			address);
	if (pgd_none(pgd))
		return pa;

	/* pud */
	pud = pud_offset(pgdp, address);
	if (kernel && kernel_pud_huge(*pud)) {
		pte = (pte_t *)pud;
		page_size = get_pud_level_page_size();
		pr_alert("PUD 0x%px = 0x%016lx is PTE of huge page\n",
			pud, pud_val(*pud));
		goto huge_pte;
	}
	if (pud_none(*pud) && (kernel || !pud_valid(*pud)) || pud_bad(*pud)) {
		pr_alert("PUD 0x%px = 0x%016lx none or bad "
			"for address 0x%016lx\n",
			pud, pud_val(*pud), address);
		return pa;
	}
	pr_alert("PUD 0x%px = 0x%016lx valid for address 0x%016lx\n",
			pud, pud_val(*pud), address);
	if (pud_none(*pud))
		return pa;

	/* pmd */
	pmd = pmd_offset(pud, address);
	if (kernel && kernel_pmd_huge(*pmd) || !kernel && pmd_huge(*pmd)) {
		pte = (pte_t *)pmd;
		page_size = get_pmd_level_page_size();
		pr_alert("PMD 0x%px = 0x%016lx is PTE of huge page\n",
			pmd, pmd_val(*pmd));
		goto huge_pte;
	}
	if (pmd_none(*pmd) && (kernel || !pmd_valid(*pmd)) || pmd_bad(*pmd)) {
		pr_alert("PMD 0x%px = 0x%016lx none or bad for "
			"address 0x%016lx\n",
			pmd, pmd_val(*pmd), address);
		return pa;
	}
	pr_alert("PMD 0x%px = 0x%016lx valid for address 0x%016lx\n",
			pmd, pmd_val(*pmd), address);
	if (pmd_none(*pmd))
		return pa;

	/* pte */
	pte = (kernel) ?
		pte_offset_kernel(pmd, address) : pte_offset_map(pmd, address);
	page_size = get_pte_level_page_size();

huge_pte:
	if (pte_none(*pte)) {
		pr_alert("PTE  0x%px = 0x%016lx none for address 0x%016lx\n",
				pte, pte_val(*pte), address);
	} else if (!pte_present(*pte)) {
		pr_alert("PTE  0x%px = 0x%016lx is pte of not present page for address 0x%016lx\n",
				pte, pte_val(*pte), address);
	} else {
		pr_alert("PTE  0x%px = 0x%016lx %s & present for address 0x%016lx %s\n",
				pte, pte_val(*pte),
				pte_valid(*pte) ? "valid" : "not valid",
				address, get_memory_type_string(*pte));

		pa = _PAGE_PFN_TO_PADDR(pte_val(*pte)) +
						(address & (page_size - 1));
	}

	return pa;
}


void print_vma_and_ptes(struct vm_area_struct *vma, e2k_addr_t address)
{
	pgd_t		*pgdp;

	printk("VMA 0x%px : start 0x%016lx, end 0x%016lx, flags 0x%lx, "
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

		/* Only for guest: print ptes of guest user address on host. */
		/* Guest page table is pseudo PT and only host PT is used */
		/* to translate any guest addresses */
		print_host_user_address_ptes(mm, address);
	}
	return pa;
}

e2k_addr_t print_user_address_ptes(struct mm_struct *mm, e2k_addr_t address)
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
	pgdp = pgd_offset_k(address);
	pa = print_address_ptes(pgdp, address, 1);
	return pa;
}

void print_address_page_tables(unsigned long address, int last_level_only)
{
	struct mm_struct *mm = current->mm;

	if (address < TASK_SIZE)
		print_user_address_ptes(mm, address);
	else
		print_kernel_address_ptes(address);

	if (last_level_only)
		return;

	if (address < TASK_SIZE) {
		print_user_address_ptes(mm,
				pte_virt_offset(round_down(address, PTE_SIZE)));
		print_user_address_ptes(mm,
				pmd_virt_offset(round_down(address, PMD_SIZE)));
		print_user_address_ptes(mm,
				pud_virt_offset(round_down(address, PUD_SIZE)));
	} else {
		print_kernel_address_ptes(
				pte_virt_offset(round_down(address, PTE_SIZE)));
		print_kernel_address_ptes(
				pmd_virt_offset(round_down(address, PMD_SIZE)));
		print_kernel_address_ptes(
				pud_virt_offset(round_down(address, PUD_SIZE)));
	}
}

int is_kernel_address_valid(e2k_addr_t address)
{
	pgd_t		*pgd;
	pud_t		*pud;
	pmd_t		*pmd;
	pte_t		*pte;
	e2k_size_t	page_size;

	if (address < TASK_SIZE) {
		printk("Address 0x%016lx is not kernel address to get PFN's\n",
			address);
		return 0;
	}
	pgd = pgd_offset_k(address);
	if (pgd_none_or_clear_bad(pgd)) {
		printk("\n============================================================\n");
		printk("PGD  0x%px = 0x%016lx none or bad for address 0x%016lx\n",
			pgd, pgd_val(*pgd), address);
		return 0;
	}
	if (kernel_pgd_huge(*pgd)) {
		pte = (pte_t *)pgd;
		page_size = get_pgd_level_page_size();
		goto huge_pte;
	}

	/* pud */
	pud = pud_offset(pgd, address);
	if (pud_none_or_clear_bad(pud)) {
		printk("\n============================================================\n");
		printk("PUD 0x%px = 0x%016lx none or bad for address 0x%016lx\n",
			pud, pud_val(*pud), address);
		return 0;
	}
	if (kernel_pud_huge(*pud)) {
		pte = (pte_t *)pud;
		page_size = get_pud_level_page_size();
		goto huge_pte;
	}

	/* pmd */
	pmd = pmd_offset(pud, address);
	if (pmd_none_or_clear_bad(pmd)) {
		printk("\n============================================================\n");
		printk("PMD 0x%px = 0x%016lx none or bad for address 0x%016lx\n",
			pmd, pmd_val(*pmd), address);
		return 0;
	}
	if (kernel_pmd_huge(*pmd)) {
		pte = (pte_t *)pmd;
		page_size = get_pmd_level_page_size();
		goto huge_pte;
	}

	/* pte */
	pte = pte_offset_kernel(pmd, address);
	page_size = get_pte_level_page_size();

huge_pte:
	if (pte_none(*pte)) {
		printk("\n============================================================\n");
		printk("PTE:  0x%px = 0x%016lx <none> for address 0x%016lx\n",
			pte, pte_val(*pte), address);
		return 0;
	}
	if (!pte_present(*pte)) {
		printk("\n============================================================\n");
		printk("PTE  0x%px = 0x%016lx is pte of swaped page for address 0x%016lx\n",
				pte, pte_val(*pte), address);
		return 0;
	}
	return 1;
}

#if 0
void print_vma_node_ptes(struct vm_area_struct *vma, e2k_addr_t address)
{
	print_vma_and_ptes(vma, address);

	if (MMU_IS_SEPARATE_PT())
		return;

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

	if (kaddr >= PAGE_OFFSET && kaddr < PAGE_OFFSET + MAX_PM_SIZE) {
		return phys_to_page(__pa(kaddrp));
	}
	if (kaddr >= KERNEL_BASE && kaddr <= KERNEL_END) {
		return phys_to_page(vpa_to_pa(kernel_va_to_pa(kaddrp)));
	}
	if (is_vmalloc_addr(kaddrp)) {
		return vmalloc_to_page(kaddrp);
	}
	if (kaddr < TASK_SIZE) {
		panic("%s(): address 0x%px is not kernel address\n",
			__func__, kaddrp);
	}
	panic("%s(): address 0x%px is invalid kernel address\n",
		__func__, kaddrp);
}

EXPORT_SYMBOL(e2k_virt_to_page);

#ifndef	CONFIG_CLW_ENABLE
#define	terminate_CLW_operation(regs)
#else
struct clw_clear_user_args {
	void __user *uaddr;
	unsigned long size;
	struct mm_struct *mm;
};

static long clw_clear_user_worker(void *pargs)
{
	struct clw_clear_user_args *args = pargs;
	unsigned long ret;

	use_mm(args->mm);
	ret = clear_user_with_tags(args->uaddr, args->size, ETAGEWD);
	unuse_mm(args->mm);
	return ret;
}

static unsigned long clw_clear_user(const struct pt_regs *regs,
		void __user *uaddr, unsigned long size)
{
	struct clw_clear_user_args args = {
		.uaddr = uaddr,
		.size = size,
		.mm = current->mm
	};
	unsigned long ret;

	if (!cpu_has(CPU_HWBUG_CLW_STALE_L1_ENTRY))
		return clear_user_with_tags(uaddr, size, ETAGEWD);

	migrate_disable();
	if (likely(smp_processor_id() == regs->clw_cpu)) {
		/* Fast path  - we are already on needed cpu */
		ret = clear_user_with_tags(uaddr, size, ETAGEWD);
	} else {
		/* Slow path - let kworker do the work on proper cpu */
		ret = work_on_cpu(regs->clw_cpu, clw_clear_user_worker, &args);
	}
	migrate_enable();

	return ret;
}

static int terminate_CLW_operation(const struct pt_regs *regs)
{
	e2k_addr_t us_cl_up = regs->us_cl_up;
	e2k_addr_t us_cl_b = regs->us_cl_b;
	const clw_reg_t *us_cl_m = regs->us_cl_m;
	unsigned long us_addr;
	u64 bit_no, mask_word, mask_bit;
	int bmask;

	DebugCLW("started for us_cl_up 0x%lx us_cl_b 0x%lx\n",
			us_cl_up, us_cl_b);
	for (bmask = 0; bmask < CLW_MASK_WORD_NUM; bmask++)
		DebugCLW("    mask[%d] = 0x%016lx\n", bmask, us_cl_m[bmask]);

	if (us_cl_up <= us_cl_b) {
		DebugCLW("nothing to clean\n");
		return 0;
	}

	for (us_addr = us_cl_up; us_addr > us_cl_b &&
				(us_cl_up - us_addr) < CLW_BYTES_PER_MASK;
			us_addr -= CLW_BYTES_PER_BIT) {
		DebugCLW("current US address 0x%lx\n"
			"check bit-mask #%lld word %lld bit in word %lld\n",
			us_addr, bit_no, mask_word, mask_bit);

		bit_no = (us_addr / CLW_BYTES_PER_BIT) & 0xffUL;
		mask_word = bit_no / (sizeof (*us_cl_m) * 8);
		mask_bit = bit_no % (sizeof (*us_cl_m) * 8);

		if (!(us_cl_m[mask_word] & (1UL << mask_bit))) {
			DebugCLW("clean stack area from 0x%lx to 0x%lx\n",
				us_addr, us_addr + CLW_BYTES_PER_BIT);
			if (clw_clear_user(regs, (void __user *) us_addr,
					CLW_BYTES_PER_BIT))
				return -EFAULT;
		}
	}
	if (us_addr <= us_cl_b) {
		DebugCLW("nothing to clean outside of area covered by bit-mask\n");
		return 0;
	}

	DebugCLW("clean stack area from 0x%lx to 0x%lx, 0x%lx bytes\n",
			us_cl_b + CLW_BYTES_PER_BIT,
			us_addr + CLW_BYTES_PER_BIT, us_addr - us_cl_b);

	if (clw_clear_user(regs, (void __user *) (us_cl_b + CLW_BYTES_PER_BIT),
			us_addr - us_cl_b))
		return -EFAULT;

	return 0;
}
#endif	/* CONFIG_CLW_ENABLE */


/*
 * To increment or decrease user data stack size we need to update
 * data stack size in the USD register and in the chain registers
 * (CR1_hi.ussz field) into all user pt_regs structures of the process
 */
static int fix_all_user_stack_pt_regs(pt_regs_t *regs, e2k_size_t delta_sp,
				      bool incr)
{
	unsigned long ts_flag;
	int ret = 0, regs_num = 0;
	struct pt_regs __user *u_regs;
	e2k_usd_hi_t usd_hi;
	e2k_cr1_hi_t cr1_hi;

	DebugUS("started with pt_regs 0x%px, delta sp 0x%lx, incr %d\n",
		regs, delta_sp, incr);
	BUG_ON(!regs);

	usd_hi = regs->stacks.usd_hi;
	if (incr)
		usd_hi.USD_hi_size += delta_sp;
	else
		usd_hi.USD_hi_size -= delta_sp;
	regs->stacks.usd_hi = usd_hi;

	cr1_hi = regs->crs.cr1_hi;
	if (incr)
		AS(cr1_hi).ussz += (delta_sp >> 4);
	else
		AS(cr1_hi).ussz -= (delta_sp >> 4);
	regs->crs.cr1_hi = cr1_hi;

	++regs_num;

	/*
	 * All other user pt_regs (except current, i.e. thread_info->pt_regs)
	 * are located in current thread's signal stack in userspace.
	 */
	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	signal_pt_regs_for_each(u_regs) {
		ret = __get_user(AW(usd_hi), &AW(u_regs->stacks.usd_hi));
		if (ret)
			break;

		if (incr)
			usd_hi.USD_hi_size += delta_sp;
		else
			usd_hi.USD_hi_size -= delta_sp;

		ret = __put_user(AW(usd_hi), &AW(u_regs->stacks.usd_hi));
		if (ret)
			break;

		ret = __get_user(AW(cr1_hi), &AW(u_regs->crs.cr1_hi));
		if (ret)
			break;

		if (incr)
			AS(cr1_hi).ussz += (delta_sp >> 4);
		else
			AS(cr1_hi).ussz -= (delta_sp >> 4);

		ret = __put_user(AW(cr1_hi), &AW(u_regs->crs.cr1_hi));
		if (ret)
			break;

		++regs_num;
	}
	clear_ts_flag(ts_flag);

	DebugUS("%d pt_regs structures (USD & CR1_hi.ussz) were corrected to decrement user stack sizes\n",
		regs_num);

	return ret;
}


struct update_chain_params {
	unsigned long delta_sp;
	stack_frame_t frames_type;
	unsigned long prev_size;
	unsigned long corrected_size;
	unsigned long prev_frame_addr;
	bool incr;
};

static int update_chain_stack_ussz(e2k_mem_crs_t *frame,
		unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, int flags, void *arg)
{
	struct update_chain_params *params = arg;
	const unsigned long delta_sp = params->delta_sp;
	const stack_frame_t frames_type = params->frames_type;
	const bool incr = params->incr;
	stack_frame_t cur_frame;
	e2k_cr1_hi_t cr1_hi;
	int ret;

	cur_frame = get_stack_frame_type_IP(frame->cr0_hi, frame->cr1_lo, false);
	if (frames_type != cur_frame) {
		/*
		 * It is a kernel function in the user PC stack. The data stack
		 * of this function is out of this stack and places in separate
		 * user or kernel space for each process.
		 * Do not correct this chain register.
		 */
		goto next;
	}

	cr1_hi = frame->cr1_hi;

	if (frames_type == user_frame_type) {
		unsigned long next_size, hw_delta, real_delta;
		int correction;

		params->corrected_size += 0x100000000L *
				getsp_adj_get_correction(corrected_frame_addr);

		next_size = ((u32) AS(cr1_hi).ussz << 4UL) +
				params->corrected_size;
		if (incr)
			next_size += delta_sp;
		else
			next_size -= delta_sp;

		hw_delta = (next_size & 0xffffffffUL) -
			   (params->prev_size & 0xffffffffUL);
		real_delta = next_size - params->prev_size;
		params->prev_size = next_size;

		WARN_ONCE((real_delta - hw_delta) & 0xffffffffUL,
				"Bad data stack parameters");
		correction = (real_delta - hw_delta) >> 32UL;

		ret = getsp_adj_set_correction(correction,
					       corrected_frame_addr);
		if (ret)
			return ret;

		if (correction) {
			e2k_cr1_lo_t prev_cr1_lo;

			if (WARN_ONCE(params->prev_frame_addr == -1UL,
					"trying to apply stack correction to the last frame\n"))
				return -ESRCH;

			if (flags & PCF_FLUSH_NEEDED)
				NATIVE_FLUSHC;
			ret = get_cr1_lo(&prev_cr1_lo,
					 params->prev_frame_addr, 0);
			if (ret)
				return ret;
			AS(prev_cr1_lo).lw = 1;
			if (flags & PCF_FLUSH_NEEDED)
				NATIVE_FLUSHC;
			ret = put_cr1_lo(prev_cr1_lo,
					 params->prev_frame_addr, 0);
			if (ret)
				return ret;
		}
	}


	if (incr)
		cr1_hi.CR1_hi_ussz += (delta_sp >> 4);
	else
		cr1_hi.CR1_hi_ussz -= (delta_sp >> 4);

	if (flags & PCF_FLUSH_NEEDED)
		NATIVE_FLUSHC;
	ret = put_cr1_hi(cr1_hi, real_frame_addr, 0);
	if (ret)
		return ret;

next:
	params->prev_frame_addr = real_frame_addr;

	return 0;
}

static int fix_all_chain_stack_sz(e2k_size_t delta_sp,
			stack_frame_t frames_type, bool incr)
{
	struct update_chain_params params;
	long ret;

	DebugUS("started with PCSP stack base 0x%px, delta sp 0x%lx, incr %d\n",
		CURRENT_PCS_BASE(), delta_sp, incr);

	if (frames_type != user_frame_type)
		return -EINVAL;

	params.delta_sp = delta_sp;
	params.frames_type = frames_type;
	params.prev_size = 0;
	params.corrected_size = 0;
	params.prev_frame_addr = -1UL;
	params.incr = incr;

	ret = parse_chain_stack(PCS_USER, NULL, update_chain_stack_ussz, &params);

	return (IS_ERR_VALUE(ret)) ? ret : 0;
}


/**
 * constrict_user_data_stack - handles user data stack underflow
 * @regs: pointer to pt_regs
 * @incr: value of decrement in bytes
 */
int constrict_user_data_stack(struct pt_regs *regs, unsigned long incr)
{
	thread_info_t	*ti = current_thread_info();
	u64		sp, stack_size;
	int		ret;

	DebugUS("started\n");

	calculate_e2k_dstack_parameters(&regs->stacks, &sp, &stack_size, NULL);

	DebugUS("base 0x%llx, size 0x%llx, top 0x%lx, bottom 0x%lx, max current size 0x%lx\n",
		sp, stack_size, ti->u_stack.top, ti->u_stack.bottom,
		ti->u_stack.size);

	/*
	 * We coudn't detect all underflows, but let's try to do something...
	 */
	if (ti->u_stack.top < sp + incr) {
		pr_info_ratelimited("constrict_user_data_stack(): user data stack underflow\n");
		return -ENOMEM;
	}

	ret = fix_all_user_stack_pt_regs(regs, stack_size, false);
	if (ret)
		return ret;

	if (ret = fix_all_chain_stack_sz(stack_size, user_frame_type, false)) {
		pr_info_ratelimited("constrict_user_data_stack(): could not correct user stack sizes in chain stack: ret %d\n",
				ret);
		return ret;
	}

	return 0;
}

/**
 * expand_user_data_stack - handles user data stack overflow
 * @regs: pointer to pt_regs
 * @incr: value of increment in bytes
 *
 * On e2k stack handling differs from everyone else for two reasons:
 * 1) All data stack memory must be allocated with 'getsp' prior to accessing;
 * 2) Data stack overflows are controlled with special registers which hold
 * stack boundaries.
 *
 * This means that guard page mechanism used for other architectures
 * isn't needed on e2k: all overflows accounting is done by hardware.
 * So we do not need the gap below the stack vma: if an attacker tries
 * to allocate a lot of stack at once in the hope of jumping over the
 * guard page, he will just run into out-of-stack exception.
 *
 * Returns 0 on success.
 */
int expand_user_data_stack(struct pt_regs *regs, unsigned long incr)
{
	thread_info_t *ti = current_thread_info();
	struct mm_struct *mm = current->mm;
	u64 sp, new_bottom, stack_size, new_size;
	struct vm_area_struct *vma, *v, *prev;
	int ret;

	if (usd_cannot_be_expanded(regs)) {
		pr_warning("process %s (%d) local data stack cannot be expanded (size fixed), stack top 0x%lx, bottom 0x%lx, current base 0x%llx, size 0x%x\n",
			current->comm, current->pid,
			ti->u_stack.top, ti->u_stack.bottom,
			regs->stacks.usd_lo.USD_lo_base,
			regs->stacks.usd_hi.USD_hi_size);
		return -EINVAL;
	}

	calculate_e2k_dstack_parameters(&regs->stacks, &sp, &stack_size, NULL);

	DebugUS("base 0x%llx, size 0x%llx, top 0x%lx, bottom 0x%lx, max current size 0x%lx\n",
		sp, stack_size, ti->u_stack.top, ti->u_stack.bottom,
		ti->u_stack.size);

	/*
	 * It can be if signal handler uses alternative stack
	 * and an overflow of this stack occured.
	 *
	 * This check must not return false positive if all of
	 * stack space is used (i.e. top == bottom).
	 */
	if ((sp > ti->u_stack.top || sp < ti->u_stack.bottom) &&
			ti->u_stack.top != ti->u_stack.bottom) {
		if (on_sig_stack(sp)) {
			pr_info_ratelimited("expand_user_data_stack(): alt stack overflow\n");
		} else {
			pr_info_ratelimited("expand_user_data_stack(): SP of user data stack 0x%llx points out of main user stack allocated from bottom 0x%lx to top 0x%lx\n",
				sp, ti->u_stack.bottom, ti->u_stack.top);
		}
		return -ENOMEM;
	}

	incr = min(incr, (rlimit(RLIMIT_STACK) & PAGE_MASK) -
			 (ti->u_stack.top - ti->u_stack.bottom));
	DebugUS("rlim 0x%lx, incr 0x%lx\n", rlimit(RLIMIT_STACK), incr);
	if (!incr)
		return -ENOMEM;

	new_bottom = sp - stack_size - incr;
	new_size = sp - new_bottom;

	/*
	 * While not all cases of stack underflow could be detected, there could
	 * be cases, where new_size > MAX_USD_HI_SIZE. Kernel shouldn't be
	 * broken in this case.
	 */
	if (new_size > MAX_USD_HI_SIZE) {
		pr_info_ratelimited("expand_user_data_stack(): new_size > MAX_USD_HI_SIZE\n");
		return -ENOMEM;
	}

	down_write(&mm->mmap_sem);

	vma = find_extend_vma(mm, new_bottom);
	if (!vma) {
		pr_info_ratelimited("expand_user_data_stack(): user data stack overflow: stack bottom 0x%lx, top 0x%lx, sp 0x%llx, rest free space size 0x%llx\n",
			ti->u_stack.bottom, ti->u_stack.top, sp, stack_size);
		goto error_unlock;
	}

	/* Check that we didn't jump over a hole */
	for (v = vma->vm_next, prev = vma; v && v->vm_end < ti->u_stack.top;
			prev = v, v = v->vm_next) {
		if (unlikely(prev->vm_end != v->vm_start ||
			     ((v->vm_flags ^ prev->vm_flags) & VM_GROWSDOWN))) {
			pr_info_ratelimited("expand_user_data_stack(): jumped over a hole 0x%lx-0x%lx or inconsistent VM_GROWSDOWN flag\n",
					prev->vm_end, v->vm_start);
			goto error_unlock;
		}
	}

	DebugUS("find_extend_vma() returned VMA 0x%px, start 0x%lx, end 0x%lx\n",
		vma, vma->vm_start, vma->vm_end);

	up_write(&mm->mmap_sem);

	/*
	 * Increment user data stack size in the USD register
	 * and in the chain registers (CR1_hi.ussz field)
	 * in all user pt_regs structures of the process.
	 */
	ret = fix_all_user_stack_pt_regs(regs, new_size - stack_size, true);
	if (ret)
		return ret;

	/*
	 * Correct cr1_hi.ussz fields for all functions in the PCSP
	 */
	ret = fix_all_chain_stack_sz(new_size - stack_size, user_frame_type, true);
	if (ret) {
		pr_info_ratelimited("expand_user_data_stack(): could not correct user stack sizes in chain stack: ret %d\n",
			ret);
		return ret;
	}

	/*
	 * Update user data stack current state info
	 */
	ti->u_stack.bottom = new_bottom;
	ti->u_stack.size += new_size - stack_size;

	DebugUS("extended stack: base 0x%llx, size 0x%llx, top 0x%lx, bottom 0x%lx, max current size 0x%lx\n",
		sp, new_size, ti->u_stack.top,
		ti->u_stack.bottom, ti->u_stack.size);

	return 0;

error_unlock:
	up_write(&mm->mmap_sem);

	return -ENOMEM;
}
EXPORT_SYMBOL(expand_user_data_stack);

#ifdef CONFIG_COMPAT
void __user *arch_compat_alloc_user_space(unsigned long len)
{
	struct pt_regs *regs = current_pt_regs();
	u64 sp, free_space;

	calculate_e2k_dstack_parameters(&regs->stacks, &sp, &free_space, NULL);

	if (len > free_space) {
		if (expand_user_data_stack(regs, len - free_space))
			return NULL;
	}

	return (void __user *) (sp - len);
}
#endif

/**
 * remap_e2k_stack - remap stack at the end of user address space
 *
 * It can be either e2k hardware stack (i.e. PSP stack or PCSP stack),
 * or it can be signal stack which is saved in privileged area at the
 * end of user space since it has some privileged structures saved
 * such as trap cellar or CTPRs.
 */
unsigned long remap_e2k_stack(unsigned long addr,
		unsigned long old_size, unsigned long new_size, bool after)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma, *next_vma;
	unsigned long ret, ts_flag, new_addr,
			end = addr + old_size, new_end = addr + new_size;
	struct vm_userfaultfd_ctx uf = NULL_VM_UFFD_CTX;
	LIST_HEAD(uf_unmap_early);
	LIST_HEAD(uf_unmap);
	bool locked = false;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);

	down_write(&mm->mmap_sem);

	/*
	 * Try to expand without remapping
	 */
	vma = find_vma(mm, end - 1);
	BUG_ON(!vma || vma->vm_start > end - 1);
	BUG_ON(vma->vm_flags & (VM_DONTEXPAND | VM_PFNMAP));

	if (vma->vm_end == end &&
	    (!vma->vm_next || vma->vm_next->vm_start >= new_end)) {
		if (!vma_adjust(vma, vma->vm_start, new_end,
				vma->vm_pgoff, NULL)) {
			int pages = (new_size - old_size) >> PAGE_SHIFT;
			/*
			 * Set valid bit on the newly allocated area
			 */
			vma = find_vma(mm, addr + old_size);
			BUG_ON(!vma || vma->vm_start > addr + old_size);
			make_vma_pages_valid(vma, addr + old_size,
					     addr + new_size);

			vm_stat_account(mm, vma->vm_flags, pages);
			if (vma->vm_flags & VM_LOCKED) {
				mm->locked_vm += pages;
				locked = true;
			}

			ret = addr;
			goto out_unlock;
		}
	}

	/*
	 * Remap all vmas
	 */
	new_addr = get_unmapped_area(NULL, (after) ? addr : USER_HW_STACKS_BASE,
			new_size, 0, MAP_PRIVATE | MAP_ANONYMOUS);
	if (IS_ERR_VALUE(new_addr)) {
		ret = new_addr;
		goto out_unlock;
	}

	for (vma = find_vma(mm, addr); vma && vma->vm_start < end;
			vma = next_vma) {
		unsigned long remap_from, remap_to,
				remap_from_size, remap_to_size;

		remap_from = vma->vm_start;
		if (vma->vm_start < addr)
			remap_from = addr;

		remap_from_size = vma->vm_end - remap_from;
		if (vma->vm_end >= end)
			remap_from_size = end - remap_from;

		remap_to = remap_from + new_addr - addr;

		remap_to_size = remap_from_size;
		if (vma->vm_end >= end) {
			remap_to_size = end - remap_from +
					(new_size - old_size);
		}

		next_vma = vma->vm_next;

		DebugHS("mremap_to(): from 0x%lx/0x%lx to 0x%lx/0x%lx\n",
			remap_from, remap_from_size, remap_to, remap_to_size);
		ret = mremap_to(remap_from, remap_from_size,
				remap_to, remap_to_size, &locked,
				&uf, &uf_unmap_early, &uf_unmap);
		if (IS_ERR_VALUE(ret)) {
			do_munmap(mm, new_addr, new_size, &uf_unmap);
			goto out_unlock;
		}
	}

	ret = new_addr;

out_unlock:
	up_write(&mm->mmap_sem);

	if (!IS_ERR_VALUE(ret) && locked)
		mm_populate(ret + old_size, new_size - old_size);

	clear_ts_flag(ts_flag);

	return ret;
}

static unsigned long handle_hardware_stack_overflow(
		struct hw_stack_area *area, bool after, size_t limit)
{
	unsigned long old_size, new_size, old_addr, new_addr;

	/*
	 * Increase size exponentially - needed to make sure we won't
	 * run into the end of virtual memory (because chain stack
	 * can only be remapped to a *higher* address for longjmp to
	 * work, and VM area for hardware stacks is limited in size).
	 */
	old_addr = (unsigned long) area->base;
	old_size = area->size;
	new_size = max(old_size + PAGE_SIZE, old_size * 11 / 8);
	new_size = round_up(new_size, PAGE_SIZE);

	/* Check for rlimit */
	if (new_size > limit) {
		if (old_size >= limit)
			return -ENOMEM;
		new_size = limit;
	}

	new_addr = remap_e2k_stack((u64) area->base, old_size, new_size, after);
	if (IS_ERR_VALUE(new_addr)) {
		return new_addr;
	} else {
		area->base = (void *) new_addr;
		area->size += new_size - old_size;
	}

	return new_addr - old_addr;
}

static int add_user_old_pc_stack_area(struct hw_stack_area *area)
{
	thread_info_t		*ti = current_thread_info();
	struct old_pcs_area	*old_pc;

	old_pc = kmalloc(sizeof(struct old_pcs_area), GFP_KERNEL);
	if (!old_pc)
		return -ENOMEM;

	old_pc->base = area->base;
	old_pc->size = area->size;

	list_add_tail(&old_pc->list_entry, &ti->old_u_pcs_list);

	return 0;
}

void __update_pcsp_regs(unsigned long base, unsigned long size,
			unsigned long new_fp,
			e2k_pcsp_lo_t *pcsp_lo, e2k_pcsp_hi_t *pcsp_hi)
{
	unsigned long new_base, new_top;

	/*
	 * Calculate new %pcsp
	 */
	new_base = max(new_fp - 0x80000000UL, base);
	new_base = round_up(new_base, ALIGN_PCSTACK_SIZE);
	new_top = min(new_fp + 0x80000000UL - 1, base + size);
	new_top = round_down(new_top, ALIGN_PCSTACK_SIZE);

	/*
	 * Important: since saved %pcsp_hi.ind value includes %pcshtp
	 * after this function we must be sure that %pcsp_hi.ind > %pcshtp.
	 * This is achieved automatically by making window as big as possible.
	 */
	AS(*pcsp_lo).base = new_base;
	AS(*pcsp_hi).size = new_top - new_base;
	AS(*pcsp_hi).ind = new_fp - new_base;
}

void update_pcsp_regs(unsigned long new_fp,
		      e2k_pcsp_lo_t *pcsp_lo, e2k_pcsp_hi_t *pcsp_hi)
{
	struct hw_stack_area *pcs = &current_thread_info()->u_hw_stack.pcs;

	__update_pcsp_regs((unsigned long)pcs->base, pcs->size,
				new_fp, pcsp_lo, pcsp_hi);
}

void __update_psp_regs(unsigned long base, unsigned long size,
			unsigned long new_fp,
			e2k_psp_lo_t *psp_lo, e2k_psp_hi_t *psp_hi)
{
	unsigned long new_base, new_top;

	new_base = max(new_fp - 0x80000000UL, base);
	new_base = round_up(new_base, ALIGN_PSTACK_SIZE);
	new_top = min(new_fp + 0x80000000UL - 1, base + size);
	new_top = round_down(new_top, ALIGN_PSTACK_SIZE);

	/*
	 * Important: since saved %psp_hi.ind value includes %pshtp.ind
	 * after this function we must be sure that %psp_hi.ind > %pshtp.ind.
	 * This is achieved automatically by making window as big as possible.
	 */
	AS(*psp_lo).base = new_base;
	AS(*psp_hi).size = new_top - new_base;
	AS(*psp_hi).ind = new_fp - new_base;
}

void update_psp_regs(unsigned long new_fp,
		     e2k_psp_lo_t *psp_lo, e2k_psp_hi_t *psp_hi)
{
	struct hw_stack_area *ps = &current_thread_info()->u_hw_stack.ps;

	__update_psp_regs((unsigned long)ps->base, ps->size,
				new_fp, psp_lo, psp_hi);
}

static void apply_delta_to_cellar(struct trap_pt_regs *trap,
		unsigned long start, unsigned long end, unsigned long delta)
{
	int tc_count, cnt;

	if (!trap)
		return;

	tc_count = trap->tc_count;
	for (cnt = 0; 3 * cnt < tc_count; cnt++) {
		unsigned long address = trap->tcellar[cnt].address;

		/* Hardware stack accesses are aligned */
		if (address >= start && address < end)
			trap->tcellar[cnt].address += delta;
	}
}

static int apply_delta_to_signal_cellar(struct pt_regs __user *u_regs,
		unsigned long start, unsigned long end, unsigned long delta)
{
	struct trap_pt_regs __user *u_trap;
	int tc_count, cnt;

	u_trap = signal_pt_regs_to_trap(u_regs);
	if (IS_ERR_OR_NULL(u_trap))
		return PTR_ERR_OR_ZERO(u_trap);

	if (__get_user(tc_count, &u_trap->tc_count))
		return -EFAULT;

	for (cnt = 0; 3 * cnt < tc_count; cnt++) {
		unsigned long address;

		if (__get_user(address, &u_trap->tcellar[cnt].address))
			return -EFAULT;

		/* Hardware stack accesses are aligned */
		if (address >= start && address < end) {
			if (__put_user(address + delta,
				       &u_trap->tcellar[cnt].address))
				return -EFAULT;
		}
	}

	return 0;
}

int apply_psp_delta_to_signal_stack(unsigned long base, unsigned long size,
		unsigned long start, unsigned long end, unsigned long delta)
{
	struct pt_regs __user *u_regs;
	unsigned long ts_flag;
	int ret = 0;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	signal_pt_regs_for_each(u_regs) {
		unsigned long new_fp;
		e2k_psp_lo_t psp_lo;
		e2k_psp_hi_t psp_hi;

		if (delta != 0) {
			ret = apply_delta_to_signal_cellar(u_regs, start, end,
								delta);
			if (ret)
				break;
		}

		ret = __get_user(AW(psp_lo), &AW(u_regs->stacks.psp_lo));
		ret = (ret) ?: __get_user(AW(psp_hi),
					  &AW(u_regs->stacks.psp_hi));
		if (ret)
			break;

		DebugHS("adding delta 0x%lx to signal PSP 0x%llx:0x%llx\n",
				delta, AW(psp_lo), AW(psp_hi));
		new_fp = AS(psp_lo).base + AS(psp_hi).ind + delta;
		__update_psp_regs(base, size, new_fp, &psp_lo, &psp_hi);

		ret = __put_user(AW(psp_hi), &AW(u_regs->stacks.psp_hi));
		ret = (ret) ?: __put_user(AW(psp_lo),
					  &AW(u_regs->stacks.psp_lo));
		if (ret)
			break;
	}
	clear_ts_flag(ts_flag);

	return ret;
}

int apply_pcsp_delta_to_signal_stack(unsigned long base, unsigned long size,
		unsigned long start, unsigned long end, unsigned long delta)
{
	struct pt_regs __user *u_regs;
	unsigned long ts_flag;
	int ret = 0;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	signal_pt_regs_for_each(u_regs) {
		unsigned long new_fp;
		e2k_pcsp_lo_t pcsp_lo;
		e2k_pcsp_hi_t pcsp_hi;

		if (delta != 0) {
			ret = apply_delta_to_signal_cellar(u_regs, start, end,
								delta);
			if (ret)
				break;
		}

		ret = __get_user(AW(pcsp_lo), &AW(u_regs->stacks.pcsp_lo));
		ret = (ret) ?: __get_user(AW(pcsp_hi),
					  &AW(u_regs->stacks.pcsp_hi));
		if (ret)
			break;

		DebugHS("adding delta 0x%lx to signal PCSP 0x%llx:0x%llx\n",
				delta, AW(pcsp_lo), AW(pcsp_hi));
		new_fp = AS(pcsp_lo).base + AS(pcsp_hi).ind + delta;
		__update_pcsp_regs(base, size, new_fp, &pcsp_lo, &pcsp_hi);

		ret = __put_user(AW(pcsp_hi), &AW(u_regs->stacks.pcsp_hi));
		ret = (ret) ?: __put_user(AW(pcsp_lo),
					  &AW(u_regs->stacks.pcsp_lo));
		if (ret)
			break;
	}
	clear_ts_flag(ts_flag);

	return ret;
}

/*
 * The function handles traps on hardware procedure stack overflow or
 * underflow. If stack overflow occured then the procedure stack will be
 * expanded. In the case of stack underflow it will be constricted
 */
int handle_proc_stack_bounds(struct e2k_stacks *stacks,
		struct trap_pt_regs *trap)
{
	hw_stack_t *u_hw_stack = &current_thread_info()->u_hw_stack;
	e2k_psp_lo_t psp_lo = stacks->psp_lo;
	e2k_psp_hi_t psp_hi = stacks->psp_hi;
	unsigned long delta, fp, real_base, real_top;
	int ret;

	fp = AS(psp_lo).base + AS(psp_hi).ind;
	real_base = (unsigned long) u_hw_stack->ps.base;
	real_top = real_base + u_hw_stack->ps.size;

	if (AS(psp_hi).ind <= AS(psp_hi).size / 2) {
		/* Underflow - check if we've hit the stack bottom */
		if (AS(psp_lo).base <= real_base)
			return -ENOMEM;
	} else if (AS(psp_lo).base + AS(psp_hi).size >= real_top) {
		struct hw_stack_area *ps;

		/* Overflow & we've hit the stack top */
		delta = handle_hardware_stack_overflow(&u_hw_stack->ps, false,
				current->signal->rlim[RLIMIT_P_STACK_EXT].rlim_cur);
		if (IS_ERR_VALUE(delta))
			return delta;

		ps = &current_thread_info()->u_hw_stack.ps;
		if (delta) {
			apply_delta_to_cellar(trap, real_base, real_top, delta);

			ret = apply_psp_delta_to_signal_stack(
					(unsigned long)ps->base, ps->size,
					real_base, real_top, delta);
			if (ret)
				return ret;
		}

		/*
		 * The follow call is actual only for paravirtualized
		 * guest to correct signal stack on host
		 */
		ret = host_apply_psp_delta_to_signal_stack(
				(unsigned long)ps->base, ps->size,
				real_base, real_top, delta);
		if (ret)
			return ret;

		fp += delta;
	}

	update_psp_regs(fp, &stacks->psp_lo, &stacks->psp_hi);

	return 0;
}

/*
 * The function handles traps on hardware procedure chain stack overflow or
 * underflow. If stack overflow occured then the procedure chaine stack will
 * be expanded. In the case of stack underflow it will be constricted
 */
int handle_chain_stack_bounds(struct e2k_stacks *stacks,
		struct trap_pt_regs *trap)
{
	hw_stack_t *u_hw_stack = &current_thread_info()->u_hw_stack;
	e2k_pcsp_lo_t pcsp_lo = stacks->pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi = stacks->pcsp_hi;
	unsigned long delta, fp, real_base, real_top;
	int ret;

	fp = AS(pcsp_lo).base + AS(pcsp_hi).ind;
	real_base = (unsigned long) u_hw_stack->pcs.base;
	real_top = real_base + u_hw_stack->pcs.size;

	if (AS(pcsp_hi).ind <= AS(pcsp_hi).size / 2) {
		/* Underflow - check if we've hit the stack bottom */
		if (AS(pcsp_lo).base <= real_base)
			return -ENOMEM;
	} else if (AS(pcsp_lo).base + AS(pcsp_hi).size >= real_top) {
		struct hw_stack_area *pcs;

		/* Overflow & we've hit the stack top */
		hw_stack_area_t	old_pcs_area = u_hw_stack->pcs;

		delta = handle_hardware_stack_overflow(&u_hw_stack->pcs, true,
				current->signal->rlim[RLIMIT_PC_STACK_EXT].rlim_cur);
		if (IS_ERR_VALUE(delta))
			return delta;

		pcs = &current_thread_info()->u_hw_stack.pcs;
		if (delta) {
			add_user_old_pc_stack_area(&old_pcs_area);

			apply_delta_to_cellar(trap, real_base, real_top, delta);

			ret = apply_pcsp_delta_to_signal_stack(
					(unsigned long)pcs->base, pcs->size,
					real_base, real_top, delta);
			if (ret)
				return ret;
		}

		/*
		 * The follow call is actual only for paravirtualized
		 * guest to correct signal stack on host
		 */
		ret = host_apply_pcsp_delta_to_signal_stack(
				(unsigned long)pcs->base, pcs->size,
				real_base, real_top, delta);
		if (ret)
			return ret;

		fp += delta;
	}

	update_pcsp_regs(fp, &stacks->pcsp_lo, &stacks->pcsp_hi);

	return 0;
}

static void print_pagefault_info(struct trap_pt_regs *trap, e2k_addr_t address,
				 bool debug_mode, bool stack)
{
	struct mm_struct *mm = current->mm;

	if (mm == NULL)
		mm = &init_mm;

	/* if this is guest, stop tracing in host to avoid buffer overwrite */
	host_ftrace_stop();

	print_all_TIRs(trap->TIRs, trap->nr_TIRs);
	print_all_TC(trap->tcellar, trap->tc_count);
	print_mmap(current);
	DebugPF("MMU_ADDR_CONT = 0x%llx\n", read_MMU_reg(MMU_ADDR_CONT));

	if (debug_mode)
		print_address_tlb(address);
	print_address_page_tables(address, !debug_mode);

	if (trap->nr_page_fault_exc == exc_instr_page_miss_num ||
	    trap->nr_page_fault_exc == exc_instr_page_prot_num) {
		unsigned long instruction_end_page =
			round_down(address + E2K_INSTR_MAX_SIZE - 1, PAGE_SIZE);

		if (instruction_end_page != round_down(address, PAGE_SIZE)) {
			if (debug_mode)
				print_address_tlb(instruction_end_page);
			print_address_page_tables(instruction_end_page,
						  !debug_mode);
		}
	}

	if (stack)
		dump_stack();
}

static inline void debug_print_trap_cellar(const trap_cellar_t *tcellar,
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

static inline unsigned long get_fault_ip(struct pt_regs *regs)
{
	e2k_tir_lo_t tir_lo;

	tir_lo.TIR_lo_reg = regs->trap->TIR_lo;
	return tir_lo.TIR_lo_ip;
}

static inline int
copy_nested_tc_records(struct pt_regs *regs,
		trap_cellar_t *tcellar, unsigned int tc_count)
{
	struct pt_regs		*pregs = regs->next;
	struct trap_pt_regs	*ptrap = pregs->trap;
	tc_cond_t		*pcond, *cond;
	int			i, skip;

	DbgTC("nested exception detected\n");

	if (unlikely(!ptrap))
		panic("do_trap_cellar() previous pt_regs are not from trap\n");

	if (unlikely(!user_mode(pregs) &&
			!current_thread_info()->usr_pfault_jump &&
			!search_exception_tables(get_fault_ip(pregs))))
		panic("do_trap_cellar() previous pt_regs are not user's\n");

	/*
	 * We suppose that there could be only one record in
	 * trap cellar because of nested exception in
	 * execute_mmu_operations() plus there could be few
	 * spill/fill records. Other records aren't allowed.
	 * 
	 * Also allow two records for quadro format.
	 */
	skip = 1;
#pragma loop count (1)
	for (i = 1; (3 * i) < tc_count; i++) {
		tc_cond_t cond = tcellar[i].condition;
		int fmt = TC_COND_FMT_FULL(cond);

		if (AS(cond).s_f)
			continue;

		if (i == 1 && (fmt == LDST_QWORD_FMT ||
			       fmt == TC_FMT_QWORD_QP)) {
			++skip;
			continue;
		}

		print_all_TC(tcellar, tc_count);
		panic("do_trap_cellar() invalid trap cellar content\n");
	}

	/* Modify fault_type */
	cond = &tcellar[0].condition;
	pcond = &ptrap->tcellar[ptrap->curr_cnt].condition;
	AS(*pcond).fault_type = AS(*cond).fault_type;

	ptrap->tcellar[ptrap->curr_cnt].flags |= TC_NESTED_EXC_FLAG;

	return skip;
}

/*
 * abn abp instructions changed fields for RPR
 * we must restore old values for this fields
 */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT

/* see iset 5.4. (PR) */
#define  get_predicate_val(x, N) (((x) >> ((N) * 2)) & 0x1)

/* see iset C.17.1.2. */
static int
calculate_ct_operation(u64 lsr, instr_ss_t instr, u64 pf)
{
	int value;
	e2k_ct_t ct_op;
	e2k_lsr_t Lsr;

	AW(Lsr) = lsr;
	AW(ct_op) = instr.ctcond;
	switch (CT_CT(ct_op)) {
	case 0:
		value = 0;
		break;
	case 1:
		value = 1;
		break;
	case 2:
		value = get_predicate_val(pf, CT_PSRC(ct_op));
		break;
	case 3:
		value = !get_predicate_val(pf, CT_PSRC(ct_op));
		break;
	case 4:
		value = ls_loop_end(Lsr);
		break;
	case 5:
		value = !ls_loop_end(Lsr);
		break;
	case 6:
		value = ((Lsr.fields.semc || !ls_prlg(Lsr)) &&
			get_predicate_val(pf, CT_PSRC(ct_op))) ||
			ls_loop_end(Lsr);
		break;
	case 7:
		value = !(((Lsr.fields.semc || !ls_prlg(Lsr)) &&
			get_predicate_val(pf, CT_PSRC(ct_op))) ||
			ls_loop_end(Lsr));
		break;
	case 8: /* must be changed !!! */
		value = ((!(Lsr.fields.semc || !ls_prlg(Lsr)) &&
			get_predicate_val(pf, CT_PSRC(ct_op))) ||
			ls_loop_end(Lsr));
		break;
	case 14:
		value = (((Lsr.fields.semc || !ls_prlg(Lsr)) &&
			!get_predicate_val(pf, CT_PSRC(ct_op))) ||
			ls_loop_end(Lsr));
		break;
	case 15:
		value = !(((Lsr.fields.semc || !ls_prlg(Lsr)) &&
			!get_predicate_val(pf, CT_PSRC(ct_op))) ||
			ls_loop_end(Lsr));
		break;
	default:
		value = 0;
		pr_info("calculate_ct_operation  bad ct_op = %d CT_PSRC =%d\n",
			CT_CT(ct_op), CT_PSRC(ct_op));
		break;
	}
	return 0;
}

static void
calculate_new_rpr(struct pt_regs *regs, e2k_addr_t ip, int stp)
{
	instr_hs_t  hs;
	instr_ss_t  ss;
	e2k_rpr_lo_t rpr_lo;
	e2k_rpr_hi_t rpr_hi;

	/*
	 * calculate new value of RPR
	 */
	AW(rpr_lo) = 0;
	RPR_STP(rpr_lo) = stp;
	RPR_IP(rpr_lo) = ip;
	WRITE_RPR_LO_REG(rpr_lo);

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
	if (ss.abn || ss.abp) {
		if (calculate_ct_operation(regs->lsr, ss,
				AW(regs->crs.cr0_lo))) {
			rpr_hi = READ_RPR_HI_REG();
			RPR_BR_CUR(rpr_hi)++;
			RPR_BR_PCUR(rpr_hi)++;
			WRITE_RPR_HI_REG(rpr_hi);
		}
	}
}
#endif

static int adjust_psp_regs(struct pt_regs *regs, s64 delta)
{
	e2k_psp_lo_t u_psp_lo = regs->stacks.psp_lo;
	e2k_psp_hi_t u_psp_hi = regs->stacks.psp_hi;

	AS(u_psp_hi).ind -= GET_PSHTP_MEM_INDEX(regs->stacks.pshtp);

	return copy_user_to_current_hw_stack(
			(void *) AS(current_thread_info()->k_psp_lo).base,
			(void *) AS(u_psp_lo).base + AS(u_psp_hi).ind,
			delta, regs, false);
}

static int adjust_pcsp_regs(struct pt_regs *regs, s64 delta)
{
	e2k_pcsp_lo_t u_pcsp_lo = regs->stacks.pcsp_lo;
	e2k_pcsp_hi_t u_pcsp_hi = regs->stacks.pcsp_hi;

	AS(u_pcsp_hi).ind -= PCSHTP_SIGN_EXTEND(regs->stacks.pcshtp);

	return copy_user_to_current_hw_stack(
			(void *) AS(current_thread_info()->k_pcsp_lo).base,
			(void *) AS(u_pcsp_lo).base + AS(u_pcsp_hi).ind,
			delta, regs, true);
}

s64 calculate_fill_delta_psp(struct pt_regs *regs, struct trap_pt_regs *trap,
			     trap_cellar_t *tcellar)
{
	e2k_psp_lo_t psp_lo = regs->stacks.psp_lo;
	e2k_psp_hi_t psp_hi = regs->stacks.psp_hi;
	unsigned long max_addr = 0;
	int i = 0;
	s64 delta;

	AS(psp_hi).ind -= GET_PSHTP_MEM_INDEX(regs->stacks.pshtp);

	for (; i < trap->tc_count / 3; i++) {
		tc_cond_t condition = tcellar[i].condition;
		unsigned long address = tcellar[i].address;

		if (!AS(condition).s_f && !IS_SPILL(tcellar[i]) ||
				AS(condition).store || AS(condition).sru)
			continue;

		max_addr = max(address, max_addr);
	}

	max_addr -= max_addr % 32;
	delta = max_addr - (AS(psp_lo).base + AS(psp_hi).ind) + 32;

	return delta;
}

static int handle_spill_fill(struct pt_regs *regs, trap_cellar_t *tcellar,
		unsigned int cnt, s64 *last_store, s64 *last_load)
{
	struct trap_pt_regs *trap = regs->trap;
	unsigned long address = tcellar[cnt].address;
	tc_cond_t condition = tcellar[cnt].condition;
	tc_mask_t mask = tcellar[cnt].mask;
	unsigned long ts_flag;
	bool call_pf = true;
	int ret;

	/* Optimization: handle each SPILL and each FILL exactly once */
	if (kvm_test_intc_emul_flag(regs)) {
		call_pf = false;
	} else if (tcellar[cnt].flags & TC_NESTED_EXC_FLAG) {
		call_pf = true;
	} else if (AS(condition).store) {
		if (*last_store != -1 && round_down(address, PAGE_SIZE) ==
		    round_down(tcellar[*last_store].address, PAGE_SIZE))
			call_pf = false;
	} else {
		if (*last_load != -1 && round_down(address, PAGE_SIZE) ==
		    round_down(tcellar[*last_load].address, PAGE_SIZE))
			call_pf = false;
	}

	if (call_pf) {
		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		ret = do_page_fault(regs, address, condition, mask, 0);
		clear_ts_flag(ts_flag);
		if (ret != PFR_SUCCESS)
			goto fail_sigsegv;

		if (AS(condition).store)
			*last_store = cnt;
		else
			*last_load = cnt;
	} else {
		if (kvm_test_intc_emul_flag(regs)) {
			if (AS(condition).store)
				*last_store = cnt;
			else
				*last_load = cnt;
		}
		ret = PFR_SUCCESS;
	}

	/*
	 * For SPILL execute_mmu_operations() will repeat interrupted stores
	 */
	if (AS(condition).store)
		return ret;

	/*
	 * For FILL we must adjust %pshtp/%pcshtp so that
	 * hardware repeats the loads.
	 *
	 * Also make sure that %pshtp/%pcshtp are adjusted only
	 * once across all the requests in the trap cellar.
	 */
	if (AS(condition).sru && !(trap->flags & TRAP_PCSP_FILL_ADJUSTED)) {
		if (adjust_pcsp_regs(regs, 32))
			goto fail_sigsegv;

		trap->flags |= TRAP_PCSP_FILL_ADJUSTED;
	} else if (!AS(condition).sru &&
			!(trap->flags & TRAP_PSP_FILL_ADJUSTED)) {
		s64 delta = calculate_fill_delta_psp(regs, trap, tcellar);

		if (adjust_psp_regs(regs, delta))
			goto fail_sigsegv;

		trap->flags |= TRAP_PSP_FILL_ADJUSTED;
	}

	/*
	 * We have adjusted pt_regs so that hardware will
	 * repeat interrupted FILL, no need to repeat in software.
	 */
	return PFR_IGNORE;

fail_sigsegv:
	/*
	 * After failed SPILL/FILL we cannot return to user
	 * so use force_sigsegv() to exit gracefully.
	 */
	force_sigsegv(SIGSEGV);

	return PFR_SIGPENDING;
}

void do_trap_cellar(struct pt_regs *regs, int only_system_tc)
{
	struct trap_pt_regs	*trap = regs->trap;
	trap_cellar_t		*tcellar = trap->tcellar;
	unsigned int		tc_count, cnt;
	tc_fault_type_t 	ftype;
	int			chan, rval = 0;
	/* flag of global_sp operations */
	int			gsp_flag;
	/* number of global_sp records */
	int			global_sp_num;
	int			ignore_request = 0;
	int			skip = 0;
	unsigned long		to_complete = 0;
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

	DbgTC("tick %lld CPU #%ld trap cellar regs addr 0x%px\n",
		READ_CLKR_REG(), (long)raw_smp_processor_id(), tcellar);
	DbgTC("regs->CR0.hi ip 0x%lx user_mode %d\n",
		(long)AS_STRUCT(regs->crs.cr0_hi).ip << 3,
		trap_from_user(regs));

	tc_count = trap->tc_count;

	if (trap->curr_cnt == -1) {
		e2k_tir_lo_t	tir_lo;
		struct pt_regs	*prev_regs = regs->next;

		if (trace_trap_cellar_enabled()) {
			int cnt;

			for (cnt = 0; (3 * cnt) < tc_count; cnt++)
				trace_trap_cellar(&tcellar[cnt], cnt);
		}

		debug_print_trap_cellar(tcellar, tc_count);

		/*
		 * Check if we are in the nested exception that appeared while
		 * executing execute_mmu_operations()
		 */
		if (unlikely(prev_regs && prev_regs->flags.exec_mmu_op)) {
			/*
			 * We suppose that spill/fill records are placed at the
			 * end of trap cellar so skip at the beginning.
			 */
			skip = copy_nested_tc_records(regs, tcellar, tc_count);

			/*
			 * Nested exc_data_page or exc_mem_lock appeared, so
			 * one needs to tell execute_mmu_operations() about it.
			 * execute_mmu_operations() will return EXEC_MMU_REPEAT
			 * in this case. do_trap_cellar() will analyze this
			 * returned value and repeat execution of current
			 * record with modified data.
			 */
			prev_regs->flags.exec_mmu_op_nested = 1;
		}

		trap->curr_cnt = skip;

		if (unlikely(GET_CLW_REQUEST_COUNT(regs))) {
			int clw_first = GET_CLW_FIRST_REQUEST(regs);
			
			DebugCLW("Detected CLW %d request(s)\n",
				GET_CLW_REQUEST_COUNT(regs));
			if (DEBUG_CLW_FAULT) {
				for (cnt = 0; (3 * cnt) < tc_count; cnt++) {
					AW(ftype) = AS(tcellar[cnt].condition).
								fault_type;
					chan = AS(tcellar[cnt].condition).chan;
					pr_info("do_trap_cellar: cnt %d "
						"add 0x%lx ftype %x "
						"chan 0x%x\n",
						cnt, tcellar[cnt].address,
						AW(ftype), chan);
					PrintTC(&tcellar[cnt], cnt);
				}
			}
			AW(ftype) = AS(tcellar[clw_first].condition).
								fault_type;
			if (AW(ftype) != 0) {
				unsigned long handled;

				DebugCLW("starts do_page_fault() for first "
					"CLW request #%d\n",
					clw_first);
				handled = pass_clw_fault_to_guest(regs,
							&tcellar[clw_first]);
				if (!handled) {
					rval = do_page_fault(regs,
						tcellar[clw_first].address,
						tcellar[clw_first].condition,
						tcellar[clw_first].mask,
						false	/* instr page */);
					if (rval == PFR_SIGPENDING) {
						DebugCLW("BAD CLW AREA\n");
						return;
					}
				}
			}
			terminate_CLW_operation(regs);
		}

		if (TASK_IS_BINCO(current))
			srp_flag = READ_RPR_HI_REG_VALUE() >> 63 & 1;
		if (srp_flag)
			trap->flags |= TRAP_SRP_FLAG;
		else
			trap->flags &= ~TRAP_SRP_FLAG;

		/*
		 * One should save srp_ip, because trap->TIR_lo could be
		 * differed from current, when do_trap_cellar() is called from
		 * do_sigreturn().
		 */
		tir_lo.TIR_lo_reg = trap->TIR_lo;
		srp_ip = tir_lo.TIR_lo_ip;
		trap->srp_ip = srp_ip;
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
		srp_flag = trap->flags & TRAP_SRP_FLAG;
		srp_ip = trap->srp_ip;
	}

	global_sp_num = 0;
	gsp_flag = 0;	/* clear the flag before the loop */

#pragma loop count (1)
	for (cnt = trap->curr_cnt; (3 * cnt) < tc_count;
			cnt++, trap->curr_cnt++) {
		unsigned long pass_result;
		unsigned long handled;
		trap_cellar_t *next_tcellar;

		if (tcellar[cnt].flags & TC_DONE_FLAG)
			continue;

		next_tcellar = NULL;
		if ((3 * (cnt + 1)) < tc_count)
			next_tcellar = &tcellar[cnt + 1];

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
retry_guest_kernel:
		pass_result = pass_page_fault_to_guest(regs, &tcellar[cnt]);
		to_complete |= KVM_GET_NEED_COMPLETE_PF(pass_result);
		if (likely(KVM_IS_NOT_GUEST_TRAP(pass_result))) {
			/* trap is not due to guest and should be handled */
			/* in the regular mode */
			;
		} else if (KVM_IS_TRAP_PASSED(pass_result)) {
			DebugKVMPF("request #%d is passed to "
				"guest: address 0x%lx condition 0x%016llx\n",
				cnt, tcellar[cnt].address,
				AW(tcellar[cnt].condition));
			goto continue_passed;
		} else if (KVM_IS_GUEST_KERNEL_ADDR_PF(pass_result)) {
			DebugKVMPF("request #%d guest kernel "
				"address 0x%lx handled by host\n",
				cnt, tcellar[cnt].address);
			rval = PFR_KVM_KERNEL_ADDRESS;
			goto handled;
		} else if (KVM_IS_SHADOW_PT_PROT_PF(pass_result)) {
			DebugKVMPF("request #%d is guest access to protected "
				"shadow PT: address 0x%lx\n",
				cnt, tcellar[cnt].address);
			goto continue_passed;
		} else if (KVM_IS_ERROR_RESULT_PF(pass_result)) {
			union pf_mode mode;

			DebugKVMPF("request #%d failed: address 0x%lx "
				"error %ld\n",
				cnt, tcellar[cnt].address,
				(long)pass_result);
			mode.word = 0;
			rval = pf_force_sig_info(SIGBUS, BUS_ADRERR,
					tcellar[cnt].address, regs);
			goto handled;
		} else {
			BUG_ON(true);
		}
		/* Probably it is KVM MMIO request (only on guest). */
		/* Handle same fault here to do not call slow path of */
		/* page fault handler (do_page_fault() ... */
		handled = mmio_page_fault(regs, &tcellar[cnt]);
		if (handled) {
			DbgTC("do_trap_cellar: request #%d was KVM MMIO guest "
				"request, handled for address 0x%lx\n",
				cnt, tcellar[cnt].address);
			goto continue_passed;
		}

repeat:
		store_flag = 0;
		rpr_srp_flag = 0;

		AW(ftype) = AS(tcellar[cnt].condition).fault_type;

		DbgTC("ftype == %x address %lx\n",
			AW(ftype), tcellar[cnt].address);

		ignore_request = 0;

		if (AS(tcellar[cnt].condition).clw) {
			DbgTC("found CLW request in : trap cellar ,cnt %d\n",
				cnt);
			ignore_request = 1;
			rval = PFR_IGNORE;
		} else if (AS(tcellar[cnt].condition).s_f ||
				IS_SPILL(tcellar[cnt])) {
			rval = handle_spill_fill(regs, tcellar, cnt,
						 &last_store, &last_load);
		} else if (AS(tcellar[cnt].condition).sru &&
			   !AS(tcellar[cnt].condition).s_f &&
			   !AS(tcellar[cnt].condition).store) {
			/* This is hardware load from CU table, mark it
			 * as having permission to access privileged area */
			unsigned long ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
			rval = do_page_fault(regs, tcellar[cnt].address,
					tcellar[cnt].condition,
					tcellar[cnt].mask, 0);
			clear_ts_flag(ts_flag);
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
					tcellar[cnt].condition,
					tcellar[cnt].mask, 0);
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
						tcellar[cnt].condition,
						tcellar[cnt].mask, 0);

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

handled:
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
						next_tcellar, regs, 1, 0, NULL, NULL);

			/* No need to execute the following user loads/stores */
			trap->ignore_user_tc = true;
			break;
		case PFR_SUCCESS:
			/* check if the position is valid */
			if (AS(ftype).global_sp || global_sp_num == 1) {
				global_sp_num++;
				DbgTC("Store local to global #%d\n",
				      global_sp_num);
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
				/*
				 * ASSERT: should be only one request
				 * with global SP (2 records in the TC)
				 */
				BUG_ON(global_sp_num > 2);

				if (global_sp_num == 1) {
					if (3 * (cnt + 1) >= tc_count)
						panic("do_trap_cellar: only one record for global SP in the TC (should be two)");
#ifdef CONFIG_PROTECTED_MODE
					/* do nothing on the second pass */
					gsp_flag = do_global_sp(
							regs, &tcellar[cnt]);
#endif /* CONFIG_PROTECTED_MODE */
				}
			}
			if (AS(tcellar[cnt].condition).sru &&
					!AS(tcellar[cnt].condition).s_f &&
					!IS_SPILL(tcellar[cnt])) {
				DbgTC("page fault on CU upload"
					" condition: 0x%llx\n",
					AW(tcellar[cnt].condition));
			} else if (!gsp_flag && !ignore_request) {
				e2k_addr_t addr;
				rval = execute_mmu_operations(&tcellar[cnt],
						next_tcellar, regs, 0,
						&addr, NULL, NULL);

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
				DbgTC("execute_mmu_operations() finished for cnt %d rval %d addr=%lx\n",
					cnt, rval, addr);
				if (rval == EXEC_MMU_STOP) {
					goto out;
				} else if (rval == EXEC_MMU_REPEAT) {
					goto repeat;
				}
			}
			break;
		case PFR_KERNEL_ADDRESS:
			if (ignore_request)
				break;

			DbgTC("kernel address has been detected in Trap Cellar for cnt %d\n",
					cnt);
			rval = execute_mmu_operations(&tcellar[cnt],
					next_tcellar, regs, 0, 0, NULL, NULL);
			DbgTC("execute_mmu_operations() finished for kernel addr 0x%lx cnt %d rval %d\n",
				tcellar[cnt].address, cnt, rval);
			if (rval == EXEC_MMU_STOP) {
				goto out;
			} else if (rval == EXEC_MMU_REPEAT) {
				goto repeat;
			}
			break;
		case PFR_KVM_KERNEL_ADDRESS: {
			e2k_addr_t addr;
			if (AS(tcellar[cnt].condition).s_f ||
					IS_SPILL(tcellar[cnt])) {
				/* it is hardware stacks fill operation */
				/* and fill will be repeated by hardware */
				rval = handle_spill_fill(regs, tcellar, cnt,
						&last_store, &last_load);
				goto handled;
			} else {
				rval = execute_mmu_operations(&tcellar[cnt],
						next_tcellar, regs, 0,
						&addr, NULL, NULL);
			}

			DebugKVMPF("execute_mmu_operations() finished for cnt %d rval %d addr=%lx\n",
				cnt, rval, addr);
			if (rval == EXEC_MMU_STOP) {
				goto out;
			} else if (rval == EXEC_MMU_REPEAT) {
				DebugKVMPF("%s(): execute_mmu_operations() could not recover KVM guest kernel faulted operation, retry\n",
					__func__);
				goto retry_guest_kernel;
			}
			break;
		}
		case PFR_IGNORE:
			DbgTC("ignore request in trap cellar and do not start execute_mmu_operations for cnt %d\n",
				cnt);
			break;
		default:
			panic("Unknown do_page_fault return value %d\n", rval);
		}

		/* Do not update RPR when nested exception occured. */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
		if (srp_flag && store_flag && !(trap->flags & TRAP_RP_FLAG))
			calculate_new_rpr(regs, srp_ip, rpr_srp_flag);
#endif

		trap->from_sigreturn = 0;

continue_passed:
		tcellar[cnt].flags |= TC_DONE_FLAG;
	}

out:
	if (only_system_tc)
		trap->curr_cnt = skip;
	if (to_complete != 0)
		complete_page_fault_to_guest(to_complete);
}

static inline int is_spec_load_fault(union pf_mode mode)
{
	return mode.spec && !mode.write;
}

/*
 * Is the operation a semi-speculative load? If yes, the address
 * could be any value. Ignore this record. The needed diagnostic
 * value has been written to the register by hardware.
 */
static int handle_spec_load_fault(unsigned long address, struct pt_regs *regs,
		union pf_mode mode)
{
	if (!is_spec_load_fault(mode))
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
		pr_notice("PAGE FAULT. ignore invalid LOAD address 0x%lx in speculative mode: IP=%px %s(pid=%d)\n",
			address, (void *) GET_IP, current->comm, current->pid);

	return 1;
}

/*
 * Are we prepared to handle this kernel fault?
 */
static int fixup_exception(struct pt_regs *regs)
{
	const struct exception_table_entry *fixup;
	unsigned long ip, new_ip;

	ip = get_fault_ip(regs);

	/* get_user/put_user case: */
	fixup = search_exception_tables(ip);
	if (fixup) {
		new_ip = fixup->fixup;

		correct_trap_return_ip(regs, new_ip);
		return PFR_CONTROLLED_ACCESS;
	}

	/* All user accesses besides get_user/put_user and wtrap: */
	if (current_thread_info()->usr_pfault_jump) {
		new_ip = current_thread_info()->usr_pfault_jump;
		correct_trap_return_ip(regs, new_ip);

		/* Controlled access from kernel to user space,
		 * just invalidate diagnostic tag in reg if load. */
		current_thread_info()->usr_pfault_jump = 0;

		return PFR_CONTROLLED_ACCESS;
	}

	return 0;
}

static int no_context(unsigned long address, struct pt_regs *regs,
		      union pf_mode mode)
{
	if (fixup_exception(regs))
		return PFR_CONTROLLED_ACCESS;

	/*
	 * Kernel should not use semi-speculative mode
	 * so we check only user accesses.
	 */
	if (mode.user && handle_spec_load_fault(address, regs, mode))
		return PFR_IGNORE;

	print_pagefault_info(regs->trap, address, DEBUG_PF_MODE, false);

	/*
	 *  Oops. The kernel tried to access some bad page.
	 */
	if (current->pid <= 1)
		panic("do_page_fault: no_context on pid %d so will be recursive traps. IP = 0x%lx\n",
				current->pid, get_fault_ip(regs));

	panic("do_page_fault: no_context for address %lx from IP = %lx\n",
			address, get_fault_ip(regs));
}

static int vmalloc_fault(unsigned long address, struct pt_regs *regs,
			 tc_fault_type_t ftype, union pf_mode mode)
{
	pr_alert("Unexpected fault for kernel address 0x%lx from VMALLOC area ( >= 0x%lx < 0x%lx)\n",
			address, VMALLOC_START, VMALLOC_END);
	print_address_ptes(pgd_offset_k(address), address, 1);
	print_kernel_address_all_nodes_ptes(address);
	BUG();
}

/*
 * Print out info about fatal segfaults, if the show_unhandled_signals
 * sysctl is set:
 */
static inline void
show_signal_msg(struct pt_regs *regs, unsigned long address,
		struct task_struct *tsk)
{
	void		*cr_ip, *tir_ip;

	if (!unhandled_signal(tsk, SIGSEGV))
		return;

	if (!printk_ratelimit())
		return;

	tir_ip = (void *)get_fault_ip(regs);
	cr_ip = (void *)GET_IP_CR0_HI(regs->crs.cr0_hi);

	if (tir_ip == cr_ip)
		printk("%s%s[%d]: segfault at %lx ip %px",
			task_pid_nr(tsk) > 1 ? KERN_INFO : KERN_EMERG,
			tsk->comm, task_pid_nr(tsk), address, tir_ip);
	else
		printk("%s%s[%d]: segfault at %lx ip %px interrupt ip %px",
			task_pid_nr(tsk) > 1 ? KERN_INFO : KERN_EMERG,
			tsk->comm, task_pid_nr(tsk), address, tir_ip, cr_ip);

	print_vma_addr(KERN_CONT " in ", (unsigned long)tir_ip);

	printk(KERN_CONT "\n");
}

static int pf_force_sig_info(int si_signo, int si_code, unsigned long address,
			     struct pt_regs *regs)
{
	struct trap_pt_regs *trap = regs->trap;

	if (si_signo == SIGBUS)
		SDBGPRINT("SIGBUS. Page fault");
	else if (si_signo == SIGSEGV)
		SDBGPRINT("SIGSEGV. Page fault");

	PFDBGPRINT("Signal %d for address 0x%lx", si_signo, address);

	if (debug_pagefault)
		print_pagefault_info(trap, address, DEBUG_PF_MODE, true);

	force_sig_fault(si_signo, si_code, (void __user *)address,
			trap->nr_page_fault_exc);

	return PFR_SIGPENDING;
}

static int clear_valid_on_spec_load_one(struct vm_area_struct *vma,
		unsigned long addr,  struct pt_regs *regs, bool *unlocked)
{
	struct mm_struct *mm = current->mm;
	unsigned long area_start, area_end;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	/*
	 * Calculate invalid area size
	 */
	if (!vma) {
		/* This is a speculative load from unmapped area */
		struct vm_area_struct *vma_prev;
		vma = find_vma_prev(mm, addr, &vma_prev);
		area_start = (vma_prev) ? vma_prev->vm_end : 0;
		area_end = TASK_SIZE;
	} else if (addr < vma->vm_start) {
		/* This is a speculative load from unmapped area */
		area_start = (vma->vm_prev) ? vma->vm_prev->vm_end : 0;
		area_end = vma->vm_start;
		vma = NULL;
	} else {
		/* Check that this is a speculative load from PROT_NONE mapping */
		if (vma->vm_flags & (VM_READ | VM_EXEC | VM_WRITE))
			return 0;

		area_start = vma->vm_start;
		area_end = vma->vm_end;
	}

	/*
	 * OK, so remove the valid bit from PTE if it is there.
	 * Otherwise this load is _not_ the cause of page fault
	 * and can be safely ignored (we know thanks to the check
	 * above that this load will just return DW).
	 */

	pgd = pgd_offset(mm, addr);
	/* Check if we can mark whole pgd invalid */
	if (pgd_none(*pgd) && round_down(addr, PGDIR_SIZE) >= area_start &&
			round_up(addr, PGDIR_SIZE) <= area_end) {
		spin_lock(&mm->page_table_lock);
		if (pgd_none(*pgd) && pgd_valid(*pgd)) {
			pgd_t entry = pgd_mknotvalid(*pgd);
			set_pgd_at(mm, addr, pgd, entry);
		}
		spin_unlock(&mm->page_table_lock);
		goto out_success;
	}

	pud = pud_alloc(mm, pgd, addr);
	if (!pud)
		goto oom;
	/* Avoid unnecessary splitting if we raced againt huge PUD fault
	 * (just for better performance) */
	if (pud_trans_huge(*pud))
		return 0;
	/* Check if we can mark whole pud invalid */
	if (pud_none(*pud) && round_down(addr, PUD_SIZE) >= area_start &&
			round_up(addr, PUD_SIZE) <= area_end) {
		spin_lock(&mm->page_table_lock);
		if (pud_none(*pud) && pud_valid(*pud)) {
			pud_t entry = pud_mknotvalid(*pud);
			set_pud_at(mm, addr, pud, entry);
		}
		spin_unlock(&mm->page_table_lock);
		goto out_success;
	}

	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
		goto oom;
	/* Avoid unnecessary splitting if we raced againt huge PMD fault
	 * (just for better performance) */
	if (pmd_trans_huge(*pmd))
		return 0;
	/* Check if we can mark whole pmd invalid */
	if (pmd_none(*pmd) && round_down(addr, PMD_SIZE) >= area_start &&
			round_up(addr, PMD_SIZE) <= area_end) {
		spinlock_t *ptl;
		if (vma && is_vm_hugetlb_page(vma)) {
			pte_t *huge_pte = (pte_t *) pmd;

			if (E2K_LARGE_PAGE_SIZE == E2K_4M_PAGE_SIZE) {
				if (huge_pte && pmd_index(addr) % 2)
					huge_pte--;
			}

			ptl = huge_pte_lockptr(hstate_vma(vma), mm, huge_pte);
		} else {
			ptl = pmd_lockptr(mm, pmd);
		}

		spin_lock(ptl);
		if (pmd_none(*pmd) && pmd_valid(*pmd)) {
			pmd_t entry = pmd_mknotvalid(*pmd);
			set_pmd_at(mm, addr, pmd, entry);
		}
		if (E2K_LARGE_PAGE_SIZE == E2K_4M_PAGE_SIZE &&
				vma && is_vm_hugetlb_page(vma)) {
			pmd = (pmd_index(addr) % 2) ? pmd - 1 : pmd + 1;
			if (pmd_none(*pmd) && pmd_valid(*pmd)) {
				pmd_t entry = pmd_mknotvalid(*pmd);
				set_pmd_at(mm, addr, pmd, entry);
			}
		}
		spin_unlock(ptl);
		goto out_success;
	}

	split_huge_pmd(vma, pmd, addr);

	/*
	 * Use pte_alloc() instead of pte_alloc_map().  We can't run
	 * pte_offset_map() on pmds where a huge pmd might be created
	 * from a different thread.
	 *
	 * pte_alloc_map() is safe to use under down_write(mmap_sem) or when
	 * parallel threads are excluded by other means.
	 *
	 * Here we only have down_read(mmap_sem).
	 */
	if (pte_alloc(mm, pmd))
		goto oom;

	/* See the comment in handle_pte_fault() */
	if (unlikely(pmd_trans_unstable(pmd)))
		return 0;

	/*
	 * A regular pmd is established and it can't morph into a huge pmd
	 * from under us anymore at this point because we hold the mmap_sem
	 * read mode and khugepaged takes it in write mode. So now it's
	 * safe to run pte_offset_map().
	 */
	pte = pte_offset_map(pmd, addr);

	if (!pte_none(*pte) || !pte_valid(*pte))
		return 0;

	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);
	/* Check if we can mark pte invalid */
	if (pte_none(*pte) && pte_valid(*pte)) {
		pte_t entry = pte_mknotvalid(*pte);
		set_pte_at(mm, addr, pte, entry);
		/* No need to flush - valid entries are not cached in DTLB */
	}
	pte_unmap_unlock(pte, ptl);

out_success:
	if (debug_semi_spec)
		pr_notice("PAGE FAULT. unmap invalid SPEC LD address 0x%lx: IP=%px %s(pid=%d)\n",
			addr, (void *) GET_IP, current->comm, current->pid);

	return PFR_IGNORE;

oom:
	up_read(&current->mm->mmap_sem);
	*unlocked = true;

	/* OOM killer could have killed us */
	pagefault_out_of_memory();

	return fatal_signal_pending(current) ? PFR_SIGPENDING : PFR_IGNORE;
}

/*
 * Setting valid bit always precisely matching vmas sometimes requires
 * a _lot_ of e2k-specific edits in arch.-indep. code.  It is simpler
 * to set the valid bit by default and remove it in case it's not set
 * in the corresponding vma (i.e. when is_pte_valid()=true but vma for
 * the address in question is unmapped or mapped with PROT_NONE).
 *
 * In the case of a race we will try clearing the valid bit again the
 * next time we get a page fault on half-spec. load.
 *
 * Returns:
 *   PFR_SIGPENDING: if this process was killed by Out-of-Memory handler;
 *   PFR_IGNORE: if the valid bit was cleared (or some race prevented us
 *               from clearing it);
 *   0: otherwise.
 */
static int clear_valid_on_spec_load(unsigned long address,
		struct vm_area_struct *vma, struct pt_regs *regs,
		union pf_mode mode, int addr_num, bool *unlocked)
{
	int ret;

	if (!is_spec_load_fault(mode))
		return 0;

	ret = clear_valid_on_spec_load_one(vma, address, regs, unlocked);
	if (ret || *unlocked)
		return ret;

	if (addr_num > 1) {
		unsigned long addr_hi = PAGE_ALIGN(address);
		if (vma && vma->vm_end <= addr_hi)
			vma = vma->vm_next;
		ret = clear_valid_on_spec_load_one(vma, addr_hi, regs, unlocked);
		if (ret)
			return ret;
	}

	return 0;
}

__cold
static int bad_area(unsigned long address, struct pt_regs *regs, union pf_mode mode,
			int addr_num, int si_code)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	bool unlocked = false;
	int ret;

	/*
	 * __do_munmap() could change mmap_sem writelock to mmap_sem readlock, so one
	 * need to take mmap_sem writelock to process with page table in
	 * clear_valid_on_spec_load_one().
	 */
	up_read(&mm->mmap_sem);
	down_write(&mm->mmap_sem);

	vma = find_vma(mm, address);

	ret = clear_valid_on_spec_load(address, vma, regs, mode, addr_num, &unlocked);

	if (!unlocked)
		up_write(&mm->mmap_sem);

	if (ret)
		return ret;

	if (!mode.user && address >= TASK_SIZE)
		return no_context(address, regs, mode);

	if (handle_spec_load_fault(address, regs, mode))
		return PFR_IGNORE;

	if (!mode.user)
		return no_context(address, regs, mode);

	trace_unhandled_page_fault(address);

	if (likely(show_unhandled_signals))
		show_signal_msg(regs, address, current);

	return pf_force_sig_info(SIGSEGV, si_code, address, regs);
}


static int access_error(struct vm_area_struct *vma, unsigned long address,
			struct pt_regs *regs, union pf_mode mode,
			int instr_page)
{
	if (mode.write) {
		/* Check write permissions */
		if (unlikely(!(vma->vm_flags & (VM_WRITE | VM_MPDMA)))) {
			if (!is_spec_load_fault(mode))
				PFDBGPRINT("Page is not writable");
			return 1;
		}
	} else if (unlikely(!(vma->vm_flags & (VM_READ | VM_EXEC |
					       VM_WRITE)))) {
		/* Check read permissions */
		if (!is_spec_load_fault(mode))
			PFDBGPRINT("Page is PROT_NONE");
		return 1;
	}

	/* Check exec permissions */
	if (instr_page && unlikely(!(vma->vm_flags & VM_EXEC))) {
		PFDBGPRINT("Page is not executable");
		return 1;
	}

	/* Check privilege level */
	if (unlikely((vma->vm_flags & VM_PRIVILEGED) &&
		     !test_ts_flag(TS_KERNEL_SYSCALL))) {
		if (!is_spec_load_fault(mode))
			PFDBGPRINT("Page is privileged");
		return 1;
	}

	return 0;
}

/*
 * bug #102076
 *
 * There are areas that can be written but cannot be read; for example,
 * areas past the end of file. Accessing them with `mova' will cause
 * a page fault which we do not want in this case (because `mova' is
 * speculative).
 *
 * For half-speculative loads we can just return to user and there will
 * be DT in register (hardware puts it there), the user application will
 * continue execution from the next wide instruction. But for AAU we have
 * to remove the valid bit from page table, otherwise it will just repeat
 * the load, resulting in an endless loop.
 *
 * Note that after removing the valid bit this entry can be written into
 * DTLB, so we have to flush it in do_page_fault().
 */
static int handle_forbidden_aau_load(struct vm_area_struct *vma,
		unsigned long address, struct pt_regs *regs, union pf_mode mode)
{
	struct mm_struct *mm = current->mm;
	e2k_tir_hi_t tir_hi;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	if (mode.write || !vma->vm_ops)
		return 0;

	AW(tir_hi) = regs->trap->TIR_hi;

	/* Is this not an AAU fault? */
	if (AS(tir_hi).j != 0 || !AS(tir_hi).aa)
		return 0;

	/*
	 * OK, so we want to ignore this.
	 * If an error occurs, just return PFR_IGNORE and retry
	 * when the page fault is generated again by AAU.
	 */

	pgd = pgd_offset(mm, address);
	pud = pud_alloc(mm, pgd, address);
	if (!pud)
		goto oom;

	pmd = pmd_alloc(mm, pud, address);
	if (!pmd)
		goto oom;

	split_huge_pmd(vma, pmd, address);

	/*
	 * Use pte_alloc() instead of pte_alloc_map().  We can't run
	 * pte_offset_map() on pmds where a huge pmd might be created
	 * from a different thread.
	 *
	 * pte_alloc_map() is safe to use under down_write(mmap_sem) or when
	 * parallel threads are excluded by other means.
	 *
	 * Here we only have down_read(mmap_sem).
	 */
	if (pte_alloc(mm, pmd))
		goto oom;

	/* See the comment in handle_pte_fault() */
	if (unlikely(pmd_trans_unstable(pmd)))
		goto ignore;

	/*
	 * A regular pmd is established and it can't morph into a huge pmd
	 * from under us anymore at this point because we hold the mmap_sem
	 * read mode and khugepaged takes it in write mode. So now it's
	 * safe to run pte_offset_map().
	 */
	pte = pte_offset_map(pmd, address);

	if (!pte_none(*pte) || !pte_valid(*pte))
		return 0;

	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);

	if (pte_none(*pte) && pte_valid(*pte)) {
		pte_t entry = pte_mknotvalid(*pte);
		set_pte_at(mm, address, pte, entry);
		/* No need to flush - valid entries are not cached in DTLB */
	}

	pte_unmap_unlock(pte, ptl);

	if (debug_semi_spec)
		pr_notice("PAGE FAULT. unmap invalid MOVA address 0x%lx: IP=%px %s(pid=%d)\n",
			address, (void *) GET_IP, current->comm, current->pid);

ignore:
	up_read(&current->mm->mmap_sem);

	return PFR_IGNORE;

oom:
	up_read(&current->mm->mmap_sem);

	/* OOM killer could have killed us */
	pagefault_out_of_memory();

	return fatal_signal_pending(current) ? PFR_SIGPENDING : PFR_SUCCESS;
}


__cold
static int mm_fault_error(struct vm_area_struct *vma, unsigned long address,
		struct pt_regs *regs, union pf_mode mode, unsigned int fault)
{
	int ret;

	/*
	 * Pagefault was interrupted by SIGKILL. We have no reason to
	 * continue pagefault.
	 */
	if (fatal_signal_pending(current)) {
		up_read(&current->mm->mmap_sem);

		if (!mode.user)
			return no_context(address, regs, mode);

		return PFR_SIGPENDING;
	}

	if (fault & VM_FAULT_OOM) {
		up_read(&current->mm->mmap_sem);

		if (!mode.user)
			return no_context(address, regs, mode);

		pagefault_out_of_memory();

		/* OOM killer could have killed us */
		return fatal_signal_pending(current) ? PFR_SIGPENDING :
						       PFR_SUCCESS;
	}

	if (fault & (VM_FAULT_SIGBUS|VM_FAULT_SIGSEGV)) {
		ret = handle_forbidden_aau_load(vma, address, regs, mode);
		if (ret)
			return ret;
	}

	up_read(&current->mm->mmap_sem);

	if (fault & (VM_FAULT_SIGBUS|VM_FAULT_SIGSEGV)) {
		int signal, si_code;

		if (!mode.user)
			return no_context(address, regs, mode);

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

		return pf_force_sig_info(signal, si_code, address, regs);
	}

	BUG();
}

int pf_on_page_boundary(unsigned long address, tc_cond_t cond)
{
	unsigned long end_address;
	const int size = tc_cond_to_size(cond);

	/* Special operations cannot cross page boundary
	 * as they do not access RAM. */
	if (tc_cond_is_special_mmu_aau(cond))
		return false;

	/*
	 * Always manually check for page boundary crossing.
	 * ftype.page_bound field is not reliable enough:
	 *
	 * 1) "ftype" field is present only in the first tcellar entry.
	 * 2) "page_bound" is shadowed by "page_miss", "nwrite_page", etc.
	 * 3) It was removed in iset V3.
	 */

	DebugNAO("not aligned operation with address 0x%lx fmt %d size %d bytes\n",
		address, TC_COND_FMT_FULL(cond), size);

	end_address = address + size - 1;

	return unlikely(end_address >> PAGE_SHIFT != address >> PAGE_SHIFT);
}

static int handle_kernel_address(unsigned long address, struct pt_regs *regs,
		union pf_mode mode, tc_fault_type_t ftype)
{
	if (mode.user) {
		if (handle_spec_load_fault(address, regs, mode))
			return PFR_IGNORE;

		PFDBGPRINT("On kernel address 0x%lx in user mode", address);
		return pf_force_sig_info(SIGBUS, BUS_ADRERR, address, regs);
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
	if (regs->trap->tc_count <= 3 || AW(ftype))
		return no_context(address, regs, mode);

	DebugPF("kernel address 0x%lx due to user address page fault\n",
			address);

	return PFR_KERNEL_ADDRESS;
}

/* bug 118398: is this an unaligned qp store with masked out
 * bytes landing in not existent page? */
bool is_spurious_qp_store(bool store, unsigned long address,
		int fmt, tc_mask_t mask, unsigned long *pf_address)
{
	if (!cpu_has(CPU_FEAT_ISET_V6) || !store || !tc_fmt_has_valid_mask(fmt))
		return false;

	/* User could do an stmqp with 0 mask.  This operation makes
	 * no sense so we will just loop repeating it until killed. */
	if (unlikely(!mask.mask))
		return false;

	if (address >> PAGE_SHIFT !=
	    (address + ffs(mask.mask) - 1) >> PAGE_SHIFT) {
		if (pf_address)
			*pf_address = address + ffs(mask.mask) - 1;
		return true;
	}

	if ((address + 15) >> PAGE_SHIFT !=
	    (address + fls(mask.mask) - 1) >> PAGE_SHIFT) {
		if (pf_address)
			*pf_address = address;
		return true;
	}

	return false;
}

#ifdef CONFIG_NESTED_PAGE_FAULT_INJECTION
static int npfi_enabled;

static ssize_t npfi_write(struct file *f,
		const char __user *buf, size_t count, loff_t *ppos)
{
	u8 val;

	int ret = kstrtou8_from_user(buf, count, 2, &val);
	if (ret)
		return ret;

	npfi_enabled = !!val;
	return count;
}

static ssize_t npfi_read(struct file *f,
		char __user *ubuf, size_t count, loff_t *ppos)
{
	char buf[3];

	snprintf(buf, sizeof(buf), "%d\n", npfi_enabled);

	return simple_read_from_buffer(ubuf, count, ppos, buf, sizeof(buf));
}

static const struct file_operations npfi_debug_fops = {
	.open = simple_open,
	.read = npfi_read,
	.write = npfi_write,
};

static int __init npfi_debugfs_init(void)
{
	if (!debugfs_create_file("nested_page_fault_injection", 0644, NULL,
			NULL, &npfi_debug_fops))
		return -ENOMEM;

	return 0;
}
late_initcall(npfi_debugfs_init);

static DEFINE_PER_CPU(unsigned int, injected_faults);
static int nested_page_fault_injected(void)
{
	if (npfi_enabled && (get_cycles() & 0x3ull)) {
		unsigned long faults;

		faults = this_cpu_read(injected_faults);
		if (faults < 10)
			++faults;
		else
			faults = 0;
		this_cpu_write(injected_faults, faults);

		return faults != 0;
	}

	return false;
}
#else
static int nested_page_fault_injected(void)
{
	return 0;
}
#endif

int do_page_fault(struct pt_regs *const regs, e2k_addr_t address,
		const tc_cond_t condition, const tc_mask_t mask,
		const int instr_page)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	tc_fault_type_t ftype;
	tc_opcode_t opcode;
	union pf_mode mode;
	const int fmt = TC_COND_FMT_FULL(condition);
	const bool qp = (fmt == LDST_QP_FMT || fmt == TC_FMT_QPWORD_Q);
	int ret, addr_num;
	int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;
	vm_fault_t major = 0;

#ifdef CONFIG_KVM_ASYNC_PF
	/*
	 * If physical page was swapped out by host, than
	 * suspend current process until page will be loaded
	 * from swap.
	 */
	if (pv_apf_read_and_reset_reason() == KVM_APF_PAGE_IN_SWAP) {
		pv_apf_wait();
		return PFR_IGNORE;
	}
#endif /* CONFIG_KVM_ASYNC_PF */

	if (nested_page_fault_injected())
		return PFR_SUCCESS;

	AW(ftype) = AS(condition).fault_type;
	AW(opcode) = AS(condition).opcode;

	mode.word = 0;
	mode.write = tc_cond_is_store(condition, machine.native_iset_ver);
	mode.spec = AS(condition).spec;
	mode.user = user_mode(regs);
	mode.root = AS(condition).root;
	mode.empty = !mode.write && !AS(condition).vr && !AS(condition).vl;

	if (AS(condition).num_align) {
		if (!qp)
			address -= 8;
		else
			address -= 16;
	}

	/*
	 * ftype could be a combination of several fault types. One should
	 * reset all fault types, except illegal_page, if illegal_page
	 * happened. See bug #67315 for detailes.
	 */
	if (AS(ftype).illegal_page) {
		AW(ftype) = 0;
		AS(ftype).illegal_page = 1;
	}

	NATIVE_CLEAR_DAM;

	DebugPF("started for address 0x%lx, instruction page:"
		"%d fault type:0x%x condition 0x%llx root:%d missl:%d cpu%d"
		" user_mode_fault=%d\n",
		address, instr_page, AW(ftype),
		AW(condition), mode.root, AS(condition).miss_lvl,
		task_cpu(current), mode.user);

	if (mode.write)
		flags |= FAULT_FLAG_WRITE;
	if (mode.user)
		flags |= FAULT_FLAG_USER;

#ifdef CONFIG_MCST_RT
	if ((rts_act_mask & RTS_PGFLT_RTWRN && rt_task(current)) ||
			rts_act_mask & RTS_PGFLT_WRN)
		pr_info("page fault while RTS mode %lx in %d/%s addr=%08lx\n",
			rts_act_mask, current->pid, current->comm, address);
#endif

	if (address >= TASK_SIZE)
		return handle_kernel_address(address, regs, mode, ftype);

	if (!mm || faulthandler_disabled())
		return no_context(address, regs, mode);

	if (pf_on_page_boundary(address, condition)) {
		unsigned long pf_address;

		if (is_spurious_qp_store(mode.write, address, fmt,
				mask, &pf_address)) {
			addr_num = 1;
			address = pf_address;
		} else {
			addr_num = 2;
		}
	} else {
		addr_num = 1;
	}

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);

	/*
	 * Kernel-mode access to the user address space should only occur
	 * on well-defined instructions. But, an erroneous kernel fault
	 * occurring outside one of those areas which also holds mmap_sem
	 * might deadlock attempting to validate the fault against
	 * the address space.
	 *
	 * Only do the expensive exception table search when we might be at
	 * risk of a deadlock.  This happens if we
	 * 1. Failed to acquire mmap_sem, and
	 * 2. The access did not originate in userspace.
	 */
	if (unlikely(!down_read_trylock(&mm->mmap_sem))) {
		if (!user_mode(regs) &&
				!current_thread_info()->usr_pfault_jump &&
				!search_exception_tables(get_fault_ip(regs))) {
			/* It is kernel code where we do not expect faults */
			return no_context(address, regs, mode);
		}
retry:
		down_read(&mm->mmap_sem);
	} else {
		/*
		 * The above down_read_trylock() might have succeeded in
		 * which case we'll have missed the might_sleep() from
		 * down_read():
		 */
		might_sleep();
	}
	vma = find_vma(mm, address);

	DebugPF("find_vma() returned 0x%px\n", vma);

	if (!vma) {
#ifdef CONFIG_SOFTWARE_SWAP_TAGS
		if (is_tags_area_addr(address)) {
			DebugPF("fault address 0x%lx is from "
				"tags virtual space\n", address);
			vma = create_tags_vma(mm, tag_to_virt(address));
			if (!vma)
				return pf_out_of_memory(address, regs, mode);
		} else 
#endif
		{
			if (!mode.spec)
				PFDBGPRINT("PAGE FAULT. Trap with not "
					"speculative load and invalid address");
			return bad_area(address, regs, mode, addr_num, SEGV_MAPERR);
		}
	}

	if (address < vma->vm_start) {
#ifdef CONFIG_SOFTWARE_SWAP_TAGS
		if (is_tags_area_addr(address)) {
			DebugPF("fault address 0x%lx is from tags virtual "
				"space\n",
				address);
			vma = create_tags_vma(mm, tag_to_virt(address));
			if (vma == NULL)
				return pf_out_of_memory(address, regs, mode);
			goto good_area;
		}
#endif

		return bad_area(address, regs, mode, addr_num, SEGV_MAPERR);
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
		DebugPGD("pgd 0x%px = 0x%lx populated on CPU #%d\n",
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
			print_va_tlb(address, 0);
			PFDBGPRINT("Instruction page protection for valid address");
			return bad_area(address, regs, mode, addr_num, SEGV_MAPERR);
		}

		/* bug #102076: now this situation is possible */
		if (debug_semi_spec && AS(ftype).illegal_page && !page_none)
			pr_notice("illegal_page for valid page, address 0x%lx\n",
				address);

		if (!(AS(ftype).page_miss || AS(ftype).priv_page ||
				AS(ftype).global_sp || AS(ftype).nwrite_page ||
				AS(ftype).page_bound ||
				AS(ftype).illegal_page)) {
			PFDBGPRINT("trap with bad fault type for valid address ft:0x%x, wr:%d",
					AW(ftype), AS(ftype).nwrite_page);
			if (debug_pagefault) {
				print_pagefault_info(regs->trap, address,
					DEBUG_PF_MODE, true);
			}
			return bad_area(address, regs, mode, addr_num, SEGV_ACCERR);
		}
	}
#endif	/* CONFIG_MAKE_ALL_PAGES_VALID */

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

	if (AS(ftype).nwrite_page) {
		DebugPF("write protection occured.\n");

#ifdef CONFIG_VIRTUALIZATION
		if (unlikely(vma->vm_flags & VM_MPDMA)) {
			WARN_ON_ONCE(vma->vm_flags & VM_WRITE);
			up_read(&mm->mmap_sem);
			handle_mpdma_fault(address);
			return PFR_SUCCESS;
		}
#endif
	}

	if (instr_page)
		DebugPF("instruction page fault occured.\n");

#ifdef CONFIG_PROTECTED_MODE
	/*
	 * Interpret the stack address in multithreaded protected mode
	 */
	if ((flags & FAULT_FLAG_ALLOW_RETRY) /* call just once */ &&
			(current->thread.flags & E2K_FLAG_PROTECTED_MODE) &&
			instr_page == 0 && WAS_MULTITHREADING) {
		DebugPF("WAS_MULTITHREADING=%d address=%lx ip=%llx\n",
				WAS_MULTITHREADING, address, GET_IP);

		ret = interpreted_ap_code(regs, &vma, &address);
		if (!ret)
			return bad_area(address, regs, mode, addr_num, SEGV_ACCERR);

		if (ret == 1 || ret == 2) {
	                up_read(&mm->mmap_sem);

			return (ret == 2) ? PFR_AP_THREAD_READ : PFR_SUCCESS;
		}
	}
#endif

	do {
		int fault;

		if (access_error(vma, address, regs, mode, instr_page))
			return bad_area(address, regs, mode, addr_num, SEGV_ACCERR);

		fault = handle_mm_fault(vma, address, flags);
		major |= fault & VM_FAULT_MAJOR;
		DebugPF("handle_mm_fault() returned %x\n", fault);

		if (unlikely(fault & VM_FAULT_RETRY)) {
			/* mmap_sem semaphore has been released by
			 * handle_mm_fault() already. Retry at most once. */
			flags &= ~FAULT_FLAG_ALLOW_RETRY;
			flags |= FAULT_FLAG_TRIED;
			if (!fatal_signal_pending(current))
				goto retry;

			if (!mode.user)
				return no_context(address, regs, mode);

			return PFR_SIGPENDING;
		}

		if (unlikely(fault & VM_FAULT_ERROR))
			return mm_fault_error(vma, address, regs, mode, fault);

		if (major) {
			current->maj_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ,
				      1, regs, address);
		} else {
			/* VM_FAULT_MINOR */
			current->min_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN,
				      1, regs, address);
		}

		if (fault == VM_FAULT_NOPAGE)
			sync_addr_range(address, address);

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
							addr_num, SEGV_MAPERR);
				}
			}
		}
	} while (unlikely(addr_num > 0));

	/*
	 * bug #102076
	 *
	 * For our special case we have to flush DTLB
	 * after putting the valid bit back into the pte.
	 */
	if (vma->vm_ops && AS(ftype).illegal_page)
		__flush_tlb_range(vma->vm_mm, address,
				  address + E2K_MAX_FORMAT);

	up_read(&mm->mmap_sem);
	DebugPF("handle_mm_fault() finished\n");

	return PFR_SUCCESS;

force_sigbus:
	up_read(&mm->mmap_sem);

	return pf_force_sig_info(SIGBUS, BUS_ADRERR, address, regs);
}

/**
 * get_recovery_mas - check for special cases when we have to use
 *		      different mas from what was specified in trap cellar
 * @condition: trap condition from trap cellar
 *
 * 1) We should recover LOAD operation with MAS == FILL_OPERATION
 * to load the value with tags. In protected mode any value has tag.
 *
 * 2) Avoid exc_illegal_opcode on e2c+
 *
 * 3) Do not lock SLT
 */
static unsigned int get_recovery_mas(tc_cond_t condition, int fmt)
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
	 * #127500 Do not execute "secondary lock trap on store" and
	 * "secondary lock trap on load/store" operations, instead
	 * downgrade them to simple loads:
	 *   "secondary lock trap on store" -> "secondary normal"
	 *   "secondary lock trap on load/store" -> "secondary normal"
	 */
	if (root && !store && !spec_mode && (chan == 0 ||
					     chan == 2 && fmt == LDST_QWORD_FMT)) {
		if (is_mas_secondary_lock_trap_on_store(mas) ||
		    is_mas_secondary_lock_trap_on_load_store(mas))
			return _MAS_MODE_LOAD_OPERATION;
	}

	/*
	 * If LOAD with 'lock wait' MAS type then we should not use MAS
	 * to recover LOAD as regular operation. The real LOAD with real
	 * MAS will be repeated later after return from trap as result
	 * of pair STORE operation with 'wait unlock' MAS
	 */
	if (!spec_mode) {
		if (chan == 0 && (machine.native_iset_ver < E2K_ISET_V3 ||
					root == 0) &&
						mod == _MAS_MODE_LOAD_OP_WAIT)
			return _MAS_MODE_LOAD_OPERATION;

		if (machine.native_iset_ver >= E2K_ISET_V3 && root &&
				chan <= 1 && !store && mas == MAS_SEC_SLT)
			return _MAS_MODE_LOAD_OPERATION;

		if (machine.native_iset_ver >= E2K_ISET_V5 && !root &&
				chan <= 1 && !store &&
				mas == _MAS_MODE_LOAD_OP_WAIT_1)
			return _MAS_MODE_LOAD_OPERATION;
	}


	if (AS(opcode).npsp ||
	    !(current->thread.flags & E2K_FLAG_PROTECTED_MODE)) {
		/*
		 * On e2c+ unprotected qword "check" and "check&unlock"
		 * instructions generated exc_illegal_opcode, use workaround.
		 */
		if (machine.native_iset_ver <= E2K_ISET_V2 &&
				AS(opcode).fmt == LDST_QWORD_FMT &&
				(mod == _MAS_MODE_LOAD_OP_UNLOCK ||
				 mod == _MAS_MODE_LOAD_OP_CHECK))
			return _MAS_MODE_LOAD_OPERATION;

		return mas;
	}

	/*
	 * If LOAD is protected then we should execute LDRD
	 * to get the value with tags. It is possible only using
	 * the special MAS in nonprotected mode
	 */
	if (mod == 0 || AS(opcode).fmt == 5 && !root) {
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

static inline void calculate_wr_data(int fmt, int offset,
		u64 *data, u8 *data_tag)
{
	u64 wr_data;

	/* Avoid undefined behavior when shifting more than argument size */
	if (offset == 0) {
		wr_data = *data;
	} else {
		wr_data = (*data >> (offset * 8)) |
			  (*data << ((8 - offset) * 8));
	}

	*data = wr_data;

	switch (fmt & 0x7) {
	case LDST_BYTE_FMT:
	case LDST_HALF_FMT:
		*data_tag = 0;
		break;
	case LDST_WORD_FMT:
		if (offset == 0)
			*data_tag &= 0x3;
		else if (offset == 4)
			*data_tag = ((*data_tag) >> 2);
		break;
	}
}

static inline void calculate_qp_wr_data(int offset,
		u64 *data, u8 *data_tag, u64 *data_ext, u8 *data_tag_ext)
{
	/* Avoid undefined behavior when shifting more than argument size */
	if (offset == 0)
		return;

	u64 wr_data = (*data >> (offset * 8)) |
		  (*data_ext << ((8 - offset) * 8));
	u64 wr_data_ext = (*data_ext >> (offset * 8)) |
		      (*data << ((8 - offset) * 8));

	*data = wr_data;
	*data_ext = wr_data_ext;
}

static void recovery_store_with_bytes(unsigned long address,
		unsigned long address_hi, unsigned long address_hi_offset,
		u64 data, u64 data_ext, ldst_rec_op_t st_rec_opc, int chan,
		int length, int mask, int mask_ext)
{
	int byte;

	st_rec_opc.fmt = LDST_BYTE_FMT;
	st_rec_opc.fmt_h = 0;

	for (byte = 0; byte < length;
			byte++, address++, data >>= 8, mask >>= 1) {
		if (address_hi_offset && byte == address_hi_offset)
			address = address_hi;

		if (byte == 8) {
			data = data_ext;
			mask = mask_ext;
		}

		if (mask & 1) {
			recovery_faulted_tagged_store(address, data, 0,
					AW(st_rec_opc), 0, 0, 0, chan,
					0 /* qp_store */,
					0 /* atomic_store */);

		}
	}
}

static enum exec_mmu_ret do_recovery_store(struct pt_regs *regs,
		const trap_cellar_t *tcellar, const trap_cellar_t *next_tcellar,
		e2k_addr_t address, e2k_addr_t address_hi_hva,
		int fmt, int chan, unsigned long hva_page_offset)
{
	bool big_endian, qp_store, q_store, atomic_qp_store, atomic_q_store,
	     atomic_store, aligned_16 = IS_ALIGNED(address, 16);
	int next_fmt, strd_fmt, offset = address & 0x7;
	ldst_rec_op_t	st_rec_opc, ld_rec_opc, st_opc_ext;
	u64 data, data_ext,
	    mas = AS(tcellar->condition).mas,
	    root = AS(tcellar->condition).root;
	u8		data_tag, data_ext_tag;
#ifdef	CONFIG_ACCESS_CONTROL
	e2k_upsr_t	upsr_to_save;
#endif	/* CONFIG_ACCESS_CONTROL */

	if (DEBUG_EXEC_MMU_OP) {
		u64	val;
		u8	tag;

		load_value_and_tagd(&tcellar->data, &val, &tag);
		DbgEXMMU("do_recovery_store: STRD store from trap cellar "
			"the data 0x%016llx tag 0x%x address 0x%lx offset %d\n",
			val, tag, address, offset);
	}

	/*
	 * #74018 Do not execute store operation if rp_ret != 0
	 */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (unlikely(regs->trap->flags & TRAP_RP_FLAG)) {
		DbgEXMMU("do_recovery_store: rp_ret != 0\n");
		return EXEC_MMU_SUCCESS;
	}
#endif

	big_endian = (mas & MAS_ENDIAN_MASK) &&
		     ((mas & MAS_MOD_MASK) != MAS_MODE_STORE_MMU_AAU_SPEC) &&
		     !root;
	qp_store = (fmt == LDST_QP_FMT || fmt == TC_FMT_QPWORD_Q);
	q_store = (fmt == LDST_QWORD_FMT || fmt == TC_FMT_QWORD_QP);
	atomic_qp_store = (cpu_has(CPU_FEAT_ISET_V6) && aligned_16 && qp_store);

	/* SPILL RF without FX is done with LDST_QWORD_FMT but
	 * with next_tcellar->address == tcellar->address + 16.
	 * Do not try to repeat this atomically. */
	next_fmt = next_tcellar ? TC_COND_FMT_FULL(next_tcellar->condition) : -1;
	atomic_q_store = (cpu_has(CPU_FEAT_ISET_V6) && aligned_16 && q_store &&
			  chan == 1 && next_fmt == fmt &&
			  (next_tcellar->address % 16) == 8);

	atomic_store = (atomic_q_store || atomic_qp_store);

	if (cpu_has(CPU_FEAT_ISET_V6) && q_store && (address % 16 == 8) &&
			chan == 3) {
		/*
		 * Second part of an atomic quadro store which takes
		 * up 2 records in cellar, actual memory access has
		 * been done already when handling the first record.
		 *
		 * We only support atomic quadro stores since iset v6
		 * because we have to distinguish between ldrd/strd
		 * with fmtr="qword" and real quadro stores.
		 */
		return EXEC_MMU_SUCCESS;
	}

	ACCESS_CONTROL_DISABLE_AND_SAVE(upsr_to_save);

	/*
	 * Load data to store from trap cellar
	 */

	AW(ld_rec_opc) = 0;
	ld_rec_opc.prot = 1;
	ld_rec_opc.mas = MAS_BYPASS_ALL_CACHES | MAS_FILL_OPERATION;
	ld_rec_opc.fmt = LDST_QWORD_FMT;
	ld_rec_opc.index = 0;

	recovery_faulted_load((e2k_addr_t)&tcellar->data,
				&data, &data_tag, AW(ld_rec_opc), 0,
				(tc_cond_t) {.word = 0});

	if (atomic_q_store) {
		recovery_faulted_load((e2k_addr_t) &next_tcellar->data,
				&data_ext, &data_ext_tag, AW(ld_rec_opc), 0,
				(tc_cond_t) {.word = 0});

		/* This is aligned so offset == 0 */
		calculate_wr_data(fmt, offset, &data, &data_tag);
		calculate_wr_data(fmt, offset, &data_ext, &data_ext_tag);
	} else if (qp_store) {
		recovery_faulted_load((e2k_addr_t)&tcellar->data_ext,
				&data_ext, &data_ext_tag, AW(ld_rec_opc), 0,
				(tc_cond_t) {.word = 0});

		calculate_qp_wr_data(offset, &data, &data_tag,
				&data_ext, &data_ext_tag);
	} else {
		calculate_wr_data(fmt, offset, &data, &data_tag);
	}

	if (DEBUG_EXEC_MMU_OP)
		pr_info("do_recovery_store: store(fmt 0x%x) chan = %d address = 0x%lx, data = 0x%llx tag = 0x%x tc_data = 0x%016llx\n",
			fmt, chan, address, data, data_tag, data);

	/*
	 * Actually re-execute the store operation
	 */

	AW(st_rec_opc) = 0;
	/* Store as little endian. Do not clear the endianness bit
	 * unconditionally as it might mean something completely
	 * different depending on other bits in the trap cellar.*/
	st_rec_opc.mas = (big_endian) ? (mas & ~MAS_ENDIAN_MASK) : mas;
	st_rec_opc.prot = !(AS(tcellar->condition).npsp);
	if (fmt == TC_FMT_QPWORD_Q || fmt == TC_FMT_DWORD_Q)
		strd_fmt = LDST_QWORD_FMT;
	else if (fmt == TC_FMT_QWORD_QP || fmt == TC_FMT_DWORD_QP)
		strd_fmt = LDST_QP_FMT;
	else
		strd_fmt = fmt & 0x7;
	st_rec_opc.fmt = strd_fmt;
	st_rec_opc.root = AS(tcellar->condition).root;
	st_rec_opc.mask = tcellar->mask.mask_lo;
	st_rec_opc.fmt_h = !!atomic_store;

	st_opc_ext = st_rec_opc;
	st_opc_ext.mask = tcellar->mask.mask_hi;
	st_opc_ext.index = 8;

	/* For big endian case should swap the two operations. */
	if (atomic_q_store && big_endian) {
		swap(data, data_ext);
		swap(data_tag, data_ext_tag);
		swap(st_rec_opc, st_opc_ext);
	}

	if (unlikely(hva_page_offset)) {
		recovery_store_with_bytes(address, address_hi_hva, hva_page_offset,
			data, data_ext, st_rec_opc, chan,
			tc_cond_to_size(tcellar->condition),
			tc_fmt_has_valid_mask(fmt) ? tcellar->mask.mask_lo : 0xff,
			tc_fmt_has_valid_mask(fmt) ? tcellar->mask.mask_hi : 0xff);
	} else if (IS_MACHINE_ES2 && AS(tcellar->condition).page_bound) {
		/*
		 * 1) Page bound exception exists on e2c+ only.
		 * 2) bug 118398: handle unaligned qp store with masked out
		 * bytes landing in not existent page.
		 */

		/* v2 only: page_bound exception */
		int length = min(8, 1 << (fmt - 1));

		recovery_store_with_bytes(address, 0, 0, data, 0,
				st_rec_opc, chan, length, 0xff, 0);
	} else if (is_spurious_qp_store(true, address,
			fmt, tcellar->mask, NULL)) {
		/* Since v6: qp store with spurious fault, repeating the whole
		 * operation will generate another spurious fault so repeat
		 * each byte store separately. */
		recovery_store_with_bytes(address, 0, 0, data, data_ext,
				st_rec_opc, chan, 16, st_rec_opc.mask, st_opc_ext.mask);
	} else {
		recovery_faulted_tagged_store(address, data, data_tag,
				AW(st_rec_opc), data_ext, data_ext_tag,
				AW(st_opc_ext), chan, qp_store, atomic_store);
	}

	ACCESS_CONTROL_RESTORE(upsr_to_save);

	/* Make sure we finished recovery operations before reading flags */
	E2K_CMD_SEPARATOR;

	/* Nested exception appeared while do_recovery_store() */
	if (regs->flags.exec_mmu_op_nested) {
		regs->flags.exec_mmu_op_nested = 0;

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
		tc_cond_t cond, unsigned *greg_num_d, bool *greg_recovery,
		bool *rotatable_greg, e2k_bgr_t *src_bgr, u64 **radr)
{
	unsigned vr = AS(cond).vr;
	unsigned vl = AS(cond).vl;
	unsigned dst_addr = AS(cond).address;

	DbgTC("load request vr=%d\n", vr);

	/*
	 * Calculate register's address
	 */
	if (!vr && !vl) {
		/*
		 * Destination register to load is NULL
		 * We should load the value from address into "air"
		 */
		*radr = NULL;
		DbgEXMMU("<dst> is NULL register\n");
	} else if (!vl) {
		panic("Invalid destination: 0x%x : vl is 0 %s(%d)\n",
			      AS(cond).dst, __FILE__, __LINE__);
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
		*greg_recovery = true;
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
			*rotatable_greg = true;
			*src_bgr = native_read_BGR_reg();
			init_BGR_reg();
			DbgEXMMU("<dst> is global rotatable register: "
				"rnum_d = 0x%x (dg%d) BGR 0x%x\n",
				dst_addr, *greg_num_d, AWP(src_bgr));
		} else {
			DbgEXMMU("<dst> is global register: rnum_d = 0x%x "
				"(dg%d)\n",
				dst_addr, *greg_num_d);
		}
	} else if (dst_addr < E2K_MAXSR_d) {
		/* it need calculate address of register */
		/* into register file frame */
		return -1;
	} else {
		panic("Invalid destination register %d in the trap "
				"cellar %s(%d)\n",
				dst_addr, __FILE__, __LINE__);
	}

	return 0;
}

/**
 * calculate_recovery_load_to_rf_frame - calculate the stack address
 *	of the register into registers file frame where the load was done.
 * @dst_addr: trap cellar's "dst" field
 * @radr: address of a "normal" register
 * @load_to_rf: load to rf should be done
 *
 * This function calculates and sets @radr.
 *
 * Returns zero on success and value of type exec_mmu_ret on failure.
 */
#define CHECK_PSHTP
static enum exec_mmu_ret calculate_recovery_load_to_rf_frame(
		struct pt_regs *regs, tc_cond_t cond,
		u64 **radr, bool *load_to_rf)
{
	unsigned	dst_addr = AS(cond).address;
	unsigned	w_base_rnum_d;
	u8		*ps_base = NULL;
	unsigned	rnum_offset_d;
	e2k_psp_lo_t u_psp_lo;
	e2k_psp_hi_t u_psp_hi;
	unsigned long u_top;
#ifdef	CHECK_PSHTP
	register long lo_1, lo_2, hi_1, hi_2;
	register long pshtp_tind_d = AS_STRUCT(regs->stacks.pshtp).tind / 8;
	register long wd_base_d = AS_STRUCT(regs->wd).base / 8;

	if (!AS_STRUCT(regs->stacks.pshtp).tind) {
		pr_err("%s(): PSHTP.tind is zero, PSHTP.ind is 0x%x\n",
			__func__, regs->stacks.pshtp.PSHTP_ind);
		return EXEC_MMU_SUCCESS;
	}
#endif	/* CHECK_PSHTP */

	BUG_ON(!(dst_addr < E2K_MAXSR_d));

	/*
	 * We can be sure that we search in right window, and we can be
	 * not afraid of nested calls, because we take as base registers
	 * that were saved when we entered in trap handler, these registers
	 * pointed to last window before interrupt.
	 * When we came to interrupt we have new window which is defined
	 * by WD (current window register) in double words which was saved
	 * in regs->wd and we use it:
	 *	w_base_rnum_d = regs->wd;
	 * Window regs file (RF) is a ring buffer with size == E2K_MAXSR_d.
	 * So w_base_rnum_d can be > or < then num of destination register
	 * (dst_addr):
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
		lo_2 = wd_base_d - pshtp_tind_d;
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
	rnum_offset_d = (w_base_rnum_d - dst_addr + E2K_MAXSR_d) % E2K_MAXSR_d;
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
		*radr += ((machine.native_iset_ver < E2K_ISET_V5) ? 1 : 2);
	DbgEXMMU("<dst> is window "
		"register: rnum_d = 0x%x offset 0x%x, "
		"PS base 0x%px WD base = 0x%x, radr = 0x%px\n",
		dst_addr, rnum_offset_d, ps_base, w_base_rnum_d, *radr);

	if (((unsigned long) *radr < AS(regs->stacks.psp_lo).base) ||
				((unsigned long) *radr >= (u64)ps_base)) {
		/*
		 * The load operation out of current
		 * register window frame (for example this
		 * load is placed in one long instruction with
		 * return. The load operationb should be ignored
		 */
		DbgEXMMU("<dst> address of register window points "
			"out of current procedure stack frame "
			"0x%px >= 0x%px, load operation will be "
			"ignored\n",
			radr, ps_base);
		return EXEC_MMU_SUCCESS;
	}

	u_psp_lo = regs->stacks.psp_lo;
	u_psp_hi = regs->stacks.psp_hi;
	AS(u_psp_hi).ind -= GET_PSHTP_MEM_INDEX(regs->stacks.pshtp);
	u_top = AS(u_psp_lo).base + AS(u_psp_hi).ind;

	/*
	 * Check if target register has been SPILLed to kernel
	 */
	if ((unsigned long) *radr < PAGE_OFFSET &&
	    (unsigned long) *radr >= u_top) {
		*radr = (u64 *) (((unsigned long) *radr - u_top) +
				 AS(current_thread_info()->k_psp_lo).base);
	}

	*load_to_rf = true;
	return 0;
}

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
static int is_MLT_mas(ldst_rec_op_t opcode)
{
	if (!opcode.root)
		return 0;

	if ((int)machine.native_iset_ver >= ELBRUS_2S_ISET) {
		unsigned int mas = opcode.mas;

		if (mas == MAS_LOAD_SEC_TRAP_ON_STORE ||
				mas == MAS_LOAD_SEC_TRAP_ON_LD_ST)
			return 1;
	} else {
		unsigned int mod = (opcode.mas & MAS_MOD_MASK) >> MAS_MOD_SHIFT;

		if (mod == _MAS_MODE_LOAD_OP_TRAP_ON_STORE ||
				mod == _MAS_MODE_LOAD_OP_TRAP_ON_LD)
			return 1;
	}

	return 0;
}
#endif

static void recovery_load_with_bytes(unsigned long address,
		unsigned long address_hi, unsigned long address_hi_offset,
		unsigned long reg_address, unsigned long reg_address_hi,
		int vr, ldst_rec_op_t ld_rec_opc, int chan, int length,
		tc_cond_t cond)
{
	int byte;
	u32 first_time;

	ld_rec_opc.fmt = LDST_BYTE_FMT;
	ld_rec_opc.fmt_h = 0;

	for (byte = 0; byte < length; byte++, address++, reg_address++) {
		if (address_hi_offset && byte == address_hi_offset)
			address = address_hi;
		first_time = (byte == 0) ? 1 : 0;
		if (byte == 8)
			reg_address = reg_address_hi;
		if (vr || byte >= 4) {
			recovery_faulted_move(address, reg_address, 0,
					1 /* vr */, AW(ld_rec_opc), chan,
					0 /* qp_load */, 0 /* atomic_load */,
					first_time /* is it first move? */,
					cond);
		}
	}
}

static void debug_print_recovery_load(unsigned long address, int fmt,
		unsigned long radr, int chan, unsigned greg_recovery,
		unsigned greg_num_d, ldst_rec_op_t ld_rec_opc)
{
	u64	val;
	u8	tag = 0;
#ifdef	CONFIG_ACCESS_CONTROL
	e2k_upsr_t	upsr_to_save;
#endif

	if (DEBUG_EXEC_MMU_OP) {
		ACCESS_CONTROL_DISABLE_AND_SAVE(upsr_to_save);
		if (!radr) {
			recovery_faulted_load(address, &val,
					&tag, AW(ld_rec_opc), 2,
					(tc_cond_t) {.word = 0});
		} else if (greg_recovery) {
			E2K_GET_DGREG_VAL_AND_TAG(greg_num_d, val, tag);
		} else {
			load_value_and_tagd((void *) radr, &val, &tag);
		}
		ACCESS_CONTROL_RESTORE(upsr_to_save);

		DbgEXMMU("do_recovery_load: load(fmt 0x%x) chan = %d "
			"address = 0x%lx, %s = %d, rdata = 0x%llx tag = 0x%x\n",
			fmt, chan, address, (greg_recovery) ? "greg" : "radr",
			greg_num_d, val, tag);
	}
}

static enum exec_mmu_ret do_recovery_load(struct pt_regs *regs,
		trap_cellar_t *tcellar, trap_cellar_t *next_tcellar, int zeroing,
		unsigned long address, unsigned long address_hi_hva,
		unsigned long radr, int fmt, int chan, unsigned greg_recovery,
		unsigned greg_num_d, e2k_addr_t *adr, unsigned long hva_page_offset)
{
	ldst_rec_op_t	ld_rec_opc;
	unsigned	vr = AS(tcellar->condition).vr;
	int next_fmt, ldrd_fmt;
#ifdef	CONFIG_ACCESS_CONTROL
	e2k_upsr_t	upsr_to_save;
#endif
	bool aligned_16 = IS_ALIGNED(address, 16), q_load, qp_load,
	     atomic_qp_load, atomic_q_load, atomic_load;

	qp_load = (fmt == LDST_QP_FMT || fmt == TC_FMT_QPWORD_Q);
	q_load = (fmt == LDST_QWORD_FMT || fmt == TC_FMT_QWORD_QP);
	atomic_qp_load = (cpu_has(CPU_FEAT_ISET_V6) && aligned_16 && qp_load);

	/* FILL RF without FX is done with LDST_QWORD_FMT but
	 * with next_tcellar->address == tcellar->address + 16.
	 * Do not try to repeat this atomically. */
	next_fmt = next_tcellar ? TC_COND_FMT_FULL(next_tcellar->condition) : -1;
	atomic_q_load = (cpu_has(CPU_FEAT_ISET_V6) && aligned_16 && q_load &&
			 (chan == 0 || chan == 2) && next_fmt == fmt &&
			 (next_tcellar->address % 16) == 8);

	atomic_load = (atomic_q_load || atomic_qp_load);

	if (DEBUG_EXEC_MMU_OP && radr) {
		u64	val;
		u8	tag;

		if (greg_recovery) {
			E2K_GET_DGREG_VAL_AND_TAG(greg_num_d, val, tag);
		} else {
			load_value_and_tagd((void *) radr,
					&val, &tag);
		}

		DbgEXMMU("load from register file background register value 0x%llx tag 0x%x\n",
			val, tag);
	}

	/*
	 * #74018 Do not execute load operation if rp_ret != 0
	 */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (unlikely(regs->trap->flags & TRAP_RP_FLAG)) {
		DbgEXMMU("do_recovery_load: rp_ret != 0\n");
		return EXEC_MMU_SUCCESS;
	}
#endif

	if (zeroing) {
		if (!greg_recovery && radr)
			store_tagged_dword((void *) radr, 0ULL, 0);

		return EXEC_MMU_SUCCESS;
	}

	if (cpu_has(CPU_FEAT_ISET_V6) && q_load && (address % 16 == 8) &&
			(chan == 1 || chan == 3)) {
		/*
		 * Second part of an atomic quadro load which takes
		 * up 2 records in cellar, actual memory access has
		 * been done already when handling the first record.
		 *
		 * We only support atomic quadro loads since iset v6
		 * because we have to distinguish between ldrd/strd
		 * with fmtr="qword" and real quadro loads.
		 */
		return EXEC_MMU_SUCCESS;
	}

	/* BUG 79642: ignore AS(tcellar->condition).empt field */
	AW(ld_rec_opc) = 0;
	ld_rec_opc.mas = get_recovery_mas(tcellar->condition, fmt);
	ld_rec_opc.prot = !(AS(tcellar->condition).npsp);
	ld_rec_opc.root = AS(tcellar->condition).root;
	if (fmt == TC_FMT_QPWORD_Q || fmt == TC_FMT_DWORD_Q)
		ldrd_fmt = LDST_QWORD_FMT;
	else if (fmt == TC_FMT_QWORD_QP || fmt == TC_FMT_DWORD_QP)
		ldrd_fmt = LDST_QP_FMT;
	else
		ldrd_fmt = fmt & 0x7;
	ld_rec_opc.fmt = ldrd_fmt;
	ld_rec_opc.fmt_h = !!atomic_load;

	ACCESS_CONTROL_DISABLE_AND_SAVE(upsr_to_save);

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (is_MLT_mas(ld_rec_opc)) {
		struct thread_info *ti = current_thread_info();
		u64 cr0_hi = AS_WORD(regs->crs.cr0_hi);

		WARN_ON(cr0_hi < ti->rp_start || cr0_hi >= ti->rp_end);
		regs->trap->flags |= TRAP_RP_FLAG;
	}
#endif

#ifdef CONFIG_PROTECTED_MODE
	if (adr)
		*adr = radr;
#endif

	if (!greg_recovery) {
		/* Load to %r/%b register - move data
		 * to register location in memory */
		unsigned long reg_address, reg_address_hi;
		u64 fake_reg[2] __aligned(16);

		reg_address = radr ?: (unsigned long) fake_reg;

		if (!cpu_has(CPU_FEAT_QPREG) || qp_load)
			reg_address_hi = reg_address + 8;
		else
			reg_address_hi = reg_address + 16;

		if (likely(!hva_page_offset)) {
			recovery_faulted_move(address, reg_address,
					reg_address_hi, vr, AW(ld_rec_opc),
					chan, qp_load, atomic_load, 1,
					tcellar->condition);
		} else {
			recovery_load_with_bytes(address, address_hi_hva,
					hva_page_offset, reg_address,
					reg_address_hi, vr, ld_rec_opc, chan,
					tc_cond_to_size(tcellar->condition),
					tcellar->condition);
		}
	} else {
		/* Load to %g register */
		u64 *saved_greg_lo = NULL, *saved_greg_hi = NULL;

		if (KERNEL_GREGS_MASK != 0 &&
				(KERNEL_GREGS_MASK & (1UL << greg_num_d))) {
			saved_greg_lo = current_thread_info()->k_gregs.g[
				    greg_num_d - KERNEL_GREGS_PAIRS_START].xreg;
		} else if (is_guest_kernel_gregs(current_thread_info(),
						 greg_num_d, &saved_greg_lo)) {
			BUG_ON(saved_greg_lo == NULL);
		} else {
			saved_greg_lo = NULL;
		}
		if (saved_greg_lo) {
			if (!atomic_q_load)
				saved_greg_hi = &saved_greg_lo[1];
			else
				saved_greg_hi = &saved_greg_lo[2];
		}
		if (likely(!hva_page_offset)) {
			recovery_faulted_load_to_greg(address, greg_num_d, vr,
					AW(ld_rec_opc), chan, qp_load,
					atomic_load, saved_greg_lo,
					saved_greg_hi, tcellar->condition);
		} else {
			u64 tmp[2] __aligned(16);
			recovery_load_with_bytes(address, address_hi_hva, hva_page_offset,
					(unsigned long) (saved_greg_lo ?: &tmp[0]),
					(unsigned long) (saved_greg_hi ?: &tmp[1]),
					vr, ld_rec_opc, chan,
					tc_cond_to_size(tcellar->condition),
					tcellar->condition);
			if (!saved_greg_lo) {
				recovery_faulted_load_to_greg(
						(unsigned long) tmp,
						greg_num_d, vr,
						AW(ld_rec_opc), chan, qp_load,
						atomic_load, NULL, NULL,
						tcellar->condition);
			}
		}
	}

	ACCESS_CONTROL_RESTORE(upsr_to_save);

	debug_print_recovery_load(address, fmt, radr, chan, greg_recovery,
			greg_num_d, ld_rec_opc);

	/* Make sure we finished recovery operations before reading flags */
	E2K_CMD_SEPARATOR;

	/* Nested exception appeared while do_recovery_load() */
	if (regs->flags.exec_mmu_op_nested) {
		regs->flags.exec_mmu_op_nested = 0;

		if (fatal_signal_pending(current))
			return EXEC_MMU_STOP;
		else
			return EXEC_MMU_REPEAT;
	}

	return EXEC_MMU_SUCCESS;
}

static inline bool
check_spill_fill_recovery(tc_cond_t cond, e2k_addr_t address, bool s_f,
				struct pt_regs *regs)
{
	bool store;

	store = AS(cond).store;
	if (unlikely(AS(cond).s_f || s_f)) {
		e2k_addr_t stack_base;
		e2k_size_t stack_ind;

		/*
		 * Not completed SPILL operation should be completed here
		 * by data store
		 * Not completed FILL operation replaced by restore of saved
		 * filling data in trap handler
		 */

		DbgEXMMU("completion of %s %s operation\n",
			(AS(cond).sru) ? "PCS" : "PS",
			(store) ? "SPILL" : "FILL");
		if (AS(cond).sru) {
			stack_base = regs->stacks.pcsp_lo.PCSP_lo_base;
			stack_ind = regs->stacks.pcsp_hi.PCSP_hi_ind;
		} else {
			stack_base = regs->stacks.psp_lo.PSP_lo_base;
			stack_ind = regs->stacks.psp_hi.PSP_hi_ind;
		}
		if (address < stack_base || address >= stack_base + stack_ind) {
			printk("%s(): invalid hardware stack addr 0x%lx < "
				"stack base 0x%lx or >= current stack "
				"offset 0x%lx\n",
				__func__, address, stack_base,
				stack_base + stack_ind);
			BUG();
		}
		if (!store && !AS(cond).sru) {
			printk("execute_mmu_operations(): not completed PS FILL operation detected in TC (only PCS FILL operation can be dropped to TC)\n");
			BUG();
		}
		return true;
	}
	return false;
}

static enum exec_mmu_ret convert_pv_gva_to_hva(unsigned long *address_hva_p,
		unsigned long address, size_t size, const struct pt_regs *regs)
{
	void *address_hva = guest_ptr_to_host((void *) address, size, regs);

	if (unlikely(IS_ERR(address_hva))) {
		pr_err("%s(): could not convert page fault addr 0x%lx "
			"to recovery format, error %ld\n",
			__func__, address, PTR_ERR(address_hva));
		if (PTR_ERR(address_hva) == -EAGAIN)
			return EXEC_MMU_REPEAT;
		else
			return EXEC_MMU_STOP;
	}

	*address_hva_p = (unsigned long) address_hva;

	return EXEC_MMU_SUCCESS;
}

enum exec_mmu_ret execute_mmu_operations(trap_cellar_t *tcellar,
		trap_cellar_t *next_tcellar, struct pt_regs *regs,
		int zeroing, e2k_addr_t *adr,
		bool (*is_spill_fill_recovery)(tc_cond_t cond,
					e2k_addr_t address, bool s_f,
					struct pt_regs *regs),
		enum exec_mmu_ret (*calculate_rf_frame)(struct pt_regs *regs,
					tc_cond_t cond, u64 **radr,
					bool *load_to_rf))
{
	unsigned long	flags, hva_page_offset = 0;
	tc_cond_t	cond = tcellar->condition;
	e2k_addr_t	address = tcellar->address, address_hi;
	int		chan, store, fmt, ret;
	bool		is_s_f;

	DbgEXMMU("started\n");
	DebugPtR(regs);

#ifdef CONFIG_PROTECTED_MODE
	/*
	 * for multithreading of protected mode
	 * (It needs to know address of register in chain stack
	 * to change SAP to AP for other threads)
	 */
	if (adr)
		*adr = 0;
#endif /* CONFIG_PROTECTED_MODE */

	regs->flags.exec_mmu_op = 1;

	fmt = TC_COND_FMT_FULL(cond);
	BUG_ON(fmt == 6 || fmt == 0 || fmt > 7 && fmt < 0xd || fmt == 0xe ||
	       fmt >= 0x10 && fmt < 0x14 || fmt >= 0x16 && fmt <= 0x1e ||
	       fmt >= 0x20);

	/*
	 * If ld/st hits to page boundary page, page fault can occur on first
	 * or on second page. If page fault occurs on second page, we need to
	 * correct addr. In this case addr points to the end of touched area.
	 */
	if (AS(cond).num_align) {
		if (fmt != LDST_QP_FMT && fmt != TC_FMT_QPWORD_Q)
			address -= 8;
		else
			address -= 16;
	}

	store = AS(cond).store;

	/*
	 * 1) In some case faulted address should be converted to some other
	 * one to enable recovery on the current MMU context.  For example,
	 * the source paravirtualized guest faulted address should be converted
	 * to host user address mapped to: gva <-> hva
	 * 2) Guest user's loads and stores also can land on a page boundary
	 * and cause a page fault on guest's page table.  After fixing the
	 * page table a hypercall is invoked to repeat the operation, and
	 * it is possible that hypercall will have to access not adjacent
	 * HVA pages.  We could support this in hypercalls, but reusing
	 * code from 1) above is simpler (does not require duplicating
	 * functionality).
	 */
	if (host_test_intc_emul_mode(regs) && !(tcellar->flags & TC_IS_HVA_FLAG) ||
			IS_ENABLED(CONFIG_KVM_GUEST_KERNEL)) {
		unsigned long address_lo_hva;
		int size = tc_cond_to_size(cond);
		int size_lo = min(PAGE_SIZE - offset_in_page(address), size);
		ret = convert_pv_gva_to_hva(&address_lo_hva, address, size_lo, regs);
		if (ret != EXEC_MMU_SUCCESS)
			return ret;

		/*
		 * Check if ls/st really hits at page boundary.  If guest ld/st hits
		 * at page boundary, gva may point to non-contigious area on the host
		 * side.  So we need to split operation into two steps:
		 * 1. execute ld/st of low part of tcellar->data to the 1st page
		 * 2. execute ld/st of high part of tcellar->data to the 2nd page
		 */
		if (pf_on_page_boundary(address, cond) &&
		    !is_spurious_qp_store(store, address, fmt, tcellar->mask, NULL)) {
			unsigned long address_hi_hva;
			ret = convert_pv_gva_to_hva(&address_hi_hva,
					PAGE_ALIGN(address), size - size_lo, regs);
			if (ret != EXEC_MMU_SUCCESS)
				return ret;

			address_hi = address_hi_hva;
			hva_page_offset = size_lo;
		}

		address = address_lo_hva;
	}

	if (likely(is_spill_fill_recovery == NULL)) {
		is_s_f = check_spill_fill_recovery(cond, tcellar->address,
						IS_SPILL(tcellar[0]), regs);
	} else {
		is_s_f = is_spill_fill_recovery(cond, address,
						IS_SPILL(tcellar[0]), regs);
	}
	if (is_s_f)
		store = 1;

	chan = AS(cond).chan;
	BUG_ON((unsigned int) chan > 3 || store && !(chan & 1));


	raw_all_irq_save(flags);
	if (store) {
		/*
		 * Here performs dropped store operation, opcode.fmt contains
		 * size of data that must be stored, address it's address where
		 * data must be stored, data is data ;-) 
		 */
		ret = do_recovery_store(regs, tcellar, next_tcellar, address,
				address_hi, fmt, chan, hva_page_offset);
	} else {
		/*
		 * Here we perform a load operation which is more difficult
		 * than store, we know only the register's number in interrupted
		 * frame, so we need to SPILL register file to memory and then
		 * find the needed register in it; only then perform operation.
		 */
		unsigned	greg_num_d = -1;
		bool		greg_recovery = false;
		bool		rotatable_greg = false;
		bool		load_to_rf = false;
		u64		*radr;
		e2k_bgr_t	src_bgr;

		ret = calculate_recovery_load_parameters(regs, cond,
				&greg_num_d, &greg_recovery,
				&rotatable_greg, &src_bgr, &radr);
		if (ret < 0) {
			if (likely(calculate_rf_frame == NULL)) {
				ret = calculate_recovery_load_to_rf_frame(regs,
						cond, &radr, &load_to_rf);
			} else {
				ret = calculate_rf_frame(regs,
						cond, &radr, &load_to_rf);
			}
		}

		if (!ret) {
			if (load_to_rf)
				COPY_STACKS_TO_MEMORY();
			ret = do_recovery_load(regs, tcellar, next_tcellar,
					zeroing, address, address_hi,
					(unsigned long) radr, fmt, chan,
					greg_recovery, greg_num_d,
					adr, hva_page_offset);

			/*
			 * Restore BGR register to recover rotatable state
			 */
			if (rotatable_greg)
				write_BGR_reg(src_bgr);
		}
	}

	raw_all_irq_restore(flags);

	regs->flags.exec_mmu_op = 0;
	regs->flags.exec_mmu_op_nested = 0;

	return ret;
}
