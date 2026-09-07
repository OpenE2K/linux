/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
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
#include <linux/pgtable.h>
#include <linux/kfence.h>

#include <asm/compat.h>
#include <asm/cpu_regs.h>
#include <asm/getsp_adj.h>
#include <asm/kfence.h>
#include <asm/mmu_regs.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/siginfo.h>
#include <asm/signal.h>
#include <asm/processor.h>
#include <asm/process.h>
#include <asm/hardirq.h>
#include <asm/mmu.h>
#include <asm/traps.h>
#include <asm/trap_cellar.h>
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


#include <asm/trace.h>

/**************************** DEBUG DEFINES *****************************/

#define	DEBUG_TRAP_CELLAR	0	/* Trap cellar */
#define DbgTC(...)		DebugPrint(DEBUG_TRAP_CELLAR, ##__VA_ARGS__)

#define	DEBUG_PF_MODE		0	/* Page fault */
#define DebugPF(...)		DebugPrint(DEBUG_PF_MODE, ##__VA_ARGS__)

#undef	DEBUG_HS_MODE
#undef	DebugHS
#define	DEBUG_HS_MODE		0	/* Expand Hard Stack */
#define DebugHS(...)		DebugPrint(DEBUG_HS_MODE, ##__VA_ARGS__)

#undef	DEBUG_US_EXPAND
#undef	DebugUS
#define	DEBUG_US_EXPAND		0	/* User stacks */
#define DebugUS(...)		DebugPrint(DEBUG_US_EXPAND, ##__VA_ARGS__)

#undef	DEBUG_USER_PTE_MODE
#undef	DebugUPTE
#define	DEBUG_USER_PTE_MODE	0
#define DebugUPTE(...)		DebugPrint(DEBUG_USER_PTE_MODE, ##__VA_ARGS__)

#define	DEBUG_NAO_MODE		0	/* Not aligned operation */
#define DebugNAO(...)		DebugPrint(DEBUG_NAO_MODE, ##__VA_ARGS__)

#define	DEBUG_EXEC_MMU_OP	0
#define DbgEXMMU(...)		DebugPrint(DEBUG_EXEC_MMU_OP, ##__VA_ARGS__)

#undef	DEBUG_CLW_FAULT
#undef	DebugCLW
#define	DEBUG_CLW_FAULT		0
#define DebugCLW(...)		DebugPrint(DEBUG_CLW_FAULT, ##__VA_ARGS__)

#undef	DEBUG_SRP_FAULT
#undef	DebugSRP
#define	DEBUG_SRP_FAULT	        0
#define DebugSRP(...)		DebugPrint(DEBUG_SRP_FAULT, ##__VA_ARGS__)

#undef	DEBUG_RPR
#undef	DebugRPR
#define	DEBUG_RPR		0	/* Recovery point register */
#define DebugRPR(...)		DebugPrint(DEBUG_RPR, ##__VA_ARGS__)

#undef	DEBUG_KVM_PAGE_FAULT_MODE
#undef	DebugKVMPF
#define	DEBUG_KVM_PAGE_FAULT_MODE	0	/* KVM page fault debugging */
#define DebugKVMPF(...)		DebugPrint(DEBUG_KVM_PAGE_FAULT_MODE, ##__VA_ARGS__)

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

static int __debug_pagefault_setup(char *str)
{
	if (!strncmp(str, "off", 3))
		debug_pagefault = SIG_PF_DEBUG_OFF;
	else if (!strncmp(str, "all", 3))
		debug_pagefault = SIG_PF_DEBUG_ALL;
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	else if (!strncmp(str, "nobincomp", 9))
		debug_pagefault = SIG_PF_DEBUG_NOBINCOMP;
#endif
	else if (!strncmp(str, "1", 1))
		debug_pagefault = SIG_PF_DEBUG_ALL;

	return 1;
}

int debug_pagefault = SIG_PF_DEBUG_OFF;
static int debug_pagefault_setup(char *str)
{
	if (strlen(str) == 0) {
		debug_pagefault = SIG_PF_DEBUG_ALL;
		return 1;
	}

	if (!strncmp(str, "=", 1))
		str++;

	return __debug_pagefault_setup(str);
}
__setup("debug_pagefault", debug_pagefault_setup);

int proc_debug_pagefault_handler(struct ctl_table *ctl, int write, void *buffer, size_t *lenp,
				 loff_t *ppos)
{
	return proc_sig_pf_debug_handler(ctl, write, buffer, lenp, ppos,
			__debug_pagefault_setup, debug_pagefault);
}

typedef union pf_mode {
	struct {
		u32 write		: 1;
		u32 exec		: 1;
		u32 spec		: 1;
		u32 user		: 1;
		u32 root		: 1;
		u32 empty		: 1;
		u32 priv		: 1;
		/* Proper user access from kernel: get_user, copy_to_user, ... */
		u32 controlled_user_access : 1;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		u32 as_kvm_injected	: 1;
		u32 as_kvm_passed	: 1;
		u32 as_kvm_copy_user	: 1;
		u32 host_dont_inject	: 1;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	};
	u32 word;
} pf_mode_t;

int show_unhandled_signals = 0;

/********************* END of PAGE FAULT DEBUG for users *****************/

e2k_addr_t user_address_to_pva(struct task_struct *tsk, e2k_addr_t address)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	e2k_addr_t offset;
	e2k_addr_t ret;
	struct vm_area_struct *vma;
	bool already_locked = false;

	ret = check_is_user_address(tsk, address);
	if (ret != 0)
		return ret;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (unlikely(IS_GUEST_USER_ADDRESS_TO_PVA(tsk, address))) {
		return guest_user_address_to_pva(tsk, address);
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	if (!mmap_read_trylock(tsk->mm))
		already_locked = true;

	vma = find_vma(tsk->mm, untagged_addr(address));
	if (vma == NULL) {
		pr_err("Could not find VMA structure of user virtual memory area: addr 0x%lx\n",
			address);
		goto out;
	}

	pgd = pgd_offset(vma->vm_mm, address);
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		BUG();
	}

	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d) || p4d_bad(*p4d)) {
		pr_err("PGD  0x%px = 0x%lx none or bad for address 0x%lx\n",
		       pgd, pgd_val(*pgd), address);
		goto out;
	}

	pud = pud_offset(p4d, address);
	if (user_pud_huge(*pud)) {
		return (unsigned long)__va((pud_pfn(*pud) << PAGE_SHIFT) |
					   (address & ~PUD_MASK));
	}
	if (pud_none(*pud) || pud_bad(*pud)) {
		pr_err("PUD  0x%px = 0x%lx none or bad for address 0x%lx\n",
		       pud, pud_val(*pud), address);
		goto out;
	}

	pmd = pmd_offset(pud, address);
	if (user_pmd_huge(*pmd)) {
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
		mmap_read_unlock(tsk->mm);
	return (e2k_addr_t) __va((pte_pfn(*pte) << PAGE_SHIFT) | offset);

out:
	if (!already_locked)
		mmap_read_unlock(tsk->mm);
	return -1;
}

pte_t *get_user_address_pte(struct vm_area_struct *vma, e2k_addr_t address)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (address < vma->vm_start || address >= vma->vm_end) {
		DebugUPTE("User address 0x%lx is  not from VMA start 0x%lx end 0x%lx\n",
			address, vma->vm_start, vma->vm_end);
		return NULL;
	}

	pgd = pgd_offset(vma->vm_mm, address);
	if (pgd_none(*pgd) && pgd_valid(*pgd)) {
		BUG();
	}
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		BUG();
	}

	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d) && p4d_valid(*p4d)) {
		DebugUPTE("PGD  0x%px = 0x%lx only valid for address 0x%lx\n",
			  pgd, pgd_val(*pgd), address);
		return (pte_t *) pgd;
	}
	if (p4d_none(*p4d) || p4d_bad(*p4d)) {
		DebugUPTE("PGD  0x%px = 0x%lx none or bad for address 0x%lx\n",
			  pgd, pgd_val(*pgd), address);
		return NULL;
	}

	pud = pud_offset(p4d, address);
	if (user_pud_huge(*pud))
		return (pte_t *) pud;
	if (pud_none(*pud) && pud_valid(*pud)) {
		DebugUPTE("PUD  0x%px = 0x%lx only valid for address 0x%lx\n",
			  pud, pud_val(*pud), address);
		return (pte_t *) pud;
	}
	if (pud_none(*pud) || pud_bad(*pud)) {
		DebugUPTE("PUD  0x%px = 0x%lx none or bad for address 0x%lx\n",
			  pud, pud_val(*pud), address);
		return NULL;
	}

	pmd = pmd_offset(pud, address);
	if (user_pmd_huge(*pmd))
		return (pte_t *) pmd;
	if (pmd_none(*pmd) && pmd_valid(*pmd)) {
		DebugUPTE("PMD 0x%px = 0x%016lx only valid for address 0x%016lx\n",
			pmd, pmd_val(*pmd), address);
		return (pte_t *) pmd;
	}
	if (pmd_none(*pmd) || pmd_bad(*pmd)) {
		DebugUPTE("PMD 0x%px = 0x%016lx none or bad for address 0x%016lx\n",
			pmd, pmd_val(*pmd), address);
		return NULL;
	}

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
e2k_addr_t kernel_address_to_pva(e2k_addr_t address)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	e2k_size_t page_size;

	if (IS_USER_ADDR(address)) {
		pr_alert("Address 0x%016lx is not kernel address o get PFN's\n",
			address);
		return -1;
	}
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (unlikely(IS_GUEST_ADDRESS_TO_HOST(address))) {
		if (address >= KERNEL_BASE && address <= KERNEL_END) {
			return __pa_symbol(address);
		} else {
			pr_alert("Address 0x%016lx is host kernel address\n",
				 address);
			return -1;
		}
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	pgd = pgd_offset_k(address);
	if (pgd_none_or_clear_bad(pgd)) {
		BUG();
	}
	if (kernel_pgd_huge(*pgd)) {
		BUG();
	}

	p4d = p4d_offset(pgd, address);
	if (p4d_none_or_clear_bad(p4d)) {
		pr_alert("PGD  0x%px = 0x%016lx none or bad for address 0x%016lx\n",
		     pgd, pgd_val(*pgd), address);
		return -1;
	}
	if (kernel_p4d_huge(*p4d)) {
		pte = (pte_t *) pgd;
		page_size = get_pgd_level_page_size();
		goto huge_pte;
	}

	pud = pud_offset(p4d, address);
	if (kernel_pud_huge(*pud)) {
		pte = (pte_t *) pud;
		page_size = get_pud_level_page_size();
		goto huge_pte;
	}
	if (pud_none_or_clear_bad(pud)) {
		pr_alert("PUD 0x%px = 0x%016lx none or bad for address 0x%016lx\n",
		     pud, pud_val(*pud), address);
		return -1;
	}

	pmd = pmd_offset(pud, address);
	if (kernel_pmd_huge(*pmd)) {
		pte = (pte_t *) pmd;
		page_size = get_pmd_level_page_size();
		goto huge_pte;
	}
	if (pmd_none_or_clear_bad(pmd)) {
		pr_alert("PMD 0x%px = 0x%016lx none or bad for address 0x%016lx\n",
		     pmd, pmd_val(*pmd), address);
		return -1;
	}

	pte = pte_offset_kernel(pmd, address);
	page_size = get_pte_level_page_size();
huge_pte:
	if (pte_none(*pte)) {
		pr_alert("PTE  0x%px:0x%016lx none for address 0x%016lx\n",
			 pte, pte_val(*pte), address);
		return -1;
	}
	if (!pte_present(*pte)) {
		pr_alert("PTE  0x%px = 0x%016lx is pte of swaped page for address 0x%016lx\n",
			pte, pte_val(*pte), address);
		return -1;
	}
	return (e2k_addr_t) __va((pte_pfn(*pte) << PAGE_SHIFT) |
				 (address & (page_size - 1)));
}

phys_addr_t pgd_kernel_address_to_phys(pgd_t *pgd, e2k_addr_t addr)
{
	phys_addr_t phys_addr;
	e2k_size_t page_size;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (unlikely(pgd_none_or_clear_bad(pgd))) {
		BUG();
	}
	if (kernel_pgd_huge(*pgd)) {
		BUG();
	}

	p4d = p4d_offset(pgd, addr);

	if (unlikely(p4d_none_or_clear_bad(p4d))) {
		pr_alert("node_kernel_address_to_phys(): pgd_none\n");
		return -EINVAL;
	}
	if (kernel_p4d_huge(*p4d)) {
		pte = (pte_t *) pgd;
		page_size = get_pgd_level_page_size();
		goto huge_pte;
	}

	pud = pud_offset(p4d, addr);
	if (kernel_pud_huge(*pud)) {
		pte = (pte_t *) pud;
		page_size = get_pud_level_page_size();
		goto huge_pte;
	}
	if (unlikely(pud_none_or_clear_bad(pud))) {
		pr_alert("node_kernel_address_to_phys(): pud_none\n");
		return -EINVAL;
	}

	pmd = pmd_offset(pud, addr);
	if (kernel_pmd_huge(*pmd)) {
		pte = (pte_t *) pmd;
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

	phys_addr = _PAGE_PFN_TO_PADDR(pte_val(*pte)) + (addr & (page_size - 1));

	return phys_addr;
}

phys_addr_t node_kernel_address_to_phys(int node, e2k_addr_t addr)
{
	pgd_t *pgd = node_pgd_offset_k(node, addr);

	return pgd_kernel_address_to_phys(pgd, addr);
}

static const char *get_memory_type_string(pte_t pte)
{
	char *memory_types_v6[8] = { "General Cacheable",
		"General nonCacheable", "Reserved-2", "Reserved-3",
		"External Prefetchable", "Reserved-5",
		"External nonPrefetchable", "External Configuration"
	};

	if (MMU_IS_PT_V6())
		return memory_types_v6[_PAGE_MT_GET_VAL(pte_val(pte))];

	if (!pte_present(pte))
		return "";

	if ((pte_val(pte) & _PAGE_CD_MASK_V3) != _PAGE_CD_MASK_V3)
		return "cacheable";

	if ((pte_val(pte) & _PAGE_PWT_V3))
		return "uncacheable";
	else
		return "write_combine";
}

void print_address_ptes(pgd_t *pgd, e2k_addr_t address, int kernel)
{
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	e2k_size_t page_size;
	const char *level_name = "PTE";

	if (kernel && kernel_pgd_huge(*pgd)) {
		BUG();
	}
	if (pgd_none(*pgd) && (kernel || !pgd_valid(*pgd)) || pgd_bad(*pgd)) {
		BUG();
	}
	if (pgd_none(*pgd))
		BUG();

	p4d = p4d_offset(pgd, address);
	if (kernel && kernel_p4d_huge(*p4d)) {
		pte = (pte_t *) pgd;
		page_size = get_pgd_level_page_size();
		level_name = "HUGE PGD";
		goto huge_pte;
	}
	if (p4d_none(*p4d) && (kernel || !p4d_valid(*p4d)) || p4d_bad(*p4d)) {
		pr_alert("%s PGD  0x%px = 0x%016lx none or bad for address 0x%016lx\n",
			 (kernel) ? "kernel" : "user", pgd, pgd_val(*pgd),
			 address);
		return;
	}
	pr_alert("%s PGD 0x%px = 0x%016lx valid for address 0x%016lx\n",
		 (kernel) ? "kernel" : "user", pgd, pgd_val(*pgd), address);
	if (p4d_none(*p4d))
		return;

	pud = pud_offset(p4d, address);
	if (kernel && kernel_pud_huge(*pud)) {
		pte = (pte_t *) pud;
		page_size = get_pud_level_page_size();
		level_name = "HUGE PUD";
		goto huge_pte;
	}
	if (pud_none(*pud) && (kernel || !pud_valid(*pud)) || pud_bad(*pud)) {
		pr_alert("PUD 0x%px = 0x%016lx none or bad for address 0x%016lx\n",
			pud, pud_val(*pud), address);
		return;
	}
	pr_alert("PUD 0x%px = 0x%016lx valid for address 0x%016lx\n",
		 pud, pud_val(*pud), address);
	if (pud_none(*pud))
		return;

	pmd = pmd_offset(pud, address);
	if (kernel && kernel_pmd_huge(*pmd) || !kernel && user_pmd_huge(*pmd)) {
		pte = (pte_t *) pmd;
		page_size = get_pmd_level_page_size();
		level_name = "HUGE PMD";
		goto huge_pte;
	}
	if (pmd_none(*pmd) && (kernel || !pmd_valid(*pmd)) || pmd_bad(*pmd)) {
		pr_alert("PMD 0x%px = 0x%016lx none or bad for address 0x%016lx\n",
			pmd, pmd_val(*pmd), address);
		return;
	}
	pr_alert("PMD 0x%px = 0x%016lx valid for address 0x%016lx\n",
		 pmd, pmd_val(*pmd), address);
	if (pmd_none(*pmd))
		return;

	pte = (kernel) ?
	    pte_offset_kernel(pmd, address) : pte_offset_map(pmd, address);
	page_size = get_pte_level_page_size();

huge_pte:
	pr_alert("%s 0x%px = 0x%016lx %s for address 0x%lx %s\n", level_name,
		 pte, pte_val(*pte),
		 (pte_none(*pte)) ? "none" :
		 (!pte_present(*pte)) ? "not present" :
		 (pte_protnone(*pte)) ? "valid & not present (migrate)" :
		 (pte_valid(*pte)) ? "valid" : "not valid",
		 address, get_memory_type_string(*pte));
}

void print_vma_and_ptes(struct vm_area_struct *vma, e2k_addr_t address)
{
	pgd_t *pgdp;

	pr_info("VMA 0x%px : start 0x%016lx, end 0x%016lx, flags 0x%lx, prot 0x%016lx\n",
	       vma, vma->vm_start, vma->vm_end, vma->vm_flags,
	       pgprot_val(vma->vm_page_prot));

	pgdp = pgd_offset(vma->vm_mm, address);
	print_address_ptes(pgdp, address, 0);
}

static e2k_addr_t
__print_user_address_ptes(struct mm_struct *mm, e2k_addr_t address)
{
	pgd_t *pgdp;
	e2k_addr_t pa = 0;

	if (mm) {
		pgdp = pgd_offset(mm, address);
		print_address_ptes(pgdp, address, 0);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		/* Only for guest: print ptes of guest user address on host. */
		/* Guest page table is pseudo PT and only host PT is used */
		/* to translate any guest addresses */
		print_host_user_address_ptes(mm, address);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	}
	return pa;
}

e2k_addr_t print_user_address_ptes(struct mm_struct *mm, e2k_addr_t address)
{
	if (address >= TASK_SIZE) {
		pr_alert
		    ("Address 0x%016lx is not user address to print PTE's\n",
		     address);
		return 0;
	}
	return __print_user_address_ptes(mm, address);
}

void print_kernel_address_ptes(e2k_addr_t address)
{
	int node, index = pgd_index(address);
	bool is_duplicated = is_duplicated_address(address);

	if (IS_USER_ADDR(address)) {
		pr_info("Address 0x%016lx is not kernel address to print PTE's\n", address);
		return;
	}

	for_each_node_mm_pgdmask(node, &init_mm) {
		pgd_t *node_pgd = mm_node_pgd(&init_mm, node) + index;

		if (is_duplicated && num_node_state(N_MEMORY) > 1)
			pr_info("NODE #%d kernel page table:\n", node);

		print_address_ptes(node_pgd, address, 1);

		if (!is_duplicated)
			break;
	}
}

void print_address_page_tables(unsigned long address, int last_level_only)
{
	struct mm_struct *mm = current->mm;

	if (IS_USER_ADDR(address))
		print_user_address_ptes(mm, address);
	else
		print_kernel_address_ptes(address);

	if (last_level_only)
		return;

	if (IS_USER_ADDR(address)) {
		print_user_address_ptes(mm, pte_virt_offset(round_down(address, PTE_SIZE)));
		print_user_address_ptes(mm, pmd_virt_offset(round_down(address, PMD_SIZE)));
		print_user_address_ptes(mm, pud_virt_offset(round_down(address, PUD_SIZE)));
	} else {
		print_kernel_address_ptes(pte_virt_offset(round_down(address, PTE_SIZE)));
		print_kernel_address_ptes(pmd_virt_offset(round_down(address, PMD_SIZE)));
		print_kernel_address_ptes(pud_virt_offset(round_down(address, PUD_SIZE)));
	}
}

phys_addr_t e2k_virt_to_phys(const void *kaddrp)
{
	unsigned long kaddr = (unsigned long) kaddrp;

	if (is_vmalloc_addr(kaddrp))
		return page_to_phys(vmalloc_to_page(kaddrp)) + offset_in_page(kaddrp);
	if (IS_USER_ADDR(kaddr))
		panic("%s(): address 0x%px is not kernel address\n", __func__, kaddrp);

	if (kaddr >= PAGE_OFFSET && kaddr < PAGE_OFFSET + MAX_PM_SIZE ||
	    kaddr >= KERNEL_BASE && kaddr < KERNEL_END)
		return __pa(kaddrp);

	panic("%s(): address 0x%px is invalid kernel address\n", __func__, kaddrp);
}

int apply_usd_delta_to_signal_stack(unsigned long top, unsigned long delta_sp, bool incr,
				    unsigned long *chain_stack_border)
{
	struct pt_regs __priv *u_regs;
	int regs_num = 0, ret = 0;

	DebugUS("stack top 0x%lx, delta_sp 0x%lx, incr %d\n", top, delta_sp, incr);
	DebugUS("signal_stack used 0x%lx, size 0x%lx, base 0x%px\n",
		current_thread_info()->signal_stack.used, current_thread_info()->signal_stack.size,
		current_thread_info()->signal_stack.base);

	signal_pt_regs_for_each(u_regs) {
		unsigned long u_top, u_bottom;
		e2k_usd_t usd;

		if (get_priv(u_top, &u_regs->stacks.top) ||
		    get_priv(HI(usd), &HI(u_regs->stacks.usd)) ||
		    get_priv(LO(usd), &LO(u_regs->stacks.usd))) {
			ret = -EFAULT;
			break;
		}

		u_bottom = USD_BASE(usd) - delta_sp;

		/*
		 * alt stack
		 */
		if (top > u_top || top < u_bottom) {
			e2k_pcsp_t pcsp;

			if (get_priv(LO(pcsp), &LO(u_regs->stacks.pcsp)) ||
			    get_priv(HI(pcsp), &HI(u_regs->stacks.pcsp))) {
				ret = -EFAULT;
				break;
			}
			*chain_stack_border = (unsigned long)U_PCSP_PTR(pcsp) + 0x20;
			break;
		}

		if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
			u64 new_usd_base = round_down(USD_PTR(usd) -
						(incr ? delta_sp : -delta_sp), PAGE_SIZE);
			u64 new_size = u_top - new_usd_base;

			if (new_size < AP_SIZE_ALIGN_8) {
				/* nothing to do. USD minimum alingnment 256 */
			} else if (new_size < AP_SIZE_ALIGN_PAGE) {
				/* bottom always aligned to PAGE. Align top */
				new_size = round_down(new_size, PAGE_SIZE);
			} else {
				new_size = AP_SIZE_ALIGN_PAGE;
			}

			usd = new_usd(new_usd_base, new_size,
				      USD_PTR(usd) - (incr ? delta_sp : -delta_sp) - new_usd_base);
		} else {
			usd.Ind += (incr ? delta_sp : -delta_sp);
		}

		if (put_priv(HI(usd), &HI(u_regs->stacks.usd)) ||
		    put_priv(LO(usd), &LO(u_regs->stacks.usd))) {
			ret = -EFAULT;
			break;
		}

		 /*
		  * `ussz` field has full size since iset v7 so nothing to update there
		  */
		 if (!cpu_has(CPU_FEAT_V7_CPU_REGS)) {
			e2k_cr1_t cr1;
			u64 ussz;

			if (get_priv(HI(cr1), &HI(u_regs->crs.cr1)) ||
			    get_priv(LO(cr1), &LO(u_regs->crs.cr1))) {
				ret = -EFAULT;
				break;
			}

			ussz = get_cr1_ussz(cr1);

			cr1 = set_cr1_ussz(cr1, ussz + (incr ? delta_sp : -delta_sp));

			if (put_priv(HI(cr1), &HI(u_regs->crs.cr1)) ||
			    put_priv(LO(cr1), &LO(u_regs->crs.cr1))) {
				ret = -EFAULT;
				break;
			}
		}

		++regs_num;
	}

	if (ret == 0) {
		DebugUS("%d pt_regs USD & CR1_hi.ussz were corrected to update signal stack\n",
			regs_num);
	} else {
		DebugUS("failed with error %d\n", ret);
		return ret;
	}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/*
	 * The following call is actual only for paravirtualized guest to correct signal stack on
	 * host
	 */
	ret = host_apply_usd_delta_to_signal_stack(top, delta_sp, incr);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	return ret;
}

/*
 * To increment or decrease user data stack size we need to update data stack size in the USD
 * register and in the chain registers (CR1_hi.ussz field) into all user pt_regs structures of the
 * process
 */
static int fix_all_user_stack_pt_regs(pt_regs_t *regs, u64 new_usd_base, e2k_size_t delta_sp,
				      bool incr, e2k_addr_t *chain_stack_border)
{
	int ret = 0;
	e2k_usd_t usd;

	DebugUS("started with pt_regs 0x%px, new_usd_base 0x%llx, delta sp 0x%lx, incr %d\n",
		regs, new_usd_base, delta_sp, incr);

	BUG_ON(!regs);

	usd = regs->stacks.usd;

	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		u64 new_size = regs->stacks.top - new_usd_base;

		if (new_size < AP_SIZE_ALIGN_8) {
			/* nothing to do. USD minimum alingnment 256 */
		} else if (new_size < AP_SIZE_ALIGN_PAGE) {
			/* bottom always aligned to PAGE. Align top */
			new_size = round_down(new_size, PAGE_SIZE);
		} else {
			new_size = AP_SIZE_ALIGN_PAGE;
		}

		/*
		 * new_usd ptr can show out of usd border, but after executing interrupted cmd
		 * (getsp, return) it will be in
		 */
		usd = new_usd(new_usd_base, new_size, USD_PTR(usd) - new_usd_base);
	} else {
		usd.Ind += (incr ? delta_sp : -delta_sp);
	}

	regs->stacks.usd = usd;

	/*
	 * `ussz` field has full size since iset v7 so nothing to update there
	 */
	if (!cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		e2k_cr1_t cr1 = regs->crs.cr1;
		u64 ussz = get_cr1_ussz(cr1);
		regs->crs.cr1 = set_cr1_ussz(cr1, ussz + (incr ? delta_sp : -delta_sp));
	}

	/*
	 * All other user pt_regs (except current, i.e. thread_info->pt_regs) are located in
	 * current thread's signal stack in userspace.
	 */
	ret = apply_usd_delta_to_signal_stack(regs->stacks.top, delta_sp, incr,
					      chain_stack_border);

	DebugUS("pt_regs USD & CR1_hi.ussz were corrected to update user stack sizes\n");

	return ret;
}

struct update_chain_params {
	unsigned long delta_sp;
	unsigned long prev_size;
	unsigned long corrected_size;
	unsigned long prev_frame_addr;
	e2k_mem_crs_t prev_frame;
	unsigned long chain_stack_border;
	bool incr;
};

static int update_chain_stack_ussz(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, chain_write_fn_t write_frame, void *arg)
{
	struct update_chain_params *params = arg;
	const unsigned long delta_sp = params->delta_sp;
	const bool incr = params->incr;
	u64 ussz, next_size, hw_delta, real_delta;
	int ret, correction;

	if (corrected_frame_addr < params->chain_stack_border)
		return 1;

	params->corrected_size += 0x100000000L *
			getsp_adj_get_correction(corrected_frame_addr);

	next_size = get_cr1_ussz(frame->cr1) + params->corrected_size;
	if (incr)
		next_size += delta_sp;
	else
		next_size -= delta_sp;

	hw_delta = (next_size & 0xffffffffUL) - (params->prev_size & 0xffffffffUL);
	real_delta = next_size - params->prev_size;
	params->prev_size = next_size;

	WARN_ONCE((real_delta - hw_delta) & 0xffffffffUL, "Bad data stack parameters");
	correction = (real_delta - hw_delta) >> 32UL;

	ret = getsp_adj_set_correction(correction, corrected_frame_addr);
	if (ret)
		return ret;

	if (correction) {
		if (WARN_ONCE(params->prev_frame_addr == -1UL,
				"trying to apply stack correction to the last frame\n"))
			return -ESRCH;

		params->prev_frame.cr1.lw = 1;
		ret = write_frame(params->prev_frame_addr, &params->prev_frame);
		if (ret)
			return ret;
	}

	ussz = get_cr1_ussz(frame->cr1);
	set_cr1p_ussz(&frame->cr1, ussz + (incr ? delta_sp : -delta_sp));

	ret = write_frame(real_frame_addr, frame);
	if (ret)
		return ret;

	params->prev_frame = *frame;
	params->prev_frame_addr = real_frame_addr;

	return 0;
}

static int fix_all_chain_stack_sz(e2k_size_t delta_sp, bool incr, unsigned long chain_stack_border)
{
	struct update_chain_params params;
	long ret;

	DebugUS("started with PCSP stack base 0x%lx, delta sp 0x%lx, incr %d\n",
		CURRENT_PCS_BASE(), delta_sp, incr);

	params.delta_sp = delta_sp;
	params.prev_size = 0;
	params.corrected_size = 0;
	params.prev_frame_addr = -1UL;
	params.incr = incr;
	params.chain_stack_border = chain_stack_border;

	ret = parse_chain_stack(true, false, NULL, update_chain_stack_ussz, &params);

	return (IS_ERR_VALUE(ret)) ? ret : 0;
}

/*
 * constrict_user_data_stack - handles user data stack underflow
 * @regs: pointer to pt_regs
 * @incr: value of decrement in bytes
 *
 * Returns 0 on success.
 */
int constrict_user_data_stack(struct pt_regs *regs, unsigned long incr)
{
	thread_info_t *ti = current_thread_info();
	e2k_addr_t chain_stack_border = 0;
	u64 sp, stack_size, new_usd_base;
	int ret;

	calculate_e2k_dstack_parameters(&regs->stacks, &sp, &stack_size, NULL);

	DebugUS("sp 0x%llx, free size 0x%llx, top 0x%lx, max current size 0x%lx\n",
	     sp, stack_size, ti->u_stack.top, ti->u_stack.size);

	/*
	 * We coudn't detect all underflows, but let's try to do something...
	 */
	if (ti->u_stack.top < sp + incr) {
		pr_info_ratelimited("constrict_user_data_stack(): user data stack impossible underflow: top = 0x%lx, sp = 0x%llx, incr = %lu\n",
			ti->u_stack.top, sp, incr);
		return -ENOMEM;
	}

	/*
	 * If we got here hi border of USD is page aligned delta_sp must cross page border
	 */
	new_usd_base = round_down(sp + incr, PAGE_SIZE);

	ret = fix_all_user_stack_pt_regs(regs, new_usd_base, stack_size, false,
					 &chain_stack_border);
	if (ret)
		return ret;

	if (!cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		ret = fix_all_chain_stack_sz(stack_size, false, chain_stack_border);
		if (ret) {
			pr_info_ratelimited("constrict_user_data_stack(): could not correct user stack sizes in chain stack: ret %d\n",
				ret);
			return ret;
		}
	}

	return 0;
}

/*
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
	u64 sp, new_bottom, stack_size, new_size, bottom;
	struct vm_area_struct *vma, *v, *prev;
	e2k_addr_t chain_stack_border = 0;
	MA_STATE(mas, &mm->mm_mt, 0, 0);
	int ret;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (usd_cannot_be_expanded(regs)) {
		pr_info_ratelimited("expand_user_data_stack(): data stack cannot be expanded (size fixed)\n");
		return -EINVAL;
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	calculate_e2k_dstack_parameters(&regs->stacks, &sp, &stack_size, NULL);

	DebugUS("sp 0x%llx, free size 0x%llx, top 0x%lx, max current size 0x%lx incr 0x%lx\n",
		sp, stack_size, ti->u_stack.top, ti->u_stack.size, incr);

	/*
	 * It can be if signal handler uses alternative stack and an overflow of this stack occured.
	 *
	 * This check must not return false positive if all of stack space is used
	 * (i.e. top == bottom).
	 */
	bottom = ti->u_stack.top - ti->u_stack.size;
	if ((sp > ti->u_stack.top || sp < bottom) && ti->u_stack.top != bottom) {
		if (on_sig_stack(sp))
			pr_info_ratelimited("expand_user_data_stack(): alt stack overflow\n");
		else
			pr_info_ratelimited("expand_user_data_stack(): SP of user data stack 0x%llx points out of main user stack allocated from bottom 0x%llx to top 0x%lx\n",
					sp, bottom, ti->u_stack.top);
		return -ENOMEM;
	}

	incr = min(incr, (rlimit(RLIMIT_STACK) & PAGE_MASK) - ti->u_stack.size);
	DebugUS("rlim 0x%lx, incr 0x%lx\n", rlimit(RLIMIT_STACK), incr);
	if (!incr) {
		DebugUS("out of rlim 0x%lx\n", rlimit(RLIMIT_STACK));
		return -ENOMEM;
	}

	new_bottom = sp - stack_size - incr;
	new_size = sp - new_bottom;

	/*
	 * We expand stack by pages, so assign new_bottom to page border
	 */
	if (cpu_has(CPU_FEAT_V7_CPU_REGS))
		new_bottom = round_down(new_bottom, PAGE_SIZE);

	/*
	 * While not all cases of stack underflow could be detected, there could be cases, where
	 * new_size > MAX_USD_HI_SIZE. Kernel shouldn't be broken in this case.
	 */
	if (!cpu_has(CPU_FEAT_V7_CPU_REGS) && new_size > MAX_USD_HI_SIZE)  {
		pr_info_ratelimited("expand_user_data_stack(): new_size > MAX_USD_HI_SIZE\n");
		return -ENOMEM;
	}

	if (new_bottom >= bottom)
		goto already_allocated;

	mmap_write_lock(mm);

	vma = find_extend_vma_locked(mm, new_bottom);
	if (!vma) {
		pr_info_ratelimited("expand_user_data_stack(): user data stack overflow: stack bottom 0x%llx, top 0x%lx, sp 0x%llx, free size 0x%llx\n",
				bottom, ti->u_stack.top, sp, stack_size);
		goto error_unlock;
	}

	mas_set(&mas, vma->vm_start);
	BUG_ON(mas_walk(&mas) != vma);

	v = mas_next(&mas, ULONG_MAX);
	prev = vma;

	/*
	 * Check that we didn't jump over a hole
	 */
	for (;v && v->vm_end < ti->u_stack.top; prev = v, v = mas_next(&mas, ULONG_MAX)) {
		if (unlikely(prev->vm_end != v->vm_start ||
			     ((v->vm_flags ^ prev->vm_flags) & VM_GROWSDOWN))) {
			pr_info_ratelimited("expand_user_data_stack(): jumped over a hole 0x%lx-0x%lx or inconsistent VM_GROWSDOWN flag\n",
					prev->vm_end, v->vm_start);
			goto error_unlock;
		}
	}

	DebugUS("find_extend_vma() returned VMA 0x%px, start 0x%lx, end 0x%lx\n",
		vma, vma->vm_start, vma->vm_end);

	mmap_write_unlock(mm);

already_allocated:
	/*
	 * Increment user data stack size in the USD register
	 * and in the chain registers (CR1_hi.ussz field)
	 * in all user pt_regs structures of the process.
	 */
	ret = fix_all_user_stack_pt_regs(regs, new_bottom, new_size - stack_size, true,
					 &chain_stack_border);
	if (ret)
		return ret;

	/*
	 * Correct cr1_hi.ussz fields for all functions in the PCSP
	 */
	if (!cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		ret = fix_all_chain_stack_sz(new_size - stack_size, true, chain_stack_border);
		if (ret) {
			pr_info_ratelimited("expand_user_data_stack(): could not correct user stack sizes in chain stack: ret %d\n",
				ret);
			return ret;
		}
	}

	/*
	 * Update user data stack current state info
	 */
	ti->u_stack.size += new_size - stack_size;

	DebugUS("extended stack sp 0x%llx, free size 0x%llx, top 0x%lx, max current size 0x%lx\n",
			sp, new_size, ti->u_stack.top, ti->u_stack.size);

	return 0;

error_unlock:
	mmap_write_unlock(mm);

	return -ENOMEM;
}

EXPORT_SYMBOL(expand_user_data_stack);

#if defined CONFIG_COMPAT || defined CONFIG_PROTECTED_MODE
void __user *e2k_alloc_user_data_stack(unsigned long len)
{
	struct pt_regs *regs = current_pt_regs();
	u64 sp, free_space;

	calculate_e2k_dstack_parameters(&regs->stacks, &sp, &free_space, NULL);

	if (len > free_space) {
		if (expand_user_data_stack(regs, len - free_space))
			return NULL;
	}

	return (void __user __force *)(sp - len);
}
EXPORT_SYMBOL(e2k_alloc_user_data_stack);
#endif
#if defined CONFIG_COMPAT
void __user *arch_compat_alloc_user_space(unsigned long len)
{
	return e2k_alloc_user_data_stack(len);
}
EXPORT_SYMBOL(arch_compat_alloc_user_space);
#endif

#include "linux/version.h"

#if defined CONFIG_PROTECTED_MODE
#if KERNEL_VERSION(5, 11, 0) > LINUX_VERSION_CODE
#define PROT_DIAG_MSG_BUFF_SIZE 256
void __user *arch_alloc_protected_user_space(unsigned long len,
					     const int
					     reserve_space_4_diag_msgs)
{
	unsigned long prot_len = len;

	if (reserve_space_4_diag_msgs)
		prot_len += PROT_DIAG_MSG_BUFF_SIZE;
/* NB> We use user stack area for temporal structures converted from protected ones.
 *     To avoid conflicts with diagnostic messages, we are to allocate space for message buffer.
 */
	return e2k_alloc_user_data_stack(prot_len);
}
#endif /* KERNEL_VERSION > 5.11 */
#endif /* CONFIG_PROTECTED_MODE && LINUX_VERSION_CODE */

/**
 * remap_e2k_stack - remap stack at the end of user address space
 *
 * It can be either e2k hardware stack (i.e. PSP stack or PCSP stack),
 * or it can be signal stack which is saved in privileged area at the
 * end of user space since it has some privileged structures saved
 * such as trap cellar or CTPRs.
 */
void __priv *remap_e2k_stack(void __priv *addr_ptr,
		unsigned long old_size, unsigned long new_size, bool after)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma, *next_vma;
	unsigned long addr = (unsigned long) addr_ptr;
	unsigned long ret, ts_flag, new_addr, end = addr + old_size, new_end = addr + new_size;
	struct vm_userfaultfd_ctx uf = NULL_VM_UFFD_CTX;
	LIST_HEAD(uf_unmap_early);
	LIST_HEAD(uf_unmap);
	bool locked = false;
	struct vma_iterator vmi;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);

	mmap_write_lock(mm);

	/*
	 * Try to expand without remapping
	 */
	vma = vma_to_resize(addr, old_size, new_size, MREMAP_FIXED);
	if (IS_ERR_VALUE(vma)) {
		ret = (unsigned long)PTR_ERR(vma);
		WARN_ONCE((long)ret != -ENOMEM, "ret = %ld\n", (long)ret);
		goto out_unlock;
	}

	vma_iter_init(&vmi, mm, vma->vm_start);
	BUG_ON(vma_find(&vmi, ULONG_MAX) != vma);
	next_vma = vma_next(&vmi);

	if (vma->vm_end == end && (!next_vma || next_vma->vm_start >= new_end)) {
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
		DebugHS("%s(): could not get unmapped area after 0x%lx "
			"size 0x%lx, error %ld\n",
			__func__, (after) ? addr : USER_HW_STACKS_BASE,
			new_size, new_addr);
		goto out_unlock;
	}

	vma_iter_init(&vmi, mm, addr);
	vma = vma_find(&vmi, ULONG_MAX);

	while (vma && vma->vm_start < end) {
		unsigned long remap_from, remap_to, remap_from_size, remap_to_size, vm_end;

		remap_from = vma->vm_start;
		if (vma->vm_start < addr)
			remap_from = addr;

		/*
		 * vma->vm_end should be stored before calling mremap_to(), that could remove vma
		 */
		vm_end = vma->vm_end;

		remap_from_size = vm_end - remap_from;
		if (vm_end >= end)
			remap_from_size = end - remap_from;

		remap_to = remap_from + new_addr - addr;

		remap_to_size = remap_from_size;
		if (vm_end >= end) {
			remap_to_size = end - remap_from +
			    (new_size - old_size);
		}

		DebugHS("mremap_to(): from 0x%lx/0x%lx to 0x%lx/0x%lx\n",
			remap_from, remap_from_size, remap_to, remap_to_size);
		ret = mremap_to(remap_from, remap_from_size,
				remap_to, remap_to_size, &locked, MREMAP_FIXED,
				&uf, &uf_unmap_early, &uf_unmap);
		if (IS_ERR_VALUE(ret)) {
			do_munmap(mm, new_addr, new_size, &uf_unmap);
			pr_err("%s(): could not mremap_to from 0x%lx to 0x%lx size 0x%lx, error %ld\n",
			       __func__, remap_from, remap_to, remap_to_size, ret);
			goto out_unlock;
		}

		vma_iter_init(&vmi, mm, vm_end);
		vma = vma_find(&vmi, ULONG_MAX);
	}

	ret = new_addr;

out_unlock:
	mmap_write_unlock(mm);

	if (!IS_ERR_VALUE(ret) && locked)
		mm_populate(ret + old_size, new_size - old_size);

	clear_ts_flag(ts_flag);

	return (void __priv *) ret;
}

static unsigned long handle_hardware_stack_overflow(struct hw_stack_area *area,
						    bool after, size_t limit)
{
	unsigned long old_size, new_size;
	void __priv *old_addr;
	void __priv *new_addr;

	/*
	 * Increase size exponentially - needed to make sure we won't
	 * run into the end of virtual memory (because chain stack
	 * can only be remapped to a *higher* address for longjmp to
	 * work, and VM area for hardware stacks is limited in size).
	 */
	old_addr = area->base;
	old_size = area->size;
	new_size = max(old_size + PAGE_SIZE, old_size * 11 / 8);
	new_size = round_up(new_size, PAGE_SIZE);

	/* Check for rlimit */
	if (new_size > limit) {
		if (old_size >= limit)
			return -ENOMEM;
		new_size = limit;
	}

	if (new_size > AP_SIZE_ALIGN_PAGE) { /* 128Gb, more then enough */
		/* To simpify v7 hw stacks alignment */
		if (old_size < AP_SIZE_ALIGN_PAGE) {
			new_size = AP_SIZE_ALIGN_PAGE;
		} else {
			return -ENOMEM;
		}
	}
	new_addr = remap_e2k_stack(area->base, old_size, new_size, after);
	if (IS_ERR(new_addr)) {
		return (unsigned long) new_addr;
	} else {
		area->base = new_addr;
		area->size += new_size - old_size;
	}

	return new_addr - old_addr;
}

static int add_user_old_pc_stack_area(struct hw_stack_area *area)
{
	thread_info_t *ti = current_thread_info();
	struct old_pcs_area *old_pc;

	old_pc = kmalloc(sizeof(struct old_pcs_area), GFP_KERNEL);
	if (!old_pc)
		return -ENOMEM;

	old_pc->base = area->base;
	old_pc->size = area->size;

	list_add_tail(&old_pc->list_entry, &ti->old_u_pcs_list);

	return 0;
}

static void __update_pcsp_regs(unsigned long base, unsigned long size,
			unsigned long new_fp, e2k_pcsp_t *pcsp)
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
	*pcsp = new_pcsp(new_base, new_top - new_base, new_fp - new_base);
}

void update_pcsp_regs(void __priv * new_fp, e2k_pcsp_t *pcsp)
{
	struct hw_stack_area *pcs = &current_thread_info()->u_hw_stack.pcs;

	__update_pcsp_regs((unsigned long)pcs->base, pcs->size,
			   (unsigned long)new_fp, pcsp);
}

static void __update_psp_regs(unsigned long base, unsigned long size,
		       volatile void __priv *new_fp_addr, e2k_psp_t *psp)
{
	unsigned long new_base, new_top;

	unsigned long new_fp = (unsigned long)new_fp_addr;
	new_base = max(new_fp - 0x80000000UL, base);
	new_base = round_up(new_base, ALIGN_PSTACK_SIZE);
	new_top = min(new_fp + 0x80000000UL - 1, base + size);
	new_top = round_down(new_top, ALIGN_PSTACK_SIZE);

	/*
	 * Important: since saved %psp_hi.ind value includes %pshtp.ind
	 * after this function we must be sure that %psp_hi.ind > %pshtp.ind.
	 * This is achieved automatically by making window as big as possible.
	 */
	*psp = new_psp(new_base, new_top - new_base, new_fp - new_base);
}

void update_psp_regs(volatile void __priv * new_pp, e2k_psp_t *psp)
{
	struct hw_stack_area *ps = &current_thread_info()->u_hw_stack.ps;

	__update_psp_regs((unsigned long)ps->base,
			  (unsigned long)ps->size, new_pp, psp);
}

/* Update trap cellar records if they pointed into the moved memory area */
static void apply_delta_to_cellar(struct trap_pt_regs *trap,
				  unsigned long start, unsigned long end,
				  unsigned long delta)
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

/* Same as apply_delta_to_cellar() but works with saved cellar in signal stacks */
static int apply_delta_to_signal_cellar(struct pt_regs __priv *u_regs,
					unsigned long start, unsigned long end,
					unsigned long delta)
{
	struct trap_pt_regs __priv *u_trap;
	int tc_count, cnt;

	u_trap = signal_pt_regs_to_trap(u_regs);
	if (IS_ERR_OR_NULL(u_trap))
		return PTR_ERR_OR_ZERO(u_trap);

	if (get_priv(tc_count, &u_trap->tc_count))
		return -EFAULT;

	for (cnt = 0; 3 * cnt < tc_count; cnt++) {
		unsigned long address;

		if (get_priv(address, &u_trap->tcellar[cnt].address))
			return -EFAULT;

		/* Hardware stack accesses are aligned */
		if (address >= start && address < end) {
			if (put_priv(address + delta, &u_trap->tcellar[cnt].address))
				return -EFAULT;
		}
	}

	return 0;
}

int apply_psp_delta_to_signal_stack(unsigned long base, unsigned long size,
				    unsigned long start, unsigned long end,
				    unsigned long delta)
{
	struct pt_regs __priv *u_regs;
	int ret = 0;

	signal_pt_regs_for_each(u_regs) {
		e2k_psp_t psp;

		if (delta != 0) {
			ret = apply_delta_to_signal_cellar(u_regs, start, end, delta);
			if (ret)
				break;
		}

		if (get_priv(LO(psp), &LO(u_regs->stacks.psp)) ||
		    get_priv(HI(psp), &HI(u_regs->stacks.psp))) {
			ret = -EFAULT;
			break;
		}

		DebugHS("adding delta 0x%lx to signal PSP 0x%llx:0x%llx\n",
			delta, LO(psp), HI(psp));
		__update_psp_regs(base, size, U_PSP_PTR(psp) + delta, &psp);

		if (put_priv(HI(psp), &HI(u_regs->stacks.psp)) ||
		    put_priv(LO(psp), &LO(u_regs->stacks.psp))) {
			ret = -EFAULT;
			break;
		}
	}

	return ret;
}

int apply_pcsp_delta_to_signal_stack(unsigned long base, unsigned long size,
				     unsigned long start, unsigned long end,
				     unsigned long delta)
{
	struct pt_regs __priv *u_regs;
	int ret = 0;

	signal_pt_regs_for_each(u_regs) {
		unsigned long new_fp;
		e2k_pcsp_t pcsp;

		if (delta != 0) {
			ret = apply_delta_to_signal_cellar(u_regs, start, end, delta);
			if (ret)
				break;
		}

		if (get_priv(LO(pcsp), &LO(u_regs->stacks.pcsp)) ||
		    get_priv(HI(pcsp), &HI(u_regs->stacks.pcsp))) {
			ret = -EFAULT;
			break;
		}

		DebugHS("adding delta 0x%lx to signal PCSP 0x%llx:0x%llx\n",
			delta, LO(pcsp), HI(pcsp));
		new_fp = (unsigned long)U_PCSP_PTR(pcsp) + delta;
		__update_pcsp_regs(base, size, new_fp, &pcsp);

		if (put_priv(HI(pcsp), &HI(u_regs->stacks.pcsp)) ||
		    put_priv(LO(pcsp), &LO(u_regs->stacks.pcsp))) {
			ret = -EFAULT;
			break;
		}
	}

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
	e2k_psp_t psp = stacks->psp;
	unsigned long delta, real_base, real_top;
	volatile void __priv *fp = U_PSP_PTR(psp);;
	int ret;

	real_base = (unsigned long)u_hw_stack->ps.base;
	real_top = real_base + u_hw_stack->ps.size;

	if (PSP_IND(psp) <= PSP_SIZE(psp) / 2) {
		/* Underflow - check if we've hit the stack bottom */
		if (PSP_BASE(psp) <= real_base)
			return -ENOMEM;
	} else if ((unsigned long)U_PSP_PTR(psp) >= real_top) {
		struct hw_stack_area *ps;

		/* Overflow & we've hit the stack top */
		delta = handle_hardware_stack_overflow(&u_hw_stack->ps, false,
					current->signal->rlim[RLIMIT_P_STACK_EXT].rlim_cur);
		if (IS_ERR_VALUE(delta))
			return delta;

		ps = &current_thread_info()->u_hw_stack.ps;
		if (delta) {
			apply_delta_to_cellar(trap, real_base, real_top, delta);

			ret = apply_psp_delta_to_signal_stack((unsigned long)
							      ps->base,
							      ps->size,
							      real_base,
							      real_top, delta);
			if (ret)
				return ret;
		}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		/*
		 * The follow call is actual only for paravirtualized
		 * guest to correct signal stack on host
		 */
		ret = host_apply_psp_delta_to_signal_stack((unsigned long) ps->base, ps->size,
							 real_base, real_top, delta);
		if (ret)
			return ret;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

		fp += delta;
	}

	update_psp_regs(fp, &stacks->psp);

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
	e2k_pcsp_t pcsp = stacks->pcsp;
	unsigned long delta, real_base, real_top;
	void __priv *fp = U_PCSP_PTR(pcsp);
	int ret;

	real_base = (unsigned long)u_hw_stack->pcs.base;
	real_top = real_base + u_hw_stack->pcs.size;

	if (PCSP_IND(pcsp) <= PCSP_SIZE(pcsp) / 2) {
		/* Underflow - check if we've hit the stack bottom */
		if (PCSP_BASE(pcsp) <= real_base)
			return -ENOMEM;
	} else if (PCSP_BASE(pcsp) + PCSP_SIZE(pcsp) >= real_top) {
		struct hw_stack_area *pcs;

		/* Overflow & we've hit the stack top */
		hw_stack_area_t old_pcs_area = u_hw_stack->pcs;

		delta = handle_hardware_stack_overflow(&u_hw_stack->pcs, true,
						       current->signal->rlim
						       [RLIMIT_PC_STACK_EXT].rlim_cur);
		if (IS_ERR_VALUE(delta))
			return delta;

		pcs = &current_thread_info()->u_hw_stack.pcs;
		if (delta) {
			add_user_old_pc_stack_area(&old_pcs_area);

			apply_delta_to_cellar(trap, real_base, real_top, delta);

			ret = apply_pcsp_delta_to_signal_stack((unsigned long)pcs->base,
							       pcs->size,
							       real_base,
							       real_top, delta);
			if (ret)
				return ret;
		}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		/*
		 * The follow call is actual only for paravirtualized
		 * guest to correct signal stack on host
		 */
		ret = host_apply_pcsp_delta_to_signal_stack((unsigned long)pcs->base, pcs->size,
							  real_base, real_top, delta);
		if (ret)
			return ret;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

		fp += delta;
	}

	update_pcsp_regs(fp, &stacks->pcsp);

	return 0;
}

__cold
static void print_mmap(struct task_struct *task)
{
	char path[256];
	struct mm_struct *mm = task->mm;
	struct vm_area_struct *vma;
	struct file *vm_file;
	bool locked;
	long all_sz = 0;
	VMA_ITERATOR(vmi, mm, 0);

	if (!mm) {
		pr_alert("     There aren't mmap areas for pid %d\n", task->pid);
		return;
	}

	/*
	 * This function is used when everything goes south
	 * so do not try too hard to lock mmap_lock
	 */
	locked = mmap_read_trylock(mm);

	pr_alert("============ MMAP AREAS for pid %d =============\n", task->pid);
	for_each_vma(vmi, vma) {
		vm_file = vma->vm_file;
		pr_alert("ADDR 0x%-10lx END 0x%-10lx ",
			vma->vm_start, vma->vm_end);
		all_sz += vma->vm_end - vma->vm_start;
		if (vma->vm_flags & VM_WRITE)
			pr_cont(" WR ");
		if (vma->vm_flags & VM_READ)
			pr_cont(" RD ");
		if (vma->vm_flags & VM_EXEC)
			pr_cont(" EX ");
		pr_cont(" PROT 0x%lx FLAGS 0x%lx",
			pgprot_val(vma->vm_page_prot), vma->vm_flags);
		if (vm_file) {
			struct seq_buf s;

			seq_buf_init(&s, path, sizeof(path));
			seq_buf_path(&s, &vm_file->f_path, "\n");
			if (seq_buf_used(&s) < sizeof(path))
				path[seq_buf_used(&s)] = 0;
			else
				path[sizeof(path) - 1] = 0;

			pr_cont("        %s\n", path);
		} else {
			pr_cont("\n");
		}
	}
	pr_alert("============ END OF MMAP AREAS all_sz %ld ======\n", all_sz);

	if (locked)
		mmap_read_unlock(mm);
}

__cold
static void print_pagefault_info(const char *reason, struct pt_regs *regs,
				     e2k_addr_t address, bool stack)
{
	struct trap_pt_regs *trap = regs->trap;

	/* if this is guest, stop tracing in host to avoid buffer overwrite */
	host_ftrace_stop();

	pr_alert("%s (%d): PAGE FAULT at address 0x%lx: %s, IP=%lx\n",
		 current->comm, current->pid, address, reason,
		 instruction_pointer(regs));

	/* Print TLB first */
	print_address_tlb(address);
	print_address_page_tables(address, true);
	print_all_TIRs(trap->TIRs, trap->nr_TIRs);
	print_all_TC(trap->tcellar, trap->tc_count);
	print_mmap(current);
	DebugPF("MMU_ADDR_CONT = 0x%llx\n", NATIVE_GET_MMUREG(pid));

	if (trap->nr_page_fault_exc == exc_instr_page_miss_num ||
	    trap->nr_page_fault_exc == exc_instr_page_prot_num) {
		unsigned long instruction_end_page =
		    round_down(address + E2K_INSTR_MAX_SIZE - 1, PAGE_SIZE);

		if (instruction_end_page != round_down(address, PAGE_SIZE)) {
			print_address_tlb(instruction_end_page);
			print_address_page_tables(instruction_end_page, true);
		}
	}

	if (stack)
		print_stack_frames(current, regs, 1);
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static inline bool is_injected_to_reexecute(struct pt_regs *regs)
{
	struct pt_regs *pregs = regs->next;
	struct trap_pt_regs *ptrap = pregs->trap;

	/*
	 * Check if we are in the nested exception that appeared while
	 * executing execute_mmu_operations()
	 */
	if (likely(!(pregs && pregs->flags.exec_mmu_op))) {
		return false;
	}

	/*
	 * It can be only on paravirtualized guest
	 * This page fault has been injected by host to translate gva->hva
	 * to reexecute previous faulted load/store recovery operation
	 */
	if (unlikely(!ptrap))
		panic("do_trap_cellar() previous pt_regs are not from trap\n");

	if (unlikely(!user_mode(pregs) && !from_uaccess_allowed_code(pregs)))
		panic("do_trap_cellar() previous pt_regs are not user's\n");

	return true;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static int copy_nested_tc_records(struct pt_regs *regs,
		trap_cellar_t *tcellar, unsigned int tc_count)
{
	struct pt_regs *pregs = regs->next;
	struct trap_pt_regs *ptrap = pregs->trap;
	int i, skip;

	DbgTC("nested exception detected\n");

	if (unlikely(!ptrap))
		panic("do_trap_cellar() previous pt_regs are not from trap\n");

	/*
	 * After kfence reports use-after-free there is a race window
	 * in which the faulted area could have been reallocated and
	 * freed/protected again.  In this case we'll get nested exception
	 * and should handle it as usual.
	 */
	if (unlikely(!from_uaccess_allowed_code(pregs) &&
			!is_kfence_address((void *) tcellar[0].address)))
		panic("do_trap_cellar() previous pt_regs are not user's\n");

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/*
	 * It can be only on paravirtualized guest
	 * This page fault has been injected by host to translate gva->hva
	 * and to reexecute previous faulted load/store recovery operation
	 */
	if (unlikely(tc_test_is_as_kvm_injected(tcellar[0].condition))) {
		DbgTC("page fault injected by host to reexecute load/store\n");
		BUG_ON(tc_count != 3);
		return 0;
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

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
		int fmt = tc_cond_fmt_full(cond);

		if (cond.s_f)
			continue;

		if (i == 1 && (fmt == LDST_QWORD_FMT || fmt == TC_FMT_QWORD_QP)) {
			++skip;
			continue;
		}

		print_all_TC(tcellar, tc_count);
		panic("do_trap_cellar() invalid trap cellar content\n");
	}

	/* Modify fault_type */
	ptrap->tcellar[ptrap->curr_cnt].condition.fault_type = tcellar[0].condition.fault_type;
	ptrap->tcellar[ptrap->curr_cnt].nested_exc = 1;

	return skip;
}

#ifndef	CONFIG_CLW_ENABLE
static int handle_clw(struct pt_regs *regs, trap_cellar_t *tcellar,
			     unsigned int cnt)
{
	return 0;
}
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

	kthread_use_mm(args->mm);
	ret = clear_user_with_tags(args->uaddr, args->size, ETAGEWD);
	kthread_unuse_mm(args->mm);
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

static int execute_CLW_operation(const struct pt_regs *regs)
{
	e2k_addr_t us_cl_up = regs->us_cl_up;
	e2k_addr_t us_cl_b = regs->us_cl_b;
	const clw_reg_t *us_cl_m = regs->us_cl_m;
	unsigned long us_addr;
	u64 bit_no, mask_word, mask_bit;
	int bmask;

	DebugCLW("started for us_cl_up 0x%lx us_cl_b 0x%lx\n", us_cl_up, us_cl_b);
	for (bmask = 0; bmask < CLW_MASK_WORD_NUM; bmask++)
		DebugCLW("    mask[%d] = 0x%016llx\n", bmask, us_cl_m[bmask]);

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
		mask_word = bit_no / (sizeof(*us_cl_m) * 8);
		mask_bit = bit_no % (sizeof(*us_cl_m) * 8);

		if (!(us_cl_m[mask_word] & (1UL << mask_bit))) {
			DebugCLW("clean stack area from 0x%lx to 0x%lx\n",
				 us_addr, us_addr + CLW_BYTES_PER_BIT);
			if (clw_clear_user(regs, (void __user *)us_addr,
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

	if (clw_clear_user(regs, (void __user *)(us_cl_b + CLW_BYTES_PER_BIT),
			   us_addr - us_cl_b))
		return -EFAULT;

	return 0;
}

static int handle_clw(struct pt_regs *regs, trap_cellar_t *tcellar, unsigned int cnt)
{
	struct trap_pt_regs *trap = regs->trap;
	size_t i;

	DebugCLW("Detected CLW request(s):\n");

	/*
	 * Mark all other CLW requests as completed since
	 * we handle all of them in a single batch
	 */
	for (i = cnt + 1; (3 * i) < trap->tc_count; i++) {
		if (tcellar[i].condition.clw)
			tcellar[i].done = 1;
	}

	/*
	 * Small optimization: call do_page_fault directly instead
	 * of relying on hardware exception from execute_CLW_operation().
	 * Covers most popular cases of small allocations.
	 */
	if (tcellar[cnt].condition.fault_type) {
		unsigned long handled;

		DebugCLW("starts do_page_fault() for first CLW request #%d\n", cnt);
		handled = pass_clw_fault_to_guest(regs, &tcellar[cnt]);
		if (!handled) {
			int ret = do_page_fault(regs, tcellar[cnt].address, tcellar[cnt].condition,
						tcellar[cnt].mask, NULL, &tcellar[cnt]);
			if (ret != PFR_SUCCESS)
				goto fail_sigsegv;
		}
	}

	if (execute_CLW_operation(regs))
		goto fail_sigsegv;

	/*
	 * The requested area is cleared so there is nothing else to be done
	 */
	return PFR_IGNORE;

fail_sigsegv:
	/*
	 * After failed CLW we cannot return to user
	 * so use force_fatal_sig() to exit gracefully.
	 */
	force_fatal_sig(SIGSEGV);

	return PFR_SIGPENDING;
}
#endif /* CONFIG_CLW_ENABLE */

static int adjust_psp_regs(struct pt_regs *regs, s64 delta)
{
	e2k_psp_t u_psp = regs->stacks.psp;

	u_psp = decr_psp_ind(u_psp, PSHTP_MEM_INDEX(regs->stacks.pshtp));

	return copy_from_user_psp_to_current_hw_stack(
			(volatile void *)PSP_BASE(current_thread_info()->k_psp),
			U_PSP_PTR(u_psp), delta, regs);
}

static int adjust_pcsp_regs(struct pt_regs *regs, s64 delta)
{
	e2k_pcsp_t u_pcsp = regs->stacks.pcsp;

	u_pcsp = decr_pcsp_ind(u_pcsp, regs->stacks.pcshtp.ind);

	return copy_from_user_pcsp_to_current_hw_stack(
		(void *)PCSP_BASE(current_thread_info()->k_pcsp),
		U_PCSP_PTR(u_pcsp), delta, regs);
}

static s64 calculate_fill_delta_psp(const struct pt_regs *regs,
		const struct trap_pt_regs *trap, const trap_cellar_t *tcellar)
{
	e2k_psp_t psp = regs->stacks.psp;
	unsigned long max_addr = 0;
	int i = 0;
	s64 delta;

	psp = decr_psp_ind(psp, PSHTP_MEM_INDEX(regs->stacks.pshtp));

	for (; i < trap->tc_count / 3; i++) {
		tc_cond_t condition = tcellar[i].condition;
		unsigned long address = tcellar[i].address;

		if (!condition.s_f && !IS_SPILL(tcellar[i]) ||
		    condition.store || condition.sru)
			continue;

		max_addr = max(address, max_addr);
	}

	max_addr -= max_addr % 32;
	delta = max_addr - (unsigned long)U_PSP_PTR(psp) + 32;

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
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (kvm_test_intc_emul_flag(regs)) {
		call_pf = false;
	} else
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	if (tcellar[cnt].nested_exc) {
		call_pf = true;
	} else if (condition.store) {
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
		ret = do_page_fault(regs, address, condition, mask, NULL, &tcellar[cnt]);
		clear_ts_flag(ts_flag);
		if (ret == PFR_SIGPENDING)
			return ret;
		if (ret != PFR_SUCCESS)
			goto fail_sigsegv;

		if (condition.store)
			*last_store = cnt;
		else
			*last_load = cnt;
	} else {
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		if (kvm_test_intc_emul_flag(regs)) {
			if (condition.store)
				*last_store = cnt;
			else
				*last_load = cnt;
		}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
		ret = PFR_SUCCESS;
	}

	/*
	 * For SPILL execute_mmu_operations() will repeat interrupted stores
	 */
	if (condition.store)
		return ret;

	/*
	 * For FILL we must adjust %pshtp/%pcshtp so that
	 * hardware repeats the loads.
	 *
	 * Also make sure that %pshtp/%pcshtp are adjusted only
	 * once across all the requests in the trap cellar.
	 */
	if (condition.sru && !trap->pcsp_fill_adjusted) {
		if (adjust_pcsp_regs(regs, 32))
			goto fail_sigsegv;

		trap->pcsp_fill_adjusted = 1;
	} else if (!condition.sru && !trap->psp_fill_adjusted) {
		s64 delta = calculate_fill_delta_psp(regs, trap, tcellar);

		if (adjust_psp_regs(regs, delta))
			goto fail_sigsegv;

		trap->psp_fill_adjusted = 1;
	}

	/*
	 * We have adjusted pt_regs so that hardware will
	 * repeat interrupted FILL, no need to repeat in software.
	 */
	return PFR_IGNORE;

fail_sigsegv:
	/*
	 * After failed SPILL/FILL we cannot return to user
	 * so use force_fatal_sig() to exit gracefully.
	 */
	force_fatal_sig(SIGSEGV);

	return PFR_SIGPENDING;
}

static void debug_trace_trap_cellar(const trap_cellar_t *tcellar,
				    unsigned int tc_count,
				    const struct pt_regs *regs)
{
	unsigned long address;
	int cnt;

	for (cnt = 0; (3 * cnt) < tc_count; cnt++)
		trace_trap_cellar(&tcellar[cnt], cnt);

	address = -1ul;
	for (cnt = 0; (3 * cnt) < tc_count; cnt++) {
		if (PFN_DOWN(address) == PFN_DOWN(tcellar[cnt].address))
			continue;

		address = tcellar[cnt].address;
		if (user_mode(regs)) {
			trace_trap_cellar_pt_dtlb(address, PT_DTLB_TRANSLATION_AUTO);
		} else {
			trace_trap_cellar_pt_dtlb(address, PT_DTLB_TRANSLATION_KERNEL);
			trace_trap_cellar_pt_dtlb(address, PT_DTLB_TRANSLATION_USER);
		}
	}
}

void do_trap_cellar(struct pt_regs *regs, int only_system_tc)
{
	struct trap_pt_regs *trap = regs->trap;
	trap_cellar_t *tcellar = trap->tcellar;
	unsigned int tc_count, cnt;
	tc_fault_type_t ftype;
	unsigned long to_complete = 0;
	pf_mode_t mode = { .word = 0 };
	int rval = 0, skip = 0;
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

	DbgTC("tick %lld CPU #%ld only_system %d trap cellar regs addr 0x%px\n",
	      read_CLKR_reg_value(), (long)raw_smp_processor_id(), only_system_tc, tcellar);
	DbgTC("regs->CR0.hi ip 0x%llx user_mode %d\n",
	      get_cr0_ip(regs->crs.cr0), trap_from_user(regs));

	tc_count = trap->tc_count;

	if (trap->curr_cnt == -1) {
		struct pt_regs *prev_regs = regs->next;

		if (trace_trap_cellar_enabled()
		    || trace_trap_cellar_pt_dtlb_enabled())
			debug_trace_trap_cellar(tcellar, tc_count, regs);

		/*
		 * Check if we are in the nested exception that appeared while
		 * executing execute_mmu_operations()
		 *
		 * Check for prev_regs->trap is needed to filter page faults
		 * happening after execve: we see that prev_regs are as
		 * initialized by start_thread() so this is not a nested trap.
		 */
		if (unlikely(prev_regs && prev_regs->trap && prev_regs->flags.exec_mmu_op)) {
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
	}
#pragma loop count (1)
	for (cnt = trap->curr_cnt; (3 * cnt) < tc_count; cnt++, trap->curr_cnt++) {
		unsigned long pass_result;
		unsigned long handled;
		trap_cellar_t *next_tcellar;

		if (tcellar[cnt].done) {
			continue;
		}

		next_tcellar = NULL;
		if ((3 * (cnt + 1)) < tc_count)
			next_tcellar = &tcellar[cnt + 1];

		if (unlikely(trap->ignore_user_tc) || only_system_tc) {
			/*
			 * Can get here if:
			 * 1) Kernel wants to handle only system records of
			 * trap cellar.
			 * 2) Controlled access from kernel to user failed.
			 *
			 * IMPORTANT: must correspond to check in
			 * copy_context_to_signal_stack().
			 */
			if (!tc_record_asynchronous(&tcellar[cnt]))
				continue;
		}
retry_guest_kernel:
		pass_result = pass_page_fault_to_guest(regs, &tcellar[cnt]);
		to_complete |= KVM_GET_NEED_COMPLETE_PF(pass_result);
		if (unlikely(KVM_IS_ERROR_RESULT_PF(pass_result))) {
			pr_err("%s(): kill the guest, fault handling was failed, error %ld\n",
				__func__, (long)pass_result);
			goto out_to_kill;
		} else if (likely(KVM_IS_NOT_GUEST_TRAP(pass_result))) {
			/* trap is not due to guest and should be handled */
			/* in the regular mode */
			;
		} else if (KVM_IS_TRAP_PASSED(pass_result)) {
			DebugKVMPF("request #%d is passed to guest: address 0x%llx condition 0x%016llx\n",
				   cnt, tcellar[cnt].address,
				   AW(tcellar[cnt].condition));
			goto continue_passed;
		} else if (KVM_IS_GUEST_KERNEL_ADDR_PF(pass_result)) {
			DebugKVMPF("request #%d guest kernel address 0x%llx handled by host\n",
				   cnt, tcellar[cnt].address);
			rval = PFR_KVM_KERNEL_ADDRESS;
			goto handled;
		} else if (KVM_IS_SHADOW_PT_PROT_PF(pass_result)) {
			DebugKVMPF("request #%d is guest access to protected shadow PT: address 0x%llx\n",
				   cnt, tcellar[cnt].address);
			goto continue_passed;
		} else {
			BUG_ON(true);
		}
		/* Probably it is KVM MMIO request (only on guest). */
		/* Handle same fault here to do not call slow path of */
		/* page fault handler (do_page_fault() ... */
		handled = mmio_page_fault(regs, &tcellar[cnt]);
		if (handled) {
			DbgTC("do_trap_cellar: request #%d was KVM MMIO guest request, handled for address 0x%llx\n",
			      cnt, tcellar[cnt].address);
			goto continue_passed;
		}

repeat:
		; /* Silence meaningless warning that will be removed in C23 */
		tc_cond_t cond = tcellar[cnt].condition;
		AW(ftype) = cond.fault_type;
		DbgTC("ftype == %x address %llx\n", AW(ftype), tcellar[cnt].address);

		if (cond.clw) {
			rval = handle_clw(regs, tcellar, cnt);
		} else if (cond.s_f || IS_SPILL(tcellar[cnt])) {
			rval = handle_spill_fill(regs, tcellar, cnt,
						 &last_store, &last_load);
		} else if (cond.sru && !cond.s_f && !cond.store) {
			/* This is hardware load from CU table, mark it
			 * as having permission to access privileged area */
			unsigned long ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
			rval = do_page_fault(regs, tcellar[cnt].address, cond,
					tcellar[cnt].mask, &mode, &tcellar[cnt]);
			clear_ts_flag(ts_flag);
		} else if (ftype.exc_mem_lock) {
			DbgTC("do_trap_cellar: exc_mem_lock\n");
			S_SIG(regs, SIGBUS, BUS_OBJERR);
			debug_signal_print("SIGBUS. Memory lock signaled", regs, false);
			break;
		} else if (TASK_IS_BINCO(current) && trap->rp &&
				cond.store && cond.root) {
			/* rm 38937 */
			DebugSRP("%s(): write fault within RP area\n",
					__func__);
			S_SIG(regs, SIGBUS, BUS_OBJERR);
			debug_signal_print("SIGBUS. Write fault within RP area signaled",
								regs, false);
			break;
		} else if (tc_cond_is_unlock(cond) || tc_cond_is_secondary_unlock(cond)) {
			/* store unlock without touching memory. Nothing to fault in. */
			rval = PFR_SUCCESS;
		} else {
			bool same = false,
			    async = tc_record_asynchronous(&tcellar[cnt]);

			if (!async && !tcellar[cnt].nested_exc) {
				if (cond.store) {
					if (last_store != -1 &&
					    round_down(tcellar[cnt].address, PAGE_SIZE) ==
					    round_down(tcellar[last_store].address, PAGE_SIZE)) {
						same = true;
					}
				} else {
					if (last_load != -1 &&
					    round_down(tcellar[cnt].address, PAGE_SIZE) ==
					    round_down(tcellar[last_load].address, PAGE_SIZE)) {
						same = true;
					}
				}
			}

			if (same) {
				rval = PFR_SUCCESS;
			} else {
				rval = do_page_fault(regs, tcellar[cnt].address, cond,
						     tcellar[cnt].mask, &mode, &tcellar[cnt]);

				if (rval == PFR_SUCCESS && !async) {
					if (cond.store)
						last_store = cnt;
					else
						last_load = cnt;
				}
			}
		}

handled:
		switch (rval) {
		case PFR_SIGPENDING:
			/*
			 * Either BAD AREA, so SIGSEGV or SIGBUS and maybe
			 * a sighandler, or SIGBUS after invalidating unaligned
			 * MLT entry on lock trap on store PF handling.
			 */
			DbgTC("BAD AREA\n");
			goto out;
		case PFR_CONTROLLED_ACCESS:
			/* Controlled access from kernel to user space failed.
			 * No need to execute the following user loads/stores */
			trap->ignore_user_tc = true;
			break;
		case PFR_SUCCESS:
			if (ftype.global_sp) {
				/* Hm? we refused to use  sap in HW and SW */
				WARN_ON_ONCE(1);
				force_sig_mceerr(BUS_MCEERR_AO,
					(void __user *)tcellar[cnt].address, 0);
				goto out;
			}
			if (cond.sru && !cond.s_f && !IS_SPILL(tcellar[cnt])) {
				DbgTC("page fault on CU upload condition: 0x%llx\n", AW(cond));
			} else {
				rval = execute_mmu_operations(&tcellar[cnt],
						next_tcellar, regs,
						NULL, NULL, !!mode.priv);
				DbgTC("execute_mmu_operations() finished"
					" for cnt %d rval %d\n", cnt, rval);
				if (rval == EXEC_MMU_STOP) {
					goto out;
				} else if (rval == EXEC_MMU_REPEAT) {
					goto repeat;
				}
			}
			break;
		case PFR_KERNEL_ADDRESS:
			DbgTC("kernel address has been detected in Trap Cellar for cnt %d\n",
					cnt);
			rval = execute_mmu_operations(&tcellar[cnt],
					next_tcellar, regs, NULL, NULL,
					!!mode.priv);
			DbgTC("execute_mmu_operations() finished for kernel addr 0x%llx cnt %d rval %d\n",
				tcellar[cnt].address, cnt, rval);
			if (rval == EXEC_MMU_STOP) {
				goto out;
			} else if (rval == EXEC_MMU_REPEAT) {
				goto repeat;
			}
			break;
		case PFR_KVM_KERNEL_ADDRESS: {
			if (cond.s_f || IS_SPILL(tcellar[cnt])) {
				/* it is hardware stacks fill operation */
				/* and fill will be repeated by hardware */
				rval = handle_spill_fill(regs, tcellar, cnt,
						&last_store, &last_load);
				goto handled;
			} else {
				rval = execute_mmu_operations(&tcellar[cnt],
						next_tcellar, regs,
						NULL, NULL, !!mode.priv);
			}

			DebugKVMPF("execute_mmu_operations() finished for cnt %d rval %d\n",
				cnt, rval);
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

continue_passed:
		tcellar[cnt].done = 1;
	}

out:
	if (only_system_tc)
		trap->curr_cnt = skip;
	if (to_complete != 0)
		complete_page_fault_to_guest(to_complete);
	return;

out_to_kill:
	do_group_exit(SIGKILL);
}

static inline int is_spec_load_fault(union pf_mode mode)
{
	return mode.spec && !mode.write;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static inline union pf_mode set_kvm_fault_injected(tc_cond_t condition,
						   pf_mode_t mode)
{
	mode.as_kvm_injected = tc_test_is_as_kvm_injected(condition);
	return mode;
}

static inline union pf_mode set_kvm_fault_passed(tc_cond_t condition,
						 pf_mode_t mode)
{
	mode.as_kvm_passed = tc_test_is_as_kvm_passed(condition);
	return mode;
}

static inline union pf_mode set_kvm_copy_user(tc_cond_t condition,
					      pf_mode_t mode)
{
	mode.as_kvm_copy_user = tc_test_is_as_kvm_copy_user(condition);
	return mode;
}

static inline union pf_mode set_kvm_fault_mode(tc_cond_t condition,
					       pf_mode_t mode)
{
	if (tc_test_is_as_kvm_injected(condition)) {
		mode = set_kvm_fault_injected(condition, mode);
		mode = set_kvm_copy_user(condition, mode);
	} else if (tc_test_is_as_kvm_passed(condition)) {
		mode = set_kvm_fault_passed(condition, mode);
	}
	return mode;
}

static inline union pf_mode set_kvm_dont_inject_mode(pt_regs_t *regs,
						     pf_mode_t mode)
{
	if (likely(!host_test_dont_inject(regs)))
		return mode;

	mode.host_dont_inject = true;
	return mode;
}

/*
 * KVM injected page fault for the guest only to eliminate the reason
 * of the fault without memory access to load/store
 */
static inline bool is_kvm_fault_injected(union pf_mode mode)
{
	return !!mode.as_kvm_injected;
}

/*
 * KVM injected page fault for the guest to eliminate the reason of the fault
 * and to recover the load/store operation that caused page fault
 */
static inline bool is_kvm_fault_passed(union pf_mode mode)
{
	return !!mode.as_kvm_passed;
}

/*
 * KVM injected page fault for the guest only:
 *  1) to eliminate the reason of the fault without memory access to load/store
 *  2) to mark copy to/from guest user space with enabled page faults
 */
static inline bool is_kvm_copy_user(union pf_mode mode)
{
	return !!mode.as_kvm_copy_user;
}

/*
 * Any KVM injection mode
 */
static inline bool is_kvm_fault_mode(union pf_mode mode)
{
	return is_kvm_fault_injected(mode) || is_kvm_fault_passed(mode);
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

/*
 * Is the operation a semi-speculative load? If yes, the address
 * could be any value. Ignore this record. The needed diagnostic
 * value has been written to the register by hardware.
 */
static bool handle_spec_load_fault(unsigned long address, struct pt_regs *regs, union pf_mode mode)
{
	if (!is_spec_load_fault(mode))
		return false;

	if (debug_semi_spec) {
		pr_notice("PAGE FAULT. ignore invalid LOAD address 0x%lx in speculative mode: IP=%lx %s(pid=%d)\n",
		     address, instruction_pointer(regs), current->comm, current->pid);
	}

	return true;
}

static notrace long return_efault(void)
{
	return -EFAULT;
}

static notrace void double_return_efault(void)
{
	e2k_cr0_t cr0 = read_CR0_reg();
	set_cr0_ip(cr0, return_efault);
	write_CR0_ip(cr0);
}

/**
 * controlled_user_access - is this from special kernel-to-user access
 *			    (get_user, copy_to_user, ...)
 * @regs: pt_regs for this trap
 */
static bool controlled_user_access(const struct pt_regs *regs)
{
	unsigned long trap_ip = get_trap_ip(regs), return_ip = get_return_ip(regs);

	/* UACCESS_FN_CALL case: */
	if (trap_ip >= (unsigned long)__uaccess_start &&
	    trap_ip < (unsigned long)__uaccess_end) {
		return true;
	}

	/* SET_USR_PFAULT case: */
	if (current->thread.usr_pfault_jump)
		return true;

	/* get_user/put_user case (slowest check so do it last): */
	if (search_exception_tables(return_ip))
		return true;

	return false;
}


/**
 * handle_uaccess_trap - handle trap caused by accessing a user address
 *		legitimately (i.e. its an intended access of user memory)
 * @regs: pt_regs for this trap
 * @skip_get_user: whether this a real exc_data_page exception or
 *	exc_diag_*.  On e2k when semi-spec. loads are used by compiler
 *	in its optimizations, it's possible that exc_diag_* will be
 *	generated instead of exc_data_page (because the load that should
 *	have generated page fault has been put into semi-spec. mode).
 */
bool handle_uaccess_trap(struct pt_regs *regs, bool skip_get_user)
{
	unsigned long trap_ip = get_trap_ip(regs), return_ip = get_return_ip(regs);

	/*
	 * UACCESS_FN_CALL case. This should be checked before
	 * SET_USR_PFAULT case because we can call SET_USR_PFAULT()
	 * from UACCESS_FN_DEFINE function.
	 *
	 * Can also happen for MADM violation on kernel to user access.
	 */
	if (trap_ip >= (unsigned long)__uaccess_start &&
	    trap_ip < (unsigned long)__uaccess_end) {
		unsigned long flags;

		if (return_ip >= (unsigned long)__uaccess_start &&
		    return_ip < (unsigned long)__uaccess_end) {
			correct_trap_return_ip(regs, (unsigned long)return_efault);
			return true;
		}

		/* Special case: the same wide instruction that had the
		 * faulting user access also had return or call instruction. */
		e2k_mem_crs_t *frame = K_PCSP_PTR(regs->stacks.pcsp);
		--frame;

		raw_all_irq_save(flags);
		COPY_STACKS_TO_MEMORY();
		if (trap_ip + E2K_GET_INSTR_SIZE(*(instr_hs_t *) trap_ip) ==
		    get_cr0_ip(frame->cr0)) {
			/* It was a call instruction, so we need to skip
			 * two functions in stack */
			correct_trap_return_ip(regs, (unsigned long) double_return_efault);
		} else {
			/* It was a return instruction, so we need
			 * to write -EFAULT directly to caller's
			 * %dr0 instead of changing return IP. */
			unsigned long dr0_addr = (unsigned long)K_PSP_PTR(regs->stacks.psp) -
							C_ABI_PSIZE_UNPROT * EXT_4_NR_SZ;
			u64 efault = -EFAULT;
			tc_cond_t cond = (tc_cond_t) { 0 };

			cond.store = 1;
			cond.chan = 1;
			recovery_faulted_move((unsigned long)&efault, dr0_addr,
					0ul /* reg_hi */, 1 /* vr */,
					ldst_rec_dword(), 0,
					false /* qp_load */, false /* atomic_load */,
					false /* big_endian */, false /* single_byte */, cond,
					false /* clear_lo */, false /* clear_hi */, false);
		}
		raw_all_irq_restore(flags);

		return true;
	}

	/* SET_USR_PFAULT case: */
	if (current->thread.usr_pfault_jump) {
		correct_trap_return_ip(regs, current->thread.usr_pfault_jump);
		current->thread.usr_pfault_jump = 0;
		return true;
	}

	/*
	 * Compiler won't use semi-spec. mode for get_user()/put_user()
	 * so do not check for get_user()/put_user() from exc_diag_*.
	 *
	 * This is the slowest check so do it last.
	 */
	if (!skip_get_user) {
		/* get_user/put_user case: */
		const struct exception_table_entry *fixup;

		fixup = search_exception_tables(return_ip);
		if (fixup) {
			correct_trap_return_ip(regs, fixup->fixup);
			return true;
		}
	}

	return false;
}

__cold
static int kernel_mode_fault(const char *reason, unsigned long address,
		struct pt_regs *regs, union pf_mode mode, tc_fault_type_t ftype)
{
	/*
	 * Are we prepared to handle this kernel fault?
	 */
	if (handle_uaccess_trap(regs, false)) {
		/* Controlled access from kernel to user space failed. */
		return PFR_CONTROLLED_ACCESS;
	}

	/*
	 * load_unaligned_zeropad() could also trigger kfence
	 * protection which should be ignored.  So check kfence
	 * after handle_uaccess_trap().
	 */
#ifdef CONFIG_KFENCE
	if (ftype.illegal_page && kfence_handle_page_fault(address, mode.write, regs))
		return PFR_SUCCESS;
#endif

	if (handle_spec_load_fault(address, regs, mode)) {
		/*
		 * Kernel's valid semi-speculative loads and user's loads are
		 * checked above, so this is an *invalid* page fault from half
		 * speculative load.  This means there is some bug in kernel,
		 * so print warning and recover by flushing bad entry from TLB.
		 */
		trace_unhandled_page_fault(address, PT_DTLB_TRANSLATION_KERNEL);
		trace_unhandled_page_fault(address, PT_DTLB_TRANSLATION_USER);

		static DEFINE_RATELIMIT_STATE(semispec_ratelimit, 60 * HZ, 3);
		if (__ratelimit(&semispec_ratelimit)) {
			WARN(1, "Unexpected page fault from kernel's semi-speculative load\n");
		}

		flush_TLB_all();
		return PFR_IGNORE;
	}

	trace_unhandled_page_fault(address, PT_DTLB_TRANSLATION_KERNEL);
	trace_unhandled_page_fault(address, PT_DTLB_TRANSLATION_USER);
	/* Do not clutter trace output with panic itself */
	tracing_off();

	/* Enable emergency console before printing */
	bust_spinlocks(1);
	print_pagefault_info(reason, regs, address, false);
	bust_spinlocks(0);

	/*
	 *  Oops. The kernel tried to access some bad page.
	 */
	if (current->pid <= 1)
		panic("do_page_fault: kernel_mode_fault on pid %d. IP 0x%lx\n",
		      current->pid, get_trap_ip(regs));

	panic("do_page_fault: kernel_mode_fault for address %lx from IP = %lx\n",
	      address, get_trap_ip(regs));
}

/*
 * Print out info about fatal segfaults, if the show_unhandled_signals
 * sysctl is set:
 */
__cold
static void show_signal_msg(struct pt_regs *regs, unsigned long address,
				struct task_struct *tsk)
{
	void *cr_ip, *tir_ip;

	if (!unhandled_signal(tsk, SIGSEGV))
		return;

	if (!printk_ratelimit())
		return;

	tir_ip = (void *)get_trap_ip(regs);
	cr_ip = (void *)instruction_pointer(regs);

	if (tir_ip == cr_ip)
		pr_info("%s%s[%d]: segfault at %lx ip %px",
		       task_pid_nr(tsk) > 1 ? KERN_INFO : KERN_EMERG,
		       tsk->comm, task_pid_nr(tsk), address, tir_ip);
	else
		pr_info("%s%s[%d]: segfault at %lx ip %px interrupt ip %px",
		       task_pid_nr(tsk) > 1 ? KERN_INFO : KERN_EMERG,
		       tsk->comm, task_pid_nr(tsk), address, tir_ip, cr_ip);

	print_vma_addr(KERN_CONT " in ", (unsigned long)tir_ip);

	pr_cont("\n");
}

__cold
int pf_force_sig_info(const char *reason, int si_signo, int si_code,
			     unsigned long address, struct pt_regs *regs)
{
	address = untagged_addr(address);
	if (IS_USER_ADDR(address))
		trace_unhandled_page_fault(address, PT_DTLB_TRANSLATION_AUTO);

	if (debug_pagefault)
		print_pagefault_info(reason, regs, address, true);

	if (si_signo == SIGBUS) {
		debug_signal_print("SIGBUS. Page fault", regs, false);
	} else if (si_signo == SIGSEGV) {
		debug_signal_print("SIGSEGV. Page fault", regs, false);
	}

	if (IS_USER_ADDR(address) && show_unhandled_signals)
		show_signal_msg(regs, address, current);

	if (regs->trap->nr_page_fault_exc == exc_mem_lock_num) {
		/* See comment in do_recovery_point() */
		send_sig_fault(si_signo, si_code, (void __user *)address, current);
	} else {
		force_sig_fault(si_signo, si_code, (void __user *)address);
	}

	return PFR_SIGPENDING;
}

static int clear_valid_on_spec_load_one(struct mm_struct *mm,
		struct vm_area_struct *vma, unsigned long addr,
		const struct pt_regs *regs, bool *unlocked, bool write_lock)
{
	struct vm_area_struct *vma_prev, *vma_next;
	unsigned long pmd_down = round_down(addr, PMD_SIZE);
	unsigned long pmd_up = round_up(addr + 1, PMD_SIZE);
	unsigned long area_start, area_end;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	/*
	 * Calculate invalid area size
	 */
	if (!vma) {
		/* This is a speculative load from unmapped area */
		vma_next = find_vma_prev(mm, addr, &vma_prev);

		area_start = (vma_prev) ? vma_prev->vm_end : 0;
		area_end = (vma_next) ? vma_next->vm_start : TASK_SIZE;
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
			round_up(addr + 1, PGDIR_SIZE) <= area_end) {
		spin_lock(&mm->page_table_lock);
		if (pgd_none(*pgd) && pgd_valid(*p4d)) {
			pgd_t entry = pgd_mknotvalid(*pgd);
			set_pgd_at(mm, addr, pgd, entry);
		}
		spin_unlock(&mm->page_table_lock);
		goto out_success;
	}

	p4d = p4d_alloc(mm, pgd, addr);
	if (!p4d)
		goto oom;
	/* Check if we can mark whole p4d invalid */
	if (p4d_none(*p4d) && round_down(addr, PGDIR_SIZE) >= area_start &&
	    round_up(addr, PGDIR_SIZE) <= area_end) {
		spin_lock(&mm->page_table_lock);
		if (p4d_none(*p4d) && p4d_valid(*p4d)) {
			p4d_t entry = p4d_mknotvalid(*p4d);
			set_p4d_at(mm, addr, p4d, entry);
		}
		spin_unlock(&mm->page_table_lock);
		goto out_success;
	}

	pud = pud_alloc(mm, p4d, addr);
	if (!pud)
		goto oom;
	/* Avoid unnecessary splitting if we raced againt huge PUD fault
	 * (just for better performance) */
	if (pud_trans_huge(*pud))
		return 0;
	/* Check if we can mark whole pud invalid */
	if (pud_none(*pud) && round_down(addr, PUD_SIZE) >= area_start &&
			round_up(addr + 1, PUD_SIZE) <= area_end) {
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
	if (pmd_none(*pmd) && pmd_down >= area_start && pmd_up <= area_end) {
		spinlock_t *ptl;
		if (vma && is_vm_hugetlb_page(vma)) {
			pte_t *huge_pte = (pte_t *) pmd;
			ptl = huge_pte_lockptr(hstate_vma(vma), mm, huge_pte);
		} else {
			ptl = pmd_lockptr(mm, pmd);
		}

		spin_lock(ptl);
		if (pmd_none(*pmd) && pmd_valid(*pmd)) {
			pmd_t entry = pmd_mknotvalid(*pmd);
			set_pmd_at(mm, addr, pmd, entry);
		}
		spin_unlock(ptl);
		goto out_success;
	}

	if (vma) {
		split_huge_pmd(vma, pmd, addr);
	} else {
		/* Use another vma within same pmd if possible. */
		if (vma_prev && vma_prev->vm_end > pmd_down) {
			split_huge_pmd(vma_prev, pmd, vma_prev->vm_end - 1);
		} else if (vma_next && vma_next->vm_start < pmd_up) {
			split_huge_pmd(vma_prev, pmd, vma_next->vm_start);
		} else {
			WARN_ONCE(1, "Could not split pmd for semi-spec. load from invalid area, address: 0x%lx, pmd boundaries: 0x%lx - 0x%lx\n",
					addr, pmd_down, pmd_up);
		}
	}

	/*
	 * Use pte_alloc() instead of pte_alloc_map().  We can't run
	 * pte_offset_map() on pmds where a huge pmd might be created
	 * from a different thread.
	 *
	 * pte_alloc_map() is safe to use under mmap_write_lock(mm) or when
	 * parallel threads are excluded by other means.
	 *
	 * Here we only have mmap_read_lock(mm).
	 */
	if (pte_alloc(mm, pmd))
		goto oom;

	/* See the comment in handle_pte_fault() */
	if (unlikely(pmd_trans_unstable(pmd)))
		return 0;

	/*
	 * A regular pmd is established and it can't morph into a huge pmd
	 * from under us anymore at this point because we hold the mmap_lock
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
		pr_notice("PAGE FAULT. unmap invalid SPEC LD address 0x%lx: IP=%lx %s(pid=%d)\n",
		     addr, instruction_pointer(regs), current->comm,
		     current->pid);

	return PFR_IGNORE;

oom:
	*unlocked = true;
	if (write_lock) {
		mmap_write_unlock(mm);
	} else {
		mmap_read_unlock(mm);
	}

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
 * next time we get a page fault on semi-spec. load.
 *
 * Releases mmap_sem.
 *
 * Returns:
 *   PFR_SIGPENDING: if this process was killed by Out-of-Memory handler;
 *   PFR_IGNORE: if the valid bit was cleared (or some race prevented us
 *               from clearing it);
 *   0: otherwise.
 */
static int clear_valid_on_spec_load_and_unlock(unsigned long address,
		struct vm_area_struct *vma, struct pt_regs *regs,
		union pf_mode mode, int addr_num, bool write_lock)
{
	struct mm_struct *mm = current->mm;
	bool unlocked = false;
	int ret;

	if (!is_spec_load_fault(mode)) {
		ret = 0;
		goto out_unlock;
	}

	/* Do not clear valid bit when the access itself was error in kernel */
	if (!mode.user && !mode.controlled_user_access) {
		ret = 0;
		goto out_unlock;
	}

	ret = clear_valid_on_spec_load_one(mm, vma, address, regs, &unlocked, write_lock);
	if (ret || unlocked)
		goto out_unlock;

	if (addr_num > 1) {
		unsigned long addr_hi = PAGE_ALIGN(address);

		vma = find_vma(mm, addr_hi);
		if (vma && addr_hi < vma->vm_start)
			vma = NULL;

		ret = clear_valid_on_spec_load_one(mm, vma, addr_hi, regs, &unlocked, write_lock);
	} else {
		ret = 0;
	}

out_unlock:
	if (!unlocked) {
		unlocked = true;
		if (write_lock) {
			mmap_write_unlock(mm);
		} else {
			mmap_read_unlock(mm);
		}
	}

	return ret;
}

/*
 * Releases mmap_sem
 */
__cold
static int bad_area(const char *reason, unsigned long address,
		    struct vm_area_struct *vma, struct pt_regs *regs,
		    union pf_mode mode, int addr_num, int si_code, tc_fault_type_t ftype,
		    bool write_lock)
{
	int ret;

	if (write_lock)
		mmap_assert_write_locked(current->mm);
	else
		mmap_assert_locked(current->mm);

	ret = clear_valid_on_spec_load_and_unlock(address, vma, regs, mode, addr_num, write_lock);
	if (ret)
		return ret;

	if (!mode.user)
		return kernel_mode_fault(reason, address, regs, mode, ftype);

	if (handle_uaccess_trap(regs, false)) {
		/* This is a fast syscall where user passed bad address. */
		return PFR_CONTROLLED_ACCESS;
	}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (unlikely(is_kvm_fault_injected(mode))) {
		if (is_injected_to_reexecute(regs) || !is_kvm_copy_user(mode))
			return pf_force_sig_info(reason, SIGSEGV, si_code,
						 address, regs);
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	if (handle_spec_load_fault(address, regs, mode))
		return PFR_IGNORE;

	return pf_force_sig_info(reason, SIGSEGV, si_code, address, regs);
}

static const char *access_error(struct vm_area_struct *vma,
				unsigned long address, struct pt_regs *regs,
				union pf_mode mode)
{
	if (mode.write) {
		/* Check write permissions */
		if (unlikely(!(vma->vm_flags & (VM_WRITE | VM_MPDMA))))
			return "page is not writable";
	} else {
		/* Check read permissions */
		if (unlikely(!(vma->vm_flags & (VM_READ | VM_EXEC | VM_WRITE))))
			return "page is PROT_NONE";
	}

	/* Check exec permissions */
	if (mode.exec && unlikely(!(vma->vm_flags & VM_EXEC)))
		return "page is not executable";

	/* Check privilege level */
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (unlikely((vma->vm_flags & VM_PRIVILEGED) &&
		     (!test_ts_flag(TS_KERNEL_SYSCALL) || !kernel_is_privileged()) &&
		     !is_kvm_fault_mode(mode))) {
		return "page is privileged";
	}
#else
	if (unlikely(vma->vm_flags & VM_PRIVILEGED) && !test_ts_flag(TS_KERNEL_SYSCALL))
		return "page is privileged";
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	return NULL;
}

/*
 * bug #102076
 *
 * There are areas that can be written but cannot be read; for example,
 * areas past the end of file. Accessing them with `mova' will cause
 * a page fault which we do not want in this case (because `mova' is
 * speculative).
 *
 * For semi-speculative loads we can just return to user and there will
 * be DT in register (hardware puts it there), the user application will
 * continue execution from the next wide instruction. But for AAU we have
 * to remove the valid bit from page table, otherwise it will just repeat
 * the load, resulting in an endless loop.
 *
 * Note that after removing the valid bit this entry can be written into
 * DTLB, so we have to flush it in do_page_fault().
 */
static int handle_forbidden_aau_load(struct vm_area_struct *vma,
				     unsigned long address,
				     struct pt_regs *regs, union pf_mode mode)
{
	struct mm_struct *mm = current->mm;
	e2k_tir_t tir;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	if (mode.write || !vma->vm_ops)
		return 0;

	tir = regs->trap->TIR;

	/* Is this not an AAU fault? */
	if (tir.j != 0 || !tir.aa)
		return 0;

	/*
	 * OK, so we want to ignore this.
	 * If an error occurs, just return PFR_IGNORE and retry
	 * when the page fault is generated again by AAU.
	 */

	pgd = pgd_offset(mm, address);

	p4d = p4d_alloc(mm, pgd, address);
	if (!p4d)
		goto oom;

	pud = pud_alloc(mm, p4d, address);
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
	 * pte_alloc_map() is safe to use under mmap_write_lock(mm) or when
	 * parallel threads are excluded by other means.
	 *
	 * Here we only have mmap_read_lock(mm).
	 */
	if (pte_alloc(mm, pmd))
		goto oom;

	/* See the comment in handle_pte_fault() */
	if (unlikely(pmd_trans_unstable(pmd)))
		goto ignore;

	/*
	 * A regular pmd is established and it can't morph into a huge pmd
	 * from under us anymore at this point because we hold the mmap_lock
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
		pr_notice("PAGE FAULT. unmap invalid MOVA address 0x%lx: IP=%lx %s(pid=%d)\n",
		     address, instruction_pointer(regs), current->comm,
		     current->pid);

ignore:
	mmap_read_unlock(current->mm);

	return PFR_IGNORE;

oom:
	mmap_read_unlock(current->mm);

	/* OOM killer could have killed us */
	pagefault_out_of_memory();

	return fatal_signal_pending(current) ? PFR_SIGPENDING : PFR_SUCCESS;
}

__cold
static int mm_fault_error(struct vm_area_struct *vma, unsigned long address,
			      struct pt_regs *regs, union pf_mode mode,
			      vm_fault_t fault, tc_fault_type_t ftype)
{
	int ret;

	/*
	 * Pagefault was interrupted by SIGKILL. We have no reason to
	 * continue pagefault.
	 */
	if (fatal_signal_pending(current)) {
		mmap_read_unlock(current->mm);

		if (!mode.user)
			return kernel_mode_fault("fatal signal pending",
						 address, regs, mode, ftype);

		return PFR_SIGPENDING;
	}

	if (fault & VM_FAULT_OOM) {
		mmap_read_unlock(current->mm);

		if (!mode.user)
			return kernel_mode_fault("Out-of-Memory", address, regs, mode, ftype);

		pagefault_out_of_memory();

		/* OOM killer could have killed us */
		return fatal_signal_pending(current) ? PFR_SIGPENDING :
		    PFR_SUCCESS;
	}

	if (fault & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV)) {
		ret = handle_forbidden_aau_load(vma, address, regs, mode);
		if (ret)
			return ret;
	}

	mmap_read_unlock(current->mm);

	if (fault & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV)) {
		int signal, si_code;

		if (!mode.user)
			return kernel_mode_fault("handle_mm_fault failed",
						 address, regs, mode, ftype);

		/* We cannot guarantee that another thread did not
		 * truncate the file we were reading from, thus we
		 * cannot rely on valid bit being cleared and must
		 * manually check for semi-speculative mode. */
		if (handle_spec_load_fault(address, regs, mode))
			return PFR_IGNORE;

		if (fault & VM_FAULT_SIGBUS) {
			signal = SIGBUS;
			si_code = BUS_ADRERR;
		} else {
			signal = SIGSEGV;
			si_code = SEGV_MAPERR;
		}

		return pf_force_sig_info("handle_mm_fault failed",
					 signal, si_code, address, regs);
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

	DebugNAO("not aligned operation with address 0x%lx fmt %d size %d bytes\n",
	     address, tc_cond_fmt_full(cond), size);

	end_address = address + size - 1;

	return unlikely(end_address >> PAGE_SHIFT != address >> PAGE_SHIFT);
}

static int handle_kernel_address(unsigned long address, struct pt_regs *regs,
				 union pf_mode mode, tc_fault_type_t ftype)
{
	if (mode.user) {
		if (handle_spec_load_fault(address, regs, mode))
			return PFR_IGNORE;

		return pf_force_sig_info("access from user to kernel", SIGBUS,
					 BUS_ADRERR, address, regs);
	}

#ifdef CONFIG_KVM_GUEST_KERNEL
	if (unlikely(address >= GUEST_VMEMMAP_START && address < GUEST_VMEMMAP_END))
		return PFR_KVM_KERNEL_ADDRESS;
#endif

	/*
	 * Check that it was the kernel address that caused the page fault
	 */
	if (regs->trap->tc_count <= 3 || AW(ftype))
		return kernel_mode_fault("page fault at kernel address",
					 address, regs, mode, ftype);

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
static int npfi_enabled = IS_ENABLED(CONFIG_NESTED_PAGE_FAULT_INJECTION_ENABLED_DEFAULT);

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
static bool nested_page_fault_injected(unsigned long address, tc_cond_t condition)
{
	if (!npfi_enabled)
		return false;

	/*
	 * Here we need to check whether address is OK, and
	 * _not_ whether `ldrd` will check for privileges.
	 * So avoid using access_ok() as it can be empty
	 * when CONFIG_ALTERNATE_USER_ADDRESS_SPACE is set.
	 */
	if (!__range_ok(address, tc_cond_to_size(condition), USER_ADDR_MAX))
		return false;

	if (get_cycles() & 0x3ull) {
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
static bool nested_page_fault_injected(unsigned long address, tc_cond_t condition)
{
	return false;
}
#endif


/**
 * handle_single_page - handle page fault for a single page
 * @vma: the faulted vma
 * @regs: the faulted pt_regs
 * @address: the faulted address
 * @mode: additional info about fault
 * @instr_page: whether page fault comes from code execution
 * @ftype: ftype field from hardware trap cellar
 * @flags: the fault flags
 * @addr_num: indicates whether memory access also hits into 2nd page
 *	      after `address` (2 if there and 1 otherwise)
 *
 * Returns:
 * 0 on success, `fault` will be updated with details;
 * -EAGAIN if we should handle the same address again;
 * value to return to do_trap_cellar() otherwise.
 */
static int handle_single_page(struct vm_area_struct *vma,
		struct pt_regs *const regs, e2k_addr_t address,
		union pf_mode mode, tc_fault_type_t ftype, int flags, int addr_num)
{
	vm_fault_t fault;
	const char *str;

	if ((str = access_error(vma, address, regs, mode)))
		return bad_area(str, address, vma, regs, mode, addr_num,
				SEGV_ACCERR, ftype, false);

	fault = handle_mm_fault(vma, address, flags, regs);
	DebugPF("handle_mm_fault() returned %x\n", fault);

	if (fault_signal_pending(fault, regs)) {
		/* Quick path to respond to signals.  The core mm code
		 * has unlocked the mm for us if we get here. */
		if (!mode.user) {
			return kernel_mode_fault("fatal signal pending",
						 address, regs, mode, ftype);
		}
		return PFR_SIGPENDING;
	}

	/* The fault is fully completed (including releasing mmap lock) */
	if (unlikely(fault & VM_FAULT_COMPLETED))
		return PFR_SUCCESS;

	if (unlikely(fault & VM_FAULT_RETRY))
		return -EAGAIN;

	if (unlikely(fault & VM_FAULT_ERROR))
		return mm_fault_error(vma, address, regs, mode, fault, ftype);

	mmap_read_unlock(current->mm);

	if (fault == VM_FAULT_NOPAGE) {
		sync_mm_addr(address);
	}

	return 0;
}

int do_page_fault(struct pt_regs *const regs, e2k_addr_t address,
		  const tc_cond_t condition, const tc_mask_t mask,
		  pf_mode_t *mode_p, trap_cellar_t *tcellar)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	tc_fault_type_t ftype;
	tc_opcode_t opcode;
	union pf_mode mode;
	const int fmt = tc_cond_fmt_full(condition);
	const bool qp = (fmt == LDST_QP_FMT || fmt == TC_FMT_QPWORD_Q);
	int addr_num, handled = 0;
	int handle_status[2];
	int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

	DebugPF("started for addr 0x%lx\n", address);

	address = untagged_addr(address);

	if (user_mode(regs))
		flags = FAULT_FLAG_DEFAULT;

#ifdef CONFIG_KVM_ASYNC_PF
	/*
	 * If physical page was swapped out by host, than
	 * suspend current process until page will be loaded
	 * from swap.
	 */
	if (pv_apf_read_and_reset_reason() == KVM_APF_PAGE_IN_SWAP) {
		pv_apf_wait();
		DebugPF("apf waiting for addr 0x%lx\n", address);
		return PFR_IGNORE;
	}
#endif /* CONFIG_KVM_ASYNC_PF */

	if (nested_page_fault_injected(address, condition))
		return PFR_SUCCESS;

	AW(ftype) = condition.fault_type;
	AW(opcode) = condition.opcode;

	mode.word = 0;
	mode.write = tc_cond_is_store(condition);
	mode.exec = (regs->trap->nr_page_fault_exc == exc_instr_page_miss_num ||
		     regs->trap->nr_page_fault_exc == exc_instr_page_prot_num ||
		     regs->trap->nr_page_fault_exc == exc_ainstr_page_miss_num ||
		     regs->trap->nr_page_fault_exc == exc_ainstr_page_prot_num);
	mode.spec = condition.spec;
	mode.user = user_mode(regs);
	mode.controlled_user_access = (mode.user) ? 0 : controlled_user_access(regs);
	mode.root = condition.root;
	mode.empty = !mode.write && !condition.vr && !condition.vl;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	mode = set_kvm_fault_mode(condition, mode);
	mode = set_kvm_dont_inject_mode(regs, mode);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	if (likely(mode_p != NULL))
		*mode_p = mode;

	if (condition.num_align) {
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
	if (ftype.illegal_page) {
		AW(ftype) = 0;
		ftype.illegal_page = 1;
	}

	NATIVE_CLEAR_DAM;

	DebugPF("started for address 0x%lx, instruction page:%d fault type:0x%x condition 0x%llx root:%d missl:%d cpu%d user_mode_fault=%d\n",
		address, mode.exec, AW(ftype), AW(condition), mode.root,
		condition.miss_lvl, task_cpu(current), mode.user);

	if (mode.write)
		flags |= FAULT_FLAG_WRITE;
	if (mode.user)
		flags |= FAULT_FLAG_USER;
	if (mode.exec)
		flags |= FAULT_FLAG_INSTRUCTION;


	if (!IS_USER_ADDR(address))
		return handle_kernel_address(address, regs, mode, ftype);

	if (unlikely(!mm || faulthandler_disabled()
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
			|| mode.host_dont_inject
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
			)) {
		const char *reason = (!mm) ? "page fault in kernel" : "PF handler disabled";
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		if (!faulthandler_disabled())
			reason = "host_dont_inject is set";
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

		return kernel_mode_fault(reason, address, regs, mode, ftype);
	}

	if (pf_on_page_boundary(address, condition)
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
			&& !unlikely(tc_test_is_as_kvm_injected(condition))
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
			) {
		unsigned long pf_address;

		if (is_spurious_qp_store(mode.write, address, fmt, mask, &pf_address)) {
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
	 * occurring outside one of those areas which also holds mmap_lock
	 * might deadlock attempting to validate the fault against
	 * the address space.
	 *
	 * Only do the expensive exception table search when we might be at
	 * risk of a deadlock.  This happens if we
	 * 1. Failed to acquire mmap_lock, and
	 * 2. The access did not originate in userspace.
	 */
	if (unlikely(!mmap_read_trylock(mm))) {
		if (!from_uaccess_allowed_code(regs)
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
				&& !is_kvm_fault_injected(mode)
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
				) {
			/* It is kernel code where we do not expect faults */
			return kernel_mode_fault("page fault in kernel",
						 address, regs, mode, ftype);
		}
retry:
		mmap_read_lock(mm);
	} else {
		/*
		 * The above down_read_trylock() might have succeeded in
		 * which case we'll have missed the might_sleep() from
		 * down_read():
		 */
		might_sleep();
	}
	vma = vma_lookup(mm, address);
	DebugPF("find_vma() returned 0x%px\n", vma);
	if (!vma) {
		if (!is_spec_load_fault(mode)) {
			return bad_area("vma not found", address, NULL, regs, mode,
					addr_num, SEGV_MAPERR, ftype, false);
		}

		/*
		 * There is a race:
		 * 1) thread1 calls sys_munmap, detaches vma and downgrades
		 * mmap_sem to read.
		 * 2) thread2 enters page fault from semispec. load on address
		 * being unmapped by thread1 and locks mmap_sem for reading.
		 * It does not find vma.
		 * 3) thread1 calls destructor for pte/pmd page and frees
		 * corresponding spinlock.
		 * 4) thread2 tries to lock the same page from bad_area() ->
		 * clear_valid_on_spec_load() - use-after-free.
		 *
		 * Avoid race by re-acquiring semaphore with write permissions.
		 */
		mmap_read_unlock(mm);
		mmap_write_lock(mm);

		/* Check again since there is a window for another thread's mmap */
		vma = vma_lookup(mm, address);
		if (!vma) {
			return bad_area("vma not found", address, NULL, regs,
					mode, addr_num, SEGV_MAPERR, ftype, true);
		}

		mmap_write_downgrade(mm);
	}

	if (!mode.user && !mode.controlled_user_access) {
		return bad_area("raw access from kernel to user",
				address, vma, regs, mode, addr_num,
				SEGV_MAPERR, ftype, false);
	}

#ifdef CONFIG_MAKE_ALL_PAGES_VALID
	/*
	 * Following check only to debug the mode when all pages
	 * should be valid 'CONFIG_MAKE_ALL_PAGES_VALID'
	 */
	if (AW(ftype)) {
		int page_none = (vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC)) == 0;

		if (mode.exec && ftype.illegal_page) {
			tracing_off();
			return bad_area("instruction page protection for valid address",
					address, vma, regs, mode, addr_num,
					SEGV_MAPERR, ftype, false);
		}

		/* bug #102076: now this situation is possible */
		if (debug_semi_spec && ftype.illegal_page && !page_none)
			pr_notice("illegal_page for valid page, address 0x%lx\n", address);

		if (!(ftype.page_miss || ftype.priv_page || ftype.addr_prot_page ||
				ftype.global_sp || ftype.nwrite_page || ftype.illegal_page
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
				|| ftype_test_sw_fault(ftype)
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
				)) {
			return bad_area("trap with bad fault type for valid address",
					address, vma, regs, mode, addr_num,
					SEGV_ACCERR, ftype, false);
		}
	}
#endif /* CONFIG_MAKE_ALL_PAGES_VALID */

	/*
	 * Ok, we have a good vm_area for this memory access, so
	 * we can handle it..
	 */
	DebugPF("have good vm_area\n");

	if (unlikely(ftype.addr_prot_page)) {
		mmap_read_unlock(mm);
		return pf_force_sig_info("addr_prot_page", SIGSEGV, SEGV_ACCERR,
					 address, regs);
	}

	if (unlikely(ftype.exc_mem_lock || ftype.ph_pr_page || ftype.io_page ||
		     ftype.prot_page || ftype.isys_page || ftype.ph_bound
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		      || !ftype_has_sw_fault(ftype)
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
			)) {
		mmap_read_unlock(mm);
		return pf_force_sig_info("bad ftype", SIGBUS, BUS_ADRERR,
					 address, regs);
	}

	if (unlikely((vma->vm_flags & VM_PRIVILEGED))) {
		mode.priv = 1;
		if (likely(mode_p != NULL))
			*mode_p = mode;
	}

	if (ftype.nwrite_page) {
		DebugPF("write protection occured.\n");

#ifdef CONFIG_VIRTUALIZATION
		if (unlikely(vma->vm_flags & VM_MPDMA)) {
			WARN_ON_ONCE(vma->vm_flags & VM_WRITE);
			mmap_read_unlock(mm);
			return handle_mpdma_fault(address, regs);
		}
#endif
	}

	do {
		handle_status[handled] = handle_single_page(vma, regs, address,
						mode, ftype, flags, addr_num);
		switch (handle_status[handled]) {
		case -EAGAIN:
			/* Retry */
			flags |= FAULT_FLAG_TRIED;
			goto retry;
		case 0:
			/* For unaligned spec. load crossing page
			 * boundary fail only if both pages are invalid. */
			if (cpu_has(CPU_FEAT_PARTIAL_SPEC_LOAD) && is_spec_load_fault(mode) &&
					handled == 1 && handle_status[0]) {
				/* First page failed, second page handled */
				if (tcellar) {
					tcellar->partial_lower = 1;
				}
			}

			/* Continue with handling */
			break;
		default:
			/* For unaligned spec. load crossing page
			 * boundary fail only if both pages are invalid. */
			if (cpu_has(CPU_FEAT_PARTIAL_SPEC_LOAD) && is_spec_load_fault(mode)) {
				if (addr_num == 2) {
					/* First page failed, go check second */
					break;
				}
				if (handled == 1 && !handle_status[0]) {
					/* First page handled, second page failed */
					if (tcellar) {
						tcellar->partial_upper = 1;
					}
					break;
				}
			}

			/* Return error */
			return handle_status[handled];
		}

		++handled;
		--addr_num;
		if (unlikely(addr_num > 0)) {
			address = PAGE_ALIGN(address);
			flags &= ~FAULT_FLAG_TRIED;

			DebugNAO("not aligned operation will start handle_mm_fault() for next page 0x%lx\n",
				address);

			mmap_read_lock(mm);
			vma = vma_lookup(mm, address);
			DebugPF("find_vma() returned 0x%px\n", vma);
			if (!vma) {
				return bad_area("vma not found", address, vma, regs,
						mode, addr_num, SEGV_MAPERR, ftype, false);
			}
		}
	} while (unlikely(addr_num > 0));

	/*
	 * bug #102076
	 *
	 * For our special case we have to flush DTLB
	 * after putting the valid bit back into the pte.
	 */
	if (vma->vm_ops && ftype.illegal_page)
		local_flush_tlb_mm_range(mm, address, address + E2K_MAX_FORMAT,
					 PAGE_SIZE, FLUSH_TLB_LEVELS_LAST);

	DebugPF("handle_mm_fault() finished\n");

	if (cpu_has(CPU_HWBUG_INTC_INSTR_PAGE_MISS) && mode.exec && ftype.page_miss) {
		instr_item_t user_instr;
		__get_user(user_instr, (instr_item_t __user *) address);
	}

	return PFR_SUCCESS;
}

/**
 * get_load_recovery_mas - check for special cases when we have to use
 *		      different mas from what was specified in trap cellar
 * @condition: trap condition from trap cellar
 * @spec_ldrd: whether `ldrd` should be encoded as speculative, i.e. `,sm`
 *
 * 1) We should recover LOAD operation with MAS == FILL_OPERATION
 * to load the value with tags. In protected mode any value has tag.
 *
 * 2) Do not lock SLT
 */
__must_check
static int get_load_recovery_mas(tc_cond_t condition, int fmt,
		ldst_rec_op_t *ld_rec_opc, bool *spec_ldrd)
{
	int big_endian = tc_cond_is_big_endian(condition);

	*spec_ldrd = condition.spec;

	/*
	 * #127500 Do not execute "secondary lock trap on store" and
	 * "secondary lock trap on load/store" operations, instead
	 * downgrade them to simple loads:
	 *   "secondary lock trap on store" -> "secondary normal"
	 *   "secondary lock trap on load/store" -> "secondary normal"
	 */
	if (tc_cond_is_secondary_lock_trap_on_store(condition) ||
	    tc_cond_is_secondary_lock_trap_on_load_store(condition)) {
		ld_rec_opc->mas = MAS_NORMAL(CACHE_BYPASS_NONE, big_endian);
		return 0;
	}

	/*
	 * If LOAD with 'lock wait' MAS type then we should not use MAS
	 * to recover LOAD as regular operation. The real LOAD with real
	 * MAS will be repeated later after return from trap as result
	 * of pair STORE operation with 'wait unlock' MAS
	 */
	if (tc_cond_is_lock_wait(condition) ||
	    tc_cond_is_secondary_lock_wait(condition)) {
		ld_rec_opc->mas = MAS_NORMAL(CACHE_BYPASS_NONE, big_endian);
		return 0;
	}

	if (!cpu_has(CPU_FEAT_SPEC_PROT_LDRD) && !condition.npsp && TASK_IS_PROTECTED(current)) {
		/*
		 * If LOAD is protected then we should execute LDRD
		 * to get the value with tags. It is possible only using
		 * the special MAS in nonprotected mode
		 */
		if (tc_cond_is_normal(condition) ||
		    tc_cond_is_semi_speculative(condition) ||
		    tc_cond_is_speculative(condition) ||
		    tc_cond_is_check(condition) ||
		    tc_cond_is_check_unlock(condition) ||
		    tc_cond_is_lock_check(condition) ||
		    tc_cond_is_spec_lock_check(condition) ||
		    tc_cond_is_fill_operation(condition) ||
		    condition.fmt == LDST_QWORD_FMT && !tc_cond_is_special_mmu_aau(condition)) {
			ld_rec_opc->mas = MAS_FILL_OPERATION(CACHE_BYPASS_NONE, big_endian);
			*spec_ldrd = false;
			return 0;
		} else {
			pr_info("%s [%d]: cannot recover protected access with MAS 0x%x\n",
				current->comm, current->pid, condition.mas);
			return -EINVAL;
		}
	}

	ld_rec_opc->mas = condition.mas;
	return 0;
}

static inline void calculate_wr_data(int fmt, int offset,
				     u64 *data, u8 *data_tag)
{
	u64 wr_data;

	/* Avoid undefined behavior when shifting more than argument size */
	if (offset == 0) {
		wr_data = *data;
	} else {
		wr_data = (*data >> (offset * 8)) | (*data << ((8 - offset) * 8));
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
					u64 *data, u8 *data_tag,
					u64 *data_ext, u8 *data_tag_ext)
{
	/* Avoid undefined behavior when shifting more than argument size */
	if (offset == 0)
		return;

	u64 wr_data = (*data >> (offset * 8)) | (*data_ext << ((8 - offset) * 8));
	u64 wr_data_ext = (*data_ext >> (offset * 8)) | (*data << ((8 - offset) * 8));

	*data = wr_data;
	*data_ext = wr_data_ext;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static void recovery_store_with_bytes(unsigned long address,
				      unsigned long address_hi,
				      unsigned long address_hi_offset, u64 data,
				      u64 data_ext, ldst_rec_op_t st_rec_opc,
				      int chan, int length, int mask,
				      int mask_ext)
{
	int byte;

	st_rec_opc.fmt = LDST_BYTE_FMT;
	st_rec_opc.fmt_h = 0;

	for (byte = 0; byte < length; byte++, address++, data >>= 8, mask >>= 1) {
		if (address_hi_offset && byte == address_hi_offset)
			address = address_hi;

		if (byte == 8) {
			data = data_ext;
			mask = mask_ext;
		}

		if (mask & 1) {
			recovery_faulted_tagged_store(address, data, 0,
						      AW(st_rec_opc), 0, 0, 0,
						      chan, 0 /* qp_store */ ,
						      0 /* atomic_store */);

		}
	}
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static enum exec_mmu_ret do_recovery_store(struct pt_regs *regs,
		const trap_cellar_t *tcellar, trap_cellar_t *next_tcellar,
		unsigned long address, unsigned long address_hi_hva,
		int fmt, int chan, unsigned long hva_page_offset,
		bool priv_user)
{
	int length = tc_cond_to_size(tcellar->condition);
	bool user = user_mode(regs);
	bool qp_store, q_store, atomic_qp_store, atomic_q_store,
	     atomic_store, aligned_16 = IS_ALIGNED(address, 16);
	int strd_fmt, offset = address & 0x7;
	ldst_rec_op_t st_rec_opc, ld_rec_opc, st_opc_ext;
	u64 data, data_ext, mas = tcellar->condition.mas;
	u8 data_tag, data_ext_tag;
#ifdef	CONFIG_ACCESS_CONTROL
	e2k_upsr_t upsr_to_save;
#endif /* CONFIG_ACCESS_CONTROL */

	if (DEBUG_EXEC_MMU_OP) {
		u64 val;
		u8 tag;

		load_value_and_tagd(&tcellar->data, &val, &tag);
		DbgEXMMU("do_recovery_store: STRD store from trap cellar the data 0x%016llx tag 0x%x address 0x%lx offset %d\n",
			 val, tag, address, offset);
	}

	/*
	 * #74018 Do not execute store operation if rp_ret != 0
	 */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (unlikely(regs->trap->rp)) {
		DbgEXMMU("do_recovery_store: rp_ret != 0\n");
		return EXEC_MMU_SUCCESS;
	}
#endif

	bool big_endian = tc_cond_is_big_endian(tcellar->condition);

	/* See comment before `atomic_q[p]_load` in `do_recovery_load()` */
	qp_store = (fmt == LDST_QP_FMT || fmt == TC_FMT_QPWORD_Q);
	q_store = (fmt == LDST_QWORD_FMT || fmt == TC_FMT_QWORD_QP);
	atomic_qp_store = (cpu_has(CPU_FEAT_ISET_V6) || user) && aligned_16 && qp_store;
	atomic_q_store = (cpu_has(CPU_FEAT_ISET_V6) || user) && aligned_16 &&
			  q_store && chan == 1 && next_tcellar != NULL &&
			  fmt == tc_cond_fmt_full(next_tcellar->condition) &&
			  (next_tcellar->address % 16) == 8;

	atomic_store = (atomic_q_store || atomic_qp_store);

	if (atomic_q_store) {
		/* Skip second part of an atomic quadro store which takes
		 * up 2 records in cellar (it is reexecuted together with
		 * first part). */
		next_tcellar->done = 1;
	}

	/*
	 * Load data to store from trap cellar
	 */

	AW(ld_rec_opc) = 0;
	ld_rec_opc.prot = 1;
	ld_rec_opc.mas = MAS_FILL_OPERATION(CACHE_BYPASS_ALL, 0);
	ld_rec_opc.fmt = LDST_QWORD_FMT;
	ld_rec_opc.index = 0;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	ld_rec_opc.pm = priv_user;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	recovery_faulted_load((unsigned long) &tcellar->data, &data, &data_tag,
			      ld_rec_opc, 0, (tc_cond_t) {.word = 0});
	if (atomic_q_store || qp_store) {
		unsigned long addr_ext = (unsigned long)
				((qp_store) ? &tcellar->data_ext : &next_tcellar->data);
		recovery_faulted_load(addr_ext, &data_ext, &data_ext_tag,
				      ld_rec_opc, 0, (tc_cond_t) {.word = 0});
	}

	/* Updated algorithm since v6 does not require manual data rotation */
	if (!cpu_has(CPU_FEAT_ISET_V6)) {
		if (atomic_q_store) {
			/* This is aligned so offset == 0 */
			calculate_wr_data(fmt, offset, &data, &data_tag);
			calculate_wr_data(fmt, offset, &data_ext, &data_ext_tag);
		} else if (qp_store) {
			calculate_qp_wr_data(offset, &data, &data_tag,
					&data_ext, &data_ext_tag);
		} else {
			calculate_wr_data(fmt, offset, &data, &data_tag);
		}
	}

	DbgEXMMU("do_recovery_store: store(fmt 0x%x) chan = %d address = 0x%lx, data = 0x%llx tag = 0x%x\n",
		     fmt, chan, address, data, data_tag);

	/*
	 * Actually re-execute the store operation
	 */

	AW(st_rec_opc) = 0;
	/* Store as little endian. Do not clear the endianness bit
	 * unconditionally as it might mean something completely
	 * different depending on other bits in the trap cellar.*/
	st_rec_opc.mas = (big_endian) ? (mas & ~MAS_ENDIAN_MASK) : mas;
	st_rec_opc.prot = !tcellar->condition.npsp;
	st_rec_opc.root = tcellar->condition.root;
	if (cpu_has(CPU_FEAT_ISET_V7) && !st_rec_opc.prot &&
			__range_ok(address, length, TASK_SIZE)) {
		/* MMU_CR.svsc check should not trigger here so use unprivileged
		 * access (mode=4) instead of the privileged one (mode=0) */
		st_rec_opc.mode_h = 1;
	}
	if (fmt == TC_FMT_QPWORD_Q || fmt == TC_FMT_DWORD_Q)
		strd_fmt = LDST_QWORD_FMT;
	else if (fmt == TC_FMT_QWORD_QP || fmt == TC_FMT_DWORD_QP)
		strd_fmt = LDST_QP_FMT;
	else
		strd_fmt = fmt & 0x7;
	st_rec_opc.fmt = strd_fmt;
	st_rec_opc.mask = tcellar->mask.mask_lo;
	st_rec_opc.fmt_h = (cpu_has(CPU_FEAT_ISET_V5) && atomic_store);
	st_rec_opc.spec = (cpu_has(CPU_FEAT_SPEC_PROT_LDRD) && tcellar->condition.spec);
	if (cpu_has(CPU_FEAT_MADM)) {
		st_rec_opc.dcp = tcellar->condition.dcp;
	}

	st_opc_ext = st_rec_opc;
	st_opc_ext.mask = tcellar->mask.mask_hi;
	st_opc_ext.index = 8;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	st_rec_opc.pm = priv_user;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	/* For big endian case should swap the two operations. */
	if (atomic_q_store && big_endian) {
		swap(data, data_ext);
		swap(data_tag, data_ext_tag);
		swap(st_rec_opc, st_opc_ext);
	}

	ACCESS_CONTROL_DISABLE_AND_SAVE(upsr_to_save);


#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (unlikely(hva_page_offset)) {
		uaccess_enable();
		recovery_store_with_bytes(address, address_hi_hva,
					  hva_page_offset, data, data_ext,
					  st_rec_opc, chan, length,
					  tc_fmt_has_valid_mask(fmt) ?
						tcellar->mask.mask_lo : 0xff,
					  tc_fmt_has_valid_mask(fmt) ?
						tcellar->mask.mask_hi : 0xff);
		uaccess_disable();
	} else
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	if (cpu_has(CPU_FEAT_ISET_V6) && !atomic_store && !offset &&
			(fmt == LDST_DWORD_FMT || fmt == LDST_QWORD_FMT ||
			 fmt == TC_FMT_DWORD_Q || fmt == TC_FMT_QPWORD_Q)) {
		/*
		 * This `if` and the next one implement an algorithm that
		 * takes into account new iset v7 features:
		 * - STMQP causes spurious exc_data_page when masked bytes
		 *   land into unmapped memory;
		 * - STMQP above can be speculative in which case tags must
		 *   be copied into the good page.
		 *
		 * For atomic operations we'll fallback to the last `else`.
		 *
		 * It's suitable for v6 so use it there too.
		 */
		st_rec_opc.fmt = LDST_QWORD_FMT;
		st_rec_opc.fmt_h = 0;
		st_rec_opc.mask = 0;
		st_opc_ext = st_rec_opc;
		st_opc_ext.index = 8;
		uaccess_enable();
		recovery_faulted_tagged_store(address, data, data_tag,
				st_rec_opc, data_ext, data_ext_tag,
				st_opc_ext, chan, qp_store, atomic_store);
		uaccess_disable();
	} else if (cpu_has(CPU_FEAT_ISET_V6) && !atomic_store) {
		address -= offset;
		st_rec_opc.fmt = LDST_QP_FMT;
		st_rec_opc.fmt_h = 0;

		/* Calculate this single cellar entry's length and
		 * not the access length (they are different for qword) */
		int entry_length = (fmt == LDST_QWORD_FMT || fmt == TC_FMT_QWORD_QP ||
			      fmt == TC_FMT_DWORD_Q || fmt == TC_FMT_DWORD_QP) ? 8 :
			     (fmt == LDST_QP_FMT || fmt == TC_FMT_QPWORD_Q) ? 16 :
			     (1 << ((fmt & 0x7) - 1));

		unsigned long mask;
		if (fmt == LDST_QP_FMT || fmt == TC_FMT_QWORD_QP || fmt == TC_FMT_DWORD_QP) {
			mask = 0;
			bitmap_set_value8(&mask, tcellar->mask.mask_lo, 0);
			bitmap_set_value8(&mask, tcellar->mask.mask_hi, 8);
		} else {
			mask = (1 << entry_length) - 1;
		}

		for (mask <<= offset; mask; mask >>= 8) {
			u64 value;
			u8 value_tag;

			if (fmt == LDST_QP_FMT && !IS_ALIGNED((u32) st_rec_opc.index, 16)) {
				value = data_ext;
				value_tag = data_ext_tag;
			} else {
				value = data;
				value_tag = data_tag;
			}

			st_rec_opc.mask = bitmap_get_value8(&mask, 0);

			uaccess_enable();
			recovery_faulted_tagged_store(address, value, value_tag,
					st_rec_opc, 0, 0,
					st_rec_opc, chan, 0, 0);
			uaccess_disable();

			st_rec_opc.index += 8;
		}
	} else {
		uaccess_enable();
		recovery_faulted_tagged_store(address, data, data_tag,
					      st_rec_opc, data_ext, data_ext_tag,
					      st_opc_ext, chan, qp_store, atomic_store);
		uaccess_disable();
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
 * @radr: address of a "normal" register will be returned here
 *
 * This function calculates and sets @greg_num_d, @greg_recovery,
 * @rotatable_greg, @src_bgr, @radr.
 *
 * @radr is set to: 0 - no target register; -1 - global target register;
 * actual address otherwise.
 *
 * Returns zero on success and value of type exec_mmu_ret on failure.
 */
static int calculate_recovery_load_parameters(struct pt_regs *regs, tc_cond_t cond,
		unsigned *greg_num_d, bool *greg_recovery, u64 *radr)
{
	unsigned vr = cond.vr;
	unsigned vl = cond.vl;
	unsigned dst_addr = cond.address;

	DbgTC("load request vr=%d\n", vr);

	/*
	 * Calculate register's address
	 */
	if (!vr && !vl) {
		/*
		 * Destination register to load is NULL
		 * We should load the value from address into "air"
		 */
		*radr = 0;
		DbgEXMMU("<dst> is NULL register\n");
	} else if (!vl) {
		panic("Invalid destination: 0x%x : vl is 0 %s(%d)\n",
		      cond.dst, __FILE__, __LINE__);
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
		*radr = -1ull;
		*greg_num_d = dst_addr - (E2K_MAXNR_d - E2K_MAXGR_d);
	} else if (dst_addr < E2K_MAXSR_d) {
		/* it need calculate address of register */
		/* into register file frame */
		return -1;
	} else {
		panic("Invalid destination register %d in the trap cellar %s(%d)\n",
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
static enum exec_mmu_ret calculate_recovery_load_to_rf_frame(struct pt_regs *regs,
			tc_cond_t cond, u64 *radr, bool *load_to_rf)
{
	unsigned dst_addr = cond.address;
	unsigned w_base_rnum_d;
	u64 frame_top = 0;
	unsigned rnum_offset_d;
#ifdef	CHECK_PSHTP
	register long lo_1, lo_2, hi_1, hi_2;
	register long pshtp_tind_d = regs->stacks.pshtp.tind / 8;
	register long wd_base_d = regs->wd.base / 8;

	if (!regs->stacks.pshtp.tind) {
		pr_err("%s(): PSHTP.tind is zero, PSHTP.ind is 0x%x\n",
		       __func__, regs->stacks.pshtp.ind);
		return EXEC_MMU_SUCCESS;
	}
#endif /* CHECK_PSHTP */

	BUG_ON(!(dst_addr < E2K_MAXSR_d));

	/*
	 * We can be sure that we search in right window, and we can be
	 * not afraid of nested calls, because we take as base registers
	 * that were saved when we entered in trap handler, these registers
	 * pointed to last window before interrupt.
	 * When we came to interrupt we have new window which is defined
	 * by WD (current window register) in double words which was saved
	 * in regs->wd and we use it:
	 *      w_base_rnum_d = regs->wd;
	 * Window regs file (RF) is a ring buffer with size == E2K_MAXSR_d.
	 * So w_base_rnum_d can be > or < then num of destination register
	 * (dst_addr):
	 *
	 *      w_base_rnum_d > dst_addr:
	 *
	 * RF 0<----| PREV-WD | TRAP WD |----------->E2K_MAXSR_d
	 *              ^dst_addr
	 *                    ^w_base_rnum_d
	 *
	 *      w_base_rnum_d < dst_addr:
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
	 *      frame_top = base + ind;
	 */

	frame_top = (unsigned long)U_PSP_PTR(regs->stacks.psp);

	/*
	 *  w_base_rnum_d is address of double reg
	 *  NR_REA_d(regs->wd, 0) is eguivalent to:
	 *  w_base_rnum_d = AS_STRUCT(regs->wd).base / 8;
	 */
	w_base_rnum_d = NR_REA_d(regs->wd, 0);

	/*
	 * Offset from beginning spilled quad-NR for our
	 * dst_addr is
	 *      rnum_offset_d.
	 * We define rnum_offset_d for dst_addr from frame_top
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
	 *      (rnum_offset_d + 1) / 2) * 32
	 * if it was uneven number we should add size of double:
	 *      (rnum_offset_d % 2) * 8
	 * starting from ISET V5 we should add size of quadro.
	 */
	*radr = frame_top - ((rnum_offset_d + 1) / 2) * 32;
	if (rnum_offset_d % 2)
		*radr += machine.qnr1_offset;
	DbgEXMMU("<dst> is window register: rnum_d = 0x%x offset 0x%x, PS base 0x%llx WD base = 0x%x, radr = 0x%llx\n",
		 dst_addr, rnum_offset_d, frame_top, w_base_rnum_d, *radr);

	if (*radr < PSP_BASE(regs->stacks.psp) || *radr >= frame_top) {
		/*
		 * The load operation out of current register window frame
		 * (for example this load is placed in one wide instruction
		 * with return).  The load operationb should be ignored.
		 */
		DbgEXMMU("<dst> address of register window points out of current procedure stack frame 0x%llx >= 0x%llx, load operation will be ignored\n",
			*radr, frame_top);
		return EXEC_MMU_SUCCESS;
	}

	/*
	 * Check if target register has been SPILLed to kernel
	 */
	if (frame_top < TASK_SIZE) {
		u64 first_spilled = frame_top - PSHTP_MEM_INDEX(regs->stacks.pshtp);

		if (*radr < TASK_SIZE && *radr >= first_spilled)
			*radr += PSP_BASE(current_thread_info()->k_psp) - first_spilled;
	}

	*load_to_rf = true;
	return 0;
}

static unsigned long byte_to_src(int byte, unsigned long address,
		unsigned long address_hi, unsigned long address_hi_offset)
{
	if (address_hi_offset && byte >= address_hi_offset) {
		return address_hi + (byte - address_hi_offset);
	} else {
		return address + byte;
	}
}

static unsigned long byte_to_dst(int byte, unsigned long reg_address, unsigned long reg_address_hi)
{
	return (byte < 8) ? reg_address + byte : reg_address_hi + (byte - 8);
}

static void load_with_bytes(unsigned long address, unsigned long address_hi,
		unsigned long address_hi_offset, unsigned long reg_address,
		unsigned long reg_address_hi, ldst_rec_op_t ld_rec_opc,
		int chan, const trap_cellar_t *tcellar, bool spec_ldrd)
{
	tc_cond_t cond = tcellar->condition;
	bool big_endian = tc_cond_is_big_endian(cond);
	int length = tc_cond_to_size(cond);
	unsigned long next_page = round_up(address, PAGE_SIZE);

	ld_rec_opc.fmt = LDST_BYTE_FMT;
	ld_rec_opc.fmt_h = 0;

	for (int byte = 0; byte < round_up(length, 8); byte++) {
		/* Revert direction if big endian */
		unsigned long dst = (big_endian)
			? byte_to_dst(length - 1 - byte, reg_address, reg_address_hi)
			: byte_to_dst(byte, reg_address, reg_address_hi);

		/* Outer part of register should be 0-filled */
		if (byte >= length)
			goto clear_byte;

		/* Skip some bytes in vr=0 case */
		if (!cond.vr && (!big_endian && byte < 4 || big_endian && byte + 4 >= length))
			continue;

		if (tcellar->partial_lower && address + byte < next_page ||
		    tcellar->partial_upper && address + byte >= next_page) {
			/* Partially faulting semispeculative load,
			 * replace the unmapped part with zero */
clear_byte:
			if (dst < TASK_SIZE) {
				put_priv(0, (u8 __priv *) dst);
			} else {
				*(u8 *) dst = 0;
			}
		} else {
			unsigned long src = byte_to_src(byte, address, address_hi,
							address_hi_offset);

			uaccess_enable();
			recovery_faulted_move(src, dst, 0,
					1 /* vr */ , ld_rec_opc, chan, 0 /* qp_load */,
					0 /* atomic_load */, false /* big_endian */,
					true /* single_byte */, cond,
					false /* clear_lo */, false /* clear_hi */, spec_ldrd);
			uaccess_disable();
		}
	}
}

static void debug_print_recovery_load(unsigned long address, int fmt,
				      unsigned long radr, int chan,
				      unsigned greg_recovery,
				      unsigned greg_num_d,
				      ldst_rec_op_t ld_rec_opc)
{
	u64 val;
	u8 tag = 0;
#ifdef	CONFIG_ACCESS_CONTROL
	e2k_upsr_t upsr_to_save;
#endif

	if (DEBUG_EXEC_MMU_OP) {
		ACCESS_CONTROL_DISABLE_AND_SAVE(upsr_to_save);
		if (!radr) {
			recovery_faulted_load(address, &val, &tag,
					ld_rec_opc, 2, (tc_cond_t) {.word = 0});
		} else if (greg_recovery) {
			E2K_GET_DGREG_VAL_AND_TAG(greg_num_d, val, tag);
		} else {
			load_value_and_tagd((volatile void *) radr, &val, &tag);
		}
		ACCESS_CONTROL_RESTORE(upsr_to_save);

		DbgEXMMU("do_recovery_load: load(fmt 0x%x) chan = %d "
			"address = 0x%lx, %s = %d, rdata = 0x%llx tag = 0x%x\n",
			fmt, chan, address, (greg_recovery) ? "greg" : "radr",
			greg_num_d, val, tag);
	}
}

static inline bool is_atomic_q_load(struct pt_regs *regs, const trap_cellar_t *tcellar,
			trap_cellar_t *next_tcellar, unsigned long address, int fmt, int chan)
{
	bool user = user_mode(regs);
	bool aligned_16 = IS_ALIGNED(address, 16);
	bool q_load = (fmt == LDST_QWORD_FMT || fmt == TC_FMT_QWORD_QP);

	return (cpu_has(CPU_FEAT_ISET_V6) || user) && aligned_16 && q_load &&
	       (chan == 0 || chan == 2) && next_tcellar != NULL &&
	       fmt == tc_cond_fmt_full(next_tcellar->condition) &&
	       (next_tcellar->address % 16) == 8 &&
	       tcellar->condition.vl == next_tcellar->condition.vl &&
	       tcellar->condition.vr == next_tcellar->condition.vr;
}

static volatile u64 *greg_num_to_addr(const struct pt_regs *regs, unsigned int greg_num_d)
{
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	volatile u64 *tmp;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	if (greg_num_d >= SCRATCH_GREGS_START && !user_mode(regs)) {
		/* Load to scratch gregs in kernel */
		return &regs->trap->k_gregs.g[greg_num_d - SCRATCH_GREGS_START].base;
	} else if (greg_num_d >= LOCAL_GREGS_START) {
		/* Load to local gregs in user */
		WARN_ON_ONCE(!user_mode(regs));
		return &current->thread.u_gregs.g[greg_num_d - KERNEL_GREGS_PAIRS_START].base;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	} else if (is_guest_kernel_gregs(current_thread_info(), greg_num_d, (u64 **)&tmp)) {
		BUG_ON(tmp == NULL);
		return tmp;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	} else {
		return NULL;
	}
}

static enum exec_mmu_ret do_recovery_load(struct pt_regs *regs,
		const trap_cellar_t *tcellar, trap_cellar_t *next_tcellar,
		unsigned long address, unsigned long address_hi_hva,
		unsigned long radr, int fmt, int chan, unsigned greg_recovery,
		unsigned greg_num_d, unsigned long hva_page_offset, bool priv_user)
{
	tc_cond_t cond = tcellar->condition;
	ldst_rec_op_t	ld_rec_opc;
	unsigned	vr = cond.vr;
	int ldrd_fmt;
#ifdef	CONFIG_ACCESS_CONTROL
	e2k_upsr_t	upsr_to_save;
#endif
	int length = tc_cond_to_size(cond);
	bool user = user_mode(regs);
	bool aligned_16 = IS_ALIGNED(address, 16);
	bool spec_ldrd;

	bool clear_lo = false, clear_hi = false;
	if ((tcellar->partial_lower || tcellar->partial_upper) && cond.spec && length == 16) {
		/*
		 * 16-bytes loads are reexecuted by two `ldrd` instructions.
		 * In partial fault case when one `ldrd` happens to land
		 * fully into unmapped page we must manually clear the
		 * resulting tag, because this `ldrd` has no way of knowing
		 * that it's part of a larger operation with partial fault.
		 */
		size_t lower_length = round_up(address, PAGE_SIZE) - address;
		size_t upper_length = length - lower_length;

		if (tcellar->partial_lower && lower_length >= 8)
			clear_lo = true;
		if (tcellar->partial_upper && upper_length >= 8)
			clear_hi = true;
	}

	/*
	 * Things to keep in mind:
	 * 1) We have to distinguish between ldrd/strd with fmtr="qword"
	 *    and real quadro loads (and same goes for fmtr="qpword" and
	 *    real qp loads).  Since iset v6 this is done by hardware but
	 *    before v6 there is no reliable way so just do not use 16 byte
	 *    atomics that can fault in kernel.
	 * 2) SPILL/FILL RF without FX is done with LDST_QWORD_FMT but with
	 *    next_tcellar->address == tcellar->address + 16.  Do not try
	 *    to repeat this atomically.
	 * 3) Quadro [packed] loads/stores can be not atomic in the sense
	 *    that they do not use atomic MAS, but they still must be
	 *    executed atomically as in one 16-bytes access instead of e.g.
	 *    two 8-bytes accesses (otherwise atomic relaxed loads/stores
	 *    would have to be implemented through atomic MAS, or user in
	 *    protected mode would be able to combine parts of different
	 *    descriptors).
	 */
	bool qp_load = (fmt == LDST_QP_FMT || fmt == TC_FMT_QPWORD_Q);
	bool atomic_qp_load = (cpu_has(CPU_FEAT_ISET_V6) || user) && aligned_16 && qp_load;
	bool atomic_q_load = is_atomic_q_load(regs, tcellar, next_tcellar, address, fmt, chan);
	bool atomic_load = (atomic_q_load || atomic_qp_load);

	bool big_endian = tc_cond_is_big_endian(cond);

	/*
	 * Skip second part of an atomic quadro load which takes up 2 records in cellar (it is
	 * reexecuted together with first part).
	 */
	if (atomic_q_load)
		next_tcellar->done = 1;

	if (DEBUG_EXEC_MMU_OP && radr) {
		u64	val;
		u8	tag;

		if (greg_recovery) {
			E2K_GET_DGREG_VAL_AND_TAG(greg_num_d, val, tag);
		} else {
			uaccess_enable();
			load_value_and_tagd((volatile void *) radr, &val, &tag);
			uaccess_disable();
		}

		DbgEXMMU("load from register file background register value 0x%llx tag 0x%x\n",
			val, tag);
	}

	/*
	 * #74018 Do not execute load operation if rp_ret != 0
	 */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (unlikely(regs->trap->rp)) {
		DbgEXMMU("do_recovery_load: rp_ret != 0\n");
		return EXEC_MMU_SUCCESS;
	}
#endif

	/* BUG 79642: ignore tcellar->condition.empt field */
	AW(ld_rec_opc) = 0;
	if (!user_mode(regs) && controlled_user_access(regs)) {
		/* mas is correct if controlled access frpm kernel to user */
		spec_ldrd = false;
	} else if (get_load_recovery_mas(cond, fmt, &ld_rec_opc, &spec_ldrd)) {
		force_sig(SIGKILL);
		return EXEC_MMU_SUCCESS;
	}
	ld_rec_opc.prot = !cond.npsp;
	ld_rec_opc.root = cond.root;
	if (cpu_has(CPU_FEAT_ISET_V7) && !ld_rec_opc.prot &&
			__range_ok(address, length, TASK_SIZE)) {
		/* MMU_CR.svsc check should not trigger here so use unprivileged
		 * access (mode=4) instead of the privileged one (mode=0) */
		ld_rec_opc.mode_h = 1;
	}
	if (fmt == TC_FMT_QPWORD_Q || fmt == TC_FMT_DWORD_Q)
		ldrd_fmt = LDST_QWORD_FMT;
	else if (fmt == TC_FMT_QWORD_QP || fmt == TC_FMT_DWORD_QP)
		ldrd_fmt = LDST_QP_FMT;
	else
		ldrd_fmt = fmt & 0x7;
	ld_rec_opc.fmt = ldrd_fmt;
	ld_rec_opc.fmt_h = (cpu_has(CPU_FEAT_ISET_V5) && atomic_load);
	ld_rec_opc.spec = (cpu_has(CPU_FEAT_SPEC_PROT_LDRD) && cond.spec);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	ld_rec_opc.pm = priv_user;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	ACCESS_CONTROL_DISABLE_AND_SAVE(upsr_to_save);

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (tc_cond_is_secondary_lock_trap_on_store(cond) ||
	    tc_cond_is_secondary_lock_trap_on_load_store(cond)) {
		struct thread_info *ti = current_thread_info();
		e2k_cr0_t cr0 = regs->crs.cr0;

		WARN_ON(get_cr0_ip(cr0) < ti->rp_start ||
			get_cr0_ip(cr0) >= ti->rp_end);
		regs->trap->rp = 1;
	}
#endif

	if (!greg_recovery) {
		/* Load to %r/%b register - move data
		 * to register location in memory */
		unsigned long reg_address, reg_address_hi;
		u64 fake_reg[3] __aligned(16);

		reg_address = radr ?: (unsigned long) fake_reg;
		reg_address_hi = reg_address +
				 ((!cpu_has(CPU_FEAT_QPREG) || qp_load) ? 8 : 16);

		if (likely(!hva_page_offset &&
				(cpu_has(CPU_FEAT_SPEC_PROT_LDRD) ||
				 !tcellar->partial_lower && !tcellar->partial_upper))) {
			uaccess_enable();
			recovery_faulted_move(address, reg_address,
					reg_address_hi, vr, ld_rec_opc, chan,
					qp_load, atomic_load, big_endian, false,
					cond, clear_lo, clear_hi, spec_ldrd);
			uaccess_disable();
		} else {
			load_with_bytes(address, address_hi_hva,
					hva_page_offset, reg_address,
					reg_address_hi, ld_rec_opc, chan, tcellar, spec_ldrd);
		}
	} else {
		/* Load to %g register */
		volatile u64 *saved_greg_lo, *saved_greg_hi = NULL;

		saved_greg_lo = greg_num_to_addr(regs, greg_num_d);
		if (saved_greg_lo) {
			if (!atomic_q_load) {
				saved_greg_hi = &saved_greg_lo[1];
			} else if (greg_num_d + 1 < E2K_MAXGR_d) {
				saved_greg_hi = greg_num_to_addr(regs, greg_num_d + 1);
			} else {
				WARN_ONCE(1, "atomic load to %%g31 ignored\n");
				return EXEC_MMU_SUCCESS;
			}
		}

		if (likely(!hva_page_offset &&
				(cpu_has(CPU_FEAT_SPEC_PROT_LDRD) ||
				 !tcellar->partial_lower && !tcellar->partial_upper))) {
			uaccess_enable();
			recovery_faulted_load_to_greg(address, greg_num_d, vr,
					ld_rec_opc, chan, qp_load, atomic_load, big_endian,
					(u64 __force *)saved_greg_lo, (u64 __force *)saved_greg_hi,
					cond, clear_lo, clear_hi, spec_ldrd);
			uaccess_disable();
		} else {
			u64 tmp[2] __aligned(16);

			load_with_bytes(address, address_hi_hva, hva_page_offset,
					(unsigned long)(saved_greg_lo ?: &tmp[0]),
					(unsigned long)(saved_greg_hi ?: &tmp[1]),
					ld_rec_opc, chan, tcellar, spec_ldrd);

			if (!saved_greg_lo) {
				/* privileged access into primary unprotected area */
				ld_rec_opc.mode_h = 0;
				ld_rec_opc.root = 0;
				ld_rec_opc.prot = 0;

				uaccess_enable();
				recovery_faulted_load_to_greg((unsigned long) tmp,
						greg_num_d, vr, ld_rec_opc, chan, qp_load,
						atomic_load, 0, NULL, NULL,
						cond, clear_lo, clear_hi, spec_ldrd);
				uaccess_disable();
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

	store = cond.store;
	if (unlikely(cond.s_f || s_f)) {
		e2k_addr_t stack_base;
		e2k_size_t stack_ind;

		/*
		 * Not completed SPILL operation should be completed here
		 * by data store
		 * Not completed FILL operation replaced by restore of saved
		 * filling data in trap handler
		 */

		DbgEXMMU("completion of %s %s operation\n",
			 cond.sru ? "PCS" : "PS", (store) ? "SPILL" : "FILL");
		if (cond.sru) {
			stack_base = PCSP_BASE(regs->stacks.pcsp);
			stack_ind = PCSP_IND(regs->stacks.pcsp);
		} else {
			stack_base = PSP_BASE(regs->stacks.psp);
			stack_ind = PSP_IND(regs->stacks.psp);
		}
		if (address < stack_base || address >= stack_base + stack_ind) {
			pr_info("%s(): invalid hardware stack addr 0x%lx < stack base 0x%lx or >= current stack offset 0x%lx\n",
			       __func__, address, stack_base,
			       stack_base + stack_ind);
			BUG();
		}
		if (!store && !cond.sru) {
			pr_info("execute_mmu_operations(): not completed PS FILL operation detected in TC (only PCS FILL operation can be dropped to TC)\n");
			BUG();
		}
		return true;
	}
	return false;
}

#if defined CONFIG_KVM_PARAVIRTUALIZATION || defined CONFIG_KVM_GUEST_KERNEL
static enum exec_mmu_ret convert_pv_gva_to_hva(unsigned long *address_hva_p,
					       bool is_write,
					       unsigned long address,
					       size_t size,
					       const struct pt_regs *regs)
{
	void __user *address_hva = guest_ptr_to_host((void *)address, is_write,
					      size, regs);

	if (unlikely(IS_ERR(address_hva))) {
		pr_err_ratelimited("%s(): could not convert page fault addr 0x%lx to recovery format, error %ld\n",
		     __func__, address, PTR_ERR(address_hva));
		if (PTR_ERR(address_hva) == -EAGAIN)
			return EXEC_MMU_REPEAT;
		else
			return EXEC_MMU_STOP;
	}

	*address_hva_p = (unsigned long) address_hva;

	return EXEC_MMU_SUCCESS;
}
#endif

enum exec_mmu_ret execute_mmu_operations(trap_cellar_t *tcellar,
		trap_cellar_t *next_tcellar, struct pt_regs *regs,
		bool (*is_spill_fill_recovery)(tc_cond_t cond,
					e2k_addr_t address, bool s_f,
					struct pt_regs *regs),
		enum exec_mmu_ret (*calculate_rf_frame)(struct pt_regs *regs,
					tc_cond_t cond, u64 *radr, bool *load_to_rf),
		bool priv_user)
{
	unsigned long	flags, hva_page_offset = 0;
	tc_cond_t	cond = tcellar->condition;
	e2k_addr_t	address = tcellar->address, address_hi = 0;
	int		chan, store, fmt, ret;
	bool		is_s_f;

	DbgEXMMU("started\n");
	DebugPtR(regs);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (unlikely(tc_test_is_as_kvm_injected(cond))) {
		/* fault is injected by KVM for guest only to eliminate */
		/* a page fault reason and load/store is fake operation */
		return EXEC_MMU_SUCCESS;
	}

	if (unlikely(tc_test_is_as_kvm_recovery_user(cond))) {
		/* fault is injected by KVM for guest load/store recover */
		/* operation (privileged hypercall) and guest should */
		/* reexecute this operation itself */

		/* reset condition flag to signal successful fault completion */
		cond = tc_reset_kvm_recovery_user(cond);
		tcellar->condition = cond;
		return EXEC_MMU_SUCCESS;
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	fmt = tc_cond_fmt_full(cond);
	BUG_ON(fmt == 6 || fmt == 0 || fmt > 7 && fmt < 0xd || fmt == 0xe ||
	       fmt >= 0x10 && fmt < 0x14 || fmt >= 0x16 && fmt <= 0x1e ||
	       fmt >= 0x20);

	/*
	 * If ld/st hits to page boundary page, page fault can occur on first
	 * or on second page. If page fault occurs on second page, we need to
	 * correct addr. In this case addr points to the end of touched area.
	 */
	if (cond.num_align) {
		if (fmt != LDST_QP_FMT && fmt != TC_FMT_QPWORD_Q)
			address -= 8;
		else
			address -= 16;
	}

	store = cond.store;

	if (likely(is_spill_fill_recovery == NULL)) {
		is_s_f = check_spill_fill_recovery(cond, tcellar->address,
						   IS_SPILL(tcellar[0]), regs);
	} else {
		is_s_f = is_spill_fill_recovery(cond, address,
						IS_SPILL(tcellar[0]), regs);
	}

#if defined CONFIG_KVM_PARAVIRTUALIZATION || defined CONFIG_KVM_GUEST_KERNEL
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
	if (host_test_intc_emul_mode(regs) && !tcellar->is_hva ||
			IS_ENABLED(CONFIG_KVM_GUEST_KERNEL)) {
		unsigned long address_lo_hva;
		int size = tc_cond_to_size(cond);
		int size_lo = min_t(int, PAGE_SIZE - (int)offset_in_page(address), size);
		bool is_write = is_s_f || store;

		ret = convert_pv_gva_to_hva(&address_lo_hva, is_write,
					address, size_lo, regs);
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
			ret = convert_pv_gva_to_hva(&address_hi_hva, is_write,
						    PAGE_ALIGN(address), size - size_lo, regs);
			if (ret != EXEC_MMU_SUCCESS)
				return ret;

			address_hi = address_hi_hva;
			hva_page_offset = size_lo;
		}

		address = address_lo_hva;
	}
#endif

	if (is_s_f)
		store = 1;

	chan = cond.chan;
	BUG_ON((unsigned int)chan > 3 || store && !(chan & 1));

	regs->flags.exec_mmu_op = 1;

	if (store) {
		/*
		 * Here performs dropped store operation, opcode.fmt contains
		 * size of data that must be stored, address it's address where
		 * data must be stored, data is data ;-)
		 */
		raw_all_irq_save(flags);
		ret = do_recovery_store(regs, tcellar, next_tcellar, address,
					address_hi, fmt, chan, hva_page_offset,
					priv_user);
		raw_all_irq_restore(flags);
	} else {
		/*
		 * Here we perform a load operation which is more difficult
		 * than store, we know only the register's number in interrupted
		 * frame, so we need to SPILL register file to memory and then
		 * find the needed register in it; only then perform operation.
		 */
		unsigned greg_num_d = -1;
		bool greg_recovery = false;
		bool load_to_rf = false;
		u64 radr;

		ret = calculate_recovery_load_parameters(regs, cond, &greg_num_d,
							 &greg_recovery, &radr);
		if (ret < 0) {
			if (likely(calculate_rf_frame == NULL)) {
				ret = calculate_recovery_load_to_rf_frame(regs, cond,
									  &radr, &load_to_rf);
			} else {
				ret = calculate_rf_frame(regs, cond, &radr, &load_to_rf);
			}
		}

		if (!ret) {
			if (radr && (unsigned long) radr < PAGE_OFFSET) {
				unsigned long ts_flag;
				tc_cond_t cond;
				tc_mask_t mask;

				regs->trap->nr_page_fault_exc = exc_data_page_num;

				AW(mask) = 0;

				AW(cond) = 0;
				cond.store = 1;
				cond.fmt = LDST_BYTE_FMT;

				ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
				ret = do_page_fault(regs, radr,
						cond, mask, NULL, NULL);
				clear_ts_flag(ts_flag);

				if (ret == PFR_SIGPENDING) {
					ret = EXEC_MMU_STOP;
					goto out;
				}
			}

			raw_all_irq_save(flags);
			if (load_to_rf)
				COPY_STACKS_TO_MEMORY();
			ret = do_recovery_load(regs, tcellar, next_tcellar,
					address, address_hi, radr,
					fmt, chan, greg_recovery, greg_num_d,
					hva_page_offset, priv_user);
			raw_all_irq_restore(flags);
		}
	}


out:
	regs->flags.exec_mmu_op = 0;
	regs->flags.exec_mmu_op_nested = 0;

	return ret;
}
