/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * VCPU MMU  virtualization, based on x86 code
 */

#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/rmap.h>
#include <linux/pagemap.h>
#include <linux/pfn_t.h>
#include <linux/gfp.h>
#include <linux/hugetlb.h>
#include <linux/syscalls.h>
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/uaccess.h>
#include <linux/sched/mm.h>

#include <asm/mmu_regs_types.h>
#include <asm/tlbflush.h>
#include <asm/pgalloc.h>
#include <asm/mman.h>
#include <asm/tlb.h>
#include <asm/process.h>
#include <asm/kvm/gpid.h>
#include <asm/kvm/trace_kvm_pv.h>

#include "process.h"
#include "cpu.h"
#include "mmu_defs.h"
#include "mmu.h"
#include "gaccess.h"
#include "user_area.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_PARAVIRT_FAULT_MODE
#undef	DebugKVMPVF
#define	DEBUG_KVM_PARAVIRT_FAULT_MODE	0	/* paravirt page fault on KVM */
#define	DebugKVMPVF(fmt, args...)					\
({									\
	if (DEBUG_KVM_PARAVIRT_FAULT_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_PAGE_FAULT_MODE
#undef	DebugKVMPF
#define	DEBUG_KVM_PAGE_FAULT_MODE	0	/* page fault on KVM */
#define	DebugKVMPF(fmt, args...)					\
({									\
	if (DEBUG_KVM_PAGE_FAULT_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_VM_PAGE_FAULT_MODE
#undef	DebugKVMVMPF
#define	DEBUG_KVM_VM_PAGE_FAULT_MODE	0	/* page fault on KVM VM */
#define	DebugKVMVMPF(fmt, args...)					\
({									\
	if (DEBUG_KVM_VM_PAGE_FAULT_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_FREE_GUEST_USER_MODE
#undef	DebugKVMFGU
#define	DEBUG_KVM_FREE_GUEST_USER_MODE	0	/* free guest user VM */
#define	DebugKVMFGU(fmt, args...)					\
({									\
	if (DEBUG_KVM_FREE_GUEST_USER_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_FREE_GUEST_PTE_MODE
#undef	DebugKVMFGUPTE
#define	DEBUG_KVM_FREE_GUEST_PTE_MODE	0	/* free guest user PTEs */
#define	DebugKVMFGUPTE(fmt, args...)					\
({									\
	if (DEBUG_KVM_FREE_GUEST_PTE_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_LOCKED_GUEST_USER_MODE
#undef	DebugKVMLGU
#define	DEBUG_KVM_LOCKED_GUEST_USER_MODE	0	/* check locked */
							/* guest user area */
#define	DebugKVMLGU(fmt, args...)					\
({									\
	if (DEBUG_KVM_LOCKED_GUEST_USER_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_LOCKED_GUEST_PTE_MODE
#undef	DebugKVMLGUPTE
#define	DEBUG_KVM_LOCKED_GUEST_PTE_MODE	0	/* check locked guest user */
						/* area PTEs */
#define	DebugKVMLGUPTE(fmt, args...)					\
({									\
	if (DEBUG_KVM_LOCKED_GUEST_PTE_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_PTE_MODE
#undef	DebugKVMPTE
#define	DEBUG_KVM_PTE_MODE	0	/* set and clear pte on KVM */
#define	DebugKVMPTE(fmt, args...)					\
({									\
	if (DEBUG_KVM_PTE_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_GUEST_VALID_MODE
#undef	DebugMGV
#define	DEBUG_GUEST_VALID_MODE	0	/* make valid guest pages */
#define	DebugMGV(fmt, args...)						\
({									\
	if (DEBUG_GUEST_VALID_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_GUEST_FREE_PT_MODE
#undef	DebugFPT
#define	DEBUG_GUEST_FREE_PT_MODE	0	/* free guest user pages */
						/* table entries */
#define	DebugFPT(fmt, args...)						\
({									\
	if (DEBUG_GUEST_FREE_PT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_USER_PTE_MODE
#undef	DebugUPTE
#define	DEBUG_USER_PTE_MODE	0	/* set and clear user ptes on KVM */
#define	DebugUPTE(fmt, args...)						\
({									\
	if (DEBUG_USER_PTE_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_VALIDATE_MODE
#undef	DebugVAL
#define	DEBUG_VALIDATE_MODE	0	/* validate user addreses on host */
#define	DebugVAL(fmt, args...)						\
({									\
	if (DEBUG_VALIDATE_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_GUEST_USER_MODE
#undef	DebugKVMGU
#define	DEBUG_KVM_GUEST_USER_MODE	0	/* guest user address */
#define	DebugKVMGU(fmt, args...)					\
({									\
	if (DEBUG_KVM_GUEST_USER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_HW_STACK_MAPPING_MODE
#undef	DebugHWSM
#define	DEBUG_HW_STACK_MAPPING_MODE	0	/* hardware stacks mapping */
#define	DebugHWSM(fmt, args...)						\
({									\
	if (DEBUG_HW_STACK_MAPPING_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_HW_STACK_REMAPPING_MODE
#undef	DebugHWSG
#define	DEBUG_HW_STACK_REMAPPING_MODE	0	/* hardware stacks mapping */
#define	DebugHWSG(fmt, args...)						\
({									\
	if (DEBUG_HW_STACK_REMAPPING_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_ANON_RMAP_MODE
#undef	DebugANON
#define	DEBUG_KVM_ANON_RMAP_MODE	0	/* anonimous VMA mapping */
#define	DebugANON(fmt, args...)						\
({									\
	if (DEBUG_KVM_ANON_RMAP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SHUTDOWN_MODE
#undef	DebugKVMSH
#define	DEBUG_KVM_SHUTDOWN_MODE	0	/* KVM shutdown debugging */
#define	DebugKVMSH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SHUTDOWN_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	VM_BUG_ON
#define VM_BUG_ON(cond) BUG_ON(cond)

static inline void
mmu_get_tc_entry(struct kvm_vcpu *vcpu, int tc_no, trap_cellar_t *tc_entry)
{
	kvm_read_pv_vcpu_mmu_tc_entry(vcpu, tc_no, tc_entry);
}

static inline void
mmu_set_tc_entry(struct kvm_vcpu *vcpu, int tc_no,
		e2k_addr_t address, tc_cond_t condition, u64 *data)
{
	kvm_write_pv_vcpu_mmu_tc_entry(vcpu, tc_no, address, condition, data);
}

void kvm_reset_mmu_state(struct kvm_vcpu *vcpu)
{
	DebugKVM("started for VCPU %d\n", vcpu->vcpu_id);

	kvm_write_pv_vcpu_MMU_CR_reg(vcpu, MMU_CR_KERNEL_OFF);
	DebugKVM("set MMU_CR to init state 0x%llx\n",
			AW(MMU_CR_KERNEL_OFF));

	kvm_write_pv_vcpu_mmu_US_CL_D_reg(vcpu, true);
	DebugKVM("set MMU_US_CL_D to init disable state\n");
}

void kvm_init_mmu_state(struct kvm_vcpu *vcpu)
{
	kvm_reset_mmu_state(vcpu);
}

unsigned int kvm_get_guest_vcpu_mmu_trap_count(struct kvm_vcpu *vcpu)
{
	return kvm_read_pv_vcpu_mmu_TRAP_COUNT_reg(vcpu);
}

void kvm_set_guest_vcpu_mmu_trap_count(struct kvm_vcpu *vcpu,
						unsigned int count)
{
	kvm_write_pv_vcpu_mmu_TRAP_COUNT_reg(vcpu, count);
}

void kvm_get_guest_vcpu_tc_entry(struct kvm_vcpu *vcpu,
					int tc_no, trap_cellar_t *tc_entry)
{
	mmu_get_tc_entry(vcpu, tc_no, tc_entry);
}

int kvm_add_guest_vcpu_tc_entry(struct kvm_vcpu *vcpu,
		e2k_addr_t address, tc_cond_t condition, u64 *data)
{
	int tc_count;
	int tc_no;

	tc_count = kvm_get_guest_vcpu_mmu_trap_count(vcpu);
	tc_no = tc_count / 3;
	mmu_set_tc_entry(vcpu, tc_no, address, condition, data);
	kvm_set_guest_vcpu_mmu_trap_count(vcpu, (tc_no + 1) * 3);
	return tc_no;
}

/**
 * page_add_shadow_rmap - add pte mapping to an shadowed page
 * @page:	the page to add the mapping to
 *
 * The caller needs to hold the pte lock, and the page must be reserved
 */
static inline void page_add_shadow_rmap(struct page *page)
{
	int first = atomic_inc_and_test(&page->_mapcount);
	if (first) {
		/* first increment was kernel space mapping */
		/* now increment for as guest shadow mapping */
		atomic_inc_and_test(&page->_mapcount);
	}

	VM_BUG_ON(!page_count(page));
}

static inline long
map_host_ttable_large_pte_range(struct vm_area_struct *vma,
	pte_t kernel_pte, pmd_t *shadow_pmd,
	e2k_addr_t kernel_addr, e2k_addr_t kernel_end,
	e2k_addr_t shadow_addr, e2k_addr_t shadow_end)
{
	pte_t		*shadow_pte;
	pte_t		*orig_shadow_pte;
	spinlock_t	*shadow_ptl = NULL;
	pte_t		pte;
	e2k_addr_t	pfn;
	e2k_addr_t	pfn_off;
	struct page	*ptepage;
	long		ret = 0;

	DebugKVM("started: kernel start 0x%lx end 0x%lx shadow start 0x%lx "
		"end 0x%lx kernel large PTE 0x%lx\n",
		kernel_addr, kernel_end, shadow_addr, shadow_end,
		pte_val(kernel_pte));
	pte = kernel_pte;
	pfn = pte_pfn(pte);
	pte = pte_set_small_size(pte);
	pfn_off = (shadow_addr & ~PMD_MASK) >> PTE_SHIFT;
	shadow_pte = pte_alloc_map_lock(current->mm, shadow_pmd, shadow_addr,
					&shadow_ptl);
	if (!shadow_pte) {
		printk(KERN_ERR "map_host_ttable_pte_range() could not alloc "
			"PTE page for shadow addr 0x%lx\n", shadow_addr);
		return -ENOMEM;
	}
	orig_shadow_pte = shadow_pte;
	do {
		if (!pte_none(*shadow_pte)) {
			printk(KERN_ERR "Old mapping existed for shadow "
				"address 0x%lx pte 0x%px = 0x%lx\n",
				shadow_addr, shadow_pte, pte_val(*shadow_pte));
			ret = -EINVAL;
			break;
		}
		ptepage = pfn_to_page(pfn + pfn_off);
		if ((!page_valid(ptepage)) || !page_count(ptepage)) {
			printk(KERN_ERR "map_host_ttable_pte_range() kernel "
				"large pte 0x%lx pfn base 0x%lx offset 0x%lx "
				"page 0x%px is not valid or is free "
				"for shadow address 0x%lx\n",
				pte_val(pte), pfn, pfn_off, ptepage,
				shadow_addr);
			ret = -EINVAL;
			break;
		}
		get_page(ptepage);
		page_add_shadow_rmap(ptepage);
		pte = mk_pfn_pte(pfn + pfn_off, pte);
		set_pte_at(current->mm, shadow_addr, shadow_pte, pte);
		DebugKVM("set shadow PTE 0x%px == 0x%lx to page 0x%px for shadow "
			"address 0x%lx\n",
			shadow_pte, pte_val(*shadow_pte), ptepage, shadow_addr);
	} while (shadow_pte++, pfn_off++,
			kernel_addr += PAGE_SIZE, shadow_addr += PAGE_SIZE,
				kernel_addr != kernel_end);
	pte_unmap_unlock(orig_shadow_pte, shadow_ptl);
	DebugKVM("finished and returns 0x%lx\n", ret);
	return ret;
}

static inline long
map_host_ttable_pte_range(struct vm_area_struct *vma,
	pmd_t *kernel_pmd, pmd_t *shadow_pmd,
	e2k_addr_t kernel_addr, e2k_addr_t kernel_end,
	e2k_addr_t shadow_addr, e2k_addr_t shadow_end)
{
	pte_t		*kernel_pte;
	pte_t		*shadow_pte;
	pte_t		*orig_shadow_pte;
	spinlock_t	*shadow_ptl = NULL;
	struct page	*ptepage;
	int		ret = 0;

	DebugKVM("started: kernel start 0x%lx end 0x%lx shadow start 0x%lx "
		"end 0x%lx kernel_pmd 0x%px == 0x%lx\n",
		kernel_addr, kernel_end, shadow_addr, shadow_end,
		kernel_pmd, pmd_val(*kernel_pmd));
	kernel_pte = pte_offset_kernel(kernel_pmd, kernel_addr);
	shadow_pte = pte_alloc_map_lock(current->mm, shadow_pmd, shadow_addr,
					&shadow_ptl);
	if (!shadow_pte) {
		printk(KERN_ERR "map_host_ttable_pte_range() could not alloc "
			"PTE page for shadow addr 0x%lx\n", shadow_addr);
		return -ENOMEM;
	}
	orig_shadow_pte = shadow_pte;
	do {
		if (pte_none(*kernel_pte)) {
			printk(KERN_ERR "map_host_ttable_pmd_range() empty "
				"PTE for kernel addr 0x%lx\n",
				kernel_addr);
			ret = -EINVAL;
			break;
		}
		DebugKVM("will map kernel address 0x%lx pte 0x%px == 0x%lx "
			"for shadow address 0x%lx\n",
			kernel_addr, kernel_pte, pte_val(*kernel_pte),
			shadow_addr);
		if (!pte_present(*kernel_pte)) {
			printk(KERN_ERR "map_host_ttable_pmd_range() kernel "
				"addr 0x%lx PTE is not present %px == 0x%lx\n",
				kernel_addr, kernel_pte, pte_val(*kernel_pte));
			ret = -EINVAL;
			break;
		}
		if (!pte_none(*shadow_pte)) {
			printk(KERN_ERR "Old mapping existed for shadow "
				"address 0x%lx pte 0x%px = 0x%lx\n",
				shadow_addr, shadow_pte, pte_val(*shadow_pte));
			ret = -EINVAL;
			break;
		}
		ptepage = pte_page(*kernel_pte);
		if ((!page_valid(ptepage)) || !page_count(ptepage)) {
			printk(KERN_ERR "map_host_ttable_pte_range() kernel "
				"pte 0x%lx page 0x%px is not valid or is "
				"free for address 0x%lx\n",
				pte_val(*kernel_pte), ptepage, kernel_addr);
			ret = -EINVAL;
			break;
		}
		get_page(ptepage);
		page_add_shadow_rmap(ptepage);
		set_pte_at(current->mm, shadow_addr, shadow_pte, *kernel_pte);
		DebugKVM("set shadow PTE 0x%px == 0x%lx to page 0x%px for shadow "
			"address 0x%lx\n",
			shadow_pte, pte_val(*shadow_pte), ptepage, shadow_addr);
	} while (kernel_pte++, shadow_pte++,
			kernel_addr += PAGE_SIZE, shadow_addr += PAGE_SIZE,
				kernel_addr != kernel_end);
	pte_unmap_unlock(orig_shadow_pte, shadow_ptl);
	DebugKVM("finished and returns %d\n", ret);
	return ret;
}

static inline long
map_host_ttable_pmd_range(struct vm_area_struct *vma,
	pud_t *kernel_pud, pud_t *shadow_pud,
	e2k_addr_t kernel_addr, e2k_addr_t kernel_end,
	e2k_addr_t shadow_addr, e2k_addr_t shadow_end)
{
	e2k_addr_t	kernel_next;
	e2k_addr_t	shadow_next;
	pmd_t		*kernel_pmd;
	pmd_t		*shadow_pmd;
	pte_t		pte;
	long		ret = 0;

	DebugKVM("started: kernel start 0x%lx end 0x%lx shadow start 0x%lx "
		"end 0x%lx kernel_pud 0x%px == 0x%lx\n",
		kernel_addr, kernel_end, shadow_addr, shadow_end,
		kernel_pud, pud_val(*kernel_pud));
	kernel_pmd = pmd_offset(kernel_pud, kernel_addr);
	shadow_pmd = pmd_alloc(current->mm, shadow_pud, shadow_addr);
	if (shadow_pmd == NULL) {
		printk(KERN_ERR "map_host_ttable_pmd_range() could not "
			"allocate PMD for shadow addr 0x%lx\n",
			shadow_addr);
		return -ENOMEM;
	}
	do {
		if (pmd_none(*kernel_pmd)) {
			printk(KERN_ERR "map_host_ttable_pmd_range() empty "
				"PMD for kernel addr 0x%lx\n",
				kernel_addr);
			return -EINVAL;
		}
		DebugKVM("will map kernel address 0x%lx pmd 0x%px == 0x%lx to "
			"shadow address 0x%lx\n",
			kernel_addr, kernel_pmd, pmd_val(*kernel_pmd),
			shadow_addr);
		kernel_next = pmd_addr_end(kernel_addr, kernel_end);
		shadow_next = pmd_addr_end(shadow_addr, shadow_end);
		pte = *((pte_t *)kernel_pmd);
		if (!pte_large_page(pte)) {
			ret = map_host_ttable_pte_range(vma,
						kernel_pmd, shadow_pmd,
						kernel_addr, kernel_next,
						shadow_addr, shadow_next);
		} else {
			ret = map_host_ttable_large_pte_range(vma,
						pte, shadow_pmd,
						kernel_addr, kernel_next,
						shadow_addr, shadow_next);
		}
		if (ret < 0)
			break;
	} while (kernel_pmd++, shadow_pmd++,
			kernel_addr = kernel_next, shadow_addr = shadow_end,
				kernel_addr != kernel_end);
	DebugKVM("finished and returns 0x%lx\n", ret);
	return ret;
}

static inline long
map_host_ttable_pud_range(struct vm_area_struct *vma,
	pgd_t *kernel_pgd, pgd_t *shadow_pgd,
	e2k_addr_t kernel_addr, e2k_addr_t kernel_end,
	e2k_addr_t shadow_addr, e2k_addr_t shadow_end)
{
	e2k_addr_t	kernel_next;
	e2k_addr_t	shadow_next;
	pud_t		*kernel_pud;
	pud_t		*shadow_pud;
	long		ret = 0;

	DebugKVM("started: kernel start 0x%lx end 0x%lx shadow start 0x%lx "
		"end 0x%lx kernel_pgd 0x%px == 0x%lx\n",
		kernel_addr, kernel_end, shadow_addr, shadow_end,
		kernel_pgd, pgd_val(*kernel_pgd));
	kernel_pud = pud_offset(kernel_pgd, kernel_addr);
	shadow_pud = pud_alloc(current->mm, shadow_pgd, shadow_addr);
	if (shadow_pud == NULL) {
		printk(KERN_ERR "map_host_ttable_pud_range() could not "
			"allocate PUD for shadow addr 0x%lx\n",
			shadow_addr);
		return -ENOMEM;
	}
	do {
		if (pud_none(*kernel_pud)) {
			printk(KERN_ERR "map_host_ttable_pud_range() empty "
				"PUD for kernel addr 0x%lx\n",
				kernel_addr);
			return -EINVAL;
		}
		DebugKVM("will map kernel address 0x%lx pud 0x%px == 0x%lx to "
			"shadow address 0x%lx\n",
			kernel_addr, kernel_pud, pud_val(*kernel_pud),
			shadow_addr);
		kernel_next = pud_addr_end(kernel_addr, kernel_end);
		shadow_next = pud_addr_end(shadow_addr, shadow_end);
		ret = map_host_ttable_pmd_range(vma, kernel_pud, shadow_pud,
			kernel_addr, kernel_next, shadow_addr, shadow_next);
		if (ret < 0)
			break;
	} while (kernel_pud++, shadow_pud++,
			kernel_addr = kernel_next, shadow_addr = shadow_next,
				kernel_addr != kernel_end);
	DebugKVM("finished and returns 0x%lx\n", ret);
	return ret;
}

/*
 * Map host kernel trap table to shadow guest kernel image
 */
int kvm_map_host_ttable_to_shadow(struct kvm *kvm, e2k_addr_t kernel_base,
					gva_t shadow_base)
{
	e2k_addr_t start_addr;
	e2k_addr_t end_addr;
	e2k_addr_t kernel_next;
	e2k_addr_t shadow_addr;
	e2k_addr_t shadow_end;
	e2k_addr_t shadow_next;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	pgd_t *kernel_pgd;
	pgd_t *shadow_pgd;
	int r;
	int nid;

	DebugKVM("started: kernel base 0x%lx, guest shadow base 0x%lx\n",
		kernel_base, shadow_base);

	start_addr = PAGE_ALIGN_UP(KERNEL_TTABLE_BASE);
	end_addr = PAGE_ALIGN_DOWN(KERNEL_TTABLE_END);
	if (mm == NULL) {
		printk(KERN_ERR "kvm_map_host_ttable_to_shadow(): user has not "
			"MM structure\n");
		return -EINVAL;
	}
	if (start_addr != kernel_base) {
		printk(KERN_ERR "kvm_map_host_ttable_to_shadow(): trap table "
			"0x%lx is not started from kernel base 0x%lx\n",
			start_addr, kernel_base);
		return -EINVAL;
	}
	shadow_addr = shadow_base;
	shadow_end = shadow_addr + (end_addr - start_addr);
	nid = numa_node_id();
	DebugKVM("will map trap table from 0x%lx to 0x%lx on node #%d\n",
		start_addr, end_addr, nid);
	mmap_write_lock(mm);
	kernel_pgd = node_pgd_offset_k(nid, start_addr);
	shadow_pgd = pgd_offset(mm, shadow_addr);
	vma = find_vma(mm, shadow_addr);
	if (vma == NULL) {
		printk(KERN_ERR "kvm_map_host_ttable_to_shadow(): could not "
			"find VMA structure for address 0x%lx\n",
			shadow_addr);
		r = -EINVAL;
		goto out;
	}
	if (vma->vm_start > shadow_addr || vma->vm_end < shadow_end) {
		printk(KERN_ERR "Invalid VMA structure start addr 0x%lx or "
			"end 0x%lx (should be <= 0x%lx &  >= 0x%lx)\n",
			vma->vm_start, vma->vm_end,
			shadow_addr, shadow_end);
		r = -EINVAL;
		goto out;
	}
	DebugKVM("found VMA from 0x%lx to 0x%lx\n",
		vma->vm_start, vma->vm_end);
	VM_BUG_ON(vma->anon_vma);
	do {
		kernel_next = pgd_addr_end(start_addr, end_addr);
		shadow_next = pgd_addr_end(shadow_addr, shadow_end);
		if (pgd_none(*kernel_pgd)) {
			printk(KERN_ERR "kvm_map_host_ttable_to_shadow() "
				"empty kernel trap table pgd for addr 0x%lx\n",
				start_addr);
			r = -EINVAL;
			break;
		}
		r = map_host_ttable_pud_range(vma, kernel_pgd, shadow_pgd,
						start_addr, kernel_next,
						shadow_addr, shadow_next);
		if (r != 0) {
			pr_err("kvm_map_host_ttable_to_shadow() failed and "
				"returns error %d\n", r);
			break;
		}
	} while (kernel_pgd++, shadow_pgd++,
			start_addr = kernel_next, shadow_addr = shadow_next,
			start_addr != end_addr);
out:
	mmap_write_unlock(mm);
	DebugKVM("finished and returns %d\n", r);
	return r;
}

static inline pte_t *get_user_ptep(gmm_struct_t *gmm, e2k_addr_t addr)
{
	pr_err("%s(): is not implemented\n", __func__);
	return NULL;
}

static e2k_addr_t do_print_guest_user_address_ptes(gmm_struct_t *gmm,
							e2k_addr_t addr)
{
	pgd_t *pgd = NULL;
	pud_t *pud = NULL;
	pmd_t *pmd = NULL;
	pte_t *pte = NULL;
	pte_t *pmd_pte, *pud_pte;
	e2k_addr_t pa = 0;

	pr_err("%s(): is not implemented\n", __func__);
	return pa;

	if (pgd_none_or_clear_bad(pgd)) {
		pr_info("host PGD  0x%px = 0x%016lx none or bad for guest user "
			"address 0x%016lx\n",
			pgd, pgd_val(*pgd), addr);
		return pa;
	}
	pr_info("host PGD  0x%px = 0x%016lx valid for guest user "
		"address 0x%016lx\n",
		pgd, pgd_val(*pgd), addr);
	if (pud == NULL) {
		pr_info("host PUD  is NULL for guest user "
			"address 0x%016lx\n",
			addr);
		return pa;
	}
	pud_pte = (pte_t *) pud;
	if (pte_large_page(*pud_pte)) {
		pr_info("host PUD 0x%px = 0x%016lx is PTE of large page for "
			"guest user address 0x%016lx\n",
			pud_pte, pte_val(*pud_pte), addr);
		pa = _PAGE_PFN_TO_PADDR(pte_val(*pud_pte)) + (addr & ~PUD_MASK);
		return pa;
	}
	if (pud_none_or_clear_bad(pud)) {
		pr_info("host PUD  0x%px = 0x%016lx none or bad for guest user "
			"address 0x%016lx\n",
			pud, pud_val(*pud), addr);
		return pa;
	}
	pr_info("host PUD  0x%px = 0x%016lx valid for guest user "
		"address 0x%016lx\n",
		pud, pud_val(*pud), addr);
	if (pmd == NULL) {
		pr_info("host PMD  is NULL for guest user "
			"address 0x%016lx\n",
			addr);
		return pa;
	}
	pmd_pte = (pte_t *) pmd;
	if (pte_large_page(*pmd_pte)) {
		pr_info("host PMD 0x%px = 0x%016lx is PTE of large page for "
			"guest user address 0x%016lx\n",
			pmd_pte, pte_val(*pmd_pte), addr);
		pa = _PAGE_PFN_TO_PADDR(pte_val(*pmd_pte)) + (addr & ~PMD_MASK);
		return pa;
	}
	if (pmd_none_or_clear_bad(pmd)) {
		pr_info("host PMD  0x%px = 0x%016lx none or bad for guest user "
			"address 0x%016lx\n",
			pmd, pmd_val(*pmd), addr);
		return pa;
	}
	pr_info("host PMD 0x%px = 0x%016lx valid for guest user address 0x%016lx\n",
			pmd, pmd_val(*pmd), addr);
	if (pte == NULL) {
		pr_info("host PTE  is NULL for guest user "
			"address 0x%016lx\n",
			addr);
		return pa;
	} else if (pte_none(*pte)) {
		pr_info("host PTE  0x%px = 0x%016lx none for guest user "
			"address 0x%016lx\n",
			pte, pte_val(*pte), addr);
		return pa;
	}
	if (!pte_present(*pte)) {
		pr_info("host PTE  0x%px = 0x%016lx is pte of swaped "
			"page for guest user address 0x%016lx\n",
			pte, pte_val(*pte), addr);
		return pa;
	}
	pr_info("host PTE  0x%px = 0x%016lx valid & present for guest user "
		"address 0x%016lx\n",
		pte, pte_val(*pte), addr);
	pa = _PAGE_PFN_TO_PADDR(pte_val(*pte)) + (addr & 0xfff);
	return pa;
}

e2k_addr_t kvm_print_guest_user_address_ptes(struct kvm *kvm,
				int gmmid_nr, e2k_addr_t addr)
{
	gmm_struct_t *gmm;
	e2k_addr_t pa = 0;

	if (addr >= GUEST_PAGE_OFFSET) {
		pr_err("address 0x%lx is not guest user address\n", addr);
		return -EINVAL;
	}
	if (gmmid_nr < 0) {
		pr_err("bad host agent id #%d of guest user mm\n", gmmid_nr);
		return -EINVAL;
	}
	gmm = kvm_find_gmmid(&kvm->arch.gmmid_table, gmmid_nr);
	if (gmm == NULL) {
		pr_err("could not find host agent #%d of guest mm "
			"for address 0x%lx\n", gmmid_nr, addr);
		return -EINVAL;
	}
	pa = do_print_guest_user_address_ptes(gmm, addr);
	print_va_tlb(addr, 0);
	print_va_tlb(pte_virt_offset(_PAGE_ALIGN_UP(addr, PTE_SIZE)), 0);
	print_va_tlb(pmd_virt_offset(_PAGE_ALIGN_UP(addr, PMD_SIZE)), 0);
	print_va_tlb(pud_virt_offset(_PAGE_ALIGN_UP(addr, PUD_SIZE)), 0);
	return pa;
}

e2k_addr_t
kvm_guest_user_address_to_pva(struct task_struct *task, e2k_addr_t address)
{
	thread_info_t	*ti = task_thread_info(task);
	struct kvm_vcpu	*vcpu;
	gmm_struct_t	*gmm;
	pte_t		*ptep, pte;
	e2k_addr_t	phys;
	bool		locked = false;

	DebugKVMGU("Task %s (%d) started for address 0x%lx\n",
		task->comm, task->pid, address);

	if (!IS_GUEST_USER_ADDRESS(address)) {
		pr_err("%s(): Address 0x%lx is not guest address\n",
			__func__, address);
		return -1L;
	}
	vcpu = ti->vcpu;
	if (vcpu == NULL) {
		pr_err("%s():VCPU process %s (%d) has not VCPU structure "
			"pointer\n",
			__func__, task->comm, task->pid);
		return -1L;
	}
	if (!is_paging(vcpu)) {
		/* Nonpaging mode: it is guest physical address */
		pte_val(pte) = pgprot_val(mmu_pt_nonpaging_gpa_to_pte(vcpu,
								address));
		gmm = pv_vcpu_get_init_gmm(vcpu);
		goto host_mapped;
	}
	gmm = pv_vcpu_get_active_gmm(ti->vcpu);
	if (gmm == NULL) {
		pr_err("%s():VCPU #%d process %s (%d) has not active guest "
			"user MM (gmm), so conversion is impossible\n",
			__func__, vcpu->vcpu_id, task->comm, task->pid);
		return -1L;
	}
	BUG_ON(ti->gthread_info == NULL);
	WARN_ON(ti->gthread_info->gmm && gmm != ti->gthread_info->gmm);

	locked = spin_trylock(&gmm->page_table_lock);

	ptep = get_user_ptep(gmm, address);
	if (ptep == NULL) {
		pr_err("%s(): could not find guest user address 0x%lx mapping "
			"on host\n", __func__, address);
		goto host_nomap;
	}
	pte = *ptep;

host_mapped:
	if (pte_none(pte)) {
		pr_err("%s(): guest user virtual address 0x%lx already "
			"unmapped on host PT\n", __func__, address);
		goto host_nomap;
	}
	if (!pte_present(pte)) {
		pr_err("%s(): host page of guest user virtual address 0x%lx "
			"mapping is not present\n", __func__, address);
		goto host_nomap;
	}

	if (locked)
		spin_unlock(&gmm->page_table_lock);

	phys = (pte_pfn(pte) << PAGE_SHIFT) | (address & ~PAGE_MASK);
	DebugKVMGU("guest user virtual address 0x%lx is physical "
		"address 0x%lx on host\n",
		address, phys);

	return (e2k_addr_t)__va(phys);

host_nomap:
	if (locked)
		spin_unlock(&gmm->page_table_lock);
	return -1L;

}

void kvm_arch_free_memory_region(struct kvm *kvm,
					struct kvm_memory_slot *memslot)
{
	unsigned long base_gfn = memslot->base_gfn;
	unsigned long guest_start = memslot->userspace_addr;
	unsigned long npages = memslot->npages;
	unsigned long guest_end = guest_start + (npages << PAGE_SHIFT);
	user_area_t *guest_area;

	DebugKVM("slot base pfn 0x%lx guest virtual from 0x%lx to 0x%lx\n",
		base_gfn, guest_start, guest_end);
	if (npages == 0)
		return;
	if (memslot->userspace_addr == 0) {
		DebugKVM("slot base gfn 0x%lx size 0x%lx pages is not "
			"allocated by user so cannot be freed\n",
			base_gfn, npages);
		return;
	}
	guest_area = memslot->arch.guest_areas.area;
	if (guest_area == NULL) {
		DebugKVM("slot base gfn 0x%lx guest virtual from 0x%lx "
			"to 0x%lx has not guest area support\n",
			base_gfn, guest_start, guest_end);
		return;
	}
	user_area_release(guest_area);
	memslot->arch.guest_areas.area = NULL;

	return;
}

UACCESS_FN_DEFINE6(recovery_faulted_tagged_store_fn,
		e2k_addr_t, address, u64, wr_data, u64, st_rec_opc,
		u64, data_ext, u64, opc_ext, union recovery_faulted_arg, arg)
{
	native_recovery_faulted_tagged_store(address, wr_data, arg.tag,
			st_rec_opc, data_ext, arg.tag_ext, opc_ext,
			arg.chan, arg.qp, arg.atomic);
	return 0;
}

/*
 * Recovery faulted store operations
 * common case: some addresses can be from host kernel address space,
 * but point to guest structures, shadow image ...
 */

/* privileged hypercall version of recovery faulted operations */

static noinline __priv_hypercall __section(".uaccess_functions") long
do_recovery_faulted_tagged_store(e2k_addr_t address, u64 wr_data,
		u64 st_rec_opc, u64 data_ext, u64 opc_ext,
		recovery_faulted_arg_t args)
{
	u32 data_tag = args.tag;
	u32 data_ext_tag = args.tag_ext;
	int chan = args.chan;
	int qp_store = args.qp;
	int atomic_store = args.atomic;
	int ret = -EAGAIN;

	if (atomic_store) {
		TRY_RECOVERY_TAGGED_STORE_ATOMIC(address, wr_data, data_tag,
				st_rec_opc, data_ext, data_ext_tag, opc_ext, ret);
	} else {
		TRY_RECOVERY_TAGGED_STORE(address, wr_data, data_tag,
				st_rec_opc, data_ext, data_ext_tag, opc_ext,
				chan, qp_store, ret);
	}
	return ret;
}

__priv_hypercall long
kvm_priv_recovery_faulted_store(e2k_addr_t address, u64 wr_data, u64 st_rec_opc,
				u64 data_ext, u64 opc_ext, u64 _args)
{
	recovery_faulted_arg_t args = { entire : _args };
	struct task_struct *p = (struct task_struct *) NATIVE_READ_CURRENT_REG_VALUE();
	struct kvm_vcpu *vcpu = task_thread_info(p)->vcpu;
	unsigned long to_save_usr_pfault_jump;
	int try_no = 0;
	long ret;

	if (vcpu == NULL) {
		/* this should not be */
		return -ENOSYS;
	}

	KVM_SET_USR_PFAULT("$.recovery_store_failed", p, to_save_usr_pfault_jump);

try_again:
	KVM_SET_RECOVERY_FAULTED("$.recovery_store_faulted", vcpu);

	ret = do_recovery_faulted_tagged_store(address, wr_data,
			st_rec_opc, data_ext, opc_ext, args);
	if (likely(ret == 0)) {
		/* recovery store operation succsefully completed */
		;
	} else if (ret == -EAGAIN) {
		/* page fault occured and host successfully fault handled */
		try_no++;
		if (likely(try_no <= 3)) {
			/* try store recovery again */
			goto try_again;
		}
		/* probably it need try page fault handle again by guest */
	} else {
		/* page fault occured, but host handler failed */
		/* return fault to guest */
		;
	}

	KVM_RESET_RECOVERY_FAULTED(vcpu);
	KVM_RESTORE_USR_PFAULT(p, to_save_usr_pfault_jump);
	return ret;
}

static noinline __priv_hypercall __section(".uaccess_functions") long
do_recovery_faulted_load(e2k_addr_t addr, u64 *ld_val, u8 *data_tag,
			 u64 ld_rec_opc, int chan)
{
	u64 val;
	u32 tag;
	long ret = -EAGAIN;

	TRY_RECOVERY_TAGGED_LOAD_TO(addr, ld_rec_opc, val, tag, chan, ret);
	*ld_val = val;
	*data_tag = tag;
	return ret;
}

__priv_hypercall long
kvm_priv_recovery_faulted_load(e2k_addr_t addr, u64 *ld_val, u8 *data_tag,
			       u64 ld_rec_opc, int chan)
{
	struct task_struct *p = (struct task_struct *) NATIVE_READ_CURRENT_REG_VALUE();
	struct kvm_vcpu *vcpu = task_thread_info(p)->vcpu;
	unsigned long to_save_usr_pfault_jump;
	int try_no = 0;
	long ret;

	if (vcpu == NULL) {
		/* this should not be */
		return -ENOSYS;
	}

	KVM_SET_USR_PFAULT("$.recovery_load_failed", p, to_save_usr_pfault_jump);

try_again:
	KVM_SET_RECOVERY_FAULTED("$.recovery_load_faulted", vcpu);

	ret = do_recovery_faulted_load(addr, ld_val, data_tag, ld_rec_opc, chan);
	if (likely(ret == 0)) {
		/* recovery load operation succsefully completed */
		;
	} else if (ret == -EAGAIN) {
		/* page fault occured and host successfully fault handled */
		try_no++;
		if (likely(try_no <= 3)) {
			/* try load recovery again */
			goto try_again;
		}
		/* probably it need try page fault handle again by guest */
	} else {
		/* page fault occured, but host handler failed */
		/* return fault to guest */
		;
	}

	KVM_RESET_RECOVERY_FAULTED(vcpu);
	KVM_RESTORE_USR_PFAULT(p, to_save_usr_pfault_jump);
	return ret;
}

static __always_inline long
try_recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
		e2k_addr_t addr_to_hi, u64 ld_rec_opc,
		recovery_faulted_arg_t args, u32 first_time)
{
	int chan = args.chan;
	int qp_load = args.qp;
	int atomic_load = args.atomic;
	int vr = args.vr;
	int ret = -EAGAIN;

	if (atomic_load) {
		TRY_MOVE_TAGGED_DWORD_WITH_OPC_VR_ATOMIC(addr_from, addr_to,
				addr_to_hi, vr, ld_rec_opc, ret);
	} else {
		TRY_MOVE_TAGGED_DWORD_WITH_OPC_CH_VR(addr_from, addr_to,
				addr_to_hi, vr, ld_rec_opc, chan, qp_load,
				first_time, ret);
	}
	return ret;
}

static noinline __priv_hypercall __section(".uaccess_functions") long
do_recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
		e2k_addr_t addr_to_hi, u64 ld_rec_opc,
		recovery_faulted_arg_t args, u32 first_time)
{
	return try_recovery_faulted_move(addr_from, addr_to, addr_to_hi,
					 ld_rec_opc, args, first_time);
}

__priv_hypercall long
kvm_priv_recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
		e2k_addr_t addr_to_hi, u64 ld_rec_opc, u64 _args, u32 first_time)
{
	recovery_faulted_arg_t args = { entire : _args };
	struct task_struct *p = (struct task_struct *) NATIVE_READ_CURRENT_REG_VALUE();
	struct kvm_vcpu *vcpu = task_thread_info(p)->vcpu;
	unsigned long to_save_usr_pfault_jump;
	int try_no = 0;
	long ret;

	if (vcpu == NULL) {
		/* this should not be */
		return -ENOSYS;
	}

	KVM_SET_USR_PFAULT("$.recovery_load_failed", p, to_save_usr_pfault_jump);

try_again:
	KVM_SET_RECOVERY_FAULTED("$.recovery_load_faulted", vcpu);

	ret = do_recovery_faulted_move(addr_from, addr_to, addr_to_hi,
				       ld_rec_opc, args, first_time);
	if (likely(ret == 0)) {
		/* recovery move operation succsefully completed */
		;
	} else if (ret == -EAGAIN) {
		/* page fault occured and host successfully fault handled */
		try_no++;
		if (likely(try_no <= 3)) {
			/* try move recovery again */
			goto try_again;
		}
		/* probably it need try page fault handle again by guest */
	} else {
		/* page fault occured, but host handler failed */
		/* return fault to guest */
		;
	}

	KVM_RESET_RECOVERY_FAULTED(vcpu);
	KVM_RESTORE_USR_PFAULT(p, to_save_usr_pfault_jump);
	return ret;
}

static __always_inline long
recovery_faulted_load_to_cpu_greg(e2k_addr_t addr, u32 greg_num_d,
		u64 ld_rec_opc, recovery_faulted_arg_t args)
{
	int chan_opc = args.chan;
	int qp_load = args.qp;
	int atomic_load = args.atomic;
	int vr = args.vr;
	int ret = -EAGAIN;

	if (atomic_load) {
		TRY_RECOVERY_LOAD_TO_A_GREG_VR_ATOMIC(addr,
			ld_rec_opc, greg_num_d, vr, qp_load, ret);
	} else {
		TRY_RECOVERY_LOAD_TO_A_GREG_CH_VR(addr,
			ld_rec_opc, greg_num_d, chan_opc, vr, qp_load, ret);
	}
	return ret;
}

static noinline __priv_hypercall __section(".uaccess_functions") long
do_recovery_faulted_load_to_greg(e2k_addr_t addr, u32 greg_num_d,
		recovery_faulted_arg_t args, u64 ld_rec_opc,
		u64 *saved_greg_lo, u64 *saved_greg_hi)
{
	long ret = -EAGAIN;

	if (!saved_greg_lo) {
		ret = recovery_faulted_load_to_cpu_greg(addr, greg_num_d,
							ld_rec_opc, args);
	} else {
		ret = try_recovery_faulted_move(addr,
			(e2k_addr_t)saved_greg_lo, (e2k_addr_t)saved_greg_hi,
			ld_rec_opc, args, 1);
	}
	return ret;
}

noinline void dump_l_gregs_state(vcpu_l_gregs_t *l_gregs)
{
	pr_err("%s() : lgregs: valid %d, updated 0x%llx\n",
		__func__, l_gregs->valid, l_gregs->updated);
	dump_stack();
}

__priv_hypercall long
kvm_priv_recovery_faulted_load_to_greg(e2k_addr_t addr, u32 greg_num_d,
		u64 ld_rec_opc, u64 _args, u64 *saved_greg_lo, u64 *saved_greg_hi)
{
	recovery_faulted_arg_t args = { .entire = _args };
	struct thread_info *ti = READ_CURRENT_REG();
	struct task_struct *p = thread_info_task(ti);
	struct kvm_vcpu *vcpu = ti->vcpu;
	unsigned long to_save_usr_pfault_jump;
	vcpu_l_gregs_t *l_gregs;
	u64 *addr_lo, *addr_hi;
	int try_no = 0;
	long ret;

	if (vcpu == NULL) {
		/* this should not be */
		return -ENOSYS;
	}

	KVM_SET_USR_PFAULT("$.recovery_load_failed", p, to_save_usr_pfault_jump);

try_again:
	KVM_SET_RECOVERY_FAULTED("$.recovery_load_faulted", vcpu);

	ret = do_recovery_faulted_load_to_greg(addr, greg_num_d, args, ld_rec_opc,
					       saved_greg_lo, saved_greg_hi);
	if (likely(ret == 0)) {
		/* recovery load operation succsefully completed */
		;
	} else if (ret == -EAGAIN) {
		/* page fault occured and host successfully fault handled */
		try_no++;
		if (likely(try_no <= 3)) {
			/* try load recovery again */
			goto try_again;
		}
		/* probably it need try page fault handle again by guest */
	} else {
		/* page fault occured, but host handler failed */
		/* return fault to guest */
		;
	}

	KVM_RESET_RECOVERY_FAULTED(vcpu);
	KVM_RESTORE_USR_PFAULT(p, to_save_usr_pfault_jump);

	if (unlikely(ret != 0))
		return ret;

	if (!(LOCAL_GREGS_USER_MASK & (1UL << greg_num_d))) {
		/* it is not "local" global register */
		return 0;
	}

	/* save updated registers value to recover upon return to user */
	E2K_KVM_BUG_ON(!(LOCAL_GREGS_USER_MASK & (1UL << greg_num_d)));
	E2K_KVM_BUG_ON((KERNEL_GREGS_MAX_MASK & (1UL << greg_num_d)) &&
			(u64 *)saved_greg_lo == NULL);
	E2K_KVM_BUG_ON((HOST_KERNEL_GREGS_PAIR_MASK & (1UL << greg_num_d)) &&
			(u64 *)saved_greg_lo == NULL);

	l_gregs = get_pv_vcpu_l_gregs(vcpu);
	E2K_KVM_BUG_ON(l_gregs == NULL);

	addr_lo = l_gregs->gregs.g[greg_num_d - LOCAL_GREGS_START].xreg;
	if (!args.atomic)
		addr_hi = &addr_lo[1];
	else
		addr_hi = &addr_lo[2];

	ret = kvm_priv_recovery_faulted_move(
			(saved_greg_lo) ? (e2k_addr_t)saved_greg_lo : addr,
			(e2k_addr_t)addr_lo, (e2k_addr_t)addr_hi,
			ld_rec_opc, args.entire, 1);
	if (ret)
		return ret;

	l_gregs->updated |= (1UL << greg_num_d);

	return 0;

}

/* generic hypercalls version of recovery faulted operations */

long kvm_recovery_faulted_tagged_guest_store(struct kvm_vcpu *vcpu,
		e2k_addr_t address, u64 wr_data, u64 st_rec_opc,
		u64 data_ext, u64 opc_ext, u64 _arg)
{
	union recovery_faulted_arg arg = { .entire = _arg };
	unsigned long hva;
	kvm_arch_exception_t exception;

	DebugKVMREC("started for address 0x%lx data 0x%llx tag 0x%x, channel #%d\n",
		address, wr_data, arg.tag, arg.chan);

	hva = kvm_vcpu_gva_to_hva(vcpu, address, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVMREC("%s(): cannot translate guest address 0x%lx, "
			"retry with page fault\n", __func__, address);
		kvm_vcpu_inject_page_fault(vcpu, (void *)address,
					&exception);
		return -EAGAIN;
	}
	address = hva;

	return __UACCESS_FN_CALL(recovery_faulted_tagged_store_fn, address,
				 wr_data, st_rec_opc, data_ext, opc_ext, arg);
}


UACCESS_FN_DEFINE5(recovery_faulted_load_fn, e2k_addr_t, address,
		u64 *, ld_val, u8 *, data_tag, u64, ld_rec_opc, int, chan)
{
	native_recovery_faulted_load(address, ld_val, data_tag, ld_rec_opc, chan);
	return 0;
}

long kvm_recovery_faulted_guest_load(struct kvm_vcpu *vcpu, e2k_addr_t address,
		u64 *ld_val, u8 *data_tag, u64 ld_rec_opc, int chan)
{
	u64 __user *ld_val_hva;
	u8 __user *data_tag_hva;
	u64 ld_val_k;
	u8 data_tag_k;
	unsigned long hva;
	kvm_arch_exception_t exception;
	long ret;

	DebugKVMREC("started for address 0x%lx, channel #%d\n",
		address, chan);

	hva = kvm_vcpu_gva_to_hva(vcpu, address, false, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVMREC("%s(): cannot translate guest address 0x%lx, "
			"retry with page fault\n", __func__, address);
		kvm_vcpu_inject_page_fault(vcpu, (void *)address,
					&exception);
		return -EAGAIN;
	}
	address = hva;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)ld_val, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVMREC("%s(): cannot translate guest ld_val 0x%lx, "
			"retry with page fault\n", __func__, ld_val);
		kvm_vcpu_inject_page_fault(vcpu, ld_val, &exception);
		return -EAGAIN;
	}
	ld_val_hva = (u64 __user *) hva;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)data_tag, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVMREC("%s(): cannot translate guest data_tag 0x%lx, "
			"retry with page fault\n", __func__, data_tag);
		kvm_vcpu_inject_page_fault(vcpu, data_tag, &exception);
		return -EAGAIN;
	}
	data_tag_hva = (u8 __user *) hva;

	ret = __UACCESS_FN_CALL(recovery_faulted_load_fn, address,
			&ld_val_k, &data_tag_k, ld_rec_opc, chan);
	if (ret)
		return ret;

	if (put_user(ld_val_k, ld_val_hva)) {
		pr_err("%s(): cannot translate guest ld_val 0x%lx, "
			"retry with page fault\n", __func__, ld_val);
		kvm_vcpu_inject_page_fault(vcpu, ld_val, &exception);
		return -EFAULT;
	}

	if (put_user(data_tag_k, data_tag_hva)) {
		pr_err("%s(): cannot translate guest data_tag 0x%lx, "
			"retry with page fault\n", __func__, data_tag);
		kvm_vcpu_inject_page_fault(vcpu, data_tag, &exception);
		return -EFAULT;
	}

	DebugKVMREC("loaded data 0x%llx tag 0x%x from address 0x%lx\n",
		*ld_val, *data_tag, address);
	return 0;
}

UACCESS_FN_DEFINE6(recovery_faulted_move_fn,
		e2k_addr_t, addr_from, e2k_addr_t, addr_to, e2k_addr_t, addr_to_hi,
		union recovery_faulted_arg, arg, u64, ld_rec_opc, u32, first_time)
{
	native_recovery_faulted_move(addr_from, addr_to, addr_to_hi,
			arg.vr, ld_rec_opc, arg.chan, arg.qp, arg.atomic,
			first_time);
	return 0;
}

long kvm_recovery_faulted_guest_move(struct kvm_vcpu *vcpu,
		e2k_addr_t addr_from, e2k_addr_t addr_to, e2k_addr_t addr_to_hi,
		u64 ld_rec_opc, u64 _arg, u32 first_time)
{
	union recovery_faulted_arg arg = { .entire = _arg };
	unsigned long hva;
	kvm_arch_exception_t exception;
	long ret;

	DebugKVMREC("started from address 0x%lx to addr 0x%lx, channel #%d\n",
		addr_from, addr_to, arg.chan);

	hva = kvm_vcpu_gva_to_hva(vcpu, addr_from, false, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVMREC("%s(): cannot translate guest addr_from 0x%lx, "
			"retry with page fault\n", __func__, addr_from);
		kvm_vcpu_inject_page_fault(vcpu, (void *)addr_from,
					&exception);
		return -EAGAIN;
	}
	addr_from = hva;

	hva = kvm_vcpu_gva_to_hva(vcpu, addr_to, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVMREC("%s(): cannot translate guest addr_to 0x%lx, "
			"retry with page fault\n", __func__, addr_to);
		kvm_vcpu_inject_page_fault(vcpu, (void *)addr_to,
					&exception);
		return -EAGAIN;
	}
	addr_to = hva;

	if (addr_to_hi) {
		hva = kvm_vcpu_gva_to_hva(vcpu, addr_to_hi, true, &exception);
		if (kvm_is_error_hva(hva)) {
			DebugKVMREC("%s(): cannot translate guest addr_to_hi 0x%lx, "
				"retry with page fault\n",
				__func__, addr_to_hi);
			kvm_vcpu_inject_page_fault(vcpu, (void *)addr_to_hi,
						&exception);
			return -EAGAIN;
		}
		addr_to_hi = hva;
	}

	ret = __UACCESS_FN_CALL(recovery_faulted_move_fn, addr_from, addr_to,
				addr_to_hi, arg, ld_rec_opc, first_time);
	DebugKVMREC("loaded data 0x%llx from address 0x%lx, ret=%ld\n",
		*((u64 *)addr_to), addr_from, ret);
	return ret;
}

UACCESS_FN_DEFINE6(recovery_faulted_load_to_greg_fn, e2k_addr_t, address,
		u32, greg_num_d, union recovery_faulted_arg, arg,
		u64, ld_rec_opc, u64 *, saved_greg_lo, u64 *, saved_greg_hi)
{
	native_recovery_faulted_load_to_greg(address, greg_num_d, arg.vr,
			ld_rec_opc, arg.chan, arg.qp, arg.atomic,
			(u64 *) saved_greg_lo, (u64 *) saved_greg_hi);
	return 0;
}

long kvm_recovery_faulted_load_to_guest_greg(struct kvm_vcpu *vcpu,
		e2k_addr_t address, u32 greg_num_d, u64 ld_rec_opc,
		u64 _arg, u64 saved_greg_lo, u64 saved_greg_hi)
{
	union recovery_faulted_arg arg = { .entire = _arg };
	unsigned long hva;
	vcpu_l_gregs_t *l_gregs;
	u64 *addr_lo, *addr_hi;
	kvm_arch_exception_t exception;
	long ret;

	DebugKVMREC("started for address 0x%lx global reg #%d, channel #%d\n",
		address, greg_num_d, arg.chan);

	hva = kvm_vcpu_gva_to_hva(vcpu, address, false, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVMREC("%s(): cannot translate guest address 0x%lx, "
			"retry with page fault\n", __func__, address);
		kvm_vcpu_inject_page_fault(vcpu, (void *)address, &exception);
		return -EAGAIN;
	}
	address = hva;

	if ((u64 *)saved_greg_lo != NULL) {
		hva = kvm_vcpu_gva_to_hva(vcpu, saved_greg_lo, true,
					&exception);
		if (kvm_is_error_hva(hva)) {
			DebugKVMREC("%s(): cannot translate guest addr_to 0x%llx, "
				"retry with page fault\n",
				__func__, saved_greg_lo);
			kvm_vcpu_inject_page_fault(vcpu,
					(void *)saved_greg_lo, &exception);
			return -EAGAIN;
		}
		saved_greg_lo = hva;
	}

	if ((u64 *)saved_greg_hi != NULL) {
		hva = kvm_vcpu_gva_to_hva(vcpu, saved_greg_hi, true,
					&exception);
		if (kvm_is_error_hva(hva)) {
			DebugKVMREC("%s(): cannot translate guest saved_greg_hi "
				"0x%llx, retry with page fault\n",
				__func__, saved_greg_hi);
			kvm_vcpu_inject_page_fault(vcpu,
					(void *)saved_greg_hi, &exception);
			return -EAGAIN;
		}
		saved_greg_hi = hva;
	}

	ret = __UACCESS_FN_CALL(recovery_faulted_load_to_greg_fn,
				address, greg_num_d, arg, ld_rec_opc,
				(u64 *) saved_greg_lo, (u64 *) saved_greg_hi);
	if (ret)
		return ret;

	if (!(LOCAL_GREGS_USER_MASK & (1UL << greg_num_d))) {
		/* it is not "local" global register */
		return 0;
	}

	/* save updated registers value to recover upon return to user */
	E2K_KVM_BUG_ON(!(LOCAL_GREGS_USER_MASK & (1UL << greg_num_d)));
	E2K_KVM_BUG_ON((KERNEL_GREGS_MAX_MASK & (1UL << greg_num_d)) &&
			(u64 *)saved_greg_lo == NULL);
	E2K_KVM_BUG_ON((HOST_KERNEL_GREGS_PAIR_MASK & (1UL << greg_num_d)) &&
			(u64 *)saved_greg_lo == NULL);

	l_gregs = get_pv_vcpu_l_gregs(vcpu);
	E2K_KVM_BUG_ON(l_gregs == NULL);

	addr_lo = l_gregs->gregs.g[greg_num_d - LOCAL_GREGS_START].xreg;
	if (!arg.atomic)
		addr_hi = &addr_lo[1];
	else
		addr_hi = &addr_lo[2];

	ret = __UACCESS_FN_CALL(recovery_faulted_move_fn,
			(saved_greg_lo) ?: address,
			(u64) addr_lo, (u64) addr_hi, arg, ld_rec_opc, 1);
	if (ret)
		return ret;

	l_gregs->updated |= (1UL << greg_num_d);

	return 0;
}

void update_pv_vcpu_local_glob_regs(struct kvm_vcpu *vcpu, local_gregs_t *gregs)
{
	vcpu_l_gregs_t *l_gregs;
	u64 updated_mask, reg_mask;
	int l, reg_no;
	u64 *addr_from, *addr_to;

	if (!is_actual_pv_vcpu_l_gregs(vcpu)) {
		/* current trap activation has not actual gregs */
		trace_empty_vcpu_l_gregs(vcpu);
		return;
	} else {
		trace_active_vcpu_l_gregs(vcpu);
	}

	l_gregs = get_actual_pv_vcpu_l_gregs(vcpu);
	E2K_KVM_BUG_ON(l_gregs == NULL);

	updated_mask = l_gregs->updated;
	if (updated_mask == 0) {
		/* nothing to update */
		goto out_updated;
	}

	E2K_KVM_BUG_ON((updated_mask & ~LOCAL_GREGS_USER_MASK) != 0);

	for (l = 0; l < LOCAL_GREGS_NUM; l++) {
		reg_no = LOCAL_GREGS_START + l;
		reg_mask = (1UL << reg_no);
		if (!(updated_mask & reg_mask))
			continue;
		addr_to = gregs->g[l].xreg;
		addr_from = l_gregs->gregs.g[l].xreg;
		trace_update_vcpu_l_gregs(vcpu, reg_no, gregs->g[l].base,
							 l_gregs->gregs.g[l].base);
		native_move_tagged_qword((u64)addr_from, (u64)addr_to);
		updated_mask &= ~reg_mask;
		if (updated_mask == 0)
			break;
	}
	l_gregs->updated = updated_mask;

out_updated:
	put_pv_vcpu_l_gregs(vcpu);
}

UACCESS_FN_DEFINE3(kvm_move_tagged_guest_data_fn, int, word_size,
		unsigned long, hva_from, unsigned long, hva_to)
{
	switch (word_size) {
	case sizeof(u32):
		native_move_tagged_word(hva_from, hva_to);
		break;
	case sizeof(u64):
		native_move_tagged_dword(hva_from, hva_to);
		break;
	case sizeof(u64) * 2:
		native_move_tagged_qword(hva_from, hva_to);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

long kvm_move_tagged_guest_data(struct kvm_vcpu *vcpu,
		int word_size, e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	unsigned long hva_from, hva_to;
	kvm_arch_exception_t exception;

	DebugKVMREC("started for address from 0x%lx to 0x%lx\n",
		addr_from, addr_to);

	hva_from = kvm_vcpu_gva_to_hva(vcpu, addr_from, false, &exception);
	if (kvm_is_error_hva(hva_from)) {
		pr_err("%s(): cannot translate guest addr_from 0x%lx, "
			"retry with page fault\n", __func__, addr_from);
		kvm_vcpu_inject_page_fault(vcpu, (void *)addr_from,
					&exception);
		return -EAGAIN;
	}
	DebugKVMREC("guest address from 0x%lx converted to hva 0x%lx\n",
		addr_from, hva_from);

	hva_to = kvm_vcpu_gva_to_hva(vcpu, addr_to, true, &exception);
	if (kvm_is_error_hva(hva_to)) {
		pr_err("%s(): cannot translate guest addr_to 0x%lx, "
			"retry with page fault\n", __func__, addr_to);
		kvm_vcpu_inject_page_fault(vcpu, (void *)addr_to,
					&exception);
		return -EAGAIN;
	}
	DebugKVMREC("guest address to 0x%lx converted to hva 0x%lx\n",
		addr_to, hva_to);

	return __UACCESS_FN_CALL(kvm_move_tagged_guest_data_fn,
			word_size, hva_from, hva_to);
}

e2k_addr_t kvm_print_guest_kernel_ptes(e2k_addr_t address)
{
	e2k_addr_t	pa = 0;

	if (address >= NATIVE_TASK_SIZE) {
		pr_info("Address 0x%016lx is not guest kernel address "
			"to print PTE's\n",
			address);
		return pa;
	}
	return print_user_address_ptes(current->mm, address);
}
