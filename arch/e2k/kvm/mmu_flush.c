/*
 * Guest kernel MMU caches support on KVM host
 * (Instruction and Data caches, TLB)
 *
 * Copyright 2016 Salavat S. Gilyazov (atic@mcst.ru)
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>

#include <asm/types.h>
#include <asm/mmu_regs.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/mmu_context.h>
#include <asm/secondary_space.h>

#undef	DEBUG_KVM_TLB_MODE
#undef	DebugPT
#define	DEBUG_KVM_TLB_MODE	0	/* TLB flushing */
#define	DebugPT(fmt, args...)						\
({									\
	if (DEBUG_KVM_TLB_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

/*
 * Flush just one page of a specified guest user.
 */
void kvm_flush_guest_tlb_page(gmm_struct_t *gmm, e2k_addr_t addr)
{
	unsigned long context;

	BUG_ON(!test_thread_flag(TIF_MULTITHREADING) ||
		!test_thread_flag(TIF_VIRTUALIZED_GUEST));

	/* FIXME: guest user context is not completely implemented, */
	/* so all guest user MMs use the current host MM context */
	/* context = gmm->context.cpumsk[raw_smp_processor_id()]; */
	context = current->active_mm->context.cpumsk[raw_smp_processor_id()];

	if (unlikely(context == 0)) {
		/* See comment in __flush_tlb_range(). */
		kvm_flush_guest_tlb_mm(gmm);
		return;
	}

	flush_TLB_page(addr, CTX_HARDWARE(context));

	/* FIXME: flush of secondary space page is not implemented
	if (TASK_IS_BINCO(current) && ADDR_IN_SS(addr) && !IS_UPT_E3S) {
		// flush secondary space address //
		flush_TLB_ss_page(addr - SS_ADDR_START, CTX_HARDWARE(context));
	}
	*/
}

/*
 * Flush a specified guest user mapping on the processor
 */
void kvm_flush_guest_tlb_mm(gmm_struct_t *gmm)
{
	thread_info_t *ti = current_thread_info();
	gthread_info_t *gti;

	BUG_ON(!test_thread_flag(TIF_MULTITHREADING) ||
		!test_thread_flag(TIF_VIRTUALIZED_GUEST));

	if (gmm == pv_vcpu_get_active_gmm(ti->vcpu)) {
		gti = ti->gthread_info;
		if (!test_gti_thread_flag(gti, GTIF_KERNEL_THREAD)) {
			/* kernel thread can manipulate with user addresses */
			/* for example while swap or page cache writeback */
			WARN_ON(pv_vcpu_get_active_gmm(ti->vcpu) != gti->gmm);
		}
		/* Should update right now */
	/* FIXME: guest user context is not completely implemented, */
	/* so all guest user MMs use the current host MM context */
	/*	reload_mmu_context(&gmm->context, gmm->sec_pgd); */
		reload_mmu_context(current->active_mm);
	} else {
	/*	invalidate_mmu_context(&gmm->context, gmm_cpumask(gmm)); */
		invalidate_mmu_context(current->active_mm);
	}
}

/*
 * Flush a specified range of pages
 */

/*
 * If the number of pages to be flushed is below this value,
 * then only those pages will be flushed.
 *
 * Flushing one page takes ~150 cycles, flushing the whole mm
 * takes ~400 cycles. Also note that __flush_tlb_range() may
 * be called repeatedly for the same process so high values
 * are bad.
 */

void kvm_flush_guest_tlb_range(gmm_struct_t *const gmm,
				const e2k_addr_t start, const e2k_addr_t end)
{
	BUG_ON(start > end);

	/* FIXME: guest user context is not completely implemented, */
	/* so all guest user MMs use the current host MM context */
	/* if (flush_tlb_context_range(&gmm->context, start, end)) */
	flush_tlb_mm_range(current->active_mm, start, end);
}

/*
 * Flush the TLB entries mapping the virtually mapped linear page
 * table corresponding to address range [start : end].
 */
void kvm_flush_guest_tlb_pgtables(gmm_struct_t *gmm,
					e2k_addr_t start, e2k_addr_t end)
{
	BUG_ON(start > end);

	/* flush virtual mapping of PTE entries (third level of page table) */
	kvm_flush_guest_tlb_range(gmm,
			pte_virt_offset(_PAGE_ALIGN_UP(start, PTE_SIZE)),
			pte_virt_offset(_PAGE_ALIGN_DOWN(end, PTE_SIZE)));

	/* flush virtual mapping of PMD entries (second level of page table) */
	kvm_flush_guest_tlb_range(gmm,
			pmd_virt_offset(_PAGE_ALIGN_UP(start, PMD_SIZE)),
			pmd_virt_offset(_PAGE_ALIGN_DOWN(end, PMD_SIZE)));

	/* flush virtual mapping of PUD entries (first level of page table) */
	kvm_flush_guest_tlb_range(gmm,
			pud_virt_offset(_PAGE_ALIGN_UP(start, PUD_SIZE)),
			pud_virt_offset(_PAGE_ALIGN_DOWN(end, PUD_SIZE)));
}

/*
 * Flush a specified range of pages and the TLB entries mapping the virtually
 * mapped linear page table corresponding to address range [start : end].
 */
void
kvm_flush_guest_tlb_range_and_pgtables(gmm_struct_t *gmm,
					e2k_addr_t start, e2k_addr_t end)
{
	kvm_flush_guest_tlb_range(gmm, start, end);
	kvm_flush_guest_tlb_pgtables(gmm, start, end);
}

#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT

/*
 * Functions to flush guest VM on host should return boolean value:
 *	true	if address or MM is from guest VM space and flushing was done
 *	false	if address or MM is not from guest VM space or flushing cannot
 *		be done
 */

/*
 * Update just one specified address of current active mm.
 * PGD is updated into CPU root page table from main user PGD table
 */
bool kvm_do_flush_guest_cpu_root_pt_page(struct vm_area_struct *vma,
						e2k_addr_t addr)
{

	BUG_ON(!test_thread_flag(TIF_MULTITHREADING));
	BUG_ON(MMU_IS_SEPARATE_PT());

	BUG_ON(addr >= HOST_TASK_SIZE);

	if (addr >= GUEST_TASK_SIZE)
		/* it is guest kernel address and guest kernel is user of */
		/* host, so host know what to do */
		return false;
	/*
	 * It is user address of some thread to manage guest machine (QEMU).
	 * VCPU and VIRQ VCPU should not use these addresses and what is more
	 * such address can be used by some guest user process.
	 * So do nothing to update CPU root table
	 */
	return true;
}
/*
 * Update user PGD entries from address range of current active mm.
 * PGDs are updated into CPU root page table from main user PGD table
 */
bool kvm_do_flush_guest_cpu_root_pt_range(struct mm_struct *mm,
					e2k_addr_t start, e2k_addr_t end)
{
	BUG_ON(start > end);

	BUG_ON(!test_thread_flag(TIF_MULTITHREADING));
	BUG_ON(MMU_IS_SEPARATE_PT());

	BUG_ON(start >= HOST_TASK_SIZE || end >= HOST_TASK_SIZE);

	if (start >= GUEST_TASK_SIZE)
		/* it is guest kernel address and guest kernel is user of */
		/* host, so host know what to do */
		return false;
	BUG_ON(end >= GUEST_TASK_SIZE);
	/*
	 * It is range of user addresses of some thread to manage guest
	 * machine (QEMU).
	 * VCPU and VIRQ VCPU should not use these addresses and what is more
	 * such address can be used by some guest user process.
	 * So do nothing to update CPU root table
	 */
	return true;
}
/*
 * Update all user PGD entries of current active mm.
 * PGDs are updated into CPU root page table from main user PGD table
 */
bool kvm_do_flush_guest_cpu_root_pt_mm(struct mm_struct *mm)
{
	BUG_ON(!test_thread_flag(TIF_MULTITHREADING));
	BUG_ON(MMU_IS_SEPARATE_PT());

	/*
	 * Updated all user PGD entries, so it can be user and kernel part
	 * of guest VM. User part of guest user MM can update only special
	 * host functions (kvm_flush_guest_xxx()). In this case can be updated
	 * only MM of host user threads to manage guest virtual machine (QEMU).
	 * But it can be updated guest kernel part of VM, so reload all PGD
	 * entries of guest kernel
	 */
	copy_guest_kernel_pgd_to_kernel_root_pt(mm->pgd);
	return true;
}
/*
 * Update all users PGD entries of all active MMs.
 * PGDs are updated into CPU root page table from main user PGD table
 */
bool kvm_do_flush_guest_cpu_root_pt(void)
{
	gmm_struct_t *active_gmm;

	BUG_ON(!test_thread_flag(TIF_MULTITHREADING));
	BUG_ON(MMU_IS_SEPARATE_PT());
	if (current->flags & PF_EXITING) {
		/* process is exiting, nothing flush */
		return true;
	}

	/*
	 * Reload guest kernel part PGDs from main user page table
	 */
	BUG_ON(current->mm == NULL);
	copy_guest_kernel_pgd_to_kernel_root_pt(current->mm->pgd);

	/*
	 * Reload guest user part PGDs from current active guest user MM
	 */
	active_gmm = pv_vcpu_get_active_gmm(current_thread_info()->vcpu);
	if (active_gmm != NULL) {
		/* there is now active guest user */
		copy_guest_user_pgd_to_kernel_root_pt(
					kvm_mmu_get_gmm_root(active_gmm));
	}
	return true;
}
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
