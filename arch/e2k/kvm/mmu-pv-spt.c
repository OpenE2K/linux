/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * VCPU MMU paravirtualization, based on x86 code and ideas.
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
#include <asm/mmu_regs_types.h>
#include <asm/tlbflush.h>
#include <asm/pgalloc.h>
#include <asm/mman.h>
#include <asm/tlb.h>
#include <asm/process.h>
#include <asm/cpu_regs.h>
#include <asm/kvm/gpid.h>
#include <asm/kvm/switch.h>
#include <asm/kvm/gva_cache.h>
#include <asm/traps.h>

#include "mmu_defs.h"
#include "mmu.h"
#include "mman.h"
#include "cpu.h"
#include "process.h"
#include "user_area.h"
#include "gaccess.h"

#define MMU_WARN_ON(x)		WARN_ON(x)
#define MMU_BUG_ON(x)		BUG_ON(x)

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE || kvm_debug)				\
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

#undef	DEBUG_KVM_PARAVIRT_FAULT_MODE
#undef	DebugKVMPVF
#define	DEBUG_KVM_PARAVIRT_FAULT_MODE	0	/* paravirt page fault on KVM */
#define	DebugKVMPVF(fmt, args...)					\
({									\
	if (DEBUG_KVM_PARAVIRT_FAULT_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_AAU_PAGE_FAULT_MODE
#undef	DebugAAUPF
#define	DEBUG_AAU_PAGE_FAULT_MODE	0	/* page fault from AAU MOVA */
#define	DebugAAUPF(fmt, args...)					\
({									\
	if (DEBUG_AAU_PAGE_FAULT_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_VM_MODE
#undef	DebugKVMVM
#define	DEBUG_KVM_VM_MODE	0	/* page fault on KVM */
#define	DebugKVMVM(fmt, args...)					\
({									\
	if (DEBUG_KVM_VM_MODE)						\
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

#undef	DEBUG_KVM_TO_VIRT_MODE
#undef	DebugTOVM
#define	DEBUG_KVM_TO_VIRT_MODE	0	/* switch guest to virtual mode */
#define	DebugTOVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_TO_VIRT_MODE || kvm_debug)			\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SHADOW_PF_MODE
#undef	DebugSPF
#define	DEBUG_KVM_SHADOW_PF_MODE	0	/* shadow PT fault mode */
#define	DebugSPF(fmt, args...)						\
({									\
	if (DEBUG_KVM_SHADOW_PF_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_NONPAGING_MODE
#undef	DebugNONP
#define	DEBUG_KVM_NONPAGING_MODE	0	/* nonpaging mode debug */
#define	DebugNONP(fmt, args...)						\
({									\
	if (DEBUG_KVM_NONPAGING_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SWITCH_MM_MODE
#undef	DebugKVMSWH
#define	DEBUG_KVM_SWITCH_MM_MODE	0	/* switch guest MM debug */
#define	DebugKVMSWH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SWITCH_MM_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_PTE_MODE
#undef	DebugPTE
#define	DEBUG_KVM_PTE_MODE	0	/* guest PTE update/write debug */
#define	DebugPTE(fmt, args...)						\
({									\
	if (DEBUG_KVM_PTE_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_GMM_MODE
#undef	DebugGMM
#define	DEBUG_KVM_GMM_MODE	0	/* guest mm freeing debug */
#define	DebugGMM(fmt, args...)						\
({									\
	if (DEBUG_KVM_GMM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_ACTIVATE_GMM_MODE
#undef	DebugAGMM
#define	DEBUG_ACTIVATE_GMM_MODE	0	/* guest mm activating debug */
#define	DebugAGMM(fmt, args...)						\
({									\
	if (DEBUG_ACTIVATE_GMM_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_GMM_FREE_MODE
#undef	DebugFREE
#define	DEBUG_KVM_GMM_FREE_MODE	0	/* guest mm PT freeing debug */
#define	DebugFREE(fmt, args...)						\
({									\
	if (DEBUG_KVM_GMM_FREE_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_REEXEC_PF_MODE
#undef	DebugREEXEC
#define	DEBUG_REEXEC_PF_MODE	0	/* reexecute load and wait debugging */
#define	DebugREEXEC(fmt, args...)					\
({									\
	if (DEBUG_REEXEC_PF_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_WRITE_REEXEC_PF_MODE
#undef	DebugWREEX
#define	DEBUG_WRITE_REEXEC_PF_MODE	0	/* reexecute store debugging */
#define	DebugWREEX(fmt, args...)					\
({									\
	if (DEBUG_WRITE_REEXEC_PF_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

/* number of retries to handle page fault */
#undef	PF_RETRIES_MAX_NUM
#define	PF_RETRIES_MAX_NUM	1
/* common number of one try and retries to handle page fault */
#undef	PF_TRIES_MAX_NUM
#define	PF_TRIES_MAX_NUM	(2 + PF_RETRIES_MAX_NUM)

void kvm_init_gmm_root_pt(struct kvm *kvm, gmm_struct_t *new_gmm)
{
	/* guest kernel part will be inited on page fault while */
	/* access to guest kernel by guest user process */
	new_gmm->root_hpa = E2K_INVALID_PAGE;
}

void kvm_fill_init_root_pt(struct kvm *kvm)
{
	pgd_t *root;

	root = kvm_mmu_get_init_gmm_root(kvm);
	if (root == NULL)
		/* is not yet created and valid */
		return;

	/* copy kernel part of root page table entries to enable host */
	/* traps and hypercalls on guest */
	copy_kernel_pgd_range(root, mm_node_pgd(&init_mm, numa_node_id()));
}

void release_gmm_root_pt(struct kvm *kvm, gmm_struct_t *gmm)
{
	hpa_t gmm_root, gk_root, vcpu_root;
	struct kvm_vcpu *vcpu;
	int r;

	gmm->pt_synced = false;

	spin_lock(&kvm->mmu_lock);
	trace_host_get_gmm_root_hpa(gmm, NATIVE_READ_IP_REG_VALUE());
	gmm_root = gmm->root_hpa;
	gk_root = gmm->gk_root_hpa;
	if (unlikely(!VALID_PAGE(gmm_root))) {
		/* gmm root has been already released */
		E2K_KVM_BUG_ON(VALID_PAGE(gk_root));
		spin_unlock(&kvm->mmu_lock);
		return;
	}
	E2K_KVM_BUG_ON(!VALID_PAGE(gk_root) && !pv_mmu_is_init_gmm(kvm, gmm));

	if (unlikely(pv_mmu_is_init_gmm(kvm, gmm))) {
		struct kvm_mmu_page *sp;

		/* init gmm (guest kernel root PT) is released */
		/* well, at least some kind of correctness */
		sp = page_header(gmm_root);
		E2K_KVM_BUG_ON(sp->root_count != atomic_read(&kvm->online_vcpus));
		sp->root_count = 1;	/* can be released */
	}

	DebugFREE("will release gmm #%d shodow PT from user root 0x%llx "
		"kernel root 0x%llx\n",
		gmm->nid.nr, gmm_root, gk_root);

	trace_host_get_gmm_root_hpa(gmm, NATIVE_READ_IP_REG_VALUE());
	kvm_release_user_root_kernel_copy(kvm, gmm);
	trace_host_get_gmm_root_hpa(gmm, NATIVE_READ_IP_REG_VALUE());
	E2K_KVM_BUG_ON(VALID_PAGE(gmm->gk_root_hpa));
	gk_root = gmm->gk_root_hpa;

	gmm->root_hpa = E2K_INVALID_PAGE;
	trace_host_set_gmm_root_hpa(gmm, gmm_root, gk_root,
				    NATIVE_READ_IP_REG_VALUE());
	spin_unlock(&kvm->mmu_lock);

	mmu_release_spt_root(kvm, gmm_root);

	mutex_lock(&kvm->lock);
	kvm_for_each_vcpu(r, vcpu, kvm) {
		if (vcpu == NULL)
			continue;

		spin_lock(&kvm->mmu_lock);
		vcpu_root = kvm_get_space_type_spt_u_root(vcpu);
		if (VALID_PAGE(vcpu_root) && vcpu_root == gmm_root) {
			/* invalidate current VCPU SPT root */
			kvm_set_space_type_spt_u_root(vcpu, E2K_INVALID_PAGE);
			kvm_set_space_type_spt_os_root(vcpu,
					pv_vcpu_get_init_root_hpa(vcpu));
			kvm_set_space_type_spt_gk_root(vcpu,
					pv_vcpu_get_init_root_hpa(vcpu));
		}
		spin_unlock(&kvm->mmu_lock);
	}
	mutex_unlock(&kvm->lock);
}

void kvm_arch_init_vm_mmap(struct kvm *kvm)
{
	kvm->arch.shadow_pt_enable = true;
#ifdef	CONFIG_KVM_PHYS_PT_ENABLE
	kvm->arch.phys_pt_enable = kvm->arch.is_hv;
# ifdef	CONFIG_KVM_TDP_ENABLE
	kvm->arch.tdp_enable = kvm->arch.phys_pt_enable;
# else	/* ! CONFIG_KVM_TDP_ENABLE */
	kvm->arch.tdp_enable = false;
# endif	/* CONFIG_KVM_TDP_ENABLE */
#else	/* ! CONFIG_KVM_PHYS_PT_ENABLE */
	kvm->arch.phys_pt_enable = false;
	kvm->arch.tdp_enable = false;
#endif	/* CONFIG_KVM_PHYS_PT_ENABLE */
}

void kvm_arch_free_memslot(struct kvm *kvm, struct kvm_memory_slot *free)
{
	const pt_struct_t *pt_struct = mmu_pt_get_host_pt_struct(kvm);
	user_area_t *guest_area;
	int i;
	unsigned long base_gfn;

	DebugKVMSH("started for memory slot %px\n", free);
	base_gfn = free->base_gfn;
	DebugKVMVM("memory slot: base gfn 0x%lx, pages 0x%lx\n",
		base_gfn, free->npages);

	guest_area = free->arch.guest_areas.area;
	if (guest_area != NULL)
		kvm_arch_free_memory_region(kvm, free);
	E2K_KVM_BUG_ON(free->arch.guest_areas.area != NULL);
	for (i = 0; i < KVM_NR_PAGE_SIZES; ++i) {
		const pt_level_t *pt_level;
		int level = i + 1;

		pt_level = get_pt_struct_level_on_id(pt_struct, level);

		kvfree(free->arch.rmap[i]);
		DebugKVMVM("free slot ID %d RMAP %px\n",
			free->id, free->arch.rmap);
		free->arch.rmap[i] = NULL;

		if (!is_huge_pt_level(pt_level))
			/* the page table level has not huge pages */
			continue;

		kvfree(free->arch.lpage_info[i - 1]);
		DebugKVMVM("free slot ID %d huge page INFO %px\n",
				free->id, free->arch.lpage_info[i - 1]);
		free->arch.lpage_info[i - 1] = NULL;
	}

	kvm_page_track_free_memslot(free);
}

/* FIXME: it need implement x86 arch function for e2k arch */
static void kvm_mmu_slot_apply_flags(struct kvm *kvm,
				     struct kvm_memory_slot *new)
{
	/* Still write protect RO slot */
	if (new->flags & KVM_MEM_READONLY) {
		kvm_mmu_slot_remove_write_access(kvm, new);
		return;
	}

	/*
	 * Call kvm_x86_ops dirty logging hooks when they are valid.
	 *
	 * kvm_x86_ops->slot_disable_log_dirty is called when:
	 *
	 *  - KVM_MR_CREATE with dirty logging is disabled
	 *  - KVM_MR_FLAGS_ONLY with dirty logging is disabled in new flag
	 *
	 * The reason is, in case of PML, we need to set D-bit for any slots
	 * with dirty logging disabled in order to eliminate unnecessary GPA
	 * logging in PML buffer (and potential PML buffer full VMEXT). This
	 * guarantees leaving PML enabled during guest's lifetime won't have
	 * any additonal overhead from PML when guest is running with dirty
	 * logging disabled for memory slots.
	 *
	 * kvm_x86_ops->slot_enable_log_dirty is called when switching new slot
	 * to dirty logging mode.
	 *
	 * If kvm_x86_ops dirty logging hooks are invalid, use write protect.
	 *
	 * In case of write protect:
	 *
	 * Write protect all pages for dirty logging.
	 *
	 * All the sptes including the large sptes which point to this
	 * slot are set to readonly. We can not create any new large
	 * spte on this slot until the end of the logging.
	 *
	 * See the comments in fast_page_fault().
	 */
	if (new->flags & KVM_MEM_LOG_DIRTY_PAGES) {
		kvm_mmu_slot_remove_write_access(kvm, new);
	}
}

void kvm_arch_commit_memory_region(struct kvm *kvm,
			const struct kvm_userspace_memory_region *mem,
			struct kvm_memory_slot *old,
			const struct kvm_memory_slot *new,
			enum kvm_mr_change change)
{
	int nr_mmu_pages = 0;

	if (!kvm->arch.n_requested_mmu_pages)
		nr_mmu_pages = kvm_mmu_calculate_mmu_pages(kvm);

	if (nr_mmu_pages)
		kvm_mmu_change_mmu_pages(kvm, nr_mmu_pages);

	/*
	 * Dirty logging tracks sptes in 4k granularity, meaning that large
	 * sptes have to be split.  If live migration is successful, the guest
	 * in the source machine will be destroyed and large sptes will be
	 * created in the destination. However, if the guest continues to run
	 * in the source machine (for example if live migration fails), small
	 * sptes will remain around and cause bad performance.
	 *
	 * Scan sptes if dirty logging has been stopped, dropping those
	 * which can be collapsed into a single large-page spte.  Later
	 * page faults will create the large-page sptes.
	 */
	if ((change != KVM_MR_DELETE) &&
		(old->flags & KVM_MEM_LOG_DIRTY_PAGES) &&
		!(new->flags & KVM_MEM_LOG_DIRTY_PAGES))
		kvm_mmu_zap_collapsible_sptes(kvm, new);

	/*
	 * Set up write protection and/or dirty logging for the new slot.
	 *
	 * For KVM_MR_DELETE and KVM_MR_MOVE, the shadow pages of old slot have
	 * been zapped so no dirty logging staff is needed for old slot. For
	 * KVM_MR_FLAGS_ONLY, the old slot is essentially the same one as the
	 * new and it's also covered when dealing with the new slot.
	 *
	 * FIXME: const-ify all uses of struct kvm_memory_slot.
	 */
	if (change != KVM_MR_DELETE)
		kvm_mmu_slot_apply_flags(kvm, (struct kvm_memory_slot *) new);
}

void kvm_arch_flush_shadow_memslot(struct kvm *kvm,
				   struct kvm_memory_slot *slot)
{
	kvm_page_track_flush_slot(kvm, slot);
}

e2k_addr_t kvm_guest_kernel_addr_to_hva(struct kvm_vcpu *vcpu,
						e2k_addr_t address)
{
	gpa_t gpa;
	e2k_addr_t hva;

	DebugKVMPVF("started for addr 0x%lx\n", address);
	if (!is_shadow_paging(vcpu)) {
		/* it should be already host address */
		E2K_KVM_BUG_ON(address >= NATIVE_TASK_SIZE);
		return address;
	}
	gpa = mmu_pt_gva_to_gpa(vcpu, address, ACC_WRITE_MASK, NULL, NULL);
	if (gpa == UNMAPPED_GVA) {
		pr_err("%s(): address 0x%lx already unmapped or invalid\n",
			__func__, address);
		return -1;
	}
	hva = gfn_to_hva(vcpu->kvm, gpa_to_gfn(gpa));
	hva |= address & ~PAGE_MASK;
	return hva;
}
int kvm_e2k_paravirt_page_prefault(pt_regs_t *regs, trap_cellar_t *tcellar)
{
	pr_err("%s(): should not be used for shadow PT support\n", __func__);
	return -EINVAL;
}

static int kvm_pv_mmu_load_u_gmm(struct kvm_vcpu *vcpu,
			gmm_struct_t *gmm, gpa_t u_phys_ptb)
{
	int ret;

	/* It need create new shadow PT */
	E2K_KVM_BUG_ON(!IS_E2K_INVALID_PAGE(gmm->root_hpa));
	ret = kvm_create_shadow_user_pt(vcpu, gmm, u_phys_ptb);
	if (ret) {
		pr_err("%s(): could not create initial shadow PT or "
			"sync all guest pages, error %d\n",
			__func__, ret);
		return ret;
	}

	E2K_KVM_BUG_ON(!VALID_PAGE(kvm_get_space_type_spt_u_root(vcpu)));

	return 0;
}

static int kvm_pv_mmu_prepare_u_gmm(struct kvm_vcpu *vcpu,
			gmm_struct_t *gmm, gpa_t u_phys_ptb)
{
	int ret;

	/* It need create new shadow PT */
	E2K_KVM_BUG_ON(!IS_E2K_INVALID_PAGE(gmm->root_hpa));
	if (unlikely(!vcpu->arch.mmu.u_context_on)) {
		vcpu->arch.mmu.u_context_on = true;
	}
	ret = kvm_prepare_shadow_user_pt(vcpu, gmm, u_phys_ptb);
	if (ret) {
		pr_err("%s(): could not create initial shadow PT or "
			"sync all guest pages, error %d\n",
			__func__, ret);
		return ret;
	}

	E2K_KVM_BUG_ON(!VALID_PAGE(gmm->root_hpa));

	return 0;
}

static int vcpu_init_pv_mmu_state(struct kvm_vcpu *vcpu,
				  vcpu_gmmu_info_t *gmmu_info)
{
	hpa_t root;
	e2k_core_mode_t core_mode;
	bool updated;
	int ret;

	if (gmmu_info->opcode & INIT_STATE_GMMU_TC_ONLY) {
		hpa_t tc_hpa;
		gpa_t tc_gpa = gmmu_info->trap_cellar;
		return vcpu_write_trap_point_mmu_reg(vcpu, tc_gpa, &tc_hpa);
	}

	ret = vcpu_write_mmu_pid_reg(vcpu, gmmu_info->pid);
	if (ret != 0)
		goto error;

	if (gmmu_info->sep_virt_space) {
		set_sep_virt_spaces(vcpu);
		ret = vcpu_write_mmu_os_pptb_reg(vcpu, gmmu_info->os_pptb,
						 &updated, &root);
		if (ret != 0)
			goto error;

		ret = vcpu_write_mmu_os_vptb_reg(vcpu, gmmu_info->os_vptb);
		if (ret != 0)
			goto error;

		ret = vcpu_write_mmu_os_vab_reg(vcpu, gmmu_info->os_vab);
		if (ret != 0)
			goto error;
	} else {
		reset_sep_virt_spaces(vcpu);
	}

	core_mode = read_guest_CORE_MODE_reg(vcpu);
	core_mode.CORE_MODE_pt_v6 = gmmu_info->pt_v6;
	core_mode.CORE_MODE_sep_virt_space = gmmu_info->sep_virt_space;
	write_guest_CORE_MODE_reg(vcpu, core_mode);

	ret = vcpu_write_mmu_u_pptb_reg(vcpu, gmmu_info->u_pptb,
					&updated, &root);
	if (ret != 0)
		goto error;

	ret = vcpu_write_mmu_u_vptb_reg(vcpu, gmmu_info->u_vptb);
	if (ret != 0)
		goto error;

	ret = vcpu_write_mmu_cr_reg(vcpu, gmmu_info->mmu_cr);
	if (ret != 0)
		goto error;

	kvm_mmu_set_init_gmm_root(vcpu, E2K_INVALID_PAGE);

	return 0;

error:
	return ret;
}

static int vcpu_set_OS_VAB_pv_mmu_state(struct kvm_vcpu *vcpu,
					vcpu_gmmu_info_t *gmmu_info)
{
	int ret;

	if (!is_sep_virt_spaces(vcpu)) {
		pr_err("%s(): VCPU was inited with united PTs MMU and OS_VAB "
			"cannot be set, so ignored\n",
			__func__);
		return -EINVAL;
	}

	ret = vcpu_write_mmu_os_vab_reg(vcpu, gmmu_info->os_vab);
	if (ret != 0)
		goto error;

	return 0;

error:
	return ret;
}

int kvm_pv_vcpu_mmu_state(struct kvm_vcpu *vcpu,
			  vcpu_gmmu_info_t __user *mmu_info)
{
	vcpu_gmmu_info_t gmmu_info;

	if (kvm_vcpu_copy_from_guest(vcpu, &gmmu_info, mmu_info,
						sizeof(*mmu_info))) {
		pr_err("%s() : copy VCPU #%d MMU info from user failed\n",
			__func__, vcpu->vcpu_id);
		return -EFAULT;
	}
	if (gmmu_info.opcode & (INIT_STATE_GMMU_OPC | INIT_STATE_GMMU_TC_ONLY)) {
		return vcpu_init_pv_mmu_state(vcpu, &gmmu_info);
	} else if (gmmu_info.opcode & SET_OS_VAB_GMMU_OPC) {
		return vcpu_set_OS_VAB_pv_mmu_state(vcpu, &gmmu_info);
	} else {
		pr_err("%s() : unknown operathion type on VCPU #%d MMU\n",
			__func__, vcpu->vcpu_id);
		return -EINVAL;
	}
	return 0;
}

int kvm_pv_activate_guest_mm(struct kvm_vcpu *vcpu,
		gmm_struct_t *new_gmm, gpa_t u_phys_ptb)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	gthread_info_t *gti;
	int ret;

	E2K_KVM_BUG_ON(!is_shadow_paging(vcpu));
	E2K_KVM_BUG_ON(vcpu->arch.is_hv);

	gti = pv_vcpu_get_gti(vcpu);
	DebugAGMM("proces #%d the new gmm #%d\n",
		gti->gpid->nid.nr, new_gmm->nid.nr);

	gti->curr_ctx_key = 0;

	new_gmm->u_pptb = u_phys_ptb;
	DebugKVMSWH("VCPU #%d guest user mm #%d root PT base: 0x%llx\n",
		vcpu->vcpu_id, new_gmm->nid.nr, u_phys_ptb);

	ret = kvm_pv_mmu_load_u_gmm(vcpu, new_gmm, u_phys_ptb);
	if (ret != 0)
		goto failed;

	mmu_pv_setup_shadow_u_pptb(vcpu, new_gmm);

	if (!mmu->u_context_on)
		mmu->u_context_on = true;

	new_gmm->pt_synced = true;

	return new_gmm->nid.nr;

failed:
	return ret;
}

int kvm_pv_prepare_guest_mm(struct kvm_vcpu *vcpu,
		gmm_struct_t *new_gmm, gpa_t u_phys_ptb)
{
	int ret;

	new_gmm->u_pptb = u_phys_ptb;
	new_gmm->u_vptb = pv_vcpu_get_init_gmm(vcpu)->u_vptb;
	DebugKVMSWH("VCPU #%d guest user mm #%d root PT base: 0x%llx\n",
		vcpu->vcpu_id, new_gmm->nid.nr, u_phys_ptb);

	E2K_KVM_BUG_ON(!is_shadow_paging(vcpu));
	E2K_KVM_BUG_ON(vcpu->arch.is_hv);

	ret = kvm_pv_mmu_prepare_u_gmm(vcpu, new_gmm, u_phys_ptb);
	if (ret != 0)
		goto failed;

	E2K_KVM_BUG_ON(!new_gmm->pt_synced);

	return 0;

failed:
	return ret;
}

static void set_pv_vcpu_mu_events_num(struct kvm_vcpu *vcpu, int events_num)
{
	E2K_KVM_BUG_ON(events_num < get_vcpu_mu_events_num(vcpu));
	set_vcpu_mu_events_num(vcpu, events_num);
}

static void set_pv_vcpu_cur_mu_event_no(struct kvm_vcpu *vcpu, int event_no)
{
	int events_num = get_vcpu_mu_events_num(vcpu);

	E2K_KVM_BUG_ON(events_num >= 0 && event_no > events_num);
	set_vcpu_mu_cur_event_no(vcpu, event_no);
	if (event_no >= get_vcpu_mu_events_num(vcpu)) {
		set_pv_vcpu_mu_events_num(vcpu, event_no + 1);
	}
}

int write_to_guest_pt_phys(struct kvm_vcpu *vcpu, gpa_t gpa,
				const pgprot_t *gpte, int bytes)
{
	int ret;

	DebugPTE("started for GPA 0x%llx gpte %px == 0x%lx\n",
		gpa, gpte, pgprot_val(*gpte));
	ret = kvm_vcpu_write_guest(vcpu, gpa, gpte, bytes);
	if (ret < 0) {
		pr_err("%s(): could not write guest pte %px == 0x%lx on host "
			"address of GPA 0x%llx\n",
			__func__, gpte, pgprot_val(*gpte), gpa);
		return ret;
	}
	kvm_page_track_write(vcpu, NULL, gpa, (const void *)gpte, bytes, 0);

	return 1;	/* fault handled and recovered */
}

int kvm_guest_addr_to_host(void **addr)
{
	struct kvm_vcpu *vcpu = current_thread_info()->vcpu;
	unsigned long hva;
	kvm_arch_exception_t exception;

	E2K_KVM_BUG_ON(vcpu == NULL || !vcpu->arch.is_pv);

	hva = kvm_vcpu_gva_to_hva(vcpu, (e2k_addr_t)*addr,
				false, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, "
			"inject page fault to guest\n", addr);
		kvm_vcpu_inject_page_fault(vcpu, (void *)addr,
				&exception);
		return -EAGAIN;
	}

	*addr = (void *)hva;
	return 0;
}

void *kvm_guest_ptr_to_host_ptr(void *guest_ptr, bool is_write,
				int size, bool need_inject)
{
	struct kvm_vcpu *vcpu = current_thread_info()->vcpu;
	unsigned long hva;
	kvm_arch_exception_t exception;

	if ((u64)guest_ptr & PAGE_MASK !=
				(u64)(guest_ptr + size - 1) & PAGE_MASK) {
		/* in this case need translation of two pages addresses */
		/* and two separate access to two part of data */
		pr_err("%s(): guest pointer %lx size %d bytes crosses "
			"page boundaries, not implemented !!!\n",
			__func__, guest_ptr, size);
		return ERR_PTR(-EINVAL);
	}

	vcpu = current_thread_info()->vcpu;
	E2K_KVM_BUG_ON(vcpu == NULL || vcpu->arch.is_hv);

	hva = kvm_vcpu_gva_to_hva(vcpu, (e2k_addr_t)guest_ptr,
				is_write, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, "
			"inject page fault to guest is %d\n",
			guest_ptr, need_inject);
		if (need_inject)
			kvm_vcpu_inject_page_fault(vcpu, (void *)guest_ptr,
					&exception);
		return ERR_PTR(-EAGAIN);
	}

	return (void *)hva;
}
static void provide_jump_to_recovery_point(struct kvm_vcpu *vcpu, pt_regs_t *regs,
					   trap_cellar_t *tcellar)
{
	tc_cond_t cond;

	E2K_KVM_BUG_ON(!KVM_TEST_RECOVERY_FAULTED(vcpu));
	cond = tcellar->condition;
	E2K_KVM_BUG_ON(!tc_test_is_as_kvm_recovery_user(cond));
	correct_trap_return_ip(regs, KVM_GET_RECOVERY_JUMP_POINT(vcpu));
	KVM_RESET_RECOVERY_FAULTED(vcpu);
}

static int inject_data_page_fault(struct kvm_vcpu *vcpu, pt_regs_t *regs,
					trap_cellar_t *tcellar)
{
	tc_cond_t cond;

	cond = tcellar->condition;
	if (KVM_TEST_RECOVERY_FAULTED(vcpu)) {
		/* page fault on guest load/store recovery operation and */
		/* fault should be on guest page handler, */
		/* so does not inject new fault */
		return 0;
	}

	tcellar->condition = tc_set_as_kvm_passed(cond);
	kvm_inject_pv_vcpu_tc_entry(vcpu, tcellar);
	kvm_inject_data_page_exc(vcpu, regs);
	return 2;
}

static void set_recovery_user_page_fault(struct kvm_vcpu *vcpu,
					 trap_cellar_t *tcellar)
{
	tc_cond_t cond;

	cond = tcellar->condition;
	cond = tc_set_kvm_fault_injected(cond);
	cond = tc_set_kvm_recovery_user(cond);
	tcellar->condition = cond;
}

static void inject_instr_page_fault(struct kvm_vcpu *vcpu, pt_regs_t *regs,
					e2k_addr_t IP)
{
	kvm_inject_instr_page_exc(vcpu, regs, exc_instr_page_miss_mask, IP);
}

static void inject_ainstr_page_fault(struct kvm_vcpu *vcpu, pt_regs_t *regs,
					e2k_addr_t IP)
{
	kvm_inject_instr_page_exc(vcpu, regs, exc_ainstr_page_miss_mask, IP);
}

static void inject_aau_page_fault(struct kvm_vcpu *vcpu, pt_regs_t *regs,
					unsigned int aa_no)
{
	kvm_inject_aau_page_exc(vcpu, regs, aa_no);
}

int kvm_pv_mmu_page_fault(struct kvm_vcpu *vcpu, struct pt_regs *regs,
				trap_cellar_t *tcellar, bool user_mode)
{
	e2k_addr_t address;
	tc_cond_t cond;
	tc_fault_type_t ftype;
	tc_opcode_t opcode;
	unsigned mas;
	bool store, page_boundary = false;
	u32 error_code = PFERR_PT_FAULT_MASK;
	bool nonpaging = !is_paging(vcpu);
	kvm_pfn_t pfn;
	gfn_t gfn;
	gpa_t gpa;
	e2k_addr_t hva;
	int bytes;
	intc_mu_state_t *mu_state;
	int r, pfres, fmt, retry;
	long try;

	address = tcellar->address;
	cond = tcellar->condition;

	AW(ftype) = AS(cond).fault_type;
	AW(opcode) = AS(cond).opcode;
	fmt = TC_COND_FMT_FULL(cond);
	E2K_KVM_BUG_ON(AS(opcode).fmt == 0 || AS(opcode).fmt == 6);
	bytes = tc_cond_to_size(cond);
	error_code = PFRES_SET_ACCESS_SIZE(error_code, bytes);
	mas = AS(cond).mas;
	store = tc_cond_is_store(cond, machine.native_iset_ver);
	DebugNONP("page fault on guest address 0x%lx fault type 0x%x\n",
		address, AW(ftype));

	E2K_KVM_BUG_ON(regs->trap == NULL);
	set_pv_vcpu_cur_mu_event_no(vcpu, regs->trap->curr_cnt);

	/*
	 * address belongs to 2 pages (ld/st through page boundary)
	 * Count real address of ld/st
	 */
	if (AS(cond).num_align) {
		if (fmt != LDST_QP_FMT && fmt != TC_FMT_QPWORD_Q)
			address -= 8;
		else
			address -= 16;
	}

	if (pf_on_page_boundary(address, cond)) {
		unsigned long pf_address;

		if (is_spurious_qp_store(store, address, fmt,
					tcellar->mask, &pf_address)) {
			page_boundary = false;
			address = pf_address;
		} else {
			page_boundary = true;
		}
	} else {
		page_boundary = false;
	}

	if (address >= NATIVE_TASK_SIZE) {
		/* address from host page space range, so pass the fault */
		/* to guest, let the guest itself handle whaut to do */
		r = inject_data_page_fault(vcpu, regs, tcellar);
		goto out;	/* fault injected to guest */
	}

	if (AW(ftype) == 0) {
		error_code |= PFERR_NOT_PRESENT_MASK;
		DebugSPF("empty page fault type\n");
	} else if (AS(ftype).page_miss) {
		error_code |= PFERR_NOT_PRESENT_MASK;
		DebugSPF("page miss fault type\n");
	} else if (AS(ftype).illegal_page) {
		error_code |= PFERR_NOT_PRESENT_MASK | PFERR_ILLEGAL_PAGE_MASK;
		DebugSPF("page miss fault type\n");
	} else if (nonpaging) {
		error_code |= PFERR_NOT_PRESENT_MASK;
		DebugSPF("fault type at nonpaging mode\n");
	}
	if (store) {
		error_code |= PFERR_WRITE_MASK;
		DebugSPF("page fault on store\n");
	} else {
		DebugSPF("page fault on load\n");
	}
	if (user_mode) {
		error_code |= PFERR_USER_MASK;
		DebugSPF("page fault at user mode\n");
	} else {
		DebugSPF("page fault at kernel mode\n");
	}
	if (AS(cond).spec) {
		error_code |= PFERR_SPEC_MASK;
		DebugSPF("speculative operation\n");
	}

	if (AS(ftype).nwrite_page) {
		error_code &= ~PFERR_NOT_PRESENT_MASK;
		error_code |= PFERR_PRESENT_MASK | PFERR_WRITE_MASK;
		DebugSPF("not write page fault type\n");
	}

	if (is_hw_access_page_fault(tcellar)) {
		error_code |= PFERR_HW_ACCESS_MASK;
		DebugSPF("hardware access page fault type\n");
	}

	if (mas == MAS_WAIT_LOCK ||
			(mas == MAS_WAIT_LOCK_Q && bytes == 16)) {
		DebugREEXEC("not writable page fault on load and lock "
			"operation\n");
		/* this mas has store semantic */
		error_code |= PFERR_WAIT_LOCK_MASK;
	}
	if (mas == MAS_IOADDR) {
		DebugSPF("IO space access operation\n");
		error_code |= PFERR_MMIO_MASK;
	}
	if (AS(ftype).priv_page) {
		error_code &= ~PFERR_NOT_PRESENT_MASK;
		error_code |= PFERR_PRESENT_MASK;
		DebugSPF("priviled page fault type\n");
	}

	if (regs->dont_inject) {
		error_code |= PFERR_DONT_INJECT_MASK;
	}

	regs->is_guest_user = !pv_vcpu_trap_on_guest_kernel(regs) &&
				is_guest_user_gva(address) && !nonpaging;
	if (regs->is_guest_user)
		error_code |= PFERR_USER_MASK;
	if (is_guest_user_gva(address) && !nonpaging)
		error_code |= PFERR_USER_ADDR_MASK;

	mu_state = get_intc_mu_state(vcpu);
	mu_state->may_be_retried = true;
	mu_state->ignore_notifier = false;

	if (KVM_TEST_RECOVERY_FAULTED(vcpu)) {
		/* page fault on guest load/store recovery operation */
		/* set corresponding flag to don't recover by host */
		set_recovery_user_page_fault(vcpu, tcellar);
	}

	/* clear flag to detect faulted address without update of PT entries */
	kvm_clear_request(KVM_REQ_ADDR_FLUSH, vcpu);

	try = 0;
	retry = 0;
	do {
		pfres = mmu_pt_page_fault(vcpu, address, error_code,
					  false, &gfn, &pfn);
		if (unlikely(pfres == PFRES_ENOSPC))
			break;
		if (page_boundary) {
			int pfres_hi;
			e2k_addr_t address_hi;
			/*
			 * If address points tp page boundary, then
			 * handle next page
			 */
			address_hi = PAGE_ALIGN(address);
			pfres_hi = mmu_pt_page_fault(vcpu, address_hi, error_code,
						     false, &gfn, &pfn);

			if (unlikely(pfres == PFRES_ENOSPC))
				break;
			if (pfres == PFRES_ERR || pfres_hi == PFRES_ERR)
				pfres = PFRES_ERR;
			else if (pfres == PFRES_RETRY ||
					pfres_hi == PFRES_RETRY)
				pfres = PFRES_RETRY;
			else if (pfres == PFRES_INJECTED ||
					pfres_hi == PFRES_INJECTED)
				pfres = PFRES_INJECTED;
			else if (pfres == PFRES_DONT_INJECT ||
					pfres_hi == PFRES_DONT_INJECT)
				pfres = PFRES_DONT_INJECT;
			else if (pfres == PFRES_WRITE_TRACK ||
					pfres_hi == PFRES_WRITE_TRACK)
				pfres = PFRES_WRITE_TRACK;
			else
				pfres = PFRES_NO_ERR;
		}

		if (likely(pfres != PFRES_RETRY))
			break;
		if (!mu_state->may_be_retried) {
			/* cannot be retried */
			break;
		}
		retry++;
		try++;
#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
		if ((try & 0xfff) == 0) {
			pr_err("%s() too many retries %ld : count is %ld "
				"seq from %ld to %ld\n",
				__func__, try, vcpu->kvm->mmu_notifier_count,
				mu_state->notifier_seq, vcpu->kvm->mmu_notifier_seq);
		}
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */
		if (retry >= PF_TRIES_MAX_NUM) {
			kvm_mmu_notifier_wait(vcpu->kvm, mu_state->notifier_seq);
			retry = 0;
		}
	} while (true);

	DebugNONP("mmu.page_fault() returned %d\n", pfres);
	if (pfres == PFRES_NO_ERR) {
		r = 0;
		goto out;	/* fault handled, but need recover */
	} else if (pfres == PFRES_INJECTED) {
		r = inject_data_page_fault(vcpu, regs, tcellar);
		goto out;	/* fault injected to guest */
	} else if (pfres == PFRES_DONT_INJECT) {
		r = 3;
		goto out;	/* fault cannot be injected to guest */
	} else if (pfres == PFRES_ENOSPC) {
		/* no space to allocate SPT: fault cannot be handled */
		r = -ENOSPC;
		goto out;
	}
	if (pfres != PFRES_WRITE_TRACK) {
		/* error detected while page fault handling */
		r = -EFAULT;
		goto out;
	}
	if ((error_code & PFERR_WAIT_LOCK_MASK) &&
				(error_code & PFERR_WRITE_MASK)) {
		return reexecute_load_and_wait_page_fault(vcpu, tcellar, gfn,
							regs);
	}

	/* fault handled but guest PT is protected at shadow PT of host */
	/* so it need convert guest address to host HPA and */
	/* recovery based on not protected host address */
	gpa = gfn_to_gpa(gfn);
	gpa |= (address & ~PAGE_MASK);
	if (likely(bytes == sizeof(pgprot_t))) {
		/*
		 * TODO: Flush translation in gva cache in case of
		 * all levels of gpt are write-protected
		 */
		/* highly likely it is update of protected PT entry */
		r = write_to_guest_pt_phys(vcpu, gpa,
				(pgprot_t *)&tcellar->data, bytes);
	} else {
		/* it cannot be pte or other PT levels entries and gfn */
		/* should be unprotected while zeroing PT entry pointed to */
		hva = kvm_vcpu_gfn_to_hva(vcpu, gfn);
		if (kvm_is_error_hva(hva)) {
			pr_err("%s(): could not convert gfn 0x%llx to hva\n",
				__func__, gfn);
			r = -EFAULT;
			goto out;
		}
		hva |= (gpa & ~PAGE_MASK);
		tcellar->address = hva;
		tcellar->is_hva = 1;
		E2K_LMS_HALT_OK;
		pr_err("%s(): guest %s : protected address 0x%lx size %d, "
			"will be reexecuted on gpa 0x%llx hva 0x%lx\n",
			__func__,
			(store) ? "store" : "load", address, bytes, gpa, hva);
		r = 0;	/* fault handled, but need recover based on HVA */
	}

out:
	if (KVM_TEST_RECOVERY_FAULTED(vcpu) && r == 0) {
		provide_jump_to_recovery_point(vcpu, regs, tcellar);
	}
	if (kvm_check_request(KVM_REQ_ADDR_FLUSH, vcpu) &&
				error_code & PFERR_ILLEGAL_PAGE_MASK) {
		/*
		 * The page fault type was illegal page, but old spte was not
		 * changed while fault handling. Probably it need flush TLB
		 * for faulted address to clear PT level entries, which masked
		 * the new translation path that leeds to illegal page for
		 * valid & present virtual address and its translation
		 */
		host_local_flush_tlb_range_and_pgtables(pv_vcpu_get_gmm(vcpu),
			address, (page_boundary) ? address + PAGE_SIZE : address);
	} else if (nonpaging) {
		/* illegal PTDs/PTE can be at TLB, flush them */
		host_local_flush_tlb_range_and_pgtables(pv_vcpu_get_gmm(vcpu),
			address, (page_boundary) ? address + PAGE_SIZE : address);
	}

	return r;
}
EXPORT_SYMBOL_GPL(kvm_pv_mmu_page_fault);

int kvm_pv_mmu_instr_page_fault(struct kvm_vcpu *vcpu,
				struct pt_regs *regs, tc_fault_type_t ftype,
				const int async_instr)
{
	e2k_addr_t address, pf_address;
	gfn_t gfn;
	u32 error_code = PFERR_PT_FAULT_MASK;
	bool nonpaging = !is_paging(vcpu);
	intc_mu_state_t *mu_state;
	int instr_num = 1, instrs, try, retry;
	int pfres, r;

	if (!async_instr) {
		e2k_tir_lo_t tir_lo;
		tir_lo.TIR_lo_reg = regs->trap->TIR_lo;
		address = tir_lo.TIR_lo_ip;
	} else {
		address = AS_STRUCT(regs->ctpr2).ta_base;
	}
	pf_address = address;

	DebugNONP("started for GVA 0x%lx\n", address);

	mu_state = get_intc_mu_state(vcpu);
	mu_state->may_be_retried = true;
	mu_state->ignore_notifier = false;

	if (unlikely(address >= NATIVE_TASK_SIZE)) {
		/* IP from host virtual space range, so pass the fault */
		/* to guest, let the guest itself handle what to do */
		if (!async_instr) {
			inject_instr_page_fault(vcpu, regs, address);
		} else {
			inject_ainstr_page_fault(vcpu, regs, address);
		}
		r = 2;
		goto out;	/* fault injected to guest */
	}

	regs->is_guest_user = is_guest_user_gva(address) && !nonpaging;
	if (regs->is_guest_user)
		error_code |= PFERR_USER_ADDR_MASK;

	if (nonpaging) {
		address = nonpaging_gva_to_gpa(vcpu, address, ACC_ALL, NULL,
						NULL);
		pf_address = address;
		if (!kvm_is_visible_gfn(vcpu->kvm, gpa_to_gfn(address))) {
			pr_err("%s(): address 0x%lx is not guest valid "
				"physical address\n",
				__func__, address);
			r = -EFAULT;
			goto out;
		}
	}

	if (likely(AS(ftype).page_miss)) {
		error_code |= PFERR_NOT_PRESENT_MASK | PFERR_INSTR_FAULT_MASK;
	} else if (AS(ftype).illegal_page) {
		error_code |= PFERR_NOT_PRESENT_MASK | PFERR_INSTR_PROT_MASK |
				PFERR_ILLEGAL_PAGE_MASK;
	}

	if (!async_instr && ((address & PAGE_MASK) !=
			((address + E2K_INSTR_MAX_SIZE - 1) & PAGE_MASK))) {
		if (!nonpaging) {
			instr_num++;
		} else if (kvm_is_visible_gfn(vcpu->kvm,
				gpa_to_gfn(address + E2K_INSTR_MAX_SIZE - 1))) {
			instr_num++;
		}
	}

	/* clear flag to detect faulted address without update of PT entries */
	kvm_clear_request(KVM_REQ_ADDR_FLUSH, vcpu);

	instrs = instr_num;
	do {
		try = 0;
		retry = 0;
		do {
			pfres = mmu_pt_page_fault(vcpu, address, error_code,
						  false, &gfn, NULL);
			if (likely(pfres != PFRES_RETRY))
				break;
			if (!mu_state->may_be_retried) {
				/* cannot be retried */
				break;
			}
			try++;
			retry++;
			if (retry >= PF_TRIES_MAX_NUM) {
				kvm_mmu_notifier_wait(vcpu->kvm,
						      mu_state->notifier_seq);
				retry = 0;
			}
		} while (true);

		if (pfres == PFRES_INJECTED)
			break;
		if (unlikely(pfres == PFRES_ENOSPC))
			break;
		address = (address & PAGE_MASK) + PAGE_SIZE;
	} while (--instrs, instrs > 0);


	DebugNONP("mmu.page_fault() returned %d\n", pfres);
	if (pfres == PFRES_NO_ERR) {
		r = 0;
		goto out;	/* fault handled */
	} else if (pfres == PFRES_INJECTED) {
		if (!async_instr) {
			inject_instr_page_fault(vcpu, regs, address);
		} else {
			inject_ainstr_page_fault(vcpu, regs, address);
		}
		r = 2;
		goto out;	/* fault injected to guest */
	} else if (pfres == PFRES_ENOSPC) {
		/* no space to allocate SPT: fault cannot be handled */
		r = -ENOSPC;
		goto out;
	}
	/* error detected while page fault handling */
	r = EFAULT;

out:
	if (r < 0)
		/* error detected while page fault handling */
		return r;

	DebugNONP("mmu.page_fault() returned %d\n", r);
	if (kvm_check_request(KVM_REQ_ADDR_FLUSH, vcpu) &&
				error_code & PFERR_ILLEGAL_PAGE_MASK) {
		/*
		 * The page fault type was illegal page, but old spte was not
		 * changed while fault handling. Probably it need flush TLB
		 * for faulted address to clear PT level entries, which masked
		 * the new translation path that leeds to illegal page for
		 * valid & present virtual address and its translation
		 */
		host_local_flush_tlb_range_and_pgtables(pv_vcpu_get_gmm(vcpu),
			pf_address, address);
	} else if (nonpaging) {
		/* illegal PTDs/PTE can be at TLB, flush them */
		host_local_flush_tlb_range_and_pgtables(pv_vcpu_get_gmm(vcpu),
			pf_address, address);
	}
	return r;
}

int kvm_pv_mmu_aau_page_fault(struct kvm_vcpu *vcpu, struct pt_regs *regs,
		e2k_addr_t address, tc_cond_t cond, unsigned int aa_no)
{
	u32 error_code = PFERR_PT_FAULT_MASK;
	bool store;
	bool nonpaging = !is_paging(vcpu);
	tc_opcode_t opcode;
	kvm_pfn_t pfn;
	gfn_t gfn;
	int bytes;
	intc_mu_state_t *mu_state;
	int r, pfres, try, retry;

	AW(opcode) = AS(cond).opcode;
	E2K_KVM_BUG_ON(AS(opcode).fmt == 0 || AS(opcode).fmt == 6);
	bytes = tc_cond_to_size(cond);
	error_code = PFRES_SET_ACCESS_SIZE(error_code, bytes);
	DebugAAUPF("page fault on guest address 0x%lx aa#%d\n",
		address, aa_no);

	E2K_KVM_BUG_ON(nonpaging);
	E2K_KVM_BUG_ON(regs->trap == NULL);

	if (address >= NATIVE_TASK_SIZE) {
		/* address from host page space range, so pass the fault */
		/* to guest, let the guest itself handle whaut to do */
		inject_aau_page_fault(vcpu, regs, aa_no);
		r = 2;
		goto out;	/* fault injected to guest */
	}

	regs->is_guest_user = is_guest_user_gva(address);
	if (regs->is_guest_user)
		error_code |= PFERR_USER_ADDR_MASK;

	error_code |= (PFERR_NOT_PRESENT_MASK | PFERR_FAPB_MASK);
	store = tc_cond_is_store(cond, machine.native_iset_ver);
	if (store) {
		error_code |= PFERR_WRITE_MASK;
	}
	error_code |= PFERR_USER_MASK;
	if (AS(cond).spec) {
		error_code |= PFERR_SPEC_MASK;
		DebugAAUPF("speculative operation\n");
	}
	/* do not inject trap to guest to recover faulted request */
	error_code |= PFERR_DONT_RECOVER_MASK;

	DebugAAUPF("page miss fault type on %s\n",
		(store) ? "store" : "load");

	mu_state = get_intc_mu_state(vcpu);
	mu_state->may_be_retried = true;
	mu_state->ignore_notifier = false;

	try = 0;
	retry = 0;
	do {
		pfres = mmu_pt_page_fault(vcpu, address, error_code,
					  false, &gfn, &pfn);
		if (likely(pfres != PFRES_RETRY))
			break;
		if (!mu_state->may_be_retried) {
			/* cannot be retried */
			break;
		}
		try++;
		retry++;
		if (retry >= PF_TRIES_MAX_NUM) {
			kvm_mmu_notifier_wait(vcpu->kvm, mu_state->notifier_seq);
			retry = 0;
		}
	} while (true);

	DebugAAUPF("mmu.page_fault() returned %d\n", pfres);
	if (pfres == PFRES_NO_ERR) {
		r = 0;
		goto out;	/* fault handled */
	} else if (pfres == PFRES_INJECTED) {
		inject_aau_page_fault(vcpu, regs, aa_no);
		r = 2;
		goto out;	/* fault injected to guest */
	} else if (pfres == PFRES_ENOSPC) {
		/* no space to allocate SPT: fault cannot be handled */
		r = -ENOSPC;
		goto out;
	} else {
		/* error detected while page fault handling */
		r = -EFAULT;
		goto out;
	}

out:
	if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu)) {
		DebugSPF("it need flush TLB, so flushing\n");
	}

	return r;
}
EXPORT_SYMBOL_GPL(kvm_pv_mmu_aau_page_fault);

pgprot_t *kvm_hva_to_pte(e2k_addr_t address)
{
	struct vm_area_struct *vma;
	pte_t *pte;

	mmap_read_lock(current->mm);

	vma = find_vma(current->mm, address);
	if (vma == NULL) {
		pr_err("%s(): Could not find VMA structure of host virtual "
			"address 0x%lx to map guest physical memory\n",
			__func__, address);
		goto failed;
	}
	pte = get_user_address_pte(vma, address);

	mmap_read_unlock(current->mm);

	return (pgprot_t *)pte;

failed:
	mmap_read_unlock(current->mm);
	return NULL;
}

int kvm_pv_mmu_pt_atomic_update(struct kvm_vcpu *vcpu, int gmmid_nr,
		gpa_t gpa, void __user *old_gpt,
		pt_atomic_op_t atomic_op, unsigned long prot_mask)
{
	gfn_t gfn;
	struct page *page = NULL;
	struct gmm_struct *gmm;
	pgprot_t old_pt;
	pgprot_t new_pt;
	char *kaddr;
	unsigned long flags = 0;
	int ret;

	DebugPTE("started for guest PT GPA 0x%llx\n", gpa);
	if (vcpu->arch.is_hv) {
		pr_warn_once("%s(): MMU is hardware virtualized, so this "
			"call/hypercall can be deleted from guest\n",
			__func__);
	}

	gfn = gpa_to_gfn(gpa);
	DebugPTE("GPA 0x%llx converted to GFN 0x%llx\n",
		gpa, gfn);

	page = kvm_vcpu_gfn_to_page(vcpu, gfn);
	if (is_error_page(page)) {
		pr_err("%s(): could not GPA 0x%llx convert to host page\n",
			__func__, gpa);
		ret = -EFAULT;
		goto failed;
	}

	kaddr = kmap_atomic(page);
	kaddr += offset_in_page(gpa);
	DebugPTE("GPA 0x%llx converted to host addr 0x%lx\n",
		gpa, kaddr);

	switch (atomic_op) {
	case ATOMIC_GET_AND_XCHG:
		pgprot_val(old_pt) = native_pt_get_and_xchg_atomic(prot_mask,
							(pgprotval_t *)kaddr);
		pgprot_val(new_pt) = prot_mask;
		if (mmu_pt_kvm_is_thp_gpmd_invalidate(vcpu, old_pt, new_pt)) {
			/* probably it is invalidate of huge PT entry */
			flags |= THP_INVALIDATE_WR_TRACK;
		}
		break;
	case ATOMIC_GET_AND_CLEAR:
		pgprot_val(old_pt) =
			native_pt_get_and_clear_atomic((pgprotval_t *)kaddr);
		pgprot_val(new_pt) = pgprot_val(old_pt) & _PAGE_INIT_VALID;
		break;
	case ATOMIC_SET_WRPROTECT:
		pgprot_val(old_pt) =
			native_pt_set_wrprotect_atomic((pgprotval_t *)kaddr);
		pgprot_val(new_pt) = pgprot_val(*(pgprot_t *)kaddr);
		break;
	case ATOMIC_TEST_AND_CLEAR_YOUNG:
		pgprot_val(old_pt) =
			native_pt_clear_young_atomic((pgprotval_t *)kaddr);
		pgprot_val(new_pt) = pgprot_val(*(pgprot_t *)kaddr);
		break;
	case ATOMIC_TEST_AND_CLEAR_RELAXED:
		pgprot_val(old_pt) = native_pt_clear_relaxed_atomic(prot_mask,
							(pgprotval_t *)kaddr);
		pgprot_val(new_pt) = pgprot_val(*(pgprot_t *)kaddr);
		break;
	default:
		pr_err("%s(): invalid type %d of atomic PT modification\n",
			__func__, atomic_op);
		ret = -ENOSYS;
		goto failed_unmap;
	}

	kunmap_atomic(kaddr);
	kvm_release_page_dirty(page);
	page = NULL;
	DebugPTE("old pt %px == 0x%lx, new 0x%lx\n",
		kaddr, pgprot_val(old_pt), pgprot_val(new_pt));

	trace_gpte_atomic_update(vcpu, pgprot_val(old_pt), pgprot_val(new_pt),
				 gmmid_nr, atomic_op, gpa);

	kvm_vcpu_mark_page_dirty(vcpu, gfn);

	if (likely(gmmid_nr >= 0)) {
		if (likely(gmmid_nr != pv_vcpu_get_init_gmm(vcpu)->nid.nr)) {
			gmm = kvm_find_gmmid(&vcpu->kvm->arch.gmmid_table,
						gmmid_nr);
			if (gmm == NULL) {
				pr_err("%s(): could not find gmm #%d\n",
					__func__, gmmid_nr);
				ret = -EINVAL;
				goto failed_unmap;
			}
		} else {
			/* gmm is kernel thread init_gmm */
			gmm = pv_vcpu_get_init_gmm(vcpu);
		}
		mmu_pt_atomic_update_shadow_pt(vcpu, gmm, gpa,
				pgprot_val(old_pt), pgprot_val(new_pt), flags);
	} else {
		/* gmm has been already released, ignore */
		;
	}

	ret = kvm_vcpu_copy_to_guest(vcpu, old_gpt, &old_pt,
					sizeof(pgprot_t));
	if (ret != 0)
		pr_err("%s(): could not copy old pte to guest, error %d\n",
			__func__, ret);
	DebugPTE("return to guest old pt %px == 0x%lx\n",
		old_gpt, pgprot_val(old_pt));

failed_unmap:
	if (page != NULL) {
		kunmap_atomic(kaddr);
		kvm_release_page_dirty(page);
		page = NULL;
	}
failed:
	return ret;
}

int kvm_pv_switch_guest_mm(struct kvm_vcpu *vcpu,
		int gpid_nr, int gmmid_nr, gpa_t u_phys_ptb)
{
	gthread_info_t *cur_gti = current_thread_info()->gthread_info;
	gthread_info_t *next_gti;
	struct gmm_struct *init_gmm = pv_vcpu_get_init_gmm(vcpu);
	struct gmm_struct *next_gmm;
	bool migrated = false;
	hpa_t root;
	int ret;

	DebugKVMSWH("started to switch from current GPID #%d to #%d, guest "
		"root PT at 0x%llx\n",
		cur_gti->gpid->nid.nr, gpid_nr, u_phys_ptb);

	next_gti = kvm_get_guest_thread_info(vcpu->kvm, gpid_nr);
	if (next_gti == NULL) {
		/* FIXME: we should kill guest kernel, but first it needs */
		/* to  switch to host kernel stacks */
		panic("%s(): could not find guest thread GPID #%d\n",
			__func__, gpid_nr);
	}
	if (next_gti->vcpu == NULL) {
		DebugKVMSWH("next thread GPID #%d starts on VCPU #%d "
			"first time\n",
			gpid_nr, vcpu->vcpu_id);
		next_gti->vcpu = vcpu;
	} else if (next_gti->vcpu != vcpu) {
		DebugKVMSWH("next thread GPID #%d migrates from current GPID "
			"#%d VCPU #%d to VCPU #%d\n",
			gpid_nr, cur_gti->gpid->nid.nr,
			next_gti->vcpu->vcpu_id, vcpu->vcpu_id);
		migrated = true;
		next_gti->vcpu = vcpu;
	} else {
		DebugKVMSWH("next thread GPID #%d continues running "
			"on VCPU #%d\n",
			gpid_nr, vcpu->vcpu_id);
	}
	if (gmmid_nr != init_gmm->nid.nr) {
		next_gmm = kvm_find_gmmid(&vcpu->kvm->arch.gmmid_table,
						gmmid_nr);
		if (next_gmm == NULL) {
			/* FIXME: we should kill guest kernel, but first */
			/* it needs to  switch to host kernel stacks */
			panic("%s(): could not find new host agent #%d of "
				"guest mm\n",
				__func__, gmmid_nr);
		}
	} else {
		/* new process is kernel thread */
		pr_err("%s(): switch to guest kernel init mm #%d\n",
			__func__, gmmid_nr);
		next_gmm = NULL;
	}

	E2K_KVM_BUG_ON(next_gmm == NULL);

	if (unlikely(!next_gmm->pt_synced)) {
		/* first swotch to new guest mm, so it need activate */
		ret = kvm_pv_activate_guest_mm(vcpu, next_gmm, u_phys_ptb);
		goto done;
	}

	/* switch to the next already activated guest mm */
	if (is_shadow_paging(vcpu)) {
		E2K_KVM_BUG_ON(!VALID_PAGE(next_gmm->root_hpa));
		root = mmu_pv_switch_spt_u_pptb(vcpu, next_gmm, u_phys_ptb);

		E2K_KVM_BUG_ON(!VALID_PAGE(root) || root != next_gmm->root_hpa);
		if (ERROR_PAGE(root)) {
			ret = PAGE_TO_ERROR(root);
		} else {
			ret = 0;
		}
		E2K_KVM_BUG_ON(true);
	}
	ret = 0;

done:
	if (ret >= 0) {
		current_thread_info()->gthread_info = next_gti;
		E2K_KVM_BUG_ON(ret > 0 && ret != gmmid_nr);
		ret = 0;
	}

	return ret;
}
