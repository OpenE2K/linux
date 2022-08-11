
/*
 * VCPU MMU  paravirtualization
 *
 * Based on x86 code and ideas.
 * Copyright (c) 2014-2018, MCST.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
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
#define	PF_RETRIES_MAX_NUM	1
/* common number of one try and retries to handle page fault */
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
	copy_kernel_pgd_range(root, cpu_kernel_root_pt);
}

void release_gmm_root_pt(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	hpa_t gmm_root, root_hpa;

	if (vcpu == NULL)
		vcpu = native_current_thread_info()->vcpu;
	if (vcpu == NULL)
		return;

	gmm_root = gmm->root_hpa;
	KVM_BUG_ON(!VALID_PAGE(gmm_root));

	root_hpa = kvm_get_space_type_guest_u_root(vcpu);
	KVM_BUG_ON(gmm_root == root_hpa);

	DebugFREE("will release gmm #%d shodow PT from root 0x%llx\n",
		gmm->nid.nr, gmm_root);

	mmu_release_spt_root(vcpu, gmm_root);
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

void kvm_arch_free_memslot(struct kvm *kvm, struct kvm_memory_slot *free,
				struct kvm_memory_slot *dont)
{
	const pt_struct_t *pt_struct = kvm_get_mmu_host_pt_struct(kvm);
	user_area_t *guest_area;
	int i;
	unsigned long base_gfn;

	DebugKVMSH("started for memory slot %px\n", free);
	base_gfn = free->base_gfn;
	DebugKVMVM("memory slot: base gfn 0x%lx, pages 0x%lx\n",
		base_gfn, free->npages);

	if (dont == NULL) {
		DebugKVMVM("started to free slot ID %d RMAP %px\n",
			free->id, free->arch.rmap);
	}
	guest_area = free->arch.guest_areas.area;
	if (guest_area != NULL)
		kvm_arch_free_memory_region(kvm, free);
	KVM_BUG_ON(free->arch.guest_areas.area != NULL);
	for (i = 0; i < KVM_NR_PAGE_SIZES; ++i) {
		const pt_level_t *pt_level;
		int level = i + 1;

		pt_level = &pt_struct->levels[level];
		if (!dont || free->arch.rmap[i] != dont->arch.rmap[i]) {
			kvfree(free->arch.rmap[i]);
			DebugKVMVM("free slot ID %d RMAP %px\n",
				free->id, free->arch.rmap);
			free->arch.rmap[i] = NULL;
		}
		if (!is_huge_pt_level(pt_level))
			/* the page table level has not huge pages */
			continue;

		if (!dont || free->arch.lpage_info[i - 1] !=
					dont->arch.lpage_info[i - 1]) {
			kvfree(free->arch.lpage_info[i - 1]);
			DebugKVMVM("free slot ID %d huge page INFO %px\n",
				free->id, free->arch.lpage_info[i - 1]);
			free->arch.lpage_info[i - 1] = NULL;
		}
	}

	kvm_page_track_free_memslot(free, dont);
}

int kvm_arch_create_memslot(struct kvm *kvm, struct kvm_memory_slot *slot,
				unsigned long npages)
{
	const pt_struct_t *pt_struct = kvm_get_mmu_host_pt_struct(kvm);
	int i;
	gfn_t bgfn = slot->base_gfn;

	DebugKVM("started for slot ID #%d base gfn 0x%llx pages 0x%lx "
		"user addr 0x%lx\n",
		slot->id, bgfn, npages, slot->userspace_addr);
	for (i = 0; i < KVM_NR_PAGE_SIZES; ++i) {
		const pt_level_t *pt_level;
		kvm_lpage_info_t *linfo;
		unsigned long ugfn;
		int lpages;
		int disallow_lpages = 0;
		int level = i + 1;

		if (level > pt_struct->levels_num)
			/* no more levels */
			break;

		pt_level = &pt_struct->levels[level];
		if (!is_page_pt_level(pt_level) &&
				!is_huge_pt_level(pt_level))
			/* nothing pages on the level */
			continue;

		lpages = gfn_to_index(bgfn + npages - 1, bgfn, pt_level) + 1;

		slot->arch.rmap[i] =
			kvzalloc(lpages * sizeof(*slot->arch.rmap[i]),
					GFP_KERNEL);
		if (!slot->arch.rmap[i])
			goto out_free;
		DebugKVM("created RMAP %px to map 0x%x pages on PT level #%d\n",
			slot->arch.rmap[i], lpages, level);

		if (!is_huge_pt_level(pt_level))
			/* the page table level has not huge pages */
			continue;

		linfo = kvzalloc(lpages * sizeof(*linfo), GFP_KERNEL);
		if (!linfo)
			goto out_free;

		slot->arch.lpage_info[i - 1] = linfo;

		if (bgfn & (KVM_PT_LEVEL_PAGES_PER_HPAGE(pt_level) - 1)) {
			linfo[0].disallow_lpage = 1;
			disallow_lpages++;
		}
		if ((bgfn + npages) &
				(KVM_PT_LEVEL_PAGES_PER_HPAGE(pt_level) - 1)) {
			linfo[lpages - 1].disallow_lpage = 1;
			disallow_lpages++;
		}
		DebugKVM("created huge pages INFO %px to map 0x%x pages "
			"on PT level #%d\n",
			slot->arch.lpage_info[i - 1], lpages, level);
		ugfn = slot->userspace_addr >> PAGE_SHIFT;
		/*
		 * If the gfn and userspace address are not aligned wrt each
		 * other, or if explicitly asked to, disable large page
		 * support for this slot
		 */
		if ((bgfn ^ ugfn) &
			(KVM_PT_LEVEL_PAGES_PER_HPAGE(pt_level) - 1) ||
				!kvm_largepages_enabled()) {
			unsigned long j;

			for (j = 0; j < lpages; ++j)
				linfo[j].disallow_lpage = 1;
				disallow_lpages++;
		}
		if (disallow_lpages != 0) {
			DebugKVM("disallowed %d huge pages on PT level #%d\n",
				disallow_lpages, level);
		}
	}

	if (kvm_page_track_create_memslot(slot, npages))
		goto out_free;

	return 0;

out_free:
	for (i = 0; i < KVM_NR_PAGE_SIZES; ++i) {
		const pt_level_t *pt_level;
		int level = i + 1;

		pt_level = &pt_struct->levels[level];
		kvfree(slot->arch.rmap[i]);
		slot->arch.rmap[i] = NULL;
		if (!is_huge_pt_level(pt_level))
			/* the page table level has not huge pages */
			continue;

		kvfree(slot->arch.lpage_info[i - 1]);
		slot->arch.lpage_info[i - 1] = NULL;
	}
	return -ENOMEM;
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
			const struct kvm_memory_slot *old,
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
		KVM_BUG_ON(address >= NATIVE_TASK_SIZE);
		return address;
	}
	gpa = e2k_gva_to_gpa(vcpu, address, ACC_WRITE_MASK, NULL);
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
	KVM_BUG_ON(!IS_E2K_INVALID_PAGE(gmm->root_hpa));
	ret = kvm_create_shadow_user_pt(vcpu, gmm, u_phys_ptb);
	if (ret) {
		pr_err("%s(): could not create initial shadow PT or "
			"sync all guest pages, error %d\n",
			__func__, ret);
		return ret;
	}

	KVM_BUG_ON(!VALID_PAGE(kvm_get_space_type_spt_u_root(vcpu)));

	return 0;
}

static int kvm_pv_mmu_prepare_u_gmm(struct kvm_vcpu *vcpu,
			gmm_struct_t *gmm, gpa_t u_phys_ptb)
{
	int ret;

	/* It need create new shadow PT */
	KVM_BUG_ON(!IS_E2K_INVALID_PAGE(gmm->root_hpa));
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

	KVM_BUG_ON(!VALID_PAGE(gmm->root_hpa));

	return 0;
}

static int vcpu_init_pv_mmu_state(struct kvm_vcpu *vcpu,
				  vcpu_gmmu_info_t *gmmu_info)
{
	gpa_t tc_gpa;
	hpa_t tc_hpa, root;
	e2k_core_mode_t core_mode;
	bool updated;
	int ret;

	tc_gpa = gmmu_info->trap_cellar;
	ret = vcpu_write_trap_point_mmu_reg(vcpu, tc_gpa, &tc_hpa);
	if (ret != 0)
		goto error;

	ret = vcpu_write_mmu_pid_reg(vcpu, gmmu_info->pid);
	if (ret != 0)
		goto error_tc;

	if (gmmu_info->sep_virt_space) {
		set_sep_virt_spaces(vcpu);
		ret = vcpu_write_mmu_os_pptb_reg(vcpu, gmmu_info->os_pptb,
						 &updated, &root);
		if (ret != 0)
			goto error_tc;

		ret = vcpu_write_mmu_os_vptb_reg(vcpu, gmmu_info->os_vptb);
		if (ret != 0)
			goto error_tc;

		ret = vcpu_write_mmu_os_vab_reg(vcpu, gmmu_info->os_vab);
		if (ret != 0)
			goto error_tc;
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
		goto error_tc;

	ret = vcpu_write_mmu_u_vptb_reg(vcpu, gmmu_info->u_vptb);
	if (ret != 0)
		goto error_tc;

	ret = vcpu_write_mmu_cr_reg(vcpu, gmmu_info->mmu_cr);
	if (ret != 0)
		goto error_tc;

	kvm_mmu_set_init_gmm_root(vcpu, E2K_INVALID_PAGE);

	return 0;

error_tc:
	kvm_vcpu_release_trap_cellar(vcpu);
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
	if (gmmu_info.opcode & INIT_STATE_GMMU_OPC) {
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

	KVM_BUG_ON(!is_shadow_paging(vcpu));
	KVM_BUG_ON(vcpu->arch.is_hv);

	gti = pv_vcpu_get_gti(vcpu);
	DebugAGMM("proces #%d the new gmm #%d\n",
		gti->gpid->nid.nr, new_gmm->nid.nr);

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

	if (is_shadow_paging(vcpu)) {
		ret = kvm_pv_mmu_prepare_u_gmm(vcpu, new_gmm, u_phys_ptb);
		if (ret != 0)
			goto failed;
		if (vcpu->arch.is_hv) {
			KVM_BUG_ON(true);
		} else if (vcpu->arch.is_pv) {
			/* new gmm will setup as active while switch to */
			;
		} else {
			KVM_BUG_ON(true);
		}
	} else {
		KVM_BUG_ON(true);
	}

	KVM_BUG_ON(!new_gmm->pt_synced);

	return 0;

failed:
	return ret;
}

static void set_pv_vcpu_mu_events_num(struct kvm_vcpu *vcpu, int events_num)
{
	KVM_BUG_ON(events_num < get_vcpu_mu_events_num(vcpu));
	set_vcpu_mu_events_num(vcpu, events_num);
}

static void set_pv_vcpu_cur_mu_event_no(struct kvm_vcpu *vcpu, int event_no)
{
	int events_num = get_vcpu_mu_events_num(vcpu);

	KVM_BUG_ON(events_num >= 0 && event_no > events_num);
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
	kvm_page_track_write(vcpu, NULL, gpa, (const void *)gpte, bytes);

	return 1;	/* fault handled and recovered */
}

int kvm_guest_addr_to_host(void **addr)
{
	struct kvm_vcpu *vcpu = current_thread_info()->vcpu;
	unsigned long hva;
	kvm_arch_exception_t exception;

	KVM_BUG_ON(vcpu == NULL || !vcpu->arch.is_pv);

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

void *kvm_guest_ptr_to_host_ptr(void *guest_ptr, int size, bool need_inject)
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
	KVM_BUG_ON(vcpu == NULL || vcpu->arch.is_hv);

	hva = kvm_vcpu_gva_to_hva(vcpu, (e2k_addr_t)guest_ptr,
				false, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, "
			"inject page fault to guest\n", guest_ptr);
		if (need_inject)
			kvm_vcpu_inject_page_fault(vcpu, (void *)guest_ptr,
					&exception);
		return ERR_PTR(-EAGAIN);
	}

	return (void *)hva;
}

static void inject_data_page_fault(struct kvm_vcpu *vcpu, pt_regs_t *regs,
					trap_cellar_t *tcellar)
{
	kvm_inject_pv_vcpu_tc_entry(vcpu, tcellar);
	kvm_inject_data_page_exc(vcpu, regs);
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
	u32 error_code = 0;
	bool nonpaging = !is_paging(vcpu);
	kvm_pfn_t pfn;
	gfn_t gfn;
	gpa_t gpa;
	e2k_addr_t hva;
	int bytes;
	intc_mu_state_t *mu_state;
	int r, pfres, try, fmt;

	address = tcellar->address;
	cond = tcellar->condition;

	AW(ftype) = AS(cond).fault_type;
	AW(opcode) = AS(cond).opcode;
	fmt = TC_COND_FMT_FULL(cond);
	KVM_BUG_ON(AS(opcode).fmt == 0 || AS(opcode).fmt == 6);
	bytes = tc_cond_to_size(cond);
	PFRES_SET_ACCESS_SIZE(error_code, bytes);
	mas = AS(cond).mas;
	store = tc_cond_is_store(cond, machine.native_iset_ver);
	DebugNONP("page fault on guest address 0x%lx fault type 0x%x\n",
		address, AW(ftype));

	KVM_BUG_ON(regs->trap == NULL);
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
		inject_data_page_fault(vcpu, regs, tcellar);
		r = 2;
		goto out;	/* fault injected to guest */
	}

	if (AW(ftype) == 0) {
		error_code |= PFERR_NOT_PRESENT_MASK;
		DebugSPF("empty page fault type\n");
	} else if (AS(ftype).page_miss) {
		error_code |= PFERR_NOT_PRESENT_MASK;
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

	if (AS(ftype).nwrite_page) {
		error_code &= ~PFERR_NOT_PRESENT_MASK;
		error_code |= PFERR_PRESENT_MASK | PFERR_WRITE_MASK;
		DebugSPF("not write page fault type\n");
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

	mu_state = get_intc_mu_state(vcpu);
	mu_state->may_be_retried = true;
	mu_state->ignore_notifier = true;

	try = 0;
	do {
		pfres = vcpu->arch.mmu.page_fault(vcpu, address, error_code,
						  false, &gfn, &pfn);
		if (page_boundary) {
			int pfres_hi;
			e2k_addr_t address_hi;
			/*
			 * If address points tp page boundary, then
			 * handle next page
			 */
			address_hi = PAGE_ALIGN(address);
			pfres_hi = vcpu->arch.mmu.page_fault(vcpu, address_hi,
					error_code, false, &gfn, &pfn);

			if (pfres == PFRES_ERR || pfres_hi == PFRES_ERR)
				pfres = PFRES_ERR;
			else if (pfres == PFRES_RETRY ||
					pfres_hi == PFRES_RETRY)
				pfres = PFRES_RETRY;
			else if (pfres == PFRES_INJECTED ||
					pfres_hi == PFRES_INJECTED)
				pfres = PFRES_INJECTED;
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
		try++;
	} while (try < PF_TRIES_MAX_NUM);

	DebugNONP("mmu.page_fault() returned %d\n", pfres);
	if (pfres == PFRES_NO_ERR) {
		r = 0;
		goto out;	/* fault handled, but need recover */
	} else if (pfres == PFRES_INJECTED) {
		inject_data_page_fault(vcpu, regs, tcellar);
		r = 2;
		goto out;	/* fault injected to guest */
	}
	if (pfres != PFRES_WRITE_TRACK) {
		/* error detected while page fault handling */
		r = EFAULT;
		goto out;
	}
	if ((error_code & PFERR_WAIT_LOCK_MASK) &&
				(error_code & PFERR_WRITE_MASK)) {
		return reexecute_load_and_wait_page_fault(vcpu, tcellar, gfn,
							regs);
	}

	/* fault handled but guest PT is protected at shadow PT of host */
	/* so it need convert guest address to host HPA and */
	/* recover based on not protected host address */
	gpa = gfn_to_gpa(gfn);
	gpa |= (address & ~PAGE_MASK);
	if (likely(bytes == sizeof(pgprot_t))) {
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
		tcellar->flags |= TC_IS_HVA_FLAG;
		E2K_LMS_HALT_OK;
		pr_err("%s(): guest %s : protected address 0x%lx size %d, "
			"will be reexecuted on gpa 0x%llx hva 0x%lx\n",
			__func__,
			(store) ? "store" : "load", address, bytes, gpa, hva);
		r = 0;	/* fault handled, but need recover based on HVA */
	}

out:
	if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu)) {
		DebugSPF("it need flush TLB, so flushing\n");
		__flush_tlb_all();
	} else if (nonpaging && (AS(ftype).illegal_page || AW(ftype) == 0)) {
		/* illegal PTDs/PTE can be at TLB, flush them */
		__flush_tlb_all();
	}

	return r;
}
EXPORT_SYMBOL_GPL(kvm_pv_mmu_page_fault);

int kvm_pv_mmu_instr_page_fault(struct kvm_vcpu *vcpu,
				struct pt_regs *regs, tc_fault_type_t ftype,
				const int async_instr)
{
	e2k_addr_t address;
	gfn_t gfn;
	u32 error_code;
	bool nonpaging = !is_paging(vcpu);
	intc_mu_state_t *mu_state;
	int instr_num = 1, try;
	int pfres, r;

	if (!async_instr) {
		e2k_tir_lo_t tir_lo;
		tir_lo.TIR_lo_reg = regs->trap->TIR_lo;
		address = tir_lo.TIR_lo_ip;
	} else {
		address = AS_STRUCT(regs->ctpr2).ta_base;
	}

	DebugNONP("started for GVA 0x%lx\n", address);

	mu_state = get_intc_mu_state(vcpu);
	mu_state->may_be_retried = true;
	mu_state->ignore_notifier = true;

	if (address >= NATIVE_TASK_SIZE) {
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

	if (nonpaging) {
		address = nonpaging_gva_to_gpa(vcpu, address, ACC_ALL, NULL);

		if (!kvm_is_visible_gfn(vcpu->kvm, gpa_to_gfn(address))) {
			pr_err("%s(): address 0x%lx is not guest valid "
				"physical address\n",
				__func__, address);
			r = -EFAULT;
			goto out;
		}
	}

	error_code = 0;
	if (AS(ftype).page_miss)
		error_code |= PFERR_NOT_PRESENT_MASK | PFERR_INSTR_FAULT_MASK;
	if (AS(ftype).illegal_page)
		error_code |= PFERR_NOT_PRESENT_MASK | PFERR_INSTR_PROT_MASK;

	if (!async_instr && ((address & PAGE_MASK) !=
			((address + E2K_INSTR_MAX_SIZE - 1) & PAGE_MASK))) {
		if (!nonpaging) {
			instr_num++;
		} else if (kvm_is_visible_gfn(vcpu->kvm,
				gpa_to_gfn(address + E2K_INSTR_MAX_SIZE - 1))) {
			instr_num++;
		}
	}

	do {
		try = 0;
		do {
			pfres = vcpu->arch.mmu.page_fault(vcpu, address,
						error_code, false, &gfn, NULL);
			if (likely(pfres != PFRES_RETRY))
				break;
			if (!mu_state->may_be_retried) {
				/* cannot be retried */
				break;
			}
			try++;
		} while (try < PF_TRIES_MAX_NUM);

		if (try >= PF_TRIES_MAX_NUM)
			break;
		if (pfres == PFRES_INJECTED)
			break;
		address = (address & PAGE_MASK) + PAGE_SIZE;
	} while (--instr_num, instr_num > 0);


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
	}
	/* error detected while page fault handling */
	r = EFAULT;

out:
	if (r < 0)
		/* error detected while page fault handling */
		return r;

	DebugNONP("mmu.page_fault() returned %d\n", r);
	if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu)) {
		DebugNONP("it need flush TLB, so flushing\n");
		__flush_tlb_all();
	} else if (nonpaging && (AS(ftype).illegal_page || AW(ftype) == 0)) {
		/* illegal PTDs/PTE can be at TLB, flush them */
		__flush_tlb_all();
	}
	return r;
}

int kvm_pv_mmu_aau_page_fault(struct kvm_vcpu *vcpu, struct pt_regs *regs,
		e2k_addr_t address, tc_cond_t cond, unsigned int aa_no)
{
	u32 error_code = 0;
	bool store;
	bool nonpaging = !is_paging(vcpu);
	tc_opcode_t opcode;
	kvm_pfn_t pfn;
	gfn_t gfn;
	int bytes;
	intc_mu_state_t *mu_state;
	int r, pfres, try;

	AW(opcode) = AS(cond).opcode;
	KVM_BUG_ON(AS(opcode).fmt == 0 || AS(opcode).fmt == 6);
	bytes = tc_cond_to_size(cond);
	PFRES_SET_ACCESS_SIZE(error_code, bytes);
	DebugAAUPF("page fault on guest address 0x%lx aa#%d\n",
		address, aa_no);

	KVM_BUG_ON(nonpaging);
	KVM_BUG_ON(regs->trap == NULL);

	if (address >= NATIVE_TASK_SIZE) {
		/* address from host page space range, so pass the fault */
		/* to guest, let the guest itself handle whaut to do */
		inject_aau_page_fault(vcpu, regs, aa_no);
		r = 2;
		goto out;	/* fault injected to guest */
	}

	error_code |= (PFERR_NOT_PRESENT_MASK | PFERR_FAPB_MASK);
	store = tc_cond_is_store(cond, machine.native_iset_ver);
	if (store) {
		error_code |= PFERR_WRITE_MASK;
	}
	error_code |= PFERR_USER_MASK;
	DebugAAUPF("page miss fault type on %s\n",
		(store) ? "store" : "load");

	mu_state = get_intc_mu_state(vcpu);
	mu_state->may_be_retried = true;
	mu_state->ignore_notifier = true;

	try = 0;
	do {
		pfres = vcpu->arch.mmu.page_fault(vcpu, address, error_code,
						  false, &gfn, &pfn);
		if (likely(pfres != PFRES_RETRY))
			break;
		if (!mu_state->may_be_retried) {
			/* cannot be retried */
			break;
		}
		try++;
	} while (try < PF_TRIES_MAX_NUM);

	DebugAAUPF("mmu.page_fault() returned %d\n", pfres);
	if (pfres == PFRES_NO_ERR) {
		r = 0;
		goto out;	/* fault handled */
	} else if (pfres == PFRES_INJECTED) {
		inject_aau_page_fault(vcpu, regs, aa_no);
		r = 2;
		goto out;	/* fault injected to guest */
	} else {
		/* error detected while page fault handling */
		r = EFAULT;
		goto out;
	}

out:
	if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu)) {
		DebugSPF("it need flush TLB, so flushing\n");
		__flush_tlb_all();
	}

	return r;
}
EXPORT_SYMBOL_GPL(kvm_pv_mmu_aau_page_fault);

pgprot_t *kvm_hva_to_pte(e2k_addr_t address)
{
	struct vm_area_struct *vma;
	pte_t *pte;

	down_read(&current->mm->mmap_sem);

	vma = find_vma(current->mm, address);
	if (vma == NULL) {
		pr_err("%s(): Could not find VMA structure of host virtual "
			"address 0x%lx to map guest physical memory\n",
			__func__, address);
		goto failed;
	}
	pte = get_user_address_pte(vma, address);

	up_read(&current->mm->mmap_sem);

	return (pgprot_t *)pte;

failed:
	up_read(&current->mm->mmap_sem);
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

	kvm_vcpu_mark_page_dirty(vcpu, gfn);

	if (likely(gmmid_nr >= 0 &&
			gmmid_nr != pv_vcpu_get_init_gmm(vcpu)->nid.nr)) {
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

	kvm_page_track_write(vcpu, gmm, gpa, (const void *)&new_pt,
				sizeof(pgprot_t));

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

	KVM_BUG_ON(next_gmm == NULL);

	if (unlikely(!next_gmm->pt_synced)) {
		/* first swotch to new guest mm, so it need activate */
		ret = kvm_pv_activate_guest_mm(vcpu, next_gmm, u_phys_ptb);
		goto done;
	}

	/* switch to the next already activated guest mm */
	if (is_shadow_paging(vcpu)) {
		KVM_BUG_ON(!VALID_PAGE(next_gmm->root_hpa));
		root = mmu_pv_switch_spt_u_pptb(vcpu, next_gmm, u_phys_ptb);

		KVM_BUG_ON(!VALID_PAGE(root) || root != next_gmm->root_hpa);
		if (ERROR_PAGE(root)) {
			ret = PAGE_TO_ERROR(root);
		} else {
			ret = 0;
		}
		KVM_BUG_ON(true);
	}
	ret = 0;

done:
	if (ret >= 0) {
		current_thread_info()->gthread_info = next_gti;
		KVM_BUG_ON(ret > 0 && ret != gmmid_nr);
		ret = 0;
	}

	return ret;
}
