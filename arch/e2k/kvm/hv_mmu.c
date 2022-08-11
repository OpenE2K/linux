
/*
 * MMU hardware virtualized support
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/uaccess.h>
#include <asm/mmu_regs_types.h>
#include <asm/kvm/mmu_hv_regs_types.h>
#include <asm/kvm/mmu_hv_regs_access.h>
#include "mmu_defs.h"
#include "mmu.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_MMU_REG_MODE
#undef	DebugMMUREG
#define	DEBUG_MMU_REG_MODE	0	/* MMU register access events */
					/* debug mode */
#define	DebugMMUREG(fmt, args...)					\
({									\
	if (DEBUG_MMU_REG_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_MMU_PID_MODE
#undef	DebugMMUPID
#define	DEBUG_MMU_PID_MODE	0	/* MMU PID register access events */
					/* debug mode */
#define	DebugMMUPID(fmt, args...)					\
({									\
	if (DEBUG_MMU_PID_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_MMU_VPT_REG_MODE
#undef	DebugMMUVPT
#define	DEBUG_MMU_VPT_REG_MODE	0	/* MMU virtual PT bases */
#define	DebugMMUVPT(fmt, args...)					\
({									\
	if (DEBUG_MMU_VPT_REG_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

void kvm_vcpu_release_trap_cellar(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.mmu.tc_page == NULL)
		return;
	kvm_release_page_dirty(vcpu->arch.mmu.tc_page);
	vcpu->arch.mmu.tc_page = NULL;
	if (vcpu->arch.mmu.tc_kaddr == NULL)
		return;
	kunmap(vcpu->arch.mmu.tc_kaddr);
	vcpu->arch.mmu.tc_kaddr = NULL;
	vcpu->arch.mmu.tc_gpa = 0;
	vcpu->arch.sw_ctxt.tc_hpa = 0;
}

int vcpu_write_trap_point_mmu_reg(struct kvm_vcpu *vcpu, gpa_t tc_gpa,
					hpa_t *tc_hpap)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	gfn_t tc_gfn;
	kvm_pfn_t tc_pfn;
	hpa_t tc_hpa;
	struct page *tc_page;
	void *tc_kaddr;
	int ret;

	if (vcpu->arch.mmu.tc_page != NULL || vcpu->arch.mmu.tc_kaddr != NULL)
		/* release old trap cellar before setup new */
		kvm_vcpu_release_trap_cellar(vcpu);

	if ((tc_gpa & MMU_TRAP_POINT_MASK) != tc_gpa) {
		if ((tc_gpa & MMU_TRAP_POINT_MASK_V2) != tc_gpa) {
			pr_err("%s(): guest TRAP POINT 0x%llx is bad aligned, "
				"should be at least 0x%llx\n",
				__func__, tc_gpa, tc_gpa & MMU_TRAP_POINT_MASK);
			return -EINVAL;
		}
		pr_warn("%s(): guest TRAP POINT 0x%llx has legacy alignment\n",
			__func__, tc_gpa);
	}

	tc_gfn = gpa_to_gfn(tc_gpa);
	tc_pfn = kvm_vcpu_gfn_to_pfn(vcpu, tc_gfn);
	if (is_error_noslot_pfn(tc_pfn)) {
		pr_err("%s(): could not convert guest TRAP POINT "
			"gfn 0x%llx to host pfn\n",
			__func__, tc_gfn);
		return -EFAULT;
	}
	tc_hpa = tc_pfn << PAGE_SHIFT;
	tc_hpa += offset_in_page(tc_gpa);
	tc_page = pfn_to_page(tc_pfn);
	if (is_error_page(tc_page)) {
		pr_err("%s(): could not convert guest TRAP POINT "
			"address 0x%llx to host page\n",
			__func__, tc_gpa);
		return -EFAULT;
	}

	tc_kaddr = kmap(tc_page);
	if (tc_kaddr == NULL) {
		pr_err("%s(): could not map guest TRAP POINT page to host "
			"memory\n",
			__func__);
		ret = -ENOMEM;
		goto kmap_error;
	}
	tc_kaddr += offset_in_page(tc_gpa);

	vcpu->arch.mmu.tc_gpa = tc_gpa;
	sw_ctxt->tc_hpa = tc_hpa;
	vcpu->arch.mmu.tc_page = tc_page;
	vcpu->arch.mmu.tc_kaddr = tc_kaddr;

	DebugMMUREG("write guest TRAP POINT: host PA 0x%llx, GPA 0x%llx, "
		"mapped to host addr %px\n",
		tc_hpa, tc_gpa, tc_kaddr);

	*tc_hpap = tc_hpa;
	return 0;

kmap_error:
	kvm_release_page_dirty(tc_page);
	return ret;
}

int vcpu_write_mmu_cr_reg(struct kvm_vcpu *vcpu, mmu_reg_t mmu_cr)
{
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;
	mmu_reg_t old_mmu_cr;
	int r;

	old_mmu_cr = read_guest_MMU_CR_reg(vcpu);

	if ((old_mmu_cr & _MMU_CR_TLB_EN) == (mmu_cr & _MMU_CR_TLB_EN)) {
		/* paging mode is not changed, so can only update */
		write_guest_MMU_CR_reg(vcpu, mmu_cr);
		hw_ctxt->sh_mmu_cr = mmu_cr;
		DebugMMUREG("guest MMU_CR paging mode does not change: "
			"only update from 0x%llx to 0x%llx, tlb_en %d\n",
			old_mmu_cr, mmu_cr, !!(mmu_cr & _MMU_CR_TLB_EN));
		return 0;
	}
	if (!!(old_mmu_cr & _MMU_CR_TLB_EN) && !(mmu_cr & _MMU_CR_TLB_EN)) {
		/* paging mode is OFF */
		write_guest_MMU_CR_reg(vcpu, mmu_cr);
		hw_ctxt->sh_mmu_cr = mmu_cr;
		DebugMMUREG("guest MMU_CR paging mode is turn OFF: "
			"from 0x%llx to 0x%llx, tlb_en %d\n",
			old_mmu_cr, mmu_cr, !!(mmu_cr & _MMU_CR_TLB_EN));
		/* it need free all page tables and invalidate roots */
		/* FIXME: turn OFF is not implemented */
		pr_err("%s(): guest turns OFF paging mode: MMU_CR "
			"from 0x%llx to 0x%llx, tlb_en %d\n",
			__func__, old_mmu_cr, mmu_cr,
			!!(mmu_cr & _MMU_CR_TLB_EN));
		KVM_BUG_ON(is_paging(vcpu) && !is_tdp_paging(vcpu));
		reset_paging_flag(vcpu);
		return 0;
	}

	/* guest turns ON paging mode */
	KVM_BUG_ON(is_paging_flag(vcpu));

	if (is_tdp_paging(vcpu)) {
		r = kvm_hv_setup_tdp_paging(vcpu);
	} else if (is_shadow_paging(vcpu)) {
		if (vcpu->arch.is_hv) {
			r = kvm_hv_setup_shadow_paging(vcpu, NULL);
		} else {
			r = kvm_hv_setup_shadow_paging(vcpu,
						pv_vcpu_get_gmm(vcpu));
		}
	} else {
		KVM_BUG_ON(true);
		r = -EINVAL;
	}
	if (r != 0) {
		pr_err("%s(): could not switch guest to paging mode, "
			"error %d\n",
			__func__, r);
		return r;
	}

	write_guest_MMU_CR_reg(vcpu, mmu_cr);
	hw_ctxt->sh_mmu_cr = mmu_cr;
	DebugMMUREG("Enable guest MMU paging:\n"
		"   SH_MMU_CR: value 0x%llx\n"
		"   SH_PID:    value 0x%llx\n",
		mmu_cr, hw_ctxt->sh_pid);

	return 0;
}

int vcpu_write_mmu_pid_reg(struct kvm_vcpu *vcpu, mmu_reg_t pid)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	/* probably it is flush mm */
	kvm_mmu_sync_roots(vcpu, U_ROOT_PT_FLAG);

	mmu->pid = pid;
	write_guest_PID_reg(vcpu, pid);
	DebugMMUPID("Set MMU guest PID: 0x%llx\n", pid);

	return 0;
}

int vcpu_write_mmu_u_pptb_reg(struct kvm_vcpu *vcpu, pgprotval_t u_pptb,
			 bool *pt_updated, hpa_t *u_root)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t sw_u_pptb;
	pgprotval_t old_u_pptb;
	int r;

	sw_u_pptb = mmu->get_vcpu_context_u_pptb(vcpu);
	old_u_pptb = mmu->get_vcpu_u_pptb(vcpu);
	KVM_BUG_ON(!is_shadow_paging(vcpu) && sw_u_pptb != old_u_pptb &&
		vcpu->arch.is_pv);

	if (!is_paging(vcpu)) {
		/* it is setup of initial guest page table */
		/* paging wiil be enabled while set MMU_CR.tlb_en */
		/* now save only base of guest */
		mmu->set_vcpu_u_pptb(vcpu, u_pptb);
		DebugMMUREG("guest MMU U_PPTB: initial PT base at 0x%lx\n",
			u_pptb);
		r = 0;
		goto handled;
	}
	if (sw_u_pptb == u_pptb) {
		/* set the same page table, so nothing to do */
		DebugMMUREG("guest MMU U_PPTB: write the same PT root "
			"at 0x%lx\n",
			u_pptb);
		r = 0;
		goto handled;
	}

	/*
	 * Switch to new page table root
	 */

	DebugMMUREG("switch to new guest U_PPTB base at 0x%lx\n",
		u_pptb);

	if (is_tdp_paging(vcpu)) {
		r = kvm_switch_tdp_u_pptb(vcpu, u_pptb);
	} else if (is_shadow_paging(vcpu)) {
		r = kvm_switch_shadow_u_pptb(vcpu, u_pptb, u_root);
		*pt_updated = true;
	} else {
		KVM_BUG_ON(true);
		r = -EINVAL;
	}

handled:
	return r;
}

int vcpu_write_mmu_os_pptb_reg(struct kvm_vcpu *vcpu, pgprotval_t os_pptb,
					bool *pt_updated, hpa_t *os_root)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t sh_os_pptb;
	pgprotval_t old_os_pptb;
	int r;

	sh_os_pptb = mmu->get_vcpu_context_os_pptb(vcpu);
	old_os_pptb = mmu->get_vcpu_os_pptb(vcpu);
	KVM_BUG_ON(!is_shadow_paging(vcpu) && sh_os_pptb != old_os_pptb);

	if (!is_paging(vcpu)) {
		/* it is setup of initial guest page table */
		/* paging wiil be enabled while set MMU_CR.tlb_en */
		/* now save only base of guest */
		mmu->set_vcpu_os_pptb(vcpu, os_pptb);
		DebugMMUREG("guest MMU OS_PPTB: initial PT base at 0x%lx\n",
			os_pptb);
		return 0;
	}
	if (old_os_pptb == os_pptb) {
		/* set the same page table, so nothing to do */
		DebugMMUREG("guest MMU OS_PPTB: write the same PT root "
			"at 0x%lx\n",
			os_pptb);
		return 0;
	}

	/*
	 * Switch to new page table root
	 */
	DebugMMUREG("switch to new guest OS PT base at 0x%lx\n",
		os_pptb);

	if (is_tdp_paging(vcpu)) {
		r = kvm_switch_tdp_os_pptb(vcpu, os_pptb);
	} else if (is_shadow_paging(vcpu)) {
		r = kvm_switch_shadow_os_pptb(vcpu, os_pptb, os_root);
		*pt_updated = true;
	} else {
		KVM_BUG_ON(true);
		r = -EINVAL;
	}

	return r;
}

int vcpu_write_mmu_u_vptb_reg(struct kvm_vcpu *vcpu, gva_t u_vptb)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t sw_u_vptb;
	gva_t old_u_vptb;

	sw_u_vptb = mmu->get_vcpu_context_u_vptb(vcpu);
	old_u_vptb = mmu->get_vcpu_u_vptb(vcpu);
	KVM_BUG_ON(!is_shadow_paging(vcpu) && sw_u_vptb != old_u_vptb &&
		vcpu->arch.is_pv);

	if (!is_paging(vcpu)) {
		/* it is setup of initial guest page table */
		/* paging wiil be enabled while set MMU_CR.tlb_en */
		/* now save only virtual base of guest */
		mmu->set_vcpu_u_vptb(vcpu, u_vptb);
		DebugMMUVPT("guest MMU U_VPTB: virtual PT base at 0x%lx\n",
			u_vptb);
		return 0;
	}
	if (sw_u_vptb == u_vptb) {
		/* set the same page table, so nothing to do */
		DebugMMUVPT("guest MMU U_VPTB: write the same PT base 0x%lx\n",
			u_vptb);
		return 0;
	}

	pr_err("%s(): virtual User PT base update from 0x%llx to 0x%lx "
		"is not implemented\n",
		__func__, sw_u_vptb, u_vptb);
	return -EINVAL;
}

int vcpu_write_mmu_os_vptb_reg(struct kvm_vcpu *vcpu, gva_t os_vptb)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t sw_os_vptb;
	gva_t old_os_vptb;

	sw_os_vptb = mmu->get_vcpu_context_os_vptb(vcpu);
	old_os_vptb = mmu->get_vcpu_os_vptb(vcpu);
	KVM_BUG_ON(!is_shadow_paging(vcpu) && sw_os_vptb != old_os_vptb);

	if (!is_paging(vcpu)) {
		/* it is setup of initial guest page table */
		/* paging wiil be enabled while set MMU_CR.tlb_en */
		/* now save only virtual base of guest */
		mmu->set_vcpu_os_vptb(vcpu, os_vptb);
		DebugMMUVPT("guest MMU OS_VPTB: virtual PT base at 0x%lx\n",
			os_vptb);
		return 0;
	}
	if (sw_os_vptb == os_vptb) {
		/* set the same page table, so nothing to do */
		DebugMMUVPT("guest MMU OS_VPTB: write the same PT base 0x%lx\n",
			os_vptb);
		return 0;
	}

	pr_err("%s(): virtual OS PT base update from 0x%llx to 0x%lx "
		"is not implemented\n",
		__func__, sw_os_vptb, os_vptb);
	return -EINVAL;
}

int vcpu_write_mmu_os_vab_reg(struct kvm_vcpu *vcpu, gva_t os_vab)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t sw_os_vab;
	gva_t old_os_vab;

	sw_os_vab = mmu->get_vcpu_context_os_vab(vcpu);
	old_os_vab = mmu->get_vcpu_os_vab(vcpu);
	KVM_BUG_ON(!is_shadow_paging(vcpu) && sw_os_vab != old_os_vab);

	if (!is_paging(vcpu)) {
		/* it is setup of initial guest page table */
		/* paging wiil be enabled while set MMU_CR.tlb_en */
		/* now save only virtual base of guest */
		mmu->set_vcpu_os_vab(vcpu, os_vab);
		return 0;
	}
	if (sw_os_vab == os_vab) {
		/* set the same page table, so nothing to do */
		DebugMMUVPT("guest MMU OS_VAB: write the same virtual "
			"addresses base 0x%lx\n",
			os_vab);
		return 0;
	}

	pr_err("%s(): guest OS virtual addresses base update from 0x%llx "
		"to 0x%lx is not implemented\n",
		__func__, sw_os_vab, os_vab);
	return -EINVAL;
}

int vcpu_read_trap_point_mmu_reg(struct kvm_vcpu *vcpu, gpa_t *tc_gpa)
{
	if (vcpu->arch.mmu.tc_page != NULL) {
		/* guest TRAP_POINT register was written */
		*tc_gpa = vcpu->arch.mmu.tc_gpa;
	} else {
		/* read without writing */
		*tc_gpa = 0;
	}

	DebugMMUREG("read guest TRAP POINT: GPA 0x%llx, host PA 0x%llx, "
		"mapped to host addr %px\n",
		*tc_gpa, vcpu->arch.sw_ctxt.tc_hpa, vcpu->arch.mmu.tc_kaddr);

	return 0;
}

int vcpu_read_mmu_cr_reg(struct kvm_vcpu *vcpu, mmu_reg_t *mmu_cr)
{
	*mmu_cr = read_guest_MMU_CR_reg(vcpu);

	DebugMMUREG("guest MMU_CR does not change: 0x%llx, tlb_en: %d\n",
		*mmu_cr, !!(*mmu_cr & _MMU_CR_TLB_EN));

	return 0;
}

int vcpu_read_mmu_u_pptb_reg(struct kvm_vcpu *vcpu, pgprotval_t *u_pptb_p)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t sw_u_pptb;
	pgprotval_t u_pptb;
	hpa_t root_u_pptb;
	bool sep_virt_space;

	sw_u_pptb = mmu->get_vcpu_context_u_pptb(vcpu);
	u_pptb = mmu->get_vcpu_u_pptb(vcpu);
	DebugMMUREG("guest MMU U_PPTB : register 0x%llx, base 0x%lx\n",
		sw_u_pptb, u_pptb);

	sep_virt_space = is_sep_virt_spaces(vcpu);

	if (!is_paging(vcpu)) {
		if (is_phys_paging(vcpu)) {
			KVM_BUG_ON(u_pptb != sw_u_pptb);
		} else {
			root_u_pptb = kvm_get_space_type_spt_u_root(vcpu);
			KVM_BUG_ON(!sep_virt_space &&
					IS_E2K_INVALID_PAGE(root_u_pptb));
			KVM_BUG_ON(sw_u_pptb != root_u_pptb);
		}
	} else if (likely(is_tdp_paging(vcpu))) {
		KVM_BUG_ON(sw_u_pptb != u_pptb);
	} else if (is_shadow_paging(vcpu)) {
		root_u_pptb = kvm_get_space_type_spt_u_root(vcpu);
		KVM_BUG_ON(!sep_virt_space && IS_E2K_INVALID_PAGE(root_u_pptb));
		if (!is_phys_paging(vcpu)) {
			KVM_BUG_ON(sw_u_pptb != root_u_pptb);
		} else {
			KVM_BUG_ON(sw_u_pptb != u_pptb);
		}
	} else {
		KVM_BUG_ON(true);
	}

	*u_pptb_p = u_pptb;

	DebugMMUREG("guest MMU U_PPTB does not change: 0x%lx\n", *u_pptb_p);

	return 0;
}

int vcpu_read_mmu_os_pptb_reg(struct kvm_vcpu *vcpu, pgprotval_t *os_pptb_p)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t sh_os_pptb;
	pgprotval_t os_pptb;
	hpa_t root;
	bool sep_virt_space;

	sh_os_pptb = mmu->get_vcpu_context_os_pptb(vcpu);
	os_pptb = mmu->get_vcpu_os_pptb(vcpu);
	DebugMMUREG("guest MMU OS_PPTB : register 0x%llx, base 0x%lx\n",
		sh_os_pptb, os_pptb);

	sep_virt_space = is_sep_virt_spaces(vcpu);

	if (!is_paging(vcpu)) {
		if (is_phys_paging(vcpu)) {
			KVM_BUG_ON(sh_os_pptb != os_pptb);
		} else {
			if (sep_virt_space) {
				root = kvm_get_space_type_spt_u_root(vcpu);
			} else {
				root = kvm_get_space_type_spt_os_root(vcpu);
			}
			KVM_BUG_ON(IS_E2K_INVALID_PAGE(root));
			KVM_BUG_ON(sh_os_pptb != root);
		}
	} else if (likely(is_tdp_paging(vcpu))) {
		KVM_BUG_ON(sh_os_pptb != os_pptb);
	} else if (is_shadow_paging(vcpu)) {
		if (sep_virt_space) {
			root = kvm_get_space_type_spt_u_root(vcpu);
		} else {
			root = kvm_get_space_type_spt_os_root(vcpu);
		}
		KVM_BUG_ON(IS_E2K_INVALID_PAGE(root));
		KVM_BUG_ON(sh_os_pptb != root);
	} else {
		KVM_BUG_ON(true);
	}

	*os_pptb_p = os_pptb;

	DebugMMUREG("guest MMU OS_PPTB does not change: 0x%lx\n", *os_pptb_p);

	return 0;
}

int vcpu_read_mmu_u_vptb_reg(struct kvm_vcpu *vcpu, gva_t *u_vptb_p)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t sw_u_vptb;
	gva_t u_vptb;
	bool sep_virt_space;

	sw_u_vptb = mmu->get_vcpu_context_u_vptb(vcpu);
	u_vptb = mmu->get_vcpu_u_vptb(vcpu);
	DebugMMUVPT("guest MMU U_VPTB : register 0x%llx, base 0x%lx\n",
		sw_u_vptb, u_vptb);

	sep_virt_space = is_sep_virt_spaces(vcpu);

	if (!is_paging(vcpu)) {
		if (is_phys_paging(vcpu)) {
			KVM_BUG_ON(u_vptb != sw_u_vptb);
		}
	} else if (likely(is_tdp_paging(vcpu))) {
		KVM_BUG_ON(sw_u_vptb != u_vptb);
	} else if (is_shadow_paging(vcpu)) {
		if (is_phys_paging(vcpu)) {
			KVM_BUG_ON(sw_u_vptb != u_vptb);
		}
	} else {
		KVM_BUG_ON(true);
	}

	*u_vptb_p = u_vptb;

	DebugMMUVPT("guest MMU U_VPTB does not change: 0x%lx\n", *u_vptb_p);

	return 0;
}

int vcpu_read_mmu_os_vptb_reg(struct kvm_vcpu *vcpu, gva_t *os_vptb_p)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t sw_os_vptb;
	gva_t os_vptb;
	bool sep_virt_space;

	sw_os_vptb = mmu->get_vcpu_context_os_vptb(vcpu);
	os_vptb = mmu->get_vcpu_os_vptb(vcpu);
	DebugMMUVPT("guest MMU OS_VPTB : register 0x%llx, base 0x%lx\n",
		sw_os_vptb, os_vptb);

	sep_virt_space = is_sep_virt_spaces(vcpu);

	if (!is_paging(vcpu)) {
		if (is_phys_paging(vcpu)) {
			KVM_BUG_ON(os_vptb != sw_os_vptb);
		}
	} else if (likely(is_tdp_paging(vcpu))) {
		KVM_BUG_ON(sw_os_vptb != os_vptb);
	} else if (is_shadow_paging(vcpu)) {
		if (is_phys_paging(vcpu)) {
			KVM_BUG_ON(sw_os_vptb != os_vptb);
		}
	} else {
		KVM_BUG_ON(true);
	}

	*os_vptb_p = os_vptb;

	DebugMMUVPT("guest MMU OS_VPTB does not change: 0x%lx\n", *os_vptb_p);

	return 0;
}

int vcpu_read_mmu_os_vab_reg(struct kvm_vcpu *vcpu, gva_t *os_vab_p)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t sw_os_vab;
	gva_t os_vab;
	bool sep_virt_space;

	sw_os_vab = mmu->get_vcpu_context_os_vab(vcpu);
	os_vab = mmu->get_vcpu_os_vab(vcpu);
	DebugMMUVPT("guest MMU OS_VAB : register 0x%llx, base 0x%lx\n",
		sw_os_vab, os_vab);

	sep_virt_space = is_sep_virt_spaces(vcpu);

	if (!is_paging(vcpu)) {
		if (is_phys_paging(vcpu)) {
			KVM_BUG_ON(os_vab != sw_os_vab);
		}
	} else if (likely(is_tdp_paging(vcpu))) {
		KVM_BUG_ON(sw_os_vab != os_vab);
	} else if (is_shadow_paging(vcpu)) {
		if (is_phys_paging(vcpu)) {
			KVM_BUG_ON(sw_os_vab != os_vab);
		}
	} else {
		KVM_BUG_ON(true);
	}

	*os_vab_p = os_vab;

	DebugMMUVPT("guest MMU OS_VAB does not change: 0x%lx\n", *os_vab_p);

	return 0;
}

bool kvm_mmu_is_hv_paging(struct kvm_vcpu *vcpu)
{
	mmu_reg_t mmu_cr;
	bool sh_mmu_cr_paging;
	int r;

	KVM_BUG_ON(!is_tdp_paging(vcpu));

	r = vcpu_read_mmu_cr_reg(vcpu, &mmu_cr);
	if (r != 0) {
		pr_err("%s(): could not read SH_MMU_CR register, error %d\n",
			__func__, r);
		KVM_BUG_ON(true);
		return false;
	}

	sh_mmu_cr_paging = !!(mmu_cr & _MMU_CR_TLB_EN);
	if (likely(sh_mmu_cr_paging)) {
		if (unlikely(!is_paging_flag(vcpu))) {
			/* guest MMU paging has been enabled */
			r = kvm_hv_setup_tdp_paging(vcpu);
			if (r != 0) {
				pr_err("%s(): could not switch guest to "
					"paging mode, error %d\n",
					__func__, r);
				KVM_BUG_ON(true);
			}
		}
		return true;
	} else {
		if (unlikely(is_paging_flag(vcpu))) {
			/* guest MMU paging has been disabled */
			pr_err("%s(): guest turns OFF paging mode: "
				"SH_MMU_CR 0x%llx\n",
				__func__, mmu_cr);
			reset_paging_flag(vcpu);
		}
		return false;
	}
}

int kvm_mmu_enable_shadow_paging(struct kvm_vcpu *vcpu)
{
	mmu_reg_t mmu_cr;
	bool sh_mmu_cr_paging;
	int r;

	KVM_BUG_ON(!is_shadow_paging(vcpu));

	r = vcpu_read_mmu_cr_reg(vcpu, &mmu_cr);
	if (r != 0) {
		pr_err("%s(): could not read SH_MMU_CR register, error %d\n",
			__func__, r);
		return r;
	}

	sh_mmu_cr_paging = !!(mmu_cr & _MMU_CR_TLB_EN);

	if (unlikely(sh_mmu_cr_paging)) {
		pr_err("%s() : paging is already enabled\n", __func__);
		return 0;
	}

	if (unlikely(is_paging_flag(vcpu))) {
		/* guest MMU paging has been disabled */
		pr_err("%s(): guest paging is turned OFF SH_MMU_CR 0x%llx\n",
			__func__, mmu_cr);
		KVM_BUG_ON(true);
		return -EBUSY;
	}

	mmu_cr |= _MMU_CR_TLB_EN;
	r = vcpu_write_mmu_cr_reg(vcpu, mmu_cr);
	if (r != 0)  {
		pr_err("%s() : could not enable paging on VCPU #%d, error %d\n",
			__func__, vcpu->vcpu_id, r);
		return r;
	}

	return 0;
}
