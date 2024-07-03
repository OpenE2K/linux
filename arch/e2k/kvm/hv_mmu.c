/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


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
#include "cpu.h"
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
			E2K_KVM_BUG_ON(u_pptb != sw_u_pptb);
		} else {
			root_u_pptb = kvm_get_space_type_spt_u_root(vcpu);
			E2K_KVM_BUG_ON(!sep_virt_space &&
					IS_E2K_INVALID_PAGE(root_u_pptb));
			E2K_KVM_BUG_ON(sw_u_pptb != root_u_pptb);
		}
	} else if (likely(is_tdp_paging(vcpu))) {
		E2K_KVM_BUG_ON(sw_u_pptb != u_pptb);
	} else if (is_shadow_paging(vcpu)) {
		root_u_pptb = kvm_get_space_type_spt_u_root(vcpu);
		E2K_KVM_BUG_ON(!sep_virt_space && IS_E2K_INVALID_PAGE(root_u_pptb));
		if (!is_phys_paging(vcpu)) {
			E2K_KVM_BUG_ON(sw_u_pptb != root_u_pptb);
		} else {
			E2K_KVM_BUG_ON(sw_u_pptb != u_pptb);
		}
	} else {
		E2K_KVM_BUG_ON(true);
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
			E2K_KVM_BUG_ON(sh_os_pptb != os_pptb);
		} else {
			if (sep_virt_space) {
				root = kvm_get_space_type_spt_u_root(vcpu);
			} else {
				root = kvm_get_space_type_spt_os_root(vcpu);
			}
			E2K_KVM_BUG_ON(IS_E2K_INVALID_PAGE(root));
			E2K_KVM_BUG_ON(sh_os_pptb != root);
		}
	} else if (likely(is_tdp_paging(vcpu))) {
		E2K_KVM_BUG_ON(sh_os_pptb != os_pptb);
	} else if (is_shadow_paging(vcpu)) {
		if (sep_virt_space) {
			root = kvm_get_space_type_spt_u_root(vcpu);
		} else {
			root = kvm_get_space_type_spt_os_root(vcpu);
		}
		E2K_KVM_BUG_ON(IS_E2K_INVALID_PAGE(root));
		E2K_KVM_BUG_ON(sh_os_pptb != root);
	} else {
		E2K_KVM_BUG_ON(true);
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
			E2K_KVM_BUG_ON(u_vptb != sw_u_vptb);
		}
	} else if (likely(is_tdp_paging(vcpu))) {
		E2K_KVM_BUG_ON(sw_u_vptb != u_vptb);
	} else if (is_shadow_paging(vcpu)) {
		if (is_phys_paging(vcpu)) {
			E2K_KVM_BUG_ON(sw_u_vptb != u_vptb);
		}
	} else {
		E2K_KVM_BUG_ON(true);
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
			E2K_KVM_BUG_ON(os_vptb != sw_os_vptb);
		}
	} else if (likely(is_tdp_paging(vcpu))) {
		E2K_KVM_BUG_ON(sw_os_vptb != os_vptb);
	} else if (is_shadow_paging(vcpu)) {
		if (is_phys_paging(vcpu)) {
			E2K_KVM_BUG_ON(sw_os_vptb != os_vptb);
		}
	} else {
		E2K_KVM_BUG_ON(true);
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
			E2K_KVM_BUG_ON(os_vab != sw_os_vab);
		}
	} else if (likely(is_tdp_paging(vcpu))) {
		E2K_KVM_BUG_ON(sw_os_vab != os_vab);
	} else if (is_shadow_paging(vcpu)) {
		if (is_phys_paging(vcpu)) {
			E2K_KVM_BUG_ON(sw_os_vab != os_vab);
		}
	} else {
		E2K_KVM_BUG_ON(true);
	}

	*os_vab_p = os_vab;

	DebugMMUVPT("guest MMU OS_VAB does not change: 0x%lx\n", *os_vab_p);

	return 0;
}

int kvm_hv_setup_tdp_paging(struct kvm_vcpu *vcpu)
{
	e2k_core_mode_t core_mode;
	bool sep_virt_space;

	setup_tdp_paging(vcpu);

	/* enable guest paging mode and shadow MMU context */

	core_mode = read_guest_CORE_MODE_reg(vcpu);
	sep_virt_space = !!core_mode.CORE_MODE_sep_virt_space;
	if (sep_virt_space)
		set_sep_virt_spaces(vcpu);
	else
		reset_sep_virt_spaces(vcpu);

	mmu_pt_init_vcpu_pt_struct(vcpu);

	/* setup TDP PTs hardware/software context */
	kvm_setup_mmu_tdp_context(vcpu);

	return 0;
}

bool kvm_mmu_is_hv_paging(struct kvm_vcpu *vcpu)
{
	e2k_mmu_cr_t mmu_cr;
	bool sh_mmu_cr_paging;
	int r;

	E2K_KVM_BUG_ON(!is_tdp_paging(vcpu));

	r = vcpu_read_mmu_cr_reg(vcpu, &mmu_cr);
	if (r != 0) {
		pr_err("%s(): could not read SH_MMU_CR register, error %d\n",
			__func__, r);
		E2K_KVM_BUG_ON(true);
		return false;
	}

	sh_mmu_cr_paging = mmu_cr.tlb_en;
	if (likely(sh_mmu_cr_paging)) {
		if (unlikely(!is_paging_flag(vcpu))) {
			/* guest MMU paging has been enabled */
			r = kvm_hv_setup_tdp_paging(vcpu);
			if (r != 0) {
				pr_err("%s(): could not switch guest to "
					"paging mode, error %d\n",
					__func__, r);
				E2K_KVM_BUG_ON(true);
			}
		}
		return true;
	} else {
		if (unlikely(is_paging_flag(vcpu))) {
			/* guest MMU paging has been disabled */
			pr_err("%s(): guest turns OFF paging mode: SH_MMU_CR 0x%llx\n",
				__func__, AW(mmu_cr));
			reset_paging_flag(vcpu);
		}
		return false;
	}
}
