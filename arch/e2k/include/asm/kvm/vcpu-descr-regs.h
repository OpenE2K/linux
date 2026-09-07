/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef	__KVM_VCPU_DESCR_REGS_H_
#define	__KVM_VCPU_DESCR_REGS_H_

#include <asm/cpu_regs_types.h>
#include <asm/kvm_host.h>

/**
 * vcpu_getsp_v7 - calculate CORE_MODE.getsp_v7 for vcpu
 */
static inline bool vcpu_getsp_v7(struct kvm_vcpu *vcpu)
{
	/* Must check CPU_FEAT_V7_CPU_REGS since the other flag is from user */
	return cpu_has(CPU_FEAT_V7_CPU_REGS) && !test_kvm_mode_flag(vcpu->kvm, KVMF_GETSP_V6);
}

/**
 * vcpu_descr_v7 - calculate CORE_MODE.descr_v7 for vcpu
 */
static inline bool vcpu_descr_v7(const struct kvm_vcpu *vcpu)
{
	/* Must check CPU_FEAT_V7_CPU_REGS since the other flag is from user */
	return cpu_has(CPU_FEAT_V7_CPU_REGS) && !test_kvm_mode_flag(vcpu->kvm, KVMF_DESCR_V6);
}

/*
 * Compilation Unit Descriptor (CUD)
 * describes the memory containing codes of the current compilation unit
 */

static __always_inline u64
vcpu_cud_base(struct kvm_vcpu *vcpu, e2k_cud_t cud)
{
	if (vcpu_descr_v7(vcpu)) {
		return CUD_BASE_V7(cud);
	} else {
		return CUD_BASE_V6(cud);
	}
}

static __always_inline u64
vcpu_cud_size(struct kvm_vcpu *vcpu, e2k_cud_t cud)
{
	if (vcpu_descr_v7(vcpu)) {
		return CUD_SIZE_V7(cud);
	} else {
		return CUD_SIZE_V6(cud);
	}
}

static __always_inline enum cud_flag
vcpu_cud_flag(struct kvm_vcpu *vcpu, e2k_cud_t cud)
{
	if (vcpu_descr_v7(vcpu)) {
		return CUD_FLAG_V7(cud);
	} else {
		return CUD_FLAG_V6(cud);
	}
}

static __always_inline e2k_cud_t
vcpu_new_cud(struct kvm_vcpu *vcpu, u64 base, u64 size, int c, enum cud_flag flag)
{
	if (vcpu_descr_v7(vcpu)) {
		return new_cud_v7(base, size, c, flag);
	} else {
		return new_cud_v6(base, size, c, flag);
	}
}

/*
 * Compilation Unit Globals Descriptor (GD)
 * describes the global variables memory of the current compilation unit
 */
static __always_inline u64
vcpu_gd_base(struct kvm_vcpu *vcpu, e2k_gd_t gd)
{
	if (vcpu_descr_v7(vcpu)) {
		return GD_BASE_V7(gd);
	}
	return GD_BASE_V6(gd);
}

static __always_inline u64
vcpu_gd_size(struct kvm_vcpu *vcpu, e2k_gd_t gd)
{
	if (vcpu_descr_v7(vcpu)) {
		return GD_SIZE_V7(gd);
	} else {
		return GD_SIZE_V6(gd);
	}
}

static __always_inline e2k_gd_t
vcpu_new_gd(struct kvm_vcpu *vcpu, u64 base, u64 size)
{
	if (vcpu_descr_v7(vcpu)) {
		return new_gd_v7(base, size);
	} else {
		return new_gd_v6(base, size);
	}
}

/*
 * Procedure Stack Pointer (PSP)
 * describes the full procedure stack memory as well as the current pointer
 * to the top of a procedure stack memory part.
 */
static __always_inline u64
vcpu_psp_base(struct kvm_vcpu *vcpu, e2k_psp_t psp)
{
	if (vcpu_descr_v7(vcpu)) {
		return PSP_BASE_V7(psp);
	} else {
		return PSP_BASE_V6(psp);
	}
}

static __always_inline u64
vcpu_psp_size(struct kvm_vcpu *vcpu, e2k_psp_t psp)
{
	if (vcpu_descr_v7(vcpu)) {
		return PSP_SIZE_V7(psp);
	} else {
		return PSP_SIZE_V6(psp);
	}
}

static __always_inline u64
vcpu_psp_ind(struct kvm_vcpu *vcpu, e2k_psp_t psp)
{
	if (vcpu_descr_v7(vcpu)) {
		return PSP_IND_V7(psp);
	} else {
		return PSP_IND_V6(psp);
	}
}

static __always_inline volatile void __priv *
vcpu_psp_ptr(struct kvm_vcpu *vcpu, e2k_psp_t psp)
{
	if (vcpu_descr_v7(vcpu)) {
		return (volatile void __priv __force *)PSP_PTR_V7(psp);
	} else {
		return (volatile void __priv __force *)PSP_PTR_V6(psp);
	}
}

static __always_inline e2k_psp_t
vcpu_new_psp(struct kvm_vcpu *vcpu, u64 base, u64 size, u64 ind)
{
	if (vcpu_descr_v7(vcpu)) {
		return new_psp_v7(base, size, ind);
	} else {
		return new_psp_v6(base, size, ind);
	}
}

static __always_inline __must_check e2k_psp_t
vcpu_set_psp_ind(struct kvm_vcpu *vcpu, e2k_psp_t psp, u64 new_ind)
{
	return vcpu_new_psp(vcpu, vcpu_psp_base(vcpu, psp),
			    vcpu_psp_size(vcpu, psp), new_ind);
}

static __always_inline __must_check e2k_psp_t
vcpu_incr_psp_ind(struct kvm_vcpu *vcpu, e2k_psp_t psp, s32 delta)
{
	return vcpu_set_psp_ind(vcpu, psp, vcpu_psp_ind(vcpu, psp) + delta);
}

static __always_inline __must_check e2k_psp_t
vcpu_decr_psp_ind(struct kvm_vcpu *vcpu, e2k_psp_t psp, s32 delta)
{
	return vcpu_set_psp_ind(vcpu, psp, vcpu_psp_ind(vcpu, psp) - delta);
}

/*
 * Procedure Chain Stack Pointer (PCSP)
 * describes the full procedure chain stack memory as well as the current
 * pointer to the top of a procedure chain stack memory part.
 */
static __always_inline u64
vcpu_pcsp_base(struct kvm_vcpu *vcpu, e2k_pcsp_t pcsp)
{
	if (vcpu_descr_v7(vcpu)) {
		return PCSP_BASE_V7(pcsp);
	} else {
		return PCSP_BASE_V6(pcsp);
	}
}

static __always_inline u64
vcpu_pcsp_size(struct kvm_vcpu *vcpu, e2k_pcsp_t pcsp)
{
	if (vcpu_descr_v7(vcpu)) {
		return PCSP_SIZE_V7(pcsp);
	} else {
		return PCSP_SIZE_V6(pcsp);
	}
}

static __always_inline u64
vcpu_pcsp_ind(struct kvm_vcpu *vcpu, e2k_pcsp_t pcsp)
{
	if (vcpu_descr_v7(vcpu)) {
		return PCSP_IND_V7(pcsp);
	} else {
		return PCSP_IND_V6(pcsp);
	}
}

static __always_inline void __priv *
vcpu_pcsp_ptr(struct kvm_vcpu *vcpu, e2k_pcsp_t pcsp)
{
	if (vcpu_descr_v7(vcpu)) {
		return (void __priv *)PCSP_PTR_V7(pcsp);
	} else {
		return (void __priv *)PCSP_PTR_V6(pcsp);
	}
}

static __always_inline e2k_pcsp_t
vcpu_new_pcsp(struct kvm_vcpu *vcpu, u64 base, u64 size, u64 ind)
{
	if (vcpu_descr_v7(vcpu)) {
		return new_pcsp_v7(base, size, ind);
	} else {
		return new_pcsp_v6(base, size, ind);
	}
}

static __always_inline __must_check e2k_pcsp_t
vcpu_set_pcsp_ind(struct kvm_vcpu *vcpu, e2k_pcsp_t pcsp, u64 new_ind)
{
	return vcpu_new_pcsp(vcpu, vcpu_pcsp_base(vcpu, pcsp),
			     vcpu_pcsp_size(vcpu, pcsp), new_ind);
}

static __always_inline __must_check e2k_pcsp_t
vcpu_incr_pcsp_ind(struct kvm_vcpu *vcpu, e2k_pcsp_t pcsp, s32 delta)
{
	return vcpu_set_pcsp_ind(vcpu, pcsp, vcpu_pcsp_ind(vcpu, pcsp) + delta);
}

static __always_inline __must_check e2k_pcsp_t
vcpu_decr_pcsp_ind(struct kvm_vcpu *vcpu, e2k_pcsp_t pcsp, s32 delta)
{
	return vcpu_set_pcsp_ind(vcpu, pcsp, vcpu_pcsp_ind(vcpu, pcsp) - delta);
}

/*
 * User Stack Descriptor (USD)
 * contains free memory space dedicated for user stack data and
 * is supposed to grow from higher memory addresses to lower ones
 */
static __always_inline u64
vcpu_usd_ptr(struct kvm_vcpu *vcpu, e2k_usd_t usd)
{
	if (vcpu_descr_v7(vcpu)) {
		return USD_PTR_V7(usd);
	} else {
		return USD_PTR_V6(usd);
	}
}

static __always_inline u64
vcpu_usd_ind_v7(struct kvm_vcpu *vcpu, e2k_usd_t usd)
{
	return USD_IND_V7(usd);
}

static __always_inline u64
vcpu_usd_ind_v6(struct kvm_vcpu *vcpu, e2k_usd_t usd)
{
	return USD_IND_V6(usd);
}

static __always_inline u64
vcpu_usd_ind(struct kvm_vcpu *vcpu, e2k_usd_t usd)
{
	if (vcpu_descr_v7(vcpu)) {
		return vcpu_usd_ind_v7(vcpu, usd);
	} else {
		return vcpu_usd_ind_v6(vcpu, usd);
	}
}

/*
 * NB> Don't use macros 'USD_BASE' in the protected mode in iset<7
 */
static __always_inline u64
vcpu_usd_base_v7(struct kvm_vcpu *vcpu, e2k_usd_t usd)
{
	return USD_BASE_V7(usd);
}

static __always_inline u64
vcpu_usd_base_v6(struct kvm_vcpu *vcpu, e2k_usd_t usd)
{
	return USD_BASE_V6(usd);
}

static __always_inline u64
vcpu_usd_base(struct kvm_vcpu *vcpu, e2k_usd_t usd)
{
	if (vcpu_descr_v7(vcpu)) {
		return vcpu_usd_base_v7(vcpu, usd);
	} else {
		return vcpu_usd_base_v6(vcpu, usd);
	}
}

static __always_inline u64
vcpu_usd_size(struct kvm_vcpu *vcpu, e2k_usd_t usd)
{
	if (vcpu_descr_v7(vcpu)) {
		return USD_SIZE_V7(usd);
	} else {
		return 0ULL;
	}
}

static __always_inline u64
vcpu_usd_pptr(struct kvm_vcpu *vcpu, e2k_usd_t usd)
{
	if (vcpu_descr_v7(vcpu)) {
		return USD_PPTR_V7(usd);
	}
	return USD_PPTR_V6(usd);
}

static __always_inline u32
vcpu_usd_psl(struct kvm_vcpu *vcpu, e2k_usd_t usd)
{
	if (vcpu_descr_v7(vcpu)) {
		return 0;
	} else {
		return USD_PSL_V6(usd);
	}
}

static __always_inline bool
vcpu_usd_p_v7(struct kvm_vcpu *vcpu)
{
	return USD_P_V7();
}

static __always_inline bool
vcpu_usd_p_v6(struct kvm_vcpu *vcpu, e2k_usd_t usd)
{
	return USD_P_V6(usd);
}

static __always_inline bool
vcpu_usd_p(struct kvm_vcpu *vcpu, e2k_usd_t usd)
{
	if (vcpu_descr_v7(vcpu)) {
		return vcpu_usd_p_v7(vcpu);
	} else {
		return vcpu_usd_p_v6(vcpu, usd);
	}
}

static __always_inline e2k_usd_t
vcpu_new_usd(struct kvm_vcpu *vcpu, u64 base, u64 size, u64 ind)
{
	if (vcpu_descr_v7(vcpu)) {
		return new_usd_v7(base, size, ind);
	} else {
		return new_usd_v6(base, ind);
	}
}

/* CR */

static __always_inline u64
vcpu_get_cr1_ussz(struct kvm_vcpu *vcpu, e2k_cr1_t cr1)
{
	if (vcpu_descr_v7(vcpu)) {
		return get_cr1_ussz_v7(cr1);
	} else {
		return get_cr1_ussz_v6(cr1);
	}
}

static __always_inline __must_check e2k_cr1_t
vcpu_set_cr1_ussz(struct kvm_vcpu *vcpu, e2k_cr1_t cr1,  u64 sz)
{
	if (vcpu_descr_v7(vcpu)) {
		return set_cr1_ussz_v7(cr1, sz);
	} else {
		return set_cr1_ussz_v6(cr1, sz);
	}
}

static __always_inline void
vcpu_set_cr1p_ussz(struct kvm_vcpu *vcpu, e2k_cr1_t *cr1p,  u64 sz)
{
	if (vcpu_descr_v7(vcpu)) {
		set_cr1p_ussz_v7(cr1p, sz);
	} else {
		set_cr1p_ussz_v6(cr1p, sz);
	}
}

#endif /* __KVM_VCPU_DESCR_REGS_H_ */
