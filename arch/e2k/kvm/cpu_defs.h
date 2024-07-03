/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_E2K_CPU_DEFS_H
#define __KVM_E2K_CPU_DEFS_H

#include <linux/kvm_host.h>
#include <asm/cpu_regs.h>

/* FIXME: the follow define only to debug, delete after completion and */
/* turn on __interrupt atribute */
#undef	DEBUG_GTI
#define	DEBUG_GTI	1

/*
 * VCPU state structure contains CPU, MMU, Local APIC and other registers
 * current values of VCPU. The structure is common for host and guest and
 * can (and should) be accessed by both.
 * Guest access do through global pointer which should be load on some global
 * register (GUEST_VCPU_STATE_GREG) or on special CPU register GD.
 * But GD can be used only if guest kernel run as protected task
 */

/*
 * Basic functions to access to virtual CPUs registers status on host.
 */

static inline u64
kvm_get_guest_vcpu_regs_status(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.kmap_vcpu_state->cpu.regs_status;
}
static inline void
kvm_put_guest_vcpu_regs_status(struct kvm_vcpu *vcpu, unsigned long new_status)
{
	vcpu->arch.kmap_vcpu_state->cpu.regs_status = new_status;
}
static inline void
kvm_reset_guest_vcpu_regs_status(struct kvm_vcpu *vcpu)
{
	kvm_put_guest_vcpu_regs_status(vcpu, 0);
}
static inline void
kvm_put_guest_updated_vcpu_regs_flags(struct kvm_vcpu *vcpu,
					unsigned long new_flags)
{
	unsigned long cur_flags = kvm_get_guest_vcpu_regs_status(vcpu);
	cur_flags = KVM_SET_UPDATED_CPU_REGS_FLAGS(cur_flags, new_flags);
	kvm_put_guest_vcpu_regs_status(vcpu, cur_flags);
}
static inline void
kvm_clear_guest_updated_vcpu_regs_flags(struct kvm_vcpu *vcpu,
					unsigned long flags)
{
	unsigned long cur_flags = kvm_get_guest_vcpu_regs_status(vcpu);
	cur_flags = KVM_CLEAR_UPDATED_CPU_REGS_FLAGS(cur_flags, flags);
	kvm_put_guest_vcpu_regs_status(vcpu, cur_flags);
}
static inline void
kvm_reset_guest_updated_vcpu_regs_flags(struct kvm_vcpu *vcpu,
					unsigned long regs_status)
{
	regs_status = KVM_INIT_UPDATED_CPU_REGS_FLAGS(regs_status);
	kvm_put_guest_vcpu_regs_status(vcpu, regs_status);
}

#define CPU_GET_SREG(vcpu, reg_name)					\
({									\
	kvm_cpu_regs_t *regs = &((vcpu)->arch.kmap_vcpu_state->cpu.regs); \
	u32 reg;							\
									\
	reg = regs->CPU_##reg_name;					\
	reg;								\
})
#define CPU_GET_SSREG(vcpu, reg_name)					\
({									\
	kvm_cpu_regs_t *regs = &((vcpu)->arch.kmap_vcpu_state->cpu.regs); \
	int reg;							\
									\
	reg = regs->CPU_##reg_name;					\
	reg;								\
})
#define CPU_GET_DSREG(vcpu, reg_name)					\
({									\
	kvm_cpu_regs_t *regs = &((vcpu)->arch.kmap_vcpu_state->cpu.regs); \
	u64 reg;							\
									\
	reg = regs->CPU_##reg_name;					\
	reg;								\
})

#define CPU_SET_SREG(vcpu, reg_name, reg_value)				\
({									\
	kvm_cpu_regs_t *regs = &((vcpu)->arch.kmap_vcpu_state->cpu.regs); \
									\
	regs->CPU_##reg_name = (reg_value);				\
})
#define CPU_SETUP_SSREG(vcpu, reg_name, reg_value)			\
({									\
	kvm_cpu_regs_t *regs = &((vcpu)->arch.kmap_vcpu_state->cpu.regs); \
									\
	regs->CPU_##reg_name = (u32)(reg_value);			\
})
#define CPU_SET_SSREG(vcpu, reg_name, reg_value)			\
({									\
	kvm_cpu_regs_t *regs = &((vcpu)->arch.kmap_vcpu_state->cpu.regs); \
									\
	regs->CPU_##reg_name = (reg_value);				\
})
#define CPU_SET_DSREG(vcpu, reg_name, reg_value)			\
({									\
	kvm_cpu_regs_t *regs = &((vcpu)->arch.kmap_vcpu_state->cpu.regs); \
									\
	regs->CPU_##reg_name = (reg_value);				\
})

#define CPU_SET_TIR_lo(vcpu, reg_no, reg_value)				\
({									\
	e2k_tir_t *tir = &((vcpu)->arch.kmap_vcpu_state->		\
					cpu.regs.CPU_TIRs[reg_no]);	\
	tir->TIR_lo.TIR_lo_reg = (reg_value);				\
})

#define CPU_SET_TIR_hi(vcpu, reg_no, reg_value)				\
({									\
	e2k_tir_t *tir = &((vcpu)->arch.kmap_vcpu_state->		\
					cpu.regs.CPU_TIRs[reg_no]);	\
	tir->TIR_hi.TIR_hi_reg = (reg_value);				\
})

#define CPU_GET_TIR_lo(vcpu, reg_no)					\
({									\
	e2k_tir_t *tir = &((vcpu)->arch.kmap_vcpu_state->		\
					cpu.regs.CPU_TIRs[reg_no]);	\
	tir->TIR_lo.TIR_lo_reg;						\
})

#define CPU_GET_TIR_hi(vcpu, reg_no)					\
({									\
	e2k_tir_t *tir = &((vcpu)->arch.kmap_vcpu_state->		\
					cpu.regs.CPU_TIRs[reg_no]);	\
	tir->TIR_hi.TIR_hi_reg;						\
})

#define CPU_SET_SBBP(vcpu, reg_no, reg_value)				\
({									\
	u64 *sbbp_reg = &((vcpu)->arch.kmap_vcpu_state->		\
					cpu.regs.CPU_SBBP[reg_no]);	\
	*sbbp_reg = (reg_value);					\
})

#define CPU_COPY_SBBP(vcpu, sbbp_from)					\
({									\
	u64 *sbbp_to = ((vcpu)->arch.kmap_vcpu_state->cpu.regs.CPU_SBBP); \
	if (likely(sbbp_from)) {					\
		memcpy(sbbp_to, sbbp_from, sizeof(*sbbp_to) * SBBP_ENTRIES_NUM); \
	} else {							\
		memset(sbbp_to, 0, sizeof(*sbbp_to) * SBBP_ENTRIES_NUM); \
	}								\
})

#define CPU_GET_SBBP(vcpu, reg_no)					\
({									\
	u64 *sbbp = &((vcpu)->arch.kmap_vcpu_state->			\
					cpu.regs.CPU_SBBP[reg_no]);	\
	*sbbp;								\
})

static inline e2k_aau_t *get_vcpu_aau_context(struct kvm_vcpu *vcpu)
{
	return &(vcpu->arch.kmap_vcpu_state->cpu.aau);
}

static inline u64 *get_vcpu_aaldi_context(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.kmap_vcpu_state->cpu.aaldi;
}

static inline e2k_aalda_t *get_vcpu_aalda_context(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.kmap_vcpu_state->cpu.aalda;
}

#define AAU_GET_SREG(vcpu, reg_name)					\
({									\
	e2k_aau_t *aau = get_vcpu_aau_context(vcpu);			\
	u32 reg;							\
									\
	reg = aau->reg_name;						\
	reg;								\
})

#define AAU_GET_DREG(vcpu, reg_name)					\
({									\
	e2k_aau_t *aau = get_vcpu_aau_context(vcpu);			\
	u64 reg;							\
									\
	reg = aau->reg_name;						\
	reg;								\
})

#define AAU_SET_SREG(vcpu, reg_name, reg_value)				\
({									\
	e2k_aau_t *aau = get_vcpu_aau_context(vcpu);			\
									\
	aau->reg_name = (reg_value);					\
})

#define AAU_SET_DREG(vcpu, reg_name, reg_value)				\
({									\
	e2k_aau_t *aau = get_vcpu_aau_context(vcpu);			\
									\
	aau->reg_name = (reg_value);					\
})

#define AAU_GET_SREGS_ITEM(vcpu, regs_name, reg_no)			\
({									\
	e2k_aau_t *aau = get_vcpu_aau_context(vcpu);			\
	u32 reg;							\
									\
	reg = (aau->regs_name)[reg_no];					\
	reg;								\
})
#define AAU_GET_DREGS_ITEM(vcpu, regs_name, reg_no)			\
({									\
	e2k_aau_t *aau = get_vcpu_aau_context(vcpu);			\
	u64 reg;							\
									\
	reg = (aau->regs_name)[reg_no];					\
	reg;								\
})
#define AAU_GET_STRUCT_REGS_ITEM(vcpu, regs_name, reg_no, reg_struct)	\
({									\
	e2k_aau_t *aau = get_vcpu_aau_context(vcpu);			\
									\
	*(reg_struct) = (aau->regs_name)[reg_no];			\
})
#define AAU_SET_SREGS_ITEM(vcpu, regs_name, reg_no, reg_value)		\
({									\
	e2k_aau_t *aau = get_vcpu_aau_context(vcpu);			\
									\
	(aau->regs_name)[reg_no] = (reg_value);				\
})
#define AAU_SET_DREGS_ITEM(vcpu, regs_name, reg_no, reg_value)		\
({									\
	e2k_aau_t *aau = get_vcpu_aau_context(vcpu);			\
									\
	(aau->regs_name)[reg_no] = (reg_value);				\
})
#define AAU_SET_STRUCT_REGS_ITEM(vcpu, regs_name, reg_no, reg_struct)	\
({									\
	e2k_aau_t *aau = get_vcpu_aau_context(vcpu);			\
									\
	(aau->regs_name)[reg_no] = *(reg_struct);			\
})

#define AAU_COPY_FROM_REGS(vcpu, regs_name, regs_to)			\
({									\
	e2k_aau_t *aau = get_vcpu_aau_context(vcpu);			\
									\
	memcpy(regs_to, aau->regs_name, sizeof(aau->regs_name));	\
})

#define AAU_COPY_TO_REGS(vcpu, regs_name, regs_from)			\
({									\
	e2k_aau_t *aau = get_vcpu_aau_context(vcpu);			\
									\
	memcpy(aau->regs_name, regs_from, sizeof(aau->regs_name));	\
})

static inline const u32
kvm_get_guest_VCPU_ID(struct kvm_vcpu *vcpu)
{
	return CPU_GET_SSREG(vcpu, VCPU_ID);
}
static inline void
kvm_setup_guest_VCPU_ID(struct kvm_vcpu *vcpu, const u32 vcpu_id)
{
	CPU_SETUP_SSREG(vcpu, VCPU_ID, vcpu_id);
}

static inline u64
kvm_get_guest_vcpu_OSCUD_lo_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, OSCUD_lo.OSCUD_lo_half);
}

static inline u64
kvm_get_guest_vcpu_OSCUD_hi_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, OSCUD_hi.OSCUD_hi_half);
}

static inline e2k_oscud_lo_t
kvm_get_guest_vcpu_OSCUD_lo(struct kvm_vcpu *vcpu)
{
	e2k_oscud_lo_t oscud_lo;

	oscud_lo.OSCUD_lo_half = kvm_get_guest_vcpu_OSCUD_lo_value(vcpu);
	return oscud_lo;
}

static inline e2k_oscud_hi_t
kvm_get_guest_vcpu_OSCUD_hi(struct kvm_vcpu *vcpu)
{
	e2k_oscud_hi_t oscud_hi;

	oscud_hi.OSCUD_hi_half = kvm_get_guest_vcpu_OSCUD_hi_value(vcpu);
	return oscud_hi;
}

static inline u64
kvm_get_guest_vcpu_OSGD_lo_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, OSGD_lo.OSGD_lo_half);
}

static inline u64
kvm_get_guest_vcpu_OSGD_hi_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, OSGD_hi.OSGD_hi_half);
}

static inline e2k_osgd_lo_t
kvm_get_guest_vcpu_OSGD_lo(struct kvm_vcpu *vcpu)
{
	e2k_osgd_lo_t osgd_lo;

	osgd_lo.OSGD_lo_half = kvm_get_guest_vcpu_OSGD_lo_value(vcpu);
	return osgd_lo;
}

static inline e2k_osgd_hi_t
kvm_get_guest_vcpu_OSGD_hi(struct kvm_vcpu *vcpu)
{
	e2k_osgd_hi_t osgd_hi;

	osgd_hi.OSGD_hi_half = kvm_get_guest_vcpu_OSGD_hi_value(vcpu);
	return osgd_hi;
}

static inline void
kvm_set_guest_vcpu_WD(struct kvm_vcpu *vcpu, e2k_wd_t WD)
{
	CPU_SET_DSREG(vcpu, WD.WD_reg, WD.WD_reg);
}
static inline u64
kvm_get_guest_vcpu_WD_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, WD.WD_reg);
}
static inline e2k_wd_t
kvm_get_guest_vcpu_WD(struct kvm_vcpu *vcpu)
{
	e2k_wd_t WD;

	WD.WD_reg = kvm_get_guest_vcpu_WD_value(vcpu);
	return WD;
}

static inline void
kvm_set_guest_vcpu_USD_hi(struct kvm_vcpu *vcpu, e2k_usd_hi_t USD_hi)
{
	CPU_SET_DSREG(vcpu, USD_hi.USD_hi_half, USD_hi.USD_hi_half);
}

static inline void
kvm_set_guest_vcpu_USD_lo(struct kvm_vcpu *vcpu, e2k_usd_lo_t USD_lo)
{
	CPU_SET_DSREG(vcpu, USD_lo.USD_lo_half, USD_lo.USD_lo_half);
}
static inline u64
kvm_get_guest_vcpu_USD_hi_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, USD_hi.USD_hi_half);
}
static inline u64
kvm_get_guest_vcpu_USD_lo_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, USD_lo.USD_lo_half);
}
static inline e2k_usd_hi_t
kvm_get_guest_vcpu_USD_hi(struct kvm_vcpu *vcpu)
{
	e2k_usd_hi_t USD_hi;

	USD_hi.USD_hi_half = kvm_get_guest_vcpu_USD_hi_value(vcpu);
	return USD_hi;
}
static inline e2k_usd_lo_t
kvm_get_guest_vcpu_USD_lo(struct kvm_vcpu *vcpu)
{
	e2k_usd_lo_t USD_lo;

	USD_lo.USD_lo_half = kvm_get_guest_vcpu_USD_lo_value(vcpu);
	return USD_lo;
}

static inline void
kvm_set_guest_vcpu_PSHTP(struct kvm_vcpu *vcpu, e2k_pshtp_t PSHTP)
{
	CPU_SET_DSREG(vcpu, PSHTP.PSHTP_reg, PSHTP.PSHTP_reg);
}
static inline u64
kvm_get_guest_vcpu_PSHTP_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, PSHTP.PSHTP_reg);
}
static inline e2k_pshtp_t
kvm_get_guest_vcpu_PSHTP(struct kvm_vcpu *vcpu)
{
	e2k_pshtp_t PSHTP;

	PSHTP.PSHTP_reg = kvm_get_guest_vcpu_PSHTP_value(vcpu);
	return PSHTP;
}

static inline void
kvm_set_guest_vcpu_PCSHTP(struct kvm_vcpu *vcpu, e2k_pcshtp_t PCSHTP)
{
	CPU_SET_SSREG(vcpu, PCSHTP, PCSHTP);
}
static inline e2k_pcshtp_t
kvm_get_guest_vcpu_PCSHTP_svalue(struct kvm_vcpu *vcpu)
{
	return CPU_GET_SSREG(vcpu, PCSHTP);
}

static inline void
kvm_set_guest_vcpu_CR0_hi(struct kvm_vcpu *vcpu, e2k_cr0_hi_t CR0_hi)
{
	CPU_SET_DSREG(vcpu, CR0_hi.CR0_hi_half, CR0_hi.CR0_hi_half);
}

static inline void
kvm_set_guest_vcpu_CR0_lo(struct kvm_vcpu *vcpu, e2k_cr0_lo_t CR0_lo)
{
	CPU_SET_DSREG(vcpu, CR0_lo.CR0_lo_half, CR0_lo.CR0_lo_half);
}

static inline void
kvm_set_guest_vcpu_CR1_hi(struct kvm_vcpu *vcpu, e2k_cr1_hi_t CR1_hi)
{
	CPU_SET_DSREG(vcpu, CR1_hi.CR1_hi_half, CR1_hi.CR1_hi_half);
}

static inline void
kvm_set_guest_vcpu_CR1_lo(struct kvm_vcpu *vcpu, e2k_cr1_lo_t CR1_lo)
{
	CPU_SET_DSREG(vcpu, CR1_lo.CR1_lo_half, CR1_lo.CR1_lo_half);
}
static inline u64
kvm_get_guest_vcpu_CR0_hi_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, CR0_hi.CR0_hi_half);
}
static inline u64
kvm_get_guest_vcpu_CR0_lo_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, CR0_lo.CR0_lo_half);
}
static inline u64
kvm_get_guest_vcpu_CR1_hi_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, CR1_hi.CR1_hi_half);
}
static inline u64
kvm_get_guest_vcpu_CR1_lo_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, CR1_lo.CR1_lo_half);
}
static inline e2k_cr0_hi_t
kvm_get_guest_vcpu_CR0_hi(struct kvm_vcpu *vcpu)
{
	e2k_cr0_hi_t CR0_hi;

	CR0_hi.CR0_hi_half = kvm_get_guest_vcpu_CR0_hi_value(vcpu);
	return CR0_hi;
}
static inline e2k_cr0_lo_t
kvm_get_guest_vcpu_CR0_lo(struct kvm_vcpu *vcpu)
{
	e2k_cr0_lo_t CR0_lo;

	CR0_lo.CR0_lo_half = kvm_get_guest_vcpu_CR0_lo_value(vcpu);
	return CR0_lo;
}
static inline e2k_cr1_hi_t
kvm_get_guest_vcpu_CR1_hi(struct kvm_vcpu *vcpu)
{
	e2k_cr1_hi_t CR1_hi;

	CR1_hi.CR1_hi_half = kvm_get_guest_vcpu_CR1_hi_value(vcpu);
	return CR1_hi;
}
static inline e2k_cr1_lo_t
kvm_get_guest_vcpu_CR1_lo(struct kvm_vcpu *vcpu)
{
	e2k_cr1_lo_t CR1_lo;

	CR1_lo.CR1_lo_half = kvm_get_guest_vcpu_CR1_lo_value(vcpu);
	return CR1_lo;
}

static inline void
kvm_set_guest_vcpu_PSP_hi(struct kvm_vcpu *vcpu, e2k_psp_hi_t PSP_hi)
{
	CPU_SET_DSREG(vcpu, PSP_hi.PSP_hi_half, PSP_hi.PSP_hi_half);
}

static inline void
kvm_set_guest_vcpu_PSP_lo(struct kvm_vcpu *vcpu, e2k_psp_lo_t PSP_lo)
{
	CPU_SET_DSREG(vcpu, PSP_lo.PSP_lo_half, PSP_lo.PSP_lo_half);
}
static inline u64
kvm_get_guest_vcpu_PSP_hi_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, PSP_hi.PSP_hi_half);
}
static inline u64
kvm_get_guest_vcpu_PSP_lo_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, PSP_lo.PSP_lo_half);
}
static inline e2k_psp_hi_t
kvm_get_guest_vcpu_PSP_hi(struct kvm_vcpu *vcpu)
{
	e2k_psp_hi_t PSP_hi;

	PSP_hi.PSP_hi_half = kvm_get_guest_vcpu_PSP_hi_value(vcpu);
	return PSP_hi;
}
static inline e2k_psp_lo_t
kvm_get_guest_vcpu_PSP_lo(struct kvm_vcpu *vcpu)
{
	e2k_psp_lo_t PSP_lo;

	PSP_lo.PSP_lo_half = kvm_get_guest_vcpu_PSP_lo_value(vcpu);
	return PSP_lo;
}

static inline void
kvm_set_guest_vcpu_PCSP_hi(struct kvm_vcpu *vcpu, e2k_pcsp_hi_t PCSP_hi)
{
	CPU_SET_DSREG(vcpu, PCSP_hi.PCSP_hi_half, PCSP_hi.PCSP_hi_half);
}

static inline void
kvm_set_guest_vcpu_PCSP_lo(struct kvm_vcpu *vcpu, e2k_pcsp_lo_t PCSP_lo)
{
	CPU_SET_DSREG(vcpu, PCSP_lo.PCSP_lo_half, PCSP_lo.PCSP_lo_half);
}
static inline u64
kvm_get_guest_vcpu_PCSP_hi_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, PCSP_hi.PCSP_hi_half);
}
static inline u64
kvm_get_guest_vcpu_PCSP_lo_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, PCSP_lo.PCSP_lo_half);
}
static inline e2k_pcsp_hi_t
kvm_get_guest_vcpu_PCSP_hi(struct kvm_vcpu *vcpu)
{
	e2k_pcsp_hi_t PCSP_hi;

	PCSP_hi.PCSP_hi_half = kvm_get_guest_vcpu_PCSP_hi_value(vcpu);
	return PCSP_hi;
}
static inline e2k_pcsp_lo_t
kvm_get_guest_vcpu_PCSP_lo(struct kvm_vcpu *vcpu)
{
	e2k_pcsp_lo_t PCSP_lo;

	PCSP_lo.PCSP_lo_half = kvm_get_guest_vcpu_PCSP_lo_value(vcpu);
	return PCSP_lo;
}

static inline void
kvm_set_guest_vcpu_SBR(struct kvm_vcpu *vcpu, e2k_addr_t sbr)
{
	CPU_SET_DSREG(vcpu, SBR.SBR_reg, sbr);
}

static inline e2k_addr_t
kvm_get_guest_vcpu_SBR_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, SBR.SBR_reg);
}
static inline e2k_sbr_t
kvm_get_guest_vcpu_SBR(struct kvm_vcpu *vcpu)
{
	e2k_sbr_t sbr;

	sbr.SBR_reg = 0;
	sbr.SBR_base = kvm_get_guest_vcpu_SBR_value(vcpu);

	return sbr;
}

static inline void
kvm_set_guest_vcpu_CUD_lo(struct kvm_vcpu *vcpu, e2k_cud_lo_t CUD_lo)
{
	CPU_SET_DSREG(vcpu, CUD_lo.CUD_lo_half, CUD_lo.CUD_lo_half);
}

static inline void
kvm_set_guest_vcpu_CUD_hi(struct kvm_vcpu *vcpu, e2k_cud_hi_t CUD_hi)
{
	CPU_SET_DSREG(vcpu, CUD_hi.CUD_hi_half, CUD_hi.CUD_hi_half);
}

static inline void
kvm_set_guest_vcpu_CUD(struct kvm_vcpu *vcpu, e2k_cud_hi_t CUD_hi,
						e2k_cud_lo_t CUD_lo)
{
	kvm_set_guest_vcpu_CUD_hi(vcpu, CUD_hi);
	kvm_set_guest_vcpu_CUD_lo(vcpu, CUD_lo);
}

static inline void
kvm_set_guest_vcpu_GD_lo(struct kvm_vcpu *vcpu, e2k_gd_lo_t GD_lo)
{
	CPU_SET_DSREG(vcpu, GD_lo.GD_lo_half, GD_lo.GD_lo_half);
}

static inline void
kvm_set_guest_vcpu_GD_hi(struct kvm_vcpu *vcpu, e2k_gd_hi_t GD_hi)
{
	CPU_SET_DSREG(vcpu, GD_hi.GD_hi_half, GD_hi.GD_hi_half);
}

static inline void
kvm_set_guest_vcpu_GD(struct kvm_vcpu *vcpu, e2k_gd_hi_t GD_hi,
						e2k_gd_lo_t GD_lo)
{
	kvm_set_guest_vcpu_GD_hi(vcpu, GD_hi);
	kvm_set_guest_vcpu_GD_lo(vcpu, GD_lo);
}

static inline void
kvm_set_guest_vcpu_OSCUD_lo(struct kvm_vcpu *vcpu, e2k_oscud_lo_t OSCUD_lo)
{
	CPU_SET_DSREG(vcpu, OSCUD_lo.OSCUD_lo_half, OSCUD_lo.OSCUD_lo_half);
}

static inline void
kvm_set_guest_vcpu_OSCUD_hi(struct kvm_vcpu *vcpu, e2k_oscud_hi_t OSCUD_hi)
{
	CPU_SET_DSREG(vcpu, OSCUD_hi.OSCUD_hi_half, OSCUD_hi.OSCUD_hi_half);
}

static inline void
kvm_set_guest_vcpu_OSCUD(struct kvm_vcpu *vcpu, e2k_oscud_hi_t OSCUD_hi,
						e2k_oscud_lo_t OSCUD_lo)
{
	kvm_set_guest_vcpu_OSCUD_hi(vcpu, OSCUD_hi);
	kvm_set_guest_vcpu_OSCUD_lo(vcpu, OSCUD_lo);
}

static inline void
kvm_set_guest_vcpu_OSGD_lo(struct kvm_vcpu *vcpu, e2k_osgd_lo_t OSGD_lo)
{
	CPU_SET_DSREG(vcpu, OSGD_lo.OSGD_lo_half, OSGD_lo.OSGD_lo_half);
}

static inline void
kvm_set_guest_vcpu_OSGD_hi(struct kvm_vcpu *vcpu, e2k_osgd_hi_t OSGD_hi)
{
	CPU_SET_DSREG(vcpu, OSGD_hi.OSGD_hi_half, OSGD_hi.OSGD_hi_half);
}

static inline void
kvm_set_guest_vcpu_OSGD(struct kvm_vcpu *vcpu, e2k_osgd_hi_t OSGD_hi,
						e2k_osgd_lo_t OSGD_lo)
{
	kvm_set_guest_vcpu_OSGD_hi(vcpu, OSGD_hi);
	kvm_set_guest_vcpu_OSGD_lo(vcpu, OSGD_lo);
}

static inline void
kvm_set_guest_vcpu_CUTD(struct kvm_vcpu *vcpu, e2k_cutd_t CUTD)
{
	CPU_SET_DSREG(vcpu, CUTD.CUTD_reg, CUTD.CUTD_reg);
}
static inline unsigned long
kvm_get_guest_vcpu_CUTD_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, CUTD.CUTD_reg);
}
static inline e2k_cutd_t
kvm_get_guest_vcpu_CUTD(struct kvm_vcpu *vcpu)
{
	e2k_cutd_t cutd;

	cutd.CUTD_reg = kvm_get_guest_vcpu_CUTD_value(vcpu);
	return cutd;
}

static inline void
kvm_set_guest_vcpu_CUIR(struct kvm_vcpu *vcpu, e2k_cuir_t CUIR)
{
	CPU_SET_SSREG(vcpu, CUIR.CUIR_reg, CUIR.CUIR_reg);
}
static inline unsigned int
kvm_get_guest_vcpu_CUIR_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_SSREG(vcpu, CUIR.CUIR_reg);
}
static inline e2k_cuir_t
kvm_get_guest_vcpu_CUIR(struct kvm_vcpu *vcpu)
{
	e2k_cuir_t cuir;

	cuir.CUIR_reg = kvm_get_guest_vcpu_CUIR_value(vcpu);
	return cuir;
}

static inline void
kvm_set_guest_vcpu_OSCUTD(struct kvm_vcpu *vcpu, e2k_cutd_t CUTD)
{
	CPU_SET_DSREG(vcpu, OSCUTD.CUTD_reg, CUTD.CUTD_reg);
}
static inline unsigned long
kvm_get_guest_vcpu_OSCUTD_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, OSCUTD.CUTD_reg);
}
static inline e2k_cutd_t
kvm_get_guest_vcpu_OSCUTD(struct kvm_vcpu *vcpu)
{
	e2k_cutd_t cutd;

	cutd.CUTD_reg = kvm_get_guest_vcpu_OSCUTD_value(vcpu);
	return cutd;
}

static inline void
kvm_set_guest_vcpu_OSCUIR(struct kvm_vcpu *vcpu, e2k_cuir_t CUIR)
{
	CPU_SET_SSREG(vcpu, OSCUIR.CUIR_reg, CUIR.CUIR_reg);
}
static inline unsigned int
kvm_get_guest_vcpu_OSCUIR_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_SSREG(vcpu, OSCUIR.CUIR_reg);
}
static inline e2k_cuir_t
kvm_get_guest_vcpu_OSCUIR(struct kvm_vcpu *vcpu)
{
	e2k_cuir_t cuir;

	cuir.CUIR_reg = kvm_get_guest_vcpu_OSCUIR_value(vcpu);
	return cuir;
}

static inline void
kvm_set_guest_vcpu_OSR0(struct kvm_vcpu *vcpu, u64 osr0)
{
	CPU_SET_DSREG(vcpu, OSR0, osr0);
}
static inline unsigned long
kvm_get_guest_vcpu_OSR0_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, OSR0);
}
static inline void
kvm_set_guest_vcpu_IDR(struct kvm_vcpu *vcpu, e2k_idr_t idr)
{
	CPU_SET_DSREG(vcpu, IDR.IDR_reg, idr.IDR_reg);
}
static inline unsigned long
kvm_get_guest_vcpu_IDR_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, IDR.IDR_reg);
}
static inline e2k_idr_t
kvm_get_guest_vcpu_IDR(struct kvm_vcpu *vcpu)
{
	e2k_idr_t idr;

	idr.IDR_reg = kvm_get_guest_vcpu_IDR_value(vcpu);
	return idr;
}
static inline bool
kvm_is_guest_irq_mask_global(struct kvm_vcpu *vcpu)
{
	e2k_idr_t idr;

	idr = kvm_get_guest_vcpu_IDR(vcpu);
	return idr.IDR_mdl == IDR_E2K_VIRT_MDL && idr.IDR_rev != 0;
}

#define	IS_GM_IRQ_MASK_GLOBAL(vcpu)	kvm_is_guest_irq_mask_global(vcpu)

static inline void
kvm_set_guest_vcpu_CORE_MODE(struct kvm_vcpu *vcpu, e2k_core_mode_t core_mode)
{
	CPU_SET_SSREG(vcpu, CORE_MODE.CORE_MODE_reg, core_mode.CORE_MODE_reg);
}
static inline unsigned int
kvm_get_guest_vcpu_CORE_MODE_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_SSREG(vcpu, CORE_MODE.CORE_MODE_reg);
}
static inline e2k_core_mode_t
kvm_get_guest_vcpu_CORE_MODE(struct kvm_vcpu *vcpu)
{
	e2k_core_mode_t core_mode;

	core_mode.CORE_MODE_reg = kvm_get_guest_vcpu_CORE_MODE_value(vcpu);
	return core_mode;
}

static inline void
kvm_set_guest_vcpu_PSR(struct kvm_vcpu *vcpu, e2k_psr_t psr)
{
	CPU_SET_SSREG(vcpu, E2K_PSR.PSR_reg, psr.PSR_reg);
}
static inline unsigned int
kvm_get_guest_vcpu_PSR_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_SSREG(vcpu, E2K_PSR.PSR_reg);
}
static inline e2k_psr_t
kvm_get_guest_vcpu_PSR(struct kvm_vcpu *vcpu)
{
	e2k_psr_t psr;

	psr.PSR_reg = kvm_get_guest_vcpu_PSR_value(vcpu);
	return psr;
}

static inline void
kvm_set_guest_vcpu_UPSR(struct kvm_vcpu *vcpu, e2k_upsr_t upsr)
{
	CPU_SET_SSREG(vcpu, UPSR.UPSR_reg, upsr.UPSR_reg);
}
static inline unsigned int
kvm_get_guest_vcpu_UPSR_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_SSREG(vcpu, UPSR.UPSR_reg);
}
static inline e2k_upsr_t
kvm_get_guest_vcpu_UPSR(struct kvm_vcpu *vcpu)
{
	e2k_upsr_t upsr;

	upsr.UPSR_reg = kvm_get_guest_vcpu_UPSR_value(vcpu);
	return upsr;
}

static inline void
kvm_set_guest_vcpu_under_upsr(struct kvm_vcpu *vcpu, bool under_upsr)
{
	if (likely(IS_GM_IRQ_MASK_GLOBAL(vcpu))) {
		E2K_KVM_BUG_ON(under_upsr);
		return;
	}
	VCPU_IRQS_UNDER_UPSR(vcpu) = under_upsr;
}
static inline bool
kvm_get_guest_vcpu_under_upsr(struct kvm_vcpu *vcpu)
{
	if (likely(IS_GM_IRQ_MASK_GLOBAL(vcpu))) {
		E2K_KVM_BUG_ON(VCPU_IRQS_UNDER_UPSR(vcpu));
		return false;
	}
	return VCPU_IRQS_UNDER_UPSR(vcpu);
}

static inline u64
kvm_get_guest_vcpu_CTPR_value(struct kvm_vcpu *vcpu, int CTPR_no)
{
	switch (CTPR_no) {
	case 1: return CPU_GET_DSREG(vcpu, CTPR1.CTPR_reg);
		break;
	case 2: return CPU_GET_DSREG(vcpu, CTPR2.CTPR_reg);
		break;
	case 3: return CPU_GET_DSREG(vcpu, CTPR3.CTPR_reg);
		break;
	default:
		BUG_ON(true);
		return -1UL;
	}
}
static inline e2k_ctpr_t
kvm_get_guest_vcpu_CTPR(struct kvm_vcpu *vcpu, int CTPR_no)
{
	e2k_ctpr_t CTPR;

	CTPR.CTPR_reg = kvm_get_guest_vcpu_CTPR_value(vcpu, CTPR_no);
	return CTPR;
}
static inline e2k_ctpr_t
kvm_get_guest_vcpu_CTPR1(struct kvm_vcpu *vcpu)
{
	return kvm_get_guest_vcpu_CTPR(vcpu, 1);
}
static inline e2k_ctpr_t
kvm_get_guest_vcpu_CTPR2(struct kvm_vcpu *vcpu)
{
	return kvm_get_guest_vcpu_CTPR(vcpu, 2);
}
static inline e2k_ctpr_t
kvm_get_guest_vcpu_CTPR3(struct kvm_vcpu *vcpu)
{
	return kvm_get_guest_vcpu_CTPR(vcpu, 3);
}

static inline void
kvm_set_guest_vcpu_CTPR(struct kvm_vcpu *vcpu, e2k_ctpr_t CTPR, int CTPR_no)
{
	switch (CTPR_no) {
	case 1:
		CPU_SET_DSREG(vcpu, CTPR1.CTPR_reg, CTPR.CTPR_reg);
		break;
	case 2:
		CPU_SET_DSREG(vcpu, CTPR2.CTPR_reg, CTPR.CTPR_reg);
		break;
	case 3:
		CPU_SET_DSREG(vcpu, CTPR3.CTPR_reg, CTPR.CTPR_reg);
		break;
	default:
		BUG_ON(true);
	}
}
static inline void
kvm_set_guest_vcpu_CTPR1(struct kvm_vcpu *vcpu, e2k_ctpr_t CTPR)
{
	kvm_set_guest_vcpu_CTPR(vcpu, CTPR, 1);
}
static inline void
kvm_set_guest_vcpu_CTPR2(struct kvm_vcpu *vcpu, e2k_ctpr_t CTPR)
{
	kvm_set_guest_vcpu_CTPR(vcpu, CTPR, 2);
}
static inline void
kvm_set_guest_vcpu_CTPR3(struct kvm_vcpu *vcpu, e2k_ctpr_t CTPR)
{
	kvm_set_guest_vcpu_CTPR(vcpu, CTPR, 3);
}

static inline void
kvm_set_guest_vcpu_LSR(struct kvm_vcpu *vcpu, u64 lsr)
{
	CPU_SET_DSREG(vcpu, LSR.LSR_reg, lsr);
}
static inline void
kvm_set_guest_vcpu_LSR1(struct kvm_vcpu *vcpu, u64 lsr1)
{
	CPU_SET_DSREG(vcpu, LSR1.LSR_reg, lsr1);
}
static inline u64
kvm_get_guest_vcpu_LSR_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, LSR.LSR_reg);
}

static inline void
kvm_set_guest_vcpu_ILCR(struct kvm_vcpu *vcpu, u64 ilcr)
{
	CPU_SET_DSREG(vcpu, ILCR.ILCR_reg, ilcr);
}
static inline void
kvm_set_guest_vcpu_ILCR1(struct kvm_vcpu *vcpu, u64 ilcr1)
{
	CPU_SET_DSREG(vcpu, ILCR1.ILCR_reg, ilcr1);
}
static inline u64
kvm_get_guest_vcpu_ILCR_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, ILCR.ILCR_reg);
}

static inline void
kvm_set_guest_vcpu_SBBP(struct kvm_vcpu *vcpu, int sbbp_no, u64 sbbp)
{
	CPU_SET_SBBP(vcpu, sbbp_no, sbbp);
}

static inline void
kvm_copy_guest_vcpu_SBBP(struct kvm_vcpu *vcpu, u64 *sbbp)
{
	CPU_COPY_SBBP(vcpu, sbbp);
}

static inline u64
kvm_get_guest_vcpu_SBBP(struct kvm_vcpu *vcpu, int sbbp_no)
{
	u64 sbbp;

	BUG_ON(sbbp_no > SBBP_ENTRIES_NUM);
	sbbp = CPU_GET_SBBP(vcpu, sbbp_no);
	return sbbp;
}

static inline void
kvm_set_guest_vcpu_TIR_lo(struct kvm_vcpu *vcpu,
				int TIR_no, e2k_tir_lo_t TIR_lo)
{
	CPU_SET_TIR_lo(vcpu, TIR_no, TIR_lo.TIR_lo_reg);
}

static inline void
kvm_set_guest_vcpu_TIR_hi(struct kvm_vcpu *vcpu,
				int TIR_no, e2k_tir_hi_t TIR_hi)
{
	CPU_SET_TIR_hi(vcpu, TIR_no, TIR_hi.TIR_hi_reg);
}

static inline void
kvm_set_guest_vcpu_TIRs_num(struct kvm_vcpu *vcpu, int TIRs_num)
{
	CPU_SET_SREG(vcpu, TIRs_num, TIRs_num);
}

static inline void
kvm_reset_guest_vcpu_TIRs_num(struct kvm_vcpu *vcpu)
{
	kvm_set_guest_vcpu_TIRs_num(vcpu, -1);
}

static inline int
kvm_get_guest_vcpu_TIRs_num(struct kvm_vcpu *vcpu)
{
	return CPU_GET_SREG(vcpu, TIRs_num);
}

static inline e2k_tir_lo_t
kvm_get_guest_vcpu_TIR_lo(struct kvm_vcpu *vcpu, int TIR_no)
{
	e2k_tir_lo_t TIR_lo;

	BUG_ON(TIR_no > kvm_get_guest_vcpu_TIRs_num(vcpu));
	TIR_lo.TIR_lo_reg = CPU_GET_TIR_lo(vcpu, TIR_no);
	return TIR_lo;
}

static inline e2k_tir_hi_t
kvm_get_guest_vcpu_TIR_hi(struct kvm_vcpu *vcpu, int TIR_no)
{
	e2k_tir_hi_t TIR_hi;

	BUG_ON(TIR_no > kvm_get_guest_vcpu_TIRs_num(vcpu));
	TIR_hi.TIR_hi_reg = CPU_GET_TIR_hi(vcpu, TIR_no);
	return TIR_hi;
}

static inline bool kvm_check_is_guest_TIRs_empty(struct kvm_vcpu *vcpu)
{
	if (kvm_get_guest_vcpu_TIRs_num(vcpu) < 0)
		return true;
	/* TIRs have traps */
	return false;
}

static inline unsigned long
kvm_update_guest_vcpu_TIR(struct kvm_vcpu *vcpu,
		int TIR_no, e2k_tir_hi_t TIR_hi, e2k_tir_lo_t TIR_lo)
{
	e2k_tir_lo_t g_TIR_lo;
	e2k_tir_hi_t g_TIR_hi;
	unsigned long trap_mask;
	int TIRs_num;
	int tir;

	TIRs_num = kvm_get_guest_vcpu_TIRs_num(vcpu);
	if (TIRs_num < TIR_no) {
		for (tir = TIRs_num + 1; tir < TIR_no; tir++) {
			g_TIR_lo.TIR_lo_reg = GET_CLEAR_TIR_LO(tir);
			g_TIR_hi.TIR_hi_reg = GET_CLEAR_TIR_HI(tir);
			kvm_set_guest_vcpu_TIR_lo(vcpu, tir, g_TIR_lo);
			kvm_set_guest_vcpu_TIR_hi(vcpu, tir, g_TIR_hi);
		}
		g_TIR_lo.TIR_lo_reg = GET_CLEAR_TIR_LO(TIR_no);
		g_TIR_hi.TIR_hi_reg = GET_CLEAR_TIR_HI(TIR_no);
	} else {
		g_TIR_hi = kvm_get_guest_vcpu_TIR_hi(vcpu, TIR_no);
		g_TIR_lo = kvm_get_guest_vcpu_TIR_lo(vcpu, TIR_no);
		BUG_ON(g_TIR_hi.TIR_hi_j != TIR_no);
		if (TIR_lo.TIR_lo_ip == 0 && g_TIR_lo.TIR_lo_ip != 0)
			/* some traps can be caused by kernel and have not */
			/* precision IP (for example hardware stack bounds) */
			TIR_lo.TIR_lo_ip = g_TIR_lo.TIR_lo_ip;
		else if (TIR_lo.TIR_lo_ip != 0 && g_TIR_lo.TIR_lo_ip == 0)
			/* new trap IP will be common for other traps */
			;
		else
			BUG_ON(g_TIR_lo.TIR_lo_ip != TIR_lo.TIR_lo_ip);
	}
	g_TIR_hi.TIR_hi_reg |= TIR_hi.TIR_hi_reg;
	g_TIR_lo.TIR_lo_reg |= TIR_lo.TIR_lo_reg;
	kvm_set_guest_vcpu_TIR_hi(vcpu, TIR_no, g_TIR_hi);
	kvm_set_guest_vcpu_TIR_lo(vcpu, TIR_no, g_TIR_lo);
	trap_mask = TIR_hi.TIR_hi_exc;
	trap_mask |= SET_AA_TIRS(0UL, GET_AA_TIRS(TIR_hi.TIR_hi_reg));
	if (TIR_no > TIRs_num)
		kvm_set_guest_vcpu_TIRs_num(vcpu, TIR_no);
	return trap_mask;
}

static inline bool kvm_guest_vcpu_irqs_disabled(struct kvm_vcpu *vcpu,
				unsigned long upsr_reg, unsigned long psr_reg)
{
	if (likely((IS_GM_IRQ_MASK_GLOBAL(vcpu)))) {
		return psr_glob_irqs_disabled_flags(psr_reg);
	} else {
		return psr_and_upsr_loc_irqs_disabled_flags(psr_reg, upsr_reg);
	}
}

static inline bool
kvm_guest_vcpu_irqs_under_upsr_flags(struct kvm_vcpu *vcpu, unsigned long psr_reg)
{
	if (likely((IS_GM_IRQ_MASK_GLOBAL(vcpu)))) {
		return false;
	} else {
		return all_loc_irqs_under_upsr_flags(psr_reg);
	}
}

static inline bool kvm_get_guest_vcpu_sge(struct kvm_vcpu *vcpu)
{
	unsigned long psr_reg;

	psr_reg = kvm_get_guest_vcpu_PSR_value(vcpu);
	return (psr_reg & PSR_SGE) != 0;
}

/* VCPU AAU context model access */

static inline void
kvm_set_guest_vcpu_aasr_value(struct kvm_vcpu *vcpu, u32 reg_value)
{
	CPU_SET_SREG(vcpu, AASR.word, reg_value);
}
static inline void
kvm_set_guest_vcpu_aasr(struct kvm_vcpu *vcpu, e2k_aasr_t aasr)
{
	kvm_set_guest_vcpu_aasr_value(vcpu, AW(aasr));
}

static inline u32
kvm_get_guest_vcpu_aasr_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_SREG(vcpu, AASR.word);
}
static inline e2k_aasr_t
kvm_get_guest_vcpu_aasr(struct kvm_vcpu *vcpu)
{
	e2k_aasr_t aasr;

	AW(aasr) = kvm_get_guest_vcpu_aasr_value(vcpu);
	return aasr;
}

static inline void
kvm_set_guest_vcpu_aafstr_value(struct kvm_vcpu *vcpu, u32 reg_value)
{
	AAU_SET_SREG(vcpu, aafstr, reg_value);
}

static inline u32
kvm_get_guest_vcpu_aafstr_value(struct kvm_vcpu *vcpu)
{
	return AAU_GET_SREG(vcpu, aafstr);
}

static inline void
kvm_set_guest_vcpu_aaldm_value(struct kvm_vcpu *vcpu, u64 reg_value)
{
	AAU_SET_DREG(vcpu, aaldm.word, reg_value);
}
static inline void
kvm_set_guest_vcpu_aaldm(struct kvm_vcpu *vcpu, e2k_aaldm_t aaldm)
{
	kvm_set_guest_vcpu_aaldm_value(vcpu, AW(aaldm));
}

static inline u64
kvm_get_guest_vcpu_aaldm_value(struct kvm_vcpu *vcpu)
{
	return AAU_GET_DREG(vcpu, aaldm.word);
}
static inline e2k_aaldm_t
kvm_get_guest_vcpu_aaldm(struct kvm_vcpu *vcpu)
{
	e2k_aaldm_t aaldm;

	AW(aaldm) = kvm_get_guest_vcpu_aaldm_value(vcpu);
	return aaldm;
}
static inline void
kvm_set_guest_vcpu_aaldv_value(struct kvm_vcpu *vcpu, u64 reg_value)
{
	AAU_SET_DREG(vcpu, aaldv.word, reg_value);
}
static inline void
kvm_set_guest_vcpu_aaldv(struct kvm_vcpu *vcpu, e2k_aaldv_t aaldv)
{
	kvm_set_guest_vcpu_aaldv_value(vcpu, AW(aaldv));
}

static inline u64
kvm_get_guest_vcpu_aaldv_value(struct kvm_vcpu *vcpu)
{
	return AAU_GET_DREG(vcpu, aaldv.word);
}
static inline e2k_aaldv_t
kvm_get_guest_vcpu_aaldv(struct kvm_vcpu *vcpu)
{
	e2k_aaldv_t aaldv;

	AW(aaldv) = kvm_get_guest_vcpu_aaldv_value(vcpu);
	return aaldv;
}

static inline void
kvm_set_guest_vcpu_aasti_value(struct kvm_vcpu *vcpu, int AASTI_no, u64 value)
{
	AAU_SET_DREGS_ITEM(vcpu, aastis, AASTI_no, value);
}
static inline u64
kvm_get_guest_vcpu_aasti_value(struct kvm_vcpu *vcpu, int AASTI_no)
{
	return AAU_GET_DREGS_ITEM(vcpu, aastis, AASTI_no);
}
static inline void
kvm_set_guest_vcpu_aasti_tags_value(struct kvm_vcpu *vcpu, u32 reg_value)
{
	AAU_SET_SREG(vcpu, aasti_tags, reg_value);
}
static inline u32
kvm_get_guest_vcpu_aasti_tags_value(struct kvm_vcpu *vcpu)
{
	return AAU_GET_SREG(vcpu, aasti_tags);
}
static inline void
kvm_copy_to_guest_vcpu_aastis(struct kvm_vcpu *vcpu, u64 *aastis_from)
{
	AAU_COPY_TO_REGS(vcpu, aastis, aastis_from);
}
static inline void
kvm_copy_from_guest_vcpu_aastis(struct kvm_vcpu *vcpu, u64 *aastis_to)
{
	AAU_COPY_FROM_REGS(vcpu, aastis, aastis_to);
}

static inline void
kvm_set_guest_vcpu_aaind_value(struct kvm_vcpu *vcpu, int AAIND_no, u64 value)
{
	AAU_SET_DREGS_ITEM(vcpu, aainds, AAIND_no, value);
}
static inline u64
kvm_get_guest_vcpu_aaind_value(struct kvm_vcpu *vcpu, int AAIND_no)
{
	return AAU_GET_DREGS_ITEM(vcpu, aainds, AAIND_no);
}
static inline void
kvm_set_guest_vcpu_aaind_tags_value(struct kvm_vcpu *vcpu, u32 reg_value)
{
	AAU_SET_SREG(vcpu, aaind_tags, reg_value);
}
static inline u32
kvm_get_guest_vcpu_aaind_tags_value(struct kvm_vcpu *vcpu)
{
	return AAU_GET_SREG(vcpu, aaind_tags);
}
static inline void
kvm_copy_to_guest_vcpu_aainds(struct kvm_vcpu *vcpu, u64 *aainds_from)
{
	AAU_COPY_TO_REGS(vcpu, aainds, aainds_from);
}
static inline void
kvm_copy_from_guest_vcpu_aainds(struct kvm_vcpu *vcpu, u64 *aainds_to)
{
	AAU_COPY_FROM_REGS(vcpu, aainds, aainds_to);
}

static inline void
kvm_set_guest_vcpu_aaincr_value(struct kvm_vcpu *vcpu, int AAINCR_no, u64 value)
{
	AAU_SET_DREGS_ITEM(vcpu, aaincrs, AAINCR_no, value);
}
static inline u64
kvm_get_guest_vcpu_aaincr_value(struct kvm_vcpu *vcpu, int AAINCR_no)
{
	return AAU_GET_DREGS_ITEM(vcpu, aaincrs, AAINCR_no);
}
static inline void
kvm_set_guest_vcpu_aaincr_tags_value(struct kvm_vcpu *vcpu, u32 reg_value)
{
	AAU_SET_SREG(vcpu, aaincr_tags, reg_value);
}
static inline u32
kvm_get_guest_vcpu_aaincr_tags_value(struct kvm_vcpu *vcpu)
{
	return AAU_GET_SREG(vcpu, aaincr_tags);
}
static inline void
kvm_copy_to_guest_vcpu_aaincrs(struct kvm_vcpu *vcpu, u64 *aaincrs_from)
{
	AAU_COPY_TO_REGS(vcpu, aaincrs, aaincrs_from);
}
static inline void
kvm_copy_from_guest_vcpu_aaincrs(struct kvm_vcpu *vcpu, u64 *aaincrs_to)
{
	AAU_COPY_FROM_REGS(vcpu, aaincrs, aaincrs_to);
}

static inline void
kvm_copy_to_guest_vcpu_aaldis(struct kvm_vcpu *vcpu, u64 *aaldis_from)
{
	u64 *aaldi = get_vcpu_aaldi_context(vcpu);
	memcpy(aaldi, aaldis_from, AALDIS_REGS_NUM * sizeof(aaldi[0]));
}

static inline void
kvm_copy_from_guest_vcpu_aaldis(struct kvm_vcpu *vcpu, u64 *aaldis_to)
{
	u64 *aaldi = get_vcpu_aaldi_context(vcpu);
	memcpy(aaldis_to, aaldi, AALDIS_REGS_NUM * sizeof(aaldi[0]));
}

static inline void
kvm_copy_to_guest_vcpu_aaldas(struct kvm_vcpu *vcpu, e2k_aalda_t *aaldas_from)
{
	e2k_aalda_t *aalda = get_vcpu_aalda_context(vcpu);
	memcpy(aalda, aaldas_from, AALDAS_REGS_NUM * sizeof(aalda[0]));
}
static inline void
kvm_copy_from_guest_vcpu_aaldas(struct kvm_vcpu *vcpu, e2k_aalda_t *aaldas_to)
{
	e2k_aalda_t *aalda = get_vcpu_aalda_context(vcpu);
	memcpy(aaldas_to, aalda, AALDAS_REGS_NUM * sizeof(aalda[0]));
}

static inline void
kvm_set_guest_vcpu_aad(struct kvm_vcpu *vcpu, int AAD_no, e2k_aadj_t *aad)
{
	AAU_SET_STRUCT_REGS_ITEM(vcpu, aads, AAD_no, aad);
}
static inline void
kvm_get_guest_vcpu_aad(struct kvm_vcpu *vcpu, int AAD_no, e2k_aadj_t *aad)
{
	AAU_GET_STRUCT_REGS_ITEM(vcpu, aads, AAD_no, aad);
}
static inline void
kvm_copy_to_guest_vcpu_aads(struct kvm_vcpu *vcpu, e2k_aadj_t *aads_from)
{
	AAU_COPY_TO_REGS(vcpu, aads, aads_from);
}
static inline void
kvm_copy_from_guest_vcpu_aads(struct kvm_vcpu *vcpu, e2k_aadj_t *aads_to)
{
	AAU_COPY_FROM_REGS(vcpu, aads, aads_to);
}

#endif	/* __KVM_E2K_CPU_DEFS_H */
