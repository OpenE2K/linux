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

static inline u64 kvm_get_guest_vcpu_regs_status(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.kmap_vcpu_state->cpu.regs_status;
}

static inline void
kvm_put_guest_vcpu_regs_status(struct kvm_vcpu *vcpu, unsigned long new_status)
{
	vcpu->arch.kmap_vcpu_state->cpu.regs_status = new_status;
}

static inline void kvm_reset_guest_vcpu_regs_status(struct kvm_vcpu *vcpu)
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

#define CPU_SET_TIR(vcpu, reg_no, TIR)					\
({									\
	e2k_tir_t *tir = &((vcpu)->arch.kmap_vcpu_state->		\
					cpu.regs.CPU_TIRs[reg_no]);	\
	*tir = TIR;							\
})

#define CPU_GET_TIR(vcpu, reg_no)					\
	((vcpu)->arch.kmap_vcpu_state->cpu.regs.CPU_TIRs[reg_no]);

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

static inline const u32 kvm_get_guest_VCPU_ID(struct kvm_vcpu *vcpu)
{
	return CPU_GET_SSREG(vcpu, VCPU_ID);
}

static inline void
kvm_setup_guest_VCPU_ID(struct kvm_vcpu *vcpu, const u32 vcpu_id)
{
	CPU_SETUP_SSREG(vcpu, VCPU_ID, vcpu_id);
}

static inline e2k_cud_t kvm_get_guest_vcpu_OSCUD(struct kvm_vcpu *vcpu)
{
	return (e2k_cud_t) {
		.lo = CPU_GET_DSREG(vcpu, OSCUD.lo),
		.hi = CPU_GET_DSREG(vcpu, OSCUD.hi)
	};
}

static inline void
kvm_set_guest_vcpu_OSCUD(struct kvm_vcpu *vcpu, e2k_cud_t CUD)
{
	CPU_SET_DSREG(vcpu, OSCUD.lo, CUD.lo);
	CPU_SET_DSREG(vcpu, OSCUD.hi, CUD.hi);
}

static inline e2k_gd_t kvm_get_guest_vcpu_OSGD(struct kvm_vcpu *vcpu)
{
	return (e2k_gd_t) {
		.lo = CPU_GET_DSREG(vcpu, OSGD.lo),
		.hi = CPU_GET_DSREG(vcpu, OSGD.hi)
	};
}

static inline void kvm_set_guest_vcpu_OSGD(struct kvm_vcpu *vcpu, e2k_gd_t GD)
{
	CPU_SET_DSREG(vcpu, OSGD.lo, GD.lo);
	CPU_SET_DSREG(vcpu, OSGD.hi, GD.hi);
}

static inline void kvm_set_guest_vcpu_WD(struct kvm_vcpu *vcpu, e2k_wd_t WD)
{
	CPU_SET_DSREG(vcpu, WD.word, WD.word);
}

static inline e2k_wd_t kvm_get_guest_vcpu_WD(struct kvm_vcpu *vcpu)
{
	return (e2k_wd_t) {
		.word = CPU_GET_DSREG(vcpu, WD.word)
	};
}

static inline e2k_usd_t kvm_get_guest_vcpu_USD(struct kvm_vcpu *vcpu)
{
	return (e2k_usd_t) {
		.lo = CPU_GET_DSREG(vcpu, USD.lo),
		.hi = CPU_GET_DSREG(vcpu, USD.hi)
	};
}

static inline void kvm_set_guest_vcpu_USD(struct kvm_vcpu *vcpu, e2k_usd_t USD)
{
	CPU_SET_DSREG(vcpu, USD.lo, USD.lo);
	CPU_SET_DSREG(vcpu, USD.hi, USD.hi);
}

static inline void
kvm_set_guest_vcpu_PSHTP(struct kvm_vcpu *vcpu, e2k_pshtp_t PSHTP)
{
	CPU_SET_DSREG(vcpu, PSHTP, PSHTP);
}

static inline e2k_pshtp_t kvm_get_guest_vcpu_PSHTP(struct kvm_vcpu *vcpu)
{
	return (e2k_pshtp_t) {
		.word = CPU_GET_DSREG(vcpu, PSHTP.word)
	};
}

static inline void
kvm_set_guest_vcpu_PCSHTP(struct kvm_vcpu *vcpu, e2k_pcshtp_t PCSHTP)
{
	CPU_SET_SSREG(vcpu, PCSHTP, PCSHTP);
}

static inline e2k_pcshtp_t kvm_get_guest_vcpu_PCSHTP(struct kvm_vcpu *vcpu)
{
	return (e2k_pcshtp_t) {
		.word = CPU_GET_SSREG(vcpu, PCSHTP.word)
	};
}

static inline e2k_cr0_t kvm_get_guest_vcpu_CR0(struct kvm_vcpu *vcpu)
{
	return (e2k_cr0_t) {
		.lo = CPU_GET_DSREG(vcpu, _CR0.lo),
		.hi = CPU_GET_DSREG(vcpu, _CR0.hi)
	};
}

static inline e2k_cr1_t kvm_get_guest_vcpu_CR1(struct kvm_vcpu *vcpu)
{
	return (e2k_cr1_t) {
		.lo = CPU_GET_DSREG(vcpu, _CR1.lo),
		.hi = CPU_GET_DSREG(vcpu, _CR1.hi)
	};
}

static inline void kvm_set_guest_vcpu_CR0(struct kvm_vcpu *vcpu, e2k_cr0_t cr0)
{
	CPU_SET_DSREG(vcpu, _CR0.lo, cr0.lo);
	CPU_SET_DSREG(vcpu, _CR0.hi, cr0.hi);
}

static inline void kvm_set_guest_vcpu_CR1(struct kvm_vcpu *vcpu, e2k_cr1_t cr1)
{
	CPU_SET_DSREG(vcpu, _CR1.lo, cr1.lo);
	CPU_SET_DSREG(vcpu, _CR1.hi, cr1.hi);
}

static inline e2k_psp_t kvm_get_guest_vcpu_PSP(struct kvm_vcpu *vcpu)
{
	return (e2k_psp_t) {
		.lo = CPU_GET_DSREG(vcpu, PSP.lo),
		.hi = CPU_GET_DSREG(vcpu, PSP.hi)
	};
}

static inline void kvm_set_guest_vcpu_PSP(struct kvm_vcpu *vcpu, e2k_psp_t PSP)
{
	CPU_SET_DSREG(vcpu, PSP.lo, PSP.lo);
	CPU_SET_DSREG(vcpu, PSP.hi, PSP.hi);
}

static inline e2k_pcsp_t kvm_get_guest_vcpu_PCSP(struct kvm_vcpu *vcpu)
{
	return (e2k_pcsp_t) {
		.lo = CPU_GET_DSREG(vcpu, PCSP.lo),
		.hi = CPU_GET_DSREG(vcpu, PCSP.hi)
	};
}

static inline void
kvm_set_guest_vcpu_PCSP(struct kvm_vcpu *vcpu, e2k_pcsp_t PCSP)
{
	CPU_SET_DSREG(vcpu, PCSP.lo, PCSP.lo);
	CPU_SET_DSREG(vcpu, PCSP.hi, PCSP.hi);
}

static inline void kvm_set_guest_vcpu_SBR(struct kvm_vcpu *vcpu, e2k_sbr_t sbr)
{
	CPU_SET_DSREG(vcpu, SBR, sbr);
}

static inline e2k_addr_t kvm_get_guest_vcpu_SBR_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, SBR.word);
}

static inline e2k_sbr_t kvm_get_guest_vcpu_SBR(struct kvm_vcpu *vcpu)
{
	return (e2k_sbr_t) {
	.base = kvm_get_guest_vcpu_SBR_value(vcpu)};
}

static inline void kvm_set_guest_vcpu_CUD(struct kvm_vcpu *vcpu, e2k_cud_t CUD)
{
	CPU_SET_DSREG(vcpu, CUD.lo, CUD.lo);
	CPU_SET_DSREG(vcpu, CUD.hi, CUD.hi);
}

static inline void kvm_set_guest_vcpu_GD(struct kvm_vcpu *vcpu, e2k_gd_t GD)
{
	CPU_SET_DSREG(vcpu, GD.lo, GD.lo);
	CPU_SET_DSREG(vcpu, GD.hi, GD.hi);
}

static inline void
kvm_set_guest_vcpu_CUTD(struct kvm_vcpu *vcpu, e2k_cutd_t CUTD)
{
	CPU_SET_DSREG(vcpu, CUTD, CUTD);
}

static inline e2k_cutd_t kvm_get_guest_vcpu_CUTD(struct kvm_vcpu *vcpu)
{
	return (e2k_cutd_t) {
		.word = CPU_GET_DSREG(vcpu, CUTD.word)
	};
}

static inline void
kvm_set_guest_vcpu_CUIR(struct kvm_vcpu *vcpu, e2k_cuir_t CUIR)
{
	CPU_SET_SSREG(vcpu, CUIR, CUIR);
}

static inline e2k_cuir_t kvm_get_guest_vcpu_CUIR(struct kvm_vcpu *vcpu)
{
	return (e2k_cuir_t) {
		.word = CPU_GET_SSREG(vcpu, CUIR.word)
	};
}

static inline void
kvm_set_guest_vcpu_OSCUTD(struct kvm_vcpu *vcpu, e2k_cutd_t CUTD)
{
	CPU_SET_DSREG(vcpu, OSCUTD, CUTD);
}

static inline e2k_cutd_t kvm_get_guest_vcpu_OSCUTD(struct kvm_vcpu *vcpu)
{
	return (e2k_cutd_t) {
		.word = CPU_GET_DSREG(vcpu, OSCUTD.word)
	};
}

static inline void
kvm_set_guest_vcpu_OSCUIR(struct kvm_vcpu *vcpu, e2k_cuir_t CUIR)
{
	CPU_SET_SSREG(vcpu, OSCUIR.word, CUIR.word);
}

static inline e2k_cuir_t kvm_get_guest_vcpu_OSCUIR(struct kvm_vcpu *vcpu)
{
	return (e2k_cuir_t) {
		.word = CPU_GET_SSREG(vcpu, OSCUIR.word)
	};
}

static inline u64 kvm_get_guest_vcpu_OSR0(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, OSR0);
}

static inline u64 kvm_get_guest_vcpu_OSR1(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, OSR1);
}

static inline void kvm_set_guest_vcpu_OSR0(struct kvm_vcpu *vcpu, u64 osr0)
{
	CPU_SET_DSREG(vcpu, OSR0, osr0);
}

static inline void kvm_set_guest_vcpu_OSR1(struct kvm_vcpu *vcpu, u64 osr1)
{
	CPU_SET_DSREG(vcpu, OSR1, osr1);
}

static inline unsigned int
kvm_get_guest_vcpu_CORE_MODE_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_SSREG(vcpu, CORE_MODE.word);
}

static inline void kvm_set_guest_vcpu_IDR(struct kvm_vcpu *vcpu, e2k_idr_t idr)
{
	CPU_SET_DSREG(vcpu, IDR.word, AW(idr));
}

static inline unsigned long kvm_get_guest_vcpu_IDR_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, IDR.word);
}

static inline e2k_idr_t kvm_get_guest_vcpu_IDR(struct kvm_vcpu *vcpu)
{
	e2k_idr_t idr;

	AW(idr) = kvm_get_guest_vcpu_IDR_value(vcpu);
	return idr;
}

static inline bool kvm_is_guest_irq_mask_global(struct kvm_vcpu *vcpu)
{
	e2k_idr_t idr;

	idr = kvm_get_guest_vcpu_IDR(vcpu);
	return idr.mdl == IDR_E2K_VIRT_MDL && idr.rev != 0;
}

#define	IS_GM_IRQ_MASK_GLOBAL(vcpu)	kvm_is_guest_irq_mask_global(vcpu)

static inline void
kvm_set_guest_vcpu_CORE_MODE(struct kvm_vcpu *vcpu, e2k_core_mode_t core_mode)
{
	CPU_SET_SSREG(vcpu, CORE_MODE.word, core_mode.word);
}

static inline e2k_core_mode_t
kvm_get_guest_vcpu_CORE_MODE(struct kvm_vcpu *vcpu)
{
	return (e2k_core_mode_t) {
		.word = CPU_GET_SSREG(vcpu, CORE_MODE.word)
	};
}

static inline void kvm_set_guest_vcpu_PSR(struct kvm_vcpu *vcpu, e2k_psr_t psr)
{
	CPU_SET_SSREG(vcpu, E2K_PSR.word, psr.word);
}

static inline e2k_psr_t kvm_get_guest_vcpu_PSR(struct kvm_vcpu *vcpu)
{
	return (e2k_psr_t) {
		.word = CPU_GET_SSREG(vcpu, E2K_PSR.word)
	};
}

static inline void
kvm_set_guest_vcpu_UPSR(struct kvm_vcpu *vcpu, e2k_upsr_t upsr)
{
	CPU_SET_SSREG(vcpu, UPSR.word, upsr.word);
}

static inline e2k_upsr_t kvm_get_guest_vcpu_UPSR(struct kvm_vcpu *vcpu)
{
	return TOS(e2k_upsr_t, CPU_GET_SSREG(vcpu, UPSR.word));
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

static inline bool kvm_get_guest_vcpu_under_upsr(struct kvm_vcpu *vcpu)
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
	case 1:
		return CPU_GET_DSREG(vcpu, CTPR1.lo);
		break;
	case 2:
		return CPU_GET_DSREG(vcpu, CTPR2.lo);
		break;
	case 3:
		return CPU_GET_DSREG(vcpu, CTPR3.lo);
		break;
	default:
		BUG_ON(true);
		return -1UL;
	}
}

static inline e2k_ctpr_t
kvm_get_guest_vcpu_CTPR(struct kvm_vcpu *vcpu, int CTPR_no)
{
	return (e2k_ctpr_t) {
		.lo = kvm_get_guest_vcpu_CTPR_value(vcpu, CTPR_no),
		.hi = 0, /* TODO */
	};
}

static inline e2k_ctpr_t kvm_get_guest_vcpu_CTPR1(struct kvm_vcpu *vcpu)
{
	return kvm_get_guest_vcpu_CTPR(vcpu, 1);
}

static inline e2k_ctpr_t kvm_get_guest_vcpu_CTPR2(struct kvm_vcpu *vcpu)
{
	return kvm_get_guest_vcpu_CTPR(vcpu, 2);
}

static inline e2k_ctpr_t kvm_get_guest_vcpu_CTPR3(struct kvm_vcpu *vcpu)
{
	return kvm_get_guest_vcpu_CTPR(vcpu, 3);
}

static inline void
kvm_set_guest_vcpu_CTPR(struct kvm_vcpu *vcpu, e2k_ctpr_t CTPR, int CTPR_no)
{
	switch (CTPR_no) {
	case 1:
		CPU_SET_DSREG(vcpu, CTPR1.lo, CTPR.lo);
		CPU_SET_DSREG(vcpu, CTPR1.hi, CTPR.hi);
		break;
	case 2:
		CPU_SET_DSREG(vcpu, CTPR2.lo, CTPR.lo);
		CPU_SET_DSREG(vcpu, CTPR2.hi, CTPR.hi);
		break;
	case 3:
		CPU_SET_DSREG(vcpu, CTPR3.lo, CTPR.lo);
		CPU_SET_DSREG(vcpu, CTPR3.hi, CTPR.hi);
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

static inline void kvm_set_guest_vcpu_LSR(struct kvm_vcpu *vcpu, u64 lsr)
{
	CPU_SET_DSREG(vcpu, LSR.word, lsr);
}

static inline void kvm_set_guest_vcpu_LSR1(struct kvm_vcpu *vcpu, u64 lsr1)
{
	CPU_SET_DSREG(vcpu, LSR1.word, lsr1);
}

static inline u64 kvm_get_guest_vcpu_LSR_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, LSR.word);
}

static inline void kvm_set_guest_vcpu_ILCR(struct kvm_vcpu *vcpu, u64 ilcr)
{
	CPU_SET_DSREG(vcpu, ILCR.word, ilcr);
}

static inline void kvm_set_guest_vcpu_ILCR1(struct kvm_vcpu *vcpu, u64 ilcr1)
{
	CPU_SET_DSREG(vcpu, ILCR1.word, ilcr1);
}

static inline u64 kvm_get_guest_vcpu_ILCR_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_DSREG(vcpu, ILCR.word);
}

static inline void
kvm_set_guest_vcpu_SBBP(struct kvm_vcpu *vcpu, int sbbp_no, u64 sbbp)
{
	CPU_SET_SBBP(vcpu, sbbp_no, sbbp);
}

static inline void kvm_copy_guest_vcpu_SBBP(struct kvm_vcpu *vcpu, u64 *sbbp)
{
	CPU_COPY_SBBP(vcpu, sbbp);
}

static inline u64 kvm_get_guest_vcpu_SBBP(struct kvm_vcpu *vcpu, int sbbp_no)
{
	u64 sbbp;

	BUG_ON(sbbp_no > SBBP_ENTRIES_NUM);
	sbbp = CPU_GET_SBBP(vcpu, sbbp_no);
	return sbbp;
}

static inline void
kvm_set_guest_vcpu_TIR(struct kvm_vcpu *vcpu, int TIR_no, e2k_tir_t TIR)
{
	CPU_SET_TIR(vcpu, TIR_no, TIR);
}

static inline void
kvm_set_guest_vcpu_TIRs_num(struct kvm_vcpu *vcpu, int TIRs_num)
{
	CPU_SET_SREG(vcpu, TIRs_num, TIRs_num);
}

static inline void kvm_reset_guest_vcpu_TIRs_num(struct kvm_vcpu *vcpu)
{
	kvm_set_guest_vcpu_TIRs_num(vcpu, -1);
}

static inline int kvm_get_guest_vcpu_TIRs_num(struct kvm_vcpu *vcpu)
{
	return CPU_GET_SREG(vcpu, TIRs_num);
}

static inline e2k_tir_t
kvm_get_guest_vcpu_TIR(struct kvm_vcpu *vcpu, int TIR_no)
{
	BUG_ON(TIR_no > kvm_get_guest_vcpu_TIRs_num(vcpu));
	return CPU_GET_TIR(vcpu, TIR_no);
}

static inline bool kvm_check_is_guest_TIRs_empty(struct kvm_vcpu *vcpu)
{
	return (kvm_get_guest_vcpu_TIRs_num(vcpu) < 0);
}

static inline unsigned long
kvm_update_guest_vcpu_TIR(struct kvm_vcpu *vcpu, int TIR_no, e2k_tir_t TIR)
{
	e2k_tir_t g_TIR;
	unsigned long trap_mask;
	int TIRs_num;
	int tir;

	TIRs_num = kvm_get_guest_vcpu_TIRs_num(vcpu);
	if (TIRs_num < TIR_no) {
		for (tir = TIRs_num + 1; tir < TIR_no; tir++) {
			g_TIR.lo = GET_CLEAR_TIR_LO(tir);
			g_TIR.hi = GET_CLEAR_TIR_HI(tir);
			kvm_set_guest_vcpu_TIR(vcpu, tir, g_TIR);
		}
		g_TIR.lo = GET_CLEAR_TIR_LO(TIR_no);
		g_TIR.hi = GET_CLEAR_TIR_HI(tir);
	} else {
		g_TIR = kvm_get_guest_vcpu_TIR(vcpu, TIR_no);
		BUG_ON(g_TIR.j != TIR_no);
		if (TIR.ip == 0 && g_TIR.ip != 0)
			/* some traps can be caused by kernel and have not */
			/* precision IP (for example hardware stack bounds) */
			TIR.ip = g_TIR.ip;
		else if (TIR.ip != 0 && g_TIR.ip == 0)
			/* new trap IP will be common for other traps */
			;
		else
			BUG_ON(g_TIR.ip != TIR.ip);
	}
	g_TIR.hi |= TIR.hi;
	g_TIR.lo |= TIR.lo;
	kvm_set_guest_vcpu_TIR(vcpu, TIR_no, g_TIR);
	trap_mask = TIR.exc;
	trap_mask |= SET_MASK_AA_TIRS(TIR.aa);
	if (TIR_no > TIRs_num)
		kvm_set_guest_vcpu_TIRs_num(vcpu, TIR_no);
	return trap_mask;
}

static inline bool kvm_guest_vcpu_irqs_disabled(struct kvm_vcpu *vcpu,
						unsigned long upsr_reg,
						unsigned long psr_reg)
{
	if (likely((IS_GM_IRQ_MASK_GLOBAL(vcpu)))) {
		return psr_glob_irqs_disabled_flags(psr_reg);
	} else {
		return psr_and_upsr_loc_irqs_disabled_flags(psr_reg, upsr_reg);
	}
}

static inline bool
kvm_guest_vcpu_irqs_under_upsr_flags(struct kvm_vcpu *vcpu,
				     unsigned long psr_reg)
{
	if (likely((IS_GM_IRQ_MASK_GLOBAL(vcpu)))) {
		return false;
	} else {
		return all_loc_irqs_under_upsr_flags(psr_reg);
	}
}

static inline bool kvm_get_guest_vcpu_sge(struct kvm_vcpu *vcpu)
{
	return kvm_get_guest_vcpu_PSR(vcpu).sge;
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

static inline u32 kvm_get_guest_vcpu_aasr_value(struct kvm_vcpu *vcpu)
{
	return CPU_GET_SREG(vcpu, AASR.word);
}

static inline e2k_aasr_t kvm_get_guest_vcpu_aasr(struct kvm_vcpu *vcpu)
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

static inline u32 kvm_get_guest_vcpu_aafstr_value(struct kvm_vcpu *vcpu)
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

static inline u64 kvm_get_guest_vcpu_aaldm_value(struct kvm_vcpu *vcpu)
{
	return AAU_GET_DREG(vcpu, aaldm.word);
}

static inline e2k_aaldm_t kvm_get_guest_vcpu_aaldm(struct kvm_vcpu *vcpu)
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

static inline u64 kvm_get_guest_vcpu_aaldv_value(struct kvm_vcpu *vcpu)
{
	return AAU_GET_DREG(vcpu, aaldv.word);
}

static inline e2k_aaldv_t kvm_get_guest_vcpu_aaldv(struct kvm_vcpu *vcpu)
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

static inline u32 kvm_get_guest_vcpu_aasti_tags_value(struct kvm_vcpu *vcpu)
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

static inline u32 kvm_get_guest_vcpu_aaind_tags_value(struct kvm_vcpu *vcpu)
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

static inline u32 kvm_get_guest_vcpu_aaincr_tags_value(struct kvm_vcpu *vcpu)
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

#endif /* __KVM_E2K_CPU_DEFS_H */
