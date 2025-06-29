/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef	_E2K_KVM_CPU_HV_REGS_ACCESS_H_
#define	_E2K_KVM_CPU_HV_REGS_ACCESS_H_

#ifdef __KERNEL__

#ifndef __ASSEMBLY__

#include <linux/kvm_host.h>
#include <asm/e2k_api.h>
#include <asm/kvm/cpu_hv_regs_types.h>
#include <asm/machdep.h>
#include <asm/kvm/machdep.h>
#include <asm/kvm/vcpu-descr-regs.h>

/*
 * Read/Write guest descriptor-registers using operations 'rrsh/rwsh'
 * to preserve the old (v6) and new (v7) format of registers
 */

static __always_inline e2k_usd_t native_read_sh_USD_reg(void)
{
	u64 lo = NATIVE_RRSH_DSREG_CLOSED_ISET(7, usd.lo);
	u64 hi = NATIVE_RRSH_DSREG_CLOSED_ISET(7, usd.hi);
	return (e2k_usd_t) { .lo = lo, .hi = hi };
}

static __always_inline void native_write_sh_USD_reg(e2k_usd_t usd)
{
	NATIVE_RWSH_DSREG_CLOSED_ISET(7, usd.hi, usd.hi);
	NATIVE_RWSH_DSREG_CLOSED_ISET(7, usd.lo, usd.lo);
}

/*
 * Virtualization control registers
 */

static __always_inline virt_ctrl_cu_t read_VIRT_CTRL_CU_reg(void)
{
	return (virt_ctrl_cu_t) {
		.word = NATIVE_GET_DSREG_CLOSED_ISET(6, virt_ctrl_cu)
	};
}

static __always_inline void write_VIRT_CTRL_CU_reg(virt_ctrl_cu_t vcc)
{
/* Bug #127239: on some CPUs "rwd %virt_ctrl_cu" instruction must also
 * contain a NOP.  This is already accomplished by using delay "5" here. */

	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, virt_ctrl_cu, vcc.word, 5, 7);
}

/* Shadow CPU registers */

/*
 * Read/write low/high double-word OS Compilation Unit Descriptor (SH_OSCUD)
 */

static __always_inline e2k_cud_t read_SH_OSCUD_reg(void)
{
	return (e2k_cud_t) {
		.lo = NATIVE_GET_DSREG_CLOSED_ISET(6, sh_oscud.lo),
		.hi = NATIVE_GET_DSREG_CLOSED_ISET(6, sh_oscud.hi)
	};
}

static __always_inline void write_SH_OSCUD_reg(e2k_cud_t cud)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, sh_oscud.lo, cud.lo, 5, 7);
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, sh_oscud.hi, cud.hi, 5, 7);
}

/*
 * Read/write low/hgh double-word OS Globals Register (SH_OSGD)
 */

static __always_inline e2k_gd_t read_SH_OSGD_reg(void)
{
	return (e2k_gd_t) {
		.lo = NATIVE_GET_DSREG_CLOSED_ISET(6, sh_osgd.lo),
		.hi = NATIVE_GET_DSREG_CLOSED_ISET(6, sh_osgd.hi)
	};
}

static __always_inline void write_SH_OSGD_reg(e2k_gd_t osgd)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, sh_osgd.lo, osgd.lo, 5, 7);
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, sh_osgd.hi, osgd.hi, 5, 7);
}

/*
 * Read/write low/high quad-word Procedure Stack Pointer Register
 * (SH_PSP, backup BU_PSP)
 */

static __always_inline e2k_psp_t read_SH_PSP_reg(void)
{
	return (e2k_psp_t) {
		.lo = NATIVE_GET_DSREG_CLOSED_ISET(6, sh_psp.lo),
		.hi = NATIVE_GET_DSREG_CLOSED_ISET(6, sh_psp.hi)
	};
}

static __always_inline void write_SH_PSP_reg(e2k_psp_t psp)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, sh_psp.lo, psp.lo, 5, 7);
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, sh_psp.hi, psp.hi, 5, 7);
}

static __always_inline e2k_psp_t read_BU_PSP_reg(void)
{
	return (e2k_psp_t) {
		.lo = NATIVE_GET_DSREG_CLOSED_ISET(6, bu_psp.lo),
		.hi = NATIVE_GET_DSREG_CLOSED_ISET(6, bu_psp.hi)
	};
}

static __always_inline void write_BU_PSP_reg(e2k_psp_t psp)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, bu_psp.lo, psp.lo, 5, 7);
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, bu_psp.hi, psp.hi, 5, 7);
}

/*
 * Read/write low/high quad-word Procedure Chain Stack Pointer Register
 * (SH_PCSP, backup registers BU_PCSP)
 */

static __always_inline e2k_pcsp_t read_SH_PCSP_reg(void)
{
	return (e2k_pcsp_t) {
		.lo = NATIVE_GET_DSREG_CLOSED_ISET(6, sh_pcsp.lo),
		.hi = NATIVE_GET_DSREG_CLOSED_ISET(6, sh_pcsp.hi)
	};
}

static __always_inline void write_SH_PCSP_reg(e2k_pcsp_t pcsp)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, sh_pcsp.lo, pcsp.lo, 5, 7);
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, sh_pcsp.hi, pcsp.hi, 5, 7);
}

static __always_inline e2k_pcsp_t read_BU_PCSP_reg(void)
{
	return (e2k_pcsp_t) {
		.lo = NATIVE_GET_DSREG_CLOSED_ISET(6, bu_pcsp.lo),
		.hi = NATIVE_GET_DSREG_CLOSED_ISET(6, bu_pcsp.hi)
	};
}

static __always_inline void write_BU_PCSP_reg(e2k_pcsp_t pcsp)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, bu_pcsp.lo, pcsp.lo, 5, 7);
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, bu_pcsp.hi, pcsp.hi, 5, 7);
}

/*
 * Read/write word Procedure Stack Harware Top Pointer (SH_PSHTP)
 */

static __always_inline e2k_pshtp_t read_SH_PSHTP_reg(void)
{
	return (e2k_pshtp_t) {
		.word = NATIVE_GET_DSREG_CLOSED_ISET(6, sh_pshtp)
	};
}

static __always_inline void write_SH_PSHTP_reg(e2k_pshtp_t pshtp)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, sh_pshtp, pshtp.word, 5, 7);
}


/*
 * Read/write word Procedure Chain Stack Harware Top Pointer (SH_PCSHTP)
 * and shadow pointer (SH_PCSHTP)
 */

static __always_inline e2k_pcshtp_t read_SH_PCSHTP_reg(void)
{
	return (e2k_pcshtp_t) {
		.word = NATIVE_GET_SREG_CLOSED_ISET(6, sh_pcshtp)
	};
}

static __always_inline void write_SH_PCSHTP_reg(e2k_pcshtp_t pcshtp)
{
	NATIVE_SET_SREG_CLOSED_NOEXC_ISET(6, sh_pcshtp, AW(pcshtp), 5, 7);
}


/*
 * Read/write current window descriptor register (SH_WD)
 */

static __always_inline e2k_wd_t read_SH_WD_reg(void)
{
	return (e2k_wd_t) {
		.word = NATIVE_GET_DSREG_CLOSED_ISET(6, sh_wd)
	};
}

static __always_inline void write_SH_WD_reg(e2k_wd_t wd)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, sh_wd, AW(wd), 5, 7);
}

/*
 * Read/write CPU enhanced system clock shadow registers
 */

static __always_inline u64 read_SH_T_off_reg(void)
{
	return NATIVE_GET_DSREG_CLOSED_ISET(7, sh_t_off);
}

static __always_inline void write_SH_T_off_reg(u64 off)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(7, sh_t_off, off, 6, 6);
}

/*
 * Read/write OS register which point to current process thread info
 * structure (SH_OSR0)
 */

static __always_inline u64 read_SH_OSR0_reg_value(void)
{
	return (u64)NATIVE_GET_DSREG_CLOSED_ISET(6, sh_osr0);
}

static __always_inline void write_SH_OSR0_reg_value(u64 osr0)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, sh_osr0, osr0, 5, 6);
}

/*
 * Read/Write system clock registers (SH_SCLKM3)
 */

static __always_inline u64 read_SH_SCLKM3_reg_value(void)
{
	return (u64) NATIVE_GET_DSREG_CLOSED_ISET(6, sh_sclkm3);

}

static __always_inline void write_SH_SCLKM3_reg_value(u64 val)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, sh_sclkm3, val, 4, 6);
}

/*
 * Read/write double-word Compilation Unit Table Register (SH_OSCUTD)
 */

static __always_inline e2k_cutd_t read_SH_OSCUTD_reg(void)
{
	return (e2k_cutd_t) {
		.word = NATIVE_GET_DSREG_CLOSED_ISET(6, sh_oscutd)
	};
}

static __always_inline void write_SH_OSCUTD_reg(e2k_cutd_t cutd)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, sh_oscutd, cutd.word, 7, 7);
}

/*
 * Read/write word Compilation Unit Index Register (SH_OSCUIR)
 */

static __always_inline e2k_cuir_t read_SH_OSCUIR_reg(void)
{
	return (e2k_cuir_t) {
		.word = NATIVE_GET_SREG_CLOSED_ISET(6, sh_oscuir)
	};
}

static __always_inline void write_SH_OSCUIR_reg(e2k_cuir_t oscuir)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, sh_oscuir, oscuir.word, 7, 7);
}

/*
 * Read/Write Processor Core Mode Register (SH_CORE_MODE)
 */

static __always_inline e2k_core_mode_t read_SH_CORE_MODE_reg(void)
{
	return (e2k_core_mode_t) {
		.word = NATIVE_GET_SREG_CLOSED_ISET(6, sh_core_mode)
	};
}

static __always_inline void write_SH_CORE_MODE_reg(e2k_core_mode_t cm)
{
	NATIVE_SET_SREG_CLOSED_NOEXC_ISET(6, sh_core_mode, AW(cm), 5, 7);
}


/*
 * Read/Write G_PREEMPT_TMR register
 */
static __always_inline e2k_g_preempt_tmr_t read_G_PREEMPT_TMR_reg(void)
{
	return (e2k_g_preempt_tmr_t) {
		.word = NATIVE_GET_DSREG_CLOSED(g_preempt_tmr)
	};
}

static __always_inline void write_G_PREEMPT_TMR_reg(e2k_g_preempt_tmr_t gpt)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, g_preempt_tmr, AW(gpt), 5, 7);
}

/*
 * Read/Write INTC_PTR_CU and INTC_INFO_CU registers
 */

static __always_inline u64 read_INTC_PTR_CU_reg_value(void)
{
	return (u64) NATIVE_GET_DSREG_CLOSED_ISET(6, intc_ptr_cu);
}

static __always_inline u64 read_INTC_INFO_CU_reg_value(void)
{
	return (u64) NATIVE_GET_DSREG_CLOSED_ISET(6, intc_info_cu);
}

static __always_inline void write_INTC_INFO_CU_reg_value(u64 v)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, intc_info_cu, v, 5, 7);
}

/* Clear INTC_INFO_CU header and INTC_PTR_CU */
static inline void clear_intc_info_cu(void)
{
	(void)read_INTC_PTR_CU_reg_value();
	write_INTC_INFO_CU_reg_value(0ULL);
	write_INTC_INFO_CU_reg_value(0ULL);
	(void)read_INTC_PTR_CU_reg_value();
}

static inline void save_intc_info_cu(intc_info_cu_t *info, int *num)
{
	u64 info_ptr, i = 0;

	/*
	 * The read of INTC_PTR will clear the hardware pointer,
	 * but the subsequent reads fo INTC_INFO will increase
	 * it again until it reaches the same value it had before.
	 */
	info_ptr = read_INTC_PTR_CU_reg_value();
	if (!info_ptr) {
		*num = -1;
		info->header.lo = 0;
		info->header.hi = 0;
		return;
	}

	info->header.lo = read_INTC_INFO_CU_reg_value();
	info->header.hi = read_INTC_INFO_CU_reg_value();
	info_ptr -= 2;

	/*
	 * Read intercepted events list
	 */
	for (; info_ptr > 0; info_ptr -= 2) {
		info->entry[i].lo = read_INTC_INFO_CU_reg_value();
		info->entry[i].hi = read_INTC_INFO_CU_reg_value();
		info->entry[i].no_restore = false;
		++i;
	};

	*num = i;
}

static inline void restore_intc_info_cu(const intc_info_cu_t *info, int num)
{
	int i;

	/* Clear the pointer, in case we just migrated to new cpu */
	(void)read_INTC_PTR_CU_reg_value();

	/* Header will be cleared by hardware during GLAUNCH */
	if (num == -1 || num == 0)
		return;

	/*
	 * Restore intercepted events. Header flags aren't used for reexecution,
	 * so restore 0 in header.
	 */
	write_INTC_INFO_CU_reg_value(0ULL);
	write_INTC_INFO_CU_reg_value(0ULL);
	for (i = 0; i < num; i++) {
		if (!info->entry[i].no_restore) {
			write_INTC_INFO_CU_reg_value(info->entry[i].lo);
			write_INTC_INFO_CU_reg_value(info->entry[i].hi);
		}
	}
}

static inline void kvm_reset_intc_info_cu_is_updated(struct kvm_vcpu *vcpu)
{
	vcpu->arch.intc_ctxt.cu_updated = false;
}

static inline void kvm_set_intc_info_cu_is_updated(struct kvm_vcpu *vcpu)
{
	vcpu->arch.intc_ctxt.cu_updated = true;
}

static inline bool kvm_get_intc_info_cu_is_updated(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.intc_ctxt.cu_updated;
}

static __always_inline e2k_usd_t
vcpu_read_sh_usd_reg_v7(struct kvm_vcpu *vcpu)
{
	/* use always rrsh/rwsh operations to access descriptor registers */
	return native_read_sh_USD_reg();
}

static __always_inline e2k_usd_t
vcpu_read_usd_reg(struct kvm_vcpu *vcpu)
{
	/* host & guest have always same old or new format */
	return native_read_USD_reg();
}

static __always_inline e2k_usd_t
vcpu_save_usd_reg_v7(struct kvm_vcpu *vcpu, bool to_guest)
{
	/*
	 * host & guest can have different descriptor-registers format:
	 *	host always has v7 format
	 *	guest can have both format v7 or v6
	 */
	if (to_guest) {
		/* host saved, guest restored */
		return vcpu_read_usd_reg(vcpu);
	} else {
		/* guest saved, host restored */
		if (vcpu_descr_v7(vcpu)) {
			/* guest has same v7 format */
			return vcpu_read_usd_reg(vcpu);
		} else {
			/* guest has old format of registers, use 'rrsh' */
			return vcpu_read_sh_usd_reg_v7(vcpu);
		}
	}
}

/* registers-descriptor access (read/write) */

static __always_inline e2k_usd_t
vcpu_save_usd_reg(struct kvm_vcpu *vcpu, bool to_guest)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return vcpu_save_usd_reg_v7(vcpu, to_guest);
	} else {
		return vcpu_read_usd_reg(vcpu);
	}
}

static __always_inline void
vcpu_write_sh_usd_reg_v7(struct kvm_vcpu *vcpu, e2k_usd_t usd)
{
	/* use always rrsh/rwsh operations to access descriptor registers */
	return native_write_sh_USD_reg(usd);
}

static __always_inline void
vcpu_write_usd_sbr_reg(struct kvm_vcpu *vcpu, e2k_sbr_t sbr, e2k_usd_t usd)
{
	/* host & guest have always native descriptor-registers old format v6 */
	native_write_USBR_USD_regs(sbr, usd);
}

static __always_inline void
vcpu_restore_usd_sbr_reg_v7(struct kvm_vcpu *vcpu, e2k_sbr_t sbr, e2k_usd_t usd,
			    bool to_guest)
{
	/*
	 * host & guest can have different descriptor-registers format:
	 *	host always has v7 format
	 *	guest can have both format v7 or v6
	 */
	if (to_guest) {
		/* guest restored, host saved */
		if (vcpu_descr_v7(vcpu)) {
			/* guest has new format of registers same as host */
			vcpu_write_usd_sbr_reg(vcpu, sbr, usd);
		} else {
			/* guest has old format of registers, use 'rwsh' */
			native_write_USBR_reg(sbr);
			vcpu_write_sh_usd_reg_v7(vcpu, usd);
		}
	} else {
		/* host restored, guest saved,  */
		vcpu_write_usd_sbr_reg(vcpu, sbr, usd);
	}
}

static __always_inline void
vcpu_restore_usd_sbr_reg(struct kvm_vcpu *vcpu, e2k_sbr_t sbr, e2k_usd_t usd,
			 bool to_guest)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		vcpu_restore_usd_sbr_reg_v7(vcpu, sbr, usd, to_guest);
	} else {
		vcpu_write_usd_sbr_reg(vcpu, sbr, usd);
	}
}

static __always_inline e2k_usincr_t
vcpu_save_usincr_reg_v7(struct kvm_vcpu *vcpu, bool to_guest)
{
	if (to_guest) {
		/* host saved, guest restored */
		return native_read_USINCR_reg();
	} else {
		/* guest saved, host restored */
		if (vcpu_getsp_v7(vcpu)) {
			/* guest support the register */
			return native_read_USINCR_reg();
		} else {
			/* guest does not support this register */
			return (e2k_usincr_t){ .word = 0 };
		}
	}
}

static __always_inline e2k_usincr_t
vcpu_save_usincr_reg_v6(struct kvm_vcpu *vcpu)
{
	/* host & guest have not this register */
	return (e2k_usincr_t) { .word = 0 };
}

static __always_inline e2k_usincr_t
vcpu_save_usincr_reg(struct kvm_vcpu *vcpu, bool to_guest)
{
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		return vcpu_save_usincr_reg_v7(vcpu, to_guest);
	} else {
		return vcpu_save_usincr_reg_v6(vcpu);
	}
}

static __always_inline void
vcpu_restore_usincr_reg_v7(struct kvm_vcpu *vcpu, e2k_usincr_t usincr, bool to_guest)
{
	if (to_guest) {
		/* guest restored, host saved */
		if (vcpu_getsp_v7(vcpu)) {
			/* guest support the register */
			native_write_USINCR_reg(usincr);
		} else {
			/* guest does not support this register */
			;
		}
	} else {
		/* host restored, guest saved */
		native_write_USINCR_reg(usincr);
	}
}

static __always_inline void
vcpu_restore_usincr_reg_v6(struct kvm_vcpu *vcpu, e2k_usincr_t usincr)
{
	/* host & guest have not this register */
}

static __always_inline void
vcpu_restore_usincr_reg(struct kvm_vcpu *vcpu, e2k_usincr_t usincr, bool to_guest)
{
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		return vcpu_restore_usincr_reg_v7(vcpu, usincr, to_guest);
	} else {
		return vcpu_restore_usincr_reg_v6(vcpu, usincr);
	}
}

static __always_inline void
vcpu_restore_us_cl_low_v7(struct kvm_vcpu *vcpu, clw_reg_t us_cl_up, u64 usd_lo)
{
	if (vcpu_descr_v7(vcpu)) {
		/* guest has new format of registers same as host */
		RESTORE_US_CL_LOW(us_cl_up, usd_lo);
	} else {
		/* guest has old format of registers, use 'rwsh' */
		RESTORE_US_CL_LOW_V7_FOR_V6(us_cl_up, usd_lo);
	}
}

static __always_inline void
vcpu_restore_us_cl_low(struct kvm_vcpu *vcpu, clw_reg_t us_cl_up, u64 usd_lo)
{
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		vcpu_restore_us_cl_low_v7(vcpu, us_cl_up, usd_lo);
	} else {
		RESTORE_US_CL_LOW(us_cl_up, usd_lo);
	}
}

#endif /*  __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif /* _E2K_KVM_CPU_HV_REGS_ACCESS_H_ */
