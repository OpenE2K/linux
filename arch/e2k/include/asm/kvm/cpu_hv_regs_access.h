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

static __always_inline e2k_usd_t native_read_guest_USD_reg(void)
{
	u64 lo = RRSH_DREG(usd.lo);
	u64 hi = RRSH_DREG(usd.hi);
	return (e2k_usd_t) { .lo = lo, .hi = hi };
}

/*
 * Virtualization control registers
 */

static __always_inline virt_ctrl_cu_t read_VIRT_CTRL_CU_reg(void)
{
	return (virt_ctrl_cu_t) {
		.word = NATIVE_GET_DREG_CLOSED_ISET(6, virt_ctrl_cu)
	};
}

static __always_inline void write_VIRT_CTRL_CU_reg(virt_ctrl_cu_t vcc)
{
	NATIVE_SET_VIRT_CTRL_CU(vcc.word);
}

/* Shadow CPU registers */

/*
 * Read/write low/high double-word OS Compilation Unit Descriptor (SH_OSCUD)
 */

static __always_inline e2k_cud_t read_SH_OSCUD_reg(void)
{
	return (e2k_cud_t) {
		.lo = NATIVE_GET_DREG_CLOSED_ISET(6, sh_oscud.lo),
		.hi = NATIVE_GET_DREG_CLOSED_ISET(6, sh_oscud.hi)
	};
}

static __always_inline void write_SH_OSCUD_reg(e2k_cud_t cud)
{
	NATIVE_SET_DREGS_NOEXC(6, sh_oscud.lo, sh_oscud.hi, cud.lo, cud.hi);
}

/*
 * Read/write low/hgh double-word OS Globals Register (SH_OSGD)
 */

static __always_inline e2k_gd_t read_SH_OSGD_reg(void)
{
	return (e2k_gd_t) {
		.lo = NATIVE_GET_DREG_CLOSED_ISET(6, sh_osgd.lo),
		.hi = NATIVE_GET_DREG_CLOSED_ISET(6, sh_osgd.hi)
	};
}

static __always_inline void write_SH_OSGD_reg(e2k_gd_t osgd)
{
	NATIVE_SET_DREGS_NOEXC(6, sh_osgd.lo, sh_osgd.hi, osgd.lo, osgd.hi);
}

/*
 * Read/write low/high quad-word Procedure Stack Pointer Register
 * (SH_PSP, backup BU_PSP)
 */

static __always_inline e2k_psp_t read_SH_PSP_reg(void)
{
	return (e2k_psp_t) {
		.lo = NATIVE_GET_DREG_CLOSED_ISET(6, sh_psp.lo),
		.hi = NATIVE_GET_DREG_CLOSED_ISET(6, sh_psp.hi)
	};
}

static __always_inline void write_SH_PSP_reg(e2k_psp_t psp)
{
	NATIVE_SET_DREGS_NOEXC(6, sh_psp.lo, sh_psp.hi, psp.lo, psp.hi);
}

static __always_inline e2k_psp_t read_BU_PSP_reg(void)
{
	return (e2k_psp_t) {
		.lo = NATIVE_GET_DREG_CLOSED_ISET(6, bu_psp.lo),
		.hi = NATIVE_GET_DREG_CLOSED_ISET(6, bu_psp.hi)
	};
}

static __always_inline void write_BU_PSP_reg(e2k_psp_t psp)
{
	NATIVE_SET_DREGS_NOEXC(6, bu_psp.lo, bu_psp.hi, psp.lo, psp.hi);
}

/*
 * Read/write low/high quad-word Procedure Chain Stack Pointer Register
 * (SH_PCSP, backup registers BU_PCSP)
 */

static __always_inline e2k_pcsp_t read_SH_PCSP_reg(void)
{
	return (e2k_pcsp_t) {
		.lo = NATIVE_GET_DREG_CLOSED_ISET(6, sh_pcsp.lo),
		.hi = NATIVE_GET_DREG_CLOSED_ISET(6, sh_pcsp.hi)
	};
}

static __always_inline void write_SH_PCSP_reg(e2k_pcsp_t pcsp)
{
	NATIVE_SET_DREGS_NOEXC(6, sh_pcsp.lo, sh_pcsp.hi, pcsp.lo, pcsp.hi);
}

static __always_inline e2k_pcsp_t read_BU_PCSP_reg(void)
{
	return (e2k_pcsp_t) {
		.lo = NATIVE_GET_DREG_CLOSED_ISET(6, bu_pcsp.lo),
		.hi = NATIVE_GET_DREG_CLOSED_ISET(6, bu_pcsp.hi)
	};
}

static __always_inline void write_BU_PCSP_reg(e2k_pcsp_t pcsp)
{
	NATIVE_SET_DREGS_NOEXC(6, bu_pcsp.lo, bu_pcsp.hi, pcsp.lo, pcsp.hi);
}

/*
 * Read/write word Procedure Stack Hardware Top Pointer (SH_PSHTP)
 */

static __always_inline e2k_pshtp_t read_SH_PSHTP_reg(void)
{
	return (e2k_pshtp_t) {
		.word = NATIVE_GET_DREG_CLOSED_ISET(6, sh_pshtp)
	};
}

static __always_inline void write_SH_PSHTP_reg(e2k_pshtp_t pshtp)
{
	NATIVE_SET_DREG_NOEXC(6, sh_pshtp, pshtp.word);
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
	NATIVE_SET_SREG_NOEXC(6, sh_pcshtp, AW(pcshtp));
}


/*
 * Read/write current window descriptor register (SH_WD)
 */

static __always_inline e2k_wd_t read_SH_WD_reg(void)
{
	return (e2k_wd_t) {
		.word = NATIVE_GET_DREG_CLOSED_ISET(6, sh_wd)
	};
}

static __always_inline void write_SH_WD_reg(e2k_wd_t wd)
{
	NATIVE_SET_DREG_NOEXC(6, sh_wd, AW(wd));
}

/*
 * Read/write CPU enhanced system clock shadow registers
 */

static __always_inline u64 read_SH_T_off_reg(void)
{
	return NATIVE_GET_DREG_CLOSED_ISET(7, sh_t_off);
}

static __always_inline void write_SH_T_off_reg(u64 off)
{
	NATIVE_SET_DREG_NOEXC(7, sh_t_off, off);
}

/*
 * Read/write OS-specific registers
 */

static __always_inline u64 read_SH_OSR0_reg_value(void)
{
	return (u64)NATIVE_GET_DREG_CLOSED_ISET(6, sh_osr0);
}

static __always_inline void write_SH_OSR0_reg_value(u64 osr0)
{
	NATIVE_SET_DREG_NOEXC(6, sh_osr0, osr0);
}

#ifdef CONFIG_CPU_HAS_OSR1
static __always_inline u64 read_SH_OSR1_reg_value(void)
{
	return (u64)NATIVE_GET_DREG_CLOSED_ISET(7, sh_osr1);
}

static __always_inline void write_SH_OSR1_reg_value(u64 osr1)
{
	NATIVE_SET_DREG_NOEXC(7, sh_osr1, osr1);
}
#endif

/*
 * Read/Write system clock registers (SH_SCLKM3)
 */

static __always_inline u64 read_SH_SCLKM3_reg_value(void)
{
	return (u64) NATIVE_GET_DREG_CLOSED_ISET(6, sh_sclkm3);

}

static __always_inline void write_SH_SCLKM3_reg_value(u64 val)
{
	NATIVE_SET_DREG_NOEXC(6, sh_sclkm3, val);
}

/*
 * Read/write double-word Compilation Unit Table Register (SH_OSCUTD)
 */

static __always_inline e2k_cutd_t read_SH_OSCUTD_reg(void)
{
	return (e2k_cutd_t) {
		.word = NATIVE_GET_DREG_CLOSED_ISET(6, sh_oscutd)
	};
}

static __always_inline void write_SH_OSCUTD_reg(e2k_cutd_t cutd)
{
	NATIVE_SET_DREG_NOEXC(6, sh_oscutd, cutd.word);
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
	NATIVE_SET_DREG_NOEXC(6, sh_oscuir, oscuir.word);
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
	NATIVE_SET_SREG_NOEXC(6, sh_core_mode, AW(cm));
}


/*
 * Read/Write G_PREEMPT_TMR register
 */
static __always_inline e2k_g_preempt_tmr_t read_G_PREEMPT_TMR_reg(void)
{
	return (e2k_g_preempt_tmr_t) {
		.word = NATIVE_GET_DREG_CLOSED(g_preempt_tmr)
	};
}

static __always_inline void write_G_PREEMPT_TMR_reg(e2k_g_preempt_tmr_t gpt)
{
	NATIVE_SET_DREG_NOEXC(6, g_preempt_tmr, AW(gpt));
}

/*
 * Read/Write INTC_PTR_CU and INTC_INFO_CU registers
 */

static __always_inline u64 read_INTC_PTR_CU_reg_value(void)
{
	return (u64) NATIVE_GET_DREG_CLOSED_ISET(6, intc_ptr_cu);
}

static __always_inline u64 read_INTC_INFO_CU_reg_value(void)
{
	return (u64) NATIVE_GET_DREG_CLOSED_ISET(6, intc_info_cu);
}

static __always_inline void write_INTC_INFO_CU_pair_value(u64 lo, u64 hi)
{
	NATIVE_SET_DREGS_EXC(6, intc_info_cu, intc_info_cu, lo, hi);
}

/* Clear INTC_INFO_CU header and INTC_PTR_CU */
static inline void clear_intc_info_cu(void)
{
	(void)read_INTC_PTR_CU_reg_value();
	write_INTC_INFO_CU_pair_value(0ULL, 0ULL);
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
	write_INTC_INFO_CU_pair_value(0ULL, 0ULL);
	for (i = 0; i < num; i++) {
		write_INTC_INFO_CU_pair_value(info->entry[i].lo, info->entry[i].hi);
	}
}

#endif /*  __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif /* _E2K_KVM_CPU_HV_REGS_ACCESS_H_ */
