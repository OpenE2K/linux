/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#ifndef	_E2K_NATIVE_CPU_REGS_ACCESS_H_
#define	_E2K_NATIVE_CPU_REGS_ACCESS_H_

#ifdef __KERNEL__

#ifndef __ASSEMBLY__
#include <asm/cpu_regs_types.h>
#include <asm/e2k_api.h>
#include <linux/bitops.h>

/*
 * Read doubleword User Processor Identification Register (IDR)
 */

static inline e2k_idr_t native_read_IDR_reg(void)
{
	e2k_idr_t IDR;
	IDR.word = NATIVE_GET_DSREG_OPEN(idr);
	return IDR;
}

/*
 * Read/write low/high double-word OS Compilation Unit Descriptor (OSCUD)
 */

static __always_inline e2k_cud_t native_read_OSCUD_reg(void)
{
	u64 lo = NATIVE_GET_DSREG_CLOSED(oscud.lo);
	u64 hi = NATIVE_GET_DSREG_CLOSED(oscud.hi);
	return (e2k_cud_t) { .lo = lo, .hi = hi };
}

static __always_inline void native_write_OSCUD_reg(e2k_cud_t OSCUD)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC(oscud.hi, OSCUD.hi, 5, 7);
	NATIVE_SET_DSREG_CLOSED_NOEXC(oscud.lo, OSCUD.lo, 5, 7);
}

/*
 * Read/write low/hgh double-word OS Globals Register (OSGD)
 */

static __always_inline e2k_gd_t native_read_OSGD_reg(void)
{
	u64 lo = NATIVE_GET_DSREG_CLOSED(osgd.lo);
	u64 hi = NATIVE_GET_DSREG_CLOSED(osgd.hi);
	return (e2k_gd_t) { .lo = lo, .hi = hi };
}

static __always_inline void native_write_OSGD_reg(e2k_gd_t gd)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC(osgd.hi, gd.hi, 5, 7);
	NATIVE_SET_DSREG_CLOSED_NOEXC(osgd.lo, gd.lo, 5, 7);
}

/*
 * Read/write low/high double-word Compilation Unit Register (CUD)
 */
static __always_inline e2k_cud_t native_read_CUD_reg(void)
{
	u64 hi = NATIVE_GET_DSREG_CLOSED(cud.hi);
	u64 lo = NATIVE_GET_DSREG_CLOSED(cud.lo);
	return (e2k_cud_t) { .lo = lo, .hi = hi };
}

static __always_inline void native_write_CUD_reg(e2k_cud_t cud)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC(cud.hi, cud.hi, 4, 5);
	NATIVE_SET_DSREG_CLOSED_NOEXC(cud.lo, cud.lo, 4, 5);
}

/*
 * Read/write low/high double-word Globals Register (GD)
 */
static __always_inline e2k_gd_t native_read_GD_reg(void)
{
	u64 lo = NATIVE_GET_DSREG_CLOSED(gd.lo);
	u64 hi = NATIVE_GET_DSREG_CLOSED(gd.hi);
	return (e2k_gd_t) { .lo = lo, .hi = hi };
}

static __always_inline void native_write_GD_reg(e2k_gd_t gd)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC(gd.hi, gd.hi, 4, 5);
	NATIVE_SET_DSREG_CLOSED_NOEXC(gd.lo, gd.lo, 4, 5);
}

/*
 * Read/write low/high quad-word Procedure Stack Pointer Register (PSP)
 */

#define ZEROED_PSP (e2k_psp_t){ 0 }

static __always_inline e2k_psp_t native_read_PSP_reg(void)
{
	u64 lo = NATIVE_GET_DSREG_OPEN(psp.lo);
	u64 hi = NATIVE_GET_DSREG_OPEN(psp.hi);
	return (e2k_psp_t) { .lo = lo, .hi = hi };
}

static __always_inline void native_write_PSP_reg(e2k_psp_t psp)
{
	NATIVE_SET_DSREGS_WAIT(psp.lo, psp.hi, psp.lo, psp.hi);
}

/*
 * Read/write low/high quad-word Procedure Chain Stack Pointer Register (PCSP)
 */

#define ZEROED_PCSP (e2k_pcsp_t){ 0 }

static __always_inline e2k_pcsp_t native_read_PCSP_reg(void)
{
	u64 lo = NATIVE_GET_DSREG_OPEN(pcsp.lo);
	u64 hi = NATIVE_GET_DSREG_OPEN(pcsp.hi);
	return (e2k_pcsp_t) { .lo = lo, .hi = hi };
}

static __always_inline void native_write_PCSP_reg(e2k_pcsp_t pcsp)
{
	NATIVE_SET_DSREGS_WAIT(pcsp.lo, pcsp.hi, pcsp.lo, pcsp.hi);
}

/*
 * Read/write low/high quad-word Current Chain Register (CR0/CR1)
 */

static __always_inline e2k_cr0_t native_read_CR0_reg(void)
{
	u64 lo = NATIVE_GET_DSREG_OPEN(cr0.lo);
	u64 hi = NATIVE_GET_DSREG_OPEN(cr0.hi);
	return (e2k_cr0_t) { .lo = lo, .hi = hi };
}

static __always_inline e2k_cr1_t native_read_CR1_reg(void)
{
	u64 lo = NATIVE_GET_DSREG_OPEN(cr1.lo);
	u64 hi = NATIVE_GET_DSREG_OPEN(cr1.hi);
	return (e2k_cr1_t) { .lo = lo, .hi = hi };
}

static __always_inline void native_write_CR0_reg(e2k_cr0_t Cr0)
{
	NATIVE_SET_CR_CLOSED_NOEXC(cr0.lo, Cr0.lo);
	NATIVE_SET_CR_CLOSED_NOEXC(cr0.hi, Cr0.hi);
}

static __always_inline void native_write_CR0_ip(e2k_cr0_t Cr0)
{
	NATIVE_SET_CR_CLOSED_NOEXC(cr0.hi, Cr0.hi);
}

static __always_inline void native_write_CR1_reg(e2k_cr1_t Cr1)
{
	NATIVE_SET_CR_CLOSED_NOEXC(cr1.lo, Cr1.lo);
	NATIVE_SET_CR_CLOSED_NOEXC(cr1.hi, Cr1.hi);
}

/*
 * Read data stack size of current frame (USFS)
 */
static __always_inline u64 native_read_USFS_reg(void)
{
	return NATIVE_GET_USFS();
}

/*
 * Read/write word Procedure Stack Harware Top Pointer (PSHTP)
 */
static __always_inline e2k_pshtp_t native_read_PSHTP_reg(void)
{
	return (e2k_pshtp_t) {
		.word = NATIVE_GET_DSREG_OPEN(pshtp)
	};
}

static __always_inline void native_write_PSHTP_reg(e2k_pshtp_t pshtp)
{
	NATIVE_SET_DSREG_WAIT(pshtp, pshtp.word);
}

static __always_inline void native_strip_PSHTP_window(void)
{
	NATIVE_SET_DSREG_WAIT(pshtp, 0);
}

/*
 * Read/write word Procedure Chain Stack Harware Top Pointer (PCSHTP)
 */

static __always_inline e2k_pcshtp_t native_read_PCSHTP_reg(void)
{
	return (e2k_pcshtp_t) {
		.word = NATIVE_GET_SREG_OPEN(pcshtp)
	};
}
static __always_inline void native_write_PCSHTP_reg(e2k_pcshtp_t pcshtp)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC(pcshtp, pcshtp.word, 5, 7);
}

static __always_inline void native_strip_PCSHTP_window(void)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC(pcshtp, 0, 5, 7);
}

/*
 * Read/write double-word Control Transfer Preparation Registers
 * (CTPR1/CTPR2/CTPR3)
 */

static inline e2k_ctpr_t native_read_CTPR1_reg(void)
{
	return (e2k_ctpr_t) {
		.lo = NATIVE_GET_DSREG_OPEN(ctpr1),
		.hi = (cpu_has(CPU_FEAT_ISET_V6))
				? NATIVE_GET_DSREG_CLOSED_CLOBBERS(ctpr1.hi, "ctpr1")
				: 0,
	};
}

static inline e2k_ctpr_t native_read_CTPR2_reg(void)
{
	return (e2k_ctpr_t) {
		.lo = NATIVE_GET_DSREG_OPEN(ctpr2),
		.hi = (cpu_has(CPU_FEAT_ISET_V6))
				? NATIVE_GET_DSREG_CLOSED_CLOBBERS(ctpr2.hi, "ctpr2")
				: 0,
	};
}

static inline e2k_ctpr_t native_read_CTPR3_reg(void)
{
	return (e2k_ctpr_t) {
		.lo = NATIVE_GET_DSREG_OPEN(ctpr3),
		.hi = (cpu_has(CPU_FEAT_ISET_V6))
				? NATIVE_GET_DSREG_CLOSED_CLOBBERS(ctpr3.hi, "ctpr3")
				: 0,
	};
}

static __always_inline void native_write_CTPR1_reg(e2k_ctpr_t ctpr)
{
	NATIVE_SET_DSREG_OPEN(ctpr1, LO(ctpr));
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		NATIVE_SET_DSREG_CLOSED_EXC_CLOBBERS_ISET(6, ctpr1.hi, HI(ctpr), "ctpr1", 4, 5);
	}
}

static __always_inline void native_write_CTPR2_reg(e2k_ctpr_t ctpr)
{
	NATIVE_SET_DSREG_OPEN(ctpr2, LO(ctpr));
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		NATIVE_SET_DSREG_CLOSED_EXC_CLOBBERS_ISET(6, ctpr2.hi, HI(ctpr), "ctpr2", 4, 5);
	}
}

static __always_inline void native_write_CTPR3_reg(e2k_ctpr_t ctpr)
{
	NATIVE_SET_DSREG_OPEN(ctpr3, LO(ctpr));
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		NATIVE_SET_DSREG_CLOSED_EXC_CLOBBERS_ISET(6, ctpr3.hi, HI(ctpr), "ctpr3", 4, 5);
	}
}


/*
 * Read/write low/high quad-word Trap Info Registers (TIRs)
 */
static __always_inline e2k_tir_t native_read_TIR_reg(void)
{
	e2k_tir_t tir;
		/* order is signicant */
	tir.hi = NATIVE_GET_DSREG_CLOSED(tir.hi);
	tir.lo = NATIVE_GET_DSREG_CLOSED(tir.lo);
	return tir;
}

static __always_inline u64 native_read_TIR_LO_reg(void)
{
	u64 lo = NATIVE_GET_DSREG_CLOSED(tir.lo);
	return lo;
}

static __always_inline u64 native_read_TIR_HI_reg(void)
{
	u64 hi = NATIVE_GET_DSREG_CLOSED(tir.hi);
	return hi;
}




static __always_inline void native_write_TIR_reg(e2k_tir_t tir)
{
	/* order is signicant */
	NATIVE_SET_DSREG_CLOSED_NOEXC(tir.hi, tir.hi, 4, 6);
	NATIVE_SET_DSREG_CLOSED_NOEXC(tir.lo, tir.lo, 4, 6);
}

static __always_inline void native_unfreeze_TIRS(void)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC(tir.lo, 0, 4, 6);
}

/*
 * Read/write double-word User Stacks Base Register (USBR)
 */

static __always_inline e2k_usbr_t native_read_USBR_reg(void)
{
	return (e2k_usbr_t) {
		.word = NATIVE_GET_DSREG_OPEN(sbr)
	};
}

#define native_read_SBR_reg native_read_USBR_reg

static __always_inline void native_write_USBR_reg(e2k_usbr_t USBR)
{
	NATIVE_SET_DSREG_OPEN(sbr, USBR.word);
}

#define native_write_SBR_reg native_write_USBR_reg

/*
 * Read/write low/high double-word Non-Protected User Stack Descriptor
 * Register (USD)
 */
#define MAX_USD_SIZE (4ULL * 1024 * 1024 * 1024 - 1ULL)

#define ZEROED_USD (e2k_usd_t){ 0 }

static __always_inline e2k_usd_t native_read_USD_reg(void)
{
	u64 lo = NATIVE_GET_DSREG_OPEN(usd.lo);
	u64 hi = NATIVE_GET_DSREG_OPEN(usd.hi);
	return (e2k_usd_t) { .lo = lo, .hi = hi };
}

static __always_inline __interrupt void
native_write_USBR_USD_regs(e2k_usbr_t usbr, e2k_usd_t usd)
{
	native_write_USBR_reg(usbr);
	if (cpu_has(CPU_HWBUG_USD_ALIGNMENT))
		NATIVE_SET_DSREG_OPEN(usd.lo, usd.lo);
	NATIVE_SET_DSREG_OPEN(usd.hi, usd.hi);
	NATIVE_SET_DSREG_OPEN(usd.lo, usd.lo);
}

static __always_inline void native_write_USD_reg(e2k_usd_t usd)
{
	NATIVE_SET_DSREG_OPEN(usd.hi, usd.hi);
	NATIVE_SET_DSREG_OPEN(usd.lo, usd.lo);
}

/* Read USINCR register */

#if CONFIG_CPU_ISET_MIN >= 7
static inline e2k_usincr_t native_read_USINCR_reg(void)
{
	return (e2k_usincr_t) {.word = NATIVE_GET_DSREG_OPEN(usincr)};
}

static __always_inline void native_write_USINCR_reg(e2k_usincr_t USINCR)
{
	NATIVE_SET_DSREG_OPEN(usincr, USINCR.word);
}
#else
static inline e2k_usincr_t native_read_USINCR_reg(void)
{
	return (e2k_usincr_t) {.word = NATIVE_GET_DSREG_CLOSED_ISET(7, usincr)};
}

static __always_inline void native_write_USINCR_reg(e2k_usincr_t USINCR)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(7, usincr, USINCR.word, 5, 7);
}
#endif

/*
 * Read/write double-word Window Descriptor Register (WD)
 */

static inline e2k_wd_t native_read_WD_reg(void)
{
	return (e2k_wd_t) {
		.word = NATIVE_GET_DSREG_OPEN(wd)
	};
}

static __always_inline void native_write_WD_reg(e2k_wd_t wd)
{
	NATIVE_SET_DSREG_WAIT(wd, AW(wd));
}

/*
 * Read/write double-word Loop Status Register (LSR/LSR1)
 */

static __always_inline e2k_lsr_t native_read_LSR_reg(void)
{
	return (e2k_lsr_t) {
		.word = NATIVE_GET_DSREG_OPEN(lsr)
	};
}

static __always_inline e2k_lsr_t native_read_LSR1_reg(void)
{
	return (e2k_lsr_t) {
		.word = NATIVE_GET_DSREG_OPEN(lsr1)
	};
}

static __always_inline void native_write_LSR_reg(e2k_lsr_t lsr)
{
	NATIVE_SET_DSREG_OPEN(lsr, lsr.word);
}

static __always_inline void native_write_LSR1_reg(e2k_lsr_t lsr1)
{
	NATIVE_SET_DSREG_OPEN(lsr1, lsr1.word);
}

/*
 * Read/write double-word Loop Status Register (ILCR/ILCR1)
 */

static __always_inline e2k_ilcr_t native_read_ILCR_reg(void)
{
	return (e2k_ilcr_t) {
		.word = NATIVE_GET_DSREG_OPEN(ilcr)
	};
}

static __always_inline e2k_ilcr_t native_read_ILCR1_reg(void)
{
	return (e2k_ilcr_t) {
		.word = NATIVE_GET_DSREG_OPEN(ilcr1)
	};
}

static __always_inline void native_write_ILCR_reg(e2k_ilcr_t ilcr)
{
	NATIVE_SET_DSREG_OPEN(ilcr, ilcr.word);
}

static __always_inline void native_write_ILCR1_reg(e2k_ilcr_t ilcr1)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC(ilcr1, ilcr1.word, 4, 6);
}

/*
 * Read/write OS register which point to current process thread info
 * structure (OSR0)
 */

static __always_inline u64 native_read_OSR0_reg_value(void)
{
	return NATIVE_GET_DSREG_OPEN(osr0);
}

static __always_inline void native_write_OSR0_reg_value(u64 osr0)
{
	NATIVE_SET_DSREG_OPEN(osr0, osr0);
}

static __always_inline u64 native_read_OSR1_reg_value(void)
{
	/* TODO bug 157081 - use open asm when fixed */
	return NATIVE_GET_DSREG_CLOSED_ISET(7, osr1);
	/* return NATIVE_GET_DSREG_OPEN(osr1); */
}

static __always_inline void native_write_OSR1_reg_value(u64 osr1)
{
	/* TODO bug 157081 - use open asm when fixed */
	NATIVE_SET_DSREG_CLOSED_EXC_ISET(7, osr1, osr1, 7, 7);
	/* NATIVE_SET_DSREG_OPEN(osr1, osr1); */
}

#ifdef CONFIG_CPU_HAS_OSR1
# define native_read_CURRENT_reg_value() \
	((struct thread_info *)native_read_OSR1_reg_value())
# define native_write_CURRENT_reg_value(t) \
	 native_write_OSR1_reg_value((u64)(t))
#else
# define native_read_CURRENT_reg_value() \
	((struct thread_info *)native_read_OSR0_reg_value())
# define native_write_CURRENT_reg_value(t) \
	 native_write_OSR0_reg_value((u64)(t))
#endif

/*
 * Read/write OS Entries Mask (OSEM)
 */

static __always_inline u32 native_read_OSEM_reg_value(void)
{
	return (u32) NATIVE_GET_SREG_CLOSED(osem);
}

static __always_inline void native_write_OSEM_reg_value(u32 osem)
{
	NATIVE_SET_SREG_CLOSED_NOEXC(osem, osem, 5, 7);
}

/*
 * Read/write word Base Global Register (BGR)
 */

static __always_inline e2k_bgr_t native_read_BGR_reg(void)
{
	e2k_bgr_t bgr;
	bgr.word = NATIVE_GET_SREG_OPEN(bgr);
	return bgr;
}

static __always_inline void native_write_BGR_reg(e2k_bgr_t bgr)
{
	NATIVE_SET_SREG_WAIT(bgr, AW(bgr),
			"g24", "g25", "g26", "g27", "g28", "g29", "g30", "g31");
}

static __always_inline void native_init_BGR_reg(void)
{
	native_write_BGR_reg(E2K_INITIAL_BGR);
}

/*
 * Read CPU current clock register (CLKR)
 */

static __always_inline u64 native_read_CLKR_reg_value(void)
{
	return NATIVE_GET_DSREG_CLOSED(clkr);
}

static __always_inline void native_reset_CLKR_reg(void)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC(clkr, 0, 4, 6);
}

/*
 * Read/Write system clock registers (SCLKM)
 */

static __always_inline u64 native_read_SCLKR_reg_value(void)
{
	return NATIVE_GET_DSREG_OPEN(sclkr);
}

static __always_inline e2k_sclkm1_t native_read_SCLKM1_reg(void)
{
	return (e2k_sclkm1_t) {
		.word = NATIVE_GET_DSREG_OPEN(sclkm1)
	};
}

static __always_inline e2k_sclkm2_t native_read_SCLKM2_reg(void)
{
	return (e2k_sclkm2_t) {
		.word = NATIVE_GET_DSREG_OPEN(sclkm2)
	};
}

static __always_inline u64 native_read_SCLKM3_reg_value(void)
{
	return (u64) NATIVE_GET_DSREG_CLOSED(sclkm3);
}

static __always_inline void native_write_SCLKR_reg_value(u64 val)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC(sclkr, val, 4, 6);
}

static __always_inline void native_write_SCLKM1_reg(e2k_sclkm1_t val)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC(sclkm1, AW(val), 4, 6);
}

static __always_inline void native_write_SCLKM2_reg(e2k_sclkm2_t val)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC(sclkm2, AW(val), 4, 6);
}

static __always_inline void native_write_SCLKM3_reg_value(u64 val)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC(sclkm3, val, 4, 6);
}

/*
 * Read CPU enhanced system clock registers (T_ABS, T_OFF)
 */

static __always_inline u64 native_read_T_ABS_reg_value(void)
{
	return NATIVE_GET_DSREG_CLOSED_ISET(7, t_abs);
}

static __always_inline u64 native_read_T_OFF_reg_value(void)
{
	return NATIVE_GET_DSREG_CLOSED_ISET(7, t_off);
}

static __always_inline void native_write_T_OFF_reg_value(u64 val)
{
	NATIVE_SET_DSREG_CLOSED_EXC_ISET(7, t_off, val, 6, 6);
}


/*
 * Read/Write Control Unit HardWare registers (CU_HW0/CU_HW1)
 */

static __always_inline e2k_cu_hw0_t native_read_CU_HW0_reg(void)
{
	return (e2k_cu_hw0_t) {
		.word = NATIVE_GET_DSREG_CLOSED(cu_hw0)
	};
}

static __always_inline void native_write_CU_HW0_reg(e2k_cu_hw0_t cu_hw0)
{
	NATIVE_SET_DSREG_CLOSED_EXC(cu_hw0, cu_hw0.word, 5, 7);
	__E2K_WAIT_ALL;
}

static __always_inline u64 native_read_CU_HW1_reg_value(void)
{
	return (u64)NATIVE_GET_DSREG_CLOSED_ISET(5, cu_hw1);
}

static __always_inline void native_write_CU_HW1_reg_value(u64 cu_hw1)
{
	NATIVE_SET_DSREG_CLOSED_EXC_ISET(5, cu_hw1, cu_hw1, 5, 7);
	__E2K_WAIT_ALL;
}


/*
 * Read/write low/high double-word Recovery point register (RPR)
 */

#define INITIAL_ZEROED_RPR   (e2k_rpr_t){ 0 }

static __always_inline e2k_rpr_t native_read_RPR_reg(void)
{
	u64 lo = NATIVE_GET_DSREG_OPEN(rpr.lo);
	u64 hi = NATIVE_GET_DSREG_OPEN(rpr.hi);
	return (e2k_rpr_t) { .lo = lo, .hi = hi };
}

static __always_inline void native_write_RPR_reg(e2k_rpr_t rpr)
{
	NATIVE_SET_DSREG_OPEN(rpr.lo, rpr.lo);
	NATIVE_SET_DSREG_OPEN(rpr.hi, rpr.hi);
}

/*
 * Read/write word Base Global Register (BGR)
 */

static __always_inline u64 native_read_SBBP_reg_value(void)
{
	return (u64) NATIVE_GET_DSREG_OPEN(sbbp);
}

static __always_inline void native_write_SBBP_reg_value(u64 sbbp)
{
	NATIVE_SET_DSREG_CLOSED_EXC(sbbp, sbbp, 0, 0);
}

/*
 * Read/write word Processor State Register (PSR)
 */


static inline e2k_psr_t native_read_PSR_reg(void)
{
	return (e2k_psr_t) {
		.word = NATIVE_GET_SREG_OPEN(psr)
	};
}

static __always_inline void native_write_PSR_reg(e2k_psr_t psr)
{
	NATIVE_SET_SREG_OPEN(psr, psr.word);
}

static __always_inline void native_write_irq_barrier_PSR_reg(e2k_psr_t psr)
{
	NATIVE_SET_PSR_IRQ_BARRIER(psr.word);
}

/*
 * Read double-word CPU current Instruction Pointer register (IP)
 */

static __always_inline u64 native_read_IP_reg_value(void)
{
	u64 ip = (u64) NATIVE_GET_DSREG_OPEN(ip);
	return ip;
}

/*
 * Read/Write Debug Instruction Monitor Trace Pointer (DIMTP)
 */

static __always_inline e2k_dimtp_t native_read_DIMTP_reg(void)
{
	if (!cpu_has(CPU_FEAT_ISET_V6))
		return (e2k_dimtp_t) { 0 };

	return (e2k_dimtp_t) {
		.lo = NATIVE_GET_DSREG_CLOSED_ISET(6, dimtp.lo),
		.hi = NATIVE_GET_DSREG_CLOSED_ISET(6, dimtp.hi)
	};
}

static __always_inline void native_write_DIMTP_reg(e2k_dimtp_t dimtp)
{
	if (!cpu_has(CPU_FEAT_ISET_V6))
		return;

	NATIVE_SET_DSREGS_CLOSED_NOEXC_ISET(6, dimtp.lo, dimtp.hi,
					    dimtp.lo, dimtp.hi, 4, 6);
}


static __always_inline void native_clear_DIMTP_reg(void)
{
	native_write_DIMTP_reg((e2k_dimtp_t) { 0 });
}

/*
 * Read debug and monitors registers
 */

static __always_inline e2k_dibcr_t native_read_DIBCR_reg(void)
{
	return (e2k_dibcr_t) {
		.word = NATIVE_GET_DSREG_CLOSED(dibcr)
	};
}

static __always_inline e2k_dibsr_t native_read_DIBSR_reg(void)
{
	return (e2k_dibsr_t) {
		.word = NATIVE_GET_DSREG_CLOSED(dibsr)
	};
}

static __always_inline u64 native_read_DIBAR0_reg_value(void)
{
	return (u64) NATIVE_GET_DSREG_OPEN(dibar0);
}

static __always_inline u64 native_read_DIBAR1_reg_value(void)
{
	return (u64) NATIVE_GET_DSREG_OPEN(dibar1);
}

static __always_inline u64 native_read_DIBAR2_reg_value(void)
{
	return (u64) NATIVE_GET_DSREG_OPEN(dibar2);
}

static __always_inline u64 native_read_DIBAR3_reg_value(void)
{
	return (u64) NATIVE_GET_DSREG_OPEN(dibar3);
}

static __always_inline s64 native_read_DIMAR0_reg_value(void)
{
	return NATIVE_GET_DSREG_OPEN(dimar0);
}

static __always_inline s64 native_read_DIMAR1_reg_value(void)
{
	return NATIVE_GET_DSREG_OPEN(dimar1);
}

/*
 * __iset__ >= 8 helps to avoid speculative reads of dimar2 and dimar3 registers while building for
 * iset v7 and executing on machines with reduced support of iset v7
 */
#if __iset__ >= 8
static __always_inline s64 native_read_DIMAR2_reg_value(void)
{
	return NATIVE_GET_DSREG_OPEN(dimar2);
}

static __always_inline s64 native_read_DIMAR3_reg_value(void)
{
	return NATIVE_GET_DSREG_OPEN(dimar3);
}
#else
static __always_inline s64 native_read_DIMAR2_reg_value(void)
{
	return NATIVE_GET_DSREG_CLOSED_ISET(7, dimar2);
}

static __always_inline s64 native_read_DIMAR3_reg_value(void)
{
	return NATIVE_GET_DSREG_CLOSED_ISET(7, dimar3);
}
#endif

static __always_inline void native_write_DIBCR_reg(e2k_dibcr_t dibcr)
{
	NATIVE_SET_SREG_CLOSED_NOEXC(dibcr, AW(dibcr), 4, 6);
}

static __always_inline void native_clear_DIBCR_reg(void)
{
	native_write_DIBCR_reg(TOS(e2k_dibcr_t, 0));
}

static __always_inline void native_write_DIBSR_reg(e2k_dibsr_t dibsr)
{
	NATIVE_SET_SREG_CLOSED_NOEXC(dibsr, dibsr.word, 4, 6);
}

static __always_inline void native_clear_DIBSR_reg(void)
{
	native_write_DIBSR_reg((e2k_dibsr_t) {.word = 0});
}

/*     DIMCR/DIMCR1  */

static __always_inline e2k_dimcr_t native_read_DIMCR_reg(void)
{
	return (e2k_dimcr_t) {
		.word = NATIVE_GET_DSREG_CLOSED(dimcr)
	};
}

static __always_inline e2k_dimcr_t native_read_DIMCR1_reg(void)
{
	return (e2k_dimcr_t) { .word = NATIVE_GET_DSREG_CLOSED_ISET(7, dimcr1) };
}

static inline bool is_event_pipe_frz_sensitive(int event)
{
	return event == 0x2e ||
	    event >= 0x30 && event <= 0x3d ||
	    event >= 0x48 && event <= 0x4a ||
	    event >= 0x58 && event <= 0x5a || event >= 0x68 && event <= 0x69;
}

static inline bool is_dimcr_pipe_frz_sensitive(e2k_dimcr_t dimcr)
{
	return dimcr_enabled(dimcr, 0) &&
	    is_event_pipe_frz_sensitive(dimcr.dimar[0].event) ||
	    dimcr_enabled(dimcr, 1) &&
	    is_event_pipe_frz_sensitive(dimcr.dimar[1].event);
}

static __always_inline void native_write_DIMCR_reg(e2k_dimcr_t dimcr)
{
	if (cpu_has(CPU_HWBUG_PIPELINE_FREEZE_MONITORS)) {
		e2k_dimcr_t old_value = native_read_DIMCR_reg();
		bool old_sensitive = is_dimcr_pipe_frz_sensitive(old_value);
		bool new_sensitive = is_dimcr_pipe_frz_sensitive(dimcr);
		if (old_sensitive != new_sensitive) {
			e2k_cu_hw0_t cu_hw0;

			e2k_psr_t psr = native_read_PSR_reg();
			e2k_psr_t psr_disabled = psr;
			psr_disabled.nmie = 0;	/* disable interrupts using psr */
			psr_disabled.ie = 0;	/* to avoid header loops */
			native_write_irq_barrier_PSR_reg(psr_disabled);
			cu_hw0 = native_read_CU_HW0_reg();
			cu_hw0.pipe_frz_dsbl = new_sensitive ? 1 : 0;
			native_write_CU_HW0_reg(cu_hw0);
			native_write_irq_barrier_PSR_reg(psr);	/* restore interrupts */
		}
	}
	/* 6 cycles delay guarantess that all counting
	 * is stopped and %dibsr is updated accordingly. */
	NATIVE_SET_DSREG_CLOSED_NOEXC(dimcr, AW(dimcr), 5, 6);
}

static __always_inline void native_write_DIMCR1_reg(e2k_dimcr_t dimcr1)
{
	/* 6 cycles delay guarantess that all counting
	 * is stopped and %dibsr is updated accordingly. */
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(7, dimcr1, AW(dimcr1), 5, 6);
}

#define native_clear_DIMCR_reg() native_write_DIMCR_reg((e2k_dimcr_t){.word = 0})

#define native_clear_DIMCR1_reg() native_write_DIMCR1_reg((e2k_dimcr_t){.word = 0})

static __always_inline void native_write_DIBAR0_reg_value(u64 dibar)
{
	NATIVE_SET_DSREG_OPEN(dibar0, dibar);
}

static __always_inline void native_write_DIBAR1_reg_value(u64 dibar)
{
	NATIVE_SET_DSREG_OPEN(dibar1, dibar);
}

static __always_inline void native_write_DIBAR2_reg_value(u64 dibar)
{
	NATIVE_SET_DSREG_OPEN(dibar2, dibar);
}

static __always_inline void native_write_DIBAR3_reg_value(u64 dibar)
{
	NATIVE_SET_DSREG_OPEN(dibar3, dibar);
}

static __always_inline void native_write_DIMAR0_reg_value(s64 dimar)
{
	NATIVE_SET_DSREG_OPEN(dimar0, dimar);
}

static __always_inline void native_write_DIMAR1_reg_value(s64 dimar)
{
	NATIVE_SET_DSREG_OPEN(dimar1, dimar);
}

#if __iset__ >= 7
static __always_inline void native_write_DIMAR2_reg_value(s64 dimar)
{
	NATIVE_SET_DSREG_OPEN(dimar2, dimar);
}

static __always_inline void native_write_DIMAR3_reg_value(s64 dimar)
{
	NATIVE_SET_DSREG_OPEN(dimar3, dimar);
}
#else
static __always_inline void native_write_DIMAR2_reg_value(s64 dimar)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(7, dimar2, dimar, 4, 4);
}

static __always_inline void native_write_DIMAR3_reg_value(s64 dimar)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(7, dimar3, dimar, 4, 4);
}
#endif

/*
 * Read/write double-word Compilation Unit Table Register (CUTD/OSCUTD)
 */

static __always_inline e2k_cutd_t native_read_CUTD_reg(void)
{
	return (e2k_cutd_t) {
		.word = NATIVE_GET_DSREG_OPEN(cutd)
	};
}

static __always_inline void native_write_CUTD_reg(e2k_cutd_t cutd)
{
	NATIVE_SET_DSREG_OPEN_NOIRQ(cutd, cutd.word);
}


static __always_inline e2k_cutd_t native_read_OSCUTD_reg(void)
{
	return (e2k_cutd_t){.word = NATIVE_GET_DSREG_CLOSED_ISET(6, oscutd)};
}

static __always_inline void native_write_OSCUTD_reg(e2k_cutd_t cutd)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, oscutd, AW(cutd), 5, 7);
}


/*
 * Read/write dword Stack Base Bloks Pointers (SBBP)
*/

static __always_inline e2k_sbbp_t native_read_SBBP_reg(void)
{
	return (e2k_sbbp_t) {
		.word = NATIVE_GET_DSREG_OPEN(sbbp)
	};
}

static __always_inline void native_write_SBBP_reg(e2k_sbbp_t sbbp)
{
	NATIVE_SET_DSREG_CLOSED_EXC(sbbp, sbbp.word, 0, 0);
}

/*
 * Read/write word Compilation Unit Index Register (CUIR/OSCUIR)
 */

static __always_inline e2k_cuir_t native_read_CUIR_reg(void)
{
	return (e2k_cuir_t) {
		.word = NATIVE_GET_SREG_CLOSED(cuir)
	};
}

static __always_inline void native_write_CUIR_reg(e2k_cuir_t cuir)
{
	NATIVE_SET_SREG_CLOSED_NOEXC(cuir, AW(cuir), 5, 7);
}


static __always_inline e2k_cuir_t native_read_OSCUIR_reg(void)
{
	return (e2k_cuir_t){.word = NATIVE_GET_SREG_CLOSED_ISET(6, oscuir)};
}

static __always_inline void native_write_OSCUIR_reg(e2k_cuir_t cuir)
{
	NATIVE_SET_SREG_CLOSED_NOEXC_ISET(6, oscuir, AW(cuir), 5, 7);
}


/*
 * Read/write word User Processor State Register (UPSR)
 */
/* upsr reg - byte register, but linux used long flag
 * to save arch_local_irq_save.To avoid casting to long(redundant stx command)
 * we can used read long register.Suprisingly, but size of image.boot decreased
 * 4096 byte
 */

#ifndef	CONFIG_ACCESS_CONTROL
#define E2K_KERNEL_UPSR_ENABLED_ASM		0xa1
#define E2K_KERNEL_UPSR_DISABLED_ALL_ASM	0x01
#else
#define E2K_KERNEL_UPSR_ENABLED_ASM		0xa5
#define E2K_KERNEL_UPSR_DISABLED_ALL_ASM	0x05
#endif /* ! (CONFIG_ACCESS_CONTROL) */

static __always_inline __interrupt e2k_upsr_t native_read_UPSR_reg(void)
{
	e2k_upsr_t upsr;
	upsr.word = NATIVE_GET_DSREG_OPEN(upsr);
	return upsr;
}

static __always_inline void native_write_UPSR_reg(e2k_upsr_t upsr)
{
	NATIVE_SET_SREG_OPEN(upsr, upsr.word);
}

static __always_inline void native_write_irq_barrier_UPSR_reg(e2k_upsr_t upsr)
{
	NATIVE_SET_UPSR_IRQ_BARRIER(upsr.word);
}

/*
 * Read/write word floating point control registers (PFPFR/FPCR/FPSR)
 */

static __always_inline e2k_pfpfr_t native_read_PFPFR_reg(void)
{
	e2k_pfpfr_t PFPFR;
	PFPFR.word = NATIVE_GET_SREG_OPEN(pfpfr);
	return PFPFR;
}

static __always_inline e2k_fpcr_t native_read_FPCR_reg(void)
{
	e2k_fpcr_t FPCR;
	FPCR.word = NATIVE_GET_SREG_OPEN(fpcr);
	return FPCR;
}

static __always_inline e2k_fpsr_t native_read_FPSR_reg(void)
{
	e2k_fpsr_t FPSR;
	FPSR.word = NATIVE_GET_SREG_OPEN(fpsr);
	return FPSR;
}

static __always_inline void native_write_PFPFR_reg(e2k_pfpfr_t PFPFR)
{
	NATIVE_SET_SREG_OPEN(pfpfr, PFPFR.word);
}

static __always_inline void native_write_FPCR_reg(e2k_fpcr_t FPCR)
{
	NATIVE_SET_SREG_OPEN(fpcr, FPCR.word);
}

static __always_inline void native_write_FPSR_reg(e2k_fpsr_t FPSR)
{
	NATIVE_SET_SREG_OPEN(fpsr, FPSR.word);
}

/*
 *   Read/Write Hypercall Entries Mask register (HCEM)
 */

static __always_inline u32 native_read_HCEM_reg_value(void)
{
	return NATIVE_GET_SREG_CLOSED_ISET(6, hcem);
}

static __always_inline void native_write_HCEM_reg_value(u32 val)
{
	NATIVE_SET_SREG_CLOSED_NOEXC_ISET(6, hcem, val, 5, 7);
}

/*
 *   Read/Write Hypercall Entries Base register (HCEB)
 */

static __always_inline u64 native_read_HCEB_reg_value(void)
{
	return NATIVE_GET_DSREG_CLOSED_ISET(6, hceb);
}

static __always_inline void native_write_HCEB_reg_value(u64 val)
{
	NATIVE_SET_DSREG_CLOSED_NOEXC_ISET(6, hceb, val, 5, 7);
}

static __always_inline void native_write_stacks(e2k_psp_t psp, e2k_pcsp_t pcsp,
		e2k_usd_t usd, e2k_sbr_t sbr)
{
	NATIVE_SET_STACK_REGS(psp, pcsp, usd, sbr);
}

static __always_inline void native_write_stacks_cr(e2k_psp_t psp, e2k_pcsp_t pcsp,
		e2k_usd_t usd, e2k_sbr_t sbr, e2k_cr0_t cr0, e2k_cr1_t cr1)
{
	NATIVE_SET_STACK_CR_REGS(psp, pcsp, usd, sbr, cr0, cr1);
}

static __always_inline void native_write_hw_stacks(e2k_psp_t psp, e2k_pcsp_t pcsp)
{
	NATIVE_SET_HW_STACK_REGS(psp, pcsp);
}

static __always_inline void native_write_hw_stacks_cr(e2k_psp_t psp, e2k_pcsp_t pcsp,
		e2k_cr0_t cr0, e2k_cr1_t cr1)
{
	NATIVE_SET_HW_STACK_CR_REGS(psp, pcsp, cr0, cr1);
}

static __always_inline void native_write_cr(e2k_cr0_t cr0, e2k_cr1_t cr1)
{
	NATIVE_SET_CR_REGS(cr0, cr1);
}


/* Instruction handling */

static __always_inline instr_cs0_t *find_cs0(void *ip)
{
        instr_hs_t *hs = (instr_hs_t *) & E2K_GET_INSTR_HS(ip);
        if (!hs->c0)
                return NULL;
        return (instr_cs0_t *) (hs + hs->s + hweight32(hs->al) + 1);
}

static __always_inline instr_cs1_t *find_cs1(void *ip)
{
	instr_hs_t *hs;

	hs = (instr_hs_t *) & E2K_GET_INSTR_HS(ip);
	if (!hs->c1)
		return NULL;

	return (instr_cs1_t *) (hs + hs->mdl);
}

static __always_inline int get_instr_size_by_vaddr(unsigned long addr)
{
	int instr_size;
	instr_syl_t *syl;
	instr_hs_t hs;

	syl = &E2K_GET_INSTR_HS((e2k_addr_t) addr);
	hs.word = *syl;
	instr_size = E2K_GET_INSTR_SIZE(hs);

	return instr_size;
}

static inline instr_als_t *find_als(const void *ip, int n)
{
	instr_hs_t *hs;

	hs = (instr_hs_t *) &E2K_GET_INSTR_HS(ip);
	if (!(hs->al & (1 << n)))
		return NULL;

	return (instr_als_t *) (hs + 1 + hs->s + hweight32(hs->al & ((1 << n) - 1)));
}

/*
 * Do not use this function if you are not sure that
 * assembler command (to which `ip' points) has at least `n'
 * LTS syllables.
 *
 * Checking for the presence of LTS syllables in the command
 * was omitted because it would not be possible without
 * implementing assembler in kernel.
 */
static inline instr_lts_t *find_lts_f32s(const void *ip, int n)
{
	int instr_size;
	instr_hs_t *hs;

	/* There are four possible LTS syllables, numbered from 0 to 3 */
	if (n < 0 || n > 3)
		return NULL;

	hs = (instr_hs_t *) &E2K_GET_INSTR_HS(ip);
	instr_size = E2K_GET_INSTR_SIZE(*hs);

	return (instr_lts_t *) (ip + instr_size - hs->cd * sizeof(instr_cds_t) -
			hs->pl * sizeof(instr_pls_t) - sizeof(instr_lts_t) * (n + 1));
}



/*
 * Read/write low/high double-word Intel segments registers (xS)
 */

#define	NATIVE_READ_CS_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(cs.lo)
#define	NATIVE_READ_CS_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(cs.hi)
#define	NATIVE_READ_DS_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(ds.lo)
#define	NATIVE_READ_DS_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(ds.hi)
#define	NATIVE_READ_ES_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(es.lo)
#define	NATIVE_READ_ES_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(es.hi)
#define	NATIVE_READ_FS_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(fs.lo)
#define	NATIVE_READ_FS_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(fs.hi)
#define	NATIVE_READ_GS_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(gs.lo)
#define	NATIVE_READ_GS_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(gs.hi)
#define	NATIVE_READ_SS_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(ss.lo)
#define	NATIVE_READ_SS_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(ss.hi)

#define	NATIVE_CL_WRITE_CS_LO_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(cs.lo, sd)
#define	NATIVE_CL_WRITE_CS_HI_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(cs.hi, sd)
#define	NATIVE_CL_WRITE_DS_LO_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(ds.lo, sd)
#define	NATIVE_CL_WRITE_DS_HI_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(ds.hi, sd)
#define	NATIVE_CL_WRITE_ES_LO_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(es.lo, sd)
#define	NATIVE_CL_WRITE_ES_HI_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(es.hi, sd)
#define	NATIVE_CL_WRITE_FS_LO_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(fs.lo, sd)
#define	NATIVE_CL_WRITE_FS_HI_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(fs.hi, sd)
#define	NATIVE_CL_WRITE_GS_LO_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(gs.lo, sd)
#define	NATIVE_CL_WRITE_GS_HI_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(gs.hi, sd)
#define	NATIVE_CL_WRITE_SS_LO_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(ss.lo, sd)
#define	NATIVE_CL_WRITE_SS_HI_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(ss.hi, sd)

/*
 * Read/Write Processor Core Mode Register (CORE_MODE)
 */
#define native_read_CORE_MODE_reg()		\
	((e2k_core_mode_t) { .word = NATIVE_GET_SREG_OPEN(core_mode) })
#define	native_write_CORE_MODE_reg(modes)	\
		NATIVE_SET_SREG_CLOSED_NOEXC(core_mode, modes.word, 5, 7)

#endif /*  __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif /* _E2K_NATIVE_CPU_REGS_ACCESS_H_ */
