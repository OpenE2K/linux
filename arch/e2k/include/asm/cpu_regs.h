/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

#include <linux/printk.h>

#include <asm/native_cpu_regs_access.h>

#define	boot_native_read_CORE_MODE_reg	native_read_CORE_MODE_reg
#define	boot_native_write_CORE_MODE_reg	native_write_CORE_MODE_reg
#define	boot_native_read_OSCUTD_reg	native_read_OSCUTD_reg
#define	boot_native_write_OSCUTD_reg	native_write_OSCUTD_reg
#define	boot_native_read_OSCUIR_reg	native_read_OSCUIR_reg
#define	boot_native_write_OSCUIR_reg	native_write_OSCUIR_reg

/*
 * Processor Core Mode Register (CORE_MODE)
 */
#define	read_CORE_MODE_reg		native_read_CORE_MODE_reg
#define	boot_read_CORE_MODE_reg		boot_native_read_CORE_MODE_reg
#define	write_CORE_MODE_reg		native_write_CORE_MODE_reg
#define	boot_write_CORE_MODE_reg	boot_native_write_CORE_MODE_reg

/*
 * OS Compilation Unit Table Descriptor Register (OSCUTD)
 */
#define	read_OSCUTD_reg			native_read_OSCUTD_reg
#define	boot_read_OSCUTD_reg		boot_native_read_OSCUTD_reg
#define	write_OSCUTD_reg		native_write_OSCUTD_reg
#define	boot_write_OSCUTD_reg		boot_native_write_OSCUTD_reg

/*
 * OS Compilation Unit Index Register (OSCUIR)
 */
#define	read_OSCUIR_reg			native_read_OSCUIR_reg
#define	write_OSCUIR_reg		native_write_OSCUIR_reg
#define	boot_read_OSCUIR_reg		boot_native_read_OSCUIR_reg
#define	boot_write_OSCUIR_reg		boot_native_write_OSCUIR_reg

/*
 * Read/write word Procedure Stack Harware Top Pointer (PSHTP)
 */
#define	read_PSHTP_reg		native_read_PSHTP_reg
#define	write_PSHTP_reg		native_write_PSHTPP_reg
#define	strip_PSHTP_window	native_strip_PSHTP_window

/*
 * Read/write word Procedure Chain Stack Harware Top Pointer (PCSHTP)
 */
#define	read_PCSHTP_reg		native_read_PCSHTP_reg
#define	write_PCSHTP_reg	native_write_PCSHTP_reg
#define	strip_PCSHTP_window	native_strip_PCSHTP_window

/*
 * Read/write low/high double-word Compilation Unit Register (CUTD)
 */

#define	read_CUTD_reg		native_read_CUTD_reg
#define	boot_read_CUTD_reg	native_read_CUTD_reg

#define	write_CUTD_reg		native_write_CUTD_reg
#define	boot_write_CUTD_reg	native_write_CUTD_reg

/*
 * Read/write low/hgh double-word OS Globals Register (OSGD)
 */

#define	read_OSGD_reg		native_read_OSGD_reg
#define	boot_read_OSGD_reg	native_read_OSGD_reg

#define	write_OSGD_reg		native_write_OSGD_reg
#define	boot_write_OSGD_reg	native_write_OSGD_reg

/*
 * Compilation Unit Globals Descriptor (GD)
 * describes the global variables memory of the current compilation unit
 */

#define	read_GD_reg		native_read_GD_reg
#define	boot_read_GD_reg	native_read_GD_reg

#define	write_GD_reg		native_write_GD_reg
#define	boot_write_GD_reg	native_write_GD_reg

static __always_inline u64 GD_BASE_V7(e2k_gd_t gd)
{
	return GET_V7_CPU_REG_BASE(gd.word);
}

static __always_inline u64 GD_BASE_V6(e2k_gd_t gd)
{
	return gd.Base;
}

static __always_inline u64 GD_BASE(e2k_gd_t gd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return GD_BASE_V7(gd);
	}
	return GD_BASE_V6(gd);
}

static __always_inline u64 GD_SIZE_V7(e2k_gd_t gd)
{
	return GET_V7_CPU_REG_SIZE(gd.word);
}

static __always_inline u64 GD_SIZE_V6(e2k_gd_t gd)
{
	return gd.Size;
}

static __always_inline u64 GD_SIZE(e2k_gd_t gd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return GD_SIZE_V7(gd);
	} else {
		return GD_SIZE_V6(gd);
	}
}

static __always_inline e2k_gd_t new_gd_v7(u64 base, u64 size)
{
	return (e2k_gd_t) {.word = NEW_V7_CPU_REG(base, 0, size)};
}

static __always_inline e2k_gd_t new_gd_v6(u64 base, u64 size)
{
	return (e2k_gd_t) {.Base = base, .Size = size};
}

static __always_inline e2k_gd_t new_gd(u64 base, u64 size)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
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

#define	read_PSP_reg		native_read_PSP_reg
#define	boot_read_PSP_reg	native_read_PSP_reg
#define	write_PSP_reg		native_write_PSP_reg
#define	boot_write_PSP_reg	native_write_PSP_reg

static __always_inline u64 PSP_BASE_V7(e2k_psp_t psp)
{
	return GET_V7_CPU_REG_BASE(psp.word);
}

static __always_inline u64 PSP_BASE_V6(e2k_psp_t psp)
{
	return psp.Base;
}

static __always_inline u64 PSP_BASE(e2k_psp_t psp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return PSP_BASE_V7(psp);
	} else {
		return PSP_BASE_V6(psp);
	}
}

static __always_inline u64 PSP_SIZE_V7(e2k_psp_t psp)
{
	return GET_V7_CPU_REG_SIZE(psp.word);
}

static __always_inline u64 PSP_SIZE_V6(e2k_psp_t psp)
{
	return psp.Size;
}

static __always_inline u64 PSP_SIZE(e2k_psp_t psp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return PSP_SIZE_V7(psp);
	} else {
		return PSP_SIZE_V6(psp);
	}
}

static __always_inline u64 PSP_IND_V7(e2k_psp_t psp)
{
	return GET_V7_CPU_REG_IND(psp.word);
}

static __always_inline u64 PSP_IND_V6(e2k_psp_t psp)
{
	return psp.Ind;
}

static __always_inline u64 PSP_IND(e2k_psp_t psp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return PSP_IND_V7(psp);
	} else {
		return PSP_IND_V6(psp);
	}
}

static __always_inline u64 PSP_PTR_V7(e2k_psp_t psp)
{
	return GET_V7_CPU_REG_PTR(psp.word);
}

static __always_inline u64 PSP_PTR_V6(e2k_psp_t psp)
{
	return (psp.Base + psp.Ind);
}

static __always_inline volatile void *K_PSP_PTR(e2k_psp_t psp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return (volatile void *)PSP_PTR_V7(psp);
	} else {
		return (volatile void *)PSP_PTR_V6(psp);
	}
}

static __always_inline volatile void __priv *U_PSP_PTR(e2k_psp_t psp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return (volatile void __priv __force *)PSP_PTR_V7(psp);
	} else {
		return (volatile void __priv __force *)PSP_PTR_V6(psp);
	}
}
static __always_inline e2k_psp_t new_psp_v7(u64 base, u64 size, u64 ind)
{
	return (e2k_psp_t) {.word = NEW_V7_CPU_REG(base, ind, size)};
}

static __always_inline e2k_psp_t new_psp_v6(u64 base, u64 size, u64 ind)
{
	return (e2k_psp_t) {.Base = base, .Size = size, .Ind  = ind};
}

static __always_inline e2k_psp_t new_psp(u64 base, u64 size, u64 ind)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return new_psp_v7(base, size, ind);
	} else {
		return new_psp_v6(base, size, ind);
	}
}

static __always_inline __must_check e2k_psp_t set_psp_ind(e2k_psp_t psp, u64 new_ind)
{
	return new_psp(PSP_BASE(psp), PSP_SIZE(psp), new_ind);
}

static __always_inline __must_check e2k_psp_t incr_psp_ind(e2k_psp_t psp, s32 delta)
{
	return set_psp_ind(psp, PSP_IND(psp) + delta);
}

static __always_inline __must_check e2k_psp_t decr_psp_ind(e2k_psp_t psp, s32 delta)
{
	return set_psp_ind(psp, PSP_IND(psp) - delta);
}

/*
 * Procedure Chain Stack Pointer (PCSP)
 * describes the full procedure chain stack memory as well as the current
 * pointer to the top of a procedure chain stack memory part.
 */

#define	read_PCSP_reg		native_read_PCSP_reg
#define	boot_read_PCSP_reg	native_read_PCSP_reg
#define	write_PCSP_reg		native_write_PCSP_reg
#define	boot_write_PCSP_reg	native_write_PCSP_reg

static __always_inline u64 PCSP_BASE_V7(e2k_pcsp_t pcsp)
{
	return GET_V7_CPU_REG_BASE(pcsp.word);
}

static __always_inline u64 PCSP_BASE_V6(e2k_pcsp_t pcsp)
{
	return pcsp.Base;
}

static __always_inline u64 PCSP_BASE(e2k_pcsp_t pcsp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return PCSP_BASE_V7(pcsp);
	} else {
		return PCSP_BASE_V6(pcsp);
	}
}

static __always_inline u64 PCSP_SIZE_V7(e2k_pcsp_t pcsp)
{
	return GET_V7_CPU_REG_SIZE(pcsp.word);
}

static __always_inline u64 PCSP_SIZE_V6(e2k_pcsp_t pcsp)
{
	return pcsp.Size;
}

static __always_inline u64 PCSP_SIZE(e2k_pcsp_t pcsp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return PCSP_SIZE_V7(pcsp);
	} else {
		return PCSP_SIZE_V6(pcsp);
	}
}

static __always_inline u64 PCSP_IND_V7(e2k_pcsp_t pcsp)
{
	return GET_V7_CPU_REG_IND(pcsp.word);
}

static __always_inline u64 PCSP_IND_V6(e2k_pcsp_t pcsp)
{
	return pcsp.Ind;
}

static __always_inline u64 PCSP_IND(e2k_pcsp_t pcsp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return PCSP_IND_V7(pcsp);
	} else {
		return PCSP_IND_V6(pcsp);
	}
}

static __always_inline u64 PCSP_PTR_V7(e2k_pcsp_t pcsp)
{
	return (u64)GET_V7_CPU_REG_PTR(pcsp.word);
}

static __always_inline u64 PCSP_PTR_V6(e2k_pcsp_t pcsp)
{
	return (u64)(pcsp.Base + pcsp.Ind);
}

static __always_inline e2k_mem_crs_t *K_PCSP_PTR(e2k_pcsp_t pcsp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return (void *)PCSP_PTR_V7(pcsp);
	} else {
		return (void *)PCSP_PTR_V6(pcsp);
	}
}

static __always_inline e2k_mem_crs_t __priv *U_PCSP_PTR(e2k_pcsp_t pcsp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return (void __priv __force *)PCSP_PTR_V7(pcsp);
	} else {
		return (void __priv __force *)PCSP_PTR_V6(pcsp);
	}
}

static __always_inline e2k_pcsp_t new_pcsp_v7(u64 base, u64 size, u64 ind)
{
	return (e2k_pcsp_t) {.word = NEW_V7_CPU_REG(base, ind, size)};
}

static __always_inline e2k_pcsp_t new_pcsp_v6(u64 base, u64 size, u64 ind)
{
	return (e2k_pcsp_t) {.Base = base, .Size = size, .Ind  = ind};
}

static __always_inline e2k_pcsp_t new_pcsp(u64 base, u64 size, u64 ind)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return new_pcsp_v7(base, size, ind);
	} else {
		return new_pcsp_v6(base, size, ind);
	}
}

static __always_inline __must_check e2k_pcsp_t set_pcsp_ind(e2k_pcsp_t pcsp, u64 new_ind)
{
	return new_pcsp(PCSP_BASE(pcsp), PCSP_SIZE(pcsp), new_ind);
}

static __always_inline __must_check e2k_pcsp_t incr_pcsp_ind(e2k_pcsp_t pcsp, s32 delta)
{
	return set_pcsp_ind(pcsp, PCSP_IND(pcsp) + delta);
}

static __always_inline __must_check e2k_pcsp_t decr_pcsp_ind(e2k_pcsp_t pcsp, s32 delta)
{
	return set_pcsp_ind(pcsp, PCSP_IND(pcsp) - delta);
}

/*
 * Batched accessors that write several stack registers at once
 */

#define write_hw_stacks			native_write_hw_stacks
#define write_hw_stacks_cr		native_write_hw_stacks_cr
#define write_hw_stacks_cr__no_wait	native_write_hw_stacks_cr__no_wait
#define write_cr			native_write_cr
#define write_cr__no_wait		native_write_cr__no_wait
#define	boot_write_hw_stacks		native_write_hw_stacks

/*
 * Read/write low/high quad-word Current Chain Register (CR0/CR1)
 */
#define	read_CR0_reg		native_read_CR0_reg
#define	boot_read_CR0_reg	native_read_CR0_reg
#define	write_CR0_reg		native_write_CR0_reg
#define	boot_write_CR0_reg	native_write_CR0_reg
#define	write_CR0_ip		native_write_CR0_ip

#define	read_CR1_reg		native_read_CR1_reg
#define	boot_read_CR1_reg	native_read_CR1_reg
#define	write_CR1_reg		native_write_CR1_reg
#define	boot_write_CR1_reg	native_write_CR1_reg

static __always_inline u64 get_cr1_ussz_v7(e2k_cr1_t cr1)
{
	/* Force types because C implicitly makes small bitfields signed */
	u64 ussz = (u64) (u32) cr1.ussz_lo << 4;
	ussz |= (u64) (u32) cr1.ussz_hi << 32;
	return ussz;
}

static __always_inline u64 get_cr1_ussz_v6(e2k_cr1_t cr1)
{
	/* Force types because C implicitly makes small bitfields signed */
	return (u64) (u32) cr1.ussz_lo << 4;
}

static __always_inline u64 get_cr1_ussz(e2k_cr1_t cr1)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return get_cr1_ussz_v7(cr1);
	} else {
		return get_cr1_ussz_v6(cr1);
	}
}

/* Special version for __check_stack functions */
static __always_inline __must_check e2k_cr1_t set_cr1_ussz_v7(e2k_cr1_t cr1,  u64 sz)
{
	cr1.ussz_lo = ((u64)(sz) >> 4) & 0x0fffffff;
	cr1.ussz_hi = ((u64)(sz) >> 32) & 0x0ffff;
	return cr1;
}

static __always_inline __must_check e2k_cr1_t set_cr1_ussz_v6(e2k_cr1_t cr1,  u64 sz)
{
	cr1.ussz_lo = ((u64)(sz) >> 4) & 0x0fffffff;
	return cr1;
}

static __always_inline __must_check e2k_cr1_t set_cr1_ussz(e2k_cr1_t cr1,  u64 sz)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return set_cr1_ussz_v7(cr1, sz);
	} else {
		return set_cr1_ussz_v6(cr1, sz);
	}
}

static __always_inline void set_cr1p_ussz_v7(e2k_cr1_t *cr1p,  u64 sz)
{
	cr1p->ussz_lo = ((u64)(sz) >> 4) & 0x0fffffff;
	cr1p->ussz_hi = ((u64)(sz) >> 32) & 0x0ffff;
}

static __always_inline void set_cr1p_ussz_v6(e2k_cr1_t *cr1p,  u64 sz)
{
	cr1p->ussz_lo = ((u64)(sz) >> 4) & 0x0fffffff;
}

static __always_inline void set_cr1p_ussz(e2k_cr1_t *cr1p,  u64 sz)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		set_cr1p_ussz_v7(cr1p, sz);
	} else {
		set_cr1p_ussz_v6(cr1p, sz);
	}
}

/*
 * Read data stack size of current frame (USFS)
 */
#define read_USFS_reg		native_read_USFS_reg
#define zero_USFS_reg		native_zero_USFS_reg

/*
 * Read/write double-word Control Transfer Preparation Registers
 * (CTPR1/CTPR2/CTPR3)
 */

#define	read_CTPR_reg(reg_no)	native_read_CTPR_reg(reg_no)

static __always_inline e2k_ctpr_t ctpr_new(u64 lo, u64 hi)
{
	return (e2k_ctpr_t) {
		.lo = lo,
		.hi = (cpu_has(CPU_FEAT_ISET_V6)) ? hi : 0,
	};
}

static __always_inline u64 ctpr_ta_tag(e2k_ctpr_t ctpr)
{
	return cpu_has(CPU_FEAT_ISET_V7) ? ctpr.v7.ta_tag : ctpr.v6.ta_tag;
}

static __always_inline __must_check e2k_ctpr_t ctpr_with_ta_tag(e2k_ctpr_t ctpr, u64 ta_tag)
{
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		ctpr.v7.ta_tag = ta_tag;
	} else {
		ctpr.v6.ta_tag = ta_tag;
	}
	return ctpr;
}

static __always_inline u64 ctpr_opc(e2k_ctpr_t ctpr)
{
	return cpu_has(CPU_FEAT_ISET_V7) ? ctpr.v7.opc : ctpr.v6.opc;
}

static __always_inline __must_check e2k_ctpr_t ctpr_with_opc(e2k_ctpr_t ctpr, u64 opc)
{
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		ctpr.v7.opc = opc;
	} else {
		ctpr.v6.opc = opc;
	}
	return ctpr;
}

static __always_inline u64 ctpr_ipd(e2k_ctpr_t ctpr)
{
	return cpu_has(CPU_FEAT_ISET_V7) ? ctpr.v7.ipd : ctpr.v6.ipd;
}

static __always_inline __must_check e2k_ctpr_t ctpr_with_ipd(e2k_ctpr_t ctpr, u64 ipd)
{
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		ctpr.v7.ipd = ipd;
	} else {
		ctpr.v6.ipd = ipd;
	}
	return ctpr;
}

/*
 * User Stack Descriptor (USD)
 * contains free memory space dedicated for user stack data and
 * is supposed to grow from higher memory addresses to lower ones
 */
#define	read_USD_reg		native_read_USD_reg
#define	boot_read_USD_reg	native_read_USD_reg
#define	write_USD_reg		native_write_USD_reg
#define	boot_write_USD_reg	native_write_USD_reg

static __always_inline u64 USD_PTR_V7(e2k_usd_t usd)
{
	return GET_V7_CPU_REG_PTR(usd.word);
}

static __always_inline u64 USD_PTR_V6(e2k_usd_t usd)
{
	return usd.Ptr;
}

static __always_inline u64 USD_PTR(e2k_usd_t usd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return USD_PTR_V7(usd);
	} else {
		return USD_PTR_V6(usd);
	}
}

static __always_inline u64 USD_IND_V7(e2k_usd_t usd)
{
	return GET_V7_CPU_REG_IND(usd.word);
}

static __always_inline u64 USD_IND_V6(e2k_usd_t usd)
{
	return usd.Ind;
}

static __always_inline u64 USD_IND(e2k_usd_t usd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return USD_IND_V7(usd);
	} else {
		return USD_IND_V6(usd);
	}
}

/*
 * NB> Don't use macros 'USD_BASE' in the protected mode in iset<7
 */
static __always_inline u64 USD_BASE_V7(e2k_usd_t usd)
{
	return GET_V7_CPU_REG_BASE(usd.word);
}

static __always_inline u64 USD_BASE_V6(e2k_usd_t usd)
{
	return usd.Ptr - usd.Ind;
}

static __always_inline u64 USD_BASE(e2k_usd_t usd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return USD_BASE_V7(usd);
	} else {
		return USD_BASE_V6(usd);
	}
}

static __always_inline u64 USD_SIZE_V7(e2k_usd_t usd)
{
	return GET_V7_CPU_REG_SIZE(usd.word);
}

static __always_inline u64 USD_PPTR_V7(e2k_usd_t usd)
{
	return GET_V7_CPU_REG_PTR(usd.word);
}

static __always_inline u64 USD_PPTR_V6(e2k_usd_t usd)
{
	return usd.P_ptr;
}

static __always_inline u64 USD_PPTR(e2k_usd_t usd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return USD_PPTR_V7(usd);
	}
	return USD_PPTR_V6(usd);
}

static __always_inline u32 USD_PSL_V6(e2k_usd_t usd)
{
	return usd.Psl;
}

static __always_inline u32 USD_PSL(e2k_usd_t usd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return 0;
	} else {
		return USD_PSL_V6(usd);
	}
}

static __always_inline bool USD_P_V7(void)
{
	return false;
}

static __always_inline bool USD_P_V6(e2k_usd_t usd)
{
	return !!usd.P;
}

static __always_inline bool USD_P(e2k_usd_t usd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return USD_P_V7();
	} else {
		return USD_P_V6(usd);
	}
}

static __always_inline e2k_usd_t new_usd_v7(u64 base, u64 size, u64 ind)
{
	e2k_usd_t usd = (e2k_usd_t) {
		.word = NEW_V7_CPU_REG(base, ind, size)
	};
	usd.perm.w = 1;
	usd.perm.r = 1;
	return usd;
}

static __always_inline e2k_usd_t new_usd_v6(u64 base, u64 ind)
{
	return (e2k_usd_t) {.Ptr = base + ind, .Ind = ind};
}

static __always_inline e2k_usd_t new_usd(u64 base, u64 size, u64 ind)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return new_usd_v7(base, size, ind);
	} else {
		return new_usd_v6(base, ind);
	}
}

static __always_inline e2k_usd_t new_pusd_v7(u64 base, u64 size, u64 ind)
{
	return new_usd_v7(base, size, ind);
}

static __always_inline e2k_usd_t new_pusd_v6(u64 base, u64 ind, u32 psl)
{
	return (e2k_usd_t) {
		.P_ptr = (base + ind) & E2K_PROTECTED_STACK_BASE_MASK,
		.Ind = ind,
		.Psl = psl,
		.P = 1
	};
}

static __always_inline e2k_usd_t new_pusd(u64 base, u64 size, u64 ind, u32 psl)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return new_pusd_v7(base, size, ind);
	} else {
		return new_pusd_v6(base, ind, psl);
	}
}

static __always_inline __must_check e2k_usd_t set_usd_ind(e2k_usd_t usd, u64 ind)
{
	return new_usd(USD_BASE(usd),
		       cpu_has(CPU_FEAT_V7_CPU_REGS) ? USD_SIZE_V7(usd) : 0ULL,
		       ind);
}

static __always_inline __must_check e2k_usd_t incr_usd_ind(e2k_usd_t usd, u64 delta)
{
	return set_usd_ind(usd, USD_IND(usd) + delta);
}

static __always_inline __must_check e2k_usd_t decr_usd_ind(e2k_usd_t usd, u64 delta)
{
	return set_usd_ind(usd, USD_IND(usd) - delta);
}

/*
 * Read/write double-word User Stacks Base Register (USBR)
 */
#define	read_USBR_reg		native_read_USBR_reg
#define	boot_read_USBR_reg	native_read_USBR_reg
#define	write_USBR_reg		native_write_USBR_reg
#define	boot_write_USBR_reg	native_write_USBR_reg

#define	read_SBR_reg		read_USBR_reg
#define	boot_read_SBR_reg	boot_read_USBR_reg
#define	write_SBR_reg		write_USBR_reg
#define	boot_write_SBR_reg	boot_write_USBR_reg

#define write_USBR_USD_values	native_write_USBR_USD_values

/*
 * Read/write double-word Window Descriptor Register (WD)
 */
#define	read_WD_reg		native_read_WD_reg
#define	write_WD_reg		native_write_WD_reg

/* CUD */

#define	read_CUD_reg		native_read_CUD_reg
#define	write_CUD_reg		native_write_CUD_reg
#define	boot_write_CUD_reg	native_write_CUD_reg

/*
 * Compilation Unit Descriptor (CUD)
 * describes the memory containing codes of the current compilation unit
 */

static __always_inline u64 CUD_BASE_V7(e2k_cud_t cud)
{
	return GET_V7_CPU_REG_BASE(cud.word);
}

static __always_inline u64 CUD_BASE_V6(e2k_cud_t cud)
{
	return cud.Base;
}

static __always_inline u64 CUD_BASE(e2k_cud_t cud)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return CUD_BASE_V7(cud);
	} else {
		return CUD_BASE_V6(cud);
	}
}

static __always_inline u64 CUD_SIZE_V7(e2k_cud_t cud)
{
	return GET_V7_CPU_REG_SIZE(cud.word);
}

static __always_inline u64 CUD_SIZE_V6(e2k_cud_t cud)
{
	return cud.Size;
}

static __always_inline u64 CUD_SIZE(e2k_cud_t cud)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return CUD_SIZE_V7(cud);
	} else {
		return CUD_SIZE_V6(cud);
	}
}

static __always_inline enum cud_flag CUD_FLAG_V7(e2k_cud_t cud)
{
	return cud.Flag;
}

static __always_inline enum cud_flag CUD_FLAG_V6(e2k_cud_t cud)
{
	return 0;
}

static __always_inline enum cud_flag CUD_FLAG(e2k_cud_t cud)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return CUD_FLAG_V7(cud);
	} else {
		return CUD_FLAG_V6(cud);
	}
}

static __always_inline bool CUD_C_V7(e2k_cud_t cud)
{
	return !!cud.C_v7;
}

static __always_inline bool CUD_C_V6(e2k_cud_t cud)
{
	return !!cud.C;
}

static __always_inline bool CUD_C(e2k_cud_t cud)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return CUD_C_V7(cud);
	} else {
		return CUD_C_V6(cud);
	}
}

static __always_inline e2k_cud_t new_cud_v7(u64 base, u64 size, int c, enum cud_flag flag)
{
	e2k_cud_t cud;

	cud.word  = NEW_V7_CPU_REG(base, 0, size);
	cud.C_v7 = c;
	cud.Flag = flag;
	return cud;
}

static __always_inline e2k_cud_t new_cud_v6(u64 base, u64 size, int c, enum cud_flag flag)
{
	e2k_cud_t cud;

	cud.lo = 0;
	cud.hi = 0;
	cud.Base = base;
	cud.Size = size;
	cud.C = c;
	cud.P = (flag == cud_m128);
	return cud;
}

static __always_inline e2k_cud_t new_cud(u64 base, u64 size, int c, enum cud_flag flag)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return new_cud_v7(base, size, c, flag);
	} else {
		return new_cud_v6(base, size, c, flag);
	}
}

/* OSCUD */
#define	read_OSCUD_reg		native_read_OSCUD_reg
#define	boot_read_OSCUD_reg	native_read_OSCUD_reg
#define	write_OSCUD_reg		native_write_OSCUD_reg
#define	boot_write_OSCUD_reg	native_write_OSCUD_reg

/* Read DIMTP */
#define	read_DIMTP_reg	native_read_DIMTP_reg

static __always_inline u64 DIMTP_BASE(e2k_dimtp_t dimtp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return GET_V7_CPU_REG_BASE(dimtp.word);
	} else {
		return dimtp.base;
	}
}

static __always_inline u64 DIMTP_SIZE(e2k_dimtp_t dimtp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return GET_V7_CPU_REG_SIZE(dimtp.word);
	} else {
		return dimtp.size;
	}
}

static __always_inline u64 DIMTP_IND(e2k_dimtp_t dimtp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return GET_V7_CPU_REG_IND(dimtp.word);
	} else {
		return dimtp.ind;
	}

}

static __always_inline e2k_dimtp_t new_dimtp(u64 base, u64 size, u64 ind)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return (e2k_dimtp_t) {.word = NEW_V7_CPU_REG(base, ind, size)};
	} else {
		return (e2k_dimtp_t) {.base = base, .size = size, .ind = ind};
	}
}

/* MADMR and OS_MADMR */
#define	read_MADMR_reg		native_read_MADMR_reg
#define	write_MADMR_reg		native_write_MADMR_reg
#define	read_OS_MADMR_reg	native_read_OS_MADMR_reg
#define	write_OS_MADMR_reg	native_write_OS_MADMR_reg


/*
 * Read/write double-word Random state Predicates Register (RNDPR)
 */
static __always_inline e2k_rndpr_t read_RNDPR_reg(void)
{
	return (e2k_rndpr_t) { .word = NATIVE_GET_DREG_OPEN(wd) };
}

static __always_inline void write_RNDPR_reg(e2k_rndpr_t rndpr)
{
	NATIVE_SET_DREG_NOEXC(3, rndpr, AW(rndpr));
}


/*
 * Read/write OS register which point to current process thread info
 * structure (OSR0/1). OSR0/1 == CURRENT
 */
#define	read_CURRENT_reg_value		native_read_CURRENT_reg_value
#define	boot_read_CURRENT_reg_value	native_read_CURRENT_reg_value

#define	write_CURRENT_reg_value		native_write_CURRENT_reg_value
#define	boot_write_CURRENT_reg_value	native_write_CURRENT_reg_value

/*
 * Read/write OS Entries Mask (OSEM)
 */
#define	read_OSEM_reg_value		native_read_OSEM_reg_value
#define	write_OSEM_reg_value		native_write_OSEM_reg_value

/*
 * Read/write word Base Global Register (BGR)
 */
#define	read_BGR_reg			native_read_BGR_reg
#define	boot_read_BGR_reg		native_read_BGR_reg

#define	write_BGR_reg		native_write_BGR_reg
#define	init_BGR_reg		native_init_BGR_reg
#define	boot_write_BGR_reg	native_write_BGR_reg
#define	boot_init_BGR_reg	native_init_BGR_reg

/*
 * Read CPU current clock regigister (CLKR)
 */
#define	read_CLKR_reg_value	native_read_CLKR_reg_value

/*
 * Read/Write system clock registers (SCLKR, SCLKMx)
 */

#define	read_SCLKR_reg		native_read_SCLKR_reg
#define	read_SCLKM1_reg		native_read_SCLKM1_reg
#define	read_SCLKM2_reg		native_read_SCLKM2_reg
#define	read_SCLKM3_reg_value	native_read_SCLKM3_reg_value

#define	write_SCLKR_reg		native_write_SCLKR_reg
#define	write_SCLKM1_reg	native_write_SCLKM1_reg
#define	write_SCLKM2_reg	native_write_SCLKM2_reg
#define	write_SCLKM3_reg_value	native_write_SCLKM3_reg_value




/*
 * Read/write CPU enhanced system clock registers (T_ABS, T_OFF)
 */
#define	read_T_ABS	native_read_T_ABS_reg_value
#define	read_T_OFF	native_read_T_OFF_reg_value

#define	write_T_OFF	native_write_T_OFF_reg_value

/*
 * Read/Write Control Unit HardWare registers (CU_HW0/CU_HW1)
 */
#define	read_CU_HW0_reg		native_read_CU_HW0_reg
#define	read_CU_HW1_reg_value	native_read_CU_HW1_reg_value

#define	write_CU_HW0_reg	native_write_CU_HW0_reg
#define	write_CU_HW1_reg_value	native_write_CU_HW1_reg_value

/*
 * Read/write low/high double-word Recovery point register (RPR)
 */
#define	read_RPR_reg	native_read_RPR_reg
#define	write_RPR_reg	native_write_RPR_reg

/*
 * Read double-word CPU current Instruction Pointer register (IP)
 */
#define	read_IP_reg_value	native_read_IP_reg_value

/*
 * Read debug and monitors regigisters
 */
#define	read_DIBCR_reg		native_read_DIBCR_reg
#define	read_DIBSR_reg		native_read_DIBSR_reg
#define	read_DIMCR_reg		native_read_DIMCR_reg
#define	read_DIMCR1_reg		native_read_DIMCR1_reg
#define	read_DIBAR0_reg		native_read_DIBAR0_reg
#define	read_DIBAR1_reg		native_read_DIBAR1_reg
#define	read_DIBAR2_reg		native_read_DIBAR2_reg
#define	read_DIBAR3_reg		native_read_DIBAR3_reg
#define	read_DIMAR0_reg		native_read_DIMAR0_reg
#define	read_DIMAR1_reg		native_read_DIMAR1_reg
#define	read_DIMAR2_reg		native_read_DIMAR2_reg
#define	read_DIMAR3_reg		native_read_DIMAR3_reg

#define	write_DIBCR_reg		native_write_DIBCR_reg
#define	write_DIBSR_reg		native_write_DIBSR_reg
#define	clear_DIBSR_reg		native_clear_DIBSR_reg
#define	clear_DIBCR_reg		native_clear_DIBCR_reg
#define	write_DIMCR_reg		native_write_DIMCR_reg
#define	write_DIMCR1_reg	native_write_DIMCR1_reg
#define	clear_DIMCR_reg		native_clear_DIMCR_reg
#define	clear_DIMCR1_reg	native_clear_DIMCR1_reg
#define	write_DIBAR0_reg	native_write_DIBAR0_reg
#define	write_DIBAR1_reg	native_write_DIBAR1_reg
#define	write_DIBAR2_reg	native_write_DIBAR2_reg
#define	write_DIBAR3_reg	native_write_DIBAR3_reg
#define	write_DIMAR0_reg	native_write_DIMAR0_reg
#define	write_DIMAR1_reg	native_write_DIMAR1_reg
#define	write_DIMAR2_reg	native_write_DIMAR2_reg
#define	write_DIMAR3_reg	native_write_DIMAR3_reg

/*
 * Read/write double-word Compilation Unit Table Register (CUTD)
 */
#define	read_CUTD_reg	native_read_CUTD_reg
#define	write_CUTD_reg	native_write_CUTD_reg

/*
 * Read word Compilation Unit Index Register (CUIR)
 */
#define	read_CUIR_reg			native_read_CUIR_reg

/*
 * Read/write word Processor State Register (PSR)
 */
#define	read_PSR_reg			native_read_PSR_reg
#define	boot_read_PSR_reg		native_read_PSR_reg

#define	write_PSR_reg			native_write_PSR_reg
#define	write_irq_barrier_PSR_reg	native_write_irq_barrier_PSR_reg

/*
 *   *   Read/Write Hypercall Entries Mask register (HCEM)
 */
#define	read_HCEM_reg_value		native_read_HCEM_reg_value
#define	write_HCEM_reg_value		native_write_HCEM_reg_value

/*
 *     Read/Write Hypercall Entries Base register (HCEB)
 */

#define	read_HCEB_reg_value		native_read_HCEB_reg_value
#define	write_HCEB_reg_value		native_write_HCEB_reg_value

/*
 * Read/write word User Processor State Register (UPSR)
 */
#define	read_UPSR_reg			native_read_UPSR_reg
#define	boot_read_UPSR_reg		native_read_UPSR_reg

#define	write_UPSR_reg			native_write_UPSR_reg
#define	boot_write_UPSR_reg		native_write_UPSR_reg
#define	write_irq_barrier_UPSR_reg	native_write_irq_barrier_UPSR_reg

/*
 * Read/write word floating point control registers (PFPFR/FPCR/FPSR)
 */
#define	read_PFPFR_reg		native_read_PFPFR_reg
#define	read_FPCR_reg		native_read_FPCR_reg
#define	read_FPSR_reg		native_read_FPSR_reg

#define write_FPU_regs		native_write_FPU_regs

/*
 * Read/write low/high double-word Intel segments registers (xS)
 */

#define	READ_CS_LO_REG_VALUE()	NATIVE_READ_CS_LO_REG_VALUE()
#define	READ_CS_HI_REG_VALUE()	NATIVE_READ_CS_HI_REG_VALUE()
#define	READ_DS_LO_REG_VALUE()	NATIVE_READ_DS_LO_REG_VALUE()
#define	READ_DS_HI_REG_VALUE()	NATIVE_READ_DS_HI_REG_VALUE()
#define	READ_ES_LO_REG_VALUE()	NATIVE_READ_ES_LO_REG_VALUE()
#define	READ_ES_HI_REG_VALUE()	NATIVE_READ_ES_HI_REG_VALUE()
#define	READ_FS_LO_REG_VALUE()	NATIVE_READ_FS_LO_REG_VALUE()
#define	READ_FS_HI_REG_VALUE()	NATIVE_READ_FS_HI_REG_VALUE()
#define	READ_GS_LO_REG_VALUE()	NATIVE_READ_GS_LO_REG_VALUE()
#define	READ_GS_HI_REG_VALUE()	NATIVE_READ_GS_HI_REG_VALUE()
#define	READ_SS_LO_REG_VALUE()	NATIVE_READ_SS_LO_REG_VALUE()
#define	READ_SS_HI_REG_VALUE()	NATIVE_READ_SS_HI_REG_VALUE()

#define	WRITE_CS_LO_REG_VALUE(sd)	NATIVE_CL_WRITE_CS_LO_REG_VALUE(sd)
#define	WRITE_CS_HI_REG_VALUE(sd)	NATIVE_CL_WRITE_CS_HI_REG_VALUE(sd)
#define	WRITE_DS_LO_REG_VALUE(sd)	NATIVE_CL_WRITE_DS_LO_REG_VALUE(sd)
#define	WRITE_DS_HI_REG_VALUE(sd)	NATIVE_CL_WRITE_DS_HI_REG_VALUE(sd)
#define	WRITE_ES_LO_REG_VALUE(sd)	NATIVE_CL_WRITE_ES_LO_REG_VALUE(sd)
#define	WRITE_ES_HI_REG_VALUE(sd)	NATIVE_CL_WRITE_ES_HI_REG_VALUE(sd)
#define	WRITE_FS_LO_REG_VALUE(sd)	NATIVE_CL_WRITE_FS_LO_REG_VALUE(sd)
#define	WRITE_FS_HI_REG_VALUE(sd)	NATIVE_CL_WRITE_FS_HI_REG_VALUE(sd)
#define	WRITE_GS_LO_REG_VALUE(sd)	NATIVE_CL_WRITE_GS_LO_REG_VALUE(sd)
#define	WRITE_GS_HI_REG_VALUE(sd)	NATIVE_CL_WRITE_GS_HI_REG_VALUE(sd)
#define	WRITE_SS_LO_REG_VALUE(sd)	NATIVE_CL_WRITE_SS_LO_REG_VALUE(sd)
#define	WRITE_SS_HI_REG_VALUE(sd)	NATIVE_CL_WRITE_SS_HI_REG_VALUE(sd)

/*
 * Read doubleword User Processor Identification Register (IDR)
 */
#define	read_IDR_reg			native_read_IDR_reg
#define	boot_read_IDR_reg		native_read_IDR_reg
