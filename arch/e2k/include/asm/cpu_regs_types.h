/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef	_E2K_CPU_REGS_TYPES_H_
#define	_E2K_CPU_REGS_TYPES_H_

#ifndef __ASSEMBLY__ 

#include <asm/cpu_regs_types_defs.h>
#include <asm/e2k_api.h>
#include <asm/cpu_features.h>
#include <uapi/asm/bootinfo.h>

/*
 * Compilation Unit Descriptor (CUD)
 * describes the memory containing codes of the current compilation unit
 */

static __always_inline u64
CUD_BASE_V7(e2k_cud_t cud)
{
	return GET_V7_CPU_REG_BASE(cud.word);
}

static __always_inline u64
CUD_BASE_V6(e2k_cud_t cud)
{
	return cud.Base;
}

static __always_inline u64
CUD_BASE(e2k_cud_t cud)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return CUD_BASE_V7(cud);
	} else {
		return CUD_BASE_V6(cud);
	}
}

static __always_inline u64
CUD_SIZE_V7(e2k_cud_t cud)
{
	return GET_V7_CPU_REG_SIZE(cud.word);
}

static __always_inline u64
CUD_SIZE_V6(e2k_cud_t cud)
{
	return cud.Size;
}

static __always_inline u64
CUD_SIZE(e2k_cud_t cud)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return CUD_SIZE_V7(cud);
	} else {
		return CUD_SIZE_V6(cud);
	}
}

static __always_inline enum cud_flag
CUD_FLAG_V7(e2k_cud_t cud)
{
	return cud.Flag;
}

static __always_inline enum cud_flag
CUD_FLAG_V6(e2k_cud_t cud)
{
	return 0;
}

static __always_inline enum cud_flag
CUD_FLAG(e2k_cud_t cud)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return CUD_FLAG_V7(cud);
	} else {
		return CUD_FLAG_V6(cud);
	}
}

static __always_inline bool
CUD_C_V7(e2k_cud_t cud)
{
	return !!cud.C_v7;
}

static __always_inline bool
CUD_C_V6(e2k_cud_t cud)
{
	return !!cud.C;
}

static __always_inline bool
CUD_C(e2k_cud_t cud)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return CUD_C_V7(cud);
	} else {
		return CUD_C_V6(cud);
	}
}

static __always_inline e2k_cud_t
new_cud_v7(u64 base, u64 size, int c, enum cud_flag flag)
{
	e2k_cud_t cud;

	cud.word  = NEW_V7_CPU_REG(base, 0, size);
	cud.C_v7 = c;
	cud.Flag = flag;
	return cud;
}

static __always_inline e2k_cud_t
new_cud_v6(u64 base, u64 size, int c, enum cud_flag flag)
{
	e2k_cud_t cud;

	cud.lo = 0;
	cud.hi = 0;
	cud.Base = base;
	cud.Size = size;
	cud.C = c;
	cud.P = (flag == cud_m128);
	cud.R = ((flag == cud_m128) || (flag == cud_m64) || (flag == cud_m32));
	return cud;
}

static __always_inline e2k_cud_t
new_cud(u64 base, u64 size, int c, enum cud_flag flag)
{
	if (unlikely(cpu_has(CPU_FEAT_V7_CPU_REGS))) {
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
GD_BASE_V7(e2k_gd_t gd)
{
	return GET_V7_CPU_REG_BASE(gd.word);
}

static __always_inline u64
GD_BASE_V6(e2k_gd_t gd)
{
	return gd.Base;
}

static __always_inline u64
GD_BASE(e2k_gd_t gd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return GD_BASE_V7(gd);
	}
	return GD_BASE_V6(gd);
}

static __always_inline u64
GD_SIZE_V7(e2k_gd_t gd)
{
	return GET_V7_CPU_REG_SIZE(gd.word);
}

static __always_inline u64
GD_SIZE_V6(e2k_gd_t gd)
{
	return gd.Size;
}

static __always_inline u64
GD_SIZE(e2k_gd_t gd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return GD_SIZE_V7(gd);
	} else {
		return GD_SIZE_V6(gd);
	}
}

static __always_inline e2k_gd_t
new_gd_v7(u64 base, u64 size)
{
	return (e2k_gd_t) {.word = NEW_V7_CPU_REG(base, 0, size)};
}

static __always_inline e2k_gd_t
new_gd_v6(u64 base, u64 size)
{
	return (e2k_gd_t) {.Base = base, .Size = size};
}

static __always_inline e2k_gd_t
new_gd(u64 base, u64 size)
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

static __always_inline u64
PSP_BASE_V7(e2k_psp_t psp)
{
	return GET_V7_CPU_REG_BASE(psp.word);
}

static __always_inline u64
PSP_BASE_V6(e2k_psp_t psp)
{
	return psp.Base;
}

static __always_inline u64
PSP_BASE(e2k_psp_t psp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return PSP_BASE_V7(psp);
	} else {
		return PSP_BASE_V6(psp);
	}
}

static __always_inline u64
PSP_SIZE_V7(e2k_psp_t psp)
{
	return GET_V7_CPU_REG_SIZE(psp.word);
}

static __always_inline u64
PSP_SIZE_V6(e2k_psp_t psp)
{
	return psp.Size;
}

static __always_inline u64
PSP_SIZE(e2k_psp_t psp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return PSP_SIZE_V7(psp);
	} else {
		return PSP_SIZE_V6(psp);
	}
}

static __always_inline u64
PSP_IND_V7(e2k_psp_t psp)
{
	return GET_V7_CPU_REG_IND(psp.word);
}

static __always_inline u64
PSP_IND_V6(e2k_psp_t psp)
{
	return psp.Ind;
}

static __always_inline u64
PSP_IND(e2k_psp_t psp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return PSP_IND_V7(psp);
	} else {
		return PSP_IND_V6(psp);
	}
}

static __always_inline u64
PSP_PTR_V7(e2k_psp_t psp)
{
	return GET_V7_CPU_REG_PTR(psp.word);
}

static __always_inline u64
PSP_PTR_V6(e2k_psp_t psp)
{
	return psp.Base + psp.Ind;
}

static __always_inline u64
PSP_PTR(e2k_psp_t psp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return PSP_PTR_V7(psp);
	} else {
		return PSP_PTR_V6(psp);
	}
}

static __always_inline e2k_psp_t
new_psp_v7(u64 base, u64 size, u64 ind)
{
	return (e2k_psp_t) {.word = NEW_V7_CPU_REG(base, ind, size)};
}

static __always_inline e2k_psp_t
new_psp_v6(u64 base, u64 size, u64 ind)
{
	return (e2k_psp_t) {.Base = base, .Size = size, .Ind  = ind};
}

static __always_inline e2k_psp_t
new_psp(u64 base, u64 size, u64 ind)
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

static __always_inline u64
PCSP_BASE_V7(e2k_pcsp_t pcsp)
{
	return GET_V7_CPU_REG_BASE(pcsp.word);
}

static __always_inline u64
PCSP_BASE_V6(e2k_pcsp_t pcsp)
{
	return pcsp.Base;
}

static __always_inline u64
PCSP_BASE(e2k_pcsp_t pcsp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return PCSP_BASE_V7(pcsp);
	} else {
		return PCSP_BASE_V6(pcsp);
	}
}

static __always_inline u64
PCSP_SIZE_V7(e2k_pcsp_t pcsp)
{
	return GET_V7_CPU_REG_SIZE(pcsp.word);
}

static __always_inline u64
PCSP_SIZE_V6(e2k_pcsp_t pcsp)
{
	return pcsp.Size;
}

static __always_inline u64
PCSP_SIZE(e2k_pcsp_t pcsp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return PCSP_SIZE_V7(pcsp);
	} else {
		return PCSP_SIZE_V6(pcsp);
	}
}

static __always_inline u64
PCSP_IND_V7(e2k_pcsp_t pcsp)
{
	return GET_V7_CPU_REG_IND(pcsp.word);
}

static __always_inline u64
PCSP_IND_V6(e2k_pcsp_t pcsp)
{
	return pcsp.Ind;
}

static __always_inline u64
PCSP_IND(e2k_pcsp_t pcsp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return PCSP_IND_V7(pcsp);
	} else {
		return PCSP_IND_V6(pcsp);
	}
}

static __always_inline u64
PCSP_PTR_V7(e2k_pcsp_t pcsp)
{
	return GET_V7_CPU_REG_PTR(pcsp.word);
}

static __always_inline u64
PCSP_PTR_V6(e2k_pcsp_t pcsp)
{
	return pcsp.Base + pcsp.Ind;
}

static __always_inline u64
PCSP_PTR(e2k_pcsp_t pcsp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return PCSP_PTR_V7(pcsp);
	} else {
		return PCSP_PTR_V6(pcsp);
	}
}

static __always_inline e2k_pcsp_t
new_pcsp_v7(u64 base, u64 size, u64 ind)
{
	return (e2k_pcsp_t) {.word = NEW_V7_CPU_REG(base, ind, size)};
}

static __always_inline e2k_pcsp_t
new_pcsp_v6(u64 base, u64 size, u64 ind)
{
	return (e2k_pcsp_t) {.Base = base, .Size = size, .Ind  = ind};
}

static __always_inline e2k_pcsp_t
new_pcsp(u64 base, u64 size, u64 ind)
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
 * User Stack Descriptor (USD)
 * contains free memory space dedicated for user stack data and
 * is supposed to grow from higher memory addresses to lower ones
 */

static __always_inline u64
USD_PTR_V7(e2k_usd_t usd)
{
	return GET_V7_CPU_REG_PTR(usd.word);
}

static __always_inline u64
USD_PTR_V6(e2k_usd_t usd)
{
	return usd.Ptr;
}

static __always_inline u64
USD_PTR(e2k_usd_t usd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return USD_PTR_V7(usd);
	} else {
		return USD_PTR_V6(usd);
	}
}

static __always_inline u64
USD_IND_V7(e2k_usd_t usd)
{
	return GET_V7_CPU_REG_IND(usd.word);
}

static __always_inline u64
USD_IND_V6(e2k_usd_t usd)
{
	return usd.Ind;
}

static __always_inline u64
USD_IND(e2k_usd_t usd)
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
static __always_inline u64
USD_BASE_V7(e2k_usd_t usd)
{
	return GET_V7_CPU_REG_BASE(usd.word);
}

static __always_inline u64
USD_BASE_V6(e2k_usd_t usd)
{
	return usd.Ptr - usd.Ind;
}

static __always_inline u64
USD_BASE(e2k_usd_t usd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return USD_BASE_V7(usd);
	} else {
		return USD_BASE_V6(usd);
	}
}

static __always_inline u64
USD_SIZE_V7(e2k_usd_t usd)
{
	return GET_V7_CPU_REG_SIZE(usd.word);
}

static __always_inline u64
USD_SIZE(e2k_usd_t usd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return USD_SIZE_V7(usd);
	} else {
		return 0ULL;
	}
}

static __always_inline u64
USD_PPTR_V7(e2k_usd_t usd)
{
	return GET_V7_CPU_REG_PTR(usd.word);
}

static __always_inline u64
USD_PPTR_V6(e2k_usd_t usd)
{
	return usd.P_ptr;
}

static __always_inline u64
USD_PPTR(e2k_usd_t usd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return USD_PPTR_V7(usd);
	}
	return USD_PPTR_V6(usd);
}

static __always_inline u32
USD_PSL_V6(e2k_usd_t usd)
{
	return usd.Psl;
}

static __always_inline u32
USD_PSL(e2k_usd_t usd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return 0;
	} else {
		return USD_PSL_V6(usd);
	}
}

static __always_inline bool
USD_P_V7(void)
{
	return false;
}

static __always_inline bool
USD_P_V6(e2k_usd_t usd)
{
	return !!usd.P;
}

static __always_inline bool
USD_P(e2k_usd_t usd)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return USD_P_V7();
	} else {
		return USD_P_V6(usd);
	}
}

static __always_inline e2k_usd_t
new_usd_v7(u64 base, u64 size, u64 ind)
{
	e2k_usd_t usd = (e2k_usd_t) {
		.word = NEW_V7_CPU_REG(base, ind, size)
	};
	usd.perm.w = 1;
	usd.perm.r = 1;
	return usd;
}

static __always_inline e2k_usd_t
new_usd_v6(u64 base, u64 ind)
{
	return (e2k_usd_t) {.Ptr = base + ind, .Ind = ind};
}

static __always_inline e2k_usd_t
new_usd(u64 base, u64 size, u64 ind)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return new_usd_v7(base, size, ind);
	} else {
		return new_usd_v6(base, ind);
	}
}

static __always_inline e2k_usd_t
new_pusd_v7(u64 base, u64 size, u64 ind)
{
	return new_usd_v7(base, size, ind);
}

static __always_inline e2k_usd_t
new_pusd_v6(u64 base, u64 ind, u32 psl)
{
	return (e2k_usd_t) {
		.P_ptr = (base + ind) & E2K_PROTECTED_STACK_BASE_MASK,
		.Ind = ind,
		.Psl = psl,
		.P = 1
	};
}

static __always_inline e2k_usd_t
new_pusd(u64 base, u64 size, u64 ind, u32 psl)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return new_pusd_v7(base, size, ind);
	} else {
		return new_pusd_v6(base, ind, psl);
	}
}


static __always_inline __must_check e2k_usd_t set_usd_ind(e2k_usd_t usd, u64 ind)
{
	return new_usd(USD_BASE(usd), USD_SIZE(usd), ind);
}


static __always_inline __must_check e2k_usd_t incr_usd_ind(e2k_usd_t usd, u64 delta)
{
	return set_usd_ind(usd, USD_IND(usd) + delta);
}


static __always_inline __must_check e2k_usd_t decr_usd_ind(e2k_usd_t usd, u64 delta)
{
	return set_usd_ind(usd, USD_IND(usd) - delta);
}

/* CR */

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

static __always_inline void
set_cr1p_ussz_v7(e2k_cr1_t *cr1p,  u64 sz)
{
	cr1p->ussz_lo = ((u64)(sz) >> 4) & 0x0fffffff;
	cr1p->ussz_hi = ((u64)(sz) >> 32) & 0x0ffff;
}

static __always_inline void
set_cr1p_ussz_v6(e2k_cr1_t *cr1p,  u64 sz)
{
	cr1p->ussz_lo = ((u64)(sz) >> 4) & 0x0fffffff;
}

static __always_inline void
set_cr1p_ussz(e2k_cr1_t *cr1p,  u64 sz)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		set_cr1p_ussz_v7(cr1p, sz);
	} else {
		set_cr1p_ussz_v6(cr1p, sz);
	}
}

/* CTPR */

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

/* DIMTP */

static inline u64
DIMTP_BASE(e2k_dimtp_t dimtp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return GET_V7_CPU_REG_BASE(dimtp.word);
	} else {
		return dimtp.base;
	}
}

static __always_inline u64
DIMTP_SIZE(e2k_dimtp_t dimtp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return GET_V7_CPU_REG_SIZE(dimtp.word);
	} else {
		return dimtp.size;
	}
}

static __always_inline u64
DIMTP_IND(e2k_dimtp_t dimtp)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return GET_V7_CPU_REG_IND(dimtp.word);
	} else {
		return dimtp.ind;
	}

}

static __always_inline e2k_dimtp_t
new_dimtp(u64 base, u64 size, u64 ind)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return (e2k_dimtp_t) {.word = NEW_V7_CPU_REG(base, ind, size)};
	} else {
		return (e2k_dimtp_t) {.base = base, .size = size, .ind = ind};
	}
}


/* Functions to print registers */

#include <linux/printk.h>

static __always_inline void print_USD(char *prolog, e2k_usd_t usd)
{
	pr_info("%s: USD: base 0x%llx, ind 0x%llx, size 0x%llx. lo:hi 0x%llx : 0x%llx\n",
		prolog, USD_BASE(usd), USD_IND(usd), USD_SIZE(usd), LO(usd), HI(usd));
}

#endif /* ! __ASSEMBLY__ */

#endif /* _E2K_CPU_REGS_TYPES_H_ */
