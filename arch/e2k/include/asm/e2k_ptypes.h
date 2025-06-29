/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 *	Descriptions of E2K tagged types
 */
 
#ifndef	_E2K_PTYPES_H_
#define	_E2K_PTYPES_H_


#ifndef __ASSEMBLY__
#include <asm/e2k_api.h>
#include <asm/base_regs_types.h>
#include <asm/e2k.h>
#include <asm/tags.h>

#include <asm/aau_regs_types.h>

/*
 *	Tagged values structures
 */

/*		Address Pointers		*/


typedef union {
	struct {
		union {
			struct { /* Low word of v6 RWAP */
				u64 Base	: E2K_VA_SIZE;	/* [47: 0] */
				u64 unused	: 59 - E2K_VA_SIZE;
				u64 rw_v6	: 2;
				u64 itag_v6	: 3;
			};
			struct { /* Low word of v6 SAP */
				u64 p_base	: 32;
				u64 psl		: 16;
			};
			struct { /* Low word of v7 AP */
				u64 Ptr		: E2K_VA_SIZE;
				u64		: 12;
				u64 color	: 4; /* [63 : 4] */
			};
		};
		union {
			struct { /* High word of v6 RWAP */
				s32 Curptr;
				u32 Size;
			};
			struct { /* High word of v7 AP interesting fields*/
				u64		: 60;
				u64 rw_v7	: 2;
				u64 itag_v7	: 2;
			};
		};
	};
	e2k_qreg_t qword; /* whole descriptor structure (AP) */
	e2k_qreg_t;
} __aligned(16) e2k_ptr_t;
typedef e2k_ptr_t e2k_ap_t;


#define	R_ENABLE	0x1
#define	W_ENABLE	0x2
#define	RW_ENABLE	0x3

#define	ITAG_AP		0
#define	ITAG_PL		1


#define AP_ITAG(ap)	(unlikely(cpu_has(CPU_FEAT_ISET_V7)) ? (ap).itag_v7 : (ap).itag_v6)
#define AP_RW(ap)	(unlikely(cpu_has(CPU_FEAT_ISET_V7)) ? (ap).rw_v7 : (ap).rw_v6)

#define IS_AP_V6(ap, tag)	((tag) == ETAGAPQ_V6)
#define IS_AP(ap, tag)	(unlikely(cpu_has(CPU_FEAT_ISET_V7)) \
					? (((tag) == ETAGAPQ_V7) && ((ap).itag_v7 == ITAG_AP)) \
					: IS_AP_V6(ap, tag))

#define IS_PL(pl, tag)	(unlikely(cpu_has(CPU_FEAT_ISET_V7)) ? \
				(((tag) == ETAGPLQ) && ((pl).itag_v7 == ITAG_PL)) : \
				((((tag) & 0xf) == ETAGPLD) || ((tag) == ETAGPLQ)))

/* handling Address Pointers */

static __always_inline u64 AP_BASE(e2k_ap_t ap)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return GET_V7_CPU_REG_BASE(ap.qword);
	} else {
		return ap.Base;
	}
}
 
 
static __always_inline u64 AP_SIZE(e2k_ap_t ap)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return GET_V7_CPU_REG_SIZE(ap.qword);
	} else {
		return ap.Size;
	}
}


static __always_inline u64 AP_IND(e2k_ap_t ap)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return GET_V7_CPU_REG_IND(ap.qword);
	} else {
		return ap.Curptr;
	}
}

static __always_inline u64 AP_PTR(e2k_ap_t ap)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return GET_V7_CPU_REG_PTR(ap.qword);
	} else {
		return ap.Base + ap.Curptr;
	}
}

static __always_inline u64 AP_PTRC(e2k_ap_t ap)
{
	if (cpu_has(CPU_FEAT_MADM)) {
		return GET_V7_CPU_REG_PTRC(ap.qword);
	}
	return AP_PTR(ap);
}

static __always_inline long AP_OBJ_SIZE(e2k_ap_t p)
{
	return (long)AP_SIZE(p) - (long)AP_IND(p);
}



static __always_inline e2k_ap_t
new_ap(u64 base, u64 size, u64 ind, u64 rw)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		e2k_ap_t ap = (e2k_ap_t){.qword = NEW_V7_CPU_REG(base, ind, size)};
		ap.rw_v7 = rw;
		ap.itag_v7 = ITAG_AP;
		return ap;
	} else {
		e2k_ap_t ap = (e2k_ap_t) {.Base	= base, .Size	= size, .Curptr	= ind};
		ap.rw_v6 = rw;
		ap.itag_v6 = E2K_AP_ITAG;
		return ap;
	}
}

#define MAKE_AP(base, len)	new_ap((u64)(base), (u64)(len), 0, RW_ENABLE)


/*
 * Procedure Label (PL)
 */


typedef union {
	struct  {
		struct {  /* PL lo word */
			u64 target	: E2K_VA_SIZE;
			u64		: 11;
			u64 pm_v6	: 1; /* [59] */
			u64		: 1;
			u64 itag_v6	: 3;
		};
		struct {  /* PL hi word */
			u64 cui		: 16;	/* [15: 0] compilation unit index */
			u64		: 42;	/* [57:16] */
			u64 pm_v7	: 1;	/* [58] */
			u64		: 3;	/* [61:59] */
			u64 itag_v7	: 2;	/* [63:62] */
		};
	};
	e2k_qreg_t;
	e2k_qreg_t qword; /* whole descriptor structure (PL) */
} __aligned(16) e2k_pl_t;

static inline e2k_pl_t DO_MAKE_PL_V3(u64 addr, bool pm)
{
	return (e2k_pl_t) {
		.target = addr,
		.pm_v6 = pm,
		.itag_v6 = E2K_PL_V3_ITAG,
		.cui = 0,
	};
}

static inline e2k_pl_t DO_MAKE_PL_V6(u64 addr, bool pm, unsigned int cui)
{
	return (e2k_pl_t) {
		.target = addr,
		.pm_v6 = pm,
		.itag_v6 = E2K_PL_ITAG,
		.cui = cui,
	};
}

static inline e2k_pl_t DO_MAKE_PL_V7(u64 addr, bool pm, unsigned int cui)
{
	return (e2k_pl_t) {
		.target = addr,
		.pm_v7 = pm,
		.itag_v7 = 1,
		.cui = cui,
	};
}


static inline e2k_pl_t new_pl(u64 addr,  unsigned int cui)
{
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		return DO_MAKE_PL_V7(addr, false, cui);
	}
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		return DO_MAKE_PL_V6(addr, false, cui);
	}
	return DO_MAKE_PL_V3(addr, false);
}

static inline e2k_pl_t new_priv_pl(u64 addr,  unsigned int cui)
{
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		return DO_MAKE_PL_V7(addr, true, cui);
	}
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		return DO_MAKE_PL_V6(addr, true, cui);
	}
	return DO_MAKE_PL_V3(addr, true);
}


#define MAKE_PL(addr, cui)	new_pl((u64)(addr), (unsigned int)(cui))

#define MAKE_PRIV_PL(addr, cui)	new_priv_pl((u64)(addr), (unsigned int)(cui))

static __always_inline u64 AAD_BASE(e2k_aadj_t aadj)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return GET_V7_CPU_REG_BASE(aadj.qword);
	} else {
		return aadj.ap_base;
	}
}

static __always_inline u64 AAD_SIZE(e2k_aadj_t aadj)
{
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		return GET_V7_CPU_REG_SIZE(aadj.qword);
	} else {
		return aadj.size;
	}
}

#define IS_AAD_AP_V6(aadj) (aadj.tag == AAD_AAUAP)
#define IS_AAD_AP_V7(aadj) (aadj.tag1 == AAD_AAUAP_V7)

#define IS_AAD_SAP_V6(aadj) (aadj.tag == AAD_AAUSAP)

#define AAD_IS_AP(aadj) (cpu_has(CPU_FEAT_ISET_V7) ? \
			IS_AAD_AP_V7(aadj) : IS_AAD_AP_V6(aadj))

#define AAD_IS_SAP(aadj) (cpu_has(CPU_FEAT_ISET_V7) ? \
			0 : IS_AAD_SAP_V6(aadj))

#define IS_AAD_SD_V6(aadj) (aadj.tag == AAD_AAUDS)
#define IS_AAD_SD_V7(aadj) (aadj.tag1 == AAD_AAUDS_V7)

/* If AADj has aauds tag, it contains a segment descriptor */
#define AAD_IS_SD(aadj) (cpu_has(CPU_FEAT_ISET_V7) ? \
			IS_AAD_SD_V7(aadj) : IS_AAD_SD_V6(aadj))

#endif	/*  __ASSEMBLY__ */

#endif	/* _E2K_PTYPES_H_ */
