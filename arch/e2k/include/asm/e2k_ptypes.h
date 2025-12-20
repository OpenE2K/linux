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
#include <asm/cpu_regs.h>
#include <asm/e2k.h>
#include <asm/tags.h>


		/*
		 *	Tagged values structures
		 */

	/*		Address Pointers		*/


typedef struct { /* High word of pointer */
		s32 curptr;
		u32 size;
} e2k_ap_hi_t;


typedef	union {	/* High word of pointer */
	e2k_ap_hi_t;
	u64 word;
} e2k_ptr_hi_t;

typedef union { /* Low word of pointer */
	struct {
		u64 base	: E2K_VA_SIZE;		/* [47: 0] */
		u64 unused	: 59 - E2K_VA_SIZE;	/* [58:48] */
		u64 rw		: 2;			/* [60:59] */
		u64 itag	: 3;			/* [63:61] */
	};
	struct {
		u64 unused2 : 59;			/* [58: 0] */
		u64 r       : 1;			/* [59:59] */
		u64 w       : 1;			/* [60:60] */
		u64 unused3 : 3;			/* [63:61] */
	};
} e2k_ap_lo_t;


typedef	union {	/* Low word of pointer */
	e2k_ap_lo_t;
	u64 word;
} e2k_ptr_lo_t;


typedef union {	/*  array pointer */
	struct {
		e2k_ap_lo_t;
		e2k_ap_hi_t;
	};
	struct {
		u64	lo;
		u64	hi;
	};
} __aligned(16) e2k_ptr_t;

#define	R_ENABLE	0x1
#define	W_ENABLE	0x2
#define	RW_ENABLE	0x3

#define AP_ITAG_MASK	0xe000000000000000ULL
#define AP_ITAG_SHIFT	61
#define	AP_ITAG		0x0UL
#define	SAP_ITAG	0x4UL

#define	E2K_PTR_PTR(p)	(p.base + p.curptr)


		/* handling Address Pointers */
#define	__E2K_PTR_PTR(low, hiw)	\
({ \
	e2k_ptr_hi_t hi; \
	e2k_ptr_lo_t lo; \
	AW(hi) = hiw; \
	AW(lo) = low; \
	(lo.base + hi.curptr); \
})



#define MAKE_AP_LO(area_base, area_size, off, access)	\
({							\
	e2k_ptr_lo_t __lo;				\
	AW(__lo) = 0UL;					\
	__lo.base = area_base;				\
	__lo.rw     = access;				\
	__lo.itag   = E2K_AP_ITAG;			\
	AW(__lo);					\
})

#define MAKE_AP_HI(area_base, area_size, offs, access) 	\
({							\
	e2k_ptr_hi_t __hi;				\
	AW(__hi)         = 0UL;				\
	__hi.size   = area_size;			\
	__hi.curptr = offs;				\
	AW(__hi);					\
})


static inline e2k_ptr_t MAKE_AP(u64 base, u64 len)
{
	e2k_ptr_t ptr = {{0}};
	ptr.lo = 0L | ((base & E2K_VA_MASK) |
		((u64)E2K_AP_ITAG << 61) |
		((u64)RW_ENABLE << 59));
	ptr.hi = 0L | ((len & 0xFFFFFFFF) << 32);
	return ptr;
}


/*
 * Procedure Label (PL)
 */

typedef	union e2k_pl_lo {
	struct {
		u64 target  : E2K_VA_SIZE;
		u64 unused1 : 58 - E2K_VA_MSB;
		u64 pm      : 1;
		u64 unused2 : 1;
		u64 itag    : 3;
	};
	u64 word;
} e2k_pl_lo_t;

typedef	union e2k_pl_hi {
	struct {
		u64 cui : 16;	/* [15: 0] compilation unit index */
		u64	: 48;	/* [63:16] */
	};
	u64 word;
} e2k_pl_hi_t;

typedef struct e2k_pl {
	union {
		struct {
			u64 target	: E2K_VA_SIZE;
			u64 unused1	: 58 - E2K_VA_MSB;
			u64 pm		: 1;
			u64 unused2	: 1;
			u64 itag	: 3;
		};
		e2k_pl_lo_t lo;
	};
	union {
		struct {
			u64 cui	: 16;	/* [15: 0] compilation unit index */
			u64	: 48;	/* [63:16] */
		};
		e2k_pl_hi_t hi;
	};
} __aligned(16) e2k_pl_t;

static inline e2k_pl_t DO_MAKE_PL_V3(u64 addr, bool pm)
{
	return (e2k_pl_t) {
		.target = addr,
		.pm = pm,
		.itag = E2K_PL_V3_ITAG,
	};
}

static inline e2k_pl_t DO_MAKE_PL_V6(u64 addr, bool pm, unsigned int cui)
{
	return (e2k_pl_t) {
		.target = addr,
		.pm = pm,
		.itag = E2K_PL_ITAG,
		.cui = cui,
	};
}

static inline e2k_pl_t MAKE_PL_V3(u64 addr)
{
	return DO_MAKE_PL_V3(addr, false);
}

static inline e2k_pl_t MAKE_PL_V6(u64 addr,  unsigned int cui)
{
	return DO_MAKE_PL_V6(addr, false, cui);
}

static inline e2k_pl_t MAKE_PL(u64 addr, unsigned int cui)
{
	return MAKE_PL_V6(addr, cui);
}

static inline e2k_pl_t MAKE_PRIV_PL(u64 addr, unsigned int cui)
{
	return DO_MAKE_PL_V6(addr, true, cui);
}

#endif	/*  __ASSEMBLY__ */

#endif	/* _E2K_PTYPES_H_ */
