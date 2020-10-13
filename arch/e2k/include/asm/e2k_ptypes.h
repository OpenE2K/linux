 
 
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

typedef	union {	/* High word of all pointers */
	struct {
		u64 curptr	: 32;		/* [31: 0] */
		u64 size	: 32;		/* [63:32] */
	} fields;
	u64 word;
} e2k_ptr_hi_t;

typedef union {
	union {
		struct {
			u64 base	: E2K_VA_SIZE;		/* [47: 0] */
			u64 unused	: 59 - E2K_VA_SIZE;	/* [58:48] */
			u64 rw		: 2;			/* [60:59] */
			u64 itag	: 3;			/* [63:61] */
		} ap;
		struct {
			u64 base	: 32;		/* [31: 0] */
			u64 psl		: 16;		/* [47:32] */
			u64 unused	: 11;		/* [58:48] */
			u64 rw		: 2;		/* [60:59] */
			u64 itag	: 3;		/* [63:61] */
		} sap;
		struct {
			u64 unused1 : 59;		/* [58: 0] */
			u64 rw      : 2;		/* [60:59] */
			u64 itag    : 3;		/* [63:61] */
		};
		struct {
			u64 unused2 : 59;		/* [58: 0] */
			u64 r       : 1;		/* [59:59] */
			u64 w       : 1;		/* [60:60] */
			u64 unused3 : 3;		/* [63:61] */
		};
	} fields;
	u64 word;
} e2k_ptr_lo_t;

typedef	union {	/* Lower word of array pointer */
	union {
		struct {
			u64 base	: E2K_VA_SIZE;		/* [47: 0] */
			u64 unused	: 59 - E2K_VA_SIZE;	/* [58:48] */
			u64 rw		: 2;			/* [60:59] */
			u64 itag	: 3;			/* [63:61] */
		};
		struct {
			u64 __unused1	: 59;		/* [58: 0] */
			u64 r		: 1;		/* [59:59] */
			u64 w		: 1;		/* [60:60] */
			u64 __unused2	: 3;		/* [63:61] */
		};
	} fields;
	u64 word;
} e2k_ap_lo_t;

typedef	union {	/* Lower word of stack array pointer */
	union {
		struct {
			u64 base	: 32;		/* [31: 0] */
			u64 psl		: 16;		/* [47:32] */
			u64 unused	: 11;		/* [58:48] */
			u64 rw		: 2;		/* [60:59] */
			u64 itag	: 3;		/* [63:61] */
		};
		struct {
			u64 __unused2	: 59;		/* [58: 0] */
			u64 r		: 1;		/* [59:59] */
			u64 w		: 1;		/* [60:60] */
			u64 __unused3	: 3;		/* [63:61] */
		};
	} fields;
	u64 word;
} e2k_sap_lo_t;

typedef struct {
	union {
		struct {
			u64 base    : E2K_VA_SIZE;	/* [47: 0] */
			u64 unused1 : 59 - E2K_VA_SIZE;	/* [58:48] */
			u64 rw      : 2;			/* [60:59] */
			u64 itag    : 3;			/* [63:61] */
		};
		struct {
			u64 unused2 : 59;		/* [58: 0] */
			u64 r       : 1;		/* [59:59] */
			u64 w       : 1;		/* [60:60] */
			u64 unused3 : 3;		/* [63:61] */
		};
	};
	struct {
		u64 curptr : 32;		/* [31: 0] */
		u64 size   : 32;		/* [63:32] */
	};
} e2k_ap_t;

typedef struct {
	union {
		struct {
			u64 base    : 32;		/* [31: 0] */
			u64 psl     : 16;		/* [47:32] */
			u64 unused1 : 11;		/* [58:48] */
			u64 rw      : 2;		/* [60:59] */
			u64 itag    : 3;		/* [63:61] */
		};
		struct {
			u64 unused2 : 59;		/* [58: 0] */
			u64 r       : 1;		/* [59:59] */
			u64 w       : 1;		/* [60:60] */
			u64 unused3 : 3;		/* [63:61] */
		};
	};
	struct {
		u64 curptr : 32;		/* [31: 0] */
		u64 size   : 32;		/* [63:32] */
	};
} e2k_sap_t;

typedef union {	/* Common array pointer */
	union {
		e2k_ap_t ap;
		e2k_sap_t sap;
		struct {
			/* Low word common fields */
			union {
				struct {
					u64 unused1 : 59;	/* [58:0] */
					u64 rw      : 2;	/* [60:59] */
					u64 itag    : 3;	/* [63:61] */
				};
				struct {
					u64 unused2 : 59;	/* [58: 0] */
					u64 r       : 1;	/* [59:59] */
					u64 w       : 1;	/* [60:60] */
					u64 unused3 : 3;	/* [63:61] */
				};
			};
			/* High word common fields */
			struct {
				u64 curptr : 32;		/* [31: 0] */
				u64 size   : 32;		/* [63:32] */
			};
		};
	} fields;
	struct {
		long	lo;
		long	hi;
	} word;
} e2k_ptr_t;

#define	R_ENABLE	0x1
#define	W_ENABLE	0x2
#define	RW_ENABLE	0x3

#define AP_ITAG_MASK	0xe000000000000000ULL
#define AP_ITAG_SHIFT	61
#define	AP_ITAG		0x0UL
#define	SAP_ITAG	0x4UL

#define	__E2K_PTR_BASE(low) \
({ \
	e2k_ptr_lo_t lo; \
	AW(lo) = low; \
	(AS(lo).itag == AP_ITAG ? AS(lo).ap.base : (AS(lo).sap.base + \
		(current_thread_info()->u_stk_base & 0xFFFF00000000UL))); \
})
#define	__E2K_PTR_PTR(low, hiw)	\
({ \
	e2k_ptr_hi_t hi; \
	AW(hi) = hiw; \
	(__E2K_PTR_BASE(low) + AS(hi).curptr); \
})

#define	E2K_PTR_BASE(p)		(AS(p).itag == AP_ITAG ? \
		AS(p).ap.base : (AS(p).sap.base + \
		(current_thread_info()->u_stk_base & 0xFFFF00000000UL)))
#define	E2K_PTRP_BASE(p)	(ASP(p).itag == AP_ITAG ? \
		ASP(p).ap.base : (ASP(p).sap.base + \
		(current_thread_info()->u_stk_base & 0xFFFF00000000UL)))

#define	E2K_PTR_PTR(p)		(unsigned long)(E2K_PTR_BASE(p) + \
						AS(p).curptr)
#define	E2K_PTRP_PTR(p)	(unsigned long)(E2K_PTRP_BASE(p) + \
					ASP(p).curptr)



		/* handling Address Pointers */

#define MAKE_AP_LO(area_base, area_size, off, access)	\
({							\
	e2k_ap_lo_t __lo;				\
	AW(__lo) = 0UL;					\
	AS(__lo).base = area_base;			\
	AS(__lo).rw     = access;			\
	AS(__lo).itag   = E2K_AP_ITAG;			\
	AW(__lo);					\
})

#define MAKE_AP_HI(area_base, area_size, offs, access) 	\
({							\
        union {						\
		e2k_ptr_hi_t hi;			\
		u64             w;			\
	} u;						\
	u.w             = 0UL;				\
	AS(u.hi).size   = area_size;			\
	AS(u.hi).curptr = offs;				\
	u.w;						\
})

#define MAKE_SAP_LO(area_base, area_size, offs, access) \
({                                                      \
	e2k_rwsap_lo_struct_t sap_lo;                   \
	AS_WORD(sap_lo) = 0;                            \
	AS_SAP_STRUCT(sap_lo).base = area_base;         \
	AS_SAP_STRUCT(sap_lo).rw = access;              \
	AS_SAP_STRUCT(sap_lo).itag = E2K_SAP_ITAG;      \
	AS_WORD(sap_lo);                                \
})

#define MAKE_SAP_HI(area_base, area_size, offs, access) \
({                                                      \
	e2k_rwsap_hi_struct_t sap_hi;                   \
	AS_WORD(sap_hi) = 0;                            \
	AS_STRUCT(sap_hi).size = area_size;             \
	AS_STRUCT(sap_hi).curptr = offs;                \
	AS_WORD(sap_hi);                                \
})

static inline e2k_ptr_t MAKE_AP(u64 base, u64 len)
{
	e2k_ptr_t ptr = {{0}};
	AW(ptr).lo = 0L | ((base & (E2K_VA_SIZE -1)) |
		((u64)E2K_AP_ITAG << 61) |
		((u64)RW_ENABLE << 59));
	AW(ptr).hi = 0L | ((len & 0xFFFFFFFF) << 32);
	return ptr;
}


/*
 * Procedure Label (PL)
 */

typedef	struct e2k_pl_fields {
	u64	target		: E2K_VA_SIZE;		/* [47: 0] */
	u64	unused3		: 55 - E2K_VA_MSB;	/* [55:48] */
	u64	stub3		:  1;	/* [56] */
	u64	stub2		:  1;	/* [57] */
	u64	stub1		:  1;	/* [58] */
	u64	pm		:  1;	/* [59]	privileged mode */
					/*	(affects only on E3S) */
	u64	unused2		:  2;	/* [61:60] */
	u64	itag		:  1;	/* [62] */
	u64	unused1		:  1;	/* [63] */
} e2k_pl_fields_t;

typedef	union  {
	e2k_pl_fields_t	fields;
	u64		word;
} e2k_pl_t;

#define	PL_TARGET	fields.target
#define	PL_ITAG		fields.itag
#define	PL_PM		fields.pm
#define	IS_PL_ITAG(a)   (((a & 0x4000000000000000UL) >> 62) == E2K_PL_ITAG)

static inline e2k_pl_t DO_MAKE_PL(u64 addr, int pm)
{
	e2k_pl_t pl = {{ 0 }};
	pl.PL_TARGET = addr;
	pl.PL_PM = pm;
	pl.PL_ITAG = E2K_PL_ITAG;
	return pl;
}

static inline e2k_pl_t MAKE_PL(u64 addr)
{
	return DO_MAKE_PL(addr, 0);
}

static inline e2k_pl_t MAKE_PRIV_PL(u64 addr)
{
	return DO_MAKE_PL(addr, 1);
}

#endif	/*  __ASSEMBLY__ */

#endif	/* _E2K_PTYPES_H_ */
