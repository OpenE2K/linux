 
 
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
} __aligned(16) e2k_ptr_t;

#define	R_ENABLE	0x1
#define	W_ENABLE	0x2
#define	RW_ENABLE	0x3

#define AP_ITAG_MASK	0xe000000000000000ULL
#define AP_ITAG_SHIFT	61
#define	AP_ITAG		0x0UL
#define	SAP_ITAG	0x4UL

#define	__E2K_PTR_BASE(low, sbr_hi) \
({ \
	e2k_ptr_lo_t lo; \
	AW(lo) = low; \
	(AS(lo).itag == AP_ITAG ? AS(lo).ap.base : (AS(lo).sap.base + (sbr_hi))); \
})
#define	__E2K_PTR_PTR(low, hiw, sbr_hi)	\
({ \
	e2k_ptr_hi_t hi; \
	AW(hi) = hiw; \
	(__E2K_PTR_BASE(low, (sbr_hi)) + AS(hi).curptr); \
})

#define	E2K_PTR_BASE(p, sbr_hi)	(AS(p).itag == AP_ITAG ? \
		AS(p).ap.base : (AS(p).sap.base + (sbr_hi)))

#define	E2K_PTR_PTR(p, sbr_hi)	(E2K_PTR_BASE(p, (sbr_hi)) + AS(p).curptr)

#define GET_SBR_HI() (current_thread_info()->u_stack.top & 0xffff00000000ULL)

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
	AW(ptr).lo = 0L | ((base & E2K_VA_MASK) |
		((u64)E2K_AP_ITAG << 61) |
		((u64)RW_ENABLE << 59));
	AW(ptr).hi = 0L | ((len & 0xFFFFFFFF) << 32);
	return ptr;
}


/*
 * Procedure Label (PL)
 */

typedef	struct pl_lo_fields {
	u64	target		: E2K_VA_SIZE;		/* [47: 0] */
	u64	unused1		: 58 - E2K_VA_MSB;	/* [58:48] */
	u64	pm		:  1;	/* [59]	privileged mode */
					/*	(affects only from v2) */
	u64	unused2		:  1;	/* [60] */
	u64	itag		:  3;	/* [63:61] internel tag bits */
} pl_lo_fields_t;
#define	PL_PM_BIT		59	/* bit # of privileged label flag */
#define	PL_PM_MASK		(1UL << PL_PM_BIT)
#define	PL_ITAG_SHIFT		61
#define	PL_ITAG_NUM_BITS	 3	/* size of field ITAG in bits */
#define	PL_ITAG_BITS_MASK	((1UL << PL_ITAG_NUM_BITS) - 1)
#define	PL_ITAG_GET(pl_lo_word)	(((pl_lo_word) >> PL_ITAG_SHIFT) &	\
					((1UL << PL_ITAG_NUM_BITS) - 1))
#define	PL_ITAG_SET(pl_lo_word, itag)	\
		(((pl_lo_word) & ~(PL_ITAG_BITS_MASK << PL_ITAG_SHIFT)) | \
			(((itag) & PL_ITAG_BITS_MASK) << PL_ITAG_SHIFT))

typedef	struct pl_hi_fields {
	u64	cui		: 16;	/* [15: 0] compilation unit undex */
	u64	unused3		: 48;	/* [63:16] */
} pl_hi_fields_t;

typedef	union e2k_pl_lo {
	struct {
		u64 target : E2K_VA_SIZE;
		u64 unused1 : 58 - E2K_VA_MSB;
		u64 pm : 1;
		u64 unused2 : 1;
		u64 itag : 3;
	};
	pl_lo_fields_t	fields;
	u64		word;
} e2k_pl_lo_t;
#define	PL_lo_target	fields.target
#define	PL_lo_itag	fields.itag
#define	PL_lo_pm	fields.pm
#define	PL_lo_value	word

typedef	union e2k_pl_hi {
	pl_hi_fields_t	fields;
	u64		word;
} e2k_pl_hi_t;
#define	PL_hi_cui	fields.cui
#define	PL_hi_value	word

typedef struct e2k_pl {
	e2k_pl_lo_t	lo;
	e2k_pl_hi_t	hi;
} e2k_pl_t;

#define	PL_target		lo.PL_lo_target
#define	PL_itag			lo.PL_lo_itag
#define	PL_pm			lo.PL_lo_pm
#define	PL_cui			hi.PL_hi_cui
#define	PLLO_value		lo.PL_lo_value
#define	PLHI_value		hi.PL_hi_value
#define	PLLO_item		lo
#define	PLHI_item		hi
#define	IS_PL_ITAG(pl_lo_word)	(PL_ITAG_GET(pl_lo_word) == E2K_PL_ITAG)

static inline e2k_pl_t DO_MAKE_PL_V2(u64 addr, bool pm)
{
	e2k_pl_t p;
	e2k_pl_lo_t pl;

	pl.PL_lo_value = 0;
	pl.PL_lo_target = addr;
	pl.PL_lo_pm = pm;
	pl.PL_lo_itag = E2K_PL_V2_ITAG;
	p.lo = pl;
	p.hi.word = 0L;
	return p;
}

static inline e2k_pl_t DO_MAKE_PL_V6(u64 addr, bool pm, unsigned int cui)
{
	e2k_pl_t pl;

	pl = DO_MAKE_PL_V2(addr, pm);
	pl.PL_itag = E2K_PL_ITAG;
	pl.PLHI_value = 0;
	pl.PL_cui = cui;
	return pl;
}

static inline e2k_pl_t MAKE_PL_V2(u64 addr)
{
	return DO_MAKE_PL_V2(addr, false);
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

static inline e2k_pl_lo_t DO_MAKE_INTEGER_PL(u64 addr)
{
	e2k_pl_lo_t pl_lo;

	pl_lo.PL_lo_value = 0;
	pl_lo.PL_lo_target = addr;
	return pl_lo;
}
#define	MAKE_INTEGER_PL(func_p)		\
		((typeof(func_p))(DO_MAKE_INTEGER_PL((u64)func_p).PL_lo_value))

#endif	/*  __ASSEMBLY__ */

#endif	/* _E2K_PTYPES_H_ */
