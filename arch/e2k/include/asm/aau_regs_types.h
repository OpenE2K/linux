/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * AAU registers structures description
 *
 * array access descriptors			(AAD0, ... , AAD31);
 * initial indices				(AIND0, ... , AAIND15);
 * indices increment values			(AAINCR0, ... , AAINCR7);
 * current values of "prefetch" indices		(AALDI0, ... , AALDI63);
 * array prefetch initialization mask		(AALDV);
 * prefetch attributes				(AALDA0, ... , AALDA63);
 * array prefetch advance mask			(AALDM);
 * array access status register			(AASR);
 * array access fault status register		(AAFSTR);
 * current values of "store" indices		(AASTI0, ... , AASTI15);
 * store attributes				(AASTA0, ... , AASTA15);
 */

#ifndef _E2K_AAU_REGS_TYPES_H_
#define _E2K_AAU_REGS_TYPES_H_

#include <asm/types.h>
#include <asm/cpu_regs_types_defs.h>

#if CONFIG_CPU_ISET_MIN >= 5
#  define	IS_AAU_ISET_V5()	true
#  define	IS_AAU_ISET_V3()	false
#  define	IS_AAU_ISET_GENERIC()	false
#elif defined CONFIG_E2K_MACHINE
#  define	IS_AAU_ISET_V3()	true
#  define	IS_AAU_ISET_V5()	false
#  define	IS_AAU_ISET_GENERIC()	false
#else
#  define	IS_AAU_ISET_GENERIC()	true
#  define	IS_AAU_ISET_V3()	false
#  define	IS_AAU_ISET_V5()	false
#endif

typedef union {			/* aadj quad-word */
	struct {
		u32		: 5;	/* [4:0] */
		u32 stb		: 1;	/* [5:5] */
		u32 iab		: 1;	/* [6:6] */
		u32 lds		: 3;	/* [9:7] */
	};
	e2k_reg_t;
} e2k_aasr_t;

/* Values for AASR.lds */
enum {
	AASR_NULL = 0,
	AASR_READY = 1,
	AASR_ACTIVE = 3,
	AASR_STOPPED = 5
};

#define E2K_FULL_AASR ((e2k_aasr_t) { .stb = 1, .iab = 1, .lds = AASR_STOPPED })
#define E2K_NULL_AASR ((e2k_aasr_t) { .lds = AASR_NULL })

/* Check up AAU state */

static __always_inline bool aau_null(e2k_aasr_t aasr)
{
	return aasr.lds == AASR_NULL;
}

static __always_inline bool aau_ready(e2k_aasr_t aasr)
{
	return aasr.lds == AASR_READY;
}

static __always_inline bool aau_active(e2k_aasr_t aasr)
{
	return aasr.lds == AASR_ACTIVE;
}

static __always_inline bool aau_stopped(e2k_aasr_t aasr)
{
	return aasr.lds == AASR_STOPPED;
}

static __always_inline bool aau_has_state(e2k_aasr_t aasr)
{
	return !aau_null(aasr) || aasr.iab || aasr.stb;
}


typedef u32 e2k_aafstr_t;


/* We are not using AAD SAP format here
 * so it is not described in the structure */
typedef union {			/* aadj quad-word */
	struct {
		union {
			struct {
				u64 ap_base	:E2K_VA_SIZE;
				u64		:53 - E2K_VA_MSB; /* [53:48] */
				u64 tag		:3;	/* [56:54] */
				u64 mb		:1;	/* [57] */
				u64 ed		:1;	/* [58] */
				u64 rw		:2;	/* [60:59] */
				u64		:3;	/* [63:60] */
			};
			struct {
				u64 sap_base	:32;
				u64 psl		:16;
				u64		:16;
			};
			struct {
				/* aadj.lo in v7 iset */
				u64		:60;
				u64 color	:4;
			};
		};
		union {
			struct {
				u64		:32;
				u64 size	:32;	/* [63:32] */
			};
			struct {
				/* aadj.hi in v7 iset */
				u64 max_ind	:32;
				u64		:30;
				u64 tag1	:2;
			};
		};
	};
	e2k_qreg_t;
	e2k_qreg_t qword;
} e2k_aadj_t;

/* Values for AAD.tag up to V6 */
enum {
	AAD_AAUNV = 0,
	AAD_AAUDT = 1,
	AAD_AAUET = 2,
	AAD_AAUAP = 4,
	AAD_AAUSAP = 5,
	AAD_AAUDS = 6
};

/* Values for AAD.tag1 and since V7 */
enum {
	AAD_AAUAP_V7 = 0,
	AAD_AAUDS_V7 = 2,
	AAD_AAUT2_V7 = 3
};


/* aaldv,aaldm,aasta_restore dword */

typedef union {		/* aaldv aasta_restore dword */
	struct {
		u32     lo;	/* read/write on left channel */
		u32     hi;	/* read/write on right channel */
	};
	e2k_dreg_t;
} e2k_aaldv_t;


typedef union {		/* aaldm aasta_restore dword */
	struct {
		u32     lo;	/* read/write on left channel */
		u32     hi;	/* read/write on right channel */
	};
	e2k_dreg_t;
} e2k_aaldm_t;



/* aalda */

typedef union {
	struct {
		u8 exc		:2;
		u8 cincr	:1;
		u8		:1;
		u8 root		:1;
		u8		:3;
	};
	u8 word;
} e2k_aalda_t;

/* Possible values for aalda.exc field */
enum {
	AALDA_EIO = 1,
	AALDA_EPM = 2,
	AALDA_EPMSI = 3
};


#define	E2K_AALDI_SIZE	(E2K_VA_SIZE + 1)
#define	AALDI_SIGN_EXTEND(aaldi) \
		(((s64) (aaldi) << (s64) (64 - E2K_AALDI_SIZE)) \
				 >> (s64) (64 - E2K_AALDI_SIZE))

#define	AASTIS_REGS_NUM		16
#define	AASTIS_TAG_no		AASTIS_REGS_NUM
#define	AAINDS_REGS_NUM		16
#define	AAINDS_TAG_no		AAINDS_REGS_NUM
#define	AAINCRS_REGS_NUM	8
#define	AAINCRS_TAG_no		AAINCRS_REGS_NUM
#define	AADS_REGS_NUM		32
#define	AALDIS_REGS_NUM		64
#define	AALDAS_REGS_NUM		64

typedef struct {
	e2k_aafstr_t		aafstr;
	e2k_aaldm_t		aaldm;
	e2k_aaldv_t		aaldv;

	/* Synchronous part */
	u64			aastis[AASTIS_REGS_NUM];
	u32			aasti_tags;

	/* Asynchronous part */
	u64			aainds[AAINDS_REGS_NUM];
	u32			aaind_tags;
	u64			aaincrs[AAINCRS_REGS_NUM];
	u32			aaincr_tags;
	e2k_aadj_t		aads[AADS_REGS_NUM];
	/* %aaldi [synonim for %aaldsi] must be saved since iset v6 */
	u64			aaldi[AALDIS_REGS_NUM];
} e2k_aau_t;

#endif /* _E2K_AAU_REGS_TYPES_H_ */
