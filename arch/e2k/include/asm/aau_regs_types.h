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
#include <asm/cpu_regs_types.h>

#if	CONFIG_CPU_ISET >= 5
#  define	IS_AAU_ISET_V5()	true
#  define	IS_AAU_ISET_V2()	false
#  define	IS_AAU_ISET_GENERIC()	false
#elif	CONFIG_CPU_ISET >= 1
#  define	IS_AAU_ISET_V2()	true
#  define	IS_AAU_ISET_V5()	false
#  define	IS_AAU_ISET_GENERIC()	false
#elif	CONFIG_CPU_ISET == 0
#  define	IS_AAU_ISET_GENERIC()	true
#  define	IS_AAU_ISET_V2()	false
#  define	IS_AAU_ISET_V5()	false
#else	/* CONFIG_CPU_ISET undefined or negative */
# warning "Undefined CPU ISET VERSION #, IS_AAU_ISET_Vx is defined dinamicaly"
#  define	IS_AAU_ISET_GENERIC()	true
#  define	IS_AAU_ISET_V2()	false
#  define	IS_AAU_ISET_V5()	false
#endif	/* CONFIG_CPU_ISET 0-6 */

/* Values for AASR.lds */
enum {
	AASR_NULL = 0,
	AASR_READY = 1,
	AASR_ACTIVE = 3,
	AASR_STOPPED = 5
};
#define AAU_AASR_STB 0x20
#define AAU_AASR_IAB 0x40
typedef struct e2k_aasr_fields {
	u32 reserved    : 5;    /* [4:0] */
	u32 stb         : 1;    /* [5:5] */
	u32 iab         : 1;    /* [6:6] */
	u32 lds         : 3;    /* [9:7] */
} e2k_aasr_fields_t;
typedef union e2k_aasr {                       /* aadj quad-word */
	e2k_aasr_fields_t fields;
	u32 word;
} e2k_aasr_t;

/* Check up AAU state */
#define AAU_NULL(aasr)		(AS(aasr).lds == AASR_NULL)
#define AAU_READY(aasr)		(AS(aasr).lds == AASR_READY)
#define AAU_ACTIVE(aasr)	(AS(aasr).lds == AASR_ACTIVE)
#define AAU_STOPPED(aasr)	(AS(aasr).lds == AASR_STOPPED)

typedef u32	e2k_aafstr_t;

/* Values for AAD.tag */
enum {
	AAD_AAUNV = 0,
	AAD_AAUDT = 1,
	AAD_AAUET = 2,
	AAD_AAUAP = 4,
	AAD_AAUSAP = 5,
	AAD_AAUDS = 6
};

/* We are not using AAD SAP format here
 * so it is not described in the structure */
typedef union e2k_aadj_lo_fields {
	struct {
		u64 ap_base	: E2K_VA_SIZE;		/* [E2K_VA_MSB:0] */
		u64 unused1	: 53 - E2K_VA_MSB;	/* [53:48] */
		u64 tag		: 3;			/* [56:54] */
		u64 mb		: 1;			/* [57] */
		u64 ed		: 1;			/* [58] */
		u64 rw		: 2;			/* [60:59] */
		u64 unused2	: 3;			/* [63:60] */
	};
	struct {
		u64 sap_base	: 32;
		u64 psl		: 16;
		u64 __pad	: 16;
	};
} e2k_aadj_lo_fields_t;
typedef struct e2k_aadj_hi_fields {
	u64 unused	: 32;
	u64 size	: 32;	/* [63:32] */
} e2k_aadj_hi_fields_t;
typedef union e2k_aadj {		/* aadj quad-word */
	struct {
		e2k_aadj_lo_fields_t	lo;
		e2k_aadj_hi_fields_t	hi;
	} fields;
	struct {
		u64			lo;
		u64			hi;
	} word;
} e2k_aadj_t;

/* Possible values for aalda.exc field */
enum {
	AALDA_EIO = 1,
	AALDA_EPM = 2,
	AALDA_EPMSI = 3
};

union e2k_u64_struct {			/* aaldv,aaldm,aasta_restore dword */
	struct {
		u32	lo;		/* read/write on left channel */
		u32	hi;		/* read/write on right channel */
	};
	u64 word;
};
typedef union e2k_u64_struct e2k_aaldv_t;
typedef union e2k_u64_struct e2k_aaldm_t;

typedef struct e2k_aalda_fields {
	u8	exc:		2;
	u8	cincr:		1;
	u8	unused1:	1;
	u8	root:		1;
	u8	unused2:	3;
} e2k_aalda_fields_t;

typedef union e2k_aalda_struct {
	e2k_aalda_fields_t	fields;
	u8			word;
} e2k_aalda_t;

#define	AASTIS_REGS_NUM		16
#define	AASTIS_TAG_no		AASTIS_REGS_NUM
#define	AAINDS_REGS_NUM		16
#define	AAINDS_TAG_no		AAINDS_REGS_NUM
#define	AAINCRS_REGS_NUM	8
#define	AAINCRS_TAG_no		AAINCRS_REGS_NUM
#define	AADS_REGS_NUM		32
#define	AALDIS_REGS_NUM		64
#define	AALDAS_REGS_NUM		64

/*
 * For virtualization, aasr might be switched to worst-case scenario (lds = AAU_STOPPED,
 * iab = 1, stb = 1). In that case, real aasr will be saved to guest_aasr
 */
typedef struct e2k_aau_context {
	e2k_aasr_t		aasr;
	e2k_aasr_t		guest_aasr;
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
