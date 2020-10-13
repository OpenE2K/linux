/*
 * AAU registers description, macroses for load/store AAU context
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

#ifndef _E2K_AAU_H_ 
#define _E2K_AAU_H_

#include <asm/e2k_api.h>
#include <asm/types.h>

/* macros to deal with E2K AAU registers */

#define E2K_GET_AAU_AAD(mem_p,reg_mn)	      E2K_GET_AAUQREG(mem_p,  reg_mn)
#define E2K_GET_AAU_AADS                      E2K_GET_AAUQREGS
#define E2K_GET_AAU_AAIND(reg_mnemonic)	      E2K_GET_AAUREG(reg_mnemonic, 2)
#define E2K_GET_AAU_AAINDS(reg1, reg2, val1, val2) \
                       E2K_GET_AAUREGS(reg1, reg2, val1, val2)
#define E2K_GET_AAU_AAIND_TAG()		      E2K_GET_AAUREG(aaind_tag, 2)
#define E2K_GET_AAU_AAINCR(reg_mnemonic)      E2K_GET_AAUREG(reg_mnemonic, 2)
#define E2K_GET_AAU_AAINCRS(reg1, reg2, val1, val2) \
                       E2K_GET_AAUREGS(reg1, reg2, val1, val2)
#define E2K_GET_AAU_AAINCR_TAG()	      E2K_GET_AAUREG(aaincr_tag, 2)
#define E2K_GET_AAU_AASTI(reg_mnemonic)	      E2K_GET_AAUREG(reg_mnemonic, 2)
#define E2K_GET_AAU_AASTIS(reg1, reg2, val1, val2) \
                       E2K_GET_AAUREGS(reg1, reg2, val1, val2)
#define E2K_GET_AAU_AASTI_TAG()		      E2K_GET_AAUREG(aasti_tag, 2)
#define E2K_GET_AAU_AASR()		      E2K_GET_AAUREG(aasr, 2)
#define E2K_GET_AAU_AALDI(lval, rval, reg_mn) \
                       E2K_GET_AAUREGS(reg_mn, reg_mn, lval, rval)
#define E2K_GET_AAU_AALDA(lval, rval, reg_mn) \
                       E2K_GET_AAUREGS(reg_mn, reg_mn, lval, rval)
#define E2K_GET_AAU_AALDV(lo, hi) E2K_GET_AAUREGS(aaldv, aaldv, lo, hi)
#define E2K_GET_AAU_AALDM(lo, hi) E2K_GET_AAUREGS(aaldm, aaldm, lo, hi)

#define E2K_SET_AAU_AAD(reg_mn, mem_p)         E2K_SET_AAUQREG(reg_mn, mem_p)
#define E2K_SET_AAU_AADS                       E2K_SET_AAUQREGS
#define E2K_SET_AAU_AAIND(reg_mn, val)         E2K_SET_AAUREG(reg_mn, val, 2)
#define E2K_SET_AAU_AAINDS(reg1, reg2, val1, val2) \
                       E2K_SET_AAUREGS(reg1, reg2, val1, val2)
#define E2K_SET_AAU_AAIND_TAG(val)	       E2K_SET_AAUREG(aaind_tag, val, 2)
#define E2K_SET_AAU_AAINCR(reg_mn, val)        E2K_SET_AAUREG(reg_mn, val, 2)
#define E2K_SET_AAU_AAINCRS(reg1, reg2, val1, val2) \
                       E2K_SET_AAUREGS(reg1, reg2, val1, val2)
#define E2K_SET_AAU_AAINCR_TAG(val)           E2K_SET_AAUREG(aaincr_tag, val,2)
#define E2K_SET_AAU_AASTI(reg_mn, val)         E2K_SET_AAUREG(reg_mn, val, 2)
#define E2K_SET_AAU_AASTIS(reg1, reg2, val1, val2) \
                       E2K_SET_AAUREGS(reg1, reg2, val1, val2)
#define E2K_SET_AAU_AASTI_TAG(val)	       E2K_SET_AAUREG(aasti_tag, val, 2)
#define E2K_SET_AAU_AASR(val)		       E2K_SET_AAUREG(aasr, val, 2)
#define E2K_SET_AAU_AALDI(reg_mn, lval, rval) \
                       E2K_SET_AAUREGS(reg_mn, reg_mn, lval, rval)
#define E2K_SET_AAU_AALDA(reg_mn, lval, rval) \
                       E2K_SET_AAUREGS(reg_mn, reg_mn, lval, rval)
#define E2K_SET_AAU_AALDV(lo, hi) E2K_SET_AAUREGS(aaldv, aaldv, lo, hi)
#define E2K_SET_AAU_AALDM(lo, hi) E2K_SET_AAUREGS(aaldm, aaldm, lo, hi)

#define        SAVE_AAU_MASK_REGS(aau_context, aasr)		\
({								\
	if (unlikely(AAU_ACTIVE(aasr))) {			\
		/* As it turns out AAU can be in ACTIVE state	\
		 * in interrupt handler (bug 53227 comment 28	\
		 * and bug 53227 comment 36).			\
		 * The hardware stops AAU automatically but	\
		 * the value to be written should be corrected	\
		 * to "stopped" so that the "DONE" instruction	\
		 * works as expected. */			\
		AS(aasr).lds = AASR_STOPPED;			\
	}							\
	(aau_context)->aasr = aasr;				\
	if (unlikely(AAU_STOPPED(aasr))) {			\
		register u32    aaldm_lo, aaldm_hi,		\
				aaldv_lo, aaldv_hi;		\
		E2K_GET_AAU_AALDV(aaldv_lo, aaldv_hi);		\
		E2K_GET_AAU_AALDM(aaldm_lo, aaldm_hi);		\
		(aau_context)->aaldv.lo = aaldv_lo;		\
		(aau_context)->aaldv.hi = aaldv_hi;		\
		(aau_context)->aaldm.lo = aaldm_lo;		\
		(aau_context)->aaldm.hi = aaldm_hi;		\
	} else {						\
		AW((aau_context)->aaldv) = 0;			\
		AW((aau_context)->aaldm) = 0;			\
	}							\
})

#define	RESTORE_AAU_MASK_REGS(aau_context)			\
({								\
	register u32 aaldm_lo, aaldm_hi, aaldv_lo, aaldv_hi;	\
	register e2k_aasr_t aasr;				\
								\
	aaldm_lo = (aau_context)->aaldm.lo;			\
	aaldm_hi = (aau_context)->aaldm.hi;			\
	aaldv_lo = (aau_context)->aaldv.lo;			\
	aaldv_hi = (aau_context)->aaldv.hi;			\
	aasr = (aau_context)->aasr;				\
								\
	E2K_SET_AAUREG(aafstr, 0, 5);				\
	E2K_SET_AAU_AALDM(aaldm_lo, aaldm_hi);			\
	E2K_SET_AAU_AALDV(aaldv_lo, aaldv_hi);			\
	/* aasr can be in 'ACTIVE' state, so we set it last */	\
	E2K_SET_AAU_AASR(AW(aasr));				\
})

#define SAVE_AADS(aau_regs)					\
({								\
	register e2k_aadj_t *aads = (aau_regs)->aads;		\
	E2K_GET_AAU_AADS(&AW(aads[0]), aadr0, aadr1, aadr2, aadr3); \
	E2K_GET_AAU_AADS(&AW(aads[4]), aadr4, aadr5, aadr6, aadr7); \
	E2K_GET_AAU_AADS(&AW(aads[8]), aadr8, aadr9, aadr10, aadr11); \
	E2K_GET_AAU_AADS(&AW(aads[12]), aadr12, aadr13, aadr14, aadr15); \
	E2K_GET_AAU_AADS(&AW(aads[16]), aadr16, aadr17, aadr18, aadr19); \
	E2K_GET_AAU_AADS(&AW(aads[20]), aadr20, aadr21, aadr22, aadr23); \
	E2K_GET_AAU_AADS(&AW(aads[24]), aadr24, aadr25, aadr26, aadr27); \
	E2K_GET_AAU_AADS(&AW(aads[28]), aadr28, aadr29, aadr30, aadr31); \
})

#define RESTORE_AADS(aau_regs)                         \
({								\
	register e2k_aadj_t *aads = (aau_regs)->aads;		\
	E2K_SET_AAU_AADS(&AW(aads[0]), aadr0, aadr1, aadr2, aadr3); \
	E2K_SET_AAU_AADS(&AW(aads[4]), aadr4, aadr5, aadr6, aadr7); \
	E2K_SET_AAU_AADS(&AW(aads[8]), aadr8, aadr9, aadr10, aadr11); \
	E2K_SET_AAU_AADS(&AW(aads[12]), aadr12, aadr13, aadr14, aadr15); \
	E2K_SET_AAU_AADS(&AW(aads[16]), aadr16, aadr17, aadr18, aadr19); \
	E2K_SET_AAU_AADS(&AW(aads[20]), aadr20, aadr21, aadr22, aadr23); \
	E2K_SET_AAU_AADS(&AW(aads[24]), aadr24, aadr25, aadr26, aadr27); \
	E2K_SET_AAU_AADS(&AW(aads[28]), aadr28, aadr29, aadr30, aadr31); \
})


#define SAVE_AALDI(aaldis)					\
do {								\
	E2K_GET_AAU_AALDI((aaldis)[0],  (aaldis)[32], aaldi0);	\
	E2K_GET_AAU_AALDI((aaldis)[1],  (aaldis)[33], aaldi1);	\
	E2K_GET_AAU_AALDI((aaldis)[2],  (aaldis)[34], aaldi2);	\
	E2K_GET_AAU_AALDI((aaldis)[3],  (aaldis)[35], aaldi3);	\
	E2K_GET_AAU_AALDI((aaldis)[4],  (aaldis)[36], aaldi4);	\
	E2K_GET_AAU_AALDI((aaldis)[5],  (aaldis)[37], aaldi5);	\
	E2K_GET_AAU_AALDI((aaldis)[6],  (aaldis)[38], aaldi6);	\
	E2K_GET_AAU_AALDI((aaldis)[7],  (aaldis)[39], aaldi7);	\
	E2K_GET_AAU_AALDI((aaldis)[8],  (aaldis)[40], aaldi8);	\
	E2K_GET_AAU_AALDI((aaldis)[9],  (aaldis)[41], aaldi9);	\
	E2K_GET_AAU_AALDI((aaldis)[10], (aaldis)[42], aaldi10);	\
	E2K_GET_AAU_AALDI((aaldis)[11], (aaldis)[43], aaldi11);	\
	E2K_GET_AAU_AALDI((aaldis)[12], (aaldis)[44], aaldi12);	\
	E2K_GET_AAU_AALDI((aaldis)[13], (aaldis)[45], aaldi13);	\
	E2K_GET_AAU_AALDI((aaldis)[14], (aaldis)[46], aaldi14);	\
	E2K_GET_AAU_AALDI((aaldis)[15], (aaldis)[47], aaldi15);	\
	E2K_GET_AAU_AALDI((aaldis)[16], (aaldis)[48], aaldi16);	\
	E2K_GET_AAU_AALDI((aaldis)[17], (aaldis)[49], aaldi17);	\
	E2K_GET_AAU_AALDI((aaldis)[18], (aaldis)[50], aaldi18);	\
	E2K_GET_AAU_AALDI((aaldis)[19], (aaldis)[51], aaldi19);	\
	E2K_GET_AAU_AALDI((aaldis)[20], (aaldis)[52], aaldi20);	\
	E2K_GET_AAU_AALDI((aaldis)[21], (aaldis)[53], aaldi21);	\
	E2K_GET_AAU_AALDI((aaldis)[22], (aaldis)[54], aaldi22);	\
	E2K_GET_AAU_AALDI((aaldis)[23], (aaldis)[55], aaldi23);	\
	E2K_GET_AAU_AALDI((aaldis)[24], (aaldis)[56], aaldi24);	\
	E2K_GET_AAU_AALDI((aaldis)[25], (aaldis)[57], aaldi25);	\
	E2K_GET_AAU_AALDI((aaldis)[26], (aaldis)[58], aaldi26);	\
	E2K_GET_AAU_AALDI((aaldis)[27], (aaldis)[59], aaldi27);	\
	E2K_GET_AAU_AALDI((aaldis)[28], (aaldis)[60], aaldi28);	\
	E2K_GET_AAU_AALDI((aaldis)[29], (aaldis)[61], aaldi29);	\
	E2K_GET_AAU_AALDI((aaldis)[30], (aaldis)[62], aaldi30);	\
	E2K_GET_AAU_AALDI((aaldis)[31], (aaldis)[63], aaldi31);	\
} while (0)

#define SAVE_AALDA(aaldas)					\
do {								\
	register u32	aalda0, aalda4, aalda8, aalda12,	\
			aalda16, aalda20, aalda24, aalda28,	\
			aalda32, aalda36, aalda40, aalda44,	\
			aalda48, aalda52, aalda56, aalda60;	\
								\
	E2K_GET_AAU_AALDA(aalda0, aalda32, aalda0);		\
	E2K_GET_AAU_AALDA(aalda4, aalda36, aalda4);		\
	E2K_GET_AAU_AALDA(aalda8, aalda40, aalda8);		\
	E2K_GET_AAU_AALDA(aalda12, aalda44, aalda12);		\
	E2K_GET_AAU_AALDA(aalda16, aalda48, aalda16);		\
	E2K_GET_AAU_AALDA(aalda20, aalda52, aalda20);		\
	E2K_GET_AAU_AALDA(aalda24, aalda56, aalda24);		\
	E2K_GET_AAU_AALDA(aalda28, aalda60, aalda28);		\
	*(u32 *) (&(aaldas)[0]) = aalda0;			\
	*(u32 *) (&(aaldas)[4]) = aalda4;			\
	*(u32 *) (&(aaldas)[8]) = aalda8;			\
	*(u32 *) (&(aaldas)[12]) = aalda12;			\
	*(u32 *) (&(aaldas)[16]) = aalda16;			\
	*(u32 *) (&(aaldas)[20]) = aalda20;			\
	*(u32 *) (&(aaldas)[24]) = aalda24;			\
	*(u32 *) (&(aaldas)[28]) = aalda28;			\
	*(u32 *) (&(aaldas)[32]) = aalda32;			\
	*(u32 *) (&(aaldas)[36]) = aalda36;			\
	*(u32 *) (&(aaldas)[40]) = aalda40;			\
	*(u32 *) (&(aaldas)[44]) = aalda44;			\
	*(u32 *) (&(aaldas)[48]) = aalda48;			\
	*(u32 *) (&(aaldas)[52]) = aalda52;			\
	*(u32 *) (&(aaldas)[56]) = aalda56;			\
	*(u32 *) (&(aaldas)[60]) = aalda60;			\
} while (0)

#define SAVE_AAFSTR(reg) \
do { \
	(reg) = E2K_GET_AAUREG(aafstr, 5); \
} while (0)

#ifdef CONFIG_USE_AAU
# define SAVE_AAU_REGS_FOR_PTRACE(pt_regs) \
do { \
	e2k_aau_t *__aau_context = (pt_regs)->aau_context; \
	if (__aau_context) { \
		SAVE_AALDI((__aau_context)->aaldi); \
		SAVE_AALDA((__aau_context)->aalda); \
		SAVE_AAFSTR((__aau_context)->aafstr); \
	} \
} while (0)
#else
# define SAVE_AAU_REGS_FOR_PTRACE(pt_regs)
#endif
	
/* Check up AAU state */
#define AAU_NULL(aasr)		(AS(aasr).lds == AASR_NULL)
#define AAU_READY(aasr)		(AS(aasr).lds == AASR_READY)
#define AAU_ACTIVE(aasr)	(AS(aasr).lds == AASR_ACTIVE)
#define AAU_STOPPED(aasr)	(AS(aasr).lds == AASR_STOPPED)

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
typedef struct e2k_aadj_lo_fields {
	u64 base	: E2K_VA_SIZE;		/* [E2K_VA_MSB:0] */
	u64 unused1	: 53 - E2K_VA_MSB;	/* [53:48] */
	u64 tag		: 3;			/* [56:54] */
	u64 mb		: 1;			/* [57] */
	u64 ed		: 1;			/* [58] */
	u64 rw		: 2;			/* [60:59] */
	u64 unused2	: 3;			/* [63:60] */
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

typedef struct e2k_aau_context {
	e2k_aasr_t		aasr;
	u32			aafstr;
	e2k_aaldm_t		aaldm;
	e2k_aaldv_t		aaldv;

	/* Synchronous part */
	u32			aastis[16];
	u32			aasti_tags;

	/* Asynchronous part */
	u32			aainds[16];
	u32			aaind_tags;
	u32			aaincrs[8];
	u32			aaincr_tags;
	e2k_aadj_t		aads[32];
	u32			aaldi[64];
	e2k_aalda_t		aalda[64];
} e2k_aau_t;

#endif /* _E2K_AAU_H_ */
