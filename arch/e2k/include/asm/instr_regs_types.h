/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#ifndef __INSTR_REGS_TYPES_H__
#define __INSTR_REGS_TYPES_H__

#include <linux/types.h>
#include <asm/base_regs_types.h>

/*
 * Instruction structure
 */

typedef u64 instr_item_t;	/* min. item of instruction */
				/* is double-word */

typedef u16 instr_semisyl_t;	/* instruction semi-syllable */
				/* is short */

typedef u32 instr_syl_t;	/* instruction syllable */
				/* is word */

#define	E2K_INSTR_MAX_SYLLABLES_NUM	8	/* max length of instruction */
						/* in terms of min item of */
						/* instruction */
#define	E2K_INSTR_MAX_SIZE		(E2K_INSTR_MAX_SYLLABLES_NUM * \
						sizeof(instr_item_t))
/* Asynchronous program instruction 'fapb' is always 16 bytes long */
#define E2K_ASYNC_INSTR_SIZE		16
/* Asynchronous program can contain maximum 32 instructions */
#define MAX_ASYNC_PROGRAM_INSTRUCTIONS	32

/*
 * Order of fixed syllables of instruction
 */
#define	E2K_INSTR_HS_NO		0	/* header syllable */
#define E2K_INSTR_SS_NO		1	/* stubs syllable (if present) */

#define	E2K_GET_INSTR_SEMISYL(instr_addr, semisyl_no)			\
		(((u16 *)(instr_addr))					\
			[((semisyl_no) & 0x1) ? ((semisyl_no) - 1) :	\
						((semisyl_no) + 1)])
#define	E2K_GET_INSTR_SYL(instr_addr, syl_no)				\
		(((u32 *)(instr_addr))[syl_no])

#define	E2K_GET_INSTR_HS(instr_addr)	E2K_GET_INSTR_SYL(instr_addr,	\
							E2K_INSTR_HS_NO)
#define	E2K_GET_INSTR_SS(instr_addr)	E2K_GET_INSTR_SYL(instr_addr,	\
							E2K_INSTR_SS_NO)
#define E2K_GET_INSTR_ALS0(instr_addr, ss_flag)				\
		E2K_GET_INSTR_SYL(instr_addr,				\
					(ss_flag) ? E2K_INSTR_SS_NO + 1 \
							:		\
							E2K_INSTR_SS_NO)
#define E2K_GET_INSTR_ALES0(instr_addr, mdl)				\
		E2K_GET_INSTR_SEMISYL(instr_addr, ((mdl) + 1) * 2)

/*
 * Header syllable structure
 */

typedef union instr_hs {
	struct {
		u32 mdl		: 4;	/* [ 3: 0] middle pointer in terms of */
					/*         syllables - 1 */
		u32 lng		: 3;	/* [ 6: 4] length of instruction in */
					/*         terms of double-words - 1 */
		u32 nop		: 3;	/* [ 9: 7] no operation code */
		u32 lm		: 1;	/*    [10] loop mode flag */
		u32 x		: 1;	/*    [11] unused field */
		u32 s		: 1;	/*    [12] Stubs syllable presence bit */
		u32 sw		: 1;	/*    [13] bit used by software */
		u32 c		: 2;	/* [15:14] Control syllables presence */
					/*         mask */
		u32 cd		: 2;	/* [17:16] Conditional execution */
					/*         syllables number */
		u32 pl		: 2;	/* [19:18] Predicate logic channel */
					/*         syllables number */
		u32 ale		: 6;	/* [25:20] Arithmetic-logic channel */
					/*         syllable extensions */
					/*         presence mask */
		u32 al		: 6;	/* [31:26] Arithmetic-logic channel */
					/*         syllables presence mask */
	};
	struct {
		u32		: 14;
		u32 c0		: 1;	/* CS0 */
		u32 c1		: 1;	/* CS1 */
		u32		: 4;
		u32 ale0	: 1;
		u32 ale1	: 1;
		u32 ale2	: 1;
		u32 ale3	: 1;
		u32 ale4	: 1;
		u32 ale5	: 1;
		u32 al0		: 1;
		u32 al1		: 1;
		u32 al2		: 1;
		u32 al3		: 1;
		u32 al4		: 1;
		u32 al5		: 1;
	};
	e2k_reg_t;		/* as entire syllable   */
} instr_hs_t;

#define E2K_INSTR_HS_LNG_MASK	0x70

#define	E2K_GET_INSTR_SIZE(hs)	(((hs).lng + 1) * sizeof(instr_item_t))

/*
 * Stubs syllable structure
 */

typedef union instr_ss {
	struct {
		u32 ctcond	: 9;	/* [ 8: 0] control transfer condition */
		u32 x		: 1;	/* [    9] unused field */
		u32 ctop	: 2;	/* [11:10] control transfer opcode */
		u32 aa		: 4;	/* [15:12] mask of AAS */
		u32 alc		: 2;	/* [17:16] advance loop counters */
		u32 abp		: 2;	/* [19:18] advance predicate base */
		u32 xx		: 1;	/*    [20] unused field */
		u32 abn		: 2;	/* [22:21] advance numeric base */
		u32 abg		: 2;	/* [24:23] advance global base */
		u32 xxx		: 1;	/*    [25] unused field */
		u32 vfdi	: 1;	/*    [26] verify deferred interrupt */
		u32 srp		: 1;	/*    [27] store recovery point */
		u32 bap		: 1;	/*    [28] begin array prefetch */
		u32 eap		: 1;	/*    [29] end array prefetch */
		u32 ipd		: 2;	/* [31:30] instruction prefetch depth */
	};
	struct {
		u32 psrc : 5;	/* control transfer condition predicate */
		u32 ct   : 4;	/* control transfer condition type */
		u32      : 23;
	};
	e2k_reg_t;		/* as entire syllable   */
} instr_ss_t;

/*
 * src1/src2/src3
 */
typedef union {
	struct {
		u8		: 5;
		u8 rt5		: 1;
		u8 rt6		: 1;
		u8 rt7		: 1;
	};
	u8 word;
} instr_src_t;

static inline bool instr_src2_is_lts16(instr_src_t src2)
{
	return (src2.word & 0xf8) == 0xd0;
}

static inline bool instr_src2_is_lts32(instr_src_t src2)
{
	return (src2.word & 0xfc) == 0xd8;
}

static inline bool instr_src2_is_lts64(instr_src_t src2)
{
	return (src2.word & 0xfc) == 0xdc;
}

static inline bool instr_src2_is_greg(instr_src_t src2)
{
	return (src2.word & 0xe0) == 0xe0;
}

static inline bool instr_src2_is_rf_reg(instr_src_t src2)
{
	return !src2.rt7 || src2.rt7 && !src2.rt6;
}

#define INSTR_SRC_DST_GREG_NUM_MASK	0x1f
#define INSTR_SRC_DST_NREG_VALUE	0x80
#define INSTR_SRC_DST_NREG_MASK		0xc0
#define INSTR_SRC_DST_NREG_NUM_MASK	0x3f
#define INSTR_SRC2_LTS_NUM_MASK		0x03
#define INSTR_SRC2_LTS_SHIFT_MASK	0x04

/*
 * ALU syllables structure
 */

typedef union {
	union {
		union {
			struct {
				u8 dst;			/* [ 7: 0] destination */
				instr_src_t src2;	/* [15: 8] source register #2 */
				u8 opce;		/* [23:16] opcode extension */
				u8 cop	: 7;		/* [30:24] code of operation */
				u8 spec	: 1;		/*    [31] speculative mode */
			};
			struct {
				u32		: 24;
				u32 opc		: 8;
			};
		} alf2;
		union {
			struct {
				instr_src_t src3;	/* [ 7: 0] source #3 */
				instr_src_t src2;	/* [15: 8] source #2 */
				instr_src_t src1;	/* [23:16] source #1 */
				u8 cop	: 7;		/* [30:24] code of operation */
				u8 spec	: 1;		/*    [31] speculative mode */
			};
			struct {
				u32		: 24;
				u32 opc		: 8;
			};
		} alf3; /* type with highest srcs amount. For SoftPM covers all other types */
	};
	e2k_reg_t;		/* as entire syllable   */
} instr_als_t;

typedef union instr_ales {
	struct {
		instr_src_t src3;
		u8 opc2;
	} alef1;
	struct {
		u16 opce	: 8;
		u16 opc2	: 8;
	} alef2;
	u16 word;		/* as entire syllable   */
} instr_ales_t;

/*
 * ALU syllable code of operations and opcode extentions
 */
#define	DRTOAP_ALS_COP		0x62	/* DRTOAP */
#define	GETSP_ALS_COP		0x58	/* GETSP */
#define	GETSPD_ALS_COP		0x59	/* GETSPd */
#define	EXT_ALES_OPC2		0x01	/* EXTension  */
#define	USD_ALS_OPCE		0xec	/* USD  */

/*
 * CS0 syllable structure
 */

typedef union {
	struct {
		u32 prefr	: 3;
		u32 ipd		: 1;
		u32 pdisp	: 24;
		u32		: 4;
	} pref;
	struct {
		u32 param	: 28;
		u32 ctp_opc	: 2;
		u32 ctpr	: 2;
	} cof1;
	struct {
		u32 disp	: 28;
		u32 ctp_opc	: 2;
		u32 ctpr	: 2;
	} cof2;
	struct {
		u32		: 28;
		u32 opc		: 4;
	};
	struct {
		u32		: 28;
		u32 ctp_opc	: 2;
		u32 ctpr	: 2;
	};
	e2k_reg_t;
} instr_cs0_t;

#define CS0_CTP_OPC_IBRANCH	0
#define CS0_CTP_OPC_DISP	0
#define CS0_CTP_OPC_LDISP	1
#define CS0_CTP_OPC_PREF	1
#define CS0_CTP_OPC_PUTTSD	2
#define CS0_CTP_OPC_RETURN	3

/*
 * CS1 syllable structure
 */

typedef union {
	struct {
		u32		: 27;
		u32 sft		: 1;
		u32		: 4;
	};
	struct {
		u32 param	: 28;
		u32 opc		: 4;
	};
	struct {
		u32 rbs		: 6;
		u32 rsz		: 6;
		u32 rcur	: 6;
		u32 psz		: 5;
		u32		: 3;
		u32 setbn	: 1;
		u32 serbp	: 1;
		u32		: 4;
	};
	struct {
		u32 mas5	: 6;
		u32 mas3	: 6;
		u32 mas2	: 6;
		u32 mas0	: 6;
		u32		: 4;
	};
	struct {
		u32 wbs		: 7;
		u32		: 25;
	};
	e2k_reg_t;
} instr_cs1_t;

/* Use this to ensure created syllable is a compile-time constant */
#define instr_cs1_c1f1(param, opc) ((param) | ((opc) << 28))

#define CS1_OPC_SETR0	0
#define CS1_OPC_SETR1	1
#define CS1_OPC_SETEI	2
#define CS1_OPC_WAIT	3
#define CS1_OPC_SETBR	4
#define CS1_OPC_CALL	5
#define CS1_OPC_MAS	6

/*
 * Literal syllable structure
 */

typedef union {
	struct {
		u32		: 3;
		u32 dbl		: 1;
		u32 nfx		: 1;
		u32 wsz		: 7;
		u32 rpsz	: 5;
		u32		: 15;
	} lts0;
	instr_syl_t word;		/* as entire syllable */
} instr_lts_t;

/*
 * Predicate logic channel syllables structure
 */

typedef union {
	struct {
		u16 pdst	: 5;
		u16 vdst	: 1;
		u16 p1		: 3;
		u16 neg1	: 1;
		u16 p0		: 3;
		u16 neg0	: 1;
		u16 opc		: 2;
	};
	instr_semisyl_t word;		/* as entire semisyllable */
} instr_clp_t;

typedef union {
	struct {
		instr_clp_t clp0;
		u16 elp1	: 7;
		u16		: 1;
		u16 elp0	: 7;
		u16		: 1;
	} pls0;
	struct {
		instr_clp_t clp1;
		u16 elp3	: 7;
		u16		: 1;
		u16 elp2	: 7;
		u16		: 1;
	} pls1;
	struct {
		instr_clp_t clp2;
	} pls2;
	instr_syl_t word;		/* as entire syllable */
} instr_pls_t;

#define PLS_ELP_PSRC_MASK	0x60

#define PLS_CLP_OPC_CLPAND	0
#define PLS_CLP_OPC_CLPLAND	1




/*
 * Conditional execution syllables structure
 */

typedef union {
	struct {
		u16 pred	: 7;
		u16 neg		: 3;
		u16 mask	: 4;
		u16 opc		: 2;
	};
	instr_semisyl_t word;		/* as entire semisyllable */
} instr_rlp_t;

typedef union {
	struct {
		instr_rlp_t rlp_lo;
		instr_rlp_t rlp_hi;
	};
	instr_syl_t word;		/* as entire syllable */
} instr_cds_t;

#define CDS_OPC_RLP0	0
#define CDS_OPC_RLP1	1
#define CDS_MASK_ALS0	1
#define CDS_MASK_ALS1	2
#define CDS_MASK_ALS2	4
#define CDS_MASK_ALS3	1
#define CDS_MASK_ALS4	2
#define CDS_MASK_ALS5	4
#define CDS_NEG_ALS0	1
#define CDS_NEG_ALS1	2
#define CDS_NEG_ALS2	4
#define CDS_NEG_ALS3	1
#define CDS_NEG_ALS4	2
#define CDS_NEG_ALS5	4

#define CDS_PRED_PCNT_MASK	0x40
#define CDS_PRED_PSRC_MASK	0x60

#endif
