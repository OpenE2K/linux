/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

#include <asm/base_regs_types.h>
#include <asm/types.h>

#define	E2K_ALIGN_CODES			12	/* Codes area boundaries  alignment */
#define E2K_ALIGN_CODES_MASK		((1 << E2K_ALIGN_CODES) - 1)
#define	E2K_ALIGN_OSCU			E2K_ALIGN_CODES
#define	E2K_ALIGN_OSCU_MASK		E2K_ALIGN_CODES_MASK

#define	E2K_ALIGN_GLOBALS		12	/* Globals area boundaries  alignment  */
#define E2K_ALIGN_GLOBALS_SZ		_BITUL(E2K_ALIGN_GLOBALS)
#define	E2K_ALIGN_GLOBALS_MASK		(_BITUL(E2K_ALIGN_GLOBALS) - 1)
#define	E2K_ALIGN_OS_GLOBALS		E2K_ALIGN_GLOBALS
#define	E2K_ALIGN_OS_GLOBALS_MASK	E2K_ALIGN_GLOBALS_MASK

#define	E2K_ALIGN_ALL_STACKS_BASE	37	/* All User stacks area  boundaries alignment */
#define	E2K_ALL_STACKS_MAX_SIZE		(1UL << E2K_ALIGN_ALL_STACKS_BASE)

#define	E2K_ALIGN_PSTACK		12	/* Procedure stack boundaries alignment */
#define	E2K_ALIGN_PSTACK_TOP		5	/* Procedure stack top  boundaries alignment */
#define ALIGN_PSTACK_SIZE		(1 << E2K_ALIGN_PSTACK)
#define ALIGN_PSTACK_TOP_SIZE		(1 << E2K_ALIGN_PSTACK_TOP)
#define	E2K_ALIGN_PSTACK_MASK		(ALIGN_PSTACK_SIZE - 1)
#define	E2K_ALIGN_PSTACK_TOP_MASK	(ALIGN_PSTACK_TOP_SIZE - 1)

#define	E2K_ALIGN_PCSTACK		12	/* Procedure chain stack boundaries alignment */
#define	E2K_ALIGN_PCSTACK_TOP		5	/* Procedure chain stack top  boundaries alignment */
#define ALIGN_PCSTACK_SIZE		(1 << E2K_ALIGN_PCSTACK)
#define ALIGN_PCSTACK_TOP_SIZE		(1 << E2K_ALIGN_PCSTACK_TOP)
#define	E2K_ALIGN_PCSTACK_MASK		(ALIGN_PCSTACK_SIZE - 1)

#define	E2K_ALIGN_STACKS_BASE		12	/* User stacks base (in terms v7)  alignment */
#define E2K_PROTECTED_STACK_BASE_BITS	32	/* Protected mode stack  does not cross 4 Gb  */
#define	E2K_ALIGN_STACK_BASE_REG	(1UL << E2K_ALIGN_STACKS_BASE)
#define	E2K_ALIGN_STACKS_BASE_MASK	((1UL << E2K_ALIGN_STACKS_BASE) - 1)
#define	E2K_PROTECTED_STACK_BASE_MASK	((1UL << E2K_PROTECTED_STACK_BASE_BITS) - 1)
#define MAX_USD_HI_SIZE			(4ULL * 1024 * 1024 * 1024 - 1ULL)

/* Since iset v7 user stack alignment increaed from 4/5 to 8 bits.
 * User might want to launch old kernels as guest on v7 hypervisor
 * so we must use the same alignment for older kernels too. */
#define E2K_ALIGN_USTACK_SIZE	_BITUL(4)
#define E2K_ALIGN_PUSTACK_SIZE	_BITUL(5)
#define E2K_ALIGN_USTACK_BOUNDS	_BITUL(8)

/*
 * This should be max(E2K_ALIGN_USTACK_SIZE, E2K_ALIGN_PUSTACK_SIZE)
 * but we want it to be constant
 */
#define E2K_ALIGN_STACK		32UL

/*
 * ==========   numeric registers (register file)  ===========
 */

#define	E2K_MAXCR		64		/* The total number of  chain registers */
#define	E2K_MAXCR_q		E2K_MAXCR	/* The total number of  chain quad-registers */
#define	E2K_ALIGN_CHAIN_WINDOW	5		/* Chain registers Window boundaries alignment */
#define	E2K_CWD_MSB		9			/* Most significant bit of CWD_base */
#define	E2K_CWD_SIZE		(E2K_CWD_MSB + 1)	/* The number of bits in  CWD_base field */
#define	E2K_PCSHTP_MSB		(E2K_CWD_MSB + 1)	/* Most significant bit  of PCSHTP */
#define	E2K_PCSHTP_SIZE		(E2K_PCSHTP_MSB + 1)	/* The number of bits in  PCSHTP */
#define E2K_USFS_MSB		47
#define E2K_USINCR_SIZE		(E2K_USFS_MSB + 2)	/* plus sign */

/* Maximum size to be filled by hardware */
#define E2K_CF_MAX_FILL_FILLC_q (E2K_MAXCR_q - 6)



/*
 * Compilation Unit Descriptor (CUD)
 * describes the memory containing codes of the current compilation unit
 */
typedef union {
	struct {
		struct {   /* <= v6 */
			u64 Base	: E2K_VA_SIZE;	/* [47: 0] */
			u64		: 56 - E2K_VA_MSB;
			u64 P		: 1;
			u64 C		: 1;
		};
		union {
			struct {   /* <= v6 */
				u64		: 32;
				u64 Size	: 32;
			};
			struct {   /* >= v7 */
				u64		: 58;
				u64 C_v7	: 1;
				u64 Flag	: 3;	/* va32 : [59]
							 * r	: [60]
							 * prot : [61]
							 */
			};
		};
	};
	e2k_qreg_t;
	e2k_qreg_t word;
} e2k_cud_t;

enum cud_flag {   /* >= v7 */
	cud_m32  = 0x3,		/* r + va32 */
	cud_m64  = 0x2,		/* r only   */
	cud_m128 = 0x6		/* r + prot */
};





/*
 * Compilation Unit Globals Descriptor (GD)
 * describes the global variables memory of the current compilation unit
 */

typedef union {
	struct {  /* <= v6 */
		struct {
			u64 Base	: E2K_VA_SIZE;	/* [47: 0] */
		};
		struct {
			u64		: 32;
			u64 Size	: 32;
		};
	};
	e2k_qreg_t;
	e2k_qreg_t word;
} e2k_gd_t;




/* CUT entry */
/* Structure of entire CUT entry */
typedef struct {
	e2k_cud_t cud;
	e2k_gd_t gd;
} e2k_cute_t;




/*
 * Procedure Stack Pointer (PSP)
 * describes the full procedure stack memory as well as the current pointer
 * to the top of a procedure stack memory part.
 */

typedef union {
	struct {  /* <= v6 */
		struct {
			u64 Base	: E2K_VA_SIZE;	/* [47: 0] */
		};
		struct {
			u64 Ind		: 32;
			u64 Size	: 32;
		};
	};
	e2k_qreg_t;
	e2k_qreg_t word;
} e2k_psp_t;

typedef e2k_psp_t psp_struct_t;





/* Structure of dword register PSHTP */

/*
 * PSHTP register contains index in terms of double-numeric registers
 * PSP register contains index in terms of extended double-numeric
 * registers spilled into memory - each double-numeric register occupy
 * two double words: one for main part and second for extension.
 * So it need some conversion to operate with PSP_ind and PSHTP_ind in
 * common terms.
 */

typedef union {
	struct {
		s64 ind		: 12;
		u64		: 4;
		u64 fxind	: 11; /* [27:16] */
		u64		: 5;
		u64 tind	: 11; /* [43:32] */
		u64		: 5;
		u64 fx		: 1; /* [48] */
		u64		: 15;
	};
	e2k_dreg_t;		/* as entire register */
} e2k_pshtp_t;

#define	PSHTP_MEM_INDEX(pshtp) (2 * (pshtp).ind)
#define	PSP_IND_TO_PSHTP(mem_ind)	((mem_ind) / 2)
#define	GET_PSHTP_Q_INDEX(pshtp)   ((pshtp).ind / 4)




/*
 * Procedure Chain Stack Pointer (PCSP)
 * describes the full procedure chain stack memory as well as the current
 * pointer to the top of a procedure chain stack memory part.
 */

typedef union {
	struct {  /* <= v6 */
		struct {
			u64 Base	: E2K_VA_SIZE;	/* [47: 0] */
		};
		struct {
			u64 Ind		: 32;
			u64 Size	: 32;
		};
	};
	e2k_qreg_t;
	e2k_qreg_t word;
} e2k_pcsp_t;




/*
 * Structure of procedure chain stack hardare top register PCSHTP
 * Register is signed value, so read from register get signed value
 * and write to put signed value.
 */

typedef union {
	struct {
		s32 ind		: E2K_PCSHTP_SIZE;
	};
	e2k_reg_t;
} e2k_pcshtp_t;





/*
 * User Stack Base Register (USBR/SBR)
 * USBR - contains the base virtual address of the current User Stack area.
 * SBR  - contains the base virtual address of an area dedicated for all user
 * stacks of the current task
 */

typedef union {
	struct {
		u64 base	: E2K_VA_SIZE;
	};
	e2k_dreg_t;
} e2k_usbr_t;

typedef e2k_usbr_t e2k_sbr_t;


/*
 * User Stack Descriptor (USD)
 * contains free memory space dedicated for user stack data and
 * is supposed to grow from higher memory addresses to lower ones
 */
typedef union {
	struct {   /* <= v6 */
		union {
			struct {
				u64 Ptr		: E2K_VA_SIZE;
			};
			struct {	/* protected mode */
				u64 P_ptr	: 32;	/* [31 :  0] */
				u64 Psl		: 16;	/* [47 : 32] */
				u64		: 10;	/* [57 : 48] */
				u64 P		: 1;	/* [58] */
			};
		};
		union {
			struct { /* <= v6 */
				u64			:32;
				u64 Ind			:32;
			};
			union {	/* >= v7 */
				struct { /* High word of v7 AP interesting fields */
					u64		: 60;		/* [59: 0] */
					u64 r_v7	: 1;		/* [60] */
					u64 w_v7	: 1;		/* [61] */
					u64 itag_v7	: 2;		/* [63:62] */
				};
				struct {
					u64		: 60;		/* [59: 0] */
					u64 r		: 1;		/* [60] */
					u64 w		: 1;		/* [61] */
					u64		: 2;		/* [63:62] */
				} perm;
			};
		};
	};
	e2k_qreg_t;
	e2k_qreg_t word;
} e2k_usd_t;


/* USINCR - Register holds getsp arg when user_stack_bounds interrupt */ 

typedef union {
	struct {
		s64 incr	: E2K_USINCR_SIZE;
	};
	e2k_dreg_t;
} e2k_usincr_t;



/* Current chain registers window descriptor (CWD) */

typedef union {
	struct {
		u32 base	: E2K_CWD_SIZE;
	};
	e2k_reg_t;
} e2k_cwd_t;



	/*
	 * Structure of LSR -Loop status register
	 */

typedef union {
	struct {
		u64 lcnt	: 32;	/* [31: 0] (loop counter) */
		u64 ecnt	: 5;	/* [36:32] (epilogue counter) */
		u64 vlc		: 1;	/* [37] (loop counter valid bit) */
		u64 over	: 1;	/* [38] */
		u64 ldmc	: 1;	/* [39] (loads manual control) */
		u64 ldovl	: 8;	/* [47:40] (load overlap) */
		u64 pcnt	: 5;	/* [52:48] (prologue counter) */
		u64 strmd	: 7;	/* [59:53] (store remainder counter) */
		u64 semc	: 1;	/* [60] (side effects manual control */
		u64 unused	: 3;	/* [63:61] */
	};
	e2k_dreg_t;		/* as entire register */
} e2k_lsr_t;

/*   see C.19.1. */
#define ls_prlg(x)              ((x).pcnt != 0)
#define ls_lst_itr(x)           ((x).vlc && ((x).lcnt < 2))
#define ls_loop_end(x)          (ls_lst_itr(x) && ((x).ecnt == 0))

#define E2K_LSR_VLC (1UL << 37)

	/*
	 * Structure of ILCR - Initial loop counters register
	 */

typedef union {			/* quad-word register */
	struct {
		u64 lcnt	: 32;	/* [31: 0] (loop counter) */
		u64 ecnt	: 5;	/* [36:32] (epilogue counter) */
		u64		: 11;	/* [47:37] unused */
		u64 pcnt	: 5;	/* [52:48] (prologue counter) */
		u64		: 11;	/* [63:53] unused */
	};
	e2k_dreg_t;		/* as entire register */
} e2k_ilcr_t;






/* see C.17.1.2. */

typedef union e2k_ct_struct_t {
	struct {
		u64 psrc	: 5;	/* [4:0] (pointer to condition) */
		u64 ct		: 4;	/* [8:5] (condition type) */
	};
	e2k_dreg_t;		/* as entire register */
} e2k_ct_t;






/*
 * ==========   numeric registers (register file)  ===========
 */

#define	E2K_MAXNR	128			/* The total number of  quad-NRs */
#define	E2K_MAXGR	16			/* The total number of global  quad-NRs */
#define	E2K_MAXSR	(E2K_MAXNR - E2K_MAXGR)	/* The total number of stack  quad-NRs */
#define	E2K_MAXNR_d	(E2K_MAXNR * 2)		/* The total number of  double-NRs */
#define	E2K_MAXGR_d	(E2K_MAXGR * 2)		/* The total number of global  double-NRs */
#define	E2K_MAXSR_d	(E2K_MAXSR * 2)		/* The total number of stack  double-NRs */
#define	E2K_NR_SIZE	16			/* Byte size of quad-NR */

/* Size of local stack registers file */
#define	MAX_SRF_SIZE	(E2K_MAXSR * E2K_NR_SIZE)





/* Current window descriptor (WD) */
typedef union e2k_wd {
	struct {
		u64		: 4;
		u64 base_q	: 7;
		u64		: 9;
		u64 size_q	: 7;
		u64		: 9;
		u64 psize_q	: 7;
		u64		: 21;
	};
	struct {
		u64		: 3;
		u64 base_d	: 8;
		u64		: 8;
		u64 size_d	: 8;
		u64		: 8;
		u64 psize_d	: 8;
		u64		: 21;
	};
	struct {
		u64 base	: 11;	/* [10: 0] window base: */
					/* %r0 physical address */
		u64		: 5;	/* [15:11] */
		u64 size	: 11;	/* [26:16] window size */
		u64		: 5;	/* [31:27] */
		u64 psize	: 11;	/* [42:32] parameters area */
		/* size */
		u64		: 5;	/* [47:43] */
		u64 fx		: 1;	/* [48]    spill/fill */
					/* extended flag; indicates */
					/* that the current procedure */
					/* has variables of FX type */
		u64 dbl		: 1;	/* [49]  */
		u64		: 14;	/* [63:50] unused field */
	};
	e2k_dreg_t;		/* as entire opcode     */
} e2k_wd_t;

/* The effective address of NR in a window (in terms of double-NR) */
#define	NR_REA_d(WD, rnum_d)	(((WD).base / 8 + rnum_d) % E2K_MAXSR_d)

/* Function parameters area size by C calling convention in quadro registers
 * (different for 128-bit mode to accomodate more descriptors) */
#define C_ABI_PSIZE_UNPROT	4
#define C_ABI_PSIZE_PROT	8
#define C_ABI_PSIZE(protected) 	((protected) ? C_ABI_PSIZE_PROT : C_ABI_PSIZE_UNPROT)






/* Numeric results */
/* Result destination (destination(ALS.dst)) is encoded in dst fields */
/* of ALS or AAS syllables as follows: */

typedef union e2k_dst {
	struct { /* as rotatable register */
		u8 index	: 7;	/* [6: 0] NR index in rotatable area */
		u8 rt7		: 1;	/* [ 7]    should be 0 */
	} nbr;
	struct { /* as window register */
		u8 index	: 6;	/* [ 5: 0] NR index in a window */
		u8 rt6		: 1;	/* [ 6]    should be 0 */
		u8 rt7		: 1;	/* [ 7]    should be 1 */
	} nr;
	u8 word;		/* as entire opcode     */
} e2k_dst_t;

#define	DST_IS_NBR(dst)		(dst.nbr.rt7 == 0)
#define	DST_IS_NR(dst)		(dst.nr.rt7 == 1 && dst.nr.rt6 == 0)
#define	DST_NBR_INDEX(dst)	(dst.nbr.index)
#define	DST_NR_INDEX(dst)	(dst.nr.index)
#define	DST_NBR_RNUM_d(dst)	DST_NBR_INDEX(dst)
#define	DST_NR_RNUM_d(dst)	DST_NR_INDEX(dst)

/* The effective address of NR in a rotatable area (in terms of double-NR) */
#define	NBR_IND_d(BR, rnum_d)	(BR.rbs * 2 + (BR.rcur * 2 + rnum_d) % (BR.rsz * 2 + 2))

/* BR */
typedef struct {		/* Structure of br reg */
	u32 rbs		: 6;		/* [ 5: 0]      */
	u32 rsz		: 6;		/* [11: 6]      */
	u32 rcur	: 6;		/* [17:12]      */
	u32 psz		: 5;		/* [22:18]      */
	u32 pcur	: 5;		/* [27:23]      */
	u32		: 4;
} e2k_br_fields_t;

typedef union {
	e2k_br_fields_t;
	e2k_reg_t;		/* as entire register   */
} e2k_br_t;

#define E2K_INITIAL_BGR_VAL     0xff

static inline int br_rsz_full_d(e2k_br_t br)
{
	return 2 * (br.rsz + 1);
}

/* see 5.25.1. */
typedef union {
	struct {
		struct {
			u64 ip		: E2K_VA_SIZE;
			u64		: 57 - E2K_VA_MSB;
			u64 stp		: 1;	/* [ 58 ] */
		};
		union {
			struct {
				e2k_br_fields_t br;	/* [27 : 0 ] */
				e2k_br_fields_t tbr;	/* [59 : 32] */
			};
			struct {
				u64		: 63;
				u64 tsrp	: 1;	/* [63] */
			};
		};
	};
	e2k_qreg_t;
} e2k_rpr_t;

/*
 * BGR. Rotation base of global registers.
 * 11 bits wide. Rounded to 32-bit, because 16-bit memory & sysreg access
 * makes no sense in this case
 */
typedef union {
	struct { /* Structure of bgr reg */
		u32 val		: 8;	/* [ 7: 0]      */
		u32 cur		: 3;	/* [10: 8]      */
	};
	e2k_reg_t;		/* as entire register   */
} e2k_bgr_t;

#define	E2K_INITIAL_BGR		((e2k_bgr_t) { .val = 0xff })
#define	E2K_GB_START_REG_NO_d	24
#define	E2K_GB_REGS_NUM_d	(E2K_MAXGR_d - E2K_GB_START_REG_NO_d)




/*
 * State of random predicates generator
 */

typedef union {
	struct {
		u64 f1 : 17;
		u64    : 15;
		u64 f2 : 18;
		u64    : 14;
	};
	u64 word;
} e2k_rndpr_t;

#define E2K_INITIAL_RNDPR ((e2k_rndpr_t) { .word = ULL(-1) })




/* CR0 */

	/* Just as defined in doc */
typedef union {
	struct {
		u64 pf;
		struct { /* Structure of cr0_hi chain reg */
			u64	: 3;
			u64 Ip	: E2K_VA_SIZE - 3;
		};
	};
	e2k_qreg_t;
} e2k_cr0_t;

#define get_cr0_ip(cr0) (cr0.Ip << 3)

#define set_cr0_ip(cr0, func)	do {	\
	cr0.Ip = ((u64) (func) >> 3);	\
} while(0)
#define set_cr0_p_ip(cr0, func)	do {	\
	(cr0)->Ip = ((u64) (func) >> 3);\
} while(0)

#define copy_cr0_ip(dst, src)	((dst).Ip = (src).Ip)




/* CR1 */

typedef union {
	struct {
		union { /* Structure of cr1_lo chain reg */
			struct {
				u64 ussz_hi	: 16;	/* [15:0]       */
				u64 ein		: 8;	/* [23:16]      */
				u64 ss		: 1;	/* [24]         */
				u64 wfx		: 1;	/* [25]         */
				u64 wpsz	: 7;	/* [32:26]      */
				u64 wbs		: 7;	/* [39:33]      */
				u64 cuir	: 17;	/* [56:40]      */
				u64 psr		: 7;	/* [63:57]      */
			};
			struct {	/* must be matched to psr and cuir regs */
				u64		: 40;	/* [39:0]       */
				u64 cui		: 16;	/* [40:55]      */
				u64 ic		: 1;	/* [56]         */
				u64 pm		: 1;	/* [57] privileged mode */
				u64 ie		: 1;	/* [58] interrupt enable */
				u64 sge		: 1;	/* [59] stack gard control enable */
				u64 lw		: 1;	/* [60] last wish */
				u64 uie		: 1;	/* [61] user interrupts enable */
				u64 nmie	: 1;	/* [62] not masked interrupts enable */
				u64 unmie	: 1;	/* [63] user not masked interrupts */
							/*      enable */
			};
		};
		union { /* Structure of cr1_hi chain reg */
			struct {
				u64 br		: 28;	/* [27: 0]      */
				u64		: 7;	/* [34:28]      */
				u64 wdbl	: 1;	/* [35:35]      */
				u64 ussz_lo	: 28;	/* [63:36]      */
			};
			struct {
				u64 rbs		: 6;	/* [5 :0 ]      */
				u64 rsz		: 6;	/* [11:6 ]      */
				u64 rcur	: 6;	/* [17:12]      */
				u64 psz		: 5;	/* [22:18]      */
				u64 pcur	: 5;	/* [27:23]      */
				u64		: 36;	/* [63:28]      */
			};
		};
	};
	e2k_qreg_t;
} e2k_cr1_t;

#define E2K_INSTR_ALIGNMENT	8	/* alignment of e2k instructions */
					/* in bytes */

/*
 * Control Transfer Preparation Register (CTPR)
 */

	/*
	 * Structure of double-word register
	 * access CTPR.CTPR_xxx or CTPR -> CTPR_xxx
	 */
typedef union {
	/* Common fields */
	struct {
		struct {
			u64 ta_base	: E2K_VA_SIZE;
			u64		: 64 - E2K_VA_SIZE;
		};
		struct {
			u64		: 64;
		};
	};
	struct {
		struct {
			u64 ta_base	: E2K_VA_SIZE;
			u64		: 54 - E2K_VA_SIZE;
			u64 ta_tag	: 3;
			u64 opc		: 2;
			u64 ipd		: 2;
			u64		: 3;
		};
		struct {
			u64		: 64;
		};
	} v3;
	struct {
		struct {
			u64 ta_base	: E2K_VA_SIZE;
			u64		: 54 - E2K_VA_SIZE;
			u64 ta_tag	: 3;
			u64 opc		: 2;
			u64 ipd		: 2;
			u64		: 3;
		};
		struct {
			u64 cui		: 16;
			u64 intc_fz	: 1;
			u64		: 47;
		};
	} v6;
	struct {
		struct {
			u64 ta_base	: E2K_VA_SIZE;
			u64		: 64 - E2K_VA_SIZE;
		};
		struct {
			u64 cui		: 16;
			u64 intc_fz	: 1;
			u64		: 40;
			u64 opc		: 2;
			u64 ipd		: 2;
			u64 ta_tag	: 3;
		};
	} v7;
	e2k_qreg_t;
} e2k_ctpr_t;

/* Control Transfer Opcodes */
#define	DISP_CT_OPC	0
#define	LDISP_CT_OPC	1
#define	RETURN_CT_OPC	3

/* Control Transfer Tag */
#define	CTPEW_CT_TAG	0	/* empty word */
#define	CTPDW_CT_TAG	1	/* diagnostic word */
#define	CTPPL_CT_TAG	2	/* procedure label */
#define	CTPLL_CT_TAG	3	/* local label */
#define	CTPNL_CT_TAG	4	/* numeric label */
#define	CTPSL_CT_TAG	5	/* system label */

/* Control Transfer Prefetch Level */
#define	NONE_CT_IPD	0	/* none any prefetching */
#define	ONE_IP_CT_IPD	1	/* only one instruction on 'ta_base' IP */
#define	TWO_IP_CT_IPD	2	/* two instructions on 'ta_base' and next IP */


/* PSR */
typedef union {
	struct {
		u32 pm		: 1;	/* [ 0]         */
		u32 ie		: 1;	/* [ 1]         */
		u32 sge		: 1;	/* [ 2]         */
		u32 lw		: 1;	/* [ 3] last wish */
		u32 uie		: 1;	/* [ 4] user interrupts enable */
		u32 nmie	: 1;	/* [ 5] not masked interrupts enable */
		u32 unmie	: 1;	/* [ 6] user not masked interrupts */
					/*      enable */
	};
	struct {
		u32 all		: 7;	/* all psr bits */
	};
	e2k_reg_t;		/* as entire register   */
} e2k_psr_t;

#define E2K_RESET_PSR ((e2k_psr_t) { .pm = 1 })

#define	PSR_PM		0x01U
#define	PSR_IE		0x02U
#define	PSR_SGE		0x04U
#define	PSR_LW		0x08U
#define	PSR_UIE		0x10U
#define	PSR_NMIE	0x20U
#define	PSR_UNMIE	0x40U
#define	PSR_DISABLE	0xff8dU	/*~(PSR_IE|PSR_NMIE|PSR_UIE|PSR_UNMIE) */
#define	PSR_PM_DISABLE	0xfffeU	/* ~PSR_PM_AS */

/* Compilation units table boundaries alignment (2's exponent value */
#define	E2K_ALIGN_CUT		5
#define	E2K_ALIGN_CUT_MASK	((1UL << E2K_ALIGN_CUT) - 1)


/* CUTD */
typedef union {
	struct {
		u64 base	: E2K_VA_SIZE;	/* [47: 0] */
	};
	e2k_dreg_t;
} e2k_cutd_t;

/* SBBP */
typedef union {
	struct {
		u64 base	: E2K_VA_SIZE;	/* [47: 0] */
	};
	e2k_dreg_t;
} e2k_sbbp_t;
/* CUIR */
typedef union {
	struct {		/* Structure of the CUIR reg    */
		u32 index	: 16;	/* [15: 0]      */
		u32 checkup	: 1;	/* [16:16]      */
	};
	e2k_reg_t;		/* as entire register   */
} e2k_cuir_t;

/* TSD */
typedef union e2k_tsd {
	struct {		/* Structure of the TSD reg     */
		u64 base	: 15;	/* [14: 0]      */
		u64		: 17;	/* [31:15]      */
		u64 size	: 15;	/* [46:32]      */
	};
	e2k_dreg_t;		/* as entire register   */
} e2k_tsd_t;

#define	CUD_CFLAG_CEARED	0	/* intermodule security verification */
					/* (ISV) have not passed             */
#define	CUD_CFLAG_SET		1	/* ISV have passed                   */

/* Hardware procedure stack memory mapping (one quad-register record, LE) */
/* Istruction sets from V3 to V4 */
typedef struct e2k_mem_ps_v3 {
	unsigned long word_lo;	/* low word value */
	unsigned long word_hi;	/* high word value */
	unsigned long ext_lo;	/* extention of low word */
	unsigned long ext_hi;	/* extention of hagh word */
} e2k_mem_ps_v3_t;
/* Istruction sets from V5 to V6 */
typedef struct e2k_mem_ps_v5 {
	unsigned long word_lo;	/* low word value */
	unsigned long ext_lo;	/* extention of low word */
	unsigned long word_hi;	/* high word value */
	unsigned long ext_hi;	/* extention of hagh word */
} e2k_mem_ps_v5_t;
typedef union e2k_mem_ps {
	struct {
		/* Common fields */
		unsigned long word_lo;
		unsigned long __pad1;
		unsigned long __pad2;
		unsigned long ext_hi;
	};
	e2k_mem_ps_v3_t v3;
	e2k_mem_ps_v5_t v5;
} e2k_mem_ps_t;

/* interkernel hardware-independent representation */
typedef struct kernel_mem_ps {
	unsigned long word_lo;	/* low word value */
	unsigned long word_hi;	/* high word value */
	unsigned long ext_lo;	/* extention of low word */
	unsigned long ext_hi;	/* extention of high word */
} kernel_mem_ps_t;

/* Chain stack memory mapping (one record, LE) */

typedef struct {
	e2k_cr0_t cr0;
	e2k_cr1_t cr1;
} e2k_mem_crs_t;


/*
 * chain stack items relative offset from cr_ind for pcsp
 */

#define CR0_I		0
#define CR1_I		(2 * 8)

#define	CR0_LO_I	(0 * 8)
#define	CR0_HI_I	(1 * 8)
#define	CR1_LO_I	(2 * 8)
#define	CR1_HI_I	(3 * 8)

/*
 * cr1.lo.wbs is size of prev proc in terms of qregs.
 * But in hard stack these regs are in extended format (*2)
 */
#define	EXT_4_NR_SZ	((4 * 4) * 2)
#define	SZ_OF_CR	sizeof(e2k_mem_crs_t)

typedef union {
	struct {
		u64 trwm_itag		: 3;
		u64 trwm_idata		: 3;
		u64 trwm_cf		: 3;
		u64 ib_snoop_dsbl	: 1;
		u64 bist_cf		: 1;
		u64 bist_tu		: 1;
		u64 bist_itag		: 1;
		u64 bist_itlbtag	: 1;
		u64 bist_itlbdata	: 1;
		u64 bist_idata_nm	: 4;
		u64 bist_idata_cnt	: 10;
		u64 pipe_frz_dsbl	: 1;	/* Since iset v5 */
		u64 rf_clean_dsbl	: 1;
		/* iset v6 */
		u64 virt_dsbl		: 1;
		u64 upt_sec_ad_shift_dsbl:1;
		u64 pdct_stat_enbl	: 1;
		u64 pdct_dyn_enbl	: 1;
		u64 pdct_rbr_enbl	: 1;
		u64 pdct_ret_enbl	: 1;
		u64 pdct_retst_enbl	: 1;
		u64 pdct_cond_enbl	: 1;
	};
	e2k_dreg_t;
} e2k_cu_hw0_t;

/*
 * Trap Info Registers
 */

typedef union {			/* simple TIRj register desc */
	struct {
		struct {
			u64 ip		: E2K_VA_SIZE;	/* [47 : 0 ] */
		};
		union {
			struct {
				u64 exc		: 44;	/* exceptions mask [43: 0] */
				u64 al		: 6;	/* ALS mask        [49:44] */
				u64		: 2;	/* unused bits     [51:50] */
				u64 aa		: 4;	/* MOVA mask       [55:52] */
				u64 j		: 8;	/* # of TIR        [63:56] */
			};
			struct {
				u64 exc_illegal_opcode		: 1;
				u64 exc_priv_action		: 1;
				u64				: 1;
				u64 exc_fp_stack_u		: 1;
				u64 exc_d_interrupt		: 1;
				u64 exc_diag_ct_cond		: 1;
				u64 exc_diag_instr_addr		: 1;
				u64 exc_illegal_instr_addr	: 1;
				u64 exc_instr_debug		: 1;
				u64 exc_window_bounds		: 1;
				u64 exc_user_stack_bounds	: 1;
				u64 exc_proc_stack_bounds	: 1;	/* [11] */
				u64 exc_chain_stack_bounds	: 1;	/* [12] */
				u64 exc_fp_stack_o		: 1;	/* [13] */
				u64 exc_diag_cond		: 1;	/* [14] */
				u64 exc_diag_operand		: 1;	/* [15] */
				u64 exc_illegal_operand		: 1;	/* [16] */
				u64 exc_array_bounds		: 1;	/* [17] */
				u64 exc_access_rights		: 1;	/* [18] */
				u64 exc_addr_not_aligned	: 1;	/* [19] */
				u64 exc_instr_page_miss		: 1;	/* [20] */
				u64 exc_instr_page_prot		: 1;	/* [21] */
				u64 exc_ainstr_page_miss	: 1;	/* [22] */
				u64 exc_ainstr_page_prot	: 1;	/* [23] */
				u64 exc_last_wish		: 1;	/* [24] */
				u64 exc_base_not_aligned	: 1;	/* [25] */
				u64 exc_software_trap		: 1;	/* [26] */
				u64				: 1;	/* [27] */
				u64 exc_data_debug		: 1;	/* [28] */
				u64 exc_data_page		: 1;	/* [29] */
				u64 exc_macp			: 1;	/* [30], starting from v7*/
				u64 exc_recovery_point		: 1;	/* [31] */
				u64 exc_interrupt		: 1;	/* [32] */
				u64 exc_nm_interrupt		: 1;	/* [33] */
				u64 exc_div			: 1;	/* [34] */
				u64 exc_fp			: 1;	/* [35] */
				u64 exc_mem_lock		: 1;	/* [36] */
				u64 exc_mem_lock_as		: 1;	/* [37] */
				u64 exc_data_error		: 1;	/* [38] */
				u64 exc_mem_error_MAU		: 1;	/* [39] */
				u64 exc_mem_error_L2		: 1;	/* [40] */
				u64 exc_mem_error_L1_35		: 1;	/* [41] */
				u64 exc_mem_error_L1_02		: 1;	/* [42] */
				u64 exc_mem_error_I		: 1;	/* [43] */

				u64 al0 : 1;
				u64 al1 : 1;
				u64 al2 : 1;
				u64 al3 : 1;
				u64 al4 : 1;
				u64 al5 : 1;
			};
			u64 exc_al_aa_j;
			struct {
				u64			: 39;
				u64 exc_mem_error	: 5;
			};
		};
	};
	e2k_qreg_t;
} e2k_tir_t;

#define GET_CLEAR_TIR_HI(tir_no)        (((tir_no) & 0xffULL) << 56)
#define GET_CLEAR_TIR_LO(tir_no)        0ULL

#define	MAX_TIRs_NUM	19

/*
 *  User processor status register (UPSR)
 */
typedef union {
	struct {
		u32 fe		: 1;	/* float-pointing enable */
		u32 se		: 1;	/* supervisor mode enable (only for Intel) */
		u32 ac		: 1;	/* not-aligned access control */
		u32 di		: 1;	/* delayed interrupt (only for Intel) */
		u32 wp		: 1;	/* write protection (only for Intel) */
		u32 ie		: 1;	/* interrupt enable */
		u32 a20		: 1;	/* emulation of 1 Mb memory (only for Intel) */
					/* should be 0 for Elbrus */
		u32 nmie	: 1;	/* not masked interrupt enable */
		/* next field of register exist only on E2S/E8C/E1C+ CPUs */
		u32 fsm		: 1;	/* floating comparison mode flag */
		/* 1 - compatible with x86/x87 */
		u32 impt	: 1;	/* ignore Memory Protection Table flag */
		u32 iuc		: 1;	/* ignore access right for uncached pages */

	};
	struct {
		u32 all:11;
	};
	e2k_reg_t;		/* as entire register   */
} e2k_upsr_t;


#define	UPSR_FE		0x01U
#define	UPSR_SE		0x02U
#define	UPSR_AC		0x04U
#define	UPSR_DI		0x08U
#define	UPSR_WP		0x10U
#define	UPSR_IE		0x20U
#define	UPSR_A20	0x40U
#define	UPSR_NMIE	0x80U
/* next field of register exist only on E2S/E8C/E1C+ CPUs */
#define	UPSR_FSM	0x100U
#define	UPSR_IMPT	0x200U
#define	UPSR_IUC	0x400U
#define	UPSR_DISABLE		(0xff5f)	/* ~(UPSR_IE_AS|UPSR_NMIE_AS) */

/* (IS_UPT_E3S ? 0 : UPSR_SE_AS) */
#ifndef IS_UPT_E3S
#define KERNEL_UPSR_SE_INIT	0
#else
#define KERNEL_UPSR_SE_INIT	UPSR_SE
#endif /* IS_UPT_E3S */
#ifndef	CONFIG_ACCESS_CONTROL
#define KERNEL_UPSR_ALL_INIT	(UPSR_FE | KERNEL_UPSR_SE_INIT)
#else
#define KERNEL_UPSR_ALL_INIT	(UPSR_FE | KERNEL_UPSR_SE_INIT | UPSR_AC)
#endif /* KERNEL_UPSR_ALL_INIT */

/*
 * Time registrs
 */

typedef union {
	struct {
		u64 lo	: 32;
		u64 hi	: 32;
	};
	u64 word;
} e2k_sclkr_t;

typedef union {
	struct {
		u64 div		: 32;
		u64 mdiv	: 1;
		u64 mode	: 1;
		u64 trn		: 1;
		u64 sw		: 1;
		u64 wsclkr	: 1;
		u64		: 19;
		u64 ver		: 8;
	};
	struct {
		u64		: 56;
		u64 w_sclkr_hi	: 1;
		u64 sclkm3	: 1;
		u64		: 6;
	};
	e2k_dreg_t;
} e2k_sclkm1_t;

typedef union {
	struct {
		u32 min;
		u32 max;
	};
	 e2k_dreg_t;
} e2k_sclkm2_t;

/*
 *  Processor Identification Register (IDR)
 */
typedef union e2k_idr {
	struct {
		u64 mdl			: 8;	/* CPU model number */
		u64 rev			: 4;	/* revision number */
		u64 wbl			: 3;	/* write back length of L2 */
		u64 core		: 5;	/* number of the core into node */
		u64 pn			: 4;	/* node number from RT_LCFG0.pn */
		u64 hw_virt		: 1;	/* hardware virtualization enabled */
		u64 hw_virt_ver		: 4;	/* hardware virtualization revision */
		/* number */
		u64 reserve		: 35;	/* reserved */
	};
	struct {
		u64		: 12;
		u64 ms		: 52;	/* model specific info */
	};
	e2k_dreg_t;		/* as entire register */
} e2k_idr_t;


/* Convert IDR register write back length code to number of bytes */
/* using current WBL code presentation */
#define	IDR_WBL_TO_BYTES(wbl)	((wbl) ? (1 << (wbl + 4)) : 1)



/*
 *  Processor Core Mode Register (CORE_MODE)
 */
typedef union e2k_core_mode {
	struct {
		u32			: 2;	/* bit #0 reserved */
		u32 sep_virt_space	: 1;	/* separate page tables for kernel and users */
		u32 gmi			: 1;	/* indicator of guest mode */
						/* actual only in guest mode */
		u32 hci			: 1;	/* indicator of hypercalls enabled */
						/* actual only in guest mode */
		u32 pt_v6		: 1;	/* new Page Tables structures mode */
						/* only for ISET >= V6 */
		u32 getsp_v7		: 1;	/* GETSAP, GETSP use v7 notation */
		u32 descr_v7		: 1;	/* CPU regs and RWAP have v7 format */
		u32			: 24;	/* other bits reserved */
	};
	struct { /* v3 */
		u32			: 1;
		u32 no_stack_prot	: 1;	/* no check stack pointers */
		u32			: 30;
	};
	struct { /* v7 */
		u32			: 8;
		u32 macp_enbl		: 1;	/* enable colour protection */
	};
	e2k_reg_t;		/* as entire register */
} e2k_core_mode_t;



/*
 *  Packed Floating Point Flag Register (PFPFR)
 */
typedef union {
	struct {
		u32 ie		: 1;	/* [0] */
		u32 de		: 1;	/* [1] */
		u32 ze		: 1;	/* [2] */
		u32 oe		: 1;	/* [3] */
		u32 ue		: 1;	/* [4] */
		u32 pe		: 1;	/* [5] */
		u32 zero1	: 1;	/* [6] */
		u32 im		: 1;	/* [7] */
		u32 dm		: 1;	/* [8] */
		u32 zm		: 1;	/* [9] */
		u32 om		: 1;	/* [10] */
		u32 um		: 1;	/* [11] */
		u32 pm		: 1;	/* [12] */
		u32 rc		: 2;	/* [14:13] */
		u32 fz		: 1;	/* [15] */
		u32 zero2	: 10;	/* [25:16] */
		u32 die		: 1;	/* [26] */
		u32 dde		: 1;	/* [27] */
		u32 dze		: 1;	/* [28] */
		u32 doe		: 1;	/* [29] */
		u32 due		: 1;	/* [30] */
		u32 dpe		: 1;	/* [31] */
	};
	e2k_reg_t;		/* as entire register   */
} e2k_pfpfr_t;

/*
 *  Floating point control register (FPCR)
 */
typedef union {
	struct {
		u32 im		: 1;	/* [0] */
		u32 dm		: 1;	/* [1] */
		u32 zm		: 1;	/* [2] */
		u32 om		: 1;	/* [3] */
		u32 um		: 1;	/* [4] */
		u32 pm		: 1;	/* [5] */
		u32 one1	: 1;	/* [6] */
		u32 zero1	: 1;	/* [7] */
		u32 pc		: 2;	/* [9:8] */
		u32 rc		: 2;	/* [11:10] */
		u32 ic		: 1;	/* [12] */
		u32 zero2	: 3;	/* [15:13] */
	};
	e2k_reg_t;		/* as entire register   */
} e2k_fpcr_t;

/*
 * Floating point status register (FPSR)
 */
typedef union {
	struct {
		u32 ie		: 1;	/* [0] */
		u32 de		: 1;	/* [1] */
		u32 ze		: 1;	/* [2] */
		u32 oe		: 1;	/* [3] */
		u32 ue		: 1;	/* [4] */
		u32 pe		: 1;	/* [5] */
		u32 zero1	: 1;	/* [6] */
		u32 es		: 1;	/* [7] */
		u32 zero2	: 1;	/* [8] */
		u32 c1		: 1;	/* [9] */
		u32 zero3	: 5;	/* [14:10] */
		u32 bf		: 1;	/* [15] */
	};
	e2k_reg_t;		/* as entire register   */
} e2k_fpsr_t;

/* Debug registers */
typedef union {
	struct {
		u32 user	: 1;
		u32 system	: 1;
		u32 trap	: 1;
		u32		: 13;
		u32 event	: 8;
		u32		: 8;
	} dimar[2];
	struct {
		u64		: 11;
		u64 u_m_en	: 1;
		u64 mode	: 4;
		u64		: 48;
	};
	u32 half_word[2];
	e2k_dreg_t;
} e2k_dimcr_t;

static inline bool dimcr_enabled(e2k_dimcr_t dimcr, int monitor)
{
	return (monitor == 0) ? (dimcr.dimar[0].user || dimcr.dimar[0].system)
	    : (dimcr.dimar[1].user || dimcr.dimar[1].system);
}

typedef union {
	struct {
		u32 b0		: 1;
		u32 b1		: 1;
		u32 b2		: 1;
		u32 b3		: 1;
		u32 bt		: 1;
		u32 m0		: 1;
		u32 m1		: 1;
		u32 ss		: 1;
		u32 btf		: 1;
		u32 p_exc	: 1;
		u32 m2		: 1;
		u32 m3		: 1;
	};
	e2k_reg_t;
} e2k_dibsr_t;

#define E2K_DIBSR_MASK(cp_num) (0x1ULL << (cp_num))
#define E2K_DIBSR_MASK_ALL_BP 0xfULL

typedef union {
	struct {
		u32 v0		: 1;
		u32 t0		: 1;

		u32 v1		: 1;
		u32 t1		: 1;

		u32 v2		: 1;
		u32 t2		: 1;

		u32 v3		: 1;
		u32 t3		: 1;

		u32 bt		: 1;
		u32 stop	: 1;
		u32 btf		: 1;
		u32 gm		: 1;
	};
	e2k_reg_t;
} e2k_dibcr_t;

typedef union e2k_dimtp {  /*  <= v6 */
	struct {
		struct {
			u64 base	: E2K_VA_SIZE;
		};
		struct {
			u64 ind		: 32;
			u64 size	: 32;
		};
	};
	e2k_qreg_t;
	e2k_qreg_t word;
} e2k_dimtp_t;

#define E2K_DIMTP_ALIGN 32


/* Memory Access Debug Modes Register */
typedef union {
	struct {
		u32 mode_ld	: 2;
		u32 mode_st	: 2;
		u32 ev_ld	: 1;
		u32 ev_st	: 1;
		u32 p_exc	: 1;
		u32 mode_wa	: 2;
		u32 ev_wa	: 1;
	};
	e2k_reg_t;
} e2k_madmr_t;

#define E2K_MADMR_EMPTY ((e2k_madmr_t) { .word = 0 })
#define E2K_MADMR_MODE_LD_NONE		0
#define E2K_MADMR_MODE_LD_DT_NO_EXC	1
#define E2K_MADMR_MODE_LD_EXC		2
#define E2K_MADMR_MODE_LD_EXC_SLOW	3
#define E2K_MADMR_MODE_ST_NONE		0
#define E2K_MADMR_MODE_ST_EXC		2
#define E2K_MADMR_MODE_ST_EXC_SLOW	3
#define E2K_MADMR_MODE_WA_NONE		0
#define E2K_MADMR_MODE_WA_FLAG		1
#define E2K_MADMR_MODE_WA_EXC_SLOW	3

/*
 * Global registers (saved state) definition
 */
typedef struct e2k_svd_gregs_struct {
	u64 base;		/* exists any time */
	u32 extension;		/* when holds an FP value */
	u8 tag;			/* any time too */
} e2k_svd_gregs_t;

struct hw_stacks {
	e2k_psp_t psp;
	e2k_pshtp_t pshtp;
	e2k_pcsp_t pcsp;
	e2k_pcshtp_t pcshtp;
};

typedef enum cu_reg_no {
	undef_cu_reg_no = -1,
	SCLKM1_cu_reg_no = 0x70,
	SCLKM2_cu_reg_no = 0x71,
	SCLKM3_cu_reg_no = 0x72,
	IDR_cu_reg_no = 0x8a,
	CLKR_cu_reg_no = 0x90,
	SCLKR_cu_reg_no = 0x92,
	DIBCR_cu_reg_no = 0x40,
	DIMCR_cu_reg_no = 0x41,
	DIBSR_cu_reg_no = 0x42,
	DTCR_cu_reg_no = 0x43,
	DIMTP_hi_cu_reg_no = 0x46,
	DIMTP_lo_cu_reg_no = 0x47,
	DIBAR0_cu_reg_no = 0x48,
	DIBAR1_cu_reg_no = 0x49,
	DIBAR2_cu_reg_no = 0x4a,
	DIBAR3_cu_reg_no = 0x4b,
	DIMAR0_cu_reg_no = 0x4c,
	DIMAR1_cu_reg_no = 0x4d,
	DTARF_cu_reg_no = 0x4e,
	DTART_cu_reg_no = 0x4f,
	CU_HW0_cu_reg_no = 0x78,
	CU_HW1_cu_reg_no = 0x79,
	CU_PMGR0_cu_reg_no = 0x7a,
} cu_reg_no_t;
