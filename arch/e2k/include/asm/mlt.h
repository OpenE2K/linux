#ifndef _E2K_MLT_H_
#define _E2K_MLT_H_

#include <asm/cpu_regs_types.h>
#include <asm/types.h>


#define	NATIVE_MLT_SIZE		16

#define REG_MLT_N_SHIFT		7
#define	REG_MLT_DW_SHIFT	5
#define	REG_MLT_TYPE_SHIFT	0

#define REG_MLT_TYPE		5UL


typedef unsigned long	e2k_mlt_line_t;

typedef struct e2k_mlt_dw0_v3_fields
{
	e2k_mlt_line_t	resc		: 4;	/* [3:0] */
	e2k_mlt_line_t	mask		: 8;	/* [11:4] */
	e2k_mlt_line_t	page		: 28;	/* [39:12]*/
	e2k_mlt_line_t	opcod_size	: 3;	/* [42:40] */
	e2k_mlt_line_t	rg		: 8;	/* [50:43] */
	e2k_mlt_line_t	lock_mode	: 1;	/* [51] */
	e2k_mlt_line_t	hit		: 1;	/* [52] */
	e2k_mlt_line_t	val		: 1;	/* [53] */
	e2k_mlt_line_t	unresolved	: 10; 	/* [63:54] */
} e2k_mlt_dw0_v3_fields_t;

typedef struct e2k_mlt_dw0_v6_fields
{
	e2k_mlt_line_t	val		: 1;	/* [0] */
	e2k_mlt_line_t	hit		: 1;	/* [1] */
	e2k_mlt_line_t	lock_mode	: 1;	/* [2] */
	e2k_mlt_line_t	word_fst	: 9;	/* [11:3] */
	e2k_mlt_line_t	page_fst	: 36;	/* [47:12]*/
	e2k_mlt_line_t	mask_fst	: 8;	/* [55:48] */
	e2k_mlt_line_t	rg		: 8;	/* [63:56] */
} e2k_mlt_dw0_v6_fields_t;

/* One reg (string) in MLT table */
typedef struct e2k_mlt_entry {
	union {
		e2k_mlt_dw0_v3_fields_t	v3_fields;
		e2k_mlt_dw0_v6_fields_t	v6_fields;
		e2k_mlt_line_t		word;
	} dw0;

	union {
		e2k_mlt_line_t		word;
	} dw1;

	union {
		e2k_mlt_line_t		word;
	} dw2;
} e2k_mlt_entry_t;

typedef struct e2k_mlt {
	int num;				/* number of entries in the MLT */
	e2k_mlt_entry_t mlt[NATIVE_MLT_SIZE];	/* valid MLT entries */
} e2k_mlt_t;

#define	NATIVE_READ_MLT_REG(addr) \
		NATIVE_DO_READ_MAS(addr, MAS_MLT_REG, e2k_mlt_line_t, d, 2)

typedef unsigned long	e2k_dam_t;

#define REG_DAM_N_SHIFT		7
#define	REG_DAM_TYPE_SHIFT	0
#define REG_DAM_TYPE		4

#define	NATIVE_READ_DAM_REG(addr) \
		NATIVE_DO_READ_MAS(addr, MAS_DAM_REG, e2k_dam_t, d, 2)

#define NATIVE_SAVE_BINCO_REGS_FOR_PTRACE(regs)				\
do {									\
	regs->rpr_lo = NATIVE_READ_RPR_LO_REG_VALUE();			\
	regs->rpr_hi = NATIVE_READ_RPR_HI_REG_VALUE();			\
} while (0)

#endif
