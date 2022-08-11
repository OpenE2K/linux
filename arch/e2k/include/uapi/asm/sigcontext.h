#ifndef _UAPI_E2K_SIGCONTEXT_H_
#define _UAPI_E2K_SIGCONTEXT_H_

#define MAX_TC_SIZE	10

#define TIR_NUM 19
#define DAM_ENTRIES_NUM 32
#define SBBP_ENTRIES_NUM 32

/* from user.h !!! */
#define MLT_NUM (16 * 3)

struct sigcontext {
	unsigned long long	cr0_lo;
	unsigned long long	cr0_hi;
	unsigned long long	cr1_lo;
	unsigned long long	cr1_hi;
	unsigned long long	sbr;	 /* 21 Stack base register: top of */
					 /*    local data (user) stack */
	unsigned long long	usd_lo;	 /* 22 Local data (user) stack */
	unsigned long long	usd_hi;	 /* 23 descriptor: base & size */
	unsigned long long	psp_lo;	 /* 24 Procedure stack pointer: */
	unsigned long long	psp_hi;	 /* 25 base & index & size */
	unsigned long long	pcsp_lo; /* 26 Procedure chain stack */
	unsigned long long	pcsp_hi; /* 27 pointer: base & index & size */
/*
 *  additional part (for binary compiler)
 */
	unsigned long long rpr_hi;
	unsigned long long rpr_lo;

	unsigned long long nr_TIRs;
	unsigned long long tir_lo[TIR_NUM];
	unsigned long long tir_hi[TIR_NUM];
	unsigned long long trap_cell_addr[MAX_TC_SIZE];
	unsigned long long trap_cell_val[MAX_TC_SIZE];
	unsigned char      trap_cell_tag[MAX_TC_SIZE];
	unsigned long long trap_cell_info[MAX_TC_SIZE];

	unsigned long long dam[DAM_ENTRIES_NUM];

	unsigned long long sbbp[SBBP_ENTRIES_NUM];

	unsigned long long mlt[MLT_NUM];

	unsigned long long upsr;
};
/*
 * This structure is used for compatibility
 * All new fields must be added in this structure
 */
struct extra_ucontext {
	int	sizeof_extra_uc;	/* size of used fields(in bytes) */
	int	curr_cnt;		/* current index into trap_celler */
	int	tc_count;		/* trap_celler records count */

	/*
	 * For getcontext()
	 */
	int	fpcr;
	int	fpsr;
	int	pfpfr;

	unsigned long long ctpr1;
	unsigned long long ctpr2;
	unsigned long long ctpr3;

	int	sc_need_rstrt;
};


#endif /* _UAPI_E2K_SIGCONTEXT_H_ */
