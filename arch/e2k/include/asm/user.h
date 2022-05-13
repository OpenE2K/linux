#ifndef _E2K_USER_H_
#define _E2K_USER_H_

#include <asm/page.h>
#include <linux/ptrace.h>


/* When the kernel dumps core, it starts by dumping the user struct -
 * this will be used by gdb to figure out where the data and stack segments
 * are within the file, and what virtual addresses to use.
 */

#define __CHECK_USER        0x1034567887654301ULL
#define __CHECK_KERNEL      0x1234567887654321ULL
#define MLT_NUM (16 * 3)

/*
 * ATTENTION!!! Any change should be submitted to debugger
 */

struct user_regs_struct {
	unsigned long long sizeof_struct;     /* interface with debugger */
	unsigned long long g[32];

	unsigned long long psr;
	unsigned long long upsr;

	unsigned long long oscud_lo;
	unsigned long long oscud_hi;
	unsigned long long osgd_lo;
	unsigned long long osgd_hi;
	unsigned long long osem;
	unsigned long long osr0;

	unsigned long long pfpfr;
	unsigned long long fpcr;
	unsigned long long fpsr;

	unsigned long long usbr;
	unsigned long long usd_lo;
	unsigned long long usd_hi;

	unsigned long long psp_lo;
	unsigned long long psp_hi;
	unsigned long long pshtp;

	unsigned long long cr0_lo;
	unsigned long long cr0_hi;
	unsigned long long cr1_lo;
	unsigned long long cr1_hi;

	unsigned long long cwd;

	unsigned long long pcsp_lo;
	unsigned long long pcsp_hi;
	unsigned long long pcshtp;

	unsigned long long cud_lo;
	unsigned long long cud_hi;
	unsigned long long gd_lo;
	unsigned long long gd_hi;

	unsigned long long cs_lo;
	unsigned long long cs_hi;
	unsigned long long ds_lo;
	unsigned long long ds_hi;
	unsigned long long es_lo;
	unsigned long long es_hi;
	unsigned long long fs_lo;
	unsigned long long fs_hi;
	unsigned long long gs_lo;
	unsigned long long gs_hi;
	unsigned long long ss_lo;
	unsigned long long ss_hi;

	unsigned long long aad[32*2]; /* %aad0.lo, %aad0.hi, %aad1.lo ... */
	unsigned long long aaind[16];
	unsigned long long aaincr[8];
	unsigned long long aaldi[64];
	unsigned long long aaldv;
	unsigned long long aalda[64];
	unsigned long long aaldm;
	unsigned long long aasr;
	unsigned long long aafstr;
	unsigned long long aasti[16];

	unsigned long long clkr;
	unsigned long long dibcr;
	unsigned long long ddbcr;
	unsigned long long dibar[4];
	unsigned long long ddbar[4];
	unsigned long long dimcr;
	unsigned long long ddmcr;
	unsigned long long dimar[2];
	unsigned long long ddmar[2];
	unsigned long long dibsr;
	unsigned long long ddbsr;
	unsigned long long dtcr;
	unsigned long long dtarf;
	unsigned long long dtart;

	unsigned long long wd;

	unsigned long long br;
	unsigned long long bgr;

	unsigned long long ip;
	unsigned long long nip;
	unsigned long long ctpr1;
	unsigned long long ctpr2;
	unsigned long long ctpr3;

	unsigned long long eir;

	unsigned long long tr; /* unused */

	unsigned long long cutd;
	unsigned long long cuir;
	unsigned long long tsd; /* unused */

	unsigned long long lsr;
	unsigned long long ilcr;

	long long	sys_rval; 
	long long	sys_num;
	long long	arg1;	
	long long       arg2;
	long long	arg3;
	long long	arg4;
	long long	arg5;
	long long	arg6;

/*
 * Some space for backup/restore of extensions and tags of global registers.
 * now places in the end of structure
 */
	unsigned char	gtag[32];
	unsigned short	gext[32];
/*
 *  additional part (for binary compiler)
 */          
        unsigned long long rpr_hi;
        unsigned long long rpr_lo;
        
        unsigned long long tir_lo [TIR_NUM];
	unsigned long long tir_hi [TIR_NUM];

	unsigned long long trap_cell_addr [MAX_TC_SIZE];
	unsigned long long trap_cell_val  [MAX_TC_SIZE];
	unsigned char      trap_cell_tag  [MAX_TC_SIZE];
	unsigned long long trap_cell_info [MAX_TC_SIZE];

	unsigned long long dam [DAM_ENTRIES_NUM];

	unsigned long long sbbp [SBBP_ENTRIES_NUM];
        
	unsigned long long mlt [MLT_NUM];

/*
 * CPU info
 */
	unsigned long long idr;
	unsigned long long core_mode;

/*
 * iset v5 additions
 */
	unsigned long long lsr1;
	unsigned long long ilcr1;

	unsigned long long gext_v5[32];
	unsigned char gext_tag_v5[32];
/*
 * Not actual registers, but still useful information
 */
	unsigned long long chain_stack_base;
	unsigned long long proc_stack_base;

/*
 * iset v6 additions
 */
	unsigned long long dimtp_lo;
	unsigned long long dimtp_hi;
	unsigned long long ctpr1_hi;
	unsigned long long ctpr2_hi;
	unsigned long long ctpr3_hi;
/* 
 * Please, include new fields below 
 */
};

struct user_pt_regs {
	/* empty */
};

struct user{
/*
 * We start with the registers, to mimic the way that "memory" is returned
 * from the ptrace(3,...) function.
 */
	struct user_regs_struct regs;		/* Where the registers */
						/* are actually stored */

/* The rest of this junk is to help gdb figure out what goes where */

	unsigned long	int u_tsize;	/* Text segment size (pages). */
	unsigned long	int u_dsize;	/* Data segment size (pages). */
	unsigned long	int u_ssize;	/* Stack segment size (pages). */
	unsigned long	start_code;	/* text starting address */
	unsigned long	start_data;	/* data starting address */
	unsigned long	start_stack;	/* stack starting address */
  	long int signal;     		/* Signal that caused the core dump. */
	int reserved;			/* No longer used */
	struct user_pt_regs * u_ar0;	/* Used by gdb to help find the */
					/* values for the registers. */
	unsigned long magic;		/* To uniquely identify a core file */
	char u_comm[32];		/* User command that was responsible */
};

#define NBPG			PAGE_SIZE
#define UPAGES			1
#define HOST_TEXT_START_ADDR	(u.start_code)
#define HOST_STACK_END_ADDR	(u.start_stack + u.u_ssize * NBPG)

#endif /* _E2K_USER_H_ */
