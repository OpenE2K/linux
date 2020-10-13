#ifndef _E2K_PTRACE_H
#define _E2K_PTRACE_H


#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/threads.h>
#endif /* __ASSEMBLY__ */

#include <asm/page.h>

#ifndef __ASSEMBLY__
#include <asm/e2k_api.h>
#include <asm/cpu_regs.h>
#include <asm/mmu_types.h>
#include <asm/mmu_regs.h>
#ifdef CONFIG_USE_AAU
#include <asm/aau_regs.h>
#endif /* CONFIG_USE_AAU */
#include <asm/mlt.h>
#include <asm/ptrace-abi.h>

#endif /* __ASSEMBLY__ */
#include <uapi/asm/ptrace.h>

/*
 * Even 32-bit applications must have big TASK_SIZE since hardware
 * stacks are placed behind the 4Gb boundary.
 */
#define TASK_SIZE	(PAGE_OFFSET)

/*
 * User process size in MA32 mode.
 */
#define TASK32_SIZE		(0xf0000000UL)

/*
 * User process size in protected mode.
 */
#define TASKP_SIZE		(0x10000000000UL)

#ifndef __ASSEMBLY__

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
#include <asm/clock_info.h>
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
#include <asm/siginfo.h>

#include <linux/signal.h>

#ifdef CONFIG_USE_AAU
extern void  notrace _get_aau_context(e2k_aau_t *context);
#endif

/*
 * The structure define state of all e2k stacks:
 * hardware pointers and registers
 *
 * WARNING: 'usd_lo' field in the 'pt_regs' structure should have offset
 * JB_USD_LO = 22 (in format of long long) as defined by e2k GLIBC header
 * /usr/include/bits/setjmp.h
 */


typedef struct e2k_stacks {
	e2k_sbr_t	sbr;	 /* 21 Stack base register: top of */
				 /*    local data (user) stack */
	e2k_usd_lo_t 	usd_lo;	 /* 22 Local data (user) stack */
	e2k_usd_hi_t 	usd_hi;	 /* 23 descriptor: base & size */
	e2k_psp_lo_t	psp_lo;	 /* 24 Procedure stack pointer: */
	e2k_psp_hi_t 	psp_hi;	 /* 25 base & index & size */
	e2k_pcsp_lo_t 	pcsp_lo; /* 26 Procedure chain stack */
	e2k_pcsp_hi_t 	pcsp_hi; /* 27 pointer: base & index & size */

	/*
	 * It needs to save and restore those registers
	 * in signal_handler and longjump
	 * This problem was created because sigaltstack
	 * After exit from  signal_handler and longjump we must
	 * restore those registers
	 */
	u64		u_stk_sz_old;	/* User's c_stack size */
	u64		u_stk_top_old;	/* Top of the stack (as SBR) */
	u64		u_stk_base_old;	/* User's C stack base */
	bool		alt_stack_old;  /* the mark of alternative stack*/
	int		valid;		/* Valid or not those regs */
} e2k_stacks_t;

typedef struct  pt_regs   	ptregs_t;
typedef struct  sw_regs   	sw_regs_t;

struct trap_pt_regs {
	u64		TIR_hi;		/* Trap info registers */
	u64		TIR_lo;
	s8		nr_TIRs;
	s8		tc_count;
	s8		curr_cnt;
	char		ignore_user_tc;
	char		tc_called;
	char		from_sigreturn;
	u8		nr_page_fault_exc;	/* number of interrupt */
	int		prev_state;
	u32		srp_flags;	/* Trap occured on the instruction */
					/* with "Store recovery point" flag */
	e2k_tir_t	TIRs[TIR_NUM];
	trap_cellar_t	tcellar[MAX_TC_SIZE + 3];
};

/*
 * WARNING: 'usd_lo' field in the 'pt_regs' structure should have offset
 * JB_USD_LO = 22 (in format of long long) as defined by e2k GLIBC header
 * /usr/include/bits/setjmp.h
 */
typedef	struct pt_regs {
	struct trap_pt_regs *trap;
	e2k_ctpr_t	ctpr1;		/* CTPRj to controll trunsfer */
	e2k_ctpr_t	ctpr2;
	e2k_ctpr_t	ctpr3;
	u64		lsr;		/* to do loops */
	u64		ilcr;		/* initial loop value */
	long		sys_rval;
	long		sys_num;	/* to restart sys_call		*/
	long		arg1;
	long		arg2;
	long		arg3;
	long		arg4;
	long		arg5;
	long		arg6;
	long		restart_needed;
	e2k_wd_t	wd;		/* current window descriptor	*/
	e2k_stacks_t	stacks;		/* current state of all stacks */
					/* registers */
	e2k_mem_crs_t	crs;		/* current chain window regs state */
	e2k_pshtp_t	pshtp;		/* Procedure stack hardware */
					/* top pointer */
	struct pt_regs	*next;		/* the previous regs structure */

					/* next 5 fields contain state of */
					/* kernel stacks and thread state */
					/* on the trap or system call */
					/* moment to recovere their state */
					/* in the case of long jump in a */
					/* signal handler */
	e2k_addr_t	k_usd_size;	/* kernel data stack size */

#ifdef CONFIG_E2S_CPU_RF_BUG
	u64			e2s_gbase[8];
#endif
#ifdef CONFIG_USE_AAU
	e2k_aau_t	*aau_context;	/* aau registers */
#endif
#ifdef	CONFIG_CLW_ENABLE
	int		clw_count;
	int		clw_first;
	clw_reg_t	us_cl_m[CLW_MASK_WORD_NUM];
	clw_reg_t	us_cl_up;
	clw_reg_t	us_cl_b;
#endif	/* CONFIG_CLW_ENABLE */
        /* for bin_comp */
        u64             rpr_lo; 
        u64             rpr_hi; 
        u64             tls;            /* tls (thread local storage)
                                           - for user application  */ 

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	u8		rp_ret;		  /* recovery point condition */
	e2k_mlt_t	mlt_state;	  /* MLT state for binco */
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	scall_times_t	*scall_times;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
	int		interrupt_vector;

	/*
	 * One should store these fields in pt_regs to have an opportunity
	 * to recalc them after returning from user signal handler. It is need
	 * because a process could be on a new kernel data stack
	 * (fork, blcr module).
	 */
	struct k_sigaction	ka;
#ifdef CONFIG_GREGS_CONTEXT
	struct {
		u64		gbase[E2K_MAXGR_d];
		u16		gext[E2K_MAXGR_d];
		u8		tag[E2K_MAXGR_d];
		e2k_bgr_t	bgr;
	} gregs;
#endif

	/* One should store these fields in pt_regs to have an oppotunity
	 * to use __interrupt attribute for signal handling functions.
	 */
	siginfo_t	info;
} pt_regs_t;

#define	SRP_FLAG_PT_REGS	0x00000001U	/* Trap occured on the */
						/* instruction with */
						/* "Store recovery point" */
						/* flag */

struct sw_regs {
	e2k_cr0_lo_t	cr0_lo;		/* chain info to recover */
	e2k_cr0_hi_t	cr0_hi;		/* chain info to recover */
	e2k_cr1_lo_t	cr_wd;
	e2k_cr1_hi_t	cr_ussz;
	e2k_sbr_t	sbr;		/* base of all c_stacks */
	e2k_sbr_t	k_sbr;		/* k_c_stack. now to print for debug */
	e2k_usd_lo_t	usd_lo;
	e2k_usd_hi_t	usd_hi;
	e2k_psp_lo_t	psp_lo;	 	/* procedure stack pointer(as empty)*/
	e2k_psp_hi_t 	psp_hi;	 	 
	e2k_pcsp_lo_t 	pcsp_lo; 	/* procedure chaine stack pointer   */
	e2k_pcsp_hi_t 	pcsp_hi; 	/* (as empty)		    	    */
	e2k_upsr_t	upsr;
	e2k_psr_t	psr;
	e2k_fpcr_t	fpcr;
	e2k_fpsr_t	fpsr;
	e2k_pfpfr_t	pfpfr;
	e2k_cutd_t	cutd;

#ifdef CONFIG_GREGS_CONTEXT
	/* space to store global registers including possible FP extension */
	u64		gbase[E2K_MAXGR_d];
	u16		gext[E2K_MAXGR_d];
	/* Tags needs to avoid hardware bug for e3m (#41346)
	 *  result of "strd" instruction can loose tag
	 */
	u8		tag[E2K_MAXGR_d];

	/* Global registers rotation base */
	e2k_bgr_t	bgr;
#endif

	u64		dimar0;
	u64		dimar1;
	e2k_dimcr_t	dimcr;
	u64		ddmar0;
	u64		ddmar1;
	e2k_ddmcr_t	ddmcr;
	e2k_dibcr_t	dibcr;
	e2k_dibsr_t	dibsr;
	u64		dibar0;
	u64		dibar1;
	u64		dibar2;
	u64		dibar3;
	e2k_ddbcr_t	ddbcr;
	e2k_ddbsr_t	ddbsr;
	u64		ddbar0;
	u64		ddbar1;
	u64		ddbar2;
	u64		ddbar3;

	/*
	 * in the case we switch from/to a BINCO task, we 
	 * need to backup/restore these registers in task switching
	 */
	u64		cs_lo;
	u64		cs_hi;
	u64		ds_lo;	
	u64		ds_hi;	
	u64		es_lo;
	u64		es_hi;	
	u64		fs_lo;
	u64		fs_hi;
	u64		gs_lo;	
	u64		gs_hi;
	u64		ss_lo;
	u64		ss_hi;

	/* Additional registers for BINCO */
        u64             rpr_lo;
        u64             rpr_hi;
#ifdef CONFIG_TC_STORAGE
	u64		tcd;
#endif
};

typedef struct jmp_info {
   u64  sigmask;
   u64  ip;
   u64  cr1lo;
   u64  pcsplo;
   u64  pcsphi;
   u32  pcshtp;
   u32  br;
   u64  reserv1;
   u64  reserv2;
} e2k_jmp_info_t;

#define	__HAVE_ARCH_KSTACK_END

static inline int kstack_end(void *addr)
{
	return (e2k_addr_t)addr >= READ_SBR_REG_VALUE();
}

#define SAVE_DAM(dam) \
do { \
	int i; \
	e2k_addr_t addr = (REG_DAM_TYPE << REG_DAM_TYPE_SHIFT); \
	for (i = 0; i < DAM_ENTRIES_NUM; i++) \
		(dam)[i] = E2K_READ_DAM_REG(addr | (i << REG_DAM_N_SHIFT)); \
} while (0)

#define SAVE_REGS_FOR_PTRACE(ti)					\
do {									\
	SAVE_DAM(ti->dam);						\
	ti->gd_lo = E2K_GET_DSREG(gd.lo);				\
	ti->gd_lo = E2K_GET_DSREG(gd.hi);				\
	ti->gd_lo = E2K_GET_DSREG(cud.lo);				\
	ti->gd_lo = E2K_GET_DSREG(cud.hi);				\
} while (0)

#define arch_ptrace_stop_needed(...) (true)
/* current->thread_info->pt_regs may be zero if ptrace_stop()
 * was called from load_elf_binary() (it happens if gdb has
 * set PTRACE_O_TRACEEXEC flag). */
#define arch_ptrace_stop(...) \
do { \
	struct pt_regs *__pt_regs = current_thread_info()->pt_regs; \
	if (__pt_regs) { \
		SAVE_AAU_REGS_FOR_PTRACE(__pt_regs); \
		SAVE_BINCO_REGS_FOR_PTRACE(__pt_regs); \
	} \
	SAVE_REGS_FOR_PTRACE(current_thread_info()); \
} while (0)

/* Arbitrarily choose the same ptrace numbers as used by the Sparc code. */
#define PTRACE_GETREGS            12
#define PTRACE_SETREGS            13
#define PTRACE_GETFPREGS          14
#define PTRACE_SETFPREGS          15
#define PTRACE_GETFPXREGS         18
#define PTRACE_SETFPXREGS         19

/* e2k extentions */
#define PTRACE_PEEKPTR            0x100
#define PTRACE_POKEPTR            0x101
#define PTRACE_PEEKTAG            0x120
#define PTRACE_POKETAG            0x121
#define PTRACE_EXPAND_STACK       0x130

#define user_stack_pointer(regs)	(AS((regs)->stacks.usd_lo).base)

static inline unsigned long regs_return_value(struct pt_regs *regs)
{
	return regs->sys_rval;
}


#define from_trap(regs)		((regs)->trap != NULL)
#define from_syscall(regs)	(!from_trap(regs))

/*
 * We could check CR.pm and TIR.ip here, but that is not needed
 * because whenever CR.pm = 1 or TIR.ip < TASK_SIZE, SBR points
 * to user space. So checking SBR alone is enough.
 *
 * Testing SBR is necessary because of HW bug #59886 - the 'ct' command
 * (return to user) may be interrupted with closed interrupts.
 * The result - kernel's ip, psr.pm=1, but SBR points to user space.
 * This case should be detected as user mode.
 *
 * Checking via SBR is also useful for detecting fast system calls as
 * user mode.
 */
#define user_mode(regs)		((regs)->stacks.sbr < TASK_SIZE)

static inline int syscall_from_kernel(const struct pt_regs *regs)
{
	return from_syscall(regs) && !user_mode(regs);
}

static inline int syscall_from_user(const struct pt_regs *regs)
{
	return from_syscall(regs) && user_mode(regs);
}

static inline int trap_from_kernel(const struct pt_regs *regs)
{
	return from_trap(regs) && !user_mode(regs);
}

static inline int trap_from_user(const struct pt_regs *regs)
{
	return from_trap(regs) && user_mode(regs);
}


#define	__call_from_kernel(regs)	(AS((regs)->crs.cr1_lo).pm)
#define	__call_from_user(regs)		(!AS((regs)->crs.cr1_lo).pm)

#define	__trap_from_kernel(regs)				\
({								\
	tir_lo_struct_t tir_lo;					\
	tir_lo.TIR_lo_reg = (regs)->TIR_lo;			\
	tir_lo.TIR_lo_ip >= TASK_SIZE;				\
})
#define __trap_from_user(regs)	(!__trap_from_kernel(regs))

#define instruction_pointer(regs) (AS_STRUCT((regs)->crs.cr0_hi).ip << 3)

#ifdef	CONFIG_DEBUG_PT_REGS
#define	CHECK_PT_REGS_LOOP(regs)					\
({									\
	if ((regs) != NULL) {						\
		if ((regs)->next == (regs)) {				\
			printk("LOOP in regs list: regs 0x%p next 0x%p\n", \
				(regs), (regs)->next);			\
			print_stack(current);				\
		}							\
	}								\
})

/*
 *  The hook to find 'ct' command ( return to user)
 *  be interrapted with cloused interrupt / HARDWARE problem #59886/
 */
#define CHECK_CT_INTERRUPTED(regs)					\
({									\
	struct pt_regs *__regs = regs;					\
	do {								\
		if (__call_from_user(__regs) || __trap_from_user(__regs)) \
			break;						\
		__regs = __regs->next;					\
	} while (__regs);						\
	if (!__regs) {							\
		printk(" signal delivery started on kernel instruction"	\
		       " sbr = 0x%lx TIR_lo=0x%lx "			\
		       " crs.cr0_hi.ip << 3 = 0x%lx\n",			\
			(regs)->stacks.sbr, (regs)->TIR_lo,		\
			instruction_pointer(regs));			\
		print_stack(current);					\
	}								\
})
#else	/* ! CONFIG_DEBUG_PT_REGS */
#define	CHECK_PT_REGS_LOOP(regs)	/* nothing */
#define CHECK_CT_INTERRUPTED(regs)
#endif	/* CONFIG_DEBUG_PT_REGS */


static inline struct pt_regs *find_user_regs(const struct pt_regs *regs)
{
	do {
		CHECK_PT_REGS_LOOP(regs);

		if (user_mode(regs))
			break;

		regs = regs->next;
	} while (regs);

	return (struct pt_regs *) regs;
}

/*
 * Finds the first pt_regs corresponding to the kernel entry
 * (i.e. user mode pt_regs) if this is a user thread.
 *
 * Finds the first pt_regs structure if this is a kernel thread.
 */
static inline struct pt_regs *find_entry_regs(const struct pt_regs *regs)
{
	const struct pt_regs *prev_regs;

	do {
		CHECK_PT_REGS_LOOP(regs);

		if (user_mode(regs))
			goto found;

		prev_regs = regs;
		regs = regs->next;
	} while (regs);

	/* Return the first pt_regs structure for kernel threads */
	regs = prev_regs;

found:
	return (struct pt_regs *) regs;
}

static inline struct pt_regs *find_trap_regs(const struct pt_regs *regs)
{
	while (regs) {
		CHECK_PT_REGS_LOOP(regs);

		if (from_trap(regs))
			break;

		regs = regs->next;
	};

	return (struct pt_regs *) regs;
}


#if defined(CONFIG_SMP)
extern unsigned long profile_pc(struct pt_regs *regs);
#else
#define profile_pc(regs) instruction_pointer(regs)
#endif
extern void show_regs(struct pt_regs *);
extern int syscall_trace_entry(struct pt_regs *regs);
extern void syscall_trace_leave(struct pt_regs *regs);

#endif /* __ASSEMBLY__ */
#endif /* _E2K_PTRACE_H */
