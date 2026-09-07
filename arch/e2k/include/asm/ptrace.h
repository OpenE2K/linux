/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_PTRACE_H
#define _E2K_PTRACE_H


#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/threads.h>

#include <asm/current.h>
#endif /* __ASSEMBLY__ */

#include <asm/page.h>

#ifndef __ASSEMBLY__
#include <asm/e2k_api.h>
#include <asm/cpu_regs.h>
#include <asm/glob_regs.h>
#include <asm/stacks.h>
#include <asm/mmu_types.h>
#include <asm/mmu_regs_types.h>
#include <asm/mlt.h>
#include <asm/ptrace-abi.h>

#endif /* __ASSEMBLY__ */
#include <uapi/asm/ptrace.h>
#include <asm/pv_info.h>

#define TASK_TOP	TASK_SIZE

/*
 * User process size in MA32 mode.
 */
#define TASK32_SIZE		(0xf0000000UL)

#ifndef __ASSEMBLY__

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
#include <asm/clock_info.h>
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */
#include <asm/siginfo.h>

#include <linux/signal_types.h>

struct mm_struct;

typedef struct pt_regs ptregs_t;
typedef struct sw_regs sw_regs_t;

struct e2k_greg {
	union {
		u64 xreg[2];		/* extended register */
		struct {
			u64 base;	/* main part of value */
			u64 ext;	/* extended part of floating point */
					/* value */
		};
	};
} __aligned(16); /* must be aligned for stgdq/stqp/ldqp to work */


typedef struct e2k_gregs {
	struct e2k_greg g[E2K_GLOBAL_REGS_NUM];
	e2k_bgr_t bgr;
} e2k_global_regs_t;

/* According to user ABI registers %g0-%g15 should not be saved upon signal
 * delivery (so called "global" gregs) */
struct global_gregs {
	struct e2k_greg g[GLOBAL_GREGS_NUM];
};

/* According to user ABI registers %g16-%g31 should be saved upon signal
 * delivery (so called "local" gregs).
 *
 * And %bgr holds additinal settings for %g24-%g31. */
typedef struct local_gregs {
	struct e2k_greg g[LOCAL_GREGS_NUM];
	e2k_bgr_t bgr;
} local_gregs_t;

/* Only a part of `local_gregs` is used by kernel for scratch
 * registers (i.e. for -fglobal-regs optimization).  The other
 * part is used to hold often accessed data. */
struct scratch_gregs {
	struct e2k_greg g[LOCAL_GREGS_NUM - KERNEL_GREGS_MAX_NUM];
};

/* gN and gN+1 global registers hold pointers to current in kernel, */
/* gN+2 and gN+3 are used for per-cpu data pointer and current cpu id. */
/* Now N = 16 (see real numbers at asm/glob_regs.h) */
typedef struct kernel_gregs {
	struct e2k_greg g[KERNEL_GREGS_NUM];
} kernel_gregs_t;

#define HW_TC_SIZE 7

typedef struct trap_pt_regs {
	e2k_tir_t	TIR;		/* Trap info registers */
	int		TIR_no;		/* current handled TIRs # */
	s8		nr_TIRs;
	s8		tc_count;
	s8		curr_cnt;
	u8		nr_trap;		/* number of trap */
	u8		nr_page_fault_exc;	/* number of page fault trap */
#if IS_ENABLED(CONFIG_SOFT_PM)
	/* parse_TIR_registers calls handlers for raised exceptions one by one. */
	/* When both illegal_operand and array_bounds raised, we can skip */
	/* processed ill_op als-s when doing array_bound by saving this mask */
	u8 corrected_als_mask;
#endif /* CONFIG_SOFT_PM */
	union {
		struct {
			u16 ignore_user_tc	: 1;
			u16 tc_called		: 1;
			u16 pcsp_fill_adjusted	: 1;
			u16 psp_fill_adjusted	: 1;
			u16 srp			: 1;
			u16 rp			: 1;
			/* intercept page fault */
			u16 is_intc		: 1;
			/* set if dim_ip field has been initialized */
			u16 dim_ip_valid	: 1;
		};
		u16 flags;
	};
	int		prev_state;
	e2k_upsr_t	upsr;
	e2k_addr_t	srp_ip;
	e2k_tir_t	TIRs[TIR_NUM];
	trap_cellar_t	tcellar[HW_TC_SIZE];
	u64 sbbp[SBBP_ENTRIES_NUM];

	/* User's %bgr, %g16-%g31 are saved to thread_struct in user traps and syscalls.
	 * Kernel's %g26-g31 are saved here in kernel traps. */
	struct scratch_gregs k_gregs;

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	e2k_mlt_t mlt_state;		/* MLT state for binco */
#endif
	u64		dim_ip;
} trap_pt_regs_t;

union pt_regs_flags {
	struct {
		/* execute_mmu_operations() is working */
		u32 exec_mmu_op		: 1;
		/* nested exception appeared while
		 * execute_mmu_operations() was working */
		u32 exec_mmu_op_nested	: 1;
		/* A signal's handler will be called upon return to userspace */
		u32 sig_call_handler	: 1;
		/* System call should be restarted after signal's handler */
		u32 sig_restart_syscall	: 1;
		/* From hardware guest interception */
		u32 kvm_hw_intercept	: 1;
		/* trap or system call is on or from guest */
		u32 trap_as_intc_emul	: 1;
		/* Trap occurred in light hypercall */
		u32 light_hypercall	: 1;
	};
	u32 word;
};

/*
 * ATTENTION!!! Any change of struct user_pt_regs should be submitted
 * to debugger. Also this structure must be the same as the struct
 * in typedef from <uapi/asm/ptrace.h>
 */
struct user_pt_regs {
	/* empty */
};

typedef struct pt_regs {
	struct pt_regs	*next;		/* the previous regs structure */
	struct trap_pt_regs *trap;
	e2k_aau_t	*aau_context;	/* aau registers */
	e2k_stacks_t	stacks;		/* current state of all stacks */
					/* registers */
	e2k_mem_crs_t	crs;		/* current chain window regs state */
	e2k_wd_t	wd;		/* current window descriptor    */
	e2k_rndpr_t	rndpr;
	int		sys_num;	/* to restart sys_call          */
	int		kernel_entry;
	struct user_pt_regs user_regs;
	union		pt_regs_flags flags;
	e2k_aasr_t	aasr;
	e2k_ctpr_t	ctpr1;		/* CTPRj for control transfer */
	e2k_ctpr_t	ctpr2;
	e2k_ctpr_t	ctpr3;
	u64		lsr;		/* loops */
	u64		ilcr;		/* initial loop value */
	u64		lsr1;
	u64		ilcr1;
	/* %root_ptb/%cont should be saved in case an interrupt happens
	 * in get_user(); so they are needed only for !user_mode traps. */
	struct {
		u64 u_root_ptb;
		u64 cont;
	} uaccess;
	int		interrupt_vector;
#ifdef	CONFIG_EPIC
	unsigned int	epic_core_priority;
#endif
	long		sys_rval;
	union {
		long		dargs[12]; /* arg1, ... arg12 */
		e2k_ptr_t	qargs[6];
	};
	long		tags;
	long		rval1;
	long		rval2;
	int		return_desk;
	int		rv1_tag;
	int		rv2_tag;
#ifdef	CONFIG_CLW_ENABLE
	int		clw_cpu;
	clw_reg_t	us_cl_m[CLW_MASK_WORD_NUM];
	clw_reg_t	us_cl_up;
	clw_reg_t	us_cl_b;
#endif				/* CONFIG_CLW_ENABLE */
	/* for bin_comp */
	e2k_rpr_t	rpr;
#ifdef	CONFIG_VIRTUALIZATION
	u64		sys_func;	/* need only for guest */
	e2k_stacks_t	g_stacks;	/* current state of guest kernel */
					/* stacks registers */
	bool		g_stacks_valid;	/* the state of guest kernel stacks */
					/* registers is valid */
	bool		g_stacks_active; /* the guest kernel stacks */
					 /* registers is in active work */
	bool		stack_regs_saved; /* stack state regs was already */
					  /* saved */
	bool		need_inject;	/* flag for unconditional injection */
					/* trap to guest to avoid acces to */
					/* guest user space in trap context */
	bool		dont_inject;	/* page fault injection to the guest */
					/* is prohibited */
	bool		in_hypercall;	/* trap is occured in hypercall */
	bool		is_guest_user;	/* trap/system call on/from guest */
					/* user */
	bool		in_fast_syscall; /* guest issues fast system call and */
					 /* it is in progress */
	unsigned long	traps_to_guest;	/* mask of traps passed to guest */
					/* and are not yet handled by guest */
					/* need only for host */
#ifdef	CONFIG_KVM_GUEST_KERNEL
/* only for guest kernel */
	/* already copyed back part of guest user hardware stacks */
	/* spilled to guest kernel stacks */
	struct {
		e2k_size_t ps_size;	/* procedure stack copyed size */
		e2k_size_t pcs_size;	/* chain stack copyesd size */
		/* The frames injected to support 'signal stack' */
		/* and trampolines to return from user to kernel */
		e2k_size_t pcs_injected_frames_size;
	} copyed;
#endif /* CONFIG_KVM_GUEST_KERNEL */

#endif /* CONFIG_VIRTUALIZATION */

#if	defined(CONFIG_KVM) || defined(CONFIG_KVM_GUEST_KERNEL)
	e2k_svd_gregs_t	guest_vcpu_state_greg;
#endif /* CONFIG_KVM || CONFIG_KVM_GUEST_KERNEL */

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	scall_times_t	*scall_times;
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */
} pt_regs_t;

static inline struct trap_pt_regs *pt_regs_to_trap_regs(struct pt_regs *regs)
{
	return PTR_ALIGN((void *) regs + sizeof(*regs), 8);
}

static inline bool is_sys_call_pt_regs(struct pt_regs *regs)
{
	return regs->trap == NULL && regs->kernel_entry != 0;
}

static inline bool is_trap_pt_regs(struct pt_regs *regs)
{
	return regs->trap != NULL && regs->kernel_entry == 0;
}

typedef struct sw_regs {   /* to save/restore regs when stack switches */
	e2k_mem_crs_t	crs;
	u64		top;	/* top of all user data stacks */
	e2k_usd_t	usd;
	e2k_usincr_t	usincr;
	e2k_psp_t	psp;	/* procedure stack pointer (as empty) */
	e2k_pcsp_t	pcsp;	/* procedure chaine stack pointer (as empty) */
	e2k_psr_t	psr;
	e2k_upsr_t	upsr;
	u32		osem;
	e2k_madmr_t	madmr;
	e2k_cutd_t	cutd;
	e2k_idr_t	idr;

	struct {
		e2k_fpcr_t fpcr;
		e2k_fpsr_t fpsr;
		e2k_pfpfr_t pfpfr;
	} fpu;

#ifdef	CONFIG_VIRTUALIZATION
	struct task_struct *prev_task;	/* task switch to current from */
#endif /* CONFIG_VIRTUALIZATION */

	/* User's %g0-%g15 are saved here */
	struct global_gregs u_gregs;

	u64 uaccess_max;

	/*
	 * These two are shared by monitors and breakpoints. Monitors
	 * are accessed by userspace directly through sys_ptrace and
	 * breakpoints are accessed through CONFIG_HW_BREAKPOINT layer
	 * (i.e. ptrace does not write directly to breakpoint registers).
	 *
	 * For this reason breakpoints related registers are moved out
	 * from sw_regs as they are managed by arch-independent layer
	 * instead of arch-dependent switch_to() function. For dibsr and
	 * ddbsr only monitors-related fields are accessed in switch_to().
	 */
	e2k_dibsr_t	dibsr;
	e2k_ddbsr_t	ddbsr;

	u64		dimar[4];
	e2k_dimcr_t	dimcr, dimcr1;
	u64		ddmar[4];
	e2k_ddmcr_t	ddmcr, ddmcr1;
	e2k_dimtp_t	dimtp;

	/*
	 * in the case we switch from/to a BINCO task, we
	 * need to backup/restore these registers in task switching
	 */
	e2k_qreg_t cs;
	e2k_qreg_t ds;
	e2k_qreg_t es;
	e2k_qreg_t fs;
	e2k_qreg_t gs;
	e2k_qreg_t ss;

	/* Additional registers for BINCO */
	e2k_rpr_t	rpr;
	u64		tcd;
} sw_regs_t;

typedef struct jmp_info {
	u64 sigmask;
	u64 ip;
	u64 cr1lo;
	u64 pcsplo;
	u64 pcsphi;
	e2k_pcshtp_t pcshtp;
	u32 br;
	u64 usd_lo;
	u32 reserved;
	u32 wd_hi32;
} e2k_jmp_info_t;

#define	__HAVE_ARCH_KSTACK_END

static inline int kstack_end(void *addr)
{
	return (e2k_addr_t)addr >= read_SBR_reg().base;
}

/* Arbitrarily choose the same ptrace numbers as used by the Sparc code. */
#define PTRACE_GETREGS            12
#define PTRACE_SETREGS            13

/* e2k extentions */
#define PTRACE_PEEKPTR            0x100
#define PTRACE_POKEPTR            0x101
#define PTRACE_PEEKTAG            0x120
#define PTRACE_POKETAG            0x121
#define PTRACE_EXPAND_STACK       0x130

#define from_trap(regs)		((regs)->trap != NULL)
#define from_syscall(regs)	(!from_trap(regs))

static inline u64 user_stack_pointer(struct pt_regs *regs)
{
	e2k_usd_t usd = regs->stacks.usd;

	return USD_P(usd) ? USD_PPTR(usd) + (regs->stacks.top & ~0xffffffffULL) : USD_PTR(usd);
}

static inline unsigned long kernel_stack_pointer(struct pt_regs *regs)
{
	return USD_PTR(regs->stacks.usd);
}

static inline void native_atomic_load_osgd_to_gd(void)
{
	E2K_LOAD_OSGD_TO_GD();
}

/**
 * regs_get_kernel_stack_nth() - get Nth entry of the stack
 * @regs:       pt_regs which contains kernel stack pointer.
 * @n:          stack entry number.
 *
 * regs_get_kernel_stack_nth() returns @n th entry of the kernel stack which
 * is specified by @regs. If the @n th entry is NOT in the kernel stack,
 * this returns 0.
 */
static inline unsigned long regs_get_kernel_stack_nth(struct pt_regs *regs,
						      unsigned int n)
{
	unsigned long addr = kernel_stack_pointer(regs);

	addr += n * sizeof(unsigned long);

	if (addr >= kernel_stack_pointer(regs) && addr < regs->stacks.top)
		return *(unsigned long *) addr;
	else
		return 0;
}

/* Query offset/name of register from its name/offset */
extern int regs_query_register_offset(const char *name);
extern const char *regs_query_register_name(unsigned int offset);

#define REGS_B_REGISTER_FLAG	(1 << 30)
#define REGS_PRED_REGISTER_FLAG	(1 << 29)
#define REGS_TIR1_REGISTER_FLAG (1 << 28)

extern unsigned long regs_get_register(const struct pt_regs *regs,
				       unsigned int offset);

static inline unsigned long regs_return_value(struct pt_regs *regs)
{
	/* System call audit case: %b[0] is not ready yet */
	if (from_syscall(regs))
		return regs->sys_rval;

	/* kretprobe case - get %b[0] */
	return regs_get_register(regs, 0 | REGS_B_REGISTER_FLAG);
}

static inline e2k_addr_t
native_check_is_user_address(struct task_struct *task, e2k_addr_t address)
{
	if (likely(address < NATIVE_TASK_SIZE))
		return 0;
	pr_err("Address 0x%016lx is native kernel address\n", address);
	return -1;
}

#define	NATIVE_IS_GUEST_USER_ADDRESS_TO_PVA(task, address)	\
		false	/* native kernel has not guests */
#define	NATIVE_IS_GUEST_ADDRESS_TO_HOST(address)		\
		false	/* native kernel has not guests */

/* guest page table is pseudo PT and only host PT is used */
/* to translate any guest addresses */
static inline void
native_print_host_user_address_ptes(struct mm_struct *mm, e2k_addr_t address)
{
	/* this function is actual only for guest */
	/* native kernel can not be guest kernel */
}

/*
 * calculate_e2k_dstack_parameters - get user data stack free area parameters
 * @stacks: stack registers
 * @sp: stack pointer will be returned here
 * @stack_size: free area size will be returned here
 * @top: stack area top will be returned here
 */
static inline void calculate_e2k_dstack_parameters(const struct e2k_stacks *stacks,
						   u64 *sp, u64 *stack_size, u64 *top)
{
	e2k_usd_t usd = stacks->usd;
	unsigned long sbr = stacks->top;

	if (top)
		*top = sbr;

	if (USD_P(usd)) {
		unsigned long usbr;
		usbr = sbr & ~E2K_PROTECTED_STACK_BASE_MASK;
		*sp = usbr + USD_PPTR(usd);
		*stack_size = USD_IND(usd);
	} else {
		*sp = USD_PTR(usd);
		*stack_size = USD_IND(usd);
	}
}

/* virtualization support */
#include <asm/kvm/ptrace.h>

typedef struct signal_stack_context {
	struct pt_regs		regs;
	struct trap_pt_regs	trap;
	struct k_sigaction	sigact;
	e2k_aau_t		aau_regs;
	struct local_gregs	l_gregs;
	struct pv_vcpu_ctxt	vcpu_ctxt;
} signal_stack_context_t;

#define __signal_pt_regs_last(ti) \
({ \
	struct pt_regs __priv *__sig_regs; \
	if (ti->signal_stack.used) { \
		__sig_regs = &((struct signal_stack_context __priv *) \
			    (ti->signal_stack.base))->regs; \
	} else { \
		__sig_regs = NULL; \
	} \
	__sig_regs; \
})
#define signal_pt_regs_last() __signal_pt_regs_last(current_thread_info())

#define signal_pt_regs_first() \
({ \
	struct pt_regs __priv *__sig_regs; \
	if (current_thread_info()->signal_stack.used) { \
		__sig_regs = &((struct signal_stack_context __priv *) \
				(current_thread_info()->signal_stack.base + \
				 current_thread_info()->signal_stack.used - \
				 sizeof(struct signal_stack_context)))->regs; \
	} else { \
		__sig_regs = NULL; \
	} \
	__sig_regs; \
})

#define signal_pt_regs_for_each(__regs) \
	for (__regs = signal_pt_regs_first(); \
	     __regs && (unsigned long) __regs >= \
		       (unsigned long) current_thread_info()->signal_stack.base; \
	     __regs = (struct pt_regs __priv *) ((void __priv *) __regs - \
					sizeof(struct signal_stack_context)))

/**
 * signal_pt_regs_to_trap - to be used inside of signal_pt_regs_for_each();
 *			    will return trap_pt_regs pointer corresponding
 *			    to the passed pt_regs structure.
 * @__u_regs: pt_regs pointer returned by signal_pt_regs_for_each()
 *
 * EXAMPLE:
 *	signal_pt_regs_for_each(u_regs) {
 *		struct trap_pt_regs __user *u_trap = signal_pt_regs_to_trap(u_regs);
 *		if (IS_ERR(u_trap))
 *			;// Caught -EFAULT from get_user()
 *		if (IS_NULL(u_trap))
 *			;// Not interrupt pt_regs
 */
#define signal_pt_regs_to_trap(__u_regs) \
({ \
	struct pt_regs __priv *__spr_u_regs = (__u_regs); \
	struct trap_pt_regs __priv *u_trap; \
 \
	if (get_priv(u_trap, &__spr_u_regs->trap)) {\
		u_trap = (struct trap_pt_regs __priv *) ERR_PTR(-EFAULT); \
	} else if (u_trap) { \
		u_trap = (struct trap_pt_regs __priv *) \
				((void __priv *) __spr_u_regs - \
				 offsetof(struct signal_stack_context, regs) + \
				 offsetof(struct signal_stack_context, trap)); \
	} \
	u_trap; \
})

#define arch_ptrace_stop_needed(...) (true)
#define arch_ptrace_stop(...) \
do { \
	struct pt_regs *__pt_regs = current_thread_info()->pt_regs; \
	user_hw_stacks_copy_full(&__pt_regs->stacks, __pt_regs, NULL); \
	SAVE_AAU_REGS_FOR_PTRACE(__pt_regs, current_thread_info()); \
	if (!paravirt_enabled()) { \
		/* FIXME: it need implement for guest kernel */ \
		NATIVE_SAVE_BINCO_REGS_FOR_PTRACE(__pt_regs); \
	} \
} while (0)

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

static inline void instruction_pointer_set(struct pt_regs *regs,
					   unsigned long val)
{
	set_cr0_ip(regs->crs.cr0, val);
}

/* IMPORTANT: this only works after parse_TIR_registers()
 * has set trap->TIR_lo. So this doesn't work for NMIs. */
static inline unsigned long get_trap_ip(const struct pt_regs *regs)
{
	return regs->trap->TIR.ip;
}

static inline unsigned long get_return_ip(const struct pt_regs *regs)
{
	return get_cr0_ip(regs->crs.cr0);
}

static inline unsigned long instruction_pointer(const struct pt_regs *regs)
{
	return get_return_ip(regs);
}


#ifdef	CONFIG_DEBUG_PT_REGS
#define	CHECK_PT_REGS_LOOP(regs)						\
({										\
	if ((regs) != NULL) {							\
		if ((regs)->next == (regs)) {					\
			pr_err("LOOP in regs list: regs 0x%px next 0x%px\n",	\
				(regs), (regs)->next);				\
			dump_stack();						\
		}								\
	}									\
})
#define	CHECK_PT_REGS_CHAIN(regs, bottom, top)						\
({											\
	pt_regs_t *next_regs = (regs);							\
	pt_regs_t *prev_regs = (pt_regs_t *)(bottom);					\
	while ((next_regs) != NULL) {							\
		if (IS_USER_ADDR(bottom))						\
			break;								\
		if ((e2k_addr_t)next_regs > (e2k_addr_t)((top) - sizeof(pt_regs_t))) {	\
			pr_err("%s(): next regs %px above top 0x%llx\n",		\
				__func__, next_regs,					\
				(top) - sizeof(pt_regs_t));				\
			print_pt_regs(next_regs);					\
			WARN_ON(true);							\
		} else if ((e2k_addr_t)next_regs == (e2k_addr_t)prev_regs) {		\
			pr_err("%s(): next regs %px is same as previous %px\n",		\
				__func__, next_regs, prev_regs);			\
			print_pt_regs(next_regs);					\
			BUG_ON(true);							\
		} else if ((e2k_addr_t)next_regs < (e2k_addr_t)prev_regs) {		\
			pr_err("%s(): next regs %px below previous %px\n",		\
				__func__, next_regs, prev_regs);			\
			print_pt_regs(next_regs);					\
			BUG_ON(true);							\
		}									\
		prev_regs = next_regs;							\
		next_regs = next_regs->next;						\
	}										\
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
		       " top = 0x%lx TIR_lo=0x%lx "			\
		       " crs.cr0.ip << 3 = 0x%lx\n",			\
			(regs)->stacks.top, (regs)->TIR_lo,		\
			instruction_pointer(regs));			\
		dump_stack();						\
	}								\
})
#else /* ! CONFIG_DEBUG_PT_REGS */
#define	CHECK_PT_REGS_LOOP(regs)	/* nothing */
#define	CHECK_PT_REGS_CHAIN(regs, bottom, top)
#define CHECK_CT_INTERRUPTED(regs)
#endif /* CONFIG_DEBUG_PT_REGS */

static inline struct pt_regs *find_user_regs(const struct pt_regs *regs)
{
	do {
		CHECK_PT_REGS_LOOP(regs);

		if (user_mode(regs) && !regs->flags.kvm_hw_intercept)
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

		if (user_mode(regs) && !regs->flags.kvm_hw_intercept)
			goto found;

		prev_regs = regs;
		regs = regs->next;
	} while (regs);

	/* Return the first pt_regs structure for kernel threads */
	regs = prev_regs;

found:
	return (struct pt_regs *) regs;
}

static inline struct pt_regs *find_host_regs(const struct pt_regs *regs)
{
	while (regs) {
		CHECK_PT_REGS_LOOP(regs);

		if (likely(!regs->flags.kvm_hw_intercept))
			break;

		regs = regs->next;
	};

	return (struct pt_regs *) regs;
}

static inline struct pt_regs *find_trap_host_regs(const struct pt_regs *regs)
{
	while (regs) {
		CHECK_PT_REGS_LOOP(regs);

		if (from_trap(regs) && !regs->flags.kvm_hw_intercept)
			break;

		regs = regs->next;
	};

	return (struct pt_regs *) regs;
}

#define count_trap_regs(regs) \
({ \
	struct pt_regs *__regs = regs; \
	int traps = 0; \
	while (__regs) { \
		if (from_trap(regs)) \
			traps++; \
		__regs = __regs->next; \
	} \
	traps; \
})
#define	current_is_in_trap()	\
		(count_trap_regs(current_thread_info()->pt_regs) > 0)

#define count_user_regs(regs) \
({ \
	struct pt_regs *__regs = regs; \
	int regs_num = 0; \
	while (__regs) { \
		CHECK_PT_REGS_LOOP(__regs); \
		if (user_mode(regs)) \
			regs_num++; \
		__regs = __regs->next; \
	} \
	regs_num; \
})

#if defined(CONFIG_SMP)
extern unsigned long profile_pc(struct pt_regs *regs);
#else
#define profile_pc(regs) instruction_pointer(regs)
#endif
extern int syscall_trace_entry(struct pt_regs *regs);
extern void syscall_trace_leave(struct pt_regs *regs);

#define arch_has_single_step()	(1)

extern long common_ptrace(struct task_struct *child, long request,
			  unsigned long addr, unsigned long data, bool compat);

#endif /* __ASSEMBLY__ */
#endif /* _E2K_PTRACE_H */
