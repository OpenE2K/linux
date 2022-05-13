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
#ifdef CONFIG_USE_AAU
#include <asm/aau_regs.h>
#endif /* CONFIG_USE_AAU */
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
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
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

#ifdef CONFIG_GREGS_CONTEXT

typedef struct global_regs {
	struct e2k_greg g[E2K_GLOBAL_REGS_NUM];
	e2k_bgr_t bgr;
} global_regs_t;

/* Sometimes we only want to save %g16-%g31 (so called "local" gregs) */
typedef struct local_gregs {
	struct e2k_greg g[LOCAL_GREGS_NUM];
	e2k_bgr_t bgr;
} local_gregs_t;

/* gN and gN+1 global registers hold pointers to current in kernel, */
/* gN+2 and gN+3 are used for per-cpu data pointer and current cpu id. */
/* Now N = 16 (see real numbers at asm/glob_regs.h) */
typedef struct kernel_gregs {
	struct e2k_greg g[KERNEL_GREGS_NUM];
} kernel_gregs_t;
#endif	/* CONFIG_GREGS_CONTEXT */

#define HW_TC_SIZE 7

/* trap_pt_regs->flags */
#define TRAP_PCSP_FILL_ADJUSTED		0x0001
#define TRAP_PSP_FILL_ADJUSTED		0x0002
#define TRAP_SRP_FLAG			0x0004
#define TRAP_RP_FLAG			0x0008

typedef struct trap_pt_regs {
	u64		TIR_hi;		/* Trap info registers */
	u64		TIR_lo;
	int		TIR_no;		/* current handled TIRs # */
	s8		nr_TIRs;
	s8		tc_count;
	s8		curr_cnt;
	char		ignore_user_tc;
	char		tc_called;
	char		from_sigreturn;
	bool		is_intc;		/* intercept page fault */
	u8		nr_trap;		/* number of trap */
	u8		nr_page_fault_exc;	/* number of page fault trap */
	int		prev_state;
	int		flags;
	e2k_addr_t	srp_ip;
	e2k_tir_t	TIRs[TIR_NUM];
	trap_cellar_t	tcellar[HW_TC_SIZE];
	u64 *sbbp;
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	e2k_mlt_t	mlt_state;	  /* MLT state for binco */
#endif
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
		/* Used to distinguish between entry8 and entry10 for protected syscalls */
		u32 protected_entry10	: 1;
		/* From hardware guest interception */
		u32 kvm_hw_intercept	: 1;
		/* trap or system call is on or from guest */
		u32 trap_as_intc_emul	: 1;
		/* Trap occurred in light hypercall */
		u32 light_hypercall	: 1;
	};
	u32 word;
};

typedef	struct pt_regs {
	struct pt_regs	*next;		/* the previous regs structure */
	struct trap_pt_regs *trap;
#ifdef CONFIG_USE_AAU
	e2k_aau_t	*aau_context;	/* aau registers */
#endif
	e2k_stacks_t	stacks;		/* current state of all stacks */
					/* registers */
	e2k_mem_crs_t	crs;		/* current chain window regs state */
	e2k_wd_t	wd;		/* current window descriptor	*/
	int		sys_num;	/* to restart sys_call		*/
	int		kernel_entry;
	union pt_regs_flags flags;
	e2k_aasr_t	aasr;
	e2k_ctpr_t	ctpr1;		/* CTPRj for control transfer */
	e2k_ctpr_t	ctpr2;
	e2k_ctpr_t	ctpr3;
	e2k_ctpr_hi_t	ctpr1_hi;
	e2k_ctpr_hi_t	ctpr2_hi;
	e2k_ctpr_hi_t	ctpr3_hi;
	u64		lsr;		/* loops */
	u64		ilcr;		/* initial loop value */
	u64		lsr1;
	u64		ilcr1;
	int		interrupt_vector;
#ifdef	CONFIG_EPIC
	unsigned int	epic_core_priority;
#endif
	long		sys_rval;
	long		args[13]; /* unused, arg1, ... arg12 */
	long		tags;
	long		rval1;
	long		rval2;
	int		return_desk;
	int		rv1_tag;
	int		rv2_tag;
#ifdef	CONFIG_CLW_ENABLE
	int		clw_cpu;
	int		clw_count;
	int		clw_first;
	clw_reg_t	us_cl_m[CLW_MASK_WORD_NUM];
	clw_reg_t	us_cl_up;
	clw_reg_t	us_cl_b;
#endif	/* CONFIG_CLW_ENABLE */
        /* for bin_comp */
        u64             rpr_lo; 
        u64             rpr_hi; 
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
	bool		in_fast_syscall;/* guest issues fast system call and */
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
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* CONFIG_VIRTUALIZATION */

#if	defined(CONFIG_KVM) || defined(CONFIG_KVM_GUEST_KERNEL)
	e2k_svd_gregs_t	guest_vcpu_state_greg;
#endif	/* CONFIG_KVM || CONFIG_KVM_GUEST_KERNEL */

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	scall_times_t	*scall_times;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
} pt_regs_t;

static inline struct trap_pt_regs *
pt_regs_to_trap_regs(struct pt_regs *regs)
{
	return PTR_ALIGN((void *) regs + sizeof(*regs), 8);
}

static inline bool
is_sys_call_pt_regs(struct pt_regs *regs)
{
	return regs->trap == NULL && regs->kernel_entry != 0;
}
static inline bool
is_trap_pt_regs(struct pt_regs *regs)
{
	return regs->trap != NULL && regs->kernel_entry == 0;
}

typedef struct sw_regs {
	e2k_mem_crs_t crs;
	e2k_addr_t	top;		/* top of all user data stacks */
	e2k_usd_lo_t	usd_lo;
	e2k_usd_hi_t	usd_hi;
	e2k_psp_lo_t	psp_lo;	 	/* procedure stack pointer(as empty)*/
	e2k_psp_hi_t 	psp_hi;	 	 
	e2k_pcsp_lo_t 	pcsp_lo; 	/* procedure chaine stack pointer   */
	e2k_pcsp_hi_t 	pcsp_hi; 	/* (as empty)		    	    */
	e2k_upsr_t	upsr;
	e2k_fpcr_t	fpcr;
	e2k_fpsr_t	fpsr;
	e2k_pfpfr_t	pfpfr;
	e2k_cutd_t	cutd;

#ifdef	CONFIG_VIRTUALIZATION
	struct task_struct *prev_task;	/* task switch to current from */
#endif	/* CONFIG_VIRTUALIZATION */

#ifdef CONFIG_GREGS_CONTEXT
	struct global_regs gregs;
#endif

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

	u64		dimar0;
	u64		dimar1;
	e2k_dimcr_t	dimcr;
	u64		ddmar0;
	u64		ddmar1;
	e2k_ddmcr_t	ddmcr;
	e2k_dimtp_t	dimtp;

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
} sw_regs_t;

typedef struct jmp_info {
   u64 sigmask;
   u64 ip;
   u64 cr1lo;
   u64 pcsplo;
   u64 pcsphi;
   u32 pcshtp;
   u32 br;
   u64 usd_lo;
   u32 reserved;
   u32 wd_hi32;
} e2k_jmp_info_t;

#define	__HAVE_ARCH_KSTACK_END

static inline int kstack_end(void *addr)
{
	return (e2k_addr_t)addr >= READ_SBR_REG_VALUE();
}

#define	NATIVE_SAVE_DAM(__dam) \
do { \
	int i; \
	e2k_addr_t addr = (REG_DAM_TYPE << REG_DAM_TYPE_SHIFT); \
	for (i = 0; i < DAM_ENTRIES_NUM; i++) \
		(__dam)[i] = NATIVE_READ_DAM_REG(addr | \
					(i << REG_DAM_N_SHIFT)); \
} while (0)

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
	e2k_usd_lo_t usd_lo = regs->stacks.usd_lo;
	u64 sp;

	if (!AS(usd_lo).p) {
		sp = AS(usd_lo).base;
	} else {
		e2k_pusd_lo_t pusd_lo;
		AW(pusd_lo) = AW(usd_lo);
		sp = AS(pusd_lo).base + (regs->stacks.top & ~0xffffffffULL);
	}

	return sp;
}

static inline unsigned long kernel_stack_pointer(struct pt_regs *regs)
{
	return AS(regs->stacks.usd_lo).base;
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

#define from_trap(regs)		((regs)->trap != NULL)
#define from_syscall(regs)	(!from_trap(regs))

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
	pr_err("Address 0x%016lx is native kernel address\n",
		address);
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

/**
 * calculate_e2k_dstack_parameters - get user data stack free area parameters
 * @stacks: stack registers
 * @sp: stack pointer will be returned here
 * @stack_size: free area size will be returned here
 * @top: stack area top will be returned here
 */
static inline void calculate_e2k_dstack_parameters(
		const struct e2k_stacks *stacks,
		u64 *sp, u64 *stack_size, u64 *top)
{
	e2k_usd_lo_t usd_lo = stacks->usd_lo;
	e2k_usd_hi_t usd_hi = stacks->usd_hi;
	unsigned long sbr = stacks->top;

	if (top)
		*top = sbr;

	if (AS(usd_lo).p) {
		e2k_pusd_lo_t pusd_lo;
		e2k_pusd_hi_t pusd_hi;
		unsigned long usbr;

		usbr = sbr & ~E2K_PROTECTED_STACK_BASE_MASK;
		AW(pusd_lo) = AW(usd_lo);
		AW(pusd_hi) = AW(usd_hi);
		*sp = usbr + (AS(pusd_lo).base & ~E2K_ALIGN_PUSTACK_MASK);
		*stack_size = AS(pusd_hi).size & ~E2K_ALIGN_PUSTACK_MASK;
	} else {
		*sp = AS(usd_lo).base;
		*stack_size = AS(usd_hi).size;
	}
}

/* virtualization support */
#include <asm/kvm/ptrace.h>

typedef struct signal_stack_context {
	struct pt_regs		regs;
	struct trap_pt_regs	trap;
	struct k_sigaction	sigact;
	e2k_aau_t		aau_regs;
#ifdef CONFIG_GREGS_CONTEXT
	struct local_gregs	l_gregs;
#endif
	u64			sbbp[SBBP_ENTRIES_NUM];
	struct pv_vcpu_ctxt	vcpu_ctxt;
} signal_stack_context_t;

#define __signal_pt_regs_last(ti) \
({ \
	struct pt_regs __user *__sig_regs; \
	if (ti->signal_stack.used) { \
		__sig_regs = &((struct signal_stack_context __user *) \
			    (ti->signal_stack.base))->regs; \
	} else { \
		__sig_regs = NULL; \
	} \
	__sig_regs; \
})
#define signal_pt_regs_last() __signal_pt_regs_last(current_thread_info())

#define signal_pt_regs_first() \
({ \
	struct pt_regs __user *__sig_regs; \
	if (current_thread_info()->signal_stack.used) { \
		__sig_regs = &((struct signal_stack_context __user *) \
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
	     __regs && (u64) __regs >= \
			     current_thread_info()->signal_stack.base; \
	     __regs = (struct pt_regs __user *) ((void *) __regs - \
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
	struct pt_regs __user *__spr_u_regs = (__u_regs); \
	struct trap_pt_regs __user *u_trap; \
 \
	if (__get_user(u_trap, &__spr_u_regs->trap)) {\
		u_trap = ERR_PTR(-EFAULT); \
	} else if (u_trap) { \
		u_trap = (struct trap_pt_regs __user *) \
				((void __user *) __spr_u_regs - \
				 offsetof(struct signal_stack_context, regs) + \
				 offsetof(struct signal_stack_context, trap)); \
	} \
	u_trap; \
})

#define arch_ptrace_stop_needed(...) (true)
/* current->thread_info->pt_regs may be zero if ptrace_stop()
 * was called from load_elf_binary() (it happens if gdb has
 * set PTRACE_O_TRACEEXEC flag). */
#define arch_ptrace_stop(...) \
do { \
	struct pt_regs *__pt_regs = current_thread_info()->pt_regs; \
	if (__pt_regs) { \
		if (!test_ts_flag(TS_USER_EXECVE)) \
			user_hw_stacks_copy_full(&__pt_regs->stacks, \
						__pt_regs, NULL); \
		SAVE_AAU_REGS_FOR_PTRACE(__pt_regs, current_thread_info()); \
		if (!paravirt_enabled()) { \
			/* FIXME: it need implement for guest kernel */ \
			NATIVE_SAVE_BINCO_REGS_FOR_PTRACE(__pt_regs); \
		} \
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
	AS(regs->crs.cr0_hi).ip = val >> 3;
}

/* IMPORTANT: this only works after parse_TIR_registers()
 * has set trap->TIR_lo. So this doesn't work for NMIs. */
static inline unsigned long get_trap_ip(const struct pt_regs *regs)
{
	e2k_tir_lo_t tir_lo;

	tir_lo.TIR_lo_reg = regs->trap->TIR_lo;
	return tir_lo.TIR_lo_ip;
}

static inline unsigned long get_return_ip(const struct pt_regs *regs)
{
	return (unsigned long) (AS(regs->crs.cr0_hi).ip << 3);
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
		if ((bottom) < TASK_SIZE)						\
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
		       " crs.cr0_hi.ip << 3 = 0x%lx\n",			\
			(regs)->stacks.top, (regs)->TIR_lo,		\
			instruction_pointer(regs));			\
		dump_stack();						\
	}								\
})
#else	/* ! CONFIG_DEBUG_PT_REGS */
#define	CHECK_PT_REGS_LOOP(regs)	/* nothing */
#define	CHECK_PT_REGS_CHAIN(regs, bottom, top)
#define CHECK_CT_INTERRUPTED(regs)
#endif	/* CONFIG_DEBUG_PT_REGS */

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

extern long common_ptrace(struct task_struct *child, long request, unsigned long addr,
		   unsigned long data, bool compat);

#endif /* __ASSEMBLY__ */
#endif /* _E2K_PTRACE_H */
