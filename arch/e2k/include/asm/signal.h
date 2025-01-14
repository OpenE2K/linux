#ifndef _E2K_SIGNAL_H_
#define _E2K_SIGNAL_H_

#include <uapi/asm/signal.h>


#undef	DEBUG_SIG_MODE
#undef	DebugSig
#define	DEBUG_SIG_MODE		0	/* Signal handling */
#if DEBUG_SIG_MODE
# define DebugSig printk
#else
# define DebugSig(...)
#endif

#undef	DEBUG_SLJ_MODE
#undef	DebugSLJ
#define	DEBUG_SLJ_MODE		0	/* Signal long jump handling */
#define DebugSLJ(...)		DebugPrint(DEBUG_SLJ_MODE ,##__VA_ARGS__)


#define __ARCH_HAS_SA_RESTORER

/*
 * exc_mem_lock_as can arrive at inside of a critical section since
 * it uses non-maskable interrupts,
 *
 * But in PREEMPT_RT force_sig_info() must be called with
 * enabled preemption because spinlocks are mutexes
 *
 * Fix this by delaying signal sending.
 */
#ifdef CONFIG_PREEMPT_RT
# define ARCH_RT_DELAYS_SIGNAL_SEND
#endif


#define _NSIG		64
#define _NSIG_BPW	64
#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

#define _NSIG_BPW32	32
#define _NSIG_WORDS32	(_NSIG / _NSIG_BPW32)

#include <asm-generic/signal-defs.h>
#include <asm/e2k_ptypes.h>

#include <asm/siginfo.h>
#include <asm/stacks.h>

# ifndef __ASSEMBLY__

typedef struct {
	e2k_ptr_t ss_sp;
	int ss_flags;
	size_t ss_size;
} stack_prot_t;

/* Most things should be clean enough to redefine this at will, if care
   is taken to make libc match.  */

typedef unsigned long old_sigset_t;

typedef struct {
	unsigned long sig[_NSIG_WORDS];
} sigset_t;

typedef struct prot_sigaction_old {
	e2k_pl_lo_t	sa_handler;
	u64		sa_flags;
	e2k_pl_lo_t	sa_restorer;
	sigset_t	sa_mask;
} prot_sigaction_old_t;

typedef struct prot_sigaction {
	e2k_pl_t	sa_handler;
	u64		sa_flags;
	e2k_pl_t	sa_restorer;
	sigset_t	sa_mask;
} prot_sigaction_t;

typedef union prot_sigval {
	int		sival_int;
	e2k_ptr_t	sival_ptr;
} prot_sigval_t;

#define PROT_SIGEV_MAX_SIZE 64
#define PROT_SIGEV_PAD_SIZE \
	((PROT_SIGEV_MAX_SIZE - (sizeof(int) * 2 + sizeof(prot_sigval_t))) / sizeof(int))

typedef struct prot_sigevent {
	prot_sigval_t sigev_value;
	int sigev_signo;
	int sigev_notify;
	union {
		int _pad[PROT_SIGEV_PAD_SIZE];
		int _tid;

		struct {
			e2k_ptr_t _function;
			e2k_ptr_t _attribute;
		} _sigev_thread;
	} _sigev_un;
} prot_sigevent_t;

#include <asm/sigcontext.h>

struct pt_regs;
struct siginfo;
struct ucontext;
struct as_sa_handler_arg;

#define ptrace_signal_deliver() do { } while (0)


struct signal_stack;
extern unsigned long allocate_signal_stack(unsigned long size);
extern void free_signal_stack(struct signal_stack *signal_stack);
extern struct signal_stack_context __user *
			get_the_signal_stack(struct signal_stack *signal_stack);
extern struct signal_stack_context __user *
			pop_the_signal_stack(struct signal_stack *signal_stack);
extern struct signal_stack_context __user *pop_signal_stack(void);
extern struct signal_stack_context __user *get_signal_stack(void);
extern struct signal_stack_context __user *
		get_prev_signal_stack(struct signal_stack_context __user *context);
extern int setup_signal_stack(struct pt_regs *regs, bool is_signal);
extern int reserve_signal_stack(void);

#define	GET_SIG_RESTORE_STACK(ti, sbr, usd_lo, usd_hi) \
do { \
	/* Reserve 64 bytes for kernel per C calling convention */ \
	u64 used_dstack_size = round_up(64, E2K_ALIGN_STACK); \
 \
	sbr = (u64)thread_info_task(ti)->stack + KERNEL_C_STACK_SIZE + \
						 KERNEL_C_STACK_OFFSET; \
	AW(usd_lo) = AW((ti)->k_usd_lo); \
	AW(usd_hi) = AW((ti)->k_usd_hi); \
	AS(usd_lo).base -= used_dstack_size; \
	AS(usd_hi).size -= used_dstack_size; \
} while (false)

/* The topmost dispatcher for any signals.  */
/* Implemented in arch/e2k/kernel/signal.c  */
extern void do_signal(struct pt_regs *);
extern int signal_rt_frame_setup(struct pt_regs *regs);
extern int prepare_sighandler_frame(struct e2k_stacks *stacks,
				u64 pframe[32], e2k_mem_crs_t *crs);

extern int native_signal_setup(struct pt_regs *regs);

extern int native_longjmp_copy_user_to_kernel_hw_stacks(struct pt_regs *regs,
							struct pt_regs *new_regs);

static inline int native_complete_long_jump(void)
{
	/* nithing to do for native kernel & host */
	return 0;
}

static inline void native_update_kernel_crs(e2k_mem_crs_t *k_crs,
				e2k_mem_crs_t *crs, e2k_mem_crs_t *prev_crs,
				e2k_mem_crs_t *p_prev_crs)
{
	*p_prev_crs = k_crs[0];
	k_crs[0] = *prev_crs;
	k_crs[1] = *crs;
}

static inline int native_add_ctx_signal_stack(u64 key, bool is_main)
{
	return 0;
}

static inline void native_remove_ctx_signal_stack(u64 key)
{
}

extern long do_sigreturn(void);
extern void sighandler_trampoline(void);
extern void sighandler_trampoline_continue(void);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* It is native paravirtualized guest kernel */
#include <asm/kvm/guest/signal.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* It is paravirtualized kernel (host and guest) */
#include <asm/paravirt/process.h>
#else	/* !CONFIG_KVM_GUEST_KERNEL && !CONFIG_PARAVIRT_GUEST */
/* native kernel with virtualization support */
/* native kernel without virtualization support */

static inline int signal_setup(struct pt_regs *regs)
{
	return native_signal_setup(regs);
}

static inline int longjmp_copy_user_to_kernel_hw_stacks(struct pt_regs *regs,
							struct pt_regs *new_regs)
{
	return native_longjmp_copy_user_to_kernel_hw_stacks(regs, new_regs);
}

static inline int complete_long_jump(struct pt_regs *regs, bool switch_stack,
					u64 to_key)
{
	return native_complete_long_jump();
}
static inline void update_kernel_crs(e2k_mem_crs_t *k_crs, e2k_mem_crs_t *crs,
			e2k_mem_crs_t *prev_crs, e2k_mem_crs_t *p_prev_crs)
{
	native_update_kernel_crs(k_crs, crs, prev_crs, p_prev_crs);
}
static inline int add_ctx_signal_stack(u64 key, bool is_main)
{
	return native_add_ctx_signal_stack(key, is_main);
}
static inline void remove_ctx_signal_stack(u64 key)
{
	native_remove_ctx_signal_stack(key);
}


#endif	/* CONFIG_KVM_GUEST_KERNEL */


# endif /* __ASSEMBLY__ */

#endif /* _E2K_SIGNAL_H_ */
