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

#define _NSIG		64
#define _NSIG_BPW	64
#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

#define _NSIG_BPW32	32
#define _NSIG_WORDS32	(_NSIG / _NSIG_BPW32)

#define _PSIG_SIZE_	24	/* ss_sp additional fp size 3*8 */

#include <asm-generic/signal-defs.h>
#include <asm/e2k_ptypes.h>
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

/*
 * Struct sigaction32 has sizeof all fields exact as sigaction
 * of gnulibc32
 */

typedef struct {
	unsigned int sig[_NSIG_WORDS32];
} sigset32_t;

struct sigaction32 {
	u32 sa_handler;
	u32 sa_flags;
	u32 sa_restorer;
	sigset32_t sa_mask;		/* mask last for extensibility */
};
struct k_sigaction32 {
	struct sigaction32 sa;
};
typedef struct sigaction32 sigaction32_t;
typedef struct k_sigaction32 k_sigaction32_t;

#include <asm/sigcontext.h>

struct pt_regs;

#define ptrace_signal_deliver() do { } while (0)


#define _BLOCKABLE (~(sigmask(SIGKILL) | sigmask(SIGSTOP)))

#define	SDBGPRINT(message) \
do { \
	if (debug_signal) \
		pr_info("%s: IP=%p %s(pid=%d)\n", \
				message, (void *) GET_IP, \
				current->comm, current->pid); \
} while (0)

/* The topmost dispatcher for any signals.  */
/* Implemented in arch/e2k/kernel/signal.c  */
int do_signal(struct pt_regs *);

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
extern long sys_tgkill_info(int pid, int tgid, struct siginfo __user *uinfo);

#define set_delayed_signal_handling(ti) \
do { \
	set_ti_status_flag(ti, TS_DELAYED_SIG_HANDLING); \
} while (0)

#define clear_delayed_signal_handling(ti) \
do { \
	clear_ti_status_flag(ti, TS_DELAYED_SIG_HANDLING); \
} while (0)

#define test_delayed_signal_handling(p, ti) \
	(unlikely(test_ti_status_flag(ti, TS_DELAYED_SIG_HANDLING)) && \
		  !__fatal_signal_pending(p))
#else
static inline void set_delayed_signal_handling(struct thread_info *ti) { }
static inline void clear_delayed_signal_handling(struct thread_info *ti) { }
static inline int test_delayed_signal_handling(struct task_thread *p,
					       struct thread_info *ti)
{
	return false;
}
#endif

/*
 * Every signal takes space in kernel data stack, so we limit their number
 */
#define MAX_HANDLED_SIGS 3

# endif /* __ASSEMBLY__ */
#endif /* _E2K_SIGNAL_H_ */
