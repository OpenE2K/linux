/*
 * $Id: thread_info.h,v 1.29 2009/08/19 07:47:20 panteleev_p Exp $
 * thread_info.h: E2K low-level thread information
 *
 */
#ifndef _E2K_THREAD_INFO_H
#define _E2K_THREAD_INFO_H

#ifdef __KERNEL__

#ifndef __ASSEMBLY__
#include <linux/list.h>
#include <linux/restart_block.h>
#include <linux/types.h>

#include <asm/e2k_api.h>
#include <asm/cpu_regs_types.h>
#include <asm/glob_regs.h>
#include <asm/3p.h>
#include <asm/mmu_regs_types.h>
#include <asm/types.h>
#include <asm/ptrace.h>
#include <asm/stacks.h>
#include <asm/trap_def.h>
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
#include <asm/clock_info.h>
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
#ifdef CONFIG_MONITORS
#include <asm/monitors.h>
#endif /* CONFIG_MONITORS */
#endif	/* __ASSEMBLY__ */


#ifndef __ASSEMBLY__

typedef struct {
	unsigned long seg;
} mm_segment_t;

struct signal_stack {
	unsigned long base;
	unsigned long size;
	unsigned long used;
};

#ifdef	CONFIG_VIRTUALIZATION
struct	gthread_info;
#endif	/* CONFIG_VIRTUALIZATION */

typedef struct thread_info {
	unsigned long		flags;		/* low level flags */

	unsigned long		status;		/* thread synchronous flags */
	long long		irq_enter_clk;	/* CPU clock when irq enter */
						/* occured */
	int			preempt_count;	/* 0 => preemptable, <0 */
						/* => BUG */
	mm_segment_t		addr_limit;	/* thread address space */
	struct pt_regs		*pt_regs;	/* head of pt_regs */
						/* structure queue: */
						/* pointer to current */
						/* pt_regs */
	e2k_usd_hi_t		k_usd_hi;	/* Kernel current data */
						/* stack size */
	e2k_usd_lo_t		k_usd_lo;	/* Kernel current data */
						/* stack base */

	/* Kernel's hardware stacks */
	e2k_psp_lo_t		k_psp_lo;
	e2k_psp_hi_t		k_psp_hi;
	e2k_pcsp_lo_t		k_pcsp_lo;
	e2k_pcsp_hi_t		k_pcsp_hi;

	/* Because we don't have pt_regs ready upon kernel entry we
	 * temporarily save stack registers here, then copy to pt_regs */
	struct hw_stacks	tmp_user_stacks;
	/* Because we have to use the same kernel entry for both user
	 * and kernel interrupts, we have to save user's global registers
	 * to some temporary area, only after we copy them to pt_regs if
	 * this was user interrupt. */
	struct kernel_gregs	tmp_k_gregs;

	struct kernel_gregs	k_gregs;

	struct kernel_gregs	k_gregs_light;

	struct restart_block	restart_block;
        e2k_upsr_t              upsr;           /* kernel upsr */

	data_stack_t		u_stack;	/* User data stack info */
	hw_stack_t		u_hw_stack;	/* User hardware stacks info */

	/* These fields are needed only for uhws_mode = UHWS_MODE_PSEUDO */
	struct list_head	old_u_pcs_list;	/* chain stack old areas list */

	struct list_head getsp_adj;

	long		usr_pfault_jump;	/* where to jump if  */
						/* copy_*_user has bad addr */
	e2k_cutd_t		u_cutd;		/* Compilation Unit Table */
						/* base (register) */
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	int			times_index;
	long			times_num;
	kernel_times_t		times[MAX_KERNEL_TIMES_NUM];
	scall_times_t		*fork_scall_times;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT 
	u64		ss_rmp_bottom;		/* lower mremap addr for
						 * secondary space area */
	u64		rp_start;		/* recovery point range start */
	u64		rp_end;			/* recovery point range end */
	u64		rp_ret_ip;		/* recovery point return IP */
	int		last_ic_flush_cpu;	/* last cpu, where IC was */
						/* flushed on migration */
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */

#ifdef CONFIG_PROTECTED_MODE
        global_store_t  *g_list;
	e2k_addr_t      multithread_address;    /* It needs to interpretate globals
                                                 * pointed to stack */  
        struct rw_semaphore *lock;              /* can't include  linux/rt_lock.h*/
	long __user	*pm_robust_list;
#endif /* CONFIG_PROTECTED_MODE */
#ifdef CONFIG_MONITORS
	monitor_registers_delta_t monitors_delta;
	atomic64_t monitors_count[NR_CPUS][MONITORS_COUNT];
#endif /* CONFIG_MONITORS */

	/* follow fields to save guest kernel hardware stacks info to free */
	/* them after sys_execve() and switch to new process */
	void	*old_ps_base;		/* old kernel procedure stack base */
	e2k_size_t old_ps_size;		/* and size */
	void	*old_pcs_base;		/* old kernel chain stack base */
	e2k_size_t old_pcs_size;	/* and size */

	/* Support {make/get/set}context: current context goes here.
	 * On thread creation this is NULL and will be allocated as
	 * needed. */
	struct hw_context *this_hw_context;

	struct {
		unsigned long entry;
		unsigned long sp;
	} execve;

	/* registers for ptrace */
	unsigned long long dam[DAM_ENTRIES_NUM];
	e2k_aalda_t	aalda[AALDAS_REGS_NUM];

	bool		last_wish;
	struct ksignal	ksig;

	/* signal stack area is used to store interrupted context */
	struct signal_stack signal_stack;

#ifdef	CONFIG_VIRTUALIZATION
	pgd_t	*kernel_image_pgd_p;	/* pointer to host kernel image pgd */
	pgd_t	kernel_image_pgd;	/* host kernel image pgd value */
	pgd_t	shadow_image_pgd;	/* paravirtualized guest image shadow */
					/* pgd value */
	pgd_t	*vcpu_pgd;		/* root PGD for the VCPU */
					/* (can be NULL if need not) */
	pgd_t	*host_pgd;		/* root PGD for the host thread */
					/* (VCPU host thread mm->pgd) */
	void	*virt_machine;		/* pointer to main structure of */
					/* virtual machine for */
					/* paravirtualized guest */
	struct kvm_vcpu *vcpu;		/* KVM VCPU state for host */
	unsigned long vcpu_state_base;	/* base of VCPU state fo guest */
	int (*paravirt_page_prefault)	/* paravirtualized guest page */
					/* prefault handler */
		(pt_regs_t *regs, trap_cellar_t *tcellar);
	struct	gthread_info *gthread_info;	/* only on host: current */
						/* guest kernel thread info */
	int	gpid_nr;			/* only on guest: the guest */
						/* kernel thread ID number */
						/* on host kernel */
	int	gmmid_nr;			/* only on guest: the guest */
						/* thread mm ID number on */
						/* the host */
	struct list_head tasks_to_spin;	/* only on host: list of tasks */
					/* to support spin lock/unlock */
	struct gthread_info *gti_to_spin; /* guest thread waitin for the */
					/* spin lock/unlock */
	int	should_stop;		/* on host: guest kernel thread */
					/* should be stopped */
	/* structure to save state of user global registers, which are */
	/* used to support virtualization and PV OPs by kernel */
	host_gregs_t h_gregs;		/* state of user global registers */
					/* used by host to support guest */
					/* kernel */
#endif	/* CONFIG_VIRTUALIZATION */
} __aligned(SMP_CACHE_BYTES) thread_info_t;

#endif	/* !__ASSEMBLY__ */

/*
 * Thread information flags:
 *
 * TIF_SYSCALL_TRACE is known to be 0 via blbs.
 */
#define TIF_SYSCALL_TRACE	0	/* syscall trace active */
#define TIF_NOTIFY_RESUME	1	/* resumption notification requested */
#define TIF_SIGPENDING		2	/* signal pending */
#define TIF_NEED_RESCHED	3	/* rescheduling necessary */
#define TIF_POLLING_NRFLAG	4	/* poll_idle is polling NEED_RESCHED */
#define TIF_32BIT		5	/* 32-bit binary */
#define TIF_MEMDIE		6
#define TIF_KERNEL_TRACE        7       /* kernel trace active */
#define TIF_NOHZ		8
#define TIF_SYSCALL_AUDIT	9	/* syscall auditing active */
#define TIF_SECCOMP		10	/* secure computing */
#define	TIF_USD_NOT_EXPANDED	14	/* local data stack cannot be */
					/* expanded (fixed size) */
					/* not used yet */
#define	TIF_BAD_USD_SIZE	15	/* checker detected kernel USD size */
					/* is wrong */
#define	TIF_USR_CONTROL_INTERRUPTS 16	/* user can control interrupts */
#define TIF_WILL_RESCHED	17	/* task will be rescheduled soon */
/* Following flags only for virtualization support */
#define	TIF_VM_CREATED		19	/* task is running as virtual kernel */
					/* and created virtual machine */
#define	TIF_MULTITHREADING	20	/* task is running as multithreading */
					/* for example host/guest kernel main */
					/* threads */
#define	TIF_VIRTUALIZED_HOST	21	/* thread is host part of VCPU to run */
					/* virtualized kernel */
#define	TIF_VIRTUALIZED_GUEST	22	/* thread is guest part of VCPU */
					/* to run virtualized kernel */
#define	TIF_PARAVIRT_GUEST	23	/* user is paravitualized guest */
					/* kernel */
#define	TIF_PSEUDOTHREAD	24	/* the thread is pseudo only to run */
					/* on VIRQ VCPU as starter of VIRQ */
					/* handler */
#define	TIF_VIRQS_ACTIVE	26	/* the thread is ready to inject */
					/* VIRQS interrupt */
#define	TIF_LIGHT_HYPERCALL	28	/* hypervisor is executing light */
					/* hypercall */
#define	TIF_GENERIC_HYPERCALL	29	/* hypervisor is executing generic */
					/* hypercall */
/* End of flags only for virtualization support */
#define TIF_SYSCALL_TRACEPOINT	30	/* syscall tracepoint instrumentation */

#define _TIF_SYSCALL_TRACE	(1 << TIF_SYSCALL_TRACE)
#define _TIF_NOTIFY_RESUME	(1 << TIF_NOTIFY_RESUME)
#define _TIF_SIGPENDING		(1 << TIF_SIGPENDING)
#define _TIF_POLLING_NRFLAG	(1 << TIF_POLLING_NRFLAG)
#define _TIF_NEED_RESCHED	(1 << TIF_NEED_RESCHED)
#define _TIF_32BIT		(1 << TIF_32BIT)
#define _TIF_KERNEL_TRACE	(1 << TIF_KERNEL_TRACE)
#define _TIF_NOHZ		(1 << TIF_NOHZ)
#define _TIF_SYSCALL_AUDIT	(1 << TIF_SYSCALL_AUDIT)
#define _TIF_SECCOMP		(1 << TIF_SECCOMP)
#define	_TIF_USD_NOT_EXPANDED	(1 << TIF_USD_NOT_EXPANDED)
#define _TIF_BAD_USD_SIZE	(1 << TIF_BAD_USD_SIZE)
#define _TIF_USR_CONTROL_INTERRUPTS	(1 << TIF_USR_CONTROL_INTERRUPTS)
#define _TIF_WILL_RESCHED	(1 << TIF_WILL_RESCHED)
#define _TIF_VM_CREATED		(1 << TIF_VM_CREATED)
#define _TIF_MULTITHREADING	(1 << TIF_MULTITHREADING)
#define _TIF_VIRTUALIZED_HOST	(1 << TIF_VIRTUALIZED_HOST)
#define _TIF_VIRTUALIZED_GUEST	(1 << TIF_VIRTUALIZED_GUEST)
#define _TIF_PARAVIRT_GUEST	(1 << TIF_PARAVIRT_GUEST)
#define _TIF_PSEUDOTHREAD	(1 << TIF_PSEUDOTHREAD)
#define	_TIF_VIRQS_ACTIVE	(1 << TIF_VIRQS_ACTIVE)
#define _TIF_LIGHT_HYPERCALL	(1 << TIF_LIGHT_HYPERCALL)
#define _TIF_GENERIC_HYPERCALL	(1 << TIF_GENERIC_HYPERCALL)
#define _TIF_SYSCALL_TRACEPOINT	(1 << TIF_SYSCALL_TRACEPOINT)

#define _TIF_WORK_SYSCALL_TRACE	(_TIF_SYSCALL_TRACE |		\
				 _TIF_KERNEL_TRACE |		\
				 _TIF_SYSCALL_TRACEPOINT |	\
				 _TIF_SYSCALL_AUDIT |		\
				 _TIF_SECCOMP |			\
				 _TIF_NOHZ)

/* Work to do on return to userspace.  */
#define _TIF_WORK_MASK		(_TIF_NOTIFY_RESUME |	\
				 _TIF_SIGPENDING |	\
				 _TIF_NEED_RESCHED)

/* Work to do on return to userspace with exception of signals.
 * This is used when it is not enough to check _TIF_SIGPENDING. */
#define _TIF_WORK_MASK_NOSIG	(_TIF_NOTIFY_RESUME |	\
				 _TIF_NEED_RESCHED)

/*
 * Thread-synchronous status.
 *
 * This is different from the flags in that nobody else
 * ever touches our thread-synchronous status, so we don't
 * have to worry about atomic accesses.
 */
#define TS_DELAYED_SIG_HANDLING		0x00000001
#define TS_KEEP_PAGES_VALID		0x00000002
#define TS_MMAP_PRIVILEGED		0x00000004
#define TS_MMAP_PS			0x00000008
#define TS_MMAP_PCS			0x00000010
#define TS_MMAP_SIGNAL_STACK		0x00000020
#define TS_KERNEL_SYSCALL		0x00000040
#define TS_USER_EXECVE			0x00000080
#define TS_SINGLESTEP_KERNEL		0x00000100
#define TS_SINGLESTEP_USER		0x00000200
/* the host thread is switching to VCPU running mode
 * and wait for interception (trap on PV mode) */
#define	TS_HOST_AT_VCPU_MODE		0x00001000

#define	THREAD_SIZE	KERNEL_STACKS_SIZE

#ifndef __ASSEMBLY__

/*
 * flag set/clear/test wrappers
 * - pass TS_xxxx constants to these functions
 */

static inline unsigned long set_ti_status_flag(struct thread_info *ti,
					       unsigned long flag)
{
	unsigned long old_flags;

	old_flags = ti->status;
	ti->status = old_flags | flag;

	return ~old_flags & flag;
}

static inline void clear_ti_status_flag(struct thread_info *ti,
					unsigned long flag)
{
	ti->status &= ~flag;
}

static inline unsigned long test_ti_status_flag(struct thread_info *ti,
						unsigned long flag)
{
	return ti->status & flag;
}

static inline unsigned long test_and_clear_ti_status_flag(
		struct thread_info *ti, int flag)
{
	typeof(ti->status) status = ti->status;
	ti->status = status & ~flag;
	return status & flag;
}

#define set_ts_flag(flag) \
	set_ti_status_flag(current_thread_info(), flag)
#define clear_ts_flag(flag) \
	clear_ti_status_flag(current_thread_info(), flag)
#define test_ts_flag(flag) \
	test_ti_status_flag(current_thread_info(), flag)
#define test_and_clear_ts_flag(flag) \
	test_and_clear_ti_status_flag(current_thread_info(), flag)

#define native_current_thread_info()	current_thread_info()
#define boot_current_thread_info()	BOOT_READ_CURRENT_REG()

/*
 * Registers (%osr0 & %gdN) usually hold pointer to current thread info
 * structure.  But these registers used to hold CPU # while boot-time
 * initialization process
 */
#define	boot_set_current_thread_info(cpu_id) \
({ \
	BOOT_WRITE_CURRENT_REG_VALUE(cpu_id); \
	E2K_SET_DGREG_NV(CURRENT_TASK_GREG, NULL); \
})

                                        /* support multithreading for protected mode */
#define NUM_THREAD(x)  ((x)->orig_psr_lw)      /* number of threads (type = TYPE_INIT) */
#define	WAS_MULTITHREADING   (current_thread_info()->g_list \
                              && NUM_THREAD(current_thread_info()->g_list) >= 1) 

#ifdef CONFIG_PROTECTED_MODE
static inline void clear_g_list(struct thread_info *thread_info)
{
	/* These are initialized from interrupt handler when a thread
	 * writes SAP to a global variable or when creating a new thread
	 * (for details see comment in arch/e2k/3p/global_sp.c) */
	thread_info->g_list = NULL;
	thread_info->multithread_address = 0;
	thread_info->lock = NULL;
}
#else /* CONFIG_PROTECTED_MODE */
void clear_g_list(struct thread_info *thread_info) { }
#endif

#define thread_info_task(ti)	\
		container_of(ti, struct task_struct, thread_info)

#define INIT_OLD_U_HW_STACKS					\
	.old_u_pcs_list = LIST_HEAD_INIT(init_task.thread_info.old_u_pcs_list),

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
# define INIT_LAST_IC_FLUSH_CPU	.last_ic_flush_cpu = -1,
#else
# define INIT_LAST_IC_FLUSH_CPU
#endif

/*
 * Macros/functions for gaining access to the thread information structure.
 *
 * preempt_count needs to be 1 initially, until the scheduler is functional.
 */
#define INIT_THREAD_INFO(tsk)			\
{						\
	.preempt_count	= INIT_PREEMPT_COUNT,	\
	.addr_limit	= KERNEL_DS,		\
	.k_usd_lo = (e2k_usd_lo_t) { \
		.word = (unsigned long) init_stack + \
				KERNEL_C_STACK_OFFSET + KERNEL_C_STACK_SIZE, \
	}, \
	.k_usd_hi = (e2k_usd_hi_t) { \
		.fields.size = KERNEL_C_STACK_SIZE \
	}, \
	INIT_OLD_U_HW_STACKS			\
	INIT_LAST_IC_FLUSH_CPU			\
}

extern void arch_task_cache_init(void);

/* Hardware stacks must be aligned on page boundary */
#define THREAD_ALIGN		PAGE_SIZE
 
#ifndef ASM_OFFSETS_C
extern void clear_thread_info(struct task_struct *task);
#endif	/* ASM_OFFSETS_C */

/*
 * Thread information allocation.
 */

extern unsigned long *alloc_thread_stack_node(struct task_struct *, int);
extern void free_thread_stack(struct task_struct *tsk);
#endif /* __ASSEMBLY__ */

#endif /* __KERNEL__ */
#endif /* _E2K_THREAD_INFO_H */
