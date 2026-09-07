/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * $Id: thread_info.h,v 1.29 2009/08/19 07:47:20 panteleev_p Exp $
 * thread_info.h: E2K low-level thread information
 *
 */
#ifndef _E2K_THREAD_INFO_H
#define _E2K_THREAD_INFO_H

#include <linux/list.h>
#include <linux/restart_block.h>
#include <linux/types.h>

#include <asm/e2k_api.h>
#include <asm/cpu_regs_types.h>
#include <asm/glob_regs.h>
#include <asm/mmu_regs_types.h>
#include <asm/types.h>
#include <asm/ptrace.h>
#include <asm/stacks.h>
#include <asm/trap_def.h>
#include <asm/cache.h>
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
#include <asm/clock_info.h>
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */
#ifdef CONFIG_PROTECTED_MODE
#include <asm/e2k_ptypes.h>
#endif

struct signal_stack {
	void __priv *base;
	unsigned long size;
	unsigned long used;
};

#ifdef	CONFIG_VIRTUALIZATION
struct	gthread_info;
#endif	/* CONFIG_VIRTUALIZATION */

typedef struct thread_info {
	unsigned long		flags;		/* low level flags */

	unsigned long		status;		/* thread synchronous flags */
	int			preempt_lazy_count;	/* 0 => lazy preemptable
							  <0 => BUG */
#ifdef CONFIG_SMP
	u32			cpu;		/* current CPU */
#endif
#ifdef SHOW_WOKEN_TIME
	long long		irq_enter_clk;	/* CPU clock when irq enter */
#endif
						/* occured */
	struct pt_regs		*pt_regs;	/* head of pt_regs */
						/* structure queue: */
						/* pointer to current */
						/* pt_regs */
	e2k_usd_t		k_usd;		/* Kernel current data stack size and base */

	/* Kernel's hardware stacks */
	e2k_psp_t		k_psp;
	e2k_pcsp_t		k_pcsp;

#ifdef CONFIG_KVM_HOST_KERNEL
	struct kernel_gregs	k_gregs_light;
#endif

	e2k_upsr_t              upsr;           /* kernel upsr */

	struct data_stack	u_stack;	/* User data stack info */
	hw_stack_t		u_hw_stack;	/* User hardware stacks info */

	/* These fields are needed only for uhws_mode = UHWS_MODE_PSEUDO */
	struct list_head	old_u_pcs_list;	/* chain stack old areas list */

	struct list_head getsp_adj;

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
	unsigned int	bc_flags;		/* special flags for binary
						 * compiler support */
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */

#ifdef CONFIG_PROTECTED_MODE
	e2k_ptr_t pm_robust_list;	/* for protected_get/set_robust_list */
#endif /* CONFIG_PROTECTED_MODE */

	/* follow fields to save guest kernel hardware stacks info to free */
	/* them after sys_execve() and switch to new process */
	void	*old_ps_base;		/* old kernel procedure stack base */
	e2k_size_t old_ps_size;		/* and size */
	void	*old_pcs_base;		/* old kernel chain stack base */
	e2k_size_t old_pcs_size;	/* and size */

	/* Support {make/get/set}context: current context goes here.
	 * On thread creation this is NULL and will be allocated as
	 * needed. */
	struct coroutine *this_hw_context;

	/* registers for ptrace */
	e2k_aalda_t	aalda[AALDAS_REGS_NUM];

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
	struct kvm_vcpu *is_vcpu;	/* process is kvm VCPU thread */
					/* but now it is not active (scheduled) */
					/* or is at vcpu-qemu mode */
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
	struct list_head tasks_to_spin;		/* only on host: list of tasks */
						/* to support spin lock/unlock */
	struct gthread_info *gti_to_spin;	/* guest thread waitin for the */
						/* spin lock/unlock */
#endif /* CONFIG_VIRTUALIZATION */
} __aligned(SMP_CACHE_BYTES) thread_info_t;

/*
 * Thread information flags:
 *
 * TIF_SYSCALL_TRACE is known to be 0 via blbs.
 */
enum {
	/* syscall trace active */
	TIF_SYSCALL_TRACE = 0,
#define TIF_SYSCALL_TRACE TIF_SYSCALL_TRACE

	/* resumption notification requested */
	TIF_NOTIFY_RESUME,
#define TIF_NOTIFY_RESUME TIF_NOTIFY_RESUME

	/* signal pending */
	TIF_SIGPENDING,
#define TIF_SIGPENDING TIF_SIGPENDING

	/* rescheduling necessary */
	TIF_NEED_RESCHED,
#define TIF_NEED_RESCHED TIF_NEED_RESCHED

	/* poll_idle is polling NEED_RESCHED */
	TIF_POLLING_NRFLAG,
#define TIF_POLLING_NRFLAG TIF_POLLING_NRFLAG

	/* 32-bit binary */
	TIF_32BIT,
#define TIF_32BIT TIF_32BIT

	TIF_MEMDIE,
#define TIF_MEMDIE TIF_MEMDIE

	/* kernel trace active */
	TIF_KERNEL_TRACE,
#define TIF_KERNEL_TRACE TIF_KERNEL_TRACE

	TIF_NOHZ,
#define TIF_NOHZ TIF_NOHZ

	/* syscall auditing active */
	TIF_SYSCALL_AUDIT,
#define TIF_SYSCALL_AUDIT TIF_SYSCALL_AUDIT

	/* secure computing */
	TIF_SECCOMP,
#define TIF_SECCOMP TIF_SECCOMP

	/* lazy rescheduling necessary */
	TIF_NEED_RESCHED_LAZY,
#define TIF_NEED_RESCHED_LAZY TIF_NEED_RESCHED_LAZY

	/* signal notifications exist */
	TIF_NOTIFY_SIGNAL,
#define TIF_NOTIFY_SIGNAL TIF_NOTIFY_SIGNAL

	/* local data stack cannot be expanded (fixed size) */
	TIF_USD_NOT_EXPANDED,

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/* the thread is ready to inject VIRQS interrupt */
	TIF_VIRQS_ACTIVE,

	/* hypervisor is executing light hypercall */
	TIF_LIGHT_HYPERCALL,

	/* hypervisor is executing generic hypercall */
	TIF_GENERIC_HYPERCALL,
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	/* syscall tracepoint instrumentation */
	TIF_SYSCALL_TRACEPOINT,

	/* napi_wq_worker() is running */
	TIF_NAPI_WORK,
};

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
#define _TIF_NEED_RESCHED_LAZY	(1 << TIF_NEED_RESCHED_LAZY)
#define _TIF_NOTIFY_SIGNAL	(1 << TIF_NOTIFY_SIGNAL)
#define	_TIF_USD_NOT_EXPANDED	(1 << TIF_USD_NOT_EXPANDED)
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#define	_TIF_VIRQS_ACTIVE	(1 << TIF_VIRQS_ACTIVE)
#define _TIF_LIGHT_HYPERCALL	(1 << TIF_LIGHT_HYPERCALL)
#define _TIF_GENERIC_HYPERCALL	(1 << TIF_GENERIC_HYPERCALL)
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
#define _TIF_SYSCALL_TRACEPOINT	(1 << TIF_SYSCALL_TRACEPOINT)
#define _TIF_NAPI_WORK		(1 << TIF_NAPI_WORK)

#define _TIF_WORK_SYSCALL_TRACE	(_TIF_SYSCALL_TRACE |		\
				 _TIF_KERNEL_TRACE |		\
				 _TIF_SYSCALL_TRACEPOINT |	\
				 _TIF_SYSCALL_AUDIT |		\
				 _TIF_SECCOMP |			\
				 _TIF_NOHZ)

/* Work to do on return to userspace with exception of _TIF_SIGPENDING. */
#define _TIF_WORK_MASK_NOSIG	(_TIF_NOTIFY_RESUME | _TIF_NOTIFY_SIGNAL | \
				 _TIF_NEED_RESCHED | _TIF_NEED_RESCHED_LAZY)

/*
 * Thread-synchronous status.
 *
 * This is different from the flags in that nobody else
 * ever touches our thread-synchronous status, so we don't
 * have to worry about atomic accesses.
 */
#define TS_MMAP_PRIVILEGED		0x00000004
#define TS_MMAP_PS			0x00000008
#define TS_MMAP_PCS			0x00000010
#define TS_MMAP_SIGNAL_STACK		0x00000020
#define TS_MMAP_CUT			0x00000040
#define TS_KERNEL_SYSCALL		0x00000080
#define TS_PTRACE_WANTS_TAG		0x00000100
#define TS_SINGLESTEP_KERNEL		0x00000200
#define TS_SINGLESTEP_USER		0x00000400
/* the host thread is switching to VCPU running mode
 * and wait for interception (trap on PV mode) */
#define	TS_HOST_AT_VCPU_MODE		0x00001000
#define	TS_HOST_TO_GUEST_USER		0x00002000
#define	TS_HOST_SWITCH_MMU_PID		0x00004000

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
/* Mark children as serving threads */
#define BC_CHILD_IS_SERVING		0x00000001
/* Thread is serving (doesn't execute x86 commands) */
#define BC_IS_SERVING			0x00000002
/* Thread should be moved to outmost ns */
#define BC_IS_OUTMOST			0x00000004
/* Thread has child serving thread in outmost ns */
#define BC_HAS_OUTMOST_CHILD		0x00000008

static __always_inline bool is_bc_outmost_thread(struct thread_info *ti)
{
	return ti->bc_flags & BC_IS_OUTMOST;
}
#endif

/*
 * flag set/clear/test wrappers
 * - pass TS_xxxx constants to these functions
 */

static __always_inline unsigned long set_ti_status_flag(struct thread_info *ti,
							unsigned long flag)
{
	unsigned long old_flags;

	old_flags = ti->status;
	ti->status = old_flags | flag;

	return ~old_flags & flag;
}

static __always_inline void clear_ti_status_flag(struct thread_info *ti,
						 unsigned long flag)
{
	ti->status &= ~flag;
}

static __always_inline unsigned long test_ti_status_flag(struct thread_info *ti,
							 unsigned long flag)
{
	return ti->status & flag;
}

static __always_inline unsigned long test_and_clear_ti_status_flag(
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
#define boot_current_thread_info()	boot_read_CURRENT_reg_value()

/*
 * Registers (%osr0/1 & %gdN) usually hold pointer to current thread info
 * structure.  But these registers used to hold CPU # while boot-time
 * initialization process
 */
#define	boot_set_current_thread_info(cpu_id) \
({ \
	boot_write_CURRENT_reg_value(cpu_id); \
	E2K_SET_DGREG_NV(CURRENT_TASK_GREG, NULL); \
})
#define thread_info_task(ti)	\
		container_of(ti, struct task_struct, thread_info)

#define INIT_OLD_U_HW_STACKS					\
	.old_u_pcs_list = LIST_HEAD_INIT(init_task.thread_info.old_u_pcs_list),

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
# define INIT_LAST_IC_FLUSH_CPU		.last_ic_flush_cpu = -1,
#else
# define INIT_LAST_IC_FLUSH_CPU
#endif

/*
 * Macros/functions for gaining access to the thread information structure.
 */
#define INIT_THREAD_INFO(tsk)				\
{							\
	INIT_OLD_U_HW_STACKS				\
	INIT_LAST_IC_FLUSH_CPU				\
	.preempt_lazy_count = 0,			\
}


extern void arch_task_cache_init(void);

/* Hardware stacks must be aligned on page boundary */
#define THREAD_ALIGN		PAGE_SIZE

/*
 * Thread information allocation.
 */

extern unsigned long *arch_alloc_thread_stack_node(struct task_struct *, int);
extern void arch_free_thread_stack(struct task_struct *tsk);
extern int free_vm_stack_cache(unsigned int cpu);

extern int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src);
extern void arch_release_task_struct(struct task_struct *tsk);

extern void arch_setup_new_exec(void);
#define arch_setup_new_exec arch_setup_new_exec

#endif /* _E2K_THREAD_INFO_H */
