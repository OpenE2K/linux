/*
 * $Id: thread_info.h,v 1.29 2009/08/19 07:47:20 panteleev_p Exp $
 * thread_info.h: E2K low-level thread information
 *
 */
#ifndef _E2K_THREAD_INFO_H
#define _E2K_THREAD_INFO_H

#ifdef __KERNEL__

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/list.h>

#include <asm/e2k_api.h>
#include <asm/cpu_regs.h>
#include <asm/3p.h>
#include <asm/mmu_regs.h>
#include <asm/stacks.h>
#include <asm/types.h>
#include <asm/traps.h>
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

typedef struct thread_info {
	struct task_struct	*task;		/* main task structure */
	unsigned long		flags;		/* low level flags */

	unsigned long		status;		/* thread synchronous flags */
#ifdef CONFIG_MCST
	long long	irq_enter_clk;	/* CPU clock when irq enter was */
#endif
	unsigned		cpu;		/* current CPU */
	int			preempt_count;	/* 0 => preemptable, <0 */
						/* => BUG */
	mm_segment_t		addr_limit;	/* thread address space */
	struct pt_regs		*pt_regs;	/* head of pt_regs */
						/* structure queue: */
						/* pointer to current */
						/* pt_regs */
	e2k_usd_hi_t		k_usd_hi;	/* Kernel current data */
						/* stack size */
	e2k_addr_t		k_stk_base;	/* Kernel data stack */
						/* bottom */
	e2k_size_t		k_stk_sz;	/* Kernel data stack */
						/* size */
	e2k_usd_lo_t		k_usd_lo;	/* Kernel current data */
						/* stack base */

	/* g16 and g17 global registers hold pointers to current in kernel. */
	u64			gbase[4];
	u16			gext[4];
	u8			tag[4];

	struct restart_block	restart_block;
	struct exec_domain	*exec_domain;	/* execution domain */
	e2k_addr_t		stack_end;	/* to write STACK_END_MAGIC */
        e2k_upsr_t              upsr;           /* kernel upsr */

	u64			u_stk_base;	/* User's C stack base */
	u64			u_stk_sz;	/* User's C stack size */
	u64			u_stk_top;	/* Top of the stack (as SBR) */

	/* These fields are needed only for uhws_mode = UHWS_MODE_PSEUDO */
	struct list_head	old_u_pcs_list;	/* chain stack old areas list */

	/*
	 * These fields are needed only for uhws_mode = UHWS_MODE_PSEUDO or
	 * uhws_mode = UHWS_MODE_DISCONT
	 */
	struct list_head	ps_list;	/* proc stack areas list */
	struct hw_stack_area	*cur_ps;	/* Current proc stack area */
	struct list_head	pcs_list;	/* chain stack areas list */
	struct hw_stack_area	*cur_pcs;	/* Current chain stack area */

	/* These fields are needed only for uhws_mode = UHWS_MODE_CONT */
	void			*ps_base;	/* procedure stack base */
	long			ps_size;	/* procedure stack total size */
	long			ps_offset;	/* Current offset of present */
						/* part of the proc stack */
	long			ps_top;		/* Current top of present */
						/* part of the proc stack */
	void			*pcs_base;	/* chain stack base */
	long			pcs_size;	/* chain stack total size */
	long			pcs_offset;	/* Current offset of present */
						/* part of the chain stack */
	long			pcs_top;	/* Current top of present */
						/* part of the chain stack */

	DECLARE_BITMAP(need_tlb_flush, NR_CPUS);

	struct vm_struct *mapped_p_stack;	/* where to map user stacks */
	struct vm_struct *mapped_pc_stack;
	struct page *mapped_p_pages[KERNEL_P_STACK_PAGES];
	struct page *mapped_pc_pages[KERNEL_PC_STACK_PAGES];

	long		usr_pfault_jump;	/* where to jump if  */
						/* copy_*_user has bad addr */
	long			pusd_pil;       /* to save pil in handle_signal */
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	int			times_index;
	long			times_num;
	kernel_times_t		times[MAX_KERNEL_TIMES_NUM];
	scall_times_t		*fork_scall_times;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT 
	u64		ss_rmp_bottom;		/* lower mremap addr for
						 * secondary space area */
	bool		sc_restart_ignore;	/* ignore system call restart
						 * in do_signal() */
	u64		rp_start;		/* recovery point range start */
	u64		rp_end;			/* recovery point range end */
	u64		rp_ret_ip;		/* recovery point return IP */
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */
	long		wtrap_jump_addr;	/* address of label where to 
						 * return to after wtrap */
#ifdef CONFIG_PROTECTED_MODE
        global_store_t  *g_list;
	unsigned long	user_stack_addr;
	size_t		user_stack_size;
	e2k_addr_t      multithread_address;    /* It needs to interpretate globals
                                                 * pointed to stack */  
        struct rw_semaphore *lock;              /* can't include  linux/rt_lock.h*/
#endif /* CONFIG_PROTECTED_MODE */
#ifdef CONFIG_MONITORS
	monitor_registers_delta_t monitors_delta;
	atomic64_t monitors_count[NR_CPUS][MONITORS_COUNT];
#endif /* CONFIG_MONITORS */
	struct list_head	tasks_to_free;	/* list of task to */
						/* delay release */
	struct list_head	hw_stacks_to_free;	/* list of task to  */
							/* delay release of */
							/* kernel hw stacks */

	/* For sys_swapcontext() - whether this thread's context was saved */
	bool			main_context_saved;
	bool			free_hw_context;
	bool			alt_stack; /*  the mark of alternative stack*/
	struct hw_context	*prev_ctx;
	struct hw_context	*next_ctx;
	void const		*ucp;
	u64			hw_context_current;

	/*  It needs some support for call's optimization  of  compat_ proc
	 *  To avoid creat and initialize pt_regs in FAST_SYS_CALL code
	 *  for frequency case (w/o expand_data_stack) we will used this fields
	 *  In this case we don't call C-code (hard_sys_call)
	 */
	e2k_usd_hi_t			u_usd_hi;
	e2k_usd_lo_t			u_usd_lo;

	/*
	 * If kernel data stack should be changed in a system call, we use these
	 * fields to store new stack's parameters. It is need for blcr module.
	 */
	e2k_addr_t	k_stk_base_new;
	e2k_size_t	k_stk_sz_new;

	struct {
		unsigned long entry;
		unsigned long sp;
	} execve;

	/* registers for ptrace */
	unsigned long long dam[DAM_ENTRIES_NUM];
	u64 gd_lo;
	u64 gd_hi;
	u64 cud_lo;
	u64 cud_hi;

	/* Functions with __interrupt attribute couldn't use kernel data stack
	 * for saving some variables, so save them in thread_info.
	 */
	e2k_ptr_t	ss_sp;

	struct task_struct *prev_task;
} thread_info_t;

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
#define	TIF_BAD_USD_SIZE	15	/* checker detected kernel USD size */
					/* is wrong */
#define	TIF_USR_CONTROL_INTERRUPTS 16	/* user can control interrupts */
#define TIF_WILL_RESCHED	24	/* task will be rescheduled soon */
#define TIF_SYSCALL_TRACEPOINT	28	/* syscall tracepoint instrumentation */

#define _TIF_SYSCALL_TRACE	(1 << TIF_SYSCALL_TRACE)
#define _TIF_NOTIFY_RESUME	(1 << TIF_NOTIFY_RESUME)
#define _TIF_SIGPENDING		(1 << TIF_SIGPENDING)
#define _TIF_POLLING_NRFLAG	(1 << TIF_POLLING_NRFLAG)
#define _TIF_NEED_RESCHED	(1 << TIF_NEED_RESCHED)
#define _TIF_32BIT		(1 << TIF_32BIT)
#define _TIF_KERNEL_TRACE	(1 << TIF_KERNEL_TRACE)
#define _TIF_NOHZ		(1 << TIF_NOHZ)
#define _TIF_SYSCALL_AUDIT	(1 << TIF_SYSCALL_AUDIT)
#define _TIF_BAD_USD_SIZE	(1 << TIF_BAD_USD_SIZE)
#define _TIF_USR_CONTROL_INTERRUPTS	(1 << TIF_USR_CONTROL_INTERRUPTS)
#define _TIF_WILL_RESCHED	(1 << TIF_WILL_RESCHED)
#define _TIF_SYSCALL_TRACEPOINT	(1 << TIF_SYSCALL_TRACEPOINT)

#define _TIF_WORK_SYSCALL_TRACE	(_TIF_SYSCALL_TRACE |		\
				 _TIF_KERNEL_TRACE |		\
				 _TIF_SYSCALL_TRACEPOINT |	\
				 _TIF_SYSCALL_AUDIT |		\
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
#define TS_HW_STACKS_EXPANDED		0x00000002
#define TS_KEEP_PAGES_VALID		0x00000004
#define TS_RESTORE_SIGMASK		0x00000008
#define TS_MMAP_PRIVILEGED		0x00000010
#define TS_MMAP_DONTEXPAND		0x00000020
#define TS_MMAP_DONTCOPY		0x00000040
#define TS_MMAP_DONTMIGRATE		0x00000080
#define TS_KERNEL_SYSCALL		0x00000100
#define TS_CLONE_BIND_TO_NODE		0x00000200
#define TS_FORK				0x00000400
#define TS_IDLE_CLONE			0x00000800
#define TS_USER_EXECVE			0x00001000
#define TS_FREE_HW_STACKS		0x00002000
#define TS_MAPPED_HW_STACKS		0x00004000
#define TS_MAPPED_HW_STACKS_INVALID	0x00008000
#define TS_KILL_ON_SYSCALL_RETURN	0x00010000
#define TS_NEW_USER_HW_STACKS		0x00020000
#define TS_MMAP_PS			0x00040000
#define TS_MMAP_PCS			0x00080000
#define TS_CLONE_MASK			0xffff000000000000UL
#define	TS_CLONE_SHIFT			48

#define TS_MMAP_HW_STACK_PS	(TS_MMAP_PRIVILEGED | TS_MMAP_DONTEXPAND | \
				 TS_MMAP_DONTCOPY | TS_MMAP_DONTMIGRATE | \
				 TS_KERNEL_SYSCALL | TS_MMAP_PS)
#define TS_MMAP_HW_STACK_PCS	(TS_MMAP_PRIVILEGED | TS_MMAP_DONTEXPAND | \
				 TS_MMAP_DONTCOPY | TS_MMAP_DONTMIGRATE | \
				 TS_KERNEL_SYSCALL | TS_MMAP_PCS)

#ifndef __ASSEMBLY__

/*
 * flag set/clear/test wrappers
 * - pass TS_xxxx constants to these functions
 */

static inline void set_ti_status_flag(struct thread_info *ti,
				      unsigned long flag)
{
	ti->status |= flag;
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

#define set_ts_flag(flag) \
	set_ti_status_flag(current_thread_info(), flag)
#define clear_ts_flag(flag) \
	clear_ti_status_flag(current_thread_info(), flag)
#define test_ts_flag(flag) \
	test_ti_status_flag(current_thread_info(), flag)


/*
 * Add unmatched brackets to make sure that
 * ts_set_clone_node() and ts_clear_clone_node()
 * are always called in pair.
 */
#define ts_set_clone_node(ti, node) \
{ \
	(ti)->status |= TS_CLONE_BIND_TO_NODE; \
	(ti)->status |= (u64) node << TS_CLONE_SHIFT;

#define ts_clear_clone_node(ti) \
	(ti)->status &= ~TS_CLONE_BIND_TO_NODE; \
}

#define ts_get_node(ti) \
({ \
	int __ts_node = NUMA_NO_NODE; \
	struct thread_info *__ts_ti = (ti); \
	if (test_ti_status_flag(__ts_ti, TS_CLONE_BIND_TO_NODE)) \
		__ts_node = (__ts_ti->status & TS_CLONE_MASK) >> \
			    TS_CLONE_SHIFT; \
	__ts_node; \
})


#ifndef CONFIG_E2S_CPU_RF_BUG
/*
 * How to get the thread information struct from C.
 * We hold current task pointer in a special system register 'OSR0'.
 */
register struct thread_info *__current_thread_info __asm__ ("%g16");

# define current_thread_info() __current_thread_info
#else
# define current_thread_info() ((struct thread_info *) E2K_GET_DSREG_NV(osr0))
#endif

static inline void
set_current_thread_info(struct thread_info *thread, struct task_struct *task)
{
	E2K_SET_DSREG_NV(osr0, thread);
	E2K_SET_DGREG_NV(16, thread);
	E2K_SET_DGREG_NV(17, task);
}

#define HAVE_SET_RESTORE_SIGMASK	1
static inline void set_restore_sigmask(void)
{
	struct thread_info *ti = current_thread_info();

	ti->status |= TS_RESTORE_SIGMASK;
	WARN_ON(!test_bit(TIF_SIGPENDING, &ti->flags));
}
static inline void clear_restore_sigmask(void)
{
	current_thread_info()->status &= ~TS_RESTORE_SIGMASK;
}
static inline bool test_restore_sigmask(void)
{
	return current_thread_info()->status & TS_RESTORE_SIGMASK;
}
static inline bool test_and_clear_restore_sigmask(void)
{
	struct thread_info *ti = current_thread_info();
	if (!(ti->status & TS_RESTORE_SIGMASK))
		return false;
	ti->status &= ~TS_RESTORE_SIGMASK;
	return true;
}


#define	PG_JMP		0xFFFFFFFFFFFFFFFFUL	/* special value for usr_pfault_jump */
						/* field. Used by put/get_user */

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

#define GET_PS_BASE(ti) \
		((UHWS_PSEUDO_MODE) ? (ti)->cur_ps->base : (ti)->ps_base)
#define GET_PS_SIZE(ti) \
		((UHWS_PSEUDO_MODE) ? (ti)->cur_ps->size : (ti)->ps_size)
#define GET_PS_OFFSET(ti) \
		((UHWS_PSEUDO_MODE) ?	\
			(ti)->cur_ps->offset : (ti)->ps_offset)
#define GET_PS_TOP(ti) \
		((UHWS_PSEUDO_MODE) ? (ti)->cur_ps->top : (ti)->ps_top)
#define GET_PCS_BASE(ti) \
		((UHWS_PSEUDO_MODE) ? (ti)->cur_pcs->base : (ti)->pcs_base)
#define GET_PCS_SIZE(ti) \
		((UHWS_PSEUDO_MODE) ? (ti)->cur_pcs->size : (ti)->pcs_size)
#define GET_PCS_OFFSET(ti) \
		((UHWS_PSEUDO_MODE) ?	\
			(ti)->cur_pcs->offset : (ti)->pcs_offset)
#define GET_PCS_TOP(ti) \
		((UHWS_PSEUDO_MODE) ? (ti)->cur_pcs->top : (ti)->pcs_top)

#define SET_PS_BASE(ti, val)					\
	do {							\
		if (UHWS_PSEUDO_MODE)				\
			(ti)->cur_ps->base = val;		\
		else						\
			(ti)->ps_base = val;			\
	} while (0)
#define SET_PS_SIZE(ti, val)					\
	do {							\
		if (UHWS_PSEUDO_MODE)				\
			(ti)->cur_ps->size = val;		\
		else						\
			(ti)->ps_size = val;			\
	} while (0)
#define SET_PS_OFFSET(ti, val)					\
	do {							\
		if (UHWS_PSEUDO_MODE)				\
			(ti)->cur_ps->offset = val;		\
		else						\
			(ti)->ps_offset = val;			\
	} while (0)
#define SET_PS_TOP(ti, val)					\
	do {							\
		if (UHWS_PSEUDO_MODE)				\
			(ti)->cur_ps->top = val;		\
		else						\
			(ti)->ps_top = val;			\
	} while (0)

#define SET_PCS_BASE(ti, val)					\
	do {							\
		if (UHWS_PSEUDO_MODE)				\
			(ti)->cur_pcs->base = val;		\
		else						\
			(ti)->pcs_base = val;			\
	} while (0)
#define SET_PCS_SIZE(ti, val)					\
	do {							\
		if (UHWS_PSEUDO_MODE)				\
			(ti)->cur_pcs->size = val;		\
		else						\
			(ti)->pcs_size = val;			\
	} while (0)
#define SET_PCS_OFFSET(ti, val)					\
	do {							\
		if (UHWS_PSEUDO_MODE)				\
			(ti)->cur_pcs->offset = val;		\
		else						\
			(ti)->pcs_offset = val;			\
	} while (0)
#define SET_PCS_TOP(ti, val)					\
	do {							\
		if (UHWS_PSEUDO_MODE)				\
			(ti)->cur_pcs->top = val;		\
		else						\
			(ti)->pcs_top = val;			\
	} while (0)

#define INIT_OLD_U_HW_STACKS					\
	.old_u_pcs_list = LIST_HEAD_INIT(init_thread_info.old_u_pcs_list),

#define INIT_U_HW_STACKS					\
	.ps_list = LIST_HEAD_INIT(init_thread_info.ps_list),	\
	.pcs_list = LIST_HEAD_INIT(init_thread_info.pcs_list),

/*
 * Macros/functions for gaining access to the thread information structure.
 *
 * preempt_count needs to be 1 initially, until the scheduler is functional.
 */
#define INIT_THREAD_INFO(tsk)			\
{						\
	.task		= &tsk,			\
	.exec_domain	= &default_exec_domain,	\
	.status		= TS_HW_STACKS_EXPANDED, /* must be set for kthreads */\
	.preempt_count	= INIT_PREEMPT_COUNT,	\
	.addr_limit	= KERNEL_DS,		\
	.restart_block = {			\
		.fn = do_no_restart_syscall,	\
	},					\
	INIT_U_HW_STACKS			\
	INIT_OLD_U_HW_STACKS			\
}

#define __HAVE_ARCH_THREAD_INFO_ALLOCATOR	1
#define	__HAVE_ARCH_TASK_STRUCT_ALLOCATOR	1
extern void __init	task_caches_init(void);
#define	arch_task_cache_init	task_caches_init

extern void free_thread(struct task_struct *task);

#define init_thread_info	(init_thread_union.thread_info)

#define KTHREAD_SIZE		(sizeof (thread_info_t) +	\
				KERNEL_C_STACK_SIZE +		\
				KERNEL_P_STACK_SIZE +		\
				KERNEL_PC_STACK_SIZE)
#define	THREAD_SIZE		KERNEL_C_STACK_SIZE

#define __HAVE_THREAD_FUNCTIONS

#ifndef ASM_OFFSETS_C
#define set_task_thread_info(task, ti)	((task)->stack = (ti))
#define task_thread_info(task)	((struct thread_info *)(task)->stack)
#define	task_stack_page(task)	(void *)(task_thread_info(task)->k_stk_base)

extern void setup_thread_stack(struct task_struct *p, struct task_struct *org);

#define end_of_stack(p)						\
	((task_thread_info(p)->k_stk_base == 0) ?			\
		&task_thread_info(p)->stack_end			\
		:						\
		(unsigned long *)(task_thread_info(p)->k_stk_base))

#else	/* ASM_OFFSETS_C */
#define task_thread_info(tsk)	((struct thread_info *) NULL)
#define	task_stack_page(task)	((void *)NULL)
#endif	/* ! ASM_OFFSETS_C */

/*
 * Thread information allocation.
 */

extern struct thread_info *alloc_thread_info_node(struct task_struct *, int);
extern void free_thread_info(struct thread_info *thread);
extern struct task_struct *alloc_task_struct_node(int);
extern void free_task_struct(struct task_struct *task);

#endif /* __ASSEMBLY__ */

#endif /* __KERNEL__ */
#endif /* _E2K_THREAD_INFO_H */
