#ifndef _ASM_L_SWITCH_TO_H
#define _ASM_L_SWITCH_TO_H

#ifdef __KERNEL__

#include <asm/mmu_context.h>
#include <asm/monitors.h>
#include <asm/regs_state.h>
#include <asm/sge.h>

#define DEBUG_SWITCH_MODE	0	/* switch process */
#define DebugSW(...)		DebugPrint(DEBUG_SWITCH_MODE ,##__VA_ARGS__)

extern void preempt_schedule_irq(void);

extern long __ret_from_fork(struct task_struct *prev);

/*
 * Tricks for __switch_to(), sys_clone(), sys_fork().
 * When we switch_to() to a new kernel thread or a forked process,
 * it works as follows:
 *
 * 1. __schedule() calls switch_to() (which is defined to __switch_to()
 * and is inlined) for the new task.
 *
 * 2. __switch_to() does E2K_FLUSHCPU and saves and sets the new stacks regs.
 *
 * 3. If switching to a freshly clone()d task, __switch_to() will jump
 * to __ret_from_fork() instead of returning into schedule().
 *
 * 4. When __ret_from_fork() returns there will be a FILL operation
 * and hard_sys_calls() window will be loaded into register file.
 *
 * 5. Return value of system call in child will be that of __ret_from_fork().
 */
static __always_inline
struct task_struct *__switch_to(struct task_struct *prev,
				struct task_struct *next)
{
	int cpu = raw_smp_processor_id();

	DebugSW("CPU #%d : %s(%d) -> %s(%d)\n", cpu, prev->comm, prev->pid,
		next->comm, next->pid);

	/* Save interrupt mask state and disable NMIs */
	UPSR_ALL_SAVE_AND_CLI(AW(prev->thread.sw_regs.upsr));
	AW(prev->thread.sw_regs.psr) = E2K_GET_DSREG_NV(psr);

	SAVE_TASK_REGS_TO_SWITCH(prev, 1);

	do_switch_mm(prev->active_mm, next->mm, cpu);

	set_current_thread_info(task_thread_info(next), next);

	RESTORE_TASK_REGS_TO_SWITCH(next, 1);

	if (unlikely(test_ts_flag(TS_FORK))) {
		clear_ts_flag(TS_FORK);

		/* Make sure we won't get erroneus overflow interrupt.
		 * Do this before enabling NMIs or calling any functions. */
		update_sge_checking();

		if (unlikely(test_bit(cpu,
				      current_thread_info()->need_tlb_flush))) {
			__clear_bit(cpu, current_thread_info()->need_tlb_flush);
			__flush_tlb_all();
		}

		/* Restore interrupt mask and enable NMIs */
		UPSR_RESTORE(AW(next->thread.sw_regs.upsr));

		E2K_JUMP_WITH_ARGUMENTS(__ret_from_fork, 1, prev);
	}

	/* Restore psr.sge before calling any functions */
	E2K_SET_DSREG(psr, AW(next->thread.sw_regs.psr));

	if (unlikely(test_bit(cpu, current_thread_info()->need_tlb_flush))) {
		__clear_bit(cpu, current_thread_info()->need_tlb_flush);
		__flush_tlb_all();
	}

	/* Restore interrupt mask and enable NMIs */
	UPSR_RESTORE(AW(next->thread.sw_regs.upsr));

	return prev;
}

#define switch_to(prev, next, last)		\
do {						\
	last = __switch_to(prev, next);		\
} while (0)

#define prepare_arch_switch(next)		\
do {						\
	prefetchw_range(&next->thread.sw_regs,	\
			offsetof(struct sw_regs, cs_lo)); \
        /* It works under CONFIG_MCST_RT */     \
        SAVE_CURR_TIME_SWITCH_TO;               \
	prepare_monitor_regs(next);		\
} while (0)

void queue_hw_stack_to_free(struct task_struct *task);
#define finish_arch_switch(prev) \
do { \
	CALCULATE_TIME_SWITCH_TO; \
	if (unlikely(prev->state == TASK_DEAD)) { \
		set_ts_flag(TS_FREE_HW_STACKS); \
		current_thread_info()->prev_task = prev; \
	} \
	finish_monitor_regs(prev); \
} while (0)

/*
 * We can do wake up only after the runqueue has been unlocked
 */
#define finish_arch_post_lock_switch() \
do { \
	if (unlikely(test_ts_flag(TS_FREE_HW_STACKS))) { \
		clear_ts_flag(TS_FREE_HW_STACKS); \
		queue_hw_stack_to_free(current_thread_info()->prev_task); \
	} \
} while (0)

#ifdef CONFIG_MONITORS
#define prepare_monitor_regs(next)		\
do {						\
	if (MONITORING_IS_ACTIVE)		\
		store_monitors_delta(current);	\
} while (0)
#define finish_monitor_regs(prev)					\
do {									\
	if (MONITORING_IS_ACTIVE) {					\
		AW(prev->thread.sw_regs.ddmcr) = E2K_GET_MMUREG(ddmcr);	\
		AW(prev->thread.sw_regs.dimcr) = E2K_GET_DSREG(dimcr);	\
		process_monitors(current);				\
	}								\
} while (0)
#else /* !CONFIG_MONITORS */
#define prepare_monitor_regs(next)
#define finish_monitor_regs(next)
#endif /* CONFIG_MONITORS */

#endif /* __KERNEL__ */

#endif /* _ASM_L_SWITCH_TO_H */
