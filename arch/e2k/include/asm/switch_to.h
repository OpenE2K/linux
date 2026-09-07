/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_L_SWITCH_TO_H
#define _ASM_L_SWITCH_TO_H

#ifdef __KERNEL__

#include <asm/mmu_context.h>
#include <asm/regs_state.h>

extern void preempt_schedule_irq(void);

extern long __ret_from_fork(struct task_struct *prev);

static inline struct task_struct *
native_ret_from_fork_get_prev_task(struct task_struct *prev)
{
	return prev;
}

static inline int native_ret_from_fork_prepare_hv_stacks(struct pt_regs *regs)
{
	return 0;	/* nothing to do */
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/switch_to.h>
#else /* !CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without any virtualization */
/* or it is host kernel with virtualization support */

static inline struct task_struct *ret_from_fork_get_prev_task(struct task_struct *prev)
{
	return native_ret_from_fork_get_prev_task(prev);
}

static inline int ret_from_fork_prepare_hv_stacks(struct pt_regs *regs)
{
	return native_ret_from_fork_prepare_hv_stacks(regs);
}
#endif /* CONFIG_KVM_GUEST_KERNEL */

extern struct task_struct *__switch_to(struct task_struct *prev,
				       struct task_struct *next);

#define native_switch_to(prev, next, last)	\
do {						\
	last = __switch_to(prev, next);		\
	e2k_finish_switch(last);		\
} while (0)

#define prepare_arch_switch(next) prepare_arch_switch(next)
static inline void prepare_arch_switch(struct task_struct *next)
{
	prefetchr_nospec_range(&next->thread.sw_regs, offsetof(struct sw_regs, cs.lo));

	/*
	 * Protect ourselves from bad code calling schedule() or some
	 * other blocking function from inside uaccess section. Such calls
	 * _must_ _not_ be made because they will lead to risking getting
	 * a page fault from a semi-speculative load inside of a critical
	 * section in kernel scheduler.
	 *
	 * On CPU_FEAT_SVSC processors kernel executes without clearing
	 * user's mmu context so this limitation does not apply.
	 */
	WARN_ON_ONCE(!IS_ENABLED(CONFIG_KVM_GUEST_KERNEL) &&
		     !cpu_has(CPU_FEAT_SVSC) && READ_MMU_PID() != E2K_KERNEL_CONTEXT);

	SAVE_CURR_TIME_SWITCH_TO;

	/*
	 * Follow the example of RISC-V and forbid IO crossing of scheduling
	 * boundary.  The bad case is when task is preempted after writeX()
	 * and migrated to another CPU fast enough so that the CPU it was
	 * preempted on has not called any spin_unlock()'s yet.
	 *
	 * Also this waits for all exc_macp to arrive before task switch.
	 */
#if CONFIG_CPU_ISET_MIN >= 6
	/* Cannot use this on V5 because of load-after-store dependencies -
	 * compiled kernel won't honour them */
	E2K_WAIT(_st_c | _ld_c | _sas | _sal | _las | _lal | _macp);
#else
	E2K_WAIT(_st_c | _ld_c | _macp);
#endif
}

#define e2k_finish_switch(prev) \
do { \
	CALCULATE_TIME_SWITCH_TO; \
} while (0)

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/switch_to.h>
#else /* !CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without virtualization support */
/* or native kernel with virtualization support */

#define	switch_to(prev, next, last)	native_switch_to(prev, next, last)

#endif /* CONFIG_KVM_GUEST_KERNEL */

#endif /* __KERNEL__ */

#endif /* _ASM_L_SWITCH_TO_H */
