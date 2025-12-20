/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __E2K_SETUP_H
#define __E2K_SETUP_H

#include <linux/sched.h>
#include <uapi/asm/setup.h>
#include <asm/regs_state.h>
#include <asm/process.h>

extern void __init e2k_start_kernel(void);
extern void __init native_setup_machine(void);
extern void __init e2k_start_kernel_switched_stacks(void);

static inline void native_bsp_switch_to_init_stack(void)
{
	unsigned long stack_base = (unsigned long) &init_stack;

	NATIVE_SWITCH_TO_KERNEL_STACK(
		stack_base + KERNEL_P_STACK_OFFSET, KERNEL_P_STACK_SIZE,
		stack_base + KERNEL_PC_STACK_OFFSET, KERNEL_PC_STACK_SIZE,
		stack_base + KERNEL_C_STACK_OFFSET, KERNEL_C_STACK_SIZE - KERNEL_PT_REGS_SIZE);
}

static inline void native_setup_bsp_idle_task(int cpu)
{
	/*
	 * Set pointer of current task structure to kernel initial task
	 */
	set_current_thread_info(&init_task.thread_info, &init_task);
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/setup.h>
#else	/* !CONFIG_KVM_GUEST_KERNEL */
/* It is native host without or with virtualization support */
static inline void arch_setup_machine(void)
{
	native_setup_machine();
}
static inline void bsp_switch_to_init_stack(void)
{
	native_bsp_switch_to_init_stack();
}
static inline void setup_bsp_idle_task(int cpu)
{
	native_setup_bsp_idle_task(cpu);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#include <asm-l/setup.h>
#endif /* __E2K_SETUP_H */
