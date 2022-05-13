#ifndef __ASM_SMP_BOOT_H
#define __ASM_SMP_BOOT_H

#include <linux/types.h>

#include <asm/regs_state.h>

#ifndef ASSEMBLY

#ifdef CONFIG_SMP

extern struct task_struct *idle_tasks[NR_CPUS];

extern void e2k_start_secondary_switched_stacks(int cpuid, int cpu);
extern void native_setup_secondary_task(int cpu);

static inline void
native_ap_switch_to_init_stack(e2k_addr_t stack_base, int cpuid, int cpu)
{
	NATIVE_SWITCH_TO_KERNEL_STACK(
		stack_base + KERNEL_P_STACK_OFFSET, KERNEL_P_STACK_SIZE,
		stack_base + KERNEL_PC_STACK_OFFSET, KERNEL_PC_STACK_SIZE,
		stack_base + KERNEL_C_STACK_OFFSET, KERNEL_C_STACK_SIZE);

	E2K_JUMP_WITH_ARGUMENTS(e2k_start_secondary_switched_stacks, 2,
			cpuid, cpu);
}

#if	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/smp.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/smp.h>
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without virtualization support */
/* or native kernel with virtualization support */
static inline void
ap_switch_to_init_stack(e2k_addr_t stack_base, int cpuid, int cpu)
{
	native_ap_switch_to_init_stack(stack_base, cpuid, cpu);
}

static inline void setup_secondary_task(int cpu)
{
	native_setup_secondary_task(cpu);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* CONFIG_SMP */
#endif	/* !ASSEMBLY */
#endif	/* __ASM_SMP_BOOT_H */
