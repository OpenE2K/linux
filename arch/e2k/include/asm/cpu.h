#ifndef _ASM_E2K_CPU_H_
#define _ASM_E2K_CPU_H_

#include <linux/cpu.h>

extern int arch_register_cpu(int num);
#ifdef CONFIG_HOTPLUG_CPU
extern void arch_unregister_cpu(int);
#endif

static inline unsigned long
native_get_cpu_running_cycles(void)
{
	/* native kernel is running always */
	return get_cycles();
}

extern void store_cpu_info(int cpuid);

#if	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized guest and host kernel */
#include <asm/paravirt/cpu.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/cpu.h>
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* native kernel or native kernel with virtualization support */

static inline unsigned long
get_cpu_running_cycles(void)
{
	return native_get_cpu_running_cycles();
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* _ASM_E2K_CPU_H_ */
