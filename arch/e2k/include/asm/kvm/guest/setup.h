#ifndef _ASM_KVM_GUEST_MACHDEP_H_
#define _ASM_KVM_GUEST_MACHDEP_H_

#include <linux/init.h>
#include <asm/kvm/guest/e2k_virt.h>

#ifdef	CONFIG_VIRTUALIZATION

extern void __init boot_e2k_virt_setup_arch(void);
extern void __init e2k_virt_setup_machine(void);
extern void __init kvm_bsp_switch_to_init_stack(void);
extern void kvm_setup_bsp_idle_task(int cpu);
extern void setup_guest_interface(void);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
static inline void arch_setup_machine(void)
{
	native_setup_machine();
	if (IS_HV_GM()) {
		setup_guest_interface();
		return;
	}
	e2k_virt_setup_machine();
}

static inline void bsp_switch_to_init_stack(void)
{
	kvm_bsp_switch_to_init_stack();
}

static inline void setup_bsp_idle_task(int cpu)
{
	kvm_setup_bsp_idle_task(cpu);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* CONFIG_VIRTUALIZATION */
#endif /* _ASM_KVM_GUEST_MACHDEP_H_ */
