#ifndef __ASM_KVM_GUEST_SMP_H
#define __ASM_KVM_GUEST_SMP_H

#include <linux/types.h>

extern void kvm_ap_switch_to_init_stack(e2k_addr_t stack_base, int cpuid,
					int cpu);
extern void kvm_setup_secondary_task(int cpu);

extern void kvm_wait_for_cpu_booting(void);
extern void kvm_wait_for_cpu_wake_up(void);
extern int kvm_activate_cpu(int cpu_id);
extern int kvm_activate_all_cpus(void);

extern void kvm_csd_lock_wait(call_single_data_t *data);
extern void kvm_csd_lock(call_single_data_t *data);
extern void kvm_arch_csd_lock_async(call_single_data_t *data);
extern void kvm_csd_unlock(call_single_data_t *data);

extern void kvm_setup_pic_virq(unsigned int cpuid);
extern void kvm_startup_pic_virq(unsigned int cpuid);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel */
static inline void
ap_switch_to_init_stack(e2k_addr_t stack_base, int cpuid, int cpu)
{
	kvm_ap_switch_to_init_stack(stack_base, cpuid, cpu);
}
static inline void setup_secondary_task(int cpu)
{
	kvm_setup_secondary_task(cpu);
}
static inline void
wait_for_cpu_booting(void)
{
	kvm_wait_for_cpu_booting();
}
static inline void
wait_for_cpu_wake_up(void)
{
	kvm_wait_for_cpu_wake_up();
}
static inline int
activate_cpu(int cpu_id)
{
	return kvm_activate_cpu(cpu_id);
}
static inline int
activate_all_cpus(void)
{
	return kvm_activate_all_cpus();
}

static inline void csd_lock_wait(call_single_data_t *data)
{
	kvm_csd_lock_wait(data);
}
static inline void csd_lock(call_single_data_t *data)
{
	kvm_csd_lock(data);
}
static inline void arch_csd_lock_async(call_single_data_t *data)
{
	kvm_arch_csd_lock_async(data);
}
static inline void csd_unlock(call_single_data_t *data)
{
	kvm_csd_unlock(data);
}

static inline void
setup_local_pic_virq(unsigned int cpuid)
{
	kvm_setup_pic_virq(cpuid);
}
static inline void
startup_local_pic_virq(unsigned int cpuid)
{
	kvm_startup_pic_virq(cpuid);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* __ASM_KVM_GUEST_SMP_H */
