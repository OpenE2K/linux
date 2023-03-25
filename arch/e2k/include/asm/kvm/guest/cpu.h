#ifndef __ASM_KVM_GUEST_CPU_H
#define __ASM_KVM_GUEST_CPU_H

#ifdef __KERNEL__

#include <linux/types.h>
#include <asm/kvm/guest.h>
#include <asm/kvm/hypervisor.h>

extern unsigned long kvm_get_cpu_running_cycles(void);

static inline bool kvm_vcpu_host_support_hw_hc(void)
{
	kvm_host_info_t *host_info;

	host_info = kvm_get_host_info();
	return host_info->support_hw_hc;
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
static inline unsigned long
get_cpu_running_cycles(void)
{
	return kvm_get_cpu_running_cycles();
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* __KERNEL__ */

#endif	/* __ASM_KVM_GUEST_CPU_H */
