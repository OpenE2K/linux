#ifndef _ASM_E2K_KVM_GUEST_CLKR_H
#define _ASM_E2K_KVM_GUEST_CLKR_H

#include <linux/types.h>
#include <linux/clocksource.h>

extern unsigned long long kvm_sched_clock(void);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
static inline unsigned long long do_sched_clock(void)
{
	return kvm_sched_clock();
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* _ASM_E2K_KVM_GUEST_CLKR_H */
