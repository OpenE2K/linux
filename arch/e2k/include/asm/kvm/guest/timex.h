#ifndef __ASM_KVM_GUEST_TIMEX_H
#define __ASM_KVM_GUEST_TIMEX_H

#ifdef __KERNEL__
#include <linux/types.h>

extern void kvm_time_init(void);
extern int kvm_read_current_timer(unsigned long *timer_val);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
static inline void
time_init(void)
{
	kvm_time_init();
}
static inline int
read_current_timer(unsigned long *timer_val)
{
	return kvm_read_current_timer(timer_val);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* __KERNEL__ */

#endif	/* __ASM_KVM_GUEST_TIMEX_H */
