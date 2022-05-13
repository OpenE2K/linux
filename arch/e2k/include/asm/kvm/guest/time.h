#ifndef __ASM_KVM_GUEST_TIME_H
#define __ASM_KVM_GUEST_TIME_H

#ifdef __KERNEL__
#include <linux/types.h>

extern unsigned long kvm_get_wallclock(void);
extern int kvm_set_wallclock(unsigned long now);
extern void kvm_clock_init(void);

#ifdef	CONFIG_PARAVIRT
/* FIXME: this method has support on arch-independent code */
/* so it should be main method to account steal time */

extern unsigned long kvm_steal_clock(int cpu);
#endif	/* CONFIG_PARAVIRT */

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
static inline void
arch_clock_init(void)
{
	kvm_clock_init();
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* __KERNEL__ */

#endif	/* __ASM_KVM_GUEST_TIME_H */
