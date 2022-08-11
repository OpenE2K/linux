/*
 *  based on include/asm-i386/mach-default/mach_time.h
 *
 *  Machine specific set RTC function for generic.
 *  Split out from time.c by Osamu Tomita <tomita@cinet.co.jp>
 */
#ifndef _E2K_TIME_H
#define _E2K_TIME_H

#include <linux/types.h>
#include <asm/machdep.h>

#define mach_set_wallclock(nowtime)	(machine.set_wallclock(nowtime))
#define mach_get_wallclock()		(machine.get_wallclock())

extern void native_clock_init(void);

#ifdef	CONFIG_PARAVIRT
/* It need only to account stolen time by guest */

struct static_key;
extern struct static_key paravirt_steal_enabled;
extern unsigned long native_steal_clock(int cpu);
#endif	/* CONFIG_PARAVIRT */

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/time.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized guest and host kernel */
#include <asm/paravirt/time.h>
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* native kernel with or without virtualization support */
static inline void arch_clock_init(void)
{
	native_clock_init();
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

extern void arch_clock_setup(void);

#endif /* !_E2K_TIME_H */
