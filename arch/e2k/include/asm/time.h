/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

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

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/time.h>
#else	/* !CONFIG_KVM_GUEST_KERNEL */
/* native kernel with or without virtualization support */
static inline void arch_clock_init(void)
{
	native_clock_init();
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

extern void arch_clock_setup(void);

#endif /* !_E2K_TIME_H */
