/*
 * Guest VM printk() on host support
 *
 * Copyright 2015 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_KVM_HOST_PRINTK_H
#define _E2K_KVM_HOST_PRINTK_H

#include <linux/types.h>

#define	HOST_PRINTK_BUFFER_MAX	128	/* max size of buffer to print */

#if	!defined(CONFIG_PARAVIRT_GUEST) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native host without any virtualization or */
/* native kernel with virtualization support */
#define	host_printk(fmt, args...)	printk(fmt, ##args)
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest */
#include <asm/paravirt/host_printk.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest (not virtualized based on pv_ops) */
#include <asm/kvm/guest/host_printk.h>
#else
 #error "Undefined type of virtualization"
#endif	/* ! CONFIG_PARAVIRT_GUEST  && ! CONFIG_KVM_GUEST_KERNEL */

#endif /* ! _E2K_KVM_HOST_PRINTK_H */
