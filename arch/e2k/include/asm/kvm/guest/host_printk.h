/*
 * KVM guest printk() on host support
 *
 * Copyright 2015 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_KVM_GUEST_HOST_PRINTK_H
#define _E2K_KVM_GUEST_HOST_PRINTK_H

#include <stdarg.h>
#include <linux/types.h>

extern int kvm_host_printk(const char *fmt, ...);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest */
#define	host_printk(fmt, args...)	kvm_host_printk(fmt, ##args)
#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

#endif /* ! _E2K_KVM_GUEST_HOST_PRINTK_H */
