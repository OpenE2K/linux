/*
 * KVM guest printk() on host support
 *
 * Copyright 2015 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_PARAVIRT_HOST_PRINTK_H
#define _E2K_PARAVIRT_HOST_PRINTK_H

#include <stdarg.h>
#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

#define pv_host_printk(fmt, args...)	(pv_cpu_ops.host_printk(fmt, ##args))

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */
#define	host_printk(fmt, args...)	pv_host_printk(fmt, ##args)
#endif	/* ! CONFIG_PARAVIRT_GUEST */

#endif /* ! _E2K_PARAVIRT_HOST_PRINTK_H */
