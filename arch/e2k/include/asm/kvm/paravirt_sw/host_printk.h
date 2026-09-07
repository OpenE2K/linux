/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Guest VM printk() on host support
 */

#ifndef _E2K_KVM_HOST_PRINTK_H
#define _E2K_KVM_HOST_PRINTK_H

#include <linux/types.h>

#define	HOST_PRINTK_BUFFER_MAX	128	/* max size of buffer to print */

#ifndef	CONFIG_KVM_GUEST_KERNEL
/* it is native kernel without any virtualization or */
/* host kernel with virtualization support */
#define	host_printk(fmt, args...)	printk(fmt, ##args)

#define	host_pr_alert(fmt, args...)	pr_alert(fmt, ##args)
#define	host_pr_cont(fmt, args...)	pr_cont(fmt, ##args)
#define	host_pr_info(fmt, args...)	pr_info(fmt, ##args)

#define host_dump_stack()		dump_stack()
#define host_print_pt_regs(regs)	print_pt_regs(regs)
#define host_print_all_TIRs(TIRs, nr_TIRs)	\
		print_all_TIRs(TIRs, nr_TIRs)
#define host_print_tc_record(tcellar, num)	\
		print_tc_record(tcellar, num)
#define host_print_all_TC(TC, TC_count)		\
		print_all_TC(TC, TC_count)
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is virtualized guest kernel */
#include <asm/kvm/guest/host_printk.h>
#else
 #error "Undefined type of virtualization"
#endif	/* !CONFIG_KVM_GUEST_KERNEL */

#endif /* !_E2K_KVM_HOST_PRINTK_H */
