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

#define	host_pr_alert(fmt, args...)	host_printk(fmt, ##args)
#define	host_pr_cont(fmt, args...)	host_printk(fmt, ##args)
#define	host_pr_info(fmt, args...)	host_printk(fmt, ##args)

extern void host_dump_stack(void);
extern u64 host_print_all_TIRs(const e2k_tir_t *TIRs, u64 nr_TIRs);
extern void host_print_tc_record(const trap_cellar_t *tcellar, int num);
extern void host_print_all_TC(const trap_cellar_t *TC, int TC_count);
extern void host_print_pt_regs(const struct pt_regs *regs);

#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

#endif /* ! _E2K_KVM_GUEST_HOST_PRINTK_H */
