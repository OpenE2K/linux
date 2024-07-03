/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM guest kernel processes debugging support
 */

#ifndef _E2K_KVM_GUEST_DEBUG_H
#define _E2K_KVM_GUEST_DEBUG_H

#include <linux/types.h>

extern int kvm_do_parse_chain_stack(bool user, struct task_struct *p,
		parse_chain_fn_t func, void *arg, unsigned long delta_user,
		unsigned long top, unsigned long bottom);

static inline void kvm_print_all_tlb(void)
{
	HYPERVISOR_dump_tlb_state();
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */

#include <asm/kvm/vcpu-regs-debug-inline.h>

#define	debug_guest_regs(task)	false	/* none any guests */
#define	get_cpu_type_name()	"VCPU"	/* virtual CPU */

static inline void print_all_tlb(void)
{
	kvm_print_all_tlb();
}

static inline void print_address_tlb(unsigned long address)
{
	pr_err("%s(): is not yet implemented for guest kernel\n", __func__);
}

static inline void print_all_guest_stacks(void)
{
	/* nothing to do, guest has not other guest processes */
}
static inline void print_guest_vcpu_stack(struct kvm_vcpu *vcpu)
{
	/* nothing to do, guest has not other guest processes */
}
static inline void
print_guest_stack(struct task_struct *task,
		stack_regs_t *const regs, bool show_reg_window)
{
	/* nothing to do, guest has not other guest processes */
}

static inline void
host_ftrace_stop(void)
{
	HYPERVISOR_ftrace_stop();
}
static inline void
host_ftrace_dump(void)
{
	HYPERVISOR_ftrace_dump();
}
static inline void
host_tracing_stop(void)
{
	HYPERVISOR_tracing_stop();
}
static inline void
host_tracing_start(void)
{
	HYPERVISOR_tracing_start();
}

static inline int
do_parse_chain_stack(bool user, struct task_struct *p,
		parse_chain_fn_t func, void *arg, unsigned long delta_user,
		unsigned long top, unsigned long bottom)
{
	return kvm_do_parse_chain_stack(user, p, func, arg, delta_user, top, bottom);
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* ! _E2K_KVM_GUEST_DEBUG_H */
