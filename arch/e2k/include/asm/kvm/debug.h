/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM guest kernel processes support
 */

#ifndef _E2K_KVM_DEBUG_H
#define _E2K_KVM_DEBUG_H

/* do not include this header directly, only through asm/e2k_debug.h */

#include <linux/types.h>
#include <asm/kvm/vcpu-regs-debug-inline.h>

extern bool kvm_debug;
extern bool kvm_ftrace_dump;
extern unsigned int kvm_g_tmr;

/*
 * Some definitions to print/dump/show stacks
 */

extern e2k_addr_t kvm_get_guest_phys_addr(struct task_struct *task,
						e2k_addr_t virt);
extern void kvm_print_all_vm_stacks(void);
extern void kvm_print_vcpu_stack(struct kvm_vcpu *vcpu);
extern void kvm_dump_guest_stack(struct task_struct *task,
		stack_regs_t *const stack_regs, bool show_reg_window);

#define	IS_GUEST_USER_ADDR(task, addr)	\
		(((e2k_addr_t)(addr)) < GUEST_TASK_SIZE)

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel */
#include <asm/kvm/guest/debug.h>
#else	/* CONFIG_VIRTUALIZATION && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native host kernel with virtualization support */
/* or it is paravirtualized host and guest kernel */
#define	debug_guest_regs(task)	\
		(paravirt_enabled() && !IS_HV_GM() || \
			is_task_at_vcpu_intc_emul_mode(task))
#define	get_cpu_type_name()	\
		((paravirt_enabled()) ? "VCPU" : "CPU")

static inline void print_all_tlb(void)
{
	native_print_all_tlb();
}

static inline void print_all_guest_stacks(void)
{
	kvm_print_all_vm_stacks();
}
static inline void print_guest_vcpu_stack(struct kvm_vcpu *vcpu)
{
	kvm_print_vcpu_stack(vcpu);
}
static inline void
print_guest_stack(struct task_struct *task,
		stack_regs_t *const stack_regs, bool show_reg_window)
{
	kvm_dump_guest_stack(task, stack_regs, show_reg_window);
}
#include <asm/kvm/hypercall.h>
static inline void
host_ftrace_stop(void)
{
	if (paravirt_enabled())
		HYPERVISOR_ftrace_stop();
}
static inline void
host_ftrace_dump(void)
{
	if (paravirt_enabled())
		HYPERVISOR_ftrace_dump();
}
static inline void
host_tracing_stop(void)
{
	if (paravirt_enabled())
		HYPERVISOR_tracing_stop();
}
static inline void
host_tracing_start(void)
{
	if (paravirt_enabled())
		HYPERVISOR_tracing_start();
}

#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

#endif /* ! _E2K_KVM_DEBUG_H */
