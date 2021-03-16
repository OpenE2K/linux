/*
 * KVM guest kernel processes debugging support
 * Copyright 2011 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_KVM_GUEST_DEBUG_H
#define _E2K_KVM_GUEST_DEBUG_H

#include <linux/types.h>

/* Read instruction word (two syllables) from IP address */
static inline unsigned long
kvm_read_instr_on_IP(e2k_addr_t ip, e2k_addr_t phys_ip)
{
	/* guest image should be read on virtual physical IP */
	return *((u64 *)pa_to_vpa(phys_ip));
}
/* Write modified instruction word at IP address */
static inline void
kvm_modify_instr_on_IP(e2k_addr_t ip, e2k_addr_t phys_ip,
				unsigned long instr_word)
{
	/* guest image should be writed on virtual physical IP */
	*((u64 *)pa_to_vpa(phys_ip)) = instr_word;
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */

#define	GET_PHYS_ADDR(task, addr)	GUEST_GET_PHYS_ADDR(task, addr)

#define	debug_guest_regs(task)	false	/* none any guests */
#define	get_cpu_type_name()	"VCPU"	/* virtual CPU */

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

/* Read instruction word (two syllables) from IP address */
static inline unsigned long
read_instr_on_IP(e2k_addr_t ip, e2k_addr_t phys_ip)
{
	return kvm_read_instr_on_IP(ip, phys_ip);
}
/* Write modified instruction word at IP address */
static inline void
modify_instr_on_IP(e2k_addr_t ip, e2k_addr_t phys_ip,
				unsigned long instr_word)
{
	kvm_modify_instr_on_IP(ip, phys_ip, instr_word);
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* ! _E2K_KVM_GUEST_DEBUG_H */
