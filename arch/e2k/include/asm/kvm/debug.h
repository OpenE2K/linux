/*
 * KVM guest kernel processes support
 * Copyright 2011 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_KVM_DEBUG_H
#define _E2K_KVM_DEBUG_H

/* do not include this header directly, only through asm/e2k_debug.h */

#include <linux/types.h>

/*
 * Some definitions to print/dump/show stacks
 */

extern e2k_addr_t kvm_get_guest_phys_addr(struct task_struct *task,
						e2k_addr_t virt);
extern void kvm_print_all_vm_stacks(void);
extern void kvm_print_vcpu_stack(struct kvm_vcpu *vcpu);
extern void kvm_dump_guest_stack(struct task_struct *task,
			stack_regs_t *const regs, bool show_reg_window);

#define	IS_GUEST_USER_ADDR(task, addr)	\
		(((e2k_addr_t)(addr)) < GUEST_TASK_SIZE)
#define	GUEST_GET_PHYS_ADDR(task, addr)	\
({									\
	e2k_addr_t phys;						\
	if (IS_GUEST_USER_ADDR(task, addr))				\
		phys = (unsigned long)user_address_to_pva(task, addr);	\
	else								\
		phys = (unsigned long)kernel_address_to_pva(addr);	\
	phys;								\
})

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel */
#include <asm/kvm/guest/debug.h>
#else	/* CONFIG_VIRTUALIZATION && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native host kernel with virtualization support */
/* or it is paravirtualized host and guest kernel */
#define GET_PHYS_ADDR(task, addr)					\
({									\
	struct thread_info *ti = task_thread_info(task);		\
	e2k_addr_t phys;						\
									\
	if (paravirt_enabled() && !IS_HV_GM()) {			\
		/* it is guest kernel or user address */		\
		phys = GUEST_GET_PHYS_ADDR(task, addr);			\
	} else if (!test_ti_thread_flag(ti, TIF_VIRTUALIZED_GUEST)) {	\
		/* it is native kernel or user process of host */	\
		phys = NATIVE_GET_PHYS_ADDR(task, addr);		\
	} else {							\
		/* it is virtual CPU process of host and it can run */	\
		/* host kernel (hypercall or trap), guest kernel */	\
		/* or guest user */					\
		phys = kvm_get_guest_phys_addr(task, addr);		\
	}								\
	phys;								\
})
#define	debug_guest_regs(task)	\
		(paravirt_enabled() && !IS_HV_GM() || \
			test_ti_thread_flag(task_thread_info(task), \
						TIF_VIRTUALIZED_GUEST))
#define	get_cpu_type_name()	\
		((paravirt_enabled()) ? "VCPU" : "CPU")

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
		stack_regs_t *const regs, bool show_reg_window)
{
	kvm_dump_guest_stack(task, regs, show_reg_window);
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

#include <asm/kvm/guest/debug.h>

/* Read instruction word (two syllables) from IP address */
static inline unsigned long
read_instr_on_IP(e2k_addr_t ip, e2k_addr_t phys_ip)
{
	if (!paravirt_enabled() || IS_HV_GM())
		return native_read_instr_on_IP(ip, phys_ip);
	else
		return kvm_read_instr_on_IP(ip, phys_ip);
}
/* Write modified instruction word at IP address */
static inline void
modify_instr_on_IP(e2k_addr_t ip, e2k_addr_t phys_ip,
				unsigned long instr_word)
{
	if (!paravirt_enabled() || IS_HV_GM())
		native_modify_instr_on_IP(ip, phys_ip, instr_word);
	else
		kvm_modify_instr_on_IP(ip, phys_ip, instr_word);
}
#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

#endif /* ! _E2K_KVM_DEBUG_H */
