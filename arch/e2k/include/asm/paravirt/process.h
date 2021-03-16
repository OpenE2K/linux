/*
 * KVM paravirtualized kernel processes support
 * Copyright 2011 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_PARAVIRT_PROCESS_H
#define _E2K_PARAVIRT_PROCESS_H

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>
#include <asm/kvm/guest/process.h>

static inline void PV_FLUSH_STACKS(void)
{
	if (!paravirt_enabled())
		native_flush_stacks();
	else
		pv_cpu_ops.flush_stacks();
}

static inline void PV_FLUSH_REGS_STACK(void)
{
	if (!paravirt_enabled())
		native_flush_regs_stack();
	else
		pv_cpu_ops.flush_regs_stack();
}

static inline void PV_FLUSH_CHAIN_STACK(void)
{
	if (!paravirt_enabled())
		native_flush_chain_stack();
	else
		pv_cpu_ops.flush_chain_stack();
}

static inline void BOOT_PV_FLUSH_STACKS(void)
{
	if (!boot_paravirt_enabled())
		native_flush_stacks();
	else
		BOOT_PARAVIRT_FLUSH(flush_stacks);
}

static inline void BOOT_PV_FLUSH_REGS_STACK(void)
{
	if (!boot_paravirt_enabled())
		native_flush_regs_stack();
	else
		BOOT_PARAVIRT_FLUSH(flush_regs_stack);
}

static inline void BOOT_PV_FLUSH_CHAIN_STACK(void)
{
	if (!boot_paravirt_enabled())
		native_flush_chain_stack();
	else
		BOOT_PARAVIRT_FLUSH(flush_chain_stack);
}

static inline void PV_COPY_STACKS_TO_MEMORY(void)
{
	pv_cpu_ops.copy_stacks_to_memory();
}

#define	PV_FLUSHCPU	PV_FLUSH_STACKS()
#define	PV_FLUSHR	PV_FLUSH_REGS_STACK()
#define	PV_FLUSHC	PV_FLUSH_CHAIN_STACK()

/* see arch/e2k/include/asm/process.h for more details why and how */
#define	PV_UPDATE_VCPU_THREAD_CONTEXT(__task, __ti, __regs, __gti, __vcpu) \
({ \
	if (paravirt_enabled()) { \
		KVM_GUEST_UPDATE_VCPU_THREAD_CONTEXT(__task, __ti, __regs, \
							__gti, __vcpu); \
	} else { \
		KVM_HOST_UPDATE_VCPU_THREAD_CONTEXT(__task, __ti, __regs, \
							__gti, __vcpu); \
	} \
})
#define	PV_CHECK_VCPU_THREAD_CONTEXT(__ti)	\
({ \
	if (paravirt_enabled()) { \
		KVM_GUEST_CHECK_VCPU_THREAD_CONTEXT(__ti); \
	} else { \
		KVM_HOST_CHECK_VCPU_THREAD_CONTEXT(__ti); \
	} \
})

#define	PV_ONLY_SET_GUEST_GREGS(__ti)	\
({ \
	if (paravirt_enabled()) { \
		KVM_ONLY_SET_GUEST_GREGS(__ti); \
	} else { \
		NATIVE_ONLY_SET_GUEST_GREGS(__ti); \
	} \
})

static inline void
pv_virt_cpu_thread_init(struct task_struct *boot_task)
{
	if (pv_cpu_ops.virt_cpu_thread_init)
		pv_cpu_ops.virt_cpu_thread_init(boot_task);
}

static inline int
pv_copy_kernel_stacks(struct task_struct *new_task,
			unsigned long fn, unsigned long arg)
{
	return pv_cpu_ops.copy_kernel_stacks(new_task, fn, arg);
}

static inline int
pv_copy_user_stacks(unsigned long clone_flags,
			e2k_addr_t new_stk_base, e2k_size_t new_stk_sz,
			struct task_struct *new_task, struct pt_regs *regs)
{
	return pv_cpu_ops.copy_user_stacks(clone_flags,
			new_stk_base, new_stk_sz, new_task, regs);
}

static inline void
pv_define_kernel_hw_stacks_sizes(struct hw_stack *hw_stacks)
{
	pv_cpu_ops.define_kernel_hw_stacks_sizes(hw_stacks);
}
static inline void
boot_pv_define_kernel_hw_stacks_sizes(struct hw_stack *hw_stacks)
{
	BOOT_PARAVIRT_GET_CPU_FUNC(define_kernel_hw_stacks_sizes)(hw_stacks);
}

static inline void
pv_define_user_hw_stacks_sizes(struct hw_stack *hw_stacks)
{
	pv_cpu_ops.define_user_hw_stacks_sizes(hw_stacks);
}

static inline void
pv_release_hw_stacks(struct thread_info *dead_ti)
{
	pv_cpu_ops.release_hw_stacks(dead_ti);
}

static inline void
pv_release_kernel_stacks(struct thread_info *dead_ti)
{
	pv_cpu_ops.release_kernel_stacks(dead_ti);
}

static inline int
pv_switch_to_new_user(struct e2k_stacks *stacks, struct hw_stack *hw_stacks,
			e2k_addr_t cut_base, e2k_size_t cut_size,
			e2k_addr_t entry_point, int cui,
			unsigned long flags, bool kernel)
{
	return pv_cpu_ops.switch_to_new_user(stacks, hw_stacks,
			cut_base, cut_size, entry_point, cui, flags, kernel);
}

static inline int
pv_do_map_user_hard_stack_to_kernel(int nid,
	e2k_addr_t kernel_start, e2k_addr_t user_stack_base,
	e2k_size_t kernel_size)
{
	return pv_cpu_ops.do_map_user_hard_stack_to_kernel(nid,
				kernel_start, user_stack_base, kernel_size);
}
static __always_inline int
pv_complete_switch_to_kernel_hardware_stacks(e2k_addr_t ps, e2k_addr_t cs,
		unsigned long *delta_proc, unsigned long *delta_chain,
		bool to_exit)
{
	if (!paravirt_enabled())
		return native_complete_switch_to_kernel_hardware_stacks(ps, cs,
				delta_proc, delta_chain, to_exit);
	else
		return kvm_complete_switch_to_kernel_hardware_stacks(ps, cs,
				delta_proc, delta_chain, to_exit);
}
static __always_inline int
pv_complete_switch_from_kernel_hardware_stacks(
		unsigned long delta_proc, unsigned long delta_chain)
{
	if (!paravirt_enabled()) {
		native_complete_switch_from_kernel_hardware_stacks(
				delta_proc, delta_chain);
		return 0;
	} else {
		return kvm_complete_switch_from_kernel_hardware_stacks(
				delta_proc, delta_chain);
	}
}
static inline void
pv_free_old_kernel_hardware_stacks(void)
{
	pv_cpu_ops.free_old_kernel_hardware_stacks();
}

static inline void
pv_fix_process_pt_regs(struct thread_info *ti, struct e2k_stacks *stacks,
			struct pt_regs *regs, struct pt_regs *old_regs)
{
	if (pv_cpu_ops.fix_process_pt_regs)
		pv_cpu_ops.fix_process_pt_regs(ti, stacks, regs, old_regs);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* It is paravirtualized host and guest kernel */

#define	E2K_FLUSHCPU	PV_FLUSHCPU
#define	E2K_FLUSHR	PV_FLUSHR
#define	E2K_FLUSHC	PV_FLUSHC
#define	BOOT_FLUSHCPU	BOOT_PV_FLUSH_STACKS()
#define	BOOT_FLUSHR	BOOT_PV_FLUSH_REGS_STACK()
#define	BOOT_FLUSHC	BOOT_PV_FLUSH_CHAIN_STACK()

static inline void COPY_STACKS_TO_MEMORY(void)
{
	PV_COPY_STACKS_TO_MEMORY();
}

#define	UPDATE_VCPU_THREAD_CONTEXT(__task, __ti, __regs, __gti, __vcpu)	\
		PV_UPDATE_VCPU_THREAD_CONTEXT(__task, __ti, __regs, \
						__gti, __vcpu)
#define	CHECK_VCPU_THREAD_CONTEXT(__ti)	\
		PV_CHECK_VCPU_THREAD_CONTEXT(__ti)
#define	ONLY_SET_GUEST_GREGS(ti)	PV_ONLY_SET_GUEST_GREGS(ti)

#ifdef	CONFIG_KVM_GUEST
 #define GOTO_RETURN_TO_PARAVIRT_GUEST(ret_value)	\
		KVM_GOTO_RETURN_TO_PARAVIRT_GUEST(ret_value)
 #define COND_GOTO_RETURN_TO_PARAVIRT_GUEST(cond, ret_value)	\
		KVM_COND_GOTO_RETURN_TO_PARAVIRT_GUEST(cond, ret_value)
 #define GOTO_DONE_TO_PARAVIRT_GUEST()			\
		KVM_GOTO_DONE_TO_PARAVIRT_GUEST()
 #define COND_GOTO_DONE_TO_PARAVIRT_GUEST(cond)		\
		KVM_COND_GOTO_DONE_TO_PARAVIRT_GUEST(cond)
#else
 #error "undefined guest kernel type"
#endif	/* CONFIG_KVM_GUEST */

static inline int
do_map_user_hard_stack_to_kernel(int nid,
	e2k_addr_t kernel_start, e2k_addr_t user_stack_base,
	e2k_size_t kernel_size)
{
	return pv_do_map_user_hard_stack_to_kernel(nid,
			kernel_start, user_stack_base, kernel_size);
}

static inline void
virt_cpu_thread_init(struct task_struct *boot_task)
{
	pv_virt_cpu_thread_init(boot_task);
}

static inline int
copy_kernel_stacks(struct task_struct *new_task,
			unsigned long fn, unsigned long arg)
{
	return pv_copy_kernel_stacks(new_task, fn, arg);
}
static inline int
copy_user_stacks(unsigned long clone_flags,
			e2k_addr_t new_stk_base, e2k_size_t new_stk_sz,
			struct task_struct *new_task, pt_regs_t *regs)
{
	return pv_copy_user_stacks(clone_flags, new_stk_base, new_stk_sz,
					new_task, regs);
}

static inline void
define_kernel_hw_stacks_sizes(hw_stack_t *hw_stacks)
{
	pv_define_kernel_hw_stacks_sizes(hw_stacks);
}

static inline void
boot_define_kernel_hw_stacks_sizes(hw_stack_t *hw_stacks)
{
	boot_pv_define_kernel_hw_stacks_sizes(hw_stacks);
}

static inline void
define_user_hw_stacks_sizes(hw_stack_t *hw_stacks)
{
	pv_define_user_hw_stacks_sizes(hw_stacks);
}

static inline void
release_hw_stacks(struct thread_info *dead_ti)
{
	pv_release_hw_stacks(dead_ti);
}
static inline void
release_kernel_stacks(struct thread_info *dead_ti)
{
	pv_release_kernel_stacks(dead_ti);
}

static inline int
switch_to_new_user(e2k_stacks_t *stacks, hw_stack_t *hw_stacks,
			e2k_addr_t cut_base, e2k_size_t cut_size,
			e2k_addr_t entry_point, int cui,
			unsigned long flags, bool kernel)
{
	return pv_switch_to_new_user(stacks, hw_stacks,
			cut_base, cut_size, entry_point, cui, flags, kernel);
}

static __always_inline int
complete_switch_to_kernel_hardware_stacks(e2k_addr_t ps, e2k_addr_t cs,
		unsigned long *delta_proc, unsigned long *delta_chain,
		bool to_exit)
{
	return pv_complete_switch_to_kernel_hardware_stacks(ps, cs,
			delta_proc, delta_chain, to_exit);
}

static __always_inline int
complete_switch_from_kernel_hardware_stacks(
		unsigned long delta_proc, unsigned long delta_chain)
{
	return pv_complete_switch_from_kernel_hardware_stacks(
			delta_proc, delta_chain);
}

static inline void
free_old_kernel_hardware_stacks(void)
{
	pv_free_old_kernel_hardware_stacks();
}

static inline void
fix_process_pt_regs(thread_info_t *ti, e2k_stacks_t *stacks,
				pt_regs_t *regs, pt_regs_t *old_regs)
{
	pv_fix_process_pt_regs(ti, stacks, regs, old_regs);
}

#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* !_E2K_PARAVIRT_PROCESS_H */
