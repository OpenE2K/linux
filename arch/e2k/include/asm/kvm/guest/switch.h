#ifndef _E2K_KVM_GUEST_SWITCH_H
#define _E2K_KVM_GUEST_SWITCH_H

#include <asm/kvm/guest/gregs.h>

static inline void kvm_guest_enter(struct thread_info *ti,
			struct kvm_vcpu_arch *vcpu, unsigned flags)
{
	/* guest cannot have own nested guests */
}

static inline void kvm_guest_exit(struct thread_info *ti,
			struct kvm_vcpu_arch *vcpu, unsigned flags)
{
	/* guest cannot have own nested guests */
}
static inline void
kvm_trap_guest_enter(struct thread_info *ti, struct pt_regs *regs,
			unsigned flags)
{
	/* guest cannot have own nested guests */
	if (likely(!IS_HV_GM()))
		/* there is not hardware virtualization support */
		/* so native trap handler cannot be used */
		return;
	if (!(flags & EXIT_FROM_TRAP_SWITCH))
		return;
	/* restore global registers used as native kernel too */
	native_trap_guest_enter(ti, regs, flags);
}
static inline void
kvm_trap_guest_exit(struct thread_info *ti, struct pt_regs *regs,
		trap_pt_regs_t *trap, unsigned flags)
{
	/* guest cannot have own nested guests */
	if (likely(!IS_HV_GM()))
		/* there is not hardware virtualization support */
		/* so native trap handler cannot be used */
		return;
	native_trap_guest_exit(ti, regs, trap, flags);
}
static inline bool
kvm_guest_trap_pending(struct thread_info *ti)
{
	/* nothing guest can be */
	return false;
}

static inline bool
kvm_trap_from_guest_user(struct thread_info *ti)
{
	return native_trap_from_guest_user(ti);
}

static inline bool
kvm_syscall_from_guest_user(struct thread_info *ti)
{
	return native_syscall_from_guest_user(ti);
}

static inline struct e2k_stacks *
kvm_trap_guest_get_restore_stacks(struct thread_info *ti, struct pt_regs *regs)
{
	return native_trap_guest_get_restore_stacks(ti, regs);
}

static inline struct e2k_stacks *
kvm_syscall_guest_get_restore_stacks(struct thread_info *ti,
						struct pt_regs *regs)
{
	return native_syscall_guest_get_restore_stacks(regs);
}

/*
 * The function should return bool is the system call from guest
 */
static inline bool kvm_guest_syscall_enter(struct pt_regs *regs)
{
	/* guest cannot have own nested guests */

	return false;	/* it is not nested guest system call */
}

static inline void kvm_pv_vcpu_syscall_intc(thread_info_t *ti, pt_regs_t *regs)
{
	/* Do nothing in guest mode */
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravrtualized) */

static inline void __guest_enter(struct thread_info *ti,
		struct kvm_vcpu_arch *vcpu, unsigned flags)
{
	kvm_guest_enter(ti, vcpu, flags);
}

static inline void __guest_exit(struct thread_info *ti,
		struct kvm_vcpu_arch *vcpu, unsigned flags)
{
	kvm_guest_exit(ti, vcpu, flags);
}
static inline void
trap_guest_enter(struct thread_info *ti, struct pt_regs *regs, unsigned flags,
			restore_caller_t from)
{
	kvm_trap_guest_enter(ti, regs, flags);
}
static inline void
trap_guest_exit(struct thread_info *ti, struct pt_regs *regs,
		trap_pt_regs_t *trap, unsigned flags)
{
	kvm_trap_guest_exit(ti, regs, trap, flags);
}
static inline bool
guest_trap_pending(struct thread_info *ti)
{
	return kvm_guest_trap_pending(ti);
}

static inline bool
guest_trap_from_user(struct thread_info *ti)
{
	return kvm_trap_from_guest_user(ti);
}

static inline bool
guest_syscall_from_user(struct thread_info *ti)
{
	return kvm_syscall_from_guest_user(ti);
}

static inline struct e2k_stacks *
trap_guest_get_restore_stacks(struct thread_info *ti, struct pt_regs *regs)
{
	return kvm_trap_guest_get_restore_stacks(ti, regs);
}

static inline struct e2k_stacks *
syscall_guest_get_restore_stacks(bool ts_host_at_vcpu_mode, struct pt_regs *regs)
{
	return kvm_syscall_guest_get_restore_stacks(
			current_thread_info(), regs);
}

#define ts_host_at_vcpu_mode() false

/*
 * The function should return bool is the system call from guest
 */
static inline bool guest_syscall_enter(struct pt_regs *regs,
		bool ts_host_at_vcpu_mode)
{
	return kvm_guest_syscall_enter(regs);
}

static inline void pv_vcpu_syscall_intc(thread_info_t *ti, pt_regs_t *regs)
{
	kvm_pv_vcpu_syscall_intc(ti, regs);
}

static inline void guest_exit_intc(struct pt_regs *regs,
		bool intc_emul_flag, restore_caller_t from) { }
static inline void guest_syscall_exit_trap(struct pt_regs *regs,
		bool ts_host_at_vcpu_mode) { }

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* ! _E2K_KVM_GUEST_SWITCH_H */
