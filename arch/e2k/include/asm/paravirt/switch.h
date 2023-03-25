#ifndef _E2K_PARAVIRT_SWITCH_H
#define _E2K_PARAVIRT_SWITCH_H

static inline void pv_guest_enter(struct thread_info *ti,
		struct kvm_vcpu_arch *vcpu, int switch_usd, int hypercall)
{
	if (!paravirt_enabled())
		host_guest_enter(ti, vcpu, switch_usd, hypercall);
}

static inline void pv_guest_exit(struct thread_info *ti,
		struct kvm_vcpu_arch *vcpu, int switch_usd, int hypercall)
{
	if (!paravirt_enabled())
		host_guest_exit(ti, vcpu, switch_usd, hypercall);
}

static inline void
pv_trap_guest_enter(struct thread_info *ti, struct pt_regs *regs)
{
	host_trap_guest_enter(ti, regs);
}
static inline void
pv_trap_guest_exit(struct thread_info *ti, struct pt_regs *regs)
{
	host_trap_guest_exit(ti, regs);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest */

static inline void __guest_enter(struct thread_info *ti,
		struct kvm_vcpu_arch *vcpu, int switch_usd, int hypercall)
{
	pv_guest_enter(ti, vcpu, switch_usd, hypercall);
}

static inline void __guest_exit(struct thread_info *ti,
		struct kvm_vcpu_arch *vcpu, int switch_usd, int hypercall)
{
	pv_guest_exit(ti, vcpu, switch_usd, hypercall);
}
static inline void
trap_guest_enter(struct thread_info *ti, struct pt_regs *regs)
{
	pv_trap_guest_enter(ti, regs);
}
static inline void
trap_guest_exit(struct thread_info *ti, struct pt_regs *regs)
{
	pv_trap_guest_exit(ti, regs);
}
#endif	/* CONFIG_PARAVIRT_GUEST */
#endif	/* ! _E2K_PARAVIRT_SWITCH_H */
