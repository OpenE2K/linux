#ifndef _E2K_ASM_KVM_GUEST_SGE_H
#define _E2K_ASM_KVM_GUEST_SGE_H

#ifdef __KERNEL__

#include <linux/types.h>

#include <asm/cpu_regs_types.h>
#include <asm/kvm/hypercall.h>
#include <asm/e2k_syswork.h>

#undef	DEBUG_GUEST_SGE_MODE
#undef	DebugGSGE
#define	DEBUG_GUEST_SGE_MODE	0	/* stack guard debugging */
#define	DebugGSGE(fmt, args...)						\
({									\
	if (DEBUG_GUEST_SGE_MODE)					\
		pr_info(fmt, ##args);					\
})

#define printk printk_fixed_args
#define panic panic_fixed_args
static inline void
kvm_do_switch_to_expanded_proc_stack(long delta_size, long delta_offset,
					bool decr_k_ps)
{
	int ret;

	ret = HYPERVISOR_switch_to_expanded_guest_proc_stack(delta_size,
						delta_offset, decr_k_ps);
	if (ret) {
		panic("kvm_do_switch_to_expanded_proc_stack() host could not "
			"switch to updated stack, error %d\n",
			ret);
	}
}
static inline void
kvm_do_switch_to_expanded_chain_stack(long delta_size, long delta_offset,
					bool decr_k_pcs)
{
	int ret;

	ret = HYPERVISOR_switch_to_expanded_guest_chain_stack(delta_size,
						delta_offset, decr_k_pcs);
	if (ret) {
		panic("kvm_do_switch_to_expanded_chain_stack() host could not "
			"switch to updated stack, error %d\n",
			ret);
	}
}

#undef printk
#undef panic

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* It is native guest kernel (without paravirtualization) */

static inline void
switch_to_expanded_proc_stack(long delta_size, long delta_offset,
					bool decr_k_ps)
{
	kvm_do_switch_to_expanded_proc_stack(delta_size, delta_offset,
						decr_k_ps);
}
static inline void
switch_to_expanded_chain_stack(long delta_size, long delta_offset,
					bool decr_k_pcs)
{
	kvm_do_switch_to_expanded_chain_stack(delta_size, delta_offset,
						decr_k_pcs);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* __KERNEL__ */
#endif /* _E2K_ASM_KVM_GUEST_SGE_H */
