#ifndef _E2K_KVM_GUEST_SIGNAL_H_
#define _E2K_KVM_GUEST_SIGNAL_H_

#include <linux/types.h>

#ifndef __ASSEMBLY__

extern int kvm_signal_setup(struct pt_regs *regs);
extern int kvm_longjmp_copy_user_to_kernel_hw_stacks(struct pt_regs *regs,
						     struct pt_regs *new_regs);
extern int kvm_complete_long_jump(struct pt_regs *regs, bool switch_stack,
				u64 to_key);
extern void kvm_update_kernel_crs(e2k_mem_crs_t *crs, e2k_mem_crs_t *prev_crs,
				e2k_mem_crs_t *p_prev_crs);
extern int kvm_add_ctx_signal_stack(u64 key, bool is_main);
extern void kvm_remove_ctx_signal_stack(u64 key);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native paravirtualized guest kernel */
/* or native kernel without virtualization support */

static inline int signal_setup(struct pt_regs *regs)
{
	return kvm_signal_setup(regs);
}

static inline int longjmp_copy_user_to_kernel_hw_stacks(struct pt_regs *regs,
							struct pt_regs *new_regs)
{
	return kvm_longjmp_copy_user_to_kernel_hw_stacks(regs, new_regs);
}

static inline int complete_long_jump(struct pt_regs *regs, bool switch_stack,
					u64 to_key)
{
	if (likely(IS_HV_GM()))
		return native_complete_long_jump();
	else
		return kvm_complete_long_jump(regs, switch_stack, to_key);
}

static inline void update_kernel_crs(e2k_mem_crs_t *k_crs, e2k_mem_crs_t *crs,
			e2k_mem_crs_t *prev_crs, e2k_mem_crs_t *p_prev_crs)
{
	if (likely(IS_HV_GM()))
		native_update_kernel_crs(k_crs, crs, prev_crs, p_prev_crs);
	else
		kvm_update_kernel_crs(crs, prev_crs, p_prev_crs);
}

static inline int add_ctx_signal_stack(u64 key, bool is_main)
{
	if (likely(IS_HV_GM()))
		return native_add_ctx_signal_stack(key, is_main);
	else
		return kvm_add_ctx_signal_stack(key, is_main);
}

static inline void remove_ctx_signal_stack(u64 key)
{
	if (likely(IS_HV_GM()))
		native_remove_ctx_signal_stack(key);
	else
		kvm_remove_ctx_signal_stack(key);
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */


#endif /* !__ASSEMBLY__ */

#endif /* !_E2K_KVM_GUEST_SIGNAL_H_ */
