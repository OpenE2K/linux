#ifndef _E2K_KVM_GUEST_SIGNAL_H_
#define _E2K_KVM_GUEST_SIGNAL_H_

#include <linux/types.h>

#ifndef __ASSEMBLY__

extern int kvm_signal_setup(struct pt_regs *regs);
extern int kvm_complete_long_jump(struct pt_regs *regs);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native paravirtualized guest kernel */
/* or native kernel without virtualization support */

static inline int signal_setup(struct pt_regs *regs)
{
	return kvm_signal_setup(regs);
}

static inline int complete_long_jump(struct pt_regs *regs)
{
	if (likely(IS_HV_GM())) {
		return native_complete_long_jump(regs);
	} else {
		return kvm_complete_long_jump(regs);
	}
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */


#endif /* !__ASSEMBLY__ */

#endif /* !_E2K_KVM_GUEST_SIGNAL_H_ */
