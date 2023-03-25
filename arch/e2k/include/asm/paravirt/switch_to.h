#ifndef _ASM_PARAVIRT_SWITCH_TO_H
#define _ASM_PARAVIRT_SWITCH_TO_H

#ifdef __KERNEL__

#include <linux/types.h>
#include <asm/kvm/guest/switch_to.h>

/* switch_to() should be only macros to update pointer 'prev' at */
/* __schedule() function. It is important for guest kernel */
#define	pv_switch_to(prev, next, last)				\
do {								\
	if (!paravirt_enabled())				\
		native_switch_to(prev, next, last);		\
	else							\
		kvm_switch_to(prev, next, last);		\
} while (false)

#ifdef	CONFIG_PARAVIRT_GUEST
/* It is paravirtualized host and guest kernel */

#define	switch_to(prev, next, last)	pv_switch_to(prev, next, last)

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* __KERNEL__ */

#endif /* _ASM_PARAVIRT_SWITCH_TO_H */
