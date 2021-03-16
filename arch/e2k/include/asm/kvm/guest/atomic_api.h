#ifndef _ASM_E2K_KVM_GUEST_ATOMIC_API_H_
#define _ASM_E2K_KVM_GUEST_ATOMIC_API_H_

#include <linux/types.h>
#include <asm/e2k_api.h>

#ifdef	__KERNEL__

#ifndef	__ASSEMBLY__

/* FIXME: here it is not implemented hardware bugs workarounds, */
/* because of such workarounds contain privileged actions and */
/* can be done only on host using appropriate hypercalls */

#define KVM_HWBUG_AFTER_LD_ACQ()	NATIVE_HWBUG_AFTER_LD_ACQ()

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not virtualized based on pv_ops */

/* Guest virtual machine should examine host machine bugs too, but now */
/* it is not implemented */
#define	virt_cpu_has(hwbug)		false

#define	VIRT_HWBUG_AFTER_LD_ACQ()	KVM_HWBUG_AFTER_LD_ACQ()
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* ! __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif /* _ASM_E2K_KVM_GUEST_ATOMIC_API_H_ */
