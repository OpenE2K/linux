#ifndef _ASM_E2K_PARAVIRT_ATOMIC_API_H_
#define _ASM_E2K_PARAVIRT_ATOMIC_API_H_

#include <linux/types.h>
#include <asm/pv_info.h>

#ifdef	__KERNEL__

#ifndef	__ASSEMBLY__

/* FIXME: on guest it is not implemented hardware bugs workarounds, */
/* because of such workarounds contain privileged actions and */
/* can be done only on host using appropriate hypercalls */

#ifdef	CONFIG_KVM_GUEST
#include <asm/kvm/guest/atomic_api.h>

#define PV_HWBUG_AFTER_LD_ACQ()		NATIVE_HWBUG_AFTER_LD_ACQ()
#else	/* ! CONFIG_KVM_GUEST */
 #error "Unknown virtualization type"
#endif	/* CONFIG_KVM_GUEST */

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */

/* FIXME: examine bare hardware bugs only for host */
/* guest virtual machine should examine host machine bugs too, but now */
/* it is not implemented */
#define	virt_cpu_has(hwbug)	((!paravirt_enabled()) && cpu_has(hwbug))

#define	VIRT_HWBUG_AFTER_LD_ACQ()	PV_HWBUG_AFTER_LD_ACQ()
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* ! __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif /* _ASM_E2K_PARAVIRT_ATOMIC_API_H_ */
