#ifndef __ASM_E2K_PARAVIRT_CPU_H
#define __ASM_E2K_PARAVIRT_CPU_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>
#include <asm/pv_info.h>

#ifdef	CONFIG_KVM_GUEST
#include <asm/kvm/guest/cpu.h>

#define	PV_VIRQ_VCPU_NO_TO_VCPU_ID(virq_vcpu_id)	\
({ \
	if (!paravirt_enabled()) { \
		NATIVE_VIRQ_VCPU_NO_TO_VCPU_ID(virq_vcpu_id); \
	} else { \
		KVM_VIRQ_VCPU_NO_TO_VCPU_ID(virq_vcpu_id); \
	} \
})
#define	PV_VCPU_ID_TO_VIRQ_VCPU_NO(vcpu_id)	\
({ \
	if (!paravirt_enabled()) { \
		NATIVE_VCPU_ID_TO_VIRQ_VCPU_NO(vcpu_id); \
	} else { \
		KVM_VCPU_ID_TO_VIRQ_VCPU_NO(vcpu_id); \
	} \
})
#define	PV_IS_ID_VIRQ_VCPU_NO(cpu_id)	\
({ \
	bool pv_is; \
	if (!paravirt_enabled()) { \
		pv_is = NATIVE_IS_ID_VIRQ_VCPU_NO(cpu_id); \
	} else { \
		pv_is = KVM_IS_ID_VIRQ_VCPU_NO(cpu_id); \
	} \
	pv_is; \
})
#define	PV_IS_ID_VCPU_ID(cpu_id)	\
({ \
	bool pv_is; \
	if (!paravirt_enabled()) { \
		pv_is = NATIVE_IS_ID_VCPU_ID(cpu_id); \
	} else { \
		pv_is = KVM_IS_ID_VCPU_ID(cpu_id); \
	} \
	pv_is; \
})
#define	PV_CONVERT_VIRQ_VCPU_NO_TO_VCPU_ID(virq_vcpu_id)	\
({ \
	if (!paravirt_enabled()) { \
		NATIVE_CONVERT_VIRQ_VCPU_NO_TO_VCPU_ID(virq_vcpu_id); \
	} else { \
		KVM_CONVERT_VIRQ_VCPU_NO_TO_VCPU_ID(virq_vcpu_id); \
	} \
})
#define	PV_CONVERT_VCPU_ID_TO_VIRQ_VCPU_NO(vcpu_id)	\
({ \
	if (!paravirt_enabled()) { \
		NATIVE_CONVERT_VCPU_ID_TO_VIRQ_VCPU_NO(vcpu_id); \
	} else { \
		KVM_CONVERT_VCPU_ID_TO_VIRQ_VCPU_NO(vcpu_id); \
	} \
})
#else	/* ! CONFIG_KVM_GUEST */
 #error "Unknown virtualization type"
#endif	/* CONFIG_KVM_GUEST */

static inline unsigned long
pv_get_cpu_running_cycles(void)
{
	return pv_time_ops.get_cpu_running_cycles();
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized guest and host kernel */

#define	VIRQ_VCPU_NO_TO_VCPU_ID(virq_vcpu_id)	\
		PV_VIRQ_VCPU_NO_TO_VCPU_ID(virq_vcpu_id)
#define	VCPU_ID_TO_VIRQ_VCPU_NO(vcpu_id)	\
		PV_VCPU_ID_TO_VIRQ_VCPU_NO(vcpu_id)
#define	IS_ID_VIRQ_VCPU_NO(cpu_id)		\
		PV_IS_ID_VIRQ_VCPU_NO(cpu_id)
#define	IS_ID_VCPU_ID(cpu_id)			\
		PV_IS_ID_VCPU_ID(cpu_id)
#define	CONVERT_VIRQ_VCPU_NO_TO_VCPU_ID(virq_vcpu_id)	\
		PV_CONVERT_VIRQ_VCPU_NO_TO_VCPU_ID(virq_vcpu_id)
#define	CONVERT_VCPU_ID_TO_VIRQ_VCPU_NO(vcpu_id)	\
		PV_CONVERT_VCPU_ID_TO_VIRQ_VCPU_NO(vcpu_id)

static inline unsigned long
get_cpu_running_cycles(void)
{
	return pv_get_cpu_running_cycles();
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* __KERNEL__ */

#endif	/* __ASM_E2K_PARAVIRT_CPU_H */
