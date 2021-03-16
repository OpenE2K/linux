/*
 * Secondary space support for E2K binary compiler
 * Paravirtualized host and guest kernel support
 */
#ifndef _ASM_PARAVIRT_SECONDARY_SPACE_H
#define	_ASM_PARAVIRT_SECONDARY_SPACE_H

/* do not include the header directly, use asm/secondary_space.h include */
#include <asm/paravirt/pv_ops.h>

#ifdef	CONFIG_KVM_GUEST
#include <asm/kvm/guest/secondary_space.h>

#define PV_IS_NEXT_ELBRUS_2S	\
		((!paravirt_enabled()) ? \
			NATIVE_IS_NEXT_ELBRUS_2S : KVM_IS_NEXT_ELBRUS_2S)
#define PV_SS_SIZE			\
		((!paravirt_enabled()) ? \
			NATIVE_SS_SIZE : KVM_SS_SIZE)
#define PV_SS_ADDR_START		\
		((!paravirt_enabled()) ? \
			NATIVE_SS_ADDR_START : KVM_SS_ADDR_START)
#else	/* ! CONFIG_KVM_GUEST */
 #error "Unknown virtualization type */
#endif	/* CONFIG_KVM_GUEST */

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */

#define IS_NEXT_ELBRUS_2S	PV_IS_NEXT_ELBRUS_2S
#define SS_SIZE			PV_SS_SIZE
#define SS_ADDR_START		PV_SS_ADDR_START
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* _ASM_PARAVIRT_SECONDARY_SPACE_H */
