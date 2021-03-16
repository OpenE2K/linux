/*
 * Secondary space support for E2K binary compiler
 * Guest kernel support
 */
#ifndef _ASM_KVM_GUEST_SECONDARY_SPACE_H
#define	_ASM_KVM_GUEST_SECONDARY_SPACE_H

/* do not include the header directly, use asm/secondary_space.h include */

#define	KVM_IS_NEXT_ELBRUS_2S	true
#define KVM_SS_ADDR_START	0x180000000000L
#define KVM_SS_SIZE		0x040000000000UL

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel */
#define IS_NEXT_ELBRUS_2S	KVM_IS_NEXT_ELBRUS_2S
#define SS_SIZE			KVM_SS_SIZE
#define SS_ADDR_START		KVM_SS_ADDR_START
#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

#endif /* _ASM_KVM_GUEST_SECONDARY_SPACE_H */
