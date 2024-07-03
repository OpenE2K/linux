/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Secondary space support for E2K binary compiler
 * Guest kernel support
 */
#ifndef _ASM_KVM_GUEST_SECONDARY_SPACE_H
#define	_ASM_KVM_GUEST_SECONDARY_SPACE_H

/* do not include the header directly, use asm/secondary_space.h include */

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel */
#define KVM_SS_ADDR_START	0x180000000000L
#define SS_ADDR_START		KVM_SS_ADDR_START
#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

#endif /* _ASM_KVM_GUEST_SECONDARY_SPACE_H */
