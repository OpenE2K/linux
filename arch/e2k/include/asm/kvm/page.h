/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E2K_KVM_PAGE_H
#define _ASM_E2K_KVM_PAGE_H

#ifdef __KERNEL__

#include <linux/types.h>

#ifdef	CONFIG_VIRTUALIZATION
/*
 * it can be:
 *	host kernel with virtualization support
 *	virtualized guest kernel
 * Shift up kernel virtual space and reserve area
 *	from	0x0000200000000000
 *	to	0x0000400000000000
 * for guest kernel virtual space and it will be top of user virtual space
 */
/* #define NATIVE_PAGE_OFFSET	0x0000d00000000000 */
#define	HOST_PAGE_OFFSET	NATIVE_PAGE_OFFSET	/* 0x0000d00000000000 */
#define	GUEST_PAGE_OFFSET	0x0000200000000000	/* start and */
#define	GUEST_KERNEL_MEM_END	0x0000400000000000	/* end of guest */
							/* kernel virtual */
							/* space */

#ifdef	CONFIG_KVM_HOST_MODE
/* it is host kernel with virtualization support */
#define	__guest_pa(x)		((e2k_addr_t)(x) - GUEST_PAGE_OFFSET)
#define __guest_va(x)		((void *)((e2k_addr_t) (x) + GUEST_PAGE_OFFSET))
#endif	/* CONFIG_KVM_HOST_MODE */

#endif	/* CONFIG_VIRTUALIZATION */

#ifndef	CONFIG_VIRTUALIZATION
/* it is native kernel without any virtualization */

#define	guest_user_address_to_pva(task, addr)	(-1)	/* none guests */

#elif defined(CONFIG_KVM_HOST_MODE)
/* it is native host kernel with virtualization support */
#define PAGE_OFFSET		HOST_PAGE_OFFSET
#define BOOT_PAGE_OFFSET	PAGE_OFFSET
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is virtualized guest kernel */
#include <asm/kvm/guest/pv_info.h>
#else
 #error	"Unknown virtualization type"
#endif	/* !CONFIG_VIRTUALIZATION */

#endif /* !(__KERNEL__) */

#endif /* ! _ASM_E2K_KVM_PAGE_H */
