/*
 * Copyright (c) 2016 MCST, Salavat Gilyazov atic@mcst.ru
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */


#ifndef __ASM_E2K_PV_INFO_H
#define __ASM_E2K_PV_INFO_H

#include <linux/types.h>

/*
 * e2k kernel general info
 */

/*
 * Even 32-bit applications must have big TASK_SIZE since hardware
 * stacks are placed behind the 4Gb boundary.
 */
/* Virtual space is splitted into two parts: user and kernel spaces. */
/* Kernel virtual space takes high area and starts from the following base */
#define	NATIVE_KERNEL_VIRTUAL_SPACE_BASE	0x0000d00000000000

/* direct mapping of all physical memory starts now from kernel virtual */
/* space beginning, but cannot map all possible 2**48 bytes */
#define NATIVE_PAGE_OFFSET	NATIVE_KERNEL_VIRTUAL_SPACE_BASE

/* Users virtual spaces take low area from 0 right up to kernel base */
#define	NATIVE_TASK_SIZE	NATIVE_KERNEL_VIRTUAL_SPACE_BASE

#ifdef	CONFIG_MMU_SEP_VIRT_SPACE
/* Users Separate Page Tables virtual base at the top of user space */
/*				0x0000 cf80 0000 0000	*/
#define	USER_VPTB_BASE_SIZE	PGDIR_SIZE
#define	USER_VPTB_BASE_ADDR	(NATIVE_TASK_SIZE - USER_VPTB_BASE_SIZE)
#else	/* ! CONFIG_MMU_SEP_VIRT_SPACE */
#define	USER_VPTB_BASE_SIZE	0
#define	USER_VPTB_BASE_ADDR	KERNEL_VPTB_BASE_ADDR
#endif	/* CONFIG_MMU_SEP_VIRT_SPACE */

/* virtualization support */
#include <asm/kvm/page.h>

#ifndef	CONFIG_VIRTUALIZATION
/* it is native kernel without any virtualization */
#define	IS_HOST_KERNEL_ADDRESS(addr)	((addr) >= NATIVE_TASK_SIZE)
#define	IS_HOST_USER_ADDRESS(addr)	((addr) < NATIVE_TASK_SIZE)
#define	IS_GUEST_KERNEL_ADDRESS(addr)	false
#define	IS_GUEST_USER_ADDRESS(addr)	false
#define	IS_GUEST_PHYS_ADDRESS(addr)	false
#else	/* CONFIG_VIRTUALIZATION */
/* it is host kernel with virtualization support */
/* or paravirtualized host and guest kernel */
/* or pure guest kernel (not paravirtualized based on pv_ops) */
#define HOST_TASK_SIZE	(HOST_PAGE_OFFSET)
#define GUEST_TASK_SIZE	(GUEST_PAGE_OFFSET)
#define HOST_TASK_TOP	HOST_TASK_SIZE
#define GUEST_TASK_TOP	GUEST_TASK_SIZE
#define	BOOT_HOST_TASK_SIZE	HOST_TASK_SIZE
#define	BOOT_GUEST_TASK_SIZE	GUEST_TASK_SIZE

#define	IS_HOST_KERNEL_ADDRESS(addr)	((addr) >= HOST_TASK_SIZE)
#define	IS_HOST_USER_ADDRESS(addr)	((addr) < HOST_TASK_SIZE)
#define	IS_GUEST_KERNEL_ADDRESS(addr)	((addr) >= GUEST_TASK_SIZE &&	\
						(addr) < HOST_TASK_SIZE)
#define	IS_GUEST_USER_ADDRESS(addr)	((addr) < GUEST_TASK_SIZE)
#define	IS_GUEST_PHYS_ADDRESS(addr)	\
		((e2k_addr_t)(addr) >= GUEST_PAGE_OFFSET && \
			(e2k_addr_t)(addr) < GUEST_PAGE_OFFSET + MAX_PM_SIZE)
#endif	/* ! CONFIG_VIRTUALIZATION */

#ifdef CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */
#define	is_paravirt_kernel()		true	/* it is paravirtualized */
						/* host and guest kernel */
#include <asm/paravirt/pv_info.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* pure guest kernel (not paravirtualized) */
#define	is_paravirt_kernel()		false
#include <asm/kvm/guest/pv_info.h>
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without virtualization support */
/* or host kernel with virtualization support */
#define	TASK_SIZE			NATIVE_TASK_SIZE

#define paravirt_enabled()		(IS_HV_GM() || false)
#define	boot_paravirt_enabled()		(BOOT_IS_HV_GM() || false)
#define	is_paravirt_kernel()		false

#ifndef	CONFIG_VIRTUALIZATION
/* it is native kernel without virtualization support */
#define	KERNEL_VIRTUAL_SPACE_BASE	NATIVE_KERNEL_VIRTUAL_SPACE_BASE
#define	PAGE_OFFSET			NATIVE_PAGE_OFFSET
#define	VMALLOC_START			NATIVE_VMALLOC_START
#define	VMALLOC_END			NATIVE_VMALLOC_END
#define	VMEMMAP_START			NATIVE_VMEMMAP_START
#define	VMEMMAP_END			NATIVE_VMEMMAP_END

#define	BOOT_KERNEL_VIRTUAL_SPACE_BASE	KERNEL_VIRTUAL_SPACE_BASE
#define	BOOT_PAGE_OFFSET		PAGE_OFFSET
#define	BOOT_TASK_SIZE			TASK_SIZE
#endif	/* ! CONFIG_VIRTUALIZATION */

#endif	/* CONFIG_PARAVIRT_GUEST */

#define	kernel_is_privileged()		(!paravirt_enabled() || IS_HV_GM())

#endif /* __ASM_E2K_PV_INFO_H */
