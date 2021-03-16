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


#ifndef __ASM_E2K_KVM_GUEST_PV_INFO_H
#define __ASM_E2K_KVM_GUEST_PV_INFO_H

#include <linux/types.h>

/*
 * e2k kernel general info
 */
#define	KVM_PAGE_OFFSET			GUEST_PAGE_OFFSET
#define	KVM_TASK_SIZE			PAGE_OFFSET
#define	KVM_VMALLOC_START		GUEST_VMALLOC_START
#define	KVM_VMALLOC_END			GUEST_VMALLOC_END
#define KVM_VMEMMAP_START		GUEST_VMEMMAP_START
#define KVM_VMEMMAP_END			GUEST_VMEMMAP_END

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#define paravirt_enabled()		true
#define	boot_paravirt_enabled()		paravirt_enabled()

#define	PAGE_OFFSET			KVM_PAGE_OFFSET
#define	TASK_SIZE			PAGE_OFFSET
#define	VMALLOC_START			KVM_VMALLOC_START
#define	VMALLOC_END			KVM_VMALLOC_END
#define VMEMMAP_START			KVM_VMEMMAP_START
#define VMEMMAP_END			KVM_VMEMMAP_END

#define	BOOT_PAGE_OFFSET		PAGE_OFFSET
#define	BOOT_TASK_SIZE			TASK_SIZE
#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

#endif /* __ASM_E2K_KVM_GUEST_PV_INFO_H */
