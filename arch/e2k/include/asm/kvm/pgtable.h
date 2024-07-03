/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * E2K page table operations for KVM virtualization support
 */

#ifndef _E2K_KVM_PGTABLE_H
#define _E2K_KVM_PGTABLE_H

/*
 * This file contains the functions and defines necessary to modify and
 * use the E2K page tables.
 * NOTE: E2K has four levels of page tables, while Linux assumes that
 * there are three levels of page tables.
 */

#include <linux/types.h>

#include <asm/pgtable_def.h>
#include <asm/head.h>

#ifdef	CONFIG_VIRTUALIZATION
#define HOST_VMALLOC_START		NATIVE_VMALLOC_START
					/* 0x0000 e400 0000 0000 */
#define HOST_VMALLOC_END		NATIVE_VMALLOC_END
					/* 0x0000 e500 0000 0000 */
#define HOST_VMEMMAP_START		NATIVE_VMEMMAP_START
					/* 0x0000 e600 0000 0000 */
#define HOST_VMEMMAP_END		NATIVE_VMEMMAP_END
					/*<0x0000 e700 0000 0000 */
#define GUEST_VMALLOC_START		(SHADOW_KERNEL_IMAGE_AREA_BASE + \
						0x008000000000UL)
					/* 0x0000 2e80 0000 0000 */
#define GUEST_VMALLOC_END		(GUEST_VMALLOC_START + \
						0x001000000000UL)
					/* 0x0000 2e90 0000 0000 */
#define GUEST_VMEMMAP_START		(GUEST_VMALLOC_END + \
						0x001000000000UL)
					/* 0x0000 2ea0 0000 0000 */
#define GUEST_VMEMMAP_END		(GUEST_VMEMMAP_START + \
						(1UL << (E2K_MAX_PHYS_BITS - \
							PAGE_SHIFT)) * \
							sizeof(struct page))
					/*<0x0000 2f00 0000 0000 */
#endif	/* CONFIG_VIRTUALIZATION */

#if	!defined(CONFIG_VIRTUALIZATION) || defined(CONFIG_KVM_HOST_MODE)
/* it is native kernel without any virtualization */
/* or host kernel with virtualization support */
#ifndef	CONFIG_VIRTUALIZATION
/* it is native kernel without any virtualization */
#include <asm/pv_info.h>
#else	/* CONFIG_VIRTUALIZATION */
/* it is native host with virtualization support */
#define VMALLOC_START		HOST_VMALLOC_START
				/* 0x0000 e400 0000 0000 */
#define VMALLOC_END		HOST_VMALLOC_END
				/* 0x0000 e500 0000 0000 */
#define VMEMMAP_START		HOST_VMEMMAP_START
				/* 0x0000 e600 0000 0000 */
#define VMEMMAP_END		HOST_VMEMMAP_END
				/*<0x0000 e700 0000 0000 */
#endif	/* !CONFIG_VIRTUALIZATION */
/* it is native kernel without any virtualization */
/* or native host with virtualization support */

#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is virtualized guest kernel */
#include <asm/kvm/guest/pgatomic.h>
#else
 #error	"Unknown virtualization type"
#endif	/* !CONFIG_VIRTUALIZATION || CONFIG_KVM_HOST_MODE */

#endif /* ! _E2K_KVM_PGTABLE_H */
