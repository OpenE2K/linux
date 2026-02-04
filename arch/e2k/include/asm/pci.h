/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_PCI_H
#define _E2K_PCI_H

#ifdef __KERNEL__

#define HAVE_PCI_LEGACY			1

#define PCIBIOS_MIN_IO		0x1000
#define PCIBIOS_MIN_MEM		0
#define	PCIBIOS_MAX_MEM_32	0xffffffffUL

#define PCIBIOS_MIN_CARDBUS_IO	0x4000

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/mm_types.h>
#include <linux/string.h>
#include <asm/io.h>


#define HAVE_PCI_MMAP
#define arch_can_pci_mmap_wc()	1

/* Elbrus PCI */
#include <asm-l/pci.h>

/* Generic PCI */
#include <asm-generic/pci.h>

#endif  /* __KERNEL__ */

#endif /* _E2K_PCI_H */
