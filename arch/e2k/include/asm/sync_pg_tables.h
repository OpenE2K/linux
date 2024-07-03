/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Functions to sync shadow page tables with guest page tables without flushing tlb.
 * Used only by guest kernels.
 */

#ifndef _E2K_SYNC_PG_TABLES_H
#define _E2K_SYNC_PG_TABLES_H

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/sync_pg_tables.h>
#else	/* !CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without any virtualization */
/* or host kernel with virtualization support */
#define sync_mm_addr(address) \
do { \
	(void) (address); \
} while (0)
#define sync_mm_range(start, end) \
do { \
	(void) (start); \
	(void) (end); \
} while (0)
#endif /* CONFIG_KVM_GUEST_KERNEL */

#endif
