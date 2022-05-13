/* Functions to sync shadow page tables with guest page tables
 * without flushing tlb. Used only by guest kernels
 *
 * Copyright 2021 Andrey Alekhin (alekhin_amcst.ru)
 */
#ifndef _E2K_SYNC_PG_TABLES_H
#define _E2K_SYNC_PG_TABLES_H

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/sync_pg_tables.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/sync_pg_tables.h>
#else	/* !CONFIG_KVM_GUEST_KERNEL && !CONFIG_PARAVIRT_GUEST */
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
