/* Functions to sync shadow page tables with guest page tables
 * without flushing tlb. Used only by guest kernels
 *
 * Copyright 2021 Andrey Alekhin (alekhin_amcst.ru)
 */
#ifndef _E2K_SYNC_PG_TABLES_H
#define _E2K_SYNC_PG_TABLES_H

#if defined(CONFIG_KVM_GUEST_KERNEL)

#include <asm/kvm/guest/sync_pg_tables.h>

#define sync_addr_range kvm_sync_addr_range
#else
#define sync_addr_range
#endif /* !CONFIG_KVM_GUEST_KERNEL */

#endif
