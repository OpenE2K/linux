/* Functions to sync shadow page tables with guest page tables
 * without flushing tlb. Used only by guest kernels
 *
 * Copyright 2021 Andrey Alekhin (alekhin_amcst.ru)
 */

#ifndef _E2K_GST_SYNC_PG_TABLES_H
#define _E2K_GST_SYNC_PG_TABLES_H

#include <asm/types.h>
#include <asm/kvm/hypercall.h>

static inline void kvm_sync_addr_range(e2k_addr_t start, e2k_addr_t end)
{
	if (!IS_HV_GM())
		HYPERVISOR_sync_addr_range(start, end);
}

#endif
