/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Functions to sync shadow page tables with guest page tables
 * without flushing tlb. Used only by guest kernels
 */

#ifndef _E2K_GST_SYNC_PG_TABLES_H
#define _E2K_GST_SYNC_PG_TABLES_H

#include <asm/types.h>
#include <asm/kvm/hypercall.h>

static inline void kvm_sync_mm_addr(e2k_addr_t addr)
{
	HYPERVISOR_sync_addr_range(addr, addr);
}

static inline void kvm_sync_mm_range(e2k_addr_t start, e2k_addr_t end)
{
	HYPERVISOR_sync_addr_range(start, end);
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel (not paravirtualized based on pv_ops) */
static inline void sync_mm_addr(e2k_addr_t addr)
{
	kvm_sync_mm_addr(addr);
}

static inline void sync_mm_range(e2k_addr_t start, e2k_addr_t end)
{
	kvm_sync_mm_range(start, end);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* !_E2K_GST_SYNC_PG_TABLES_H */
