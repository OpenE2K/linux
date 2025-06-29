/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _KVM_E2K_VMID_H
#define _KVM_E2K_VMID_H

/*
 * Guest virtual machine identifier (vmid) allocator
 * Based on simplified include/linux/pid.h
 */

#include <linux/threads.h>
#include <linux/hash.h>
#include <linux/kvm_host.h>
#include <asm/kvm/mmu_hv_regs_types.h>
#include <asm/kvm/nid.h>

#define	VMID_MAX_LIMIT		MMU_GID_SIZE
#define	RESERVED_VMIDS		1	/* GID #0 reserved for hypervisor */
					/* by hardware */

#define VMIDMAP_ENTRIES		((VMID_MAX_LIMIT + 8*PAGE_SIZE - 1)/PAGE_SIZE/8)

#define VMID_HASH_BITS		5
#define VMID_HASH_SIZE		(1 << VMID_HASH_BITS)

typedef struct nid vmid_t;

typedef struct nidmap vmidmap_t;

typedef struct kvm_nid_table kvm_vmid_table_t;

#define vmid_hashfn(nr)	hash_long((unsigned long)nr, VMID_HASH_BITS)

extern int kvm_alloc_vmid(struct kvm *kvm);
extern void kvm_free_vmid(struct kvm *kvm);

extern int kvm_vmidmap_init(void);
extern void kvm_vmidmap_destroy(void);

#endif /* _KVM_E2K_VMID_H */
