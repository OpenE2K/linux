/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Generic KVM ID allocator
 *
 * Based on simplified kernel/pid.c
 */

#include <linux/mm.h>
#include <linux/export.h>
#include <linux/init.h>
#include <asm/e2k_debug.h>
#include "vmid.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

static kvm_nidmap_t vmid_nidmap[VMIDMAP_ENTRIES];
static struct hlist_head vmid_hash[VMID_HASH_SIZE];
static kvm_vmid_table_t vmid_table;

int kvm_alloc_vmid(struct kvm *kvm)
{
	int nr;

	DebugKVM("started\n");

	nr = kvm_alloc_nid(&vmid_table, &kvm->arch.vmid);
	if (nr < 0)
		DebugKVM("could not allocate VM ID, error %d\n", nr);
	else
		DebugKVM("allocated VM ID #%d\n", kvm->arch.vmid.nr);

	return nr;
}

void kvm_free_vmid(struct kvm *kvm)
{
	DebugKVM("started\n");

	kvm_free_nid(&kvm->arch.vmid, &vmid_table);
}

int kvm_vmidmap_init(void)
{
	int ret;

	DebugKVM("started\n");
	vmid_table.nidmap = vmid_nidmap;
	vmid_table.nidmap_entries = VMIDMAP_ENTRIES;
	vmid_table.nid_hash = vmid_hash;
	vmid_table.nid_hash_bits = VMID_HASH_BITS;
	vmid_table.nid_hash_size = VMID_HASH_SIZE;
	ret = kvm_nidmap_init(&vmid_table, VMID_MAX_LIMIT, RESERVED_VMIDS,
				/* GID #0 reserved for hupervisor */
				RESERVED_VMIDS - 1);
	if (ret != 0) {
		pr_err("kvm_vmidmap_init() could not create NID map\n");
		return ret;
	}
	return 0;
}

void kvm_vmidmap_destroy(void)
{
	DebugKVM("started\n");
	kvm_nidmap_destroy(&vmid_table);
}
