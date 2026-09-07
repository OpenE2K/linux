/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Generic guest pidhash and scalable, time-bounded GPID allocator
 *
 * Based on simplified kernel/pid.c
 */

#include <linux/mm.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/kvm_host.h>
#include <asm/kvm/gpid.h>

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

gpid_t *kvm_alloc_gpid(kvm_gpid_table_t *gpid_table)
{
	gpid_t *gpid;
	int nr;

	DebugKVM("started\n");
	gpid = kmem_cache_alloc(gpid_table->nid_cachep, GFP_KERNEL);
	if (!gpid)
		goto out;

	nr = kvm_alloc_nid(gpid_table, &gpid->nid);
	if (nr < 0)
		goto out_free;

	gpid->gthread_info = NULL;
	DebugKVM("allocated guest PID %d structure at %px\n",
		gpid->nid.nr, gpid);

out:
	return gpid;

out_free:

	kmem_cache_free(gpid_table->nid_cachep, gpid);
	gpid = NULL;
	goto out;
}

static void kvm_drop_gpid(gpid_t *gpid, kvm_gpid_table_t *gpid_table)
{
	DebugKVM("started\n");
	kmem_cache_free(gpid_table->nid_cachep, gpid);
}

void kvm_do_free_gpid(gpid_t *gpid, kvm_gpid_table_t *gpid_table)
{
	DebugKVM("started\n");

	kvm_do_free_nid(&gpid->nid, gpid_table);
	kvm_drop_gpid(gpid, gpid_table);
}

void kvm_free_gpid(gpid_t *gpid, kvm_gpid_table_t *gpid_table)
{
	unsigned long flags;

	DebugKVM("started\n");

	gpid_table_lock_irqsave(gpid_table, flags);
	kvm_do_free_gpid(gpid, gpid_table);
	gpid_table_unlock_irqrestore(gpid_table, flags);
}

/*
 * The gpid hash table is scaled according to the amount of memory in the
 * machine.  From a minimum of 16 slots up to 4096 slots at one gigabyte or
 * more.
 */

int kvm_gpidmap_init(struct kvm *kvm, kvm_gpid_table_t *gpid_table,
			kvm_nidmap_t *gpid_nidmap, int gpidmap_entries,
			struct hlist_head *gpid_hash, int gpid_hash_bits)
{
	int ret;

	DebugKVM("started\n");
	gpid_table->nidmap = gpid_nidmap;
	gpid_table->nidmap_entries = gpidmap_entries;
	gpid_table->nid_hash = gpid_hash;
	gpid_table->nid_hash_bits = gpid_hash_bits;
	gpid_table->nid_hash_size = NID_HASH_SIZE(gpid_hash_bits);
	ret = kvm_nidmap_init(gpid_table, GPID_MAX_LIMIT, RESERVED_GPIDS,
				/* last gpid: no reserved, */
				/* init_task gpid #0 will be allocated first */
				-1);
	if (ret != 0) {
		pr_err("kvm_gpidmap_init() could not create NID map\n");
		return ret;
	}
	sprintf(gpid_table->nid_cache_name, "gpid_VM%d", kvm->arch.vmid.nr);
	gpid_table->nid_cachep =
		kmem_cache_create(gpid_table->nid_cache_name,
					sizeof(gpid_t), 0,
					SLAB_HWCACHE_ALIGN, NULL);
	if (gpid_table->nid_cachep == NULL) {
		pr_err("kvm_gpidmap_init() could not allocate GPID cache\n");
		return -ENOMEM;
	}
	return 0;
}

void kvm_gpidmap_reset(struct kvm *kvm, kvm_gpid_table_t *gpid_table)
{
	DebugKVM("started\n");
	kvm_nidmap_reset(gpid_table,
			 -1	/* init_task gpid #0 will be allocated first */);
}

void kvm_gpidmap_destroy(kvm_gpid_table_t *gpid_table)
{
	gpid_t *gpid;
	struct hlist_node *next;
	unsigned long flags;
	int i;

	DebugKVM("started\n");
	gpid_table_lock_irqsave(gpid_table, flags);
	for_each_guest_thread_info(gpid, i, next, gpid_table) {
		kvm_do_free_gpid(gpid, gpid_table);
	}
	gpid_table_unlock_irqrestore(gpid_table, flags);
	kvm_nidmap_destroy(gpid_table);
	kmem_cache_destroy(gpid_table->nid_cachep);
	gpid_table->nid_cachep = NULL;
}
