/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _KVM_E2K_GPID_H
#define _KVM_E2K_GPID_H

/*
 * Guest processes identifier (gpid) allocator
 * Based on simplified include/linux/pid.h
 */

#include <linux/threads.h>
#include <linux/hash.h>
#include "process.h"

#define	GPID_MAX_LIMIT		(PID_MAX_LIMIT / 2)

#define GPIDMAP_ENTRIES		((GPID_MAX_LIMIT + 8*PAGE_SIZE - 1)/PAGE_SIZE/8)

#define GPID_HASH_BITS		4
#define CPID_HASH_SIZE		(1 << GPID_HASH_BITS)

typedef struct gpid {
	int nr;
	gthread_desc_t *gthread_desc;
	struct hlist_node gpid_chain;
} gpid_t;

typedef struct gpidmap {
	atomic_t nr_free;
	void *page;
} gpidmap_t;

typedef struct kvm_gpid_table {
	raw_spinlock_t gpidmap_lock;
	gpidmap_t gpidmap[GPIDMAP_ENTRIES];
	int last_gpid;
	struct kmem_cache *gpid_cachep;
	struct hlist_head gpid_hash[CPID_HASH_SIZE];
	unsigned int gpidhash_shift;
} kvm_gpid_table_t;

#define gpid_hashfn(nr)	hash_long((unsigned long)nr, GPID_HASH_BITS)

static inline gthread_desc_t *kvm_gpid_proc_desk(gpid_t *gpid)
{
	return gpid->gthread_desc;
}

extern gpid_t *kvm_alloc_gpid(kvm_gpid_table_t *gpid_table);
extern void kvm_do_free_gpid(gpid_t *gpid, kvm_gpid_table_t *gpid_table);
extern void kvm_free_gpid(gpid_t *gpid, kvm_gpid_table_t *gpid_table);

extern int kvm_gpidmap_init(kvm_gpid_table_t *gpid_table);
extern void kvm_gpidmap_destroy(kvm_gpid_table_t *gpid_table);

#endif /* _KVM_E2K_GPID_H */
