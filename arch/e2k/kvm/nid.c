/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Generic guest pidhash and scalable, time-bounded NID allocator
 *
 * Based on simplified kernel/pid.c
 */

#include <linux/mm.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <asm/kvm/nid.h>

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#define BITS_PER_PAGE		(PAGE_SIZE * 8)
#define BITS_PER_PAGE_MASK	(BITS_PER_PAGE-1)

static inline int mk_nid(struct kvm_nid_table *nid_table,
				kvm_nidmap_t *map, int off)
{
	return (map - nid_table->nidmap)*BITS_PER_PAGE + off;
}

#define find_next_offset(map, off)					\
		find_next_zero_bit((map)->page, BITS_PER_PAGE, off)

static void free_nidmap(int nr, struct kvm_nid_table *nid_table)
{
	kvm_nidmap_t *map = nid_table->nidmap + nr / BITS_PER_PAGE;
	int offset = nr & BITS_PER_PAGE_MASK;

	DebugKVM("started for NID %d\n", nr);
	clear_bit(offset, map->page);
	atomic_inc(&map->nr_free);
}

static int alloc_nidmap(struct kvm_nid_table *nid_table)
{
	int i, offset, max_scan, nid;
	int last = nid_table->last_nid;
	int nid_max_limit = nid_table->nid_max_limit;
	int reserved_nids = nid_table->reserved_nids;
	kvm_nidmap_t *map;

	DebugKVM("started\n");
	nid = last + 1;
	if (nid >= nid_max_limit)
		nid = reserved_nids;
	offset = nid & BITS_PER_PAGE_MASK;
	map = &nid_table->nidmap[nid/BITS_PER_PAGE];
	max_scan = (nid_max_limit + BITS_PER_PAGE - 1)/BITS_PER_PAGE - !offset;
	for (i = 0; i <= max_scan; ++i) {
		if (unlikely(!map->page)) {
			void *page = kzalloc(PAGE_SIZE, GFP_KERNEL);
			/*
			 * Free the page if someone raced with us
			 * installing it:
			 */
			raw_spin_lock_irq(&nid_table->nidmap_lock);
			if (!map->page) {
				map->page = page;
				page = NULL;
			}
			raw_spin_unlock_irq(&nid_table->nidmap_lock);
			kfree(page);
			if (unlikely(!map->page))
				break;
		}
		if (likely(atomic_read(&map->nr_free))) {
			do {
				if (!test_and_set_bit(offset, map->page)) {
					atomic_dec(&map->nr_free);
					nid_table->last_nid = nid;
					DebugKVM("returns NID %d\n", nid);
					return nid;
				}
				offset = find_next_offset(map, offset);
				nid = mk_nid(nid_table, map, offset);
			/*
			 * find_next_offset() found a bit, the nid from it
			 * is in-bounds, and if we fell back to the last
			 * bitmap block and the final block was the same
			 * as the starting point, nid is before last_nid.
			 */
			} while (offset < BITS_PER_PAGE &&
					nid < nid_max_limit &&
					(i != max_scan || nid < last ||
					    !((last+1) & BITS_PER_PAGE_MASK)));
		}
		if (map < &nid_table->nidmap[(nid_max_limit-1) /
							BITS_PER_PAGE]) {
			++map;
			offset = 0;
		} else {
			map = &nid_table->nidmap[0];
			offset = reserved_nids;
			if (unlikely(last == offset))
				break;
		}
		nid = mk_nid(nid_table, map, offset);
	}
	return -1;
}

void kvm_do_free_nid(kvm_nid_t *nid, struct kvm_nid_table *nid_table)
{
	DebugKVM("started\n");
	hlist_del(&nid->nid_chain);

	free_nidmap(nid->nr, nid_table);
}

void kvm_free_nid(kvm_nid_t *nid, struct kvm_nid_table *nid_table)
{
	/* We can be called with write_lock_irq(&tasklist_lock) held */
	unsigned long flags;

	DebugKVM("started\n");
	raw_spin_lock_irqsave(&nid_table->nidmap_lock, flags);
	kvm_do_free_nid(nid, nid_table);
	raw_spin_unlock_irqrestore(&nid_table->nidmap_lock, flags);
}

int kvm_alloc_nid(struct kvm_nid_table *nid_table, kvm_nid_t *nid)
{
	int nr;

	DebugKVM("started\n");

	nr = alloc_nidmap(nid_table);
	if (nr < 0)
		return nr;

	nid->nr = nr;
	DebugKVM("allocated NID %d structure at %px\n", nr, nid);

	raw_spin_lock_irq(&nid_table->nidmap_lock);
	hlist_add_head(&nid->nid_chain,
			&nid_table->nid_hash[nid_hashfn(nr,
						nid_table->nid_hash_bits)]);
	raw_spin_unlock_irq(&nid_table->nidmap_lock);
	return 0;
}

/*
 * The nid hash table is scaled according to the amount of memory in the
 * machine.  From a minimum of 16 slots up to 4096 slots at one gigabyte or
 * more.
 */
static void nidhash_init(struct kvm_nid_table *nid_table)
{
	int i;

	for (i = 0; i < nid_table->nid_hash_size; i++)
		INIT_HLIST_HEAD(&nid_table->nid_hash[i]);
}

int kvm_nidmap_init(struct kvm_nid_table *nid_table,
			int nid_max_limit, int reserved_nids, int last_nid)
{
	int entry;

	DebugKVM("started\n");
	raw_spin_lock_init(&nid_table->nidmap_lock);

	for (entry = 0; entry < nid_table->nidmap_entries; entry++) {
		atomic_set(&nid_table->nidmap[entry].nr_free, BITS_PER_PAGE);
		nid_table->nidmap[entry].page = NULL;
	}
	nid_table->nidmap[0].page = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (nid_table->nidmap[0].page == NULL) {
		pr_err("kvm_nidmap_init() could not allocate first page "
			"for NID map\n");
		return -ENOMEM;
	}

	nid_table->nid_max_limit = nid_max_limit;
	nid_table->reserved_nids = reserved_nids;
	nid_table->last_nid = last_nid;
	nid_table->nid_cachep = NULL;
	nidhash_init(nid_table);

	return 0;
}

void kvm_nidmap_reset(struct kvm_nid_table *nid_table, int last_nid)
{
	DebugKVM("started\n");
	raw_spin_lock_irq(&nid_table->nidmap_lock);
	nid_table->last_nid = last_nid;
	nidhash_init(nid_table);
	raw_spin_unlock_irq(&nid_table->nidmap_lock);
}

static void nidmap_release(struct kvm_nid_table *nid_table)
{
	kvm_nidmap_t *map;
	int entry;

	DebugKVM("started\n");
	for (entry = 0; entry < nid_table->nidmap_entries; entry++) {
		map = &nid_table->nidmap[entry];
		if (atomic_read(&map->nr_free) != BITS_PER_PAGE) {
			printk(KERN_WARNING "nidmap_release() mapping #%d is "
				"not empty, only %d entries from %ld is free\n",
				entry, atomic_read(&map->nr_free),
				BITS_PER_PAGE);
		}
		if (map->page != NULL) {
			kfree(map->page);
			map->page = NULL;
		}
	}
}

void kvm_nidmap_destroy(struct kvm_nid_table *nid_table)
{
	DebugKVM("started\n");
	nidmap_release(nid_table);
}
