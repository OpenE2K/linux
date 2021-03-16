#ifndef _ASM_E2K_KVM_NID_H
#define _ASM_E2K_KVM_NID_H

/*
 * Numeric identifier (nid) allocator
 */

#include <linux/threads.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/hash.h>

typedef struct kvm_nidmap {
	atomic_t nr_free;	/* number of free elements */
	void *page;
} kvm_nidmap_t;

struct kvm_nid_table {
	raw_spinlock_t nidmap_lock;
	struct kmem_cache *nid_cachep;
	char nid_cache_name[32];
	int nidmap_entries;
	int nid_hash_bits;
	int nid_hash_size;
	kvm_nidmap_t *nidmap;
	struct hlist_head *nid_hash;
	int nid_max_limit;
	int reserved_nids;
	int last_nid;
	unsigned int nidhash_shift;
};

#define	NID_HASH_SIZE(NID_HASH_BITS)	(1 << (NID_HASH_BITS))

typedef	struct kvm_nid {
	int nr;
	struct hlist_node nid_chain;
} kvm_nid_t;

#define nid_hashfn(nr, NID_HASH_BITS)					\
		hash_long((unsigned long)(nr), NID_HASH_BITS)

extern int kvm_alloc_nid(struct kvm_nid_table *nid_table, kvm_nid_t *nid);
extern void kvm_do_free_nid(kvm_nid_t *nid, struct kvm_nid_table *nid_table);
extern void kvm_free_nid(kvm_nid_t *nid, struct kvm_nid_table *nid_table);
extern int kvm_nidmap_init(struct kvm_nid_table *nid_table,
		int nid_max_limit, int reserved_nids, int last_nid);
extern void kvm_nidmap_destroy(struct kvm_nid_table *nid_table);

static inline kvm_nid_t *
kvm_find_nid(struct kvm_nid_table *nid_table, int nid_nr, int hash_index)
{
	kvm_nid_t *nid;
	unsigned long flags;

	raw_spin_lock_irqsave(&nid_table->nidmap_lock, flags);
	hlist_for_each_entry(nid,
			&(nid_table->nid_hash[hash_index]),
			nid_chain) {
		if (nid->nr == nid_nr) {
			raw_spin_unlock_irqrestore(&nid_table->nidmap_lock,
							flags);
			return nid;
		}
	}
	raw_spin_unlock_irqrestore(&nid_table->nidmap_lock, flags);
	return NULL;
}

#define	for_each_guest_nid_node(node, entry, next, nid_table,	\
						nid_hlist_member)	\
	for ((entry) = 0; (entry) < (nid_table)->nid_hash_size; (entry)++) \
		hlist_for_each_entry_safe(node, next,			\
			&((nid_table)->nid_hash[entry]),		\
			nid_hlist_member)
#define	nid_table_lock(nid_table)	\
		raw_spin_lock(&(nid_table)->nidmap_lock)
#define	nid_table_unlock(nid_table)	\
		raw_spin_unlock(&(nid_table)->nidmap_lock)
#define	nid_table_lock_irq(nid_table)	\
		raw_spin_lock_irq(&(nid_table)->nidmap_lock)
#define	nid_table_unlock_irq(nid_table)	\
		raw_spin_unlock_irq(&(nid_table)->nidmap_lock)
#define	nid_table_lock_irqsave(nid_table, flags)	\
		raw_spin_lock_irqsave(&(nid_table)->nidmap_lock, flags)
#define	nid_table_unlock_irqrestore(nid_table, flags)	\
		raw_spin_unlock_irqrestore(&(nid_table)->nidmap_lock, flags)

#endif /* _ASM_E2K_KVM_NID_H */
