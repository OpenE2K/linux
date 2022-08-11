#ifndef _ASM_E2K_KVM_GPID_H
#define _ASM_E2K_KVM_GPID_H

/*
 * Guest processes identifier (gpid) allocator
 * Based on simplified include/linux/pid.h
 */

#include <linux/threads.h>
#include <linux/hash.h>

#include <asm/kvm/nid.h>

#define	GPID_MAX_LIMIT		(PID_MAX_LIMIT / 2)
#define RESERVED_GPIDS		300

#define GPIDMAP_ENTRIES		((GPID_MAX_LIMIT + 8*PAGE_SIZE - 1)/PAGE_SIZE/8)

#define GPID_HASH_BITS		4
#define	GPID_HASH_SIZE		NID_HASH_SIZE(GPID_HASH_BITS)

struct kvm;

typedef struct gpid {
	kvm_nid_t nid;
	struct gthread_info *gthread_info;
} gpid_t;

typedef struct kvm_nid_table kvm_gpid_table_t;

#define gpid_hashfn(nr)	nid_hashfn(nr, GPID_HASH_BITS)

extern gpid_t *kvm_alloc_gpid(kvm_gpid_table_t *gpid_table);
extern void kvm_do_free_gpid(gpid_t *gpid, kvm_gpid_table_t *gpid_table);
extern void kvm_free_gpid(gpid_t *gpid, kvm_gpid_table_t *gpid_table);
extern int kvm_gpidmap_init(struct kvm *kvm, kvm_gpid_table_t *gpid_table,
			kvm_nidmap_t *gpid_nidmap, int gpidmap_entries,
			struct hlist_head *gpid_hash, int gpid_hash_bits);
extern void kvm_gpidmap_destroy(kvm_gpid_table_t *gpid_table);

#define	for_each_guest_thread_info(gpid, entry, next, gpid_table)	\
		for_each_guest_nid_node(gpid, entry, next, gpid_table,  \
					nid.nid_chain)
#define gpid_entry(ptr)	container_of(ptr, gpid_t, nid)
#define	gpid_table_lock(gpid_table)	\
		nid_table_lock(gpid_table)
#define	gpid_table_unlock(gpid_table)	\
		nid_table_unlock(gpid_table)
#define	gpid_table_lock_irq(gpid_table)	\
		nid_table_lock_irq(gpid_table)
#define	gpid_table_unlock(gpid_table)	\
		nid_table_unlock(gpid_table)
#define	gpid_table_lock_irqsave(gpid_table, flags)	\
		nid_table_lock_irqsave(gpid_table, flags)
#define	gpid_table_unlock_irqrestore(gpid_table, flags)	\
		nid_table_unlock_irqrestore(gpid_table, flags)

static inline gpid_t *
kvm_find_gpid(kvm_gpid_table_t *gpid_table, int gpid_nr)
{
	kvm_nid_t *nid;

	nid = kvm_find_nid(gpid_table, gpid_nr, gpid_hashfn(gpid_nr));
	if (nid == NULL)
		return NULL;
	return gpid_entry(nid);
}

#endif /* _ASM_E2K_KVM_GPID_H */
