#ifndef __E2K_KVM_HOST_MM_H
#define __E2K_KVM_HOST_MM_H

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/kvm.h>

#include <asm/kvm/nid.h>

#define	GMMID_MAX_LIMIT		(GPID_MAX_LIMIT)
#define RESERVED_GMMIDS		1	/* 0 is reserved for init_mm */

#define GMMIDMAP_ENTRIES	((GMMID_MAX_LIMIT + 8*PAGE_SIZE - 1)/	\
				PAGE_SIZE/8)

#define GMMID_HASH_BITS		GPID_HASH_BITS
#define	GMMID_HASH_SIZE		NID_HASH_SIZE(GMMID_HASH_BITS)

/*
 * Guest mm structure agent on host
 * The structure on host is only agent of real mm structure on guest,
 * so sinchronization should be done by guest using real mm semaphores and
 * spinlocks and here on host we does not use locking/unlocking
 */
typedef struct gmm_struct {
	kvm_nid_t nid;			/* numeric ID of the host agent */
					/* of guest mm structure */
	atomic_t mm_count;		/* How many references to guest mm */
					/* shared mm */
#ifdef	CONFIG_KVM_HV_MMU
	hpa_t root_hpa;			/* physical base of root shadow PT */
					/* for guest mm on host */
	gfn_t root_gpa;			/* 'physical' base of guest root PT */
	gpa_t os_pptb;			/* guest kernel root PT physical base */
	gpa_t u_pptb;			/* guest user root PT physical base */
	gva_t os_vptb;			/* guest kernel root PT virtual base */
	gva_t u_vptb;			/* guest user root PT virtual base */
	bool pt_synced;			/* root guest PT was synced with */
					/* host shadow PT */
#endif	/* CONFIG_KVM_HV_MMU */
	spinlock_t page_table_lock;	/* Protects page tables of mm */
	/* MMU context (PID) support */
	mm_context_t context;		/* MMU context (PID) support for */
					/* the guest mm */
	cpumask_t cpu_vm_mask;		/* mask of CPUs where the mm is */
					/* in use or was some early */
	bool in_release;		/* guest mm is in release and cannot */
					/* be used as active */
} gmm_struct_t;

/* same as accessor for struct mm_struct's cpu_vm_mask but for guest mm */
#define gmm_cpumask(gmm) (&(gmm)->cpu_vm_mask)

typedef struct kvm_nid_table gmmid_table_t;

#define gmmid_hashfn(nr)	nid_hashfn(nr, GMMID_HASH_BITS)

struct kvm;

extern int kvm_guest_mm_drop(struct kvm_vcpu *vcpu, int gmmid_nr);
extern int kvm_activate_guest_mm(struct kvm_vcpu *vcpu,
			int active_gmmid_nr, int gmmid_nr, gpa_t u_phys_ptb);
extern int kvm_guest_pv_mm_init(struct kvm *kvm);
extern void kvm_guest_pv_mm_destroy(struct kvm *kvm);

#define	for_each_guest_mm(gmm, entry, next, gmmid_table)	\
		for_each_guest_nid_node(gmm, entry, next, gmmid_table,  \
					nid.nid_chain)
#define gmmid_entry(ptr)	container_of(ptr, gmm_struct_t, nid)
#define	gmmid_table_lock(gmmid_table)	\
		nid_table_lock(gmmid_table)
#define	gmmid_table_unlock(gmmid_table)	\
		nid_table_unlock(gmmid_table)
#define	gmmid_table_lock_irq(gmmid_table)	\
		nid_table_lock_irq(gmmid_table)
#define	gmmid_table_unlock(gmmid_table)	\
		nid_table_unlock(gmmid_table)
#define	gmmid_table_lock_irqsave(gmmid_table, flags)	\
		nid_table_lock_irqsave(gmmid_table, flags)
#define	gmmid_table_unlock_irqrestore(gmmid_table, flags)	\
		nid_table_unlock_irqrestore(gmmid_table, flags)

static inline gmm_struct_t *
kvm_find_gmmid(gmmid_table_t *gmmid_table, int gmmid_nr)
{
	kvm_nid_t *nid;

	nid = kvm_find_nid(gmmid_table, gmmid_nr, gmmid_hashfn(gmmid_nr));
	if (nid == NULL)
		return NULL;
	return gmmid_entry(nid);
}

#endif	/* __E2K_KVM_HOST_MM_H */
