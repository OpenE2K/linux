
/*
 * VCPU guest MM  virtualization
 *
 * Based on x86 code, Copyright (c) 2004, Intel Corporation.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/mm.h>
#include <linux/kvm.h>
#include <asm/pgalloc.h>
#include <asm/kvm/gpid.h>
#include <asm/process.h>
#include <asm/kvm/mm.h>
#include "mmu.h"
#include "process.h"
#include "mman.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_GMM_MODE
#undef	DebugGMM
#define	DEBUG_KVM_GMM_MODE	0	/* guest mm freeing */
					/* debugging */
#define	DebugGMM(fmt, args...)						\
({									\
	if (DEBUG_KVM_GMM_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_GMM_FREE_MODE
#undef	DebugKVMF
#define	DEBUG_KVM_GMM_FREE_MODE	0	/* guest mm freeing */
					/* debugging */
#define	DebugKVMF(fmt, args...)						\
({									\
	if (DEBUG_KVM_GMM_FREE_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SHUTDOWN_MODE
#undef	DebugKVMSH
#define	DEBUG_KVM_SHUTDOWN_MODE	1	/* KVM shutdown debugging */
#define	DebugKVMSH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SHUTDOWN_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

/* FIXME: the function is not yet called (see details below)
static void gmm_delete(struct kvm *kvm, gmm_struct_t *gmm);
 */

/*
 * Initialize a new mmu context for guest process.
 * FIXME: is not yet implemented
 */
static	inline int
init_new_gmm_context(struct kvm *kvm, gmm_struct_t *gmm)
{
	DebugKVM("started for gmm #%d\n", gmm->nid.nr);
	kvm_init_new_context(kvm, gmm);
	return 0;
}

static void destroy_gmm_u_context(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	gmm_struct_t *init_gmm = pv_vcpu_get_init_gmm(vcpu);

	/*
	 * update gmm to emulate same as init gmm state before the gmm
	 * will be deleted
	 */

	gmm->root_hpa = init_gmm->root_hpa;
	gmm->root_gpa = init_gmm->root_gpa;

	/* FIXME: the followimg values is not used, probably may be deleted
	gmm->u_pptb = init_gmm->u_pptb;
	gmm->os_pptb = init_gmm->os_pptb;
	 */

	KVM_BUG_ON(gmm == pv_vcpu_get_gmm(vcpu));
	if (gmm == pv_vcpu_get_active_gmm(vcpu)) {
		pv_vcpu_switch_to_init_spt(vcpu, gmm);
	} else if (atomic_read(&gmm->mm_count) == 1) {
		/* gmm has nothing users, so release it */
		kvm_free_gmm(vcpu->kvm, gmm);
	}
}

/*
 * Allocate and initialize host agent of guest mm
 */

static inline void gmm_init(gmm_struct_t *gmm)
{
	atomic_set(&gmm->mm_count, 1);
	spin_lock_init(&gmm->page_table_lock);
	kvm_gmm_init(gmm);
}

static inline gmm_struct_t *do_alloc_gmm(gmmid_table_t *gmmid_table)
{
	gmm_struct_t *gmm;
	int nr;

	gmm = kmem_cache_alloc(gmmid_table->nid_cachep, GFP_KERNEL);
	if (!gmm) {
		DebugKVM("could not allocate guest mm structure\n");
		return NULL;
	}
	memset(gmm, 0, sizeof(*gmm));

	nr = kvm_alloc_nid(gmmid_table, &gmm->nid);
	if (nr < 0) {
		DebugKVM("could not allocate NID for mm structure\n");
		goto out_free;
	}

	gmm_init(gmm);
	DebugKVM("allocated guest mm structure #%d at %px\n",
		gmm->nid.nr, gmm);

out:
	return gmm;

out_free:
	kmem_cache_free(gmmid_table->nid_cachep, gmm);
	gmm = NULL;
	goto out;
}

static inline gmm_struct_t *allocate_gmm(struct kvm *kvm)
{
	return do_alloc_gmm(&kvm->arch.gmmid_table);
}

static inline void do_drop_gmm(gmm_struct_t *gmm, gmmid_table_t *gmmid_table)
{
	DebugKVMF("started for guest mm #%d\n", gmm->nid.nr);
	kmem_cache_free(gmmid_table->nid_cachep, gmm);
}

void do_free_gmm(gmm_struct_t *gmm, gmmid_table_t *gmmid_table)
{
	DebugKVMF("started for guest mm #%d\n", gmm->nid.nr);

	kvm_do_free_nid(&gmm->nid, gmmid_table);
	do_drop_gmm(gmm, gmmid_table);
}

static gmm_struct_t *alloc_gmm(struct kvm *kvm)
{
	gmm_struct_t	*new_gmm;
	int ret;

	new_gmm = allocate_gmm(kvm);
	if (new_gmm == NULL) {
		DebugKVM("could not allocate agent of guest mm structure\n");
		return NULL;
	}

	ret = init_new_gmm_context(kvm, new_gmm);
	if (unlikely(ret != 0)) {
		DebugKVM("could not init MMU context for guest mm\n");
		goto out_free_gmm;
	}
	return new_gmm;

out_free_gmm:
	free_gmm(kvm, new_gmm);
	return NULL;
}

gmm_struct_t *create_gmm(struct kvm *kvm)
{
	gmm_struct_t *new_gmm;

	DebugKVM("started\n");

	new_gmm = alloc_gmm(kvm);
	if (new_gmm == NULL) {
		DebugKVM("could not allocate agent of guest mm structure\n");
		return NULL;
	}

	kvm_init_gmm_root_pt(kvm, new_gmm);

	DebugKVM("created host agent #%d of guest mm structure\n",
		new_gmm->nid.nr);
	return new_gmm;
}

/*
 * Called when the last reference to the guest mm agent is dropped.
 * Free the page directory and the guest mm structure.
 */
void do_gmm_drop(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	DebugGMM("started on for guest MM #%d at %px users %d\n",
		gmm->nid.nr, gmm, atomic_read(&gmm->mm_count));

	if (atomic_read(&gmm->mm_count) > 2) {
		pr_err("%s(): GMM #%d user's counter is %d not empty\n",
			__func__, gmm->nid.nr, atomic_read(&gmm->mm_count));
	}
	release_gmm_root_pt(vcpu, gmm);
}
void gmm_drop(struct kvm *kvm, gmm_struct_t *gmm)
{
	unsigned long flags;

	gmmid_table_lock_irqsave(&kvm->arch.gmmid_table, flags);
	do_gmm_drop(current_thread_info()->vcpu, gmm);
	gmmid_table_unlock_irqrestore(&kvm->arch.gmmid_table, flags);
}

int kvm_guest_mm_drop(struct kvm_vcpu *vcpu, int gmmid_nr)
{
	gmm_struct_t	*active_gmm = pv_vcpu_get_active_gmm(vcpu);
	gthread_info_t	*cur_gti = pv_vcpu_get_gti(vcpu);
	gmm_struct_t	*gmm;

	DebugGMM("started for host agent #%d of guest mm\n", gmmid_nr);
	gmm = kvm_find_gmmid(&vcpu->kvm->arch.gmmid_table, gmmid_nr);
	if (gmm == NULL) {
		pr_err("%s(): could not find gmm host agent GMMID #%d\n",
			__func__, gmmid_nr);
		return -ENODEV;
	}
	BUG_ON(gmm == NULL);
	DebugGMM("host gmm #%d at %px users %d\n",
		gmmid_nr, gmm, atomic_read(&gmm->mm_count));

	if (active_gmm == gmm) {
		DebugGMM("gmm #%d can be now as active, so deactivate it\n",
			gmm->nid.nr);
		KVM_BUG_ON(atomic_read(&gmm->mm_count) < 2);
		kvm_mmu_unload_gmm_root(vcpu);
	} else if (cur_gti && cur_gti->gmm) {
		KVM_BUG_ON(cur_gti->gmm == gmm &&
				!pv_vcpu_is_init_gmm(vcpu, active_gmm));
	}

	gmm_drop(vcpu->kvm, gmm);

	destroy_gmm_u_context(vcpu, gmm);

	return 0;
}

static inline void force_drop_gmm(struct kvm *kvm, gmm_struct_t *gmm)
{
	if (atomic_read(&gmm->mm_count) != 0) {
		pr_err("%s(): gmm GMMID #%d usage counter is %d, should be 0\n",
			__func__, gmm->nid.nr, atomic_read(&gmm->mm_count));
		atomic_set(&gmm->mm_count, 0);
	}
	do_gmm_drop(current_thread_info()->vcpu, gmm);
	free_gmm(kvm, gmm);
}

static void force_exit_gmm(struct kvm *kvm, gthread_info_t *gthread_info)
{
	gmm_struct_t	*gmm = gthread_info->gmm;

	DebugKVM("started for guest MM %px\n", gmm);

	do_gmm_drop(current_thread_info()->vcpu, gmm);
	gthread_info->gmm = NULL;
}

static int kvm_deactivate_gmm(struct kvm_vcpu *vcpu,
			gthread_info_t *gti, gmm_struct_t *gmm)
{
	gmm_struct_t *cur_gmm;
	int gmmid = gmm->nid.nr;

	DebugGMM("started for host gmm agent #%d users %d\n",
		gmmid, atomic_read(&gmm->mm_count));
	KVM_BUG_ON(gmm != gti->gmm);
	KVM_BUG_ON(atomic_read(&gmm->mm_count) < 2);

	cur_gmm = pv_vcpu_get_gmm(vcpu);
	if (gmm == cur_gmm) {
		/* deactivated GMM is not more current active gmm */
		kvm_mmu_unload_gmm_root(vcpu);
	}
	kvm_gmm_only_put(vcpu->kvm, gti);
	DebugGMM("guest mm agent #%d of process agent #%d is deactivated\n",
		gmmid, gti->gpid->nid.nr);

	return 0;
}

int kvm_activate_guest_mm(struct kvm_vcpu *vcpu,
		int active_gmmid_nr, int gmmid_nr, gpa_t u_phys_ptb)
{
	struct kvm *kvm = vcpu->kvm;
	gthread_info_t *cur_gti = pv_vcpu_get_gti(vcpu);
	gmm_struct_t *new_gmm;
	gmm_struct_t *cur_gmm;

	DebugGMM("started for new host agent of new guest mm, pptb at %px\n",
		(void *)u_phys_ptb);
	new_gmm = create_gmm(kvm);
	if (new_gmm == NULL) {
		DebugGMM("could not create new host agent of guest mm\n");
		return -EINVAL;
	}
	gmmid_nr = new_gmm->nid.nr;
	cur_gmm = pv_vcpu_get_gmm(vcpu);
	if (active_gmmid_nr == 0)  {
		DebugGMM("active host agent is init guest mm: %d\n",
			active_gmmid_nr);
		if (!pv_vcpu_is_init_gmm(vcpu, cur_gmm)) {
			pr_err("%s(): active host agent is init guest mm, "
				"but current host agent #%d is not NULL\n",
				__func__, (cur_gmm) ? cur_gmm->nid.nr : -1);
			return -EINVAL;
		}
	} else {
		DebugGMM("active host agent is #%d\n", active_gmmid_nr);
		if (pv_vcpu_is_init_gmm(vcpu, cur_gmm)) {
			GTI_BUG_ON(!cur_gti->gmm_in_release &&
				!test_gti_thread_flag(cur_gti,
						GTIF_KERNEL_THREAD));
		} else if (cur_gmm->nid.nr != active_gmmid_nr &&
				!vcpu->arch.is_hv) {
			pr_err("%s(): active host agent is #%d, but current "
				"host agent #%d is not the same\n",
				__func__, active_gmmid_nr, cur_gmm->nid.nr);
			return -EINVAL;
		}
	}
	BUG_ON(cur_gmm == new_gmm);

	/* deactivate old gmm of this thread */
	if (!pv_vcpu_is_init_gmm(vcpu, cur_gmm)) {
		int ret;

		ret = kvm_deactivate_gmm(vcpu, cur_gti, cur_gmm);
		if (ret) {
			pr_err("%s(): could not deactivate current guest mm, "
				"error %d\n",
				__func__, ret);
			return ret;
		}
	}

	kvm_gmm_get(vcpu, cur_gti, new_gmm);
	return kvm_pv_activate_guest_mm(vcpu, new_gmm, u_phys_ptb);
}

static int kvm_gmmidmap_init(struct kvm *kvm, gmmid_table_t *gmmid_table,
			kvm_nidmap_t *gmmid_nidmap, int gmmidmap_entries,
			struct hlist_head *gmmid_hash, int gmmid_hash_bits)
{
	int ret;

	DebugKVM("started\n");

	gmmid_table->nidmap = gmmid_nidmap;
	gmmid_table->nidmap_entries = gmmidmap_entries;
	gmmid_table->nid_hash = gmmid_hash;
	gmmid_table->nid_hash_bits = gmmid_hash_bits;
	gmmid_table->nid_hash_size = NID_HASH_SIZE(gmmid_hash_bits);
	ret = kvm_nidmap_init(gmmid_table, GMMID_MAX_LIMIT, RESERVED_GMMIDS,
				/* last gmm_id: no reserved, */
				/* init_gmm_id #0 will be allocated first */
				-1);
	if (ret != 0) {
		pr_err("kvm_gmmidmap_init() could not create NID map\n");
		return ret;
	}
	sprintf(gmmid_table->nid_cache_name, "gmm_struct_VM%d",
						kvm->arch.vmid.nr);
	gmmid_table->nid_cachep =
		kmem_cache_create(gmmid_table->nid_cache_name,
					sizeof(gmm_struct_t), 0,
					SLAB_HWCACHE_ALIGN, NULL);
	if (gmmid_table->nid_cachep == NULL) {
		pr_err("kvm_gpidmap_init() could not allocate GMM cache\n");
		return -ENOMEM;
	}
	return 0;
}

/*
 * Delete dropped guest mm from all guest threads
 */
/* FIXME: the function is not yet called (see details above)
static void gmm_delete(struct kvm *kvm, gmm_struct_t *gmm)
{
	gpid_t *gpid;
	struct hlist_node *next;
	unsigned long flags;
	int i;

	DebugKVM("started\n");
	gpid_table_lock_irqsave(&kvm->arch.gpid_table, flags);
	for_each_guest_thread_info(gpid, i, next, &kvm->arch.gpid_table) {
		if (gpid->gthread_info->gmm == gmm) {
			gpid->gthread_info->gmm = NULL;
		}
	}
	gpid_table_unlock_irqrestore(&kvm->arch.gpid_table, flags);
}
 */

int kvm_guest_pv_mm_init(struct kvm *kvm)
{
	int ret;

	DebugKVM("started\n");

	ret = kvm_gmmidmap_init(kvm, &kvm->arch.gmmid_table,
				kvm->arch.gmmid_nidmap, GMMIDMAP_ENTRIES,
				kvm->arch.gmmid_hash, GMMID_HASH_BITS);
	if (ret) {
		DebugKVM("could not create ID mapping for host agents of "
			"guest MMs structures\n");
		return ret;
	}
	kvm->arch.init_gmm = alloc_gmm(kvm);
	if (kvm->arch.init_gmm == NULL) {
		DebugKVM("could not allocate agent of guest init mm "
			"structure\n");
		return -ENOMEM;
	}
	DebugKVM("created guest init mm agent #%d at %px\n",
		kvm->arch.init_gmm->nid.nr, kvm->arch.init_gmm);

	kvm_fill_init_root_pt(kvm);

	return ret;
}

void kvm_guest_pv_mm_destroy(struct kvm *kvm)
{
	gpid_t *gpid;
	gmm_struct_t *gmm;
	struct hlist_node *next;
	int i;

	DebugKVMSH("started\n");
	gpid_table_lock(&kvm->arch.gpid_table);
	for_each_guest_thread_info(gpid, i, next, &kvm->arch.gpid_table) {
		if (gpid->gthread_info->gmm != NULL)
			kvm_gmm_put(kvm, gpid->gthread_info);
	}
	for_each_guest_thread_info(gpid, i, next, &kvm->arch.gpid_table) {
		if (gpid->gthread_info->gmm != NULL) {
			pr_err("%s(): could not free mm on GPID %d\n",
				__func__, gpid->nid.nr);
			force_exit_gmm(kvm, gpid->gthread_info);
		}
	}
	gpid_table_unlock(&kvm->arch.gpid_table);
	gmmid_table_lock(&kvm->arch.gmmid_table);
	for_each_guest_mm(gmm, i, next, &kvm->arch.gmmid_table) {
		if (gmm != pv_mmu_get_init_gmm(kvm)) {
			pr_err("%s(): mm %px #%d is not used by any task, "
				"but is not free\n",
				__func__, gmm, gmm->nid.nr);
		}
		force_drop_gmm(kvm, gmm);
	}
	gmmid_table_unlock(&kvm->arch.gmmid_table);
	kvm_nidmap_destroy(&kvm->arch.gmmid_table);
	kmem_cache_destroy(kvm->arch.gmmid_table.nid_cachep);
	kvm->arch.gmmid_table.nid_cachep = NULL;
}
