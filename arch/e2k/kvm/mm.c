
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
#include <asm/kvm/gva_cache.h>
#include <asm/kvm/ctx_signal_stacks.h>
#include "mmu.h"
#include "process.h"
#include "mman.h"

#include "mmutrace-e2k.h"

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

#undef	DEBUG_KVM_FREE_GMM_SP_MODE
#undef	DebugFGMM
#define	DEBUG_KVM_FREE_GMM_SP_MODE	0	/* guest mm SPs freeing */
						/* debug */
#define	DebugFGMM(fmt, args...)						\
({									\
	if (DEBUG_KVM_FREE_GMM_SP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SHUTDOWN_MODE
#undef	DebugKVMSH
#define	DEBUG_KVM_SHUTDOWN_MODE	0	/* KVM shutdown debugging */
#define	DebugKVMSH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SHUTDOWN_MODE || kvm_debug)			\
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
	DebugKVM("started for gmm #%d\n", gmm->id);
	kvm_init_new_context(kvm, gmm);
	gmm_init_cpumask(gmm);

#ifdef CONFIG_KVM_GVA_CACHE
	/* Allocate gva->gpa cache for this process */
	gmm->gva_cache = gva_cache_init();
#endif /* CONFIG_KVM_GVA_CACHE */

	return 0;
}

static void destroy_gmm_u_context(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	struct kvm *kvm = vcpu->kvm;
	gthread_info_t *gti;
	gpid_t *gpid;
	struct hlist_node *next;
	int gmm_count, i;

	/*
	 * root PT should be already deleted
	 */
	KVM_BUG_ON(VALID_PAGE(gmm->root_hpa));
	gmm->root_gpa = E2K_INVALID_PAGE;

	KVM_BUG_ON(gmm == pv_vcpu_get_gmm(vcpu));
	KVM_BUG_ON(gmm == pv_vcpu_get_active_gmm(vcpu));

	/*
	 * GMM context is distroying, but some GTIs can have reference to it,
	 * so dereference this gmm structure for all gti structures
	 */
	gmm_count = atomic_read(&gmm->mm_count);
	if (gmm_count > 1) {
		/* there is(are) some gti with reference to this gmm */
		gpid_table_lock(&kvm->arch.gpid_table);
		for_each_guest_thread_info(gpid, i, next, &kvm->arch.gpid_table) {
			gti = gpid->gthread_info;
			if (likely(gti->gmm != gmm))
				continue;
			kvm_gmm_only_put(kvm, gti);
			trace_kvm_gmm_put("destroy gmm context, dereference gmm "
				"for all gti",
				vcpu, gti, gmm);
			gmm_count--;
			if (gmm_count <= 1)
				break;
		}
		gpid_table_unlock(&kvm->arch.gpid_table);
	}
	if (unlikely(atomic_read(&gmm->mm_count) != 1)) {
		pr_err("%s(): gmm user's counter should be now 1, but it is %d\n",
			__func__, atomic_read(&gmm->mm_count));
		atomic_set(&gmm->mm_count, 1);
		trace_kvm_gmm_put("destroy gmm context, so clear gmm counter",
			vcpu, NULL, gmm);
	}
	kvm_free_gmm(vcpu->kvm, gmm);
}

/*
 * Allocate and initialize host agent of guest mm
 */

static inline void gmm_init(gmm_struct_t *gmm)
{
	atomic_set(&gmm->mm_count, 1);
	spin_lock_init(&gmm->page_table_lock);
	gmm->root_hpa = E2K_INVALID_PAGE;
	gmm->gk_root_hpa = E2K_INVALID_PAGE;
#ifdef	CONFIG_GUEST_MM_SPT_LIST
	INIT_LIST_HEAD(&gmm->spt_list);
	spin_lock_init(&gmm->spt_list_lock);
	gmm->spt_list_size = 0;
	gmm->total_released = 0;
#endif	/* CONFIG_GUEST_MM_SPT_LIST */
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

	gmm_init(gmm);

	nr = kvm_alloc_nid(gmmid_table, &gmm->nid);
	if (nr < 0) {
		DebugKVM("could not allocate NID for mm structure\n");
		goto out_free;
	}
	gmm->id = gmm->nid.nr;
	DebugKVM("allocated guest mm structure #%d at %px\n",
		gmm->id, gmm);

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
	DebugKVMF("started for guest mm #%d\n", gmm->id);
#ifdef CONFIG_KVM_GVA_CACHE
	gva_cache_erase(gmm->gva_cache);
	gmm->gva_cache = NULL;
#endif /* CONFIG_KVM_GVA_CACHE */
	kmem_cache_free(gmmid_table->nid_cachep, gmm);
}

void do_free_gmm(struct kvm *kvm, gmm_struct_t *gmm, gmmid_table_t *gmmid_table)
{
	DebugKVMF("started for guest mm #%d\n", gmm->id);

	if (atomic_read(&gmm->mm_count) != 1) {
		pr_err("%s(): gmm #%d users counter is %d - not empty\n",
			__func__, gmm->id, atomic_read(&gmm->mm_count));
	}
	if (!kvm_is_empty_gmm_spt_list(gmm)) {
		pr_err("%s(): gmm #%d SP list is not empty, force release\n",
			__func__, gmm->id);
		kvm_delete_gmm_sp_list(kvm, gmm);
	}

	if (gmm->ctx_stacks) {
		free_gst_ctx_sig_stacks_ht(gmm->ctx_stacks);
	}

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
	trace_kvm_gmm_get("create new gmm",
		NULL, NULL, new_gmm);

	kvm_init_gmm_root_pt(kvm, new_gmm);

	DebugKVM("created host agent #%d of guest mm structure\n",
		new_gmm->id);
	return new_gmm;
}

/*
 * Called when the last reference to the guest mm agent is dropped.
 * Free the page directory and the guest mm structure.
 */
static void do_gmm_drop(struct kvm *kvm, gmm_struct_t *gmm)
{
	DebugGMM("started on for guest MM #%d at %px users %d\n",
		gmm->id, gmm, atomic_read(&gmm->mm_count));

	if (atomic_read(&gmm->mm_count) > 2 && gmm != pv_mmu_get_init_gmm(kvm)) {
		pr_err("%s(): GMM #%d user's counter is %d not empty\n",
			__func__, gmm->id, atomic_read(&gmm->mm_count));
	}
	release_gmm_root_pt(kvm, gmm);
}
void gmm_drop(struct kvm *kvm, gmm_struct_t *gmm)
{
	unsigned long flags;

	gmmid_table_lock_irqsave(&kvm->arch.gmmid_table, flags);
	do_gmm_drop(kvm, gmm);
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

	DebugFGMM("gmm #%d before release has 0x%lx SPs\n",
		gmm->id, kvm_get_gmm_spt_list_size(gmm));

	if (active_gmm == gmm) {
		DebugGMM("gmm #%d can be now as active, so deactivate it\n",
			gmm->id);
		KVM_BUG_ON(atomic_read(&gmm->mm_count) < 2);
		kvm_mmu_unload_gmm_root(vcpu);
	} else if (cur_gti && cur_gti->gmm) {
		KVM_BUG_ON(cur_gti->gmm == gmm &&
				!pv_vcpu_is_init_gmm(vcpu, active_gmm));
	}

	release_gmm_root_pt(vcpu->kvm, gmm);

	DebugFGMM("gmm #%d after release has 0x%lx SPs, total released 0x%lx\n",
		gmm->id, kvm_get_gmm_spt_list_size(gmm),
		kvm_get_gmm_spt_total_released(gmm));

	if (!kvm_is_empty_gmm_spt_list(gmm)) {
		kvm_delete_gmm_sp_list(vcpu->kvm, gmm);
		KVM_WARN_ON(true);
	}

	destroy_gmm_u_context(vcpu, gmm);

	return 0;
}

static inline void force_drop_gmm(struct kvm *kvm, gmm_struct_t *gmm)
{
	if (atomic_read(&gmm->mm_count) != 1) {
		if (gmm != pv_mmu_get_init_gmm(kvm)) {
			DebugGMM("gmm #%d usage counter is %d, should be 1\n",
				gmm->id, atomic_read(&gmm->mm_count));
		}
		atomic_set(&gmm->mm_count, 1);
		trace_kvm_gmm_put("force drop guest mm, so clear gmm counter",
			NULL, NULL, gmm);
	}
	do_gmm_drop(kvm, gmm);
	free_gmm(kvm, gmm);
}

static void force_exit_gmm(struct kvm *kvm, gthread_info_t *gthread_info)
{
	gmm_struct_t *gmm = gthread_info->gmm;

	DebugKVM("started for guest MM %px\n", gmm);

	gmm_drop(kvm, gmm);
	gthread_info->gmm = NULL;
}

static int kvm_deactivate_gmm(struct kvm_vcpu *vcpu,
			gthread_info_t *gti, gmm_struct_t *gmm)
{
	gmm_struct_t *cur_gmm;
	int gmmid = gmm->id;

	DebugGMM("started for host gmm agent #%d users %d\n",
		gmmid, atomic_read(&gmm->mm_count));
	KVM_BUG_ON(gmm != gti->gmm);
	if (unlikely(atomic_read(&gmm->mm_count) < 2)) {
		pr_err("%s(): gmm #%d count %d but should be >= 2\n",
			__func__, gmmid, atomic_read(&gmm->mm_count));
	}

	cur_gmm = pv_vcpu_get_gmm(vcpu);
	if (gmm == cur_gmm) {
		/* deactivated GMM is not more current active gmm */
		kvm_mmu_unload_gmm_root(vcpu);
	}
	kvm_gmm_only_put(vcpu->kvm, gti);
	trace_kvm_gmm_put("deactivate gmm", vcpu, gti, gmm);
	DebugGMM("guest mm agent #%d of process agent #%d is deactivated\n",
		gmmid, gti->gpid->nid.nr);

	return 0;
}

int kvm_activate_guest_mm(struct kvm_vcpu *vcpu,
		int active_gmmid_nr, int gmmid_nr, gpa_t u_phys_ptb)
{
	struct kvm *kvm = vcpu->kvm;
	gthread_info_t *cur_gti = pv_vcpu_get_gti(vcpu);
	gmm_struct_t *new_gmm, *old_gmm, *cur_gmm;

	DebugGMM("started for new host agent of new guest mm, pptb at %px\n",
		(void *)u_phys_ptb);
	new_gmm = create_gmm(kvm);
	if (new_gmm == NULL) {
		DebugGMM("could not create new host agent of guest mm\n");
		return -EINVAL;
	}

	/* Allocate new hash table for guest context signal stacks */
	new_gmm->ctx_stacks = alloc_gst_ctx_sig_stacks_ht();

	cur_gmm = pv_vcpu_get_gmm(vcpu);
	if (!pv_vcpu_is_init_gmm(vcpu, cur_gmm)) {
		/* current gmm should have been switched to init gmm */
		pr_err("%s(): active gmm #%d is not init guest\n",
			__func__, cur_gmm->id);
	}

	old_gmm = cur_gti->gmm;
	if (likely(active_gmmid_nr > 0)) {
		/* old process was user guest process */
		DebugGMM("guest old gmm is #%d\n", active_gmmid_nr);
		if (old_gmm && old_gmm->id != active_gmmid_nr &&
							!vcpu->arch.is_hv) {
			pr_err("%s(): old host gmm is #%d, but guest old "
				"gmm #%d is not the same\n",
				__func__, old_gmm->id, active_gmmid_nr);
		}
		KVM_BUG_ON(old_gmm == NULL);
	} else {
		/* old task was guest kernel thread */
		DebugGMM("guest old gmm is #%d (init gmm)\n", active_gmmid_nr);
		if (old_gmm && !pv_vcpu_is_init_gmm(vcpu, old_gmm) &&
							!vcpu->arch.is_hv) {
			pr_err("%s(): old guest gmm is init #%d, but host old "
				"gmm #%d is not the init too\n",
				__func__, active_gmmid_nr, old_gmm->id);
		}
		KVM_BUG_ON(old_gmm != NULL);
	}

	/* deactivate old gmm of this thread */
	if (likely(old_gmm && !pv_vcpu_is_init_gmm(vcpu, old_gmm))) {
		int ret;

		ret = kvm_deactivate_gmm(vcpu, cur_gti, old_gmm);
		if (ret) {
			pr_err("%s(): could not deactivate old guest mm, "
				"error %d\n",
				__func__, ret);
			return ret;
		}
	}

	kvm_gmm_get(vcpu, cur_gti, new_gmm);
	trace_kvm_gmm_get("activate new guest mm", vcpu, cur_gti, new_gmm);

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
		pr_err("kvm_gmmidmap_init() could not allocate GMM cache\n");
		return -ENOMEM;
	}
	return 0;
}

static void kvm_gmmidmap_reset(struct kvm *kvm, gmmid_table_t *gmmid_table)
{
	kvm_nidmap_reset(gmmid_table,
			 -1	/* init_gmm_id #0 will be allocated first */);
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

int kvm_pv_init_gmm_create(struct kvm *kvm)
{
	DebugKVMSH("started\n");

	kvm->arch.init_gmm = alloc_gmm(kvm);
	if (kvm->arch.init_gmm == NULL) {
		pr_err("%s(): could not allocate agent of guest init mm "
			"structure\n", __func__);
		return -ENOMEM;
	}
	trace_kvm_gmm_get("create init gmm",
		NULL, NULL, kvm->arch.init_gmm);
	DebugKVMSH("created guest init mm agent #%d at %px\n",
		kvm->arch.init_gmm->id, kvm->arch.init_gmm);

	kvm_fill_init_root_pt(kvm);

	return 0;
}

int kvm_guest_pv_mm_init(struct kvm *kvm)
{
	int ret;

	DebugKVMSH("started\n");

	ret = kvm_gmmidmap_init(kvm, &kvm->arch.gmmid_table,
				kvm->arch.gmmid_nidmap, GMMIDMAP_ENTRIES,
				kvm->arch.gmmid_hash, GMMID_HASH_BITS);
	if (ret) {
		DebugKVM("could not create ID mapping for host agents of "
			"guest MMs structures\n");
	}

	return ret;
}

void kvm_guest_pv_mm_reset(struct kvm *kvm)
{
	DebugKVMSH("started\n");

	kvm_gmmidmap_reset(kvm, &kvm->arch.gmmid_table);
	pv_mmu_clear_init_gmm(kvm);
}

void kvm_guest_pv_mm_free(struct kvm *kvm)
{
	gpid_t *gpid;
	gthread_info_t *gti;
	gmm_struct_t *gmm;
	struct hlist_node *next;
	int i;

	DebugKVMSH("started\n");

	/* release nonpaging PTs */
	spin_lock(&kvm->mmu_lock);
	if (likely(VALID_PAGE(kvm->arch.nonp_root_hpa))) {
		DebugKVMSH("will release nonpaging SPTs at 0x%llx\n",
			kvm->arch.nonp_root_hpa);
		mmu_release_spt_nonpaging_root(kvm, kvm->arch.nonp_root_hpa);
		kvm->arch.nonp_root_hpa = E2K_INVALID_PAGE;
	} else if (IS_E2K_INVALID_PAGE(kvm->arch.nonp_root_hpa)) {
		DebugKVMSH("nonpaging SPTs already were released\n");
	} else if (ERROR_PAGE(kvm->arch.nonp_root_hpa)) {
		DebugKVMSH("root nonpaging SPT creation has been failed, "
			"error %ld\n",
			PAGE_TO_ERROR(kvm->arch.nonp_root_hpa));
	} else {
		KVM_BUG_ON(true);
	}
	spin_unlock(&kvm->mmu_lock);

	gpid_table_lock(&kvm->arch.gpid_table);
	for_each_guest_thread_info(gpid, i, next, &kvm->arch.gpid_table) {
		gti = gpid->gthread_info;
		gmm = gti->gmm;
		if (gmm != NULL) {
			kvm_gmm_put_and_drop(kvm, gpid->gthread_info);
			trace_kvm_gmm_put("drop guest mm and free gmm",
				NULL, gti, gmm);
		}
	}
	for_each_guest_thread_info(gpid, i, next, &kvm->arch.gpid_table) {
		gti = gpid->gthread_info;
		gmm = gti->gmm;
		if (gmm != NULL) {
			pr_err("%s(): could not free mm on GPID %d\n",
				__func__, gpid->nid.nr);
			force_exit_gmm(kvm, gti);
			trace_kvm_gmm_put("drop guest mm and free gmm",
				NULL, gti, gmm);
		}
	}
	gpid_table_unlock(&kvm->arch.gpid_table);
	gmmid_table_lock(&kvm->arch.gmmid_table);
	for_each_guest_mm(gmm, i, next, &kvm->arch.gmmid_table) {
		force_drop_gmm(kvm, gmm);
	}
	gmmid_table_unlock(&kvm->arch.gmmid_table);

	/* release init gmm */
	pv_mmu_clear_init_gmm(kvm);
}

void kvm_guest_pv_mm_destroy(struct kvm *kvm)
{
	kvm_guest_pv_mm_free(kvm);
	kvm_nidmap_destroy(&kvm->arch.gmmid_table);
	kmem_cache_destroy(kvm->arch.gmmid_table.nid_cachep);
	kvm->arch.gmmid_table.nid_cachep = NULL;
}
