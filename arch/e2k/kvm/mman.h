#ifndef __KVM_E2K_MMAN_H
#define __KVM_E2K_MMAN_H

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/kvm_host.h>
#include <asm/mman.h>
#include <asm/e2k_debug.h>

#undef	DEBUG_KVM_MM_MODE
#undef	DebugKVMMM
#define	DEBUG_KVM_MM_MODE	0	/* host kernel MM debugging */
#define	DebugKVMMM(fmt, args...)					\
({									\
	if (DEBUG_KVM_MM_MODE)						\
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

#undef	DEBUG_KVM_SP_LIST_GMM_MODE
#undef	DebugSPGMM
#define	DEBUG_KVM_SP_LIST_GMM_MODE	0	/* guest mm : SP list add */
						/* delete debug */
#define	DEBUG_EXCLUDE_INIT_GMM		false
#define	DebugSPGMM(fmt, args...)					\
({									\
	if (DEBUG_KVM_SP_LIST_GMM_MODE) {				\
		if (DEBUG_EXCLUDE_INIT_GMM && gmm->nid.nr == 0) {	\
			;						\
		} else {						\
			pr_info("%s(): " fmt, __func__, ##args);	\
		}							\
	}								\
})

#undef	DEBUG_KVM_FREE_GMM_SP_MODE
#undef	DebugFGMM
#define	DEBUG_KVM_FREE_GMM_SP_MODE	0	/* guest mm SPs freeing */
						/* debug */
#define	DebugFGMM(fmt, args...)						\
({									\
	if (DEBUG_KVM_FREE_GMM_SP_MODE || kvm_debug)			\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

extern gmm_struct_t *create_gmm(struct kvm *kvm);
extern void kvm_init_gmm_root_pt(struct kvm *kvm, gmm_struct_t *new_gmm);
extern void kvm_switch_to_init_root_pt(struct kvm_vcpu *vcpu,
						gmm_struct_t *gmm);
extern void kvm_fill_init_root_pt(struct kvm *kvm);
extern void do_free_gmm(struct kvm *kvm, gmm_struct_t *gmm,
			gmmid_table_t *gmmid_table);
extern void gmm_drop(struct kvm *kvm, gmm_struct_t *gmm);

static inline void free_gmm(struct kvm *kvm, gmm_struct_t *gmm)
{
	do_free_gmm(kvm, gmm, &kvm->arch.gmmid_table);
}

static inline void kvm_free_gmm(struct kvm *kvm, gmm_struct_t *gmm)
{
	unsigned long flags;

	gmmid_table_lock_irqsave(&kvm->arch.gmmid_table, flags);
	free_gmm(kvm, gmm);
	gmmid_table_unlock_irqrestore(&kvm->arch.gmmid_table, flags);
}

static inline void do_gmm_get(gmm_struct_t *gmm)
{
	atomic_inc(&gmm->mm_count);
}

static inline void kvm_gmm_get(struct kvm_vcpu *vcpu, gthread_info_t *gti,
				gmm_struct_t *gmm)
{
	do_gmm_get(gmm);
	if (likely(!pv_vcpu_is_init_gmm(vcpu, gmm))) {
		gti->gmm = gmm;
		gti->gmm_in_release = false;
	}
	DebugGMM("GPID #%d guest mm #%d at %px has now %d users\n",
		gti->gpid->nid.nr, gmm->nid.nr, gmm,
		atomic_read(&gmm->mm_count));
}
static inline int do_gmm_put(struct kvm *kvm, gmm_struct_t *gmm)
{
	int count;

	count = atomic_dec_return(&gmm->mm_count);
	KVM_BUG_ON(count <= 0);
	return count;
}
static inline int kvm_do_gmm_put(struct kvm *kvm, gthread_info_t *gti,
				 bool only_put)
{
	gmm_struct_t *gmm;
	int count;

	if (likely(!test_gti_thread_flag(gti, GTIF_KERNEL_THREAD))) {
		gmm = gti->gmm;
	} else {
		gmm = pv_mmu_get_init_gmm(kvm);
	}
	DebugGMM("started for guest thread GPID #%d, gmm #%d users %d\n",
		gti->gpid->nid.nr, gmm->nid.nr, atomic_read(&gmm->mm_count));

	count = do_gmm_put(kvm, gmm);
	gti->gmm = NULL;
	if (!only_put && count == 1) {
		/* nothing users gmm has now, so can be released */
		kvm_free_gmm(kvm, gmm);
		count--;
	}
	return count;
}
static inline int kvm_gmm_put(struct kvm *kvm, gthread_info_t *gti)
{
	return kvm_do_gmm_put(kvm, gti, false);
}
static inline int kvm_gmm_only_put(struct kvm *kvm, gthread_info_t *gti)
{
	return kvm_do_gmm_put(kvm, gti, true);
}

static inline void kvm_check_pgd(pgd_t *pgd)
{
	int	ptr;
	pgd_t	*cur_pgd;

	BUG_ON(pgd == NULL);
	for (ptr = 0; ptr < USER_PTRS_PER_PGD; ptr++) {
		cur_pgd = pgd + ptr;
		if (!pgd_none(*cur_pgd)) {
			pgd_ERROR(*cur_pgd);
			pr_err("is not empty current pgd #0x%x %px = 0x%lx\n",
				ptr, cur_pgd, pgd_val(*cur_pgd));
			*cur_pgd = __pgd(0);
		}
	}
}

#ifdef	CONFIG_GUEST_MM_SPT_LIST
static inline void kvm_init_sp_gmm_entry(struct kvm_mmu_page *sp)
{
	INIT_LIST_HEAD(&sp->gmm_entry);
	sp->gmm = NULL;
}
static inline size_t kvm_get_gmm_spt_list_size(gmm_struct_t *gmm)
{
	return gmm->spt_list_size;
}
static inline size_t kvm_get_gmm_spt_total_released(gmm_struct_t *gmm)
{
	return gmm->total_released;
}
static inline bool kvm_is_empty_gmm_spt_list(gmm_struct_t *gmm)
{
	bool is_empty;
	size_t list_size;

	spin_lock(&gmm->spt_list_lock);
	is_empty = list_empty(&gmm->spt_list);
	list_size = gmm->spt_list_size;
	spin_unlock(&gmm->spt_list_lock);

	KVM_BUG_ON(is_empty && list_size != 0);
	KVM_BUG_ON(!is_empty && list_size == 0);

	return is_empty;
}
static inline bool kvm_is_not_empty_gmm_spt_list(gmm_struct_t *gmm)
{
	return !kvm_is_empty_gmm_spt_list(gmm);
}
static inline void
kvm_add_sp_to_gmm_list(gmm_struct_t *gmm, struct kvm_mmu_page *sp)
{
	KVM_BUG_ON(!list_empty(&sp->gmm_entry));

	spin_lock(&gmm->spt_list_lock);
	list_add_tail(&sp->gmm_entry, &gmm->spt_list);
	gmm->spt_list_size++;
	sp->gmm = gmm;
	spin_unlock(&gmm->spt_list_lock);

	KVM_BUG_ON(gmm->spt_list_size <= 0);

	DebugSPGMM("gmm #%d : SP #%ld for GFN 0x%llx, role 0x%x GVA 0x%lx\n",
		gmm->nid.nr, gmm->spt_list_size - 1, sp->gfn, sp->role.word,
		sp->gva);
}
static inline void
kvm_try_add_sp_to_gmm_list(gmm_struct_t *gmm, struct kvm_mmu_page *sp)
{
	if (unlikely(!list_empty(&sp->gmm_entry))) {
		/* SP already at the some list, probably it is good */
		if (sp->gmm == gmm) {
			/* the gmm is the one it need */
			return;
		}
	}
	kvm_add_sp_to_gmm_list(gmm, sp);
}
static inline void
kvm_init_root_gmm_spt_list(gmm_struct_t *gmm, struct kvm_mmu_page *root_sp)
{
	kvm_add_sp_to_gmm_list(gmm, root_sp);
}
static inline void
kvm_set_root_gmm_spt_list(gmm_struct_t *gmm)
{
	struct kvm_mmu_page *sp;

	KVM_BUG_ON(!VALID_PAGE(gmm->root_hpa));

	sp = page_header(gmm->root_hpa);
	kvm_init_root_gmm_spt_list(gmm, sp);
}
static inline void
kvm_delete_sp_from_the_gmm_list(gmm_struct_t *gmm, struct kvm_mmu_page *sp)
{
	KVM_BUG_ON(list_empty(&sp->gmm_entry));
	KVM_BUG_ON(list_empty(&gmm->spt_list));
	KVM_BUG_ON(sp->gmm != gmm);

	spin_lock(&gmm->spt_list_lock);
	list_del_init(&sp->gmm_entry);
	gmm->spt_list_size--;
	gmm->total_released++;
	sp->gmm = NULL;
	spin_unlock(&gmm->spt_list_lock);

	KVM_BUG_ON(gmm->spt_list_size < 0);

	DebugSPGMM("gmm #%d : SP #%ld for GFN 0x%llx, role 0x%x GVA 0x%lx\n",
		gmm->nid.nr, gmm->spt_list_size, sp->gfn, sp->role.word,
		sp->gva);
}
static inline void
kvm_delete_sp_from_gmm_list(struct kvm_mmu_page *sp)
{
	gmm_struct_t *gmm;

	gmm = sp->gmm;
	if (sp->role.direct && gmm == NULL)
		return;

	kvm_delete_sp_from_the_gmm_list(gmm, sp);
}
static inline gmm_struct_t *
kvm_get_page_fault_gmm(struct kvm_vcpu *vcpu, u32 error_code)
{
	gmm_struct_t *gmm;

	if (vcpu->arch.is_hv)
		return NULL;

	if (error_code & PFERR_USER_MASK) {
		gmm = pv_vcpu_get_gmm(vcpu);
	} else {
		gmm = pv_vcpu_get_init_gmm(vcpu);
	}

	KVM_BUG_ON(gmm == NULL);

	return gmm;
}
static inline gmm_struct_t *
kvm_get_faulted_addr_gmm(struct kvm_vcpu *vcpu, gva_t faulted_gva)
{
	gmm_struct_t *gmm;

	if (vcpu->arch.is_hv)
		return NULL;

	if (faulted_gva < GUEST_TASK_SIZE) {
		gmm = pv_vcpu_get_gmm(vcpu);
	} else {
		gmm = pv_vcpu_get_init_gmm(vcpu);
	}

	KVM_BUG_ON(gmm == NULL);

	return gmm;
}
static inline void
kvm_delete_gmm_sp_list(struct kvm *kvm, gmm_struct_t *gmm)
{
	struct kvm_mmu_page *sp, *nsp;

	if (kvm_is_empty_gmm_spt_list(gmm))
		return;

	DebugFGMM("gmm #%d before SP list release has 0x%lx SPs\n",
		gmm->nid.nr, gmm->spt_list_size);

	list_for_each_entry_safe(sp, nsp, &gmm->spt_list, gmm_entry) {
		DebugFGMM("gmm #%d : SP #%ld for GFN 0x%llx, role 0x%x "
			"GVA 0x%lx\n",
			gmm->nid.nr, gmm->spt_list_size, sp->gfn,
			sp->role.word, sp->gva);
		kvm_mmu_free_page(kvm, sp);
	}

	DebugFGMM("gmm #%d after release has 0x%lx SPs, total released 0x%lx\n",
		gmm->nid.nr, gmm->spt_list_size, gmm->total_released);
}
#else	/* !CONFIG_GUEST_MM_SPT_LIST */
static inline size_t kvm_get_gmm_spt_list_size(gmm_struct_t *gmm)
{
	return 0;
}
static inline size_t kvm_get_gmm_spt_total_released(gmm_struct_t *gmm)
{
	return 0;
}
static inline void
kvm_init_sp_gmm_entry(struct kvm_mmu_page *sp)
{
}
static inline bool kvm_is_empty_gmm_spt_list(gmm_struct_t *gmm)
{
	return true;
}
static inline bool kvm_is_not_empty_gmm_spt_list(gmm_struct_t *gmm)
{
	/* should be not empty at any case */
	return true;
}
static inline void
kvm_add_sp_to_gmm_list(gmm_struct_t *gmm, struct kvm_mmu_page *sp)
{
}
static inline void
kvm_try_add_sp_to_gmm_list(gmm_struct_t *gmm, struct kvm_mmu_page *sp)
{
}
static inline void
kvm_set_root_gmm_spt_list(gmm_struct_t *gmm)
{
}
static inline void
kvm_init_root_gmm_spt_list(gmm_struct_t *gmm, struct kvm_mmu_page *root_sp)
{
}
static inline void
kvm_delete_sp_from_the_gmm_list(gmm_struct_t *gmm, struct kvm_mmu_page *sp)
{
}
static inline void
kvm_delete_sp_from_gmm_list(struct kvm_mmu_page *sp)
{
}
static inline gmm_struct_t *
kvm_get_page_fault_gmm(struct kvm_vcpu *vcpu, u32 error_code)
{
	return NULL;
}
static inline gmm_struct_t *
kvm_get_faulted_addr_gmm(struct kvm_vcpu *vcpu, gva_t faulted_gva)
{
	return NULL;
}
static inline void
kvm_delete_gmm_sp_list(struct kvm *kvm, gmm_struct_t *gmm)
{
}
#endif	/* CONFIG_GUEST_MM_SPT_LIST */

#endif	/* __KVM_E2K_MMAN_H */
