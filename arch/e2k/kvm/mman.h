#ifndef __KVM_E2K_MMAN_H
#define __KVM_E2K_MMAN_H

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/kvm_host.h>
#include <asm/mman.h>

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

extern gmm_struct_t *create_gmm(struct kvm *kvm);
extern void kvm_init_gmm_root_pt(struct kvm *kvm, gmm_struct_t *new_gmm);
extern void kvm_switch_to_init_root_pt(struct kvm_vcpu *vcpu,
						gmm_struct_t *gmm);
extern void kvm_fill_init_root_pt(struct kvm *kvm);
extern void do_free_gmm(gmm_struct_t *gmm, gmmid_table_t *gmmid_table);
extern void gmm_drop(struct kvm *kvm, gmm_struct_t *gmm);

static inline void free_gmm(struct kvm *kvm, gmm_struct_t *gmm)
{
	do_free_gmm(gmm, &kvm->arch.gmmid_table);
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

#ifdef	CONFIG_KVM_HV_MMU
static inline void kvm_gmm_init(gmm_struct_t *gmm)
{
	gmm->root_hpa = E2K_INVALID_PAGE;
}
#else	/* ! CONFIG_KVM_HV_MMU */
static inline void kvm_gmm_init(gmm_struct_t *gmm)
{
}
#endif	/* CONFIG_KVM_HV_MMU */

#endif	/* __KVM_E2K_MMAN_H */
