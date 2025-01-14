/*
 * KVM guest kernel virtual space context support
 * Copyright 2016 Salavat S. Gilyazov (atic@mcst.ru)
 */

#ifndef _E2K_KVM_GMMU_CONTEXT_H
#define _E2K_KVM_GMMU_CONTEXT_H

#include <linux/types.h>
#include <linux/kvm_host.h>
#include <asm/pgtable_def.h>
#include <asm/tlbflush.h>
#include <asm/pgd.h>
#include <asm/kvm/thread_info.h>
#include <asm/kvm/mmu.h>

#undef	DEBUG_KVM_SWITCH_MODE
#undef	DebugKVMSW
#define	DEBUG_KVM_SWITCH_MODE	0	/* switch mm debugging */
#define	DebugKVMSW(fmt, args...)					\
({									\
	if (DEBUG_KVM_SWITCH_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#define GUEST_USER_PTRS_PER_PGD		(GUEST_PAGE_OFFSET / PGDIR_SIZE)
#define	GUEST_USER_PGD_PTRS_START	0
#define	GUEST_USER_PGD_PTRS_END		GUEST_USER_PTRS_PER_PGD
#define	GUEST_KERNEL_PGD_PTRS_START	GUEST_USER_PGD_PTRS_END
#define	GUEST_KERNEL_PGD_PTRS_END	(GUEST_KERNEL_MEM_END / PGDIR_SIZE)
#define	GUEST_KERNEL_PTRS_PER_PGD	(GUEST_KERNEL_PGD_PTRS_END -	\
						GUEST_KERNEL_PGD_PTRS_START)
#define HOST_USER_PTRS_PER_PGD	(HOST_PAGE_OFFSET / PGDIR_SIZE)

#ifdef	CONFIG_VIRTUALIZATION

static inline int
kvm_init_new_context(struct kvm *kvm, gmm_struct_t *gmm)
{
	/* current cui of guest user will be inited later while */
	/* switch to new guest user process */
	__init_new_context(NULL, NULL, &gmm->context);
	return 0;
}

#ifdef	CONFIG_KVM_HV_MMU

static inline pgd_t *
kvm_mmu_get_init_gmm_root(struct kvm *kvm)
{
	hpa_t root_hpa = kvm_mmu_get_init_gmm_root_hpa(kvm);

	if (!VALID_PAGE(root_hpa))
		return NULL;
	return (pgd_t *)__va(root_hpa);
}

static inline void
kvm_mmu_set_init_gmm_root(struct kvm_vcpu *vcpu, hpa_t root)
{
	gmm_struct_t *gmm = pv_mmu_get_init_gmm(vcpu->kvm);
	gpa_t root_gpa;

	if (gmm == NULL)
		return;
	spin_lock(&vcpu->kvm->mmu_lock);
	if (likely(VALID_PAGE(gmm->root_hpa))) {
		/* root has been already set */
		if (VALID_PAGE(root)) {
			KVM_BUG_ON(root != gmm->root_hpa);
		}
		goto out_unlock;
	}
	if (VALID_PAGE(root)) {
		gmm->root_hpa = root;
	}
	if (is_sep_virt_spaces(vcpu)) {
		root_gpa = kvm_get_space_type_guest_os_root(vcpu);
	} else {
		root_gpa = kvm_get_space_type_guest_u_root(vcpu);
	}
	gmm->u_pptb = vcpu->arch.mmu.get_vcpu_u_pptb(vcpu);
	gmm->os_pptb = vcpu->arch.mmu.get_vcpu_os_pptb(vcpu);
	gmm->u_vptb = vcpu->arch.mmu.get_vcpu_u_vptb(vcpu);

out_unlock:
	spin_unlock(&vcpu->kvm->mmu_lock);
	return;
}
static inline pgd_t *
kvm_mmu_get_gmm_root(struct gmm_struct *gmm)
{
	GTI_BUG_ON(gmm == NULL);
	if (!VALID_PAGE(gmm->root_hpa))
		return NULL;
	return (pgd_t *)__va(gmm->root_hpa);
}
static inline pgd_t *
kvm_mmu_get_gmm_gk_root(struct gmm_struct *gmm)
{
	GTI_BUG_ON(gmm == NULL);
	if (!VALID_PAGE(gmm->gk_root_hpa)) {
		return NULL;
	}
	return (pgd_t *)__va(gmm->gk_root_hpa);
}

static inline hpa_t
kvm_mmu_load_the_init_gmm_root(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	hpa_t root;

	GTI_BUG_ON(!pv_vcpu_is_init_gmm(vcpu, gmm));

	root = gmm->root_hpa;
	GTI_BUG_ON(!VALID_PAGE(root));

	if (unlikely(is_sep_virt_spaces(vcpu))) {
		vcpu->arch.mmu.set_vcpu_os_pptb(vcpu, gmm->os_pptb);
		kvm_set_space_type_spt_os_root(vcpu, root);
	} else {
		vcpu->arch.mmu.set_vcpu_u_pptb(vcpu, gmm->u_pptb);
		vcpu->arch.mmu.set_vcpu_os_pptb(vcpu, gmm->u_vptb);
		kvm_set_space_type_spt_os_root(vcpu, root);
		kvm_set_space_type_spt_u_root(vcpu, root);
		kvm_set_space_type_spt_gk_root(vcpu, root);
	}
	return root;
}

static inline hpa_t
kvm_mmu_load_the_user_gmm_root(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	hpa_t root, gk_root;

	root = gmm->root_hpa;
	GTI_BUG_ON(!VALID_PAGE(root));
	gk_root = gmm->gk_root_hpa;
	GTI_BUG_ON(!VALID_PAGE(gk_root));

	vcpu->arch.mmu.set_vcpu_u_pptb(vcpu, gmm->u_pptb);
	kvm_set_space_type_spt_u_root(vcpu, root);
	kvm_set_space_type_spt_gk_root(vcpu, gk_root);
	if (likely(!is_sep_virt_spaces(vcpu))) {
		vcpu->arch.mmu.set_vcpu_os_pptb(vcpu, gmm->u_pptb);
		kvm_set_space_type_spt_os_root(vcpu, root);
	}
	return gk_root;
}

static inline pgd_t *
kvm_mmu_load_the_gmm_root(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	hpa_t root, gk_root;

	if (unlikely(pv_vcpu_is_init_gmm(vcpu, gmm))) {
		root = kvm_mmu_load_the_init_gmm_root(vcpu, gmm);
		return (pgd_t *)__va(root);
	} else {
		gk_root = kvm_mmu_load_the_user_gmm_root(vcpu, gmm);
		return (pgd_t *)__va(gk_root);
	}
}

static inline pgd_t *
kvm_mmu_load_gmm_root(thread_info_t *next_ti, gthread_info_t *next_gti)
{
	struct kvm_vcpu *vcpu;
	gmm_struct_t *next_gmm = next_gti->gmm;
	pgd_t *root;

	vcpu = next_ti->vcpu;
	root = kvm_mmu_load_the_gmm_root(vcpu, next_gmm);
	return root;
}

static inline pgd_t *
kvm_mmu_load_init_root(struct kvm_vcpu *vcpu)
{
	gmm_struct_t *init_gmm;
	pgd_t *root;

	init_gmm = pv_vcpu_get_init_gmm(vcpu);
	root = kvm_mmu_load_the_gmm_root(vcpu, init_gmm);
	return root;
}
#else	/* !CONFIG_KVM_HV_MMU */
static inline pgd_t *
kvm_mmu_get_init_gmm_root(struct kvm *kvm)
{
	return NULL;
}
static inline pgd_t *
kvm_mmu_get_gmm_root(struct gmm_struct *gmm)
{
	return NULL;
}
static inline pgd_t *
kvm_mmu_load_the_gmm_root(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	return NULL;
}
static inline pgd_t *
kvm_mmu_load_gmm_root(thread_info_t *next_ti, gthread_info_t *next_gti)
{
	return kvm_mmu_get_gmm_root(next_gti->gmm);
}

static inline pgd_t *
kvm_mmu_load_init_root(struct kvm_vcpu *vcpu)
{
	return kvm_mmu_get_init_gmm_root(vcpu->kvm);
}

static inline hpa_t
kvm_mmu_load_the_init_gmm_root(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	return (hpa_t)kvm_mmu_load_init_root(vcpu);
}

#endif	/* CONFIG_KVM_HV_MMU */

extern hpa_t kvm_convert_to_init_gmm(struct kvm_vcpu *vcpu, gthread_info_t *gti);

static inline void
switch_guest_pgd(pgd_t *next_pgd)
{
	thread_info_t	*thread_info = native_current_thread_info();
	pgd_t *pgd_to_set;

	DebugKVMSW("CPU #%d %s(%d) kernel image pgd %px = 0x%lx\n",
			raw_smp_processor_id(), current->comm, current->pid,
			thread_info->kernel_image_pgd_p,
			(thread_info->kernel_image_pgd_p) ?
				pgd_val(*thread_info->kernel_image_pgd_p)
				:
				0);
	KVM_BUG_ON(next_pgd == NULL);

	if (unlikely(test_ti_thread_flag(thread_info, TIF_PARAVIRT_GUEST))) {
		pgd_to_set = thread_info->vcpu_pgd;
		if (pgd_to_set) {
			/* copy user part of PT including guest kernel part */
			copy_pgd_range(pgd_to_set, next_pgd,
						0, USER_PTRS_PER_PGD);
		}
	} else {
		pgd_to_set = next_pgd;
	}

	KVM_BUG_ON(PCSHTP_SIGN_EXTEND(NATIVE_READ_PCSHTP_REG_SVALUE()) != 0);

	if (pgd_to_set != NULL) {
		reload_root_pgd(pgd_to_set);
		/* ALso update context for kvm_switch_mmu_pt_regs() */
		if (!MMU_IS_SEPARATE_PT())
			thread_info->vcpu->arch.sw_ctxt.sh_u_pptb = __pa(pgd_to_set);
		/* FIXME: support of guest secondary space is not yet implemented
		reload_secondary_page_dir(mm);
		*/
	}
}

#define	DO_NOT_USE_ACTIVE_GMM	/* turn OFF optimization */

static inline gmm_struct_t *
switch_guest_mm(gthread_info_t *next_gti, struct gmm_struct *next_gmm)
{
	struct kvm_vcpu	*vcpu = current_thread_info()->vcpu;
	gthread_info_t	*cur_gti = pv_vcpu_get_gti(vcpu);
	gmm_struct_t	*active_gmm;
	pgd_t		*next_pgd;

	DebugKVMSW("started to switch guest mm from GPID #%d to GPID #%d\n",
		cur_gti->gpid->nid.nr, next_gti->gpid->nid.nr);
	active_gmm = pv_vcpu_get_active_gmm(vcpu);
	if (unlikely(next_gti->gmm_in_release)) {
		/* it need switch to init gmm from guest user gmm in release */
		next_gmm = pv_vcpu_get_init_gmm(vcpu);
	} else if (next_gmm == NULL || next_gti->gmm == NULL) {
#ifdef	DO_NOT_USE_ACTIVE_GMM
		/* switch to guest kernel thread, but optimization */
		/* has been turned OFF, so switch to init gmm & PTs */
		next_gmm = pv_vcpu_get_init_gmm(vcpu);
#else	/* !DO_NOT_USE_ACTIVE_GMM */
		/* switch to guest kernel thread: do not switch mm */
		if (active_gmm == NULL) {
			/* now active is guest kernel init mm */
			DebugKVMSW("task to switch is guest kernel thread, "
				"active mm is init mm\n");
		} else {
			DebugKVMSW("task to switch is guest kernel thread, "
				"active mm is now %px #%d\n",
				active_gmm, active_gmm->nid.nr);
		}
		goto out;
#endif	/* DO_NOT_USE_ACTIVE_GMM */
	} else if (active_gmm == next_gmm) {
		/* new mm is already active: so do not switch to mm again */
		DebugKVMSW("task to switch is guest user thread, but its mm is "
			"already active, so do not switch to active mm %px #%d "
			"again\n",
			active_gmm, active_gmm->nid.nr);
		goto out;
	}
	if (likely(!pv_vcpu_is_init_gmm(vcpu, next_gmm))) {
		next_pgd = kvm_mmu_load_gmm_root(current_thread_info(),
						 next_gti);
		if (unlikely(next_pgd == NULL)) {
			next_gmm = pv_vcpu_get_init_gmm(vcpu);
			goto to_init_root;
		}
		pv_vcpu_set_gmm(vcpu, next_gmm);
	} else if (next_gti->gmm_in_release) {
		hpa_t root_hpa;

		root_hpa = kvm_convert_to_init_gmm(vcpu, next_gti);
		next_pgd = (pgd_t *)__va(root_hpa);
	} else {
to_init_root:
		next_pgd = kvm_mmu_load_init_root(vcpu);
		pv_vcpu_clear_gmm(vcpu);
	}
	switch_guest_pgd(next_pgd);
#ifdef	CONFIG_SMP
	/* Stop flush ipis for the previous mm */
	if (likely(active_gmm != next_gmm))
		cpumask_clear_cpu(raw_smp_processor_id(), gmm_cpumask(active_gmm));
#endif	/* CONFIG_SMP */
	pv_vcpu_set_active_gmm(vcpu, next_gmm);
	DebugKVMSW("task to switch is guest user thread, and its mm is not "
		"already active, so switch and make active mm %px #%d\n",
		next_gmm, next_gmm->nid.nr);
	return next_gmm;
out:
	if (DEBUG_KVM_SWITCH_MODE) {
		/* any function call can fill old state of hardware stacks */
		/* so after all calls do flush stacks again */
		NATIVE_FLUSHCPU;
		E2K_WAIT(_all_e);
	}
	return next_gmm;
}

static inline bool
kvm_switch_to_init_guest_mm(struct kvm_vcpu *vcpu)
{
	gthread_info_t *cur_gti = pv_vcpu_get_gti(vcpu);
	gmm_struct_t *init_gmm;
	gmm_struct_t *active_gmm;
	hpa_t root_hpa;

	init_gmm = pv_vcpu_get_init_gmm(vcpu);
	active_gmm = pv_vcpu_get_active_gmm(vcpu);
	if (unlikely(init_gmm == active_gmm)) {
		/* already on init mm */
		return false;
	}
	KVM_BUG_ON(cur_gti->gmm != active_gmm);
	root_hpa = kvm_mmu_load_the_init_gmm_root(vcpu, init_gmm);
	switch_guest_pgd((pgd_t *)__va(root_hpa));
#ifdef	CONFIG_SMP
	/* Stop flush ipis for the previous mm */
	cpumask_clear_cpu(raw_smp_processor_id(), gmm_cpumask(active_gmm));
#endif	/* CONFIG_SMP */
	kvm_init_gmm_get(vcpu, cur_gti);
	pv_vcpu_set_active_gmm(vcpu, init_gmm);
	pv_vcpu_clear_gmm(vcpu);
	return true;
}

static inline void
kvm_guest_kernel_pgd_populate(struct mm_struct *mm, pgd_t *pgd)
{
	/* should be populated on page fault */
	/* while access by guest kernel or user */
}
static inline void
kvm_guest_user_pgd_populate(gmm_struct_t *gmm, pgd_t *pgd)
{
	/* should be populated on page fault */
	/* while access by guest user */
}

static inline void
virt_kernel_pgd_populate(struct mm_struct *mm, pgd_t *pgd)
{
	kvm_guest_kernel_pgd_populate(mm, pgd);
}

extern e2k_addr_t kvm_guest_user_address_to_pva(struct task_struct *task,
							e2k_addr_t address);
static inline e2k_addr_t
guest_user_address_to_pva(struct task_struct *task, e2k_addr_t address)
{
	return kvm_guest_user_address_to_pva(task, address);
}
#else	/* ! CONFIG_VIRTUALIZATION */
static inline void
virt_kernel_pgd_populate(struct mm_struct *mm, pgd_t *pgd)
{
	/* nothing to do, none any guests */
}
#endif	/* CONFIG_VIRTUALIZATION */

#endif /* ! _E2K_KVM_GMMU_CONTEXT_H */
