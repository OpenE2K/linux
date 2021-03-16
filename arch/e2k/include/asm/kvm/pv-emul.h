#ifndef __KVM_E2K_PV_EMUL_H
#define __KVM_E2K_PV_EMUL_H

#ifndef	__ASSEMBLY__

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>

#include <asm/ptrace.h>

#ifdef	CONFIG_VIRTUALIZATION

static __always_inline bool
kvm_host_at_pv_vcpu_mode(thread_info_t *ti)
{
	return ti->vcpu && test_ti_thread_flag(ti, TIF_HOST_AT_VCPU_MODE);
}

static __always_inline void
kvm_set_intc_emul_flag(pt_regs_t *regs)
{
	regs->flags |= TRAP_AS_INTC_EMUL_PT_REGS;
}

static __always_inline bool
kvm_test_intc_emul_flag(pt_regs_t *regs)
{
	return !!(regs->flags & TRAP_AS_INTC_EMUL_PT_REGS);
}

static __always_inline void
kvm_clear_intc_emul_flag(pt_regs_t *regs)
{
	regs->flags &= ~TRAP_AS_INTC_EMUL_PT_REGS;
}

static __always_inline bool
kvm_test_and_clear_intc_emul_flag(pt_regs_t *regs)
{
	bool is_emul = kvm_test_intc_emul_flag(regs);
	kvm_clear_intc_emul_flag(regs);
	return is_emul;
}
#ifdef	CONFIG_KVM_HOST_MODE
/* it is host kernel with virtualization support */
static inline bool
host_test_intc_emul_mode(const struct pt_regs *regs)
{
	if (likely(native_current_thread_info()->vcpu == NULL)) {
		return false;
	} else if (regs == NULL) {
		return false;
	} else if (!kvm_test_intc_emul_flag((pt_regs_t *)regs)) {
		/* host is not in interception emulation mode */
		return false;
	}

	return true;
}
#else	/* !CONFIG_KVM_HOST_MODE */
/* it is not host kernel */
static inline bool
host_test_intc_emul_mode(const pt_regs_t *regs)
{
	return false;
}
#endif	/* CONFIG_KVM_HOST_MODE */

static inline int kvm_get_vcpu_intc_TIRs_num(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.intc_ctxt.nr_TIRs;
}

static inline bool kvm_check_is_vcpu_intc_TIRs_empty(struct kvm_vcpu *vcpu)
{
	if (kvm_get_vcpu_intc_TIRs_num(vcpu) < 0)
		return true;
	/* TIRs have traps */
	return false;
}

static inline bool
kvm_check_is_vcpu_guest_stacks_empty(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	if (!regs->g_stacks_valid) {
		/* guest kernel stacks is not even inited */
		return true;
	}
	return !!(regs->g_stacks.psp_hi.PSP_hi_ind == 0 &&
			regs->g_stacks.pcsp_hi.PCSP_hi_ind == 0 &&
				!regs->need_inject);
}

static inline bool
kvm_is_vcpu_guest_stacks_pending(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	if (!kvm_check_is_vcpu_guest_stacks_empty(vcpu, regs)) {
		if (!regs->g_stacks_active) {
			return true;
		}
	}
	return false;
}

static inline void
kvm_clear_vcpu_guest_stacks_pending(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	if (regs->g_stacks_valid) {
		regs->g_stacks_active = true;
	}
}

extern noinline void insert_pv_vcpu_traps(thread_info_t *ti, pt_regs_t *regs);

extern void kvm_emulate_pv_vcpu_intc(struct thread_info *ti, pt_regs_t *regs,
					trap_pt_regs_t *trap);
extern void return_from_pv_vcpu_intc(struct thread_info *ti, pt_regs_t *regs);
extern bool pv_vcpu_syscall_intc(thread_info_t *ti, pt_regs_t *regs);

static inline bool kvm_vcpu_in_hypercall(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.sw_ctxt.in_hypercall;
}

static inline gthread_info_t *pv_vcpu_get_gti(struct kvm_vcpu *vcpu)
{
	if (likely(!vcpu->arch.is_hv && vcpu->arch.is_pv)) {
		return vcpu->arch.gti;
	}
	return NULL;
}

static inline void pv_vcpu_set_gti(struct kvm_vcpu *vcpu, gthread_info_t *gti)
{
	if (likely(!vcpu->arch.is_hv && vcpu->arch.is_pv)) {
		vcpu->arch.gti = gti;
	} else {
		KVM_BUG_ON(true);
	}
}

static inline int pv_vcpu_get_gpid_id(struct kvm_vcpu *vcpu)
{
	gthread_info_t *gti;

	gti = pv_vcpu_get_gti(vcpu);
	if (likely(gti != NULL)) {
		return gti->gpid->nid.nr;
	} else {
		return -EINVAL;
	}
}

static inline gmm_struct_t *pv_mmu_get_init_gmm(struct kvm *kvm)
{
	return kvm->arch.init_gmm;
}

static inline gmm_struct_t *pv_vcpu_get_init_gmm(struct kvm_vcpu *vcpu)
{
	return pv_mmu_get_init_gmm(vcpu->kvm);
}

static inline bool pv_vcpu_is_init_gmm(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	if (likely(!vcpu->arch.is_hv && vcpu->arch.is_pv)) {
		return gmm == pv_vcpu_get_init_gmm(vcpu);
	} else {
		KVM_BUG_ON(true);
	}
	return false;
}

static inline void pv_vcpu_clear_gmm(struct kvm_vcpu *vcpu)
{
	if (likely(!vcpu->arch.is_hv && vcpu->arch.is_pv)) {
		vcpu->arch.mmu.gmm = NULL;
	} else {
		KVM_BUG_ON(true);
	}
}

static inline gmm_struct_t *pv_vcpu_get_gmm(struct kvm_vcpu *vcpu)
{
	if (likely(!vcpu->arch.is_hv && vcpu->arch.is_pv)) {
		if (vcpu->arch.mmu.gmm != NULL) {
			return vcpu->arch.mmu.gmm;
		} else {
			return pv_vcpu_get_init_gmm(vcpu);
		}
	} else {
		KVM_BUG_ON(true);
	}
	return NULL;
}

static inline void pv_vcpu_set_gmm(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	if (likely(!vcpu->arch.is_hv && vcpu->arch.is_pv)) {
		if (gmm != NULL && !pv_vcpu_is_init_gmm(vcpu, gmm)) {
			vcpu->arch.mmu.gmm = gmm;
		} else {
			pv_vcpu_clear_gmm(vcpu);
		}
	} else {
		KVM_BUG_ON(true);
	}
}

static inline gmm_struct_t *pv_vcpu_get_active_gmm(struct kvm_vcpu *vcpu)
{
	if (likely(!vcpu->arch.is_hv && vcpu->arch.is_pv)) {
		return vcpu->arch.mmu.active_gmm;
	} else {
		KVM_BUG_ON(true);
	}
	return NULL;
}

static inline void
pv_vcpu_set_active_gmm(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	if (likely(!vcpu->arch.is_hv && vcpu->arch.is_pv)) {
		vcpu->arch.mmu.active_gmm = gmm;
	} else {
		KVM_BUG_ON(true);
	}
}

static inline mm_context_t *pv_vcpu_get_gmm_context(struct kvm_vcpu *vcpu)
{
	return &pv_vcpu_get_gmm(vcpu)->context;
}

#else	/* !CONFIG_VIRTUALIZATION */
static __always_inline bool
kvm_host_at_pv_vcpu_mode(thread_info_t *ti)
{
	return false;
}

static __always_inline void
kvm_set_intc_emul_flag(pt_regs_t *regs)
{
}

static __always_inline bool
kvm_test_intc_emul_flag(pt_regs_t *regs)
{
	return false;
}

static __always_inline void
kvm_clear_intc_emul_flag(pt_regs_t *regs)
{
}

static __always_inline bool
kvm_test_and_clear_intc_emul_flag(pt_regs_t *regs)
{
	return false;
}
static inline bool
host_test_intc_emul_mode(const pt_regs_t *regs)
{
	return false;
}
static inline void insert_pv_vcpu_traps(thread_info_t *ti, pt_regs_t *regs)
{
}

static inline bool kvm_vcpu_in_hypercall(struct kvm_vcpu *vcpu)
{
	return false;
}

#endif	/* CONFIG_VIRTUALIZATION */

#endif	/* ! __ASSEMBLY__ */

#endif	/* __KVM_E2K_PV_EMUL_H */
