/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#include "mmu-pt.h"
#include "mmutrace-e2k.h"

static inline const pt_struct_t *
mmu_get_host_pt_struct(struct kvm *kvm)
{
	return mmu_pt_get_host_pt_struct(kvm);
}

static inline void
mmu_set_host_pt_struct(struct kvm *kvm, const pt_struct_t *pt_struct)
{
	mmu_pt_set_host_pt_struct(kvm, pt_struct);
	if (pt_struct != NULL) {
		DebugPTS("Setting hypervisor page table type: %s\n",
			pt_struct->name);
	} else {
		DebugPTS("Reset hypervisor page table type, "
			"should not be used\n");
	}
}

static inline void
mmu_set_host_pt_struct_func(struct kvm *kvm, get_pt_struct_func_t func)
{
	kvm->arch.mmu_pt_ops.get_host_pt_struct = func;
}

static inline const pt_struct_t *
mmu_get_kvm_vcpu_pt_struct(struct kvm *kvm)
{
	return mmu_pt_get_kvm_vcpu_pt_struct(kvm);
}

static inline const pt_struct_t *
mmu_get_vcpu_pt_struct(struct kvm_vcpu *vcpu)
{
	return mmu_pt_get_vcpu_pt_struct(vcpu);
}

static inline void
mmu_set_vcpu_pt_struct(struct kvm *kvm, const pt_struct_t *pt_struct)
{
	mmu_pt_set_vcpu_pt_struct(kvm, pt_struct);
	if (pt_struct != NULL) {
		DebugPTS("Setting guest page table type: %s\n",
			pt_struct->name);
	} else {
		DebugPTS("Reset guest page table type, "
			"should not be used\n");
	}
}

static inline void
mmu_set_vcpu_pt_struct_func(struct kvm *kvm, get_vcpu_pt_struct_func_t func)
{
	kvm->arch.mmu_pt_ops.get_vcpu_pt_struct = func;
}

static inline const pt_struct_t *
mmu_get_gp_pt_struct(struct kvm *kvm)
{
	BUG_ON(kvm->arch.mmu_pt_ops.gp_pt_struct == NULL);
	return kvm->arch.mmu_pt_ops.gp_pt_struct;
}

static inline void
mmu_set_gp_pt_struct(struct kvm *kvm, const pt_struct_t *pt_struct)
{
	kvm->arch.mmu_pt_ops.gp_pt_struct = pt_struct;
	if (pt_struct != NULL) {
		DebugPTS("Setting guest physical addresses page table "
			"type: %s\n",
			pt_struct->name);
	} else {
		DebugPTS("Reset guest physical addresses page table type, "
			"should not be used\n");
	}
}

static inline void
mmu_set_gp_pt_struct_func(struct kvm *kvm, get_pt_struct_func_t func)
{
	kvm->arch.mmu_pt_ops.get_gp_pt_struct = func;
}

static inline const pt_struct_t *
kvm_get_host_pt_struct(struct kvm *kvm)
{
#if	PT_TYPE == E2K_PT_DYNAMIC
	BUG_ON(kvm->arch.mmu_pt_ops.get_host_pt_struct(kvm) == NULL);
	return kvm->arch.mmu_pt_ops.get_host_pt_struct(kvm);
#else	/* PT_TYPE != E2K_PT_DYNAMIC */
	BUILD_BUG_ON(true);
	return NULL;
#endif	/* PT_TYPE == E2K_PT_DYNAMIC */
}

static inline const pt_struct_t *
kvm_get_vcpu_pt_struct(struct kvm_vcpu *vcpu)
{
#if	PT_TYPE == E2K_PT_DYNAMIC
	BUG_ON(vcpu->kvm->arch.mmu_pt_ops.get_vcpu_pt_struct == NULL);
	return vcpu->kvm->arch.mmu_pt_ops.get_vcpu_pt_struct(vcpu);
#else	/* PT_TYPE != E2K_PT_DYNAMIC */
	BUILD_BUG_ON(true);
	return NULL;
#endif	/* PT_TYPE == E2K_PT_DYNAMIC */
}

static inline const pt_struct_t *
kvm_get_gp_pt_struct(struct kvm *kvm)
{
#if	PT_TYPE == E2K_PT_DYNAMIC
	BUG_ON(kvm->arch.mmu_pt_ops.get_gp_pt_struct == NULL);
	return kvm->arch.mmu_pt_ops.get_gp_pt_struct(kvm);
#else	/* PT_TYPE != E2K_PT_DYNAMIC */
	BUILD_BUG_ON(true);
	return NULL;
#endif	/* PT_TYPE == E2K_PT_DYNAMIC */
}

static const pt_struct_t *
kvm_mmu_get_host_pt_struct(struct kvm *kvm)
{
	return mmu_get_host_pt_struct(kvm);
}

static const pt_struct_t *
kvm_mmu_get_vcpu_pt_struct(struct kvm_vcpu *vcpu)
{
	return mmu_get_vcpu_pt_struct(vcpu);
}

static const pt_struct_t *
kvm_mmu_get_gp_pt_struct(struct kvm *kvm)
{
	return mmu_get_gp_pt_struct(kvm);
}

static inline pgprotval_t
kvm_get_pte_pfn_mask(const pt_struct_t *pt)
{
	return pt->pfn_mask;
}

static inline pgprotval_t get_spte_mmio_mask(struct kvm *kvm)
{
	const pt_struct_t *host_pt = mmu_pt_get_host_pt_struct(kvm);

	return host_pt->sw_mmio_mask;
}

static inline u64 generation_mmio_spte_mask(unsigned int gen)
{
	u64 mask;

	WARN_ON(gen & ~MMIO_GEN_MASK);

	mask = (gen & MMIO_GEN_LOW_MASK) << MMIO_SPTE_GEN_LOW_SHIFT;
	mask |= ((u64)gen >> MMIO_GEN_LOW_SHIFT) << MMIO_SPTE_GEN_HIGH_SHIFT;
	return mask;
}

static inline unsigned int
get_mmio_spte_generation(struct kvm *kvm, pgprotval_t spte)
{
	unsigned int gen;

	spte &= ~get_spte_mmio_mask(kvm);

	gen = (spte >> MMIO_SPTE_GEN_LOW_SHIFT) & MMIO_GEN_LOW_MASK;
	gen |= (spte >> MMIO_SPTE_GEN_HIGH_SHIFT) << MMIO_GEN_LOW_SHIFT;
	return gen;
}

static inline unsigned int kvm_current_mmio_generation(struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_memslots(vcpu)->generation & MMIO_GEN_MASK;
}

static inline bool is_mmio_spte(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mmio_mask = get_spte_mmio_mask(kvm);

	return (pgprot_val(spte) & mmio_mask) == mmio_mask;
}

static inline gfn_t get_mmio_spte_gfn(struct kvm *kvm, pgprot_t spte)
{
	u64 mask = generation_mmio_spte_mask(MMIO_GEN_MASK) |
						get_spte_mmio_mask(kvm);
	return (pgprot_val(spte) & ~mask) >> PAGE_SHIFT;
}

static inline unsigned get_mmio_spte_access(struct kvm *kvm, pgprot_t spte)
{
	u64 mask = generation_mmio_spte_mask(MMIO_GEN_MASK) |
						get_spte_mmio_mask(kvm);
	return (pgprot_val(spte) & ~mask) & ~PAGE_MASK;
}

static inline bool check_mmio_spte(struct kvm_vcpu *vcpu, pgprot_t spte)
{
	unsigned int kvm_gen, spte_gen;

	kvm_gen = kvm_current_mmio_generation(vcpu);
	spte_gen = get_mmio_spte_generation(vcpu->kvm, pgprot_val(spte));

	trace_check_mmio_spte(spte, kvm_gen, spte_gen);
	return likely(kvm_gen == spte_gen);
}

static inline pgprotval_t
get_spte_bit_mask(struct kvm *kvm, bool accessed, bool dirty,
		  bool present, bool valid)
{
	const pt_struct_t *host_pt = mmu_pt_get_host_pt_struct(kvm);
	pgprotval_t mask = 0;

	if (accessed)
		mask |= host_pt->accessed_mask;
	if (dirty)
		mask |= host_pt->dirty_mask;
	if (present)
		mask |= host_pt->present_mask;
	if (valid)
		mask |= host_pt->valid_mask;
	return mask;
}
static inline pgprotval_t get_spte_accessed_mask(struct kvm *kvm)
{
	return get_spte_bit_mask(kvm, true, false, false, false);
}
static inline pgprotval_t get_spte_dirty_mask(struct kvm *kvm)
{
	return get_spte_bit_mask(kvm, false, true, false, false);
}
static inline pgprotval_t get_spte_present_mask(struct kvm *kvm)
{
	return get_spte_bit_mask(kvm, false, false, true, false);
}
static inline pgprotval_t get_spte_valid_mask(struct kvm *kvm)
{
	return get_spte_bit_mask(kvm, false, false, false, true);
}
static inline pgprotval_t get_spte_present_valid_mask(struct kvm *kvm)
{
	return get_spte_bit_mask(kvm, false, false, true, true);
}

static inline pgprotval_t get_gpmd_thp_invalidate_mask(struct kvm_vcpu *vcpu)
{
	const pt_struct_t *gpt = mmu_pt_get_vcpu_pt_struct(vcpu);
	pgprotval_t mask = 0;

#ifdef	CONFIG_TRANSPARENT_HUGEPAGE
	E2K_KVM_BUG_ON(PMD_THP_INVALIDATE_FLAGS !=
				(UNI_PAGE_PRESENT | UNI_PAGE_PROTNONE));
	mask |= gpt->present_mask;
	mask |= gpt->protnone_mask;
#endif	/* CONFIG_TRANSPARENT_HUGEPAGE */

	return mask;
}

static inline pgprot_t
set_spte_bit_mask(struct kvm *kvm, pgprot_t spte,
		  bool accessed, bool dirty, bool present, bool valid)
{
	const pt_struct_t *host_pt = mmu_pt_get_host_pt_struct(kvm);
	pgprotval_t mask = 0;

	if (accessed)
		mask |= host_pt->accessed_mask;
	if (dirty)
		mask |= host_pt->dirty_mask;
	if (present)
		mask |= host_pt->present_mask;
	if (valid)
		mask |= host_pt->valid_mask;
	spte = __pgprot(pgprot_val(spte) | mask);
	return spte;
}

static inline bool is_spte_accessed_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_accessed_mask(kvm);
	return pgprot_val(spte) & mask;
}
static inline pgprot_t set_spte_accessed_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_accessed_mask(kvm);
	return __pgprot(pgprot_val(spte) | mask);
}
static inline pgprot_t clear_spte_accessed_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_accessed_mask(kvm);
	return __pgprot(pgprot_val(spte) & ~mask);
}

static inline pgprotval_t get_pte_mode_mask(const pt_struct_t *pt_struct)
{
	if (pt_struct->user_mask != 0)
		return pt_struct->user_mask;
	else if (pt_struct->priv_mask != 0)
		return pt_struct->priv_mask;
	else
		/* pte has not user or priv mode */
		;
	return (pgprotval_t) 0;
}

static inline pgprotval_t get_spte_mode_mask(struct kvm *kvm)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	return get_pte_mode_mask(spt);
}

static inline pgprotval_t get_gpte_mode_mask(struct kvm_vcpu *vcpu)
{
	const pt_struct_t *gpt = mmu_pt_get_vcpu_pt_struct(vcpu);

	return get_pte_mode_mask(gpt);
}

static inline pgprotval_t get_spte_user_mask(struct kvm *kvm)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	return spt->user_mask;
}

static inline pgprotval_t get_gpte_user_mask(struct kvm_vcpu *vcpu)
{
	const pt_struct_t *gpt = mmu_pt_get_vcpu_pt_struct(vcpu);

	return gpt->user_mask;
}

static inline pgprotval_t get_spte_priv_mask(struct kvm *kvm)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	return spt->priv_mask;
}

static inline pgprotval_t get_gpte_priv_mask(struct kvm_vcpu *vcpu)
{
	const pt_struct_t *gpt = mmu_pt_get_vcpu_pt_struct(vcpu);

	return gpt->priv_mask;
}

static inline bool is_spte_user_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	if (spt->user_mask != 0)
		return pgprot_val(spte) & spt->user_mask;
	else if (spt->priv_mask != 0)
		return !(pgprot_val(spte) & spt->priv_mask);
	else
		/* pte has not user or priv mode */
		;
	return false;
}
static inline pgprot_t set_spte_user_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	if (spt->user_mask != 0)
		return __pgprot(pgprot_val(spte) | spt->user_mask);
	else if (spt->priv_mask != 0)
		return __pgprot(pgprot_val(spte) & ~spt->priv_mask);
	else
		/* pte has not user or priv mode */
		;
	return spte;
}
static inline pgprot_t clear_spte_user_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	if (kvm->arch.is_pv && !kvm->arch.is_hv)
		/* software paravirtualized guest */
		/* can be run only at user mode */
		return spte;
	if (spt->user_mask != 0)
		return __pgprot(pgprot_val(spte) & ~spt->user_mask);
	else if (spt->priv_mask != 0)
		return __pgprot(pgprot_val(spte) | spt->priv_mask);
	else
		/* pte has not user or priv mode */
		;
	return spte;
}

static inline bool is_spte_priv_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	if (spt->priv_mask != 0)
		return pgprot_val(spte) & spt->priv_mask;
	else if (spt->user_mask != 0)
		return !(pgprot_val(spte) & spt->user_mask);
	else
		/* pte has not user or priv mode */
		return true;	/* always privileged */
	return false;
}
static inline pgprot_t set_spte_priv_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	if (kvm->arch.is_pv && !kvm->arch.is_hv)
		/* software paravirtualized guest */
		/* can be run only at user mode */
		return spte;
	if (spt->priv_mask != 0)
		return __pgprot(pgprot_val(spte) | spt->priv_mask);
	else if (spt->user_mask != 0)
		return __pgprot(pgprot_val(spte) & ~spt->user_mask);
	else
		/* pte has not user or priv mode */
		;
	return spte;
}
static inline pgprot_t clear_spte_priv_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	if (spt->priv_mask != 0)
		return __pgprot(pgprot_val(spte) & ~spt->priv_mask);
	else if (spt->user_mask != 0)
		return __pgprot(pgprot_val(spte) | spt->user_mask);
	else
		/* pte has not user or priv mode */
		;
	return spte;
}
static inline pgprot_t set_spte_user_priv_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	if (likely(kvm->arch.is_pv && !kvm->arch.is_hv)) {
		/* special case, user hardware stacks should be privileged */
		if (likely(spt->priv_mask != 0)) {
			return __pgprot(pgprot_val(spte) | spt->priv_mask);
		}
		E2K_KVM_BUG_ON(true);
	} else {
		E2K_KVM_BUG_ON(true);
	}
	return spte;
}
static inline pgprot_t clear_spte_user_priv_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	if (likely(kvm->arch.is_pv && !kvm->arch.is_hv)) {
		/* special case, user hardware stacks should be privileged */
		if (likely(spt->priv_mask != 0)) {
			return __pgprot(pgprot_val(spte) & ~spt->priv_mask);
		}
		E2K_KVM_BUG_ON(true);
	} else {
		E2K_KVM_BUG_ON(true);
	}
	return spte;
}
static inline bool is_spte_dirty_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_dirty_mask(kvm);
	return pgprot_val(spte) & mask;
}
static inline pgprot_t set_spte_dirty_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_dirty_mask(kvm);
	return __pgprot(pgprot_val(spte) | mask);
}
static inline pgprot_t set_spte_cui(pgprot_t spte, u64 cui)
{
	return !cpu_has(CPU_FEAT_ISET_V6) ? __pgprot(pgprot_val(spte) |
			_PAGE_INDEX_TO_CUNIT_V3(cui)) : spte;
}
static inline pgprot_t clear_spte_dirty_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_dirty_mask(kvm);
	return __pgprot(pgprot_val(spte) & ~mask);
}
static inline bool is_spte_present_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_present_mask(kvm);
	return pgprot_val(spte) & mask;
}
static inline pgprot_t set_spte_present_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_present_mask(kvm);
	return __pgprot(pgprot_val(spte) | mask);
}
static inline pgprot_t clear_spte_present_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_present_mask(kvm);
	return __pgprot(pgprot_val(spte) & ~mask);
}
static inline bool is_spte_valid_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_valid_mask(kvm);
	return pgprot_val(spte) & mask;
}
static inline pgprot_t set_spte_valid_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_valid_mask(kvm);
	return __pgprot(pgprot_val(spte) | mask);
}
static inline pgprot_t clear_spte_valid_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_valid_mask(kvm);
	return __pgprot(pgprot_val(spte) & ~mask);
}
static inline pgprot_t set_spte_present_valid_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_present_valid_mask(kvm);
	return __pgprot(pgprot_val(spte) | mask);
}

static inline pgprotval_t get_spte_x_mask(struct kvm *kvm)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	return spt->exec_mask;
}
static inline pgprotval_t get_pte_nx_mask(const pt_struct_t *pt_struct)
{
	return pt_struct->non_exec_mask;
}
static inline pgprotval_t get_spte_nx_mask(struct kvm *kvm)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	return get_pte_nx_mask(spt);
}
static inline pgprotval_t get_gpte_nx_mask(struct kvm_vcpu *vcpu)
{
	const pt_struct_t *gpt = mmu_pt_get_vcpu_pt_struct(vcpu);

	return get_pte_nx_mask(gpt);
}
static inline bool is_spte_x_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	if (spt->exec_mask != 0)
		return pgprot_val(spte) & spt->exec_mask;
	else if (spt->non_exec_mask != 0)
		return !(pgprot_val(spte) & spt->non_exec_mask);
	else
		/* pte has not executable field */
		return true;	/* always executable */
	return false;
}
static inline pgprot_t set_spte_x_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	if (spt->exec_mask != 0)
		return __pgprot(pgprot_val(spte) | spt->exec_mask);
	else if (spt->non_exec_mask != 0)
		return __pgprot(pgprot_val(spte) & ~spt->non_exec_mask);
	else
		/* pte has not executable field */
		;
	return spte;
}
static inline pgprot_t clear_spte_x_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	if (spt->exec_mask != 0)
		return __pgprot(pgprot_val(spte) & ~spt->exec_mask);
	else if (spt->non_exec_mask != 0)
		return __pgprot(pgprot_val(spte) | spt->non_exec_mask);
	else
		/* pte has not executable field */
		;
	return spte;
}
static inline bool is_spte_nx_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	if (spt->exec_mask != 0)
		return !(pgprot_val(spte) & spt->exec_mask);
	else if (spt->non_exec_mask != 0)
		return pgprot_val(spte) & spt->non_exec_mask;
	else
		/* pte has not executable field */
		return true;	/* always can be not executable */
	return false;
}
static inline pgprot_t set_spte_nx_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	if (spt->exec_mask != 0)
		return __pgprot(pgprot_val(spte) & ~spt->exec_mask);
	else if (spt->non_exec_mask != 0)
		return __pgprot(pgprot_val(spte) | spt->non_exec_mask);
	else
		/* pte has not executable field */
		;
	return spte;
}
static inline pgprot_t clear_spte_nx_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	if (spt->exec_mask != 0)
		return __pgprot(pgprot_val(spte) | spt->exec_mask);
	else if (spt->non_exec_mask != 0)
		return __pgprot(pgprot_val(spte) & ~spt->non_exec_mask);
	else
		/* pte has not executable field */
		;
	return spte;
}
static inline bool is_spte_huge_page_mask(struct kvm *kvm, pgprot_t spte)
{
	return pgprot_val(spte) & PT_PAGE_SIZE_MASK;
}
static inline pgprot_t set_spte_huge_page_mask(struct kvm *kvm, pgprot_t spte)
{
	return __pgprot(pgprot_val(spte) | PT_PAGE_SIZE_MASK);
}
static inline pgprot_t clear_spte_huge_page_mask(struct kvm *kvm, pgprot_t spte)
{
	return __pgprot(pgprot_val(spte) & ~PT_PAGE_SIZE_MASK);
}
static inline bool is_spte_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return pgprot_val(spte) & PT_WRITABLE_MASK;
}
static inline pgprot_t set_spte_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return __pgprot(pgprot_val(spte) | PT_WRITABLE_MASK);
}
static inline pgprot_t clear_spte_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return __pgprot(pgprot_val(spte) & ~PT_WRITABLE_MASK);
}

static inline pgprot_t
set_spte_val_memory_type(struct kvm_vcpu *vcpu, pgprot_t spte, unsigned mtype)
{
#if	PT_TYPE == E2K_PT_DYNAMIC
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(vcpu->kvm);

	return spt->set_pte_val_memory_type(spte, mtype);
#elif	PT_TYPE == E2K_PT_V3 || PT_TYPE == E2K_PT_V5 || PT_TYPE == E2K_PT_V6_OLD
	return mmu_pt_set_pte_val_memory_type_v3(spte, mtype);
#elif	PT_TYPE == E2K_PT_V6_NEW
	return mmu_pt_set_pte_val_memory_type_v6(spte, mtype);
#elif	PT_TYPE == E2K_PT_V6_GP
	return mmu_pt_set_pte_val_memory_type_gp(spte, mtype);
#else
# error	"Invalid page table structures type"
#endif
}
static inline bool is_shadow_zero_bits_set(struct kvm_mmu *mmu, pgprot_t spte,
					   int level)
{
	if (is_ss(NULL)) {
		pr_err_once("FIXME: %s() is not implemented\n", __func__);
	}
	return false;
}

#define SPTE_HOST_WRITABLE_SW_MASK(__spt)	((__spt)->sw_bit1_mask)
#define SPTE_MMU_WRITABLE_SW_MASK(__spt)	((__spt)->sw_bit2_mask)

static inline pgprotval_t get_spte_sw_mask(struct kvm *kvm, bool host, bool mmu)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);
	pgprotval_t mask = 0;

	if (host)
		mask |= SPTE_HOST_WRITABLE_SW_MASK(spt);
	if (mmu)
		mask |= SPTE_MMU_WRITABLE_SW_MASK(spt);
	return mask;
}
static inline bool is_spte_sw_writable_mask(struct kvm *kvm, pgprot_t spte,
						bool host, bool mmu)
{
	pgprotval_t sw_mask = 0;

	sw_mask = get_spte_sw_mask(kvm, host, mmu);
	return pgprot_val(spte) & sw_mask;
}
static inline bool is_spte_all_sw_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t sw_mask = 0;

	sw_mask = get_spte_sw_mask(kvm, true, true);
	return (pgprot_val(spte) & sw_mask) == sw_mask;
}
static inline pgprot_t set_spte_sw_writable_mask(struct kvm *kvm, pgprot_t spte,
						 bool host, bool mmu)
{
	pgprotval_t sw_mask = 0;

	sw_mask = get_spte_sw_mask(kvm, host, mmu);
	return __pgprot(pgprot_val(spte) | sw_mask);
}
static inline pgprot_t clear_spte_sw_writable_mask(struct kvm *kvm, pgprot_t spte,
						   bool host, bool mmu)
{
	pgprotval_t sw_mask = 0;

	sw_mask = get_spte_sw_mask(kvm, host, mmu);
	return __pgprot(pgprot_val(spte) & ~sw_mask);
}
static inline bool is_spte_host_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return is_spte_sw_writable_mask(kvm, spte, true, false);
}
static inline bool is_spte_mmu_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return is_spte_sw_writable_mask(kvm, spte, false, true);
}
static inline pgprot_t set_spte_host_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return set_spte_sw_writable_mask(kvm, spte, true, false);
}
static inline pgprot_t set_spte_mmu_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return set_spte_sw_writable_mask(kvm, spte, false, true);
}
static inline pgprot_t clear_spte_host_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return clear_spte_sw_writable_mask(kvm, spte, true, false);
}
static inline pgprot_t clear_spte_mmu_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return clear_spte_sw_writable_mask(kvm, spte, false, true);
}

static inline pgprotval_t get_spte_pt_user_prot(struct kvm *kvm)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	return spt->ptd_user_prot;
}

static inline pgprotval_t get_spte_pt_kernel_prot(struct kvm *kvm)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	return spt->ptd_kernel_prot;
}

static inline pgprot_t set_spte_memory_type_mask(struct kvm_vcpu *vcpu,
					pgprot_t spte, gfn_t gfn, bool is_mmio)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(vcpu->kvm);
	unsigned int mem_type;

	/*
	 * FIXME: here comments for x86, probably it can be useful for e2k,
	 * so keep its
	 * For VT-d and EPT combination
	 * 1. MMIO: always map as UC
	 * 2. EPT with VT-d:
	 *   a. VT-d without snooping control feature: can't guarantee the
	 *	result, try to trust guest.
	 *   b. VT-d with snooping control feature: snooping control feature of
	 *	VT-d engine can guarantee the cache correctness. Just set it
	 *	to WB to keep consistent with host. So the same as item 3.
	 * 3. EPT without VT-d: always map as WB and set IPAT=1 to keep
	 *    consistent with host MTRR
	 */

	/*
	 * FIXME: now is implemented only two case of memory type
	 *  a. MMIO: always map as "External Configuration"
	 *  b. Physical memory: always map as "General Cacheable"
	 */
	if (unlikely(is_mmio_prefixed_gfn(vcpu, gfn)))
		mem_type = EXT_NON_PREFETCH_MT;
	else
		if (is_mmio)
			mem_type = EXT_CONFIG_MT;
		else
			mem_type = GEN_CACHE_MT;

	return set_spte_val_memory_type(vcpu, spte, mem_type);
}

static inline bool is_shadow_none_pte(pgprot_t pte)
{
	return (pgprot_val(pte) == 0);
}

static inline bool is_shadow_present_pte(struct kvm *kvm, pgprot_t pte)
{
	return (pgprot_val(pte) != 0) &&
			pgprot_val(pte) != get_spte_valid_mask(kvm) &&
				!is_mmio_spte(kvm, pte);
}

static inline bool is_shadow_valid_pte(struct kvm *kvm, pgprot_t pte)
{
	return pgprot_val(pte) == get_spte_valid_mask(kvm) ||
			is_mmio_spte(kvm, pte) &&
				is_spte_valid_mask(kvm, pte) &&
				!is_spte_present_mask(kvm, pte);
}

static inline bool is_shadow_present_or_valid_pte(struct kvm *kvm, pgprot_t pte)
{
	return is_shadow_present_pte(kvm, pte) ||
				is_shadow_valid_pte(kvm, pte);
}

static inline bool is_shadow_unmapped_pte(struct kvm *kvm, pgprot_t pte)
{
	return pgprot_val(pte) == 0;
}

static inline bool is_large_pte(pgprot_t pte)
{
	return pgprot_val(pte) & PT_PAGE_SIZE_MASK;
}

static inline bool is_shadow_huge_pte(pgprot_t pte)
{
	return is_large_pte(pte);
}

static inline bool is_last_spte(pgprot_t pte, int level)
{
	if (level == PT_PAGE_TABLE_LEVEL)
		return true;
	if (is_large_pte(pte))
		return true;
	return false;
}

static inline e2k_addr_t
kvm_pte_pfn_to_phys_addr(pgprot_t pte, const pt_struct_t *pt)
{
	return pgprot_val(pte) & kvm_get_pte_pfn_mask(pt);
}
static inline e2k_addr_t
kvm_gpte_pfn_to_phys_addr(pgprotval_t pte, const pt_struct_t *pt)
{
	return pte & kvm_get_pte_pfn_mask(pt);
}
static inline e2k_addr_t
kvm_spte_pfn_to_phys_addr(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = GET_HOST_PT_STRUCT(kvm);

	return kvm_pte_pfn_to_phys_addr(spte, spt);
}
static inline gpa_t
kvm_gpte_gfn_to_phys_addr(struct kvm_vcpu *vcpu, pgprot_t gpte)
{
	const pt_struct_t *gpt = GET_VCPU_PT_STRUCT(vcpu);

	return kvm_pte_pfn_to_phys_addr(gpte, gpt);
}

static inline gfn_t gpte_to_gfn(struct kvm_vcpu *vcpu, pgprotval_t gpte)
{
	return gpa_to_gfn(kvm_gpte_gfn_to_phys_addr(vcpu, __pgprot(gpte)));
}

static inline pgprotval_t get_spte_pfn_mask(struct kvm *kvm)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);

	return kvm_get_pte_pfn_mask(spt);
}

static inline kvm_pfn_t spte_to_pfn(struct kvm *kvm, pgprot_t spte)
{
	return kvm_spte_pfn_to_phys_addr(kvm, spte) >> PAGE_SHIFT;
}

static inline pgprot_t set_spte_pfn(struct kvm *kvm, pgprot_t spte, kvm_pfn_t pfn)
{
	pgprotval_t pfn_mask = get_spte_pfn_mask(kvm);

	return __pgprot((pgprot_val(spte) & ~pfn_mask) |
				((pfn << PAGE_SHIFT) & pfn_mask));
}
static inline pgprot_t clear_spte_pfn(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t pfn_mask = get_spte_pfn_mask(kvm);

	return __pgprot(pgprot_val(spte) & ~pfn_mask);
}

static inline void __set_spte(pgprot_t *sptep, pgprot_t spte)
{
	WRITE_ONCE(*sptep, spte);
}

static inline void __update_clear_spte_fast(pgprot_t *sptep, pgprot_t spte)
{
	WRITE_ONCE(*sptep, spte);
}

static inline pgprot_t __update_clear_spte_slow(pgprot_t *sptep, pgprot_t spte)
{
	return __pgprot(xchg((pgprotval_t *)sptep, pgprot_val(spte)));
}

static inline bool spte_is_locklessly_modifiable(struct kvm *kvm, pgprot_t spte)
{
	return is_spte_all_sw_writable_mask(kvm, spte);
}

static inline bool spte_has_volatile_bits(struct kvm *kvm, pgprot_t spte)
{
	/*
	 * Always atomically update spte if it can be updated
	 * out of mmu-lock, it can ensure dirty bit is not lost,
	 * also, it can help us to get a stable is_writable_pte()
	 * to ensure tlb flush is not missed.
	 */

	if (!is_shadow_valid_pte(kvm, spte))
		return false;

	if (spte_is_locklessly_modifiable(kvm, spte))
		return true;

	if (!get_spte_accessed_mask(kvm))
		return false;

	if (!is_shadow_present_pte(kvm, spte))
		return false;

	if (is_spte_accessed_mask(kvm, spte) &&
		(!is_writable_pte(spte) || is_spte_dirty_mask(kvm, spte)))
		return false;

	return true;
}

static inline bool
spte_is_bit_cleared(pgprot_t old_spte, pgprot_t new_spte, pgprotval_t prot_mask)
{
	return (pgprot_val(old_spte) & prot_mask) &&
			!(pgprot_val(new_spte) & prot_mask);
}

static inline bool
spte_is_bit_changed(pgprot_t old_spte, pgprot_t new_spte, pgprotval_t prot_mask)
{
	return (pgprot_val(old_spte) & prot_mask) !=
			(pgprot_val(new_spte) & prot_mask);
}

#define PT64_PERM_MASK(kvm)	\
		(PT_PRESENT_MASK | PT_WRITABLE_MASK | \
			get_spte_user_mask(kvm) | get_spte_priv_mask(kvm) | \
				get_spte_x_mask(kvm) | get_spte_nx_mask(kvm))

#define for_each_shadow_pt_entry(_vcpu, _spt_root, _addr, _walker)	\
		for (shadow_pt_walk_init(&(_walker), _vcpu, _spt_root, _addr); \
			shadow_walk_okay(&(_walker));			\
				shadow_walk_next(&(_walker)))
#define for_each_shadow_entry(_vcpu, _addr, _walker)			\
		for (shadow_walk_init(&(_walker), _vcpu, _addr);	\
			shadow_walk_okay(&(_walker));			\
				shadow_walk_next(&(_walker)))

#define for_each_shadow_entry_lockless(_vcpu, _addr, _walker, spte)	\
		for (shadow_walk_init(&(_walker), _vcpu, _addr);	\
			shadow_walk_okay(&(_walker)) &&			\
				({ spte = mmu_spte_get_lockless(	\
							_walker.sptep);	\
					true;				\
				});					\
				__shadow_walk_next(&(_walker), spte))

/* Rules for using mmu_spte_set:
 * Set the sptep from nonpresent to present.
 * Note: the sptep being assigned *must* be either not present
 * or in a state where the hardware will not attempt to update
 * the spte.
 */
static inline void
mmu_spte_set(struct kvm *kvm, pgprot_t *sptep, pgprot_t new_spte)
{
	WARN_ON(is_shadow_present_pte(kvm, *sptep));
	__set_spte(sptep, new_spte);
}

static inline pgprotval_t
kvm_get_gpte_bit_mask(struct kvm *kvm, bool present, bool valid, bool huge)
{
	const pt_struct_t *gpt = GET_KVM_VCPU_PT_STRUCT(kvm);
	pgprotval_t mask = 0;

	if (present)
		mask |= gpt->present_mask;
	if (valid)
		mask |= gpt->valid_mask;
	if (huge)
		mask |= gpt->huge_mask;
	return mask;
}

static inline pgprotval_t kvm_get_gpte_present_mask(struct kvm *kvm)
{
	return kvm_get_gpte_bit_mask(kvm, true, false, false);
}

static inline pgprotval_t kvm_get_gpte_valid_mask(struct kvm *kvm)
{
	return kvm_get_gpte_bit_mask(kvm, false, true, false);
}

static inline pgprotval_t kvm_get_gpte_huge_mask(struct kvm *kvm)
{
	return kvm_get_gpte_bit_mask(kvm, false, false, true);
}

static inline pgprotval_t
get_gpte_bit_mask(struct kvm_vcpu *vcpu, bool present, bool valid, bool huge)
{
	return kvm_get_gpte_bit_mask(vcpu->kvm, present, valid, huge);
}

static inline pgprotval_t get_gpte_present_mask(struct kvm_vcpu *vcpu)
{
	return get_gpte_bit_mask(vcpu, true, false, false);
}

static inline pgprotval_t get_gpte_valid_mask(struct kvm_vcpu *vcpu)
{
	return get_gpte_bit_mask(vcpu, false, true, false);
}

static inline pgprotval_t get_gpte_huge_mask(struct kvm_vcpu *vcpu)
{
	return get_gpte_bit_mask(vcpu, false, false, true);
}

static inline pgprotval_t get_gpte_unmapped_mask(struct kvm_vcpu *vcpu)
{
	return (pgprotval_t) 0;
}

static inline bool is_none_gpte(pgprotval_t pte)
{
	return pte == 0;
}

static inline bool is_present_gpte(pgprotval_t pte)
{
	return pte & PT_PRESENT_MASK;
}

static inline bool is_unmapped_gpte(struct kvm_vcpu *vcpu, pgprotval_t pte)
{
	return pte == get_gpte_unmapped_mask(vcpu);
}

static inline bool is_only_valid_gpte(struct kvm_vcpu *vcpu, pgprotval_t pte)
{
	return pte == get_gpte_valid_mask(vcpu);
}

static inline bool is_valid_gpte(struct kvm_vcpu *vcpu, pgprotval_t pte)
{
	return !!(pte & get_gpte_valid_mask(vcpu));
}

static inline bool is_present_or_valid_gpte(struct kvm_vcpu *vcpu, pgprotval_t pte)
{
	return is_present_gpte(pte) || is_only_valid_gpte(vcpu, pte);
}

static inline bool is_huge_gpte(struct kvm_vcpu *vcpu, pgprotval_t pte)
{
	return pte & get_gpte_huge_mask(vcpu);
}

static inline bool kvm_is_only_valid_gpte(struct kvm *kvm, pgprotval_t pte)
{
	return pte == kvm_get_gpte_valid_mask(kvm);
}

static inline bool kvm_is_valid_gpte(struct kvm *kvm, pgprotval_t pte)
{
	return !!(pte & kvm_get_gpte_valid_mask(kvm));
}

static inline bool kvm_is_present_or_valid_gpte(struct kvm *kvm, pgprotval_t pte)
{
	return is_present_gpte(pte) || kvm_is_only_valid_gpte(kvm, pte);
}

static inline bool kvm_is_huge_gpte(struct kvm *kvm, pgprotval_t pte)
{
	return pte & kvm_get_gpte_huge_mask(kvm);
}

static inline bool has_pt_level_huge_gpte(struct kvm_vcpu *vcpu, int level)
{
	const pt_struct_t *gpt = GET_VCPU_PT_STRUCT(vcpu);

	return is_huge_pt_struct_level(gpt, level);
}

static inline gfn_t
gpte_to_gfn_level(struct kvm_vcpu *vcpu,
		  pgprotval_t gpte, const pt_level_t *pt_level)
{
	gpa_t gpa;

	gpa = kvm_gpte_gfn_to_phys_addr(vcpu, __pgprot(gpte));
	if (unlikely(is_huge_pt_level(pt_level) && is_huge_gpte(vcpu, gpte))) {
		gpa &= get_pt_level_mask(pt_level);
	}

	return gpa_to_gfn(gpa);
}

static inline pgprot_t *
sp_gpa_to_spte(struct kvm_mmu_page *sp, gpa_t gpa)
{
	pgprot_t *sptep;
	unsigned long page_offset;

	page_offset = offset_in_page(gpa);
	sptep = &sp->spt[page_offset / sizeof(*sptep)];
	return sptep;
}

static inline gfn_t
gpte_to_gfn_level_sp(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
		     pgprot_t *sptep, pgprotval_t gpte)
{
	const pt_struct_t *gpt = GET_VCPU_PT_STRUCT(vcpu);
	const pt_level_t *pt_level;
	unsigned index;

	pt_level = get_pt_struct_level_on_id(gpt, sp->role.level);
	if (sp->role.direct) {
		index = sptep - sp->spt;
	} else {
		index = 0;
	}
	return gpte_to_gfn_level(vcpu, gpte, pt_level) + index;
}
static inline gfn_t
gpte_to_gfn_level_address(struct kvm_vcpu *vcpu, gva_t address,
			  pgprotval_t gpte, const pt_level_t *pt_level)
{
	unsigned index = 0;

	if (unlikely(is_huge_pt_level(pt_level) && is_huge_gpte(vcpu, gpte))) {
		index = (address & get_pt_level_offset(pt_level)) >> PAGE_SHIFT;
	}
	return gpte_to_gfn_level(vcpu, gpte, pt_level) + index;
}

static gfn_t kvm_mmu_sp_get_gfn(struct kvm_mmu_page *sp, int index)
{
	if (!sp->role.direct)
		return sp->gfn;

	return sp->gfn + (index << ((sp->role.level - 1) * PT64_LEVEL_BITS));
}

/* KVM Hugepage definitions for host machine */
static inline int
kvm_mmu_hpage_shift(struct kvm *kvm, int level_id)
{
	const pt_level_t *pt_level;

	pt_level = get_pt_struct_level_on_id(GET_HOST_PT_STRUCT(kvm), level_id);
	return KVM_PT_LEVEL_HPAGE_SHIFT(pt_level);
}
static inline unsigned long
kvm_mmu_hpage_size(struct kvm *kvm, int level_id)
{
	const pt_level_t *pt_level;

	pt_level = get_pt_struct_level_on_id(GET_HOST_PT_STRUCT(kvm), level_id);
	return KVM_PT_LEVEL_HPAGE_SIZE(pt_level);
}
static inline unsigned long
kvm_mmu_hpage_mask(struct kvm *kvm, int level_id)
{
	const pt_level_t *pt_level;

	pt_level = get_pt_struct_level_on_id(GET_HOST_PT_STRUCT(kvm), level_id);
	return KVM_PT_LEVEL_HPAGE_MASK(pt_level);
}
static inline unsigned long
kvm_mmu_pages_per_hpage(struct kvm *kvm, int level_id)
{
	const pt_level_t *pt_level;

	pt_level = get_pt_struct_level_on_id(GET_HOST_PT_STRUCT(kvm), level_id);
	return KVM_PT_LEVEL_PAGES_PER_HPAGE(pt_level);
}
static inline unsigned long
kvm_mmu_hpage_gfn_shift(struct kvm *kvm, int level_id)
{
	return kvm_mmu_hpage_shift(kvm, level_id) - PAGE_SHIFT;
}

static inline gfn_t
kvm_gfn_to_index(struct kvm *kvm, gfn_t gfn, gfn_t base_gfn, int level_id)
{
	const pt_level_t *pt_level;

	pt_level = get_pt_struct_level_on_id(GET_HOST_PT_STRUCT(kvm), level_id);
	return gfn_to_index(gfn, base_gfn, pt_level);
}
