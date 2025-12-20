/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_E2K_MMU_PT_H
#define __KVM_E2K_MMU_PT_H

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/kvm_host.h>
#include <asm/pgtable_def.h>
#include <asm/kvm/mmu.h>
#include <asm/kvm/mmu_pte.h>
#include <asm/kvm/cpu_hv_regs_access.h>

#include "mmu-e2k.h"
#include "hv_mmu.h"
#include "mmu_defs.h"
#include "pgtable-gp.h"

#undef	DEBUG_PT_STRUCT_MODE
#undef	DebugPTS
#define	DEBUG_PT_STRUCT_MODE	0	/* page tables structure debugging */
#define	DebugPTS(fmt, args...)						\
({									\
	if (DEBUG_PT_STRUCT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#define PT_PRESENT_MASK	PT_E2K_PRESENT_MASK
#define PT_WRITABLE_MASK	PT_E2K_WRITABLE_MASK
#define PT_ACCESSED_MASK	PT_E2K_ACCESSED_MASK
#define PT_DIRTY_MASK		PT_E2K_DIRTY_MASK
#define PT_PAGE_SIZE_MASK	PT_E2K_PAGE_SIZE_MASK
#define PT_GLOBAL_MASK		PT_E2K_GLOBAL_MASK

#define PT64_ROOT_LEVEL		PT_E2K_ROOT_LEVEL
#define PT_ROOT_LEVEL		PT64_ROOT_LEVEL
#define PT_DIRECTORY_LEVEL	PT_E2K_DIRECTORY_LEVEL	/* pmd */
#define PT_PAGE_TABLE_LEVEL	PT_E2K_PAGE_TABLE_LEVEL	/* pte */
#define PT_MAX_HUGEPAGE_LEVEL	PT_E2K_MAX_HUGEPAGE_LEVEL

#define PT64_ENTRIES_BITS	PT_E2K_ENTRIES_BITS
#define PT64_ENT_PER_PAGE	PT_E2K_ENT_PER_PAGE
#define PT_ENT_PER_PAGE		PT64_ENT_PER_PAGE
#define PT64_LEVEL_BITS		PT64_ENTRIES_BITS

#define PTE_PREFETCH_NUM	8

/* number of retries to handle page fault */
#define	PF_RETRIES_MAX_NUM	1
/* common number of one try and retries to handle page fault */
#define	PF_TRIES_MAX_NUM	(1 + PF_RETRIES_MAX_NUM)

#define	HW_REEXECUTE_IS_SUPPORTED	true
#define	HW_MOVE_TO_TC_IS_SUPPORTED	true

/* all available page tables abstructs */
extern const pt_struct_t pgtable_struct_e2k_v3;
extern const pt_struct_t pgtable_struct_e2k_v5;
extern const pt_struct_t pgtable_struct_e2k_v6_pt_v6;
extern const pt_struct_t pgtable_struct_e2k_v6_gp;

#define	pgtable_struct_e2k_v6_pt_v3	pgtable_struct_e2k_v5

#define	E2K_PT_V3	0xe203
#define	E2K_PT_V5	0xe205
#define	E2K_PT_V6_NEW	0xe20606
#define	E2K_PT_V6_OLD	0xe20605
#define	E2K_PT_V6_GP	0xe20600
#define	E2K_PT_DYNAMIC	0xe200

#define	E2K_PT_V3_POST		pt_v3
#define	E2K_PT_V5_POST		pt_v5
#define	E2K_PT_V6_NEW_POST	pt_v6_v6
#define	E2K_PT_V6_OLD_POST	pt_v6_v5
#define	E2K_PT_V6_GP_POST	pt_v6_gp
#define	E2K_PT_DYNAMIC_POST	pt_v6_all

#define	PT_FNAME_POSTFIX(func, post)	func##_##post
#define	DO_PT_FNAME_POSTFIX(func, post) PT_FNAME_POSTFIX(func, post)
#define	PT_FNAME(func, post)		DO_PT_FNAME_POSTFIX(func, post)
#define PTNAME_V3(func)			PT_FNAME(func, E2K_PT_V3_POST)
#define PTNAME_V5(func)			PT_FNAME(func, E2K_PT_V5_POST)
#define PTNAME_V6(func)			PT_FNAME(func, E2K_PT_V6_NEW_POST)
#define PTNAME_V6_V5(func)		PT_FNAME(func, E2K_PT_V6_OLD_POST)
#define PTNAME_V6_GP(func)		PT_FNAME(func, E2K_PT_V6_GP_POST)
#define PTNAME_DYNAMIC(func)		PT_FNAME(func, E2K_PT_DYNAMIC_POST)

#ifdef	CONFIG_DYNAMIC_PT_STRUCT
extern void PT_FNAME(mmu_init_pt_interface, E2K_PT_DYNAMIC_POST)(struct kvm *kvm);
#else	/* !CONFIG_DYNAMIC_PT_STRUCT */
extern void PT_FNAME(mmu_init_pt_interface, E2K_PT_V3_POST)(struct kvm *kvm);
extern void PT_FNAME(mmu_init_pt_interface, E2K_PT_V5_POST)(struct kvm *kvm);
extern void PT_FNAME(mmu_init_pt_interface, E2K_PT_V6_NEW_POST)(struct kvm *kvm);
extern void PT_FNAME(mmu_init_pt_interface, E2K_PT_V6_OLD_POST)(struct kvm *kvm);
extern void PT_FNAME(mmu_init_pt_interface, E2K_PT_V6_GP_POST)(struct kvm *kvm);
#endif	/* CONFIG_DYNAMIC_PT_STRUCT */

static inline unsigned kvm_page_table_hashfn(gfn_t gfn)
{
	return gfn & ((1 << KVM_MMU_HASH_SHIFT) - 1);
}

static inline const pt_struct_t *get_cpu_iset_mmu_pt_struct(int iset, bool mmu_pt_v6)
{
	const pt_struct_t *pts;

	if (iset < E2K_ISET_V5) {
		pts = &pgtable_struct_e2k_v3;
	} else if (iset == E2K_ISET_V5) {
		pts = &pgtable_struct_e2k_v5;
	} else if (iset >= E2K_ISET_V6) {
		if (mmu_pt_v6)
			pts = &pgtable_struct_e2k_v6_pt_v6;
		else
			pts = &pgtable_struct_e2k_v6_pt_v3;
	} else {
		BUG_ON(true);
	}
	return pts;
}

static inline const pt_struct_t *kvm_get_cpu_host_pt_struct(struct kvm *kvm)
{
	return get_cpu_iset_mmu_pt_struct(machine.native_iset_ver,
					  machine.mmu_pt_v6);
}

static inline const pt_struct_t *kvm_get_cpu_mmu_pt_struct(struct kvm_vcpu *vcpu)
{
	kvm_guest_info_t *guest_info = &vcpu->kvm->arch.guest_info;
	bool pt_v6;

	if (vcpu->arch.is_hv) {
		e2k_core_mode_t core_mode;

		core_mode = read_SH_CORE_MODE_reg();
		pt_v6 = !!core_mode.CORE_MODE_pt_v6;
		if (guest_info->mmu_support_pt_v6 != pt_v6) {
			pr_warn("%s(): VCPU #%d SH_CORE_MODE.pt_v6 is %d, "
				"but guest info claims the opposite\n",
				__func__, vcpu->vcpu_id, pt_v6);
			guest_info->mmu_support_pt_v6 = pt_v6;
		}
	} else {
		pt_v6 = guest_info->mmu_support_pt_v6;
	}
	return get_cpu_iset_mmu_pt_struct(guest_info->cpu_iset, pt_v6);
}

static inline const pt_struct_t *kvm_get_mmu_host_pt_struct(struct kvm *kvm)
{
	return kvm_get_cpu_host_pt_struct(kvm);
}

static inline const pt_struct_t *kvm_get_mmu_guest_pt_struct(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.is_hv) {
		/* depends on guest CPU type */
		return kvm_get_cpu_mmu_pt_struct(vcpu);
	} else if (vcpu->arch.is_pv) {
		/* paravirtualization case: guest PT type emulates */
		/* same as native PT type */
		return kvm_get_cpu_host_pt_struct(vcpu->kvm);
	} else {
		E2K_KVM_BUG_ON(true);
	}

	return NULL;
}

static inline const pt_struct_t *mmu_pt_get_host_pt_struct(struct kvm *kvm)
{
	return kvm->arch.mmu_pt_ops.host_pt_struct;
}

static inline void mmu_pt_set_host_pt_struct(struct kvm *kvm,
					     const pt_struct_t *pt_struct)
{
	kvm->arch.mmu_pt_ops.host_pt_struct = pt_struct;
	if (pt_struct != NULL) {
		DebugPTS("Setting host page table type: %s\n", pt_struct->name);
	} else {
		DebugPTS("Reset host page table type, should not be used\n");
	}
}

static inline const pt_struct_t *mmu_pt_get_kvm_vcpu_pt_struct(struct kvm *kvm)
{
	E2K_KVM_BUG_ON(kvm->arch.mmu_pt_ops.guest_pt_struct == NULL);
	return kvm->arch.mmu_pt_ops.guest_pt_struct;
}

static inline const pt_struct_t *mmu_pt_get_vcpu_pt_struct(struct kvm_vcpu *vcpu)
{
	return mmu_pt_get_kvm_vcpu_pt_struct(vcpu->kvm);
}

static inline void mmu_pt_set_vcpu_pt_struct(struct kvm *kvm,
					     const pt_struct_t *pt_struct)
{
	kvm->arch.mmu_pt_ops.guest_pt_struct = pt_struct;
	if (pt_struct != NULL) {
		DebugPTS("Setting guest page table type: %s\n", pt_struct->name);
	} else {
		DebugPTS("Reset guest page table type, should not be used\n");
	}
}

/*
 * the low bit of the generation number is always presumed to be zero.
 * This disables mmio caching during memslot updates.  The concept is
 * similar to a seqcount but instead of retrying the access we just punt
 * and ignore the cache.
 *
 * spte bits 5-11 are used as bits 1-7 of the generation number,
 * the bits 48-57 are used as bits 8-17 of the generation number.
 */
#define MMIO_SPTE_GEN_LOW_SHIFT		4
#define MMIO_SPTE_GEN_HIGH_SHIFT	48

#define MMIO_GEN_SHIFT			18
#define MMIO_GEN_LOW_SHIFT		8
#define MMIO_GEN_LOW_MASK		((1 << MMIO_GEN_LOW_SHIFT) - 2)
#define MMIO_GEN_MASK			((1 << MMIO_GEN_SHIFT) - 1)

static inline gfn_t
mmu_pt_gfn_to_index(struct kvm *kvm, gfn_t gfn, gfn_t base_gfn, int level_id)
{
	return kvm->arch.mmu_pt_ops.kvm_gfn_to_index(kvm, gfn, base_gfn, level_id);
}

static inline bool
mmu_pt_kvm_is_thp_gpmd_invalidate(struct kvm_vcpu *vcpu,
				pgprot_t old_gpmd,  pgprot_t new_gpmd)
{
	return vcpu->kvm->arch.mmu_pt_ops.kvm_is_thp_gpmd_invalidate(vcpu,
							old_gpmd, new_gpmd);
}

static inline bool is_last_gpte(struct kvm_mmu *mmu,
				unsigned level, unsigned gpte)
{
	/*
	 * PT_PAGE_TABLE_LEVEL always terminates.  The RHS has bit 7 set
	 * iff level <= PT_PAGE_TABLE_LEVEL, which for our purpose means
	 * level == PT_PAGE_TABLE_LEVEL; set PT_PAGE_SIZE_MASK in gpte then.
	 */
	gpte |= level - PT_PAGE_TABLE_LEVEL - 1;

	/*
	 * The RHS has bit 7 set iff level < mmu->last_nonleaf_level.
	 * If it is clear, there are no large pages at this level, so clear
	 * PT_PAGE_SIZE_MASK in gpte if that is the case.
	 */
	gpte &= level - mmu->last_nonleaf_level;

	return gpte & PT_PAGE_SIZE_MASK;
}

static inline void
mmu_pt_kvm_vmlpt_kernel_spte_set(struct kvm *kvm, pgprot_t *spte, pgprot_t *root)
{
	kvm->arch.mmu_pt_ops.kvm_vmlpt_kernel_spte_set(kvm, spte, root);
}

static inline void
mmu_pt_kvm_vmlpt_user_spte_set(struct kvm *kvm, pgprot_t *spte, pgprot_t *root)
{
	kvm->arch.mmu_pt_ops.kvm_vmlpt_user_spte_set(kvm, spte, root);
}

static inline pgprotval_t mmu_pt_get_spte_valid_mask(struct kvm *kvm)
{
	return kvm->arch.mmu_pt_ops.get_spte_valid_mask(kvm);
}

static inline pgprotval_t mmu_pt_get_spte_pfn_mask(struct kvm *kvm)
{
	return kvm->arch.mmu_pt_ops.get_spte_pfn_mask(kvm);
}

static inline int
mmu_pt_mmu_unsync_walk(struct kvm *kvm, kvm_mmu_page_t *sp,
			 struct kvm_mmu_pages *pvec, int pt_entries_level)
{
	return kvm->arch.mmu_pt_ops.mmu_unsync_walk(kvm, sp, pvec,
							pt_entries_level);
}

static inline unsigned int
mmu_pt_get_pte_val_memory_type_v3(pgprot_t pte)
{
	return get_pte_val_v3_memory_type(pgprot_val(pte));
}
static inline pgprot_t
mmu_pt_set_pte_val_memory_type_v3(pgprot_t pte, unsigned int mtype)
{
	return __pgprot(set_pte_val_v3_memory_type(pgprot_val(pte), mtype));
}
static inline unsigned int
mmu_pt_get_pte_val_memory_type_v6(pgprot_t pte)
{
	return get_pte_val_v6_memory_type(pgprot_val(pte));
}
static inline pgprot_t
mmu_pt_set_pte_val_memory_type_v6(pgprot_t pte, unsigned int mtype)
{
	return __pgprot(set_pte_val_v6_memory_type(pgprot_val(pte), mtype));
}
static inline unsigned int
mmu_pt_get_pte_val_memory_type_gp(pgprot_t pte)
{
	return get_pte_val_gp_memory_type(pgprot_val(pte));
}
static inline pgprot_t
mmu_pt_set_pte_val_memory_type_gp(pgprot_t pte, unsigned int mtype)
{
	return __pgprot(set_pte_val_gp_memory_type(pgprot_val(pte), mtype));
}
static inline unsigned int
mmu_pt_get_pte_val_memory_type_rule_gp(pgprot_t pte)
{
	return get_pte_val_gp_memory_type_rule(pgprot_val(pte));
}
static inline pgprot_t
mmu_pt_set_pte_val_memory_type_rule_gp(pgprot_t pte, unsigned int mtcr)
{
	return __pgprot(set_pte_val_gp_memory_type_rule(pgprot_val(pte), mtcr));
}

static inline bool
mmu_pt_rmap_write_protect(struct kvm_vcpu *vcpu, u64 gfn)
{
	return vcpu->kvm->arch.mmu_pt_ops.rmap_write_protect(vcpu, gfn);
}

static inline void
mmu_pt_account_shadowed(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	kvm->arch.mmu_pt_ops.account_shadowed(kvm, sp);
}

static inline int
mmu_pt_walk_shadow_pts(struct kvm_vcpu *vcpu, gva_t addr,
			struct kvm_shadow_trans *st, hpa_t spt_root)
{
	return vcpu->kvm->arch.mmu_pt_ops.walk_shadow_pts(vcpu, addr, st, spt_root);
}

static inline void
mmu_pt_unaccount_shadowed(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	kvm->arch.mmu_pt_ops.unaccount_shadowed(kvm, sp);
}

static inline int
mmu_pt_sync_shadow_pt_range(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			hpa_t spt_root, gva_t start, gva_t end,
			gpa_t guest_root, gva_t vptb)
{
	return vcpu->kvm->arch.mmu_pt_ops.sync_shadow_pt_range(vcpu,
			gmm, spt_root, start, end, guest_root, vptb);
}

static inline int
mmu_pt_atomic_update_shadow_pt(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			gpa_t gpa, pgprotval_t old_gpte, pgprotval_t new_gpte,
			unsigned long flags)
{
	return vcpu->kvm->arch.mmu_pt_ops.atomic_update_shadow_pt(vcpu, gmm,
					gpa, old_gpte, new_gpte, flags);
}
static inline int
mmu_pt_shadow_protection_fault(struct kvm_vcpu *vcpu,
				gpa_t addr, kvm_mmu_page_t *sp)
{
	return vcpu->kvm->arch.mmu_pt_ops.shadow_protection_fault(vcpu, addr, sp);
}

static inline long
mmu_pt_hv_page_fault(struct kvm_vcpu *vcpu, struct pt_regs *regs,
		     intc_info_mu_t *intc_info_mu)
{
	return vcpu->kvm->arch.mmu_pt_ops.kvm_hv_mmu_page_fault(vcpu, regs,
								intc_info_mu);
}

static inline bool
mmu_pt_slot_gfn_write_protect(struct kvm *kvm, struct kvm_memory_slot *slot,
			      u64 gfn)
{
	return kvm->arch.mmu_pt_ops.mmu_slot_gfn_write_protect(kvm, slot, gfn);
}

static inline void
mmu_pt_gfn_disallow_lpage(struct kvm *kvm, struct kvm_memory_slot *slot, gfn_t gfn)
{
	kvm->arch.mmu_pt_ops.mmu_gfn_disallow_lpage(kvm, slot, gfn);
}

static inline void
mmu_pt_gfn_allow_lpage(struct kvm *kvm, struct kvm_memory_slot *slot, gfn_t gfn)
{
	kvm->arch.mmu_pt_ops.mmu_gfn_allow_lpage(kvm, slot, gfn);
}

static inline void
mmu_pt_direct_unmap_prefixed_mmio_gfn(struct kvm *kvm, gfn_t gfn)
{
	kvm->arch.mmu_pt_ops.direct_unmap_prefixed_mmio_gfn(kvm, gfn);
}

static inline pgprot_t
mmu_pt_nonpaging_gpa_to_pte(struct kvm_vcpu *vcpu, gva_t addr)
{
	return vcpu->kvm->arch.mmu_pt_ops.nonpaging_gpa_to_pte(vcpu, addr);
}

static inline void
mmu_pt_free_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	kvm->arch.mmu_pt_ops.kvm_mmu_free_page(kvm, sp);
}

static inline void
mmu_pt_copy_guest_shadow_root_range(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			pgprot_t *dst_root, pgprot_t *src_root,
			int start_index, int end_index)
{
	vcpu->kvm->arch.mmu_pt_ops.copy_guest_shadow_root_range(vcpu, gmm,
				dst_root, src_root, start_index, end_index);
}

static inline void
mmu_pt_switch_kernel_pgd_range(struct kvm_vcpu *vcpu, int cpu)
{
	vcpu->kvm->arch.mmu_pt_ops.switch_kernel_pgd_range(vcpu, cpu);
}

static inline void
mmu_pt_zap_linked_children(struct kvm *kvm, pgprot_t *root_spt,
				int start_index, int end_index)
{
	kvm->arch.mmu_pt_ops.zap_linked_children(kvm, root_spt,
						 start_index, end_index);
}

static inline void
mmu_pt_mark_parents_unsync(struct kvm *kvm, kvm_mmu_page_t *sp)
{
	kvm->arch.mmu_pt_ops.mark_parents_unsync(kvm, sp);
}

static inline int
mmu_pt_prepare_zap_page(struct kvm *kvm, kvm_mmu_page_t *sp,
			struct list_head *invalid_list)
{
	return kvm->arch.mmu_pt_ops.prepare_zap_page(kvm, sp, invalid_list);
}

static inline bool
mmu_pt_slot_handle_ptes_level_range(struct kvm *kvm,
		const struct kvm_memory_slot *memslot,
		slot_level_handler fn, int start_level, int end_level,
		gfn_t start_gfn, gfn_t end_gfn, bool lock_flush_tlb)
{
	return kvm->arch.mmu_pt_ops.slot_handle_ptes_level_range(kvm,
				memslot, fn, start_level, end_level,
				start_gfn, end_gfn, lock_flush_tlb);
}

static inline bool
mmu_pt_slot_handle_rmap_write_protect(struct kvm *kvm,
		const struct kvm_memory_slot *memslot,
		slot_level_handler fn, bool lock_flush_tlb)
{
	return kvm->arch.mmu_pt_ops.slot_handle_rmap_write_protect(kvm,
						memslot, fn, lock_flush_tlb);
}

static inline bool
mmu_pt_slot_handle_collapsible_sptes(struct kvm *kvm,
		const struct kvm_memory_slot *memslot,
		slot_level_handler fn, bool lock_flush_tlb)
{
	return kvm->arch.mmu_pt_ops.slot_handle_collapsible_sptes(kvm,
						memslot, fn, lock_flush_tlb);
}

static inline bool
mmu_pt_slot_handle_clear_dirty(struct kvm *kvm,
		const struct kvm_memory_slot *memslot,
		slot_level_handler fn, bool lock_flush_tlb)
{
	return kvm->arch.mmu_pt_ops.slot_handle_clear_dirty(kvm,
						memslot, fn, lock_flush_tlb);
}

static inline bool
mmu_pt_slot_handle_largepage_remove_write_access(struct kvm *kvm,
		const struct kvm_memory_slot *memslot,
		slot_level_handler fn, bool lock_flush_tlb)
{
	return kvm->arch.mmu_pt_ops.slot_handle_largepage_remove_write_access(kvm,
						memslot, fn, lock_flush_tlb);
}

static inline bool
mmu_pt_slot_handle_set_dirty(struct kvm *kvm,
		const struct kvm_memory_slot *memslot,
		slot_level_handler fn, bool lock_flush_tlb)
{
	return kvm->arch.mmu_pt_ops.slot_handle_set_dirty(kvm,
						memslot, fn, lock_flush_tlb);
}

static inline gpa_t
mmu_pt_gva_to_gpa(struct kvm_vcpu *vcpu, gva_t gva, u32 access,
		kvm_arch_exception_t *exception, gw_attr_t *gw_res)
{
	return (vcpu->arch.mmu.gva_to_gpa) ?
			vcpu->arch.mmu.gva_to_gpa(vcpu, gva, access,
						  exception, gw_res)
			:
			(gpa_t)gva;
}

static inline long
mmu_pt_sync_gva_range(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			gva_t gva_start, gva_t gva_end)
{
	return vcpu->arch.mmu.sync_gva_range(vcpu, gmm, gva_start, gva_end);
}

static inline pf_res_t
mmu_pt_page_fault(struct kvm_vcpu *vcpu, gva_t addr, u32 error_code,
			bool prefault, gfn_t *gfnp, kvm_pfn_t *pfnp)
{
	return vcpu->arch.mmu.page_fault(vcpu, addr, error_code,
					 prefault, gfnp, pfnp);
}
static inline int
mmu_pt_sync_page(struct kvm_vcpu *vcpu, kvm_mmu_page_t *sp)
{
	return vcpu->arch.mmu.sync_page(vcpu, sp);
}

static inline void
mmu_pt_inject_page_fault(struct kvm_vcpu *vcpu, struct kvm_arch_exception *fault)
{
	if (likely(vcpu->arch.mmu.inject_page_fault)) {
		vcpu->arch.mmu.inject_page_fault(vcpu, fault);
	}
}

static inline void
mmu_pt_update_spte(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
			pgprot_t *spte, pgprotval_t gpte)
{
	vcpu->arch.mmu.update_spte(vcpu, sp, spte, gpte);
}

static inline void mmu_pt_init_vcpu_pt_struct(struct kvm_vcpu *vcpu)
{
	vcpu->kvm->arch.mmu_pt_ops.mmu_init_vcpu_pt_struct(vcpu);
}

static inline void mmu_pt_init_mmu_pt_structs(struct kvm *kvm)
{
	kvm->arch.mmu_pt_ops.kvm_init_mmu_pt_structs(kvm);
}

static inline void mmu_pt_init_nonpaging_pt_structs(struct kvm *kvm, hpa_t root)
{
	kvm->arch.mmu_pt_ops.kvm_init_nonpaging_pt_structs(kvm, root);
}

static inline void mmu_pt_setup_shadow_pt_structs(struct kvm_vcpu *vcpu)
{
	vcpu->kvm->arch.mmu_pt_ops.setup_shadow_pt_structs(vcpu);
}

static inline void mmu_pt_setup_tdp_pt_structs(struct kvm_vcpu *vcpu)
{
	vcpu->kvm->arch.mmu_pt_ops.setup_tdp_pt_structs(vcpu);
}

static inline void mmu_pt_init_mmu_spt_context(struct kvm_vcpu *vcpu,
						struct kvm_mmu *context)
{
	vcpu->kvm->arch.mmu_pt_ops.kvm_init_mmu_spt_context(vcpu, context);
}

static inline void mmu_pt_init_mmu_tdp_context(struct kvm_vcpu *vcpu,
						struct kvm_mmu *context)
{
	vcpu->kvm->arch.mmu_pt_ops.kvm_init_mmu_tdp_context(vcpu, context);
}

static inline void mmu_pt_init_mmu_nonpaging_context(struct kvm_vcpu *vcpu,
						     struct kvm_mmu *context)
{
	vcpu->kvm->arch.mmu_pt_ops.kvm_init_mmu_nonpaging_context(vcpu, context);
}

#endif	/* __KVM_E2K_MMU_PT_H */
