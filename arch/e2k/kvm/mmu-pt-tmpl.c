/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Kernel-based Virtual Machine MMU page tables support template
 * to construct support for a specific version of PT structures
 */

#include <linux/kvm_host.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/moduleparam.h>
#include <linux/export.h>
#include <linux/swap.h>
#include <linux/hugetlb.h>
#include <linux/compiler.h>
#include <linux/srcu.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/delay.h>

#include <asm/page.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/mmu_hv_regs_access.h>
#include <asm/kvm/pgtable-tdp.h>
#include <asm/kvm/async_pf.h>
#include <asm/kvm/trace_kvm.h>

#include "cpu.h"
#include "mmu.h"
#include "mman.h"
#include "gaccess.h"
#include "intercepts.h"
#include "io.h"

#undef	CHECK_MMU_PAGES_AVAILABLE

/* now implemented only dynamic PT support for guest MMU */
#define	GET_KVM_VCPU_PT_STRUCT(kvm)	mmu_get_kvm_vcpu_pt_struct(kvm)
#define	GET_VCPU_PT_STRUCT(vcpu)	mmu_get_vcpu_pt_struct(vcpu)

#if	PT_TYPE == E2K_PT_V3
#define PTNAME(ptname)	PT_FNAME(ptname, E2K_PT_V3_POST)
#define	GET_HOST_PT_STRUCT(kvm)	&pgtable_struct_e2k_v3
#include "mmu-pt-tmpl.h"
#elif	PT_TYPE == E2K_PT_V5
#define PTNAME(ptname)	PT_FNAME(ptname, E2K_PT_V5_POST)
#define	GET_HOST_PT_STRUCT(kvm)	&pgtable_struct_e2k_v5
#include "mmu-pt-tmpl.h"
#elif	PT_TYPE == E2K_PT_V6_NEW
#define PTNAME(ptname)	PT_FNAME(ptname, E2K_PT_V6_NEW_POST)
#define	GET_HOST_PT_STRUCT(kvm)	&pgtable_struct_e2k_v6_pt_v6
#include "mmu-pt-tmpl.h"
#elif	PT_TYPE == E2K_PT_V6_OLD
#define PTNAME(ptname)	PT_FNAME(ptname, E2K_PT_V6_OLD_POST)
#define	GET_HOST_PT_STRUCT(kvm)	&pgtable_struct_e2k_v6_pt_v3
#include "mmu-pt-tmpl.h"
#elif	PT_TYPE == E2K_PT_V6_GP
#define PTNAME(ptname)	PT_FNAME(ptname, E2K_PT_V6_GP_POST)
#define	GET_HOST_PT_STRUCT(kvm)	&pgtable_struct_e2k_v6_gp
#include "mmu-pt-tmpl.h"
#elif	PT_TYPE == E2K_PT_DYNAMIC
#define PTNAME(ptname)	PT_FNAME(ptname, E2K_PT_DYNAMIC_POST)
#define	GET_HOST_PT_STRUCT(kvm)	mmu_get_host_pt_struct(kvm)
#include "mmu-pt-tmpl.h"
#else
	#error Invalid PT_TYPE value
#endif

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SYNC_ROOTS_MODE
#undef	DebugSYNC
#define	DEBUG_SYNC_ROOTS_MODE	0	/* PT roots alloc and sync debugging */
#define	DebugSYNC(fmt, args...)						\
({									\
	if (DEBUG_SYNC_ROOTS_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PT_RANGE_SYNC_MODE
#undef	DebugPTSYNC
#define	DEBUG_PT_RANGE_SYNC_MODE	0	/* PT range sync debug */
#define	DebugPTSYNC(fmt, args...)					\
({									\
	if (DEBUG_PT_RANGE_SYNC_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_TO_VIRT_MODE
#undef	DebugTOVM
#define	DEBUG_KVM_TO_VIRT_MODE	0	/* switch guest to virtual mode */
#define	DebugTOVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_TO_VIRT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SET_PAGING_MODE
#undef	DebugSETPM
#define	DEBUG_SET_PAGING_MODE	0	/* setup guest paging mode */
#define	DebugSETPM(fmt, args...)					\
({									\
	if (DEBUG_SET_PAGING_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_REEXEC_PF_MODE
#undef	DebugREEXEC
#define	DEBUG_REEXEC_PF_MODE	0	/* reexecute load and wait debugging */
#define	DebugREEXEC(fmt, args...)					\
({									\
	if (DEBUG_REEXEC_PF_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SYNC_VERBOSE_MODE
#undef	DebugSYNCV
#define	DEBUG_KVM_SYNC_VERBOSE_MODE	0	/* new PT synchronizatiom */
						/* verbose mode */
#define	DebugSYNCV(fmt, args...)					\
({									\
	if (DEBUG_KVM_SYNC_VERBOSE_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_UNSYNC_MODE
#undef	DebugUNSYNC
#define	DEBUG_KVM_UNSYNC_MODE	0	/* PT unsynchronizatiom mode */
#define	DebugUNSYNC(fmt, args...)					\
({									\
	if (DEBUG_KVM_UNSYNC_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SHADOW_PT_MODE
#undef	DebugSPT
#define	DEBUG_KVM_SHADOW_PT_MODE	0	/* shadow PT manage */
#define	DebugSPT(fmt, args...)						\
({									\
	if (DEBUG_KVM_SHADOW_PT_MODE) {					\
		pr_info("%s(): " fmt, __func__, ##args);		\
	}								\
})

#undef	DEBUG_KVM_GMM_FREE_MODE
#undef	DebugFREE
#define	DEBUG_KVM_GMM_FREE_MODE	0	/* guest mm PT freeing debug */
#define	DebugFREE(fmt, args...)						\
({									\
	if (DEBUG_KVM_GMM_FREE_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_PAGE_FAULT_MODE
#undef	DebugSPF
#define	DEBUG_KVM_PAGE_FAULT_MODE	0	/* page fault manage */
#define	DebugSPF(fmt, args...)						\
({									\
	if (DEBUG_KVM_PAGE_FAULT_MODE) {				\
		pr_info("%s(): " fmt, __func__, ##args);		\
	}								\
})

#undef	DEBUG_KVM_SPT_WALK_MODE
#undef	DebugWSPT
#define	DEBUG_KVM_SPT_WALK_MODE	0	/* walk all SPT levels */
#define	DebugWSPT(fmt, args...)						\
({									\
	if (DEBUG_KVM_SPT_WALK_MODE) {					\
		pr_info("%s(): " fmt, __func__, ##args);		\
	}								\
})

#undef	DEBUG_KVM_GPT_WALK_MODE
#undef	DebugWGPT
#define	DEBUG_KVM_GPT_WALK_MODE	0	/* walk all guest PT levels */
#define	DebugWGPT(fmt, args...)						\
({									\
	if (DEBUG_KVM_GPT_WALK_MODE) {					\
		pr_info("%s(): " fmt, __func__, ##args);		\
	}								\
})

#undef	DEBUG_KVM_GPT_ATOMIC_MODE
#undef	DebugAGPT
#define	DEBUG_KVM_GPT_ATOMIC_MODE 0	/* guest PT levels atomic access */
#define	DebugAGPT(fmt, args...)						\
({									\
	if (DEBUG_KVM_GPT_ATOMIC_MODE) {				\
		pr_info("%s(): " fmt, __func__, ##args);		\
	}								\
})

#undef	DEBUG_KVM_GPT_WALK_RANGE_MODE
#undef	DebugRGPT
#define	DEBUG_KVM_GPT_WALK_RANGE_MODE 0	/* walk addr range guest PT levels */
#define	DebugRGPT(fmt, args...)						\
({									\
	if (DEBUG_KVM_GPT_WALK_RANGE_MODE) {				\
		pr_info("%s(): " fmt, __func__, ##args);		\
	}								\
})

#undef	DEBUG_KVM_GPT_NEXT_MODE
#undef	DebugNGPT
#define	DEBUG_KVM_GPT_NEXT_MODE 0	/* guest PT levels walk next gptes */
#define	DebugNGPT(fmt, args...)						\
({									\
	if (DEBUG_KVM_GPT_NEXT_MODE) {					\
		pr_info("%s(): " fmt, __func__, ##args);		\
	}								\
})

#undef	DEBUG_KVM_NONPAGING_MODE
#undef	DebugNONP
#define	DEBUG_KVM_NONPAGING_MODE	0	/* nonpaging mode debug */
#define	DebugNONP(fmt, args...)						\
({									\
	if (DEBUG_KVM_NONPAGING_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_TDP_MODE
#undef	DebugTDP
#define	DEBUG_KVM_TDP_MODE	0	/* TDP mode debug */
#define	DebugTDP(fmt, args...)						\
({									\
	if (DEBUG_KVM_TDP_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_INTC_PAGE_FAULT_MODE
#undef	DebugPFINTC
#define	DEBUG_INTC_PAGE_FAULT_MODE	0	/* MMU intercept on data */
						/* page fault mode debug */
#define	DebugPFINTC(fmt, args...)					\
({									\
	if (DEBUG_INTC_PAGE_FAULT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_INSTR_FAULT_MODE
#undef	DebugIPF
#define	DEBUG_KVM_INSTR_FAULT_MODE	0	/* instruction page fault */
						/* mode debug */
#define	DebugIPF(fmt, args...)						\
({									\
	if (DEBUG_KVM_INSTR_FAULT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_PTE_MODE
#undef	DebugPTE
#define	DEBUG_KVM_PTE_MODE	0	/* guest PTE update/write debug */
#define	DebugPTE(fmt, args...)						\
({									\
	if (DEBUG_KVM_PTE_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SHADOW_INJECT_MODE
#undef	DebugSHINJ
#define	DEBUG_SHADOW_INJECT_MODE	0	/* shadow page faults */
						/* injection debug */
#define	DebugSHINJ(fmt, args...)					\
({									\
	if (DEBUG_SHADOW_INJECT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_READ_PROT_INJECT_MODE
#undef	DebugRPROT
#define	DEBUG_READ_PROT_INJECT_MODE	0	/* shadow page faults on */
						/* load after store debug */
#define	DebugRPROT(fmt, args...)					\
({									\
	if (DEBUG_READ_PROT_INJECT_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_COPY_SPT_MODE
#undef	DebugCPSPT
#define	DEBUG_COPY_SPT_MODE	0	/* copy guest kernel SPT range */
#define	DebugCPSPT(fmt, args...)					\
({									\
	if (DEBUG_COPY_SPT_MODE)					\
		pr_err("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_FREE_SPT_MODE
#undef	DebugFRSPT
#define	DEBUG_FREE_SPT_MODE	0	/* free guest kernel SPT range */
#define	DebugFRSPT(fmt, args...)					\
({									\
	if (DEBUG_FREE_SPT_MODE)					\
		pr_err("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_GUEST_MM_MODE
#undef	DebugGMM
#define	DEBUG_KVM_GUEST_MM_MODE	0	/* guest MM support */
#define	DebugGMM(fmt, args...)						\
({									\
	if (DEBUG_KVM_GUEST_MM_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_FLOOD_MODE
#undef	DebugFLOOD
#define	DEBUG_KVM_FLOOD_MODE	0	/* host SP flood support */
#define	DebugFLOOD(fmt, args...)					\
({									\
	if (DEBUG_KVM_FLOOD_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_FREE_SP_MODE
#undef	DebugZAP
#define	DEBUG_KVM_FREE_SP_MODE	0	/* host SP free debug */
#define	DebugZAP(fmt, args...)					\
({									\
	if (DEBUG_KVM_FREE_SP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_EXEC_MMU_OP
#undef	DbgEXMMU
#define	DEBUG_EXEC_MMU_OP	0	/* recovery operations debug */
#define	DbgEXMMU(fmt, args...)						\
({									\
	if (DEBUG_EXEC_MMU_OP)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PF_RETRY_MODE
#undef	DebugTRY
#define	DEBUG_PF_RETRY_MODE	0	/* retry page fault debug */
#define	DebugTRY(fmt, args...)						\
({									\
	if (DEBUG_PF_RETRY_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_RETRY_MODE
#undef	DebugRETRY
#define	DEBUG_RETRY_MODE	0	/* retry page fault debug */
#define	DebugRETRY(fmt, args...)					\
({									\
	if (DEBUG_RETRY_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PF_EXC_RPR_MODE
#undef	DebugEXCRPR
#define	DEBUG_PF_EXC_RPR_MODE	0	/* page fault at recovery mode debug */
#define	DebugEXCRPR(fmt, args...)					\
({									\
	if (DEBUG_PF_EXC_RPR_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SHUTDOWN_MODE
#undef	DebugKVMSH
#define	DEBUG_KVM_SHUTDOWN_MODE	0	/* KVM shutdown debugging */
#define	DebugKVMSH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SHUTDOWN_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_UNIMPL_MODE
#undef	DebugUNIMPL
#define	DEBUG_KVM_UNIMPL_MODE	0	/* unimplemented */
#define	DebugUNIMPL(fmt, args...)					\
({									\
	if (DEBUG_KVM_MODE || kvm_debug)				\
		pr_err_once(fmt, ##args);				\
})

#undef	DEBUG_MMU_REG_MODE
#undef	DebugMMUREG
#define	DEBUG_MMU_REG_MODE	0	/* MMU register access events */
					/* debug mode */
#define	DebugMMUREG(fmt, args...)					\
({									\
	if (DEBUG_MMU_REG_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_MMU_PID_MODE
#undef	DebugMMUPID
#define	DEBUG_MMU_PID_MODE	0	/* MMU PID register access events */
					/* debug mode */
#define	DebugMMUPID(fmt, args...)					\
({									\
	if (DEBUG_MMU_PID_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_MMU_VPT_REG_MODE
#undef	DebugMMUVPT
#define	DEBUG_MMU_VPT_REG_MODE	0	/* MMU virtual PT bases */
#define	DebugMMUVPT(fmt, args...)					\
({									\
	if (DEBUG_MMU_VPT_REG_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SHADOW_CONTEXT_MODE
#undef	DebugSHC
#define	DEBUG_SHADOW_CONTEXT_MODE 0	/* shadow context debugging */
#define	DebugSHC(fmt, args...)					\
({									\
	if (DEBUG_SHADOW_CONTEXT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#include "mmu-notifier-trace.h"

#include <trace/events/kvm.h>

static pgprot_t set_spte_pfn(struct kvm *kvm, pgprot_t spte, kvm_pfn_t pfn);
static void mmu_spte_set(struct kvm *kvm, pgprot_t *sptep, pgprot_t spte);
static void pv_mmu_drop_copied_parent_pte(struct kvm *kvm,
			struct kvm_mmu_page *child,
			struct kvm_mmu_page *parent, pgprot_t *parent_pte);
static void sync_dropped_guest_shadow_root_range(struct kvm *kvm,
			pgprot_t *dst_root, pgprot_t *src_root,
			int start_index, int end_index);
static int kvm_mmu_prepare_zap_page(struct kvm *kvm, struct kvm_mmu_page *sp,
				    struct list_head *invalid_list);

static void walk_shadow_page_lockless_begin(struct kvm_vcpu *vcpu)
{
	/*
	 * Prevent page table teardown by making any free-er wait during
	 * kvm_flush_remote_tlbs() IPI to all active vcpus.
	 */
	local_irq_disable();

	/*
	 * Make sure a following spte read is not reordered ahead of the write
	 * to vcpu->mode.
	 */
	smp_store_mb(vcpu->mode, READING_SHADOW_PAGE_TABLES);
}

static void walk_shadow_page_lockless_end(struct kvm_vcpu *vcpu)
{
	/*
	 * Make sure the write to vcpu->mode is not reordered in front of
	 * reads to sptes.  If it does, kvm_commit_zap_page() can see us
	 * OUTSIDE_GUEST_MODE and proceed to free the shadow page table.
	 */
	smp_store_release(&vcpu->mode, OUTSIDE_GUEST_MODE);
	local_irq_enable();
}

static void mark_mmio_spte(struct kvm_vcpu *vcpu, pgprot_t *sptep, u64 gfn,
				unsigned access)
{
	unsigned int gen = kvm_current_mmio_generation(vcpu);
	u64 mask = generation_mmio_spte_mask(gen);
	pgprot_t spte;

	access &= (ACC_WRITE_MASK | ACC_USER_MASK | ACC_PRIV_MASK);
	mask |= get_spte_mmio_mask(vcpu->kvm) | access | gfn << PAGE_SHIFT;

	pgprot_val(spte) = (get_spte_valid_mask(vcpu->kvm) | mask);

	spte = set_spte_memory_type_mask(vcpu, spte, gfn, true);

	trace_mark_mmio_spte(sptep, gfn, access, gen);
	mmu_spte_set(vcpu->kvm, sptep, spte);
}

static void mark_mmio_space_spte(struct kvm_vcpu *vcpu, pgprot_t *sptep,
					u64 gfn, unsigned access)
{
	unsigned int gen = kvm_current_mmio_generation(vcpu);
	u64 mask = generation_mmio_spte_mask(gen);
	pgprot_t spte;

	mask |= get_spte_mmio_mask(vcpu->kvm) | gfn << PAGE_SHIFT;

	pgprot_val(spte) = (get_spte_valid_mask(vcpu->kvm) | mask);

	spte = set_spte_memory_type_mask(vcpu, spte, gfn, true);

	mmu_spte_set(vcpu->kvm, sptep, spte);
}

static void mark_mmio_prefixed_spte(struct kvm_vcpu *vcpu, pgprot_t *sptep,
			gfn_t gfn, kvm_pfn_t pfn, int level, unsigned access)
{
	struct kvm *kvm = vcpu->kvm;
	u64 mask;
	pgprot_t spte;

	mask = get_spte_mmio_mask(kvm);

	pgprot_val(spte) = get_spte_present_valid_mask(kvm);
	pgprot_val(spte) |= mask;
	DebugSPF("spte %px initial value 0x%lx\n",
		sptep, pgprot_val(spte));

	spte = set_spte_nx_mask(kvm, spte);

	spte = set_spte_priv_mask(kvm, spte);

	if (level > PT_PAGE_TABLE_LEVEL)
		spte = set_spte_huge_page_mask(kvm, spte);

	spte = set_spte_memory_type_mask(vcpu, spte, gfn, true);

	spte = set_spte_pfn(kvm, spte, pfn);

	if (access & ACC_WRITE_MASK) {
		spte = set_spte_writable_mask(kvm, spte);
	}

	DebugSPF("spte %px final value 0x%lx\n",
		sptep, pgprot_val(spte));

	mmu_spte_set(vcpu->kvm, sptep, spte);
}

static bool set_mmio_spte(struct kvm_vcpu *vcpu, pgprot_t *sptep, gfn_t gfn,
			  kvm_pfn_t pfn, int level, unsigned access)
{
	if (unlikely(is_mmio_prefixed_gfn(vcpu, gfn))) {
		mark_mmio_prefixed_spte(vcpu, sptep, gfn, pfn, level, access);
		return true;
	}
	if (unlikely(is_mmio_space_pfn(pfn))) {
		mark_mmio_space_spte(vcpu, sptep, gfn, access);
		return true;
	}
	if (unlikely(is_noslot_pfn(pfn))) {
		mark_mmio_spte(vcpu, sptep, gfn, access);
		return true;
	}

	return false;
}

/* Rules for using mmu_spte_update:
 * Update the state bits, it means the mapped pfn is not changed.
 *
 * Whenever we overwrite a writable spte with a read-only one we
 * should flush remote TLBs. Otherwise rmap_write_protect
 * will find a read-only spte, even though the writable spte
 * might be cached on a CPU's TLB, the return value indicates this
 * case.
 */
static bool mmu_spte_update(struct kvm *kvm, pgprot_t *sptep, pgprot_t new_spte)
{
	pgprot_t old_spte = *sptep;
	bool ret = false;

	WARN_ON(!is_shadow_present_or_valid_pte(kvm, new_spte));

	if (!is_shadow_present_pte(kvm, old_spte)) {
		mmu_spte_set(kvm, sptep, new_spte);
		return ret;
	}

	if (!spte_has_volatile_bits(kvm, old_spte))
		__update_clear_spte_fast(sptep, new_spte);
	else
		old_spte = __update_clear_spte_slow(sptep, new_spte);

	/*
	 * For the spte updated out of mmu-lock is safe, since
	 * we always atomically update it, see the comments in
	 * spte_has_volatile_bits().
	 */
	if (spte_is_locklessly_modifiable(kvm, old_spte) &&
			!is_writable_pte(new_spte))
		ret = true;

	if (is_writable_pte(old_spte) != is_writable_pte(new_spte)) {
		/* changed writable bit of pte */
		ret = true;
	}

	if (unlikely(spte_same(old_spte, new_spte))) {
		/* the new pte is the same as old, probably it need */
		/* flush TLB address & PT levels entries to clear new value */
		kvm_make_request(KVM_REQ_ADDR_FLUSH, current_thread_info()->vcpu);
	}

	if (!get_spte_accessed_mask(kvm)) {
		/*
		 * We don't set page dirty when dropping non-writable spte.
		 * So do it now if the new spte is becoming non-writable.
		 */
		if (ret)
			kvm_set_pfn_dirty(spte_to_pfn(kvm, old_spte));
		return ret;
	}

	/*
	 * Flush TLB when accessed/dirty bits are changed in the page tables,
	 * to guarantee consistency between TLB and page tables.
	 */
	if (spte_is_bit_changed(old_spte, new_spte,
			get_spte_bit_mask(kvm, true, true, false, false)))
		ret = true;

	if (spte_is_bit_cleared(old_spte, new_spte,
				get_spte_accessed_mask(kvm)))
		kvm_set_pfn_accessed(spte_to_pfn(kvm, old_spte));
	if (spte_is_bit_cleared(old_spte, new_spte,
				get_spte_dirty_mask(kvm)))
		kvm_set_pfn_dirty(spte_to_pfn(kvm, old_spte));

	return ret;
}

static bool kvm_is_mmio_pfn(kvm_pfn_t pfn)
{
	if (pfn_valid(pfn))
		return !is_zero_pfn(pfn) && PageReserved(pfn_to_page(pfn));

	return true;
}

/*
 * Rules for using mmu_spte_clear_track_bits:
 * It sets the sptep from present to nonpresent, and track the
 * state bits, it is used to clear the last level sptep.
 */
static int mmu_spte_clear_track_bits(struct kvm *kvm, pgprot_t *sptep)
{
	kvm_pfn_t pfn;
	pgprot_t old_spte = *sptep;
	struct kvm_mmu_page *sp;

	sp = page_header(__pa(sptep));

	DebugPTE("started for spte %px == 0x%lx\n",
		sptep, pgprot_val(old_spte));
	E2K_KVM_BUG_ON(is_shadow_present_pte(kvm, old_spte) &&
			!is_shadow_huge_pte(old_spte) &&
				sp->role.level != PT_PAGE_TABLE_LEVEL);
	if (!spte_has_volatile_bits(kvm, old_spte)) {
		__update_clear_spte_fast(sptep,
			(is_shadow_present_or_valid_pte(kvm, old_spte) &&
					!sp->released) ?
				__pgprot(get_spte_valid_mask(kvm))
				:
				__pgprot(0ull));
	} else {
		old_spte = __update_clear_spte_slow(sptep,
				(sp->released) ?
					__pgprot(0ull)
					:
					__pgprot(get_spte_valid_mask(kvm)));
	}
	DebugPTE("cleared spte %px == 0x%lx\n",
		sptep, pgprot_val(*sptep));

	if (!is_shadow_present_pte(kvm, old_spte) ||
					is_mmio_spte(kvm, old_spte))
		return 0;

	pfn = spte_to_pfn(kvm, old_spte);
	DebugPTE("host pfn 0x%llx, reserved %d, count %d\n",
		pfn, kvm_is_reserved_pfn(pfn), page_count(pfn_to_page(pfn)));

	/*
	 * KVM does not hold the refcount of the page used by
	 * kvm mmu, before reclaiming the page, we should
	 * unmap it from mmu first.
	 */
	WARN_ON(!kvm_is_reserved_pfn(pfn) && !page_count(pfn_to_page(pfn)) &&
		is_spte_writable_mask(kvm, old_spte));

	if (is_spte_accessed_mask(kvm, old_spte))
		kvm_set_pfn_accessed(pfn);
	if (is_spte_dirty_mask(kvm, old_spte))
		kvm_set_pfn_dirty(pfn);
	return 1;
}

static void kvm_vmlpt_kernel_spte_set(struct kvm *kvm, pgprot_t *spte,
					pgprot_t *root)
{
	pgprot_t k_spte = __pgprot(get_spte_pt_user_prot(kvm));

	*spte = set_spte_pfn(kvm, k_spte, __pa(root) >> PAGE_SHIFT);
}

static void kvm_vmlpt_user_spte_set(struct kvm *kvm, pgprot_t *spte,
					pgprot_t *root)
{
	pgprot_t k_spte = __pgprot(get_spte_pt_user_prot(kvm));

	*spte = set_spte_pfn(kvm, k_spte, __pa(root) >> PAGE_SHIFT);
}

/*
 * Rules for using mmu_spte_clear_no_track:
 * Directly clear spte without caring the state bits of sptep,
 * it is used to set the upper level spte.
 */
static void mmu_spte_clear_no_track(pgprot_t *sptep)
{
	__update_clear_spte_fast(sptep, __pgprot(0ull));
}

static void mmu_spte_clear_as_valid(struct kvm *kvm, pgprot_t *sptep)
{
	__update_clear_spte_fast(sptep, __pgprot(get_spte_valid_mask(kvm)));
}

/*
 * Return the pointer to the large page information for a given gfn,
 * handling slots that are not large page aligned.
 */
static struct kvm_lpage_info *
lpage_info_slot(struct kvm *kvm, gfn_t gfn, kvm_memory_slot_t *slot, int level)
{
	unsigned long idx;

	idx = kvm_gfn_to_index(kvm, gfn, slot->base_gfn, level);
	return &slot->arch.lpage_info[level - 2][idx];
}

static void update_gfn_disallow_lpage_count(struct kvm *kvm,
			kvm_memory_slot_t *slot, gfn_t gfn, int count)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);
	struct kvm_lpage_info *linfo;
	int i;

	for (i = PT_DIRECTORY_LEVEL; i <= PT_MAX_HUGEPAGE_LEVEL; ++i) {
		if (!is_huge_pt_struct_level(spt, i))
			continue;
		linfo = lpage_info_slot(kvm, gfn, slot, i);
		linfo->disallow_lpage += count;
		WARN_ON(linfo->disallow_lpage < 0);
	}
}

static void mmu_gfn_disallow_lpage(struct kvm *kvm, kvm_memory_slot_t *slot,
				   gfn_t gfn)
{
	update_gfn_disallow_lpage_count(kvm, slot, gfn, 1);
}

static void mmu_gfn_allow_lpage(struct kvm *kvm, kvm_memory_slot_t *slot,
				gfn_t gfn)
{
	update_gfn_disallow_lpage_count(kvm, slot, gfn, -1);
}

static void account_shadowed(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *slot;
	gfn_t gfn;

	kvm->arch.indirect_shadow_pages++;
	gfn = sp->gfn;
	slots = kvm_memslots_for_spte_role(kvm, sp->role);
	slot = __gfn_to_memslot(slots, gfn);
	E2K_KVM_BUG_ON(slot == NULL);

	/*
	 * Allow guest to write to the lowest levels of guest pt if
	 * CONFIG_PARAVIRT_TLB_FLUSH is enabled
	 */
	if (unlikely(!IS_ENABLED(CONFIG_KVM_PARAVIRT_TLB_FLUSH))) {
		kvm_slot_page_track_add_page(kvm, slot, gfn,
					KVM_PAGE_TRACK_WRITE);
		mmu_gfn_disallow_lpage(kvm, slot, gfn);
	}
}

static void unaccount_shadowed(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *slot;
	gfn_t gfn;

	kvm->arch.indirect_shadow_pages--;
	gfn = sp->gfn;
	DebugFREE("SP %px level #%d gfn 0x%llx gva 0x%lx\n",
		sp, sp->role.level, sp->gfn, sp->gva);
	slots = kvm_memslots_for_spte_role(kvm, sp->role);
	slot = __gfn_to_memslot(slots, gfn);
	if (kvm_page_track_is_active(kvm, slot, gfn, KVM_PAGE_TRACK_WRITE))
		kvm_slot_page_track_remove_page(kvm, slot, gfn,
						KVM_PAGE_TRACK_WRITE);
	if (unlikely(!IS_ENABLED(CONFIG_KVM_PARAVIRT_TLB_FLUSH))) {
		mmu_gfn_allow_lpage(kvm, slot, gfn);
	}
}

static bool __mmu_gfn_lpage_is_disallowed(struct kvm *kvm,
				gfn_t gfn, int level, kvm_memory_slot_t *slot)
{
	struct kvm_lpage_info *linfo;

	if (slot) {
		linfo = lpage_info_slot(kvm, gfn, slot, level);
		return !!linfo->disallow_lpage;
	}

	return true;
}

static bool mmu_gfn_lpage_is_disallowed(struct kvm_vcpu *vcpu, gfn_t gfn,
					int level)
{
	struct kvm_memory_slot *slot;

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	return __mmu_gfn_lpage_is_disallowed(vcpu->kvm, gfn, level, slot);
}

static unsigned long pv_vma_host_hugepage_size(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	/*
	 * Only host pfn can give the answer to the size of virtual page
	 * it can be mapped to (see transparent_hugepage_adjust())
	 */
	return PAGE_SIZE;
}
static unsigned long hv_vma_host_hugepage_size(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	return kvm_host_page_size(vcpu, gfn);
}

static unsigned long kvm_host_hugepage_size(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	struct kvm_memory_slot *memslot;
	unsigned long size;

	size = PAGE_SIZE;

	memslot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	if (likely(memslot != NULL)) {
		if (likely(vcpu->arch.is_hv)) {
			size = hv_vma_host_hugepage_size(vcpu, gfn);
		} else {
			size = pv_vma_host_hugepage_size(vcpu, gfn);
		}
	}

	return size;
}

static int host_mapping_level(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	unsigned long page_size;
	int i, ret = 0;

	page_size = kvm_host_hugepage_size(vcpu, gfn);

	for (i = PT_PAGE_TABLE_LEVEL; i <= PT_MAX_HUGEPAGE_LEVEL; ++i) {
		if (page_size >= kvm_mmu_hpage_size(vcpu->kvm, i))
			ret = i;
		else
			break;
	}

	return ret;
}

static int mapping_level(struct kvm_vcpu *vcpu, gfn_t large_gfn,
			 bool *force_pt_level)
{
	int host_level, level, max_level;
	const pt_level_t *pt_level;
	kvm_memory_slot_t *slot;

	if (unlikely(*force_pt_level))
		return PT_PAGE_TABLE_LEVEL;

	slot = kvm_vcpu_gfn_to_memslot(vcpu, large_gfn);
	*force_pt_level = !memslot_valid_for_gpte(slot, true);
	if (unlikely(*force_pt_level))
		return PT_PAGE_TABLE_LEVEL;

	host_level = host_mapping_level(vcpu, large_gfn);

	if (host_level == PT_PAGE_TABLE_LEVEL)
		return host_level;

	max_level = min(MAX_HUGE_PAGES_LEVEL, host_level);

	pt_level = &mmu_pt_get_host_pt_struct(vcpu->kvm)->levels[
							PT_DIRECTORY_LEVEL];
	for (level = PT_DIRECTORY_LEVEL; level <= max_level; ++level) {
		if (!is_huge_pt_level(pt_level))
			break;
		if (__mmu_gfn_lpage_is_disallowed(vcpu->kvm, large_gfn,
						level, slot))
			break;
		++pt_level;
	}

	return level - 1;
}

static gfn_t kvm_mmu_page_get_gfn(struct kvm_mmu_page *sp, int index)
{
	if (!sp->role.direct)
		return sp->gfns[index];

	return sp->gfn + (index << ((sp->role.level - 1) * PT64_LEVEL_BITS));
}

static void kvm_mmu_page_set_gfn(struct kvm_mmu_page *sp, int index, gfn_t gfn)
{
	if (sp->role.direct)
		E2K_KVM_BUG_ON(gfn != kvm_mmu_page_get_gfn(sp, index));
	else
		sp->gfns[index] = gfn;
}

static bool kvm_is_thp_gpmd_invalidate(struct kvm_vcpu *vcpu,
				pgprot_t old_gpmd,  pgprot_t new_gpmd)
{
	pgprotval_t old_pmd, new_pmd;

	old_pmd = pgprot_val(old_gpmd);
	new_pmd = pgprot_val(new_gpmd);

	if (likely(!is_huge_gpte(vcpu, old_pmd) || !is_huge_gpte(vcpu, new_pmd)))
		return false;

	return old_pmd != new_pmd &&
		(old_pmd & ~get_gpmd_thp_invalidate_mask(vcpu)) == new_pmd;
}

static struct kvm_rmap_head *
pt_level_gfn_to_rmap(gfn_t gfn, const pt_level_t *pt_level, kvm_memory_slot_t *slot)
{
	unsigned long idx;
	int level = get_pt_level_id(pt_level);

	if (!(pt_level->is_pte || pt_level->is_huge)) {
		return NULL;
	}
	idx = gfn_to_index(gfn, slot->base_gfn, pt_level);
	return &slot->arch.rmap[level - PT_PAGE_TABLE_LEVEL][idx];
}

static struct kvm_rmap_head *
__gfn_to_rmap(struct kvm *kvm, gfn_t gfn, int level, kvm_memory_slot_t *slot)
{
	unsigned long idx;

	idx = kvm_gfn_to_index(kvm, gfn, slot->base_gfn, level);
	return &slot->arch.rmap[level - PT_PAGE_TABLE_LEVEL][idx];
}

static struct kvm_rmap_head *gfn_to_rmap(struct kvm *kvm, gfn_t gfn,
					 struct kvm_mmu_page *sp)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *slot;

	slots = kvm_memslots_for_spte_role(kvm, sp->role);
	slot = __gfn_to_memslot(slots, gfn);
	return __gfn_to_rmap(kvm, gfn, sp->role.level, slot);
}

static int rmap_add(struct kvm_vcpu *vcpu, pgprot_t *spte, gfn_t gfn)
{
	struct kvm_mmu_page *sp;
	struct kvm_rmap_head *rmap_head;

	sp = page_header(__pa(spte));
	kvm_mmu_page_set_gfn(sp, spte - sp->spt, gfn);
	rmap_head = gfn_to_rmap(vcpu->kvm, gfn, sp);
	trace_rmap_add_sp_entry(sp, gfn, spte, rmap_head);
	if (unlikely(is_shadow_present_pte(vcpu->kvm, *spte) &&
				trace_rmap_sp_entry_page_enabled())) {
		struct page *page;
		kvm_pfn_t pfn;

		pfn = spte_to_pfn(vcpu->kvm, *spte);
		page = pfn_to_page(pfn);
		trace_rmap_sp_entry_page(sp, spte, pfn, page, rmap_head);
	}

	return pte_list_add(vcpu, spte, rmap_head);
}

static void rmap_remove(struct kvm *kvm, pgprot_t *spte)
{
	struct kvm_mmu_page *sp;
	gfn_t gfn;
	struct kvm_rmap_head *rmap_head;

	DebugPTE("started for spte %px == 0x%lx\n",
		spte, pgprot_val(*spte));
	sp = page_header(__pa(spte));
	gfn = kvm_mmu_page_get_gfn(sp, spte - sp->spt);
	DebugPTE("SP gfn is 0x%llx\n", gfn);
	rmap_head = gfn_to_rmap(kvm, gfn, sp);
	DebugPTE("gfn rmap head at %px, val 0x%lx\n",
		rmap_head, rmap_head->val);
	trace_rmap_remove_sp_entry(sp, gfn, spte, rmap_head);
	pte_list_remove(spte, rmap_head);
	if (unlikely(is_shadow_present_pte(kvm, *spte) &&
				trace_rmap_sp_entry_page_enabled())) {
		struct page *page;
		kvm_pfn_t pfn;

		pfn = spte_to_pfn(kvm, *spte);
		page = pfn_to_page(pfn);
		trace_rmap_sp_entry_page(sp, spte, pfn, page, rmap_head);
	}
}

/*
 * Used by the following functions to iterate through the sptes linked by a
 * rmap.  All fields are private and not assumed to be used outside.
 */
struct rmap_iterator {
	/* private fields */
	struct pte_list_desc *desc;	/* holds the sptep if not NULL */
	int pos;			/* index of the sptep */
};

/*
 * Iteration must be started by this function.  This should also be used after
 * removing/dropping sptes from the rmap link because in such cases the
 * information in the itererator may not be valid.
 *
 * Returns sptep if found, NULL otherwise.
 */
static pgprot_t *rmap_get_first(struct kvm *kvm,
			struct kvm_rmap_head *rmap_head,
			struct rmap_iterator *iter)
{
	pgprot_t *sptep;

	if (!rmap_head->val)
		return NULL;

	if (!(rmap_head->val & 1)) {
		iter->desc = NULL;
		sptep = (pgprot_t *)rmap_head->val;
		goto out;
	}

	iter->desc = (struct pte_list_desc *)(rmap_head->val & ~1ul);
	iter->pos = 0;
	sptep = iter->desc->sptes[iter->pos];
out:
	BUG_ON(!is_shadow_present_pte(kvm, *sptep));
	return sptep;
}

/*
 * Must be used with a valid iterator: e.g. after rmap_get_first().
 *
 * Returns sptep if found, NULL otherwise.
 */
static pgprot_t *rmap_get_next(struct kvm *kvm, struct rmap_iterator *iter)
{
	pgprot_t *sptep;

	if (iter->desc) {
		if (iter->pos < PTE_LIST_EXT - 1) {
			++iter->pos;
			sptep = iter->desc->sptes[iter->pos];
			if (sptep)
				goto out;
		}

		iter->desc = iter->desc->more;

		if (iter->desc) {
			iter->pos = 0;
			/* desc->sptes[0] cannot be NULL */
			sptep = iter->desc->sptes[iter->pos];
			goto out;
		}
	}

	return NULL;
out:
	BUG_ON(!is_shadow_present_pte(kvm, *sptep));
	return sptep;
}

#define for_each_rmap_spte(_kvm_, _rmap_head_, _iter_, _spte_)		\
	for (_spte_ = rmap_get_first(_kvm_, _rmap_head_, _iter_);	\
	     _spte_; _spte_ = rmap_get_next(_kvm_, _iter_))

static void clear_spte(struct kvm *kvm, pgprot_t *sptep)
{
	DebugPTE("started for spte %px == 0x%lx\n",
		sptep, pgprot_val(*sptep));

	__update_clear_spte_fast(sptep, __pgprot(0ull));
}

static void validate_spte(struct kvm *kvm, pgprot_t *sptep)
{
	DebugPTE("started for spte %px == 0x%lx\n",
		sptep, pgprot_val(*sptep));

	__update_clear_spte_fast(sptep, __pgprot(get_spte_valid_mask(kvm)));
}

static bool drop_spte(struct kvm *kvm, pgprot_t *sptep)
{
	pgprot_t old_spte = *sptep;
	bool rmap_removed = false;

	DebugPTE("started for spte %px == 0x%lx\n",
		sptep, pgprot_val(old_spte));
	if (mmu_spte_clear_track_bits(kvm, sptep)) {
		trace_kvm_drop_spte(sptep, old_spte, spte_to_pfn(kvm, old_spte));
		rmap_remove(kvm, sptep);
		rmap_removed = true;
	}
	return rmap_removed;
}


static bool __drop_large_spte(struct kvm *kvm, pgprot_t *sptep)
{
	if (unlikely(is_large_pte(*sptep))) {
		WARN_ON(page_header(__pa(sptep))->role.level ==
			PT_PAGE_TABLE_LEVEL);
		drop_spte(kvm, sptep);
		--kvm->stat.lpages;
		return true;
	}

	return false;
}

static bool drop_large_spte(struct kvm_vcpu *vcpu, pgprot_t *sptep)
{
	if (__drop_large_spte(vcpu->kvm, sptep)) {
		mmu_flush_huge_remote_tlbs(vcpu, sptep);
		return true;
	}
	return false;
}

/*
 * Write-protect on the specified @sptep, @pt_protect indicates whether
 * spte write-protection is caused by protecting shadow page table.
 *
 * Note: write protection is difference between dirty logging and spte
 * protection:
 * - for dirty logging, the spte can be set to writable at anytime if
 *   its dirty bitmap is properly set.
 * - for spte protection, the spte can be writable only after unsync-ing
 *   shadow page.
 *
 * Return true if tlb need be flushed.
 */
static bool spte_write_protect(struct kvm *kvm,
				pgprot_t *sptep, bool pt_protect)
{
	pgprot_t spte = *sptep;

	if (!is_writable_pte(spte) &&
	      !(pt_protect && spte_is_locklessly_modifiable(kvm, spte)))
		return false;

	rmap_printk("rmap_write_protect: spte %px %lx\n",
		sptep, pgprot_val(*sptep));

	if (pt_protect)
		spte = clear_spte_mmu_writable_mask(kvm, spte);
	spte = clear_spte_writable_mask(kvm, spte);

	return mmu_spte_update(kvm, sptep, spte);
}

static bool __rmap_write_protect(struct kvm *kvm,
				 struct kvm_rmap_head *rmap_head,
				 bool pt_protect)
{
	pgprot_t *sptep, old_spte;
	struct rmap_iterator iter;
	bool flush = false;

	for_each_rmap_spte(kvm, rmap_head, &iter, sptep) {
		old_spte = *sptep;
		flush = spte_write_protect(kvm, sptep, pt_protect);
		if (flush && !kvm->arch.is_hv) {
			mmu_pt_flush_shadow_pt_level_tlb(kvm, sptep, old_spte);
		}
	}

	return flush;
}

static bool spte_clear_dirty(struct kvm *kvm, pgprot_t *sptep)
{
	pgprot_t spte = *sptep;

	rmap_printk("rmap_clear_dirty: spte %px %lx\n",
		sptep, pgprot_val(*sptep));

	spte = clear_spte_dirty_mask(kvm, spte);

	return mmu_spte_update(kvm, sptep, spte);
}

static bool __rmap_clear_dirty(struct kvm *kvm, kvm_rmap_head_t *rmap_head)
{
	pgprot_t *sptep, old_spte;
	struct rmap_iterator iter;
	bool flush = false;

	for_each_rmap_spte(kvm, rmap_head, &iter, sptep) {
		old_spte = *sptep;
		flush |= spte_clear_dirty(kvm, sptep);
		if (flush && !kvm->arch.is_hv) {
			mmu_pt_flush_shadow_pt_level_tlb(kvm, sptep, old_spte);
		}
	}

	return flush;
}

static bool spte_set_dirty(struct kvm *kvm, pgprot_t *sptep)
{
	pgprot_t spte = *sptep;

	rmap_printk("rmap_set_dirty: spte %px %lx\n",
		sptep, pgprot_val(*sptep));

	spte = set_spte_dirty_mask(kvm, spte);

	return mmu_spte_update(kvm, sptep, spte);
}

static bool __rmap_set_dirty(struct kvm *kvm, struct kvm_rmap_head *rmap_head)
{
	pgprot_t *sptep, old_spte;
	struct rmap_iterator iter;
	bool flush = false;

	for_each_rmap_spte(kvm, rmap_head, &iter, sptep) {
		old_spte = *sptep;
		flush |= spte_set_dirty(kvm, sptep);
		if (flush && !kvm->arch.is_hv) {
			mmu_pt_flush_shadow_pt_level_tlb(kvm, sptep, old_spte);
		}
	}

	return flush;
}

/**
 * kvm_mmu_write_protect_pt_masked - write protect selected PT level pages
 * @kvm: kvm instance
 * @slot: slot to protect
 * @gfn_offset: start of the BITS_PER_LONG pages we care about
 * @mask: indicates which pages we should protect
 *
 * Used when we do not need to care about huge page mappings: e.g. during dirty
 * logging we do not have any such mappings.
 */
static void kvm_mmu_write_protect_pt_masked(struct kvm *kvm,
				     struct kvm_memory_slot *slot,
				     gfn_t gfn_offset, unsigned long mask)
{
	struct kvm_rmap_head *rmap_head;

	while (mask) {
		rmap_head = __gfn_to_rmap(kvm,
				slot->base_gfn + gfn_offset + __ffs(mask),
				PT_PAGE_TABLE_LEVEL, slot);
		__rmap_write_protect(kvm, rmap_head, false);

		/* clear the first set bit */
		mask &= mask - 1;
	}
}

/**
 * kvm_arch_mmu_enable_log_dirty_pt_masked - enable dirty logging for selected
 * PT level pages.
 *
 * It calls kvm_mmu_write_protect_pt_masked to write protect selected pages to
 * enable dirty logging for them.
 *
 * Used when we do not need to care about huge page mappings: e.g. during dirty
 * logging we do not have any such mappings.
 */
static void arch_mmu_enable_log_dirty_pt_masked(struct kvm *kvm,
				struct kvm_memory_slot *slot,
				gfn_t gfn_offset, unsigned long mask)
{
	/* FIXME: x86 has own enable_log_dirty_pt_masked() if PML mode */
	/* is supported
	if (kvm_x86_ops->enable_log_dirty_pt_masked)
		kvm_x86_ops->enable_log_dirty_pt_masked(kvm, slot, gfn_offset,
				mask);
	else
	 */
	kvm_mmu_write_protect_pt_masked(kvm, slot, gfn_offset, mask);
}

static bool mmu_slot_gfn_write_protect(struct kvm *kvm,
				struct kvm_memory_slot *slot, u64 gfn)
{
	const pt_struct_t *spt = mmu_pt_get_host_pt_struct(kvm);
	struct kvm_rmap_head *rmap_head;
	int i;
	bool write_protected = false;

	for (i = PT_PAGE_TABLE_LEVEL; i <= PT_MAX_HUGEPAGE_LEVEL; ++i) {
		if (!(is_huge_pt_struct_level(spt, i) ||
				is_page_pt_struct_level(spt, i)))
			continue;
		rmap_head = __gfn_to_rmap(kvm, gfn, i, slot);
		write_protected |= __rmap_write_protect(kvm, rmap_head, true);
	}

	return write_protected;
}

static bool rmap_write_protect(struct kvm_vcpu *vcpu, u64 gfn)
{
	struct kvm_memory_slot *slot;

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	return mmu_slot_gfn_write_protect(vcpu->kvm, slot, gfn);
}

static bool kvm_zap_rmapp(struct kvm *kvm, struct kvm_rmap_head *rmap_head)
{
	pgprot_t *sptep, old_spte;
	struct rmap_iterator iter;
	bool flush = false;

	while ((sptep = rmap_get_first(kvm, rmap_head, &iter))) {
		bool removed;

		old_spte = *sptep;
		rmap_printk("%s: spte %px %lx.\n",
			__func__, sptep, pgprot_val(old_spte));

		removed = drop_spte(kvm, sptep);
		if (unlikely(!kvm->arch.is_hv)) {
			struct kvm_mmu_page *sp;
			gmm_struct_t *gmm;

			sp = page_header(__pa(sptep));
			gmm = kvm_get_sp_gmm(sp);
			trace_kvm_unmap_rmap(sp, sptep, old_spte, gmm, removed);

			if (removed) {
				mmu_pt_flush_shadow_pt_level_tlb(kvm,
							sptep, old_spte);
			}
		}
		flush = true;
	}

	return flush;
}

static int kvm_unmap_rmapp(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			   struct kvm_memory_slot *slot, gfn_t gfn, int level,
			   unsigned long data)
{
	return kvm_zap_rmapp(kvm, rmap_head);
}

static int kvm_set_pte_rmapp(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			     struct kvm_memory_slot *slot, gfn_t gfn, int level,
			     unsigned long data)
{
	pgprot_t *sptep, old_spte;
	struct rmap_iterator iter;
	int need_flush = 0;
	pgprot_t new_spte;
	pte_t *ptep = (pte_t *)data;
	kvm_pfn_t new_pfn;

	WARN_ON(pte_huge(*ptep));
	new_pfn = pte_pfn(*ptep);

restart:
	for_each_rmap_spte(kvm, rmap_head, &iter, sptep) {
		rmap_printk("kvm_set_pte_rmapp: spte %px %lx gfn %llx (%d)\n",
			     sptep, pgprot_val(*sptep), gfn, level);

		need_flush = 1;
		old_spte = *sptep;

		if (pte_write(*ptep)) {
			bool removed;

			removed = drop_spte(kvm, sptep);
			if (!kvm->arch.is_hv) {
				struct kvm_mmu_page *sp;
				gmm_struct_t *gmm;

				sp = page_header(__pa(sptep));
				gmm = kvm_get_sp_gmm(sp);
				trace_kvm_set_pte_rmapp(ptep, sp, sptep, old_spte,
							gmm, true);
				if (removed) {
					mmu_pt_flush_shadow_pt_level_tlb(kvm,
								sptep, old_spte);
				}
			}
			goto restart;
		} else {
			new_spte = set_spte_pfn(kvm, *sptep, new_pfn);

			new_spte = clear_spte_writable_mask(kvm, new_spte);
			new_spte = clear_spte_host_writable_mask(kvm, new_spte);
			new_spte = clear_spte_accessed_mask(kvm, new_spte);

			mmu_spte_clear_track_bits(kvm, sptep);
			mmu_spte_set(kvm, sptep, new_spte);
			if (!kvm->arch.is_hv) {
				struct kvm_mmu_page *sp;
				gmm_struct_t *gmm;

				sp = page_header(__pa(sptep));
				gmm = kvm_get_sp_gmm(sp);
				trace_kvm_set_pte_rmapp(ptep, sp, sptep, old_spte,
							gmm, false);
				mmu_pt_flush_shadow_pt_level_tlb(kvm, sptep,
								 old_spte);
			}
		}
	}

	if (need_flush)
		kvm_flush_remote_tlbs(kvm);

	return 0;
}

static int kvm_age_rmapp(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			 struct kvm_memory_slot *slot, gfn_t gfn, int level,
			 unsigned long data)
{
	pgprot_t *sptep;
	struct rmap_iterator iter;
	int young = 0;

	BUG_ON(!get_spte_accessed_mask(kvm));

	for_each_rmap_spte(kvm, rmap_head, &iter, sptep) {
		if (is_spte_accessed_mask(kvm, *sptep)) {
			young = 1;
			clear_bit((ffs(get_spte_accessed_mask(kvm)) - 1),
				 (unsigned long *)sptep);
		}
	}

	trace_kvm_age_page(gfn, level, slot, young);
	return young;
}

static int kvm_test_age_rmapp(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			      struct kvm_memory_slot *slot, gfn_t gfn,
			      int level, unsigned long data)
{
	pgprot_t *sptep;
	struct rmap_iterator iter;
	int young = 0;

	/*
	 * If there's no access bit in the secondary pte set by the
	 * hardware it's up to gup-fast/gup to set the access bit in
	 * the primary pte or in the page structure.
	 */
	if (!get_spte_accessed_mask(kvm))
		goto out;

	for_each_rmap_spte(kvm, rmap_head, &iter, sptep) {
		if (is_spte_accessed_mask(kvm, *sptep)) {
			young = 1;
			break;
		}
	}
out:
	return young;
}

typedef struct slot_rmap_walk_iterator {
	/* input fields. */
	struct kvm_memory_slot *slot;
	gfn_t start_gfn;
	gfn_t end_gfn;
	int start_level;
	int end_level;

	/* output fields. */
	gfn_t gfn;
	struct kvm_rmap_head *rmap;
	int level;

	/* private field. */
	struct kvm_rmap_head *end_rmap;
	const pt_struct_t *pt_struct;
	const pt_level_t *pt_level;
} slot_rmap_walk_iterator_t;

static void
rmap_walk_init_level(slot_rmap_walk_iterator_t *iterator, int level)
{
	iterator->level = level;
	iterator->pt_level = &iterator->pt_struct->levels[level];
	iterator->gfn = iterator->start_gfn;
	iterator->rmap = pt_level_gfn_to_rmap(iterator->gfn,
					iterator->pt_level, iterator->slot);
	iterator->end_rmap = pt_level_gfn_to_rmap(iterator->end_gfn,
					iterator->pt_level, iterator->slot);
}

static void
slot_rmap_walk_init(struct kvm *kvm, slot_rmap_walk_iterator_t *iterator,
		    kvm_memory_slot_t *slot, int start_level,
		    int end_level, gfn_t start_gfn, gfn_t end_gfn)
{
	iterator->slot = slot;
	iterator->start_level = start_level;
	iterator->pt_struct = mmu_pt_get_host_pt_struct(kvm);
	iterator->end_level = end_level;
	iterator->start_gfn = start_gfn;
	iterator->end_gfn = end_gfn;

	rmap_walk_init_level(iterator, iterator->start_level);
}

static bool slot_rmap_walk_okay(struct slot_rmap_walk_iterator *iterator)
{
	return !!iterator->rmap;
}

static void slot_rmap_walk_next(struct slot_rmap_walk_iterator *iterator)
{
	if (++iterator->rmap <= iterator->end_rmap) {
		iterator->gfn +=
			(1UL << KVM_PT_LEVEL_HPAGE_GFN_SHIFT(iterator->pt_level));
		return;
	}

	if (++iterator->level > iterator->end_level) {
		iterator->rmap = NULL;
		return;
	}

	rmap_walk_init_level(iterator, iterator->level);
}

#define for_each_slot_rmap_range(_slot_, _start_level_, _end_level_,	\
	   _start_gfn, _end_gfn, _iter_, _kvm_)				\
		for (slot_rmap_walk_init(_kvm_, _iter_, _slot_,		\
				_start_level_, _end_level_,		\
				_start_gfn, _end_gfn);			\
			slot_rmap_walk_okay(_iter_);			\
				slot_rmap_walk_next(_iter_))

static int kvm_handle_rmap_range(struct kvm *kvm, kvm_memory_slot_t *memslot,
			unsigned long start, unsigned long end,
			unsigned long data,
			int (*handler)(struct kvm *kvm,
				struct kvm_rmap_head *rmap_head,
				struct kvm_memory_slot *slot,
				gfn_t gfn, int level, unsigned long data))
{
	unsigned long hva_start, hva_end;
	gfn_t gfn_start, gfn_end;
	slot_rmap_walk_iterator_t iterator;
	int ret = 0;

	hva_start = max(start, memslot->userspace_addr);
	hva_end = min(end, memslot->userspace_addr +
				(memslot->npages << PAGE_SHIFT));
	if (hva_start >= hva_end)
		return false;

	/*
	 * {gfn(page) | page intersects with
	 *			[hva_start, hva_end)} =
	 * {gfn_start, gfn_start+1, ..., gfn_end-1}
	 */
	gfn_start = hva_to_gfn_memslot(hva_start, memslot);
	gfn_end = hva_to_gfn_memslot(hva_end + PAGE_SIZE - 1, memslot);

	trace_kvm_handle_rmap_range(hva_start, hva_end, gfn_to_gpa(gfn_start),
		gfn_to_gpa(gfn_end), (void *)handler);

	for_each_slot_rmap_range(memslot,
				 PT_PAGE_TABLE_LEVEL,  PT_MAX_HUGEPAGE_LEVEL,
				 gfn_start, gfn_end - 1, &iterator, kvm) {
		ret |= handler(kvm, iterator.rmap, memslot,
				iterator.gfn, iterator.level, data);
	}

	return ret;
}

static int kvm_handle_hva_range(struct kvm *kvm,
				unsigned long start,
				unsigned long end,
				unsigned long data,
				int (*handler)(struct kvm *kvm,
					       struct kvm_rmap_head *rmap_head,
					       struct kvm_memory_slot *slot,
					       gfn_t gfn,
					       int level,
					       unsigned long data))
{
	struct kvm_memslots *slots;
	kvm_memory_slot_t *memslot;
	int ret = 0;
	int i;

	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		slots = __kvm_memslots(kvm, i);
		kvm_for_each_memslot(memslot, slots) {
			ret |= kvm_handle_rmap_range(kvm, memslot,
					start, end, data, handler);
		}
	}

	return ret;
}

static int kvm_handle_hva(struct kvm *kvm, unsigned long hva,
			  unsigned long data,
			  int (*handler)(struct kvm *kvm,
					 struct kvm_rmap_head *rmap_head,
					 struct kvm_memory_slot *slot,
					 gfn_t gfn, int level,
					 unsigned long data))
{
	return kvm_handle_hva_range(kvm, hva, hva + 1, data, handler);
}

static int unmap_hva_range(struct kvm *kvm, unsigned long start,
				unsigned long end, unsigned flags)
{
	trace_kvm_unmap_hva_range_start(kvm, start, end, flags);
	return kvm_handle_hva_range(kvm, start, end, 0, kvm_unmap_rmapp);
}

static int set_spte_hva(struct kvm *kvm, unsigned long hva, pte_t pte)
{
	trace_kvm_set_spte_hva(kvm, hva, pte);
	return kvm_handle_hva(kvm, hva, (unsigned long)&pte, kvm_set_pte_rmapp);
}

static int age_hva(struct kvm *kvm, unsigned long start, unsigned long end)
{
	trace_kvm_age_hva(start, end);
	return kvm_handle_hva_range(kvm, start, end, 0, kvm_age_rmapp);
}

static int test_age_hva(struct kvm *kvm, unsigned long hva)
{
	trace_kvm_test_age_hva(hva);
	return kvm_handle_hva(kvm, hva, 0, kvm_test_age_rmapp);
}

#define RMAP_RECYCLE_THRESHOLD 1000

static void rmap_recycle(struct kvm_vcpu *vcpu, pgprot_t *spte, gfn_t gfn)
{
	struct kvm_rmap_head *rmap_head;
	struct kvm_mmu_page *sp;

	sp = page_header(__pa(spte));

	rmap_head = gfn_to_rmap(vcpu->kvm, gfn, sp);

	kvm_unmap_rmapp(vcpu->kvm, rmap_head, NULL, gfn, sp->role.level, 0);
	mmu_flush_remote_tlbs(vcpu, spte, sp->role.level);
}

#ifdef MMU_DEBUG
static int is_empty_shadow_page(struct kvm *kvm, pgprot_t *spt)
{
	pgprot_t *pos;
	pgprot_t *end;

	for (pos = spt, end = pos + PAGE_SIZE / sizeof(pgprot_t);
			pos != end; pos++)
		if (is_shadow_present_pte(kvm, *pos)) {
			pr_err("%s: %px %lx\n",
				__func__, pos, pgprot_val(*pos));
			return 0;
		}
	return 1;
}
#endif

static void kvm_mmu_free_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	DebugZAP("SP at %px gva 0x%lx gfn 0x%llx spt at %px\n",
		sp, sp->gva, sp->gfn, sp->spt);
	KVM_WARN_ON(!is_empty_shadow_page(kvm, sp->spt));
	hlist_del(&sp->hash_link);
	list_del(&sp->link);
	if (!kvm->arch.is_hv) {
		kvm_delete_sp_from_gmm_list(sp);
	}
	free_page((unsigned long)sp->spt);
	if (!sp->role.direct)
		free_page((unsigned long)sp->gfns);
	kmem_cache_free(mmu_page_header_cache, sp);
}

static void do_drop_parent_pte(struct kvm *kvm, struct kvm_mmu_page *sp,
			    pgprot_t *parent_pte, bool as_valid)
{
	struct kvm_mmu_page *parent_sp = page_header(__pa(parent_pte));

	if (unlikely(parent_sp == sp)) {
		/* it is one PGD entry for the VPTB self-map. */
		E2K_KVM_BUG_ON(sp->role.level != PT64_ROOT_LEVEL);
	} else {
		mmu_page_remove_parent_pte(sp, parent_pte);
	}
	if (likely(!as_valid)) {
		mmu_spte_clear_no_track(parent_pte);
	} else {
		mmu_spte_clear_as_valid(kvm, parent_pte);
	}
	pv_mmu_drop_copied_parent_pte(kvm, sp, parent_sp, parent_pte);
}

static inline void drop_parent_pte(struct kvm *kvm, struct kvm_mmu_page *sp,
				      pgprot_t *parent_pte)
{
	do_drop_parent_pte(kvm, sp, parent_pte, false);
}

static inline void drop_parent_pte_as_valid(struct kvm *kvm,
			struct kvm_mmu_page *sp, pgprot_t *parent_pte)
{
	do_drop_parent_pte(kvm, sp, parent_pte, true);
}

static void mark_unsync(struct kvm *kvm, pgprot_t *spte, int level);
static void mark_parents_unsync(struct kvm *kvm, kvm_mmu_page_t *sp)
{
	pgprot_t *sptep;
	struct rmap_iterator iter;

	for_each_rmap_spte(kvm, &sp->parent_ptes, &iter, sptep) {
		mark_unsync(kvm, sptep, sp->role.level + 1);
	}
}

static void mark_unsync(struct kvm *kvm, pgprot_t *spte, int level)
{
	kvm_mmu_page_t *sp;
	unsigned int index;

	sp = page_header(__pa(spte));
	if (unlikely(sp == NULL)) {
		if (level == E2K_PGD_LEVEL_NUM) {
			/* pgd level can by copied for host & guest entries */
			/* and copied PTs should not have own SP structures */
			return;
		}
		E2K_KVM_BUG_ON(true);
	}
	index = spte - sp->spt;
	if (__test_and_set_bit(index, sp->unsync_child_bitmap))
		return;
	if (sp->unsync_children++)
		return;
	mark_parents_unsync(kvm, sp);
}

static int __mmu_unsync_walk(struct kvm *kvm, kvm_mmu_page_t *sp,
				struct kvm_mmu_pages *pvec, int pte_level);
static int __mmu_release_walk(struct kvm *kvm, kvm_mmu_page_t *sp,
				struct kvm_mmu_pages *pvec, int pte_level);

static int __mmu_unsync_sp(struct kvm *kvm, kvm_mmu_page_t *sp,
		   struct kvm_mmu_pages *pvec, int i, bool unsync, int pt_level)
{
	int ret, nr_unsync_leaf = 0;
	struct kvm_mmu_page *child;
	pgprot_t ent = sp->spt[i];

	if (!is_shadow_present_pte(kvm, ent)) {
		if (unsync)
			clear_unsync_child_bit(sp, i);
		DebugPTE("pte not present, return 0\n");
		return 0;
	}

	DebugFREE("found unsynced child entry index 0x%03lx : 0x%lx\n",
		i * sizeof(pgprot_t), pgprot_val(ent));

	BUG_ON(sp->role.level < pt_level);

	if (sp->role.level == pt_level) {
		DebugFREE("sp %px level #%d, return 1\n", sp, sp->role.level);
		return 1;
	}
	if (is_large_pte(ent)) {
		DebugFREE("sp %px level #%d is huge page gfn 0x%llx\n",
			sp, sp->role.level, sp->gfn);
		return 1;
	}

	child = page_header(kvm_spte_pfn_to_phys_addr(kvm, ent));
	child->released = sp->released;

	if (child->unsync_children || child->released) {
		if (mmu_pages_add(pvec, child, i)) {
			ret = -ENOSPC;
			goto out_failed;
		}

		if (child->released) {
			ret = __mmu_release_walk(kvm, child, pvec, pt_level);
		} else {
			ret = __mmu_unsync_walk(kvm, child, pvec, pt_level);
		}
		if (!ret) {
			if (unsync)
				clear_unsync_child_bit(sp, i);
		} else if (ret > 0) {
			nr_unsync_leaf += ret;
		} else {
			goto out_failed;
		}
	} else if (child->unsync) {
		nr_unsync_leaf++;
		if (mmu_pages_add(pvec, child, i)) {
			ret = -ENOSPC;
			goto out_failed;
		}
	} else {
		if (unsync)
			clear_unsync_child_bit(sp, i);
	}

	DebugFREE("return nr_unsync_leaf %d\n", nr_unsync_leaf);
	return nr_unsync_leaf;

out_failed:
	DebugFREE("failed error %d\n", ret);
	return ret;
}

static int __mmu_unsync_walk(struct kvm *kvm, kvm_mmu_page_t *sp,
			struct kvm_mmu_pages *pvec, int pte_level)
{
	int i, ret, nr_unsync_leaf = 0;

	DebugFREE("started to walk unsynced SP %px level #%d\n",
		sp, sp->role.level);
	for_each_set_bit(i, sp->unsync_child_bitmap, 512) {
		ret = __mmu_unsync_sp(kvm, sp, pvec, i, true, pte_level);
		if (!ret) {
			continue;
		} else if (ret > 0) {
			nr_unsync_leaf += ret;
		} else {
			goto out_failed;
		}
	}

	DebugFREE("return nr_unsync_leaf %d\n", nr_unsync_leaf);
	return nr_unsync_leaf;

out_failed:
	DebugFREE("failed error %d\n", ret);
	return ret;
}

static int __mmu_release_walk(struct kvm *kvm, kvm_mmu_page_t *sp,
				struct kvm_mmu_pages *pvec, int pte_level)
{
	int i, ret, nr_unsync_leaf = 0;

	DebugFREE("started to walk released SP %px level #%d\n",
		sp, sp->role.level);
	for (i = 0; i < 512; i++) {
		ret = __mmu_unsync_sp(kvm, sp, pvec, i, false, pte_level);
		if (!ret) {
			continue;
		} else if (ret > 0) {
			nr_unsync_leaf += ret;
		} else {
			goto out_failed;
		}
	}
	if (nr_unsync_leaf == 0 && sp->role.level == pte_level) {
		/* pgd/pud/pmd level PT is empty & can be released */
		DebugFREE("SP %px level #%d gfn 0x%llx gva 0x%lx is empty "
			"to release\n",
			sp, sp->role.level, sp->gfn, sp->gva);
		nr_unsync_leaf++;
	}

	DebugFREE("return nr_unsync_leaf %d\n", nr_unsync_leaf);
	return nr_unsync_leaf;

out_failed:
	DebugFREE("failed error %d\n", ret);
	return ret;
}

static int mmu_unsync_walk(struct kvm *kvm, kvm_mmu_page_t *sp,
			struct kvm_mmu_pages *pvec, int pt_entries_level)
{
	int nr_unsync_leaf = 0;

	pvec->nr = 0;
	DebugFREE("SP %px level #%d gfn 0x%llx gva 0x%lx\n",
		sp, sp->role.level, sp->gfn, sp->gva);
	if (!sp->unsync_children && !sp->released) {
		DebugFREE("sp %px level #%d not released, return 0\n",
			sp, sp->role.level);
		return 0;
	}

	mmu_pages_add(pvec, sp, INVALID_INDEX);
	if (sp->released) {
		nr_unsync_leaf = __mmu_release_walk(kvm, sp, pvec,
							pt_entries_level);
	} else {
		nr_unsync_leaf = __mmu_unsync_walk(kvm, sp, pvec,
							pt_entries_level);
	}

	DebugFREE("return nr_unsync_leaf %d\n", nr_unsync_leaf);
	return nr_unsync_leaf;
}

static void shadow_pt_walk_init(kvm_shadow_walk_iterator_t *iterator,
		struct kvm_vcpu *vcpu, hpa_t spt_root, u64 addr)
{
	iterator->addr = addr;
	iterator->shadow_addr = spt_root;
	iterator->level = vcpu->arch.mmu.shadow_root_level;
	iterator->pt_struct = mmu_pt_get_host_pt_struct(vcpu->kvm);
	iterator->pt_level = &iterator->pt_struct->levels[iterator->level];

	if (iterator->level == PT64_ROOT_LEVEL &&
		vcpu->arch.mmu.root_level < PT64_ROOT_LEVEL &&
			!vcpu->arch.mmu.direct_map) {
		--iterator->level;
		--iterator->pt_level;
	}
}
static void shadow_walk_init(kvm_shadow_walk_iterator_t *iterator,
			struct kvm_vcpu *vcpu, u64 addr)
{
	hpa_t spt_root = kvm_get_space_addr_root(vcpu, addr);

	shadow_pt_walk_init(iterator, vcpu, spt_root, addr);
}

static bool shadow_walk_okay(kvm_shadow_walk_iterator_t *iterator)
{
	if (iterator->level < PT_PAGE_TABLE_LEVEL)
		return false;

	iterator->index = get_pt_level_addr_index(iterator->addr,
							iterator->pt_level);
	iterator->sptep	= ((pgprot_t *)__va(iterator->shadow_addr)) +
							iterator->index;
	return true;
}

static void __shadow_walk_next(kvm_shadow_walk_iterator_t *iterator,
				pgprot_t spte)
{
	if (is_last_spte(spte, iterator->level)) {
		iterator->level = 0;
		iterator->pt_level = &iterator->pt_struct->levels[0];
		return;
	}

	iterator->shadow_addr = kvm_pte_pfn_to_phys_addr(spte,
						iterator->pt_struct);
	--iterator->level;
	--iterator->pt_level;
}

static void shadow_walk_next(struct kvm_shadow_walk_iterator *iterator)
{
	return __shadow_walk_next(iterator, *iterator->sptep);
}

static void pv_mmu_make_sync_request(struct kvm_vcpu *vcpu,
			struct kvm_mmu_page *sp, gmm_struct_t *gmm)
{
	if (likely(vcpu->arch.is_hv ||
			sp == NULL || sp->role.level != E2K_PGD_LEVEL_NUM))
		return;

	if (gmm == NULL)
		gmm = kvm_get_sp_gmm(sp);

	if (unlikely(pv_vcpu_is_init_gmm(vcpu, gmm))) {
		kvm_make_request(KVM_REQ_SYNC_INIT_SPT_ROOT, vcpu);
	} else {
		kvm_make_request(KVM_REQ_SYNC_GMM_SPT_ROOT, vcpu);
	}
}

static void pv_mmu_spte_make_sync_request(struct kvm_vcpu *vcpu, pgprot_t *spte)
{
	struct kvm_mmu_page *sp;
	int pte_index;

	sp = page_header(__pa(spte));
	E2K_KVM_BUG_ON(sp == NULL);
	E2K_KVM_BUG_ON(sp->role.level != E2K_PGD_LEVEL_NUM);

	pte_index = spte - sp->spt;
	pv_mmu_make_sync_request(vcpu, sp, NULL);
}

static void link_shadow_page(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				pgprot_t *sptep, struct kvm_mmu_page *sp)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_mmu_page *parent_sp;
	pgprot_t spte;

	pgprot_val(spte) = get_spte_pt_user_prot(kvm);
	spte = set_spte_pfn(kvm, spte, __pa(sp->spt) >> PAGE_SHIFT);

	mmu_spte_set(vcpu->kvm, sptep, spte);

	mmu_page_add_parent_pte(vcpu, sp, sptep);

	if (unlikely(!vcpu->arch.is_hv)) {
		kvm_try_add_sp_to_gmm_list(gmm, sp);
	}

	parent_sp = page_header(__pa(sptep));
	pv_mmu_make_sync_request(vcpu, parent_sp, gmm);

	if (likely(parent_sp != NULL && (sp->unsync_children || sp->unsync)))
		mark_unsync(kvm, sptep, parent_sp->role.level);
}

static void validate_direct_spte(struct kvm_vcpu *vcpu, pgprot_t *sptep,
				   unsigned direct_access)
{
	if (is_shadow_present_pte(vcpu->kvm, *sptep) && !is_large_pte(*sptep)) {
		struct kvm_mmu_page *child;

		/*
		 * For the direct sp, if the guest pte's dirty bit
		 * changed form clean to dirty, it will corrupt the
		 * sp's access: allow writable in the read-only sp,
		 * so we should update the spte at this point to get
		 * a new sp with the correct access.
		 */
		child = page_header(kvm_spte_pfn_to_phys_addr(vcpu->kvm,
								*sptep));
		if (child->role.access == direct_access)
			return;

		drop_parent_pte(vcpu->kvm, child, sptep);
		kvm_flush_remote_tlbs(vcpu->kvm);
	}
}

static void link_copied_shadow_page(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
					pgprot_t *dst_sptep, pgprot_t src_spte)
{
	struct kvm_mmu_page *child;

	child = page_header(kvm_spte_pfn_to_phys_addr(vcpu->kvm, src_spte));
	E2K_KVM_BUG_ON(child == NULL);
	link_shadow_page(vcpu, gmm, dst_sptep, child);
	DebugCPSPT("copied %px = 0x%lx from 0x%lx\n",
		dst_sptep, pgprot_val(*dst_sptep), pgprot_val(src_spte));
}

static void copy_guest_shadow_root_range(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
					 pgprot_t *dst_root, pgprot_t *src_root,
					 int start_index, int end_index)
{
	int index;
	pgprot_t *sptep, spte;

	for (index = start_index; index < end_index; index++) {
		sptep = &dst_root[index];
		spte = src_root[index];
		if (!is_shadow_present_pte(vcpu->kvm, spte))
			continue;
		link_copied_shadow_page(vcpu, gmm, sptep, spte);
	}
}

static void pv_mmu_drop_copied_parent_pte(struct kvm *kvm,
			struct kvm_mmu_page *child,
			struct kvm_mmu_page *parent, pgprot_t *parent_pte)
{
	gmm_struct_t *gmm;
	pgprot_t *gk_root, *gk_spte;
	int pte_index;

	if (likely(kvm->arch.is_hv ||
			parent == NULL || parent->role.level != E2K_PGD_LEVEL_NUM))
		return;

	if (unlikely(parent->root_flags.nonpaging)) {
		/* there is not copied PTs in nonpaging mode */
		return;
	}
	gmm = kvm_get_sp_gmm(child);
	pte_index = parent_pte - parent->spt;
	if (pte_index < GUEST_USER_PGD_PTRS_START ||
			pte_index >= GUEST_USER_PGD_PTRS_END) {
		/* there is guest kernel pgd entry dropping */
		/* it need issue request to sync all copied PTs entries */
		E2K_KVM_BUG_ON(!pv_mmu_is_init_gmm(kvm, gmm));
		trace_host_get_gmm_root_hpa(gmm, NATIVE_READ_IP_REG_VALUE());
		if (!VALID_PAGE(gmm->gk_root_hpa))
			return;
		gk_root = (pgprot_t *)__va(gmm->gk_root_hpa);
		sync_dropped_guest_shadow_root_range(kvm,
			gk_root, (pgprot_t *)kvm_mmu_get_init_gmm_root(kvm),
			pte_index, pte_index + 1);
		return;
	}

	E2K_KVM_BUG_ON(pv_mmu_is_init_gmm(kvm, gmm));

	trace_host_get_gmm_root_hpa(gmm, NATIVE_READ_IP_REG_VALUE());
	if (likely(!VALID_PAGE(gmm->gk_root_hpa)))
		return;

	gk_root = (pgprot_t *)__va(gmm->gk_root_hpa);
	gk_spte = &gk_root[pte_index];

	drop_parent_pte(kvm, child, gk_spte);
}

static void drop_copied_root_spte(struct kvm *kvm, pgprot_t *sptep)
{
	struct kvm_mmu_page *child;

	child = page_header(kvm_spte_pfn_to_phys_addr(kvm, *sptep));
	if (unlikely(child == NULL)) {
		pr_err("%s(): empty child for sptep %px == 0x%lx\n",
			__func__, sptep, pgprot_val(*sptep));
		pgprot_val(*sptep) = 0;
		return;
	}
	drop_parent_pte(kvm, child, sptep);
}

static void sync_dropped_guest_shadow_root_range(struct kvm *kvm,
			pgprot_t *dst_root, pgprot_t *src_root,
			int start_index, int end_index)
{
	int index;
	pgprot_t *sptep, spte;

	for (index = start_index; index < end_index; index++) {
		sptep = &dst_root[index];
		spte = src_root[index];
		if (likely(pgprot_val(spte) == 0)) {
			if (likely(!is_shadow_present_pte(kvm, *sptep))) {
				*sptep = spte;
				continue;
			}
			drop_copied_root_spte(kvm, sptep);
		} else {
			E2K_KVM_BUG_ON(true);
		}
	}
}

static void sync_guest_shadow_root_range(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
					 pgprot_t *dst_root, pgprot_t *src_root,
					 int start_index, int end_index)
{
	int index;
	pgprot_t *sptep, spte;

	for (index = start_index; index < end_index; index++) {
		sptep = &dst_root[index];
		spte = src_root[index];
		if (!is_shadow_present_pte(vcpu->kvm, spte)) {
			if (likely(!is_shadow_present_pte(vcpu->kvm, *sptep))) {
				*sptep = spte;
				continue;
			}
			drop_copied_root_spte(vcpu->kvm, sptep);
			continue;
		}
		if (likely(spte_same(spte, *sptep)))
			continue;
		if (unlikely(is_shadow_present_pte(vcpu->kvm, *sptep))) {
			/* release old link from pgd */
			drop_copied_root_spte(vcpu->kvm, sptep);
		}
		link_copied_shadow_page(vcpu, gmm, sptep, spte);
	}
}

static void sync_guest_user_root_range(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				       pgprot_t *dst_root, pgprot_t *src_root)
{
	sync_guest_shadow_root_range(vcpu, gmm, dst_root, src_root,
		GUEST_USER_PGD_PTRS_START, GUEST_USER_PGD_PTRS_END);
}

static void sync_guest_kernel_root_range(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
					 pgprot_t *init_root)
{
	gmm_struct_t *init_gmm;
	pgprot_t *gk_root;

	trace_host_get_gmm_root_hpa(gmm, NATIVE_READ_IP_REG_VALUE());
	if (unlikely(!VALID_PAGE(gmm->gk_root_hpa))) {
		/* gmm is now releasing */
		return;
	}
	gk_root = (pgprot_t *)__va(gmm->gk_root_hpa);
	init_gmm = pv_vcpu_get_init_gmm(vcpu);
	sync_guest_shadow_root_range(vcpu, init_gmm, gk_root, init_root,
		GUEST_KERNEL_PGD_PTRS_START, GUEST_KERNEL_PGD_PTRS_END);
}

#define	CHECK_GUEST_USER_ROOT
#define	CHECK_GUEST_KERNEL_ROOT

#ifdef	CHECK_GUEST_USER_ROOT
static void check_guest_root_empty_range(struct kvm_vcpu *vcpu,
			pgprot_t *root, int start_index, int end_index,
			const char *root_info)
{
	pgprot_t spte;
	int index;

	for (index = start_index; index < end_index; index++) {
		spte = root[index];
		if (likely(pgprot_val(spte) == 0))
				continue;
		pr_err("%s(): %s\n"
			"     entry at %px[%03lx] : %016lx\n",
			__func__, root_info, root, index * sizeof(pgprot_t),
			pgprot_val(spte));
	}
}

static void check_guest_user_root_kernel_range(struct kvm_vcpu *vcpu,
					       gmm_struct_t *gmm)
{
	pgprot_t *u_root;

	if (unlikely(pv_vcpu_is_init_gmm(vcpu, gmm)))
		return;
	if (unlikely(!VALID_PAGE(gmm->root_hpa)))
		return;

	u_root = (pgprot_t *)__va(gmm->root_hpa);
	check_guest_root_empty_range(vcpu, u_root,
		GUEST_KERNEL_PGD_PTRS_START, GUEST_KERNEL_PGD_PTRS_END,
		"guest user PT root contains guest kernel");
}

static void check_guest_init_root_user_range(struct kvm_vcpu *vcpu)
{
	gmm_struct_t *init_gmm;
	pgprot_t *init_root;

	init_gmm = pv_vcpu_get_init_gmm(vcpu);
	if (unlikely(!VALID_PAGE(init_gmm->root_hpa)))
		return;
	init_root = (pgprot_t *)__va(init_gmm->root_hpa);
	check_guest_root_empty_range(vcpu, init_root,
		GUEST_USER_PGD_PTRS_START, GUEST_USER_PGD_PTRS_END,
		"guest init PT root contains guest user");
}
#else	/* !CHECK_GUEST_USER_ROOT */
static void check_guest_user_root_kernel_range(struct kvm_vcpu *vcpu,
					       gmm_struct_t *gmm)
{
}
static void check_guest_init_root_user_range(struct kvm_vcpu *vcpu)
{
}
#endif	/* CHECK_GUEST_USER_ROOT */

#ifdef	CHECK_GUEST_KERNEL_ROOT
static void check_guest_kernel_root_equal_range(struct kvm_vcpu *vcpu,
			gmm_struct_t *gmm, pgprot_t *copied_root,
			pgprot_t *src_root, int start_index, int end_index,
			const char *root_info)
{
	pgprot_t src_spte, copied_spte;
	int index;

	for (index = start_index; index < end_index; index++) {
		src_spte = src_root[index];
		copied_spte = copied_root[index];
		if (likely(spte_same(src_spte, copied_spte)))
				continue;
		pr_err("%s(): %s\n"
			"     copied entry at %px[%03lx] : %016lx\n"
			"     source entry at %px[%03lx] : %016lx\n",
			__func__, root_info,
			copied_root, index * sizeof(pgprot_t),
			pgprot_val(copied_spte),
			src_root, index * sizeof(pgprot_t),
			pgprot_val(src_spte));
		sync_guest_shadow_root_range(vcpu, gmm, copied_root, src_root,
						index, index + 1);
	}
}
static void check_guest_kernel_root_user_range(struct kvm_vcpu *vcpu,
					       gmm_struct_t *gmm)
{
	pgprot_t *u_root, *gk_root;

	if (unlikely(pv_vcpu_is_init_gmm(vcpu, gmm)))
		return;

	u_root = (pgprot_t *)__va(gmm->root_hpa);
	trace_host_get_gmm_root_hpa(gmm, NATIVE_READ_IP_REG_VALUE());
	if (unlikely(!VALID_PAGE(gmm->gk_root_hpa)))
		return;
	gk_root = (pgprot_t *)__va(gmm->gk_root_hpa);

	check_guest_kernel_root_equal_range(vcpu, gmm, gk_root, u_root,
		GUEST_USER_PGD_PTRS_START, GUEST_USER_PGD_PTRS_END,
		"guest kernel PT root is not synced with user PT");
}
static void check_guest_kerne_root_init_range(struct kvm_vcpu *vcpu,
					      gmm_struct_t *gmm)
{
	gmm_struct_t *init_gmm;
	pgprot_t *init_root, *gk_root;

	init_gmm = pv_vcpu_get_init_gmm(vcpu);
	init_root = (pgprot_t *)__va(init_gmm->root_hpa);
	trace_host_get_gmm_root_hpa(gmm, NATIVE_READ_IP_REG_VALUE());
	if (unlikely(!VALID_PAGE(gmm->gk_root_hpa)))
		return;
	gk_root = (pgprot_t *)__va(gmm->gk_root_hpa);

	check_guest_kernel_root_equal_range(vcpu, init_gmm, gk_root, init_root,
		GUEST_KERNEL_PGD_PTRS_START, GUEST_KERNEL_PGD_PTRS_END,
		"guest kernel PT root is not synced with init PT");
}
#else	/* !CHECK_GUEST_KERNEL_ROOT */
static void check_guest_kernel_root_user_range(struct kvm_vcpu *vcpu,
					       gmm_struct_t *gmm)
{
}
static void check_guest_kerne_root_init_range(struct kvm_vcpu *vcpu,
					      gmm_struct_t *gmm)
{
}
#endif	/* CHECK_GUEST_KERNEL_ROOT */

static void check_and_sync_guest_user_root(struct kvm_vcpu *vcpu,
					   gmm_struct_t *gmm)
{
	pgprot_t *u_root, *gk_root;

	check_guest_user_root_kernel_range(vcpu, gmm);

	if (likely(!kvm_check_request(KVM_REQ_SYNC_GMM_SPT_ROOT, vcpu))) {
		check_guest_kernel_root_user_range(vcpu, gmm);
		return;
	}

	E2K_KVM_BUG_ON(pv_vcpu_is_init_gmm(vcpu, gmm));
	trace_host_get_gmm_root_hpa(gmm, NATIVE_READ_IP_REG_VALUE());
	E2K_KVM_BUG_ON(!VALID_PAGE(gmm->gk_root_hpa));

	u_root = (pgprot_t *)__va(gmm->root_hpa);
	gk_root = (pgprot_t *)__va(gmm->gk_root_hpa);
	sync_guest_user_root_range(vcpu, gmm, gk_root, u_root);
}

static void check_and_sync_guest_kernel_root(struct kvm_vcpu *vcpu)
{
	gmm_struct_t *init_gmm, *gmm;
	hpa_t init_root_hpa;
	pgprot_t *init_root;
	struct hlist_node *next;
	int i;
#ifdef	CHECK_GUEST_KERNEL_ROOT
	bool no_sync = false;
#endif	/* CHECK_GUEST_KERNEL_ROOT */

	check_guest_init_root_user_range(vcpu);

	if (likely(!kvm_check_request(KVM_REQ_SYNC_INIT_SPT_ROOT, vcpu))) {
#ifndef	CHECK_GUEST_KERNEL_ROOT
		return;
#else	/* CHECK_GUEST_KERNEL_ROOT */
		no_sync = true;
#endif	/* !CHECK_GUEST_KERNEL_ROOT */
	}

	init_gmm = pv_vcpu_get_init_gmm(vcpu);
	init_root_hpa = init_gmm->root_hpa;
	if (unlikely(!VALID_PAGE(init_root_hpa)))
		return;

	trace_host_get_gmm_root_hpa(init_gmm, NATIVE_READ_IP_REG_VALUE());
	E2K_KVM_BUG_ON(VALID_PAGE(init_gmm->gk_root_hpa));
	init_root = (pgprot_t *)__va(init_root_hpa);

	gmmid_table_lock(&vcpu->kvm->arch.gmmid_table);
	for_each_guest_mm(gmm, i, next, &vcpu->kvm->arch.gmmid_table) {
		if (unlikely(pv_vcpu_is_init_gmm(vcpu, gmm)))
			continue;
#ifdef	CHECK_GUEST_KERNEL_ROOT
		if (likely(no_sync && gmm->pt_synced)) {
			check_guest_kerne_root_init_range(vcpu, gmm);
			continue;
		}
#endif	/* CHECK_GUEST_KERNEL_ROOT */
		sync_guest_kernel_root_range(vcpu, gmm, init_root);
	}
	gmmid_table_unlock(&vcpu->kvm->arch.gmmid_table);
}

static void check_and_sync_guest_roots(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	check_and_sync_guest_user_root(vcpu, gmm);
	check_and_sync_guest_kernel_root(vcpu);
}

static void switch_kernel_pgd_range(struct kvm_vcpu *vcpu, int cpu)
{
	hpa_t vcpu_root, vptb;
	pgprot_t spte;
	int pt_index;

	if (unlikely(!vcpu->kvm->arch.shadow_pt_set_up))
		return;

	if (is_sep_virt_spaces(vcpu)) {
		vcpu_root = kvm_get_space_type_spt_os_root(vcpu);
		vptb = kvm_get_space_type_spt_vptb(vcpu, false);
	} else {
		vcpu_root = kvm_get_space_type_spt_u_root(vcpu);
		vptb = kvm_get_space_type_spt_vptb(vcpu, true);
	}

	if (unlikely(!VALID_PAGE(vcpu_root)))
		return;

	pt_index = pgd_index(vptb);
	spte = ((pgprot_t *)__va(vcpu_root))[pt_index];
	KVM_WARN_ON(pgprot_val(spte) != 0 &&
			kvm_spte_pfn_to_phys_addr(vcpu->kvm, spte) != vcpu_root);
}

static void zap_linked_children(struct kvm *kvm, pgprot_t *root_spt,
				    int start_index, int end_index)
{
	int index;
	pgprot_t *sptep, spte;
	struct kvm_mmu_page *child;
	struct kvm_rmap_head *parent_ptes;

	if (root_spt == (pgprot_t *)kvm_mmu_get_init_gmm_root(kvm)) {
		/* it is guest kernel root PT, so free unconditionally */
		return;
	}
	for (index = start_index; index < end_index; index++) {
		sptep = &root_spt[index];
		spte = *sptep;
		if (!is_shadow_present_pte(kvm, spte))
			continue;

		child = page_header(kvm_spte_pfn_to_phys_addr(kvm, spte));
		parent_ptes = &child->parent_ptes;
		if (!parent_ptes->val) {
			pr_err("%s(): index 0x%lx %px : nothing links\n",
				__func__, index * sizeof(pgprot_t), sptep);
			E2K_KVM_BUG_ON(true);
		} else if (!(parent_ptes->val & 1)) {
			DebugFRSPT("index 0x%lx %px : only one last link\n",
				index * sizeof(pgprot_t), sptep);
		} else {
			DebugFRSPT("index 0x%lx %px : many links\n",
				index * sizeof(pgprot_t), sptep);
			drop_parent_pte(kvm, child, sptep);
		}
	}
}

static struct kvm_mmu_page *mmu_page_zap_pte(struct kvm *kvm,
				struct kvm_mmu_page *sp, pgprot_t *spte)
{
	pgprot_t pte;
	struct kvm_mmu_page *child = NULL;

	pte = *spte;
	DebugPTE("started spte %px == 0x%lx\n", spte, pgprot_val(pte));
	if (is_shadow_present_pte(kvm, pte) && !is_mmio_spte(kvm, pte)) {
		DebugFREE("SP %px level #%d gfn 0x%llx gva 0x%lx idx 0x%llx\n",
			sp, sp->role.level, sp->gfn, sp->gva,
			(u64)spte & ~PAGE_MASK);
		if (is_last_spte(pte, sp->role.level)) {
			drop_spte(kvm, spte);
			trace_kvm_sync_spte(spte, pte, sp->role.level);
			DebugPTE("spte at %px == 0x%lx dropped\n",
				spte, pgprot_val(*spte));
			if (is_large_pte(pte))
				--kvm->stat.lpages;
			return NULL;
		} else {
			child = page_header(
					kvm_spte_pfn_to_phys_addr(kvm, pte));
			if (child) {
				drop_parent_pte(kvm, child, spte);
				child->released = true;
			}
			DebugPTE("dropped spte of child SP at %px\n", child);
			return child;
		}
	}

	if (is_mmio_spte(kvm, pte))
		mmu_spte_clear_no_track(spte);

	return child;
}

static void kvm_mmu_page_unlink_children(struct kvm *kvm,
					 struct kvm_mmu_page *sp)
{
	unsigned i;

	DebugFREE("SP %px level #%d gfn 0x%llx gva 0x%lx\n",
		sp, sp->role.level, sp->gfn, sp->gva);
	for (i = 0; i < PT64_ENT_PER_PAGE; ++i)
		mmu_page_zap_pte(kvm, sp, sp->spt + i);
}

static void kvm_mmu_unlink_parents(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	pgprot_t *sptep;
	struct rmap_iterator iter;

	DebugFREE("sp %px level #%d gfn 0x%llx gva 0x%lx\n",
		sp, sp->role.level, sp->gfn, sp->gva);
	while ((sptep = rmap_get_first(kvm, &sp->parent_ptes, &iter))) {
		DebugFREE("spte %px : 0x%lx\n", sptep, pgprot_val(*sptep));
		drop_parent_pte(kvm, sp, sptep);
	}
}

static int kvm_mmu_unlink_one_child(struct kvm *kvm, struct kvm_mmu_page *sp,
				int spte_idx, struct list_head *invalid_list)
{
	int ret;
	pgprot_t spte;
	struct kvm_mmu_page *child_sp;

	spte = sp->spt[spte_idx];

	if (!is_shadow_present_pte(kvm, spte))
		return 0;

	if (is_large_pte(spte))
		return 1;

	child_sp = page_header(
			kvm_spte_pfn_to_phys_addr(kvm, spte));

	/* Propagate released flag to lower levels of spt */
	child_sp->released = sp->released;

	if (sp->released) {
		/* If released flag is set, then zap child */
		ret = kvm_mmu_prepare_zap_page(kvm, child_sp, invalid_list);
	} else if (sp->unsync_children &&
			test_bit(spte_idx, sp->unsync_child_bitmap)) {
		/*
		 * If relesed flag is not set, then zap child only
		 * if it is marked as unsynced.
		 */
		ret = kvm_mmu_prepare_zap_page(kvm, child_sp,
					invalid_list);
		/* Clear unsync flag for zapped child */
		clear_unsync_child_bit(sp, spte_idx);
	} else {
		ret = 0;
	}

	return ret;
}

static int kvm_mmu_prepare_zap_page(struct kvm *kvm, struct kvm_mmu_page *sp,
				    struct list_head *invalid_list)
{
	int ret = 0, spte_idx;
	bool zap_this_sp;

	DebugFREE("started for SP %px level #%d gfn 0x%llx gva 0x%lx\n",
		sp, sp->role.level, sp->gfn, sp->gva);
	trace_kvm_mmu_prepare_zap_page(sp);

	++kvm->stat.mmu_shadow_zapped;

	/*
	 * If this sp is pgd, zero mapping of guest kernel and host kernel
	 * ranges to prevent adding them to zap list.
	 */
	if (sp->root_flags.has_host_pgds || sp->root_flags.has_guest_pgds) {
		/* clear host PGDs, which were added to support hypervisor */
		/* MMU PTs at guest <-> hypervisor mode */
		kvm_clear_shadow_root(kvm, sp);
		sp->root_flags.has_host_pgds = 0;
		sp->root_flags.has_guest_pgds = 0;
	}

	if (sp->role.level == PT_PAGE_TABLE_LEVEL) {
		/*
		 * If this sp is on the last level of shadow pt
		 * (sptes map physical pages), then check if we need to
		 * zap list and return back to upper level of pt.
		 */
		if (sp->released || sp->unsync) {
			zap_this_sp = true;
			ret = PT_ENTRIES_PER_PAGE;
		} else {
			zap_this_sp = false;
			ret = 0;
		}
	} else {
		/* Scan all children of this sp */
		for (spte_idx = 0; spte_idx < PT_ENTRIES_PER_PAGE;
							spte_idx++) {
			ret += kvm_mmu_unlink_one_child(kvm, sp, spte_idx,
					invalid_list);
		}

		/*
		 * If this sp has released flag or all child sp's
		 * are marked as unsync, than zap it.
		 */
		if (sp->unsync_children == PT_ENTRIES_PER_PAGE ||
				sp->released)
			zap_this_sp = true;
		else
			zap_this_sp = false;

	}

	if (!zap_this_sp)
		return ret;

	/*
	 * Zap all entries of this sp , unlink it from parent and
	 * from children's parnt_ptes lists.
	 */
	kvm_mmu_page_unlink_children(kvm, sp);
	kvm_mmu_unlink_parents(kvm, sp);

	if (!sp->role.invalid && !sp->role.direct)
		unaccount_shadowed(kvm, sp);

	if (sp->unsync)
		kvm_unlink_unsync_page(kvm, sp);

	if (!sp->root_count) {
		/* Count self */
		ret++;
		list_move(&sp->link, invalid_list);
		kvm_mod_used_mmu_pages(kvm, -1);
	} else {
		list_move(&sp->link, &kvm->arch.active_mmu_pages);

		/*
		 * The obsolete pages can not be used on any vcpus.
		 * See the comments in kvm_mmu_invalidate_zap_all_pages().
		 */
		if (!sp->role.invalid && !is_obsolete_sp(kvm, sp))
			kvm_reload_remote_mmus(kvm);
	}
	sp->role.invalid = 1;
	return ret;
}

static int set_spte(struct kvm_vcpu *vcpu, pgprot_t *sptep,
		    unsigned pte_access, int level,
		    gfn_t gfn, kvm_pfn_t pfn, bool speculative,
		    bool can_unsync, bool host_writable,
		    bool only_validate, u64 pte_cui)
{
	struct kvm *kvm = vcpu->kvm;
	pgprot_t spte;
	int ret = 0;

	DebugSPF("level #%d gfn 0x%llx pfn 0x%llx pte access 0x%x\n",
		level, gfn, pfn, pte_access);
	if (set_mmio_spte(vcpu, sptep, gfn, pfn, level, pte_access))
		return 0;

	/*
	 * For the EPT case, shadow_present_mask is 0 if hardware
	 * supports exec-only page table entries.  In that case,
	 * ACC_USER_MASK and shadow_user_mask are used to represent
	 * read access.  See FNAME(gpte_access) in paging_tmpl.h.
	 */
	if (!only_validate) {
		pgprot_val(spte) = get_spte_present_valid_mask(kvm);
	} else {
		pgprot_val(spte) = get_spte_valid_mask(kvm);
		goto set_pte;
	}
	DebugSPF("spte %px base value 0x%lx, speculative %d\n",
		sptep, pgprot_val(spte), speculative);
	if (!speculative)
		spte = set_spte_accessed_mask(kvm, spte);

	if (pte_access & ACC_EXEC_MASK)
		spte = set_spte_x_mask(kvm, spte);
	else
		spte = set_spte_nx_mask(kvm, spte);

	if (pte_access & ACC_USER_MASK) {
		if (likely(!(pte_access & ACC_PRIV_MASK))) {
			spte = set_spte_priv_mask(kvm, spte);
		} else {
			/* special case: user hardware stacks */
			/* should be mapped as privileged */
			spte = set_spte_user_priv_mask(kvm, spte);
		}
	} else {
		spte = set_spte_priv_mask(kvm, spte);
	}

	if (level > PT_PAGE_TABLE_LEVEL)
		spte = set_spte_huge_page_mask(kvm, spte);

	spte = set_spte_memory_type_mask(vcpu, spte,
				gfn, kvm_is_mmio_pfn(pfn));

	if (host_writable)
		spte = set_spte_host_writable_mask(kvm, spte);
	else
		pte_access &= ~ACC_WRITE_MASK;
	DebugSPF("spte %px current value 0x%lx, host_writable %d\n",
		sptep, pgprot_val(spte), host_writable);

	spte = set_spte_cui(spte, pte_cui);

	spte = set_spte_pfn(kvm, spte, pfn);

	if (pte_access & ACC_WRITE_MASK) {

		/*
		 * Other vcpu creates new sp in the window between
		 * mapping_level() and acquiring mmu-lock. We can
		 * allow guest to retry the access, the mapping can
		 * be fixed if guest refault.
		 */
		if (level > PT_PAGE_TABLE_LEVEL &&
		    mmu_gfn_lpage_is_disallowed(vcpu, gfn, level))
			goto done;

		spte = set_spte_writable_mask(kvm, spte);
		spte = set_spte_mmu_writable_mask(kvm, spte);

		/*
		 * Optimization: for pte sync, if spte was writable the hash
		 * lookup is unnecessary (and expensive). Write protection
		 * is responsibility of mmu_get_page / kvm_sync_page.
		 * Same reasoning can be applied to dirty page accounting.
		 */
		if (!can_unsync && is_writable_pte(*sptep))
			goto set_pte;

		if (mmu_need_write_protect(vcpu, gfn, can_unsync)) {
			pgprintk("%s: found shadow page for %llx, marking ro\n",
				 __func__, gfn);
			ret = PFRES_WRITE_TRACK;
			pte_access &= ~ACC_WRITE_MASK;
			spte = clear_spte_writable_mask(kvm, spte);
			spte = clear_spte_mmu_writable_mask(kvm, spte);
		}
	}

	if (pte_access & ACC_WRITE_MASK) {
		kvm_vcpu_mark_page_dirty(vcpu, gfn);
		spte = set_spte_dirty_mask(kvm, spte);
	}
	DebugSPF("spte %px final value 0x%lx, can_unsync %d\n",
		sptep, pgprot_val(spte), can_unsync);

set_pte:
	if (mmu_spte_update(kvm, sptep, spte)) {
		mmu_flush_remote_tlbs(vcpu, sptep, level);
	}
done:
	DebugSPF("spte %px == 0x%lx\n", sptep, pgprot_val(spte));
	return ret;
}

static pf_res_t mmu_set_spte(struct kvm_vcpu *vcpu, pgprot_t *sptep,
			 unsigned pte_access, int write_fault,
			 int level, gfn_t gfn, kvm_pfn_t pfn,
			 bool speculative, bool host_writable,
			 bool only_validate, u64 pte_cui)
{
	int was_rmapped = 0;
	int rmap_count;
	pf_res_t emulate = PFRES_NO_ERR;

	pgprintk("%s: spte %lx write_fault %d gfn %llx\n",
		__func__, pgprot_val(*sptep), write_fault, gfn);

	if (only_validate)
		pfn = KVM_PFN_NULL;
	if (is_shadow_present_pte(vcpu->kvm, *sptep)) {
		pgprintk("updating spte %px == 0x%lx, new pfn 0x%llx spec %d "
			"wr %d only validate %d\n",
			sptep, pgprot_val(*sptep),
			pfn, speculative, host_writable, only_validate);
		/*
		 * If we overwrite a PTE page pointer with a 2MB PMD, unlink
		 * the parent of the now unreachable PTE.
		 */
		if (level > PT_PAGE_TABLE_LEVEL &&
					!is_large_pte(*sptep)) {
			struct kvm_mmu_page *child;
			pgprot_t pte = *sptep;
			LIST_HEAD(invalid_list);

			pgprintk("%s(): pfn old is not large, new on level #%d "
				"spte %px : 0x%lx\n",
				__func__, level, sptep, pgprot_val(*sptep));
			child = page_header(kvm_spte_pfn_to_phys_addr(vcpu->kvm,
									pte));
			if (likely(!only_validate)) {
				drop_parent_pte(vcpu->kvm, child, sptep);
			} else {
				drop_parent_pte_as_valid(vcpu->kvm, child, sptep);
			}
			mmu_flush_remote_tlbs(vcpu, sptep, level);

			/* child SP can be now released, because of */
			/* it has not more some references from parent */
			child->released = true;
			kvm_mmu_prepare_zap_page(vcpu->kvm, child, &invalid_list);
			kvm_mmu_commit_zap_page(vcpu->kvm, &invalid_list);
		} else if (pfn == KVM_PFN_NULL) {
			pgprintk("level #%d updating spte %px == 0x%lx, "
				"new pfn NULL gfn 0x%llx spec %d wr %d "
				"only validate %d\n",
				level, sptep, pgprot_val(*sptep), gfn,
				speculative, host_writable, only_validate);
			trace_kvm_sync_drop_pfn_spte(sptep, pfn, level);
			drop_spte(vcpu->kvm, sptep);
			mmu_flush_remote_tlbs(vcpu, sptep, level);
		} else if (pfn != spte_to_pfn(vcpu->kvm, *sptep)) {
			pgprintk("pfn old %llx new %llx\n",
				 spte_to_pfn(vcpu->kvm, *sptep), pfn);
			trace_kvm_sync_drop_pfn_spte(sptep, pfn, level);
			drop_spte(vcpu->kvm, sptep);
			mmu_flush_remote_tlbs(vcpu, sptep, level);
		} else {
			was_rmapped = 1;
		}
	}

	if (set_spte(vcpu, sptep, pte_access, level, gfn, pfn, speculative,
			true, host_writable, only_validate, pte_cui)) {
		if (write_fault)
			emulate = PFRES_WRITE_TRACK;
		kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
	}

	if (unlikely(is_mmio_spte(vcpu->kvm, *sptep) &&
				!is_mmio_prefixed_gfn(vcpu, gfn)))
		emulate = PFRES_TRY_MMIO;

	pgprintk("%s: setting spte %lx\n", __func__, pgprot_val(*sptep));
	if (!only_validate && !is_mmio_space_pfn(pfn))
		pgprintk("instantiating %s PTE (%s) at %llx (%lx) addr %px\n",
			(is_large_pte(*sptep)) ? "2MB" : "4kB",
			(pgprot_val(*sptep) & PT_PRESENT_MASK) ? "RW" : "R",
			gfn, pgprot_val(*sptep), sptep);
	else
		pgprintk("instantiating only valid PTE at %llx (%lx) addr %px\n",
			gfn, pgprot_val(*sptep), sptep);
	if (!was_rmapped && is_large_pte(*sptep) && !only_validate)
		++vcpu->kvm->stat.lpages;

	if (is_shadow_present_pte(vcpu->kvm, *sptep) &&
					!is_mmio_prefixed_gfn(vcpu, gfn)) {
		if (!was_rmapped) {
			rmap_count = rmap_add(vcpu, sptep, gfn);
			if (rmap_count > RMAP_RECYCLE_THRESHOLD)
				rmap_recycle(vcpu, sptep, gfn);
		}
	}

	if (!only_validate && pfn != KVM_PFN_NULL)
		kvm_release_pfn_clean(pfn);

	return emulate;
}

static struct kvm_memory_slot *
gfn_to_memslot_dirty_bitmap(struct kvm_vcpu *vcpu, gfn_t gfn,
			    bool no_dirty_log)
{
	struct kvm_memory_slot *slot;

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	if (!memslot_valid_for_gpte(slot, no_dirty_log))
		slot = NULL;

	return slot;
}

static int direct_pte_prefetch_many(struct kvm_vcpu *vcpu,
				    struct kvm_mmu_page *sp,
				    pgprot_t *start, pgprot_t *end)
{
	struct page *pages[PTE_PREFETCH_NUM];
	struct kvm_memory_slot *slot;
	unsigned access = sp->role.access;
	int i, ret;
	gfn_t gfn;

	gfn = kvm_mmu_page_get_gfn(sp, start - sp->spt);
	slot = gfn_to_memslot_dirty_bitmap(vcpu, gfn, access & ACC_WRITE_MASK);
	if (!slot)
		return -1;

	ret = gfn_to_page_many_atomic(slot, gfn, pages, end - start);
	if (ret <= 0)
		return -1;

	for (i = 0; i < ret; i++, gfn++, start++)
		mmu_set_spte(vcpu, start, access, 0, sp->role.level, gfn,
			     page_to_pfn(pages[i]), true, true, false, 0);

	return 0;
}

static void __direct_pte_prefetch(struct kvm_vcpu *vcpu,
				  struct kvm_mmu_page *sp, pgprot_t *sptep)
{
	pgprot_t *spte, *start = NULL;
	int i;

	WARN_ON(!sp->role.direct);

	i = (sptep - sp->spt) & ~(PTE_PREFETCH_NUM - 1);
	spte = sp->spt + i;

	for (i = 0; i < PTE_PREFETCH_NUM; i++, spte++) {
		if (is_shadow_present_pte(vcpu->kvm, *spte) || spte == sptep) {
			if (!start)
				continue;
			if (direct_pte_prefetch_many(vcpu, sp, start, spte) < 0)
				break;
			start = NULL;
		} else if (!start) {
			start = spte;
		}
	}
}

static void direct_pte_prefetch(struct kvm_vcpu *vcpu, pgprot_t *sptep)
{
	struct kvm_mmu_page *sp;

	/*
	 * Since it's no accessed bit on EPT, it's no way to
	 * distinguish between actually accessed translations
	 * and prefetched, so disable pte prefetch if EPT is
	 * enabled.
	 */
	if (!get_spte_accessed_mask(vcpu->kvm))
		return;

	sp = page_header(__pa(sptep));
	if (sp->role.level > PT_PAGE_TABLE_LEVEL)
		return;

	__direct_pte_prefetch(vcpu, sp, sptep);
}

static pf_res_t __direct_map(struct kvm_vcpu *vcpu, int write, int map_writable,
			int level, gfn_t gfn, kvm_pfn_t pfn, bool prefault)
{
	kvm_shadow_walk_iterator_t iterator;
	kvm_mmu_page_t *sp;
	pf_res_t emulate = PFRES_NO_ERR;
	gfn_t pseudo_gfn;
	gmm_struct_t *init_gmm = NULL;

	DebugNONP("started for level %d gfn 0x%llx pfn 0x%llx\n",
		level, gfn, pfn);
	trace_kvm_direct_map(vcpu, gfn, pfn, level, write, map_writable);

	if (!VALID_PAGE(kvm_get_gp_phys_root(vcpu)))
		return 0;

	if (unlikely(!vcpu->arch.is_hv)) {
		init_gmm = pv_vcpu_get_init_gmm(vcpu);
	}

	for_each_shadow_entry(vcpu, (u64)gfn << PAGE_SHIFT, iterator) {
		pgprotval_t old_spte;

		DebugNONP("iterator root 0x%llx level %d spte %px == 0x%lx\n",
			iterator.shadow_addr, iterator.level, iterator.sptep,
			pgprot_val(*iterator.sptep));
		E2K_KVM_BUG_ON(iterator.level == vcpu->arch.mmu.shadow_root_level &&
				iterator.shadow_addr != kvm_get_gp_phys_root(vcpu));
		old_spte = pgprot_val(*iterator.sptep);
		if (iterator.level == level) {
			emulate = mmu_set_spte(vcpu, iterator.sptep, ACC_ALL,
					       write, level, gfn, pfn, prefault,
					       map_writable, false, 0);
			DebugNONP("set spte %px == 0x%lx\n",
				iterator.sptep, pgprot_val(*iterator.sptep));
			trace_kvm_direct_map_spte(vcpu, iterator.sptep, old_spte,
					  iterator.level);
			if (emulate == PFRES_TRY_MMIO)
				break;
			direct_pte_prefetch(vcpu, iterator.sptep);
			++vcpu->stat.pf_fixed;
			break;
		}

		drop_large_spte(vcpu, iterator.sptep);
		if (!is_shadow_present_pte(vcpu->kvm, *iterator.sptep)) {
			gpa_t base_addr = iterator.addr;

			base_addr &= get_pt_level_mask(iterator.pt_level);
			pseudo_gfn = base_addr >> PAGE_SHIFT;
			sp = kvm_mmu_get_page(vcpu, pseudo_gfn, iterator.addr,
					      iterator.level - 1,
					      true, base_addr,
					      ACC_ALL, false /* validate */);

			link_shadow_page(vcpu, init_gmm, iterator.sptep, sp);
			DebugNONP("allocated PTD to nonpaging level %d, pseudo "
				"gfn 0x%llx SPTE %px == 0x%lx\n",
				iterator.level - 1, pseudo_gfn,
				iterator.sptep, pgprot_val(*iterator.sptep));
		}
		trace_kvm_direct_map_spte(vcpu, iterator.sptep, old_spte,
					  iterator.level);
	}
	return emulate;
}

static pgprot_t nonpaging_gpa_to_pte(struct kvm_vcpu *vcpu, gva_t addr)
{
	kvm_shadow_walk_iterator_t iterator;
	pgprot_t spte = {0ull};
	gpa_t gpa;

	DebugNONP("started for GVA 0x%lx\n", addr);

	gpa = nonpaging_gva_to_gpa(vcpu, addr, ACC_ALL, NULL, NULL);

	if (!kvm_is_visible_gfn(vcpu->kvm, gpa_to_gfn(gpa))) {
		pr_err("%s(): address 0x%llx is not guest valid physical "
			"address\n",
			__func__, gpa);
		return __pgprot(0);
	}

	if (!VALID_PAGE(kvm_get_gp_phys_root(vcpu))) {
		pr_err("%s(): nonpaging root PT is not yet allocated\n",
			__func__);
		return __pgprot(0);
	}

	walk_shadow_page_lockless_begin(vcpu);
	for_each_shadow_entry_lockless(vcpu, gpa, iterator, spte) {
		DebugNONP("iteratot level %d SPTE %px == 0x%lx\n",
			iterator.level, iterator.sptep, pgprot_val(spte));
		if (!is_shadow_present_pte(vcpu->kvm, spte))
			break;
	}
	walk_shadow_page_lockless_end(vcpu);

	return spte;
}

static void transparent_hugepage_adjust(struct kvm_vcpu *vcpu,
					gfn_t *gfnp, kvm_pfn_t *pfnp,
					int *levelp)
{
	kvm_pfn_t pfn = *pfnp;
	gfn_t gfn = *gfnp;
	int level = *levelp;

	/*
	 * Check if it's a transparent hugepage. If this would be an
	 * hugetlbfs page, level wouldn't be set to
	 * PT_PAGE_TABLE_LEVEL and there would be no adjustment done
	 * here.
	 */
	if (!is_error_noslot_pfn(pfn) &&
			!kvm_is_reserved_pfn(pfn) &&
			level == PT_PAGE_TABLE_LEVEL &&
			PageTransCompoundMap(pfn_to_page(pfn)) &&
			!mmu_gfn_lpage_is_disallowed(vcpu, gfn,
							PT_DIRECTORY_LEVEL)) {
		unsigned long mask;
		/*
		 * mmu_notifier_retry was successful and we hold the
		 * mmu_lock here, so the pmd can't become splitting
		 * from under us, and in turn
		 * __split_huge_page_refcount() can't run from under
		 * us and we can safely transfer the refcount from
		 * PG_tail to PG_head as we switch the pfn to tail to
		 * head.
		 */
		*levelp = level = PT_DIRECTORY_LEVEL;
		mask = kvm_mmu_pages_per_hpage(vcpu->kvm, level) - 1;
		VM_BUG_ON((gfn & mask) != (pfn & mask));
		if (pfn & mask) {
			gfn &= ~mask;
			*gfnp = gfn;
			kvm_release_pfn_clean(pfn);
			pfn &= ~mask;
			kvm_get_pfn(pfn);
			*pfnp = pfn;
		}
	}
}

static bool
fast_pf_fix_direct_spte(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
			pgprot_t *sptep, pgprot_t spte)
{
	gfn_t gfn;

	WARN_ON(!sp->role.direct);

	/*
	 * The gfn of direct spte is stable since it is calculated
	 * by sp->gfn.
	 */
	gfn = kvm_mmu_page_get_gfn(sp, sptep - sp->spt);

	/*
	 * Theoretically we could also set dirty bit (and flush TLB) here in
	 * order to eliminate unnecessary PML logging. See comments in
	 * set_spte. But fast_page_fault is very unlikely to happen with PML
	 * enabled, so we do not do this. This might result in the same GPA
	 * to be logged in PML buffer again when the write really happens, and
	 * eventually to be called by mark_page_dirty twice. But it's also no
	 * harm. This also avoids the TLB flush needed after setting dirty bit
	 * so non-PML cases won't be impacted.
	 *
	 * Compare with set_spte where instead shadow_dirty_mask is set.
	 */
	if (cmpxchg64((pgprotval_t *)sptep, pgprot_val(spte),
			pgprot_val(set_spte_writable_mask(vcpu->kvm, spte))) ==
				pgprot_val(spte))
		kvm_vcpu_mark_page_dirty(vcpu, gfn);

	return true;
}

/*
 * Return value:
 * - true: let the vcpu to access on the same address again.
 * - false: let the real page fault path to fix it.
 */
static bool fast_page_fault(struct kvm_vcpu *vcpu, gva_t gva, int level,
			    u32 error_code)
{
	struct kvm_shadow_walk_iterator iterator;
	struct kvm_mmu_page *sp;
	bool ret = false;
	pgprot_t spte = {0ull};

	DebugNONP("VCPU #%d started for GVA 0x%lx level %d\n",
		vcpu->vcpu_id, gva, level);

	if (!VALID_PAGE(kvm_get_space_addr_root(vcpu, gva)))
		return false;

	if (!page_fault_can_be_fast(error_code))
		return false;

	walk_shadow_page_lockless_begin(vcpu);
	for_each_shadow_entry_lockless(vcpu, gva, iterator, spte) {
		DebugNONP("iteratot level %d SPTE %px == 0x%lx\n",
			iterator.level, iterator.sptep, pgprot_val(spte));
		if (!is_shadow_present_pte(vcpu->kvm, spte) ||
						iterator.level < level)
			break;
	}

	/*
	 * If the mapping has been changed, let the vcpu fault on the
	 * same address again.
	 */
	if (!is_shadow_present_pte(vcpu->kvm, spte)) {
		ret = true;
		DebugNONP("the mapping has been changed, SPTE 0x%lx\n",
			pgprot_val(spte));
		goto exit;
	}

	sp = page_header(__pa(iterator.sptep));
	if (!is_last_spte(spte, sp->role.level)) {
		DebugNONP("SPTE 0x%lx is not last\n",
			pgprot_val(spte));
		goto exit;
	}

	/*
	 * Check if it is a spurious fault caused by TLB lazily flushed.
	 *
	 * Need not check the access of upper level table entries since
	 * they are always ACC_ALL.
	 */
	 if (is_writable_pte(spte)) {
		ret = true;
		DebugNONP("SPTE 0x%lx is writable - spurious fault\n",
			pgprot_val(spte));
		goto exit;
	}

	/*
	 * Currently, to simplify the code, only the spte write-protected
	 * by dirty-log can be fast fixed.
	 */
	if (!spte_is_locklessly_modifiable(vcpu->kvm, spte)) {
		DebugNONP("SPTE 0x%lx is not locklessly modifiable\n",
			pgprot_val(spte));
		goto exit;
	}

	/*
	 * Do not fix write-permission on the large spte since we only dirty
	 * the first page into the dirty-bitmap in fast_pf_fix_direct_spte()
	 * that means other pages are missed if its slot is dirty-logged.
	 *
	 * Instead, we let the slow page fault path create a normal spte to
	 * fix the access.
	 *
	 * See the comments in kvm_arch_commit_memory_region().
	 */
	if (sp->role.level > PT_PAGE_TABLE_LEVEL) {
		DebugNONP("SP level %d > PT_PAGE_TABLE_LEVEL\n",
			sp->role.level);
		goto exit;
	}

	/*
	 * Currently, fast page fault only works for direct mapping since
	 * the gfn is not stable for indirect shadow page.
	 * See Documentation/virtual/kvm/locking.txt to get more detail.
	 */
	ret = fast_pf_fix_direct_spte(vcpu, sp, iterator.sptep, spte);
	DebugNONP("fast fix direct SPTE %px == 0x%lx, ret %d\n",
		iterator.sptep, pgprot_val(spte), ret);
exit:
	trace_fast_page_fault(vcpu, gva, error_code, iterator.sptep,
			      spte, ret);
	walk_shadow_page_lockless_end(vcpu);

	return ret;
}

static pf_res_t nonpaging_map(struct kvm_vcpu *vcpu, gva_t v, u32 error_code,
				gfn_t gfn, bool prefault)
{
	pf_res_t r;
	int level;
	bool force_pt_level = false;
	kvm_pfn_t pfn;
	bool map_writable, write = error_code & PFERR_WRITE_MASK;
#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	intc_mu_state_t *mu_state = get_intc_mu_state(vcpu);
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

	DebugNONP("VCPU #%d started for GVA 0x%lx gfn 0x%llx\n",
		vcpu->vcpu_id, v, gfn);
	level = mapping_level(vcpu, gfn, &force_pt_level);
	if (likely(!force_pt_level)) {
		/*
		 * This path builds a PAE pagetable - so we can map
		 * 2mb pages at maximum. Therefore check if the level
		 * is larger than that.
		 */
		if (is_ss(vcpu) && level > PT_DIRECTORY_LEVEL)
			level = PT_DIRECTORY_LEVEL;

		gfn &= ~(kvm_mmu_pages_per_hpage(vcpu->kvm, level) - 1);
	}
	DebugNONP("mapping level %d force %d gfn 0x%llx\n",
		level, force_pt_level, gfn);

	if (fast_page_fault(vcpu, v, level, error_code))
		return 0;

	DebugNONP("there is slow page fault case\n");
	trace_kvm_slow_nonpaging_map(vcpu, v, level, error_code);

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	mu_state->notifier_seq = vcpu->kvm->mmu_notifier_seq;
	smp_rmb();
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

	pfn = mmio_prefixed_gfn_to_pfn(vcpu->kvm, gfn);

	if (unlikely(pfn)) {
		map_writable = true;
	} else {
		if (try_async_pf(vcpu, prefault, gfn, v, &pfn, write,
				&map_writable))
			return PFRES_NO_ERR;
		DebugNONP("try_async_pf() returned pfn 0x%llx\n", pfn);
	}
	trace_kvm_nonpaging_map(vcpu, gfn, pfn);

	if (handle_abnormal_pfn(vcpu, v, gfn, pfn, ACC_ALL, &r)) {
		return r;
	}

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	if (r == PFRES_TRY_MMIO) {
		mu_state->may_be_retried = false;
	}
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

	spin_lock(&vcpu->kvm->mmu_lock);
#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	if (unlikely(!mmu_notifier_no_retry(vcpu->kvm, mu_state->notifier_seq) &&
			!mu_state->ignore_notifier && r != PFRES_TRY_MMIO))
		goto out_unlock;
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */
	if (make_mmu_pages_available(vcpu) < 0)
		goto out_unlock;
	if (likely(!force_pt_level))
		transparent_hugepage_adjust(vcpu, &gfn, &pfn, &level);
	r = __direct_map(vcpu, write, map_writable, level, gfn, pfn, prefault);
	spin_unlock(&vcpu->kvm->mmu_lock);

	DebugNONP("returns %d\n", r);
	return r;

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
out_unlock:
	spin_unlock(&vcpu->kvm->mmu_lock);
	kvm_release_pfn_clean(pfn);
	E2K_KVM_BUG_ON(!mu_state->may_be_retried);
	return PFRES_RETRY;
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */
}

static void direct_unmap_prefixed_mmio_gfn(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_shadow_walk_iterator iterator;
	struct kvm_mmu_page *sp;
	int level;
	pgprot_t *sptep;
	struct kvm_vcpu *vcpu = kvm->vcpus[0];

	/*
	 * Prefixed MMIO is not rmapped, not in MMIO cache.
	 * But it is cached in TLB, and mmu_page_zap_pte() doesn't request
	 * flush for MMIO, so call it directly
	 */
	spin_lock(&kvm->mmu_lock);
	for_each_shadow_entry(vcpu, (u64)gfn << PAGE_SHIFT, iterator) {
		level = iterator.level;
		sptep = iterator.sptep;

		sp = page_header(__pa(sptep));
		if (is_last_spte(*sptep, level)) {
			mmu_page_zap_pte(kvm, sp, sptep);
			kvm_flush_remote_tlbs(kvm);
			break;
		}

		if (!is_shadow_present_pte(kvm, *sptep))
			break;

	}
	spin_unlock(&kvm->mmu_lock);
}

/* return true if reserved bit is detected on spte. */
static bool
walk_shadow_page_get_mmio_spte(struct kvm_vcpu *vcpu, u64 addr, pgprot_t *sptep)
{
	struct kvm_shadow_walk_iterator iterator;
	pgprot_t sptes[PT64_ROOT_LEVEL];
	pgprot_t spte = {0ull};
	int root, leaf;
	bool reserved = false;

	if (!VALID_PAGE(kvm_get_space_addr_root(vcpu, addr)))
		goto exit;

	walk_shadow_page_lockless_begin(vcpu);

	for (shadow_walk_init(&iterator, vcpu, addr),
		leaf = iterator.level, root = leaf;
			shadow_walk_okay(&iterator);
				__shadow_walk_next(&iterator, spte)) {
		spte = mmu_spte_get_lockless(iterator.sptep);

		sptes[leaf - 1] = spte;
		leaf--;

		if (!is_shadow_present_pte(vcpu->kvm, spte))
			break;

		reserved |= is_shadow_zero_bits_set(&vcpu->arch.mmu, spte,
						    iterator.level);
	}

	walk_shadow_page_lockless_end(vcpu);

	if (reserved) {
		pr_err("%s: detect reserved bits on spte, addr 0x%llx, "
			"dump hierarchy:\n",
		       __func__, addr);
		while (root > leaf) {
			pr_err("------ spte 0x%lx level %d.\n",
				pgprot_val(sptes[root - 1]), root);
			root--;
		}
	}
exit:
	*sptep = spte;
	return reserved;
}

static int handle_mmio_page_fault(struct kvm_vcpu *vcpu, u64 addr, gfn_t *gfn,
				  bool direct)
{
	pgprot_t spte;
	bool reserved;

	reserved = walk_shadow_page_get_mmio_spte(vcpu, addr, &spte);
	if (WARN_ON(reserved))
		return RET_MMIO_PF_BUG;

	if (is_mmio_spte(vcpu->kvm, spte)) {
		unsigned access = get_mmio_spte_access(vcpu->kvm, spte);

		*gfn = get_mmio_spte_gfn(vcpu->kvm, spte);
		if (is_mmio_prefixed_gfn(vcpu, *gfn))
			/* prefixed MMIO areas were mapped directly */
			/* and should not cause page faults */
			return RET_MMIO_PF_INVALID;
		if (!check_mmio_spte(vcpu, spte))
			return RET_MMIO_PF_INVALID;

		if (direct)
			addr = 0;

		trace_handle_mmio_page_fault(addr, *gfn, access);
		vcpu_cache_mmio_info(vcpu, addr, *gfn, access);
		return RET_MMIO_PF_EMULATE;
	}

	/*
	 * If the page table is zapped by other cpus, let CPU fault again on
	 * the address.
	 */
	return RET_MMIO_PF_RETRY;
}

static pf_res_t nonpaging_page_fault(struct kvm_vcpu *vcpu, gva_t gva,
			u32 error_code, bool prefault,
			gfn_t *gfnp, kvm_pfn_t *pfnp)
{
	gpa_t gpa = gva;
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int r;

	DebugNONP("VCPU #%d GPA 0x%llx, error 0x%x\n",
		vcpu->vcpu_id, gpa, error_code);
	pgprintk("%s: gpa 0x%llx error %x\n", __func__, gpa, error_code);

	trace_kvm_nonpaging_page_fault(vcpu, gva, error_code);

	if (gfnp != NULL)
		*gfnp = gfn;

	if (page_fault_handle_page_track(vcpu, error_code, gfn))
		return PFRES_WRITE_TRACK;

	r = mmu_topup_memory_caches(vcpu);
	if (r)
		return PFRES_ERR;

	MMU_WARN_ON(!VALID_PAGE(kvm_get_gp_phys_root(vcpu)));


	return nonpaging_map(vcpu, gpa & PAGE_MASK,
			     error_code, gfn, prefault);
}

static long kvm_hv_mmu_page_fault(struct kvm_vcpu *vcpu, struct pt_regs *regs,
				  intc_info_mu_t *intc_info_mu)
{
	intc_mu_state_t *mu_state = get_intc_mu_state(vcpu);
	intc_info_mu_event_code_t event = intc_info_mu->hdr.event_code;
	tc_cond_t cond = intc_info_mu->condition;
	e2k_addr_t address = intc_info_mu->gva;
	gpa_t gpa = intc_info_mu->gpa;
	tc_fault_type_t ftype;
	tc_opcode_t opcode;
	unsigned mas = AS(cond).mas;
	bool root = AS(cond).root;	/* secondary space */
	bool ignore_store = false;	/* the store should not be reexecuted */
	u32 error_code = 0;
	bool nonpaging = !is_paging(vcpu);
	bool gpa_for_spt = false;
	bool direct;
	kvm_pfn_t pfn;
	gfn_t gfn;
	const pgprot_t *gpte;
	int bytes;
	int try, retry;
	pf_res_t pfres;
	long r;

	if (is_shadow_paging(vcpu)) {
		if (nonpaging) {
			if (is_phys_paging(vcpu)) {
				address = gpa;
			}
		} else if (event == IME_GPA_DATA) {
			E2K_KVM_BUG_ON(mas != MAS_LOAD_PA &&
					mas != MAS_STORE_PA &&
						mas != MAS_IOADDR);
			address = gpa;
			gpa_for_spt = true;
			DebugPFINTC("%s(): intercept on GPA->PA translation "
				"fault at shadow PT mode, GPA 0x%lx,"
				"mas 0x%02x\n",
				__func__, address, mas);
		}
	} else if (is_tdp_paging(vcpu)) {
		address = gpa;
	} else if (is_phys_paging(vcpu)) {
		address = gpa;
	} else {
		E2K_KVM_BUG_ON(true);
	}

	AW(ftype) = AS(cond).fault_type;
	AW(opcode) = AS(cond).opcode;
	E2K_KVM_BUG_ON(AS(opcode).fmt == 0 || AS(opcode).fmt == 6);
	bytes = tc_cond_to_size(cond);
	if (AS(cond).s_f)
		bytes = 16;
	DebugPFINTC("page fault on guest address 0x%lx fault type 0x%x\n",
		address, AW(ftype));

	if (!nonpaging && AS(ftype).illegal_page) {
		DebugPFINTC("illegal page fault type, return back to host\n");
		r = -EINVAL;
		goto out;
	}
	if (AW(ftype) == 0) {
		error_code |= PFERR_FORCED_MASK;
		DebugPFINTC("empty page fault type\n");
	} else if (AS(ftype).page_miss) {
		error_code |= PFERR_NOT_PRESENT_MASK;
		DebugPFINTC("page miss fault type\n");
	} else if (nonpaging || gpa_for_spt) {
		error_code |= PFERR_NOT_PRESENT_MASK;
		DebugPFINTC("fault type at nonpaging mode\n");
	}
	if (tc_cond_is_store(cond, machine.native_iset_ver)) {
		error_code |= PFERR_WRITE_MASK;
		DebugPFINTC("page fault on store\n");
	} else {
		DebugPFINTC("page fault on load\n");
	}

	if (mas == MAS_WAIT_LOCK ||
			(mas == MAS_WAIT_LOCK_Q && bytes == 16)) {
		DebugPFINTC("not writable page fault on load and lock "
			"operation\n");
		/* this mas has store semantic */
		error_code |= PFERR_WAIT_LOCK_MASK;
	}
	if (mas == MAS_IOADDR) {
		DebugPFINTC("IO space access operation\n");
		error_code |= PFERR_MMIO_MASK;
	}
	if (AS(ftype).nwrite_page) {
		error_code &= ~PFERR_NOT_PRESENT_MASK;
		error_code |= PFERR_PRESENT_MASK;
		if (!(error_code & PFERR_WRITE_MASK)) {
			panic("%s(): not store or unknown or unimplemented "
				"case of load operation with store semantic: "
				"GVA 0x%lx, condition 0x%llx\n",
				__func__, address, AW(cond));
		}
		DebugPFINTC("not writable page fault type\n");
		if (AS(cond).s_f) {
			/* spill/fill operation to/from protected page */
			/* so need unprotect page */
			r = kvm_mmu_unprotect_page_virt(vcpu, address);
			if (r) {
				DebugPFINTC("unprotected GVA 0x%lx "
					"to spill/fill\n",
					address);
			}
		}
	}
	if (AS(ftype).priv_page) {
		error_code &= ~PFERR_NOT_PRESENT_MASK;
		error_code |= (PFERR_PRESENT_MASK | PFERR_USER_MASK);
		DebugPFINTC("priviled page fault type\n");
	}
	if (root && kvm_has_vcpu_exc_recovery_point(vcpu)) {
		ignore_store = !!(error_code & PFERR_WRITE_MASK);
		if (ignore_store) {
			DebugEXCRPR("%s secondary space at recovery mode: "
				"GVA 0x%lx, GPA 0x%llx, cond 0x%016llx\n",
				(ignore_store) ?
					((AS(cond).store) ? "store to"
						: "load with store "
							"semantics to")
					: "load from",
				intc_info_mu->gva, gpa, AW(cond));
		}
	}

	direct = vcpu->arch.mmu.direct_map;

	/* Software cache containing one GVA->GPA translation for the
	 * last intercepted MMIO access */
	if (is_cached_mmio_page_fault(vcpu, address, &gfn, direct)) {
		pfres = PFRES_TRY_MMIO;
		goto mmio_emulate;
	}

	/* Fast path for previously mapped MMIO (only for MAS_IOADDR) */
	if (unlikely(error_code & PFERR_MMIO_MASK)) {
		r = handle_mmio_page_fault(vcpu, address, &gfn, direct);

		if (r == RET_MMIO_PF_EMULATE) {
			pfres = PFRES_TRY_MMIO;
			goto mmio_emulate;
		}
		if (r == RET_MMIO_PF_RETRY) {
			/* MMIO address is not yet known */
		}
		if (r < 0)
			goto out;
	}

	mu_state->may_be_retried = true;
	mu_state->ignore_notifier = false;

	if (likely(!gpa_for_spt)) {
		pfres = handle_mmu_page_fault(vcpu, address, error_code,
						false, &gfn, &pfn);
	} else {
		try = 0;
		retry = 0;
		do {
			set_spt_gpa_fault(vcpu);
			mmu_set_host_pt_struct_func(vcpu->kvm,
					&kvm_mmu_get_gp_pt_struct);
			pfres = nonpaging_page_fault(vcpu, address,
					error_code, false, &gfn, &pfn);
			mmu_set_host_pt_struct_func(vcpu->kvm,
					&kvm_mmu_get_host_pt_struct);
			reset_spt_gpa_fault(vcpu);
			if (likely(pfres != PFRES_RETRY))
				break;
			try++;
			retry++;
			if (retry >= PF_RETRIES_MAX_NUM) {
				DebugTRY("retry #%d to handle page fault "
					"on %s : address 0x%lx, "
					"pfn 0x%llx / gfn 0x%llx\n",
					try,
					(AS(cond).store) ? "store" : "load",
					address, pfn, gfn);
				kvm_mmu_notifier_wait(vcpu->kvm,
						      mu_state->notifier_seq);
				retry = 0;
			}
		} while (true);
		if (PF_RETRIES_MAX_NUM > 0 && pfres == PFRES_RETRY) {
			DebugTRY("could not handle page fault on %s : "
				"retries %d, address 0x%lx, "
				"pfn 0x%llx / gfn 0x%llx\n",
				(AS(cond).store) ? "store" : "load",
				try, address, pfn, gfn);
		}
	}

	mu_state->pfres = pfres;
	DebugPFINTC("mmu.page_fault() returned %d\n", pfres);

	if (pfres == PFRES_RETRY) {
		E2K_KVM_BUG_ON(!mu_state->may_be_retried);
		r = 0;
		goto out;
	}
	if (pfres == PFRES_NO_ERR) {
		e2k_addr_t hva;
		kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
		trap_cellar_t *next_tcellar;

		/* page fault successfully handled and need recover */
		/* load/store operation */
		if (HW_REEXECUTE_IS_SUPPORTED) {
			/* MMU hardware itself will reexecute the memory */
			/* access operations */
			r = 0;
			goto out;
		}

		E2K_KVM_BUG_ON(ignore_store);

		hva = kvm_vcpu_gfn_to_hva(vcpu, gfn);
		if (kvm_is_error_hva(hva)) {
			pr_err("%s(): could not convert gfn 0x%llx to hva\n",
				__func__, gfn);
			r = -EFAULT;
			goto out;
		}
		hva |= (address & ~PAGE_MASK);
		intc_info_mu->gva = hva;
		DebugPFINTC("converted guest address 0x%lx to hva 0x%lx to "
			"recovery guest %s operation\n",
			address, hva, (AS(cond).store) ? "store" : "load");

		if (intc_ctxt->cur_mu + 1 < intc_ctxt->mu_num) {
			next_tcellar = (trap_cellar_t *)
					&(intc_info_mu + 1)->gva;
		} else {
			next_tcellar = NULL;
		}
		r = execute_mmu_operations((trap_cellar_t *)&intc_info_mu->gva,
				next_tcellar, regs, NULL,
				&check_guest_spill_fill_recovery,
				&calculate_guest_recovery_load_to_rf_frame,
				false	/* user privileged space access */);
		if (r != EXEC_MMU_SUCCESS)
			return -EFAULT;
		return 0;
	}
	if (pfres == PFRES_ERR) {
		/* error detected while page fault handling */
		r = -EFAULT;
		goto out;
	}

	if (pfres == PFRES_INJECTED) {
		/* page fault injected to guest */
		E2K_KVM_BUG_ON(ignore_store);
		return 0;
	}

mmio_emulate:

	if (pfres == PFRES_TRY_MMIO) {
		/* page fault on MMIO access */
		E2K_KVM_BUG_ON(mu_state->may_be_retried);

		if (unlikely(ignore_store && !AS(cond).spec)) {
			DebugEXCRPR("store to secondary IO space at recovery mode: "
				"injecting exc_data_page.io_page to guest\n");
			AS(intc_info_mu->condition).fault_type = 0;
			AS(intc_info_mu->condition).io_page = 1;
			kvm_set_intc_info_mu_is_updated(vcpu);
			mmu_pt_inject_page_fault(vcpu, NULL);
			return 0;
		}

		gpa = gfn_to_gpa(gfn);
		gpa |= (address & ~PAGE_MASK);
		return kvm_hv_io_page_fault(vcpu, gpa, intc_info_mu);
	}

	E2K_KVM_BUG_ON(pfres != PFRES_WRITE_TRACK);
	E2K_KVM_BUG_ON(ignore_store);

	/* set flag to enable writing for hardware recovery operation */
	intc_info_mu->hdr.ignore_wr_rights = 1;
	kvm_set_intc_info_mu_is_updated(vcpu);
	if ((error_code & PFERR_WAIT_LOCK_MASK) &&
				(error_code & PFERR_WRITE_MASK)) {
		struct kvm_mmu_page *sp;
		LIST_HEAD(invalid_list);

		/*
		 * It is load and wait lock operations.
		 * Hardware reexecute the operation, but the subsequent
		 * store and unlock operation can not be intercepted and
		 * only inevitable flush TLB line should be intercepted
		 * to update atomicaly updated PT entry.
		 */
		DebugPFINTC("reexecute hardware recovery load and wait lock "
			"operation\n");
		spin_lock(&vcpu->kvm->mmu_lock);
		for_each_gfn_indirect_valid_sp(vcpu->kvm, sp, gfn) {
			if (sp->unsync)
				continue;
			DebugPTE("found SP at %px mapped gva from 0x%lx, "
				"gfn 0x%llx\n",
				sp, sp->gva, gfn);
			if (sp->role.level != PT_PAGE_TABLE_LEVEL) {
				/* it can be only freed pgd/pud/pmd PT page */
				/* which is now used as pte PT page */
				kvm_mmu_prepare_zap_page(vcpu->kvm, sp,
							&invalid_list);
				continue;
			}
			kvm_unsync_page(vcpu, sp);
		}
		kvm_mmu_commit_zap_page(vcpu->kvm, &invalid_list);
		spin_unlock(&vcpu->kvm->mmu_lock);
		return 0;
	}

	gpa = gfn_to_gpa(gfn);
	gpa |= (address & ~PAGE_MASK);
	gpte = (const pgprot_t *)&intc_info_mu->data;

	if (HW_REEXECUTE_IS_SUPPORTED) {
		/* MMU hardware itself will reexecute the memory */
		/* access operations */
		/* FIXME: kvm_page_track_write() function assumes that
		   guest pte was already updated, but MMU hardware will
		   reexecute store to gpte operation only while return to guest
		   (GLAUNCH starts all reexecutions).
		   So temporarly hypervisor itself reexecute the store
		   and MMU hardware will reexecute too one more time.
		   It is not good
		kvm_page_track_write(vcpu, gpa,
					(const void*)gpte, sizeof(*gpte));
		return PFR_SUCCESS;
		*/
	}
	/* MMU does not support reexecition of write protected memory access */
	/* so it need convert guest address to host 'physical' and */
	/* recover based on not protected host address */
	r = write_to_guest_pt_phys(vcpu, gpa, gpte, bytes);

	if (r == 1) {
		/* guest try write to protected PT, page fault handled */
		/* and recovered by hypervisor */
		return 0;
	}

out:
	if (ignore_store) {
		/* mark the INTC_INFO_MU event as deleted to avoid */
		/* hardware reexucution of the store operation */
		kvm_delete_intc_info_mu(vcpu, intc_info_mu);
		DebugEXCRPR("store to secondary space at recovery mode "
			"will not be reexecuted by hardware\n");
	}
	return r;
}

#ifdef CONFIG_KVM_HW_VIRTUALIZATION

static pf_res_t tdp_page_fault(struct kvm_vcpu *vcpu, gva_t gpa, u32 error_code,
			       bool prefault, gfn_t *gfnp, kvm_pfn_t *pfnp)
{
	kvm_pfn_t pfn;
	pf_res_t r = PFRES_ERR;
	int ret;
	int level;
	bool force_pt_level;
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int write = error_code & PFERR_WRITE_MASK;
	bool map_writable = true;
#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	intc_mu_state_t *mu_state = get_intc_mu_state(vcpu);
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

	MMU_WARN_ON(!VALID_PAGE(kvm_get_gp_phys_root(vcpu)));

	DebugTDP("started for GPA 0x%lx\n", gpa);

	*gfnp = gfn;

	if (page_fault_handle_page_track(vcpu, error_code, gfn))
		return PFRES_WRITE_TRACK;

	ret = mmu_topup_memory_caches(vcpu);
	if (ret)
		return PFRES_ERR;

	force_pt_level = false;
	level = mapping_level(vcpu, gfn, &force_pt_level);
	if (likely(!force_pt_level)) {
		if (level > PT_DIRECTORY_LEVEL)
			level = PT_DIRECTORY_LEVEL;
		gfn &= ~(kvm_mmu_pages_per_hpage(vcpu->kvm, level) - 1);
		*gfnp = gfn;
	}

	if (fast_page_fault(vcpu, gpa, level, error_code))
		return PFRES_NO_ERR;

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	mu_state->notifier_seq = vcpu->kvm->mmu_notifier_seq;
	smp_rmb();
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

	pfn = mmio_prefixed_gfn_to_pfn(vcpu->kvm, gfn);

	if (unlikely(pfn)) {
		map_writable = true;
	} else {
		if (try_async_pf(vcpu, prefault, gfn, gpa, &pfn, write,
				&map_writable))
			return PFRES_NO_ERR;
	}

	if (handle_abnormal_pfn(vcpu, gpa, gfn, pfn, ACC_ALL, &r))
		return r;

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	if (r == PFRES_TRY_MMIO) {
		mu_state->may_be_retried = false;
	}
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

	spin_lock(&vcpu->kvm->mmu_lock);
#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	if (unlikely(!mmu_notifier_no_retry(vcpu->kvm, mu_state->notifier_seq) &&
			!mu_state->ignore_notifier && r != PFRES_TRY_MMIO))
		goto out_unlock;
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */
	if (make_mmu_pages_available(vcpu) < 0)
		goto out_unlock;
	if (likely(!force_pt_level)) {
		transparent_hugepage_adjust(vcpu, &gfn, &pfn, &level);
		*gfnp = gfn;
	}
	r = __direct_map(vcpu, write, map_writable, level, gfn, pfn, prefault);
	spin_unlock(&vcpu->kvm->mmu_lock);

	return r;

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
out_unlock:
	spin_unlock(&vcpu->kvm->mmu_lock);
	kvm_release_pfn_clean(pfn);
	if (pfnp != NULL) {
		*pfnp = pfn;
	}
	E2K_KVM_BUG_ON(!mu_state->may_be_retried && !prefault);
	return PFRES_RETRY;
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */
}
#else	/* !CONFIG_KVM_HW_VIRTUALIZATION */
static pf_res_t tdp_page_fault(struct kvm_vcpu *vcpu, gva_t gpa, u32 error_code,
			       bool prefault, gfn_t *gfnp, kvm_pfn_t *pfnp)
{
	E2K_KVM_BUG_ON(true);
	return -EINVAL;
}
#endif /* CONFIG_KVM_HW_VIRTUALIZATION */

static bool sync_mmio_spte(struct kvm_vcpu *vcpu, pgprot_t *sptep, gfn_t gfn,
			   unsigned access, int *nr_present)
{
	if (unlikely(is_mmio_spte(vcpu->kvm, *sptep))) {
		if (gfn != get_mmio_spte_gfn(vcpu->kvm, *sptep)) {
			mmu_spte_clear_no_track(sptep);
			return true;
		}

		(*nr_present)++;
		mark_mmio_spte(vcpu, sptep, gfn, access);
		return true;
	}

	return false;
}

#include "paging_tmpl.h"

static bool need_remote_flush(struct kvm *kvm, pgprot_t old, pgprot_t new)
{
	if (!is_shadow_present_pte(kvm, old))
		return false;
	if (!is_shadow_present_pte(kvm, new))
		return true;
	if ((pgprot_val(old) ^ pgprot_val(new)) & get_spte_pfn_mask(kvm))
		return true;
	pgprot_val(old) ^= get_spte_nx_mask(kvm);
	pgprot_val(new) ^= get_spte_nx_mask(kvm);
	return (pgprot_val(old) & ~pgprot_val(new) & PT64_PERM_MASK(kvm)) != 0;
}

static pgprot_t *get_written_sptes(struct kvm_mmu_page *sp, gpa_t gpa,
					int *nspte)
{
	unsigned page_offset, quadrant;
	pgprot_t *spte;
	int level;

	page_offset = offset_in_page(gpa);
	level = sp->role.level;
	*nspte = 1;
	if (!sp->role.cr4_pae) {
		page_offset <<= 1;	/* 32->64 */
		quadrant = page_offset >> PAGE_SHIFT;
		page_offset &= ~PAGE_MASK;
		if (quadrant != sp->role.quadrant)
			return NULL;
	}

	spte = &sp->spt[page_offset / sizeof(*spte)];
	return spte;
}

static void kvm_mmu_pte_write(struct kvm_vcpu *vcpu, struct gmm_struct *gmm,
			gpa_t gpa, const u8 *new, int bytes, unsigned long flags)
{
	gfn_t gfn = gpa_to_gfn(gpa), new_gfn = INVALID_GPA;
	struct kvm_mmu_page *sp;
	LIST_HEAD(invalid_list);
	pgprot_t entry, *spte;
	pgprotval_t gentry;
	int npte, nspte, hspte;
	bool remote_flush, local_flush;
	union kvm_mmu_page_role mask = { };

	DebugPTE("started for GPA 0x%llx, new pte %px == 0x%lx\n",
		gpa, new, *((pgprotval_t *)new));

	mask.cr0_wp = 1;
	mask.cr4_pae = 1;
	mask.nxe = 1;
	mask.smep_andnot_wp = 1;
	mask.smap_andnot_wp = 1;
	mask.smm = 1;

	/*
	 * If we don't have indirect shadow pages, it means no page is
	 * write-protected, so we can exit simply.
	 */
	if (!READ_ONCE(vcpu->kvm->arch.indirect_shadow_pages))
		return;

	remote_flush = false;
	local_flush = false;

	pgprintk("%s: gpa %llx bytes %d\n", __func__, gpa, bytes);

	gentry = mmu_pte_write_fetch_gpte(vcpu, &gpa, new, &bytes);
	if (likely(!flags)) {
		new_gfn = gpa_to_gfn(kvm_gpte_gfn_to_phys_addr(vcpu,
							__pgprot(gentry)));
	} else if (flags & THP_INVALIDATE_WR_TRACK) {
		/* entry is updated by guest to invalidate and free huge page */
		;
	} else {
		/* unknown flag */
		E2K_KVM_BUG_ON(true);
	}
	DebugPTE("guest new pte %px == 0x%lx\n",
		new, pte_val(*(pte_t *)new));

	/*
	 * No need to care whether allocation memory is successful
	 * or not since pte prefetch is skiped if it does not have
	 * enough objects in the cache.
	 */
	mmu_topup_memory_caches(vcpu);

	spin_lock(&vcpu->kvm->mmu_lock);
	++vcpu->kvm->stat.mmu_pte_write;
	kvm_mmu_audit(vcpu, AUDIT_PRE_PTE_WRITE);

	nspte = 0;	/* number of spte */
	hspte = 0;	/* number of handled spte */
	for_each_gfn_indirect_valid_sp(vcpu->kvm, sp, gfn) {
		DebugPTE("found SP at %px mapped gva from 0x%lx, gfn 0x%llx\n",
			sp, sp->gva, gfn);

#ifdef CONFIG_KVM_GVA_CACHE
		/* Update translation in gva->gpa cache */
		if (sp->role.level == PT_PAGE_TABLE_LEVEL && sp->gmm) {
			u32 access = e2k_gpte_access(vcpu, gentry, sp->gva);
			gva_cache_t *gva_cache = sp->gmm->gva_cache;
			gpa_t page_gpa = kvm_gpte_gfn_to_phys_addr(vcpu,
							__pgprot(gentry));
			u64 pte_off = (gpa - gfn_to_gpa(sp->gfn)) /
							sizeof(pgprotval_t);
			gva_t res_gva = sp->gva + pte_off << PAGE_SHIFT;

			DbgGvaCache("cache 0x%lx gentry 0x%lx acc 0x%x\n",
					gva_cache, gentry, access);

			if (!is_present_gpte(gentry))
				gva_cache_flush_addr(gva_cache, res_gva);
			else
				gva_cache_fetch_addr(gva_cache, res_gva,
							page_gpa, access);
		}
#endif /* CONFIG_KVM_GVA_CACHE */

		nspte++;

		if (unlikely(gmm != NULL && gmm != kvm_get_sp_gmm(sp))) {
			/* it is shadow PT of other gmm, should be ignored */
			pr_err("%s(): other gmm #%d for sp level #%d gfn 0x%llx "
				"gva 0x%lx gmm #%d, gpa 0x%llx\n",
				__func__, gmm->nid.nr, sp->role.level, sp->gfn,
				sp->gva, kvm_get_sp_gmm(sp)->nid.nr, gpa);
			continue;
		}
		spte = get_written_sptes(sp, gpa, &npte);
		if (unlikely(!spte)) {
			pr_err("%s(): empty sp level #%d gfn 0x%llx gva 0x%lx "
				"for gpa 0x%llx\n",
				__func__, sp->role.level, sp->gfn, sp->gva, gpa);
			continue;
		}

		DebugPTE("GPA 0x%llx mapped by spte %px == 0x%lx, ptes %d\n",
			gpa, spte, pgprot_val(*spte), npte);
		if (unlikely(flags & THP_INVALIDATE_WR_TRACK)) {
			if (has_pt_level_huge_gpte(vcpu, sp->role.level)) {
				/*
				 * pte is updated by guest to invalidate and free
				 * huge page, so release old child SP on host
				 */
				new_gfn = INVALID_GPA;
			}
		}

		local_flush = true;
		while (npte--) {
			struct kvm_mmu_page *child;

			entry = *spte;
			child = mmu_page_zap_pte(vcpu->kvm, sp, spte);
			if (gentry &&
			      !((sp->role.word ^ vcpu->arch.mmu.base_role.word)
			      & mask.word) && rmap_can_add(vcpu)) {
				mmu_pte_write_new_pte(vcpu, sp, spte, gpa, gentry);
			}
			if (child && (child->released || child->gfn != new_gfn)) {
				child->released = true;
				kvm_mmu_prepare_zap_page(vcpu->kvm, child,
							&invalid_list);
			}
			if (need_remote_flush(vcpu->kvm, entry, *spte))
				remote_flush = true;
			++spte;
		}
		hspte++;
	}
	kvm_mmu_flush_or_zap(vcpu, &invalid_list, remote_flush, local_flush);
	kvm_mmu_audit(vcpu, AUDIT_POST_PTE_WRITE);
	spin_unlock(&vcpu->kvm->mmu_lock);

	KVM_WARN_ON(nspte != 0 && hspte == 0);
}

/* The caller should hold mmu-lock before calling this function. */
static bool
slot_handle_level_range(struct kvm *kvm,
			const struct kvm_memory_slot *memslot,
			slot_level_handler fn, int start_level, int end_level,
			gfn_t start_gfn, gfn_t end_gfn, bool lock_flush_tlb)
{
	struct slot_rmap_walk_iterator iterator;
	bool flush = false;

	for_each_slot_rmap_range((struct kvm_memory_slot *)memslot,
				 start_level, end_level, start_gfn,
				 end_gfn, &iterator, kvm) {
		if (iterator.rmap)
			flush |= fn(kvm, iterator.rmap);

		if (need_resched() || spin_needbreak(&kvm->mmu_lock)) {
			if (flush && lock_flush_tlb) {
				kvm_flush_remote_tlbs(kvm);
				flush = false;
			}
			cond_resched_lock(&kvm->mmu_lock);
		}
	}

	if (flush && lock_flush_tlb) {
		kvm_flush_remote_tlbs(kvm);
		flush = false;
	}

	return flush;
}

static bool
slot_handle_level(struct kvm *kvm,
		  const struct kvm_memory_slot *memslot,
		  slot_level_handler fn, int start_level, int end_level,
		  bool lock_flush_tlb)
{
	return slot_handle_level_range(kvm, memslot, fn, start_level,
			end_level, memslot->base_gfn,
			memslot->base_gfn + memslot->npages - 1,
			lock_flush_tlb);
}

static bool
slot_handle_all_level(struct kvm *kvm,
		      const struct kvm_memory_slot *memslot,
		      slot_level_handler fn, bool lock_flush_tlb)
{
	return slot_handle_level(kvm, memslot, fn, PT_PAGE_TABLE_LEVEL,
				 PT_MAX_HUGEPAGE_LEVEL, lock_flush_tlb);
}

static bool
slot_handle_large_level(struct kvm *kvm,
			const struct kvm_memory_slot *memslot,
			slot_level_handler fn, bool lock_flush_tlb)
{
	return slot_handle_level(kvm, memslot, fn, PT_PAGE_TABLE_LEVEL + 1,
				 PT_MAX_HUGEPAGE_LEVEL, lock_flush_tlb);
}

static bool
slot_handle_leaf(struct kvm *kvm, const struct kvm_memory_slot *memslot,
		 slot_level_handler fn, bool lock_flush_tlb)
{
	return slot_handle_level(kvm, memslot, fn, PT_PAGE_TABLE_LEVEL,
				 PT_PAGE_TABLE_LEVEL, lock_flush_tlb);
}

static bool
slot_handle_ptes_level_range(struct kvm *kvm,
			const struct kvm_memory_slot *memslot,
			slot_level_handler fn, int start_level, int end_level,
			gfn_t start_gfn, gfn_t end_gfn, bool lock_flush_tlb)
{
	return slot_handle_level_range(kvm, memslot,
			(fn == NULL) ? kvm_zap_rmapp : fn,
			start_level, end_level, start_gfn, end_gfn,
			lock_flush_tlb);
}

static bool slot_rmap_write_protect(struct kvm *kvm,
				    struct kvm_rmap_head *rmap_head)
{
	return __rmap_write_protect(kvm, rmap_head, false);
}

static bool slot_handle_rmap_write_protect(struct kvm *kvm,
			const struct kvm_memory_slot *memslot,
			slot_level_handler fn, bool lock_flush_tlb)
{
	return slot_handle_all_level(kvm, memslot,
			(fn == NULL) ? slot_rmap_write_protect : fn,
			lock_flush_tlb);
}

static bool kvm_mmu_zap_collapsible_spte(struct kvm *kvm,
					 struct kvm_rmap_head *rmap_head)
{
	pgprot_t *sptep;
	struct rmap_iterator iter;
	int need_tlb_flush = 0;
	kvm_pfn_t pfn;
	struct kvm_mmu_page *sp;

restart:
	for_each_rmap_spte(kvm, rmap_head, &iter, sptep) {
		sp = page_header(__pa(sptep));
		pfn = spte_to_pfn(kvm, *sptep);

		/*
		 * We cannot do huge page mapping for indirect shadow pages,
		 * which are found on the last rmap (level = 1) when not using
		 * tdp; such shadow pages are synced with the page table in
		 * the guest, and the guest page table is using 4K page size
		 * mapping if the indirect sp has level = 1.
		 */
		if (sp->role.direct &&
			!kvm_is_reserved_pfn(pfn) &&
			PageTransCompoundMap(pfn_to_page(pfn))) {
			drop_spte(kvm, sptep);
			need_tlb_flush = 1;
			goto restart;
		}
	}

	return need_tlb_flush;
}

static bool slot_handle_collapsible_sptes(struct kvm *kvm,
			const struct kvm_memory_slot *memslot,
			slot_level_handler fn, bool lock_flush_tlb)
{
	return slot_handle_leaf(kvm, memslot,
			(fn == NULL) ? kvm_mmu_zap_collapsible_spte : fn,
			lock_flush_tlb);
}

static bool slot_handle_clear_dirty(struct kvm *kvm,
			const struct kvm_memory_slot *memslot,
			slot_level_handler fn, bool lock_flush_tlb)
{
	return slot_handle_leaf(kvm, memslot,
			(fn == NULL) ? __rmap_clear_dirty : fn,
			lock_flush_tlb);
}

static bool slot_handle_largepage_remove_write_access(struct kvm *kvm,
			const struct kvm_memory_slot *memslot,
			slot_level_handler fn, bool lock_flush_tlb)
{
	return slot_handle_large_level(kvm, memslot,
			(fn == NULL) ? slot_rmap_write_protect : fn,
			lock_flush_tlb);
}

static bool slot_handle_set_dirty(struct kvm *kvm,
			const struct kvm_memory_slot *memslot,
			slot_level_handler fn, bool lock_flush_tlb)
{
	return slot_handle_all_level(kvm, memslot,
			(fn == NULL) ? __rmap_set_dirty : fn,
			lock_flush_tlb);
}

static void mmu_flush_spte_tlb_range(struct kvm_vcpu *vcpu,
					     pgprot_t *sptep, int level)
{
	struct kvm_mmu_page *sp;
	gmm_struct_t *gmm;
	gva_t start_gva, end_gva;
	unsigned index;
	const pt_level_t *spt_level;

	sp = page_header(__pa(sptep));
	E2K_KVM_BUG_ON(sp->role.level != level);
	index = sptep - sp->spt;
	spt_level = get_pt_struct_level_on_id(GET_HOST_PT_STRUCT(vcpu->kvm), level);
	start_gva = sp->gva & get_pt_level_mask(spt_level);
	start_gva = set_pt_level_addr_index(start_gva, index, spt_level);
	end_gva = start_gva + get_pt_level_size(spt_level);
	gmm = kvm_get_sp_gmm(sp);

	host_flush_shadow_pt_tlb_range(vcpu, gmm, start_gva, end_gva, *sptep, level);
}

static void mmu_flush_large_spte_tlb_range(struct kvm_vcpu *vcpu,
						   pgprot_t *sptep)
{
	mmu_flush_spte_tlb_range(vcpu, sptep, E2K_PMD_LEVEL_NUM);
}

static void mmu_flush_shadow_pt_level_tlb(struct kvm *kvm,
					pgprot_t *sptep, pgprot_t old_spte)
{
	struct kvm_mmu_page *sp;
	gmm_struct_t *gmm;
	const pt_struct_t *spt = GET_HOST_PT_STRUCT(kvm);
	const pt_level_t *spt_level;
	gva_t gva;
	unsigned index;
	int level;

	sp = page_header(__pa(sptep));
	level = sp->role.level;

	E2K_KVM_BUG_ON(!(is_huge_pt_struct_level(spt, level) ||
				is_page_pt_struct_level(spt, level)));

	index = sptep - sp->spt;
	spt_level = get_pt_struct_level_on_id(spt, level);
	gva = sp->gva & get_pt_level_mask(spt_level);
	gva = set_pt_level_addr_index(gva, index, spt_level);
	gmm = kvm_get_sp_gmm(sp);

	DebugFLSPT("flush shadow pt leve #%d gva 0x%lx spte updated from 0x%lx "
		"to 0x%lx at %px\n",
		level, gva, pgprot_val(old_spte), pgprot_val(*sptep), sptep);

	host_flush_shadow_pt_level_tlb(kvm, gmm, gva, level, *sptep, old_spte);
}

typedef enum pte_type {
	undefined_pte_type,
	none_pte_type,
	only_valid_pte_type,
	huge_pte_type,
	present_pte_type,
} pte_type_t;

static e2k_addr_t pt_level_next_addr(e2k_addr_t addr, e2k_addr_t end,
					const pt_level_t *pt_level)
{
	e2k_addr_t boundary = (addr + pt_level->page_size) & pt_level->page_mask;

	return (boundary - 1 < end - 1) ? boundary : end;
}

static int kvm_read_guest_pte(struct kvm *kvm, pgprotval_t *gpap, pgprotval_t *dst)
{
	gpa_t gpa = (gpa_t)gpap;
	unsigned offset;
	hva_t hva;
	int ret;

	offset = offset_in_page(gpa);

	E2K_KVM_BUG_ON(sizeof(pgprotval_t) + offset > PAGE_SIZE);

	hva = gfn_to_hva_prot(kvm, gpa_to_gfn(gpa), NULL);
	if (unlikely(kvm_is_error_hva(hva))) {
		return -EFAULT;
	}
	hva += offset;

	ret = __copy_from_user(dst, (void __user *)hva, sizeof(pgprotval_t));
	if (unlikely(ret)) {
		return -EFAULT;
	}

	return 0;
}

static pte_type_t get_host_pte(struct kvm *kvm, pgprot_t *ptep, e2k_addr_t addr)
{
	pte_type_t pte_type;
	pgprot_t pte;

	pte = *ptep;
	if (is_shadow_huge_pte(pte)) {
		pte_type = huge_pte_type;
	} else if (is_shadow_none_pte(pte) && !is_shadow_valid_pte(kvm, pte)) {
		pte_type = none_pte_type;
	} else if (is_shadow_valid_pte(kvm, pte) &&
				!is_shadow_present_pte(kvm, pte)) {
		pte_type = only_valid_pte_type;
	} else {
		pte_type = present_pte_type;
	}
	return pte_type;
}

static void dump_host_pte(struct kvm *kvm, pgprot_t *ptep, e2k_addr_t addr)
{
	pgprot_t pte;

	pte = *ptep;
	pr_cont("[%012lx]          : PTE %px : 0x%016lx ",
		addr, ptep, pgprot_val(pte));
	if (is_shadow_huge_pte(pte)) {
		pr_cont("PTE of huge page\n");
	} else if (is_shadow_none_pte(pte) && !is_shadow_valid_pte(kvm, pte)) {
		pr_cont("none or bad\n");
	} else if (is_shadow_valid_pte(kvm, pte) &&
				!is_shadow_present_pte(kvm, pte)) {
		pr_cont("only valid\n");
	} else {
		pr_cont("valid & present\n");
	}
}

static pte_type_t get_guest_pte(struct kvm *kvm, pgprotval_t pte, e2k_addr_t addr)
{
	pte_type_t pte_type;

	if (kvm_is_huge_gpte(kvm, pte)) {
		pte_type = huge_pte_type;
	} else if (is_none_gpte(pte) && !kvm_is_valid_gpte(kvm, pte)) {
		pte_type = none_pte_type;
	} else if (kvm_is_valid_gpte(kvm, pte) && !is_present_gpte(pte)) {
		pte_type = only_valid_pte_type;
	} else {
		pte_type = present_pte_type;
	}
	return pte_type;
}

static void dump_guest_pte(struct kvm *kvm, pgprotval_t *ptep, pgprotval_t pte,
			   e2k_addr_t addr)
{
	pr_cont("                        : PTE %px : 0x%016lx ",
		ptep, pte);
	if (kvm_is_huge_gpte(kvm, pte)) {
		pr_cont("PTE of huge page\n");
	} else if (is_none_gpte(pte) && !kvm_is_valid_gpte(kvm, pte)) {
		pr_cont("none or bad\n");
	} else if (kvm_is_valid_gpte(kvm, pte) && !is_present_gpte(pte)) {
		pr_cont("only valid\n");
	} else {
		pr_cont("valid & present\n");
	}
}

static void dump_host_and_guest_ptes(struct kvm *kvm,
				pgprot_t *host_pmdp, pgprotval_t guest_pmd,
				e2k_addr_t start, e2k_addr_t end,
				bool do_dump_host_pte, bool do_dump_guest_pte)
{
	const pt_struct_t *host_pt_struct;
	const pt_struct_t *guest_pt_struct;
	const pt_level_t *host_pt_level;
	const pt_level_t *guest_pt_level;
	pgprot_t *host_ptep;
	pgprotval_t *guest_pteb, *guest_ptep, guest_pte;
	e2k_addr_t addr, hva_next, gva_next;
	pte_type_t cur_host_pte_type, prev_host_pte_type;
	pte_type_t cur_guest_pte_type, prev_guest_pte_type;
	int host_pte_num, guest_pte_num;
	pgprot_t *prev_host_ptep;
	pgprotval_t *prev_guest_ptep, prev_guest_pte;
	e2k_addr_t prev_host_addr, prev_guest_addr;
	bool do_dump_cur_host, do_dump_cur_guest;
	int ret;

	host_pt_struct = mmu_pt_get_host_pt_struct(kvm);
	host_pt_level = &host_pt_struct->levels[E2K_PTE_LEVEL_NUM];
	guest_pt_struct = mmu_pt_get_kvm_vcpu_pt_struct(kvm);
	guest_pt_level = &guest_pt_struct->levels[E2K_PTE_LEVEL_NUM];
	guest_pteb = (pgprotval_t *)kvm_gpte_pfn_to_phys_addr(guest_pmd,
								guest_pt_struct);

	prev_host_pte_type = undefined_pte_type;
	prev_guest_pte_type = undefined_pte_type;
	host_pte_num = 0;
	guest_pte_num = 0;
	addr = start;
	do {
		hva_next = pt_level_next_addr(addr, end, host_pt_level);
		gva_next = pt_level_next_addr(addr, end, guest_pt_level);
		if (do_dump_host_pte) {
			host_ptep = (pgprot_t *)pte_offset_map((pmd_t *)host_pmdp,
								addr);
			cur_host_pte_type = get_host_pte(kvm, host_ptep, addr);
		} else {
			cur_host_pte_type = undefined_pte_type;
		}
		if (do_dump_guest_pte) {
			guest_ptep = (pgprotval_t *)(guest_pteb) + pte_index(addr);
			ret = kvm_read_guest_pte(kvm, guest_ptep, &guest_pte);
			if (unlikely(ret != 0)) {
				pr_err("%s(); copy gpte from gpa %px failed, "
					"error %d\n",
					__func__, guest_ptep, ret);
				guest_pte = 0;
			}
			cur_guest_pte_type = get_guest_pte(kvm, guest_pte, addr);
		} else {
			cur_guest_pte_type = undefined_pte_type;
		}
		do_dump_cur_host = false;
		if (do_dump_host_pte) {
			if (cur_host_pte_type == huge_pte_type ||
					cur_host_pte_type == present_pte_type) {
				prev_host_pte_type = cur_host_pte_type;
				if (host_pte_num > 0) {
					dump_host_pte(kvm, prev_host_ptep,
						prev_host_addr);
				}
				do_dump_cur_host = true;
			} else if (prev_host_pte_type != cur_host_pte_type) {
				prev_host_pte_type = cur_host_pte_type;
				if (host_pte_num > 0) {
					dump_host_pte(kvm, prev_host_ptep,
						prev_host_addr);
				}
				do_dump_cur_host = true;
				host_pte_num = 1;
			} else {
				host_pte_num++;
				if (host_pte_num == 3) {
					pr_alert("                        : "
						"--- ------------------\n");
				}
				prev_host_ptep = host_ptep;
				prev_host_addr = addr;
			}
			if (!do_dump_cur_host &&
					(cur_host_pte_type != cur_guest_pte_type ||
					prev_host_pte_type != cur_host_pte_type)) {
				dump_host_pte(kvm, host_ptep, addr);
				host_pte_num = 0;
			}
		}
		do_dump_cur_guest = false;
		if (do_dump_guest_pte) {
			if (cur_guest_pte_type == huge_pte_type ||
					cur_guest_pte_type == present_pte_type) {
				prev_guest_pte_type = cur_guest_pte_type;
				if (guest_pte_num > 0) {
					dump_guest_pte(kvm, prev_guest_ptep,
						prev_guest_pte, prev_guest_addr);
				}
				do_dump_cur_guest = true;
			} else if (prev_guest_pte_type != cur_guest_pte_type) {
				prev_guest_pte_type = cur_guest_pte_type;
				if (guest_pte_num > 0) {
					dump_guest_pte(kvm, prev_guest_ptep,
						prev_guest_pte, prev_guest_addr);
				}
				do_dump_cur_guest = true;
				guest_pte_num = 1;
			} else {
				guest_pte_num++;
				if (guest_pte_num == 3) {
					pr_alert("                        : "
						"--- ------------------\n");
				}
				prev_guest_ptep = guest_ptep;
				prev_guest_pte = guest_pte;
				prev_guest_addr = addr;
			}
			if (!do_dump_cur_guest &&
					(cur_host_pte_type != cur_guest_pte_type ||
					prev_guest_pte_type != cur_guest_pte_type)) {
				dump_guest_pte(kvm, guest_ptep, guest_pte, addr);
				guest_pte_num = 0;
			}
		}
		if (do_dump_cur_host) {
			dump_host_pte(kvm, host_ptep, addr);
			do_dump_cur_host = false;
			host_pte_num = 0;
		}
		if (do_dump_cur_guest) {
			dump_guest_pte(kvm, guest_ptep, guest_pte, addr);
			do_dump_cur_guest = false;
			guest_pte_num = 0;
		}
		msleep(100);
		addr = hva_next;
	} while (addr < end);

	if (do_dump_host_pte && host_pte_num > 1) {
		dump_host_pte(kvm, host_ptep, addr);
		host_pte_num = 0;
	}
	if (do_dump_guest_pte && guest_pte_num > 1) {
		dump_guest_pte(kvm, guest_ptep, guest_pte, addr);
		guest_pte_num = 0;
	}
}

static bool dump_host_pmd(struct kvm *kvm, pgprot_t *pmdp, e2k_addr_t addr)
{
	pgprot_t pmd;
	bool none_pte = false;

	pmd = *pmdp;
	pr_cont("[%012lx]       : PMD %px : 0x%016lx ",
		addr, pmdp, pgprot_val(pmd));
	if (is_shadow_huge_pte(pmd)) {
		pr_cont("PTE of huge page\n");
		none_pte = true;
	} else if (is_shadow_none_pte(pmd) && !is_shadow_valid_pte(kvm, pmd)) {
		pr_cont("none or bad\n");
		none_pte = true;
	} else if (is_shadow_valid_pte(kvm, pmd) &&
				!is_shadow_present_pte(kvm, pmd)) {
		pr_cont("only valid\n");
		none_pte = true;
	} else {
		pr_cont("valid & present\n");
	}
	return !none_pte;
}

static bool dump_guest_pmd(struct kvm *kvm, pgprotval_t *pmdp, pgprotval_t pmd,
			   e2k_addr_t addr)
{
	bool none_pte = false;

	pr_cont("                     : PMD %px : 0x%016lx ",
		pmdp, pmd);
	if (kvm_is_huge_gpte(kvm, pmd)) {
		pr_cont("PTE of huge page\n");
		none_pte = true;
	} else if (is_none_gpte(pmd) && !kvm_is_valid_gpte(kvm, pmd)) {
		pr_cont("none or bad\n");
		none_pte = true;
	} else if (kvm_is_valid_gpte(kvm, pmd) && !is_present_gpte(pmd)) {
		pr_cont("only valid\n");
		none_pte = true;
	} else {
		pr_cont("valid & present\n");
	}
	return !none_pte;
}

static void dump_host_and_guest_pmds(struct kvm *kvm,
				pgprot_t *host_pudp, pgprotval_t guest_pud,
				e2k_addr_t start, e2k_addr_t end,
				bool do_dump_host_pmd, bool do_dump_guest_pmd)
{
	const pt_struct_t *host_pt_struct;
	const pt_struct_t *guest_pt_struct;
	const pt_level_t *host_pt_level;
	const pt_level_t *guest_pt_level;
	pgprot_t *host_pmdp;
	pgprotval_t *guest_pmdb, *guest_pmdp, guest_pmd;
	e2k_addr_t addr, hva_next, gva_next;
	bool do_dump_host_pte, do_dump_guest_pte;
	int ret;

	host_pt_struct = mmu_pt_get_host_pt_struct(kvm);
	host_pt_level = &host_pt_struct->levels[E2K_PMD_LEVEL_NUM];
	guest_pt_struct = mmu_pt_get_kvm_vcpu_pt_struct(kvm);
	guest_pt_level = &guest_pt_struct->levels[E2K_PMD_LEVEL_NUM];
	if (do_dump_guest_pmd) {
		guest_pmdb = (pgprotval_t *)kvm_gpte_pfn_to_phys_addr(guest_pud,
								guest_pt_struct);
	}

	addr = start;
	do {
		hva_next = pt_level_next_addr(addr, end, host_pt_level);
		gva_next = pt_level_next_addr(addr, end, guest_pt_level);
		if (do_dump_host_pmd) {
			host_pmdp = (pgprot_t *)pmd_offset((pud_t *)host_pudp,
								addr);
			do_dump_host_pte = dump_host_pmd(kvm, host_pmdp, addr);
		} else {
			do_dump_host_pte = false;
		}
		if (do_dump_guest_pmd) {
			guest_pmdp = (pgprotval_t *)(guest_pmdb) + pmd_index(addr);
			ret = kvm_read_guest_pte(kvm, guest_pmdp, &guest_pmd);
			if (unlikely(ret != 0)) {
				pr_err("%s(); copy gpte from gpa %px failed, "
					"error %d\n",
					__func__, guest_pmdp, ret);
				guest_pmd = 0;
			}
			do_dump_guest_pte = dump_guest_pmd(kvm, guest_pmdp,
							   guest_pmd, addr);
		} else {
			do_dump_guest_pte = false;
		}
		if (likely(do_dump_host_pte || do_dump_guest_pte)) {
			dump_host_and_guest_ptes(kvm, host_pmdp, guest_pmd,
				addr, hva_next, do_dump_host_pte, do_dump_guest_pte);
		}
		addr = hva_next;
	} while (addr < end);
}

static bool dump_host_pud(struct kvm *kvm, pgprot_t *pudp, e2k_addr_t addr)
{
	pgprot_t pud;
	bool none_pmd = false;

	pud = *pudp;
	pr_cont("[%012lx]    : PUD %px : 0x%016lx ",
		addr, pudp, pgprot_val(pud));
	if (is_shadow_huge_pte(pud)) {
		pr_cont("PTE of huge page\n");
		none_pmd = true;
	} else if (is_shadow_none_pte(pud) && !is_shadow_valid_pte(kvm, pud)) {
		pr_cont("none or bad\n");
		none_pmd = true;
	} else if (is_shadow_valid_pte(kvm, pud) &&
				!is_shadow_present_pte(kvm, pud)) {
		pr_cont("only valid\n");
		none_pmd = true;
	} else {
		pr_cont("valid & present\n");
	}
	return !none_pmd;
}

static bool dump_guest_pud(struct kvm *kvm, pgprotval_t *pudp, pgprotval_t pud,
			   e2k_addr_t addr)
{
	bool none_pmd = false;

	pr_cont("                  : PUD %px : 0x%016lx ",
		pudp, pud);
	if (kvm_is_huge_gpte(kvm, pud)) {
		pr_cont("PTE of huge page\n");
		none_pmd = true;
	} else if (is_none_gpte(pud) && !kvm_is_valid_gpte(kvm, pud)) {
		pr_cont("none or bad\n");
		none_pmd = true;
	} else if (kvm_is_valid_gpte(kvm, pud) && !is_present_gpte(pud)) {
		pr_cont("only valid\n");
		none_pmd = true;
	} else {
		pr_cont("valid & present\n");
	}
	return !none_pmd;
}

static void dump_host_and_guest_puds(struct kvm *kvm,
			pgprot_t *host_pgdp, pgprotval_t guest_pgd,
			e2k_addr_t start, e2k_addr_t end,
			bool do_dump_host_pud, bool do_dump_guest_pud)
{
	const pt_struct_t *host_pt_struct;
	const pt_struct_t *guest_pt_struct;
	const pt_level_t *host_pt_level;
	const pt_level_t *guest_pt_level;
	pgprot_t *host_pudp;
	pgprotval_t *guest_pudb, *guest_pudp, guest_pud;
	e2k_addr_t addr, hva_next, gva_next;
	bool do_dump_host_pmd, do_dump_guest_pmd;
	int ret;

	host_pt_struct = mmu_pt_get_host_pt_struct(kvm);
	host_pt_level = &host_pt_struct->levels[E2K_PUD_LEVEL_NUM];
	guest_pt_struct = mmu_pt_get_kvm_vcpu_pt_struct(kvm);
	guest_pt_level = &guest_pt_struct->levels[E2K_PUD_LEVEL_NUM];
	if (do_dump_guest_pud) {
		guest_pudb = (pgprotval_t *)kvm_gpte_pfn_to_phys_addr(guest_pgd,
								guest_pt_struct);
	}

	addr = start;
	do {
		hva_next = pt_level_next_addr(addr, end, host_pt_level);
		gva_next = pt_level_next_addr(addr, end, guest_pt_level);
		if (do_dump_host_pud) {
			host_pudp = (pgprot_t *)pud_offset((pgd_t *)host_pgdp,
								addr);
			do_dump_host_pmd = dump_host_pud(kvm, host_pudp, addr);
		} else {
			do_dump_host_pmd = false;
		}
		if (likely(do_dump_guest_pud)) {
			guest_pudp = (pgprotval_t *)(guest_pudb) + pud_index(addr);
			ret = kvm_read_guest_pte(kvm, guest_pudp, &guest_pud);
			if (unlikely(ret != 0)) {
				pr_err("%s(); copy gpte from gpa %px failed, "
					"error %d\n",
					__func__, guest_pudp, ret);
				guest_pud = 0;
			}
			do_dump_guest_pmd = dump_guest_pud(kvm, guest_pudp,
							   guest_pud, addr);
		} else {
			do_dump_guest_pmd = false;
		}
		if (likely(do_dump_host_pmd || do_dump_guest_pmd)) {
			dump_host_and_guest_pmds(kvm, host_pudp, guest_pud,
				addr, hva_next, do_dump_host_pmd, do_dump_guest_pmd);
		}
		addr = hva_next;
	} while (addr < end);
}

static bool dump_host_pgd(struct kvm *kvm, pgprot_t *pgdp, e2k_addr_t addr)
{
	pgprot_t pgd;
	bool none_pud = false;

	pgd = *pgdp;
	pr_cont("[%012lx] : PGD %px : 0x%016lx ",
		addr, pgdp, pgprot_val(pgd));
	if (is_shadow_huge_pte(pgd)) {
		pr_cont("PTE of huge page\n");
		none_pud = true;
	} else if (is_shadow_none_pte(pgd) && !is_shadow_valid_pte(kvm, pgd)) {
		pr_cont("none or bad\n");
		none_pud = true;
	} else if (is_shadow_valid_pte(kvm, pgd) &&
				!is_shadow_present_pte(kvm, pgd)) {
		pr_cont("only valid\n");
		none_pud = true;
	} else {
		pr_cont("valid & present\n");
	}
	return !none_pud;
}

static bool dump_guest_pgd(struct kvm *kvm, pgprotval_t *pgdp, pgprotval_t pgd,
			   e2k_addr_t addr)
{
	bool none_pud = false;

	pr_cont("               : PGD %px : 0x%016lx ", pgdp, pgd);
	if (kvm_is_huge_gpte(kvm, pgd)) {
		pr_cont("PTE of huge page\n");
		none_pud = true;
	} else if (is_none_gpte(pgd) && !kvm_is_valid_gpte(kvm, pgd)) {
		pr_cont("none or bad\n");
		none_pud = true;
	} else if (kvm_is_valid_gpte(kvm, pgd) && !is_present_gpte(pgd)) {
		pr_cont("only valid\n");
		none_pud = true;
	} else {
		pr_cont("valid & present\n");
	}
	return !none_pud;
}

static void dump_host_and_guest_pts(struct kvm *kvm, gmm_struct_t *gmm,
				 e2k_addr_t start, e2k_addr_t end)
{
	hpa_t host_root;
	gpa_t guest_root;
	const pt_struct_t *host_pt_struct;
	const pt_struct_t *guest_pt_struct;
	const pt_level_t *host_pt_level;
	const pt_level_t *guest_pt_level;
	pgprot_t *host_pgdp;
	pgprotval_t *guest_pgdp, guest_pgd;
	e2k_addr_t addr, hva_next, gva_next;
	bool do_dump_host_pud, do_dump_guest_pud;
	int ret, cpu;

	host_root = gmm->root_hpa;
	if (!VALID_PAGE(host_root)) {
		/* shadow PT of the gmm has been already released */
		pr_alert("host PT of gmm #%d was already released\n", gmm->id);
		return;
	}
	guest_root = gmm->u_pptb;
	host_pt_struct = mmu_pt_get_host_pt_struct(kvm);
	host_pt_level = &host_pt_struct->levels[E2K_PGD_LEVEL_NUM];
	guest_pt_struct = mmu_pt_get_kvm_vcpu_pt_struct(kvm);
	guest_pt_level = &guest_pt_struct->levels[E2K_PGD_LEVEL_NUM];

	pr_alert("\n\n===== Host & guest gmm #%d PTs state addr "
		"range 0x%lx - 0x%lx =====\n",
		gmm->id, start, end);
	pr_alert("host pgd at 0x%llx guest pgd at 0x%llx "
		"active on cpu mask 0x%lx\n",
		host_root, guest_root, cpumask_bits(&gmm->cpu_vm_mask)[0]);
	for_each_online_cpu(cpu) {
		unsigned long cntx;

		cntx = gmm->context.cpumsk[cpu];
		pr_alert("   cpu #%d  context 0x%lx : version %llx "
			"hardware context %03llx\n",
			cpu, cntx, CTX_VERSION(cntx) >> CTX_VERSION_SHIFT,
			CTX_HARDWARE(cntx));
	}
	addr = start;
	do {
		hva_next = pt_level_next_addr(addr, end, host_pt_level);
		gva_next = pt_level_next_addr(addr, end, guest_pt_level);
		host_pgdp = (pgprot_t *)(host_root) + pgd_index(addr);
		host_pgdp = __va(host_pgdp);
		do_dump_host_pud = dump_host_pgd(kvm, host_pgdp, addr);
		guest_pgdp = (pgprotval_t *)(guest_root) + pgd_index(addr);
		ret = kvm_read_guest_pte(kvm, guest_pgdp, &guest_pgd);
		if (unlikely(ret != 0)) {
			pr_err("%s(); copy gpte from gpa %px failed, error %d\n",
				__func__, guest_pgdp, ret);
			guest_pgd = 0;
		}
		do_dump_guest_pud = dump_guest_pgd(kvm, guest_pgdp, guest_pgd,
						   addr);
		if (likely(do_dump_host_pud || do_dump_guest_pud)) {
			dump_host_and_guest_puds(kvm, host_pgdp, guest_pgd,
				addr, hva_next, do_dump_host_pud, do_dump_guest_pud);
		}
		addr = hva_next;
	} while (addr < end);
}

static void mmu_init_vcpu_pt_struct(struct kvm_vcpu *vcpu)
{
	const pt_struct_t *pt_struct;

	/* setup page table structures type to properly manage PTs */
	pt_struct = kvm_get_mmu_guest_pt_struct(vcpu);
	mmu_set_vcpu_pt_struct(vcpu->kvm, pt_struct);
	mmu_set_vcpu_pt_struct_func(vcpu->kvm, &kvm_mmu_get_vcpu_pt_struct);
}

static void kvm_init_mmu_pt_structs(struct kvm *kvm)
{
	if (kvm_is_phys_pt_enable(kvm)) {
		mmu_set_gp_pt_struct(kvm, &pgtable_struct_e2k_v6_gp);
		mmu_set_host_pt_struct(kvm, &pgtable_struct_e2k_v6_gp);
	} else if (kvm_is_shadow_pt_enable(kvm)) {
		mmu_set_gp_pt_struct(kvm, kvm_get_mmu_host_pt_struct(kvm));
		mmu_set_host_pt_struct(kvm, kvm_get_mmu_host_pt_struct(kvm));
	} else {
		BUG_ON(true);
	}
	mmu_set_gp_pt_struct_func(kvm, &kvm_mmu_get_gp_pt_struct);
	mmu_set_host_pt_struct_func(kvm, &kvm_mmu_get_host_pt_struct);
}

static void kvm_init_nonpaging_pt_structs(struct kvm *kvm, hpa_t root)
{
	mmu_set_gp_pt_struct_func(kvm, &kvm_mmu_get_gp_pt_struct);
	mmu_set_host_pt_struct_func(kvm, &kvm_mmu_get_gp_pt_struct);
	if (kvm_is_phys_pt_enable(kvm)) {
		mmu_set_gp_pt_struct(kvm, &pgtable_struct_e2k_v6_gp);
	} else if (kvm_is_shadow_pt_enable(kvm)) {
		mmu_set_gp_pt_struct(kvm, kvm_get_mmu_host_pt_struct(kvm));

		/* Since V6 hardware support has been simplified
		 * and self-pointing pgd is not required anymore. */
		if (!cpu_has(CPU_FEAT_ISET_V6)) {
			/* One PGD entry is the VPTB self-map. */
			int pt_index = pgd_index(KERNEL_VPTB_BASE_ADDR);
			pgprot_t *new_root = (pgprot_t *)__va(root);
			kvm_vmlpt_kernel_spte_set(kvm, &new_root[pt_index], new_root);
		}
	} else {
		E2K_KVM_BUG_ON(true);
	}
}

static void setup_shadow_pt_structs(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;

	/* setup page table structures type to properly manage PTs */
	mmu_set_host_pt_struct(kvm, kvm_get_mmu_host_pt_struct(kvm));
	mmu_set_vcpu_pt_struct(kvm, kvm_get_mmu_guest_pt_struct(vcpu));
	mmu_set_host_pt_struct_func(kvm, &kvm_mmu_get_host_pt_struct);
	mmu_set_vcpu_pt_struct_func(kvm, &kvm_mmu_get_vcpu_pt_struct);
}

static void setup_tdp_pt_structs(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;

	/* setup page table structures type to properly manage PTs */
	mmu_set_vcpu_pt_struct(kvm, kvm_get_mmu_guest_pt_struct(vcpu));
	mmu_set_vcpu_pt_struct_func(kvm, &kvm_mmu_get_vcpu_pt_struct);
}

static void kvm_init_mmu_spt_context(struct kvm_vcpu *vcpu,
					struct kvm_mmu *context)
{
	context->page_fault = &page_fault;
	context->gva_to_gpa = &gva_to_gpa;
	context->sync_page = &spt_sync_page;
	context->sync_gva = &sync_gva;
	context->sync_gva_range = &sync_gva_range;
	context->update_spte = &update_spte;
}

static void kvm_init_mmu_tdp_context(struct kvm_vcpu *vcpu,
					struct kvm_mmu *context)
{
	context->page_fault = &tdp_page_fault;

	if (!is_paging(vcpu)) {
		context->gva_to_gpa = &nonpaging_gva_to_gpa;
	} else if (!is_ss(vcpu)) {
		context->gva_to_gpa = &gva_to_gpa;
	}
}

static void kvm_init_mmu_nonpaging_context(struct kvm_vcpu *vcpu,
						struct kvm_mmu *context)
{
	context->page_fault = &nonpaging_page_fault;
	context->gva_to_gpa = &nonpaging_gva_to_gpa;
}

void PTNAME(mmu_init_pt_interface)(struct kvm *kvm)
{
	kvm_mmu_pt_ops_t *pt_ops = &kvm->arch.mmu_pt_ops;

	pt_ops->get_spte_valid_mask = &get_spte_valid_mask;
	pt_ops->get_spte_pfn_mask = &get_spte_pfn_mask;
	pt_ops->kvm_gfn_to_index = &kvm_gfn_to_index;
	pt_ops->kvm_is_thp_gpmd_invalidate = &kvm_is_thp_gpmd_invalidate;
	pt_ops->kvm_vmlpt_kernel_spte_set = &kvm_vmlpt_kernel_spte_set;
	pt_ops->kvm_vmlpt_user_spte_set = &kvm_vmlpt_user_spte_set;
	pt_ops->mmu_gfn_disallow_lpage = &mmu_gfn_disallow_lpage;
	pt_ops->mmu_gfn_allow_lpage = &mmu_gfn_allow_lpage;
	pt_ops->mmu_unsync_walk = &mmu_unsync_walk;
	pt_ops->rmap_write_protect = &rmap_write_protect;
	pt_ops->mmu_slot_gfn_write_protect = &mmu_slot_gfn_write_protect;
	pt_ops->account_shadowed = &account_shadowed;
	pt_ops->unaccount_shadowed = &unaccount_shadowed;
	pt_ops->walk_shadow_pts = &walk_shadow_pts;
	pt_ops->nonpaging_page_fault = &nonpaging_page_fault;
	pt_ops->nonpaging_gpa_to_pte = &nonpaging_gpa_to_pte;
	pt_ops->kvm_hv_mmu_page_fault = &kvm_hv_mmu_page_fault;
	pt_ops->kvm_mmu_pte_write = &kvm_mmu_pte_write;
	pt_ops->sync_shadow_pt_range = &sync_shadow_pt_range;
	pt_ops->atomic_update_shadow_pt = &atomic_update_shadow_pt;
	pt_ops->shadow_protection_fault = &shadow_protection_fault;
	pt_ops->direct_unmap_prefixed_mmio_gfn = &direct_unmap_prefixed_mmio_gfn;
	pt_ops->kvm_mmu_free_page = &kvm_mmu_free_page;
	pt_ops->copy_guest_shadow_root_range = &copy_guest_shadow_root_range;
	pt_ops->switch_kernel_pgd_range = &switch_kernel_pgd_range;
	pt_ops->zap_linked_children = &zap_linked_children;
	pt_ops->mark_parents_unsync = &mark_parents_unsync;
	pt_ops->prepare_zap_page = &kvm_mmu_prepare_zap_page;
	pt_ops->unmap_hva_range = &unmap_hva_range;
	pt_ops->set_spte_hva = &set_spte_hva;
	pt_ops->age_hva = &age_hva;
	pt_ops->test_age_hva = &test_age_hva;
	pt_ops->arch_mmu_enable_log_dirty_pt_masked =
				&arch_mmu_enable_log_dirty_pt_masked;
	pt_ops->slot_handle_ptes_level_range = &slot_handle_ptes_level_range;
	pt_ops->slot_handle_rmap_write_protect = &slot_handle_rmap_write_protect;
	pt_ops->slot_handle_collapsible_sptes = &slot_handle_collapsible_sptes;
	pt_ops->slot_handle_clear_dirty = &slot_handle_clear_dirty;
	pt_ops->slot_handle_set_dirty = &slot_handle_set_dirty;
	pt_ops->slot_handle_largepage_remove_write_access =
				&slot_handle_largepage_remove_write_access;

	pt_ops->mmu_flush_spte_tlb_range = &mmu_flush_spte_tlb_range;
	pt_ops->mmu_flush_large_spte_tlb_range = &mmu_flush_large_spte_tlb_range;
	pt_ops->mmu_flush_shadow_pt_level_tlb = &mmu_flush_shadow_pt_level_tlb;

	pt_ops->dump_host_and_guest_pts = &dump_host_and_guest_pts;

	pt_ops->mmu_init_vcpu_pt_struct = &mmu_init_vcpu_pt_struct;
	pt_ops->kvm_init_mmu_pt_structs = &kvm_init_mmu_pt_structs;
	pt_ops->kvm_init_nonpaging_pt_structs = &kvm_init_nonpaging_pt_structs;
	pt_ops->setup_shadow_pt_structs = &setup_shadow_pt_structs;
	pt_ops->setup_tdp_pt_structs = &setup_tdp_pt_structs;
	pt_ops->kvm_init_mmu_spt_context = &kvm_init_mmu_spt_context;
	pt_ops->kvm_init_mmu_tdp_context = &kvm_init_mmu_tdp_context;
	pt_ops->kvm_init_mmu_nonpaging_context = &kvm_init_mmu_nonpaging_context;
}
