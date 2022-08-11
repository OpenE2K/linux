/*
 * Kernel-based Virtual Machine MMU driver for Linux
 *
 * This module enables machines with e2k hardware virtualization extensions
 * to run virtual machines without emulation or binary translation.
 *
 * Based on x86 MMU virtualization ideas and sources:
 *	arch/x86/kvm/mmu.c
 *	arch/x86/kvm/mmu.h
 *	arch/x86/kvm/paging_tmpl.h
 *
 * Copyright 2018 MCST.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
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

/*
 * When setting this variable to true it enables Two-Dimensional-Paging
 * where the hardware walks 2 page tables:
 * 1. the guest-virtual to guest-physical
 * 2. while doing 1. it walks guest-physical to host-physical
 * If the hardware supports that we don't need to do shadow paging.
 */
bool tdp_enabled = false;

enum {
	AUDIT_PRE_PAGE_FAULT,
	AUDIT_POST_PAGE_FAULT,
	AUDIT_PRE_PTE_WRITE,
	AUDIT_POST_PTE_WRITE,
	AUDIT_PRE_SYNC,
	AUDIT_POST_SYNC
};

#define	HW_REEXECUTE_IS_SUPPORTED	true
#define	HW_MOVE_TO_TC_IS_SUPPORTED	true

#ifdef DEBUG
#define ASSERT(x)							\
do {									\
	if (!(x)) {							\
		printk(KERN_EMERG "assertion failed %s: %d: %s\n",	\
		       __FILE__, __LINE__, #x);				\
		BUG();							\
	}								\
} while (0)
#else
#define ASSERT(x) do { } while (0)
#endif

#define	MMU_DEBUG

#ifdef	MMU_DEBUG
static bool dbg = false;
module_param(dbg, bool, 0644);

#define pgprintk(x...)		do { if (sync_dbg) printk(x); } while (false)
#define rmap_printk(x...)	do { if (sync_dbg) printk(x); } while (false)
#define MMU_WARN_ON(x)		WARN_ON(x)
#define MMU_BUG_ON(x)		BUG_ON(x)
#else	/* ! MMU_DEBUG */
#define pgprintk(x...)		do { } while (false)
#define rmap_printk(x...)	do { } while (false)
#define MMU_WARN_ON(x)		WARN_ON(x)
#define MMU_BUG_ON(x)		BUG_ON(x)
#endif	/* MMU_DEBUG */

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

bool sync_dbg = false;

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

#define PTE_PREFETCH_NUM	8

#define PT64_LEVEL_BITS		PT64_ENTRIES_BITS

#define PT32_LEVEL_BITS		PT32_ENTRIES_BITS

#define PT64_PERM_MASK(kvm)	\
		(PT_PRESENT_MASK | PT_WRITABLE_MASK | \
			get_spte_user_mask(kvm) | get_spte_priv_mask(kvm) | \
				get_spte_x_mask(kvm) | get_spte_nx_mask(kvm))

/* number of retries to handle page fault */
#define	PF_RETRIES_MAX_NUM	1
/* common number of one try and retries to handle page fault */
#define	PF_TRIES_MAX_NUM	(1 + PF_RETRIES_MAX_NUM)

#include <trace/events/kvm.h>

#define CREATE_TRACE_POINTS
#include "mmutrace-e2k.h"

#define SPTE_HOST_WRITABLE_SW_MASK(__spt)	((__spt)->sw_bit1_mask)
#define SPTE_MMU_WRITABLE_SW_MASK(__spt)	((__spt)->sw_bit2_mask)

#define SHADOW_PT_INDEX(addr, level) PT64_INDEX(addr, level)

/* make pte_list_desc fit well in cache line */
#define PTE_LIST_EXT	3

typedef struct pte_list_desc {
	pgprot_t *sptes[PTE_LIST_EXT];
	struct pte_list_desc *more;
} pte_list_desc_t;

static struct kmem_cache *pte_list_desc_cache;
static struct kmem_cache *mmu_page_header_cache;
static struct percpu_counter kvm_total_used_mmu_pages;

static pgprot_t set_spte_pfn(struct kvm *kvm, pgprot_t spte, kvm_pfn_t pfn);
static int e2k_walk_shadow_pts(struct kvm_vcpu *vcpu, gva_t addr,
				kvm_shadow_trans_t *st, hpa_t spt_root);

static void mmu_spte_set(struct kvm *kvm, pgprot_t *sptep, pgprot_t spte);
static void mmu_free_roots(struct kvm_vcpu *vcpu, unsigned flags);
static void kvm_unsync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp);
static int kvm_sync_shadow_root(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				hpa_t root_hpa, unsigned flags);

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

static pgprotval_t get_spte_mmio_mask(struct kvm *kvm)
{
	const pt_struct_t *host_pt = kvm_get_host_pt_struct(kvm);

	return host_pt->sw_mmio_mask;
}

static u64 generation_mmio_spte_mask(unsigned int gen)
{
	u64 mask;

	WARN_ON(gen & ~MMIO_GEN_MASK);

	mask = (gen & MMIO_GEN_LOW_MASK) << MMIO_SPTE_GEN_LOW_SHIFT;
	mask |= ((u64)gen >> MMIO_GEN_LOW_SHIFT) << MMIO_SPTE_GEN_HIGH_SHIFT;
	return mask;
}

static unsigned int get_mmio_spte_generation(struct kvm *kvm, pgprotval_t spte)
{
	unsigned int gen;

	spte &= ~get_spte_mmio_mask(kvm);

	gen = (spte >> MMIO_SPTE_GEN_LOW_SHIFT) & MMIO_GEN_LOW_MASK;
	gen |= (spte >> MMIO_SPTE_GEN_HIGH_SHIFT) << MMIO_GEN_LOW_SHIFT;
	return gen;
}

static unsigned int kvm_current_mmio_generation(struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_memslots(vcpu)->generation & MMIO_GEN_MASK;
}

static bool is_mmio_spte(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mmio_mask = get_spte_mmio_mask(kvm);

	return (pgprot_val(spte) & mmio_mask) == mmio_mask;
}

static gfn_t get_mmio_spte_gfn(struct kvm *kvm, pgprot_t spte)
{
	u64 mask = generation_mmio_spte_mask(MMIO_GEN_MASK) |
						get_spte_mmio_mask(kvm);
	return (pgprot_val(spte) & ~mask) >> PAGE_SHIFT;
}

static unsigned get_mmio_spte_access(struct kvm *kvm, pgprot_t spte)
{
	u64 mask = generation_mmio_spte_mask(MMIO_GEN_MASK) |
						get_spte_mmio_mask(kvm);
	return (pgprot_val(spte) & ~mask) & ~PAGE_MASK;
}

static bool check_mmio_spte(struct kvm_vcpu *vcpu, pgprot_t spte)
{
	unsigned int kvm_gen, spte_gen;

	kvm_gen = kvm_current_mmio_generation(vcpu);
	spte_gen = get_mmio_spte_generation(vcpu->kvm, pgprot_val(spte));

	trace_check_mmio_spte(spte, kvm_gen, spte_gen);
	return likely(kvm_gen == spte_gen);
}

static pgprotval_t get_spte_bit_mask(struct kvm *kvm,
			bool accessed, bool dirty, bool present, bool valid)
{
	const pt_struct_t *host_pt = kvm_get_host_pt_struct(kvm);
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
static pgprotval_t get_spte_accessed_mask(struct kvm *kvm)
{
	return get_spte_bit_mask(kvm, true, false, false, false);
}
static pgprotval_t get_spte_dirty_mask(struct kvm *kvm)
{
	return get_spte_bit_mask(kvm, false, true, false, false);
}
static pgprotval_t get_spte_present_mask(struct kvm *kvm)
{
	return get_spte_bit_mask(kvm, false, false, true, false);
}
static pgprotval_t get_spte_valid_mask(struct kvm *kvm)
{
	return get_spte_bit_mask(kvm, false, false, false, true);
}
static pgprotval_t get_spte_present_valid_mask(struct kvm *kvm)
{
	return get_spte_bit_mask(kvm, false, false, true, true);
}

pgprotval_t get_gpte_valid_mask(struct kvm_vcpu *vcpu)
{
	const pt_struct_t *gpt = kvm_get_vcpu_pt_struct(vcpu);

	return gpt->valid_mask;
}

pgprotval_t get_gpte_unmapped_mask(struct kvm_vcpu *vcpu)
{
	return (pgprotval_t) 0;
}

pgprot_t set_spte_bit_mask(struct kvm *kvm, pgprot_t spte,
			bool accessed, bool dirty, bool present, bool valid)
{
	const pt_struct_t *host_pt = kvm_get_host_pt_struct(kvm);
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

static bool is_spte_accessed_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_accessed_mask(kvm);
	return pgprot_val(spte) & mask;
}
static pgprot_t set_spte_accessed_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_accessed_mask(kvm);
	return __pgprot(pgprot_val(spte) | mask);
}
static pgprot_t clear_spte_accessed_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_accessed_mask(kvm);
	return __pgprot(pgprot_val(spte) & ~mask);
}

pgprotval_t get_pte_mode_mask(const pt_struct_t *pt_struct)
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

pgprotval_t get_spte_mode_mask(struct kvm *kvm)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	return get_pte_mode_mask(spt);
}

pgprotval_t get_gpte_mode_mask(struct kvm_vcpu *vcpu)
{
	const pt_struct_t *gpt = kvm_get_vcpu_pt_struct(vcpu);

	return get_pte_mode_mask(gpt);
}

pgprotval_t get_spte_user_mask(struct kvm *kvm)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	return spt->user_mask;
}

pgprotval_t get_gpte_user_mask(struct kvm_vcpu *vcpu)
{
	const pt_struct_t *gpt = kvm_get_vcpu_pt_struct(vcpu);

	return gpt->user_mask;
}

pgprotval_t get_spte_priv_mask(struct kvm *kvm)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	return spt->priv_mask;
}

pgprotval_t get_gpte_priv_mask(struct kvm_vcpu *vcpu)
{
	const pt_struct_t *gpt = kvm_get_vcpu_pt_struct(vcpu);

	return gpt->priv_mask;
}

bool is_spte_user_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	if (spt->user_mask != 0)
		return pgprot_val(spte) & spt->user_mask;
	else if (spt->priv_mask != 0)
		return !(pgprot_val(spte) & spt->priv_mask);
	else
		/* pte has not user or priv mode */
		;
	return false;
}
pgprot_t set_spte_user_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	if (spt->user_mask != 0)
		return __pgprot(pgprot_val(spte) | spt->user_mask);
	else if (spt->priv_mask != 0)
		return __pgprot(pgprot_val(spte) & ~spt->priv_mask);
	else
		/* pte has not user or priv mode */
		;
	return spte;
}
pgprot_t clear_spte_user_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

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

bool is_spte_priv_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	if (spt->priv_mask != 0)
		return pgprot_val(spte) & spt->priv_mask;
	else if (spt->user_mask != 0)
		return !(pgprot_val(spte) & spt->user_mask);
	else
		/* pte has not user or priv mode */
		return true;	/* always privileged */
	return false;
}
pgprot_t set_spte_priv_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

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
pgprot_t clear_spte_priv_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	if (spt->priv_mask != 0)
		return __pgprot(pgprot_val(spte) & ~spt->priv_mask);
	else if (spt->user_mask != 0)
		return __pgprot(pgprot_val(spte) | spt->user_mask);
	else
		/* pte has not user or priv mode */
		;
	return spte;
}
static bool is_spte_dirty_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_dirty_mask(kvm);
	return pgprot_val(spte) & mask;
}
static pgprot_t set_spte_dirty_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_dirty_mask(kvm);
	return __pgprot(pgprot_val(spte) | mask);
}
static pgprot_t set_spte_cui(pgprot_t spte, u64 cui)
{
	return !cpu_has(CPU_FEAT_ISET_V6) ? __pgprot(pgprot_val(spte) |
			_PAGE_INDEX_TO_CUNIT_V2(cui)) : spte;
}
static pgprot_t clear_spte_dirty_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_dirty_mask(kvm);
	return __pgprot(pgprot_val(spte) & ~mask);
}
bool is_spte_present_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_present_mask(kvm);
	return pgprot_val(spte) & mask;
}
pgprot_t set_spte_present_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_present_mask(kvm);
	return __pgprot(pgprot_val(spte) | mask);
}
pgprot_t clear_spte_present_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_present_mask(kvm);
	return __pgprot(pgprot_val(spte) & ~mask);
}
bool is_spte_valid_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_valid_mask(kvm);
	return pgprot_val(spte) & mask;
}
pgprot_t set_spte_valid_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_valid_mask(kvm);
	return __pgprot(pgprot_val(spte) | mask);
}
pgprot_t clear_spte_valid_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_valid_mask(kvm);
	return __pgprot(pgprot_val(spte) & ~mask);
}
pgprot_t set_spte_present_valid_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t mask;

	mask = get_spte_present_valid_mask(kvm);
	return __pgprot(pgprot_val(spte) | mask);
}

pgprotval_t get_spte_x_mask(struct kvm *kvm)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	return spt->exec_mask;
}
static pgprotval_t get_pte_nx_mask(const pt_struct_t *pt_struct)
{
	return pt_struct->non_exec_mask;
}
static pgprotval_t get_spte_nx_mask(struct kvm *kvm)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	return get_pte_nx_mask(spt);
}
static pgprotval_t get_gpte_nx_mask(struct kvm_vcpu *vcpu)
{
	const pt_struct_t *gpt = kvm_get_vcpu_pt_struct(vcpu);

	return get_pte_nx_mask(gpt);
}
bool is_spte_x_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	if (spt->exec_mask != 0)
		return pgprot_val(spte) & spt->exec_mask;
	else if (spt->non_exec_mask != 0)
		return !(pgprot_val(spte) & spt->non_exec_mask);
	else
		/* pte has not executable field */
		return true;	/* always executable */
	return false;
}
static pgprot_t set_spte_x_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	if (spt->exec_mask != 0)
		return __pgprot(pgprot_val(spte) | spt->exec_mask);
	else if (spt->non_exec_mask != 0)
		return __pgprot(pgprot_val(spte) & ~spt->non_exec_mask);
	else
		/* pte has not executable field */
		;
	return spte;
}
pgprot_t clear_spte_x_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	if (spt->exec_mask != 0)
		return __pgprot(pgprot_val(spte) & ~spt->exec_mask);
	else if (spt->non_exec_mask != 0)
		return __pgprot(pgprot_val(spte) | spt->non_exec_mask);
	else
		/* pte has not executable field */
		;
	return spte;
}
bool is_spte_nx_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	if (spt->exec_mask != 0)
		return !(pgprot_val(spte) & spt->exec_mask);
	else if (spt->non_exec_mask != 0)
		return pgprot_val(spte) & spt->non_exec_mask;
	else
		/* pte has not executable field */
		return true;	/* always can be not executable */
	return false;
}
static pgprot_t set_spte_nx_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	if (spt->exec_mask != 0)
		return __pgprot(pgprot_val(spte) & ~spt->exec_mask);
	else if (spt->non_exec_mask != 0)
		return __pgprot(pgprot_val(spte) | spt->non_exec_mask);
	else
		/* pte has not executable field */
		;
	return spte;
}
pgprot_t clear_spte_nx_mask(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	if (spt->exec_mask != 0)
		return __pgprot(pgprot_val(spte) | spt->exec_mask);
	else if (spt->non_exec_mask != 0)
		return __pgprot(pgprot_val(spte) & ~spt->non_exec_mask);
	else
		/* pte has not executable field */
		;
	return spte;
}
bool is_spte_huge_page_mask(struct kvm *kvm, pgprot_t spte)
{
	return pgprot_val(spte) & PT_PAGE_SIZE_MASK;
}
static pgprot_t set_spte_huge_page_mask(struct kvm *kvm, pgprot_t spte)
{
	return __pgprot(pgprot_val(spte) | PT_PAGE_SIZE_MASK);
}
pgprot_t clear_spte_huge_page_mask(struct kvm *kvm, pgprot_t spte)
{
	return __pgprot(pgprot_val(spte) & ~PT_PAGE_SIZE_MASK);
}
static bool is_spte_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return pgprot_val(spte) & PT_WRITABLE_MASK;
}
static pgprot_t set_spte_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return __pgprot(pgprot_val(spte) | PT_WRITABLE_MASK);
}
static pgprot_t clear_spte_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return __pgprot(pgprot_val(spte) & ~PT_WRITABLE_MASK);
}

static pgprotval_t get_spte_sw_mask(struct kvm *kvm, bool host, bool mmu)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);
	pgprotval_t mask = 0;

	if (host)
		mask |= SPTE_HOST_WRITABLE_SW_MASK(spt);
	if (mmu)
		mask |= SPTE_MMU_WRITABLE_SW_MASK(spt);
	return mask;
}
static bool is_spte_sw_writable_mask(struct kvm *kvm, pgprot_t spte,
					bool host, bool mmu)
{
	pgprotval_t sw_mask = 0;

	sw_mask = get_spte_sw_mask(kvm, host, mmu);
	return pgprot_val(spte) & sw_mask;
}
static bool is_spte_all_sw_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t sw_mask = 0;

	sw_mask = get_spte_sw_mask(kvm, true, true);
	return (pgprot_val(spte) & sw_mask) == sw_mask;
}
static pgprot_t set_spte_sw_writable_mask(struct kvm *kvm, pgprot_t spte,
						bool host, bool mmu)
{
	pgprotval_t sw_mask = 0;

	sw_mask = get_spte_sw_mask(kvm, host, mmu);
	return __pgprot(pgprot_val(spte) | sw_mask);
}
static pgprot_t clear_spte_sw_writable_mask(struct kvm *kvm, pgprot_t spte,
						bool host, bool mmu)
{
	pgprotval_t sw_mask = 0;

	sw_mask = get_spte_sw_mask(kvm, host, mmu);
	return __pgprot(pgprot_val(spte) & ~sw_mask);
}
bool is_spte_host_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return is_spte_sw_writable_mask(kvm, spte, true, false);
}
bool is_spte_mmu_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return is_spte_sw_writable_mask(kvm, spte, false, true);
}
static pgprot_t set_spte_host_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return set_spte_sw_writable_mask(kvm, spte, true, false);
}
static pgprot_t set_spte_mmu_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return set_spte_sw_writable_mask(kvm, spte, false, true);
}
static pgprot_t clear_spte_host_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return clear_spte_sw_writable_mask(kvm, spte, true, false);
}
static pgprot_t clear_spte_mmu_writable_mask(struct kvm *kvm, pgprot_t spte)
{
	return clear_spte_sw_writable_mask(kvm, spte, false, true);
}

static pgprotval_t get_spte_pt_user_prot(struct kvm *kvm)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	return spt->ptd_user_prot;
}

static pgprotval_t get_spte_pt_kernel_prot(struct kvm *kvm)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	return spt->ptd_kernel_prot;
}

static pgprot_t set_spte_memory_type_mask(struct kvm_vcpu *vcpu, pgprot_t spte,
						gfn_t gfn, bool is_mmio)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(vcpu->kvm);
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

	return spt->set_pte_val_memory_type(spte, mem_type);
}

static void mark_mmio_spte(struct kvm_vcpu *vcpu, pgprot_t *sptep, u64 gfn,
			   unsigned access)
{
	unsigned int gen = kvm_current_mmio_generation(vcpu);
	u64 mask = generation_mmio_spte_mask(gen);
	pgprot_t spte;

	access &= ACC_WRITE_MASK | ACC_USER_MASK;
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

static void mark_mmio_prefixed_spte(struct kvm_vcpu *vcpu, pgprot_t *sptep, gfn_t gfn,
				kvm_pfn_t pfn, int level, unsigned access)
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

static int is_nx(struct kvm_vcpu *vcpu)
{
	return true;	/* not executable flag is supported */
}

static int is_smap(struct kvm_vcpu *vcpu)
{
	pr_err_once("FIXME: %s() secondary PT is not supported\n", __func__);
	return false;
}

static int is_smep(struct kvm_vcpu *vcpu)
{
	pr_err_once("FIXME: %s() secondary PT is not supported\n", __func__);
	return false;
}

static int is_smm(struct kvm_vcpu *vcpu)
{
	pr_err_once("FIXME: %s() secondary PT is not supported\n", __func__);
	return false;
}

static bool is_shadow_present_pte(struct kvm *kvm, pgprot_t pte)
{
	return (pgprot_val(pte) != 0) &&
			pgprot_val(pte) != get_spte_valid_mask(kvm) &&
				!is_mmio_spte(kvm, pte);
}

static bool is_shadow_valid_pte(struct kvm *kvm, pgprot_t pte)
{
	return pgprot_val(pte) == get_spte_valid_mask(kvm) ||
			is_mmio_spte(kvm, pte) &&
				is_spte_valid_mask(kvm, pte) &&
				!is_spte_present_mask(kvm, pte);
}

static bool is_shadow_present_or_valid_pte(struct kvm *kvm, pgprot_t pte)
{
	return is_shadow_present_pte(kvm, pte) ||
				is_shadow_valid_pte(kvm, pte);
}

static bool is_large_pte(pgprot_t pte)
{
	return pgprot_val(pte) & PT_PAGE_SIZE_MASK;
}

static bool is_last_spte(pgprot_t pte, int level)
{
	if (level == PT_PAGE_TABLE_LEVEL)
		return true;
	if (is_large_pte(pte))
		return true;
	return false;
}

static inline pgprotval_t
kvm_get_pte_pfn_mask(const pt_struct_t *pt)
{
	return pt->pfn_mask;
}
static inline pgprotval_t
kvm_get_spte_pfn_mask(struct kvm *kvm)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	return kvm_get_pte_pfn_mask(spt);
}

static inline e2k_addr_t
kvm_pte_pfn_to_phys_addr(pgprot_t pte, const pt_struct_t *pt)
{
	return pgprot_val(pte) & kvm_get_pte_pfn_mask(pt);
}
static inline e2k_addr_t
kvm_spte_pfn_to_phys_addr(struct kvm *kvm, pgprot_t spte)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);

	return kvm_pte_pfn_to_phys_addr(spte, spt);
}
static inline gpa_t
kvm_gpte_gfn_to_phys_addr(struct kvm_vcpu *vcpu, pgprot_t gpte)
{
	const pt_struct_t *gpt = kvm_get_vcpu_pt_struct(vcpu);

	return kvm_pte_pfn_to_phys_addr(gpte, gpt);
}

static kvm_pfn_t spte_to_pfn(struct kvm *kvm, pgprot_t spte)
{
	return kvm_spte_pfn_to_phys_addr(kvm, spte) >> PAGE_SHIFT;
}

static pgprot_t set_spte_pfn(struct kvm *kvm, pgprot_t spte, kvm_pfn_t pfn)
{
	pgprotval_t pfn_mask = kvm_get_spte_pfn_mask(kvm);

	return __pgprot((pgprot_val(spte) & ~pfn_mask) |
				((pfn << PAGE_SHIFT) & pfn_mask));
}
pgprot_t clear_spte_pfn(struct kvm *kvm, pgprot_t spte)
{
	pgprotval_t pfn_mask = kvm_get_spte_pfn_mask(kvm);

	return __pgprot(pgprot_val(spte) & ~pfn_mask);
}

void kvm_vmlpt_kernel_spte_set(struct kvm *kvm, pgprot_t *spte, pgprot_t *root)
{
	pgprot_t k_spte = __pgprot(get_spte_pt_kernel_prot(kvm));

	*spte = set_spte_pfn(kvm, k_spte, __pa(root) >> PAGE_SHIFT);
}

void kvm_vmlpt_user_spte_set(struct kvm *kvm, pgprot_t *spte, pgprot_t *root)
{
	pgprot_t k_spte = __pgprot(get_spte_pt_user_prot(kvm));

	*spte = set_spte_pfn(kvm, k_spte, __pa(root) >> PAGE_SHIFT);
}

static void __set_spte(pgprot_t *sptep, pgprot_t spte)
{
	WRITE_ONCE(*sptep, spte);
}

static void __update_clear_spte_fast(pgprot_t *sptep, pgprot_t spte)
{
	WRITE_ONCE(*sptep, spte);
}

static pgprot_t __update_clear_spte_slow(pgprot_t *sptep, pgprot_t spte)
{
	return __pgprot(xchg((pgprotval_t *)sptep, pgprot_val(spte)));
}

static pgprot_t __get_spte_lockless(pgprot_t *sptep)
{
	return __pgprot(READ_ONCE(*(pgprotval_t *)sptep));
}

static bool spte_is_locklessly_modifiable(struct kvm *kvm, pgprot_t spte)
{
	return is_spte_all_sw_writable_mask(kvm, spte);
}

static bool spte_has_volatile_bits(struct kvm *kvm, pgprot_t spte)
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

static bool spte_is_bit_cleared(pgprot_t old_spte,
				pgprot_t new_spte, pgprotval_t prot_mask)
{
	return (pgprot_val(old_spte) & prot_mask) &&
			!(pgprot_val(new_spte) & prot_mask);
}

static bool spte_is_bit_changed(pgprot_t old_spte,
				pgprot_t new_spte, pgprotval_t prot_mask)
{
	return (pgprot_val(old_spte) & prot_mask) !=
			(pgprot_val(new_spte) & prot_mask);
}

/* Rules for using mmu_spte_set:
 * Set the sptep from nonpresent to present.
 * Note: the sptep being assigned *must* be either not present
 * or in a state where the hardware will not attempt to update
 * the spte.
 */
static void mmu_spte_set(struct kvm *kvm, pgprot_t *sptep, pgprot_t new_spte)
{
	WARN_ON(is_shadow_present_pte(kvm, *sptep));
	__set_spte(sptep, new_spte);
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
	WARN_ON(!kvm_is_reserved_pfn(pfn) && !page_count(pfn_to_page(pfn)));

	if (!get_spte_accessed_mask(kvm) ||
			is_spte_accessed_mask(kvm, old_spte))
		kvm_set_pfn_accessed(pfn);
	if ((get_spte_dirty_mask(kvm)) ?
			is_spte_dirty_mask(kvm, old_spte) :
				is_spte_writable_mask(kvm, old_spte))
		kvm_set_pfn_dirty(pfn);
	return 1;
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

static pgprot_t mmu_spte_get_lockless(pgprot_t *sptep)
{
	return __get_spte_lockless(sptep);
}

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

static int mmu_topup_memory_cache(struct kvm_mmu_memory_cache *cache,
				  struct kmem_cache *base_cache, int min)
{
	void *obj;

	cache->kmem_cache = base_cache;

	if (cache->nobjs >= min)
		return 0;
	while (cache->nobjs < ARRAY_SIZE(cache->objects)) {
		obj = kmem_cache_zalloc(base_cache, GFP_KERNEL);
		if (!obj)
			return -ENOMEM;
		cache->objects[cache->nobjs++] = obj;
	}
	return 0;
}

static bool mmu_need_topup_memory_cache(struct kvm_mmu_memory_cache *cache,
					int min)
{
	return (cache->nobjs < min);
}

static int mmu_memory_cache_free_objects(struct kvm_mmu_memory_cache *cache)
{
	return cache->nobjs;
}

static void mmu_free_memory_cache(struct kvm_mmu_memory_cache *mc,
				  struct kmem_cache *cache)
{
	while (mc->nobjs)
		kmem_cache_free(cache, mc->objects[--mc->nobjs]);
}

static int mmu_topup_memory_cache_page(struct kvm_mmu_memory_cache *cache,
					int min)
{
	void *page;

	cache->kmem_cache = NULL;

	if (cache->nobjs >= min)
		return 0;
	while (cache->nobjs < ARRAY_SIZE(cache->objects)) {
		page = (void *)__get_free_page(GFP_KERNEL);
		if (!page)
			return -ENOMEM;
		cache->objects[cache->nobjs++] = page;
	}
	return 0;
}

static void mmu_free_memory_cache_page(struct kvm_mmu_memory_cache *mc)
{
	while (mc->nobjs)
		free_page((unsigned long)mc->objects[--mc->nobjs]);
}

static int mmu_topup_memory_caches(struct kvm_vcpu *vcpu)
{
	int r;

	r = mmu_topup_memory_cache(&vcpu->arch.mmu_pte_list_desc_cache,
				   pte_list_desc_cache, KVM_NR_MIN_MEM_OBJS);
	if (r)
		goto out;
	r = mmu_topup_memory_cache_page(&vcpu->arch.mmu_page_cache,
					KVM_NR_MIN_MEM_OBJS);
	if (r)
		goto out;
	r = mmu_topup_memory_cache(&vcpu->arch.mmu_page_header_cache,
				   mmu_page_header_cache,
				   KVM_NR_MIN_MEM_OBJS);
out:
	return r;
}

static bool mmu_need_topup_memory_caches(struct kvm_vcpu *vcpu)
{
	bool r = false;

	r = mmu_need_topup_memory_cache(&vcpu->arch.mmu_pte_list_desc_cache,
					KVM_NR_MIN_MEM_OBJS);
	if (r)
		goto out;
	r = mmu_need_topup_memory_cache(&vcpu->arch.mmu_page_cache,
					KVM_NR_MIN_MEM_OBJS);
	if (r)
		goto out;
	r = mmu_need_topup_memory_cache(&vcpu->arch.mmu_page_header_cache,
					KVM_NR_MIN_MEM_OBJS);
out:
	return r;
}

static void mmu_free_memory_caches(struct kvm_vcpu *vcpu)
{
	mmu_free_memory_cache(&vcpu->arch.mmu_pte_list_desc_cache,
				pte_list_desc_cache);
	mmu_free_memory_cache_page(&vcpu->arch.mmu_page_cache);
	mmu_free_memory_cache(&vcpu->arch.mmu_page_header_cache,
				mmu_page_header_cache);
}

static inline void *mmu_memory_cache_alloc_obj(
				struct kvm_mmu_memory_cache *mc,
				gfp_t gfp_flags)
{
	if (mc->kmem_cache)
		return kmem_cache_zalloc(mc->kmem_cache, gfp_flags);
	else
		return (void *)__get_free_page(gfp_flags);
}

static void *mmu_memory_cache_alloc(struct kvm_mmu_memory_cache *mc)
{
	void *p;

	if (!mc->nobjs)
		p = mmu_memory_cache_alloc_obj(mc,
				GFP_ATOMIC | __GFP_ACCOUNT);
	else
		p = mc->objects[--mc->nobjs];

	KVM_BUG_ON(!p);

	return p;
}

static struct pte_list_desc *mmu_alloc_pte_list_desc(struct kvm_vcpu *vcpu)
{
	return mmu_memory_cache_alloc(&vcpu->arch.mmu_pte_list_desc_cache);
}

static void mmu_free_pte_list_desc(struct pte_list_desc *pte_list_desc)
{
	kmem_cache_free(pte_list_desc_cache, pte_list_desc);
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
		KVM_BUG_ON(gfn != kvm_mmu_page_get_gfn(sp, index));
	else
		sp->gfns[index] = gfn;
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
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);
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

void kvm_mmu_gfn_disallow_lpage(struct kvm *kvm,
			kvm_memory_slot_t *slot, gfn_t gfn)
{
	update_gfn_disallow_lpage_count(kvm, slot, gfn, 1);
}

void kvm_mmu_gfn_allow_lpage(struct kvm *kvm,
			kvm_memory_slot_t *slot, gfn_t gfn)
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

	/*
	 * Allow guest to write to the lowest levels of guest pt if
	 * CONFIG_PARAVIRT_TLB_FLUSH is enabled
	 */
	if ((sp->role.level > PT_PAGE_TABLE_LEVEL) ||
			!IS_ENABLED(CONFIG_KVM_PARAVIRT_TLB_FLUSH))
		kvm_slot_page_track_add_page(kvm, slot, gfn,
					KVM_PAGE_TRACK_WRITE);

	kvm_mmu_gfn_disallow_lpage(kvm, slot, gfn);
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
	kvm_mmu_gfn_allow_lpage(kvm, slot, gfn);
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

static int host_mapping_level(struct kvm *kvm, gfn_t gfn)
{
	unsigned long page_size;
	struct kvm_vcpu *vcpu = kvm_get_vcpu(kvm, 0);
	int i, ret = 0;

	page_size = kvm_host_page_size(vcpu, gfn);

	for (i = PT_PAGE_TABLE_LEVEL; i <= PT_MAX_HUGEPAGE_LEVEL; ++i) {
		if (page_size >= KVM_MMU_HPAGE_SIZE(kvm, i))
			ret = i;
		else
			break;
	}

	return ret;
}

static inline bool memslot_valid_for_gpte(struct kvm_memory_slot *slot,
					  bool no_dirty_log)
{
	if (!slot || slot->flags & KVM_MEMSLOT_INVALID)
		return false;
	if (no_dirty_log && slot->dirty_bitmap)
		return false;

	return true;
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

	host_level = host_mapping_level(vcpu->kvm, large_gfn);

	if (host_level == PT_PAGE_TABLE_LEVEL)
		return host_level;

	max_level = min(MAX_HUGE_PAGES_LEVEL, host_level);

	pt_level = &kvm_get_host_pt_struct(vcpu->kvm)->levels[
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

/*
 * About rmap_head encoding:
 *
 * If the bit zero of rmap_head->val is clear, then it points to the only spte
 * in this rmap chain. Otherwise, (rmap_head->val & ~1) points to a struct
 * pte_list_desc containing more mappings.
 */

/*
 * Returns the number of pointers in the rmap chain, not counting the new one.
 */
static int pte_list_add(struct kvm_vcpu *vcpu, pgprot_t *spte,
			struct kvm_rmap_head *rmap_head)
{
	struct pte_list_desc *desc;
	int i, count = 0;

	if (!rmap_head->val) {
		rmap_printk("pte_list_add: %px %lx 0->1\n",
			spte, pgprot_val(*spte));
		rmap_head->val = (unsigned long)spte;
	} else if (!(rmap_head->val & 1)) {
		rmap_printk("pte_list_add: %px %lx 1->many\n",
			spte, pgprot_val(*spte));
		desc = mmu_alloc_pte_list_desc(vcpu);
		desc->sptes[0] = (pgprot_t *)rmap_head->val;
		desc->sptes[1] = spte;
		rmap_head->val = (unsigned long)desc | 1;
		++count;
	} else {
		rmap_printk("pte_list_add: %px %lx many->many\n",
			spte, pgprot_val(*spte));
		desc = (struct pte_list_desc *)(rmap_head->val & ~1ul);
		while (desc->sptes[PTE_LIST_EXT-1] && desc->more) {
			desc = desc->more;
			count += PTE_LIST_EXT;
		}
		if (desc->sptes[PTE_LIST_EXT-1]) {
			desc->more = mmu_alloc_pte_list_desc(vcpu);
			desc = desc->more;
		}
		for (i = 0; desc->sptes[i]; ++i)
			++count;
		desc->sptes[i] = spte;
	}
	return count;
}

static void
pte_list_desc_remove_entry(struct kvm_rmap_head *rmap_head,
			   struct pte_list_desc *desc, int i,
			   struct pte_list_desc *prev_desc)
{
	int j;

	for (j = PTE_LIST_EXT - 1; !desc->sptes[j] && j > i; --j)
		;
	desc->sptes[i] = desc->sptes[j];
	desc->sptes[j] = NULL;
	if (j != 0)
		return;
	if (!prev_desc && !desc->more)
		rmap_head->val = (unsigned long)desc->sptes[0];
	else
		if (prev_desc)
			prev_desc->more = desc->more;
		else
			rmap_head->val = (unsigned long)desc->more | 1;
	mmu_free_pte_list_desc(desc);
}

static void pte_list_remove(pgprot_t *spte, struct kvm_rmap_head *rmap_head)
{
	struct pte_list_desc *desc;
	struct pte_list_desc *prev_desc;
	int i;

	if (!rmap_head->val) {
		pr_err("%s(): %px 0x%lx 0->BUG\n",
			__func__, spte, pgprot_val(*spte));
		BUG();
	} else if (!(rmap_head->val & 1)) {
		rmap_printk("pte_list_remove:  %px 1->0\n", spte);
		DebugPTE("%px 1->0\n", spte);
		if ((pgprot_t *)rmap_head->val != spte) {
			pr_err("%s():  %px 0x%lx 1->BUG\n",
				__func__, spte, pgprot_val(*spte));
			BUG();
		}
		rmap_head->val = 0;
	} else {
		rmap_printk("pte_list_remove:  %px many->many\n", spte);
		desc = (struct pte_list_desc *)(rmap_head->val & ~1ul);
		prev_desc = NULL;
		DebugPTE("%px many->many, desc %px\n", spte, desc);
		while (desc) {
			for (i = 0; i < PTE_LIST_EXT && desc->sptes[i]; ++i) {
				if (desc->sptes[i] == spte) {
					pte_list_desc_remove_entry(rmap_head,
							desc, i, prev_desc);
					DebugPTE("remove desc from list #%d, "
						"prev %px\n",
						i, prev_desc);
					return;
				}
			}
			prev_desc = desc;
			desc = desc->more;
		}
		pr_err("pte_list_remove: %px many->many\n", spte);
		BUG();
	}
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

static bool rmap_can_add(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu_memory_cache *cache;

	cache = &vcpu->arch.mmu_pte_list_desc_cache;
	return mmu_memory_cache_free_objects(cache);
}

static int rmap_add(struct kvm_vcpu *vcpu, pgprot_t *spte, gfn_t gfn)
{
	struct kvm_mmu_page *sp;
	struct kvm_rmap_head *rmap_head;

	sp = page_header(__pa(spte));
	kvm_mmu_page_set_gfn(sp, spte - sp->spt, gfn);
	rmap_head = gfn_to_rmap(vcpu->kvm, gfn, sp);
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
	pte_list_remove(spte, rmap_head);
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

static void drop_spte(struct kvm *kvm, pgprot_t *sptep)
{
	DebugPTE("started for spte %px == 0x%lx\n",
		sptep, pgprot_val(*sptep));
	if (mmu_spte_clear_track_bits(kvm, sptep))
		rmap_remove(kvm, sptep);
}


static bool __drop_large_spte(struct kvm *kvm, pgprot_t *sptep)
{
	if (is_large_pte(*sptep)) {
		WARN_ON(page_header(__pa(sptep))->role.level ==
			PT_PAGE_TABLE_LEVEL);
		drop_spte(kvm, sptep);
		--kvm->stat.lpages;
		return true;
	}

	return false;
}

static void drop_large_spte(struct kvm_vcpu *vcpu, pgprot_t *sptep)
{
	if (__drop_large_spte(vcpu->kvm, sptep))
		kvm_flush_remote_tlbs(vcpu->kvm);
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
	pgprot_t *sptep;
	struct rmap_iterator iter;
	bool flush = false;

	for_each_rmap_spte(kvm, rmap_head, &iter, sptep)
		flush |= spte_write_protect(kvm, sptep, pt_protect);

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
	pgprot_t *sptep;
	struct rmap_iterator iter;
	bool flush = false;

	for_each_rmap_spte(kvm, rmap_head, &iter, sptep)
		flush |= spte_clear_dirty(kvm, sptep);

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
	pgprot_t *sptep;
	struct rmap_iterator iter;
	bool flush = false;

	for_each_rmap_spte(kvm, rmap_head, &iter, sptep)
		flush |= spte_set_dirty(kvm, sptep);

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
 * kvm_mmu_clear_dirty_pt_masked - clear MMU D-bit for PT level pages
 * @kvm: kvm instance
 * @slot: slot to clear D-bit
 * @gfn_offset: start of the BITS_PER_LONG pages we care about
 * @mask: indicates which pages we should clear D-bit
 *
 * Used for PML to re-log the dirty GPAs after userspace querying dirty_bitmap.
 */
void kvm_mmu_clear_dirty_pt_masked(struct kvm *kvm,
				     struct kvm_memory_slot *slot,
				     gfn_t gfn_offset, unsigned long mask)
{
	struct kvm_rmap_head *rmap_head;

	while (mask) {
		rmap_head = __gfn_to_rmap(kvm,
				slot->base_gfn + gfn_offset + __ffs(mask),
				PT_PAGE_TABLE_LEVEL, slot);
		__rmap_clear_dirty(kvm, rmap_head);

		/* clear the first set bit */
		mask &= mask - 1;
	}
}
EXPORT_SYMBOL_GPL(kvm_mmu_clear_dirty_pt_masked);

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
void kvm_arch_mmu_enable_log_dirty_pt_masked(struct kvm *kvm,
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

bool kvm_mmu_slot_gfn_write_protect(struct kvm *kvm,
				    struct kvm_memory_slot *slot, u64 gfn)
{
	const pt_struct_t *spt = kvm_get_host_pt_struct(kvm);
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
	return kvm_mmu_slot_gfn_write_protect(vcpu->kvm, slot, gfn);
}

static bool kvm_zap_rmapp(struct kvm *kvm, struct kvm_rmap_head *rmap_head)
{
	pgprot_t *sptep;
	struct rmap_iterator iter;
	bool flush = false;

	while ((sptep = rmap_get_first(kvm, rmap_head, &iter))) {
		rmap_printk("%s: spte %px %lx.\n",
			__func__, sptep, pgprot_val(*sptep));

		drop_spte(kvm, sptep);
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
	pgprot_t *sptep;
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

		if (pte_write(*ptep)) {
			drop_spte(kvm, sptep);
			goto restart;
		} else {
			new_spte = set_spte_pfn(kvm, *sptep, new_pfn);

			new_spte = clear_spte_writable_mask(kvm, new_spte);
			new_spte = clear_spte_host_writable_mask(kvm, new_spte);
			new_spte = clear_spte_accessed_mask(kvm, new_spte);

			mmu_spte_clear_track_bits(kvm, sptep);
			mmu_spte_set(kvm, sptep, new_spte);
		}
	}

	if (need_flush)
		kvm_flush_remote_tlbs(kvm);

	return 0;
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
	iterator->pt_struct = kvm_get_host_pt_struct(kvm);
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
			(1UL << KVM_PT_LEVEL_HPAGE_SHIFT(iterator->pt_level));
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

int kvm_unmap_hva(struct kvm *kvm, unsigned long hva)
{
	return kvm_handle_hva(kvm, hva, 0, kvm_unmap_rmapp);
}

int kvm_unmap_hva_range(struct kvm *kvm, unsigned long start, unsigned long end, unsigned flags)
{
	return kvm_handle_hva_range(kvm, start, end, 0, kvm_unmap_rmapp);
}

int kvm_set_spte_hva(struct kvm *kvm, unsigned long hva, pte_t pte)
{
	kvm_handle_hva(kvm, hva, (unsigned long)&pte, kvm_set_pte_rmapp);
	return 0;
}

static int kvm_age_rmapp(struct kvm *kvm, struct kvm_rmap_head *rmap_head,
			 struct kvm_memory_slot *slot, gfn_t gfn, int level,
			 unsigned long data)
{
	pgprot_t *sptep;
	struct rmap_iterator uninitialized_var(iter);
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

#define RMAP_RECYCLE_THRESHOLD 1000

static void rmap_recycle(struct kvm_vcpu *vcpu, pgprot_t *spte, gfn_t gfn)
{
	struct kvm_rmap_head *rmap_head;
	struct kvm_mmu_page *sp;

	sp = page_header(__pa(spte));

	rmap_head = gfn_to_rmap(vcpu->kvm, gfn, sp);

	kvm_unmap_rmapp(vcpu->kvm, rmap_head, NULL, gfn, sp->role.level, 0);
	kvm_flush_remote_tlbs(vcpu->kvm);
}

int kvm_age_hva(struct kvm *kvm, unsigned long start, unsigned long end)
{
	/*
	 * In case of absence of EPT Access and Dirty Bits supports,
	 * emulate the accessed bit for EPT, by checking if this page has
	 * an EPT mapping, and clearing it if it does. On the next access,
	 * a new EPT mapping will be established.
	 * This has some overhead, but not as much as the cost of swapping
	 * out actively used pages or breaking up actively used hugepages.
	 */
	if (!get_spte_accessed_mask(kvm)) {
#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
		/*
		 * We are holding the kvm->mmu_lock, and we are blowing up
		 * shadow PTEs. MMU notifier consumers need to be kept at bay.
		 * This is correct as long as we don't decouple the mmu_lock
		 * protected regions (like invalidate_range_start|end does).
		 */
		kvm->mmu_notifier_seq++;
		return kvm_handle_hva_range(kvm, start, end, 0,
					    kvm_unmap_rmapp);
#else	/* ! KVM_ARCH_WANT_MMU_NOTIFIER */
		kvm_pr_unimpl("%s(): absence of TDP Access and Dirty Bits "
			"supports is not implemented case\n",
			__func__);
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */
	}

	return kvm_handle_hva_range(kvm, start, end, 0, kvm_age_rmapp);
}

int kvm_test_age_hva(struct kvm *kvm, unsigned long hva)
{
	return kvm_handle_hva(kvm, hva, 0, kvm_test_age_rmapp);
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

/*
 * This value is the sum of all of the kvm instances's
 * kvm->arch.n_used_mmu_pages values.  We need a global,
 * aggregate version in order to make the slab shrinker
 * faster
 */
static inline void kvm_mod_used_mmu_pages(struct kvm *kvm, int nr)
{
	kvm->arch.n_used_mmu_pages += nr;
	percpu_counter_add(&kvm_total_used_mmu_pages, nr);
}

void kvm_mmu_free_page(struct kvm *kvm, struct kvm_mmu_page *sp)
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

static unsigned kvm_page_table_hashfn(gfn_t gfn)
{
	return gfn & ((1 << KVM_MMU_HASH_SHIFT) - 1);
}

static void mmu_page_add_parent_pte(struct kvm_vcpu *vcpu,
			struct kvm_mmu_page *sp, pgprot_t *parent_pte)
{
	if (!parent_pte)
		return;

	pte_list_add(vcpu, parent_pte, &sp->parent_ptes);
}

static void mmu_page_remove_parent_pte(struct kvm_mmu_page *sp,
				       pgprot_t *parent_pte)
{
	pte_list_remove(parent_pte, &sp->parent_ptes);
}

static void drop_parent_pte(struct kvm_mmu_page *sp,
			    pgprot_t *parent_pte)
{
	struct kvm_mmu_page *parent_sp = page_header(__pa(parent_pte));

	if (parent_sp == sp) {
		/* it is one PGD entry for the VPTB self-map. */
		KVM_BUG_ON(sp->role.level != PT64_ROOT_LEVEL);
	} else {
		mmu_page_remove_parent_pte(sp, parent_pte);
	}
	mmu_spte_clear_no_track(parent_pte);
}

static kvm_mmu_page_t *kvm_mmu_alloc_page(struct kvm_vcpu *vcpu, int direct)
{
	kvm_mmu_page_t *sp;

	sp = mmu_memory_cache_alloc(&vcpu->arch.mmu_page_header_cache);
	sp->spt = mmu_memory_cache_alloc(&vcpu->arch.mmu_page_cache);
	if (!direct)
		sp->gfns = mmu_memory_cache_alloc(&vcpu->arch.mmu_page_cache);
	set_page_private(virt_to_page(sp->spt), (unsigned long)sp);

	/*
	 * The active_mmu_pages list is the FIFO list, do not move the
	 * page until it is zapped. kvm_zap_obsolete_pages depends on
	 * this feature. See the comments in kvm_zap_obsolete_pages().
	 */
	list_add(&sp->link, &vcpu->kvm->arch.active_mmu_pages);
	kvm_mod_used_mmu_pages(vcpu->kvm, +1);
	return sp;
}

static void mark_unsync(struct kvm *kvm, pgprot_t *spte);
static void kvm_mmu_mark_parents_unsync(struct kvm *kvm, kvm_mmu_page_t *sp)
{
	pgprot_t *sptep;
	struct rmap_iterator iter;

	for_each_rmap_spte(kvm, &sp->parent_ptes, &iter, sptep) {
		mark_unsync(kvm, sptep);
	}
}

static void mark_unsync(struct kvm *kvm, pgprot_t *spte)
{
	kvm_mmu_page_t *sp;
	unsigned int index;

	sp = page_header(__pa(spte));
	index = spte - sp->spt;
	if (__test_and_set_bit(index, sp->unsync_child_bitmap))
		return;
	if (sp->unsync_children++)
		return;
	kvm_mmu_mark_parents_unsync(kvm, sp);
}

static int nonpaging_sync_page(struct kvm_vcpu *vcpu,
			       struct kvm_mmu_page *sp)
{
	return 0;
}

static void nonpaging_sync_gva(struct kvm_vcpu *vcpu, gva_t gva)
{
}

static void nonpaging_sync_gva_range(struct kvm_vcpu *vcpu,
					gva_t gva_start,
					gva_t gva_end,
					bool flush_tlb)
{
}

static void nonpaging_update_pte(struct kvm_vcpu *vcpu,
				 struct kvm_mmu_page *sp, pgprot_t *spte,
				 const void *pte)
{
	WARN_ON(1);
}

#define KVM_PAGE_ARRAY_NR 16

struct kvm_mmu_pages {
	struct mmu_page_and_offset {
		struct kvm_mmu_page *sp;
		unsigned int idx;
	} page[KVM_PAGE_ARRAY_NR];
	unsigned int nr;
};

static int mmu_pages_add(struct kvm_mmu_pages *pvec, struct kvm_mmu_page *sp,
			 int idx)
{
	int i;

	if (sp->unsync || sp->released) {
		for (i = 0; i < pvec->nr; i++)
			if (pvec->page[i].sp == sp) {
				DebugFREE("found same sp %px level #%d "
					"gva 0x%lx at pvec #%d\n",
					sp, sp->role.level, sp->gva, i);
				return 0;
			}
	}

	pvec->page[pvec->nr].sp = sp;
	pvec->page[pvec->nr].idx = idx;
	DebugFREE("pvec[0x%02x] : new sp %px level #%d gva 0x%lx idx 0x%03lx\n",
		pvec->nr, sp, sp->role.level, sp->gva,
		idx * sizeof(pgprot_t));
	pvec->nr++;
	return (pvec->nr == KVM_PAGE_ARRAY_NR);
}

static inline void clear_unsync_child_bit(struct kvm_mmu_page *sp, int idx)
{
	--sp->unsync_children;
	WARN_ON((int)sp->unsync_children < 0);
	__clear_bit(idx, sp->unsync_child_bitmap);
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

#define INVALID_INDEX (-1)

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

static void kvm_unlink_unsync_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	WARN_ON(!sp->unsync);
	trace_kvm_mmu_sync_page(sp);
	sp->unsync = 0;
	--kvm->stat.mmu_unsync;
}

static int kvm_mmu_prepare_zap_page(struct kvm *kvm, struct kvm_mmu_page *sp,
				    struct list_head *invalid_list);
static void kvm_mmu_commit_zap_page(struct kvm *kvm,
				    struct list_head *invalid_list);

/*
 * NOTE: we should pay more attention on the zapped-obsolete page
 * (is_obsolete_sp(sp) && sp->role.invalid) when you do hash list walk
 * since it has been deleted from active_mmu_pages but still can be found
 * at hast list.
 *
 * for_each_gfn_valid_sp() has skipped that kind of pages.
 */
#define for_each_gfn_valid_sp(_kvm, _sp, _gfn)				\
	hlist_for_each_entry(_sp,					\
	  &(_kvm)->arch.mmu_page_hash[kvm_page_table_hashfn(_gfn)], hash_link) \
		if ((_sp)->gfn != (_gfn) || is_obsolete_sp((_kvm), (_sp)) \
			|| (_sp)->role.invalid) {} else

#define for_each_gfn_indirect_valid_sp(_kvm, _sp, _gfn)			\
	for_each_gfn_valid_sp(_kvm, _sp, _gfn)				\
		if ((_sp)->role.direct) {} else

/* @sp->gfn should be write-protected at the call site */
static bool __kvm_sync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
			    struct list_head *invalid_list)
{
	if (sp->role.cr4_pae != !!is_pae(vcpu)) {
		kvm_mmu_prepare_zap_page(vcpu->kvm, sp, invalid_list);
		return false;
	}

	if (vcpu->arch.mmu.sync_page(vcpu, sp) == 0) {
		kvm_mmu_prepare_zap_page(vcpu->kvm, sp, invalid_list);
		return false;
	}

	return true;
}

static void kvm_mmu_flush_or_zap(struct kvm_vcpu *vcpu,
				 struct list_head *invalid_list,
				 bool remote_flush, bool local_flush)
{
	if (!list_empty(invalid_list)) {
		kvm_mmu_commit_zap_page(vcpu->kvm, invalid_list);
		return;
	}

	if (remote_flush)
		kvm_flush_remote_tlbs(vcpu->kvm);
	else if (local_flush)
		kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
}

#ifdef CONFIG_KVM_MMU_AUDIT
#include "mmu_audit.c"
#else
static void kvm_mmu_audit(struct kvm_vcpu *vcpu, int point) { }
static void mmu_audit_disable(void) { }
#endif

static bool is_obsolete_sp(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	return unlikely(sp->mmu_valid_gen != kvm->arch.mmu_valid_gen);
}

static bool kvm_sync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
			 struct list_head *invalid_list)
{
	kvm_unlink_unsync_page(vcpu->kvm, sp);
	return __kvm_sync_page(vcpu, sp, invalid_list);
}

/* @gfn should be write-protected at the call site */
static bool kvm_sync_pages(struct kvm_vcpu *vcpu, gfn_t gfn,
			   struct list_head *invalid_list)
{
	struct kvm_mmu_page *s;
	bool ret = false;

	for_each_gfn_indirect_valid_sp(vcpu->kvm, s, gfn) {
		if (!s->unsync)
			continue;

		WARN_ON(s->role.level != PT_PAGE_TABLE_LEVEL);
		ret |= kvm_sync_page(vcpu, s, invalid_list);
	}

	return ret;
}

struct mmu_page_path {
	struct kvm_mmu_page *parent[PT64_ROOT_LEVEL];
	unsigned int idx[PT64_ROOT_LEVEL];
};

#define for_each_sp(pvec, sp, parents, i)			\
		for (i = mmu_pages_first(&pvec, &parents,	\
						PT_PAGE_TABLE_LEVEL);	\
			i < pvec.nr && ({ sp = pvec.page[i].sp; 1; });	\
			i = mmu_pages_next(&pvec, &parents, i, \
						PT_PAGE_TABLE_LEVEL))

#define for_each_sp_level(pvec, sp, parents, i, pt_level)	\
		for (i = mmu_pages_first(&pvec, &parents, pt_level);	\
			i < pvec.nr && ({ sp = pvec.page[i].sp; 1; });	\
			i = mmu_pages_next(&pvec, &parents, i, \
						pt_level))

static int mmu_pages_next(struct kvm_mmu_pages *pvec,
			  struct mmu_page_path *parents,
			  int i, int pt_level)
{
	int n;

	DebugFREE("started pvec num %d i %d\n", pvec->nr, i);
	for (n = i+1; n < pvec->nr; n++) {
		struct kvm_mmu_page *sp = pvec->page[n].sp;
		unsigned idx = pvec->page[n].idx;
		int level = sp->role.level;

		DebugFREE("pvec [0x%02x] : SP %px level #%d gfn 0x%llx "
			"gva 0x%lx idx 0x%03lx\n",
			n, sp, level, sp->gfn, sp->gva,
			idx * sizeof(pgprot_t));
		BUG_ON(level < pt_level);
		parents->idx[level-1] = idx;
		DebugFREE("parents level #%d idx %px : 0x%03lx\n",
			level - 1, &parents->idx[level-1],
			idx * sizeof(pgprot_t));
		if (level == pt_level)
			break;

		parents->parent[level-2] = sp;
		DebugFREE("parents level #%d parent %px : sp %px\n",
			level - 2, &parents->parent[level-2], sp);
	}

	return n;
}

static int mmu_pages_first(struct kvm_mmu_pages *pvec,
			struct mmu_page_path *parents, int pt_level)
{
	struct kvm_mmu_page *sp;
	int level;

	DebugFREE("started pvec num %d\n", pvec->nr);
	if (pvec->nr == 0)
		return 0;

	WARN_ON(pvec->page[0].idx != INVALID_INDEX);

	sp = pvec->page[0].sp;
	level = sp->role.level;
	WARN_ON(level <= PT_PAGE_TABLE_LEVEL);
	DebugFREE("pvec [0x%02x] : SP %px level #%d gfn 0x%llx gva 0x%lx\n",
		0, sp, level, sp->gfn, sp->gva);

	parents->parent[level-2] = sp;
	DebugFREE("parents level #%d parent %px : sp %px\n",
		level - 2, &parents->parent[level-2], sp);

	/* Also set up a sentinel.  Further entries in pvec are all
	 * children of sp, so this element is never overwritten.
	 */
	parents->parent[level-1] = NULL;
	DebugFREE("parents level #%d parent %px : sp %px\n",
		level - 1, &parents->parent[level-1], NULL);
	return mmu_pages_next(pvec, parents, 0, pt_level);
}

static void mmu_pages_clear_parents(struct mmu_page_path *parents, int pt_level)
{
	struct kvm_mmu_page *sp;
	unsigned int level = pt_level - PT_PAGE_TABLE_LEVEL;

	do {
		unsigned int idx = parents->idx[level];
		sp = parents->parent[level];
		if (!sp)
			return;

		WARN_ON(idx == INVALID_INDEX);
		if (!sp->released) {
			clear_unsync_child_bit(sp, idx);
		}
		level++;
	} while (!sp->unsync_children);
}

static void mmu_sync_children(struct kvm_vcpu *vcpu,
			      struct kvm_mmu_page *parent)
{
	int i, nr_unsync_leaf;
	struct kvm_mmu_page *sp;
	struct mmu_page_path parents;
	struct kvm_mmu_pages pages;
	LIST_HEAD(invalid_list);
	bool flush = false;

	DebugUNSYNC("started on VCPU #%d for parent SP %px\n",
		vcpu->vcpu_id, parent);
	while (nr_unsync_leaf = mmu_unsync_walk(vcpu->kvm, parent, &pages,
					PT_PAGE_TABLE_LEVEL),
			nr_unsync_leaf) {
		bool protected = false;

		DebugFREE("nr_unsync_leaf is not zero %d\n", nr_unsync_leaf);
		for_each_sp(pages, sp, parents, i)
			protected |= rmap_write_protect(vcpu, sp->gfn);

		if (protected) {
			kvm_flush_remote_tlbs(vcpu->kvm);
			flush = false;
		}

		for_each_sp(pages, sp, parents, i) {
			flush |= kvm_sync_page(vcpu, sp, &invalid_list);
			mmu_pages_clear_parents(&parents, PT_PAGE_TABLE_LEVEL);
		}
		if (need_resched() || spin_needbreak(&vcpu->kvm->mmu_lock)) {
			kvm_mmu_flush_or_zap(vcpu, &invalid_list, false, flush);
			cond_resched_lock(&vcpu->kvm->mmu_lock);
			flush = false;
		}
	}
	if (nr_unsync_leaf == 0) {
		DebugFREE("nr_unsync_leaf is zero %d\n", nr_unsync_leaf);
	}

	kvm_mmu_flush_or_zap(vcpu, &invalid_list, false, flush);
}

static void __clear_sp_write_flooding_count(struct kvm_mmu_page *sp)
{
	atomic_set(&sp->write_flooding_count,  0);
}

static void clear_sp_write_flooding_count(pgprot_t *spte)
{
	struct kvm_mmu_page *sp =  page_header(__pa(spte));

	__clear_sp_write_flooding_count(sp);
}

static void clear_shadow_pt(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
				bool validate)
{
	pgprot_t *spt;
	pgprot_t init_pt;
	int i;

	spt = sp->spt;
	if (validate) {
		pgprot_val(init_pt) = get_spte_valid_mask(vcpu->kvm);
	} else {
		pgprot_val(init_pt) = 0UL;
	}

	for (i = 0; i < PT64_ENT_PER_PAGE; i++) {
		spt[i] = init_pt;
	}
}

static void check_pt_validation(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp)
{
	pgprot_t *spt;
	pgprotval_t valid_pt;
	int i;

	if (sp->role.direct)
		return;

	if (sp->unsync)
		return;

	spt = sp->spt;
	valid_pt = get_spte_valid_mask(vcpu->kvm);

	for (i = 0; i < PT64_ENT_PER_PAGE; i++) {
		KVM_BUG_ON(pgprot_val(spt[i]) != valid_pt);
	}
}

static inline bool
kvm_compare_mmu_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
			gva_t gaddr, gfn_t gfn, bool is_direct)
{
	gva_t sp_gva, pt_gva;
	unsigned index;
	const pt_struct_t *gpt;
	const pt_level_t *gpt_level;
	int level;

	if (unlikely(!is_paging(vcpu)))
		return true;

	level = sp->role.level;
	KVM_BUG_ON(level < PT_PAGE_TABLE_LEVEL);
	gpt = kvm_get_vcpu_pt_struct(vcpu);
	gpt_level = &gpt->levels[level];
	index = (gaddr & ~PAGE_MASK) / sizeof(pgprotval_t);
	sp_gva = sp->gva & get_pt_level_mask(gpt_level);
	sp_gva = set_pt_level_addr_index(sp_gva, index, gpt_level);
	pt_gva = gaddr & get_pt_level_mask(gpt_level);
	pt_gva = set_pt_level_addr_index(pt_gva, index, gpt_level);
	if (!is_direct && pt_gva >= GUEST_KERNEL_IMAGE_AREA_BASE &&
				pt_gva < GUEST_KERNEL_IMAGE_AREA_BASE +
						vcpu->arch.guest_size) {
		/* it is virtual address from guest kernel image, */
		/* convert it to equal "virtual" physical */
		pt_gva -= GUEST_KERNEL_IMAGE_AREA_BASE;
		pt_gva += GUEST_PAGE_OFFSET + vcpu->arch.guest_phys_base;
	}
	if (sp_gva != pt_gva) {
		DebugFLOOD("SP for GFN 0x%llx map other virt "
			"addr 0x%lx then need 0x%lx\n",
			gfn, sp_gva, pt_gva);
		return false;
	}
	return true;
}

static struct kvm_mmu_page *kvm_mmu_get_page(struct kvm_vcpu *vcpu,
					     gfn_t gfn,
					     gva_t gaddr,
					     unsigned level,
					     int direct,
					     unsigned access,
					     bool validate)
{
	union kvm_mmu_page_role role;
	unsigned quadrant;
	struct kvm_mmu_page *sp;
	bool need_sync = false;
	bool flush = false;
	LIST_HEAD(invalid_list);

	role = vcpu->arch.mmu.base_role;
	role.level = level;
	role.direct = direct;
	if (role.direct)
		role.cr4_pae = 0;
	role.access = access;
	if (!vcpu->arch.mmu.direct_map &&
			vcpu->arch.mmu.root_level <= PT32_ROOT_LEVEL) {
		quadrant = gaddr >> (PAGE_SHIFT + (PT64_LEVEL_BITS * level));
		quadrant &= (1 << ((PT32_LEVEL_BITS - PT64_LEVEL_BITS) *
								level)) - 1;
		role.quadrant = quadrant;
	}
	for_each_gfn_valid_sp(vcpu->kvm, sp, gfn) {
		if (!need_sync && sp->unsync)
			need_sync = true;

		if (unlikely(sp->role.word != role.word)) {
			if (unlikely(is_paging(vcpu) &&
					!sp->role.direct && role.cr4_pae)) {
				DebugFLOOD("SP for GFN 0x%llx map other role "
					"PT level 0x%x then need 0x%x\n",
					gfn, sp->role.word, role.word);
			}
			continue;
		}

		if (unlikely(!kvm_compare_mmu_page(vcpu, sp, gaddr, gfn,
							direct)))
			continue;

		if (sp->unsync) {
			/* The page is good, but __kvm_sync_page might still end
			 * up zapping it.  If so, break in order to rebuild it.
			 */
			if (!__kvm_sync_page(vcpu, sp, &invalid_list))
				break;

			WARN_ON(!list_empty(&invalid_list));
			kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
		}
		if (sp->unsync_children)
			kvm_make_request(KVM_REQ_MMU_SYNC, vcpu);

		KVM_BUG_ON(sp->released);

		__clear_sp_write_flooding_count(sp);
		if (validate) {
			check_pt_validation(vcpu, sp);
		}
		trace_kvm_mmu_get_page(sp, false);
		return sp;
	}

	++vcpu->kvm->stat.mmu_cache_miss;
	sp = kvm_mmu_alloc_page(vcpu, direct);
	sp->gfn = gfn;
	sp->gva = gaddr;
	sp->role = role;
	hlist_add_head(&sp->hash_link,
		&vcpu->kvm->arch.mmu_page_hash[kvm_page_table_hashfn(gfn)]);
	kvm_init_sp_gmm_entry(sp);
	if (!direct) {
		/*
		 * we should do write protection before syncing pages
		 * otherwise the content of the synced shadow page may
		 * be inconsistent with guest page table.
		 */
		account_shadowed(vcpu->kvm, sp);
		if (level == PT_PAGE_TABLE_LEVEL &&
		      rmap_write_protect(vcpu, gfn))
			kvm_flush_remote_tlbs(vcpu->kvm);

		if (level > PT_PAGE_TABLE_LEVEL && need_sync)
			flush |= kvm_sync_pages(vcpu, gfn, &invalid_list);

		if (level == PT64_ROOT_LEVEL)
			kvm_unsync_page(vcpu, sp);
	}
	sp->mmu_valid_gen = vcpu->kvm->arch.mmu_valid_gen;
	clear_shadow_pt(vcpu, sp, validate);
	DebugSPF("allocated shadow page at %px, level %d, gfn 0x%llx, "
		"gva 0x%lx\n",
		 sp, sp->role.level, gfn, gaddr);
	trace_kvm_mmu_get_page(sp, true);

	kvm_mmu_flush_or_zap(vcpu, &invalid_list, false, flush);
	return sp;
}

void shadow_pt_walk_init(kvm_shadow_walk_iterator_t *iterator,
		struct kvm_vcpu *vcpu, hpa_t spt_root, u64 addr)
{
	iterator->addr = addr;
	iterator->shadow_addr = spt_root;
	iterator->level = vcpu->arch.mmu.shadow_root_level;
	iterator->pt_struct = kvm_get_host_pt_struct(vcpu->kvm);
	iterator->pt_level = &iterator->pt_struct->levels[iterator->level];

	if (iterator->level == PT64_ROOT_LEVEL &&
		vcpu->arch.mmu.root_level < PT64_ROOT_LEVEL &&
			!vcpu->arch.mmu.direct_map) {
		--iterator->level;
		--iterator->pt_level;
	}

	if (iterator->level == PT32E_ROOT_LEVEL) {
		iterator->shadow_addr
			= vcpu->arch.mmu.pae_root[(addr >> 30) & 3];
		iterator->shadow_addr &= kvm_get_spte_pfn_mask(vcpu->kvm);
		--iterator->level;
		--iterator->pt_level;
		if (!iterator->shadow_addr) {
			iterator->level = 0;
			iterator->pt_level = &iterator->pt_struct->levels[0];
		}
	}
}
void shadow_walk_init(kvm_shadow_walk_iterator_t *iterator,
			struct kvm_vcpu *vcpu, u64 addr)
{
	hpa_t spt_root = kvm_get_space_addr_root(vcpu, addr);

	shadow_pt_walk_init(iterator, vcpu, spt_root, addr);
}

bool shadow_walk_okay(kvm_shadow_walk_iterator_t *iterator)
{
	if (iterator->level < PT_PAGE_TABLE_LEVEL)
		return false;

	iterator->index = get_pt_level_addr_index(iterator->addr,
							iterator->pt_level);
	iterator->sptep	= ((pgprot_t *)__va(iterator->shadow_addr)) +
							iterator->index;
	return true;
}

void __shadow_walk_next(kvm_shadow_walk_iterator_t *iterator, pgprot_t spte)
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

void shadow_walk_next(struct kvm_shadow_walk_iterator *iterator)
{
	return __shadow_walk_next(iterator, *iterator->sptep);
}

static void link_shadow_page(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				pgprot_t *sptep, struct kvm_mmu_page *sp)
{
	struct kvm *kvm = vcpu->kvm;
	pgprot_t spte;

	pgprot_val(spte) = get_spte_pt_user_prot(kvm);
	spte = set_spte_pfn(kvm, spte, __pa(sp->spt) >> PAGE_SHIFT);

	mmu_spte_set(vcpu->kvm, sptep, spte);

	mmu_page_add_parent_pte(vcpu, sp, sptep);

	if (unlikely(!vcpu->arch.is_hv)) {
		kvm_try_add_sp_to_gmm_list(gmm, sp);
	}

	if (sp->unsync_children || sp->unsync)
		mark_unsync(kvm, sptep);
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

		drop_parent_pte(child, sptep);
		kvm_flush_remote_tlbs(vcpu->kvm);
	}
}

void copy_guest_kernel_root_range(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			struct kvm_mmu_page *sp, pgprot_t *src_root)
{
	int start, end, index;
	pgprot_t *dst_root = sp->spt;
	pgprot_t *sptep, spte;
	struct kvm_mmu_page *child;
	gmm_struct_t *init_gmm = pv_vcpu_get_init_gmm(vcpu);

	start = GUEST_KERNEL_PGD_PTRS_START;
	end = GUEST_KERNEL_PGD_PTRS_END;

	for (index = start; index < end; index++) {
		sptep = &dst_root[index];
		spte = src_root[index];
		if (!is_shadow_present_pte(vcpu->kvm, spte))
			continue;
		child = page_header(kvm_spte_pfn_to_phys_addr(vcpu->kvm, spte));
		KVM_BUG_ON(child == NULL);
		link_shadow_page(vcpu, init_gmm, sptep, child);
		DebugCPSPT("copied %px = 0x%lx from %px = 0x%lx index 0x%lx\n",
			sptep, pgprot_val(*sptep), &src_root[index],
			pgprot_val(spte), index * sizeof(pgprot_t));
	}
}

void mmu_zap_linked_children(struct kvm *kvm, struct kvm_mmu_page *parent)
{
	int start, end, index;
	pgprot_t *root_spt = parent->spt;
	pgprot_t *sptep, spte;
	struct kvm_mmu_page *child;
	struct kvm_rmap_head *parent_ptes;

	start = GUEST_KERNEL_PGD_PTRS_START;
	end = GUEST_KERNEL_PGD_PTRS_END;

	if (root_spt == (pgprot_t *)kvm_mmu_get_init_gmm_root(kvm)) {
		/* it is guest kernel root PT, so free unconditionally */
		return;
	}
	for (index = start; index < end; index++) {
		sptep = &root_spt[index];
		spte = *sptep;
		if (!is_shadow_present_pte(kvm, spte))
			continue;

		child = page_header(kvm_spte_pfn_to_phys_addr(kvm, spte));
		parent_ptes = &child->parent_ptes;
		if (!parent_ptes->val) {
			pr_err("%s(): index 0x%lx %px : nothing links\n",
				__func__, index * sizeof(pgprot_t), sptep);
			KVM_BUG_ON(true);
		} else if (!(parent_ptes->val & 1)) {
			DebugFRSPT("index 0x%lx %px : only one last link\n",
				index * sizeof(pgprot_t), sptep);
		} else {
			DebugFRSPT("index 0x%lx %px : many links\n",
				index * sizeof(pgprot_t), sptep);
			drop_parent_pte(child, sptep);
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
			DebugPTE("spte at %px == 0x%lx dropped\n",
				spte, pgprot_val(*spte));
			if (is_large_pte(pte))
				--kvm->stat.lpages;
			return NULL;
		} else {
			child = page_header(
					kvm_spte_pfn_to_phys_addr(kvm, pte));
			drop_parent_pte(child, spte);
			child->released = sp->released;
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
		drop_parent_pte(sp, sptep);
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

static void kvm_mmu_commit_zap_page(struct kvm *kvm,
				    struct list_head *invalid_list)
{
	struct kvm_mmu_page *sp, *nsp;

	if (list_empty(invalid_list))
		return;

	/*
	 * We need to make sure everyone sees our modifications to
	 * the page tables and see changes to vcpu->mode here. The barrier
	 * in the kvm_flush_remote_tlbs() achieves this. This pairs
	 * with vcpu_enter_guest and walk_shadow_page_lockless_begin/end.
	 *
	 * In addition, kvm_flush_remote_tlbs waits for all vcpus to exit
	 * guest mode and/or lockless shadow page table walks.
	 */
	kvm_flush_remote_tlbs(kvm);

	list_for_each_entry_safe(sp, nsp, invalid_list, link) {
		WARN_ON(!sp->role.invalid || sp->root_count);
		kvm_mmu_free_page(kvm, sp);
	}
}

static bool prepare_zap_oldest_mmu_page(struct kvm *kvm,
					struct list_head *invalid_list)
{
	struct kvm_mmu_page *sp;
	int zapped;

	if (list_empty(&kvm->arch.active_mmu_pages))
		return false;

	sp = list_last_entry(&kvm->arch.active_mmu_pages,
			     struct kvm_mmu_page, link);
	zapped = kvm_mmu_prepare_zap_page(kvm, sp, invalid_list);

	return (zapped > 0) ? true : false;
}

void kvm_get_spt_translation(struct kvm_vcpu *vcpu, e2k_addr_t address,
	pgdval_t *pgd, pudval_t *pud, pmdval_t *pmd, pteval_t *pte, int *pt_level)
{
	kvm_shadow_trans_t st;
	pgprot_t spte;
	int level, level_off;

	KVM_BUG_ON(address >= NATIVE_TASK_SIZE);

	spin_lock(&vcpu->kvm->mmu_lock);

	level_off = e2k_walk_shadow_pts(vcpu, address, &st, E2K_INVALID_PAGE);
	*pt_level = E2K_PGD_LEVEL_NUM + 1;

	for (level = E2K_PT_LEVELS_NUM; level > level_off; level--) {

		spte = st.pt_entries[level].spte;
		if (level == E2K_PGD_LEVEL_NUM) {
			*pgd = pgprot_val(spte);
			if (likely(!pgd_huge(__pgd(*pgd)) &&
					!pgd_none(__pgd(*pgd)) &&
						!pgd_bad(__pgd(*pgd)))) {
				continue;
			}
			*pt_level = E2K_PGD_LEVEL_NUM;
			break;
		}

		if (level == E2K_PUD_LEVEL_NUM) {
			*pud = pgprot_val(spte);
			if (likely(!pud_huge(__pud(*pud)) &&
					!pud_none(__pud(*pud)) &&
						!pud_bad(__pud(*pud)))) {
				continue;
			}
			*pt_level = E2K_PUD_LEVEL_NUM;
			break;
		}

		if (level == E2K_PMD_LEVEL_NUM) {
			*pmd = pgprot_val(spte);
			if (likely(!pmd_huge(__pmd(*pmd)) &&
					!pmd_none(__pmd(*pmd)) &&
						!pmd_bad(__pmd(*pmd)))) {
				continue;
			}
			*pt_level = E2K_PMD_LEVEL_NUM;
			break;
		}

		if (level == E2K_PTE_LEVEL_NUM) {
			*pte = pgprot_val(spte);
			*pt_level = E2K_PTE_LEVEL_NUM;
			break;
		}
	}
	spin_unlock(&vcpu->kvm->mmu_lock);
}

int kvm_get_va_spt_translation(struct kvm_vcpu *vcpu, e2k_addr_t address,
				mmu_spt_trans_t __user *user_trans_info)
{
	mmu_spt_trans_t trans_info;
	int ret;

	kvm_get_spt_translation(vcpu, address,
		&trans_info.pgd, &trans_info.pud, &trans_info.pmd,
		&trans_info.pte, &trans_info.pt_levels);

	ret = kvm_vcpu_copy_to_guest(vcpu, user_trans_info, &trans_info,
					sizeof(trans_info));
	if (unlikely(ret < 0)) {
		pr_err("%s(): could not copy info to user, error %d\n",
			__func__, ret);
		return ret;
	}
	return 0;
}

unsigned long kvm_get_gva_to_hva(struct kvm_vcpu *vcpu, gva_t gva)
{
	unsigned long hva;

	hva = kvm_vcpu_gva_to_hva(vcpu, gva, true, NULL);
	if (kvm_is_error_hva(hva)) {
		pr_err("%s(): failed to convert GVA 0x%lx to HVA\n",
			__func__, gva);
		hva = 0;
	}
	return hva;
}

/*
 * Changing the number of mmu pages allocated to the vm
 * Note: if goal_nr_mmu_pages is too small, you will get dead lock
 */
void kvm_mmu_change_mmu_pages(struct kvm *kvm, unsigned int goal_nr_mmu_pages)
{
	LIST_HEAD(invalid_list);

	spin_lock(&kvm->mmu_lock);

	if (kvm->arch.n_used_mmu_pages > goal_nr_mmu_pages) {
		/* Need to free some mmu pages to achieve the goal. */
		while (kvm->arch.n_used_mmu_pages > goal_nr_mmu_pages)
			if (!prepare_zap_oldest_mmu_page(kvm, &invalid_list))
				break;

		kvm_mmu_commit_zap_page(kvm, &invalid_list);
		goal_nr_mmu_pages = kvm->arch.n_used_mmu_pages;
	}

	kvm->arch.n_max_mmu_pages = goal_nr_mmu_pages;

	spin_unlock(&kvm->mmu_lock);
}

int kvm_mmu_unprotect_page(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_mmu_page *sp;
	LIST_HEAD(invalid_list);
	int r;

	pgprintk("%s: looking for gfn %llx\n", __func__, gfn);
	r = 0;
	spin_lock(&kvm->mmu_lock);
	for_each_gfn_indirect_valid_sp(kvm, sp, gfn) {
		pgprintk("%s: gfn %llx role %x\n", __func__, gfn,
			 sp->role.word);
		r = 1;
		kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list);
	}
	kvm_mmu_commit_zap_page(kvm, &invalid_list);
	spin_unlock(&kvm->mmu_lock);

	return r;
}
EXPORT_SYMBOL_GPL(kvm_mmu_unprotect_page);

static void kvm_unsync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp)
{
	trace_kvm_mmu_unsync_page(sp);
	++vcpu->kvm->stat.mmu_unsync;
	sp->unsync = 1;

	kvm_mmu_mark_parents_unsync(vcpu->kvm, sp);
}

static bool mmu_need_write_protect(struct kvm_vcpu *vcpu, gfn_t gfn,
				   bool can_unsync)
{
	struct kvm_mmu_page *sp;
	struct kvm_memory_slot *slot;

	slot = __gfn_to_memslot(kvm_memslots_for_spte_role(vcpu->kvm, 0),
				gfn);

	if (kvm_page_track_is_active(vcpu->kvm, slot, gfn,
				KVM_PAGE_TRACK_WRITE))
		return true;

	for_each_gfn_indirect_valid_sp(vcpu->kvm, sp, gfn) {
		if (!can_unsync)
			return true;

		if (sp->unsync)
			continue;

		WARN_ON(sp->role.level != PT_PAGE_TABLE_LEVEL);
		kvm_unsync_page(vcpu, sp);
	}

	return false;
}

static bool kvm_is_mmio_pfn(kvm_pfn_t pfn)
{
	if (pfn_valid(pfn))
		return !is_zero_pfn(pfn) && PageReserved(pfn_to_page(pfn));

	return true;
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

	if (pte_access & ACC_USER_MASK)
		spte = set_spte_user_mask(kvm, spte);
	else
		spte = set_spte_priv_mask(kvm, spte);

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
	if (mmu_spte_update(kvm, sptep, spte))
		kvm_flush_remote_tlbs(vcpu->kvm);
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

			pgprintk("hfn old is not large, new on level #%d\n",
				 level);
			child = page_header(kvm_spte_pfn_to_phys_addr(vcpu->kvm,
									pte));
			drop_parent_pte(child, sptep);
			kvm_flush_remote_tlbs(vcpu->kvm);
		} else if (pfn == KVM_PFN_NULL) {
			KVM_BUG_ON(true);
		} else if (pfn != spte_to_pfn(vcpu->kvm, *sptep)) {
			pgprintk("hfn old %llx new %llx\n",
				 spte_to_pfn(vcpu->kvm, *sptep), pfn);
			drop_spte(vcpu->kvm, sptep);
			kvm_flush_remote_tlbs(vcpu->kvm);
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

static kvm_pfn_t pte_prefetch_gfn_to_pfn(struct kvm_vcpu *vcpu, gfn_t gfn,
			struct kvm_memory_slot **slot, bool no_dirty_log)
{
	*slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	if (!*slot) {
		if (gfn_is_from_mmio_space(vcpu, gfn)) {
			return KVM_PFN_MMIO_FAULT;
		}
	}

	return gfn_to_pfn_memslot_atomic(*slot, gfn);
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

	if (!VALID_PAGE(kvm_get_gp_phys_root(vcpu)))
		return 0;

	if (unlikely(!vcpu->arch.is_hv)) {
		init_gmm = pv_vcpu_get_init_gmm(vcpu);
	}

	for_each_shadow_entry(vcpu, (u64)gfn << PAGE_SHIFT, iterator) {
		DebugNONP("iterator level %d spte %px == 0x%lx\n",
			iterator.level, iterator.sptep,
			pgprot_val(*iterator.sptep));
		if (iterator.level == level) {
			emulate = mmu_set_spte(vcpu, iterator.sptep, ACC_ALL,
					       write, level, gfn, pfn, prefault,
					       map_writable, false, 0);
			DebugNONP("set spte %px == 0x%lx\n",
				iterator.sptep, pgprot_val(*iterator.sptep));
			if (emulate == PFRES_TRY_MMIO)
				break;
			direct_pte_prefetch(vcpu, iterator.sptep);
			++vcpu->stat.pf_fixed;
			break;
		}

		drop_large_spte(vcpu, iterator.sptep);
		if (!is_shadow_present_pte(vcpu->kvm, *iterator.sptep)) {
			u64 base_addr = iterator.addr;

			base_addr &= get_pt_level_mask(iterator.pt_level);
			pseudo_gfn = base_addr >> PAGE_SHIFT;
			sp = kvm_mmu_get_page(vcpu, pseudo_gfn, iterator.addr,
					      iterator.level - 1, 1, ACC_ALL,
					      false /* validate */);

			link_shadow_page(vcpu, init_gmm, iterator.sptep, sp);
			DebugNONP("allocated PTD to nonpaging level %d, pseudo "
				"gfn 0x%llx SPTE %px == 0x%lx\n",
				iterator.level - 1, pseudo_gfn,
				iterator.sptep, pgprot_val(*iterator.sptep));
		}
	}
	return emulate;
}

pgprot_t nonpaging_gpa_to_pte(struct kvm_vcpu *vcpu, gva_t addr)
{
	kvm_shadow_walk_iterator_t iterator;
	pgprot_t spte = {0ull};
	gpa_t gpa;

	DebugNONP("started for GVA 0x%lx\n", addr);

	gpa = nonpaging_gva_to_gpa(vcpu, addr, ACC_ALL, NULL);

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

static void kvm_send_hwpoison_signal(unsigned long address,
					struct task_struct *task)
{
	kernel_siginfo_t info;

	info.si_signo	= SIGBUS;
	info.si_errno	= 0;
	info.si_code	= BUS_MCEERR_AR;
	info.si_addr	= (void __user *)address;
	info.si_addr_lsb = PAGE_SHIFT;

	send_sig_info(SIGBUS, &info, task);
}

static int kvm_handle_bad_page(struct kvm_vcpu *vcpu, gfn_t gfn, kvm_pfn_t pfn)
{
	/*
	 * Do not cache the mmio info caused by writing the readonly gfn
	 * into the spte otherwise read access on readonly gfn also can
	 * caused mmio page fault and treat it as mmio access.
	 * Return 1 to tell kvm to emulate it.
	 */
	if (pfn == KVM_PFN_ERR_RO_FAULT)
		return 1;

	if (pfn == KVM_PFN_ERR_HWPOISON) {
		kvm_send_hwpoison_signal(kvm_vcpu_gfn_to_hva(vcpu, gfn),
						current);
		return 0;
	}

	if (pfn == KVM_PFN_MMIO_FAULT)
		return 1;

	return -EFAULT;
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
		mask = KVM_MMU_PAGES_PER_HPAGE(vcpu->kvm, level) - 1;
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

static bool handle_abnormal_pfn(struct kvm_vcpu *vcpu, gva_t gva, gfn_t gfn,
				kvm_pfn_t pfn, unsigned access,
				pf_res_t *ret_val)
{
	int ret;

	if (is_mmio_space_pfn(pfn)) {
		/* gfn is from MMIO space, but is not registered on host */
		*ret_val = PFRES_TRY_MMIO;
		return false;
	}

	/* The pfn is invalid, report the error! */
	if (unlikely(is_error_pfn(pfn))) {
		ret = kvm_handle_bad_page(vcpu, gfn, pfn);
		if (ret) {
			*ret_val = PFRES_ERR;
		} else {
			*ret_val = PFRES_NO_ERR;
		}
		return true;
	}

	if (unlikely(is_noslot_pfn(pfn))) {
		vcpu_cache_mmio_info(vcpu, gva, gfn, access);
		*ret_val = PFRES_TRY_MMIO;
	} else {
		*ret_val = PFRES_NO_ERR;
	}

	return false;
}

static bool page_fault_can_be_fast(u32 error_code)
{
	/*
	 * Do not fix the mmio spte with invalid generation number which
	 * need to be updated by slow page fault path.
	 */
	if (unlikely(error_code & PFERR_RSVD_MASK))
		return false;

	/*
	 * #PF can be fast only if the shadow page table is present and it
	 * is caused by write-protect, that means we just need change the
	 * W bit of the spte which can be done out of mmu-lock.
	 */
	return (error_code & PFERR_PRESENT_MASK) && (error_code & PFERR_WRITE_MASK);
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

static bool try_async_pf(struct kvm_vcpu *vcpu, bool prefault, gfn_t gfn,
			 gva_t gva, kvm_pfn_t *pfn, bool write, bool *writable);
static void make_mmu_pages_available(struct kvm_vcpu *vcpu);

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

		gfn &= ~(KVM_MMU_PAGES_PER_HPAGE(vcpu->kvm, level) - 1);
	}
	DebugNONP("mapping level %d force %d gfn 0x%llx\n",
		level, force_pt_level, gfn);

	if (fast_page_fault(vcpu, v, level, error_code))
		return 0;

	DebugNONP("there is slow page fault case\n");

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
	if (!mu_state->ignore_notifier && r != PFRES_TRY_MMIO &&
			mmu_notifier_retry(vcpu->kvm, mu_state->notifier_seq))
		goto out_unlock;
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */
	make_mmu_pages_available(vcpu);
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
	KVM_BUG_ON(!mu_state->may_be_retried);
	return PFRES_RETRY;
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */
}

/*static*/ e2k_addr_t get_vcpu_secondary_pptb(struct kvm_vcpu *vcpu)
{
	pr_err("FIXME: %s() is not implemented\n", __func__);
	return get_vcpu_u2_pptb(vcpu);
}

/*static*/ void set_vcpu_secondary_pptb(struct kvm_vcpu *vcpu, e2k_addr_t base)
{
	pr_err("FIXME: %s() is not implemented\n", __func__);
	set_vcpu_u2_pptb(vcpu, base);
}

/*static*/ e2k_addr_t get_vcpu_secondary_mpt_b(struct kvm_vcpu *vcpu)
{
	pr_err("FIXME: %s() is not implemented\n", __func__);
	return get_vcpu_mpt_b(vcpu);
}

/*static*/ void set_vcpu_secondary_mpt_b(struct kvm_vcpu *vcpu, e2k_addr_t base)
{
	pr_err("FIXME: %s() is not implemented\n", __func__);
	set_vcpu_mpt_b(vcpu, base);
}

/*
 * Need support:
 *	- hardware virtualization;
 *	- paravirtualization;
 *	- non paging (nonp);
 *	- two dimensional paging (tdp);
 *	- shadow paging	for
 *		hardware virtualizatio (spt_hv);
 *		paravirtualization (spt_pv);
 *
 * MMU structure of VCPU contains software copies of hardware registers
 * to support first of all paravirtualization and nonpaging mode.
 * Nonpaging with hardware virtulization can be based on hardware registers,
 * but use software model for compatibility with paravirtualization. Besides
 * registers should not be used by hardware until paging on guest is off.
 *
 * TDP mode can be only with hardware virtualization extensions and should
 * use hardware registers and software part of guest context
 *
 * Shadow paging use software model or hardware registers depending on the type
 * of virtualization - para or full.
 * Besides shadow paging should replace some registers to enable guest
 * addresses translations, so need have both shadow and source guest values.
 */

static void set_vcpu_nonp_u_pptb(struct kvm_vcpu *vcpu, pgprotval_t base)
{
	vcpu->arch.mmu.u_pptb = base;
}
static void set_vcpu_nonp_sh_u_pptb(struct kvm_vcpu *vcpu, hpa_t root)
{
	KVM_BUG_ON(is_phys_paging(vcpu));
	vcpu->arch.mmu.sh_u_root_hpa = root;
}
static void set_vcpu_nonp_u_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	vcpu->arch.mmu.u_vptb = base;
}
static void set_vcpu_nonp_sh_u_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	KVM_BUG_ON(is_phys_paging(vcpu));
	vcpu->arch.mmu.sh_u_vptb = base;
}
static void set_vcpu_nonp_os_pptb(struct kvm_vcpu *vcpu, pgprotval_t base)
{
	vcpu->arch.mmu.os_pptb = base;
}
static void set_vcpu_nonp_sh_os_pptb(struct kvm_vcpu *vcpu, hpa_t root)
{
	KVM_BUG_ON(is_phys_paging(vcpu));
	vcpu->arch.mmu.sh_os_root_hpa = root;
}
static void set_vcpu_nonp_os_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	vcpu->arch.mmu.os_vptb = base;
}
static void set_vcpu_nonp_sh_os_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	KVM_BUG_ON(is_phys_paging(vcpu));
	vcpu->arch.mmu.sh_os_vptb = base;
}
static void set_vcpu_nonp_os_vab(struct kvm_vcpu *vcpu, gva_t os_virt_base)
{
	KVM_BUG_ON(!is_sep_virt_spaces(vcpu));
	vcpu->arch.mmu.sh_os_vab = os_virt_base;
}
static void set_vcpu_nonp_gp_pptb(struct kvm_vcpu *vcpu, hpa_t root)
{
	KVM_BUG_ON(vcpu->arch.is_hv && !kvm_is_phys_pt_enable(vcpu->kvm));
	vcpu->arch.mmu.gp_root_hpa = root;
}
static void set_vcpu_nonp_pt_context(struct kvm_vcpu *vcpu, unsigned flags)
{
	if (likely((flags & GP_ROOT_PT_FLAG) && is_phys_paging(vcpu))) {
		KVM_BUG_ON(!VALID_PAGE(vcpu->arch.mmu.gp_root_hpa));
		write_GP_PPTB_reg(vcpu->arch.mmu.gp_root_hpa);
	} else if (is_shadow_paging(vcpu)) {
		if ((flags & U_ROOT_PT_FLAG) ||
				((flags & OS_ROOT_PT_FLAG) &&
					!is_sep_virt_spaces(vcpu))) {
			KVM_BUG_ON(!VALID_PAGE(vcpu->arch.mmu.sh_u_root_hpa));
			vcpu->arch.sw_ctxt.sh_u_pptb =
				vcpu->arch.mmu.sh_u_root_hpa;
			vcpu->arch.sw_ctxt.sh_u_vptb =
				vcpu->arch.mmu.sh_u_vptb;
		}
		if ((flags & OS_ROOT_PT_FLAG) && is_sep_virt_spaces(vcpu)) {
			KVM_BUG_ON(!VALID_PAGE(vcpu->arch.mmu.sh_os_root_hpa));
			write_SH_OS_PPTB_reg(vcpu->arch.mmu.sh_os_root_hpa);
			write_SH_OS_VPTB_reg(vcpu->arch.mmu.sh_os_vptb);
			write_SH_OS_VAB_reg(vcpu->arch.mmu.sh_os_vab);
		}
	} else {
		KVM_BUG_ON(true);
	}
}
static void init_vcpu_nonp_ptb(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.u_pptb = 0;
	vcpu->arch.mmu.sh_u_root_hpa = E2K_INVALID_PAGE;
	vcpu->arch.mmu.u_vptb = 0;
	vcpu->arch.mmu.sh_u_vptb = 0;
	vcpu->arch.mmu.os_pptb = 0;
	vcpu->arch.mmu.sh_os_root_hpa = E2K_INVALID_PAGE;
	vcpu->arch.mmu.os_vptb = 0;
	vcpu->arch.mmu.sh_os_vptb = 0;
	vcpu->arch.mmu.sh_os_vab = 0;
	vcpu->arch.mmu.gp_root_hpa = E2K_INVALID_PAGE;
}

static pgprotval_t get_vcpu_nonp_u_pptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.u_pptb;
}
static hpa_t get_vcpu_nonp_sh_u_pptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.sh_u_root_hpa;
}
static gva_t get_vcpu_nonp_u_vptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.u_vptb;
}
static gva_t get_vcpu_nonp_sh_u_vptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.sh_u_vptb;
}
static pgprotval_t get_vcpu_nonp_os_pptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.os_pptb;
}
static hpa_t get_vcpu_nonp_sh_os_pptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.sh_os_root_hpa;
}
static gva_t get_vcpu_nonp_os_vptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.os_vptb;
}
static gva_t get_vcpu_nonp_sh_os_vptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.sh_os_vptb;
}
static gva_t get_vcpu_nonp_os_vab(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.sh_os_vab;
}
static hpa_t get_vcpu_nonp_gp_pptb(struct kvm_vcpu *vcpu)
{
	KVM_BUG_ON(vcpu->arch.is_hv && !kvm_is_phys_pt_enable(vcpu->kvm));
	return vcpu->arch.mmu.gp_root_hpa;
}

static pgprotval_t get_vcpu_context_nonp_u_pptb(struct kvm_vcpu *vcpu)
{
	return (pgprotval_t)vcpu->arch.sw_ctxt.sh_u_pptb;
}
static gva_t get_vcpu_context_nonp_u_vptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.sw_ctxt.sh_u_vptb;
}
static pgprotval_t get_vcpu_context_nonp_os_pptb(struct kvm_vcpu *vcpu)
{
	return (pgprotval_t)read_SH_OS_PPTB_reg();
}
static gva_t get_vcpu_context_nonp_os_vptb(struct kvm_vcpu *vcpu)
{
	return read_SH_OS_VPTB_reg();
}
static gva_t get_vcpu_context_nonp_os_vab(struct kvm_vcpu *vcpu)
{
	return read_SH_OS_VAB_reg();
}
static hpa_t get_vcpu_context_nonp_gp_pptb(struct kvm_vcpu *vcpu)
{
	KVM_BUG_ON(vcpu->arch.is_hv && !kvm_is_phys_pt_enable(vcpu->kvm));
	return read_GP_PPTB_reg();
}

static void set_vcpu_tdp_u_pptb(struct kvm_vcpu *vcpu, pgprotval_t base)
{
	/* Guest can and must set, host should not change it */
	KVM_BUG_ON(!vcpu->arch.is_pv);
	vcpu->arch.mmu.u_pptb = base;
}
static void set_vcpu_tdp_sh_u_pptb(struct kvm_vcpu *vcpu, hpa_t root)
{
	/* shadow PTs are not used */
	KVM_BUG_ON(true);
}
static void set_vcpu_tdp_u_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	/* Guest can and must set, host should not change it */
	KVM_BUG_ON(!vcpu->arch.is_pv);
	vcpu->arch.mmu.u_vptb = base;
}
static void set_vcpu_tdp_sh_u_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	/* shadow PTs are not used, so same as guest native PTs */
	KVM_BUG_ON(true);
}
static void set_vcpu_tdp_os_pptb(struct kvm_vcpu *vcpu, pgprotval_t base)
{
	/* Guest can and must set, host should not change it */
	KVM_BUG_ON(!vcpu->arch.is_pv);
	vcpu->arch.mmu.os_pptb = base;
}
static void set_vcpu_tdp_sh_os_pptb(struct kvm_vcpu *vcpu, hpa_t root)
{
	/* shadow PTs are not used, so same as guest native PTs */
	KVM_BUG_ON(true);
}
static void set_vcpu_tdp_os_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	/* Guest can and must set, host should not change it */
	KVM_BUG_ON(!vcpu->arch.is_pv);
	vcpu->arch.mmu.os_vptb = base;
}
static void set_vcpu_tdp_sh_os_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	/* shadow PTs are not used, so same as guest native PTs */
	KVM_BUG_ON(true);
}
static void set_vcpu_tdp_os_vab(struct kvm_vcpu *vcpu, gva_t os_virt_base)
{
	/* Guest can and must set, host should not change it */
	KVM_BUG_ON(!vcpu->arch.is_pv);
	vcpu->arch.mmu.sh_os_vab = os_virt_base;
}
static void set_vcpu_tdp_gp_pptb(struct kvm_vcpu *vcpu, hpa_t root)
{
	/* initial PT (from nonpaging mode) is continuing to be used */
	KVM_BUG_ON(VALID_PAGE(root));
	vcpu->arch.mmu.gp_root_hpa = root;
}
static void set_vcpu_tdp_pt_context(struct kvm_vcpu *vcpu, unsigned flags)
{
	KVM_BUG_ON(!is_phys_paging(vcpu));
	if ((flags & GP_ROOT_PT_FLAG) && likely(is_phys_paging(vcpu))) {
		if (VALID_PAGE(vcpu->arch.mmu.gp_root_hpa)) {
			/* GP_* tables should not changed from nonpaging mode */
			KVM_BUG_ON(read_GP_PPTB_reg() !=
						vcpu->arch.mmu.gp_root_hpa);
		} else {
			/* invalidate GP_* tables register state */
			write_GP_PPTB_reg(vcpu->arch.mmu.gp_root_hpa);
		}
	}
	if (vcpu->arch.is_pv) {
		/* paravirtualized guest can pass own PTs through hcalls */
		if ((flags & U_ROOT_PT_FLAG) ||
				((flags & OS_ROOT_PT_FLAG) &&
					!is_sep_virt_spaces(vcpu))) {
			vcpu->arch.sw_ctxt.sh_u_pptb = vcpu->arch.mmu.u_pptb;
			vcpu->arch.sw_ctxt.sh_u_vptb = vcpu->arch.mmu.u_vptb;
		}
		if ((flags & OS_ROOT_PT_FLAG) && is_sep_virt_spaces(vcpu)) {
			write_SH_OS_PPTB_reg(vcpu->arch.mmu.os_pptb);
			write_SH_OS_VPTB_reg(vcpu->arch.mmu.os_vptb);
			write_SH_OS_VAB_reg(vcpu->arch.mmu.sh_os_vab);
		}
	}
}
static void init_vcpu_tdp_ptb(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.u_pptb = 0;
	vcpu->arch.mmu.sh_u_root_hpa = E2K_INVALID_PAGE;
	vcpu->arch.mmu.u_vptb = 0;
	vcpu->arch.mmu.sh_u_vptb = 0;
	vcpu->arch.mmu.os_pptb = 0;
	vcpu->arch.mmu.sh_os_root_hpa = E2K_INVALID_PAGE;
	vcpu->arch.mmu.os_vptb = 0;
	vcpu->arch.mmu.sh_os_vptb = 0;
	vcpu->arch.mmu.sh_os_vab = 0;
	/* GP_* tables should not changed from nonpaging mode
	vcpu->arch.mmu.gp_root_hpa = E2K_INVALID_PAGE;
	 */
}

static pgprotval_t get_vcpu_tdp_u_pptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.u_pptb;
}
static hpa_t get_vcpu_tdp_sh_u_pptb(struct kvm_vcpu *vcpu)
{
	/* shadow PT does not be used */
	KVM_BUG_ON(true);
	return (hpa_t)-EINVAL;
}
static gva_t get_vcpu_tdp_u_vptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.u_vptb;
}
static gva_t get_vcpu_tdp_sh_u_vptb(struct kvm_vcpu *vcpu)
{
	/* shadow PT does not be used */
	KVM_BUG_ON(true);
	return (gva_t)-EINVAL;
}
static pgprotval_t get_vcpu_tdp_os_pptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.os_pptb;
}
static hpa_t get_vcpu_tdp_sh_os_pptb(struct kvm_vcpu *vcpu)
{
	/* shadow PT does not be used */
	KVM_BUG_ON(true);
	return (hpa_t)-EINVAL;
}
static gva_t get_vcpu_tdp_os_vptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.os_vptb;
}
static gva_t get_vcpu_tdp_sh_os_vptb(struct kvm_vcpu *vcpu)
{
	/* shadow PT does not be used */
	KVM_BUG_ON(true);
	return (gva_t)-EINVAL;
}
static gva_t get_vcpu_tdp_os_vab(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.sh_os_vab;
}
static hpa_t get_vcpu_tdp_gp_pptb(struct kvm_vcpu *vcpu)
{
	/* current guest root should be on hardware hypervisor register */
	return vcpu->arch.mmu.gp_root_hpa;
}

static pgprotval_t get_vcpu_context_tdp_u_pptb(struct kvm_vcpu *vcpu)
{
	return (pgprotval_t)vcpu->arch.sw_ctxt.sh_u_pptb;
}
static gva_t get_vcpu_context_tdp_u_vptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.sw_ctxt.sh_u_vptb;
}
static pgprotval_t get_vcpu_context_tdp_os_pptb(struct kvm_vcpu *vcpu)
{
	return (pgprotval_t)read_SH_OS_PPTB_reg();
}
static gva_t get_vcpu_context_tdp_os_vptb(struct kvm_vcpu *vcpu)
{
	return read_SH_OS_VPTB_reg();
}
static gva_t get_vcpu_context_tdp_os_vab(struct kvm_vcpu *vcpu)
{
	return read_SH_OS_VAB_reg();
}
static hpa_t get_vcpu_context_tdp_gp_pptb(struct kvm_vcpu *vcpu)
{
	KVM_BUG_ON(!is_phys_paging(vcpu));
	if (!VALID_PAGE(get_vcpu_tdp_gp_pptb(vcpu))) {
		return E2K_INVALID_PAGE;
	}
	return read_GP_PPTB_reg();
}

static void set_vcpu_spt_u_pptb(struct kvm_vcpu *vcpu, pgprotval_t base)
{
	vcpu->arch.mmu.u_pptb = base;
}
static void set_vcpu_spt_sh_u_pptb(struct kvm_vcpu *vcpu, hpa_t root)
{
	/* hypervisor replaces the guest value with its own */
	vcpu->arch.mmu.sh_u_root_hpa = root;
}
static void set_vcpu_spt_u_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	vcpu->arch.mmu.u_vptb = base;
}
static void set_vcpu_spt_sh_u_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	/* hypervisor replaces the guest value with its own */
	vcpu->arch.mmu.sh_u_vptb = base;
}
static void set_vcpu_spt_os_pptb(struct kvm_vcpu *vcpu, pgprotval_t base)
{
	vcpu->arch.mmu.os_pptb = base;
}
static void set_vcpu_spt_sh_os_pptb(struct kvm_vcpu *vcpu, hpa_t root)
{
	/* hypervisor replaces the guest value with its own */
	vcpu->arch.mmu.sh_os_root_hpa = root;
}
static void set_vcpu_spt_os_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	vcpu->arch.mmu.os_vptb = base;
}
static void set_vcpu_spt_sh_os_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	/* hypervisor replaces the guest value with its own */
	vcpu->arch.mmu.sh_os_vptb = base;
}
static void set_vcpu_spt_os_vab(struct kvm_vcpu *vcpu, gva_t base)
{
	vcpu->arch.mmu.sh_os_vab = base;
}
static void set_vcpu_spt_gp_pptb(struct kvm_vcpu *vcpu, hpa_t root)
{
	/* initial PT (from nonpaging mode) is continuing to be used */
	KVM_BUG_ON(VALID_PAGE(root));
	vcpu->arch.mmu.gp_root_hpa = root;
}
static void set_vcpu_spt_pt_context(struct kvm_vcpu *vcpu, unsigned flags)
{
	if ((flags & U_ROOT_PT_FLAG) ||
			((flags & OS_ROOT_PT_FLAG) &&
					!is_sep_virt_spaces(vcpu))) {
		KVM_BUG_ON(!VALID_PAGE(vcpu->arch.mmu.sh_u_root_hpa));
		vcpu->arch.sw_ctxt.sh_u_pptb = vcpu->arch.mmu.sh_u_root_hpa;
		vcpu->arch.sw_ctxt.sh_u_vptb = vcpu->arch.mmu.sh_u_vptb;
	}
	if ((flags & OS_ROOT_PT_FLAG) && is_sep_virt_spaces(vcpu)) {
		KVM_BUG_ON(!VALID_PAGE(vcpu->arch.mmu.sh_os_root_hpa));
		write_SH_OS_PPTB_reg(vcpu->arch.mmu.sh_os_root_hpa);
		write_SH_OS_VPTB_reg(vcpu->arch.mmu.sh_os_vptb);
		write_SH_OS_VAB_reg(vcpu->arch.mmu.sh_os_vab);
	}
	if ((flags & GP_ROOT_PT_FLAG) && likely(is_phys_paging(vcpu))) {
		/* GP_* tables should not changed from nonpaging mode */
		KVM_BUG_ON(read_GP_PPTB_reg() != vcpu->arch.mmu.gp_root_hpa);
	}
}
static void init_vcpu_spt_ptb(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.u_pptb = 0;
	vcpu->arch.mmu.sh_u_root_hpa = E2K_INVALID_PAGE;
	vcpu->arch.mmu.u_vptb = 0;
	vcpu->arch.mmu.sh_u_vptb = 0;
	vcpu->arch.mmu.os_pptb = 0;
	vcpu->arch.mmu.sh_os_root_hpa = E2K_INVALID_PAGE;
	vcpu->arch.mmu.os_vptb = 0;
	vcpu->arch.mmu.sh_os_vptb = 0;
	vcpu->arch.mmu.sh_os_vab = 0;
	/* GP_* tables should not changed from nonpaging mode
	vcpu->arch.mmu.gp_root_hpa = E2K_INVALID_PAGE;
	 */
}

static pgprotval_t get_vcpu_spt_u_pptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.u_pptb;
}
static hpa_t get_vcpu_spt_sh_u_pptb(struct kvm_vcpu *vcpu)
{
	/* hypervisor replaces the guest value with its own */
	return vcpu->arch.mmu.sh_u_root_hpa;
}
static gva_t get_vcpu_spt_u_vptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.u_vptb;
}
static gva_t get_vcpu_spt_sh_u_vptb(struct kvm_vcpu *vcpu)
{
	/* hypervisor replaces the guest value with its own */
	return vcpu->arch.mmu.sh_u_vptb;
}
static pgprotval_t get_vcpu_spt_os_pptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.os_pptb;
}
static hpa_t get_vcpu_spt_sh_os_pptb(struct kvm_vcpu *vcpu)
{
	/* hypervisor replaces the guest value with its own */
	return vcpu->arch.mmu.sh_os_root_hpa;
}
static gva_t get_vcpu_spt_os_vptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.os_vptb;
}
static gva_t get_vcpu_spt_sh_os_vptb(struct kvm_vcpu *vcpu)
{
	/* hypervisor replaces the guest value with its own */
	return vcpu->arch.mmu.sh_os_vptb;
}
static gva_t get_vcpu_spt_os_vab(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.sh_os_vab;
}
static hpa_t get_vcpu_spt_gp_pptb(struct kvm_vcpu *vcpu)
{
	if (is_phys_paging(vcpu)) {
		return read_GP_PPTB_reg();
	} else {
		return vcpu->arch.mmu.gp_root_hpa;
	}
}

static pgprotval_t get_vcpu_context_spt_u_pptb(struct kvm_vcpu *vcpu)
{
	/* hypervisor replaces the guest value with its own */
	return (pgprotval_t)vcpu->arch.sw_ctxt.sh_u_pptb;
}
static gva_t get_vcpu_context_spt_u_vptb(struct kvm_vcpu *vcpu)
{
	/* hypervisor replaces the guest value with its own */
	return vcpu->arch.sw_ctxt.sh_u_vptb;
}
static pgprotval_t get_vcpu_context_spt_os_pptb(struct kvm_vcpu *vcpu)
{
	/* hypervisor replaces the guest value with its own */
	return (pgprotval_t)read_SH_OS_PPTB_reg();
}
static gva_t get_vcpu_context_spt_os_vptb(struct kvm_vcpu *vcpu)
{
	/* hypervisor replaces the guest value with its own */
	return read_SH_OS_VPTB_reg();
}
static gva_t get_vcpu_context_spt_os_vab(struct kvm_vcpu *vcpu)
{
	return read_SH_OS_VAB_reg();
}
static hpa_t get_vcpu_context_spt_gp_pptb(struct kvm_vcpu *vcpu)
{
	KVM_BUG_ON(!is_phys_paging(vcpu) && vcpu->arch.is_hv);
	return read_GP_PPTB_reg();
}

void mmu_get_spt_roots(struct kvm_vcpu *vcpu, unsigned flags,
		hpa_t *os_root_p, hpa_t *u_root_p, hpa_t *gp_root_p)
{
	hpa_t os_root, u_root, gp_root;

	if (flags & OS_ROOT_PT_FLAG) {
		if (is_sep_virt_spaces(vcpu)) {
			os_root = kvm_get_space_type_spt_os_root(vcpu);
		} else {
			os_root = kvm_get_space_type_spt_u_root(vcpu);
		}
		if (flags & U_ROOT_PT_FLAG) {
			if (!is_sep_virt_spaces(vcpu)) {
				/* common OS & USER root */
				u_root = os_root;
			} else {
				u_root = kvm_get_space_type_spt_u_root(vcpu);
			}
		} else {
			u_root = E2K_INVALID_PAGE;
		}
	} else if (!(flags & U_ROOT_PT_FLAG)) {
		os_root = E2K_INVALID_PAGE;
		u_root = E2K_INVALID_PAGE;
	} else {
		os_root = E2K_INVALID_PAGE;
		u_root = kvm_get_space_type_spt_u_root(vcpu);
	}
	if (flags & GP_ROOT_PT_FLAG) {
		gp_root = kvm_get_gp_phys_root(vcpu);
	} else {
		gp_root = E2K_INVALID_PAGE;
	}
	if (os_root_p != NULL)
		*os_root_p = os_root;
	if (u_root_p != NULL)
		*u_root_p = u_root;
	if (gp_root_p != NULL)
		*gp_root_p = gp_root;
}

void mmu_check_invalid_roots(struct kvm_vcpu *vcpu, bool invalid,
					unsigned flags)
{
	if (is_tdp_paging(vcpu) || !is_paging(vcpu) && is_phys_paging(vcpu)) {
		hpa_t gp_root;

		gp_root = kvm_get_gp_phys_root(vcpu);
		if (invalid) {
			WARN_ON(VALID_PAGE(gp_root));
		} else {
			WARN_ON(!VALID_PAGE(gp_root));
		}
	}
	if (is_shadow_paging(vcpu)) {
		hpa_t os_root, u_root;

		mmu_get_spt_roots(vcpu, flags, &os_root, &u_root, NULL);
		if (invalid) {
			WARN_ON(VALID_PAGE(os_root));
			WARN_ON(VALID_PAGE(u_root));
		} else {
			if (flags & U_ROOT_PT_FLAG) {
				WARN_ON(!VALID_PAGE(u_root));
			}
			if (flags & OS_ROOT_PT_FLAG) {
				WARN_ON(!VALID_PAGE(os_root));
			}
		}
	}
}

static void do_free_spt_root(struct kvm_vcpu *vcpu, hpa_t root_hpa, bool force)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_mmu_page *sp;
	LIST_HEAD(invalid_list);

	DebugFREE("started to free root hpa 0x%llx\n", root_hpa);
	if (!VALID_PAGE(root_hpa)) {
		MMU_WARN_ON(true);
		return;
	}

	spin_lock(&kvm->mmu_lock);
	sp = page_header(root_hpa);
	if (!force) {
		KVM_BUG_ON(sp->root_count <= 0);
	} else {
		/* FIXME: root counter should be zero to release sp. */
		/* It need implement strict mechanism get()/put() */
		/* to account the current users of the structure */
		--sp->root_count;
		KVM_BUG_ON(sp->root_count != 0);
		sp->released = true;
	}
	DebugFREE("freed root 0x%llx, SP at %px, count %d (invalid %d), "
		"gfn 0x%llx\n",
		root_hpa, sp, sp->root_count, sp->role.invalid, sp->gfn);
	if (!sp->root_count && sp->role.invalid || force) {
		int zapped = kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list);
		DebugFREE("zapped %d pages\n", zapped);
		kvm_mmu_commit_zap_page(kvm, &invalid_list);
	}
	spin_unlock(&kvm->mmu_lock);
}

void mmu_free_spt_root(struct kvm_vcpu *vcpu, hpa_t root_hpa)
{
	do_free_spt_root(vcpu, root_hpa, false);
}

void mmu_release_spt_root(struct kvm_vcpu *vcpu, hpa_t root_hpa)
{
	do_free_spt_root(vcpu, root_hpa, true);
}

static void e2k_mmu_free_roots(struct kvm_vcpu *vcpu, unsigned flags)
{
	hpa_t gp_root, os_root, u_root;

	KVM_BUG_ON(!(vcpu->arch.mmu.shadow_root_level == PT64_ROOT_LEVEL &&
			(vcpu->arch.mmu.root_level == PT64_ROOT_LEVEL ||
				vcpu->arch.mmu.direct_map)));

	if (vcpu->arch.mmu.direct_map) {
		if (is_phys_paging(vcpu) || flags & GP_ROOT_PT_FLAG) {
			if (!(flags & GP_ROOT_PT_FLAG))
				return;
			gp_root = kvm_get_gp_phys_root(vcpu);
			if (!VALID_PAGE(gp_root))
				return;
			mmu_free_spt_root(vcpu, gp_root);
			kvm_set_gp_phys_root(vcpu, E2K_INVALID_PAGE);
		}
		if (is_shadow_paging(vcpu)) {
			kvm_set_space_type_spt_u_root(vcpu, E2K_INVALID_PAGE);
			kvm_set_space_type_spt_os_root(vcpu, E2K_INVALID_PAGE);
		}
		/* invalidate context registers
		kvm_set_vcpu_pt_context(vcpu);
		*/
		return;
	}

	if (!(flags & (OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG)))
		return;

	mmu_get_spt_roots(vcpu, flags, &os_root, &u_root, NULL);
	if (!VALID_PAGE(os_root) && !VALID_PAGE(u_root))
		return;

	if (VALID_PAGE(u_root) &&
			((flags & U_ROOT_PT_FLAG) ||
				((flags & OS_ROOT_PT_FLAG) &&
						!is_sep_virt_spaces(vcpu)))) {
		mmu_free_spt_root(vcpu, u_root);
		kvm_set_space_type_spt_u_root(vcpu, E2K_INVALID_PAGE);
	}
	if (VALID_PAGE(os_root) && (flags & OS_ROOT_PT_FLAG)) {
		mmu_free_spt_root(vcpu, os_root);
		kvm_set_space_type_spt_os_root(vcpu, E2K_INVALID_PAGE);
	}
}

static void mmu_free_roots(struct kvm_vcpu *vcpu, unsigned flags)
{
	int i;
	struct kvm_mmu_page *sp;
	LIST_HEAD(invalid_list);

	if (vcpu->arch.mmu.shadow_root_level == PT64_ROOT_LEVEL &&
			(vcpu->arch.mmu.root_level == PT64_ROOT_LEVEL ||
				vcpu->arch.mmu.direct_map)) {
		e2k_mmu_free_roots(vcpu, flags);
		return;
	}

	spin_lock(&vcpu->kvm->mmu_lock);
	for (i = 0; i < 4; ++i) {
		hpa_t root = vcpu->arch.mmu.pae_root[i];

		if (root) {
			root &= kvm_get_spte_pfn_mask(vcpu->kvm);
			sp = page_header(root);
			--sp->root_count;
			if (!sp->root_count && sp->role.invalid)
				kvm_mmu_prepare_zap_page(vcpu->kvm, sp,
							 &invalid_list);
		}
		vcpu->arch.mmu.pae_root[i] = E2K_INVALID_PAGE;
	}
	kvm_mmu_commit_zap_page(vcpu->kvm, &invalid_list);
	spin_unlock(&vcpu->kvm->mmu_lock);
/*	kvm_set_space_type_root_hpa(vcpu, E2K_INVALID_PAGE, u_root); */
}

static int mmu_check_root(struct kvm_vcpu *vcpu, gfn_t root_gfn)
{
	int ret = 0;

	if (!kvm_is_visible_gfn(vcpu->kvm, root_gfn)) {
		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		ret = 1;
	}

	return ret;
}

static int mmu_alloc_direct_roots(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu_page *sp;
	unsigned i;

	DebugKVM("started on VCPU #%d\n", vcpu->vcpu_id);
	if (vcpu->arch.mmu.shadow_root_level == PT64_ROOT_LEVEL) {
		hpa_t root;

		MMU_WARN_ON(VALID_PAGE(kvm_get_gp_phys_root(vcpu)));

		spin_lock(&vcpu->kvm->mmu_lock);
		make_mmu_pages_available(vcpu);
		sp = kvm_mmu_get_page(vcpu, 0, 0, PT64_ROOT_LEVEL, 1, ACC_ALL,
					false /* validate */);
		++sp->root_count;
		spin_unlock(&vcpu->kvm->mmu_lock);
		root = __pa(sp->spt);
		kvm_set_gp_phys_root(vcpu, root);
	} else if (vcpu->arch.mmu.shadow_root_level == PT32E_ROOT_LEVEL) {
		for (i = 0; i < 4; ++i) {
			hpa_t root = vcpu->arch.mmu.pae_root[i];

			MMU_WARN_ON(VALID_PAGE(root));
			spin_lock(&vcpu->kvm->mmu_lock);
			make_mmu_pages_available(vcpu);
			sp = kvm_mmu_get_page(vcpu, i << (30 - PAGE_SHIFT),
					i << 30, PT32_ROOT_LEVEL, 1, ACC_ALL,
					false /* validate */);
			root = __pa(sp->spt);
			++sp->root_count;
			spin_unlock(&vcpu->kvm->mmu_lock);
			vcpu->arch.mmu.pae_root[i] = root | PT_PRESENT_MASK;
		}
/*		kvm_set_space_type_root_hpa(vcpu, __pa(vcpu->arch.mmu.pae_root),
						false user space ? ); */
	} else {
		BUG();
	}
	return 0;
}

static hpa_t e2k_mmu_alloc_spt_root(struct kvm_vcpu *vcpu, gfn_t root_gfn)
{
	struct kvm_mmu_page *sp;
	hpa_t root_hpa;

	DebugSPT("started on VCPU #%d, guest PT root at 0x%llx\n",
		vcpu->vcpu_id, root_gfn << PAGE_SHIFT);

	if (mmu_check_root(vcpu, root_gfn)) {
		pr_err("%s(): check of guest root PT failed\n", __func__);
		return E2K_INVALID_PAGE;
	}

	/*
	 * Do we shadow a long mode page table? If so we need to
	 * write-protect the guests page table root.
	 */
	KVM_BUG_ON(vcpu->arch.mmu.root_level != PT64_ROOT_LEVEL);

	spin_lock(&vcpu->kvm->mmu_lock);
	make_mmu_pages_available(vcpu);
	sp = kvm_mmu_get_page(vcpu, root_gfn, 0, PT64_ROOT_LEVEL, 0,
			ACC_WRITE_MASK,	/* PTD should be not executable */
					/* and privileged */
			false /* validate */);
	root_hpa = __pa(sp->spt);
	++sp->root_count;
	spin_unlock(&vcpu->kvm->mmu_lock);
	DebugSPT("VCPU #%d created shadow PT root at 0x%llx, "
		"sp struct at %px, gfn 0x%llx\n",
		vcpu->vcpu_id, root_hpa, sp, sp->gfn);
	return root_hpa;
}

static int e2k_mmu_alloc_shadow_roots(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
					unsigned flags)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	pgprotval_t u_pptb, os_pptb;
	gpa_t root_gpa;
	hpa_t root;

	/*
	 * Do we shadow a long mode page table? If so we need to
	 * write-protect the guests page table root.
	 */
	KVM_BUG_ON(mmu->root_level != PT64_ROOT_LEVEL);

	u_pptb = mmu->get_vcpu_u_pptb(vcpu);
	os_pptb = mmu->get_vcpu_os_pptb(vcpu);

	if (flags & OS_ROOT_PT_FLAG) {
		if (is_sep_virt_spaces(vcpu)) {
			root_gpa = kvm_get_space_type_guest_os_root(vcpu);
			root = kvm_get_space_type_spt_os_root(vcpu);
		} else {
			root_gpa = kvm_get_space_type_guest_u_root(vcpu);
			root = kvm_get_space_type_spt_u_root(vcpu);
		}
		MMU_WARN_ON(VALID_PAGE(root));

		root = e2k_mmu_alloc_spt_root(vcpu, gpa_to_gfn(root_gpa));
		MMU_WARN_ON(!VALID_PAGE(root));
		if (is_sep_virt_spaces(vcpu)) {
			kvm_set_space_type_spt_os_root(vcpu, root);
			if (u_pptb == os_pptb) {
				kvm_set_space_type_spt_u_root(vcpu, root);
			}
		} else {
			kvm_set_space_type_spt_u_root(vcpu, root);
		}
		if (!(flags & DONT_SYNC_ROOT_PT_FLAG)) {
			kvm_sync_shadow_root(vcpu, gmm, root, OS_ROOT_PT_FLAG);
		}
		DebugSPT("VCPU #%d, guest OS_PT root at 0x%llx shadow root "
			"at 0x%llx\n",
			vcpu->vcpu_id, root_gpa, root);

		if (flags & U_ROOT_PT_FLAG) {
			if (!is_sep_virt_spaces(vcpu)) {
				/* already allocated as OS & USER root */
				return 0;
			}
		} else {
			return 0;
		}
	} else if (!(flags & U_ROOT_PT_FLAG)) {
		return 0;
	}

	/* allocate guest user PT root */
	root_gpa = kvm_get_space_type_guest_u_root(vcpu);
	root = e2k_mmu_alloc_spt_root(vcpu, gpa_to_gfn(root_gpa));
	MMU_WARN_ON(!VALID_PAGE(root));
	kvm_set_space_type_spt_u_root(vcpu, root);
	if (is_sep_virt_spaces(vcpu) && u_pptb == os_pptb) {
		kvm_set_space_type_spt_os_root(vcpu, root);
	}
	if (!(flags & DONT_SYNC_ROOT_PT_FLAG)) {
		kvm_sync_shadow_root(vcpu, gmm, root, U_ROOT_PT_FLAG);
	}
	DebugSPT("VCPU #%d, guest U_PT root at 0x%llx, shadow root "
		"at 0x%llx\n",
		vcpu->vcpu_id, root_gpa, root);

	return 0;
}

int x86_mmu_alloc_shadow_roots(struct kvm_vcpu *vcpu, unsigned flags)
{
	struct kvm_mmu_page *sp;
	pgprotval_t pdpte, pm_mask;
	gfn_t root_gfn;
	int i;

	root_gfn = kvm_get_space_type_spt_u_root(vcpu);
	root_gfn = gpa_to_gfn(root_gfn);

	if (mmu_check_root(vcpu, root_gfn)) {
		pr_err("%s(): check of guest root PT failed\n", __func__);
		return 1;
	}

	/*
	 * Do we shadow a long mode page table? If so we need to
	 * write-protect the guests page table root.
	 */
	if (vcpu->arch.mmu.root_level == PT64_ROOT_LEVEL) {
		pr_err("%s(): is not yet implemented\n", __func__);
		return -ENODEV;
	}

	/*
	 * We shadow x86 32 bit page table. This may be a legacy 2-level
	 * or a PAE 3-level page table. In either case we need to be aware that
	 * the shadow page table may be a PAE or a long mode page table.
	 */
	pm_mask = PT_PRESENT_MASK;
	if (vcpu->arch.mmu.shadow_root_level == PT64_ROOT_LEVEL)
		pm_mask |= PT_ACCESSED_MASK | PT_WRITABLE_MASK |
						PT_X86_USER_MASK;

	for (i = 0; i < 4; ++i) {
		hpa_t root = vcpu->arch.mmu.pae_root[i];

		MMU_WARN_ON(VALID_PAGE(root));
		if (vcpu->arch.mmu.root_level == PT32E_ROOT_LEVEL) {
			pdpte = get_vcpu_pdpte(vcpu, i);
			if (!(pdpte & PT_PRESENT_MASK)) {
				vcpu->arch.mmu.pae_root[i] = 0;
				continue;
			}
			root_gfn = pdpte >> PAGE_SHIFT;
			if (mmu_check_root(vcpu, root_gfn))
				return 1;
		}
		spin_lock(&vcpu->kvm->mmu_lock);
		make_mmu_pages_available(vcpu);
		sp = kvm_mmu_get_page(vcpu, root_gfn, i << 30, PT32_ROOT_LEVEL,
				      0, ACC_ALL, false /* validate */);
		root = __pa(sp->spt);
		++sp->root_count;
		spin_unlock(&vcpu->kvm->mmu_lock);

		vcpu->arch.mmu.pae_root[i] = root | pm_mask;
	}
/*	kvm_set_space_type_root_hpa(vcpu, __pa(vcpu->arch.mmu.pae_root),
					u_root); */

	/*
	 * If we shadow a 32 bit page table with a long mode page
	 * table we enter this path.
	 */
	if (vcpu->arch.mmu.shadow_root_level == PT64_ROOT_LEVEL) {
		if (vcpu->arch.mmu.lm_root == NULL) {
			/*
			 * The additional page necessary for this is only
			 * allocated on demand.
			 */

			u64 *lm_root;

			lm_root = (void *)get_zeroed_page(GFP_KERNEL);
			if (lm_root == NULL)
				return 1;

			lm_root[0] = __pa(vcpu->arch.mmu.pae_root) | pm_mask;

			vcpu->arch.mmu.lm_root = lm_root;
		}

		kvm_set_space_type_spt_u_root(vcpu,
				__pa(vcpu->arch.mmu.lm_root));
	}

	return 0;
}

static int mmu_alloc_shadow_roots(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
					unsigned flags)
{
	KVM_BUG_ON(vcpu->arch.mmu.direct_map);
	return e2k_mmu_alloc_shadow_roots(vcpu, gmm, flags);
}

static void mmu_sync_spt_root(struct kvm_vcpu *vcpu, hpa_t root)
{
	struct kvm_mmu_page *sp;

	kvm_mmu_audit(vcpu, AUDIT_PRE_SYNC);
	sp = page_header(root);
	DebugSYNC("SP at %px for root PT 0x%llx, gfn 0x%llx\n",
		sp, root, sp->gfn);
	mmu_sync_children(vcpu, sp);
	kvm_mmu_audit(vcpu, AUDIT_POST_SYNC);
}

static void e2k_mmu_sync_roots(struct kvm_vcpu *vcpu, unsigned flags)
{
	hpa_t os_root, u_root;

	if (vcpu->arch.mmu.direct_map)
		return;
	if (flags & DONT_SYNC_ROOT_PT_FLAG)
		return;

	KVM_BUG_ON(vcpu->arch.mmu.root_level != PT64_ROOT_LEVEL);

	mmu_get_spt_roots(vcpu, flags, &os_root, &u_root, NULL);
	if (!VALID_PAGE(os_root) && !VALID_PAGE(u_root))
		return;

	vcpu_clear_mmio_info(vcpu, MMIO_GVA_ANY);

	if (VALID_PAGE(u_root)) {
		DebugSYNC("started on VCPU #%d for root U_PT at 0x%llx\n",
			vcpu->vcpu_id, u_root);
		mmu_sync_spt_root(vcpu, u_root);
	}
	if (VALID_PAGE(os_root) && os_root != u_root) {
		DebugSYNC("started on VCPU #%d for root OS_PT at 0x%llx\n",
			vcpu->vcpu_id, os_root);
		mmu_sync_spt_root(vcpu, os_root);
	}
}

static void mmu_sync_roots(struct kvm_vcpu *vcpu, unsigned flags)
{
	int i;
	struct kvm_mmu_page *sp;

	if (vcpu->arch.mmu.direct_map)
		return;

	if (vcpu->arch.mmu.root_level == PT64_ROOT_LEVEL) {
		e2k_mmu_sync_roots(vcpu, flags);
		return;
	}
	vcpu_clear_mmio_info(vcpu, MMIO_GVA_ANY);
	kvm_mmu_audit(vcpu, AUDIT_PRE_SYNC);
	for (i = 0; i < 4; ++i) {
		hpa_t root = vcpu->arch.mmu.pae_root[i];

		if (root && VALID_PAGE(root)) {
			root &= kvm_get_spte_pfn_mask(vcpu->kvm);
			sp = page_header(root);
			mmu_sync_children(vcpu, sp);
		}
	}
	kvm_mmu_audit(vcpu, AUDIT_POST_SYNC);
}

void kvm_mmu_sync_roots(struct kvm_vcpu *vcpu, unsigned flags)
{
	spin_lock(&vcpu->kvm->mmu_lock);
	mmu_sync_roots(vcpu, flags);
	spin_unlock(&vcpu->kvm->mmu_lock);
}
EXPORT_SYMBOL_GPL(kvm_mmu_sync_roots);

gpa_t nonpaging_gva_to_gpa(struct kvm_vcpu *vcpu, gva_t vaddr,
				  u32 access, kvm_arch_exception_t *exception)
{
	if (exception)
		exception->error_code = 0;
	return vaddr;
}

static bool is_shadow_zero_bits_set(struct kvm_mmu *mmu, pgprot_t spte,
					int level)
{
	if (is_ss(NULL)) {
		pr_err_once("FIXME: %s() is not implemented\n", __func__);
	}
	return false;
}

static pf_res_t handle_mmu_page_fault(struct kvm_vcpu *vcpu, gva_t address,
				u32 error_code, bool prefault,
				gfn_t *gfn, kvm_pfn_t *pfn)
{
	intc_mu_state_t *mu_state = get_intc_mu_state(vcpu);
	pf_res_t pfres;
	int try = 0;

	do {
		pfres = vcpu->arch.mmu.page_fault(vcpu, address,
					error_code, prefault, gfn, pfn);
		if (likely(pfres != PFRES_RETRY))
			break;
		if (!mu_state->may_be_retried) {
			/* cannot be retried */
			break;
		}
		try++;
		if (try <= PF_RETRIES_MAX_NUM) {
			DebugTRY("retry #%d seq 0x%lx to handle page fault : "
				"address 0x%lx, pfn 0x%llx / gfn 0x%llx\n",
				try, mu_state->notifier_seq, address,
				(pfn != NULL) ? *pfn : ~0ULL,
				(gfn != NULL) ? *gfn : ~0ULL);
		}
	} while (try < PF_TRIES_MAX_NUM);

	mu_state->pfres = pfres;

	DebugPFINTC("mmu.page_fault() returned %d\n", pfres);


	if (PF_RETRIES_MAX_NUM > 0 && pfres == PFRES_RETRY) {
		DebugTRY("could not handle page fault : retries %d, "
			"address 0x%lx, pfn 0x%llx / gfn 0x%llx\n",
			try, address,
			(pfn != NULL) ? *pfn : ~0ULL,
			(gfn != NULL) ? *gfn : ~0ULL);
	}

	return pfres;
}

static void inject_page_fault(struct kvm_vcpu *vcpu,
			      kvm_arch_exception_t *fault)
{
	if (vcpu->arch.mmu.inject_page_fault) {
		vcpu->arch.mmu.inject_page_fault(vcpu, fault);
	}
}

void direct_unmap_prefixed_mmio_gfn(struct kvm *kvm, gfn_t gfn)
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

static bool mmio_info_in_cache(struct kvm_vcpu *vcpu, u64 addr, bool direct)
{
	if (direct)
		return vcpu_match_mmio_gpa(vcpu, addr);

	return vcpu_match_mmio_gva(vcpu, addr);
}

static inline bool is_cached_mmio_page_fault(struct kvm_vcpu *vcpu, u64 addr,
					     gfn_t *gfn, bool direct)
{
	if (mmio_info_in_cache(vcpu, addr, direct)) {
		*gfn = vcpu->arch.mmio_gfn;
		return true;
	}
	return false;
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

int handle_mmio_page_fault(struct kvm_vcpu *vcpu, u64 addr, gfn_t *gfn,
				bool direct)
{
	pgprot_t spte;
	bool reserved;

	if (is_cached_mmio_page_fault(vcpu, addr, gfn, direct)) {
		return RET_MMIO_PF_EMULATE;
	}

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
EXPORT_SYMBOL_GPL(handle_mmio_page_fault);

static bool page_fault_handle_page_track(struct kvm_vcpu *vcpu,
					 u32 error_code, gfn_t gfn)
{
	struct kvm_memory_slot *slot;

	if (unlikely(error_code & PFERR_RSVD_MASK))
		return false;

	if (!(error_code & PFERR_PRESENT_MASK) ||
	      !(error_code & PFERR_WRITE_MASK))
		return false;

	/*
	 * guest is writing the page which is write tracked which can
	 * not be fixed by page fault handler.
	 */
	slot = __gfn_to_memslot(kvm_memslots_for_spte_role(vcpu->kvm, 0),
				gfn);
	if (kvm_page_track_is_active(vcpu->kvm, slot, gfn,
				KVM_PAGE_TRACK_WRITE))
		return true;

	return false;
}

static void shadow_page_table_clear_flood(struct kvm_vcpu *vcpu, gva_t addr)
{
	struct kvm_shadow_walk_iterator iterator;
	pgprot_t spte;

	if (!VALID_PAGE(kvm_get_space_addr_root(vcpu, addr)))
		return;

	walk_shadow_page_lockless_begin(vcpu);
	for_each_shadow_entry_lockless(vcpu, addr, iterator, spte) {
		clear_sp_write_flooding_count(iterator.sptep);
		if (!is_shadow_present_pte(vcpu->kvm, spte))
			break;
	}
	walk_shadow_page_lockless_end(vcpu);
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

int kvm_prefetch_mmu_area(struct kvm_vcpu *vcpu, gva_t start, gva_t end,
			  u32 error_code)
{
	int evn_no = 0;	/* should not be used here */
	intc_mu_state_t *mu_state;
	gva_t addr;
	gfn_t gfn;
	pf_res_t pfres;

	DebugSPF("started on VCPU #%d : area from 0x%lx to 0x%lx\n",
		vcpu->vcpu_id, start, end);

	vcpu->arch.intc_ctxt.cur_mu = evn_no;
	mu_state = get_intc_mu_state(vcpu);
	mu_state->may_be_retried = true;
	mu_state->ignore_notifier = true;

	/* FIXME: only trivial case of addresses and sizes in terms of */
	/* PAGE_SIZE is implemented. It need support huge pages too */
	addr = start;
	do {
		pfres = handle_mmu_page_fault(vcpu, addr, error_code, true,
						&gfn, NULL);
		if (likely(pfres == PFRES_NO_ERR)) {
			continue;
		} else {
			pr_err("%s(): failed to handle addr 0x%lx, error %d\n",
				__func__, addr, pfres);
			return -EFAULT;
		}
	} while (addr += PAGE_SIZE, addr < end);

	return 0;
}

static void move_mu_intc_to_trap_cellar(struct kvm_vcpu *vcpu, int evn_no)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	int mu_num = intc_ctxt->mu_num;
	unsigned long evn_mask;

	KVM_BUG_ON(evn_no < 0 || evn_no >= mu_num);
	evn_mask = 1UL << evn_no;

	KVM_BUG_ON(intc_ctxt->intc_mu_to_move & evn_mask);
	if (!HW_MOVE_TO_TC_IS_SUPPORTED) {
		intc_ctxt->intc_mu_to_move |= evn_mask;
	}
}

static int move_rest_mu_intc_to_trap_cellar(struct kvm_vcpu *vcpu,
						int from_evn_no)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	intc_info_mu_t *mus = intc_ctxt->mu;
	intc_info_mu_t *mu, *mu_event;
	int event;
	int mu_num = intc_ctxt->mu_num;
	int evn_no;

	KVM_BUG_ON(from_evn_no < 0 || from_evn_no >= mu_num);

	mu = &mus[from_evn_no];

	/* loop on MMU events before event injected to guest */
	for (evn_no = 0; evn_no < from_evn_no; evn_no++) {
		mu_event = &mus[evn_no];
		event = mu_event->hdr.event_code;
		switch (event) {
		case IME_FORCED:
		case IME_FORCED_GVA:
			DebugSHINJ("event #%d %s cannot precede the "
				"event #%d %s injected to guest\n",
				evn_no, kvm_get_mu_event_name(event),
				from_evn_no,
				kvm_get_mu_event_name(mu->hdr.event_code));
			break;
		case IME_GPA_DATA:
		case IME_SHADOW_DATA:
		case IME_GPA_INSTR:
		case IME_GPA_AINSTR:
		default:
			DebugSHINJ("event #%d %s precedes the event #%d %s "
				"injected to guest\n",
				evn_no, kvm_get_mu_event_name(event),
				from_evn_no,
				kvm_get_mu_event_name(mu->hdr.event_code));
			break;
		}
	}

	/* loop on MMU events after event injected to guest */
	for (evn_no = from_evn_no + 1; evn_no < mu_num; evn_no++) {
		mu_event = &mus[evn_no];
		event = mu_event->hdr.event_code;

		switch (event) {
		case IME_FORCED:
		case IME_FORCED_GVA:
			DebugSHINJ("event #%d %s move to guest trap cellar: "
				"it is after the event #%d %s injected "
				"to guest\n",
				evn_no, kvm_get_mu_event_name(event),
				from_evn_no,
				kvm_get_mu_event_name(mu->hdr.event_code));
			if (!HW_MOVE_TO_TC_IS_SUPPORTED) {
				/* update 'condition.address' destination */
				/* register abs number from dst_ind field, */
				/* new destination register number */
				AS(mu_event->condition).address =
					AS(mu_event->condition).dst_ind;
			}
			move_mu_intc_to_trap_cellar(vcpu, evn_no);
			break;
		case IME_GPA_INSTR:
		case IME_GPA_AINSTR:
			DebugSHINJ("event #%d %s should be injected too: "
				"it is after the event #%d %s injected "
				"to guest\n",
				evn_no, kvm_get_mu_event_name(event),
				from_evn_no,
				kvm_get_mu_event_name(mu->hdr.event_code));
			break;
		case IME_GPA_DATA:
		case IME_SHADOW_DATA:
			DebugSHINJ("event #%d %s will move to guest trap "
				"cellar too: but it is after the already "
				"injected event #%d %s WHY\n",
				evn_no, kvm_get_mu_event_name(event),
				from_evn_no,
				kvm_get_mu_event_name(mu->hdr.event_code));
			move_mu_intc_to_trap_cellar(vcpu, evn_no);
			break;
		default:
			DebugSHINJ("event #%d %s should be handled although "
				"it is after the event #%d %s injected "
				"to guest\n",
				evn_no, kvm_get_mu_event_name(event),
				from_evn_no,
				kvm_get_mu_event_name(mu->hdr.event_code));
			break;
		}
	}
	return 0;
}

static void move_mu_intc_to_vcpu_exception(struct kvm_vcpu *vcpu, int evn_no)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;

	BUILD_BUG_ON(INTC_INFO_MU_ITEM_MAX >
				sizeof(intc_ctxt->intc_mu_to_move) * 8);
	KVM_BUG_ON(intc_ctxt->intc_mu_to_move != 0);

	move_mu_intc_to_trap_cellar(vcpu, evn_no);
}

static int inject_shadow_data_page_fault(struct kvm_vcpu *vcpu,
				int evn_no, intc_info_mu_t *mu_event)
{
	int event;
	e2k_addr_t address;
	int ret;

	event = mu_event->hdr.event_code;
	address = mu_event->gva;

	DebugSHINJ("intercept event #%d code %d %s, guest address 0x%lx "
		"fault type 0x%x\n",
		evn_no, event, kvm_get_mu_event_name(event),
		address, AS(mu_event->condition).fault_type);

	/* update event code to inject by hardware the event to guest */
	mu_event->hdr.event_code = IME_FORCED_GVA;
	kvm_set_intc_info_mu_is_updated(vcpu);
	if (!HW_MOVE_TO_TC_IS_SUPPORTED) {
		/* update 'condition.address' destination register abs number */
		/* from dst_ind field, new destination register number */
		AS(mu_event->condition).address =
			AS(mu_event->condition).dst_ind;
	}
	/* inject page fault exception into TIRs */
	kvm_need_create_vcpu_exception(vcpu, exc_data_page_mask);
	if (!HW_MOVE_TO_TC_IS_SUPPORTED) {
		/* FIXME: simulator bug: simulator does not move reguests */
		/* which should be reeexecuted from INTC_INFO_MU to trap */
		/* cellar unlike the hardware, so make it by software */
		move_mu_intc_to_vcpu_exception(vcpu, evn_no);
	}
	/* mark all rest MMU intercept events as moved to guest */
	/* now is here only to debug injection and requests moving */
	/* should be under !HW_MOVE_TO_TC_IS_SUPPORTED */
	ret = move_rest_mu_intc_to_trap_cellar(vcpu, evn_no);
	return ret;
}

static int inject_shadow_instr_page_fault(struct kvm_vcpu *vcpu,
				int evn_no, intc_info_mu_t *mu_event)
{
	int event;
	gva_t IP;
	tc_cond_t cond;
	tc_fault_type_t ftype;
	unsigned long exc_mask;
	const char *trap_name;

	event = mu_event->hdr.event_code;
	IP = mu_event->gva;
	cond = mu_event->condition;
	AW(ftype) = AS(cond).fault_type;

	DebugSHINJ("intercept event #%d code %d %s, guest IP 0x%lx, "
		"fault type 0x%x\n",
		evn_no, event, kvm_get_mu_event_name(event), IP, AW(ftype));

	if (AS(ftype).page_miss) {
		exc_mask = exc_instr_page_miss_mask;
		trap_name = "instr_page_miss";
	} else if (AS(ftype).prot_page) {
		exc_mask = exc_instr_page_prot_mask;
		trap_name = "instr_page_prot";
	} else {
		pr_err("%s(): bad fault type 0x%x, pass instruction protection "
			"fault to guest\n",
			__func__, AW(ftype));
		exc_mask = exc_instr_page_prot_mask;
		trap_name = "invalid_instr_page";
	}

	DebugSHINJ("intercept on %s fault, IP 0x%lx\n", trap_name, IP);

	kvm_need_create_vcpu_exc_and_IP(vcpu, exc_mask, IP);

	return 0;
}

static int inject_shadow_ainstr_page_fault(struct kvm_vcpu *vcpu,
				int evn_no, intc_info_mu_t *mu_event)
{
	int event;
	gva_t IP;
	tc_cond_t cond;
	tc_fault_type_t ftype;
	unsigned long exc_mask;
	const char *trap_name;

	event = mu_event->hdr.event_code;
	IP = mu_event->gva;
	cond = mu_event->condition;
	AW(ftype) = AS(cond).fault_type;

	DebugSHINJ("intercept event #%d code %d %s, guest IP 0x%lx, "
		"fault type 0x%x\n",
		evn_no, event, kvm_get_mu_event_name(event), IP, AW(ftype));

	if (AS(ftype).page_miss) {
		exc_mask = exc_ainstr_page_miss_mask;
		trap_name = "ainstr_page_miss";
	} else if (AS(ftype).prot_page) {
		exc_mask = exc_ainstr_page_prot_mask;
		trap_name = "ainstr_page_prot";
	} else {
		pr_err("%s(): bad fault type 0x%x, pass instruction protection "
			"fault to guest\n",
			__func__, AW(ftype));
		exc_mask = exc_ainstr_page_prot_mask;
		trap_name = "invalid_ainstr_page";
	}

	DebugSHINJ("intercept on %s fault, IP 0x%lx\n", trap_name, IP);

	kvm_need_create_vcpu_exc_and_IP(vcpu, exc_mask, IP);

	return 0;
}

static void inject_shadow_page_fault(struct kvm_vcpu *vcpu,
					kvm_arch_exception_t *fault)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	intc_info_mu_t *mu_event;
	int mu_num = intc_ctxt->mu_num;
	int evn_no = intc_ctxt->cur_mu;
	int event;
	int ret = 0;

	KVM_BUG_ON(evn_no < 0 || evn_no >= mu_num);

	mu_event = &intc_ctxt->mu[evn_no];
	event = mu_event->hdr.event_code;

	DebugSHINJ("INTC MU event #%d code %d %s\n",
		evn_no, event, kvm_get_mu_event_name(event));

	switch (event) {
	case IME_GPA_DATA:
		pr_err("%s(): invalid event #%d code %d %s for access on "
			"virtual address at shadow PT mode\n",
			__func__, evn_no, event, kvm_get_mu_event_name(event));
		ret = -EINVAL;
		break;
	case IME_FORCED:
	case IME_FORCED_GVA:
		DebugSHINJ("INTC MU event #%d vode %d %s will be reexecuted "
			"by hardware while intercept completion\n",
			evn_no, event, kvm_get_mu_event_name(event));
		break;
	case IME_SHADOW_DATA:
		ret = inject_shadow_data_page_fault(vcpu, evn_no, mu_event);
		break;
	case IME_GPA_INSTR:
		ret = inject_shadow_instr_page_fault(vcpu, evn_no, mu_event);
		break;
	case IME_GPA_AINSTR:
		ret = inject_shadow_ainstr_page_fault(vcpu, evn_no, mu_event);
		break;
	default:
		pr_err("%s(): event #%d %s should not cause injection\n",
			__func__, evn_no, kvm_get_mu_event_name(event));
		ret = -EINVAL;
		break;
	}

	KVM_BUG_ON(ret != 0);

}

/**
 * calculate_recovery_load_to_rf_frame - calculate the stack address
 *	of the register into registers file frame where the load was done.
 * @dst_ind: trap cellar's "dst" field
 * @radr: address of a "normal" register
 * @load_to_rf: load to rf should be done
 *
 * This function calculates and sets @radr.
 *
 * Returns zero on success and value of type exec_mmu_ret on failure.
 */
static enum exec_mmu_ret calculate_guest_recovery_load_to_rf_frame(
		struct pt_regs *regs, tc_cond_t cond,
		u64 **radr, bool *load_to_rf)
{
	unsigned	dst_ind = AS(cond).dst_ind;
	unsigned	w_base_rnum_d, frame_rnum_d;
	u8		*ps_base = NULL, *frame_base;
	unsigned	rnum_offset_d, rnum_ind_d;
	unsigned	w_size_q;
	u64		*rind;

	BUG_ON(!(dst_ind < E2K_MAXSR_d));

	/*
	 * The guest registers frame was spilled to backup stacks and
	 * it should be at the top frame of the stack
	 * Intercept hardware set <dst_ind> to INTC_INFO_MU and its calculated
	 * as:
	 *   d is physical number of register to load to
	 *   b is base of register ftame of guest function with load WD.base_d
	 *   s is size of register frame WD.size_d
	 *
	 *	i = (d >= b) ? (d - b) : (MAXSR_d + d - b);
	 *	if (vm_dst != 0)
	 *		dst_ind = MAXSR_d - s + i;
	 *	else
	 *		dst_ind = undefined;
	 * so:
	 *	i = dst_ind - MAXSR_d + s
	 *
	 *	always w_base_rnum_d > dst_ind:
	 *
	 * RF 0<-------| THE GUEST FRAME WD |E2K_MAXSR_d
	 *                    ^dst_ind
	 *                                  ^w_base_rnum_d == E2K_MAXSR_d
	 *
	 *
	 * --|---------| THE GUEST FRAME    |E2K_MAXSR_d
	 *   ^psp.base                      ^psp.ind
	 *
	 * First address of first empty byte of psp stack is
	 *	ps_base = base + ind;
	 * Our address to load is:
	 *	ps_base - s + i
	 */

	ps_base = (u8 *)(regs->stacks.psp_lo.PSP_lo_base +
			regs->stacks.psp_hi.PSP_hi_ind);
	w_base_rnum_d = E2K_MAXSR_d;
	w_size_q = regs->crs.cr1_lo.CR1_lo_wbs;
	frame_base = ps_base - w_size_q * EXT_4_NR_SZ;

	/*
	 * Offset from beginning spilled quad-NR for our
	 * dst_ind is
	 *	rnum_offset_d.
	 * We define rnum_offset_d for dst_ind from ps_base
	 * in terms of double.
	 * Note. dst_ind is double too.
	 */
	if (w_base_rnum_d > dst_ind) {
		rnum_offset_d = w_base_rnum_d - dst_ind;
		frame_rnum_d = w_base_rnum_d - w_size_q * 2;
		rnum_ind_d = dst_ind - frame_rnum_d;
	} else {
		KVM_BUG_ON(true);
	}
	/*
	 * Window boundaries are aligned at least to quad-NR.
	 * When windows spill then quad-NR is spilled as minimum.
	 * Also, extantion of regs is spilled too.
	 * So, each spilled quad-NR take 2*quad-NR size == 32 bytes
	 * So, bytes offset for our rnum_offset_d is
	 *	(rnum_offset_d + 1) / 2) * 32
	 * if it was uneven number we should add size of double:
	 *	(rnum_offset_d % 2) * 8
	 * starting from ISET V5 we should add size of quadro.
	 */
	*radr = (u64 *) (ps_base - ((rnum_offset_d + 1) / 2) * 32);
	if (rnum_offset_d % 2)
		*radr += ((machine.native_iset_ver < E2K_ISET_V5) ? 1 : 2);
	DbgEXMMU("<dst from end> is window register: "
		"rnum_d = 0x%x offset 0x%x, "
		"PS end 0x%px WD end = 0x%x, radr = 0x%px\n",
		dst_ind, rnum_offset_d, ps_base, w_base_rnum_d, *radr);

	rind = (u64 *) (frame_base + ((rnum_ind_d + 0) / 2) * 32);
	if (rnum_ind_d % 2)
		rind += ((machine.native_iset_ver < E2K_ISET_V5) ? 1 : 2);
	DbgEXMMU("<dst from base> is window register: "
		"rnum_d = 0x%x index 0x%x, "
		"PS base 0x%px WD base = 0x%x, radr = 0x%px\n",
		dst_ind, rnum_ind_d, frame_base, frame_rnum_d, rind);

	KVM_BUG_ON(*radr != rind);

	if (((unsigned long) *radr < (u64)frame_base) ||
				((unsigned long) *radr >= (u64)ps_base)) {
		/*
		 * The load operation out of guest top register window frame
		 * (for example this load is placed in one long instruction
		 * with return. The load operationb should be ignored
		 */
		DbgEXMMU("<dst> address of register window points "
			"out of guest top register procedure stack frame "
			"0x%px > 0x%px >= 0x%px, load operation will be "
			"ignored\n",
			frame_base, *radr, ps_base);
		return EXEC_MMU_SUCCESS;
	}

	*load_to_rf = false;
	return 0;
}

static bool
check_guest_spill_fill_recovery(tc_cond_t cond, e2k_addr_t address, bool s_f,
				struct pt_regs *regs)
{
	struct kvm_vcpu *vcpu = current_thread_info()->vcpu;
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;
	bool store;

	store = AS(cond).store;

	if (unlikely(AS(cond).s_f || s_f)) {
		e2k_addr_t stack_base;
		e2k_size_t stack_ind;

		return true;

		/*
		 * Not completed SPILL operation should be completed here
		 * by data store
		 * Not completed FILL operation replaced by restore of saved
		 * filling data in trap handler
		 */

		DbgEXMMU("completion of %s %s operation\n",
			(AS(cond).sru) ? "PCS" : "PS",
			(store) ? "SPILL" : "FILL");
		if (AS(cond).sru) {
			stack_base = hw_ctxt->sh_pcsp_lo.PCSP_lo_base;
			stack_ind = hw_ctxt->sh_pcsp_hi.PCSP_hi_ind;
		} else {
			stack_base = hw_ctxt->sh_psp_lo.PSP_lo_base;
			stack_ind = hw_ctxt->sh_psp_hi.PSP_hi_ind;
		}
		if (address < stack_base || address >= stack_base + stack_ind) {
			pr_err("%s(): invalid procedure stack addr 0x%lx < "
				"stack base 0x%lx or >= current stack "
				"offset 0x%lx\n",
				__func__, address, stack_base,
				stack_base + stack_ind);
			BUG();
		}
		if (!store && !AS(cond).sru) {
			pr_err("%s(): not completed PS FILL operation detected "
				"in TC (only PCS FILL operation can be "
				"dropped to TC)\n",
				__func__);
			BUG();
		}
		return true;
	}
	return false;
}

int reexecute_load_and_wait_page_fault(struct kvm_vcpu *vcpu,
		trap_cellar_t *tcellar, gfn_t gfn, pt_regs_t *regs)
{
	e2k_addr_t address;
	tc_cond_t cond;
	e2k_addr_t hva;
	trap_cellar_t *next_tcellar;
	struct kvm_mmu_page *sp;
	LIST_HEAD(invalid_list);
	int r;

	/*
	 * It is load and wait lock operations.
	 * Hardware reexecute the operation, but the subsequent
	 * store and unlock operation can not be intercepted and
	 * only inevitable flush TLB line should be intercepted
	 * to update atomicaly updated PT entry.
	 */
	DebugREEXEC("reexecute hardware recovery load and wait lock "
		"operation\n");

	address = tcellar->address;
	cond = tcellar->condition;

	hva = kvm_vcpu_gfn_to_hva(vcpu, gfn);
	if (kvm_is_error_hva(hva)) {
		pr_err("%s(): could not convert gfn 0x%llx to hva\n",
			__func__, gfn);
		return -EFAULT;
	}
	hva |= (address & ~PAGE_MASK);
	tcellar->address = hva;
	tcellar->flags |= TC_IS_HVA_FLAG;
	DebugREEXEC("converted guest address 0x%lx, gfn 0x%llx to hva 0x%lx "
		"to recovery guest %s operation\n",
		address, gfn, hva, (AS(cond).store) ? "store" : "load");

	if (regs->trap->curr_cnt + 1 < get_vcpu_mu_events_num(vcpu)) {
		next_tcellar = tcellar + 1;
	} else {
		next_tcellar = NULL;
	}
	r = execute_mmu_operations(tcellar, next_tcellar, regs, 0, NULL,
			NULL, /*&check_guest_spill_fill_recovery,*/
			NULL /*&calculate_guest_recovery_load_to_rf_frame*/);
	DebugREEXEC("reexecution of %s and wait: address 0x%lx, hva 0x%lx "
		"completed, error %d\n",
		(AS(cond).store) ? "store" : "load",
		address, hva, r);
	if (r != EXEC_MMU_SUCCESS)
		return -EFAULT;

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

long kvm_hv_mmu_page_fault(struct kvm_vcpu *vcpu, struct pt_regs *regs,
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
	int try;
	pf_res_t pfres;
	long r;

	if (is_shadow_paging(vcpu)) {
		if (nonpaging) {
			if (is_phys_paging(vcpu)) {
				address = gpa;
			}
		} else if (event == IME_GPA_DATA) {
			KVM_BUG_ON(mas != MAS_LOAD_PA &&
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
		KVM_BUG_ON(true);
	}

	AW(ftype) = AS(cond).fault_type;
	AW(opcode) = AS(cond).opcode;
	KVM_BUG_ON(AS(opcode).fmt == 0 || AS(opcode).fmt == 6);
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
	if (!nonpaging && AS(ftype).page_bound) {
		DebugPFINTC("page baund fault type, return back to host\n");
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

	if (unlikely(error_code & PFERR_MMIO_MASK)) {
		KVM_BUG_ON(ignore_store);
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
	} else if (is_cached_mmio_page_fault(vcpu, address, &gfn, direct)) {
		pfres = PFRES_TRY_MMIO;
		goto mmio_emulate;
	}

	mu_state->may_be_retried = true;
	mu_state->ignore_notifier = false;

	if (likely(!gpa_for_spt)) {
		pfres = handle_mmu_page_fault(vcpu, address, error_code,
						false, &gfn, &pfn);
	} else {
		try = 0;
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
			if (try <= PF_RETRIES_MAX_NUM) {
				DebugTRY("retry #%d to handle page fault "
					"on %s : address 0x%lx, "
					"pfn 0x%llx / gfn 0x%llx\n",
					try,
					(AS(cond).store) ? "store" : "load",
					address, pfn, gfn);
			}
		} while (try < PF_TRIES_MAX_NUM);
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
		KVM_BUG_ON(!mu_state->may_be_retried);
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

		KVM_BUG_ON(ignore_store);

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
				next_tcellar, regs, 0, NULL,
				&check_guest_spill_fill_recovery,
				&calculate_guest_recovery_load_to_rf_frame);
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
		KVM_BUG_ON(ignore_store);
		return 0;
	}

mmio_emulate:

	KVM_BUG_ON(ignore_store);

	if (pfres == PFRES_TRY_MMIO) {
		/* page fault on MMIO access */
		KVM_BUG_ON(mu_state->may_be_retried);
		gpa = gfn_to_gpa(gfn);
		gpa |= (address & ~PAGE_MASK);
		return kvm_hv_io_page_fault(vcpu, gpa, intc_info_mu);
	}

	KVM_BUG_ON(pfres != PFRES_WRITE_TRACK);

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
EXPORT_SYMBOL_GPL(kvm_hv_mmu_page_fault);

int kvm_mmu_instr_page_fault(struct kvm_vcpu *vcpu, gva_t address,
				bool async_instr, u32 error_code)
{
	int instr_num = 1;
	gfn_t gfn;
	pf_res_t r;

	DebugIPF("started for IP 0x%lx\n", address);

	if (!async_instr && ((address & PAGE_MASK) !=
			((address + E2K_INSTR_MAX_SIZE - 1) & PAGE_MASK))) {
		instr_num++;
	}

	do {
		r = handle_mmu_page_fault(vcpu, address, error_code, false,
					  &gfn, NULL);
		if (r != PFRES_NO_ERR)
			break;
		address = (address & PAGE_MASK) + PAGE_SIZE;
	} while (--instr_num, instr_num > 0);

	if (likely(r == PFRES_NO_ERR || r == PFRES_INJECTED)) {
		/* fault was handler or injected to guest */
		kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
		return 0;
	} else if (r == PFRES_RETRY) {
		/* paga fault handling should be retried */
		return 0;
	}

	/* it need something emulate */
	return -EFAULT;

	/* TODO In the end this interception will go away, so probably
	 * there is no need to handle AAU instruction page miss here */
}

#ifdef CONFIG_KVM_ASYNC_PF

/* Can start handling async page fault or not ? */
static bool kvm_can_do_async_pf(struct kvm_vcpu *vcpu)
{
	if (!vcpu->arch.apf.enabled)
		return false;

	/*
	 * Page fault can be handled asynchronously only if
	 * it has occured in user mode
	 */
	if (vcpu->arch.apf.in_pm)
		return false;

	/*
	 * Data and instruction page faults can be handled asyncronyously.
	 * Other events should be handled immediately.
	 */
	int ev_no = vcpu->arch.intc_ctxt.cur_mu;
	intc_info_mu_event_code_t ev_code = get_event_code(vcpu, ev_no);

	if (ev_code > IME_GPA_AINSTR)
		return false;

	if (intc_mu_record_asynchronous(vcpu, ev_no))
		return false;

	return true;
}

/*
 * Start async page fault handling
 */
static int kvm_arch_setup_async_pf(struct kvm_vcpu *vcpu, gva_t gva, gfn_t gfn)
{
	struct kvm_arch_async_pf arch;

	/* Unique identifier of async page fault event */
	arch.apf_id = (vcpu->arch.apf.cnt++ << 12 | vcpu->vcpu_id);

	return kvm_setup_async_pf(vcpu, gva, kvm_vcpu_gfn_to_hva(vcpu, gfn),
					&arch);
}

/*
 * Write async page fault type to guest per-vcpu pv_apf_event.apf_reason
 * Return value: 0 - on success , error code - on failure.
 */
static int kvm_set_apf_reason(struct kvm_vcpu *vcpu, u32 apf_reason)
{
	return kvm_write_guest_cached(vcpu->kvm, &vcpu->arch.apf.reason_gpa,
				&apf_reason, sizeof(u32));
}

/*
 * Write async page fault id to guest per-vcpu pv_apf_event.apf_id
 * Return value: 0 - on success , error code - on failure.
 */
static int kvm_set_apf_id(struct kvm_vcpu *vcpu, u32 apf_id)
{
	return kvm_write_guest_cached(vcpu->kvm, &vcpu->arch.apf.id_gpa,
				&apf_id, sizeof(u32));
}

/*
 * Read async page fault type from guest per-vcpu pv_apf_event.apf_reason
 * Return value: 0 - on success , error code - on failure.
 */
static int kvm_get_apf_reason(struct kvm_vcpu *vcpu, u32 *apf_reason)
{
	return kvm_read_guest_cached(vcpu->kvm, &vcpu->arch.apf.reason_gpa,
				apf_reason, sizeof(u32));
}

/*
 * Read async page fault id from guest per-vcpu pv_apf_event.apf_id
 * Return value: 0 - on success , error code - on failure.
 */
static int kvm_get_apf_id(struct kvm_vcpu *vcpu, u32 *apf_id)
{
	return kvm_read_guest_cached(vcpu->kvm, &vcpu->arch.apf.id_gpa,
				apf_id, sizeof(u32));
}


/*
 * Notify guest that physical page is swapped out by host
 */
void kvm_arch_async_page_not_present(struct kvm_vcpu *vcpu,
				     struct kvm_async_pf *work)
{
	if (!kvm_set_apf_reason(vcpu, KVM_APF_PAGE_IN_SWAP) &&
			!kvm_set_apf_id(vcpu, work->arch.apf_id)) {
		vcpu->arch.apf.host_apf_reason = KVM_APF_PAGE_IN_SWAP;
		kvm_need_create_vcpu_exception(vcpu, exc_data_page_mask);
	} else {
		pr_err("Host: async_pf, %s, error while setting "
				"apf_reason and apf_id\n", __func__);
		force_sig(SIGKILL);
	}
}

/*
 * Notify guest that physical page is loaded from disk and ready for access
 */
void kvm_arch_async_page_present(struct kvm_vcpu *vcpu,
				 struct kvm_async_pf *work)
{
	if (!kvm_set_apf_reason(vcpu, KVM_APF_PAGE_READY) &&
			!kvm_set_apf_id(vcpu, work->arch.apf_id)) {
		vcpu->arch.apf.host_apf_reason = KVM_APF_PAGE_READY;
		switch (vcpu->arch.apf.irq_controller) {
		case EPIC_CONTROLLER:
			kvm_hw_epic_async_pf_wake_deliver(vcpu);
			break;
		case APIC_CONTROLLER:
			/* TODO: support injecting page ready through APIC */
			pr_err("Host: async_pf, %s, APIC is not supported\n",
					__func__);
			force_sig(SIGKILL);
			break;
		default:
			pr_err("Host: async_pf, %s, unsupported type of"
					" irq controller\n", __func__);
			force_sig(SIGKILL);
		}
	} else {
		pr_err("Host: async_pf, %s, error while setting apf_reason"
				" and apf_id\n", __func__);
		force_sig(SIGKILL);
	}
}

/*
 * Fix up hypervisor page table when physical page is loaded from disk
 * and ready for access.
 */
void kvm_arch_async_page_ready(struct kvm_vcpu *vcpu, struct kvm_async_pf *work)
{
	pf_res_t ret = PFRES_NO_ERR;
	gfn_t gfnp;
	kvm_pfn_t pfnp;

	for (;;) {
		ret = vcpu->arch.mmu.page_fault(vcpu, work->cr2_or_gpa, 0,
					true, &gfnp, &pfnp);

		if (ret == PFRES_RETRY)
			cond_resched();
		else
			break;
	}
}

bool kvm_arch_can_inject_async_page_present(struct kvm_vcpu *vcpu)
{
	u32 guest_apf_reason, guest_apf_id;

	if (kvm_get_apf_reason(vcpu, &guest_apf_reason) ||
			kvm_get_apf_id(vcpu, &guest_apf_id)) {
		force_sig(SIGKILL);
		return false;
	}

	return vcpu->arch.apf.enabled &&
			guest_apf_reason == KVM_APF_NO && guest_apf_id == 0;
}

#endif /* CONFIG_KVM_ASYNC_PF */

static bool try_async_pf(struct kvm_vcpu *vcpu, bool prefault, gfn_t gfn,
			 gva_t gva, kvm_pfn_t *pfn, bool write, bool *writable)
{
	struct kvm_memory_slot *slot;
	bool async;

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);

#ifdef CONFIG_KVM_ASYNC_PF

	if (prefault || !kvm_can_do_async_pf(vcpu)) {
		*pfn = __gfn_to_pfn_memslot(slot, gfn, false, NULL,
				write, writable);
		return false;
	}

	/*
	 * Try to get pfn from hv page table. Use flag FOLL_NOWAIT for
	 * get_user_pages(). If physical page was swapped out by host,
	 * then start i/o , indicate async=true and return without sleeping
	 * while pages are loading from disk.
	 */
	async = false;
	*pfn = __gfn_to_pfn_memslot(slot, gfn, false, &async, write, writable);
	if (!async)
		return false; /* *pfn has correct page now */

	if (vcpu->arch.apf.host_apf_reason)
		return true;

	/* Physical page was swapped out by host, handle async page fault */
	if (kvm_arch_setup_async_pf(vcpu, gva, gfn))
		return true;

#endif /* CONFIG_KVM_ASYNC_PF */

	/* If attempt to handle page fault asynchronyously failed */
	*pfn = __gfn_to_pfn_memslot(slot, gfn, false, NULL, write, writable);

	return false;
}

/*
 * The function try convert gfn to rmapped host pfn, but only if gfn is valid
 * anf pfn is exist, without faulting and pfn allocation.
 * The function returns:
 *	- TRY_PF_NO_ERR - gfn is valid and gfn is rmapped to pfn
 *	- TRY_PF_ONLY_VALID_ERR - gfn is valid, but pfn is not yet allocated
 *	- TRY_PF_MMIO_ERR - gfn is from MMIO space, but not registered on host
 *	- < 0 - gfn is invalid, some actions failed or other errors
 */

static try_pf_err_t try_atomic_pf(struct kvm_vcpu *vcpu, gfn_t gfn,
					kvm_pfn_t *pfn, bool no_dirty_log)
{
	struct kvm_memory_slot *slot;

	*pfn = pte_prefetch_gfn_to_pfn(vcpu, gfn, &slot, no_dirty_log);
	if (is_mmio_space_pfn(*pfn)) {
		/* gfn is from MMIO space, but is not registered on host */
		return TRY_PF_MMIO_ERR;
	} else if (is_noslot_pfn(*pfn)) {
		/* gfn is out of phisical memory, probably it is from IO */
		return TRY_PF_MMIO_ERR;
	} else if (*pfn == KVM_PFN_ERR_FAULT) {
		e2k_addr_t hva;

		/* gfn is not valid or rmapped to pfn on host */
		hva = gfn_to_hva_memslot(slot, gfn);
		if (kvm_is_error_hva(hva)) {
			pr_err("%s(): gfn_to_hva_memslot() gfn 0x%llx failed\n",
				__func__, gfn);
			return TO_TRY_PF_ERR(-EFAULT);
		}

		/* Bug 129228: we may want to use a separate thread for HVA->HPA and debug prints */
		return TRY_PF_ONLY_VALID_ERR;
#if 0
		pgprot_t *pgprot;
		pgprot = kvm_hva_to_pte(hva);
		if (pgprot == NULL) {
			pr_err("%s(): kvm_hva_to_pte() for gfn 0x%llx failed\n",
				__func__, gfn);
			return TO_TRY_PF_ERR(-EFAULT);
		}
		if (pgprot_present(*pgprot)) {
			/* gfn is present and already rmapped on host */
			if ((pgprot_special(*pgprot) ||
				is_huge_zero_pmd(*(pmd_t *)pgprot) ||
					is_huge_zero_pud(*(pud_t *)pgprot)) &&
				!pgprot_write(*pgprot)) {
				/* hva is zero mapped to huge page */
				/* so gfn can be mapped as only valid */
				return TRY_PF_ONLY_VALID_ERR;
			}
			pr_err("%s(): gfn 0x%llx present hva 0x%lx "
				"pte %px == 0x%lx\n",
				__func__, gfn, hva, pgprot,
				pgprot_val(*pgprot));
			return TRY_PF_ONLY_VALID_ERR;
		} else if (pgprot_valid(*pgprot)) {
			/* gfn is valid, but not yet rmapped on host */
			DebugTOVM("gfn 0x%llx valid hva 0x%lx "
				"pte %px == 0x%lx\n",
				gfn, hva, pgprot, pgprot_val(*pgprot));
			return TRY_PF_ONLY_VALID_ERR;
		}
		KVM_BUG_ON(true);
#endif
	} else if (is_error_pfn(*pfn)) {
		pr_err("%s(): gfn_to_pfn_memslot_atomic() for gfn 0x%llx "
			"failed\n",
			__func__, gfn);
		return TO_TRY_PF_ERR(-EFAULT);
	}
	return TRY_PF_NO_ERR;
}

bool kvm_mtrr_check_gfn_range_consistency(struct kvm_vcpu *vcpu, gfn_t gfn,
					  int page_num)
{
	if (!is_ss(vcpu))
		return true;
	pr_err("FIXME: %s() is not implemented\n", __func__);
	return true;
}

static bool
check_hugepage_cache_consistency(struct kvm_vcpu *vcpu, gfn_t gfn, int level)
{
	int page_num = KVM_MMU_PAGES_PER_HPAGE(vcpu->kvm, level);

	gfn &= ~(page_num - 1);

	return kvm_mtrr_check_gfn_range_consistency(vcpu, gfn, page_num);
}

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

	force_pt_level = !check_hugepage_cache_consistency(vcpu, gfn,
							   PT_DIRECTORY_LEVEL);
	level = mapping_level(vcpu, gfn, &force_pt_level);
	if (likely(!force_pt_level)) {
		if (level > PT_DIRECTORY_LEVEL &&
		    !check_hugepage_cache_consistency(vcpu, gfn, level))
			level = PT_DIRECTORY_LEVEL;
		gfn &= ~(KVM_MMU_PAGES_PER_HPAGE(vcpu->kvm, level) - 1);
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
	if (!mu_state->ignore_notifier && r != PFRES_TRY_MMIO &&
			mmu_notifier_retry(vcpu->kvm, mu_state->notifier_seq))
		goto out_unlock;
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */
	make_mmu_pages_available(vcpu);
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
	KVM_BUG_ON(!mu_state->may_be_retried && !prefault);
	return PFRES_RETRY;
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */
}

static void nonpaging_init_context(struct kvm_vcpu *vcpu,
				   struct kvm_mmu *context)
{
	if (kvm_is_tdp_enable(vcpu->kvm)) {
		if (vcpu->arch.mmu.virt_ctrl_mu.rw_mmu_cr) {
			/* access to MMU_CR register is intercepted */
			/* so paging state can be accessed as soft flag */
			context->is_paging = NULL;
		} else {
			/* paging state can be accessed only though SH_MMU_CR */
			context->is_paging = kvm_mmu_is_hv_paging;
		}
	} else {
		context->is_paging = NULL;
	}
	context->set_vcpu_u_pptb = set_vcpu_nonp_u_pptb;
	context->set_vcpu_sh_u_pptb = set_vcpu_nonp_sh_u_pptb;
	context->set_vcpu_u_vptb = set_vcpu_nonp_u_vptb;
	context->set_vcpu_sh_u_vptb = set_vcpu_nonp_sh_u_vptb;
	context->set_vcpu_os_pptb = set_vcpu_nonp_os_pptb;
	context->set_vcpu_sh_os_pptb = set_vcpu_nonp_sh_os_pptb;
	context->set_vcpu_os_vptb = set_vcpu_nonp_os_vptb;
	context->set_vcpu_sh_os_vptb = set_vcpu_nonp_sh_os_vptb;
	context->set_vcpu_os_vab = set_vcpu_nonp_os_vab;
	context->set_vcpu_gp_pptb = set_vcpu_nonp_gp_pptb;
	context->get_vcpu_u_pptb = get_vcpu_nonp_u_pptb;
	context->get_vcpu_sh_u_pptb = get_vcpu_nonp_sh_u_pptb;
	context->get_vcpu_u_vptb = get_vcpu_nonp_u_vptb;
	context->get_vcpu_sh_u_vptb = get_vcpu_nonp_sh_u_vptb;
	context->get_vcpu_os_pptb = get_vcpu_nonp_os_pptb;
	context->get_vcpu_sh_os_pptb = get_vcpu_nonp_sh_os_pptb;
	context->get_vcpu_os_vptb = get_vcpu_nonp_os_vptb;
	context->get_vcpu_sh_os_vptb = get_vcpu_nonp_sh_os_vptb;
	context->get_vcpu_os_vab = get_vcpu_nonp_os_vab;
	context->get_vcpu_gp_pptb = get_vcpu_nonp_gp_pptb;
	context->set_vcpu_pt_context = set_vcpu_nonp_pt_context;
	context->init_vcpu_ptb = init_vcpu_nonp_ptb;
	context->get_vcpu_context_u_pptb = get_vcpu_context_nonp_u_pptb;
	context->get_vcpu_context_u_vptb = get_vcpu_context_nonp_u_vptb;
	context->get_vcpu_context_os_pptb = get_vcpu_context_nonp_os_pptb;
	context->get_vcpu_context_os_vptb = get_vcpu_context_nonp_os_vptb;
	context->get_vcpu_context_os_vab = get_vcpu_context_nonp_os_vab;
	context->get_vcpu_context_gp_pptb = get_vcpu_context_nonp_gp_pptb;
	context->page_fault = nonpaging_page_fault;
	context->gva_to_gpa = nonpaging_gva_to_gpa;
	context->sync_page = nonpaging_sync_page;
	context->update_pte = nonpaging_update_pte;
	context->root_level = 0;
	if (is_ss(vcpu))
		context->shadow_root_level = PT32E_ROOT_LEVEL;
	else
		context->shadow_root_level = PT64_ROOT_LEVEL;
	context->sh_os_root_hpa = E2K_INVALID_PAGE;
	context->sh_u_root_hpa = E2K_INVALID_PAGE;
	context->gp_root_hpa = E2K_INVALID_PAGE;
	context->sh_root_hpa = E2K_INVALID_PAGE;
	context->direct_map = true;
	context->nx = false;
}

void kvm_mmu_new_pptb(struct kvm_vcpu *vcpu, unsigned flags)
{
	mmu_free_roots(vcpu, flags);
}

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

#define	PTTYPE_E2K	0xe2
#define PTTYPE_EPT	18 /* arbitrary */

#define	PTTYPE		PTTYPE_E2K
#include "paging_tmpl.h"
#undef PTTYPE

#ifdef	CONFIG_X86_HW_VIRTUALIZATION
#define PTTYPE PTTYPE_EPT
#include "paging_tmpl.h"
#undef PTTYPE

#define PTTYPE 64
#include "paging_tmpl.h"
#undef PTTYPE

#define PTTYPE 32
#include "paging_tmpl.h"
#undef PTTYPE
#endif	/* CONFIG_X86_HW_VIRTUALIZATION */

#ifdef	CONFIG_X86_HW_VIRTUALIZATION
static void
__reset_rsvds_bits_mask(struct kvm_vcpu *vcpu,
			struct rsvd_bits_validate *rsvd_check,
			int maxphyaddr, int level, bool nx, bool gbpages,
			bool pse, bool amd)
{
	u64 exb_bit_rsvd = 0;
	u64 gbpages_bit_rsvd = 0;
	u64 nonleaf_bit8_rsvd = 0;

	rsvd_check->bad_mt_xwr = 0;

	if (!nx)
		exb_bit_rsvd = rsvd_bits(63, 63);
	if (!gbpages)
		gbpages_bit_rsvd = rsvd_bits(7, 7);

	/*
	 * Non-leaf PML4Es and PDPEs reserve bit 8 (which would be the G bit for
	 * leaf entries) on AMD CPUs only.
	 */
	if (amd)
		nonleaf_bit8_rsvd = rsvd_bits(8, 8);

	switch (level) {
	case PT32_ROOT_LEVEL:
		/* no rsvd bits for 2 level 4K page table entries */
		rsvd_check->rsvd_bits_mask[0][1] = 0;
		rsvd_check->rsvd_bits_mask[0][0] = 0;
		rsvd_check->rsvd_bits_mask[1][0] =
			rsvd_check->rsvd_bits_mask[0][0];

		if (!pse) {
			rsvd_check->rsvd_bits_mask[1][1] = 0;
			break;
		}

		if (is_cpuid_PSE36())
			/* 36bits PSE 4MB page */
			rsvd_check->rsvd_bits_mask[1][1] = rsvd_bits(17, 21);
		else
			/* 32 bits PSE 4MB page */
			rsvd_check->rsvd_bits_mask[1][1] = rsvd_bits(13, 21);
		break;
	case PT32E_ROOT_LEVEL:
		rsvd_check->rsvd_bits_mask[0][2] =
			rsvd_bits(maxphyaddr, 63) |
			rsvd_bits(5, 8) | rsvd_bits(1, 2);	/* PDPTE */
		rsvd_check->rsvd_bits_mask[0][1] = exb_bit_rsvd |
			rsvd_bits(maxphyaddr, 62);	/* PDE */
		rsvd_check->rsvd_bits_mask[0][0] = exb_bit_rsvd |
			rsvd_bits(maxphyaddr, 62);	/* PTE */
		rsvd_check->rsvd_bits_mask[1][1] = exb_bit_rsvd |
			rsvd_bits(maxphyaddr, 62) |
			rsvd_bits(13, 20);		/* large page */
		rsvd_check->rsvd_bits_mask[1][0] =
			rsvd_check->rsvd_bits_mask[0][0];
		break;
	case PT64_ROOT_LEVEL:
		rsvd_check->rsvd_bits_mask[0][3] = exb_bit_rsvd |
			nonleaf_bit8_rsvd | rsvd_bits(7, 7) |
			rsvd_bits(maxphyaddr, 51);
		rsvd_check->rsvd_bits_mask[0][2] = exb_bit_rsvd |
			nonleaf_bit8_rsvd | gbpages_bit_rsvd |
			rsvd_bits(maxphyaddr, 51);
		rsvd_check->rsvd_bits_mask[0][1] = exb_bit_rsvd |
			rsvd_bits(maxphyaddr, 51);
		rsvd_check->rsvd_bits_mask[0][0] = exb_bit_rsvd |
			rsvd_bits(maxphyaddr, 51);
		rsvd_check->rsvd_bits_mask[1][3] =
			rsvd_check->rsvd_bits_mask[0][3];
		rsvd_check->rsvd_bits_mask[1][2] = exb_bit_rsvd |
			gbpages_bit_rsvd | rsvd_bits(maxphyaddr, 51) |
			rsvd_bits(13, 29);
		rsvd_check->rsvd_bits_mask[1][1] = exb_bit_rsvd |
			rsvd_bits(maxphyaddr, 51) |
			rsvd_bits(13, 20);		/* large page */
		rsvd_check->rsvd_bits_mask[1][0] =
			rsvd_check->rsvd_bits_mask[0][0];
		break;
	}
}

static void reset_rsvds_bits_mask(struct kvm_vcpu *vcpu,
				  struct kvm_mmu *context)
{
	__reset_rsvds_bits_mask(vcpu, &context->guest_rsvd_check,
				cpuid_maxphyaddr(vcpu), context->root_level,
				context->nx, guest_cpuid_has_gbpages(vcpu),
				is_pse(vcpu), guest_cpuid_is_amd(vcpu));
}

static void
__reset_rsvds_bits_mask_ept(struct rsvd_bits_validate *rsvd_check,
			    int maxphyaddr, bool execonly)
{
	u64 bad_mt_xwr;

	rsvd_check->rsvd_bits_mask[0][3] =
		rsvd_bits(maxphyaddr, 51) | rsvd_bits(3, 7);
	rsvd_check->rsvd_bits_mask[0][2] =
		rsvd_bits(maxphyaddr, 51) | rsvd_bits(3, 6);
	rsvd_check->rsvd_bits_mask[0][1] =
		rsvd_bits(maxphyaddr, 51) | rsvd_bits(3, 6);
	rsvd_check->rsvd_bits_mask[0][0] = rsvd_bits(maxphyaddr, 51);

	/* large page */
	rsvd_check->rsvd_bits_mask[1][3] = rsvd_check->rsvd_bits_mask[0][3];
	rsvd_check->rsvd_bits_mask[1][2] =
		rsvd_bits(maxphyaddr, 51) | rsvd_bits(12, 29);
	rsvd_check->rsvd_bits_mask[1][1] =
		rsvd_bits(maxphyaddr, 51) | rsvd_bits(12, 20);
	rsvd_check->rsvd_bits_mask[1][0] = rsvd_check->rsvd_bits_mask[0][0];

	bad_mt_xwr = 0xFFull << (2 * 8);	/* bits 3..5 must not be 2 */
	bad_mt_xwr |= 0xFFull << (3 * 8);	/* bits 3..5 must not be 3 */
	bad_mt_xwr |= 0xFFull << (7 * 8);	/* bits 3..5 must not be 7 */
	bad_mt_xwr |= REPEAT_BYTE(1ull << 2);	/* bits 0..2 must not be 010 */
	bad_mt_xwr |= REPEAT_BYTE(1ull << 6);	/* bits 0..2 must not be 110 */
	if (!execonly) {
		/* bits 0..2 must not be 100 unless VMX capabilities allow it */
		bad_mt_xwr |= REPEAT_BYTE(1ull << 4);
	}
	rsvd_check->bad_mt_xwr = bad_mt_xwr;
}

static void reset_rsvds_bits_mask_ept(struct kvm_vcpu *vcpu,
		struct kvm_mmu *context, bool execonly)
{
	__reset_rsvds_bits_mask_ept(&context->guest_rsvd_check,
				    cpuid_maxphyaddr(vcpu), execonly);
}

/*
 * the page table on host is the shadow page table for the page
 * table in guest or amd nested guest, its mmu features completely
 * follow the features in guest.
 */
void
reset_shadow_zero_bits_mask(struct kvm_vcpu *vcpu, struct kvm_mmu *context)
{
	bool uses_nx = context->nx || context->base_role.smep_andnot_wp;

	/*
	 * Passing "true" to the last argument is okay; it adds a check
	 * on bit 8 of the SPTEs which KVM doesn't use anyway.
	 */
	__reset_rsvds_bits_mask(vcpu, &context->shadow_zero_check,
				boot_cpu_data.x86_phys_bits,
				context->shadow_root_level, uses_nx,
				guest_cpuid_has_gbpages(vcpu), is_pse(vcpu),
				true);
}
EXPORT_SYMBOL_GPL(reset_shadow_zero_bits_mask);

static inline bool boot_cpu_is_amd(void)
{
	WARN_ON_ONCE(!tdp_enabled);
	return shadow_x_mask == 0;
}

/*
 * the direct page table on host, use as much mmu features as
 * possible, however, kvm currently does not do execution-protection.
 */
static void
reset_tdp_shadow_zero_bits_mask(struct kvm_vcpu *vcpu,
				struct kvm_mmu *context)
{
	if (boot_cpu_is_amd())
		__reset_rsvds_bits_mask(vcpu, &context->shadow_zero_check,
					boot_cpu_data.x86_phys_bits,
					context->shadow_root_level, false,
					boot_cpu_has(X86_FEATURE_GBPAGES),
					true, true);
	else
		__reset_rsvds_bits_mask_ept(&context->shadow_zero_check,
					    boot_cpu_data.x86_phys_bits,
					    false);

}

/*
 * as the comments in reset_shadow_zero_bits_mask() except it
 * is the shadow page table for intel nested guest.
 */
static void
reset_ept_shadow_zero_bits_mask(struct kvm_vcpu *vcpu,
				struct kvm_mmu *context, bool execonly)
{
	__reset_rsvds_bits_mask_ept(&context->shadow_zero_check,
				    boot_cpu_data.x86_phys_bits, execonly);
}

static void update_permission_bitmask(struct kvm_vcpu *vcpu,
				      struct kvm_mmu *mmu, bool ept)
{
	unsigned bit, byte, pfec;
	u8 map;
	bool fault, x, w, u, wf, uf, ff, smapf, cr4_smap, cr4_smep, smap = 0;

	cr4_smep = kvm_read_cr4_bits(vcpu, X86_CR4_SMEP);
	cr4_smap = kvm_read_cr4_bits(vcpu, X86_CR4_SMAP);
	for (byte = 0; byte < ARRAY_SIZE(mmu->permissions); ++byte) {
		pfec = byte << 1;
		map = 0;
		wf = pfec & PFERR_WRITE_MASK;
		uf = pfec & PFERR_USER_MASK;
		ff = pfec & PFERR_FETCH_MASK;
		/*
		 * PFERR_RSVD_MASK bit is set in PFEC if the access is not
		 * subject to SMAP restrictions, and cleared otherwise. The
		 * bit is only meaningful if the SMAP bit is set in CR4.
		 */
		smapf = !(pfec & PFERR_RSVD_MASK);
		for (bit = 0; bit < 8; ++bit) {
			x = bit & ACC_EXEC_MASK;
			w = bit & ACC_WRITE_MASK;
			u = bit & ACC_USER_MASK;

			if (!ept) {
				/* Not really needed: !nx will cause pte.nx */
				/* to fault */
				x |= !mmu->nx;
				/* Allow supervisor writes if !cr0.wp */
				w |= !is_write_protection(vcpu) && !uf;
				/* Disallow supervisor fetches of user code */
				/* if cr4.smep */
				x &= !(cr4_smep && u && !uf);

				/*
				 * SMAP:kernel-mode data accesses from user-mode
				 * mappings should fault. A fault is considered
				 * as a SMAP violation if all of the following
				 * conditions are ture:
				 *   - X86_CR4_SMAP is set in CR4
				 *   - An user page is accessed
				 *   - Page fault in kernel mode
				 *   - if CPL = 3 or X86_EFLAGS_AC is clear
				 *
				 *   Here, we cover the first three conditions.
				 *   The fourth is computed dynamically in
				 *   permission_fault() and is in smapf.
				 *
				 *   Also, SMAP does not affect instruction
				 *   fetches, add the !ff check here to make it
				 *   clearer.
				 */
				smap = cr4_smap && u && !uf && !ff;
			}

			fault = (ff && !x) || (uf && !u) || (wf && !w) ||
				(smapf && smap);
			map |= fault << bit;
		}
		mmu->permissions[byte] = map;
	}
}

/*
* PKU is an additional mechanism by which the paging controls access to
* user-mode addresses based on the value in the PKRU register.  Protection
* key violations are reported through a bit in the page fault error code.
* Unlike other bits of the error code, the PK bit is not known at the
* call site of e.g. gva_to_gpa; it must be computed directly in
* permission_fault based on two bits of PKRU, on some machine state (CR4,
* CR0, EFER, CPL), and on other bits of the error code and the page tables.
*
* In particular the following conditions come from the error code, the
* page tables and the machine state:
* - PK is always zero unless CR4.PKE=1 and EFER.LMA=1
* - PK is always zero if RSVD=1 (reserved bit set) or F=1 (instruction fetch)
* - PK is always zero if U=0 in the page tables
* - PKRU.WD is ignored if CR0.WP=0 and the access is a supervisor access.
*
* The PKRU bitmask caches the result of these four conditions.  The error
* code (minus the P bit) and the page table's U bit form an index into the
* PKRU bitmask.  Two bits of the PKRU bitmask are then extracted and ANDed
* with the two bits of the PKRU register corresponding to the protection key.
* For the first three conditions above the bits will be 00, thus masking
* away both AD and WD.  For all reads or if the last condition holds, WD
* only will be masked away.
*/
static void update_pkru_bitmask(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
				bool ept)
{
	unsigned bit;
	bool wp;

	if (ept) {
		mmu->pkru_mask = 0;
		return;
	}

	/* PKEY is enabled only if CR4.PKE and EFER.LMA are both set. */
	if (!kvm_read_cr4_bits(vcpu, X86_CR4_PKE) || !is_long_mode(vcpu)) {
		mmu->pkru_mask = 0;
		return;
	}

	wp = is_write_protection(vcpu);

	for (bit = 0; bit < ARRAY_SIZE(mmu->permissions); ++bit) {
		unsigned pfec, pkey_bits;
		bool check_pkey, check_write, ff, uf, wf, pte_user;

		pfec = bit << 1;
		ff = pfec & PFERR_FETCH_MASK;
		uf = pfec & PFERR_USER_MASK;
		wf = pfec & PFERR_WRITE_MASK;

		/* PFEC.RSVD is replaced by ACC_USER_MASK. */
		pte_user = pfec & PFERR_RSVD_MASK;

		/*
		 * Only need to check the access which is not an
		 * instruction fetch and is to a user page.
		 */
		check_pkey = (!ff && pte_user);
		/*
		 * write access is controlled by PKRU if it is a
		 * user access or CR0.WP = 1.
		 */
		check_write = check_pkey && wf && (uf || wp);

		/* PKRU.AD stops both read and write access. */
		pkey_bits = !!check_pkey;
		/* PKRU.WD stops write access. */
		pkey_bits |= (!!check_write) << 1;

		mmu->pkru_mask |= (pkey_bits & 3) << pfec;
	}
}
#else	/* ! CONFIG_X86_HW_VIRTUALIZATION */

static void reset_rsvds_bits_mask(struct kvm_vcpu *vcpu,
					struct kvm_mmu *context)
{
	if (is_ss(vcpu))
		pr_err("FIXME: %s() is not implemented\n", __func__);
}
static void update_permission_bitmask(struct kvm_vcpu *vcpu,
					struct kvm_mmu *context, bool ept)
{
	if (is_ss(vcpu))
		pr_err("FIXME: %s() is not implemented\n", __func__);
}
static void update_pkru_bitmask(struct kvm_vcpu *vcpu,
					struct kvm_mmu *context, bool ept)
{
	if (is_ss(vcpu))
		pr_err("FIXME: %s() is not implemented\n", __func__);
}
static void reset_tdp_shadow_zero_bits_mask(struct kvm_vcpu *vcpu,
				struct kvm_mmu *context)
{
	if (is_ss(vcpu))
		pr_err("FIXME: %s() is not implemented\n", __func__);
}
void
reset_shadow_zero_bits_mask(struct kvm_vcpu *vcpu, struct kvm_mmu *context)
{
	if (is_ss(vcpu))
		pr_err("FIXME: %s() is not implemented\n", __func__);
}
#endif	/* CONFIG_X86_HW_VIRTUALIZATION */

static void update_last_nonleaf_level(struct kvm_vcpu *vcpu,
						struct kvm_mmu *mmu)
{
	unsigned root_level = mmu->root_level;

	mmu->last_nonleaf_level = root_level;
	if (root_level == PT32_ROOT_LEVEL && is_pse(vcpu))
		mmu->last_nonleaf_level++;
}

static void e2k_paging_init_context_common(struct kvm_vcpu *vcpu,
					 struct kvm_mmu *context,
					 int level)
{
	DebugKVM("started on VCPU #%d\n", vcpu->vcpu_id);
	context->nx = is_nx(vcpu);
	context->root_level = level;

	reset_rsvds_bits_mask(vcpu, context);
	update_permission_bitmask(vcpu, context, false);
	update_pkru_bitmask(vcpu, context, false);
	update_last_nonleaf_level(vcpu, context);

	context->is_paging = NULL;
	context->set_vcpu_u_pptb = set_vcpu_spt_u_pptb;
	context->set_vcpu_sh_u_pptb = set_vcpu_spt_sh_u_pptb;
	context->set_vcpu_u_vptb = set_vcpu_spt_u_vptb;
	context->set_vcpu_sh_u_vptb = set_vcpu_spt_sh_u_vptb;
	context->set_vcpu_os_pptb = set_vcpu_spt_os_pptb;
	context->set_vcpu_sh_os_pptb = set_vcpu_spt_sh_os_pptb;
	context->set_vcpu_os_vptb = set_vcpu_spt_os_vptb;
	context->set_vcpu_sh_os_vptb = set_vcpu_spt_sh_os_vptb;
	context->set_vcpu_os_vab = set_vcpu_spt_os_vab;
	context->set_vcpu_gp_pptb = set_vcpu_spt_gp_pptb;
	context->get_vcpu_u_pptb = get_vcpu_spt_u_pptb;
	context->get_vcpu_sh_u_pptb = get_vcpu_spt_sh_u_pptb;
	context->get_vcpu_u_vptb = get_vcpu_spt_u_vptb;
	context->get_vcpu_sh_u_vptb = get_vcpu_spt_sh_u_vptb;
	context->get_vcpu_os_pptb = get_vcpu_spt_os_pptb;
	context->get_vcpu_sh_os_pptb = get_vcpu_spt_sh_os_pptb;
	context->get_vcpu_os_vptb = get_vcpu_spt_os_vptb;
	context->get_vcpu_sh_os_vptb = get_vcpu_spt_sh_os_vptb;
	context->get_vcpu_os_vab = get_vcpu_spt_os_vab;
	context->get_vcpu_gp_pptb = get_vcpu_spt_gp_pptb;
	context->set_vcpu_pt_context = set_vcpu_spt_pt_context;
	context->init_vcpu_ptb = init_vcpu_spt_ptb;
	context->get_vcpu_context_u_pptb = get_vcpu_context_spt_u_pptb;
	context->get_vcpu_context_u_vptb = get_vcpu_context_spt_u_vptb;
	context->get_vcpu_context_os_pptb = get_vcpu_context_spt_os_pptb;
	context->get_vcpu_context_os_vptb = get_vcpu_context_spt_os_vptb;
	context->get_vcpu_context_os_vab = get_vcpu_context_spt_os_vab;
	context->get_vcpu_context_gp_pptb = get_vcpu_context_spt_gp_pptb;
	context->page_fault = e2k_page_fault;
	context->gva_to_gpa = e2k_gva_to_gpa;
	context->sync_page = e2k_sync_page;
	context->sync_gva = e2k_sync_gva;
	context->sync_gva_range = e2k_sync_gva_range;
	context->update_pte = e2k_update_pte;
	context->shadow_root_level = level;
	context->sh_os_root_hpa = E2K_INVALID_PAGE;
	context->sh_u_root_hpa = E2K_INVALID_PAGE;
	context->direct_map = false;
}

static void e2k_paging_init_context(struct kvm_vcpu *vcpu,
				  struct kvm_mmu *context)
{
	e2k_paging_init_context_common(vcpu, context, PT_E2K_ROOT_LEVEL);
}

#ifdef	CONFIG_X86_HW_VIRTUALIZATION
static void paging64_init_context_common(struct kvm_vcpu *vcpu,
					 struct kvm_mmu *context,
					 int level)
{
	context->nx = is_nx(vcpu);
	context->root_level = level;

	reset_rsvds_bits_mask(vcpu, context);
	update_permission_bitmask(vcpu, context, false);
	update_pkru_bitmask(vcpu, context, false);
	update_last_nonleaf_level(vcpu, context);

	MMU_WARN_ON(!is_pae(vcpu));
	context->page_fault = paging64_page_fault;
	context->gva_to_gpa = paging64_gva_to_gpa;
	context->sync_page = paging64_sync_page;
	context->sync_gva = paging64_sync_gva;
	context->sync_gva_range = paging64_sync_gva_range;
	context->update_pte = paging64_update_pte;
	context->shadow_root_level = level;
	context->os_root_hpa = E2K_INVALID_PAGE;
	context->u_root_hpa = E2K_INVALID_PAGE;
	context->direct_map = false;
}

static void paging64_init_context(struct kvm_vcpu *vcpu,
				  struct kvm_mmu *context)
{
	paging64_init_context_common(vcpu, context, PT64_ROOT_LEVEL);
}

static void paging32_init_context(struct kvm_vcpu *vcpu,
				  struct kvm_mmu *context)
{
	context->nx = false;
	context->root_level = PT32_ROOT_LEVEL;

	reset_rsvds_bits_mask(vcpu, context);
	update_permission_bitmask(vcpu, context, false);
	update_pkru_bitmask(vcpu, context, false);
	update_last_nonleaf_level(vcpu, context);

	context->page_fault = paging32_page_fault;
	context->gva_to_gpa = paging32_gva_to_gpa;
	context->sync_page = paging32_sync_page;
	context->sync_gva = paging32_sync_gva;
	context->sync_gva_range = paging32_sync_gva_range;
	context->update_pte = paging32_update_pte;
	context->shadow_root_level = PT32E_ROOT_LEVEL;
	context->os_root_hpa = E2K_INVALID_PAGE;
	context->u_root_hpa = E2K_INVALID_PAGE;
	context->direct_map = false;
}

static void paging32E_init_context(struct kvm_vcpu *vcpu,
				   struct kvm_mmu *context)
{
	paging64_init_context_common(vcpu, context, PT32E_ROOT_LEVEL);
}
#else	/* ! CONFIG_X86_HW_VIRTUALIZATION */

static void paging64_init_context(struct kvm_vcpu *vcpu,
				  struct kvm_mmu *context)
{
	if (is_ss(vcpu))
		panic("FIXME: %s() is not yet implemented\n", __func__);
	else
		panic("FIXME: %s() secondary space support is not yet "
			"implemented\n", __func__);
}
static void paging32_init_context(struct kvm_vcpu *vcpu,
				  struct kvm_mmu *context)
{
	if (is_ss(vcpu))
		panic("FIXME: %s() is not yet implemented\n", __func__);
	else
		panic("FIXME: %s() secondary space support is not yet "
			"implemented\n", __func__);
}

static void paging32E_init_context(struct kvm_vcpu *vcpu,
				   struct kvm_mmu *context)
{
	if (is_ss(vcpu))
		panic("FIXME: %s() is not yet implemented\n", __func__);
	else
		panic("FIXME: %s() secondary space support is not yet "
			"implemented\n", __func__);
}
#endif	/* CONFIG_X86_HW_VIRTUALIZATION */

static void init_kvm_nonpaging_mmu(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *context = &vcpu->arch.mmu;

	DebugKVM("started on VCPU #%d is PV %s, is HV %s\n",
		vcpu->vcpu_id,
		(vcpu->arch.is_pv) ? "true" : "false",
		(vcpu->arch.is_hv) ? "true" : "false");

	KVM_BUG_ON(is_paging(vcpu));

	nonpaging_init_context(vcpu, context);
}

static void init_kvm_tdp_mmu(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *context = &vcpu->arch.mmu;

	DebugTDP("started on VCPU #%d\n", vcpu->vcpu_id);

	context->base_role.word = 0;
	context->base_role.smm = is_smm(vcpu);
	context->page_fault = tdp_page_fault;
	context->sync_page = nonpaging_sync_page;
	context->sync_gva = nonpaging_sync_gva;
	context->sync_gva_range = nonpaging_sync_gva_range;
	context->update_pte = nonpaging_update_pte;
	context->shadow_root_level = get_tdp_root_level();
	if (!is_paging(vcpu)) {
		context->sh_os_root_hpa = E2K_INVALID_PAGE;
		context->sh_u_root_hpa = E2K_INVALID_PAGE;
	}
	context->direct_map = true;
	if (vcpu->arch.mmu.virt_ctrl_mu.rw_mmu_cr) {
		/* access to MMU_CR register is intercepted */
		/* so paging state can be accessed as soft flag */
		context->is_paging = NULL;
	} else {
		/* paging state can be accessed only though SH_MMU_CR */
		context->is_paging = kvm_mmu_is_hv_paging;
	}
	context->set_vcpu_u_pptb = set_vcpu_tdp_u_pptb;
	context->set_vcpu_sh_u_pptb = set_vcpu_tdp_sh_u_pptb;
	context->set_vcpu_u_vptb = set_vcpu_tdp_u_vptb;
	context->set_vcpu_sh_u_vptb = set_vcpu_tdp_sh_u_vptb;
	context->set_vcpu_os_pptb = set_vcpu_tdp_os_pptb;
	context->set_vcpu_sh_os_pptb = set_vcpu_tdp_sh_os_pptb;
	context->set_vcpu_os_vptb = set_vcpu_tdp_os_vptb;
	context->set_vcpu_sh_os_vptb = set_vcpu_tdp_sh_os_vptb;
	context->set_vcpu_os_vab = set_vcpu_tdp_os_vab;
	context->set_vcpu_gp_pptb = set_vcpu_tdp_gp_pptb;
	if (vcpu->arch.mmu.virt_ctrl_mu.rw_pptb) {
		/* access to PT context registers are intercepted */
		/* so PT context have copy at MMU soft structure */
		context->get_vcpu_u_pptb = get_vcpu_tdp_u_pptb;
		context->get_vcpu_u_vptb = get_vcpu_tdp_u_vptb;
		context->get_vcpu_os_pptb = get_vcpu_tdp_os_pptb;
		context->get_vcpu_os_vptb = get_vcpu_tdp_os_vptb;
		context->get_vcpu_os_vab = get_vcpu_tdp_os_vab;
		context->get_vcpu_gp_pptb = get_vcpu_tdp_gp_pptb;
	} else {
		/* PT context registers only on shadow registers */
		context->get_vcpu_u_pptb = get_vcpu_context_tdp_u_pptb;
		context->get_vcpu_u_vptb = get_vcpu_context_tdp_u_vptb;
		context->get_vcpu_os_pptb = get_vcpu_context_tdp_os_pptb;
		context->get_vcpu_os_vptb = get_vcpu_context_tdp_os_vptb;
		context->get_vcpu_os_vab = get_vcpu_context_tdp_os_vab;
		context->get_vcpu_gp_pptb = get_vcpu_context_tdp_gp_pptb;
	}
	context->get_vcpu_sh_u_pptb = get_vcpu_tdp_sh_u_pptb;
	context->get_vcpu_sh_u_vptb = get_vcpu_tdp_sh_u_vptb;
	context->get_vcpu_sh_os_pptb = get_vcpu_tdp_sh_os_pptb;
	context->get_vcpu_sh_os_vptb = get_vcpu_tdp_sh_os_vptb;
	context->set_vcpu_pt_context = set_vcpu_tdp_pt_context;
	context->init_vcpu_ptb = init_vcpu_tdp_ptb;
	context->get_vcpu_context_u_pptb = get_vcpu_context_tdp_u_pptb;
	context->get_vcpu_context_u_vptb = get_vcpu_context_tdp_u_vptb;
	context->get_vcpu_context_os_pptb = get_vcpu_context_tdp_os_pptb;
	context->get_vcpu_context_os_vptb = get_vcpu_context_tdp_os_vptb;
	context->get_vcpu_context_os_vab = get_vcpu_context_tdp_os_vab;
	context->get_vcpu_context_gp_pptb = get_vcpu_context_tdp_gp_pptb;
	context->get_vcpu_pdpte = get_vcpu_pdpte;
	context->inject_page_fault = NULL;

	if (!is_paging(vcpu)) {
		context->nx = false;
		context->gva_to_gpa = nonpaging_gva_to_gpa;
		context->root_level = 0;
	} else if (!is_ss(vcpu)) {
		context->nx = is_nx(vcpu);
		context->root_level = PT_E2K_ROOT_LEVEL;
		reset_rsvds_bits_mask(vcpu, context);
		context->gva_to_gpa = e2k_gva_to_gpa;
#ifdef	CONFIG_X86_HW_VIRTUALIZATION
	} else if (is_long_mode(vcpu)) {
		context->nx = is_nx(vcpu);
		context->root_level = PT64_ROOT_LEVEL;
		reset_rsvds_bits_mask(vcpu, context);
		context->gva_to_gpa = paging64_gva_to_gpa;
	} else if (is_pae(vcpu)) {
		context->nx = is_nx(vcpu);
		context->root_level = PT32E_ROOT_LEVEL;
		reset_rsvds_bits_mask(vcpu, context);
		context->gva_to_gpa = paging64_gva_to_gpa;
	} else {
		context->nx = false;
		context->root_level = PT32_ROOT_LEVEL;
		reset_rsvds_bits_mask(vcpu, context);
		context->gva_to_gpa = paging32_gva_to_gpa;
#endif	/* CONFIG_X86_HW_VIRTUALIZATION */
	}

	update_permission_bitmask(vcpu, context, false);
	update_pkru_bitmask(vcpu, context, false);
	update_last_nonleaf_level(vcpu, context);
	reset_tdp_shadow_zero_bits_mask(vcpu, context);
}

void kvm_init_shadow_mmu(struct kvm_vcpu *vcpu)
{
	bool smep = is_smep(vcpu);
	bool smap = is_smap(vcpu);
	struct kvm_mmu *context = &vcpu->arch.mmu;

	DebugKVM("started on VCPU #%d is PV %s, is HV %s\n",
		vcpu->vcpu_id,
		(vcpu->arch.is_pv) ? "true" : "false",
		(vcpu->arch.is_hv) ? "true" : "false");

	mmu_check_invalid_roots(vcpu, true /* invalid */,
				OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG);

	if (!is_paging(vcpu))
		nonpaging_init_context(vcpu, context);
	else if (!is_ss(vcpu))
		e2k_paging_init_context(vcpu, context);
	else if (is_long_mode(vcpu))
		paging64_init_context(vcpu, context);
	else if (is_pae(vcpu))
		paging32E_init_context(vcpu, context);
	else
		paging32_init_context(vcpu, context);

	context->base_role.nxe = is_nx(vcpu);
	context->base_role.cr4_pae = !!is_pae(vcpu);
	context->base_role.cr0_wp  = is_write_protection(vcpu);
	context->base_role.smep_andnot_wp
		= smep && !is_write_protection(vcpu);
	context->base_role.smap_andnot_wp
		= smap && !is_write_protection(vcpu);
	context->base_role.smm = is_smm(vcpu);
	reset_shadow_zero_bits_mask(vcpu, context);
}
EXPORT_SYMBOL_GPL(kvm_init_shadow_mmu);

#ifdef	CONFIG_X86_EPT_MMU
void kvm_init_shadow_ept_mmu(struct kvm_vcpu *vcpu, bool execonly)
{
	struct kvm_mmu *context = &vcpu->arch.mmu;

	MMU_WARN_ON(VALID_PAGE(context->root_hpa));

	context->shadow_root_level = get_tdp_root_level();

	context->nx = true;
	context->page_fault = ept_page_fault;
	context->gva_to_gpa = ept_gva_to_gpa;
	context->sync_page = ept_sync_page;
	context->sync_gva = ept_sync_gva;
	context->sync_gva_range = ept_sync_gva_range;
	context->update_pte = ept_update_pte;
	context->root_level = context->shadow_root_level;
	context->root_hpa = E2K_INVALID_PAGE;
	context->direct_map = false;

	update_permission_bitmask(vcpu, context, true);
	update_pkru_bitmask(vcpu, context, true);
	reset_rsvds_bits_mask_ept(vcpu, context, execonly);
	reset_ept_shadow_zero_bits_mask(vcpu, context, execonly);
}
#else	/* ! CONFIG_X86_EPT_MMU */
void kvm_init_shadow_ept_mmu(struct kvm_vcpu *vcpu, bool execonly)
{
	pr_err("%s() is not supported on e2k arch\n", __func__);
}
#endif	/* CONFIG_X86_EPT_MMU */
EXPORT_SYMBOL_GPL(kvm_init_shadow_ept_mmu);

static void init_kvm_softmmu(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *context = &vcpu->arch.mmu;

	DebugKVM("started on VCPU #%d\n", vcpu->vcpu_id);
	kvm_init_shadow_mmu(vcpu);
	if (vcpu->arch.is_hv) {
		context->inject_page_fault = inject_shadow_page_fault;
	} else if (vcpu->arch.is_pv) {
		/* the function to inject depends on fault type */
		/* and will be called directly from page fault handler */
		context->inject_page_fault = NULL;
	} else {
		KVM_BUG_ON(true);
	}
}

static void init_kvm_mmu(struct kvm_vcpu *vcpu)
{
	if (!is_paging(vcpu)) {
		init_kvm_nonpaging_mmu(vcpu);
	} else if (tdp_enabled) {
		init_kvm_tdp_mmu(vcpu);
	} else {
		init_kvm_softmmu(vcpu);
	}
}

void kvm_mmu_reset_context(struct kvm_vcpu *vcpu, unsigned flags)
{
	kvm_mmu_unload(vcpu, flags);
	init_kvm_mmu(vcpu);
}
EXPORT_SYMBOL_GPL(kvm_mmu_reset_context);

int kvm_mmu_load(struct kvm_vcpu *vcpu, gmm_struct_t *gmm, unsigned flags)
{
	int r;

	DebugSYNC("started on VCPU #%d\n", vcpu->vcpu_id);
	r = mmu_topup_memory_caches(vcpu);
	if (r)
		goto out;
	if (vcpu->arch.mmu.direct_map) {
		r = mmu_alloc_direct_roots(vcpu);
	} else {
		r = mmu_alloc_shadow_roots(vcpu, gmm, flags);
	}
	kvm_mmu_sync_roots(vcpu, flags);
	if (r)
		goto out;
	/* set_vcpu_pptb() should ensure TLB has been flushed */
	/* FIXME: guest U_PPTB register should point to physical base of */
	/* guest PT, so I do not understand why the follow setting
	vcpu->arch.mmu.set_vcpu_pptb(vcpu, vcpu->arch.mmu.root_hpa);
	 */
out:
	return r;
}
EXPORT_SYMBOL_GPL(kvm_mmu_load);

void kvm_mmu_unload(struct kvm_vcpu *vcpu, unsigned flags)
{
	mmu_free_roots(vcpu, flags);
	mmu_check_invalid_roots(vcpu, true /* invalid ? */, flags);
}
EXPORT_SYMBOL_GPL(kvm_mmu_unload);

static void kvm_invalidate_all_roots(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int r;

	kvm_for_each_vcpu(r, vcpu, kvm) {
		kvm_set_gp_phys_root(vcpu, E2K_INVALID_PAGE);
		if (is_shadow_paging(vcpu)) {
			kvm_set_space_type_spt_u_root(vcpu, E2K_INVALID_PAGE);
			kvm_set_space_type_spt_os_root(vcpu, E2K_INVALID_PAGE);
		}
	}
}

static void mmu_pte_write_new_pte(struct kvm_vcpu *vcpu, struct gmm_struct *gmm,
				  struct kvm_mmu_page *sp, pgprot_t *spte,
				  gpa_t gpa, const void *new)
{
	DebugPTE("started for spte at %px == 0x%lx, new %px == 0x%lx\n",
		spte, pgprot_val(*spte), new, pgprot_val(*(pgprot_t *)new));
	if (sp->role.level != PT_PAGE_TABLE_LEVEL) {
		int ret;

		++vcpu->kvm->stat.mmu_pde_zapped;
		DebugPTE("PT level %d is not pte level, it need set pde\n",
			sp->role.level);
		spin_unlock(&vcpu->kvm->mmu_lock);
		ret = e2k_shadow_pt_protection_fault(vcpu, gmm, gpa, sp);
		KVM_BUG_ON(ret < 0);
		DebugPTE("set PDE spte at %px == 0x%lx\n",
			spte, pgprot_val(*spte));
		spin_lock(&vcpu->kvm->mmu_lock);
		return;
	}
	++vcpu->kvm->stat.mmu_pte_updated;
	DebugPTE("set PTE spte at %px == 0x%lx\n",
		spte, pgprot_val(*spte));
	vcpu->arch.mmu.update_pte(vcpu, sp, spte, new);
	DebugPTE("updated to new spte at %px == 0x%lx\n",
		spte, pgprot_val(*spte));
}

static bool need_remote_flush(struct kvm *kvm, pgprot_t old, pgprot_t new)
{
	if (!is_shadow_present_pte(kvm, old))
		return false;
	if (!is_shadow_present_pte(kvm, new))
		return true;
	if ((pgprot_val(old) ^ pgprot_val(new)) & kvm_get_spte_pfn_mask(kvm))
		return true;
	pgprot_val(old) ^= get_spte_nx_mask(kvm);
	pgprot_val(new) ^= get_spte_nx_mask(kvm);
	return (pgprot_val(old) & ~pgprot_val(new) & PT64_PERM_MASK(kvm)) != 0;
}

static pgprotval_t mmu_pte_write_fetch_gpte(struct kvm_vcpu *vcpu, gpa_t *gpa,
				    const u8 *new, int *bytes)
{
	pgprotval_t gentry;
	int r;

	/*
	 * Assume that the pte write on a page table of the same type
	 * as the current vcpu paging mode since we update the sptes only
	 * when they have the same mode.
	 */
	if (is_pae(vcpu) && *bytes == 4) {
		/* Handle a 32-bit guest writing two halves of a 64-bit gpte */
		*gpa &= ~(gpa_t)7;
		*bytes = 8;
		r = kvm_vcpu_read_guest(vcpu, *gpa, &gentry, 8);
		if (r)
			gentry = 0;
		new = (const u8 *)&gentry;
	}

	switch (*bytes) {
	case 4:
		gentry = *(const u32 *)new;
		break;
	case 8:
		gentry = *(const u64 *)new;
		break;
	default:
		gentry = 0;
		break;
	}

	return gentry;
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
		/*
		 * A 32-bit pde maps 4MB while the shadow pdes map
		 * only 2MB.  So we need to double the offset again
		 * and zap two pdes instead of one.
		 */
		if (level == PT32_ROOT_LEVEL) {
			page_offset &= ~7; /* kill rounding error */
			page_offset <<= 1;
			*nspte = 2;
		}
		quadrant = page_offset >> PAGE_SHIFT;
		page_offset &= ~PAGE_MASK;
		if (quadrant != sp->role.quadrant)
			return NULL;
	}

	spte = &sp->spt[page_offset / sizeof(*spte)];
	return spte;
}

static void kvm_mmu_pte_write(struct kvm_vcpu *vcpu, struct gmm_struct *gmm,
				gpa_t gpa, const u8 *new, int bytes)
{
	gfn_t gfn = gpa_to_gfn(gpa), new_gfn;
	struct kvm_mmu_page *sp;
	LIST_HEAD(invalid_list);
	pgprot_t entry, *spte;
	pgprotval_t gentry;
	int npte;
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
	new_gfn = gpa_to_gfn(
			kvm_gpte_gfn_to_phys_addr(vcpu, __pgprot(gentry)));
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

	for_each_gfn_indirect_valid_sp(vcpu->kvm, sp, gfn) {
		DebugPTE("found SP at %px mapped gva from 0x%lx, gfn 0x%llx\n",
			sp, sp->gva, gfn);

		spte = get_written_sptes(sp, gpa, &npte);
		if (!spte)
			continue;

		DebugPTE("GPA 0x%llx mapped by spte %px == 0x%lx, ptes %d\n",
			gpa, spte, pgprot_val(*spte), npte);

		local_flush = true;
		while (npte--) {
			struct kvm_mmu_page *child;

			entry = *spte;
			child = mmu_page_zap_pte(vcpu->kvm, sp, spte);
			if (gentry &&
			      !((sp->role.word ^ vcpu->arch.mmu.base_role.word)
			      & mask.word) && rmap_can_add(vcpu)) {
				mmu_pte_write_new_pte(vcpu, gmm, sp, spte,
							gpa, &gentry);
			}
			if (child && (child->gfn != new_gfn)) {
				child->released = true;
				kvm_mmu_prepare_zap_page(vcpu->kvm, child,
							&invalid_list);
			}
			if (need_remote_flush(vcpu->kvm, entry, *spte))
				remote_flush = true;
			++spte;
		}
	}
	kvm_mmu_flush_or_zap(vcpu, &invalid_list, remote_flush, local_flush);
	kvm_mmu_audit(vcpu, AUDIT_POST_PTE_WRITE);
	spin_unlock(&vcpu->kvm->mmu_lock);
}

int kvm_mmu_unprotect_page_virt(struct kvm_vcpu *vcpu, gva_t gva)
{
	gpa_t gpa;
	int r;

	if (vcpu->arch.mmu.direct_map)
		return 0;

	gpa = kvm_mmu_gva_to_gpa_read(vcpu, gva, NULL);

	r = kvm_mmu_unprotect_page(vcpu->kvm, gpa_to_gfn(gpa));

	return r;
}
EXPORT_SYMBOL_GPL(kvm_mmu_unprotect_page_virt);

static void make_mmu_pages_available(struct kvm_vcpu *vcpu)
{
	LIST_HEAD(invalid_list);

	if (likely(kvm_mmu_available_pages(vcpu->kvm) >=
					KVM_MIN_FREE_MMU_PAGES))
		return;

	while (kvm_mmu_available_pages(vcpu->kvm) < KVM_REFILL_PAGES) {
		if (!prepare_zap_oldest_mmu_page(vcpu->kvm, &invalid_list))
			break;

		++vcpu->kvm->stat.mmu_recycled;
	}
	kvm_mmu_commit_zap_page(vcpu->kvm, &invalid_list);
}

void kvm_mmu_flush_gva(struct kvm_vcpu *vcpu, gva_t gva)
{
	vcpu->arch.mmu.sync_gva(vcpu, gva);
	kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
	++vcpu->stat.flush_gva;
}
EXPORT_SYMBOL_GPL(kvm_mmu_flush_gva);

void kvm_enable_tdp(void)
{
	tdp_enabled = true;
}
EXPORT_SYMBOL_GPL(kvm_enable_tdp);

void kvm_disable_tdp(void)
{
	tdp_enabled = false;
}
EXPORT_SYMBOL_GPL(kvm_disable_tdp);

static void free_mmu_pages(struct kvm_vcpu *vcpu)
{
	free_page((unsigned long)vcpu->arch.mmu.pae_root);
	if (vcpu->arch.mmu.lm_root != NULL)
		free_page((unsigned long)vcpu->arch.mmu.lm_root);
}

static int alloc_mmu_pages(struct kvm_vcpu *vcpu)
{
	struct page *page;
	int i;

	/*
	 * When emulating 32-bit mode, cr3 is only 32 bits even on x86_64.
	 * Therefore we need to allocate shadow page tables in the first
	 * 4GB of memory, which happens to fit the DMA32 zone.
	 */
	page = alloc_page(GFP_KERNEL | __GFP_DMA32);
	if (!page)
		return -ENOMEM;

	vcpu->arch.mmu.pae_root = page_address(page);
	for (i = 0; i < 4; ++i)
		vcpu->arch.mmu.pae_root[i] = E2K_INVALID_PAGE;

	return 0;
}

int kvm_mmu_create(struct kvm_vcpu *vcpu)
{
	vcpu->arch.walk_mmu = &vcpu->arch.mmu;
	vcpu->arch.mmu.sh_os_root_hpa = E2K_INVALID_PAGE;
	vcpu->arch.mmu.sh_u_root_hpa = E2K_INVALID_PAGE;
	vcpu->arch.mmu.gp_root_hpa = E2K_INVALID_PAGE;
	vcpu->arch.mmu.sh_root_hpa = E2K_INVALID_PAGE;
	vcpu->arch.mmu.translate_gpa = translate_gpa;

	kvm_setup_paging_mode(vcpu);

	return alloc_mmu_pages(vcpu);
}

void kvm_mmu_setup(struct kvm_vcpu *vcpu)
{
	mmu_check_invalid_roots(vcpu, true /* invalid */,
				OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG);
	kvm_setup_mmu_intc_mode(vcpu);
	init_kvm_mmu(vcpu);
}

static const pt_struct_t *get_cpu_iset_mmu_pt_struct(int iset, bool mmu_pt_v6)
{
	const pt_struct_t *pts;

	if (iset <= E2K_ISET_V2) {
		pts = &pgtable_struct_e2k_v2;
	} else if (iset < E2K_ISET_V5) {
		pts = &pgtable_struct_e2k_v3;
	} else if (iset == E2K_ISET_V5) {
		pts = &pgtable_struct_e2k_v5;
	} else if (iset >= E2K_ISET_V6) {
		if (mmu_pt_v6)
			pts = &pgtable_struct_e2k_v6_pt_v6;
		else
			pts = &pgtable_struct_e2k_v6_pt_v2;
	} else {
		BUG_ON(true);
	}
	return pts;
}

const pt_struct_t *kvm_get_mmu_host_pt_struct(struct kvm *kvm)
{
	return get_cpu_iset_mmu_pt_struct(machine.native_iset_ver,
					  machine.mmu_pt_v6);
}

const pt_struct_t *kvm_get_cpu_mmu_pt_struct(struct kvm_vcpu *vcpu)
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

const pt_struct_t *kvm_get_mmu_guest_pt_struct(struct kvm_vcpu *vcpu)
{
	if (!vcpu->arch.is_hv) {
		/* paravirtualization case: guest PT type emulates */
		/* same as native PT type */
		return kvm_get_mmu_host_pt_struct(vcpu->kvm);
	} else {
		/* depends on guest CPU type */
		return kvm_get_cpu_mmu_pt_struct(vcpu);
	}

	BUG_ON(true);
	return NULL;
}

const pt_struct_t *kvm_mmu_get_host_pt_struct(struct kvm *kvm)
{
	return mmu_get_host_pt_struct(kvm);
}

const pt_struct_t *kvm_mmu_get_vcpu_pt_struct(struct kvm_vcpu *vcpu)
{
	return mmu_get_vcpu_pt_struct(vcpu);
}

const pt_struct_t *kvm_mmu_get_gp_pt_struct(struct kvm *kvm)
{
	return mmu_get_gp_pt_struct(kvm);
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

static void kvm_mmu_invalidate_zap_pages_in_memslot(struct kvm *kvm,
			struct kvm_memory_slot *slot,
			struct kvm_page_track_notifier_node *node)
{
	kvm_mmu_invalidate_zap_all_pages(kvm);
}

void kvm_mmu_init_vm(struct kvm *kvm)
{
	struct kvm_page_track_notifier_node *node;

	kvm_init_mmu_pt_structs(kvm);

	node = &kvm->arch.mmu_sp_tracker;
	node->track_write = kvm_mmu_pte_write;
	node->track_flush_slot = kvm_mmu_invalidate_zap_pages_in_memslot;
	kvm_page_track_register_notifier(kvm, node);

}

void kvm_mmu_uninit_vm(struct kvm *kvm)
{
	struct kvm_page_track_notifier_node *node = &kvm->arch.mmu_sp_tracker;

	kvm_page_track_unregister_notifier(kvm, node);
}

/* The return value indicates if tlb flush on all vcpus is needed. */
typedef bool (*slot_level_handler)(struct kvm *kvm,
					struct kvm_rmap_head *rmap_head);

/* The caller should hold mmu-lock before calling this function. */
static bool
slot_handle_level_range(struct kvm *kvm, struct kvm_memory_slot *memslot,
			slot_level_handler fn, int start_level, int end_level,
			gfn_t start_gfn, gfn_t end_gfn, bool lock_flush_tlb)
{
	struct slot_rmap_walk_iterator iterator;
	bool flush = false;

	for_each_slot_rmap_range(memslot, start_level, end_level, start_gfn,
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
slot_handle_level(struct kvm *kvm, struct kvm_memory_slot *memslot,
		  slot_level_handler fn, int start_level, int end_level,
		  bool lock_flush_tlb)
{
	return slot_handle_level_range(kvm, memslot, fn, start_level,
			end_level, memslot->base_gfn,
			memslot->base_gfn + memslot->npages - 1,
			lock_flush_tlb);
}

static bool
slot_handle_all_level(struct kvm *kvm, struct kvm_memory_slot *memslot,
		      slot_level_handler fn, bool lock_flush_tlb)
{
	return slot_handle_level(kvm, memslot, fn, PT_PAGE_TABLE_LEVEL,
				 PT_MAX_HUGEPAGE_LEVEL, lock_flush_tlb);
}

static bool
slot_handle_large_level(struct kvm *kvm, struct kvm_memory_slot *memslot,
			slot_level_handler fn, bool lock_flush_tlb)
{
	return slot_handle_level(kvm, memslot, fn, PT_PAGE_TABLE_LEVEL + 1,
				 PT_MAX_HUGEPAGE_LEVEL, lock_flush_tlb);
}

static bool
slot_handle_leaf(struct kvm *kvm, struct kvm_memory_slot *memslot,
		 slot_level_handler fn, bool lock_flush_tlb)
{
	return slot_handle_level(kvm, memslot, fn, PT_PAGE_TABLE_LEVEL,
				 PT_PAGE_TABLE_LEVEL, lock_flush_tlb);
}

void kvm_zap_gfn_range(struct kvm *kvm, gfn_t gfn_start, gfn_t gfn_end)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int i;

	spin_lock(&kvm->mmu_lock);
	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		slots = __kvm_memslots(kvm, i);
		kvm_for_each_memslot(memslot, slots) {
			gfn_t start, end;

			start = max(gfn_start, memslot->base_gfn);
			end = min(gfn_end, memslot->base_gfn + memslot->npages);
			if (start >= end)
				continue;

			slot_handle_level_range(kvm, memslot, kvm_zap_rmapp,
						PT_PAGE_TABLE_LEVEL,
						PT_MAX_HUGEPAGE_LEVEL,
						start, end - 1, true);
		}
	}

	spin_unlock(&kvm->mmu_lock);
}

static bool slot_rmap_write_protect(struct kvm *kvm,
				    struct kvm_rmap_head *rmap_head)
{
	return __rmap_write_protect(kvm, rmap_head, false);
}

void kvm_mmu_slot_remove_write_access(struct kvm *kvm,
				      struct kvm_memory_slot *memslot)
{
	bool flush;

	spin_lock(&kvm->mmu_lock);
	flush = slot_handle_all_level(kvm, memslot, slot_rmap_write_protect,
				      false);
	spin_unlock(&kvm->mmu_lock);

	/*
	 * kvm_mmu_slot_remove_write_access() and kvm_vm_ioctl_get_dirty_log()
	 * which do tlb flush out of mmu-lock should be serialized by
	 * kvm->slots_lock otherwise tlb flush would be missed.
	 */
	lockdep_assert_held(&kvm->slots_lock);

	/*
	 * We can flush all the TLBs out of the mmu lock without TLB
	 * corruption since we just change the spte from writable to
	 * readonly so that we only need to care the case of changing
	 * spte from present to present (changing the spte from present
	 * to nonpresent will flush all the TLBs immediately), in other
	 * words, the only case we care is mmu_spte_update() where we
	 * haved checked SPTE_HOST_WRITABLE | SPTE_MMU_WRITABLE
	 * instead of PT_WRITABLE_MASK, that means it does not depend
	 * on PT_WRITABLE_MASK anymore.
	 */
	if (flush)
		kvm_flush_remote_tlbs(kvm);
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

void kvm_mmu_zap_collapsible_sptes(struct kvm *kvm,
				   const struct kvm_memory_slot *memslot)
{
	/* FIXME: const-ify all uses of struct kvm_memory_slot.  */
	spin_lock(&kvm->mmu_lock);
	slot_handle_leaf(kvm, (struct kvm_memory_slot *)memslot,
			 kvm_mmu_zap_collapsible_spte, true);
	spin_unlock(&kvm->mmu_lock);
}

void kvm_mmu_slot_leaf_clear_dirty(struct kvm *kvm,
				   struct kvm_memory_slot *memslot)
{
	bool flush;

	spin_lock(&kvm->mmu_lock);
	flush = slot_handle_leaf(kvm, memslot, __rmap_clear_dirty, false);
	spin_unlock(&kvm->mmu_lock);

	lockdep_assert_held(&kvm->slots_lock);

	/*
	 * It's also safe to flush TLBs out of mmu lock here as currently this
	 * function is only used for dirty logging, in which case flushing TLB
	 * out of mmu lock also guarantees no dirty pages will be lost in
	 * dirty_bitmap.
	 */
	if (flush)
		kvm_flush_remote_tlbs(kvm);
}
EXPORT_SYMBOL_GPL(kvm_mmu_slot_leaf_clear_dirty);

void kvm_mmu_slot_largepage_remove_write_access(struct kvm *kvm,
					struct kvm_memory_slot *memslot)
{
	bool flush;

	spin_lock(&kvm->mmu_lock);
	flush = slot_handle_large_level(kvm, memslot, slot_rmap_write_protect,
					false);
	spin_unlock(&kvm->mmu_lock);

	/* see kvm_mmu_slot_remove_write_access */
	lockdep_assert_held(&kvm->slots_lock);

	if (flush)
		kvm_flush_remote_tlbs(kvm);
}
EXPORT_SYMBOL_GPL(kvm_mmu_slot_largepage_remove_write_access);

void kvm_mmu_slot_set_dirty(struct kvm *kvm,
			    struct kvm_memory_slot *memslot)
{
	bool flush;

	spin_lock(&kvm->mmu_lock);
	flush = slot_handle_all_level(kvm, memslot, __rmap_set_dirty, false);
	spin_unlock(&kvm->mmu_lock);

	lockdep_assert_held(&kvm->slots_lock);

	/* see kvm_mmu_slot_leaf_clear_dirty */
	if (flush)
		kvm_flush_remote_tlbs(kvm);
}
EXPORT_SYMBOL_GPL(kvm_mmu_slot_set_dirty);

#define BATCH_ZAP_PAGES	10
static void kvm_zap_obsolete_pages(struct kvm *kvm)
{
	struct kvm_mmu_page *sp, *node;
	int batch = 0;

	DebugKVMSH("started\n");
restart:
	list_for_each_entry_safe_reverse(sp, node,
	      &kvm->arch.active_mmu_pages, link) {
		int ret;

		/*
		 * No obsolete page exists before new created page since
		 * active_mmu_pages is the FIFO list.
		 */
		if (!is_obsolete_sp(kvm, sp))
			break;

		/*
		 * Since we are reversely walking the list and the invalid
		 * list will be moved to the head, skip the invalid page
		 * can help us to avoid the infinity list walking.
		 */
		if (sp->role.invalid)
			continue;

		/*
		 * Need not flush tlb since we only zap the sp with invalid
		 * generation number.
		 */
		if (batch >= BATCH_ZAP_PAGES &&
		      cond_resched_lock(&kvm->mmu_lock)) {
			batch = 0;
			goto restart;
		}

		/* all SPs should be released unconditionally */
		sp->released = true;

		ret = kvm_mmu_prepare_zap_page(kvm, sp,
				&kvm->arch.zapped_obsolete_pages);
		batch += ret;

		if (ret)
			goto restart;
	}

	/*
	 * Should flush tlb before free page tables since lockless-walking
	 * may use the pages.
	 */
	kvm_mmu_commit_zap_page(kvm, &kvm->arch.zapped_obsolete_pages);
}

/*
 * Fast invalidate all shadow pages and use lock-break technique
 * to zap obsolete pages.
 *
 * It's required when memslot is being deleted or VM is being
 * destroyed, in these cases, we should ensure that KVM MMU does
 * not use any resource of the being-deleted slot or all slots
 * after calling the function.
 */
void kvm_mmu_invalidate_zap_all_pages(struct kvm *kvm)
{
	DebugKVMSH("started\n");
	spin_lock(&kvm->mmu_lock);
	trace_kvm_mmu_invalidate_zap_all_pages(kvm);
	kvm->arch.mmu_valid_gen++;

	/*
	 * Notify all vcpus to reload its shadow page table
	 * and flush TLB. Then all vcpus will switch to new
	 * shadow page table with the new mmu_valid_gen.
	 *
	 * Note: we should do this under the protection of
	 * mmu-lock, otherwise, vcpu would purge shadow page
	 * but miss tlb flush.
	 */
	kvm_reload_remote_mmus(kvm);

	kvm_zap_obsolete_pages(kvm);

	/* invalidate all page tables root pointers */
	kvm_invalidate_all_roots(kvm);

	spin_unlock(&kvm->mmu_lock);
}

static bool kvm_has_zapped_obsolete_pages(struct kvm *kvm)
{
	return unlikely(!list_empty_careful(&kvm->arch.zapped_obsolete_pages));
}

void kvm_mmu_invalidate_mmio_sptes(struct kvm *kvm, u64 gen)
{
	gen &= MMIO_GEN_MASK;

	/*
	 * Shift to eliminate the "update in-progress" flag, which isn't
	 * included in the spte's generation number.
	 */
	gen >>= 1;

	/*
	 * Generation numbers are incremented in multiples of the number of
	 * address spaces in order to provide unique generations across all
	 * address spaces.  Strip what is effectively the address space
	 * modifier prior to checking for a wrap of the MMIO generation so
	 * that a wrap in any address space is detected.
	 */
	gen &= ~((u64)KVM_ADDRESS_SPACE_NUM - 1);

	/*
	 * The very rare case: if the MMIO generation number has wrapped,
	 * zap all shadow pages.
	 */
	if (unlikely(gen == 0)) {
		kvm_debug_ratelimited("kvm: zapping shadow pages for mmio generation wraparound\n");
		kvm_mmu_invalidate_zap_all_pages(kvm);
	}
}

static unsigned long
mmu_shrink_scan(struct shrinker *shrink, struct shrink_control *sc)
{
	struct kvm *kvm;
	int nr_to_scan = sc->nr_to_scan;
	unsigned long freed = 0;

	mutex_lock(&kvm_lock);

	list_for_each_entry(kvm, &vm_list, vm_list) {
		int idx;
		LIST_HEAD(invalid_list);

		/*
		 * Never scan more than sc->nr_to_scan VM instances.
		 * Will not hit this condition practically since we do not try
		 * to shrink more than one VM and it is very unlikely to see
		 * !n_used_mmu_pages so many times.
		 */
		if (!nr_to_scan--)
			break;
		/*
		 * n_used_mmu_pages is accessed without holding kvm->mmu_lock
		 * here. We may skip a VM instance errorneosly, but we do not
		 * want to shrink a VM that only started to populate its MMU
		 * anyway.
		 */
		if (!kvm->arch.n_used_mmu_pages &&
		      !kvm_has_zapped_obsolete_pages(kvm))
			continue;

		idx = srcu_read_lock(&kvm->srcu);
		spin_lock(&kvm->mmu_lock);

		if (kvm_has_zapped_obsolete_pages(kvm)) {
			kvm_mmu_commit_zap_page(kvm,
			      &kvm->arch.zapped_obsolete_pages);
			goto unlock;
		}

		if (prepare_zap_oldest_mmu_page(kvm, &invalid_list))
			freed++;
		kvm_mmu_commit_zap_page(kvm, &invalid_list);

unlock:
		spin_unlock(&kvm->mmu_lock);
		srcu_read_unlock(&kvm->srcu, idx);

		/*
		 * unfair on small ones
		 * per-vm shrinkers cry out
		 * sadness comes quickly
		 */
		list_move_tail(&kvm->vm_list, &vm_list);
		break;
	}

	mutex_unlock(&kvm_lock);
	return freed;
}

static unsigned long
mmu_shrink_count(struct shrinker *shrink, struct shrink_control *sc)
{
	return percpu_counter_read_positive(&kvm_total_used_mmu_pages);
}

static struct shrinker mmu_shrinker = {
	.count_objects = mmu_shrink_count,
	.scan_objects = mmu_shrink_scan,
	.seeks = DEFAULT_SEEKS * 10,
};

static int init_nonpaging_root_pt(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	hpa_t root;
	pgprot_t *new_root;
	int pt_index;

	KVM_BUG_ON(VALID_PAGE(kvm->arch.nonp_root_hpa));

	root = kvm_get_gp_phys_root(vcpu);
	KVM_BUG_ON(IS_E2K_INVALID_PAGE(root));
	DebugNONP("VCPU #%d created root PT at 0x%llx\n",
		vcpu->vcpu_id, root);

	kvm->arch.nonp_root_hpa = root;	/* PT root is common for all VCPUs */

	mmu_set_gp_pt_struct_func(kvm, &kvm_mmu_get_gp_pt_struct);
	mmu_set_host_pt_struct_func(kvm, &kvm_mmu_get_gp_pt_struct);
	if (kvm_is_phys_pt_enable(kvm)) {
		mmu_set_gp_pt_struct(kvm, &pgtable_struct_e2k_v6_gp);
	} else if (kvm_is_shadow_pt_enable(kvm)) {
		mmu_set_gp_pt_struct(kvm, kvm_get_mmu_host_pt_struct(kvm));

		/* One PGD entry is the VPTB self-map. */
		pt_index = pgd_index(KERNEL_VPTB_BASE_ADDR);
		new_root = (pgprot_t *)__va(root);
		kvm_vmlpt_kernel_spte_set(kvm, &new_root[pt_index], new_root);
	} else {
		BUG_ON(true);
	}

	/* init intercept handling for nonpagin mode */
	mmu_init_nonpaging_intc(vcpu);

	return 0;
}

/*
 * Hypervisor should use only separate virtual space mode
 * to provide atomic hardware switch hypervisor <-> guest.
 * Only guest OS can be run at nonpaging mode, so use guest OS space
 * to support this mode, but it is not surely.
 */
static void kvm_hv_setup_nonp_phys_pt(struct kvm_vcpu *vcpu, hpa_t root)
{
	/* guest PTs are not yet created and not used, only GP_PT */
	set_phys_paging(vcpu);
	KVM_BUG_ON(!VALID_PAGE(vcpu->arch.mmu.get_vcpu_gp_pptb(vcpu)));
}

static void kvm_setup_nonp_shadow_pt(struct kvm_vcpu *vcpu, hpa_t root)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	set_shadow_paging(vcpu);
	if (!is_phys_paging(vcpu)) {
		/* guest physical addresses are translated by hypervisor */
		/* OS_* / U_* PTs */
		if (is_sep_virt_spaces(vcpu)) {
			kvm_set_space_type_spt_os_root(vcpu, root);
		} else {
			kvm_set_space_type_spt_u_root(vcpu, root);
		}
		if (is_sep_virt_spaces(vcpu)) {
			KVM_BUG_ON(mmu->get_vcpu_sh_os_pptb(vcpu) != root);
			mmu->set_vcpu_sh_os_vptb(vcpu, MMU_GUEST_OS_PT_VPTB);
			mmu->set_vcpu_os_vab(vcpu, 0);
		} else {
			KVM_BUG_ON(mmu->get_vcpu_sh_u_pptb(vcpu) != root);
			mmu->set_vcpu_sh_u_vptb(vcpu, MMU_UNITED_USER_VPTB);
		}
		/* GP_* PTs cannot be used */
		if (vcpu->arch.is_hv) {
			/* shadow PTs cannot be used for host translations */
			;
		} else if (vcpu->arch.is_pv) {
			/* shadow PTs will be used in both modes */
			/* as well as host and guest translations */
			kvm_prepare_shadow_root(vcpu, NULL,
					root, E2K_INVALID_PAGE,
					(is_sep_virt_spaces(vcpu)) ?
						MMU_SEPARATE_KERNEL_VPTB
						:
						MMU_UNITED_KERNEL_VPTB);
		} else {
			KVM_BUG_ON(true);
		}
	}
}

static void kvm_hv_setup_nonp_tdp(struct kvm_vcpu *vcpu)
{
	KVM_BUG_ON(!is_phys_paging(vcpu));
	set_tdp_paging(vcpu);
}

int kvm_hv_setup_nonpaging_mode(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	unsigned flags;
	int ret;

	DebugNONP("started on VCPU #%d\n", vcpu->vcpu_id);

	KVM_BUG_ON(is_paging(vcpu));

	/* It need create new nonpaging PT to translate guest physical */
	/* addresses to host physical pages GPA->PA */

	/* set all guest page table pointers to initial state */
	vcpu->arch.mmu.init_vcpu_ptb(vcpu);

	/* create root PT level */
	if (kvm_is_phys_pt_enable(vcpu->kvm)) {
		flags = GP_ROOT_PT_FLAG;
	} else if (kvm_is_shadow_pt_enable(kvm)) {
		if (vcpu->arch.is_hv) {
			set_sep_virt_spaces(vcpu);
			flags = OS_ROOT_PT_FLAG;
		} else {
			reset_sep_virt_spaces(vcpu);
			flags = U_ROOT_PT_FLAG;
		}
	} else {
		KVM_BUG_ON(true);
	}
	ret = kvm_mmu_load(vcpu, NULL, flags);
	if (ret) {
		pr_err("%s(): could not create VCPU #%d root PT, error %d\n",
			__func__, vcpu->vcpu_id, ret);
		return ret;
	}

	mutex_lock(&kvm->slots_lock);
	if (IS_E2K_INVALID_PAGE(kvm->arch.nonp_root_hpa)) {
		ret = init_nonpaging_root_pt(vcpu);
		if (ret)
			goto failed;
	} else if (VALID_PAGE(kvm->arch.nonp_root_hpa)) {
		DebugNONP("VCPU #%d root PT has been already "
			"created at 0x%llx\n",
			vcpu->vcpu_id, kvm->arch.nonp_root_hpa);
	} else if (ERROR_PAGE(kvm->arch.nonp_root_hpa)) {
		ret = PAGE_TO_ERROR(kvm->arch.nonp_root_hpa);
		DebugNONP("VCPU #%d root PT creation has been failed, "
			"error %d\n",
			vcpu->vcpu_id, ret);
		goto failed;
	} else {
		KVM_BUG_ON(true);
	}
	mutex_unlock(&kvm->slots_lock);

	if (kvm_is_phys_pt_enable(vcpu->kvm))
		kvm_hv_setup_nonp_phys_pt(vcpu, kvm->arch.nonp_root_hpa);

	if (kvm_is_tdp_enable(vcpu->kvm)) {
		kvm_hv_setup_nonp_tdp(vcpu);
	} else if (kvm_is_shadow_pt_enable(vcpu->kvm)) {
		kvm_setup_nonp_shadow_pt(vcpu, kvm->arch.nonp_root_hpa);
	}

	KVM_BUG_ON(!(is_shadow_paging(vcpu) || is_phys_paging(vcpu)));

	return 0;

failed:
	mutex_unlock(&kvm->slots_lock);
	return ret;
}

static void complete_nonpaging_mode(struct kvm_vcpu *vcpu)
{
	set_paging_flag(vcpu);
	kvm_mmu_reset_context(vcpu, OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG);
}

static int setup_shadow_root(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				unsigned flags)
{
	struct kvm *kvm = vcpu->kvm;
	hpa_t os_root, u_root, gp_root;
	int ret;

	/* setup page table structures type to properly manage PTs */
	mmu_set_host_pt_struct(kvm, kvm_get_mmu_host_pt_struct(kvm));
	mmu_set_vcpu_pt_struct(kvm, kvm_get_mmu_guest_pt_struct(vcpu));
	mmu_set_host_pt_struct_func(kvm, &kvm_mmu_get_host_pt_struct);
	mmu_set_vcpu_pt_struct_func(kvm, &kvm_mmu_get_vcpu_pt_struct);

	ret = kvm_mmu_load(vcpu, gmm, flags);
	if (ret) {
		pr_err("%s(): could not create support of VCPU #%d MMU\n",
			__func__, vcpu->vcpu_id);
		return ret;
	}

	mmu_get_spt_roots(vcpu, flags | GP_ROOT_PT_FLAG,
				&os_root, &u_root, &gp_root);

	if (VALID_PAGE(u_root)) {
		kvm_prepare_shadow_root(vcpu, gmm, u_root, gp_root,
			vcpu->arch.mmu.get_vcpu_sh_u_vptb(vcpu));
	}
	if (VALID_PAGE(os_root) && os_root != u_root) {
		kvm_prepare_shadow_root(vcpu, gmm, os_root, gp_root,
			vcpu->arch.mmu.get_vcpu_sh_os_vptb(vcpu));
	}

	return 0;
}

static int kvm_sync_shadow_root(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				hpa_t root_hpa, unsigned flags)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	struct kvm_mmu_page *sp;
	e2k_addr_t sync_start, sync_end;
	pgprotval_t pptb, u_pptb, os_pptb;
	gva_t vptb;
	const char *type;
	int ret;

	sp = page_header(root_hpa);
	if (!sp->unsync)
		return 0;

	u_pptb = mmu->get_vcpu_u_pptb(vcpu);
	os_pptb = mmu->get_vcpu_os_pptb(vcpu);

	if (flags & U_ROOT_PT_FLAG) {
		if (is_sep_virt_spaces(vcpu)) {
			if (u_pptb != os_pptb) {
				/* can be two PTs user and OS */
				sync_start = 0;
				sync_end = mmu->get_vcpu_os_vab(vcpu);
				pptb = u_pptb;
				vptb = mmu->get_vcpu_sh_u_vptb(vcpu);
				type = "user U_PT";
			} else {
				/* there is one PT (OS and user) */
				sync_start = 0;
				sync_end = E2K_VA_MASK;
				pptb = os_pptb;
				vptb = mmu->get_vcpu_sh_os_vptb(vcpu);
				type = "OS/user OS_PT";
			}
		} else {
			/* there is one PT (OS and user) */
			sync_start = 0;
			sync_end = E2K_VA_MASK;
			pptb = u_pptb;
			vptb = mmu->get_vcpu_sh_u_vptb(vcpu);
			type = "OS/user U_PT";
		}
		DebugSPT("VCPU #%d created shadow root %s at 0x%llx "
			"for guest ininitial root PT at 0x%lx\n",
			vcpu->vcpu_id, type, root_hpa, pptb);
	} else if (flags & OS_ROOT_PT_FLAG) {
		if (is_sep_virt_spaces(vcpu)) {
			if (u_pptb != os_pptb) {
				/* can be two PTs user and OS */
				sync_start = mmu->get_vcpu_os_vab(vcpu);
				sync_end = E2K_VA_MASK;
				pptb = os_pptb;
				vptb = mmu->get_vcpu_sh_os_vptb(vcpu);
				type = "OS_PT";
			} else {
				/* there is one PT (OS and user) */
				sync_start = 0;
				sync_end = E2K_VA_MASK;
				pptb = os_pptb;
				vptb = mmu->get_vcpu_sh_os_vptb(vcpu);
				type = "OS/user OS_PT";
			}
		} else {
			sync_start = 0;
			sync_end = E2K_VA_MASK;
			pptb = u_pptb;
			vptb = mmu->get_vcpu_sh_u_vptb(vcpu);
			type = "OS/user U_PT";
		}
		DebugSPT("VCPU #%d created shadow root %s at 0x%llx "
			"for guest ininitial root PT at 0x%lx\n",
			vcpu->vcpu_id, type, root_hpa, pptb);
	} else {
		KVM_BUG_ON(true);
	}

	kvm_unlink_unsync_page(vcpu->kvm, sp);
	ret = e2k_sync_shadow_pt_range(vcpu, gmm, root_hpa,
			sync_start, sync_end, E2K_INVALID_PAGE, vptb);
	if (ret) {
		pr_err("%s(): could not sync host shadow U_PT "
			"and guest initial PT, error %d\n",
			__func__, ret);
		return ret;
	}
	DebugSPT("VCPU #%d shadow root %s at 0x%llx synced "
		"from 0x%lx to 0x%lx\n",
		vcpu->vcpu_id, type, root_hpa, sync_start, sync_end);

	return 0;
}

static int kvm_sync_shadow_u_root(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
					bool force)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	struct kvm_mmu_page *sp;
	hpa_t root;
	e2k_addr_t sync_start, sync_end;
	pgprotval_t u_pptb;
	gva_t vptb;
	const char *type;
	int ret;

	root = kvm_get_space_type_spt_u_root(vcpu);
	u_pptb = mmu->get_vcpu_u_pptb(vcpu);
	sp = page_header(root);
	if (!sp->unsync && !force) {
		DebugSPT("VCPU #%d user shadow root at 0x%llx for guest "
			"root PT at 0x%lxis already synced\n",
			vcpu->vcpu_id, root, u_pptb);
		return 0;
	} else if (!sp->unsync) {
		sp->unsync = 1;
	}

	if (is_sep_virt_spaces(vcpu)) {
		/* can be two PTs user and OS */
		sync_start = 0;
		sync_end = mmu->get_vcpu_os_vab(vcpu);
		vptb = mmu->get_vcpu_sh_u_vptb(vcpu);
		type = "separate user U_PT";
	} else {
		/* there is one PT (OS and user) */
		sync_start = 0;
		sync_end = HOST_TASK_SIZE;
		vptb = mmu->get_vcpu_sh_u_vptb(vcpu);
		type = "united OS/user U_PT";
	}
	DebugSPT("will be synced VCPU #%d root %s at 0x%llx for guest "
		"root PT at 0x%lx\n",
		vcpu->vcpu_id, type, root, u_pptb);

	kvm_unlink_unsync_page(vcpu->kvm, sp);
	ret = e2k_sync_shadow_pt_range(vcpu, gmm, root, sync_start, sync_end,
					u_pptb, vptb);
	if (ret) {
		pr_err("%s(): could not sync host shadow U_PT "
			"and guest root PT, error %d\n",
			__func__, ret);
		return ret;
	}
	DebugSPT("VCPU #%d shadow user root %s at 0x%llx synced "
		"from 0x%lx to 0x%lx\n",
		vcpu->vcpu_id, type, root, sync_start, sync_end);

	return 0;
}

static int sync_pv_vcpu_shadow_u_root(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
					hpa_t root_hpa, gpa_t u_pptb)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	struct kvm_mmu_page *sp;
	e2k_addr_t sync_start, sync_end;
	gva_t vptb;
	int ret;

	sp = page_header(root_hpa);
	if (!sp->unsync)
		return 0;

	if (is_sep_virt_spaces(vcpu)) {
		/* can be two PTs user and OS */
		sync_start = 0;
		if (sp->guest_kernel_synced) {
			sync_end = GUEST_TASK_SIZE;
		} else {
			sync_end = mmu->get_vcpu_os_vab(vcpu);
		}
		vptb = mmu->get_vcpu_sh_u_vptb(vcpu);
	} else {
		/* there is one PT (OS and user) */
		sync_start = 0;
		if (sp->guest_kernel_synced) {
			sync_end = GUEST_TASK_SIZE;
		} else {
			sync_end = HOST_TASK_SIZE;
		}
		vptb = mmu->get_vcpu_sh_u_vptb(vcpu);
	}
	DebugGMM("VCPU #%d created shadow user root at 0x%llx "
		"for guest ininitial root PT at 0x%llx\n",
		vcpu->vcpu_id, root_hpa, u_pptb);

	kvm_unlink_unsync_page(vcpu->kvm, sp);
	ret = e2k_sync_shadow_pt_range(vcpu, gmm, root_hpa,
				sync_start, sync_end, u_pptb, vptb);
	if (ret) {
		pr_err("%s(): could not sync host shadow user PT "
			"and guest initial PT, error %d\n",
			__func__, ret);
		return ret;
	}
	DebugGMM("VCPU #%d shadow user root at 0x%llx synced "
		"from 0x%lx to 0x%lx\n",
		vcpu->vcpu_id, root_hpa, sync_start, sync_end);

	return 0;
}

int kvm_sync_init_shadow_pt(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
		gpa_t u_phys_ptb, gva_t u_virt_ptb,
		gpa_t os_phys_ptb, gva_t os_virt_ptb, gva_t os_virt_base)
{
	hpa_t os_root, u_root;
	unsigned flags;
	int ret;

	KVM_BUG_ON(gmm == NULL);
	KVM_BUG_ON(VALID_PAGE(gmm->root_hpa));

	/* always separate speces should be used */
	set_sep_virt_spaces(vcpu);

	vcpu->arch.mmu.set_vcpu_os_pptb(vcpu, os_phys_ptb);
	vcpu->arch.mmu.set_vcpu_os_vptb(vcpu, os_virt_ptb);
	vcpu->arch.mmu.set_vcpu_sh_os_vptb(vcpu, os_virt_ptb);
	vcpu->arch.mmu.set_vcpu_os_vab(vcpu, os_virt_base);
	vcpu->arch.mmu.set_vcpu_u_pptb(vcpu, u_phys_ptb);
	vcpu->arch.mmu.set_vcpu_u_vptb(vcpu, u_virt_ptb);
	vcpu->arch.mmu.set_vcpu_sh_u_vptb(vcpu, u_virt_ptb);
	flags = OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG;

	ret = setup_shadow_root(vcpu, gmm, flags);
	if (ret) {
		pr_err("%s(): could not create support of VCPU #%d MMU\n",
			__func__, vcpu->vcpu_id);
		goto failed;
	}

	mmu_get_spt_roots(vcpu, flags, &os_root, &u_root, NULL);

	/* shadow PT root is common for all VCPUs */
	if (VALID_PAGE(os_root)) {
		gmm->root_hpa = os_root;
	} else if (VALID_PAGE(u_root)) {
		gmm->root_hpa = u_root;
	} else {
		KVM_BUG_ON(true);
	}
	kvm_set_root_gmm_spt_list(gmm);
	return 0;

failed:
	gmm->root_hpa = TO_ERROR_PAGE(ret);
	return ret;
}

int kvm_prepare_shadow_user_pt(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				gpa_t u_phys_ptb)
{
	hpa_t root;
	struct kvm_mmu_page *sp;
	int ret;

	KVM_BUG_ON(!is_shadow_paging(vcpu));
	KVM_BUG_ON(gmm == NULL);
	KVM_BUG_ON(VALID_PAGE(gmm->root_hpa));
	KVM_BUG_ON(!vcpu->arch.mmu.u_context_on);

	ret = mmu_topup_memory_caches(vcpu);
	if (ret) {
		pr_err("%s(): could not create  memory caches on VCPU #%d "
			"error %d\n",
			__func__, vcpu->vcpu_id, ret);
		goto failed;
	}

	root = e2k_mmu_alloc_spt_root(vcpu, gpa_to_gfn(u_phys_ptb));
	DebugGMM("VCPU #%d created shadow root PT at 0x%llx for guest "
		"user root PT physical at 0x%llx for gmm #%d\n",
		vcpu->vcpu_id, root, u_phys_ptb, gmm->nid.nr);

	mmu_pv_prepare_spt_u_root(vcpu, gmm, root);

	sp = page_header(root);
	kvm_init_root_gmm_spt_list(gmm, sp);

	ret = sync_pv_vcpu_shadow_u_root(vcpu, gmm, root, u_phys_ptb);
	if (ret) {
		pr_err("%s(): failed to sync user root of GMM #%d, error %d\n",
			__func__, gmm->nid.nr, ret);
		goto failed;
	}
	DebugGMM("VCPU #%d, guest user root at 0x%llx, shadow root "
		"at 0x%llx\n",
		vcpu->vcpu_id, u_phys_ptb, root);

	gmm->pt_synced = true;
	gmm->root_hpa = root;	/* shadow PT root has been set */
	return 0;

failed:
	gmm->root_hpa = TO_ERROR_PAGE(ret);
	return ret;
}

int kvm_create_shadow_user_pt(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				gpa_t u_phys_ptb)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	hpa_t root;
	struct kvm_mmu_page *sp;
	e2k_addr_t sync_start, sync_end;
	int ret;

	KVM_BUG_ON(!is_shadow_paging(vcpu));
	KVM_BUG_ON(gmm == NULL);
	KVM_BUG_ON(VALID_PAGE(gmm->root_hpa));

	if (likely(mmu->u_context_on)) {
		/* unload previous MMU PT and context before load new */
		kvm_mmu_unload(vcpu, U_ROOT_PT_FLAG);
	} else {
		/* enable support of guest user space */
		root = kvm_get_space_type_spt_u_root(vcpu);
		if (VALID_PAGE(root)) {
			KVM_BUG_ON(is_sep_virt_spaces(vcpu) &&
				root != kvm_get_space_type_spt_os_root(vcpu));
			/* unload previous MMU PT and context before load new */
			kvm_mmu_unload(vcpu, U_ROOT_PT_FLAG);
		}
		if (is_sep_virt_spaces(vcpu)) {
			mmu->set_vcpu_sh_u_vptb(vcpu, USER_VPTB_BASE_ADDR);
			mmu->set_vcpu_os_vab(vcpu, MMU_GUEST_OS_VAB);
		} else {
			mmu->set_vcpu_sh_u_vptb(vcpu, MMU_UNITED_USER_VPTB);
		}
	}
	mmu->set_vcpu_u_pptb(vcpu, u_phys_ptb);
	ret = kvm_mmu_load(vcpu, gmm, U_ROOT_PT_FLAG | DONT_SYNC_ROOT_PT_FLAG);
	if (ret) {
		pr_err("%s(): could not load MMU support of VCPU #%d\n",
			__func__, vcpu->vcpu_id);
		ret = -ENOMEM;
		goto failed;
	}
	mmu->pid = gmm->nid.nr;

	root = kvm_get_space_type_spt_u_root(vcpu);
	DebugSPT("VCPU #%d created shadow root PT at 0x%llx for guest "
		"user root PT physical at 0x%lx, virtual at 0x%lx\n",
		vcpu->vcpu_id, root, mmu->get_vcpu_u_pptb(vcpu),
		mmu->get_vcpu_sh_u_vptb(vcpu));

	mmu_pv_prepare_spt_u_root(vcpu, gmm, root);

	sp = page_header(root);
	kvm_init_root_gmm_spt_list(gmm, sp);

	sync_start = 0;
	if (sp->guest_kernel_synced) {
		sync_end = GUEST_TASK_SIZE;
	} else {
		sync_end = HOST_TASK_SIZE;
	}

	ret = e2k_sync_shadow_pt_range(vcpu, gmm, root, sync_start, sync_end,
			u_phys_ptb, mmu->get_vcpu_sh_u_vptb(vcpu));
	if (ret) {
		pr_err("%s(): could not sync host shadow PT and guest "
			"initial PT, error %d\n",
			__func__, ret);
		goto failed;
	}
	DebugSPT("VCPU #%d shadow root at 0x%llx synced "
		"from 0x%lx to 0x%lx\n",
		vcpu->vcpu_id, root, sync_start, sync_end);

	gmm->pt_synced = true;
	gmm->root_hpa = root;	/* shadow PT root has been set */
	return 0;

failed:
	gmm->root_hpa = TO_ERROR_PAGE(ret);
	return ret;
}

static int switch_shadow_pptb(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				gpa_t pptb, unsigned flags)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	hpa_t root;
	int ret;

	KVM_BUG_ON(!is_shadow_paging(vcpu));

	/* unload previous MMU PT and context before load new */
	kvm_mmu_unload(vcpu, flags);

	/* switch VCPU MMU to new PT */
	if ((flags & U_ROOT_PT_FLAG) ||
			((flags & OS_ROOT_PT_FLAG) &&
					is_sep_virt_spaces(vcpu))) {
		mmu->set_vcpu_u_pptb(vcpu, pptb);
	} else if (flags & OS_ROOT_PT_FLAG) {
		mmu->set_vcpu_os_pptb(vcpu, pptb);
	} else {
		KVM_BUG_ON(true);
	}
	ret = kvm_mmu_load(vcpu, gmm, flags);
	if (ret) {
		pr_err("%s(): could not load new shadow PT\n", __func__);
		goto failed;
	}

	root = kvm_get_space_type_spt_u_root(vcpu);
	DebugSPT("VCPU #%d created shadow root PT at 0x%llx for guest "
		"user root PT at 0x%llx, virtual at 0x%lx\n",
		vcpu->vcpu_id, root, pptb, mmu->get_vcpu_sh_u_vptb(vcpu));

	if (!vcpu->arch.is_hv) {
		KVM_BUG_ON(true);
		kvm_prepare_shadow_root(vcpu, NULL, root, E2K_INVALID_PAGE,
					mmu->get_vcpu_sh_u_vptb(vcpu));
	}

	ret = kvm_sync_shadow_u_root(vcpu, gmm, false);
	if (ret) {
		pr_err("%s(): could not sync host shadow PT and guest "
			"user root PT, error %d\n",
			__func__, ret);
		goto failed;
	}

	return 0;

failed:
	return ret;
}

hpa_t mmu_pv_switch_spt_u_pptb(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				gpa_t u_phys_ptb)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	hpa_t root;
	int ret;

	ret = switch_shadow_pptb(vcpu, gmm, u_phys_ptb, U_ROOT_PT_FLAG);
	if (ret) {
		pr_err("%s(): could not load PT of next MM pid #%d\n",
			__func__, gmm->nid.nr);
		goto failed;
	}
	mmu->pid = gmm->nid.nr;

	root = kvm_get_space_type_spt_u_root(vcpu);
	DebugSPT("VCPU #%d loaded root PT at 0x%llx for guest "
		"user root PT physical at 0x%llx, PID %d\n",
		vcpu->vcpu_id, root, u_phys_ptb, mmu->pid);

	/* switch MMU hardware/sofware context to new mm */
	kvm_switch_mmu_guest_u_pt(vcpu);

	return root;

failed:
	return TO_ERROR_PAGE(ret);
}

int kvm_switch_shadow_u_pptb(struct kvm_vcpu *vcpu, gpa_t u_pptb,
				hpa_t *u_root)
{
	hpa_t root;
	int ret;

	DebugSPT("started on VCPU #%d for guest user root PT at 0x%llx\n",
		vcpu->vcpu_id, u_pptb);

	KVM_BUG_ON(!vcpu->arch.is_hv);

	ret = switch_shadow_pptb(vcpu, NULL, u_pptb, U_ROOT_PT_FLAG);
	if (ret) {
		pr_err("%s(): could not load new U_PPTB root\n",
			__func__);
		return ret;
	}

	kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);

	root = kvm_get_space_type_spt_u_root(vcpu);

	/* switch MMU hardware/sofware context to new PT root */
	kvm_setup_shadow_u_pptb(vcpu);

	*u_root = root;

	return 0;
}

int kvm_switch_shadow_os_pptb(struct kvm_vcpu *vcpu, gpa_t os_pptb,
				hpa_t *os_root)
{
	hpa_t root;
	int ret;

	KVM_BUG_ON(!vcpu->arch.is_hv);

	ret = switch_shadow_pptb(vcpu, NULL, os_pptb, OS_ROOT_PT_FLAG);
	if (ret) {
		pr_err("%s(): could not load new OS PT root\n",
			__func__);
		return ret;
	}

	if (is_sep_virt_spaces(vcpu)) {
		root = kvm_get_space_type_spt_u_root(vcpu);
	} else {
		root = kvm_get_space_type_spt_os_root(vcpu);
	}

	/* switch MMU hardware/sofware context to new PT root */
	kvm_setup_shadow_os_pptb(vcpu);

	*os_root = root;

	return 0;
}

int mmu_pv_create_tdp_user_pt(struct kvm_vcpu *vcpu, gpa_t u_phys_ptb)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	KVM_BUG_ON(!is_tdp_paging(vcpu));

	mmu->set_vcpu_u_pptb(vcpu, u_phys_ptb);
	mmu->set_vcpu_u_vptb(vcpu, USER_VPTB_BASE_ADDR);
	mmu->set_vcpu_os_vab(vcpu, MMU_GUEST_OS_VAB);

	return 0;
}

static int switch_tdp_pptb(struct kvm_vcpu *vcpu, gpa_t pptb, unsigned flags)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	KVM_BUG_ON(!is_tdp_paging(vcpu));

	/* switch VCPU MMU to new PT */
	if ((flags & U_ROOT_PT_FLAG) ||
			((flags & OS_ROOT_PT_FLAG) &&
					is_sep_virt_spaces(vcpu))) {
		mmu->set_vcpu_u_pptb(vcpu, pptb);
	} else if (flags & OS_ROOT_PT_FLAG) {
		mmu->set_vcpu_os_pptb(vcpu, pptb);
	} else {
		KVM_BUG_ON(true);
	}

	return 0;
}

int mmu_pv_switch_tdp_u_pptb(struct kvm_vcpu *vcpu, int pid, gpa_t u_phys_ptb)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	int ret;

	ret = switch_tdp_pptb(vcpu, u_phys_ptb, U_ROOT_PT_FLAG);
	if (ret) {
		pr_err("%s(): could not load PT of next MM pid #%d\n",
			__func__, pid);
		goto failed;
	}
	mmu->pid = pid;

	/* switch MMU hardware/sofware context to new mm */
	kvm_setup_mmu_tdp_u_pt_context(vcpu);

	return 0;

failed:
	return ret;
}

static void setup_tdp_paging(struct kvm_vcpu *vcpu)
{
	KVM_BUG_ON(is_paging_flag(vcpu));
	set_paging_flag(vcpu);

	KVM_BUG_ON(!is_tdp_paging(vcpu));

	tdp_enabled = true;

	init_kvm_mmu(vcpu);
}

int kvm_switch_to_tdp_paging(struct kvm_vcpu *vcpu,
		gpa_t u_phys_ptb, gva_t u_virt_ptb,
		gpa_t os_phys_ptb, gva_t os_virt_ptb, gva_t os_virt_base)
{
	struct kvm *kvm = vcpu->kvm;

	DebugTDP("started on VCPU #%d to switch TDP to paging mode GP "
		"root at 0x%llx\n",
		vcpu->vcpu_id, kvm_get_gp_phys_root(vcpu));

	setup_tdp_paging(vcpu);

	DebugTDP("VCPU #%d guest OS root PT base: physical 0x%llx, "
		"virtual 0x%lx, space offset 0x%lx\n",
		vcpu->vcpu_id, os_phys_ptb, os_virt_ptb, os_virt_base);
	DebugTDP("VCPU #%d guest user root PT base: physical 0x%llx, "
		"virtual 0x%lx\n",
		vcpu->vcpu_id, u_phys_ptb, u_virt_ptb);

	/* always separate speces should be used for paravirtualized guest */
	set_sep_virt_spaces(vcpu);

	vcpu->arch.mmu.set_vcpu_u_pptb(vcpu, u_phys_ptb);
	vcpu->arch.mmu.set_vcpu_u_vptb(vcpu, u_virt_ptb);
	vcpu->arch.mmu.set_vcpu_os_pptb(vcpu, os_phys_ptb);
	vcpu->arch.mmu.set_vcpu_os_vptb(vcpu, os_virt_ptb);
	vcpu->arch.mmu.set_vcpu_os_vab(vcpu, os_virt_base);

	/* setup page table structures type to properly manage PTs */
	mmu_set_vcpu_pt_struct(kvm, kvm_get_mmu_guest_pt_struct(vcpu));
	mmu_set_vcpu_pt_struct_func(kvm, &kvm_mmu_get_vcpu_pt_struct);

	return 0;
}

int kvm_hv_setup_tdp_paging(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	e2k_core_mode_t core_mode;
	bool sep_virt_space;

	setup_tdp_paging(vcpu);

	/* enable guest paging mode and shadow MMU context */

	core_mode = read_guest_CORE_MODE_reg(vcpu);
	sep_virt_space = !!core_mode.CORE_MODE_sep_virt_space;
	if (sep_virt_space)
		set_sep_virt_spaces(vcpu);
	else
		reset_sep_virt_spaces(vcpu);

	/* setup page table structures type to properly manage PTs */
	mmu_set_vcpu_pt_struct(kvm, kvm_get_mmu_guest_pt_struct(vcpu));
	mmu_set_vcpu_pt_struct_func(kvm, &kvm_mmu_get_vcpu_pt_struct);

	/* setup TDP PTs hardware/software context */
	kvm_setup_mmu_tdp_context(vcpu);

	return 0;
}

static int setup_shadow_paging(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				unsigned flags)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	hpa_t os_root, u_root;
	int ret;

	KVM_BUG_ON(VALID_PAGE(mmu->sh_root_hpa));

	/* setup shadow root of USER page table */
	ret = setup_shadow_root(vcpu, gmm, flags);
	if (ret) {
		pr_err("%s(): could not create shadow PT root "
			"of VCPU #%d MMU\n",
			__func__, vcpu->vcpu_id);
		goto failed;
	}

	kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);

	mmu_get_spt_roots(vcpu, flags, &os_root, &u_root, NULL);

	/* shadow PT root is common for all VCPUs */
	if (VALID_PAGE(os_root)) {
		mmu->sh_root_hpa = os_root;
	} else if (VALID_PAGE(u_root)) {
		mmu->sh_root_hpa = u_root;
	} else {
		KVM_BUG_ON(true);
	}
	kvm_mmu_set_init_gmm_root(vcpu, mmu->sh_root_hpa);
	if (!vcpu->arch.is_hv) {
		kvm_set_root_gmm_spt_list(gmm);
	}
	return 0;

failed:
	mmu->sh_root_hpa = TO_ERROR_PAGE(ret);
	return ret;
}

int kvm_hv_setup_shadow_paging(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	gva_t os_vptb, u_vptb;
	unsigned flags;
	bool mmu_is_load = false;
	e2k_core_mode_t core_mode;
	bool sep_virt_space;
	int ret;

	core_mode = read_guest_CORE_MODE_reg(vcpu);
	sep_virt_space = !!core_mode.CORE_MODE_sep_virt_space;

	complete_nonpaging_mode(vcpu);

	if (sep_virt_space) {
		/* create two kernel and user shadow PTs */
		flags = OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG;
		set_sep_virt_spaces(vcpu);
		u_vptb = MMU_SEPARATE_USER_VPTB;
		os_vptb = MMU_SEPARATE_KERNEL_VPTB;
		mmu->set_vcpu_sh_u_vptb(vcpu, u_vptb);
		mmu->set_vcpu_sh_os_vptb(vcpu, os_vptb);
	} else {
		/* create only one user shadow PT */
		flags = U_ROOT_PT_FLAG;
		reset_sep_virt_spaces(vcpu);
		os_vptb = MMU_UNITED_KERNEL_VPTB;
		mmu->set_vcpu_sh_u_vptb(vcpu, os_vptb);
	}

	/* setup page table structures type to properly manage PTs */
	mmu_set_vcpu_pt_struct(kvm, kvm_get_mmu_guest_pt_struct(vcpu));
	mmu_set_vcpu_pt_struct_func(kvm, &kvm_mmu_get_vcpu_pt_struct);

	/* It need create new shadow PT */
	mutex_lock(&vcpu->kvm->slots_lock);
	if (!kvm->arch.shadow_pt_set_up) {
		DebugSETPM("VCPU #%d shadow root PT is not yet created, so create\n",
			vcpu->vcpu_id);
		ret = setup_shadow_paging(vcpu, gmm, flags);
		if (ret) {
			pr_err("%s(): coiuld not create initial shadow PT error %d\n",
				__func__, ret);
			goto unlock_failed;
		}
		kvm->arch.shadow_pt_set_up = true;
		mmu_is_load = true;
	} else {
		DebugSETPM("VCPU #%d shadow PT has been already created\n", vcpu->vcpu_id);
	}
	mutex_unlock(&vcpu->kvm->slots_lock);
	if (!mmu_is_load) {
		kvm_mmu_load(vcpu, gmm, flags);
	}

	kvm_setup_mmu_spt_context(vcpu);

	return 0;

unlock_failed:
	mutex_unlock(&vcpu->kvm->slots_lock);
	return ret;
}

static void mmu_destroy_caches(void)
{
	if (pte_list_desc_cache)
		kmem_cache_destroy(pte_list_desc_cache);
	if (mmu_page_header_cache)
		kmem_cache_destroy(mmu_page_header_cache);
}

int kvm_mmu_module_init(void)
{
	pte_list_desc_cache = kmem_cache_create("pte_list_desc",
					    sizeof(struct pte_list_desc),
					    0, 0, NULL);
	if (!pte_list_desc_cache)
		goto nomem;

	mmu_page_header_cache = kmem_cache_create("kvm_mmu_page_header",
						  sizeof(struct kvm_mmu_page),
						  0, 0, NULL);
	if (!mmu_page_header_cache)
		goto nomem;

	if (percpu_counter_init(&kvm_total_used_mmu_pages, 0, GFP_KERNEL))
		goto nomem;

	register_shrinker(&mmu_shrinker);

	return 0;

nomem:
	mmu_destroy_caches();
	return -ENOMEM;
}

/*
 * Caculate mmu pages needed for kvm.
 */
unsigned int kvm_mmu_calculate_mmu_pages(struct kvm *kvm)
{
	unsigned int nr_mmu_pages;
	unsigned int  nr_pages = 0;
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int i;

	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		slots = __kvm_memslots(kvm, i);

		kvm_for_each_memslot(memslot, slots)
			nr_pages += memslot->npages;
	}

	nr_mmu_pages = nr_pages * KVM_PERMILLE_MMU_PAGES / 1000;
	nr_mmu_pages = max(nr_mmu_pages,
			   (unsigned int) KVM_MIN_ALLOC_MMU_PAGES);

	return nr_mmu_pages;
}

void kvm_mmu_destroy(struct kvm_vcpu *vcpu)
{
	kvm_mmu_unload(vcpu, OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG |
				GP_ROOT_PT_FLAG);
	free_mmu_pages(vcpu);
	kvm_vcpu_release_trap_cellar(vcpu);
	mmu_free_memory_caches(vcpu);
}

void kvm_mmu_module_exit(void)
{
	mmu_destroy_caches();
	percpu_counter_destroy(&kvm_total_used_mmu_pages);
	unregister_shrinker(&mmu_shrinker);
	mmu_audit_disable();
}
