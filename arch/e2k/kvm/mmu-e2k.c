/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

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

#undef	CHECK_MMU_PAGES_AVAILABLE

/*
 * When setting this variable to true it enables Two-Dimensional-Paging
 * where the hardware walks 2 page tables:
 * 1. the guest-virtual to guest-physical
 * 2. while doing 1. it walks guest-physical to host-physical
 * If the hardware supports that we don't need to do shadow paging.
 */
bool tdp_enabled = false;

#ifdef	MMU_DEBUG
bool dbg = false;
module_param(dbg, bool, 0644);
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

#undef	DEBUG_TDP_INJECT_MODE
#undef	DebugTDPINJ
#define	DEBUG_TDP_INJECT_MODE	0		/* TDP page faults */
						/* injection debug */
#define	DebugTDPINJ(fmt, args...)					\
({									\
	if (DEBUG_TDP_INJECT_MODE || kvm_debug)				\
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

#include <trace/events/kvm.h>

#define CREATE_TRACE_POINTS
#include "mmutrace-e2k.h"
#include "mmu-notifier-trace.h"

static struct kmem_cache *pte_list_desc_cache;
struct kmem_cache *mmu_page_header_cache;
const char *pte_list_desc_cache_name = "pte_list_desc";
const char *mmu_page_header_cache_name = "kvm_mmu_page_header";
const char *mmu_page_cache_name = "kvm_mmu_memory_pages";

static struct percpu_counter kvm_total_used_mmu_pages;

static void mmu_init_memory_caches(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu_pte_list_desc_cache.name = pte_list_desc_cache_name;
	vcpu->arch.mmu_page_header_cache.name = mmu_page_header_cache_name;
	vcpu->arch.mmu_page_cache.name = mmu_page_cache_name;
}

static int kvm_sync_shadow_root(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				hpa_t root_hpa, unsigned flags);

static int mmu_topup_memory_cache(struct kvm_mmu_memory_cache *cache,
				  struct kmem_cache *base_cache, int min)
{
	void *obj;

	cache->kmem_cache = base_cache;

	if (cache->nobjs >= min)
		return 0;
	trace_mmu_topup_memory_cache(cache->name, cache->nobjs, min,
			ARRAY_SIZE(cache->objects) - cache->nobjs);
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
	if (mc->nobjs)
		trace_mmu_free_memory_cache(mc->name, mc->nobjs);

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
	trace_mmu_topup_memory_cache(cache->name, cache->nobjs, min,
			ARRAY_SIZE(cache->objects) - cache->nobjs);
	while (cache->nobjs < ARRAY_SIZE(cache->objects)) {
		page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
		if (!page)
			return -ENOMEM;
		cache->objects[cache->nobjs++] = page;
	}
	return 0;
}

static void mmu_free_memory_cache_page(struct kvm_mmu_memory_cache *mc)
{
	if (mc->nobjs)
		trace_mmu_free_memory_cache(mc->name, mc->nobjs);

	while (mc->nobjs)
		free_page((unsigned long)mc->objects[--mc->nobjs]);
}

int mmu_topup_memory_caches(struct kvm_vcpu *vcpu)
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

bool mmu_need_topup_memory_caches(struct kvm_vcpu *vcpu)
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
	if (mc->kmem_cache) {
		trace_mmu_memory_cache_alloc_obj(mc->name, mc->nobjs);
		return kmem_cache_zalloc(mc->kmem_cache, gfp_flags);
	} else {
		trace_mmu_memory_cache_alloc_obj(mc->name, mc->nobjs);
		return (void *)__get_free_page(gfp_flags);
	}
}

void *mmu_memory_cache_alloc(struct kvm_mmu_memory_cache *mc)
{
	void *p;

	if (!mc->nobjs) {
		p = mmu_memory_cache_alloc_obj(mc,
			GFP_ATOMIC | __GFP_ACCOUNT | __GFP_ZERO);
	} else {
		trace_mmu_memory_cache_alloc(mc->name, mc->nobjs);
		p = mc->objects[--mc->nobjs];
	}

	E2K_KVM_BUG_ON(!p);

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

/*
 * Same as arch-independent kvm_host_page_size() but based on kvm
 * instead of vcpu structure
 */
unsigned long kvm_slot_page_size(struct kvm_memory_slot *slot, gfn_t gfn)
{
	struct vm_area_struct *vma;
	unsigned long addr, size;

	size = PAGE_SIZE;

	addr = __gfn_to_hva_memslot(slot, gfn);
	if (kvm_is_error_hva(addr))
		return size;

	mmap_read_lock(current->mm);
	vma = find_vma(current->mm, addr);
	if (!vma)
		goto out;

	size = vma_kernel_pagesize(vma);

out:
	mmap_read_unlock(current->mm);

	return size;
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
int pte_list_add(struct kvm_vcpu *vcpu, pgprot_t *spte,
			struct kvm_rmap_head *rmap_head)
{
	struct pte_list_desc *desc;
	int i, count = 0;

	if (!rmap_head->val) {
		rmap_printk("pte_list_add: %px %lx 0->1\n",
			spte, pgprot_val(*spte));
		rmap_head->val = (unsigned long)spte;
		trace_rmap_add_0_1_spte(rmap_head, spte);
	} else if (!(rmap_head->val & 1)) {
		rmap_printk("pte_list_add: %px %lx 1->many\n",
			spte, pgprot_val(*spte));
		desc = mmu_alloc_pte_list_desc(vcpu);
		desc->sptes[0] = (pgprot_t *)rmap_head->val;
		desc->sptes[1] = spte;
		rmap_head->val = (unsigned long)desc | 1;
		trace_rmap_add_1_many_spte(rmap_head, desc, spte);
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
			trace_rmap_add_new_desc(rmap_head, desc);
		}
		for (i = 0; desc->sptes[i]; ++i)
			++count;
		desc->sptes[i] = spte;
		trace_rmap_add_many_many_spte(rmap_head, desc, spte, i);
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
	trace_rmap_move_desc(rmap_head, desc, i, j);
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
	trace_rmap_remove_desc(rmap_head, desc, prev_desc);
	mmu_free_pte_list_desc(desc);
}

void pte_list_remove(pgprot_t *spte, struct kvm_rmap_head *rmap_head)
{
	struct pte_list_desc *desc;
	struct pte_list_desc *prev_desc;
	int i;

	if (!rmap_head->val) {
		pr_err("%s(): %px 0x%lx 0-> probably was already removed\n",
			__func__, spte, pgprot_val(*spte));
		trace_rmap_remove_0_bad_spte(rmap_head, spte);
		BUG();
	} else if (!(rmap_head->val & 1)) {
		rmap_printk("pte_list_remove:  %px 1->0\n", spte);
		DebugPTE("%px 1->0\n", spte);
		if ((pgprot_t *)rmap_head->val != spte) {
			pr_err("%s():  %px 0x%lx 1-> spte != %px (rmap head), "
				"probably was already removed\n",
				__func__, spte, pgprot_val(*spte),
				(pgprot_t *)rmap_head->val);
			trace_rmap_remove_1_bad_spte(rmap_head, spte);
			BUG();
		} else {
			trace_rmap_remove_1_0_spte(rmap_head, spte);
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
					trace_rmap_remove_many_many_spte(rmap_head,
						spte, desc, i);
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
		pr_err("%s(): could not find spte %px many->many, probably "
			"was already removed\n",
			__func__, spte);
		trace_rmap_remove_many_bad_spte(rmap_head, spte);
		BUG();
	}
}

bool rmap_can_add(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu_memory_cache *cache;

	cache = &vcpu->arch.mmu_pte_list_desc_cache;
	return mmu_memory_cache_free_objects(cache);
}

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
void kvm_mmu_notifier_wait(struct kvm *kvm, unsigned long mmu_seq)
{
	struct swait_queue_head *wqp = &kvm->arch.mmu_wq;
	DECLARE_SWAITQUEUE(wait);
	mmu_retry_t mmu_retry;

	spin_lock(&kvm->mmu_lock);

	mmu_retry = mmu_arch_notifier_retry(kvm, mmu_seq);
	if (mmu_retry == NO_MMU_RETRY) {
		/* nothing kvm mmu updates */
		goto out_unlock;
	} else if (mmu_retry == DO_MMU_RETRY) {
		/* there are commited kvm mmu updates */
		goto out_unlock;
	}

	spin_unlock(&kvm->mmu_lock);

	for (;;) {
		prepare_to_swait_exclusive(wqp, &wait, TASK_INTERRUPTIBLE);

		if (mmu_arch_notifier_retry(kvm, mmu_seq) != WAIT_FOR_MMU_RETRY)
			break;

		schedule();
	}

	finish_swait(wqp, &wait);
	return;

out_unlock:
	spin_unlock(&kvm->mmu_lock);
}

static bool kvm_mmu_notifier_wake_up(struct kvm *kvm)
{
	struct swait_queue_head *wqp = &kvm->arch.mmu_wq;

	if (swq_has_sleeper(wqp)) {
		swake_up_all(wqp);
		return true;
	}

	return false;
}

void kvm_arch_mmu_notifier_invalidate_range_end(struct kvm *kvm,
				const struct mmu_notifier_range *range)
{
	spin_lock(&kvm->mmu_lock);
	trace_kvm_unmap_hva_range_end(kvm, range->start, range->end, range->flags);
	if (likely(kvm->mmu_notifier_count == 0)) {
		kvm_mmu_notifier_wake_up(kvm);
	}
	spin_unlock(&kvm->mmu_lock);
}

#else	/* !KVM_ARCH_WANT_MMU_NOTIFIER */
void kvm_mmu_notifier_wait(struct kvm *kvm, unsigned long mmu_seq)
{
}
static bool kvm_mmu_notifier_wake_up(struct kvm *kvm)
{
	return false;
}
void kvm_arch_mmu_notifier_invalidate_range_end(struct kvm *kvm,
				const struct mmu_notifier_range *range)
{
	(void)kvm_mmu_notifier_wake_up(kvm);
}
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

/*
 * This value is the sum of all of the kvm instances's
 * kvm->arch.n_used_mmu_pages values.  We need a global,
 * aggregate version in order to make the slab shrinker
 * faster
 */
void kvm_mod_used_mmu_pages(struct kvm *kvm, int nr)
{
	kvm->arch.n_used_mmu_pages += nr;
	percpu_counter_add(&kvm_total_used_mmu_pages, nr);
}

void mmu_page_add_parent_pte(struct kvm_vcpu *vcpu,
			struct kvm_mmu_page *sp, pgprot_t *parent_pte)
{
	if (!parent_pte)
		return;

	trace_rmap_add_parent_pte(sp, parent_pte, &sp->parent_ptes);
	pte_list_add(vcpu, parent_pte, &sp->parent_ptes);
}

void mmu_page_remove_parent_pte(struct kvm_mmu_page *sp,
				       pgprot_t *parent_pte)
{
	trace_rmap_remove_parent_pte(sp, parent_pte, &sp->parent_ptes);
	pte_list_remove(parent_pte, &sp->parent_ptes);
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

static int nonpaging_sync_page(struct kvm_vcpu *vcpu,
			       struct kvm_mmu_page *sp)
{
	return 0;
}

#ifdef CONFIG_KVM_HW_VIRTUALIZATION
static int nonpaging_sync_gva(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				gva_t gva)
{
	return 0;
}

static long nonpaging_sync_gva_range(struct kvm_vcpu *vcpu,
				gmm_struct_t *gmm, gva_t gva_start,
				gva_t gva_end)
{
	return 0;
}
#endif

static void nonpaging_update_spte(struct kvm_vcpu *vcpu,
				  struct kvm_mmu_page *sp, pgprot_t *spte,
				  pgprotval_t gpte)
{
	WARN_ON(1);
}

int mmu_pages_add(struct kvm_mmu_pages *pvec, struct kvm_mmu_page *sp,
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

void kvm_unlink_unsync_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	WARN_ON(!sp->unsync);
	trace_kvm_mmu_sync_page(sp);
	sp->unsync = 0;
	--kvm->stat.mmu_unsync;
}

/* @sp->gfn should be write-protected at the call site */
static bool __kvm_sync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
			    struct list_head *invalid_list)
{
	if (sp->role.cr4_pae != !!is_pae(vcpu)) {
		mmu_pt_prepare_zap_page(vcpu->kvm, sp, invalid_list);
		return false;
	}

	if (mmu_pt_sync_page(vcpu, sp) == 0) {
		mmu_pt_prepare_zap_page(vcpu->kvm, sp, invalid_list);
		return false;
	}

	return true;
}

void kvm_mmu_flush_or_zap(struct kvm_vcpu *vcpu,
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

#ifdef	CONFIG_KVM_MMU_AUDIT
#include "mmu_audit.c"
#endif	/* CONFIG_KVM_MMU_AUDIT */

bool kvm_sync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
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

int mmu_pages_next(struct kvm_mmu_pages *pvec, struct mmu_page_path *parents,
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

int mmu_pages_first(struct kvm_mmu_pages *pvec,
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

void mmu_pages_clear_parents(struct mmu_page_path *parents, int pt_level)
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
	while (nr_unsync_leaf = mmu_pt_mmu_unsync_walk(vcpu->kvm, parent, &pages,
							PT_PAGE_TABLE_LEVEL),
			nr_unsync_leaf) {
		bool protected = false;

		DebugFREE("nr_unsync_leaf is not zero %d\n", nr_unsync_leaf);
		for_each_sp(pages, sp, parents, i)
			protected |= mmu_pt_rmap_write_protect(vcpu, sp->gfn);

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

void kvm_unsync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp)
{
	trace_kvm_mmu_unsync_page(sp);
	++vcpu->kvm->stat.mmu_unsync;
	sp->unsync = 1;

	mmu_pt_mark_parents_unsync(vcpu->kvm, sp);
}

static void __clear_sp_write_flooding_count(struct kvm_mmu_page *sp)
{
	atomic_set(&sp->write_flooding_count,  0);
}

void clear_sp_write_flooding_count(pgprot_t *spte)
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
		pgprot_val(init_pt) = mmu_pt_get_spte_valid_mask(vcpu->kvm);
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
	valid_pt = mmu_pt_get_spte_valid_mask(vcpu->kvm);

	for (i = 0; i < PT64_ENT_PER_PAGE; i++) {
		E2K_KVM_BUG_ON(pgprot_val(spt[i]) != valid_pt);
	}
}

static inline bool
kvm_compare_mmu_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
			gva_t gaddr, gfn_t gfn, bool is_direct, gpa_t gpt_gpa)
{
	gva_t sp_gva, pt_gva;
	unsigned index;
	const pt_struct_t *gpt;
	const pt_level_t *gpt_level;
	int level;

	if (unlikely(!is_paging(vcpu)))
		return true;

	level = sp->role.level;
	E2K_KVM_BUG_ON(level < PT_PAGE_TABLE_LEVEL);
	gpt = mmu_pt_get_vcpu_pt_struct(vcpu);
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
	if (!vcpu->arch.is_hv && is_direct && gpt_gpa != sp->huge_gpt_gpa) {
		/* different guest PTs point to same huge page mapping */
		return false;
	}
	return true;
}

struct kvm_mmu_page *kvm_mmu_get_page(struct kvm_vcpu *vcpu,
				      gfn_t gfn,
				      gva_t gaddr,
				      unsigned level,
				      int direct, gpa_t gpt_gpa,
				      unsigned access,
				      bool validate)
{
	union kvm_mmu_page_role role;
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

		if (unlikely(sp->released))
			continue;

		if (unlikely(!kvm_compare_mmu_page(vcpu, sp, gaddr, gfn,
							direct, gpt_gpa)))
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

		E2K_KVM_BUG_ON(sp->released);

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
	sp->huge_gpt_gpa = gpt_gpa;
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
		mmu_pt_account_shadowed(vcpu->kvm, sp);
		if (level == PT_PAGE_TABLE_LEVEL &&
				mmu_pt_rmap_write_protect(vcpu, gfn))
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

static void copy_guest_kernel_root_range(struct kvm_vcpu *vcpu, pgprot_t *dst_root)
{
	gmm_struct_t *init_gmm;
	pgprot_t *src_root;

	init_gmm = pv_vcpu_get_init_gmm(vcpu);
	src_root = (pgprot_t *)kvm_mmu_get_init_gmm_root(vcpu->kvm);

	mmu_pt_copy_guest_shadow_root_range(vcpu, init_gmm, dst_root, src_root,
		GUEST_KERNEL_PGD_PTRS_START, GUEST_KERNEL_PGD_PTRS_END);
}

static void copy_guest_user_root_range(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				pgprot_t *dst_root, pgprot_t *src_root)
{
	mmu_pt_copy_guest_shadow_root_range(vcpu, gmm, dst_root, src_root,
		GUEST_USER_PGD_PTRS_START, GUEST_USER_PGD_PTRS_END);
}

void copy_host_kernel_root_range(struct kvm_vcpu *vcpu, pgprot_t *dst_root)
{
	pgd_t *dst_pgd = (pgd_t *)dst_root;

	E2K_KVM_BUG_ON(vcpu->cpu < 0);
	copy_kernel_pgd_range(dst_pgd, mm_node_pgd(&init_mm, numa_node_id()));
}

static void release_guest_kernel_root_range(struct kvm *kvm, pgprot_t *root)
{
	mmu_pt_zap_linked_children(kvm, root,
		GUEST_KERNEL_PGD_PTRS_START, GUEST_KERNEL_PGD_PTRS_END);
}

static void release_guest_user_root_range(struct kvm *kvm, pgprot_t *root)
{
	mmu_pt_zap_linked_children(kvm, root,
		GUEST_USER_PGD_PTRS_START, GUEST_USER_PGD_PTRS_END);
}

void kvm_mmu_commit_zap_page(struct kvm *kvm, struct list_head *invalid_list)
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
		mmu_pt_free_page(kvm, sp);
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
	zapped = mmu_pt_prepare_zap_page(kvm, sp, invalid_list);

	return (zapped > 0) ? true : false;
}

void kvm_get_spt_translation(struct kvm_vcpu *vcpu, e2k_addr_t address,
	pgdval_t *pgd, pudval_t *pud, pmdval_t *pmd, pteval_t *pte, int *pt_level)
{
	kvm_shadow_trans_t st;
	pgprot_t spte;
	int level, level_off;

	E2K_KVM_BUG_ON(address >= NATIVE_TASK_SIZE);

	spin_lock(&vcpu->kvm->mmu_lock);

	level_off = mmu_pt_walk_shadow_pts(vcpu, address, &st, E2K_INVALID_PAGE);
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
			if (likely(!user_pud_huge(__pud(*pud)) &&
					!pud_none(__pud(*pud)) &&
						!pud_bad(__pud(*pud)))) {
				continue;
			}
			*pt_level = E2K_PUD_LEVEL_NUM;
			break;
		}

		if (level == E2K_PMD_LEVEL_NUM) {
			*pmd = pgprot_val(spte);
			if (likely(!user_pmd_huge(__pmd(*pmd)) &&
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
		mmu_pt_prepare_zap_page(kvm, sp, &invalid_list);
	}
	kvm_mmu_commit_zap_page(kvm, &invalid_list);
	spin_unlock(&kvm->mmu_lock);

	return r;
}
EXPORT_SYMBOL_GPL(kvm_mmu_unprotect_page);

bool mmu_need_write_protect(struct kvm_vcpu *vcpu, gfn_t gfn,
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
	}

	return false;
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

bool handle_abnormal_pfn(struct kvm_vcpu *vcpu, gva_t gva, gfn_t gfn,
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

bool page_fault_can_be_fast(u32 error_code)
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
	E2K_KVM_BUG_ON(is_phys_paging(vcpu));
	vcpu->arch.mmu.sh_u_root_hpa = root;
}
static void set_vcpu_nonp_sh_gk_pptb(struct kvm_vcpu *vcpu, hpa_t root)
{
	set_vcpu_nonp_sh_u_pptb(vcpu, root);
}
static void set_vcpu_nonp_u_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	vcpu->arch.mmu.u_vptb = base;
}
static void set_vcpu_nonp_sh_u_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	E2K_KVM_BUG_ON(is_phys_paging(vcpu));
	vcpu->arch.mmu.sh_u_vptb = base;
}
static void set_vcpu_nonp_os_pptb(struct kvm_vcpu *vcpu, pgprotval_t base)
{
	vcpu->arch.mmu.os_pptb = base;
}
static void set_vcpu_nonp_sh_os_pptb(struct kvm_vcpu *vcpu, hpa_t root)
{
	E2K_KVM_BUG_ON(is_phys_paging(vcpu));
	vcpu->arch.mmu.sh_os_root_hpa = root;
}
static void set_vcpu_nonp_os_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	vcpu->arch.mmu.os_vptb = base;
}
static void set_vcpu_nonp_sh_os_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	E2K_KVM_BUG_ON(is_phys_paging(vcpu));
	vcpu->arch.mmu.sh_os_vptb = base;
}
static void set_vcpu_nonp_os_vab(struct kvm_vcpu *vcpu, gva_t os_virt_base)
{
	E2K_KVM_BUG_ON(!is_sep_virt_spaces(vcpu));
	vcpu->arch.mmu.sh_os_vab = os_virt_base;
}
static void set_vcpu_nonp_gp_pptb(struct kvm_vcpu *vcpu, hpa_t root)
{
	E2K_KVM_BUG_ON(vcpu->arch.is_hv && !kvm_is_phys_pt_enable(vcpu->kvm));
	vcpu->arch.mmu.gp_root_hpa = root;
}
static void set_vcpu_nonp_pt_context(struct kvm_vcpu *vcpu, unsigned flags)
{
	if (likely((flags & GP_ROOT_PT_FLAG) && is_phys_paging(vcpu))) {
		E2K_KVM_BUG_ON(!VALID_PAGE(vcpu->arch.mmu.gp_root_hpa));
		write_GP_PPTB_reg(vcpu->arch.mmu.gp_root_hpa);
	} else if (is_shadow_paging(vcpu)) {
		if ((flags & U_ROOT_PT_FLAG) ||
				((flags & OS_ROOT_PT_FLAG) &&
					!is_sep_virt_spaces(vcpu))) {
			E2K_KVM_BUG_ON(!VALID_PAGE(vcpu->arch.mmu.sh_u_root_hpa));
			vcpu->arch.sw_ctxt.sh_u_pptb =
				vcpu->arch.mmu.sh_u_root_hpa;
			vcpu->arch.sw_ctxt.sh_u_vptb =
				vcpu->arch.mmu.sh_u_vptb;
		}
		if ((flags & OS_ROOT_PT_FLAG) && is_sep_virt_spaces(vcpu)) {
			E2K_KVM_BUG_ON(!VALID_PAGE(vcpu->arch.mmu.sh_os_root_hpa));
			write_SH_OS_PPTB_reg(vcpu->arch.mmu.sh_os_root_hpa);
			write_SH_OS_VPTB_reg(vcpu->arch.mmu.sh_os_vptb);
			write_SH_OS_VAB_reg(vcpu->arch.mmu.sh_os_vab);
		}
	} else {
		E2K_KVM_BUG_ON(true);
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
notrace __interrupt
static hpa_t get_vcpu_nonp_sh_u_pptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.sh_u_root_hpa;
}
static hpa_t get_vcpu_nonp_sh_gk_pptb(struct kvm_vcpu *vcpu)
{
	return get_vcpu_nonp_sh_u_pptb(vcpu);
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
notrace __interrupt
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
	E2K_KVM_BUG_ON(vcpu->arch.is_hv && !kvm_is_phys_pt_enable(vcpu->kvm));
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
	if (unlikely(current_thread_info()->vcpu != vcpu))
		return (pgprotval_t)vcpu->arch.hw_ctxt.sh_os_pptb;
	else
		return (pgprotval_t)read_SH_OS_PPTB_reg();
}
static gva_t get_vcpu_context_nonp_os_vptb(struct kvm_vcpu *vcpu)
{
	if (unlikely(current_thread_info()->vcpu != vcpu))
		return vcpu->arch.hw_ctxt.sh_os_vptb;
	else
		return read_SH_OS_VPTB_reg();
}
static gva_t get_vcpu_context_nonp_os_vab(struct kvm_vcpu *vcpu)
{
	if (unlikely(current_thread_info()->vcpu != vcpu))
		return vcpu->arch.hw_ctxt.sh_os_vab;
	else
		return read_SH_OS_VAB_reg();
}
static hpa_t get_vcpu_context_nonp_gp_pptb(struct kvm_vcpu *vcpu)
{
	E2K_KVM_BUG_ON(vcpu->arch.is_hv && !kvm_is_phys_pt_enable(vcpu->kvm));

	if (unlikely(current_thread_info()->vcpu != vcpu))
		return vcpu->arch.hw_ctxt.gp_pptb;
	else
		return read_GP_PPTB_reg();
}

#ifdef CONFIG_KVM_HW_VIRTUALIZATION
static void set_vcpu_tdp_u_pptb(struct kvm_vcpu *vcpu, pgprotval_t base)
{
	/* Guest can and must set, host should not change it */
	E2K_KVM_BUG_ON(!vcpu->arch.is_pv);
	vcpu->arch.mmu.u_pptb = base;
}
static void set_vcpu_tdp_sh_u_pptb(struct kvm_vcpu *vcpu, hpa_t root)
{
	/* shadow PTs are not used */
	E2K_KVM_BUG_ON(true);
}
static void set_vcpu_tdp_u_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	/* Guest can and must set, host should not change it */
	E2K_KVM_BUG_ON(!vcpu->arch.is_pv);
	vcpu->arch.mmu.u_vptb = base;
}
static void set_vcpu_tdp_sh_u_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	/* shadow PTs are not used, so same as guest native PTs */
	E2K_KVM_BUG_ON(true);
}
static void set_vcpu_tdp_os_pptb(struct kvm_vcpu *vcpu, pgprotval_t base)
{
	/* Guest can and must set, host should not change it */
	E2K_KVM_BUG_ON(!vcpu->arch.is_pv);
	vcpu->arch.mmu.os_pptb = base;
}
static void set_vcpu_tdp_sh_os_pptb(struct kvm_vcpu *vcpu, hpa_t root)
{
	/* shadow PTs are not used, so same as guest native PTs */
	E2K_KVM_BUG_ON(true);
}
static void set_vcpu_tdp_os_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	/* Guest can and must set, host should not change it */
	E2K_KVM_BUG_ON(!vcpu->arch.is_pv);
	vcpu->arch.mmu.os_vptb = base;
}
static void set_vcpu_tdp_sh_os_vptb(struct kvm_vcpu *vcpu, gva_t base)
{
	/* shadow PTs are not used, so same as guest native PTs */
	E2K_KVM_BUG_ON(true);
}
static void set_vcpu_tdp_os_vab(struct kvm_vcpu *vcpu, gva_t os_virt_base)
{
	/* Guest can and must set, host should not change it */
	E2K_KVM_BUG_ON(!vcpu->arch.is_pv);
	vcpu->arch.mmu.sh_os_vab = os_virt_base;
}
static void set_vcpu_tdp_gp_pptb(struct kvm_vcpu *vcpu, hpa_t root)
{
	vcpu->arch.mmu.gp_root_hpa = root;
}
static void set_vcpu_tdp_pt_context(struct kvm_vcpu *vcpu, unsigned flags)
{
	E2K_KVM_BUG_ON(!is_phys_paging(vcpu));
	if ((flags & GP_ROOT_PT_FLAG) && likely(is_phys_paging(vcpu))) {
		E2K_KVM_BUG_ON(!VALID_PAGE(vcpu->arch.mmu.gp_root_hpa));
		write_GP_PPTB_reg(vcpu->arch.mmu.gp_root_hpa);
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
notrace __interrupt
static hpa_t get_vcpu_tdp_sh_u_pptb(struct kvm_vcpu *vcpu)
{
	/* shadow PT does not be used */
	E2K_KVM_BUG_ON(true);
	return (hpa_t)-EINVAL;
}
static gva_t get_vcpu_tdp_u_vptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.u_vptb;
}
static gva_t get_vcpu_tdp_sh_u_vptb(struct kvm_vcpu *vcpu)
{
	/* shadow PT does not be used */
	E2K_KVM_BUG_ON(true);
	return (gva_t)-EINVAL;
}
static pgprotval_t get_vcpu_tdp_os_pptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.os_pptb;
}
notrace __interrupt
static hpa_t get_vcpu_tdp_sh_os_pptb(struct kvm_vcpu *vcpu)
{
	/* shadow PT does not be used */
	E2K_KVM_BUG_ON(true);
	return (hpa_t)-EINVAL;
}
static gva_t get_vcpu_tdp_os_vptb(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.os_vptb;
}
static gva_t get_vcpu_tdp_sh_os_vptb(struct kvm_vcpu *vcpu)
{
	/* shadow PT does not be used */
	E2K_KVM_BUG_ON(true);
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
	if (unlikely(current_thread_info()->vcpu != vcpu))
		return vcpu->arch.hw_ctxt.sh_os_pptb;
	else
		return (pgprotval_t)read_SH_OS_PPTB_reg();
}
static gva_t get_vcpu_context_tdp_os_vptb(struct kvm_vcpu *vcpu)
{
	if (unlikely(current_thread_info()->vcpu != vcpu))
		return vcpu->arch.hw_ctxt.sh_os_vptb;
	else
		return read_SH_OS_VPTB_reg();
}
static gva_t get_vcpu_context_tdp_os_vab(struct kvm_vcpu *vcpu)
{
	if (unlikely(current_thread_info()->vcpu != vcpu))
		return vcpu->arch.hw_ctxt.sh_os_vab;
	else
		return read_SH_OS_VAB_reg();
}
static hpa_t get_vcpu_context_tdp_gp_pptb(struct kvm_vcpu *vcpu)
{
	E2K_KVM_BUG_ON(!is_phys_paging(vcpu));
	if (!VALID_PAGE(get_vcpu_tdp_gp_pptb(vcpu))) {
		return E2K_INVALID_PAGE;
	}
	if (unlikely(current_thread_info()->vcpu != vcpu))
		return vcpu->arch.hw_ctxt.gp_pptb;
	else
		return read_GP_PPTB_reg();
}
#endif

static void set_vcpu_spt_u_pptb(struct kvm_vcpu *vcpu, pgprotval_t base)
{
	vcpu->arch.mmu.u_pptb = base;
}
static void set_vcpu_spt_sh_u_pptb(struct kvm_vcpu *vcpu, hpa_t root)
{
	/* hypervisor replaces the guest value with its own */
	vcpu->arch.mmu.sh_u_root_hpa = root;
}
static void set_vcpu_spt_sh_gk_pptb(struct kvm_vcpu *vcpu, hpa_t gk_root)
{
	vcpu->arch.mmu.sh_gk_root_hpa = gk_root;
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
	E2K_KVM_BUG_ON(VALID_PAGE(root));
	vcpu->arch.mmu.gp_root_hpa = root;
}
static void set_vcpu_spt_u_pptb_context(struct kvm_vcpu *vcpu)
{
	E2K_KVM_BUG_ON(!VALID_PAGE(vcpu->arch.mmu.sh_u_root_hpa));
	vcpu->arch.sw_ctxt.sh_u_pptb = vcpu->arch.mmu.sh_u_root_hpa;
}
static void set_vcpu_spt_pt_context(struct kvm_vcpu *vcpu, unsigned flags)
{
	if ((flags & U_ROOT_PT_FLAG) ||
			((flags & OS_ROOT_PT_FLAG) &&
					!is_sep_virt_spaces(vcpu))) {
		set_vcpu_spt_u_pptb_context(vcpu);
		vcpu->arch.sw_ctxt.sh_u_vptb = vcpu->arch.mmu.sh_u_vptb;
	}
	if ((flags & OS_ROOT_PT_FLAG) && is_sep_virt_spaces(vcpu)) {
		E2K_KVM_BUG_ON(!VALID_PAGE(vcpu->arch.mmu.sh_os_root_hpa));
		write_SH_OS_PPTB_reg(vcpu->arch.mmu.sh_os_root_hpa);
		write_SH_OS_VPTB_reg(vcpu->arch.mmu.sh_os_vptb);
		write_SH_OS_VAB_reg(vcpu->arch.mmu.sh_os_vab);
	}
	if ((flags & GP_ROOT_PT_FLAG) && likely(is_phys_paging(vcpu))) {
		/* GP_* tables should not changed from nonpaging mode */
		E2K_KVM_BUG_ON(read_GP_PPTB_reg() != vcpu->arch.mmu.gp_root_hpa);
	}
}
static void init_vcpu_spt_ptb(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.u_pptb = 0;
	vcpu->arch.mmu.sh_u_root_hpa = E2K_INVALID_PAGE;
	vcpu->arch.mmu.sh_gk_root_hpa = E2K_INVALID_PAGE;
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
notrace __interrupt
static notrace hpa_t get_vcpu_spt_sh_u_pptb(struct kvm_vcpu *vcpu)
{
	/* hypervisor replaces the guest value with its own */
	return vcpu->arch.mmu.sh_u_root_hpa;
}
static notrace hpa_t get_vcpu_spt_sh_gk_pptb(struct kvm_vcpu *vcpu)
{
	/* hypervisor replaces the guest value with its own */
	return vcpu->arch.mmu.sh_gk_root_hpa;
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
notrace __interrupt
static notrace hpa_t get_vcpu_spt_sh_os_pptb(struct kvm_vcpu *vcpu)
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
static notrace hpa_t get_vcpu_spt_gp_pptb(struct kvm_vcpu *vcpu)
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
	E2K_KVM_BUG_ON(!is_phys_paging(vcpu) && vcpu->arch.is_hv);
	return read_GP_PPTB_reg();
}

int mmu_pt_unmap_hva_range(struct kvm *kvm, unsigned long start,
				unsigned long end, unsigned flags)
{
	return kvm->arch.mmu_pt_ops.unmap_hva_range(kvm, start, end, flags);
}

int mmu_pt_set_spte_hva(struct kvm *kvm, unsigned long hva, pte_t pte)
{
	return kvm->arch.mmu_pt_ops.set_spte_hva(kvm, hva, pte);
}

int mmu_pt_age_hva(struct kvm *kvm, unsigned long start, unsigned long end)
{
	return kvm->arch.mmu_pt_ops.age_hva(kvm, start, end);
}

int mmu_pt_test_age_hva(struct kvm *kvm, unsigned long hva)
{
	return kvm->arch.mmu_pt_ops.test_age_hva(kvm, hva);
}

void kvm_arch_mmu_enable_log_dirty_pt_masked(struct kvm *kvm,
					struct kvm_memory_slot *slot,
					gfn_t gfn_offset,
					unsigned long mask)
{
	kvm->arch.mmu_pt_ops.arch_mmu_enable_log_dirty_pt_masked(kvm,
						slot, gfn_offset, mask);
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

static void do_free_spt_root(struct kvm *kvm, hpa_t root_hpa, bool force)
{
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
		E2K_KVM_BUG_ON(sp->root_count <= 0);
	} else {
		/* FIXME: root counter should be zero to release sp. */
		/* It need implement strict mechanism get()/put() */
		/* to account the current users of the structure */
		--sp->root_count;
		E2K_KVM_BUG_ON(sp->root_count != 0);
		sp->released = true;
	}
	DebugFREE("freed root 0x%llx, SP at %px, count %d (invalid %d), "
		"gfn 0x%llx\n",
		root_hpa, sp, sp->root_count, sp->role.invalid, sp->gfn);
	if (!sp->root_count && sp->role.invalid || force) {
		int zapped = mmu_pt_prepare_zap_page(kvm, sp, &invalid_list);
		DebugFREE("zapped %d pages\n", zapped);
		kvm_mmu_commit_zap_page(kvm, &invalid_list);
	}
	spin_unlock(&kvm->mmu_lock);
}

void mmu_free_spt_root(struct kvm_vcpu *vcpu, hpa_t root_hpa)
{
	do_free_spt_root(vcpu->kvm, root_hpa, false);
}

void mmu_release_spt_root(struct kvm *kvm, hpa_t root_hpa)
{
	do_free_spt_root(kvm, root_hpa, true);
}

void mmu_release_nonpaging_root(struct kvm *kvm, hpa_t root_hpa)
{
	do_free_spt_root(kvm, root_hpa, true);
}

void mmu_release_spt_nonpaging_root(struct kvm *kvm, hpa_t root_hpa)
{
	struct kvm_mmu_page *root_sp;
	LIST_HEAD(invalid_list);
	int zapped;

	/* nonpaging PT root has been loaded by each VCPUs */
	root_sp = page_header(root_hpa);

	KVM_WARN_ON(root_sp->root_count != atomic_read(&kvm->online_vcpus));
	root_sp->root_count = 0;
	root_sp->role.invalid = true;
	root_sp->released = true;

	zapped = mmu_pt_prepare_zap_page(kvm, root_sp, &invalid_list);
	DebugFREE("zapped %d pages\n", zapped);
	kvm_mmu_commit_zap_page(kvm, &invalid_list);
}

static void e2k_mmu_free_roots(struct kvm_vcpu *vcpu, unsigned flags)
{
	hpa_t gp_root, os_root, u_root;

	E2K_KVM_BUG_ON(!(vcpu->arch.mmu.shadow_root_level == PT64_ROOT_LEVEL &&
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
			vcpu->kvm->arch.nonp_root_hpa = E2K_INVALID_PAGE;
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
	if (likely(!VALID_PAGE(os_root) && !VALID_PAGE(u_root)))
		return;

	if (unlikely(VALID_PAGE(u_root) &&
			((flags & U_ROOT_PT_FLAG) ||
				((flags & OS_ROOT_PT_FLAG) &&
						!is_sep_virt_spaces(vcpu))))) {
		mmu_free_spt_root(vcpu, u_root);
		kvm_set_space_type_spt_u_root(vcpu, E2K_INVALID_PAGE);
		kvm_set_space_type_spt_gk_root(vcpu,
					pv_vcpu_get_init_root_hpa(vcpu));
	}
	if (unlikely(VALID_PAGE(os_root) && (flags & OS_ROOT_PT_FLAG))) {
		mmu_free_spt_root(vcpu, os_root);
		kvm_set_space_type_spt_os_root(vcpu, E2K_INVALID_PAGE);
	}
}

void mmu_free_roots(struct kvm_vcpu *vcpu, unsigned flags)
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

	if (vcpu->arch.mmu.pae_root == NULL)
		return;

	spin_lock(&vcpu->kvm->mmu_lock);
	for (i = 0; i < 4; ++i) {
		hpa_t root = vcpu->arch.mmu.pae_root[i];

		if (root && root != E2K_INVALID_PAGE) {
			root &= mmu_pt_get_spte_pfn_mask(vcpu->kvm);
			sp = page_header(root);
			--sp->root_count;
			if (!sp->root_count && sp->role.invalid)
				mmu_pt_prepare_zap_page(vcpu->kvm, sp,
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

	DebugKVM("started on VCPU #%d\n", vcpu->vcpu_id);
	if (vcpu->arch.mmu.shadow_root_level == PT64_ROOT_LEVEL) {
		hpa_t root;

		MMU_WARN_ON(VALID_PAGE(kvm_get_gp_phys_root(vcpu)));

		spin_lock(&vcpu->kvm->mmu_lock);
#ifdef	CHECK_MMU_PAGES_AVAILABLE
		if (make_mmu_pages_available(vcpu) < 0) {
			spin_unlock(&vcpu->kvm->mmu_lock);
			pr_err("%s(): there are not mmu available pages\n",
				__func__);
			return -ENOSPC;
		}
#endif	/* CHECK_MMU_PAGES_AVAILABLE */
		sp = kvm_mmu_get_page(vcpu, 0, 0, PT64_ROOT_LEVEL,
					true, 0,
					ACC_ALL, false /* validate */);
		++sp->root_count;
		spin_unlock(&vcpu->kvm->mmu_lock);
		root = __pa(sp->spt);
		kvm_set_gp_phys_root(vcpu, root);
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
	E2K_KVM_BUG_ON(vcpu->arch.mmu.root_level != PT64_ROOT_LEVEL);

	spin_lock(&vcpu->kvm->mmu_lock);
#ifdef	CHECK_MMU_PAGES_AVAILABLE
	if (make_mmu_pages_available(vcpu) < 0) {
		spin_unlock(&vcpu->kvm->mmu_lock);
		pr_err("%s(): there are not mmu available pages\n", __func__);
		return E2K_INVALID_PAGE;
	}
#endif	/* CHECK_MMU_PAGES_AVAILABLE */
	sp = kvm_mmu_get_page(vcpu, root_gfn, 0, PT64_ROOT_LEVEL,
			false, gfn_to_gpa(root_gfn),
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
	E2K_KVM_BUG_ON(mmu->root_level != PT64_ROOT_LEVEL);

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
		if (pv_vcpu_is_init_gmm(vcpu, gmm)) {
			/* guest kernel root is the same as init root */
			kvm_set_space_type_spt_gk_root(vcpu, root);
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
	if (pv_vcpu_is_init_gmm(vcpu, gmm)) {
		/* guest kernel root is the same as init root */
		kvm_set_space_type_spt_gk_root(vcpu, root);
	}
	if (!(flags & DONT_SYNC_ROOT_PT_FLAG)) {
		kvm_sync_shadow_root(vcpu, gmm, root, U_ROOT_PT_FLAG);
	}
	DebugSPT("VCPU #%d, guest U_PT root at 0x%llx, shadow root "
		"at 0x%llx\n",
		vcpu->vcpu_id, root_gpa, root);

	return 0;
}

static int mmu_alloc_shadow_roots(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
					unsigned flags)
{
	E2K_KVM_BUG_ON(vcpu->arch.mmu.direct_map);
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

	E2K_KVM_BUG_ON(vcpu->arch.mmu.root_level != PT64_ROOT_LEVEL);

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
			root &= mmu_pt_get_spte_pfn_mask(vcpu->kvm);
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

pf_res_t handle_mmu_page_fault(struct kvm_vcpu *vcpu, gva_t address,
				u32 error_code, bool prefault,
				gfn_t *gfn, kvm_pfn_t *pfn)
{
	intc_mu_state_t *mu_state = get_intc_mu_state(vcpu);
	pf_res_t pfres;
	int try = 0, retry = 0;

	do {
		pfres = mmu_pt_page_fault(vcpu, address, error_code,
					  prefault, gfn, pfn);
		if (likely(pfres != PFRES_RETRY))
			break;
		if (!mu_state->may_be_retried) {
			/* cannot be retried */
			break;
		}
		retry++;
		try++;
		if (retry >= PF_RETRIES_MAX_NUM) {
			DebugTRY("try #%d seq 0x%lx to handle page fault : "
				"address 0x%lx, pfn 0x%llx / gfn 0x%llx\n",
				try, mu_state->notifier_seq, address,
				(pfn != NULL) ? *pfn : ~0ULL,
				(gfn != NULL) ? *gfn : ~0ULL);
			kvm_mmu_notifier_wait(vcpu->kvm, mu_state->notifier_seq);
			retry = 0;
		}
	} while (true);

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

bool page_fault_handle_page_track(struct kvm_vcpu *vcpu,
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

#ifdef CONFIG_KVM_HW_VIRTUALIZATION
static void move_mu_intc_to_trap_cellar(struct kvm_vcpu *vcpu, int evn_no)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	int mu_num = intc_ctxt->mu_num;
	unsigned long evn_mask;

	E2K_KVM_BUG_ON(evn_no < 0 || evn_no >= mu_num);
	evn_mask = 1UL << evn_no;

	E2K_KVM_BUG_ON(intc_ctxt->intc_mu_to_move & evn_mask);
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

	E2K_KVM_BUG_ON(from_evn_no < 0 || from_evn_no >= mu_num);

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
	E2K_KVM_BUG_ON(intc_ctxt->intc_mu_to_move != 0);

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

	E2K_KVM_BUG_ON(evn_no < 0 || evn_no >= mu_num);

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

	E2K_KVM_BUG_ON(ret != 0);
}

static int inject_tdp_data_page_fault(struct kvm_vcpu *vcpu, int evn_no,
				 intc_info_mu_t *mu_event)
{
	int event;
	e2k_addr_t address;

	event = mu_event->hdr.event_code;
	address = mu_event->gva;

	DebugTDPINJ("intercept event #%d code %d %s, guest address 0x%lx "
		"fault type 0x%x\n",
		evn_no, event, kvm_get_mu_event_name(event),
		address, AS(mu_event->condition).fault_type);

	/* update event code to inject by hardware the event to guest */
	mu_event->hdr.event_code = IME_FORCED_GVA;
	kvm_set_intc_info_mu_is_updated(vcpu);

	/* inject page fault exception into TIRs */
	kvm_need_create_vcpu_exception(vcpu, exc_data_page_mask);

	return 0;
}

static void inject_tdp_page_fault(struct kvm_vcpu *vcpu,
					kvm_arch_exception_t *fault)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	intc_info_mu_t *mu_event;
	int mu_num = intc_ctxt->mu_num;
	int evn_no = intc_ctxt->cur_mu;
	int event;
	int ret = 0;

	E2K_KVM_BUG_ON(evn_no < 0 || evn_no >= mu_num);

	mu_event = &intc_ctxt->mu[evn_no];
	event = mu_event->hdr.event_code;

	DebugTDPINJ("INTC MU event #%d code %d %s\n",
		evn_no, event, kvm_get_mu_event_name(event));

	switch (event) {
	case IME_GPA_DATA:
		ret = inject_tdp_data_page_fault(vcpu, evn_no, mu_event);
		break;
	default:
		pr_err("%s(): event #%d %s should not cause injection\n",
			__func__, evn_no, kvm_get_mu_event_name(event));
		ret = -EINVAL;
		break;
	}

	E2K_KVM_BUG_ON(ret != 0);
}
#else
static void inject_shadow_page_fault(struct kvm_vcpu *vcpu,
					kvm_arch_exception_t *fault)
{
	BUG();
}
#endif /* CONFIG_KVM_HW_VIRTUALIZATION */

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
enum exec_mmu_ret calculate_guest_recovery_load_to_rf_frame(
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
		E2K_KVM_BUG_ON(true);
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

	E2K_KVM_BUG_ON(*radr != rind);

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

bool check_guest_spill_fill_recovery(tc_cond_t cond, e2k_addr_t address, bool s_f,
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
	tcellar->is_hva = 1;
	DebugREEXEC("converted guest address 0x%lx, gfn 0x%llx to hva 0x%lx "
		"to recovery guest %s operation\n",
		address, gfn, hva, (AS(cond).store) ? "store" : "load");

	if (regs->trap->curr_cnt + 1 < get_vcpu_mu_events_num(vcpu)) {
		next_tcellar = tcellar + 1;
	} else {
		next_tcellar = NULL;
	}
	r = execute_mmu_operations(tcellar, next_tcellar, regs, NULL,
			NULL,	/*&check_guest_spill_fill_recovery,*/
			NULL,	/*&calculate_guest_recovery_load_to_rf_frame*/
			false	/* user privileged space access */);
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
			mmu_pt_prepare_zap_page(vcpu->kvm, sp,
						&invalid_list);
			continue;
		}
		kvm_unsync_page(vcpu, sp);
	}
	kvm_mmu_commit_zap_page(vcpu->kvm, &invalid_list);
	spin_unlock(&vcpu->kvm->mmu_lock);

	return 0;
}

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
		/* fault was handled or injected to guest */
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
bool kvm_arch_async_page_not_present(struct kvm_vcpu *vcpu,
				     struct kvm_async_pf *work)
{
	if (!kvm_set_apf_reason(vcpu, KVM_APF_PAGE_IN_SWAP) &&
			!kvm_set_apf_id(vcpu, work->arch.apf_id)) {
		vcpu->arch.apf.host_apf_reason = KVM_APF_PAGE_IN_SWAP;
		kvm_need_create_vcpu_exception(vcpu, exc_data_page_mask);
	} else {
		pr_err("%s(); kill guest: Host: async_pf, error while "
			"setting apf_reason and apf_id\n",
			__func__);
		force_sig(SIGKILL);
	}

	return true;
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
			pr_err("%s(): kill guest: Host: async_pf, APIC is not"
				"supported\n", __func__);
			force_sig(SIGKILL);
			break;
		default:
			pr_err("%s(): kill guest: Host: async_pf, unsupported "
				"type of irq controller\n", __func__);
			force_sig(SIGKILL);
		}
	} else {
		pr_err("%s(): kill guest: Host: async_pf, error while setting "
			"apf_reason and apf_id\n", __func__);
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
	intc_mu_state_t *mu_state = get_intc_mu_state(vcpu);
	int try = 0, retry = 0;

	for (;;) {
		ret = mmu_pt_page_fault(vcpu, work->cr2_or_gpa, 0,
					true, &gfnp, &pfnp);

		if (ret != PFRES_RETRY)
			break;

		retry++;
		try++;
		if (retry >= PF_RETRIES_MAX_NUM) {
			kvm_mmu_notifier_wait(vcpu->kvm, mu_state->notifier_seq);
			retry = 0;
		}
	}
}

bool kvm_arch_can_dequeue_async_page_present(struct kvm_vcpu *vcpu)
{
	u32 guest_apf_reason, guest_apf_id;

	if (kvm_get_apf_reason(vcpu, &guest_apf_reason) ||
			kvm_get_apf_id(vcpu, &guest_apf_id)) {
		pr_err("%s(): kill guest: get async page fault reason or ID "
			"failed\n", __func__);
		force_sig(SIGKILL);
		return false;
	}

	return vcpu->arch.apf.enabled &&
			guest_apf_reason == KVM_APF_NO && guest_apf_id == 0;
}

#endif /* CONFIG_KVM_ASYNC_PF */

bool try_async_pf(struct kvm_vcpu *vcpu, bool prefault, gfn_t gfn,
		  gva_t gva, kvm_pfn_t *pfn, bool write, bool *writable)
{
	struct kvm_memory_slot *slot;
#ifdef CONFIG_KVM_ASYNC_PF
	bool async;
#endif

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

try_pf_err_t try_atomic_pf(struct kvm_vcpu *vcpu, gfn_t gfn,
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
		E2K_KVM_BUG_ON(true);
#endif
	} else if (is_error_pfn(*pfn)) {
		pr_err("%s(): gfn_to_pfn_memslot_atomic() for gfn 0x%llx "
			"failed\n",
			__func__, gfn);
		return TO_TRY_PF_ERR(-EFAULT);
	}
	return TRY_PF_NO_ERR;
}

static void nonpaging_init_context(struct kvm_vcpu *vcpu,
				   struct kvm_mmu *context)
{
#ifdef CONFIG_KVM_HW_VIRTUALIZATION
	if (kvm_is_tdp_enable(vcpu->kvm)) {
		if (vcpu->arch.mmu.virt_ctrl_mu.rw_mmu_cr) {
			/* access to MMU_CR register is intercepted */
			/* so paging state can be accessed as soft flag */
			context->is_paging = NULL;
		} else {
			/* paging state can be accessed only though SH_MMU_CR */
			context->is_paging = kvm_mmu_is_hv_paging;
		}
	} else
#endif /* CONFIG_KVM_HW_VIRTUALIZATION */
	{
		context->is_paging = NULL;
	}
	context->set_vcpu_u_pptb = set_vcpu_nonp_u_pptb;
	context->set_vcpu_sh_u_pptb = set_vcpu_nonp_sh_u_pptb;
	context->set_vcpu_sh_gk_pptb = set_vcpu_nonp_sh_gk_pptb;
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
	context->get_vcpu_sh_gk_pptb = get_vcpu_nonp_sh_gk_pptb;
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
	context->sync_page = nonpaging_sync_page;
	context->update_spte = nonpaging_update_spte;
	context->inject_page_fault = NULL;
	context->root_level = 0;
	context->shadow_root_level = PT64_ROOT_LEVEL;
	context->sh_os_root_hpa = E2K_INVALID_PAGE;
	context->sh_u_root_hpa = E2K_INVALID_PAGE;
	context->sh_gk_root_hpa = E2K_INVALID_PAGE;
	context->gp_root_hpa = E2K_INVALID_PAGE;
	context->sh_root_hpa = E2K_INVALID_PAGE;
	context->direct_map = true;
	context->nx = false;

	mmu_pt_init_mmu_nonpaging_context(vcpu, context);
}

void kvm_mmu_new_pptb(struct kvm_vcpu *vcpu, unsigned flags)
{
	mmu_free_roots(vcpu, flags);
}

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
#ifdef CONFIG_KVM_HW_VIRTUALIZATION
static void reset_tdp_shadow_zero_bits_mask(struct kvm_vcpu *vcpu,
				struct kvm_mmu *context)
{
	if (is_ss(vcpu))
		pr_err("FIXME: %s() is not implemented\n", __func__);
}
#endif /* CONFIG_KVM_HW_VIRTUALIZATION */
void
reset_shadow_zero_bits_mask(struct kvm_vcpu *vcpu, struct kvm_mmu *context)
{
	if (is_ss(vcpu))
		pr_err("FIXME: %s() is not implemented\n", __func__);
}

static void update_last_nonleaf_level(struct kvm_vcpu *vcpu,
						struct kvm_mmu *mmu)
{
	unsigned root_level = mmu->root_level;

	mmu->last_nonleaf_level = root_level;
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
	context->set_vcpu_sh_gk_pptb = set_vcpu_spt_sh_gk_pptb;
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
	context->get_vcpu_sh_gk_pptb = get_vcpu_spt_sh_gk_pptb;
	context->get_vcpu_u_vptb = get_vcpu_spt_u_vptb;
	context->get_vcpu_sh_u_vptb = get_vcpu_spt_sh_u_vptb;
	context->get_vcpu_os_pptb = get_vcpu_spt_os_pptb;
	context->get_vcpu_sh_os_pptb = get_vcpu_spt_sh_os_pptb;
	context->get_vcpu_os_vptb = get_vcpu_spt_os_vptb;
	context->get_vcpu_sh_os_vptb = get_vcpu_spt_sh_os_vptb;
	context->get_vcpu_os_vab = get_vcpu_spt_os_vab;
	context->get_vcpu_gp_pptb = get_vcpu_spt_gp_pptb;
	context->set_vcpu_u_pptb_context = set_vcpu_spt_u_pptb_context;
	context->set_vcpu_pt_context = set_vcpu_spt_pt_context;
	context->init_vcpu_ptb = init_vcpu_spt_ptb;
	context->get_vcpu_context_u_pptb = get_vcpu_context_spt_u_pptb;
	context->get_vcpu_context_u_vptb = get_vcpu_context_spt_u_vptb;
	context->get_vcpu_context_os_pptb = get_vcpu_context_spt_os_pptb;
	context->get_vcpu_context_os_vptb = get_vcpu_context_spt_os_vptb;
	context->get_vcpu_context_os_vab = get_vcpu_context_spt_os_vab;
	context->get_vcpu_context_gp_pptb = get_vcpu_context_spt_gp_pptb;
	context->shadow_root_level = level;
	context->sh_os_root_hpa = E2K_INVALID_PAGE;
	context->sh_u_root_hpa = E2K_INVALID_PAGE;
	context->sh_gk_root_hpa = E2K_INVALID_PAGE;
	context->direct_map = false;

	mmu_pt_init_mmu_spt_context(vcpu, context);
}

static void e2k_paging_init_context(struct kvm_vcpu *vcpu,
				  struct kvm_mmu *context)
{
	e2k_paging_init_context_common(vcpu, context, PT_E2K_ROOT_LEVEL);
}

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

static void init_kvm_nonpaging_mmu(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *context = &vcpu->arch.mmu;

	DebugKVM("started on VCPU #%d is PV %s, is HV %s\n",
		vcpu->vcpu_id,
		(vcpu->arch.is_pv) ? "true" : "false",
		(vcpu->arch.is_hv) ? "true" : "false");

	E2K_KVM_BUG_ON(is_paging(vcpu));

	nonpaging_init_context(vcpu, context);
}

#ifdef CONFIG_KVM_HW_VIRTUALIZATION
static void init_kvm_tdp_mmu(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *context = &vcpu->arch.mmu;

	DebugTDP("started on VCPU #%d\n", vcpu->vcpu_id);

	context->base_role.word = 0;
	context->base_role.smm = is_smm(vcpu);
	context->sync_page = nonpaging_sync_page;
	context->sync_gva = nonpaging_sync_gva;
	context->sync_gva_range = nonpaging_sync_gva_range;
	context->update_spte = nonpaging_update_spte;
	context->inject_page_fault = inject_tdp_page_fault;
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

	if (!is_paging(vcpu)) {
		context->nx = false;
		context->root_level = 0;
	} else if (!is_ss(vcpu)) {
		context->nx = is_nx(vcpu);
		context->root_level = PT_E2K_ROOT_LEVEL;
		reset_rsvds_bits_mask(vcpu, context);
	}

	mmu_pt_init_mmu_tdp_context(vcpu, context);

	update_permission_bitmask(vcpu, context, false);
	update_pkru_bitmask(vcpu, context, false);
	update_last_nonleaf_level(vcpu, context);
	reset_tdp_shadow_zero_bits_mask(vcpu, context);
}
#else
static void init_kvm_tdp_mmu(struct kvm_vcpu *vcpu)
{
	panic("kvm: trying to initialize TDP on hardware without it");
}
#endif

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
		E2K_KVM_BUG_ON(true);
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

static void kvm_mmu_reset_context(struct kvm_vcpu *vcpu, unsigned flags)
{
	kvm_mmu_unload(vcpu, flags);
	init_kvm_mmu(vcpu);
}

static void complete_nonpaging_mode(struct kvm_vcpu *vcpu)
{
	set_paging_flag(vcpu);
	kvm_mmu_reset_context(vcpu, OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG);
}

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
		if (unlikely(!is_paging(vcpu)))
			continue;
		kvm_set_gp_phys_root(vcpu, E2K_INVALID_PAGE);
		if (is_shadow_paging(vcpu)) {
			kvm_set_space_type_spt_u_root(vcpu, E2K_INVALID_PAGE);
			kvm_set_space_type_spt_os_root(vcpu, E2K_INVALID_PAGE);
		}
	}
	kvm->arch.nonp_root_hpa = E2K_INVALID_PAGE;
}

void mmu_pte_write_new_pte(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
			   pgprot_t *spte, gpa_t gpa, pgprotval_t new_gpte)
{
	pgprot_t old_spte = *spte;

	if (sp->role.level != PT_PAGE_TABLE_LEVEL) {
		++vcpu->kvm->stat.mmu_pde_zapped;
#ifndef	CONFIG_KVM_PARAVIRT_TLB_FLUSH
		DebugPTE("PT level %d is not pte level, it need set pde\n",
			sp->role.level);
		spin_unlock(&vcpu->kvm->mmu_lock);
		E2K_KVM_BUG_ON(mmu_pt_shadow_protection_fault(vcpu, gpa, sp) < 0);
		DebugPTE("set PDE spte at %px == 0x%lx\n",
			spte, pgprot_val(*spte));
		spin_lock(&vcpu->kvm->mmu_lock);
		return;
#endif	/* !CONFIG_KVM_PARAVIRT_TLB_FLUSH */
	} else {
		++vcpu->kvm->stat.mmu_pte_updated;
	}
	mmu_pt_update_spte(vcpu, sp, spte, new_gpte);
	DebugPTE("updated spte at %px from %016lx to %016lx\n",
		spte, pgprot_val(old_spte), pgprot_val(*spte));
	trace_mmu_write_new_pte(vcpu, sp, spte, old_spte, kvm_get_sp_gmm(sp), gpa);
}

pgprotval_t mmu_pte_write_fetch_gpte(struct kvm_vcpu *vcpu, gpa_t *gpa,
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
		r = kvm_vcpu_get_guest_pte_atomic(vcpu, *gpa, gentry);
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

int make_mmu_pages_available(struct kvm_vcpu *vcpu)
{
	LIST_HEAD(invalid_list);

	if (likely(kvm_mmu_available_pages(vcpu->kvm) >=
					KVM_MIN_FREE_MMU_PAGES))
		return 0;

	while (kvm_mmu_available_pages(vcpu->kvm) < KVM_REFILL_PAGES) {
		if (!prepare_zap_oldest_mmu_page(vcpu->kvm, &invalid_list))
			break;

		++vcpu->kvm->stat.mmu_recycled;
	}
	kvm_mmu_commit_zap_page(vcpu->kvm, &invalid_list);

	if (!kvm_mmu_available_pages(vcpu->kvm))
		return -ENOSPC;
	return 0;
}

void kvm_mmu_flush_gva(struct kvm_vcpu *vcpu, gva_t gva)
{
	vcpu->arch.mmu.sync_gva(vcpu, pv_vcpu_get_gmm(vcpu), gva);
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
	if (vcpu->arch.mmu.pae_root != NULL)
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
	vcpu->arch.mmu.sh_gk_root_hpa = E2K_INVALID_PAGE;
	vcpu->arch.mmu.gp_root_hpa = E2K_INVALID_PAGE;
	vcpu->arch.mmu.sh_root_hpa = E2K_INVALID_PAGE;

	mmu_init_memory_caches(vcpu);

	kvm_setup_paging_mode(vcpu);

	if (likely(vcpu->arch.is_hv || vcpu->arch.is_pv))
		return 0;

	/* there is support of x86 trap tables emulation mode */
	return alloc_mmu_pages(vcpu);
}

void kvm_mmu_setup(struct kvm_vcpu *vcpu)
{
	mmu_check_invalid_roots(vcpu, true /* invalid */,
				OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG);
	kvm_setup_mmu_intc_mode(vcpu);
}

void kvm_mmu_reset(struct kvm_vcpu *vcpu)
{
	mmu_check_invalid_roots(vcpu, true /* invalid */,
		OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG | GP_ROOT_PT_FLAG);
	kvm_reset_mmu_intc_mode(vcpu);
	kvm_setup_paging_mode(vcpu);
	init_kvm_nonpaging_mmu(vcpu);
}

static void kvm_mmu_invalidate_zap_pages_in_memslot(struct kvm *kvm,
			struct kvm_memory_slot *slot,
			struct kvm_page_track_notifier_node *node)
{
	kvm_mmu_invalidate_zap_all_pages(kvm);
}

static void kvm_mmu_init_pt_interface(struct kvm *kvm)
{
#ifdef	CONFIG_DYNAMIC_PT_STRUCT
	PTNAME_DYNAMIC(mmu_init_pt_interface)(kvm);
#else	/* !CONFIG_DYNAMIC_PT_STRUCT */
	int iset = machine.native_iset_ver;
	bool mmu_pt_v6 = machine.mmu_pt_v6;


	if (iset < E2K_ISET_V5) {
		PTNAME_V3(mmu_init_pt_interface)(kvm);
	} else if (iset == E2K_ISET_V5) {
		PTNAME_V5(mmu_init_pt_interface)(kvm);
	} else if (iset >= E2K_ISET_V6) {
		if (mmu_pt_v6) {
			if (likely(kvm_is_phys_pt_enable(kvm))) {
				PTNAME_V6_GP(mmu_init_pt_interface)(kvm);
			} else {
				PTNAME_V6(mmu_init_pt_interface)(kvm);
			}
		} else {
			if (likely(kvm_is_phys_pt_enable(kvm))) {
				PTNAME_V6_GP(mmu_init_pt_interface)(kvm);
			} else {
				PTNAME_V6_V5(mmu_init_pt_interface)(kvm);
			}
		}
	} else {
		BUG_ON(true);
	}
#endif	/* CONFIG_DYNAMIC_PT_STRUCT */
}

void kvm_mmu_init_vm(struct kvm *kvm)
{
	struct kvm_page_track_notifier_node *node;

	kvm_mmu_init_pt_interface(kvm);
	mmu_pt_init_mmu_pt_structs(kvm);

	node = &kvm->arch.mmu_sp_tracker;
	node->track_write = kvm->arch.mmu_pt_ops.kvm_mmu_pte_write;
	node->track_flush_slot = kvm_mmu_invalidate_zap_pages_in_memslot;
	kvm_page_track_register_notifier(kvm, node);

}

void kvm_mmu_uninit_vm(struct kvm *kvm)
{
	struct kvm_page_track_notifier_node *node = &kvm->arch.mmu_sp_tracker;

	kvm_page_track_unregister_notifier(kvm, node);
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

			mmu_pt_slot_handle_ptes_level_range(kvm, memslot, NULL,
				PT_PAGE_TABLE_LEVEL, PT_MAX_HUGEPAGE_LEVEL,
				start, end - 1, true);
		}
	}

	spin_unlock(&kvm->mmu_lock);
}

void kvm_mmu_slot_remove_write_access(struct kvm *kvm,
				      struct kvm_memory_slot *memslot)
{
	bool flush;

	spin_lock(&kvm->mmu_lock);
	flush = mmu_pt_slot_handle_rmap_write_protect(kvm, memslot, NULL, false);
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

void kvm_mmu_zap_collapsible_sptes(struct kvm *kvm,
				   const struct kvm_memory_slot *memslot)
{
	/* FIXME: const-ify all uses of struct kvm_memory_slot.  */
	spin_lock(&kvm->mmu_lock);
	mmu_pt_slot_handle_collapsible_sptes(kvm,
			(struct kvm_memory_slot *)memslot, NULL, true);
	spin_unlock(&kvm->mmu_lock);
}

void kvm_mmu_slot_leaf_clear_dirty(struct kvm *kvm,
				   struct kvm_memory_slot *memslot)
{
	bool flush;

	spin_lock(&kvm->mmu_lock);
	flush = mmu_pt_slot_handle_clear_dirty(kvm, memslot, NULL, false);
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
	flush = mmu_pt_slot_handle_largepage_remove_write_access(kvm, memslot,
								 NULL, false);
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
	flush = mmu_pt_slot_handle_set_dirty(kvm, memslot, NULL, false);
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

		ret = mmu_pt_prepare_zap_page(kvm, sp,
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

	E2K_KVM_BUG_ON(VALID_PAGE(kvm->arch.nonp_root_hpa));

	root = kvm_get_gp_phys_root(vcpu);
	E2K_KVM_BUG_ON(IS_E2K_INVALID_PAGE(root));
	DebugNONP("VCPU #%d created root PT at 0x%llx\n",
		vcpu->vcpu_id, root);

	kvm->arch.nonp_root_hpa = root;	/* PT root is common for all VCPUs */

	mmu_pt_init_nonpaging_pt_structs(kvm, root);

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
	E2K_KVM_BUG_ON(!VALID_PAGE(vcpu->arch.mmu.get_vcpu_gp_pptb(vcpu)));
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
		kvm_set_space_type_spt_gk_root(vcpu, root);
		if (is_sep_virt_spaces(vcpu)) {
			E2K_KVM_BUG_ON(mmu->get_vcpu_sh_os_pptb(vcpu) != root);
			mmu->set_vcpu_sh_os_vptb(vcpu, MMU_GUEST_OS_PT_VPTB);
			mmu->set_vcpu_os_vab(vcpu, 0);
		} else {
			E2K_KVM_BUG_ON(mmu->get_vcpu_sh_u_pptb(vcpu) != root);
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
			E2K_KVM_BUG_ON(true);
		}
	}
}

static void kvm_hv_setup_nonp_tdp(struct kvm_vcpu *vcpu)
{
	E2K_KVM_BUG_ON(!is_phys_paging(vcpu));
	set_tdp_paging(vcpu);
}

int kvm_hv_setup_nonpaging_mode(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	unsigned flags;
	int ret;

	DebugNONP("started on VCPU #%d\n", vcpu->vcpu_id);

	E2K_KVM_BUG_ON(is_paging(vcpu));

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
		E2K_KVM_BUG_ON(true);
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
		E2K_KVM_BUG_ON(true);
	}
	mutex_unlock(&kvm->slots_lock);

	if (kvm_is_phys_pt_enable(vcpu->kvm))
		kvm_hv_setup_nonp_phys_pt(vcpu, kvm->arch.nonp_root_hpa);

	if (kvm_is_tdp_enable(vcpu->kvm)) {
		kvm_hv_setup_nonp_tdp(vcpu);
	} else if (kvm_is_shadow_pt_enable(vcpu->kvm)) {
		kvm_setup_nonp_shadow_pt(vcpu, kvm->arch.nonp_root_hpa);
	}

	E2K_KVM_BUG_ON(!(is_shadow_paging(vcpu) || is_phys_paging(vcpu)));

	return 0;

failed:
	mutex_unlock(&kvm->slots_lock);
	return ret;
}

static int setup_shadow_root(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				unsigned flags)
{
	hpa_t os_root, u_root, gp_root;
	int ret;

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
	pptb = E2K_INVALID_PAGE;

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
		E2K_KVM_BUG_ON(true);
	}

	kvm_unlink_unsync_page(vcpu->kvm, sp);
	ret = mmu_pt_sync_shadow_pt_range(vcpu, gmm, root_hpa,
				sync_start, sync_end, pptb, vptb);
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
	ret = mmu_pt_sync_shadow_pt_range(vcpu, gmm, root, sync_start, sync_end,
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
	ret = mmu_pt_sync_shadow_pt_range(vcpu, gmm, root_hpa,
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

/*
 * Create a copy of guest user shadow PT to run guest kernel on this copy,
 * which includes mapping of the guest kernel virtual space.
 * The guest user will be run on the main guest PT to exclude access to
 * kernel spaces
 */
static int kvm_create_user_root_kernel_copy(struct kvm_vcpu *vcpu,
					    gmm_struct_t *gmm)
{
	pgprot_t *gu_root;
	pgprot_t *gk_root;
	hpa_t old_root, old_gk_root;

	gk_root = mmu_memory_cache_alloc(&vcpu->arch.mmu_page_cache);
	gu_root = (pgprot_t *)__va(gmm->root_hpa);

	spin_lock(&vcpu->kvm->mmu_lock);

	/* copy guest user part of PGDs to access to guest user space */
	copy_guest_user_root_range(vcpu, gmm, gk_root, gu_root);

	/* copy guest kernel PGSs to access to guest kernel virtual space */
	copy_guest_kernel_root_range(vcpu, gk_root);

	spin_unlock(&vcpu->kvm->mmu_lock);

	/* copy host kernel PGDs to access to host kernel space */
	copy_host_kernel_root_range(vcpu, gk_root);

	/* Since V6 hardware support has been simplified
	 * and self-pointing pgd is not required anymore. */
	if (!cpu_has(CPU_FEAT_ISET_V6)) {
		/* One PGD entry is the VPTB self-map. */
		int vmlpt_index = kvm_vcpu_get_vmlpt_index(vcpu, gmm);
		mmu_pt_kvm_vmlpt_kernel_spte_set(vcpu->kvm, &gk_root[vmlpt_index],
						 gk_root);
	}

	old_root = gmm->root_hpa;
	old_gk_root = gmm->gk_root_hpa;
	gmm->gk_root_hpa = (hpa_t)__pa(gk_root);
	trace_host_set_gmm_root_hpa(gmm, old_root, old_gk_root,
				    NATIVE_READ_IP_REG_VALUE());

	return 0;
}

void kvm_release_user_root_kernel_copy(struct kvm *kvm, gmm_struct_t *gmm)
{
	pgprot_t *gk_root;
	hpa_t old_root, old_gk_root;

	trace_host_get_gmm_root_hpa(gmm, NATIVE_READ_IP_REG_VALUE());
	if (unlikely(!VALID_PAGE(gmm->gk_root_hpa))) {
		/* gmm root copy has been already released */
		return;
	}
	if (unlikely(pv_mmu_is_init_gmm(kvm, gmm))) {
		/* init gmm has not copied PTs */
		goto out;
	}

	gk_root = (pgprot_t *)__va(gmm->gk_root_hpa);

	/* Since V6 hardware support has been simplified
	 * and self-pointing pgd is not required anymore. */
	if (!cpu_has(CPU_FEAT_ISET_V6)) {
		/* Clear one PGD entry is the VPTB self-map. */
		int vmlpt_index = kvm_get_vmlpt_index(kvm, gmm);
		kvm_vmlpt_spte_reset(kvm, &gk_root[vmlpt_index]);
	}

	/* Clear host kernel PGDs to access to host kernel space */
	kvm_clear_host_kernel_root_range(kvm, gk_root);

	/* Release guest kernel PGSs to access to guest kernel virtual space */
	release_guest_kernel_root_range(kvm, gk_root);

	/* Release guest user part of PGDs to access to guest user space */
	release_guest_user_root_range(kvm, gk_root);

out:
	old_root = gmm->root_hpa;
	old_gk_root = gmm->gk_root_hpa;
	gmm->gk_root_hpa = E2K_INVALID_PAGE;
	trace_host_set_gmm_root_hpa(gmm, old_root, old_gk_root,
				    NATIVE_READ_IP_REG_VALUE());
}

int kvm_prepare_shadow_user_pt(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				gpa_t u_phys_ptb)
{
	hpa_t old_root, old_gk_root;
	hpa_t root;
	struct kvm_mmu_page *sp;
	int ret;

	E2K_KVM_BUG_ON(!is_shadow_paging(vcpu));
	E2K_KVM_BUG_ON(gmm == NULL);
	E2K_KVM_BUG_ON(VALID_PAGE(gmm->root_hpa));
	E2K_KVM_BUG_ON(!vcpu->arch.mmu.u_context_on);

	ret = mmu_topup_memory_caches(vcpu);
	if (ret) {
		pr_err("%s(): could not create  memory caches on VCPU #%d "
			"error %d\n",
			__func__, vcpu->vcpu_id, ret);
		old_gk_root = gmm->gk_root_hpa;
		goto failed;
	}

	root = e2k_mmu_alloc_spt_root(vcpu, gpa_to_gfn(u_phys_ptb));
	DebugGMM("VCPU #%d created shadow root PT at 0x%llx for guest "
		"user root PT physical at 0x%llx for gmm #%d\n",
		vcpu->vcpu_id, root, u_phys_ptb, gmm->nid.nr);

	mmu_pv_prepare_spt_u_root(vcpu, gmm, root);

	sp = page_header(root);
	kvm_init_root_gmm_spt_list(gmm, sp);
	old_root = gmm->root_hpa;
	old_gk_root = gmm->gk_root_hpa;
	gmm->root_hpa = root;	/* shadow PT root has been set */
	trace_host_set_gmm_root_hpa(gmm, old_root, old_gk_root,
				    NATIVE_READ_IP_REG_VALUE());

	ret = kvm_create_user_root_kernel_copy(vcpu, gmm);
	if (unlikely(ret != 0))
		goto failed_copy;

	ret = sync_pv_vcpu_shadow_u_root(vcpu, gmm, root, u_phys_ptb);
	if (ret) {
		pr_err("%s(): failed to sync user root of GMM #%d, error %d\n",
			__func__, gmm->nid.nr, ret);
		goto failed_sync;
	}
	DebugGMM("VCPU #%d, guest user root at 0x%llx, shadow root "
		"at 0x%llx\n",
		vcpu->vcpu_id, u_phys_ptb, root);

	gmm->pt_synced = true;

	return 0;

failed_sync:
	mmu_release_spt_root(vcpu->kvm, root);
failed_copy:
	old_gk_root = gmm->gk_root_hpa;
	gmm->gk_root_hpa = E2K_INVALID_PAGE;
failed:
	old_root = gmm->root_hpa;
	gmm->root_hpa = TO_ERROR_PAGE(ret);
	trace_host_set_gmm_root_hpa(gmm, old_root, old_gk_root,
				    NATIVE_READ_IP_REG_VALUE());
	return ret;
}

int kvm_create_shadow_user_pt(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				gpa_t u_phys_ptb)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	hpa_t old_root, old_gk_root;
	hpa_t root;
	struct kvm_mmu_page *sp;
	e2k_addr_t sync_start, sync_end;
	int ret;

	E2K_KVM_BUG_ON(!is_shadow_paging(vcpu));
	E2K_KVM_BUG_ON(gmm == NULL);
	E2K_KVM_BUG_ON(VALID_PAGE(gmm->root_hpa));

	if (likely(mmu->u_context_on)) {
		/* unload previous MMU PT and context before load new */
		kvm_mmu_unload(vcpu, U_ROOT_PT_FLAG);
	} else {
		/* enable support of guest user space */
		root = kvm_get_space_type_spt_u_root(vcpu);
		if (VALID_PAGE(root)) {
			E2K_KVM_BUG_ON(is_sep_virt_spaces(vcpu) &&
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
		old_gk_root = gmm->gk_root_hpa;
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
	old_root = gmm->root_hpa;
	old_gk_root = gmm->gk_root_hpa;
	gmm->root_hpa = root;	/* shadow PT root has been set */
	trace_host_set_gmm_root_hpa(gmm, old_root, old_gk_root,
				    NATIVE_READ_IP_REG_VALUE());

	ret = kvm_create_user_root_kernel_copy(vcpu, gmm);
	if (unlikely(ret != 0))
		goto failed_copy;

	/* activate copied guest kernel PT */
	trace_host_get_gmm_root_hpa(gmm, NATIVE_READ_IP_REG_VALUE());
	kvm_set_space_type_spt_gk_root(vcpu, gmm->gk_root_hpa);

	/* guest user PT is now empty */
	sync_start = GUEST_TASK_SIZE;
	if (sp->guest_kernel_synced) {
		sync_end = GUEST_TASK_SIZE;
	} else {
		sync_end = HOST_TASK_SIZE;
	}

	if (unlikely(sync_end > sync_start)) {
		ret = mmu_pt_sync_shadow_pt_range(vcpu, gmm, root,
				sync_start, sync_end,
				u_phys_ptb, mmu->get_vcpu_sh_u_vptb(vcpu));
		if (ret) {
			pr_err("%s(): could not sync host shadow PT and guest "
				"initial PT, error %d\n",
				__func__, ret);
			goto failed_sync;
		}
		DebugSPT("VCPU #%d shadow root at 0x%llx synced "
			"from 0x%lx to 0x%lx\n",
			vcpu->vcpu_id, root, sync_start, sync_end);
	}

	gmm->pt_synced = true;

	return 0;

failed_sync:
	mmu_release_spt_root(vcpu->kvm, root);
failed_copy:
	old_gk_root = gmm->gk_root_hpa;
	gmm->gk_root_hpa = E2K_INVALID_PAGE;
failed:
	old_root = gmm->root_hpa;
	gmm->root_hpa = TO_ERROR_PAGE(ret);
	trace_host_set_gmm_root_hpa(gmm, old_root, old_gk_root,
				    NATIVE_READ_IP_REG_VALUE());
	return ret;
}

void kvm_switch_mmu_guest_u_pt(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	/* setup user PT hardware and software context */
	kvm_set_vcpu_u_pt_context(vcpu);

	write_guest_PID_reg(vcpu, mmu->pid);

	kvm_dump_shadow_u_pptb(vcpu, "Set MMU guest shadow U_PT context:\n");
}

static void kvm_setup_shadow_u_pptb(struct kvm_vcpu *vcpu)
{
	/* setup new user PT hardware/software context */
	kvm_set_vcpu_u_pt_context(vcpu);

	kvm_dump_shadow_u_pptb(vcpu, "Set MMU guest shadow U_PT context:\n");
}

void mmu_pv_setup_shadow_u_pptb(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	kvm_setup_shadow_u_pptb(vcpu);
	pv_vcpu_set_gmm(vcpu, gmm);
	pv_vcpu_set_active_gmm(vcpu, gmm);
}

static int switch_shadow_pptb(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				gpa_t pptb, unsigned flags)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	hpa_t root;
	int ret;

	E2K_KVM_BUG_ON(!is_shadow_paging(vcpu));

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
		E2K_KVM_BUG_ON(true);
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
		E2K_KVM_BUG_ON(true);
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

	E2K_KVM_BUG_ON(!vcpu->arch.is_hv);

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

static void kvm_dump_shadow_os_pt_regs(struct kvm_vcpu *vcpu)
{
	if (is_sep_virt_spaces(vcpu)) {
		DebugSHC("Set MMU guest shadow OS PT context:\n"
			"   SH_OS_PPTB:     value 0x%lx\n"
			"   SH_OS_VPTB:     value 0x%lx\n"
			"   OS_PPTB:        value 0x%lx\n"
			"   OS_VPTB:        value 0x%lx\n"
			"   SH_OS_VAB:      value 0x%lx\n"
			"   OS_VAB:         value 0x%lx\n",
			vcpu->arch.mmu.get_vcpu_context_os_pptb(vcpu),
			vcpu->arch.mmu.get_vcpu_context_os_vptb(vcpu),
			vcpu->arch.mmu.get_vcpu_os_pptb(vcpu),
			vcpu->arch.mmu.get_vcpu_os_vptb(vcpu),
			vcpu->arch.mmu.get_vcpu_context_os_vab(vcpu),
			vcpu->arch.mmu.get_vcpu_os_vab(vcpu));
	} else {
		DebugSHC("Set MMU guest shadow OS/U PT context:\n"
			"   SH_OS/U_PPTB:   value 0x%lx\n"
			"   SH_OS/U_VPTB:   value 0x%lx\n"
			"   OS/U_PPTB:      value 0x%lx\n"
			"   OS/U_VPTB:      value 0x%lx\n",
			vcpu->arch.mmu.get_vcpu_context_u_pptb(vcpu),
			vcpu->arch.mmu.get_vcpu_context_u_vptb(vcpu),
			vcpu->arch.mmu.get_vcpu_u_pptb(vcpu),
			vcpu->arch.mmu.get_vcpu_u_vptb(vcpu));
	}
}

static void kvm_setup_shadow_os_pptb(struct kvm_vcpu *vcpu)
{
	/* setup kernel new PT hardware/software context */
	kvm_set_vcpu_os_pt_context(vcpu);

	kvm_dump_shadow_os_pt_regs(vcpu);
}

int kvm_switch_shadow_os_pptb(struct kvm_vcpu *vcpu, gpa_t os_pptb,
				hpa_t *os_root)
{
	hpa_t root;
	int ret;

	E2K_KVM_BUG_ON(!vcpu->arch.is_hv);

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

#ifdef CONFIG_KVM_HW_VIRTUALIZATION
int mmu_pv_create_tdp_user_pt(struct kvm_vcpu *vcpu, gpa_t u_phys_ptb)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	E2K_KVM_BUG_ON(!is_tdp_paging(vcpu));

	mmu->set_vcpu_u_pptb(vcpu, u_phys_ptb);
	mmu->set_vcpu_u_vptb(vcpu, USER_VPTB_BASE_ADDR);
	mmu->set_vcpu_os_vab(vcpu, MMU_GUEST_OS_VAB);

	return 0;
}

static int switch_tdp_pptb(struct kvm_vcpu *vcpu, gpa_t pptb, unsigned flags)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	E2K_KVM_BUG_ON(!is_tdp_paging(vcpu));

	/* switch VCPU MMU to new PT */
	if ((flags & U_ROOT_PT_FLAG) ||
			((flags & OS_ROOT_PT_FLAG) &&
					is_sep_virt_spaces(vcpu))) {
		mmu->set_vcpu_u_pptb(vcpu, pptb);
	} else if (flags & OS_ROOT_PT_FLAG) {
		mmu->set_vcpu_os_pptb(vcpu, pptb);
	} else {
		E2K_KVM_BUG_ON(true);
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

void setup_tdp_paging(struct kvm_vcpu *vcpu)
{
	E2K_KVM_BUG_ON(is_paging_flag(vcpu));
	set_paging_flag(vcpu);

	E2K_KVM_BUG_ON(!is_tdp_paging(vcpu));

	tdp_enabled = true;

	init_kvm_mmu(vcpu);
}

int kvm_switch_to_tdp_paging(struct kvm_vcpu *vcpu,
		gpa_t u_phys_ptb, gva_t u_virt_ptb,
		gpa_t os_phys_ptb, gva_t os_virt_ptb, gva_t os_virt_base)
{
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
	mmu_pt_setup_tdp_pt_structs(vcpu);

	return 0;
}
#endif

static int setup_shadow_paging(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				unsigned flags)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	hpa_t os_root, u_root;
	int ret;

	E2K_KVM_BUG_ON(VALID_PAGE(mmu->sh_root_hpa));

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
		E2K_KVM_BUG_ON(true);
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

void kvm_setup_mmu_spt_context(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	/* setup OS and user PT hardware and software context */
	kvm_set_vcpu_pt_context(vcpu);

	if (vcpu->arch.is_hv) {
		kvm_hv_setup_mmu_spt_context(vcpu);
	}

	kvm_dump_shadow_u_pptb(vcpu, "Set MMU guest shadow OS/U_PT context:\n");

	if (DEBUG_SHADOW_CONTEXT_MODE && is_sep_virt_spaces(vcpu)) {
		pr_info("   sh_OS_PPTB: value 0x%lx\n"
			"   sh_OS_VPTB: value 0x%lx\n"
			"   OS_PPTB:    value 0x%lx\n"
			"   OS_VPTB:    value 0x%lx\n"
			"   SH_OS_VAB:  value 0x%lx\n",
			mmu->get_vcpu_context_os_pptb(vcpu),
			mmu->get_vcpu_context_os_vptb(vcpu),
			mmu->get_vcpu_os_pptb(vcpu),
			mmu->get_vcpu_os_vptb(vcpu),
			mmu->get_vcpu_context_os_vab(vcpu));
	}
	if (DEBUG_SHADOW_CONTEXT_MODE) {
		if (is_phys_paging(vcpu)) {
			pr_info("   GP_PPTB:    value 0x%llx\n",
				mmu->get_vcpu_context_gp_pptb(vcpu));
		}
		if (!vcpu->arch.is_hv) {
			pr_info("   GP_PPTB:    value 0x%llx\n",
				mmu->get_vcpu_gp_pptb(vcpu));
		}
	}
	if (DEBUG_SHADOW_CONTEXT_MODE && is_paging(vcpu)) {
		pr_info("   SH_MMU_CR:  value 0x%llx\n",
			AW(read_guest_MMU_CR_reg(vcpu)));
	}
	if (DEBUG_SHADOW_CONTEXT_MODE) {
		e2k_core_mode_t core_mode = read_guest_CORE_MODE_reg(vcpu);

		pr_info("   CORE_MODE:  value 0x%x sep_virt_space: %s\n",
			core_mode.CORE_MODE_reg,
			(core_mode.CORE_MODE_sep_virt_space) ?
				"true" : "false");
	}
}

static int kvm_setup_shadow_paging(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
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
	mmu_pt_setup_shadow_pt_structs(vcpu);

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

int vcpu_read_mmu_cr_reg(struct kvm_vcpu *vcpu, e2k_mmu_cr_t *mmu_cr)
{
	*mmu_cr = read_guest_MMU_CR_reg(vcpu);

	DebugMMUREG("guest MMU_CR does not change: 0x%llx, tlb_en: %d\n",
			AW(*mmu_cr), (*mmu_cr).tlb_en);

	return 0;
}

int vcpu_write_mmu_cr_reg(struct kvm_vcpu *vcpu, e2k_mmu_cr_t mmu_cr)
{
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;
	e2k_mmu_cr_t old_mmu_cr;
	int r;

	old_mmu_cr = read_guest_MMU_CR_reg(vcpu);

	if (old_mmu_cr.tlb_en == mmu_cr.tlb_en) {
		/* paging mode is not changed, so can only update */
		write_guest_MMU_CR_reg(vcpu, mmu_cr);
		hw_ctxt->sh_mmu_cr = mmu_cr;
		DebugMMUREG("guest MMU_CR paging mode does not change: only update from 0x%llx to 0x%llx, tlb_en %d\n",
			AW(old_mmu_cr), AW(mmu_cr), mmu_cr.tlb_en);
		return 0;
	}

	if (old_mmu_cr.tlb_en && !mmu_cr.tlb_en) {
		/* paging mode is OFF */
		write_guest_MMU_CR_reg(vcpu, mmu_cr);
		hw_ctxt->sh_mmu_cr = mmu_cr;
		DebugMMUREG("guest MMU_CR paging mode is turn OFF: from 0x%llx to 0x%llx, tlb_en %d\n",
			AW(old_mmu_cr), AW(mmu_cr), mmu_cr.tlb_en);
		/* it need free all page tables and invalidate roots */
		/* FIXME: turn OFF is not implemented */
		pr_err("%s(): guest turns OFF paging mode: MMU_CR from 0x%llx to 0x%llx, tlb_en %d\n",
			__func__, AW(old_mmu_cr), AW(mmu_cr), mmu_cr.tlb_en);
		E2K_KVM_BUG_ON(is_paging(vcpu) && !is_tdp_paging(vcpu));
		reset_paging_flag(vcpu);
		return 0;
	}

	/* guest turns ON paging mode */
	E2K_KVM_BUG_ON(is_paging_flag(vcpu));

	if (is_tdp_paging(vcpu)) {
		r = kvm_hv_setup_tdp_paging(vcpu);
	} else if (is_shadow_paging(vcpu)) {
		if (vcpu->arch.is_hv) {
			r = kvm_setup_shadow_paging(vcpu, NULL);
		} else {
			r = kvm_setup_shadow_paging(vcpu,
						pv_vcpu_get_gmm(vcpu));
		}
	} else {
		E2K_KVM_BUG_ON(true);
		r = -EINVAL;
	}
	if (r != 0) {
		pr_err("%s(): could not switch guest to paging mode, "
			"error %d\n",
			__func__, r);
		return r;
	}

	write_guest_MMU_CR_reg(vcpu, mmu_cr);
	hw_ctxt->sh_mmu_cr = mmu_cr;
	DebugMMUREG("Enable guest MMU paging:\n"
		    "   SH_MMU_CR: value 0x%llx\n"
		    "   SH_PID:    value 0x%llx\n",
		    AW(mmu_cr), hw_ctxt->sh_pid);

	return 0;
}

int vcpu_read_trap_point_mmu_reg(struct kvm_vcpu *vcpu, gpa_t *tc_gpa)
{
	if (vcpu->arch.mmu.tc_page != NULL) {
		/* guest TRAP_POINT register was written */
		*tc_gpa = vcpu->arch.mmu.tc_gpa;
	} else {
		/* read without writing */
		*tc_gpa = 0;
	}

	DebugMMUREG("read guest TRAP POINT: GPA 0x%llx, host PA 0x%llx, mapped to host addr %px\n",
		*tc_gpa, vcpu->arch.sw_ctxt.tc_hpa, vcpu->arch.mmu.tc_kaddr);

	return 0;
}

int vcpu_write_trap_point_mmu_reg(struct kvm_vcpu *vcpu, gpa_t tc_gpa,
					hpa_t *tc_hpap)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	gfn_t tc_gfn;
	kvm_pfn_t tc_pfn;
	hpa_t tc_hpa;
	struct page *tc_page;
	void *tc_kaddr;
	int ret;

	if (vcpu->arch.mmu.tc_page != NULL || vcpu->arch.mmu.tc_kaddr != NULL)
		/* release old trap cellar before setup new */
		kvm_vcpu_release_trap_cellar(vcpu);

	if ((tc_gpa & MMU_TRAP_POINT_MASK) != tc_gpa) {
		if ((tc_gpa & MMU_TRAP_POINT_MASK_V3) != tc_gpa) {
			pr_err("%s(): guest TRAP POINT 0x%llx is bad aligned, "
				"should be at least 0x%llx\n",
				__func__, tc_gpa, tc_gpa & MMU_TRAP_POINT_MASK);
			return -EINVAL;
		}
		pr_warn("%s(): guest TRAP POINT 0x%llx has legacy alignment\n",
			__func__, tc_gpa);
	}

	tc_gfn = gpa_to_gfn(tc_gpa);
	tc_pfn = kvm_vcpu_gfn_to_pfn(vcpu, tc_gfn);
	if (is_error_noslot_pfn(tc_pfn)) {
		pr_err("%s(): could not convert guest TRAP POINT "
			"gfn 0x%llx to host pfn\n",
			__func__, tc_gfn);
		return -EFAULT;
	}
	tc_hpa = tc_pfn << PAGE_SHIFT;
	tc_hpa += offset_in_page(tc_gpa);
	tc_page = pfn_to_page(tc_pfn);
	if (is_error_page(tc_page)) {
		pr_err("%s(): could not convert guest TRAP POINT "
			"address 0x%llx to host page\n",
			__func__, tc_gpa);
		return -EFAULT;
	}

	tc_kaddr = kmap(tc_page);
	if (tc_kaddr == NULL) {
		pr_err("%s(): could not map guest TRAP POINT page to host "
			"memory\n",
			__func__);
		ret = -ENOMEM;
		goto kmap_error;
	}
	tc_kaddr += offset_in_page(tc_gpa);

	vcpu->arch.mmu.tc_gpa = tc_gpa;
	sw_ctxt->tc_hpa = tc_hpa;
	vcpu->arch.mmu.tc_page = tc_page;
	vcpu->arch.mmu.tc_kaddr = tc_kaddr;

	DebugMMUREG("write guest TRAP POINT: host PA 0x%llx, GPA 0x%llx, "
		"mapped to host addr %px\n",
		tc_hpa, tc_gpa, tc_kaddr);

	*tc_hpap = tc_hpa;
	return 0;

kmap_error:
	kvm_release_page_dirty(tc_page);
	return ret;
}

int vcpu_write_mmu_pid_reg(struct kvm_vcpu *vcpu, mmu_reg_t pid)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	/* probably it is flush mm */
	kvm_mmu_sync_roots(vcpu, U_ROOT_PT_FLAG);

	mmu->pid = pid;
	write_guest_PID_reg(vcpu, pid);
	DebugMMUPID("Set MMU guest PID: 0x%llx\n", pid);

	return 0;
}

int vcpu_write_mmu_u_pptb_reg(struct kvm_vcpu *vcpu, pgprotval_t u_pptb,
			 bool *pt_updated, hpa_t *u_root)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t sw_u_pptb;
	pgprotval_t old_u_pptb;
	int r;

	sw_u_pptb = mmu->get_vcpu_context_u_pptb(vcpu);
	old_u_pptb = mmu->get_vcpu_u_pptb(vcpu);
	E2K_KVM_BUG_ON(!is_shadow_paging(vcpu) && sw_u_pptb != old_u_pptb &&
		vcpu->arch.is_pv);

	if (!is_paging(vcpu)) {
		/* it is setup of initial guest page table */
		/* paging wiil be enabled while set MMU_CR.tlb_en */
		/* now save only base of guest */
		mmu->set_vcpu_u_pptb(vcpu, u_pptb);
		DebugMMUREG("guest MMU U_PPTB: initial PT base at 0x%lx\n",
			u_pptb);
		r = 0;
		goto handled;
	}
	if (sw_u_pptb == u_pptb) {
		/* set the same page table, so nothing to do */
		DebugMMUREG("guest MMU U_PPTB: write the same PT root "
			"at 0x%lx\n",
			u_pptb);
		r = 0;
		goto handled;
	}

	/*
	 * Switch to new page table root
	 */

	DebugMMUREG("switch to new guest U_PPTB base at 0x%lx\n",
		u_pptb);

	if (is_tdp_paging(vcpu)) {
		r = kvm_switch_tdp_u_pptb(vcpu, u_pptb);
	} else if (is_shadow_paging(vcpu)) {
		r = kvm_switch_shadow_u_pptb(vcpu, u_pptb, u_root);
		*pt_updated = true;
	} else {
		E2K_KVM_BUG_ON(true);
		r = -EINVAL;
	}

handled:
	return r;
}

int vcpu_write_mmu_os_pptb_reg(struct kvm_vcpu *vcpu, pgprotval_t os_pptb,
					bool *pt_updated, hpa_t *os_root)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t sh_os_pptb;
	pgprotval_t old_os_pptb;
	int r;

	sh_os_pptb = mmu->get_vcpu_context_os_pptb(vcpu);
	old_os_pptb = mmu->get_vcpu_os_pptb(vcpu);
	E2K_KVM_BUG_ON(!is_shadow_paging(vcpu) && sh_os_pptb != old_os_pptb);

	if (!is_paging(vcpu)) {
		/* it is setup of initial guest page table */
		/* paging wiil be enabled while set MMU_CR.tlb_en */
		/* now save only base of guest */
		mmu->set_vcpu_os_pptb(vcpu, os_pptb);
		DebugMMUREG("guest MMU OS_PPTB: initial PT base at 0x%lx\n",
			os_pptb);
		return 0;
	}
	if (old_os_pptb == os_pptb) {
		/* set the same page table, so nothing to do */
		DebugMMUREG("guest MMU OS_PPTB: write the same PT root "
			"at 0x%lx\n",
			os_pptb);
		return 0;
	}

	/*
	 * Switch to new page table root
	 */
	DebugMMUREG("switch to new guest OS PT base at 0x%lx\n",
		os_pptb);

	if (is_tdp_paging(vcpu)) {
		r = kvm_switch_tdp_os_pptb(vcpu, os_pptb);
	} else if (is_shadow_paging(vcpu)) {
		r = kvm_switch_shadow_os_pptb(vcpu, os_pptb, os_root);
		*pt_updated = true;
	} else {
		E2K_KVM_BUG_ON(true);
		r = -EINVAL;
	}

	return r;
}

int vcpu_write_mmu_u_vptb_reg(struct kvm_vcpu *vcpu, gva_t u_vptb)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t sw_u_vptb;
	gva_t old_u_vptb;

	sw_u_vptb = mmu->get_vcpu_context_u_vptb(vcpu);
	old_u_vptb = mmu->get_vcpu_u_vptb(vcpu);
	E2K_KVM_BUG_ON(!is_shadow_paging(vcpu) && sw_u_vptb != old_u_vptb &&
		vcpu->arch.is_pv);

	if (!is_paging(vcpu)) {
		/* it is setup of initial guest page table */
		/* paging wiil be enabled while set MMU_CR.tlb_en */
		/* now save only virtual base of guest */
		mmu->set_vcpu_u_vptb(vcpu, u_vptb);
		DebugMMUVPT("guest MMU U_VPTB: virtual PT base at 0x%lx\n",
			u_vptb);
		return 0;
	}
	if (sw_u_vptb == u_vptb) {
		/* set the same page table, so nothing to do */
		DebugMMUVPT("guest MMU U_VPTB: write the same PT base 0x%lx\n",
			u_vptb);
		return 0;
	}

	pr_err("%s(): virtual User PT base update from 0x%llx to 0x%lx "
		"is not implemented\n",
		__func__, sw_u_vptb, u_vptb);
	return -EINVAL;
}

int vcpu_write_mmu_os_vptb_reg(struct kvm_vcpu *vcpu, gva_t os_vptb)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t sw_os_vptb;
	gva_t old_os_vptb;

	sw_os_vptb = mmu->get_vcpu_context_os_vptb(vcpu);
	old_os_vptb = mmu->get_vcpu_os_vptb(vcpu);
	E2K_KVM_BUG_ON(!is_shadow_paging(vcpu) && sw_os_vptb != old_os_vptb);

	if (!is_paging(vcpu)) {
		/* it is setup of initial guest page table */
		/* paging wiil be enabled while set MMU_CR.tlb_en */
		/* now save only virtual base of guest */
		mmu->set_vcpu_os_vptb(vcpu, os_vptb);
		DebugMMUVPT("guest MMU OS_VPTB: virtual PT base at 0x%lx\n",
			os_vptb);
		return 0;
	}
	if (sw_os_vptb == os_vptb) {
		/* set the same page table, so nothing to do */
		DebugMMUVPT("guest MMU OS_VPTB: write the same PT base 0x%lx\n",
			os_vptb);
		return 0;
	}

	pr_err("%s(): virtual OS PT base update from 0x%llx to 0x%lx "
		"is not implemented\n",
		__func__, sw_os_vptb, os_vptb);
	return -EINVAL;
}

int vcpu_write_mmu_os_vab_reg(struct kvm_vcpu *vcpu, gva_t os_vab)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t sw_os_vab;
	gva_t old_os_vab;

	sw_os_vab = mmu->get_vcpu_context_os_vab(vcpu);
	old_os_vab = mmu->get_vcpu_os_vab(vcpu);
	E2K_KVM_BUG_ON(!is_shadow_paging(vcpu) && sw_os_vab != old_os_vab);

	if (!is_paging(vcpu)) {
		/* it is setup of initial guest page table */
		/* paging wiil be enabled while set MMU_CR.tlb_en */
		/* now save only virtual base of guest */
		mmu->set_vcpu_os_vab(vcpu, os_vab);
		return 0;
	}
	if (sw_os_vab == os_vab) {
		/* set the same page table, so nothing to do */
		DebugMMUVPT("guest MMU OS_VAB: write the same virtual "
			"addresses base 0x%lx\n",
			os_vab);
		return 0;
	}

	pr_err("%s(): guest OS virtual addresses base update from 0x%llx "
		"to 0x%lx is not implemented\n",
		__func__, sw_os_vab, os_vab);
	return -EINVAL;
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
	pte_list_desc_cache = kmem_cache_create(pte_list_desc_cache_name,
					    sizeof(struct pte_list_desc),
					    0, 0, NULL);
	if (!pte_list_desc_cache)
		goto nomem;

	mmu_page_header_cache = kmem_cache_create(mmu_page_header_cache_name,
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

void kvm_vcpu_release_trap_cellar(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.mmu.tc_page == NULL)
		return;
	kvm_release_page_dirty(vcpu->arch.mmu.tc_page);
	vcpu->arch.mmu.tc_page = NULL;
	if (vcpu->arch.mmu.tc_kaddr == NULL)
		return;
	kunmap(vcpu->arch.mmu.tc_kaddr);
	vcpu->arch.mmu.tc_kaddr = NULL;
	vcpu->arch.mmu.tc_gpa = 0;
	vcpu->arch.sw_ctxt.tc_hpa = 0;
}

void vcpu_mmu_destroy(struct kvm_vcpu *vcpu)
{
	unsigned flags = (OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG | GP_ROOT_PT_FLAG);

	mmu_check_invalid_roots(vcpu, true /* invalid ? */, flags);
	reset_paging_flag(vcpu);
	free_mmu_pages(vcpu);
	kvm_vcpu_release_trap_cellar(vcpu);
	mmu_free_memory_caches(vcpu);
}

void kvm_mmu_destroy(struct kvm *kvm)
{
	kvm_invalidate_all_roots(kvm);
	tdp_enabled = false;
	kvm->arch.shadow_pt_set_up = false;
}

void kvm_mmu_module_exit(void)
{
	mmu_destroy_caches();
	percpu_counter_destroy(&kvm_total_used_mmu_pages);
	unregister_shrinker(&mmu_shrinker);
	mmu_audit_disable();
}
