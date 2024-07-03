/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_E2K_MMU_H
#define __KVM_E2K_MMU_H

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/kvm_host.h>
#include <linux/sched.h>
#include <linux/hugetlb.h>
#include <asm/mmu_context.h>
#include <asm/cacheflush.h>
#include <asm/pgalloc.h>
#include <linux/uaccess.h>
#include <asm/vga.h>
#include <asm/e2k_sic.h>
#include <asm/e2k_debug.h>
#include <asm/kvm/hypercall.h>
#include <asm/kvm/mmu.h>
#include <asm/kvm/mmu_pte.h>
#include <asm/kvm/mmu_exc.h>

#include "mmu-pt.h"
#include "mmu-e2k.h"
#include "hv_mmu.h"
#include "cpu_defs.h"
#include "mmu_defs.h"
#include "mman.h"

#undef	ASSERT
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
extern bool dbg, sync_dbg;

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

#undef	DEBUG_KVM_RECOVERY_MODE
#undef	DebugKVMREC
#define	DEBUG_KVM_RECOVERY_MODE	0	/* kernel recovery debugging */
#define	DebugKVMREC(fmt, args...)					\
({									\
	if (DEBUG_KVM_RECOVERY_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SHADOW_MODE
#undef	DebugKVMSH
#define	DEBUG_KVM_SHADOW_MODE	0	/* shadow adresses debugging */
#define	DebugKVMSH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SHADOW_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PT_STRUCT_MODE
#undef	DebugPTS
#define	DEBUG_PT_STRUCT_MODE	0	/* page tables structure debugging */
#define	DebugPTS(fmt, args...)					\
({									\
	if (DEBUG_PT_STRUCT_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_FLUSH_SPT_MODE
#undef	DebugFLSPT
#define	DEBUG_KVM_FLUSH_SPT_MODE	0	/* shadow pt levels TLB flushing */
#define	DebugFLSPT(fmt, args...)					\
({									\
	if (DEBUG_KVM_FLUSH_SPT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_UNIMPL_MODE
#undef	DebugUNIMPL
#define	DEBUG_KVM_UNIMPL_MODE	0	/* unimplemented */
#define	DebugUNIMPL(fmt, args...)					\
({									\
	if (DEBUG_KVM_UNIMPL_MODE || kvm_debug)				\
		pr_err_once(fmt, ##args);					\
})

extern void dump_page_struct(struct page *page);

/* try atomic/async page fault handling results */
typedef enum try_pf_err {
	TRY_PF_NO_ERR = 0,
	TRY_PF_ONLY_VALID_ERR,
	TRY_PF_MMIO_ERR,
} try_pf_err_t;

#define	TO_TRY_PF_ERR(errno)	((try_pf_err_t)(errno))

/*
 * It is copy/paste from include/linux/kvm_host.h to add e2k-arch specific
 * gfn -> pfn  translation errors:
 * For the normal pfn, the highest 12 bits should be zero,
 * so we can mask bit 62 ~ bit 52  to indicate the error pfn,
 * mask bit 63 to indicate the noslot pfn.
#define KVM_PFN_ERR_MASK	(0x7ffULL << 52)
#define KVM_PFN_ERR_NOSLOT_MASK	(0xfffULL << 52)
#define KVM_PFN_NOSLOT		(0x1ULL << 63)

#define KVM_PFN_ERR_FAULT	(KVM_PFN_ERR_MASK)
#define KVM_PFN_ERR_HWPOISON	(KVM_PFN_ERR_MASK + 1)
#define KVM_PFN_ERR_RO_FAULT	(KVM_PFN_ERR_MASK + 2)
 *
 * Do not forget modify here, if something changes in arch-indep header
 */
#define KVM_PFN_MMIO_FAULT	(KVM_PFN_ERR_MASK + 9)

/* MMIO space pfn indicates that the gfn is from IO space, */
/* but not registered on host (by VM launcher) */
static inline bool is_mmio_space_pfn(kvm_pfn_t pfn)
{
	return pfn == KVM_PFN_MMIO_FAULT;
}

/* FIXME: following emulation is for x86 arch, so it need be updated */
/* for e2k arch */
enum emulation_result {
	EMULATE_DONE,         /* no further processing */
	EMULATE_USER_EXIT,    /* kvm_run ready for userspace exit */
	EMULATE_FAIL,         /* can't emulate this instruction */
};

#define EMULTYPE_NO_DECODE	    (1 << 0)
#define EMULTYPE_TRAP_UD	    (1 << 1)
#define EMULTYPE_SKIP		    (1 << 2)
#define EMULTYPE_RETRY		    (1 << 3)
#define EMULTYPE_NO_REEXECUTE	    (1 << 4)

static inline gpa_t translate_gpa(struct kvm_vcpu *vcpu, gpa_t gpa, u32 access,
					kvm_arch_exception_t *exception)
{
	return gpa;
}

/* FIXME: x86 can support 2 addresses spaces at role.smm */
/* (in system management mode */
#define kvm_memslots_for_spte_role(kvm, role) __kvm_memslots(kvm, 0)

typedef struct kvm_memory_slot	kvm_memory_slot_t;

static inline bool gfn_is_from_mmio_space(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	gpa_t gpa = gfn_to_gpa(gfn);

	if (gpa >= VGA_VRAM_PHYS_BASE &&
			gpa < VGA_VRAM_PHYS_BASE + VGA_VRAM_SIZE) {
		/* address is from VGA VRAM space */
		return true;
	} else if (gpa >= sic_get_io_area_base() &&
			gpa < sic_get_io_area_base() +
					sic_get_io_area_max_size()) {
		/* address is from IO area space */
		return true;
	}
	return false;
}

/* FIXME: follow define is from x86 arch */
#define PF_VECTOR 14

static inline bool is_pae(struct kvm_vcpu *vcpu)
{
	if (is_ss(vcpu))
		return vcpu->arch.mmu.is_spae;
	return true;
}

static inline bool is_pse(struct kvm_vcpu *vcpu)
{
	if (is_ss(vcpu))
		return vcpu->arch.mmu.is_pse;
	return false;
}

static inline bool is_write_protection(struct kvm_vcpu *vcpu)
{
	if (is_ss(vcpu))
		pr_err("FIXME: %s() is not yet implemented\n", __func__);
	return false;
}

static inline void kvm_setup_paging_mode(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.is_pv && !vcpu->arch.is_hv) {
		/* it is software full paravirtulization mode, */
#ifdef	CONFIG_KVM_NONPAGING_ENABLE
		/* guest should be booted in nonpaging mode */
		reset_paging_flag(vcpu);
#else	/* ! CONFIG_KVM_NONPAGING_ENABLE */
		/* nonpaging mode is not supported or should not be used */
		set_paging_flag(vcpu);
#endif	/* CONFIG_KVM_NONPAGING_ENABLE */
		return;
	}

#ifdef	CONFIG_KVM_NONPAGING_ENABLE
	if (!vcpu->arch.is_hv) {
		/* hardware has not virtualization support, */
		/* only software virtualization can be used (see above) */
		if (!vcpu->arch.is_pv) {
			pr_err("%s(): hardware has not virtualization support, "
				"only paravirtualized guests can be run on "
				"this hypervisor\n",
				__func__);
		}
		set_paging_flag(vcpu);
		return;
	} else {
		reset_tdp_paging(vcpu);
	}
	reset_paging_flag(vcpu);
	return;
#else	/* ! CONFIG_KVM_NONPAGING_ENABLE */
	/* nonpaging mode is not supported or should not be used */
	if (!vcpu->arch.is_pv) {
		pr_err("%s(): nonpaging mode is not supported or should "
			"not be used on this hypervisor\n",
			__func__);
	}
	set_paging_flag(vcpu);
	return;
#endif	/* CONFIG_KVM_NONPAGING_ENABLE */
}

static inline void
vcpu_write_SH_MMU_CR_reg(struct kvm_vcpu *vcpu, e2k_mmu_cr_t mmu_cr)
{
	if (vcpu->arch.is_hv) {
		write_SH_MMU_CR_reg(mmu_cr);
	} else if (vcpu->arch.is_pv) {
		kvm_write_pv_vcpu_MMU_CR_reg(vcpu, mmu_cr);
	} else {
		E2K_KVM_BUG_ON(true);
	}
}

static inline int is_nx(struct kvm_vcpu *vcpu)
{
	return true;	/* not executable flag is supported */
}

static inline int is_smap(struct kvm_vcpu *vcpu)
{
	DebugUNIMPL("FIXME: %s() secondary PT is not supported\n", __func__);
	return false;
}

static inline int is_smep(struct kvm_vcpu *vcpu)
{
	DebugUNIMPL("FIXME: %s() secondary PT is not supported\n", __func__);
	return false;
}

static inline int is_smm(struct kvm_vcpu *vcpu)
{
	DebugUNIMPL("FIXME: %s() secondary PT is not supported\n", __func__);
	return false;
}

static inline bool is_long_mode(struct kvm_vcpu *vcpu)
{
	if (!is_ss(vcpu))
		return true;
	pr_err("FIXME: %s() is not yet implemented\n", __func__);
	return false;
}

static inline bool is_rsvd_bits_set(struct kvm_mmu *mmu, u64 gpte, int level)
{
	DebugUNIMPL("FIXME: %s() is not yet implemented\n", __func__);
	return false;
}

static inline bool is_cpuid_PSE36(void)
{
	pr_err("FIXME: %s() is not yet implemented\n", __func__);
	return false;
}

static inline int pse36_gfn_delta(pgprotval_t pte)
{
	pr_err("FIXME: %s() is not yet implemented\n", __func__);
	return 0;
}

static inline pgprotval_t get_vcpu_u2_pptb(struct kvm_vcpu *vcpu)
{
	if (is_ss(vcpu))
		return vcpu->arch.mmu.u2_pptb & PAGE_MASK;
	return E2K_INVALID_PAGE;
}
static inline e2k_addr_t get_vcpu_mpt_b(struct kvm_vcpu *vcpu)
{
	if (is_ss(vcpu))
		return vcpu->arch.mmu.mpt_b;
	return E2K_INVALID_PAGE;
}
static inline void set_vcpu_u2_pptb(struct kvm_vcpu *vcpu, pgprotval_t base)
{
	if (is_ss(vcpu))
		vcpu->arch.mmu.u2_pptb = base;
}
static inline void set_vcpu_mpt_b(struct kvm_vcpu *vcpu, e2k_addr_t base)
{
	if (is_ss(vcpu))
		vcpu->arch.mmu.mpt_b = base;
}

static inline pgprotval_t get_vcpu_pdpte(struct kvm_vcpu *vcpu, int no)
{
	if (is_ss(vcpu))
		return vcpu->arch.mmu.pdptes[no];
	return 0;
}

#define	kvm_vcpu_get_guest_pte(vcpu, gpa, ___hk_ptr, ___h_ptep,		\
				___writable)				\
		kvm_vcpu_get_guest_ptr(vcpu, gpa, ___hk_ptr, ___h_ptep,	\
					___writable)

#define	kvm_vcpu_get_guest_pte_atomic(vcpu, gpa, ___hk_pte)		\
		kvm_get_guest_atomic((vcpu)->kvm, gpa, ___hk_pte)

#define	kvm_vcpu_get_gpte_hva_atomic(__hk_ptr, __hva_ptrp)		\
({									\
	__typeof__(__hk_ptr) __user *hva_ptr;				\
	int r;								\
									\
	hva_ptr = (__typeof__((__hk_ptr)) *)(__hva_ptrp);		\
	pagefault_disable();						\
	r = native_get_user((__hk_ptr), hva_ptr);			\
	pagefault_enable();						\
	r;								\
})

/*
 * Return zero if the access does not fault; return the page fault error code
 * if the access faults.
 */
static inline u32 permission_fault(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
				  unsigned pte_access, unsigned pte_pkey,
				  unsigned pfec)
{
	u32 errcode = PFERR_PRESENT_MASK;

	if (is_ss(vcpu))
		pr_err("FIXME: %s() is not implemented\n", __func__);

	E2K_KVM_BUG_ON((pfec & PFERR_NOT_PRESENT_MASK) && !(pfec & PFERR_PT_FAULT_MASK));

	if ((pfec & (PFERR_WRITE_MASK | PFERR_WAIT_LOCK_MASK)) &&
			!(pte_access & ACC_WRITE_MASK))
		/* try write to write protected page (by pte) */
		return errcode | PFERR_WRITE_MASK;
	if (unlikely((pfec & PFERR_USER_MASK) && (pfec & PFERR_PRESENT_MASK) &&
			!(pfec & PFERR_FAPB_MASK) &&
				!(pte_access & ACC_WRITE_MASK)))
		/* try access from user to privileged page */
		return errcode | PFERR_USER_MASK;
	if (unlikely((pfec & (PFERR_INSTR_PROT_MASK | PFERR_INSTR_FAULT_MASK)) &&
			!(pte_access & ACC_EXEC_MASK)))
		/* try execute not executable page */
		return errcode | PFERR_INSTR_PROT_MASK;

	return 0;
}

/* FIXME: it need implementore priecision flush of various MMU TLBs */
/* instead of flush all TLBs */
static inline void kvm_vcpu_flush_tlb(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.is_hv) {
		/* ++vcpu->stat.tlb_flush; */
		local_flush_tlb_all();
		__flush_icache_all();
	}
}

#define KVM_PAGE_ARRAY_NR 16

typedef struct kvm_mmu_pages {
	struct mmu_page_and_offset {
		struct kvm_mmu_page *sp;
		unsigned int idx;
	} page[KVM_PAGE_ARRAY_NR];
	unsigned int nr;
} kvm_mmu_pages_t;

typedef struct kvm_spt_entry {
	pgprot_t *sptep;
	pgprot_t spte;
} kvm_spt_entry_t;
typedef struct kvm_shadow_trans {
	e2k_addr_t addr;
	kvm_spt_entry_t pt_entries[E2K_PT_LEVELS_NUM + 1];
	int last_level;
} kvm_shadow_trans_t;

typedef struct kvm_shadow_walk_iterator {
	e2k_addr_t addr;
	hpa_t shadow_addr;
	pgprot_t *sptep;
	const pt_struct_t *pt_struct;
	const pt_level_t *pt_level;
	int level;
	unsigned index;
} kvm_shadow_walk_iterator_t;

static inline pgprot_t __get_spte_lockless(pgprot_t *sptep)
{
	return __pgprot(READ_ONCE(*(pgprotval_t *)sptep));
}

static inline pgprot_t mmu_spte_get_lockless(pgprot_t *sptep)
{
	return __get_spte_lockless(sptep);
}

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

#define INVALID_INDEX (-1)

extern int kvm_get_va_spt_translation(struct kvm_vcpu *vcpu, e2k_addr_t address,
				mmu_spt_trans_t __user *user_trans_info);

/*
 * Return values of handle_mmio_page_fault:
 * RET_MMIO_PF_EMULATE: it is a real mmio page fault, emulate the instruction
 *			directly.
 * RET_MMIO_PF_INVALID: invalid spte is detected then let the real page
 *			fault path update the mmio spte.
 * RET_MMIO_PF_RETRY: let CPU fault again on the address.
 * RET_MMIO_PF_BUG: a bug was detected (and a WARN was printed).
 */
typedef enum ret_mmio_pf {
	RET_MMIO_PF_EMULATE = 1,
	RET_MMIO_PF_INVALID = 2,
	RET_MMIO_PF_RETRY = 0,
	RET_MMIO_PF_BUG = -1,
} ret_mmio_pf_t;

static inline void vcpu_cache_mmio_info(struct kvm_vcpu *vcpu,
					gva_t gva, gfn_t gfn, unsigned access)
{
	vcpu->arch.mmio_gva = gva & PAGE_MASK;
	vcpu->arch.access = access;
	vcpu->arch.mmio_gfn = gfn;
	vcpu->arch.mmio_gen = kvm_memslots(vcpu->kvm)->generation;
}

static inline bool vcpu_match_mmio_gen(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmio_gen == kvm_memslots(vcpu->kvm)->generation;
}

/*
 * Clear the mmio cache info for the given gva. If gva is MMIO_GVA_ANY, we
 * clear all mmio cache info.
 */
#define MMIO_GVA_ANY	(~(gva_t)0)

static inline void vcpu_clear_mmio_info(struct kvm_vcpu *vcpu, gva_t gva)
{
	if (gva != MMIO_GVA_ANY && vcpu->arch.mmio_gva != (gva & PAGE_MASK))
		return;

	vcpu->arch.mmio_gva = 0;
}

static inline bool vcpu_match_mmio_gva(struct kvm_vcpu *vcpu, unsigned long gva)
{
	if (vcpu_match_mmio_gen(vcpu) && vcpu->arch.mmio_gva &&
	      vcpu->arch.mmio_gva == (gva & PAGE_MASK))
		return true;

	return false;
}

static inline bool vcpu_match_mmio_gpa(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	if (vcpu_match_mmio_gen(vcpu) && vcpu->arch.mmio_gfn &&
	      vcpu->arch.mmio_gfn == gpa >> PAGE_SHIFT)
		return true;

	return false;
}

static bool mmio_info_in_cache(struct kvm_vcpu *vcpu, u64 addr, bool direct)
{
	if (direct)
		return vcpu_match_mmio_gpa(vcpu, addr);

	return vcpu_match_mmio_gva(vcpu, addr);
}

typedef struct mmu_page_path {
	struct kvm_mmu_page *parent[PT64_ROOT_LEVEL];
	unsigned int idx[PT64_ROOT_LEVEL];
} mmu_page_path_t;

extern int mmu_pages_first(struct kvm_mmu_pages *pvec,
			   struct mmu_page_path *parents, int pt_level);
extern int mmu_pages_next(struct kvm_mmu_pages *pvec,
			  struct mmu_page_path *parents,
			  int i, int pt_level);
extern bool kvm_sync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
			  struct list_head *invalid_list);
extern void mmu_pages_clear_parents(struct mmu_page_path *parents, int pt_level);
extern void kvm_mmu_flush_or_zap(struct kvm_vcpu *vcpu,
				 struct list_head *invalid_list,
				 bool remote_flush, bool local_flush);
extern void kvm_unlink_unsync_page(struct kvm *kvm, struct kvm_mmu_page *sp);
extern void kvm_mod_used_mmu_pages(struct kvm *kvm, int nr);
extern void kvm_mmu_commit_zap_page(struct kvm *kvm,
				    struct list_head *invalid_list);
extern struct kvm_mmu_page *kvm_mmu_get_page(struct kvm_vcpu *vcpu,
					     gfn_t gfn,
					     gva_t gaddr,
					     unsigned level,
					     int direct, gpa_t gpt_gpa,
					     unsigned access,
					     bool validate);
extern int make_mmu_pages_available(struct kvm_vcpu *vcpu);
extern int mmu_topup_memory_caches(struct kvm_vcpu *vcpu);
extern pf_res_t handle_mmu_page_fault(struct kvm_vcpu *vcpu, gva_t address,
				      u32 error_code, bool prefault,
				      gfn_t *gfn, kvm_pfn_t *pfn);
extern void kvm_unsync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp);

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

static inline bool is_obsolete_sp(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	return unlikely(sp->mmu_valid_gen != kvm->arch.mmu_valid_gen);
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

#define KVM_SET_USR_PFAULT(name, p, prev_usr_pfault_jmp) \
do { \
	(prev_usr_pfault_jmp) = (p)->thread.usr_pfault_jump; \
	GET_LBL_ADDR(name, (p)->thread.usr_pfault_jump); \
} while (false)

#define KVM_RESTORE_USR_PFAULT(p, saved_usr_pfault_jmp) \
({ \
	unsigned long __pfault_result = (p)->thread.usr_pfault_jump;\
	(p)->thread.usr_pfault_jump = (saved_usr_pfault_jmp); \
	unlikely(!__pfault_result); \
})

#define	KVM_SET_RECOVERY_FAULTED(name, vcpu) \
do { \
	E2K_KVM_BUG_ON((vcpu)->arch.mmu.recovery_pfault_jump != 0); \
	GET_LBL_ADDR(name, (vcpu)->arch.mmu.recovery_pfault_jump); \
} while (false)

#define	KVM_RESET_RECOVERY_FAULTED(vcpu) \
do { \
	(vcpu)->arch.mmu.recovery_pfault_jump = 0; \
} while (false)

#define	KVM_TEST_RECOVERY_FAULTED(vcpu) \
		((vcpu)->arch.mmu.recovery_pfault_jump != 0)

#define	KVM_GET_RECOVERY_JUMP_POINT(vcpu) \
		((vcpu)->arch.mmu.recovery_pfault_jump)

#ifndef	CONFIG_KVM_MMU_AUDIT
static inline void kvm_mmu_audit(struct kvm_vcpu *vcpu, int point) { }
static inline void mmu_audit_disable(void) { }
#endif	/* !CONFIG_KVM_MMU_AUDIT */

typedef enum {
	AUDIT_PRE_PAGE_FAULT,
	AUDIT_POST_PAGE_FAULT,
	AUDIT_PRE_PTE_WRITE,
	AUDIT_POST_PTE_WRITE,
	AUDIT_PRE_SYNC,
	AUDIT_POST_SYNC
} audit_type_t;

extern bool tdp_enabled;

extern struct kmem_cache *mmu_page_header_cache;
extern void *mmu_memory_cache_alloc(struct kvm_mmu_memory_cache *mc);

extern int kvm_mmu_load(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			unsigned flags);
extern void kvm_mmu_unload(struct kvm_vcpu *vcpu, unsigned flags);

extern void kvm_mmu_set_mmio_spte_mask(pgprotval_t mmio_mask);

extern void kvm_init_shadow_mmu(struct kvm_vcpu *vcpu);
extern void kvm_init_shadow_tdp_mmu(struct kvm_vcpu *vcpu, bool execonly);
extern pgprot_t *kvm_hva_to_pte(e2k_addr_t address);
extern int kvm_prefetch_mmu_area(struct kvm_vcpu *vcpu,
			gva_t start, gva_t end, u32 error_code);
extern void guest_pv_vcpu_state_to_paging(struct kvm_vcpu *vcpu);
extern gpa_t kvm_vcpu_gva_to_gpa(struct kvm_vcpu *vcpu, gva_t gva, u32 access,
				kvm_arch_exception_t *exception);
extern void kvm_mmu_flush_gva(struct kvm_vcpu *vcpu, gva_t gva);
extern void kvm_mmu_sync_roots(struct kvm_vcpu *vcpu, unsigned flags);
extern bool mmu_need_topup_memory_caches(struct kvm_vcpu *vcpu);
extern bool rmap_can_add(struct kvm_vcpu *vcpu);
extern void mmu_page_add_parent_pte(struct kvm_vcpu *vcpu,
			struct kvm_mmu_page *sp, pgprot_t *parent_pte);
extern void mmu_page_remove_parent_pte(struct kvm_mmu_page *sp,
				       pgprot_t *parent_pte);
extern int mmu_pages_add(struct kvm_mmu_pages *pvec, struct kvm_mmu_page *sp,
			 int idx);
extern void clear_sp_write_flooding_count(pgprot_t *spte);
extern bool mmu_need_write_protect(struct kvm_vcpu *vcpu, gfn_t gfn,
				   bool can_unsync);
extern bool handle_abnormal_pfn(struct kvm_vcpu *vcpu, gva_t gva, gfn_t gfn,
				kvm_pfn_t pfn, unsigned access,
				pf_res_t *ret_val);
extern bool page_fault_can_be_fast(u32 error_code);
extern bool try_async_pf(struct kvm_vcpu *vcpu, bool prefault, gfn_t gfn,
			 gva_t gva, kvm_pfn_t *pfn, bool write, bool *writable);
extern bool page_fault_handle_page_track(struct kvm_vcpu *vcpu,
					 u32 error_code, gfn_t gfn);
extern enum exec_mmu_ret calculate_guest_recovery_load_to_rf_frame(
		struct pt_regs *regs, tc_cond_t cond,
		u64 **radr, bool *load_to_rf);
extern bool check_guest_spill_fill_recovery(tc_cond_t cond, e2k_addr_t address,
					    bool s_f, struct pt_regs *regs);
extern try_pf_err_t try_atomic_pf(struct kvm_vcpu *vcpu, gfn_t gfn,
					kvm_pfn_t *pfn, bool no_dirty_log);
extern void mmu_pte_write_new_pte(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
				  pgprot_t *spte, gpa_t gpa, pgprotval_t new_gpte);
extern pgprotval_t mmu_pte_write_fetch_gpte(struct kvm_vcpu *vcpu, gpa_t *gpa,
					    const u8 *new, int *bytes);
extern int pte_list_add(struct kvm_vcpu *vcpu, pgprot_t *spte,
			struct kvm_rmap_head *rmap_head);
extern void pte_list_remove(pgprot_t *spte, struct kvm_rmap_head *rmap_head);

static inline int is_writable_pte(pgprot_t pte)
{
	return pgprot_val(pte) & PT_WRITABLE_MASK;
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

static inline void clear_unsync_child_bit(struct kvm_mmu_page *sp, int idx)
{
	--sp->unsync_children;
	KVM_WARN_ON((int)sp->unsync_children < 0);
	__clear_bit(idx, sp->unsync_child_bitmap);
}

void kvm_mmu_slot_remove_write_access(struct kvm *kvm,
				      struct kvm_memory_slot *memslot);
void kvm_mmu_zap_collapsible_sptes(struct kvm *kvm,
				   const struct kvm_memory_slot *memslot);
unsigned int kvm_mmu_calculate_mmu_pages(struct kvm *kvm);
void kvm_mmu_change_mmu_pages(struct kvm *kvm, unsigned int kvm_nr_mmu_pages);

extern void kvm_vcpu_release_trap_cellar(struct kvm_vcpu *vcpu);
void kvm_zap_gfn_range(struct kvm *kvm, gfn_t gfn_start, gfn_t gfn_end);
int kvm_mmu_unprotect_page(struct kvm *kvm, gfn_t gfn);
unsigned long kvm_slot_page_size(struct kvm_memory_slot *slot, gfn_t gfn);

static inline int kvm_get_pv_mmu_vmlpt_index(struct kvm *kvm)
{
	int pt_index;

	if (likely(!MMU_IS_SEPARATE_PT() && !kvm->arch.is_hv)) {
		pt_index = pgd_index(MMU_UNITED_KERNEL_VPTB);
	} else {
		E2K_KVM_BUG_ON(true);
		pt_index = -1;
	}
	return pt_index;
}

static inline int kvm_get_vmlpt_index(struct kvm *kvm, gmm_struct_t *gmm)
{
	int pt_index;

	if (likely(!kvm->arch.is_hv)) {
		pt_index = kvm_get_pv_mmu_vmlpt_index(kvm);
	} else {
		pt_index = pgd_index(gmm->u_vptb);
	}
	return pt_index;
}

static inline int kvm_vcpu_get_vmlpt_index(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	return kvm_get_vmlpt_index(vcpu->kvm, gmm);
}

static inline void kvm_vmlpt_spte_reset(struct kvm *kvm, pgprot_t *spte)
{
	pgprot_t zero = __pgprot(0);

	*spte = zero;
}

extern void kvm_set_mmu_guest_pt(struct kvm_vcpu *vcpu);
extern void kvm_set_mmu_guest_u_pt(struct kvm_vcpu *vcpu);
extern void kvm_switch_mmu_guest_u_pt(struct kvm_vcpu *vcpu);
extern void kvm_setup_mmu_tdp_context(struct kvm_vcpu *vcpu);
extern void kvm_setup_mmu_tdp_u_pt_context(struct kvm_vcpu *vcpu);

extern int mmu_pv_create_tdp_user_pt(struct kvm_vcpu *vcpu, gpa_t u_phys_ptb);

extern void mmu_pv_setup_shadow_u_pptb(struct kvm_vcpu *vcpu,
					gmm_struct_t *gmm);
extern int kvm_switch_shadow_u_pptb(struct kvm_vcpu *vcpu, gpa_t u_pptb,
					hpa_t *u_root);
extern int kvm_switch_shadow_os_pptb(struct kvm_vcpu *vcpu, gpa_t os_pptb,
					hpa_t *os_root);
extern int kvm_prepare_shadow_user_pt(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				gpa_t u_phys_ptb);
extern void copy_host_kernel_root_range(struct kvm_vcpu *vcpu, pgprot_t *dst_root);
extern void kvm_release_user_root_kernel_copy(struct kvm *kvm, gmm_struct_t *gmm);

static inline void
set_guest_kernel_pgd_range(pgd_t *dst_pgd, pgd_t pgd_to_set)
{
	set_pgd_range(dst_pgd, pgd_to_set, GUEST_KERNEL_PGD_PTRS_START,
			GUEST_KERNEL_PGD_PTRS_END);
}

static inline void
kvm_prepare_shadow_root(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			hpa_t root, hpa_t gp_root, gva_t vptb)
{
	pgprot_t *new_root;

	E2K_KVM_BUG_ON(!VALID_PAGE(root));
	new_root = (pgprot_t *)__va(root);

	/* copy kernel part of root page table entries to enable host */
	/* traps and hypercalls on guest */

	if (likely(!MMU_IS_SEPARATE_PT() && !vcpu->arch.is_hv)) {
		kvm_mmu_page_t *sp;
		unsigned long flags;

		sp = page_header(root);

		copy_host_kernel_root_range(vcpu, new_root);

		spin_lock(&vcpu->kvm->mmu_lock);

		/* copy MMU context of the guest nonpaging PT on host */
		raw_all_irq_save(flags);
		if (!IS_E2K_INVALID_PAGE(gp_root)) {
			E2K_KVM_BUG_ON(!pv_vcpu_is_init_gmm(vcpu,
						pv_vcpu_get_gmm(vcpu)));
		} else {
			E2K_KVM_BUG_ON(is_paging(vcpu) &&
					pv_vcpu_is_init_gmm(vcpu,
						pv_vcpu_get_gmm(vcpu)));
			get_mmu_pid_irqs_off(pv_vcpu_get_gmm_context(vcpu),
					MMU_PID_RELOAD_FORCED__NO_UPDATE);
		}
		sp->root_flags.has_host_pgds = 1;
		sp->root_flags.nonpaging = !is_paging(vcpu);
		if (likely(sp->root_flags.nonpaging)) {
			gmm_struct_t *init_gmm = pv_vcpu_get_init_gmm(vcpu);

			kvm_try_init_root_gmm_spt_list(init_gmm, sp);
		}
		sp->host_synced = true;
		raw_all_irq_restore(flags);
		spin_unlock(&vcpu->kvm->mmu_lock);
	}

	/* Since V6 hardware support has been simplified
	 * and self-pointing pgd is not required anymore. */
	if (!cpu_has(CPU_FEAT_ISET_V6)) {
		/* One PGD entry is the VPTB self-map. */
		int pt_index = kvm_vcpu_get_vmlpt_index(vcpu, gmm);
		mmu_pt_kvm_vmlpt_kernel_spte_set(vcpu->kvm, &new_root[pt_index], new_root);
	}
}

static inline void
mmu_pv_prepare_spt_u_root(struct kvm_vcpu *vcpu, gmm_struct_t *gmm, hpa_t root)
{
	pgprot_t *new_root;
	kvm_mmu_page_t *sp;
	unsigned long flags;

	E2K_KVM_BUG_ON(!VALID_PAGE(root));

	/* copy kernel part of root page table entries to enable host */
	/* traps and hypercalls on guest */
	new_root = (pgprot_t *)__va(root);
	copy_host_kernel_root_range(vcpu, new_root);

	E2K_KVM_BUG_ON(pv_vcpu_is_init_gmm(vcpu, gmm));
	sp = page_header(root);

	spin_lock(&vcpu->kvm->mmu_lock);

	/* create new host MMU context for guest user process */
	raw_all_irq_save(flags);
	get_mmu_pid_irqs_off(&gmm->context, MMU_PID_RELOAD_FORCED__NO_UPDATE);
	sp->root_flags.has_host_pgds = 1;
	sp->host_synced = true;
	sp->guest_kernel_synced = true;
	raw_all_irq_restore(flags);
	spin_unlock(&vcpu->kvm->mmu_lock);

	/* Since V6 hardware support has been simplified
	 * and self-pointing pgd is not required anymore. */
	if (!cpu_has(CPU_FEAT_ISET_V6)) {
		/* One PGD entry is the VPTB self-map. */
		int pt_index = kvm_vcpu_get_vmlpt_index(vcpu, gmm);
		mmu_pt_kvm_vmlpt_kernel_spte_set(vcpu->kvm, &new_root[pt_index], new_root);
	}
}

static inline void
kvm_clear_host_kernel_root_range(struct kvm *kvm, pgprot_t *root)
{
	pgd_t *pgd;
	pgd_t zero;

	pgd = (pgd_t *)root;
	pgd_val(zero) = 0;

	/* clear host kernel part of root page table entries */
	set_kernel_pgd_range(pgd, zero);
}

static inline void
kvm_clear_shadow_root(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	struct gmm_struct *gmm;
	pgprot_t *root;

	if (unlikely(MMU_IS_SEPARATE_PT() || kvm->arch.is_hv))
		return;

	gmm = kvm_try_get_sp_gmm(sp);
	if (likely(gmm != NULL)) {
		if (likely(VALID_PAGE(gmm->root_hpa))) {
			if (likely(!sp->root_flags.nonpaging)) {
				root = __va(gmm->root_hpa);
			} else {
				root = __va(kvm->arch.nonp_root_hpa);
			}
			E2K_KVM_BUG_ON(root != sp->spt);
		} else {
			root = sp->spt;
		}
	} else {
		E2K_KVM_BUG_ON(true);
	}
	if (likely(sp->root_flags.has_host_pgds)) {
		/* clear host kernel part of root page table entries */
		kvm_clear_host_kernel_root_range(kvm, root);
	}

	/* Since V6 hardware support has been simplified
	 * and self-pointing pgd is not required anymore. */
	if (!cpu_has(CPU_FEAT_ISET_V6)) {
		/* One PGD entry is the VPTB self-map. */
		int vmlpt_index = kvm_get_pv_mmu_vmlpt_index(kvm);
		kvm_vmlpt_spte_reset(kvm, &root[vmlpt_index]);
	}
}

static inline int
kvm_switch_tdp_u_pptb(struct kvm_vcpu *vcpu, gpa_t u_pptb)
{
	return 0;	/* nothing now to do */
}

static inline int
kvm_switch_tdp_os_pptb(struct kvm_vcpu *vcpu, gpa_t os_pptb)
{
	return 0;	/* nothing now to do */
}

static inline void
kvm_set_vcpu_the_pt_context(struct kvm_vcpu *vcpu, unsigned flags)
{
	vcpu->arch.mmu.set_vcpu_pt_context(vcpu, flags);
}

static inline void kvm_set_vcpu_pt_context(struct kvm_vcpu *vcpu)
{
	kvm_set_vcpu_the_pt_context(vcpu,
			OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG | GP_ROOT_PT_FLAG);
}

static inline void kvm_set_vcpu_u_pt_context(struct kvm_vcpu *vcpu)
{
	kvm_set_vcpu_the_pt_context(vcpu, U_ROOT_PT_FLAG);
}

static inline void kvm_set_vcpu_os_pt_context(struct kvm_vcpu *vcpu)
{
	kvm_set_vcpu_the_pt_context(vcpu, OS_ROOT_PT_FLAG);
}

static inline void kvm_set_vcpu_gp_pt_context(struct kvm_vcpu *vcpu)
{
	kvm_set_vcpu_the_pt_context(vcpu, GP_ROOT_PT_FLAG);
}

static inline int get_vcpu_mu_events_num(struct kvm_vcpu *vcpu)
{
	if (likely(vcpu->arch.is_hv || vcpu->arch.is_pv)) {
		return vcpu->arch.intc_ctxt.mu_num;
	} else {
		E2K_KVM_BUG_ON(true);
	}
	return 0;
}

static inline bool pv_vcpu_is_init_root_hpa(struct kvm_vcpu *vcpu, hpa_t root)
{
	gmm_struct_t *init_gmm = pv_vcpu_get_init_gmm(vcpu);

	return root == init_gmm->root_hpa;
}

static inline hpa_t pv_vcpu_get_init_root_hpa(struct kvm_vcpu *vcpu)
{
	gmm_struct_t *init_gmm = pv_vcpu_get_init_gmm(vcpu);

	return init_gmm->root_hpa;
}

static inline void set_vcpu_mu_events_num(struct kvm_vcpu *vcpu, int events_num)
{
	E2K_KVM_BUG_ON(events_num <= vcpu->arch.intc_ctxt.mu_num);
	if (likely(vcpu->arch.is_hv || vcpu->arch.is_pv)) {
		vcpu->arch.intc_ctxt.mu_num = events_num;
	} else {
		E2K_KVM_BUG_ON(true);
	}
}

static inline void set_vcpu_mu_cur_event_no(struct kvm_vcpu *vcpu, int event_no)
{
	int events_num = get_vcpu_mu_events_num(vcpu);

	E2K_KVM_BUG_ON(events_num >= 0 && event_no > events_num);
	if (likely(vcpu->arch.is_hv || vcpu->arch.is_pv)) {
		vcpu->arch.intc_ctxt.cur_mu = event_no;
	} else {
		E2K_KVM_BUG_ON(true);
	}
}

static inline intc_mu_state_t *get_intc_mu_state(struct kvm_vcpu *vcpu)
{
	if (likely(vcpu->arch.is_hv || vcpu->arch.is_pv)) {
		int evn_no = vcpu->arch.intc_ctxt.cur_mu;
		return &vcpu->arch.intc_ctxt.mu_state[evn_no];
	} else {
		E2K_KVM_BUG_ON(true);
	}
	return NULL;
}

#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
static inline void kvm_clear_intc_mu_state(struct kvm_vcpu *vcpu)
{
	intc_mu_state_t *mu_state = vcpu->arch.intc_ctxt.mu_state;
	int mu_num;
	int no;

	mu_num = get_vcpu_mu_events_num(vcpu);

	for (no = 0; no < mu_num; no++) {
		intc_mu_state_t *entry;

		entry = &mu_state[no];
		entry->notifier_seq = 0;
		entry->pfres = PFRES_NO_ERR;
		entry->may_be_retried = false;
		entry->ignore_notifier = false;
	}
}
#else
static inline void kvm_clear_intc_mu_state(struct kvm_vcpu *vcpu)
{
}
#endif	/* CONFIG_MMU_NOTIFIER) && KVM_ARCH_WANT_MMU_NOTIFIER */

#ifdef	CONFIG_KVM_HV_MMU
static inline int kvm_arch_init_vm_mmu(struct kvm *kvm)
{
	kvm->arch.nonp_root_hpa = E2K_INVALID_PAGE;

	INIT_HLIST_HEAD(&kvm->arch.mask_notifier_list);
	INIT_LIST_HEAD(&kvm->arch.active_mmu_pages);
	INIT_LIST_HEAD(&kvm->arch.zapped_obsolete_pages);

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	init_swait_queue_head(&kvm->arch.mmu_wq);
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

	return 0;
}

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER

/*
 * The same as arch-independent function, but can return 3 values
 *	to do not any retry
 *	to wait for zeroing mmu notifier counter (mmu notifier is in progress)
 *	to do retry (mmu notifier was completed)
 */
static inline mmu_retry_t
mmu_arch_notifier_retry(struct kvm *kvm, unsigned long mmu_seq)
{
	if (unlikely(kvm->mmu_notifier_count))
		return WAIT_FOR_MMU_RETRY;
	/*
	 * Ensure the read of mmu_notifier_count happens before the read
	 * of mmu_notifier_seq.  This interacts with the smp_wmb() in
	 * mmu_notifier_invalidate_range_end to make sure that the caller
	 * either sees the old (non-zero) value of mmu_notifier_count or
	 * the new (incremented) value of mmu_notifier_seq.
	 * PowerPC Book3s HV KVM calls this under a per-page lock
	 * rather than under kvm->mmu_lock, for scalability, so
	 * can't rely on kvm->mmu_lock to keep things ordered.
	 */
	smp_rmb();
	if (kvm->mmu_notifier_seq != mmu_seq)
		return DO_MMU_RETRY;

	return NO_MMU_RETRY;
}
#else	/* !KVM_ARCH_WANT_MMU_NOTIFIER */
static inline mmu_retry_t
mmu_arch_notifier_retry(struct kvm *kvm, unsigned long mmu_seq)
{
	return NO_MMU_RETRY;
}
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

extern void kvm_mmu_notifier_wait(struct kvm *kvm, unsigned long mmu_seq);

static inline bool
mmu_notifier_no_retry(struct kvm *kvm, unsigned long mmu_seq)
{
	return mmu_arch_notifier_retry(kvm, mmu_seq) == NO_MMU_RETRY;
}

static inline void kvm_init_sw_ctxt(struct kvm_vcpu *vcpu)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	vcpu_boot_stack_t *boot_stacks = &vcpu->arch.boot_stacks;
	e2k_stacks_t *boot_regs = &boot_stacks->regs.stacks;
	e2k_mem_crs_t *crs = &boot_stacks->regs.crs;
	kvm_guest_info_t *guest_info = &vcpu->kvm->arch.guest_info;

	/* set to initial state some fields */
	sw_ctxt->saved.valid = false;

	/* set pointers of guest boot-time local stacks to initial state */
	sw_ctxt->sbr.SBR_reg = boot_regs->top;
	sw_ctxt->usd_lo = boot_regs->usd_lo;
	sw_ctxt->usd_hi = boot_regs->usd_hi;
	if (vcpu->arch.is_pv) {
		sw_ctxt->crs.cr0_lo = crs->cr0_lo;
		sw_ctxt->crs.cr0_hi = crs->cr0_hi;
		sw_ctxt->crs.cr1_lo = crs->cr1_lo;
		sw_ctxt->crs.cr1_hi = crs->cr1_hi;
	}

	sw_ctxt->upsr.UPSR_reg = 0;
	if (guest_info->cpu_iset < E2K_ISET_V6) {
		sw_ctxt->upsr.UPSR_fe = 1;
	}

	/* set pointer to CUTD area */
	if (vcpu->arch.is_pv) {
		sw_ctxt->cutd = kvm_get_guest_vcpu_CUTD(vcpu);
	} else {
		sw_ctxt->cutd.CUTD_reg = 0;
	}

	sw_ctxt->trap_count = 0;

#ifdef	CONFIG_CLW_ENABLE
	/* Initialize CLW context */
	sw_ctxt->us_cl_d = 1;
	sw_ctxt->us_cl_b = 0;
	sw_ctxt->us_cl_up = 0;
	sw_ctxt->us_cl_m0 = 0;
	sw_ctxt->us_cl_m1 = 0;
	sw_ctxt->us_cl_m2 = 0;
	sw_ctxt->us_cl_m3 = 0;
#endif
}
extern int kvm_hv_setup_nonpaging_mode(struct kvm_vcpu *vcpu);
extern int write_to_guest_pt_phys(struct kvm_vcpu *vcpu, gpa_t gpa,
				const pgprot_t *gpte, int bytes);
extern int kvm_mmu_unprotect_page_virt(struct kvm_vcpu *vcpu, gva_t gva);
#else	/* ! CONFIG_KVM_HV_MMU */
static inline int kvm_arch_init_vm_mmu(struct kvm *kvm)
{
	return 0;
}
static inline int kvm_hv_setup_nonpaging_mode(struct kvm_vcpu *vcpu)
{
	E2K_KVM_BUG_ON(!is_paging(vcpu));
	/* guest physical addresses are translated by hypervisor */
	/* OS_* / U_* PTs */
	vcpu->arch.mmu.os_pptb = (pgprotval_t)NATIVE_READ_MMU_OS_PPTB_REG();
	vcpu->arch.mmu.os_vptb = NATIVE_READ_MMU_OS_VPTB_REG();
	vcpu->arch.mmu.u_pptb =
		(pgprotval_t)__pa(kvm_mmu_get_init_gmm_root(vcpu->kvm));
	vcpu->arch.mmu.u_vptb = NATIVE_READ_MMU_U_VPTB_REG();
	vcpu->arch.mmu.sh_os_vab = NATIVE_READ_MMU_OS_VAB_REG();
	vcpu->arch.mmu.tc_gpa = NATIVE_READ_MMU_TRAP_POINT();
	return 0;
}
static inline void kvm_init_sw_ctxt(struct kvm_vcpu *vcpu)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;

	/* In this case guest PT are the same as host PTs */
	sw_ctxt->sh_u_pptb = vcpu->arch.mmu.u_pptb;
	sw_ctxt->sh_u_vptb = vcpu->arch.mmu.u_vptb;
	sw_ctxt->tc_hpa = vcpu->arch.mmu.tc_gpa;
}
#endif	/* CONFIG_KVM_HV_MMU */

#ifdef CONFIG_KVM_HW_VIRTUALIZATION
extern void mmu_init_nonpaging_intc(struct kvm_vcpu *vcpu);
extern void setup_tdp_paging(struct kvm_vcpu *vcpu);
#else
static inline void mmu_init_nonpaging_intc(struct kvm_vcpu *vcpu) { }
static inline void setup_tdp_paging(struct kvm_vcpu *vcpu) { }
#endif

#ifdef	CONFIG_KVM_SHADOW_PT_ENABLE

extern int kvm_mmu_module_init(void);
extern void kvm_mmu_module_exit(void);

extern void kvm_mmu_destroy(struct kvm *kvm);
extern void vcpu_mmu_destroy(struct kvm_vcpu *vcpu);
extern int kvm_mmu_create(struct kvm_vcpu *vcpu);
extern void kvm_mmu_setup(struct kvm_vcpu *vcpu);
extern void kvm_mmu_reset(struct kvm_vcpu *vcpu);
extern void kvm_mmu_init_vm(struct kvm *kvm);
extern void kvm_mmu_uninit_vm(struct kvm *kvm);
extern int kvm_pv_switch_guest_mm(struct kvm_vcpu *vcpu,
			int gpid_nr, int gmmid_nr, gpa_t u_phys_ptb);

void kvm_mmu_invalidate_mmio_sptes(struct kvm *kvm, u64 gen);
void kvm_mmu_invalidate_zap_all_pages(struct kvm *kvm);

extern int kvm_pv_vcpu_mmu_state(struct kvm_vcpu *vcpu,
			  vcpu_gmmu_info_t __user *mmu_info);
extern int kvm_create_shadow_user_pt(struct kvm_vcpu *vcpu,
			gmm_struct_t *gmm, gpa_t u_phys_ptb);
extern hpa_t mmu_pv_switch_spt_u_pptb(struct kvm_vcpu *vcpu,
			gmm_struct_t *gmm, gpa_t u_phys_ptb);
extern int mmu_pv_switch_tdp_u_pptb(struct kvm_vcpu *vcpu,
			int pid, gpa_t u_phys_ptb);

extern void mmu_get_spt_roots(struct kvm_vcpu *vcpu, unsigned flags,
			hpa_t *os_root_p, hpa_t *u_root_p, hpa_t *gp_root_p);
extern void mmu_check_invalid_roots(struct kvm_vcpu *vcpu, bool invalid,
					unsigned flags);
extern void mmu_free_roots(struct kvm_vcpu *vcpu, unsigned flags);

extern int kvm_switch_to_tdp_paging(struct kvm_vcpu *vcpu,
		gpa_t u_phys_ptb, gva_t u_virt_ptb,
		gpa_t os_phys_ptb, gva_t os_virt_ptb, gva_t os_virt_base);

static inline void
pv_vcpu_switch_to_init_spt(struct kvm_vcpu *vcpu, hpa_t root)
{
	gmm_struct_t *init_gmm = pv_vcpu_get_init_gmm(vcpu);

	kvm_set_space_type_spt_u_root(vcpu, root);
	if (likely(!is_sep_virt_spaces(vcpu))) {
		kvm_set_space_type_guest_u_root(vcpu, init_gmm->u_pptb);
	} else {
		kvm_set_space_type_guest_os_root(vcpu, init_gmm->os_pptb);
	}
	kvm_set_vcpu_os_pt_context(vcpu);
}
static inline gmm_struct_t *
kvm_get_page_fault_gmm(struct kvm_vcpu *vcpu, u32 error_code)
{
	gmm_struct_t *gmm;

	if (vcpu->arch.is_hv)
		return NULL;

	if (error_code & (PFERR_USER_MASK | PFERR_USER_ADDR_MASK)) {
		gmm = pv_vcpu_get_gmm(vcpu);
	} else {
		gmm = pv_vcpu_get_init_gmm(vcpu);
	}

	E2K_KVM_BUG_ON(gmm == NULL);

	return gmm;
}
static inline gmm_struct_t *
kvm_get_faulted_addr_gmm(struct kvm_vcpu *vcpu, gva_t faulted_gva)
{
	gmm_struct_t *gmm;

	if (vcpu->arch.is_hv)
		return NULL;

	if (is_guest_user_gva(faulted_gva)) {
		gmm = pv_vcpu_get_gmm(vcpu);
	} else {
		gmm = pv_vcpu_get_init_gmm(vcpu);
	}

	E2K_KVM_BUG_ON(gmm == NULL);

	return gmm;
}

static inline gmm_struct_t *
kvm_get_space_addr_gmm(struct kvm_vcpu *vcpu, gva_t gva)
{
	gmm_struct_t *gmm;

	if (is_guest_kernel_gva(gva)) {
		/* guest kernel address - so it is init_gmm */
		return pv_vcpu_get_init_gmm(vcpu);
	} else if (is_guest_user_gva(gva)) {
		gmm = pv_vcpu_get_gmm(vcpu);
		if (unlikely(gmm == NULL)) {
			gmm = pv_vcpu_get_init_gmm(vcpu);
		}
	} else {
		E2K_KVM_BUG_ON(true);
		gmm = NULL;
	}
	return gmm;
}

static inline void kvm_mmu_unload_gmm_root(struct kvm_vcpu *vcpu)
{
	gthread_info_t *gti;
	gmm_struct_t *cur_gmm;
	hpa_t u_root, init_root;

	cur_gmm = pv_vcpu_get_gmm(vcpu);
	if (pv_vcpu_is_init_gmm(vcpu, cur_gmm)) {
		/* current gmm is init_gmm, cannot be unloaded */
		return;
	}
	mmu_get_spt_roots(vcpu, U_ROOT_PT_FLAG, NULL, &u_root, NULL);
	E2K_KVM_BUG_ON(!VALID_PAGE(u_root));
	if (unlikely(pv_vcpu_is_init_root_hpa(vcpu, u_root))) {
		/* current root PT is guest kernel init PT, */
		/* cannot be unloaded */
		;
	} else {
		kvm_mmu_unload(vcpu, U_ROOT_PT_FLAG);
	}
	gti = pv_vcpu_get_gti(vcpu);
	gti->gmm_in_release = true;
	init_root = kvm_convert_to_init_gmm(vcpu, gti);
	if (likely(u_root != init_root)) {
		pv_vcpu_switch_to_init_spt(vcpu, init_root);
	}
}

static inline unsigned int kvm_mmu_available_pages(struct kvm *kvm)
{
	if (kvm->arch.n_max_mmu_pages > kvm->arch.n_used_mmu_pages)
		return kvm->arch.n_max_mmu_pages -
				kvm->arch.n_used_mmu_pages;

	return 0;
}

/* FIXME: Currently only implemented for nonpaging & tdp */
static inline int kvm_mmu_reload(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				 unsigned flags)
{
	int r;

	E2K_KVM_BUG_ON(!is_phys_paging(vcpu));
	if (likely(VALID_PAGE(kvm_get_gp_phys_root(vcpu))))
		return 0;

	r = kvm_mmu_load(vcpu, gmm, flags);
	if (r)
		return r;

	kvm_set_vcpu_the_pt_context(vcpu, flags);

	return 0;
}

static inline int kvm_mmu_populate_area(struct kvm *kvm,
				e2k_addr_t area_start, e2k_addr_t area_end)
{
	struct kvm_vcpu *vcpu;
	int ret;

	if (!kvm->arch.is_pv)
		return 0;

	/* guest is software virtualized KVM, so it need */
	/* populate locked area on shadow PTs */
	vcpu = current_thread_info()->vcpu;
	E2K_KVM_BUG_ON(vcpu == NULL);
	if (unlikely(!vcpu->arch.mmu.shadow_pt_on))
		/* shadow PT is not yet enabled to use */
		return 0;
	ret = kvm_prefetch_mmu_area(vcpu, area_start, area_end,
				PFERR_PRESENT_MASK | PFERR_WRITE_MASK);
	return ret;
}

extern int kvm_pv_mmu_ptep_get_and_clear(struct kvm_vcpu *vcpu, gpa_t gpa,
				void __user *old_gpte, int as_valid);
extern int kvm_pv_mmu_pt_atomic_update(struct kvm_vcpu *vcpu, int gmmid_nr,
			gpa_t gpa, void __user *old_gpte,
			pt_atomic_op_t atomic_op,
			unsigned long prot_mask);
extern void mmu_free_spt_root(struct kvm_vcpu *vcpu, hpa_t root_hpa);
extern void mmu_release_spt_root(struct kvm *kvm, hpa_t root_hpa);
extern void mmu_release_nonpaging_root(struct kvm *kvm, hpa_t root_hpa);
extern void mmu_release_spt_nonpaging_root(struct kvm *kvm, hpa_t root_hpa);
extern int reexecute_load_and_wait_page_fault(struct kvm_vcpu *vcpu,
		trap_cellar_t *tcellar, gfn_t gfn, pt_regs_t *regs);
extern void release_gmm_root_pt(struct kvm *kvm, gmm_struct_t *gmm);
extern int kvm_dump_host_and_guest_pts(struct kvm *kvm, int gmmid_nr,
				       e2k_addr_t start, e2k_addr_t end);

static inline void mmu_flush_remote_tlbs(struct kvm_vcpu *vcpu,
					 pgprot_t *sptep, int level)
{
	if (vcpu->arch.is_hv) {
		kvm_flush_remote_tlbs(vcpu->kvm);
	} else {
		vcpu->kvm->arch.mmu_pt_ops.mmu_flush_spte_tlb_range(vcpu,
								sptep, level);
	}
}

static inline void mmu_flush_huge_remote_tlbs(struct kvm_vcpu *vcpu,
					      pgprot_t *sptep)
{
	if (vcpu->arch.is_hv) {
		kvm_flush_remote_tlbs(vcpu->kvm);
	} else {
		vcpu->kvm->arch.mmu_pt_ops.mmu_flush_large_spte_tlb_range(vcpu,
								sptep);
	}
}

static inline void mmu_pt_flush_shadow_pt_level_tlb(struct kvm *kvm,
					pgprot_t *sptep, pgprot_t old_spte)
{
	kvm->arch.mmu_pt_ops.mmu_flush_shadow_pt_level_tlb(kvm, sptep, old_spte);
}

static inline void
mmu_flush_shadow_gmm_tlb(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	host_flush_tlb_mm(gmm);
}

static inline void mmu_pt_dump_host_and_guest_pts(struct kvm *kvm,
			gmm_struct_t *gmm, e2k_addr_t start, e2k_addr_t end)
{
	kvm->arch.mmu_pt_ops.dump_host_and_guest_pts(kvm, gmm, start, end);
}

static inline gpa_t
nonpaging_gva_to_gpa(struct kvm_vcpu *vcpu, gva_t vaddr,
			u32 access, kvm_arch_exception_t *exception,
			gw_attr_t *gw_res)
{
	if (exception)
		exception->error_code = 0;
	return vaddr;
}

#else	/* ! CONFIG_KVM_SHADOW_PT_ENABLE */

static inline int kvm_mmu_module_init(void)
{
	return 0;
}
static inline void kvm_mmu_module_exit(void)
{
}

static inline void vcpu_mmu_destroy(struct kvm_vcpu *vcpu)
{
}
static inline void kvm_mmu_destroy(struct kvm *kvm)
{
}

static inline int kvm_mmu_create(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.gva_to_gpa = kvm_vcpu_gva_to_gpa;
	kvm_setup_paging_mode(vcpu);
	return 0;
}
static inline void kvm_mmu_setup(struct kvm_vcpu *vcpu)
{
}
static inline void kvm_mmu_reset(struct kvm_vcpu *vcpu)
{
}

static inline void kvm_mmu_init_vm(struct kvm *kvm)
{
}
static inline void kvm_mmu_uninit_vm(struct kvm *kvm)
{
}
static inline int
kvm_pv_switch_guest_mm(struct kvm_vcpu *vcpu,
		int gpid_nr, int gmmid_nr, gpa_t u_phys_ptb)
{
	E2K_KVM_BUG_ON(true);
	return 0;
}

static inline void
kvm_mmu_invalidate_mmio_sptes(struct kvm *kvm, u64 gen)
{
	return;
}
static inline void kvm_mmu_invalidate_zap_all_pages(struct kvm *kvm)
{
	return;
}

static inline pgprot_t
nonpaging_gpa_to_pte(struct kvm_vcpu *vcpu, gva_t addr)
{
	E2K_KVM_BUG_ON(!is_paging(vcpu));
	return __pgprot(0);
}

static inline int switch_to_shadow_pt(struct kvm_vcpu *vcpu,
			e2k_addr_t phys_ptb, e2k_addr_t virt_ptb)
{
	return 0;
}
static inline int
kvm_switch_to_tdp_paging(struct kvm_vcpu *vcpu,
		gpa_t u_phys_ptb, gva_t u_virt_ptb,
		gpa_t os_phys_ptb, gva_t os_virt_ptb, gva_t os_virt_base)
{
	E2K_KVM_BUG_ON(true);
	return 0;
}
static inline int kvm_mmu_pv_page_fault(struct kvm_vcpu *vcpu,
			struct pt_regs *regs, trap_cellar_t *tcellar,
			bool user_mode)
{
	/* guest is user of host, so host should handle page fault */
	return -1;
}

static inline int kvm_mmu_populate_area(struct kvm *kvm,
				e2k_addr_t start, e2k_addr_t end)
{
	return 0;
}

static inline int
kvm_pv_mmu_ptep_get_and_clear(struct kvm_vcpu *vcpu, gpa_t gpa,
				void __user *old_gpte, int as_valid)
{
	pr_warn_once("%s(): the hypervisor does not support guest MMU based "
		"on Shadow PTs, so this call/hypercall cannot be done\n",
		__func__);
	return -ENOTTY;
}
static inline int
kvm_pv_mmu_pt_atomic_op(struct kvm_vcpu *vcpu, gpa_t gpa, void __user *old_gpte,
			pt_atomic_op_t atomic_op, unsigned long prot_mask)
{
	pr_warn_once("%s(): the hypervisor does not support guest MMU based "
		"on Shadow PTs, so this call/hypercall cannot be done\n",
		__func__);
	return -ENOTTY;
}
#endif	/* CONFIG_KVM_SHADOW_PT_ENABLE */

#define	MMU_GUEST_PHYS_PT_VPTB	MMU_SEPARATE_KERNEL_VPTB
#define	MMU_GUEST_OS_PT_VPTB	MMU_SEPARATE_KERNEL_VPTB
#define	MMU_GUEST_USER_PT_VPTB	MMU_SEPARATE_USER_VPTB
#define	MMU_GUEST_OS_VAB	MMU_ADDR_TO_VAB(GUEST_PAGE_OFFSET)

extern int kvm_pv_activate_guest_mm(struct kvm_vcpu *vcpu,
			gmm_struct_t *new_gmm, gpa_t u_phys_ptb);
extern int kvm_pv_prepare_guest_mm(struct kvm_vcpu *vcpu,
		gmm_struct_t *new_gmm, gpa_t u_phys_ptb);

static inline bool kvm_is_shadow_pt_enable(struct kvm *kvm)
{
	return kvm->arch.shadow_pt_enable;
}
static inline void kvm_shadow_pt_disable(struct kvm *kvm)
{
	kvm->arch.shadow_pt_enable = false;
}

static inline bool kvm_is_phys_pt_enable(struct kvm *kvm)
{
	return kvm->arch.phys_pt_enable;
}
static inline void kvm_phys_pt_disable(struct kvm *kvm)
{
	kvm->arch.phys_pt_enable = false;
}

static inline bool kvm_is_tdp_enable(struct kvm *kvm)
{
	return kvm->arch.tdp_enable;
}
static inline void kvm_tdp_disable(struct kvm *kvm)
{
	kvm->arch.tdp_enable = false;
}

static inline int kvm_disable_tdp_mode(struct kvm *kvm)
{
	if (!kvm_is_tdp_enable(kvm))
		return 0;

	if (!kvm_is_shadow_pt_enable(kvm)) {
		pr_err("%s(): TDP mode should be disabled, but shadow PT mode "
			"is too disabled\n",
			__func__);
		return -EINVAL;
	}
	kvm_tdp_disable(kvm);
	return 0;
}

/*
 * Guest "physical" memory layout
 */
static inline bool kvm_is_ram_gfn(gfn_t gfn)
{
	e2k_addr_t phys_addr = gfn << PAGE_SHIFT;

	if (phys_addr >= GUEST_RAM_PHYS_BASE &&
			phys_addr < GUEST_RAM_PHYS_BASE +
						GUEST_MAX_RAM_SIZE)
		return true;
	else
		return false;
}
static inline bool kvm_is_vcpu_vram_gfn(gfn_t gfn)
{
	e2k_addr_t phys_addr = gfn << PAGE_SHIFT;

	if (phys_addr >= GUEST_VCPU_VRAM_PHYS_BASE &&
			phys_addr < GUEST_VCPU_VRAM_PHYS_BASE +
						GUEST_MAX_VCPU_VRAM_SIZE)
		return true;
	else
		return false;
}
static inline bool kvm_is_io_vram_gfn(gfn_t gfn)
{
	e2k_addr_t phys_addr = gfn << PAGE_SHIFT;

	if (phys_addr >= GUEST_IO_VRAM_PHYS_BASE &&
			phys_addr < GUEST_IO_VRAM_PHYS_BASE +
						GUEST_IO_VRAM_SIZE)
		return true;
	else
		return false;
}

extern void kvm_reset_mmu_state(struct kvm_vcpu *vcpu);
extern void kvm_init_mmu_state(struct kvm_vcpu *vcpu);
extern unsigned int kvm_get_guest_vcpu_mmu_trap_count(struct kvm_vcpu *vcpu);
extern void kvm_set_guest_vcpu_mmu_trap_count(struct kvm_vcpu *vcpu,
							unsigned int count);
extern void kvm_get_guest_vcpu_tc_entry(struct kvm_vcpu *vcpu,
					int tc_no, trap_cellar_t *tc_entry);
extern int kvm_add_guest_vcpu_tc_entry(struct kvm_vcpu *vcpu,
			e2k_addr_t address, tc_cond_t condition, u64 *data);

extern int kvm_gva_to_memslot_unaliased(struct kvm *kvm, gva_t gva);
extern gva_t kvm_gva_to_gpa(struct kvm *kvm, gva_t gva);
extern void kvm_free_user_pages(gva_t start, gva_t end);
extern int kvm_map_host_ttable_to_shadow(struct kvm *kvm,
				e2k_addr_t kernel_base, gva_t shadow_base);
extern e2k_addr_t kvm_guest_kernel_addr_to_hva(struct kvm_vcpu *vcpu,
							e2k_addr_t address);
extern int kvm_e2k_paravirt_page_prefault(pt_regs_t *regs,
						trap_cellar_t *tcellar);
extern int kvm_arch_vm_fault(struct vm_fault *vmf);

extern e2k_addr_t kvm_print_guest_kernel_ptes(e2k_addr_t address);
extern e2k_addr_t print_user_address_ptes(struct mm_struct *mm,
						e2k_addr_t address);
extern e2k_addr_t kvm_print_guest_user_address_ptes(struct kvm *kvm,
				int gmmid_nr, unsigned long address);

static inline long
kvm_move_guest_tagged_data(int word_size,
		e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	DebugKVMREC("started for address from 0x%lx to 0x%lx\n",
		addr_from, addr_to);

	if (IS_HOST_KERNEL_ADDRESS(addr_from)) {
		DebugKVMREC("invalid address 0x%lx from (outside "
			"guest space)\n",
			addr_from);
		return -EINVAL;
	}
	if (IS_HOST_KERNEL_ADDRESS(addr_to)) {
		DebugKVMREC("invalid address 0x%lx to (outside guest space)\n",
			addr_to);
		return -EINVAL;
	}
	switch (word_size) {
	case sizeof(u32):
		native_move_tagged_word(addr_from, addr_to);
		break;
	case sizeof(u64):
		native_move_tagged_dword(addr_from, addr_to);
		break;
	case sizeof(u64) * 2:
		native_move_tagged_qword(addr_from, addr_to);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/*
 * Recovery faulted store operations
 * common case: some addresses can be from host kernel address space,
 * but point to guest structures, shadow image ...
 */
extern __priv_hypercall long
kvm_priv_recovery_faulted_store(e2k_addr_t address, u64 wr_data, u64 st_rec_opc,
				u64 data_ext, u64 opc_ext, u64 args);
extern __priv_hypercall long
kvm_priv_recovery_faulted_load(e2k_addr_t addr, u64 *ld_val, u8 *data_tag,
			       u64 ld_rec_opc, int chan);
extern __priv_hypercall long
kvm_priv_recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
		e2k_addr_t addr_to_hi, u64 ld_rec_opc, u64 _args, u32 first_time);
extern __priv_hypercall long
kvm_priv_recovery_faulted_load_to_greg(e2k_addr_t addr, u32 greg_num_d,
		u64 ld_rec_opc, u64 _args, u64 *saved_greg_lo, u64 *saved_greg_hi);

extern long kvm_recovery_faulted_tagged_guest_store(struct kvm_vcpu *vcpu,
		e2k_addr_t address, u64 wr_data, u64 st_rec_opc,
		u64 data_ext, u64 opc_ext, u64 arg);
extern long kvm_recovery_faulted_guest_load(struct kvm_vcpu *vcpu,
		e2k_addr_t address, u64 *ld_val, u8 *data_tag,
		u64 ld_rec_opc, int chan);
extern long kvm_recovery_faulted_guest_move(struct kvm_vcpu *vcpu,
		e2k_addr_t addr_from, e2k_addr_t addr_to,
		e2k_addr_t addr_to_hi, u64 ld_rec_opc, u64 _arg,
		u32 first_time);
extern long kvm_recovery_faulted_load_to_guest_greg(struct kvm_vcpu *vcpu,
		e2k_addr_t address, u32 greg_num_d, u64 ld_rec_opc,
		u64 arg, u64 saved_greg_lo, u64 saved_greg_hi);
extern long kvm_move_tagged_guest_data(struct kvm_vcpu *vcpu,
		int word_size, e2k_addr_t addr_from, e2k_addr_t addr_to);

extern void update_pv_vcpu_local_glob_regs(struct kvm_vcpu *vcpu,
					   local_gregs_t *l_gregs);

static inline long
kvm_read_guest_dtlb_reg(e2k_addr_t virt_addr)
{
	return NATIVE_READ_DTLB_REG(virt_addr);
}

static inline long
kvm_get_guest_DAM(unsigned long long __user *dam, int dam_entries)
{
	int entries;
	int i;
	int ret = 0;

	if (dam_entries < DAM_ENTRIES_NUM)
		entries = dam_entries;
	else if (dam_entries > DAM_ENTRIES_NUM)
		entries = DAM_ENTRIES_NUM;
	else
		entries = dam_entries;

	for (i = 0; i < dam_entries; i++)
		ret |= __put_user(current->thread.dam[i], &dam[i]);
	return ret;
}

static inline long
kvm_flush_guest_dcache_line(e2k_addr_t virt_addr)
{
	NATIVE_FLUSH_DCACHE_LINE(virt_addr);
	return 0;
}
static inline long
kvm_clear_guest_dcache_l1_set(e2k_addr_t virt_addr, unsigned long set)
{
	NATIVE_CLEAR_DCACHE_L1_SET(virt_addr, set);
	return 0;
}

static inline long
kvm_flush_guest_dcache_range(void *virt_addr, size_t len)
{
	native_flush_DCACHE_range(virt_addr, len);
	return 0;
}
static inline long
kvm_clear_guest_dcache_l1_range(void *virt_addr, size_t len)
{
	native_clear_DCACHE_L1_range(virt_addr, len);
	return 0;
}
static inline long
kvm_flush_guest_icache_all(void)
{
	native_flush_icache_all();
	return 0;
}
static inline long
kvm_guest_mmu_probe(e2k_addr_t virt_addr, kvm_mmu_probe_t what)
{
	if (what == KVM_MMU_PROBE_ENTRY) {
		return NATIVE_ENTRY_PROBE_MMU_OP(virt_addr);
	} else if (what == KVM_MMU_PROBE_ADDRESS) {
		return NATIVE_ADDRESS_PROBE_MMU_OP(virt_addr);
	}
	/* invalid MMU probe type */
	return ILLEGAL_PAGE_EP_RES;
}

extern void kvm_arch_init_vm_mmap(struct kvm *kvm);
extern void kvm_arch_free_memory_region(struct kvm *kvm,
				struct kvm_memory_slot *memslot);

#endif	/* __KVM_E2K_MMU_H */
