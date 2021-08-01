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
#include <asm/kvm/hypercall.h>
#include <asm/kvm/mmu.h>

#include "mmu-e2k.h"
#include "mmu-x86.h"
#include "hv_mmu.h"
#include "cpu_defs.h"
#include "mmu_defs.h"

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
#define	DEBUG_PT_STRUCT_MODE	1	/* page tables structure debugging */
#define	DebugPTS(fmt, args...)					\
({									\
	if (DEBUG_PT_STRUCT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#if	PT_E2K_PRESENT_MASK == PT_X86_PRESENT_MASK
# define PT_PRESENT_MASK	PT_E2K_PRESENT_MASK
#else
# error	"Page table PRESENT bit is different for e2k vs x86"
#endif
#if	PT_E2K_WRITABLE_MASK == PT_X86_WRITABLE_MASK
# define PT_WRITABLE_MASK	PT_E2K_WRITABLE_MASK
#else
# error	"Page table WRITABLE bit is different for e2k vs x86"
#endif
#if	PT_E2K_ACCESSED_MASK == PT_X86_ACCESSED_MASK
# define PT_ACCESSED_MASK	PT_E2K_ACCESSED_MASK
#else
# error	"Page table ACCESSED bit is different for e2k vs x86"
#endif
#if	PT_E2K_DIRTY_MASK == PT_X86_DIRTY_MASK
# define PT_DIRTY_MASK		PT_E2K_DIRTY_MASK
#else
# error	"Page table DIRTY bit is different for e2k vs x86"
#endif
#if	PT_E2K_PAGE_SIZE_MASK == PT_X86_PAGE_SIZE_MASK
# define PT_PAGE_SIZE_MASK	PT_E2K_PAGE_SIZE_MASK
#else
# error	"Page table PAGE SIZE bit is different for e2k vs x86"
#endif
#if	PT_E2K_GLOBAL_MASK == PT_X86_GLOBAL_MASK
# define PT_GLOBAL_MASK		PT_E2K_GLOBAL_MASK
#else
# error	"Page table GLOBAL bit is different for e2k vs x86"
#endif

#if	PT_E2K_ROOT_LEVEL == PT_X86_64_ROOT_LEVEL
# define PT64_ROOT_LEVEL	PT_E2K_ROOT_LEVEL
#else
# error	"Page table root level is different for e2k vs x86"
#endif
#define	PT32_ROOT_LEVEL		PT_X86_32_ROOT_LEVEL
#define	PT32E_ROOT_LEVEL	PT_X86_PAE_ROOT_LEVEL

#if	PT_E2K_DIRECTORY_LEVEL == PT_X86_DIRECTORY_LEVEL
# define PT_DIRECTORY_LEVEL	PT_E2K_DIRECTORY_LEVEL	/* pmd */
#else
# error	"Page table directory level is different for e2k vs x86"
#endif
#if	PT_E2K_PAGE_TABLE_LEVEL == PT_X86_PAGE_TABLE_LEVEL
# define PT_PAGE_TABLE_LEVEL	PT_E2K_PAGE_TABLE_LEVEL	/* pte */
#else
# error	"Page table entries level is different for e2k vs x86"
#endif
#if	PT_E2K_MAX_HUGEPAGE_LEVEL >= PT_X86_MAX_HUGEPAGE_LEVEL
# define PT_MAX_HUGEPAGE_LEVEL	PT_E2K_MAX_HUGEPAGE_LEVEL
#else	/* PT_X86_MAX_HUGEPAGE_LEVEL > PT_E2K_MAX_HUGEPAGE_LEVEL */
# define PT_MAX_HUGEPAGE_LEVEL	PT_X86_MAX_HUGEPAGE_LEVEL
#endif

#if	PT_E2K_ENTRIES_BITS == PT_X86_64_ENTRIES_BITS
# define PT64_ENTRIES_BITS	PT_E2K_ENTRIES_BITS
#else
# error	"Page table level entry bits number is different for e2k vs x86"
#endif
#define	PT32_ENTRIES_BITS	PT_X86_32_ENTRIES_BITS

#if	PT_E2K_ENT_PER_PAGE == PT_X86_64_ENT_PER_PAGE
# define PT64_ENT_PER_PAGE	PT_E2K_ENT_PER_PAGE
#else
# error	"Page table level number of entries is different for e2k vs x86"
#endif
#define	PT32_ENT_PER_PAGE	PT_X86_32_ENT_PER_PAGE

/* all available page tables abstructs */
extern const pt_struct_t __nodedata pgtable_struct_e2k_v2;
extern const pt_struct_t __nodedata pgtable_struct_e2k_v3;
extern const pt_struct_t __nodedata pgtable_struct_e2k_v5;
extern const pt_struct_t __nodedata pgtable_struct_e2k_v6_pt_v6;
extern const pt_struct_t __nodedata pgtable_struct_e2k_v6_gp;

#define	pgtable_struct_e2k_v6_pt_v2	pgtable_struct_e2k_v5

extern const pt_struct_t *kvm_mmu_get_host_pt_struct(struct kvm *kvm);
extern const pt_struct_t *kvm_mmu_get_vcpu_pt_struct(struct kvm_vcpu *vcpu);
extern const pt_struct_t *kvm_mmu_get_gp_pt_struct(struct kvm *kvm);

extern const pt_struct_t *kvm_get_mmu_host_pt_struct(struct kvm *kvm);
extern const pt_struct_t *kvm_get_mmu_guest_pt_struct(struct kvm_vcpu *vcpu);

static inline const pt_struct_t *
mmu_get_host_pt_struct(struct kvm *kvm)
{
	return kvm->arch.host_pt_struct;
}

static inline void
mmu_set_host_pt_struct(struct kvm *kvm, const pt_struct_t *pt_struct)
{
	kvm->arch.host_pt_struct = pt_struct;
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
	kvm->arch.get_host_pt_struct = func;
}

static inline const pt_struct_t *
mmu_get_vcpu_pt_struct(struct kvm_vcpu *vcpu)
{
	BUG_ON(vcpu->kvm->arch.guest_pt_struct == NULL);
	return vcpu->kvm->arch.guest_pt_struct;
}

static inline void
mmu_set_vcpu_pt_struct(struct kvm *kvm, const pt_struct_t *pt_struct)
{
	kvm->arch.guest_pt_struct = pt_struct;
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
	kvm->arch.get_vcpu_pt_struct = func;
}

static inline const pt_struct_t *
mmu_get_gp_pt_struct(struct kvm *kvm)
{
	BUG_ON(kvm->arch.gp_pt_struct == NULL);
	return kvm->arch.gp_pt_struct;
}

static inline void
mmu_set_gp_pt_struct(struct kvm *kvm, const pt_struct_t *pt_struct)
{
	kvm->arch.gp_pt_struct = pt_struct;
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
	kvm->arch.get_gp_pt_struct = func;
}

static inline const pt_struct_t *
kvm_get_host_pt_struct(struct kvm *kvm)
{
	BUG_ON(kvm->arch.get_host_pt_struct(kvm) == NULL);
	return kvm->arch.get_host_pt_struct(kvm);
}

static inline const pt_struct_t *
kvm_get_vcpu_pt_struct(struct kvm_vcpu *vcpu)
{
	BUG_ON(vcpu->kvm->arch.get_vcpu_pt_struct == NULL);
	return vcpu->kvm->arch.get_vcpu_pt_struct(vcpu);
}

static inline const pt_struct_t *
kvm_get_gp_pt_struct(struct kvm *kvm)
{
	BUG_ON(kvm->arch.get_gp_pt_struct == NULL);
	return kvm->arch.get_gp_pt_struct(kvm);
}

extern void dump_page_struct(struct page *page);

/* KVM Hugepage definitions for host machine */
#define KVM_MMU_HPAGE_SHIFT(kvm, level_id)	\
		KVM_PT_LEVEL_HPAGE_SHIFT(	\
			get_pt_struct_level_on_id(kvm_get_host_pt_struct(kvm), \
							level_id))
#define KVM_MMU_HPAGE_SIZE(kvm, level_id)	\
		KVM_PT_LEVEL_HPAGE_SIZE(	\
			get_pt_struct_level_on_id(kvm_get_host_pt_struct(kvm), \
							level_id))
#define KVM_MMU_HPAGE_MASK(kvm, level_id)	\
		KVM_PT_LEVEL_HPAGE_MASK(	\
			get_pt_struct_level_on_id(kvm_get_host_pt_struct(kvm), \
							level_id))
#define KVM_MMU_PAGES_PER_HPAGE(kvm, level_id)	\
		KVM_PT_LEVEL_PAGES_PER_HPAGE(	\
			get_pt_struct_level_on_id(kvm_get_host_pt_struct(kvm), \
							level_id))
#define KVM_MMU_HPAGE_GFN_SHIFT(kvm, level_id)	\
		(KVM_MMU_HPAGE_SHIFT(kvm, level_id) - PAGE_SHIFT)

static inline gfn_t
kvm_gfn_to_index(struct kvm *kvm, gfn_t gfn, gfn_t base_gfn, int level_id)
{
	return gfn_to_index(gfn, base_gfn,
			get_pt_struct_level_on_id(kvm_get_host_pt_struct(kvm),
							level_id));
}

/*			uwx	(u - user mode, w - writable, x executable) */
#define ACC_EXEC_MASK	0x1
#define ACC_WRITE_MASK	0x2
#define	ACC_USER_MASK	0x4
#define ACC_ALL		(ACC_EXEC_MASK | ACC_WRITE_MASK | ACC_USER_MASK)
/* page tables directories always privileged & not executable */
#define	ACC_PT_DIR	(ACC_WRITE_MASK)

#define PFERR_PRESENT_BIT	0
#define PFERR_WRITE_BIT		1
#define PFERR_USER_BIT		2
#define PFERR_RSVD_BIT		3
#define PFERR_FETCH_BIT		4
#define	PFERR_NOT_PRESENT_BIT	5
#define	PFERR_PT_FAULT_BIT	6
#define	PFERR_INSTR_FAULT_BIT	7
#define	PFERR_INSTR_PROT_BIT	8
#define	PFERR_FORCED_BIT	9
#define	PFERR_WAIT_LOCK_BIT	10
#define	PFERR_GPTE_CHANGED_BIT	11
#define	PFERR_MMIO_BIT		12
#define	PFERR_ONLY_VALID_BIT	13
#define	PFERR_READ_PROT_BIT	14
#define	PFERR_IS_UNMAPPED_BIT	15
#define	PFERR_FAPB_BIT		16

#define	PFERR_ACCESS_SIZE_BIT	24

#define PFERR_PRESENT_MASK	(1U << PFERR_PRESENT_BIT)
#define PFERR_WRITE_MASK	(1U << PFERR_WRITE_BIT)
#define PFERR_USER_MASK		(1U << PFERR_USER_BIT)
#define PFERR_RSVD_MASK		(1U << PFERR_RSVD_BIT)
#define PFERR_FETCH_MASK	(1U << PFERR_FETCH_BIT)
#define	PFERR_NOT_PRESENT_MASK	(1U << PFERR_NOT_PRESENT_BIT)
#define	PFERR_PT_FAULT_MASK	(1U << PFERR_PT_FAULT_BIT)
#define	PFERR_INSTR_FAULT_MASK	(1U << PFERR_INSTR_FAULT_BIT)
#define	PFERR_INSTR_PROT_MASK	(1U << PFERR_INSTR_PROT_BIT)
#define	PFERR_FORCED_MASK	(1U << PFERR_FORCED_BIT)
#define	PFERR_WAIT_LOCK_MASK	(1U << PFERR_WAIT_LOCK_BIT)
#define	PFERR_GPTE_CHANGED_MASK	(1U << PFERR_GPTE_CHANGED_BIT)
#define	PFERR_MMIO_MASK		(1U << PFERR_MMIO_BIT)
#define	PFERR_ONLY_VALID_MASK	(1U << PFERR_ONLY_VALID_BIT)
#define	PFERR_READ_PROT_MASK	(1U << PFERR_READ_PROT_BIT)
#define	PFERR_IS_UNMAPPED_MASK	(1U << PFERR_IS_UNMAPPED_BIT)
#define	PFERR_FAPB_MASK		(1U << PFERR_FAPB_BIT)

#define	PFERR_ACCESS_SIZE_MASK	(~0U << PFERR_ACCESS_SIZE_BIT)

#define	PFRES_GET_ACCESS_SIZE(pfres)	\
		(((pfres) & PFERR_ACCESS_SIZE_MASK) >> PFERR_ACCESS_SIZE_BIT)
#define	PFRES_SET_ACCESS_SIZE(pfres, size)	\
		(((pfres) & ~PFERR_ACCESS_SIZE_MASK) | \
			((size) << PFERR_ACCESS_SIZE_BIT))

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

typedef struct kvm_arch_exception {
	bool error_code_valid;	/* PFERR_* flags is valid */
	u32 error_code;		/* PFERR_* flags */
	u64 address;		/* page fault gpa */
	u64 ip;			/* IP to inject trap */
} kvm_arch_exception_t;

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
vcpu_write_SH_MMU_CR_reg(struct kvm_vcpu *vcpu, mmu_reg_t mmu_cr)
{
	if (vcpu->arch.is_hv) {
		write_SH_MMU_CR_reg(mmu_cr);
	} else if (vcpu->arch.is_pv) {
		kvm_write_pv_vcpu_MMU_CR_reg(vcpu, mmu_cr);
	} else {
		KVM_BUG_ON(true);
	}
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
	pr_err_once("FIXME: %s() is not yet implemented\n", __func__);
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

	/* It need investigate how PFERR_NOT_PRESENT_MASK fault to lead to */
	/* present pte at guest PT and not present at shadow PT */
	KVM_BUG_ON(pfec & PFERR_PT_FAULT_MASK);

	if ((pfec & (PFERR_WRITE_MASK | PFERR_WAIT_LOCK_MASK)) &&
			!(pte_access & ACC_WRITE_MASK))
		/* try write to write protected page (by pte) */
		return errcode | PFERR_WRITE_MASK;
	if ((pfec & PFERR_USER_MASK) && !(pfec & PFERR_FAPB_MASK) &&
			!(pte_access & ACC_WRITE_MASK))
		/* try access from user to privileged page */
		return errcode | PFERR_USER_MASK;
	if ((pfec & (PFERR_INSTR_PROT_MASK | PFERR_INSTR_FAULT_MASK)) &&
			!(pte_access & ACC_EXEC_MASK))
		/* try execute not executable page */
		return errcode | PFERR_INSTR_PROT_MASK;

	return 0;
}

/* FIXME: it need implementore priecision flush of various MMU TLBs */
/* instead of flush all TLBs */
static inline void kvm_vcpu_flush_tlb(struct kvm_vcpu *vcpu)
{
/*	++vcpu->stat.tlb_flush; */
	__flush_tlb_all();
	__flush_icache_all();
}

typedef struct kvm_shadow_walk_iterator {
	e2k_addr_t addr;
	hpa_t shadow_addr;
	pgprot_t *sptep;
	const pt_struct_t *pt_struct;
	const pt_level_t *pt_level;
	int level;
	unsigned index;
} kvm_shadow_walk_iterator_t;

void shadow_walk_init(kvm_shadow_walk_iterator_t *iterator,
				struct kvm_vcpu *vcpu, u64 addr);
bool shadow_walk_okay(kvm_shadow_walk_iterator_t *iterator);
void __shadow_walk_next(kvm_shadow_walk_iterator_t *iterator, pgprot_t spte);
void shadow_walk_next(struct kvm_shadow_walk_iterator *iterator);

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

extern bool tdp_enabled;

extern int kvm_mmu_load(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			unsigned flags);
extern void kvm_mmu_unload(struct kvm_vcpu *vcpu, unsigned flags);
extern void kvm_mmu_free_page(struct kvm *kvm, struct kvm_mmu_page *sp);

extern void kvm_setup_mmu_intc_mode(struct kvm_vcpu *vcpu);

extern void kvm_mmu_set_mmio_spte_mask(pgprotval_t mmio_mask);

extern void direct_unmap_prefixed_mmio_gfn(struct kvm *kvm, gfn_t gfn);

extern int handle_mmio_page_fault(struct kvm_vcpu *vcpu, u64 addr, gfn_t *gfn,
					bool direct);
extern void kvm_init_shadow_mmu(struct kvm_vcpu *vcpu);
extern void kvm_init_shadow_tdp_mmu(struct kvm_vcpu *vcpu, bool execonly);
extern pgprot_t *kvm_hva_to_pte(e2k_addr_t address);
extern int e2k_shadow_pt_protection_fault(struct kvm_vcpu *vcpu, gpa_t addr,
						kvm_mmu_page_t *sp);
extern int kvm_prefetch_mmu_area(struct kvm_vcpu *vcpu,
			gva_t start, gva_t end, u32 error_code);
extern gpa_t e2k_gva_to_gpa(struct kvm_vcpu *vcpu, gva_t vaddr, u32 access,
				kvm_arch_exception_t *exception);
extern void guest_pv_vcpu_state_to_paging(struct kvm_vcpu *vcpu);
extern gpa_t kvm_vcpu_gva_to_gpa(struct kvm_vcpu *vcpu, gva_t gva, u32 access,
				kvm_arch_exception_t *exception);
extern void kvm_mmu_flush_gva(struct kvm_vcpu *vcpu, gva_t gva);
extern void kvm_mmu_sync_roots(struct kvm_vcpu *vcpu, unsigned flags);

static inline int is_writable_pte(pgprot_t pte)
{
	return pgprot_val(pte) & PT_WRITABLE_MASK;
}

void kvm_mmu_slot_remove_write_access(struct kvm *kvm,
				      struct kvm_memory_slot *memslot);
void kvm_mmu_zap_collapsible_sptes(struct kvm *kvm,
				   const struct kvm_memory_slot *memslot);
unsigned int kvm_mmu_calculate_mmu_pages(struct kvm *kvm);
void kvm_mmu_change_mmu_pages(struct kvm *kvm, unsigned int kvm_nr_mmu_pages);

void kvm_zap_gfn_range(struct kvm *kvm, gfn_t gfn_start, gfn_t gfn_end);
int kvm_mmu_unprotect_page(struct kvm *kvm, gfn_t gfn);

void kvm_mmu_gfn_disallow_lpage(struct kvm *kvm,
				kvm_memory_slot_t *slot, gfn_t gfn);
void kvm_mmu_gfn_allow_lpage(struct kvm *kvm,
				kvm_memory_slot_t *slot, gfn_t gfn);
bool kvm_mmu_slot_gfn_write_protect(struct kvm *kvm,
					kvm_memory_slot_t *slot, u64 gfn);
int kvm_sync_init_shadow_pt(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
		gpa_t phys_ptb, gva_t virt_ptb,
		gpa_t os_phys_ptb, gva_t os_virt_ptb, gva_t os_virt_base);

extern void kvm_vmlpt_kernel_spte_set(struct kvm *kvm,
				pgprot_t *spte, pgprot_t *root);
extern void kvm_vmlpt_user_spte_set(struct kvm *kvm,
				pgprot_t *spte, pgprot_t *root);

extern void kvm_update_guest_stacks_registers(struct kvm_vcpu *vcpu,
						guest_hw_stack_t *stack_regs);
extern void kvm_set_mmu_guest_pt(struct kvm_vcpu *vcpu);
extern void kvm_set_mmu_guest_u_pt(struct kvm_vcpu *vcpu);
extern void kvm_switch_mmu_guest_u_pt(struct kvm_vcpu *vcpu);
extern void kvm_setup_mmu_spt_context(struct kvm_vcpu *vcpu);
extern void kvm_setup_mmu_tdp_context(struct kvm_vcpu *vcpu);
extern void kvm_setup_mmu_tdp_u_pt_context(struct kvm_vcpu *vcpu);

extern int mmu_pv_create_tdp_user_pt(struct kvm_vcpu *vcpu, gpa_t u_phys_ptb);

extern void mmu_pv_setup_shadow_u_pptb(struct kvm_vcpu *vcpu,
					gmm_struct_t *gmm);
extern void kvm_setup_shadow_u_pptb(struct kvm_vcpu *vcpu);
extern void kvm_setup_shadow_os_pptb(struct kvm_vcpu *vcpu);
extern int kvm_switch_shadow_u_pptb(struct kvm_vcpu *vcpu, gpa_t u_pptb,
					hpa_t *u_root);
extern int kvm_switch_shadow_os_pptb(struct kvm_vcpu *vcpu, gpa_t os_pptb,
					hpa_t *os_root);
extern int kvm_prepare_shadow_user_pt(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				gpa_t u_phys_ptb);
extern void kvm_dump_shadow_os_pt_regs(struct kvm_vcpu *vcpu);
extern void copy_guest_kernel_root_range(struct kvm_vcpu *vcpu,
		gmm_struct_t *gmm, struct kvm_mmu_page *sp, pgprot_t *src_root);
extern void mmu_zap_linked_children(struct kvm *kvm,
					struct kvm_mmu_page *parent);

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
	int pt_index;

	KVM_BUG_ON(!VALID_PAGE(root));

	/* copy kernel part of root page table entries to enable host */
	/* traps and hypercalls on guest */

	if (likely(!MMU_IS_SEPARATE_PT() && !vcpu->arch.is_hv)) {
		kvm_mmu_page_t *sp;
		pgd_t *new_pgd, *init_pgd;
		pgprot_t *src_root;
		unsigned long flags;

		sp = page_header(root);
		new_pgd = (pgd_t *)__va(root);
		init_pgd = kvm_mmu_get_init_gmm_root(vcpu->kvm);

		copy_kernel_pgd_range(new_pgd, current->mm->pgd);

		src_root = (pgprot_t *)init_pgd;
		if (init_pgd != NULL)
			copy_guest_kernel_root_range(vcpu, gmm, sp, src_root);

		/* copy MMU context of the guest nonpaging PT on host */
		spin_lock(&vcpu->kvm->mmu_lock);
		raw_all_irq_save(flags);
		if (!IS_E2K_INVALID_PAGE(gp_root)) {
			KVM_BUG_ON(!pv_vcpu_is_init_gmm(vcpu,
						pv_vcpu_get_gmm(vcpu)));
		} else {
			KVM_BUG_ON(is_paging(vcpu) &&
					pv_vcpu_is_init_gmm(vcpu,
						pv_vcpu_get_gmm(vcpu)));
			get_new_mmu_pid(pv_vcpu_get_gmm_context(vcpu),
					smp_processor_id());
		}
		sp->root_flags.has_host_pgds = 1;
		sp->host_synced = true;
		if (init_pgd != NULL)
			sp->guest_kernel_synced = true;
		raw_all_irq_restore(flags);
		spin_unlock(&vcpu->kvm->mmu_lock);
		pt_index = pgd_index(MMU_UNITED_KERNEL_VPTB);
	} else {
		pt_index = pgd_index(vptb);
	}

	/* One PGD entry is the VPTB self-map. */
	new_root = (pgprot_t *)__va(root);
	kvm_vmlpt_kernel_spte_set(vcpu->kvm, &new_root[pt_index], new_root);
}

static inline void
mmu_pv_prepare_spt_u_root(struct kvm_vcpu *vcpu, gmm_struct_t *gmm, hpa_t root)
{
	pgd_t *new_pgd;
	pgprot_t *new_root, *src_root;
	kvm_mmu_page_t *sp;
	unsigned long flags;
	int pt_index;

	KVM_BUG_ON(!VALID_PAGE(root));

	/* copy kernel part of root page table entries to enable host */
	/* traps and hypercalls on guest */
	new_pgd = (pgd_t *)__va(root);
	copy_kernel_pgd_range(new_pgd, current->mm->pgd);

	src_root = (pgprot_t *)kvm_mmu_get_init_gmm_root(vcpu->kvm);
	KVM_BUG_ON(src_root == NULL);
	sp = page_header(root);
	copy_guest_kernel_root_range(vcpu, gmm, sp, src_root);

	/* create new host MMU context for guest user process */
	KVM_BUG_ON(pv_vcpu_is_init_gmm(vcpu, gmm));
	spin_lock(&vcpu->kvm->mmu_lock);
	raw_all_irq_save(flags);
	get_new_mmu_pid(&gmm->context, smp_processor_id());
	sp->root_flags.has_host_pgds = 1;
	sp->host_synced = true;
	sp->guest_kernel_synced = true;
	raw_all_irq_restore(flags);
	spin_unlock(&vcpu->kvm->mmu_lock);

	/* One PGD entry is the VPTB self-map. */
	pt_index = pgd_index(MMU_UNITED_KERNEL_VPTB);
	new_root = (pgprot_t *)__va(root);
	kvm_vmlpt_kernel_spte_set(vcpu->kvm, &new_root[pt_index], new_root);
}

static inline void
kvm_clear_shadow_root(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	pgd_t *pgd;
	int root_pt_index;
	pgd_t zero;

	if (unlikely(MMU_IS_SEPARATE_PT() || kvm->arch.is_hv))
		return;

	pgd = (pgd_t *)sp->spt;
	pgd_val(zero) = 0;

	if (likely(sp->root_flags.has_host_pgds)) {
		/* clear host kernel part of root page table entries */
		set_kernel_pgd_range(pgd, zero);
	}

	if (unlikely(sp->root_flags.has_guest_pgds)) {
		/* clear guest kernel part of root page table entries */
		set_guest_kernel_pgd_range(pgd, zero);
	} else {
		mmu_zap_linked_children(kvm, sp);
	}

	/* One PGD entry is the VPTB self-map. */
	root_pt_index = pgd_index(MMU_UNITED_KERNEL_VPTB);
	pgd[root_pt_index] = zero;
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
		KVM_BUG_ON(true);
	}
	return 0;
}

static inline bool pv_vcpu_is_init_root_hpa(struct kvm_vcpu *vcpu, hpa_t root)
{
	gmm_struct_t *init_gmm = pv_vcpu_get_init_gmm(vcpu);

	return root == init_gmm->root_hpa;
}

static inline void set_vcpu_mu_events_num(struct kvm_vcpu *vcpu, int events_num)
{
	KVM_BUG_ON(events_num <= vcpu->arch.intc_ctxt.mu_num);
	if (likely(vcpu->arch.is_hv || vcpu->arch.is_pv)) {
		vcpu->arch.intc_ctxt.mu_num = events_num;
	} else {
		KVM_BUG_ON(true);
	}
}

static inline void set_vcpu_mu_cur_event_no(struct kvm_vcpu *vcpu, int event_no)
{
	int events_num = get_vcpu_mu_events_num(vcpu);

	KVM_BUG_ON(events_num >= 0 && event_no > events_num);
	if (likely(vcpu->arch.is_hv || vcpu->arch.is_pv)) {
		vcpu->arch.intc_ctxt.cur_mu = event_no;
	} else {
		KVM_BUG_ON(true);
	}
}

static inline intc_mu_state_t *get_intc_mu_state(struct kvm_vcpu *vcpu)
{
	if (likely(vcpu->arch.is_hv || vcpu->arch.is_pv)) {
		int evn_no = vcpu->arch.intc_ctxt.cur_mu;
		return &vcpu->arch.intc_ctxt.mu_state[evn_no];
	} else {
		KVM_BUG_ON(true);
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

	return 0;
}

static inline void kvm_init_sw_ctxt(struct kvm_vcpu *vcpu)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	vcpu_boot_stack_t *boot_stacks = &vcpu->arch.boot_stacks;
	e2k_stacks_t *boot_regs = &boot_stacks->regs.stacks;
	e2k_mem_crs_t *crs = &boot_stacks->regs.crs;

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

	/* set pointer to CUTD area */
	if (vcpu->arch.is_pv) {
		sw_ctxt->cutd = kvm_get_guest_vcpu_CUTD(vcpu);
	} else {
		sw_ctxt->cutd.CUTD_reg = 0;
	}

	sw_ctxt->trap_count = 0;

	/* Initialize CLW context */
	sw_ctxt->us_cl_d = 1;
	sw_ctxt->us_cl_b = 0;
	sw_ctxt->us_cl_up = 0;
	sw_ctxt->us_cl_m0 = 0;
	sw_ctxt->us_cl_m1 = 0;
	sw_ctxt->us_cl_m2 = 0;
	sw_ctxt->us_cl_m3 = 0;
}
extern int kvm_hv_setup_nonpaging_mode(struct kvm_vcpu *vcpu);
extern int write_to_guest_pt_phys(struct kvm_vcpu *vcpu, gpa_t gpa,
				const pgprot_t *gpte, int bytes);
extern int kvm_mmu_unprotect_page_virt(struct kvm_vcpu *vcpu, gva_t gva);
extern void mmu_init_nonpaging_intc(struct kvm_vcpu *vcpu);
#else	/* ! CONFIG_KVM_HV_MMU */
static inline int kvm_arch_init_vm_mmu(struct kvm *kvm)
{
	return 0;
}
static inline int kvm_hv_setup_nonpaging_mode(struct kvm_vcpu *vcpu)
{
	KVM_BUG_ON(!is_paging(vcpu));
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

#ifdef	CONFIG_KVM_SHADOW_PT_ENABLE

extern int kvm_mmu_module_init(void);
extern void kvm_mmu_module_exit(void);

extern void kvm_mmu_destroy(struct kvm_vcpu *vcpu);
extern int kvm_mmu_create(struct kvm_vcpu *vcpu);
extern void kvm_mmu_setup(struct kvm_vcpu *vcpu);
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

extern int kvm_hv_setup_tdp_paging(struct kvm_vcpu *vcpu);
extern int kvm_hv_setup_shadow_paging(struct kvm_vcpu *vcpu, gmm_struct_t *gmm);
extern void mmu_get_spt_roots(struct kvm_vcpu *vcpu, unsigned flags,
			hpa_t *os_root_p, hpa_t *u_root_p, hpa_t *gp_root_p);
extern void mmu_check_invalid_roots(struct kvm_vcpu *vcpu, bool invalid,
					unsigned flags);

extern int kvm_switch_to_tdp_paging(struct kvm_vcpu *vcpu,
		gpa_t u_phys_ptb, gva_t u_virt_ptb,
		gpa_t os_phys_ptb, gva_t os_virt_ptb, gva_t os_virt_base);
extern gpa_t nonpaging_gva_to_gpa(struct kvm_vcpu *vcpu, gva_t vaddr,
				  u32 access, kvm_arch_exception_t *exception);
extern pgprot_t nonpaging_gpa_to_pte(struct kvm_vcpu *vcpu, gva_t addr);

static inline void
pv_vcpu_switch_to_init_spt(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	gmm_struct_t *init_gmm = pv_vcpu_get_init_gmm(vcpu);
	pgd_t *root;

	KVM_BUG_ON(gmm == init_gmm);
	root = kvm_mmu_get_gmm_root(init_gmm);
	kvm_set_space_type_spt_u_root(vcpu, (hpa_t)__pa(root));
	if (likely(!is_sep_virt_spaces(vcpu))) {
		kvm_set_space_type_guest_u_root(vcpu, init_gmm->u_pptb);
	} else {
		kvm_set_space_type_guest_os_root(vcpu, init_gmm->os_pptb);
	}
	kvm_set_vcpu_os_pt_context(vcpu);
}

static inline void kvm_mmu_unload_gmm_root(struct kvm_vcpu *vcpu)
{
	gmm_struct_t *cur_gmm;
	hpa_t u_root;

	cur_gmm = pv_vcpu_get_gmm(vcpu);
	if (pv_vcpu_is_init_gmm(vcpu, cur_gmm)) {
		/* current gmm is init_gmm, cannot be unliaded */
		return;
	}
	mmu_get_spt_roots(vcpu, U_ROOT_PT_FLAG, NULL, &u_root, NULL);
	KVM_BUG_ON(!VALID_PAGE(u_root));
	if (unlikely(pv_vcpu_is_init_root_hpa(vcpu, u_root))) {
		/* current root PT is guest kernel init PT, */
		/* cannot be unloaded */
		;
	} else {
		kvm_mmu_unload(vcpu, U_ROOT_PT_FLAG);
	}
	pv_vcpu_clear_gmm(vcpu);
	pv_vcpu_set_active_gmm(vcpu, pv_vcpu_get_init_gmm(vcpu));
	if (likely(!pv_vcpu_is_init_root_hpa(vcpu, u_root))) {
		pv_vcpu_switch_to_init_spt(vcpu, cur_gmm);
	}
}

static inline unsigned int kvm_mmu_available_pages(struct kvm *kvm)
{
	if (kvm->arch.n_max_mmu_pages > kvm->arch.n_used_mmu_pages)
		return kvm->arch.n_max_mmu_pages -
				kvm->arch.n_used_mmu_pages;

	return 0;
}

static inline int kvm_mmu_reload(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				 unsigned flags)
{
	mmu_check_invalid_roots(vcpu, true /* invalid ? */, flags);

	return kvm_mmu_load(vcpu, gmm, flags);
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
	KVM_BUG_ON(vcpu == NULL);
	if (unlikely(!vcpu->arch.mmu.shadow_pt_on))
		/* shadow PT is not yet enabled to use */
		return 0;
	ret = kvm_prefetch_mmu_area(vcpu, area_start, area_end,
				PFERR_PRESENT_MASK | PFERR_WRITE_MASK);
	return ret;
}

extern int kvm_pv_mmu_ptep_get_and_clear(struct kvm_vcpu *vcpu, gpa_t gpa,
				void __user *old_gpte, int as_valid);
extern int kvm_pv_mmu_pt_atomic_update(struct kvm_vcpu *vcpu, gpa_t gpa,
			void __user *old_gpte, pt_atomic_op_t atomic_op,
			unsigned long prot_mask);
extern void mmu_free_spt_root(struct kvm_vcpu *vcpu, hpa_t root_hpa);
extern void mmu_release_spt_root(struct kvm_vcpu *vcpu, hpa_t root_hpa);
extern int reexecute_load_and_wait_page_fault(struct kvm_vcpu *vcpu,
		trap_cellar_t *tcellar, gfn_t gfn, pt_regs_t *regs);
extern void release_gmm_root_pt(struct kvm_vcpu *vcpu, gmm_struct_t *gmm);

#else	/* ! CONFIG_KVM_SHADOW_PT_ENABLE */

static inline int kvm_mmu_module_init(void)
{
	return 0;
}
static inline void kvm_mmu_module_exit(void)
{
	return;
}

static inline void kvm_mmu_destroy(struct kvm_vcpu *vcpu)
{
	return;
}
static inline int kvm_mmu_create(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.gva_to_gpa = kvm_vcpu_gva_to_gpa;
	kvm_setup_paging_mode(vcpu);
	return 0;
}
static inline void kvm_mmu_setup(struct kvm_vcpu *vcpu)
{
	return;
}
static inline void kvm_mmu_init_vm(struct kvm *kvm)
{
	return;
}
static inline void kvm_mmu_uninit_vm(struct kvm *kvm)
{
	return;
}
static inline int
kvm_pv_switch_guest_mm(struct kvm_vcpu *vcpu,
		int gpid_nr, int gmmid_nr, gpa_t u_phys_ptb)
{
	KVM_BUG_ON(true);
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
	KVM_BUG_ON(!is_paging(vcpu));
	return __pgprot(0);
}
static inline gpa_t
nonpaging_gva_to_gpa(struct kvm_vcpu *vcpu, gva_t vaddr,
			u32 access, kvm_arch_exception_t *exception)
{
	return vaddr;
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
	KVM_BUG_ON(true);
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

extern int kvm_init_vcpu_root_pt(struct kvm_vcpu *vcpu);
extern void kvm_free_vcpu_root_pt(void);

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
extern int kvm_find_shadow_slot(struct kvm *kvm, int slot,
				e2k_addr_t kernel_addr, gva_t shadow_addr);
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

/*
 * Convert guest kernel address matching with host address to shadow
 * user address on host
 */
static inline void *kvm_get_guest_shadow_addr(void *src)
{
	thread_info_t *ti = native_current_thread_info();
	struct kvm_vcpu *vcpu = ti->vcpu;
	e2k_addr_t address = (e2k_addr_t)src;
	e2k_addr_t shadow_address;

	if (!test_ti_thread_flag(ti, TIF_PARAVIRT_GUEST) || !vcpu) {
		/* thread is not paravirtualized guest kernel */
		return NULL;
	}
	if (address < NATIVE_TASK_SIZE) {
		/* address is into guest kernel space area, */
		/* so do not search shadow */
		return NULL;
	}
	shadow_address = kvm_guest_kernel_addr_to_hva(vcpu, address);
	if (shadow_address == 0) {
		/* guest address has not host shadow address */
		return NULL;
	}
	return (void *)shadow_address;
}

static inline bool
kvm_is_shadow_addr_host_ttable(struct kvm *kvm, e2k_addr_t shadow_addr)
{
	kvm_kernel_shadow_t *shadow;
	e2k_addr_t ttable_start;
	e2k_addr_t ttable_end;
	e2k_addr_t kernel_base;
	e2k_addr_t shadow_base;
	e2k_addr_t shadow_end;
	int slot;

	DebugKVMSH("started for shadow addr 0x%lx\n", shadow_addr);
	ttable_start = PAGE_ALIGN_UP(KERNEL_TTABLE_BASE);
	ttable_end = PAGE_ALIGN_DOWN(KERNEL_TTABLE_END);

	slot = kvm_find_shadow_slot(kvm, 0, 0, shadow_addr);
	if (slot < 0) {
		DebugKVMSH("could not find shadow address 0x%lx at the list "
			"of guest shadow areas\n", shadow_addr);
		return false;
	}
	shadow = &kvm->arch.shadows[slot];
	kernel_base = shadow->kernel_start;
	shadow_base = shadow->shadow_start;
	DebugKVMSH("shadow address 0x%lx is found at the slot %d: host kernel "
		"base 0x%lx, shadow base 0x%lx\n",
		shadow_addr, slot, kernel_base, shadow_base);
	if (kernel_base != ttable_start)
		return false;
	shadow_end = shadow_base + (ttable_end - ttable_start);
	DebugKVMSH("host ttable shadow base 0x%lx end 0x%lx\n",
		shadow_base, shadow_end);
	if (shadow_addr >= shadow_base && shadow_addr < shadow_end)
		return true;
	return false;
}

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
	thread_info_t *ti = native_current_thread_info();
	int entries;
	int i;
	int ret = 0;

	if (dam_entries < DAM_ENTRIES_NUM)
		entries = dam_entries;
	else if (dam_entries > DAM_ENTRIES_NUM)
		entries = DAM_ENTRIES_NUM;
	else
		entries = dam_entries;
	NATIVE_SAVE_DAM(ti->dam);
	for (i = 0; i < dam_entries; i++)
		ret |= __put_user(ti->dam[i], &dam[i]);
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
