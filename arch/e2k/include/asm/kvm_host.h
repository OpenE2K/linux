/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This header defines architecture specific interfaces, e2k version
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef _ASM_E2K_KVM_HOST_H
#define _ASM_E2K_KVM_HOST_H

#include <linux/types.h>
#include <linux/bug.h>
#include <linux/interrupt.h> /* irq_handler_t */
#include <linux/list.h>
#include <linux/numa.h>

#include <asm/e2k_api.h>
#include <linux/kvm.h>
#include <linux/kvm_para.h>
#include <linux/kvm_types.h>
#include <asm/cpu_regs_types.h>
#include <asm/kvm/cpu_hv_regs_types.h>
#include <asm/kvm/mmu_hv_regs_types.h>
#include <asm/apicdef.h>
#include <asm/traps.h>
#include <asm/kvm/guest.h>
#include <asm/kvm/gpid.h>
#include <asm/kvm/mm.h>
#include <asm/kvm/thread_info.h>
#include <asm/kvm/threads.h>
#include <asm/kvm/csd_lock.h>
#include <asm/kvm/page_track.h>

#include <asm/kvm/boot_spinlock_slow.h>
#include <asm/kvm/spinlock_slow.h>

#define	KVM_E2K_DEBUG

#ifdef	KVM_E2K_DEBUG
#define	KVM_BUG_ON(__condition)		BUG_ON(__condition)
#else	/* ! KVM_E2K_DEBUG */
#define	KVM_BUG_ON(__condition)		BUILD_BUG_ON_INVALID(__condition)
#endif	/* KVM_E2K_DEBUG */

/* Avoid printk from arch-independent WARN_ON as
 * KVM implementation uses __interrupt functions */
#define KVM_WARN_ON(condition) ({					\
	int __ret_warn_on = !!(condition);				\
	if (unlikely(__ret_warn_on))					\
		__WARN();						\
	unlikely(__ret_warn_on);					\
})

#define	KVM_E2K_SV_VM_TYPE_MASK		(1 << KVM_E2K_SV_VM_TYPE)
#define	KVM_E2K_SW_PV_VM_TYPE_MASK	(1 << KVM_E2K_SW_PV_VM_TYPE)
#define	KVM_E2K_HV_VM_TYPE_MASK		(1 << KVM_E2K_HV_VM_TYPE)
#define	KVM_E2K_HW_PV_VM_TYPE_MASK	(1 << KVM_E2K_HW_PV_VM_TYPE)

/* mask of available and supported by the hypervisor VM types */
/* depends on hardware, CPU ISET, kernel & hypervisor configuration */
extern unsigned int kvm_vm_types_available;

/* atomic operations under mask values, for example kvm_vm_types_available */
static inline void atomic_clear_mask(unsigned int mask, unsigned int *value)
{
	__api_atomic_op(mask, value, w, "andns", RELAXED_MB);
}
static inline void atomic_set_mask(unsigned int mask, unsigned int *value)
{
	__api_atomic_op(mask, value, w, "ors", RELAXED_MB);
}
static inline void atomic64_clear_mask(unsigned long mask, unsigned long *value)
{
	__api_atomic_op(mask, value, d, "andnd", RELAXED_MB);
}
static inline void atomic64_set_mask(unsigned long mask, unsigned long *value)
{
	__api_atomic_op(mask, value, d, "ord", RELAXED_MB);
}

static inline bool
kvm_is_sv_vm_available(void)
{
	return kvm_vm_types_available & KVM_E2K_SV_VM_TYPE_MASK;
}
static inline bool
kvm_is_sw_pv_vm_available(void)
{
	return kvm_vm_types_available & KVM_E2K_SW_PV_VM_TYPE_MASK;
}
static inline bool
kvm_is_hv_vm_available(void)
{
	return kvm_vm_types_available & KVM_E2K_HV_VM_TYPE_MASK;
}
static inline bool
kvm_is_hw_pv_vm_available(void)
{
	return kvm_vm_types_available & KVM_E2K_HW_PV_VM_TYPE_MASK;
}

#define KVM_USER_MEM_SLOTS	32
/* memory slots that does not exposed to userspace */
#define KVM_PRIVATE_MEM_SLOTS	4

#undef E2K_INVALID_PAGE
#define E2K_INVALID_PAGE	(~(hpa_t)0)

#define UNMAPPED_GVA		(~(gpa_t)0)
#define	arch_is_error_gpa(gpa)	((gpa_t)(gpa) == UNMAPPED_GVA)

/*
 * See include/linux/kvm_host.h
 * For the normal pfn, the highest 12 bits should be zero,
 * so we can mask bit 62 ~ bit 52  to indicate the error pfn,
 * mask bit 63 to indicate the noslot pfn.
 * Some arch e2k extensions:
 * Bit 51 indicates NULL pagse
 */
#define KVM_PFN_NULL	(1ULL << 51)

/* number of page sizes supported by KVM */
/* KVM can now support pages on each page table level, real MMU capabilities */
/* are presenting by page table & page levels structures */
#define KVM_NR_PAGE_SIZES	MAX_HUGE_PAGES_LEVEL

#define KVM_PT_LEVEL_HPAGE_SHIFT(ptl)	get_pt_level_page_shift(ptl)
#define KVM_PT_LEVEL_HPAGE_SIZE(ptl)	get_pt_level_page_size(ptl)
#define KVM_PT_LEVEL_HPAGE_MASK(ptl)	get_pt_level_page_mask(ptl)
#define KVM_PT_LEVEL_PAGES_PER_HPAGE(ptl)	\
		(KVM_PT_LEVEL_HPAGE_SIZE(ptl) / PAGE_SIZE)
#define KVM_PT_LEVEL_HPAGE_GFN_SHIFT(ptl)	\
		(KVM_PT_LEVEL_HPAGE_SHIFT(ptl) - PAGE_SHIFT)

static inline gfn_t
gfn_to_index(gfn_t gfn, gfn_t base_gfn, const pt_level_t *pt_level)
{
	/* KVM_PT_LEVEL_HPAGE_GFN_SHIFT(PT_PAGE_TABLE_LEVEL) must be 0. */
	KVM_BUG_ON(!pt_level->is_pte && !pt_level->is_huge);
	return (gfn >> KVM_PT_LEVEL_HPAGE_GFN_SHIFT(pt_level)) -
			(base_gfn >> KVM_PT_LEVEL_HPAGE_GFN_SHIFT(pt_level));
}

#define E2K_INVALID_PAGE		(~(hpa_t)0)
#define	ERROR_PAGE(x)		IS_ERR_VALUE(x)
#define	TO_ERROR_PAGE(x)	((hpa_t)((long)(x)))
#define	PAGE_TO_ERROR(x)	((long)(x))
#define	IS_E2K_INVALID_PAGE(x)	((x) == E2K_INVALID_PAGE)
#define VALID_PAGE(x)		(!IS_E2K_INVALID_PAGE(x) && !ERROR_PAGE(x))

#define KVM_PERMILLE_MMU_PAGES	20
#define KVM_MIN_ALLOC_MMU_PAGES	64
#define KVM_MMU_HASH_SHIFT	10
#define KVM_NUM_MMU_PAGES	(1 << KVM_MMU_HASH_SHIFT)
#define KVM_MIN_FREE_MMU_PAGES	5
#define KVM_REFILL_PAGES	25

#define KVM_ALIAS_SLOTS		4

#define KVM_SHADOW_SLOTS	8

#define KVM_HALT_POLL_NS_DEFAULT 400000

#define KVM_IRQCHIP_NUM_PINS  KVM_IOEPIC_NUM_PINS

#define	KVM_MAX_EIOHUB_NUM	MAX_NUMNODES

#define ASYNC_PF_PER_VCPU 64

bool kvm_arch_can_inject_async_page_present(struct kvm_vcpu *vcpu);
void kvm_arch_async_page_ready(struct kvm_vcpu *vcpu,
				struct kvm_async_pf *work);

struct kvm_vcpu;
struct kvm;

extern struct mutex kvm_lock;
extern struct list_head vm_list;

enum kvm_reg {
	VCPU_REGS_UPSR = 0,
	NR_VCPU_REGS
};

enum {
	VCPU_SREG_USD_lo,
	VCPU_SREG_USD_hi,
	VCPU_SREG_PSP_lo,
	VCPU_SREG_PSP_hi,
	VCPU_SREG_PCSP_lo,
	VCPU_SREG_PCSP_hi,
	NR_VCPU_SREG
};

struct kvm_vcpu_stat {
	/* follow fields should have any arch and arch-independent updated */
	u32 halt_successful_poll;
	u32 halt_attempted_poll;
	u64 halt_poll_invalid;
	u32 halt_wakeup;
	/* MMU stat */
	u64 pf_fixed;
	u64 pf_guest;
	u64 flush_gva;
	u64 mmio_exits;
	u64 signal_exits;
};

/*
 * backup hardware stacks:
 *	1) to spill/fill guest stacks while intercept/glaunch
 *	2) to support hypercalls
 */
typedef struct bu_hw_stack {
	hw_stack_area_t	ps;		/* procedure stack area */
	hw_stack_area_t	pcs;		/* chain stack area */
	e2k_psp_lo_t	psp_lo;		/* Procedure stack pointer: */
	e2k_psp_hi_t	psp_hi;		/* base & index & size */
	e2k_pcsp_lo_t	pcsp_lo;	/* Procedure chain stack */
	e2k_pcsp_hi_t	pcsp_hi;	/* pointer: base & index & size */
	int		users;		/* number of active hypercalls, */
					/* handlers on these stacks */
} bu_hw_stack_t;

/* sizes as common kernel stacks */
#define	HYPV_BACKUP_PS_SIZE		KERNEL_P_STACK_SIZE
#define	HYPV_BACKUP_PCS_SIZE		KERNEL_PC_STACK_SIZE

#define GET_BACKUP_PS_SIZE(bu_stacks)	((bu_stacks)->ps.size)
#define GET_BACKUP_PCS_SIZE(bu_stacks)	((bu_stacks)->pcs.size)
#define SET_BACKUP_PS_SIZE(bu_stacks, val)	\
		(GET_BACKUP_PS_SIZE(bu_stacks) = (val))
#define SET_BACKUP_PCS_SIZE(bu_stacks, val)	\
		(GET_BACKUP_PCS_SIZE(bu_stacks) = (val))
#define	GET_BACKUP_PS_BASE(bu_stacks)	GET_PS_BASE(bu_stacks)
#define	GET_BACKUP_PCS_BASE(bu_stacks)	GET_PCS_BASE(bu_stacks)

/*
 * guest VCPU boot-time stacks
 */
typedef struct vcpu_boot_stack {
	data_stack_t	data;		/* local data stack */
	void		*data_stack;	/* data stack pointer at user space */
	hw_stack_area_t	ps;		/* procedure stack area */
	hw_stack_area_t	pcs;		/* chain stack area */
	void		*proc_stack;	/* procedure stack pointer at user */
					/* space */
	void		*chain_stack;	/* procedure chain stack pointer at */
					/* user space */
	guest_hw_stack_t regs;		/* current registers state */
} vcpu_boot_stack_t;

#define GET_VCPU_BOOT_CS_BASE(boot_stacks)	((boot_stacks)->data.bottom)
#define GET_VCPU_BOOT_CS_TOP(boot_stacks)	((boot_stacks)->data.top)
#define GET_VCPU_BOOT_CS_SIZE(boot_stacks)	((boot_stacks)->data.size)
#define	GET_VCPU_BOOT_PS_BASE(boot_stacks)	GET_PS_BASE(boot_stacks)
#define GET_VCPU_BOOT_PS_SIZE(boot_stacks)	((boot_stacks)->ps.size)
#define	GET_VCPU_BOOT_PCS_BASE(boot_stacks)	GET_PCS_BASE(boot_stacks)
#define GET_VCPU_BOOT_PCS_SIZE(boot_stacks)	((boot_stacks)->pcs.size)
#define SET_VCPU_BOOT_CS_BASE(boot_stacks, val)	\
		(GET_VCPU_BOOT_CS_BASE(boot_stacks) = (e2k_addr_t)(val))
#define SET_VCPU_BOOT_CS_TOP(boot_stacks, val)	\
		(GET_VCPU_BOOT_CS_TOP(boot_stacks) = (e2k_addr_t)(val))
#define SET_VCPU_BOOT_CS_SIZE(boot_stacks, val)	\
		(GET_VCPU_BOOT_CS_SIZE(boot_stacks) = (val))
#define SET_VCPU_BOOT_PS_BASE(boot_stacks, val)	\
		(GET_VCPU_BOOT_PS_BASE(boot_stacks) = (val))
#define SET_VCPU_BOOT_PS_SIZE(boot_stacks, val)	\
		(GET_VCPU_BOOT_PS_SIZE(boot_stacks) = (val))
#define SET_VCPU_BOOT_PCS_BASE(boot_stacks, val)	\
		(GET_VCPU_BOOT_PCS_BASE(boot_stacks) = (val))
#define SET_VCPU_BOOT_PCS_SIZE(boot_stacks, val)	\
		(GET_VCPU_BOOT_PCS_SIZE(boot_stacks) = (val))

struct kvm_vm_stat {
	ulong mmu_shadow_zapped;
	ulong mmu_pte_write;
	ulong mmu_pte_updated;
	ulong mmu_pde_zapped;
	ulong mmu_flooded;
	ulong mmu_recycled;
	ulong mmu_cache_miss;
	ulong mmu_unsync;
	ulong remote_tlb_flush;
	ulong lpages;
};

/*
 * Don't want allocation failures within the mmu code, so need preallocate
 * enough memory for a single page fault in a cache.
 */
#define	KVM_NR_MEM_OBJS		400
#define	KVM_NR_MIN_MEM_OBJS	40

typedef struct kvm_mmu_memory_cache {
	struct kmem_cache *kmem_cache;
	int nobjs;
	void *objects[KVM_NR_MEM_OBJS];
} kvm_mmu_memory_cache_t;

/*
 * the pages used as guest page table on soft mmu are tracked by
 * kvm_memory_slot.arch.gfn_track which is 16 bits, so the role bits used
 * by indirect shadow page can not be more than 15 bits.
 *
 * Currently, we used 14 bits that are @level, @cr4_pae, @quadrant, @access,
 * @nxe, @cr0_wp, @smep_andnot_wp and @smap_andnot_wp.
 */
typedef union kvm_mmu_page_role {
	unsigned word;
	struct {
		unsigned level:4;
		unsigned cr4_pae:1;
		unsigned quadrant:2;
		unsigned direct:1;
		unsigned access:3;
		unsigned invalid:1;
		unsigned nxe:1;
		unsigned cr0_wp:1;
		unsigned smep_andnot_wp:1;
		unsigned smap_andnot_wp:1;
		unsigned unused:8;

		/*
		 * This is left at the top of the word so that
		 * kvm_memslots_for_spte_role can extract it with a
		 * simple shift.  While there is room, give it a whole
		 * byte so it is also faster to load it from memory.
		 */
		unsigned smm:8;
	};
} kvm_mmu_page_role_t;

typedef union kvm_mmu_root_flags {
	unsigned word;
	struct {
		unsigned has_host_pgds:1;
		unsigned has_guest_pgds:1;
		unsigned unused:30;
	};
} kvm_mmu_root_flags_t;

typedef struct kvm_rmap_head {
	unsigned long val;
} kvm_rmap_head_t;

typedef struct kvm_mmu_page {
	struct list_head link;
	struct hlist_node hash_link;

	/*
	 * The following two entries are used to key the shadow page in the
	 * hash table.
	 */
	gfn_t gfn;
	kvm_mmu_page_role_t role;
	kvm_mmu_root_flags_t root_flags;

	pgprot_t *spt;
	gva_t gva;	/* the shadow PT map guest virtual addresses from */
	/* hold the gfn of each spte inside spt */
	gfn_t *gfns;
	bool unsync;
	bool host_synced;		/* host kernel range already synced */
	bool guest_kernel_synced;	/* guest kernel range already synced */
	bool guest_user_synced;		/* guest user range synced */
	bool released;			/* root already under release */
	atomic_t atomic_unsync;	/* there are atomicaly updated of PT entries */
	int root_count;          /* Currently serving as active root */
	unsigned int unsync_children;
	struct kvm_rmap_head parent_ptes; /* rmap pointers to parent sptes */

	/* The page is obsolete if mmu_valid_gen != kvm->arch.mmu_valid_gen.  */
	unsigned long mmu_valid_gen;

	DECLARE_BITMAP(unsync_child_bitmap, 512);

#ifdef CONFIG_X86_32
	/*
	 * Used out of the mmu-lock to avoid reading spte values while an
	 * update is in progress; see the comments in __get_spte_lockless().
	 */
	int clear_spte_count;
#endif

	/* Number of writes since the last time traversal visited this page.  */
	atomic_t write_flooding_count;
#ifdef	CONFIG_GUEST_MM_SPT_LIST
	struct list_head gmm_entry;	/* entry at the gmm list of SPs */
	gmm_struct_t *gmm;		/* the gmm in whose list the entry */
#endif	/* CONFIG_GUEST_MM_SPT_LIST */
} kvm_mmu_page_t;

/* page fault handling results */
typedef enum pf_res {
	PFRES_NO_ERR = 0,
	PFRES_WRITE_TRACK,
	PFRES_INJECTED,
	PFRES_TRY_MMIO,
	PFRES_ERR,
	PFRES_RETRY,		/* page fault is not handled and can */
				/* be retried on guest or should be handled */
				/* from begining by hypervisor */
} pf_res_t;

struct kvm_arch_exception;

/*
 * e2k supports 2 types of virtual space:
 *	- primary (native);
 *	- secondary (x86 emulation).
 * enable 3 paging modes:
 *	- 4-level 64-bit, primary and secondary;
 *	- 3-level 64-bit, only secondary;
 *	- 2-level 32-bit, only secondary.
 * Primary (native) virtual space can be managed as:
 *	- common linux standard: user and OS share single virtual space. In this
 *	  case there is one united PT to translate user and kernel addresses and
 *	  one PT root pointed to by MMU registers U_PPTB/U_VPTB;
 *	- separate user and OS virtual spaces: there are two separate PTs
 *	  to translate user and kernel addresses and two separate PTs roots
 *	  pointed to by MMU registers U_PPTB/U_VPTB (for users) and
 *	  OS_PPTB/OS_VPTB (for kernel).
 *
 * The kvm_mmu structure abstracts the details of the current mmu mode.
 */
typedef struct kvm_mmu {
	hpa_t	sh_u_root_hpa;	/* shadow PT root for user (and probably OS) */
	hpa_t	sh_os_root_hpa;	/* shadow PT root for OS (separate spoaces) */
	hpa_t	gp_root_hpa;	/* physical base of root PT to translate */
				/* guest physical addresses */
	gva_t	sh_u_vptb;	/* shadow base address to map user */
				/* (and probably OS) PTs to virtual space */
	gva_t	sh_os_vptb;	/* shadow base address to map kernel */
				/* (separate spaces) PTs to virtual space */
	gva_t	sh_os_vab;	/* common hypervisor and guest pointer to */
				/* border of user and OS spaces */
	hpa_t	sh_root_hpa;
	bool	sep_virt_space;	/* separate virtual spaces for OS and user */
	bool	direct_map;
	bool	is_spae;	/* extended physical memory is enabled */
	bool	is_pse;		/* 4 Mb pages is enable for secondary space */
	bool	paging_on;	/* virtual space translation mode is ON */
	bool	shadow_pt_on;	/* shadow PT mode is enabled */
	bool	phys_pt_on;	/* guest physical addresses PT is ON */
	bool	tdp_on;		/* two dimensional paging is ON */
	bool	spt_gpa_fault;	/* guest physical address access fault */
				/* at shodow paging mode */
	bool	nx;		/* not executable is ??? */
	bool	u_context_on;	/* guest user MMU context created and is ON */
	int	pid;		/* guest process ID (mmu context) */
	int	pid2;		/* guest process ID at secondary space */
	int	root_level;
	int	shadow_root_level;
	kvm_mmu_page_role_t base_role;
	u64		*pae_root;
	u64		*lm_root;
	/* guest PT roots pointers */
	pgprotval_t	os_pptb;	/* guest OS primary (native) */
					/* page table physical base of VCPU */
	gva_t		os_vptb;	/* guest OS primary (native) */
					/* page table virtual base of VCPU */
	pgprotval_t	u_pptb;		/* guest user primary (native) */
					/* page table physical base of VCPU */
	gva_t		u_vptb;		/* guest user primary (native) */
					/* page table virtual base of VCPU */
	pgprotval_t	u2_pptb;	/* guest secondary page table */
					/* physical base of VCPU */
	gpa_t		mpt_b;		/* guest protection table base */
					/* of VCPU */
	pgprotval_t	pdptes[4];	/* current root level PTEs registers */
					/* of VCPU for extended physical */
					/* address mode (SPAE) */
	gpa_t		tc_gpa;		/* guest 'physical address' of */
					/* trap cellar (TRAP_POINT MMU reg.) */
	struct page	*tc_page;	/* host page of guest trap cellar */
	void		*tc_kaddr;	/* host virtual address of guest */
					/* trap cellar */
	int		tc_num;		/* number of entries at trap cellar */
					/* same as TRAP_COUNT / 3 */
	gmm_struct_t	*gmm;		/* host agent of current guest mm */
	gmm_struct_t	*active_gmm;	/* only on host: current active */
					/* guest mm agent on host (same as */
					/* active_mm at native mode) */

	/* MMU interceptions control registers state */
	virt_ctrl_mu_t	virt_ctrl_mu;
	mmu_reg_t	g_w_imask_mmu_cr;

	/* MMU shadow control registers initial state */
	mmu_reg_t	init_sh_mmu_cr;
	mmu_reg_t	init_sh_pid;

	/* Can have large pages at levels 2..last_nonleaf_level-1. */
	u8	last_nonleaf_level;

	/* MMU interface */
	bool (*is_paging)(struct kvm_vcpu *vcpu);
	void (*set_vcpu_u_pptb)(struct kvm_vcpu *vcpu, pgprotval_t base);
	void (*set_vcpu_sh_u_pptb)(struct kvm_vcpu *vcpu, hpa_t root);
	void (*set_vcpu_os_pptb)(struct kvm_vcpu *vcpu, pgprotval_t base);
	void (*set_vcpu_sh_os_pptb)(struct kvm_vcpu *vcpu, hpa_t root);
	void (*set_vcpu_u_vptb)(struct kvm_vcpu *vcpu, gva_t base);
	void (*set_vcpu_sh_u_vptb)(struct kvm_vcpu *vcpu, gva_t base);
	void (*set_vcpu_os_vptb)(struct kvm_vcpu *vcpu, gva_t base);
	void (*set_vcpu_sh_os_vptb)(struct kvm_vcpu *vcpu, gva_t base);
	void (*set_vcpu_os_vab)(struct kvm_vcpu *vcpu, gva_t os_virt_base);
	void (*set_vcpu_gp_pptb)(struct kvm_vcpu *vcpu, hpa_t root);
	pgprotval_t (*get_vcpu_u_pptb)(struct kvm_vcpu *vcpu);
	hpa_t (*get_vcpu_sh_u_pptb)(struct kvm_vcpu *vcpu);
	pgprotval_t (*get_vcpu_os_pptb)(struct kvm_vcpu *vcpu);
	hpa_t (*get_vcpu_sh_os_pptb)(struct kvm_vcpu *vcpu);
	gva_t (*get_vcpu_u_vptb)(struct kvm_vcpu *vcpu);
	gva_t (*get_vcpu_sh_u_vptb)(struct kvm_vcpu *vcpu);
	gva_t (*get_vcpu_os_vptb)(struct kvm_vcpu *vcpu);
	gva_t (*get_vcpu_sh_os_vptb)(struct kvm_vcpu *vcpu);
	gva_t (*get_vcpu_os_vab)(struct kvm_vcpu *vcpu);
	hpa_t (*get_vcpu_gp_pptb)(struct kvm_vcpu *vcpu);
	void (*set_vcpu_pt_context)(struct kvm_vcpu *vcpu, unsigned flags);
	void (*init_vcpu_ptb)(struct kvm_vcpu *vcpu);
	pgprotval_t (*get_vcpu_context_u_pptb)(struct kvm_vcpu *vcpu);
	gva_t (*get_vcpu_context_u_vptb)(struct kvm_vcpu *vcpu);
	pgprotval_t (*get_vcpu_context_os_pptb)(struct kvm_vcpu *vcpu);
	gva_t (*get_vcpu_context_os_vptb)(struct kvm_vcpu *vcpu);
	gva_t (*get_vcpu_context_os_vab)(struct kvm_vcpu *vcpu);
	hpa_t (*get_vcpu_context_gp_pptb)(struct kvm_vcpu *vcpu);
	pgprotval_t (*get_vcpu_pdpte)(struct kvm_vcpu *vcpu, int index);
	pf_res_t (*page_fault)(struct kvm_vcpu *vcpu, gva_t gva, u32 err,
			  bool prefault, gfn_t *gfn, kvm_pfn_t *pfn);
	void (*inject_page_fault)(struct kvm_vcpu *vcpu,
				  struct kvm_arch_exception *fault);
	gpa_t (*gva_to_gpa)(struct kvm_vcpu *vcpu, gva_t gva, u32 access,
			    struct kvm_arch_exception *exception);
	gpa_t (*translate_gpa)(struct kvm_vcpu *vcpu, gpa_t gpa, u32 access,
			       struct kvm_arch_exception *exception);
	void (*update_pte)(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
			   pgprot_t *spte, const void *pte);
	void (*sync_gva)(struct kvm_vcpu *vcpu, gva_t gva);
	void (*sync_gva_range)(struct kvm_vcpu *vcpu, gva_t gva_start,
					gva_t gva_end, bool flush_tlb);
	int (*sync_page)(struct kvm_vcpu *vcpu, kvm_mmu_page_t *sp);
} kvm_mmu_t;

typedef struct intc_mu_state {
	unsigned long notifier_seq;	/* 'mmu_notifier_seq' state before */
					/* gfn->pfn translation */
	pf_res_t pfres;			/* page fault handling result */
	bool may_be_retried;		/* the MMU request can be retied */
	bool ignore_notifier;		/* the MMU request should ignore the
					 * MMU notifier status */
} intc_mu_state_t;

/* define exit reasons (requests) from guest to host */
#define EXIT_REASON_VM_PANIC	0
#define EXIT_REASON_MMIO_REQ	1
#define EXIT_REASON_IOPORT_REQ	2

#define	EXIT_NOTIFY_IO		3

#define	EXIT_SHUTDOWN		4

typedef struct kvm_ioport_req {
	uint64_t port;
	uint64_t data;		/* single data or guest address of string */
	u32 __user *user_data;	/* user pointer to data */
	uint32_t count;
	uint32_t cur_count;
	uint8_t size;
	uint8_t is_out;
	uint8_t	string;
	uint8_t needed;
	uint8_t completed;
} kvm_ioport_req_t;

typedef struct kvm_lapic_irq {
	u32 vector;
	u32 delivery_mode;
	u32 dest_mode;
	u32 level;
	u32 trig_mode;
	u32 shorthand;
	u32 dest_id;
} kvm_lapic_irq_t;

/*
 * Unlike kvm_lapic_irq, CEPIC doesn't have dest_mode (physical/logical)
 * and level (polarity) fields
 */
typedef struct kvm_cepic_irq {
	u32 vector;
	u32 delivery_mode;
	u32 trig_mode;
	u32 shorthand;
	u32 dest_id;
} kvm_cepic_irq_t;

typedef struct kvm_mem_alias {
	unsigned long alias_start;
	unsigned long target_start;
	gfn_t alias_base_gfn;
	unsigned long npages;
	u32 target_slot;
} kvm_mem_alias_t;

typedef struct kvm_kernel_shadow {
	unsigned long kernel_start;
	unsigned long shadow_start;
	unsigned long area_size;
	u32 alias_slot;
} kvm_kernel_shadow_t;

struct user_area_t;

typedef struct kvm_mem_guest {
	struct user_area	*area;
	kvm_guest_mem_type_t	type;	/* type of memory: RAM, VRAM */
} kvm_mem_guest_t;

/*
 * Delivery modes of Virtual IRQs (see field 'flags' below)
 */
#define	DIRECT_INJ_VIRQ_FLAG	0x0010UL	/* direct injection of VIRQ */
						/* to VCPU process */
typedef struct kvm_guest_virq {
	int virq_id;			/* VIRQ number */
	atomic_t *count;		/* pointer to atomic counter */
					/* of unhandled VIRQs */
	unsigned long flags;		/* delivery mode and other flags of */
					/* virtual IRQ (see above) */
	struct kvm_vcpu *vcpu;		/* Virtual guest CPU to handle VIRQ */
	struct task_struct *host_task;	/* host task structure of VIRQ */
	int stop_handler;		/* VIRQ handler should be stopped */
} kvm_guest_virq_t;

/*
 * Context that is saved and restored by software when
 * switching from hypervisor to guest or vice versa.
 */
typedef struct kvm_sw_cpu_context {
	int osem;
	bool in_hypercall;

	e2k_usd_lo_t usd_lo;
	e2k_usd_hi_t usd_hi;
	e2k_sbr_t sbr;

	struct to_save {
		bool valid;
		e2k_usd_lo_t usd_lo;
		e2k_usd_hi_t usd_hi;
		e2k_sbr_t sbr;
	} saved;

	/*
	 * Host VCPU local data stack pointer registers state (to save/restore).
	 * It is relevant only for paravirtualization, since in this case
	 * there is one VCPU process, but there are two mode of its execution:
	 *	as host part of VCPU (qemu)
	 *	as guest part of VCPU
	 * and, accordingly, two stacks: host & guest.
	 */
	e2k_usd_lo_t host_usd_lo;
	e2k_usd_hi_t host_usd_hi;
	e2k_sbr_t host_sbr;

	e2k_mem_crs_t	crs;	/* only for PV guest */

	/*
	 * TODO here goes stuff that can be not switched
	 * on hypercalls if we do not support calling QEMU from them
	 */
	e2k_fpcr_t fpcr;
	e2k_fpsr_t fpsr;
	e2k_pfpfr_t pfpfr;

	e2k_upsr_t upsr;

#ifdef	CONFIG_GREGS_CONTEXT
	/*
	 * Guest has own global registers context (vcpu) different
	 * from QEMU (host).
	 * The VCPU (guest) context should be restored while vcpu_load()
	 * after saving the host (QEMU) context and be saved while vcpu_put()
	 * before restoring the host (QEMU) context.
	 * Only one current VCPU or host context should be saved and restored
	 * while switch to/from other processes.
	 */
	global_regs_t vcpu_gregs;
	global_regs_t host_gregs;
	kernel_gregs_t vcpu_k_gregs;
	kernel_gregs_t host_k_gregs;
	host_gregs_t vcpu_h_gregs;
	host_gregs_t host_h_gregs;
#endif	/* CONFIG_GREGS_CONTEXT */

	e2k_cutd_t cutd;

	/* guest (hypervisor shadow) user page table bases: */
	mmu_reg_t	sh_u_pptb;	/* physical */
	mmu_reg_t	sh_u_vptb;	/* and virtual */
	mmu_reg_t	tc_hpa;		/* host physical base of VCPU */
					/* trap cellar */
	mmu_reg_t	trap_count;

	e2k_dibcr_t	dibcr;
	e2k_ddbcr_t	ddbcr;
	e2k_dibsr_t	dibsr;
	e2k_ddbsr_t	ddbsr;
	e2k_dimcr_t	dimcr;
	e2k_ddmcr_t	ddmcr;
	u64		dimar0;
	u64		dimar1;
	u64		ddmar0;
	u64		ddmar1;
	u64		dibar0;
	u64		dibar1;
	u64		dibar2;
	u64		dibar3;
	u64		ddbar0;
	u64		ddbar1;
	u64		ddbar2;
	u64		ddbar3;

#ifdef CONFIG_USE_AAU
	e2k_aau_t aau_context;
#endif

	u64 cs_lo;
	u64 cs_hi;
	u64 ds_lo;
	u64 ds_hi;
	u64 es_lo;
	u64 es_hi;
	u64 fs_lo;
	u64 fs_hi;
	u64 gs_lo;
	u64 gs_hi;
	u64 ss_lo;
	u64 ss_hi;
	u64 rpr_lo;
	u64 rpr_hi;
	u64 tcd;

	mmu_reg_t us_cl_d;
	clw_reg_t us_cl_b;
	clw_reg_t us_cl_up;
	clw_reg_t us_cl_m0;
	clw_reg_t us_cl_m1;
	clw_reg_t us_cl_m2;
	clw_reg_t us_cl_m3;
} kvm_sw_cpu_context_t;

/*
 * Context that is saved and restored by software _only_ for
 * interceptions when switching from hypervisor to guest or vice versa.
 */
typedef struct kvm_intc_cpu_context {
	e2k_ctpr_t	ctpr1;
	e2k_ctpr_t	ctpr2;
	e2k_ctpr_t	ctpr3;
	e2k_ctpr_hi_t	ctpr1_hi;
	e2k_ctpr_hi_t	ctpr2_hi;
	e2k_ctpr_hi_t	ctpr3_hi;
	u64		lsr;
	u64		ilcr;
	u64		lsr1;
	u64		ilcr1;

	int cu_num, mu_num;
	int cur_mu;		/* # of current MMU intercept in handling */
	intc_info_cu_t cu;
	intc_info_mu_t mu[INTC_INFO_MU_ITEM_MAX];
	intc_mu_state_t mu_state[INTC_INFO_MU_ITEM_MAX];
	bool mu_updated;	/* the mu info was updated, so need restote */
				/* on the registers */
	bool cu_updated;	/* the cu info was updated, so need restore */
				/* on the registers */
	s8 nr_TIRs;
	u64 exceptions;		/* source mask of all exceptions in the TIRs */
				/* at the interception moment */
				/* should be the same as INTC_INFO_CU.hi.exc */
	u64 exc_to_create;	/* mask of the new exceptions to add at TIRs */
	u64 exc_to_delete;	/* mask of the exceptions to delete from TIRs */
	u64 exc_to_pass;	/* mask of the exceptions from source */
				/* TIRs exceptions to pass to the guest */
	gva_t exc_IP_to_create;	/* IP to create exceptions like instruction */
				/* page faults */
	e2k_tir_t TIRs[TIR_NUM];
	u64 sbbp[SBBP_ENTRIES_NUM];
	u64 intc_mu_to_move;
	u64 cu_entry_handled;
} kvm_intc_cpu_context_t;

struct kvm_epic_page;

/*
 * here goes context that is:
 *  - saved and restored by hardware when switching
 *    from hypervisor to guest or vice versa.
 *  - belongs only to guest and isn't used by hypervisor
 *
 * Then this context is:
 * 1) Initialized by hypervisor in init_hw_ctxt()
 * 2) Written to actual registers for the first time
 *    in write_hw_ctxt_to_registers()
 * 3) Switched in save/restore_kvm_context_v6()
 */
typedef struct kvm_hw_cpu_context {
	e2k_psp_lo_t sh_psp_lo;
	e2k_psp_hi_t sh_psp_hi;
	e2k_pcsp_lo_t sh_pcsp_lo;
	e2k_pcsp_hi_t sh_pcsp_hi;
	e2k_pshtp_t sh_pshtp;
	e2k_pcshtp_t sh_pcshtp;
	e2k_wd_t sh_wd;
	e2k_psp_lo_t bu_psp_lo;
	e2k_psp_hi_t bu_psp_hi;
	e2k_pcsp_lo_t bu_pcsp_lo;
	e2k_pcsp_hi_t bu_pcsp_hi;

	mmu_reg_t sh_mmu_cr;
	mmu_reg_t sh_pid;
	mmu_reg_t sh_os_pptb;
	mmu_reg_t gp_pptb;
	mmu_reg_t sh_os_vptb;
	mmu_reg_t sh_os_vab;
	mmu_reg_t gid;

	e2k_oscud_lo_t sh_oscud_lo;
	e2k_oscud_hi_t sh_oscud_hi;
	e2k_osgd_lo_t sh_osgd_lo;
	e2k_osgd_hi_t sh_osgd_hi;
	e2k_cutd_t sh_oscutd;
	e2k_cuir_t sh_oscuir;
	u64 sh_osr0;
	e2k_core_mode_t sh_core_mode;

	virt_ctrl_cu_t virt_ctrl_cu;
	virt_ctrl_mu_t virt_ctrl_mu;
	mmu_reg_t g_w_imask_mmu_cr;

	struct kvm_epic_page *cepic;

	/* Secondary space registers */
	u64 u2_pptb;
	u64 pid2;
	u64 mpt_b;
	u64 pci_l_b;
	u64 ph_h_b;
	u64 ph_hi_l_b;
	u64 ph_hi_h_b;
	u64 pat;
	u64 pdpte0;
	u64 pdpte1;
	u64 pdpte2;
	u64 pdpte3;
} kvm_hw_cpu_context_t;

/*
 * The structure needs only for paravitualized guest mode:
 *	!vcpu->arch.is_hv && vcpu->arch.is_pv
 *
 * Hypervisor context which should be different for host VCPU thread (qemu)
 * and guest VCPUs threads to allow running the VCPU kernel thread as
 * multi-threading.
 * The one VCPY kernel thread is running the one of the following processes:
 *	the host application qemu (or some other to control VM);
 *	the guest kernel threads;
 *	the guest user threads;
 * This structure is to save/restore and switch from/to the one host VCPU thread
 * and many guest threads.
 * If the host thread is now active then the thread info contains this active
 * context and vcpu->arch.host_ctxt contains context of last running guest
 * thread.
 * If the guest thread is active then the thread_info contains context of this
 * active guest thread and the structure vcpu->arch.host_ctxt contains context
 * of the host thread.
 * Contexts of not active guest threads were saved/restored at the such
 * structures into its gthread_info
 */
typedef struct kvm_host_context {
	/* the task->stack ponter */
	unsigned long	*stack;
	/* the host kernel's stack of local data */
	/* one for host thread and one common for all guest threads */
	e2k_usd_hi_t	k_usd_hi;
	e2k_usd_lo_t	k_usd_lo;
	e2k_sbr_t	k_sbr;
	/* the host kernel's hardware stacks */
	/* one for host thread and one common for all guest threads */
	e2k_psp_lo_t	k_psp_lo;
	e2k_psp_hi_t	k_psp_hi;
	e2k_pcsp_lo_t	k_pcsp_lo;
	e2k_pcsp_hi_t	k_pcsp_hi;

	/* pointer to the top of 'pt_regs' structures list */
	pt_regs_t	*pt_regs;
	/* some additional items of processes context */
	e2k_upsr_t	upsr;	/* user UPSR register state */
	unsigned	osem;	/* OSEM register state */
	/* the host kernel's signal/trap stack of contexts */
	kvm_signal_context_t signal;
} kvm_host_context_t;

#ifdef CONFIG_KVM_ASYNC_PF
struct kvm_apf_ready {
	struct list_head link;
	u32 apf_id;
};
#endif /* CONFIG_KVM_ASYNC_PF */

struct kvm_vcpu_arch {
	kvm_sw_cpu_context_t	sw_ctxt;
	kvm_intc_cpu_context_t	intc_ctxt;
	kvm_hw_cpu_context_t	hw_ctxt;
	kvm_host_context_t	host_ctxt;

	int launched;
	int last_exit;
	bool is_pv;			/* VCPU is under paravirtualized */
					/* support */
	bool is_hv;			/* VCPU is under hardware virtualized */
					/* support */
	/* host switch to vcpu-host mode from host interception emulation mode */
	/* (trap or system call on PV mode) */
	bool from_pv_intc;

	kvm_vcpu_state_t *vcpu_state;
	kvm_vcpu_state_t *kmap_vcpu_state;	/* alias of VCPU state */
						/* mapped into kernel VM */
						/* space */
	e2k_cute_t *guest_cut;
	e2k_addr_t guest_phys_base;	/* guest image (kernel) physical base */
	char *guest_base;		/* guest image (kernel) virtual base */
	e2k_size_t guest_size;		/* guest image (kernel) size */
	e2k_size_t trap_offset;		/* guest trap table #0 entry offset */
					/* from guest image base */
	char *trap_entry;		/* guest trap table #0 base as entry */
					/* to paravirtualized trap handler */

	bu_hw_stack_t hypv_backup;	/* backup hardware stacks */
	vcpu_boot_stack_t boot_stacks;	/* guest boot-time stacks */
	guest_hw_stack_t guest_stacks;	/* guest hardware stacks state */
					/* to emulate harware supported */
					/* HCALLs */
	gthread_info_t *gti;		/* host agent of current active guest */
					/* thread/process */

	/*
	 * Paging state of the vcpu
	 * This context is always used to handle faults.
	 */
	kvm_mmu_t mmu;

	/*
	 * Pointer to the mmu context currently used for
	 * gva_to_gpa translations.
	 */
	kvm_mmu_t *walk_mmu;

	kvm_mmu_memory_cache_t mmu_pte_list_desc_cache;
	kvm_mmu_memory_cache_t mmu_page_cache;
	kvm_mmu_memory_cache_t mmu_page_header_cache;

	/* FIXME: Cache MMIO info is not fully implemented */
	u64 mmio_gva;
	unsigned access;
	gfn_t mmio_gfn;
	u64 mmio_gen;
	u64 mmio_data[1];
	u64 __user *mmio_user_data;
	intc_info_mu_t *io_intc_info;

	/*
	 * Indicate whether the access faults on its page table in guest
	 * which is set when fix page fault and used to detect unhandeable
	 * instruction.
	 * FIXME: it is field from x86 arch, so does it need for e2k???
	 */
	bool write_fault_to_shadow_pgtable;

	u64 apic_base;
	struct kvm_lapic *apic;		/* kernel irqchip context */
	int32_t apic_arb_prio;

	/* Software KVM CEPIC model */
	u64 epic_base;
	struct kvm_cepic *epic;

	/* Hardware guest CEPIC support */
	raw_spinlock_t epic_dam_lock;	/* lock to update dam_active */
	bool epic_dam_active;
	struct hrtimer cepic_idle;

	int mp_state;
	int sipi_vector;
	struct task_struct *guest_task;	/* guest task */
	struct task_struct *host_task;	/* host task: main VCPU host */
					/* or VIRQ VCPU host for VIRQ VCPUs */
	struct mutex lock;		/* host and guest part of VCPU */
					/* including VIRQ VCPUs */
					/* synchronization */
	struct list_head vcpus_to_spin;	/* list of VCPUs to support boot-time */
					/* spin lock/unlock */
	bool unhalted;			/* VCPU was woken up by pv_kick */
	bool halted;			/* VCPU is halted */
	bool on_idle;			/* VCPU is on idle waiting for some */
					/* events for guest */
	bool on_spinlock;		/* VCPU is on slow spinlock waiting */
	bool on_csd_lock;		/* VCPU is waiting for csd unlocking */
					/* (IPI completion) */
	bool should_stop;		/* guest VCPU thread should be */
					/* stopped and completed */
	bool virq_wish;			/* trap 'last wish' is injection to */
					/* pass pending VIRQs to guest */
	bool virq_injected;		/* interrupt is injected to handle */
					/* pending VIRQs by guest */
	bool on_virqs_handling;		/* VCPU is handling pending VIRQs */
	bool vm_exit_wish;		/* VCPU is need to VM exit and */
					/* exit reason handling */
	bool trap_wish;			/* VCPU is need to inject traps */
	bool hcall_irqs_disabled;	/* VCPU entered HCALL with disabled interrupts */
	unsigned long trap_mask_wish;	/* mask of traps to wish */
	struct completion exited;	/* guest VCPU thread completed */
	struct completion released;	/* all VCPU threads completed and */
					/* VCPU can be freed */
	struct hrtimer hrt;		/* local timer of VCPU */
	int hrt_virq_no;		/* number of VIRQ of local timer */
	long hrt_period;		/* period of hr timer */
	long hrt_running_start;		/* VCPU running time when timer */
					/* was started */

	char *entry_point;	/* startup point of guest image */
	int args_num;		/* arguments number to pass to guest */
	u64 args[KVM_VCPU_MAX_GUEST_ARGS];	/* arguments to pass */

	/* Exit data for guest */
	uint32_t exit_reason;
	kvm_ioport_req_t ioport;	/* IO port access (in()/out()) */
	void *ioport_data;		/* pointer to IO port data at */
					/* kvm_run page (now middle) */
	int64_t ioport_data_size;	/* max size of IO port data area */
	uint32_t notifier_io;		/* IO request notifier */

	bool in_exit_req;			/* VCPU is waiting for exit */
						/* request completion */
						/* exit request in progress */
	struct completion exit_req_done;	/* exit request is completed */

	struct list_head exit_reqs_list;	/* exit requests list head */
						/* used only on main VCPU */
	struct list_head exit_req;		/* the VCPU exit request */
	raw_spinlock_t exit_reqs_lock;		/* to lock list of exit */
						/* requests */

	struct work_struct dump_work;		/* to schedule work to dump */
						/* guest VCPU state */

	u8 event_exit_inst_len;

	uint32_t  exit_shutdown_terminate;

#ifdef CONFIG_KVM_ASYNC_PF
	struct {
		bool enabled;
		struct gfn_to_hva_cache reason_gpa; /* hva of guest per-cpu */
						/* pv_apf_event.apf_reason */
		struct gfn_to_hva_cache id_gpa; /* hva of guest per-cpu */
						   /* pv_apf_event.apf_id */
		u32 cnt; /* Counter of async pf */
			 /* events on this vcpu. */
		u32 host_apf_reason; /* Reason for async pf: */
				     /* page in swap or page ready. */
		u32 apf_ready_vector; /* Irq vector number to notify */
				/* that page is ready */
		u32 irq_controller; /* Type of irq controller to use */
				/* to notify guest that page is ready */
		bool in_pm; /* Is privilidged mode intercepted? */
	} apf;
#endif /* CONFIG_KVM_ASYNC_PF */

	int node_id;
	int hard_cpu_id;
};

#ifdef	CONFIG_KVM_HV_MMU
typedef struct kvm_lpage_info {
	int disallow_lpage;
} kvm_lpage_info_t;

typedef struct kvm_arch_memory_slot {
	kvm_rmap_head_t		*rmap[KVM_NR_PAGE_SIZES];
	kvm_lpage_info_t	*lpage_info[KVM_NR_PAGE_SIZES - 1];
	kvm_mem_guest_t		guest_areas;
	unsigned short		*gfn_track[KVM_PAGE_TRACK_MAX];
} kvm_arch_memory_slot_t;
#else	/* ! CONFIG_KVM_HV_MMU */
struct kvm_lpage_info {
	int write_count;
};

struct kvm_arch_memory_slot {
	unsigned long *rmap;
	struct kvm_lpage_info *lpage_info[KVM_NR_PAGE_SIZES - 1];
	kvm_mem_guest_t guest_areas;
};

extern struct file_operations kvm_vm_fops;
#endif	/* CONFIG_KVM_HV_MMU */

/*
 * e2k-arch vcpu->requests bit members
 */
#define KVM_REQ_TRIPLE_FAULT		10	/* FIXME: not implemented */
#define KVM_REQ_MMU_SYNC		11	/* FIXME: not implemented */
#define KVM_REQ_PENDING_IRQS		15	/* there are unhandled IRQs */
						/* injected on VCPU */
#define KVM_REQ_PENDING_VIRQS		16	/* there are unhandled VIRQs */
						/* to inject on VCPU */
#define	KVM_REG_SHOW_STATE		17	/* bit should be cleared */
						/* after show state of VCPU */
						/* completion */
#define	KVM_REQ_KICK			18	/* VCPU should be kicked */
#define KVM_REQ_VIRQS_INJECTED		20	/* pending VIRQs injected */
#define KVM_REQ_SCAN_IOAPIC		23	/* scan IO-APIC */
#define KVM_REQ_SCAN_IOEPIC		24	/* scan IO-EPIC */

#define kvm_set_pending_virqs(vcpu)	\
		set_bit(KVM_REQ_PENDING_VIRQS, (void *)&vcpu->requests)
#define	kvm_test_and_clear_pending_virqs(vcpu)	\
		test_and_clear_bit(KVM_REQ_PENDING_VIRQS,	\
			(void *)&vcpu->requests)
#define	kvm_clear_pending_virqs(vcpu)	\
		clear_bit(KVM_REQ_PENDING_VIRQS, (void *)&vcpu->requests)
#define	kvm_test_pending_virqs(vcpu)	\
		test_bit(KVM_REQ_PENDING_VIRQS, (void *)&vcpu->requests)
#define kvm_set_virqs_injected(vcpu)	\
		set_bit(KVM_REQ_VIRQS_INJECTED, (void *)&vcpu->requests)
#define	kvm_test_and_clear_virqs_injected(vcpu)	\
		test_and_clear_bit(KVM_REQ_VIRQS_INJECTED,	\
			(void *)&vcpu->requests)
#define	kvm_clear_virqs_injected(vcpu)	\
		clear_bit(KVM_REQ_VIRQS_INJECTED, (void *)&vcpu->requests)
#define	kvm_test_virqs_injected(vcpu)	\
		test_bit(KVM_REQ_VIRQS_INJECTED, (void *)&vcpu->requests)
#define	kvm_start_vcpu_show_state(vcpu)	\
		test_and_set_bit(KVM_REG_SHOW_STATE, (void *)&vcpu->requests)
#define	kvm_complete_vcpu_show_state(vcpu)	\
do { \
	if (test_and_clear_bit(KVM_REG_SHOW_STATE, (void *)&vcpu->requests)) \
		wake_up_bit((void *)&vcpu->requests, KVM_REG_SHOW_STATE); \
} while (false)

struct kvm_irq_mask_notifier {
	void (*func)(struct kvm_irq_mask_notifier *kimn, bool masked);
	int irq;
	struct hlist_node link;
};

typedef const pt_struct_t * (*get_pt_struct_func_t)(struct kvm *kvm);
typedef const pt_struct_t * (*get_vcpu_pt_struct_func_t)(struct kvm_vcpu *vcpu);

struct irq_remap_table {
	bool enabled;
	unsigned int host_pin;
	unsigned int guest_pin;
	int host_node;
	int guest_node;
	/* IOEPIC passthrough page start */
	hpa_t hpa;
	gpa_t gpa;
	struct pci_dev *vfio_dev;
};

struct kvm_arch {
	unsigned long vm_type;	/* virtual machine type */
	unsigned long flags;
	int naliases;
	int nshadows;
	kvm_nid_t vmid;		/* VM ID */
	unsigned int bsp_vcpu_id;
	bool is_pv;		/* paravirtualized VM */
	bool is_hv;		/* hardware virtualized VM */
	bool shadow_pt_enable;	/* shadow PT is supported and is base of */
				/* guest MMU emulation */
	bool phys_pt_enable;	/* guest physical addresses PT is supported */
				/* by MMU and hypervisor */
	bool tdp_enable;	/* two dimensional paging is supported */
				/* by hardware MMU and hypervisor */
	bool shadow_pt_set_up;	/* shadow PT was set up, skip setup on other VCPUs */
	kvm_mem_alias_t aliases[KVM_ALIAS_SLOTS];
	kvm_kernel_shadow_t shadows[KVM_SHADOW_SLOTS];
	kvm_nidmap_t gpid_nidmap[GPIDMAP_ENTRIES];
	struct hlist_head gpid_hash[GPID_HASH_SIZE];
	kvm_gpid_table_t gpid_table;
	struct kmem_cache *gti_cachep;
	char gti_cache_name[32];
	kvm_nidmap_t gmmid_nidmap[GMMIDMAP_ENTRIES];
	struct hlist_head gmmid_hash[GMMID_HASH_SIZE];
	gmmid_table_t gmmid_table;
	gmm_struct_t *init_gmm;		/* host agent of guest kernel mm */

	/* host page table structure to support guest MMU and PTs can be */
	/* different in common case */
	const pt_struct_t *host_pt_struct;	/* abstractions for details */
					/* of the host page table structure */
	const pt_struct_t *guest_pt_struct;	/* abstractions for details */
					/* of the guest page table structure */
	const pt_struct_t *gp_pt_struct;	/* abstractions for details */
					/* of the guest physical page table */
					/* structure, if is enable */
	get_pt_struct_func_t get_host_pt_struct;
	get_vcpu_pt_struct_func_t get_vcpu_pt_struct;
	get_pt_struct_func_t get_gp_pt_struct;

#ifdef	CONFIG_KVM_HV_MMU
	/* MMU nonpaging mode */
	hpa_t nonp_root_hpa;		/* physical base of nonpaging root PT */
	/* MMU pages statistic */
	unsigned int n_used_mmu_pages;
	unsigned int n_requested_mmu_pages;
	unsigned int n_max_mmu_pages;
	unsigned int indirect_shadow_pages;
	unsigned long mmu_valid_gen;
	struct hlist_head mmu_page_hash[KVM_NUM_MMU_PAGES];

	/* Hash table of struct kvm_mmu_page. */
	struct list_head active_mmu_pages;
	struct list_head zapped_obsolete_pages;
	struct kvm_page_track_notifier_node mmu_sp_tracker;
	struct kvm_page_track_notifier_head track_notifier_head;
#endif	/* CONFIG_KVM_HV_MMU */

	kvm_host_info_t *host_info;	/* host machine and kernel INFO */
	kvm_host_info_t *kmap_host_info; /* host machine and kernel INFO */
					 /* mapped to kernel space */
	kvm_guest_info_t guest_info;	/* guest machine and kernel INFO */
	raw_spinlock_t time_state_lock;	/* lock to update VM time */
	bool is_epic;	/* 0 - paravirt LAPIC/IO-APIC model */
			/* 1 - paravirt CEPIC/IO-EPIC model */
	struct kvm_ioapic *vioapic[KVM_MAX_EIOHUB_NUM];
	struct kvm_ioepic *ioepic[KVM_MAX_EIOHUB_NUM];
	int vapics_in_nmi_mode;
	struct page *epic_pages; /* HW CEPIC support */
	struct list_head assigned_dev_head;
	struct iommu_domain *iommu_domain;
	struct irq_remap_table *irt;
	unsigned long irq_sources_bitmap;
	struct kvm_nbsr *nbsr;
	struct kvm_lt *lt[KVM_MAX_EIOHUB_NUM];
	struct kvm_spmc *spmc[KVM_MAX_EIOHUB_NUM];

	/* boot-time spinlocks manage */
	struct hlist_head boot_spinlock_hash[BOOT_SPINLOCK_HASH_SIZE];
	boot_spinlock_unlocked_t boot_spinunlocked_list[
					BOOT_SPINUNLOCKED_LIST_SIZE];
	struct list_head boot_spinunlocked_head;
	struct list_head boot_spinunlocked_free;
	struct list_head boot_spinunlocked_wait;
	raw_spinlock_t boot_spinlock_hash_lock;
	bool boot_spinlock_hash_disable;

/* TODO memory leak!!! */
	/* spinlocks manage */
	struct hlist_head spinlock_hash[SPINLOCK_HASH_SIZE];
	spinlock_unlocked_t spinunlocked_list[SPINUNLOCKED_LIST_SIZE];
	struct list_head spinunlocked_head;
	struct list_head spinunlocked_free;
	struct list_head spinunlocked_wait;
	raw_spinlock_t spinlock_hash_lock;
	bool spinlock_hash_disable;

	/* VIRQ manage */
	raw_spinlock_t virq_lock;
	kvm_guest_virq_t guest_virq[KVM_MAX_NR_VIRQS];
	int max_irq_no;		/* max number of IRQ (from 0) */
#ifdef	CONFIG_SMP
	/* guest CSD lock wait management on host */
	raw_spinlock_t csd_spinlock;
	struct list_head csd_lock_wait_head;	/* head of list of waiters */
	struct list_head csd_lock_free_head;	/* head of list of free */
						/* structures */
	csd_lock_waiter_t csd_lock_free_list[KVM_MAX_CSD_LOCK_FREE_NUM];
#endif	/* CONFIG_SMP */

	/* reads protected by irq_srcu, writes by irq_lock */
	struct hlist_head irq_ack_notifier_list;

	struct hlist_head mask_notifier_list;

	bool halted;			/* VM is halted */
	/* sign of reboot VM, true - reboot */
	bool reboot;

	/* lock to update num_sclkr_run and common sh_sclkm3
	 * for all vcpu-s of the guest */
	raw_spinlock_t sh_sclkr_lock;
	int num_sclkr_run;
	s64 sh_sclkm3;
	unsigned int num_numa_nodes;
	unsigned int max_nr_node_cpu;

	/* CEPIC timer frequency (Hz) */
	unsigned long cepic_freq;

	/* Multiplier for watchdog timer prescaler (allows to slow down
	 * its frequency) */
	unsigned long wd_prescaler_mult;

	/* Directly map legacy VGA area (0xa0000-0xbffff) to guest */
	bool legacy_vga_passthrough;
};

#ifdef CONFIG_KVM_ASYNC_PF

/* Async page fault event descriptor */
struct kvm_arch_async_pf {
	u32 apf_id;	/* Unique identifier of async page fault event */
};

#endif /* CONFIG_KVM_ASYNC_PF */

#define arch_to_vcpu(arch_vcpu)	container_of(arch_vcpu, struct kvm_vcpu, arch)

/*
 * KVM arch-dependent flags
 */
#define	KVMF_PARAVIRT_GUEST	0	/* guest kernel is paravirtualized */
					/* and has shadow image address */
#define	KVMF_VCPU_STARTED	1	/* VCPUs (one or more) is started */
					/* VM real active */
#define	KVMF_IN_SHOW_STATE	8	/* show state of KVM (print all */
					/* stacks) is in progress */
#define	KVMF_NATIVE_KERNEL	32	/* guest is running native */
					/* e2k linux kernel */
#define	KVMF_PARAVIRT_KERNEL	33	/* guest is running paravirtualized */
					/* e2k linux kernel */
#define	KVMF_LINTEL		40	/* guest is running LIntel */
#define	KVMF_PARAVIRT_GUEST_MASK	(1UL << KVMF_PARAVIRT_GUEST)
#define	KVMF_VCPU_STARTED_MASK		(1UL << KVMF_VCPU_STARTED)
#define	KVMF_IN_SHOW_STATE_MASK		(1UL << KVMF_IN_SHOW_STATE)
#define	KVMF_NATIVE_KERNEL_MASK		(1UL << KVMF_NATIVE_KERNEL)
#define	KVMF_PARAVIRT_KERNEL_MASK	(1UL << KVMF_PARAVIRT_KERNEL)
#define	KVMF_LINTEL_MASK		(1UL << KVMF_LINTEL)

#define set_kvm_mode_flag(kvm, flag)					\
({									\
	set_bit(flag, (unsigned long *)&(kvm)->arch.flags);		\
})

#define clear_kvm_mode_flag(kvm, flag)					\
({									\
	clear_bit(flag, (unsigned long *)&(kvm)->arch.flags);		\
})

#define test_and_set_kvm_mode_flag(kvm, flag)				\
({									\
	test_and_set_bit(flag, (unsigned long *)&(kvm)->arch.flags);	\
})

#define test_and_clear_kvm_mode_flag(kvm, flag)				\
({									\
	test_and_clear_bit(flag, (unsigned long *)&(kvm)->arch.flags);	\
})

#define test_kvm_mode_flag(kvm, flag)					\
({									\
	test_bit(flag, (unsigned long *)&(kvm)->arch.flags);		\
})

#define kvm_clear_vcpu(kvm, vcpu_no)					\
({									\
	(kvm)->vcpus[vcpu_no] = NULL;					\
	smp_wmb();							\
})

struct kvm_e2k_info {
	struct module	*module;
};

static inline void kvm_arch_vcpu_block_finish(struct kvm_vcpu *vcpu)
{
	/* nothing to do */
}

/*
 * Shadow page tables root flags to get/set/update/alloc/free
 */
#define	U_ROOT_PT_BIT		0	/* user shadow PT root */
#define	OS_ROOT_PT_BIT		1	/* kernel (OS) PT root */
#define	GP_ROOT_PT_BIT		2	/* hypervisor PT root to translate */
					/* guest physical addresses */
#define	SEP_VIRT_ROOT_PT_BIT	3	/* separate virtual spaces mode */
#define	DONT_SYNC_ROOT_PT_BIT	4	/* do not sync shadow PT root */

#define	U_ROOT_PT_FLAG		(1U << U_ROOT_PT_BIT)
#define	OS_ROOT_PT_FLAG		(1U << OS_ROOT_PT_BIT)
#define	GP_ROOT_PT_FLAG		(1U << GP_ROOT_PT_BIT)
#define	SEP_VIRT_ROOT_PT_FLAG	(1U << SEP_VIRT_ROOT_PT_BIT)
#define	DONT_SYNC_ROOT_PT_FLAG	(1U << DONT_SYNC_ROOT_PT_BIT)

#define KVM_ARCH_WANT_MMU_NOTIFIER

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
int kvm_unmap_hva_range(struct kvm *kvm, unsigned long start, unsigned long end, unsigned flags);
int kvm_set_spte_hva(struct kvm *kvm, unsigned long hva, pte_t pte);
int kvm_age_hva(struct kvm *kvm, unsigned long start, unsigned long end);
int kvm_test_age_hva(struct kvm *kvm, unsigned long hva);
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

extern void kvm_fire_mask_notifiers(struct kvm *kvm, int irq, bool mask);

extern int kvm_wake_up_vcpu_host(struct kvm_vcpu *vcpu, int wait);
extern struct kvm_vcpu *kvm_get_vcpu_on_id(struct kvm *kvm, int vcpu_id);
extern struct kvm_vcpu *kvm_get_vcpu_on_hard_cpu_id(struct kvm *kvm,
							int hard_cpu_id);
extern bool kvm_vcpu_is_bsp(struct kvm_vcpu *vcpu);

extern void kvm_make_scan_ioapic_request(struct kvm *kvm);

#ifdef CONFIG_KVM_ASYNC_PF
extern void kvm_arch_async_page_not_present(struct kvm_vcpu *vcpu,
		struct kvm_async_pf *work);
extern void kvm_arch_async_page_present(struct kvm_vcpu *vcpu,
		struct kvm_async_pf *work);
#endif /* CONFIG_KVM_ASYNC_PF */

#if	defined(CONFIG_KVM_HW_VIRTUALIZATION) && \
			!defined(CONFIG_KVM_GUEST_KERNEL)
/* it is hypervisor or host with virtualization support */
extern void kvm_hv_epic_load(struct kvm_vcpu *vcpu);
extern void kvm_epic_invalidate_dat(struct kvm_vcpu *vcpu);
extern void kvm_epic_enable_int(void);
extern void kvm_epic_timer_start(void);
extern void kvm_epic_timer_stop(void);
extern void kvm_deliver_cepic_epic_interrupt(void);
extern void kvm_epic_check_int_status(struct kvm_vcpu_arch *vcpu);
extern void kvm_init_cepic_idle_timer(struct kvm_vcpu *vcpu);
extern void kvm_epic_start_idle_timer(struct kvm_vcpu *vcpu);
extern void kvm_epic_stop_idle_timer(struct kvm_vcpu *vcpu);
#else	/* ! CONFIG_KVM_HW_VIRTUALIZATION || CONFIG_KVM_GUEST_KERNEL */
/* it is host without virtualization support */
/* or native paravirtualized guest */
static inline void kvm_hv_epic_load(struct kvm_vcpu *vcpu)
{
	/* nothing to do */
}

static inline void kvm_epic_invalidate_dat(struct kvm_vcpu *vcpu)
{
	/* nothing to do */
}

static inline void kvm_epic_enable_int(void)
{
	/* nothing to do */
}

static inline void kvm_epic_timer_start(void)
{
	/* nothing to do */
}

static inline void kvm_epic_timer_stop(void)
{
	/* nothing to do */
}

static inline void kvm_deliver_cepic_epic_interrupt(void)
{
	/* nothing to do */
}

static inline void kvm_epic_check_int_status(struct kvm_vcpu_arch *vcpu)
{
	/* nothing to do */
}

static inline void kvm_init_cepic_idle_timer(struct kvm_vcpu *vcpu)
{
	/* nothing to do */
}

static inline void kvm_epic_start_idle_timer(struct kvm_vcpu *vcpu)
{
	/* nothing to do */
}

static inline void kvm_epic_stop_idle_timer(struct kvm_vcpu *vcpu)
{
	/* nothing to do */
}
#endif /* CONFIG_KVM_HW_VIRTUALIZATION && !CONFIG_KVM_GUEST_KERNEL */

extern struct work_struct kvm_dump_stacks;
extern void wait_for_print_all_guest_stacks(struct work_struct *work);

#endif /* _ASM_E2K_KVM_HOST_H */
