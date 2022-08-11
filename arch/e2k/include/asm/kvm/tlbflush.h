/*
 * Guest MMU caches flushing on KVM host
 *
 * Copyright 2016 Salavat S. Gilyazov (atic@mcst.ru)
 */
#ifndef _E2K_KVM_TLBFLUSH_H
#define _E2K_KVM_TLBFLUSH_H

#include <linux/mm.h>
#include <asm/kvm/thread_info.h>


/*
 * Guest VM support on host
 * TLB flushing:
 *
 *  - flush_tlb_mm(mm) flushes the specified mm context TLB's
 *  - flush_tlb_page(vma, vmaddr) flushes one page
 *  - flush_tlb_range(mm, start, end) flushes a range of pages
 *  - flush_tlb_pgtables(mm, start, end) flushes a range of page tables
 */

#ifndef	CONFIG_VIRTUALIZATION
/* it is native kernel without any virtualization */
static __always_inline bool
__flush_guest_cpu_root_pt_page(struct vm_area_struct *vma, e2k_addr_t addr)
{
	return false;	/* none any guests and guest addresses */
}
static __always_inline bool
__flush_guest_cpu_root_pt_range(struct mm_struct *mm,
				e2k_addr_t start, e2k_addr_t end)
{
	return false;	/* none any guests and guest addresses */
}
static __always_inline bool
__flush_guest_cpu_root_pt_mm(struct mm_struct *mm)
{
	return false;	/* none any guests and guest addresses */
}
static __always_inline bool
__flush_guest_cpu_root_pt(void)
{
	return false;	/* none any guests and guest addresses */
}
#else	/* CONFIG_VIRTUALIZATION */
extern void kvm_flush_guest_tlb_mm(struct gmm_struct *gmm);
extern void kvm_flush_guest_tlb_page(struct gmm_struct *gmm, e2k_addr_t addr);
extern void kvm_flush_guest_tlb_range(struct gmm_struct *gmm,
				e2k_addr_t start, e2k_addr_t end);
extern void kvm_flush_guest_tlb_pgtables(struct gmm_struct *gmm,
				e2k_addr_t start, e2k_addr_t end);
extern void kvm_flush_guest_tlb_range_and_pgtables(struct gmm_struct *gmm,
				e2k_addr_t start, e2k_addr_t end);

/*
 * Functions to flush guest CPU root PT on host should return boolean value:
 *	true	if address or MM is from guest VM space and flushing was done
 *	false	if address or MM is not from guest VM space or flushing cannot
 *		be done
 */
extern bool kvm_do_flush_guest_cpu_root_pt_page(struct vm_area_struct *vma,
					e2k_addr_t addr);
extern bool kvm_do_flush_guest_cpu_root_pt_range(struct mm_struct *mm,
					e2k_addr_t start, e2k_addr_t end);
extern bool kvm_do_flush_guest_cpu_root_pt_mm(struct mm_struct *mm);
extern bool kvm_do_flush_guest_cpu_root_pt(void);

static inline bool
kvm_flush_guest_cpu_root_pt_page(struct vm_area_struct *vma, e2k_addr_t addr)
{
	if (MMU_IS_SEPARATE_PT()) {
		/* cannot be any CPU root PTs */
		return false;
	} else if (!test_thread_flag(TIF_VIRTUALIZED_GUEST)) {
		/* it is not guest VCPU process on host */
		/* so cannot have guest VM */
		return false;
	} else if (paravirt_enabled()) {
		/* it is guest process on guest and guest has not own guests */
		return false;
	}
	return kvm_do_flush_guest_cpu_root_pt_page(vma, addr);
}

static inline bool
kvm_flush_guest_cpu_root_pt_range(struct mm_struct *mm,
					e2k_addr_t start, e2k_addr_t end)
{
	if (MMU_IS_SEPARATE_PT()) {
		/* cannot be any CPU root PTs */
		return false;
	} else if (!test_thread_flag(TIF_VIRTUALIZED_GUEST)) {
		/* it is not guest VCPU process on host */
		/* so cannot have guest VM */
		return false;
	} else if (paravirt_enabled()) {
		/* it is guest process on guest and guest has not own guests */
		return false;
	}
	return kvm_do_flush_guest_cpu_root_pt_range(mm, start, end);
}

static inline bool
kvm_flush_guest_cpu_root_pt_mm(struct mm_struct *mm)
{
	if (MMU_IS_SEPARATE_PT()) {
		/* cannot be any CPU root PTs */
		return false;
	} else if (!test_thread_flag(TIF_VIRTUALIZED_GUEST)) {
		/* it is not guest VCPU process on host */
		/* so cannot have guest VM */
		return false;
	} else if (paravirt_enabled()) {
		/* it is guest process on guest and guest has not own guests */
		return false;
	}
	return kvm_do_flush_guest_cpu_root_pt_mm(mm);
}

static inline bool
kvm_flush_guest_cpu_root_pt(void)
{
	if (MMU_IS_SEPARATE_PT()) {
		/* cannot be any CPU root PTs */
		return false;
	} else if (!test_thread_flag(TIF_VIRTUALIZED_GUEST)) {
		/* it is not guest VCPU process on host */
		/* so cannot have guest VM */
		return false;
	} else if (paravirt_enabled()) {
		/* it is guest process on guest and guest has not own guests */
		return false;
	}
	return kvm_do_flush_guest_cpu_root_pt();
}

#ifndef	CONFIG_KVM_GUEST_KERNEL
/* it is native host kernel with virtualization support */
/* or it is paravirtualized host/guest kernel */
static inline bool
__flush_guest_cpu_root_pt_page(struct vm_area_struct *vma, e2k_addr_t addr)
{
	return kvm_flush_guest_cpu_root_pt_page(vma, addr);
}
static inline bool
__flush_guest_cpu_root_pt_range(struct mm_struct *mm,
					e2k_addr_t start, e2k_addr_t end)
{
	return kvm_flush_guest_cpu_root_pt_range(mm, start, end);
}
static inline bool
__flush_guest_cpu_root_pt_mm(struct mm_struct *mm)
{
	return kvm_flush_guest_cpu_root_pt_mm(mm);
}
static inline bool
__flush_guest_cpu_root_pt(void)
{
	return kvm_flush_guest_cpu_root_pt();
}

#endif	/* ! CONFIG_KVM_GUEST_KERNEL */
#endif	/* ! CONFIG_VIRTUALIZATION */
#endif /* _E2K_KVM_TLBFLUSH_H */
