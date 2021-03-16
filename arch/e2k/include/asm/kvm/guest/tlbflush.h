/*
 * Guest MMU caches flushing support on guest kernel
 *
 * Guest VM is fake virtual memory support.
 * Guest kernel manage own VM as any linux kernel, but all it is fake,
 * real used page tables, real physical pages, real flushing is made by host.
 *
 * Copyright 2016 Salavat S. Gilyazov (atic@mcst.ru)
 */
#ifndef _E2K_KVM_GUEST_TLBFLUSH_H
#define _E2K_KVM_GUEST_TLBFLUSH_H

#include <linux/mm.h>
#include <asm/kvm/tlbflush.h>

#ifdef CONFIG_KVM_GUEST_KERNEL
extern void kvm_pv_flush_tlb_all(void);
extern void kvm_pv_flush_tlb_mm(struct mm_struct *mm);
extern void kvm_pv_flush_tlb_page(struct mm_struct *mm, e2k_addr_t addr);
extern void kvm_pv_flush_tlb_range(struct mm_struct *mm, e2k_addr_t start,
					e2k_addr_t end);
extern void kvm_pv_flush_tlb_kernel_range(e2k_addr_t start, e2k_addr_t end);
extern void kvm_pv_flush_pmd_tlb_range(struct mm_struct *mm, e2k_addr_t start,
					e2k_addr_t end);
extern void kvm_pv_flush_tlb_range_and_pgtables(struct mm_struct *mm,
					e2k_addr_t start,
					e2k_addr_t end);
#ifndef CONFIG_SMP
static inline void
kvm_flush_tlb_all(void)
{
	if (IS_HV_GM())
		__flush_tlb_all();
	else
		kvm_pv_flush_tlb_all();
}
static inline void
kvm_flush_tlb_mm(struct mm_struct *mm)
{
	if (IS_HV_GM())
		__flush_tlb_mm(mm);
	else
		kvm_pv_flush_tlb_mm(mm);
}
static inline void
kvm_flush_tlb_page(struct vm_area_struct *vma, e2k_addr_t addr)
{
	if (IS_HV_GM())
		__flush_tlb_page(vma->vm_mm, addr);
	else
		kvm_pv_flush_tlb_page(vma->vm_mm, addr);
}
static inline void
kvm_flush_tlb_range(struct mm_struct *mm, e2k_addr_t start, e2k_addr_t end)
{
	if (IS_HV_GM())
		__flush_tlb_range(mm, start, end);
	else
		kvm_pv_flush_tlb_range(mm, start, end);
}
static inline void
kvm_flush_tlb_kernel_range(e2k_addr_t start, e2k_addr_t end)
{
	if (IS_HV_GM())
		__flush_tlb_all();
	else
		kvm_pv_flush_tlb_kernel_range(start, end);
}
static inline void
kvm_flush_pmd_tlb_range(struct mm_struct *mm, e2k_addr_t start,
				e2k_addr_t end)
{
	if (IS_HV_GM())
		__flush_pmd_tlb_range(mm, start, end);
	else
		kvm_pv_flush_pmd_tlb_range(mm, start, end);
}
static inline void
kvm_flush_tlb_range_and_pgtables(struct mm_struct *mm,
				e2k_addr_t start, e2k_addr_t end)
{
	if (IS_HV_GM())
		__flush_tlb_range_and_pgtables(mm, start, end);
	else
		kvm_pv_flush_tlb_range_and_pgtables(mm, start, end);
}
#else /* CONFIG_SMP */
extern void native_smp_flush_tlb_all(void);
extern void native_smp_flush_tlb_mm(struct mm_struct *mm);
extern void native_smp_flush_tlb_page(struct vm_area_struct *vma,
			e2k_addr_t addr);
extern void native_smp_flush_tlb_range(struct mm_struct *mm,
			e2k_addr_t start, e2k_addr_t end);
extern void native_smp_flush_pmd_tlb_range(struct mm_struct *mm,
			e2k_addr_t start, e2k_addr_t end);
extern void native_smp_flush_tlb_range_and_pgtables(struct mm_struct *mm,
			e2k_addr_t start, e2k_addr_t end);
static inline void
kvm_flush_tlb_all(void)
{
	if (IS_HV_GM())
		native_smp_flush_tlb_all();
	else
		kvm_pv_flush_tlb_all();
}
static inline void
kvm_flush_tlb_mm(struct mm_struct *mm)
{
	if (IS_HV_GM())
		native_smp_flush_tlb_mm(mm);
	else
		kvm_pv_flush_tlb_mm(mm);
}
static inline void
kvm_flush_tlb_page(struct vm_area_struct *vma, e2k_addr_t addr)
{
	if (IS_HV_GM())
		native_smp_flush_tlb_page(vma, addr);
	else
		kvm_pv_flush_tlb_page(vma->vm_mm, addr);
}
static inline void
kvm_flush_tlb_range(struct mm_struct *mm, e2k_addr_t start, e2k_addr_t end)
{
	if (IS_HV_GM())
		native_smp_flush_tlb_range(mm, start, end);
	else
		kvm_pv_flush_tlb_range(mm, start, end);
}
static inline void
kvm_flush_tlb_kernel_range(e2k_addr_t start, e2k_addr_t end)
{
	if (IS_HV_GM())
		native_smp_flush_tlb_all();
	else
		kvm_pv_flush_tlb_kernel_range(start, end);
}
static inline void
kvm_flush_pmd_tlb_range(struct mm_struct *mm, e2k_addr_t start,
		e2k_addr_t end)
{
	if (IS_HV_GM())
		native_smp_flush_pmd_tlb_range(mm, start, end);
	else
		kvm_pv_flush_pmd_tlb_range(mm, start, end);
}
static inline void
kvm_flush_tlb_range_and_pgtables(struct mm_struct *mm,
				e2k_addr_t start, e2k_addr_t end)
{
	if (IS_HV_GM())
		native_smp_flush_tlb_range_and_pgtables(mm, start, end);
	else
		kvm_pv_flush_tlb_range_and_pgtables(mm, start, end);
}
#endif	/* CONFIG_SMP */

/* it is native KVM guest kernel (not paravirtualized) */
/* guest kernel does not support other virtual machines and guests */
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
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* _E2K_KVM_GUEST_TLBFLUSH_H */
