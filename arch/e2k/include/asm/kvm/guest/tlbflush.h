/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Guest MMU caches flushing support on guest kernel
 *
 * Guest VM is fake virtual memory support.
 * Guest kernel manage own VM as any linux kernel, but all it is fake,
 * real used page tables, real physical pages, real flushing is made by host.
 */

#ifndef _E2K_KVM_GUEST_TLBFLUSH_H
#define _E2K_KVM_GUEST_TLBFLUSH_H

#include <linux/mm_types.h>
#include <asm/kvm/tlbflush.h>
#include <asm/tlbflush.h>

#ifdef CONFIG_KVM_GUEST_KERNEL
extern void kvm_pv_flush_tlb_all(void);
extern void kvm_pv_flush_tlb_mm(struct mm_struct *mm);
extern void kvm_pv_flush_tlb_page(struct mm_struct *mm, e2k_addr_t addr);
extern void kvm_pv_flush_tlb_range(struct mm_struct *mm,
				e2k_addr_t start, e2k_addr_t end);
extern void kvm_pv_flush_tlb_mm_range(struct mm_struct *mm,
					e2k_addr_t start, e2k_addr_t end,
					unsigned long stride, u32 levels_mask);
extern void kvm_pv_flush_tlb_kernel_range(e2k_addr_t start, e2k_addr_t end);
extern void kvm_pv_flush_pmd_tlb_range(struct mm_struct *mm, e2k_addr_t start,
					e2k_addr_t end);
extern void kvm_pv_flush_tlb_range_and_pgtables(struct mm_struct *mm,
					e2k_addr_t start, e2k_addr_t end);

static inline void kvm_flush_tlb_all(void)
{
	if (IS_HV_GM())
		native_flush_tlb_all();
	else
		kvm_pv_flush_tlb_all();
}

static inline void kvm_flush_tlb_mm(struct mm_struct *mm)
{
	if (IS_HV_GM())
		native_flush_tlb_mm(mm);
	else
		kvm_pv_flush_tlb_mm(mm);
}

static inline void kvm_flush_tlb_page(struct mm_struct *mm, e2k_addr_t addr)
{
	if (IS_HV_GM())
		native_flush_tlb_page(mm, addr);
	else
		kvm_pv_flush_tlb_page(mm, addr);
}

static inline void kvm_flush_tlb_range(struct mm_struct *mm,
				       e2k_addr_t start, e2k_addr_t end)
{
	if (IS_HV_GM())
		native_flush_tlb_range(mm, start, end);
	else
		kvm_pv_flush_tlb_range(mm, start, end);
}

static inline void kvm_flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
		unsigned long end, unsigned long stride, u32 levels_mask)
{
	if (IS_HV_GM())
		native_flush_tlb_mm_range(mm, start, end, stride, levels_mask);
	else
		kvm_pv_flush_tlb_mm_range(mm, start, end, stride, levels_mask);
}

static inline void kvm_flush_tlb_kernel_range(e2k_addr_t start, e2k_addr_t end)
{
	if (IS_HV_GM())
		native_flush_tlb_kernel_range(start, end);
	else
		kvm_pv_flush_tlb_kernel_range(start, end);
}

static inline void kvm_flush_pmd_tlb_range(struct mm_struct *mm,
		e2k_addr_t start, e2k_addr_t end)
{
	if (IS_HV_GM())
		native_flush_pmd_tlb_range(mm, start, end);
	else
		kvm_pv_flush_pmd_tlb_range(mm, start, end);
}

static inline void kvm_flush_pud_tlb_range(struct mm_struct *mm,
		e2k_addr_t start, e2k_addr_t end)
{
	if (IS_HV_GM())
		native_flush_pud_tlb_range(mm, start, end);
	else
		kvm_pv_flush_tlb_range(mm, start, end);
}

static inline void kvm_flush_tlb_range_and_pgtables(struct mm_struct *mm,
				e2k_addr_t start, e2k_addr_t end)
{
	if (IS_HV_GM())
		native_flush_tlb_range_and_pgtables(mm, start, end);
	else
		kvm_pv_flush_tlb_range_and_pgtables(mm, start, end);
}

static inline void kvm_flush_tlb_page_and_pgtables(struct mm_struct *mm,
						   unsigned long uaddr)
{
	kvm_flush_tlb_range_and_pgtables(mm, uaddr, uaddr + 1);
}

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
