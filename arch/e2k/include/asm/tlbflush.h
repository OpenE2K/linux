/* $Id: tlbflush.h,v 1.3 2006/09/12 13:12:54 tokot Exp $
 * pgalloc.h: the functions and defines necessary to allocate
 * page tables.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */
#ifndef _E2K_TLBFLUSH_H
#define _E2K_TLBFLUSH_H

#include <linux/mm.h>


/*
 * TLB flushing:
 *
 *  - flush_tlb_all() flushes all processes TLBs
 *  - flush_tlb_mm(mm) flushes the specified mm context TLB's
 *  - flush_tlb_page(vma, vmaddr) flushes one page
 *  - flush_tlb_range(mm, start, end) flushes a range of pages
 */

extern void __flush_tlb_all(void);
extern void __flush_tlb_mm(struct mm_struct *mm);
extern void __flush_tlb_page(struct mm_struct *mm, e2k_addr_t addr);
extern void __flush_tlb_range(struct mm_struct *mm, e2k_addr_t start,
			      e2k_addr_t end);
extern void __flush_pmd_tlb_range(struct mm_struct *mm,
		unsigned long start, unsigned long end);
extern void __flush_tlb_pgtables(struct mm_struct *mm, e2k_addr_t start,
				 e2k_addr_t end);
extern void __flush_tlb_page_and_pgtables(struct mm_struct *mm,
					  unsigned long addr);

extern void __flush_tlb_range_and_pgtables(struct mm_struct *mm,
					   e2k_addr_t start, e2k_addr_t end);
extern void __flush_tlb_address(e2k_addr_t addr);
extern void __flush_tlb_address_pgtables(e2k_addr_t addr);

#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
extern void __flush_cpu_root_pt_mm(struct mm_struct *mm);
extern void __flush_cpu_root_pt(void);
#else	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
#define	__flush_cpu_root_pt_mm(mm)
#define	__flush_cpu_root_pt()
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */


#if	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/tlbflush.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native guest kernel */
#include <asm/kvm/guest/tlbflush.h>
#define flush_tlb_all		kvm_flush_tlb_all
#define flush_tlb_mm		kvm_flush_tlb_mm
#define flush_tlb_page(vma, addr) kvm_flush_tlb_page(vma, addr)
#define flush_tlb_range(vma, start, end) \
			kvm_flush_tlb_range(vma->vm_mm, start, end)
#define flush_tlb_kernel_range(start, end) \
			kvm_flush_tlb_kernel_range(start, end)
#define flush_pmd_tlb_range(vma, start, end) \
			kvm_flush_pmd_tlb_range(vma->vm_mm, start, end)
#define flush_tlb_mm_range(mm, start, end) \
			kvm_flush_tlb_range(mm, start, end)
#define flush_tlb_range_and_pgtables(mm, start, end) \
			kvm_flush_tlb_range_and_pgtables(mm, start, end)
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without virtualization support */
/* or native kernel with virtualization support */

#ifndef CONFIG_SMP

#define flush_tlb_all			__flush_tlb_all
#define flush_tlb_mm			__flush_tlb_mm
#define flush_tlb_page(vma, addr)	__flush_tlb_page(vma->vm_mm, addr)
#define flush_tlb_range(vma, start, end) \
				__flush_tlb_range(vma->vm_mm, start, end)
#define flush_pmd_tlb_range(vma, start, end) \
				__flush_pmd_tlb_range(vma->vm_mm, start, end)
#define flush_tlb_mm_range(mm, start, end) \
				__flush_tlb_range(mm, start, end)
#define flush_tlb_range_and_pgtables(mm, start, end) \
				__flush_tlb_range_and_pgtables(mm, start, end)

#else	/* CONFIG_SMP */

#include <asm/smp.h>

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

#define flush_tlb_all		native_smp_flush_tlb_all
#define flush_tlb_mm		native_smp_flush_tlb_mm
#define flush_tlb_page(vma, addr) native_smp_flush_tlb_page(vma, addr)
#define flush_tlb_range(vma, start, end) \
			native_smp_flush_tlb_range(vma->vm_mm, start, end)
#define flush_pmd_tlb_range(vma, start, end) \
			native_smp_flush_pmd_tlb_range(vma->vm_mm, start, end)
#define flush_tlb_mm_range(mm, start, end) \
			native_smp_flush_tlb_range(mm, start, end)
#define flush_tlb_range_and_pgtables(mm, start, end) \
			native_smp_flush_tlb_range_and_pgtables(mm, start, end)

#endif	/* CONFIG_SMP */

#define	flush_tlb_kernel_range(start, end)	flush_tlb_all()

#endif	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */


static inline void update_mmu_cache(struct vm_area_struct *vma,
		unsigned long address, pte_t *pte)
{
}

static inline void update_mmu_cache_pmd(struct vm_area_struct *vma,
		unsigned long address, pmd_t *pmd)
{
}

#include <asm/kvm/tlbflush.h>

#endif /* _E2K_TLBFLUSH_H */
