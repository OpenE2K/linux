/*
 * Host and guest MMU caches flushing on paravirtualized kernel
 *
 * Copyright 2016 Salavat S. Gilyazov (atic@mcst.ru)
 */
#ifndef _E2K_PARAVIRT_TLBFLUSH_H
#define _E2K_PARAVIRT_TLBFLUSH_H

#include <linux/mm.h>
#include <asm/paravirt/pv_ops.h>

#ifdef	CONFIG_SMP
static inline void
pv_smp_flush_tlb_all(void)
{
	pv_cpu_ops.smp_flush_tlb_all();
}
static inline void
pv_smp_flush_tlb_mm(struct mm_struct *mm)
{
	pv_cpu_ops.smp_flush_tlb_mm(mm);
}
static inline void
pv_smp_flush_tlb_page(struct vm_area_struct *vma, e2k_addr_t addr)
{
	pv_cpu_ops.smp_flush_tlb_page(vma, addr);
}
static inline void
pv_smp_flush_tlb_range(struct mm_struct *mm,
		e2k_addr_t start, e2k_addr_t end)
{
	pv_cpu_ops.smp_flush_tlb_range(mm, start, end);
}
static inline void
pv_smp_flush_pmd_tlb_range(struct mm_struct *mm,
		e2k_addr_t start, e2k_addr_t end)
{
	pv_cpu_ops.smp_flush_pmd_tlb_range(mm, start, end);
}
static inline void
pv_smp_flush_tlb_range_and_pgtables(struct mm_struct *mm,
		e2k_addr_t start, e2k_addr_t end)
{
	pv_cpu_ops.smp_flush_tlb_range_and_pgtables(mm, start, end);
}
#endif	/* CONFIG_SMP */

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */
#ifdef	CONFIG_SMP
static inline void
smp_flush_tlb_all(void)
{
	pv_smp_flush_tlb_all();
}
static inline void
smp_flush_tlb_mm(struct mm_struct *mm)
{
	pv_smp_flush_tlb_mm(mm);
}
static inline void
smp_flush_tlb_page(struct vm_area_struct *vma, e2k_addr_t addr)
{
	pv_smp_flush_tlb_page(vma, addr);
}
static inline void
smp_flush_tlb_range(struct mm_struct *mm, e2k_addr_t start, e2k_addr_t end)
{
	pv_smp_flush_tlb_range(mm, start, end);
}
static inline void
smp_flush_pmd_tlb_range(struct mm_struct *mm, e2k_addr_t start, e2k_addr_t end)
{
	pv_smp_flush_pmd_tlb_range(mm, start, end);
}
static inline void
smp_flush_tlb_range_and_pgtables(struct mm_struct *mm,
		e2k_addr_t start, e2k_addr_t end)
{
	pv_smp_flush_tlb_range_and_pgtables(mm, start, end);
}
#endif	/* CONFIG_SMP */
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* _E2K_PARAVIRT_TLBFLUSH_H */
