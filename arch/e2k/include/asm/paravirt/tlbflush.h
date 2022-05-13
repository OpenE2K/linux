/*
 * Host and guest MMU caches flushing on paravirtualized kernel
 *
 * Copyright 2016 Salavat S. Gilyazov (atic@mcst.ru)
 */
#ifndef _E2K_PARAVIRT_TLBFLUSH_H
#define _E2K_PARAVIRT_TLBFLUSH_H

#include <linux/mm.h>
#include <asm/paravirt/pv_ops.h>

static inline void pv_flush_tlb_all(void)
{
	pv_cpu_ops.flush_tlb_all();
}
static inline void pv_flush_tlb_mm(struct mm_struct *mm)
{
	pv_cpu_ops.flush_tlb_mm(mm);
}
static inline void
pv_flush_tlb_page(struct vm_area_struct *vma, e2k_addr_t addr)
{
	pv_cpu_ops.flush_tlb_page(vma, addr);
}
static inline void pv_flush_tlb_mm_range(struct mm_struct *mm,
		unsigned long start, unsigned long end,
		unsigned long stride, u32 levels_mask)
{
	pv_cpu_ops.flush_tlb_mm_range(mm, start, end, stride, levels_mask);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */
static inline void flush_tlb_all(void)
{
	pv_flush_tlb_all();
}
static inline void flush_tlb_mm(struct mm_struct *mm)
{
	pv_flush_tlb_mm(mm);
}
static inline void flush_tlb_page(struct vm_area_struct *vma, e2k_addr_t addr)
{
	pv_flush_tlb_page(vma, addr);
}
static inline void flush_tlb_mm_range(struct mm_struct *mm,
		unsigned long start, unsigned long end,
		unsigned long stride, u32 levels_mask)
{
	pv_flush_tlb_mm_range(mm, start, end, stride, levels_mask);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* _E2K_PARAVIRT_TLBFLUSH_H */
