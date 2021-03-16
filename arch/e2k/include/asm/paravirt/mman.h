#ifndef __ASM_PARAVIRT_MMAN_H
#define __ASM_PARAVIRT_MMAN_H

#ifdef __KERNEL__

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

struct mm_struct;
struct vm_area_struct;
struct task_struct;
struct vmap_area;

/* Memory management mman */

static inline int
pv_remap_area_pages(unsigned long address, unsigned long phys_addr,
			unsigned long size, unsigned long flags)
{
	return pv_mmu_ops.remap_area_pages(address, phys_addr, size, flags);
}

static inline int
pv_host_guest_vmap_area(e2k_addr_t start, e2k_addr_t end)
{
	if (pv_mmu_ops.host_guest_vmap_area != NULL)
		return pv_mmu_ops.host_guest_vmap_area(start, end);
	else
		return 0;
}
static inline int
pv_unhost_guest_vmap_area(e2k_addr_t start, e2k_addr_t end)
{
	if (pv_mmu_ops.unhost_guest_vmap_area != NULL)
		return pv_mmu_ops.unhost_guest_vmap_area(start, end);
	else
		return 0;
}

/*
 * Memory management mman
 */
extern inline void pv_free_mm(struct mm_struct *mm)
{
	pv_mmu_ops.free_mm(mm);
}
extern inline struct mm_struct *pv_mm_init(struct mm_struct *mm,
						struct task_struct *p,
						struct user_namespace *user_ns)
{
	return pv_mmu_ops.mm_init(mm, p, user_ns);
}
static inline int pv_make_host_pages_valid(struct vm_area_struct *vma,
			e2k_addr_t start_addr, e2k_addr_t end_addr,
			bool chprot, bool flush)
{
	return pv_mmu_ops.make_host_pages_valid(vma, start_addr, end_addr,
						chprot, flush);
}
static inline int
pv_set_memory_attr_on_host(e2k_addr_t start, e2k_addr_t end,
				enum sma_mode mode)
{
	return pv_mmu_ops.set_memory_attr_on_host(start, end, mode);
}
static inline int pv_access_process_vm(struct task_struct *tsk,
			unsigned long addr, void *buf, int len,
			unsigned int gup_flags)
{
	return pv_mmu_ops.access_process_vm(tsk, addr, buf, len, gup_flags);
}

extern inline struct vmap_area *pv_alloc_vmap_area(unsigned long size,
				unsigned long align,
				unsigned long vstart, unsigned long vend,
				int node, gfp_t gfp_mask)
{
	return pv_mmu_ops.alloc_vmap_area(size, align, vstart, vend,
							node, gfp_mask);
}
extern inline void pv__free_vmap_area(struct vmap_area *va)
{
	pv_mmu_ops.__free_vmap_area(va);
}
#ifdef	CONFIG_SMP
extern inline struct vm_struct **
pv_pcpu_get_vm_areas(const unsigned long *offsets,
			const size_t *sizes, int nr_vms,
			size_t align)
{
	return pv_mmu_ops.pcpu_get_vm_areas(offsets, sizes, nr_vms, align);
}
#endif	/* CONFIG_SMP */
static inline void
pv_free_pgd_range(struct mmu_gather *tlb,
			unsigned long addr, unsigned long end,
			unsigned long floor, unsigned long ceiling)
{
	pv_mmu_ops.free_pgd_range(tlb, addr, end, floor, ceiling);
}
extern inline void pv_free_unmap_vmap_area(struct vmap_area *va)
{
	pv_mmu_ops.free_unmap_vmap_area(va);
}

extern inline void pv_unmap_initmem(void *start, void *end)
{
	if (pv_mmu_ops.unmap_initmem) {
		pv_mmu_ops.unmap_initmem(start, end);
	}
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* Memory management mman */
static inline void free_mm(struct mm_struct *mm)
{
	pv_free_mm(mm);
}
static inline struct mm_struct *mm_init(struct mm_struct *mm,
					struct task_struct *p,
					struct user_namespace *user_ns)
{
	return pv_mm_init(mm, p, user_ns);
}
static inline int make_host_pages_valid(struct vm_area_struct *vma,
			e2k_addr_t start_addr, e2k_addr_t end_addr,
			bool chprot, bool flush)
{
	return pv_make_host_pages_valid(vma, start_addr, end_addr,
						chprot, flush);
}
static inline int
set_memory_attr_on_host(e2k_addr_t start, e2k_addr_t end,
				enum sma_mode mode)
{
	return pv_set_memory_attr_on_host(start, end, mode);
}
static inline int access_process_vm(struct task_struct *tsk,
			unsigned long addr, void *buf, int len,
			unsigned int gup_flags)
{
	return pv_access_process_vm(tsk, addr, buf, len, gup_flags);
}

static inline struct vmap_area *alloc_vmap_area(unsigned long size,
				unsigned long align,
				unsigned long vstart, unsigned long vend,
				int node, gfp_t gfp_mask)
{
	return pv_alloc_vmap_area(size, align, vstart, vend,
							node, gfp_mask);
}
static inline void __free_vmap_area(struct vmap_area *va)
{
	pv__free_vmap_area(va);
}
#ifdef	CONFIG_SMP
static inline struct vm_struct **
pcpu_get_vm_areas(const unsigned long *offsets,
			const size_t *sizes, int nr_vms,
			size_t align)
{
	return pv_pcpu_get_vm_areas(offsets, sizes, nr_vms, align);
}
#endif	/* CONFIG_SMP */
static inline void
free_pgd_range(struct mmu_gather *tlb,
		unsigned long addr, unsigned long end,
		unsigned long floor, unsigned long ceiling)
{
	pv_free_pgd_range(tlb, addr, end, floor, ceiling);
}
static inline void free_unmap_vmap_area(struct vmap_area *va)
{
	pv_free_unmap_vmap_area(va);
}
static inline void unmap_initmem(void *start, void *end)
{
	pv_unmap_initmem(start, end);
}
static inline int
remap_area_pages(unsigned long address, unsigned long phys_addr,
				unsigned long size, unsigned long flags)
{
	return pv_remap_area_pages(address, phys_addr, size, flags);
}

static inline int
host_guest_vmap_area(e2k_addr_t start, e2k_addr_t end)
{
	return pv_host_guest_vmap_area(start, end);
}
static inline int
unhost_guest_vmap_area(e2k_addr_t start, e2k_addr_t end)
{
	return pv_unhost_guest_vmap_area(start, end);
}

#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* __KERNEL__ */

#endif	/* __ASM_PARAVIRT_MMAN_H */
