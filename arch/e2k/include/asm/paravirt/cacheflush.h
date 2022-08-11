#ifndef __ASM_PARAVIRT_CACHEFLUSH_H
#define __ASM_PARAVIRT_CACHEFLUSH_H

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

#ifdef	CONFIG_SMP
static inline void
pv_smp_flush_icache_range(e2k_addr_t start, e2k_addr_t end)
{
	pv_cpu_ops.smp_flush_icache_range(start, end);
}
static inline void
pv_smp_flush_icache_range_array(void *icache_range_arr)
{
	pv_cpu_ops.smp_flush_icache_range_array(icache_range_arr);
}
static inline void
pv_smp_flush_icache_page(struct vm_area_struct *vma, struct page *page)
{
	pv_cpu_ops.smp_flush_icache_page(vma, page);
}
static inline void
pv_smp_flush_icache_all(void)
{
	pv_cpu_ops.smp_flush_icache_all();
}
static inline void
pv_smp_flush_icache_kernel_line(e2k_addr_t addr)
{
	pv_cpu_ops.smp_flush_icache_kernel_line(addr);
}
#endif	/* CONFIG_SMP */

static inline void
pv_flush_DCACHE_range(void *addr, size_t len)
{
	pv_mmu_ops.flush_dcache_range(addr, len);
}
static inline void
pv_clear_DCACHE_L1_range(void *virt_addr, size_t len)
{
	pv_mmu_ops.clear_dcache_l1_range(virt_addr, len);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */
#ifdef	CONFIG_SMP
static inline void
smp_flush_icache_range(e2k_addr_t start, e2k_addr_t end)
{
	pv_smp_flush_icache_range(start, end);
}
static inline void
smp_flush_icache_range_array(struct icache_range_array *icache_range_arr)
{
	pv_smp_flush_icache_range_array(icache_range_arr);
}
static inline void
smp_flush_icache_page(struct vm_area_struct *vma, struct page *page)
{
	pv_smp_flush_icache_page(vma, page);
}
static inline void
smp_flush_icache_all(void)
{
	pv_smp_flush_icache_all();
}
static inline void
smp_flush_icache_kernel_line(e2k_addr_t addr)
{
	pv_smp_flush_icache_kernel_line(addr);
}
#endif	/* CONFIG_SMP */

static inline void
flush_DCACHE_range(void *addr, size_t len)
{
	pv_flush_DCACHE_range(addr, len);
}
static inline void
clear_DCACHE_L1_range(void *virt_addr, size_t len)
{
	pv_clear_DCACHE_L1_range(virt_addr, len);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* __ASM_PARAVIRT_CACHEFLUSH_H */
