#ifndef __ASM_KVM_GUEST_CACHEFLUSH_H
#define __ASM_KVM_GUEST_CACHEFLUSH_H

#include <linux/types.h>

#ifndef __ASSEMBLY__

struct icache_range_array;
struct vm_area_struct;
struct page;

#ifdef	CONFIG_SMP
/*
 * Guest kernel functions can be run on any guest user processes and can have
 * arbitrary MMU contexts to track which on host is not possible, therefore
 * it is necessary to flush all instruction caches
 */
extern void smp_flush_icache_all(void);

static inline void
kvm_smp_flush_icache_range(e2k_addr_t start, e2k_addr_t end)
{
	smp_flush_icache_all();
}
static inline void
kvm_smp_flush_icache_range_array(struct icache_range_array *icache_range_arr)
{
	smp_flush_icache_all();
}
static inline void
kvm_smp_flush_icache_page(struct vm_area_struct *vma, struct page *page)
{
	smp_flush_icache_all();
}
static inline void
kvm_smp_flush_icache_kernel_line(e2k_addr_t addr)
{
	smp_flush_icache_all();
}
#endif	/* CONFIG_SMP */

extern void kvm_flush_dcache_line(e2k_addr_t virt_addr);
extern void kvm_clear_dcache_l1_set(e2k_addr_t virt_addr, unsigned long set);
extern void kvm_flush_dcache_range(void *addr, size_t len);
extern void kvm_clear_dcache_l1_range(void *virt_addr, size_t len);
extern void kvm_write_dcache_l2_reg(unsigned long reg_val,
					int reg_num, int bank_num);
extern unsigned long kvm_read_dcache_l2_reg(int reg_num, int bank_num);
extern void kvm_flush_icache_all(void);
extern void kvm_flush_icache_range(e2k_addr_t start, e2k_addr_t end);
extern void kvm_flush_icache_range_array(
			struct icache_range_array *icache_range_arr);
extern void kvm_flush_icache_page(struct vm_area_struct *vma,
				  struct page *page);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#ifdef	CONFIG_SMP
static inline void
smp_flush_icache_range(e2k_addr_t start, e2k_addr_t end)
{
	kvm_smp_flush_icache_range(start, end);
}
static inline void
smp_flush_icache_range_array(struct icache_range_array *icache_range_arr)
{
	kvm_smp_flush_icache_range_array(icache_range_arr);
}
static inline void
smp_flush_icache_page(struct vm_area_struct *vma, struct page *page)
{
	kvm_smp_flush_icache_page(vma, page);
}
static inline void
smp_flush_icache_kernel_line(e2k_addr_t addr)
{
	kvm_smp_flush_icache_kernel_line(addr);
}
#endif	/* CONFIG_SMP */

static inline void
flush_DCACHE_range(void *addr, size_t len)
{
	kvm_flush_dcache_range(addr, len);
}
static inline void
clear_DCACHE_L1_range(void *virt_addr, size_t len)
{
	kvm_clear_dcache_l1_range(virt_addr, len);
}
static inline void
__flush_icache_all(void)
{
	kvm_flush_icache_all();
}
static inline void
__flush_icache_range(e2k_addr_t start, e2k_addr_t end)
{
	kvm_flush_icache_range(start, end);
}
static inline void
__flush_icache_range_array(struct icache_range_array *icache_range_arr)
{
	kvm_flush_icache_range_array(icache_range_arr);
}
static inline void
__flush_icache_page(struct vm_area_struct *vma, struct page *page)
{
	kvm_flush_icache_page(vma, page);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* !__ASSEMBLY__ */

#endif	/* __ASM_KVM_GUEST_CACHEFLUSH_H */
