/*
 * pgalloc.h: the functions and defines necessary to allocate
 * page tables.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */
#ifndef _E2K_CACHEFLUSH_H
#define _E2K_CACHEFLUSH_H

#include <asm/debug_print.h>
#include <asm/mmu_regs.h>
#include <asm/machdep.h>

#include <uapi/asm/e2k_syswork.h>
#include <asm/mmu_regs_access.h>

#undef	DEBUG_MR_MODE
#undef	DebugMR
#define	DEBUG_MR_MODE		0	/* MMU registers access */
#define DebugMR(...)		DebugPrint(DEBUG_MR_MODE, ##__VA_ARGS__)

/*
 * Caches flushing routines.  This is the kind of stuff that can be very
 * expensive, so should try to avoid them whenever possible.
 */

/*
 * Caches aren't brain-dead on the E2K
 */
#define flush_cache_all()			do { } while (0)
#define flush_cache_mm(mm)			do { } while (0)
#define flush_cache_dup_mm(mm)			do { } while (0)
#define flush_cache_range(mm, start, end)	do { } while (0)
#define flush_cache_page(vma, vmaddr, pfn)	do { } while (0)
#define flush_page_to_ram(page)			do { } while (0)
#define ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE	0
#define flush_dcache_page(page)			do { } while (0)
#define flush_dcache_mmap_lock(mapping)		do { } while (0)
#define flush_dcache_mmap_unlock(mapping)	do { } while (0)
#define flush_cache_vmap(start, end)		do { } while (0)
#define flush_cache_vunmap(start, end)		do { } while (0)

/*
 * Invalidate all ICAHES of the host processor
 */

typedef struct icache_range_array {
	icache_range_t		*ranges;
	int			count;
	struct mm_struct	*mm;
} icache_range_array_t;

extern void native_flush_icache_all(void);
extern void native_flush_icache_range(e2k_addr_t start, e2k_addr_t end);
extern void native_flush_icache_range_array(
			icache_range_array_t *icache_range_arr);
extern void native_flush_icache_page(struct vm_area_struct *vma,
				     struct page *page);

#ifndef CONFIG_SMP
#define flush_icache_all()		__flush_icache_all()
#define	flush_icache_range(start, end)	__flush_icache_range(start, end)
#define	flush_icache_range_array	__flush_icache_range_array
#define	flush_icache_page(vma, page)	__flush_icache_page(vma, page)

#define	smp_flush_icache_all()
#define	native_smp_flush_icache_range_array(icache_range_arr)
#define	native_smp_flush_icache_page(vma, page)
#define	native_smp_flush_icache_kernel_line(addr)
#else	/* CONFIG_SMP */
extern void smp_flush_icache_all(void);
extern void native_smp_flush_icache_range_array(
			icache_range_array_t *icache_range_arr);
extern void native_smp_flush_icache_page(struct vm_area_struct *vma,
			struct page *page);
extern void native_smp_flush_icache_kernel_line(e2k_addr_t addr);

#define flush_icache_all()		smp_flush_icache_all()
#define	flush_icache_range(start, end)	__flush_icache_range(start, end);
#define flush_icache_range_array	smp_flush_icache_range_array
#define	flush_icache_page(vma, page)	__flush_icache_page(vma, page);

#endif	/* ! (CONFIG_SMP) */

/*
 * Some usefull routines to flush caches
 */

/*
 * Write Back and Invalidate all caches (instruction and data).
 * "local_" versions work on the calling CPU only.
 */
extern void local_write_back_cache_all(void);
extern void local_write_back_cache_range(unsigned long start, size_t size);
extern void write_back_cache_all(void);
extern void write_back_cache_range(unsigned long start, size_t size);

/*
 * Flush multiple DCACHE lines
 */
static inline void
native_flush_DCACHE_range(void *addr, size_t len)
{
	char *cp, *end;
	unsigned long stride;

	DebugMR("Flush DCACHE range: virtual addr 0x%lx, len %lx\n", addr, len);

	/* Although L1 cache line is 32 bytes, coherency works
	 * with 64 bytes granularity.  So a single flush_dc_line
	 * can flush _two_ lines from L1 */
	stride = SMP_CACHE_BYTES;

	end = PTR_ALIGN(addr + len, SMP_CACHE_BYTES);

	E2K_WAIT_ST;
	for (cp = addr; cp < end; cp += stride)
		flush_DCACHE_line((unsigned long) cp);
	E2K_WAIT_FLUSH;
}

/*
 * Clear multiple DCACHE L1 lines
 */
static inline void
native_clear_DCACHE_L1_range(void *virt_addr, size_t len)
{
	unsigned long cp;
	unsigned long end = (unsigned long) virt_addr + len;
	unsigned long stride;

	stride = cacheinfo_get_l1d_line_size();

	for (cp = (u64) virt_addr; cp < end; cp += stride)
		clear_DCACHE_L1_line(cp);
}

#if	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/cacheflush.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native guest kernel */
#include <asm/kvm/guest/cacheflush.h>
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without virtualization support */
/* or native kernel with virtualization support */
static inline void
smp_flush_icache_range_array(icache_range_array_t *icache_range_arr)
{
	native_smp_flush_icache_range_array(icache_range_arr);
}
static inline void
smp_flush_icache_page(struct vm_area_struct *vma, struct page *page)
{
	native_smp_flush_icache_page(vma, page);
}
static inline void
smp_flush_icache_kernel_line(e2k_addr_t addr)
{
	native_smp_flush_icache_kernel_line(addr);
}

static inline void
__flush_icache_all(void)
{
	native_flush_icache_all();
}
static inline void
__flush_icache_range(e2k_addr_t start, e2k_addr_t end)
{
	native_flush_icache_range(start, end);
}
static inline void
__flush_icache_range_array(icache_range_array_t *icache_range_arr)
{
	native_flush_icache_range_array(icache_range_arr);
}
static inline void
__flush_icache_page(struct vm_area_struct *vma, struct page *page)
{
	native_flush_icache_page(vma, page);
}

static inline void
flush_DCACHE_range(void *addr, size_t len)
{
	native_flush_DCACHE_range(addr, len);
}
static inline void
clear_DCACHE_L1_range(void *virt_addr, size_t len)
{
	native_clear_DCACHE_L1_range(virt_addr, len);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

static inline void copy_to_user_page(struct vm_area_struct *vma,
		struct page *page, unsigned long vaddr, void *dst,
		const void *src, unsigned long len)
{
	if (IS_ALIGNED((unsigned long) dst, 8) &&
	    IS_ALIGNED((unsigned long) src, 8) && IS_ALIGNED(len, 8)) {
		tagged_memcpy_8(dst, src, len);
	} else {
		memcpy(dst, src, len);
	}
	flush_icache_range((unsigned long) dst, (unsigned long) dst + len);
}

static inline void copy_from_user_page(struct vm_area_struct *vma,
		struct page *page, unsigned long vaddr, void *dst,
		const void *src, size_t len)
{
	if (IS_ALIGNED((unsigned long) dst, 8) &&
	    IS_ALIGNED((unsigned long) src, 8) && IS_ALIGNED(len, 8)) {
		tagged_memcpy_8(dst, src, len);
	} else {
		memcpy(dst, src, len);
	}
}

#endif /* _E2K_CACHEFLUSH_H */
