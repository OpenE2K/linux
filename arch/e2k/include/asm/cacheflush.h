/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * The functions and defines necessary to allocate page tables.
 */

#ifndef _E2K_CACHEFLUSH_H
#define _E2K_CACHEFLUSH_H

#include <asm/debug_print.h>
#include <asm/mmu_regs.h>
#include <asm/machdep.h>
#include <asm/tlbflush.h> /* flush_tlb_kernel_range() */

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
 * Caches are clever on the E2K...
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
/*
 * ...sometimes too clever for their own good
 *
 * Half-speculative loads can write empty PTE value to DTLB if they
 * accidentally hit into unmapped area. After mapping that area
 * consecutive h.-s. loads would return a diagnostic value causing
 * kernel to crash. So we flush those empty PTEs from DTLB here.
 *
 * For guest kernels without hardware virualization support we have
 * a similar situation.  Even if such kernel is built without
 * CONFIG_HALF_SPECULATIVE_KERNEL, modern lcc versions will still
 * use half-speculative loads (although rather carefully, just for
 * addresses that are known to be good).  So there might be a h.-s.
 * load from VMALLOC area, and we need to have shadow page tables
 * updated with valid bit to avoid putting empty PTEs into DTLB.
 */
#define flush_cache_vmap(start, end) \
do { \
	if (IS_ENABLED(CONFIG_HALF_SPECULATIVE_KERNEL) || \
			IS_ENABLED(CONFIG_KVM_GUEST_KERNEL)) \
		flush_tlb_kernel_range(start, end); \
} while (0)
#define flush_cache_vunmap(start, end)		do { } while (0)

extern void native_flush_icache_all(void);
extern void native_flush_icache_range(e2k_addr_t start, e2k_addr_t end);
extern void native_flush_icache_page(struct vm_area_struct *vma,
				     struct page *page);

#define flush_icache_begin()	flush_DCACHE_line_begin()
#define flush_icache_end()	flush_DCACHE_line_end(true)
#define	flush_icache_range(start, end) \
do { \
	flush_icache_begin(); \
	__flush_icache_range((start), (end)); \
	flush_icache_end(); \
} while (0)
#define	flush_icache_page(vma, page) \
do { \
	flush_icache_begin(); \
	__flush_icache_page(vma, page); \
	flush_icache_end(); \
} while (0)

#ifndef CONFIG_SMP
#define	smp_flush_icache_all()

#define flush_icache_all()		__flush_icache_all()

#else	/* CONFIG_SMP */
extern void smp_flush_icache_all(void);

#define flush_icache_all()		smp_flush_icache_all()
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

	DebugMR("Flush DCACHE range: virtual addr 0x%lx, len %lx\n", (unsigned long) addr, len);

	/* Although L1 cache line is 32 bytes, coherency works
	 * with 64 bytes granularity.  So a single flush_dc_line
	 * can flush _two_ lines from L1 */
	stride = SMP_CACHE_BYTES;

	end = PTR_ALIGN(addr + len, SMP_CACHE_BYTES);

	flush_DCACHE_line_begin();
	for (cp = addr; cp < end; cp += stride)
		__flush_DCACHE_line((unsigned long) cp);
	flush_DCACHE_line_end(false);
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

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/cacheflush.h>
#else	/* !CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without virtualization support */
/* or native kernel with virtualization support */
static inline void
__flush_icache_all(void)
{
	flush_ICACHE_all();
}
static inline void
__flush_icache_range(e2k_addr_t start, e2k_addr_t end)
{
	native_flush_icache_range(start, end);
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
#endif	/* CONFIG_KVM_GUEST_KERNEL */

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

extern u8 get_tag_and_color_from_user_page(const void *src);

static inline void copy_from_user_page(struct vm_area_struct *vma,
		struct page *page, unsigned long vaddr, void *dst,
		const void *src, size_t len)
{
	if (test_ts_flag(TS_PTRACE_WANTS_TAG)) {
		*(unsigned long *)dst = get_tag_and_color_from_user_page(src);
		return;
	}
	memcpy(dst, src, len);
}

#endif /* _E2K_CACHEFLUSH_H */
