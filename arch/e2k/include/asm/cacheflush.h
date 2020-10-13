/* $Id: cacheflush.h,v 1.7 2007/07/09 11:12:46 atic Exp $
 * pgalloc.h: the functions and defines necessary to allocate
 * page tables.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */
#ifndef _E2K_CACHEFLUSH_H
#define _E2K_CACHEFLUSH_H

#include <linux/mm.h>
#include <asm/machdep.h>
#include <asm/mmu_regs_access.h>


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

typedef struct icache_range {
	e2k_addr_t	start;
	e2k_addr_t	end;
} icache_range_t;

typedef struct icache_range_array {
	icache_range_t		*ranges;
	int			count;
	struct mm_struct	*mm;
} icache_range_array_t;

extern	void __flush_icache_all(void);
extern	void __flush_icache_range(e2k_addr_t start, e2k_addr_t end);
extern	void __flush_icache_range_array(
				icache_range_array_t *icache_range_arr);
extern	void __flush_icache_page(struct vm_area_struct *vma, struct page *page);

#ifndef CONFIG_SMP
#define flush_icache_all()		__flush_icache_all()
#define	flush_icache_range(start, end)	__flush_icache_range(start, end)
#define	flush_icache_range_array	__flush_icache_range_array
#define	flush_icache_page(vma, page)	__flush_icache_page(vma, page)
#else	/* CONFIG_SMP */
extern	void smp_flush_icache_all(void);
extern	void smp_flush_icache_range(e2k_addr_t start, e2k_addr_t end);
extern	void smp_flush_icache_range_array(
			icache_range_array_t *icache_range_arr);
extern	void smp_flush_icache_page(struct vm_area_struct *vma,
				struct page *page);

#define flush_icache_all()		smp_flush_icache_all()

#define	flush_icache_range(start, end)			\
({							\
	if (machine.iset_ver >= E2K_ISET_V3)		\
		__flush_icache_range(start, end);	\
	else						\
		smp_flush_icache_range(start, end);	\
})

#define flush_icache_range_array	smp_flush_icache_range_array

#define	flush_icache_page(vma, page)			\
({							\
	if (machine.iset_ver >= E2K_ISET_V3)		\
		__flush_icache_page(vma, page);		\
	else						\
		smp_flush_icache_page(vma, page);	\
})

#endif	/* ! (CONFIG_SMP) */

#define copy_to_user_page(vma, page, vaddr, dst, src, len) \
		memcpy(dst, src, len)
#define copy_from_user_page(vma, page, vaddr, dst, src, len) \
		memcpy(dst, src, len)

/*
 * Some usefull routines to flush caches of the host processor
 */

/*
 * Invalidate all caches (instruction and data) of the host processor
 * or Write Back and Invalidate ones
 */
extern void __invalidate_cache_all(void);
extern void __write_back_cache_all(void);

extern int change_page_attr(struct page *page, int numpages, pgprot_t prot);
extern void global_flush_tlb(void);
extern void __init init_change_page_attr(void);

#ifdef CONFIG_DEBUG_PAGEALLOC
/* internal debugging function */
void kernel_map_pages(struct page *page, int numpages, int enable);
#endif


/*
 * Flush multiple DCACHE lines
 */
static inline void
flush_DCACHE_range(void *addr, size_t len)
{
	char *cp;
	char *end = addr + len;
	unsigned long stride;

	DebugMR("Flush DCACHE range: virtual addr 0x%lx, len %lx\n", addr, len);

	stride = cpu_data[raw_smp_processor_id()].L1_bytes;
	if (!stride)
		stride = 32;

	E2K_WAIT_ST;
	for (cp = addr; cp < end; cp += stride)
		E2K_WRITE_MAS_D(cp, 0UL, MAS_DCACHE_LINE_FLUSH);
	E2K_WAIT_FLUSH;
}

/*
 * Clear multiple DCACHE L1 lines
 */
static inline void
clear_DCACHE_L1_range(void *virt_addr, size_t len)
{
	unsigned long cp;
	unsigned long end = (unsigned long) virt_addr + len;
	unsigned long stride;

	stride = cpu_data[raw_smp_processor_id()].L1_bytes;
	if (!stride)
		stride = 32;

	for (cp = (u64) virt_addr; cp < end; cp += stride)
		clear_DCACHE_L1_line(cp);
}


#endif /* _E2K_CACHEFLUSH_H */
