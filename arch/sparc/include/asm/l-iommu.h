#ifndef _SPARC64_IOMMU_E90S_H
#define _SPARC64_IOMMU_E90S_H

#include <asm/io.h>
#include <asm/e90s.h>
#include <asm/iolinkmask.h>

#include <asm-l/swiotlb.h>

#define L_IOMMU_CTRL		NBSR_IOMMU_CTRL
#define L_IOMMU_BA		NBSR_IOMMU_BA
#define L_IOMMU_FLUSH_ALL	NBSR_IOMMU_FLUSH_ALL
#define L_IOMMU_FLUSH_ADDR	NBSR_IOMMU_FLUSH_ADDR

#define IO_PAGE_SHIFT			13

#define MIN_IOMMU_WINSIZE	(32*1024*1024UL)
#define MAX_IOMMU_WINSIZE	(4*1024*1024*1024UL)
#define DFLT_IOMMU_WINSIZE	(2*1024*1024*1024UL)

#define	addr_to_flush(__addr)	(__addr)

#define IOPTE_PAGE_MASK    0xffffffe0
#define IOPTE_CACHE   0x00000008 /* Cached                */
#define IOPTE_WRITE   0x00000004 /* Writeable             */
#define IOPTE_VALID   0x00000002 /* IOPTE is valid        */

#define pa_to_iopte(addr) (((unsigned long)(addr) >> (IO_PAGE_SHIFT - 5)) \
						& IOPTE_PAGE_MASK)
#define iopte_to_pa(iopte) (((unsigned long)(iopte) & IOPTE_PAGE_MASK) \
						<< (IO_PAGE_SHIFT - 5))

static inline void l_iommu_write(unsigned node, u32 val, unsigned long addr)
{
	nbsr_writel(val, addr, node);
}

static inline void l_iommu_set_ba(unsigned node, unsigned long *ba)
{
	l_iommu_write(node, (u32)pa_to_iopte(ba[0]), L_IOMMU_BA);
}

static inline void *l_iommu_map_table(void *va, unsigned long size)
{
	return va;
}

static inline void *l_iommu_unmap_table(void *va)
{
	return va;
}

static inline int l_iommu_get_table(unsigned long iova)
{
	return 0;
}

#define l_iommu_supported()		1


#define	L_PGSIZE_BITMAP SZ_8K

/* software MMU support */

#define	E90S_SWIOTLB_DEFAULT_SIZE	(64 * 1024 * 1024)
#define	L_SWIOTLB_DEFAULT_SIZE		E90S_SWIOTLB_DEFAULT_SIZE

#endif /* !(_SPARC64_IOMMU_E90S_H) */
