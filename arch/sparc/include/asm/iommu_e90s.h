/* iommu.h: Definitions for the sun5 IOMMU.
 *
 * Copyright (C) 1996, 1999, 2007 David S. Miller (davem@davemloft.net)
 */
#ifndef _SPARC64_IOMMU_E90S_H
#define _SPARC64_IOMMU_E90S_H

#include <asm/io.h>
#include <asm/e90s.h>
#include <asm/iolinkmask.h>


#define L_IOMMU_CTRL		NBSR_IOMMU_CTRL
#define L_IOMMU_BA		NBSR_IOMMU_BA
#define L_IOMMU_FLUSH_ALL	NBSR_IOMMU_FLUSH_ALL
#define L_IOMMU_FLUSH_ADDR	NBSR_IOMMU_FLUSH_ADDR

#define IO_PAGE_SHIFT			13

#define MIN_IOMMU_WINSIZE	(32*1024*1024UL)
#define MAX_IOMMU_WINSIZE	(4*1024*1024*1024UL)
#define DFLT_IOMMU_WINSIZE	(2*1024*1024*1024UL)

#define	addr_to_flush(__addr)	(__addr)

static inline void l_iommu_write(unsigned node, unsigned link,
				  u32 val, unsigned long addr)
{
	__raw_writel(val, BASE_NODE0 + (BASE_NODE1 - BASE_NODE0) * node + addr);
}

static inline void l_iommu_set_ba(unsigned node, unsigned link, unsigned long *ba)
{
	l_iommu_write(node, link, (u32)(ba[0]), L_IOMMU_BA);
}

#define IOPTE_PAGE_MASK    0xffffffe0
#define IOPTE_CACHE   0x00000008 /* Cached                */
#define IOPTE_WRITE   0x00000004 /* Writeable             */
#define IOPTE_VALID   0x00000002 /* IOPTE is valid        */

#define pa_to_iopte(addr) (((unsigned long)(addr) >> (IO_PAGE_SHIFT - 5)) & IOPTE_PAGE_MASK)

static inline void *l_iommu_map(void *va, unsigned long size)
{
	return va;
}

#define l_iommu_supported()		1


#if defined(CONFIG_IOHUB_DOMAINS)
#define for_each_iommu		for_each_online_iohub
#else

#define for_each_iommu(domain)		\
		for ((domain) = 0; (domain) < 1; (domain)++)
#endif

#define l_domain_to_node	iohub_domain_to_node
#define l_domain_to_link	iohub_domain_to_link



#endif /* !(_SPARC64_IOMMU_E90S_H) */
