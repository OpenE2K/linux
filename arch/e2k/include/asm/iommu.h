#ifndef _E2K_IOMMU_H
#define _E2K_IOMMU_H

#include <linux/dma-mapping.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/iolinkmask.h>

#define L_IOMMU_CTRL		SIC_iommu_ctrl
#define L_IOMMU_FLUSH_ALL	SIC_iommu_flush
#define L_IOMMU_FLUSH_ADDR	SIC_iommu_flushP
#define L_IOMMU_ERROR		SIC_iommu_err
#define L_IOMMU_ERROR1		SIC_iommu_err1

#define IO_PAGE_SHIFT		12

#define IOMMU_TABLES_NR		2
#define IOMMU_HIGH_TABLE	0
#define IOMMU_LOW_TABLE		1

static inline int dev_to_table(struct device *dev)
{
	return dma_get_mask(dev) > DMA_BIT_MASK(32) ?
			IOMMU_HIGH_TABLE : IOMMU_LOW_TABLE;
}

#define MIN_IOMMU_WINSIZE	(4*1024*1024*1024UL)
#define MAX_IOMMU_WINSIZE	(512*1024*1024*1024UL)
#define DFLT_IOMMU_WINSIZE	(4*1024*1024*1024UL)

#define addr_to_flush(__a) ((__a) >> IO_PAGE_SHIFT)

static inline void l_iommu_write(unsigned node, unsigned link,
				  u32 val, unsigned long addr)
{
	sic_write_node_iolink_nbsr_reg(node, link, addr, val);
}

static inline u32 l_iommu_read(unsigned node, unsigned link,
				 unsigned long addr)
{
	return sic_read_node_iolink_nbsr_reg(node, link, addr);
}

static inline void l_iommu_set_ba(unsigned node, unsigned link, unsigned long *ba)
{
	l_iommu_write(node, link, (u32)(ba[IOMMU_LOW_TABLE]), SIC_iommu_ba_lo);
	l_iommu_write(node, link, (u32)(ba[IOMMU_HIGH_TABLE]), SIC_iommu_ba_hi);
}

#define IOPTE_PAGE_MASK    0xfffffff0
#define IOPTE_CACHE   0x00000004 /* Cached                */
#define IOPTE_WRITE   0x00000001 /* Writeable             */
#define IOPTE_VALID   0x00000002 /* IOPTE is valid        */

#define pa_to_iopte(addr) (((unsigned long)(addr) >> 8) & IOPTE_PAGE_MASK)

static inline void *l_iommu_map(void *va, unsigned long size)
{
	return va;
}

#define l_iommu_supported() HAS_MACHINE_E2K_IOMMU


#define for_each_iommu		for_each_online_iohub
#define l_domain_to_node	iohub_domain_to_node
#define l_domain_to_link	iohub_domain_to_link

typedef struct { unsigned iopte; } iopte_t;

#define iopte_val(x)	((x).iopte)

#endif /* !(_E2K_IOMMU_H) */
