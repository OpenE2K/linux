#ifndef _E2K_IOMMU_H
#define _E2K_IOMMU_H

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/dma-mapping.h>

#include <asm/set_memory.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/iolinkmask.h>

#include <asm-l/swiotlb.h>


#ifdef CONFIG_PM_SLEEP
extern void l_iommu_stop_all(void);
#endif

#define L_IOMMU_CTRL		SIC_iommu_ctrl
#define L_IOMMU_FLUSH_ALL	SIC_iommu_flush
#define L_IOMMU_FLUSH_ADDR	SIC_iommu_flushP
#define L_IOMMU_ERROR		SIC_iommu_err
#define L_IOMMU_ERROR1		SIC_iommu_err1

#define IO_PAGE_SHIFT		12

#define IOMMU_TABLES_NR		2
#define IOMMU_LOW_TABLE		0
#define IOMMU_HIGH_TABLE	1

typedef struct { unsigned iopte; } iopte_t;

#define iopte_val(x)	((x).iopte)


#define MIN_IOMMU_WINSIZE	(4*1024*1024*1024UL)
#define MAX_IOMMU_WINSIZE	(512*1024*1024*1024UL)
#define DFLT_IOMMU_WINSIZE	(4*1024*1024*1024UL)

#define IOPTE_PAGE_MASK		0xfffffff0
#define IOPTE_CACHE		0x00000004 /* Cached                */
#define IOPTE_STP_PREF_IOPTE	0x00000004 /* stop prefetch iopte */
#define IOPTE_WRITE		0x00000001 /* Writeable             */
#define IOPTE_VALID		0x00000002 /* IOPTE is valid        */

#define pa_to_iopte(addr) (((unsigned long)(addr) >> 8) & IOPTE_PAGE_MASK)
#define iopte_to_pa(iopte) (((unsigned long)(iopte) & IOPTE_PAGE_MASK) << 8)


#define addr_to_flush(__a) ((__a) >> IO_PAGE_SHIFT)

static inline void l_iommu_write(unsigned node, u32 val, unsigned long addr)
{
	sic_write_node_iolink_nbsr_reg(node, 0, addr, val);
}

static inline u32 l_iommu_read(unsigned node, unsigned long addr)
{
	return sic_read_node_iolink_nbsr_reg(node, 0, addr);
}

static inline void l_iommu_set_ba(unsigned node, unsigned long *ba)
{
	l_iommu_write(node, pa_to_iopte(ba[IOMMU_LOW_TABLE]), SIC_iommu_ba_lo);
	l_iommu_write(node, pa_to_iopte(ba[IOMMU_HIGH_TABLE]), SIC_iommu_ba_hi);
}

#define l_prefetch_iopte_supported	l_prefetch_iopte_supported
static inline int l_prefetch_iopte_supported(void)
{
	return (int)machine.native_iset_ver >= ELBRUS_8C2_ISET;
}

static inline void l_prefetch_iopte(iopte_t *iopte, int prefetch)
{
	if (prefetch)
		iopte_val(iopte[0]) &= ~IOPTE_STP_PREF_IOPTE;
	else
		iopte_val(iopte[0]) |= IOPTE_STP_PREF_IOPTE;
}

static inline void *l_iommu_map_table(void *va, unsigned long size)
{
	phys_addr_t start = __pa(va);
	pgprot_t prot = pgprot_writecombine(PAGE_KERNEL);
	struct page **pages;
	phys_addr_t page_start;
	unsigned int page_count;
	unsigned int i;
	void *vaddr;

	if (!cpu_has(CPU_HWBUG_IOMMU))
		return va;

	page_start = start - offset_in_page(start);
	page_count = DIV_ROUND_UP(size + offset_in_page(start), PAGE_SIZE);

	pages = kmalloc_array(page_count, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return NULL;

	for (i = 0; i < page_count; i++) {
		phys_addr_t addr = page_start + i * PAGE_SIZE;
		pages[i] = pfn_to_page(addr >> PAGE_SHIFT);
	}

	vaddr = vmap(pages, page_count, VM_MAP, prot);
	kfree(pages);

	return vaddr;
}

static inline void *l_iommu_unmap_table(void *va)
{
	void *p;
	if (!cpu_has(CPU_HWBUG_IOMMU))
		return va;
	p = page_address(vmalloc_to_page(va)) + offset_in_page(va);
	vunmap(va);
	return p;
}

static inline int l_iommu_get_table(unsigned long iova)
{
	return iova & (~0UL << 32) ? IOMMU_HIGH_TABLE : IOMMU_LOW_TABLE;
}

#define boot_l_iommu_supported()	BOOT_HAS_MACHINE_L_IOMMU
#define l_iommu_supported()		HAS_MACHINE_L_IOMMU

extern int l_iommu_no_numa_bug;
extern int l_iommu_force_numa_bug_on;
extern unsigned long l_iommu_win_sz;

#define l_iommu_has_numa_bug() (l_iommu_force_numa_bug_on || \
		(nr_online_nodes > 1 && l_iommu_no_numa_bug == 0 && \
		cpu_has(CPU_HWBUG_CANNOT_DO_DMA_IN_NEIGHBOUR_NODE)))

#define	L_PGSIZE_BITMAP SZ_4K

/* software MMU support */

#define	E2K_SWIOTLB_DEFAULT_SIZE	(64 * 1024 * 1024)
#define	E2K_SWIOTLB_MIN_SIZE		(8 * 1024 * 1024)
#define	L_SWIOTLB_DEFAULT_SIZE		E2K_SWIOTLB_DEFAULT_SIZE
#define	L_SWIOTLB_MIN_SIZE		E2K_SWIOTLB_MIN_SIZE

#define SWIOTLB_POOL_DEFAULT_NUM	64
#define SWIOTLB_ISA_POOL_DEFAULT_NUM	16
#define	SWIOTLB_POOL_DEFAULT_SIZE	(SWIOTLB_POOL_DEFAULT_NUM * PAGE_SIZE)
#define	SWIOTLB_ISA_POOL_DEFAULT_SIZE	\
		(SWIOTLB_ISA_POOL_DEFAULT_NUM * PAGE_SIZE)

#endif /* !(_E2K_IOMMU_H) */
