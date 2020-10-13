/* iommu.c: Generic sparc64 IOMMU support.
 *
 * Copyright (C) 1999, 2007, 2008 David S. Miller (davem@davemloft.net)
 * Copyright (C) 1999, 2000 Jakub Jelinek (jakub@redhat.com)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/iommu-helper.h>
#include <linux/bitmap.h>
#include <linux/topology.h>
#include <linux/slab.h>

#ifdef CONFIG_PCI
#include <linux/pci.h>
#endif
#ifdef	CONFIG_SWIOTLB
#include <linux/swiotlb.h>
#endif

#include <asm/iommu.h>

#undef	DEBUG_IOMMU_MODE
#undef	DebugIOMMU
#define	DEBUG_IOMMU_MODE	0	/* IOMMU init */
#define	DebugIOMMU(fmt, args...)			\
		({ if (DEBUG_IOMMU_MODE)		\
			pr_debug(fmt, ##args); })

#ifndef	IOMMU_TABLES_NR
#define IOMMU_TABLES_NR		1

#define dev_to_table(dev)	0

#endif

#ifndef L_IOMMU_DUMMY_PAGE
#define L_IOMMU_DUMMY_PAGE	0
#endif


#define SG_ENT_PHYS_ADDRESS(__SG)	(page_to_phys(sg_page(__SG)) + (__SG)->offset)

struct l_iommu_arena {
	unsigned long *map;
	unsigned int hint;
	unsigned int limit;
};

struct l_iommu {
	/* This protects the controller's IOMMU and all
	 * streaming buffers underneath.
	 */
#ifdef IOMMU_USES_MUTEX
	spinlock_t	lock;
#else
	raw_spinlock_t lock;
#endif
	struct l_iommu_arena arena;

	/* IOMMU page table, a linear array of ioptes. */
	iopte_t *page_table;	/* The page table itself. */

	/* Base PCI memory space address where IOMMU mappings
	 * begin.
	 */
	unsigned long page_table_map_base;
	unsigned long dummy_page;
	unsigned long dummy_page_pa;
};

#ifdef IOMMU_USES_MUTEX
#define	lock_iommu(iommu, flags)	spin_lock(&iommu->lock)
#define unlock_iommu(iommu, flags)	spin_unlock(&iommu->lock)
#else
#define lock_iommu(iommu, flags)	raw_spin_lock_irqsave(&iommu->lock, flags)
#define unlock_iommu(iommu, flags)	raw_spin_unlock_irqrestore(&iommu->lock, flags)
#endif

static struct l_iommu *l_iommu[MAX_NUMNODES][MAX_NODE_IOLINKS][IOMMU_TABLES_NR];

static struct l_iommu *dev_to_iommu(struct device *dev)
{
	unsigned i = 0, j = 0, k = 0;
#ifdef CONFIG_NUMA
#ifdef CONFIG_PCI
	if (dev_is_pci(dev)) {
		struct pci_bus *bus = to_pci_dev(dev)->bus;
		i = pcibus_to_node(bus);
		j = pcibus_to_link(bus);
	} else
#endif
	{
		i = dev_to_node(dev);
		j = dev_to_link(dev);
	}
	k = dev_to_table(dev);
	BUG_ON(i > MAX_NUMNODES);
	BUG_ON(j > MAX_NODE_IOLINKS);
	BUG_ON(!l_iommu[i][j][k]);
#endif

	DebugIOMMU("dev_to_iommu() node %d io link %d table %d iommu %p\n",
		i, j, k, l_iommu[i][j][k]);
	return l_iommu[i][j][k];
}

/*
 * These give mapping size of each iommu pte/tlb.
 */
#define IO_PAGE_SIZE			(1UL << IO_PAGE_SHIFT)
#define IO_PAGE_MASK			(~(IO_PAGE_SIZE-1))
#define IO_PAGE_ALIGN(addr)		ALIGN(addr, IO_PAGE_SIZE)

static inline int is_span_boundary(unsigned long entry,
				   unsigned long shift,
				   unsigned long boundary_size,
				   struct scatterlist *outs,
				   struct scatterlist *sg)
{
	unsigned long addr = SG_ENT_PHYS_ADDRESS(outs);
	int nr = iommu_num_pages(addr, outs->dma_length + sg->length,
				 IO_PAGE_SIZE);

	return iommu_is_span_boundary(entry, nr, shift, boundary_size);
}

#define IOMMU_CTRL_IMPL     0xf0000000	/* Implementation */
#define IOMMU_CTRL_VERS     0x0f000000	/* Version */
#define IOMMU_CTRL_CASHABLE_TTE	    0x00000020	/* Cachable TTE */
#define IOMMU_CTRL_RNGE     0x0000001c	/* Mapping RANGE */
#define IOMMU_CTRL_ENAB     0x00000001	/* IOMMU Enable */

#define IOMMU_RNGE_OFF      2

#define IOPTE_DEFAULT (IOPTE_VALID | IOPTE_CACHE)

/* Must be invoked under the IOMMU lock. */
static void __iommu_flushall(unsigned node, unsigned link)
{
	l_iommu_write(node, link, 0, L_IOMMU_FLUSH_ALL);
}

static inline void iommu_flush(struct l_iommu *iommu, struct device *dev,
			       dma_addr_t addr)
{
#if defined(CONFIG_NUMA)
	unsigned node = dev_to_node(dev);
#else
	unsigned node = 0;
#endif

	l_iommu_write(node, dev_to_link(dev),
		      addr_to_flush(addr), L_IOMMU_FLUSH_ADDR);
}

static inline void iommu_dummy_flush(struct l_iommu *iommu, struct device *dev,
			       dma_addr_t addr)
{
#if defined(CONFIG_NUMA)
	unsigned node = dev_to_node(dev);
#else
	unsigned node = 0;
#endif

	if (L_IOMMU_DUMMY_PAGE) {
		wmb();
		l_iommu_write(node, dev_to_link(dev),
			addr_to_flush(addr), L_IOMMU_FLUSH_ADDR);
		wmb();
	}
}
static inline void iopte_make_dummy(struct l_iommu *iommu, iopte_t *iopte)
{
	if (L_IOMMU_DUMMY_PAGE)
		iopte_val(*iopte) = IOPTE_DEFAULT |
		    IOPTE_WRITE | pa_to_iopte(iommu->dummy_page_pa);
	else
		iopte_val(*iopte) = 0;
}

/* Based almost entirely upon the ppc64 iommu allocator.  If you use the 'handle'
 * facility it must all be done in one pass while under the iommu lock.
 */
unsigned long iommu_range_alloc(struct device *dev,
				struct l_iommu *iommu,
				unsigned long npages, unsigned long *handle)
{
	unsigned long n, end, start, limit, boundary_size;
	struct l_iommu_arena *arena = &iommu->arena;
	int pass = 0;

	/* This allocator was derived from x86_64's bit string search */

	/* Sanity check */
	if (unlikely(npages == 0)) {
		if (printk_ratelimit())
			WARN_ON(1);
		return DMA_ERROR_CODE;
	}

	if (handle && *handle)
		start = *handle;
	else
		start = arena->hint;

	limit = arena->limit;

	/* The case below can happen if we have a small segment appended
	 * to a large, or when the previous alloc was at the very end of
	 * the available space. If so, go back to the beginning and flush.
	 */
	if (start >= limit)
		start = 0;

      again:

	if (dev)
		boundary_size = ALIGN((u64) dma_get_seg_boundary(dev) + 1,
				      1 << IO_PAGE_SHIFT) >> IO_PAGE_SHIFT;
	else
		boundary_size = 1UL << (32 - IO_PAGE_SHIFT);

	n = iommu_area_alloc(arena->map, limit, start, npages,
			     iommu->page_table_map_base >> IO_PAGE_SHIFT,
			     boundary_size, 0);
	if (n == -1) {
		if (likely(pass < 1)) {
			/* First failure, rescan from the beginning.  */
			start = 0;
			pass++;
			goto again;
		} else {
			/* Second failure, give up */
			return DMA_ERROR_CODE;
		}
	}

	end = n + npages;

	arena->hint = end;

	/* Update handle for SG allocations */
	if (handle)
		*handle = end;

	return n;
}

void iommu_range_free(struct l_iommu *iommu, dma_addr_t dma_addr,
		      unsigned long npages)
{
	struct l_iommu_arena *arena = &iommu->arena;
	unsigned long entry;

	entry = (dma_addr - iommu->page_table_map_base) >> IO_PAGE_SHIFT;

	bitmap_clear(arena->map, entry, npages);
}

int iommu_table_init(struct l_iommu *iommu, int tsbsize,
		     u32 dma_offset, int numa_node)
{
	unsigned long order, sz, num_tsb_entries;
	struct page *page;

	DebugIOMMU("iommu_table_init() node %d iommu %p size 0x%x dma offset "
		"0x%x\n",
		numa_node, iommu, tsbsize, dma_offset);
	num_tsb_entries = tsbsize / sizeof(iopte_t);

	/* Setup initial software IOMMU state. */
#ifdef IOMMU_USES_MUTEX 
	spin_lock_init(&iommu->lock);
#else
	raw_spin_lock_init(&iommu->lock);
#endif
	iommu->page_table_map_base = dma_offset;

	/* Allocate and initialize the free area map.  */
	sz = num_tsb_entries / 8;
	sz = (sz + 7UL) & ~7UL;
	iommu->arena.map = kzalloc_node(sz, GFP_KERNEL, numa_node);
	if (!iommu->arena.map) {
		pr_err("IOMMU: Error, kmalloc(arena.map) failed.\n");
		return -ENOMEM;
	}
	iommu->arena.limit = num_tsb_entries;

	if (L_IOMMU_DUMMY_PAGE) {
		/* Allocate and initialize the dummy page which we
		 * set inactive IO PTEs to point to.
		 */
		page = alloc_pages_node(numa_node, GFP_KERNEL | __GFP_ZERO, 0);
		if (!page) {
			pr_err("IOMMU: Error, gfp(dummy_page) failed.\n");
			goto out_free_dummy_page;
		}
		iommu->dummy_page = (unsigned long)page_address(page);
		iommu->dummy_page_pa = page_to_phys(page);
		DebugIOMMU("iommu_table_init() dummy page 0x%lx phys 0x%lx\n",
			iommu->dummy_page, iommu->dummy_page_pa);
	}
	/* Now allocate and setup the IOMMU page table itself.  */
	order = get_order(tsbsize);
	page = alloc_pages_node(numa_node, GFP_KERNEL, order);
	if (!page) {
		pr_err("IOMMU: Error, gfp(tsb) failed.\n");
		goto out_free_map;
	}
	iommu->page_table = (iopte_t *) page_address(page);
	DebugIOMMU("iommu_table_init() page table at %p\n",
		iommu->page_table);

	return 0;

out_free_dummy_page:
	if (iommu->dummy_page)
		free_page(iommu->dummy_page);
	iommu->dummy_page = 0UL;

out_free_map:
	kfree(iommu->arena.map);
	iommu->arena.map = NULL;

	return -ENOMEM;
}

static inline iopte_t *alloc_npages(struct device *dev, struct l_iommu *iommu,
				    unsigned long npages)
{
	unsigned long entry;

	entry = iommu_range_alloc(dev, iommu, npages, NULL);
	if (unlikely(entry == DMA_ERROR_CODE))
		return NULL;

	DebugIOMMU("alloc_npages() allocated entry 0x%lx at %p\n",
		entry, iommu->page_table + entry);
	return iommu->page_table + entry;
}

static void *l_alloc_coherent(struct device *dev, size_t size,
			      dma_addr_t * dma_addrp, gfp_t gfp,
				   struct dma_attrs *attrs)
{
#if !defined(IOMMU_USES_MUTEX)
	unsigned long flags;
#endif
	unsigned long order, addr;
	struct l_iommu *iommu = dev_to_iommu(dev);
	struct page *page;
	int npages, i;
	iopte_t *iopte;

	size = IO_PAGE_ALIGN(size);
	order = get_order(size);

	page = alloc_pages_node(dev_to_node(dev), gfp, order);
	if (unlikely(!page))
		return NULL;

	addr = page_to_phys(page);
	DebugIOMMU("l_alloc_coherent() allocated page %p phys 0x%lx "
		"on node %d\n",
		page, addr, dev_to_node(dev));

	lock_iommu(iommu, flags);
	iopte = alloc_npages(dev, iommu, size >> IO_PAGE_SHIFT);
	unlock_iommu(iommu, flags);

	if (unlikely(iopte == NULL)) {
		free_pages(addr, order);
		return NULL;
	}

	*dma_addrp = (iommu->page_table_map_base +
		      ((iopte - iommu->page_table) << IO_PAGE_SHIFT));

	npages = size >> IO_PAGE_SHIFT;
	DebugIOMMU("l_alloc_coherent() dma addr 0x%llx, pages %d\n",
		(u64) *dma_addrp, npages);

	for (i = 0; i < npages; i++, addr += IO_PAGE_SIZE) {
		iopte_val(iopte[i]) = IOPTE_DEFAULT |
		    IOPTE_WRITE | pa_to_iopte(addr);
		iommu_dummy_flush(iommu, dev, *dma_addrp + i * IO_PAGE_SIZE);
		DebugIOMMU("l_alloc_coherent() set iopte %p to 0x%x\n",
			&iopte[i], iopte_val(iopte[i]));
	}
	/* IOPTE must be seen before DMA started */
	wmb();
	memset(page_address(page), 0, size);
	return page_address(page);
}

static void l_free_coherent(struct device *dev, size_t size,
			    void *cpu, dma_addr_t baddr,
				   struct dma_attrs *attrs)
{
#if !defined(IOMMU_USES_MUTEX)
	unsigned long flags;
#endif
	int i;
	struct l_iommu *iommu = dev_to_iommu(dev);
	iopte_t *iopte;
	unsigned long order, npages;
	dma_addr_t addr = baddr & IO_PAGE_MASK;

	npages = IO_PAGE_ALIGN(size) >> IO_PAGE_SHIFT;
	DebugIOMMU("l_free_coherent() free %ld pages from dma addr 0x%llx\n",
		npages, (u64) addr);
	iopte = iommu->page_table +
	    ((baddr - iommu->page_table_map_base) >> IO_PAGE_SHIFT);

	/* Clear out TSB entries. */
	for (i = 0; i < npages; i++, baddr += IO_PAGE_SIZE) {
		iopte_make_dummy(iommu, iopte + i);
		/* IOPTE must be cleaned before flush */
		wmb();
		iommu_flush(iommu, dev, baddr);
		DebugIOMMU("l_free_coherent() cleaned iopte at %p for addr 0x%llx, iommu %p\n",
			iopte + i, (u64) baddr, iommu);
	}

	lock_iommu(iommu, flags);
	iommu_range_free(iommu, addr, npages);
	unlock_iommu(iommu, flags);

	order = get_order(size);
	free_pages((unsigned long)cpu, order);
}

static dma_addr_t l_map_page(struct device *dev, struct page *page,
			     unsigned long offset, size_t sz,
			     enum dma_data_direction direction,
			     struct dma_attrs *attrs)
{
#if !defined(IOMMU_USES_MUTEX)
	unsigned long flags;
#endif
	struct l_iommu *iommu = dev_to_iommu(dev);
	iopte_t *iopte;
	unsigned long  npages, oaddr;
	unsigned long i, addr;
	u32 ret;
	unsigned long prot = IOPTE_DEFAULT;

	oaddr = page_to_phys(page) + offset;
	npages = IO_PAGE_ALIGN(oaddr + sz) - (oaddr & IO_PAGE_MASK);
	npages >>= IO_PAGE_SHIFT;
	DebugIOMMU("l_map_page() addr 0x%lx, pages %ld, iommu %p\n",
		oaddr, npages, iommu);

	lock_iommu(iommu, flags);
	iopte = alloc_npages(dev, iommu, npages);
	unlock_iommu(iommu, flags);
	if (unlikely(!iopte))
		goto bad;

	ret = (iommu->page_table_map_base +
	       ((iopte - iommu->page_table) << IO_PAGE_SHIFT));
	ret = ret | (oaddr & ~IO_PAGE_MASK);
	addr = oaddr & IO_PAGE_MASK;

	if (direction != DMA_TO_DEVICE)
		prot |= IOPTE_WRITE;

	for (i = 0; i < npages; i++, addr += IO_PAGE_SIZE) {
		iopte_val(iopte[i]) = prot | pa_to_iopte(addr);
		iommu_dummy_flush(iommu, dev, ret + i * IO_PAGE_SIZE);
		DebugIOMMU("l_map_page() set iopte %p to 0x%x for addr 0x%lx\n",
			&iopte[i], iopte_val(iopte[i]), ret + i * IO_PAGE_SIZE);
	}
	/* IOPTE must be seen before DMA started */
	wmb();

	return ret;
      bad:
	return DMA_ERROR_CODE;
}

static void l_unmap_page(struct device *dev, dma_addr_t baddr,
			 size_t sz, enum dma_data_direction direction,
			 struct dma_attrs *attrs)
{
#if !defined(IOMMU_USES_MUTEX)
	unsigned long flags;
#endif
	struct l_iommu *iommu = dev_to_iommu(dev);
	iopte_t *iopte;
	unsigned long npages, i;
	dma_addr_t addr;

	npages = IO_PAGE_ALIGN(baddr + sz) - (baddr & IO_PAGE_MASK);
	npages >>= IO_PAGE_SHIFT;
	iopte = iommu->page_table +
	    ((baddr - iommu->page_table_map_base) >> IO_PAGE_SHIFT);
	baddr &= IO_PAGE_MASK;
	addr = baddr;

	/* Clear out TSB entries. */
	for (i = 0; i < npages; i++, baddr += IO_PAGE_SIZE) {
		iopte_make_dummy(iommu, iopte + i);
		/* IOPTE must be cleaned before flush */
		wmb();
		iommu_flush(iommu, dev, baddr);
		DebugIOMMU("l_unmap_page() cleaned iopte %p for addr 0x%llx\n",
			iopte + i, (u64) baddr);
	}

	lock_iommu(iommu, flags);
	iommu_range_free(iommu, addr, npages);
	unlock_iommu(iommu, flags);
}

static int l_map_sg(struct device *dev, struct scatterlist *sglist,
		    int nelems, enum dma_data_direction direction,
		    struct dma_attrs *attrs)
{
#if !defined(IOMMU_USES_MUTEX)
	unsigned long flags;
#endif
	struct scatterlist *s, *outs, *segstart;
	unsigned long handle, prot = IOPTE_DEFAULT;
	dma_addr_t dma_next = 0, dma_addr;
	unsigned int max_seg_size;
	unsigned long seg_boundary_size;
	int outcount, incount, i;
	struct l_iommu *iommu = dev_to_iommu(dev);
	unsigned long base_shift;

	if (nelems == 0)
		return 0;

	lock_iommu(iommu, flags);

	if (direction != DMA_TO_DEVICE)
		prot |= IOPTE_WRITE;

	outs = s = segstart = &sglist[0];
	outcount = 1;
	incount = nelems;
	handle = 0;

	/* Init first segment length for backout at failure */
	outs->dma_length = 0;

	max_seg_size = dma_get_max_seg_size(dev);
	seg_boundary_size = ALIGN((u64) dma_get_seg_boundary(dev) + 1,
				  IO_PAGE_SIZE) >> IO_PAGE_SHIFT;
	base_shift = iommu->page_table_map_base >> IO_PAGE_SHIFT;
	for_each_sg(sglist, s, nelems, i) {
		unsigned long addr, npages, entry, out_entry = 0, slen;
		iopte_t *iopte;
		int j;
		slen = s->length;

		/* Sanity check */
		if (slen == 0) {
			dma_next = 0;
			continue;
		}
		/* Allocate iommu entries for that segment */
		addr = SG_ENT_PHYS_ADDRESS(s);
		npages = iommu_num_pages(addr, slen, IO_PAGE_SIZE);
		entry = iommu_range_alloc(dev, iommu, npages, &handle);

		/* Handle failure */
		if (unlikely(entry == DMA_ERROR_CODE)) {
			if (printk_ratelimit())
				printk(KERN_INFO
				       "iommu_alloc failed, iommu %p addr %lx"
				       " npages %lx\n", iommu, addr, npages);
			goto iommu_map_failed;
		}

		iopte = iommu->page_table + entry;

		/* Convert entry to a dma_addr_t */
		dma_addr = iommu->page_table_map_base +
		    (entry << IO_PAGE_SHIFT);
		dma_addr |= (s->offset & ~IO_PAGE_MASK);

		/* Insert into HW table */
		addr &= IO_PAGE_MASK;

		for (j = 0; j < npages; j++, addr += IO_PAGE_SIZE) {
			iopte_val(iopte[j]) = prot | pa_to_iopte(addr);
			iommu_dummy_flush(iommu, dev, dma_addr + i * IO_PAGE_SIZE);
			DebugIOMMU("l_map_sg() set iopte %p to 0x%x "
				"for addr 0x%lx\n",
				&iopte[j], iopte_val(iopte[j]), addr);
		}

		/* If we are in an open segment, try merging */
		if (segstart != s) {
			/* We cannot merge if:
			 * - allocated dma_addr isn't contiguous to previous allocation
			 */
			if ((dma_addr != dma_next) ||
			    (outs->dma_length + s->length > max_seg_size) ||
			    (is_span_boundary(out_entry, base_shift,
					      seg_boundary_size, outs, s))) {
				/* Can't merge: create a new segment */
				segstart = s;
				outcount++;
				outs = sg_next(outs);
			} else {
				outs->dma_length += s->length;
			}
		}

		if (segstart == s) {
			/* This is a new segment, fill entries */
			outs->dma_address = dma_addr;
			outs->dma_length = slen;
			out_entry = entry;
		}

		/* Calculate next page pointer for contiguous check */
		dma_next = dma_addr + slen;
	}

	unlock_iommu(iommu, flags);

	if (outcount < incount) {
		outs = sg_next(outs);
		outs->dma_address = DMA_ERROR_CODE;
		outs->dma_length = 0;
	}
	DebugIOMMU("l_map_sg() sg list %p dma addr 0x%llx size 0x%x\n",
		outs, (u64) outs->dma_address, outs->dma_length);

	return outcount;

      iommu_map_failed:
	DebugIOMMU("l_map_sg() failed\n");
	for_each_sg(sglist, s, nelems, i) {
		if (s->dma_length != 0) {
			int j;
			unsigned long vaddr, npages, entry;
			iopte_t *iopte;

			vaddr = s->dma_address & IO_PAGE_MASK;
			npages = iommu_num_pages(s->dma_address, s->dma_length,
						 IO_PAGE_SIZE);
			iommu_range_free(iommu, vaddr, npages);

			entry = (vaddr - iommu->page_table_map_base)
			    >> IO_PAGE_SHIFT;
			iopte = iommu->page_table + entry;
			/* Clear out TSB entries. */
			for (j = 0; j < npages; j++)
				iopte_make_dummy(iommu, iopte + j);
			s->dma_address = DMA_ERROR_CODE;
			s->dma_length = 0;
		}
		if (s == outs)
			break;
	}
	unlock_iommu(iommu, flags);

	return 0;
}

static void l_unmap_sg(struct device *dev, struct scatterlist *sglist,
		       int nelems, enum dma_data_direction direction,
		       struct dma_attrs *attrs)
{
#if !defined(IOMMU_USES_MUTEX)
	unsigned long flags;
#endif
	struct scatterlist *sg;
	struct l_iommu *iommu = dev_to_iommu(dev);

	lock_iommu(iommu, flags);

	sg = sglist;
	while (nelems--) {
		dma_addr_t baddr = sg->dma_address;
		unsigned int len = sg->dma_length;
		unsigned long npages, entry;
		iopte_t *iopte;
		int i;

		if (!len)
			break;
		npages = iommu_num_pages(baddr, len, IO_PAGE_SIZE);
		iommu_range_free(iommu, baddr, npages);

		entry = ((baddr - iommu->page_table_map_base)
			 >> IO_PAGE_SHIFT);
		iopte = iommu->page_table + entry;

		baddr &= IO_PAGE_MASK;

		/* Clear out TSB entries. */
		for (i = 0; i < npages; i++, baddr += IO_PAGE_SIZE) {
			iopte_make_dummy(iommu, iopte + i);
			/* IOPTE must be cleaned before flush */
			wmb();
			iommu_flush(iommu, dev, baddr);
			DebugIOMMU("l_unmap_sg() cleaned iopte %p for addr 0x%llx\n",
				iopte + i, (u64) baddr);
		}

		sg = sg_next(sg);
	}
	unlock_iommu(iommu, flags);
}

static struct dma_map_ops l_dma_ops = {
	.alloc = l_alloc_coherent,
	.free = l_free_coherent,
	.map_page = l_map_page,
	.unmap_page = l_unmap_page,
	.map_sg = l_map_sg,
	.unmap_sg = l_unmap_sg,
};

struct dma_map_ops *dma_ops = &l_dma_ops;
EXPORT_SYMBOL(dma_ops);

#if	MAX_IOMMU_WINSIZE >= (4 * 1024 * 1024 * 1024ULL)

#define VGA_MEMORY_OFFSET            0x000A0000
#define VGA_MEMORY_SIZE              0x00020000

static void __init l_iommu_fixup(struct l_iommu *iommu, unsigned long sz)
{
	unsigned nr, st;
	if (sz != 4UL * 1024 * 1024 * 1024)
		return;
	/*
	* IOHUB don't let through address space 0x80000000 - 0xffffFFFF
	* at e2k and 0 - 0x80000000 at E90S. So we must shrink
	* address window.
	* Page table must be 4MiB aligned at e2k.
	*/
	nr = sz / IO_PAGE_SIZE / 2;
#ifdef	__e2k__
	st = nr;
	iommu->arena.limit /= 2;
	/* I don't like NULL pointer */
	bitmap_set(iommu->arena.map, 0, 1);
	/* reserve VGA memory */
	bitmap_set(iommu->arena.map, VGA_MEMORY_OFFSET / IO_PAGE_SIZE,
				VGA_MEMORY_SIZE / IO_PAGE_SIZE);
#else
	st = 0;
	iommu->arena.hint = nr;
#endif	/* __e2k__ */
	bitmap_set(iommu->arena.map, st, nr);
}
#else
static void __init l_iommu_fixup(struct l_iommu *iommu, unsigned long sz) {}
#endif

static int __init l_iommu_init_one(struct l_iommu **iommu,
				      unsigned long win_sz, int node, int link)
{
	int i, j, n;
	unsigned long ta[IOMMU_TABLES_NR];
	unsigned long range;
	win_sz = roundup_pow_of_two(win_sz);
	if (win_sz > MAX_IOMMU_WINSIZE)
		win_sz = MAX_IOMMU_WINSIZE;
	else if (win_sz < MIN_IOMMU_WINSIZE)
		win_sz = MIN_IOMMU_WINSIZE;

	n = ilog2(win_sz) > 32 ? IOMMU_TABLES_NR : 1;

	for (i = 0; i < n; i++) {
		unsigned long tsbsize;
		unsigned long start, sz;
		sz = i ? MIN_IOMMU_WINSIZE : win_sz;
		iommu[i] = kzalloc_node(sizeof(struct l_iommu),
					GFP_KERNEL, node);
		if (!iommu[i]) {
			pr_err("IOMMU: Error, kmalloc(iommu) failed.\n");
			return -ENOMEM;
		}
		start = (~0UL) << ilog2(sz);
		tsbsize = (sz / IO_PAGE_SIZE) * sizeof(iopte_t);

		if (iommu_table_init(iommu[i], tsbsize, start, node))
			return -1;
		l_iommu_fixup(iommu[i], sz);
		ta[i] = pa_to_iopte(__pa(iommu[i]->page_table));
		iommu[i]->page_table = (iopte_t *)
				l_iommu_map(iommu[i]->page_table, tsbsize);
		if (!iommu[i]->page_table)
			return -1;

		for (j = 0; j < tsbsize / sizeof(iopte_t); j++)
			iopte_make_dummy(iommu[i], iommu[i]->page_table + j);
	}
	for (i = n; i < IOMMU_TABLES_NR; i++) {
		iommu[i] = iommu[n - 1];
		ta[i] = ta[n - 1];
	}

	l_iommu_set_ba(node, link, ta);

	range = ilog2(win_sz) - ilog2(MIN_IOMMU_WINSIZE);
	range <<= IOMMU_RNGE_OFF;	/* Virtual DMA Address Range */
	l_iommu_write(node, link, range | IOMMU_CTRL_CASHABLE_TTE
		      | IOMMU_CTRL_ENAB, L_IOMMU_CTRL);

	__iommu_flushall(node, link);
	printk("IOMMU:%d:%d: enabled; window size %lu MiB\n",
	       node, link, win_sz / (1024 * 1024));
	return 0;
}

#ifdef	CONFIG_SWIOTLB
static void *l_swiotlb_alloc_coherent(struct device *dev, size_t size,
					dma_addr_t * dma_handle, gfp_t gfp,
				   	struct dma_attrs *attrs)
{
	if (dev->coherent_dma_mask != DMA_BIT_MASK(64))
		gfp |= GFP_DMA;
	return swiotlb_alloc_coherent(dev, size, dma_handle, gfp);
}

static void l_swiotlb_free_coherent(struct device *dev, size_t size,
				void *vaddr, dma_addr_t dma_addr,
				struct dma_attrs *attrs)
{
	swiotlb_free_coherent(dev, size, vaddr, dma_addr);
}

struct dma_map_ops swiotlb_dma_ops = {
	.alloc = l_swiotlb_alloc_coherent,
	.free = l_swiotlb_free_coherent,
	.map_page = swiotlb_map_page,
	.unmap_page = swiotlb_unmap_page,
	.map_sg = swiotlb_map_sg_attrs,
	.unmap_sg = swiotlb_unmap_sg_attrs,
	.sync_single_for_cpu = swiotlb_sync_single_for_cpu,
	.sync_single_for_device = swiotlb_sync_single_for_device,
	.sync_sg_for_cpu = swiotlb_sync_sg_for_cpu,
	.sync_sg_for_device = swiotlb_sync_sg_for_device,
	.dma_supported = swiotlb_dma_supported,
	.mapping_error = swiotlb_dma_mapping_error,
};
#endif /*CONFIG_SWIOTLB */

static unsigned long __initdata l_iommu_win_sz = DFLT_IOMMU_WINSIZE;

static int __init l_iommu_setup(char *str)
{
	l_iommu_win_sz = memparse(str, &str);
	return 1;
}

__setup("iommu=", l_iommu_setup);

static int __init l_iommu_init(void)
{
	int i, j, d;
#ifdef	CONFIG_SWIOTLB
	if (!l_iommu_supported() || !l_iommu_win_sz) {
		extern int swiotlb_late_init_with_default_size(size_t size);
		swiotlb_late_init_with_default_size(64 * 1024 * 1024);
		dma_ops = &swiotlb_dma_ops;
		if (l_iommu_supported()) {
			for_each_iommu(d) {
				i = l_domain_to_node(d);
				j = l_domain_to_link(d);
				l_iommu_write(i, j, 0, L_IOMMU_CTRL);
			}
		}
		return 0;
	}
#endif	/*CONFIG_SWIOTLB*/
	for_each_iommu(d) {
		i = l_domain_to_node(d);
		j = l_domain_to_link(d);
		if (l_iommu_init_one(l_iommu[i][j], l_iommu_win_sz, i, j)) {
			pr_err("IOMMU: Error, iommu init failed.\n");
			return -1;
		}
	}
	return 0;
}

arch_initcall(l_iommu_init);
