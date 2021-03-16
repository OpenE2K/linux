#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/iommu.h>
#include <linux/dma-iommu.h>
#include <linux/topology.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/pci.h>
#include <linux/swiotlb.h>
#include <linux/syscore_ops.h>
#include <linux/dma-direct.h>
#include <linux/dma-direction.h>
#include <linux/genalloc.h>
#include <linux/iommu-helper.h>

#include <asm/l-iommu.h>
#include <asm-l/l-uncached.h>

#ifndef	IOMMU_TABLES_NR
#define IOMMU_TABLES_NR		1
#define IOMMU_LOW_TABLE		0
#define IOMMU_HIGH_TABLE	0
#endif

int __initdata l_use_swiotlb = 0;
int l_iommu_no_numa_bug = 0;
EXPORT_SYMBOL(l_iommu_no_numa_bug);

int l_iommu_force_numa_bug_on = 0;
EXPORT_SYMBOL(l_iommu_force_numa_bug_on);
unsigned long l_iommu_win_sz = DFLT_IOMMU_WINSIZE;

static int __initdata l_not_use_prefetch = 0;
static const struct iommu_ops l_iommu_ops;


#ifndef l_prefetch_iopte_supported
#define l_prefetch_iopte_supported()	0
#define	l_prefetch_iopte(iopte, prefetch)	do {} while (0)
#endif

#ifndef l_iommu_has_numa_bug
#define l_iommu_has_numa_bug()	0
#endif

/*
 * These give mapping size of each iommu pte/tlb.
 */
#define IO_PAGE_SIZE			(1UL << IO_PAGE_SHIFT)
#define IO_PAGE_MASK			(~(IO_PAGE_SIZE-1))
#define IO_PAGE_ALIGN(addr)		ALIGN(addr, IO_PAGE_SIZE)

#define IOMMU_CTRL_IMPL     0xf0000000	/* Implementation */
#define IOMMU_CTRL_VERS     0x0f000000	/* Version */
#define IOMMU_CTRL_PREFETCH_EN	    0x00000040	/* enable prefeth TTE */
#define IOMMU_CTRL_CASHABLE_TTE	    0x00000020	/* Cachable TTE */
#define IOMMU_CTRL_RNGE     0x0000001c	/* Mapping RANGE */
#define IOMMU_CTRL_ENAB     0x00000001	/* IOMMU Enable */

#define IOMMU_RNGE_OFF      2

struct l_iommu {
	int node;

	struct l_iommu_table {
		iopte_t	*pgtable;
		unsigned long map_base;
	} table[IOMMU_TABLES_NR];

	unsigned int prefetch_supported:	1;
	struct iommu_group *default_group;

	struct iommu_device iommu;	/* IOMMU core handle */
};

static void __iommu_flushall(unsigned node)
{
	l_iommu_write(node, 0, L_IOMMU_FLUSH_ALL);
}

static inline void iommu_flush(struct l_iommu *iommu,
			       dma_addr_t addr)
{
	l_iommu_write(iommu->node,
		      addr_to_flush(addr), L_IOMMU_FLUSH_ADDR);
}

static unsigned long l_iommu_prot_to_pte(int prot)
{
	unsigned long pte_prot = IOPTE_CACHE;
	if (prot & IOMMU_READ)
		pte_prot |= IOPTE_VALID;

	if (prot & IOMMU_WRITE)
		pte_prot |= IOPTE_VALID | IOPTE_WRITE;
	return pte_prot;
}

struct l_iommu_domain {
	struct l_iommu *iommu;
	struct iommu_domain domain; /* generic domain data structure */
};

static struct l_iommu_domain *to_l_domain(struct iommu_domain *dom)
{
	return container_of(dom, struct l_iommu_domain, domain);
}

static struct l_iommu *dev_to_iommu(struct device *dev)
{
	struct iohub_sysdata *sd;

	if (WARN_ON(!dev))
		return NULL;
	if (WARN_ON(!dev_is_pci(dev)))
		return NULL;

	sd = to_pci_dev(dev)->bus->sysdata;

	return sd->l_iommu;
}

static struct l_iommu_table *l_iommu_to_table(struct l_iommu *i,
						unsigned long iova)
{
	return i->table + l_iommu_get_table(iova);
}

static unsigned l_iommu_page_indx(struct l_iommu_table *t, unsigned long iova)
{
	return (iova - t->map_base) / IO_PAGE_SIZE;
}

static iopte_t *l_iommu_iopte(struct l_iommu *i, unsigned long iova)
{
	struct l_iommu_table *t = l_iommu_to_table(i, iova);
	return t->pgtable + l_iommu_page_indx(t, iova);
}

static bool l_dom_iova_hi(unsigned long iova)
{
	return iova & (~0UL << 32) ? true : false;
}

static struct idr *l_dom_get_idr(struct iommu_domain *d, unsigned long iova)
{
	return l_dom_iova_hi(iova) ? &d->idr_hi : &d->idr_lo;
}

static unsigned l_dom_page_indx(struct iommu_domain *d, unsigned long iova)
{
	if (!l_dom_iova_hi(iova))
		return iova / IO_PAGE_SIZE;

	return (iova - d->map_base) / IO_PAGE_SIZE;
}

static int l_dom_alloc_id(struct iommu_domain *d,
		phys_addr_t phys, unsigned long iova)
{
	int ret;
	unsigned long flags;
	struct idr *idr = l_dom_get_idr(d, iova);
	unsigned i = l_dom_page_indx(d, iova);

	idr_preload(GFP_ATOMIC);
	idr_lock_irqsave(idr, flags);
	ret = idr_alloc(idr, (void *)phys, i, i + 1, GFP_NOWAIT);
	idr_unlock_irqrestore(idr, flags);
	idr_preload_end();

	return ret;
}

static void l_dom_free_id(struct iommu_domain *d, unsigned long iova)
{
	unsigned long flags;
	struct idr *idr = l_dom_get_idr(d, iova);
	unsigned i = l_dom_page_indx(d, iova);

	idr_lock_irqsave(idr, flags);
	WARN_ON(idr_remove(idr, i) == NULL);
	idr_unlock_irqrestore(idr, flags);
}

static phys_addr_t l_dom_lookup_id(struct iommu_domain *d,
				     unsigned long iova)
{
	void *p;
	unsigned long flags;
	struct idr *idr = l_dom_get_idr(d, iova);
	unsigned i = l_dom_page_indx(d, iova);

	idr_lock_irqsave(idr, flags);
	p = idr_find(idr, i);
	idr_unlock_irqrestore(idr, flags);

	return (phys_addr_t)p;
}

static phys_addr_t l_alloc_pages(struct iommu_domain *d, phys_addr_t orig_phys,
				  size_t size, unsigned long iova, int node)
{
	int ret;
	int npages = iommu_num_pages(orig_phys, size, IO_PAGE_SIZE);
	gfp_t gfp_mask = __GFP_THISNODE | GFP_ATOMIC | __GFP_NOWARN;
	int order = get_order(npages * IO_PAGE_SIZE);
	struct page *page = alloc_pages_node(node, gfp_mask, order);
	if (!page)
		return 0;
	ret = l_dom_alloc_id(d, orig_phys, iova);
	if (ret < 0) {
		__free_pages(page, order);
		return 0;
	}
	return page_to_phys(page);
}

static void l_free_pages(struct iommu_domain *d, phys_addr_t phys,
				size_t size, unsigned long iova)
{
	phys_addr_t orig_paddr = l_dom_lookup_id(d, iova);
	int npages = iommu_num_pages(phys, size, IO_PAGE_SIZE);
	int order = get_order(npages * IO_PAGE_SIZE);
	if (!orig_paddr)
		return;
	__free_pages(phys_to_page(phys), order);
	l_dom_free_id(d, iova);
}

static void l_iommu_init_hw(struct l_iommu *iommu,
					unsigned long win_sz, int node)
{
	int i;
	unsigned long pa[ARRAY_SIZE(iommu->table)];
	unsigned long range = ilog2(win_sz) - ilog2(MIN_IOMMU_WINSIZE);
	range <<= IOMMU_RNGE_OFF;	/* Virtual DMA Address Range */
	for (i = 0; i < ARRAY_SIZE(iommu->table); i++)
		pa[i] = __pa(iommu->table[i].pgtable);

	l_iommu_set_ba(node, pa);

	if (iommu->prefetch_supported)
		range |= IOMMU_CTRL_PREFETCH_EN;

	l_iommu_write(node, range | IOMMU_CTRL_CASHABLE_TTE |
					IOMMU_CTRL_ENAB, L_IOMMU_CTRL);
	__iommu_flushall(node);
}

static int l_iommu_init_table(struct l_iommu_table *t, unsigned long win_sz,
						int node)
{
	int win_bits = ilog2(win_sz);
	size_t sz = win_sz / IO_PAGE_SIZE * sizeof(iopte_t);
	void *p = kzalloc_node(sz, GFP_KERNEL, node);
	if (!p)
		goto fail;

	t->pgtable = l_iommu_map_table(p, win_sz);

	t->map_base = (~0UL) << win_bits;
	if (win_bits <= 32)
		t->map_base &= 0xFFFFffff;

	return 0;
fail:
	return -1;
}

static void l_iommu_free_table(struct l_iommu_table *t)
{
	t->pgtable = l_iommu_unmap_table(t->pgtable);
	kfree(t->pgtable);
}

static struct l_iommu *__l_iommu_init(int node, unsigned long win_sz,
					  struct device *parent)
{
	struct l_iommu *iommu = kzalloc_node(sizeof(*iommu), GFP_KERNEL, node);
	int ret = 0;
	int i, n = ARRAY_SIZE(iommu->table);

	if (!iommu)
		return iommu;

	if (win_sz <= (1UL << 32))
		n = 1;
	if (n == 2) {
		ret = l_iommu_init_table(&iommu->table[IOMMU_LOW_TABLE],
				MIN_IOMMU_WINSIZE, node);
		if (ret)
			goto fail;
		ret = l_iommu_init_table(&iommu->table[IOMMU_HIGH_TABLE],
					  win_sz, node);
	} else {
		ret = l_iommu_init_table(&iommu->table[IOMMU_LOW_TABLE],
					  win_sz, node);
	}
	if (ret)
		goto fail;
	iommu->default_group = iommu_group_alloc();
	if (IS_ERR(iommu->default_group))
		goto fail;

	iommu->node = node;
	if (l_prefetch_iopte_supported() && !l_not_use_prefetch)
		iommu->prefetch_supported = 1;

	iommu_device_sysfs_add(&iommu->iommu, parent, NULL, "iommu%d", node);
	iommu_device_set_ops(&iommu->iommu, &l_iommu_ops);
	iommu_device_register(&iommu->iommu);
	l_iommu_init_hw(iommu, win_sz, node);
	return iommu;
fail:
	for (i = 0; i < ARRAY_SIZE(iommu->table); i++)
		l_iommu_free_table(iommu->table);
	kfree(iommu);
	return NULL;
}

static int __init l_iommu_debugfs_init(void)
{
#if defined CONFIG_IOMMU_DEBUGFS
	/*TODO:*/;
	return 0;
#else /* CONFIG_IOMMU_DEBUGFS */
	return 0;
#endif /* CONFIG_IOMMU_DEBUGFS */
}

/* IOMMU API */
static int l_iommu_map(struct iommu_domain *iommu_domain,
			    unsigned long iova, phys_addr_t phys, size_t size,
			    int iommu_prot)
{
	unsigned long prot;
	phys_addr_t orig_phys = phys;
	struct l_iommu_domain *d = to_l_domain(iommu_domain);
	iopte_t *ptep = l_iommu_iopte(d->iommu, iova);
	int node = d->iommu->node;
	bool copy = l_iommu_has_numa_bug() &&
			page_to_nid(phys_to_page(phys)) != node;

	if (WARN_ON(!IS_ALIGNED(phys, size)))
		return -EINVAL;
	if (WARN_ON(!IS_ALIGNED(iova, size)))
		return -EINVAL;
	if (WARN_ON(size ^ L_PGSIZE_BITMAP))
		return -EINVAL;


	/* If no access, then nothing to do */
	if (!(iommu_prot & (IOMMU_READ | IOMMU_WRITE)))
		return 0;

	if (copy) {
		phys = l_alloc_pages(iommu_domain, orig_phys, size, iova, node);
		if (phys == 0)
			return -ENOMEM;
	}

	prot = l_iommu_prot_to_pte(iommu_prot);

	if (iopte_val(*ptep)) {
		panic("iommu: %lx -> %llx: pte (%x) is not empty\n",
				iova, phys, iopte_val(*ptep));
	}

	iopte_val(*ptep) = prot | pa_to_iopte(phys);

	return 0;
}

static size_t l_iommu_unmap(struct iommu_domain *iommu_domain,
				unsigned long iova, size_t size,
				struct iommu_iotlb_gather *gather)
{
	struct l_iommu_domain *d = to_l_domain(iommu_domain);
	iopte_t *ptep = l_iommu_iopte(d->iommu, iova);

	if (WARN_ON(!IS_ALIGNED(iova, size)))
		return 0;
	if (WARN_ON(size ^ L_PGSIZE_BITMAP))
		return 0;
	if (l_iommu_has_numa_bug()) {
		l_free_pages(iommu_domain,
			     iopte_to_pa(iopte_val(*ptep)), size, iova);
	}

	iopte_val(*ptep) = 0;
	/* Clear out TSB entry. */
	wmb();
	/*TODO: iotlb_sync */
	iommu_flush(d->iommu, iova);

	return size;
}

static phys_addr_t l_iommu_iova_to_phys(struct iommu_domain *iommu_domain,
					  dma_addr_t iova)
{
	struct l_iommu_domain *d = to_l_domain(iommu_domain);
	iopte_t *ptep = l_iommu_iopte(d->iommu, iova);
	return iopte_to_pa(iopte_val(*ptep));
}

static void l_iommu_detach_device(struct iommu_domain *iommu_domain,
				    struct device *dev)
{
}

static int l_iommu_attach_device(struct iommu_domain *iommu_domain,
				   struct device *dev)
{
	struct l_iommu *i = dev_to_iommu(dev);
	struct l_iommu_domain *d = to_l_domain(iommu_domain);
	if (!i)
		return -EINVAL;

	d->iommu = i;

	return 0;
}

static struct iommu_domain *__l_iommu_domain_alloc(unsigned type, int node)
{
	struct l_iommu_domain *d = kzalloc_node(sizeof(*d), GFP_KERNEL, node);
	int win_bits = ilog2(l_iommu_win_sz);
	unsigned long start = ~0UL << win_bits;
	unsigned long end   = ~0UL;
	if (!d)
		return NULL;

	if (type == IOMMU_DOMAIN_DMA) {
		if (iommu_get_dma_cookie(&d->domain) != 0)
			goto err_pgtable;
	} else if (type != IOMMU_DOMAIN_UNMANAGED) {
		goto err_pgtable;
	}
	if (win_bits <= 32) {
		start &= 0xffffFFFF;
		end   &= 0xffffFFFF;
	} else {
		start = 0;
	}
	d->domain.geometry.aperture_start = start;
	d->domain.geometry.aperture_end   = end;
	d->domain.geometry.force_aperture = true;

	idr_init(&d->domain.idr_lo);
	idr_init(&d->domain.idr_hi);
	d->domain.map_base = (~0UL) << win_bits;

	return &d->domain;

err_pgtable:
	kfree(d);
	return NULL;
}

static struct iommu_domain *l_iommu_domain_alloc(unsigned type)
{
		return __l_iommu_domain_alloc(type, -1);
}

static void l_iommu_domain_free(struct iommu_domain *iommu_domain)
{
	struct l_iommu_domain *d = to_l_domain(iommu_domain);
	iommu_put_dma_cookie(iommu_domain);

	idr_destroy(&d->domain.idr_lo);
	idr_destroy(&d->domain.idr_hi);

	kfree(d);
}

static int l_iommu_add_device(struct device *dev)
{
	struct iommu_group *group = iommu_group_get_for_dev(dev);

	if (IS_ERR(group))
		return PTR_ERR(group);

	iommu_group_put(group);
	iommu_device_link(&dev_to_iommu(dev)->iommu, dev);
	iommu_setup_dma_ops(dev, 0, dma_get_mask(dev) + 1);

	return 0;
}

static void l_iommu_remove_device(struct device *dev)
{
	iommu_device_unlink(&dev_to_iommu(dev)->iommu, dev);
	iommu_group_remove_device(dev);
}

static struct iommu_group *l_iommu_device_group(struct device *dev)
{
	return dev_to_iommu(dev)->default_group;
}

static bool l_iommu_capable(enum iommu_cap cap)
{
	switch (cap) {
	case IOMMU_CAP_CACHE_COHERENCY:
		return true;
	case IOMMU_CAP_INTR_REMAP:
		return true; /* MSIs are just memory writes */
	case IOMMU_CAP_NOEXEC:
		return true;
	default:
		return false;
	}
}

#define VGA_MEMORY_OFFSET            0x000A0000
#define VGA_MEMORY_SIZE              0x00020000
#define RT_MSI_MEMORY_SIZE           0x100000	/* 1 Mb */
static void l_iommu_get_resv_regions(struct device *dev,
				      struct list_head *head)
{
	struct iommu_resv_region *region;
	int prot = IOMMU_WRITE | IOMMU_NOEXEC | IOMMU_MMIO;
	struct iohub_sysdata *sd;

	if (WARN_ON(!dev_is_pci(dev)))
		return;

	if (l_iommu_win_sz > (1UL << 32)) {
		unsigned long start = 1UL << 32;
		unsigned long sz = ULONG_MAX  - l_iommu_win_sz + 1;
		/* remove space beetween 0xffffFFFF and map_base */
		region = iommu_alloc_resv_region(start, sz,
						prot, IOMMU_RESV_RESERVED);
		if (!region)
			return;
		list_add_tail(&region->list, head);
	}

	sd = to_pci_dev(dev)->bus->sysdata;
	if (!sd->pci_msi_addr_lo)
		return;

	region = iommu_alloc_resv_region(((u64)sd->pci_msi_addr_hi)
			<< 32 |	sd->pci_msi_addr_lo, RT_MSI_MEMORY_SIZE,
					prot, IOMMU_RESV_MSI);
	if (!region)
		return;
	list_add_tail(&region->list, head);

	region = iommu_alloc_resv_region(VGA_MEMORY_OFFSET, VGA_MEMORY_SIZE,
					 prot, IOMMU_RESV_RESERVED);
	if (!region)
		return;
	list_add_tail(&region->list, head);

	iommu_dma_get_resv_regions(dev, head);
}

static void l_iommu_put_resv_regions(struct device *dev,
				      struct list_head *head)
{
	struct iommu_resv_region *entry, *next;

	list_for_each_entry_safe(entry, next, head, list)
		kfree(entry);
}

static const struct iommu_ops l_iommu_ops = {
	.map		= l_iommu_map,
	.unmap		= l_iommu_unmap,
	.iova_to_phys	= l_iommu_iova_to_phys,

	.domain_alloc	= l_iommu_domain_alloc,
	.domain_free	= l_iommu_domain_free,
	.attach_dev	= l_iommu_attach_device,
	.detach_dev	= l_iommu_detach_device,
	.add_device	= l_iommu_add_device,
	.remove_device	= l_iommu_remove_device,
	.device_group	= l_iommu_device_group,
	.capable	= l_iommu_capable,

	.get_resv_regions	= l_iommu_get_resv_regions,
	.put_resv_regions	= l_iommu_put_resv_regions,

	.pgsize_bitmap = L_PGSIZE_BITMAP,
};

#ifdef	CONFIG_SWIOTLB

static int l_dma_mmap(struct device *dev, struct vm_area_struct *vma,
		      void *cpu_addr, dma_addr_t dma_addr, size_t size,
		      unsigned long attrs)
{
	int ret = -ENXIO;
	unsigned long user_count = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	unsigned long count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	unsigned long pfn = page_to_pfn(virt_to_page(cpu_addr));
	unsigned long off = vma->vm_pgoff;

	if (attrs)
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	if (off >= count || user_count > (count - off))
		return -ENXIO;
	if (is_vmalloc_addr(cpu_addr)) {
		ret = remap_vmalloc_range(vma, cpu_addr, off);
	} else {
		ret = remap_pfn_range(vma, vma->vm_start,
				      pfn + off,
				      user_count << PAGE_SHIFT,
				      vma->vm_page_prot);
	}

	return ret;
}

static void *l_swiotlb_alloc_coherent(struct device *dev, size_t size,
					dma_addr_t *dma_handle, gfp_t gfp,
					unsigned long attrs)
{
	if (attrs & DMA_ATTR_NON_CONSISTENT) {
		void *va = l_alloc_uncached(dev, size, dma_handle, gfp);
		if (va)
			memset(va, 0, size);
		return va;
	}
	return dma_direct_alloc(dev, size, dma_handle, gfp, attrs);
}

static void l_swiotlb_free_coherent(struct device *dev, size_t size,
				void *cpu_addr, dma_addr_t dma_handle,
				unsigned long attrs)
{
	if (attrs & DMA_ATTR_NON_CONSISTENT)
		l_free_uncached(dev, size, cpu_addr);
	else
		dma_direct_free(dev, size, cpu_addr, dma_handle, attrs);
}

static const struct dma_map_ops l_swiotlb_dma_ops = {
	.alloc = l_swiotlb_alloc_coherent,
	.free = l_swiotlb_free_coherent,
	.map_page = dma_direct_map_page,
	.unmap_page = dma_direct_unmap_page,
	.map_sg = dma_direct_map_sg,
	.unmap_sg = dma_direct_unmap_sg,
	.mmap = l_dma_mmap,
	.sync_single_for_cpu = dma_direct_sync_single_for_cpu,
	.sync_single_for_device = dma_direct_sync_single_for_device,
	.sync_sg_for_cpu = dma_direct_sync_sg_for_cpu,
	.sync_sg_for_device = dma_direct_sync_sg_for_device,
	.dma_supported = dma_direct_supported,
};

/* Built-in e1cp devices work bypassing iommu. They must work
 * using swiotlb.
 */
static void l_quirk_iommu_bypass_devices(struct pci_dev *pdev)
{
	set_dma_ops(&pdev->dev, &l_swiotlb_dma_ops);
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_MGA2,
			  l_quirk_iommu_bypass_devices);
#endif /* CONFIG_SWIOTLB */

#ifdef CONFIG_PM_SLEEP
void l_iommu_stop_all(void)
{
	struct pci_bus *b;

	if (!l_iommu_supported())
		return;

	list_for_each_entry(b, &pci_root_buses, node) {
		int node = 0;

#ifdef CONFIG_IOHUB_DOMAINS
		node = ((struct iohub_sysdata *)b->sysdata)->node;
#endif
		l_iommu_write(node, 0, L_IOMMU_CTRL);
	}
}

static int l_iommu_suspend(void)
{
	return 0;
}

static void l_iommu_resume(void)
{
	struct pci_bus *b;

	list_for_each_entry(b, &pci_root_buses, node) {
		struct iohub_sysdata *sd = b->sysdata;
		int node = 0;

#ifdef CONFIG_IOHUB_DOMAINS
		node = sd->node;
#endif
		l_iommu_init_hw(sd->l_iommu, l_iommu_win_sz, node);
	}
}

static void l_iommu_shutdown(void)
{
	l_iommu_stop_all();
}

static struct syscore_ops l_iommu_syscore_ops = {
	.resume		= l_iommu_resume,
	.suspend	= l_iommu_suspend,
	.shutdown	= l_iommu_shutdown,
};

static void __init l_iommu_init_pm_ops(void)
{
	register_syscore_ops(&l_iommu_syscore_ops);
}

#else
static inline void l_iommu_stop_all(void) {}
static inline void l_iommu_init_pm_ops(void) {}
#endif	/* CONFIG_PM_SLEEP */


static resource_size_t l_get_max_resource_end(struct pci_bus *bus)
{
	int i;
	struct resource *res;
	resource_size_t end = 0, c;

	pci_bus_for_each_resource(bus, res, i) {
		if (!res || !res->flags || res->start > res->end)
			continue;
		if (!(res->flags & IORESOURCE_MEM))
			continue;
		c = res->end;
		if (c > end)
			end = c;
	}
	return end;
}

static void l_trim_pci_window(struct pci_bus *root_bus)
{
	struct pci_bus *b;
	resource_size_t end = 0, c;
	struct resource_entry *window;
	struct pci_host_bridge *bridge = pci_find_host_bridge(root_bus);

	list_for_each_entry(b, &root_bus->children, node) {
		c = l_get_max_resource_end(b);
		if (c > end)
			end = c;
	}

	resource_list_for_each_entry(window, &bridge->windows) {
		if (resource_type(window->res) != IORESOURCE_MEM)
			continue;
		/*
		 * Fixup for iova_reserve_pci_windows(): trim the window if
		 * the boot didn't pass us pci memory ranges
		 * (see mp_pci_add_resources()).
		 */
		if (window->res->end == ~0UL)
			window->res->end = end;
	}
}

const struct dma_map_ops *dma_ops;
EXPORT_SYMBOL(dma_ops);

static int __init l_iommu_setup(char *str)
{
	unsigned long win_sz = DFLT_IOMMU_WINSIZE;

	if (!strcmp(str, "force-numa-bug-on"))
		l_iommu_force_numa_bug_on = 1;
	if (!strcmp(str, "no-numa-bug")) {
		l_iommu_no_numa_bug = 1;
	} else if (!strcmp(str, "noprefetch")) {
		l_not_use_prefetch = 1;
	} else {
		win_sz = memparse(str, &str);
		if (win_sz == 0)
			l_use_swiotlb = 1;
	}

	win_sz = roundup_pow_of_two(win_sz);
	if (win_sz > MAX_IOMMU_WINSIZE)
		win_sz = MAX_IOMMU_WINSIZE;
	else if (win_sz < MIN_IOMMU_WINSIZE)
		win_sz = MIN_IOMMU_WINSIZE;
	l_iommu_win_sz = win_sz;

	return 1;
}
__setup("iommu=", l_iommu_setup);

static int __init l_iommu_init(void)
{
	int ret;
	struct pci_bus *b;
	size_t idr_sz = 1UL + INT_MAX;
	size_t tbl_sz = l_iommu_win_sz / IO_PAGE_SIZE * sizeof(iopte_t);
#if defined CONFIG_SWIOTLB || defined CONFIG_E2K
	if (HAS_MACHINE_E2K_IOMMU && !l_use_swiotlb)
			return 0;

	if (!l_iommu_supported() || l_use_swiotlb) {
		extern int swiotlb_late_init_with_default_size(size_t size);
		swiotlb_late_init_with_default_size(L_SWIOTLB_DEFAULT_SIZE);
		dma_ops = &l_swiotlb_dma_ops;
		l_iommu_stop_all();
		pr_info("iommu disabled\n");
		return 0;
	}
#endif	/* CONFIG_SWIOTLB */
	if (tbl_sz > PAGE_SIZE << (MAX_ORDER - 1)) {
		tbl_sz = PAGE_SIZE << (MAX_ORDER - 1);
		l_iommu_win_sz = tbl_sz / sizeof(iopte_t) * IO_PAGE_SIZE;
	}
	if (l_iommu_has_numa_bug() && l_iommu_win_sz > idr_sz * PAGE_SIZE)
		l_iommu_win_sz = idr_sz * PAGE_SIZE;


	list_for_each_entry(b, &pci_root_buses, node) {
		int node = 0;
		struct l_iommu *i;
		struct iohub_sysdata *sd = b->sysdata;

#ifdef CONFIG_IOHUB_DOMAINS
		node = sd->node;
#endif
		l_trim_pci_window(b);
		i = __l_iommu_init(node, l_iommu_win_sz, &b->dev);
		if (!i)
			return -ENOMEM;
		pr_info("iommu:%d: enabled; window size %lu MiB\n",
				node,  l_iommu_win_sz / (1024 * 1024));
		sd->l_iommu = i;
	}
	ret  = bus_set_iommu(&pci_bus_type, &l_iommu_ops);
	if (ret)
		return ret;

	l_iommu_init_pm_ops();
	l_iommu_debugfs_init();
	return ret;
}

/*
 * Needs to be done after pci initialization which are subsys_initcall.
 */
subsys_initcall_sync(l_iommu_init);
