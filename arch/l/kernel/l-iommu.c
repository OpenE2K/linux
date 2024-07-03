/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

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
#include <linux/platform_device.h>
#include <linux/swiotlb.h>
#include <linux/syscore_ops.h>
#include <linux/dma-direct.h>
#include <linux/dma-direction.h>
#include <linux/genalloc.h>
#include <linux/iommu-helper.h>

#include <asm/l-iommu.h>


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
static struct iommu_ops l_iommu_ops;


#ifndef l_prefetch_iopte_supported
#define l_prefetch_iopte_supported()	0
#define	l_prefetch_iopte(iopte, prefetch)	do {} while (0)
#endif

#ifndef l_iommu_has_numa_bug
#define l_iommu_has_numa_bug()	0
#endif

#ifndef l_has_devices_with_iommu
#define l_has_devices_with_iommu()	0
#endif

#ifndef l_iommu_enable_embedded_iommus
#define l_iommu_enable_embedded_iommus(node)	do {} while (0)
#endif

/* iohub, iohub2 supports only 56-bit of virtual address */
#define L_IOMMU_VA_MASK		((1UL << 56) - 1)

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
	struct list_head list;		/* list of all iommu */
	int node;
	unsigned regs_offset;
	unsigned companion_regs_offset;
	struct mutex mutex;

	struct l_iommu_table {
		iopte_t	*pgtable;
		unsigned long pgtable_pa;
		unsigned long map_base;
	} table[IOMMU_TABLES_NR];

	unsigned prefetch_supported:	1;
	struct iommu_group *default_group;

	struct iommu_device iommu;	/* IOMMU core handle */
};

static int l_dev_to_node(struct device *dev)
{
	return dev && dev_to_node(dev) >= 0 ?
			dev_to_node(dev) : 0;
}

static void l_iommu_write(struct l_iommu *iommu, unsigned val, unsigned addr)
{
	__l_iommu_write(iommu->node, val, addr + iommu->regs_offset);
	if (iommu->companion_regs_offset) {
		__l_iommu_write(iommu->node, val,
				addr + iommu->companion_regs_offset);
	}
}
#ifdef __l_iommu_set_ba
static inline void l_iommu_set_ba(struct l_iommu *iommu, unsigned long *ba)
{
	__l_iommu_set_ba(iommu->node, ba);
}
#else
static inline void l_iommu_set_ba(struct l_iommu *iommu, unsigned long *ba)
{
	l_iommu_write(iommu, (u32)pa_to_iopte(ba[0]), L_IOMMU_BA);
}
#endif

static void iommu_flushall(struct l_iommu *iommu)
{
	l_iommu_write(iommu, 0, L_IOMMU_FLUSH_ALL);
}

static inline void iommu_flush(struct l_iommu *iommu, dma_addr_t addr)
{
	l_iommu_write(iommu, addr_to_flush(addr), L_IOMMU_FLUSH_ADDR);
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

static unsigned l_dom_page_indx(struct iommu_domain *d, unsigned long iova)
{
	if (!l_dom_iova_hi(iova))
		return iova / IO_PAGE_SIZE;

	return (iova - d->map_base) / IO_PAGE_SIZE;
}

static int l_add_buffer(struct iommu_domain *d,
		phys_addr_t phys, unsigned long iova)
{
	int ret;
	unsigned long flags;
	unsigned i = l_dom_page_indx(d, iova);
	if (!l_dom_iova_hi(iova)) {
		WARN_ON(d->orig_phys_lo[i]);
		d->orig_phys_lo[i] = phys;
		return 0;
	}

	idr_preload(GFP_ATOMIC);
	write_lock_irqsave(&d->lock_hi, flags);
	ret = idr_alloc(&d->idr_hi, (void *)phys, i, i + 1, GFP_NOWAIT);
	write_unlock_irqrestore(&d->lock_hi, flags);
	idr_preload_end();

	return ret;
}

static void l_remove_buffer(struct iommu_domain *d, unsigned long iova)
{
	unsigned long flags;
	unsigned i = l_dom_page_indx(d, iova);
	if (!l_dom_iova_hi(iova)) {
		WARN_ON(!d->orig_phys_lo[i]);
		d->orig_phys_lo[i] = 0;
		return;
	}
	write_lock_irqsave(&d->lock_hi, flags);
	WARN_ON(idr_remove(&d->idr_hi, i) == NULL);
	write_unlock_irqrestore(&d->lock_hi, flags);
}

static phys_addr_t l_dom_lookup_buffer(struct iommu_domain *d,
				     unsigned long iova)
{
	void *p;
	unsigned long flags;
	unsigned i = l_dom_page_indx(d, iova);
	if (!l_dom_iova_hi(iova))
		return d->orig_phys_lo[i];

	read_lock_irqsave(&d->lock_hi, flags);
	p = idr_find(&d->idr_hi, i);
	read_unlock_irqrestore(&d->lock_hi, flags);

	return (phys_addr_t)p;
}

static phys_addr_t l_alloc_buffer(struct iommu_domain *d, phys_addr_t orig_phys,
				  size_t size, unsigned long iova, int node)
{
	int ret;
	int npages = iommu_num_pages(orig_phys, size, IO_PAGE_SIZE);
	gfp_t gfp_mask = __GFP_THISNODE | GFP_ATOMIC | __GFP_NOWARN;
	int order = get_order(npages * IO_PAGE_SIZE);
	struct page *page = alloc_pages_node(node, gfp_mask, order);
	if (!page)
		return 0;
	ret = l_add_buffer(d, orig_phys, iova);
	if (ret < 0) {
		__free_pages(page, order);
		return 0;
	}
	return page_to_phys(page);
}

static void l_free_buffer(struct iommu_domain *d, phys_addr_t phys,
				size_t size, unsigned long iova)
{
	phys_addr_t orig_paddr = l_dom_lookup_buffer(d, iova);
	int npages = iommu_num_pages(phys, size, IO_PAGE_SIZE);
	int order = get_order(npages * IO_PAGE_SIZE);
	if (!orig_paddr)
		return;
	__free_pages(phys_to_page(phys), order);
	l_remove_buffer(d, iova);
}

static struct pci_dev *l_dev_to_parent_pcidev(struct device *dev)
{
	while (dev && !dev_is_pci(dev))
		dev = dev->parent;
	BUG_ON(!dev);
	BUG_ON(!dev_is_pci(dev));
	return to_pci_dev(dev);
}

/*
 * This function checks if the driver got a valid device from the caller to
 * avoid dereferencing invalid pointers.
 */
static bool l_iommu_check_device(struct device *dev)
{
	struct pci_dev *pdev;
	if (!dev || !dev->dma_mask)
		return false;

	while (dev && !dev_is_pci(dev))
		dev = dev->parent;

	if (!dev || !dev_is_pci(dev))
		return false;
	pdev = to_pci_dev(dev);
	if (pdev->vendor == PCI_VENDOR_ID_MCST_TMP &&
			pdev->device == PCI_DEVICE_ID_MCST_3D_VIVANTE_R2000P &&
			/* Check if r2000+ is a video card */
			(pdev->subsystem_device != 3)) {
		return false;
	}
	return true;
}

static void l_iommu_init_hw(struct l_iommu *iommu, unsigned long win_sz)
{
	int i;
	unsigned long pa[ARRAY_SIZE(iommu->table)];
	unsigned long range = ilog2(win_sz) - ilog2(MIN_IOMMU_WINSIZE);
	range <<= IOMMU_RNGE_OFF;	/* Virtual DMA Address Range */
	for (i = 0; i < ARRAY_SIZE(iommu->table); i++)
		pa[i] = iommu->table[i].pgtable_pa;

	l_iommu_set_ba(iommu, pa);

	if (iommu->prefetch_supported)
		range |= IOMMU_CTRL_PREFETCH_EN;

	l_iommu_write(iommu, range | IOMMU_CTRL_CASHABLE_TTE |
					IOMMU_CTRL_ENAB, L_IOMMU_CTRL);
	iommu_flushall(iommu);
}

static int l_iommu_init_table(struct l_iommu_table *t, unsigned long win_sz,
						int node)
{
	int win_bits = ilog2(win_sz);
	size_t sz = win_sz / IO_PAGE_SIZE * sizeof(iopte_t);
	void *p;
	if (t->pgtable)
		return 0;
	p = kzalloc_node(sz, GFP_KERNEL, node);
	if (!p)
		goto fail;
	t->pgtable_pa = __pa(p);

	t->pgtable = l_iommu_map_table(t->pgtable_pa, sz);
	if (!t->pgtable)
		goto fail;

	t->map_base = (~0UL) << win_bits;
	t->map_base &= L_IOMMU_VA_MASK;
	if (win_bits <= 32)
		t->map_base &= 0xFFFFffff;

	return 0;
fail:
	return -1;
}

static void l_iommu_free_table(struct l_iommu_table *t)
{
	if (t->pgtable == NULL)
		return;

	t->pgtable = l_iommu_unmap_table(t->pgtable);
	kfree(t->pgtable);
	t->pgtable = NULL;
}

struct l_iommu_device {
	unsigned regs_offset;
	unsigned companion_regs_offset;
};

static int l_iommu_init_tables(struct l_iommu *iommu)
{
	unsigned long win_sz = l_iommu_win_sz;
	int node = iommu->node;
	int n = ARRAY_SIZE(iommu->table), i, ret;
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
	return ret;
fail:
	for (i = 0; i < ARRAY_SIZE(iommu->table); i++)
		l_iommu_free_table(iommu->table);
	return ret;
}

static void l_iommu_cleanup_one(struct l_iommu *iommu, int stage)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(iommu->table); i++)
		l_iommu_free_table(iommu->table);

	switch (stage) {
	case 4:
		iommu_device_unregister(&iommu->iommu);
		fallthrough;
	case 3:
		iommu_device_sysfs_remove(&iommu->iommu);
		fallthrough;
	case 2:
		iommu_group_put(iommu->default_group);
		fallthrough;
	case 1:
		kfree(iommu);
	}
}

static __init struct l_iommu *l_iommu_init_one(int node, struct device *parent,
					const struct l_iommu_device *desc)
{
	int ret, stage = 0;
	struct l_iommu *i = kzalloc_node(sizeof(*i), GFP_KERNEL, node);

	if (!i)
		return ERR_PTR(-ENOMEM);
	stage++;
	i->node = node;
	i->regs_offset = desc->regs_offset;
	i->companion_regs_offset = desc->companion_regs_offset;

	mutex_init(&i->mutex);

	if (l_prefetch_iopte_supported() && !l_not_use_prefetch)
		i->prefetch_supported = 1;

	i->default_group = iommu_group_alloc();
	if (IS_ERR(i->default_group)) {
		ret = PTR_ERR(i->default_group);
		goto fail;
	}
	stage++;

	ret = iommu_device_sysfs_add(&i->iommu,  parent, NULL,
			"iommu%x", i->regs_offset ? i->regs_offset : node);
	if (ret)
		goto fail;
	stage++;
	iommu_device_set_ops(&i->iommu, &l_iommu_ops);
	ret = iommu_device_register(&i->iommu);
	if (ret)
		goto fail;
	return i;
fail:
	l_iommu_cleanup_one(i, stage);
	return ERR_PTR(ret);
}

static void l_quirk_enable_local_iommu(struct pci_dev *pdev)
{
	struct l_iommu *i = pdev->dev.archdata.iommu;

	/* Check if r2000+ is a video card */
	if (pdev->device == PCI_DEVICE_ID_MCST_MGA26 && (
			pdev->subsystem_device == 9 ||
			pdev->subsystem_device == 10)) {
		return;
	}
	if (pdev->subsystem_device == 3)
		return;
	if (WARN_ON(pdev->bus->number != 0)) /* r2000+ not a video card */
		return;
	WARN_ON(l_iommu_init_tables(i));
	l_iommu_init_hw(i, l_iommu_win_sz);
}
DECLARE_PCI_FIXUP_ENABLE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_MGA26, l_quirk_enable_local_iommu);
DECLARE_PCI_FIXUP_ENABLE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_VP9_BIGEV2_R2000P, l_quirk_enable_local_iommu);
DECLARE_PCI_FIXUP_ENABLE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_VP9_G2_R2000P, l_quirk_enable_local_iommu);

static const struct pci_device_id l_devices_with_iommu[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_MGA26)},
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_VP9_BIGEV2_R2000P)},
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_VP9_G2_R2000P)},
	{ }	/* terminate list */
};
/* must correspond to l_devices_with_iommu[] */
static const unsigned l_iommu_devices_iommu_offset[] = {
	0x2800,
	0x2c00,
	0x2c00,
};

static const struct l_iommu_device l_iommu_devices[] = {
	{ 0x2800 },
	{ 0x2c00 },
};

static LIST_HEAD(l_iommus);
static struct l_iommu *l_node_to_iommu[MAX_NUMNODES];

#define for_each_iommu(iommu) \
	list_for_each_entry(iommu, &l_iommus, list)

static struct l_iommu *l_iommu_get_iommu_for_device(struct device *dev)
{
	int i;
	unsigned o;
	struct l_iommu *iommu;
	const struct pci_device_id *id;
	struct pci_dev *pdev;
	if (!l_has_devices_with_iommu())
		return NULL;
	pdev = l_dev_to_parent_pcidev(dev);
	id = pci_match_id(l_devices_with_iommu, pdev);
	if (!id)
		return NULL;
	if (pdev->subsystem_device == 3)  /* r2000+ not a video card */
		return NULL;
	if (WARN_ON(pdev->bus->number != 0)) /* r2000+ not a video card */
		return NULL;
	i = id - l_devices_with_iommu;
	o = l_iommu_devices_iommu_offset[i];

	for_each_iommu(iommu) {
		if (l_dev_to_node(dev) == iommu->node &&
				  iommu->regs_offset == o) {
			return iommu;
		}
	}
	BUG(); /* unreachable */
	return NULL;
}

static struct l_iommu *l_find_iommu(struct device *dev)
{
	struct l_iommu *i;
	if (!l_iommu_check_device(dev))
		return NULL;
	i = l_iommu_get_iommu_for_device(dev);
	if (i)
		return i;
	return l_node_to_iommu[l_dev_to_node(dev)];
}

static void l_iommu_cleaup(void)
{
	struct l_iommu *i, *ii;
	list_for_each_entry_safe(i, ii, &l_iommus, list) {
		list_del(&i->list);
		l_iommu_cleanup_one(i, 4);
	}
	memset(l_node_to_iommu, 0, sizeof(l_node_to_iommu));
}

static __init int __l_iommu_init(int node, struct device *parent)
{
	int j;
	struct l_iommu_device default_desc = {};
	struct l_iommu *i;
	i = l_iommu_init_one(node, parent, &default_desc);
	if (IS_ERR(i))
		goto fail;
	list_add(&i->list, &l_iommus);
	l_node_to_iommu[node] = i;
	if (l_iommu_init_tables(i)) {
		i = ERR_PTR(-ENOMEM);
		goto fail;
	}
	l_iommu_write(i, 0, L_IOMMU_CTRL);
	l_iommu_enable_embedded_iommus(node);

	l_iommu_init_hw(i, l_iommu_win_sz);

	if (!l_has_devices_with_iommu())
		return 0;

	for (j = 0; j < ARRAY_SIZE(l_iommu_devices); j++) {
		i = l_iommu_init_one(node, parent, &l_iommu_devices[j]);
		if (IS_ERR(i))
			goto fail;
		list_add(&i->list, &l_iommus);
	}
	return 0;
fail:
	l_iommu_cleaup();
	return PTR_ERR(i);
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
			    int iommu_prot, gfp_t gfp)
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
	if (WARN_ON(!d->iommu->table[IOMMU_LOW_TABLE].pgtable))
		return -ENODEV;

	/* If no access, then nothing to do */
	if (!(iommu_prot & (IOMMU_READ | IOMMU_WRITE)))
		return 0;

	if (copy) {
		phys = l_alloc_buffer(iommu_domain, orig_phys, size, iova, node);
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
		l_free_buffer(iommu_domain,
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
	int ret = 0;
	unsigned o;
	struct page *p;
	struct l_iommu_domain *d = to_l_domain(iommu_domain);
	struct l_iommu *i = dev->archdata.iommu;
	mutex_lock(&i->mutex);
	if (l_iommu_has_numa_bug() && !iommu_domain->orig_phys_lo) {
		o = get_order(MIN_IOMMU_WINSIZE / IO_PAGE_SIZE *
				sizeof(*iommu_domain->orig_phys_lo));
		p = alloc_pages_node(i->node,
					__GFP_ZERO | GFP_KERNEL, o);

		if (p)
			iommu_domain->orig_phys_lo = page_address(p);
		else
			ret = -ENOMEM;
	}
	mutex_unlock(&i->mutex);

	d->iommu = i;
	return ret;
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
		end &= L_IOMMU_VA_MASK;
	}
	d->domain.geometry.aperture_start = start;
	d->domain.geometry.aperture_end   = end;
	d->domain.geometry.force_aperture = true;

	idr_init(&d->domain.idr_hi);
	rwlock_init(&d->domain.lock_hi);
	d->domain.map_base = (~0UL) << win_bits;
	d->domain.map_base &= L_IOMMU_VA_MASK;

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
	idr_destroy(&d->domain.idr_hi);
	kfree(d);
}

static void l_iommu_probe_finalize(struct device *dev)
{
	iommu_setup_dma_ops(dev, 0, dma_get_mask(dev) + 1);
}
static struct iommu_device *l_iommu_probe_device(struct device *dev)
{
	struct l_iommu *i;
	if (!l_iommu_check_device(dev))
		return ERR_PTR(-ENODEV);
	i = l_find_iommu(dev);
	if (!i)
		return ERR_PTR(-ENODEV);
	dev->archdata.iommu = i;
	return &i->iommu;
}

static void l_iommu_release_device(struct device *dev)
{
	dev->archdata.iommu = NULL;
}

static struct iommu_group *l_iommu_device_group(struct device *dev)
{
	struct l_iommu *i;
	if (!l_iommu_check_device(dev))
		return NULL;
	i = l_find_iommu(dev);
	if (!i)
		return NULL;
	return iommu_group_ref_get(i->default_group);
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
	struct pci_dev *pdev = l_dev_to_parent_pcidev(dev);


	if (l_iommu_win_sz > (1UL << 32)) {
		unsigned long start = 1UL << 32;
		unsigned long sz = L_IOMMU_VA_MASK  - l_iommu_win_sz + 1;
		/* remove space beetween 0xffffFFFF and map_base */
		region = iommu_alloc_resv_region(start, sz,
						prot, IOMMU_RESV_RESERVED);
		if (!region)
			return;
		list_add_tail(&region->list, head);
	}

	sd = pdev->bus->sysdata;
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

	if (dev_iommu_fwspec_get(dev))
		iommu_dma_get_resv_regions(dev, head);
}

static void l_iommu_put_resv_regions(struct device *dev,
				      struct list_head *head)
{
	struct iommu_resv_region *entry, *next;

	list_for_each_entry_safe(entry, next, head, list)
		kfree(entry);
}

static struct iommu_ops l_iommu_ops = {
	.map		= l_iommu_map,
	.unmap		= l_iommu_unmap,
	.iova_to_phys	= l_iommu_iova_to_phys,

	.domain_alloc	= l_iommu_domain_alloc,
	.domain_free	= l_iommu_domain_free,
	.attach_dev	= l_iommu_attach_device,
	.detach_dev	= l_iommu_detach_device,
	.probe_device	= l_iommu_probe_device,
	.release_device	= l_iommu_release_device,
	.probe_finalize = l_iommu_probe_finalize,
	.device_group	= l_iommu_device_group,
	.capable	= l_iommu_capable,

	.get_resv_regions	= l_iommu_get_resv_regions,
	.put_resv_regions	= l_iommu_put_resv_regions,

	.pgsize_bitmap = L_PGSIZE_BITMAP,
};

static void l_quirk_iommu_direct_devices(struct pci_dev *pdev)
{
	/* use dma-direct interface */
	set_dma_ops(&pdev->dev, NULL);
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_MGA2,
			  l_quirk_iommu_direct_devices);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_MCST_TMP,
	PCI_DEVICE_ID_MCST_3D_VIVANTE_R2000P, l_quirk_iommu_direct_devices);

#define VCFG 0x40
# define VCFG_Convert32BitAddressForIommu 0x00000002
static void l_quirk_iommu_direct_devices_r2000p(struct pci_dev *pdev)
{
	/*
	 * http://wiki.lab.sun.mcst.ru/e2kwiki/R2000p#.D0.A0.D0.B5.D0.B3.D0.B8.D1.81.D1.82.D1.80_VCFG
	 *
	 * Clear VCFG.Convert32BitAddressForIommu bit: disable hardware
	 * setting of [39:32] bits in IOMMU DMA addresses with IommuEnable.
	 */
	u32 data;
	pci_read_config_dword(pdev, VCFG, &data);
	data = data & ~VCFG_Convert32BitAddressForIommu;
	pci_write_config_dword(pdev, VCFG, data);
	/* Check if r2000+ is a video card */
	if (pdev->subsystem_device != 3) {
		/* use dma-direct interface */
		set_dma_ops(&pdev->dev, NULL);
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_MCST_TMP,
	PCI_DEVICE_ID_MCST_3D_VIVANTE_R2000P, l_quirk_iommu_direct_devices_r2000p);

#ifdef CONFIG_PM_SLEEP
static int l_iommu_suspend(void)
{
	return 0;
}

static void l_iommu_resume(void)
{
	struct l_iommu *i;
	for_each_iommu(i)
		l_iommu_init_hw(i, l_iommu_win_sz);
}

void l_iommu_shutdown(void)
{
	struct l_iommu *i;
	if (paravirt_enabled())
		return;
	for_each_iommu(i)
		l_iommu_write(i, 0, L_IOMMU_CTRL);
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
void l_iommu_shutdown(void) {}
static inline void l_iommu_init_pm_ops(void) {}
#endif	/* CONFIG_PM_SLEEP */


static void l_get_max_resource(struct pci_bus *bus, resource_size_t *start, resource_size_t *end)
{
	int i;
	struct resource *res;
	resource_size_t e = 0, s = ~0ULL;
	struct pci_dev *dev = bus->self;

	pci_bus_for_each_resource(bus, res, i) {
		if (!res || !res->flags || res->start > res->end)
			continue;
		if (!(res->flags & IORESOURCE_MEM))
			continue;
		if (res->start < s)
			s = res->start;
		if (res->end > e)
			e = res->end;
	}
	for (i = 0; dev && i < DEVICE_COUNT_RESOURCE; i++) {
		res = dev->resource + i;
		if (!res || !res->flags || res->start > res->end)
			continue;
		if (!(res->flags & IORESOURCE_MEM))
			continue;
		if (res->start < s)
			s = res->start;
		if (res->end > e)
			e = res->end;
	}
	*start = s;
	*end = e;
}

static void l_trim_pci_window(struct pci_bus *root_bus)
{
	struct pci_bus *b;
	resource_size_t start = ~0ULL, end = 0;
	struct resource_entry *window;
	struct pci_host_bridge *bridge = pci_find_host_bridge(root_bus);

	list_for_each_entry(b, &root_bus->children, node) {
		resource_size_t s, e;
		l_get_max_resource(b, &s, &e);
		if (s < start)
			start = s;
		if (e > end)
			end = e;
	}

	resource_list_for_each_entry(window, &bridge->windows) {
		struct resource *res;
		if (window->res != &iomem_resource)
			continue;
		/*
		 * Fixup for iova_reserve_pci_windows(): trim the window if
		 * the boot didn't pass us pci memory ranges
		 * (see mp_pci_add_resources()).
		 */
		res = kzalloc(sizeof(*res), GFP_KERNEL);
		BUG_ON(res == NULL);
		res->name = "PCI mem";
		res->flags = IORESOURCE_MEM;
		res->start = start;
		res->end = end;
		window->res = res;
		pr_info("iommu: trim bridge window: %pR\n", window->res);
		break;
	}
}

const struct dma_map_ops *dma_ops;
EXPORT_SYMBOL(dma_ops);

static int __init l_iommu_setup(char *str)
{
	unsigned long win_sz = DFLT_IOMMU_WINSIZE;

	if (!strcmp(str, "force-numa-bug-on")) {
		l_iommu_force_numa_bug_on = 1;
	} else if (!strcmp(str, "no-numa-bug")) {
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

static int l_init_uncached_pool(void)
{
	struct gen_pool *p;
	int ret = 0;

	p = gen_pool_create(PAGE_SHIFT, 0);
	if (!p) {
		ret = -ENOMEM;
		goto error;
	}
	gen_pool_set_algo(p, gen_pool_first_fit_order_align, NULL);

error:
	return ret;
}

static int __init l_iommu_init(void)
{
	int ret;
	struct pci_bus *b;
	size_t idr_sz = 1UL + INT_MAX;
	size_t tbl_sz = l_iommu_win_sz / IO_PAGE_SIZE * sizeof(iopte_t);

	WARN_ON(l_init_uncached_pool());
#if defined(CONFIG_SWIOTLB) || defined(CONFIG_E2K)
	if (e2k_iommu_supported() && !l_use_swiotlb)
		return 0;

	if (!l_iommu_supported() || l_use_swiotlb) {
		int node;

		for_each_online_node(node) {
			if (!NODE_DATA(node))
				continue;

# if defined(CONFIG_E2K) && defined(CONFIG_NUMA)
			swiotlb_late_init_with_default_size(L_SWIOTLB_DEFAULT_SIZE, node);
# else
			swiotlb_late_init_with_default_size(L_SWIOTLB_DEFAULT_SIZE);
# endif
		}

		l_iommu_shutdown();

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

	if (paravirt_enabled())
		return 0;

	list_for_each_entry(b, &pci_root_buses, node) {
		int node = 0;
#ifdef CONFIG_IOHUB_DOMAINS
		struct iohub_sysdata *sd = b->sysdata;
		node = sd->node;
#endif
		l_trim_pci_window(b);
		ret = __l_iommu_init(node, &b->dev);
		if (ret)
			return ret;
		pr_info("iommu:%d: enabled; window size %lu MiB\n",
				node,  l_iommu_win_sz / (1024 * 1024));
	}
	ret = bus_set_iommu(&pci_bus_type, &l_iommu_ops);
	if (ret)
		return ret;
	ret = bus_set_iommu(&platform_bus_type, &l_iommu_ops);
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
