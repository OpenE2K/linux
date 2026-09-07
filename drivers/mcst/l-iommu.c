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
#include <linux/of_platform.h>
#include <linux/irq.h>

#include <asm/l-iommu.h>

#include "../../../drivers/iommu/dma-iommu.h"


#ifndef	IOMMU_TABLES_NR
#define IOMMU_TABLES_NR		1
#define IOMMU_LOW_TABLE		0
#define IOMMU_HIGH_TABLE	0
#endif

int l_use_swiotlb = 0;
int l_iommu_no_numa_bug = 0;
EXPORT_SYMBOL(l_iommu_no_numa_bug);

int l_iommu_force_numa_bug_on = 0;
EXPORT_SYMBOL(l_iommu_force_numa_bug_on);
unsigned long l_iommu_win_sz = DFLT_IOMMU_WINSIZE;

static int l_not_use_prefetch = 0;
static struct iommu_ops l_iommu_ops;


#ifndef l_prefetch_iopte_supported
#define l_prefetch_iopte_supported()	0
#define	l_prefetch_iopte(iopte, prefetch)	do {} while (0)
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
	int node;
	int irq;

	struct mutex mutex;

	struct l_iommu_table {
		iopte_t	*pgtable;
		unsigned long pgtable_pa;
		unsigned long map_base;
	} table[IOMMU_TABLES_NR];

	unsigned prefetch_supported:	1;

	struct iommu_group *l_iommu_group;
	struct iommu_device iommu;	/* IOMMU core handle */
};

static int l_dev_to_node(struct device *dev)
{
	return dev && dev_to_node(dev) >= 0 ?
			dev_to_node(dev) : 0;
}

static void l_iommu_write(struct l_iommu *iommu, unsigned val, unsigned addr)
{
	__l_iommu_write(iommu->node, val, addr);
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

	/* Check if r2000+ is a video card */
	if (pdev->device == PCI_DEVICE_ID_MCST_3D_VIVANTE_R2000P &&
			pdev->vendor == PCI_VENDOR_ID_MCST_TMP &&
			((pdev->subsystem_device != 3) &&
			(pdev->subsystem_device != 4)))
		return false;

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
		iommu_group_put(iommu->l_iommu_group);
		fallthrough;
	case 1:
		;
	}
}

static int l_iommu_ini(struct l_iommu *i, struct device *dev)
{
	int ret, stage = 0;

	stage++;

	mutex_init(&i->mutex);

	if (l_prefetch_iopte_supported() && !l_not_use_prefetch)
		i->prefetch_supported = 1;


	i->l_iommu_group = iommu_group_alloc();
	if (IS_ERR(i->l_iommu_group)) {
		ret = PTR_ERR(i->l_iommu_group);
		goto fail;
	}
	stage++;

	ret = iommu_device_sysfs_add(&i->iommu, dev, NULL,
			"iommu%x", i->node);
	if (ret)
		goto fail;

	return ret;

fail:
	l_iommu_cleanup_one(i, stage);
	return ret;
}

static int l_iommu_init_one(struct l_iommu *iommu, struct device *dev)
{
	int ret;

	ret = iommu_device_register(&iommu->iommu, &l_iommu_ops, dev);
	if (ret) {
		l_iommu_cleanup_one(iommu, 3);
		return ret;
	}

	return 0;
}

static int __l_iommu_init(struct l_iommu *iommu, struct device *dev)
{
	int ret = l_iommu_ini(iommu, dev);
	if (ret)
		goto fail;

	ret = l_iommu_init_one(iommu, dev);
	if (ret)
		goto fail;

	if (l_iommu_init_tables(iommu)) {
		l_iommu_cleanup_one(iommu, 4);
		ret = -ENOMEM;
		goto fail;
	}

	l_iommu_write(iommu, 0, L_IOMMU_CTRL);
	l_iommu_init_hw(iommu, l_iommu_win_sz);

	return 0;

fail:
	return ret;
}

/* IOMMU API */
static int l_iommu_map(struct iommu_domain *iommu_domain,
			    unsigned long iova, phys_addr_t phys, size_t size,
			    int iommu_prot, gfp_t gfp)
{
	unsigned long prot;
	struct l_iommu_domain *d = to_l_domain(iommu_domain);
	iopte_t *ptep = l_iommu_iopte(d->iommu, iova);

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
	struct l_iommu_domain *d = to_l_domain(iommu_domain);
	struct l_iommu *i = dev_iommu_priv_get(dev);

	d->iommu = i;
	return 0;
}

static struct iommu_domain *__l_iommu_domain_alloc(unsigned type, int node)
{
	struct l_iommu_domain *d;
	int win_bits = ilog2(l_iommu_win_sz);
	unsigned long start = ~0UL << win_bits;
	unsigned long end   = ~0UL;

	if (type != IOMMU_DOMAIN_DMA && type != IOMMU_DOMAIN_UNMANAGED)
		return NULL;

	d = kzalloc_node(sizeof(*d), GFP_KERNEL, node);
	if (!d)
		return NULL;

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

	return &d->domain;

}

static struct iommu_domain *l_iommu_domain_alloc(unsigned type)
{
	return __l_iommu_domain_alloc(type, -1);
}

static void l_iommu_domain_free(struct iommu_domain *iommu_domain)
{
	struct l_iommu_domain *d = to_l_domain(iommu_domain);
	kfree(d);
}

static void l_iommu_probe_finalize(struct device *dev)
{
	iommu_setup_dma_ops(dev, 0, dma_get_mask(dev) + 1);
}

static struct iommu_device *l_iommu_probe_device(struct device *dev)
{
	struct l_iommu *i;
	struct device *d = dev;
	if (!l_iommu_check_device(dev))
		return ERR_PTR(-ENODEV);

	do {
		i = dev_iommu_priv_get(d);
		d = d->parent;
	} while (!i && d);

	if (!i)
		return ERR_PTR(-ENODEV);
	dev_iommu_priv_set(dev, i);
	return &i->iommu;
}

static void l_iommu_release_device(struct device *dev)
{
	dev_iommu_priv_set(dev, NULL);
}

static struct iommu_group *l_iommu_device_group(struct device *dev)
{
	struct l_iommu *i = dev_iommu_priv_get(dev);
	if (!i || !l_iommu_check_device(dev))
		return ERR_PTR(-ENODEV);
	/*  We can not use pci_device_group() due to poor iohub1
	 pci hierarchy */
	return iommu_group_ref_get(i->l_iommu_group);

}

static bool l_iommu_capable(struct device *dev, enum iommu_cap cap)
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
	u64 msi_addr;
	struct irq_data *d;
	struct msi_msg msg;
	struct pci_config_window *cfg;
	struct iommu_resv_region *region;
	struct l_iommu *i = dev_iommu_priv_get(dev);
	int prot = IOMMU_WRITE | IOMMU_NOEXEC | IOMMU_MMIO;
	struct pci_dev *pdev = l_dev_to_parent_pcidev(dev);

	if (l_iommu_win_sz > (1UL << 32)) {
		unsigned long start = 1UL << 32;
		unsigned long sz = L_IOMMU_VA_MASK  - l_iommu_win_sz + 1;
		/* remove space beetween 0xffffFFFF and map_base */
		region = iommu_alloc_resv_region(start, sz, prot, IOMMU_RESV_RESERVED, GFP_KERNEL);
		if (!region)
			return;
		list_add_tail(&region->list, head);
	}

	cfg = pdev->bus->sysdata;

	d = irq_get_irq_data(i->irq);

	/* get msi address from irq controller */
	if (WARN_ON(irq_chip_compose_msi_msg(d, &msg)))
		return;

	msi_addr = ((u64)msg.address_hi) << 32 |
			(msg.address_lo & ~(RT_MSI_MEMORY_SIZE - 1));
	if (WARN_ON(msi_addr == 0))
		return;
	region = iommu_alloc_resv_region(msi_addr, RT_MSI_MEMORY_SIZE,
				prot, IOMMU_RESV_MSI, GFP_KERNEL);
	if (!region)
		return;
	list_add_tail(&region->list, head);

	region = iommu_alloc_resv_region(VGA_MEMORY_OFFSET, VGA_MEMORY_SIZE, prot,
			IOMMU_RESV_RESERVED, GFP_KERNEL);
	if (!region)
		return;
	list_add_tail(&region->list, head);

	if (dev_iommu_fwspec_get(dev))
		iommu_dma_get_resv_regions(dev, head);
}

static int l_iommu_of_xlate(struct device *dev, struct of_phandle_args *args)
{
	struct platform_device *pdev;

	if (args->args_count != 1) {
		dev_err(dev, "invalid #iommu-cells(%d) property for IOMMU\n",
			args->args_count);
		return -EINVAL;
	}

	if (!dev_iommu_priv_get(dev)) {
		/* Get the iommu device */
		pdev = of_find_device_by_node(args->np);
		if (WARN_ON(!pdev))
			return -EINVAL;

		dev_iommu_priv_set(dev, platform_get_drvdata(pdev));
	}
	return iommu_fwspec_add_ids(dev, args->args, 1);
}

static struct iommu_ops l_iommu_ops = {
	.domain_alloc		= l_iommu_domain_alloc,
	.probe_device		= l_iommu_probe_device,
	.release_device		= l_iommu_release_device,
	.probe_finalize		= l_iommu_probe_finalize,
	.device_group		= l_iommu_device_group,
	.capable		= l_iommu_capable,
	.get_resv_regions	= l_iommu_get_resv_regions,
	.of_xlate		= l_iommu_of_xlate,
	.pgsize_bitmap		= L_PGSIZE_BITMAP,
	.default_domain_ops = &(const struct iommu_domain_ops) {
		.map		= l_iommu_map,
		.unmap		= l_iommu_unmap,
		.iova_to_phys	= l_iommu_iova_to_phys,
		.free		= l_iommu_domain_free,
		.attach_dev	= l_iommu_attach_device,
		.detach_dev	= l_iommu_detach_device,
	}
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
	if ((pdev->subsystem_device != 3) &&
		(pdev->subsystem_device != 4)) {
		/* use dma-direct interface */
		set_dma_ops(&pdev->dev, NULL);
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_MCST_TMP,
	PCI_DEVICE_ID_MCST_3D_VIVANTE_R2000P, l_quirk_iommu_direct_devices_r2000p);


int iommu_panic_off = 0;

static int __init
disable_iommu_panic(char *str)
{
	iommu_panic_off = 1;
	return 1;
}
__setup("iommupanicoff", disable_iommu_panic);

const struct dma_map_ops *dma_ops;
EXPORT_SYMBOL(dma_ops);

#define	L_IOMMU_MLT_HIT			0x8
#define	L_IOMMU_PROT_VIOL_RD		0x4
#define	L_IOMMU_PROT_VIOL_WR		0x2
#define	L_IOMMU_MMU_ERR_ADDR		0x1

static irqreturn_t l_iommu_interrupt(int irq, void *data)
{
	int node = numa_node_id(), n;
	int cpu = smp_processor_id();
	unsigned long fsr = 0, fsr2 = 0, addr;
	char *err;
	char str[1024];

	fsr = l_iommu_read(node, L_IOMMU_ERROR);
	fsr2 = l_iommu_read(node, L_IOMMU_ERROR1);

	addr = (fsr & (~0xf)) << (IO_PAGE_SHIFT - 4);

	err = fsr & L_IOMMU_MLT_HIT		? "Multihit"
		: fsr & L_IOMMU_PROT_VIOL_WR	? "Write protection error"
		: fsr & L_IOMMU_MMU_ERR_ADDR	? "Page miss"
		: fsr & L_IOMMU_PROT_VIOL_RD	? "Read protection error"
			: "Unknown error";
	n = snprintf(str, sizeof(str),
		"IOMMU:%d: error on cpu %d:\n"
		       "\t%s at address 0x%lx "
			"(device: %lx:%lx:%lx, error regs:%lx,%lx).\n",
			node, cpu,
			err, addr,
			(fsr2 >> 8) & 0xff, (fsr2 >> 3) & 0x1f,
			(fsr2 >> 0) & 0x7,
			fsr, fsr2);

	debug_dma_dump_mappings(NULL);

	if (iommu_panic_off)
		pr_emerg("%s", str);
	else
		panic(str);
	return IRQ_HANDLED;
}

static int l_iommu_suspend(struct platform_device *pdev, pm_message_t state)
{
	return 0;
}

static int l_iommu_resume(struct platform_device *pdev)
{
	struct l_iommu *i = platform_get_drvdata(pdev);
	l_iommu_init_hw(i, l_iommu_win_sz);
	return 0;
}

static void l_iommu_shutdown_node(int node)
{
	if (paravirt_enabled())
		return;
	for_each_online_node(node)
		__l_iommu_write(node, 0, L_IOMMU_CTRL);
}

static void l_iommu_shutdown(struct platform_device *pdev)
{
	struct l_iommu *i = platform_get_drvdata(pdev);

	if (paravirt_enabled())
		return;
	l_iommu_write(i, 0, L_IOMMU_CTRL);
}

static int l_iommu_remove(struct platform_device *pdev)
{
	struct l_iommu *i = platform_get_drvdata(pdev);
	l_iommu_cleanup_one(i, 4);
	platform_set_drvdata(pdev, NULL);
	return 0;
}

static int l_iommu_probe(struct platform_device *pdev)
{
	int ret;
	struct l_iommu *i;
	struct device *dev = &pdev->dev;
	int node = l_dev_to_node(dev);
	size_t tbl_sz = l_iommu_win_sz / IO_PAGE_SIZE * sizeof(iopte_t);

	if (paravirt_enabled()) {
		l_iommu_shutdown_node(node);
		return 0;
	}

	if (tbl_sz > PAGE_SIZE << (MAX_ORDER - 1)) {
		tbl_sz = PAGE_SIZE << (MAX_ORDER - 1);
		l_iommu_win_sz = tbl_sz / sizeof(iopte_t) * IO_PAGE_SIZE;
	}

	i = devm_kzalloc(dev, sizeof(*i), GFP_KERNEL);
	if (!i)
		return -ENOMEM;

	i->node = node;
	platform_set_drvdata(pdev, i);

	ret = __l_iommu_init(i, dev);
	if (ret)
		return ret;
	ret = platform_get_irq(pdev, 0);
	if (ret <= 0)
		return ret;

	i->irq = ret;
	ret = devm_request_irq(dev, i->irq, l_iommu_interrupt,
			       0, dev_name(dev), i);
	if (WARN(ret, "%s: %d", dev_name(dev), ret))
		return ret;


	pr_info("iommu:%d: enabled; window size %lu MiB\n",
			i->node,  l_iommu_win_sz / (1024 * 1024));

	return 0;
}

static const struct of_device_id l_iommu_dt_ids[] = {
	{.compatible = "mcst,l-iommu"},
	{ /* sentinel value */ }
};

static struct platform_driver l_iommu_driver = {
	.driver = {
		.name = "l-iommu",
		.of_match_table = of_match_ptr(l_iommu_dt_ids),
	},
	.probe    = l_iommu_probe,
	.remove   = l_iommu_remove,
	.suspend  = l_iommu_suspend,
	.resume   = l_iommu_resume,
	.shutdown = l_iommu_shutdown,
};
module_platform_driver(l_iommu_driver);
MODULE_LICENSE("GPL v2");

