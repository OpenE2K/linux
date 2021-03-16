/* Copyright 2012 Google Inc. All Rights Reserved. */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/swiotlb.h>

#include "mem2alloc.h"

static int mem2alloc_major = 0;	/* dynamic */
static DEFINE_SPINLOCK(mem_lock);

struct ma_chunk {
	struct ma_chunk *next;
	struct page *page;
	MemallocParams params;
};

static int AllocMemory(MemallocParams *p, struct file *filp);
static int FreeMemory(u64 busaddr, struct file *filp);

static long mem2alloc_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long _arg)
{
	int ret = 0;
	void __user *arg = (void __user *) _arg;
	MemallocParams memparams;
	u64 busaddr;

	if (_IOC_DIR(cmd) & _IOC_READ)
		ret = !access_ok(arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		ret = !access_ok(arg, _IOC_SIZE(cmd));
	if (ret)
		return -EFAULT;

	switch (cmd) {
	case MEMALLOC_IOCXGETBUFFER:
		ret = copy_from_user(&memparams, (MemallocParams *) arg,
				     sizeof(MemallocParams));
		if (ret)
			break;

		ret = AllocMemory(&memparams, filp);

		ret |= copy_to_user((MemallocParams *) arg, &memparams,
				    sizeof(MemallocParams));
		break;
	case MEMALLOC_IOCSFREEBUFFER:
		__get_user(busaddr, (u64 *) arg);

		ret = FreeMemory(busaddr, filp);
		break;
	}
	return ret;
}

static int mem2alloc_open(struct inode *inode, struct file *filp)
{
	filp->private_data = NULL;
	return 0;
}

static int mem2alloc_release(struct inode *inode, struct file *filp)
{
	struct ma_chunk *c;
	for (c = filp->private_data; c;) {
		struct pci_dev *pdev;
		struct device *dev = NULL;
		MemallocParams *p = &c->params;
		struct ma_chunk *c2 = c;
		pdev = pci_get_domain_bus_and_slot(p->pci_domain, p->bus,
				PCI_DEVFN(p->slot, p->function));
		if (pdev)
			dev = &pdev->dev;
		dma_unmap_page(dev, p->dma_address, p->size,
			       DMA_BIDIRECTIONAL);
		__free_pages(c->page, get_order(p->size));
		c = c->next;
		kfree(c2);
	}
	return 0;
}

void __exit mem2alloc_cleanup(void)
{
	unregister_chrdev(mem2alloc_major, "mem2alloc");
}

/* VFS methods */
static struct file_operations mem2alloc_fops = {
	.owner = THIS_MODULE,
	.open = mem2alloc_open,
	.release = mem2alloc_release,
	.compat_ioctl = mem2alloc_ioctl,
	.unlocked_ioctl = mem2alloc_ioctl
};

int __init mem2alloc_init(void)
{
	int result =
	    register_chrdev(mem2alloc_major, "mem2alloc", &mem2alloc_fops);
	if (result < 0)
		goto err;
	else if (result != 0)	/* this is for dynamic major */
		mem2alloc_major = result;

	return 0;
      err:
	return result;
}

static int AllocMemory(MemallocParams *p, struct file *filp)
{
	int ret = 0;
	struct pci_dev *pdev;
	struct device *dev = NULL;
	struct ma_chunk *n, *c = kzalloc(sizeof(*c), GFP_KERNEL);
	gfp_t gfp_mask = __GFP_ZERO | GFP_KERNEL;
	pdev = pci_get_domain_bus_and_slot(p->pci_domain, p->bus,
			PCI_DEVFN(p->slot, p->function));
	if (!c)
		return -ENOMEM;
	if (p->size == 0) {
		ret = -EINVAL;
		goto err;
	}
	if (pdev)
		dev = &pdev->dev;
	if (swiotlb_max_segment() &&  /* swiotlb is running */
		   dma_get_mask(dev) <= DMA_BIT_MASK(32)) {
		gfp_mask |= __GFP_DMA;
	}
	c->page = alloc_pages(gfp_mask | __GFP_RETRY_MAYFAIL | __GFP_NOWARN,
			       get_order(p->size));
	if (!c->page)
		c->page = alloc_pages(gfp_mask | __GFP_NOFAIL,
				      get_order(p->size));
	if (!c->page) {
		ret = -ENOMEM;
		goto err;
	}

	p->dma_address = dma_map_page(dev, c->page, 0, p->size,
				      DMA_BIDIRECTIONAL);
	ret = dma_mapping_error(dev, p->dma_address);
	pci_dev_put(pdev);
	if (ret) {
		ret = -EFAULT;
		goto err;
	}
	spin_lock(&mem_lock);
	n = filp->private_data;
	c->next = n;
	filp->private_data = c;
	spin_unlock(&mem_lock);

	p->phys_address = page_to_phys(c->page);
	memcpy(&c->params, p, sizeof(*p));
	return 0;
      err:
	if (c->page)
		__free_pages(c->page, get_order(p->size));
	kfree(c);
	return ret;
}

static int FreeMemory(u64 busaddr, struct file *filp)
{
	int r = -ENOENT;
	struct ma_chunk *c, *prev = NULL;
	struct pci_dev *pdev;
	struct device *dev = NULL;
	MemallocParams *p;

	spin_lock(&mem_lock);
	for (c = filp->private_data; c && c->params.dma_address != busaddr;
					c = c->next)
		prev = c;

	if (c) {
		if (prev)
			prev->next = c->next;
		else
			filp->private_data = c->next;
	}
	spin_unlock(&mem_lock);

	if (!c)
		return r;

	p = &c->params;
	pdev = pci_get_domain_bus_and_slot(p->pci_domain, p->bus,
			PCI_DEVFN(p->slot, p->function));
	if (pdev)
		dev = &pdev->dev;
	dma_unmap_page(dev, p->dma_address, p->size,
			DMA_BIDIRECTIONAL);
	__free_pages(c->page, get_order(p->size));
	kfree(c);
	r = 0;

	return r;
}

module_init(mem2alloc_init);
module_exit(mem2alloc_cleanup);

/* module description */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Google");
MODULE_DESCRIPTION("DMA RAM allocation");
