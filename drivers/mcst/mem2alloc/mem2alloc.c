/* Copyright 2012 Google Inc. All Rights Reserved. */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/swiotlb.h>

#ifdef CONFIG_E2K
# include <asm/set_memory.h>
#endif

#include "mem2alloc.h"

#ifdef CONFIG_MCST
#ifndef CLASS_NAME
#define CLASS_NAME               "mem2alloc_class"
#endif
static struct class* devClass = NULL;
#endif
static int mem2alloc_major = 0;	/* dynamic */
static DEFINE_SPINLOCK(mem_lock);

struct ma_chunk {
	struct ma_chunk *next;
	struct page *page;
	MemallocParams params;
};

static int AllocMemory(MemallocParams *p, struct file *filp);
static int FreeMemory(u64 busaddr, struct file *filp);
static int mem2alloc_mmap(struct file *file, struct vm_area_struct *vma);

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
		if (ret)
			break;

		ret = copy_to_user((MemallocParams *) arg, &memparams,
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
#ifdef CONFIG_E2K
		set_memory_wb((unsigned long) __va(p->phys_address), (p->size >> PAGE_SHIFT));
#endif
		__free_pages(c->page, get_order(p->size));
		c = c->next;
		kfree(c2);
	}
	return 0;
}

void __exit mem2alloc_cleanup(void)
{
#ifdef CONFIG_MCST
    device_destroy(devClass, MKDEV(mem2alloc_major, 0));
    class_destroy(devClass);
#endif
	unregister_chrdev(mem2alloc_major, "mem2alloc");
}

/* VFS methods */
static struct file_operations mem2alloc_fops = {
	.owner = THIS_MODULE,
	.open = mem2alloc_open,
	.release = mem2alloc_release,
	.compat_ioctl = mem2alloc_ioctl,
	.unlocked_ioctl = mem2alloc_ioctl,
	.mmap = mem2alloc_mmap
};

int __init mem2alloc_init(void)
{
	int result =
	    register_chrdev(mem2alloc_major, "mem2alloc", &mem2alloc_fops);
	if (result < 0)
		goto err;
	else if (result != 0)	/* this is for dynamic major */
		mem2alloc_major = result;

#ifdef CONFIG_MCST
    devClass = class_create(THIS_MODULE, CLASS_NAME);

    if (IS_ERR(devClass))
    {
		devClass = NULL;
        printk(KERN_ERR "mem2alloc: Failed to create the class.\n");
		goto err;
    }

    device_create(devClass, NULL, MKDEV(mem2alloc_major, 0), NULL, "mem2alloc");
#endif
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
	gfp_t gfp_mask = __GFP_ZERO | GFP_USER;
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
#if defined(CONFIG_E2K) && defined(CONFIG_NUMA)
	if (swiotlb_max_segment(swiotlb_node(dev)) &&	/* swiotlb is running */
#else
	if (swiotlb_max_segment() &&
#endif
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

	p->phys_address = page_to_phys(c->page);
#ifdef CONFIG_E2K
	set_memory_wc((unsigned long) __va(p->phys_address), (p->size >> PAGE_SHIFT));
#endif

	spin_lock(&mem_lock);
	n = filp->private_data;
	c->next = n;
	filp->private_data = c;
	spin_unlock(&mem_lock);

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
#ifdef CONFIG_E2K
	set_memory_wb((unsigned long) __va(p->phys_address), (p->size >> PAGE_SHIFT));
#endif
	__free_pages(c->page, get_order(p->size));
	kfree(c);
	r = 0;

	return r;
}

static int mem2alloc_mmap(struct file *file, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;
	phys_addr_t offset = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;
	struct ma_chunk *c;
	int ret;

	/* Check that this is indeed a chunk that was allocated with mem2alloc */
	spin_lock(&mem_lock);
	for (c = file->private_data; c != NULL; c = c->next) {
		if (c->params.phys_address == offset)
			break;
	}
	ret = (!c || WARN_ON_ONCE(c->params.size != size)) ? -EINVAL : 0;
	spin_unlock(&mem_lock);
	if (ret)
		return ret;

	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	/* Remap-pfn-range will mark the range VM_IO */
	if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
			    size, vma->vm_page_prot)) {
		return -EAGAIN;
	}
	return 0;
}

module_init(mem2alloc_init);
module_exit(mem2alloc_cleanup);

/* module description */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Google");
MODULE_DESCRIPTION("DMA RAM allocation");
