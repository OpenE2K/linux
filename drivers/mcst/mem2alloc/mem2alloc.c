/* Copyright 2012 Google Inc. All Rights Reserved. */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/swiotlb.h>

#include "mem2alloc.h"

#ifndef CLASS_NAME
#define CLASS_NAME               "mem2alloc_class"
#endif
static struct class* devClass = NULL;
static int mem2alloc_major = 0;	/* dynamic */
static DEFINE_SPINLOCK(mem_lock);

struct ma_chunk {
	struct ma_chunk *next;
	struct device *dev;
	void *cpu_address;
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
	struct ma_chunk *c = NULL;
	for (c = filp->private_data; c;) {
		struct ma_chunk *c2 = c;
		if (c->dev && c->cpu_address)
			dma_free_wc(c->dev, c->params.size, c->cpu_address, c->params.dma_address);
		c = c->next;
		kfree(c2);
	}
	return 0;
}

void __exit mem2alloc_cleanup(void)
{
    device_destroy(devClass, MKDEV(mem2alloc_major, 0));
    class_destroy(devClass);
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

    devClass = class_create(THIS_MODULE, CLASS_NAME);

    if (IS_ERR(devClass))
    {
		devClass = NULL;
        printk(KERN_ERR "mem2alloc: Failed to create the class.\n");
		goto err;
    }

    device_create(devClass, NULL, MKDEV(mem2alloc_major, 0), NULL, "mem2alloc");
	return 0;
      err:
	return result;
}

static int AllocMemory(MemallocParams *p, struct file *filp)
{
	int ret = 0;
	struct pci_dev *pdev = NULL;
	struct device *dev = NULL;
	struct ma_chunk *n, *c = kzalloc(sizeof(*c), GFP_KERNEL);
	gfp_t gfp_mask = GFP_KERNEL | __GFP_ZERO;

	if (!c)
		return -ENOMEM;
	if (p->size == 0) {
		ret = -EINVAL;
		goto err;
	}

	pdev = pci_get_domain_bus_and_slot(p->pci_domain, p->bus,
			PCI_DEVFN(p->slot, p->function));
	if (pdev)
		dev = &pdev->dev;
	if (!dev) {
		ret = -EINVAL;
		goto err;
	}

	c->dev = dev;
	c->params.size = p->size;
	c->cpu_address = dma_alloc_wc(c->dev, c->params.size, &c->params.dma_address, gfp_mask);
	if (!c->cpu_address) {
		ret = -ENOMEM;
		goto err;
	}

	p->dma_address = c->params.dma_address;
	p->phys_address = p->dma_address;

	pci_dev_put(pdev);

	spin_lock(&mem_lock);
	n = filp->private_data;
	c->next = n;
	filp->private_data = c;
	spin_unlock(&mem_lock);

	memcpy(&c->params, p, sizeof(*p));
	return 0;
err:
	if (c->dev && c->cpu_address)
		dma_free_wc(c->dev, c->params.size, c->cpu_address, c->params.dma_address);
	kfree(c);
	return ret;
}

static int FreeMemory(u64 busaddr, struct file *filp)
{
	int r = -ENOENT;
	struct ma_chunk *c, *prev = NULL;

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

	if (c->dev && c->cpu_address)
		dma_free_wc(c->dev, c->params.size, c->cpu_address, c->params.dma_address);
	kfree(c);
	r = 0;

	return r;
}

static int mem2alloc_mmap(struct file *file, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;
	dma_addr_t offset = (dma_addr_t)vma->vm_pgoff << PAGE_SHIFT;
	struct ma_chunk *c = NULL;
	int ret = 0;

	/* Check that this is indeed a chunk that was allocated with mem2alloc */
	spin_lock(&mem_lock);
	for (c = file->private_data; c != NULL; c = c->next) {
		if (c->params.dma_address == offset)
			break;
	}
	ret = (!c || !c->dev || !c->cpu_address ||
			WARN_ON_ONCE(c->params.size != size)) ? -EINVAL : 0;
	spin_unlock(&mem_lock);
	if (ret)
		return ret;

	vma->vm_pgoff = 0;
	vma->vm_flags |= VM_IO | VM_DONTEXPAND | VM_DONTDUMP;

	ret = dma_mmap_wc(c->dev, vma, c->cpu_address,
			c->params.dma_address, c->params.size);
	if (ret)
		return -EAGAIN;

	return 0;
}

module_init(mem2alloc_init);
module_exit(mem2alloc_cleanup);

/* module description */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Google");
MODULE_DESCRIPTION("DMA RAM allocation");
