/*!
 *****************************************************************************
 *
 * @File       vxd_plat_emu.c
 * ---------------------------------------------------------------------------
 *
 * Copyright (c) Imagination Technologies Ltd.
 *
 * The contents of this file are subject to the MIT license as set out below.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 ("GPL")in which case the provisions of
 * GPL are applicable instead of those above.
 *
 * If you wish to allow use of your version of this file only under the terms
 * of GPL, and not to allow others to use your version of this file under the
 * terms of the MIT license, indicate your decision by deleting the provisions
 * above and replace them with the notice and other provisions required by GPL
 * as set out in the file called "GPLHEADER" included in this distribution. If
 * you do not delete the provisions above, a recipient may use your version of
 * this file under the terms of either the MIT license or GPL.
 *
 * This License is also included in this distribution in the file called
 * "MIT_COPYING".
 *
 *****************************************************************************/

#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/gfp.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/pm.h>
#include <linux/mod_devicetable.h>

#include "vxd_common.h"
#include "vxd_plat.h"

#define DEVICE_NAME "vxd"

/*
 * Spec:
 * Emulator PCIe In-Circuit Interface Card.Technical Reference Manual.1.0.24.External PSTDRW.External
 */

/* Emulator address range 0x4000-0x4FFF */
#define PCI_EMU_SYS_CTRL_REGS_BAR (0)
/* Offset of INTERRUPT_ENABLE */
#define PCI_EMU_INTERRUPT_ENABLE_OFS (0x4048)
/* master interrupt enable - default high */
#define PCI_EMU_IRQ_ENABLE (1<<0)
#define PCI_EMU_IRQ_HIGH (1<<1)

/* Emulator reset offset */
#define PCI_EMU_RESET_OFS (0x4000)
/* Emulator reset bits */
#define PCI_EMU_RESET_LOGIC (1<<0)
#define PCI_EMU_RESET_DUT   (1<<1)

#define PCI_EMU_VENDOR_ID (0x1010)
#define PCI_EMU_DEVICE_ID (0x1CE3)

static unsigned long poll_interrupts = 1;   /* Enabled by default */
module_param(poll_interrupts, ulong, 0444);
MODULE_PARM_DESC(poll_interrupts, "Poll for interrupts? 0: No, 1: Yes");

static unsigned long irq_poll_delay_us = 100000; /* 100 ms */
module_param(irq_poll_delay_us, ulong, 0444);
MODULE_PARM_DESC(irq_poll_delay_us, "Delay in us between each interrupt poll");

const unsigned long vxd_plat_poll_udelay = 1000;

static struct heap_config vxd_plat_emu_heap_configs[] = {
#ifdef CONFIG_GENERIC_ALLOCATOR
	{
		.type = IMG_MEM_HEAP_TYPE_CARVEOUT,
		/* .options.carveout to be filled at run time */
		/* .to_dev_addr to be filled at run time */
	},
#else
#error CONFIG_GENERIC_ALLOCATOR was defined
#endif
};

static const int vxd_plat_emu_heaps =
	sizeof(vxd_plat_emu_heap_configs)/sizeof(*vxd_plat_emu_heap_configs);

static const struct pci_device_id pci_pci_ids[] = {
	{ PCI_DEVICE(PCI_EMU_VENDOR_ID, PCI_EMU_DEVICE_ID) },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, pci_pci_ids);

struct imgpci_prvdata {
	int irq;
	struct {
		unsigned long addr;
		unsigned long size;
		void __iomem *km_addr;
	} memmap[3];
	struct pci_dev *pci_dev;
	int irq_poll;
	struct delayed_work irq_work;
};


struct img_pci_driver {
	struct pci_dev *pci_dev;
	struct pci_driver pci_driver;
};

static int vxd_plat_probe(struct pci_dev *pci_dev,
		const struct pci_device_id *id);
static void vxd_plat_remove(struct pci_dev *dev);

static int vxd_plat_suspend(struct device *dev);
static int vxd_plat_resume(struct device *dev);

static UNIVERSAL_DEV_PM_OPS(vxd_pm_plat_ops,
		vxd_plat_suspend, vxd_plat_resume, NULL);

static struct img_pci_driver vxd_pci_drv = {
	.pci_driver = {
		.name = "vxd_pci",
		.id_table = pci_pci_ids,
		.probe = vxd_plat_probe,
		.remove = vxd_plat_remove,
		.driver = {
			.pm = &vxd_pm_plat_ops,
		}
	},
};

static ulong maxmapsizeMB = (sizeof(void *) == 4) ? 400 : 1024;

#if 0
static unsigned int emu_readreg32(struct imgpci_prvdata *data,
		int bar, unsigned long offset
)
{
	void __iomem *reg =
		(void __iomem *)(data->memmap[bar].km_addr + offset);
	return ioread32(reg);
}
#endif

static void emu_writereg32(struct imgpci_prvdata *data,
		int bar, unsigned long offset, int val)
{
	void __iomem *reg =
		(void __iomem *)(data->memmap[bar].km_addr + offset);
	iowrite32(val, reg);
}

static void reset_emu(struct pci_dev *dev,
		struct imgpci_prvdata *data)
{
	if (!dev)
		return;

	emu_writereg32(data, PCI_EMU_SYS_CTRL_REGS_BAR,
			PCI_EMU_RESET_OFS, ~(PCI_EMU_RESET_LOGIC|PCI_EMU_RESET_DUT));
	mdelay(100);
	emu_writereg32(data, PCI_EMU_SYS_CTRL_REGS_BAR,
			PCI_EMU_RESET_OFS, PCI_EMU_RESET_LOGIC|PCI_EMU_RESET_DUT);
}

static irqreturn_t pci_thread_irq(int irq, void *dev_id)
{
	struct pci_dev *dev = (struct pci_dev *)dev_id;

	return vxd_handle_thread_irq(&dev->dev);
}

static irqreturn_t pci_isrcb(int irq, void *dev_id)
{
	struct pci_dev *dev = (struct pci_dev *)dev_id;
	struct imgpci_prvdata *data = vxd_get_plat_data(&dev->dev);
	irqreturn_t ret = IRQ_NONE;

	if (data == NULL || dev_id == NULL) {
		/* spurious interrupt: not yet initialised. */
		goto exit;
	}

	ret = vxd_handle_irq(&dev->dev);
exit:
	return ret;
}

/* Interrupt polling function */
static void pci_poll_interrupt(struct work_struct *work)
{
	struct imgpci_prvdata *data = container_of(work,
			struct imgpci_prvdata, irq_work.work);
	struct pci_dev *dev = data->pci_dev;

	if (vxd_handle_irq(&dev->dev) == IRQ_WAKE_THREAD)
		vxd_handle_thread_irq(&dev->dev);

	/* retrigger */
	if (data->irq_poll)
		schedule_delayed_work(&data->irq_work,
				usecs_to_jiffies(irq_poll_delay_us));
}

int vxd_plat_deinit(void)
{
	struct pci_dev *dev = vxd_pci_drv.pci_dev;
	int ret;

	if (dev) {
		struct imgpci_prvdata *data = vxd_get_plat_data(&dev->dev);

		if (data) {
			/* reset the emulator */
			reset_emu(data->pci_dev, data);
		} else {
			dev_dbg(&dev->dev,
				"%s: prv data not found, HW reset omitted\n",
				__func__);
		}
	} else {
		pr_debug("%s: dev missing, HW reset omitted\n", __func__);
	}

	/* Unregister the driver from the OS */
	pci_unregister_driver(&(vxd_pci_drv.pci_driver));

	ret = vxd_deinit();
	if (ret)
		pr_err("VXD driver deinit failed\n");

	return ret;
}

#ifdef CONFIG_GENERIC_ALLOCATOR
static phys_addr_t carveout_to_dev_addr(union heap_options *options,
					phys_addr_t addr)
{
	phys_addr_t base = options->carveout.phys;
	size_t size = options->carveout.size;

	if (addr >= base && addr < base + size) {
		return addr - base;
	} else {
		pr_err("%s: unexpected addr! base %llx size %zu addr %#llx\n",
		       __func__, base, size, addr);
		WARN_ON(1);
		return addr;
	}
}
#endif

static int vxd_plat_probe(struct pci_dev *pci_dev,
		const struct pci_device_id *id)
{
	int bar, ret = 0;
	struct imgpci_prvdata *data;
	size_t maxmapsize = maxmapsizeMB * 1024 * 1024;
	struct device *dev = &pci_dev->dev;
#ifdef CONFIG_GENERIC_ALLOCATOR
	int heap;
#endif

	dev_dbg(dev, "probing device, pci_dev: %p\n", dev);

	/* Enable the device */
	if (pci_enable_device(pci_dev))
		goto out_free;

	if (pci_set_dma_mask(pci_dev, DMA_BIT_MASK(40))) {
		printk(KERN_ERR "vxd WARNING: No usable 40bit DMA configuration\n");
	}

	dev_info(dev, "%s dma_get_mask : %#llx\n", __func__, dma_get_mask(dev));
	if (dev->dma_mask) {
		dev_info(dev, "%s dev->dma_mask : %p : %#llx\n",
			 __func__, dev->dma_mask, *dev->dma_mask);
	} else {
		dev_info(dev, "%s mask unset, setting coherent\n", __func__);
		dev->dma_mask = &dev->coherent_dma_mask;
	}
	dev_info(dev, "%s dma_set_mask %#llx\n", __func__, dma_get_mask(dev));
	ret = dma_set_mask(dev, dma_get_mask(dev));
	if (ret) {
		dev_err(dev, "%s failed to set dma mask\n", __func__);
		goto out_disable;
	}

	pci_set_master(pci_dev);

	/* Reserve PCI I/O and memory resources */
	if (pci_request_regions(pci_dev, "imgpci"))
		goto out_disable;

	/* Create a kernel space mapping for each of the bars */
	data = devm_kzalloc(dev, sizeof(*data), GFP_KERNEL);
	dev_dbg(dev, "allocated imgpci_prvdata @ %p\n", data);
	memset(data, 0, sizeof(*data));
	for (bar = 0; bar < 3; bar++) {
		data->memmap[bar].addr = pci_resource_start(pci_dev, bar);
		data->memmap[bar].size = pci_resource_len(pci_dev, bar);
		if (data->memmap[bar].size > maxmapsize) {
			/*
			 * We avoid mapping too big regions: we do not need
			 * such a big amount of memory and some times we do
			 * not have enough contiguous 'vmallocable' memory.
			 */
			dev_warn(dev, "not mapping all mem for bar %u\n", bar);
			data->memmap[bar].size = maxmapsize;
		}
		data->memmap[bar].km_addr = devm_ioremap(dev,
				pci_resource_start(pci_dev, bar),
				data->memmap[bar].size);

		dev_dbg(dev, "[bar %u] addr: 0x%lx size: 0x%lx km: 0x%p\n",
				bar, data->memmap[bar].addr,
				data->memmap[bar].size,
				data->memmap[bar].km_addr);
	}

	/* Get the IRQ...*/
	data->irq = pci_dev->irq;
	data->pci_dev = pci_dev;
	vxd_pci_drv.pci_dev = pci_dev;

	reset_emu(pci_dev, data);

	if (!poll_interrupts) {
		/* Enable interrupts */
		emu_writereg32(data, PCI_EMU_SYS_CTRL_REGS_BAR,
				PCI_EMU_INTERRUPT_ENABLE_OFS,
				PCI_EMU_IRQ_ENABLE);
	}

#ifdef CONFIG_GENERIC_ALLOCATOR
	/* patch heap config with PCI memory addresses */
	for (heap = 0; heap < vxd_plat_emu_heaps; heap++) {
		struct heap_config *cfg = &vxd_plat_emu_heap_configs[heap];

		if (cfg->type == IMG_MEM_HEAP_TYPE_CARVEOUT) {
			/*
			 * Device memory is I/O memory and as a rule, it cannot
			 * be dereferenced safely without memory barriers, that
			 * is why it is guarded by __iomem (return of ioremap)
			 * and checked by sparse. It is accessed only through
			 * ioread32(), iowrit32(), etc.
			 *
			 * In x86 this memory can be dereferenced and safely
			 * accessed, i.e.  a * __iomem pointer can be casted to
			 * a regular void* * pointer.  We cast this here
			 * assuming emu is x86 and add __force to silence the
			 * sparse warning
			 */
			void *kptr = (void * __force *)data->memmap[2].km_addr;

			cfg->options.carveout.phys = data->memmap[2].addr;
			cfg->options.carveout.kptr = kptr;
			cfg->options.carveout.size = data->memmap[2].size;
			cfg->to_dev_addr = carveout_to_dev_addr;
			break;
		}
	}
#endif

	ret = vxd_add_dev(dev, vxd_plat_emu_heap_configs,
			vxd_plat_emu_heaps, data,
			data->memmap[1].km_addr, data->memmap[1].size);
	if (ret) {
		dev_err(dev, "failed to intialize driver core!\n");
		goto out_release;
	}

	if (!poll_interrupts) {
		/* Install the ISR callback...*/
		ret = devm_request_threaded_irq(dev, data->irq, &pci_isrcb,
				&pci_thread_irq, IRQF_SHARED, DEVICE_NAME,
				(void *)pci_dev);
		if (ret) {
			dev_err(dev, "failed to request irq!\n");
			goto out_rm_dev;
		}
		dev_dbg(dev, "registerd irq %d\n", data->irq);
	} else {
		INIT_DELAYED_WORK(&data->irq_work, pci_poll_interrupt);
		data->irq_poll = 1;
		/* Start the interrupt poll */
		schedule_delayed_work(&data->irq_work, usecs_to_jiffies(irq_poll_delay_us));
	}

	return ret;

out_rm_dev:
	vxd_rm_dev(dev);
out_release:
	pci_release_regions(pci_dev);
out_disable:
	pci_disable_device(pci_dev);
out_free:
	return ret;
}

static void vxd_plat_remove(struct pci_dev *dev)
{
	struct imgpci_prvdata *data = vxd_get_plat_data(&dev->dev);

	dev_dbg(&dev->dev, "removing device\n");

	if (data == NULL)
		dev_err(&dev->dev, "PCI priv data missing!\n");
	else {
		emu_writereg32(data, PCI_EMU_SYS_CTRL_REGS_BAR,
			PCI_EMU_INTERRUPT_ENABLE_OFS, ~PCI_EMU_IRQ_ENABLE);
		if (poll_interrupts) {
			data->irq_poll = 0;
			cancel_delayed_work_sync(&data->irq_work);
		}
	}

	pci_release_regions(dev);
	pci_disable_device(dev);

	vxd_rm_dev(&dev->dev);
}

#ifdef CONFIG_PM
static int vxd_plat_suspend(struct device *dev)
{
	return vxd_suspend_dev(dev);
}

static int vxd_plat_resume(struct device *dev)
{
	return vxd_resume_dev(dev);
}
#endif

int vxd_plat_init(void)
{
	int ret;

	ret = pci_register_driver(&vxd_pci_drv.pci_driver);
	if (ret) {
		pr_err("failed to register PCI driver!\n");
		return ret;
	}

	/* pci_dev should be set in probe */
	if (!vxd_pci_drv.pci_dev) {
		pr_err("failed to find VXD PCI dev!\n");
		pci_unregister_driver(&vxd_pci_drv.pci_driver);
		return -ENODEV;
	}

	return 0;
}

/*
 * coding style for emacs
 *
 * Local variables:
 * indent-tabs-mode: t
 * tab-width: 8
 * c-basic-offset: 8
 * End:
 */
