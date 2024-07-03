/*!
 *****************************************************************************
 *
 * @File       vxd_plat_fpga.c
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

#define IS_AVNET_OR_MCST_DEVICE(devid) \
	(((devid) != PCI_ATLAS_DEVICE_ID) && ((devid) != PCI_APOLLO_DEVICE_ID))

#define IS_ATLAS_DEVICE(devid) ((devid) == PCI_ATLAS_DEVICE_ID)
#define IS_APOLLO_DEVICE(devid) ((devid) == PCI_APOLLO_DEVICE_ID)

/*
 * Disables all fpga level registers access (bar0)
 * Useful when using virtual platform with CSIM attached as PCI device.
 */
//#define BYPASS_FPGA_BAR

/*
 * from TCF Support FPGA.Technical Reference
 * Manual.1.0.92.Internal Atlas GEN.External.doc:
 */
/* Altas - System control register bar */
#define PCI_ATLAS_SYS_CTRL_REGS_BAR (0)
/* Altas - System control register offset */
#define PCI_ATLAS_SYS_CTRL_REGS_OFFSET (0x0000)
/* Atlas - Offset of INTERRUPT_STATUS */
#define PCI_ATLAS_INTERRUPT_STATUS (0x00E0)
/* Atlas - Offset of INTERRUPT_ENABLE */
#define PCI_ATLAS_INTERRUPT_ENABLE (0x00F0)
/* Atlas - Offset of INTERRUPT_CLEAR */
#define PCI_ATLAS_INTERRUPT_CLEAR (0x00F8)
/* Atlas - Master interrupt enable */
#define PCI_ATLAS_MASTER_ENABLE (1<<31)
/* Atlas - Device interrupt */
#define PCI_ATLAS_DEVICE_INT (1<<13)
/* Atlas - SCB Logic soft reset */
#define PCI_ATLAS_SCB_RESET (1<<4)
/* Atlas - PDP2 soft reset */
#define PCI_ATLAS_PDP2_RESET (1<<3)
/* Atlas - PDP1 soft reset */
#define PCI_ATLAS_PDP1_RESET (1<<2)
/* Atlas - soft reset the DDR logic */
#define PCI_ATLAS_DDR_RESET (1<<1)
/* Atlas - soft reset the device under test */
#define PCI_ATLAS_DUT_RESET (1<<0)
#define PCI_ATLAS_RESET_REG_OFFSET (0x0080)
#define PCI_ATLAS_RESET_BITS (PCI_ATLAS_DDR_RESET | PCI_ATLAS_DUT_RESET \
		| PCI_ATLAS_PDP1_RESET | PCI_ATLAS_PDP2_RESET | \
		PCI_ATLAS_SCB_RESET)

/* Apollo - Offset of INTERRUPT_STATUS */
#define PCI_APOLLO_INTERRUPT_STATUS (0x00C8)
/* Apollo - Offset of INTERRUPT_ENABLE */
#define PCI_APOLLO_INTERRUPT_ENABLE (0x00D8)
/* Apollo - Offset of INTERRUPT_CLEAR */
#define PCI_APOLLO_INTERRUPT_CLEAR (0x00E0)
/* Apollo - DCM Logic soft reset */
#define PCI_APOLLO_DCM_RESET (1<<10)
#define PCI_APOLLO_RESET_BITS (PCI_ATLAS_RESET_BITS | PCI_APOLLO_DCM_RESET)

#define PCI_ATLAS_TEST_CTRL (0xb0)
#define PCI_APOLLO_TEST_CTRL (0x98)

#define PCI_ATLAS_VENDOR_ID (0x1010)
#define PCI_ATLAS_DEVICE_ID (0x1CF1)
#define PCI_APOLLO_DEVICE_ID (0x1CF2)

#define PCI_MCST_VENDOR_ID (0x1fff)
#define PCI_MCST_DEVICE_ID (0x802c)

#define IS_MCST_DEVICE(devid) ((devid)==PCI_MCST_DEVICE_ID)

#define FPGA_IMAGE_REV_OFFSET (0x604)
#define FPGA_IMAGE_REV_MASK (0xFFFF)

const unsigned long vxd_plat_poll_udelay = 100;

static struct heap_config vxd_plat_fpga_heap_configs[] = {
#ifdef FPGA_BUS_MASTERING
	{
		.type = IMG_MEM_HEAP_TYPE_UNIFIED,
		.options.unified = {
			.gfp_type = GFP_HIGHUSER | __GFP_ZERO,
		},
		.to_dev_addr = NULL,
	},
#ifdef CONFIG_DMA_SHARED_BUFFER
	/* DMABUF is enabled only in bus mastering mode. Special handling
	   (not implemented) is required for the VXD device to be able to
	   access both carvout buffers (internal memory) and dmabuf buffers
	   (system memory). The latter have to go through the system bus to
	   be accessed whereas the former do not */
	{
		.type = IMG_MEM_HEAP_TYPE_DMABUF,
		.to_dev_addr = NULL,
	},
#endif
#elif CONFIG_GENERIC_ALLOCATOR
	{
		.type = IMG_MEM_HEAP_TYPE_CARVEOUT,
		/* .options.carveout to be filled at run time */
		/* .to_dev_addr to be filled at run time */
	},
#else
#error Neither FPGA_BUS_MASTERING or CONFIG_GENERIC_ALLOCATOR was defined
#endif
};

static const int vxd_plat_fpga_heaps =
	sizeof(vxd_plat_fpga_heap_configs)/sizeof(*vxd_plat_fpga_heap_configs);

static const struct pci_device_id pci_pci_ids[] = {
	{ PCI_DEVICE(PCI_MCST_VENDOR_ID, PCI_MCST_DEVICE_ID), },
#if 0 /* it kills e1c+*/
	{ PCI_DEVICE(PCI_ATLAS_VENDOR_ID, PCI_ATLAS_DEVICE_ID), },
	{ PCI_DEVICE(PCI_ATLAS_VENDOR_ID, PCI_APOLLO_DEVICE_ID), },
#endif
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
};

#ifndef CONFIG_MCST
struct img_pci_driver {
	struct pci_dev *pci_dev;
	struct pci_driver pci_driver;
};
#endif

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

#ifdef CONFIG_MCST
struct img_pci_driver *vxd_pci_drv_ptr;
#endif
static ulong maxmapsizeMB = (sizeof(void *) == 4) ? 400 : 1024;

static int interrupt_status_reg = -1;
static int interrupt_clear_reg = -1;
static int interrupt_enable_reg = -1;
static int test_ctrl_reg = -1;

static unsigned int fpga_readreg32(struct imgpci_prvdata *data,
		int bar, unsigned long offset
)
{
#ifndef BYPASS_FPGA_BAR
	void __iomem *reg =
		(void __iomem *)(data->memmap[bar].km_addr + offset);
	return ioread32(reg);
#else
	return ~0;
#endif
}

static void fpga_writereg32(struct imgpci_prvdata *data,
		int bar, unsigned long offset, int val)
{
#ifndef BYPASS_FPGA_BAR
	void __iomem *reg =
		(void __iomem *)(data->memmap[bar].km_addr + offset);
	iowrite32(val, reg);
#endif
}

static void reset_fpga(struct pci_dev *dev,
		struct imgpci_prvdata *data, unsigned int mask)
{
	u32 bits = 0;

	if (!dev)
		return;

	if (IS_ATLAS_DEVICE(dev->device))
		bits = PCI_ATLAS_RESET_BITS;
	else if (IS_APOLLO_DEVICE(dev->device))
		bits = PCI_APOLLO_RESET_BITS;

	dev_dbg(&dev->dev, "reset fpga!\n");
	bits &= mask;

	if (bits) {
		u32 val = fpga_readreg32(data, 0, PCI_ATLAS_RESET_REG_OFFSET);

		val &= ~bits;
		fpga_writereg32(data, 0, PCI_ATLAS_RESET_REG_OFFSET, val);
		udelay(100); /* arbitrary delays, just in case! */
		val |= bits;
		fpga_writereg32(data, 0, PCI_ATLAS_RESET_REG_OFFSET, val);
		msleep(500);
	}
}

static void fpga_clear_irq(struct imgpci_prvdata *data, unsigned int intstatus)
{
	unsigned int max_retries = 1000;

	while (fpga_readreg32(data, PCI_ATLAS_SYS_CTRL_REGS_BAR,
				interrupt_status_reg) && max_retries--)
		fpga_writereg32(data, PCI_ATLAS_SYS_CTRL_REGS_BAR,
				interrupt_clear_reg,
				(PCI_ATLAS_MASTER_ENABLE | intstatus));
}

static irqreturn_t pci_thread_irq(int irq, void *dev_id)
{
	struct pci_dev *dev = (struct pci_dev *)dev_id;

	return vxd_handle_thread_irq(&dev->dev);
}

static irqreturn_t pci_isrcb(int irq, void *dev_id)
{
	unsigned int intstatus;
	struct pci_dev *dev = (struct pci_dev *)dev_id;
	struct imgpci_prvdata *data = vxd_get_plat_data(&dev->dev);
	irqreturn_t ret = IRQ_NONE;

	if (data == NULL || dev_id == NULL) {
		/* spurious interrupt: not yet initialised. */
		dev_dbg(&dev->dev, "%s: fpga spurious interrupt (not yet initialised?) !\n", __func__);
		goto exit;
	}

	/* If Atlas/Apollo FPGA...*/
	if (!IS_AVNET_OR_MCST_DEVICE(dev->device)) {
		intstatus = fpga_readreg32(data,
				PCI_ATLAS_SYS_CTRL_REGS_BAR,
				interrupt_status_reg);
	} else {
		/* Avnet...*/
		intstatus = 1;
	}

	if (intstatus) {

		ret = vxd_handle_irq(&dev->dev);

		/* If Atlas/Apollo FPGA...*/
		if (!IS_AVNET_OR_MCST_DEVICE(dev->device)) {
			/*
			 * We need to clear interrupts for the embedded device
			 * via the Atlas interrupt controller...
			 */
			fpga_clear_irq(data, intstatus);
		}
	} else {
		dev_dbg(&dev->dev,
				"%s: fpga spurious interrupt !\n",
				__func__);
		WARN_ON(1);
	}

exit:

	return ret;
}

int vxd_plat_deinit(void)
{
	struct pci_dev *dev = vxd_pci_drv.pci_dev;
	int ret;

	if (dev) {
		struct imgpci_prvdata *data = vxd_get_plat_data(&dev->dev);

		if (data) {
			/* reset the hardware */
			reset_fpga(data->pci_dev, data, ~0);
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

	if ((ret = pci_set_dma_mask(pci_dev, DMA_BIT_MASK(40)))) {
		printk(KERN_ERR "vxd WARNING: No usable 40bit DMA configuration ???\n");
		goto out_free;
	}
	if ((ret = pci_set_consistent_dma_mask(pci_dev, DMA_BIT_MASK(40))))
		goto out_free;

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
#ifdef CONFIG_MCST
	vxd_pci_drv_ptr = &vxd_pci_drv;
#endif
	reset_fpga(pci_dev, data, ~0);

	if (IS_ATLAS_DEVICE(pci_dev->device)) {
		interrupt_status_reg = PCI_ATLAS_SYS_CTRL_REGS_OFFSET +
			PCI_ATLAS_INTERRUPT_STATUS;
		interrupt_clear_reg = PCI_ATLAS_SYS_CTRL_REGS_OFFSET +
			PCI_ATLAS_INTERRUPT_CLEAR;
		interrupt_enable_reg = PCI_ATLAS_SYS_CTRL_REGS_OFFSET +
			PCI_ATLAS_INTERRUPT_ENABLE;
		test_ctrl_reg = PCI_ATLAS_SYS_CTRL_REGS_OFFSET +
			PCI_ATLAS_TEST_CTRL;
	} else if (IS_APOLLO_DEVICE(pci_dev->device)) {
		interrupt_status_reg = PCI_ATLAS_SYS_CTRL_REGS_OFFSET +
			PCI_APOLLO_INTERRUPT_STATUS;
		interrupt_clear_reg = PCI_ATLAS_SYS_CTRL_REGS_OFFSET +
			PCI_APOLLO_INTERRUPT_CLEAR;
		interrupt_enable_reg = PCI_ATLAS_SYS_CTRL_REGS_OFFSET +
			PCI_APOLLO_INTERRUPT_ENABLE;
		test_ctrl_reg = PCI_ATLAS_SYS_CTRL_REGS_OFFSET +
			PCI_APOLLO_TEST_CTRL;
	}

	/* If Atlas/Apollo FPGA...*/
	if (!IS_AVNET_OR_MCST_DEVICE(pci_dev->device)) {
		/*
		 * We need to enable interrupts for the embedded device
		 * via the Atlas interrupt controller...
		 */
		unsigned int ena;

		ena = fpga_readreg32(data, PCI_ATLAS_SYS_CTRL_REGS_BAR,
				interrupt_enable_reg);
		ena |= PCI_ATLAS_MASTER_ENABLE | PCI_ATLAS_DEVICE_INT;

		fpga_writereg32(data, PCI_ATLAS_SYS_CTRL_REGS_BAR,
				interrupt_enable_reg, ena);

		fpga_clear_irq(data, ena);
	}

#ifdef FPGA_BUS_MASTERING
	dev_dbg(dev, "enabling FPGA bus mastering\n");
    if( !IS_MCST_DEVICE(pci_dev->device) )
    {
	fpga_writereg32(data, PCI_ATLAS_SYS_CTRL_REGS_BAR, test_ctrl_reg, 0x0);
    }
#else
	/* Route to internal RAM - this is reset value */
	dev_dbg(dev, "disabling FPGA bus mastering\n");
	fpga_writereg32(data, PCI_ATLAS_SYS_CTRL_REGS_BAR, test_ctrl_reg, 0x1);
#endif

#ifdef CONFIG_GENERIC_ALLOCATOR
	/* patch heap config with PCI memory addresses */
	for (heap = 0; heap < vxd_plat_fpga_heaps; heap++) {
		struct heap_config *cfg = &vxd_plat_fpga_heap_configs[heap];

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
			 * assuming FPGA is x86 and add __force to silence the
			 * sparse warning
			 */
    if( !IS_MCST_DEVICE(pci_dev->device) ) /* MCST_VXD device w/o BAR for device memory reg! */
    {
			void *kptr = (void * __force *)data->memmap[2].km_addr;

			cfg->options.carveout.phys = data->memmap[2].addr;
			cfg->options.carveout.kptr = kptr;
			cfg->options.carveout.size = data->memmap[2].size;
    }
			cfg->to_dev_addr = carveout_to_dev_addr;
			break;
		}
	}
#endif

    if( IS_MCST_DEVICE(pci_dev->device) )
    {
	ret = vxd_add_dev(dev, vxd_plat_fpga_heap_configs,
			vxd_plat_fpga_heaps, data,
			data->memmap[0].km_addr, data->memmap[0].size);
    }
    else
    {
	ret = vxd_add_dev(dev, vxd_plat_fpga_heap_configs,
			vxd_plat_fpga_heaps, data,
			data->memmap[1].km_addr, data->memmap[1].size);
    }
	if (ret) {
		dev_err(dev, "failed to intialize driver core!\n");
		goto out_release;
	}

    if( !IS_MCST_DEVICE(pci_dev->device) )
    {

	/*
	 * Reset FPGA DUT only after disabling PVDEC clocks in
	 * vxd_add_dev(). This workaround is required to ensure that PVDEC
	 * clocks (on daughter board) are enabled for test slave scripts to
	 * read FPGA build version register.
	 * NOTE: Asserting other bits like DDR reset bit cause problems
	 * with bus mastering feature, thus results in memory failures.
	 */
	reset_fpga(pci_dev, data, PCI_ATLAS_DUT_RESET);
	{
		u32 fpga_rev = fpga_readreg32(data, 1,
				FPGA_IMAGE_REV_OFFSET) & FPGA_IMAGE_REV_MASK;
		dev_dbg(dev, "fpga image revision: 0x%x\n", fpga_rev);
		if (!fpga_rev || fpga_rev == 0xdead1) {
			dev_err(dev, "fpga revision incorrect (0x%x)!\n",
					fpga_rev);
			goto out_rm_dev;
		}
	}
    }

	/* Install the ISR callback...*/
	ret = devm_request_threaded_irq(dev, data->irq, &pci_isrcb,
			&pci_thread_irq, IRQF_SHARED, DEVICE_NAME,
			(void *)pci_dev);
	if (ret) {
		dev_err(dev, "failed to request irq!\n");
		goto out_rm_dev;
	}
	dev_dbg(dev, "registerd irq %d\n", data->irq);

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

	if (data == NULL) {
		dev_err(&dev->dev, "PCI priv data missing!\n");
	} else if (!IS_AVNET_OR_MCST_DEVICE(dev->device)) {
		/*
		 * If Atlas FPGA, we  need to disable interrupts for the
		 * embedded device via the Atlas interrupt controller...
		 */
		fpga_writereg32(data, PCI_ATLAS_SYS_CTRL_REGS_BAR,
				interrupt_enable_reg, 0x00000000);
	}

#ifdef FPGA_BUS_MASTERING
	/* Route to internal RAM - this is reset value */
	dev_dbg(&dev->dev, "disabling FPGA bus mastering\n");
    if( !IS_MCST_DEVICE(dev->device) )
    {
	fpga_writereg32(data, PCI_ATLAS_SYS_CTRL_REGS_BAR, test_ctrl_reg, 0x1);
    }
#endif

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
