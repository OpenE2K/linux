/* vi: set ts=8 sw=8 sts=8: */
/*************************************************************************/ /*!
@Codingstyle    LinuxKernel
@Copyright      Copyright (c) Imagination Technologies Ltd. All Rights Reserved
@Copyright      Copyright (c) MCST
@License        Dual MIT/GPLv2

The contents of this file are subject to the MIT license as set out below.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

Alternatively, the contents of this file may be used under the terms of
the GNU General Public License Version 2 ("GPL") in which case the provisions
of GPL are applicable instead of those above.

If you wish to allow use of your version of this file only under the terms of
GPL, and not to allow others to use your version of this file under the terms
of the MIT license, indicate your decision by deleting the provisions above
and replace them with the notice and other provisions required by GPL as set
out in the file called "GPL-COPYING" included in this distribution. If you do
not delete the provisions above, a recipient may use your version of this file
under the terms of either the MIT license or GPL.

This License is also included in this distribution in the file called
"MIT-COPYING".

EXCEPT AS OTHERWISE STATED IN A NEGOTIATED AGREEMENT: (A) THE SOFTWARE IS
PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT; AND (B) IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/ /**************************************************************************/

/*
 * This is a device driver for the E2C3 GPU.
 */

#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/iommu.h>

#if defined(CONFIG_MTRR)
#include <asm/mtrr.h>
#endif

#include "pvrmodule.h"

#include "e2c3_gpu_drv_internal.h"

/* RGX regs on BAR0 */
#define E2C3_GPU_RGX_REG_PCI_BASENUM 0

MODULE_DESCRIPTION("PowerVR E2C3 GPU driver");

int request_pci_io_addr(struct pci_dev *pdev, u32 index, resource_size_t offset,
			resource_size_t length)
{
	resource_size_t start, end;

	start = pci_resource_start(pdev, index);
	end = pci_resource_end(pdev, index);

	if ((start + offset + length - 1) > end)
		return -EIO;
	if (pci_resource_flags(pdev, index) & IORESOURCE_IO) {
		if (request_region(start + offset, length, DRV_NAME) == NULL)
			return -EIO;
	} else {
		if (request_mem_region(start + offset, length, DRV_NAME) ==
		    NULL)
			return -EIO;
	}
	return 0;
}

void release_pci_io_addr(struct pci_dev *pdev, u32 index, resource_size_t start,
			 resource_size_t length)
{
	if (pci_resource_flags(pdev, index) & IORESOURCE_IO)
		release_region(start, length);
	else
		release_mem_region(start, length);
}

int setup_io_region(struct pci_dev *pdev, struct e2c3_gpu_io_region *region,
		    u32 index, resource_size_t offset, resource_size_t size)
{
	int err;
	resource_size_t pci_phys_addr;

	err = request_pci_io_addr(pdev, index, offset, size);
	if (err) {
		dev_err(&pdev->dev,
			"Failed to request E2C3 GPU registers (err=%d)\n", err);
		return -EIO;
	}
	pci_phys_addr = pci_resource_start(pdev, index);
	region->region.base = pci_phys_addr + offset;
	region->region.size = size;

	region->registers = ioremap(region->region.base, region->region.size);

	if (!region->registers) {
		dev_err(&pdev->dev, "Failed to map E2C3 GPU registers\n");
		release_pci_io_addr(pdev, index, region->region.base,
				    region->region.size);
		return -EIO;
	}
	return 0;
}

int e2c3_gpu_register_ext_device(struct e2c3_gpu_device *e2c3_gpu)
{
	int err = 0;
	struct resource rogue_resources[] = {
		DEFINE_RES_MEM_NAMED(
			pci_resource_start(e2c3_gpu->pdev,
					   E2C3_GPU_RGX_REG_PCI_BASENUM),
			E2C3_GPU_RGX_REG_REGION_SIZE, "rogue-regs"),
	};
	struct platform_device_info rogue_device_info = {
		.parent = &e2c3_gpu->pdev->dev,
		.name = E2C3_GPU_DEVICE_NAME_ROGUE,
		.id = PLATFORM_DEVID_AUTO,
		.res = rogue_resources,
		.num_res = ARRAY_SIZE(rogue_resources),
		.data = NULL,
		.size_data = 0,
		.dma_mask = DMA_BIT_MASK(40),
	};

	e2c3_gpu->ext_dev = platform_device_register_full(&rogue_device_info);

	if (IS_ERR(e2c3_gpu->ext_dev)) {
		err = PTR_ERR(e2c3_gpu->ext_dev);
		dev_err(&e2c3_gpu->pdev->dev,
			"Failed to register rogue device (%d)\n", err);
		e2c3_gpu->ext_dev = NULL;
		return err;
	}
	return err;
}

irqreturn_t e2c3_gpu_irq_handler(int irq, void *data)
{
	unsigned long flags;
	irqreturn_t ret = IRQ_NONE;
	struct e2c3_gpu_device *e2c3_gpu = (struct e2c3_gpu_device *)data;
	struct e2c3_gpu_interrupt_handler *ext_int;

	spin_lock_irqsave(&e2c3_gpu->interrupt_handler_lock, flags);

	ext_int = &e2c3_gpu->interrupt_handler;
	if (ext_int->enabled && ext_int->handler_function) {
		ext_int->handler_function(ext_int->handler_data);
	}
	ret = IRQ_HANDLED;

	spin_unlock_irqrestore(&e2c3_gpu->interrupt_handler_lock, flags);

	return ret;
}

#if defined(E2C3_GPU_FAKE_INTERRUPTS)
void e2c3_gpu_irq_fake_wrapper(unsigned long data)
{
	struct e2c3_gpu_device *e2c3_gpu = (struct e2c3_gpu_device *)data;

	e2c3_gpu_irq_handler(0, e2c3_gpu);
	mod_timer(&e2c3_gpu->timer,
		  jiffies + msecs_to_jiffies(E2C3_GPU_FAKE_INTERRUPT_TIME_MS));
}
#endif

static void e2c3_gpu_devres_release(struct device *dev, void *res)
{
	/* No extra cleanup needed */
}

static int e2c3_gpu_cleanup(struct pci_dev *pdev)
{
	struct e2c3_gpu_device *e2c3_gpu =
		devres_find(&pdev->dev, e2c3_gpu_devres_release, NULL, NULL);
	int err = 0;

	if (!e2c3_gpu) {
		dev_err(&pdev->dev, "No E2C3 GPU device resources found\n");
		return -ENODEV;
	}

	if (e2c3_gpu->interrupt_handler.enabled)
		e2c3_gpu_disable_interrupt(&pdev->dev);

#if defined(E2C3_GPU_FAKE_INTERRUPTS)
	del_timer_sync(&e2c3_gpu->timer);
#else
	free_irq(e2c3_gpu->pdev->irq, e2c3_gpu);
#endif

	return err;
}

static int e2c3_gpu_init(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct e2c3_gpu_device *e2c3_gpu;
	int err = 0;

	if (!devres_open_group(&pdev->dev, NULL, GFP_KERNEL))
		return -ENOMEM;

	e2c3_gpu = devres_alloc(e2c3_gpu_devres_release, sizeof(*e2c3_gpu),
				GFP_KERNEL);
	if (!e2c3_gpu) {
		err = -ENOMEM;
		goto err_out;
	}

	devres_add(&pdev->dev, e2c3_gpu);

	err = e2c3_gpu_enable(&pdev->dev);
	if (err) {
		dev_err(&pdev->dev, "e2c3_gpu_enable failed %d\n", err);
		goto err_release;
	}

	e2c3_gpu->pdev = pdev;

	spin_lock_init(&e2c3_gpu->interrupt_handler_lock);
	spin_lock_init(&e2c3_gpu->interrupt_enable_lock);

#if defined(E2C3_GPU_FAKE_INTERRUPTS)
	dev_warn(&pdev->dev, "WARNING: Faking interrupts every %d ms",
		 FAKE_INTERRUPT_TIME_MS);
	setup_timer(&tc->timer, tc_irq_fake_wrapper, (unsigned long)tc);
	mod_timer(&tc->timer,
		  jiffies + msecs_to_jiffies(E2C3_GPU_FAKE_INTERRUPT_TIME_MS));
#else
	err = request_irq(e2c3_gpu->pdev->irq, e2c3_gpu_irq_handler,
			  IRQF_SHARED, DRV_NAME, e2c3_gpu);
	if (err) {
		dev_err(&pdev->dev,
			"e2c3_gpu_enable request irq #%d failed %d\n",
			e2c3_gpu->pdev->irq, err);
		goto err_dev_cleanup;
	}
#endif

	err = e2c3_gpu_register_ext_device(e2c3_gpu);
	if (err)
		goto err_dev_cleanup;

	devres_remove_group(&pdev->dev, NULL);

err_out:
	if (err)
		dev_err(&pdev->dev, "%s: failed\n", __func__);

	return err;

err_dev_cleanup:
	e2c3_gpu_cleanup(pdev);
	e2c3_gpu_disable(&pdev->dev);
err_release:
	devres_release_group(&pdev->dev, NULL);
	goto err_out;
}

static void e2c3_gpu_exit(struct pci_dev *pdev)
{
	struct e2c3_gpu_device *e2c3_gpu =
		devres_find(&pdev->dev, e2c3_gpu_devres_release, NULL, NULL);
	if (!e2c3_gpu) {
		dev_err(&pdev->dev, "No E2C3 GPU device resources found\n");
		return;
	}

	if (e2c3_gpu->ext_dev)
		platform_device_unregister(e2c3_gpu->ext_dev);

	e2c3_gpu_cleanup(pdev);

	e2c3_gpu_disable(&pdev->dev);
}

static struct pci_device_id e2c3_gpu_pci_tbl[] = {
	{ PCI_VDEVICE(MCST_TMP, PCI_DEVICE_ID_MCST_3D_IMAGINATION_GX6650) },
	{},
};

static struct pci_driver e2c3_gpu_pci_driver = {
	.name = DRV_NAME,
	.id_table = e2c3_gpu_pci_tbl,
	.probe = e2c3_gpu_init,
	.remove = e2c3_gpu_exit,
};

module_pci_driver(e2c3_gpu_pci_driver);

MODULE_DEVICE_TABLE(pci, e2c3_gpu_pci_tbl);

int e2c3_gpu_enable(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	int err;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "error - pci_enable_device returned %d\n",
			err);
		goto err_out;
	}

	/* Enable BUS master */
	pci_set_master(pdev);

	if ((err = pci_set_dma_mask(pdev, DMA_BIT_MASK(40))))
		goto err_disable_device;
	if ((err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(40))))
		goto err_disable_device;
err_out:
	return err;

err_disable_device:
	pci_disable_device(pdev);
	return err;
}
EXPORT_SYMBOL(e2c3_gpu_enable);

void e2c3_gpu_disable(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	pci_disable_device(pdev);
}
EXPORT_SYMBOL(e2c3_gpu_disable);

int e2c3_gpu_set_interrupt_handler(struct device *dev,
				   void (*handler_function)(void *), void *data)
{
	struct e2c3_gpu_device *e2c3_gpu =
		devres_find(dev, e2c3_gpu_devres_release, NULL, NULL);
	int err = 0;
	unsigned long flags;

	if (!e2c3_gpu) {
		dev_err(dev, "No E2C3 GPU device resources found\n");
		err = -ENODEV;
		goto err_out;
	}

	spin_lock_irqsave(&e2c3_gpu->interrupt_handler_lock, flags);

	e2c3_gpu->interrupt_handler.handler_function = handler_function;
	e2c3_gpu->interrupt_handler.handler_data = data;

	spin_unlock_irqrestore(&e2c3_gpu->interrupt_handler_lock, flags);

err_out:
	return err;
}
EXPORT_SYMBOL(e2c3_gpu_set_interrupt_handler);

int e2c3_gpu_enable_interrupt(struct device *dev)
{
	struct e2c3_gpu_device *e2c3_gpu =
		devres_find(dev, e2c3_gpu_devres_release, NULL, NULL);
	int err = 0;
	unsigned long flags;

	if (!e2c3_gpu) {
		dev_err(dev, "No E2C3 GPU device resources found\n");
		err = -ENODEV;
		goto err_out;
	}
	spin_lock_irqsave(&e2c3_gpu->interrupt_enable_lock, flags);

	if (e2c3_gpu->interrupt_handler.enabled) {
		dev_warn(dev, "Interrupt already enabled\n");
		err = -EEXIST;
		goto err_unlock;
	}
	e2c3_gpu->interrupt_handler.enabled = true;

err_unlock:
	spin_unlock_irqrestore(&e2c3_gpu->interrupt_enable_lock, flags);
err_out:
	return err;
}
EXPORT_SYMBOL(e2c3_gpu_enable_interrupt);

int e2c3_gpu_disable_interrupt(struct device *dev)
{
	struct e2c3_gpu_device *e2c3_gpu =
		devres_find(dev, e2c3_gpu_devres_release, NULL, NULL);
	int err = 0;
	unsigned long flags;

	if (!e2c3_gpu) {
		dev_err(dev, "No E2C3 GPU device resources found\n");
		err = -ENODEV;
		goto err_out;
	}
	spin_lock_irqsave(&e2c3_gpu->interrupt_enable_lock, flags);

	if (!e2c3_gpu->interrupt_handler.enabled) {
		dev_warn(dev, "Interrupt already disabled\n");
	}
	e2c3_gpu->interrupt_handler.enabled = false;

	spin_unlock_irqrestore(&e2c3_gpu->interrupt_enable_lock, flags);
err_out:
	return err;
}
EXPORT_SYMBOL(e2c3_gpu_disable_interrupt);
