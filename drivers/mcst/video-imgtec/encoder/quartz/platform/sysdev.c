/*************************************************************************/ /*!
@File           sysdev.c
@Title          Backend handling OS integration for FPGA board
@Copyright      Copyright (c) Imagination Technologies Ltd. All Rights Reserved
@Description    Access pci bar through ioremap regions and register isr in the kernel
@License        Strictly Confidential.
*/ /**************************************************************************/
#include <img_types.h>
#include <sysdev_utils.h>
#include <sysmem_utils.h>

#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/dma-direct.h>

/* Quartz register bank span */
#define QUARTZ_DEV_REG_SIZE				(0x00080000)

#define PCI_ATLAS_VENDOR_ID				(0x1010)
#define PCI_ATLAS_DEVICE_ID 			(0x1CF1)	//!< Atlas V1 - FPGA device ID.
#define PCI_APOLLO_DEVICE_ID			(0x1CF2)	//!< Apollo - FPGA device ID.

#define PCI_MCST_VENDOR_ID			(0x1fff)
#define PCI_MCST_DEVICE_ID			(0x802b)

//#define IS_AVNET_DEVICE(devid)  ((devid)!=PCI_ATLAS_DEVICE_ID && (devid)!=PCI_APOLLO_DEVICE_ID)
#define IS_AVNET_OR_MCST_DEVICE(devid)  ((devid)!=PCI_ATLAS_DEVICE_ID && (devid)!=PCI_APOLLO_DEVICE_ID)
#define IS_ATLAS_DEVICE(devid)  ((devid)==PCI_ATLAS_DEVICE_ID)
#define IS_APOLLO_DEVICE(devid) ((devid)==PCI_APOLLO_DEVICE_ID)
#define IS_MCST_DEVICE(devid) ((devid)==PCI_MCST_DEVICE_ID)

// from TCF Support FPGA.Technical Reference Manual.1.0.92.Internal Atlas GEN.External.doc:
#define PCI_ATLAS_SYS_CTRL_REGS_BAR		(0)			//!< Altas - System control register bar
#define PCI_ATLAS_PDP_REGS_BAR			(0)			//!< Altas - PDP register bar
#define PCI_ATLAS_PDP_REGS_SIZE			(0x2000)	//!< Atlas - size of PDP register area
#define PCI_ATLAS_SYS_CTRL_REGS_OFFSET	(0x0000)	//!< Altas - System control register offset
#define PCI_ATLAS_PDP1_REGS_OFFSET		(0xC000)	//!< Atlas - PDP1 register offset into bar
#define PCI_ATLAS_PDP2_REGS_OFFSET		(0xE000)	//!< Atlas - PDP2 register offset into bar
#define PCI_ATLAS_INTERRUPT_STATUS		(0x00E0)	//!< Atlas - Offset of INTERRUPT_STATUS
#define PCI_ATLAS_INTERRUPT_ENABLE		(0x00F0)	//!< Atlas - Offset of INTERRUPT_ENABLE
#define PCI_ATLAS_INTERRUPT_CLEAR		(0x00F8)	//!< Atlas - Offset of INTERRUPT_CLEAR
#define PCI_ATLAS_MASTER_ENABLE			(1<<31)		//!< Atlas - Master interrupt enable
#define PCI_ATLAS_DEVICE_INT			(1<<13)		//!< Atlas - Device interrupt
#define PCI_ATLAS_PDP1_INT				(1<<14)		//!< Atlas - PDP1 interrupt
#define PCI_ATLAS_PDP2_INT				(1<<15)		//!< Atlas - PDP2 interrupt
#define PCI_ATLAS_SCB_RESET				(1<<4)		//!< Atlas - SCB Logic soft reset
#define PCI_ATLAS_PDP2_RESET			(1<<3)		//!< Atlas - PDP2 soft reset
#define PCI_ATLAS_PDP1_RESET			(1<<2)		//!< Atlas - PDP1 soft reset
#define PCI_ATLAS_DDR_RESET				(1<<1)		//!< Atlas - soft reset the DDR logic
#define PCI_ATLAS_DUT_RESET				(1<<0)		//!< Atlas - soft reset the device under test
#define PCI_ATLAS_RESET_REG_OFFSET 		0x0080
#define PCI_ATLAS_RESET_BITS			(PCI_ATLAS_DDR_RESET | PCI_ATLAS_DUT_RESET |PCI_ATLAS_PDP1_RESET| PCI_ATLAS_PDP2_RESET | PCI_ATLAS_SCB_RESET )

#define PCI_ATLAS_TEST_CTRL		(0xb0)
#define PCI_APOLLO_TEST_CTRL	(0x98)

#define PCI_APOLLO_INTERRUPT_STATUS		(0x00C8)	//!< Atlas - Offset of INTERRUPT_STATUS
#define PCI_APOLLO_INTERRUPT_ENABLE		(0x00D8)	//!< Atlas - Offset of INTERRUPT_ENABLE
#define PCI_APOLLO_INTERRUPT_CLEAR		(0x00E0)	//!< Atlas - Offset of INTERRUPT_CLEAR


#if defined (LARGER_BAR_MEM)
#define PCI_BAR_MEM_LIMIT (512*1024*1024)			//!< For 4k (especially 10bit), we need to push the memory BAR limit up to 512MBytes
#define MAP_MEM_SIZE (512*1024*1024)				//!< If we really want a bigger pool, we also need to increase the dev map size
#else /* defined (LARGER_BAR_MEM) */
#define PCI_BAR_MEM_LIMIT (256*1024*1024)			//!< For normal cases, 256MBytes is enough for the memory BAR
#define MAP_MEM_SIZE (128*1024*1024)				//!< Map size limit should follow BAR size limit for coherency (it is actually smaller)
#endif /* defined (LARGER_BAR_MEM) */

#if ! defined(FPGA_BUS_MASTERING)
#if (VXE_KM_SUPPORTED_DEVICES == 1)
#define POOL_SINGLE_SIZE (MAP_MEM_SIZE)
#elif (VXE_KM_SUPPORTED_DEVICES == 2)
#define POOL_SINGLE_SIZE (MAP_MEM_SIZE >> 1)
#else
/* Guard more than an error*/
#error "Not supported for more than 2 devices"
#endif
#endif

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0) )
#ifndef DEFINE_PCI_DEVICE_TABLE
#define DEFINE_PCI_DEVICE_TABLE(_table) const struct pci_device_id _table[]
#endif /* DEFINE_PCI_DEVICE_TABLE */
#endif /* >= 4.8.0 */

static DEFINE_PCI_DEVICE_TABLE(pci_pci_ids) =
{
	{ PCI_MCST_VENDOR_ID,  PCI_MCST_DEVICE_ID,   PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0, },
#if 0
	{ PCI_ATLAS_VENDOR_ID, PCI_ATLAS_DEVICE_ID,  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0, },
	{ PCI_ATLAS_VENDOR_ID, PCI_APOLLO_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0, },
#endif
	{ 0,0,0,0,0,0,0, }
};
MODULE_DEVICE_TABLE(pci, pci_pci_ids);


unsigned long memoffset;


static int interrupt_status_reg = -1;
static int interrupt_clear_reg = -1;
static int interrupt_enable_reg = -1;
static int test_ctrl_reg = -1;

#define NO_DEVICES_REGISTERED (0)

static int registered_devices = NO_DEVICES_REGISTERED;

struct imgpci_prvdata {
	int irq;
	struct {
		IMG_PHYSADDR addr;
		unsigned long size;
		void __iomem *km_addr;
	} memmap[3];
	SYSDEVU_sInfo * devs[VXE_KM_SUPPORTED_DEVICES];
	struct pci_dev *pci_dev;
};


static void pciremove_func(struct pci_dev *dev);
static int pciprobe_func(struct pci_dev *dev, const struct pci_device_id *id);

static struct img_pci_driver {
	struct pci_dev *pci_dev;
	struct pci_driver pci_driver;
} img_pci_driver =
{
	.pci_driver = {
		.name		= "imgpciif",	/* can change this name as necessary */
		.id_table	= pci_pci_ids,
		.probe		= pciprobe_func,
		.remove		= pciremove_func,
	}
};

static unsigned int readreg32(struct pci_dev *dev, int bar, unsigned long offset)
{
	void __iomem *reg;
	struct imgpci_prvdata *data = (struct imgpci_prvdata *)pci_get_drvdata(dev);

	reg = (void __iomem *)(data->memmap[bar].km_addr + offset);
	return ioread32(reg);
}

static void	writereg32(struct pci_dev *dev, int bar, unsigned long offset, int val)
{
	void __iomem *reg;
	struct imgpci_prvdata *data = (struct imgpci_prvdata *)pci_get_drvdata(dev);

	reg = (void __iomem *)(data->memmap[bar].km_addr + offset);
	iowrite32(val, reg);
}

static void reset_all(struct pci_dev *dev)
{
	struct imgpci_prvdata *data;
	if(!dev)
		return;

	data = pci_get_drvdata(dev);
	if(!data)
		return;


	if(IS_ATLAS_DEVICE(dev->device))
	{
		// toggle the ATLAS reset line.
		volatile u32 * reg = (u32*)((char*)((unsigned long)data->memmap[0].km_addr) + PCI_ATLAS_RESET_REG_OFFSET);
		u32 val;
		printk("resetting ATLAS fpga\n");
		msleep(10);
		val = *reg;
		*reg = val & ~PCI_ATLAS_RESET_BITS;
		udelay(100);		// arbitrary delays, just in case!
		*reg = val | PCI_ATLAS_RESET_BITS;
		msleep(500);
	}
	else if(IS_APOLLO_DEVICE(dev->device))
	{
		printk("resetting APOLLO fpga\n");
		// toggle the reset line
		iowrite32(0x20000, (data->memmap[0].km_addr) + 0x0080);
		udelay(100);
		iowrite32(0x2041f, (data->memmap[0].km_addr) + 0x0080);
		msleep(500);
    }
}

static irqreturn_t pci_isrcb(int irq, void *dev_id
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
	, struct pt_regs * regs
#endif
)
{
	unsigned int intstatus;
	int handled = 0;
	struct pci_dev *dev = (struct pci_dev *)dev_id;
	struct imgpci_prvdata *data = pci_get_drvdata(dev);
	SYSDEVU_sInfo *subdev = NULL;
	int i;

	if(dev_id == NULL)
	{
		// spurious interrupt: not yet initialised.
		return IRQ_NONE;
	}

	/* If Atlas FPGA...*/
	if (!IS_AVNET_OR_MCST_DEVICE(dev->device))
	{
		intstatus = readreg32(dev, PCI_ATLAS_SYS_CTRL_REGS_BAR, interrupt_status_reg);
	}
	else
	{
		/* Avnet...*/
		intstatus = 1;
	}

	/* If an interrupt fired...*/
	if (intstatus)
	{
		for (i = 0 ; i < VXE_KM_SUPPORTED_DEVICES; i++)
		{
			subdev = data->devs[i];
			/* If there is a LISR registered...*/
			if ((subdev) && (subdev->pfnDevKmLisr != IMG_NULL) )
			{
				/* Call it...*/
				SYSOSKM_DisableInt();
				handled |= subdev->pfnDevKmLisr(subdev->pvParam);
				SYSOSKM_EnableInt();
			}
		}

		/* If the LISR handled the interrupt...*/
		if (handled)
		{
			/* If Atlas FPGA...*/
			if (!IS_AVNET_OR_MCST_DEVICE(dev->device))
			{
				/* We need to clear interrupts for the embedded device via the Atlas interrupt controller...*/
				writereg32(dev,	PCI_ATLAS_SYS_CTRL_REGS_BAR, interrupt_clear_reg,
								(PCI_ATLAS_MASTER_ENABLE | intstatus));
			}

			/* Signal this...*/
			return IRQ_HANDLED;
		}
	}

	/* If Atlas FPGA...*/
	if ( (intstatus) && !IS_AVNET_OR_MCST_DEVICE(dev->device) )
	{
		/* We need to clear interrupts for the embedded device via the Atlas interrupt controller...*/
		writereg32(dev, PCI_ATLAS_SYS_CTRL_REGS_BAR, interrupt_clear_reg, intstatus);
	}

	return IRQ_NONE;
}

static void pci_freedev(SYSDEVU_sInfo *dev)
{
	unsigned bar, bar_num;
	struct imgpci_prvdata *data;

	if (NO_DEVICES_REGISTERED != registered_devices)
	{
		return; /*not yet time to free the PCI device*/
	}

	data = (struct imgpci_prvdata *)dev->pPrivate;

	free_irq(data->irq, (void *)data->pci_dev);

	// reset the hardware
	reset_all(data->pci_dev);

	/* Unregister the driver from the OS */
	pci_unregister_driver(&(img_pci_driver.pci_driver));

	bar_num = IS_MCST_DEVICE(data->pci_dev->device)? 1 : 3;
	for (bar = 0; bar < bar_num; ++bar)
	{
		iounmap(data->memmap[bar].km_addr);

		printk("%s bar %u address 0x%llx size 0x%lx km addr 0x%p\n", __func__,
			bar, data->memmap[bar].addr, data->memmap[bar].size, data->memmap[bar].km_addr);

		data->memmap[bar].km_addr = NULL;
	}

	kfree(data);
}

static void handle_suspend(SYSDEVU_sInfo *dev, IMG_BOOL forAPM)
{
	/* customer specific code for handling device suspend ( disabling clocks ) */
	pr_debug("PCI platform handle_suspend %s APM\n", forAPM ? "for" : "not for");
}

static void handle_resume(SYSDEVU_sInfo *dev, IMG_BOOL forAPM)
{
	/* customer specific code for handling device resume ( enabling clocks ) */
	pr_debug("PCI platform handle_resume %s APM\n", forAPM ? "for" : "not for");
}


static int pciprobe_func(struct pci_dev *dev, const struct pci_device_id *id) {
	int bar, bar_num;
	int	ret;
	struct imgpci_prvdata *data;

	/* Enable the device */
	if (pci_enable_device(dev))
	{
		goto out_free;
	}

	if ((ret = pci_set_dma_mask(dev, DMA_BIT_MASK(40)))) {
		printk(KERN_ERR "vxekm WARNING: No usable 40bit DMA configuration\n");
		goto out_free;
	}
	if ((ret = pci_set_consistent_dma_mask(dev, DMA_BIT_MASK(40))))
		goto out_free;
	pci_set_master(dev);

	/* Reserve PCI I/O and memory resources */
	if (pci_request_regions(dev, "imgpci"))
	{
		goto out_disable;
	}

	/* Create a kernel space mapping for each of the bars */
	data = (struct imgpci_prvdata *)kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
	{
		goto malloc_failed;
	}

	bar_num = IS_MCST_DEVICE(dev->device)? 1 : 3;
	for (bar = 0; bar < bar_num; bar++)
	{
		data->memmap[bar].addr = pci_resource_start(dev, bar);
		data->memmap[bar].size = pci_resource_len(dev, bar);
		if(data->memmap[bar].size > PCI_BAR_MEM_LIMIT)
		{
			printk("%s limiting bar %u size from 0x%lx\n", __func__, bar, data->memmap[bar].size);
			data->memmap[bar].size = PCI_BAR_MEM_LIMIT;
		}
		data->memmap[bar].km_addr = ioremap(data->memmap[bar].addr, data->memmap[bar].size);

		printk("%s bar %u address 0x%llx size 0x%lx km addr 0x%p\n", __func__,
			bar, data->memmap[bar].addr, data->memmap[bar].size, data->memmap[bar].km_addr);
	}

	/* Get the IRQ...*/
	data->irq = dev->irq;
	data->pci_dev = dev;
	img_pci_driver.pci_dev = dev;

	pci_set_drvdata(dev, (void *)data);

	reset_all(dev);

	if(IS_ATLAS_DEVICE(dev->device))
	{
		interrupt_status_reg = PCI_ATLAS_SYS_CTRL_REGS_OFFSET + PCI_ATLAS_INTERRUPT_STATUS;
		interrupt_clear_reg  = PCI_ATLAS_SYS_CTRL_REGS_OFFSET + PCI_ATLAS_INTERRUPT_CLEAR;
		interrupt_enable_reg = PCI_ATLAS_SYS_CTRL_REGS_OFFSET + PCI_ATLAS_INTERRUPT_ENABLE;
		test_ctrl_reg = PCI_ATLAS_SYS_CTRL_REGS_OFFSET + PCI_ATLAS_TEST_CTRL;
	}
	else if(IS_APOLLO_DEVICE(dev->device))
	{
		interrupt_status_reg = PCI_ATLAS_SYS_CTRL_REGS_OFFSET+PCI_APOLLO_INTERRUPT_STATUS;
		interrupt_clear_reg  = PCI_ATLAS_SYS_CTRL_REGS_OFFSET+PCI_APOLLO_INTERRUPT_CLEAR;
		interrupt_enable_reg = PCI_ATLAS_SYS_CTRL_REGS_OFFSET+PCI_APOLLO_INTERRUPT_ENABLE;
		test_ctrl_reg = PCI_ATLAS_SYS_CTRL_REGS_OFFSET + PCI_APOLLO_TEST_CTRL;
	}

	/* Install the ISR callback...*/
	ret = request_irq(data->irq, &pci_isrcb, IRQF_SHARED, "quartz", (void *)dev);
	IMG_ASSERT(ret == 0);
	if (ret != 0)
	{
		return -ENODEV;
	}

	/* If Atlas FPGA...*/
	if(!IS_AVNET_OR_MCST_DEVICE(dev->device))
	{
		/* We need to enable interrupts for the embedded device via the Atlas interrupt controller...*/
		IMG_UINT32 ui32Enable = readreg32(dev, PCI_ATLAS_SYS_CTRL_REGS_BAR, interrupt_enable_reg);
		ui32Enable |= PCI_ATLAS_MASTER_ENABLE | PCI_ATLAS_DEVICE_INT;

		writereg32(dev,	PCI_ATLAS_SYS_CTRL_REGS_BAR, interrupt_enable_reg, ui32Enable);

#ifdef FPGA_BUS_MASTERING
	writereg32(dev, PCI_ATLAS_SYS_CTRL_REGS_BAR, test_ctrl_reg, 0x0);
#else
	writereg32(dev, PCI_ATLAS_SYS_CTRL_REGS_BAR, test_ctrl_reg, 0x1);
	memoffset = data->memmap[2].addr; /*bar2 is memory*/
#endif
	}

	/* All the above only needs to be done once since there is only one FPGA board */

	return 0;

malloc_failed:
	pci_release_regions(dev);

out_disable:
	pci_disable_device(dev);

out_free:
	return -ENODEV;
}

static void pciremove_func(struct pci_dev *dev) {
	/* If Atlas FPGA...*/
	if (!IS_AVNET_OR_MCST_DEVICE(dev->device))
	{
		/* We need to disable interrupts for the embedded device via the Atlas interrupt controller...*/
		writereg32(dev, PCI_ATLAS_SYS_CTRL_REGS_BAR, interrupt_enable_reg, 0x00000000);
	}

	pci_release_regions(dev);
	pci_disable_device(dev);
}

static IMG_PHYSADDR paddr_to_devpaddr(struct SYSDEVU_sInfo *sysdev, IMG_PHYSADDR paddr) {
#ifdef FPGA_BUS_MASTERING
#ifdef CONFIG_SWIOTLB
	return phys_to_dma(sysdev->native_device, paddr);
#else
	return paddr;
#endif
#else
	IMG_UINT64 size;
	IMG_PHYSADDR membase, devpaddr = 0x0;
	struct imgpci_prvdata *data = sysdev->pPrivate;

	membase = data->memmap[2].addr;
	size = data->memmap[2].size;

	if ((paddr >= membase) && (paddr < membase + size))
		devpaddr = paddr - membase;
	else {
		IMG_ASSERT(IMG_FALSE);
	}

	/* Return the device physical address...*/
	return devpaddr;
#endif
}

static struct SYSDEV_ops device_ops = {
		.free_device = pci_freedev,
		.paddr_to_devpaddr = paddr_to_devpaddr,

		.resume_device = handle_resume,
		.suspend_device = handle_suspend

};

IMG_RESULT SYSDEVU_RegisterDriver(SYSDEVU_sInfo *sysdev) {
	int ret, i;
	struct imgpci_prvdata *data;
	struct pci_dev *dev;
	int ramSize;

	/* We are registering the first device driver */
	if (NO_DEVICES_REGISTERED == registered_devices)
	{
		ret = pci_register_driver(&(img_pci_driver.pci_driver));
		BUG_ON(ret != 0);
		if(ret != 0)
		{
			pci_unregister_driver(&(img_pci_driver.pci_driver));
			return IMG_ERROR_DEVICE_UNAVAILABLE;
		}
	}

	dev = img_pci_driver.pci_dev;
	BUG_ON(dev == IMG_NULL);

	data = (struct imgpci_prvdata *)pci_get_drvdata(dev);

	if (data->memmap[2].size > MAP_MEM_SIZE)
	{
		ramSize = MAP_MEM_SIZE;
	}
	else
	{
		ramSize = data->memmap[2].size;
	}

	for (i = 0; i < VXE_KM_SUPPORTED_DEVICES; i++)
	{
		sysdev[i].native_device = (void*)&dev->dev;
		data->devs[i] = &sysdev[i];

	/* Save register pointer etc....*/
	    if( IS_MCST_DEVICE(dev->device) )
	    {
#ifdef FPGA_BUS_MASTERING
               SYSDEVU_SetDevMap(
                       &sysdev[i],
                       data->memmap[0].addr + (i * QUARTZ_DEV_REG_SIZE),
                       (IMG_UINT32 *)((IMG_UINTPTR)data->memmap[0].km_addr + (i * QUARTZ_DEV_REG_SIZE)),
                       QUARTZ_DEV_REG_SIZE,
                       0,
                       IMG_NULL,
                       0,
                       0);
#else
#error Mode w/o FPGA_BUS_MASTERING not supported!!!
               SYSDEVU_SetDevMap(
                       &sysdev[i],
                       data->memmap[0].addr + (i * QUARTZ_DEV_REG_SIZE),
                       (IMG_UINT32 *)((IMG_UINTPTR)data->memmap[0].km_addr + (i * QUARTZ_DEV_REG_SIZE)),
                       QUARTZ_DEV_REG_SIZE,
                       data->memmap[0].addr,
                       (IMG_UINT32 *)data->memmap[0].km_addr,
                       MAP_MEM_SIZE,
                       0);
#endif
	    }
	    else
	    {
#ifdef FPGA_BUS_MASTERING
		SYSDEVU_SetDevMap(
			&sysdev[i],
			data->memmap[1].addr + (i * QUARTZ_DEV_REG_SIZE),
			(IMG_UINT32 *)((IMG_UINTPTR)data->memmap[1].km_addr + (i * QUARTZ_DEV_REG_SIZE)),
			QUARTZ_DEV_REG_SIZE,
			0,
			IMG_NULL,
			0,
			0);
#else
		SYSDEVU_SetDevMap(
			&sysdev[i],
			data->memmap[1].addr + (i * QUARTZ_DEV_REG_SIZE),
			(IMG_UINT32 *)((IMG_UINTPTR)data->memmap[1].km_addr + (i * QUARTZ_DEV_REG_SIZE)),
			QUARTZ_DEV_REG_SIZE,
			data->memmap[2].addr,
			(IMG_UINT32 *)data->memmap[2].km_addr,
			ramSize,
			0);
#endif
	    }
		SYSDEVU_SetDeviceOps(&sysdev[i], &device_ops);
		sysdev[i].pPrivate = data;
	}

	/* Memory has same offset for each device */
#ifdef FPGA_BUS_MASTERING
	ret = SYSMEMKM_AddSystemMemory(&sysdev[0], &sysdev[0].sMemPool);
#else
	ret = SYSMEMKM_AddCarveoutMemory(&sysdev[0], (IMG_UINTPTR)sysdev[0].pui32KmMemBase, sysdev[0].paPhysMemBase, ramSize, &sysdev[0].sMemPool);
#endif
	if(IMG_SUCCESS != ret)
	{
		goto new_heap_failed;
	}
	registered_devices++;

	/* Each device uses the same memory pool */
	for (i = 1; i < VXE_KM_SUPPORTED_DEVICES; i++)
	{
		sysdev[i].sMemPool = sysdev[0].sMemPool;
		registered_devices++;
	}

	/* Check for consistency */
	IMG_ASSERT(registered_devices == VXE_KM_SUPPORTED_DEVICES);
	if (registered_devices != VXE_KM_SUPPORTED_DEVICES)
	{
		/* Inform caller about this critical failure */
		ret = IMG_ERROR_DEVICE_UNAVAILABLE;
	}
	else
	{
		return 0;
	}

new_heap_failed:
	for (i = 0; i < registered_devices; dev++)
	{
		/* Free the heap and release pci device on last */
		SYSDEVU_UnRegisterDriver(data->devs[i]);
		data->devs[i] = NULL;
	}

	IMG_ASSERT(registered_devices == NO_DEVICES_REGISTERED);

	return ret;
}

IMG_RESULT SYSDEVU_UnRegisterDriver(SYSDEVU_sInfo *sysdev) {
	/* No device ever registered (can be caused by an earlier error) */
	if (NO_DEVICES_REGISTERED != registered_devices)
	{
		registered_devices--;
		if (NO_DEVICES_REGISTERED == registered_devices)
		{
			SYSMEMU_RemoveMemoryHeap(sysdev->sMemPool);
		}
		/* Free the pci device */
		sysdev->ops->free_device(sysdev);
	}
	return IMG_SUCCESS;
}
