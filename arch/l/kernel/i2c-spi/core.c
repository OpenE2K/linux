/*
 * Elbrus I2C_SPI controller support
 *
 * Copyright (C) 2012 MCST
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * 2012-05-29	Created
 */

#include <linux/irq.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pci.h>
#include <linux/spi/spi.h>
#include <asm/io.h>
#include <asm/io_apic.h>

#include <asm-l/i2c-spi.h>

/*
 * Elbrus I2C-SPI and Reset Controller that is part of Elbrus IOHUB
 * and is implemented as a pci device in iohub.
 */

static struct pci_device_id i2c_spi_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_ELBRUS, PCI_DEVICE_ID_MCST_I2CSPI) },
 	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_SM) },
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_I2C_SPI) },
	{ 0, }
};

#ifdef CONFIG_L_SPI_CONTROLLER
/* SPI controller */
static struct platform_device spi_controller = {
	.name		= "l_spi",
	.id		= 0	/* spi_master will use this as SPI bus_num */
};
#endif

struct i2c_spi i2c_spi[MAX_NUMIOLINKS];

#ifdef CONFIG_L_I2C_CONTROLLER
/* I2C controller */
static struct platform_device i2c_controller[MAX_NUMIOLINKS];
#endif /* CONFIG_L_I2C_CONTROLLER */

#ifdef CONFIG_I2C_SPI_IRQ

# ifdef CONFIG_L_SPI_CONTROLLER
#  define L_SPI_STATUS		0x04
#  define 	L_SPI_STATUS_INTR_SHIFT		1
#  define 	L_SPI_STATUS_INTR		(1 << L_SPI_STATUS_INTR_SHIFT)
#  define 	L_SPI_STATUS_FAIL_SHIFT		2
#  define 	L_SPI_STATUS_FAIL		(1 << L_SPI_STATUS_FAIL_SHIFT)
#  define L_SPI_MODE		0x10
#  define 	L_SPI_MODE_INTR_SHIFT		4
#  define 	L_SPI_MODE_INTR			(1 << L_SPI_MODE_INTR_SHIFT)

static int spi_irq_num = -1;
# endif

# ifdef CONFIG_L_I2C_CONTROLLER
#  define L_I2C_STATUS		0x18
#  define 	L_I2C_STATUS_INTR_SHIFT		1
#  define 	L_I2C_STATUS_INTR		(1 << L_I2C_STATUS_INTR_SHIFT)
#  define 	L_I2C_STATUS_FAIL_SHIFT		2
#  define 	L_I2C_STATUS_FAIL		(1 << L_I2C_STATUS_FAIL_SHIFT)
#  define L_I2C_MODE		0x1c
#  define 	L_I2C_MODE_INTR_SHIFT		8
#  define 	L_I2C_MODE_INTR			(1 << L_I2C_MODE_INTR_SHIFT)

static int i2c_irq_num = -1;
# endif

/* rtc are on the first iohub,- fortunately we do not have
 * any other exotic configuirations at least with rtc. Emkr.
 */
static void mask_i2c_spi_irq(struct irq_data *irq_data)
{
	unsigned int irq = irq_data->irq;
	void __iomem *ctrl = i2c_spi[0].cntrl_base;
	u32 mode;

	pr_debug("I2C_SPI: masking %d irq\n", irq);

# ifdef CONFIG_L_SPI_CONTROLLER
	if (irq == spi_irq_num) {
		mode = readl(ctrl + L_SPI_MODE);
		writel(mode | L_SPI_MODE_INTR, ctrl + L_SPI_MODE);
	}
# endif

# ifdef CONFIG_L_I2C_CONTROLLER
	if (irq == i2c_irq_num) {
		mode = readl(ctrl + L_I2C_MODE);
		writel(mode | L_I2C_MODE_INTR, ctrl + L_I2C_MODE);
	}
# endif
}

static void unmask_i2c_spi_irq(struct irq_data *irq_data)
{
	unsigned int irq = irq_data->irq;
	void __iomem *ctrl = i2c_spi[0].cntrl_base;
	u32 mode;

	pr_debug("I2C_SPI: unmasking %d irq\n", irq);

# ifdef CONFIG_L_SPI_CONTROLLER
	if (irq == spi_irq_num) {
		mode = readl(ctrl + L_SPI_MODE);
		writel(mode & ~L_SPI_MODE_INTR, ctrl + L_SPI_MODE);
	}
# endif

# ifdef CONFIG_L_I2C_CONTROLLER
	if (irq == i2c_irq_num) {
		mode = readl(ctrl + L_I2C_MODE);
		writel(mode & ~L_I2C_MODE_INTR, ctrl + L_I2C_MODE);
	}
# endif
}

/* I2C_SPI controller gets interrupts from i2c and spi devices
 * ans passes them to IO-APIC, so it is an IRQ controller,
 * Define a corresponding irq_chip. */
static struct irq_chip i2c_spi_chip = {
	.name		= "I2C_SPI",
	.irq_mask	= mask_i2c_spi_irq,
	.irq_unmask	= unmask_i2c_spi_irq
};

static irqreturn_t i2c_spi_interrupt(int irq, void *dev_id)
{
	void __iomem *ctrl = (void __iomem *) dev_id;
	int ret = IRQ_NONE;
	u32 status;

	pr_debug("I2C_SPI interrupt entered\n");

# ifdef CONFIG_L_SPI_CONTROLLER
	status = readl(ctrl + L_SPI_STATUS);
	if (status & (L_SPI_STATUS_INTR | L_SPI_STATUS_FAIL)) {
		generic_handle_irq(spi_irq_num);
		writel(status, ctrl + L_SPI_STATUS);
		pr_debug("SPI interrupt handled\n");
		ret = IRQ_HANDLED;
	}
# endif

# ifdef CONFIG_L_I2C_CONTROLLER
	status = readl(ctrl + L_I2C_STATUS);
	if (status & (L_I2C_STATUS_INTR | L_I2C_STATUS_FAIL)) {
		generic_handle_irq(i2c_irq_num);
		writel(status, ctrl + L_I2C_STATUS);
		pr_debug("I2C interrupt handled\n");
		ret = IRQ_HANDLED;
	}
# endif

	return ret;
}
#endif


#ifdef CONFIG_L_SPI_CONTROLLER

#if defined(CONFIG_RTC_DRV_CY14B101P)
static struct spi_board_info spi_rtc_cy14b101p = {
	.modalias	= "rtc-cy14b101p",
	.max_speed_hz	= 16 * 1024 * 1024, /* 16 MHz */
	.mode		= SPI_MODE_0,
	.bus_num	= 0,	/* Matches 'id' of spi_controller device */
	.chip_select	= 1
};
#endif /* CONFIG_RTC_DRV_CY14B101P */

static struct spi_board_info spi_rtc_fm33256 = {
	.modalias	= "rtc-fm33256",
	.max_speed_hz	= 16 * 1024 * 1024, /* 16 MHz */
	.mode		= SPI_MODE_0,
	.bus_num	= 0,	/* Matches 'id' of spi_controller device */
	.chip_select	= 1
};

static struct spi_board_info spi_rom_s25fl064a = {
	.modalias	= "spidev",
	/* Actually 50 MHz is supported, but not for the READ
	 * command which is usually used by userspace. */
	.max_speed_hz	= 25 * 1024 * 1024, /* 25 MHz */
	.mode		= SPI_MODE_0,
	.bus_num	= 0,
	.chip_select	= 0
};


static int is_cy14b101p_exist(void)
{
	int mbtype = bootblock_virt->info.bios.mb_type;
	switch (mbtype) {
#ifdef CONFIG_E2K
	case MB_TYPE_ES2_RTC_CY14B101P:
	case MB_TYPE_ES2_RTC_CY14B101P_MULTICLOCK:
	case MB_TYPE_E1CP_IOHUB2_RAZBRAKOVSCHIK:
	case MB_TYPE_ES2_EL2S4:
#endif
#ifdef CONFIG_E90S
	case MB_TYPE_E90S_SIVUCH2:
#endif
		return 1;
	default:
#ifdef CONFIG_E2K
		if ((mbtype > MB_TYPE_ES2_EL2S4) &&
			(mbtype < MB_TYPE_E1CP_BASE)) {
			return 1;
		}
		if (mbtype >= MB_TYPE_ES4_BASE) {
			return 1;
		}
#endif
#ifdef CONFIG_E90S
		if (mbtype > MB_TYPE_E90S_REJECTOR) {
			return 1;
		}
#endif
	}
	return 0;
}

static int register_spi_devices(void)
{
	/* Declare SPI devices to the SPI core */
	if (!is_cy14b101p_exist())
		spi_register_board_info(&spi_rtc_fm33256, 1);
# ifdef CONFIG_RTC_DRV_CY14B101P
	else
		spi_register_board_info(&spi_rtc_cy14b101p, 1);
# endif

	spi_register_board_info(&spi_rom_s25fl064a, 1);

	return 0;
}
#endif /* CONFIG_L_SPI_CONTROLLER */

static int i2c_spi_probe(struct pci_dev *iohub_dev,
		const struct pci_device_id *id)
{
#ifdef CONFIG_I2C_SPI_IRQ
	int nr_irqs_gsi;
#endif
	int domain;
	int ret = 0;

	domain = pci_domain_nr(iohub_dev->bus);
	if (domain > 0) {
#if defined(CONFIG_IOHUB_DOMAINS) && MAX_NUMIOLINKS > 1
		void __iomem *regs;
		void __iomem *data;

		if (i2c_spi[domain].cntrl_base == NULL ||
					i2c_spi[domain].data_base == NULL) {
			regs = ioremap(pci_resource_start(iohub_dev, 0),
						I2C_SPI_CNTRL_AREA_SIZE);
			i2c_spi[domain].cntrl_base = regs;
			if (regs == NULL) {
				printk(KERN_ERR
					"i2c_spi_probe() could not map I2C "
					"control registers base address for "
					"domain %d to virtual space\n",
					domain);
				return -ENOMEM;
			}

			data = ioremap(pci_resource_start(iohub_dev, 1),
							I2C_SPI_DATA_AREA_SIZE);
			i2c_spi[domain].data_base = data;
			if (data == NULL) {
				printk("i2c_spi_probe() could not map I2C "
					"data buffers base address to "
					"domain %d virtual space\n",
					domain);
				return -ENOMEM;
			}
			printk(KERN_ERR "Domain %d: found BAR0 %lx BAR1 %lx\n",
				domain, i2c_spi[domain].cntrl_base,
				i2c_spi[domain].data_base);
		}

		ret = pci_enable_device(iohub_dev);
		if (ret) {
			dev_err(&iohub_dev->dev,
				"Failed to setup Elbrus reset control "
				"in i2c-iohub: Unable to make enable device\n");
			return ret;
		}

#ifdef CONFIG_L_I2C_CONTROLLER
		/* Declare I2C controller */
		i2c_controller[domain].id = domain;
		i2c_controller[domain].dev.parent = &iohub_dev->dev;
		ret = platform_device_register(&i2c_controller[domain]);
		if (ret) {
			dev_err(&iohub_dev->dev,
				"Failed to register I2C controller\n");
			goto error1;
		}
#endif /* CONFIG_L_I2C_CONTROLLER */
		return 0;

#else /* CONFIG_IOHUB_DOMAINS && MAX_NUMIOLINKS > 1 */
		dev_info(&iohub_dev->dev,
			"Skipping I2C_SPI controller from PCI domain %d\n",
			domain);
		return 0;
#endif /* !(CONFIG_IOHUB_DOMAINS && MAX_NUMIOLINKS > 1) */
	}

	ret = pci_enable_device(iohub_dev);
	if (ret) {
		dev_err(&iohub_dev->dev,
			"Failed to setup  Elbrus reset control "
			"in i2c-iohub: Unable to make enable device\n");
		return ret;
	}

#ifdef CONFIG_I2C_SPI_IRQ
	nr_irqs_gsi = get_nr_irqs_gsi();
# ifdef CONFIG_L_SPI_CONTROLLER
	spi_irq_num = irq_alloc_desc_from(get_nr_irqs_gsi(), numa_node_id());
	if (spi_irq_num < 0) {
		dev_err(&iohub_dev->dev, "Could not allocate irq for l_spi\n");
		goto error1;
	}
	irq_set_chip_and_handler(spi_irq_num, &i2c_spi_chip, handle_simple_irq);
	dev_info(&iohub_dev->dev, "Allocated %d irq for SPI\n", spi_irq_num);
# endif
# ifdef CONFIG_L_I2C_CONTROLLER
	i2c_irq_num = irq_alloc_desc_from(get_nr_irqs_gsi(), numa_node_id());
	if (i2c_irq_num < 0) {
		dev_err(&iohub_dev->dev, "Could not allocate irq for l_i2c\n");
		goto error1;
	}
	irq_set_chip_and_handler(i2c_irq_num, &i2c_spi_chip, handle_simple_irq);
	dev_info(&iohub_dev->dev, "Allocated %d irq for I2C\n", i2c_irq_num);
# endif
	/* TODO FIXME when migrating to 3.0 use IRQF_NO_THREAD here */
	ret = request_irq(i2c_spi[0].IRQ, i2c_spi_interrupt, IRQF_SHARED,
			"I2C_SPI", i2c_spi.cntrl_base);
	if (ret) {
		dev_err(&iohub_dev->dev, "Could not allocate interrupt handler "
				"for the I2C_SPI controller\n");
		goto error1;
	}
#endif

#ifdef CONFIG_L_SPI_CONTROLLER
	/* Declare SPI devices */
	register_spi_devices();

	/* Declare SPI controller */
	spi_controller.dev.parent = &iohub_dev->dev;
	ret = platform_device_register(&spi_controller);
	if (ret) {
		dev_err(&iohub_dev->dev, "Failed to register "
				"SPI controller\n");
		goto error1;
	}
#endif

#ifdef CONFIG_L_I2C_CONTROLLER
	/* Declare I2C controller */
	i2c_controller[0].dev.parent = &iohub_dev->dev;
	ret = platform_device_register(&i2c_controller[0]);
	if (ret) {
		dev_err(&iohub_dev->dev, "Failed to register "
				"I2C controller\n");
		goto error2;
	}
#endif

	return 0;

#ifdef CONFIG_L_I2C_CONTROLLER
error2:
# ifdef CONFIG_L_SPI_CONTROLLER
	platform_device_unregister(&spi_controller);
# endif
#endif
#if defined(CONFIG_L_I2C_CONTROLLER) || defined(CONFIG_L_SPI_CONTROLLER)
error1:
	pci_disable_device(iohub_dev);

	return ret;
#endif
}

static void i2c_spi_remove(struct pci_dev *dev)
{
	int domain;

	domain = pci_domain_nr(dev->bus);

#ifdef CONFIG_L_SPI_CONTROLLER
	if (domain == 0)
		platform_device_unregister(&spi_controller);
#endif

#ifdef CONFIG_L_I2C_CONTROLLER
	platform_device_unregister(&i2c_controller[domain]);
#endif
}

static struct pci_driver i2c_spi_driver = {
	.name		= "i2c_spi",
	.id_table	= i2c_spi_ids,
	.probe		= i2c_spi_probe,
	.remove		= i2c_spi_remove
};

__init
static int i2c_spi_init(void)
{
	return pci_register_driver(&i2c_spi_driver);
}
module_init(i2c_spi_init);

__exit
static void i2c_spi_exit(void)
{
	pci_unregister_driver(&i2c_spi_driver);
}
module_exit(i2c_spi_exit);


DEFINE_SPINLOCK(i2c_spi_lock);

__init
static int early_i2c_spi_init(void)
{
	void __iomem *regs;
	void __iomem *data;
	int i;

#ifdef CONFIG_E2K
	if (!HAS_MACHINE_E2K_IOHUB)
		return 0;
#endif

	i2c_controller[0].name = "l_i2c";
	i2c_controller[0].id = 0;

#if defined(CONFIG_IOHUB_DOMAINS) && MAX_NUMIOLINKS > 1
	for (i = 1; i < MAX_NUMIOLINKS; i++) {
		i2c_spi[i].cntrl_base = NULL;
		i2c_spi[i].data_base = NULL;
		i2c_controller[i].name = "l_i2c";
		i2c_controller[i].id = -1;
	}
#endif /* CONFIG_IOHUB_DOMAINS && MAX_NUMIOLINKS > 1 */

	regs = ioremap((unsigned long)i2c_spi[0].cntrl_base,
					I2C_SPI_CNTRL_AREA_SIZE);
	i2c_spi[0].cntrl_base = regs;
	if (regs == NULL) {
		printk("spi_init() could not map IOHUB I2C/SPI control "
			"registers base address to virtual space\n");
		return -ENOMEM;
	}
	data = ioremap((unsigned long)i2c_spi[0].data_base,
						I2C_SPI_DATA_AREA_SIZE);
	i2c_spi[0].data_base = data;
	if (data == NULL) {
		printk("spi_init() could not map IOHUB I2C/SPI data "
			"buffers base address to virtual space\n");
		return -ENOMEM;
	}
	return 0;
}
arch_initcall(early_i2c_spi_init);


MODULE_AUTHOR("Evgeny Kravtsunov <kravtsunov_e@mcst.ru>");
MODULE_DESCRIPTION("Elbrus I2C-SPI SMBus driver");
MODULE_LICENSE("GPL");
