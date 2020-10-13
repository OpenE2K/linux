/*
 * Elbrus IDE driver specific
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ioport.h>
#include <linux/pci.h>
#include <linux/hdreg.h>
#include <linux/ide.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/irq.h>

#include <asm/io.h>
#include <asm/l_ide.h>

#undef	DEBUG_IDE_MODE
#undef	DebugIDE
#define	DEBUG_IDE_MODE		0	/* PCI init */
#define	DebugIDE		if (DEBUG_IDE_MODE) printk
#define	DebugBUSINFO		if (DEBUG_IDE_MODE) Debug_BUS_INFO
#define	DebugRESINFO		if (DEBUG_IDE_MODE) Debug_RES_INFO
#define	DebugALLRESINFO		if (DEBUG_IDE_MODE) Debug_ALL_RES_INFO
#define	DebugDEVINFO		if (DEBUG_IDE_MODE) Debug_DEV_INFO


#define DRV_NAME "ELBRUS-IDE"

/*
 * IDE Configuration registers
 */
#define	L_IDE_CONTROL		0x40	/* IDE control register 0x40-0x41 */

/* IDE Control Register structure */
#define	UDMA_MASTER_PRIMARY_IDEC	0x0001	/* Ultra DMA mode for master */
						/* of primary channel */
#define	UDMA_SLAVE_PRIMARY_IDEC		0x0002	/* Ultra DMA mode for slave */
						/* of primary channel */
#define	UDMA_MASTER_SECONDARY_IDEC	0x0004	/* Ultra DMA mode for master */
						/* of secjndary channel */
#define	UDMA_SLAVE_SECONDARY_IDEC	0x0008	/* Ultra DMA mode for slave */
						/* of secjndary channel */
#define	PREF_ENABLE_PRIMARY_IDEC	0x0010	/* Post and prefetch enable */
						/* for primary channel */
#define	PREF_ENABLE_SECONDARY_IDEC	0x0020	/* Post and prefetch enable */
						/* for secondary channel */
#define	RESET_INTERFACE_IDEC		0x0040	/* reset IDE interface */
#define	MASK_INTB_IDEC			0x0080	/* intb interrupt masked */
#define	MASK_INT_PRIMARY_IDEC		0x0100	/* interrupt masked for */
						/* primary channel */
#define	MASK_INT_SECONDARY_IDEC		0x0200	/* interrupt masked for */
						/* primary channel */

#define	GET_ULTRA_DMA_ENABLE_MODE_IDEC(reg_value, secondary, slave)	\
({									\
	unsigned int mode;						\
	if (secondary) {						\
		if (slave)						\
			mode = (reg_value) & UDMA_SLAVE_SECONDARY_IDEC;	\
		else							\
			mode = (reg_value) & UDMA_MASTER_SECONDARY_IDEC;\
	} else {							\
		if (slave)						\
			mode = (reg_value) & UDMA_SLAVE_PRIMARY_IDEC;		\
		else							\
			mode = (reg_value) & UDMA_MASTER_PRIMARY_IDEC;		\
	}								\
	mode = (mode != 0);						\
})
#define	SET_ULTRA_DMA_ENABLE_MODE_IDEC(reg_value, secondary, slave)	\
({									\
	if (secondary) {						\
		if (slave)						\
			(reg_value) |= UDMA_SLAVE_SECONDARY_IDEC;	\
		else							\
			(reg_value) |= UDMA_MASTER_SECONDARY_IDEC;\
	} else {							\
		if (slave)						\
			(reg_value) |= UDMA_SLAVE_PRIMARY_IDEC;		\
		else							\
			(reg_value) |= UDMA_MASTER_PRIMARY_IDEC;		\
	}								\
})
#define	SET_MULTIWORD_DMA_ENABLE_MODE_IDEC(reg_value, secondary, slave)	\
({									\
	if (secondary) {						\
		if (slave)						\
			(reg_value) &= ~UDMA_SLAVE_SECONDARY_IDEC;	\
		else							\
			(reg_value) &= ~UDMA_MASTER_SECONDARY_IDEC;\
	} else {							\
		if (slave)						\
			(reg_value) &= ~UDMA_SLAVE_PRIMARY_IDEC;		\
		else							\
			(reg_value) &= ~UDMA_MASTER_PRIMARY_IDEC;		\
	}								\
})

/* Class Code register */
#define	NATIVE_MODE_PRIMARY_CLASSC	0x01	/* primary channel in native */
						/* mode */
#define	NATIVE_MODE_SECONDARY_CLASSC	0x04	/* secondary channel in */
						/* native mode */
#define	NATIVE_MODE_CLASSC		(NATIVE_MODE_PRIMARY_CLASSC | \
						NATIVE_MODE_SECONDARY_CLASSC)

/* IDE PIO register port access timing register */
#define	L_IDE_PIO_RPA			0x44	/* IDE register 0x44 */
/* register structure */
#define	MODE_0_IDE_PIO_RPA		0x00	/* Mode 0 to access */
#define	MODE_1_IDE_PIO_RPA		0x01	/* Mode 1 to access */
#define	MODE_2_IDE_PIO_RPA		0x02	/* Mode 2 to access */
#define	MODE_3_IDE_PIO_RPA		0x03	/* Mode 3 to access */
#define	MODE_4_IDE_PIO_RPA		0x04	/* Mode 4 to access */

/* IDE PIO data port access timing register */
#define	L_IDE_PIO_DPA			0x48	/* IDE register 0x48-0x4b */
/* register structure */
#define	L_IDE_PIO_DPA0_P		0x48	/* primary channel master */
#define	L_IDE_PIO_DPA1_P		0x49	/* primary channel slave */
#define	L_IDE_PIO_DPA0_S		0x4a	/* secondary channel master */
#define	L_IDE_PIO_DPA1_S		0x4b	/* secondary channel slave */

#define	MODE_0_IDE_PIO_DPA		0x00	/* Mode 0 to access */
#define	MODE_1_IDE_PIO_DPA		0x01	/* Mode 1 to access */
#define	MODE_2_IDE_PIO_DPA		0x02	/* Mode 2 to access */
#define	MODE_3_IDE_PIO_DPA		0x03	/* Mode 3 to access */
#define	MODE_4_IDE_PIO_DPA		0x04	/* Mode 4 to access */
#define	MAX_MODE_IDE_PIO_DPA		MODE_4_IDE_PIO_DPA

/* IDE DMA IDE access timing register */
#define	L_IDE_DMA_DA			0x4c	/* IDE register 0x4c-0x4f */
/* register structure */
#define	L_IDE_DMA_DA0_P			0x4c	/* primary channel master */
#define	L_IDE_DMA_DA1_P			0x4d	/* primary channel slave */
#define	L_IDE_DMA_DA0_S			0x4e	/* secondary channel master */
#define	L_IDE_DMA_DA1_S			0x4f	/* secondary channel slave */

#define	MULTIWORD_DMA_MODE_0_IDE	0x00	/* Multiword Mode 0 to access */
#define	MULTIWORD_DMA_MODE_1_IDE	0x01	/* Multiword Mode 1 to access */
#define	MULTIWORD_DMA_MODE_2_IDE	0x02	/* Multiword Mode 2 to access */
#define	ULTRA_DMA_MODE_0_IDE		0x00	/* Ultra DMA Mode 0 to access */
#define	ULTRA_DMA_MODE_1_IDE		0x01	/* Ultra DMA Mode 1 to access */
#define	ULTRA_DMA_MODE_2_IDE		0x02	/* Ultra DMA Mode 2 to access */
#define	ULTRA_DMA_MODE_3_IDE		0x03	/* Ultra DMA Mode 3 to access */
#define	ULTRA_DMA_MODE_4_IDE		0x04	/* Ultra DMA Mode 4 to access */
#define	ULTRA_DMA_MODE_5_IDE		0x05	/* Ultra DMA Mode 5 to access */

#define	GET_L_IDE_MODE(reg_value, secondary, slave)			\
({									\
	unsigned int mode;						\
	if (secondary) {						\
		if (slave)						\
			mode = ((reg_value) >> 24) & 0xff;		\
		else							\
			mode = ((reg_value) >> 16) & 0xff;		\
	} else {							\
		if (slave)						\
			mode = ((reg_value) >> 8) & 0xff;		\
		else							\
			mode = ((reg_value) >> 0) & 0xff;		\
	}								\
	mode;								\
})
#define	SET_L_IDE_MODE(reg_value, mode, secondary, slave)		\
({									\
	if (secondary) {						\
		if (slave) {						\
			(reg_value) &= ~((0xff) << 24);		\
			(reg_value) |= ((mode) << 24);			\
		} else {						\
			(reg_value) &= ~((0xff) << 16);		\
			(reg_value) |= ((mode) << 16);			\
		}							\
	} else {							\
		if (slave) {						\
			(reg_value) &= ~((0xff) << 8);			\
			(reg_value) |= ((mode) << 8);			\
		} else {						\
			(reg_value) &= ~((0xff) << 0);			\
			(reg_value) |= ((mode) << 0);			\
		}							\
	}								\
})

/* IDE iterrupt number */
#define	NATIVE_MODE_IDE_IRQ		11	/* IRQ # for native mode */
#define	LEGACY_MODE_IDE_IRQ		14	/* IRQ # for legacy mode */

/* Number of word size registers in PCI config space */
#define L_IDE_CONFIG_REGS_NUM		32

static u32 saved_config_space[L_IDE_CONFIG_REGS_NUM];

static struct pci_device_id l_pci_tbl[] = {
	{
		.vendor = PCI_VENDOR_ID_ELBRUS,
		.device = PCI_DEVICE_ID_MCST_IDE,
		.subvendor = PCI_ANY_ID,
		.subdevice = PCI_ANY_ID,
	},
	{
		.vendor = PCI_VENDOR_ID_MCST_TMP,
		.device = PCI_DEVICE_ID_MCST_IDE_SDHCI,
		.subvendor = 0,
		.subdevice = 0,
	},
	{
		0,
	},
};

static void init_hwif_l_ide(ide_hwif_t *hwif);
static int init_chipset_l_ide(struct pci_dev *dev);
static void l_init_iops(ide_hwif_t *hwif);

static int l_dma_mode = L_DEAULT_IDE_DMA_MODE;

static int __init l_setup_ide_dma(char *str)
{
	if (strcmp(str, "mw2") == 0 || strcmp(str, "mword2") == 0) {
		l_dma_mode = ATA_MWDMA2;	/* multi-word 2 */
	} else if (strcmp(str, "udma2") == 0 || strcmp(str, "udma33") == 0) {
		l_dma_mode = ATA_UDMA2;		/* ultra DMA 33 */
	} else if (strcmp(str, "udma4") == 0 || strcmp(str, "udma66") == 0) {
		l_dma_mode = ATA_UDMA4;		/* ultra DMA 66 */
	} else if (strcmp(str, "udma5") == 0) {
		l_dma_mode = ATA_UDMA5;		/* ultra DMA 100 */
	}
	return 1;
}

__setup("idedma=", l_setup_ide_dma);

static u8 l_udma_filter(ide_drive_t *drive)
{
	return (l_dma_mode);
}

/**
 *	l_set_pio_mode		-	set host controller for PIO mode
 *	@drive: drive to tune
 *	@pio: desired PIO mode
 *
 *	Set the interface PIO mode based upon  the settings done by AMI BIOS
 *	(might be useful if drive is not registered in CMOS for any reason).
 */
static void l_set_pio_mode (ide_hwif_t *hwif, ide_drive_t *drive)
{
	struct pci_dev *dev	= to_pci_dev(hwif->dev);
	const u8 pio = drive->pio_mode - XFER_PIO_0;

	DebugIDE("%s: l_set_pio_mode() PIO mode is 0x%x\n",
		pci_name(dev), pio);
}

/**
 *	l_set_dma_mode	-	tune a Elbrus IDE interface
 *	@drive: IDE drive to tune
 *	@speed: speed to configure
 *
 *	Set a IDE interface channel to the desired speeds. This involves
 *	requires the right timing data into the IDE configuration space
 *	then setting the drive parameters appropriately
 */

static void l_set_dma_mode(ide_hwif_t *hwif, ide_drive_t *drive)
{
	struct pci_dev *dev	= to_pci_dev(hwif->dev);
	int channel		= hwif->channel;
	int slave		= drive->dn & 1;
	u16 ide_cntr;
	u16 new_cntr;
	u32 ide_timing;
	u8  timing;
	const u8 speed = drive->dma_mode;

	DebugIDE("%s: l_set_dma_mode() config drive %s.%s speed to 0x%x\n",
		pci_name(dev), (channel) ? "secondary" : "primary",
		(!slave) ? "master" : "slave",
		speed);
	pci_read_config_word(dev, L_IDE_CONTROL, &ide_cntr);
	new_cntr = ide_cntr;
	pci_read_config_dword(dev, L_IDE_DMA_DA, &ide_timing);
	DebugIDE("%s: IDE Control Register 0x%04x, DMA mode 0x%08x\n",
		pci_name(dev), ide_cntr, ide_timing);
	switch(speed) {
		case XFER_UDMA_5:
		case XFER_UDMA_4:
		case XFER_UDMA_3:
		case XFER_UDMA_2:
		case XFER_UDMA_1:
		case XFER_UDMA_0:
			SET_ULTRA_DMA_ENABLE_MODE_IDEC(new_cntr,
							channel, slave);
			break;
		case XFER_MW_DMA_2:
		case XFER_MW_DMA_1:
		case XFER_SW_DMA_2:
		case XFER_MW_DMA_0:
		case XFER_SW_DMA_1:
		case XFER_SW_DMA_0:
			SET_MULTIWORD_DMA_ENABLE_MODE_IDEC(new_cntr,
							channel, slave);
			break;
		default:
			panic("l_tune_chipset() Bad IDE %s speed 0x%x\n",
				pci_name(dev), speed);
	}
	switch(speed) {
		case XFER_UDMA_5:
			timing = ULTRA_DMA_MODE_5_IDE;
			break;
		case XFER_UDMA_4:
			timing = ULTRA_DMA_MODE_4_IDE;
			break;
		case XFER_UDMA_3:
			timing = ULTRA_DMA_MODE_3_IDE;
			break;
		case XFER_UDMA_2:
			timing = ULTRA_DMA_MODE_2_IDE;
			break;
		case XFER_UDMA_1:
			timing = ULTRA_DMA_MODE_1_IDE;
			break;
		case XFER_UDMA_0:
			timing = ULTRA_DMA_MODE_0_IDE;
			break;
		case XFER_MW_DMA_2:
		case XFER_SW_DMA_2:
			timing = MULTIWORD_DMA_MODE_2_IDE;
			break;
		case XFER_MW_DMA_1:
		case XFER_SW_DMA_1:
			timing = MULTIWORD_DMA_MODE_1_IDE;
			break;
		case XFER_MW_DMA_0:
		case XFER_SW_DMA_0:
			timing = MULTIWORD_DMA_MODE_0_IDE;
			break;
			break;
		default:
			panic("l_tune_chipset() Bad IDE %s speed 0x%x\n",
				pci_name(dev), speed);
	}
	if (ide_cntr != new_cntr) {
		pci_write_config_word(dev, L_IDE_CONTROL, new_cntr);
		DebugIDE("%s: set %s DMA enable mode for %s %s in IDE "
			"Control Register 0x%04x\n",
			pci_name(dev),
			(GET_ULTRA_DMA_ENABLE_MODE_IDEC(new_cntr,
				channel, slave)) ? "ULTRA" : "MULTIWORD",
			(channel) ? "secondary" : "primary",
			(slave) ? "slave" : "master",
			new_cntr);
	}
	if (GET_L_IDE_MODE(ide_timing, channel, slave) != timing) {
#ifdef CONFIG_E90
                SET_L_IDE_MODE(ide_timing, 0xee, channel, slave);
#else
		SET_L_IDE_MODE(ide_timing, timing, channel, slave);
#endif
		pci_write_config_dword(dev, L_IDE_DMA_DA, ide_timing);
		DebugIDE("%s: set %s DMA (%d) mode for %s %s in IDE "
			"DMA Timing Register 0x%08x\n",
			pci_name(dev),
			(GET_ULTRA_DMA_ENABLE_MODE_IDEC(new_cntr,
				channel, slave)) ? "ULTRA" : "MULTIWORD",
			timing,
			(channel) ? "secondary" : "primary",
			(slave) ? "slave" : "master",
			ide_timing);
	}
}

static u8 l_cable_detect(ide_hwif_t *hwif)
{
	/*
	 * Elbrus IDE controller support ULTRA DMA-5 mode, but
	 * has not hardware support to detect cable type
	 * So driver supposes that a 80 wire cable was detected
	 * To limitate DMA mode use command line option
	 * idedma=  (udma2, udma3 ... udma5)
	 */

	return (ATA_CBL_PATA80);
}

static void l_ide_reset(struct pci_dev *dev)
{
	u16 ide_cntr;
	/* Resetting controller */
	pr_warning("%s:  resetting IDE controller\n", pci_name(dev));
	pci_read_config_word(dev, L_IDE_CONTROL, &ide_cntr);
	ide_cntr |= RESET_INTERFACE_IDEC;
	pci_write_config_word(dev, L_IDE_CONTROL, ide_cntr);
	udelay(25);
	pci_read_config_word(dev, L_IDE_CONTROL, &ide_cntr);
	ide_cntr &= ~RESET_INTERFACE_IDEC;
	pci_write_config_word(dev, L_IDE_CONTROL, ide_cntr);
}

#ifndef CONFIG_E90
static void l_dma_clear(ide_drive_t *drive)
{
	ide_hwif_t *hwif = drive->hwif;
	__le32 *t = (__le32 *)hwif->dmatable_cpu;
		pr_warning("DMA table:\n");
	do {
		pr_warning("\t%04x\t%04x\n",
		       le32_to_cpu(t[0]), le32_to_cpu(t[1]));
		if (le32_to_cpu(t[1]) & 0x80000000)
			break;
		t += 2;
	} while (1);

	l_ide_reset(to_pci_dev(hwif->dev));
}

static int l_ide_timer_expiry(ide_drive_t *drive)
{
	ide_hwif_t *hwif = drive->hwif;
	u8 dma_stat = hwif->dma_ops->dma_sff_read_status(hwif);

	pr_warning("%s: DMA status (0x%02x) {%s %s %s}\n",
			drive->name, dma_stat,
			dma_stat & ATA_DMA_ERR ? "Error" : NULL,
			dma_stat & ATA_DMA_ACTIVE ? "Active" : NULL,
			dma_stat & ATA_DMA_INTR ? "Interrupt" : NULL
	      );
	ide_dump_status(drive, "DMA timeout",
					hwif->tp_ops->read_status(hwif));

	if ((dma_stat & 0x18) == 0x18)	/* BUSY Stupid Early Timer !! */
		return WAIT_CMD;

	hwif->expiry = NULL;	/* one free ride for now */

	if (dma_stat & ATA_DMA_ERR) {	/* ERROR */
		l_dma_clear(drive);
		return -1;
	}

	if (dma_stat & ATA_DMA_ACTIVE)	/* DMAing */
		return WAIT_CMD;

	if (dma_stat & ATA_DMA_INTR)	/* Got an Interrupt */
		return WAIT_CMD;

	return 0;	/* Status is unknown -- reset the bus */
}

static const struct ide_dma_ops l_ide_dma_ops = {
	.dma_host_set		= ide_dma_host_set,
	.dma_setup		= ide_dma_setup,
	.dma_start		= ide_dma_start,
	.dma_end		= ide_dma_end,
	.dma_test_irq		= ide_dma_test_irq,
	.dma_lost_irq		= ide_dma_lost_irq,
	.dma_timer_expiry	= l_ide_timer_expiry,
	.dma_sff_read_status	= ide_dma_sff_read_status,
	.dma_clear		= l_dma_clear,
};
#endif	/*CONFIG_E90*/

static const struct ide_port_ops l_port_ops = {
	.set_pio_mode		= l_set_pio_mode,
	.set_dma_mode		= l_set_dma_mode,
	.udma_filter		= l_udma_filter,
	.cable_detect		= l_cable_detect,
};

static struct ide_port_info l_pci_info = {
	.name		= "ELBRUS",
	.init_hwif	= &init_hwif_l_ide,
	.init_chipset	= &init_chipset_l_ide,
	.init_iops	= l_init_iops,
	.host_flags	= IDE_HFLAG_NO_AUTODMA,
	.port_ops	= &l_port_ops,
#ifdef CONFIG_E90
	.dma_ops	= &e90_dma_ops,
#else
	.dma_ops	= &l_ide_dma_ops,
#endif
	.pio_mask	= ATA_PIO4,
	.mwdma_mask	= ATA_MWDMA2,
	.udma_mask	= ATA_UDMA5,
};

static int init_chipset_l_ide(struct pci_dev *dev)
{
	u16 ide_cntr;

	DebugIDE("%s: init_chipset_l_ide() started\n", pci_name(dev));
	pci_read_config_word(dev, L_IDE_CONTROL, &ide_cntr);
	DebugIDE("%s: IDE Control Register 0x%04x, IRQ %d\n",
		pci_name(dev), ide_cntr, dev->irq);
	if (ide_cntr & (MASK_INTB_IDEC | MASK_INT_PRIMARY_IDEC |
						MASK_INT_SECONDARY_IDEC)) {
		printk(KERN_INFO "%s: Unmask interrupts\n", pci_name(dev));
		ide_cntr &= ~(MASK_INTB_IDEC | MASK_INT_PRIMARY_IDEC |
						MASK_INT_SECONDARY_IDEC);
		pci_write_config_word(dev, L_IDE_CONTROL, ide_cntr);
	}
#ifndef CONFIG_E90
	if (dev->class & (NATIVE_MODE_CLASSC)) {
		if (dev->irq <= 0) {
			DebugIDE("%s: IDE in native mode set IRQ to %d\n",
				pci_name(dev), NATIVE_MODE_IDE_IRQ);
			dev->irq = NATIVE_MODE_IDE_IRQ;
		}
		DebugIDE("%s: IDE in native mode set IRQ to %d\n",
			pci_name(dev), dev->irq);

		l_pci_info.host_flags &= ~IDE_HFLAG_ISA_PORTS;
	} else {
		if (dev->irq <= 0) {
			DebugIDE("%s: IDE in legacy mode set IRQ to %d\n",
				pci_name(dev), LEGACY_MODE_IDE_IRQ);
			dev->irq = LEGACY_MODE_IDE_IRQ;
		}
		l_pci_info.host_flags |= IDE_HFLAG_ISA_PORTS;
	}
#endif
	return (0);
}

static void l_enable_io_ports(struct pci_dev *dev, bool enable)
{
	u16 old_cmd, cmd;

	pci_read_config_word(dev, PCI_COMMAND, &old_cmd);
	if (enable)
		cmd = old_cmd | PCI_COMMAND_IO;
	else
		cmd = old_cmd & ~PCI_COMMAND_IO;
	if (cmd != old_cmd) {
		DebugIDE("l_enable_io_ports() IO space: %s \n",
			enable ? "enabling" : "disabling");
		pci_write_config_word(dev, PCI_COMMAND, cmd);
	}
}

/**
 *	init_hwif_l_ide		-	fill in the hwif for the ELBRUS
 *	@hwif: IDE interface
 *
 *	Set up the ide_hwif_t for the ELBRUS interface according to the
 *	capabilities of the hardware.
 */

static void init_hwif_l_ide(ide_hwif_t *hwif)
{
	l_enable_io_ports(to_pci_dev(hwif->dev), 1);
	if (!hwif->dma_base) {
		DebugIDE("%s: init_hwif_l_ide() DMA base does not set\n",
			pci_name(to_pci_dev(hwif->dev)));
		return;
	}
	DebugIDE("%s: init_hwif_l_ide() DMA base set to 0x%lx\n",
		pci_name(to_pci_dev(hwif->dev)), hwif->dma_base);
}

/**
 *	l_probe	- called when a Elbrus IDE is found
 *	@dev: the Elbrus device
 *	@id: the matching pci id
 *
 *	Called when the PCI registration layer (or the IDE initialization)
 *	finds a device matching our IDE device tables.
 */

static int l_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	struct ide_port_info *d = &l_pci_info;
	if (id->driver_data != 0) {
		pr_alert("%s: l_probe() invalid IDE id %ld should be only 0\n",
			pci_name(dev), id->driver_data);
		return (-1);
	}

	if(L_FORCE_NATIVE_MODE) {
		pci_write_config_dword(dev, PCI_CLASS_REVISION,
						NATIVE_MODE_CLASSC << 8);
		dev->class |= NATIVE_MODE_CLASSC;
	}

	return ide_pci_init_one(dev, d, NULL);
}

static int l_suspend(struct pci_dev *dev, pm_message_t state)
{
	int i;

	DebugIDE("%s: l_suspend() save PCI config space:\n", pci_name(dev));
	for (i = 0; i < L_IDE_CONFIG_REGS_NUM; i++) {
		pci_read_config_dword(dev, i * 4, &saved_config_space[i]);
		DebugIDE("reg[%d]=0x%x\n", i, saved_config_space[i]);
	}

	return 0;
}

static int l_resume(struct pci_dev *dev)
{
	int i;
	struct irq_desc *irq_desc;
	struct irq_chip *irq_chip;
	struct irq_data *irq_data;

	l_ide_reset(dev);

	/* Config space recovery */
	DebugIDE("%s: l_resume() recovery PCI config space:\n", pci_name(dev));
	for (i = L_IDE_CONFIG_REGS_NUM - 1; i >= 0; i--) {
		u32 val;
		pci_read_config_dword(dev, i * 4, &val);
		if (val != saved_config_space[i]) {
			pci_write_config_dword(dev, i * 4,
				saved_config_space[i]);
		}
		DebugIDE("reg[%d]=0x%x\n", i, saved_config_space[i]);
	}

	/* Unmask interrupt in IOAPIC */
	DebugIDE("%s: l_resume() unmask 0x%x interrupt in IOAPIC\n",
		pci_name(dev), dev->irq);

	irq_desc = irq_to_desc(dev->irq);
	irq_chip = irq_desc_get_chip(irq_desc);
	irq_data = irq_desc_get_irq_data(irq_desc);			

	irq_chip->irq_unmask(irq_data);

	return 0;
}

MODULE_DEVICE_TABLE(pci, l_pci_tbl);

static struct pci_driver driver = {
	.name		= DRV_NAME,
	.id_table	= l_pci_tbl,
	.probe		= l_probe,
	.suspend	= l_suspend,
	.resume		= l_resume,
};

static int __init l_ide_init(void)
{
	return ide_pci_register_driver(&driver);
}

module_init(l_ide_init);

MODULE_AUTHOR("Salavat Gilazov, Alexey Sitnikov");
MODULE_DESCRIPTION("PCI driver module for Elbrus IDE");
MODULE_LICENSE("GPL");
