/*
 * $Id: mptable.c,v 1.22 2009/02/24 15:13:30 atic Exp $
 */

#include <linux/types.h>
#include <linux/cpumask.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>

#include <asm/mpspec.h>
#include <asm/e2k_debug.h>
#include <asm/e2k_api.h>
#include <asm/e2k.h>

#include "printk.h"
#include "pci.h"
#include "../boot_io.h"

#undef BIOS_DEBUG
#define MTABLE_DEBUG 0
#define BIOS_DEBUG MTABLE_DEBUG

#define	MP_IRQ_EDGE_HIGH	(MP_IRQ_TRIGGER_EDGE  | MP_IRQ_POLARITY_HIGH)
#define	MP_IRQ_LEVEL_HIGH	(MP_IRQ_TRIGGER_LEVEL | MP_IRQ_POLARITY_HIGH)
#define	MP_BUS_ISA_NUM	0x1f

/* Setting resources for iopic, timer and cmos to mptable */
void smp_write_ioepic_i2c_spi_info(struct mpc_table *mc,
	struct bios_pci_dev *dev, unsigned int ioepicid)
{
	unsigned int timer_base;
	unsigned int domain = bios_pci_domain_nr(dev->bus);
	unsigned int ioepic_base;

	pcibios_read_config_dword(domain, dev->bus->number,
			dev->devfn, PCI_BASE_ADDRESS_2, &timer_base);
	rom_printk("Reading timer_base from I2C-SPI: 0x%x\n", timer_base);
	timer_base = timer_base & 0xfffffff0; /* Masking the lower bits */
	smp_i2c_spi_timer(mc, MP_LT_TYPE, MP_LT_VERSION, MP_LT_FLAGS,
				timer_base);
	smp_i2c_spi_timer(mc, MP_RTC_TYPE, MP_RTC_VER_CY14B101P, 0,
				0xffffffff);

	pcibios_read_config_dword(domain, dev->bus->number,
			dev->devfn, PCI_BASE_ADDRESS_3, &ioepic_base);
	rom_printk("Reading ioepic_base from I2C-SPI: 0x%x\n", ioepic_base);

	ioepic_base = ioepic_base & 0xfffffff0; /* Masking the lower bits */
	smp_write_ioepic(mc, ioepicid, domain, 0x0, ioepic_base);

	smp_i2c_spi_dev(mc, 1, 15, (unsigned long)dev);

	/*
	 * Additionally, write IO-link info for EIOHub. Otherwise, kernel
	 * will try to construct one by default, discover that IO-APIC entry
	 * is missing from the MP table (nr_ioapics) and panic.
	 * Includes new mpc_config_iolink fields for IOMMU: PCI MEM area
	 */
	rom_printk("Passing PCI MEM area for IOMMU (node %d): 0x%x - 0x%x\n",
		domain, PCI_MEM_DOMAIN_START(domain),
		PCI_MEM_DOMAIN_END(domain));
	smp_write_iolink(mc, domain, 0, 0, 1, ioepicid,
		PCI_MEM_DOMAIN_START(domain), PCI_MEM_DOMAIN_END(domain));
}

/* Setting resources for iopic, timer and cmos to mptable */
void smp_write_ioapic_i2c_spi_info(struct mpc_table *mc,
	struct bios_pci_dev *dev, unsigned int ioapicid)
{
	unsigned int timer_base;
	unsigned long timeraddr;
	unsigned int timer_upper32;
	unsigned int domain = bios_pci_domain_nr(dev->bus);

	pcibios_read_config_dword(domain, dev->bus->number,
				dev->devfn, SYSTEM_TIMER_BASE_ADDRESS, &timer_base);
	pcibios_read_config_dword(domain, dev->bus->number, dev->devfn,
				SYSTEM_TIMER_UPPER_ADDRESS, &timer_upper32);
	rom_printk("MP: setting timeraddr to mptable:\n"
		   "timer_upper32 = 0x%x, timer_base = 0x%x\n",
				timer_upper32, timer_base);
	timeraddr = timer_upper32;
	timeraddr = (timeraddr << 32);
	timeraddr |= timer_base;
	smp_i2c_spi_timer(mc, MP_LT_TYPE, MP_LT_VERSION, MP_LT_FLAGS,
				timeraddr);

	smp_write_ioapic(mc, ioapicid, 0x11, 0xfec00000 + domain * 0x1000);

	smp_i2c_spi_dev(mc, 1, 23, (unsigned long)dev);

	smp_write_iolink(mc, domain, 0, 1, 3, ioapicid, 0, 0);
}

void smp_write_ioapic_intsrc_info(struct mpc_table *mc, unsigned int node,
	unsigned int bus, unsigned int ioapicid)
{
	smp_write_intsrc(mc, mp_ExtINT,     0x05, 0x00, 0x00, ioapicid, 0x00); /* PIC */
	smp_write_intsrc(mc, mp_FixINT,     0x05, 0x1f, 0x00, ioapicid, 0x02); /* System Timer */
	smp_write_intsrc(mc, mp_FixINT,     0x0d, 0x1f, 0x16, ioapicid, 0x16); /* SERR */
	smp_write_intsrc(mc, mp_FixINT,     0x0d, 0x1f, 0x09, ioapicid, 0x09); /* gpio 1 */
#ifdef	CONFIG_L_IOH2
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(1, 0),
					ioapicid, 0x0a); /* Ethernet */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(10, 0),
					ioapicid, 0x0c); /* USB */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(10, 1),
					ioapicid, 0x0c); /* USB */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(11, 0),
					ioapicid, 0x0d); /* USB */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(11, 1),
					ioapicid, 0x0d); /* USB */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(2, 0),
					ioapicid, 0x0b); /* IDE */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(2, 0),
					ioapicid, 0x17); /* IDE hidden */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(2, 0),
					ioapicid, 0x0b); /* IDE cable */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(2, 0),
					ioapicid, 0x0b); /* IDE cable */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(2, 1),
					ioapicid, 0x08); /* WD TIMER + gpio 0 */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(2, 1),
					ioapicid, 0x0f); /* I2c/spi */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(2, 2),
					ioapicid, 0x03); /* Serial Port */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(2, 2),
					ioapicid, 0x04); /* Serial Port */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(2, 2),
					ioapicid, 0x07); /* Parallel Port */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(2, 3),
					ioapicid, 0x05); /* AC-97 */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(3, 0),
					ioapicid, 0x14); /* SATA */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x01, PCI_DEVFN(3, 1),
					ioapicid, 0x15); /* SATA */
#else	/* IOHUB version 1 */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x02, PCI_DEVFN(1, 0),
					ioapicid, 0x0a); /* Ethernet */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x03, PCI_DEVFN(1, 0),
					ioapicid, 0x14); /* USB */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x02, PCI_DEVFN(2, 0),
					ioapicid, 0x0b); /* IDE */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x02, PCI_DEVFN(2, 0),
					ioapicid, 0x0d); /* IDE hidden */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x02, PCI_DEVFN(2, 0),
					ioapicid, 0x0e); /* IDE cable */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x02, PCI_DEVFN(2, 0),
					ioapicid, 0x0f); /* IDE cable */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x02, PCI_DEVFN(2, 1),
					ioapicid, 0x08); /* WD TIMER + gpio 0 */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x02, PCI_DEVFN(2, 1),
					ioapicid, 0x17); /* I2c/spi */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x02, PCI_DEVFN(2, 2),
					ioapicid, 0x03); /* Serial Port */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x02, PCI_DEVFN(2, 2),
					ioapicid, 0x04); /* Serial Port */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x02, PCI_DEVFN(2, 2),
					ioapicid, 0x07); /* Parallel Port */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x02, PCI_DEVFN(2, 3),
					ioapicid, 0x05); /* AC-97 */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x02, PCI_DEVFN(3, 0),
					ioapicid, 0x15); /* SATA */
#endif	/* CONFIG_L_IOH2 */
	/* On bus 0 device 0 PCI -> PCIexp bridge pin 2 (intb) */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x01, ioapicid, 0x11); /* IOAPIC IRQ B */

	/* On bus 0 device 1  virtual PCI -> PCI bridge interrupt pin unused */

	/* On bus 2 device 0  PCI -> PCI bridge pin 1 */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x02, 0x00, ioapicid, 0x10); /* IOAPIC IRQ A */

#ifdef	CONFIG_E2K_LEGACY_SIC
	/* Configure embeded IO-APIC */
	smp_write_ioapic(mc, ioapicid + 1, 0x11, E1CP_EMBEDED_IOAPIC_BASE);
	/* IRQ0 - GC2500 level high */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x1f, 0x00, ioapicid + 1, 0x00);
	/* IRQ1 - MGA2 level high */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x1f, 0x01, ioapicid + 1, 0x01);
	/* IRQ2 - PMC level high */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x1f, 0x02, ioapicid + 1, 0x02);
	/* IRQ3 - IIC level high */
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x1f, 0x03, ioapicid + 1, 0x03);
	/* IRQ4 - IOMMU edge high */
	smp_write_intsrc(mc, mp_FixINT, 0x05, 0x1f, 0x04, ioapicid + 1, 0x04);
	/* IRQ5 - WLCC edge high */
	smp_write_intsrc(mc, mp_FixINT, 0x05, 0x1f, 0x05, ioapicid + 1, 0x05);
	/* IRQ6 - SIC edge high */
	smp_write_intsrc(mc, mp_FixINT, 0x05, 0x1f, 0x06, ioapicid + 1, 0x06);
#endif	/* CONFIG_E2K_LEGACY_SIC */
}

void smp_write_ioepic_intsrc_info(struct mpc_table *mc, unsigned int node,
	unsigned int bus, unsigned int ioepicid)
{
	if (node == 0)
		smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH,
			MP_BUS_ISA_NUM, 0, ioepicid,  0); /* IPMB */
	else
		smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH,
			bus, PCI_DEVFN(2, 1), ioepicid, 0); /* IPMB */

	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus,
		PCI_DEVFN(9, 0), ioepicid, 1); /* SCI */

	if (node == 0)
		smp_write_intsrc(mc, mp_FixINT, MP_IRQ_EDGE_HIGH,
			MP_BUS_ISA_NUM, 0, ioepicid, 2); /* System Timer */
	else
		smp_write_intsrc(mc, mp_FixINT, MP_IRQ_EDGE_HIGH,
			bus, PCI_DEVFN(2, 1), ioepicid, 2); /* System Timer */

	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(1, 0),
		ioepicid, 3); /* Ethernet0_tx0 */
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(1, 0),
		ioepicid, 4); /* Ethernet0_tx1 */
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(1, 0),
		ioepicid, 5); /* Ethernet0_rx0 */
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(1, 0),
		ioepicid, 6); /* Ethernet0_rx1 */
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(1, 0),
		ioepicid, 7); /* Ethernet0_sys */

	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(2, 3),
		ioepicid, 8); /* HDA (eioh) */

	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(2, 0),
		ioepicid, 9); /* Mpv_timers0 */
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(2, 0),
		ioepicid, 10); /* Mpv_timers1 */
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(2, 0),
		ioepicid, 11); /* Mpv_timers2 */

	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(2, 0),
		ioepicid, 12); /* GPIO0 */
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(2, 0),
		ioepicid, 13); /* GPIO1 */

	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(2, 2),
		ioepicid, 14); /* Serial port */

	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(2, 1),
		ioepicid, 15); /* I2c/spi */

	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(2, 1),
		ioepicid, 16); /* PCI IRQ A */
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(2, 1),
		ioepicid, 17); /* PCI IRQ B */
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(2, 1),
		ioepicid, 18); /* PCI IRQ C */
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(2, 1),
		ioepicid, 19); /* PCI IRQ D */

	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(2, 1),
		ioepicid, 20); /* WD Timer */

	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(3, 0),
		ioepicid, 21); /* SATA-3 */

	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, MP_BUS_ISA_NUM, 22,
		ioepicid, 22); /* SERR */

	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(1, 1),
		ioepicid, 23); /* Ethernet1_tx0 */
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(1, 1),
		ioepicid, 24); /* Ethernet2_tx1 */
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(1, 1),
		ioepicid, 25); /* Ethernet1_rx0 */
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(1, 1),
		ioepicid, 26); /* Ethernet1_rx1 */
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(1, 1),
		ioepicid, 27); /* Ethernet1_sys */

	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH, bus, PCI_DEVFN(0, 0),
		ioepicid, 28); /* USB */

	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_EDGE_HIGH,  bus,
		PCI_DEVFN(10, 0), ioepicid, 29); /* WLCC */
#ifdef	CONFIG_E2C3
	/* Embedded devices */
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH,  0,
		PCI_DEVFN(26, 0), ioepicid, 32);
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH,  0,
		PCI_DEVFN(26, 1), ioepicid, 33);
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH,  0,
		PCI_DEVFN(26, 2), ioepicid, 34);
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_LEVEL_HIGH,  0,
		PCI_DEVFN(27, 0), ioepicid, 35);
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_EDGE_HIGH,  0,
		PCI_DEVFN(28, 0), ioepicid, 36);
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_EDGE_HIGH,  0,
		PCI_DEVFN(29, 0), ioepicid, 37);
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_EDGE_HIGH,  0,
		PCI_DEVFN(30, 0), ioepicid, 38);
	smp_write_intsrc(mc, mp_FixINT, MP_IRQ_EDGE_HIGH,  0,
		PCI_DEVFN(31, 0), ioepicid, 39);
#endif


}

void *smp_write_config_table(struct intel_mp_floating *mpf,
	unsigned int phys_cpu_num)
{
	int iopic_id = 0;
	static const char sig[4] = "PCMP";
	static const char oem[8] = "LNXI    ";
	static const char productid[12] = "440GX      ";
	struct mpc_table *mc;
	struct bios_pci_dev *dev;
	unsigned int domain, bus;

	mc = (void *)(((char *)mpf) + SMP_FLOATING_TABLE_LEN);
	memset(mc, 0, sizeof(*mc));

	memcpy(mc->mpc_signature, sig, sizeof(sig));
	mc->mpc_length = sizeof(*mc); /* initially just the header */
	mc->mpc_spec = 0x04;
	mc->mpc_checksum = 0; /* not yet computed */
	memcpy(mc->mpc_oem, oem, sizeof(oem));
	memcpy(mc->mpc_productid, productid, sizeof(productid));
	mc->mpc_oemptr = 0;
	mc->mpc_oemsize = 0;
	mc->mpc_oemcount = 0; /* No entries yet... */
	mc->mpc_lapic = LAPIC_ADDR;
	mc->mpe_length = 0;
	mc->mpe_checksum = 0;
	mc->reserved = 0;

	smp_write_processors(mc, phys_cpu_num);
	iopic_id = NR_CPUS /*phys_cpu_num*/;

	smp_write_bus(mc, 0, "PCI   ");
	smp_write_bus(mc, 1, "PCI   ");
	smp_write_bus(mc, 2, "PCI   ");

#ifdef CONFIG_E2K_SIC
	smp_write_bus(mc, 3, "PCI   ");
#endif	/* ! CONFIG_E2K_SIC */
	smp_write_bus(mc, 0x1f, "ISA   ");

#ifdef CONFIG_E2K_SIC
#ifdef CONFIG_EIOH
	rom_printk("MP: Scanning PCI bus for eiohub i2c/spi+ioepic\n");
	dev = NULL;
	do {
		dev = bios_pci_find_device(PCI_VENDOR_ID_MCST_TMP,
				PCI_DEVICE_ID_MCST_I2C_SPI_EPIC, dev);
		if (dev) {
			domain = bios_pci_domain_nr(dev->bus);
			bus = dev->bus->number;
			rom_printk("found on domain %d bus %d "
				"device %d\n",
				domain, bus, PCI_SLOT(dev->devfn));
			smp_write_ioepic_i2c_spi_info(mc, dev, iopic_id);
			smp_write_ioepic_intsrc_info(mc, domain, bus, iopic_id);
			iopic_id++;
		}
	} while (dev);
#endif

	rom_printk("MP: Scanning PCI bus for iohub1 i2c/spi+ioapic\n");
	dev = NULL;
	do {
		dev = bios_pci_find_device(INTEL_MULTIFUNC_VENDOR,
						INTEL_MULTIFUNC_DEVICE, dev);
		if (dev) {
			domain = bios_pci_domain_nr(dev->bus);
			bus = dev->bus->number;
			rom_printk("IOHub found on domain %d bus %d "
				"device %d\n",
				domain, bus, PCI_SLOT(dev->devfn));
			smp_write_ioapic_i2c_spi_info(mc, dev, iopic_id);
			smp_write_ioapic_intsrc_info(mc, domain, bus, iopic_id);
			iopic_id++;
		}
	} while (dev);

	rom_printk("MP: Scanning PCI bus for iohub2 i2c/spi+ioapic\n");
	dev = NULL;
	do {
		dev = bios_pci_find_device(PCI_VENDOR_ID_MCST_TMP,
				PCI_DEVICE_ID_MCST_I2C_SPI, dev);
		if (dev) {
			domain = bios_pci_domain_nr(dev->bus);
			bus = dev->bus->number;
			rom_printk("IOHub-2 found on domain %d bus %d "
				"device %d\n",
				domain, bus, PCI_SLOT(dev->devfn));
			smp_write_ioapic_i2c_spi_info(mc, dev, iopic_id);
			smp_write_ioapic_intsrc_info(mc, domain, bus, iopic_id);
			iopic_id++;
		}
	} while (dev);
#endif

#ifndef CONFIG_EIOH
	/* Standard local interrupt assignments */
	smp_write_lintsrc(mc, mp_ExtINT, 0x05, 0x03, 0x00, MP_APIC_ALL, 0x00); /* local connection pic->ioapic */
	smp_write_lintsrc(mc, mp_NMI,    0x05, 0x00, 0x00, MP_APIC_ALL, 0x01); /* local connection lapic->ioapic */
#endif

	mc->mpe_checksum = smp_compute_checksum(smp_next_mpc_entry(mc), mc->mpe_length);
	mc->mpc_checksum = smp_compute_checksum(mc, mc->mpc_length);
	printk_debug("Wrote the mp table end at: %px - %px\n",
		mc, smp_next_mpe_entry(mc));
	return smp_next_mpe_entry(mc);
}

unsigned int write_smp_table(struct intel_mp_floating *mpf, unsigned int phys_cpu_num)
{
	rom_printk("write_smp_table() will create floating table\n");
	smp_write_floating_table(mpf);
	return (unsigned long)smp_write_config_table(mpf, phys_cpu_num);
}


