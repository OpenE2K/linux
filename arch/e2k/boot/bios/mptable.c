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

#undef BIOS_DEBUG
#define MTABLE_DEBUG 0
#define BIOS_DEBUG MTABLE_DEBUG

#define	E3M_NB_VENDOR			PCI_VENDOR_ID_INTEL
#define	E3M_NB_DEVICE			PCI_DEVICE_ID_INTEL_82443GX_0

#define	E3M_MOTHERBOARD_PETROV		0
#define	E3M_MOTHERBOARD_STUDENTS	1

static void error(char *x)
{
        rom_puts("\n\n");
        rom_puts(x);
        rom_puts("\n\n -- System halted");

        E2K_LMS_HALT_ERROR(0xdead); /* Halt */
}

void *smp_write_config_table(struct intel_mp_floating *mpf, unsigned int phys_cpu_num)
{
	int ioapicid = 0;
	static const char sig[4] = "PCMP";
	static const char oem[8] = "LNXI    ";
	static const char productid[12] = "440GX      ";
	struct mpc_table *mc;
	struct bios_pci_dev *dev;
#ifdef CONFIG_E2K_SIC
	unsigned long timeraddr;
	unsigned int timer_base, timer_upper32;
#endif

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

#ifndef CONFIG_E2K_SIC
	rom_printk("Scanning PCI bus for NorthBridge chip ...");

	dev = bios_pci_find_device(E3M_NB_VENDOR,
				PCI_DEVICE_ID_INTEL_82443GX_0, NULL);
	if (dev == NULL) {
		dev = bios_pci_find_device(E3M_NB_VENDOR,
				PCI_DEVICE_ID_INTEL_82443GX_2, NULL);
	}

	if (dev) {
		rom_printk("found on bus %d device %d\n",
			dev->bus->number, PCI_SLOT(dev->devfn));
		rom_printk("NB subsystem id: %x\n", dev->subsys_id);
	} else {
		rom_printk("!!! NOT FOUND !!!\n");
		error("Hardware failure!");
	}
#endif
	smp_write_processors(mc, phys_cpu_num);
	/* FIXME if number of ioapics is more then one - cycle needed */
	ioapicid = NR_CPUS /*phys_cpu_num*/;

	smp_write_bus(mc, 0, "PCI   ");
	smp_write_bus(mc, 1, "PCI   ");
	smp_write_bus(mc, 2, "PCI   ");

#ifdef CONFIG_E2K_SIC
	smp_write_bus(mc, 3, "PCI   ");
#endif	/* ! CONFIG_E2K_SIC */
	smp_write_bus(mc, 0x1f, "ISA   ");

	smp_write_ioapic(mc, ioapicid, 0x11, 0xfec00000);
#ifdef CONFIG_E2K_SIC
	rom_printk("MP: Scanning PCI bus for ioapic/pic/timer i2c/spi controller ...");
	dev = bios_pci_find_device(E3M_MULTIFUNC_VENDOR, E3M_MULTIFUNC_DEVICE,
					NULL);
	if (dev == NULL) {
		do {
			dev = bios_pci_find_device(PCI_VENDOR_ID_MCST_TMP,
					PCI_DEVICE_ID_MCST_I2C_SPI, dev);
			if (dev) {
				if (bios_pci_domain_nr(dev->bus) != 0)
					continue;
				rom_printk("found on domain %d bus %d "
					"device %d\n",
					bios_pci_domain_nr(dev->bus),
					dev->bus->number,
					PCI_SLOT(dev->devfn));
				break;
			}
		} while (dev);
	}
	if (dev) {
		rom_printk("found on bus %d device %d\n",
			dev->bus->number, PCI_SLOT(dev->devfn));
	}else{
		rom_printk("!!! NOT FOUND !!!\n");
		error("Hardware failure!");
	}
	/* Setting resources for timer to mptable */
	pcibios_read_config_dword(0, dev->bus->number,
				dev->devfn, SYSTEM_TIMER_BASE_ADDRESS, &timer_base);
	pcibios_read_config_dword(0, dev->bus->number, dev->devfn,
				SYSTEM_TIMER_UPPER_ADDRESS, &timer_upper32);
	rom_printk("MP: setting timeraddr to mptable: \n" 
		   "timer_upper32 = 0x%x, timer_base = 0x%x\n",
				timer_upper32, timer_base);
	timeraddr = timer_upper32;
	timeraddr = (timeraddr << 32);
	timeraddr |= timer_base;
	smp_i2c_spi_timer(mc, MP_LT_TYPE, MP_LT_VERSION, MP_LT_FLAGS, timeraddr);	
	/* Setting resources for cmos to mptable */
	smp_i2c_spi_dev(mc, 1, 23, (unsigned long)dev);
#endif
	/* ISA backward compatibility interrupts  */
#ifndef CONFIG_E2K_SIC
	smp_write_intsrc(mc, mp_ExtINT,  0x05, 0x1f, 0x00, ioapicid, 0x00);
	smp_write_intsrc(mc, mp_INT,     0x05, 0x1f, 0x01, ioapicid, 0x01);
	smp_write_intsrc(mc, mp_INT,     0x05, 0x1f, 0x00, ioapicid, 0x02);
	smp_write_intsrc(mc, mp_INT,     0x05, 0x1f, 0x03, ioapicid, 0x03);
	smp_write_intsrc(mc, mp_INT,     0x05, 0x1f, 0x04, ioapicid, 0x04);
	smp_write_intsrc(mc, mp_INT,     0x05, 0x1f, 0x06, ioapicid, 0x06);
	smp_write_intsrc(mc, mp_INT,     0x05, 0x1f, 0x07, ioapicid, 0x07);
	smp_write_intsrc(mc, mp_INT,     0x05, 0x1f, 0x08, ioapicid, 0x08);
	smp_write_intsrc(mc, mp_INT,     0x05, 0x1f, 0x0c, ioapicid, 0x0c);
	smp_write_intsrc(mc, mp_INT,     0x05, 0x1f, 0x0d, ioapicid, 0x0d);
	smp_write_intsrc(mc, mp_INT,     0x05, 0x1f, 0x0e, ioapicid, 0x0e);
	smp_write_intsrc(mc, mp_INT,     0x05, 0x1f, 0x0f, ioapicid, 0x0f);
#else
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
	smp_write_intsrc(mc, mp_FixINT, 0x0d, 0x03, PCI_DEVFN(6, 0),
					ioapicid, 0x15); /* SATA */
#endif	/* CONFIG_L_IOH2 */
	/* On bus 0 device 0 PCI -> PCIexp bridge pin 2 (intb) */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x01, ioapicid, 0x11); /* IOAPIC IRQ B */

	/* On bus 0 device 1  virtual PCI -> PCI bridge interrupt pin unused */

	/* On bus 2 device 0  PCI -> PCI bridge pin 1 */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x02, 0x00, ioapicid, 0x10); /* IOAPIC IRQ A */
#if defined(CONFIG_ES2) && !defined(CONFIG_ADC_DISABLE)
	smp_write_ioapic(mc, ioapicid + 1, 0x11, 0xfec01000);
	smp_write_intsrc(mc, mp_FixINT,     0x0d, 0x01, PCI_DEVFN(1, 0), ioapicid + 1, 0x0a); /* ADC */
	smp_write_intsrc(mc, mp_FixINT,     0x0d, 0x01, PCI_DEVFN(2, 0), ioapicid + 1, 0x17); /* I2c/spi */
#endif /* CONFIG_ES2  && ! CONFIG_ADC_DISABLE */

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
	/* Configure second IO-link */
#endif /* CONFIG_E2K_SIC */

	/* On bus 0 device 1 is the 440GX AGP/PCI bridge to bus 1 */
	/* On bus 1 device f is a DEC PCI bridge to bus 2 */
#if 0
	/* Onboard pci devices */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x30, ioapicid, 0x13); /* onboard SCSI */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x38, ioapicid, 0x15); /* onboard NIC */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x4b, ioapicid, 0x15); /* onboard PIIX4 */

#endif
#ifndef CONFIG_E2K_SIC
	/* AGP/PCI bridge */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x01, 0x14, ioapicid, 0x10); /* IOAPIC IRQ A */

	/* PCI card slots */
	switch(dev->subsys_id)
	{
	case E3M_MOTHERBOARD_STUDENTS:
	/* USB */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x50, ioapicid, 0x13); /* IOAPIC IRQ D */

	/* Slot one is the slot closest to the processor */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x40, ioapicid, 0x11); /* slot 1 B */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x41, ioapicid, 0x12); /* slot 1 C */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x42, ioapicid, 0x13); /* slot 1 D */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x43, ioapicid, 0x10); /* slot 1 A */
	
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x44, ioapicid, 0x13); /* slot 2 D */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x45, ioapicid, 0x10); /* slot 2 A */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x46, ioapicid, 0x11); /* slot 2 B */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x47, ioapicid, 0x12); /* slot 2 C */

	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x48, ioapicid, 0x12); /* slot 3 C */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x49, ioapicid, 0x13); /* slot 3 D */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x4a, ioapicid, 0x10); /* slot 3 A */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x4b, ioapicid, 0x11); /* slot 3 B */

	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x4c, ioapicid, 0x10); /* slot 4 A */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x4d, ioapicid, 0x11); /* slot 4 B */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x4e, ioapicid, 0x12); /* slot 4 C */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x4f, ioapicid, 0x13); /* slot 4 D */
		break;


	case E3M_MOTHERBOARD_PETROV:
	default:
	/* USB */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x1c, ioapicid, 0x13); /* IOAPIC IRQ D */
	
	/* Slot one is the slot closest to the processor */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x44, ioapicid, 0x10); /* slot 1 A */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x45, ioapicid, 0x11); /* slot 1 B */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x46, ioapicid, 0x12); /* slot 1 C */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x47, ioapicid, 0x13); /* slot 1 D */

	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x48, ioapicid, 0x13); /* slot 2 A */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x49, ioapicid, 0x10); /* slot 2 B */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x4a, ioapicid, 0x11); /* slot 2 C */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x4b, ioapicid, 0x12); /* slot 2 D */

	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x4c, ioapicid, 0x12); /* slot 3 A */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x4d, ioapicid, 0x13); /* slot 3 B */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x4e, ioapicid, 0x10); /* slot 3 C */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x4f, ioapicid, 0x11); /* slot 3 D */

	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x50, ioapicid, 0x11); /* slot 4 A */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x51, ioapicid, 0x12); /* slot 4 B */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x52, ioapicid, 0x13); /* slot 4 C */
	smp_write_intsrc(mc, mp_INT,     0x0f, 0x00, 0x53, ioapicid, 0x10); /* slot 4 D */
		break;
	}
#endif

	/* Standard local interrupt assignments */
	smp_write_lintsrc(mc, mp_ExtINT, 0x05, 0x03, 0x00, MP_APIC_ALL, 0x00); /* local connection pic->ioapic */
	smp_write_lintsrc(mc, mp_NMI,    0x05, 0x00, 0x00, MP_APIC_ALL, 0x01); /* local connection lapic->ioapic */

	/* The following information in the extension section linux doesn't currnetly need
	 * and has just been copied from the bios for now.
	 */
#if 0
	smp_write_address_space(mc, 0x00, ADDRESS_TYPE_IO,       0x00000000, 0, 0x00010000, 0);
	smp_write_address_space(mc, 0x00, ADDRESS_TYPE_MEM,      0x08000000, 0, 0xee000000, 0);
	smp_write_address_space(mc, 0x00, ADDRESS_TYPE_PREFETCH, 0xf6000000, 0, 0x06000000, 0);
	smp_write_address_space(mc, 0x00, ADDRESS_TYPE_MEM,      0xfc000000, 0, 0x02e00000, 0);
	smp_write_address_space(mc, 0x00, ADDRESS_TYPE_MEM,      0xfef00000, 0, 0x01100000, 0);
	smp_write_address_space(mc, 0x00, ADDRESS_TYPE_MEM,      0x000a0000, 0, 0x00200000, 0);
	smp_write_address_space(mc, 0x00, ADDRESS_TYPE_MEM,      0x000d4000, 0, 0x00014000, 0);
	
	smp_write_bus_hierarchy(mc, 0x03, BUS_SUBTRACTIVE_DECODE, 0x00);

	smp_write_compatibility_address_space(mc, 0x00, ADDRESS_RANGE_ADD, RANGE_LIST_IO_ISA);
	smp_write_compatibility_address_space(mc, 0x00, ADDRESS_RANGE_ADD, RANGE_LIST_IO_VGA);
#endif
	mc->mpe_checksum = smp_compute_checksum(smp_next_mpc_entry(mc), mc->mpe_length);
	mc->mpc_checksum = smp_compute_checksum(mc, mc->mpc_length);
	printk_debug("Wrote the mp table end at: %p - %p\n",
		mc, smp_next_mpe_entry(mc));
	return smp_next_mpe_entry(mc);
}

unsigned int write_smp_table(struct intel_mp_floating *mpf, unsigned int phys_cpu_num)
{
	rom_printk("write_smp_table() will create floating table\n");
	smp_write_floating_table(mpf);
	return (unsigned long)smp_write_config_table(mpf, phys_cpu_num);
}


