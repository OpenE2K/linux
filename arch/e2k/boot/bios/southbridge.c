/*
 * $Id: southbridge.c,v 1.18 2009/02/24 15:14:04 atic Exp $
 */

#include <linux/pci.h>
#include <linux/pci_ids.h>

#include "../boot_io.h"

#include <asm/e2k_debug.h>
#include <asm/e2k.h>
#include <asm/timer.h>
#include <asm/sic_regs.h>
#include <asm/l_timer.h>

#include "pci_isa_config.h"
#include "ide_config.h"
#include "southbridge.h"
#include "mc146818rtc.h"
#include "pci.h"

#define DEBUG_IOSB		1
#define DebugSB	if (DEBUG_IOSB) rom_printk

extern volatile unsigned long	phys_node_pres_map;
extern int			phys_node_num;
extern volatile unsigned long	online_iohubs_map;
extern int			online_iohubs_num;
extern volatile unsigned long	possible_iohubs_map;
extern int			possible_iohubs_num;

int SB_bus, SB_device;

#ifdef CONFIG_E2K_SIC
# define E2K_IO_APIC_AREA_PHYS_BASE	0x00000000fec00000UL
static void configure_iohub_apic(int domain)
{
	struct bios_pci_dev *dev = NULL;
	unsigned int ioapic_base, ioapic_upper32;
#ifndef	CONFIG_BOOT_EPIC
	unsigned int lapic_base, lapic_upper32;
#ifdef	CONFIG_E2K_FULL_SIC
	unsigned int sapic_base;
	unsigned int sapic_upper32;
#endif	/* CONFIG_E2K_FULL_SIC */
#endif
	unsigned long tmp;
	
	rom_printk("Scanning PCI domain %d bus for ioapic/pic/timer i2c/spi "
		"controller ...", domain);
	do {
		dev = bios_pci_find_device(INTEL_MULTIFUNC_VENDOR,
						INTEL_MULTIFUNC_DEVICE, dev);
		if (dev) {
			if (bios_pci_domain_nr(dev->bus) != domain)
				continue;
			rom_printk("found on domain %d bus %d device %d\n",
				bios_pci_domain_nr(dev->bus), dev->bus->number,
				PCI_SLOT(dev->devfn));
			break;
		}
	} while (dev);
	if (dev == NULL) {
		do {
			dev = bios_pci_find_device(PCI_VENDOR_ID_MCST_TMP,
					PCI_DEVICE_ID_MCST_I2C_SPI, dev);
			if (dev) {
				if (bios_pci_domain_nr(dev->bus) != domain)
					continue;
				rom_printk("found on domain %d bus %d "
					"device %d\n",
					bios_pci_domain_nr(dev->bus),
					dev->bus->number,
					PCI_SLOT(dev->devfn));
				break;
			}
		} while (dev);
		if (dev == NULL) {
			rom_printk("!!! NOT FOUND !!!\n");
			return;
		}
	}

	/* configure configuration space for ioapic on domain */
	ioapic_base = E2K_IO_APIC_AREA_PHYS_BASE + domain * 0x1000;
	DebugSB("configure_apic_system: --> to i2c & scrb (iohub)\n"
		"ioapic_upper32 = 0x%x, ioapic_base = 0x%x\n",
		0, ioapic_base);
	pcibios_write_config_dword(domain, dev->bus->number, dev->devfn,
			IOAPIC_BASE_ADDRESS, ioapic_base);
	pcibios_write_config_dword(domain, dev->bus->number, dev->devfn,
			IOAPIC_UPPER_ADDRESS, 0);
	system_commutator_e2s_ioh_write_dword(domain, dev->bus->number,
				A2_BA0, ioapic_base);
	system_commutator_e2s_ioh_write_dword(domain, dev->bus->number,
				A2_BUA0, 0);

/* LAPICINT and SAPICINT should not be written on EPIC systems */
#ifndef	CONFIG_BOOT_EPIC
#ifdef	CONFIG_E2K_FULL_SIC
	/* configure configuration space for sapic on BSP */
#if	defined(CONFIG_E2S)
	tmp = E2S_SAPICINT_BASE + (domain * APICINT_SIZE);
#elif	defined(CONFIG_E8C) || defined(CONFIG_E8C2)
	tmp = E8C_SAPICINT_BASE + (domain * (APICINT_SIZE));
#elif	defined(CONFIG_E12C)
	tmp = E12C_SAPICINT_BASE + (domain * (APICINT_SIZE));
#elif	defined(CONFIG_E16C)
	tmp = E16C_SAPICINT_BASE + (domain * (APICINT_SIZE));
#elif	defined(CONFIG_E2C3)
	tmp = E2C3_SAPICINT_BASE + (domain * (APICINT_SIZE));
#else
 #error	"Invalid e2k machine type"
#endif	/* CONFIG_E2S */
	sapic_base = tmp & 0xffffffff;
	sapic_upper32 = (tmp >> 32) & 0xffffffff;
	DebugSB("configure_apic_system: --> to i2c & scrb (iohub)\n" 
		"sapic_message_upper32  = 0x%x, sapic_message_base  = 0x%x\n",
		sapic_upper32, sapic_base);
	pcibios_write_config_dword(domain, dev->bus->number, dev->devfn,
				MSI_TRANSACTION_ADDRESS, sapic_base);
	pcibios_write_config_dword(domain, dev->bus->number, dev->devfn,
				MSI_TRANSACTION_UPPER_ADDRESS, sapic_upper32);
	system_commutator_e2s_ioh_write_dword(domain, dev->bus->number, A2_BA1,
						sapic_base);
	system_commutator_e2s_ioh_write_dword(domain, dev->bus->number, A2_BUA1,
						sapic_upper32);
#endif	/* CONFIG_E2K_FULL_SIC */
	/* configure configuration space for lapic on BSP */
#if	defined(CONFIG_E2S)
	tmp = E2S_LAPICINT_BASE + (domain * APICINT_SIZE);
#elif	defined(CONFIG_E8C) || defined(CONFIG_E8C2)
	tmp = E8C_LAPICINT_BASE + (domain * (APICINT_SIZE));
#elif	defined(CONFIG_E1CP)
	tmp = E1CP_LAPICINT_BASE + (domain * (APICINT_SIZE));
#elif	defined(CONFIG_E12C) 
	tmp = E12C_LAPICINT_BASE + (domain * (APICINT_SIZE));
#elif	defined(CONFIG_E16C) 
	tmp = E16C_LAPICINT_BASE + (domain * (APICINT_SIZE));
#elif	defined(CONFIG_E2C3) 
	tmp = E2C3_LAPICINT_BASE + (domain * (APICINT_SIZE));
#else
 #error	"Invalid e2k machine type"
#endif	/* CONFIG_E2S */
	lapic_base = tmp & 0xffffffff;
	lapic_upper32 = (tmp >> 32) & 0xffffffff;
	DebugSB("configure_apic_system: --> to i2c & scrb (iohub)\n"
		"lapic_message_upper32  = 0x%x, lapic_message_base  = 0x%x\n",
		lapic_upper32, lapic_base);
#ifdef	CONFIG_E2K_LEGACY_SIC
	early_sic_write_node_nbsr_reg(0, SIC_rt_lapicintb, tmp >> 12);
	DebugSB("configure_apic_system: NBSR lapicint base  = 0x%x\n",
		early_sic_read_node_nbsr_reg(0, SIC_rt_lapicintb));
#endif	/* CONFIG_E2K_LEGACY_SIC */
	pcibios_write_config_dword(domain, dev->bus->number, dev->devfn,
				LAPIC_MESSAGE_BASE_ADDRESS, lapic_base);
	pcibios_write_config_dword(domain, dev->bus->number, dev->devfn,
				LAPIC_MESSAGE_UPPER_ADDRESS, lapic_upper32);
#endif
	
	/* configure configuration space for ioapic on BSP */
#if	defined(CONFIG_E2S)
	tmp = E2S_IOAPICINT_BASE + (domain * APICINT_SIZE);
#elif	defined(CONFIG_E8C) || defined(CONFIG_E8C2)
	tmp = E8C_IOAPICINT_BASE + (domain * (APICINT_SIZE));
#elif	defined(CONFIG_E1CP)
	tmp = E1CP_IOAPICINT_BASE + (domain * (APICINT_SIZE));
#elif	defined(CONFIG_E12C)
	tmp = E12C_IOAPICINT_BASE + (domain * (APICINT_SIZE));
#elif	defined(CONFIG_E16C)
	tmp = E16C_IOAPICINT_BASE + (domain * (APICINT_SIZE));
#elif	defined(CONFIG_E2C3)
	tmp = E2C3_IOAPICINT_BASE + (domain * (APICINT_SIZE));
#else
 #error	"Invalid e2k machine type"
#endif	/* CONFIG_E2S */
	ioapic_base = tmp & 0xffffffff;
	ioapic_upper32 = (tmp >> 32) & 0xffffffff;
	DebugSB("configure_apic_system: --> to i2c\n"
		"ioapic_message_upper32 = 0x%x, ioapic_message_base = 0x%x\n",
		ioapic_upper32, ioapic_base);
#ifdef	CONFIG_E2K_LEGACY_SIC
	early_sic_write_node_nbsr_reg(0, SIC_rt_ioapicintb, tmp >> 12);
	DebugSB("configure_apic_system: NBSR ioapicint base  = 0x%x\n",
		early_sic_read_node_nbsr_reg(0, SIC_rt_ioapicintb));
#endif	/* CONFIG_E2K_LEGACY_SIC */
	system_commutator_e2s_ioh_write_dword(domain, dev->bus->number,
				A2_BA2, ioapic_base);
	system_commutator_e2s_ioh_write_dword(domain, dev->bus->number,
				A2_BUA2, ioapic_upper32);
	pcibios_write_config_dword(domain, dev->bus->number, dev->devfn,
				IOAPIC_MESSAGE_BASE_ADDRESS, ioapic_base);
	pcibios_write_config_dword(domain, dev->bus->number, dev->devfn,
				IOAPIC_MESSAGE_UPPER_ADDRESS, ioapic_upper32);
}
#ifdef	CONFIG_E2K_LEGACY_SIC
void configure_embeded_apic(void)
{
	unsigned long ioapic_base;
	unsigned int hb_cfg;

	/* configure configuration space for ioapic: */
	/* embeded IOAPIC always is #1 */
	ioapic_base = E1CP_EMBEDED_IOAPIC_BASE;
	early_writell_hb_reg(ioapic_base, HB_PCI_IOAPICBASE);
	rom_printk("set embeded ioapic base to 0x%X\n",
		early_readll_hb_reg(HB_PCI_IOAPICBASE));
	/* enable embeded IOAPIC and IRQs at host bridge CFG */
	hb_cfg = early_readl_hb_reg(HB_PCI_CFG);
	DebugSB("configure_embeded_apic: host bridge CFG 0x%08x\n",
		hb_cfg);
	hb_cfg |= HB_CFG_InternalIoApicEnable;
	hb_cfg |= (HB_CFG_MaskIntSic | HB_CFG_MaskIntWlcc |
			HB_CFG_MaskIntIommu);
	hb_cfg &= ~HB_CFG_ShareHostInterrupts;
	early_writel_hb_reg(hb_cfg, HB_PCI_CFG);
	rom_printk("host bridge CFG: enable embeded IOAPIC AND IRQs 0x%X\n",
		early_readl_hb_reg(HB_PCI_CFG));
}
#endif	/* CONFIG_E2K_LEGACY_SIC */

void configure_pic_system(void)
{
	int domain;

	for (domain = 0; domain < MAX_NUMIOHUBS; domain ++) {
		if (!(online_iohubs_map & (1 << domain)))
			continue;
		configure_iohub_apic(domain);
	}
#ifdef	CONFIG_E2K_LEGACY_SIC
	configure_embeded_apic();
#endif	/* CONFIG_E2K_LEGACY_SIC */
}

#define ONEMEG (1 << 20)
/** round a number to an alignment. 
 * @param val the starting value
 * @param roundup Alignment as a power of two
 * @returns rounded up number
 */
extern unsigned long round(unsigned long val, unsigned long roundup);

static void configure_iohub_system_timer(int domain)
{
	struct bios_pci_dev *dev;
	unsigned int timer_base, timer_upper32;
	wd_control_t	wd_control;
	unsigned long addr = 0;

	DebugSB("start configure_system_timer\n");
	rom_printk("Scanning PCI #%d bus for ioapic/pic/timer i2c/spi controller ...",
		domain);
	dev = bios_pci_find_device(INTEL_MULTIFUNC_VENDOR,
					INTEL_MULTIFUNC_DEVICE, NULL);
	if (dev == NULL) {
		do {
			dev = bios_pci_find_device(PCI_VENDOR_ID_MCST_TMP,
					PCI_DEVICE_ID_MCST_I2C_SPI, dev);
			if (dev) {
				if (bios_pci_domain_nr(dev->bus) != domain)
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
	if (dev && bios_pci_domain_nr(dev->bus) == domain) {
		rom_printk("found on bus %d device %d\n",
			dev->bus->number, PCI_SLOT(dev->devfn));
	} else {
		rom_printk("!!! NOT FOUND !!!\n");
		return;
	}

	/* configure configuration space for timer on BSP */
	timer_base = round(pci_root[0].prefmemlimit, ONEMEG);
	timer_upper32 = 0;
	DebugSB("configure_system_timer:\n"
		"timer_upper32 = 0x%x, timer_base = 0x%x\n",
		timer_upper32, timer_base);
	pcibios_write_config_dword(domain, dev->bus->number, dev->devfn,
				SYSTEM_TIMER_BASE_ADDRESS, timer_base);
	pcibios_write_config_dword(domain, dev->bus->number, dev->devfn,
				SYSTEM_TIMER_UPPER_ADDRESS, timer_upper32); 
	system_commutator_e2s_ioh_write_dword(domain, dev->bus->number,
				A3_BA0, timer_base);
	system_commutator_e2s_ioh_write_dword(domain, dev->bus->number,
				A3_BUA0, timer_upper32);
	/* Disable WD timer */
	AS_WORD(wd_control) = 0;
	addr = timer_base + WD_CONTROL;
	AS_WORD(wd_control) = NATIVE_READ_MAS_W(addr, MAS_IOADDR);
	if (AS_STRUCT(wd_control).w_out_e){
		DebugSB("configure_system_timer: wd timer found to be enabled.\n");
		DebugSB("configure_system_timer: Set wd timer to disable mode\n");
		AS_STRUCT(wd_control).w_out_e = 0;
		AS_STRUCT(wd_control).w_m = 1; /* Interrupt mode  */
		NATIVE_WRITE_MAS_W(addr, AS_WORD(wd_control), MAS_IOADDR);
	}
}	

void configure_system_timer(void)
{
	int domain;

	for (domain = 0; domain < MAX_NUMIOHUBS; domain ++) {
		if (!(online_iohubs_map & (1 << domain)))
			continue;
		configure_iohub_system_timer(domain);
	}
}

#endif

void sb_enable_rtc(void)
{
	int xdata;
	
	rom_printk("southbridge enable rtc ...\n");
	
	xdata = SB_read_config32(SB_GENCFG, 0);
	xdata |= SB_GENCFG_SIGNAL_PIN_SELECTED14;
	SB_write_config32(xdata, SB_GENCFG, 0);
	
	DebugSB("GENCFG = 0x%x\n",
			SB_read_config32(SB_GENCFG, 0));

	rtc_init(0);
}

void sb_enable_ide(void)
{
	int xdata;
	
	rom_printk("southbridge enable ide ...\n");
	
	xdata = SB_read_config32(SB_IDETIM, 1);
	xdata |= ((SB_IDETIM_DECODE_ENABLE << SB_IDETIM_SHIFT) |
			SB_IDETIM_DECODE_ENABLE);
	SB_write_config32(xdata, SB_IDETIM, 1);
	
	DebugSB("IDETIM = 0x%x\n",
			SB_read_config32(SB_IDETIM, 1));

	xdata = SB_read_config16(SB_PCICMD, 1);
	xdata |= SB_PCICMD_IOSE;
	SB_write_config32(xdata, SB_PCICMD, 1);
	
	DebugSB("PCICMD = 0x%x\n",
			SB_read_config16(SB_PCICMD, 1) & 0xffff);
}
