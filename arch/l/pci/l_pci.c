/*
 *    Low-Level PCI Support for Elbrus E3S
 *
 */
#include <linux/pci.h>
#include "pci.h"
#include <linux/pci_ids.h>
#include <asm/io.h>

#undef __KERNEL__

/**************************** DEBUG DEFINES *****************************/
#undef	DEBUG_PCI_MODE
#undef	DebugPCI
#define	DEBUG_PCI_MODE		0	/* PCI init */
#define	DebugPCI		if (DEBUG_PCI_MODE) printk
/************************************************************************/


/*
 * Direct access to PCI hardware...
 */

/*
 * Functions for accessing PCI configuration space
 */

static inline int
l_pci_read_config_byte(unsigned int domain, unsigned int bus, 
				int devfn, int where, u8 *value)
{
	conf_inb(domain, bus, CONFIG_CMD(bus, devfn, where), value);
	DebugPCI("l_pci_read_config_byte: domain %d, bus %d, devfn %d,"
		"where %d read value 0x%x\n",
		domain, bus, devfn, where, *value);
	return 0;
}

static inline int
l_pci_read_config_word(unsigned int domain, unsigned int bus, 
				int devfn, int where, u16 *value)
{
	conf_inw(domain, bus, CONFIG_CMD(bus, devfn, where), value);
	DebugPCI("l_pci_read_config_word: domain %d, bus %d, devfn %d,"
		"where %d read value 0x%x\n",
		domain, bus, devfn, where, *value);
	return 0;
}

static inline int
l_pci_read_config_dword(unsigned int domain, unsigned int bus, 
				int devfn, int where, u32 *value)
{
	conf_inl(domain, bus, CONFIG_CMD(bus, devfn, where), value);
	DebugPCI("l_pci_read_config_dword: domain %d, bus %d, devfn %d,"
		"where %d read value 0x%x\n",
		domain, bus, devfn, where, *value);
	return 0;
}


static inline int
l_pci_write_config_byte(unsigned int domain, unsigned int bus, 
				int devfn, int where, u8 value)
{
	conf_outb(domain, bus, CONFIG_CMD(bus, devfn, where), value);
	DebugPCI("l_pci_write_config_byte: domain %d, bus %d, devfn %d,"
		"where %d write value 0x%x\n",
		domain, bus, devfn, where, value);
	return 0;
}

static inline int
l_pci_write_config_word(unsigned int domain, unsigned int bus, 
				int devfn, int where, u16 value)
{
	conf_outw(domain, bus, CONFIG_CMD(bus, devfn, where), value);
	DebugPCI("l_pci_write_config_word: domain %d, bus %d, devfn %d,"
		"where %d write value 0x%x\n",
		domain, bus, devfn, where, value);
	return 0;
}

static inline int
l_pci_write_config_dword(unsigned int domain, unsigned int bus, int devfn, 
				int where, u32 value)
{
	conf_outl(domain, bus, CONFIG_CMD(bus, devfn, where), value);
	DebugPCI("l_pci_write_config_dword: domain %d, bus %d, devfn %d, "
		"where %d write value 0x%x\n",
		domain, bus, devfn, where, value);
	return 0;
}

static int
l_pci_read(unsigned int domain, unsigned int bus,
		unsigned int devfn, int reg, int len, u32 *value)
{
	unsigned long flags;
	u16 tmp16;
	u8 tmp8;

	if (!value || (bus > 0xff) || (devfn > 0xff) || (reg > 0xfff))
		return -EINVAL;

	raw_spin_lock_irqsave(&pci_config_lock, flags);

	switch (len) {
	case 1:
		l_pci_read_config_byte(domain, bus, devfn, reg, &tmp8);
		*value = (u32)tmp8;
		break;
	case 2:
		l_pci_read_config_word(domain, bus, devfn, reg, &tmp16);
		*value = (u32)tmp16;
		break;
	case 4:
		l_pci_read_config_dword(domain, bus, devfn, reg, value);
		break;
	}

	raw_spin_unlock_irqrestore(&pci_config_lock, flags);

	return 0;
}

static int
l_pci_write(unsigned int domain, unsigned int bus,
		  unsigned int devfn, int reg, int len, u32 value)
{
	unsigned long flags;

	if ((bus > 0xff) || (devfn > 0xff) || (reg > 0xfff))
		return -EINVAL;

	raw_spin_lock_irqsave(&pci_config_lock, flags);

	switch (len) {
	case 1:
		l_pci_write_config_byte(domain, bus, devfn, reg, (u8)value);
		break;
	case 2:
		l_pci_write_config_word(domain, bus, devfn, reg, (u16)value);
		break;
	case 4:
		l_pci_write_config_dword(domain, bus, devfn, reg, value);
		break;
	}

	raw_spin_unlock_irqrestore(&pci_config_lock, flags);

	return 0;
}

struct pci_raw_ops l_pci_direct_ops = {
	.read =		l_pci_read,
	.write =	l_pci_write,
};

int __init
pci_check_type_l(void)
{
	if (!HAS_MACHINE_L_SIC)
		return (0);

	raw_pci_ops = &l_pci_direct_ops;

	return (1);
}

