/*
 *    $Id: linuxpci.c,v 1.10 2008/05/23 20:26:35 alexmipt Exp $
 *
 *      PCI Bus Services, see include/linux/pci.h for further explanation.
 *
 *      Copyright 1993 -- 1997 Drew Eckhardt, Frederic Potter,
 *      David Mosberger-Tang
 *
 *      Copyright 1997 -- 1999 Martin Mares <mj@atrey.karlin.mff.cuni.cz>
 */

#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/types.h>
#include <asm/e2k_api.h>
#include "asm/string.h"
#include <asm/cpu_regs_access.h>
#include <asm/head.h>
#include "pci.h"

#define	GCC_WORKS_ON_O2		0

/**************************** DEBUG DEFINES *****************************/
#undef	DEBUG_BOOT_MODE
#undef	Dprintk
#define	DEBUG_BOOT_MODE		0	/* PCI scanning */
#define	Dprintk			if (DEBUG_BOOT_MODE) rom_printk

#undef DEBUG_VERBOSE_BOOT_MODE
#undef VDprintk
#define	DEBUG_VERBOSE_BOOT_MODE	0       /* verbose PCI scanning */
#define	VDprintk		if (DEBUG_VERBOSE_BOOT_MODE) rom_printk
/************************************************************************/


/**
 * This is the root of the PCI tree. A PCI tree always has 
 * one bus, bus 0. Bus 0 contains devices and bridges. 
 */
struct bios_pci_bus pci_root[MAX_NUMIOHUBS];
int pci_root_num = 0;
/// Linked list of PCI devices. ALL devices are on this list 
struct bios_pci_dev *pci_devices = 0;
/// pointer to the last device */
static struct bios_pci_dev **pci_last_dev_p = &pci_devices;
/// We're going to probably delete this -- flag to add in reverse order */
static int pci_reverse = 0;

/**
 * Given a bus and a devfn number, find the device structure
 * @param bus The bus number
 * @param devfn a device/function number
 * @return pointer to the device structure
 */
struct bios_pci_dev *pci_find_slot(unsigned int bus, unsigned int devfn)
{
	struct bios_pci_dev *dev;

	for (dev = pci_devices; dev; dev = dev->next)
		if (dev->bus->number == bus && dev->devfn == devfn)
			break;
	return dev;
}

/** Find a device of a given vendor and type
 * @param vendor Vendor ID (e.g. 0x8086 for Intel)
 * @param device Device ID
 * @param from Pointer to the device structure, used as a starting point
 *        in the linked list of devices, which can be 0 to start at the 
 *        head of the list (i.e. pci_devices)
 * @return Pointer to the device struct 
 */
struct bios_pci_dev *bios_pci_find_device(unsigned int vendor,
			unsigned int device, struct bios_pci_dev *from)
{
	if (!from)
		from = pci_devices;
	else
		from = from->next;
	while (from && (from->vendor != vendor || from->device != device))
		from = from->next;
	return from;
}

/** Find a device of a given class
 * @param class Class of the device
 * @param from Pointer to the device structure, used as a starting point
 *        in the linked list of devices, which can be 0 to start at the 
 *        head of the list (i.e. pci_devices)
 * @return Pointer to the device struct 
 */
struct bios_pci_dev *pci_find_class(unsigned int class,
					struct bios_pci_dev *from)
{
	if (!from)
		from = pci_devices;
	else
		from = from->next;
	while (from && from->class != class)
		from = from->next;
	return from;
}

/** Given a device, set the PCI_COMMAND_MASTER bit in the command register
 * @param dev Pointer to the device structure
 */
void bios_pci_set_master(struct bios_pci_dev *dev)
{
	u16 cmd;
	u8 lat;

	bios_pci_read_config_word(dev, PCI_COMMAND, &cmd);
	if (!(cmd & PCI_COMMAND_MASTER)) {
		printk_debug("PCI: Enabling bus mastering for device %02x:%02x\n",
		       dev->bus->number, dev->devfn);
		cmd |= PCI_COMMAND_MASTER;
		bios_pci_write_config_word(dev, PCI_COMMAND, cmd);
	}
	bios_pci_read_config_byte(dev, PCI_LATENCY_TIMER, &lat);
	if (lat < 16) {
		printk_debug("PCI: Increasing latency timer of device %02x:%02x to 64\n",
		       dev->bus->number, dev->devfn);
		bios_pci_write_config_byte(dev, PCI_LATENCY_TIMER, 64);
	}
}

/** Given a device and register, read the size of the BAR for that register. 
 * @param dev Pointer to the device structure
 * @param reg Which register to use
 * @param addr Address to load into the register after size is found
 */
void pci_get_size(struct bios_pci_dev *dev, unsigned long reg,
						unsigned long addr)
{
	u32 size;
	unsigned long type;

	/* FIXME: more consideration for 64-bit PCI devices */
	// get the size
	bios_pci_write_config_dword(dev, PCI_BASE_ADDRESS_0 + (reg << 2), ~0);
	bios_pci_read_config_dword(dev, PCI_BASE_ADDRESS_0 + (reg << 2),
					&size);

	// restore addr
	bios_pci_write_config_dword(dev, PCI_BASE_ADDRESS_0 + (reg << 2),
					addr);

	// some broken hardware has read-only registers that do not 
	// really size correctly. You can tell this if addr == size
	// Example: the acer m7229 has BARs 1-4 normally read-only. 
	// so BAR1 at offset 0x10 reads 0x1f1. If you size that register
	// by writing 0xffffffff to it, it will read back as 0x1f1 -- a 
	// violation of the spec. 
	// We catch this case and ignore it by settting size and type to 0.
	// This incidentally catches the common case where registers 
	// read back as 0 for both address and size. 

#if 0 /* DON'T WORk on E2K */
	if (addr == size) {
		printk_debug(
			"pci_get_size: dev_fn 0x%x, register %d, read-only"
			" SO, ignoring it\n",
			dev->devfn, reg);
		printk_debug("addr was 0x%x, size was 0x%x\n",addr,size); 
		type = 0;
         	size = 0;
         }
	// Now compute the actual size, See PCI Spec 6.2.5.1 ... 
         else
#endif
	if (size & PCI_BASE_ADDRESS_SPACE_IO) {
		type = size & (~PCI_BASE_ADDRESS_IO_MASK);
		size &= (PCI_BASE_ADDRESS_IO_MASK);
		// BUG! Top 16 bits can be zero (or not) 
		// So set them to 0xffff so they go away ...
		size |= 0xffff0000;
		size = ~size;
		size++;
	} else {
		type = size & (~PCI_BASE_ADDRESS_MEM_MASK);
		size &= (PCI_BASE_ADDRESS_MEM_MASK);
		size = ~size;
		size++;
	}
	dev->size[reg] = size | type;
	Dprintk("BAR%d = %x (size %x, type %x)\n",
			reg, size | type, size, type);
}

/** Read the base address registers for a given device. 
 * @param dev Pointer to the dev structure
 * @param howmany How many registers to read (6 for device, 2 for bridge)
 */
void pci_read_bases(struct bios_pci_dev *dev, unsigned int howmany)
{
	unsigned int reg;
	u32 /* unsigned long for 64 bits ?? */ addr;

	/* FIXME: to deal with 64-bits PCI */
	Dprintk("pci_read_bases bus 0x%x, devfn 0x%x\n",
		dev->bus->number, dev->devfn);
	for (reg = 0; reg < howmany; reg++) {
		bios_pci_read_config_dword(dev, PCI_BASE_ADDRESS_0 + (reg << 2),
			&addr);
		if (addr == 0xffffffff)
			continue;

		/* get address space size */
		pci_get_size(dev, reg, addr);

		addr &= (PCI_BASE_ADDRESS_SPACE |
				PCI_BASE_ADDRESS_MEM_TYPE_MASK);
		if (addr == (PCI_BASE_ADDRESS_SPACE_MEMORY |
					PCI_BASE_ADDRESS_MEM_TYPE_64)) {
			printk_debug("reg %d is 64-bit\n", reg);
			/* this is a 64-bit memory base address */
			reg++;
			bios_pci_read_config_dword(dev,
				PCI_BASE_ADDRESS_0 + (reg << 2), &addr);
			if (addr) {
#if BITS_PER_LONG == 64
				dev->base_address[reg - 1] |=
					((unsigned long) addr) << 32;
#else
				printk_err("PCI: Unable to handle 64-bit "
					"address for device %02x:%02x\n",
					dev->bus->number, dev->devfn);
				dev->base_address[reg - 1] = 0;
#endif
			}
		}
	}
}

/*
 * Find the extent of a PCI decode..
 */
static unsigned int pci_size(unsigned int base, unsigned int maxbase, unsigned long mask)
{
	unsigned int size = mask & maxbase;	/* Find the significant bits */
	if (!size)
		return 0;

//	Dprintk("pci_size: base = %x maxbase = %x\n", base, maxbase);

	/* Get the lowest of them to find the decode size, and
	   from that the extent.  */
	size = (size & ~(size-1)) ; /* - 1; NEEDSWORK: Linar */

	/* base == maxbase can be valid only if the BAR has
	   already been programmed with all 1s.  */
	if (base == maxbase && ((base | size) & mask) != mask)
		return 0;

	return size;
}

#ifdef CONFIG_E2K_SIC
/* That means the level of buses hierarchy. The 0 level means the main bus called 
*  the pci_root. The main bus may has several subbuses due to the CPU amount.
*  Each system on CPU has its own PCI2PCI bridge that serves the link between
*  the main bus pci_root and other devices chiped in that system on CPU. So each 
*  system has its own configuration space.  */
int level = -1; 
#endif

/** Scan the bus, first for bridges and next for devices. 
 * @param bios_pci_bus pointer to the bus structure
 * @return The maximum bus number found, after scanning all subordinate busses
 */
static unsigned int bios_pci_scan_bus(struct bios_pci_bus *bus)
{
	unsigned int devfn, max;
	struct bios_pci_dev *dev, **bus_last;
	struct bios_pci_bus *child;
	int domain = bios_pci_domain_nr(bus);
#if 0
	unsigned int  msg_st[2], msg_end[2];
	unsigned long start, end;
#endif
#ifdef CONFIG_E2K_SIC
	/* Each time we enter the bios_pci_scan_bus function we must to
	 * encrease the bus hierarchy level */
	level++;
	Dprintk("PCI #%d: bios_pci_scan_bus enter for level %d\n",
		domain, level);
#endif
	Dprintk("PCI #%d: bios_pci_scan_bus for bus %d\n",
		domain, bus->number);

	bus_last = &bus->devices;
	max = bus->secondary;

	/* probe all devices on this bus with some optimization for non-existance and 
	   single funcion devices */
	for (devfn = 0; devfn < 0xff; devfn++) {
		u32 id, class, addr, size;
		u8 cmd, tmp, hdr_type;
		u16 subsystem;
#if 0
		u32 tmphdr;
#endif	/* 0 */
		// gcc just went to hell. Don't test -- this always
		// returns 0 anyway. 
#if GCC_WORKS_ON_O2
		if (pcibios_read_config_dword(domain, bus->number, devfn, PCI_VENDOR_ID, &id)) {
		   printk_spew("PCI #%d: devfn 0x%x, read_config_dword fails\n",
				domain, devfn);
		    continue;
		}
#endif
		pcibios_read_config_dword(domain, bus->number, devfn, PCI_VENDOR_ID, &id);

		/* some broken boards return 0 if a slot is empty: */
		if (id == 0xffffffff || id == 0x00000000 || id == 0x0000ffff || id == 0xffff0000) {
			VDprintk("PCI #%d: devfn 0x%x, bad id 0x%x\n",
				domain, devfn, id);
			if (PCI_FUNC(devfn) == 0x00) {
				/* if this is a function 0 device and it is not present,
				   skip to next device */
				devfn += 0x07;
			}
			/* multi function device, skip to next function */
			continue;
		}
		if (pcibios_read_config_byte(domain, bus->number, devfn, PCI_HEADER_TYPE, &hdr_type)){
			Dprintk("PCI #%d: devfn 0x%x, header type read fails\n",
				domain, devfn);
			continue;
		}
		if (pcibios_read_config_dword(domain, bus->number, devfn, PCI_CLASS_REVISION, &class)) {
		    Dprintk("PCI #%d: devfn 0x%x, class read fails\n",
			domain, devfn);
			continue;
		}
		if (pcibios_read_config_word(domain, bus->number, devfn, PCI_SUBSYSTEM_ID, &subsystem)){
		    Dprintk("PCI #%d: devfn 0x%x, subsystem id read fails\n",
			domain, devfn);
		    continue;
		}

		if ((dev = malloc(sizeof(*dev))) == 0) {
			printk_err("PCI: out of memory.\n");
			continue;
		}

		memset(dev, 0, sizeof(*dev));
		dev->bus = bus;
		dev->devfn = devfn;
		dev->vendor = id & 0xffff;
		dev->device = (id >> 16) & 0xffff;
		dev->hdr_type = hdr_type;
		dev->revision = (unsigned char) class & 0xff;
		/* class code, the upper 3 bytes of PCI_CLASS_REVISION */
		dev->class = class >> 8;
		class >>= 16;
		dev->subsys_id = subsystem ;

		/* non-destructively determine if device can be a master: */
		pcibios_read_config_byte(domain, bus->number, devfn,
						PCI_COMMAND, &cmd);
		pcibios_write_config_byte(domain, bus->number, devfn,
						PCI_COMMAND,
						cmd | PCI_COMMAND_MASTER);
		pcibios_read_config_byte(domain, bus->number, devfn,
						PCI_COMMAND, &tmp);
		dev->master = ((tmp & PCI_COMMAND_MASTER) != 0);
		pcibios_read_config_byte(domain, bus->number, devfn,
						PCI_COMMAND, &cmd);
		Dprintk("PCI %d:%d:%d:%d CMD %02x\n",
			domain, bus->number, PCI_SLOT(devfn), PCI_FUNC(devfn),
			cmd);

		switch (hdr_type & 0x7f) {	/* header type */
		case PCI_HEADER_TYPE_NORMAL:	/* standard header */
			Dprintk("PCI #%d: detected header type PCI_HEADER_TYPE_NORMAL\n",
				domain);
			if (class == PCI_CLASS_BRIDGE_PCI)
				goto bad;
			/*  read base address registers, again pci_fixup() can tweak these */
			pci_read_bases(dev, 6);
			pcibios_read_config_dword(domain, bus->number, devfn, PCI_ROM_ADDRESS, &addr);
			pcibios_write_config_dword(domain, bus->number, devfn, PCI_ROM_ADDRESS, ~PCI_ROM_ADDRESS_ENABLE);
			pcibios_read_config_dword(domain, bus->number, devfn, PCI_ROM_ADDRESS, &size);
			pcibios_write_config_dword(domain, bus->number, devfn, PCI_ROM_ADDRESS, addr);
			if (addr == 0xffffffff)
				addr = 0;
			if (size && size != 0xffffffff) {
				size = pci_size(addr, size, PCI_ROM_ADDRESS_MASK);
				if (size) {
					dev->rom_address = addr;
					dev->rom_address &= PCI_ROM_ADDRESS_MASK;
					dev->rom_size = size;
				}
			}

			break;
		case PCI_HEADER_TYPE_BRIDGE:	/* bridge header */
			Dprintk("PCI #%d: detected header type PCI_HEADER_TYPE_BRIDGE\n",
				domain);
			if (class != PCI_CLASS_BRIDGE_PCI)
				goto bad;
			pci_read_bases(dev, 2);
			pcibios_read_config_dword(domain, bus->number, devfn, PCI_ROM_ADDRESS1, &addr);
			dev->rom_address = (addr == 0xffffffff) ? 0 : addr;
			break;
		case PCI_HEADER_TYPE_CARDBUS:	/* CardBus bridge header */
			Dprintk("PCI #%d: detected header type PCI_HEADER_TYPE_CARDBUS\n",
				domain);
			if (class != PCI_CLASS_BRIDGE_CARDBUS)
				goto bad;
			pci_read_bases(dev, 1);
			break;
		default:	/* unknown header */
		bad:
			printk_err("PCI: %02x:%02x [%04x/%04x/%06x] has unknown header "
			       "type %02x, ignoring.\n",
			       bus->number, dev->devfn, dev->vendor, dev->device, class,
			       hdr_type);
			continue;
		}

		Dprintk("PCI #%d: %02x:%02x [%04x/%04x]\n",
			domain, bus->number, dev->devfn,
			dev->vendor, dev->device);

		/* Put it into the global PCI device chain. It's used to find devices once
		   everything is set up. */
		if (!pci_reverse) {
			*pci_last_dev_p = dev;
			pci_last_dev_p = &dev->next;
		} else {
			dev->next = pci_devices;
			pci_devices = dev;
		}

		/* Now insert it into the list of devices held by the parent bus. */
		*bus_last = dev;
		bus_last = &dev->sibling;

		if (PCI_FUNC(devfn) == 0x00 && (hdr_type & 0x80) != 0x80) {
			/* if this is not a multi function device, don't waste time probe
			   another function. Skip to next device. */
			devfn += 0x07;
		}
	}

	/*
	 * After performing arch-dependent fixup of the bus, look behind
	 * all PCI-to-PCI bridges on this bus.
	 */
	//pcibios_fixup_bus(bus);
	/*
	 * The fixup code may have just found some peer pci bridges on this
	 * machine.  Update the max variable if that happened so we don't
	 * get duplicate bus numbers.
	 */
#ifndef CONFIG_E2K_SIC
	for (child = &pci_root[domain]; child; child = child->next)
		max = ((max > child->subordinate) ? max : child->subordinate);
#endif
	for (dev = bus->devices; dev; dev = dev->sibling)
		/* If it's a bridge, scan the bus behind it. */
		if ((dev->class >> 8) == PCI_CLASS_BRIDGE_PCI) {
			u32 buses;
			unsigned int devfn = dev->devfn;
			unsigned short cr;
#define NOTUSED
#ifdef NOTUSED
			/*
			 * Check for a duplicate bus.  If we already scanned
			 * this bus number as a peer bus, don't also scan it
			 * as a child bus
			 */
			if (((dev->vendor == PCI_VENDOR_ID_SERVERWORKS) &&
			     ((dev->device == PCI_DEVICE_ID_SERVERWORKS_HE) ||
			      (dev->device == PCI_DEVICE_ID_SERVERWORKS_LE))) ||
			    ((dev->vendor == PCI_VENDOR_ID_INTEL) &&
			     ((dev->device == PCI_DEVICE_ID_INTEL_82454NX)||
			      (dev->device == PCI_DEVICE_ID_INTEL_82451NX))))
				continue;

			/* Read the existing primary/secondary/subordinate bus number
			   configuration to determine if the PCI bridge has already been
			   configured by the system.  If so, check to see if we've already
			   scanned this bus as a result of peer bus scanning, if so, skip this.
			   FIMXE: We are BIOS, is there anyone else doing this dirty job BEFORE us ?? */
			pcibios_read_config_dword(domain, bus->number, devfn, PCI_PRIMARY_BUS, &buses);
			if ((buses & 0xFFFFFF) != 0) {
				for (child = pci_root[domain].next; child; child = child->next)
					if (child->number == ((buses >> 8) & 0xff))
						goto skip_it;
			}
#endif
			/* Insert it into the tree of buses. */
			if ((child = malloc(sizeof(*child))) == 0) {
				printk_err("PCI: out of memory for bridge.\n");
				continue;
			}
			memset(child, 0, sizeof(*child));
			child->next = bus->children;
			bus->children = child;
			child->self = dev;
			child->parent = bus;

			/* Set up the primary, secondary and subordinate bus numbers. We have
			   no idea how many buses are behind this bridge yet, so we set the
			   subordinate bus number to 0xff for the moment */
			bios_set_pci_domain_nr(child, domain);
			child->number = child->secondary = ++max;
			child->primary = bus->secondary;
			child->subordinate = 0xff;
#ifdef CONFIG_E2K_SIC
			/* you are programming the main bus bridges when
			 * the level is 0
			 * FIXME must be reconstructed using NSR number
			 * FIXME now for 1 iohub only
			 */
			if (child->number >= 255) {
				Dprintk("bios_pci_scan_bus: too large amount "
					"of bridges,encrease the option "
					"please!!!\n");
				break;
			}
#endif
			/* Clear all status bits and turn off memory, I/O and master enables. */
			pcibios_read_config_word(domain, bus->number, devfn, PCI_COMMAND, &cr);
			pcibios_write_config_word(domain, bus->number, devfn, PCI_COMMAND, 0x0000);
			pcibios_write_config_word(domain, bus->number, devfn, PCI_STATUS, 0xffff);

			/*
			 * Read the existing primary/secondary/subordinate bus
			 * number configuration to determine if the PCI bridge
			 * has already been configured by the system.  If so,
			 * do not modify the configuration, merely note it.
			 */
			pcibios_read_config_dword(domain, bus->number, devfn, PCI_PRIMARY_BUS, &buses);

#ifdef BRIDGE_CONFIGURED_AT_POWERUP
			// There is some hardware (ALPHA) that configures bridges in hardware, at bootup. 
			// We need to take that into account at some point. 
			// At the same time, we're finding buggy bridge hardware that comes up 
			// with these registers non-zero (VIA VT8601). Hence this #ifdef -- in some cases, 
			// you should never check the buses; in other cases, you have no choice. 
			if ((buses & 0xFFFFFF) != 0) {
				unsigned int cmax;

				child->primary = buses & 0xFF;
				child->secondary = (buses >> 8) & 0xFF;
				child->subordinate = (buses >> 16) & 0xFF;
				child->number = child->secondary;
				cmax = bios_pci_scan_bus(child);
				if (cmax > max)
					max = cmax;
			} else
#endif 
			{
				/* Configure the bus numbers for this bridge: the configuration
				   transactions will not be propagated by the bridge if it is not
				   correctly configured */
				buses &= 0xff000000;
				buses |= (((unsigned int) (child->primary) << 0) |
					  ((unsigned int) (child->secondary) << 8) |
					  ((unsigned int) (child->subordinate) << 16));
				pcibios_write_config_dword(domain, bus->number, devfn,
							   PCI_PRIMARY_BUS, buses);
#ifdef	CONFIG_E2K_SIC
#ifndef	CONFIG_L_IOH2
				/* Here we need to setup system commutator register for PCI bridges
		 		 * (PCI Bridge Bus Number Reg - 0x18 - 0x1b ) that is in accordance with 
				 * that of current bridge. We are interested only Subordinate Bus Number 
				 * and Secondary Bus Number fields so it is useless to write Primary. 
				 * According to iset manual aren't required for virtual PCI_2_PCI on 
				 * bus 0 */
				if ((dev->device !=
					PCI_DEVICE_ID_MCST_VIRT_PCI_BRIDGE) &&
					(dev->device !=
					PCI_DEVICE_ID_MCST_PCIE_BRIDGE)) {
					Dprintk("PCI #%d: bios_pci_scan_bus: "
						"setup iohub for buses\n",
						domain);
					system_commutator_e3s_ioh_write_dword(
						domain, bus->number, B1_BN,
						buses);
				} else if (dev->device ==
					PCI_DEVICE_ID_MCST_VIRT_PCI_BRIDGE) {
					unsigned long scrb_base;
					unsigned char iohub_num;

					pcibios_read_config_byte(domain,
						bus->number, devfn,
						IOHUB_DevNum, &iohub_num);
					Dprintk("PCI #%d: bios_pci_scan_bus: "
						"IOHUB.DevNum = 0x%x\n",
						domain, iohub_num);
					scrb_base =
						IOHUB_SCRB_DOMAIN_START(domain);
					/* Setup SCBA_0, SCBA_1 seems to be 0.
					 * If E2K_SCRB_PHYS_BASE has
					 * more then 32 bits you should setup
					 * SCBA_1 register. Its only for
					 * virtual PCI_2_PCI BRIDGE
					 */
					Dprintk("PCI #%d: bios_pci_scan_bus: "
						"setup for SCRB table ... "
						"virtual PCI_2_PCI on bus 0x%x "
						"slot %d func %d\n",
						domain, bus->number,
						PCI_SLOT(devfn),
						PCI_FUNC(devfn));
					pcibios_write_config_dword(domain,
						bus->number, devfn, PCI_SCBA_0,
						(scrb_base | 0x1));
					Dprintk("PCI #%d: bios_pci_scan_bus: "
						"SCBA_0 = 0x%x\n",
						domain, (scrb_base | 0x1));
				}
#endif	/* ! CONFIG_L_IOH2 */
#endif	
				/* Now we can scan all subordinate buses i.e. the bus hehind the bridge */
				max = bios_pci_scan_bus(child);

				/* We know the number of buses behind this
				 * bridge. Set the subordinate
				 * bus number to its real value
				 */
				child->subordinate = max;

				buses = (buses & 0xff00ffff) |
					((unsigned int) (child->subordinate) <<
									16);
				pcibios_write_config_dword(domain, bus->number,
					devfn, PCI_PRIMARY_BUS, buses);
#ifdef CONFIG_E2K_SIC
#ifndef	CONFIG_L_IOH2
				if ((dev->device !=
					PCI_DEVICE_ID_MCST_VIRT_PCI_BRIDGE) &&
					(dev->device !=
					PCI_DEVICE_ID_MCST_PCIE_BRIDGE)) {
					system_commutator_e3s_ioh_write_dword(
						domain, bus->number, B1_BN,
						buses);
				}
#endif	/* ! CONFIG_L_IOH2 */
#endif
				Dprintk("PCI #%d: bios_pci_scan_bus: found "
					"Bridge, primary = %d, number = %d, "
					"subordinate = %d\n",
					domain, child->primary, child->number,
					child->subordinate);
			}
			
			pcibios_write_config_word(domain, bus->number, devfn,
							PCI_COMMAND, cr);
skip_it:
			;
		}
	/*
	 * We've scanned the bus and so we know all about what's on
	 * the other side of any bridges that may be on this bus plus
	 * any devices.
	 *
	 * Return how far we've got finding sub-buses.
	 */
	
	Dprintk("PCI #%d: bios_pci_scan_bus returning with max=%02x\n",
		domain, max);
#ifdef CONFIG_E2K_SIC
	/* Each time we leave bios_pci_scan_bus function we must to decrease
	 * the bus hierarchy level */
	level--;
#endif
	return max;
}

/** Initialize pci root struct, then scan starting at the root. 
 * Note that this function will recurse at each bridge. 
 */
struct bios_pci_bus *pci_init(domain)
{
	struct bios_pci_bus *root_bus;

	root_bus = &pci_root[pci_root_num];
	memset(root_bus, 0, sizeof(*root_bus));
	bios_set_pci_domain_nr(root_bus, domain);
	set_iohub_dev_num(domain);
	pci_root->subordinate = bios_pci_scan_bus(root_bus);
	pci_root_num ++;
	return (root_bus);
}
