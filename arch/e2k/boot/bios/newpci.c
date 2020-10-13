/*
 *    Low-Level PCI Support for PC
 *
 *      (c) 1999--2000 Martin Mares <mj@suse.cz>
 */
/* lots of mods by ron minnich (rminnich@lanl.gov), with 
 * the final architecture guidance from Tom Merritt (tjm@codegen.com)
 * In particular, we changed from the one-pass original version to 
 * Tom's recommended multiple-pass version. I wasn't sure about doing 
 * it with multiple passes, until I actually started doing it and saw
 * the wisdom of Tom's recommendations ...
 */
#include <linux/pci.h>
#include "pci.h"
#include <linux/pci_ids.h>
#include <linux/topology.h>

#include "../boot_io.h"

#undef __KERNEL__

/**************************** DEBUG DEFINES *****************************/
#undef	DEBUG_BOOT_MODE
#undef	Dprintk
#undef	DEBUG_BOOT_AIO_MODE
#undef	DaIOprintk
#undef	DEBUG_BOOT_AR_MODE
#undef	DaRprintk
#define	DEBUG_BOOT_MODE		0	/* SMP CPU boot */
#define	Dprintk			if (DEBUG_BOOT_MODE) rom_printk
#define	DEBUG_BOOT_AIO_MODE	0	/* SMP CPU boot */
#define	DaIOprintk		if (DEBUG_BOOT_AIO_MODE) rom_printk
#define	DEBUG_BOOT_AR_MODE	0	/* SMP CPU boot */
#define	DaRprintk		if (DEBUG_BOOT_AR_MODE) rom_printk
/************************************************************************/

#define ONEMEG (1 << 20)

/* IDE iterrupt number */
#define	NATIVE_MODE_IDE_IRQ		11	/* IRQ # for native mode */
#define	LEGACY_MODE_IDE_IRQ		14	/* IRQ # for legacy mode */

#define	IOHUB_AMR_PRIMARY_NATIVE	0x1	/* IDE primary channel at */
						/* native mode */ 
#define	IOHUB_AMR_SECONDARY_NATIVE	0x4	/* IDE secondary channel at */
						/* native mode */ 

extern volatile unsigned long	phys_node_pres_map;
extern int			phys_node_num;
extern volatile unsigned long	online_iohubs_map;                                   
extern int			online_iohubs_num;
extern volatile unsigned long	possible_iohubs_map;
extern int			possible_iohubs_num;

// historical functions, sometimes very useful. 
/*
 *    Write the special configuration registers on the INTEL
 */
void intel_conf_writeb(unsigned long port, unsigned char value)
{
	unsigned char whichbyte = port & 3;
	port &= (~3);
	outl(port, PCI_CONF_REG_INDEX);
	outb(value, PCI_CONF_REG_DATA + whichbyte);
}

/*
 *    Read the special configuration registers on the INTEL
 */
unsigned char intel_conf_readb(unsigned long port)
{
	unsigned char whichbyte = port & 3;
	port &= (~3);
	outl(port, PCI_CONF_REG_INDEX);
	return inb(PCI_CONF_REG_DATA + whichbyte);
}


struct bios_pci_ops {
	int (*read_byte) (int domain, u8 bus, int devfn, int where, u8 * val);
	int (*read_word) (int domain, u8 bus, int devfn, int where, u16 * val);
	int (*read_dword) (int domain, u8 bus, int devfn, int where, u32 * val);
	int (*write_byte) (int domain, u8 bus, int devfn, int where, u8 val);
	int (*write_word) (int domain, u8 bus, int devfn, int where, u16 val);
	int (*write_dword) (int domain, u8 bus, int devfn, int where, u32 val);
};

static const struct bios_pci_ops *conf;


/*
 * Direct access to PCI hardware...
 */

/*
 * Functions for accessing PCI configuration space with type 1 accesses
 */

#ifdef CONFIG_E2K_SIC
//#define CONFIG_CMD(bus,devfn,where)   ((bus&0xFF)<<24)|((devfn&0xFF)<<16)|(where&0xFFC)
#define CONFIG_CMD(bus,devfn,where)   	((bus&0xFF)<<20)|((devfn&0xFF)<<12)|(where&0xFFF)
#define BUS_DEV_FUNC(bus,devfn)		((bus&0xFF)<<20)|((devfn&0xFF)<<12)
#define	SLOT_DEV_FN(devfn)		((devfn) >> 3)
#define	FUNC_DEV_FN(devfn)		((devfn) & 0x7)
#ifdef	CONFIG_L_IOH2
#define B2_2_0	BUS_DEV_FUNC(1, ((2<<3)|0))
#define B2_2_1	BUS_DEV_FUNC(1, ((2<<3)|1))
#define B2_2_2	BUS_DEV_FUNC(1, ((2<<3)|2))
#define B2_2_3	BUS_DEV_FUNC(1, ((2<<3)|3))
#define B2_0_0	BUS_DEV_FUNC(1, ((0<<3)|0))
#define B2_1_0	BUS_DEV_FUNC(1, ((1<<3)|0))
#define	B1_1_0	BUS_DEV_FUNC(0, ((1<<3)|0))
#define	B1_2_0	BUS_DEV_FUNC(0, ((2<<3)|0))
#else	/* IOHUB-1 */
#define B2_2_0	BUS_DEV_FUNC(2, ((2<<3)|0))
#define B2_2_1	BUS_DEV_FUNC(2, ((2<<3)|1))
#define B2_2_2	BUS_DEV_FUNC(2, ((2<<3)|2))
#define B2_2_3	BUS_DEV_FUNC(2, ((2<<3)|3))
#define B2_0_0	BUS_DEV_FUNC(2, ((0<<3)|0))
#define B2_1_0	BUS_DEV_FUNC(2, ((1<<3)|0))
#define	B1_1_0	BUS_DEV_FUNC(1, ((1<<3)|0))
#define	B1_2_0	BUS_DEV_FUNC(1, ((2<<3)|0))
#endif	/* CONFIG_L_IOH2 */
#else
#undef	CONFIG_CMD
#define CONFIG_CMD(bus,devfn,where)   (0x80000000 | (bus << 16) | (devfn << 8) | (where & ~3))
#endif

static int pci_conf1_read_config_byte(int domain, unsigned char bus, int devfn,
					int where, u8 * value)
{
#ifdef CONFIG_E2K_SIC
	printk_spew("pci_conf1_read_config_byte start\n");
//	conf_outl(bus, CONFIG_CMD(bus, devfn, where), 0xCF8);
//	*value = boot_conf_inb(bus, 0xCFC + (where & 3));
	*value = boot_conf_inb(domain, bus, CONFIG_CMD(bus, devfn, where));
#else
	outl(CONFIG_CMD(bus, devfn, where), 0xCF8);
	*value = inb(0xCFC + (where & 3));
#endif
	return 0;
}

static int pci_conf1_read_config_word(int domain, unsigned char bus, int devfn,
					int where, u16 * value)
{
#ifdef CONFIG_E2K_SIC
	printk_spew("pci_conf1_read_config_word start\n");
//	conf_outl(bus, CONFIG_CMD(bus, devfn, where), 0xCF8);
//	*value = conf_inw(bus, 0xCFC + (where & 2));
	*value = boot_conf_inw(domain, bus, CONFIG_CMD(bus, devfn, where));
#else
	outl(CONFIG_CMD(bus, devfn, where), 0xCF8);
	*value = inw(0xCFC + (where & 2));
#endif
	return 0;
}

static int pci_conf1_read_config_dword(int domain, unsigned char bus, int devfn,
					int where, u32 * value)
{
#ifdef CONFIG_E2K_SIC
	printk_spew("pci_conf1_read_config_dword start\n");
//	conf_outl(bus, CONFIG_CMD(bus, devfn, where), 0xCF8);
//	*value = conf_inl(bus, 0xCFC);
	*value = boot_conf_inl(domain, bus, CONFIG_CMD(bus, devfn, where));
#else
	outl(CONFIG_CMD(bus, devfn, where), 0xCF8);
	*value = inl(0xCFC);
#endif
	return 0;
}

#ifdef	CONFIG_E2K_SIC
#ifndef	CONFIG_L_IOH2
int system_commutator_e3s_ioh_write_byte(int domain, unsigned char bus,
						int where, u8 value)
{
	int link = iohub_domain_to_link(domain);
	/* You must programming SCRB table registers only for bus 2 link 0 */
	/* or bus 1 link 1 on es2 (cubic) */
	if ((bus == 2 && link == 0) || (bus == 1 && link == 1)) {
		boot_ioh_e3s_outb(domain, bus, value, where);
	}
	return 0;
}

int system_commutator_e3s_ioh_read_byte(int domain, unsigned char bus,
						int where, u8 *value)
{
	int link = iohub_domain_to_link(domain);
	/* You must programming SCRB table registers only for bus 2 link 0 */
	/* or bus 1 link 1 on es2 (cubic) */
	if ((bus == 2 && link == 0) || (bus == 1 && link == 1)) {
		*value = boot_ioh_e3s_inb(domain, bus, where);
	}
	return 0;
}

int system_commutator_e3s_ioh_write_word(int domain, unsigned char bus,
						int where, u16 value)
{
	int link = iohub_domain_to_link(domain);
	/* You must programming SCRB table registers only for bus 2 link 0 */
	/* or bus 1 link 1 on es2 (cubic) */
	if ((bus == 2 && link == 0) || (bus == 1 && link == 1)) {
		boot_ioh_e3s_outw(domain, bus, value, where);
	}
	return 0;
}

int system_commutator_e3s_ioh_read_word(int domain, unsigned char bus,
						int where, u16 *value)
{
	int link = iohub_domain_to_link(domain);
	/* You must programming SCRB table registers only for bus 2 link 0 */
	/* or bus 1 link 1 on es2 (cubic) */
	if ((bus == 2 && link == 0) || (bus == 1 && link == 1)) {
		*value = boot_ioh_e3s_inw(domain, bus, where);
	}
	return 0;
}

int system_commutator_e3s_ioh_write_dword(int domain, unsigned char bus,
						int where, u32 value)
{
	int link = iohub_domain_to_link(domain);
	/* You must programming SCRB table registers only for bus 2 link 0 */
	/* or bus 1 link 1 on es2 (cubic) */
	if ((bus == 2 && link == 0) || (bus == 1 && link == 1)) {
		boot_ioh_e3s_outl(domain, bus, value, where);
	}
	return 0;
}
int system_commutator_e3s_ioh_read_dword(int domain, unsigned char bus,
						int where, u32 *value)
{
	int link = iohub_domain_to_link(domain);
	/* You must programming SCRB table registers only for bus 2 link 0 */
	/* or bus 1 link 1 on es2 (cubic) */
	if ((bus == 2 && link == 0) || (bus == 1 && link == 1)) {
		*value = boot_ioh_e3s_inl(domain, bus, where);
	}
	return 0;
}
#endif	/* ! CONFIG_L_IOH2 */
#endif

static int pci_conf1_write_config_byte(int domain, unsigned char bus, int devfn,
					int where, u8 value)
{
#ifdef CONFIG_E2K_SIC
	printk_spew("pci_conf1_write_config_byte start\n");
//	conf_outl(bus, CONFIG_CMD(bus, devfn, where), 0xCF8);
//	conf_outb(bus, value, 0xCFC + (where & 3));
	boot_conf_outb(domain, bus, value, CONFIG_CMD(bus, devfn, where));
#else
	outl(CONFIG_CMD(bus, devfn, where), 0xCF8);
	outb(value, 0xCFC + (where & 3));
#endif
	return 0;
}

static int pci_conf1_write_config_word(int domain, unsigned char bus, int devfn,
					int where, u16 value)
{
#ifdef CONFIG_E2K_SIC
	printk_spew("pci_conf1_write_config_word start\n");
//	conf_outl(bus, CONFIG_CMD(bus, devfn, where), 0xCF8);
//	conf_outw(bus, value, 0xCFC + (where & 2));
	boot_conf_outw(domain, bus, value, CONFIG_CMD(bus, devfn, where));
#else
	outl(CONFIG_CMD(bus, devfn, where), 0xCF8);
	outw(value, 0xCFC + (where & 2));
#endif
	return 0;
}

static int pci_conf1_write_config_dword(int domain, unsigned char bus,
					int devfn, int where, u32 value)
{
#ifdef CONFIG_E2K_SIC
	printk_spew("pci_conf1_write_config_dword start\n");
//	conf_outl(bus, CONFIG_CMD(bus, devfn, where), 0xCF8);
//	conf_outl(bus, value, 0xCFC);
	boot_conf_outl(domain, bus, value, CONFIG_CMD(bus, devfn, where));
#else
	outl(CONFIG_CMD(bus, devfn, where), 0xCF8);
	outl(value, 0xCFC);
#endif
	return 0;
}

#undef CONFIG_CMD

static const struct bios_pci_ops pci_direct_conf1 =
{
	pci_conf1_read_config_byte,
	pci_conf1_read_config_word,
	pci_conf1_read_config_dword,
	pci_conf1_write_config_byte,
	pci_conf1_write_config_word,
	pci_conf1_write_config_dword
};

/*
 * Functions for accessing PCI configuration space with type 2 accesses
 */

#define IOADDR(devfn, where)	((0xC000 | ((devfn & 0x78) << 5)) + where)
#define FUNC(devfn)		(((devfn & 7) << 1) | 0xf0)
#define SET(bus,devfn)		if (devfn & 0x80) return -1;outb(FUNC(devfn), 0xCF8); outb(bus, 0xCFA);

static int pci_conf2_read_config_byte(int domain, unsigned char bus, int devfn,
		int where, u8 * value)
{
	SET(bus, devfn);
	*value = inb(IOADDR(devfn, where));
	outb(0, 0xCF8);
	return 0;
}

static int pci_conf2_read_config_word(int domain, unsigned char bus, int devfn,
		int where, u16 * value)
{
	SET(bus, devfn);
	*value = inw(IOADDR(devfn, where));
	outb(0, 0xCF8);
	return 0;
}

static int pci_conf2_read_config_dword(int domain, unsigned char bus, int devfn,
		int where, u32 * value)
{
	SET(bus, devfn);
	*value = inl(IOADDR(devfn, where));
	outb(0, 0xCF8);
	return 0;
}

static int pci_conf2_write_config_byte(int domain, unsigned char bus, int devfn,
		int where, u8 value)
{
	SET(bus, devfn);
	outb(value, IOADDR(devfn, where));
	outb(0, 0xCF8);
	return 0;
}

static int pci_conf2_write_config_word(int domain, unsigned char bus, int devfn,
		int where, u16 value)
{
	SET(bus, devfn);
	outw(value, IOADDR(devfn, where));
	outb(0, 0xCF8);
	return 0;
}

static int pci_conf2_write_config_dword(int domain, unsigned char bus,
		int devfn, int where, u32 value)
{
	SET(bus, devfn);
	outl(value, IOADDR(devfn, where));
	outb(0, 0xCF8);
	return 0;
}

#undef SET
#undef IOADDR
#undef FUNC

static const struct bios_pci_ops pci_direct_conf2 =
{
	pci_conf2_read_config_byte,
	pci_conf2_read_config_word,
	pci_conf2_read_config_dword,
	pci_conf2_write_config_byte,
	pci_conf2_write_config_word,
	pci_conf2_write_config_dword
};

/*
 * Before we decide to use direct hardware access mechanisms, we try to do some
 * trivial checks to ensure it at least _seems_ to be working -- we just test
 * whether bus 00 contains a host bridge (this is similar to checking
 * techniques used in XFree86, but ours should be more reliable since we
 * attempt to make use of direct access hints provided by the PCI BIOS).
 *
 * This should be close to trivial, but it isn't, because there are buggy
 * chipsets (yes, you guessed it, by Intel and Compaq) that have no class ID.
 */
#ifndef CONFIG_E2K_SIC /* pots do not used now */
static int pci_sanity_check(const struct bios_pci_ops *o)
{
	u16 x;
	u8 bus;
	int devfn;
#define PCI_CLASS_BRIDGE_HOST		0x0600
#define PCI_CLASS_DISPLAY_VGA		0x0300
#define PCI_VENDOR_ID_COMPAQ		0x0e11
#define PCI_VENDOR_ID_INTEL		0x8086

	for (bus = 0, devfn = 0; devfn < 0x100; devfn++)
		if ((!o->read_word(0, bus, devfn, PCI_CLASS_DEVICE, &x) &&
		     (x == PCI_CLASS_BRIDGE_HOST || x == PCI_CLASS_DISPLAY_VGA)) ||
		    (!o->read_word(0, bus, devfn, PCI_VENDOR_ID, &x) &&
		(x == PCI_VENDOR_ID_INTEL || x == PCI_VENDOR_ID_COMPAQ)))
			return 1;
	printk_err("PCI: Sanity check failed\n");
	return 0;
}

static const struct bios_pci_ops *pci_check_direct(void)
{
	unsigned int tmp;

	/*
	 * Check if configuration type 1 works.
	 */
	{
		outb(0x01, 0xCFB);
		tmp = inl(0xCF8);
		outl(0x80000000, 0xCF8);
		if (inl(0xCF8) == 0x80000000 &&
		    pci_sanity_check(&pci_direct_conf1)) {
			outl(tmp, 0xCF8);
			Dprintk("PCI: Using configuration type 1\n");
			return &pci_direct_conf1;
		}
		outl(tmp, 0xCF8);
	}

	/*
	 * Check if configuration type 2 works.
	 */
	{
		outb(0x00, 0xCFB);
		outb(0x00, 0xCF8);
		outb(0x00, 0xCFA);
		if (inb(0xCF8) == 0x00 && inb(0xCFA) == 0x00 &&
		    pci_sanity_check(&pci_direct_conf2)) {
			Dprintk("PCI: Using configuration type 2\n");
			return &pci_direct_conf2;
		}
	}

	return 0;
}
#endif /* ! CONFIG_E2K_SIC  с портами пока не работаем */


int bios_pci_read_config_byte(struct bios_pci_dev *dev, u8 where, u8 *val)
{
	int res;
	int domain = bios_pci_domain_nr(dev->bus);

	res = conf->read_byte(domain, dev->bus->number, dev->devfn, where, val);
	printk_spew("Read config byte bus %d,devfn 0x%x,reg 0x%x,val 0x%x,res 0x%x\n",
	    dev->bus->number, dev->devfn, where, *val, res);
	return res;


}

int bios_pci_read_config_word(struct bios_pci_dev *dev, u8 where, u16 *val)
{
	int res; 
	int domain = bios_pci_domain_nr(dev->bus);

	res = conf->read_word(domain, dev->bus->number, dev->devfn, where, val);
	printk_spew( "Read config word bus %d,devfn 0x%x,reg 0x%x,val 0x%x,res 0x%x\n",
	    dev->bus->number, dev->devfn, where, *val, res);
	return res;
}

int bios_pci_read_config_dword(struct bios_pci_dev *dev, u8 where, u32 *val)
{
	int res; 
	int domain = bios_pci_domain_nr(dev->bus);

	res = conf->read_dword(domain, dev->bus->number, dev->devfn, where, val);
	printk_spew( "Read config dword bus %d,devfn 0x%x,reg 0x%x,val 0x%x,res 0x%x\n",
	    dev->bus->number, dev->devfn, where, *val, res);
	return res;
}

int bios_pci_write_config_byte(struct bios_pci_dev *dev, u8 where, u8 val)
{
	int domain = bios_pci_domain_nr(dev->bus);

	printk_spew( "Write config byte bus %d, devfn 0x%x, reg 0x%x, val 0x%x\n",
	    dev->bus->number, dev->devfn, where, val);
	return conf->write_byte(domain, dev->bus->number, dev->devfn, where, val);
}

int bios_pci_write_config_word(struct bios_pci_dev *dev, u8 where, u16 val)
{
	int domain = bios_pci_domain_nr(dev->bus);

	printk_spew( "Write config word bus %d, devfn 0x%x, reg 0x%x, val 0x%x\n",
	    dev->bus->number, dev->devfn, where, val);
	return conf->write_word(domain, dev->bus->number, dev->devfn, where, val);
}

int bios_pci_write_config_dword(struct bios_pci_dev *dev, u8 where, u32 val)
{
	int domain = bios_pci_domain_nr(dev->bus);

	printk_spew( "Write config dword bus %d, devfn 0x%x, reg 0x%x, val 0x%x\n",
	    dev->bus->number, dev->devfn, where, val);
	return conf->write_dword(domain, dev->bus->number, dev->devfn, where, val);	
}

int pcibios_read_config_byte(int domain, unsigned char bus, unsigned char devfn,
				u8 where, u8 *val)
{
	int res; 

	res = conf->read_byte(domain, bus, devfn, where, val);
	printk_spew( "Read config byte bus %d,devfn 0x%x,reg 0x%x,val 0x%x,res 0x%x\n",
	    bus, devfn, where, *val, res);
	return res;
}

int pcibios_read_config_word(int domain, unsigned char bus, unsigned char devfn,
				u8 where, u16 *val)
{
	int res; 

	res = conf->read_word(domain, bus, devfn, where, val);
	printk_spew( "Read config word bus %d,devfn 0x%x,reg 0x%x,val 0x%x, "
		"res 0x%x\n",
		bus, devfn, where, *val, res);

	return res;

}

int pcibios_read_config_dword(int domain, unsigned char bus,
				unsigned char devfn, u8 where, u32 *val)
{
	int res;

	res = conf->read_dword(domain, bus, devfn, where, val);
	printk_spew( "Read config dword bus %d,devfn 0x%x,reg 0x%x,val 0x%x, "
		"res 0x%x\n",
		bus, devfn, where, *val, res);
	return res;

}

int pcibios_write_config_byte(int domain, unsigned char bus,
				unsigned char devfn, u8 where, u8 val)
{
	printk_spew( "Write byte bus %d, devfn 0x%x, reg 0x%x, val 0x%x\n",
		bus, devfn, where, val);
	return conf->write_byte(domain, bus, devfn, where, val);
}

int pcibios_write_config_word(int domain, unsigned char bus,
				unsigned char devfn, u8 where, u16 val)
{
	printk_spew( "Write word bus %d, devfn 0x%x, reg 0x%x, val 0x%x\n",
		bus, devfn, where, val);
	return conf->write_word(domain, bus, devfn, where, val);
}

int pcibios_write_config_dword(int domain, unsigned char bus,
				unsigned char devfn, u8 where, u32 val)
{
	printk_spew( "Write doubleword bus %d, devfn 0x%x, reg 0x%x, val 0x%x\n",
		bus, devfn, where, val);
	return conf->write_dword(domain, bus, devfn, where, val);
}

/** round a number to an alignment. 
 * @param val the starting value
 * @param roundup Alignment as a power of two
 * @returns rounded up number
 */
unsigned long round(unsigned long val, unsigned long roundup)
{
	// ROUNDUP MUST BE A POWER OF TWO. 
	unsigned long inverse;
	inverse = ~(roundup - 1);
	val += (roundup - 1);
	val &= inverse;
	return val;
}

/** Set the method to be used for PCI, type I or type II
 */
void pci_set_method()
{
	conf = &pci_direct_conf1;
#ifndef CONFIG_E2K_SIC /* с портами пока не работаем */
	conf = pci_check_direct();
#endif
}

/* allocating resources on PCI is a mess. The reason is that 
 * the BAR size is actually two things: one is the size, and
 * the other is the alignment of the data. Take, for example, the 
 * SiS agp hardware. BAR 0 reports a size as follows: 0xf8000008. 
 * This means prefetchable, and you can compute the size of 
 * 0x8000000 (128 Mbytes). But it also turns you that only the 
 * top five bits of the address are decoded. So you can not, for 
 * example, allocate address space at 0x400000 for 0x8000000 bytes, 
 * because in the register that will turn into 0. You have
 * to allocate address space using only the top five bits of the 
 * PCI address space, i.e. you have to start allocating at 0x8000000. 
 * 
 * we have a more complex algorithm for address space allocation in the
 * works, that is actually simple code but gets the desired behavior. 
 * For now, though, we operate as follows: 
 * as you encounter BAR values, just round up the current usage
 * to be aligned to the BAR size. Then allocate. 
 * This has the advantage of being simple, and in practice there are 
 * so few large BAR areas that we expect it to cover all cases. 
 * If we find problems with this strategy we'll go to the more complex
 * algorithm. 
 */
/* it's worse than I thought ... 
 * rules: 
 * bridges contain all sub-bridges, and the address space for mem and 
 * prefetch has to be contiguous. 
 * Anyway, this has gotten so complicated we're going to a one-pass 
 * allocate for now. 
 */


/** Given a desired amount of io, round it to IO_BRIDGE_ALIGN
 * @param amount Amount of memory desired. 
 */
unsigned long iolimit(unsigned long amount)
{
	/* Workaround - if amount is 0 do not return -1.
	 * Otherwise iobase calculation in compute_allocate_io()
	 * will round it up to some bogus value taking up all
	 * IO space. */
	if (amount)
		amount = round(amount, IO_BRIDGE_ALIGN) - 1;
	else
		amount = IO_BRIDGE_ALIGN - 1;
	return amount;
}

/** Given a desired amount of memory, round it to ONEMEG
 * @param amount Amount of memory desired. 
 */
unsigned long memlimit(unsigned long amount)
{
	amount = round(amount, ONEMEG) - 1;
	return amount;
}

/** Compute and allocate the io for this bus. 
 * @param bus Pointer to the struct for this bus. 
 */
void compute_allocate_io(struct bios_pci_bus *bus)
{
	int i;
	struct bios_pci_bus *curbus;
	struct bios_pci_dev *curdev;
	unsigned long io_base;
	int domain = bios_pci_domain_nr(bus);

	io_base = bus->iobase;
	DaIOprintk("compute_allocate_io: base 0x%x\n", bus->iobase);

	/* First, walk all the bridges. When you return, grow the limit of the current bus
	   since sub-busses need IO rounded to 4096 */
	for (curbus = bus->children; curbus; curbus = curbus->next) {
		curbus->iobase = io_base;
		compute_allocate_io(curbus);
		io_base = round(curbus->iolimit, IO_BRIDGE_ALIGN);
		DaIOprintk("BUSIO: done PCI #%d Bridge Bus 0x%x, iobase now 0x%x\n",
			domain, curbus->number, io_base);
	}

	/* Walk through all the devices on current bus and compute IO address space.*/
	for (curdev = bus->devices; curdev; curdev = curdev->sibling) {
		u32 class_revision;
		/* FIXME Special case for VGA for now just note
		 * we have an I/O resource later make certain
		 * we don't have a device conflict.
		 */
		bios_pci_read_config_dword(curdev, PCI_CLASS_REVISION,
						&class_revision);
		DaIOprintk("Vendor %02x, Device %02x\n", curdev->vendor,
				curdev->device);
		if (((class_revision >> 24) == 0x03) &&
			((class_revision >> 16) != 0x380)) {
			DaIOprintk("Running VGA fix...\n");
			/* All legacy VGA cards have I/O space registers */
			curdev->command |= PCI_COMMAND_IO;	
		}
		for (i = 0; i < 6; i++) {
			unsigned long size = curdev->size[i];
			if (size & PCI_BASE_ADDRESS_SPACE_IO) {
				unsigned long iosize = size & PCI_BASE_ADDRESS_IO_MASK;
				if (!iosize)
					continue;

				DaIOprintk("DEVIO: PCI #%d Bus 0x%x, devfn 0x%x, reg 0x%x: "
				    "iosize 0x%x\n",
				    domain, curdev->bus->number, curdev->devfn, i, iosize);
				// Make sure that iosize is a minimum 
				// size. 
				iosize = round(iosize, IO_ALIGN);
				// io_base must be aligned to the io size.
				io_base = round(io_base, iosize);
				DaIOprintk("  rounded size 0x%x base 0x%x\n", iosize, io_base);
				curdev->base_address[i] = io_base;
				// some chipsets allow us to set/clear the IO bit. 
				// (e.g. VIA 82c686a.) So set it to be safe)
				curdev->base_address[i] |= 
				    PCI_BASE_ADDRESS_SPACE_IO;
				DaIOprintk("-->set base to 0x%x\n", io_base);
				io_base += iosize;
				if (io_base > PCI_IO_DOMAIN_END(domain)) {
					rom_printk("ERROR: PCI #%d IO memory limit %X "
						"is exceeded %X\n",
						domain,
						PCI_IO_DOMAIN_END(domain),
						io_base);
					break;
				}
				curdev->command |= PCI_COMMAND_IO;
			}
		}
		if ((class_revision >> 16) == PCI_CLASS_STORAGE_IDE) {
			u8 progif;
			/* Set IDE to native mode */
			bios_pci_read_config_byte(curdev, PCI_CLASS_PROG,
							&progif);
			progif |= 0x5;
			bios_pci_write_config_byte(curdev, PCI_CLASS_PROG,
							progif);
		}
	}
	bus->iolimit = iolimit(io_base);

	DaIOprintk("BUS %d: set iolimit to 0x%x\n", bus->number, bus->iolimit);
}

/** Compute and allocate the memory for this bus. 
 * @param bus Pointer to the struct for this bus. 
 */
void compute_allocate_mem(struct bios_pci_bus *bus)
{
	int i;
	struct bios_pci_bus *curbus;
	struct bios_pci_dev *curdev;
	unsigned long mem_base;
	int domain = bios_pci_domain_nr(bus);

	mem_base = bus->membase;
	Dprintk("compute_allocate_mem: PCI #%d, bus %d base 0x%x\n",
		domain, bus->number, bus->membase);

	/* First, walk all the bridges. When you return, grow the limit of the current bus
	   since sub-busses need MEMORY rounded to 1 Mega */
	for (curbus = bus->children; curbus; curbus = curbus->next) {
		curbus->membase = mem_base;
		compute_allocate_mem(curbus);
		mem_base = round(curbus->memlimit, ONEMEG);
		Dprintk("BUSMEM: PCI #%d Bridge Bus 0x%x,membase now 0x%x\n",
			domain, curbus->number, mem_base);
	}

	/* Walk through all the devices on current bus and oompute MEMORY address space.*/
	for (curdev = bus->devices; curdev; curdev = curdev->sibling) {
		Dprintk("compute_allocate_mem() device %d:%d:%d:%d\n",
			domain, curdev->bus->number,
			PCI_SLOT(curdev->devfn), PCI_FUNC(curdev->devfn));
		for (i = 0; i < 6; i++) {
			unsigned long size = curdev->size[i];
			unsigned long memorysize = size & (PCI_BASE_ADDRESS_MEM_MASK);
			unsigned long type = size & (~PCI_BASE_ADDRESS_MEM_MASK);
			Dprintk("compute_allocate_mem() device resorce #%d "
				"size is 0x%x\n",
				i, curdev->size[i]);
			if (!memorysize) {
				continue;
			}

			if (type & PCI_BASE_ADDRESS_SPACE_IO) {
				continue;
			}

			// we don't support the 1M type
			if (type & PCI_BASE_ADDRESS_MEM_TYPE_1M) {
			    continue;
			}

			// if it's prefetch type, continue;
			if (type & PCI_BASE_ADDRESS_MEM_PREFETCH) {
				continue;
			}

			// now mask out all but the 32 or 64 bits
			type &= PCI_BASE_ADDRESS_MEM_TYPE_MASK;

			// I'm pretty sure this test is not needed, but ...
			if ((type == PCI_BASE_ADDRESS_MEM_TYPE_32) ||
			    (type == PCI_BASE_ADDRESS_MEM_TYPE_64)) {
				/* this is normal memory space */
				unsigned long regmem;

				Dprintk("DEVMEM: PCI #%d Bus 0x%x, devfn 0x%x, reg 0x%x: "
					   "memsize 0x%x\n", domain,
					   curdev->bus->number, curdev->devfn, i, memorysize);

				/* PCI BUS Spec suggests that the memory address should be
				   consumed in 4KB unit */
				regmem = round(memorysize, MEM_ALIGN);

				mem_base = round(mem_base, regmem);
				Dprintk("  rounded size 0x%x base 0x%x\n", regmem, mem_base);
				curdev->base_address[i] = mem_base;
				Dprintk("-->set base to 0x%x\n", mem_base);

				mem_base += regmem;
				if (mem_base > PCI_MEM_DOMAIN_END(domain)) {
					rom_printk("ERROR: PCI #%d MEMory limit %X "
						"is exceeded %X\n",
						domain,
						PCI_MEM_DOMAIN_END(domain),
						mem_base);
					break;
				}
				curdev->command |= PCI_COMMAND_MEMORY;
				// for 64-bit BARs, the odd ones don't count
				if (type == PCI_BASE_ADDRESS_MEM_TYPE_64)
				    continue;

			}
		}
		/* Now we take care about ROM BIOS */
		{
			unsigned long size = curdev->rom_size;
			unsigned long memorysize = size & (PCI_BASE_ADDRESS_MEM_MASK);
			unsigned long regmem;

			if (!memorysize)
				continue;
			Dprintk("DEVROM: Bus 0x%x, devfn 0x%x: "
				    "memsize 0x%x\n",
				    curdev->bus->number, curdev->devfn, memorysize);
			regmem = round(memorysize, MEM_ALIGN);
			mem_base = round(mem_base, regmem);
			Dprintk("  rounded size 0x%x base 0x%x\n", regmem, mem_base);
			curdev->rom_address = mem_base;
			Dprintk("-->set base to 0x%x\n", mem_base);
			mem_base += regmem;
			if (mem_base > PCI_MEM_DOMAIN_END(domain)) {
				rom_printk("ERROR: PCI #%d ROM memory limit %X "
					"is exceeded %X\n",
					domain,
					PCI_MEM_DOMAIN_END(domain),
					mem_base);
				break;
			}
			curdev->command |= PCI_COMMAND_MEMORY;
		}
	}
	bus->memlimit = memlimit(mem_base);

	Dprintk("BUS %d: set memlimit to 0x%x\n", bus->number, bus->memlimit);
}

/** Compute and allocate the prefetch memory for this bus. 
 * @param bus Pointer to the struct for this bus. 
 */
void compute_allocate_prefmem(struct bios_pci_bus *bus)
{
	int i;
	struct bios_pci_bus *curbus;
	struct bios_pci_dev *curdev;
	unsigned long prefmem_base;
	int domain = bios_pci_domain_nr(bus);

	prefmem_base = bus->prefmembase;
	Dprintk("Compute_allocate_prefmem: base 0x%x\n", bus->prefmembase);

	/* First, walk all the bridges. When you return, grow the limit of the current bus
	   since sub-busses need MEMORY rounded to 1 Mega */
	for (curbus = bus->children; curbus; curbus = curbus->next) {
		curbus->prefmembase = prefmem_base;
		compute_allocate_prefmem(curbus);
		prefmem_base = round(curbus->prefmemlimit, ONEMEG);
		Dprintk("BUSPREFMEM: Bridge Bus 0x%x, prefmem base now 0x%x\n",
		    curbus->number, prefmem_base);
	}

	/* Walk through all the devices on current bus and oompute PREFETCHABLE MEMORY address space.*/
	for (curdev = bus->devices; curdev; curdev = curdev->sibling) {
		for (i = 0; i < 6; i++) {
			unsigned long size = curdev->size[i];
			unsigned long memorysize = size & (PCI_BASE_ADDRESS_MEM_MASK);
			unsigned long type = size & (~PCI_BASE_ADDRESS_MEM_MASK);

			if (!memorysize)
				continue;

			if (type & PCI_BASE_ADDRESS_SPACE_IO) {
			    continue;
			}

			// we don't support the 1M type
			if (type & PCI_BASE_ADDRESS_MEM_TYPE_1M) {
			    Dprintk("compute_allocate_prefmem: 1M memory not supported\n");
			    continue;
			}

			// if it's not a prefetch type, continue;
			if (! (type & PCI_BASE_ADDRESS_MEM_PREFETCH))
			    continue;
			// this should be a function some day ... comon code with 
			// the non-prefetch allocate
			// now mask out all but the 32 or 64 bit type info
			type &= PCI_BASE_ADDRESS_MEM_TYPE_MASK;
			// if all these names confuse you, they confuse me too!
			if ((type == PCI_BASE_ADDRESS_MEM_TYPE_32) ||
			    (type == PCI_BASE_ADDRESS_MEM_TYPE_64)) {
				unsigned long regmem;

				/* PCI BUS Spec suggests that the memory address should be
				   consumed in 4KB unit */
				Dprintk("DEVPREFMEM: Bus 0x%x, devfn 0x%x, reg 0x%x: "
				    "prefmemsize 0x%x\n",
				    curdev->bus->number, curdev->devfn, i, memorysize);
				regmem = round(memorysize, MEM_ALIGN);
				prefmem_base = round(prefmem_base, regmem);
				Dprintk("  rounded size 0x%x base 0x%x\n", regmem, prefmem_base);
				curdev->base_address[i] = prefmem_base;
				Dprintk("-->set base to 0x%x\n", prefmem_base);
				prefmem_base += regmem;
				if (prefmem_base > PCI_MEM_DOMAIN_END(domain)) {
					rom_printk("ERROR: PCI #%d PREF MEMory limit %X "
						"is exceeded %X\n",
						domain,
						PCI_MEM_DOMAIN_END(domain),
						prefmem_base);
					break;
				}
				curdev->command |= PCI_COMMAND_MEMORY;
				// for 64-bit BARs, the odd ones don't count
				if (type == PCI_BASE_ADDRESS_MEM_TYPE_64)
				    continue;
			}
		}
	}
	bus->prefmemlimit = memlimit(prefmem_base);

	Dprintk("BUS %d: set prefmemlimit to 0x%x\n", bus->number, bus->prefmemlimit);
}

/** Compute and allocate resources. 
 * This is a one-pass process. We first compute all the IO, then 
 * memory, then prefetchable memory. 
 * This is really only called at the top level
 * @param bus Pointer to the struct for this bus. 
 */
void compute_allocate_resources(struct bios_pci_bus *bus)
{
	Dprintk("COMPUTE_ALLOCATE: do IO\n");
	compute_allocate_io(bus);

	Dprintk("COMPUTE_ALLOCATE: do MEM\n");
	compute_allocate_mem(bus);

	// now put the prefetchable memory at the end of the memory
	bus->prefmembase = round(bus->memlimit, ONEMEG);

	Dprintk("COMPUTE_ALLOCATE: do PREFMEM\n");
	compute_allocate_prefmem(bus);
}

/** Assign the computed resources to the bridges and devices on the bus.
 * Recurse to any bridges found on this bus first. Then do the devices
 * on this bus. 
 * @param bus Pointer to the structure for this bus
 */ 
void assign_resources(struct bios_pci_bus *bus)
{
	struct bios_pci_dev *curdev = pci_devices;
	struct bios_pci_bus *curbus;
#ifdef CONFIG_E2K_SIC
	u16	b1_iobl_val;
	u32	b1_mbl_val, b1_pmbl_val;
#endif	
	int	domain = bios_pci_domain_nr(bus);

	DaRprintk("ASSIGN RESOURCES, bus %d\n", bus->number);

	/* walk trhough all the buses, assign resources for bridges */
	for (curbus = bus->children; curbus; curbus = curbus->next) {
		curbus->self->command = 0;

		/* set the IO ranges
		   WARNING: we don't really do 32-bit addressing for IO yet! */
		if (curbus->iobase || curbus->iolimit) {
			curbus->self->command |= PCI_COMMAND_IO;
			bios_pci_write_config_byte(curbus->self, PCI_IO_BASE,
					      curbus->iobase >> 8);
			bios_pci_write_config_byte(curbus->self, PCI_IO_LIMIT,
					      curbus->iolimit >> 8);
			DaRprintk("assign_resources: for BRIDGE on bus 0x%x IO "
				"base 0x%x limit 0x%x\n",
				curbus->self->bus->number, curbus->iobase,
				curbus->iolimit);

#ifdef CONFIG_E2K_SIC
			if (curbus->self->device !=
				PCI_DEVICE_ID_MCST_VIRT_PCI_BRIDGE &&
				curbus->self->device !=
					PCI_DEVICE_ID_MCST_PCIE_BRIDGE) {
				b1_iobl_val = ((curbus->iolimit)&0xff00) |
						((curbus->iobase >> 8) & 0xff);
				DaRprintk("assign_resources: bus 0x%x, io val "
					"to SCRB = 0x%x\n",
					curbus->self->bus->number, b1_iobl_val);
				system_commutator_e3s_ioh_write_word(domain,
					curbus->self->bus->number, B1_IOBL,
					b1_iobl_val);
			} else {
				DaRprintk("assign_resources: PCI_IO_BASE "
					"skiping device 0x%x on bus 0x%x\n",
					curbus->self->device, bus->number);
			}
#endif
			DaRprintk("Bus 0x%x Child Bus %x iobase to 0x%x "
				"iolimit 0x%x\n",
				bus->number, curbus->number, curbus->iobase,
				curbus->iolimit);
		}

		// set the memory range
		if (curbus->membase) {
			curbus->self->command |= PCI_COMMAND_MEMORY;
			bios_pci_write_config_word(curbus->self,
				PCI_MEMORY_BASE, curbus->membase >> 16);
			bios_pci_write_config_word(curbus->self,
				PCI_MEMORY_LIMIT, curbus->memlimit >> 16);
#ifdef CONFIG_E2K_SIC
			if (curbus->self->device !=
				PCI_DEVICE_ID_MCST_VIRT_PCI_BRIDGE &&
				curbus->self->device !=
					PCI_DEVICE_ID_MCST_PCIE_BRIDGE) {
				b1_mbl_val = ((curbus->memlimit)&0xffff0000) |
						((curbus->membase >> 16) &
							0xffff);
				DaRprintk("assign_resources: will set bus "
					"0x%x, mem val to SCRB = 0x%x\n",
					curbus->self->bus->number, b1_mbl_val);
				system_commutator_e3s_ioh_write_dword(domain,
					curbus->self->bus->number, B1_MBL,
					b1_mbl_val);
				system_commutator_e3s_ioh_read_dword(domain,
					curbus->self->bus->number, B1_MBL,
					&b1_mbl_val);
				DaRprintk("assign_resources: read bus 0x%x, "
					"mem val from SCRB = 0x%x\n",
					curbus->self->bus->number, b1_mbl_val);
			} else {
				DaRprintk("assign_resources: PCI_MEMORY_BASE "
					"skiping device 0x%x on bus 0x%x\n",
					curbus->self->device, bus->number);
			}
#endif			
			DaRprintk("Bus 0x%x Child Bus %x membase to 0x%x "
				"memlimit 0x%x\n",
				bus->number, curbus->number, curbus->membase,
				curbus->memlimit);

		}

		// set the prefetchable memory range
		if (curbus->prefmembase) {
			curbus->self->command |= PCI_COMMAND_MEMORY;
			bios_pci_write_config_word(curbus->self,
				PCI_PREF_MEMORY_BASE,
				curbus->prefmembase >> 16);
			bios_pci_write_config_word(curbus->self,
				PCI_PREF_MEMORY_LIMIT,
				curbus->prefmemlimit >> 16);
#ifdef CONFIG_E2K_SIC
			if (curbus->self->device !=
				PCI_DEVICE_ID_MCST_VIRT_PCI_BRIDGE &&
				curbus->self->device !=
					PCI_DEVICE_ID_MCST_PCIE_BRIDGE) {
				b1_pmbl_val = ((curbus->prefmemlimit) &
							0xffff0000) |
						((curbus->prefmembase >> 16) &
							0xffff);
				DaRprintk("assign_resources: bus 0x%x, pmem "
					"val to SCRB = 0x%x\n",
					curbus->self->bus->number, b1_pmbl_val);
				system_commutator_e3s_ioh_write_dword(domain,
					curbus->self->bus->number, B1_PMBL,
					b1_pmbl_val);
			} else {
				DaRprintk("assign_resources: "
					"PCI_PREF_MEMORY_BASE skiping device "
					"0x%x on bus 0x%x\n",
					curbus->self->device, bus->number);
			}
#endif
			DaRprintk("Bus 0x%x Child Bus %x prefmembase to 0x%x "
				"prefmemlimit 0x%x\n",
				bus->number, curbus->number,
				curbus->prefmembase, curbus->prefmemlimit);

		}
		curbus->self->command |= PCI_COMMAND_MASTER;
		assign_resources(curbus);
	}

	for (curdev = bus->devices; curdev; curdev = curdev->sibling) {
		int i;
		for (i = 0; i < 6; i++) {
			unsigned long reg;
			if (curdev->base_address[i] == 0)
				continue;

			reg = PCI_BASE_ADDRESS_0 + (i << 2);
			bios_pci_write_config_dword(curdev, reg,
						curdev->base_address[i]);
#ifdef CONFIG_E2K_SIC
			switch (BUS_DEV_FUNC(curdev->bus->number,
							curdev->devfn)) {
			case B2_2_3:  /* BUS:2 DEV:2 FUNC:3 = AC97 audio/gpio */
				if (i == 0){
					system_commutator_e3s_ioh_write_dword(
						domain, curdev->bus->number,
						A0_BA0,
						curdev->base_address[i]);
					break;
				}
				if (i == 1){
					system_commutator_e3s_ioh_write_dword(
						domain, curdev->bus->number,
						A0_BA1,
						curdev->base_address[i]);
					break;
				}
				DaRprintk("assign_resources: warning: found "
					"i = 0x%x for 2_2_3 device\n", i);
				break;
			case B1_2_0:	/* BUS:1 DEV:2 FUNC:0 =
					 * ioapic/pic/timer/i2c/spi
					 * on IOLINK 1
					 */
			case B2_2_1:	/* BUS:2 DEV:2 FUNC:1 =
					 * ioapic/pic/timer/i2c/spi
					 * on IOLINK 1
					 */
				if (i == 0){ /* i2c/spi */
					system_commutator_e3s_ioh_write_dword(
						domain, curdev->bus->number,
						A1_BA0,
						curdev->base_address[i]);
					break;
				}
				if (i == 1){ /* i2c/spi */
					system_commutator_e3s_ioh_write_dword(
						domain, curdev->bus->number,
						A1_BA1,
						curdev->base_address[i]);
					break;
				}
				DaRprintk("assign_resources: warning: found "
					"i = 0x%x for I2C/SPI device\n", i);
				break;
			case B2_2_2: /* BUS:2 DEV:2 FUNC:2 = ieee1284/rs232 */
				if (i == 0){ /* parport */
					system_commutator_e3s_ioh_write_dword(
						domain, curdev->bus->number,
						A5_BA0,
						curdev->base_address[i]);
					break;
				}
				if (i == 1){ /* rs232 */
					system_commutator_e3s_ioh_write_dword(
						domain, curdev->bus->number,
						A6_BA0,
						curdev->base_address[i]);
					break;
				}
				DaRprintk("assign_resources: warning: found "
					"i = 0x%x for 2_2_2 device\n", i);
				break;
			case B2_2_0: /* IDE contr */
				if (i == 0) {
					u32 bar;
					system_commutator_e3s_ioh_write_dword(
						domain, curdev->bus->number,
						A7_BA0,
						curdev->base_address[i]);
					system_commutator_e3s_ioh_read_dword(
						domain, curdev->bus->number,
						A7_BA0, &bar);
					DaRprintk("assign_resources: set "
						"A7_BA0 to 0x%x for 2_2_0 "
						"device\n",
						bar);
					break;
				}
				if (i == 1){
					u32 bar;
					system_commutator_e3s_ioh_write_dword(
						domain, curdev->bus->number,
						A7_BA1,
						curdev->base_address[i]);
					system_commutator_e3s_ioh_read_dword(
						domain, curdev->bus->number,
						A7_BA1, &bar);
					DaRprintk("assign_resources: set "
						"A7_BA1 to 0x%x for 2_2_0 "
						"device\n",
						bar);
					break;
				}
				if (i == 2){
					u32 bar;
					system_commutator_e3s_ioh_write_dword(
						domain, curdev->bus->number,
						A7_BA2,
						curdev->base_address[i]);
					system_commutator_e3s_ioh_read_dword(
						domain, curdev->bus->number,
						A7_BA2,
						&bar);
					DaRprintk("assign_resources: set "
						"A7_BA2 to 0x%x for 2_2_0 "
						"device\n",
						bar);
					break;
				}
				if (i == 3){
					u32 bar;
					system_commutator_e3s_ioh_write_dword(
						domain, curdev->bus->number,
						A7_BA3,
						curdev->base_address[i]);
					system_commutator_e3s_ioh_read_dword(
						domain, curdev->bus->number,
						A7_BA3, &bar);
					DaRprintk("assign_resources: set "
						"A7_BA3 to 0x%x for 2_2_0 "
						"device\n",
						bar);
					break;
				}
				if (i == 4){
					u32 bar;
					system_commutator_e3s_ioh_write_dword(
						domain, curdev->bus->number,
						A7_BA4,
						curdev->base_address[i]);
					system_commutator_e3s_ioh_read_dword(
						domain, curdev->bus->number,
						A7_BA4, &bar);
					DaRprintk("assign_resources: set "
						"A7_BA4 to 0x%x for 2_2_0 "
						"device\n",
						bar);
					break;
				}
				DaRprintk("assign_resources: warning: found "
					"i = 0x%x for 2_2_0 device\n", i);
				break;
			case B2_1_0: /* ETHERNET */
				if (i == 0) {
					system_commutator_e3s_ioh_write_dword(
						domain, curdev->bus->number,
						A4_BA0,
						curdev->base_address[i]);
					DaRprintk("assign_resources: warning: "
						"found i = 0x%x for ETHERNET "
						"device\n", i);
				}
				break;
			case B1_1_0: /* ADC */
				if (i == 0) {
					system_commutator_e3s_ioh_write_dword(
						domain, curdev->bus->number,
						A4_BA0,
						curdev->base_address[i]);
					DaRprintk("assign_resources: warning: "
						"found i = 0x%x for ADC "
						"device\n", i);
				}
				break;
			default:
				DaRprintk("assign_resources: bus: 0x%x dev: "
					"0x%x func: 0x%x shouldn't be "
					"configured for i(reg) = %d.\n",
					curdev->bus->number,
					(curdev->devfn) >> 3,
					(curdev->devfn)&0x7, i);
				break;
			}
#endif
			DaRprintk("PCI #%d Bus 0x%x devfn 0x%x resource #%d "
				"base to 0x%x\n",
				domain, curdev->bus->number,
				PCI_SLOT(curdev->devfn),
				PCI_FUNC(curdev->devfn),
				i, curdev->base_address[i]);
		}
		if (curdev->rom_address == 0 || curdev->rom_size == 0)
				continue;

		bios_pci_write_config_dword(curdev, PCI_ROM_ADDRESS,
				curdev->rom_address | PCI_ROM_ADDRESS_ENABLE);
		DaRprintk("Bus 0x%x devfn 0x%x ROM address base to 0x%x\n",
		    curdev->bus->number, curdev->devfn, curdev->rom_address);

		/* set a default latency timer */
		bios_pci_write_config_byte(curdev, PCI_LATENCY_TIMER, 0x40);
	}
	DaRprintk("ASSIGN RESOURCES, exit for bus %d\n", bus->number);
}

void enable_resources(struct bios_pci_bus *bus)
{
	struct bios_pci_dev *curdev = pci_devices;

	/* walk through the chain of all pci device, this time we don't
	 * have to deal with the device v.s. bridge stuff, since every
	 * bridge has its own bios_pci_dev assocaited with it
	 */
	for (curdev = pci_devices; curdev; curdev = curdev->next) {
		u16 command;
		int domain;

		domain = bios_pci_domain_nr(curdev->bus);
		bios_pci_read_config_word(curdev, PCI_COMMAND, &command);
#ifdef CONFIG_E2K_SIC
		if ((BUS_DEV_FUNC(curdev->bus->number, curdev->devfn) ==
								B2_2_1) ||
			(BUS_DEV_FUNC(curdev->bus->number, curdev->devfn) ==
								B1_2_0)) {
			curdev->command |= PCI_COMMAND_IO;
			curdev->command |= PCI_COMMAND_MASTER;
		}
#endif
		command |= curdev->command;
		Dprintk("DEV Set command bus 0x%x devfn 0x%x to 0x%x\n",
		    curdev->bus->number, curdev->devfn, command);
		bios_pci_write_config_word(curdev, PCI_COMMAND, command);
#ifdef CONFIG_E2K_SIC
		switch (BUS_DEV_FUNC(curdev->bus->number,curdev->devfn)){
		case B2_2_3:  /* BUS:2 DEV:2 FUNC:3 = AC97 audio/gpio */
			system_commutator_e3s_ioh_write_byte(domain,
				curdev->bus->number, A0_SE,
				PCI_COMMAND_MEMORY);
			break;
		case B1_2_0:	/* BUS:1 DEV:2 FUNC:0 =
				 * ioapic/pic/timer/i2c/spi IOLINK 1
				 */
			Dprintk("enable_resources() enable BUS:1 DEV:2 FUNC:0 "
				"= ioapic/pic/timer/i2c/spi contr\n");
			system_commutator_e3s_ioh_write_byte(domain,
				curdev->bus->number, A1_SE,
				PCI_COMMAND_MEMORY | PCI_COMMAND_IO);
			break;
		case B2_2_1:	/* BUS:2 DEV:2 FUNC:1 =
				 * ioapic/pic/timer/i2c/spi IOLINK 0
				 */
			Dprintk("enable_resources() enable BUS:2 DEV:2 FUNC:1 "
				"= ioapic/pic/timer/i2c/spi contr\n");
			system_commutator_e3s_ioh_write_byte(domain,
				curdev->bus->number, A1_SE,
				PCI_COMMAND_MEMORY | PCI_COMMAND_IO);
			break;
		case B2_2_2: /* BUS:2 DEV:2 FUNC:2 = ieee1284/rs232 */
			system_commutator_e3s_ioh_write_byte(domain,
				curdev->bus->number, A5_SE,
				PCI_COMMAND_MEMORY | PCI_COMMAND_IO);
			break;
		case B2_2_0: /* BUS:2 DEV:2 FUNC:0 = IDE contr */
			bios_pci_write_config_dword(curdev, PCI_CLASS_REVISION,
				NATIVE_MODE_CLASSC << 8);
			system_commutator_e3s_ioh_write_byte(domain,
				curdev->bus->number, A7_AMR,
				NATIVE_MODE_CLASSC);
			Dprintk("enable_resources() set IDE BUS:2 DEV:2 FUNC:0 "
				"to native mode\n");
			system_commutator_e3s_ioh_write_byte(domain,
				curdev->bus->number, A7_SE,
				PCI_COMMAND_MEMORY | PCI_COMMAND_IO);
			/* set Addressing Mode Register to native mode
			 * on IOHUB
			 */
			system_commutator_e3s_ioh_write_byte(domain,
				curdev->bus->number, A7_AMR,
				IOHUB_AMR_PRIMARY_NATIVE |
						IOHUB_AMR_SECONDARY_NATIVE);
			break;
		case B2_0_0: /* BUS:2 DEV:0 FUNC:0 = REAL PCI_2_PCI BRIDGE */
			system_commutator_e3s_ioh_write_byte(domain,
				curdev->bus->number, B1_SE,
				PCI_COMMAND_MEMORY | PCI_COMMAND_IO);
			/* Allow arbitration to everyone */
			bios_pci_write_config_word(curdev, Arb_CtlSta, 0xf);
			break;
		case B1_1_0: /* BUS:1 DEV:1 FUNC:0 = ADC */
		case B2_1_0: /* BUS:2 DEV:1 FUNC:0 = ETHERNET */
			system_commutator_e3s_ioh_write_byte(domain,
				curdev->bus->number, A4_SE,
				PCI_COMMAND_MEMORY);
			break;
		default:
			Dprintk("enable_resources: bus: 0x%x dev: 0x%x func: "
				"0x%x shouldn't be configured\n",
				curdev->bus->number, (curdev->devfn) >> 3,
				(curdev->devfn)&0x7);
			break;
		}
#endif
	}
}

void assign_interrupts(struct bios_pci_bus *bus)
{
#ifdef CONFIG_E2K_SIC
	struct bios_pci_dev *curdev = pci_devices;
	int domain = bios_pci_domain_nr(bus);

	/*
	 * Walk through the all pci device on the bus and
	 * assifn interrupts if device interrupt pin directly
	 * connect to IOAPIC pin
	 */
	for (curdev = pci_devices; curdev; curdev = curdev->next) {
		u8 int_line;
		int bus = curdev->bus->number;
		int slot = SLOT_DEV_FN(curdev->devfn);
		int func = FUNC_DEV_FN(curdev->devfn);
		if (bios_pci_domain_nr(curdev->bus) != domain)
			continue;
		switch (BUS_DEV_FUNC(bus, curdev->devfn)) {
		case B2_2_3:  /* BUS:2 DEV:2 FUNC:3 = AC97 audio/gpio */
			int_line = 0x05;
			Dprintk("%d.%d.%d.%d: AC-97",
				domain, bus, slot, func);
			break;
		case B1_2_0: /* BUS:1 DEV:2 FUNC:0 = i2c/spi IOLINK 1 */
			int_line = 0x17;
			Dprintk("%d.%d.%d.%d: i2c/spi controller",
				domain, bus, slot, func);
			break;
		case B2_2_1: /* BUS:2 DEV:2 FUNC:1 = i2c/spi IOLINK 0 */
			int_line = 0x0f;
			Dprintk("%d.%d.%d.%d: i2c/spi controller",
				domain, bus, slot, func);
			break;
		case B2_2_2: /* BUS:2 DEV:2 FUNC:2 = ieee1284/rs232 */
			int_line = 0x03;
			Dprintk("%d.%d.%d.%d: ieee1284/rs232 controller",
				domain, bus, slot, func);
			break;
		case B2_2_0: /* BUS:2 DEV:2 FUNC:0 = IDE contr */
			int_line = 0x0b;
			Dprintk("%d.%d.%d.%d: IDE controller",
				domain, bus, slot, func);
			break;
		case B2_1_0: /* BUS:2 DEV:1 FUNC:0 = ETHERNET */
			int_line = 0x0a;
			Dprintk("%d.%d.%d.%d: Ethernet 1Gb controller",
				domain, bus, slot, func);
			break;
		case B1_1_0: /* BUS:1 DEV:1 FUNC:0 = ADC */
			int_line = 0x0a;
			Dprintk("%d.%d.%d.%d: ADC controller",
				domain, bus, slot, func);
			break;
		default:
			bios_pci_read_config_byte(curdev, PCI_INTERRUPT_LINE,
								&int_line);
			Dprintk("%d.%d.%d.%d: does not connect directly "
				"to IOAPIC",
				domain, bus, slot, func);
			break;
		}
		bios_pci_write_config_byte(curdev, PCI_INTERRUPT_LINE,
								int_line);
		Dprintk(": Assign IRQ %d\n", int_line);
	}
#endif	/* CONFIG_E2K_SIC */
}

/** Enumerate the resources on the PCI by calling pci_init
 */
struct bios_pci_bus *pci_enumerate(int domain)
{
	struct bios_pci_bus  *bus_root;
	printk_info("Scanning PCI domain %d (node %d link %d) bus...",
			domain, iohub_domain_to_node(domain),
			iohub_domain_to_link(domain));
	// scan it.
	bus_root = pci_init(domain);
	printk_info("done\n");
	return (bus_root);
}

/** Starting at the root, compute what resources are needed and allocate them.
 * We start memory, prefetchable memory at PCI_MEM_START. I/O starts at
 * PCI_IO_START. Since the assignment is hierarchical we set the values
 * into the pci_root struct.
 */
void pci_configure(struct bios_pci_bus *pci_root)
{
	int domain = bios_pci_domain_nr(pci_root);

	printk_info("Allocating PCI domain %d (node %d link %d) resources...",
		domain, iohub_domain_to_node(domain),
		iohub_domain_to_link(domain));
	pci_root->membase = PCI_MEM_DOMAIN_START(domain);
	pci_root->prefmembase = PCI_MEM_DOMAIN_START(domain);
	pci_root->iobase = PCI_IO_DOMAIN_START(domain);

	compute_allocate_resources(pci_root);
	// now just set things into registers ... we hope ...
	assign_resources(pci_root);
	assign_interrupts(pci_root);
	printk_info("done.\n");
}

/** Starting at the root, walk the tree and enable all devices/bridges. 
 * What really happens is computed COMMAND bits get set in register 4
 */
void pci_enable(struct bios_pci_bus *pci_root)
{
	int domain = bios_pci_domain_nr(pci_root);

	printk_info("Enabling PCI domain %d (node %d link %d) resources...",
		domain, iohub_domain_to_node(domain),
		iohub_domain_to_link(domain));

	// now enable everything.
	enable_resources(pci_root);
	printk_info("done.\n");
}

void pci_zero_irq_settings(void)
{
	struct bios_pci_dev *pcidev;
	unsigned char line;
  
	printk_info("Zeroing PCI IRQ settings...");

	pcidev = pci_devices;
  
	while (pcidev) {
		bios_pci_read_config_byte(pcidev, 0x3d, &line);
		if (line) {
			bios_pci_write_config_byte(pcidev, 0x3c, 0);
		}
		pcidev = pcidev->next;
	}
	printk_info("done.\n");
}

void
handle_superio(int pass, struct superio *all_superio[], int nsuperio)
{
  int i;
  struct superio *s;
  printk_debug("handle_superio start, nsuperio %d\n", nsuperio);
  for(i = 0; i < nsuperio; i++){
      s = all_superio[i];
      printk_debug("handle_superio: Pass %d, check #%d, s %x s->super %x\n",
	  pass, i, s, s->super);
    if (!s->super) {
	printk_debug("handle_superio: Pass %d, Skipping #%d as it has no superio pointer!\n", pass, i);
        continue;
    }
    printk_debug("handle_superio: Pass %d, Superio %s\n", pass, 
	   s->super->name);
    // if no port is assigned use the defaultport
    printk_info("handle_superio: port 0x%x, defaultport 0x%x\n",
	   s->port, s->super->defaultport);
    if (! s->port)
      s->port = s->super->defaultport;

    printk_info("handle_superio: Using port 0x%x\n", s->port);

    // need to have both pre_pci_init and devfn defined.
    if (s->super->pre_pci_init && (pass == 0)) {
      printk_debug("handle_superio: Call pre_pci_init\n");
      s->super->pre_pci_init(s);
    }
    else
      if (s->super->init && (pass == 1)) 
	{
	  printk_debug("  Call init\n");
	  s->super->init(s);
	}
      else
	if (s->super->finishup && (pass == 2))
	  {
	    printk_debug("  Call finishup\n");
	    s->super->finishup(s);
	  }
    printk_debug("handle_superio: Pass %d, done #%d\n", pass, i);
  }
  printk_debug("handle_superio done\n");
}

void
handle_southbridge(int pass, struct southbridge *s, int nsouthbridge)
{
  int i;
  for(i = 0; i < nsouthbridge; i++, s++){
    
    if (!s->southbridge)
      continue;
    printk_debug("handle_southbridge: Pass %d, Superio %s\n", pass, 
	   s->southbridge->name);

    // need to have both pre_pci_init and devfn defined.
    if (s->southbridge->pre_pci_init && (pass == 0) && (s->devfn)) {
      printk_debug("  Call pre_pci_init\n");
      s->southbridge->pre_pci_init(s);
    }
    else
      {
	// first, have to set up any device not set up. 
	// policy: we ignore the devfn here. First, it's in the pcidev, and
	// second, it's really only to be used BEFORE pci config is done. 
	if (!s->device)
		s->device = bios_pci_find_device(s->southbridge->vendor,
						s->southbridge->device, 0);

	if (! s->device) { // not there!
	  printk_info("  No such device\n");
	  continue;
	}
	// problem. We have to handle multiple devices of same type. 
	// We don't do this yet. One way is to mark the pci device used at
	// this point, i.e. 
	// s->device->inuse = 1
	// and then continue looking if the device is in use.
	// For now, let's get this basic thing to work.
	if (s->southbridge->init && (pass == 1)) {
	  printk_debug("  Call init\n");
	  s->southbridge->init(s);
	}
	else
	  if (s->southbridge->finishup && (pass == 2)) {
	    printk_debug("  Call finishup\n");
	    s->southbridge->finishup(s);
	  }
      }
  }
}

void pci_bios(void)
{
	struct bios_pci_bus *pci_root;
	int domain;

	printk_info("Finding PCI configuration type\n");
        pci_set_method();
	for (domain = 0; domain < MAX_NUMIOHUBS; domain ++) {
		if (!(online_iohubs_map & (1 << domain)))
			continue;
		pci_root = pci_enumerate(domain);
		pci_configure(pci_root);
		pci_enable(pci_root);
	}
}

