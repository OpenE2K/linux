/*
 *	$Id: pci.h,v 1.13 2009/01/27 11:34:42 atic Exp $
 *
 *	PCI defines and function prototypes
 *	Copyright 1994, Drew Eckhardt
 *	Copyright 1997--1999 Martin Mares <mj@atrey.karlin.mff.cuni.cz>
 *
 *	For more information, please consult the following manuals (look at
 *	http://www.pcisig.com/ for how to get them):
 *
 *	PCI BIOS Specification
 *	PCI Local Bus Specification
 *	PCI to PCI Bridge Specification
 *	PCI System Design Guide
 */

#ifndef PCI_H
#define PCI_H

#include <linux/types.h>
#include <linux/pci.h>
#include "../boot_io.h"

extern unsigned char     inb(unsigned long port);
extern u16		 inw(unsigned long port);
extern u32		 inl(unsigned long port);
extern void             outb(unsigned char b,unsigned long port);
extern void             outw(unsigned short w,unsigned long port);
extern void             outl(unsigned int l,unsigned long port);

extern void *malloc(int size);

#undef BIOS_DEBUG
#define PCIBIOS_DEBUG 0

#define BIOS_DEBUG PCIBIOS_DEBUG

#include "printk.h"

#undef	DEBUG_PCI_MODE
#undef	DebugCI
#define	DEBUG_PCI_MODE		0	/* PCI scanning */
#define	DebugPCI(fmt, args...)				\
		({ if (DEBUG_PCI_MODE)			\
			rom_printk(fmt, ##args); })

/*
 * PCI memory and IO ports mapping
 */
#ifdef	CONFIG_E2K_SIC
#define	PCI_IO_START		0x00000000
#define	PCI_IO_DOMAIN_SIZE	0x00002000
#define	PCI_IO_END		0x00010000
#define	PCI_MEM_START		0x80000000
#define	PCI_MEM_DOMAIN_SIZE	0x10000000
#define	PCI_MEM_END		E2K_PCI_MEM_AREA_PHYS_END       // f800_0000

#define	IOHUB_SCRB_DOMAIN_SIZE	E2K_SCRB_SIZE                   // 1000

#define	PCI_IO_DOMAIN_START(domain)     \
		(PCI_IO_START + PCI_IO_DOMAIN_SIZE * (domain))
#define	PCI_IO_DOMAIN_END(domain)					\
({									\
	unsigned long io_end;						\
	io_end = (PCI_IO_DOMAIN_START(domain) + PCI_IO_DOMAIN_SIZE);	\
	if (io_end > PCI_IO_END)					\
		io_end = PCI_IO_END;					\
	io_end;								\
})
#define	PCI_MEM_DOMAIN_START(domain)	\
	(PCI_MEM_START + PCI_MEM_DOMAIN_SIZE * (domain))
#define	PCI_MEM_DOMAIN_END(domain)					\
({									\
	unsigned long mem_end;						\
	mem_end = (PCI_MEM_DOMAIN_START(domain) + PCI_MEM_DOMAIN_SIZE);	\
	if (mem_end > PCI_MEM_END)					\
		mem_end = PCI_MEM_END;					\
	mem_end;							\
})
#define	IOHUB_SCRB_DOMAIN_START(domain) \
		(PCI_MEM_DOMAIN_END(domain) - IOHUB_SCRB_DOMAIN_SIZE)
#define	IOHUB_SCRB_DOMAIN_END(domain)   \
		(PCI_MEM_DOMAIN_END(domain))
#else  /* ! CONFIG_E2K_SIC (e3m or e3m + IOHUB) */
#define PCI_IO_START	0x00001000
#define	PCI_IO_DOMAIN_SIZE	0x0000f000
#define	PCI_IO_END		0x00010000
#define	PCI_MEM_START		0x80000000
#define	PCI_MEM_DOMAIN_SIZE	0x80000000
#define	PCI_MEM_END		PCI_MEM_DOMAIN_SIZE

#define	PCI_IO_DOMAIN_START(domain)	PCI_IO_START
#define	PCI_IO_DOMAIN_END(domain)	PCI_IO_END
#define	PCI_MEM_DOMAIN_START(domain)	PCI_MEM_START
#define	PCI_MEM_DOMAIN_END(domain)	PCI_MEM_END
#endif /* CONFIG_E2K_SIC */


/*
 * Under PCI, each device has 256 bytes of configuration address space,
 * of which the first 64 bytes are standardized as follows:
 */
#ifdef CONFIG_E2K_SIC
/* Additional registers in PCI configuration space for virtual PCI to PCI bridges */
#if	defined(CONFIG_L_IOH2)
/* IOHUB Device Number register */
#define	IOH2_DevNum		0x44	/* IOHUB Device Number */
#define	IOHUB_DevNum		IOH2_DevNum
 #define IOHUB_DevNum_valid	0x0100
 #define set_IOHUB_DevNum(num)	((num) & 0x000f)
#else	/* IOHUB version 1 */
#define PCI_SCBA_0		0xf0	/* System commutator base address [31:00] */
#define PCI_SCBA_1		0xf4	/* System commutator base address [63:32] */
/* IOHUB Device Number register */
#define	IOH_DevNum		0xf8
#define	IOHUB_DevNum		IOH_DevNum
 #define IOHUB_DevNum_valid	0x10
 #define set_IOHUB_DevNum(num)	((num) & 0x0f)
#endif	/* CONFIG_L_IOH2 */

/* Additional registers in PCI configuration space for I2C/SPI controller */
	/** IOAPIC Base Address(SCRB: "ioapic" Mem Base Address Register 0) **/
#define IOAPIC_BASE_ADDRESS		0x40	// [31:5]-RWS [4:0]-RO
	/** IOAPIC Upper Base Address(SCRB: "ioapic" Mem Base Address Register 0 Upper 32 bits) **/	
#define IOAPIC_UPPER_ADDRESS		0x44	
	/** MSI TRANSACTION ADDRESS (SCRB: "ioapic" Mem Base Address Register 1) **/
#define MSI_TRANSACTION_ADDRESS		0x48	// [31:2]-RWS [1:0]-RO
	/** MSI TRANSACTION UPPER ADDRESS(SCRB: "ioapic" Mem Base Address Register 1 Upper 32 bits) **/
#define MSI_TRANSACTION_UPPER_ADDRESS	0x4c
	/** IOPIC Message Base Address(SCRB: "ioapic" Mem Base Address Register 2) **/
#define IOAPIC_MESSAGE_BASE_ADDRESS	0x50	// [31:12]-RWS [11:0]-RO
	/** IOPIC Upper Base Address(SCRB: "ioapic" Mem Base Address Register 2 Upper 32 bits) **/
#define IOAPIC_MESSAGE_UPPER_ADDRESS	0x54
	/** System Timer Base Address(SCRB: "timer" Mem Base Address Register 0) **/
#define SYSTEM_TIMER_BASE_ADDRESS	0x58	// [31:6]-RWS [5:0]-RO
	/** System Timer Upper Base Address(SCRB: "timer" Mem Base Address Register 0 Upper 32 bits) **/
#define SYSTEM_TIMER_UPPER_ADDRESS	0x5c
	/** Reset Control **/
#define RESET_CONTROL			0x60
	/** Software Reset Control **/
#define SOFTWARE_RESET_CONTROL		0x64		
	/** Software Reset Duration **/
#define SOFTWARE_RESET_DURATION		0x68
	/** LAPIC Message Base Address  **/
#define LAPIC_MESSAGE_BASE_ADDRESS	0x6c
	/** LAPIC Message Upper Address  **/
#define LAPIC_MESSAGE_UPPER_ADDRESS	0x70

#define IOAPICINT_BASE		0x13000000
#define SAPICINT_BASE		0x1f000000
#define LAPICINT_BASE		0x17000000

#define	APICINT_SIZE		0x01000000

#define	ES2_LAPICINT_BASE	0x120000000
#define	ES2_IOAPICINT_BASE	0x130000000
#define	ES2_SAPICINT_BASE	0x140000000

#define	E2S_LAPICINT_BASE	ES2_LAPICINT_BASE
#define	E2S_IOAPICINT_BASE	ES2_IOAPICINT_BASE
#define	E2S_SAPICINT_BASE	ES2_SAPICINT_BASE

#define	E8C_LAPICINT_BASE	ES2_LAPICINT_BASE
#define	E8C_IOAPICINT_BASE	ES2_IOAPICINT_BASE
#define	E8C_SAPICINT_BASE	ES2_SAPICINT_BASE

#define	E1CP_EMBEDED_IOAPIC_BASE 0x00000010fec01000
#define	E1CP_LEGACY_NBSR_BASE	 0x0000001100000000
#define	E1CP_LAPICINT_BASE	 0x0000001200000000
#define	E1CP_IOAPICINT_BASE	 0x0000001300000000
#define	E1CP_PMC_BASE		 0x0000001400000000

#endif

#define E3M_MULTIFUNC_VENDOR	PCI_VENDOR_ID_INTEL
#define E3M_MULTIFUNC_DEVICE	0x0002

#define  PCI_BRIDGE_CTL_PARITY	0x01	/* Enable parity detection on secondary interface */
#define  PCI_BRIDGE_CTL_SERR	0x02	/* The same for SERR forwarding */
#define  PCI_BRIDGE_CTL_NO_ISA	0x04	/* Disable bridging of ISA ports */
#define  PCI_BRIDGE_CTL_VGA	0x08	/* Forward VGA addresses */
#define  PCI_BRIDGE_CTL_MASTER_ABORT 0x20  /* Report master aborts */
#define  PCI_BRIDGE_CTL_BUS_RESET 0x40	/* Secondary bus reset */
#define  PCI_BRIDGE_CTL_FAST_BACK 0x80	/* Fast Back2Back enabled on secondary interface */
#ifdef CONFIG_E2K_SIC
/* SCRB registers only for bus after virual bus */
#define B0_SE			0x104	/* 8/0x03 		PCIe brigde Spaces Enable   0:N:0{04} */
#define B0_BN			0x118   /* 32/0x00ffffff	PCIe brigde Bus Number	    0:N:0{0x18-0x1b} */
#define B0_IOBL			0x11c	/* 16/0xf0f0		PCIe bridge I/O Base and 
					 *			Limit Register		    0:N:0{0x1c-0x1d} */
#define B0_IOBLU		0x130	/* 32/0xffffffff	PCIe bridge I/O Base and
					 *			Limit Upper 16 bits	    0:N:0{0x30-0x33} */
#define B0_MBL			0x120	/* 32/0xfff0fff0	PCIe bridge Mem Base and
					 *			Limit Register		    0:N:0{0x20-0x23} */
#define B0_PMBL			0x124	/* 32/0xfff0fff0	PCIe bridge Prefetchable
					 *			Mem Base and Limit Register 0:N:0{0x24-0x27} */
#define	B0_PMBU32		0x128	/* 32/0xffffffff	PCIe bridge Prefetchable
					 *			Memory Base Upper 32 bits   0:N:0{0x28-0x2b} */
#define	B0_PMLU32		0x12c	/* 32/0xffffffff	PCIe bridge Prefetchable
					 *			Memory Limit Upper 32 bits  0:N:0{0x2c-0x2f} */
#define B0_BA0			0x17c	/* 32/0xfffffff0	PCIe bridge Base Address
					 *			Register		    0:N:0{0x7c-0x7f} */
#define B0_BUA0			0x180	/* 32/0xffffffff	PCIe bridge Base Address
					 *			Upper 32 bits		    0:N:0{0x80-0x83} */
#define	B0_BCTRL		0x13e	/* 8/0x03		PCIe bridge control	    0:N:0{0x3e}	     */
#define	B1_SE			0x204	/* 8/0x03		PCI bridge Spaces Enable    m:0:0{0x04}	     */
#define B1_BN			0x218	/* 32/0x00ffffff	PCI bridge Bus Number	    m:0:0{0x18-0x1b} */
#define B1_IOBL			0x21c	/* 16/0xf0f0		PCI bridge I/O Base and
					 *			Limit Register		    m:0:0{0x1c-0x1d} */
#define B1_IOBLU		0x230   /* 32/0xffffffff        PCI bridge I/O Base and
					 *			Limit Upper 16 bits	    m:0:0{0x30-0x33} */
#define B1_MBL			0x220	/* 32/0xfff0fff0        PCI bridge Mem Base and
					 *			Limit Register		    m:0:0{0x20-0x23} */
#define B1_PMBL		        0x224   /* 32/0xfff0fff0	PCI bridge Prefetchable
					 *			Mem Base and Limit Register m:0:0{0x24-0x27} */
#define B1_PMBU32	        0x228   /* 32/0xffffffff	PCI bridge Prefetchable
					 *			Memory Base Upper 32 bits   m:0:0{0x28-0x2b} */
#define B1_PMLU32	        0x22c   /* 32/0xffffffff	PCI bridge Prefetchable
					 *			Memory Limit Upper 32 bits  m:0:0{0x2c-0x2f} */
#define B1_BCTRL		0x23e   /* 8/0x1c		PCI bridge control	    m:0:0{0x3e}      */	
#define A0_SE			0x304	/* 8/0x02		"AC97" Mem Space Enable     m:2:3{0x04}      */  
#define A0_BA0			0x310   /* 32/0xfffff000	"AC97" Mem Base Address
					 *			Register 0		    m:2:3{0x10-0x13} */
#define A0_BA1			0x314	/* 32/0xfffff000	"gpio" Mem Base Address
					 *			Register 1		    m:2:3{0x14-0x17} */
#define A1_SE			0x404   /* 8/0x02		"i2c/spi/ioapic" Mem Space
					 *			Enable   		    m:2:1{0x04}	     */
#define A1_BA0			0x410   /* 32/0xffffffc0	"i2c/spi" Mem Base Address
					 *			Register 0		    m:2:1{0x10-0x13} */
#define A1_BA1			0x414   /* 32/0xffffffc0	"i2c/spi" Mem Base Address
					 *			Register 1		    m:2:1{0x14-0x17} */
#define A2_BA0			0x440   /* 32/0xffffffe0        "ioapic"  Mem Base Address
					 *			Register 0		    m:2:1{0x40-0x43} */
#define A2_BUA0			0x444   /* 32/0xffffffff        "ioapic"  Mem Base Address 0
					 *			Upper 32 bits		    m:2:1{0x44-0x47} */
#define A2_BA1			0x448   /* 32/0xfffffffc        "ioapic"  Mem Base Address
					 *			Register 1		    m:2:1{0x48-0x4b} */
#define A2_BUA1			0x44c   /* 32/0xffffffff        "ioapic"  Mem Base Address 1
					 *			Upper 32 bits		    m:2:1{0x4c-0x4f} */
#define A2_BA2			0x450   /* 32/0xfffff000        "ioapic"  Mem Base Address
					 *			Register 2		    m:2:1{0x50-0x53} */
#define A2_BUA2			0x454   /* 32/0xffffffff        "ioapic"  Mem Base Address 2
					 *			Upper 32 bits		    m:2:1{0x54-0x57} */
#define A3_BA0			0x458   /* 32/0xffffffc0        "timer"   Mem Base Address
					 *			Register 0		    m:2:1{0x58-0x5b} */
#define A3_BUA0			0x45c   /* 32/0xffffffff        "timer"   Mem Base Address 
					 *			Upper 32 bits		    m:2:1{0x5c-0x5f} */
#define A4_SE			0x504   /* 8/0x02		"eth"     Mem Space Enable  m:1:0{0x04}	     */
#define A4_BA0			0x510   /* 32/0xffffffe0        "eth"     Mem Base Address
					 *			Register		    m:1:0{0x10-0x13} */
#define A5_SE			0x604   /* 8/0x03		"parport/rs232" Spaces 
					 *			Enable  		    m:2:2{0x04}	     */
#define A5_BA0			0x610   /* 32/0xffffffe0        "parport" IO Base Address
					 *			Register		    m:2:2{0x10-0x13} */
#define A6_BA0			0x614   /* 32/??        	"rs232"   Mem Base Address
					 *			Register		    m:2:2{0x14-0x17} */
#define A7_SE			0x704   /* 8/0x03		"IDE"     Spaces Enable     m:2:0{0x04}	     */
#define A7_AMR			0x709	/* 8/0x05               "IDE" Addressing Mode
					 *			Register		    m:2:0{0x09}	     */
#define A7_BA0			0x710   /* 32/0xfffffff8        "IDE"     IO Base Address
					 *			Register 0		    m:2:0{0x10-0x13} */
#define A7_BA1			0x714   /* 32/0xfffffffc        "IDE"     IO Base Address
					 *			Register 1		    m:2:0{0x14-0x17} */
#define A7_BA2			0x718   /* 32/0xfffffff8        "IDE"     IO Base Address
					 *			Register 2		    m:2:0{0x18-0x1b} */
#define A7_BA3			0x71c   /* 32/0xfffffffc        "IDE"     IO Base Address
					 *			Register 3		    m:2:0{0x1c-0x1f} */
#define A7_BA4			0x720   /* 32/0x0000fff0        "IDE"     IO Base Address
					 *			Register 4		    m:2:0{0x20-0x23} */
#define A7_HCE			0x750   /* 8/0x40        	"IDE"     Hidden Channel
					 *			Enable		    	    m:2:0{0x50}      */
#define A7_BA5			0x758   /* 32/0xffffffe0        "IDE"     Mem Base Address
					 *			Register 5		    m:2:0{0x58-0x5b} */
#define A7_BUA5			0x75c   /* 32/0xffffffff        "IDE"     Mem Base Address 5
					 *			Upper 32 bits		    m:2:0{0x5c-0x5f} */
#define A7_BA6			0x760   /* 32/0xfffffff0        "IDE"     Mem Base Address
					 *			Register 6		    m:2:0{0x60-0x63} */
#define A7_BUA6			0x764   /* 32/0xffffffff        "IDE"     Mem Base Address 6
					 *			Upper 32 bits		    m:2:0{0x64-0x67} */
#define A7_BA7			0x768   /* 32/0xfffffff0        "IDE"     Mem Base Address
					 *			Register 7		    m:2:0{0x68-0x6b} */
#define A7_BUA7			0x76c   /* 32/0xffffffff        "IDE"     Mem Base Address 7
					 *			Upper 32 bits		    m:2:0{0x6c-0x6f} */
/* Control Register */
#define AHOM			0xa00   /*			Abonent Hide Operation Mode	R/W	     */	

/* Registers for Real Pci 2 Pci Bridge */
#define Arb_CtlSta		0x78	/* Arbitration Control (Real Pci 2 Pci Configuration Space) */	
#endif


/*
 * There is one bios_pci_dev structure for each slot-number/function-number
 * combination:
 */
struct bios_pci_dev {
	struct bios_pci_bus	*bus;		/* bus this device is on */
	struct bios_pci_dev	*sibling;	/* next device on this bus */
	struct bios_pci_dev	*next;		/* chain of all devices */

	void		*sysdata;	/* hook for sys-specific extension */
	struct proc_dir_entry *procent;	/* device entry in /proc/bus/pci */

	unsigned int	devfn;		/* encoded device & function index */
	unsigned short	vendor;
	unsigned short	device;
	unsigned char	revision;	/* chip revision */
	unsigned int	class;		/* 3 bytes: (base,sub,prog-if) */
	unsigned char	subsys_id;	/* subsystem ID */
	unsigned int	hdr_type;	/* PCI header type */
	unsigned int	master : 1;	/* set if device is master capable */
	u8 command;
	/*
	 * In theory, the irq level can be read from configuration
	 * space and all would be fine.  However, old PCI chips don't
	 * support these registers and return 0 instead.  For example,
	 * the Vision864-P rev 0 chip can uses INTA, but returns 0 in
	 * the interrupt line and pin registers.  pci_init()
	 * initializes this field with the value at PCI_INTERRUPT_LINE
	 * and it is the job of pcibios_fixup() to change it if
	 * necessary.  The field must not be 0 unless the device
	 * cannot generate interrupts at all.
	 */
	unsigned int	irq;		/* irq generated by this device */

	/* Base registers for this device, can be adjusted by
	 * pcibios_fixup() as necessary.
	 */
	unsigned long	base_address[6];
	unsigned long   size[6];
	unsigned long	rom_address;
	unsigned long	rom_size;
};

struct bios_pci_bus {
	struct bios_pci_bus *parent;	/* parent bus this bridge is on */
	struct bios_pci_bus *children;	/* chain of P2P bridges on this bus */
	struct bios_pci_bus *next;	/* chain of all PCI buses */

	struct bios_pci_dev *self;	/* bridge device as seen by parent */
	struct bios_pci_dev *devices;	/* devices behind this bridge */

	void		*sysdata;	/* hook for sys-specific extension */
	struct proc_dir_entry *procdir;	/* directory entry in /proc/bus/pci */
	unsigned char	number;		/* bus number */
	unsigned char	primary;	/* number of primary bridge */
	unsigned char	secondary;	/* number of secondary bridge */
	unsigned char	subordinate;	/* max number of subordinate buses */

	unsigned long mem, prefmem, io;	/* amount of mem, prefetch mem,
					 * and I/O needed for this bridge. 
					 * computed by compute_resources, 
					 * inclusive of all child bridges
					 * and devices 
					 */
	u32 membase, memlimit;
	u32 prefmembase, prefmemlimit;
	u32 iobase, iolimit;
};

extern struct bios_pci_bus  pci_root[];		/* root buses */
extern int pci_root_num;
extern struct bios_pci_dev *pci_devices;	/* list of all devices */

#ifdef CONFIG_E2K_SIC
static inline int bios_pci_domain_nr(struct bios_pci_bus *bus)
{
	return ((unsigned long)bus->sysdata);
}
static inline void bios_set_pci_domain_nr(struct bios_pci_bus *bus, int domain)
{
	bus->sysdata = (void *)domain;
}
#else  /* ! CONFIG_E2K_SIC */
#define	bios_pci_domain_nr(bus)	(0)
#define	bios_set_pci_domain_nr(bus, domain)
#endif /* CONFIG_E2K_SIC */

/*
 * Error values that may be returned by the PCI bios.
 */
#define PCIBIOS_SUCCESSFUL		0x00
#define PCIBIOS_FUNC_NOT_SUPPORTED	0x81
#define PCIBIOS_BAD_VENDOR_ID		0x83
#define PCIBIOS_DEVICE_NOT_FOUND	0x86
#define PCIBIOS_BAD_REGISTER_NUMBER	0x87
#define PCIBIOS_SET_FAILED		0x88
#define PCIBIOS_BUFFER_TOO_SMALL	0x89

/* Class Code register */
#define	NATIVE_MODE_PRIMARY_CLASSC	0x01	/* primary channel in native */
						/* mode */
#define	NATIVE_MODE_SECONDARY_CLASSC	0x04	/* secondary channel in */
						/* native mode */
#define	NATIVE_MODE_CLASSC		(NATIVE_MODE_PRIMARY_CLASSC | \
						NATIVE_MODE_SECONDARY_CLASSC)

/* Low-level architecture-dependent routines */

int pcibios_present (void);
void pcibios_init(void);
void pcibios_fixup(void);
char *pcibios_setup (char *str);
int bios_pci_read_config_byte(struct bios_pci_dev *dev, u8 where, u8 *val);
int bios_pci_read_config_word(struct bios_pci_dev *dev, u8 where, u16 *val);
int bios_pci_read_config_dword(struct bios_pci_dev *dev, u8 where, u32 *val);
int bios_pci_write_config_byte(struct bios_pci_dev *dev, u8 where, u8 val);
int bios_pci_write_config_word(struct bios_pci_dev *dev, u8 where, u16 val);
int bios_pci_write_config_dword(struct bios_pci_dev *dev, u8 where, u32 val);
int pcibios_read_config_byte(int domain, unsigned char bus, unsigned char dev_fn,
			      unsigned char where, u8 *val);
int pcibios_read_config_word(int domain, unsigned char bus, unsigned char dev_fn,
			      unsigned char where, u16 *val);
int pcibios_read_config_dword(int domain, unsigned char bus, unsigned char dev_fn,
			       unsigned char where, u32 *val);
int pcibios_write_config_byte(int domain, unsigned char bus, unsigned char dev_fn,
			       unsigned char where, u8 val);
int pcibios_write_config_word(int domain, unsigned char bus, unsigned char dev_fn,
			       unsigned char where, u16 val);
int pcibios_write_config_dword(int domain, unsigned char bus, unsigned char dev_fn,
				unsigned char where, u32 val);
int pcibios_debugwrite_config_byte(int domain, unsigned char bus, unsigned char dev_fn,
			       unsigned char where, u8 val);
int pcibios_debugwrite_config_word(int domain, unsigned char bus, unsigned char dev_fn,
			       unsigned char where, u16 val);
int pcibios_debugwrite_config_dword(int domain, unsigned char bus, unsigned char dev_fn,
				unsigned char where, u32 val);

#ifdef CONFIG_E2K_SIC
#ifndef	CONFIG_L_IOH2
int system_commutator_e3s_ioh_write_byte(int domain, unsigned char bus,
							int where, u8 value);
int system_commutator_e3s_ioh_read_byte(int domain, unsigned char bus,
							int where, u8 *value);
int system_commutator_e3s_ioh_write_word(int domain, unsigned char bus,
							int where, u16 value);
int system_commutator_e3s_ioh_read_word(int domain, unsigned char bus,
							int where, u16 *value);
int system_commutator_e3s_ioh_write_dword(int domain, unsigned char bus,
							int where, u32 value);
int system_commutator_e3s_ioh_read_dword(int domain, unsigned char bus,
							int where, u32 *value);
#else	/* CONFIG_L_IOH2 */
/* IOHUB #2 has not SCRB registers to read/write */
#define system_commutator_e3s_ioh_write_byte(domain, bus, where, value)	0
#define system_commutator_e3s_ioh_read_byte(domain, bus, where, value)	0
#define system_commutator_e3s_ioh_write_word(domain, bus, where, value)	0
#define system_commutator_e3s_ioh_read_word(domain, bus, where, value)	0
#define system_commutator_e3s_ioh_write_dword(domain, bus, where, value) 0
#define system_commutator_e3s_ioh_read_dword(domain, bus, where, value)	0
#endif	/* ! CONFIG_L_IOH2 */
#endif /* CONFIG_E2K_SIC */


/* Don't use these in new code, use pci_find_... instead */

int pcibios_find_class (unsigned int class_code, unsigned short index, unsigned char *bus, unsigned char *dev_fn);
int pcibios_find_device (unsigned short vendor, unsigned short dev_id,
			 unsigned short index, unsigned char *bus,
			 unsigned char *dev_fn);

/* Generic PCI interface functions */

struct bios_pci_bus *pci_init(int domain);
void pci_setup(char *str, int *ints);
void pci_quirks_init(void);
void pci_proc_init(void);
void proc_old_pci_init(void);
int get_pci_list(char *buf);
int pci_proc_attach_device(struct bios_pci_dev *dev);
int pci_proc_detach_device(struct bios_pci_dev *dev);

struct bios_pci_dev *bios_pci_find_device(unsigned int vendor,
				unsigned int device, struct bios_pci_dev *from);
struct bios_pci_dev *pci_find_class(unsigned int class,
					struct bios_pci_dev *from);
struct bios_pci_dev *pci_find_slot(unsigned int bus, unsigned int devfn);

#define pci_present pcibios_present
int pci_debugwrite_config_byte(struct bios_pci_dev *dev, u8 where, u8 val);
int pci_debugwrite_config_word(struct bios_pci_dev *dev, u8 where, u16 val);
int pci_debugwrite_config_dword(struct bios_pci_dev *dev, u8 where, u32 val);
void bios_pci_set_master(struct bios_pci_dev *dev);
void pci_set_method(void);
struct bios_pci_bus *pci_enumerate(int domain);
void pci_configure(struct bios_pci_bus *root_bus);
void pci_enable(struct bios_pci_bus *root_bus);
void pci_zero_irq_settings(void);

// historical functions ...
void intel_conf_writeb(unsigned long port, unsigned char value);
unsigned char intel_conf_readb(unsigned long port);

#ifdef CONFIG_E2K_SIC
static inline void set_iohub_dev_num(int domain)
{
	int devfn;
	unsigned int reg;

	reg = set_IOHUB_DevNum(domain) | IOHUB_DevNum_valid;
#ifdef	CONFIG_L_IOH2
	devfn = domain * 8;
	pcibios_write_config_word(domain, 0, devfn, IOHUB_DevNum, (u16)reg);
	pcibios_read_config_word(domain, 0, devfn, IOHUB_DevNum, (u16 *)&reg);
#else	/* IOHUB-1 */
	devfn = (domain * 2 + 1) * 8; /* slot #0 PCIe, #1: virt PCI to PCI */
	pcibios_write_config_byte(domain, 0, devfn, IOHUB_DevNum, (u8)reg);
	pcibios_read_config_byte(domain, 0, devfn, IOHUB_DevNum, (u8 *)&reg);
#endif	/* CONFIG_L_IOH2 */
	DebugPCI("set_iohub_dev_num() set device number to 0x%04x\n", reg);
}
#else	/* ! CONFIG_E2K_SIC */
#define	set_iohub_dev_num(domain)
#endif	/* CONFIG_E2K_SIC */

//#include <linux/vmalloc.h>

// Rounding for boundaries. 
// Due to some chip bugs, go ahead and roung IO to 16
#define IO_ALIGN 16 
#define IO_BRIDGE_ALIGN 4096
#define MEM_ALIGN 4096

#include "pciconf.h"

/* linkages from devices of a type (e.g. superio devices) 
 * to the actual physical PCI device. This type is used in an array of 
 * structs built by NLBConfig.py. We owe this idea to Plan 9.
 */

struct superio;

struct superio_control {
  void (*pre_pci_init)(struct superio *s);
  void (*init)(struct superio *s);
  void (*finishup)(struct superio *s);
  unsigned int defaultport;     /* the defaultport. Can be overridden
				 * by commands in config
				 */
  // This is the print name for debugging
  char *name;
};

struct com_ports {
  unsigned int enable,baud, base, irq;
};

// lpt port description. 
// Note that for many superios you only really need to define the 
// enable. 
struct lpt_ports {
	unsigned int enable, // 1 if this port is enabled
		     mode,   // pp mode
		     base,   // IO base of the parallel port 
                     irq;    // irq
};

struct superio {
	struct superio_control *super; // the ops for the device. 
	unsigned int port; // if non-zero, overrides the default port
	// com ports. This is not done as an array (yet). 
	// We think it's easier to set up from python if it is not an array. 
	struct com_ports com1, com2, com3, com4;
	// DMA, if it exists. 
	struct lpt_ports lpt1, lpt2;
	/* flags for each device type. Unsigned int. */
	// low order bit ALWAYS means enable. Next bit means to enable
	// LPT is in transition, so we leave this here for the moment. 
	// The winbond chips really stretched the way this works. 
	// so many functions!
	unsigned int ide, floppy, lpt;
	unsigned int keyboard, cir, game;
	unsigned int gpio1, gpio2, gpio3;
	unsigned int acpi,hwmonitor;
};

struct southbridge;

struct southbridge_control {
  void (*pre_pci_init)(struct southbridge *s);
  void (*init)(struct southbridge *s);
  void (*finishup)(struct southbridge *s);
  // this is the  vendor and device id
  unsigned int vendor, device;
  // This is the print name for debugging
  char *name;
};

struct southbridge {
	struct bios_pci_dev *device;	/* the device. */
	struct southbridge_control *southbridge; /* the ops for the device. */
	unsigned int devfn;	/* the devfn.
				 * if devfn is known, the device can be
				 * configured for PCI discovery.
				 * this is needed for some devices
				 * such as acer m1535
				 */
	/* flags for each device type. Unsigned int.
	 * low order bit ALWAYS means enable. Next bit means to enable
	 * DMA, if it exists.
	 */
	unsigned int ide;
};

#endif /* PCI_H */




