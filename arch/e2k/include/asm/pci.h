#ifndef _E2K_PCI_H
#define _E2K_PCI_H

#ifdef __KERNEL__

#define HAVE_PCI_LEGACY			1
#define HAVE_MULTIROOT_BUS_PCI_DOMAINS	1	/* each IOHUB has own */
						/* config space */

extern unsigned long pci_mem_start;
#define PCIBIOS_MIN_IO		0x1000
#define PCIBIOS_MIN_MEM		(pci_mem_start)
#define	PCIBIOS_MAX_MEM_32	0xffffffffUL

#define PCIBIOS_MIN_CARDBUS_IO	0x4000

#define	PCI_ARCH_CACHE_LINE_SIZE	32
/* Dynamic DMA mapping stuff.
 * i386 has everything mapped statically.
 */

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <asm/io.h>

/* The PCI address space does equal the physical memory
 * address space.  The networking and block device layers use
 * this boolean for bounce buffer decisions.
 */
#define PCI_DMA_BUS_IS_PHYS	(1)

struct pci_raw_ops {
	int (*read)(unsigned int domain, unsigned int bus, unsigned int devfn,
		    int reg, int len, u32 *val);
	int (*write)(unsigned int domain, unsigned int bus, unsigned int devfn,
		     int reg, int len, u32 val);
};

extern struct pci_raw_ops *raw_pci_ops;

#define HAVE_PCI_MMAP
#define arch_can_pci_mmap_wc()	1

/* generic elbrus pci stuff */
#include <asm-l/pci.h>

/* generic pci stuff */
#include <asm-generic/pci.h>
#endif  /* __KERNEL__ */

#endif /* _E2K_PCI_H */
