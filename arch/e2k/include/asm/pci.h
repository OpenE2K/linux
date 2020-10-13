#ifndef _E2K_PCI_H
#define _E2K_PCI_H

#ifdef __KERNEL__


#define HAVE_PCI_LEGACY			1
#define HAVE_MULTIROOT_BUS_PCI_DOMAINS	1	/* each IOHUB has own */
						/* config space */

extern int pci_legacy_read(struct pci_bus *bus, loff_t port, u32 *val,
			   size_t count);
extern int pci_legacy_write(struct pci_bus *bus, loff_t port, u32 val,
			    size_t count);
extern int pci_mmap_legacy_page_range(struct pci_bus *bus,
				      struct vm_area_struct *vma,
				      enum pci_mmap_state mmap_state);

extern unsigned long pci_mem_start;
#define PCIBIOS_MIN_IO		0x1000
#define PCIBIOS_MIN_MEM		(pci_mem_start)

#define PCIBIOS_MIN_CARDBUS_IO	0x4000

#define	PCI_ARCH_CACHE_LINE_SIZE	32
/* Dynamic DMA mapping stuff.
 * i386 has everything mapped statically.
 */

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/scatterlist.h>
#include <linux/string.h>
#include <asm/io.h>

struct pci_dev;

/* The PCI address space does equal the physical memory
 * address space.  The networking and block device layers use
 * this boolean for bounce buffer decisions.
 */
#define PCI_DMA_BUS_IS_PHYS	(1)

/* This is always fine. */
#define pci_dac_dma_supported(pci_dev, mask)	(1)

struct pci_raw_ops {
	int (*read)(unsigned int domain, unsigned int bus, unsigned int devfn,
		    int reg, int len, u32 *val);
	int (*write)(unsigned int domain, unsigned int bus, unsigned int devfn,
		     int reg, int len, u32 val);
};

extern struct pci_raw_ops *raw_pci_ops;

static inline dma_addr_t
pci_dac_page_to_dma(struct pci_dev *pdev, struct page *page, unsigned long offset, int direction)
{
	return (dma_addr_t) page_to_phys(page) +
		(dma_addr_t) offset;
}

static inline struct page *
pci_dac_dma_to_page(struct pci_dev *pdev, dma_addr_t dma_addr)
{
	return pfn_to_page(dma_addr >> PAGE_SHIFT);
}

static inline unsigned long
pci_dac_dma_to_offset(struct pci_dev *pdev, dma_addr_t dma_addr)
{
	return dma_addr & ~PAGE_MASK;
}

static inline void
pci_dac_dma_sync_single_for_cpu(struct pci_dev *pdev, dma_addr_t dma_addr,
				size_t len, int direction)
{
}

static inline void
pci_dac_dma_sync_single_for_device(struct pci_dev *pdev, dma_addr_t dma_addr,
					size_t len, int direction)
{
	flush_write_buffers();
}

#define HAVE_PCI_MMAP
extern int pci_mmap_page_range(struct pci_dev *dev, struct vm_area_struct *vma,
			       enum pci_mmap_state mmap_state,
				int write_combine);


#ifdef CONFIG_PCI
static inline void pci_dma_burst_advice(struct pci_dev *pdev,
					enum pci_dma_burst_strategy *strat,
					unsigned long *strategy_parameter)
{
	*strat = PCI_DMA_BURST_INFINITY;
	*strategy_parameter = ~0UL;
}
#endif /* CONFIG_PCI */

/* generic elbrus pci stuff */
#include <asm-l/pci.h>

/* implement the pci_ DMA API in terms of the generic device dma_ one */
#include <asm-generic/pci-dma-compat.h>

/* generic pci stuff */
#include <asm-generic/pci.h>
#endif  /* __KERNEL__ */

#endif /* _E2K_PCI_H */
