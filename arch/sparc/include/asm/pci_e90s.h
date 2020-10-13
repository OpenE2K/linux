#ifndef __SPARC64_PCI_E90S_H
#define __SPARC64_PCI_E90S_H

#ifdef __KERNEL__
#include <asm/e90s.h>

#define HAVE_PCI_MMAP
#define HAVE_PCI_LEGACY			1
#define HAVE_COMMONROOT_BUS_PCI_DOMAINS	1	/* all IOHUBs accessed */
						/* through common root */
						/* bus #0 */

int pci_mmap_page_range(struct pci_dev *dev, struct vm_area_struct *vma,
			enum pci_mmap_state mmap_state, int write_combine);
extern int pci_legacy_read(struct pci_bus *bus, loff_t port, u32 *val,
			   size_t count);
extern int pci_legacy_write(struct pci_bus *bus, loff_t port, u32 val,
			    size_t count);
extern int pci_mmap_legacy_page_range(struct pci_bus *bus,
				      struct vm_area_struct *vma,
				      enum pci_mmap_state mmap_state);

extern void
pcibios_resource_to_bus(struct pci_bus *dev, struct pci_bus_region *region,
			struct resource *res);
extern void
pcibios_bus_to_resource(struct pci_bus *dev, struct resource *res,
			struct pci_bus_region *region);

#define PCIBIOS_MIN_IO		0UL
#define PCIBIOS_MIN_MEM		0UL

extern void pci_config_read8(u8 *addr, u8 *ret);
extern void pci_config_read16(u16 *addr, u16 *ret);
extern void pci_config_read32(u32 *addr, u32 *ret);
extern void pci_config_write8(u8 *addr, u8 val);
extern void pci_config_write16(u16 *addr, u16 val);
extern void pci_config_write32(u32 *addr, u32 val);
#define conf_inb(domain, bus, port, val)	\
		pci_config_read8((u8 *)(PCI_CONFIG_BASE + (port)), val)
#define conf_inw(domain, bus, port, val)	\
		pci_config_read16((u16 *)(PCI_CONFIG_BASE + (port)), val)
#define conf_inl(domain, bus, port, val)	\
		pci_config_read32((u32 *)(PCI_CONFIG_BASE + (port)), val)
#define	conf_outb(domain, bus, port, val)	\
		pci_config_write8((u8 *)(PCI_CONFIG_BASE + (port)), val)
#define conf_outw(domain, bus, port, val)	\
		pci_config_write16((u16 *)(PCI_CONFIG_BASE + (port)), val)
#define conf_outl(domain, bus, port, val)	\
		pci_config_write32((u32 *)(PCI_CONFIG_BASE + (port)), val)


#define	PCI_ARCH_CACHE_LINE_SIZE	SMP_CACHE_BYTES_SHIFT
#define PCI_DMA_BUS_IS_PHYS	(0)
#define PCI_IRQ_NONE		0xffffffff

static inline int pci_get_legacy_ide_irq(struct pci_dev *dev, int channel)
{
	return PCI_IRQ_NONE;
}

#include <asm-l/pci.h>

#endif /* __KERNEL__ */

#endif /* __SPARC64_PCI_E90S_H */
