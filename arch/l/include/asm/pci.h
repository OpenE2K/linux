#ifndef _L_PCI_H
#define _L_PCI_H

#if !defined ___ASM_SPARC_PCI_H && !defined _E2K_PCI_H
# error Do not include "asm-l/pci.h" directly, use "linux/pci.h" instead
#endif

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>

#ifdef __KERNEL__

#define PCI_PROBE_BIOS		0x0001
#define PCI_PROBE_CONF1		0x0002
#define PCI_PROBE_CONF2		0x0004
#define PCI_PROBE_MMCONF	0x0008
#define PCI_PROBE_L		0x0010
#define PCI_PROBE_MASK		0x001f

#define PCI_NO_SORT		0x0100
#define PCI_BIOS_SORT		0x0200
#define PCI_NO_CHECKS		0x0400
#define PCI_USE_PIRQ_MASK	0x0800
#define PCI_ASSIGN_ROMS		0x1000
#define PCI_BIOS_IRQ_SCAN	0x2000
#define PCI_ASSIGN_ALL_BUSSES	0x4000

#undef	CONFIG_CMD
#define CONFIG_CMD(bus, devfn, where)  	\
		((bus&0xFF)<<20)|((devfn&0xFF)<<12)|(where&0xFFF)

#define	L_IOHUB_ROOT_BUS_NUM	0x00
#define	L_IOHUB_ROOT_SLOT	0x00	/* BSP IOHUB start slot (devfn) */
					/* on root bus 0 */
#define	SLOTS_PER_L_IOHUB	4	/* number of slots reserved per */
					/* each IOHUB */

#ifndef L_IOHUB_SLOTS_NUM
#define	L_IOHUB_SLOTS_NUM	2	/* number of slots (devfns) for */
					/* each IOHUB on root bus */
#endif

extern int IOHUB_revision;
static inline int is_prototype(void)
{
	return IOHUB_revision >= 0xf0;
}

extern unsigned long pirq_table_addr;
struct e2k_iommu;
struct pci_dev;
struct pci_bus;
enum pci_mmap_state;
struct pci_ops;

typedef struct iohub_sysdata {
#ifdef CONFIG_IOHUB_DOMAINS
	int	domain;		/* IOHUB (PCI) domain */
	int	node;		/* NUMA node */
	int	link;		/* local number of IO link on the node */
#endif /* CONFIG_IOHUB_DOMAINS */
	u32	pci_msi_addr_lo; /* MSI transaction address */
	u32	pci_msi_addr_hi;/* MSI transaction upper address */
	/*IOHUB can be connected to EIOHUB and vice versa */
	bool	has_iohub;
	u8	iohub_revision;		/* IOHUB revision */
	u8	iohub_generation;	/* IOHUB generation */
	bool	has_eioh;
	u8	eioh_generation;	/* EIOHUB generation */
	u8	eioh_revision;		/* EIOHUB revision */

	struct resource		mem_space; /* pci registers memory */
	void *l_iommu;
} iohub_sysdata_t;

bool l_eioh_device(struct pci_dev *pdev);

#define iohub_revision(pdev)	({				\
	struct iohub_sysdata *sd = pdev->bus->sysdata;		\
	u8 rev = l_eioh_device(pdev) ? sd->eioh_revision :	\
					sd->iohub_revision;	\
	(rev >> 1);						\
})

#define iohub_generation(pdev)	({			\
	struct iohub_sysdata *sd = pdev->bus->sysdata;	\
	(l_eioh_device(pdev) ? sd->eioh_generation :	\
				sd->iohub_generation);	\
})

#ifdef CONFIG_IOHUB_DOMAINS

#define pci_domain_nr(bus)	({			\
	struct iohub_sysdata *sd = bus->sysdata;	\
	sd->domain;					\
})

#define pci_proc_domain(bus) pci_domain_nr(bus)

static inline int pci_iohub_domain_to_slot(const int domain)
{
	return L_IOHUB_ROOT_SLOT + domain * SLOTS_PER_L_IOHUB;
}
/* Returns the node based on pci bus */
#define __pcibus_to_node(bus)	({			\
	const struct iohub_sysdata *sd = bus->sysdata;	\
	sd->node;					\
})
#define __pcibus_to_link(bus)	({			\
	const struct iohub_sysdata *sd = bus->sysdata;	\
	sd->link;					\
})

#else  /* ! CONFIG_IOHUB_DOMAINS */
#define        __pcibus_to_node(bus)   0       /* only one IOHUB on node #0 */
#define        __pcibus_to_link(bus)   0
#endif /* CONFIG_IOHUB_DOMAINS */

/* Can be used to override the logic in pci_scan_bus for skipping
   already-configured bus numbers - to be used for buggy BIOSes
   or architectures with incomplete PCI setup by the loader */

#ifdef CONFIG_PCI
extern unsigned int pcibios_assign_all_busses(void);
#else
#define pcibios_assign_all_busses()	0
#endif
#define pcibios_scan_all_fns(a, b)	0

/* the next function placed at drivers/pci/probe.c and updated only to */
/* support commonroot bus domains */
unsigned int pci_scan_root_child_bus(struct pci_bus *bus);

struct pci_bus * pcibios_scan_root(int bus);

/* scan a bus after allocating a iohub_sysdata for it */
extern struct pci_bus *pci_scan_bus_on_node(int busno, struct pci_ops *ops,
					int node);

void __init pcibios_fixup_resources(struct pci_bus *pbus);
int pcibios_enable_resources(struct pci_dev *, int);

void pcibios_set_master(struct pci_dev *dev);
void pcibios_penalize_isa_irq(int irq, int active);
int l_pci_direct_init(void);

extern int (*pcibios_enable_irq)(struct pci_dev *dev);
extern void (*pcibios_disable_irq)(struct pci_dev *dev);

extern raw_spinlock_t pci_config_lock;

extern int pci_legacy_read(struct pci_bus *bus, loff_t port, u32 *val,
				size_t count);
extern int pci_legacy_write(struct pci_bus *bus, loff_t port, u32 val,
				size_t count);
extern int pci_mmap_legacy_page_range(struct pci_bus *bus,
					struct vm_area_struct *vma,
					enum pci_mmap_state mmap_state);

#ifndef	L_IOPORT_RESOURCE_OFFSET
#define	L_IOPORT_RESOURCE_OFFSET	0UL
#endif
#ifndef	L_IOMEM_RESOURCE_OFFSET
#define	L_IOMEM_RESOURCE_OFFSET		0UL
#endif

#endif /* __KERNEL__ */

#endif /* _L_PCI_H */
