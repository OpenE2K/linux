#ifndef _L_PCI_H
#define _L_PCI_H

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
#define	L_IOHUB_SLOTS_NUM	2	/* number of slots (devfns) for */
					/* each IOHUB on root bus */
#define	SLOTS_PER_L_IOHUB	4	/* number of slots reserved per */
					/* each IOHUB */

extern int IOHUB_revision;
extern unsigned int pci_probe;
extern unsigned long pirq_table_addr;

typedef struct iohub_sysdata {
#ifdef CONFIG_IOHUB_DOMAINS
	int	domain;		/* IOHUB (PCI) domain */
	int	node;		/* NUMA node */
	int	link;		/* local number of IO link on the node */
#endif /* CONFIG_IOHUB_DOMAINS */
	u32	pci_msi_addr_lo;	/* MSI transaction address */
	u32	pci_msi_addr_hi;	/* MSI transaction upper address */
	u8	revision;	/* IOHUB revision */
	u8	generation;	/* IOHUB generation */
} iohub_sysdata_t;

static inline u8 iohub_revision(const struct pci_dev *pdev)
{
	struct iohub_sysdata *sd = pdev->bus->sysdata;
	return sd->revision >> 1;
}
static inline u8 iohub_generation(const struct pci_dev *pdev)
{
	struct iohub_sysdata *sd = pdev->bus->sysdata;
	return sd->generation;
}

#ifdef CONFIG_IOHUB_DOMAINS

static inline int pci_domain_nr(struct pci_bus *bus)
{
	struct iohub_sysdata *sd = bus->sysdata;
	return sd->domain;
}

static inline int pci_proc_domain(struct pci_bus *bus)
{
	return pci_domain_nr(bus);
}
static inline int pci_iohub_domain_to_slot(const int domain)
{
	return L_IOHUB_ROOT_SLOT + domain * SLOTS_PER_L_IOHUB;
}
/* Returns the node based on pci bus */
static inline int __pcibus_to_node(const struct pci_bus *bus)
{
	const struct iohub_sysdata *sd = bus->sysdata;

	return sd->node;
}
static inline int __pcibus_to_link(const struct pci_bus *bus)
{
	const struct iohub_sysdata *sd = bus->sysdata;

	return sd->link;
}
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

/* MSI arch hook */

#define arch_teardown_msi_irq native_teardown_msi_irq
#define arch_setup_msi_irqs native_setup_msi_irqs


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



#endif /* __KERNEL__ */

#endif /* _L_PCI_H */
