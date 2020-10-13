/*
 * numa.c - Low-level PCI access for NUMA-Q machines
 */

#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/slab.h>

#include <asm/iolinkmask.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/mpspec.h>
#include <linux/module.h>

#include "pci.h"

/**************************** DEBUG DEFINES *****************************/
#undef	DEBUG_PCI_MODE
#undef	DebugPCI
#define	DEBUG_PCI_MODE		0	/* PCI init */
#define	DebugPCI		if (DEBUG_PCI_MODE) printk
/************************************************************************/

/*
 * IO Links of all nodes configuration
 */
int		iolinks_num = 0;
iolinkmask_t	iolink_iohub_map = IOLINK_MASK_NONE;
iolinkmask_t	iolink_online_iohub_map = IOLINK_MASK_NONE;
int		iolink_iohub_num = 0;
int		iolink_online_iohub_num = 0;
iolinkmask_t	iolink_rdma_map = IOLINK_MASK_NONE;
iolinkmask_t	iolink_online_rdma_map = IOLINK_MASK_NONE;
int		iolink_rdma_num = 0;
int		iolink_online_rdma_num = 0;

/* Add for rdma_sic module */
EXPORT_SYMBOL(iolinks_num);
EXPORT_SYMBOL(iolink_iohub_map);
EXPORT_SYMBOL(iolink_online_iohub_map);
EXPORT_SYMBOL(iolink_iohub_num);
EXPORT_SYMBOL(iolink_online_iohub_num);
EXPORT_SYMBOL(iolink_rdma_map);
EXPORT_SYMBOL(iolink_online_rdma_map);
EXPORT_SYMBOL(iolink_rdma_num);
EXPORT_SYMBOL(iolink_online_rdma_num);


int get_domain_to_root_busnum(int domain)
{
	int busnum;
	int node = iohub_domain_to_node(domain);
	int link = iohub_domain_to_link(domain);

	if (domain < 0 || domain >= MAX_NUMIOLINKS) {
		printk(KERN_ERR "get_domain_to_root_busnum() invalid domain "
			"# %d (< 0 or >= max %d)\n",
			domain, MAX_NUMIOLINKS);
		return (-1);
	}
	busnum = mp_find_iolink_root_busnum(node, link);
//	if (busnum >= 0)
//		return (busnum);
	if (domain == first_iohub_online()) {
		busnum = 0;
	} else {
		busnum = 0;
	}

	return (busnum);
}

struct pci_bus *pcibios_scan_root_domain(int domain, int busnum)
{
	struct pci_bus *bus = NULL;
	struct iohub_sysdata *sd;
	int node, link;

	node = iohub_domain_to_node(domain);
	link = iohub_domain_to_link(domain);
	DebugPCI("pcibios_scan_root_domain(): root bus # %d on IOHUB "
		"domain #%d (node %d, link %d)\n",
		busnum, domain, node, link);
	while ((bus = pci_find_next_bus(bus)) != NULL) {
		DebugPCI("pcibios_scan_root_domain() find next bus # %d\n",
			bus->number);
		if (bus->number == busnum) {
			/* Already scanned */
			DebugPCI("pcibios_scan_root_domain() bus # %d already "
				"scanned\n", busnum);
			return bus;
		}
	}

	/* Allocate per-root-bus (not per bus) arch-specific data.
	 * TODO: leak; this memory is never freed.
	 * It's arguable whether it's worth the trouble to care.
	 */
	sd = kzalloc(sizeof(*sd), GFP_KERNEL);
	if (!sd) {
		printk(KERN_ERR "PCI: OOM, not probing PCI bus %02x\n", busnum);
		return NULL;
	}

	sd->domain = domain;
	sd->node = node;
	sd->link = link;

	printk(KERN_INFO "PCI: Probing PCI hardware (bus %02x)\n", busnum);
	bus = pci_scan_bus_parented(NULL, busnum, &pci_root_ops, sd);
	if (!bus) {
		DebugPCI("pcibios_scan_root_domain() scanning failed\n");
		kfree(sd);
	} else {
		DebugPCI("pcibios_scan_root_domain() scanning returned bus "
			"#%d %s\n", bus->number, bus->name);
	}

	return bus;
}

struct pci_bus *pci_scan_bus_on_domain(int busno, struct pci_ops *ops, int domain)
{
	struct pci_bus *bus = NULL;
	struct iohub_sysdata *sd;
	int node, link;

	node = iohub_domain_to_node(domain);
	link = iohub_domain_to_link(domain);
	DebugPCI("pci_scan_bus_on_domain(): bus # %d on IOHUB "
		"domain #%d (node %d, link %d)\n",
		busno, domain, node, link);
	/*
	 * Allocate per-root-bus (not per bus) arch-specific data.
	 * TODO: leak; this memory is never freed.
	 * It's arguable whether it's worth the trouble to care.
	 */
	sd = kzalloc(sizeof(*sd), GFP_KERNEL);
	if (!sd) {
		printk(KERN_ERR "PCI: OOM, skipping PCI bus %02x\n", busno);
		return NULL;
	}
	sd->domain = domain;
	sd->node = node;
	sd->link = link;
	bus = pci_scan_bus(busno, ops, sd);
	if (!bus) {
		DebugPCI("pci_scan_bus_on_domain() scanning failed\n");
		kfree(sd);
	} else {
		DebugPCI("pci_scan_bus_on_domain() scanning returned bus "
			"#%d %s\n", bus->number, bus->name);
	}

	return bus;
}

#ifdef	HAVE_MULTIROOT_BUS_PCI_DOMAINS
/*
 * Root bus is separate for each PCI domain (as on e2k)
 */
static int __init pci_scan_multiroot_bus_domains(void)
{
	int root_domain;
	int domain = 0;
	int root_busnum;
	int node, link;

	DebugPCI("pci_scan_multiroot_bus_domains() started\n");
	root_domain = first_iohub_online();
	if (root_domain < 0 || root_domain >= MAX_NUMIOLINKS) {
		printk("PCI: none IOHUB found at the system\n");
		return (-1); 
	}
	node = iohub_domain_to_node(domain);
	link = iohub_domain_to_link(domain);
	DebugPCI("pci_scan_multiroot_bus_domains() root IOHUB: domain #%d "
		"(node %d, link %d)\n",
		root_domain, node, link);
	root_busnum = get_domain_to_root_busnum(root_domain);
	if (root_busnum < 0 || root_domain >= 256) {
		printk("PCI: invalid root bus # %d for IOHUB domain #%d "
			"(node %d, link %d)\n",
			root_busnum, root_domain, node, link);
		return (-1); 
	}
	DebugPCI("pci_scan_multiroot_bus_domains() root IOHUB: root bus %d\n",
		root_busnum);
	pci_root_bus = pcibios_scan_root_domain(root_domain, root_busnum);
	if (pci_root_bus) {
		pci_bus_add_devices(pci_root_bus);
		DebugPCI("pci_scan_multiroot_bus_domains() root IOHUB: root "
			"bus %s devices was added\n",
			pci_root_bus->name);
	}
	if (num_online_iohubs() <= 1) {
		DebugPCI("pci_scan_multiroot_bus_domains() only one IOHUB "
			"detected\n");
		return (0);
	}
	for_each_online_iohub(domain) {
		int busnum, node, link;
		struct pci_bus *domain_root_bus;

		if (domain == root_domain)
			continue;
		busnum = get_domain_to_root_busnum(domain);
		node = iohub_domain_to_node(domain);
		link = iohub_domain_to_link(domain);
		if (busnum < 0 || busnum >= 256) {
			printk("PCI: invalid root bus # %d for IOHUB "
				"domain #%d (node %d, link %d)\n",
				busnum, domain, node, link);
			continue;
		}
		printk(KERN_INFO "Scanning PCI root bus %d of IOHUB domain #%d "
			"(node %d, link %d)\n",
			busnum, domain, node, link);
		domain_root_bus = pci_scan_bus_on_domain(busnum, &pci_root_ops,
								domain);
		if (domain_root_bus) {
			printk(KERN_INFO "PCI: created domain #%d (node %d, "
				"link %d) from root bus %s\n",
				domain, node, link, domain_root_bus->name);
			pcibios_fixup_resources(domain_root_bus);
		} else {
			printk(KERN_INFO "PCI: empty domain #%d (node %d, "
				"link %d) will ignore\n",
				domain, node, link);
		}
	}
	return 0;
}
#endif	/* HAVE_MULTIROOT_BUS_PCI_DOMAINS */

#ifdef	HAVE_COMMONROOT_BUS_PCI_DOMAINS
struct pci_bus *pci_scan_root_bus_domain(int domain)
{
	struct pci_bus *bus = NULL;
	struct iohub_sysdata *sd;
	int node, link;
	int root_slot, slot;
	unsigned char	subordinate;
	LIST_HEAD(resources);

	node = iohub_domain_to_node(domain);
	link = iohub_domain_to_link(domain);
	DebugPCI("pci_scan_root_bus_domain(): IOHUB domain #%d (node %d, "
		"link %d)\n",
		domain, node, link);
	sd = kzalloc(sizeof(*sd), GFP_KERNEL);
	if (!sd) {
		printk(KERN_ERR "PCI: OOM, not probing root PCI domain %d\n",
			domain);
		return NULL;
	}

	sd->domain = domain;
	sd->node = node;
	sd->link = link;
	pci_add_resource(&resources, &ioport_resource);
	pci_add_resource(&resources, &iomem_resource);
	bus = pci_create_root_bus(NULL, L_IOHUB_ROOT_BUS_NUM, &pci_root_ops, sd,
				 &resources);
	if (!bus) {
		pr_err("PCI: could not create root PCI bus on "
			"domain %d (node %d, link %d)\n",
			domain, node, link);
		kfree(sd);
		return NULL;
	}
	DebugPCI("pci_scan_root_bus_domain() created root PCI bus %s\n",
		bus->name);

	root_slot = pci_iohub_domain_to_slot(domain);
	for (slot = 0; slot < L_IOHUB_SLOTS_NUM; slot++) {
		int devs;
		int devfn;

		devfn = (root_slot + slot) * 8;
		devs = pci_scan_slot(bus, devfn);
		DebugPCI("pci_scan_root_bus_domain() detected %d devices "
			"on root PCI slot #%d\n",
			devs, root_slot + slot);
	}
	subordinate = pci_scan_root_child_bus(bus);
	pci_bus_add_devices(bus);
	DebugPCI("pci_scan_root_bus_domain() max subordinated bus on PCI "
		"domain %d is 0x%02x\n", domain, subordinate);
	return bus;
}

/*
 * Root bus is common for all PCI domains (as on e90s)
 */
static int pci_scan_commonroot_bus_domains(void)
{
	int root_domain;
	int domain = 0;
	int node, link;

	DebugPCI("pci_scan_commonroot_bus_domains() started\n");
	root_domain = first_iohub_online();
	if (root_domain < 0 || root_domain >= MAX_NUMIOLINKS) {
		pr_info("PCI: none IOHUB found at the system\n");
		return -EINVAL;
	}
	node = iohub_domain_to_node(root_domain);
	link = iohub_domain_to_link(root_domain);
	DebugPCI("pci_scan_commonroot_bus_domains() root IOHUB: domain #%d "
		"(node %d, link %d)\n",
		root_domain, node, link);

	pci_root_bus = pci_scan_root_bus_domain(root_domain);
	if (!pci_root_bus) {
		printk(KERN_ERR "PCI: could not create root PCI bus "
			"on domain %d\n", root_domain);
		return -ENOMEM;
	}
	if (num_online_iohubs() <= 1) {
		DebugPCI("pci_scan_commonroot_bus_domains() only one IOHUB "
			"detected\n");
		return 0;
	}
	for_each_online_iohub(domain) {
		int node, link;
		struct pci_bus *domain_root_bus;

		if (domain == root_domain)
			continue;
		node = iohub_domain_to_node(domain);
		link = iohub_domain_to_link(domain);
		pr_info("Scanning PCI root bus of IOHUB domain #%d "
			"(node %d, link %d)\n",
			domain, node, link);
		domain_root_bus = pci_scan_root_bus_domain(domain);
		if (domain_root_bus) {
			pr_info("PCI: created domain #%d (node %d, "
				"link %d)\n",
				domain, node, link);
			pcibios_fixup_resources(domain_root_bus);
		} else {
			pr_info("PCI: empty domain #%d (node %d, "
				"link %d)\n",
				domain, node, link);
		}
	}
	return 0;
}
#endif	/* HAVE_COMMONROOT_BUS_PCI_DOMAINS */

static int __init pci_numa_init(void)
{
#if defined(HAVE_MULTIROOT_BUS_PCI_DOMAINS)
	return pci_scan_multiroot_bus_domains();
#elif defined(HAVE_COMMONROOT_BUS_PCI_DOMAINS)
	return pci_scan_commonroot_bus_domains();
#else
	#error "PCI domain root bus type is undefined"
	return -ENODEV;
#endif
}

subsys_initcall(pci_numa_init);
