#include <linux/export.h>
#include <linux/ptrace.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/nodemask.h>
#include <linux/smp.h>

#include <asm/apic.h>
#include <asm/e2k_api.h>
#include <asm/e2k.h>
#include <asm/e2k_sic.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/iolinkmask.h>
#include <asm/io.h>
#include <asm/console.h>

#undef  DEBUG_SIC_MODE
#undef  DebugSIC
#define	DEBUG_SIC_MODE		0	/* SIC mapping & init */
#define	DebugSIC(fmt, args...)					\
		({ if (DEBUG_SIC_MODE)				\
			pr_debug(fmt, ##args); })

#undef	DEBUG_ERALY_NBSR_MODE
#undef	DebugENBSR
#define	DEBUG_ERALY_NBSR_MODE	0	/* early NBSR access */
#define DebugENBSR(...)		DebugPrint(DEBUG_ERALY_NBSR_MODE ,##__VA_ARGS__)


extern int __initdata max_iolinks;
extern int __initdata max_node_iolinks;

e2k_addr_t sic_get_io_area_max_size(void)
{
	if (E2K_FULL_SIC_IO_AREA_SIZE >= E2K_LEGACY_SIC_IO_AREA_SIZE)
		return E2K_FULL_SIC_IO_AREA_SIZE;
	else
		return E2K_LEGACY_SIC_IO_AREA_SIZE;
}

unsigned int sic_get_mc_ecc(int node, int num)
{
	int reg_offset = 0;

	switch (num) {
	case 0:
		reg_offset = SIC_mc0_ecc;
		break;
	case 1:
		reg_offset = SIC_mc1_ecc;
		break;
	case 2:
		reg_offset = SIC_mc2_ecc;
		break;
	case 3:
		reg_offset = SIC_mc3_ecc;
		break;
	};

	if (reg_offset)
		return sic_read_node_nbsr_reg(node, reg_offset);
	return 0;
}

void sic_set_mc_ecc(int node, int num, unsigned int reg_value)
{
	int reg_offset = 0;

	switch (num) {
	case 0:
		reg_offset = SIC_mc0_ecc;
		break;
	case 1:
		reg_offset = SIC_mc1_ecc;
		break;
	case 2:
		reg_offset = SIC_mc2_ecc;
		break;
	case 3:
		reg_offset = SIC_mc3_ecc;
		break;
	};

	if (reg_offset)
		sic_write_node_nbsr_reg(node, reg_offset, reg_value);
}

unsigned int sic_get_ipcc_csr(int node, int num)
{
	int reg_offset = 0;

	switch (num) {
	case 1:
		reg_offset = SIC_ipcc_csr1;
		break;
	case 2:
		reg_offset = SIC_ipcc_csr2;
		break;
	case 3:
		reg_offset = SIC_ipcc_csr3;
		break;
	};

	if (reg_offset)
		return sic_read_node_nbsr_reg(node, reg_offset);
	return 0;
}

void sic_set_ipcc_csr(int node, int num, unsigned int reg_value)
{
	int reg_offset = 0;

	switch (num) {
	case 1:
		reg_offset = SIC_ipcc_csr1;
		break;
	case 2:
		reg_offset = SIC_ipcc_csr2;
		break;
	case 3:
		reg_offset = SIC_ipcc_csr3;
		break;
	};

	if (reg_offset)
		sic_write_node_nbsr_reg(node, reg_offset, reg_value);

	return;
}

unsigned int sic_get_ipcc_str(int node, int num)
{
	int reg_offset = 0;

	switch (num) {
	case 1:
		reg_offset = SIC_ipcc_str1;
		break;
	case 2:
		reg_offset = SIC_ipcc_str2;
		break;
	case 3:
		reg_offset = SIC_ipcc_str3;
		break;
	};

	if (reg_offset)
		return sic_read_node_nbsr_reg(node, reg_offset);
	return 0;
}

void sic_set_ipcc_str(int node, int num, unsigned int val)
{
	int reg_offset = 0;

	switch (num) {
	case 1:
		reg_offset = SIC_ipcc_str1;
		break;
	case 2:
		reg_offset = SIC_ipcc_str2;
		break;
	case 3:
		reg_offset = SIC_ipcc_str3;
		break;
	};

	if (reg_offset)
		sic_write_node_nbsr_reg(node, reg_offset, val);
}

unsigned int sic_get_io_str(int node, int num)
{
	int reg_offset = 0;

	switch (num) {
	case 0:
		reg_offset = SIC_io_str;
		break;
	case 1:
		reg_offset = machine.sic_io_str1;
		break;
	};

	if (reg_offset)
		return sic_read_node_nbsr_reg(node, reg_offset);
	return 0;
}

void sic_set_io_str(int node, int num, unsigned int val)
{
	int reg_offset = 0;

	switch (num) {
	case 0:
		reg_offset = SIC_io_str;
		break;
	case 1:
		reg_offset = machine.sic_io_str1;
		break;
	};

	if (reg_offset)
		sic_write_node_nbsr_reg(node, reg_offset, val);
}

static void create_nodes_io_config(void);

int __init
e2k_early_iohub_online(int node, int link)
{
	e2k_iol_csr_struct_t	io_link;
	e2k_io_csr_struct_t	io_hub;
	int domain = node_iolink_to_domain(node, link);
	int iohub_on = 0;

	DebugENBSR("started on node %d link %d\n",
		node, link);
	if (!node_online(node))
		return 0;
	if (domain >= max_iolinks)
		return 0;
	if (link >= max_node_iolinks)
		return 0;
	/* FIXME: IO link registers of SIC mutate to WLCC registers */
	/* on legacy SIC */
	/* now we assume IO link on node #0 connected to IOHUB online */
	if (HAS_MACHINE_E2K_LEGACY_SIC) {
		iohub_on = 1;
	} else {
		io_link.E2K_IOL_CSR_reg = early_sic_read_node_iolink_nbsr_reg(
						node, link, SIC_iol_csr);
		if (io_link.E2K_IOL_CSR_mode != IOHUB_IOL_MODE)
			return 0;
		io_hub.E2K_IO_CSR_reg = early_sic_read_node_iolink_nbsr_reg(
						node, link, SIC_io_csr);
		if (io_hub.E2K_IO_CSR_ch_on) {
			iohub_on = 1;
		}
	}
	DebugENBSR("IOHUB of node %d link %d %s\n",
		node, link, (iohub_on) ? "ON" : "OFF");
	return iohub_on;
}

/*
 * SIC area mapping and init
 */
unsigned char *nodes_nbsr_base[MAX_NUMNODES];
EXPORT_SYMBOL_GPL(nodes_nbsr_base);

phys_addr_t nodes_nbsr_phys_base[MAX_NUMNODES];

int __init
e2k_sic_init(void)
{
	unsigned char *nbsr_base;
	unsigned long long phys_base;
	int node;
	int ret = 0;

	if (!HAS_MACHINE_L_SIC) {
		printk("e2k_sic_init() the arch has not SIC\n");
		return -ENODEV;
	}
	for_each_online_node(node) {
		phys_base = (unsigned long long)THE_NODE_NBSR_PHYS_BASE(node);
		nbsr_base = ioremap(phys_base, NODE_NBSR_SIZE);
		if (nbsr_base == NULL) {
			printk("e2k_sic_init() could not map NBSR registers "
				"of node #%d, phys base 0x%llx, size 0x%lx\n",
				node, phys_base, NODE_NBSR_SIZE);
			ret =-ENOMEM;
		}
		DebugSIC("map NBSR of node #%d phys base "
			"0x%llx, size 0x%lx to virtual addr 0x%px\n",
			node, phys_base, NODE_NBSR_SIZE, nbsr_base);
		nodes_nbsr_base[node] = nbsr_base;
		nodes_nbsr_phys_base[node] = phys_base;
	}
	create_nodes_io_config();
	return ret;
}

unsigned long domain_to_pci_conf_base[MAX_NUMIOLINKS] = {
				[ 0 ... (MAX_NUMIOLINKS-1) ] = 0
			};

#ifdef CONFIG_IOHUB_DOMAINS
static void create_nodes_pci_conf(void)
{

	int domain;

	for_each_iohub(domain) {
		domain_to_pci_conf_base[domain] =
			sic_domain_pci_conf_base(domain);
		DebugSIC("IOHUB domain #%d (node %d, "
			"IO link %d) PCI CFG base 0x%lx\n",
			domain, iohub_domain_to_node(domain),
			iohub_domain_to_link(domain),
			domain_to_pci_conf_base[domain]);
	}

}
#else /* !CONFIG_IOHUB_DOMAINS: */
static void create_nodes_pci_conf(void)
{
	domain_to_pci_conf_base[0] =
		sic_domain_pci_conf_base(0);
}
#endif /* !CONFIG_IOHUB_DOMAINS */

#ifdef CONFIG_IOHUB_DOMAINS
/*
 * IO Links of all nodes configuration
 */

static void create_iolink_config(int node, int link)
{
	e2k_iol_csr_struct_t	io_link;
	e2k_io_csr_struct_t	io_hub;
	e2k_rdma_cs_struct_t	rdma;
	int link_on;

	link_on = 0;

	/* FIXME: IO link registers of SIC mutate to WLCC registers */
	/* on legacy SIC */
	/* now we assume IO link on node #0 connected to IOHUB online */
	if (HAS_MACHINE_E2K_LEGACY_SIC) {
		io_link.E2K_IOL_CSR_reg = 0;
		io_link.E2K_IOL_CSR_mode = IOHUB_IOL_MODE;
		io_link.E2K_IOL_CSR_abtype = IOHUB_ONLY_IOL_ABTYPE;
	} else {
		io_link.E2K_IOL_CSR_reg = sic_read_node_iolink_nbsr_reg(
						node, link, SIC_iol_csr);
	}
	printk(KERN_INFO "Node #%d IO LINK #%d is", node, link);
	if (io_link.E2K_IOL_CSR_mode == IOHUB_IOL_MODE) {
		node_iohub_set(node, link, iolink_iohub_map);
		iolink_iohub_num ++;
		printk(" IO HUB controller");
		/* FIXME: IO link registers of SIC mutate to WLCC registers */
		/* on legacy SIC */
		/* now we assume IO link on node #0 connected to IOHUB online */
		if (HAS_MACHINE_E2K_LEGACY_SIC) {
			io_hub.E2K_IO_CSR_reg = 0;
			io_hub.E2K_IO_CSR_ch_on = 1;
		} else {
			io_hub.E2K_IO_CSR_reg = sic_read_node_iolink_nbsr_reg(
							node, link, SIC_io_csr);
		}
		if (io_hub.E2K_IO_CSR_ch_on) {
			node_iohub_set(node, link, iolink_online_iohub_map);
			iolink_online_iohub_num ++;
			link_on = 1;
			printk(" ON");
		} else {
			printk(" OFF");
		}
	} else {
		if (machine.native_iset_ver <= E2K_ISET_V3) {
			node_rdma_set(node, link, iolink_rdma_map);
			iolink_rdma_num++;
			printk(" RDMA controller");
			rdma.E2K_RDMA_CS_reg = sic_read_node_iolink_nbsr_reg(
						       node, link, SIC_rdma_cs);
			if (rdma.E2K_RDMA_CS_ch_on) {
				node_rdma_set(node, link,
						iolink_online_rdma_map);
				iolink_online_rdma_num++;
				link_on = 1;
				printk(" ON 0x%08x", rdma.E2K_RDMA_CS_reg);
			} else {
				printk(" OFF 0x%08x", rdma.E2K_RDMA_CS_reg);
			}
		} else {
			printk(" not connected");
		}
	}
	if (link_on) {
		int ab_type = io_link.E2K_IOL_CSR_abtype;
		printk(" connected to");
		switch (ab_type) {
		case IOHUB_ONLY_IOL_ABTYPE:
			printk(" IO HUB controller");
			break;
		case RDMA_ONLY_IOL_ABTYPE:
			printk(" RDMA controller");
			break;
		case RDMA_IOHUB_IOL_ABTYPE:
			printk(" IO HUB/RDMA controller");
			break;
		default:
			printk(" unknown controller");
			break;
		}
	}
	printk("\n");
}

static void __init create_nodes_io_config(void)
{
	int node;
	int link;

	for_each_online_node(node) {
		for_each_iolink_of_node(link) {
			if (iolinks_num >= max_iolinks)
				break;
			if (link >= max_node_iolinks)
				break;
			iolinks_num ++;
			create_iolink_config(node, link);
		}
		if (iolinks_num >= max_iolinks)
			break;
	}
	if (iolinks_num > 1) {
		printk(KERN_INFO "Total IO links %d: IOHUBs %d, RDMAs %d\n",
			iolinks_num, iolink_iohub_num, iolink_rdma_num);
	}
	create_nodes_pci_conf();
}
#else /* !CONFIG_IOHUB_DOMAINS */

 /*
  * IO Link of nodes configuration
  */
nodemask_t	node_iohub_map = NODE_MASK_NONE;
nodemask_t	node_online_iohub_map = NODE_MASK_NONE;
int		node_iohub_num = 0;
int		node_online_iohub_num = 0;
nodemask_t	node_rdma_map = NODE_MASK_NONE;
nodemask_t	node_online_rdma_map = NODE_MASK_NONE;
int		node_rdma_num = 0;
int		node_online_rdma_num = 0;

static void __init create_nodes_io_config(void)
{
	int node;
	e2k_iol_csr_struct_t	io_link;
	e2k_io_csr_struct_t	io_hub;
	e2k_rdma_cs_struct_t	rdma;
	int link_on;

	for_each_online_node(node) {
		link_on = 0;
		/* FIXME: IO link registers of SIC mutate to WLCC registers */
		/* on legacy SIC */
		/* now we assume IO link on node #0 connected to IOHUB online */
		if (HAS_MACHINE_E2K_LEGACY_SIC) {
			io_link.E2K_IOL_CSR_reg = 0;
			io_link.E2K_IOL_CSR_mode = IOHUB_IOL_MODE;
			io_link.E2K_IOL_CSR_abtype = IOHUB_ONLY_IOL_ABTYPE;
		} else {
			io_link.E2K_IOL_CSR_reg = sic_read_node_nbsr_reg(node,
								SIC_iol_csr);
		}
		printk("Node #%d IO LINK is", node);
		if (io_link.E2K_IOL_CSR_mode == IOHUB_IOL_MODE) {
			node_set(node, node_iohub_map);
			node_iohub_num ++;
                        printk(" IO HUB controller");
			/* FIXME: IO link registers of SIC mutate to WLCC */
			/* registers on legacy SIC */
			/* now we assume IO link on node #0 connected to */
			/* IOHUB online */
			if (HAS_MACHINE_E2K_LEGACY_SIC) {
				io_hub.E2K_IO_CSR_reg = 0;
				io_hub.E2K_IO_CSR_ch_on = 1;
			} else {
				io_hub.E2K_IO_CSR_reg =
					sic_read_node_nbsr_reg(node,
								SIC_io_csr);
			}
			if (io_hub.E2K_IO_CSR_ch_on) {
				node_set(node, node_online_iohub_map);
				node_online_iohub_num ++;
				link_on = 1;
				printk(" ON");
			} else {
				printk(" OFF");
			}
		} else {
			node_set(node, node_rdma_map);
			node_rdma_num ++;
			printk(" RDMA controller");
			rdma.E2K_RDMA_CS_reg =
				sic_read_node_nbsr_reg(node, SIC_rdma_cs);
			if (rdma.E2K_RDMA_CS_ch_on) {
				node_set(node, node_online_rdma_map);
				node_online_rdma_num ++;
				link_on = 1;
				printk(" ON 0x%08x", rdma.E2K_RDMA_CS_reg);
			} else {
				printk(" OFF 0x%08x", rdma.E2K_RDMA_CS_reg);
			}
		}	
		if (link_on) {
			int ab_type = io_link.E2K_IOL_CSR_abtype;
			printk(" connected to");
			switch (ab_type) {
			case IOHUB_ONLY_IOL_ABTYPE:
				printk(" IO HUB controller");
				break;
			case RDMA_ONLY_IOL_ABTYPE:
				printk(" RDMA controller");
				break;
			case RDMA_IOHUB_IOL_ABTYPE:
				printk(" IO HUB/RDMA controller");
				break;
			default:
				printk(" unknown controller");
				break;
			}
		}
		printk("\n");
	}
	create_nodes_pci_conf();
}
/* Add for rdma_sic module */
EXPORT_SYMBOL(node_rdma_num);
EXPORT_SYMBOL(node_online_rdma_map);
EXPORT_SYMBOL(node_online_rdma_num);

#endif /* !CONFIG_IOHUB_DOMAINS */
