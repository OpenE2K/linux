
#include <linux/nodemask.h>
#include <linux/errno.h>
#include <linux/smp.h>

#include <asm/sections.h>
#include <asm/e90s.h>
#include <asm/sic_regs.h>
#include <asm/iolinkmask.h>
#include <asm/io.h>
#include <asm/console.h>

#undef  DEBUG_SIC_MODE
#undef  DebugSIC
#define	DEBUG_SIC_MODE	0	/* SIC mapping & init */
#define	DebugSIC(fmt, args...)				\
		({ if (DEBUG_SIC_MODE)			\
			pr_info(fmt, ##args); })

#ifndef	CONFIG_IOHUB_DOMAINS
/*
 * IO Links of all nodes configuration
 */
#undef		iolinks_num
#undef		iolink_iohub_num

int		iolinks_num = 0;
iolinkmask_t	iolink_iohub_map = IOLINK_MASK_NONE;
iolinkmask_t	iolink_online_iohub_map = IOLINK_MASK_NONE;
int		iolink_iohub_num = 0;
int		iolink_online_iohub_num = 0;
iolinkmask_t	iolink_rdma_map = IOLINK_MASK_NONE;
iolinkmask_t	iolink_online_rdma_map = IOLINK_MASK_NONE;
int		iolink_rdma_num = 0;
int		iolink_online_rdma_num = 0;
#endif	/* CONFIG_IOHUB_DOMAINS */

static void create_nodes_io_config(void);

#ifndef	CONFIG_NUMA

unsigned long nodes_present_map = 0;
unsigned long iolinks_present_map = 0;

void __init create_nodes_config(void)
{
	e90s_ncfg_struct_t	io_link;

	NBSR_NCFG_reg(io_link) = early_sic_read_node_iolink_nbsr_reg(0, 0,
								NBSR_NODE_CFG);
	nodes_present_map = NBSR_NCFG_ApicNodePresentMask(io_link);
	iolinks_present_map = NBSR_NCFG_ApicIoPresentMask(io_link);
	printk(KERN_INFO "Nodes present map 0x%lx IO links maap 0x%lx\n",
		nodes_present_map, iolinks_present_map);
}
#endif	/* ! CONFIG_NUMA */

int __init
e90s_early_iohub_online(int node, int link)
{
	e90s_nc_info_struct_t	nc_info;
	e90s_ncfg_struct_t	io_link;
	int iohub_on = 0;

#ifdef	CONFIG_NUMA
	if (!node_online(node))
		return 0;
#else	/* ! CONFIG_NUMA */
	if (!(nodes_present_map & (1 << node)))
		return 0;
#endif	/* CONFIG_NUMA */
	NBSR_NC_INFO_reg(nc_info) = early_sic_read_node_nbsr_reg(node,
							NBSR_NODE_CFG_INFO);
	if (!NBSR_NC_INFO_IoccLinkUp(nc_info))
		return 0;
	NBSR_NCFG_reg(io_link) = early_sic_read_node_nbsr_reg(node,
								NBSR_NODE_CFG);
	if (NBSR_NCFG_IoLinkRdmaMode(io_link) == IOHUB_IOL_MODE) {
		iohub_on = 1;
	}
	DebugENBSR("e90s_early_iohub_online() IOHUB of node %d link %d %s\n",
		node, link, (iohub_on) ? "ON" : "OFF");
	return iohub_on;
}
/*
 * NBSR area mapping and init
 */

int __init
e90s_sic_init(void)
{
	DebugSIC("e90s_sic_init() started\n");
	if (!HAS_MACHINE_E90S_SIC) {
		pr_info("e90s_sic_init() the arch has not NBSR\n");
		return -ENODEV;
	}
#ifndef	CONFIG_NUMA
	create_nodes_config();
#endif	/* ! CONFIG_NUMA */
	create_nodes_io_config();
	return 0;
}

#ifdef	CHECK_IOLINKS
/*
 * IO Links of all nodes configuration
 */

static void check_iolink_config(int node, int link)
{
	e90s_nc_info_struct_t	nc_info;
	int link_on;
	int ab_type;

	link_on = 0;

	NBSR_NC_INFO_reg(nc_info) = sic_read_node_iolink_nbsr_reg(
						node, link, NBSR_NODE_CFG_INFO);
	link_on = NBSR_NC_INFO_IoccLinkUp(nc_info);
	ab_type = NBSR_NC_INFO_IoccLinkRtype(nc_info);
	pr_info("Node #%d IO LINK #%d is", node, link);
	if (ab_type == IOHUB_ONLY_IOL_ABTYPE) {
		node_iohub_set(node, link, iolink_iohub_map);
		iolink_iohub_num++;
		pr_cont(" IO HUB controller");
		if (link_on) {
			node_iohub_set(node, link, iolink_online_iohub_map);
			iolink_online_iohub_num++;
			pr_cont(" ON");
		} else {
			pr_cont(" OFF");
		}
	} else if (ab_type == RDMA_ONLY_IOL_ABTYPE ||
			ab_type == RDMA_IOHUB_IOL_ABTYPE) {
		node_rdma_set(node, link, iolink_rdma_map);
		iolink_rdma_num++;
		pr_cont(" RDMA controller");
		if (link_on) {
			node_rdma_set(node, link, iolink_online_rdma_map);
			iolink_online_rdma_num++;
			pr_cont(" ON");
		} else {
			pr_cont(" OFF");
		}
	} else {
		pr_cont(" unknown controller");
		if (link_on) {
			pr_cont(" ON");
		} else {
			pr_cont(" OFF");
		}
	}
	if (link_on) {
		pr_cont(" connected to");
		switch (ab_type) {
		case IOHUB_ONLY_IOL_ABTYPE:
			pr_cont(" IO HUB controller");
			break;
		case RDMA_ONLY_IOL_ABTYPE:
			pr_cont(" RDMA controller");
			break;
		case RDMA_IOHUB_IOL_ABTYPE:
			pr_cont(" IO HUB/RDMA controller");
			break;
		default:
			pr_cont(" unknown controller");
			break;
		}
	}
	pr_cont("\n");
}
#endif	/* CHECK_IOLINKS */

void create_iolink_config(int node, int link)
{
	e90s_nc_info_struct_t	nc_info;
	e90s_ncfg_struct_t	io_link;
	e90s_io_csr_struct_t	io_hub;
	e90s_rdma_cs_struct_t	rdma;
	int ab_type;
	int link_on;

	link_on = 0;

	NBSR_NC_INFO_reg(nc_info) = sic_read_node_iolink_nbsr_reg(
						node, link, NBSR_NODE_CFG_INFO);
	ab_type = NBSR_NC_INFO_IoccLinkRtype(nc_info);
	NBSR_NCFG_reg(io_link) = sic_read_node_iolink_nbsr_reg(node, link,
								NBSR_NODE_CFG);
	pr_info("Node #%d IO LINK #%d is", node, link);
	if (NBSR_NCFG_IoLinkRdmaMode(io_link) == IOHUB_IOL_MODE) {
		node_iohub_set(node, link, iolink_iohub_map);
		iolink_iohub_num++;
		pr_cont(" IO HUB controller");
		NBSR_IO_CSR_reg(io_hub) =
			sic_read_node_iolink_nbsr_reg(node, link, NBSR_IO_CSR);
		if (NBSR_IO_CSR_ch_on(io_hub)) {
			node_iohub_set(node, link, iolink_online_iohub_map);
			iolink_online_iohub_num++;
			link_on = 1;
			pr_cont(" ON");
		} else {
			pr_cont(" OFF");
		}
	} else {
		node_rdma_set(node, link, iolink_rdma_map);
		iolink_rdma_num++;
		pr_cont(" RDMA controller");
		NBSR_RDMA_CS_reg(rdma) =
			sic_read_node_iolink_nbsr_reg(node, link, NBSR_CS);
		if (NBSR_RDMA_CS_ch_on(rdma)) {
			node_rdma_set(node, link, iolink_online_rdma_map);
			iolink_online_rdma_num++;
			link_on = 1;
			pr_cont(" ON");
		} else {
			pr_cont(" OFF");
		}
	}
	if (link_on) {
		pr_cont(" connected to");
		switch (ab_type) {
		case IOHUB_ONLY_IOL_ABTYPE:
			pr_cont(" IO HUB controller");
			break;
		case RDMA_ONLY_IOL_ABTYPE:
			pr_cont(" RDMA controller");
			break;
		case RDMA_IOHUB_IOL_ABTYPE:
			pr_cont(" IO HUB/RDMA controller");
			break;
		default:
			pr_cont(" unknown controller");
			break;
		}
	}
	pr_cont("\n");
}

static void create_nodes_io_config(void)
{
	int node;
	int link;

	DebugSIC("create_nodes_io_config() started\n");
	for_each_online_node(node) {
		DebugSIC("create_nodes_io_config() on node #%d\n", node);
		for_each_iolink_of_node(link) {
#ifndef	CONFIG_NUMA
			if (!(nodes_present_map & (1 << link)))
				continue;
#endif	/* ! CONFIG_NUMA */
			DebugSIC("create_nodes_io_config() on link #%d\n",
				link);
			iolinks_num++;
#ifdef	CONFIG_NUMA
			create_iolink_config(node, link);
#else	/* ! CONFIG_NUMA */
			create_iolink_config(link, 0);
#endif	/* CONFIG_NUMA */
		}
	}
	if (iolinks_num > 1) {
		printk(KERN_INFO "Total IO links %d: IOHUBs %d, RDMAs %d\n",
			iolinks_num, iolink_iohub_num, iolink_rdma_num);
	}
}
