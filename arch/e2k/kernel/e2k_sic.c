/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

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
#include <asm/nbsr_v6_regs.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/iolinkmask.h>
#include <asm/io.h>
#include <asm/console.h>
#include <asm/l-mcmonitor.h>

#include <asm-l/pic.h>

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

static DEFINE_RAW_SPINLOCK(sic_mc_reg_lock);

static unsigned int
sic_read_node_mc_nbsr_reg(int node, int channel, int reg_offset)
{
	unsigned int reg_val;
	unsigned long flags;

	if (machine.native_iset_ver >= E2K_ISET_V6) {
		raw_spin_lock_irqsave(&sic_mc_reg_lock, flags);
		sic_write_node_nbsr_reg(node, MC_CH, channel);
	}

	reg_val = sic_read_node_nbsr_reg(node, reg_offset);

	if (machine.native_iset_ver >= E2K_ISET_V6)
		raw_spin_unlock_irqrestore(&sic_mc_reg_lock, flags);

	return reg_val;
}

static void
sic_write_node_mc_nbsr_reg(int node, int channel, int reg_offset, unsigned int reg_value)
{
	unsigned long flags;

	if (machine.native_iset_ver >= E2K_ISET_V6) {
		raw_spin_lock_irqsave(&sic_mc_reg_lock, flags);
		sic_write_node_nbsr_reg(node, MC_CH, channel);
	}

	sic_write_node_nbsr_reg(node, reg_offset, reg_value);

	if (machine.native_iset_ver >= E2K_ISET_V6)
		raw_spin_unlock_irqrestore(&sic_mc_reg_lock, flags);
}

static int sic_mc_ecc_reg_offset(int node, int num)
{
	if (machine.native_iset_ver < E2K_ISET_V6) {
		switch (num) {
		case 0:
			return SIC_mc0_ecc;
		case 1:
			return SIC_mc1_ecc;
		case 2:
			return SIC_mc2_ecc;
		case 3:
			return SIC_mc3_ecc;
		};
	} else {
		return MC_ECC;
	}

	return 0;
}

unsigned int sic_get_mc_ecc(int node, int num)
{
	int reg_offset;

	if (reg_offset = sic_mc_ecc_reg_offset(node, num))
		return sic_read_node_mc_nbsr_reg(node, num, reg_offset);

	return 0;
}
EXPORT_SYMBOL(sic_get_mc_ecc);

void sic_set_mc_ecc(int node, int num, unsigned int reg_value)
{
	int reg_offset;

	if (reg_offset = sic_mc_ecc_reg_offset(node, num))
		sic_write_node_mc_nbsr_reg(node, num, reg_offset, reg_value);
}


static int sic_mc_opmb_reg_offset(int node, int num)
{
	if (machine.native_iset_ver < E2K_ISET_V6) {
		switch (num) {
		case 0:
			return SIC_mc0_opmb;
		case 1:
			return SIC_mc1_opmb;
		case 2:
			return SIC_mc2_opmb;
		case 3:
			return SIC_mc3_opmb;
		};
	} else {
		return MC_OPMB;
	}

	return 0;
}

unsigned int sic_get_mc_opmb(int node, int num)
{
	int reg_offset;

	if (reg_offset = sic_mc_opmb_reg_offset(node, num))
		return sic_read_node_mc_nbsr_reg(node, num, reg_offset);

	return 0;
}
EXPORT_SYMBOL(sic_get_mc_opmb);

static int sic_mc_cfg_reg_offset(int node, int num)
{
	if (machine.native_iset_ver < E2K_ISET_V6) {
		switch (num) {
		case 0:
			return SIC_mc0_cfg;
		case 1:
			return SIC_mc1_cfg;
		case 2:
			return SIC_mc2_cfg;
		case 3:
			return SIC_mc3_cfg;
		};
	} else {
		return MC_CFG;
	}

	return 0;
}

unsigned int sic_get_mc_cfg(int node, int num)
{
	int reg_offset;

	if (reg_offset = sic_mc_cfg_reg_offset(node, num))
		return sic_read_node_mc_nbsr_reg(node, num, reg_offset);

	return 0;
}
EXPORT_SYMBOL(sic_get_mc_cfg);

static int sic_ipcc_csr_reg_offset(int num)
{
	switch (num) {
	case 1:
		return SIC_ipcc_csr1;
	case 2:
		return SIC_ipcc_csr2;
	case 3:
		return SIC_ipcc_csr3;
	};

	return 0;
}

unsigned int sic_get_ipcc_csr(int node, int num)
{
	int reg_offset;

	if (reg_offset = sic_ipcc_csr_reg_offset(num))
		return sic_read_node_nbsr_reg(node, reg_offset);

	return 0;
}

void sic_set_ipcc_csr(int node, int num, unsigned int reg_value)
{
	int reg_offset;

	if (reg_offset = sic_ipcc_csr_reg_offset(num))
		sic_write_node_nbsr_reg(node, reg_offset, reg_value);
}

static int sic_ipcc_str_reg_offset(int num)
{
	switch (num) {
	case 1:
		return SIC_ipcc_str1;
	case 2:
		return SIC_ipcc_str2;
	case 3:
		return SIC_ipcc_str3;
	};

	return 0;
}

unsigned int sic_get_ipcc_str(int node, int num)
{
	int reg_offset;

	if (reg_offset = sic_ipcc_str_reg_offset(num))
		return sic_read_node_nbsr_reg(node, reg_offset);

	return 0;
}

void sic_set_ipcc_str(int node, int num, unsigned int val)
{
	int reg_offset;

	if (reg_offset = sic_ipcc_str_reg_offset(num))
		sic_write_node_nbsr_reg(node, reg_offset, val);
}

static int sic_io_str_reg_offset(int num)
{
	switch (num) {
	case 0:
		return SIC_io_str;
	case 1:
		return machine.sic_io_str1;
	};

	return 0;
}

unsigned int sic_get_io_str(int node, int num)
{
	int reg_offset;

	if (reg_offset = sic_io_str_reg_offset(num))
		return sic_read_node_nbsr_reg(node, reg_offset);

	return 0;
}

void sic_set_io_str(int node, int num, unsigned int val)
{
	int reg_offset;

	if (reg_offset = sic_io_str_reg_offset(num))
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
unsigned char __iomem *nodes_nbsr_base[MAX_NUMNODES];
EXPORT_SYMBOL_GPL(nodes_nbsr_base);

phys_addr_t nodes_nbsr_phys_base[MAX_NUMNODES];

int __init
e2k_sic_init(void)
{
	unsigned char __iomem *nbsr_base;
	unsigned long long phys_base;
	int node;
	int ret = 0;

	if (!HAS_MACHINE_L_SIC) {
		printk("e2k_sic_init() the arch has not SIC\n");
		return -ENODEV;
	}
	for_each_online_node(node) {
		phys_base = (unsigned long long)THE_NODE_NBSR_PHYS_BASE(node);
		nbsr_base = (unsigned char __iomem *) ioremap(phys_base, NODE_NBSR_SIZE);
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
		if (paravirt_enabled() && iolink_online_iohub_num >= mp_iohubs_num)
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

static DEFINE_RAW_SPINLOCK(sic_error_lock);

static void sic_mc_regs_dump(int node)
{
	if (machine.native_iset_ver < E2K_ISET_V6) {
		int offset = SIC_MC_BASE, i = 0;

		for (; i < SIC_MC_COUNT; i++) {
			char s[256];
			e2k_mc_ecc_struct_t ecc;

			ecc.E2K_MC_ECC_reg = sic_get_mc_ecc(node, i);
			pr_emerg("%s\n", l_mc_get_error_str(&ecc, i, s, sizeof(s)));
		}

		pr_emerg("MC registers dump:\n");
		for (; offset < SIC_MC_BASE + SIC_MC_SIZE; offset += 4)
			pr_emerg("%x ", sic_read_node_nbsr_reg(node, offset));
		pr_emerg("\n");
	} else {
		u32 hmu_mic = sic_read_node_nbsr_reg(node, HMU_MIC);
		int i = 0;

		pr_emerg("HMU_MIC 0x%x\n", hmu_mic);

		hmu_mic = (hmu_mic & 0xff000000) >> 24;

		for (; i < SIC_MAX_MC_COUNT; i++) {
			if (hmu_mic & (1 << i)) {
				pr_emerg("MC_STATUS[%d] 0x%x", i,
					sic_read_node_mc_nbsr_reg(node, i, MC_STATUS_E2K));
			}
		}
	}
}

static void sic_hmu_regs_dump(int node)
{
	pr_emerg("HMU0_INT 0x%x HMU1_INT 0x%x HMU2_INT 0x%x HMU3_INT 0x%x\n",
		sic_read_node_nbsr_reg(node, HMU0_INT),
		sic_read_node_nbsr_reg(node, HMU1_INT),
		sic_read_node_nbsr_reg(node, HMU2_INT),
		sic_read_node_nbsr_reg(node, HMU3_INT));
}

void do_sic_error_interrupt(void)
{
	int node;
	unsigned long flags;

	if (!raw_spin_trylock_irqsave(&sic_error_lock, flags))
		return;

	for_each_online_node(node) {
		pr_emerg("----- NODE%d -----\n", node);

		pr_emerg("%s_INT=0x%x\n",
			(machine.native_iset_ver < E2K_ISET_V6) ? "SIC" : "XMU",
			sic_read_node_nbsr_reg(node, SIC_sic_int));

		if (machine.native_iset_ver >= E2K_ISET_V6)
			sic_hmu_regs_dump(node);

		sic_mc_regs_dump(node);
	}

	raw_spin_unlock_irqrestore(&sic_error_lock, flags);
}

void sic_error_interrupt(struct pt_regs *regs)
{
	ack_pic_irq();
	irq_enter();

	do_sic_error_interrupt();

	irq_exit();

	panic("SIC error interrupt received on CPU%d:\n",
		smp_processor_id());
}
