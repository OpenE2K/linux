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
#include <linux/platform_device.h>
#include <linux/of_platform.h>

#include <asm/e2k_api.h>
#include <asm/e2k.h>
#include <asm/e2k_sic.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/iolinkmask.h>
#include <asm/io.h>
#include <asm/console.h>
#include <asm/hardirq.h>
#include <asm/pic.h>
#include <asm/setup.h>

#include <asm/l-mcmonitor.h>

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



e2k_addr_t sic_get_io_area_max_size(void)
{
	if (E2K_FULL_SIC_IO_AREA_SIZE >= E2K_LEGACY_SIC_IO_AREA_SIZE)
		return E2K_FULL_SIC_IO_AREA_SIZE;
	else
		return E2K_LEGACY_SIC_IO_AREA_SIZE;
}

static DEFINE_RAW_SPINLOCK(sic_mc_reg_lock);


static e2k_mc_ctl_t sic_get_mc_ctl(int node, int channel)
{
	u32 val;
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		unsigned long flags;
		raw_spin_lock_irqsave(&sic_mc_reg_lock, flags);
		sic_write_node_nbsr_reg(node, MC_CH, channel);
		val = sic_read_node_nbsr_reg(node, MC_CTL);
		raw_spin_unlock_irqrestore(&sic_mc_reg_lock, flags);
	} else {
		val = sic_read_node_nbsr_reg(node, MC_CTL + channel * 0x40);
	}
	return (e2k_mc_ctl_t){.word = val};
}


static unsigned int
sic_read_node_mc_nbsr_reg(int node, int channel, int reg_offset)
{
	unsigned int reg_val;

	if (machine.native_iset_ver >= E2K_ISET_V6) {
		unsigned long flags;
		if (cpu_has(CPU_HWBUG_MCNA_PLLMC_ACCESS) && MCNA_REG(reg_offset) && (channel == 1))
			channel = 2;
		raw_spin_lock_irqsave(&sic_mc_reg_lock, flags);
		sic_write_node_nbsr_reg(node, MC_CH, channel);
		reg_val = sic_read_node_nbsr_reg(node, reg_offset);
		raw_spin_unlock_irqrestore(&sic_mc_reg_lock, flags);
	} else {
		reg_val = sic_read_node_nbsr_reg(node, reg_offset);
	}

	return reg_val;
}
u32 sic_read_node_v7_mc_nbsr_reg(int node, int channel, int reg_offset)
{
	unsigned long flags;
	if (cpu_has(CPU_HWBUG_MCNA_PLLMC_ACCESS) && MCNA_REG(reg_offset) && (channel == 1))
		channel = 2;
	u32 reg_val;
	raw_spin_lock_irqsave(&sic_mc_reg_lock, flags);
	sic_write_node_nbsr_reg(node, MC_CH, channel);
	reg_val = sic_read_node_nbsr_reg(node, reg_offset);
	raw_spin_unlock_irqrestore(&sic_mc_reg_lock, flags);
	return reg_val;
}
EXPORT_SYMBOL(sic_read_node_v7_mc_nbsr_reg);


static void
sic_write_node_mc_nbsr_reg(int node, int channel, int reg_offset, unsigned int reg_value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		unsigned long flags;
		if (cpu_has(CPU_HWBUG_MCNA_PLLMC_ACCESS) && MCNA_REG(reg_value) && (channel == 1))
			channel = 2;
		raw_spin_lock_irqsave(&sic_mc_reg_lock, flags);
		sic_write_node_nbsr_reg(node, MC_CH, channel);
		sic_write_node_nbsr_reg(node, reg_offset, reg_value);
		raw_spin_unlock_irqrestore(&sic_mc_reg_lock, flags);
	} else {
		sic_write_node_nbsr_reg(node, reg_offset, reg_value);
	}
}

void sic_write_node_v7_mc_nbsr_reg(int node, int channel, int reg_offset, u32 reg_value)
{
	unsigned long flags;
	if (cpu_has(CPU_HWBUG_MCNA_PLLMC_ACCESS) && MCNA_REG(reg_value) && (channel == 1))
		channel = 2;
	raw_spin_lock_irqsave(&sic_mc_reg_lock, flags);
	sic_write_node_nbsr_reg(node, MC_CH, channel);
	sic_write_node_nbsr_reg(node, reg_offset, reg_value);
	raw_spin_unlock_irqrestore(&sic_mc_reg_lock, flags);
}
EXPORT_SYMBOL(sic_write_node_v7_mc_nbsr_reg);

u32 sic_read_l3_reg(int node, int ha_bank, int reg_off)
{
	unsigned long flags;
	u32 reg_val;
	raw_spin_lock_irqsave(&sic_mc_reg_lock, flags);
	sic_write_node_nbsr_reg(node, L3_BASC, reg_off);
	reg_val = sic_read_node_nbsr_reg(node, L3_BASR(ha_bank));
	raw_spin_unlock_irqrestore(&sic_mc_reg_lock, flags);
	return reg_val;
}
EXPORT_SYMBOL(sic_read_l3_reg);

void  sic_write_l3_reg(int node, int ha_bank, int reg_off, u32 val)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&sic_mc_reg_lock, flags);
	sic_write_node_nbsr_reg(node, L3_BASC, reg_off);
	sic_write_node_nbsr_reg(node, L3_BASR(ha_bank), val);
	raw_spin_unlock_irqrestore(&sic_mc_reg_lock, flags);
}
EXPORT_SYMBOL(sic_write_l3_reg);


static u32 sic_read_ocn_reg(int node, int commn, int reg_off)
{
	unsigned long flags;
	u32 reg_val;
	raw_spin_lock_irqsave(&sic_mc_reg_lock, flags);
	sic_write_node_nbsr_reg(node, L3_BASC, reg_off);
	reg_val = sic_read_node_nbsr_reg(node, OCN_LASR(commn));
	raw_spin_unlock_irqrestore(&sic_mc_reg_lock, flags);
	return reg_val;
}

u32 sic_read_ha_reg(int node, int ha_bank, int reg_off)
{
	unsigned long flags;
	u32 reg_val;
	raw_spin_lock_irqsave(&sic_mc_reg_lock, flags);
	sic_write_node_nbsr_reg(node, HA_BASC, reg_off);
	reg_val = sic_read_node_nbsr_reg(node, LOC_HA_BASC(ha_bank));
	raw_spin_unlock_irqrestore(&sic_mc_reg_lock, flags);
	return reg_val;
}

void sic_write_ha_reg(int node, int ha_bank, int reg_off, u32 val)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&sic_mc_reg_lock, flags);
	sic_write_node_nbsr_reg(node, HA_BASC, reg_off);
	sic_write_node_nbsr_reg(node, LOC_HA_BASC(ha_bank), val);
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

e2k_mc_ecc_t sic_get_mc_ecc(int node, int num)
{
	int reg_offset = sic_mc_ecc_reg_offset(node, num);
	if (reg_offset) {
		return (e2k_mc_ecc_t) {
			.word = sic_read_node_mc_nbsr_reg(node, num, reg_offset)
		};
	}

	return E2K_MC_ECC_DISABLED;
}
EXPORT_SYMBOL(sic_get_mc_ecc);

void sic_set_mc_ecc(int node, int num, e2k_mc_ecc_t reg_value)
{
	int reg_offset = sic_mc_ecc_reg_offset(node, num);
	if (reg_offset)
		sic_write_node_mc_nbsr_reg(node, num, reg_offset, AW(reg_value));
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
	int reg_offset = sic_mc_opmb_reg_offset(node, num);
	if (reg_offset)
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
	int reg_offset = sic_mc_cfg_reg_offset(node, num);
	if (reg_offset)
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
	int reg_offset = sic_ipcc_csr_reg_offset(num);
	if (reg_offset)
		return sic_read_node_nbsr_reg(node, reg_offset);

	return 0;
}

void sic_set_ipcc_csr(int node, int num, unsigned int reg_value)
{
	int reg_offset = sic_ipcc_csr_reg_offset(num);
	if (reg_offset)
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
	int reg_offset = sic_ipcc_str_reg_offset(num);
	if (reg_offset)
		return sic_read_node_nbsr_reg(node, reg_offset);

	return 0;
}

void sic_set_ipcc_str(int node, int num, unsigned int val)
{
	int reg_offset = sic_ipcc_str_reg_offset(num);
	if (reg_offset)
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
	int reg_offset = sic_io_str_reg_offset(num);
	if (reg_offset)
		return sic_read_node_nbsr_reg(node, reg_offset);

	return 0;
}

void sic_set_io_str(int node, int num, unsigned int val)
{
	int reg_offset = sic_io_str_reg_offset(num);
	if (reg_offset)
		sic_write_node_nbsr_reg(node, reg_offset, val);
}

static void create_nodes_io_config(void);

int __init e2k_early_iohub_online(int node, int link)
{
	e2k_iol_csr_t io_link;
	e2k_io_csr_t io_hub;
	int domain = node_iolink_to_domain(node, link);
	int iohub_on = 0;

	DebugENBSR("started on node %d link %d\n", node, link);
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
		AW(io_link) = early_sic_read_node_iolink_nbsr_reg(node, link, SIC_iol_csr);
		if (io_link.mode != IOHUB_IOL_MODE)
			return 0;
		AW(io_hub) = early_sic_read_node_iolink_nbsr_reg(node, link, SIC_io_csr);
		if (io_hub.ch_on) {
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



/* Secret knowledge of v7. See bug 129813
mc_en  = [31 : 24]
mch_en = [12 : 11]
       for e8v7:
MC0  turned on,  if OCN_MIL.mc_en[0]=1
MC1  turned on,  if OCN_MIL.mc_en[1]=1
*/

static int v7_mc_enabled(e2k_ocn_mil_t ocn_mil, int mc)
{
	u32 mc_en = ocn_mil.mc_en;
	if (machine.native_id == MACHINE_ID_E8V7) {
		return (mc_en & (1 << mc));
	}
	switch (mc >> 1) {
	case 0: return (mc_en & (1 << 0));
	case 1: return (mc_en & (1 << 3));
	case 2: return (mc_en & (1 << 2));
	case 3: return (mc_en & (1 << 1));
	case 4: return (mc_en & (1 << 4));
	case 5: return (mc_en & (1 << 7));
	case 6: return (mc_en & (1 << 6));
	case 7: return (mc_en & (1 << 5));
	default: return 0;
	}
}

static int v7_mch_enabled(int node, int mc)
{
	if (machine.native_id == MACHINE_ID_E8V7) {
		return true;
	}
	u32 mcna_ctrl = sic_read_node_v7_mc_nbsr_reg(node, 2 * (mc >> 1), MCNA_CTRL);
	return ((mcna_ctrl >> 11) & (1 << (mc & 1)));
}

static int is_mc_enabled(int node, int mch)
{
	if (!node_online(node)) {
		return 0;
	}
	e2k_mc_ctl_t mc_ctl = sic_get_mc_ctl(node, mch);
	if (!mc_ctl.mcen) {
		return 0;
	}
	if (machine.native_iset_ver == E2K_ISET_V6) {
		e2k_hmu_mic_t hmu_mic;
		AW(hmu_mic) = sic_read_node_nbsr_reg(node, HMU_MIC);
		return !!(hmu_mic.mcen & (1 << mch));
	}
	if (machine.native_iset_ver == E2K_ISET_V7) {
		e2k_ocn_mil_t ocn_mil;
		AW(ocn_mil) = sic_read_node_nbsr_reg(node, OCN_MIL);
		return !!(v7_mc_enabled(ocn_mil, mch) && v7_mch_enabled(node, mch));
	}
	return 1;
}


phys_addr_t nodes_nbsr_phys_base[MAX_NUMNODES];
u64 mc_enabled_mask[MAX_NUMNODES] = { 0 };
EXPORT_SYMBOL(mc_enabled_mask);

int __init e2k_sic_init(void)
{
	unsigned char __iomem *nbsr_base;
	phys_addr_t phys_base;
	int node;
	int ret = 0;

	if (!HAS_MACHINE_L_SIC) {
		printk("e2k_sic_init() the arch has not SIC\n");
		return -ENODEV;
	}
	for_each_online_node(node) {
		phys_base = (unsigned long) THE_NODE_NBSR_PHYS_BASE(node);
		nbsr_base = (unsigned char __iomem *) ioremap_np(phys_base, NODE_NBSR_SIZE);
		if (nbsr_base == NULL) {
			pr_info("e2k_sic_init() could not map NBSR registers\n"
			       "of node #%d, phys base 0x%llx, size 0x%lx\n",
			       node, phys_base, NODE_NBSR_SIZE);
			ret = -ENOMEM;
		}
		DebugSIC("map NBSR of node #%d phys base 0x%llx, size 0x%lx to virtual addr 0x%px\n",
			 node, phys_base, NODE_NBSR_SIZE, nbsr_base);
		nodes_nbsr_base[node] = nbsr_base;
		nodes_nbsr_phys_base[node] = phys_base;
		int mc;
		for (mc = 0; mc < SIC_MC_COUNT; mc++) {
			if (is_mc_enabled(node, mc)) {
				mc_enabled_mask[node] |= (1 << mc);
			}
		}
		pr_info("mc_enabled_mask[%d] = 0x%08llx\n", node, mc_enabled_mask[node]);
		if (CURRENT_ISET >= E2K_ISET_V7) {
			e2k_l3_imsk_t r;
			AW(r) = 0;
			r.ecc_sed_dm = 1;
			r.ecc_sed_ld = 1;
			r.pmon = 1;
			sic_write_node_nbsr_reg(node, L3_IMSK, AW(r));
		}
	}
	create_nodes_io_config();
	return ret;
}

unsigned long domain_to_pci_conf_base[MAX_NUMIOLINKS] = {
	[0 ... (MAX_NUMIOLINKS - 1)] = 0
};

#ifdef CONFIG_IOHUB_DOMAINS
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

static void create_nodes_pci_conf(void)
{

	int domain;

	for_each_iohub(domain) {
		domain_to_pci_conf_base[domain] = sic_domain_pci_conf_base(domain);
		DebugSIC("IOHUB domain #%d (node %d, IO link %d) PCI CFG base 0x%lx\n",
			 domain, iohub_domain_to_node(domain), iohub_domain_to_link(domain),
			 domain_to_pci_conf_base[domain]);
	}

}
#else /* !CONFIG_IOHUB_DOMAINS: */
static void create_nodes_pci_conf(void)
{
	domain_to_pci_conf_base[0] = sic_domain_pci_conf_base(0);
}
#endif /* !CONFIG_IOHUB_DOMAINS */

#ifdef CONFIG_IOHUB_DOMAINS
/*
 * IO Links of all nodes configuration
 */

static void create_iolink_config(int node, int link)
{
	e2k_iol_csr_t io_link;
	e2k_io_csr_t io_hub;
	e2k_rdma_cs_t rdma;
	int link_on;

	link_on = 0;

	/* FIXME: IO link registers of SIC mutate to WLCC registers */
	/* on legacy SIC */
	/* now we assume IO link on node #0 connected to IOHUB online */
	if (HAS_MACHINE_E2K_LEGACY_SIC) {
		AW(io_link) = 0;
		io_link.mode = IOHUB_IOL_MODE;
		io_link.abtype = IOHUB_ONLY_IOL_ABTYPE;
	} else {
		AW(io_link) = sic_read_node_iolink_nbsr_reg(node, link, SIC_iol_csr);
	}
	printk(KERN_INFO "Node #%d IO LINK #%d is", node, link);
	if (io_link.mode == IOHUB_IOL_MODE) {
		node_iohub_set(node, link, iolink_iohub_map);
		iolink_iohub_num++;
		printk(" IO HUB controller");
		/* FIXME: IO link registers of SIC mutate to WLCC registers */
		/* on legacy SIC */
		/* now we assume IO link on node #0 connected to IOHUB online */
		if (HAS_MACHINE_E2K_LEGACY_SIC) {
			AW(io_hub) = 0;
			io_hub.ch_on = 1;
		} else {
			AW(io_hub) = sic_read_node_iolink_nbsr_reg(node, link, SIC_io_csr);
		}
		if (io_hub.ch_on) {
			node_iohub_set(node, link, iolink_online_iohub_map);
			iolink_online_iohub_num++;
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
			AW(rdma) = sic_read_node_iolink_nbsr_reg(node, link, SIC_rdma_cs);
			if (rdma.ch_on) {
				node_rdma_set(node, link,
					      iolink_online_rdma_map);
				iolink_online_rdma_num++;
				link_on = 1;
				printk(" ON 0x%08x", AW(rdma));
			} else {
				printk(" OFF 0x%08x", AW(rdma));
			}
		} else {
			printk(" not connected");
		}
	}
	if (link_on) {
		int ab_type = io_link.abtype;
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
			iolinks_num++;
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
static nodemask_t	node_iohub_map = NODE_MASK_NONE;
static nodemask_t	node_online_iohub_map = NODE_MASK_NONE;
static int		node_iohub_num = 0;
static int		node_online_iohub_num = 0;
static nodemask_t	node_rdma_map = NODE_MASK_NONE;

static void __init create_nodes_io_config(void)
{
	int node;
	e2k_iol_csr_t io_link;
	e2k_io_csr_t io_hub;
	e2k_rdma_cs_t rdma;
	int link_on;

	for_each_online_node(node) {
		link_on = 0;
		/* FIXME: IO link registers of SIC mutate to WLCC registers */
		/* on legacy SIC */
		/* now we assume IO link on node #0 connected to IOHUB online */
		if (HAS_MACHINE_E2K_LEGACY_SIC) {
			io_link.mode = IOHUB_IOL_MODE;
			io_link.abtype = IOHUB_ONLY_IOL_ABTYPE;
		} else {
			AW(io_link) = sic_read_node_nbsr_reg(node, SIC_iol_csr);
		}
		printk("Node #%d IO LINK is", node);
		if (io_link.mode == IOHUB_IOL_MODE) {
			node_set(node, node_iohub_map);
			node_iohub_num++;
			printk(" IO HUB controller");
			/* FIXME: IO link registers of SIC mutate to WLCC */
			/* registers on legacy SIC */
			/* now we assume IO link on node #0 connected to */
			/* IOHUB online */
			if (HAS_MACHINE_E2K_LEGACY_SIC) {
				AW(io_hub) = 0;
				io_hub.ch_on = 1;
			} else {
				AW(io_hub) = sic_read_node_nbsr_reg(node, SIC_io_csr);
			}
			if (io_hub.ch_on) {
				node_set(node, node_online_iohub_map);
				node_online_iohub_num++;
				link_on = 1;
				printk(" ON");
			} else {
				printk(" OFF");
			}
		} else {
			node_set(node, node_rdma_map);
			printk(" RDMA controller");
			AW(rdma) = sic_read_node_nbsr_reg(node, SIC_rdma_cs);
			if (rdma.ch_on) {
				link_on = 1;
				printk(" ON 0x%08x", AW(rdma));
			} else {
				printk(" OFF 0x%08x", AW(rdma));
			}
		}
		if (link_on) {
			int ab_type = io_link.abtype;
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

#endif /* !CONFIG_IOHUB_DOMAINS */



static DEFINE_RAW_SPINLOCK(sic_error_lock);

static void sic_mc_regs_dump(int node)
{
	if (CURRENT_ISET < E2K_ISET_V6) {
		int offset, i;

		for (i = 0; i < SIC_MC_COUNT; i++) {
			char s[256];
			e2k_mc_ecc_t ecc = sic_get_mc_ecc(node, i);
			pr_emerg("%s\n", l_mc_get_error_str(&ecc, i, s, sizeof(s)));
		}

		pr_emerg("MC registers dump:\n");
		offset = SIC_MC_BASE;
		for (i = 0; offset < SIC_MC_BASE + SIC_MC_SIZE; offset += 4, i++) {
			if ((i > 0) && ((i & 3) == 0)) {
				pr_emerg("");
			}
			pr_cont("0x%08x ", sic_read_node_nbsr_reg(node, offset));
		}
		pr_emerg("\n");
	} else {
		int mc;
		u32 reg;
		pr_emerg("Crime MC_STATUS regs:\n");
		for_each_mc_enabled_of_node(node, mc) {
			reg = sic_read_node_v7_mc_nbsr_reg(node, mc, MC_STATUS_E2K);
			if (reg != MC_STATUS_REG_GOOD)
				pr_emerg("MC_STATUS[%d] 0x%x\n", mc, reg);
		}
	}

}


static void sic_ha_l3_regs_dump(int node)
{
	u64 ha_mask = (u64)sic_read_node_nbsr_reg(node, OCN_L3EN0) |
		      ((u64)(sic_read_node_nbsr_reg(node, OCN_L3EN1) & 0xffff) << 32);
	int ha;
	u32 reg;
	ha_mask = ~ha_mask & CURRENT_HA_MASK;
	pr_emerg("Crime HA_INT and L3_INT regs:\n");
	for (ha = 0; ha < machine.sic_ha_num; ha++) {
		if (!(ha_mask & (1 << ha))) {
			continue;
		}
		reg = sic_read_ha_reg(node, ha, HA_INT);
		if (reg) {
			pr_emerg("HA_INT of L3 %d: 0x%08x\n", ha, reg);
		}
		reg = sic_read_l3_reg(node, ha, L3_INT);
		if (reg) {
			pr_emerg("L3_INT of L3 %d: 0x%08x\n", ha, reg);
			if (cpu_has(CPU_FEAT_V7_CPU_REGS) && (reg & (1 << 4))) {
				reg = sic_read_l3_reg(node, ha, L3_EMRG0);
				pr_emerg("       L3_EMRG0 of L3 %d: 0x%08x\n", ha, reg);
				reg = sic_read_l3_reg(node, ha, L3_EMRG1);
				pr_emerg("       L3_EMRG1 of L3 %d: 0x%08x\n", ha, reg);
				reg = sic_read_l3_reg(node, ha, L3_EMRG2);
				pr_emerg("       L3_EMRG2 of L3 %d: 0x%08x\n", ha, reg);
				reg = sic_read_l3_reg(node, ha, L3_EMRG3);
				pr_emerg("       L3_EMRG3 of L3 %d: 0x%08x\n", ha, reg);
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

static void sic_ocn_par_regs_dump(int node)
{
	u32 ocn_par[6];
	int comm;
	int i;

	pr_emerg("Crime OCN_PAR regs:\n");
	for (comm = 0; comm < CURRENT_COMMS_IN_NODE; comm++) {
		for (i = 0; i < 6; i++) {
			ocn_par[i] = sic_read_ocn_reg(node, comm, OCN_PAR(i));
		}
		if (ocn_par[0] || ocn_par[1] || ocn_par[2] ||
		    ocn_par[3] || ocn_par[4] || ocn_par[5]) {
			pr_emerg("OCN_PAR regs of COMM %d: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n",
				 comm, ocn_par[0], ocn_par[1], ocn_par[2],
				 ocn_par[3], ocn_par[4], ocn_par[5]);
		}
	}
}

void do_sic_error_interrupt(void)
{
	int node;
	unsigned long flags;

	do {
		cpu_relax();
	} while (!raw_spin_trylock_irqsave(&sic_error_lock, flags));

	for_each_online_node(node) {
		pr_emerg("----- NODE%d -----\n", node);

		pr_emerg("%s_INT=0x%x\n",
			 (CURRENT_ISET < E2K_ISET_V6) ? "SIC" : "XMU",
			 sic_read_node_nbsr_reg(node, SIC_sic_int));

		if (CURRENT_ISET == E2K_ISET_V6) {
			sic_hmu_regs_dump(node);
		} else if (CURRENT_ISET >= E2K_ISET_V7) {
			sic_ha_l3_regs_dump(node);
			sic_ocn_par_regs_dump(node);
		}

		sic_mc_regs_dump(node);
	}

	raw_spin_unlock_irqrestore(&sic_error_lock, flags);
}

static irqreturn_t sic_interrupt(int irq, void *data)
{
	do_sic_error_interrupt();
	panic("SIC error interrupt received on CPU%d:\n", smp_processor_id());

	return IRQ_HANDLED;
}

static int sic_probe(struct platform_device *pdev)
{
	int ret;
	struct device *dev = &pdev->dev;
	ret = platform_get_irq(pdev, 0);
	if (ret <= 0)
		return ret;

	ret = devm_request_irq(dev, ret, sic_interrupt,
			       0, dev_name(dev), NULL);
	if (WARN(ret, "%s: %d", dev_name(dev), ret))
		return ret;
	return ret;
}

static const struct of_device_id sic_dt_ids[] = {
	{.compatible = "mcst,sic"},
	{ /* sentinel value */ }
};

static struct platform_driver sic_driver = {
	.driver = {
		.name = "sic",
		.of_match_table = of_match_ptr(sic_dt_ids),
	},
	.probe    = sic_probe,
};
module_platform_driver(sic_driver);
MODULE_LICENSE("GPL v2");
