#include <linux/module.h>
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

#undef  BOOT_DEBUG_SIC_MODE
#undef  BootDebugSIC
#define	BOOT_DEBUG_SIC_MODE	0	/* SIC mapping & init */
#define	BootDebugSIC(fmt, args...)					\
		({ if (BOOT_DEBUG_SIC_MODE)				\
			dump_printk(fmt, ##args); })


extern int __initdata max_iolinks;
extern int __initdata max_node_iolinks;

int boot_get_e2k_machine_id(void)
{
	e2k_idr_t idr;
	int mdl;
	int mach_id;

	idr = read_IDR_reg();
	mdl = idr.IDR_mdl;
	BootDebugSIC("boot_get_e2k_machine_id() CPU model is %d, "
		"IDR 0x%lx\n", mdl, idr.IDR_reg);
	if (mdl == IDR_E3S_MDL) {
		mach_id  = MACHINE_ID_E3S;
	} else if (mdl == IDR_ES2_DSP_MDL) {
		mach_id  = MACHINE_ID_ES2_DSP;
	} else if (mdl == IDR_ES2_RU_MDL) {
		mach_id  = MACHINE_ID_ES2_RU;
	} else if (mdl == IDR_E2S_MDL) {
		mach_id  = MACHINE_ID_E2S;
	} else if (mdl == IDR_E8C_MDL) {
		mach_id  = MACHINE_ID_E8C;
	} else if (mdl == IDR_E1CP_MDL) {
		mach_id  = MACHINE_ID_E1CP;
	} else if (mdl == IDR_E8C2_MDL) {
		mach_id  = MACHINE_ID_E8C2;
	} else {
		BootDebugSIC("Undefined CPU model number %d\n", mdl);
		mach_id  = MACHINE_ID_NONE;
	}
	return mach_id;
}

void __init
boot_e2k_sic_setup_arch(void)
{
	if (BOOT_HAS_MACHINE_E2K_FULL_SIC) {
		boot_machine.x86_io_area_base = E2K_FULL_SIC_IO_AREA_PHYS_BASE;
	} else if (BOOT_HAS_MACHINE_E2K_LEGACY_SIC) {
		boot_machine.x86_io_area_base =
			E2K_LEGACY_SIC_IO_AREA_PHYS_BASE;
	} else {
		pr_err("boot_e2k_sic_setup_arch() this machine has not SIC "
			"capability\n");
	}
	boot_machine.rev = read_IDR_reg().IDR_rev;
}

#ifdef CONFIG_PIC
/*
 * Read IRQ # vector from PIC (implemented only on e3s and e90s)
 */
# define E2K_IO_APIC_PIC_IRQVEC_REG	0x0f0	/* IOAPIC register number */
						/* to read ExtINT IRQ vector */
# define E2K_IO_APIC_AREA_PHYS_BASE	0x00000000fec00000UL
static inline int
io_apic_read_PIC_IRQVEC(void)
{
	return E2K_READ_MAS_W(E2K_IO_APIC_AREA_PHYS_BASE +
			E2K_IO_APIC_PIC_IRQVEC_REG, MAS_IOADDR);
}
#endif

int e2k_sic_get_vector(void)
{
	int vector;

	vector = arch_apic_read(APIC_VECT);

	if (unlikely(APIC_VECT_IS_EXTINT(vector))) {
#ifdef CONFIG_PIC
		/*
		 * IOAPIC IRQ vector has flag of PIC IRQ/ so read now vector
		 * from PIC through IOAPIC special register
		 */

		/* FIXME: IOAPICs can be more then one, but PIC can have only 1 */
		/* now we assume only BSP processor IOHUB has active PIC */
		vector = io_apic_read_PIC_IRQVEC();
#else
		pr_emerg("Received ExtINT interrupt on kernel without PIC! "
				"Read vector is %x\n", vector);
		vector = SPURIOUS_APIC_VECTOR;
#endif
	}

	return APIC_VECT_VECTOR(vector);
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

unsigned int sic_get_mc_opmb(int node, int num)
{
	int reg_offset = 0;

	switch (num) {
	case 0:
		reg_offset = SIC_mc0_opmb;
		break;
	case 1:
		reg_offset = SIC_mc1_opmb;
		break;
	case 2:
		reg_offset = SIC_mc2_opmb;
		break;
	case 3:
		reg_offset = SIC_mc3_opmb;
		break;
	};

	if (reg_offset)
		return sic_read_node_nbsr_reg(node, reg_offset);
	return 0;
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

unsigned int sic_get_ipcc_pmr(int node, int num)
{
	int reg_offset = 0;

	switch (num) {
	case 1:
		reg_offset = SIC_ipcc_pmr1;
		break;
	case 2:
		reg_offset = SIC_ipcc_pmr2;
		break;
	case 3:
		reg_offset = SIC_ipcc_pmr3;
		break;
	};

	if (reg_offset)
		return sic_read_node_nbsr_reg(node, reg_offset);
	return 0;
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

unsigned int sic_get_io_csr(int node, int num)
{
	int reg_offset = 0;

	switch (num) {
	case 0:
		reg_offset = SIC_io_csr;
		break;
	case 1:
		reg_offset = ((IS_MACHINE_ES2) ? SIC_io_csr1 : SIC_io_csr_hi);
		break;
	};

	if (reg_offset)
		return sic_read_node_nbsr_reg(node, reg_offset);
	return 0;
}

unsigned int sic_get_io_tmr(int node, int num)
{
	int reg_offset = 0;

	switch (num) {
	case 0:
		reg_offset = SIC_io_tmr;
		break;
	case 1:
		reg_offset = ((IS_MACHINE_ES2) ? SIC_io_tmr1 : SIC_io_tmr_hi);
		break;
	};

	if (reg_offset)
		return sic_read_node_nbsr_reg(node, reg_offset);
	return 0;
}

unsigned int sic_get_io_str(int node, int num)
{
	int reg_offset = 0;

	switch (num) {
	case 0:
		reg_offset = SIC_io_str;
		break;
	case 1:
		reg_offset = ((IS_MACHINE_ES2) ? SIC_io_str1 : SIC_io_str_hi);
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
		reg_offset = ((IS_MACHINE_ES2) ? SIC_io_str1 : SIC_io_str_hi);
		break;
	};

	if (reg_offset)
		sic_write_node_nbsr_reg(node, reg_offset, val);
}

unsigned int sic_get_pl_csr(int node, int num)
{
	int reg_offset = 0;

	switch (num) {
	case 0:
		reg_offset = SIC_pl_csr1;
		break;
	case 1:
		reg_offset = SIC_pl_csr2;
		break;
	case 2:
		reg_offset = SIC_pl_csr3;
		break;
	};

	if (reg_offset)
		return sic_read_node_nbsr_reg(node, reg_offset);
	return 0;
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
unsigned char *nodes_nbsr_base[MAX_NUMNODES] = { NULL };
EXPORT_SYMBOL(nodes_nbsr_base);

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
			"0x%llx, size 0x%lx to virtual addr 0x%p\n",
			node, phys_base, NODE_NBSR_SIZE, nbsr_base);
		nodes_nbsr_base[node] = nbsr_base;
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
		node_rdma_set(node, link, iolink_rdma_map);
		iolink_rdma_num ++;
		printk(" RDMA controller");
		rdma.E2K_RDMA_CS_reg =
			sic_read_node_iolink_nbsr_reg(node, link, SIC_rdma_cs);
		if (rdma.E2K_RDMA_CS_ch_on) {
			node_rdma_set(node, link, iolink_online_rdma_map);
			iolink_online_rdma_num ++;
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
