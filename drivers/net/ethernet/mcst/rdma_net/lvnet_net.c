/*
 * Copyright (c) 2011 by MCST.
 * lvnet_net.c
 * Implementation of networking protocols TCP\IP via rdma
 */

#include <linux/errno.h>
#include <linux/string.h>
#ifdef MEM_COPY_LCC_V9
#undef  memcpy
extern void *memcpy(void *to, const void *from, size_t len);
#endif
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/fb.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/pci.h>
#include <linux/ioport.h>
#include <linux/of_platform.h>
#include <linux/pci.h>
#ifdef	CONFIG_MCST
#include <asm/setup.h>
#endif


#include "rdma_user_intf_net.h"
#include "rdma_reg_net.h"
#include "rdma_error_net.h"

#define LVNET_TIMEOUT 20
#define LVNET_RX_INTR 100
#define LVNET_TX_INTR 200

#ifdef BOTTOM_HALF_RX_THREAD_RDMA
extern int rx_thread_action(void *arg);
#endif

#define NUM_NODE_RDMA(num_link_rdma)	(int)(num_link_rdma/NODE_NUMIOLINKS)
#define NUM_LINK_IN_NODE_RDMA(num_link_rdma)	(num_link_rdma  - ((int)(num_link_rdma/NODE_NUMIOLINKS))*NODE_NUMIOLINKS)

///DEFINE_RAW_SPINLOCK(mu_fix_event); 

#if defined(CONFIG_E90S) || defined(CONFIG_E2K)
extern int	rdma_present;
#endif

extern int init_mem_for_event(void);
extern void clear_mem_for_event(void);
int mem_print_event = 0;

#ifdef CONFIG_E90

#undef sbus_writew
#undef sbus_writel
#undef sbus_readl
#undef sbus_readw

#define sbus_writew(b,addr)	(*(volatile unsigned short *)(addr) = (b))
#define sbus_writel(b,addr)	(*(volatile unsigned int *)(addr) = (b))
#define sbus_readl(addr)	(*(volatile unsigned int *)(addr))
#define sbus_readw(addr)	(*(volatile unsigned short *)(addr))

#define BASE_NODE0      	0x80000000
#define NODE_OFF	 	0x00000100
#define NODE0_SIZE	 	0x0d
#define NODE_SIZE	 	0x38

#define for_each_online_rdma(node) 	for (node = 1; node <= 2; node++ )

struct of_device *op_rdmaon = NULL;
struct of_device *op_rdmach0 = NULL;
struct of_device *op_rdmach1 = NULL;

#endif

#ifndef CONFIG_E90
static inline void
sic_write_node_nbsr_reg_rdma(int node_id, unsigned int reg_offset, unsigned int reg_value);

static inline unsigned int
sic_read_node_nbsr_reg_rdma(int node_id, int reg_offset);
#endif

void free_ptx(struct rdma_tx_block *ptx, struct rdma_private *rp);
static void rdma_free_hwresources(struct rdma_private *rp);

unsigned int	SHIFT_VID;		/* RDMA VID 			*/
unsigned int	SHIFT_IOL_CSR;
unsigned int	SHIFT_IO_CSR;
unsigned int	SHIFT_CH0_IDT;		/* RDMA ID/Type E90/E3M1	*/
unsigned int	SHIFT_CH1_IDT;		/* RDMA ID/Type E90/E3M1	*/
unsigned int	SHIFT_CH_IDT;		/* RDMA ID/Type E3S/E90S	*/
unsigned int	SHIFT_CS;		/* RDMA Control/Status 000028a0	*/
unsigned int	SHIFT_DD_ID;		/* Data Destination ID 		*/
unsigned int	SHIFT_DMD_ID;		/* Data Message Destination ID 	*/
unsigned int	SHIFT_N_IDT;		/* Neighbour ID/Type 		*/
unsigned int	SHIFT_ES;		/* Event Status 		*/
unsigned int	SHIFT_IRQ_MC;		/* Interrupt Mask Control 	*/
unsigned int	SHIFT_DMA_TCS;		/* DMA Tx Control/Status 	*/
unsigned int	SHIFT_DMA_TSA;		/* DMA Tx Start Address 	*/
unsigned int	SHIFT_DMA_HTSA;		/* DMA Tx Start Address 	*/
unsigned int	SHIFT_DMA_TBC;		/* DMA Tx Byte Counter 		*/
unsigned int	SHIFT_DMA_RCS;		/* DMA Rx Control/Status 	*/
unsigned int	SHIFT_DMA_RSA;		/* DMA Rx Start Address 	*/
unsigned int	SHIFT_DMA_HRSA;		/* DMA Rx Start Address 	*/
unsigned int	SHIFT_DMA_RBC;		/* DMA Rx Byte Counter 		*/
unsigned int	SHIFT_MSG_CS;		/* Messages Control/Status 	*/
unsigned int	SHIFT_TDMSG;		/* Tx Data_Messages Buffer 	*/
unsigned int	SHIFT_RDMSG;		/* Rx Data_Messages Buffer 	*/
unsigned int	SHIFT_CAM;		/* CAM - channel alive management */


/* Init rdma for sparc V9 */

#ifdef CONFIG_E90S

static inline unsigned int
sic_read_node_iolink_nbsr_reg(int node_id, unsigned int io_link, int reg_offset)
{
	unsigned int reg_value;

	reg_value =  __raw_readl(BASE_NODE0 + node_id * NODE_OFF + SIC_io_reg_offset(io_link, reg_offset));
	return (reg_value);
}

static inline void
sic_write_node_iolink_nbsr_reg(int node_id, int io_link, unsigned int reg_offset, unsigned int reg_value)
{
	__raw_writel(reg_value, BASE_NODE0 + node_id * NODE_OFF + SIC_io_reg_offset(io_link, reg_offset));
}

#if 0
static inline unsigned int
sic_read_nbsr_reg(int reg_offset)
{
	return (sic_read_node_nbsr_reg(numa_node_id(), reg_offset));
}

static inline void
sic_write_nbsr_reg(int reg_offset, unsigned int reg_value)
{
	sic_write_node_nbsr_reg(numa_node_id(), reg_offset, reg_value);
}
#endif

unsigned int	node_online_rdma_map = 0;
static int		node_rdma_num = 0;
static int		node_online_rdma_num = 0;


void init_node_e90s( void )
{
/* Until no support NUMA for sparc V9 in kernel*/
	unsigned int 	node_iohub_map = 0;
	unsigned int	node_online_iohub_map = 0;
	int		node_iohub_num = 0;
	int		node_online_iohub_num = 0;
	unsigned int	node_rdma_map = 0;
	unsigned int	node_mask = 0,
			cpu_mask = 0,
			i;
	int 		node;
	int 		link_on;
	unsigned int 	reg;

	for_each_online_cpu(node) {
		cpu_mask = cpu_mask | (1 << node);
	}
	for (i = 0; i < MAX_NUMIOLINKS; i++ ) {
		if ((cpu_mask >> E90S_MAX_NR_NODE_CPUS*i) & 0x0000000f)
			node_mask = node_mask | (1 << i);
	}
	for (i = 0; i < MAX_NUMIOLINKS; i++ )
	{
		if ((node_mask >> i) & 0x00000001)
		node = i;
			else continue;
#define DBG_REG_RDMA 0
#if DBG_REG_RDMA	
		reg = sic_read_node_nbsr_reg_rdma( node, NBSR_INT_CFG );
		printk("NBSR_INT_CFG: %x \n", reg);
		reg = sic_read_node_nbsr_reg_rdma( node, NBSR_INF_CFG );
		printk("NBSR_INF_CFG: %x \n", reg);
		reg = sic_read_node_nbsr_reg_rdma( node, NBSR_NODE_CFG );
		printk("NBSR_NODE_CFG: %x \n", reg);
		reg = sic_read_node_nbsr_reg_rdma( node, SHIFT_IO_CSR );
		printk("SHIFT_IO_CSR: %x \n",  reg);
		reg = sic_read_node_nbsr_reg_rdma( node, SHIFT_CS );
		printk("SHIFT_CS: %x \n", reg);
#endif
		link_on = 0;
		reg = sic_read_node_nbsr_reg_rdma( node, NBSR_NODE_CFG );
		printk("Node #%d IO LINK is", node);

		if ((reg & IO_HAB_FLAG) == IOHUB_IOL_MODE) {
			node_iohub_map = node_iohub_map | (1 << node);
			node_iohub_num ++;
			printk(" IO HUB controller");
			reg =
				sic_read_node_nbsr_reg_rdma( node, SHIFT_IO_CSR );
			if (reg & E90_IO_CSR_ch_on) {
				node_online_iohub_map = node_online_iohub_map | (1 << node);
				node_online_iohub_num ++;
				link_on = 1;
				printk(" ON");
			} else {
				printk(" OFF");
			}
		} else {
			node_rdma_map = node_rdma_map | (1 << node);
			node_rdma_num ++;
			printk(" RDMA controller");
			reg = sic_read_node_nbsr_reg_rdma( node, SHIFT_CS );
			if (reg & E90_RDMA_CS_ch_on) {
				node_online_rdma_map = node_online_rdma_map | (1 << node);
				node_online_rdma_num ++;
				link_on = 1;
				printk(" ON");
			} else {
				printk(" OFF");
			}
		}

		if (link_on) {
			reg = sic_read_node_nbsr_reg_rdma( node, NBSR_INF_CFG );
			int ab_type = (reg & E90_IOL_CSR_abtype_mask) >> 16 ;

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

	printk(" \n");
	}
}
#endif

#ifndef CONFIG_E90
static inline void
sic_write_node_nbsr_reg_rdma(int node_id, unsigned int reg_offset, unsigned int reg_value)
{
	sic_write_node_iolink_nbsr_reg(NUM_NODE_RDMA(node_id), NUM_LINK_IN_NODE_RDMA(node_id), reg_offset, reg_value );
}

static inline unsigned int
sic_read_node_nbsr_reg_rdma(int node_id, int reg_offset)
{
	unsigned int reg_value;
	reg_value = sic_read_node_iolink_nbsr_reg(NUM_NODE_RDMA(node_id), NUM_LINK_IN_NODE_RDMA(node_id), reg_offset );
	return (reg_value);
}
#endif

#ifdef CONFIG_E90
static int rdma_check_hardware(const char *name, struct device_node *dp)
{
	int	inst = 0;

	for_each_node_by_name(dp, name)
		inst++;

	if ( !inst )
		return 0;

	return inst;
}
#endif

void init_regs( void )
{
#ifdef CONFIG_E2K /* E3M & E3S*/
	if (HAS_MACHINE_E2K_FULL_SIC) { /* E3S */
		SHIFT_IOL_CSR	= IOL_CSR;
		SHIFT_IO_CSR	= IO_CSR;
		SHIFT_VID	= RDMA_VID;
		SHIFT_CH_IDT	= RDMA_CH_IDT;
		SHIFT_CS	= RDMA_CS;
		SHIFT_DD_ID	= RDMA_DD_ID;
		SHIFT_DMD_ID	= RDMA_DMD_ID;
		SHIFT_N_IDT	= RDMA_N_IDT;
		SHIFT_ES	= RDMA_ES;
		SHIFT_IRQ_MC	= RDMA_IRQ_MC;
		SHIFT_DMA_TCS	= RDMA_DMA_TCS;
		SHIFT_DMA_TSA	= RDMA_DMA_TSA;
		SHIFT_DMA_TBC	= RDMA_DMA_TBC;
		SHIFT_DMA_RCS	= RDMA_DMA_RCS;
		SHIFT_DMA_RSA	= RDMA_DMA_RSA;	
		SHIFT_DMA_RBC	= RDMA_DMA_RBC;	
		SHIFT_MSG_CS	= RDMA_MSG_CS;
		SHIFT_TDMSG	= RDMA_TDMSG;
		SHIFT_RDMSG	= RDMA_RDMSG;
		SHIFT_DMA_HTSA	= RDMA_DMA_HTSA;
		SHIFT_DMA_HRSA	= RDMA_DMA_HRSA;
		SHIFT_CAM	= RDMA_CAM;
	}
	else { /* E3M */
		SHIFT_VID	= E3M_RDMA_VID;
		SHIFT_CH0_IDT	= E3M_RDMA_CH0_IDT;
		SHIFT_CH1_IDT	= E3M_RDMA_CH1_IDT;
		SHIFT_CS	= E3M_RDMA_CS;
		SHIFT_DD_ID	= E3M_RDMA_DD_ID;
		SHIFT_DMD_ID	= E3M_RDMA_DMD_ID;
		SHIFT_N_IDT	= E3M_RDMA_N_IDT;
		SHIFT_ES	= E3M_RDMA_ES;
		SHIFT_IRQ_MC	= E3M_RDMA_IRQ_MC;
		SHIFT_DMA_TCS	= E3M_RDMA_DMA_TCS;
		SHIFT_DMA_TSA	= E3M_RDMA_DMA_TSA;
		SHIFT_DMA_TBC	= E3M_RDMA_DMA_TBC;
		SHIFT_DMA_RCS	= E3M_RDMA_DMA_RCS;
		SHIFT_DMA_RSA	= E3M_RDMA_DMA_RSA;	
		SHIFT_DMA_RBC	= E3M_RDMA_DMA_RBC;	
		SHIFT_MSG_CS	= E3M_RDMA_MSG_CS;
		SHIFT_TDMSG	= E3M_RDMA_TDMSG;
		SHIFT_RDMSG	= E3M_RDMA_RDMSG;
		SHIFT_CAM	= E3M_RDMA_CAM;
	}
#endif /* E3M & E3S*/

#ifdef CONFIG_E90 /* E90 */
	SHIFT_VID	= RDMA_VID;
	SHIFT_CH0_IDT	= RDMA_CH0_IDT;
	SHIFT_CH1_IDT	= RDMA_CH1_IDT;
	SHIFT_CS	= RDMA_CS;
	SHIFT_DD_ID	= RDMA_DD_ID;
	SHIFT_DMD_ID	= RDMA_DMD_ID;
	SHIFT_N_IDT	= RDMA_N_IDT;
	SHIFT_ES	= RDMA_ES;
	SHIFT_IRQ_MC	= RDMA_IRQ_MC;
	SHIFT_DMA_TCS	= RDMA_DMA_TCS;
	SHIFT_DMA_TSA	= RDMA_DMA_TSA;
	SHIFT_DMA_TBC	= RDMA_DMA_TBC;
	SHIFT_DMA_RCS	= RDMA_DMA_RCS;
	SHIFT_DMA_RSA	= RDMA_DMA_RSA;	
	SHIFT_DMA_RBC	= RDMA_DMA_RBC;	
	SHIFT_MSG_CS	= RDMA_MSG_CS;
	SHIFT_TDMSG	= RDMA_TDMSG;
	SHIFT_RDMSG	= RDMA_RDMSG;
#endif 	/* E90 */

#ifdef CONFIG_E90S /* E90S */
	SHIFT_VID	= RDMA_VID;
	SHIFT_IOL_CSR	= IOL_CSR;
	SHIFT_IO_CSR	= IO_CSR;
	SHIFT_CH_IDT	= RDMA_CH_IDT;
	SHIFT_DMA_HTSA	= RDMA_DMA_HTSA;
	SHIFT_DMA_HRSA	= RDMA_DMA_HRSA;
	SHIFT_CS	= RDMA_CS;
	SHIFT_DD_ID	= RDMA_DD_ID;
	SHIFT_DMD_ID	= RDMA_DMD_ID;
	SHIFT_N_IDT	= RDMA_N_IDT;
	SHIFT_ES	= RDMA_ES;
	SHIFT_IRQ_MC	= RDMA_IRQ_MC;
	SHIFT_DMA_TCS	= RDMA_DMA_TCS;
	SHIFT_DMA_TSA	= RDMA_DMA_TSA;
	SHIFT_DMA_TBC	= RDMA_DMA_TBC;
	SHIFT_DMA_RCS	= RDMA_DMA_RCS;
	SHIFT_DMA_RSA	= RDMA_DMA_RSA;	
	SHIFT_DMA_RBC	= RDMA_DMA_RBC;	
	SHIFT_MSG_CS	= RDMA_MSG_CS;
	SHIFT_TDMSG	= RDMA_TDMSG;
	SHIFT_RDMSG	= RDMA_RDMSG;
	SHIFT_CAM	= RDMA_CAM;
#endif 	/* E90S */
}


void		*lvnet_dev[MAX_RDMA_NET_DEV]; 	
void __iomem 	*e_rega[MAX_RDMA_NET_DEV];	/* e1rega, e2rega, e3rega; */
rdma_who_t	who;
int		state_tx[MAX_RDMA_NET_DEV]; 
int		state_rx[MAX_RDMA_NET_DEV]; 
int 		stop_rdma[MAX_RDMA_NET_DEV] = {0};

spin_snd_msg_rdma_p	spin_snd_msg_rdma[MAX_RDMA_NET_DEV]; 
int			rdma_event_init;
#ifdef CONFIG_E2K
//extern void __iomem e3m_reg_base; /* for do_IRQ */
#endif

#if DBG_DHCP
int	print_header = 1;
#else
int	print_header = 0;
#endif

extern int arp_find(unsigned char *haddr, struct sk_buff *skb);
struct rdma_private	*root_rdma_dev;

unsigned int	clear_es(struct rdma_private *rp, int reset);
u32		rdma_set_print_packets = 0;
u32		who_locked_free_skb = 0;
u32		who_locked_tx = 0;
int		rdc_byte[MAX_RDMA_NET_DEV];

unsigned int lvnet_tx_timeout_count[MAX_RDMA_NET_DEV] = {0};

#ifdef CONFIG_E2K
static void rdma_remove_net(struct pci_dev *dev);
static int rdma_pci_probe(struct pci_dev *dev, const struct pci_device_id *ent);
struct rdma_state *rdma_state;


/*
static struct pci_device_id rdma_devices[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_RDMA, PCI_DEVICE_ID_MCST_RDMA) },
	{ 0, }
};

static struct pci_driver rdma_driver = {
	.name		= "rdma_net",
	.id_table	= rdma_devices,
	.probe		= rdma_pci_probe,
	.remove		= rdma_remove_net
};
*/

int pcibios_read_config_dword (unsigned char bus, unsigned char devfn,
			       unsigned char where, u32 *val)
{
	outl(CONFIG_CMD_RDMA(bus, devfn, where), 0xCF8);
	*val = inl(0xCFC);
	return 0;
}

int pcibios_write_config_dword (unsigned char bus, unsigned char devfn,
				unsigned char where, u32 val)
{
	outl(CONFIG_CMD_RDMA(bus, devfn, where), 0xCF8);
	outl(val, 0xCFC);
	return 0;
}

static int rdma_pci_probe(struct pci_dev *dev, const struct pci_device_id *ent)
{
	unsigned char	bus_number_rdma, devfn_rdma;
	struct pci_bus	*bus;
	int		ret = -EINVAL;
	int		id, i;
	unsigned int	val;
	int		size_rdma_state;

	if ((ret = pci_enable_device(dev))) {
		printk( KERN_ERR "rdma_probe: finish FAIL (%s: cannot enable pci device)\n", dev->dev.init_name );
		return ret; 
	}
	if (!(bus = dev->bus)) {
		printk("rdma_probe: finish FAIL (no rdma_cards, bus is NULL)\n");
		pci_disable_device(dev);
		return -ENODEV;
	}
	for (devfn_rdma = 0; devfn_rdma < 0xff; devfn_rdma++) {
		pcibios_read_config_dword(bus->number, devfn_rdma, 0, &id);
		if (id == 0x71918086) {
			bus_number_rdma = bus->number;
			rdma_dbg("EDBUS-RDMA config space\n");
			for (i = 0; i < 7; i++) {
				pcibios_read_config_dword(bus->number, devfn_rdma, i<<2, &val);
				rdma_dbg("%2d 0x%08u\n", i<<2, val);
			}
			break;
		}
	}
	if (devfn_rdma == 0xff) {
		printk("rdma_probe: finish FAIL (no rdma_cards, devfn_rdma == 0xff)\n");
		pci_disable_device(dev);
		return -ENODEV;
	}

	pcibios_write_config_dword(bus->number, devfn_rdma, 4, 0x7);
	pcibios_read_config_dword(bus->number, devfn_rdma, 4, &val);

	size_rdma_state = sizeof (struct rdma_state);
	rdma_state = (struct rdma_state *)kmalloc(size_rdma_state, GFP_KERNEL);
	if (rdma_state == (struct rdma_state *)NULL) {
		pci_disable_device(dev);
		printk("rdma_probe: rdma_state == NULL\n");
		return (-ENOMEM);
	}

	memset(rdma_state, 0, size_rdma_state);

	rdma_state->mmio_base	= pci_resource_start(dev, PCI_MMIO_BAR);
	rdma_state->mmio_len	= pci_resource_len(dev, PCI_MMIO_BAR);

	if ( (ret = pci_request_region(dev, PCI_MMIO_BAR, "rdma MMIO")) ) {
		printk("rdma_probe: finish FAIL (cannot reserved PCI I/O and memory resource)\n");
		goto fail_mem;
	}

	rdma_state->mmio_vbase = ioremap(rdma_state->mmio_base, rdma_state->mmio_len);

	if ( !rdma_state->mmio_vbase ) {
		printk("rdma_probe: finish FAIL (cannot ioremap MMIO (0x%08lx:0x%x))\n", rdma_state->mmio_base, rdma_state->mmio_len);
		ret = -ENOMEM;
		goto fail_mmio_ioremap;
	}
	rdma_dbg("rdma_probe: mmio_vbase: %p mmio_base: 0x%ld mmio_len: %d\n",
			rdma_state->mmio_vbase, rdma_state->mmio_base, rdma_state->mmio_len);
	
	pci_set_drvdata(dev, rdma_state);
	return 0;

fail_mmio_ioremap:
	pci_release_region(dev, PCI_MMIO_BAR);
fail_mem:
	pci_disable_device(dev);
	kfree(rdma_state);
	return ret;
}

static void rdma_remove_net(struct pci_dev *dev)
{
	struct rdma_state *rdma_st = pci_get_drvdata(dev);

	rdma_dbg("rdma_remove START\n");
	if (rdma_st) {
		rdma_dbg("rdma_remove rdma_st yes\n");
		iounmap(rdma_st->mmio_vbase);
		pci_release_region(dev, PCI_MMIO_BAR);
		pci_set_drvdata(dev, NULL);
		pci_disable_device(dev);
		kfree(rdma_st);
	}
	rdma_dbg("rdma_remove FINISH\n");
}
#endif

static u8 rdma_char_to_hex(const char name)
{
    u8 val = 0;

	switch (name) {
	    case '0':
		val = 0x0; break;
	    case '1':
		val = 0x1; break;
	    case '2':
		val = 0x2; break;
	    case '3':
		val = 0x3; break;
	    case '4':
		val = 0x4; break;
	    case '5':
		val = 0x5; break;
	    case '6':
		val = 0x6; break;
	    case '7':
		val = 0x7; break;
	    case '8':
		val = 0x8; break;
	    case '9':
		val = 0x9; break;
	    case 'a':
		val = 0xa; break;
	    case 'b':
		val = 0xb; break;
	    case 'c':
		val = 0xc; break;
	    case 'd':
		val = 0xd; break;
	    case 'e':
		val = 0xe; break;
	    case 'f':
		val = 0xf; break;
	}
		return val;
}

int 	rdma_mac_setup = 0;

static u8	id_ethaddr[6] = {0};
module_param_array(id_ethaddr, byte, NULL, 0);
MODULE_PARM_DESC(id_ethaddr, "Mac address for sn");

static int __init rdma_mac_Setup(char *str)
{
	int 	i;
	rdma_mac_setup = 1;
	rdma_dbg("rdma_mac_Setup: start - str  %s strlen(str) %x\n", str, (unsigned int) strlen(str));
	if (strlen(str)!=17) {
		printk("rdma_mac_Setup: bad mac adress:%s strlen(str) %x\n", str,(unsigned int) strlen(str));
		return 0;
	}
	i = 0;
	while ((str != NULL) && (*str != '\0')) {
		id_ethaddr[i] = (rdma_char_to_hex (str[0]) << 4 ) | (rdma_char_to_hex (str[1])) ;
		str = strchr(str, ':');
		if (str != NULL){
			str += strspn(str, ":");
			i++;
		}
	}
	rdma_dbg("rdma_mac_Setup: finish - ok\n");
	return 1;

}
__setup("mac-rdma=", rdma_mac_Setup);

#ifdef CONFIG_RDMA_NET 
int	net_device_present = 1;
static int __init rdma_not_net(char *str)
{
	net_device_present = 0;
	return 1;
}
__setup("RdmaNN", rdma_not_net);
#else
int	net_device_present = 0;
#endif


#ifdef CONFIG_E2K
	int 	boot_cl = 0x00;

static int __init rdma_client_Setup(char *str)
{
	int 	ints[3];

	rdma_dbg("rdma_client_Setup: start\n");
	
	str = get_options(str, ARRAY_SIZE(ints), ints);
	if (ints[0]) boot_cl = ints[1];
	else {
		printk("rdma_client_Setup: finish - not client \n");
	return 0;
	}
	rdma_dbg("rdma_client_Setup: finish - client : %d\n", boot_cl);
	return 1;
}

__setup("boot_cl=", rdma_client_Setup);
#endif


/* Returns nanoseconds */
hrtime_t
rdma_gethrtime(void)
{ 
	struct timeval tv;
	hrtime_t val;
	do_gettimeofday(&tv);
	val = tv.tv_sec * 1000000000LL + tv.tv_usec * 1000LL;
	return (val);
}

int get_pc_call()
{
#ifdef CONFIG_E2K
	return E2K_GET_DSREG(clkr);
#else
	return get_cycles();
#endif

}

unsigned int allign_dma(unsigned int n)
{
	if (n&(ALLIGN_RDMA-1)) {
		n += ALLIGN_RDMA;
		n = n&(~(ALLIGN_RDMA-1));
	}
        return n;
}

int find_link_rdma(struct rdma_private *rp)
{
	int count_read_riam = 0,
		 count_read_riam_max =
	    20, rdma_find = 0;
	int evs;

	WRR(rp->regbase, SHIFT_MSG_CS, MSG_CS_SIR_Msg,
	    (dev_rdma_sem_t *) NULL);
	while (count_read_riam < count_read_riam_max) {
		evs =
		    RDR(rp->regbase, SHIFT_ES,
				(dev_rdma_sem_t *) NULL);
			if (evs & ES_RIAM_Ev) {
				WRR(rp->regbase, SHIFT_ES, ES_RIAM_Ev,
				    (dev_rdma_sem_t *) NULL);
				rdma_find = 1;
				break;
			}
			count_read_riam++;

		}
	return rdma_find;
}

void prn_reg_rdma(void __iomem *reg_base)
{
	unsigned int 	inst = 0xf;

#ifdef CONFIG_E90 /* E90 */
	int cpu = raw_smp_processor_id();
	if (reg_base == e_rega[0])
		inst = 2;
	else if (reg_base == e_rega[1])
		inst = 0;
	else if (reg_base == e_rega[2])
		inst = 1;
	else {
		printk("<1>cpu: %d reg_base=%lx BAD addres!!!\n",
		       cpu, (unsigned long) reg_base);
		return;
	}
#else /* !E90 */
	unsigned int 	i;
	if (HAS_MACHINE_E2K_FULL_SIC) { /*E3S & E90S*/
		for ( i = 0; i < MAX_RDMA_NET_DEV; i++) {
			if (reg_base == e_rega[i]) inst = i;
		}
		if ( inst == 0xf ) {
			printk("PRN_REG_RDMA: Error address SIC(NBSR) registers.\n");
			return;
		}
	}
#ifdef CONFIG_E2K
	else { /* E3M */
		if (reg_base == e_rega[0])
			inst = 0;
		else {
			printk("PRN_REG_RDMA: 0x%lx  BAD addres!!!\n",
			       (unsigned long) reg_base);
			return;
		}
	}
#endif /* E2K */

#endif /* E90 */

#if defined(CONFIG_E90S) || defined(CONFIG_E2K) 
/* !E90 */
	if (HAS_MACHINE_E2K_FULL_SIC) { /* E90S & E3S */
		printk("%x 0x%08x 0x%04x - SHIFT_IOL_CSR\n",	inst, RDR (reg_base,SHIFT_IOL_CSR, (dev_rdma_sem_t *)NULL), SHIFT_IOL_CSR);
		printk("%x 0x%08x 0x%04x - SHIFT_IO_CSR\n",	inst, RDR (reg_base,SHIFT_IO_CSR, (dev_rdma_sem_t *)NULL), SHIFT_IO_CSR);
		printk("%x 0x%08x 0x%04x - SHIFT_VID\n", 	inst, RDR (reg_base,SHIFT_VID, (dev_rdma_sem_t *)NULL), SHIFT_VID);
		printk("%x 0x%08x 0x%04x - SHIFT_CS\n",		inst, RDR (reg_base,SHIFT_CS, (dev_rdma_sem_t *)NULL), SHIFT_CS);
		printk("%x 0x%08x 0x%04x - SHIFT_CH_IDT\n", 	inst, RDR (reg_base,SHIFT_CH_IDT, (dev_rdma_sem_t *)NULL), SHIFT_CH_IDT);
	} else { /* E3M */
		printk("%x 0x%08x 0x%04x - SHIFT_VID\n", 	inst, RDR (reg_base,SHIFT_VID, (dev_rdma_sem_t *)NULL), SHIFT_VID);
		printk("%x 0x%08x 0x%04x - SHIFT_CS\n",		inst, RDR (reg_base,SHIFT_CS, (dev_rdma_sem_t *)NULL), SHIFT_CS);
		printk("%x 0x%08x 0x%04x - SHIFT_CH0_IDT\n", 	inst, RDR (reg_base,SHIFT_CH0_IDT, (dev_rdma_sem_t *)NULL), SHIFT_CH0_IDT);
		printk("%x 0x%08x 0x%04x - SHIFT_CH1_IDT\n", 	inst, RDR (reg_base,SHIFT_CH1_IDT, (dev_rdma_sem_t *)NULL), SHIFT_CH1_IDT);
	}
#else /* E90 */
	u32 inst_temp = 2;
	printk("%x 0x%08x 0x%04x - SHIFT_VID\n", 	inst_temp, RDR (reg_base,SHIFT_VID, (dev_rdma_sem_t *)NULL), SHIFT_VID);
	printk("%x 0x%08x 0x%04x - SHIFT_CS\n",		inst_temp, RDR (reg_base,SHIFT_CS, (dev_rdma_sem_t *)NULL), SHIFT_CS);
	printk("%x 0x%08x 0x%04x - SHIFT_CH0_IDT\n", 	inst, RDR (reg_base,SHIFT_CH0_IDT, (dev_rdma_sem_t *)NULL), SHIFT_CH0_IDT);
	printk("%x 0x%08x 0x%04x - SHIFT_CH1_IDT\n", 	inst, RDR (reg_base,SHIFT_CH1_IDT, (dev_rdma_sem_t *)NULL), SHIFT_CH1_IDT);
#endif /* !E90 */
	printk("%x 0x%08x 0x%04x - SHIFT_DD_ID\n", 	inst, RDR (reg_base,SHIFT_DD_ID, (dev_rdma_sem_t *)NULL), SHIFT_DD_ID);
	printk("%x 0x%08x 0x%04x - SHIFT_DMD_ID\n", 	inst, RDR (reg_base,SHIFT_DMD_ID, (dev_rdma_sem_t *)NULL), SHIFT_DMD_ID);
	printk("%x 0x%08x 0x%04x - SHIFT_N_IDT\n", 	inst, RDR (reg_base,SHIFT_N_IDT, (dev_rdma_sem_t *)NULL), SHIFT_N_IDT);
	printk("%x 0x%08x 0x%04x - SHIFT_ES\n", 	inst, RDR (reg_base,SHIFT_ES, (dev_rdma_sem_t *)NULL), SHIFT_ES);
	printk("%x 0x%08x 0x%04x - SHIFT_IRQ_MC\n", 	inst, RDR (reg_base,SHIFT_IRQ_MC, (dev_rdma_sem_t *)NULL), SHIFT_IRQ_MC);
	printk("%x 0x%08x 0x%04x - SHIFT_DMA_TCS\n", 	inst, RDR (reg_base, SHIFT_DMA_TCS, (dev_rdma_sem_t *)NULL), SHIFT_DMA_TCS);
	printk("%x 0x%08x 0x%04x - SHIFT_DMA_TSA\n", 	inst, RDR (reg_base, SHIFT_DMA_TSA, (dev_rdma_sem_t *)NULL), SHIFT_DMA_TSA);
	printk("%x 0x%08x 0x%04x - SHIFT_DMA_TBC\n", 	inst, RDR (reg_base, SHIFT_DMA_TBC, (dev_rdma_sem_t *)NULL), SHIFT_DMA_TBC);
	printk("%x 0x%08x 0x%04x - SHIFT_DMA_RCS\n", 	inst, RDR (reg_base, SHIFT_DMA_RCS, (dev_rdma_sem_t *)NULL), SHIFT_DMA_RCS);
	printk("%x 0x%08x 0x%04x - SHIFT_DMA_RSA\n", 	inst, RDR (reg_base, SHIFT_DMA_RSA, (dev_rdma_sem_t *)NULL), SHIFT_DMA_RSA);
	printk("%x 0x%08x 0x%04x - SHIFT_DMA_RBC\n", 	inst, RDR (reg_base, SHIFT_DMA_RBC, (dev_rdma_sem_t *)NULL), SHIFT_DMA_RBC);
	printk("%x 0x%08x 0x%04x - SHIFT_MSG_CS\n", 	inst, RDR (reg_base, SHIFT_MSG_CS, (dev_rdma_sem_t *)NULL), SHIFT_MSG_CS);
	printk("%x 0x%08x 0x%04x - SHIFT_TDMSG\n", 	inst, RDR (reg_base, SHIFT_TDMSG, (dev_rdma_sem_t *)NULL), SHIFT_TDMSG);
/*	printk("%d 0x%08x 0x34 - SHIFT_RDMSG\n", 	inst, RDR (reg_base, SHIFT_RDMSG, (dev_rdma_sem_t *)NULL), SHIFT_RDMSG); */
#if defined(CONFIG_E90S) || defined(CONFIG_E2K) 
/* !E90 */
	printk("%x 0x%08x 0x%04x - SHIFT_CAM\n", inst, RDR (reg_base, SHIFT_CAM, (dev_rdma_sem_t *)NULL), SHIFT_CAM);
#endif /* !E90 */ 
}

void WRR(void __iomem *reg_base, unsigned int reg_offset, unsigned int reg_value, dev_rdma_sem_t *dev_sem)
{
	unsigned int 	inst = 0xf;
	struct	rdma_event	*re;

	re = &rdma_event;
#ifdef CONFIG_E90 /* E90 */
	int cpu = raw_smp_processor_id();
	if (reg_base == e_rega[0])
		inst = 2;
	else if (reg_base == e_rega[1])
		inst = 0;
	else if (reg_base == e_rega[2])
		inst = 1;
	else {
		printk("<1>cpu: %d WRR[0x%lx] reg=%x BAD addres!!!\n",
		       cpu, (unsigned long) reg_base, reg_offset);
		return;
	}
	if ((reg_offset & 3) != 0) {
		printk
		    ("<1>cpu: %d WRR[0x%lx] reg=%x unaligned! inst: %x\n",
		     cpu, (unsigned long) reg_base, reg_offset, inst);
		return;
	}
	sbus_writel(reg_value, reg_base + reg_offset); 
#else /* !E90 */
	unsigned int 	i;
	if (HAS_MACHINE_E2K_FULL_SIC) { /*E3S & E90S*/
		for ( i = 0; i < MAX_RDMA_NET_DEV; i++) {
			if (reg_base == e_rega[i]) inst = i;
		}
		if ( inst == 0xf ) {
			printk("WRR: Error address SIC(NBSR) registers.\n");
			return;
		}
		sic_write_node_nbsr_reg_rdma(inst, reg_offset, reg_value);
	}
#ifdef CONFIG_E2K
	else { /* E3M */
		if (reg_base == e_rega[0])
			inst = 0;
		else {
			printk("WRR: 0x%lx  BAD addres!!!\n",
			       (unsigned long) reg_base);
			return;
		}
		writel(reg_value, reg_base + reg_offset);

	}
#endif
#endif /* E90 */
	event_regs(inst, WRR_EVENT, reg_offset, reg_value);
}

unsigned int RDR(void __iomem *reg_base, unsigned int reg_offset, dev_rdma_sem_t *dev_sem)
{
	unsigned int reg_value;
	unsigned int 	inst = 0xf;
	struct	rdma_event	*re;

	re = &rdma_event;

#ifdef CONFIG_E90 /* E90 */
	int cpu = raw_smp_processor_id();
	if (reg_base == e_rega[0])
		inst = 2;
	else if (reg_base == e_rega[1])
		inst = 0;
	else if (reg_base == e_rega[2])
		inst = 1;
	else {
		printk("<1>cpu: %d RDR[0x%lx] reg=%x BAD addres!!!\n",
		       cpu, (unsigned long) reg_base, reg_offset);
		return((unsigned int)-1);
	}
	if ((reg_offset & 3) != 0) {
		printk
		    ("<1>cpu: %d RDR[0x%lx] reg=%x unaligned! inst: %x\n",
		     cpu, (unsigned long) reg_base, reg_offset, inst);
		return((unsigned int)-1);
	}
	reg_value = sbus_readl(reg_base + reg_offset); 
#else /* !E90 */
	unsigned int i;
	if (HAS_MACHINE_E2K_FULL_SIC) { /*E3S & E90S*/
		for ( i = 0; i < MAX_RDMA_NET_DEV; i++) {
			if (reg_base == e_rega[i]) inst = i;
		}

		if ( inst == 0xf ) {
			printk("WRR: Error address SIC(NBSR) registers.\n");
			return((unsigned int)-1);
		}
		reg_value = sic_read_node_nbsr_reg_rdma(inst, reg_offset);
	}
#ifdef CONFIG_E2K
	else { /* E3M */
		if (reg_base == e_rega[0])
			inst = 0;
		else {
			printk("RDR: 0x%lx  BAD addres!!!\n",
			       (unsigned long) reg_base);
			return((unsigned int)-1);
		}
		reg_value = readl(reg_base + reg_offset);
	}
#endif
#endif /* E90 */
	event_regs(inst, RDR_EVENT, reg_offset, reg_value);
	return reg_value;

}

struct	rdma_event rdma_event;

void	fix_event(unsigned int channel, unsigned int event, unsigned int val1, unsigned int val2)
{
	unsigned long flags;
	struct	rdma_event *re;

	if (!rdma_event_init)
		return;
	re = &rdma_event;
	raw_spin_lock_irqsave(&re->mu_fix_event, flags);
	re->event[re->event_cur + 0] = (unsigned int)rdma_gethrtime();
	re->event[re->event_cur + 1] = event;
	re->event[re->event_cur + 2] = channel;
	re->event[re->event_cur + 3] = val1;
	re->event[re->event_cur + 4] = val2;
	re->event_cur = re->event_cur + 5;
	if (SIZE_EVENT - re->event_cur < 5) {
		re->event_cur = 0;
	}
	raw_spin_unlock_irqrestore(&re->mu_fix_event, flags);
	return;
}

#ifdef CONFIG_E90
int vik_mmu_probe_c(unsigned int va)
{
	unsigned int va_page;
	unsigned int fa_page;
	unsigned int ttt;
	unsigned int fsr;

        dbg_asi("<1>vik_mmu_probe_c: va: 0x%08x\n", va);
	va_page = va & 0xfffff000;
	ttt = va_page | 0x400;
	fa_page = read_asi(ttt, 0x03);
        dbg_asi("<1>vik_mmu_probe_c:1 read_asi(0x%08x, 0x03): 0x%08x\n",
		ttt,fa_page);
	if (!fa_page)
		goto probe_done;
	ttt = va_page | 0x200;
	fa_page = read_asi(ttt, 0x03);
        dbg_asi("<1>vik_mmu_probe_c:2 read_asi(0x%08x, 0x03): 0x%08x\n",
		ttt,fa_page);
	ttt = fa_page & 3;
	if (ttt != 2)
		goto f1;
	ttt = va_page >> 12;
	ttt = ttt & 0xfff;
	ttt = ttt << 8;
	fa_page = fa_page | ttt;
	goto probe_done;
f1:
	ttt = va_page | 0x100;
	fa_page = read_asi(ttt, 0x03);
        dbg_asi("<1>vik_mmu_probe_c:3 read_asi(0x%08x, 0x03): 0x%08x\n",
		ttt,fa_page);
	ttt = fa_page & 3;
	if (ttt != 2)
		goto f2;
	ttt = va_page >> 12;
	ttt = ttt & 0x3f;
	ttt = ttt << 8;
	fa_page = fa_page | ttt;
	goto probe_done;
f2:
	ttt = va_page | 0x000;
	fa_page = read_asi(ttt, 0x03);
        dbg_asi("<1>vik_mmu_probe_c:4 read_asi(0x%08x, 0x03): 0x%08x\n",
		ttt,fa_page);

probe_done:
	fsr = read_asi(0x300, 0x04);
	dbg_asi("<1>vik_mmu_probe_c: va: 0x%08x fsr: 0x%08x\n",
		va, fsr);
	return 	fa_page;
}

int	va_to_pa_sol(unsigned int va)
{
	unsigned int ttt;

	ttt = vik_mmu_probe_c(va);
        dbg_asi("<1>va_to_pa_sol: vik_mmu_probe_c: 0x%08x 0x%08x\n",
		va,ttt);
	if (ttt == 0) {
		return -1;
	}
	if ((ttt & 3) == 0) {
		return -1;
	}
	if (ttt & 0x10000000) {
		ttt |= 0x04000000;
		printk("<1>va_to_pa_sol: va: 0x%08x pte: 0x%08x is ASI 21\n",
			va, ttt);
	}
	ttt >>= 8;
	return ((ttt << 12) | (va & 0xfff));
}

int	va_to_pte(unsigned int va)
{
	unsigned int ttt;

	ttt = vik_mmu_probe_c(va);
        dbg_asi("<1>va_to_pa_sol: vik_mmu_probe_c: 0x%08x 0x%08x\n",
		va,ttt);
	if (ttt == 0) {
		return -1;
	}
	if ((ttt & 3) == 0) {
		return -1;
	}
	if (ttt & 0x10000000) {
		ttt |= 0x04000000;
	}
	dbg_asi("<1>va_to_pa_sol: va: 0x%08x pte: 0x%08x\n",
		va,ttt);
	return ttt;
}

int	va_to_fa_ld_lock(unsigned int va)
{
	return va_to_pa_sol(va);
}
#endif /* CONFIG_E90 */

int lvnet_open(struct net_device *dev)
{
	struct rdma_private 	*rp;
	struct stat_rdma	*pst;
	struct	rdma_event	*re;
	re = &rdma_event;
#ifndef CONFIG_E90
	u32	 		reg;
#endif
	rdma_dbg("lvnet_open: START for %s\n", dev->name);
	netif_start_queue(dev);
	rp = netdev_priv(dev);	
//	event_queue_net(rp->inst, LVNET_OPEN_EVENT, 0, 0);
//	event_queue_net(rp->inst, NET_QUEUE_START_EVENT, 0, 0);
	pst = &rp->stat_rdma;
#if defined(CONFIG_E90S) || defined(CONFIG_E2K) 
/* !E90 */
	if (HAS_MACHINE_E2K_FULL_SIC) { /* E90S & E3S */
		reg = RDR(rp->regbase, SHIFT_DMA_TCS, 0);
		WRR(rp->regbase, SHIFT_DMA_TCS, reg | RCode_64 | DMA_TCS_DRCL, 0);
		reg = RDR(rp->regbase, SHIFT_DMA_RCS, 0);
		WRR(rp->regbase, SHIFT_DMA_RCS, reg | WCode_64, 0);
	}
#endif /* !E90 */
	WRR(rp->regbase, SHIFT_IRQ_MC, MASK_SET_NET,
	    (dev_rdma_sem_t *) NULL);
	pst->netif = 1;
	rp->opened = 1;

	rdma_dbg("lvnet_open: FINISH for %s\n", dev->name);
	return 0;

}

unsigned int clear_es(struct rdma_private *rp, int reset)
{
	struct rdma_tx_block *ptx;
	u32 evs;
	unsigned long flags;

	rdma_dbg("clear_es: start node # %x \n", rp->inst);
	if (rp->opened)  
		netif_stop_queue(rp->dev);
	if (reset)
		WRR(rp->regbase, SHIFT_IRQ_MC, 0x00000000, (dev_rdma_sem_t *) NULL);

	/* Read & clear ints */
	evs = RDR(rp->regbase, SHIFT_ES, (dev_rdma_sem_t *)NULL); 	

	if (reset && (evs & ES_RDM_Ev)) {
		int	rdmc = (evs & ES_RDMC)>>27;
		volatile unsigned int	msg;
		if (rdmc == 0)
			rdmc = 32;
		while (rdmc--) {
			msg = RDR(rp->regbase, SHIFT_RDMSG, (dev_rdma_sem_t *)NULL);
		}
	}

	WRR(rp->regbase, SHIFT_DMA_TCS, DMA_TCS_Tx_Rst, (dev_rdma_sem_t *)NULL);
	WRR(rp->regbase, SHIFT_DMA_RCS, DMA_RCS_Rx_Rst, (dev_rdma_sem_t *)NULL);
	WRR(rp->regbase, SHIFT_ES, evs & MASK_INTR_NET, (dev_rdma_sem_t *)NULL);

	if (reset) {
		ptx = &rp->rt_block;
		raw_spin_lock_irqsave(&ptx->lock, flags);
		ptx->rx = 0;
		reset_ptx(ptx);
		raw_spin_unlock_irqrestore(&ptx->lock, flags);
		ptx = &rp->tx_block;
		raw_spin_lock_irqsave(&ptx->lock, flags);
		ptx->tx = 0;
		reset_ptx(ptx);
		raw_spin_unlock_irqrestore(&ptx->lock, flags);
		if (rp->reset) {
#ifdef CONFIG_E90
			printk("Reset sn%x\n", rp->inst);
#else
			printk("Reset sn%x\n", NUM_NODE_RDMA(rp->inst) + (NUM_LINK_IN_NODE_RDMA(rp->inst)?(10 * NUM_NODE_RDMA(rp->inst) + NUM_LINK_IN_NODE_RDMA(rp->inst)):0));
#endif
			rp->reset = 0;
#ifdef BOTTOM_HALF_RX_REFILL_SKB
			raw_spin_lock(&rp->thread_lock);
			rp->start_thread = 1; 
			raw_spin_unlock(&rp->thread_lock);
			wake_up_process(rp->rdma_rx_tsk);
#endif
			if (rp->opened) { 
				WRR(rp->regbase, SHIFT_IRQ_MC, MASK_SET_NET, (dev_rdma_sem_t *) NULL);
				netif_wake_queue(rp->dev);
			}
			if (!rp->timeout) stop_rdma[rp->inst] = 0;
		}
		try_work(rp);
	}
#if defined(CONFIG_E90S) || defined(CONFIG_E2K) 
/* !E90 */
	u32 reg;
	if (HAS_MACHINE_E2K_FULL_SIC) { /* E90S & E3S */
		reg = RDR(rp->regbase, SHIFT_DMA_TCS, 0);
		WRR(rp->regbase, SHIFT_DMA_TCS, reg | RCode_64 | DMA_TCS_DRCL, 0);
		reg = RDR(rp->regbase, SHIFT_DMA_RCS, 0);
		WRR(rp->regbase, SHIFT_DMA_RCS, reg | WCode_64, 0);
	}
#endif /* !E90 */

//	if (reset)
//		WRR(rp->regbase, SHIFT_IRQ_MC, MASK_SET_NET, (dev_rdma_sem_t *) NULL);

	rdma_dbg("clear_es: stop node # %x \n", rp->inst);
	return RDR(rp->regbase, SHIFT_ES, (dev_rdma_sem_t *)NULL);

}

void reset_ptx(struct rdma_tx_block *ptx)
{
	struct rdma_tx_desc	*pbtx;
	unsigned int		i;

	rdma_dbg("reset_ptx: start ptx->alloc_buf_rdma # %x \n", ptx->alloc_buf_rdma);

	ptx->avail = TX_RING_SIZE;
	ptx->fe = ptx->fb = ptx->state_tx = ptx->state_rx = 0;
	ptx->rec_trwd_tx = ptx->rec_trwd_bc = ptx->rec_trwd_tr = ptx->last_snd_ready = 0;
	for (i = 0; i < ptx->alloc_buf_rdma; i++) {
		pbtx = &ptx->btx_ring[i];
		pbtx->count_dsf = pbtx->worked = pbtx->busy = pbtx->for_snd_trwd = pbtx->for_rec_trwd = 0;
		pbtx->for_rec_trwd = 0;
		*(u32 *)pbtx->vaddr = WASTE_PACKET;
	}
	rdma_dbg("reset_ptx: stop ptx->alloc_buf_rdma # %x \n", ptx->alloc_buf_rdma);
}

int lvnet_stop(struct net_device *dev)
{
	struct stat_rdma	*pst;
	struct rdma_private	*rp;
	struct	rdma_event	*re;
	re = &rdma_event;

	event_intr(0, LVNET_STOP_EVENT, 0, 0);
	rp = netdev_priv(dev);
	pst = &rp->stat_rdma;
	netif_stop_queue(dev);
	event_queue(0, NETIF_STOP_QUEUE, rp->inst, NR_lvnet_stop);
	pst->netif = 1;
	WRR(rp->regbase, SHIFT_IRQ_MC, 0, (dev_rdma_sem_t *) NULL);
	rp->opened = 0;
	return 0;
}

int	inst_transit = 0;
unsigned int	count_lvnet_tx[MAX_RDMA_NET_DEV] = {0};

#ifdef CONFIG_PREEMPT_RT_FULL
#define CHECK_DISABLED(n) \
				if (irqs_disabled()) { \
					printk("0x%x irqs_disabled in %s line: %d\n", n, __FUNCTION__, __LINE__); \
				} \
				if (()) { \
					printk("0x%x raw_irqs_disabled in %s line: %d\n", n, __FUNCTION__, __LINE__); \
				}
#else
#define CHECK_DISABLED(n)
#endif

int lvnet_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct rdma_tx_block	*ptx;
	struct rdma_tx_desc	*pbtx;
	struct stat_rdma	*pst;
	struct rdma_private	*rp;
	struct net_device_stats *p_stats;
	int 			ret = 0;
	u32 			inst;
	struct	rdma_event	*re;
	re = &rdma_event;
	unsigned long flags;

	rp = netdev_priv(dev);
	inst = rp->inst;
	count_lvnet_tx[inst]++;
//	CHECK_DISABLED(count_lvnet_tx[inst])
	event_queue_net(inst, LVNET_TX_EVENT, 0, count_lvnet_tx[inst]);
	dbg_dhcp("count_lvnet_tx 0x%08x\n", count_lvnet_tx[inst]);
	dbg_lvnet_tx("\nlvnet_tx(0x%x): start from 0x%x inst: %x\n", count_lvnet_tx[inst], get_pc_call(), rp->inst);
	pst = &rp->stat_rdma;
	p_stats = &rp->net_stats;
	ptx = &rp->tx_block;
	/* Close spinlock for tx_block[inst] */
	raw_spin_lock_irqsave(&ptx->lock, flags);
	if (PTX_BUFFS_AVAIL != ptx->avail) {
		raw_spin_unlock_irqrestore(&ptx->lock, flags);
		/* Error!!! Separated counters */ 
		printk("lvnet_tx(%x) 0x%x: ERR: PTX_BUFFS_AVAIL(%x) != ptx->avail(%x) "
			"fe: %x fb: %x tx: 0x%x %p\n",
			inst, count_lvnet_tx[inst], PTX_BUFFS_AVAIL, ptx->avail, ptx->fe, ptx->fb, ptx->tx, ptx);
		netif_stop_queue(dev);
		prn_puls(rp);
		ret = -1;
		goto try_sent_trwd;
	}
	if (!ptx->avail) {
		raw_spin_unlock_irqrestore(&ptx->lock, flags);
		/* Error!!! Not free buffers */ 
		printk("lvnet_tx(%x) 0x%u: ERR: ptx->avail is 0 "
			"tx: 0x%x %p\n",
			inst, count_lvnet_tx[inst], ptx->tx, ptx);
		p_stats->tx_errors++;
		pst->send_skb_pio_err_1++;
		/* Error!!! Close queue the stack */ 
		netif_stop_queue(dev);
		prn_puls(rp);
		if (ptx->fe != ptx->fb) {
			printk("lvnet_tx(%x) 0x%x: ERR: ptx->avail(%x), "
				"but fe(%x) != fb(%x) state_tx: %x state_rx: %x tx: 0x%x %p\n",
				inst, count_lvnet_tx[inst], ptx->avail, ptx->fe, ptx->fb, ptx->state_tx, ptx->state_rx, ptx->tx, ptx);
		}
		/* The package can not be taken from the stack */
		PRINT_BUFS(inst)
		pst->fail_lvnet_tx++;
		ret = -1;
		goto try_sent_trwd;
	}
	pbtx = &ptx->btx_ring[ptx->fe];
	/* Must be free*/
	if (pbtx->for_snd_trwd) {
		raw_spin_unlock_irqrestore(&ptx->lock, flags);
		/* Error - Must be free*/
		printk("lvnet_tx(%x) 0x%x: ERR: ptx->avail(%x), "
			"but pbtx->msg: 0x%x fe: %x fb: %x state_tx: %x state_rx: %x tx: 0x%x %p\n",
			inst, count_lvnet_tx[inst], ptx->avail, pbtx->for_snd_trwd, ptx->fe,
			ptx->fb, ptx->state_tx, ptx->state_rx, ptx->tx, ptx);
		/* The package can not be taken from the stack */
		netif_stop_queue(dev);
		pst->stop_wake_queue = 0;
		pst->stop_queue++;
		prn_puls(rp);
		ret = -1;
		goto try_sent_trwd;
	}
	ptx->fe = TX_NEXT(ptx->fe); ptx->avail--;pst->tx_avail = ptx->avail;
	if (ptx->avail <=0 ) {
		netif_stop_queue(dev);
		event_queue_net(rp->inst, NET_QUEUE_STOP_EVENT, ptx->avail, p_stats->tx_bytes);
		pst->stop_wake_queue = 0;
		pst->stop_queue++;
	}
	ptx->tx++;
	event_mem(inst, MEMCPY_EVENT, skb->len , 0); 		
	memcpy(pbtx->vaddr, skb->data, skb->len);
	event_mem(inst, MEMCPY_EVENT, skb->len , 1); 		
#ifdef CHECK_MEMORY_E90S	
	event_mem(inst, MEMCPY_EVENT, 4 , 0); 		
	memcpy(pbtx->vaddr + skb->len, &ptx->tx, sizeof(unsigned int));
	pbtx->for_snd_trwd = MSG_NET_WR | MSG_TRWD | ((skb->len & MSG_USER) + sizeof(unsigned int));
#else
	pbtx->for_snd_trwd = MSG_NET_WR | MSG_TRWD | (skb->len & MSG_USER);
#endif
	event_mem(inst, MEMCPY_EVENT, pbtx->for_snd_trwd , 1); 		
	pbtx->addr = skb;
#ifdef BOTTOM_HALF_RX_REFILL_SKB
	pbtx->skb_in_steck_for_free = 0;
#endif
#if AOE_DBG
	printk("tx(%x) ptx->tx: 0x%08x: len 0x%08x\n"
//		"%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x\n"
//		"%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x\n"
		"%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x\n",
		inst, ptx->tx, pbtx->for_snd_trwd & MSG_USER,
		*((u32 *)pbtx->vaddr+ 0), *((u32 *)pbtx->vaddr+ 1)
//		*((u32 *)pbtx->vaddr+ 2), *((u32 *)pbtx->vaddr+ 3),
//		*((u32 *)pbtx->vaddr+ 4), *((u32 *)pbtx->vaddr+ 5),
//		*((u32 *)pbtx->vaddr+ 6), *((u32 *)pbtx->vaddr+ 7)
		);
#endif

	pbtx->trans_start = dev->trans_start = jiffies;
	dbg_lvnet_tx("\nlvnet_tx(0x%x): pbtx->msg: 0x%x fe: %x fb: %x avail: %x ptx(%x): %p\n",
		count_lvnet_tx[inst], pbtx->for_snd_trwd, ptx->fe, ptx->fb, ptx->avail, inst, ptx); /* qdisc_restart */
	lvnet_tx_timeout_count[rp->inst] = 0;
	raw_spin_unlock_irqrestore(&ptx->lock, flags);
try_sent_trwd:
	who_locked_tx = 0;
	who_locked_free_skb = 2;
//	dev_kfree_skb_any(skb);
	who_locked_free_skb = 0;
	try_send_trwd(rp);
	dbg_lvnet_tx("\nlvnet_tx(0x%x): return %d\n", count_lvnet_tx[inst], ret); 
	event_queue_net(inst, LVNET_TX_EVENT, 1, count_lvnet_tx[inst]);
	return ret;
}


void prn_puls( struct rdma_private *rp )
{
//	if (mem_print_event) get_event_rdma();
	stop_rdma[rp->inst] = 1;
//	prn_reg_rdma(rp->regbase);
//	clear_es_for_error(rp);	
}

#if 0
#ifdef HAVE_TX_TIMEOUT
static int timeout = LVNET_TIMEOUT;
MODULE_PARM_DESC(timeout, "i");
#endif
#endif

#define clean_tx_ring									\
		ptx->avail = TX_RING_SIZE;						\
		pst->tx_avail = TX_RING_SIZE;						\
		ptx->running = 1;							\
		ptx->frx = TX_RING_SIZE;						\
		ptx->msg = 0;								\
		ptx->fe = ptx->fb = ptx->state_tx = ptx->state_rx = 0;	\
		for (i = 0; i < TX_RING_SIZE; i++) {					\
			pbtx = &ptx->btx_ring[i];					\
			pbtx->count_dsf = pbtx->worked = pbtx->busy = pbtx->msg = 0;	\
		}

/* Calling from dev_watchdog */
void lvnet_tx_timeout(struct net_device *dev) 
{
	struct rdma_private *rp;
	struct	rdma_event	*re;
	re = &rdma_event;

	printk("lvnet_tx_timeout: lvnet_tx_timeout start \n ");
	rp = netdev_priv(dev);
	event_intr(rp->inst, LVNET_TIMEOUT_EVENT, 0, lvnet_tx_timeout_count[rp->inst]); 
	/* Reset */
	rp->reset = 1;
	stop_rdma[rp->inst] = 1;
	rp->timeout = 1;
	clear_es(rp, 1);
	WRR(rp->regbase, SHIFT_MSG_CS, MSG_CS_SIR_Msg, (dev_rdma_sem_t *)NULL);
	mdelay(100);
	stop_rdma[rp->inst] = 0;
	rp->timeout = 0;
//	netif_wake_queue (dev);
	dev->trans_start = jiffies;
	printk("lvnet_tx_timeout: lvnet_tx_timeout stop \n ");
	return;

}

void reset_ptx_tx(struct rdma_tx_block *ptx)
{
	struct rdma_tx_desc	*pbtx;
	unsigned int		i;

	for (i = ptx->fb; ; i = TX_NEXT(i)) {
		pbtx = &ptx->btx_ring[i];
		printk("reset_ptx_tx: for_snd_trwd: 0x%08x\n", pbtx->for_snd_trwd);
		if (i == ptx->fe)
			return;
	}
}

int lvnet_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	printk("lvnet_ioctl: START from 0x%x cmd: %x\n", get_pc_call(), cmd);
	return 0;
}

static	struct net_device_stats *lvnet_stats(struct net_device *dev)
{
	struct rdma_private *rp = netdev_priv(dev);
	dbg_net("lvnet_stats: START from 0x%x\n", get_pc_call());
	return (&rp->net_stats);
}

int lvnet_config(struct net_device *dev, struct ifmap *map)
{
	printk("lvnet_config: START from 0x%x\n", get_pc_call());
	return 0;
}

static int lvnet_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr=p;
	int i;
	char *pchar = p;

	dbg_net("lvnet_mac_addr: START from 0x%x\n", get_pc_call());
	for (i = 0; i < ETH_ALEN; i++)
		dbg_net("%02x", *pchar++);
	dbg_net("\n");
	if (netif_running(dev))
		return -EBUSY;
	memcpy(dev->dev_addr, addr->sa_data,dev->addr_len);
	return 0;
}

static int lvnet_change_mtu(struct net_device *dev, int new_mtu)
{
	printk("lvnet_change_mtu: START from 0x%x dev->mtu: %u new_mtu: %d\n", get_pc_call(), dev->mtu, new_mtu);
/*
	if (new_mtu < 1000) {
		print_header = 0;
		return 0;
	}
	if (new_mtu > 1000) {
		print_header = 1;
		return 0;
	}
*/
	dev->mtu = new_mtu; 
	return 0;
}

u32 rec_msg[MAX_RDMA_NET_DEV][REC_MSG_SIZE];		
u32 fe_rec_msg[MAX_RDMA_NET_DEV];			

int init_ptx(struct rdma_tx_block *ptx, struct rdma_private *rp)
{
	struct net_device *dev = rp->dev;
	struct rdma_tx_desc *pbtx;
	int nr32 = TX_BUFF_SIZE_ALIGN32 >> 2;
	int order = get_order(TX_BUFF_SIZE_ALIGN32);
	unsigned int i, k;
#ifdef BOTTOM_HALF_RX_REFILL_SKB
	struct sk_buff *skb;
#endif
	u32 *pp;
	struct page *map, *mapend;

	memset(ptx, 0, sizeof (struct rdma_tx_block));
	rdma_dbg("init_lvnet: TX_BUFF_SIZE_ALIGN32 %x ,  TX_BUFF_SIZE_ALIGN32 >> 2 %x order %x\n",	TX_BUFF_SIZE_ALIGN32, TX_BUFF_SIZE_ALIGN32 >> 2, order); 

	raw_spin_lock_init(&ptx->lock);

	ptx->avail = TX_RING_SIZE;
	ptx->fe = ptx->fb = ptx->state_tx = ptx->state_rx = 0;
	ptx->rec_trwd_tx = ptx->rec_trwd_bc = ptx->rec_trwd_tr = ptx->last_snd_ready = 0;
	for (i = 0; i < TX_RING_SIZE; i++) {
		pbtx = &ptx->btx_ring[i];
#ifdef CONFIG_E90 /* E90 */
		pbtx->vaddr = (u8 *)__get_free_pages(GFP_KERNEL | GFP_DMA, order);
#else /* !E90 */
		if (HAS_MACHINE_E2K_FULL_SIC) { /*E3S & E90S*/
			pbtx->vaddr = (u8 *)__get_free_pages(GFP_KERNEL, order);
		} else {
			pbtx->vaddr = (u8 *)__get_free_pages(GFP_KERNEL |
								GFP_DMA, order);
		}
#endif /* E90 */
		if (!pbtx->vaddr) {
			printk("init_lvnet: memory alloc for "
				"ptx->tx_buf[%u]. TX_BUFF_SIZE_ALIGN32: %d\n",
				i, TX_BUFF_SIZE_ALIGN32);
			goto bad_alloc_buffer;
		}
		mapend = virt_to_page ((pbtx->vaddr) + (PAGE_SIZE << order) - 1);
		for (map = virt_to_page((pbtx->vaddr)); map <= mapend; map++)
			SetPageReserved(map);
		ptx->alloc_buf_rdma++;
#ifdef BOTTOM_HALF_RX_REFILL_SKB
		skb = dev_alloc_skb(SIZE_MTU_DEV + 2);
		if (unlikely(!skb)) {
			printk("init_lvnet: memory dev_alloc_skb for "
				"ptx->tx_buf[%x]. SIZE_MTU_DEV: %x\n",
				i, SIZE_MTU_DEV);
			goto bad_alloc_buffer;
		}
		ptx->alloc_buf_skb++;
		skb->dev = dev;
		pbtx->addr = skb;
		pbtx->skb_in_steck_for_free = 0;
#endif
#ifdef CONFIG_E90 /* E90 */
		pbtx->phaddr = va_to_fa_ld_lock((uint_t)pbtx->vaddr);
#else /* !E90 */
		if (HAS_MACHINE_E2K_FULL_SIC)
			pbtx->phaddr = __pa((unsigned long) pbtx->vaddr);
#ifdef CONFIG_E2K /* E3M */
		else {
//			pbtx->phaddr = pci_map_single((struct pci_dev *)rp->pdev, (void *) pbtx->vaddr, TX_BUFF_SIZE_ALIGN32, PCI_DMA_BIDIRECTIONAL);
			pbtx->phaddr = __pa((unsigned long) pbtx->vaddr);
		}
#endif
#endif /* E90 */
		for (pp = (u32 *)pbtx->vaddr, k = 0; k < nr32; k++, pp++) {
			*pp = 0x80000000 | (i << 20) | (k & 0xfffff);
 		}
		*(u32 *)pbtx->vaddr = WASTE_PACKET;
		pbtx->count_dsf = pbtx->worked = pbtx->busy = pbtx->for_rec_trwd = pbtx->for_snd_trwd = 0;
#ifdef BOTTOM_HALF_RX_REFILL_SKB
		rdma_dbg("init ptxb: addr: %p va: %p pha: 0x%llx ptx->alloc_buf_rdma: %x ptx->alloc_buf_skb: %x %x\n", pbtx->addr, pbtx->vaddr, (u64)pbtx->phaddr, ptx->alloc_buf_rdma, ptx->alloc_buf_skb, i);
#else
		rdma_dbg("ptxb: va: %p   0x%llx %x\n", pbtx->vaddr, pbtx->phaddr, i);
#endif
	}
	return 0;
bad_alloc_buffer:
	return 1;
}

void free_ptx(struct rdma_tx_block *ptx, struct rdma_private *rp)
{
	struct rdma_tx_desc	*pbtx;
	int order = get_order(TX_BUFF_SIZE_ALIGN32);
	unsigned int		i;
	struct page *map, *mapend;

	rdma_dbg("free_ptx: start node \n");
#ifdef BOTTOM_HALF_RX_REFILL_SKB
	struct sk_buff *skb;
	for (i = 0; i < ptx->alloc_buf_skb; i++) {
		pbtx = &ptx->btx_ring[i];
		skb = pbtx->addr;
		if ((skb) && (!pbtx->skb_in_steck_for_free))
			dev_kfree_skb_any(skb);
	}
#endif
	for (i = 0; i < ptx->alloc_buf_rdma; i++) {
		pbtx = &ptx->btx_ring[i];
		rdma_dbg("ptxb: va: %p   0x%llx %x\n", pbtx->vaddr, (u64)pbtx->phaddr, i);
		mapend = virt_to_page ((pbtx->vaddr) + (PAGE_SIZE << order) - 1);
		for (map = virt_to_page((pbtx->vaddr)); map <= mapend; map++)
			ClearPageReserved(map);

#ifdef CONFIG_E2K /* E3M */
/*
		if (!HAS_MACHINE_E2K_FULL_SIC) {
			pci_unmap_single((struct pci_dev *)rp->pdev,
				pbtx->phaddr, TX_BUFF_SIZE_ALIGN32,
				PCI_DMA_BIDIRECTIONAL);
		}
*/
#endif
		free_pages((unsigned long)pbtx->vaddr, order);
	}
	rdma_dbg("free_ptx: stop node \n");
}

static void rdma_free_hwresources(struct rdma_private *rp)
{
#ifdef CONFIG_E90 /* E90 */
	printk("RDMA controller(RDMA-NET mode): Free resources sn%x\n", rp->inst);
#else
	printk("RDMA controller(RDMA-NET mode): Free resources sn%x\n", NUM_NODE_RDMA(rp->inst) + (NUM_LINK_IN_NODE_RDMA(rp->inst)?(10 * NUM_NODE_RDMA(rp->inst) + NUM_LINK_IN_NODE_RDMA(rp->inst)):0));
#endif
	rdma_dbg("rdma_free_hwresource: stop node # %x \n", rp->inst);
#ifdef BOTTOM_HALF_RX_THREAD_RDMA
	if (rp->rdma_rx_tsk) 
		kthread_stop(rp->rdma_rx_tsk);
#endif
	clear_es(rp, 0);
#ifdef CONFIG_E90 /* E90 */
	if (rp->inst)
		if (rp->regbase)
			iounmap(rp->regbase);
	if ((op_rdmach0) && (rp->inst == 1 )) 
		kfree(op_rdmach0);
	if ((op_rdmach1) && (rp->inst == 2 )) 
		kfree(op_rdmach1);
#else /* !E90 */
	if (HAS_MACHINE_E2K_FULL_SIC) {
#ifdef CONFIG_E90S /* E90 */
		if (rp->inst)
			if (rp->regbase)
				iounmap(rp->regbase);
#endif
	}
#ifdef CONFIG_E2K /* E3M */
	else {
		if (rp->pdev)	
		rdma_remove_net(rp->pdev);
	}
#endif /* E3M */	
#endif /* E90 */
	rdma_dbg("rdma_free_hwresource: stop node # %x \n", rp->inst);
}


struct net_device *netdev_addr[MAX_RDMA_NET_DEV];

#if 0
static int lvnet_rebuild_header(struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *)skb->data;
	struct net_device *dev = skb->dev;

	dbg_net_header("lvnet_rebuild_header: start from 0x%x\n", get_pc_call());
	switch (eth->h_proto)
	{
#ifdef CONFIG_INET
	case __constant_htons(ETH_P_IP):
 		return arp_find(eth->h_dest, skb);
#endif	
	default:
		printk(KERN_DEBUG
		       "%s: unable to resolve type %X addresses.\n", 
		       dev->name, (int)eth->h_proto);
		
		memcpy(eth->h_source, dev->dev_addr, dev->addr_len);
		break;
	}

	return 0;
}
static int lvnet_header(struct sk_buff *skb, struct net_device *dev, unsigned short type,
	   const void *daddr, const void *saddr, unsigned len)
{
	struct ethhdr	*eth;
	int		i;
	rdma_addr_struct_t	time;

	time.addr = rdma_gethrtime();

	/*
	 *	Set the protocol type. For a packet of type ETH_P_802_3 we put the length
	 *	in here instead. It is up to the 802.2 layer to carry protocol information.
	 */
	
	dbg_net_header("lvnet_header: START dev.name: %s  from 0x%x time: 0x%08x%08x\n",
		dev->name, get_pc_call(), time.fields.haddr, time.fields.laddr);
	eth = (struct ethhdr *)skb_push(skb, ETH_HLEN);

	if(type != ETH_P_802_3) 
		eth->h_proto = htons(type);
	else
		eth->h_proto = htons(len);

	/*
	 *	Set the source hardware address. 
	 */
	 
	if (saddr) {
		memcpy(eth->h_source, saddr, dev->addr_len);
	} else {
		dbg_net_header("lvnet_header: saddr: NULL\n");
		memcpy(eth->h_source, dev->dev_addr, dev->addr_len);
	}
	dbg_net_header("lvnet_header: addr_len: %d h_source:", dev->addr_len);
	for (i = 0; i < dev->addr_len; i++)
		dbg_net_header("%02x.", eth->h_source[i]);
	dbg_net_header("\n");

	/*
	 *	Anyway, the loopback-device should never use this function... 
	 */

	if (dev->flags & (IFF_LOOPBACK|IFF_NOARP)) {
		dbg_net_header("lvnet_header: IFF_LOOPBACK|IFF_NOARP: h_dest: NULL\n");
		memset(eth->h_dest, 0, dev->addr_len);
		return(dev->hard_header_len);
	}
	
	if (daddr) {
		memcpy(eth->h_dest, daddr, dev->addr_len);
		dbg_net_header("lvnet_header: addr_len: %d h_dest  :", dev->addr_len);
		for (i = 0; i < dev->addr_len; i++)
			dbg_net_header("%02x.", eth->h_dest[i]);
		dbg_net_header("\n");
		return dev->hard_header_len;
	}
	dbg_net_header("lvnet_header: return -%d\n", dev->hard_header_len);
	
	return -dev->hard_header_len;
}

static int lvnet_header_parse(const struct sk_buff *skb, unsigned char *haddr)
{
//	struct ethhdr *eth = (struct ethhdr *)skb->mac.raw;
	struct ethhdr *eth = eth_hdr(skb);
	dbg_net_header("lvnet_header_parse: START from 0x%x\n", get_pc_call());
	memcpy(haddr, eth->h_source, ETH_ALEN);
	return ETH_ALEN;
}

static int lvnet_header_cache(const struct neighbour *neigh, struct hh_cache *hh)
{
	unsigned short type = hh->hh_type;
	struct ethhdr *eth;
	struct net_device *dev = neigh->dev;

	dbg_net_header("lvnet_header_cache: START from 0x%x\n", get_pc_call());
	eth = (struct ethhdr*)
		(((u8*)hh->hh_data) + (HH_DATA_OFF(sizeof(*eth))));

	if (type == __constant_htons(ETH_P_802_3))
		return -1;

	eth->h_proto = type;
	memcpy(eth->h_source, dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest, neigh->ha, dev->addr_len);
	hh->hh_len = ETH_HLEN;
	return 0;
}

/*
 * Called by Address Resolution module to notify changes in address.
 */

static void lvnet_header_cache_update(struct hh_cache *hh, const struct net_device *dev, const unsigned char * haddr)
{
	dbg_net_header("lvnet_header_cache_update: START from 0x%x\n", get_pc_call());
	memcpy(((u8*)hh->hh_data) + HH_DATA_OFF(sizeof(struct ethhdr)),
	       haddr, dev->addr_len);
}

static const struct header_ops lvnet_hard_header_ops = {
	.create  	= lvnet_header,	
	.rebuild	= lvnet_rebuild_header,
	.parse		= lvnet_header_parse,
	.cache		= lvnet_header_cache,
	.cache_update	= lvnet_header_cache_update,
};
#endif

static const struct net_device_ops lvnet_netdev_ops = {
	.ndo_open		= lvnet_open,
	.ndo_stop		= lvnet_stop,
	.ndo_start_xmit		= lvnet_tx,
	.ndo_get_stats		= lvnet_stats,
	.ndo_set_mac_address	= lvnet_mac_addr,
	.ndo_tx_timeout 	= lvnet_tx_timeout,
	.ndo_change_mtu		= lvnet_change_mtu,
//	.ndo_do_ioctl		= lvnet_ioctl,
	.ndo_set_config		= lvnet_config,
};

static int __init dev_rdma_init(int node, struct pci_dev *pdev)
{
	struct net_device	*dev;
	struct rdma_private	*rp;
	struct stat_rdma	*pst;
	struct rdma_tx_block	*ptx;
	spin_snd_msg_rdma_p	*ssmr;
	u32			evs;
	char			namedev[16];
	int 			ret = 0;
#ifdef CONFIG_E90 /* E90 */
	int irq_sbus;
	unsigned int sdev_irqs;
	unsigned long irq_flags;
#endif /* E90 */

	rdma_dbg("dev_rdma_init start: node # %d\n", node);
	dev = alloc_netdev(sizeof(struct rdma_private) + 8, "sn0%d", ether_setup);
	if (!dev) {
		printk(KERN_ERR "RDMA controller(RDMA-NET mode): ENOMEM for dev sn on node : %d \n", node);
		return -ENOMEM;
	}

#ifndef CONFIG_E90 /* !E90 */
	/*Address dev for interrupt*/
	netdev_addr[node] = dev;
	rdma_dbg("dev_rdma_init: netdev_addr[%d]: %p dev: %p \n", node, netdev_addr[node], dev );
#endif /* !E90 */
	rp = netdev_priv(dev);

#ifdef CONFIG_E90 /* E90 */
	struct device_node *dp = NULL;
	switch (node) {
	case 1:
	if (rdma_check_hardware(board_name0, dp)) {
		rdma_dbg("find MCST,rdmach0.\n");
		op_rdmach0 = kzalloc(sizeof(*op_rdmach0), GFP_KERNEL);
		op_rdmach0->node = dp;
		op_rdmach0->resource[0].name = "MCST,rdmaon";
		op_rdmach0->resource[0].flags = 0x10e;
		op_rdmach0->resource[0].start = BASE_NODE0 + node * NODE_OFF;
		op_rdmach0->resource[0].end = BASE_NODE0 + node * NODE_OFF + NODE_SIZE -1 ;
		rp->regbase = of_ioremap(&op_rdmach0->resource[0], 0,
					op_rdmach0->resource[0].end - op_rdmach0->resource[0].start + 1,
					"MCST,rdmaon");
		rdma_dbg("rdma_probe: ioremap adr_e_rega[%d]: %p \n", node, rp->regbase);
		if (!rp->regbase) {
			printk(KERN_ERR "RDMA controller(RDMA-NET mode): Cannot map registers for node %d\n",  node);
			goto fail;
		}
		e_rega[1] = rp->regbase;
		printk("RDMA controller(RDMA-NET mode): ioremap address MCST,op_rdmach0 rega[0]: 0x%p op_rdmach0->resource[0].start: 0x%x op_rdmach0->resource[0].end: 0x%08x\n", e_rega[1], op_rdmach0->resource[0].start, op_rdmach0->resource[0].end);
		sdev_irqs = 0x32;
		irq_sbus = 1;
		WRR(e_rega[0], SHIFT_CS,
		    (RDR(e_rega[0], SHIFT_CS, (dev_rdma_sem_t *) NULL) &
		     ~CS_C0ILN) | (irq_sbus << 13),
		    (dev_rdma_sem_t *) NULL);
		rdma_dbg("rdma_probe: SHIFT_CS [0]: 0x%08x \n", RDR(e_rega[0], SHIFT_CS, (dev_rdma_sem_t *) NULL));
		} else
			goto fail;
		break;
	case 2:
	if (rdma_check_hardware(board_name1, dp)) {
		rdma_dbg("find MCST,rdmach1.\n");
		op_rdmach1 = kzalloc(sizeof(*op_rdmach1), GFP_KERNEL);
		op_rdmach1->node = dp;
		op_rdmach1->resource[0].name = "MCST,rdmaon";
		op_rdmach1->resource[0].flags = 0x10e;
		op_rdmach1->resource[0].start = BASE_NODE0 + node * NODE_OFF;
		op_rdmach1->resource[0].end = BASE_NODE0 + node * NODE_OFF + NODE_SIZE - 1;
		rp->regbase = of_ioremap(&op_rdmach1->resource[0], 0,
					op_rdmach1->resource[0].end - op_rdmach1->resource[0].start + 1,
					"MCST,rdmaon");
		rdma_dbg("rdma_probe: ioremap adr_e_rega[%d]: %p \n", node, rp->regbase);
		if (!rp->regbase) {
			printk(KERN_ERR "RDMA controller(RDMA-NET mode): Cannot map registers for node %d\n",  node);
			goto fail;
		}
		e_rega[2] = rp->regbase;
		printk("RDMA controller(RDMA-NET mode): ioremap address MCST,op_rdmach1 rega[0]: 0x%p op_rdmach1->resource[0].start: 0x%x op_rdmach1->resource[0].end: 0x%x\n", e_rega[2], op_rdmach1->resource[0].start, op_rdmach1->resource[0].end);

		sdev_irqs = 0x3b;
		irq_sbus = 6;
		WRR(e_rega[0], SHIFT_CS,
		    (RDR(e_rega[0], SHIFT_CS, (dev_rdma_sem_t *) NULL) &
		     ~CS_C1ILN) | (irq_sbus << 10),
		    (dev_rdma_sem_t *) NULL);
		rdma_dbg("rdma_probe: SHIFT_CS [0]: %x \n", RDR(e_rega[0], SHIFT_CS, (dev_rdma_sem_t *) NULL));
		} else
			goto fail;
		break;
	default:
		printk("RDMA controller(RDMA-NET mode): ERR: rdma_cards: %d\n", node);
		return -ENODEV;
	}
	rp->inst = node;
	rp->size = NODE_SIZE;
	rdma_dbg("dev_rdma_init: dev_rdma_init() map registers "
		"of card #%d, virt base 0x%p\n", node, rp->regbase);

#else /* !E90 */
#ifdef CONFIG_E90S /* E90S */
	unsigned long long 	phys_base;
//	phys_base = BASE_NODE0+node*NODE_OFF;
	phys_base = BASE_NODE0 + (node / NODE_NUMIOLINKS) * NODE_OFF + 0x1000 * (node % NODE_NUMIOLINKS); /*Error*/
	rdma_dbg("dev_rdma_init: dev_rdma_init() NBSR registers "
		"of node #%d, phys base 0x%llu\n", node, phys_base);
	rp->regbase = ioremap(phys_base, NODE_OFF);
	rp->size = NODE_OFF;
	e_rega[node] = rp->regbase;
#endif /* E90S */
#ifdef CONFIG_E2K  /* E3S & E3M */
#define	SIC_io_reg_offset(io_link, reg)	((reg) + 0x1000 * (io_link))
	if (HAS_MACHINE_E2K_FULL_SIC) { /* E3S */
		rp->regbase = nodes_nbsr_base[node / NODE_NUMIOLINKS] + 0x1000 * (node % NODE_NUMIOLINKS);
		rp->size = NODE_NBSR_SIZE;
		e_rega[node] = rp->regbase;
	} else {
		rp->regbase = (void __iomem *) rdma_state->mmio_vbase;
		e_rega[node] = rp->regbase;
//		e3m_reg_base = rp->regbase;	
		rp->pdev = pdev;
	}
	
#endif /* E3S & E3M */
	rdma_dbg("dev_rdma_init: dev_rdma_init() mmap registers "
		"of node #%d, virt base 0x%p\n", node, rp->regbase);
	rp->inst = node;
#endif /* E90 */
	ssmr = &spin_snd_msg_rdma[rp->inst];
	raw_spin_lock_init(&ssmr->lock);
	evs = RDR(rp->regbase, SHIFT_ES, (dev_rdma_sem_t *)NULL); 
	rdma_dbg("dev_rdma_init: dev_rdma_init(%d): evs: 0x%08x\n", node, evs);

	/* MBC/C. RDMA links are connected by constantly */
#ifdef CONFIG_E90 /* E90 */
	if ( find_link_rdma(rp) )
		printk("RDMA controller(RDMA-NET mode): There is a link to rdma sn%d\n", node);
	else {
		printk("RDMA controller(RDMA-NET mode): There not link to rdma sn%d\n", node);
		goto fail_link;
	}
#endif /* E90 */
	if (evs & ES_RIRM_Ev)
		rp->irmsg = 1;
	raw_spin_lock_init(&rp->lock);
	dev->dev_addr[0] = 'L';
#ifdef CONFIG_E90 /* E90 */
/*	#ifndef CONFIG_E90_FASTBOOT
	dev->dev_addr[1] = (unsigned char) node - 1;	
	dev->dev_addr[2] = idprom->id_ethaddr[2];
	dev->dev_addr[3] = idprom->id_ethaddr[3];
	dev->dev_addr[4] = idprom->id_ethaddr[4];
	dev->dev_addr[5] = idprom->id_ethaddr[5]; 	
	#else
*/
		dev->dev_addr[1] = (unsigned char) node - 1;
		dev->dev_addr[2] = l_base_mac_addr[2];
		dev->dev_addr[3] = l_base_mac_addr[3];
		dev->dev_addr[4] = l_base_mac_addr[4];
		dev->dev_addr[5] = l_base_mac_addr[5]; 
//	#endif

#endif /* E90 */

#ifdef CONFIG_E2K /* E2K */
	if (rdma_mac_setup) {
		dev->dev_addr[1] = id_ethaddr[1];
		dev->dev_addr[2] = boot_cl;	//id_ethaddr[2];
		dev->dev_addr[3] = id_ethaddr[3];
		dev->dev_addr[4] = id_ethaddr[4];
		dev->dev_addr[5] = (unsigned char)node;
	} else {
		dev->dev_addr[1] = l_base_mac_addr[1];
		dev->dev_addr[2] = l_base_mac_addr[2];	//boot_cl;
		dev->dev_addr[3] = l_base_mac_addr[3];
		dev->dev_addr[4] = l_base_mac_addr[4];
		dev->dev_addr[5] = (unsigned char) node; 
	}
#endif /* E2K */
#ifdef CONFIG_E90S /* E90S */
	if (rdma_mac_setup) {
		dev->dev_addr[1] = id_ethaddr[1];
		dev->dev_addr[2] = id_ethaddr[2];
		dev->dev_addr[3] = id_ethaddr[3];
		dev->dev_addr[4] = id_ethaddr[4];
		dev->dev_addr[5] = (unsigned char)node;
	} else {
		dev->dev_addr[1] = l_base_mac_addr[1];;
		dev->dev_addr[2] = l_base_mac_addr[2];
		dev->dev_addr[3] = l_base_mac_addr[3];
		dev->dev_addr[4] = l_base_mac_addr[4];
		dev->dev_addr[5] = (unsigned char) node; 
	}
#endif /* E90S */

	dev->dev_addr[6] = '\0';
	dev->netdev_ops 	= &lvnet_netdev_ops;
	dev->watchdog_timeo	= 10 * HZ;
	dev->mtu		= SIZE_MTU_DEV; /* rdma_mtu = SIZE_BUF_NET - 0x100 */
	dev->dma 		= 0;

#ifdef CONFIG_E90 /* E90 */
	dev->irq = sdev_irqs;
#endif /* E90 */
	rp->dev = dev;
	ptx = &rp->rt_block;
	if (init_ptx(ptx, rp)) {
		printk("RDMA controller(RDMA-NET mode): Error alloc rx buffers.\n");
//		stop_rdma[rp->inst] = 1;
		goto fail_rx;
	}
	ptx = &rp->tx_block;
	if (init_ptx(ptx, rp)) {
		printk("RDMA controller(RDMA-NET mode): Error alloc tx buffers.\n");
//		stop_rdma[rp->inst] = 1;
		goto fail_tx;
	}
#ifndef CONFIG_E90 /* !E90 */
//	sprintf(namedev, "sn%d", node);
//For two links - (sn1,sn11,sn12,...), (sn2,sn21,sn22,...), ...
	sprintf(namedev, "sn%d", NUM_NODE_RDMA(node) + (NUM_LINK_IN_NODE_RDMA(node)?(10 * NUM_NODE_RDMA(node) + NUM_LINK_IN_NODE_RDMA(node)):0));
	strcpy(dev->name, namedev);
#else /* E90 */
	sprintf(namedev, "sn%d", node - 1);
	strcpy(dev->name, namedev);
#endif

#ifdef BOTTOM_HALF_RX_THREAD_RDMA
        rp->rdma_rx_tsk = kthread_create(rx_thread_action, rp, "%s-refill-thread", dev->name);
	if (!rp->rdma_rx_tsk) {
		printk(KERN_ERR "irqd: could not create %s-refill-thread\n", dev->name);
		return -ENOMEM;
	}
	raw_spin_lock_init(&rp->thread_lock);	//150812	
#endif

#ifdef CONFIG_E90 /* !E90 */
	irq_flags = IRQF_SHARED;
#if defined(CONFIG_MCST_RT)
//	irq_flags |=  IRQF_DISABLED;
#endif
	if (request_threaded_irq
	    (dev->irq, &rdma_intr, NULL, irq_flags, dev->name, (void *) dev)) {
		printk(KERN_ERR "RDMA controller(RDMA-NET mode): Can't get irq %d\n", dev->irq);
		goto fail;
	}
	printk("RDMA controller(RDMA-NET mode):irq %d for %s ok.\n", dev->irq, namedev);
#endif /* E90 */
	ret = register_netdev(dev);
	if ( ret ) {
		printk(KERN_ERR "RDMA controller(RDMA-NET mode): Cannot register device: %d\n", ret);
		goto fail;
	}
#ifdef CONFIG_E90S
	rdma_dbg(KERN_ERR "%02x:%02x:%02x:%02x:%02x:%02x Ethernet\n",
		    id_ethaddr[0], id_ethaddr[1],
		    id_ethaddr[2], id_ethaddr[3],
		    id_ethaddr[4], id_ethaddr[5]);
#else
	if (!rdma_mac_setup) {
		rdma_dbg(KERN_ERR "%pM Ethernet\n", l_base_mac_addr);
	} else {
		rdma_dbg(KERN_ERR "%02x:%02x:%02x:%02x:%02x:%02x Ethernet\n",
			    id_ethaddr[0], id_ethaddr[1],
			    id_ethaddr[2], id_ethaddr[3],
			    id_ethaddr[4], id_ethaddr[5]);
	}
#endif
	printk(KERN_ERR "%02x:%02x:%02x:%02x:%02x:%02x %s\n",
		    dev->dev_addr[0], dev->dev_addr[1],
		    dev->dev_addr[2], dev->dev_addr[3],
		    dev->dev_addr[4], dev->dev_addr[5], dev->name);

	rp->next_module = root_rdma_dev;
	root_rdma_dev = rp;

	/* move from lvnet_open */
	rp->opened = 0;
//	rp->snd_ir_msg = 0;
	ptx = &rp->rt_block;
	reset_ptx(ptx);
	ptx = &rp->tx_block;
	reset_ptx(ptx);
	ptx->work_next_rdma = 1;
	ptx->work_broadcast_rdma = 1;
	ptx->work_transit_rdma = 1;
	pst = &rp->stat_rdma;
	pst->tx_avail = TX_RING_SIZE;
	pst->rx_avail = TX_RING_SIZE;
	pst->bc_avail = TX_RING_SIZE;
	pst->tr_avail = TX_RING_SIZE;
	who.who_rec_ready[rp->inst].chann = NICH_RX;
	who.who_rec_ready[rp->inst].msg = 0;
	who.who_snd_ready[rp->inst].chann = CAST_RX;
	who.who_snd_ready[rp->inst].msg = 0;
	state_tx[rp->inst] = 0;
	state_rx[rp->inst] = 0;
#ifdef CONFIG_E90
	clear_es(rp, 0);
#else
	clear_es(rp, 1);
#endif
/* For correct reboot */
#if RDMA_REBOOT
	WRR(rp->regbase, SHIFT_MSG_CS, MSG_CS_SIR_Msg, (dev_rdma_sem_t *)NULL);
//	rp->snd_ir_msg = 1;
#endif

#if (RDMA_DBG)
	prn_reg_rdma(rp->regbase);
#endif
	return 0;
fail:
#ifdef BOTTOM_HALF_RX_THREAD_RDMA
//	kthread_stop(rp->rdma_rx_tsk);
#endif

fail_tx:
	ptx = &rp->tx_block;
	free_ptx(ptx, rp);
fail_rx:
	ptx = &rp->rt_block;
	free_ptx(ptx, rp); 

#ifdef CONFIG_E90 /* E90 */
fail_link:
#endif
	rdma_free_hwresources(rp);
	free_netdev(dev);
//	printk(KERN_ERR "RDMA controller(RDMA-NET mode): sn: ENODEV\n");
	return -ENODEV;
}

int rdma_cards = 0;

static int __init rdma_probe(void)
{
	struct	rdma_event	*re;
	int			ret, node;
#ifdef CONFIG_E2K 
	 struct pci_dev 	*dev = NULL;
#endif
	static int 		called;


	rdma_dbg("rdma_probe: start\n");

#ifdef CONFIG_RDMA_NET 
	if (!net_device_present) {
#ifndef CONFIG_E90 /* E90 */
		printk("RDMA controller: RDMA-NET mode not supported, load module rdma.ko(E3M) or rdma_sic.ko(SIC machine) \n");
#endif
		return -1; 
	} else 
		printk("RDMA controller: RDMA-NET mode  \n");
#endif
	if (called) {
		printk("RDMA controller: RDMA registers busy. \n");
		return -ENODEV;
	}	
	called++;

	init_regs();
#if defined(CONFIG_E90S) || defined(CONFIG_E2K)
	rdma_dbg("rdma_probe: rdma_present: %d\n", rdma_present);
	if (!rdma_present) {
		rdma_present = 1;
	} else {
		printk("RDMA controller: RDMA registers busy. \n");
		return -ENODEV;	
	}
#endif

/*Find RDMA on sbus  for E90*/
#ifdef CONFIG_E90 /* E90 */
	struct device_node *dp = NULL;
	if (rdma_check_hardware(board_name, dp)) {
		rdma_dbg("find MCST,rdmaon.\n");
		printk("RDMA-NET: I am worked on E90\n");
		op_rdmaon = kzalloc(sizeof(*op_rdmaon), GFP_KERNEL);
		if (!op_rdmaon) { 
			printk("rdma_probe: error kzalloc op_rdmaon for MCST,rdmaon\n");
			called = 0;
			return -ENODEV;
		}
		op_rdmaon->node = dp;
		op_rdmaon->resource[0].name = "MCST,rdmaon";
		op_rdmaon->resource[0].flags = 0x10e;
		op_rdmaon->resource[0].start = BASE_NODE0;
		op_rdmaon->resource[0].end = BASE_NODE0 + NODE0_SIZE - 1;
		e_rega[0] = of_ioremap(&op_rdmaon->resource[0], 0,
					op_rdmaon->resource[0].end - op_rdmaon->resource[0].start + 1,
					"MCST,rdmaon");
		if (!e_rega[0]) { 
			printk("RDMA controller(RDMA-NET mode): error ioremap for MCST,rdmaon\n");
			kfree(op_rdmaon);
			called = 0;
			return -ENODEV;
		}
		printk("RDMA controller(RDMA-NET mode): ioremap address MCST,rdmaon rega[0]: 0x%p op_rdmaon->resource[0].start: 0x%x op_rdmaon->resource[0].end: 0x%x\n", e_rega[0], op_rdmaon->resource[0].start, op_rdmaon->resource[0].end);
	} else {	/* if R500, not RDMA */
		printk("RDMA controller(RDMA-NET mode): RDMA-NET not support (CPU R500, not RDMA)\n");
		called = 0;
		return -ENODEV;
	}

	/* Packet Time Out Counter Load */
	rdma_dbg("rdma_probe: SHIFT_CS [0]: %u \n", RDR(e_rega[0], SHIFT_CS, (dev_rdma_sem_t *) NULL));
	WRR(e_rega[0], SHIFT_CS, CS_PTOCL, (dev_rdma_sem_t *) NULL);
	rdma_dbg("rdma_probe: SHIFT_CS [0]: %u \n", RDR(e_rega[0], SHIFT_CS, (dev_rdma_sem_t *) NULL));
	for_each_online_rdma(node) {
		rdma_dbg("rdma_probe: node # %d\n", node);
		ret = dev_rdma_init(node , NULL);
		if (!ret) {
		rdma_cards++;
		}
	}
#else /* !E90 */
	/*Find RDMA node for E90S & E3S */
	if (HAS_MACHINE_E2K_FULL_SIC) { /*E3S & E90S*/
#ifdef CONFIG_E2K /* E3S */
		printk("RDMA controller(RDMA-NET mode): I am worked on SIC(E3S\E2S) MAX_RDMA_NET_DEV: %d NODE_NUMIOLINKS: %x\n", MAX_RDMA_NET_DEV, NODE_NUMIOLINKS);
#else /* E90S */
		printk("RDMA controller(RDMA-NET mode): I am worked on SIC(E90S) MAX_RDMA_NET_DEV: %d NODE_NUMIOLINKS: %x\n", MAX_RDMA_NET_DEV, NODE_NUMIOLINKS);
		init_node_e90s();
#endif
		for_each_online_rdma(node) {
//			rdma_dbg("rdma_probe: node # %d\n", NUM_NODE_RDMA(node));
//			ret = dev_rdma_init(NUM_NODE_RDMA(node), NULL);
			rdma_dbg("rdma_probe: node # %d\n", node);
			ret = dev_rdma_init(node, NULL);
				if (!ret) {
					rdma_cards++;
				}
		}
	}
#ifdef CONFIG_E2K /* E3M */
	/*Find RDMA node for E3M */
	else { /* E3M */
		printk("RDMA controller(RDMA-NET mode): I am worked on E3M\n");
		    do {
			//dev = pci_find_device(0x8086, 0x7191, dev);  /* 0x71918086 */
			dev = pci_get_device(0x8086, 0x7191, dev);
			
			if (dev) {
				if (rdma_pci_probe(dev, NULL) == 0) {
					ret = dev_rdma_init(rdma_cards, dev);
		    			if (!ret) {
						rdma_cards++;
					}	
				}
	    		}
		} while(dev != NULL);
	}
#endif /* E3M */
	/* Registration handler*/
	if (rdma_cards)	
		rdma_interrupt_p = rdma_interrupt;
#endif /* E90 */
	if (!rdma_cards) {
		printk("RDMA controller(RDMA-NET mode): finish FAIL (not sn interfaces).\n");
#if defined(CONFIG_E90S) || defined(CONFIG_E2K)
		rdma_present = 0;
#endif
#if defined(CONFIG_E90)
		printk("RDMA controller(RDMA-NET mode): Free resources op_rdmaon. \n");
		if (e_rega[0]) {
			iounmap(e_rega[0]);
			kfree(op_rdmaon);
		}
		called = 0;
#endif

		return -ENODEV;
	}
	/*For delete get_free_pages from interrupt */
	if (!init_mem_for_event()) { 
		printk("RDMA controller(RDMA-NET mode): Memory for print events RDMA initialized.\n");
		mem_print_event = 1;
	}
	else {
		printk("RDMA controller(RDMA-NET mode): Memory for print events RDMA not initialized.\n");
		mem_print_event = 0;
	}
	memset(rdma_event.event, 0, (SIZE_EVENT << 2));
	re = &rdma_event;
	re->event_cur = 0;
	rdma_event_init = 1;
	raw_spin_lock_init(&re->mu_fix_event);
#if RDMA_PROC_FS
	proc_rdma_event_init();
#endif
	rdma_dbg("rdma_probe: finish OK (rdma_cards: %d)\n", rdma_cards);
	return 0;
}

static void __exit rdma_cleanup(void)
{
	struct rdma_private 	*rp;
	struct rdma_tx_block	*ptx;

	rdma_dbg("rdma_cleanup: start\n");
	while (root_rdma_dev) {
		rp = root_rdma_dev->next_module;
		stop_rdma[root_rdma_dev->inst] = 0;
#ifdef CONFIG_E90 /* E90 */
		free_irq(root_rdma_dev->dev->irq, root_rdma_dev->dev);
#endif
		if (root_rdma_dev->opened)  
			netif_stop_queue(root_rdma_dev->dev);
		WRR(root_rdma_dev->regbase, SHIFT_IRQ_MC, 0x00000000, (dev_rdma_sem_t *) NULL);
		unregister_netdev(root_rdma_dev->dev);
		free_netdev(root_rdma_dev->dev);
		ptx = &root_rdma_dev->rt_block;
		free_ptx(ptx, rp); 
		ptx = &root_rdma_dev->tx_block;
		free_ptx(ptx, rp); 
		rdma_free_hwresources(root_rdma_dev);
		root_rdma_dev = rp;
	}
#ifndef CONFIG_E90 /* E90 */
	rdma_interrupt_p = (void *) NULL;
#endif
#ifdef CONFIG_E90 /* E90 */
	if (op_rdmaon) {
		iounmap(e_rega[0]);
		kfree(op_rdmaon);
	}
#endif
	clear_mem_for_event();

#if RDMA_PROC_FS
	proc_rdma_event_close();	
#endif
#if defined(CONFIG_E90S) || defined(CONFIG_E2K)
	rdma_present = 0;
	rdma_dbg("rdma_cleanup: rdma_present: %d\n", rdma_present);
#endif
	rdma_dbg("rdma_cleanup: finish\n");
}

module_init(rdma_probe);
module_exit(rdma_cleanup);
MODULE_LICENSE("GPL");
