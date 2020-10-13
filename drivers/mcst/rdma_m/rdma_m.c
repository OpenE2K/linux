/*
 * BUGS:
 * - E3M : can not be used in table mode.
 * - E3S, CUBIC, E90S: rfsm mode can not be used in a table mode.
 */

#include <linux/kernel.h>
#include <asm/setup.h>
#include "rdma.h"
#include "rdma_regs.h"
#include "rdma_error.h"

#if 0
#define LMS
#endif

#ifndef VM_RESERVED
#define VM_RESERVED (VM_DONTEXPAND | VM_DONTDUMP)
#endif

#ifdef CONFIG_E2K
#define LOOP_MODE 1
#endif

#define DSF_NO 1
#define TX_RX_WAIT_DMA 1000000

#ifdef CONFIG_RDMA_BOOT_MEM_ALLOC
int busy_rdma_boot_mem = 0;
extern unsigned int R_M;
extern volatile void *rdma_link_mem[MAX_NUMNODES];
#endif

MODULE_AUTHOR("Copyright by MCST 2005-2013");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RDMA driver");

/*
 * Parametr's driver
 */
#ifndef LMS
#ifdef CONFIG_RDMA_BOOT_MEM_ALLOC
#define MAX_SIZE_BUFF 0x10000000
#else
#define MAX_SIZE_BUFF 0x400000
#define LIMIT_SIZE_BUFF 0x2000000
#endif
#define MAX_SIZE_BUFF_TM 0x4000000
#else
#ifdef CONFIG_RDMA_BOOT_MEM_ALLOC
#define MAX_SIZE_BUFF 0x10000
#else
#define MAX_SIZE_BUFF 0x8000
#define LIMIT_SIZE_BUFF 0x200000
#endif
#define MAX_SIZE_BUFF_TM 0x80000
#endif

extern iolinkmask_t	iolink_online_rdma_map;
extern iolinkmask_t	iolink_rdma_map;

/*
 * Struct for class rdma in sysfs
 */
static struct class *rdma_class;

/*
 * Set ATL
 */
unsigned int tr_atl;
static int  atl_v = TR_ATL_B;
module_param(atl_v, int, 0);
MODULE_PARM_DESC(atl_v, "Changes the value of ATL (alive timer limit) reg CAM.");

/*
 * Mode:
 *  0 - single mode
 *  1 - table mode
 */
static int tm_mode = 0x1;
module_param(tm_mode, int, 0);

/*
 * Max size buf for single mode
 */
static int max_size_buf = MAX_SIZE_BUFF;
module_param(max_size_buf, int, 0);

/*
 * Max size buf for table mode
 */
static int max_size_buf_tm = MAX_SIZE_BUFF_TM;
module_param(max_size_buf_tm, int, 0);

/*
 * The number of buffers
 */
#ifdef LMS
static int num_buf = 2;
#else
static int num_buf = RDMA_BUF_NUM;
#endif
module_param(num_buf, int, 0);

/*
 * Allocate memory on its node
 */
#ifdef LMS
static int node_mem_alloc = 0x0;
#else
static int node_mem_alloc = 0x1;
#endif
module_param(node_mem_alloc, int, 0);

/*
 * Develop for multy channel
 */
static int count_rdma_vc = RDMA_NODE_DEV;
#if 0
module_param(count_rdma_vc, int, 0);
#endif

/*
 * Print events
 */
static int ev_pr = 0;
module_param(ev_pr, int, 0);

/*
 * Enable RFSM - rfsm.
 *  rfsm  = ENABLE_RFSM  - RFSM disable (default).
 *  rfsm  = DMA_RCS_RFSM - RFSM enable.
 */
#define CLEAR_RFSM	DISABLE_RFSM
unsigned int rfsm = CLEAR_RFSM;

/*
 * E2S if not online link
 */
int only_loopback = 0;

link_id_t rdma_link_id;
extern int rdma_present;

struct pci_dev *rdma_dev;
link_id_t rdma_link_id;
unsigned long time_ID_REQ;
unsigned long time_ID_ANS;
unsigned long flags_s;
unsigned char *e0regad;
unsigned char *e1regad;
unsigned int count_read_sm_max = 800;
unsigned int intr_rdc_count[RDMA_MAX_NUMIOLINKS];
unsigned int msg_cs_dmrcl;
unsigned int state_cam = 0;
unsigned int state_GP0;
int buf_size;

unsigned int SHIFT_IO_VID;
unsigned int SHIFT_VID;		/* RDMA VID 			*/
unsigned int SHIFT_IOL_CSR;
unsigned int SHIFT_IO_CSR;
unsigned int SHIFT_CH0_IDT;	/* RDMA ID/Type E90/E3M1	*/
unsigned int SHIFT_CH1_IDT;	/* RDMA ID/Type E90/E3M1	*/
unsigned int SHIFT_CH_IDT;	/* RDMA ID/Type E3S/E90S	*/
unsigned int SHIFT_CS;		/* RDMA Control/Status 000028a0	*/
unsigned int SHIFT_DD_ID;	/* Data Destination ID 		*/
unsigned int SHIFT_DMD_ID;	/* Data Message Destination ID 	*/
unsigned int SHIFT_N_IDT;	/* Neighbour ID/Type 		*/
unsigned int SHIFT_ES;		/* Event Status 		*/
unsigned int SHIFT_IRQ_MC;	/* Interrupt Mask Control 	*/
unsigned int SHIFT_DMA_TCS;	/* DMA Tx Control/Status 	*/
unsigned int SHIFT_DMA_TSA;	/* DMA Tx Start Address 	*/
unsigned int SHIFT_DMA_HTSA;	/* DMA Tx Start Address 	*/
unsigned int SHIFT_DMA_TBC;	/* DMA Tx Byte Counter 		*/
unsigned int SHIFT_DMA_RCS;	/* DMA Rx Control/Status 	*/
unsigned int SHIFT_DMA_RSA;	/* DMA Rx Start Address 	*/
unsigned int SHIFT_DMA_HRSA;	/* DMA Rx Start Address 	*/
unsigned int SHIFT_DMA_RBC;	/* DMA Rx Byte Counter 		*/
unsigned int SHIFT_MSG_CS;	/* Messages Control/Status 	*/
unsigned int SHIFT_TDMSG;	/* Tx Data_Messages Buffer 	*/
unsigned int SHIFT_RDMSG;	/* Rx Data_Messages Buffer 	*/
unsigned int SHIFT_CAM;		/* CAM - channel alive management */

#ifdef CONFIG_COMPAT
static int do_ioctl(struct file *f, unsigned cmd, unsigned long arg);
static long rdma_compat_ioctl(struct file *f, unsigned cmd, unsigned long arg);
#endif
static long rdma_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
static ssize_t rdma_read(struct file *, char *, size_t, loff_t *);
static ssize_t rdma_write(struct file *, const char *, size_t, loff_t *);
static int rdma_open(struct inode *inode, struct file *file);
static int rdma_close(struct inode *inode, struct file *file);
static int rdma_mmap(struct file *file, struct vm_area_struct *vma);
void test_send_msg_rdma(unsigned int i, unsigned int msg);
int get_file_minor(struct file *file);
void init_reg(void);
void rdma_mem_free(size_t size, dma_addr_t dev_memory,
		   unsigned long dma_memory);
void init_rdma_link(int link);
void read_regs_rdma(int);
int rdma_mem_alloc(int node, size_t size, dma_addr_t *mem,
		   size_t *real_size, unsigned long *dma_memory);
int write_buf(int link, rdma_ioc_parm_t *parm, unsigned int f_flags);
int read_buf(int link, rdma_ioc_parm_t *parm, unsigned int f_flags);
int rdma_remap_page(void *va, size_t sz, struct vm_area_struct *vma);
//int rdma_remap_page(unsigned long pha, size_t sz, struct vm_area_struct *vma);
int rdma_remap_page_tbl(void *va, size_t sz, struct vm_area_struct *vma);
long wait_time_rdma(struct rdma_reg_state *rdma_reg_state,
		    signed long timeout);
int rdma_check_buf(unsigned long addr_buf, unsigned int cnst,
		   unsigned int need_free_page, char *prefix);
unsigned long join_curr_clock( void );
unsigned int RDR_rdma(unsigned int reg, unsigned int node);
void WRR_rdma(unsigned int reg, unsigned int node, unsigned int val);
int create_dev_rdma(int major);
int remove_dev_rdma(int major);
int init_buff(int link, int rw);
int rdma_mem_alloc_pool(rdma_pool_buf_t *);
void rdma_mem_free_pool(rdma_pool_buf_t *);
static void rdma_cleanup(void);
int send_msg_check(unsigned int msg, unsigned int link, unsigned int cmd,
		   dev_rdma_sem_t *dev, int print_enable);

#if RESET_THREAD_DMA
int rst_thr_action(void *arg);
#endif

DEFINE_RAW_SPINLOCK(mu_fix_event);

static struct file_operations rdma_fops = {
	.owner		= THIS_MODULE,
	.read		= rdma_read,
	.write		= rdma_write,
	.unlocked_ioctl = rdma_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= rdma_compat_ioctl,
#endif
	.mmap		= rdma_mmap,
	.open		= rdma_open,
	.release 	= rdma_close,
};

/*
 * Init E3M
 */
#ifdef CONFIG_E2K
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

/*
static struct pci_device_id rdma_devices[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_RDMA, PCI_DEVICE_ID_MCST_RDMA) },
		     { 0, }
};
*/

#define RDMA_PCI_PROBE_DBG 0
#define RDMA_PCI_PROBE_DEBUG_MSG(x...)\
		if (RDMA_PCI_PROBE_DBG) DEBUG_MSG(x)
static int rdma_pci_probe(struct pci_dev *dev, const struct pci_device_id *ent,
			  rdma_parms_e3m_t *parms_e3m)
{
	unsigned char bus_number_rdma, devfn_rdma;
	struct pci_bus *bus;
	unsigned int val;
	int ret = -EINVAL;
	int id, i;
	
	RDMA_PCI_PROBE_DEBUG_MSG("%s: SART\n", __FUNCTION__);
	if ((ret = pci_enable_device(dev))) {
#ifdef RDMA_2_6_14
		ERROR_MSG("%s: FAIL (%s: cannot enable pci device)\n",
			  __FUNCTION__, dev->dev.bus_id );
#else
		ERROR_MSG("%s: FAIL (%s: cannot enable pci device)\n",
			  __FUNCTION__, dev->dev.init_name );
#endif
		return ret;
	}
	if (!(bus = dev->bus)) {
		ERROR_MSG("%s: FAIL (bus is NULL)\n", __FUNCTION__);
		pci_disable_device(dev);
		return -ENODEV;
	}
	for (devfn_rdma = 0; devfn_rdma < 0xff; devfn_rdma++) {
		pcibios_read_config_dword(bus->number, devfn_rdma, 0, &id);
		if (id == 0x71918086) {
			bus_number_rdma = bus->number;
			RDMA_PCI_PROBE_DEBUG_MSG("%s: EDBUS-RDMA config space\n",
						 __FUNCTION__);
			for (i = 0; i < 7; i++) {
				pcibios_read_config_dword(bus->number,
							devfn_rdma, i<<2, &val);
				RDMA_PCI_PROBE_DEBUG_MSG("%s: %2d 0x%08u\n",
							__FUNCTION__, i<<2, val);
			}
			break;
		}
	}
	if (devfn_rdma == 0xff) {
		ERROR_MSG("%s: FAIL (no rdma_cards, devfn_rdma == 0xff)\n",
			  __FUNCTION__);
		pci_disable_device(dev);
		return -ENODEV;
	}

	pcibios_write_config_dword(bus->number, devfn_rdma, 4, 0x7);
	pcibios_read_config_dword(bus->number, devfn_rdma, 4, &val);

	parms_e3m->mmio_base = pci_resource_start(dev, PCI_MMIO_BAR);
	parms_e3m->mmio_len = pci_resource_len(dev, PCI_MMIO_BAR);

	if ( (ret = pci_request_region(dev, PCI_MMIO_BAR, "rdma MMIO")) ) {
		ERROR_MSG("%s: FAIL (cannot reserved PCI I/O and memory "
			  "resource)\n", __FUNCTION__);
		goto fail_mem;
	}

	parms_e3m->mmio_vbase = ioremap(parms_e3m->mmio_base,
					parms_e3m->mmio_len);

	if ( !parms_e3m->mmio_vbase ) {
		ERROR_MSG("%s: FAIL (cannot ioremap MMIO (0x%08lx:0x%x))\n",
			  __FUNCTION__, parms_e3m->mmio_base,
			  parms_e3m->mmio_len);
		ret = -ENOMEM;
		goto fail_mmio_ioremap;
	}
	e0regad = (unsigned char *)parms_e3m->mmio_vbase;
	RDMA_PCI_PROBE_DEBUG_MSG("%s: mmio_vbase: %p mmio_base: 0x%ld "
				 "mmio_len: %d\n",
				 __FUNCTION__, parms_e3m->mmio_vbase,
				 parms_e3m->mmio_base, parms_e3m->mmio_len);
	return 0;

fail_mmio_ioremap:
	pci_release_region(dev, PCI_MMIO_BAR);
fail_mem:
	pci_disable_device(dev);
	RDMA_PCI_PROBE_DEBUG_MSG("%s: FINISH\n", __FUNCTION__);
	return ret;
}

int init_node_e3m(rdma_parms_e3m_t *parms_e3m)
{
	struct pci_dev *dev = NULL;
	do {
		//dev = pci_find_device(0x8086, 0x7191, dev);  /* 0x71918086 */
		dev = pci_get_device(0x8086, 0x7191, dev);
		if (dev) {
			rdma_dev = dev;
			if (rdma_pci_probe(dev, NULL, parms_e3m) == 0) {
				return 0;
			}
		}
		break;
	} while(dev != NULL);
	return -1;
}
#endif

/*
 * IO Links of all nodes configuration
 */
_RDMA_iolinkmask_t _RDMA_iolink_online_rdma_map = _RDMA_IOLINK_MASK_NONE;
_RDMA_iolinkmask_t _RDMA_iolink_rdma_map = _RDMA_IOLINK_MASK_NONE;
int _RDMA_iolinks_num = 0,
    _RDMA_iolink_rdma_num = 0,
    _RDMA_iolink_online_rdma_num = 0;

#ifdef CONFIG_E2K
static void _RDMA_create_iolink_config(int node)
{
	e2k_iol_csr_struct_t io_link;
	e2k_rdma_cs_struct_t rdma;
	int iol_csr_link, link_on, rdma_2_link = 1, link;

	link_on = 0;
	/*
	 * E2S two link
	 */
	iol_csr_link = 0;
	sic_hw1_struct_t sic_hw1;

	sic_hw1.HW1_reg = sic_read_node_iolink_nbsr_reg(node,
			iol_csr_link, SIC_HW1_ADDR);
#define TWO_CHANNEL_RDMA_E2S_DBG	1
#if TWO_CHANNEL_RDMA_E2S_DBG
	INFO_MSG("DEFAULT: two link's RDMA (SIC_HW1: %08x): %s\n",
		 sic_hw1.HW1_reg, sic_hw1.HW1_mode ? "ENABLE":"DISABLE");
	sic_write_node_iolink_nbsr_reg(node, iol_csr_link,
				       SIC_HW1_ADDR, sic_hw1.HW1_reg | 0x1);
	sic_hw1.HW1_reg = sic_read_node_iolink_nbsr_reg(node,
			iol_csr_link, SIC_HW1_ADDR);
	INFO_MSG("SET: two link's RDMA (SIC_HW1: %08x): %s\n", sic_hw1.HW1_reg,
		 sic_hw1.HW1_mode ? "ENABLE":"DISABLE");
#endif
	INFO_MSG("Two link's RDMA for E2S: %s\n",
		 sic_hw1.HW1_mode ? "ENABLE":"DISABLE");
	if (!sic_hw1.HW1_mode)
		rdma_2_link = 0;
	io_link.E2K_IOL_CSR_reg = sic_read_node_iolink_nbsr_reg(node,
			iol_csr_link, IOL_CSR);
	for (link = 0; link < 2; link ++) {
		_RDMA_iolink_rdma_num ++;
		_RDMA_node_rdma_set(node, link,
				    _RDMA_iolink_rdma_map);
		INFO_MSG("Node #%d IO LINK (mode rdma) #%d is", node, link);
		if (!rdma_2_link && (link > 0)) {
			printk(" DISABLE ");
			break;
		}
		rdma.E2K_RDMA_CS_reg = sic_read_node_iolink_nbsr_reg(node,
				iol_csr_link, SHIFT_CS + link * E2S_OFFSET);
		if (rdma.E2K_RDMA_CS_ch_on) {
			_RDMA_node_rdma_set(node, link,
					    _RDMA_iolink_online_rdma_map);
			_RDMA_iolink_online_rdma_num ++;
			printk(" ON 0x%08x", rdma.E2K_RDMA_CS_reg);
			link_on = 1;
		} else {
			printk(" OFF 0x%08x", rdma.E2K_RDMA_CS_reg);
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
}
#endif

static void _RDMA_create_nodes_io_config(void)
{
	int node;
	
#ifdef CONFIG_E2K
	if (!IS_MACHINE_E2S) {
		memcpy(&_RDMA_iolink_online_rdma_map, &iolink_online_rdma_map,
			sizeof(iolinkmask_t));
		memcpy(&_RDMA_iolink_rdma_map, &iolink_rdma_map,
			sizeof(iolinkmask_t));
		_RDMA_iolink_rdma_num = iolink_rdma_num;
		_RDMA_iolink_online_rdma_num = iolink_online_rdma_num;
	}
	else {
		for_each_rdma(node)
			_RDMA_create_iolink_config(node);
	}
#else
	memcpy(&_RDMA_iolink_online_rdma_map, &iolink_online_rdma_map,
		sizeof(iolinkmask_t));
	memcpy(&_RDMA_iolink_rdma_map, &iolink_rdma_map,
		sizeof(iolinkmask_t));
	_RDMA_iolink_rdma_num = iolink_rdma_num;
	_RDMA_iolink_online_rdma_num = iolink_online_rdma_num;
#endif
}

void init_regs( void )
{
#ifdef CONFIG_E2K /* E3M & E3S*/
	if (HAS_MACHINE_L_SIC) { /* E3S */
		SHIFT_IO_VID	= IO_VID;
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
		SHIFT_IO_VID	= E3M_RDMA_VID;
		SHIFT_VID	= E3M_RDMA_VID;
		SHIFT_CH0_IDT	= E3M_RDMA_CH0_IDT;
		SHIFT_CH1_IDT	= E3M_RDMA_CH1_IDT;
		SHIFT_CH_IDT	= E3M_RDMA_CH0_IDT;
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
	SHIFT_IO_VID	= RDMA_VID;
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
#endif	/* E90 */

#ifdef CONFIG_E90S /* E90S */
	SHIFT_IO_VID	= IO_VID;
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
#endif	/* E90S */
}

static inline void sic_write_node_nbsr_reg_rdma(int node_id,
		unsigned int reg_offset, unsigned int reg_value)
{
	int node, link;
	unsigned int e2s_offset;
	
	node = NUM_NODE_RDMA(node_id);
	link = NUM_LINK_IN_NODE_RDMA(node_id);
	e2s_offset = 0;
#ifdef CONFIG_E2K
	if (IS_MACHINE_E2S) {
		if (link == 1)
			e2s_offset = E2S_OFFSET;
		link = 0;
	}
#endif
	sic_write_node_iolink_nbsr_reg(node, link, reg_offset + e2s_offset,
				       reg_value );
}

static inline unsigned int sic_read_node_nbsr_reg_rdma(int node_id,
		int reg_offset)
{
	unsigned int reg_value;
	int node, link;
	unsigned int e2s_offset;
	
	node = NUM_NODE_RDMA(node_id);
	link = NUM_LINK_IN_NODE_RDMA(node_id);
	e2s_offset = 0;
#ifdef CONFIG_E2K
	if (IS_MACHINE_E2S) {
		if (link == 1)
			e2s_offset = E2S_OFFSET;
		link = 0;
	}
#endif
	reg_value = sic_read_node_iolink_nbsr_reg(node, link,
						  reg_offset + e2s_offset);
	return (reg_value);
}

static rdma_buf_t* search_in_list (struct list_head* list1, int num1)
{
	struct list_head* tmp;
	rdma_buf_t* ret = NULL;

	list_for_each(tmp, list1) {
		ret = list_entry(tmp, rdma_buf_t, list);
		if(ret->num == num1) return (ret);
	}
	return (NULL);
}

unsigned long join_curr_clock(void)
{
	unsigned long ret;
	ret = get_cycles();
	return ret;
}

static inline void __raw_add_wait_queue_from_ddi(raw_wait_queue_head_t *head,
						 raw_wait_queue_t *new)
{
        list_add(&new->task_list, &head->task_list);
}
static inline void __raw_remove_wait_queue_from_ddi(raw_wait_queue_head_t *head,
		 				    raw_wait_queue_t *old)
{
        list_del(&old->task_list);
}

void raw_add_wait_queue_from_ddi(raw_wait_queue_head_t *q,
				 raw_wait_queue_t *wait)
{
        unsigned long flags;

        raw_spin_lock_irqsave(&q->lock, flags);
        __raw_add_wait_queue_from_ddi(q, wait);
        raw_spin_unlock_irqrestore(&q->lock, flags);
}

void raw_remove_wait_queue_from_ddi(raw_wait_queue_head_t *q,
				    raw_wait_queue_t *wait)
{
        unsigned long flags;

        raw_spin_lock_irqsave(&q->lock, flags);
        __raw_remove_wait_queue_from_ddi(q, wait);
        raw_spin_unlock_irqrestore(&q->lock, flags);
}

unsigned int	rdc_byte;

void WRR_rdma(unsigned int reg, unsigned int node, unsigned int val)
{
	/*
	 * SIC machine (E3S, Cubic, E2S, R1000)
	 */
	/*sic_write_node_iolink_nbsr_reg(node, io_link, reg, val); */
	if (HAS_MACHINE_L_SIC)
		sic_write_node_nbsr_reg_rdma(node, reg, val);
	/*
	 * E3M machine
	 */
	else
		writel(val, e0regad + reg);
	fix_event(node, WRR_EVENT, reg, val);
}

unsigned int RDR_rdma(unsigned int reg, unsigned int node)
{
	unsigned int val;
	/*
	 * SIC machine (E3S, Cubic, E2S, R1000)
	 */
	/* val = sic_read_node_iolink_nbsr_reg(node, io_link, reg); */
	if (HAS_MACHINE_L_SIC)
		val = sic_read_node_nbsr_reg_rdma(node, reg);
	/*
	 * E3M machine
	 */
	else
		val = readl(e0regad + reg);
	fix_event(node, RDR_EVENT, reg, val);
	return val;
}

unsigned int allign_dma(unsigned int n)
{
	if (n&(ALLIGN_RDMA-1)) {
		n += ALLIGN_RDMA;
		n = n&(~(ALLIGN_RDMA-1));
	}
        return n;
}

#define ALLIGN_RDMA_BUF 16 * PAGE_SIZE
unsigned int allign_dma_buf(unsigned int n)
{
	if (n&(ALLIGN_RDMA_BUF-1)) {
		n += ALLIGN_RDMA_BUF;
		n = n&(~(ALLIGN_RDMA_BUF-1));
	}
	return n;
}

int	MCG_CS_SEND_ALL_MSG =
		(MSG_CS_SD_Msg  | MSG_CS_SGP0_Msg | MSG_CS_SGP1_Msg |
		MSG_CS_SGP2_Msg | MSG_CS_SGP3_Msg | MSG_CS_SL_Msg   |
		MSG_CS_SUL_Msg  | MSG_CS_SIR_Msg);
int	MSG_CS_MSF_ALL = MSG_CS_DMPS_Err | MSG_CS_MPCRC_Err | MSG_CS_MPTO_Err |
		 	 MSG_CS_DMPID_Err;
unsigned int	count_loop_send_msg_max = 10;
unsigned int	count_wait_rdm_max = 64;

hrtime_t rdma_gethrtime(void)
{
	struct timeval tv;
	hrtime_t val;

	do_gettimeofday(&tv);
	val = tv.tv_sec * 1000000000LL + tv.tv_usec * 1000LL;
	return (val);
}

extern int wake_up_state(struct task_struct *p, unsigned int state);

static void __raw_wake_up_common_from_ddi(raw_wait_queue_head_t *q)
{
	struct list_head *tmp, *next;
	raw_wait_queue_t *curr;

	list_for_each_safe(tmp, next, &q->task_list) {
		curr = list_entry(tmp, raw_wait_queue_t, task_list);
		//wake_up_state(curr->task, 
		//	      TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE);
		wake_up_process(curr->task);
	}
}

void __raw_wake_up_from_ddi(raw_wait_queue_head_t *q)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&q->lock, flags);
	__raw_wake_up_common_from_ddi(q);
	raw_spin_unlock_irqrestore(&q->lock, flags);
}

int ddi_cv_broadcast_from_ddi(raw_wait_queue_head_t *cvp)
{
	__raw_wake_up_from_ddi(cvp);
        return 0;
}

int rdma_cv_broadcast_rdma(void* dev_rdma_sem, unsigned int link)
{
	rdma_addr_struct_t p_xxb;

	dev_rdma_sem_t *dev = dev_rdma_sem;
	dev->irq_count_rdma ++;
	dev->time_broadcast = join_curr_clock();
	p_xxb.addr = (unsigned long)dev;
	fix_event(link, RDMA_BROADCAST, p_xxb.fields.laddr,
		  dev->irq_count_rdma);
	ddi_cv_broadcast_from_ddi(&dev->cond_var);
	return (0);
}

/* 
 * Convert mksec to HZ 
 */
clock_t drv_usectohz_from_ddi(register clock_t mksec)
{
        clock_t clock;
	struct timespec rqtp;

	rqtp.tv_nsec = ((mksec % 1000000L) * 1000L);
	rqtp.tv_sec  = mksec / 1000000L;
	DEBUG_MSG("drv_usectohz: start, mksec = 0x%lx\n", mksec);
	DEBUG_MSG("drv_usectohz: rqtp.tv_nsec = 0x%lx, rqtp.tv_sec  = 0x%lx\n",
		  rqtp.tv_nsec, rqtp.tv_sec);
	clock = timespec_to_jiffies(&rqtp);
	return (clock);
}

int ddi_cv_spin_timedwait_from_ddi(raw_wait_queue_head_t *cvp,
				   raw_spinlock_t *lock, long tim)
{
        struct task_struct *tsk = current;
        unsigned long expire;
        int rval = 0;
	int raw_spin_locking_done = 0;
	
	DECLARE_RAW_WAIT_QUEUE(wait);
	expire = tim - jiffies;
	tsk->state = TASK_INTERRUPTIBLE;
	raw_add_wait_queue_from_ddi(cvp, &wait);
	raw_spin_locking_done = raw_spin_is_locked(lock);
	if(raw_spin_locking_done)
		spin_mutex_exit(lock);

	fix_event(0, WAIT_TRY_SCHTO_EVENT,
		(unsigned int)expire, 0);
	expire = schedule_timeout(expire);
	raw_remove_wait_queue_from_ddi(cvp, &wait);
	tsk->state = TASK_RUNNING;
	if(raw_spin_locking_done)
		spin_mutex_enter(lock);
	if (expire) {
		if (signal_pending(current)) {
			rval = -2;
		}
	} else {
		rval = -1;
	}
	return rval;
}

int wait_for_irq_rdma_sem(void* dev_rdma_sem, signed long usec_timeout,
			  unsigned int link)
{
	rdma_addr_struct_t p_xxb;
	dev_rdma_sem_t *dev = dev_rdma_sem;
	unsigned int time_current;
	unsigned int delta_time;
	signed long timeout_tick;
	int ret = 0;
	
	if (!raw_spin_is_locked(&dev->lock)) {
		printk("%s: spin is NOT locked:dev: %p\n", __FUNCTION__, dev);
		return -3;
	}
	if (dev->irq_count_rdma) {
	        printk("%s(%p): dev->irq_count_rdma: %u"
		       "num_obmen: %u\n", __FUNCTION__, &dev->lock,
   		       dev->irq_count_rdma, (unsigned int)dev->num_obmen);
		delta_time = 0;
		if (dev->time_broadcast) {
			time_current = join_curr_clock();
			if (time_current > dev->time_broadcast) {
				delta_time = (unsigned int)(time_current -
						dev->time_broadcast);
			} else {
				delta_time = (unsigned int)(time_current +
						(~0U - dev->time_broadcast));
			}
			delta_time |= (1<<31);
			fix_event(link, WAIT_RET_SCHT0_EVENT, delta_time,
				  dev->num_obmen);
			fix_event(link, WAIT_RET_SCHT0_EVENT,
				  dev->irq_count_rdma, dev->num_obmen);
			dev->time_broadcast = 0;
		}
		return(1);
	}
	p_xxb.addr = usec_timeout;
	fix_event(link, WAIT_TRY_SCHTO_EVENT,
		p_xxb.fields.laddr, dev->num_obmen);
	timeout_tick = (unsigned long)jiffies;
	timeout_tick += usec_timeout;
	ret = ddi_cv_spin_timedwait_from_ddi(&dev->cond_var, &dev->lock,
					      timeout_tick);
	delta_time = 0;
	if (dev->time_broadcast) {
		time_current = join_curr_clock();
		if (time_current > dev->time_broadcast) {
			delta_time = (unsigned int)(time_current -
					dev->time_broadcast);
		} else {
			delta_time = (unsigned int)(time_current +
					(~0U - dev->time_broadcast));
		}
		fix_event(link, WAIT_RET_SCHT1_EVENT, ret, dev->num_obmen);
		dev->time_broadcast = 0;
	} else {
		fix_event(dev->irq_count_rdma, WAIT_RET_SCHT2_EVENT, ret,
			  dev->num_obmen);
	}
	return ret;
}

rdma_event_t 	rdma_event;
int		rdma_event_init = 0;

#include "get_event_rdma.c"

void	fix_event_proc(unsigned int channel, unsigned int event,
		       unsigned int val1, unsigned int val2)
{
	struct event_cur *event_cur;
	unsigned long flags;

	if (!rdma_event_init)
		return;
	raw_spin_lock_irqsave(&mu_fix_event, flags);
	event_cur = &rdma_event.event[rdma_event.event_cur];
	event_cur->clkr = join_curr_clock();
	event_cur->event = event;
	event_cur->channel = channel;
	event_cur->val1 = val1;
	event_cur->val2 = val2;
	rdma_event.event_cur++;
	if (SIZE_EVENT == rdma_event.event_cur) {
		rdma_event.event_cur = 0;
	}
	raw_spin_unlock_irqrestore(&mu_fix_event, flags);
	return;
}

#include "rdma_intr.c"
#include "rdma_read_buf.c"
#include "rdma_write_buf.c"
#include "rdma_send_msg.c"

struct rdma_state *rdma_state;

int	irq_mc, irq_mc_0;

struct rdma_reg_state rdma_reg_state[RDMA_MAX_NUMIOLINKS];

 
int send_msg_check(unsigned int msg, unsigned int link, unsigned int cmd,
		   dev_rdma_sem_t *dev, int print_enable)
{
	rdma_state_link_t *rdma_link;
	int ret_send_msg, i, count_repeat = 10;
	unsigned long flags_s;
	
	rdma_link = &rdma_state->rdma_link[link];
	raw_spin_lock_irqsave(&rdma_link->mutex_send_msg, flags_s);
	for (i = 0; i < count_repeat; i++) {
		ret_send_msg = send_msg(rdma_link, msg, link, cmd, 0);
		if (ret_send_msg > 0) 
			break;
		if (ret_send_msg < 0) {
			if (print_enable)
				ERROR_MSG("%s: FAIL send msg: 0x%08x "
					  "cmd: 0x%08x from link: %d ret: %d\n",
					  __FUNCTION__, msg, cmd, link,
					  ret_send_msg);
			} else if (ret_send_msg == 0) {
				if (print_enable)
					DEBUG_MSG("%s: FAIL send msg: 0x%08x "
						  "cmd: 0x%08x from link: %d "
						  "ret: %d. SM is absent. "
						  "MSG_CS: 0x%08x \n", 
						  __FUNCTION__, msg, cmd, link,
						  ret_send_msg, 
						  RDR_rdma(SHIFT_MSG_CS, link));
				}
	}
	raw_spin_unlock_irqrestore(&rdma_link->mutex_send_msg, flags_s);
	if (ret_send_msg > 0) {
		fix_event(link, SNDMSGOK_EVENT, ret_send_msg, count_repeat);
		fix_event(link, SNDMSGOK_EVENT, 0xff, raw_smp_processor_id());
	} else { 
		fix_event(link,	SNDMSGBAD_EVENT, ret_send_msg, count_repeat);
		fix_event(link, SNDMSGBAD_EVENT, 0xff, raw_smp_processor_id());
	}
	return ret_send_msg;
}

#if RESET_THREAD_DMA

#define RST_THR_ACT_DBG 0
#define RST_THR_ACT_DEBUG_MSG(x...)\
		if (RST_THR_ACT_DBG) DEBUG_MSG(x)
int rst_thr_action(void *arg)
{
	rdma_state_link_t *rdma_link = (rdma_state_link_t *) arg;
	struct sched_param param = { .sched_priority = MAX_RT_PRIO/4 };
	unsigned long flags;
	int link = rdma_link->link;
	int count = 0;
	int ret_smsg, file_reciver_open = 0;
	unsigned int sending_msg;
	rw_state_p pd = NULL;
	dev_rdma_sem_t *dev_sem;
	rdma_pool_buf_t *r_pool_buf;

	RST_THR_ACT_DEBUG_MSG("%s: START link:%d rdma_link: %p\n", __FUNCTION__,
				 link, rdma_link);
	//sys_sched_setscheduler(current->pid, SCHED_FIFO, &param);
	sched_setscheduler(current, SCHED_FIFO, &param);
	pd = &rdma_link->rw_states_d[READER];
	dev_sem = &pd->dev_rdma_sem;
	r_pool_buf = &rdma_link->read_pool;
	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		//raw_spin_lock_irqsave(&dev_sem->lock, flags);
		raw_spin_lock_irq(&dev_sem->lock);
		if (pd->state_open_close) { 
			file_reciver_open = 1;
		}			
		else 
			file_reciver_open = 0;
		//raw_spin_unlock_irqrestore(&dev_sem->lock, flags);
		raw_spin_unlock_irq(&dev_sem->lock);
		raw_spin_lock_irqsave(&rdma_link->rst_thr_lock, flags);
		if ( rdma_link->start_rst_thr == 0) { 
			raw_spin_unlock_irqrestore(&rdma_link->rst_thr_lock, 
						   flags);
			RST_THR_ACT_DEBUG_MSG("%s: link:%d rdma_link: %p "
					      "no reset\n", __FUNCTION__, link,
	   				      rdma_link);
			schedule();
			continue;
		}
#if RST_THR_ACT_DBG
		read_regs_rdma(link);
#endif
		rdma_link->start_rst_thr = 0;
		raw_spin_unlock_irqrestore(&rdma_link->rst_thr_lock, flags);
#define DELAY_RESET 10
#define COUNT_RESET_RCS 10
		for (count = 1; count < COUNT_RESET_RCS; count++) {
			WRR_rdma(SHIFT_DMA_RCS, link, DMA_RCS_Rx_Rst);
			mdelay(DELAY_RESET);
		}
		WRR_rdma(SHIFT_DMA_RCS, link, RDR_rdma(SHIFT_DMA_RCS, link) |
				WCode_64);
#define COUNT_RESET_TCS 10
		for (count = 1; count < COUNT_RESET_TCS; count++) {
			WRR_rdma(SHIFT_DMA_TCS, link, DMA_TCS_Tx_Rst);
			mdelay(DELAY_RESET);
		}
		WRR_rdma(SHIFT_DMA_TCS, link, 
			 RDR_rdma(SHIFT_DMA_TCS, link) | RCode_64 |
					 DMA_TCS_DRCL);
		/*rdma_link->start_rst_thr = 0;*/
#if RST_THR_ACT_DBG
		read_regs_rdma(link);
#endif
		/*
		 * If file reciver open && transmiter reset
		 */
		if (file_reciver_open) {
			unsigned long flags_r;
			raw_spin_lock_irqsave(&pd->lock_rd, flags_r);
			/*
			 * The release of buffers
			 */
			while (!list_empty(&r_pool_buf->ready_list)) {
				list_move_tail(r_pool_buf->ready_list.next,
					       &r_pool_buf->free_list);
				r_pool_buf->num_free_buf ++;
			}
			/*while (!list_empty(&r_pool_buf->busy_list)) {
				list_move_tail(r_pool_buf->busy_list.next,
					       &r_pool_buf->free_list);
			}
			r_pool_buf->num_free_buf = num_buf;*/
			raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
			/*
			 * Create MSG_READY_DMA
			 */
			sending_msg = MSG_READY_DMA | r_pool_buf->num_free_buf;
			/*
			 * Send MSG_READY_DMA
			 */
#ifdef LOOP_MODE
			if (rdma_link->mode_loop == DISABLE_LOOP) {
#endif
			if ((ret_smsg = send_msg_check(sending_msg, link,
				0, dev_sem, 0)) <= 0) {
				fix_event(link, READ_SNDMSGBAD_EVENT,
					  sending_msg, dev_sem->num_obmen);
			} else {
				fix_event(link, READ_SNDNGMSG_EVENT,
					  sending_msg, dev_sem->num_obmen);
			}
#ifdef LOOP_MODE
		} else {
			rdma_pool_buf_t *w_pool_buf;
			rw_state_p pd_wr;
			dev_rdma_sem_t *dev_sem_wr;
			unsigned long flags_wr;
			
			w_pool_buf = &rdma_link->write_pool;
			pd_wr = &rdma_link->rw_states_d[WRITER];
			dev_sem_wr = &pd_wr->dev_rdma_sem;
			
			raw_spin_lock_irqsave(&dev_sem_wr->lock, flags_wr);
			pd_wr->trwd_was = sending_msg & MSG_USER;
			/*
			 * If hes free buf's reciver
			 */
			if (pd_wr->trwd_was) {
				switch (pd_wr->int_ac) {
				case 1:
					/*
					 * Wake up write
					 */
					rdma_cv_broadcast_rdma(&pd_wr->dev_rdma_sem, 
							link);
						break;
				default:
					break;
				}
			}
			raw_spin_unlock_irqrestore(&dev_sem_wr->lock, flags_wr);
		}
#endif
		}
		WRR_rdma(SHIFT_IRQ_MC, link ,irq_mc);

		RST_THR_ACT_DEBUG_MSG("%s: link:%d rdma_link: %p reset\n",
				      __FUNCTION__, link, rdma_link);
	}
	__set_current_state(TASK_RUNNING);
	RST_THR_ACT_DEBUG_MSG("%s: STOP link:%d rdma_link: %p\n", __FUNCTION__,
			      link, rdma_link);
	return 0;
}
#endif

#define INIT_POOL_BUF_DBG 0
#define INIT_POOL_BUF_DEBUG_MSG(x...)\
		if (INIT_POOL_BUF_DBG) DEBUG_MSG(x)

static int init_pool_buf(int link, int rw)
{
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[link];
	rdma_tbl_64_struct_t *peltbl, *peltbl_tmp;
	rdma_addr_struct_t pxx;
	rdma_pool_buf_t *pool_buf;
	int buf_size_page;
	int i;
	rdma_buf_t *r_buf; 
	
	INIT_POOL_BUF_DEBUG_MSG("%s: buffer(%s) START \n", __FUNCTION__,
				rw ? "write" : "read");
	rw ? (pool_buf = &rdma_link->write_pool) :
	     (pool_buf = &rdma_link->read_pool);
	pool_buf->alloc = RDMA_BUF_EMPTY;
	tm_mode ? (buf_size = PAGE_ALIGN(max_size_buf_tm)) :
 	          /*(buf_size = PAGE_ALIGN(max_size_buf));*/
		  (buf_size = allign_dma(max_size_buf));
	//tm_mode ? (buf_size = allign_dma_buf(max_size_buf_tm)) :
 	//          (buf_size = PAGE_ALIGN(max_size_buf));
	buf_size_page = buf_size / PAGE_SIZE;
	if (tm_mode)
		INIT_POOL_BUF_DEBUG_MSG("%s: max_size_buf_tm: "
					"0x%08x buf_size: 0x%08x  "
					"buf_size_page: %d\n",
					__FUNCTION__, max_size_buf_tm,
					buf_size, buf_size_page);
	else 
		INIT_POOL_BUF_DEBUG_MSG("%s: max_size_buf: "
					"0x%08x buf_size: 0x%08x  "
					"buf_size_page: %d\n",
					__FUNCTION__, max_size_buf,
					buf_size, buf_size_page);
	pool_buf->buf_size = buf_size;
	pool_buf->size = buf_size * num_buf;
	pool_buf->node_for_memory = NUM_NODE_RDMA(link);
	pool_buf->tm_mode = tm_mode; 
	INIT_POOL_BUF_DEBUG_MSG("%s: buffer(%s) buf_size: 0x%016lx tm_mode: %d "
				"node_for_memory: 0x%08x\n", __FUNCTION__,
				rw ? "write" : "read", pool_buf->size,
				pool_buf->tm_mode, pool_buf->node_for_memory);
	/*
	 * Alloc memory for pool (get user access address and DMA address)
	 */
#ifdef CONFIG_RDMA_BOOT_MEM_ALLOC
	if ((R_M) && (rdma_link_mem[NUM_NODE_RDMA(link)])) {
		INFO_MSG("%s: alloc bootmem rdma_link_mem[%d]: %p\n",
			 __FUNCTION__, NUM_NODE_RDMA(link),
			 rdma_link_mem[NUM_NODE_RDMA(link)]);
		tm_mode = 0;
		pool_buf->tm_mode = tm_mode;
		pool_buf->vdma = (caddr_t)(rdma_link_mem[NUM_NODE_RDMA(link)] +
				pool_buf->size * busy_rdma_boot_mem);
		pool_buf->fdma = (dma_addr_t)virt_to_phys(pool_buf->vdma);
		/*busy_rdma_boot_mem++;*/
		pool_buf->dma_size = pool_buf->size;
	} else
#endif
		if (rdma_mem_alloc_pool(pool_buf)) {
			ERROR_MSG("%s: ERROR: Cannot alloc device buffer "
				  "for link: %d buf: %s\n", __FUNCTION__,
				  link, rw ? "write" : "read");
			goto failed;
		}
	pool_buf->alloc = RDMA_BUF_ALLOCED;
	
	/*
	 * Init list's
	 */
	INIT_LIST_HEAD(&pool_buf->ready_list);
	INIT_LIST_HEAD(&pool_buf->free_list);
	INIT_LIST_HEAD(&pool_buf->busy_list);
	
	if (pool_buf->tm_mode) 
		peltbl = (rdma_tbl_64_struct_t *)pool_buf->vdma;
	for(i = 0; i < num_buf; i++) {
		r_buf = &pool_buf->buf[i];
		INIT_POOL_BUF_DEBUG_MSG("%s: ADDR BUFF[%d]: %p\n", __FUNCTION__,
					i, r_buf);
		INIT_POOL_BUF_DEBUG_MSG("%s: alloc buf[%d]\n", __FUNCTION__, i);
		pool_buf->buf[i].num = i;
		INIT_POOL_BUF_DEBUG_MSG("%s: pool_buf->buf[%d].num : 0x%08x\n",
					__FUNCTION__, i, pool_buf->buf[i].num);
		pool_buf->buf[i].st = RDMA_BUF_ST_FREE;
		INIT_POOL_BUF_DEBUG_MSG("%s: pool_buf->buf[%d].st: 0x%08x\n",
					__FUNCTION__, i, pool_buf->buf[i].st);
		if (pool_buf->tm_mode) {
			peltbl_tmp = peltbl + i * buf_size_page;
			pool_buf->buf[i].buf_addr =
				(caddr_t)((unsigned long)peltbl_tmp);
			pool_buf->buf[i].dma_addr = (dma_addr_t)
				virt_to_phys(pool_buf->buf[i].buf_addr);
			/*pool_buf->buf[i].dma_addr = (dma_addr_t)
					virt_to_phys((caddr_t)(unsigned long)peltbl_tmp);*/
			pxx.addr = (unsigned long)peltbl_tmp;
			printk("%s: 0x%08x%08x peltbl : %p buf[%d]\n",
			       __FUNCTION__, pxx.fields.haddr, pxx.fields.laddr,
			       peltbl_tmp, i);
			pxx.addr = peltbl_tmp->addr;
			printk("%s: 0x%08x%08x peltbl->addr buf[%d]\n",
			       __FUNCTION__, pxx.fields.haddr,
			       pxx.fields.laddr, i);
			printk("%s: 0x%llx peltbl->sz buf[%d]\n", __FUNCTION__,
			       peltbl_tmp->sz, i);
		} else {
			pool_buf->buf[i].buf_addr =
					(caddr_t)((unsigned long)pool_buf->vdma
					+ buf_size * i);
#ifdef CONFIG_E2K
			if (IS_MACHINE_E3M)
				pool_buf->buf[i].dma_addr = (dma_addr_t)
					virt_to_phys(pool_buf->buf[i].buf_addr);
			else
#endif
				pool_buf->buf[i].dma_addr = (dma_addr_t)
					virt_to_phys(pool_buf->buf[i].buf_addr);
		}
		pool_buf->buf[i].size = pool_buf->buf_size;
		INIT_POOL_BUF_DEBUG_MSG("%s: pool_buf->buf[%d].size: 0x%016lx\n",
					__FUNCTION__, i, pool_buf->buf[i].size);
		pxx.addr = (unsigned long) pool_buf->buf[i].buf_addr;
		INIT_POOL_BUF_DEBUG_MSG("%s: 0x%08x%08x "
					"pool_buf->buf[%d].buf_addr\n",
					__FUNCTION__, pxx.fields.haddr,
					pxx.fields.laddr, i);
		pxx.addr = pool_buf->buf[i].dma_addr;
		INIT_POOL_BUF_DEBUG_MSG("%s: 0x%08x%08x "
					"pool_buf->buf[%d].dma_addr\n",
					__FUNCTION__, pxx.fields.haddr,
					pxx.fields.laddr, i);
		list_add_tail(&pool_buf->buf[i].list, &pool_buf->free_list);
	}
	pool_buf->num_free_buf = num_buf;
	/*rw ? (pool_buf->num_free_buf = 1) : (pool_buf->num_free_buf = num_buf);*/
#if 0	
	if (!rw) {
		unsigned int sending_msg;
		int ret_smsg;

		// Create MSG_READY_DMA 
		sending_msg = MSG_READY_DMA | pool_buf->num_free_buf;
		// Send TRWD 
		if ((ret_smsg = send_msg(rdma_link, sending_msg, link, 
		     0, (dev_rdma_sem_t *)NULL)) > 0)
			fix_event(link, READ_SNDMSGBAD_EVENT, ret_smsg, 
				  pool_buf->num_free_buf);

	}
#endif	
	INIT_POOL_BUF_DEBUG_MSG("%s: buffer(%s) STOP \n", __FUNCTION__,
				rw ? "write" : "read");
	return 0;
failed:
	return -1;
}

#define FREE_POOL_BUF_DBG 0
#define FREE_POOL_BUF_DEBUG_MSG(x...)\
		if (FREE_POOL_BUF_DBG) DEBUG_MSG(x)
static int free_pool_buf(int link, int rw)
{
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[link];
	rdma_addr_struct_t pxx;
	rdma_pool_buf_t *pool_buf;
	int i;
		
	FREE_POOL_BUF_DEBUG_MSG("%s: buffer(%s) START \n", __FUNCTION__,
				rw ? "write" : "read");
	rw ? (pool_buf = &rdma_link->write_pool) :
 	     (pool_buf = &rdma_link->read_pool);
	
	//INIT_LIST_HEAD(&pool_buf->ready_list);
	//INIT_LIST_HEAD(&pool_buf->free_list);
	//INIT_LIST_HEAD(&pool_buf->busy_list);
	
	/*
	 * Free memory for pool (get user access address and DMA address)
	 */
#ifndef CONFIG_RDMA_BOOT_MEM_ALLOC	
	rdma_mem_free_pool(pool_buf);
#endif
	for(i = 0; i < num_buf; i++) {
		FREE_POOL_BUF_DEBUG_MSG("%s: free buf[%d]\n", __FUNCTION__, i);
		pool_buf->buf[i].size = 0;
		FREE_POOL_BUF_DEBUG_MSG("%s: pool_buf->buf[%d].size: 0x%016lx\n",
					__FUNCTION__, i, pool_buf->buf[i].size);
		pool_buf->buf[i].buf_addr = NULL;
		pxx.addr = (unsigned long) pool_buf->buf[i].buf_addr;
		FREE_POOL_BUF_DEBUG_MSG("%s: 0x%08x%08x "
					"pool_buf->buf[%d].buf_addr\n",
					__FUNCTION__, pxx.fields.haddr,
					pxx.fields.laddr, i);
		pool_buf->buf[i].dma_addr = 0;
		pxx.addr = pool_buf->buf[i].dma_addr;
		FREE_POOL_BUF_DEBUG_MSG("%s: 0x%08x%08x "
					"pool_buf->buf[%d].dma_addr\n",
					__FUNCTION__, pxx.fields.haddr,
					pxx.fields.laddr, i);
	}
	return 0;
}

int init_bufs_regs_link(int i)
{
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[i];
	unsigned int cs;
#ifndef LMS
	WRR_rdma(SHIFT_CH_IDT, i, (l_base_mac_addr[3] + i) |
				  ((l_base_mac_addr[4] + i) << 8));
#endif
	init_rdma_link(i);
#ifdef CONFIG_RDMA_BOOT_MEM_ALLOC
	busy_rdma_boot_mem = 0;
#endif		
	if (init_pool_buf(i, READER))
		goto failed;
#ifdef CONFIG_RDMA_BOOT_MEM_ALLOC
	busy_rdma_boot_mem = 1;
#endif		
	if (init_pool_buf(i, WRITER))
		goto failed;
	cs = RDR_rdma(SHIFT_CS, i);
#ifdef CONFIG_E2K
	if (IS_MACHINE_E2S) 
		WRR_rdma(SHIFT_CS, i, cs | CS_DSM | E2S_CS_PTOCL );
	else if (IS_MACHINE_E3M)
		WRR_rdma(SHIFT_CS, i, 0x2a00);
	else
		WRR_rdma(SHIFT_CS, i, cs | CS_DSM );
#else
	WRR_rdma(SHIFT_CS, i, cs | CS_DSM );
#endif
	INFO_MSG("SHIFT_CS: 0x%08x\n", RDR_rdma(SHIFT_CS, i));
	/*
	 * Spin lock send msg
	 */
	raw_spin_lock_init(&rdma_link->mutex_send_msg);
#if RESET_THREAD_DMA
	rdma_link->rst_thr = kthread_create(rst_thr_action, rdma_link,
					    "%d-rdma-rx-rst-thr", i);
	if (!rdma_link->rst_thr) {
		ERROR_MSG("%s: could not create %d-rdma-rst-thr\n",
			  __FUNCTION__, i);
		goto failed;
	}
	/*
	 * Spin lock thread reset
	 */
	raw_spin_lock_init(&rdma_link->rst_thr_lock);
	rdma_link->start_rst_thr = 0;
#else
	WRR_rdma(SHIFT_DMA_TCS, i, DMA_TCS_Tx_Rst);
#ifdef CONFIG_E2K 
	WRR_rdma(SHIFT_DMA_TCS, i, RDR_rdma(SHIFT_DMA_TCS, i) |
		(IS_MACHINE_E3M ? DMA_TCS_DRCL : RCode_64 | DMA_TCS_DRCL));
#else
	WRR_rdma(SHIFT_DMA_TCS, i, RDR_rdma(SHIFT_DMA_TCS, i) |
			( RCode_64 | DMA_TCS_DRCL));
#endif		
#define COUNT_RESET_RCS 10
	int count = 0;
	for (count = 1; count < COUNT_RESET_RCS; count++)
		WRR_rdma(SHIFT_DMA_RCS, i, DMA_RCS_Rx_Rst);
#ifdef CONFIG_E2K 
	WRR_rdma(SHIFT_DMA_RCS, i, RDR_rdma(SHIFT_DMA_RCS, i) |
			(IS_MACHINE_E3M ? 0x0 : WCode_64));
#else
	WRR_rdma(SHIFT_DMA_RCS, i, RDR_rdma(SHIFT_DMA_RCS, i) | WCode_64);
#endif
#endif
	rdma_link->mode_loop = DISABLE_LOOP;
	return 0;
failed:
	return 1;
}

void set_mask_and_start_reset(int i)
{
#if RESET_THREAD_DMA
		unsigned long flags;
		
		rdma_state_link_t *rdma_link = &rdma_state->rdma_link[i];
		WRR_rdma(SHIFT_IRQ_MC, i ,irq_mc_0);
		raw_spin_lock_irqsave(&rdma_link->rst_thr_lock, flags);
		rdma_link->start_rst_thr = 1;
		raw_spin_unlock_irqrestore(&rdma_link->rst_thr_lock, flags);
		wake_up_process(rdma_link->rst_thr);
#else
		WRR_rdma(SHIFT_IRQ_MC, i ,irq_mc);
#endif
}

int send_SIR_and_SGP0_Msg(int i)
{
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[i];
	rdma_addr_struct_t p_xxb;
	int ret = 0;

	p_xxb.addr = (unsigned long)rdma_link;
	INFO_MSG("%s: link: %d rdma_state->rdma_link: 0x%08x%08x\n",
		 __FUNCTION__, i, p_xxb.fields.haddr, p_xxb.fields.laddr);
	/*
	 * Send SIR (start CAM)
	 */
	ret = send_msg_check(0, i, MSG_CS_SIR_Msg, 0, 0);
	if (ret < 0) {
		ERROR_MSG("%s: FAIL send MSG_CS_SIR_Msg from link: 0x%08x "
			  "ret: %d\n", __FUNCTION__, i, ret);
	} else
		if (ret == 0) {
			INFO_MSG("%s: FAIL send MSG_CS_SIR_Msg"
				 "from link: 0x%08x. SM is absent\n",
     				 __FUNCTION__, i);
		}
#if RESET_THREAD_DMA
		/*
		 * Send GP0 (reset)
		 */
		ret = send_msg_check(0, i, MSG_CS_SGP0_Msg, 0, 0);
		if (ret < 0) {
			ERROR_MSG("%s: FAIL send MSG_CS_SGP0_Msg from"
				  "link: 0x%08x ret: %d\n",
    				  __FUNCTION__, i, ret);
		} else
			if (ret == 0) {
				INFO_MSG("%s: FAIL send MSG_CS_SGP0_Msg"
					 "from link: 0x%08x. SM is absent\n",
					 __FUNCTION__, i);
			}
#endif
	return ret;
}

#define RDMA_INIT_DBG 0
#define RDMA_INIT_DEBUG_MSG(x...)\
		if (RDMA_INIT_DBG) DEBUG_MSG(x)
static int __init rdma_init(void)
{
	size_t size_rdma_state;
	unsigned int i;
	int node;
	int major;
	
	/*
	if (!HAS_MACHINE_L_SIC) {
		ERROR_MSG("%s: sorry, I am worked on e3s/e90s/e2s\n",
			  __FUNCTION__);
		RDMA_INIT_DEBUG_MSG("%s: FINISH\n", __FUNCTION__);
		return -ENODEV;
	}
	*/
	if (!rdma_present) {
		rdma_present = 1;
	} else {
		ERROR_MSG("%s: RDMA registers busy. \n", __FUNCTION__);
		return -ENODEV;
	}
	
	if (!rdma_apic_init) {
		ERROR_MSG("%s: Hard rdma is absent(not registers interrupt "
			  "for RDMA)\n", __FUNCTION__);
		rdma_present = 0;
		return -ENODEV;
	}

	/*
	 * Init reg's for E3S, E3M, E90S, E90
	 */
	init_regs();
	
	/*
	 * Create rdma link config
	 */
	if (HAS_MACHINE_L_SIC) {
		_RDMA_create_nodes_io_config();
	}
	
	if (HAS_MACHINE_L_SIC) {
		if (!_RDMA_num_possible_rdmas()) {
			ERROR_MSG("%s: hard rdma is absent(no link RDMA mode)\n",
				  __FUNCTION__);
			rdma_present = 0;
			return -ENODEV;
		}
		/*
		 *  Add hot plugging
		 */
#ifdef CONFIG_E2K
		if (IS_MACHINE_E2S) {
			if (!_RDMA_num_online_rdmas()) {
				only_loopback = 1;
				INFO_MSG("E2S. Proccesig only Loopback mode.\n");
			}
		} else
#endif
		if (!_RDMA_num_online_rdmas()) {
			ERROR_MSG("%s: RDMA does not support hot plugging."
				  "Connect the cable and reboot machine.\n",
				  __FUNCTION__);
			rdma_present = 0;
			return -ENODEV;
		}
	}
	rdma_event_init = 1;
#ifdef CONFIG_E90S
	INFO_MSG("RDMA: I am worked on E90S, NODE_NUMIOLINKS: %d"
		 "MAX_NUMIOLINKS: %d\n ", RDMA_NODE_IOLINKS,
		 RDMA_MAX_NUMIOLINKS);
	INFO_MSG("E90S. Loopback mode is not implemented.\n");
#else 
	INFO_MSG("I am worked on E3M/E3S/CUBIC/E2S, NODE_NUMIOLINKS: %d "
		 "MAX_NUMIOLINKS: %d\n", RDMA_NODE_IOLINKS,
		 RDMA_MAX_NUMIOLINKS);
	if (IS_MACHINE_E3S) {
		INFO_MSG("E3S. Loopback mode is not implemented.\n");
	}
	if (IS_MACHINE_ES2) {
		INFO_MSG("CUBIC. Loopback mode is not implemented.\n");
	}
	if (IS_MACHINE_E2S) {
		INFO_MSG("E2S. Loopback mode implemented.\n");
	}
	if (IS_MACHINE_E3M) {
		rdma_parms_e3m_t parms_e3m;
		INFO_MSG("E3M. Loopback mode is not implemented.\n");
		if (init_node_e3m(&parms_e3m)) {
			ERROR_MSG("%s: RDMA devices not find.\n", __FUNCTION__);
			rdma_present = 0;
			return -ENODEV;
		}
		if (tm_mode == 1) {
			INFO_MSG("E3M. Table mode is not implemented. "
				 "Set no tables mode.\n");
			tm_mode = 0;
		}
	}
#endif
	if (num_buf >  RDMA_BUF_NUM) {
		ERROR_MSG("%s: num_buf > max_buf(%d).\n", __FUNCTION__,
			  RDMA_BUF_NUM);
		rdma_present = 0;
		return (-EINVAL);
	}
	
	if (!tm_mode) {
		if ((max_size_buf * num_buf ) > LIMIT_SIZE_BUFF) {
			ERROR_MSG("%s: The large size of the buffer. "
				  "The buffer must be: max_size_buf * "
				  "num_buf <= 0x%08x. \n",
				  __FUNCTION__, LIMIT_SIZE_BUFF);
			rdma_present = 0;
			return (-EINVAL);
		}
	}
#if 0
	if (tm_mode) {
		if (max_size_buf_tm > MAX_SIZE_BUFF_TM){
			ERROR_MSG("%s: The large size of the buffer. "
					"The buffer must be <= 0x%08x. \n",
					__FUNCTION__, MAX_SIZE_BUFF_TM);
			rdma_present = 0;
			return (-EINVAL);
		}
	} else {
		if (max_size_buf > MAX_SIZE_BUFF){
			ERROR_MSG("%s: The large size of the buffer. "
					"The buffer must be <= 0x%08x.\n",
					__FUNCTION__, MAX_SIZE_BUFF);
			rdma_present = 0;
			return (-EINVAL);
		}
	}
#endif
	INFO_MSG("tm_mode : %d\n", tm_mode);
	INFO_MSG("num_buf : %d\n", num_buf);
	if (tm_mode)
		INFO_MSG("max_size_buf_tm : 0x%x\n", max_size_buf_tm);
	else
		INFO_MSG("max_size_buf : 0x%x\n", max_size_buf);
	INFO_MSG("node_mem_alloc : %d\n", node_mem_alloc);
	if (ev_pr)
		INFO_MSG("Print event's mode.\n");
	
	if (HAS_MACHINE_L_SIC) {
		node = numa_node_id();
	} else
		node = 0;
	fix_event(node, RDMA_INIT, START_EVENT, 0);
	major = register_chrdev(0, board_name, &rdma_fops);
	if ( major < 0 ) {
		ERROR_MSG("%s: There isn't free major\n", __FUNCTION__);
		/*goto failed;*/
		rdma_present = 0;
		return (-EINVAL);
	}
	RDMA_INIT_DEBUG_MSG("%s: major: %d\n", __FUNCTION__, major);
	RDMA_INIT_DEBUG_MSG("%s: I am on %d numa_node_id\n", __FUNCTION__,
			    node);
	RDMA_INIT_DEBUG_MSG("%s: %lx: sizeof (nodemask_t)\n", __FUNCTION__,
			    sizeof (nodemask_t));
	size_rdma_state = sizeof (struct rdma_state);
	rdma_state = (struct rdma_state *)kmalloc(size_rdma_state, GFP_KERNEL);
	if (rdma_state == (struct rdma_state *)NULL) {
		ERROR_MSG("%s: rdma_state == NULL\n", __FUNCTION__);
		unregister_chrdev(major, board_name);
		rdma_present = 0;
		return (-EFAULT);
	}
	memset(rdma_state, 0, size_rdma_state);
	RDMA_INIT_DEBUG_MSG("%s: sizeof (struct rdma_state): 0x%016lx\n",
			    __FUNCTION__, size_rdma_state);
	rdma_state->size_rdma_state = size_rdma_state;
	rdma_state->major = major;
#ifdef CONFIG_E2K
	if (IS_MACHINE_E3M)
		rdma_state->dev_rdma = rdma_dev;
#endif
#ifdef MODULE
	if (create_dev_rdma(major))
		ERROR_MSG("rdma_init: Error creating devices. "
			  "Create a device manually.");
#endif
#ifdef CONFIG_RDMA_BOOT_MEM_ALLOC
	/*
	 * Memory alloceted boot time
	 */
	if (R_M) {
		INFO_MSG("%s: check alloc bootmem R_M: %x\n",
			 __FUNCTION__, R_M);
		if ((long)R_M < (long)(PAGE_ALIGN(max_size_buf) * num_buf)) {
			ERROR_MSG("%s: Error alloc bootmem for rdma. "
				  "R_M(%x) < max_size_buf * num_buf(%x)\n",
				  __FUNCTION__, R_M,
				  PAGE_ALIGN(max_size_buf) * num_buf);
			goto failed;
		}
	}
#endif
	if (HAS_MACHINE_L_SIC)
		/*_RDMA_for_each_online_rdma(i) { */
		_RDMA_for_each_rdma(i) {
			if (init_bufs_regs_link(i))
				goto failed;
		}
	else {
		if (init_bufs_regs_link(0))
			goto failed;
	}
	
	tr_atl = ATL_B | (atl_v & ATL);
	INFO_MSG("Reg CAM ATL: %x\n", tr_atl);
	
	rdma_interrupt_p = rdma_interrupt;
	irq_mc_0 =
			IRQ_RGP3M	|
			//IRQ_RDM	|
			IRQ_RGP0M;
	irq_mc =
			IRQ_RDM		|
			IRQ_RGP3M	|
			IRQ_RGP2M	|
			IRQ_RGP1M	|
			IRQ_RGP0M	|
			IRQ_RIAM	|
			IRQ_RIRM	|
			IRQ_RULM	|
			IRQ_RLM		|
			IRQ_MSF		|
#if DSF_NO
			//IRQ_DSF	|
#else
			IRQ_DSF		|
#endif
			IRQ_TDC		|
			IRQ_RDC		|
			IRQ_CMIE
			;
	
	if (HAS_MACHINE_L_SIC)
		/*_RDMA_for_each_online_rdma(i) {*/
		_RDMA_for_each_rdma(i) {
			set_mask_and_start_reset(i);
		}
	else
		set_mask_and_start_reset(0);
	msg_cs_dmrcl = MSG_CS_DMRCL;
#ifdef LOOP_MODE
	if (!only_loopback)
#endif
	if (HAS_MACHINE_L_SIC)
		_RDMA_for_each_online_rdma(i) {
			send_SIR_and_SGP0_Msg(i);
		}
	else {
		send_SIR_and_SGP0_Msg(0);
	}
	return 0;
failed:
	rdma_cleanup();
	RDMA_INIT_DEBUG_MSG("%s: FINISH\n", __FUNCTION__);
	return -ENODEV;
}
/*
 * Unset mask interrupt and free buff's
 */
void unset_mask_and_free_buff(int i)
{
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[i];
	
	WRR_rdma(SHIFT_IRQ_MC, i,  0x0);
#ifndef CONFIG_RDMA_BOOT_MEM_ALLOC
	free_pool_buf(i, READER);
	free_pool_buf(i, WRITER);
#endif
#if RESET_THREAD_DMA
	if (rdma_link->rst_thr)
		kthread_stop(rdma_link->rst_thr);
	if (rdma_link->rst_thr)
		kthread_stop(rdma_link->rst_thr);
#endif
}

#define RDMA_CLEANUP_DBG 0
#define RDMA_CLEANUP_DEBUG_MSG(x...)\
		if (RDMA_CLEANUP_DBG) DEBUG_MSG(x)
static void rdma_cleanup(void)
{
	int i, major;
	
	major = (int)rdma_state->major;
	RDMA_CLEANUP_DEBUG_MSG("%s: START rdma_state->major %d\n", __FUNCTION__,
			       major);
	if (HAS_MACHINE_L_SIC)
		/*_RDMA_for_each_online_rdma(i) {*/
		_RDMA_for_each_rdma(i) {
			unset_mask_and_free_buff(i);
		}
	else
		unset_mask_and_free_buff(0);
	rdma_interrupt_p = (void *) NULL;
#ifdef MODULE
	remove_dev_rdma(major);
#endif
#ifdef CONFIG_E2K
	if (IS_MACHINE_E3M) {
		iounmap(e0regad);
		pci_release_region(rdma_state->dev_rdma, PCI_MMIO_BAR);
	}
#endif
	unregister_chrdev(rdma_state->major, board_name);
#ifdef CONFIG_E2K
	if (IS_MACHINE_E3M) {
		pci_disable_device(rdma_state->dev_rdma);
	}
#endif
	rdma_event_init = 0;
	kfree(rdma_state);
	if (rdma_present)
		rdma_present = 0;
	RDMA_CLEANUP_DEBUG_MSG("%s:  FINISH\n", __FUNCTION__);
	return;
}

#define RDMA_CLOSE_DBG 0
#define RDMA_CLOSE_DEBUG_MSG(x...)\
		if (RDMA_CLOSE_DBG) DEBUG_MSG(x)
static int rdma_close(struct inode *inode, struct file *file)
{
	rdma_state_link_t *rdma_link;
	dev_rdma_sem_t *dev_sem;
	rw_state_t *rdma_private_data;
	rw_state_p pd;
	unsigned long flags_w, flags_r;
	int minor, file_eys = 0, i;
	int link, file_open_mode;

	/*
	 * Cleanup: make over rdma_private_data.
	 */
	RDMA_CLOSE_DEBUG_MSG("%s: START\n", __FUNCTION__);
	minor = MINOR(inode->i_rdev);
	if (minor < 0) {
		ERROR_MSG("%s: minor(%d) < 0\n", __FUNCTION__, minor);
		return (-EINVAL);
	}
	link = DEV_inst(minor);
	if (HAS_MACHINE_L_SIC) {
		/*_RDMA_for_each_online_rdma(i)*/
		_RDMA_for_each_rdma(i)
			if (i == link)
				file_eys++;
	} else {
		if (0 == link)
			file_eys++;
	}
	if (!file_eys) {
		ERROR_MSG("%s: link %d not support RDMA\n", __FUNCTION__,
			  link);
		return (-EINVAL);
	}
	rdma_link = &rdma_state->rdma_link[link];
	file_open_mode = minor % 2;
	rdma_private_data = &rdma_link->rw_states_d[file_open_mode];
	RDMA_CLOSE_DEBUG_MSG("%s: mode close %s (minor: 0x%08x)\n",
			     __FUNCTION__, file_open_mode ? "WRITE" : "READ",
			     minor);
	mutex_enter(&rdma_link->mu);
	rdma_link->opened &= ~(1 << rdma_private_data->open_mode);
	rdma_private_data->open_mode = 0;
	file->private_data = NULL;
	RDMA_CLOSE_DEBUG_MSG("%s: opened.minor.link.channel: 0x%x.%d.%d.%d\n",
			    __FUNCTION__, rdma_link->opened, minor, link,
			    rdma_private_data->open_mode);
	mutex_exit(&rdma_link->mu);
	
	pd = &rdma_link->rw_states_d[file_open_mode];
	dev_sem = &pd->dev_rdma_sem;
	/*raw_spin_lock_irqsave(&dev_sem->lock, flags);*/
	raw_spin_lock_irq(&dev_sem->lock);
	/*
	 * File open as READER
	 */
	if (!file_open_mode) {
		rdma_pool_buf_t *r_pool_buf;
		unsigned int ret_wait_rdc;
		unsigned int sending_msg;
		unsigned int ret_smsg;
		int count_wait_rdc = TX_RX_WAIT_DMA;
		
		r_pool_buf = &rdma_link->read_pool;
		/*
		 * Reciver wait dma
		 */
		while (count_wait_rdc--)
		{
			ret_wait_rdc = RDR_rdma(SHIFT_DMA_RCS, link);
			if (!(ret_wait_rdc & DMA_RCS_RE)) {
				goto end_wait_rdc;
			}
		}
		ERROR_MSG("%s: link %d ret_wait_rdc: 0x%08x "
			  "count_wait_rdc: %d\n", __FUNCTION__, link,
			  ret_wait_rdc, count_wait_rdc);	
end_wait_rdc:
		raw_spin_lock_irqsave(&pd->lock_rd, flags_r);
		/*
		 * The release of buffers
		*/
		while (!list_empty(&r_pool_buf->ready_list)) {
			list_move_tail(r_pool_buf->ready_list.next,
				       &r_pool_buf->free_list);
		}
		while (!list_empty(&r_pool_buf->busy_list)) {
			list_move_tail(r_pool_buf->busy_list.next,
				       &r_pool_buf->free_list);
		}
		r_pool_buf->num_free_buf = 0;
		raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
#ifdef LOOP_MODE
		if (rdma_link->mode_loop == DISABLE_LOOP) {
#endif
		/*
		 * Send READY_DMA
		 */
		sending_msg = MSG_READY_DMA | r_pool_buf->num_free_buf;
		if ((ret_smsg = send_msg_check(sending_msg, link, 0,
		     dev_sem, 0)) <= 0) {
			     fix_event(link, READ_SNDMSGBAD_EVENT,
				       sending_msg, dev_sem->num_obmen);
		} else {
			     fix_event(link, READ_SNDNGMSG_EVENT,
				       sending_msg, dev_sem->num_obmen);
		}
#ifdef LOOP_MODE
		} else {
			rdma_pool_buf_t *w_pool_buf;
			rw_state_p pd_wr;
			dev_rdma_sem_t *dev_sem_wr;
			unsigned long flags_wr;
			
			w_pool_buf = &rdma_link->write_pool;
			pd_wr = &rdma_link->rw_states_d[WRITER];
			dev_sem_wr = &pd_wr->dev_rdma_sem;
			raw_spin_lock_irqsave(&dev_sem_wr->lock, flags_wr);
			pd_wr->trwd_was = r_pool_buf->num_free_buf;
			raw_spin_unlock_irqrestore(&dev_sem_wr->lock, flags_wr);
		}
#endif
	} else {
		/*
		 * File open as WRITER
		 */
		rdma_pool_buf_t	*w_pool_buf;
		unsigned int	ret_wait_tdc;
		int	count_wait_tdc = TX_RX_WAIT_DMA;
		
		w_pool_buf = &rdma_link->write_pool;
		/* 
		 * Sender wait dma
		 */
		while (count_wait_tdc--)
		{	
			ret_wait_tdc = RDR_rdma(SHIFT_DMA_TCS, link);
			if (!(ret_wait_tdc & DMA_TCS_TE)) {
				     goto end_wait_tdc;
			}
		}
		ERROR_MSG("%s: link %d ret_wait_tdc: 0x%08x "
			  "count_wait_tdc: %d\n",
			  __FUNCTION__, link, ret_wait_tdc, count_wait_tdc);
end_wait_tdc:
		raw_spin_lock_irqsave(&pd->lock_wr, flags_w);
		/*
		 * The release of buffers
		*/
		while (!list_empty(&w_pool_buf->ready_list)) {
			list_move_tail(w_pool_buf->ready_list.next,
		       &w_pool_buf->free_list);
		}
		while (!list_empty(&w_pool_buf->busy_list)) {
			list_move_tail(w_pool_buf->busy_list.next,
				       &w_pool_buf->free_list);
		}
		raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
	}
	pd->state_open_close = 0;
	raw_spin_unlock_irq(&dev_sem->lock);
	RDMA_CLOSE_DEBUG_MSG("%s: FINISH\n", __FUNCTION__);
	return 0;
}

#define RDMA_OPEN_DBG 0
#define RDMA_OPEN_DEBUG_MSG(x...)\
		if (RDMA_OPEN_DBG) DEBUG_MSG(x)
static int rdma_open(struct inode *inode, struct file *file)
{
	rdma_state_link_t *rdma_link;
	rw_state_t *rdma_private_data;
	dev_rdma_sem_t *dev_sem;
	rw_state_p pd;
	unsigned long flags_w, flags_r;
	int minor, file_eys = 0, i, file_open_mode;
	int link;
	int firstopen = 0;
	
	/*
         * Cleanup: make over rdma_private_data.
	 */
	RDMA_OPEN_DEBUG_MSG("%s: START\n",  __FUNCTION__);
	if (file == (struct file *)NULL) {
		ERROR_MSG("%s: file is NULL\n", __FUNCTION__);
		return (-EINVAL);
	}
 	minor = MINOR(inode->i_rdev);
	if (minor < 0) {
		ERROR_MSG("%s: minor(%d) < 0\n", __FUNCTION__, minor);
		return (-EINVAL);
	}
	link = DEV_inst(minor);
	if (HAS_MACHINE_L_SIC) {
		/*_RDMA_for_each_online_rdma(i)*/
		_RDMA_for_each_rdma(i)
			if (i == link)
				file_eys++;
	} else {
		if (0 == link)
			file_eys++;
	}
	if (!file_eys) {
		ERROR_MSG("%s: link %d not support RDMA\n", __FUNCTION__,
			  link);
		return (-EINVAL);
	}
	file->private_data = NULL;
	rdma_link = &rdma_state->rdma_link[link];
	/*
	 * File open mode.
	 */
	file_open_mode = minor % 2;
	rdma_private_data = &rdma_link->rw_states_d[file_open_mode];
	rdma_private_data->open_mode = file_open_mode;
	RDMA_OPEN_DEBUG_MSG("%s: mode open %s (minor: %x)\n",
			    __FUNCTION__, file_open_mode ? "WRITE" : "READ",
			    minor);
	rdma_private_data->link = link;
	file->private_data = rdma_private_data;
	mutex_enter(&rdma_link->mu);
	firstopen =
		(((1 << rdma_private_data->open_mode) & rdma_link->opened) == 0);
	if (firstopen == 0) {
		ERROR_MSG("%s: device EBUSY: minor: %d link: %d channel: %d\n", 
			  __FUNCTION__, minor, link, rdma_private_data->open_mode);
		mutex_exit(&rdma_link->mu);
		return (-EBUSY);
	}
	rdma_link->opened |= (1 << rdma_private_data->open_mode);
	RDMA_OPEN_DEBUG_MSG("%s: opened.minor.link.channel: 0x%x.%d.%d.%d\n",
			    __FUNCTION__, rdma_link->opened, minor, link,
			    rdma_private_data->open_mode);
	mutex_exit(&rdma_link->mu);
	pd = &rdma_link->rw_states_d[file_open_mode];
	dev_sem = &pd->dev_rdma_sem;
	raw_spin_lock_irq(&dev_sem->lock);
	pd->state_open_close = 1;
	/*
	 * File opened as READER
	 */
	if (!file_open_mode) {
		rdma_pool_buf_t	*r_pool_buf;
		unsigned int sending_msg;
		unsigned int ret_smsg, ret_wait_rdc;
		int count_wait_rdc = TX_RX_WAIT_DMA;
		
		pd->first_open++;
		r_pool_buf = &rdma_link->read_pool;
		raw_spin_lock_irqsave(&pd->lock_rd, flags_r);
		r_pool_buf->num_free_buf = num_buf;
		/*
		 * The release of buffers
		 */
		while (!list_empty(&r_pool_buf->ready_list)) {
			list_move_tail(r_pool_buf->ready_list.next, 
				       &r_pool_buf->free_list);
		}
		while (!list_empty(&r_pool_buf->busy_list)) {
			list_move_tail(r_pool_buf->busy_list.next, 
				       &r_pool_buf->free_list);
		}
		raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
		/*
		 * Waiting for the end of the last dma
		 */
		while (count_wait_rdc --)
		{	
			ret_wait_rdc = RDR_rdma(SHIFT_DMA_RCS, link);
			if (!(ret_wait_rdc & DMA_RCS_RE)) {
#ifdef LOOP_MODE
				if (rdma_link->mode_loop == DISABLE_LOOP) {
#endif
					/*
				 	 * Create MSG_READY_DMA 
				 	 */
					sending_msg = MSG_READY_DMA |
						r_pool_buf->num_free_buf;
					/*
				 	 * Send MSG_READY_DMA
					 */
					if ((ret_smsg =
						send_msg_check(sending_msg,
						link, 0, dev_sem, 0)) <= 0) {
						fix_event(link,
							  READ_SNDMSGBAD_EVENT,
							  sending_msg,
							  dev_sem->num_obmen);
					} else {
						fix_event(link,
							  READ_SNDNGMSG_EVENT,
							  sending_msg,
							  dev_sem->num_obmen);
					}
#ifdef LOOP_MODE
				} else {
					rdma_pool_buf_t *w_pool_buf;
					rw_state_p pd_wr;
					dev_rdma_sem_t *dev_sem_wr;
					unsigned long flags_wr;
					
					w_pool_buf = &rdma_link->write_pool;
					pd_wr = &rdma_link->rw_states_d[WRITER];
					dev_sem_wr = &pd_wr->dev_rdma_sem;
					RDMA_OPEN_DEBUG_MSG("%s: "
						"rdma_link->mode_loop: 0x%x "
						"pd->trwd_was:%x pd->int_ac:%x\n",
						__FUNCTION__,
						rdma_link->mode_loop,
						pd_wr->trwd_was, pd_wr->int_ac);
					raw_spin_lock_irqsave(&dev_sem_wr->lock, flags_wr);
					pd_wr->trwd_was =
							r_pool_buf->num_free_buf;
					/*
					 * If hes free buf's reciver
					 */
					
					if (pd_wr->trwd_was) {
						switch (pd_wr->int_ac) {
						case 1:
						/*
						 * Wake up write
						 */
							rdma_cv_broadcast_rdma(
								&pd_wr->dev_rdma_sem,
								link);
								break;
							default:
								break;
						}
					} 
					raw_spin_unlock_irqrestore(&dev_sem_wr->lock, flags_wr);
					RDMA_OPEN_DEBUG_MSG("%s: "
						"rdma_link->mode_loop: 0x%x "
						"pd->trwd_was:%x pd->int_ac:%x\n",
						__FUNCTION__,
						rdma_link->mode_loop,
						pd_wr->trwd_was, pd_wr->int_ac);
				}
#endif
				goto end_wait_rdc;
			}
		}
		/*
		 * Error ???
		 */
		ERROR_MSG("%s: link %d ret_wait_rdc: 0x%08x "
			  "count_wait_rdc: %d\n",
			  __FUNCTION__, link, ret_wait_rdc, count_wait_rdc);
end_wait_rdc:;
	} else {
		/*
		 * File opened as WRITER
		 */
		rdma_pool_buf_t *w_pool_buf;
		unsigned int ret_wait_tdc;
		int count_wait_tdc = TX_RX_WAIT_DMA;
		
		w_pool_buf = &rdma_link->write_pool;
		/*
		 * The release of buffers
		 */
		raw_spin_lock_irqsave(&pd->lock_wr, flags_w);
		while (!list_empty(&w_pool_buf->ready_list)) {
			list_move_tail(w_pool_buf->ready_list.next,
				       &w_pool_buf->free_list);
		}
		while (!list_empty(&w_pool_buf->busy_list)) {
			list_move_tail(w_pool_buf->busy_list.next,
				       &w_pool_buf->free_list);
		}
		raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
		/*
		 * Waiting for the end of the last dma
		 */
		while (count_wait_tdc --)
		{
			ret_wait_tdc = RDR_rdma(SHIFT_DMA_TCS, link);
			if (!(ret_wait_tdc & DMA_TCS_TE)) {
				goto end_wait_tdc;
			}
		}
		/*
		 * Error ???
		 */
		ERROR_MSG("%s: link %d ret_wait_tdc: 0x%08x "
			  "count_wait_tdc: %d\n",
			  __FUNCTION__, link, ret_wait_tdc, count_wait_tdc);
end_wait_tdc:;
	}
	raw_spin_unlock_irq(&dev_sem->lock);
	RDMA_OPEN_DEBUG_MSG("%s: FINISH\n", __FUNCTION__);
	return 0;
}

#define RDMA_READ_DBG 0
#define RDMA_READ_DEBUG_MSG(x...)\
		if (RDMA_READ_DBG) DEBUG_MSG(x)
static ssize_t rdma_read(struct file *filp, char __user *buf, size_t size,
			 loff_t *pos)
{
	RDMA_READ_DEBUG_MSG("%s: read call is not supported!", __FUNCTION__);
	return 0;
}

#define RDMA_WRITE_DBG 0
#define RDMA_WRITE_DEBUG_MSG(x...)\
		if (RDMA_WRITE_DBG) DEBUG_MSG(x)
static ssize_t rdma_write(struct file *filp, const char __user *buf,
			  size_t size, loff_t *pos)
{
	RDMA_READ_DEBUG_MSG("%s: write call is not supported!", __FUNCTION__);
	return 0;
}

#define RDMA_IOCTL_DBG 0
#define RDMA_IOCTL_DEBUG_MSG(x...)\
		if (RDMA_IOCTL_DBG) DEBUG_MSG(x)
#define IOC_SUCCESFULL 0
static long rdma_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	rdma_state_link_t *rdma_link;
	rdma_ioc_parm_t	parm;
	dev_rdma_sem_t *dev_sem;
	rw_state_t *rdma_private_data;
	rw_state_p pd;
	size_t rval;
	unsigned long flags_w, flags_r;
	unsigned int open_mode;
	int ret = IOC_SUCCESFULL;
	int minor;
	int link;
	int res = 0;
	
	minor = get_file_minor(filp);
	if (minor < 0) {
		ERROR_MSG("%s: minor(%d) < 0 cmd: 0x%08x\n", __FUNCTION__,
			  (int)minor, cmd);
		return minor;
	}
	link = DEV_inst(minor);
	RDMA_IOCTL_DEBUG_MSG("%s: link: %d cmd: 0x%08x. START\n", __FUNCTION__,
			     link, cmd);
	rdma_link = &rdma_state->rdma_link[link];
	rval = copy_from_user(&parm, (void __user *)arg,
			       sizeof (rdma_ioc_parm_t));
	if (rval) {
		ERROR_MSG("%s: link: %d cmd: 0x%08x. Copy_from_user failed.\n",
			  __FUNCTION__, link, cmd);
		ret = -EINVAL;
	}
	RDMA_IOCTL_DEBUG_MSG("%s: in :\n"
			     "	parm.reqlen: 0x%08x\n"
			     "	parm.acclen: 0x%08x\n"
			     "	parm.err_no: 0x%08x\n"
			     "	parm.rwmode: 0x%08x\n"
			     "	parm.msg   : 0x%08x\n"
			     "	parm.clkr  : %llx\n"
			     "	parm.clkr1 : %llx\n", 
			     __FUNCTION__, parm.reqlen,
			     parm.acclen, parm.err_no, parm.rwmode, parm.msg,
			     parm.clkr, parm.clkr1);
	rdma_private_data = filp->private_data;
	open_mode = rdma_private_data->open_mode;
	parm.err_no = res = 0;
	
	switch (cmd) {
	case RDMA_IOC_GET_neighbour_map:
	{
		if (copy_to_user((void __user *)arg, &node_online_neighbour_map,
		    sizeof (nodemask_t))) {
			ERROR_MSG("%s: link %d cmd: RDMA_IOC_GET_neighbour_map "
				  "copy_to_user failed\n", __FUNCTION__, link);
			return -EINVAL;
		}
		return 0;
		break;
	}
	
	case RDMA_IOC_GET_ID:
	{
		int i;
		rdma_link_id.count_links = MAX_NUMIOLINKS;
		if (HAS_MACHINE_L_SIC) {
			_RDMA_for_each_online_rdma(i) {
				rdma_link_id.link_id[i][0] = 1;
				rdma_link_id.link_id[i][1] = 
						RDR_rdma(SHIFT_CH_IDT, i);
				rdma_link_id.link_id[i][2] = 
						RDR_rdma(SHIFT_N_IDT, i);
			}
		} else {
			i = 0;
			rdma_link_id.link_id[i][0] = 1;
			rdma_link_id.link_id[i][1] = RDR_rdma(SHIFT_CH_IDT, i);
			rdma_link_id.link_id[i][2] = RDR_rdma(SHIFT_N_IDT, i);
		}
		if (copy_to_user((void __user *)arg, &rdma_link_id,
		    sizeof(link_id_t)) == -1) {
			ERROR_MSG("%s:RDMA_IOC_GET_ID: copy_to_user failed\n", 
				  __FUNCTION__);
			return EINVAL;
		}
		return 0;
		break;
	}
	
	case RDMA_SET_ATL:
	{
		unsigned int atl;

		tr_atl = ATL_B | (parm.reqlen & ATL);
		WRR_rdma(SHIFT_CAM, link, tr_atl);
		atl = RDR_rdma(SHIFT_CAM, link);
		parm.acclen = atl;
		break;
	}
		
	case RDMA_IOC_GET_BUF_NUM:
	{
		parm.acclen = num_buf;
		ret = IOC_SUCCESFULL;
		break;
	}
		
	case RDMA_IOC_GET_BUF_SIZE:
	{
		parm.acclen = buf_size;
		ret = IOC_SUCCESFULL;
		break;
	}

	case RDMA_IOC_SET_MODE_RFSM:
	{
		if (parm.reqlen == DISABLE_RFSM) {
			rfsm = CLEAR_RFSM;
		} else {
			rfsm = DMA_RCS_RFSM;
		}
		parm.acclen = rfsm;
		break;
	}
	case RDMA_IOC_SET_MODE_LOOP:
	{
#ifdef LOOP_MODE
		if (IS_MACHINE_E2S) {
			if (parm.reqlen == DISABLE_LOOP) {
				rdma_link->mode_loop = DISABLE_LOOP;
				WRR_rdma(SHIFT_CS, link,
					 RDR_rdma(SHIFT_CS, link) &
					 (~E2S_CS_LOOP));
			} else {
				rdma_link->mode_loop = ENABLE_LOOP;
				WRR_rdma(SHIFT_CS, link,
					 RDR_rdma(SHIFT_CS, link) |
					 E2S_CS_LOOP);
			}
			parm.acclen = rdma_link->mode_loop;
		} else
#endif
			parm.acclen = NOT_SUPPORTED_LOOP;
		break;
	}
	case RDMA_IOC_GET_WR_BUF:
	{
		rdma_pool_buf_t *w_pool_buf;
		rdma_buf_t *w_buf;
		
		if (open_mode == READER) {
			ERROR_MSG("%s: link: %d cmd: RDMA_IOC_GET_WR_BUF. "
				  "File open as READER.\n", __FUNCTION__, link);
			ret = -EBADF;
			break;
		}
		w_pool_buf = &rdma_link->write_pool;
		pd = &rdma_link->rw_states_d[WRITER];
		/*
		 * Search free buffer to write
		 */
		raw_spin_lock_irqsave(&pd->lock_wr, flags_w);
		if (list_empty(&w_pool_buf->free_list)) {
			raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_GET_WR_BUF(0x%08x). "
				  "Search free for write buf failed.\n",
     				  __FUNCTION__, link, cmd);
			ret = -EBUSY;
			break;
		}
		w_buf = list_entry(w_pool_buf->free_list.next, rdma_buf_t,
				   list);
		list_move_tail(&w_buf->list, &w_pool_buf->ready_list);
		raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
		parm.acclen = w_buf->num;
		ret = IOC_SUCCESFULL;
		break;
	}
	
	case RDMA_IOC_WR_BUF:
	{
		rdma_pool_buf_t *w_pool_buf;
		rdma_buf_t *w_buf; 

		if (open_mode == READER) {
			ERROR_MSG("%s: link: %d cmd: RDMA_IOC_WR_BUF(0x%08x). "
				  "File open as READER.\n", __FUNCTION__, link, cmd);
			ret = -EBADF;
			break;
		}
		w_pool_buf = &rdma_link->write_pool;
		pd = &rdma_link->rw_states_d[WRITER];
		/*
		 * Find user buffer
		 */
		raw_spin_lock_irqsave(&pd->lock_wr, flags_w);
		w_buf = search_in_list(&w_pool_buf->ready_list, parm.acclen);
		if (w_buf == NULL) {
			raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
			ERROR_MSG("%s: link: %d cmd: RDMA_IOC_WR_BUF(0x%08x). "
				  "Cant find buf.\n", __FUNCTION__, link, cmd);
			parm.err_no = RDMA_E_BAD_BUFFER;
			/*ret = -EAGAIN;*/
			ret = -EFAULT;
			break;
		}
        	/*
		 * Mark this buf as busy and place in the end of queue
		 */
		list_move_tail(&w_buf->list, &w_pool_buf->busy_list);
		w_pool_buf->work_buf = w_buf;
		raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
		/*
		 * Call write function's
		 */
		ret = write_buf(link, &parm, filp->f_flags);
#if 0		
		// Move ioctl RDMA_IOC_PUT_WR_BUF
		// /*
		//  * Remove buf from busy and move free list
		//  */
		// raw_spin_lock_irqsave(&pd->lock_wr, flags_w);
		// list_move_tail(&w_buf->list, &w_pool_buf->free_list);
		// w_pool_buf->work_buf = NULL;
		// raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
#endif		
		break;
	}

	case RDMA_IOC_PUT_WR_BUF:
	{
		rdma_pool_buf_t *w_pool_buf;
		rdma_buf_t *w_buf; 
		
		if (open_mode == READER) {
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_PUT_WR_BUF(0x%08x). "
				  "File open as READER.\n", __FUNCTION__,
				  link, cmd);
			ret = -EBADF;
			break;
		}
		if ( parm.acclen < 0 || parm.acclen > num_buf ) {
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_PUT_WR_BUF(0x%08x). "
				  "Wrong num buf: 0x%08x.\n", __FUNCTION__,
				  link, cmd, parm.acclen);
			ret = -ERANGE;
			break;
		}
		w_pool_buf = &rdma_link->write_pool;
		pd = &rdma_link->rw_states_d[WRITER];
		/*
		 * Remove buf from busy and move free list
		 */
		raw_spin_lock_irqsave(&pd->lock_wr, flags_w);
		w_buf = search_in_list(&w_pool_buf->busy_list, parm.acclen);
		if (w_buf == NULL) {
			raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_PUT_WR_BUF(0x%08x). "
				  "Cant find buf.\n", __FUNCTION__, link, cmd);
			ret = -EFAULT;
			break;
		}		
		list_move_tail(&w_buf->list, &w_pool_buf->free_list);
		w_pool_buf->work_buf = NULL;
		raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
		ret = IOC_SUCCESFULL;
		break;
	}
		
	case RDMA_IOC_GET_RD_BUF:
	{
#if 0		
		INFO_MSG("%s: Ioctl RDMA_IOC_GET_RD_BUF not implementation.\n",
			 __FUNCTION__);
		ret = -EINVAL;
		break; 
#endif		
		rdma_pool_buf_t *r_pool_buf;
		rdma_buf_t *r_buf; 
		
		if (open_mode == WRITER) {
			ERROR_MSG("%s: link: %d cmd: RDMA_IOC_GET_RD_BUF. "
					"File open as WRITER.\n", __FUNCTION__,
					link);
			ret = -EBADF;
			break;
		}
		r_pool_buf = &rdma_link->read_pool;
		pd = &rdma_link->rw_states_d[READER];
		/*
		* Search free buffer to write
		*/
		raw_spin_lock_irqsave(&pd->lock_rd, flags_r);
		if (list_empty(&r_pool_buf->free_list)) {
			raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
			ERROR_MSG("%s: link: %d "
					"cmd: RDMA_IOC_GET_RD_BUF(0x%08x). "
					"Search free for read buf failed.\n",
					__FUNCTION__, link, cmd);
			ret = -EBUSY;
			break;
		}
		r_buf = list_entry(r_pool_buf->free_list.next, rdma_buf_t,
				   list);
		list_move_tail(&r_buf->list, &r_pool_buf->ready_list);
		raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
		parm.acclen = r_buf->num;
		ret = IOC_SUCCESFULL;
		break;
		
	}
	
	case RDMA_IOC_RD_BUF:
	{
		rdma_pool_buf_t *r_pool_buf;
		rdma_buf_t *r_buf; 
				
		if (open_mode == WRITER) {
			ERROR_MSG("%s: link: %d cmd: RDMA_IOC_RD_BUF(0x%08x). "
				  "File open as WRITER.", __FUNCTION__,
				  link, cmd);
			ret = -EBADF;
			break;
		}
		r_pool_buf = &rdma_link->read_pool;
		pd = &rdma_link->rw_states_d[READER];
		dev_sem = &pd->dev_rdma_sem;
		/*
		 * Call read function's
		 */
		ret = read_buf(link, &parm, filp->f_flags);
		if ( ret < 0)  {
			ERROR_MSG("%s: link: %d cmd: RDMA_IOC_RD_BUF(0x%08x). "
				  "Error read_buf.\n", __FUNCTION__, link, cmd);
			parm.acclen = -1;
			/*ret = -EAGAIN;*/
			break;
		}
		/*
		 * Time for reserve
		 */
		parm.clkr = join_curr_clock();
		/*
		 * Find user buffer
		 */
		raw_spin_lock_irqsave(&pd->lock_rd, flags_r);
		/*r_buf = list_entry(r_pool_buf->ready_list.next, rdma_buf_t, list);*/
		r_buf = list_entry(r_pool_buf->busy_list.next, rdma_buf_t, list);
		raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
		if (r_buf == NULL) {
			ERROR_MSG("%s: link: %d cmd: RDMA_IOC_RD_BUF(0x%08x). "
				  "Cant find buf. \n", __FUNCTION__, link, cmd);
			event_ioctl(link, READ_BAD2_EVENT, 0,
				   dev_sem->num_obmen);
			parm.acclen = -1;
			parm.err_no = RDMA_E_BAD_BUFFER;
			ret = -EFAULT;
			break;
		}
		if ( r_buf->num < 0 || r_buf->num > num_buf ) {
			ERROR_MSG("%s: link: %d cmd: RDMA_IOC_RD_BUF(0x%08x). "
				  "Wrong num buf: %d.\n", __FUNCTION__,
     				  link, cmd, r_buf->num);
			event_ioctl(link, READ_BAD3_EVENT, r_buf->num,
				   dev_sem->num_obmen);
			parm.acclen = r_buf->num;
			parm.err_no = RDMA_E_BAD_BUFFER;
			ret = -ERANGE;
			break;
		}
		parm.acclen = r_buf->num;
		/*
		 * Cleanup: join rfsm_size & r_buf->real_size.
		 */
		if (rfsm)
			parm.reqlen = r_buf->rfsm_size;
		else
			parm.reqlen = r_buf->real_size;
		break;
	}
	
	case RDMA_IOC_PUT_RD_BUF:
	{
		rdma_pool_buf_t *r_pool_buf;
		rdma_buf_t *r_buf;
		unsigned int sending_msg;
		int ret_smsg;

		if (open_mode == WRITER) {
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_PUT_RD_BUF(0x%08x). "
				  "File open as WRITER.", __FUNCTION__,
     				  link, cmd);
			ret = -EBADF;
			break;
		}
		if ( parm.acclen < 0 || parm.acclen > num_buf ) {
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_PUT_RD_BUF(0x%08x). "
				  "Wrong num buf: 0x%08x.\n", __FUNCTION__,
				  link, cmd, parm.acclen);
			ret = -ERANGE;
			break;
		}
		r_pool_buf = &rdma_link->read_pool;
		pd = &rdma_link->rw_states_d[READER];
		/*
		 * Find user buffer
		 */
		raw_spin_lock_irqsave(&pd->lock_rd, flags_r);
		r_buf = search_in_list(&r_pool_buf->busy_list, parm.acclen);
		if (r_buf == NULL) {
			raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_PUT_RD_BUF(0x%08x). "
				  "Cant find buf.\n", __FUNCTION__, link, cmd);
			ret = -EFAULT;
			break;
		}
        	/*
		 * Mark this buf as free and place in the end of queue
		 */
		list_move_tail(&r_buf->list, &r_pool_buf->free_list);
		if (!r_pool_buf->num_free_buf) {
			r_pool_buf->num_free_buf++;
#ifdef LOOP_MODE
			if (rdma_link->mode_loop == DISABLE_LOOP) {
#endif
				/*
			 	 * Create MSG_READY_DMA 
				 */
				sending_msg = MSG_READY_DMA |
						r_pool_buf->num_free_buf;
				/*
				 * Send READY_DMA
				 */
				if ((ret_smsg = send_msg_check(sending_msg,
				     link, 0, 0, 0)) <= 0) {
					fix_event(link, READ_SNDMSGBAD_EVENT,
						  ret_smsg,
						  r_pool_buf->num_free_buf);
				} else {
					fix_event(link, READ_SNDNGMSG_EVENT,
						  ret_smsg,
						  r_pool_buf->num_free_buf);
				}
#ifdef LOOP_MODE
			} else {
				rdma_pool_buf_t *w_pool_buf;
				w_pool_buf = &rdma_link->write_pool;
				rw_state_p pd_wr;
				dev_rdma_sem_t *dev_sem_wr;
				unsigned long flags_wr;
				
				pd_wr = &rdma_link->rw_states_d[WRITER];
				dev_sem_wr = &pd_wr->dev_rdma_sem;
				RDMA_OPEN_DEBUG_MSG("%s: "
					"rdma_link->mode_loop: 0x%x "
					"pd->trwd_was:%x pd->int_ac:%x\n",
					__FUNCTION__, rdma_link->mode_loop,
					pd_wr->trwd_was, pd_wr->int_ac);
				
				raw_spin_lock_irqsave(&dev_sem_wr->lock, flags_wr);
				pd_wr->trwd_was = r_pool_buf->num_free_buf;
				/*
				* If hes free buf's reciver
				*/
				if (pd_wr->trwd_was) {
					switch (pd_wr->int_ac) {
					case 1:
					/*
					 * Wake up write
					 */
					rdma_cv_broadcast_rdma(&pd_wr->dev_rdma_sem,
							       link);
							break;
					default:
						break;
					}
				}
				raw_spin_unlock_irqrestore(&dev_sem_wr->lock, 
							   flags_wr);
				RDMA_OPEN_DEBUG_MSG("%s: "
					"rdma_link->mode_loop: 0x%x "
					"pd->trwd_was:%x pd->int_ac:%x\n",
					__FUNCTION__, rdma_link->mode_loop,
					pd_wr->trwd_was, pd_wr->int_ac);
			}
#endif
		} else {
			r_pool_buf->num_free_buf++;
#ifdef LOOP_MODE
			if (rdma_link->mode_loop == ENABLE_LOOP) {
				rdma_pool_buf_t *w_pool_buf;
				rw_state_p pd_wr;
				dev_rdma_sem_t *dev_sem_wr;
				unsigned long flags_wr;
				rdma_buf_t *w_buf; 
				
				w_pool_buf = &rdma_link->write_pool;
				w_buf = w_pool_buf->work_buf;
				pd_wr = &rdma_link->rw_states_d[WRITER];
				dev_sem_wr = &pd_wr->dev_rdma_sem;
				raw_spin_lock_irqsave(&dev_sem_wr->lock, flags_wr);
				pd_wr->trwd_was = r_pool_buf->num_free_buf;
				raw_spin_unlock_irqrestore(&dev_sem_wr->lock, flags_wr);
				RDMA_OPEN_DEBUG_MSG("%s: "
					"rdma_link->mode_loop: 0x%x "
					"pd->trwd_was:%x pd->int_ac:%x\n",
					__FUNCTION__, rdma_link->mode_loop,
					pd_wr->trwd_was, pd_wr->int_ac);
				
			}
#endif
		}
		raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
		ret = IOC_SUCCESFULL;
		break;
	}
	
	case RDMA_IOC_SET_TIMEOUT_RD:
	{
		if (open_mode == WRITER) {
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_SET_TIMEOUT_RD(0x%08x). "
				  "File open as READER.\n", __FUNCTION__,
				  link, cmd);
			ret = -EBADF;
			break;
		}
		pd = &rdma_link->rw_states_d[READER];
		dev_sem = &pd->dev_rdma_sem;
		dev_sem->timeout = parm.reqlen;
		parm.acclen = dev_sem->timeout;
		ret = IOC_SUCCESFULL;
		break;
	}
	
	case RDMA_IOC_SET_TIMEOUT_WR:
	{
		if (open_mode == READER) {
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_SET_TIMEOUT_WR(0x%08x). "
				  "File open as READER.\n", __FUNCTION__,
				  link, cmd);
			ret = -EBADF;
			break;
		}
		pd = &rdma_link->rw_states_d[WRITER];
		dev_sem = &pd->dev_rdma_sem;
		dev_sem->timeout = parm.reqlen;
		parm.acclen = dev_sem->timeout;
		ret = IOC_SUCCESFULL;
		break;
	}
		
	case RDMA_SET_STAT:
	{
		memset(&rdma_link->stat_rdma, 0, sizeof (struct stat_rdma));
		parm.acclen = 0;
		ret = IOC_SUCCESFULL;
		break;
	}
#if 1	
	case RDMA_IS_CAM_YES :
	{
		unsigned int atl;
		int ret_time_dwait = 0;
		dev_rdma_sem_t *dev_sem;
		rw_state_p pcam;

		event_ioctl(link, RDMA_IS_CAM_YES_EVENT, 1, 0);
		pcam = &rdma_link->ralive;
		dev_sem = &pcam->dev_rdma_sem;
		ret_time_dwait = 0;
		atl = RDR_rdma(SHIFT_CAM, link);
		if (atl) {
			parm.acclen = atl;
			parm.err_no = 0;
			goto end_RDMA_IS_CAM_YES;
		}
		/*raw_spin_lock_irqsave(&dev_sem->lock, flags);*/
		raw_spin_lock_irq(&dev_sem->lock);
		dev_sem->irq_count_rdma = 0;
		pcam->stat = 1;
		ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, IO_TIMEOUT,
						       link);
		pcam->stat = 0;
		raw_spin_unlock_irq(&dev_sem->lock);
		parm.acclen = RDR_rdma(SHIFT_CAM, link);
		if (ret_time_dwait == -2) {
			parm.err_no = -RDMA_E_SIGNAL;
		} else
			if (ret_time_dwait == -1) {
				parm.err_no = -RDMA_E_TIMER;
			} else
				if (ret_time_dwait > 0) {
					parm.err_no = ret_time_dwait;
				} else
					parm.err_no = 0;
end_RDMA_IS_CAM_YES:
		event_ioctl(0, RDMA_IS_CAM_YES_EVENT, 0, 0);
		break;
	}
	case RDMA_IS_CAM_NO:
	{
		unsigned int atl;
		int ret_time_dwait = 0;
		dev_rdma_sem_t *dev_sem;
		rw_state_p pcam;

		event_ioctl(link, RDMA_IS_CAM_NO_EVENT, 1, 0);
		pcam = &rdma_link->talive;
		dev_sem = &pcam->dev_rdma_sem;
		atl = RDR_rdma(SHIFT_CAM, link);
		if (!atl) {
			parm.acclen = 0;
			parm.err_no = 0;
			goto end_RDMA_IS_CAM_NO;
		}
		raw_spin_lock_irq(&dev_sem->lock);
		dev_sem->irq_count_rdma = 0;
		pcam->stat = 1;
		ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, IO_TIMEOUT,
						       link);
		pcam->stat = 0;
		raw_spin_unlock_irq(&dev_sem->lock);
		parm.acclen = RDR_rdma(SHIFT_CAM, link);
		if (ret_time_dwait == -2) {
			parm.err_no = -RDMA_E_SIGNAL;
		} else
			if (ret_time_dwait == -1) {
				parm.err_no = -RDMA_E_TIMER;
			} else
				if (ret_time_dwait > 0) {
					parm.err_no = ret_time_dwait;
				} else
					parm.err_no = 0;
end_RDMA_IS_CAM_NO:
		parm.clkr = join_curr_clock();
		parm.clkr1 = pcam->clkr;
		parm.reqlen = pcam->int_cnt;
		}
		event_ioctl(0, RDMA_IS_CAM_NO_EVENT, 0, 0);
		break;
#endif
	default:
		ERROR_MSG("%s: link: %d unknown cmd: 0x%08x\n", __FUNCTION__,
			  link, cmd);
		ret = -EFAULT;
		break;
	}
	
	RDMA_IOCTL_DEBUG_MSG("%s: out	parm.reqlen: 0x%08x\n"
			     "	parm.acclen: 0x%08x\n"
			     "	parm.err_no: 0x%08x\n"
			     "	parm.rwmode: 0x%08x\n"
			     "	parm.msg: 0x%08x\n"
			     "	parm.clkr: %llx\n"
			     "	parm.clkr1: %llx\n", 
			     __FUNCTION__, parm.reqlen, parm.acclen,
			     parm.err_no, parm.rwmode, parm.msg, parm.clkr,
      			     parm.clkr1);
	rval = copy_to_user((rdma_ioc_parm_t __user *)arg, &parm,
			     sizeof (rdma_ioc_parm_t));
	if (rval) {
		ERROR_MSG("%s: link: %d cmd: 0x%08x copy_to_user failed\n",
			  __FUNCTION__, link, cmd);
		ret = -EINVAL;
	}
	RDMA_IOCTL_DEBUG_MSG("%s: link: %d cmd: 0x%08x FINISH\n", __FUNCTION__,
			     link, cmd);
	return ret;
}

#ifdef CONFIG_COMPAT
static int do_ioctl(struct file *f, unsigned cmd, unsigned long arg)
{
	int ret;
	ret = rdma_ioctl(f, cmd, arg);
	/*ret = rdma_ioctl(f->f_dentry->d_inode, f, cmd, arg);*/
	return ret;
}

static long rdma_compat_ioctl(struct file *f, unsigned cmd, unsigned long arg)
{
	switch (cmd) {

	case RDMA_IOC_DUMPREG0:
	case RDMA_IOC_DUMPREG1:
	case RDMA_IOC_WRR:
	case RDMA_IOC_RDR:
	case RDMA_IOC_GET_neighbour_map:
	case RDMA_CLEAN_TDC_COUNT:
	case RDMA_GET_CLKR:
	case RDMA_GET_MAX_CLKR:
	case RDMA_CLEAN_RDC_COUNT:
	case RDMA_TIMER_FOR_READ :
	case RDMA_TIMER_FOR_WRITE:
	case RDMA_IOC_ALLOCB:
	case RDMA_GET_STAT:
	case RDMA_GET_EVENT:
	case RDMA_SET_STAT:
	case RDMA_SET_ATL:
	case RDMA_IS_CAM_YES:
	case RDMA_IS_CAM_NO:
	case RDMA_WAKEUP_WRITER:
	case RDMA_WAKEUP_READER:
	case RDMA_IOC_GET_ID:
	case RDMA_IOC_RESET_DMA:
	case RDMA_IOC_SET_MODE_RFSM:
	case RDMA_IOC_SET_MODE_EXIT_GP0:
	case RDMA_IOC_RESET_TCS:
	case RDMA_IOC_RESET_RCS:
	case RDMA_IOC_SET_MODE_LOOP:
	case RDMA_IOC_GET_BUF_NUM:
	case RDMA_IOC_GET_BUF_SIZE:
	case RDMA_IOC_RD_BUF:
	case RDMA_IOC_WR_BUF:
	case RDMA_IOC_GET_RD_BUF:
	case RDMA_IOC_GET_WR_BUF:
	case RDMA_IOC_PUT_RD_BUF:
	case RDMA_IOC_PUT_WR_BUF:
	case RDMA_IOC_SET_TIMEOUT_RD:
	case RDMA_IOC_SET_TIMEOUT_WR:
		return do_ioctl(f, cmd, arg);
	default:
		return -ENOIOCTLCMD;
	}
}
#endif

#define GET_FILE_MINOR_DBG 0
#define GET_FILE_MINOR_DEBUG_MSG(x...)\
		if (GET_FILE_MINOR_DBG) DEBUG_MSG(x)
int get_file_minor(struct file *file)
{
	int major;
	struct dentry *f_dentry_rdma;
	struct inode *d_inode;

	f_dentry_rdma = file->f_dentry;
	if (!f_dentry_rdma) {
		ERROR_MSG("get_file_minor: file->f_dentry is NULL\n");
		return -EBADF;
	}
	d_inode = f_dentry_rdma->d_inode;
	if (!d_inode) {
		ERROR_MSG("get_file_minor: f_dentry->d_inode is NULL\n");
		return -EBADF;
	}
	major = MAJOR(d_inode->i_rdev);
	GET_FILE_MINOR_DEBUG_MSG("get_file_minor:d_inode->i_rdev: 0x%08u "
				 "major: %d minor:%u\n", d_inode->i_rdev, major,
   				 MINOR(d_inode->i_rdev));
	return MINOR(d_inode->i_rdev);
}

#define RDMA_REMAP_DBG 0
#define RDMA_REMAP_DEBUG_MSG(x...)\
		if (RDMA_REMAP_DBG) DEBUG_MSG(x)
#define REMAP RDMA_REMAP_DEBUG_MSG
int rdma_remap_page(void *va, size_t sz, struct vm_area_struct *vma)
/*int rdma_remap_page(unsigned long pha, size_t sz, struct vm_area_struct *vma)*/
{
	unsigned long pha;
	unsigned long vm_end;
	unsigned long vm_start;
	unsigned long vm_pgoff;
	size_t size;

	REMAP("%s: START\n", __FUNCTION__);
	if (!sz) return -EINVAL;
	pha = virt_to_phys(va);
	size = (long )PAGE_ALIGN((pha & ~PAGE_MASK) + sz);
	if ((vma->vm_pgoff << PAGE_SHIFT) > size) return -ENXIO;
	pha += (vma->vm_pgoff << PAGE_SHIFT);
	vm_end = vma->vm_end;
	vm_start = vma->vm_start;
	vm_pgoff = vma->vm_pgoff;

	if ((vm_end - vm_start) < size)
		size = vm_end - vm_start;

	vma->vm_flags |= (VM_READ | VM_WRITE | VM_RESERVED);

#ifdef __e2k__
	if (vma->vm_flags & VM_IO)
		vma->vm_page_prot = __pgprot(pgprot_val(vma->vm_page_prot) |
				_PAGE_CD_DIS | _PAGE_PWT );
#endif
	if (remap_pfn_range(vma, vm_start, (pha >> PAGE_SHIFT), size,
	    vma->vm_page_prot)) {
		ERROR_MSG("%s: FAIL remap_pfn_range\n", __FUNCTION__);
		return -EAGAIN;
	}
	REMAP("%s: FINISH\n", __FUNCTION__);
	return 0;
}

#define RDMA_REMAP_T_DBG 0
#define RDMA_REMAP_T_DEBUG_MSG(x...)\
		if (RDMA_REMAP_T_DBG) DEBUG_MSG(x)
#define REMAP_T RDMA_REMAP_T_DEBUG_MSG
int rdma_remap_page_tbl(void *va, size_t sz, struct vm_area_struct *vma)
{
	rdma_tbl_64_struct_t *ptbl;
	unsigned long vm_start;
	unsigned long vm_pgoff;
	unsigned long sz_pha;
	unsigned long vm_end;
	unsigned long pha;
	size_t size;

	REMAP_T("%s: START size(sz): 0x%016lx\n", __FUNCTION__, sz);
	if (!sz) return -EINVAL;
	if (vma->vm_pgoff) {
		ERROR_MSG("%s: vma->vm_pgoff: 0x%lx\n", __FUNCTION__,
			  vma->vm_pgoff);
		return -EINVAL;
	}
	size = (long)PAGE_ALIGN(sz);
	vm_end = vma->vm_end;
	vm_start = vma->vm_start;
	vm_pgoff = vma->vm_pgoff;
	if ((vm_end - vm_start) < size) {
		size = vm_end - vm_start;
		REMAP_T("%s: vm_end(%lx) - vm_start(%lx) < size(%lx)\n",
			__FUNCTION__, vm_end, vm_start, size);
	}
	vma->vm_flags |= (VM_READ | VM_WRITE | VM_RESERVED);
#ifdef __e2k__
	if (vma->vm_flags & VM_IO)
		vma->vm_page_prot = __pgprot(pgprot_val(vma->vm_page_prot) |
					_PAGE_CD_DIS | _PAGE_PWT );
#endif
	for (ptbl = (rdma_tbl_64_struct_t *)va; ptbl; ptbl++) {
		rdma_addr_struct_t pxx;
		pxx.addr = (unsigned long)ptbl;
		REMAP_T("%s: 0x%08x%08x ptbl\n", __FUNCTION__, pxx.fields.haddr,
			pxx.fields.laddr);
		pxx.addr = ptbl->addr;
		REMAP_T("%s: 0x%08x%08x ptbl->addr\n", __FUNCTION__,
			pxx.fields.haddr, pxx.fields.laddr);
#ifdef CONFIG_E90S
		pha = (unsigned long)(cpu_to_le64(ptbl->addr));
		REMAP_T("%s: pha cpu_to_le64(pha): %lx \n",
			__FUNCTION__, pha);
#else /* E3S */
		pha = (unsigned long)ptbl->addr;
#endif
		pxx.addr = (unsigned long)phys_to_virt(pha);
		REMAP_T("%s: 0x%08x%08x __va(ptbl->addr)\n",
			__FUNCTION__, pxx.fields.haddr, pxx.fields.laddr);
		pxx.addr = pha;
		REMAP_T("%s: 0x%08x%08x __fa(ptbl->addr)\n",
			__FUNCTION__, pxx.fields.haddr, pxx.fields.laddr);
		sz_pha = ptbl->sz;
#ifdef CONFIG_E90S
		sz_pha = cpu_to_le64(sz_pha);
		REMAP_T("%s: sz_pha cpu_to_le64(sz_pha): %lx\n",
			__FUNCTION__, sz_pha);
#endif
		if (remap_pfn_range(vma, vm_start,(pha >> PAGE_SHIFT), sz_pha,
		    vma->vm_page_prot)) {
			ERROR_MSG("%s: FAIL remap_pfn_range\n", __FUNCTION__);
			return -EAGAIN;
		}
		vm_start += sz_pha;
		REMAP_T("%s: vm_start: %lx vm_end: %lx sz_pha: %lx \n",
			__FUNCTION__, vm_start, vm_end, sz_pha);
		if (vm_start >= vm_end) {
			REMAP_T("%s: vm_start(%lx) >= vm_end(%lx)\n",
				__FUNCTION__, vm_start, vm_end);
			break;
		}
	}
	REMAP_T("%s: FINISH\n", __FUNCTION__);
	return 0;
}

#define RDMA_MMAP_DBG 0
#define RDMA_MMAP_DEBUG_MSG(x...)\
		if (RDMA_MMAP_DBG) DEBUG_MSG(x)
static int rdma_mmap(struct file *file, struct vm_area_struct *vma)
{
	rdma_pool_buf_t *pool_buf;
	rdma_state_link_t *rdma_link;
	rw_state_t *rdma_private_data;
	int minor, rw;
	int link;
	int rval;

	RDMA_MMAP_DEBUG_MSG("%s: START\n", __FUNCTION__);
	minor = get_file_minor(file);
	/*minor = MINOR(inode->i_rdev);*/
	if (minor < 0)
		return minor;
	link = DEV_inst(minor);
	rdma_link = &rdma_state->rdma_link[link];
	rdma_private_data = file->private_data;
	rw = rdma_private_data->open_mode;
	rw ? (pool_buf = &rdma_link->write_pool) :
	     (pool_buf = &rdma_link->read_pool);
#if 0
	if (pool_buf->alloc != RDMA_BUF_ALLOCED) {
		ERROR_MSG("%s : pool_buf->alloc != RDMA_BUF_ALLOCED\n",
					  __FUNCTION__);
		return -EAGAIN;
	}
#endif
	if (pool_buf->tm_mode) {
		rval = rdma_remap_page_tbl((void *)pool_buf->vdma, 
					    pool_buf->dma_size,
					    vma);
	} else {
		//rval = rdma_remap_page((unsigned long)pool_buf->fdma, 
		rval = rdma_remap_page((void *)pool_buf->vdma,
					pool_buf->dma_size, vma);
	}
	if (rval) {
		ERROR_MSG("%s: FAIL\n", __FUNCTION__);
		return -EAGAIN;
	}
	pool_buf->alloc = RDMA_BUF_MMAP;
	RDMA_MMAP_DEBUG_MSG("%s: FINISH\n", __FUNCTION__);
	return 0;
}

unsigned long __get_free_pages_rdma(int node, gfp_t gfp_mask,
				    unsigned int order)
{
	struct page *page;

	page = alloc_pages_node(node, gfp_mask, order);
	if (!page)
		return (unsigned long)NULL;
	return (unsigned long) page_address(page);
}

#define RDMA_MEM_ALLOC_DBG 0
#define RDMA_MEM_ALLOC_DEBUG_MSG(x...)\
		if (RDMA_MEM_ALLOC_DBG) DEBUG_MSG(x)
int rdma_mem_alloc(int node, size_t size, dma_addr_t *mem, size_t *real_size,
		   unsigned long *dma_memory)
{
	struct page *map, *mapend;
	int order;

	RDMA_MEM_ALLOC_DEBUG_MSG("%s: START\n", __FUNCTION__);
	order = get_order(size);
#ifdef CONFIG_E2K
	if (IS_MACHINE_E3M)
		*dma_memory = __get_free_pages(GFP_KERNEL | GFP_DMA ,
					       order);
	else
#endif
		*dma_memory = __get_free_pages_rdma(node, GFP_KERNEL , order);
	if (!(*dma_memory)) {
		ERROR_MSG("%s: Cannot bind DMA address order: %d"
			  " size: 0x%lx\n", __FUNCTION__, order, size);
	      return -1;
	}
	mapend = virt_to_page((*dma_memory) + (PAGE_SIZE << order) - 1);
	for (map = virt_to_page((*dma_memory)); map <= mapend; map++)
		SetPageReserved(map);
#ifdef CONFIG_E2K 
	if (IS_MACHINE_E3M)
		*mem = pci_map_single((struct pci_dev *)rdma_state->dev_rdma,
				      (void *)*dma_memory, size,
				      PCI_DMA_FROMDEVICE);
	else
#endif		
		*mem = __pa(*dma_memory);
	
	*real_size = PAGE_SIZE << order;
	RDMA_MEM_ALLOC_DEBUG_MSG("%s: FINISH va: 0x%lx fa: 0x%llx size: 0x%lx "
				 "real_size: 0x%lx\n", __FUNCTION__,
				 *dma_memory, *mem, size, *real_size);
	return 0;
}

/*
 * Size table element SIZE_TLB_EL: 64 bit's addr and 64 bit's size
 */
#define RDMA_MEM_ALLOC_POOL_DBG 0
#define RDMA_MEM_ALLOC_POOL_DEBUG_MSG(x...)\
		if (RDMA_MEM_ALLOC_POOL_DBG) DEBUG_MSG(x)
int rdma_mem_alloc_pool(rdma_pool_buf_t *pool_buf)
{
	rdma_tbl_64_struct_t *peltbl;
	rdma_addr_struct_t pxx;
	size_t size_tm;
	char *err_msg = NULL;
	int SIZE_TLB, max_size, rest;
	
#define SIZE_TLB_EL 128
	RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: START \n", __FUNCTION__);
	if (tm_mode) {
		max_size = pool_buf->size;
		SIZE_TLB =
			((PAGE_ALIGN(max_size) / PAGE_SIZE + 1) * SIZE_TLB_EL);
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: table mode "
					      "PAGE_SIZE: 0x%016lx\n",
					      __FUNCTION__, PAGE_SIZE);
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: try alloc for tm size "
					      "SIZE_TLB : 0x%08x\n",
					      __FUNCTION__, SIZE_TLB);
		if (rdma_mem_alloc(pool_buf->node_for_memory, SIZE_TLB,
		    (dma_addr_t *)&pool_buf->fdma, &size_tm,
		    (unsigned long *)&pool_buf->vdma)) {
			err_msg = "rdma_mem_alloc for tm";
			goto failed;
		}
		pxx.addr = (unsigned long)pool_buf->vdma;
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: 0x%08x%08x virt_mem table\n",
					      __FUNCTION__, pxx.fields.haddr,
					      pxx.fields.laddr);
		pxx.addr = pool_buf->fdma;
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: 0x%08x%08x phys_mem table\n",
					      __FUNCTION__, pxx.fields.haddr,
					      pxx.fields.laddr);
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: size table: 0x%016lx \n",
					      __FUNCTION__, size_tm);
		pool_buf->size_tm = size_tm;
		rest = (int)pool_buf->size;
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: rest: 0x%08x "
					      "pool_buf->size: 0x%016lx\n",
					      __FUNCTION__, rest,
					      pool_buf->size);
		pool_buf->dma_size = 0;
		for (peltbl = (rdma_tbl_64_struct_t *)pool_buf->vdma; rest > 0;
			       peltbl++){
			size_t size_el;
			unsigned long addr;
			if (rdma_mem_alloc(pool_buf->node_for_memory,
			    	SIZE_EL_TBL64_RDMA,
				(dma_addr_t *)&peltbl->addr,
				&size_el, (unsigned long *)&addr)) {
				goto failed;
			}
			pxx.addr = (unsigned long)peltbl;
			RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: 0x%08x%08x peltbl\n",
						      __FUNCTION__,
						      pxx.fields.haddr,
	    					      pxx.fields.laddr);
#ifdef CONFIG_E90S
			peltbl->addr = le64_to_cpu(peltbl->addr);
#endif
			pxx.addr = peltbl->addr;
			RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: 0x%08x%08x "
						      "peltbl->addr\n",
					    	      __FUNCTION__,
						      pxx.fields.haddr,
	    					      pxx.fields.laddr);
			peltbl->sz = (unsigned long)size_el;
#ifdef CONFIG_E90S
			peltbl->sz = le64_to_cpu(peltbl->sz);
#endif
			rest -= size_el;
			pool_buf->dma_size += size_el;
		}
		peltbl->sz = 0;
	} else {
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: single mode "
					      "PAGE_SIZE: 0x%016lx\n",
				   	      __FUNCTION__, PAGE_SIZE);
#if 0		
		//if (pool_buf->size > num_buf * allign_dma(MAX_SIZE_BUFF)) {
		//	ERROR_MSG("%s: The large size of the buffer. "
		//			"The buffer must be <= 0x%08x.\n", 
		//			__FUNCTION__, MAX_SIZE_BUFF);
		//	goto failed;
		//}
#endif
		if (rdma_mem_alloc(pool_buf->node_for_memory, pool_buf->size,
		    (dma_addr_t *)&pool_buf->fdma, &pool_buf->dma_size,
		     (unsigned long *)&pool_buf->vdma)) {
			err_msg = "rdma_mem_alloc";
			goto failed;
		}
		pxx.addr = (unsigned long)pool_buf->vdma;
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: 0x%08x%08x virt_mem\n",
					      __FUNCTION__,
	   			pxx.fields.haddr, pxx.fields.laddr);
		pxx.addr = pool_buf->fdma;
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: 0x%08x%08x phys_mem\n",
					      __FUNCTION__, pxx.fields.haddr,
					      pxx.fields.laddr);
	}
	RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: FINISH buf real size: 0x%016lx\n",
				      __FUNCTION__, pool_buf->dma_size);
	return 0;

failed:
	ERROR_MSG("%s: %s FAILED ****\n", __FUNCTION__, err_msg);
	return (-1);
}

#define RDMA_MEM_FREE_DBG 0
#define RDMA_MEM_FREE_DEBUG_MSG(x...)\
		if (RDMA_MEM_FREE_DBG) DEBUG_MSG(x)
void rdma_mem_free(size_t size, dma_addr_t dev_memory,
		   unsigned long dma_memory)
{
	struct page *map, *mapend;
	caddr_t mem;
	int order;

	RDMA_MEM_FREE_DEBUG_MSG("%s: START\n", __FUNCTION__);
	mem = (caddr_t)dma_memory;
	order = get_order(size);
	mapend = virt_to_page(mem + (PAGE_SIZE << order) - 1);
	for (map = virt_to_page(mem); map <= mapend; map++)
		ClearPageReserved(map);
	free_pages(dma_memory, order);
	RDMA_MEM_FREE_DEBUG_MSG("%s: FINISH va: 0x%lx, fa: 0x%llx size: 0x%lx\n",
				__FUNCTION__, dma_memory, dev_memory, size);
}

#define RDMA_MEM_FREE_POOL_DBG 0
#define RDMA_MEM_FREE_POOL_DEBUG_MSG(x...)\
		if (RDMA_MEM_FREE_POOL_DBG) DEBUG_MSG(x)
void rdma_mem_free_pool(rdma_pool_buf_t *pool_buf)
{
	signed int rest;
	
	RDMA_MEM_FREE_POOL_DEBUG_MSG("%s: START\n", __FUNCTION__);
	if (pool_buf->tm_mode) {
		rdma_tbl_64_struct_t *peltbl;
		for (peltbl = (rdma_tbl_64_struct_t *)pool_buf->vdma,
		     rest = pool_buf->dma_size; rest > 0; peltbl++) {
#ifdef CONFIG_E90S
			peltbl->addr = cpu_to_le64(peltbl->addr);
			peltbl->sz = cpu_to_le64(peltbl->sz);
#endif
			rdma_mem_free(peltbl->sz, (dma_addr_t) peltbl->addr,
				      (unsigned long) __va(peltbl->addr));
			rest -= peltbl->sz;
		}
		rdma_mem_free(pool_buf->size_tm, pool_buf->fdma,
			      (unsigned long)pool_buf->vdma);
	} else
		/*if (pool_buf->size) {*/
		if (pool_buf->alloc) {
			rdma_mem_free(pool_buf->dma_size, pool_buf->fdma,
				      (unsigned long)pool_buf->vdma);
		}
	pool_buf->size = 0;
	pool_buf->dma_size = 0;
	pool_buf->alloc = RDMA_BUF_EMPTY;
	pool_buf->vdma = NULL;
	pool_buf->fdma = 0;
	RDMA_MEM_FREE_POOL_DEBUG_MSG("%s: FINISH\n", __FUNCTION__);
}

#define INIT_RDMA_LINK_DBG 0
#define INIT_RDMA_LINK_DEBUG_MSG(x...)\
		if (INIT_RDMA_LINK_DBG) DEBUG_MSG(x)
void init_rdma_link(int link)
{
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[link];
	rdma_addr_struct_t p_xxb;
	dev_rdma_sem_t *dev_sem;
	rw_state_t *pd, *pm;
	int i;

	INIT_RDMA_LINK_DEBUG_MSG("%s: START\n", __FUNCTION__);
	p_xxb.addr = (unsigned long)rdma_link;
	INIT_RDMA_LINK_DEBUG_MSG("%s: link: %d rdma_link: 0x%08x%08x\n",
				 __FUNCTION__, link, p_xxb.fields.haddr,
     				 p_xxb.fields.laddr);
	rdma_link->link = link;
	mutex_init(&rdma_link->mu);
	pm = &rdma_link->talive;
	mutex_init(&pm->mu);
	raw_spin_lock_init(&pm->mu_spin);
	pm->stat = 0;
	pm->timer = TIMER_MIN;
	dev_sem = &pm->dev_rdma_sem;
	raw_spin_lock_init(&dev_sem->lock);
	cv_init(&dev_sem->cond_var);
	dev_sem->irq_count_rdma = 0;
	pm = &rdma_link->ralive;
	mutex_init(&pm->mu);
	raw_spin_lock_init(&pm->mu_spin);
	pm->stat = 0;
	pm->timer = TIMER_MIN;
	dev_sem = &pm->dev_rdma_sem;
	raw_spin_lock_init(&dev_sem->lock);
	cv_init(&dev_sem->cond_var);
	dev_sem->irq_count_rdma = 0;
	for (i = 0; i < 2; i++) {
		pm = &rdma_link->rw_states_m[i];
		mutex_init(&pm->mu);
		raw_spin_lock_init(&pm->mu_spin);
		pm->stat = 0;
		pm->timer = TIMER_MIN;
		dev_sem = &pm->dev_rdma_sem;
		raw_spin_lock_init(&dev_sem->lock);
		cv_init(&dev_sem->cond_var);
		dev_sem->irq_count_rdma = 0;
		pd = &rdma_link->rw_states_d[i];
		mutex_init(&pd->mu);
		raw_spin_lock_init(&pd->mu_spin);
		raw_spin_lock_init(&pd->lock_wr);
		raw_spin_lock_init(&pd->lock_rd);
		dev_sem = &pd->dev_rdma_sem;
		raw_spin_lock_init(&dev_sem->lock);
		cv_init(&dev_sem->cond_var);
		dev_sem->irq_count_rdma = 0;
		pd->trwd_was = 0;
		pd->clock_receive_trwd = 0;
		pd->clock_begin_read = 0;
		pd->clock_end_read_old = 0;
		pd->clock_begin_read_old = 0;
		pd->trwd_send_count = 0;
		pd->ready_send_count = 0;
		pd->trwd_rec_count = 0;
		pd->ready_rec_count = 0;
		pd->n_ready = 0;
		pd->stat = 0;
		pd->timer_read = TIMER_MIN;
		pd->timer_write = TIMER_MIN;
		pd->timer_for_read = TIMER_FOR_READ_MIN;
		pd->timer_for_write = TIMER_FOR_WRITE_MIN;
		pd->state_open_close = 0;
		pd->first_open = 0;
	}
	INIT_RDMA_LINK_DEBUG_MSG("%s: FINISH\n", __FUNCTION__);
}

void read_regs_rdma(int i)
{
	printk("%d 0x%08x - 0x0 SHIFT_IOL_CSR\n",  i,
	       RDR_rdma(SHIFT_IOL_CSR, i));
	printk("%d 0x%08x - 0x0 SHIFT_IO_CSR\n",   i,
	        RDR_rdma(SHIFT_IO_CSR, i));
	printk("%d 0x%08x - 0x0 SHIFT_VID\n", 	   i,
	       RDR_rdma(SHIFT_VID, i));
	printk("%d 0x%08x - 0x4 SHIFT_CH_IDT\n",   i,
	       RDR_rdma(SHIFT_CH_IDT, i));
	printk("%d 0x%08x - 0x8 SHIFT_CS\n",       i,
	       RDR_rdma(SHIFT_CS, i));
	printk("%d 0x%08x 0x00 - SHIFT_DD_ID\n",   i,
	       RDR_rdma(SHIFT_DD_ID, i));
	printk("%d 0x%08x 0x04 - SHIFT_DMD_ID\n",  i,
	       RDR_rdma(SHIFT_DMD_ID, i));
	printk("%d 0x%08x 0x08 - SHIFT_N_IDT\n",   i,
	       RDR_rdma(SHIFT_N_IDT, i));
	printk("%d 0x%08x 0x0c - SHIFT_ES\n",      i,
	       RDR_rdma(SHIFT_ES, i));
	printk("%d 0x%08x 0x10 - SHIFT_IRQ_MC\n",  i,
	       RDR_rdma(SHIFT_IRQ_MC, i));
	printk("%d 0x%08x 0x14 - SHIFT_DMA_TCS\n", i,
	       RDR_rdma(SHIFT_DMA_TCS, i));
	printk("%d 0x%08x 0x18 - SHIFT_DMA_TSA\n", i,
	       RDR_rdma(SHIFT_DMA_TSA, i));
	printk("%d 0x%08x 0x1c - SHIFT_DMA_TBC\n", i,
	       RDR_rdma(SHIFT_DMA_TBC, i));
	printk("%d 0x%08x 0x20 - SHIFT_DMA_RCS\n", i,
	       RDR_rdma(SHIFT_DMA_RCS, i));
	printk("%d 0x%08x 0x24 - SHIFT_DMA_RSA\n", i,
	       RDR_rdma(SHIFT_DMA_RSA, i));
	printk("%d 0x%08x 0x28 - SHIFT_DMA_RBC\n", i,
	       RDR_rdma(SHIFT_DMA_RBC, i));
	printk("%d 0x%08x 0x2c - SHIFT_MSG_CS\n",  i,
	       RDR_rdma(SHIFT_MSG_CS, i));
	printk("%d 0x%08x 0x30 - SHIFT_TDMSG\n",   i,
	       RDR_rdma(SHIFT_TDMSG, i));
	/*
	printk("%d 0x%08x 0x34 - SHIFT_RDMSG\n",   i, 
	       RDR_rdma(SHIFT_RDMSG, i));
	*/
	printk("%d 0x%08x 0x38 - SHIFT_CAM\n",     i,
	       RDR_rdma(SHIFT_CAM, i));
}

void del_dev_rdma(int major, int i)
{
	int i_rdma = 0;
	char nod[128];
	int minor;
	
	for (i_rdma= 0; i_rdma < RDMA_NODE_DEV; i_rdma++) {
		minor = RDMA_NODE_IOLINKS * i * RDMA_NODE_DEV + i_rdma;
		(void) sprintf(nod,"rdma_%d_:%d_r",i, i_rdma);
		device_destroy(rdma_class, MKDEV(major, minor));
		minor ++;
		(void) sprintf(nod,"rdma_%d_:%d_w",i, i_rdma);
		device_destroy(rdma_class, MKDEV(major, minor));
	}
}

int add_dev_rdma(int major, int mode,  int i)
{
	int i_rdma = 0;
	int minor;
	char nod[128];
	int ret = 0;
	
	for (i_rdma = 0; i_rdma < RDMA_NODE_DEV; i_rdma++) {
		minor = RDMA_NODE_IOLINKS * i * RDMA_NODE_DEV + i_rdma;
		sprintf(nod,"rdma_%d_:%d_r", i, i_rdma);
		pr_info("make node /sys/class/rdma/%s\n", nod);
		if (device_create(rdma_class, NULL, MKDEV(major,
		    minor), NULL, nod) == NULL) {
			pr_err("create dev: %s a node: %d failed\n",
			       nod, i);
			return -1;
		}
		minor ++;
		sprintf(nod,"rdma_%d_:%d_w", i, i_rdma);
		pr_info("make node /sys/class/rdma/%s\n", nod);
		if (device_create(rdma_class, NULL, MKDEV(major,
		    minor), NULL, nod) == NULL) {
				pr_err("create dev: %s a node: %d failed\n",
				       nod, i);
				return -1;
		}
	}
	return ret;
}

int create_dev_rdma(int major)
{
	int i = 0, mode = 0, ret = 0;
	
	/*
	 * Create rdma nodes in /sysfs
	 */
	rdma_class = class_create(THIS_MODULE, "rdma");
	if (IS_ERR(rdma_class)) {
		pr_err("Error creating class: /sys/class/rdma.\n");
	} else 
		pr_info("Create /sys/class/rdma.\n");
	if (HAS_MACHINE_L_SIC) {
		/*_RDMA_for_each_online_rdma(i)*/
		_RDMA_for_each_rdma(i) {
			if (add_dev_rdma(major, mode,  i))
				ret = -1;
		}
	} else {
		if (add_dev_rdma(major, mode,  0))
			ret = -1;
	}
	return ret;
}

int remove_dev_rdma(int major)
{
	int i = 0;
	
	/*
	 * Remove rdma nodes in /sysfs
	 */
	if (HAS_MACHINE_L_SIC) {
		_RDMA_for_each_rdma(i)
			del_dev_rdma(major, i);
	} else {
		del_dev_rdma(major, 0);
	}
	class_destroy(rdma_class);
	return 0;
}

module_init(rdma_init);
module_exit(rdma_cleanup);
