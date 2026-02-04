/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * EDAC ECC kernel module for e2k platforms e8c* (P1, P9), e16c, e2c3, e12c, e48c, e8v7
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/edac.h>
#include <asm/io.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>

#include "edac_module.h"

#define DEBUG_E2K_EDAC_POISON

#define E2K_EDAC_REVISION	" Ver: 2.0"
#define E2K_EDAC_DRVNAME	"e2k_edac"

#define e2k_info(fmt, arg...) \
	edac_printk(KERN_INFO, "e2k", fmt, ##arg)

#define e2k_warn(fmt, arg...) \
	edac_printk(KERN_WARNING, "e2k", "Warning: " fmt, ##arg)

#define e2k_err(fmt, arg...) \
	edac_printk(KERN_ERR, "e2k", "Error: " fmt, ##arg)

#define E2K_EDAC_DEBUG	0

#define e2k_edac_dbg(fmt, args...) \
	if (E2K_EDAC_DEBUG) pr_info("%s: " fmt, __func__, ##args)
#define e2k_edac_err(fmt, args...) pr_err("E2K_EDAC internal error. " fmt, ##args)

static LIST_HEAD(e2k_edac_list);

/*********************** pci section *************************************/

/* not present */

/*********************** cpu section *************************************/

/* not present */

/*********************** ecc section *************************************/

static int poll_msec = 2000;
module_param(poll_msec, int, 0444);
MODULE_PARM_DESC(poll_msec, KBUILD_MODNAME "poll period delay");

static struct task_struct *e2k_edac_thread = NULL;
/*
   We have MC_ECC regs in many chips - e8c2, e16c, e48c, e8v7.
   And in all arch's they are different.
   Declare abstract mcc reg, read_mcc_reg() will return it,
   no need understand type of reg in each place to use
*/

#define ecc_supported()	HAS_MACHINE_L_SIC
static int use_cfg_reg = 1;


#define MAX_NODES		4
#define MAX_MCS_ON_NODE		16
#define MAX_PBS_ON_MC		4
#define MC_SLOT_SZ		MAX_PBS_ON_MC
#define NODE_SLOT_SZ		(MC_SLOT_SZ * MAX_MCS_ON_NODE)

static	struct mem_ctl_info	*mci;
typedef struct { 
	struct platform_device	*pdev;
	u32 ce_err_cnt[MAX_NODES * NODE_SLOT_SZ];
	u32 ue_err_cnt[MAX_NODES * NODE_SLOT_SZ];
} e2k_edac_t;
static e2k_edac_t e2k_edac;
	
#define e2k_edac_ce_err_cnt(node, mc, pb)	\
	e2k_edac.ce_err_cnt[NODE_SLOT_SZ * node + mc * MC_SLOT_SZ + pb]

#define e2k_edac_ue_err_cnt(node, mc, pb)	\
	e2k_edac.ue_err_cnt[NODE_SLOT_SZ * node + mc * MC_SLOT_SZ + pb]



static struct edac_device_ctl_info *l12caches;
static struct {
	struct platform_device	*pdev;
	u32 ce_err_cnt[MAX_NR_CPUS];
	u32 ue_err_cnt[MAX_NR_CPUS];
} e2k_l12_edac;

static struct mutex mc_lock;
static struct edac_device_ctl_info *l3caches;
static struct {
	struct platform_device	*pdev;
	u32 ce_err_cnt[MAX_NODES];
	u32 ue_err_cnt[MAX_NODES];
} e2k_l3_edac;


static inline u32 ecc_get_error_cnt(e2k_mc_ecc_t *ecc, int node, int nr)
{
	*ecc = sic_get_mc_ecc(node, nr);
	return ecc->secnt;
}

static inline bool ecc_enabled(void)
{
	return sic_get_mc_ecc(0, 0).ee;
}


static int num_arch_nodes(void)
{
	switch (machine.native_id) {
		case MACHINE_ID_E8C:
		case MACHINE_ID_E8C2:
		case MACHINE_ID_E16C:
		case MACHINE_ID_E12C:
		case MACHINE_ID_E48C:
		case MACHINE_ID_E1CP:
		case MACHINE_ID_E2C3:
		case MACHINE_ID_E8V7:
			return cpu_max_cores_num();
		default:
			return 0;
	}
}


static int num_pb_in_mc(void)
{
	return 4;
}

/* Check for ECC Errors */
static void e2k_v6_ecc_check_node(int node)
{
	e2k_mc_ecc_t ecc;
	int mc;
	u32 cnt, current_cnt;
	u32 current_ue;
	char s[32];
	int v6 = (CURRENT_ISET == E2K_ISET_V6);

	
	for_each_mc_enabled(node, mc) {
		cnt = ecc_get_error_cnt(&ecc, node, mc);
		/* For old CPUs just mc granuality */
		current_cnt = cnt - e2k_edac_ce_err_cnt(node, mc, 0);
		current_ue = v6 ? ecc.v6_uecnt :ecc.ue;
#if 0
		e2k_edac_dbg("node %d mc%d secnt %d of %d ue %d reg 0x%08x.\n",
			 node, mc, ecc.secnt,
			v6 ? 0 : ecc.of, current_ue,  AW(ecc));
#endif
		if (current_ue > e2k_edac_ue_err_cnt(node, mc, 0)) {
			edac_mc_handle_error(HW_EVENT_ERR_UNCORRECTED, mci,
			     current_ue - e2k_edac_ue_err_cnt(node, mc, 0),
			     0, 0, 0, node, mc, 0,
			     "E2K MC", "");
			e2k_edac_ue_err_cnt(node, mc, 0) = current_ue;
		}
		/* check old errors */
		if (current_cnt == 0) {
			continue;
		}
		e2k_edac_ce_err_cnt(node, mc, 0) = cnt;
		snprintf(s, 30, "");
		if (!v6 && ecc.of) {
			snprintf(s, 30, "(error buffer overflow)");
		}
		edac_mc_handle_error(HW_EVENT_ERR_CORRECTED, mci,
			     current_cnt, 0, 0, 0, node, mc, 0,
			     "E2K MC", s);
	}
}


static int pb_type(struct mem_ctl_info *mci, int node, int mc, int pb, int *wtype)
{
	int pbtype;
	if (machine.native_id == MACHINE_ID_E1CP ||
	    machine.native_id == MACHINE_ID_E8C) {
		e2k_mc_opmb_t r;
		AW(r) = sic_get_mc_opmb(node, mc);
		pbtype = r.pbm & (1 << pb);
		if (!pbtype) {
			return 0;
		}
		mci->mtype_cap = MEM_FLAG_DDR3;
		pbtype = r.rm ? MEM_RDDR3 : MEM_DDR3;
		*wtype = DEV_X4;
		return pbtype;
	}

	int dqw;
	if (machine.native_id == MACHINE_ID_E48C) {
		e2k_e48c_mc_cfg_t mc_cfg;
		AW(mc_cfg) = sic_get_mc_cfg(node, mc);
		pbtype = mc_cfg.pbm & (1 << pb);
		if (!pbtype) {
			return 0;
		}
		if (is_prototype()) {
			mci->mtype_cap = MEM_FLAG_DDR4;
			pbtype = mc_cfg.rm ? MEM_RDDR4 : MEM_DDR4;
		} else {
			mci->mtype_cap = MEM_FLAG_DDR5;
			pbtype = mc_cfg.rm ? MEM_RDDR5 : MEM_DDR5;
		}
		/* DQ Width (dqw) = ct[1:0] - 1 */
		dqw = (((pb & 1) >> 1 ? mc_cfg.ct1 : mc_cfg.ct0) & 3) - 1;
	} else {
		e2k_mc_cfg_t mc_cfg;
		AW(mc_cfg) = sic_get_mc_cfg(node, mc);
		pbtype = mc_cfg.pbm & (1 << pb);
		if (!pbtype) {
			return 0;
		}
		mci->mtype_cap = MEM_FLAG_DDR4;
		pbtype = mc_cfg.rm ? MEM_RDDR4 : MEM_DDR4;
		dqw = mc_cfg.dqw;
	}
	switch (dqw) {
	case 0:
		*wtype = DEV_X4;
		break;
	case 1:
		*wtype = DEV_X8;
		break;
	case 2:
		*wtype = DEV_X16;
		break;
	case 3:
		*wtype = DEV_X32;
		break;
	default:
		*wtype = DEV_UNKNOWN;
		break;
	}
	return pbtype;
}
		 
	
static int init_csrow_of_mc(struct mem_ctl_info *mci, int node, int mc)
{
	int pb;
	struct dimm_info *dimm;
	int pbtype;
	int wtype;
	/* in edac dimm == pb */
	for (pb = 0; pb < mci->layers[2].size; pb++) {
		pbtype = pb_type(mci, node, mc, pb, &wtype);
		if (pbtype == 0) {
			continue;
		}
		dimm = edac_get_dimm(mci, node, mc, pb);
		if (dimm == NULL) {
			e2k_edac_err("No dim for %d - %d -%d\n", node, mc, pb);
			return -EFAULT;
		}
		e2k_edac_dbg("dimm %d for pb %d-%d-%d\n", dimm->idx, node, mc, pb);
		dimm->mtype = pbtype;
		dimm->edac_mode = EDAC_SECDED;
		dimm->nr_pages = 8 * 1024 * 1024; /* just to have in sysfs */
		dimm->grain = 32;
		dimm->dtype = wtype;
		snprintf(dimm->label, sizeof(dimm->label), "CPU %d, MC %d, slot %d",
			node, mc, pb >> 1);
	}
	return 0;
}
		 
static int init_csrow_of_node(struct mem_ctl_info *mci, int node)
{
	int mc;
	for_each_mc_enabled_of_node(node, mc) {
		e2k_edac_dbg("calls init_csrow_of_mc(mci, %d, %d)\n", node, mc);
		if (init_csrow_of_mc(mci, node, mc)) {
			return -EFAULT;
		}
	}
	return 0;
}


static int init_csrows(struct mem_ctl_info *mci)
{
	int node;

	for_each_online_node(node) {
		e2k_edac_dbg("calls init_csrow_of_node(mci, %d}\n", node);
		if (init_csrow_of_node(mci, node)) {
			return -EFAULT;
		}
	}
	return 0;
}

/*********************** main section ************************************/

static inline int cpu_supported(void)
{
	if (cpu_has(CPU_FEAT_E48C_MAKET)) {
		return 0;
	}
	return num_arch_nodes() > 0;
}

/* In v7 CPUs the tool to generate ecc errors introduced.
   Supporting this tool is above
*/
static void e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(int node, int mc, int reg, u32 val)
{
	e2k_edac_dbg(" node %d, mc %2d, reg 0x%x, val = 0x%08x\n",
		node, mc, reg, val);
	sic_write_node_v7_mc_nbsr_reg(node, mc, reg, val);
}

static int pb_enable(int node, int mc, int pb) {
	return (sic_read_node_v7_mc_nbsr_reg(node, mc, MC_CFG) & (1 << (pb + 8)));
}

static ssize_t inject_data_error_show(struct device *dev,
				      struct device_attribute *mattr,
				      char *data)
{       
	return sprintf(data, "To generate single (recovered) ECC error:\n"
		"echo node -> this_file\n");
}

static u32 diag_msk;
static int cur_int_mc;
static void set_mc_eccdiag_regs(int node)
{
	e2k_mc_eccdiag1_t mc_eccdiag1;
	int i;
	int mc;

	mc_eccdiag1 = (e2k_mc_eccdiag1_t) {.regnum = 1, .ce_ins = 1};
	for_each_mc_enabled_of_node(node, mc) {
		for (i = 0; i < 4; i++) {
			mc_eccdiag1.pb = i;
			e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node,  mc,
							      MC_ECCDIAG, AW(mc_eccdiag1));
		}
	}
}


static void clear_mc_eccdiag_regs(int node)
{
	e2k_mc_eccdiag1_t mc_eccdiag1;
	int i;
	int mc;

	mc_eccdiag1 = (e2k_mc_eccdiag1_t) {.regnum = 1};
	for_each_mc_enabled_of_node(node, mc) {
		for (i = 0; i < 4; i++) {
			mc_eccdiag1.pb = i;
			e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node, mc,
							      MC_ECCDIAG, AW(mc_eccdiag1));
		}
	}
}



static void produce_v7_diag_io(int node, u64 va_base)
{
	e2k_mcna_diag_addr_t mcna_diag_addr;
	u64 pha_base = __pa(va_base);
	u64 pha;
	int mc;

	diag_msk = 0;
	for_each_mc_enabled_of_node(node, mc) {
		diag_msk |= (1 << mc);
	}
	e2k_edac_dbg("node_chnls = 0x%02x, pha_base = 0x%llx \n",
			diag_msk, pha_base);
	for (pha = pha_base; pha < pha_base + 8 * 32; pha += 32) {
		if (diag_msk == 0) {
			/* all channels checked */
			e2k_edac_dbg("%s. All MC tested\n", __func__); 
			break;
		}
		mutex_lock(&mc_lock);
		/* Use broadcast, but request should go just to cur_mc chan */
		/* Set pha diag request */
		AW(mcna_diag_addr) = 0;
		mcna_diag_addr.req_gen = 0;
		mcna_diag_addr.data_type = 0;
		mcna_diag_addr.addr_half = 0;
		mcna_diag_addr.phys_addr = pha & 0xffffff;
		e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node, 0x1f,
					MCNA_DIAG_ADDR, AW(mcna_diag_addr));
		mcna_diag_addr.addr_half = 1;
		mcna_diag_addr.phys_addr = (pha >> 24) & 0xffffff;
		e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node, 0x1f,
					MCNA_DIAG_ADDR, AW(mcna_diag_addr));

		int i;
		/* Set diag data */
		mcna_diag_addr.data_type = 1;
		for (i = 0; i < 8; i++) {
			mcna_diag_addr.data_word = i;
			e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node, 0x1f,
						      MCNA_DIAG_ADDR, AW(mcna_diag_addr));
			e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node, 0x1f,
					MCNA_DIAG_DATA,	(i & 1) ? 0xaaaaaaaa : 0x55555555);
		}

		/* Set MC_ECCDIAG ce_ins for all pbs of all available MC */
		set_mc_eccdiag_regs(node);

		cur_int_mc = -1;

		/* Start request to generate ecc error */
		e2k_edac_dbg("Start request to generate ecc ce error\n");
		mcna_diag_addr.req_gen = 1;
		mcna_diag_addr.req_type = 1;
		e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node, 0x1f,
						MCNA_DIAG_ADDR, AW(mcna_diag_addr));

		/* Diagnostic read to get interrupt */
		/* Casual read would produce interrupt as well */
		mcna_diag_addr.req_type = 0;
		e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node, 0x1f,
						MCNA_DIAG_ADDR, AW(mcna_diag_addr));


		mutex_unlock(&mc_lock);
		mdelay(4 * poll_msec); /* edac polling every 1000 msecs */
		mutex_lock(&mc_lock);

		if (cur_int_mc < 0) {
			pr_warn("E2K_EDAC. No ecc error after generating ecc error\n");
			clear_mc_eccdiag_regs(node);
			break;
		} else {
			diag_msk &= ~(1 << cur_int_mc);
			
		}

		/* Clear MC_ECCDIAG fields */
		clear_mc_eccdiag_regs(node);
		mutex_unlock(&mc_lock);
	}
	if (diag_msk) {
		pr_info("Not tested channels: 0x%04x\n", diag_msk);
	}
}

	
static ssize_t inject_data_error_store(struct device *dev,
				       struct device_attribute *mattr,
				       const char *data, size_t count)
{
	unsigned int node;
	e2k_edac_dbg("node = %s\n", data);
	if (sscanf(data, "%u", &node) != 1) {
		return -EINVAL;
	}
	struct page *page = alloc_pages_node(node, GFP_KERNEL, 0);
	if (page == NULL) {
		return -EINVAL;
	}
	produce_v7_diag_io(node, (u64)page_address(page));
	memset(page_address(page), 0, PAGE_SIZE);
	__free_pages(page, 0); 
	return count;
} 

static DEVICE_ATTR_RW(inject_data_error);


#ifdef DEBUG_E2K_EDAC_POISON

static ssize_t inject_poison_show(struct device *dev,
				  struct device_attribute *mattr,
				  char *data)
{
	return sprintf(data, "To generate multiple error (poisoned data:\n"
		"echo user_addr_of page locked_in_memory -> this_file\n");
}
static unsigned long get_pa_of_user_va(unsigned long address)
{
	u64 dtlb_entry;
	uaccess_enable();
	dtlb_entry = get_MMU_DTLB_ENTRY(address);
	flush_DCACHE_line(address);
	uaccess_disable();
	return _PAGE_PFN_V6 & dtlb_entry;
}

#if 0
#define P_DBG pr_info
#else
#define P_DBG(a, b)
#endif
static ssize_t inject_poison_store(struct device *dev,
				   struct device_attribute *mattr,
				   const char *data, size_t count)
{
	unsigned long m;
	unsigned long pha;
	int mc;
	int node;
	e2k_mcna_diag_addr_t mcna_diag_addr;

	if (sscanf(data, "0x%lx", &m) != 1) {
		return -EINVAL;
	}
	if (!access_ok(m, PAGE_SIZE)) {
		return -EFAULT;
	}
	if (m & (PAGE_SIZE - 1)) {
		/* must be page alligned */
		return -EINVAL;
	}
	pha = get_pa_of_user_va(m);
	node = page_to_nid(phys_to_page(pha));

	mutex_lock(&mc_lock);
	/* Set pha diag request */
	/* It is hard to know mc for pha, use broadcast */
	AW(mcna_diag_addr) = 0;
	mcna_diag_addr.req_gen = 0;
	mcna_diag_addr.data_type = 0;
	mcna_diag_addr.addr_half = 0;
	mcna_diag_addr.phys_addr = pha & 0xffffff;
	e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node, 0x1f,
					MCNA_DIAG_ADDR, AW(mcna_diag_addr));
	P_DBG("1 MCNA_DIAG_ADDR = %#08x\n", AW(mcna_diag_addr));
	mcna_diag_addr.addr_half = 1;
	mcna_diag_addr.phys_addr = (pha >> 24) & 0xffffff;
	e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node, 0x1f,
				MCNA_DIAG_ADDR, AW(mcna_diag_addr));
	P_DBG("2 MCNA_DIAG_ADDR = %#08x\n", AW(mcna_diag_addr));
	int i;
	/* Set diag data */
	mcna_diag_addr.data_type = 1;
	for (i = 0; i < 8; i++) {
		mcna_diag_addr.data_word = i;
		mcna_diag_addr.data_type = 1;
		e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node, 0x1f,
					      MCNA_DIAG_ADDR, AW(mcna_diag_addr));
		P_DBG("3 MCNA_DIAG_ADDR = %#08x\n", AW(mcna_diag_addr));
		e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node, 0x1f,
				MCNA_DIAG_DATA,	(i & 1) ? 0xaaaaaaaa : 0x55555555);
		P_DBG("4 MCNA_DIAG_DATA = %#08x\n", (i & 1) ? 0xaaaaaaaa : 0x55555555);
	}

	e2k_mc_eccdiag1_t mc_eccdiag1;

	/* Set MC_ECCDIAG for generating multiple ECC error for all pbs of all available MC */
	mc_eccdiag1 = (e2k_mc_eccdiag1_t) {.regnum = 1, .ue_ins = 1};
	for_each_mc_enabled_of_node(node, mc) {
		for (i = 0; i < 4; i++) {
			mc_eccdiag1.pb = i;
			e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node,  mc,
					      MC_ECCDIAG, AW(mc_eccdiag1));
			P_DBG("5 MC_ECCDIAG = %#08x\n", AW(mc_eccdiag1));
		}
	}



	/* Start request. Memory must be marked as poisoned */
	e2k_edac_dbg("Start request to generate ecc ue error\n");
	mcna_diag_addr.req_gen = 1;
	mcna_diag_addr.req_type = 1;
	e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node, 0x1f,
					MCNA_DIAG_ADDR, AW(mcna_diag_addr));
	P_DBG("6 MCNA_DIAG_ADDR = %#08x\n", AW(mcna_diag_addr));
#if 0
	/* Diagnostic read to get interrupt */
	/* Casual read would produce interrupt as well */
	mcna_diag_addr.req_type = 0;
	P_DBG("7 MCNA_DIAG_ADDR = %#08x\n", AW(mcna_diag_addr));
	e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node, 0x1f,
					MCNA_DIAG_ADDR, AW(mcna_diag_addr));
#endif
	clear_mc_eccdiag_regs(node);
	mutex_unlock(&mc_lock);

	return count;
}

static DEVICE_ATTR_RW(inject_poison);

#endif /*DEBUG_E2K_EDAC_POISON */
static int edac_create_sysfs_attributes(struct mem_ctl_info *mci)
{
	int r = 0;
	if (CURRENT_ISET < E2K_ISET_V7) {
		return 0;
	}
#ifdef DEBUG_E2K_EDAC_POISON
	r = device_create_file(&mci->dev, &dev_attr_inject_poison);
#endif
	return  r || device_create_file(&mci->dev, &dev_attr_inject_data_error);
}

static void edac_remove_sysfs_attributes(struct mem_ctl_info *mci)
{
	if (CURRENT_ISET < E2K_ISET_V7) {
		return;
	}
#ifdef DEBUG_E2K_EDAC_POISON
	device_remove_file(&mci->dev, &dev_attr_inject_poison);
#endif
	device_remove_file(&mci->dev, &dev_attr_inject_data_error);
}

static void send_edac_v7_single_error_message(int node, int mc, int pb, u16 cnt)
{
	char s[256];
	if (machine.native_id == MACHINE_ID_E48C) {
		snprintf(s, 256, "Single recovered ecc error on node %d,"
			" chanel %d, mch = %d,  pb %d.\n",
			node, mc >> 1, mc & 1, pb);
	} else { /*e8v7 */
		snprintf(s, 256, "Single recovered ecc error on node %d,"
			" chanel %d, slot %d.\n",
			node, mc, pb);
	}
	e2k_edac_dbg("%s", s);

	edac_mc_handle_error(HW_EVENT_ERR_CORRECTED, mci,
			     cnt, 0, 0, 0,
			     node, mc, pb,
			     "E2K MC", s);

}


static void send_edac_v7_multiple_error_message(int node, int mc, int pb, u32 cnt)
{
	char s[256];
	if (machine.native_id == MACHINE_ID_E48C) {
		snprintf(s, 256, "Multiple ecc error on node %d, chanel %d, mch = %d,  pb %d.\n",
			node, mc >> 1, mc & 1, pb);
	} else { /*e8v7 */
		snprintf(s, 256, "Multiple ecc error on node %d, chanel %d, slot %d.\n",
			node, mc, pb);
	}
	e2k_edac_dbg("%s", s);
	edac_mc_handle_error(HW_EVENT_ERR_DEFERRED, mci, cnt, 0, 0, 0,
			     node, mc, pb, "E2K MC", s);
}



static void handle_mc(int node)
{
	e2k_mc_status_t mc_st;
	int mc;
	e2k_edac_dbg("node %d\n", node);
	if (machine.native_id != MACHINE_ID_E48C &&
	    machine.native_id != MACHINE_ID_E8V7) {
		return;
	}
	mutex_lock(&mc_lock);
	for_each_mc_enabled_of_node(node, mc) {
		AW(mc_st) = sic_read_node_v7_mc_nbsr_reg(node, mc, MC_STATUS_E2K);
		mc_st = (e2k_mc_status_t) {.par_alert_delay = mc_st.par_alert_delay,
					   .ce_int = 1};
		e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node, mc, MC_STATUS_E2K, AW(mc_st));
		int pb;
		for (pb = 0; pb < 4; pb++) {
			e2k_mc_eccdiag1_t mc_ed1;
			u32 cnt;
			u32 ce_cnt;
			if (!(pb_enable(node, mc, pb))) {
				/* no pbm side */
				continue;
			}
			mc_ed1 = (e2k_mc_eccdiag1_t)
				 { .regnum = 0,  .pb = pb};
			e2k_edac_dbg_sic_write_node_v7_mc_nbsr_reg(node, mc, MC_ECCDIAG, AW(mc_ed1));
			cnt = sic_read_node_v7_mc_nbsr_reg(node, mc, MC_ECCDIAG);
			ce_cnt = cnt & 0xffff;
			if (ce_cnt > e2k_edac_ce_err_cnt(node, mc, pb)) {
				cur_int_mc = mc; /* just for debug via inject_data_error file */
				send_edac_v7_single_error_message(node, mc, pb,
					ce_cnt - e2k_edac_ce_err_cnt(node, mc, pb));
				e2k_edac_ce_err_cnt(node, mc, pb) = ce_cnt;
			}

			u32 ue_cnt = (cnt >> 16) & 0xff;
			if (ue_cnt > e2k_edac_ue_err_cnt(node, mc, pb)) {
				send_edac_v7_multiple_error_message(node, mc, pb,
					ue_cnt - e2k_edac_ue_err_cnt(node, mc, pb));
				e2k_edac_ue_err_cnt(node, mc, pb) = ue_cnt;
			}
		}	
	}
	mutex_unlock(&mc_lock);
}

static void handle_l3(int node)
{
	u64 ha_mask = (u64)sic_read_node_nbsr_reg(node, OCN_L3EN0) |
		      ((u64)(sic_read_node_nbsr_reg(node, OCN_L3EN1) & 0xffff) << 32);
	int ha;
	e2k_l3_ecc_t reg;
	char msg[48];
	ha_mask = ~ha_mask & CURRENT_HA_MASK;
	for (ha = 0; ha < machine.sic_ha_num; ha++) {
		int clear = 0;
		if (!(ha_mask & (1 << ha))) {
			continue;
		}
		AW(reg) = sic_read_l3_reg(node, ha, L3_ECC);
		if (reg.dm_ded_poison) {
			snprintf(msg, 48, "L3 poisoned data of ha %d", ha);
			edac_device_handle_ue_count(l3caches, reg.dm_cnt, node, 0, msg);
			clear = 1;
		}
		if (reg.dm_sed) {
			snprintf(msg, 48, "L3 correctable error of ha %d", ha);
			edac_device_handle_ce_count(l3caches, reg.dm_cnt, node, 0, msg);
			clear = 1;
		}
		if (reg.ld_sed) {
			snprintf(msg, 48, "L3 directory correctable error of ha %d", ha);
			edac_device_handle_ce_count(l3caches, reg.ld_cnt, node, 0, msg);
			clear = 1;
		}
		if (clear) {
			sic_write_l3_reg(node, ha, L3_ECC, 0);
		}
	}
}

static void handle_l1(void)
{
	e2k_l1_fault_reg_t fr;
	AW(fr) = READ_L1_FAULT_REG();
	if (fr.val != 0) {
		edac_device_handle_ue_count(l12caches, 1 + (fr.val > 0x100),
			smp_processor_id(), 0, "L1 user poisoned data");
		if (!fr.fatal) {
			fr.val = 0;
			WRITE_L1_FAULT_REG(AW(fr));
		}
	}
}


static void handle_l2(void)
{
	int bank = 0;
	e2k_l2_err_t l2_err;
	e2k_l2_cnt_err1_t cnt_err1;
	e2k_l2_cnt_err2_t cnt_err2;
	for (; bank < E2K_L2_BANK_NUM; bank++) {
		AW(l2_err) = read_DCACHE_L2_ERR_reg(bank);
		if (!l2_err.fv) {
			continue;
		}
		AW(cnt_err1) = read_DCACHE_L2_CNT_ERR1_reg(bank);
		if (cnt_err1.ce_cnt) {
			char m[48];
			snprintf(m, 47, "bank %d L2_ERR = %#16llx", bank, AW(l2_err));
			edac_device_handle_ce_count(l12caches, cnt_err1.ce_cnt,
				smp_processor_id(), 1, m);
			clear_DCACHE_L2_CNT_ERR1_reg(bank);
		}
		AW(cnt_err2) = read_DCACHE_L2_CNT_ERR2_reg(bank);
		if (cnt_err2.err2_cnt > cnt_err2.psn_cnt) {
			/* poisoned data were logged by MC */
			char m[48];
			snprintf(m, 47, "bank %d L2_ERR = %#16llx", bank, AW(l2_err));
			edac_device_handle_ue_count(l12caches, cnt_err2.psn_cnt,
					smp_processor_id(), 1, m);
			clear_DCACHE_L2_CNT_ERR2_reg(bank);
		} else if (cnt_err2.psn_cnt == 0x3ff) {
			clear_DCACHE_L2_CNT_ERR2_reg(bank);
		}
		if (!l2_err.err_fatal)
			write_DCACHE_L2_ERR_reg(bank, AW(l2_err));
	}
}


static void e2k_ecc_check(void)
{
	int node;
	for_each_online_node(node) {
		if (CURRENT_ISET < E2K_ISET_V7) {
			e2k_v6_ecc_check_node(node);
		} else {
			handle_mc(node);
			handle_l3(node);
		}
	}
	if (CURRENT_ISET < E2K_ISET_V7) {
		return;
	}
	int cpu;
	cpumask_var_t new_mask;
	cpumask_var_t old_mask;
	if (!zalloc_cpumask_var(&new_mask, GFP_KERNEL)) {
		pr_warn("%s: could not alloc cpu mask\n", __func__);
		return;
	}
	if (!zalloc_cpumask_var(&old_mask, GFP_KERNEL)) {
		pr_warn("%s: could not alloc cpu mask\n", __func__);
		free_cpumask_var(new_mask);
		return;
	}
	sched_getaffinity(current->pid, old_mask);
	for_each_online_cpu(cpu) {
		int r;
		cpumask_set_cpu(cpu, new_mask);
		r = sched_setaffinity(current->pid, new_mask);
		if (unlikely(r)) {
			char buf[64];
			cpumap_print_bitmask_to_buf(buf, new_mask, 0, 64);
			pr_warn("%s: could not set affinity to cpu %d. err = %d, mask = %s\n",
				__func__, cpu, r, buf);
		}  else {
			handle_l1();
			handle_l2();
		}
		cpumask_clear_cpu(cpu, new_mask);
	}
	sched_setaffinity(current->pid, old_mask);
	free_cpumask_var(new_mask);
	free_cpumask_var(old_mask);
}

static int stop_e2k_edac_threadfn = 0;
static int e2k_edac_threadfn_stopped = 0;

static int e2k_edac_threadfn(void *foo)
{
	while (!stop_e2k_edac_threadfn) {
		e2k_ecc_check();
			msleep(poll_msec);
	}
	e2k_edac_threadfn_stopped = 1;
	return 0;
}

/* ===========  */
static void  e2k_edac_exit(void);

static int __init e2k_edac_init(void)
{
	long ret = 0;
	const char *owner;

	owner = edac_get_owner();
	if (owner &&
	    strncmp(owner, E2K_EDAC_DRVNAME, sizeof(E2K_EDAC_DRVNAME))) {
		e2k_info("E2K EDAC driver " E2K_EDAC_REVISION " - busy\n");
		return -EBUSY;
	}

	e2k_info("E2K EDAC driver " E2K_EDAC_REVISION "\n");

	if (!cpu_supported()) {
		e2k_info("CPU not supported\n");
		return -ENODEV;
	}

	if (!ecc_supported()) {
		e2k_info("ECC not supported\n");
		return -ENODEV;
	}

	if (!ecc_enabled()) {
		e2k_info("ECC not enabled\n");
		return -ENODEV;
	}

	if (machine.native_id == MACHINE_ID_E1CP ||
	    machine.native_id == MACHINE_ID_E8C) {
		use_cfg_reg = 0;
	}


	struct edac_mc_layer layers[3];
	/* Possible nodes(cpus) in machine */
	layers[0].type = EDAC_MC_LAYER_BRANCH;
	layers[0].size = num_arch_nodes();
	layers[0].is_virt_csrow = false;
	/* Possible controllers in cpu */
	layers[1].type = EDAC_MC_LAYER_CHANNEL;
	layers[1].size = SIC_MC_COUNT;
	layers[1].is_virt_csrow = false;
	/* Num phys banks on controller */
	layers[2].type = EDAC_MC_LAYER_CHIP_SELECT;
	layers[2].size = num_pb_in_mc();
	layers[2].is_virt_csrow = true;
	e2k_edac_dbg("Layers(%ld): %d - %d - %d\n",
		ARRAY_SIZE(layers), layers[0].size, layers[1].size, layers[2].size);
	e2k_edac.pdev = platform_device_register_simple("E2K_EDAC_MC", 0, NULL, 0);
	if (IS_ERR(e2k_edac.pdev)) {
		edac_printk(KERN_ERR, EDAC_MC,
			"Failed to platform_device_register_simple\n");
		return -EFAULT;
	}

	mci = edac_mc_alloc(0, ARRAY_SIZE(layers), layers, 0);
	if (!mci) {
		platform_device_unregister(e2k_edac.pdev);
		edac_printk(KERN_ERR, EDAC_MC,
			"Failed memory allocation for mc instance\n");
		return -ENOMEM;
	} 
	mci->pdev = &e2k_edac.pdev->dev;

	if (init_csrows(mci)) {
		edac_mc_free(mci);
		platform_device_unregister(e2k_edac.pdev);
		return -EFAULT;
	}
	mci->edac_ctl_cap = EDAC_FLAG_SECDED;
	mci->edac_cap = EDAC_FLAG_SECDED;
	mci->scrub_cap = SCRUB_FLAG_HW_SRC;
	mci->scrub_mode = SCRUB_HW_SRC;
	mci->mod_name = "E2K ECC";
	mci->ctl_name = dev_name(&e2k_edac.pdev->dev);
	mci->dev_name = dev_name(&e2k_edac.pdev->dev);
	mci->ctl_page_to_phys = NULL;
	edac_op_state = EDAC_OPSTATE_INT;


	/* register with edac core */
	ret = edac_mc_add_mc(mci);
	if (ret) {
		edac_mc_free(mci);
		platform_device_unregister(e2k_edac.pdev);
		e2k_err("failed to register with EDAC core\n");
		return ret;
	}
	if (edac_create_sysfs_attributes(mci)) {
		pr_warn("Could not create files for E2K_EDAC debuf\n");
	}
	if (!ret && CURRENT_ISET >= E2K_ISET_V7) {
		l12caches = edac_device_alloc_ctl_info(0, "CPU", nr_cpu_ids,
						       "L", 2, 1, NULL, 0, 0);
		if (l12caches) {
			e2k_l12_edac.pdev = platform_device_register_simple("E2K_EDAC_CPU",
									    1, NULL, 0);
			if (IS_ERR(e2k_l12_edac.pdev)) {
				edac_printk(KERN_ERR, EDAC_MC,
					"Failed to platform_device_register_simple 1\n");
				edac_device_free_ctl_info(l12caches);
				l12caches = NULL;
				goto after_l12_label;
			}
			l12caches->dev = &e2k_l12_edac.pdev->dev;
			l12caches->mod_name = "E2K L1,L2";
			l12caches->ctl_name = dev_name(l12caches->dev);
			l12caches->dev_name = dev_name(l12caches->dev);
			if (edac_device_add_device(l12caches)) {
				platform_device_unregister(e2k_l12_edac.pdev);
				edac_device_free_ctl_info(l12caches);
				l12caches = NULL;
			}
		}
after_l12_label:
		l3caches = edac_device_alloc_ctl_info(0, "NODE", nr_node_ids,
						      "L", 1, 3, NULL, 0, 1);
		if (l3caches) {
			e2k_l3_edac.pdev = platform_device_register_simple("E2K_EDAC_NODE",
									   2, NULL, 0);
			if (IS_ERR(e2k_l3_edac.pdev)) {
				edac_printk(KERN_ERR, EDAC_MC,
					"Failed to platform_device_register_simple 2\n");
				edac_device_free_ctl_info(l3caches);
				l3caches = NULL;
				goto after_l3_label;
			}
			l3caches->dev = &e2k_l3_edac.pdev->dev;
			l3caches->mod_name = "E2K L3";
			l3caches->ctl_name = dev_name(&e2k_l3_edac.pdev->dev);
			l3caches->dev_name = dev_name(&e2k_l3_edac.pdev->dev);
			if (edac_device_add_device(l3caches)) {
				platform_device_unregister(e2k_l3_edac.pdev);
				edac_device_free_ctl_info(l3caches);
				l3caches = NULL;
				goto after_l3_label;
			}
		}
after_l3_label:
		;
	}
	mutex_init(&mc_lock);
	e2k_edac_thread = kthread_create(e2k_edac_threadfn, NULL, "e2k-edac-thread");
	if (IS_ERR(e2k_edac_thread)) {
		ret = PTR_ERR(e2k_edac_thread);
		e2k_edac_thread = NULL;
		e2k_edac_exit();
	} else {
		wake_up_process(e2k_edac_thread);
	}
	return (int)ret;
}

static void e2k_edac_exit(void)
{
	if (e2k_edac_thread) {
		stop_e2k_edac_threadfn = 1;
		while (!e2k_edac_threadfn_stopped) {
			msleep(poll_msec);
		}
	}
	edac_remove_sysfs_attributes(mci);
	if (edac_mc_del_mc(&e2k_edac.pdev->dev)) {
		edac_mc_free(mci);
	}
	platform_device_unregister(e2k_edac.pdev);
	if (l3caches) {
		edac_device_del_device(l3caches->dev);
		edac_device_free_ctl_info(l3caches);
		platform_device_unregister(e2k_l3_edac.pdev);
	}
	if (l12caches) {
		edac_device_del_device(&e2k_l12_edac.pdev->dev);
		edac_device_free_ctl_info(l12caches);
		platform_device_unregister(e2k_l12_edac.pdev);
	}
}

module_init(e2k_edac_init);
module_exit(e2k_edac_exit);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("edac ECC driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(E2K_EDAC_REVISION);
