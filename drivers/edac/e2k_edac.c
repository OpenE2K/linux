/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * EDAC ECC kernel module for e2k platforms e8c* (P1, P9), e16c, e2c3, e12c, e48c, e8v7
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/edac.h>

#include <asm/io.h>
#include <asm/sic_regs.h>

#include "edac_module.h"

#define E2K_EDAC_REVISION	" Ver: 0.3"
#define E2K_EDAC_DRVNAME	"e2k_edac"

#define e2k_info(fmt, arg...) \
	edac_printk(KERN_INFO, "e2k", fmt, ##arg)

#define e2k_warn(fmt, arg...) \
	edac_printk(KERN_WARNING, "e2k", "Warning: " fmt, ##arg)

#define e2k_err(fmt, arg...) \
	edac_printk(KERN_ERR, "e2k", "Error: " fmt, ##arg)

static LIST_HEAD(e2k_edac_list);

/*********************** pci section *************************************/

/* not present */

/*********************** cpu section *************************************/

/* not present */

/*********************** ecc section *************************************/

#define DIMM_ON_CHANNEL 2

typedef e2k_mc_ecc_struct_t ecc_struct_t;

static int use_cfg_reg = 1;
static int total_mc_num = 0;

struct channel_info {
	int			arch_size;/* ctX */
	int			num_side; /* pbmX */
};

struct e2k_edac_dev {
	struct list_head	list;
	int			node;
	int			mcN;      /* internal num MC on node*/
	int			id;       /* total num MC on machine */
	/**********************************/
	struct channel_info	dimm[DIMM_ON_CHANNEL];
	int			m_type;   /* DDR3/DDR4 */
	int			r_type;   /* rm - register/unregister*/
	int			freq;     /* sf */
	int			w_type;   /* dqw - width type */
	/**********************************/
	u16			last_ecc_ce;
	u8			last_ecc_ue;
	/**********************************/
	struct platform_device	*pdev;
	struct mem_ctl_info	*mci;
};

struct e2k_mci_priv {
	struct e2k_edac_dev *dev;
};

static inline u32 ecc_get_error_cnt(ecc_struct_t *ecc, int node, int nr)
{
	ecc->E2K_MC_ECC_reg = sic_get_mc_ecc(node, nr);
	return ecc->E2K_MC_ECC_secnt;
}

static inline bool ecc_enabled(void)
{
	ecc_struct_t ecc;
	ecc.E2K_MC_ECC_reg = sic_get_mc_ecc(0, 0);
	return ecc.E2K_MC_ECC_ee;
}

#define ecc_supported()	HAS_MACHINE_L_SIC

/* Check for ECC Errors */
static void e2k_ecc_check(struct mem_ctl_info *mci)
{
	int node, i;
	u32 cnt, current_cnt;
	struct e2k_mci_priv *priv = mci->pvt_info;
	struct e2k_edac_dev *dev;
	char s[32];
	ecc_struct_t ecc;

	dev = priv->dev;

	node = dev->node;
	i = dev->mcN;
	cnt = ecc_get_error_cnt(&ecc, node, i);
	current_cnt = cnt - dev->last_ecc_ce;
/*
	e2k_info("node %d mc%d secnt %d of %d ue %d reg 0x%x.\n",
		 node, i,
		 ecc.E2K_MC_ECC_secnt,
		 ecc.E2K_MC_ECC_of,
		 ecc.E2K_MC_ECC_ue,
		 ecc.E2K_MC_ECC_reg);
*/
	if (!dev->last_ecc_ue && ecc.E2K_MC_ECC_ue) {
		/* e2k_err("node %d mc%d: unrecoverable error.\n", node, i); */
		dev->last_ecc_ue = 1;
		edac_mc_handle_error(HW_EVENT_ERR_UNCORRECTED, mci,
				     1, 0, 0, 0,
				     0, 0, -1,
				     "E2K MC", "");
	}

	/* check old errors */
	if (current_cnt == 0) {
		return;
	}

	dev->last_ecc_ce = cnt;

	snprintf(s, 30, "");
	if (ecc.E2K_MC_ECC_of) {
		snprintf(s, 30, "(error buffer overflow)");
	}
	/*
	e2k_warn("node %d mc%d: %d correctable errors. %s\n",
		 node, i, current_cnt, s);
	*/
	edac_mc_handle_error(HW_EVENT_ERR_CORRECTED, mci,
			     current_cnt, 0, 0, 0,
			     0, 0, -1,
			     "E2K MC", s);
}


static int init_csrows(struct e2k_edac_dev *dev)
{
	struct mem_ctl_info *mci = dev->mci;
	struct dimm_info *dimm;
	int i;

	for (i = 0; i < DIMM_ON_CHANNEL; i++) {
		/* DIMM not present */
		if (!dev->dimm[i].num_side) {
			continue;
		}

		dimm = edac_get_dimm(mci, 0, i, 0);
		if (dev->m_type == MEM_DDR4) {
			dimm->mtype = dev->r_type ? MEM_RDDR4 : MEM_DDR4;
		} else {
			dimm->mtype = dev->r_type ? MEM_RDDR3 : MEM_DDR3;
		}
		dimm->edac_mode = EDAC_SECDED;
		dimm->nr_pages = dev->dimm[i].arch_size;
		dimm->grain = 32; /* ??? */
		dimm->dtype = dev->w_type;
		snprintf(dimm->label, sizeof(dimm->label), "DIMM%u", dev->id);
	}

	return 0;
}


static struct e2k_edac_dev *alloc_e2k_dev(int node, int mcN)
{
	struct e2k_edac_dev *e2k_edac_dev;

	e2k_edac_dev = kzalloc(sizeof(*e2k_edac_dev), GFP_KERNEL);
	if (!e2k_edac_dev)
		return NULL;

	e2k_edac_dev->pdev = platform_device_register_simple(E2K_EDAC_DRVNAME,
							     total_mc_num,
							     NULL, 0);
	if (IS_ERR(e2k_edac_dev->pdev)) {
		kfree(e2k_edac_dev);
		return NULL;
	}

	e2k_edac_dev->node = node;
	e2k_edac_dev->mcN = mcN;
	e2k_edac_dev->id = total_mc_num;

	total_mc_num++;

	list_add_tail(&e2k_edac_dev->list, &e2k_edac_list);

	return e2k_edac_dev;
}

static void free_e2k_dev(struct e2k_edac_dev *e2k_edac_dev)
{
	list_del(&e2k_edac_dev->list);
	kfree(e2k_edac_dev);
}

static void e2k_free_all_devices(void)
{
	struct e2k_edac_dev *e2k_edac_dev, *tmp;

	list_for_each_entry_safe(e2k_edac_dev, tmp,
				 &e2k_edac_list, list) {
		free_e2k_dev(e2k_edac_dev);
	}
}

static inline int get_chip_CFG_size(int ct)
{
	switch (ct) {
	case 0: return 256*8;
	case 1: return 512*4;
	case 2: return 1024*4;
	case 3: return 2048*4;
	case 4: return 4096*4;
	}
	return 8192*4;
}

static inline int get_chip_OPMB_size(int ct)
{
	switch (ct) {
	case 0: return 64*8;
	case 1: return 128*8;
	case 2: return 256*8;
	case 3: return 512*8;
	case 4: return 1024*8;
	}
	return 2048*8;
}

static inline int get_chip_speed(int sf)
{
	switch (sf) {
	case 0: return 1600;
	case 1: return 1866;
	case 2: return 2133;
	case 3: return 2400;
	case 4: return 2666;
	case 5: return 3200;
	}
	return 3200;
}

static inline int get_chip_bus_width(int dqw)
{
	switch (dqw) {
	case 0: return DEV_X4;
	case 1: return DEV_X8;
	case 2: return DEV_X16;
	case 3: return DEV_X32;
	}
	return DEV_UNKNOWN;
}

static inline int get_chip_memory_type(void)
{
	if (machine.native_id == MACHINE_ID_E1CP ||
	    machine.native_id == MACHINE_ID_E8C) {
		return MEM_DDR3;
	}

	/* for next machine type -- DDR4:
	 * machine.native_id == MACHINE_ID_E8C2
	 * machine.native_id == MACHINE_ID_E12C
	 * machine.native_id == MACHINE_ID_E16C
	 * machine.native_id == MACHINE_ID_E2C3
	 * machine.native_id == MACHINE_ID_E48C
	 * machine.native_id == MACHINE_ID_E8V7
	 */
	return MEM_DDR4;
}

static void fill_info_about_channel(struct e2k_edac_dev *dev)
{
	if (use_cfg_reg) {
		e2k_mc_cfg_struct_t r;
		r.E2K_MC_CFG_reg = sic_get_mc_cfg(dev->node, dev->mcN);

		dev->dimm[0].num_side = r.fields.pbm0;
		dev->dimm[0].arch_size = 0;
		if (r.fields.pbm0) {
			dev->dimm[0].arch_size =
				get_chip_CFG_size(r.fields.ct0);
		}
		dev->dimm[1].num_side = r.fields.pbm1;
		dev->dimm[1].arch_size = 0;
		if (r.fields.pbm1) {
			dev->dimm[1].arch_size =
				get_chip_CFG_size(r.fields.ct1);
		}
		dev->m_type = get_chip_memory_type();
		dev->r_type = r.fields.rm;
		dev->w_type = get_chip_bus_width(r.fields.dqw);
		dev->freq = get_chip_speed(r.fields.sf);
	} else {
		e2k_mc_opmb_struct_t r;
		r.E2K_MC_OPMB_reg = sic_get_mc_opmb(dev->node, dev->mcN);

		dev->dimm[0].num_side = r.fields.pbm0;
		dev->dimm[0].arch_size = 0;
		if (r.fields.pbm0) {
			dev->dimm[0].arch_size =
				get_chip_OPMB_size(r.fields.ct0);
		}
		dev->dimm[1].num_side = r.fields.pbm1;
		dev->dimm[1].arch_size = 0;
		if (r.fields.pbm1) {
			dev->dimm[1].arch_size =
				get_chip_OPMB_size(r.fields.ct1);
		}
		dev->m_type = get_chip_memory_type();
		dev->r_type = r.fields.rm;
		dev->w_type = DEV_X4; /* no data */
		dev->freq = 0; /* no data */
	}
}


static int e2k_register_mci(struct e2k_edac_dev *e2k_edac_dev)
{
	struct mem_ctl_info *mci;
	struct edac_mc_layer layers[2];
	struct platform_device *pdev = e2k_edac_dev->pdev;
	struct e2k_mci_priv *priv;
	int rc, ret = -ENXIO;

	/* allocate & init EDAC MC data structure */
	layers[0].type = EDAC_MC_LAYER_CHANNEL;
	layers[0].size = 1;
	layers[0].is_virt_csrow = false;
	layers[1].type = EDAC_MC_LAYER_SLOT;
	layers[1].size = 2;
	layers[1].is_virt_csrow = true;

	mci = edac_mc_alloc(e2k_edac_dev->id, ARRAY_SIZE(layers), layers,
		sizeof(struct e2k_mci_priv));
	if (!mci) {
		ret = -ENOMEM;
		goto err;
	}

	e2k_edac_dev->mci = mci;

	mci->pdev = &pdev->dev;
	if (e2k_edac_dev->m_type == MEM_DDR4) {
		mci->mtype_cap = MEM_FLAG_DDR4;
	} else {
		mci->mtype_cap = MEM_FLAG_DDR3;
	}
	mci->edac_ctl_cap = EDAC_FLAG_SECDED;
	mci->edac_cap = EDAC_FLAG_SECDED;
	mci->scrub_cap = SCRUB_FLAG_HW_SRC;
	mci->scrub_mode = SCRUB_HW_SRC;
	mci->mod_name = "E2K ECC";
	mci->ctl_name = dev_name(&pdev->dev);
	mci->dev_name = dev_name(&pdev->dev);
	mci->edac_check = e2k_ecc_check;
	mci->ctl_page_to_phys = NULL;
	priv = mci->pvt_info;
	priv->dev = e2k_edac_dev; /* save ptr to myself */

	/* directly setup polling by default, very strange rule */
	edac_op_state = EDAC_OPSTATE_POLL;

	rc = init_csrows(e2k_edac_dev);
	if (rc) {
		e2k_err("failed to init csrows\n");
		ret = rc;
		goto err_free;
	}

	/* register with edac core */
	rc = edac_mc_add_mc(mci);
	if (rc) {
		e2k_err("failed to register with EDAC core\n");
		ret = rc;
		goto err_free;
	}

	return 0;

err_free:
	edac_mc_free(mci);
err:
	return ret;
}

static int e2k_unregister_mci(struct e2k_edac_dev *e2k_edac_dev)
{
	struct mem_ctl_info *mci = e2k_edac_dev->mci;

	mci = edac_mc_del_mc(mci->pdev);
	if (mci) {
		edac_mc_free(mci);
	}

	platform_device_unregister(e2k_edac_dev->pdev);

	return 0;
}

/*********************** main section ************************************/

static inline int cpu_supported(void)
{
	if (machine.native_id != MACHINE_ID_E1CP &&
	    machine.native_id != MACHINE_ID_E8C &&
	    machine.native_id != MACHINE_ID_E8C2 &&
	    machine.native_id != MACHINE_ID_E12C &&
	    machine.native_id != MACHINE_ID_E16C &&
	    machine.native_id != MACHINE_ID_E2C3 &&
	    machine.native_id != MACHINE_ID_E48C &&
	    machine.native_id != MACHINE_ID_E8V7)
		return 0;

	return 1;
}

static int __init e2k_edac_init(void)
{
	int ret = 0, i;
	const char *owner;
	struct e2k_edac_dev *e2k_edac_dev;
	int node;

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

	for_each_online_node(node) {
		for (i = 0; i < SIC_MC_COUNT; i++) {
			e2k_edac_dev = alloc_e2k_dev(node, i);
			if (!e2k_edac_dev) {
				e2k_err("alloc e2k err\n");
				ret = -ENOMEM;
				goto err;
			}
			fill_info_about_channel(e2k_edac_dev);
		}
	}

	list_for_each_entry(e2k_edac_dev, &e2k_edac_list, list) {
		ret = e2k_register_mci(e2k_edac_dev);
		if (ret) {
			e2k_err("register mci err\n");
			goto err;
		}
	}

	return 0;
err:
	list_for_each_entry(e2k_edac_dev, &e2k_edac_list, list) {
		e2k_unregister_mci(e2k_edac_dev);
	}

	return ret;
}

static void __exit e2k_edac_exit(void)
{
	struct e2k_edac_dev *e2k_edac_dev;

	list_for_each_entry(e2k_edac_dev, &e2k_edac_list, list) {
		e2k_unregister_mci(e2k_edac_dev);
	}
	e2k_free_all_devices();
}

module_init(e2k_edac_init);
module_exit(e2k_edac_exit);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("edac ECC driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(E2K_EDAC_REVISION);
