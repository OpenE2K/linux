/*
 * e8c* (P1, P9) EDAC ECC kernel module for e2k platforms
 *
 * Author: Alexey Mukhin <if@mcst.ru>
 * 2021 (c) MCST
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/edac.h>

#include <asm/io.h>
#include <asm/sic_regs.h>

#include "edac_module.h"

#define E2K_EDAC_REVISION	" Ver: 0.1"
#define E2K_EDAC_DRVNAME	"e2k_edac"

#define e2k_info(fmt, arg...) \
	edac_printk(KERN_INFO, "e2k", fmt, ##arg)

#define e2k_warn(fmt, arg...) \
	edac_printk(KERN_WARNING, "e2k", "Warning: " fmt, ##arg)

#define e2k_err(fmt, arg...) \
	edac_printk(KERN_ERR, "e2k", "Error: " fmt, ##arg)

/*********************** pci section *************************************/

/* not present */

/*********************** mem section *************************************/

/* not present */

/*********************** cpu section *************************************/

/* not present */

/*********************** ecc section *************************************/

typedef e2k_mc_ecc_struct_t ecc_struct_t;

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

struct e2k_edac_priv {
	struct edac_device_ctl_info *dci;
};


/* Check for ECC Errors */
static void e2k_ecc_check(struct edac_device_ctl_info *dci)
{
	static u16 last_ecc_ce[MAX_NUMNODES][SIC_MAX_MC_COUNT] = {};
	static u8  last_ecc_ue[MAX_NUMNODES][SIC_MAX_MC_COUNT] = {};

	int node, i;

	for_each_online_node(node) {
		for (i = 0; i < SIC_MC_COUNT; i++) {
			char s[256];
			ecc_struct_t ecc;
			u32 cnt = ecc_get_error_cnt(&ecc, node, i);

			if (!last_ecc_ue[node][i] && ecc.E2K_MC_ECC_ue) {
				e2k_err("node %d mc%d: unrecoverable error.\n",
					node, i);
				last_ecc_ue[node][i] = 1;
				edac_device_handle_ue(dci,
						      node, i, dci->ctl_name);
			}

			if ((cnt - last_ecc_ce[node][i]) == 0) {
				continue;
			}

			last_ecc_ce[node][i] = cnt;
			if (ecc.E2K_MC_ECC_of) {
				snprintf(s, 256, "(error buffer overflow)");
			}
			e2k_warn("node %d mc%d: correctable error. %s\n",
				 node, i, s);
			edac_device_handle_ce(dci, node, i, dci->ctl_name);
		}
	}
}

static int e2k_ecc_register(struct platform_device *pdev)
{
	struct e2k_edac_priv *p;

	p = devm_kzalloc(&pdev->dev, sizeof(*p), GFP_KERNEL);
	if (!p) {
		return -ENOMEM;
	}
	platform_set_drvdata(pdev, p);

	/*
	  unsigned sz_private,
	  char *edac_device_name, unsigned nr_instances,
	  char *edac_block_name,  unsigned nr_blocks,
	  unsigned offset_value, // zero, 1, or other based offset
	  struct edac_dev_sysfs_block_attribute *attrib_spec,
	  unsigned nr_attrib,
	  int device_index
	*/
	p->dci = edac_device_alloc_ctl_info(0,
					    "e2k_node", num_online_nodes(),
					    "e2k_mc", SIC_MC_COUNT,
					    0, NULL, 0,
					    edac_device_alloc_index());
	if (!p->dci) {
		return -ENOMEM;
	}

	p->dci->dev = &pdev->dev;
	p->dci->mod_name = "E2K ECC Manager";
	p->dci->ctl_name = dev_name(&pdev->dev);
	p->dci->dev_name = dev_name(&pdev->dev);
	p->dci->edac_check = e2k_ecc_check;

	if (edac_device_add_device(p->dci)) {
		dev_err(p->dci->dev, "failed to register with EDAC core\n");
		goto err;
	}

	return 0;

err:
	edac_device_free_ctl_info(p->dci);

	return -ENXIO;
}

static int e2k_ecc_unregister(struct platform_device *pdev)
{
	struct e2k_edac_priv *p = platform_get_drvdata(pdev);

	edac_device_del_device(&pdev->dev);
	edac_device_free_ctl_info(p->dci);

	return 0;
}

/*********************** main section ************************************/

static struct platform_device *e2k_pdev;

static int __init e2k_edac_init(void)
{
	int ret = 0;
	const char *owner;

	owner = edac_get_owner();
	if (owner &&
	    strncmp(owner, E2K_EDAC_DRVNAME, sizeof(E2K_EDAC_DRVNAME))) {
		e2k_info("E2K EDAC driver " E2K_EDAC_REVISION " - busy\n");
		return -EBUSY;
	}

	e2k_info("E2K EDAC driver " E2K_EDAC_REVISION "\n");

	if (!ecc_supported()) {
		e2k_info("ECC not supported\n");
		return -ENODEV;
	}

	if (!ecc_enabled()) {
		e2k_info("ECC not enabled\n");
		return -ENODEV;
	}

	e2k_pdev = platform_device_register_simple(E2K_EDAC_DRVNAME, 0,
						   NULL, 0);
	if (IS_ERR(e2k_pdev)) {
		return PTR_ERR(e2k_pdev);
	}

	ret = e2k_ecc_register(e2k_pdev);
	if (ret) {
		platform_device_unregister(e2k_pdev);
	}

	return ret;

}

static void __exit e2k_edac_exit(void)
{
	e2k_ecc_unregister(e2k_pdev);
	platform_device_unregister(e2k_pdev);
}

module_init(e2k_edac_init);
module_exit(e2k_edac_exit);

MODULE_AUTHOR("Alexey Mukhin, MCST");
MODULE_DESCRIPTION("e8c/e8c2 edac ECC driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(E2K_EDAC_REVISION);
