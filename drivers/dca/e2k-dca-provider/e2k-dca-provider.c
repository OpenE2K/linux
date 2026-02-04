/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST.
 */

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/dca.h>
#include <asm/sic_regs.h>

/*
 * E2K DCA provider is used to support
 * a E2K DCA(TPH) mode in intel network cards.
 */
struct dca_slot {
	struct pci_dev *pdev;
};

#define DCA_MAX_REQ 8

struct dca_priv {
	int			max_requesters;
	int			requester_count;
	struct dca_slot	req_slots[DCA_MAX_REQ];
};

static const int hc_ctrl_regs[] = {
			(HC_CTRL),
			(SIC_xmu_a_hc_ctrl),
			(SIC_xmu_b_hc_ctrl),
			(SIC_xmu_c_hc_ctrl),
			(SIC_xmu_d_hc_ctrl)};

int is_e2k_dca_enabled(struct pci_dev *pdev)
{
	int rc;
	u32 reg;
	int i;
	int node;
	int domain;

	if (machine.native_id != MACHINE_ID_E48C) {
		dev_err(&pdev->dev, "E2K DCA is not supported by this CPU: %d\n",
			machine.native_id);
		return 1;
	}

	/* 5 domains: L(0),A(1),B(2),C(3),D(4) */
	domain = pci_domain_nr(pdev->bus);
	i = domain % 5;
	node = domain / 5;
	reg = sic_read_node_nbsr_reg(node, hc_ctrl_regs[i]);
	reg |= (HC_CTRL_DCAE);
	sic_write_node_nbsr_reg(node, hc_ctrl_regs[i], reg);
	reg = sic_read_node_nbsr_reg(node, hc_ctrl_regs[i]);
	rc = ((HC_CTRL_DCAE) & reg);
	if (!rc) {
		dev_err(&pdev->dev, "E2K DCA is disabled in XMU_%c(node %d)\n",
			       'A' + i, node);
		return 1;
	}

	reg &=  ~(HC_CTRL_WL3STE);
	sic_write_node_nbsr_reg(node, hc_ctrl_regs[i], reg);
	reg = sic_read_node_nbsr_reg(node, hc_ctrl_regs[i]);
	rc = ((HC_CTRL_WL3STE) & reg);
	if (rc) {
		dev_err(&pdev->dev, "STE is enabled in XMU_%c(node %d)\n",
			       'A' + i, node);
		return 1;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(is_e2k_dca_enabled);

static int e2k_dca_dev_managed(struct dca_provider *dca,
				struct device *dev)
{
	struct dca_priv *pdca = dca_priv(dca);
	struct pci_dev *pdev = to_pci_dev(dev);
	int i;

	for (i = 0; i < pdca->max_requesters; i++) {
		if (pdca->req_slots[i].pdev == pdev)
			return 1;
	}

	return 0;
}

static int e2k_dca_add_requester(struct dca_provider *dca, struct device *dev)
{
	struct dca_priv *pdca = dca_priv(dca);
	struct pci_dev *pdev = to_pci_dev(dev);
	int i;


	if (pdca->requester_count == pdca->max_requesters)
		return -ENODEV;

	for (i = 0; i < pdca->max_requesters; i++) {
		if (pdca->req_slots[i].pdev == NULL) {
			pdca->requester_count++;
			pdca->req_slots[i].pdev = pdev;
			dev_info(&pdev->dev, "E2K DCA requester %d added\n", i);
			return i;
		}
	}
	return -EFAULT;
}

static int e2k_dca_remove_requester(struct dca_provider *dca,
				      struct device *dev)
{
	struct dca_priv *pdca = dca_priv(dca);
	struct pci_dev *pdev = to_pci_dev(dev);
	int i;

	for (i = 0; i < pdca->max_requesters; i++) {
		if (pdca->req_slots[i].pdev == pdev) {
			pdca->req_slots[i].pdev = NULL;
			pdca->requester_count--;
			dev_info(&pdev->dev, "E2K DCA requester %d removed\n", i);
			return i;
		}
	}
	return -ENODEV;
}

static u8 e2k_dca_get_tag(struct dca_provider *dca,
			    struct device *dev, int cpu)
{
	return cpu_to_node(cpu);
}

static const struct dca_ops e2k_dca_ops = {
	.add_requester		= e2k_dca_add_requester,
	.remove_requester	= e2k_dca_remove_requester,
	.get_tag			= e2k_dca_get_tag,
	.dev_managed		= e2k_dca_dev_managed,
};

struct dca_provider *e2k_dca_provider_init(struct pci_dev *pdev)
{
	struct dca_provider *dca;
	struct dca_priv *pdca;
	int err;

	if (is_e2k_dca_enabled(pdev))
		return NULL;

	dca = alloc_dca_provider(&e2k_dca_ops, sizeof(struct dca_priv));
	if (!dca)
		return NULL;

	pdca = dca_priv(dca);
	pdca->max_requesters = DCA_MAX_REQ;

	err = register_dca_provider(dca, &pdev->dev);
	if (err) {
		free_dca_provider(dca);
		return NULL;
	}
	dev_info(&pdev->dev, "E2K DCA provider registered\n");

	return dca;
}
EXPORT_SYMBOL_GPL(e2k_dca_provider_init);

