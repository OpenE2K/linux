/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/irqchip.h>
#include <linux/irqdomain.h>

#include <asm/pic.h>

#include "io_pic.h"
#include "epic/io_epic.h"
#include "../../../e2k/kvm/ioepic.h"

#ifdef CONFIG_EPIC

static int epic_msi_set_vcpu_affinity(struct irq_data *data, void *vcpu_info)
{
	struct ioepic_vcpu_info *info = vcpu_info;
	struct irq_cfg *cfg = irqd_cfg(data);

	pci_msi_mask_irq(data);

	/* Restore host MSI configuration, when shutting down irq bypass */
	if (!info->valid) {
		irq_chip_compose_msi_msg(data, &info->msi);
		info->msi_valid = true;
	}

	if (!info->msi_valid)
		return -EINVAL;

	/*
	 * e2k does not support interrupt remapping: write guest vector and dest_id to device
	 * This might cause problems with VFIO (which assumes interrupt remapping)
	 */
	pci_write_msi_msg(data->irq, &info->msi);

	/* cfg->passthrough = info->valid; */

	pci_msi_unmask_irq(data);

	return 0;
}
#endif /* CONFIG_EPIC */

static struct irq_chip l_pci_msi_controller = {
	.name			= "PCI-MSI",
	.irq_ack		= irq_chip_ack_parent,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
#ifdef CONFIG_EPIC
	.irq_set_vcpu_affinity	= epic_msi_set_vcpu_affinity
#endif
};

static struct msi_domain_info l_pci_msi_domain_info = {
	.flags		= MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
				MSI_FLAG_PCI_MSIX,
	.chip		= &l_pci_msi_controller,
	.handler	= handle_edge_irq,
	.handler_name	= "edge",
};

static int l_msi_probe(struct platform_device *pdev)
{
	struct irq_domain *d, *prnt;
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	struct fwnode_handle *fn = of_node_to_fwnode(np);

	prnt = irq_find_host(of_irq_find_parent(np));
	BUG_ON(!prnt);

	d = pci_msi_create_irq_domain(fn, &l_pci_msi_domain_info, prnt);

	if (WARN(!d, "%pOF: Failed to create msi domain\n", np))
		return -1;

	platform_set_drvdata(pdev, d);

	return 0;
}

static int l_msi_remove(struct platform_device *pdev)
{
	struct irq_domain *d = platform_get_drvdata(pdev);

	irq_domain_remove(d);
	platform_set_drvdata(pdev, NULL);

	return 0;
}

static const struct of_device_id l_msi_dt_ids[] = {
	{.compatible = "mcst,l-msi"},
	{ /* sentinel value */ }
};

static struct platform_driver l_msi_driver = {
	.driver = {
		.name = "l-msi",
		.of_match_table = of_match_ptr(l_msi_dt_ids),
	},
	.probe    = l_msi_probe,
	.remove   = l_msi_remove,
};
module_platform_driver(l_msi_driver);

MODULE_LICENSE("GPL v2");
