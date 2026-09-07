/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/of_platform.h>

static int e2k_of_add_property(struct device_node *np,
					  const char *name, const void *value,
					  int length)
{
	struct property *prop;
	int ret = -ENOMEM;

	prop = kzalloc(sizeof(*prop), GFP_KERNEL);
	if (!prop)
		return -ENOMEM;

	prop->name = kstrdup(name, GFP_KERNEL);
	if (!prop->name)
		goto out_err;

	prop->value = kmemdup(value, length, GFP_KERNEL);
	if (!prop->value)
		goto out_err;

	prop->length = length;

	ret = of_add_property(np, prop);
	if (!ret)
		return 0;

out_err:
	return ret;
}

static int e2k_of_ranges_patch(struct pci_dev *pdev)
{
	int ret, i, j = 0;
	unsigned long bar_msk;
	struct device *dev = &pdev->dev;
	struct device_node *np, *dn = dev->of_node;
	struct ranges {
		__be32 chld_addr[2];
		__be32 prnt_addr[3];
		__be32 chld_sz[1];
	} r[PCI_NUM_RESOURCES] = {};

	int ns, na, pna = of_n_addr_cells(dn);
	np = of_get_next_child(dn, NULL);
	na = of_n_addr_cells(np);
	ns = of_n_size_cells(np);
	if (WARN(pna != ARRAY_SIZE(r[0].prnt_addr) ||
			na != ARRAY_SIZE(r[0].chld_addr) ||
			ns != ARRAY_SIZE(r[0].chld_sz),
			"Wrong cells nr: %pOF: %d %pOF: %d %d\n",
			dn, pna, np, na, ns)) {
		ret = -ERANGE;
		goto out;
	}

	/*ranges = <  0 0   child address
			0 0 0  parent address
			0>;    child size */
	bar_msk = pci_select_bars(pdev, IORESOURCE_MEM);
	for_each_set_bit(i, &bar_msk, PCI_NUM_RESOURCES) {
		r[j].chld_addr[0] = cpu_to_be32(i); /*bar nr*/
		r[j].prnt_addr[2] = cpu_to_be32(pci_resource_start(pdev, i));
		r[j].chld_sz[0]   = cpu_to_be32(pci_resource_len(pdev, i));
		j++;
	}
	ret = e2k_of_add_property(dn, "ranges", r, sizeof(r));
	if (ret < 0)
		goto out;
out:
	of_node_put(np);
	return ret;
}

static int gpio_mvp_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int ret;
	struct device *dev = &pdev->dev;
	if (!of_get_next_child(dev->of_node, NULL))
		return -ENODEV;

	ret = e2k_of_ranges_patch(pdev);
	if (WARN_ON(ret))
		goto err;

	ret = devm_of_platform_populate(dev);
	if (WARN_ON(ret))
		goto err;
err:
	return ret;
}

static void gpio_mvp_pci_remove(struct pci_dev *pdev)
{
	struct property *prop;
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;

	prop = of_find_property(np, "range", NULL);
	of_remove_property(np, prop);
}

static const struct pci_device_id gpio_mvp_pci_id_list[] = {
	{ PCI_VDEVICE(MCST_TMP, PCI_DEVICE_ID_MCST_GPIO_MPV_EIOH) },
	{ PCI_VDEVICE(MCST_TMP, PCI_DEVICE_ID_MCST_GPIO_MPV) },
	{ PCI_DEVICE(PCI_AC97GPIO_VENDOR_ID_ELBRUS,
		    PCI_AC97GPIO_DEVICE_ID_ELBRUS),},
	{},
};
MODULE_DEVICE_TABLE(pci, gpio_mvp_pci_id_list);

static struct pci_driver gpio_mvp_pci_driver = {
	.name = "gpio-mpv",
	.id_table = gpio_mvp_pci_id_list,
	.probe = gpio_mvp_pci_probe,
	.remove = gpio_mvp_pci_remove,

};
module_pci_driver(gpio_mvp_pci_driver);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("Elbrus gpio-mpv main driver");
MODULE_LICENSE("GPL v2");
