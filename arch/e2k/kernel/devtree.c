/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 MCST
 */

#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/slab.h>
#include <asm/bootinfo.h>
#include <asm/sclkr.h>
#include <asm-l/devtree.h>

static int __init e2k_of_add_property(struct device_node *np,
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

static struct device_node *__init e2k_add_node(struct device_node *parent,
			const char *path, struct property *proplist)
{
	struct device_node *np;
	int err = -ENOMEM;

	np = kzalloc(sizeof(*np), GFP_KERNEL);
	if (!np)
		goto out_err;

	np->full_name = kstrdup(kbasename(path), GFP_KERNEL);
	if (!np->full_name)
		goto out_err;

	np->properties = proplist;
	of_node_set_flag(np, OF_DYNAMIC);
	of_node_init(np);

	np->parent = parent;

	err = of_attach_node(np);
	if (err) {
		printk(KERN_ERR "Failed to add device node %s\n", path);
		goto out_err;
	}
	return np;
out_err:
	if (np) {
		kfree(np->full_name);
		kfree(np);
	}
	return ERR_PTR(err);
}

static int __init e2k_patch_clocksource(void)
{
	struct device_node *np_sclkr = NULL, *np_esclk = NULL;
	int ret = 0;

	/*
	 * Patch clocksource information into current device tree if it's missing
	 */
	const char sclkr_compatible[] = "mcst,sclkr-timer";
	const char esclk_compatible[] = "mcst,esclk-timer";
	np_sclkr = of_find_compatible_node(NULL, NULL, sclkr_compatible);
	np_esclk = of_find_compatible_node(NULL, NULL, esclk_compatible);
	if (np_sclkr || np_esclk) {
		if (np_sclkr)
			of_node_put(np_sclkr);
		if (np_esclk)
			of_node_put(np_esclk);
		return ret;
	}

#ifdef CONFIG_SCLKR_CLOCKSOURCE
	if (!cpu_has(CPU_FEAT_ISET_V7)) {
		struct device_node *np = e2k_add_node(of_root, "sclkr_timer", NULL);
		if (WARN_ON(IS_ERR(np)))
			return PTR_ERR(np);

		u32 freq_be32 = cpu_to_be32(sclkr_get_frequency());
		ret = e2k_of_add_property(np, "clock-frequency", &freq_be32, 4);

		return ret ?: e2k_of_add_property(np, "compatible",
				sclkr_compatible, sizeof(sclkr_compatible));
	}
#endif

	return 0;
}

int __init e2k_apply_device_tree_patches(void)
{
	if (IS_HV_GM()) /* we do not know user configuration */
		return 0;

	/*
	 * For guests can rely on QEMU to provide correct devtree,
	 * but for native execution due to backwards compatibility
	 * we must assume that provided devtree can miss clocksource
	 * information.  In that case we patch it in.
	 */
	if (WARN_ON(e2k_patch_clocksource()))
		return 0;

	return 0;
}

void __init early_device_tree_init(void)
{
	/* get cmdline from devtree */
	if (bootblock_virt->info.bios.devtree) {
		early_init_dt_scan(__va(bootblock_virt->info.bios.devtree));
	} else {
		early_init_dt_scan(__dtb_default_begin);
	}
}

void __init device_tree_init(void)
{
	if (bootblock_virt->info.bios.devtree)
		unflatten_device_tree();
	else /* We can not use unflatten_device_tree(): __dtb_start is in init section */
		unflatten_and_copy_device_tree();
}