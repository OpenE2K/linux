/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#define DEBUG
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/nodemask.h>
#include <asm/bug.h>
#include <asm/page.h>
#include <asm/iolinkmask.h>
#include <asm/bootinfo.h>
#include <asm/pic.h>
#include "../../../drivers/of/of_private.h"

struct e2k_dtb {
	char *begin, *end;
};

typedef struct e2k_dtb dtb_t;

#define DTB_DECL(type)			\
	extern char __dtb_##type##_begin[];		\
	extern char __dtb_##type##_end[]

#define DTB(type)		{		\
		.begin = __dtb_##type##_begin,		\
		.end = __dtb_##type##_end		\
}


#ifdef CONFIG_CPU_E2S
DTB_DECL(e2s_1x1);
DTB_DECL(e2s_2x2);
DTB_DECL(e2s_4x4);
static dtb_t e2s_dtb_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e2s_1x1),
	[1] = DTB(e2s_2x2),
	[2] = DTB(e2s_4x4),
};
#else
#define e2s_dtb_patch NULL
#endif

#ifdef CONFIG_CPU_E1CP
DTB_DECL(e1cp);
static dtb_t e1cp_dtb_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e1cp),
};
#else
#define e1cp_dtb_patch NULL
#endif

#if defined(CONFIG_CPU_E8C) || defined(CONFIG_CPU_E8C2)
DTB_DECL(e8c_1x1);
DTB_DECL(e8c_2x2);
DTB_DECL(e8c_4x4);
static dtb_t e8c_dtb_10_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e8c_1x1),
	[1] = DTB(e8c_2x2),
	[2] = DTB(e8c_4x4),
};
DTB_DECL(e8c_11_1x1);
DTB_DECL(e8c_11_2x2);
DTB_DECL(e8c_11_4x4);
static dtb_t e8c_dtb_11_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e8c_11_1x1),
	[1] = DTB(e8c_11_2x2),
	[2] = DTB(e8c_11_4x4),
};
#else
#define e8c_dtb_patch NULL
#define e8c_dtb_10_patch NULL
#define e8c_dtb_11_patch NULL
#endif

#ifdef CONFIG_CPU_E2C3
DTB_DECL(e2c3);
static dtb_t e2c3_dtb_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e2c3),
};

DTB_DECL(e2c3_addr_cells2);
static dtb_t e2c3_dtb_acls2_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e2c3_addr_cells2),
};
#else
#define e2c3_dtb_patch NULL
#define e2c3_dtb_acls2_patch NULL
#endif

#if defined(CONFIG_CPU_E12C) || defined(CONFIG_CPU_E16C)
DTB_DECL(e16c_1x1);
DTB_DECL(e16c_2x2);
DTB_DECL(e16c_4x4);
static dtb_t e16c_dtb_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e16c_1x1),
	[1] = DTB(e16c_2x2),
	[2] = DTB(e16c_4x4),
};
#else
#define e16c_dtb_patch NULL
#endif

static dtb_t *e2k_dtb_patch[][2][3] __initdata = {
	[CPU_TYPE_E2S]      = { { NULL, e2s_dtb_patch  }, },
	[CPU_TYPE_E8C]	    = { { e8c_dtb_10_patch, e8c_dtb_11_patch }, },
	[CPU_TYPE_E1CP]	    = { { NULL, e1cp_dtb_patch }, },
	[CPU_TYPE_E8C2]	    = { { e8c_dtb_10_patch, e8c_dtb_11_patch }, },
	[CPU_TYPE_E12C]	    = { { NULL, e16c_dtb_patch }, },
	[CPU_TYPE_E16C]	    = { { NULL, e16c_dtb_patch }, },
	[CPU_TYPE_E2C3]	    = { { NULL, e2c3_dtb_patch }, { NULL, NULL, e2c3_dtb_acls2_patch }, },
};

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

static int __init e2k_of_disable_offline_iohubs(void)
{
	int ret = 0, i;
	struct device_node *np;
	char *dv[] = {"mcst,l-iommu", "mcst,ioapic", "mcst,l-pci",
			 "mcst,ioepic", "mcst,e2k-iommu"};

	for (i = 0; i < ARRAY_SIZE(dv); i++) {
		for_each_compatible_node(np, NULL, dv[i]) {
			int node = of_node_to_nid(np);
			if (node < 0 || iohub_online(node))
				continue;
			pr_debug("%d: %pOF disabled\n", node, np);
			ret = e2k_of_add_property(np, "status",
					"disabled", sizeof("disabled"));
			if (ret < 0)
				goto done;
		}
	}

done:
	return ret;
}

static int __init e2k_apply_legacy_dtb_patch(dtb_t *dtb)
{
	int ret, id;
	const struct e2k_dtb *b;
	unsigned long nr = num_online_nodes();
	unsigned long n = node_online_map.bits[0];

	BUILD_BUG_ON(!is_power_of_2(MAX_NUMNODES));
	BUILD_BUG_ON(BITS_TO_LONGS(ilog2(MAX_NUMNODES)) > 1);

	if (WARN_ON(!is_power_of_2(n + 1)))
		return -ENXIO;

	b = &dtb[ilog2(nr)];

	if (WARN(b->begin == NULL, "devtree: patch %ld not exist\n", nr))
		return -ENODEV;

	ret = of_overlay_fdt_apply(b->begin, b->end - b->begin, &id);
	if (WARN(ret, "devtree: %ld patch apply failed: %d\n",
			nr, ret)) {
		return ret;
	}
	if ((ret = e2k_of_disable_offline_iohubs()))
		return ret;

	return 0;
}

static int e2k_add_node(struct device_node *parent, const char *path, struct property *proplist)
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
	return 0;
out_err:
	if (np) {
		kfree(np->full_name);
		kfree(np);
	}
	return err;
}

struct property *e2k_prop_dup(struct device_node *np, char *name)
{
	struct property *p, *p2 = NULL;
	p = of_find_property(np, name, NULL);
	if (!p)
		goto out;
	p2 = __of_prop_dup(p, GFP_KERNEL);
	if (!p2)
		goto out;
out:
	return p2;
}

static void property_list_free(struct property *prop_list)
{
	struct property *prop, *next;

	for (prop = prop_list; prop != NULL; prop = next) {
		next = prop->next;
		kfree(prop->name);
		kfree(prop->value);
		kfree(prop);
	}
}

static int __e2k_patch_mga2(char *s)
{
	int ret;
	struct device_node *np;
	struct property *p;

	np = of_find_compatible_node(NULL, NULL, s);
	if (!np)
		return 0;
	p = e2k_prop_dup(np, "interrupt-parent");
	if (!p) {
		ret = -ENODEV;
		goto out;
	}
	p->next = e2k_prop_dup(np, "interrupts");
	if (!p->next) {
		ret = -ENOMEM;
		goto out;
	}

	ret = e2k_add_node(np, "auc", p);
out:
	of_node_put(np);
	if (ret)
		property_list_free(p);

	return ret;
}

/* Add auc node in order to save interrupt properties of mga2 node */
static int e2k_patch_mga2(void)
{
	int i, ret;
	char *s[] = { "mcst,mga20",  "mcst,mga25",  "mcst,mga26" };
	for (i = ret = 0; !ret && i < ARRAY_SIZE(s); i++)
		ret = __e2k_patch_mga2(s[i]);
	return ret;
}

/* We can not apply patches in device_tree_init(): memory is not ready yet */
int __init e2k_apply_device_tree_patches(void)
{
	int ret;
	/* Can't use GET_CPU_TYPE(): it returns 0 in guest kernel */
	int cpu = read_IDR_reg().mdl;
	int ac = of_n_addr_cells(of_root);
	int sc = of_n_size_cells(of_root);

	if (IS_HV_GM()) /* we do not know user configuration */
		return 0;

	if (cpu >= ARRAY_SIZE(e2k_dtb_patch))
		return 0;
	if (WARN_ON(ac <= 0))
		return 0;
	if (WARN_ON(ac > ARRAY_SIZE(e2k_dtb_patch[0])))
		return 0;
	if (WARN_ON(sc > ARRAY_SIZE(e2k_dtb_patch[0][0])))
		return 0;
	ac--;
	if (WARN(e2k_dtb_patch[cpu][ac][sc] == NULL,
			"No devtree patch: %d:%d:%d", cpu, ac, sc)) {
		return 0;
	}
	if (WARN_ON(e2k_patch_mga2()))
		return 0;
	ret = e2k_apply_legacy_dtb_patch(e2k_dtb_patch[cpu][ac][sc]);

	return ret;
}

DTB_DECL(e48c);

static struct e2k_dtb e2k_dtb[] __initdata = {
#ifdef CONFIG_CPU_E48C
	[CPU_TYPE_E48C]	    =  DTB(e48c),
#endif
#ifdef CONFIG_CPU_E8V7
	[CPU_TYPE_E8V7]	    =  DTB(e48c),
#endif
};

#ifdef CONFIG_KVM
DTB_DECL(epic_guest);
DTB_DECL(apic_guest);
#else
#define __dtb_apic_guest_begin NULL
#define __dtb_epic_guest_begin NULL
#endif

void __init early_device_tree_init(void)
{
	void *dt = NULL;
	extern char __dtb_default_begin[];
	unsigned cpu = GET_CPU_TYPE(bootblock_virt->info.cpu_type);

	if (bootblock_virt->info.devtree) {
		dt = __va(bootblock_virt->info.devtree);
	} else if (IS_HV_GM()) {
		dt = cpu_has_epic() ?
			__dtb_epic_guest_begin :
			__dtb_apic_guest_begin;
	} else if (cpu < ARRAY_SIZE(e2k_dtb) && e2k_dtb[cpu].begin) {
		dt = e2k_dtb[cpu].begin;
	} else {
		dt = __dtb_default_begin;
	}

	/* get cmdline from devtree */
	early_init_dt_scan(dt);
}

void __init device_tree_init(void)
{
	if (bootblock_virt->info.devtree)
		unflatten_device_tree();
	else /* We can not use unflatten_device_tree(): __dtb_start is in init section */
		unflatten_and_copy_device_tree();
}
