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
#include <linux/swiotlb.h>
#include <asm/bug.h>
#include <asm/page.h>
#include <asm/iolinkmask.h>
#include <asm/bootinfo.h>
#include <asm/pic.h>
#include <asm/sclkr.h>
#include <asm/l-iommu.h>
#include <asm-l/setup.h>
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
DTB_DECL(e2s_a1s1_1x1);
DTB_DECL(e2s_a1s1_2x2);
DTB_DECL(e2s_a1s1_4x4);
static dtb_t e2s_dtb_a1s1_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e2s_a1s1_1x1),
# ifdef CONFIG_NUMA
	[1] = DTB(e2s_a1s1_2x2),
	[2] = DTB(e2s_a1s1_4x4),
# endif
};
#else
#define e2s_dtb_a1s1_patch NULL
#endif

#ifdef CONFIG_CPU_E1CP
DTB_DECL(e1cp_a1s1);
static dtb_t e1cp_dtb_a1s1_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e1cp_a1s1),
};
#else
#define e1cp_dtb_a1s1_patch NULL
#endif

#if defined(CONFIG_CPU_E8C)
DTB_DECL(e8c_a1s0_1x1);
DTB_DECL(e8c_a1s0_2x2);
DTB_DECL(e8c_a1s0_4x4);
static dtb_t e8c_dtb_a1s0_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e8c_a1s0_1x1),
# ifdef CONFIG_NUMA
	[1] = DTB(e8c_a1s0_2x2),
	[2] = DTB(e8c_a1s0_4x4),
# endif
};
DTB_DECL(e8c_a1s1_1x1);
DTB_DECL(e8c_a1s1_2x2);
DTB_DECL(e8c_a1s1_4x4);
static dtb_t e8c_dtb_a1s1_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e8c_a1s1_1x1),
# ifdef CONFIG_NUMA
	[1] = DTB(e8c_a1s1_2x2),
	[2] = DTB(e8c_a1s1_4x4),
# endif
};
DTB_DECL(e8c_a2s2_1x1);
DTB_DECL(e8c_a2s2_2x2);
DTB_DECL(e8c_a2s2_4x4);
static dtb_t e8c_dtb_a2s2_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e8c_a2s2_1x1),
# ifdef CONFIG_NUMA
	[1] = DTB(e8c_a2s2_2x2),
	[2] = DTB(e8c_a2s2_4x4),
# endif
};
#else
#define e8c_dtb_a1s0_patch NULL
#define e8c_dtb_a1s1_patch NULL
#define e8c_dtb_a2s2_patch NULL
#endif

#if defined(CONFIG_CPU_E8C2)
DTB_DECL(e8c2_a1s0_1x1);
DTB_DECL(e8c2_a1s0_2x2);
DTB_DECL(e8c2_a1s0_4x4);
static dtb_t e8c2_dtb_a1s0_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e8c2_a1s0_1x1),
# ifdef CONFIG_NUMA
	[1] = DTB(e8c2_a1s0_2x2),
	[2] = DTB(e8c2_a1s0_4x4),
# endif
};
DTB_DECL(e8c2_a1s1_1x1);
DTB_DECL(e8c2_a1s1_2x2);
DTB_DECL(e8c2_a1s1_4x4);
static dtb_t e8c2_dtb_a1s1_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e8c2_a1s1_1x1),
# ifdef CONFIG_NUMA
	[1] = DTB(e8c2_a1s1_2x2),
	[2] = DTB(e8c2_a1s1_4x4),
# endif
};
DTB_DECL(e8c2_a2s2_1x1);
DTB_DECL(e8c2_a2s2_2x2);
DTB_DECL(e8c2_a2s2_4x4);
static dtb_t e8c2_dtb_a2s2_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e8c2_a2s2_1x1),
# ifdef CONFIG_NUMA
	[1] = DTB(e8c2_a2s2_2x2),
	[2] = DTB(e8c2_a2s2_4x4),
# endif
};
#else
#define e8c2_dtb_a1s0_patch NULL
#define e8c2_dtb_a1s1_patch NULL
#define e8c2_dtb_a2s2_patch NULL
#endif

#ifdef CONFIG_CPU_E2C3
DTB_DECL(e2c3_a1s1);
static dtb_t e2c3_dtb_a1s1_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e2c3_a1s1),
};

DTB_DECL(e2c3_a2s2);
static dtb_t e2c3_dtb_a2s2_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e2c3_a2s2),
};
#else
#define e2c3_dtb_a1s1_patch NULL
#define e2c3_dtb_a2s2_patch NULL
#endif

#if defined(CONFIG_CPU_E12C) || defined(CONFIG_CPU_E16C)
DTB_DECL(e16c_a1s1_1x1);
DTB_DECL(e16c_a1s1_2x2);
DTB_DECL(e16c_a1s1_4x4);
static dtb_t e16c_dtb_a1s1_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e16c_a1s1_1x1),
# ifdef CONFIG_NUMA
	[1] = DTB(e16c_a1s1_2x2),
	[2] = DTB(e16c_a1s1_4x4),
# endif
};
DTB_DECL(e16c_a2s2_1x1);
DTB_DECL(e16c_a2s2_2x2);
DTB_DECL(e16c_a2s2_4x4);
static dtb_t e16c_dtb_a2s2_patch[ilog2(MAX_NUMNODES) + 1] __initdata = {
	[0] = DTB(e16c_a2s2_1x1),
# ifdef CONFIG_NUMA
	[1] = DTB(e16c_a2s2_2x2),
	[2] = DTB(e16c_a2s2_4x4),
# endif
};
#else
#define e16c_dtb_a1s1_patch NULL
#define e16c_dtb_a2s2_patch NULL
#endif

static dtb_t *e2k_dtb_patch[][2][3] __initdata = {
	[CPU_TYPE_E2S]      = { { NULL, e2s_dtb_a1s1_patch  }, },
	[CPU_TYPE_E8C]	    = { { e8c_dtb_a1s0_patch, e8c_dtb_a1s1_patch },
				{ NULL, NULL, e8c_dtb_a2s2_patch }, },
	[CPU_TYPE_E1CP]	    = { { NULL, e1cp_dtb_a1s1_patch }, },
	[CPU_TYPE_E8C2]	    = { { e8c2_dtb_a1s0_patch, e8c2_dtb_a1s1_patch },
				{ NULL, NULL, e8c2_dtb_a2s2_patch }, },
	[CPU_TYPE_E12C]	    = { { NULL, e16c_dtb_a1s1_patch },
				{ NULL, NULL, e16c_dtb_a2s2_patch }, },
	[CPU_TYPE_E16C]	    = { { NULL, e16c_dtb_a1s1_patch },
				{ NULL, NULL, e16c_dtb_a2s2_patch }, },
	[CPU_TYPE_E2C3]	    = { { NULL, e2c3_dtb_a1s1_patch },
				{ NULL, NULL, e2c3_dtb_a2s2_patch }, },
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

static struct property * __init e2k_prop_dup(struct device_node *np, char *name)
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

static int __init __e2k_patch_mga2(char *s)
{
	int ret = 0;
	struct property *p;
	struct device_node *np, *np_child;

	np = of_find_compatible_node(NULL, NULL, s);
	if (!np)
		return 0;
	np_child = of_get_child_by_name(np, "auc");
	if (np_child) {
		of_node_put(np_child);
		goto out;
	}
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

	np_child = e2k_add_node(np, "auc", p);
	ret = PTR_ERR_OR_ZERO(np_child);
out:
	of_node_put(np);
	if (ret)
		property_list_free(p);

	return ret;
}

/* Add auc node in order to save interrupt properties of mga2 node */
static int __init e2k_patch_mga2(void)
{
	int i, ret;
	char *s[] = { "mcst,mga20",  "mcst,mga25",  "mcst,mga26" };
	for (i = ret = 0; !ret && i < ARRAY_SIZE(s); i++)
		ret = __e2k_patch_mga2(s[i]);
	return ret;
}

/* We have to add backup property to device trees v2.0 for
 compatibility with old linux and renamed it here */
static int __init __e2k_patch_mga2_2dot0(char *s)
{
	int ret = 0;
	char *newname = NULL;
	struct property *p, *p2 = NULL;
	struct device_node *np;

	np = of_find_compatible_node(NULL, NULL, s);
	if (!np)
		return 0;

	p = of_find_property(np, "interrupts-extended-backup", NULL);
	if (!p)
		return 0;

	p2 = __of_prop_dup(p, GFP_KERNEL);
	if (!p2)
		goto out;

	newname = kstrdup("interrupts-extended", GFP_KERNEL);
	if (newname == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	kfree(p2->name);
	p2->name = newname;

	ret = of_add_property(np, p2);
	if (ret)
		goto out;
out:
	of_node_put(np);
	if (ret) {
		kfree(newname);
		property_list_free(p2);
	}

	return ret;
}

/* Add auc node in order to save interrupt properties of mga2 node */
static int __init e2k_patch_mga2_2dot0(void)
{
	int i, ret;
	char *s[] = { "mcst,mga20",  "mcst,mga25",  "mcst,mga26" };
	for (i = ret = 0; !ret && i < ARRAY_SIZE(s); i++)
		ret = __e2k_patch_mga2_2dot0(s[i]);
	return ret;
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

		__be32 freq_be32 = cpu_to_be32(sclkr_get_frequency());
		ret = e2k_of_add_property(np, "clock-frequency", &freq_be32, 4);

		return ret ?: e2k_of_add_property(np, "compatible",
				sclkr_compatible, sizeof(sclkr_compatible));
	}
#endif
#ifdef CONFIG_ESCLKR_CLOCKSOURCE
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		struct device_node *np = e2k_add_node(of_root, "esclk_timer", NULL);
		if (WARN_ON(IS_ERR(np)))
			return PTR_ERR(np);

		return e2k_of_add_property(np, "compatible",
				esclk_compatible, sizeof(esclk_compatible));
	}
#endif

	return 0;
}

static bool __initdata l_no_iommu = 0;

static int __init l_iommu_setup(char *str)
{
	if (!strcmp(str, "no") || !strcmp(str, "0"))
		l_no_iommu = 1;

	return 1;
}
__setup("iommu=", l_iommu_setup);

static int __init e2k_patch_iommu(void)
{
	int ret = 0, i, node, domain;
	struct device_node *np;
	char *dv[] = {"mcst,l-iommu", "mcst,e2k-iommu"};
	if ((cpu_has(CPU_HWBUG_CANNOT_DO_DMA_IN_NEIGHBOUR_NODE) &&
			nr_online_nodes > 1) ||
		(cpu_has(CPU_HWBUG_CANNOT_DO_DMA_THROUGH_LINKS_B_AND_C) &&
			nr_online_nodes > 2)) {
		l_no_iommu = 1;
	}
	if (l_no_iommu == 0)
		return 0;

	for (i = 0; i < ARRAY_SIZE(dv); i++) {
		for_each_compatible_node(np, NULL, dv[i]) {
			pr_debug("%pOF disabled\n", np);
			ret = e2k_of_add_property(np, "status",
					"disabled", sizeof("disabled"));
			if (ret < 0)
				goto done;
		}
	}
	for_each_online_iohub(domain) {
		node = iohub_domain_to_node(domain);
#if defined(CONFIG_E2K) && defined(CONFIG_NUMA)
		swiotlb_init_late(L_SWIOTLB_DEFAULT_SIZE, GFP_DMA, NULL, node);
#else
		swiotlb_init_late(L_SWIOTLB_DEFAULT_SIZE, GFP_DMA, NULL);
#endif
	}

done:
	return ret;
}

/* We can not apply patches in device_tree_init(): memory is not ready yet */
int __init e2k_apply_device_tree_patches(void)
{
	int ret;
	unsigned long ver = 0;
	const char *version;
	/* Can't use GET_CPU_TYPE(): it returns 0 in guest kernel */
	int cpu = read_IDR_reg().mdl;
	int ac = of_n_addr_cells(of_root);
	int sc = of_n_size_cells(of_root);

	if (IS_HV_GM()) /* we do not know user configuration */
		goto out;

	ret = of_property_read_string(of_root, "version", &version);
	if (ret == 0) {
		ver = simple_strtoul(version, NULL, 10);
		pr_info("devtree version: %s (%ld)\n", version, ver);
		if (ver >= 2) /*version >= 2.0 does not need any patches*/
			goto out;
	}
	/*
	 * For guests can rely on QEMU to provide correct devtree,
	 * but for native execution due to backwards compatibility
	 * we must assume that provided devtree can miss clocksource
	 * information.  In that case we patch it in.
	 */
	if (WARN_ON(e2k_patch_clocksource()))
		return 0;

	if (cpu >= ARRAY_SIZE(e2k_dtb_patch))
		goto out;
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
	if (ret)
		return 0;
out:
	if (WARN_ON(e2k_patch_iommu()))
		return 0;
	if (WARN_ON(e2k_patch_mga2_2dot0()))
		return 0;

	return 0;
}

#ifdef CONFIG_CPU_E48C
DTB_DECL(e48c_a2s2);
#endif
#ifdef CONFIG_CPU_E8V7
DTB_DECL(e8v7_a2s2);
#endif
static struct e2k_dtb e2k_dtb[] __initdata = {
#ifdef CONFIG_CPU_E48C
	[CPU_TYPE_E48C]	    =  DTB(e48c_a2s2),
#endif
#ifdef CONFIG_CPU_E8V7
	[CPU_TYPE_E8V7]	    =  DTB(e8v7_a2s2),
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
