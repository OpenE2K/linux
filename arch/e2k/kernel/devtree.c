/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/init.h>
#include <linux/export.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/memblock.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/phy.h>

#include <asm/bootinfo.h>
#include <asm/page.h>
#include <asm/e2k_api.h>

#include <asm-l/devtree.h>

int devtree_detected = 1;


void * __init early_init_dt_alloc_memory_arch(u64 size, u64 align)
{
	return memblock_alloc(size, align);
}

/*
 * This function will create device nodes in sysfs coresponding to nodes
 * described in dtb.
 */
int __init e2k_publish_devices(void)
{
	if (!of_have_populated_dt()) {
		return 0;
	}
	return of_platform_populate(NULL, of_default_bus_match_table,
					NULL, NULL);
}
device_initcall(e2k_publish_devices);

static u64 get_device_tree_addr(void)
{
	return bootblock_virt->info.bios.devtree;
}

u32 get_dtb_size(void)
{
	u32 *blob_addr = (u32 *)get_device_tree_addr();
	u32 dtb_data = boot_readl((void __iomem *)blob_addr);
	u32 magic = OF_DT_HEADER;

	if (be32_to_cpu(dtb_data) != magic) {
		printk(KERN_ERR "DevTree: disabled (incorrect magic): %x\n",
				dtb_data);
		return 0;
	}
	dtb_data = boot_readl((void __iomem *)(blob_addr + 1));

	return __be32_to_cpu(dtb_data);
}

void get_dtb_from_boot(u8 *blob, u32 len)
{
	u32 *blob_addr = (u32 *)get_device_tree_addr();
	u8 *dtb_ptr = (u8 *)blob_addr;
	int i;

	for (i = 0; i < len; i++) {
		u8 dt = boot_readb((void __iomem *)dtb_ptr);
		blob[i] = dt;
		dtb_ptr++;
	}

	return;
}

int __init device_tree_init(void)
{
#ifdef CONFIG_DTB_L_TEST
	initial_boot_params = (struct boot_param_header *)test_blob;
#else
	u32 sz = get_dtb_size();
	if (sz == 0) {
		printk(KERN_ERR "DevTree: device tree size is 0\n");
		devtree_detected = 0;
		return -1;
	} else {
		printk(KERN_INFO "DevTree: device tree size is %d\n", sz);
	}

	u8 *dt = memblock_alloc(sz, SMP_CACHE_BYTES);
	if (dt == NULL) {
		printk(KERN_ERR "DevTree: not enough memory\n");
		devtree_detected = 0;
		return -2;
	}

	get_dtb_from_boot(dt, sz);

	initial_boot_params = (struct boot_param_header *)dt;
#endif
	unflatten_device_tree();
	return 0;
}
