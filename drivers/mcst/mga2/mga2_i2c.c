/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include "mga2_drv.h"
#include <linux/platform_data/i2c-l-i2c2.h>


static int dev_is_type(struct device *dev, void *type)
{
	if (dev->type == type)
		return 1;
	return 0;
}

static struct device *dev_find_type(struct device *parent, void *type)
{
	if (dev_is_type(parent, type)) {
		get_device(parent);
		return parent;
	}
	return device_find_child(parent, type, dev_is_type);
}

static struct resource res_parent;

struct i2c_adapter *mga2_i2c_create(struct device *parent,
			resource_size_t regs_phys,
			char *name, unsigned base_freq_hz,
			unsigned desired_freq_hz)
{
	struct device *d;
	struct platform_device *p;

	struct resource r[] = {
		{
			.parent = &res_parent,
			.flags	= IORESOURCE_MEM,
			.start	= regs_phys,
			.end	= regs_phys + 0x20 - 1
		},
	};
	struct l_i2c2_platform_data mga2_i2c = {
		.bus_nr	         = -1,
		.base_freq_hz    = base_freq_hz,
		.desired_freq_hz = desired_freq_hz,
		.two_stage_register_access = true,
	};
	/*
	 * HACK: void insert_resource() call failure in platform_device_add().
	*/
	memset(&res_parent, 0, sizeof(res_parent));
	res_parent.end   = ULONG_MAX;
	res_parent.flags = IORESOURCE_MEM;
	p = platform_device_register_resndata(parent,
				"mga2-i2c", PLATFORM_DEVID_AUTO, r,
				ARRAY_SIZE(r),
				&mga2_i2c, sizeof(mga2_i2c));
	if (IS_ERR(p)) {
		DRM_ERROR("failed to register mga2-i2c (%ld)\n", PTR_ERR(p));
		return NULL;
	}

	d = dev_find_type(&p->dev, &i2c_adapter_type);
	if (!d)
		return NULL;
	return to_i2c_adapter(d);
}

void mga2_i2c_destroy(struct i2c_adapter *adapter)
{
	struct device *d = &adapter->dev;
	if (!adapter)
		return;
	put_device(d); /* for dev_find_type() above */
	platform_device_unregister(to_platform_device(d->parent));
}
