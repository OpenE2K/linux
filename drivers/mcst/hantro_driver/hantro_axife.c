// SPDX-License-Identifier: GPL-2.0
/*
 *    Hantro axife controller hardware driver.
 *
 *    Copyright (c) 2017, VeriSilicon Inc.
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License, version 2, as
 *    published by the Free Software Foundation.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License version 2 for more details.
 *
 *    You may obtain a copy of the GNU General Public License
 *    Version 2 at the following locations:
 *    https://opensource.org/licenses/gpl-2.0.php
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>

#include "hantro_axife.h"
#include "hantro_device.h"
#include "ipoffset/axife_offset.h"

static struct axife_core_cfg axifecores[] = {                                                               
    { 0x000400, 64*4, 0, 0x000800 },                                                                 
};

static int axifeprobed;
long AxifeReadRegs(struct axife_t *dev, struct core_desc *core)
{
	u32 i;
	long ret = 0;

	i = core->reg_id;
	/* user has to know exactly what they are asking for */
	//if (core->size != (HANTRO_VC9000D_REGS * 4))
	//	return -EFAULT;

	/* read specific registers from hardware */
	for (i = core->reg_id; i < core->reg_id + core->size / 4; i++)
		dev->dec_regs[i] = ioread32(dev->hwregs + i * 4);

	/* put registers to user space*/
	ret = copy_to_user(core->regs, dev->dec_regs + core->reg_id,
			   core->size);
	if (ret) {
		pr_debug("copy_to_user failed, returned %li\n", ret);
		return -EFAULT;
	}
	return 0;
}

long AxifeWriteRegs(struct axife_t *dev, struct core_desc *core)
{
	u32 i;
	long ret = 0;

	i = core->reg_id;
	ret = copy_from_user(dev->dec_regs + core->reg_id,
			     core->regs, core->size);
	if (ret) {
		pr_debug("copy_from_user failed, returned %li\n", ret);
		return -EFAULT;
	}
	for (i = core->reg_id; i < core->reg_id + core->size / 4; i++)
		iowrite32(dev->dec_regs[i], dev->hwregs + i * 4);

	return 0;
}

void AXIFEEnable(volatile u8 __iomem *hwregs)
{
	if (!hwregs)
		return;

	//AXI FE pass through
	iowrite32(0x0, (void __iomem *)(hwregs + HANTRO_AXIFE_OFFSET +
						 AXI_REG11_SW_WORK_MODE));
	pr_info("AXI FE: 0x2C = 0x%x\n",
		ioread32((void __iomem *)(hwregs + AXI_REG11_SW_WORK_MODE)));
	iowrite32(0x2, (void __iomem *)(hwregs + HANTRO_AXIFE_OFFSET +
		 AXI_REG10_SW_FRONTEND_EN));
	pr_info("AXI FE: 0x28 = 0x%x\n",
		ioread32((void __iomem *)(hwregs + AXI_REG10_SW_FRONTEND_EN)));
}

int AXIFEFlush(volatile u8 __iomem *hwregs)
{
	int loop_cnt = 0;

	if (!hwregs)
		return 0;

	/* trigger AXI FE flush, AXI FE will automatically read or empty data in its
	 * Master side until the Master status is IDLE.
	 */
	iowrite32(0x01, (void __iomem *)(hwregs + 0x8C));
	pr_info("AXI FE: Flush Enable: 0x8C = 0x%x\n",
		ioread32((void __iomem *)(hwregs + 0x8C)));

	//polling read flush status(swreg[0]). If it is set to 1, means flush is completed.
	while (!(ioread32((void __iomem *)hwregs + AXI_REG0_SW_HWCFG) >> 31)) {
		loop_cnt++;
		mdelay(10); // wait 10ms
		if (loop_cnt > 20) { // too long
			pr_info("AXI FE: too long before axife flushed successfully\n");
			return -1;
		}
	}

	return 0;
}

int hantro_axife_probe(dtbnode *pnode, int loop, struct axife_t *axifecore)
{
	struct axife_t *paxife;

	if (loop == 0) {
#ifndef USE_DTB_PROBE
		int i;

		for (i = 0; i < ARRAY_SIZE(axifecores); i++) {
			paxife = vmalloc(sizeof(*paxife));
			if (!paxife)
				break;
			paxife->core_cfg = axifecores[i];
			add_axifenode(axifecores[i].sliceidx, paxife);
		}
#else //ndef USE_DTB_PROBE
		{
			paxife = vmalloc(sizeof(*paxife));
			if (!paxife)
				return -ENOMEM;
			paxife->core_cfg.axifecorebase = pnode->ioaddr;
			paxife->core_cfg.iosize = pnode->iosize;
			paxife->core_cfg.sliceidx = pnode->sliceidx;
			paxife->core_cfg.parentaddr = pnode->parentaddr;

			add_axifenode(pnode->sliceidx, paxife);
		}
#endif
	} else {
		if (!request_mem_region(axifecore->core_cfg.axifecorebase,
					axifecore->core_cfg.iosize,
					"hantroaxife")) {
			pr_err("axife: HW regs busy\n");
			return -ENODEV;
		}
		axifecore->hwregs = ioremap(axifecore->core_cfg.axifecorebase,
				    	    axifecore->core_cfg.iosize);
		if (!axifecore->hwregs) {
			release_mem_region(axifecore->core_cfg.axifecorebase,
					   axifecore->core_cfg.iosize);
			pr_err("axife: failed to map HW regs\n");
			return -ENODEV;
		}
		axifecore->dec_regs = vmalloc(axifecore->core_cfg.iosize);
		if (!axifecore->dec_regs)
			return -ENOMEM;

		AXIFEEnable(axifecore->hwregs);
	}

	return 0;
}

#if defined(CONFIG_MCST)
void hantro_axife_cleanup(void)
#else
void __exit hantro_axife_cleanup(void)
#endif
{
	int i, slicen = get_slicenumber();
	struct axife_t *dev, *pp;

	for (i = 0; i < slicen; i++) {
		dev = get_axifenodes(i, 0);
		while (dev) {
			if (dev->hwregs)
				release_mem_region(dev->core_cfg.axifecorebase,
						   dev->core_cfg.iosize);
			if (dev->dec_regs)
				vfree(dev->dec_regs);
			pp = dev->next;
			vfree(dev);
			dev = pp;
		}
	}
	axifeprobed = 0;
}

#if defined(CONFIG_MCST)
int hantroaxife_init(void)
#else
int __init hantroaxife_init(void)
#endif
{
	axifeprobed = 0;
	return 0;
}
