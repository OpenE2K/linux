/*
 * Copyright (C) 2006 Ben Skeggs.
 * Copyright (c) 2012-2013 ZAO "MCST". All rights reserved.
 *
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER(S) AND/OR ITS SUPPLIERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

/*
 * Authors:
 *   Ben Skeggs <darktama@iinet.net.au>
 *   Alexander Troosh <troosh@mcst.ru>
 */

#include "drmP.h"
//#include "drm.h"
#include "mcst_drv.h"
#include "mcst_util.h"

void
mcst_irq_preinstall(struct drm_device *dev)
{
CH();
	/* Master disable */
	/* mcst_io_write32(dev, NV03_PMC_INTR_EN_0, 0); */
}

int
mcst_irq_postinstall(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;

CH();
	/* Master enable */
	/* mcst_io_write32(dev, NV03_PMC_INTR_EN_0,
			   NV_PMC_INTR_EN_0_MASTER_ENABLE); */
	if (mcst->msi_enabled) {
		/* mcst_io_write08(dev, 0x00088068, 0xff); */
	}

	return 0;
}

void
mcst_irq_uninstall(struct drm_device *dev)
{
	/* Master disable */
	/* mcst_io_write32(dev, NV03_PMC_INTR_EN_0, 0); */
CH();
}

irqreturn_t
mcst_irq_handler(DRM_IRQ_ARGS)
{
	struct drm_device *dev = (struct drm_device *)arg;
	struct mcst_private *mcst = dev->dev_private;
	irqreturn_t res = IRQ_NONE;
	unsigned long flags;
	u32 stat;
	int cell, i, cell_num;

	cell_num = (mcst->chip == MCST_MGA3D) ? 2 : 1;
	for (cell = 0; cell < cell_num; cell++) {
		stat = mcst_io_read32(mcst, cell, REG_STAT);
		if (stat == 0 || stat == ~0)
			continue;

		/* Masking all bits non interrupt */
		stat &= REG_STAT_IRQS_MASK;

		spin_lock_irqsave(&mcst->context_switch_lock, flags);
		for (i = 0; i < 32 && stat; i++) {
			if (!(stat & (1 << i)) || !mcst->irq_handler[cell][i])
				continue;

			mcst->irq_handler[cell][i](dev);
			stat &= ~(1 << i);
			res = IRQ_HANDLED;
		}
		if (mcst->msi_enabled) {
			/* mcst_io_write08(dev, 0x00088068, 0xff); */
		}
		spin_unlock_irqrestore(&mcst->context_switch_lock, flags);

		if (stat && mcst_ratelimit()) {
			DRM_ERROR("MGA unhandled INTR (cell=%d stat=0x%02x"
					"CTRL=0x%08x)\n", cell, stat,
					mcst_io_read32(mcst, cell, REG_CTRL));
		}
	}
	return res;
}

int
mcst_irq_init(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;
	int ret;

CH();
	if (mcst_msi != 0 && MCST_CARD_SUPPORT_MSI(mcst->chip)) {
		ret = pci_enable_msi(dev->pdev);
		if (ret == 0) {
			DRM_INFO("enabled MSI\n");
			mcst->msi_enabled = true;
		}
	}

	return drm_irq_install(dev);
}

void
mcst_irq_fini(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;

CH();
	drm_irq_uninstall(dev);
	if (mcst->msi_enabled)
		pci_disable_msi(dev->pdev);
}


void
mcst_irq_register(struct drm_device *dev, int cell, int status_bit,
		  void (*handler)(struct drm_device *))
{
	struct mcst_private *mcst = dev->dev_private;
	unsigned long flags;

CH();
	spin_lock_irqsave(&mcst->context_switch_lock, flags);
	mcst->irq_handler[cell][status_bit] = handler;
	spin_unlock_irqrestore(&mcst->context_switch_lock, flags);
}

void
mcst_irq_unregister(struct drm_device *dev, int cell, int status_bit)
{
	struct mcst_private *mcst = dev->dev_private;
	unsigned long flags;

CH();
	spin_lock_irqsave(&mcst->context_switch_lock, flags);
	mcst->irq_handler[cell][status_bit] = NULL;
	spin_unlock_irqrestore(&mcst->context_switch_lock, flags);
}
