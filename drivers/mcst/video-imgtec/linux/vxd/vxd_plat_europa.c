/*!
 *****************************************************************************
 *
 * @File       vxd_plat_europa.c
 * ---------------------------------------------------------------------------
 *
 * Copyright (c) Imagination Technologies Ltd.
 *
 * The contents of this file are subject to the MIT license as set out below.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 ("GPL")in which case the provisions of
 * GPL are applicable instead of those above.
 *
 * If you wish to allow use of your version of this file only under the terms
 * of GPL, and not to allow others to use your version of this file under the
 * terms of the MIT license, indicate your decision by deleting the provisions
 * above and replace them with the notice and other provisions required by GPL
 * as set out in the file called "GPLHEADER" included in this distribution. If
 * you do not delete the provisions above, a recipient may use your version of
 * this file under the terms of either the MIT license or GPL.
 *
 * This License is also included in this distribution in the file called
 * "MIT_COPYING".
 *
 *****************************************************************************/

#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>

#include <img_mem_man.h>
#include "vxd_plat.h"
#include "vxd_plat_dt.h"

const unsigned long vxd_plat_poll_udelay = 100;

const struct of_device_id vxd_plat_dt_of_ids[] = {
	{ .compatible = "img,d5500-vxd" },
	{ }
};

static struct heap_config europa_heap_configs[] = {
	{
		.type = IMG_MEM_HEAP_TYPE_UNIFIED,
		.options.unified = {
			.gfp_type = GFP_KERNEL | __GFP_ZERO,
		},
		.to_dev_addr = NULL,
	},
	{
		.type = IMG_MEM_HEAP_TYPE_DMABUF,
		.to_dev_addr = NULL,
	},
};


int vxd_plat_dt_hw_init(struct platform_device *pdev,
			struct heap_config **heap_configs, int *num_heaps)
{
	struct device *dev = &pdev->dev;
	int ret;

	dev_dbg(dev, "%s dma_get_mask : %#llx\n", __func__, dma_get_mask(dev));
	if (dev->dma_mask) {
		dev_info(dev, "%s dev->dma_mask : %p : %#llx\n",
			 __func__, dev->dma_mask, *dev->dma_mask);
	} else {
		dev_info(dev, "%s mask unset, setting coherent\n", __func__);
		dev->dma_mask = &dev->coherent_dma_mask;
	}
	ret = dma_set_mask(dev, dma_get_mask(dev));
	if (ret) {
		dev_err(dev, "%s failed to set dma mask\n", __func__);
		return ret;
	}

	*heap_configs = europa_heap_configs;
	*num_heaps = sizeof(europa_heap_configs)/sizeof(struct heap_config);
	return 0;
}

void vxd_plat_dt_hw_destroy(struct platform_device *pdev)
{
}

int vxd_plat_dt_hw_suspend(struct platform_device *pdev)
{
	return 0;
}

int vxd_plat_dt_hw_resume(struct platform_device *pdev)
{
	return 0;
}

MODULE_DEVICE_TABLE(of, vxd_plat_dt_of_ids);
