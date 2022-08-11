/*!
 *****************************************************************************
 *
 * @File       vxd_plat_dt.c
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


#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/io.h>
#include <linux/pm.h>

#include <img_mem_man.h>
#include "vxd_common.h"
#include "vxd_plat.h"
#include "vxd_plat_dt.h"

#define DEVICE_NAME "vxd"

static irqreturn_t dt_plat_thread_irq(int irq, void *dev_id)
{
	struct platform_device *ofdev = (struct platform_device *)dev_id;

	return vxd_handle_thread_irq(&ofdev->dev);
}

static irqreturn_t dt_plat_isrcb(int irq, void *dev_id)
{
	struct platform_device *ofdev = (struct platform_device *)dev_id;

	if (!ofdev)
		return IRQ_NONE;

	return vxd_handle_irq(&ofdev->dev);
}

static int vxd_plat_probe(struct platform_device *ofdev)
{
	struct heap_config *heap_configs;
	int num_heaps;
	int ret, reg_size, module_irq;
	struct resource res;
	void __iomem *reg_addr;

	ret = of_address_to_resource(ofdev->dev.of_node, 0, &res);
	if (ret) {
		dev_err(&ofdev->dev, "missing 'reg' property in device tree\n");
		return ret;
	}
	pr_info("%s: registers %#llx-%#llx\n", __func__,
		(unsigned long long)res.start, (unsigned long long)res.end);

	module_irq = irq_of_parse_and_map(ofdev->dev.of_node, 0);
	if (module_irq == 0) {
		dev_err(&ofdev->dev, "could not map IRQ\n");
		return -ENXIO;
	}

	reg_size = res.end - res.start + 1;

	reg_addr = devm_ioremap(&ofdev->dev, res.start, reg_size);
	if (!reg_addr) {
		dev_err(&ofdev->dev, "failed to map registers\n");
		return -ENXIO;
	}

	ret = vxd_plat_dt_hw_init(ofdev, &heap_configs, &num_heaps);
	if (ret) {
		dev_err(&ofdev->dev, "failed to init platform-specific hw!\n");
		goto out_add_dev;
	}

	ret = vxd_add_dev(&ofdev->dev, heap_configs, num_heaps,
			  NULL /* plat priv data */, reg_addr, reg_size);
	if (ret) {
		dev_err(&ofdev->dev, "failed to intialize driver core!\n");
		goto out_add_dev;
	}

	ret = devm_request_threaded_irq(&ofdev->dev, module_irq, &dt_plat_isrcb,
			&dt_plat_thread_irq, IRQF_SHARED, DEVICE_NAME, ofdev);
	if (ret) {
		dev_err(&ofdev->dev, "failed to request irq\n");
		goto out_irq;
	}

	return ret;

out_irq:
	vxd_rm_dev(&ofdev->dev);
out_add_dev:
	devm_iounmap(&ofdev->dev, reg_addr);

	return ret;
}

static int vxd_plat_remove(struct platform_device *ofdev)
{
	vxd_rm_dev(&ofdev->dev);

	vxd_plat_dt_hw_destroy(ofdev);

	return 0;
}

#ifdef CONFIG_PM
static int vxd_plat_suspend(struct device *dev)
{
	struct platform_device *ofdev =
		container_of(dev, struct platform_device, dev);
	int ret = 0;

	/* Wait for completion of core activities */
	ret = vxd_suspend_dev(dev);
	if (ret) {
		dev_err(&ofdev->dev, "failed to suspend core hw!\n");
		goto out_suspend;
	}

	ret = vxd_plat_dt_hw_suspend(ofdev);
	if (ret)
		dev_err(&ofdev->dev, "failed to suspend platform-specific hw!\n");

out_suspend:
	return ret;
}

static int vxd_plat_resume(struct device *dev)
{
	struct platform_device *ofdev =
		container_of(dev, struct platform_device, dev);
	int ret = 0;

	ret = vxd_plat_dt_hw_resume(ofdev);
	if (ret) {
		dev_err(&ofdev->dev, "failed to resume platform-specific hw!\n");
		goto out_init_failed;
	}

	ret = vxd_resume_dev(dev);
	if (ret)
		dev_err(&ofdev->dev, "failed to resume core hw!\n");

out_init_failed:
	return ret;
}
#endif

static UNIVERSAL_DEV_PM_OPS(vxd_pm_plat_ops,
		vxd_plat_suspend, vxd_plat_resume, NULL);

static struct platform_driver vxd_plat_drv = {
	.probe  = vxd_plat_probe,
	.remove = vxd_plat_remove,
	.driver = {
		.name = "d5500-vxd",
		.owner = THIS_MODULE,
		.of_match_table = vxd_plat_dt_of_ids,
		.pm = &vxd_pm_plat_ops,
	},
};

int vxd_plat_init(void)
{
	int ret = 0;

	ret = platform_driver_register(&vxd_plat_drv);
	if (ret) {
		pr_err("failed to register VXD driver!\n");
		return ret;
	}

	return 0;
}

int vxd_plat_deinit(void)
{
	int ret;

	/* Unregister the driver from the OS */
	platform_driver_unregister(&vxd_plat_drv);

	ret = vxd_deinit();
	if (ret)
		pr_err("VXD driver deinit failed\n");

	return ret;
}

/*
 * coding style for emacs
 *
 * Local variables:
 * indent-tabs-mode: t
 * tab-width: 8
 * c-basic-offset: 8
 * End:
 */
