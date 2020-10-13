/*
 * Copyright 2012 Red Hat Inc.
 * Copyright (c) 2012-2013 ZAO "MCST". All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS, AUTHORS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 */
/*
 * Authors: Dave Airlie <airlied@redhat.com>
 *	    Alexander Troosh <troosh@mcst.ru>
 */
#include <linux/module.h>
#include <linux/console.h>

#include "drmP.h"
//#include "drm.h"
#include "drm_crtc_helper.h"

#include "mcst_drv.h"

int mcst_modeset = -1;

MODULE_PARM_DESC(modeset, "Disable/Enable modesetting");
module_param_named(modeset, mcst_modeset, int, 0400);

MODULE_PARM_DESC(msi, "Enable MSI (default: off)");
int mcst_msi;
module_param_named(msi, mcst_msi, int, 0400);

static struct drm_driver driver;

#define MCST_VIDEO_DEVICE(vendor_code, id, info) {		\
	.class = PCI_BASE_CLASS_DISPLAY << 16,	\
	.class_mask = 0xff0000,			\
	.vendor = vendor_code,			\
	.device = id,				\
	.subvendor = PCI_ANY_ID,		\
	.subdevice = PCI_ANY_ID,		\
	.driver_data = (unsigned long) info }

static DEFINE_PCI_DEVICE_TABLE(pciidlist) = {
	MCST_VIDEO_DEVICE(0x108e, 0x8000,  MCST_MGA),
	MCST_VIDEO_DEVICE(0x1fff, 0x800c,  MCST_MGA3D),
	{0, 0, 0, 0, 0, 0, 0},
};

MODULE_DEVICE_TABLE(pci, pciidlist);

static int 
mcst_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
CH();
	return drm_get_pci_dev(pdev, ent, &driver);
}

static void
mcst_pci_remove(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);
CH();

	drm_put_dev(dev);
}



static int mcst_drm_freeze(struct drm_device *dev)
{
CH();
	drm_kms_helper_poll_disable(dev);

	pci_save_state(dev->pdev);

	console_lock();
	mcst_fbdev_set_suspend(dev, 1);
	console_unlock();
	return 0;
}

static int mcst_drm_thaw(struct drm_device *dev)
{
	int error = 0;

CH();
/*	mcst_post_gpu(dev); */

	drm_mode_config_reset(dev);
	mutex_lock(&dev->mode_config.mutex);
	drm_helper_resume_force_mode(dev);
	mutex_unlock(&dev->mode_config.mutex);

	console_lock();
	mcst_fbdev_set_suspend(dev, 0);
	console_unlock();
	return error;
}

static int mcst_drm_resume(struct drm_device *dev)
{
	int ret;
CH();

	if (pci_enable_device(dev->pdev))
		return -EIO;

	ret = mcst_drm_thaw(dev);
	if (ret)
		return ret;

	drm_kms_helper_poll_enable(dev);
	return 0;
}

static int mcst_pm_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);
	int error;
CH();

	error = mcst_drm_freeze(ddev);
	if (error)
		return error;

	pci_disable_device(pdev);
	pci_set_power_state(pdev, PCI_D3hot);
	return 0;
}
static int mcst_pm_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);
CH();
	return mcst_drm_resume(ddev);
}

static int mcst_pm_freeze(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);
CH();

	if (!ddev || !ddev->dev_private)
		return -ENODEV;
	return mcst_drm_freeze(ddev);

}

static int mcst_pm_thaw(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);
CH();
	return mcst_drm_thaw(ddev);
}

static int mcst_pm_poweroff(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);
CH();
	return mcst_drm_freeze(ddev);
}

static const struct dev_pm_ops mcst_pm_ops = {
	.suspend = mcst_pm_suspend,
	.resume = mcst_pm_resume,
	.freeze = mcst_pm_freeze,
	.thaw = mcst_pm_thaw,
	.poweroff = mcst_pm_poweroff,
	.restore = mcst_pm_resume,
};

static struct pci_driver mcst_pci_driver = {
	.name = DRIVER_NAME,
	.id_table = pciidlist,
	.probe = mcst_pci_probe,
	.remove = mcst_pci_remove,
	.driver.pm = &mcst_pm_ops,
};

static const struct file_operations mcst_fops = {
	.owner = THIS_MODULE,
	.open = drm_open,
	.release = drm_release,
	.unlocked_ioctl = drm_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = drm_compat_ioctl,
#endif
	.mmap = mcst_mmap,
	.poll = drm_poll,
	.read = drm_read,
};

static struct drm_driver driver = {
	.driver_features = DRIVER_USE_MTRR | DRIVER_MODESET | DRIVER_GEM |
			   DRIVER_HAVE_IRQ | DRIVER_IRQ_SHARED
			   /* | DRIVER_PCI_DMA | DRIVER_SG | DRIVER_PRIME */,
	.dev_priv_size = 0,

	.load = mcst_driver_load,
	.unload = mcst_driver_unload,

	.gem_init_object = mcst_gem_init_object,
	.gem_free_object = mcst_gem_free_object,

	.irq_preinstall = mcst_irq_preinstall,
	.irq_postinstall = mcst_irq_postinstall,
	.irq_uninstall = mcst_irq_uninstall,
	.irq_handler = mcst_irq_handler,

	.get_vblank_counter = drm_vblank_count,
	.enable_vblank = mcst_enable_vblank,
	.disable_vblank = mcst_disable_vblank,

	.dumb_create = mcst_dumb_create,
	.dumb_map_offset = mcst_dumb_mmap_offset,
	.dumb_destroy = mcst_dumb_destroy,
	/* .ioctls = */
	.fops = &mcst_fops,
	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,
	.date = DRIVER_DATE,
	.major = DRIVER_MAJOR,
	.minor = DRIVER_MINOR,
	.patchlevel = DRIVER_PATCHLEVEL,
};

static int __init mcst_init(void)
{
CH();
#ifdef CONFIG_VGA_CONSOLE
	if (vgacon_text_force() && mcst_modeset == -1)
		return -EINVAL;
#endif

	if (mcst_modeset == 0)
		return -EINVAL;
	return drm_pci_init(&driver, &mcst_pci_driver);
}
static void __exit mcst_exit(void)
{
	drm_pci_exit(&driver, &mcst_pci_driver);
}

module_init(mcst_init);
module_exit(mcst_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL and additional rights");

