/****************************************************************************
*
*    Copyright (C) 2005 - 2015 by Vivante Corp.
*
*    This program is free software; you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation; either version 2 of the license, or
*    (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program; if not write to the Free Software
*    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****************************************************************************/


#include <linux/version.h>
#include <linux/module.h>

#include <drm/drmP.h>
#include "vivante_drv.h"

#include <drm/drm_legacy.h>


static char platformdevicename[] = "Vivante GCCore";
static struct platform_device *pplatformdev=NULL;


static const struct file_operations vivante_fops = {
	.owner = THIS_MODULE,
	.open = drm_open,
	.release = drm_release,
	.unlocked_ioctl = drm_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = drm_compat_ioctl,
#endif
	.mmap = drm_legacy_mmap,
	.poll = drm_poll,
	.read = drm_read,
};

int vivante_driver_load(struct drm_device *drm, unsigned long flags)
{
	struct platform_device *pdev = to_platform_device(drm->dev);
	platform_set_drvdata(pdev, drm);
	return 0;
}

static struct drm_driver vivante_driver = {

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,38)
	.driver_features = DRIVER_LEGACY,
#else
	.driver_features = DRIVER_USE_MTRR | DRIVER_USE_PLATFORM_DEVICE,
#endif
//    .reclaim_buffers = drm_core_reclaim_buffers,
	.load = vivante_driver_load,
	.fops = &vivante_fops,

	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,
	.date = DRIVER_DATE,
	.major = DRIVER_MAJOR,
	.minor = DRIVER_MINOR,
	.patchlevel = DRIVER_PATCHLEVEL,
};

static int shmob_drm_probe(struct platform_device *platdev)
{
	struct drm_driver *driver = &vivante_driver;
	struct drm_device *dev;
	int ret;

	DRM_DEBUG("\n");

	dev = drm_dev_alloc(driver, &platdev->dev);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	ret = drm_dev_register(dev, 0);
	if (ret)
		goto err_free;

	DRM_INFO("Initialized %s %d.%d.%d %s on minor %d\n",
		 driver->name, driver->major, driver->minor, driver->patchlevel,
		 driver->date, dev->primary->index);

	return 0;

err_free:
	drm_dev_put(dev);
	return ret;
}

static int shmob_drm_remove(struct platform_device *pdev)
{
	drm_put_dev(platform_get_drvdata(pdev));

	return 0;
}

static struct platform_driver shmob_drm_platform_driver = {
	.probe		= shmob_drm_probe,
	.remove		= shmob_drm_remove,
	.driver		= {
		.owner	= THIS_MODULE,
		.name	= platformdevicename,
	},
};

static int __init vivante_init(void)
{
    int retcode;

	retcode = platform_driver_register(&shmob_drm_platform_driver);
	if (retcode < 0)
		goto out_ipp;

    pplatformdev=platform_device_register_simple(platformdevicename,-1,NULL,0);
    if (pplatformdev==NULL) printk(KERN_ERR"Platform device is null\n");

out_ipp:
    return retcode;

}

static void __exit vivante_exit(void)
{
    if (pplatformdev) {
        platform_device_unregister(pplatformdev);
        platform_driver_unregister(&shmob_drm_platform_driver);
        pplatformdev=NULL;
    }

}

module_init(vivante_init);
module_exit(vivante_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL and additional rights");
