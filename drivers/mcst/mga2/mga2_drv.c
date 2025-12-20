/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include "mga2_drv.h"

#define DRIVER_AUTHOR		"MCST"

#define DRIVER_NAME		"mga2"
#define DRIVER_DESC		"DRM driver for MCST MGA2"
#define DRIVER_DATE		"20221102"

#define DRIVER_MAJOR		1
#define DRIVER_MINOR		2
#define DRIVER_PATCHLEVEL	0

static struct drm_driver driver;

static struct mga2_info mga2_info = {
	.regs_bar       = 2,
	.vram_bar       = 0,
	.dc_regs_base   = 0x800,
	.int_regs_base  = 0x02000,
	.vid_regs_base  = 0x02400,
	.mga2_crts_nr   = 2,
};

static const struct pci_device_id pciidlist[] = {
	{ PCI_VDEVICE(MCST_TMP, PCI_DEVICE_ID_MCST_MGA2),
					(kernel_ulong_t)&mga2_info },
	{},
};

MODULE_DEVICE_TABLE(pci, pciidlist);

static int
mga2_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct drm_device *dev;
	int ret;

	dev = drm_dev_alloc(&driver, &pdev->dev);
	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		goto err;
	}

	dev->pdev = pdev;
	pci_set_drvdata(pdev, dev);

	ret = mga2_driver_load(dev, ent->driver_data);
	if (ret)
		goto err_drm_dev_put;

	ret = drm_dev_register(dev, ent->driver_data);
	if (ret)
		goto err_driver_unload;

	return 0;

err_driver_unload:
	mga2_driver_unload(dev);
err_drm_dev_put:
	drm_dev_put(dev);
err:
	return ret;
}

static void mga2_pci_remove(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);

	drm_put_dev(dev);
	drm_dev_unregister(dev);
	mga2_driver_unload(dev);
	drm_dev_put(dev);
}

/*
 * Userspace get information ioctl
 */
/**
 * mga2_info_ioctl - answer a device specific request.
 *
 * @mga2: amdgpu device pointer
 * @data: request object
 * @filp: drm filp
 *
 * This function is used to pass device specific parameters to the userspace
 * drivers.  Examples include: pci device id, pipeline parms, tiling params,
 * etc. (all asics).
 * Returns 0 on success, -EINVAL on failure.
 */
static int mga2_info_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct mga2 *mga2 = dev->dev_private;
	struct drm_mga2_info *info = data;
	void __user *out = (void __user *)(uintptr_t)info->return_pointer;
	uint32_t size = info->return_size;

	if (!info->return_size || !info->return_pointer)
		return -EINVAL;

	switch (info->query) {
	case MGA2_INFO_MEMORY: {
		const struct drm_mm *mm = &mga2->vram_mm;
		struct drm_mga2_memory_info mem = {};
		const struct drm_mm_node *entry = NULL;
		u64 total_used = 0, total_free = 0, total = 0;
	
		total_free += mm->head_node.hole_size;

		drm_mm_for_each_node(entry, mm) {
			total_used += entry->size;
			total_free += entry->hole_size;
		}
		total = total_free + total_used;
		mem.vram.total_heap_size = total;
		mem.vram.usable_heap_size = total;
		mem.vram.heap_usage = total_used;
		mem.vram.max_allocation = mem.vram.usable_heap_size * 3 / 4;

		memcpy(&mem.cpu_accessible_vram, &mem.vram, sizeof(mem.vram));
		return copy_to_user(out, &mem,
				    min((size_t)size, sizeof(mem)))
				    ? -EFAULT : 0;
	}
	default:
		DRM_DEBUG_KMS("Invalid request %d\n", info->query);
		return -EINVAL;
	}
	return 0;
}


struct drm_ioctl_desc mga2_ioctls[] = {
	DRM_IOCTL_DEF_DRV(MGA2_BCTRL, mga2_bctrl_ioctl,  DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_GEM_CREATE, mga2_gem_create_ioctl, DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_GEM_MMAP, mga2_gem_mmap_ioctl, DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_SYNC, mga2_gem_sync_ioctl, DRM_AUTH | DRM_UNLOCKED),
     	DRM_IOCTL_DEF_DRV(MGA2_INFO, mga2_info_ioctl, DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_AUC2, mga2_auc2_ioctl,  DRM_AUTH | DRM_UNLOCKED),
};

#ifdef CONFIG_PM_SLEEP
static int mga2_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm = pci_get_drvdata(pdev);
	struct mga2 *mga2 = drm->dev_private;
	int ret = drm_mode_config_helper_suspend(drm);
	if (ret)
		return ret;

	ret = __mga2_sync(mga2);
	if (ret)
		return ret;
	mga2_reset(drm);
	return 0;
}

static int mga2_resume(struct device *dev)
{
	int ret;
	struct drm_crtc *crtc;
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm = pci_get_drvdata(pdev);
	struct mga2 *mga2 = drm->dev_private;

	if (pci_enable_device(pdev))
		return -EIO;

	mga2_reset(drm);
	pci_set_master(pdev);

	if ((ret = mga2fb_bctrl_hw_init(mga2)))
		goto out;

	drm_for_each_crtc(crtc, drm)
		mga2_crtc_hw_init(crtc);

	if ((ret = mga2_mode_init_hw(drm)))
		goto out;
	/*enable irqs*/
	mga2_driver_irq_postinstall(drm);

	ret = drm_mode_config_helper_resume(drm);
out:
	return ret;
}
#endif

static SIMPLE_DEV_PM_OPS(mga2_pm_ops, mga2_suspend, mga2_resume);

static void mga2_pci_shutdown(struct pci_dev *pdev)
{
	mga2_suspend(&pdev->dev);
}

static struct pci_driver mga2_pci_driver = {
	.name = DRIVER_NAME,
	.id_table = pciidlist,
	.probe = mga2_pci_probe,
	.remove = mga2_pci_remove,
	.shutdown = mga2_pci_shutdown,
	.driver.pm = &mga2_pm_ops,
};

static const struct file_operations mga2_fops = {
	.owner = THIS_MODULE,
	.open = drm_open,
	.release = drm_release,
	.unlocked_ioctl = drm_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = drm_compat_ioctl,
#endif
	.mmap = mga2_mmap,
	.poll = drm_poll,
	.read = drm_read,
};

const struct vm_operations_struct mga2_gem_vm_ops = {
	.open = drm_gem_vm_open,
	.close = drm_gem_vm_close,
};

static struct drm_driver driver = {
	.driver_features = DRIVER_MODESET | DRIVER_GEM | DRIVER_ATOMIC,

	.dev_priv_size = 0,

	.lastclose = mga2_lastclose,

	.fops = &mga2_fops,
	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,
	.date = DRIVER_DATE,
	.major = DRIVER_MAJOR,
	.minor = DRIVER_MINOR,
	.patchlevel = DRIVER_PATCHLEVEL,

	.gem_free_object_unlocked = mga2_gem_free_object,
	.gem_vm_ops = &mga2_gem_vm_ops,

	.dumb_create = mga2_dumb_create,

	.prime_handle_to_fd	= drm_gem_prime_handle_to_fd,
	.prime_fd_to_handle	= drm_gem_prime_fd_to_handle,
	.gem_prime_export	= drm_gem_prime_export,
	.gem_prime_import	= drm_gem_prime_import,
	.gem_prime_get_sg_table	= mga2_prime_get_sg_table,
	.gem_prime_import_sg_table = mga2_prime_import_sg_table,
	.gem_prime_vmap		= mga2_prime_vmap,
	.gem_prime_vunmap	= mga2_prime_vunmap,
	.gem_prime_mmap		= mga2_prime_mmap,

	.irq_preinstall = mga2_driver_irq_preinstall,
	.irq_uninstall = mga2_driver_irq_uninstall,
	.irq_handler = mga2_driver_irq_handler,

	.ioctls = mga2_ioctls,
	.num_ioctls = DRM_ARRAY_SIZE(mga2_ioctls),

#if defined(CONFIG_DEBUG_FS)
	.debugfs_init = mga2_debugfs_init,
#endif
};

module_pci_driver(mga2_pci_driver);

MODULE_SOFTDEP("pre: dw_hdmi_imx");
MODULE_SOFTDEP("pre: panel-lvds");

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL v2");
