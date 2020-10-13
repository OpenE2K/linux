#include <linux/module.h>
#include <linux/console.h>

#include "mga2_drv.h"

int mga2_modeset = -1;

MODULE_PARM_DESC(modeset, "Disable/Enable modesetting");
module_param_named(modeset, mga2_modeset, int, 0400);

static struct drm_driver driver;

static DEFINE_PCI_DEVICE_TABLE(pciidlist) = {
	{
	PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_MGA2)}, {
},};

MODULE_DEVICE_TABLE(pci, pciidlist);

static int __init
mga2_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	return drm_get_pci_dev(pdev, ent, &driver);
}

static void mga2_pci_remove(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);

	drm_put_dev(dev);
}

static int mga2_drm_freeze(struct drm_device *dev)
{
	drm_kms_helper_poll_disable(dev);

	pci_save_state(dev->pdev);

	console_lock();
	mga2_fbdev_set_suspend(dev, 1);
	console_unlock();
	return 0;
}

static int mga2_drm_thaw(struct drm_device *dev)
{
	int error = 0;

	drm_mode_config_reset(dev);
	mutex_lock(&dev->mode_config.mutex);
	drm_helper_resume_force_mode(dev);
	mutex_unlock(&dev->mode_config.mutex);

	console_lock();
	mga2_fbdev_set_suspend(dev, 0);
	console_unlock();
	return error;
}

static int mga2_drm_resume(struct drm_device *dev)
{
	int ret;

	if (pci_enable_device(dev->pdev))
		return -EIO;

	ret = mga2_drm_thaw(dev);
	if (ret)
		return ret;

	drm_kms_helper_poll_enable(dev);
	return 0;
}

static int mga2_pm_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);
	int error;

	error = mga2_drm_freeze(ddev);
	if (error)
		return error;

	pci_disable_device(pdev);
	pci_set_power_state(pdev, PCI_D3hot);
	return 0;
}
static int mga2_pm_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);
	return mga2_drm_resume(ddev);
}

static int mga2_pm_freeze(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);

	if (!ddev || !ddev->dev_private)
		return -ENODEV;
	return mga2_drm_freeze(ddev);

}

static int mga2_pm_thaw(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);
	return mga2_drm_thaw(ddev);
}

static int mga2_pm_poweroff(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);

	return mga2_drm_freeze(ddev);
}
struct drm_ioctl_desc mga2_ioctls[] = {
	DRM_IOCTL_DEF_DRV(MGA2_BCTRL, mga2_bctrl_ioctl,
			  DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_GEM_CREATE, mga2_gem_create_ioctl,
			  DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_GEM_MMAP, mga2_gem_mmap_ioctl,
			  DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_SYNC, mga2_gem_sync_ioctl,
			  DRM_AUTH | DRM_UNLOCKED),
};

static const struct dev_pm_ops mga2_pm_ops = {
	.suspend = mga2_pm_suspend,
	.resume = mga2_pm_resume,
	.freeze = mga2_pm_freeze,
	.thaw = mga2_pm_thaw,
	.poweroff = mga2_pm_poweroff,
	.restore = mga2_pm_resume,
};

static struct pci_driver mga2_pci_driver = {
	.name = DRIVER_NAME,
	.id_table = pciidlist,
	.probe = mga2_pci_probe,
	.remove = mga2_pci_remove,
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
	.driver_features = DRIVER_MODESET | DRIVER_GEM |
	    /*DRIVER_PCI_DMA | DRIVER_HAVE_DMA | DRIVER_FB_DMA | */
	    DRIVER_HAVE_IRQ | DRIVER_IRQ_SHARED,

	.dev_priv_size = 0,

	.load = mga2_driver_load,
	.unload = mga2_driver_unload,
	.lastclose = mga2_lastclose,

	.fops = &mga2_fops,
	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,
	.date = DRIVER_DATE,
	.major = DRIVER_MAJOR,
	.minor = DRIVER_MINOR,
	.patchlevel = DRIVER_PATCHLEVEL,

	.gem_free_object = mga2_gem_free_object,
	.gem_vm_ops = &mga2_gem_vm_ops,

	.dumb_create = mga2_dumb_create,
	.dumb_map_offset = mga2_dumb_mmap_offset,
	.dumb_destroy = mga2_dumb_destroy,

	.get_vblank_counter = mga2_vblank_count,
	.enable_vblank = mga2_enable_vblank,
	.disable_vblank = mga2_disable_vblank,
	.irq_preinstall = mga2_driver_irq_preinstall,
	.irq_postinstall = mga2_driver_irq_postinstall,
	.irq_uninstall = mga2_driver_irq_uninstall,
	.irq_handler = mga2_driver_irq_handler,

	.ioctls = mga2_ioctls,
	.num_ioctls = DRM_ARRAY_SIZE(mga2_ioctls),
};

static int __init mga2_init(void)
{
	if (mga2_modeset == 0)
		return -EINVAL;
	return drm_pci_init(&driver, &mga2_pci_driver);
}
static void __exit mga2_exit(void)
{
	drm_pci_exit(&driver, &mga2_pci_driver);
}

module_init(mga2_init);
module_exit(mga2_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL and additional rights");
