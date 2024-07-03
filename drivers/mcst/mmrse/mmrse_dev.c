/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mmrse_dev.c - MMR/M-SE module device driver
 *
 * Char Device part
 */

#include "mmrse_main.h"
#include "mmrse_regs.h"
#include "mmrse_dbg.h"


uint64_t mmrse_hw_get_dmalatency_ns(mmrse_priv_t *priv);


/**
 ******************************************************************************
 * GLOBAL
 ******************************************************************************
 */

#define DEVICE_FIRST	 0
#define ALL_DEVICE_COUNT (1U << MINORBITS)        /* max minor num */
#define MAX_DEVICE_COUNT (ALL_DEVICE_COUNT >> 2)  /* ==max/4 - BC, RT, BM, */
#define DEVICE_COUNT	 ((MAX_DEVICE_COUNT > 32) ? 32 : MAX_DEVICE_COUNT)

#define DEVNAMELEN	31


static struct class *DevClass;

static int Major = 0;

static DEFINE_MUTEX(minor_lock);

static int last_minor = 0;
static int minors[DEVICE_COUNT] = {-1};
static char bus_name[DEVICE_COUNT][DEVNAMELEN + 1] = { {0} };


/**
 ******************************************************************************
 * file operation part (Char device methods)  /dev/xmmrN
 ******************************************************************************
 */

/**
 * ioctl file operation
 */
static long cdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	mmrse_priv_t *priv = (mmrse_priv_t *)filp->private_data;
	void __user *uarg = (void __user *)arg;

	if (!priv)
		return -ENODEV;

	if ((_IOC_TYPE(cmd) != MMRSE_IOC_MAGIC)) {
		dev_err(priv->dev,
			"invalid IOC_MAGIC in command 0x%X(%d)\n", cmd, cmd);
		return -ENOTTY;
	}

	DEV_DBG(DBG_MSK_CDEV, priv->dev, "CDEV_IOCTL: 0x%X(%d)\n", cmd, cmd);


	switch (cmd) {
	case MMRSE_IOCTL_GET_STATS:
	{
		if (copy_to_user(uarg, (caddr_t)&priv->stats, _IOC_SIZE(cmd))) {
			dev_err(priv->dev,
				"GET_STATS: copy_to_user failure\n");
			ret = -EFAULT;
		}
		break;
	}
	case MMRSE_IOCTL_GET_DMA_LATENCY:
	{
		uint64_t dma_lat;

		dma_lat = mmrse_hw_get_dmalatency_ns(priv);
		if (copy_to_user(uarg, (caddr_t)&dma_lat, _IOC_SIZE(cmd))) {
			dev_err(priv->dev,
				"GET_DMA_LATENCY: copy_to_user failure\n");
			ret = -EFAULT;
		}
		break;
	}
	default:
		dev_err(priv->dev,
			"invalid command 0x%X(%d)\n", cmd, cmd);
		return -ENOTTY;
	} /* switch(cmd) */

	return ret;
} /* cdev_ioctl */


#ifdef CONFIG_COMPAT

static long compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return cdev_ioctl(filp, cmd, arg);
}

#endif /* CONFIG_COMPAT */


/**
 * open file operation
 */
static int cdev_open(struct inode *inode, struct file *filp)
{
	mmrse_priv_t *priv = container_of(inode->i_cdev, mmrse_priv_t, cdev);

	if (!priv)
		return -ENODEV;

	filp->private_data = priv;

	kobject_get(&priv->dev->kobj);

	return 0;
} /* cdev_open */

/**
 * close file operation
 */
static int cdev_release(struct inode *inode, struct file *filp)
{
	mmrse_priv_t *priv = (mmrse_priv_t *)filp->private_data;

	if (!priv)
		return -ENODEV;

	DEV_DBG(DBG_MSK_CDEV, priv->dev, "CDEV_CLOSE\n");

	kobject_put(&priv->dev->kobj);

	filp->private_data = NULL;

	return 0;
} /* cdev_release */

/**
 * file operation
 */
static const struct file_operations dev_fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.unlocked_ioctl = cdev_ioctl,
    #ifdef CONFIG_COMPAT
	.compat_ioctl	= compat_ioctl,
    #endif
	.open		= cdev_open,
	.release	= cdev_release,
};


/**
 ******************************************************************************
 * Minor part of cdev
 ******************************************************************************
 */

/*
 * Allocate minor for current PCI device
 */
static int get_minor(mmrse_priv_t *priv, unsigned int *minor)
{
	int ret = -EINVAL;
	struct pci_dev *pdev = priv->pdev;
	int i;

	mutex_lock(&minor_lock);

	/* find prev minor for busname */
	for (i = 0; i < last_minor; i++) {
		if (0 == strcmp(dev_name(&pdev->dev), bus_name[i])) {
			*minor = minors[i];
			dev_dbg(&pdev->dev,
				"found saved minor: %d (%s)\n",
				*minor, dev_name(&pdev->dev));
			ret = 0;
			break;
		}
	}
	if (ret != 0) {
		if (DEVICE_COUNT == last_minor) {
			dev_err(&pdev->dev,
				"too many char devices, aborting\n");
		} else {
			/* new busname */
			minors[last_minor] = last_minor;
			strcpy(bus_name[last_minor], dev_name(&pdev->dev));
			*minor = last_minor;
			last_minor += 1;
			ret = 0;
			dev_dbg(&pdev->dev,
				"save minor %d for bus %s\n",
				*minor, bus_name[*minor]);
		}
	}

	mutex_unlock(&minor_lock);

	return ret;
} /* get_minor */


/**
 * Create cdev for BC or RT or BM
 */
int mmrse_cdev_register(mmrse_priv_t *priv, int devtype)
{
	int ret = 0;
	dev_t devt;
	unsigned int minor;
	char name[DEVNAMELEN + 1];
	struct pci_dev *pdev = priv->pdev;

	ret = get_minor(priv, &minor);
	if (ret) {
		dev_err(&pdev->dev, "get_minor failed, aborting\n");
		goto err_exit;
	}

	switch (devtype) {

	case MMRSE_CDEV_MAIN:
		snprintf(name, DEVNAMELEN, "%s%d", KBUILD_MODNAME, minor);
		minor += DEVICE_COUNT * devtype;
		devt = MKDEV(Major, minor);

		cdev_init(&priv->cdev, &dev_fops);
		priv->cdev.owner = THIS_MODULE;
		priv->minor = minor;

		ret = cdev_add(&priv->cdev, devt, 1);
		if (ret) {
			dev_err(&pdev->dev,
				"failed to add main char device %d:%d\n",
				Major, minor);
			goto err_free_idr;
		}

		priv->dev = device_create(DevClass, &pdev->dev, devt,
					  NULL, name);
		if (IS_ERR(priv->dev)) {
			dev_err(&pdev->dev,
				"main char device register failed\n");
			ret = PTR_ERR(priv->dev);
			goto err_del_cdev;
		}
		dev_info(&pdev->dev,
			 "main char device %s (%d:%d) installed\n",
			 name, Major, minor);
		break;

	case MMRSE_CDEV_BC:
		snprintf(name, DEVNAMELEN, "%s%d%s",
			 KBUILD_MODNAME, minor, DEVNAME_BC);
		minor += DEVICE_COUNT * devtype;
		devt = MKDEV(Major, minor);

		cdev_init(&priv->cdev_bc, &mmrse_bc_dev_fops);
		priv->cdev_bc.owner = THIS_MODULE;
		priv->minor_bc = minor;

		ret = cdev_add(&priv->cdev_bc, devt, 1);
		if (ret) {
			dev_err(&pdev->dev,
				"failed to add BC char device %d:%d\n",
				Major, minor);
			goto err_free_idr;
		}

		priv->dev_bc = device_create(DevClass, &pdev->dev, devt,
					     NULL, name);
		if (IS_ERR(priv->dev_bc)) {
			dev_err(&pdev->dev,
				"BC char device register failed\n");
			ret = PTR_ERR(priv->dev_bc);
			goto err_del_cdev;
		}
		dev_info(&pdev->dev,
			 "BC char device %s (%d:%d) installed\n",
			 name, Major, minor);
		break;

	case MMRSE_CDEV_RT:
		snprintf(name, DEVNAMELEN, "%s%d%s",
			 KBUILD_MODNAME, minor, DEVNAME_RT);
		minor += DEVICE_COUNT * devtype;
		devt = MKDEV(Major, minor);

		cdev_init(&priv->cdev_rt, &mmrse_rt_dev_fops);
		priv->cdev_rt.owner = THIS_MODULE;
		priv->minor_rt = minor;

		ret = cdev_add(&priv->cdev_rt, devt, 1);
		if (ret) {
			dev_err(&pdev->dev,
				"failed to add RT char device %d:%d\n",
				Major, minor);
			goto err_free_idr;
		}

		priv->dev_rt = device_create(DevClass, &pdev->dev, devt,
					     NULL, name);
		if (IS_ERR(priv->dev_rt)) {
			dev_err(&pdev->dev,
				"RT char device register failed\n");
			ret = PTR_ERR(priv->dev_rt);
			goto err_del_cdev;
		}
		dev_info(&pdev->dev,
			 "RT char device %s (%d:%d) installed\n",
			 name, Major, minor);
		break;

	case MMRSE_CDEV_BM:
		snprintf(name, DEVNAMELEN, "%s%d%s",
			 KBUILD_MODNAME, minor, DEVNAME_BM);
		minor += DEVICE_COUNT * devtype;
		devt = MKDEV(Major, minor);

		cdev_init(&priv->cdev_bm, &mmrse_bm_dev_fops);
		priv->cdev_bm.owner = THIS_MODULE;
		priv->minor_bm = minor;

		ret = cdev_add(&priv->cdev_bm, devt, 1);
		if (ret) {
			dev_err(&pdev->dev,
				"failed to add BM char device %d:%d\n",
				Major, minor);
			goto err_free_idr;
		}

		priv->dev_bm = device_create(DevClass, &pdev->dev, devt,
					     NULL, name);
		if (IS_ERR(priv->dev_bm)) {
			dev_err(&pdev->dev,
				"BM char device register failed\n");
			ret = PTR_ERR(priv->dev_bm);
			goto err_del_cdev;
		}
		dev_info(&pdev->dev,
			 "BM char device %s (%d:%d) installed\n",
			 name, Major, minor);
		break;
	}

	return 0;

err_del_cdev:
	switch (devtype) {
	case MMRSE_CDEV_MAIN:
		cdev_del(&priv->cdev);
		break;
	case MMRSE_CDEV_BC:
		cdev_del(&priv->cdev_bc);
		break;
	case MMRSE_CDEV_RT:
		cdev_del(&priv->cdev_rt);
		break;
	case MMRSE_CDEV_BM:
		cdev_del(&priv->cdev_bm);
		break;
	}
err_free_idr:
err_exit:
	return ret;
} /* mmrse_cdev_register */

/**
 * Remove cdev
 */
void mmrse_cdev_remove(mmrse_priv_t *priv, int devtype)
{
	switch (devtype) {

	case MMRSE_CDEV_MAIN:
		dev_dbg(priv->dev,
			"remove main char device (%d:%d)\n",
			Major, priv->minor);
		device_destroy(DevClass, MKDEV(Major, priv->minor));
		cdev_del(&priv->cdev);
		break;

	case MMRSE_CDEV_BC:
		dev_dbg(priv->dev_bc,
			"remove BC char device (%d:%d)\n",
			Major, priv->minor_bc);
		device_destroy(DevClass, MKDEV(Major, priv->minor_bc));
		cdev_del(&priv->cdev_bc);
		break;

	case MMRSE_CDEV_RT:
		dev_dbg(priv->dev_rt,
			"remove RT char device (%d:%d)\n",
			Major, priv->minor_rt);
		device_destroy(DevClass, MKDEV(Major, priv->minor_rt));
		cdev_del(&priv->cdev_rt);
		break;

	case MMRSE_CDEV_BM:
		dev_dbg(priv->dev_bm,
			"remove BM char device (%d:%d)\n",
			Major, priv->minor_bm);
		device_destroy(DevClass, MKDEV(Major, priv->minor_bm));
		cdev_del(&priv->cdev_bm);
		break;
	}
} /* mmrse_cdev_remove */


/**
 ******************************************************************************
 * Major part of cdev
 ******************************************************************************
 */

static int major_init(void)
{
	int ret = 0;
	dev_t devt = 0;

	ret = alloc_chrdev_region(&devt, DEVICE_FIRST, ALL_DEVICE_COUNT,
				  KBUILD_MODNAME);
	if (ret) {
		pr_err(KBUILD_MODNAME
		       ": Could not register char device region, aborting\n");
		goto err_exit;
	}

	Major = MAJOR(devt);

	PDEBUG(DBG_MSK_CDEV, "chrdev_region registered: major %d\n", Major);
	return 0;

err_exit:
	return ret;
} /* major_init */

static void major_delete(void)
{
	unregister_chrdev_region(MKDEV(Major, 0), ALL_DEVICE_COUNT);

	PDEBUG(DBG_MSK_CDEV, "chrdev_region unregistered (major %d)\n", Major);
} /* major_delete */


/**
 * Get Major and register class for cdev
 */
int __init mmrse_dev_init(void)
{
	int ret;

	ret = major_init();
	if (ret)
		goto err_exit;

	/* class register */
	DevClass = class_create(THIS_MODULE, KBUILD_MODNAME);
	if (IS_ERR(DevClass)) {
		pr_err(KBUILD_MODNAME ": couldn't create class %s, aborting\n",
		       KBUILD_MODNAME);
		ret = PTR_ERR(DevClass);
		goto err_class_register;
	}
	PDEBUG(DBG_MSK_CDEV, "class %s created\n", KBUILD_MODNAME);

	return 0;

err_class_register:
	major_delete();
err_exit:
	return ret;
} /* mmrse_dev_init */

/**
 * Deregister class for cdev and free major
 */
void __exit mmrse_dev_exit(void)
{
	class_destroy(DevClass);
	major_delete();

	PDEBUG(DBG_MSK_CDEV, "class %s destroyed\n", KBUILD_MODNAME);
} /* mmrse_dev_exit */
