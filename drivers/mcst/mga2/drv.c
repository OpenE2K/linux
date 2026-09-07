/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include "drv.h"

#define DRIVER_AUTHOR		"MCST"

#define DRIVER_NAME		"mga2"
#define DRIVER_DESC		"DRM driver for MCST MGA 2.5 and higher"
#define DRIVER_DATE		"20221102"

#define DRIVER_MAJOR		1
#define DRIVER_MINOR		2
#define DRIVER_PATCHLEVEL	0

int mga2_timeout_ms = 10000;
module_param_named(timeout, mga2_timeout_ms, int, 0644);
MODULE_PARM_DESC(timeout, "blitter, AUC & BCTRL timeout in milliseconds");

int mga2_get_version(const struct device *dev)
{
	int i;
	const char *name;
	struct property *prop;
	char *ids[] = {
		[MGA20_PCI_PROTO]  = "mcst,mga20-pci-proto",
		[MGA20_PROTO]     = "mcst,mga20-proto",
		[MGA20]           = "mcst,mga20",
		[MGA25_PCI_PROTO] = "mcst,mga25-pci-proto",
		[MGA25_PROTO]     = "mcst,mga25-proto",
		[MGA25]           = "mcst,mga25",
		[MGA26_PCI_PROTO] = "mcst,mga26-pci-proto",
		[MGA26_PROTO]     = "mcst,mga26-proto",
		[MGA26]           = "mcst,mga26",
		[MGA26_PCIe]      = "mcst,mga26-pcie",
		[MGA26_PCIe_PROTO] = "mcst,mga26-pcie-proto",
		[MGA27_PCI_PROTO] = "mcst,mga27-pci-proto",
		[MGA27_PROTO]     = "mcst,mga27-proto",
		[MGA27] = "mcst,mga27",
	};

	for(i = 0; i < ARRAY_SIZE(ids); i++) {
		of_property_for_each_string(dev->of_node,
					    "compatible", prop, name) {
			if (!strcmp(ids[i], name))
				return i;
		}
	}
	WARN_ON(1);
	return -1;
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
static int mga2_info_ioctl(struct drm_device *drm, void *data, struct drm_file *filp)
{
	struct mga2 *mga2 = drm->dev_private;
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

static struct drm_ioctl_desc mga2_ioctls[] = {
	DRM_IOCTL_DEF_DRV(MGA2_BCTRL, mga2_bctrl_ioctl,  DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_GEM_CREATE, mga2_gem_create_ioctl, DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_GEM_MMAP, mga2_gem_mmap_ioctl, DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_SYNC, mga2_gem_sync_ioctl, DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_INFO, mga2_info_ioctl, DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_AUC2, mga2_auc2_ioctl,  DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_VIRT_TO_HNDL, mga2_virt_to_handle,  DRM_AUTH | DRM_UNLOCKED),
};

static const struct file_operations mga2_fops = {
	.owner = THIS_MODULE,
	.open = drm_open,
	.release = drm_release,
	.unlocked_ioctl = drm_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = drm_compat_ioctl,
#endif
#if defined(CONFIG_E2K) && defined(CONFIG_PROTECTED_MODE)
	.ptr128_ioctl = drm_ptr128_ioctl,
#endif
	.mmap = mga2_mmap,
	.poll = drm_poll,
	.read = drm_read,
	.llseek = noop_llseek,
};


static struct drm_driver mga2_drm_driver = {
	.driver_features = DRIVER_MODESET | DRIVER_GEM | DRIVER_ATOMIC,

	.fops = &mga2_fops,
	.name = "mga2", /* for compatibility with the old driver */
	.desc = DRIVER_DESC,
	.date = DRIVER_DATE,
	.major = DRIVER_MAJOR,
	.minor = DRIVER_MINOR,
	.patchlevel = DRIVER_PATCHLEVEL,

	.ioctls = mga2_ioctls,
	.num_ioctls = DRM_ARRAY_SIZE(mga2_ioctls),

	/* copy of DRM_GEM_DMA_DRIVER_OPS */
	.dumb_create		= mga2_dumb_create,
	.dumb_map_offset =	mga2_gem_dumb_map_offset,
	.prime_handle_to_fd	= drm_gem_prime_handle_to_fd,
	.prime_fd_to_handle	= drm_gem_prime_fd_to_handle,
	.gem_prime_import_sg_table = mga2_prime_import_sg_table,
	.gem_prime_mmap		= drm_gem_prime_mmap,

};

static struct regmap_config mga2_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.max_register = 0,
};

static const struct drm_mode_config_funcs mga2_mode_funcs = {
	.fb_create = drm_gem_fb_create,
	.atomic_check = drm_atomic_helper_check,
	.atomic_commit = drm_atomic_helper_commit,
};

/*
 * Copy-paste of drm_atomic_helper_wait_for_vblanks() without
 * drm_atomic_helper_wait_for_vblanks()
 */
static void mga2_commit_tail_rpm(struct drm_atomic_state *old_state)
{
	struct drm_device *dev = old_state->dev;

	drm_atomic_helper_commit_modeset_disables(dev, old_state);

	drm_atomic_helper_commit_modeset_enables(dev, old_state);

	drm_atomic_helper_commit_planes(dev, old_state,
					DRM_PLANE_COMMIT_ACTIVE_ONLY);

	drm_atomic_helper_fake_vblank(old_state);

	drm_atomic_helper_commit_hw_done(old_state);

	/*drm_atomic_helper_wait_for_vblanks(dev, old_state);*/

	drm_atomic_helper_cleanup_planes(dev, old_state);
}

static struct drm_mode_config_helper_funcs mga2_mode_config_helpers = {
	.atomic_commit_tail = mga2_commit_tail_rpm,
};

static unsigned mga2_drm_encoder_clones(struct drm_encoder *e)
{
	struct drm_encoder *c;
	struct drm_device *dev = e->dev;
	unsigned clone_mask = 0;

	mutex_lock(&dev->mode_config.mutex);

	drm_for_each_encoder(c, dev) {
		if (c->encoder_type == e->encoder_type)
			clone_mask |= drm_encoder_mask(c);
	}

	mutex_unlock(&dev->mode_config.mutex);

	return clone_mask;
}

static void mga2_setup_possible_clones(struct drm_device *dev)
{
	struct drm_encoder *e;

	drm_for_each_encoder(e, dev)
		e->possible_clones = mga2_drm_encoder_clones(e);

}

static irqreturn_t mga2_irq_handler(int irq, void *arg)
{
	struct mga2 *mga2 = arg;
	mga2_update_ptr(mga2);
	return IRQ_HANDLED;
}

static int mga2_get_irq(struct device *dev)
{
	int irq;
	struct device_node *np;
	of_node_get(dev->of_node);
	np = of_get_child_by_name(dev->of_node, "auc");
	np = np ? : dev->of_node;
	irq = of_irq_get(np, 0);
	of_node_put(np);
	return irq;
}

static int mga2_bind(struct device *dev)
{
	int ret, irq;
	struct drm_device *drm = dev_get_drvdata(dev);
	struct mga2 *mga2 = drm->dev_private;

	ret = component_bind_all(dev, drm);
	if (ret)
		goto err;

	irq = mga2_get_irq(dev);
	if (WARN_ON(irq < 0)) {
		ret = irq;
		goto err_unbind_all;
	}
	mga2->irq = irq;
	mga2->hwirq = irqd_to_hwirq(irq_get_irq_data(irq));
	irq_set_status_flags(irq, IRQ_NOAUTOEN | IRQ_DISABLE_UNLAZY);
	ret = request_irq(irq, mga2_irq_handler,
			       0, dev_name(dev), mga2);
	if (WARN_ON(ret))
		goto err_unbind_all;

	/*Now we now hwirq value*/
	mga2_init_desc0_interrupt(mga2);

	ret = drm_vblank_init(drm, drm->mode_config.num_crtc);
	if (WARN_ON(ret))
		goto err_cleanup;

	drm_kms_helper_poll_init(drm);

	drm_mode_config_reset(drm);
	mga2_setup_possible_clones(drm);

	ret = drm_dev_register(drm, 0);
	if (WARN_ON(ret))
		goto err_cleanup;

	drm_fbdev_generic_setup(drm, 32);

	return 0;

err_cleanup:
err_unbind_all:
	component_unbind_all(drm->dev, drm);
err:
	return ret;
}

static void mga2_unbind(struct device *dev)
{
	struct drm_device *drm = dev_get_drvdata(dev);
	struct mga2 *mga2 = drm->dev_private;
	drm_dev_unregister(drm);
	drm_kms_helper_poll_fini(drm);
	drm_atomic_helper_shutdown(drm);
	free_irq(mga2->irq, mga2);
	component_unbind_all(drm->dev, drm);
	drm_dev_put(drm);
	drm_mm_takedown(&mga2->vram_mm);
}

static const struct component_master_ops mga2_ops = {
	.bind   = mga2_bind,
	.unbind = mga2_unbind,
};

#define MGA2_OF_DTB_DECLARATION(type)			\
	extern char __dtb_##type##_begin[];		\
	extern char __dtb_##type##_end[]

#define MGA2_OF_DTB_INIT(type)		{		\
		.begin = __dtb_##type##_begin,		\
		.end = __dtb_##type##_end		\
}

MGA2_OF_DTB_DECLARATION(mga20);
MGA2_OF_DTB_DECLARATION(mga25_pci_proto);
MGA2_OF_DTB_DECLARATION(mga25);
MGA2_OF_DTB_DECLARATION(mga26_pcie);
MGA2_OF_DTB_DECLARATION(mga26_pcie_proto);
MGA2_OF_DTB_DECLARATION(mga27_pci_proto);

static const struct mga2_dtb {
	char *begin, *end;
} mga2_dtb[MGA2X_NR] = {
	[MGA20]      = MGA2_OF_DTB_INIT(mga20),
	[MGA25_PCI_PROTO] = MGA2_OF_DTB_INIT(mga25_pci_proto),
	[MGA25]           = MGA2_OF_DTB_INIT(mga25),
	[MGA26_PCI_PROTO] = MGA2_OF_DTB_INIT(mga25_pci_proto),
	[MGA26_PCIe] = MGA2_OF_DTB_INIT(mga26_pcie),
	[MGA26_PCIe_PROTO] = MGA2_OF_DTB_INIT(mga26_pcie_proto),
	[MGA27_PCI_PROTO] = MGA2_OF_DTB_INIT(mga27_pci_proto),
};

static void mga2_of_overlay_release(void *data)
{
	int id = (long)data;
	WARN_ON(of_overlay_remove(&id));
}

static int mga2_get_emebedded_dtb(struct pci_dev *pdev)
{
	u16 d = U16_MAX;
	struct device *dev = &pdev->dev;
	const struct mga2_dtb *b;
	int id = 0, ret;
	pci_read_config_word(pdev, PCI_SUBSYSTEM_ID, &d);
	if (d > ARRAY_SIZE(mga2_dtb))
		return -ENODEV;
	b = &mga2_dtb[d];
	if (!b->begin)
		return -ENOENT;

	ret = of_overlay_fdt_apply(b->begin, b->end - b->begin, &id);
	if (ret)
		return ret;
	ret = devm_add_action(dev, mga2_of_overlay_release, (void *)(long)id);
	if (ret)
		return ret;
	dev->of_node = of_find_node_by_path("/pci@0/mga2_ext");
	if (!dev->of_node)
		return -ENODEV;

	return id;
}

static int mga2_of_add_property(struct of_changeset *ocs,
					  struct device_node *np,
					  const char *name, const void *value,
					  int length)
{
	struct property *prop;
	int ret = -ENOMEM;

	prop = kzalloc(sizeof(*prop), GFP_KERNEL);
	if (!prop)
		return -ENOMEM;

	prop->name = kstrdup(name, GFP_KERNEL);
	if (!prop->name)
		goto out_err;

	prop->value = kmemdup(value, length, GFP_KERNEL);
	if (!prop->value)
		goto out_err;

	of_property_set_flag(prop, OF_DYNAMIC);

	prop->length = length;

	ret = of_changeset_add_property(ocs, np, prop);
	if (!ret)
		return 0;

out_err:
	kfree(prop->value);
	kfree(prop->name);
	kfree(prop);
	return ret;
}

static void mga2_of_changeset_release(void *data)
{
	struct of_changeset *cs = data;
	WARN_ON(of_changeset_revert(cs));
	of_changeset_destroy(cs);
}

#define OF_MAX_ADDR_CELLS	4
#define OF_CHECK_ADDR_COUNT(na)	((na) > 0 && (na) <= OF_MAX_ADDR_CELLS)

static int mga2_of_ranges_patch(struct pci_dev *pdev, int bar)
{
	int ret, na;
	struct device *dev = &pdev->dev;
	struct device_node *dn = dev->of_node;
	struct of_changeset *cs = devm_kzalloc(dev, sizeof(*cs), GFP_KERNEL);
	__be32 v[OF_MAX_ADDR_CELLS + 2] = {};
	if (!cs)
		return -ENOMEM;
	na = of_n_addr_cells(dn);
	if (WARN_ON(!OF_CHECK_ADDR_COUNT(na)))
		return -EINVAL;

	if (WARN_ON(pci_resource_start(pdev, bar) > U32_MAX))
		return -EINVAL;
	if (WARN_ON(pci_resource_len(pdev, bar) > U32_MAX))
		return -EINVAL;
	v[na]     = cpu_to_be32(pci_resource_start(pdev, bar)),  /* child addr */
	v[na + 1] = cpu_to_be32(pci_resource_len(pdev, bar)), /* child size */

	of_changeset_init(cs);

	ret = mga2_of_add_property(cs, dn, "ranges", v, sizeof(v));
	if (ret < 0)
		goto done;

	ret = of_changeset_apply(cs);
	if (ret < 0)
		goto done;
	ret = devm_add_action(dev, mga2_of_changeset_release, cs);
	if (ret < 0)
		goto done;
done:
	if (ret < 0)
		of_changeset_destroy(cs);
	return ret;
}


static struct platform_driver * const drivers[] = {
	&mga2_pic_driver,
	&mga2_gpio_driver,
	&mga2_gpio_pwm_driver,
	&mga2_pwm_driver,
	&mga2_crtc_driver,
	&mga2_hdmi_driver,
	&mga2_rgb_driver,
	&mga2_dsi_driver,
	&mga2_lvds_driver,
	&mga2_pll_driver,
	&mga2_clk_mux_driver,
};


static void mga2_load_3d(void *data, async_cookie_t cookie)
{
	request_module_nowait("galcore");
	request_module_nowait("vivante");
}

static int mga2_compare_of(struct device *dev, void *data)
{
	DRM_DEBUG_DRIVER("Comparing of node %pOF with %pOF\n",
			 dev->of_node,
			 data);
	return dev->of_node == data;
}

static void mga20_reset(struct pci_dev *pdev)
{
	u16 cmd, vcfg, tmp;
	int timeout_us = 1;
#if HZ < 100 /* supposing it is processor prototype */
	timeout_us *= 200;
#endif
#define PCI_VCFG	0x40
#define PCI_MGA2_RESET	(1 << 2)
	pci_read_config_word(pdev, PCI_COMMAND, &cmd);
	pci_write_config_word(pdev, PCI_COMMAND,
				cmd & ~PCI_COMMAND_MASTER);

	pci_read_config_word(pdev, PCI_VCFG, &vcfg);
	vcfg &= ~PCI_MGA2_RESET;
	pci_write_config_word(pdev, PCI_VCFG,
				vcfg | PCI_MGA2_RESET);
	pci_read_config_word(pdev, PCI_VCFG, &tmp);
	udelay(timeout_us);
	pci_write_config_word(pdev, PCI_VCFG, vcfg);
	pci_write_config_word(pdev, PCI_COMMAND, cmd);
}

#define PCI_MCST_CFG	0x40
#define PCI_MCST_RESET		(1 << 6)
#define PCI_MCST_IOMMU_DSBL	(1 << 5)
#define PCI_MCST_IOMMU_BL_DSBL	(1 << 4)
#define PCI_MCST_IOMMU_FB_DSBL	(1 << 3)
static void mga25_enable_iommu(struct pci_dev *pdev)
{
	u8 tmp8;
	/* enable iommu translation */
	pci_read_config_byte(pdev, PCI_MCST_CFG, &tmp8);
	tmp8 &= ~(PCI_MCST_IOMMU_DSBL | PCI_MCST_IOMMU_BL_DSBL |
			PCI_MCST_IOMMU_FB_DSBL);
	pci_write_config_byte(pdev, PCI_MCST_CFG, tmp8);
}

static void mga2_reset(struct drm_device *drm)
{
	struct mga2 *mga2 = drm->dev_private;
	struct device *dev = drm->dev;
	struct pci_dev *pdev = to_pci_dev(dev);

	/* Lock vga-console to prevent e2c3 deadlock (bug 136108). */
	console_lock();

	switch (mga2->dev_id) {
	case MGA20_PCI_PROTO:
	case MGA25_PCI_PROTO:
	case MGA26_PCI_PROTO:
	case MGA27_PCI_PROTO:/*deadlock at pci-proto*/
		goto out;
	case MGA20_PROTO:
	case MGA20:
		mga20_reset(pdev);
		goto out;
	case MGA26:
	case MGA26_PROTO: /* use pci-e flr capability*/
		WARN_ON(pci_reset_function_locked(pdev));
		goto out;
	case MGA25:
	case MGA25_PROTO:
	case MGA27:
	case MGA27_PROTO: /* use reset_mcst_generic_dev() */
		WARN_ON(pci_reset_function_locked(pdev));
		mga25_enable_iommu(pdev);
		goto out;
	default:
		WARN_ON(1);
	}
out:;
	console_unlock();
}

static void mga2_init_hw(struct mga2 *mga2)
{
	int r;
	struct regmap *regmap = mga2->regmap;
	BUG_ON(!regmap);

	if (mga20(mga2->dev_id)) {
		/* Bug 140737 */
		regmap_write(regmap, 0x2810, 0x0000f001);
		regmap_write(regmap, 0x2c10, 0x0000f001);
		/* disable vga to prevent dma-access initiated
		 in restore_vga_text() */
		regmap_write(regmap, 0x800, 0x80000003);
	} else if (mga2->dev_id == MGA25 || mga2->dev_id == MGA25_PROTO) { /*TODO*/
		for (r = 0x400; r <= 0xc00; r += 0x400) /*Bug 138934*/
			regmap_write(regmap, r + 0xc0, 0x8080);
		regmap_write(regmap, 0x2ca0, 0x00008080);
		/* disable vga to prevent dma-access initiated
		 in restore_vga_text() */
		regmap_write(regmap, 0x400, 0x80000003);
	} else if (mga2->dev_id == MGA26 || mga2->dev_id == MGA26_PROTO) {
		for (r = 0x400; r <= 0xc00; r += 0x400) /*Bug 138934*/
			regmap_write(regmap, r + 0xc4, 0x00010100);
		/* disable vga to prevent dma-access initiated
		 in restore_vga_text() */
		regmap_write(regmap, 0x400, 0x80000003);
	} else if (mga2->dev_id == MGA27 || mga2->dev_id == MGA27_PROTO) {
		for (r = 0x400; r <= 0xc00; r += 0x400) /*Bug 138934*/
			regmap_write(regmap, r + 0xc4, 0x00010100);
		/* disable vga to prevent dma-access initiated
		 in restore_vga_text() */
		regmap_write(regmap, 0x400, 0x80000003);
	}
}

static int mga2_init(struct drm_device *drm, int reg_bar, int vram_bar)
{
	int ret = 0;
	u64 vstart = 0, vsize = 0;
	struct device *dev = drm->dev;
	struct pci_dev *pdev = to_pci_dev(dev);
	struct mga2 *mga2 = devm_kzalloc(dev, sizeof(*mga2), GFP_KERNEL);
	if (!mga2)
		return -ENOMEM;

	if ((ret = pci_enable_device(pdev)))
		goto out;

	mga2->dev_id = mga2_get_version(dev);
	if (mga2->dev_id < 0)
		return -ENODEV;

	if (mga2_has_vram(mga2->dev_id)) {
		if (WARN_ON(vram_bar < 0))
			return WARN_ON(-EINVAL);

		vstart = pci_resource_start(pdev, vram_bar);
		vsize = pci_resource_len(pdev, vram_bar);
		if (mga2->dev_id == MGA26_PCIe ||
				mga2->dev_id == MGA26_PCIe_PROTO) {
			/* bug 149246: leave one quarter for 3d-gpu */
			vsize /= 4;
		}
		mga2->vram_paddr = vstart;

		if ((ret = dma_set_mask(dev, DMA_BIT_MASK(64))))
			goto out;
		if ((ret = dma_set_coherent_mask(dev, DMA_BIT_MASK(64))))
			goto out;

	}

	WARN_ON(dma_set_max_seg_size(dev, UINT_MAX));

	mga2->regs = devm_ioremap(dev,
			pci_resource_start(pdev, reg_bar),
			pci_resource_len(pdev, reg_bar));
	if (WARN_ON(!mga2->regs)) {
		ret = -EIO;
		goto out;
	}
	mga2_regmap_config.max_register = pci_resource_len(pdev, reg_bar) - 4;
	mga2->regmap = devm_regmap_init_mmio(dev, mga2->regs,
					   &mga2_regmap_config);
	if (WARN_ON(IS_ERR(mga2->regmap))) {
		ret = PTR_ERR(mga2->regmap);
		goto out;
	}
	dev_set_drvdata(dev, drm);

	drm->dev_private = mga2;
	mga2->drm = drm;
	mutex_init(&mga2->bctrl_mu);
	spin_lock_init(&mga2->fence_lock);
	atomic_set(&mga2->ring_int, 0);

	drm_mm_init(&mga2->vram_mm, vstart, vsize);

	mga2_reset(drm);
	mga2_init_hw(mga2);
	pci_set_master(pdev);

	drm_mode_config_init(drm);
	drm->mode_config.funcs = &mga2_mode_funcs;
	drm->mode_config.helper_private = &mga2_mode_config_helpers;

	drm->mode_config.min_width = 0;
	drm->mode_config.min_height = 0;
	drm->mode_config.preferred_depth = 24;
	 /*XXX: drm_gem_vram_helper.c won't work without this*/
	if (mga2_has_vram(mga2->dev_id))
		drm->mode_config.prefer_shadow = 1;
	drm->mode_config.quirk_addfb_prefer_host_byte_order = true;

	drm->mode_config.max_width = (1 << 16) - 1;
	drm->mode_config.max_height = (1 << 16) - 1;
	drm->max_vblank_count = 0xffffffff; /* full 32 bit counter */

	if (WARN_ON((ret = mga2fb_bctrl_init(mga2))))
		goto out;
	if (mga20(mga2->dev_id)) {
		/* 3d has no pci-device, so load drivers here. */
		/* Do it on another thread to avoid deadlock. */
		async_schedule(mga2_load_3d, NULL);
	}
out:
	return ret;
}

static int mga2_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int reg_bar, vram_bar;
	int ret, i, id = 0;
	struct mga2 *mga2;
	struct device_node *np;
	struct device *dev = &pdev->dev;
	char *m[] = { "pwm-bl", "panel-lvds", "lp872x", "fixed", "i2c-dev",
		"panel-simple", "ti-sn65dsi86", "i2c-gpio",
		"dw-mipi-dsi", "sii902x", "simple-bridge",
		"display-connector", "sil164", "ite-it66121" };
	struct drm_device *drm = drm_dev_alloc(&mga2_drm_driver, dev);
	if (WARN_ON(IS_ERR(drm)))
		return PTR_ERR(drm);

	ret = drm_aperture_remove_conflicting_pci_framebuffers(pdev,
				&mga2_drm_driver);
	if (WARN_ON(ret))
		goto err_drm_dev_put;

	np = dev->of_node;
	if (!np) {
		ret = mga2_get_emebedded_dtb(pdev);
		if (ret <= 0) {
			dev_err(&pdev->dev, "*ERROR*: No device tree found "
					"(please upgrade dtb on flash).\n");
			goto err_drm_dev_put;
		}
		id = ret;
		np = dev->of_node;
	}
	/* load dependent modules */
	for (i = 0; i < ARRAY_SIZE(m); i++) {
		if (WARN((ret = request_module(m[i])),
				"*ERROR*: failed to load %s module: %d\n",
				 m[i], ret)) {
			goto err_drm_dev_put;
		}
	}

	ret = of_property_read_u32(np, "reg-bar", &reg_bar);
	if (WARN_ON(ret))
		goto err_drm_dev_put;
	ret = of_property_read_u32(np, "vram-bar", &vram_bar);
	if (ret)
		vram_bar = -1;

	ret = mga2_of_ranges_patch(pdev, reg_bar);
	if (WARN_ON(ret))
		goto err_drm_dev_put;

	ret = mga2_init(drm, reg_bar, vram_bar);
	if (ret)
		goto err_drm_dev_put;

	mga2 = drm->dev_private;
	mga2->of_overlay_id = id;
	/* HACK: use underscore version of the function to prevent references to
	 the module */
	ret = __platform_register_drivers(drivers, ARRAY_SIZE(drivers), NULL);
	if (WARN_ON(ret))
		goto err;

	ret = i2c_add_driver(&cy22394_driver);
	if (WARN_ON(ret))
		goto err;

	ret = devm_of_platform_populate(dev);
	if (WARN_ON(ret))
		goto err;

	ret = drm_of_component_probe(dev, mga2_compare_of, &mga2_ops);
	if (WARN_ON(ret))
		goto err;

	return ret;
err:
	platform_unregister_drivers(drivers, ARRAY_SIZE(drivers));
	i2c_del_driver(&cy22394_driver);
err_drm_dev_put:
	drm_dev_put(drm);
	if (ret == -EPROBE_DEFER) /* to avoid recursion*/
		return -EINVAL;
	return ret;
}

static void mga2_pci_remove(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	struct drm_device *drm = dev_get_drvdata(dev);
	struct mga2 *mga2 = drm->dev_private;
	component_master_del(dev, &mga2_ops);
	i2c_del_driver(&cy22394_driver);
	platform_unregister_drivers(drivers, ARRAY_SIZE(drivers));
	if (mga2->of_overlay_id) {
		of_node_put(dev->of_node);
		dev->of_node = NULL;
	}
}

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

#ifdef CONFIG_PM_SLEEP
static int mga2_resume(struct device *dev)
{
	int ret;
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm = pci_get_drvdata(pdev);
	struct mga2 *mga2 = drm->dev_private;

	if (pci_enable_device(pdev))
		return -EIO;

	mga2_reset(drm);

	mga2_init_hw(mga2);

	pci_set_master(pdev);

	if ((ret = mga2fb_bctrl_hw_init(mga2)))
		goto out;

	mga2->head = 0;
	mga2->tail = 0;
	mga2->fence_seqno = 0;

	ret = drm_mode_config_helper_resume(drm);
out:
	return ret;
}
#endif

static SIMPLE_DEV_PM_OPS(mga2_pm_ops, mga2_suspend, mga2_resume);

static void mga2_pci_shutdown(struct pci_dev *pdev)
{
	mga2_suspend(&pdev->dev);

	/*
	 * After kexec MGA missing some setup from boot, so
	 * forbid access for VGA-IO registers through IO space
	 * (and allow through MEMBAR space) and set VGA-incompatible
	 * mode for display controller.
	 */
	struct drm_device *drm = pci_get_drvdata(pdev);
	struct mga2 *mga2 = drm->dev_private;
	if (mga2->dev_id == MGA25 || mga2->dev_id == MGA25_PROTO)
		regmap_write(mga2->regmap, 0x400, 0x3);

}

static const struct pci_device_id mga2_pci_id_list[] = {
	{ PCI_VDEVICE(MCST_TMP, PCI_DEVICE_ID_MCST_MGA27) },
	{ PCI_VDEVICE(MCST_TMP, PCI_DEVICE_ID_MCST_MGA26) },
	{ PCI_VDEVICE(MCST_TMP, PCI_DEVICE_ID_MCST_MGA25) },
	{ PCI_VDEVICE(MCST_TMP, PCI_DEVICE_ID_MCST_MGA2)},
	{},
};
MODULE_DEVICE_TABLE(pci, mga2_pci_id_list);

static struct pci_driver mga2_pci_driver = {
	.name = DRIVER_NAME,
	.id_table = mga2_pci_id_list,
	.probe = mga2_pci_probe,
	.remove = mga2_pci_remove,
	.shutdown = mga2_pci_shutdown,
	.driver.pm = &mga2_pm_ops,
};
module_pci_driver(mga2_pci_driver);

MODULE_SOFTDEP("pre: pwm-bl");
MODULE_SOFTDEP("pre: panel-lvds");
MODULE_SOFTDEP("pre: lp872x");
MODULE_SOFTDEP("pre: fixed");
MODULE_SOFTDEP("pre: i2c-dev");
MODULE_SOFTDEP("pre: panel-simple");
MODULE_SOFTDEP("pre: ti-sn65dsi86");
MODULE_SOFTDEP("pre: i2c-gpio");
MODULE_SOFTDEP("pre: dw-mipi-dsi");
MODULE_SOFTDEP("pre: sii902x");
MODULE_SOFTDEP("pre: simple-bridge");
MODULE_SOFTDEP("pre: display-connector");
MODULE_SOFTDEP("pre: sil164");
MODULE_SOFTDEP("pre: ite-it66121");

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL v2");
