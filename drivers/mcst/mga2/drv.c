

#include "drv.h"

#define DRIVER_AUTHOR		"MCST"

#define DRIVER_NAME		"mga2"
#define DRIVER_DESC		"DRM driver for MCST MGA2"
#define DRIVER_DATE		"20210728"

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
		[MGA2_PCI_PROTO]  = "mcst,mga20-pci-proto",
		[MGA20_PROTO]     = "mcst,mga20-proto",
		[MGA20]           = "mcst,mga20",
		[MGA25_PCI_PROTO] = "mcst,mga25-pci-proto",
		[MGA25_PROTO]     = "mcst,mga25-proto",
		[MGA25]           = "mcst,mga25",
		[MGA26_PCI_PROTO] = "mcst,mga26-pci-proto",
		[MGA26_PROTO]     = "mcst,mga26-proto",
		[MGA26]           = "mcst,mga26",
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

struct drm_ioctl_desc mga2_ioctls[] = {
	DRM_IOCTL_DEF_DRV(MGA2_BCTRL, mga2_bctrl_ioctl,  DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_GEM_CREATE, mga2_gem_create_ioctl, DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_GEM_MMAP, mga2_gem_mmap_ioctl, DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_SYNC, mga2_gem_sync_ioctl, DRM_AUTH | DRM_UNLOCKED),
     	DRM_IOCTL_DEF_DRV(MGA2_INFO, mga2_info_ioctl, DRM_AUTH | DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(MGA2_AUC2, mga2_auc2_ioctl,  DRM_AUTH | DRM_UNLOCKED),
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

static struct drm_driver mga2_drm_driver = {
	.driver_features = DRIVER_MODESET | DRIVER_GEM | DRIVER_ATOMIC,

	.fops = &mga2_fops,
	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,
	.date = DRIVER_DATE,
	.major = DRIVER_MAJOR,
	.minor = DRIVER_MINOR,
	.patchlevel = DRIVER_PATCHLEVEL,

	.lastclose = mga2_lastclose,

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


	.ioctls = mga2_ioctls,
	.num_ioctls = DRM_ARRAY_SIZE(mga2_ioctls),

#if defined(CONFIG_DEBUG_FS)
	.debugfs_init = mga2_debugfs_init,
#endif
};

static struct regmap_config mga2_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.max_register = 0,
};

static struct drm_framebuffer *mga2_user_framebuffer_create(struct drm_device
							    *drm, struct drm_file
							    *file, const struct
							    drm_mode_fb_cmd2
							    *mode_cmd)
{
	struct drm_gem_object *gobj;
	struct mga2_framebuffer *mga2_fb;
	int ret;

	gobj = drm_gem_object_lookup(file, mode_cmd->handles[0]);
	if (gobj == NULL)
		return ERR_PTR(-ENOENT);

	mga2_fb = kzalloc(sizeof(*mga2_fb), GFP_KERNEL);
	if (!mga2_fb) {
		drm_gem_object_put_unlocked(gobj);
		return ERR_PTR(-ENOMEM);
	}

	ret = mga2_framebuffer_init(drm, mga2_fb,
			(struct drm_mode_fb_cmd2 *)mode_cmd, gobj);
	if (ret) {
		drm_gem_object_put_unlocked(gobj);
		kfree(mga2_fb);
		return ERR_PTR(ret);
	}
	return &mga2_fb->base;
}

static void mga2_drm_output_poll_changed(struct drm_device *drm)
{
	struct mga2 *mga2 = drm->dev_private;
	if (mga2->fbdev)
		drm_fb_helper_hotplug_event(&mga2->fbdev->helper);
}

static const struct drm_mode_config_funcs mga2_mode_funcs = {
	.fb_create = mga2_user_framebuffer_create,
	.output_poll_changed = mga2_drm_output_poll_changed,
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

static void mga2_load_3d(void *data, async_cookie_t cookie)
{
	request_module_nowait("galcore");
	request_module_nowait("vivante");
}

void mga2_lastclose(struct drm_device *drm)
{
	struct mga2 *mga2 = drm->dev_private;
	if (mga2->fbdev)
		drm_fb_helper_restore_fbdev_mode_unlocked(&mga2->fbdev->helper);
}

static int mga2_compare_of(struct device *dev, void *data)
{
	DRM_DEBUG_DRIVER("Comparing of node %pOF with %pOF\n",
			 dev->of_node,
			 data);
	return dev->of_node == data;
}

static irqreturn_t mga2_irq_handler(int irq, void *arg)
{
	struct mga2 *mga2 = arg;
	mga2_update_ptr(mga2);
	return IRQ_HANDLED;
}

#define PCI_MCST_CFG	0x40
#define PCI_MCST_RESET		(1 << 6)
#define PCI_MCST_IOMMU_DSBL	(1 << 5)
#define PCI_MCST_IOMMU_BL_DSBL	(1 << 4)
#define PCI_MCST_IOMMU_FB_DSBL	(1 << 3)

void mga2_reset(struct drm_device *drm)
{
	u16 cmd, vcfg, tmp;
	struct mga2 *mga2 = drm->dev_private;
	struct device *dev = drm->dev;
	struct pci_dev *pdev = to_pci_dev(dev);
	/* Lock vga-console to prevent e2c3 deadlock (bug 136108). */
	console_lock();

	if (!mga20(mga2->dev_id)) {
		u8 tmp;
		pci_reset_function_locked(pdev);
		if (mga2->dev_id != MGA25 && mga2->dev_id != MGA25_PROTO)
			goto out;
		/* enable iommu translation */
		pci_read_config_byte(pdev, PCI_MCST_CFG, &tmp);
		tmp &= ~(PCI_MCST_IOMMU_DSBL | PCI_MCST_IOMMU_BL_DSBL |
				PCI_MCST_IOMMU_FB_DSBL);
		pci_write_config_byte(pdev, PCI_MCST_CFG, tmp);
		goto out;
	}
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
	udelay(1);
	pci_write_config_word(pdev, PCI_VCFG, vcfg);
	pci_write_config_word(pdev, PCI_COMMAND, cmd);
out:
	console_unlock();
}

static int mga2_init(struct drm_device *drm)
{
	int ret = 0, r, reg_bar, vram_bar;
	u64 vstart = 0, vsize = 0;
	struct regmap *regmap;
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

	switch (mga2->dev_id) { /*TODO*/
	case MGA20:
		reg_bar = 2;
		break;
	case MGA25:
		reg_bar = 0;
		break;
	case MGA26:
	case MGA26_PROTO:
		reg_bar = 2;
		break;
	default:
		return WARN_ON(-ENODEV);

	}
	if (mga2_has_vram(mga2->dev_id)) {
		if (mga20(mga2->dev_id))
			vram_bar = 0;
		else /*TODO*/
			return WARN_ON(-ENODEV);

		vstart = pci_resource_start(pdev, vram_bar);
		vsize = pci_resource_len(pdev, vram_bar);
		mga2->vram_paddr = vstart;

		if ((ret = dma_set_mask(dev, DMA_BIT_MASK(64))))
			goto out;
		if ((ret = dma_set_coherent_mask(dev, DMA_BIT_MASK(64))))
			goto out;
	}
	mga2->regs = devm_ioremap(dev,
			pci_resource_start(pdev, reg_bar),
			pci_resource_len(pdev, reg_bar));
	if (WARN_ON(!mga2->regs)) {
		ret = -EIO;
		goto out;
	}
	mga2_regmap_config.max_register = pci_resource_len(pdev, reg_bar) - 4;
	regmap = devm_regmap_init_mmio(dev, mga2->regs,
					   &mga2_regmap_config);
	if (WARN_ON(IS_ERR(regmap))) {
		ret = PTR_ERR(regmap);
		goto out;
	}
	dev_set_drvdata(dev, drm);

	drm->pdev = pdev;/*FIXME:*/
	drm->dev_private = mga2;
	mga2->drm = drm;
	mutex_init(&mga2->bctrl_mu);
	mutex_init(&mga2->vram_mu);
	spin_lock_init(&mga2->fence_lock);
	atomic_set(&mga2->ring_int, 0);

	mga2_reset(drm);
	pci_set_master(pdev);
	if (mga20(mga2->dev_id)) {
		/* Bug 140737 */
		regmap_write(regmap, 0x2810, 0x0000f001);
		regmap_write(regmap, 0x2c10, 0x0000f001);
		/* disable vga to prevent dma-access initiated
		 in restore_vga_text() */
		regmap_write(regmap, 0x800, 0x80000003);
	} else if (mga25(mga2->dev_id)) { /*TODO*/
		for (r = 0x400; r <= 0xc00; r += 0x400) /*Bug 138934*/
			regmap_write(regmap, r + 0xc0, 0x8080);
		regmap_write(regmap, 0x2ca0, 0x00008080);
		/* disable vga to prevent dma-access initiated
		 in restore_vga_text() */
		regmap_write(regmap, 0x400, 0x80000003);
	}
	if (mga26(mga2->dev_id)) {
		for (r = 0x400; r <= 0xc00; r += 0x400) /*Bug 138934*/
			regmap_write(regmap, r + 0xc4, 0x00010100);
	}
	drm->mode_config.funcs = &mga2_mode_funcs;
	drm->mode_config.helper_private = &mga2_mode_config_helpers;

	drm->mode_config.min_width = 0;
	drm->mode_config.min_height = 0;
	drm->mode_config.preferred_depth = 24;
	drm->mode_config.prefer_shadow = 0;
	drm->mode_config.quirk_addfb_prefer_host_byte_order = true;

        drm->mode_config.max_width = (1 << 16) - 1;
        drm->mode_config.max_height = (1 << 16) - 1;
	drm->max_vblank_count = 0xffffffff; /* full 32 bit counter */

	mga2->uncached_pool = gen_pool_create(PAGE_SHIFT, dev_to_node(dev));
	if (!mga2->uncached_pool) {
		ret = -ENOMEM;
		goto out;
	}

	drm_mm_init(&mga2->vram_mm, vstart, vsize);
	drm_mode_config_init(drm);
	drm_kms_helper_poll_init(drm);
	if (mga20(mga2->dev_id)) {
		/* 3d has no pci-device, so load drivers here. */
		/* Do it on another thread to avoid deadlock. */
		async_schedule(mga2_load_3d, NULL);
	}
out:
	return ret;
}

static void mga2_cleanup(struct drm_device *drm)
{
	struct device *dev = drm->dev;
	struct mga2 *mga2 = drm->dev_private;
	drm_kms_helper_poll_fini(drm);
	drm_mode_config_cleanup(drm);
	drm_mm_takedown(&mga2->vram_mm);
	mga2_pool_destroy(mga2->uncached_pool, dev);
}


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

static int mga2_bind(struct device *dev)
{
	int ret, irq;
	struct drm_device *drm = dev_get_drvdata(dev);
	struct mga2 *mga2 = drm->dev_private;

	ret = component_bind_all(dev, drm);
	if (ret)
		goto err;

	irq = of_irq_get(dev->of_node, 0);
	if (WARN_ON(irq < 0)) {
		ret = irq;
		goto err_unbind_all;
	}
	mga2->irq = irq;
	mga2->hwirq = irqd_to_hwirq(irq_get_irq_data(irq));
	irq_set_status_flags(irq, IRQ_NOAUTOEN | IRQ_DISABLE_UNLAZY);
	ret = devm_request_irq(dev, irq, mga2_irq_handler,
			       0, dev_name(dev), mga2);
	if (WARN_ON(ret))
		goto err_unbind_all;
	/*
	 * enable drm irq mode.
	 * - with irq_enabled = true, we can use the vblank feature.
	 */
	drm->irq_enabled = true;

	ret = drm_vblank_init(drm, drm->mode_config.num_crtc);
	if (WARN_ON(ret))
		goto err_cleanup;

	if ((ret = mga2fb_bctrl_init(mga2)))
	if (WARN_ON(ret))
		goto err_cleanup;

	drm_mode_config_reset(drm);
	mga2_setup_possible_clones(drm);
	ret = mga2_fbdev_init(drm);
	if (WARN_ON(ret))
		goto err_cleanup;

	if (mga2_use_uncached(mga2->dev_id)) {
		u32 v = mga2->uncached_pool_first_pa >> 32;
		WARN_ON(!mga2->uncached_pool_first_pa);
		writel(v, mga2->regs + MGA2_6_VMMUX_OFFSETH);
		writel(v, mga2->regs + MGA2_6_FBMUX_OFFSETH);
	}

	ret = drm_dev_register(drm, 0);
	if (WARN_ON(ret))
		goto err_fbdev;

	return 0;

err_fbdev:
	mga2_fbdev_fini(drm);
err_cleanup:
	mga2_cleanup(drm);
err_unbind_all:
	component_unbind_all(drm->dev, drm);
err:
	return ret;
}

static void mga2_unbind(struct device *dev)
{
	struct drm_device *drm = dev_get_drvdata(dev);

	drm_dev_unregister(drm);
	drm_atomic_helper_shutdown(drm);
	mga2_fbdev_fini(drm);
	mga2_cleanup(drm);
	component_unbind_all(drm->dev, drm);
	drm_dev_put(drm);
}

static const struct component_master_ops mga2_ops = {
	.bind   = mga2_bind,
	.unbind = mga2_unbind,
};

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


/*FIXME:*/
static struct of_changeset changeset;
static void mga2_of_changeset_release(void *data)
{
	WARN_ON(of_changeset_revert(&changeset));
	of_changeset_destroy(&changeset);
}

#define OF_MAX_ADDR_CELLS	4
#define OF_CHECK_ADDR_COUNT(na)	((na) > 0 && (na) <= OF_MAX_ADDR_CELLS)

static int mga2_of_ranges_patch(struct pci_dev *pdev, int bar)
{
	int ret, na;
	struct device *dev = &pdev->dev;
	struct device_node *dn = dev->of_node;
	struct of_changeset *cs = &changeset;
	__be32 v[OF_MAX_ADDR_CELLS + 2] = {};

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
	ret = devm_add_action(dev, mga2_of_changeset_release, NULL);
	if (ret < 0)
		goto done;
done:
	if (ret < 0)
		of_changeset_destroy(cs);
	return ret;
}

extern struct platform_driver mga2_pic_driver;
extern struct platform_driver mga2_lvds_driver;
extern struct platform_driver mga2_hdmi_driver;
extern struct platform_driver mga2_rgb_driver;
extern struct platform_driver mga2_dsi_driver;
extern struct platform_driver mga2_crtc_driver;
extern struct platform_driver mga2_gpio_driver;
extern struct platform_driver mga2_pwm_driver;
extern struct platform_driver mga2_gpio_pwm_driver;
extern struct platform_driver mga2_pll_driver;
extern struct platform_driver mga2_clk_mux_driver;

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

extern struct i2c_driver cy22394_driver;

static int mga2_get_lvds_channels_nr(struct device_node *np)
{
	int i, n = 0;
	struct device_node *r, *c;
	for_each_child_of_node(np, c) {
		if (!of_device_is_compatible(c, "mcst,mga2x-lvds"))
			continue;
		for (i = 0; i < 4; i++) {
			r = of_graph_get_remote_node(c, 1, i);
			if (of_device_is_compatible(r, "panel-lvds")) {
				n = of_graph_get_endpoint_count(r);
				of_node_put(c);
				of_node_put(r);
				goto out;
			}
			of_node_put(r);
		}
	}
out:
	return n;
}

static int mga2_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int reg_bar, vram_bar;
	int ret, i;
	struct mga2 *mga2;
	struct device_node *np;
	struct device *dev = &pdev->dev;
	char *m[] = { "pwm-bl", "panel-lvds", "lp872x", "i2c-dev",
		"panel-simple", "ti-sn65dsi86", "i2c-gpio",
		"dw-mipi-dsi", "sii902x", "dumb-vga-dac", "sil164" };
	struct drm_device *drm = drm_dev_alloc(&mga2_drm_driver, dev);
	if (IS_ERR(drm))
		return PTR_ERR(drm);

	np = dev->of_node;
	if (!np) {
		dev_err(&pdev->dev, "*ERROR*: No device tree found "
					"(please upgrade dtb on flash).\n");
		ret = -ENODEV;
		goto err_drm_dev_put;
	}
	/* load dependent modules */
	for (i = 0; i < ARRAY_SIZE(m); i++) {
		if ((ret = request_module(m[i])))
			goto err_drm_dev_put;
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

	ret = mga2_init(drm);
	if (ret)
		goto err_drm_dev_put;

	mga2 = drm->dev_private;
	mga2->used_lvds_channels = mga2_get_lvds_channels_nr(np);

	ret = platform_register_drivers(drivers, ARRAY_SIZE(drivers));
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
	return ret;
}

static void mga2_pci_remove(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	component_master_del(dev, &mga2_ops);
	i2c_del_driver(&cy22394_driver);
	platform_unregister_drivers(drivers, ARRAY_SIZE(drivers));
}

#ifdef CONFIG_PM_SLEEP
static int mga2_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm = pci_get_drvdata(pdev);
	int ret = drm_mode_config_helper_suspend(drm);
	if (ret)
		return ret;
	mga2_reset(drm);
	return 0;
}

static int mga2_resume(struct device *dev)
{
	int ret;
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm = pci_get_drvdata(pdev);
	struct mga2 *mga2 = drm->dev_private;

	if (pci_enable_device(pdev))
		return -EIO;

	mga2_reset(drm);
	pci_set_master(pdev);

	if ((ret = mga2fb_bctrl_init(mga2)))
		goto out;

	/*TODO:*/

	ret = drm_mode_config_helper_resume(drm);
out:
	return ret;
}
#endif

static SIMPLE_DEV_PM_OPS(mga2_pm_ops, mga2_suspend, mga2_resume);

static void mga2_pci_shutdown(struct pci_dev *pdev)
{
	struct drm_device *drm = pci_get_drvdata(pdev);
	/* prevent dma during reboot & kexec */
	mga2_reset(drm);
}

static const struct pci_device_id mga2_pci_id_list[] = {
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

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
