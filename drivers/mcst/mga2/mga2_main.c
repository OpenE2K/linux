/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include "mga2_drv.h"

#include <linux/console.h>
#include <linux/component.h>
#include <linux/dma-buf.h>
#include <linux/regmap.h>
#include <linux/genalloc.h>
#include <linux/async.h>

#include <drm/drm_gem.h>
#include <drm/drm_probe_helper.h>
#include <drm/ttm/ttm_bo_driver.h>

#ifdef CONFIG_E2K
#include <asm/set_memory.h>
#endif

MODULE_PARM_DESC(lvds, "LVDS channels number. "
			"Panel parameters may be set from cmdline. Example:\n"
			"\tvideo=LVDS-1:1600x1200@60 mga2.lvds=2");
int mga2_lvds_channels = 0;
module_param_named(lvds, mga2_lvds_channels, int, 0400);
MODULE_PARM_DESC(dvi, "enable dvi");
static bool mga2_dvi_enable = 0;
module_param_named(dvi, mga2_dvi_enable, bool, 0400);
MODULE_PARM_DESC(hdmi, "enable hdmi");
static bool mga2_hdmi_enable = 1;
module_param_named(hdmi, mga2_hdmi_enable, bool, 0400);
MODULE_PARM_DESC(extpll, "use external pll");
bool mga2_use_external_pll = 0;
module_param_named(extpll, mga2_use_external_pll, bool, 0400);
static s8 mga2_possible_crtc_mask[] = { [0 ... MGA2_MAX_CRTS_NR - 1] = -1 };
module_param_array_named(crtc_mask, mga2_possible_crtc_mask, byte, NULL, 0400);
MODULE_PARM_DESC(crtc_mask, "Override possible crtc mask");
int mga2_timeout_ms = 10000;
module_param_named(timeout, mga2_timeout_ms, int, 0644);
MODULE_PARM_DESC(timeout, "blitter, AUC & BCTRL timeout in milliseconds");

static struct gen_pool *mga2_uncached_pool;
static unsigned long mga2_uncached_pool_first_pa;

static void mga2_pool_destroy(struct gen_pool *pool, struct device *dev);

static void mga2_user_framebuffer_destroy(struct drm_framebuffer *fb)
{
	struct mga2_framebuffer *mga2_fb = to_mga2_framebuffer(fb);
	drm_framebuffer_cleanup(fb);
	drm_gem_object_put(mga2_fb->gobj);
	kfree(fb);
}

static int mga2_user_framebuffer_create_handle(struct drm_framebuffer *fb,
					       struct drm_file *file,
					       unsigned int *handle)
{
	return -EINVAL;
}

static const struct drm_framebuffer_funcs mga2_fb_funcs = {
	.destroy = mga2_user_framebuffer_destroy,
	.create_handle = mga2_user_framebuffer_create_handle,
};

int mga2_framebuffer_init(struct drm_device *drm,
			  struct mga2_framebuffer *mga2_fb,
			  struct drm_mode_fb_cmd2 *mode_cmd,
			  struct drm_gem_object *gobj)
{
	int ret;
	drm_helper_mode_fill_fb_struct(drm, &mga2_fb->base, mode_cmd);

	ret = drm_framebuffer_init(drm, &mga2_fb->base, &mga2_fb_funcs);
	if (ret) {
		DRM_ERROR("framebuffer init failed %d\n", ret);
		return ret;
	}
	mga2_fb->gobj = gobj;
	return 0;
}

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
		drm_gem_object_put(gobj);
		return ERR_PTR(-ENOMEM);
	}

	ret = mga2_framebuffer_init(drm, mga2_fb,
			(struct drm_mode_fb_cmd2 *)mode_cmd, gobj);
	if (ret) {
		drm_gem_object_put(gobj);
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

static int mga2_compare(struct device *dev, void *data)
{
	return dev == data;
}

static int mga2_bind(struct device *dev)
{
	return component_bind_all(dev, dev_get_drvdata(dev));
}

static void mga2_unbind(struct device *dev)
{
	component_unbind_all(dev, dev_get_drvdata(dev));
}

static const struct component_master_ops mga2_master_ops = {
	.bind = mga2_bind,
	.unbind = mga2_unbind,
};

static int mga2_add_hdmi(struct drm_device *drm)
{
	int ret = 0, i, irq;
	struct component_match *match = NULL;
	struct mga2 *mga2 = drm->dev_private;
	resource_size_t vid_phys = mga2->regs_phys + mga2->info->vid_regs_base;
	int bar = mga2->info->regs_bar;
	char *dev = mga2_p2(mga2) ? "mga2-hdmi" : "mga25-hdmi";
	struct resource mga2_hdmi_resources[][2] = {
	{
		[0] = {
			.flags	= IORESOURCE_MEM,
			.start	= 0x40000,
			.end	= 0x40000 + 0x20000 - 1
		},
		[1] = {
			.flags	= IORESOURCE_IRQ,
		},
	}, {
		[0] = {
			.flags	= IORESOURCE_MEM,
			.start	= 0x60000,
			.end	= 0x60000 + 0x20000 - 1
		},
		[1] = {
			.flags	= IORESOURCE_IRQ,
		},
	},
	};

	if (!mga2_hdmi(mga2))
		return 0;
	if ((ret = request_module("dw_hdmi_imx")))
		goto out;
	irq = drm->pdev->irq;
	if (mga2_p2(mga2))
		irq++;
	else if (mga2->subdevice == MGA26)
		irq = mga2->msix_entries[0].vector;

	for (i = 0; i < ARRAY_SIZE(mga2->mga2_hdmi_device); i++) {
		struct resource *r = &mga2_hdmi_resources[i][0];
		char name[64];
		sprintf(name, "DWC_hdmi_tx %d ddc", i);
		r[0].start += pci_resource_start(drm->pdev, bar);
		r[0].end += pci_resource_start(drm->pdev, bar);
		r[1].start = irq;
		r[1].end = irq;

		mga2->mga2_hdmi_device[i] =
			platform_device_register_resndata(drm->dev,
				dev, i, r,
				ARRAY_SIZE(mga2_hdmi_resources[0]),
				NULL, 0);
		if (!mga2->mga2_hdmi_device[i]) {
			ret = -1;
			goto out;
		}
		component_match_add(drm->dev, &match, mga2_compare,
				&mga2->mga2_hdmi_device[i]->dev);

		mga2->hdmi_ddc[i] = mga2_i2c_create(
					&mga2->mga2_hdmi_device[i]->dev,
					vid_phys + MGA2_VID0_DDCI2C +
					(i + 1) * MGA2_VID0_SZ, name,
					mga2->base_freq, 100 * 1000);

		if (!mga2->hdmi_ddc[i]) {
			ret = -1;
			goto out;
		}
	}
	ret = component_master_add_with_match(drm->dev,
					&mga2_master_ops, match);
	if (ret)
		goto out;
out:
	return ret;
}

static const u32 mga20_lvds_default_frame_table[
		LVDS_FRAME_TABLE_SZ] = { /*bug73760*/
	24, 25, 25, 25, 24, 24, 24,
	 2,  3,  4,  5,  6,  7, 15,
	23, 10, 11, 12, 13, 14, 22,
	27, 28, 18, 19, 20, 21, 26,
	16, 17,  8,  9,  0,  1, 25,
};

static int mga2_add_devices(struct drm_device *drm)
{
	int devtree_panel;
	struct drm_crtc *crtc;
	struct mga2 *mga2 = drm->dev_private;
	struct device_node *remote = NULL;
	resource_size_t vid_phys = mga2->regs_phys + mga2->info->vid_regs_base;
	void __iomem *vid_regs = mga2->regs + mga2->info->vid_regs_base;
	uint32_t crtc_mask = 0;
	int ret = 0, i, crtc_nr = 3;

	drm_for_each_crtc(crtc, drm)
		crtc_mask |= drm_crtc_mask(crtc);

	if (mga2_dvi_enable) {
		mga2->dvi_i2c =  mga2_i2c_create(drm->dev, vid_phys + MGA2_VID0_TXI2C,
				"SIL1178" " tx", mga2->base_freq, 50 * 1000);
		if (!mga2->dvi_i2c) {
			ret = -1;
			goto out;
		}
	}
	switch (mga2->subdevice) {
	case MGA25_PCI_PROTO:
	case MGA26_PCI_PROTO:
		goto out;
	case MGA2_P2_PROTO:
		ret = mga2_common_connector_init(drm, vid_phys,
				DRM_MODE_CONNECTOR_VGA, true, crtc_mask);
		goto out;
	case MGA2_P2:
		if (!mga2_dvi_enable)
			break;
		ret = mga2_dvi_init(drm, vid_regs, vid_phys);
		if (ret  == -ENODEV) {
			ret = 0;
			DRM_INFO("DVI i2c encoder not connected\n");
		}
		if (ret)
			goto out;
		break;
	case MGA26_PROTO:
		mga2->dvi_i2c =  mga2_i2c_create(drm->dev, vid_phys + MGA2_VID0_TXI2C,
				"ad9889b", mga2->base_freq, 50 * 1000);
		if (!mga2->dvi_i2c) {
			ret = -1;
			goto out;
		}
		crtc_nr = 1;
	case MGA25_PROTO:
		for (i = 0; i < crtc_nr && ret >= 0; i++) {
			s8 m = mga2_possible_crtc_mask[i];
			if (m < 0)
				m = crtc_mask;
			ret = mga2_common_connector_init(drm,
					vid_phys + i * MGA2_VID0_SZ,
					DRM_MODE_CONNECTOR_VGA, true, m);
		}
		goto out;
	case MGA25:
		if (!mga2_dvi_enable)
			break;
		ret = mga2_common_connector_init(drm, vid_phys,
				DRM_MODE_CONNECTOR_DVID, true, crtc_mask);
		if (ret)
			goto out;
		break;
	}

	if (mga2_hdmi_enable) {
		ret = mga2_add_hdmi(drm);
		if (ret)
			goto out;
	}

	if (!(mga2_lvds_channels == 0 || mga2_lvds_channels == 1 ||
		mga2_lvds_channels == 2 || mga2_lvds_channels == 4)) {
		DRM_WARN("wrong 'lvds' option (lvds=%d). "
			"LVDS initialization ignored\n", mga2_lvds_channels);
		mga2_lvds_channels = 0;
	}
	mga2->used_lvds_channels = mga2_lvds_channels;
	remote = of_graph_get_remote_node(drm->dev->of_node, 0, 0);
	devtree_panel = of_device_is_compatible(remote, "panel-lvds");
	if (devtree_panel || mga2_lvds_channels) {
		const u32 *f = mga20_lvds_default_frame_table;
		u32 *t = mga2->lvds_frame_table;
		if (devtree_panel) { /* load dependent modules */
			if ((ret = request_module("panel-lvds")))
				goto out;
		}
		ret = mga2_common_connector_init(drm, 0,
				DRM_MODE_CONNECTOR_LVDS, false, crtc_mask);
		if (ret < 0)
			goto out;
		if (WARN_ON(remote && ret == 0)) {
			ret = -ENODEV;
			goto out;
		}
		if (mga2->used_lvds_channels == 0)
			mga2->used_lvds_channels = ret;

		ret = of_property_read_u32_array(drm->dev->of_node,
			"frame-table",
			t, ARRAY_SIZE(mga2->lvds_frame_table));
		if (ret && ret != -EINVAL)
			goto out;
		if (ret) /* not found */
			memcpy(t, f, sizeof(mga2->lvds_frame_table));
		ret = 0;
	}
out:
	of_node_put(remote);
	return ret;
}

static void mga2_remove_devices(struct drm_device *drm)
{
	int i;
	struct mga2 *mga2 = drm->dev_private;

	if (mga2_hdmi_enable) {
		for (i = 0; i < ARRAY_SIZE(mga2->mga2_hdmi_device); i++) {
			mga2_i2c_destroy(mga2->hdmi_ddc[i]);
			platform_device_unregister(mga2->mga2_hdmi_device[i]);
		}
	}
	mga2_i2c_destroy(mga2->dvi_i2c);
}

#define PCI_MCST_CFG	0x40
#define PCI_MCST_RESET		(1 << 6)
#define PCI_MCST_IOMMU_DSBL	(1 << 5)
#define PCI_MCST_IOMMU_BL_DSBL	(1 << 4)
#define PCI_MCST_IOMMU_FB_DSBL	(1 << 3)

void mga2_reset(struct drm_device *drm)
{
	u32 o, d;
	u16 cmd, vcfg, tmp;
	struct mga2 *mga2 = drm->dev_private;
	/* Lock vga-console to prevent e2c3 deadlock (bug 136108). */
	console_lock();
	/* HACK: save gpio state of mga2-gpio driver */
	d = readl(mga2->regs + MGA2_VID3_GPIO_DIR);
	o = readl(mga2->regs + MGA2_VID3_GPIO_OUT);
	if (!mga2_p2(mga2)) {
		u8 tmp;
		pci_reset_function_locked(drm->pdev);
		if (!mga25(mga2))
			goto out;
		/* enable iommu translation */
		pci_read_config_byte(drm->pdev, PCI_MCST_CFG, &tmp);
		tmp &= ~(PCI_MCST_IOMMU_DSBL | PCI_MCST_IOMMU_BL_DSBL |
				PCI_MCST_IOMMU_FB_DSBL);
		pci_write_config_byte(drm->pdev, PCI_MCST_CFG, tmp);
		goto out;
	}
#define PCI_VCFG	0x40
#define PCI_MGA2_RESET	(1 << 2)
	pci_read_config_word(drm->pdev, PCI_COMMAND, &cmd);
	pci_write_config_word(drm->pdev, PCI_COMMAND,
				cmd & ~PCI_COMMAND_MASTER);

	pci_read_config_word(drm->pdev, PCI_VCFG, &vcfg);
	vcfg &= ~PCI_MGA2_RESET;
	pci_write_config_word(drm->pdev, PCI_VCFG,
				vcfg | PCI_MGA2_RESET);
	pci_read_config_word(drm->pdev, PCI_VCFG, &tmp);
	udelay(1);
	pci_write_config_word(drm->pdev, PCI_VCFG, vcfg);
	pci_write_config_word(drm->pdev, PCI_COMMAND, cmd);
out:
	writel(d, mga2->regs + MGA2_VID3_GPIO_DIR);
	writel(o, mga2->regs + MGA2_VID3_GPIO_OUT);
	console_unlock();
}

static unsigned int mga2_drm_encoder_clones(struct drm_encoder *encoder)
{
	struct drm_encoder *clone;
	struct drm_device *dev = encoder->dev;
	struct drm_connector *c;
	struct drm_connector_list_iter conn_iter;
	unsigned int clone_mask = 0;
	int cnt = 0;
	int type = DRM_MODE_CONNECTOR_Unknown;

	mutex_lock(&dev->mode_config.mutex);

	drm_connector_list_iter_begin(dev, &conn_iter);
	drm_for_each_connector_iter(c, &conn_iter) {
		if (c->encoder == encoder) {
			type = c->connector_type;
			break;
		}
	}
	drm_connector_list_iter_end(&conn_iter);

	drm_for_each_encoder(clone, dev) {
		if (clone != encoder) {
			drm_connector_list_iter_begin(dev, &conn_iter);
			drm_for_each_connector_iter(c, &conn_iter) {
				if (c->encoder == clone &&
						c->connector_type == type)
					clone_mask |= 1 << cnt;
			}
			drm_connector_list_iter_end(&conn_iter);
		}
		cnt++;
	}

	mutex_unlock(&dev->mode_config.mutex);

	return clone_mask;
}

static void mga2_setup_possible_clones(struct drm_device *dev)
{
	struct drm_encoder *encoder;

	drm_for_each_encoder(encoder, dev)
		encoder->possible_clones = mga2_drm_encoder_clones(encoder);
}

static struct regmap_config mga2_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.max_register = 0,
};

static struct drm_mode_config_helper_funcs mga2_mode_config_helpers = {
	.atomic_commit_tail	= drm_atomic_helper_commit_tail_rpm,
};

static void mga2_load_3d(void *data, async_cookie_t cookie)
{
	request_module_nowait("galcore");
	request_module_nowait("vivante");
}

int mga2_driver_load(struct drm_device *drm, unsigned long flags)
{
	struct mga2 *mga2;
	struct regmap *regmap;
	struct mga2_info *info = (void *)flags;
	int ret = 0;
	int irq = 0;
	u64 vstart = 0, vsize = 0;

	mga2 = devm_kzalloc(drm->dev, sizeof(struct mga2), GFP_KERNEL);
	if (!mga2)
		return -ENOMEM;

	drm->dev_private = mga2;
	mga2->drm = drm;
	mga2->info = info;
	mga2->drm->dev->of_node =
		of_find_compatible_node(NULL, NULL, "mcst,mga2");
	mutex_init(&mga2->bctrl_mu);
	mutex_init(&mga2->vram_mu);
	spin_lock_init(&mga2->fence_lock);

	mga2->subdevice = 0xffff;
	pci_read_config_word(drm->pdev, PCI_SUBSYSTEM_ID, &mga2->subdevice);

	DRM_INFO("subdevice ID: %x\n", mga2->subdevice);

	if (mga2->subdevice == MGA26_PCI_PROTO) {
		info->vram_bar = 2;
		info->regs_bar = 0;
	}
	if (mga2_has_vram(mga2)) {
		vstart = pci_resource_start(drm->pdev, info->vram_bar);
		vsize = pci_resource_len(drm->pdev, info->vram_bar);
		mga2->vram_paddr = vstart;

		if ((ret = dma_set_mask(drm->dev, DMA_BIT_MASK(64))))
			goto out;
		if ((ret = dma_set_coherent_mask(drm->dev, DMA_BIT_MASK(64))))
			goto out;
	}
	mga2->regs_phys = pci_resource_start(drm->pdev, info->regs_bar);
	mga2->regs = devm_ioremap(drm->dev,
			pci_resource_start(drm->pdev, info->regs_bar),
			pci_resource_len(drm->pdev, info->regs_bar));
	if (!mga2->regs) {
		ret = -EIO;
		goto out;
	}
	mga2_regmap_config.max_register =
			 pci_resource_len(drm->pdev, info->regs_bar) - 4;
	regmap = devm_regmap_init_mmio(drm->dev, mga2->regs,
					   &mga2_regmap_config);
	if (IS_ERR(regmap)) {
		ret = PTR_ERR(regmap);
		goto out;
	}

	switch (mga2->subdevice) {
	case MGA2_PCI_PROTO:
		mga2->base_freq = 133 * 1000 * 1000;
		mga2_use_external_pll = 1;
		break;
	case MGA2_P2_PROTO:
		mga2->base_freq = 6 * 1000 * 1000;
		mga2_use_external_pll = 1;
		break;
	case MGA2_P2:
		mga2->base_freq = 500 * 1000 * 1000;
		break;
	case MGA25_PCI_PROTO:
	case MGA26_PCI_PROTO:
		mga2->base_freq = 125 * 1000 * 1000;
		break;
	case MGA25_PROTO:
		mga2->base_freq = 5 * 1000 * 1000;
		break;
	case MGA25:
		mga2->base_freq = 1000 * 1000 * 1000;
		break;
	case MGA26_PROTO:
		mga2_use_external_pll = 1;
		mga2->base_freq = 80 * 1000 * 1000;
		break;
	case MGA26:
		mga2->base_freq = 1000 * 1000 * 1000;
		break;
	default:
		mga2->base_freq = 33 * 1000 * 1000;
		break;
	}
	mga2_reset(drm);
	pci_set_master(drm->pdev);

	drm_mm_init(&mga2->vram_mm, vstart, vsize);

	drm_mode_config_init(drm);

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

	mga2_uncached_pool = gen_pool_create(PAGE_SHIFT, dev_to_node(drm->dev));
	if (!mga2_uncached_pool) {
		ret = -ENOMEM;
		goto out;
	}

	ret = mga2_mode_init(drm);
	if (ret)
		goto out;

	irq = drm->pdev->irq;
	if (mga2_p2(mga2)) {
		irq++;
	} else if (mga2->subdevice == MGA26_PROTO ||
		mga2->subdevice == MGA26) {
		int i, numvecs = ARRAY_SIZE(mga2->msix_entries);
		/* populate entry values */
		for (i = 0; i < numvecs; i++)
			mga2->msix_entries[i].entry = i;

		ret = pci_enable_msix_range(drm->pdev,
					mga2->msix_entries,
					numvecs,
					numvecs);
		if (ret < 0)
			goto out;
		irq = mga2->msix_entries[0].vector;
	}
	ret = drm_irq_install(drm, irq);
	if (ret)
		goto out;

	ret = mga2_add_devices(drm);
	if (ret)
		goto out_dev;

	mga2_setup_possible_clones(drm);

	drm_mode_config_reset(drm);

	/* init kms poll for handling hpd */
	drm_kms_helper_poll_init(drm);

	if (mga2_use_uncached(mga2)) {
		u32 v = mga2_uncached_pool_first_pa >> 32;
		WARN_ON(!mga2_uncached_pool_first_pa);
		writel(v, mga2->regs + MGA2_6_VMMUX_OFFSETH);
		writel(v, mga2->regs + MGA2_6_FBMUX_OFFSETH);
	}

	/* enable irqs */
	mga2_driver_irq_postinstall(drm);

	ret = mga2_fbdev_init(drm);
	if (ret)
		goto out_fb;

	if (mga2_p2(mga2)) {
		/* 3d has no pci-device, so load drivers here. */
		/* Do it on another thread to avoid deadlock. */
		async_schedule(mga2_load_3d, NULL);
	}

	return ret;
out_fb:
	mga2_remove_devices(drm);
out_dev:
	schedule_timeout(msecs_to_jiffies(20));
	drm->irq_enabled = false;
	drm_kms_helper_poll_fini(drm);
	drm_mode_config_cleanup(drm);
	drm_mm_takedown(&mga2->vram_mm);
	mga2_mode_fini(drm);
out:
	drm->dev_private = NULL;
	return ret;
}

void mga2_driver_unload(struct drm_device *drm)
{
	struct mga2 *mga2 = drm->dev_private;
	unsigned msecs = 20;
	if (mga2_proto(mga2))
		msecs *= 20;
	schedule_timeout(msecs_to_jiffies(msecs));

	drm_atomic_helper_shutdown(drm);

	drm_kms_helper_poll_fini(drm);
	drm_irq_uninstall(drm);

	mga2_fbdev_fini(drm);
	mga2_mode_fini(drm);

	drm_mode_config_cleanup(drm);

	if (mga2_hdmi_enable)
		component_master_del(drm->dev, &mga2_master_ops);

	mga2_remove_devices(drm);
	drm_mm_takedown(&mga2->vram_mm);
	mga2_pool_destroy(mga2_uncached_pool, drm->dev);
}

void mga2_lastclose(struct drm_device *drm)
{
	struct mga2 *mga2 = drm->dev_private;
	if (mga2->fbdev)
		drm_fb_helper_restore_fbdev_mode_unlocked(&mga2->fbdev->helper);
}

static struct mga2_gem_object *
__mga2_gem_create(struct drm_device *drm, size_t size)
{
	int ret;
	struct mga2_gem_object *obj;
	struct drm_gem_object *gobj =
			 kzalloc(sizeof(*obj), GFP_KERNEL);
	if (!gobj)
		return ERR_PTR(-ENOMEM);
	obj = container_of(gobj, struct mga2_gem_object, base);

	ret = drm_gem_object_init(drm, gobj, size);
	if (ret)
		goto error;

	ret = drm_gem_create_mmap_offset(gobj);
	if (ret) {
		drm_gem_object_release(gobj);
		goto error;
	}

	return obj;

error:
	kfree(obj);
	return ERR_PTR(ret);
}

/*
 * Add a new chunk of uncached memory pages to the specified pool.
 *
 * @pool: pool to add new chunk of uncached memory to
 * @nid: node id of node to allocate memory from, or -1
 *
 * This is accomplished by first allocating a granule of cached memory pages
 * and then converting them to uncached memory pages.
 */
static int mga2_uncached_add_chunk(struct gen_pool *uc_pool, int nid)
{
	int ret;
	unsigned long pa;
	struct page *page = __alloc_pages_node(nid, GFP_KERNEL | __GFP_THISNODE,
							MAX_ORDER - 1);
	if (!page)
		return -1;
	pa = page_to_phys(page);
	if (mga2_uncached_pool_first_pa)
		WARN_ON(pa >> 32 != mga2_uncached_pool_first_pa >> 32);
	else
		mga2_uncached_pool_first_pa = pa;

	ret = gen_pool_add(uc_pool, pa,
			    PAGE_SIZE << (MAX_ORDER - 1), nid);
	if (ret)
		goto failed;
	/*FIXME: NUMA */
#ifdef CONFIG_E90S
	e90s_flush_l2_cache();
#elif defined(CONFIG_E2K)
	write_back_cache_all();
#else
	WARN("FIXME: add flush cache\n");
#endif
	return 0;
failed:
	__free_pages(page, MAX_ORDER - 1);
	return -1;
}

/*
 * mga2_uncached_alloc_page
 *
 * @nid: node id, or -1
 * @n_pages: number of contiguous pages to allocate
 *
 * Allocate the specified number of contiguous uncached pages on the
 * the requested node.
 */
static unsigned long mga2_uncached_alloc_page(int nid, int n_pages)
{
	unsigned long uc_addr;
	struct gen_pool *uc_pool = mga2_uncached_pool;

	do {
		uc_addr = gen_pool_alloc(uc_pool, n_pages * PAGE_SIZE);
		if (uc_addr != 0)
			return uc_addr;
	} while (mga2_uncached_add_chunk(uc_pool, nid) == 0);

	return 0;
}

/*
 * uncached_free_page
 *
 * @uc_addr: uncached address of first page to free
 * @n_pages: number of contiguous pages to free
 *
 * Free the specified number of uncached pages.
 */
static void mga2_uncached_free_page(unsigned long uc_addr, int n_pages)
{
	struct gen_pool *pool = mga2_uncached_pool;
	gen_pool_free(pool, uc_addr, n_pages * PAGE_SIZE);
}


static void *mga2_alloc_uncached(struct device *dev, size_t size,
		dma_addr_t *dma_handle, gfp_t gfp)
{
	void *v;
	int pages = PAGE_ALIGN(size) / PAGE_SIZE;
	unsigned long p = mga2_uncached_alloc_page(dev_to_node(dev), pages);
	if (p == 0)
		return NULL;

	v = ioremap_wc(p, size);
	if (!v) {
		mga2_uncached_free_page(dev_to_node(dev), pages);
		return NULL;
	}

	memset_io(v, 0, size);
	*dma_handle = p - (mga2_uncached_pool_first_pa & (~0UL << 32));

	return v;
}

static void mga2_free_uncached(struct device *dev, size_t size,
		void *cpu_addr, dma_addr_t dma_handle)
{
	int pages = PAGE_ALIGN(size) / PAGE_SIZE;
	iounmap(cpu_addr);
	dma_handle += mga2_uncached_pool_first_pa & (~0UL << 32);
	mga2_uncached_free_page(dma_handle, pages);
}

static void mga2_free_chunk(struct gen_pool *pool,
			      struct gen_pool_chunk *chunk, void *data)
{
	free_pages(chunk->start_addr, MAX_ORDER - 1);
}

static void mga2_pool_destroy(struct gen_pool *pool, struct device *dev)
{
	if (!pool)
		return;
	/* this is quite ugly but no better idea */
	gen_pool_for_each_chunk(pool, mga2_free_chunk, dev);
	gen_pool_destroy(pool);
}

struct drm_gem_object *mga2_gem_create(struct drm_device *drm,
				       size_t size, u32 domain)
{
	int ret;
	struct mga2_gem_object *obj;
	struct drm_gem_object *gobj;
	struct drm_mm_node *node;
	struct mga2 *mga2 = drm->dev_private;
	gfp_t flag = GFP_USER | __GFP_ZERO;

	if (domain == MGA2_GEM_DOMAIN_VRAM && !mga2_has_vram(mga2)
					&& !mga2_use_uncached(mga2)) {
		domain = MGA2_GEM_DOMAIN_CPU;
		size = PAGE_ALIGN(size);
		if (IS_ENABLED(CONFIG_E2K) && size / PAGE_SIZE > 8) {
			/* align to save tlb entries in iommu */
			size = ALIGN(size, HPAGE_SIZE);
			/* try hard */
			flag |= __GFP_RETRY_MAYFAIL;
		}
	} else {
		size = PAGE_ALIGN(size);
	}
	obj = __mga2_gem_create(drm, size);
	if (IS_ERR(obj))
		return ERR_CAST(obj);

	gobj = &obj->base;
	node = &obj->node;

	switch (domain) {
	case MGA2_GEM_DOMAIN_VRAM: if (mga2_use_uncached(mga2)) {
		obj->vaddr = mga2_alloc_uncached(drm->dev, size,
				&obj->dma_addr, flag);
		if (!obj->vaddr) {
			ret = -ENOMEM;
			goto fail;
		}
	} else {
		mutex_lock(&mga2->vram_mu);
		ret = drm_mm_insert_node(&mga2->vram_mm, node, size);
		mutex_unlock(&mga2->vram_mu);
		if (ret)
			goto fail;

		obj->dma_addr = node->start - mga2->vram_paddr;
		obj->vaddr = ioremap_wc(node->start, size);
		if (!obj->vaddr) {
			ret = -EFAULT;
			goto fail;
		}
		memset_io(obj->vaddr, 0, size);
	}
	break;
	case MGA2_GEM_DOMAIN_CPU: {
		obj->vaddr = dma_alloc_coherent(drm->dev, size,
				&obj->dma_addr, flag);
		if (!obj->vaddr && (flag & __GFP_RETRY_MAYFAIL)) {
			/* Couldn't allocate even after trying hard.
			 * Now we'll try indefinitely...
			 * IMPORTANT: this can hang current process
			 * if memory fragmentation is too high, the
			 * proper way is to use CMA. */
			flag &= ~__GFP_RETRY_MAYFAIL;
			flag |= __GFP_NOFAIL;
			obj->vaddr = dma_alloc_coherent(drm->dev, size,
					&obj->dma_addr, flag);
		}
		if (!obj->vaddr) {
			ret = -ENOMEM;
			goto fail;
		}
#ifdef CONFIG_E2K
		set_memory_wc((unsigned long) obj->vaddr,
			      PAGE_ALIGN(size) >> PAGE_SHIFT);
#endif
		break;
	}
	default:
		WARN_ON(1);
		ret = -EINVAL;
		goto fail;
	}
	obj->write_domain = domain;
	dma_resv_init(&obj->resv);

	return gobj;
      fail:
	drm_gem_object_release(gobj);
	kfree(obj);
	return ERR_PTR(ret);
}

void mga2_gem_free_object(struct drm_gem_object *gobj)
{
	struct drm_device *drm = gobj->dev;
	struct mga2_gem_object *mo = to_mga2_obj(gobj);
	struct drm_mm_node *node = &mo->node;
	struct dma_resv *resv = &mo->resv;
	struct mga2 *mga2 = (struct mga2 *)gobj->dev->dev_private;
	long ret = 0, timeout_msec = mga2_timeout(mga2);

	if (0)
		DRM_DEBUG("freeing %llx with %d\n", mo->dma_addr,
			resv->fence ? resv->fence->shared_count : 0);
	ret = dma_resv_wait_timeout_rcu(resv, true, false,
					msecs_to_jiffies(timeout_msec));
	if (ret == 0) {
		DRM_ERROR("mga2: reservation %d wait timed out.\n", mga2->tail);
	} else if (ret < 0) {
		DRM_ERROR("mga2: reservation wait failed (%ld).\n", ret);
	}

	drm_gem_free_mmap_offset(gobj);

	switch (mo->write_domain) {
	case MGA2_GEM_DOMAIN_VRAM:
		 if (mga2_use_uncached(mga2)) {
			mga2_free_uncached(drm->dev, gobj->size,
					mo->vaddr, mo->dma_addr);
		} else {
			mutex_lock(&mga2->vram_mu);
			drm_mm_remove_node(node);
			mutex_unlock(&mga2->vram_mu);
		}
		break;
	case MGA2_GEM_DOMAIN_CPU:
		 if (gobj->import_attach) {
			drm_prime_gem_destroy(gobj, mo->sgt);
			vunmap(mo->vaddr);
		} else if (mo->vaddr) {
#ifdef CONFIG_E2K
			set_memory_wb((unsigned long) mo->vaddr,
				      PAGE_ALIGN(gobj->size) >> PAGE_SHIFT);
#endif
			dma_free_coherent(drm->dev, gobj->size,
					mo->vaddr, mo->dma_addr);
		}
		break;
	default:
		WARN_ON(1);
	}
	dma_resv_fini(&mo->resv);
	drm_gem_object_release(gobj);
	kvfree(mo->pages);
	kfree(mo);
}

struct drm_gem_object *mga2_gem_create_with_handle(struct drm_file *file,
						   struct drm_device *drm,
						   size_t size, u32 domain,
						   u32 *handle)
{
	int ret;
	struct drm_gem_object *gobj = mga2_gem_create(drm, size, domain);

	if (IS_ERR(gobj))
		return gobj;

	/*
	 * allocate a id of idr table where the gobj is registered
	 * and handle has the id what user can see.
	 */
	ret = drm_gem_handle_create(file, gobj, handle);

	/* drop reference from allocate - handle holds it now. */
	drm_gem_object_put(gobj);
	if (ret)
		return ERR_PTR(ret);
	return gobj;
}

static int mga2_gem_object_mmap(struct drm_gem_object *gobj,
				   struct vm_area_struct *vma)
{
	int ret = 0;
	struct mga2_gem_object *mo = to_mga2_obj(gobj);
	struct mga2 *mga2 = (struct mga2 *)gobj->dev->dev_private;

	/*
	 * Clear the VM_PFNMAP flag that was set by drm_gem_mmap(), and set the
	 * vm_pgoff (used as a fake buffer offset by DRM) to 0 as we want to map
	 * the whole buffer.
	 */
	vma->vm_flags &= ~VM_PFNMAP;
	vma->vm_pgoff = 0;
 
	switch (mo->write_domain) {
	case MGA2_GEM_DOMAIN_VRAM: {
		struct drm_mm_node *node = &mo->node;
		unsigned long pfn = node->start >> PAGE_SHIFT;
		if (mga2_use_uncached(mga2)) {
			pfn = (long)mo->vaddr >> PAGE_SHIFT;
			WARN(!IS_ENABLED(CONFIG_E90S), "FIXME:pfn\n");
		}

		ret = io_remap_pfn_range(vma, vma->vm_start,
					pfn,
					vma->vm_end - vma->vm_start,
					ttm_io_prot(TTM_PL_FLAG_WC,
					vma->vm_page_prot));
		break;
	}
	case MGA2_GEM_DOMAIN_CPU: {
		ret = dma_mmap_coherent(gobj->dev->dev, vma,
				  mo->vaddr, mo->dma_addr, gobj->size);
		break;
	}
	default:
		BUG();
	}

	if (ret)
		drm_gem_vm_close(vma);

	return ret;
}

/*
 * mga2_gem_mmap - (struct file_operation)->mmap callback function
 */
int mga2_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct drm_file *priv = file->private_data;
	struct drm_device *dev = priv->minor->dev;
	struct drm_gem_object *gobj;
	int ret = 0;

	ret = drm_gem_mmap(file, vma);
	if (ret)
		return ret;

	/* HACK: check whether it is not gma object and drm_gem_mmap()
		has already handled it.
	 */
	drm_vma_offset_lock_lookup(dev->vma_offset_manager);
	if (!drm_vma_offset_lookup_locked(dev->vma_offset_manager,
					   vma->vm_pgoff,
					   vma_pages(vma))) {

		drm_vma_offset_unlock_lookup(dev->vma_offset_manager);
		return 0;
	}
	drm_vma_offset_unlock_lookup(dev->vma_offset_manager);

	gobj = vma->vm_private_data;
	return mga2_gem_object_mmap(gobj, vma);
}

int mga2_dumb_create(struct drm_file *file,
		     struct drm_device *drm, struct drm_mode_create_dumb *args)
{
	struct drm_gem_object *gobj;
	int min_pitch = DIV_ROUND_UP(args->width * args->bpp, 8);
	if (args->pitch < min_pitch)
		args->pitch = min_pitch;

	if (args->size < args->pitch * args->height)
		args->size = args->pitch * args->height;

	gobj = mga2_gem_create_with_handle(file, drm,
					   args->size, MGA2_GEM_DOMAIN_VRAM,
					   &args->handle);

	if (IS_ERR(gobj))
		return PTR_ERR(gobj);
	return 0;
}

int mga2_gem_create_ioctl(struct drm_device *drm, void *data,
			  struct drm_file *file)
{
	struct drm_mga2_gem_create *args = data;
	struct drm_gem_object *gobj =
		mga2_gem_create_with_handle(file, drm,
					args->size, args->domain,
					&args->handle);

	if (IS_ERR(gobj))
		return PTR_ERR(gobj);

	return 0;
}

int mga2_gem_mmap_ioctl(struct drm_device *drm, void *data,
			struct drm_file *file)
{
	struct drm_mga2_gem_mmap *args = data;
	return drm_gem_dumb_map_offset(file, drm, args->handle,
						&args->offset);
}


/* low-level interface prime helpers */

/**
 * mga2_prime_get_sg_table - provide a scatter/gather table of pinned
 *     pages for a MGA2 GEM object
 * @obj: GEM object
 *
 * This function exports a scatter/gather table suitable for PRIME usage by
 * calling the standard DMA mapping API.
 *
 * Returns:
 * A pointer to the scatter/gather table of pinned pages or NULL on failure.
 */
struct sg_table *mga2_prime_get_sg_table(struct drm_gem_object *obj)
{
	struct mga2_gem_object *mga2_gem = to_mga2_gem(obj);
	struct sg_table *sgt;
	int ret;

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return NULL;

	ret = dma_get_sgtable(obj->dev->dev, sgt, mga2_gem->vaddr,
			      mga2_gem->dma_addr, obj->size);
	if (ret < 0)
		goto out;

	return sgt;

out:
	kfree(sgt);
	return NULL;
}

/**
 * mga2_prime_import_sg_table - produce a MGA2 GEM object from another
 *     driver's scatter/gather table of pinned pages
 * @dev: device to import into
 * @attach: DMA-BUF attachment
 * @sgt: scatter/gather table of pinned pages
 *
 * This function imports a scatter/gather table exported via DMA-BUF by
 * another driver. Imported buffers must be physically contiguous info memory
 * (i.e. the scatter/gather table must contain a single entry).
 *
 * Returns:
 * A pointer to a newly created GEM object or an ERR_PTR-encoded negative
 * error code on failure.
 */
struct drm_gem_object *
mga2_prime_import_sg_table(struct drm_device *dev,
				     struct dma_buf_attachment *attach,
				     struct sg_table *sgt)
{
	struct mga2_gem_object *mo;
	pgprot_t prot = PAGE_KERNEL;
	int npages;
	int ret;

	mo = __mga2_gem_create(dev, attach->dmabuf->size);
	if (IS_ERR(mo)) {
		ret = PTR_ERR(mo);
		return ERR_PTR(ret);
	}

	npages = DIV_ROUND_UP(mo->base.size, PAGE_SIZE);
	mo->pages = kvmalloc_array(npages,
				sizeof(struct page *), GFP_KERNEL);
	if (!mo->pages) {
		ret = -ENOMEM;
		goto err;
	}

	ret = drm_prime_sg_to_page_addr_arrays(sgt, mo->pages, NULL,
					       npages);
	if (ret < 0)
		goto err_free_large;

#ifdef CONFIG_E2K
	/* Imagination GPU uses dma_buf to share DMA buffer with MGA2.
	 * Since Imagination uses PCIe No Snoop accesses, we make sure
	 * to allocate & export everything as WC.  And naturally we must
	 * vmap() the buffer as WC too (since all mappings on e2k must
	 * use the same coherency attributes). */
	prot = pgprot_writecombine(prot);
#endif
	mo->vaddr = vmap(mo->pages, npages, VM_MAP, prot);
	if (!mo->vaddr) {
		ret = -EFAULT;
		goto err_free_large;
	}
	mo->write_domain = MGA2_GEM_DOMAIN_CPU;
	mo->dma_addr = sg_dma_address(sgt->sgl);
	mo->sgt = sgt;

	return &mo->base;

err_free_large:
	kvfree(mo->pages);
err:
	drm_gem_object_release(&mo->base);
	kfree(mo);
	return ERR_PTR(ret);
}

/**
 * mga2_prime_mmap - memory-map an exported GEM object
 * @obj: GEM object
 * @vma: VMA for the area to be mapped
 *
 * This function maps a buffer imported via DRM PRIME into a userspace
 * process's address space.
 *
 * Returns:
 * 0 on success or a negative error code on failure.
 */
int mga2_prime_mmap(struct drm_gem_object *gobj,
			   struct vm_area_struct *vma)
{
	int ret;

	ret = drm_gem_mmap_obj(gobj, gobj->size, vma);
	if (ret < 0)
		return ret;

	return mga2_gem_object_mmap(gobj, vma);
}

/**
 * mga2_prime_vmap - map a GEM object into the kernel's virtual
 *     address space
 * @obj: GEM object
 *
 * This function maps a buffer exported via DRM PRIME into the kernel's
 * virtual address space. Since the MGA2 buffers are already mapped into the
 * kernel virtual address space this simply returns the cached virtual
 * address.
 *
 * Returns:
 * The kernel virtual address of the MGA2 GEM object's backing store.
 */
void *mga2_prime_vmap(struct drm_gem_object *gobj)
{
	struct mga2_gem_object *obj = to_mga2_obj(gobj);

	return obj->vaddr;
}

/**
 * mga2_prime_vunmap - unmap a MGA2 GEM object from the kernel's virtual
 *     address space
 * @obj: GEM object
 * @vaddr: kernel virtual address where the MGA2 GEM object was mapped
 *
 * This function removes a buffer exported via DRM PRIME from the kernel's
 * virtual address space. This is a no-op because MGA2 buffers cannot be
 * unmapped from kernel space.
 */
void mga2_prime_vunmap(struct drm_gem_object *gobj, void *vaddr)
{
	/* Nothing to do */
}

#ifdef CONFIG_DEBUG_FS
static int mga2_debugfs_framebuffers(struct seq_file *s, void *data)
{
	struct drm_info_node *node = (struct drm_info_node *)s->private;
	struct drm_device *drm = node->minor->dev;
	struct drm_framebuffer *fb;

	mutex_lock(&drm->mode_config.fb_lock);

	list_for_each_entry(fb, &drm->mode_config.fb_list, head) {
		seq_printf(s, "%3d: user size: %d x %d, depth %d, %d bpp, refcount %d\n",
			   fb->base.id, fb->width, fb->height,
			   fb->format->depth,
			   fb->format->cpp[0] * 8,
			   drm_framebuffer_read_refcount(fb));
	}

	mutex_unlock(&drm->mode_config.fb_lock);

	return 0;
}

static int mga2_debugfs_iova(struct seq_file *s, void *data)
{
	struct drm_info_node *node = (struct drm_info_node *)s->private;
	struct drm_device *drm = node->minor->dev;
	struct mga2 *mga2 = drm->dev_private;
	struct drm_printer p = drm_seq_file_printer(s);

	drm_mm_print(&mga2->vram_mm, &p);

	return 0;
}

static int mga2_debugfs_gem_bo_info(int id, void *ptr, void *data)
{
	struct drm_gem_object *gobj = ptr;
	struct mga2_gem_object *obj = to_mga2_obj(gobj);
	struct drm_mm_node *node = &obj->node;
	struct seq_file *m = data;

	const char *placement = "BUG";

	switch (obj->write_domain) {
	case MGA2_GEM_DOMAIN_VRAM:
		placement = "VRAM";
		break;
	case MGA2_GEM_DOMAIN_CPU:
		placement = " CPU";
		break;
	}
	seq_printf(m, "\t0x%08x: %12ld byte %s @ 0x%010llx\n",
		   id, gobj->size, placement, node->start);

	return 0;
}

static int mga2_debugfs_gem_info(struct seq_file *m, void *data)
{
	struct drm_info_node *node = (struct drm_info_node *)m->private;
	struct drm_device *dev = node->minor->dev;
	struct drm_file *file;
	struct mga2 *mga2 = dev->dev_private;
	int r;

	r = mutex_lock_interruptible(&mga2->vram_mu);
	if (r)
		return r;

	list_for_each_entry(file, &dev->filelist, lhead) {
		struct task_struct *task;

		/*
		 * Although we have a valid reference on file->pid, that does
		 * not guarantee that the task_struct who called get_pid() is
		 * still alive (e.g. get_pid(current) => fork() => exit()).
		 * Therefore, we need to protect this ->comm access using RCU.
		 */
		rcu_read_lock();
		task = pid_task(file->pid, PIDTYPE_PID);
		seq_printf(m, "pid %8d command %s:\n", pid_nr(file->pid),
			   task ? task->comm : "<unknown>");
		rcu_read_unlock();

		spin_lock(&file->table_lock);
		idr_for_each(&file->object_idr, mga2_debugfs_gem_bo_info, m);
		spin_unlock(&file->table_lock);
	}

	mutex_unlock(&mga2->vram_mu);
	return 0;
}

static struct drm_info_list mga2_debugfs_list[] = {
	{ "mga2_framebuffers", mga2_debugfs_framebuffers},
	{ "mga2_vram_mm"     , mga2_debugfs_iova},
	{ "mga2_gem_info"    , &mga2_debugfs_gem_info},
	{ "mga2-bctrl"       , &mga2_debugfs_bctrl},
};

void mga2_debugfs_init(struct drm_minor *minor)
{
	return drm_debugfs_create_files(mga2_debugfs_list,
					ARRAY_SIZE(mga2_debugfs_list),
					minor->debugfs_root, minor);
}
#endif
