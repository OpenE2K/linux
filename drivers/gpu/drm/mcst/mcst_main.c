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
#include "drmP.h"
#include "mcst_drv.h"

#include "drm_fb_helper.h"
#include "drm_crtc_helper.h"

#include "mcst_util.h"

static int mcst_detect_chip(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;
	unsigned int stamp;
	int hw_rev = dev->pdev->revision;
CH();

	switch (dev->pdev->device) {
	case PCI_CHIP_MCST_MGA3D:
		mcst->chip = MCST_MGA3D;
		DRM_INFO("MGA3D card detected\n");
		break;
	case PCI_CHIP_MCST_MGA:
		if ((hw_rev != MGA_MODEL_PMUP2_0)
		    && (hw_rev != MGA_MODEL_PMUP2_1)) {
			mcst->chip = MCST_MGA;
			DRM_INFO("MGA card detected\n");
		} else {
			mcst->chip = MCST_UNSUPPORTED_MGA;
			DRM_ERROR("MGA model PMUP2 not supported!\n");
		}
		break;
	default:
		DRM_ERROR("Unknow card!\n");
	}

	/* Reading firmware version (for cell #0 only) */
	stamp = mcst_io_read32(mcst, 0, REG_STAMP);
	mcst->firmware_version = stamp >> 24;
	DRM_INFO("Firmware: version %d (20%02d-%02d-%02d), hw rev %d\n",
			mcst->firmware_version,
			(stamp & 0xff0000) >> 16,
			(stamp & 0x00ff00) >> 8,
			(stamp & 0x0000ff),
			hw_rev);

	if (mcst->firmware_version == 0) {
		/* Very old firmware, possible BitBLT module hangs */
		DRM_ERROR("Firmware version 0 does not support acceleration");
	}

	/* Init BitBLT module */
	mcst_io_write32(mcst, REG_CTRL, 0, BB_CTRL_CMD_ABORT);

	if ((mcst_io_read32(mcst, 0, REG_BB_STAT) & BB_STAT_DMA) == 0) {
		/* DMA disabled in firmware (bug on 66MHz PCI bus) */
		DRM_ERROR("DMA disabled (this hardware doesn't support it)");
	}
	return 0;
}

static int mcst_get_dram_info(struct drm_device *dev)
{
CH();
#if 0
	ast->dram_bus_width = 32;
	ast->dram_type = AST_DRAM_512Mx16;
	ast->mclk = ref_pll * (num + 2) / (denum + 2) * (div * 1000);
#endif
	return 0;
}

uint32_t mcst_get_max_dclk(struct drm_device *dev, int bpp)
{
CH();
#if 0
	struct mcst_private *mcst = dev->dev_private;
	uint32_t dclk, jreg;
	uint32_t dram_bus_width, mclk, dram_bandwidth, actual_dram_bandwidth,
		 dram_efficency = 500;

	dram_bus_width = ast->dram_bus_width;
	mclk = ast->mclk;

	dram_bandwidth = mclk * dram_bus_width * 2 / 8;
	actual_dram_bandwidth = dram_bandwidth * dram_efficency / 1000;

	 {
		jreg = ast_get_index_reg_mask(ast, AST_IO_CRTC_PORT,
					      0xd0, 0xff);
		if ((jreg & 0x08))
			dclk = actual_dram_bandwidth / ((bpp + 1 + 16) / 8);
		else if ((jreg & 0x08) && (bpp == 8))
			dclk = actual_dram_bandwidth / ((bpp + 1 + 24) / 8);
		else
			dclk = actual_dram_bandwidth / ((bpp + 1) / 8);
	}

	if (dclk > 165)
		dclk = 165;
	return dclk;
#endif
	return 165;
}

static void mcst_user_framebuffer_destroy(struct drm_framebuffer *fb)
{
	struct mcst_framebuffer *mcst_fb = to_mcst_framebuffer(fb);
CH();
	if (mcst_fb->obj)
		drm_gem_object_unreference_unlocked(mcst_fb->obj);

	drm_framebuffer_cleanup(fb);
	kfree(fb);
}

static int mcst_user_framebuffer_create_handle(struct drm_framebuffer *fb,
					      struct drm_file *file,
					      unsigned int *handle)
{
CH();
	return -EINVAL;
}

static const struct drm_framebuffer_funcs mcst_fb_funcs = {
	.destroy = mcst_user_framebuffer_destroy,
	.create_handle = mcst_user_framebuffer_create_handle,
};


int mcst_framebuffer_init(struct drm_device *dev,
			 struct mcst_framebuffer *mcst_fb,
			 struct drm_mode_fb_cmd2 *mode_cmd,
			 struct drm_gem_object *obj)
{
	int ret;
CH();

	ret = drm_framebuffer_init(dev, &mcst_fb->base, &mcst_fb_funcs);
	if (ret) {
		DRM_ERROR("framebuffer init failed %d\n", ret);
		return ret;
	}
	drm_helper_mode_fill_fb_struct(&mcst_fb->base, mode_cmd);
	mcst_fb->obj = obj;
	return 0;
}

static struct drm_framebuffer *
mcst_user_framebuffer_create(struct drm_device *dev,
	       struct drm_file *filp,
	       struct drm_mode_fb_cmd2 *mode_cmd)
{
	struct drm_gem_object *obj;
	struct mcst_framebuffer *mcst_fb;
	int ret;
CH();

	obj = drm_gem_object_lookup(dev, filp, mode_cmd->handles[0]);
	if (obj == NULL)
		return ERR_PTR(-ENOENT);

	mcst_fb = kzalloc(sizeof(*mcst_fb), GFP_KERNEL);
	if (!mcst_fb) {
		drm_gem_object_unreference_unlocked(obj);
		return ERR_PTR(-ENOMEM);
	}

	ret = mcst_framebuffer_init(dev, mcst_fb, mode_cmd, obj);
	if (ret) {
		drm_gem_object_unreference_unlocked(obj);
		kfree(mcst_fb);
		return ERR_PTR(ret);
	}
	return &mcst_fb->base;
}

static const struct drm_mode_config_funcs mcst_mode_funcs = {
	.fb_create = mcst_user_framebuffer_create,
};

static u32 mcst_get_vram_info(struct drm_device *dev)
{
CH();
	/* TODO: Size of vram in MGA card while equal size of FBMEM PCI BAR */
	return pci_resource_len(dev->pdev, PCI_MGA_FBMEM_BAR);
}

int mcst_driver_load(struct drm_device *dev, unsigned long flags)
{
	struct mcst_private *mcst;
	int ret = 0;
CH();

	mcst = kzalloc(sizeof(struct mcst_private), GFP_KERNEL);
	if (!mcst)
		return -ENOMEM;

	dev->dev_private = mcst;
	mcst->dev = dev;

	mcst->ioregs[0] = pci_iomap(dev->pdev, PCI_MGA_MMIO_BAR, 0);
	if (!mcst->ioregs[0]) {
		ret = -EIO;
		goto out_free;
	}
	mcst->ioregs[1] = mcst->ioregs[0] + 0x2000; /* TODO: fix style */

	mcst->i2cregs = pci_iomap(dev->pdev, PCI_MGA_I2C_BAR, 0);
	if (!mcst->i2cregs) {
		pci_iounmap(dev->pdev, mcst->ioregs);
		ret = -EIO;
		goto out_free;
	}

	mcst_detect_chip(dev);
	mcst_pll_init_pixclock(mcst->i2cregs);
	{
		mcst_get_dram_info(dev);
		mcst->vram_size = mcst_get_vram_info(dev);
		DRM_INFO("DRAM size: %d Mbytes\n", mcst->vram_size/(1024*1024));
	}

	ret = mcst_mm_init(mcst);
	if (ret)
		goto out_free;
CH();
	drm_mode_config_init(dev);

	dev->mode_config.funcs = (void *)&mcst_mode_funcs;
	dev->mode_config.min_width = 0;
	dev->mode_config.min_height = 0;
	dev->mode_config.preferred_depth = 24;
	dev->mode_config.prefer_shadow = 1;

	dev->mode_config.max_width = 1920;
	dev->mode_config.max_height = 1200;

	ret = mcst_irq_init(dev);
	if (ret)
		goto out_free;

	ret = mcst_mode_init(dev);
	if (ret)
		goto out_free;

	ret = mcst_fbdev_init(dev);
	if (ret)
		goto out_free;

	if (dev->mode_config.num_crtc) {
		ret = drm_vblank_init(dev, dev->mode_config.num_crtc);
		if (ret)
			goto vblank_err;
	}

	{ /* FIXME: debug!!! */
		int i;
		int cell_num = (mcst->chip == MCST_MGA3D) ? 2 : 1;

		for (i = 0; i < cell_num; i++) {
			mcst_hexdump_regs(mcst, i);
		}
	}

	return 0;

vblank_err:
/*	  disp->destroy(dev); */


/* fail */
out_free:
	kfree(mcst);
	dev->dev_private = NULL;
	return ret;
}

int mcst_driver_unload(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;
CH();

	mcst_mode_fini(dev);
	mcst_fbdev_fini(dev);

	drm_mode_config_cleanup(dev);

	mcst_mm_fini(mcst);
	mcst_irq_fini(dev);

	pci_iounmap(dev->pdev, mcst->i2cregs);
	pci_iounmap(dev->pdev, mcst->ioregs);
	kfree(mcst);
	return 0;
}

int mcst_gem_create(struct drm_device *dev,
		   u32 size, bool iskernel,
		   struct drm_gem_object **obj)
{
	struct mcst_bo *mcstbo;
	int ret;
CH();

	*obj = NULL;

	size = roundup(size, PAGE_SIZE);
	if (size == 0)
		return -EINVAL;

	ret = mcst_bo_create(dev, size, 0, 0, &mcstbo);
	if (ret) {
		if (ret != -ERESTARTSYS)
			DRM_ERROR("failed to allocate GEM object\n");
		return ret;
	}
	*obj = &mcstbo->gem;
	return 0;
}

int mcst_dumb_create(struct drm_file *file,
		    struct drm_device *dev,
		    struct drm_mode_create_dumb *args)
{
	int ret;
	struct drm_gem_object *gobj;
	u32 handle;
CH();

	args->pitch = args->width * ((args->bpp + 7) / 8);
	args->size = args->pitch * args->height;

	ret = mcst_gem_create(dev, args->size, false,
			     &gobj);
	if (ret)
		return ret;

	ret = drm_gem_handle_create(file, gobj, &handle);
	drm_gem_object_unreference_unlocked(gobj);
	if (ret)
		return ret;

	args->handle = handle;
	return 0;
}

int mcst_dumb_destroy(struct drm_file *file,
		     struct drm_device *dev,
		     uint32_t handle)
{
CH();
	return drm_gem_handle_delete(file, handle);
}

int mcst_gem_init_object(struct drm_gem_object *obj)
{
CH();
	BUG();
	return 0;
}

void mcst_bo_unref(struct mcst_bo **bo)
{
	struct ttm_buffer_object *tbo;
CH();

	if ((*bo) == NULL)
		return;

	tbo = &((*bo)->bo);
	ttm_bo_unref(&tbo);
	if (tbo == NULL)
		*bo = NULL;

}
void mcst_gem_free_object(struct drm_gem_object *obj)
{
	struct mcst_bo *mcst_bo = gem_to_mcst_bo(obj);
CH();

	if (!mcst_bo)
		return;
	mcst_bo_unref(&mcst_bo);
}


static inline u64 mcst_bo_mmap_offset(struct mcst_bo *bo)
{
	return bo->bo.addr_space_offset;
}
int
mcst_dumb_mmap_offset(struct drm_file *file,
		     struct drm_device *dev,
		     uint32_t handle,
		     uint64_t *offset)
{
	struct drm_gem_object *obj;
	int ret;
	struct mcst_bo *bo;
CH();

	mutex_lock(&dev->struct_mutex);
	obj = drm_gem_object_lookup(dev, file, handle);
	if (obj == NULL) {
		ret = -ENOENT;
		goto out_unlock;
	}
CH();
	bo = gem_to_mcst_bo(obj);
	*offset = mcst_bo_mmap_offset(bo);

	drm_gem_object_unreference(obj);
	ret = 0;
out_unlock:
	mutex_unlock(&dev->struct_mutex);
	return ret;

}

