/*
 * Copyright б╘ 2007 David Airlie
 * Copyright б╘ 2009 VMware, Inc., Palo Alto, CA., USA
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
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/sysrq.h>
#include <linux/delay.h>
#include <linux/fb.h>
#include <linux/init.h>


#include "drmP.h"
//#include "drm.h"
#include "drm_crtc.h"
#include "drm_fb_helper.h"
#include "mcst_drv.h"

/* FPS of screen update */
#ifdef __e2k__
#define MCST_DIRTY_DELAY (HZ / 5)
#else
#define MCST_DIRTY_DELAY (HZ / 25)
#endif

static void mcst_dirty_update(struct mcst_fbdev *mfbdev,
			      int x, int y, int width, int height)
{
	int i;
	struct drm_gem_object *obj;
	struct mcst_bo *bo;
	int src_offset, dst_offset;
	int bpp = (mfbdev->mfb.base.bits_per_pixel + 7)/8;
	int ret;
	bool unmap = false;

/* CH(); troosh: so many flood */
	obj = mfbdev->mfb.obj;
	bo = gem_to_mcst_bo(obj);

	ret = mcst_bo_reserve(bo, true);
	if (ret) {
		DRM_ERROR("failed to reserve fb bo\n");
		return;
	}

	if (!bo->kmap.virtual) {
		ret = ttm_bo_kmap(&bo->bo, 0, bo->bo.num_pages, &bo->kmap);
		if (ret) {
			DRM_ERROR("failed to kmap fb updates\n");
			mcst_bo_unreserve(bo);
			return;
		}
		unmap = true;
	}
#if 1
	for (i = y; i < y + height; i++) {
		/* assume equal stride for now */
		src_offset = i * mfbdev->mfb.base.pitches[0] + (x * bpp);
		dst_offset = src_offset;
		memcpy_toio(bo->kmap.virtual + src_offset,
			    mfbdev->sysram   + src_offset, width * bpp);

	}
#else
	/* troosh FIXME: DEBUG! */
	memcpy_toio(bo->kmap.virtual, mfbdev->sysram, mfbdev->size);
#endif

	if (unmap)
		ttm_bo_kunmap(&bo->kmap);

	mcst_bo_unreserve(bo);
}

/*
 * Dirty code
 */

static void mcst_fb_dirty_flush(struct mcst_fbdev *mfbdev)
{
	struct fb_info *info = mfbdev->helper.fbdev;
	unsigned long flags;
	unsigned x, y, w, h;

	spin_lock_irqsave(&mfbdev->dirty.lock, flags);
	if (!mfbdev->dirty.active) {
		spin_unlock_irqrestore(&mfbdev->dirty.lock, flags);
		return;
	}
	x = mfbdev->dirty.x1;
	y = mfbdev->dirty.y1;
	w = min(mfbdev->dirty.x2, info->var.xres) - x;
	h = min(mfbdev->dirty.y2, info->var.yres) - y;
	mfbdev->dirty.x1 = 0;
	mfbdev->dirty.x2 = 0;
	mfbdev->dirty.y1 = 0;
	mfbdev->dirty.y2 = 0;
	spin_unlock_irqrestore(&mfbdev->dirty.lock, flags);

#if 0
	DRM_INFO("%s, (%u, %u) (%ux%u)\n", __func__, x, y, w, h);
#endif
	mcst_dirty_update(mfbdev, x, y, w, h);
}


static void mcst_fb_dirty_mark(struct mcst_fbdev *mfbdev,
		unsigned x1, unsigned y1,
		unsigned width, unsigned height)
{
	struct fb_info *info = mfbdev->helper.fbdev;
	unsigned long flags;
	unsigned x2 = x1 + width;
	unsigned y2 = y1 + height;

	spin_lock_irqsave(&mfbdev->dirty.lock, flags);
	if (mfbdev->dirty.x1 == mfbdev->dirty.x2) {
		mfbdev->dirty.x1 = x1;
		mfbdev->dirty.y1 = y1;
		mfbdev->dirty.x2 = x2;
		mfbdev->dirty.y2 = y2;
		/* if we are active start the dirty work
		 * we share the work with the defio system */
		if (mfbdev->dirty.active)
			schedule_delayed_work(&info->deferred_work,
					      MCST_DIRTY_DELAY);
	} else {
		if (x1 < mfbdev->dirty.x1)
			mfbdev->dirty.x1 = x1;
		if (y1 < mfbdev->dirty.y1)
			mfbdev->dirty.y1 = y1;
		if (x2 > mfbdev->dirty.x2)
			mfbdev->dirty.x2 = x2;
		if (y2 > mfbdev->dirty.y2)
			mfbdev->dirty.y2 = y2;
	}
	spin_unlock_irqrestore(&mfbdev->dirty.lock, flags);
}

static void mcst_deferred_io(struct fb_info *info,
			     struct list_head *pagelist)
{
	struct mcst_fbdev *mfbdev = info->par;
	unsigned long start, end, min, max;
	unsigned long flags;
	struct page *page;
	int y1, y2;

	min = ULONG_MAX;
	max = 0;
	list_for_each_entry(page, pagelist, lru) {
		start = page->index << PAGE_SHIFT;
		end = start + PAGE_SIZE - 1;
		min = min(min, start);
		max = max(max, end);
	}

	if (min < max) {
		y1 = min / info->fix.line_length;
		y2 = (max / info->fix.line_length) + 1;

		spin_lock_irqsave(&mfbdev->dirty.lock, flags);
		mfbdev->dirty.x1 = 0;
		mfbdev->dirty.y1 = y1;
		mfbdev->dirty.x2 = info->var.xres;
		mfbdev->dirty.y2 = y2;
		spin_unlock_irqrestore(&mfbdev->dirty.lock, flags);
	}

	mcst_fb_dirty_flush(mfbdev);
};

struct fb_deferred_io mcst_defio = {
	.delay		= MCST_DIRTY_DELAY,
	.deferred_io	= mcst_deferred_io,
};

static void mcst_fillrect(struct fb_info *info,
			  const struct fb_fillrect *rect)
{
	struct mcst_fbdev *mfbdev = info->par;
/* CH(); troosh: so many flood */
	sys_fillrect(info, rect);
	mcst_fb_dirty_mark(mfbdev, rect->dx, rect->dy, rect->width,
			   rect->height);
}

static void mcst_copyarea(struct fb_info *info,
			  const struct fb_copyarea *area)
{
	struct mcst_fbdev *mfbdev = info->par;
CH();
	sys_copyarea(info, area);
	mcst_fb_dirty_mark(mfbdev, area->dx, area->dy, area->width,
			   area->height);
}

static void mcst_imageblit(struct fb_info *info,
			   const struct fb_image *image)
{
	struct mcst_fbdev *mfbdev = info->par;

/* CH(); troosh: so many flood */
	sys_imageblit(info, image);
	mcst_fb_dirty_mark(mfbdev, image->dx, image->dy, image->width,
			   image->height);
}

static struct fb_ops mcstfb_ops = {
	.owner = THIS_MODULE,
	.fb_check_var = drm_fb_helper_check_var,
	.fb_set_par = drm_fb_helper_set_par,
	.fb_fillrect = mcst_fillrect,
	.fb_copyarea = mcst_copyarea,
	.fb_imageblit = mcst_imageblit,
	.fb_pan_display = drm_fb_helper_pan_display,
	.fb_blank = drm_fb_helper_blank,
	.fb_setcmap = drm_fb_helper_setcmap,
#if 0
	.fb_debug_enter = drm_fb_helper_debug_enter,
	.fb_debug_leave = drm_fb_helper_debug_leave,
#endif
};

static int mcstfb_create_object(struct mcst_fbdev *mfbdev,
			       struct drm_mode_fb_cmd2 *mode_cmd,
			       struct drm_gem_object **gobj_p)
{
	struct drm_device *dev = mfbdev->helper.dev;
	u32 bpp, depth;
	u32 size;
	struct drm_gem_object *gobj;

	int ret = 0;
CH();
	drm_fb_get_bpp_depth(mode_cmd->pixel_format, &depth, &bpp);

	size = mode_cmd->pitches[0] * mode_cmd->height;
	ret = mcst_gem_create(dev, size, true, &gobj);
	if (ret)
		return ret;

CH();
	*gobj_p = gobj;
	return ret;
}

static int mcst_fb_create(struct mcst_fbdev *mfbdev,
			struct drm_fb_helper_surface_size *sizes)
{
	struct drm_device *dev = mfbdev->helper.dev;
	struct drm_mode_fb_cmd2 mode_cmd;
	struct drm_framebuffer *fb;
	struct fb_info *info;
	int size, ret;
	struct device *device = &dev->pdev->dev;
	void *sysram;
	struct drm_gem_object *gobj = NULL;
	struct mcst_bo *bo = NULL;
CH();
	mode_cmd.width = sizes->surface_width;
	mode_cmd.height = sizes->surface_height;
	mode_cmd.pitches[0] = mode_cmd.width * ((sizes->surface_bpp + 7)/8);

	mode_cmd.pixel_format = drm_mode_legacy_fb_format(sizes->surface_bpp,
							  sizes->surface_depth);

	size = mode_cmd.pitches[0] * mode_cmd.height;

	ret = mcstfb_create_object(mfbdev, &mode_cmd, &gobj);
	if (ret) {
		DRM_ERROR("failed to create fbcon backing object %d\n", ret);
		return ret;
	}
	bo = gem_to_mcst_bo(gobj);

	sysram = vmalloc(size);
	if (!sysram) {
		return -ENOMEM;
	}

	info = framebuffer_alloc(0, device);
	if (!info) {
		return -ENOMEM;
	}
	info->par = mfbdev;

	ret = mcst_framebuffer_init(dev, &mfbdev->mfb, &mode_cmd, gobj);
	if (ret) {
		goto out;
	}

	mfbdev->sysram = sysram;
	mfbdev->size = size;

	fb = &mfbdev->mfb.base;
	mfbdev->helper.fb = fb;
	mfbdev->helper.fbdev = info;

	strcpy(info->fix.id, "mcstdrmfb");

	info->flags = FBINFO_DEFAULT /*| FBINFO_CAN_FORCE_OUTPUT*/;
	info->fbops = &mcstfb_ops;

	ret = fb_alloc_cmap(&info->cmap, 256, 0);
	if (ret) {
		ret = -ENOMEM;
		goto out;
	}
	info->apertures = alloc_apertures(1);
	if (!info->apertures) {
		ret = -ENOMEM;
		goto out_unref;
	}

	info->apertures->ranges[0].base = pci_resource_start(dev->pdev, PCI_MGA_FBMEM_BAR);
	info->apertures->ranges[0].size = pci_resource_len(dev->pdev, PCI_MGA_FBMEM_BAR);

	drm_fb_helper_fill_fix(info, fb->pitches[0], fb->depth);
	drm_fb_helper_fill_var(info, &mfbdev->helper, sizes->fb_width,
			       sizes->fb_height);

	info->screen_base = sysram;
	info->screen_size = size;
	/* FIXME: Why other DRM driver don't init smem_start/smen_len,
	 * may be new framebuffer code from kernel 3.5 do copy from
	 * info->screen_base/info->screen_size?
	 * Possible need backport framebuffer code, too?
	 */
#if 1
	info->fix.smem_start = (unsigned long) sysram;
	info->fix.smem_len   = size;
#else
	info->fix.smem_start = info->aperture_base;
	info->fix.smem_len   = size;
#endif

	info->pixmap.flags = FB_PIXMAP_SYSTEM;

	/* TODO: This is real good idea grand access to contol registers of
	 * MGA card? (other driver don't init mmio_start/mmio_len)
	 */
	info->fix.mmio_start = pci_resource_start(dev->pdev, PCI_MGA_MMIO_BAR);
	info->fix.mmio_len = pci_resource_len(dev->pdev, PCI_MGA_MMIO_BAR);

	/**
	 * Dirty & Deferred IO
	 */
	mfbdev->dirty.x1 = 0;
	mfbdev->dirty.x2 = 0;
	mfbdev->dirty.y1 = 0;
	mfbdev->dirty.y2 = 0;
	mfbdev->dirty.active = true;
	spin_lock_init(&mfbdev->dirty.lock);
	info->fbdefio = &mcst_defio;
	fb_deferred_io_init(info);

	DRM_DEBUG_KMS("allocated %dx%d\n", fb->width, fb->height);
	DRM_INFO("fb mappable at 0x%lX\n", info->fix.smem_start);
	DRM_INFO("vram aper at 0x%lX\n", (unsigned long)info->fix.smem_start);
	DRM_INFO("size %lu\n", (unsigned long)info->fix.smem_len);
	DRM_INFO("fb depth is %d\n", fb->depth);
	DRM_INFO("   pitch is %d\n", fb->pitches[0]);
	DRM_INFO("[FB:%d] init done\n", fb->base.id);
	return 0;
out_unref:
out:
	return ret;
}

static void mcst_fb_gamma_set(struct drm_crtc *crtc, u16 red, u16 green,
			       u16 blue, int regno)
{
	struct mcst_crtc *mcst_crtc = to_mcst_crtc(crtc);
/* CH(); */
	mcst_crtc->lut_r[regno] = red >> 8;
	mcst_crtc->lut_g[regno] = green >> 8;
	mcst_crtc->lut_b[regno] = blue >> 8;
}

static void mcst_fb_gamma_get(struct drm_crtc *crtc, u16 *red, u16 *green,
			       u16 *blue, int regno)
{
	struct mcst_crtc *mcst_crtc = to_mcst_crtc(crtc);
CH();
	*red = mcst_crtc->lut_r[regno] << 8;
	*green = mcst_crtc->lut_g[regno] << 8;
	*blue = mcst_crtc->lut_b[regno] << 8;
}

static int
mcst_find_or_create_single(struct drm_fb_helper *helper,
			   struct drm_fb_helper_surface_size *sizes)
{
	struct mcst_fbdev *mfbdev = (struct mcst_fbdev *)helper;
	int new_fb = 0;
	int ret;
CH();

	if (!helper->fb) {
		ret = mcst_fb_create(mfbdev, sizes);
		if (ret)
			return ret;
		new_fb = 1;
	}
	return new_fb;
}

static struct drm_fb_helper_funcs mcst_fb_helper_funcs = {
	.gamma_set = mcst_fb_gamma_set,
	.gamma_get = mcst_fb_gamma_get,
	.fb_probe = mcst_find_or_create_single,
};

static void mcst_fbdev_destroy(struct drm_device *dev,
			      struct mcst_fbdev *mfbdev)
{
	struct fb_info *info;
	struct mcst_framebuffer *mfb = &mfbdev->mfb;
CH();
	if (mfbdev->helper.fbdev) {
		info = mfbdev->helper.fbdev;
		unregister_framebuffer(info);
		if (info->cmap.len)
			fb_dealloc_cmap(&info->cmap);
		framebuffer_release(info);
	}

	if (mfb->obj) {
		drm_gem_object_unreference_unlocked(mfb->obj);
		mfb->obj = NULL;
	}
	drm_fb_helper_fini(&mfbdev->helper);

	vfree(mfbdev->sysram);
	drm_framebuffer_cleanup(&mfb->base);
}

int mcst_fbdev_init(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;
	struct mcst_fbdev *mfbdev;
	int crtc_count, max_conn_count;
	int bpp_sel = 32;  /*16*/ /*8*/
	int ret;
CH();

	mfbdev = kzalloc(sizeof(struct mcst_fbdev), GFP_KERNEL);
	if (!mfbdev)
		return -ENOMEM;

	mcst->fbdev = mfbdev;
	mfbdev->helper.funcs = &mcst_fb_helper_funcs;

	switch (mcst->chip) {
	case MCST_MGA:
		crtc_count = 1;
		max_conn_count = 1;
		break;
	case MCST_MGA3D:
		crtc_count = 2;
		max_conn_count = 2;
		break;
	default:
		DRM_ERROR("???");
		return -EINVAL;
	}
	ret = drm_fb_helper_init(dev, &mfbdev->helper,
			crtc_count, max_conn_count);
CH();
	if (ret) {
		kfree(mfbdev);
		return ret;
	}

CH();
	drm_fb_helper_single_add_all_connectors(&mfbdev->helper);
CH();
	drm_fb_helper_initial_config(&mfbdev->helper, bpp_sel);
	return 0;
}

void mcst_fbdev_fini(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;
CH();

	if (!mcst->fbdev)
		return;

	mcst_fbdev_destroy(dev, mcst->fbdev);
	kfree(mcst->fbdev);
	mcst->fbdev = NULL;
}

void mcst_fbdev_set_suspend(struct drm_device *dev, int state)
{
	struct mcst_private *mcst = dev->dev_private;
CH();

	if (!mcst->fbdev)
		return;

	fb_set_suspend(mcst->fbdev->helper.fbdev, state);
}

