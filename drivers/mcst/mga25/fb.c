/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*#define DEBUG*/
#include "drv.h"

MODULE_PARM_DESC(nofbaccel, "Disable fbcon acceleration");
static int mga25_nofbaccel = 0;
module_param_named(nofbaccel, mga25_nofbaccel, int, 0400);
MODULE_PARM_DESC(nohwcursor, "Disable hardware cursor");
static int mga25_nohwcursor = 0;
module_param_named(nohwcursor, mga25_nohwcursor, int, 0400);

#define	__rfb(__addr) readl(mga2->regs + __addr)
#define	__wfb(__v, __addr) writel(__v, mga2->regs + __addr)

#ifdef DEBUG
#define rfb(__offset)				\
({								\
	unsigned __val = __rfb(__offset);			\
	/*DRM_DEBUG_KMS("R: %x: %s\n", __val, # __offset);*/	\
	__val;							\
})

#define wfb(__val, __offset)					\
({								\
	unsigned __val2 = __val;				\
	DRM_DEBUG_KMS("W: %x: %s\n", __val2, # __offset);	\
	/*printk(KERN_DEBUG"%x %x\n",  MGA2_DC0_ ## __offset, __val2);*/	\
	__wfb(__val2, __offset);				\
})

#else
#define		rfb		__rfb
#define		wfb		__wfb
#endif

static int get_free_desc(struct mga2 *mga2);
static int append_desc(struct mga2 *mga2, struct mga25_gem_object *mo);
static struct mga25_gem_object *mga25_auc_ioctl(struct drm_device *dev,
					void *data, struct drm_file *filp);
static void __mga25_update_ptr(struct mga2 *mga2);

#include "bctrl.c"
#include "auc2.c"
#include "fbdev.c"

static int mga2fb_create_object(struct mga25_fbdev *fbdev,
				struct drm_mode_fb_cmd2 *mode_cmd,
				struct drm_gem_object **gobj_p)
{
	struct drm_device *drm = fbdev->helper.dev;
	u32 size;
	struct drm_gem_object *gobj;

	size = mode_cmd->pitches[0] * mode_cmd->height;
	gobj = mga25_gem_create(drm, size, MGA2_GEM_DOMAIN_VRAM);

	if (IS_ERR(gobj))
		return PTR_ERR(gobj);

	*gobj_p = gobj;
	return 0;
}

static int mga2fb_create(struct mga25_fbdev *fbdev,
			 struct drm_fb_helper_surface_size *sizes)
{
	struct drm_device *drm = fbdev->helper.dev;
	struct mga2 *mga2 = drm->dev_private;
	struct drm_mode_fb_cmd2 mode_cmd;
	struct drm_framebuffer *dfb;
	struct fb_info *info;
	int size, ret;
	struct mga25_framebuffer *mga25_fb;
	struct drm_gem_object *gobj = NULL;
	mode_cmd.width = sizes->surface_width;
	mode_cmd.height = sizes->surface_height;
	mode_cmd.pitches[0] = mode_cmd.width * ((sizes->surface_bpp + 7) / 8);

	mode_cmd.pixel_format = drm_driver_legacy_fb_format(drm,
					sizes->surface_bpp,
					sizes->surface_depth);

	size = mode_cmd.pitches[0] * mode_cmd.height;

	info = drm_fb_helper_alloc_fbi(&fbdev->helper);
	if (IS_ERR(info)) {
		dev_err(drm->dev, "failed to allocate framebuffer info\n");
		return PTR_ERR(info);
	}

	ret = mga2fb_create_object(fbdev, &mode_cmd, &gobj);
	if (ret) {
		DRM_ERROR("failed to create fbcon backing object %d\n", ret);
		return ret;
	}

	mga25_fb = kzalloc(sizeof(*mga25_fb), GFP_KERNEL);
	if (!mga25_fb) {
		return -ENOMEM;
	}
	ret = mga25_framebuffer_init(drm, mga25_fb, &mode_cmd, gobj);
	if (ret)
		goto out;

	dfb = &mga25_fb->base;
	fbdev->helper.fb = dfb;

	info->flags = FBINFO_DEFAULT;
		/*TODO:
			FBINFO_READS_FAST |
			FBINFO_HWACCEL_XPAN |
			FBINFO_HWACCEL_YPAN;
		*/

	switch (mga25_nofbaccel) {
	case 1:
		info->flags |= FBINFO_HWACCEL_DISABLED;
		break;
	case 2:
		mga2->flags |= MGA2_BCTRL_OFF;
		info->flags |= FBINFO_HWACCEL_COPYAREA |
			FBINFO_HWACCEL_FILLRECT | FBINFO_HWACCEL_IMAGEBLIT;
		break;
	case 3:
		mga2->flags |= MGA2_BCTRL_OFF;
		info->flags |= FBINFO_HWACCEL_COPYAREA;
		break;
	case 4:
		mga2->flags |= MGA2_BCTRL_OFF;
		info->flags |= FBINFO_HWACCEL_FILLRECT;
		break;
	case 5:
		mga2->flags |= MGA2_BCTRL_OFF;
		info->flags |= FBINFO_HWACCEL_IMAGEBLIT;
		break;
	default:
		info->flags |= FBINFO_HWACCEL_COPYAREA |
			FBINFO_HWACCEL_FILLRECT | FBINFO_HWACCEL_IMAGEBLIT;
	}

	if (mga25_nohwcursor)
		mga2fb_ops.fb_cursor = NULL;

	info->fbops = &mga2fb_ops;

	drm_fb_helper_fill_info(info, &fbdev->helper, sizes);
/*TODO:*/
	info->apertures->ranges[0].base = pci_resource_start(drm->pdev, 0);
	info->apertures->ranges[0].size = pci_resource_len(drm->pdev, 0);

	info->screen_base = to_mga25_obj(mga25_fb->gobj)->vaddr;
	info->screen_size = size;

	info->fix.smem_len = size;
	info->pixmap.flags = FB_PIXMAP_SYSTEM;

	DRM_DEBUG_KMS("allocated %dx%d\n", dfb->width, dfb->height);
	DRM_INFO("fb is %dx%d-%d\n", sizes->fb_width,
		 sizes->fb_height, dfb->format->depth);
	DRM_INFO("   pitch is %d\n", dfb->pitches[0]);

	return 0;
      out:
	return ret;
}

static int mga25_find_or_create_single(struct drm_fb_helper *helper,
				      struct drm_fb_helper_surface_size *sizes)
{
	struct mga25_fbdev *fb = to_mga25_fbdev(helper);
	int new_fb = 0;
	int ret;

	if (!helper->fb) {
		ret = mga2fb_create(fb, sizes);
		if (ret)
			return ret;
		new_fb = 1;
	}
	return new_fb;
}

static struct drm_fb_helper_funcs mga25_fb_helper_funcs = {
	.fb_probe = mga25_find_or_create_single,
};

static void mga25_fbdev_destroy(struct drm_device *drm, struct mga25_fbdev *fb)
{
	if (!fb)
		return;

	drm_fb_helper_unregister_fbi(&fb->helper);
	if (fb->helper.fbdev && fb->pixmap_dma) {
		struct mga2 *mga2 = drm->dev_private;
		struct fb_info *info = fb->helper.fbdev;
		dma_unmap_single(mga2->drm->dev, fb->pixmap_dma,
				 info->pixmap.size, DMA_TO_DEVICE);
	}
	/* release drm framebuffer and real buffer */
	if (fb->helper.fb)
		drm_framebuffer_remove(fb->helper.fb);

	drm_fb_helper_fini(&fb->helper);
}

int mga2fb_bctrl_hw_init(struct mga2 *mga2)
{
	int ret = 0;
	if (mga25(mga2->dev_id))
		ret = mga2fb_auc2_hw_init(mga2);
	if (ret)
		return ret;
	return __mga2fb_bctrl_hw_init(mga2);
}

int mga2fb_bctrl_init(struct mga2 *mga2)
{
	int ret = 0;

	if (mga25(mga2->dev_id))
		ret = mga2fb_auc2_init(mga2);
	if (ret)
		return ret;
	ret = __mga2fb_bctrl_init(mga2);
	if (ret)
		return ret;
	return mga2fb_bctrl_hw_init(mga2);
}

int mga25_fbdev_init(struct drm_device *drm)
{
	struct mga2 *mga2 = drm->dev_private;
	struct mga25_fbdev *fb;
	int ret;

	if (WARN_ON(!drm->mode_config.num_crtc || !drm->mode_config.num_connector))
		return -EINVAL;


	fb = kzalloc(sizeof(struct mga25_fbdev), GFP_KERNEL);
	if (!fb)
		return -ENOMEM;

	mga2->fbdev = fb;

	drm_fb_helper_prepare(drm, &fb->helper, &mga25_fb_helper_funcs);

	ret = drm_fb_helper_init(drm, &fb->helper);
	if (ret)
		goto fail;

	ret = drm_fb_helper_initial_config(&fb->helper, 32);
	if (ret)
		goto fail;

	return 0;
      fail:
	kfree(fb);
	return ret;
}

void mga25_fbdev_fini(struct drm_device *drm)
{
	struct mga2 *mga2 = drm->dev_private;

	if (!mga2->fbdev)
		return;
	mga25_fbdev_destroy(drm, mga2->fbdev);
	kfree(mga2->fbdev);
	mga2->fbdev = NULL;
}

void mga25_fbdev_set_suspend(struct drm_device *drm, int state)
{
	struct mga2 *mga2 = drm->dev_private;

	if (!mga2->fbdev)
		return;

	fb_set_suspend(mga2->fbdev->helper.fbdev, state);
}

int mga25_gem_sync_ioctl(struct drm_device *drm, void *data,
			struct drm_file *filp)
{
	struct mga2 *mga2 = drm->dev_private;
	return __mga25_sync(mga2);
}
