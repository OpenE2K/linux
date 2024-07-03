/*
 * Copyright © 2007 David Airlie
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *     David Airlie
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/vga_switcheroo.h>

#include <drm/drm_crtc.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_fourcc.h>
#include <drm/radeon_drm.h>

#include "radeon.h"

/* object hierarchy -
 * this contains a helper + a radeon fb
 * the helper contains a pointer to radeon framebuffer baseclass.
 */
struct radeon_fbdev {
	struct drm_fb_helper helper; /* must be first */
	struct drm_framebuffer fb;
	struct radeon_device *rdev;

#ifdef CONFIG_MCST
	struct radeon_bo *rbosys;
	struct drm_clip_rect dirty_clip;
	spinlock_t dirty_lock;
	struct work_struct dirty_work;
#endif
};

static int
radeonfb_open(struct fb_info *info, int user)
{
	struct radeon_fbdev *rfbdev = info->par;
	struct radeon_device *rdev = rfbdev->rdev;
	int ret = pm_runtime_get_sync(rdev->ddev->dev);
	if (ret < 0 && ret != -EACCES) {
		pm_runtime_mark_last_busy(rdev->ddev->dev);
		pm_runtime_put_autosuspend(rdev->ddev->dev);
		return ret;
	}
	return 0;
}

static int
radeonfb_release(struct fb_info *info, int user)
{
	struct radeon_fbdev *rfbdev = info->par;
	struct radeon_device *rdev = rfbdev->rdev;
#ifdef CONFIG_MCST
	if (radeon_fbdev_accel)
		cancel_work_sync(&rfbdev->dirty_work);
#endif

	pm_runtime_mark_last_busy(rdev->ddev->dev);
	pm_runtime_put_autosuspend(rdev->ddev->dev);
	return 0;
}

#ifdef CONFIG_MCST
static void __radeon_dirty(struct radeon_fbdev *rfbdev,
			  struct drm_clip_rect *c)
{
	int r;
	struct drm_framebuffer *fb = &rfbdev->fb;
	struct radeon_bo *rbo = gem_to_radeon_bo(fb->obj[0]);
	struct radeon_bo *rbosys = rfbdev->rbosys;
	uint64_t src = radeon_bo_gpu_offset(rbosys);
	uint64_t dst = radeon_bo_gpu_offset(rbo);
	struct radeon_fence *fence = NULL;
	int y = c->y1;
	int height = c->y2 - c->y1;
	int offset = y * fb->pitches[0];
	int size = (y + height) * fb->pitches[0];
	offset = round_down(offset, RADEON_GPU_PAGE_SIZE);
	size = round_up(size - offset, RADEON_GPU_PAGE_SIZE);

	mutex_lock(&rfbdev->rdev->ddev->mode_config.mutex);

	r = radeon_bo_reserve(rbo, false);
	if (unlikely(r)) {
		mutex_unlock(&rfbdev->rdev->ddev->mode_config.mutex);
		return;
	}

	fence = radeon_copy_dma(rfbdev->rdev, src + offset, dst + offset,
				size / RADEON_GPU_PAGE_SIZE, rbo->tbo.base.resv);
	if (IS_ERR(fence)) {
		DRM_ERROR("Failed GTT->VRAM copy\n");
			r = PTR_ERR(fence);
		goto out;
	}
	r = radeon_fence_wait(fence, false);
	radeon_fence_unref(&fence);
	if (r) {
		DRM_ERROR("Failed to wait for GTT->VRAM fence\n");
		goto out;
	}
out:
	radeon_bo_unreserve(rbo);
	mutex_unlock(&rfbdev->rdev->ddev->mode_config.mutex);
}

#define to_radeon_fbdev(x) container_of(x, struct radeon_fbdev, fb)

static int radeon_dirty(struct drm_framebuffer *fb,
					 struct drm_file *file_priv,
					 unsigned flags, unsigned color,
					 struct drm_clip_rect *clips,
					 unsigned num_clips)
{
	__radeon_dirty(to_radeon_fbdev(fb), clips);
	return 0;
}

static void radeon_fb_helper_dirty_work(struct work_struct *work)
{
	struct radeon_fbdev *helper = container_of(work,
					struct radeon_fbdev, dirty_work);
	struct drm_clip_rect *clip = &helper->dirty_clip;
	struct drm_clip_rect clip_copy;
	unsigned long flags;
	spin_lock_irqsave(&helper->dirty_lock, flags);
	clip_copy = *clip;
	clip->x1 = clip->y1 = ~0;
	clip->x2 = clip->y2 = 0;
	spin_unlock_irqrestore(&helper->dirty_lock, flags);

	/* call dirty callback only when it has been really touched */
	if (!(clip_copy.x1 < clip_copy.x2 && clip_copy.y1 < clip_copy.y2))
		return;
	radeon_dirty(&helper->fb, NULL, 0, 0, &clip_copy, 1);
}

static void radeon_fb_helper_dirty(struct fb_info *info, u32 x, u32 y,
				u32 width, u32 height)
{
	struct radeon_fbdev *rfbdev = info->par;
	struct drm_clip_rect *clip = &rfbdev->dirty_clip;
	unsigned long flags;

	spin_lock_irqsave(&rfbdev->dirty_lock, flags);
	clip->x1 = min_t(u32, clip->x1, x);
	clip->y1 = min_t(u32, clip->y1, y);
	clip->x2 = max_t(u32, clip->x2, x + width);
	clip->y2 = max_t(u32, clip->y2, y + height);
	spin_unlock_irqrestore(&rfbdev->dirty_lock, flags);

	if (info->state == FBINFO_STATE_RUNNING)
		queue_work(system_long_wq, &rfbdev->dirty_work);
}

static void radeon_fillrect(struct fb_info *p, const struct fb_fillrect *rect)
{
	sys_fillrect(p, rect);
	radeon_fb_helper_dirty(p, rect->dx, rect->dy,
			    rect->width, rect->height);
}

static void radeon_copyarea(struct fb_info *p, const struct fb_copyarea *area)
{
	sys_copyarea(p, area);
	radeon_fb_helper_dirty(p, area->dx, area->dy,
			    area->width, area->height);
}

static void radeon_imageblit(struct fb_info *p, const struct fb_image *image)
{
	sys_imageblit(p, image);
	radeon_fb_helper_dirty(p, image->dx, image->dy,
			    image->width, image->height);

}

static ssize_t radeon_fbwrite(struct fb_info *info, const char __user *buf,
				size_t count, loff_t *ppos)
{
	ssize_t ret;
	ret = fb_sys_write(info, buf, count, ppos);
	if (ret > 0)
		radeon_fb_helper_dirty(info, 0, 0, info->var.xres,
				    info->var.yres);
	return ret;
}
#endif /* CONFIG_MCST */

#ifdef CONFIG_MCST
static struct fb_ops radeonfb_ops = {
#else
static const struct fb_ops radeonfb_ops = {
#endif
	.owner = THIS_MODULE,
	DRM_FB_HELPER_DEFAULT_OPS,
	.fb_open = radeonfb_open,
	.fb_release = radeonfb_release,
#ifdef CONFIG_MCST
	.fb_fillrect = radeon_fillrect,
	.fb_copyarea = radeon_copyarea,
	.fb_imageblit = radeon_imageblit,
	.fb_read	= fb_sys_read,
	.fb_write	= radeon_fbwrite,
#else
	.fb_fillrect = drm_fb_helper_cfb_fillrect,
	.fb_copyarea = drm_fb_helper_cfb_copyarea,
	.fb_imageblit = drm_fb_helper_cfb_imageblit,
#endif
};


int radeon_align_pitch(struct radeon_device *rdev, int width, int cpp, bool tiled)
{
	int aligned = width;
	int align_large = (ASIC_IS_AVIVO(rdev)) || tiled;
	int pitch_mask = 0;

	switch (cpp) {
	case 1:
		pitch_mask = align_large ? 255 : 127;
		break;
	case 2:
		pitch_mask = align_large ? 127 : 31;
		break;
	case 3:
	case 4:
		pitch_mask = align_large ? 63 : 15;
		break;
	}

	aligned += pitch_mask;
	aligned &= ~pitch_mask;
	return aligned * cpp;
}

static void radeonfb_destroy_pinned_object(struct drm_gem_object *gobj)
{
	struct radeon_bo *rbo = gem_to_radeon_bo(gobj);
	int ret;

	ret = radeon_bo_reserve(rbo, false);
	if (likely(ret == 0)) {
		radeon_bo_kunmap(rbo);
		radeon_bo_unpin(rbo);
		radeon_bo_unreserve(rbo);
	}
	drm_gem_object_put(gobj);
}

static int radeonfb_create_pinned_object(struct radeon_fbdev *rfbdev,
					 struct drm_mode_fb_cmd2 *mode_cmd,
					 struct drm_gem_object **gobj_p)
{
	const struct drm_format_info *info;
	struct radeon_device *rdev = rfbdev->rdev;
	struct drm_gem_object *gobj = NULL;
	struct radeon_bo *rbo = NULL;
	bool fb_tiled = false; /* useful for testing */
	u32 tiling_flags = 0;
	int ret;
	int aligned_size, size;
	int height = mode_cmd->height;
	u32 cpp;

	info = drm_get_format_info(rdev->ddev, mode_cmd);
	cpp = info->cpp[0];

	/* need to align pitch with crtc limits */
	mode_cmd->pitches[0] = radeon_align_pitch(rdev, mode_cmd->width, cpp,
						  fb_tiled);

	if (rdev->family >= CHIP_R600)
		height = ALIGN(mode_cmd->height, 8);
	size = mode_cmd->pitches[0] * height;
	aligned_size = ALIGN(size, PAGE_SIZE);
	ret = radeon_gem_object_create(rdev, aligned_size, 0,
				       RADEON_GEM_DOMAIN_VRAM,
				       0, true, &gobj);
	if (ret) {
		pr_err("failed to allocate framebuffer (%d)\n", aligned_size);
		return -ENOMEM;
	}
	rbo = gem_to_radeon_bo(gobj);

	if (fb_tiled)
		tiling_flags = RADEON_TILING_MACRO;

#ifdef __BIG_ENDIAN
	switch (cpp) {
	case 4:
		tiling_flags |= RADEON_TILING_SWAP_32BIT;
		break;
	case 2:
		tiling_flags |= RADEON_TILING_SWAP_16BIT;
	default:
		break;
	}
#endif

	if (tiling_flags) {
		ret = radeon_bo_set_tiling_flags(rbo,
						 tiling_flags | RADEON_TILING_SURFACE,
						 mode_cmd->pitches[0]);
		if (ret)
			dev_err(rdev->dev, "FB failed to set tiling flags\n");
	}


	ret = radeon_bo_reserve(rbo, false);
	if (unlikely(ret != 0))
		goto out_unref;
	/* Only 27 bit offset for legacy CRTC */
	ret = radeon_bo_pin_restricted(rbo, RADEON_GEM_DOMAIN_VRAM,
				       ASIC_IS_AVIVO(rdev) ? 0 : 1 << 27,
				       NULL);
	if (ret) {
		radeon_bo_unreserve(rbo);
		goto out_unref;
	}
	if (fb_tiled)
		radeon_bo_check_tiling(rbo, 0, 0);
	ret = radeon_bo_kmap(rbo, NULL);
	radeon_bo_unreserve(rbo);
	if (ret) {
		goto out_unref;
	}

	*gobj_p = gobj;
	return 0;
out_unref:
	radeonfb_destroy_pinned_object(gobj);
	*gobj_p = NULL;
	return ret;
}

#ifdef CONFIG_MCST
static struct radeon_bo *radeon_mk_obj(struct radeon_device *rdev,
				unsigned size, int domain,
				uint64_t *gpu_addr, void **addr)
{
	struct radeon_bo *obj = NULL;
	int r;
	r = radeon_bo_create(rdev, size, PAGE_SIZE, true,
				domain, 0, NULL, NULL, &obj);
	if (r) {
		DRM_ERROR("Failed to create object\n");
		goto out_lclean;
	}

	r = radeon_bo_reserve(obj, false);
	if (unlikely(r != 0)) {
		DRM_ERROR("Failed to reserve object\n");
		goto out_lclean_unref;
	}
	r = radeon_bo_pin(obj, domain, gpu_addr);
	if (r) {
		DRM_ERROR("Failed to pin object\n");
		goto out_lclean_unres;
	}

	r = radeon_bo_kmap(obj, addr);
	if (r) {
		DRM_ERROR("Failed to map object\n");
		goto out_lclean_unpin;
	}
	radeon_bo_unreserve(obj);
	return obj;

out_lclean_unpin:
		radeon_bo_unpin(obj);
out_lclean_unres:
		radeon_bo_unreserve(obj);
out_lclean_unref:
		radeon_bo_unref(&obj);
out_lclean:
	return NULL;
}

static void radeon_rm_obj(struct radeon_bo *obj)
{
	radeon_bo_kunmap(obj);
	radeon_bo_unpin(obj);
	radeon_bo_unreserve(obj);
	radeon_bo_unref(&obj);
}
#endif /* CONFIG_MCST */

static int radeonfb_create(struct drm_fb_helper *helper,
			   struct drm_fb_helper_surface_size *sizes)
{
	struct radeon_fbdev *rfbdev =
		container_of(helper, struct radeon_fbdev, helper);
	struct radeon_device *rdev = rfbdev->rdev;
	struct fb_info *info;
	struct drm_framebuffer *fb = NULL;
	struct drm_mode_fb_cmd2 mode_cmd;
	struct drm_gem_object *gobj = NULL;
	struct radeon_bo *rbo = NULL;
	int ret;
	unsigned long tmp;

	mode_cmd.width = sizes->surface_width;
	mode_cmd.height = sizes->surface_height;

	/* avivo can't scanout real 24bpp */
	if ((sizes->surface_bpp == 24) && ASIC_IS_AVIVO(rdev))
		sizes->surface_bpp = 32;

	mode_cmd.pixel_format = drm_mode_legacy_fb_format(sizes->surface_bpp,
							  sizes->surface_depth);

	ret = radeonfb_create_pinned_object(rfbdev, &mode_cmd, &gobj);
	if (ret) {
		DRM_ERROR("failed to create fbcon object %d\n", ret);
		return ret;
	}

	rbo = gem_to_radeon_bo(gobj);

#ifdef CONFIG_MCST
	if (!rdev->accel_working)
		radeon_fbdev_accel = 0;
	if (radeon_fbdev_accel) {
		void *addr;
		uint64_t gpu_addr;
		rfbdev->rbosys = radeon_mk_obj(rdev, gobj->size,
					RADEON_GEM_DOMAIN_GTT,
						&gpu_addr, &addr);
		if (rfbdev->rbosys == NULL) {
			ret = -ENOMEM;
			goto out;
		}
	} else {
		radeonfb_ops.fb_fillrect  = cfb_fillrect;
		radeonfb_ops.fb_copyarea  = cfb_copyarea;
		radeonfb_ops.fb_imageblit = cfb_imageblit;
		radeonfb_ops.fb_read	  = NULL;
		radeonfb_ops.fb_write	  = NULL;
	}
#endif /* CONFIG_MCST */

	/* okay we have an object now allocate the framebuffer */
	info = drm_fb_helper_alloc_fbi(helper);
	if (IS_ERR(info)) {
		ret = PTR_ERR(info);
		goto out;
	}

	/* radeon resume is fragile and needs a vt switch to help it along */
	info->skip_vt_switch = false;

	ret = radeon_framebuffer_init(rdev->ddev, &rfbdev->fb, &mode_cmd, gobj);
	if (ret) {
		DRM_ERROR("failed to initialize framebuffer %d\n", ret);
		goto out;
	}

	fb = &rfbdev->fb;

	/* setup helper */
	rfbdev->helper.fb = fb;

	memset_io(rbo->kptr, 0x0, radeon_bo_size(rbo));

#ifdef CONFIG_MCST
	if (radeon_fbdev_accel)
		info->flags |= FBINFO_READS_FAST;
#endif
	info->fbops = &radeonfb_ops;

	tmp = radeon_bo_gpu_offset(rbo) - rdev->mc.vram_start;
	info->fix.smem_start = rdev->mc.aper_base + tmp;
	info->fix.smem_len = radeon_bo_size(rbo);
	info->screen_base = rbo->kptr;
#ifdef CONFIG_MCST
	if (radeon_fbdev_accel)
		info->screen_base = rfbdev->rbosys->kptr;
#endif
	info->screen_size = radeon_bo_size(rbo);

	drm_fb_helper_fill_info(info, &rfbdev->helper, sizes);

	/* setup aperture base/size for vesafb takeover */
	info->apertures->ranges[0].base = rdev->ddev->mode_config.fb_base;
	info->apertures->ranges[0].size = rdev->mc.aper_size;

	/* Use default scratch pixmap (info->pixmap.flags = FB_PIXMAP_SYSTEM) */

	if (info->screen_base == NULL) {
		ret = -ENOSPC;
		goto out;
	}

	DRM_INFO("fb mappable at 0x%lX\n",  info->fix.smem_start);
	DRM_INFO("vram apper at 0x%lX\n",  (unsigned long)rdev->mc.aper_base);
	DRM_INFO("size %lu\n", (unsigned long)radeon_bo_size(rbo));
	DRM_INFO("fb depth is %d\n", fb->format->depth);
	DRM_INFO("   pitch is %d\n", fb->pitches[0]);

	vga_switcheroo_client_fb_set(rdev->ddev->pdev, info);
	return 0;

out:
#ifdef CONFIG_MCST
	if (rfbdev->rbosys)
		radeon_rm_obj(rfbdev->rbosys);
#endif
	if (rbo) {

	}
	if (fb && ret) {
		drm_gem_object_put(gobj);
		drm_framebuffer_unregister_private(fb);
		drm_framebuffer_cleanup(fb);
		kfree(fb);
	}
	return ret;
}

static int radeon_fbdev_destroy(struct drm_device *dev, struct radeon_fbdev *rfbdev)
{
	struct drm_framebuffer *fb = &rfbdev->fb;

	drm_fb_helper_unregister_fbi(&rfbdev->helper);

#ifdef CONFIG_MCST
	if (rfbdev->rbosys) {
		cancel_work_sync(&rfbdev->dirty_work);
		radeon_rm_obj(rfbdev->rbosys);
		rfbdev->rbosys = NULL;
	}
#endif

	if (fb->obj[0]) {
		radeonfb_destroy_pinned_object(fb->obj[0]);
		fb->obj[0] = NULL;
		drm_framebuffer_unregister_private(fb);
		drm_framebuffer_cleanup(fb);
	}
	drm_fb_helper_fini(&rfbdev->helper);

	return 0;
}

static const struct drm_fb_helper_funcs radeon_fb_helper_funcs = {
	.fb_probe = radeonfb_create,
};

int radeon_fbdev_init(struct radeon_device *rdev)
{
	struct radeon_fbdev *rfbdev;
	int bpp_sel = 32;
	int ret;

	/* don't enable fbdev if no connectors */
	if (list_empty(&rdev->ddev->mode_config.connector_list))
		return 0;

	/* select 8 bpp console on 8MB cards, or 16 bpp on RN50 or 32MB */
	if (rdev->mc.real_vram_size <= (8*1024*1024))
		bpp_sel = 8;
	else if (ASIC_IS_RN50(rdev) ||
		 rdev->mc.real_vram_size <= (32*1024*1024))
		bpp_sel = 16;

	rfbdev = kzalloc(sizeof(struct radeon_fbdev), GFP_KERNEL);
	if (!rfbdev)
		return -ENOMEM;

	rfbdev->rdev = rdev;
	rdev->mode_info.rfbdev = rfbdev;
#ifdef CONFIG_MCST
	spin_lock_init(&rfbdev->dirty_lock);
	INIT_WORK(&rfbdev->dirty_work, radeon_fb_helper_dirty_work);
	rfbdev->dirty_clip.x1 = rfbdev->dirty_clip.y1 = ~0;
#endif
	drm_fb_helper_prepare(rdev->ddev, &rfbdev->helper,
			      &radeon_fb_helper_funcs);

	ret = drm_fb_helper_init(rdev->ddev, &rfbdev->helper);
	if (ret)
		goto free;

	/* disable all the possible outputs/crtcs before entering KMS mode */
	drm_helper_disable_unused_functions(rdev->ddev);

	ret = drm_fb_helper_initial_config(&rfbdev->helper, bpp_sel);
	if (ret)
		goto fini;

	return 0;

fini:
	drm_fb_helper_fini(&rfbdev->helper);
free:
	kfree(rfbdev);
	return ret;
}

void radeon_fbdev_fini(struct radeon_device *rdev)
{
	if (!rdev->mode_info.rfbdev)
		return;

	radeon_fbdev_destroy(rdev->ddev, rdev->mode_info.rfbdev);
	kfree(rdev->mode_info.rfbdev);
	rdev->mode_info.rfbdev = NULL;
}

void radeon_fbdev_set_suspend(struct radeon_device *rdev, int state)
{
	if (rdev->mode_info.rfbdev)
		drm_fb_helper_set_suspend(&rdev->mode_info.rfbdev->helper, state);

#ifdef CONFIG_MCST
	if (rdev->mode_info.rfbdev && state && radeon_fbdev_accel)
		cancel_work_sync(&rdev->mode_info.rfbdev->dirty_work);
#endif
}

bool radeon_fbdev_robj_is_fb(struct radeon_device *rdev, struct radeon_bo *robj)
{
	if (!rdev->mode_info.rfbdev)
		return false;

	if (robj == gem_to_radeon_bo(rdev->mode_info.rfbdev->fb.obj[0]))
		return true;
	return false;
}
