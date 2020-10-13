/*
 * Copyright 2012 Red Hat Inc.
 * Parts based on xf86-video-ast
 * Copyright (c) 2005 ASPEED Technology Inc.
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
#include "drmP.h"
#include "drm_crtc.h"
#include "drm_crtc_helper.h"
#include "mcst_drv.h"
#include "mcst_util.h"

static struct mcst_i2c_chan *mcst_i2c_create(struct drm_device *dev, int cell);
static void mcst_i2c_destroy(struct mcst_i2c_chan *i2c);
static int mcst_cursor_set(struct drm_crtc *crtc,
			  struct drm_file *file_priv,
			  uint32_t handle,
			  uint32_t width,
			  uint32_t height);
static int mcst_cursor_move(struct drm_crtc *crtc,
			   int x, int y);

static inline void mcst_load_palette_index(struct mcst_private *mcst,
					   int cell,
					   int index,
					   u8 red, u8 green, u8 blue)
{
	mcst_io_write32(mcst, cell, REG_PCLT + index*4,
			(red << 16) | (green << 8) | blue);
	/* TODO: while write to both table, - need remove */
	mcst_io_write32(mcst, cell, REG_PCLT + (index+256)*4,
			(red << 16) | (green << 8) | blue);
}

static void mcst_crtc_load_lut(struct drm_crtc *crtc)
{
	struct mcst_private *mcst = crtc->dev->dev_private;
	struct mcst_crtc *mcst_crtc = to_mcst_crtc(crtc);
	int cell = mcst_crtc->cell;
	int i;

	if (!crtc->enabled)
		return;

	for (i = 0; i < 256; i++) {
		mcst_load_palette_index(mcst, cell, i,
					mcst_crtc->lut_r[i],
					mcst_crtc->lut_g[i],
					mcst_crtc->lut_b[i]);
	}
}


/**
 * TODO: MGA display don't support pitch for framebuffer output
 * (always equal HTIM.Thgate)
 */
#if 0
static void mcst_set_offset_reg(struct drm_crtc *crtc)
{
	struct mcst_private *mcst = crtc->dev->dev_private;

	u16 offset;
CH();

	offset = crtc->fb->pitches[0] >> 3;
	mcst_set_index_reg(mcst, mcst_IO_CRTC_PORT, 0x13, (offset & 0xff));
	mcst_set_index_reg(mcst, mcst_IO_CRTC_PORT, 0xb0, (offset >> 8) & 0x3f);
}
#endif


bool mcst_set_dac_reg(struct drm_crtc *crtc, struct drm_display_mode *mode)
{
CH();
	switch (crtc->fb->bits_per_pixel) {
	case 8:
		break;
	default:
		return false;
	}
	return true;
}

void mcst_set_start_address_crt1(struct drm_crtc *crtc, unsigned offset)
{
	struct mcst_private *mcst = crtc->dev->dev_private;
	struct mcst_crtc *mcst_crtc = to_mcst_crtc(crtc);
	int cell = mcst_crtc->cell;
CH();
	/* Address must be aligned to 4 */
	DRM_INFO("cell#%d: Setup hw addr of framebuffer to 0x%x\n",
			cell, offset);
	mcst_io_write32(mcst, cell, REG_VBARa, offset);
}

static void mcst_crtc_dpms(struct drm_crtc *crtc, int mode)
{
	struct mcst_private *mcst = crtc->dev->dev_private;
	struct mcst_crtc *mcst_crtc = to_mcst_crtc(crtc);
	int cell = mcst_crtc->cell;

CH();
	/**
	 *  TODO: Can MGA display controller stop refresh framebuffer,
	 *  without stop [hv]syncs?
	 */
	DRM_INFO("dpms mode => %d\n", mode);

	switch (mode) {
	case DRM_MODE_DPMS_ON:
		mcst_io_write32(mcst, cell, REG_CTRL,
				mcst_io_read32(mcst, cell, REG_CTRL)
				| CTRL_VEN);
		mcst_crtc_load_lut(crtc);
		break;
	case DRM_MODE_DPMS_STANDBY:
	case DRM_MODE_DPMS_SUSPEND:
	case DRM_MODE_DPMS_OFF:
		mcst_io_write32(mcst, cell, REG_CTRL,
				mcst_io_read32(mcst, cell, REG_CTRL)
				& ~CTRL_VEN);
		break;
	}
}


static bool mcst_crtc_mode_fixup(struct drm_crtc *crtc,
				  const struct drm_display_mode *mode,
				  struct drm_display_mode *adjusted_mode)
{
CH();
	return true;
}

/* mcst is different - we will force move buffers out of VRAM */
static int mcst_crtc_do_set_base(struct drm_crtc *crtc,
				struct drm_framebuffer *fb,
				int x, int y, int atomic)
{
	struct mcst_private *mcst = crtc->dev->dev_private;
	struct drm_gem_object *obj;
	struct mcst_framebuffer *mcst_fb;
	struct mcst_bo *bo;
	int ret;
	u64 gpu_addr;

CH();
	/* push the previous fb to system ram */
	if (!atomic && fb) {
		mcst_fb = to_mcst_framebuffer(fb);
		obj = mcst_fb->obj;
		bo = gem_to_mcst_bo(obj);
		ret = mcst_bo_reserve(bo, false);
		if (ret)
			return ret;
		mcst_bo_push_sysram(bo);
		mcst_bo_unreserve(bo);
	}

	mcst_fb = to_mcst_framebuffer(crtc->fb);
	obj = mcst_fb->obj;
	bo = gem_to_mcst_bo(obj);

	ret = mcst_bo_reserve(bo, false);
	if (ret)
		return ret;

	ret = mcst_bo_pin(bo, TTM_PL_FLAG_VRAM, &gpu_addr);
	if (ret) {
		mcst_bo_unreserve(bo);
		return ret;
	}

	if (&mcst->fbdev->mfb == mcst_fb) {
		/* if pushing console in kmap it */
		ret = ttm_bo_kmap(&bo->bo, 0, bo->bo.num_pages, &bo->kmap);
		if (ret)
			DRM_ERROR("failed to kmap fbcon\n");
	}
	mcst_bo_unreserve(bo);

	mcst_set_start_address_crt1(crtc, (u32)gpu_addr);

	return 0;
}

static int mcst_crtc_mode_set_base(struct drm_crtc *crtc, int x, int y,
			     struct drm_framebuffer *old_fb)
{
CH();
	return mcst_crtc_do_set_base(crtc, old_fb, x, y, 0);
}

static struct mcst_bitfield ctrl_bits_intr[] = {
	{ 0,  1, "VEN"	     },
	{ 1,  1, "VIE"	     },
	{ 2,  1, "HIE"	     },
	{ 3,  1, "VBSIE"     },
	{ 4,  1, "CBSIE"     },
	{ 5,  1, "VBSWE"     },
	{ 6,  1, "CBSWE"     },
	{ 7,  2, "VBL"	     },
	{ 9,  2, "CD"	     },
	{ 11, 1, "PC"	     },
	{ 12, 1, "HSL"	     },
	{ 13, 1, "VSL"	     },
	{ 14, 1, "CSL"	     },
	{ 15, 1, "BL"	     },
	{ 16, 1, "FPM"	     },
	{ 20, 1, "HC0E"      },
	{ 21, 1, "HC0R"      },
	{ 29, 3, "INVSWPMOD" },
	{}
};


static int mcst_crtc_mode_set(struct drm_crtc *crtc,
			     struct drm_display_mode *mode,
			     struct drm_display_mode *adjusted_mode,
			     int x, int y,
			     struct drm_framebuffer *old_fb)
{
	struct mcst_crtc *mcst_crtc = to_mcst_crtc(crtc);
	struct mcst_private *mcst = crtc->dev->dev_private;
	int cell = mcst_crtc->cell;

/*
	if (mode->flags & DRM_MODE_FLAG_INTERLACE)
		timing->vmode = FB_VMODE_INTERLACED;
	else
		timing->vmode = FB_VMODE_NONINTERLACED;

	if (mode->flags & DRM_MODE_FLAG_DBLSCAN)
		timing->vmode |= FB_VMODE_DOUBLE;

FIXME: How about INTERLACED and DBLSCAN in MGA display controller
*/

	int bpp = crtc->fb->bits_per_pixel;

	/* The Horizontal Syncronization Time (Sync Pulse) */
	int hsync = mode->hsync_end - mode->hsync_start;

	/* The Horizontal Gate Delay Time (Back Porch) */
	int hgdel = mode->htotal    - mode->hsync_end;

	/* The Horizontal Gate Time (Active Time) */
	int hgate = mode->hdisplay;

	/* The Horizontal Length Time (Line Total) */
	int hlen  = mode->htotal;

	/* The Vertical Syncronization Time (Sync Pulse) */
	int vsync = mode->vsync_end - mode->vsync_start;

	/* The Vertical Gate Delay Time (Back Porch) */
	int vgdel = mode->vtotal    - mode->vsync_end;

	/* The Vertical Gate Time (Active Time) */
	int vgate = mode->vdisplay;

	/* The Vertical Length Time (Frame total) */
	int vlen  = mode->vtotal;

	/* Video Memory Burst Length */
	int vbl = CTRL_VBL1024;

	int ctrl = (REG_STAT_IRQS_MASK & mcst_io_read32(mcst, cell, REG_CTRL));

	uint32_t pixclock = 1000000000 / mode->clock;

CH();
	ctrl |= CTRL_BL_NEG | vbl;
	DRM_INFO("mcst_crtc_mode_set(): cell=%d clock=%d kHz => %d\n"
		  "hdisplay=%d hsync_start=%d hsync_end=%d htotal=%d hskew=%d\n"
		  "vdisplay=%d vsync_start=%d vsync_end=%d vtotal=%d vscan=%d\n"
		  "flags=0x%x\n",
		  cell, mode->clock, pixclock,
		  mode->hdisplay, mode->hsync_start, mode->hsync_end,
		  mode->htotal, mode->hskew,
		  mode->vdisplay, mode->vsync_start, mode->vsync_end,
		  mode->vtotal, mode->vscan,
		  mode->flags);

	switch (mcst->chip) {
	case MCST_MGA:
		/* TODO: For classic MGA card need setup both PLL output */
		mcst_pll_set_pixclock(0, mcst->i2cregs, pixclock);
		mcst_pll_set_pixclock(1, mcst->i2cregs, pixclock);
		break;
	case MCST_MGA3D:
		mcst_pll_set_pixclock(cell, mcst->i2cregs, pixclock);
		break;
	case MCST_UNSUPPORTED_MGA:
		/* TODO: nothing to safe */
		break;
	}

	/* MGA device internally always works in little endian mode */
	switch (bpp) {
	case 8:
		ctrl |= CTRL_CD_8BPP | CTRL_PC_PSEUDO;
		break;
	case 16:
		ctrl |= CTRL_CD_16BPP;
#ifdef __LITTLE_ENDIAN
		/* Turn off bytes-in-half word twister (seted by default) */
		ctrl |= CTRL_IN_WORDS16_TWISTER;
#endif
		break;
	case 24:
		ctrl |= CTRL_CD_24BPP;
		DRM_ERROR("bbp == 24, you are crazy!?\n");
		break;
	case 32:
		ctrl |= CTRL_CD_32BPP;
#ifdef __LITTLE_ENDIAN
		/* Turn off half words twister (seted by default ) */
		ctrl |= CTRL_WORDS16_IN_WORDS32_TWISTER;
		/* Turn off bytes-in-half word twister (seted by default) */
		ctrl |= CTRL_IN_WORDS16_TWISTER;
#endif
		break;
	default:
		DRM_ERROR("Invalid color depth: %d\n", bpp);
		return -EINVAL;
	}

	/* Set syncs polarity */
	if (mode->flags & DRM_MODE_FLAG_NVSYNC)
		ctrl |= CTRL_VSYNC_NEG;
	if (mode->flags & DRM_MODE_FLAG_NHSYNC)
		ctrl |= CTRL_HSYNC_NEG;
	/** Always set CTRL_CSYNC_NEG, don't check DRM_MODE_FLAG_NCSYNC
	 * (get a green vertical bar)
	 */
	ctrl |= CTRL_CSYNC_NEG;

	/* FIXME: Make sure that you need it and put into the formula above */
	hsync--, hgdel--, hgate--, vsync--, vgdel--, vgate--, hlen--, vlen--;

	mcst_io_write32(mcst, cell, REG_CTRL, ctrl);
	mcst_io_write32(mcst, cell, REG_HTIM,
			hsync << 24 | hgdel << 16 | hgate);
	mcst_io_write32(mcst, cell, REG_VTIM,
			vsync << 24 | vgdel << 16 | vgate);
	mcst_io_write32(mcst, cell, REG_HVLEN, hlen << 16 | vlen);


	DRM_INFO("hsync: %d hgdel: %d hgate %d\n", hsync, hgdel, hgate);
	DRM_INFO("vsync: %d vgdel: %d vgate %d\n", vsync, vgdel, vgate);
	DRM_INFO("hlen: %d vlen: %d\n", hlen, vlen);

/*mcst_set_dac_reg(crtc,adjusted_mode);This is empty fuction, need call it? */
	mcst_crtc_mode_set_base(crtc, x, y, old_fb);

	ctrl |= CTRL_VEN;
	mcst_io_write32(mcst, cell, REG_CTRL, ctrl);
	DRM_INFO("REG_CTRL = 0x%x\n", ctrl);
	mcst_bitfield_print(ctrl_bits_intr, ctrl);
	return 0;




#if 0
	struct drm_device *dev = crtc->dev;
	struct mcst_private *mcst = crtc->dev->dev_private;
	struct mcst_vbios_mode_info vbios_mode;
	bool ret;

CH();
	ret = mcst_get_vbios_mode_info(crtc, mode, adjusted_mode, &vbios_mode);
	if (ret == false)
		return -EINVAL;

	mcst_set_index_reg_mask(mcst, mcst_IO_CRTC_PORT, 0xa1, 0xff, 0x04);

/*	mcst_set_std_reg(crtc, adjusted_mode, &vbios_mode); */
/*	mcst_set_crtc_reg(crtc, adjusted_mode, &vbios_mode); */
	mcst_set_offset_reg(crtc);
/*	mcst_set_dclk_reg(dev, adjusted_mode, &vbios_mode); */
/*	mcst_set_ext_reg(crtc, adjusted_mode, &vbios_mode); */
/*	mcst_set_sync_reg(dev, adjusted_mode, &vbios_mode); */
	mcst_set_dac_reg(crtc, adjusted_mode);

	mcst_crtc_mode_set_base(crtc, x, y, old_fb);

	return 0;
#endif
}

static void mcst_crtc_disable(struct drm_crtc *crtc)
{
CH();
}

static void mcst_crtc_prepare(struct drm_crtc *crtc)
{
CH();
}

static void mcst_crtc_commit(struct drm_crtc *crtc)
{
CH();
}


static const struct drm_crtc_helper_funcs mcst_crtc_helper_funcs = {
	.dpms = mcst_crtc_dpms,
	.mode_fixup = mcst_crtc_mode_fixup,
	.mode_set = mcst_crtc_mode_set,
	.mode_set_base = mcst_crtc_mode_set_base,
	.disable = mcst_crtc_disable,
	.load_lut = mcst_crtc_load_lut,
	.prepare = mcst_crtc_prepare,
	.commit = mcst_crtc_commit,
};

static void mcst_crtc_reset(struct drm_crtc *crtc)
{
CH();

}

static void mcst_crtc_gamma_set(struct drm_crtc *crtc, u16 *red, u16 *green,
				 u16 *blue, uint32_t start, uint32_t size)
{
	struct mcst_crtc *mcst_crtc = to_mcst_crtc(crtc);
	int end = (start + size > 256) ? 256 : start + size, i;

CH();
	/* userspace palettes are always correct as is */
	for (i = start; i < end; i++) {
		mcst_crtc->lut_r[i] = red[i] >> 8;
		mcst_crtc->lut_g[i] = green[i] >> 8;
		mcst_crtc->lut_b[i] = blue[i] >> 8;
	}
	mcst_crtc_load_lut(crtc);
}


static void mcst_crtc_destroy(struct drm_crtc *crtc)
{
	struct drm_device *dev = crtc->dev;
	struct mcst_crtc *mcst_crtc = to_mcst_crtc(crtc);
	int cell = mcst_crtc->cell;
CH();
	mcst_irq_unregister(dev, cell, STAT_VINT_BIT_NUM);
	drm_crtc_cleanup(crtc);
	kfree(crtc);
}

static const struct drm_crtc_funcs mcst_crtc_funcs = {
	.cursor_set = mcst_cursor_set,
	.cursor_move = mcst_cursor_move,
	.reset = mcst_crtc_reset,
	.set_config = drm_crtc_helper_set_config,
	.gamma_set = mcst_crtc_gamma_set,
	.destroy = mcst_crtc_destroy,
};

int
mcst_enable_vblank(struct drm_device *dev, int crtc_num)
{
	struct mcst_private *mcst = dev->dev_private;

CH();
	/* Enable interrupt from VINT */
	mcst_io_write32(mcst, crtc_num, REG_CTRL,
			mcst_io_read32(mcst, crtc_num, REG_CTRL) | CTRL_VIE);

	return 0;
}

/* TODO: Other function save bit CTRL_VIE or can reset it? */

void
mcst_disable_vblank(struct drm_device *dev, int crtc_num)
{
	struct mcst_private *mcst = dev->dev_private;

CH();
	/* Disable interrupt from VINT */
	mcst_io_write32(mcst, crtc_num, REG_CTRL,
			mcst_io_read32(mcst, crtc_num, REG_CTRL) & ~CTRL_VIE);
}


/**
 * Interrupt handlers from MGA card
 */
static void
mcst_sint_crtc0_isr(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;

	/* confirm interrupt */
	mcst_io_write32(mcst, 0, REG_STAT, STAT_SINT_MASK);
	DRM_ERROR("MGA: System Error Interrupt!\n");
}

static void
mcst_sint_crtc1_isr(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;

	/* confirm interrupt */
	mcst_io_write32(mcst, 1, REG_STAT, STAT_SINT_MASK);
	DRM_ERROR("MGA: System Error Interrupt!\n");
}

static void
mcst_luint_crtc0_isr(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;

	/* confirm interrupt */
	mcst_io_write32(mcst, 0, REG_STAT, STAT_LUINT_MASK);
	DRM_ERROR("MGA: Line Error Interrupt!\n");
}

static void
mcst_luint_crtc1_isr(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;

	/* confirm interrupt */
	mcst_io_write32(mcst, 1, REG_STAT, STAT_LUINT_MASK);
	DRM_ERROR("MGA: Line Error Interrupt!\n");
}

static void
mcst_vint_crtc0_isr(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;

	/* confirm interrupt */
	mcst_io_write32(mcst, 0, REG_STAT, STAT_VINT_MASK);

	drm_handle_vblank(dev, 0);
}

static void
mcst_vint_crtc1_isr(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;

	/* confirm interrupt */
	mcst_io_write32(mcst, 1, REG_STAT, STAT_VINT_MASK);

	drm_handle_vblank(dev, 0);
}

static void
mcst_hint_crtc0_isr(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;

	/* confirm interrupt */
	mcst_io_write32(mcst, 0, REG_STAT, STAT_HINT_MASK);
	/* ... */
}

static void
mcst_hint_crtc1_isr(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;

	/* confirm interrupt */
	mcst_io_write32(mcst, 1, REG_STAT, STAT_HINT_MASK);
	/* ... */
}

static void
mcst_vbsint_crtc0_isr(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;

	/* confirm interrupt */
	mcst_io_write32(mcst, 0, REG_STAT, STAT_VBSINT_MASK);
	/* ... */
}

static void
mcst_vbsint_crtc1_isr(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;

	/* confirm interrupt */
	mcst_io_write32(mcst, 1, REG_STAT, STAT_VBSINT_MASK);
	/* ... */
}

static void
mcst_cbsint_crtc0_isr(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;

	/* confirm interrupt */
	mcst_io_write32(mcst, 0, REG_STAT, STAT_CBSINT_MASK);
	/* ... */
}

static void
mcst_cbsint_crtc1_isr(struct drm_device *dev)
{
	struct mcst_private *mcst = dev->dev_private;

	/* confirm interrupt */
	mcst_io_write32(mcst, 1, REG_STAT, STAT_CBSINT_MASK);
	/* ... */
}


static int mcst_crtc_init(struct drm_device *dev, int cell)
{
	struct mcst_crtc *mcst_crtc;
	int i;

CH();
	mcst_crtc = kzalloc(sizeof(struct mcst_crtc), GFP_KERNEL);
	if (!mcst_crtc) {
		DRM_ERROR("mcst_crtc_init(): mcst_crtc==0!\n");
		return -ENOMEM;
	}
/*	  mcst->crtc[cell] = crtc;*/
	mcst_crtc->cell = cell;

	drm_crtc_init(dev, &mcst_crtc->base, &mcst_crtc_funcs);
	drm_mode_crtc_set_gamma_size(&mcst_crtc->base, 256);
	drm_crtc_helper_add(&mcst_crtc->base, &mcst_crtc_helper_funcs);

	for (i = 0; i < 256; i++) {
		mcst_crtc->lut_r[i] = i;
		mcst_crtc->lut_g[i] = i;
		mcst_crtc->lut_b[i] = i;
	}

	/**
	 * Register all interrupt handler from MGA card
	 */
	switch (cell) {
	case 0:
		mcst_irq_register(dev, cell, STAT_SINT_BIT_NUM,
				  mcst_sint_crtc0_isr);
		mcst_irq_register(dev, cell, STAT_LUINT_BIT_NUM,
				  mcst_luint_crtc0_isr);
		mcst_irq_register(dev, cell, STAT_VINT_BIT_NUM,
				  mcst_vint_crtc0_isr);
		mcst_irq_register(dev, cell, STAT_HINT_BIT_NUM,
				  mcst_hint_crtc0_isr);
		mcst_irq_register(dev, cell, STAT_VBSINT_BIT_NUM,
				  mcst_vbsint_crtc0_isr);
		mcst_irq_register(dev, cell, STAT_CBSINT_BIT_NUM,
				  mcst_cbsint_crtc0_isr);
		break;
	case 1:
		mcst_irq_register(dev, cell, STAT_SINT_BIT_NUM,
				  mcst_sint_crtc1_isr);
		mcst_irq_register(dev, cell, STAT_LUINT_BIT_NUM,
				  mcst_luint_crtc1_isr);
		mcst_irq_register(dev, cell, STAT_VINT_BIT_NUM,
				  mcst_vint_crtc1_isr);
		mcst_irq_register(dev, cell, STAT_HINT_BIT_NUM,
				  mcst_hint_crtc1_isr);
		mcst_irq_register(dev, cell, STAT_VBSINT_BIT_NUM,
				  mcst_vbsint_crtc1_isr);
		mcst_irq_register(dev, cell, STAT_CBSINT_BIT_NUM,
				  mcst_cbsint_crtc1_isr);
		break;
	}

	DRM_INFO("[CRTC:%d] init done\n", mcst_crtc->base.base.id);
	return 0;
}

static void mcst_encoder_destroy(struct drm_encoder *encoder)
{
CH();
	drm_encoder_cleanup(encoder);
	kfree(encoder);
}


static struct drm_encoder *
mcst_best_single_encoder(struct drm_connector *connector)
{
	int enc_id = connector->encoder_ids[0];
	struct drm_mode_object *obj;
	struct drm_encoder *encoder;

CH();
	/* pick the encoder ids */
	if (enc_id) {
		obj = drm_mode_object_find(connector->dev, enc_id,
					   DRM_MODE_OBJECT_ENCODER);
		if (!obj) {
			return NULL;
		}
CH();
		encoder = obj_to_encoder(obj);
		return encoder;
	}
CH();
	return NULL;
}


static const struct drm_encoder_funcs mcst_enc_funcs = {
	.destroy = mcst_encoder_destroy,
};

static void mcst_encoder_dpms(struct drm_encoder *encoder, int mode)
{
CH();

}

static bool mcst_mode_fixup(struct drm_encoder *encoder,
			   const struct drm_display_mode *mode,
			   struct drm_display_mode *adjusted_mode)
{
CH();
	return true;
}

static void mcst_encoder_mode_set(struct drm_encoder *encoder,
			       struct drm_display_mode *mode,
			       struct drm_display_mode *adjusted_mode)
{
CH();
}

static void mcst_encoder_prepare(struct drm_encoder *encoder)
{
CH();
}

static void mcst_encoder_commit(struct drm_encoder *encoder)
{
CH();
}


static const struct drm_encoder_helper_funcs mcst_enc_helper_funcs = {
	.dpms = mcst_encoder_dpms,
	.mode_fixup = mcst_mode_fixup,
	.prepare = mcst_encoder_prepare,
	.commit = mcst_encoder_commit,
	.mode_set = mcst_encoder_mode_set,
};

static int mcst_encoder_init(struct drm_device *dev, int cell)
{
	struct mcst_encoder *mcst_encoder;
	struct mcst_private *mcst = dev->dev_private;

CH();
	mcst_encoder = kzalloc(sizeof(struct mcst_encoder), GFP_KERNEL);
	if (!mcst_encoder) {
		DRM_ERROR("mcst_encoder_init(): mcst_encoder==0!\n");
		return -ENOMEM;
	}

	drm_encoder_init(dev, &mcst_encoder->base, &mcst_enc_funcs,
			 (mcst->chip == MCST_MGA3D) ? DRM_MODE_ENCODER_TMDS
						    : DRM_MODE_ENCODER_DAC);
	drm_encoder_helper_add(&mcst_encoder->base, &mcst_enc_helper_funcs);

	mcst_encoder->base.possible_crtcs = (1<<cell);

	DRM_INFO("[ENCODER:%d:%s] init done\n",
			mcst_encoder->base.base.id,
			drm_get_encoder_name(&mcst_encoder->base));
	return 0;
}

static int mcst_get_modes(struct drm_connector *connector)
{
	struct mcst_connector *mcst_connector = to_mcst_connector(connector);
	struct edid *edid;
	int ret;

CH();
	edid = drm_get_edid(connector, &mcst_connector->i2c->adapter);
	if (edid) {
		drm_mode_connector_update_edid_property(&mcst_connector->base,
							edid);
		ret = drm_add_edid_modes(connector, edid);
		kfree(edid);
		return ret;
	} else
		drm_mode_connector_update_edid_property(&mcst_connector->base,
							NULL);
	return 0;
}

static int mcst_mode_valid(struct drm_connector *connector,
			  struct drm_display_mode *mode)
{
CH();
	return MODE_OK;
}

static void mcst_connector_destroy(struct drm_connector *connector)
{
	struct mcst_connector *mcst_connector = to_mcst_connector(connector);
	mcst_i2c_destroy(mcst_connector->i2c);
	drm_sysfs_connector_remove(connector);
	drm_connector_cleanup(connector);
	kfree(connector);
}

static enum drm_connector_status
mcst_connector_detect(struct drm_connector *connector, bool force)
{
CH();
	return connector_status_connected;
}

static const struct drm_connector_helper_funcs mcst_connector_helper_funcs = {
	.mode_valid = mcst_mode_valid,
	.get_modes = mcst_get_modes,
	.best_encoder = mcst_best_single_encoder,
};

static const struct drm_connector_funcs mcst_connector_funcs = {
	.dpms = drm_helper_connector_dpms,
	.detect = mcst_connector_detect,
	.fill_modes = drm_helper_probe_single_connector_modes,
	.destroy = mcst_connector_destroy,
};

int mcst_connector_init(struct drm_device *dev, int cell)
{
	struct mcst_connector *mcst_connector;
	struct drm_connector *connector;
	struct drm_encoder *encoder = NULL;
	struct mcst_private *mcst = dev->dev_private;
	int encoder_num = 0;

CH();
	mcst_connector = kzalloc(sizeof(struct mcst_connector), GFP_KERNEL);
	if (!mcst_connector) {
		DRM_ERROR("mcst_connector_init(): mcst_connector==0\n");
		return -ENOMEM;
	}

	connector = &mcst_connector->base;
	drm_connector_init(dev, connector, &mcst_connector_funcs,
			   (mcst->chip == MCST_MGA3D) ? DRM_MODE_CONNECTOR_DVID
						      : DRM_MODE_CONNECTOR_VGA);

	drm_connector_helper_add(connector, &mcst_connector_helper_funcs);

	connector->interlace_allowed = 0;
	connector->doublescan_allowed = 0;

	drm_sysfs_connector_add(connector);

	connector->polled = DRM_CONNECTOR_POLL_CONNECT;

	DRM_INFO("[CONNECTOR:%d:%s] init done (cell=%d)\n",
			connector->base.id,
			drm_get_connector_name(connector), cell);

	list_for_each_entry(encoder, &dev->mode_config.encoder_list, head) {
		if (encoder_num == cell) {
			break;
		}
		++encoder_num;
	}
	if (encoder) {
		DRM_INFO("Attach [ENCODER:%d:%s] to [CONNECTOR:%d:%s] "
				"(cell=%d)\n",
				encoder->base.id,
				drm_get_encoder_name(encoder),
				connector->base.id,
				drm_get_connector_name(connector), cell);
	} else {
		DRM_ERROR("!!! encoder == 0");
	}
	drm_mode_connector_attach_encoder(connector, encoder);

	mcst_connector->i2c = mcst_i2c_create(dev, cell);
	if (!mcst_connector->i2c)
		DRM_ERROR("failed to add ddc bus for connector\n");

	return 0;
}

/* allocate cursor cache and pin at start of VRAM */
int mcst_cursor_init(struct drm_device *dev)
{
	return 0;
}

void mcst_cursor_fini(struct drm_device *dev)
{
}

int mcst_mode_init(struct drm_device *dev)
{
	int i;
	struct mcst_private *mcst = dev->dev_private;
	int cell_num = (mcst->chip == MCST_MGA3D) ? 2 : 1;
CH();
	mcst_cursor_init(dev); /* TODO: fix this: need loop by cell_num */

	for (i = 0; i < cell_num; i++) {
		/* allocate crtcs */
		mcst_crtc_init(dev, i);

		/* allocate encoders */
		mcst_encoder_init(dev, i);
	}
	for (i = 0; i < cell_num; i++) {
		/* allocate connectors */
		mcst_connector_init(dev, i);
	}
	return 0;
}

void mcst_mode_fini(struct drm_device *dev)
{
CH();
	mcst_cursor_fini(dev);
}

static int get_clock(void *i2c_priv)
{
	struct mcst_i2c_chan *i2c = i2c_priv;
	struct mcst_private *mcst = i2c->dev->dev_private;
	uint32_t val;

	val = mcst_io_read32(mcst, i2c->cell, REG_DDC);
	return (val & REG_DDC_SCL_INPUT_MASK) ? 1 : 0;
}

static int get_data(void *i2c_priv)
{
	struct mcst_i2c_chan *i2c = i2c_priv;
	struct mcst_private *mcst = i2c->dev->dev_private;
	uint32_t val;

	val = mcst_io_read32(mcst, i2c->cell, REG_DDC);
	return (val & REG_DDC_SDA_INPUT_MASK) ? 1 : 0;
}

static void set_clock(void *i2c_priv, int clock)
{
	struct mcst_i2c_chan *i2c = i2c_priv;
	struct mcst_private *mcst = i2c->dev->dev_private;
	int i;

CH();
	for (i = 0; i < 0x10000; i++) {
		mcst_io_write32(mcst, i2c->cell, REG_DDC,
				(clock & 0x01) ? REG_DDC_SCL_LO
					       : REG_DDC_SCL_HI);
		if (get_clock(i2c_priv) == clock)
			break;
	}
}

static void set_data(void *i2c_priv, int data)
{
	struct mcst_i2c_chan *i2c = i2c_priv;
	struct mcst_private *mcst = i2c->dev->dev_private;
	int i;

CH();
	for (i = 0; i < 0x10000; i++) {
		mcst_io_write32(mcst, i2c->cell, REG_DDC,
				(data & 0x01) ? REG_DDC_SDA_LO
					      : REG_DDC_SDA_HI);
		if (get_data(i2c_priv) == data)
			break;
	}
}

static struct mcst_i2c_chan *mcst_i2c_create(struct drm_device *dev, int cell)
{
	struct mcst_i2c_chan *i2c;
	int ret;

CH();
	i2c = kzalloc(sizeof(struct mcst_i2c_chan), GFP_KERNEL);
	if (!i2c) {
		DRM_ERROR("mcst_i2c_create() i2c==NULL\n");
		return NULL;
	}

	i2c->adapter.owner = THIS_MODULE;
	i2c->adapter.class = I2C_CLASS_DDC;
	i2c->adapter.dev.parent = &dev->pdev->dev;
	i2c->dev = dev;
	i2c->cell = cell;
	i2c_set_adapdata(&i2c->adapter, i2c);
	snprintf(i2c->adapter.name, sizeof(i2c->adapter.name),
		 "MCST DDC/i2c bit bus #%d", cell);
	i2c->adapter.algo_data = &i2c->bit;

	i2c->bit.udelay = 20;
	i2c->bit.timeout = 2;
	i2c->bit.data = i2c;
	i2c->bit.setsda = set_data;
	i2c->bit.setscl = set_clock;
	i2c->bit.getsda = get_data;
	i2c->bit.getscl = get_clock;
	ret = i2c_bit_add_bus(&i2c->adapter);
	if (ret) {
		DRM_ERROR("Failed to register bit i2c\n");
		goto out_free;
	}

	return i2c;
out_free:
	kfree(i2c);
	return NULL;
}

static void mcst_i2c_destroy(struct mcst_i2c_chan *i2c)
{
CH();
	if (!i2c)
		return;
	i2c_del_adapter(&i2c->adapter);
	kfree(i2c);
}



void mcst_show_cursor(struct drm_crtc *crtc)
{
	struct mcst_private *mcst = crtc->dev->dev_private;
	struct mcst_crtc *mcst_crtc = to_mcst_crtc(crtc);
	int cell = mcst_crtc->cell;
CH();
	mcst_io_write32(mcst, cell, REG_CTRL,
			  mcst_io_read32(mcst, cell, REG_CTRL) | CTRL_HC0E);
}

void mcst_hide_cursor(struct drm_crtc *crtc)
{
	struct mcst_private *mcst = crtc->dev->dev_private;
	struct mcst_crtc *mcst_crtc = to_mcst_crtc(crtc);
	int cell = mcst_crtc->cell;
CH();
	mcst_io_write32(mcst, cell, REG_CTRL,
			  mcst_io_read32(mcst, cell, REG_CTRL) & ~CTRL_HC0E);
}

static int copy_cursor_image(u8 *src, int width, int height)
{
#if 0
	union {
		u32 ul;
		u8 b[4];
	} srcdata32[2], data32;
	union {
		u16 us;
		u8 b[2];
	} data16;
	s32 alpha_dst_delta, lmcst_alpha_dst_delta;
	u8 *srcxor, *dstxor;
	u32 per_pixel_copy, two_pixel_copy;
#endif
	int i, j;

CH();
	DRM_INFO("CURSOR: width=%d height=%d\n", width, height);
	for (j = 0; j < height; j++) {
		for (i = 0; i < width; i++) {
			DRM_INFO("cursor data(%d,%d)= %02x %02x %02x %02x\n",
				i, j, src[0], src[1], src[2], src[3]);
			src += 4;
		}
	}

#if 0
	alpha_dst_delta = mcst_MAX_HWC_WIDTH << 1;
	lmcst_alpha_dst_delta = alpha_dst_delta - (width << 1);

	srcxor = src;
	dstxor = (u8 *)dst + lmcst_alpha_dst_delta
		 + (mcst_MAX_HWC_HEIGHT - height) * alpha_dst_delta;
	per_pixel_copy = width & 1;
	two_pixel_copy = width >> 1;

	for (j = 0; j < height; j++) {
		for (i = 0; i < two_pixel_copy; i++) {
			srcdata32[0].ul = *((u32 *)srcxor) & 0xf0f0f0f0;
			srcdata32[1].ul = *((u32 *)(srcxor + 4)) & 0xf0f0f0f0;
			data32.b[0] = srcdata32[0].b[1]
				      | (srcdata32[0].b[0] >> 4);
			data32.b[1] = srcdata32[0].b[3]
				      | (srcdata32[0].b[2] >> 4);
			data32.b[2] = srcdata32[0].b[1]
				      | (srcdata32[1].b[0] >> 4);
			data32.b[3] = srcdata32[0].b[3]
				      | (srcdata32[1].b[2] >> 4);

			writel(data32.ul, dstxor);
			dstxor += 4;
			srcxor += 8;

		}

		for (i = 0; i < per_pixel_copy; i++) {
			srcdata32[0].ul = *((u32 *)srcxor) & 0xf0f0f0f0;
			data16.b[0] = srcdata32[0].b[1]
				      | (srcdata32[0].b[0] >> 4);
			data16.b[1] = srcdata32[0].b[3]
				      | (srcdata32[0].b[2] >> 4);
			writew(data16.us, dstxor);
			dstxor += 2;
			srcxor += 4;
		}
		dstxor += lmcst_alpha_dst_delta;
	}
#endif
	return 0;
}

static int mcst_cursor_set(struct drm_crtc *crtc,
			  struct drm_file *file_priv,
			  uint32_t handle,
			  uint32_t width,
			  uint32_t height)
{
/*	struct mcst_private *mcst = crtc->dev->dev_private; */
/*	struct mcst_crtc *mcst_crtc = to_mcst_crtc(crtc);   */
	struct drm_gem_object *obj;
	struct mcst_bo *bo;
/*	uint64_t gpu_addr; */
	int ret;
	struct ttm_bo_kmap_obj uobj_map;
	u8 *src;
	bool src_isiomem;

CH();
	if (!handle) {
		mcst_hide_cursor(crtc);
		return 0;
	}

	if (width > 64 /*mcst_MAX_HWC_WIDTH*/
	    || height > 64 /*mcst_MAX_HWC_HEIGHT*/)
		return -EINVAL;

	obj = drm_gem_object_lookup(crtc->dev, file_priv, handle);
	if (!obj) {
		DRM_ERROR("Cannot find cursor object %x for crtc\n", handle);
		return -ENOENT;
	}
	bo = gem_to_mcst_bo(obj);

	ret = mcst_bo_reserve(bo, false);
	if (ret)
		goto fail;

	ret = ttm_bo_kmap(&bo->bo, 0, bo->bo.num_pages, &uobj_map);

	src = ttm_kmap_obj_virtual(&uobj_map, &src_isiomem);

	if (src_isiomem == true)
		DRM_ERROR("src cursor bo should be in main memory\n");

	/* do data transfer to cursor table */
	copy_cursor_image(src, width, height);

	/* write checksum + signature */
	ttm_bo_kunmap(&uobj_map);
	mcst_bo_unreserve(bo);


	{
	}

	mcst_show_cursor(crtc);

	drm_gem_object_unreference_unlocked(obj);
	return 0;
fail:
	drm_gem_object_unreference_unlocked(obj);
	return ret;
}

static int mcst_cursor_move(struct drm_crtc *crtc,
			   int x, int y)
{
	struct mcst_private *mcst = crtc->dev->dev_private;
	struct mcst_crtc *mcst_crtc = to_mcst_crtc(crtc);
#if 0
	/* TODO: make fix for old firmware */
	if (mcst->firmware_version == 0) {
		if (x < 0) {
			x = 0;
		}

		if (y < 0) {
			y = 0;
		}
	}
#endif
	mcst_io_write32(mcst, mcst_crtc->cell, REG_C0XY,
			(y & 0xffff) << 16 | (x & 0xffff));
	return 0;
}
