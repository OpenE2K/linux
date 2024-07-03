/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#define	 MGA2_BB_SZ		0x400
/*
 *******************************************************************************
 * MMIO BitBlt Module Registers
 *******************************************************************************
 */
#define REG_BB_CTRL	0x1000	/* BitBlt module control register (write only) */
#define REG_BB_STAT	0x1000	/* BitBlt module status register (read only) */

#define REG_BB_WINDOW	0x1004	/* Operation geometry */
#define REG_BB_SADDR	0x1008	/* Source start address */
#define REG_BB_DADDR	0x100c	/* Destination start address */
#define REG_BB_PITCH	0x1010	/* */
#define REG_BB_BG	0x1014	/* Background color */
#define REG_BB_FG	0x1018	/* Foreground color */

/* BitBlt status register bits */
#define BB_STAT_PROCESS	(0x1<<31)	/* 1 - processing operation, 0 - idle */
#define BB_STAT_FULL	(0x1<<30)	/* 1 - pipeline full */
#define BB_STAT_DMA	(0x1<<26)	/* DMA support */

#define BB_CTRL_CMD_MASK	0xC0000000
#define BB_CTRL_CMD_START		(0x1<<31)
#define BB_CTRL_CMD_ABORT		(0x1<<30)


#define BB_CTRL_BITS_IN_BYTE_TWISTER	(0x1<<22)

#define BB_CTRL_DDMA_EN			(0x1<<21)
#define BB_CTRL_SDMA_EN			(0x1<<20)
#define BB_CTRL_SOFFS_MASK	(0x7<<16)

/* Binary raster operations */
#define BB_CTRL_ROP_MASK		0x0000F000

#define BB_CTRL_ROP_0			(0x0<<12)	/* clear */
#define BB_CTRL_ROP_AND			(0x1<<12)	/* and */
#define BB_CTRL_ROP_NOT_SRC_AND_DST	(0x2<<12)	/* andReverse */
#define BB_CTRL_ROP_DST			(0x3<<12)	/* copy */
#define BB_CTRL_ROP_SRC_AND_NOT_DST	(0x4<<12)	/* andInverted */
#define BB_CTRL_ROP_SRC			(0x5<<12)	/* noop */
#define BB_CTRL_ROP_XOR			(0x6<<12)	/* xor */
#define BB_CTRL_ROP_OR			(0x7<<12)	/* or */
#define BB_CTRL_ROP_NOR			(0x8<<12)	/* nor */
#define BB_CTRL_ROP_NXOR		(0x9<<12)	/* equiv */
#define BB_CTRL_ROP_NOT_SRC		(0xa<<12)	/* invert */
#define BB_CTRL_ROP_NOT_SRC_OR_DST	(0xb<<12)	/* orReverse */
#define BB_CTRL_ROP_NOT_DST		(0xc<<12)	/* copyInverted */
#define BB_CTRL_ROP_SRC_OR_NOT_DST	(0xd<<12)	/* orInverted */
#define BB_CTRL_ROP_NAND		(0xe<<12)	/* nand */
#define BB_CTRL_ROP_1			(0xf<<12)	/* set */

#define BB_CTRL_HDIR	(0x1<<5)
#define BB_CTRL_VDIR	(0x1<<6)

#define BB_CTRL_CE_EN		(0x1<<0)
#define BB_CTRL_PAT_EN		(0x1<<1)
#define BB_CTRL_SFILL_EN	(0x1<<2)
#define BB_CTRL_TR_EN		(0x1<<4)

#define BB_CTRL_SRC_MODE	(0x1<<7)

#define BB_CTRL_TERM_00		(0x0<<8)
#define BB_CTRL_TERM_01		(0x1<<8)
#define BB_CTRL_TERM_10		(0x2<<8)

#define BB_CTRL_BPP_8	        (0x0<<10)
#define BB_CTRL_BPP_16	        (0x1<<10)
#define BB_CTRL_BPP_24	        (0x2<<10)
#define BB_CTRL_BPP_32	        (0x3<<10)
#ifdef __BIG_ENDIAN
#define BB_CTRL_BPP_CD_8	(BB_CTRL_BPP_8)
#define BB_CTRL_BPP_CD_16	(BB_CTRL_BPP_16 | 0x0800000)
#define BB_CTRL_BPP_CD_24	(BB_CTRL_BPP_24 | 0x1800000)
#define BB_CTRL_BPP_CD_32	(BB_CTRL_BPP_32 | 0x1800000)
#elif defined(__LITTLE_ENDIAN)
#define BB_CTRL_BPP_CD_8	BB_CTRL_BPP_8
#define BB_CTRL_BPP_CD_16	BB_CTRL_BPP_16
#define BB_CTRL_BPP_CD_24	BB_CTRL_BPP_24
#define BB_CTRL_BPP_CD_32	BB_CTRL_BPP_32
#else
#error byte order not defined
#endif


#define MGA2_BB_R0	0x01000
#define MGA2_BB_R7	0x0101C	/* base registers of MGA-compatible blitter */
#define MGA2_BB_FMTCFG	0x01020	/* pixel format control for alpha-op */
#define MGA2_BB_ASRC	0x01024	/* Fs calculation */
#define MGA2_BB_ADST	0x01028	/* Fd calculation */
#define MGA2_BB_PALADDR	0x0102C	/* set LUT address (palette) for 1bpp/4bpp/8bpp formats */
#define MGA2_BB_PALDATA	0x01030	/* write data to LUT element (palette) for 1bpp/4bpp/8bpp formats */
#define REG_BB_SADDR64	0x01034	/* high part of 64-bit DMA address */
				/* in system memory for source channel */
#define REG_BB_DADDR64	0x01038	/* low part of 64-bit DMA address */
				/* in system memory for destination channel */


static bool mga25_drm_is_open(struct drm_device *dev)
{
	/*
	 * FIXME: open_count is protected by drm_global_mutex but that would lead
	 * to locking inversion with the driver load path. And the access here is
	 * completely racy anyway. So don't bother with locking for now.
	 */
	return atomic_read(&dev->open_count) != 0;
}

static u32 mga25_get_busy(struct mga2 *mga2)
{
	u32 busy = rfb(REG_BB_CTRL) & BB_STAT_PROCESS;
	if (busy)
		return busy;
	if (mga20(mga2->dev_id)) {
		busy = (rfb(MGA2_BCTRL_STATUS) & MGA2_BCTRL_B_BUSY) ||
		    (rfb(MGA2_SYSMUX_BITS) & MGA2_SYSMUX_BLT_WR_BUSY) ||
		    (rfb(MGA2_VIDMUX_BITS) & MGA2_VIDMUX_BLT_WR_BUSY);
	} else if (mga25(mga2->dev_id)) {
		busy = (rfb(MGA2_AUC2_CTRLSTAT) & MGA2_AUC2_B_BUSY) ||
			(rfb(REG_BB_CTRL + MGA2_BB_SZ) & BB_STAT_PROCESS) ||
			rfb(MGA25_SYSMUX_BITS) ||
			rfb(MGA25_VMMUX_BITS) ||
			(rfb(MGA2_BCTRL_STATUS) & MGA2_BCTRL_B_BUSY);
	}
	return busy;
}

static int ___mga25_sync(struct mga2 *mga2)
{
	int ret = 0, i;
	int timeout_usec = mga25_timeout(mga2) * 1000;
	if (mga25_nofbaccel)
		return 0;
	for (i = 0; i < timeout_usec; i++) {
		u32 busy = mga25_get_busy(mga2);

		if (!busy)
			break;
		udelay(1);
	}

	if (i == timeout_usec) {
		mga2->flags |= MGA2_BCTRL_OFF;
		mga25_nofbaccel = 1;
		DRM_ERROR("sync timeout\n");
		ret = -ETIME;
	}
	return ret;
}

static u64 mga25_get_current_desc(struct mga2 *mga2)
{
	if (mga25(mga2->dev_id))
		return auc2_get_current_desc(mga2);
	else
		return bctrl_get_current_desc(mga2);
}

int __mga25_sync(struct mga2 *mga2)
{
	long ret = 0, timeout = msecs_to_jiffies(mga25_timeout(mga2));
	int n = circ_dec(mga2->head);
	struct dma_fence *fence = mga2->mga25_fence[n];
	u64 current_desc = mga25_get_current_desc(mga2);
	if (mga2->flags & MGA2_BCTRL_OFF)
		goto cant_sleep;

	mga25_update_ptr(mga2);

	if (circ_idle(mga2))
		return 0;

	if (in_atomic() || in_dbg_master() || irqs_disabled())
		goto cant_sleep;

	while (0 == (ret = dma_fence_wait_timeout(fence, true, timeout))) {
		/* Timeout */
		u64 d = mga25_get_current_desc(mga2);
		if (d == current_desc) /* AUC's stuck */
			break;
		/* AUC is still working, let's wait. */
		current_desc = d;
	}
	if (ret == 0) {
		ret = -ETIMEDOUT;
		mga2->flags |= MGA2_BCTRL_OFF;
		mga25_nofbaccel = 1;
		dma_fence_signal(fence);
		DRM_ERROR("fence %d wait timed out.\n", n);
	} else if (ret < 0) {
		DRM_DEBUG("fence %d wait failed (%ld).\n", n, ret);
	} else {
		ret = 0;
	}
	return ret;
cant_sleep:
	return ___mga25_sync(mga2);
}

/*
 *	   fb_sync - NOT a required function. Normally the accel engine
 *		     for a graphics card take a specific amount of time.
 *		     Often we have to wait for the accelerator to finish
 *		     its operation before we can write to the framebuffer
 *		     so we can have consistent display output.
 *
 *      @info: frame buffer structure that represents a single frame buffer
 *
 *      If the driver has implemented its own hardware-based drawing function,
 *      implementing this function is highly recommended.
 */

static int mga25_sync(struct fb_info *info)
{
	struct mga25_fbdev *fb = info->par;
	struct mga2 *mga2 = fb->helper.dev->dev_private;
	if (!mga25_drm_is_open(mga2->drm))
		return __mga25_sync(mga2);
	return 0;
}

struct mga25_fence {
	struct dma_fence base;
	struct mga2 *mga2;
};

static inline struct mga25_fence *to_mga2_fence(struct dma_fence *f)
{
	return container_of(f, struct mga25_fence, base);
}

static inline struct mga2 *fence_to_mga2(struct dma_fence *f)
{
	return to_mga2_fence(f)->mga2;
}

/*
 * Common fence implementation
 */

static const char *mga25_fence_get_driver_name(struct dma_fence *fence)
{
	return "mga2";
}

static const char *mga25_fence_get_timeline_name(struct dma_fence *f)
{
	return "mga2-auc";
}

/**
 * mga25_irq_sw_irq_get - enable software interrupt
 *
 * @mga2: mga2 device pointer
 *
 * Enables the software interrupt for the ring.
 * The software interrupt is used to signal a fence on
 * the ring.
 */
static void mga25_irq_sw_irq_get(struct mga2 *mga2)
{
	if (atomic_inc_return(&mga2->ring_int) == 1)
		enable_irq(mga2->irq);
}

/**
 * mga25_irq_sw_irq_put - disable software interrupt
 *
 * @mga2: mga2 device pointer
 *
 * Disables the software interrupt for the ring.
 * The software interrupt is used to signal a fence on
 * the ring.
 */
static void mga25_irq_sw_irq_put(struct mga2 *mga2)
{
	if (atomic_dec_and_test(&mga2->ring_int))
		disable_irq_nosync(mga2->irq);
}


#define MGA2_FENCE_IRQ_EN	DMA_FENCE_FLAG_USER_BITS

/**
 * mga25_fence_enable_signaling - enable signalling on fence
 * @fence: fence
 *
 * This function is called with fence_queue lock held, and adds a callback
 * to fence_queue that checks if this fence is signaled, and if so it
 * signals the fence and removes itself.
 */
static bool mga25_fence_enable_signaling(struct dma_fence *f)
{
	struct mga2 *mga2 = fence_to_mga2(f);
	set_bit(MGA2_FENCE_IRQ_EN, &f->flags);
	mga25_irq_sw_irq_get(mga2);
	DMA_FENCE_TRACE(f, "armed on ring!\n");

	return true;
}

/**
 * mga25_fence_release - callback that fence can be freed
 *
 * @fence: fence
 *
 * This function is called when the reference count becomes zero.
 */
static void mga25_fence_release(struct dma_fence *f)
{
	kfree(to_mga2_fence(f));
}

static const struct dma_fence_ops mga25_fence_ops = {
//FIXME:	.use_64bit_seqno = true,
	.get_driver_name = mga25_fence_get_driver_name,
	.get_timeline_name = mga25_fence_get_timeline_name,
	.enable_signaling = mga25_fence_enable_signaling,
	.release = mga25_fence_release,
};


static void __mga25_update_ptr(struct mga2 *mga2)
{
	if (mga25(mga2->dev_id) && !mga2->bctrl_active)
		auc2_update_ptr(mga2);
	else
		bctrl_update_ptr(mga2);
}

void mga25_update_ptr(struct mga2 *mga2)
{
	int h, t;
	unsigned long flags;
	spin_lock_irqsave(&mga2->fence_lock, flags);
	h = mga2->tail;
	__mga25_update_ptr(mga2);
	t = circ_inc(mga2->tail);

	for (; __circ_space(h, t); h = circ_inc(h)) {
		struct dma_fence *f = mga2->mga25_fence[h];
		if (test_and_clear_bit(MGA2_FENCE_IRQ_EN, &f->flags))
			mga25_irq_sw_irq_put(mga2);
		dma_fence_signal_locked(f);
	}
	spin_unlock_irqrestore(&mga2->fence_lock, flags);
}

static int wait_for_ring(struct mga2 *mga2)
{
	struct dma_fence *fence;
	long ret = 0;
	int n, timeout = msecs_to_jiffies(mga25_timeout(mga2));

	mga25_update_ptr(mga2);
	if (circ_space(mga2))
		return 0;

	if (in_atomic() || in_dbg_master() || irqs_disabled()) {
		ret = ___mga25_sync(mga2);
		if (ret)
			return ret;
		mga25_update_ptr(mga2);
		if (!circ_space(mga2))
			return -ENOSPC;
	}
	n = mga2->tail;
	fence = mga2->mga25_fence[n];
	ret = dma_fence_wait_timeout(fence, true, timeout);
	if (ret == 0) {
		ret = -ETIMEDOUT;
		mga2->flags |= MGA2_BCTRL_OFF;
		dma_fence_signal(fence);
		DRM_ERROR("fence %d wait timed out.\n", n);
	} else if (ret < 0) {
		DRM_DEBUG("fence %d wait failed (%ld).\n", n, ret);
	} else {
		ret = 0;
	}

	return ret;
}

static int __get_free_desc(struct mga2 *mga2)
{
	int ret, h;
	unsigned seqno;
	struct mga25_fence *fence;
	struct dma_fence *f, *old;
	if (!circ_space(mga2)) {
		if ((ret = wait_for_ring(mga2)))
			return ret;
	}
	h = mga2->head;
	/* Can not freely reuse mga25_fence memory:
	 * the lifetime of the fence depends on a dma_resv it was added to,
	 * so we have to use alloc/dma_fence_put/free mechanism */
	fence = kzalloc(sizeof(*fence), GFP_KERNEL);
	if (!fence)
		return -ENOMEM;
	fence->mga2 = mga2;
	f = &fence->base;
	seqno = mga2->fence_seqno;
	BUG_ON(h != seqno % MGA2_RING_SIZE);
	dma_fence_init(f, &mga25_fence_ops, &mga2->fence_lock, 0, seqno);

	old = mga2->mga25_fence[h];
	mga2->mga25_fence[h] = f;
	dma_fence_put(old);

	if (mga25(mga2->dev_id)) {
		struct desc1 *c = &mga2->desc1[h];
		memset(c, 0, sizeof(*c));
	}
	return h;
}

static int get_free_desc(struct mga2 *mga2)
{
	if (mga2->flags & MGA2_BCTRL_OFF) {
		__mga25_sync(mga2);
		return 0;
	}
	return __get_free_desc(mga2);
}

static int append_desc(struct mga2 *mga2, struct mga25_gem_object *mo)
{
	if (mga2->flags & MGA2_BCTRL_OFF)
		return 0;
	if (mga25(mga2->dev_id) && mga2->bctrl_active) {
		mga25_update_ptr(mga2);
		mga2->bctrl_active = false;
	}

	if (mga25(mga2->dev_id))
		return auc2_append_desc(mga2, mo);

	bctrl_append_desc(mga2, mo);

	return 0;
}

#define wdesc(__cmd, __data, __reg, __first, __last)	do {	\
	if (mga2->flags & MGA2_BCTRL_OFF) {			\
		wfb(__data, __reg);				\
		break;						\
	}							\
	mga25(mga2->dev_id) ? auc2_wdesc(mga2, __data, __reg) :	\
		      bctrl_wdesc(mga2, __cmd, __data, __reg, __first, __last); \
} while(0)

static void mga25_color_blit(int width, int height, int pitch, int dest,
			    int rop, int color, int Bpp, struct mga2 *mga2)
{
	int head = get_free_desc(mga2);
	u32 ctrl = rop | BB_CTRL_CE_EN | BB_CTRL_SFILL_EN | BB_CTRL_CMD_START
	    | (((Bpp - 1) & 0x3) << 10);
	if (head < 0)
		return;

	wdesc(0, color, REG_BB_FG, 1, 0);
	wdesc(1, (height << 16) | (width * Bpp), REG_BB_WINDOW, 0, 0);
	wdesc(2, dest, REG_BB_DADDR, 0, 0);
	wdesc(3, 0, REG_BB_DADDR64, 0, 0);
	wdesc(4, pitch << 16 | 0, REG_BB_PITCH, 0, 0);
	wdesc(5, 0, MGA2_BB_FMTCFG, 0, 0);
	wdesc(6, ctrl, REG_BB_CTRL, 0, 1);

	append_desc(mga2, NULL);
}

void mga25_fillrect(struct fb_info *info, const struct fb_fillrect *rect)
{
	struct mga25_fbdev *fbdev = info->par;
	struct mga2 *mga2 = fbdev->helper.dev->dev_private;
	struct mga25_framebuffer *fb = to_mga25_framebuffer(fbdev->helper.fb);
	struct mga25_gem_object *mo = to_mga25_obj(fb->gobj);
	u32 dx, dy, width, height, dest, rop = 0, color = 0;
	u32 Bpp = info->var.bits_per_pixel >> 3;

	if (mga25_drm_is_open(mga2->drm) || mga25_nofbaccel == 1 ||
		 info->flags & FBINFO_HWACCEL_DISABLED ||
		!(info->flags & FBINFO_HWACCEL_FILLRECT)) {
		if (mga25_has_vram(mga2->dev_id) || mga25_use_uncached(mga2->dev_id))
			cfb_fillrect(info, rect);
		else
			sys_fillrect(info, rect);
		return;
	}

	if (Bpp == 1)
		color = rect->color;
	else
		color = ((u32 *) (info->pseudo_palette))[rect->color];

	rop = (rect->rop != ROP_COPY) ? BB_CTRL_ROP_XOR : BB_CTRL_ROP_SRC;

	dx = rect->dx * Bpp;
	width = rect->width;
	dy = rect->dy;
	height = rect->height;

	dest = mo->dma_addr + (dy * info->fix.line_length) + dx;
	mga25_color_blit(width, height, info->fix.line_length, dest, rop, color,
			Bpp, mga2);
}

static void mga25_hw_copyarea(struct mga2 *mga2, unsigned sBase,	/* Address of source: offset in frame buffer */
			     unsigned sPitch,	/* Pitch value of source surface in BYTE */
			     unsigned sx, unsigned sy,	/* Starting coordinate of source surface */
			     unsigned dBase,	/* Address of destination: offset in frame buffer */
			     unsigned dPitch,	/* Pitch value of destination surface in BYTE */
			     unsigned Bpp,	/* Color depth of destination surface */
			     unsigned dx, unsigned dy,	/* Starting coordinate of destination surface */
			     unsigned width, unsigned height	/* width and height of rectangle in pixel value */
    )
{
	int head = get_free_desc(mga2);
	unsigned saddr, daddr;
	unsigned ctrl = BB_CTRL_ROP_SRC | BB_CTRL_CMD_START;

	if (head < 0)
		return;

	saddr = sBase + sy * dPitch + sx * Bpp;
	daddr = dBase + dy * dPitch + dx * Bpp;

	wdesc(0, (height << 16) | (width * Bpp), REG_BB_WINDOW, 1, 0);
	wdesc(1, saddr, REG_BB_SADDR,   0, 0);
	wdesc(2,     0, REG_BB_SADDR64, 0, 0);
	wdesc(3, daddr, REG_BB_DADDR,   0, 0);
	wdesc(4,     0, REG_BB_DADDR64, 0, 0);
	wdesc(5, sPitch << 16 | sPitch, REG_BB_PITCH, 0, 0);
	wdesc(6, 0, MGA2_BB_FMTCFG, 0, 0);
	wdesc(7, ctrl, REG_BB_CTRL, 0, 1);

	append_desc(mga2, NULL);
}

static void mga25_copyarea(struct fb_info *info, const struct fb_copyarea *area)
{
	struct mga25_fbdev *fbdev = info->par;
	struct mga2 *mga2 = fbdev->helper.dev->dev_private;
	struct mga25_framebuffer *fb = to_mga25_framebuffer(fbdev->helper.fb);
	struct mga25_gem_object *mo = to_mga25_obj(fb->gobj);
	unsigned base, pitch, Bpp;

	if (mga25_drm_is_open(mga2->drm) || mga25_nofbaccel == 1 ||
			 info->flags & FBINFO_HWACCEL_DISABLED ||
			!(info->flags & FBINFO_HWACCEL_COPYAREA)) {
		if (mga25_has_vram(mga2->dev_id) || mga25_use_uncached(mga2->dev_id))
			cfb_copyarea(info, area);
		else
			sys_copyarea(info, area);
		return;
	}

	base = mo->dma_addr;
	pitch = info->fix.line_length;
	Bpp = info->var.bits_per_pixel >> 3;

	mga25_hw_copyarea(mga2, base, pitch, area->sx, area->sy,
			 base, pitch, Bpp, area->dx, area->dy,
			 area->width, area->height);
}

static void mga25_imageblit(struct fb_info *info, const struct fb_image *image)
{
	struct mga25_fbdev *fbdev = info->par;
	struct mga2 *mga2 = fbdev->helper.dev->dev_private;
	/* We can not use hw imageblit here, as preemption is disabled
	 * and we can not wait for the dma-operation to complete */
	if (mga25_has_vram(mga2->dev_id) || mga25_use_uncached(mga2->dev_id))
		cfb_imageblit(info, image);
	else
		sys_imageblit(info, image);
}

static void mga25_fb_writel(struct mga2 *mga2,
			    u32 value, void *addr)
{
	if (mga25_has_vram(mga2->dev_id) || mga25_use_uncached(mga2->dev_id))
		writel(value, addr);
	else
		*(u32 *)addr = value;
}

static void mga25_load_mono_to_argb_cursor(struct mga2 *mga2, u32 *dst1,
			const void *data8, u32 bg, u32 fg, u32 w, u32 h)
{
	int i, j;
	const int spitch = DIV_ROUND_UP(w, 8), dpitch = MGA2_MAX_HWC_WIDTH;
	const u8 *s = data8, *src;

	for (i = 0; i < h; i++, dst1 += dpitch, s += spitch) {
		u32 *dst = dst1;
		int shift;

		for (j = 0, shift = 7, src = s; j < w; j++, dst++, shift--) {
			u32 p = *src & (1 << shift) ? fg : bg;
			mga25_fb_writel(mga2, p, dst);
			if (!shift) {
				shift = 7;
				src++;
			}
		}
	}
}

static int mga25_cursor_load(struct drm_crtc *crtc, struct fb_info *info,
			    struct fb_cursor *c)
{
	struct mga25_crtc *mga25_crtc = to_mga25_crtc(crtc);
	struct mga25_fbdev *fb = info->par;
	struct mga2 *mga2 = fb->helper.dev->dev_private;
	struct fb_image *image = &c->image;
	u32 s_pitch = (c->image.width + 7) >> 3;
	unsigned i, dsize;
	u8 *src;
	u32 bg_idx = image->bg_color;
	u32 fg_idx = image->fg_color;
	u32 fg, bg;
	void *dst = mga25_crtc->cursor_addr;
	s_pitch = (c->image.width + 7) >> 3;
	dsize = s_pitch * image->height;

	src = kmalloc(dsize, GFP_ATOMIC);
	if (!src) {
		return -ENOMEM;
	}

	switch (c->rop) {
	case ROP_XOR:
		for (i = 0; i < dsize; i++) {
			src[i] = image->data[i] ^ c->mask[i];
		}
		break;
	case ROP_COPY:
	default:
		for (i = 0; i < dsize; i++) {
			src[i] = image->data[i] & c->mask[i];
		}
		break;
	}

	fg = ((info->cmap.red[fg_idx] & 0xff) << 0) |
	    ((info->cmap.green[fg_idx] & 0xff) << 8) |
	    ((info->cmap.blue[fg_idx] & 0xff) << 16) | (0xff << 24);

	bg = ((info->cmap.red[bg_idx] & 0xff) << 0) |
	    ((info->cmap.green[bg_idx] & 0xff) << 8) |
	    ((info->cmap.blue[bg_idx] & 0xff) << 16);

	mga25_load_mono_to_argb_cursor(mga2, dst, c->mask, bg, fg, image->width,
				      image->height);
	kfree(src);
	return 0;
}

static int __mga25_fb_cursor(struct drm_crtc *crtc, struct fb_info *info,
			    struct fb_cursor *cursor)
{
	struct mga25_crtc *mga25_crtc = to_mga25_crtc(crtc);
	struct mga2 *mga2 = mga25_crtc->base.dev->dev_private;
	int set = cursor->set;

	mga25_cursor_hide(crtc);

	if (set & FB_CUR_SETPOS) {
		mga25_cursor_move(crtc, cursor->image.dx - info->var.xoffset,
				 cursor->image.dy - info->var.yoffset);
	}

	if (set & FB_CUR_SETSIZE) {
		if (mga25_has_vram(mga2->dev_id) || mga25_use_uncached(mga2->dev_id))
			memset_io(mga25_crtc->cursor_addr, 0, MGA2_HWC_SIZE);
		else
			memset(mga25_crtc->cursor_addr, 0, MGA2_HWC_SIZE);

	}

	if (set & (FB_CUR_SETSHAPE | FB_CUR_SETCMAP | FB_CUR_SETIMAGE))
		mga25_cursor_load(crtc, info, cursor);

	if (cursor->enable)
		mga25_cursor_show(crtc, mga25_crtc->cursor_offset);

	return 0;
}

static int mga25_fb_cursor(struct fb_info *info, struct fb_cursor *cursor)
{
	struct mga25_fbdev *fb = info->par;
	struct drm_client_dev *client = &fb->helper.client;
	struct drm_mode_set *mode_set;

	if (cursor->image.width > MGA2_MAX_HWC_WIDTH
	    || cursor->image.height > MGA2_MAX_HWC_HEIGHT)
		return -EINVAL;

	mutex_lock(&client->modeset_mutex);

	drm_client_for_each_modeset(mode_set, client) {
		struct drm_crtc *crtc = mode_set->crtc;
		__mga25_fb_cursor(crtc, info, cursor);
	}

	mutex_unlock(&client->modeset_mutex);

	return 0;
}

static int mga25_fb_mmap(struct fb_info *info, struct vm_area_struct *vma)
{
	struct mga25_fbdev *fbdev = info->par;
	struct mga2 *mga2 = fbdev->helper.dev->dev_private;
	struct mga25_framebuffer *fb = to_mga25_framebuffer(fbdev->helper.fb);
	struct mga25_gem_object *mo = to_mga25_obj(fb->gobj);
	unsigned long vm_size;
	int ret;

	vma->vm_flags |= VM_IO | VM_DONTEXPAND | VM_DONTDUMP;

	vm_size = vma->vm_end - vma->vm_start;

	if (vm_size > mo->base.size)
		return -EINVAL;

	if (mga25_has_vram(mga2->dev_id) || mga25_use_uncached(mga2->dev_id)) {
		phys_addr_t start = mo->node.start;
		vma->vm_page_prot = ttm_io_prot(TTM_PL_FLAG_WC,
					vma->vm_page_prot);
		if (mga25_use_uncached(mga2->dev_id)) {
			start = (phys_addr_t)mo->vaddr;
			WARN(!IS_ENABLED(CONFIG_E90S), "FIXME:start\n");
		}
		ret = vm_iomap_memory(vma, start, vm_size);
	} else {
		ret = dma_mmap_coherent(mga2->drm->dev, vma, mo->vaddr,
					mo->dma_addr, vm_size);
	}

	return ret;
}

static int mga25_fb_set_par(struct fb_info *info)
{
	struct mga25_fbdev *fbdev = info->par;
	struct mga2 *mga2 = fbdev->helper.dev->dev_private;
	struct device *dev = mga2->drm->dev;

	if (fbdev->pixmap_dma == 0 &&
			/* if swiotlb is running */
			/* don't try to map 64-bit address */
#if defined(CONFIG_E2K) && defined(CONFIG_NUMA)
			!(swiotlb_max_segment(swiotlb_node(dev)) &&
#else
			!(swiotlb_max_segment() &&
#endif
			(virt_to_phys(info->pixmap.addr) & (-1LL << 32)))) {
		dma_addr_t dma;

		dma = dma_map_single(dev, info->pixmap.addr, info->pixmap.size, DMA_TO_DEVICE);
		if (!dma_mapping_error(dev, dma))
			fbdev->pixmap_dma = dma;
	}

	return drm_fb_helper_set_par(info);
}

static struct fb_ops mga2fb_ops = {
	.owner = THIS_MODULE,
	DRM_FB_HELPER_DEFAULT_OPS,
	.fb_set_par  = mga25_fb_set_par,
	.fb_fillrect = mga25_fillrect,
	.fb_copyarea  = mga25_copyarea,
	.fb_imageblit = mga25_imageblit,
	.fb_cursor    = mga25_fb_cursor,
	.fb_sync      = mga25_sync,
	.fb_mmap      = mga25_fb_mmap,
};
