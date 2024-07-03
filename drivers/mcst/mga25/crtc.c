/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#define DEBUG

#include "drv.h"

#define	 MGA2_DC0_CTRL		0x00000
#define MGA2_DC_B_NO_FETCH	(1 << 16)
#define MGA2_DC_CTRL_NATIVEMODE        (1 << 0)
#define MGA2_DC_CTRL_DIS_VGAREGS       (1 << 1)
#define MGA2_DC_CTRL_LINEARMODE        (1 << 2)
#define MGA2_DC_CTRL_NOSCRRFRSH        (1 << 16)
#define MGA2_DC_CTRL_SOFT_RESET        (1 << 31)
#define MGA2_DC_CTRL_DEFAULT	(MGA2_DC_CTRL_NATIVEMODE | MGA2_DC_CTRL_DIS_VGAREGS)

#define	 MGA2_DC0_VGAWINOFFS		0x00004
#define	 MGA2_DC0_VGABASE		0x00008
#define	 MGA2_DC0_VGAREGS		0x0000C
#define	 MGA2_DC0_TMPADDR		0x00010

#define	 MGA2_DC0_PIXFMT		0x00020
#define MGA2_DC_B_EXT_TXT		(1 << 31)
#define MGA2_DC_B_BGR			(0x24 << 4)
#define MGA2_DC_B_RGB			(0x06 << 4)


#define MGA26_DC_B_RGB16		(0 << 4)
#define MGA26_DC_B_BGR16		(1 << 4)
#define MGA26_DC_B_RGB16_SWAP_BYTES	(2 << 4)
#define MGA26_DC_B_BGR16_SWAP_BYTES	(4 << 4)

#define MGA2_DC_B_XRGB_FMT		(0 << 2)
#define MGA2_DC_B_RGBX_FMT		(2 << 2)

#define MGA2_DC_B_1555_FMT		(0 << 2)
#define MGA2_DC_B_565_FMT		(1 << 2)
#define MGA2_DC_B_4444_FMT		(2 << 2)

#define MGA2_DC_B_8BPP			0
#define MGA2_DC_B_16BPP			1
#define MGA2_DC_B_24BPP			2
#define MGA2_DC_B_32BPP			3

#define	 MGA2_DC0_WSTART	0x00030
#define	 MGA2_DC0_WOFFS		0x00034
#define	 MGA2_DC0_WCRSADDR	0x00038
#define	 MGA2_DC0_WCRSCOORD	0x0003C
#define	 MGA2_DC0_WPALID	0x00040
#define	 MGA2_DC0_NSTART	0x00050
#define	 MGA2_DC0_NOFFS		0x00054

#define	 MGA2_DC0_NCRSADDR	0x00058
#define	 MGA2_DC_B_CRS_ENA	(1 << 0)

#define	 MGA2_DC0_NCRSCOORD	0x0005C
#define	 MGA2_DC0_NPALID	0x00060
#define	 MGA2_DC0_DISPCTRL	0x00064
#define MGA2_DC_B_STROB        (1 << 31)

#define	 MGA2_DC0_HVCTRL	0x00070

#define MGA2_DC_B_CSYNC_MODE    (1 << 16)
#define MGA2_DC_B_HSYNC_ENA     (1 << 11)
#define MGA2_DC_B_VSYNC_ENA     (1 << 10)
#define MGA2_DC_B_CSYNC_ENA     (1 << 9)
#define MGA2_DC_B_DE_ENA        (1 << 8)
#define MGA2_DC_B_HSYNC_POL     (1 << 3)
#define MGA2_DC_B_VSYNC_POL     (1 << 2)
#define MGA2_DC_B_CSYNC_POL     (1 << 1)
#define MGA2_DC_B_DE_POL        (1 << 0)

#define	 MGA2_DC0_HSYNC		0x00074
#define	 MGA2_DC0_HDELAY	0x00078
#define	 MGA2_DC0_HVIS		0x0007C
#define	 MGA2_DC0_HTOT		0x00080
#define	 MGA2_DC0_VSYNC		0x00084
#define	 MGA2_DC0_VDELAY	0x00088
#define	 MGA2_DC0_VVIS		0x0008C
#define	 MGA2_DC0_VTOT		0x00090
#define	 MGA2_DC0_HCOUNT	0x00094
#define	 MGA2_DC0_VCOUNT	0x00098
#define	 MGA2_DC0_PALADDR	0x000A0

#define	 MGA2_DC_B_AUTOINC       (1 << 31)

#define	 MGA2_DC0_PALDATA	0x000A4
#define	 MGA2_DC0_GAMCTRL	0x000A8
#define MGA2_DC_GAMCTRL_ENABLE	(1 << 31)

#define MGA2_DC0_GAMSET		0x000AC
#define MGA2_DC_GAMSET_SEL_BLUE        (1 << 8)
#define MGA2_DC_GAMSET_SEL_GREEN       (1 << 9)
#define MGA2_DC_GAMSET_SEL_RED         (1 << 10)
#define MGA2_DC_GAMSET_SEL_ALL         (7 << 8)
#define MGA2_DC_GAMSET_ADDR_OFFSET     16

#define	 MGA2_DC0_DITCTRL		0x000B0
#define MGA2_DC_DITCTRL_ENABLE         (1 << 31)
#define MGA2_DC_DITCTRL_DISABLE        (0 << 31)

#define	 MGA2_DC0_DITSET0		0x000B4
#define	 MGA2_DC0_DITSET1		0x000B8


#define	MGA2_DC0_GPIO_MUX		0x00120
#define MGA2_DC_B_GPIOMUX_CS1		(1 << 1)
#define MGA2_DC_B_GPIOMUX_CS0		(1 << 0)
#define	MGA2_DC0_GPIO_MUXSETRST		0x00124
#define	 MGA2_DC0_GPIO_PUP		0x00128
#define	 MGA2_DC0_GPIO_PUPSETRST	0x0092C
#define	 MGA2_DC0_GPIO_DIR		0x00130
#define	 MGA2_DC0_GPIO_DIRSETRST	0x00934
#define	 MGA2_DC0_GPIO_OUT		0x00138
#define	 MGA2_DC0_GPIO_OUTSETRST	0x0093C
#define	 MGA2_DC0_GPIO_IN		0x00140


#define MGA2_DC0_OVL_CTRL       (0x60 * 4)
# define MGA2_DC0_OVL_UPD_BUSY  (1 << 31)
# define MGA2_DC0_OVL_ENABLE    (1 << 0)
# define MGA2_DC0_OVL_ALPHA_SHIFT    8
#define MGA2_DC0_OVL_XY         (0x61 * 4)
#define MGA2_DC0_OVL_KEY_MIN    (0x62 * 4)
#define MGA2_DC0_OVL_KEY_MAX    (0x63 * 4)
#define MGA2_DC0_OVL_BASE0      (0x64 * 4)
#define MGA2_DC0_OVL_BASE1      (0x65 * 4)
#define MGA2_DC0_OVL_BASE2      (0x66 * 4)
#define MGA2_DC0_OVL_STRIDE0    (0x67 * 4)
#define MGA2_DC0_OVL_STRIDE1    (0x68 * 4)
#define MGA2_DC0_OVL_STRIDE2    (0x69 * 4)
#define MGA2_DC0_OVL_GEOMETRY   (0x6A * 4)
#define MGA2_DC0_OVL_MODE       (0x6B * 4)
# define  MGA2_DC_B_MODE_RGB		0x00
# define  MGA2_DC_B_MODE_ARGB		0x08
# define  MGA2_DC_B_MODE_YUYV		0x10
# define  MGA2_DC_B_MODE_AYUV		0X0C
# define  MGA2_DC_B_MODE_YUV		0X04
# define  MGA2_DC_B_MODE_NV12		0x42
# define  MGA2_DC_B_MODE_NV21		0x43
# define  MGA2_DC_B_MODE_NV16		0x40
# define  MGA2_DC_B_MODE_NV61		0x41
# define  MGA2_DC_B_MODE_NV24		0x44
# define  MGA2_DC_B_MODE_NV42		0x45
# define  MGA2_DC_B_MODE_YUV420		0x22
# define  MGA2_DC_B_MODE_YUV422		0x20
# define  MGA2_DC_B_MODE_YUV444		0x24
# define  MGA2_DC_B_MODE_ENDIAN_SHIFT	8
# define MGA_MODE_ENDIAN(_a, _b, _c, _d) (( \
	(((_a)&3) << 6) | (((_b)&3) << 4) | \
	(((_c)&3) << 2) | (((_d)&3) << 0))  \
	    << MGA2_DC_B_MODE_ENDIAN_SHIFT)

# define MGA2_DC0_MODE_ODD_H_PXL   (1 << 24)
# define MGA2_DC0_MODE_ODD_V_PXL   (1 << 25)

#define MGA2_DC0_ZOOM_DSTGEOM   (0x6C * 4)
#define MGA2_DC0_ZOOM_SRCGEOM   (0x6D * 4)
#define MGA2_DC0_ZOOM_HPITCH    (0x6E * 4)
#define MGA2_DC0_ZOOM_VPITCH    (0x6F * 4)
#define MGA2_DC0_ZOOM_IHVSUM    (0x70 * 4)
#define MGA2_DC0_ZOOM_CTRL      (0x71 * 4)
#define MGA2_DC0_ZOOM_FTAP0     (0x72 * 4)
#define MGA2_DC0_ZOOM_FTAP1     (0x73 * 4)
#define MGA2_DC0_ZOOM_FTAP2     (0x74 * 4)
#define MGA2_DC0_ZOOM_FTAP3     (0x75 * 4)
#define MGA2_DC0_ZOOM_FTAP4     (0x76 * 4)
#define MGA2_DC0_ZOOM_FWRITE    (0x77 * 4)
# define MGA2_DC0_ZOOM_COORD_SHIFT	4

#define MGA2_DC0_Y2R_YPRE       (0x78 * 4)
#define MGA2_DC0_Y2R_UPRE       (0x79 * 4)
#define MGA2_DC0_Y2R_VPRE       (0x7A * 4)
#define MGA2_DC0_Y2R_MATRIX     (0x7B * 4)
#define MGA2_DC0_Y2R_RSH        (0x7C * 4)
#define MGA2_DC0_Y2R_GSH        (0x7D * 4)
#define MGA2_DC0_Y2R_BSH        (0x7E * 4)


#define __rcrtc(__offset)	 ({			\
	unsigned __v = 0;				\
	__v = readl(mcrtc->regs + MGA2_DC0_ ## __offset); \
	__v;				\
})
#define __wcrtc(__val, __offset)	do {			\
	writel(__val, mcrtc->regs + MGA2_DC0_ ## __offset); \
} while (0)

#ifdef DEBUG
#define rcrtc(__offset)						\
({								\
	unsigned __val = __rcrtc(__offset);			\
	DRM_DEBUG_KMS("R: %x: %s\n", __val, # __offset);	\
	__val;							\
})

#define wcrtc(__val, __offset) do {				\
	unsigned __val2 = __val;				\
	unsigned __o = MGA2_DC0_ ## __offset;	\
	DRM_DEV_DEBUG_KMS(mcrtc->dev, "W:%x:%x: %s\n", __o, __val2, # __offset);	\
	__wcrtc(__val2, __offset);				\
} while(0)

#else
#define		rcrtc		__rcrtc
#define		wcrtc		__wcrtc
#endif

#define __swab24(x)	\
({	\
	__u32 __x = (x);	\
	((__u32)(	\
		((__x & (__u32)0x000000ffUL) << 16)	|	\
		(__x & (__u32)0x0000ff00UL)			|	\
		((__x & (__u32)0x00ff0000UL) >> 16)));	\
})

#if (defined(__KERNEL__) && defined(__LITTLE_ENDIAN)) || \
	(defined(__BYTE_ORDER) && (__BYTE_ORDER == __LITTLE_ENDIAN))
	#define cpu_to_le24(x) ((__u32)(x))
	#define le24_to_cpu(x) ((__u32)(x))
#else
	#define cpu_to_le24(x) __swab24(x)
	#define le24_to_cpu(x) __swab24(x)
#endif

#include "layer.c"

#define MGA2_GAMMA_SIZE	256


static int mga25_cursor_init(struct drm_crtc *crtc);
static void mga25_cursor_fini(struct drm_crtc *crtc);


void mga25_cursor_show(struct drm_crtc *crtc, u32 addr)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	__wcrtc(addr | MGA2_DC_B_CRS_ENA, NCRSADDR);
	__wcrtc(MGA2_DC_B_STROB, DISPCTRL);
}

void mga25_cursor_hide(struct drm_crtc *crtc)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	__wcrtc(0, NCRSADDR);
	__wcrtc(MGA2_DC_B_STROB, DISPCTRL);
}

int mga25_cursor_move(struct drm_crtc *crtc, int x, int y)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	__wcrtc((x << 16) | (y & 0xffff), NCRSCOORD);
	__wcrtc(MGA2_DC_B_STROB, DISPCTRL);
	return 0;
}

static int mga25_cursor_init(struct drm_crtc *crtc)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	struct drm_gem_object *gobj =
	    mga25_gem_create(crtc->dev, MGA2_HWC_SIZE, MGA2_GEM_DOMAIN_VRAM);

	if (IS_ERR(gobj))
		return PTR_ERR(gobj);

	mcrtc->cursor_bo = gobj;
	mcrtc->cursor_offset = to_mga25_obj(gobj)->dma_addr;
	mcrtc->cursor_addr = to_mga25_obj(gobj)->vaddr;
	DRM_DEBUG_KMS("pinned cursor cache at %llx\n",
		      mcrtc->cursor_offset);
	return 0;
}

static void mga25_cursor_fini(struct drm_crtc *crtc)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	drm_gem_object_put(mcrtc->cursor_bo);
}

static int mga25_crtc_mode_set(struct drm_crtc *crtc,
					struct drm_display_mode *mode)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	uint32_t hvctrl;
	int ret = 0;
	struct videomode v, *vm = &v;
	/* The Horizontal Syncronization Time (Sync Pulse) */
	int hsync = mode->hsync_end - mode->hsync_start;

	/* The Horizontal Gate Delay Time (Back Porch) */
	int hgdel = mode->htotal - mode->hsync_end;

	/* The Horizontal Gate Time (Active Time) */
	int hgate = mode->hdisplay;

	/* The Horizontal Length Time (Line Total) */
	int hlen = mode->htotal;

	/* The Vertical Syncronization Time (Sync Pulse) */
	int vsync = mode->vsync_end - mode->vsync_start;

	/* The Vertical Gate Delay Time (Back Porch) */
	int vgdel = mode->vtotal - mode->vsync_end;

	/* The Vertical Gate Time (Active Time) */
	int vgate = mode->vdisplay;

	/* The Vertical Length Time (Frame total) */
	int vlen = mode->vtotal;

	wcrtc(hsync, HSYNC);
	wcrtc(hgdel, HDELAY);
	wcrtc(hgate, HVIS);
	wcrtc(hlen, HTOT);
	wcrtc(vsync, VSYNC);
	wcrtc(vgdel, VDELAY);
	wcrtc(vgate, VVIS);
	wcrtc(vlen, VTOT);


	hvctrl = MGA2_DC_B_DE_ENA;

	if (mode->flags & DRM_MODE_FLAG_NVSYNC)
		hvctrl |= MGA2_DC_B_VSYNC_POL | MGA2_DC_B_VSYNC_ENA;
	else if (mode->flags & DRM_MODE_FLAG_PVSYNC)
		hvctrl |= MGA2_DC_B_VSYNC_ENA;

	if (mode->flags & DRM_MODE_FLAG_NHSYNC)
		hvctrl |= MGA2_DC_B_HSYNC_POL | MGA2_DC_B_HSYNC_ENA;
	else if (mode->flags & DRM_MODE_FLAG_PHSYNC)
		hvctrl |= MGA2_DC_B_HSYNC_ENA;

	if (mode->flags & DRM_MODE_FLAG_CSYNC ||
	    mcrtc->dev_id == MGA20_PROTO)
		hvctrl |= MGA2_DC_B_CSYNC_ENA | MGA2_DC_B_CSYNC_POL;

	wcrtc(hvctrl, HVCTRL);

	DRM_DEBUG("\thdisplay is %d\n"
		"\tvdisplay is %d\n"
		"\tHSS is %d\n"
		"\tHSE is %d\n"
		"\thtotal is %d\n"
		"\tVSS is %d\n"
		"\tVSE is %d\n"
		"\tvtotal is %d\n"
		"\tclock is %d\n",
		mode->hdisplay,
		mode->vdisplay,
		mode->hsync_start,
		mode->hsync_end,
		mode->htotal,
		mode->vsync_start,
		mode->vsync_end,
		mode->vtotal,
		mode->clock
		);
	drm_display_mode_to_videomode(mode, vm);
	DRM_DEBUG("\thback-porch  = <%d>\n", vm->hback_porch);
	DRM_DEBUG("\thfront-porch = <%d>\n", vm->hfront_porch);
	DRM_DEBUG("\thactive      = <%d>\n", vm->hactive);
	DRM_DEBUG("\thsync-len    = <%d>\n", vm->hsync_len);
	DRM_DEBUG("\tvback-porch  = <%d>\n", vm->vback_porch);
	DRM_DEBUG("\tvfront-porch = <%d>\n", vm->vfront_porch);
	DRM_DEBUG("\tvactive      = <%d>\n", vm->vactive);
	DRM_DEBUG("\tvsync-len    = <%d>\n", vm->vsync_len);
	DRM_DEBUG("\tclock-frequency = <%ld>\n", vm->pixelclock);
	DRM_DEBUG("\tflags        = <%d>\n", vm->flags);

	return ret;
}

static void mga25_crtc_atomic_begin(struct drm_crtc *crtc,
				    struct drm_crtc_state *old_state)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	struct drm_device *dev = crtc->dev;
	unsigned long flags;

	if (crtc->state->event) {
		WARN_ON(drm_crtc_vblank_get(crtc) != 0);

		spin_lock_irqsave(&dev->event_lock, flags);
		mcrtc->event = crtc->state->event;
		spin_unlock_irqrestore(&dev->event_lock, flags);
		crtc->state->event = NULL;
	 }
}

static void mga25_write_gamma_table(struct drm_crtc *crtc,
				     struct drm_crtc_state *old_state)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	struct drm_color_lut *lut;
	int i, length;
	if (!crtc || !crtc->state)
		return;
	if (!crtc->state->color_mgmt_changed)
		return;
	if (!crtc->state->gamma_lut) {
		wcrtc(0, GAMCTRL);
		return;
	}
	length = drm_color_lut_size(crtc->state->gamma_lut);
	if (WARN_ON(length > MGA2_GAMMA_SIZE)) {
		wcrtc(0, GAMCTRL);
		return;
	}

	lut = (struct drm_color_lut *)crtc->state->gamma_lut->data;

	for (i = 0; i < length; i++) {
		u32 word;
		word = (i << MGA2_DC_GAMSET_ADDR_OFFSET) |
			MGA2_DC_GAMSET_SEL_RED |
				drm_color_lut_extract(lut[i].red, 8);
		__wcrtc(word, GAMSET);
		word = (i << MGA2_DC_GAMSET_ADDR_OFFSET) |
			MGA2_DC_GAMSET_SEL_GREEN |
				drm_color_lut_extract(lut[i].green, 8);
		__wcrtc(word, GAMSET);
		word = (i << MGA2_DC_GAMSET_ADDR_OFFSET) |
			MGA2_DC_GAMSET_SEL_BLUE |
				drm_color_lut_extract(lut[i].blue, 8);
		__wcrtc(word, GAMSET);
	}
	wcrtc(MGA2_DC_GAMCTRL_ENABLE, GAMCTRL);
}

static void mga25_crtc_atomic_flush(struct drm_crtc *crtc,
				    struct drm_crtc_state *old_crtc_state)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	struct drm_pending_vblank_event *event = crtc->state->event;

	DRM_DEBUG_DRIVER("Committing plane changes\n");

	mga25_write_gamma_table(crtc, old_crtc_state);
	wcrtc(MGA2_DC_B_STROB, DISPCTRL);

	if (event) {
		crtc->state->event = NULL;

		spin_lock_irq(&crtc->dev->event_lock);
		if (drm_crtc_vblank_get(crtc) == 0)
			drm_crtc_arm_vblank_event(crtc, event);
		else
			drm_crtc_send_vblank_event(crtc, event);
		spin_unlock_irq(&crtc->dev->event_lock);
	}
}

static void mga25_crtc_atomic_disable(struct drm_crtc *crtc,
				      struct drm_crtc_state *old_state)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	wcrtc(MGA2_DC_CTRL_SOFT_RESET | MGA2_DC_CTRL_DEFAULT, CTRL);
	struct drm_plane_state *ps =
			drm_atomic_get_plane_state(old_state->state, crtc->primary);
	bool fb_changed = !IS_ERR(ps) && ps->fb;

	/*
	 * We need to make sure that all planes are disabled before we
	 * enable the crtc. Otherwise we might try to scan from a destroyed
	 * buffer later.
	 */
	if (mga25(mcrtc->dev_id))
		wcrtc(MGA2_DC0_OVL_UPD_BUSY, OVL_CTRL);
	/*
	* A scanout can still be occurring, so we can't drop the
	* reference to the old framebuffer. To solve this we get a
	* reference to old_fb and set a worker to release it later.
	*/
	if (fb_changed && !mcrtc->fb_unref_gem) {
		mcrtc->fb_unref_gem = to_mga25_framebuffer(ps->fb)->gobj;
		drm_gem_object_get(mcrtc->fb_unref_gem);
	}
	mga25_cursor_hide(crtc);

	DRM_DEBUG_DRIVER("Disabling the CRTC\n");
	drm_crtc_vblank_off(crtc);

	if (crtc->state->event && !crtc->state->active) {
		spin_lock_irq(&crtc->dev->event_lock);
		drm_crtc_send_vblank_event(crtc, crtc->state->event);
		spin_unlock_irq(&crtc->dev->event_lock);

		crtc->state->event = NULL;
	}

	if (mcrtc->dev_id == MGA26) /*FIXME: DSI won't work without this: */
		mcrtc->force_mode_changed = true;
}

static void mga25_crtc_atomic_enable(struct drm_crtc *crtc,
				     struct drm_crtc_state *old_state)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	wcrtc(MGA2_DC_CTRL_SOFT_RESET | MGA2_DC_CTRL_DEFAULT, CTRL);
	WARN_ON(mga25_crtc_mode_set(crtc, &crtc->state->adjusted_mode));
	drm_crtc_vblank_on(crtc);
	mcrtc->force_mode_changed = false;
}

static int mga25_crtc_atomic_check(struct drm_crtc *crtc,
		struct drm_crtc_state *state)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	if (mcrtc->force_mode_changed)
		state->mode_changed = true;

	return 0;
}

static enum drm_mode_status mga25_drm_crtc_mode_valid(struct drm_crtc *crtc,
	const struct drm_display_mode *mode)
{
	if (mode->flags & DRM_MODE_FLAG_INTERLACE)
		return MODE_NO_INTERLACE;

	return MODE_OK;
}

static const struct drm_crtc_helper_funcs mga25_crtc_helper_funcs = {
	.mode_valid	= mga25_drm_crtc_mode_valid,
	.atomic_begin	= mga25_crtc_atomic_begin,
	.atomic_flush	= mga25_crtc_atomic_flush,
	.atomic_enable	= mga25_crtc_atomic_enable,
	.atomic_disable	= mga25_crtc_atomic_disable,
	.atomic_check	= mga25_crtc_atomic_check,
};

static void mga25_crtc_destroy(struct drm_crtc *crtc)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	mga25_cursor_fini(crtc);
	drm_gem_object_put(mcrtc->fb_unref_gem);
	of_node_put(crtc->port);
	drm_crtc_cleanup(crtc);
}

static void mga25_finish_page_flip(struct drm_device *drm, struct drm_crtc *crtc)
{
	unsigned long flags;
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);

	spin_lock_irqsave(&drm->event_lock, flags);
	if (mcrtc->event) {
		drm_crtc_send_vblank_event(&mcrtc->base, mcrtc->event);
		drm_crtc_vblank_put(&mcrtc->base);
		mcrtc->event = NULL;
	}
	spin_unlock_irqrestore(&drm->event_lock, flags);
}

static irqreturn_t mga25_crtc_irq_handler(int irq, void *arg)
{
	struct mga25_crtc *mcrtc = arg;
	struct drm_crtc *crtc = &mcrtc->base;
	struct drm_device *drm = crtc->dev;

	mga25_finish_page_flip(drm, crtc);
	drm_crtc_handle_vblank(crtc);
	return IRQ_HANDLED;
}

static u32 mga25_crtc_vblank_count(struct drm_crtc *crtc)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	u32 v =  __rcrtc(VCOUNT);
	return v;
}

static int mga25_crtc_enable_vblank(struct drm_crtc *crtc)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	enable_irq(mcrtc->irq);
	return 0;
}

static void mga25_crtc_disable_vblank(struct drm_crtc *crtc)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	disable_irq_nosync(mcrtc->irq);
}

static const struct drm_crtc_funcs mga25_crtc_funcs = {
	.atomic_destroy_state	= drm_atomic_helper_crtc_destroy_state,
	.atomic_duplicate_state	= drm_atomic_helper_crtc_duplicate_state,
	.destroy		= mga25_crtc_destroy,
	.page_flip		= drm_atomic_helper_page_flip,
	.reset			= drm_atomic_helper_crtc_reset,
	.set_config		= drm_atomic_helper_set_config,
	.gamma_set		= drm_atomic_helper_legacy_gamma_set,

	.get_vblank_counter	= mga25_crtc_vblank_count,
	.enable_vblank		= mga25_crtc_enable_vblank,
	.disable_vblank		= mga25_crtc_disable_vblank,
};

static int mga25_y2r_matrix38[3][3] = {
	{1.1644 * 0x100,  0.0000 * 0x100,  1.7927 * 0x100},
	{1.1644 * 0x100, -0.2123 * 0x100, -0.5329 * 0x100},
	{1.1644 * 0x100,  2.1030 * 0x100,  0.0000 * 0x100},
};

static void mga25_crtc_load_default_pallete(struct drm_crtc *crtc)
{
	int i;
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	wcrtc(MGA2_DC_B_AUTOINC, PALADDR);
	for (i = 0; i < 256; i++) {
		__wcrtc((i << 16) |
			(i <<  8) |
			(i <<  0), PALDATA);
	}
}

static void mga25_crtc_hw_init(struct drm_crtc *crtc)
{
	int i, j;
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	/* Load default values as drm uses gamma-table for C8 pixels */
	mga25_crtc_load_default_pallete(crtc);
	if (!mga25(mcrtc->dev_id))
		goto out;

	wcrtc(0, ZOOM_IHVSUM);
	wcrtc(0, ZOOM_CTRL);
	wcrtc(0, OVL_KEY_MIN);
	wcrtc(~0, OVL_KEY_MAX);
	wcrtc(0.5 * 0x100, Y2R_RSH); /* round to nearest */
	wcrtc(0.5 * 0x100, Y2R_GSH); /* round to nearest */
	wcrtc(0.5 * 0x100, Y2R_BSH); /* round to nearest */

	wcrtc((1 << 24) | (219 << 16) | (0 << 8) | (255 & -16), Y2R_YPRE);
	wcrtc((0 << 31) | (1 << 28) | (1 << 24) |
		(112 << 16) | ((255 & -112) << 8) | 128, Y2R_UPRE);
	wcrtc((0 << 31) | (1 << 28) | (1 << 24) |
		(112 << 16) | ((255 & -112) << 8) | 128, Y2R_VPRE);

	for (i = 0; i < ARRAY_SIZE(mga25_y2r_matrix38); i++) {
		for (j = 0; j < ARRAY_SIZE(mga25_y2r_matrix38[0]); j++) {
			wcrtc((i << 24) | (j << 16) |
				(mga25_y2r_matrix38[i][j] & 0x7ff), Y2R_MATRIX);
		}
	}
out:;
}

static int mga25_crtc_init(struct mga25_crtc *mcrtc, struct drm_device *drm)
{
	int i, ret;
	struct drm_plane *primary = NULL, *cursor = NULL;
	struct drm_crtc *crtc = &mcrtc->base;
	struct drm_plane **planes = mga25_layers_init(mcrtc, drm);
	if (IS_ERR(planes)) {
		dev_err(mcrtc->dev, "Couldn't create the planes\n");
		return PTR_ERR(planes);
	}

	crtc->port = of_graph_get_port_by_id(mcrtc->dev->of_node, 0);
	/* find primary and cursor planes for drm_crtc_init_with_planes */
	for (i = 0; planes[i]; i++) {
		struct drm_plane *plane = planes[i];

		switch (plane->type) {
		case DRM_PLANE_TYPE_PRIMARY:
			primary = plane;
			break;
		case DRM_PLANE_TYPE_CURSOR:
			cursor = plane;
			break;
		default:
			break;
		}
	}

	ret = drm_crtc_init_with_planes(drm, crtc,
					primary,
					cursor,
					&mga25_crtc_funcs,
					NULL);
	if (ret) {
		dev_err(mcrtc->dev, "Couldn't init DRM CRTC\n");
		goto err;
	}
	drm_mode_crtc_set_gamma_size(crtc, MGA2_GAMMA_SIZE);
	drm_crtc_helper_add(crtc, &mga25_crtc_helper_funcs);
	/* Set possible_crtcs to this crtc for overlay planes */
	for (i = 0; planes[i]; i++) {
		struct drm_plane *plane = planes[i];
		if (plane->type == DRM_PLANE_TYPE_OVERLAY)
			plane->possible_crtcs = drm_crtc_mask(&mcrtc->base);
	}
	mga25_cursor_init(crtc);

	drm_crtc_enable_color_mgmt(crtc, 0, false, MGA2_GAMMA_SIZE);

	return 0;
err:
	of_node_put(crtc->port);
	return ret;
}

static int mga25_crtc_bind(struct device *dev, struct device *master, void *data)
{
	int ret, irq;
	struct drm_device *drm = data;
	struct platform_device *pdev = to_platform_device(dev);
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	struct mga25_crtc *mcrtc = devm_kzalloc(dev, sizeof(*mcrtc), GFP_KERNEL);
	if (!mcrtc)
		return -ENOMEM;

	mcrtc->dev = dev;
	mcrtc->dev_id = mga25_get_version(dev->parent);

	mcrtc->regs = devm_ioremap_resource(dev, res);
	if (IS_ERR(mcrtc->regs))
		return PTR_ERR(mcrtc->regs);

	irq = of_irq_get(dev->of_node, 0);
	if (WARN_ON(irq < 0)) {
		ret = irq;
		goto out;
	}
	mcrtc->irq = irq;
	 /* mga25_crtc_enable_vblank() will enable irq */
	irq_set_status_flags(irq, IRQ_NOAUTOEN | IRQ_DISABLE_UNLAZY);
	ret = devm_request_irq(dev, irq, mga25_crtc_irq_handler,
			       0, dev_name(dev), mcrtc);
	if (WARN_ON(ret))
		goto out;
	ret = mga25_crtc_init(mcrtc, drm);
	if (WARN_ON(ret))
		return ret;
	mga25_crtc_hw_init(&mcrtc->base);
	dev_set_drvdata(dev, mcrtc);
out:
	return ret;
}

static void mga25_crtc_unbind(struct device *dev, struct device *master, void *data)
{
	dev_set_drvdata(dev, NULL);
}

const struct component_ops mga25_crtc_component_ops = {
	.bind = mga25_crtc_bind,
	.unbind = mga25_crtc_unbind,
};

static int mga25_crtc_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	return component_add(dev, &mga25_crtc_component_ops);
}

static int mga25_crtc_remove(struct platform_device *pdev)
{
	component_del(&pdev->dev, &mga25_crtc_component_ops);
	return 0;
}

static const struct of_device_id mga25_crtc_driver_dt_match[] = {
	{ .compatible = "mcst,mga2x-crtc"},
	{},
};
MODULE_DEVICE_TABLE(of, mga25_crtc_driver_dt_match);

struct platform_driver mga25_crtc_driver = {
	.probe = mga25_crtc_probe,
	.remove = mga25_crtc_remove,
	.driver = {
		.name = "mga2-crtc",
		.of_match_table = of_match_ptr(mga25_crtc_driver_dt_match),
	},
};
