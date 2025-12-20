/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#define DEBUG

#include "mga2_drv.h"

#define	__rlayer(__addr) readl(mcrtc->regs + MGA2_DC0_ ## __addr)
#define	__wlayer(__v, __addr) writel(__v, mcrtc->regs + MGA2_DC0_ ## __addr)

#ifdef DEBUG
#define rlayer(__offset)				\
({								\
	unsigned __val = __rlayer(__offset);			\
	DRM_DEBUG_KMS("%x:R: %x:%s\n", mcrtc->index,	\
			__val, # __offset);			\
	__val;							\
})

#define wlayer(__val, __offset)	do {				\
	unsigned __val2 = __val;				\
	DRM_DEBUG_KMS("%x:W:%x: %s\n", mcrtc->index,	\
			__val2, # __offset);			\
	__wlayer(__val2, __offset);				\
} while (0)

#else
#define		rlayer		__rlayer
#define		wlayer		__wlayer
#endif

struct mga2_layer {
	struct drm_plane	plane;
};

static inline struct mga2_layer *
plane_to_mga2_layer(struct drm_plane *plane)
{
	return container_of(plane, struct mga2_layer, plane);
}

struct mga2_plane_desc {
	       enum drm_plane_type     type;
	       u8                      pipe;
	       const uint32_t          *formats;
	       uint32_t                nformats;
	       const struct drm_plane_helper_funcs *func;
};

static void mga2_cursor_atomic_disable(struct drm_plane *plane,
				       struct drm_plane_state *old_state)
{
	if (!old_state->crtc)
		return;
	mga2_cursor_hide(old_state->crtc);
}

static void mga2_cursor_atomic_update(struct drm_plane *plane,
					      struct drm_plane_state *old_state)
{
	struct drm_plane_state *state = plane->state;
	struct drm_framebuffer *fb = state->fb;
	struct mga2_framebuffer *mga2_fb = to_mga2_framebuffer(fb);
	struct mga2_crtc *mcrtc = to_mga2_crtc(state->crtc);
	unsigned offset = to_mga2_obj(mga2_fb->gobj)->dma_addr;
	wlayer((state->crtc_x << 16) |
				(state->crtc_y & 0xffff), NCRSCOORD);
	wlayer(offset | MGA2_DC_B_CRS_ENA, NCRSADDR);
	wlayer(MGA2_DC_B_STROB, DISPCTRL);
}

static const struct drm_plane_helper_funcs mga2_cursor_helper_funcs = {
	.atomic_disable	= mga2_cursor_atomic_disable,
	.atomic_update	= mga2_cursor_atomic_update,
	/*.atomic_check	= TODO:*/
};

#define MGA2_MAX_SCALE	(2 << 16) /*16.16 fixed point*/
#define MGA2_MIN_SCALE	1	  /*16.16 fixed point*/

static int mga2_overlay_plane_atomic_check(struct drm_plane *plane,
					struct drm_plane_state *pstate)
{
	struct drm_crtc_state *crtc_state;
	struct drm_crtc *crtc = pstate->crtc;

	if (!crtc)
		return 0;

	crtc_state = drm_atomic_get_existing_crtc_state(pstate->state, crtc);
	if (WARN_ON(!crtc_state))
		return -EINVAL;

	return drm_atomic_helper_check_plane_state(pstate, crtc_state,
					   MGA2_MIN_SCALE,
					   MGA2_MAX_SCALE,
					   true, true);
}

static void mga2_overlay_atomic_disable(struct drm_plane *plane,
				       struct drm_plane_state *old_state)
{
	struct mga2_crtc *mcrtc = to_mga2_crtc(old_state->crtc);
	if (!old_state->crtc)
		return;
	wlayer(MGA2_DC0_OVL_UPD_BUSY, OVL_CTRL);
}

static u64 mga2_plane_to_offset(struct drm_plane_state *state, int plane)
{
	struct drm_framebuffer *fb = state->fb;
	unsigned x = state->src.x1 >> 16;
	unsigned y = state->src.y1 >> 16;

	if (plane) {
		x /= fb->format->hsub;
		y /= fb->format->vsub;
	}
	return fb->offsets[plane] + fb->pitches[plane] * y +
			fb->format->cpp[plane] * x;
}

static u32 mga2_format_to_overlay(u32 format, int *plane)
{
	u32 mode;
	plane[0] = 0;
	plane[1] = 1;
	plane[2] = 2;
	switch (format) {
	case DRM_FORMAT_ARGB8888:
	case DRM_FORMAT_XRGB8888:
		mode = MGA2_DC_B_MODE_ARGB | MGA_MODE_ENDIAN(3, 2, 1, 0);
		break;
	case DRM_FORMAT_RGBA8888:
	case DRM_FORMAT_RGBX8888:
		mode = MGA2_DC_B_MODE_ARGB | MGA_MODE_ENDIAN(0, 3, 2, 1);
		break;
	case DRM_FORMAT_ABGR8888:
	case DRM_FORMAT_XBGR8888:
		mode = MGA2_DC_B_MODE_ARGB | MGA_MODE_ENDIAN(3, 0, 1, 2);
		break;
	case DRM_FORMAT_BGRA8888:
	case DRM_FORMAT_BGRX8888:
		mode = MGA2_DC_B_MODE_ARGB | MGA_MODE_ENDIAN(0, 1, 2, 3);
		break;
	case DRM_FORMAT_AYUV:
		mode = MGA2_DC_B_MODE_AYUV | MGA_MODE_ENDIAN(0, 1, 2, 3);
		break;
	case DRM_FORMAT_RGB888:
		mode = MGA2_DC_B_MODE_RGB | MGA_MODE_ENDIAN(3, 2, 1, 0);
		break;
	case DRM_FORMAT_BGR888:
		mode = MGA2_DC_B_MODE_RGB | MGA_MODE_ENDIAN(3, 0, 1, 2);
		break;
	case DRM_FORMAT_YUYV:
		mode = MGA2_DC_B_MODE_YUYV | MGA_MODE_ENDIAN(0, 1, 2, 3);
		break;
	case DRM_FORMAT_YVYU:
		mode = MGA2_DC_B_MODE_YUYV | MGA_MODE_ENDIAN(0, 3, 2, 1);
		break;
	case DRM_FORMAT_UYVY:
		mode = MGA2_DC_B_MODE_YUYV | MGA_MODE_ENDIAN(1, 0, 3, 2);
		break;
	case DRM_FORMAT_VYUY:
		mode = MGA2_DC_B_MODE_YUYV | MGA_MODE_ENDIAN(1, 2, 3, 0);
		break;
	case DRM_FORMAT_NV12:
		mode = MGA2_DC_B_MODE_NV12;
		break;
	case DRM_FORMAT_NV21:
		mode = MGA2_DC_B_MODE_NV21;
		break;
	case DRM_FORMAT_NV16:
		mode = MGA2_DC_B_MODE_NV16;
		break;
	case DRM_FORMAT_NV61:
		mode = MGA2_DC_B_MODE_NV61;
		break;
	case DRM_FORMAT_NV24:
		mode = MGA2_DC_B_MODE_NV24;
		break;
	case DRM_FORMAT_NV42:
		mode = MGA2_DC_B_MODE_NV42;
		break;
	case DRM_FORMAT_YUV420:
		mode = MGA2_DC_B_MODE_YUV420;
		break;
	case DRM_FORMAT_YVU420:
		mode = MGA2_DC_B_MODE_YUV420;
		plane[0] = 0;
		plane[1] = 2;
		plane[2] = 1;
		break;
	case DRM_FORMAT_YUV422:
		mode = MGA2_DC_B_MODE_YUV422;
		break;
	case DRM_FORMAT_YVU422:
		mode = MGA2_DC_B_MODE_YUV422;
		plane[0] = 0;
		plane[1] = 2;
		plane[2] = 1;
		break;
	case DRM_FORMAT_YUV444:
		mode = MGA2_DC_B_MODE_YUV444;
		break;
	case DRM_FORMAT_YVU444:
		mode = MGA2_DC_B_MODE_YUV444;
		plane[0] = 0;
		plane[1] = 2;
		plane[2] = 1;
		break;
	default:
		mode = MGA2_DC_B_MODE_ARGB | MGA_MODE_ENDIAN(3, 2, 1, 0);
		WARN_ON(1);
	}
	return mode;
}

/*
 Lanczos2-windowed sinc function
 5 taps
 16 phases per tap
 Quantized to 2.8-bit signed numbers
*/
static int mga2_fir_coeff[16][5] = {
	{    0,     0,   256,     0,     0, },
	{    0,    -9,   254,    11,     0, },
	{   -1,   -15,   248,    25,    -1, },
	{   -2,   -20,   238,    42,    -2, },
	{   -3,   -22,   225,    60,    -4, },
	{   -4,   -22,   208,    81,    -7, },
	{   -5,   -21,   190,   102,   -10, },
	{   -5,   -19,   169,   124,   -13, },
	{   -6,   -16,   147,   147,   -16, },
	{   -6,   -13,   125,   169,   -19, },
	{   -5,   -10,   102,   190,   -21, },
	{   -5,    -7,    81,   209,   -22, },
	{   -4,    -4,    60,   225,   -21, },
	{   -3,    -2,    42,   238,   -19, },
	{   -2,    -1,    26,   248,   -15, },
	{   -1,     0,    12,   254,    -9, },
};

static u32 mga2_get_fir_coeff(int ratio, int phase, int tap)
{
	u32 no_zoom_coeff[] = {0, 0, 256, 0, 0};
	if (ratio >> 16 == 1)
		return no_zoom_coeff[tap];

	return mga2_fir_coeff[phase][tap];
}

static u32 mga2_rect_wh_fp(struct drm_rect *r)
{
	/* round to nearest */
	return ((drm_rect_width(r) + 0x8000) & 0xffff0000) |
		(drm_rect_height(r) + 0x8000) >> 16;
}

static u32 mga2_rect_wh(struct drm_rect *r)
{
	return drm_rect_width(r) << 16 | (drm_rect_height(r) & 0x0000ffff);
}

static u32 mga2_rect_xy(struct drm_rect *r)
{
	return (r)->x1 << 16 | ((r)->y1 & 0x0000ffff);
}

static void mga2_set_zoom(struct mga2_crtc *mcrtc, int hscale, int vscale)
{
	int coord, phase, tap;
	int ratio[2] = {vscale, hscale};

	for (coord = 0; coord < 2; coord++) {
		for (phase = 0; phase < 16; phase++) {
			for (tap = 0; tap < 5; tap++) {
				u32 v = mga2_get_fir_coeff(
						ratio[coord], phase, tap);
				wlayer(v, ZOOM_FTAP0 + tap * 4);
			}
			wlayer(coord << MGA2_DC0_ZOOM_COORD_SHIFT | phase,
							ZOOM_FWRITE);
		}
	}
	wlayer(vscale, ZOOM_VPITCH);
	wlayer(hscale, ZOOM_HPITCH);
}

static int mga2_rect_calc_vscale(const struct drm_rect *src,
			 const struct drm_rect *dst,
			 int min_hscale, int max_hscale)
{
	int src_h = drm_rect_height(src) - (1 << 16);
	int dst_h = drm_rect_height(dst) - 1;
	return dst_h ? src_h / dst_h : 1 << 16;
}

static int mga2_rect_calc_hscale(const struct drm_rect *src,
			 const struct drm_rect *dst,
			 int min_hscale, int max_hscale)
{
	int src_w = drm_rect_width(src) - (1 << 16);
	int dst_w = drm_rect_width(dst) - 1;
	return dst_w ? src_w / dst_w : 1 << 16;
}

static void mga2_overlay_atomic_update(struct drm_plane *plane,
					      struct drm_plane_state *old_state)
{
	struct drm_plane_state *state = plane->state;
	struct mga2_crtc *mcrtc = to_mga2_crtc(state->crtc);
	struct drm_framebuffer *fb = state->fb;
	struct mga2_framebuffer *mga2_fb = to_mga2_framebuffer(fb);
	u64 ba = to_mga2_obj(mga2_fb->gobj)->dma_addr;
	int pl[3] = {};
	u32 alpha, v;
	int hscale, vscale, scale = 0;
	struct drm_rect s = drm_plane_state_src(state);
	struct drm_rect d = drm_plane_state_dest(state);

	BUILD_BUG_ON(-1 >> 1 != -1);
	if (!state->fb  || WARN_ON(!state->crtc) ||
			(!old_state->visible && !state->visible))
		return;
	if (!state->visible) {
		wlayer(MGA2_DC0_OVL_UPD_BUSY, OVL_CTRL);
		return;
	}
	WARN_ON(DRM_MODE_ROTATE_0 != (state->rotation & DRM_MODE_ROTATE_MASK));

	drm_rect_debug_print("src: ", &state->src, true);
	drm_rect_debug_print("dst: ", &state->dst, false);

	hscale = mga2_rect_calc_hscale(&s, &d, MGA2_MIN_SCALE, MGA2_MAX_SCALE);
	vscale = mga2_rect_calc_vscale(&s, &d, MGA2_MIN_SCALE, MGA2_MAX_SCALE);

	s = drm_plane_state_src(old_state);
	d = drm_plane_state_dest(old_state);

	scale = hscale != mga2_rect_calc_hscale(&s, &d,
				MGA2_MIN_SCALE, MGA2_MAX_SCALE) ||
		vscale != mga2_rect_calc_vscale(&s, &d, MGA2_MIN_SCALE,
					MGA2_MAX_SCALE);
	scale = scale || !old_state->fb;
	if (scale)
		mga2_set_zoom(mcrtc, hscale, vscale);

	v = mga2_rect_xy(&state->dst);
	if (mga2_rect_xy(&old_state->dst) != v || scale)
		wlayer(v, OVL_XY);
	v = mga2_rect_wh_fp(&state->src);
	if (mga2_rect_wh_fp(&old_state->src) != v || scale) {
		wlayer(v, OVL_GEOMETRY);
		wlayer(v, ZOOM_SRCGEOM);
	}
	v = mga2_rect_wh(&state->dst);
	if (mga2_rect_wh(&old_state->dst) != v || scale)
		wlayer(v, ZOOM_DSTGEOM);

	v = mga2_format_to_overlay(fb->format->format, pl);
	if (!old_state->fb || fb->format->format !=
				old_state->fb->format->format) {
		wlayer(v, OVL_MODE);
		wlayer(fb->pitches[pl[0]], OVL_STRIDE0);
		wlayer(fb->pitches[pl[1]], OVL_STRIDE1);
		wlayer(fb->pitches[pl[2]], OVL_STRIDE2);
	}
	if (old_state->src.x1 != state->src.x1 ||
			old_state->src.y1 != state->src.y1 ||
			old_state->fb != state->fb ||
			state->crtc->state->mode_changed) {
		wlayer(ba + mga2_plane_to_offset(state, pl[0]), OVL_BASE0);
		wlayer(ba + mga2_plane_to_offset(state, pl[1]), OVL_BASE1);
		wlayer(ba + mga2_plane_to_offset(state, pl[2]), OVL_BASE2);
	}

	alpha = state->alpha != DRM_BLEND_ALPHA_OPAQUE ?
			state->alpha >> 8 :
			fb->format->has_alpha ? 0 : 0xff;
	alpha <<= MGA2_DC0_OVL_ALPHA_SHIFT;
	wlayer(MGA2_DC0_OVL_UPD_BUSY | MGA2_DC0_OVL_ENABLE | alpha, OVL_CTRL);
}

static const struct drm_plane_helper_funcs mga2_overlay_helper_funcs = {
	.atomic_disable	= mga2_overlay_atomic_disable,
	.atomic_update	= mga2_overlay_atomic_update,
	.atomic_check	= mga2_overlay_plane_atomic_check,
};


static int mga2_primary_atomic_check(struct drm_plane *plane,
					struct drm_plane_state *pstate)
{
	struct drm_crtc_state *crtc_state;
	struct drm_crtc *crtc = pstate->crtc;
	if (!crtc)
		return 0;

	crtc_state = drm_atomic_get_existing_crtc_state(pstate->state, crtc);
	if (WARN_ON(!crtc_state))
		return -EINVAL;

	return drm_atomic_helper_check_plane_state(pstate, crtc_state,
					   DRM_PLANE_HELPER_NO_SCALING,
					   DRM_PLANE_HELPER_NO_SCALING,
					   false, true);
}

static void mga2_finish_page_flip(struct drm_device *drm, int ctrc)
{
	unsigned long flags;
	struct mga2_crtc *mcrtc =
			 to_mga2_crtc(drm_crtc_from_index(drm, ctrc));

	spin_lock_irqsave(&drm->event_lock, flags);
	if (mcrtc->event) {
		drm_crtc_send_vblank_event(&mcrtc->base, mcrtc->event);
		drm_crtc_vblank_put(&mcrtc->base);
		mcrtc->event = NULL;
	}
	spin_unlock_irqrestore(&drm->event_lock, flags);
}

void mga2_handle_vblank(struct drm_device *drm, int crtc)
{
	struct mga2_crtc *mcrtc = to_mga2_crtc(drm_crtc_from_index(drm, crtc));
	mga2_finish_page_flip(drm, crtc);
	drm_handle_vblank(drm, crtc);
	if (!test_and_clear_bit(MGA2_PENDING_FB_UNREF, &mcrtc->pending))
		return;
	if (rlayer(WSTART) != rlayer(NSTART)) {
		/* Race occured. We have to wait for another IRQ. */
		set_bit(MGA2_PENDING_FB_UNREF, &mcrtc->pending);
		return;
	}
	drm_crtc_vblank_put(&mcrtc->base);
	drm_flip_work_commit(&mcrtc->fb_unref_work, system_unbound_wq);

}

static void mga2_primary_atomic_disable(struct drm_plane *plane,
				       struct drm_plane_state *old_state)
{
	struct mga2_crtc *mcrtc = to_mga2_crtc(old_state->crtc);
	wlayer(MGA2_DC_CTRL_NOSCRRFRSH | rlayer(CTRL), CTRL);
	drm_framebuffer_get(old_state->fb);
	drm_flip_work_queue(&mcrtc->fb_unref_work, old_state->fb);
	set_bit(MGA2_PENDING_FB_UNREF_DISABLE, &mcrtc->pending);
}

static int mga2_format_to_primary(u32 format)
{
	int pixfmt;

	switch (format) {
	case DRM_FORMAT_RGBX8888:
	case DRM_FORMAT_BGRX8888:
	case DRM_FORMAT_XRGB8888:
	case DRM_FORMAT_XBGR8888:
		pixfmt = MGA2_DC_B_32BPP;
#ifdef __BIG_ENDIAN
		pixfmt |= MGA2_DC_B_BGR | MGA2_DC_B_RGBX_FMT;
#else
		pixfmt |= MGA2_DC_B_RGB;
#endif
	break;
	case DRM_FORMAT_RGB888:
	case DRM_FORMAT_BGR888:
		pixfmt = MGA2_DC_B_24BPP;
#ifdef __BIG_ENDIAN
		pixfmt |= MGA2_DC_B_BGR | MGA2_DC_B_RGBX_FMT;
#else
		pixfmt |= MGA2_DC_B_RGB;
#endif
	break;
	case DRM_FORMAT_RGB565:
	case DRM_FORMAT_BGR565:
		pixfmt = MGA2_DC_B_16BPP;
		pixfmt |= MGA2_DC_B_565_FMT;
#ifdef __BIG_ENDIAN
		pixfmt |= MGA2_DC_B_RGB_16SWAP;
#endif
	break;
	case DRM_FORMAT_XRGB1555:
	case DRM_FORMAT_BGRX5551:
		pixfmt = MGA2_DC_B_16BPP;
		pixfmt |= MGA2_DC_B_565_FMT;
#ifdef __BIG_ENDIAN
		pixfmt |= MGA2_DC_B_RGB_16SWAP;
#endif
	break;
	case DRM_FORMAT_XRGB4444:
	case DRM_FORMAT_BGRX4444:
		pixfmt = MGA2_DC_B_16BPP;
		pixfmt |= MGA2_DC_B_4444_FMT;
#ifdef __BIG_ENDIAN
		pixfmt |= MGA2_DC_B_RGB_16SWAP;
#endif
	break;
	case DRM_FORMAT_C8:
		pixfmt = MGA2_DC_B_8BPP;
	break;
	default:
		return -EINVAL;
	}

	return pixfmt;
}

static void mga2_primary_atomic_update(struct drm_plane *plane,
					      struct drm_plane_state *old_state)
{
	struct drm_plane_state *state = plane->state;
	struct drm_framebuffer *fb = state->fb;
	struct mga2_framebuffer *mga2_fb = to_mga2_framebuffer(fb);
	struct drm_crtc *crtc = state->crtc;
	struct mga2_crtc *mcrtc = to_mga2_crtc(state->crtc);
	unsigned offset = to_mga2_obj(mga2_fb->gobj)->dma_addr;
	int x = state->src_x >> 16;
	int y = state->src_y >> 16;
	int pix = mga2_format_to_primary(fb->format->format);
	bool fb_changed = old_state->fb && old_state->fb != state->fb;

	WARN_ON(to_mga2_obj(mga2_fb->gobj)->dma_addr & (-1LL << 32));
	if (WARN_ON(pix < 0))
		return;

	drm_rect_debug_print("src: ", &state->src, true);
	drm_rect_debug_print("dst: ", &state->dst, false);

	offset += /*fb->offsets[0] +*/ y * fb->pitches[0] +
		x * fb->format->cpp[0];

	wlayer(offset, NSTART);
	wlayer(fb->pitches[0], NOFFS);
	wlayer(pix, PIXFMT);
	wlayer(MGA2_DC_B_STROB, DISPCTRL);
	wlayer(MGA2_DC_CTRL_DEFAULT, CTRL);

	DRM_DEBUG("%s:%s (%d, %d) pitch: %d, offset: %d\n",
			plane->name, (char *)&fb->format->format, x, y,
			fb->pitches[0], fb->offsets[0]);
	/*
	* A scanout can still be occurring, so we can't drop the
	* reference to the old framebuffer. To solve this we get a
	* reference to old_fb and set a worker to release it later.
	*/
	if (fb_changed) {
		drm_framebuffer_get(old_state->fb);
		drm_flip_work_queue(&mcrtc->fb_unref_work, old_state->fb);
	}

	if (fb_changed || test_and_clear_bit(MGA2_PENDING_FB_UNREF_DISABLE,
							&mcrtc->pending)) {
		WARN_ON(drm_crtc_vblank_get(crtc) != 0);
		set_bit(MGA2_PENDING_FB_UNREF, &mcrtc->pending);
	}
}

static const struct drm_plane_helper_funcs mga2_primary_helper_funcs = {
	.atomic_disable	= mga2_primary_atomic_disable,
	.atomic_update	= mga2_primary_atomic_update,
	.atomic_check	= mga2_primary_atomic_check,
};

static const struct drm_plane_funcs mga2_layer_funcs = {
	.atomic_destroy_state	= drm_atomic_helper_plane_destroy_state,
	.atomic_duplicate_state	= drm_atomic_helper_plane_duplicate_state,
	.destroy		= drm_plane_cleanup,
	.disable_plane		= drm_atomic_helper_disable_plane,
	.reset			= drm_atomic_helper_plane_reset,
	.update_plane		= drm_atomic_helper_update_plane,
};

static const uint32_t mga2_primary_formats[] = {
	DRM_FORMAT_XRGB8888,
	DRM_FORMAT_RGBX8888,
	DRM_FORMAT_XBGR8888,
	DRM_FORMAT_BGRX8888,
	DRM_FORMAT_RGB888,
	DRM_FORMAT_BGR888,
	DRM_FORMAT_RGB565,
	DRM_FORMAT_BGR565,
	DRM_FORMAT_XRGB1555,
	DRM_FORMAT_BGRX5551,
#ifdef __BIG_ENDIAN
	DRM_FORMAT_XRGB4444,
	DRM_FORMAT_BGRX4444,
#endif
	DRM_FORMAT_C8,
};

static const uint32_t mga2_cursor_formats[] = {
	DRM_FORMAT_ARGB8888,
};

static const uint32_t mga2_overlay_formats[] = {
	DRM_FORMAT_ARGB8888,
	DRM_FORMAT_XRGB8888,
	DRM_FORMAT_RGBA8888,
	DRM_FORMAT_RGBX8888,
	DRM_FORMAT_ABGR8888,
	DRM_FORMAT_XBGR8888,
	DRM_FORMAT_BGRA8888,
	DRM_FORMAT_BGRX8888,
	DRM_FORMAT_AYUV,
	/*DRM_FORMAT_YUVA, linux don't know such */
	DRM_FORMAT_RGB888,
	DRM_FORMAT_BGR888,
	DRM_FORMAT_YUYV,
	DRM_FORMAT_YVYU,
	DRM_FORMAT_UYVY,
	DRM_FORMAT_VYUY,
	DRM_FORMAT_NV12,
	DRM_FORMAT_NV21,
	DRM_FORMAT_NV16,
	DRM_FORMAT_NV61,
	DRM_FORMAT_NV24,
	DRM_FORMAT_NV42,

	DRM_FORMAT_YUV420,
	DRM_FORMAT_YVU420,
	DRM_FORMAT_YUV422,
	DRM_FORMAT_YVU422,
	DRM_FORMAT_YUV444,
	DRM_FORMAT_YVU444,
};

static const struct mga2_plane_desc mga2_planes[] = {
	{
		.type = DRM_PLANE_TYPE_PRIMARY,
		.formats = mga2_primary_formats,
		.nformats = ARRAY_SIZE(mga2_primary_formats),
		.func = &mga2_primary_helper_funcs,
	},
	{
		.type = DRM_PLANE_TYPE_CURSOR,
		.formats = mga2_cursor_formats,
		.nformats = ARRAY_SIZE(mga2_cursor_formats),
		.func = &mga2_cursor_helper_funcs,
	},

	{ /* must be the last */
		.type = DRM_PLANE_TYPE_OVERLAY,
		.formats = mga2_overlay_formats,
		.nformats = ARRAY_SIZE(mga2_overlay_formats),
		.func = &mga2_overlay_helper_funcs,
	},
};

static struct mga2_layer *mga2_layer_init_one(struct drm_device *drm,
					const struct mga2_plane_desc *plane)
{
	struct mga2_layer *layer;
	int ret;

	layer = devm_kzalloc(drm->dev, sizeof(*layer), GFP_KERNEL);
	if (!layer)
		return ERR_PTR(-ENOMEM);

	/* possible crtcs are set later */
	ret = drm_universal_plane_init(drm, &layer->plane, 0,
				       &mga2_layer_funcs,
				       plane->formats, plane->nformats,
				       NULL, plane->type, NULL);
	if (ret) {
		dev_err(drm->dev, "Couldn't initialize layer\n");
		return ERR_PTR(ret);
	}

	if (plane->type == DRM_PLANE_TYPE_OVERLAY) {
		ret = drm_plane_create_alpha_property(&layer->plane);
		if (ret)
			return ERR_PTR(ret);
	}
	drm_plane_helper_add(&layer->plane, plane->func);

	return layer;
}

struct drm_plane **mga2_layers_init(struct drm_device *drm)
{
	struct mga2 *mga2 = drm->dev_private;
	struct drm_plane **planes;
	int i;
	int n = mga25(mga2) ? ARRAY_SIZE(mga2_planes) :
			 ARRAY_SIZE(mga2_planes) - 1;
	planes = devm_kcalloc(drm->dev, ARRAY_SIZE(mga2_planes) + 1,
			      sizeof(*planes), GFP_KERNEL);
	if (!planes)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < n; i++) {
		const struct mga2_plane_desc *plane = &mga2_planes[i];
		struct mga2_layer *layer;

		layer = mga2_layer_init_one(drm, plane);
		if (IS_ERR(layer)) {
			return ERR_CAST(layer);
		};
		planes[i] = &layer->plane;
	}

	return planes;
}
