/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */



static unsigned long get_next_vblank_time(struct drm_crtc *crtc)
{
	struct drm_device *drm = crtc->dev;
	struct mga2 *mga2 = drm->dev_private;
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	unsigned int pipe = drm_crtc_index(crtc);
	struct drm_vblank_crtc *vblank = &drm->vblank[pipe];
	if (mga25_proto(mga2->dev_id))
		return jiffies + 5 * HZ;
	return jiffies + nsecs_to_jiffies(vblank->framedur_ns) + 1;
}

struct mga25_layer {
	struct drm_plane	plane;
};

struct mga25_plane_desc {
	       enum drm_plane_type     type;
	       u8                      pipe;
	       const uint32_t          *formats;
	       uint32_t                nformats;
	       const struct drm_plane_helper_funcs *func;
};

static void mga25_cursor_atomic_disable(struct drm_plane *plane,
				       struct drm_plane_state *old_state)
{
	if (!old_state->crtc)
		return;
	mga25_cursor_hide(old_state->crtc);
}

static void mga25_cursor_atomic_update(struct drm_plane *plane,
					      struct drm_plane_state *old_state)
{
	struct drm_plane_state *state = plane->state;
	struct drm_framebuffer *fb = state->fb;
	struct mga25_framebuffer *mga25_fb = to_mga25_framebuffer(fb);
	struct mga25_crtc *mcrtc = to_mga25_crtc(state->crtc);
	unsigned offset = to_mga25_obj(mga25_fb->gobj)->dma_addr;
	wcrtc((state->crtc_x << 16) |
				(state->crtc_y & 0xffff), NCRSCOORD);
	wcrtc(offset | MGA2_DC_B_CRS_ENA, NCRSADDR);
	wcrtc(MGA2_DC_B_STROB, DISPCTRL);
}

static const struct drm_plane_helper_funcs mga25_cursor_helper_funcs = {
	.atomic_disable	= mga25_cursor_atomic_disable,
	.atomic_update	= mga25_cursor_atomic_update,
	/*.atomic_check	= TODO:*/
};

#define MGA2_MAX_SCALE	(2 << 16) /*16.16 fixed point*/
#define MGA2_MIN_SCALE	1	  /*16.16 fixed point*/

static int mga25_overlay_plane_atomic_check(struct drm_plane *plane,
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

static void mga25_overlay_atomic_disable(struct drm_plane *plane,
				       struct drm_plane_state *old_state)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(old_state->crtc);
	bool fb_changed = !!old_state->fb;
	struct drm_crtc *crtc = old_state->crtc;
	if (!crtc)
		return;
	wcrtc(MGA2_DC0_OVL_UPD_BUSY, OVL_CTRL);
	/*
	* A scanout can still be occurring, so we can't drop the
	* reference to the old framebuffer. To solve this we get
	* the time of the release of the old framebuffer in order
	* to check it while freeing.
	*/
	if (fb_changed) {
		struct mga25_gem_object *mo =
			to_mga25_obj(to_mga25_framebuffer(old_state->fb)->gobj);
		mo->hw_unref_time = get_next_vblank_time(old_state->crtc);
	}
}

static u64 mga25_plane_to_offset(struct drm_plane_state *state, int plane)
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

static u32 mga25_format_to_overlay(u32 format, int *plane)
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
static int mga25_fir_coeff[16][5] = {
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

static u32 mga25_get_fir_coeff(int ratio, int phase, int tap)
{
	u32 no_zoom_coeff[] = {0, 0, 256, 0, 0};
	if (ratio == DRM_PLANE_HELPER_NO_SCALING)
		return no_zoom_coeff[tap];

	return mga25_fir_coeff[phase][tap];
}

static u32 mga25_rect_wh_fp(struct drm_rect *r)
{
	/* round to nearest */
	return ((drm_rect_width(r) + 0x8000) & 0xffff0000) |
		(drm_rect_height(r) + 0x8000) >> 16;
}

static u32 mga25_rect_wh(struct drm_rect *r)
{
	return drm_rect_width(r) << 16 | (drm_rect_height(r) & 0x0000ffff);
}

static u32 mga25_rect_xy(struct drm_rect *r)
{
	return (r)->x1 << 16 | ((r)->y1 & 0x0000ffff);
}

static void mga25_set_zoom(struct mga25_crtc *mcrtc, int hscale, int vscale)
{
	int coord, phase, tap;
	int ratio[2] = {vscale, hscale};

	for (coord = 0; coord < 2; coord++) {
		for (phase = 0; phase < 16; phase++) {
			for (tap = 0; tap < 5; tap++) {
				u32 v = mga25_get_fir_coeff(
						ratio[coord], phase, tap);
				wcrtc(v, ZOOM_FTAP0 + tap * 4);
			}
			wcrtc(coord << MGA2_DC0_ZOOM_COORD_SHIFT | phase,
							ZOOM_FWRITE);
		}
	}
	wcrtc(vscale, ZOOM_VPITCH);
	wcrtc(hscale, ZOOM_HPITCH);
}

static int mga25_rect_calc_vscale(const struct drm_rect *src,
			 const struct drm_rect *dst,
			 int min_hscale, int max_hscale)
{
	int src_h = drm_rect_height(src) - (1 << 16);
	int dst_h = drm_rect_height(dst) - 1;
	return dst_h ? src_h / dst_h : 1 << 16;
}

static int mga25_rect_calc_hscale(const struct drm_rect *src,
			 const struct drm_rect *dst,
			 int min_hscale, int max_hscale)
{
	int src_w = drm_rect_width(src) - (1 << 16);
	int dst_w = drm_rect_width(dst) - 1;
	return dst_w ? src_w / dst_w : 1 << 16;
}

static void mga25_overlay_atomic_update(struct drm_plane *plane,
					      struct drm_plane_state *old_state)
{
	struct drm_plane_state *state = plane->state;
	struct drm_crtc *crtc = state->crtc;
	struct mga25_crtc *mcrtc = to_mga25_crtc(crtc);
	struct drm_framebuffer *fb = state->fb;
	struct mga25_framebuffer *mga25_fb = to_mga25_framebuffer(fb);
	u64 ba = to_mga25_obj(mga25_fb->gobj)->dma_addr;
	int pl[3] = {};
	u32 alpha, v;
	int hscale, vscale, scale = 0;
	struct drm_rect os, s = drm_plane_state_src(state);
	struct drm_rect od, d = drm_plane_state_dest(state);
	bool fb_changed = old_state->fb && old_state->fb != state->fb;
	struct mga2 *mga2 = plane->dev->dev_private;

	BUILD_BUG_ON(-1 >> 1 != -1);
	if (!state->fb  || WARN_ON(!state->crtc) ||
			(!old_state->visible && !state->visible))
		return;
	if (!state->visible) {
		wcrtc(MGA2_DC0_OVL_UPD_BUSY, OVL_CTRL);
		return;
	}
	WARN_ON(DRM_MODE_ROTATE_0 != (state->rotation & DRM_MODE_ROTATE_MASK));
	hscale = mga25_rect_calc_hscale(&s, &d, MGA2_MIN_SCALE, MGA2_MAX_SCALE);
	vscale = mga25_rect_calc_vscale(&s, &d, MGA2_MIN_SCALE, MGA2_MAX_SCALE);

	drm_rect_debug_print("src: ", &s, true);
	drm_rect_debug_print("dst: ", &d, false);

	os = drm_plane_state_src(old_state);
	od = drm_plane_state_dest(old_state);

	scale = hscale != mga25_rect_calc_hscale(&os, &od,
				MGA2_MIN_SCALE, MGA2_MAX_SCALE) ||
		vscale != mga25_rect_calc_vscale(&os, &od, MGA2_MIN_SCALE,
					MGA2_MAX_SCALE);
	scale = scale || !old_state->fb;

	s = state->src;
	d = state->dst;
	os = old_state->src;
	od = old_state->dst;
	drm_rect_debug_print("clipped src: ", &s, true);
	drm_rect_debug_print("clipped dst: ", &d, false);

	mga25_set_zoom(mcrtc, hscale, vscale);

	v = mga25_rect_xy(&d);
	if (mga25_rect_xy(&od) != v || scale)
		wcrtc(v, OVL_XY);
	v = mga25_rect_wh_fp(&s);
	if (mga25_rect_wh_fp(&os) != v || scale) {
		wcrtc(v, OVL_GEOMETRY);
		wcrtc(v, ZOOM_SRCGEOM);
	}
	v = mga25_rect_wh(&d);
	if (mga25_rect_wh(&od) != v || scale)
		wcrtc(v, ZOOM_DSTGEOM);

	v = mga25_format_to_overlay(fb->format->format, pl);
	if (s.x1 & (1 << 16))
		v |= MGA2_DC0_MODE_ODD_H_PXL;
	if (s.y1 & (1 << 16))
		v |= MGA2_DC0_MODE_ODD_V_PXL;
	wcrtc(v, OVL_MODE);
	if (!old_state->fb || fb->format->format !=
				old_state->fb->format->format) {
		wcrtc(fb->pitches[pl[0]], OVL_STRIDE0);
		wcrtc(fb->pitches[pl[1]], OVL_STRIDE1);
		wcrtc(fb->pitches[pl[2]], OVL_STRIDE2);
	}

	wcrtc(ba + mga25_plane_to_offset(state, pl[0]), OVL_BASE0);
	wcrtc(ba + mga25_plane_to_offset(state, pl[1]), OVL_BASE1);
	wcrtc(ba + mga25_plane_to_offset(state, pl[2]), OVL_BASE2);

	alpha = state->alpha != DRM_BLEND_ALPHA_OPAQUE ?
			state->alpha >> 8 :
			fb->format->has_alpha ? 0 : 0xff;
	alpha <<= MGA2_DC0_OVL_ALPHA_SHIFT;
	wcrtc(MGA2_DC0_OVL_UPD_BUSY | MGA2_DC0_OVL_ENABLE | alpha, OVL_CTRL);

	if (!old_state->visible && state->visible) {
		wcrtc(mga2->props.colorkey_min_val, OVL_KEY_MIN);
		wcrtc(mga2->props.colorkey_max_val, OVL_KEY_MAX);
	}

	/*
	* A scanout can still be occurring, so we can't drop the
	* reference to the old framebuffer. To solve this we get
	* the time of the release of the old framebuffer in order
	* to check it while freeing.
	*/
	if (fb_changed) {
		struct mga25_gem_object *mo =
			to_mga25_obj(to_mga25_framebuffer(old_state->fb)->gobj);
		mo->hw_unref_time = get_next_vblank_time(crtc);
	}
}

static int mga25_layer_create_properties(struct drm_device *drm)
{
	struct mga2 *mga2 = drm->dev_private;

	if (mga2->props.colorkey_min || mga2->props.colorkey_max)
		return 0;

	mga2->props.colorkey_min = drm_property_create_range(drm, 0,
					"colorkey_min", 0, 0xffffff);
	mga2->props.colorkey_max = drm_property_create_range(drm, 0,
					"colorkey_max", 0, 0xffffff);

	if (!mga2->props.colorkey_min || !mga2->props.colorkey_max)
		return -ENOMEM;

	return 0;
}

static void mga25_layer_attach_properties(struct drm_device *drm,
					struct drm_mode_object *obj)
{
	struct mga2 *mga2 = drm->dev_private;

	drm_object_attach_property(obj, mga2->props.colorkey_min, 0);
	drm_object_attach_property(obj, mga2->props.colorkey_max, ~0);
	mga2->props.colorkey_min_val = 0;
	mga2->props.colorkey_max_val = ~0;
}

static int mga25_overlay_atomic_set_property(struct drm_plane *plane,
					struct drm_plane_state *state,
					struct drm_property *property,
					uint64_t val)
{
	struct mga2 *mga2 = plane->dev->dev_private;

	if (property == mga2->props.colorkey_min) {
		mga2->props.colorkey_min_val = le24_to_cpu(val);
	} else if (property == mga2->props.colorkey_max) {
		mga2->props.colorkey_max_val = le24_to_cpu(val);
	} else {
		return -EINVAL;
	}

	return 0;
}

static int mga25_overlay_atomic_get_property(struct drm_plane *plane,
					const struct drm_plane_state *state,
					struct drm_property *property,
					uint64_t *val)
{
	struct mga2 *mga2 = plane->dev->dev_private;

	if (property == mga2->props.colorkey_min) {
		*val = cpu_to_le24(mga2->props.colorkey_min_val);
	} else if (property == mga2->props.colorkey_max) {
		*val = cpu_to_le24(mga2->props.colorkey_max_val);
	} else {
		return -EINVAL;
	}

	return 0;
}

static const struct drm_plane_helper_funcs mga25_overlay_helper_funcs = {
	.atomic_disable	= mga25_overlay_atomic_disable,
	.atomic_update	= mga25_overlay_atomic_update,
	.atomic_check	= mga25_overlay_plane_atomic_check,
};

static int mga25_primary_atomic_check(struct drm_plane *plane,
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

static void mga25_primary_atomic_disable(struct drm_plane *plane,
				       struct drm_plane_state *old_state)
{
	struct mga25_crtc *mcrtc = to_mga25_crtc(old_state->crtc);
	bool fb_changed = !!old_state->fb;
	if (!old_state->crtc)
		return;
	wcrtc(MGA2_DC_CTRL_NOSCRRFRSH | rcrtc(CTRL), CTRL);
	/*
	* A scanout can still be occurring, so we can't drop the
	* reference to the old framebuffer. To solve this we get a
	* reference to old_fb and set a worker to release it later.
	*/
	if (fb_changed && !mcrtc->fb_unref_gem) {
		mcrtc->fb_unref_gem = to_mga25_framebuffer(old_state->fb)->gobj;
		drm_gem_object_get(mcrtc->fb_unref_gem);
	}
}

static int mga25_format_to_primary(struct mga25_crtc *m, u32 format)
{
	int pixfmt, big_endian = 0;

	if (format & DRM_FORMAT_BIG_ENDIAN) {
		format &= ~DRM_FORMAT_BIG_ENDIAN;
		big_endian = 1;
	}
	switch (format) {
	case DRM_FORMAT_RGBX8888:
		pixfmt = MGA2_DC_B_32BPP;
		pixfmt |= MGA2_DC_B_RGB | MGA2_DC_B_RGBX_FMT;
	break;
	case DRM_FORMAT_BGRX8888:
		pixfmt = MGA2_DC_B_32BPP;
		pixfmt |= MGA2_DC_B_BGR | MGA2_DC_B_RGBX_FMT;
	break;
	case DRM_FORMAT_XRGB8888:
		pixfmt = MGA2_DC_B_32BPP;
		pixfmt |= MGA2_DC_B_RGB | MGA2_DC_B_XRGB_FMT;
	break;
	case DRM_FORMAT_XBGR8888:
		pixfmt = MGA2_DC_B_32BPP;
		pixfmt |= MGA2_DC_B_BGR | MGA2_DC_B_XRGB_FMT;
	break;
	case DRM_FORMAT_RGB888:
		pixfmt = MGA2_DC_B_24BPP;
		pixfmt |= MGA2_DC_B_RGB;
	break;
	case DRM_FORMAT_BGR888:
		pixfmt = MGA2_DC_B_24BPP;
		pixfmt |= MGA2_DC_B_BGR;
	break;
	case DRM_FORMAT_RGB565:
		pixfmt = MGA2_DC_B_16BPP;
		pixfmt |= MGA2_DC_B_565_FMT;
		if (mga26(m->dev_id)) {
			pixfmt |= big_endian ?
				MGA26_DC_B_RGB16_SWAP_BYTES :
				MGA26_DC_B_RGB16;
		} else {
			pixfmt |= MGA2_DC_B_RGB;
		}
	break;
	case DRM_FORMAT_BGR565:
		pixfmt = MGA2_DC_B_16BPP;
		pixfmt |= MGA2_DC_B_565_FMT;
		if (mga26(m->dev_id)) {
			pixfmt |= big_endian ?
				MGA26_DC_B_BGR16_SWAP_BYTES :
				MGA26_DC_B_BGR16;
		} else {
			pixfmt |= MGA2_DC_B_BGR;
		}

	break;
	case DRM_FORMAT_XRGB1555:
		pixfmt = MGA2_DC_B_16BPP;
		pixfmt |= MGA2_DC_B_1555_FMT;
		if (mga26(m->dev_id)) {
			pixfmt |= big_endian ?
				MGA26_DC_B_RGB16_SWAP_BYTES :
				MGA26_DC_B_RGB16;
		} else {
			pixfmt |= MGA2_DC_B_RGB;
		}
	break;
	case DRM_FORMAT_XBGR1555:
		pixfmt = MGA2_DC_B_16BPP;
		pixfmt |= MGA2_DC_B_1555_FMT;
		if (mga26(m->dev_id)) {
			pixfmt |= big_endian ?
				MGA26_DC_B_BGR16_SWAP_BYTES :
				MGA26_DC_B_BGR16;
		} else {
			pixfmt |= MGA2_DC_B_BGR;
		}
	break;
	case DRM_FORMAT_XRGB4444:
		pixfmt = MGA2_DC_B_16BPP;
		pixfmt |= MGA2_DC_B_4444_FMT;
		if (mga26(m->dev_id)) {
			pixfmt |= big_endian ?
				MGA26_DC_B_RGB16_SWAP_BYTES :
				MGA26_DC_B_RGB16;
		} else {
			pixfmt |= MGA2_DC_B_RGB;
		}
	break;
	case DRM_FORMAT_XBGR4444:
		pixfmt = MGA2_DC_B_16BPP;
		pixfmt |= MGA2_DC_B_4444_FMT;
		if (mga26(m->dev_id)) {
			pixfmt |= big_endian ?
				MGA26_DC_B_BGR16_SWAP_BYTES :
				MGA26_DC_B_BGR16;
		} else {
			pixfmt |= MGA2_DC_B_BGR;
		}
	break;
	case DRM_FORMAT_C8:
		pixfmt = MGA2_DC_B_8BPP;
	break;
	default:
		return -EINVAL;
	}

	return pixfmt;
}

static void mga25_put_fb_unref_gem(void *data, async_cookie_t cookie)
{
	drm_gem_object_put(data);
}

static void mga25_primary_atomic_update(struct drm_plane *plane,
					      struct drm_plane_state *old_state)
{

	unsigned long hw_unref_time;
	struct mga25_gem_object *mo;
	struct drm_format_name_buf format_name;
	struct drm_plane_state *state = plane->state;
	struct drm_framebuffer *fb = state->fb;
	struct mga25_framebuffer *mga25_fb = to_mga25_framebuffer(fb);
	struct mga25_crtc *mcrtc = to_mga25_crtc(state->crtc);
	unsigned offset = to_mga25_obj(mga25_fb->gobj)->dma_addr;
	int x = state->src_x >> 16;
	int y = state->src_y >> 16;
	int pix = mga25_format_to_primary(mcrtc, fb->format->format);
	bool fb_changed = old_state->fb && old_state->fb != state->fb;

	WARN_ON(to_mga25_obj(mga25_fb->gobj)->dma_addr & (-1LL << 32));
	if (WARN_ON(pix < 0))
		return;

	drm_rect_debug_print("src: ", &state->src, true);
	drm_rect_debug_print("dst: ", &state->dst, false);

	offset += /*fb->offsets[0] +*/ y * fb->pitches[0] +
		x * fb->format->cpp[0];

	wcrtc(offset, NSTART);
	wcrtc(fb->pitches[0], NOFFS);
	wcrtc(pix, PIXFMT);
	wcrtc(MGA2_DC_B_STROB, DISPCTRL);
	/* just in case atomic_disable() if was called */
	wcrtc(MGA2_DC_CTRL_DEFAULT, CTRL);
	DRM_DEBUG("%s:%s (%d, %d) pitch: %d, offset: %d\n",
		plane->name,
		drm_get_format_name(fb->format->format, &format_name),
		x, y,
		fb->pitches[0], fb->offsets[0]);
	/*
	* A scanout can still be occurring, so we can't drop the
	* reference to the old framebuffer. To solve this we get
	* the time of the release of the old framebuffer in order
	* to check it while freeing.
	*/
	hw_unref_time = get_next_vblank_time(state->crtc);
	if (fb_changed) {
		mo = to_mga25_obj(to_mga25_framebuffer(old_state->fb)->gobj);
		mo->hw_unref_time = hw_unref_time;
	}
	if (mcrtc->fb_unref_gem) {
		struct drm_gem_object *gem = mcrtc->fb_unref_gem;
		mo = to_mga25_gem(gem);
		mo->hw_unref_time = hw_unref_time;
		mcrtc->fb_unref_gem = NULL;
		async_schedule(mga25_put_fb_unref_gem, gem);
	}
}

static const struct drm_plane_helper_funcs mga25_primary_helper_funcs = {
	.atomic_disable	= mga25_primary_atomic_disable,
	.atomic_update	= mga25_primary_atomic_update,
	.atomic_check	= mga25_primary_atomic_check,
};

static const struct drm_plane_funcs mga25_layer_funcs = {
	.atomic_destroy_state	= drm_atomic_helper_plane_destroy_state,
	.atomic_duplicate_state	= drm_atomic_helper_plane_duplicate_state,
	.destroy		= drm_plane_cleanup,
	.disable_plane		= drm_atomic_helper_disable_plane,
	.reset			= drm_atomic_helper_plane_reset,
	.update_plane		= drm_atomic_helper_update_plane,
	.atomic_set_property	= mga25_overlay_atomic_set_property,
	.atomic_get_property	= mga25_overlay_atomic_get_property,
};

static const uint32_t mga25_primary_formats[] = {
	DRM_FORMAT_XRGB8888,
	DRM_FORMAT_RGBX8888,
	DRM_FORMAT_XBGR8888,
	DRM_FORMAT_BGRX8888,
	DRM_FORMAT_RGB888,
	DRM_FORMAT_BGR888,
	DRM_FORMAT_RGB565,
	DRM_FORMAT_BGR565,
	DRM_FORMAT_XRGB1555,
	DRM_FORMAT_XBGR1555,
#ifdef __BIG_ENDIAN
	DRM_FORMAT_XRGB4444,
	DRM_FORMAT_XBGR4444,
#endif
	DRM_FORMAT_C8,
};

static const uint32_t mga25_cursor_formats[] = {
	DRM_FORMAT_ARGB8888,
};

static const uint32_t mga25_overlay_formats[] = {
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

static const struct mga25_plane_desc mga25_planes[] = {
	{
		.type = DRM_PLANE_TYPE_PRIMARY,
		.formats = mga25_primary_formats,
		.nformats = ARRAY_SIZE(mga25_primary_formats),
		.func = &mga25_primary_helper_funcs,
	},
	{
		.type = DRM_PLANE_TYPE_CURSOR,
		.formats = mga25_cursor_formats,
		.nformats = ARRAY_SIZE(mga25_cursor_formats),
		.func = &mga25_cursor_helper_funcs,
	},

	{ /* must be the last */
		.type = DRM_PLANE_TYPE_OVERLAY,
		.formats = mga25_overlay_formats,
		.nformats = ARRAY_SIZE(mga25_overlay_formats),
		.func = &mga25_overlay_helper_funcs,
	},
};

static struct mga25_layer *mga25_layer_init_one(struct drm_device *drm,
					const struct mga25_plane_desc *plane)
{
	struct mga25_layer *layer;
	int ret;

	layer = devm_kzalloc(drm->dev, sizeof(*layer), GFP_KERNEL);
	if (!layer)
		return ERR_PTR(-ENOMEM);

	/* possible crtcs are set later */
	ret = drm_universal_plane_init(drm, &layer->plane, 0,
				       &mga25_layer_funcs,
				       plane->formats, plane->nformats,
				       NULL, plane->type, NULL);
	if (ret) {
		dev_err(drm->dev, "Couldn't initialize layer\n");
		return ERR_PTR(ret);
	}

	if (plane->type == DRM_PLANE_TYPE_OVERLAY) {
		ret = mga25_layer_create_properties(drm);
		if (ret) {
			dev_err(drm->dev, "Couldn't create layer properties\n");
			return ERR_PTR(ret);
		}

		mga25_layer_attach_properties(drm, &layer->plane.base);

		ret = drm_plane_create_alpha_property(&layer->plane);
		if (ret)
			return ERR_PTR(ret);
	}
	drm_plane_helper_add(&layer->plane, plane->func);

	return layer;
}

static struct drm_plane **mga25_layers_init(struct mga25_crtc *mcrtc,
					    struct drm_device *drm)
{
	struct drm_plane **planes;
	int i;
	int n = mga25(mcrtc->dev_id) ? ARRAY_SIZE(mga25_planes) :
			 ARRAY_SIZE(mga25_planes) - 1;
	planes = devm_kcalloc(drm->dev, ARRAY_SIZE(mga25_planes) + 1,
			      sizeof(*planes), GFP_KERNEL);
	if (!planes)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < n; i++) {
		const struct mga25_plane_desc *plane = &mga25_planes[i];
		struct mga25_layer *layer;

		layer = mga25_layer_init_one(drm, plane);
		if (IS_ERR(layer)) {
			return ERR_CAST(layer);
		};
		planes[i] = &layer->plane;
	}

	return planes;
}
