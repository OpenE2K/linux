/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#define DEBUG

#include "mga2_drv.h"

#define MGA2_GAMMA_SIZE	256

#define	__rcrtc(__addr) readl(mcrtc->regs + MGA2_DC0_ ## __addr)
#define	__wcrtc(__v, __addr) writel(__v, mcrtc->regs + MGA2_DC0_ ## __addr)

#ifdef DEBUG
#define rcrtc(__offset)				\
({								\
	unsigned __val = __rcrtc(__offset);			\
	DRM_DEBUG_KMS("%x:R: %x:%s\n", mcrtc->index,	\
			__val, # __offset);			\
	__val;							\
})

#define wcrtc(__val, __offset)	do {				\
	unsigned __val2 = __val;				\
	DRM_DEBUG_KMS("%x:W: %x:%s\n", mcrtc->index,	\
			__val2, # __offset);			\
	__wcrtc(__val2, __offset);				\
} while (0)

#else
#define		rcrtc		__rcrtc
#define		wcrtc		__wcrtc
#endif

static int mga2_cursor_init(struct drm_crtc *crtc);
static void mga2_cursor_fini(struct drm_crtc *crtc);

static int __mga2_get_vid(struct drm_connector *connector)
{
	int vid = 0, id;
	struct drm_connector *c;
	struct drm_connector_list_iter conn_iter;
	id = connector->connector_type_id;
	drm_connector_list_iter_begin(connector->dev, &conn_iter);
	drm_for_each_connector_iter(c, &conn_iter) {
		if (id == c->connector_type_id)
			break;
		vid++;
	}
	drm_connector_list_iter_end(&conn_iter);

	return vid;
}

static int mga2_get_vid(struct drm_connector *connector)
{
	int vid = 0, id, i;
	struct drm_connector *c;
	struct drm_connector_list_iter conn_iter;
	switch (connector->connector_type) {
	case DRM_MODE_CONNECTOR_VGA:
		return __mga2_get_vid(connector);
		break;
	case DRM_MODE_CONNECTOR_DVID:
		vid = 0;
		break;
	case DRM_MODE_CONNECTOR_HDMIA:
		i = 0;
		vid = 1;
		id = connector->connector_type_id;
		drm_connector_list_iter_begin(connector->dev, &conn_iter);
		drm_for_each_connector_iter(c, &conn_iter) {
			if (c->connector_type != DRM_MODE_CONNECTOR_HDMIA)
				continue;
			i++;
			BUG_ON(i > 2);
			if (id == c->connector_type_id)
				continue;
			/* FIXME: only 2 hdmi supported */
			vid = id < c->connector_type_id ? 1 : 2;
			break;
		}
		drm_connector_list_iter_end(&conn_iter);
		break;
	case DRM_MODE_CONNECTOR_LVDS:
		vid = 3;
		break;
	default:
		BUG();
	}
	return vid;
}

static void __mga2_vid_dpms(struct drm_crtc *crtc,
			struct drm_connector *connector, int mode)
{
	int i;
	struct mga2 *mga2 = crtc->dev->dev_private;
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	void __iomem *vid_regs = mga2->regs + mga2->info->vid_regs_base +
				mga2_get_vid(connector) * MGA2_VID0_SZ;
	u32 omux = rvidc(MUX);
	u32 mux = omux & ~(MGA2_VID_B_MUX_ALL << MGA2_VID_B_MUX_OFFSET);
	u32 ctrl = rvidc(CTRL) & ~MGA2_VID0_B_ENABLE;

	if (mode == DRM_MODE_DPMS_ON)
		mux |= (mcrtc->index + MGA2_VID_B_MUX_DC0)
			 << MGA2_VID_B_MUX_OFFSET;
	if (mux == omux) /*everything is already set */
		return;

	switch (connector->connector_type) {
	case DRM_MODE_CONNECTOR_VGA:
	case DRM_MODE_CONNECTOR_DVID:
		ctrl &= ~((MGA2_VID0_B_MODE_ALL <<
			 	MGA2_VID0_B_MODE_OFFSET) |
			(MGA2_VID0_B_STROBE_DELAY_ALL <<
				MGA2_VID0_B_STROBE_DELAY_OFFSET) |
			MGA2_VID0_B_2XDDR_EN_RESYNC);
		if (crtc->mode.clock > 165000) { /* dual link */
			ctrl |= (MGA2_VID0_B_MODE_2XDDR <<
					MGA2_VID0_B_MODE_OFFSET) /*|
					MGA2_VID0_B_2XDDR_EN_RESYNC*/;
		} else {
			ctrl |= MGA2_VID0_B_MODE_1XDDR <<
					MGA2_VID0_B_MODE_OFFSET;
		}

		ctrl |= MGA2_VID0_B_STROBE_DELAY_1_4 <<
				MGA2_VID0_B_STROBE_DELAY_OFFSET;
		break;
	case DRM_MODE_CONNECTOR_HDMIA:
		ctrl &= ~(MGA2_VID12_B_HDMI_RSTZ |
			(MGA2_VID12_B_CONV_ALL << MGA2_VID12_B_DE_CONV_OFFSET) |
			(MGA2_VID12_B_CONV_ALL << MGA2_VID12_B_HS_CONV_OFFSET) |
			(MGA2_VID12_B_CONV_ALL << MGA2_VID12_B_VS_CONV_OFFSET) |
			MGA2_VID12_B_USE_MGA2_DDC);

		ctrl |= (MGA2_VID12_B_CONV_DIRECT << MGA2_VID12_B_DE_CONV_OFFSET) |
			(MGA2_VID12_B_CONV_DIRECT << MGA2_VID12_B_HS_CONV_OFFSET) |
			(MGA2_VID12_B_CONV_DIRECT << MGA2_VID12_B_VS_CONV_OFFSET) |
			MGA2_VID12_B_USE_MGA2_DDC;
		wvidc(ctrl, CTRL); /*XXX: change mux only under reset*/
		ctrl |= MGA2_VID12_B_HDMI_RSTZ;
		break;
	case DRM_MODE_CONNECTOR_LVDS:
		ctrl = 0;
		for (i = 0; i < mga2->used_lvds_channels; i++) {
			ctrl |= i << (MGA2_VID3_B_P0CHAN_OFFSET + i * 2);
			ctrl |= 1 << (MGA2_VID3_B_P0ENA_OFFSET + i);
		}
		ctrl |= ilog2(mga2->used_lvds_channels) | MGA2_VID3_B_RESYNC;

		break;
	default:
		BUG();
	}

	wvidc(ctrl, CTRL);
	wvidc(mux, MUX);
	if (mode == DRM_MODE_DPMS_ON)
		wvidc(ctrl | MGA2_VID0_B_ENABLE, CTRL);

	rvidc(RESYNC_CTRL);

	/* FIXME: workaround for hw bug: vertical lines at gradient stipes */
	if (mga2_p2(mga2) && mode == DRM_MODE_DPMS_ON &&
			connector->connector_type == DRM_MODE_CONNECTOR_LVDS) {
		u32 *v = mga2->lvds_frame_table;
		for (i = 0; i < ARRAY_SIZE(mga2->lvds_frame_table); i++)
			wvidc(v[i] | (i << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
	}
}

static void __mga25_vid_dpms(struct drm_crtc *crtc,
			struct drm_connector *connector, int mode)
{
	struct mga2 *mga2 = crtc->dev->dev_private;
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	void __iomem *vid_regs = mga2->regs + mga2->info->vid_regs_base +
			 	mga2_get_vid(connector) * MGA2_VID0_SZ;
	u32 omux = rvidc(MUX), mux = 0, i;
	u32 ctrl = rvidc(CTRL) & ~MGA2_VID0_B_ENABLE;


	if (mode == DRM_MODE_DPMS_ON)
		mux |= ((mcrtc->index) << MGA25_VID0_B_AUSEL_OFFSET) |
			MGA25_VID0_B_AUENA |
			((mcrtc->index) << MGA25_VID0_B_PXSEL_OFFSET) |
			MGA25_VID0_B_PXENA;

	if (mux == omux) /*everything is already set */
		return;

	switch (connector->connector_type) {
	case DRM_MODE_CONNECTOR_VGA:
	case DRM_MODE_CONNECTOR_DVID:
		ctrl = MGA2_VID0_B_2XDDR_EN_RESYNC |
				(MGA2_VID0_B_STROBE_DELAY_1_4 <<
				MGA2_VID0_B_STROBE_DELAY_OFFSET);
		break;
	case DRM_MODE_CONNECTOR_HDMIA:
		ctrl &= ~(MGA2_VID12_B_ENABLE |
			(MGA2_VID12_B_CONV_ALL << MGA2_VID12_B_DE_CONV_OFFSET) |
			(MGA2_VID12_B_CONV_ALL << MGA2_VID12_B_HS_CONV_OFFSET) |
			(MGA2_VID12_B_CONV_ALL << MGA2_VID12_B_VS_CONV_OFFSET));

		ctrl |= (MGA2_VID12_B_CONV_DIRECT << MGA2_VID12_B_DE_CONV_OFFSET) |
			(MGA2_VID12_B_CONV_DIRECT << MGA2_VID12_B_HS_CONV_OFFSET) |
			(MGA2_VID12_B_CONV_DIRECT << MGA2_VID12_B_VS_CONV_OFFSET);
		ctrl |= MGA2_VID12_B_ENABLE;
		break;
	case DRM_MODE_CONNECTOR_LVDS:
		mux |= MGA25_VID3_B_SCALER_OFF;
		ctrl = MGA2_VID3_B_10BIT;
		for (i = 0; i < mga2->used_lvds_channels; i++) {
			ctrl |= i << (MGA2_VID3_B_P0CHAN_OFFSET + i * 2);
			ctrl |= 1 << (MGA2_VID3_B_P0ENA_OFFSET + i);
		}
		ctrl |= ilog2(mga2->used_lvds_channels) | MGA2_VID3_B_RESYNC;

		break;
	default:
		WARN_ON(1);
	}
	wvidc(ctrl, CTRL);
	wvidc(mux, MUX);

	if (mode == DRM_MODE_DPMS_ON)
		wvidc(ctrl | MGA2_VID0_B_ENABLE, CTRL);

	/*hw bug 130094, comment 9*/
	if (mga25(mga2) && mode == DRM_MODE_DPMS_ON &&
			connector->connector_type == DRM_MODE_CONNECTOR_LVDS) {
		char v[] = {
			19,  4,  5,  6,  7,  8,  9,
			28, 29, 14, 15, 16, 17, 18,
			34, 35, 36, 24, 25, 26, 27,
			32, 22, 23, 12, 13,  2, 3,
			32, 20, 21, 10, 11,  0, 1,
			33, 33, 32, 32, 32, 33, 33,
		};
		for (i = 0; i < ARRAY_SIZE(v); i++)
			wvidc(v[i] | (i << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
	}
	if (0) {
		wvidc(LVDS25_00 | (0 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_B9 | (1 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_B8 | (2 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_G9 | (3 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_G8 | (4 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_R9 | (5 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_R8 | (6 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);

		wvidc(LVDS25_01 | (7 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_01 | (8 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_00 | (9 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_00 | (10 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_00 | (11 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_01 | (12 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_01 | (13 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);

		wvidc(LVDS25_G0 | (14 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_R5 | (15 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_R4 | (16 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_R3 | (17 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_R2 | (18 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_R1 | (19 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_R0 | (20 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);

		wvidc(LVDS25_B1 | (21 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_B0 | (22 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_G5 | (23 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_G4 | (24 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_G3 | (25 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_G2 | (26 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_G1 | (27 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);

		wvidc(LVDS25_DE | (28 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_VS | (29 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_HS | (30 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_B5 | (31 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_B4 | (32 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_B3 | (33 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_B2 | (34 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);

		wvidc(LVDS25_00 | (35 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_B7 | (36 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_B6 | (37 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_G7 | (38 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_G6 | (39 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_R7 | (40 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
		wvidc(LVDS25_R6 | (41 << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);
	}
}

static void mga2_vid_dpms(struct drm_crtc *crtc,
			struct drm_connector *connector, int mode)
{
	struct mga2 *mga2 = crtc->dev->dev_private;
	mga25(mga2) ? __mga25_vid_dpms(crtc, connector, mode) :
			 __mga2_vid_dpms(crtc, connector, mode);
}

static void mga2_vids_dpms(struct drm_crtc *crtc, int mode)
{
	struct drm_device *dev = crtc->dev;
	struct drm_connector *connector;
	struct mga2 *mga2 = crtc->dev->dev_private;

	if (mga2->subdevice == MGA2_P2_PROTO)
		return;

	list_for_each_entry(connector, &dev->mode_config.connector_list, head) {
		if (!connector->encoder ||
				   connector->encoder->crtc != crtc)
			continue;
		mga2_vid_dpms(crtc, connector, mode);
	}
}

#define TIMEOUT_PLL_USEC	(50 * 1000)

#define mga2_wait_bit(__reg, __bitmask) do {		\
	int __i;					\
	u32 __b = __bitmask;				\
	for (__i = 0; __i < TIMEOUT_PLL_USEC / 10; __i++) {	\
		if ((__rcrtc(__reg) & __b) == __b)	\
			break;				\
		udelay(10);				\
	}						\
	if (__i == TIMEOUT_PLL_USEC / 10) {		\
		DRM_ERROR("timeout on waiting %s bit set\n", #__bitmask); \
		ret = -ETIME;				\
		goto out;				\
	}						\
} while(0)

#define mga2_wait_bit_clear(__reg, __bitmask) do {	\
	int __i;					\
	u32 __b = __bitmask;				\
	for (__i = 0; __i < TIMEOUT_PLL_USEC / 10; __i++) {	\
		if ((__rcrtc(__reg) & __b) == 0)	\
			break;				\
		udelay(10);				\
	}						\
	if (__i == TIMEOUT_PLL_USEC / 10) {		\
		DRM_ERROR("timeout on waiting %s bit clear\n", #__bitmask); \
		ret = -ETIME;				\
		goto out;				\
	}						\
} while(0)

enum mga2_clks {
	CLN40G = 44,
	CLN16FF
};
static int __mga2_calc_int_pll(struct mga2_clk *clk, unsigned long long fout,
		const struct mga2_div *d, struct mga2_div *div, int pll_type)
{
	bool found = false;
	int ret = -EINVAL, i, k = 0;
	unsigned long long merr = ULLONG_MAX, err, mfvco = 1, fvco;
	for (i = 0; d[i].pix && merr; i++) {
		unsigned long long a, b, fa, fb;
		struct mga2_clk c;
		switch (pll_type) {
		case CLN40G:
			ret = mga2_calc_int_pll(&c, fout * d[i].pix, &fvco, &err);
			break;
		case CLN16FF:
			ret = mga25_calc_int_pll(&c, fout * d[i].pix, &fvco, &err);
			break;
		default:
			BUG();
		}
		if (ret)
			continue;
		a = merr / (fout * d[k].pix);
		b =  err / (fout * d[i].pix);
		if (b > a)
			continue;
		if (b < a)
			goto found;
		fa = merr % (fout * d[k].pix);
		fb =  err % (fout * d[i].pix);
		if (fb < fa)
			goto found;

		continue;
found:
		mfvco = fvco;
		merr = err;
		k = i;
		*clk = c;
		found = true;
	}
	memcpy(div, d + k, sizeof(*d));
	fout *= div->pix;
	if (!found) {
		DRM_ERROR("failed to calculate PLL setup.\n");
	} else {
		DRM_DEBUG_KMS("Calculated: %lld kHz => %lld kHz"
			" (err: %lld.%02lld%%)"
			", Fvco = %lld\n"
			"\tPLL setup: ",
			fout / 1000, mfvco / clk->od / 1000,
			merr * 100   / fout,
			merr * 10000 / fout % 100,
			mfvco);
		switch (pll_type) {
		case CLN40G:
		DRM_DEBUG_KMS("nr=%d nf=%lld od=%d nb=%d\n",
				clk->nr, clk->nf, clk->od, clk->nb);
			break;
		case CLN16FF:
		DRM_DEBUG_KMS("nr=%d nf=%lld.%lld od=%d\n",
				clk->nr, clk->nf_i, clk->nf_f, clk->od);
			break;
		default:
			BUG();
		}
		ret = 0;
	}
	return ret;
}

static int mga2_int_pll_set_pixclock(struct drm_crtc *crtc,
		unsigned long clock_khz,
		const struct mga2_div *d, struct mga2_div *div)
{
	unsigned val;
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	struct mga2_clk clk = {};
	int ret = __mga2_calc_int_pll(&clk, clock_khz * 1000, d, div, CLN40G);
	if (ret)
		goto out;

	/* enabling gpll0 */
	val = rcrtc(CLKCTRL) & ~MGA2_DC_B_ARST;
	wcrtc(val, CLKCTRL);

	/* switching PIXMUX & AUXMUX to reference */
	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_PIXMUX_UPD
					| MGA2_DC_B_AUXMUX_UPD);
	val = rcrtc(CLKCTRL);
	val &= ~(MGA2_DC_B_CLKMUX_ALL << MGA2_DC_B_PIXMUX_SEL_OFFSET);
	val |= MGA2_DC_B_PIXMUX_BYPASS;
	val &= ~(MGA2_DC_B_CLKMUX_ALL << MGA2_DC_B_AUXMUX_SEL_OFFSET);
	val |= MGA2_DC_B_AUXMUX_BYPASS;
	wcrtc(val, CLKCTRL);
	val |= MGA2_DC_B_PIXMUX_UPD | MGA2_DC_B_AUXMUX_UPD;
	wcrtc(val, CLKCTRL);
	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_PIXMUX_UPD
					| MGA2_DC_B_AUXMUX_UPD);

	/* resetting PLL */
	wcrtc(MGA2_DC_B_INTPLL_RESET, INTPLLCTRL);
	/* configuring channel #0 */
	wcrtc(clk.nf - 1, INTPLLCLKF0);
	wcrtc(clk.nr - 1, INTPLLCLKR0);
	wcrtc(clk.od - 1, INTPLLCLKOD0);
	wcrtc(clk.nb - 1, INTPLLBWADJ0);

	udelay(5);
	/* clearing reset and waiting for lock */
	wcrtc(0, INTPLLCTRL);
	udelay(5);
	mga2_wait_bit(INTPLLCTRL, MGA2_DC_B_INTPLL_LOCK);
	/* waiting for clock sense */
	mga2_wait_bit(CLKCTRL, MGA2_DC_B_AUXMUX_SENSE1 |
				MGA2_DC_B_PIXMUX_SENSE1);
out:
	return ret;
}

static int mga2_ext_pll_set_pixclock(struct drm_crtc *crtc,
			unsigned long clock_khz,
			const struct mga2_div *d, struct mga2_div *div)
{
	int ret;
	unsigned clkctrl;
	struct mga2 *mga2 = crtc->dev->dev_private;
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	memcpy(div, d, sizeof(*d));
	clock_khz *= div->pix;

	ret = _mga2_ext_pll_set_pixclock(mcrtc->pll,
					      mcrtc->i2c, clock_khz);

	if (ret)
		goto out;
	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_EXTDIV_UPD);
	clkctrl = rcrtc(CLKCTRL) & ~(MGA2_DC_B_ARST | MGA2_DC_B_EXTDIV_BYPASS |
				     (3 << MGA2_DC_B_EXTDIV_SEL_OFFSET));
	clkctrl |= mga2->subdevice == MGA2_P2_PROTO ?
			(1 << MGA2_DC_B_EXTDIV_SEL_OFFSET) :
			 MGA2_DC_B_EXTDIV_BYPASS;
	clkctrl |= MGA2_DC_B_EXTDIV_ENA;
	wcrtc(clkctrl, CLKCTRL);
	clkctrl |= MGA2_DC_B_EXTDIV_UPD;
	wcrtc(clkctrl, CLKCTRL);

	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_EXTDIV_UPD);
	/* waiting for clock sense */
	mga2_wait_bit(CLKCTRL, MGA2_DC_B_AUXMUX_SENSE0 |
				MGA2_DC_B_PIXMUX_SENSE0);
out:
	return ret;
}

static struct drm_connector *mga2_get_connector(struct drm_crtc *crtc)
{
	struct drm_device *dev = crtc->dev;
	struct drm_connector *connector;

	list_for_each_entry(connector, &dev->mode_config.connector_list, head) {
		if (!connector->encoder ||
				connector->encoder->crtc != crtc)
			continue;
		return connector;
	}
	return NULL;
}

static const struct mga2_div mga2_default_div[] = {
	{1, 1}, {2, 2}, {4, 4}, {6, 6}, {7, 7}, {}
};
static const struct mga2_div mga2_dvi_duallink_div[] = {
	{2, 1}, {4, 2}, {}
};
static const struct mga2_div mga2_lvds_div[][2] = {
	{ {} },
	{ {7, 1}, {} },
	{ {7, 2}, {} },
	{ {} },
	{ {7, 4}, {} }
};

static int mga2_pll_set_pixclock(struct drm_crtc *crtc,
		unsigned long clock_khz, struct mga2_div *div)
{
	int ret;
	struct mga2 *mga2 = crtc->dev->dev_private;
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	struct drm_connector *connector = mga2_get_connector(crtc);
	const struct mga2_div *d = mga2_default_div;

	switch (connector->connector_type) {
	case DRM_MODE_CONNECTOR_DVID:
		if (clock_khz <= 165000)
			d = mga2_dvi_duallink_div;
		break;
	case DRM_MODE_CONNECTOR_HDMIA:
		break;
	case DRM_MODE_CONNECTOR_LVDS:
		d = mga2_lvds_div[mga2->used_lvds_channels];
		break;
	case DRM_MODE_CONNECTOR_VGA:
			div->pix = 4;
		break;
	default:
		BUG();
	}

	ret = mcrtc->i2c ?
		mga2_ext_pll_set_pixclock(crtc, clock_khz, d, div) :
		mga2_int_pll_set_pixclock(crtc, clock_khz, d, div);

	DRM_DEBUG("clock: %ld, pixdiv: %d, auxdiv: %d\n",
		  clock_khz, div->pix, div->aux);
	return ret;
}

static int mga2_crtc_setup_div(struct drm_crtc *crtc, struct mga2_div *div)
{
	int ret = 0;
	u32 val;
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);

	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_PIXDIV_UPD);
	val = rcrtc(CLKCTRL) & ~(MGA2_DC_B_PIXDIV_BYPASS |
		(MGA2_DC_B_CLKDIV_ALL << MGA2_DC_B_PIXDIV_SEL_OFFSET));

	switch (div->pix) {
	case 1:
		val |= MGA2_DC_B_PIXDIV_BYPASS;
		break;
	case 2:
		val |= MGA2_DC_B_CLKDIV_DIV2 << MGA2_DC_B_PIXDIV_SEL_OFFSET;
		break;
	case 4:
		val |= MGA2_DC_B_CLKDIV_DIV4 << MGA2_DC_B_PIXDIV_SEL_OFFSET;
		break;
	case 6:
		val |= MGA2_DC_B_CLKDIV_DIV6 << MGA2_DC_B_PIXDIV_SEL_OFFSET;
		break;
	case 7:
		val |= MGA2_DC_B_CLKDIV_DIV7 << MGA2_DC_B_PIXDIV_SEL_OFFSET;
		break;
	default:
		BUG();
	}
	val |= MGA2_DC_B_PIXDIV_ENA;
	wcrtc(val, CLKCTRL);
	val |= MGA2_DC_B_PIXDIV_UPD;
	wcrtc(val, CLKCTRL);
	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_PIXDIV_UPD);

	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_AUXDIV_UPD);
	val = rcrtc(CLKCTRL) & ~(MGA2_DC_B_AUXDIV_BYPASS |
		(MGA2_DC_B_CLKDIV_ALL << MGA2_DC_B_AUXDIV_SEL_OFFSET));

	switch (div->aux) {
	case 1:
		val |= MGA2_DC_B_AUXDIV_BYPASS;
		break;
	case 2:
		val |= MGA2_DC_B_CLKDIV_DIV2 << MGA2_DC_B_AUXDIV_SEL_OFFSET;
		break;
	case 4:
		val |= MGA2_DC_B_CLKDIV_DIV4 << MGA2_DC_B_AUXDIV_SEL_OFFSET;
		break;
	case 6:
		val |= MGA2_DC_B_CLKDIV_DIV6 << MGA2_DC_B_AUXDIV_SEL_OFFSET;
		break;
	case 7:
		val |= MGA2_DC_B_CLKDIV_DIV7 << MGA2_DC_B_PIXDIV_SEL_OFFSET;
		break;
	default:
		BUG();
	}
	val |= MGA2_DC_B_AUXDIV_ENA;
	wcrtc(val, CLKCTRL);
	val |= MGA2_DC_B_AUXDIV_UPD;
	wcrtc(val, CLKCTRL);
	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_AUXDIV_UPD);
out:
	return ret;
}

static int __mga2_setup_clock(struct drm_crtc *crtc,
					struct drm_display_mode *mode)
{
	int ret = 0;
	u32 val;
	struct mga2_div div;
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	int int_pll = mcrtc->i2c ? 0 : 1;

	ret = mga2_pll_set_pixclock(crtc, mode->clock, &div);
	if (ret)
		goto out;

	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_PIXMUX_UPD);
	val = rcrtc(CLKCTRL) & ~(MGA2_DC_B_PIXMUX_BYPASS |
			(MGA2_DC_B_CLKMUX_ALL << MGA2_DC_B_PIXMUX_SEL_OFFSET));
	val |= (int_pll << MGA2_DC_B_PIXMUX_SEL_OFFSET);
	wcrtc(val, CLKCTRL);
	val |= MGA2_DC_B_PIXMUX_UPD;
	wcrtc(val, CLKCTRL);
	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_PIXMUX_UPD);

	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_AUXMUX_UPD);
	val = rcrtc(CLKCTRL) & ~(MGA2_DC_B_AUXMUX_BYPASS |
		(MGA2_DC_B_CLKMUX_ALL << MGA2_DC_B_AUXMUX_SEL_OFFSET));
	val |= (int_pll << MGA2_DC_B_AUXMUX_SEL_OFFSET);
	wcrtc(val, CLKCTRL);
	val |= MGA2_DC_B_AUXMUX_UPD;
	wcrtc(val, CLKCTRL);
	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_AUXMUX_UPD);
	ret = mga2_crtc_setup_div(crtc, &div);
	if (ret)
		goto out;
out:
	return ret;
}

static int mga25_int_pll_set_pixclock(struct drm_crtc *crtc,
		unsigned long clock_khz,
		const struct mga2_div *d, struct mga2_div *div)
{
	unsigned v;
	struct mga2 *mga2 = crtc->dev->dev_private;
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	struct mga2_clk clk = {};
	int ret = 0;
	if (mga2_proto(mga2))
		goto out;
	ret = __mga2_calc_int_pll(&clk, clock_khz * 1000, d, div, CLN16FF);
	if (ret)
		goto out;

	/* switching PIXMUX & AUXMUX to reference */
	mga2_wait_bit_clear(CLKCTRL, MGA25_DC_B_INPROGRESS);
	v = rcrtc(CLKCTRL);
	v |= MGA25_DC_B_FPIXENA;
	wcrtc(v, CLKCTRL);
	mga2_wait_bit_clear(CLKCTRL, MGA25_DC_B_INPROGRESS);

	/* resetting PLL */
	wcrtc(MGA2_DC_B_INTPLL_RESET, PLLCTRL_25);

	wcrtc(clk.nf_i, PLLCLKF0INT_25);
	wcrtc((clk.nf_f) >> 1, PLLCLKF0FRAC_25);
	wcrtc(clk.nr - 1, PLLCLKR0_25);
	wcrtc(clk.od - 1, PLLCLKOD0_25);

	udelay(5);
	/* clearing reset and waiting for lock */
	wcrtc(0, PLLCTRL_25);
	udelay(5);
	mga2_wait_bit(PLLCTRL_25, MGA2_DC_B_INTPLL_LOCK);
out:
	return ret;
}

static const struct mga2_div mga25_default_div[] = {
	{1, 1}, {},
	/*{1, 1}, {}, {2, 2}, {4, 4}, {6, 6}, {7, 7}, {8, 8}, {9, 9}, {}*/
};
static const struct mga2_div mga25_dvi_duallink_div[] = {
	{2, 1}, {4, 2}, {}
};
static const struct mga2_div mga25_lvds_div[][2] = {
	{ {} },
	{ {7, 1}, {} },
	{ {7, 2}, {} },
	{ {} },
	{ {7, 4}, {} }
};

static int mga25_div2val(int div)
{
	int v[10] = {0, 0, 2, 3, 4, 5, 6, 7, 0, 1};
	BUG_ON(div > ARRAY_SIZE(v));
	return v[div];
}

static int mga25_div2sel(int div)
{
	return div == 1 ? 2 : 3;
}

static int __mga25_setup_clock(struct drm_crtc *crtc,
					struct drm_display_mode *mode)
{
	int ret = 0;
	u32 v;
	struct mga2 *mga2 = crtc->dev->dev_private;
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	struct drm_connector *connector = mga2_get_connector(crtc);
	unsigned long clock_khz;
	const struct mga2_div *d = mga25_default_div;
	struct mga2_div dd = {
		.pix = 1,
		.aux = 1
	}, *div = &dd;

	switch (connector->connector_type) {
	case DRM_MODE_CONNECTOR_DVID:
		if (clock_khz <= 165000)
			d = mga25_dvi_duallink_div;
		break;
	case DRM_MODE_CONNECTOR_HDMIA:
		break;
	case DRM_MODE_CONNECTOR_LVDS:
		d = mga25_lvds_div[mga2->used_lvds_channels];
		break;
	case DRM_MODE_CONNECTOR_VGA:
		div->pix = 2;
		div->aux = 1;
		break;
	default:
		BUG();
	}
	clock_khz = mode->clock * div->pix;
	ret = mcrtc->i2c ?
		_mga2_ext_pll_set_pixclock(mcrtc->pll, mcrtc->i2c, clock_khz) :
		mga25_int_pll_set_pixclock(crtc, clock_khz, d, div);
	if (ret)
		goto out;

	mga2_wait_bit_clear(CLKCTRL, MGA25_DC_B_INPROGRESS);
	v = MGA25_DC_B_FAUXENA |
		(mga25_div2sel(div->aux) << MGA25_DC_B_FAUXSEL_OFFSET) |
		(mga25_div2val(div->aux) << MGA25_DC_B_FAUXDIV_OFFSET) |
		MGA25_DC_B_FPIXENA |
		(mga25_div2sel(div->pix) << MGA25_DC_B_FPIXSEL_OFFSET) |
		(mga25_div2val(div->pix) << MGA25_DC_B_FPIXDIV_OFFSET);
	wcrtc(v, CLKCTRL);
	DRM_DEBUG("clock: %ld, pixdiv: %d, auxdiv: %d\n",
		  clock_khz, div->pix, div->aux);
out:
	return ret;
}

static int mga2_setup_clock(struct drm_crtc *crtc,
					struct drm_display_mode *mode)
{
	struct mga2 *mga2 = crtc->dev->dev_private;
	return mga25(mga2) ? __mga25_setup_clock(crtc, mode) :
			 __mga2_setup_clock(crtc, mode);
}

static int mga2_crtc_mode_set(struct drm_crtc *crtc,
					struct drm_display_mode *mode)
{
	struct mga2 *mga2 = crtc->dev->dev_private;
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	uint32_t hvctrl;
	int ret = 0;

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

	if ((ret = mga2_setup_clock(crtc, mode)))
		goto out;

	wcrtc(hsync, HSYNC);
	wcrtc(hgdel, HDELAY);
	wcrtc(hgate, HVIS);
	wcrtc(hlen, HTOT);
	wcrtc(vsync, VSYNC);
	wcrtc(vgdel, VDELAY);
	wcrtc(vgate, VVIS);
	wcrtc(vlen, VTOT);


	hvctrl = MGA2_DC_B_DE_ENA;
	if (mga2_lvds_channels && mga2->subdevice == MGA25) /*FIXME:*/
		hvctrl |= MGA2_DC_B_VSYNC_POL | MGA2_DC_B_HSYNC_POL;

	if (mode->flags & DRM_MODE_FLAG_NVSYNC)
		hvctrl |= MGA2_DC_B_VSYNC_POL | MGA2_DC_B_VSYNC_ENA;
	else if (mode->flags & DRM_MODE_FLAG_PVSYNC)
		hvctrl |= MGA2_DC_B_VSYNC_ENA;

	if (mode->flags & DRM_MODE_FLAG_NHSYNC)
		hvctrl |= MGA2_DC_B_HSYNC_POL | MGA2_DC_B_HSYNC_ENA;
	else if (mode->flags & DRM_MODE_FLAG_PHSYNC)
		hvctrl |= MGA2_DC_B_HSYNC_ENA;

	if (mode->flags & DRM_MODE_FLAG_CSYNC ||
	    mga2->subdevice == MGA2_P2_PROTO)
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
	mga2_vids_dpms(crtc, DRM_MODE_DPMS_ON);

out:
	return ret;
}

static void mga2_crtc_atomic_begin(struct drm_crtc *crtc,
				    struct drm_crtc_state *old_state)
{
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
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

static void mga2_write_gamma_table(struct drm_crtc *crtc,
				     struct drm_crtc_state *old_state)
{
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	struct drm_color_lut *lut;
	int i;

	if (!crtc || !crtc->state)
		return;
	if (!crtc->state->color_mgmt_changed)
		return;
	if (!crtc->state->gamma_lut || drm_color_lut_size(
			crtc->state->gamma_lut) != MGA2_GAMMA_SIZE) {
		wcrtc(0, GAMCTRL);
		return;
	}

	lut = (struct drm_color_lut *)crtc->state->gamma_lut->data;

	for (i = 0; i < MGA2_GAMMA_SIZE; i++) {
		u32 word;
		word = (i << MGA2_DC_GAMSET_ADDR_OFFSET) |
			MGA2_DC_GAMSET_SEL_RED |
				drm_color_lut_extract(lut[i].red, 8);
		wcrtc(word, GAMSET);
		word = (i << MGA2_DC_GAMSET_ADDR_OFFSET) |
			MGA2_DC_GAMSET_SEL_GREEN |
				drm_color_lut_extract(lut[i].green, 8);
		wcrtc(word, GAMSET);
		word = (i << MGA2_DC_GAMSET_ADDR_OFFSET) |
			MGA2_DC_GAMSET_SEL_BLUE |
				drm_color_lut_extract(lut[i].blue, 8);
		wcrtc(word, GAMSET);
	}
	wcrtc(MGA2_DC_GAMCTRL_ENABLE, GAMCTRL);
}

static void mga2_crtc_atomic_flush(struct drm_crtc *crtc,
				    struct drm_crtc_state *old_crtc_state)
{
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	struct drm_pending_vblank_event *event = crtc->state->event;

	DRM_DEBUG_DRIVER("Committing plane changes\n");

	mga2_write_gamma_table(crtc, old_crtc_state);
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

static void mga2_crtc_atomic_disable(struct drm_crtc *crtc,
				      struct drm_crtc_state *old_state)
{
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	wcrtc(MGA2_DC_CTRL_SOFT_RESET | MGA2_DC_CTRL_DEFAULT, CTRL);

	DRM_DEBUG_DRIVER("Disabling the CRTC\n");
	drm_crtc_vblank_off(crtc);

	if (crtc->state->event && !crtc->state->active) {
		spin_lock_irq(&crtc->dev->event_lock);
		drm_crtc_send_vblank_event(crtc, crtc->state->event);
		spin_unlock_irq(&crtc->dev->event_lock);

		crtc->state->event = NULL;
	}
}

static void mga2_crtc_atomic_enable(struct drm_crtc *crtc,
				     struct drm_crtc_state *old_state)
{
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	wcrtc(MGA2_DC_CTRL_SOFT_RESET | MGA2_DC_CTRL_DEFAULT, CTRL);
	WARN_ON(mga2_crtc_mode_set(crtc, &crtc->state->adjusted_mode));
	drm_crtc_vblank_on(crtc);
}

static enum drm_mode_status mga2_drm_crtc_mode_valid(struct drm_crtc *crtc,
	const struct drm_display_mode *mode)
{
	if (mode->flags & DRM_MODE_FLAG_INTERLACE)
		return MODE_NO_INTERLACE;

	return MODE_OK;
}

static const struct drm_crtc_helper_funcs mga2_crtc_helper_funcs = {
	.mode_valid	= mga2_drm_crtc_mode_valid,
	.atomic_begin	= mga2_crtc_atomic_begin,
	.atomic_flush	= mga2_crtc_atomic_flush,
	.atomic_enable	= mga2_crtc_atomic_enable,
	.atomic_disable	= mga2_crtc_atomic_disable,
};

static void mga2_crtc_destroy(struct drm_crtc *crtc)
{
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	mga2_i2c_destroy(mcrtc->i2c);
	mga2_cursor_fini(crtc);
	drm_flip_work_cleanup(&mcrtc->fb_unref_work);
	drm_crtc_cleanup(crtc);
	kfree(crtc);
}
static u32 mga2_crtc_vblank_count(struct drm_crtc *crtc)
{
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	u32 v =  __rcrtc(VCOUNT);
	return v;
}

static const struct drm_crtc_funcs mga2_crtc_funcs = {
	.atomic_destroy_state	= drm_atomic_helper_crtc_destroy_state,
	.atomic_duplicate_state	= drm_atomic_helper_crtc_duplicate_state,
	.destroy		= mga2_crtc_destroy,
	.page_flip		= drm_atomic_helper_page_flip,
	.reset			= drm_atomic_helper_crtc_reset,
	.set_config		= drm_atomic_helper_set_config,
	.gamma_set		= drm_atomic_helper_legacy_gamma_set,
	.get_vblank_counter     = mga2_crtc_vblank_count,
	.disable_vblank		= mga2_crtc_disable_vblank,
	.enable_vblank		= mga2_crtc_enable_vblank,
};

static int mga2_y2r_matrix38[3][3] = {
	{1.1644 * 0x100,  0.0000 * 0x100,  1.7927 * 0x100},
	{1.1644 * 0x100, -0.2123 * 0x100, -0.5329 * 0x100},
	{1.1644 * 0x100,  2.1030 * 0x100,  0.0000 * 0x100},
};

void mga2_crtc_hw_init(struct drm_crtc *crtc)
{
	int i, j, ret;
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	struct mga2 *mga2 = crtc->dev->dev_private;

	wcrtc(MGA2_DC_CTRL_SOFT_RESET | MGA2_DC_CTRL_DEFAULT, CTRL);
	wcrtc(MGA2_DC_DITCTRL_DISABLE, DITCTRL);
	if (mga2_p2(mga2))
		goto out;

	mga2_wait_bit_clear(CLKCTRL, MGA25_DC_B_INPROGRESS);
	wcrtc(MGA25_DC_B_FAUXENA | MGA25_DC_B_FPIXENA, CLKCTRL);

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

	for (i = 0; i < ARRAY_SIZE(mga2_y2r_matrix38); i++) {
		for (j = 0; j < ARRAY_SIZE(mga2_y2r_matrix38[0]); j++) {
			wcrtc((i << 24) | (j << 16) |
				(mga2_y2r_matrix38[i][j] & 0x7ff), Y2R_MATRIX);
		}
	}
out:;
}

static void mga2_fb_unref_worker(struct drm_flip_work *work, void *val)
{
	drm_framebuffer_put(val);
}

int mga2_crtc_init(struct drm_device *dev, int index, void __iomem * regs)
{
	struct mga2_crtc *mcrtc;
	struct mga2 *mga2 = dev->dev_private;
	struct drm_plane *primary = NULL, *cursor = NULL;
	int i, ret;
	struct drm_plane **planes = mga2_layers_init(dev);
	if (IS_ERR(planes)) {
		dev_err(dev->dev, "Couldn't create the planes\n");
		return PTR_ERR(planes);
	}

	mcrtc = kzalloc(sizeof(struct mga2_crtc), GFP_KERNEL);
	if (!mcrtc)
		return -ENOMEM;

	mcrtc->regs = regs;
	mcrtc->index = index;
	drm_flip_work_init(&mcrtc->fb_unref_work, "fb_unref",
			   mga2_fb_unref_worker);

	switch (mga2->subdevice) {
	case MGA2_PCI_PROTO:
		mcrtc->pll = 2;
		break;
	default:
		mcrtc->pll = 1;
		break;
	}

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

	ret = drm_crtc_init_with_planes(dev, &mcrtc->base,
					primary,
					cursor,
					&mga2_crtc_funcs,
					NULL);
	if (ret) {
		dev_err(dev->dev, "Couldn't init DRM CRTC\n");
		return ret;
	}
	drm_mode_crtc_set_gamma_size(&mcrtc->base, MGA2_GAMMA_SIZE);
	drm_crtc_helper_add(&mcrtc->base, &mga2_crtc_helper_funcs);
	/* Set possible_crtcs to this crtc for overlay planes */
	for (i = 0; planes[i]; i++) {
		struct drm_plane *plane = planes[i];
		if (plane->type == DRM_PLANE_TYPE_OVERLAY)
			plane->possible_crtcs = drm_crtc_mask(&mcrtc->base);
	}
	mga2_cursor_init(&mcrtc->base);

	drm_crtc_enable_color_mgmt(&mcrtc->base, 0, false, 256);

	if (mga2->subdevice == MGA26_PROTO && index != 0)
		goto out;

	if (mga2_use_external_pll) {
		resource_size_t r = mcrtc->regs - mga2->regs;
		if (mga2->subdevice == MGA26_PROTO)
			r = mga2->regs_phys + 0x02C00 + 0x30;
		else if (mga2_p2(mga2))
			r += mga2->regs_phys + 0x900;
		else
			WARN_ON(1);

		mcrtc->i2c = mga2_i2c_create(dev->dev, r,
				"extpll", mga2->base_freq, 100 * 1000);

		if (!mcrtc->i2c) {
			DRM_ERROR("failed to add pll i2c bus for display controller\n");
			return -1;
		}
		mga2_pll_init_pixclock(mcrtc->i2c);
	}
out:
	return 0;
}

static int mga2_cursor_init(struct drm_crtc *crtc)
{
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	struct drm_gem_object *gobj =
	    mga2_gem_create(crtc->dev, MGA2_HWC_SIZE, MGA2_GEM_DOMAIN_VRAM);

	if (IS_ERR(gobj))
		return PTR_ERR(gobj);

	mcrtc->cursor_bo = gobj;
	mcrtc->cursor_offset = to_mga2_obj(gobj)->dma_addr;
	mcrtc->cursor_addr = to_mga2_obj(gobj)->vaddr;
	DRM_DEBUG_KMS("pinned cursor cache at %llx\n",
		      mcrtc->cursor_offset);
	return 0;
}

static void mga2_cursor_fini(struct drm_crtc *crtc)
{
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	drm_gem_object_put(mcrtc->cursor_bo);
}

static int mga2_hdmi_init(struct drm_device *dev, void __iomem *regs)
{
	int ret = 0;
	void __iomem *vid_regs = regs;
	u32 val = rvidc(CTRL);

	val |= MGA2_VID12_B_ENABLE | MGA2_VID12_B_HDMI_RSTZ |
			 MGA2_VID12_B_USE_MGA2_DDC;

	wvidc(val, CTRL);

	return ret;
}

static int _mga2_dvi_init(struct drm_device *dev, void __iomem *regs)
{
	void __iomem *vid_regs = regs;

	wvidc(MGA2_VID0_GPIO_MSEN, GPIO_PUPSETRST);

	/* reset SIL1178 */
	wvidc(MGA2_VID0_B_GPIOMUX_I2C, GPIO_MUX);
	wvidc(0x0, GPIO_OUT);
	wvidc(MGA2_VID0_GPIO_RSTPIN, GPIO_DIR);
	udelay(1000);
	/* remove reset SIL1178 */
	wvidc(MGA2_VID0_GPIO_RSTPIN, GPIO_OUT);
	udelay(1000);

	return 0;
}

static int mga2_lvds_init(struct drm_device *dev, void __iomem *regs)
{
	int ret = 0;
	void __iomem *vid_regs = regs;
	struct mga2 *mga2 = dev->dev_private;
	if (!mga25(mga2))
		return ret;
	wvidc(MGA25_DC_B_FAUXENA | MGA25_DC_B_FPIXENA, CLKCTRL25);

	return ret;
}

int mga2_mode_init_hw(struct drm_device *dev)
{
	int ret;
	struct mga2 *mga2 = dev->dev_private;
	void __iomem *vid_regs = mga2->regs + mga2->info->vid_regs_base;
	if (mga2_p2(mga2) && (ret = _mga2_dvi_init(dev,
					vid_regs + 0 * MGA2_VID0_SZ))) {
			goto out;
	}
	if ((ret = mga2_hdmi_init(dev, vid_regs + 1 * MGA2_VID0_SZ)))
		goto out;
	if ((ret = mga2_hdmi_init(dev, vid_regs + 2 * MGA2_VID0_SZ)))
		goto out;
	if ((ret = mga2_lvds_init(dev, vid_regs + 3 * MGA2_VID0_SZ)))
		goto out;
out:
	return ret;
}

int mga2_mode_init(struct drm_device *dev)
{
	int i, ret;
	struct drm_crtc *crtc;
	struct mga2 *mga2 = dev->dev_private;
	for (i = 0; i < mga2->info->mga2_crts_nr; i++) {
		mga2_crtc_init(dev, i, mga2->regs +
			mga2->info->dc_regs_base + i * MGA2_DC0_REG_SZ);
	}

	if ((ret = drm_vblank_init(dev, mga2->info->mga2_crts_nr)))
		goto out;

	if ((ret = mga2fb_bctrl_init(mga2)))
		goto out;

	drm_for_each_crtc(crtc, dev)
		mga2_crtc_hw_init(crtc);

	 /* turn on i2c for hdmi-transmiter */
	if (mga2->subdevice == MGA26_PROTO) {
		void __iomem *vid_regs = mga2->regs + mga2->info->vid_regs_base;
		wvidc(MGA2_VID0_B_GPIOMUX_I2C, GPIO_MUX);
	}

	if ((ret = mga2_mode_init_hw(dev)))
		goto out;
out:
	return ret;
}

void mga2_mode_fini(struct drm_device *dev)
{
	struct mga2 *mga2 = dev->dev_private;
	mga2fb_bctrl_fini(mga2);
}

void mga2_cursor_show(struct drm_crtc *crtc, u32 addr)
{
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	__wcrtc(addr | MGA2_DC_B_CRS_ENA, NCRSADDR);
	__wcrtc(MGA2_DC_B_STROB, DISPCTRL);
}

void mga2_cursor_hide(struct drm_crtc *crtc)
{
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	__wcrtc(0, NCRSADDR);
	__wcrtc(MGA2_DC_B_STROB, DISPCTRL);
}

int mga2_cursor_move(struct drm_crtc *crtc, int x, int y)
{
	struct mga2_crtc *mcrtc = to_mga2_crtc(crtc);
	__wcrtc((x << 16) | (y & 0xffff), NCRSCOORD);
	__wcrtc(MGA2_DC_B_STROB, DISPCTRL);
	return 0;
}
