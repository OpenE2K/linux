/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#define DEBUG

#include "drv.h"
#include <drm/bridge/dw_hdmi.h>


struct mga25_hdmi {
	struct drm_encoder base;
	struct device *dev;
	void __iomem *regs;
	int dev_id;
	struct dw_hdmi *hdmi;
	struct dw_hdmi_plat_data pdata;
	union {
		struct clk *clk[MGA2_MAX_CRTS_NR * 3];
		struct {
			struct clk *pll;
			struct clk *pix;
			struct clk *aux;
		} clks[MGA2_MAX_CRTS_NR];
	};
};

#define to_mga25_hdmi(x)	container_of(x, struct mga25_hdmi, base)

#define __rvidc(__offset)	 ({				\
	unsigned __v = 0;					\
	__v = readl(m->regs + MGA2_VID0_ ## __offset);	\
	__v;				\
})
#define __wvidc(__val, __offset)	do {		\
	writel(__val, m->regs + MGA2_VID0_ ## __offset); \
} while (0)

#ifdef DEBUG
#define rvidc(__offset)						\
({								\
	unsigned __val = __rvidc(__offset);			\
	DRM_DEBUG_KMS("R: %x: %s\n", __val, # __offset);	\
	__val;							\
})

#define wvidc(__val, __offset) do {				\
	unsigned __val2 = __val;				\
	DRM_DEBUG_KMS("W: %x: %s\n", __val2, # __offset);	\
	__wvidc(__val2, __offset);				\
} while(0)

#else
#define		rvidc		__rvidc
#define		wvidc		__wvidc
#endif


# define MGA20_VID12_B_HDMI_RSTZ          (1 << 12)
#define	 MGA2_VID0_CTRL		0x00010
# define MGA2_VID12_B_USE_MGA2_DDC       (1 << 0)
# define MGA2_VID12_B_USE_MGA2_DDC       (1 << 0)
# define MGA2_VID12_B_HS_CONV_OFFSET     2
# define MGA2_VID12_B_VS_CONV_OFFSET     4
# define MGA2_VID12_B_DE_CONV_OFFSET     6
# define MGA2_VID12_B_CEC_IN_INVERT      (1 << 8)
# define MGA2_VID12_B_CEC_ACT_LEVEL      (1 << 9)
# define MGA2_VID12_B_CEC_OUT_LEVEL      (1 << 10)
# define MGA20_VID12_B_HDMI_RSTZ          (1 << 12)
# define MGA2_VID12_B_EN_SFRCLK          (1 << 13)
# define MGA2_VID12_B_EN_CECCLK          (1 << 14)
# define MGA2_VID12_B_EN_I2SCLK          (1 << 15)
# define MGA2_VID12_B_ENABLE             (1 << 31)
# define MGA2_VID0_B_ENABLE              (1 << 31)

# define MGA2_VID12_B_CONV_ALL           3
# define MGA2_VID12_B_CONV_NON_INV       0
# define MGA2_VID12_B_CONV_INV           1
# define MGA2_VID12_B_CONV_DIRECT        2

#define	 MGA2_VID0_MUX		0x00000
# define MGA25_VID0_B_PXENA      (1 << 3)

#define MGA20_VID_B_MUX_DC0	2

static void mga25_hdmi_init_hw(struct mga25_hdmi *m)
{
	u32 val = rvidc(CTRL);

	val |= MGA2_VID0_B_ENABLE | MGA2_VID12_B_USE_MGA2_DDC;
	if (mga20(m->dev_id))
		val |= MGA20_VID12_B_HDMI_RSTZ;
	wvidc(val, CTRL);
}

static void mga25_hdmi_encoder_disable(struct drm_encoder *e)
{
	struct mga25_hdmi *m = to_mga25_hdmi(e);
	wvidc(0, MUX);
}

static void mga20_hdmi_encoder_enable(struct drm_encoder *e)
{
	struct mga25_hdmi *m = to_mga25_hdmi(e);
	u32 mux, ctrl = rvidc(CTRL);
	int crtc = drm_of_encoder_active_endpoint_id(m->dev->of_node, e);
	struct drm_display_mode *mode = &e->crtc->state->adjusted_mode;

	WARN_ON(clk_set_rate(m->clks[crtc].pll, mode->clock * 1000));
	WARN_ON(clk_set_rate(m->clks[crtc].pix, 1));
	mux = crtc + MGA20_VID_B_MUX_DC0;

	ctrl &= ~(MGA20_VID12_B_HDMI_RSTZ |
		(MGA2_VID12_B_CONV_ALL << MGA2_VID12_B_DE_CONV_OFFSET) |
		(MGA2_VID12_B_CONV_ALL << MGA2_VID12_B_HS_CONV_OFFSET) |
		(MGA2_VID12_B_CONV_ALL << MGA2_VID12_B_VS_CONV_OFFSET) |
		MGA2_VID12_B_USE_MGA2_DDC);

	ctrl |= (MGA2_VID12_B_CONV_DIRECT << MGA2_VID12_B_DE_CONV_OFFSET) |
		(MGA2_VID12_B_CONV_DIRECT << MGA2_VID12_B_HS_CONV_OFFSET) |
		(MGA2_VID12_B_CONV_DIRECT << MGA2_VID12_B_VS_CONV_OFFSET) |
		MGA2_VID12_B_USE_MGA2_DDC;
	ctrl |= MGA20_VID12_B_HDMI_RSTZ;
	wvidc(mux, MUX);
	wvidc(ctrl | MGA2_VID0_B_ENABLE, CTRL);


}

static void mga25_hdmi_encoder_enable(struct drm_encoder *e)
{
	struct mga25_hdmi *m = to_mga25_hdmi(e);
	u32 mux, ctrl = rvidc(CTRL);
	int crtc = drm_of_encoder_active_endpoint_id(m->dev->of_node, e);
	struct drm_display_mode *mode = &e->crtc->state->adjusted_mode;

	WARN_ON(clk_set_rate(m->clks[crtc].pll, mode->clock * 1000));
	WARN_ON(clk_set_rate(m->clks[crtc].pix, 1));
	mux = crtc | MGA25_VID0_B_PXENA;

	ctrl = (MGA2_VID12_B_CONV_DIRECT << MGA2_VID12_B_DE_CONV_OFFSET) |
		(MGA2_VID12_B_CONV_DIRECT << MGA2_VID12_B_HS_CONV_OFFSET) |
		(MGA2_VID12_B_CONV_DIRECT << MGA2_VID12_B_VS_CONV_OFFSET) |
		MGA2_VID12_B_USE_MGA2_DDC;
	wvidc(mux, MUX);
	wvidc(ctrl | MGA2_VID0_B_ENABLE, CTRL);
}

static int mga25_hdmi_atomic_check(struct drm_encoder *e,
				    struct drm_crtc_state *crtc_state,
				    struct drm_connector_state *conn_state)
{
	return 0;
}

static const struct drm_encoder_helper_funcs mga20_hdmi_encoder_helper_funcs = {
	.enable	    = mga20_hdmi_encoder_enable,
	.disable    = mga25_hdmi_encoder_disable,
	.atomic_check = mga25_hdmi_atomic_check,
};

static const struct drm_encoder_helper_funcs mga25_hdmi_encoder_helper_funcs = {
	.enable	    = mga25_hdmi_encoder_enable,
	.disable    = mga25_hdmi_encoder_disable,
	.atomic_check = mga25_hdmi_atomic_check,
};

static const struct drm_encoder_funcs mga25_hdmi_encoder_funcs = {
	.destroy = drm_encoder_cleanup,
};

static enum drm_mode_status
mga25_hdmi_mode_valid(struct dw_hdmi *hdmi, void *data,
		       const struct drm_display_info *info,
		       const struct drm_display_mode *mode)
{
	unsigned long max = 552.75e+06 / 1000;
	if (mode->clock < 10000)
		return MODE_CLOCK_LOW;
	if (mode->clock <= max)
		return MODE_OK;
	return MODE_CLOCK_HIGH;
}

static const struct dw_hdmi_mpll_config mga20_mpll_cfg[] = {
	{
		45250000, {
			{ 0x01e0, 0x0000 },
			{ 0x21e1, 0x0000 },
			{ 0x41e2, 0x0000 }
		},
	}, {
		92500000, {
			{ 0x0140, 0x0005 },
			{ 0x2141, 0x0005 },
			{ 0x4142, 0x0005 },
	},
	}, {
		148500000, {
			{ 0x00a0, 0x000a },
			{ 0x20a1, 0x000a },
			{ 0x40a2, 0x000a },
		},
	}, {
		216000000, {
			{ 0x00a0, 0x000a },
			{ 0x2001, 0x000f },
			{ 0x4002, 0x000f },
		},
	}, {
		~0UL, {
			{ 0x0000, 0x0000 },
			{ 0x0000, 0x0000 },
			{ 0x0000, 0x0000 },
		},
	}
};

static const struct dw_hdmi_curr_ctrl mga20_cur_ctr[] = {
	/*      pixelclk     bpp8    bpp10   bpp12 */
	{
		54000000, { 0x091c, 0x091c, 0x06dc },
	}, {
		58400000, { 0x091c, 0x06dc, 0x06dc },
	}, {
		72000000, { 0x06dc, 0x06dc, 0x091c },
	}, {
		74250000, { 0x06dc, 0x0b5c, 0x091c },
	}, {
		118800000, { 0x091c, 0x091c, 0x06dc },
	}, {
		216000000, { 0x06dc, 0x0b5c, 0x091c },
	}, {
		~0UL, { 0x0000, 0x0000, 0x0000 },
	},
};

/*
 * Resistance term 133Ohm Cfg
 * PREEMP config 0.00
 * TX/CK level 10
 */
static const struct dw_hdmi_phy_config mga20_phy_config[] = {
	/*pixelclk   symbol   term   vlev */
	{ 216000000, 0x800d, 0x0005, 0x01ad},
	{ ~0UL,      0x0000, 0x0000, 0x0000}
};

#define MGA25_HDMI_PHY_OPMODE_PLLCFG	0x06	/* Mode of operation and PLL dividers */
#define MGA25_HDMI_PHY_PLLCURRGMPCTRL	0x10	/* PLL current and Gmp (conductance) */
#define MGA25_HDMI_PHY_PLLDIVCTRL	0x11	/* PLL dividers */

struct mga25_hdmi_phy_params {
	unsigned long mpixelclock;
	u16 opmode_div;	/* Mode of operation and PLL dividers */
	u16 curr_gmp;	/* PLL current and Gmp (conductance) */
	u16 div;	/* PLL dividers */
};

static const struct mga25_hdmi_phy_params mga25_hdmi_phy_params[] = {
	{ 13.500e+06, 0x0003, 0x0280, 0x0650 },
	{ 13.500e+06, 0x0002, 0x1280, 0x0650 },
	{ 13.500e+06, 0x0001, 0x2280, 0x0650 },
	{ 21.600e+06, 0x0001, 0x2281, 0x0632 },
	{ 21.600e+06, 0x0000, 0x3281, 0x0632 },
	{ 25.175e+06, 0x0003, 0x0283, 0x0628 },
	{   31.5e+06, 0x0003, 0x0283, 0x0628 },
	{  33.75e+06, 0x0003, 0x0283, 0x0628 },
	{   35.5e+06, 0x0003, 0x0283, 0x0628 },
	{ 43.200e+06, 0x0000, 0x3203, 0x0619 },
	{   44.9e+06, 0x0003, 0x0285, 0x0228 },
	{   49.5e+06, 0x0002, 0x1183, 0x0614 },
	{  50.35e+06, 0x0002, 0x1183, 0x0614 },
	{  56.25e+06, 0x0002, 0x1183, 0x0614 },
	{   59.4e+06, 0x0002, 0x1183, 0x0614 },
	{  68.25e+06, 0x0002, 0x1183, 0x0614 },
	{  73.25e+06, 0x0002, 0x1142, 0x0214 },
	{  74.25e+06, 0x0002, 0x1142, 0x0214 },
	{  78.75e+06, 0x0002, 0x1142, 0x0214 },
	{   79.5e+06, 0x0002, 0x1142, 0x0214 },
	{   82.5e+06, 0x0002, 0x1142, 0x0214 },
	{   83.5e+06, 0x0002, 0x1142, 0x0214 },
	{   85.5e+06, 0x0002, 0x1142, 0x0214 },
	{  88.75e+06, 0x0002, 0x1142, 0x0214 },
	{   94.5e+06, 0x0001, 0x20c0, 0x060a },
	{  100.7e+06, 0x0001, 0x20c0, 0x060a },
	{ 102.25e+06, 0x0001, 0x20c0, 0x060a },
	{  106.5e+06, 0x0001, 0x20c0, 0x060a },
	{  115.5e+06, 0x0001, 0x20c0, 0x060a },
	{  117.5e+06, 0x0001, 0x20c0, 0x060a },
	{  118.8e+06, 0x0001, 0x20c0, 0x060a },
	{ 121.75e+06, 0x0001, 0x20c0, 0x060a },
	{  122.5e+06, 0x0001, 0x20c0, 0x060a },
	{ 136.75e+06, 0x0001, 0x20c0, 0x060a },
	{ 140.25e+06, 0x0001, 0x20c0, 0x060a },
	{ 146.25e+06, 0x0001, 0x2080, 0x020a },
	{ 148.25e+06, 0x0001, 0x2080, 0x020a },
	{  148.5e+06, 0x0001, 0x2080, 0x020a },
	{  157.5e+06, 0x0001, 0x2080, 0x020a },
	{  175.5e+06, 0x0001, 0x2080, 0x020a },
	{  179.5e+06, 0x0001, 0x2080, 0x020a },
	{ 182.75e+06, 0x0001, 0x2080, 0x020a },
	{185.625e+06, 0x0000, 0x3040, 0x0605 },
	{ 187.25e+06, 0x0000, 0x3040, 0x0605 },
	{ 193.25e+06, 0x0000, 0x3040, 0x0605 },
	{  202.5e+06, 0x0000, 0x3040, 0x0605 },
	{ 204.75e+06, 0x0000, 0x3040, 0x0605 },
	{ 214.75e+06, 0x0000, 0x3040, 0x0605 },
	{ 218.25e+06, 0x0000, 0x3040, 0x0605 },
	{  229.5e+06, 0x0000, 0x3040, 0x0605 },
	{  237.6e+06, 0x0000, 0x3040, 0x0605 },
	{ 245.25e+06, 0x0000, 0x3040, 0x0605 },
	{  245.5e+06, 0x0000, 0x3040, 0x0605 },
	{ 268.25e+06, 0x0000, 0x3040, 0x0605 },
	{  268.5e+06, 0x0000, 0x3040, 0x0605 },
	{ 281.25e+06, 0x0000, 0x3040, 0x0605 },
	{ 333.25e+06, 0x0000, 0x3041, 0x0205 },
	{  348.5e+06, 0x0640, 0x3041, 0x0205 },
	{  356.5e+06, 0x0640, 0x3041, 0x0205 },
	{ 371.25e+06, 0x0640, 0x3041, 0x0205 },
	{  380.5e+06, 0x0640, 0x3041, 0x0205 },
	{  475.2e+06, 0x0640, 0x3080, 0x0005 },
	{ 505.25e+06, 0x0640, 0x3080, 0x0005 },
	{ 552.75e+06, 0x0640, 0x3080, 0x0005 },
	{  /* sentinel */ },
};

#define MGA25_HDMI_PHY_CKSYMTXCTRL	0x09	/* Clock Symbol and Transmitter Control Register */
#define MGA25_HDMI_PHY_VLEVCTRL_PLLMEASCTRL 0x0e /* Voltage Level Control Register, PLL Measure Control Register*/
#define MGA25_HDMI_PHY_TXTERM		0x19 /*Transmission Termination Register*/

struct mga25_hdmi_phy_drvr_vltg_lvl {
	unsigned long mpixelclock;
	u16 cksymtxctrl;
	u16 vlevctrl_pllmeasctrl;
	u16 txterm;
};

static const struct mga25_hdmi_phy_drvr_vltg_lvl mga25_hdmi_phy_drvr_vltg_lvl[] = {
	/*	       tx_symon    ck_symon,     txlvl,   txterm */
	{    165e+06, (0xc << 4) | (8 << 0), (12 << 5), (4 << 0) /* 100 Omh */ }, /* HDMI 1.4 < 1.65Gbps */
	{    340e+06, (0xc << 4) | (8 << 0), (12 << 5), (4 << 0) /* 100 Omh */ }, /* HDMI 1.4 > 1.65Gbps */
	{ 552.75e+06, (0xf << 4) | (5 << 0), (12 << 5), (0 << 0) /*  50 Omh */ }, /* HDMI 2.0 (Data rate greater than 3.4 Gbps)*/
	{ /* sentinel */ },
};

static int mga25_hdmi_phy_configure(struct dw_hdmi *m, void *pdata,
				    unsigned long mpixelclock)
{
	const struct mga25_hdmi_phy_params *p = mga25_hdmi_phy_params;
	const struct mga25_hdmi_phy_drvr_vltg_lvl *d =
					mga25_hdmi_phy_drvr_vltg_lvl;

	for (; p->mpixelclock && mpixelclock > p->mpixelclock; p++);

	if (p->mpixelclock == 0)
		return -EINVAL;

	for (; d->mpixelclock && mpixelclock > d->mpixelclock; d++);

	if (d->mpixelclock == 0)
		return -EINVAL;

	dw_hdmi_phy_i2c_write(m, d->cksymtxctrl,
			      MGA25_HDMI_PHY_CKSYMTXCTRL);
	dw_hdmi_phy_i2c_write(m, d->vlevctrl_pllmeasctrl,
			      MGA25_HDMI_PHY_VLEVCTRL_PLLMEASCTRL);
	dw_hdmi_phy_i2c_write(m, d->txterm,
				MGA25_HDMI_PHY_TXTERM);

	dw_hdmi_phy_i2c_write(m, p->opmode_div,
			      MGA25_HDMI_PHY_OPMODE_PLLCFG);
	dw_hdmi_phy_i2c_write(m, p->curr_gmp,
			      MGA25_HDMI_PHY_PLLCURRGMPCTRL);
	dw_hdmi_phy_i2c_write(m, p->div, MGA25_HDMI_PHY_PLLDIVCTRL);

	return 0;
}

static struct dw_hdmi_plat_data mga20_drv_data = {
	.mpll_cfg = mga20_mpll_cfg,
	.cur_ctr  = mga20_cur_ctr,
	.phy_config = mga20_phy_config,
	.mode_valid = mga25_hdmi_mode_valid,
};
static const struct dw_hdmi_plat_data mga25_drv_data = {
	.mode_valid = mga25_hdmi_mode_valid,
	.configure_phy	= mga25_hdmi_phy_configure,
};

static int mga25_hdmi_bind(struct device *dev, struct device *master,
			    void *data)
{
	int ret, i;
	struct drm_device *drm = data;
	struct mga25_hdmi *m = dev_get_drvdata(dev);
	struct drm_encoder *e = &m->base;
	struct dw_hdmi_plat_data *pdata = &m->pdata;
	const struct drm_encoder_helper_funcs *hlp_fnc;
	struct platform_device *pdev = to_platform_device(dev);
	switch (m->dev_id) { /*TODO*/
	case MGA20:
		hlp_fnc = &mga20_hdmi_encoder_helper_funcs;
		break;
	case MGA25:
		hlp_fnc = &mga25_hdmi_encoder_helper_funcs;
		break;
	default:
		return WARN_ON(-ENODEV);
	}
	for (i = 0; i < ARRAY_SIZE(m->clk); i++) {
		struct clk *c = of_clk_get(dev->of_node, i);
		if (IS_ERR(c)) {
			ret = PTR_ERR(c);
			if (WARN_ON(ret != -ENOENT))
				goto err;
			ret = 0;
			break;
		}
		m->clk[i] = c;
	}
	e->possible_crtcs = drm_of_find_possible_crtcs(drm, dev->of_node);
	if (WARN_ON(e->possible_crtcs == 0))
		return -ENODEV;

	drm_encoder_helper_add(e, hlp_fnc);
	drm_encoder_init(drm, e, &mga25_hdmi_encoder_funcs,
			 DRM_MODE_ENCODER_TMDS, NULL);

	m->hdmi = dw_hdmi_bind(pdev, e, pdata);

	/*
	 * If dw_hdmi_bind() fails we'll never call dw_hdmi_unbind(),
	 * which would have called the encoder cleanup.  Do it manually.
	 */
	if (WARN_ON(IS_ERR(m->hdmi))) {
		ret = PTR_ERR(m->hdmi);
		drm_encoder_cleanup(e);
		goto err;
	}
	return ret;
err:
	for (i = 0; i < ARRAY_SIZE(m->clk); i++)
		clk_put(m->clk[i]);
	return ret;
}

static void mga25_hdmi_unbind(struct device *dev, struct device *master,
			       void *data)
{
	int i;
	struct mga25_hdmi *m = dev_get_drvdata(dev);
	if (!m)
		return;
	dw_hdmi_unbind(m->hdmi);
	for (i = 0; i < ARRAY_SIZE(m->clk); i++)
		clk_put(m->clk[i]);
}

static const struct component_ops mga25_hdmi_ops = {
	.bind	= mga25_hdmi_bind,
	.unbind	= mga25_hdmi_unbind,
};

static int mga25_hdmi_resume(struct platform_device *pdev)
{
	struct mga25_hdmi *m = dev_get_drvdata(&pdev->dev);
	mga25_hdmi_init_hw(m);
	return 0;
}

static int mga25_hdmi_probe(struct platform_device *pdev)
{
	int ret;
	struct device *dev = &pdev->dev;
	struct device *parent = dev->parent;
	struct dw_hdmi_plat_data *pdata;
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	struct mga25_hdmi *m = devm_kzalloc(dev, sizeof(*m), GFP_KERNEL);
	if (WARN_ON(!m))
		return -ENOMEM;

	m->dev = dev;
	pdata = &m->pdata;
	memcpy(pdata, of_device_get_match_data(dev), sizeof(*pdata));

	m->dev_id = mga25_get_version(parent);
	if (WARN_ON(m->dev_id < 0))
		return -ENODEV;

	m->regs = devm_ioremap_resource(dev, res);
	if (WARN_ON(IS_ERR(m->regs)))
		return PTR_ERR(m->regs);


	dev_set_drvdata(dev, m);
	mga25_hdmi_init_hw(m);

	ret = component_add(&pdev->dev, &mga25_hdmi_ops);
	if (WARN_ON(ret))
		goto err;
	return ret;
err:
	return ret;
}

static int mga25_hdmi_remove(struct platform_device *pdev)
{
	component_del(&pdev->dev, &mga25_hdmi_ops);
	return 0;
}

static const struct of_device_id mga25_hdmi_dt_ids[] = {
	{
	  .compatible = "mcst,mga20-hdmi",
	  .data = &mga20_drv_data,
	},
	{
	  .compatible = "mcst,mga25-hdmi",
	  .data = &mga25_drv_data,
	},
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, mga25_hdmi_dt_ids);

struct platform_driver mga25_hdmi_driver = {
	.probe  = mga25_hdmi_probe,
	.remove = mga25_hdmi_remove,
	.resume = mga25_hdmi_resume,
	.driver = {
		.name = "mga2x-hdmi",
		.of_match_table = mga25_hdmi_dt_ids,
	},
};
