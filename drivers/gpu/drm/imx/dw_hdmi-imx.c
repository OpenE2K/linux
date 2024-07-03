// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2011-2013 Freescale Semiconductor, Inc.
 *
 * derived from imx-hdmi.c(renamed to bridge/dw_hdmi.c now)
 */

#ifdef CONFIG_MCST
#define DEBUG
#endif /* CONFIG_MCST */

#include <linux/component.h>
#include <linux/mfd/syscon.h>
#include <linux/mfd/syscon/imx6q-iomuxc-gpr.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>

#include <video/imx-ipu-v3.h>

#include <drm/bridge/dw_hdmi.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_edid.h>
#include <drm/drm_encoder.h>
#include <drm/drm_of.h>
#include <drm/drm_print.h>
#include <drm/drm_simple_kms_helper.h>

#include "imx-drm.h"

struct imx_hdmi {
	struct device *dev;
	struct drm_encoder encoder;
	struct dw_hdmi *hdmi;
	struct regmap *regmap;
};

static inline struct imx_hdmi *enc_to_imx_hdmi(struct drm_encoder *e)
{
	return container_of(e, struct imx_hdmi, encoder);
}

static const struct dw_hdmi_mpll_config imx_mpll_cfg[] = {
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

static const struct dw_hdmi_curr_ctrl imx_cur_ctr[] = {
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
static const struct dw_hdmi_phy_config imx_phy_config[] = {
	/*pixelclk   symbol   term   vlev */
	{ 216000000, 0x800d, 0x0005, 0x01ad},
	{ ~0UL,      0x0000, 0x0000, 0x0000}
};

static int dw_hdmi_imx_parse_dt(struct imx_hdmi *hdmi)
{
#ifndef CONFIG_MCST
	struct device_node *np = hdmi->dev->of_node;

	hdmi->regmap = syscon_regmap_lookup_by_phandle(np, "gpr");
	if (IS_ERR(hdmi->regmap)) {
		dev_err(hdmi->dev, "Unable to get gpr\n");
		return PTR_ERR(hdmi->regmap);
	}

#endif /* ! CONFIG_MCST */
	return 0;
}

static void dw_hdmi_imx_encoder_enable(struct drm_encoder *encoder)
{
#ifndef CONFIG_MCST
	struct imx_hdmi *hdmi = enc_to_imx_hdmi(encoder);
	int mux = drm_of_encoder_active_port_id(hdmi->dev->of_node, encoder);

	regmap_update_bits(hdmi->regmap, IOMUXC_GPR3,
			   IMX6Q_GPR3_HDMI_MUX_CTL_MASK,
			   mux << IMX6Q_GPR3_HDMI_MUX_CTL_SHIFT);
#endif /* ! CONFIG_MCST */
}

static int dw_hdmi_imx_atomic_check(struct drm_encoder *encoder,
				    struct drm_crtc_state *crtc_state,
				    struct drm_connector_state *conn_state)
{
#ifndef CONFIG_MCST
	struct imx_crtc_state *imx_crtc_state = to_imx_crtc_state(crtc_state);

	imx_crtc_state->bus_format = MEDIA_BUS_FMT_RGB888_1X24;
	imx_crtc_state->di_hsync_pin = 2;
	imx_crtc_state->di_vsync_pin = 3;
#endif /* ! CONFIG_MCST */
	return 0;
}

static const struct drm_encoder_helper_funcs dw_hdmi_imx_encoder_helper_funcs = {
	.enable	    = dw_hdmi_imx_encoder_enable,
	.atomic_check = dw_hdmi_imx_atomic_check,
};

static enum drm_mode_status
imx6q_hdmi_mode_valid(struct dw_hdmi *hdmi, void *data,
		      const struct drm_display_info *info,
		      const struct drm_display_mode *mode)
{
	if (mode->clock < 13500)
		return MODE_CLOCK_LOW;
	/* FIXME: Hardware is capable of 266MHz, but setup data is missing. */
	if (mode->clock > 216000)
		return MODE_CLOCK_HIGH;

	return MODE_OK;
}

static enum drm_mode_status
imx6dl_hdmi_mode_valid(struct dw_hdmi *hdmi, void *data,
		       const struct drm_display_info *info,
		       const struct drm_display_mode *mode)
{
	if (mode->clock < 13500)
		return MODE_CLOCK_LOW;
	/* FIXME: Hardware is capable of 270MHz, but setup data is missing. */
	if (mode->clock > 216000)
		return MODE_CLOCK_HIGH;

	return MODE_OK;
}

#ifdef CONFIG_MCST
static enum drm_mode_status
mga2_hdmi_mode_valid(struct dw_hdmi *hdmi, void *data,
		     const struct drm_display_info *info,
		     const struct drm_display_mode *mode)
{
	unsigned long max = 552.75e+06;
	if (mode->clock <=max)
		return MODE_OK;
	return MODE_CLOCK_HIGH;	
}

#endif /* CONFIG_MCST */
static struct dw_hdmi_plat_data imx6q_hdmi_drv_data = {
	.mpll_cfg   = imx_mpll_cfg,
	.cur_ctr    = imx_cur_ctr,
	.phy_config = imx_phy_config,
	.mode_valid = imx6q_hdmi_mode_valid,
};

static struct dw_hdmi_plat_data imx6dl_hdmi_drv_data = {
	.mpll_cfg = imx_mpll_cfg,
	.cur_ctr  = imx_cur_ctr,
	.phy_config = imx_phy_config,
	.mode_valid = imx6dl_hdmi_mode_valid,
};

#ifdef CONFIG_MCST

static int dw_hdmi_phy_reg_read(void *context, unsigned int reg,
				  unsigned int *result)
{
	struct dw_hdmi *hdmi = context;
	*result = __dw_hdmi_phy_i2c_read(hdmi, reg);
	return 0;
}

static int dw_hdmi_phy_reg_write(void *context, unsigned int reg,
				  unsigned int value)
{
	struct dw_hdmi *hdmi = context;
	__dw_hdmi_phy_i2c_write(hdmi, value, reg);
	return 0;
}

static const struct regmap_config dw_hdmi_phy_regmap_config = {
	.name = "phy-regs",
	.reg_bits = 8,
	.val_bits = 16,
	.reg_read = dw_hdmi_phy_reg_read,
	.reg_write = dw_hdmi_phy_reg_write,
	.max_register = 0x3b,
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

static int mga25_hdmi_phy_configure(struct dw_hdmi *hdmi, void *pdata,
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

	dw_hdmi_phy_i2c_write(hdmi, d->cksymtxctrl,
			      MGA25_HDMI_PHY_CKSYMTXCTRL);
	dw_hdmi_phy_i2c_write(hdmi, d->vlevctrl_pllmeasctrl,
			      MGA25_HDMI_PHY_VLEVCTRL_PLLMEASCTRL);
	dw_hdmi_phy_i2c_write(hdmi, d->txterm,
				MGA25_HDMI_PHY_TXTERM);

	dw_hdmi_phy_i2c_write(hdmi, p->opmode_div,
			      MGA25_HDMI_PHY_OPMODE_PLLCFG);
	dw_hdmi_phy_i2c_write(hdmi, p->curr_gmp,
			      MGA25_HDMI_PHY_PLLCURRGMPCTRL);
	dw_hdmi_phy_i2c_write(hdmi, p->div, MGA25_HDMI_PHY_PLLDIVCTRL);

	return 0;
}

static struct dw_hdmi_plat_data mga2_drv_data = {
	.mpll_cfg = imx_mpll_cfg,
	.cur_ctr  = imx_cur_ctr,
	.phy_config = imx_phy_config,
	.mode_valid = mga2_hdmi_mode_valid,
};
static const struct dw_hdmi_plat_data mga25_drv_data = {
	.mode_valid = mga2_hdmi_mode_valid,
	.configure_phy	= mga25_hdmi_phy_configure,
};

static struct platform_device_id imx_hdmi_devtype[] = {
	{
	  .name = "mga2-hdmi",
	  .driver_data = (unsigned long)&mga2_drv_data
	}, {
	  .name = "mga25-hdmi",
	  .driver_data = (unsigned long)&mga25_drv_data
	},
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(platform, imx_hdmi_devtype);

#endif /* CONFIG_MCST */
static const struct of_device_id dw_hdmi_imx_dt_ids[] = {
	{ .compatible = "fsl,imx6q-hdmi",
	  .data = &imx6q_hdmi_drv_data
	}, {
	  .compatible = "fsl,imx6dl-hdmi",
	  .data = &imx6dl_hdmi_drv_data
	},
#ifdef CONFIG_MCST
	{
	  .compatible = "mga2-hdmi",
	  .data = &mga2_drv_data
	},
#endif /* CONFIG_MCST */
	{},
};
MODULE_DEVICE_TABLE(of, dw_hdmi_imx_dt_ids);

static int dw_hdmi_imx_bind(struct device *dev, struct device *master,
			    void *data)
{
	struct platform_device *pdev = to_platform_device(dev);
	const struct dw_hdmi_plat_data *plat_data;
#ifdef CONFIG_MCST
	struct drm_crtc *crtc;
	uint32_t crtc_mask = 0;
#else
	const struct of_device_id *match;
#endif /* ! CONFIG_MCST */
	struct drm_device *drm = data;
	struct drm_encoder *encoder;
	struct imx_hdmi *hdmi;
	int ret;

#ifndef CONFIG_MCST
	if (!pdev->dev.of_node)
		return -ENODEV;
#endif /* ! CONFIG_MCST */

	hdmi = dev_get_drvdata(dev);
	memset(hdmi, 0, sizeof(*hdmi)); 

#ifndef CONFIG_MCST
	match = of_match_node(dw_hdmi_imx_dt_ids, pdev->dev.of_node);
	plat_data = match->data;
#else /* CONFIG_MCST */
	plat_data = (struct dw_hdmi_plat_data *)
				platform_get_device_id(pdev)->driver_data;
#endif /* CONFIG_MCST */
	hdmi->dev = &pdev->dev;
	encoder = &hdmi->encoder;

#ifdef CONFIG_MCST
	drm_for_each_crtc(crtc, drm)
		crtc_mask |= drm_crtc_mask(crtc);
	encoder->possible_crtcs = crtc_mask;
#else
	ret = imx_drm_encoder_parse_of(drm, encoder, dev->of_node);
	if (ret)
		return ret;
#endif
	ret = dw_hdmi_imx_parse_dt(hdmi);
	if (ret < 0)
		return ret;

	drm_encoder_helper_add(encoder, &dw_hdmi_imx_encoder_helper_funcs);
	drm_simple_encoder_init(drm, encoder, DRM_MODE_ENCODER_TMDS);

	hdmi->hdmi = dw_hdmi_bind(pdev, encoder, plat_data);

	/*
	 * If dw_hdmi_bind() fails we'll never call dw_hdmi_unbind(),
	 * which would have called the encoder cleanup.  Do it manually.
	 */
	if (IS_ERR(hdmi->hdmi)) {
		ret = PTR_ERR(hdmi->hdmi);
		drm_encoder_cleanup(encoder);
	}
#ifdef CONFIG_MCST
	WARN_ON(IS_ERR(devm_regmap_init(dev, NULL, hdmi->hdmi,
		 &dw_hdmi_phy_regmap_config)));
#endif
	return ret;
}

static void dw_hdmi_imx_unbind(struct device *dev, struct device *master,
			       void *data)
{
	struct imx_hdmi *hdmi = dev_get_drvdata(dev);

	dw_hdmi_unbind(hdmi->hdmi);
}

static const struct component_ops dw_hdmi_imx_ops = {
	.bind	= dw_hdmi_imx_bind,
	.unbind	= dw_hdmi_imx_unbind,
};

static int dw_hdmi_imx_probe(struct platform_device *pdev)
{
	struct imx_hdmi *hdmi;

	hdmi = devm_kzalloc(&pdev->dev, sizeof(*hdmi), GFP_KERNEL);
	if (!hdmi)
		return -ENOMEM;

	platform_set_drvdata(pdev, hdmi);

	return component_add(&pdev->dev, &dw_hdmi_imx_ops);
}

static int dw_hdmi_imx_remove(struct platform_device *pdev)
{
	component_del(&pdev->dev, &dw_hdmi_imx_ops);

	return 0;
}

static struct platform_driver dw_hdmi_imx_platform_driver = {
	.probe  = dw_hdmi_imx_probe,
	.remove = dw_hdmi_imx_remove,
	.driver = {
		.name = "dwhdmi-imx",
		.of_match_table = dw_hdmi_imx_dt_ids,
	},
#ifdef CONFIG_MCST
	.id_table = imx_hdmi_devtype,
#endif /* CONFIG_MCST */
};

module_platform_driver(dw_hdmi_imx_platform_driver);

MODULE_AUTHOR("Andy Yan <andy.yan@rock-chips.com>");
MODULE_AUTHOR("Yakir Yang <ykk@rock-chips.com>");
MODULE_DESCRIPTION("IMX6 Specific DW-HDMI Driver Extension");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:dwhdmi-imx");
