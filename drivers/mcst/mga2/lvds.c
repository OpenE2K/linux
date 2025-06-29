/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#define DEBUG
#include "drv.h"

#define LVDS_CHNL_NR	4
#define LVDS_PORT	1

static const u32 mga27_lvds_default_frame_table[] = {
	33, 33, 32, 32, 32, 33, 33,
	19,  4,  5,  6,  7,  8,  9,
	28, 29, 14, 15, 16, 17, 18,
	34, 35, 36, 24, 25, 26, 27,
	32, 22, 23, 12, 13,  2, 3,
	32, 20, 21, 10, 11,  0, 1,
};

static const u32 mga2_lvds_default_frame_table[] = {
	19,  4,  5,  6,  7,  8,  9,
	28, 29, 14, 15, 16, 17, 18,
	34, 35, 36, 24, 25, 26, 27,
	32, 22, 23, 12, 13,  2, 3,
	32, 20, 21, 10, 11,  0, 1,
	33, 33, 32, 32, 32, 33, 33,
};

static const u32 mga20_lvds_default_frame_table[
		sizeof(mga2_lvds_default_frame_table)] = { /*bug73760*/
	24, 25, 25, 25, 24, 24, 24,
	 2,  3,  4,  5,  6,  7, 15,
	23, 10, 11, 12, 13, 14, 22,
	27, 28, 18, 19, 20, 21, 26,
	16, 17,  8,  9,  0,  1, 25,
};

struct mga2_lvds {
	struct drm_encoder base;
	struct device *dev;
	void __iomem *regs;
	int dev_id;
	u32 frame_table[ARRAY_SIZE(mga2_lvds_default_frame_table)];
	bool panel_10bit;
	int channels_nr;
	union {
		struct clk *clk[MGA2_MAX_CRTS_NR * 3];
		struct {
			struct clk *pll;
			struct clk *pix;
			struct clk *aux;
		} clks[MGA2_MAX_CRTS_NR];
	};

	struct drm_connector	connector;
	struct display_timings *timings;
	struct drm_panel	*panel;
};

#define to_mga2_lvds(x)	container_of(x, struct mga2_lvds, base)


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
} while (0)

#else
#define		rvidc		__rvidc
#define		wvidc		__wvidc
#endif


#define	 MGA2_VID0_MUX		0x00000

# define MGA25_VID3_B_SCALER_OFF      (2 << 30)
# define MGA25_VID0_B_AUENA      (1 << 7)
# define MGA25_VID0_B_AUSEL_OFFSET      4
# define MGA25_VID0_B_PXENA      (1 << 3)
# define MGA25_VID0_B_PXSEL_OFFSET      0


#define	 MGA2_VID0_CTRL		0x00010
#define MGA2_VID0_B_ENABLE	(1 << 31)
# define MGA2_VID3_B_ENABLE    (1 << 31)
# define MGA2_VID3_B_RESYNC    (1 << 30)
# define MGA2_VID3_B_10BIT    (1 << 28)

# define MGA2_VID3_B_P3CHAN_OFFSET    22
# define MGA2_VID3_B_P2CHAN_OFFSET    20
# define MGA2_VID3_B_P1CHAN_OFFSET    18
# define MGA2_VID3_B_P0CHAN_OFFSET    16


#define	 MGA2_VID0_CLKCTRL25	0x000a0
# define MGA25_DC_B_FAUXENA       (1 << 15)
# define MGA25_DC_B_FPIXENA       (1 << 7)

static void mga2_lvds_encoder_enable(struct drm_encoder *e)
{
	int i, ret;
	struct mga2_lvds *m = to_mga2_lvds(e);
	u32 *v = m->frame_table;
	u32 mux, ctrl = MGA2_VID0_B_ENABLE;
	struct drm_display_mode *mode = &e->crtc->state->adjusted_mode;
	int crtc = drm_of_encoder_active_endpoint_id(m->dev->of_node, e);
	struct device_node *ep, *rep;
	if (WARN_ON(crtc < 0 || crtc > ARRAY_SIZE(m->clks)))
		return;

	WARN_ON(clk_set_rate(m->clks[crtc].pll, (long)mode->clock * 7 * 1000));
	WARN_ON(clk_set_rate(m->clks[crtc].pix, 7));
	WARN_ON(clk_set_rate(m->clks[crtc].aux, m->channels_nr));

	mux = (crtc << MGA25_VID0_B_AUSEL_OFFSET) |
		MGA25_VID0_B_AUENA |
		(crtc << MGA25_VID0_B_PXSEL_OFFSET) |
		MGA25_VID0_B_PXENA;
	mux |= MGA25_VID3_B_SCALER_OFF;

	if (m->panel_10bit)
		ctrl |= MGA2_VID3_B_10BIT;

	for_each_endpoint_of_node(m->dev->of_node, ep) {
		struct of_endpoint eid, rid;
		rep = of_graph_get_remote_endpoint(ep);
		if (WARN_ON(!rep))
			continue;
		ret = of_graph_parse_endpoint(rep, &rid);
		of_node_put(rep);
		if (WARN_ON(ret))
			continue;
		ret = of_graph_parse_endpoint(ep, &eid);
		if (WARN_ON(ret))
			continue;
		if (WARN_ON(eid.id >= LVDS_CHNL_NR || rid.id >= LVDS_CHNL_NR))
			continue;
		if (eid.port != LVDS_PORT)
			continue;
		DRM_DEV_DEBUG(m->dev, "lvds connection: %d.%d -> %d.%d\n",
				eid.port, eid.id, rid.port, rid.id);
		ctrl |= rid.id << (MGA2_VID3_B_P0CHAN_OFFSET + eid.id * 2);
		ctrl |= 1 << (MGA2_VID3_B_P0ENA_OFFSET + eid.id);
	}

	ctrl |= ilog2(m->channels_nr) | MGA2_VID3_B_RESYNC;

	wvidc(MGA25_DC_B_FAUXENA | MGA25_DC_B_FPIXENA, CLKCTRL25);
	wvidc(mux, MUX);
	wvidc(ctrl, CTRL);

	for (i = 0; i < ARRAY_SIZE(m->frame_table); i++)
		wvidc(v[i] | (i << MGA2_VID3_B_ADDR_OFFSET), BITCTRL);

	if (m->panel) {
		drm_panel_prepare(m->panel);
		drm_panel_enable(m->panel);
	}
}

static void mga2_lvds_encoder_disable(struct drm_encoder *encoder)
{
	struct mga2_lvds *m = to_mga2_lvds(encoder);
	if (m->panel) {
		drm_panel_disable(m->panel);
		drm_panel_unprepare(m->panel);
	}
	wvidc(0, CTRL);
}

static enum drm_mode_status
mga2_lvds_mode_valid(struct drm_encoder *e,
				const struct drm_display_mode *mode)
{
	unsigned long max = 350.e+06 / 1000; /*2560x1600x60Hz;*/
	if (mode->clock < 10000)
		return MODE_CLOCK_LOW;
	if (mode->clock <= max)
		return MODE_OK;
	return MODE_CLOCK_HIGH;
}

static const struct drm_encoder_helper_funcs mga2_lvds_enc_helper_funcs = {
	.disable	= mga2_lvds_encoder_disable,
	.enable		= mga2_lvds_encoder_enable,
	.mode_valid	= mga2_lvds_mode_valid,
};

static const struct drm_encoder_funcs mga2_lvds_enc_funcs = {
	.destroy	= drm_encoder_cleanup,
};


static inline struct mga2_lvds *
drm_connector_to_mga2_lvds(struct drm_connector *connector)
{
	return container_of(connector, struct mga2_lvds,
			    connector);
}

static int mga2_lvds_add_cmdline_mode(struct drm_connector *connector)
{
	struct drm_cmdline_mode *cmdline_mode;
	struct drm_display_mode *mode;

	cmdline_mode = &connector->cmdline_mode;
	if (!cmdline_mode->specified)
		return 0;

	/* Only add a GTF mode if we find no matching probed modes */
	list_for_each_entry(mode, &connector->probed_modes, head) {
		if (mode->hdisplay != cmdline_mode->xres ||
		    mode->vdisplay != cmdline_mode->yres)
			continue;

		if (cmdline_mode->refresh_specified) {
			/* The probed mode's vrefresh is set until later */
			if (drm_mode_vrefresh(mode) != cmdline_mode->refresh)
				continue;
		}

		return 0;
	}

	mode = drm_mode_create_from_cmdline_mode(connector->dev,
						 cmdline_mode);
	if (mode == NULL)
		return 0;

	mode->type |= DRM_MODE_TYPE_PREFERRED;

	drm_mode_probed_add(connector, mode);
	return 1;
}

static unsigned int mga2_lvds_get_timings_modes(struct drm_connector *connector)
{
	struct drm_device *dev = connector->dev;
	struct mga2_lvds *m = drm_connector_to_mga2_lvds(connector);
	struct display_timings *timings = m->timings;
	unsigned i;
	if (!timings)
		return 0;

	for (i = 0; i < timings->num_timings; i++) {
		struct drm_display_mode *mode;
		struct videomode vm;

		if (videomode_from_timings(timings, &vm, i))
			break;

		mode = drm_mode_create(dev);
		if (!mode)
			break;

		drm_display_mode_from_videomode(&vm, mode);

		mode->type = DRM_MODE_TYPE_DRIVER;

		if (timings->native_mode == i)
			mode->type |= DRM_MODE_TYPE_PREFERRED;

		drm_mode_set_name(mode);
		drm_mode_probed_add(connector, mode);
	}

	return i;
}

static int mga2_lvds_get_modes(struct drm_connector *connector)
{
	struct mga2_lvds *m = drm_connector_to_mga2_lvds(connector);
	int cnt = mga2_lvds_add_cmdline_mode(connector);
	if (cnt > 0)
		return cnt;
	cnt = mga2_lvds_get_timings_modes(connector);
	if (cnt > 0)
		return cnt;
	if (m->panel)
		return drm_panel_get_modes(m->panel, connector);
	return -ENODEV;
}

static struct drm_connector_helper_funcs mga2_lvds_con_helper_funcs = {
	.get_modes	= mga2_lvds_get_modes,
};

static void mga2_lvds_connector_destroy(struct drm_connector *connector)
{
	struct mga2_lvds *m = drm_connector_to_mga2_lvds(connector);
	if (m->timings)
		display_timings_release(m->timings);
	drm_connector_cleanup(connector);
}

static const struct drm_connector_funcs mga2_lvds_con_funcs = {
	.fill_modes		= drm_helper_probe_single_connector_modes,
	.destroy		= mga2_lvds_connector_destroy,
	.reset			= drm_atomic_helper_connector_reset,
	.atomic_duplicate_state	= drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state	= drm_atomic_helper_connector_destroy_state,
};


static int mga2_lvds_bind(struct device *dev, struct device *master,
			    void *data)
{
	int ret, i;
	struct mga2_lvds *m = dev_get_drvdata(dev);
	struct drm_encoder *e = &m->base;
	struct drm_device *drm = data;
	struct device_node *np = dev->of_node;

	e->possible_crtcs = drm_of_find_possible_crtcs(drm, np);
	if (WARN_ON(e->possible_crtcs == 0))
		return -ENODEV;

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
	drm_encoder_helper_add(e, &mga2_lvds_enc_helper_funcs);
	drm_encoder_init(drm, e, &mga2_lvds_enc_funcs,
			 DRM_MODE_ENCODER_LVDS, NULL);

	for (ret = -ENODEV, i = 0; i < LVDS_CHNL_NR && ret; i++) {
		ret = drm_of_find_panel_or_bridge(np, 1, i,
						&m->panel, NULL);
	}
	if (ret) {
		DRM_ERROR("No panel or bridge found (%d)...\n", ret);
		return ret;
	}

	if (m->panel)
		m->timings = of_get_display_timings(m->panel->dev->of_node);

	drm_connector_helper_add(&m->connector,
					&mga2_lvds_con_helper_funcs);
	ret = drm_connector_init(drm, &m->connector,
					&mga2_lvds_con_funcs,
					DRM_MODE_CONNECTOR_LVDS);
	if (ret) {
		DRM_ERROR("Couldn't initialise the m connector\n");
		goto err_cleanup_connector;
	}
	m->connector.status = connector_status_connected;

	drm_connector_attach_encoder(&m->connector, e);

	if (m->panel) {
		m->channels_nr = of_graph_get_endpoint_count(
						m->panel->dev->of_node);
		DRM_INFO("Panel has %d channels\n", m->channels_nr);
		if (WARN_ON(m->channels_nr < 1 || m->channels_nr > LVDS_CHNL_NR)) {
			ret = -EINVAL;
			goto err_cleanup_connector;
		}
	}

	return 0;
err_cleanup_connector:
	drm_encoder_cleanup(e);
err:
	for (i = 0; i < ARRAY_SIZE(m->clk); i++)
		clk_put(m->clk[i]);
	return ret;
}

static void mga2_lvds_unbind(struct device *dev, struct device *master,
			       void *data)
{
	int i;
	struct mga2_lvds *m = dev_get_drvdata(dev);
	struct drm_encoder *e = &m->base;
	drm_encoder_cleanup(e);
	for (i = 0; i < ARRAY_SIZE(m->clk); i++)
		clk_put(m->clk[i]);
}

static const struct component_ops mga2_lvds_ops = {
	.bind	= mga2_lvds_bind,
	.unbind	= mga2_lvds_unbind,
};

static int mga2_lvds_probe(struct platform_device *pdev)
{
	int ret;
	struct device *dev = &pdev->dev;
	struct device *parent = dev->parent;
	struct device_node *np = dev->of_node;
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	struct mga2_lvds *m = devm_kzalloc(dev, sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;

	m->dev = dev;
	m->dev_id = mga2_get_version(parent);
	if (m->dev_id < 0)
		return -ENODEV;
	ret = of_property_read_u32_array(np, "frame-table",
			m->frame_table, ARRAY_SIZE(m->frame_table));
	if (ret && ret != -EINVAL)
		return ret;
	if (ret) { /* not found */
		const u32 *t = mga27(m->dev_id) ?
				mga27_lvds_default_frame_table :
				mga20(m->dev_id) ?
				mga20_lvds_default_frame_table :
				mga2_lvds_default_frame_table;
		memcpy(m->frame_table, t, sizeof(m->frame_table));
	}
	m->panel_10bit = of_property_read_bool(np, "panel-10-bit");

	m->regs = devm_ioremap_resource(dev, res);
	if (IS_ERR(m->regs))
		return PTR_ERR(m->regs);
	dev_set_drvdata(dev, m);

	return component_add(&pdev->dev, &mga2_lvds_ops);
}

static int mga2_lvds_remove(struct platform_device *pdev)
{
	component_del(&pdev->dev, &mga2_lvds_ops);

	return 0;
}

static const struct of_device_id mga2_lvds_dt_ids[] = {
	{
	  .compatible = "mcst,mga2x-lvds",
	},
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, mga2_lvds_dt_ids);

struct platform_driver mga2_lvds_driver = {
	.probe  = mga2_lvds_probe,
	.remove = mga2_lvds_remove,
	.driver = {
		.name = "mga2x-lvds",
		.of_match_table = mga2_lvds_dt_ids,
	},
};
