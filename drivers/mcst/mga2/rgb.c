#define DEBUG

#include "drv.h"
#include <drm/drm_encoder_slave.h>
#include <drm/i2c/sil164.h>


struct mga2_rgb {
	struct drm_encoder_slave base;
	struct device *dev;
	void __iomem *regs;
	int dev_id;
	struct drm_bridge *bridge;
	struct i2c_adapter *slave;
	bool dual_edge;
	union {
		struct clk *clk[MGA2_MAX_CRTS_NR * 3];
		struct {
			struct clk *pll;
			struct clk *pix;
			struct clk *aux;
		} clks[MGA2_MAX_CRTS_NR];
	};
};

static inline struct mga2_rgb *to_mga2(struct drm_encoder *enc)
{
	struct drm_encoder_slave *slave = to_encoder_slave(enc);

	return container_of(slave, struct mga2_rgb, base);
}


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

#define	 MGA2_VID0_CTRL		0x00010
# define MGA2_VID0_B_MODE_OFFSET	0
# define MGA2_VID0_B_MODE_ALL	3
# define MGA2_VID0_B_MODE_2XDDR	2
# define MGA2_VID0_B_MODE_1XDDR	1
# define MGA2_VID0_B_MODE_SDR	0
# define MGA2_VID0_B_STROBE_DELAY_OFFSET	8
# define MGA2_VID0_B_STROBE_DELAY_ALL	3
# define MGA2_VID0_B_STROBE_DELAY_0	0
# define MGA2_VID0_B_STROBE_DELAY_1_4	1
# define MGA2_VID0_B_STROBE_DELAY_1_2	2
# define MGA2_VID0_B_STROBE_DELAY_3_4	3
# define MGA2_VID0_B_DDR_LOW_FIRST	(1 << 10)
# define MGA2_VID0_B_2XDDR_EN_RESYNC	(1 << 11)
# define MGA2_VID0_B_1XDDR_EN_COPY	(1 << 16)
# define MGA2_VID0_B_ENABLE	(1 << 31)


#define	 MGA2_VID0_MUX		0x00000
# define MGA25_VID0_B_AUSEL_OFFSET      4
# define MGA25_VID0_B_PXENA      (1 << 3)
# define MGA25_VID0_B_PXSEL_OFFSET      0

#define	 MGA2_VID0_GPIO_MUX		0x00040
#define MGA2_VID0_B_GPIOMUX_I2C	3

static void mga2_rgb_init_hw(struct mga2_rgb *m, bool tx_i2c)
{
	if (tx_i2c) /* turn on tx-i2c for transmiter */
		wvidc(MGA2_VID0_B_GPIOMUX_I2C, GPIO_MUX);
}

static void mga2_rgb_encoder_disable(struct drm_encoder *e)
{
	struct mga2_rgb *m = to_mga2(e);
	u32 ctrl = rvidc(CTRL) & ~MGA2_VID0_B_ENABLE;
	if (m->slave)
		drm_i2c_encoder_prepare(e);
	wvidc(ctrl, CTRL);
}

static void mga2_rgb_encoder_enable(struct drm_encoder *e)
{
	struct mga2_rgb *m = to_mga2(e);
	u32 mux, ctrl = MGA2_VID0_B_MODE_SDR;
	struct drm_display_mode *mode = &e->crtc->state->mode;
	struct drm_display_mode *amode = &e->crtc->state->adjusted_mode;
	int crtc = drm_of_encoder_active_endpoint_id(m->dev->of_node, e);

	WARN_ON(clk_set_rate(m->clks[crtc].pll, (long)amode->clock * 2 * 1000));
	WARN_ON(clk_set_rate(m->clks[crtc].pix, 2));
	WARN_ON(clk_set_rate(m->clks[crtc].aux, 1));


	mux = (crtc << MGA25_VID0_B_AUSEL_OFFSET) |
		MGA25_VID0_B_AUENA |
		(crtc << MGA25_VID0_B_PXSEL_OFFSET) |
		MGA25_VID0_B_PXENA;

	if (m->dual_edge) {
		ctrl = MGA2_VID0_B_MODE_1XDDR;
		ctrl |= MGA2_VID0_B_STROBE_DELAY_1_2 <<
				MGA2_VID0_B_STROBE_DELAY_OFFSET;
	}

	wvidc(mux, MUX);
	wvidc(ctrl | MGA2_VID0_B_ENABLE, CTRL);
	if (m->slave)
		drm_i2c_encoder_mode_set(e, mode, amode);
}

static int mga2_rgb_atomic_check(struct drm_encoder *e,
				    struct drm_crtc_state *crtc_state,
				    struct drm_connector_state *conn_state)
{
	return 0;
}

static enum drm_mode_status
mga2_rgb_mode_valid(struct drm_encoder *e,
				const struct drm_display_mode *mode)
{
	struct mga2_rgb *m = to_mga2(e);
	unsigned clock = mode->clock;
	if (mode->clock < 10000)
		return MODE_CLOCK_LOW;
	if (mga2_proto(m->dev_id) && clock > 39 * 1000) /* 800x600 */
		return MODE_CLOCK_HIGH;

	if (clock > 150 * 1000) /* full-hd/duallink */
		return MODE_CLOCK_HIGH;
	return MODE_OK;
}

static const struct drm_encoder_helper_funcs mga2_rgb_encoder_helper_funcs = {
	.enable	    = mga2_rgb_encoder_enable,
	.disable    = mga2_rgb_encoder_disable,
	.atomic_check = mga2_rgb_atomic_check,
	.mode_valid = mga2_rgb_mode_valid,
};

static void mga2_rgb_encoder_destroy(struct drm_encoder *e)
{
	struct mga2_rgb *m = to_mga2(e);
	if (m->slave)
		drm_i2c_encoder_destroy(e);
	drm_encoder_cleanup(e);
}

static const struct drm_encoder_funcs mga2_rgb_encoder_funcs = {
	.destroy = mga2_rgb_encoder_destroy,
};


static struct i2c_adapter *mga2_rgb_retrieve_slave_i2c(struct device *dev)
{
	struct device_node *phandle;
	struct i2c_adapter *slave;
	phandle = of_parse_phandle(dev->of_node, "slave-i2c-bus", 0);
	if (!phandle)
		return ERR_PTR(-ENODEV);

	slave = of_get_i2c_adapter_by_node(phandle);
	of_node_put(phandle);
	if (!slave)
		return ERR_PTR(-EPROBE_DEFER);

	return slave;
}

static int mga2_rgb_bind(struct device *dev, struct device *master,
			    void *data)
{
	int ret, i;
	struct drm_device *drm = data;
	struct mga2_rgb *m = dev_get_drvdata(dev);
	struct drm_encoder *e = &m->base.base;
	struct i2c_board_info si = {
		.type = "sil164",
		.addr = 0x70 >> 1, /* 7 bit addressing */
		.platform_data = &(struct sil164_encoder_params) {
			.input_edge  = SIL164_INPUT_EDGE_RISING,
			.input_width = m->dual_edge ? SIL164_INPUT_WIDTH_12BIT :
						SIL164_INPUT_WIDTH_24BIT,
			.input_dual  = m->dual_edge ? SIL164_INPUT_DUAL_EDGE :
					SIL164_INPUT_SINGLE_EDGE,
			.input_skew  = -4, /*default (recommended setting)*/
			.pll_filter  = SIL164_PLL_FILTER_ON,
		}
	};

	e->possible_crtcs = drm_of_find_possible_crtcs(drm, dev->of_node);
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

	m->slave = mga2_rgb_retrieve_slave_i2c(dev);
	if (IS_ERR(m->slave)) {
		ret = PTR_ERR(m->slave);
		m->slave = NULL;
		if (WARN_ON(ret != -ENODEV))
			goto err;
	}
	mga2_rgb_init_hw(m, m->slave);
	drm_encoder_helper_add(e, &mga2_rgb_encoder_helper_funcs);
	drm_encoder_init(drm, e, &mga2_rgb_encoder_funcs,
			 DRM_MODE_ENCODER_DAC, NULL);

	if (m->slave) {
		ret = drm_i2c_encoder_init(drm, to_encoder_slave(e),
					m->slave, &si);
		if (ret < 0)
			goto err_encoder_cleanup;
	}
	ret = drm_of_find_panel_or_bridge(dev->of_node,
					  1, 0, NULL, &m->bridge);
	if (WARN_ON(ret))
		goto err_slave_destroy;

	ret = drm_bridge_attach(e, m->bridge, NULL);
	if (WARN_ON(ret))
		goto err_slave_destroy;

	return 0;
err_slave_destroy:
	if (m->slave)
		drm_i2c_encoder_destroy(e);
err_encoder_cleanup:
	drm_encoder_cleanup(e);
err:
	i2c_put_adapter(m->slave);
	for (i = 0; i < ARRAY_SIZE(m->clk); i++)
		clk_put(m->clk[i]);
	return ret;
}

static void mga2_rgb_unbind(struct device *dev, struct device *master,
			       void *data)
{
	int i;
	struct mga2_rgb *m = dev_get_drvdata(dev);
	struct drm_encoder *e = &m->base.base;
	drm_encoder_cleanup(e);
	for (i = 0; i < ARRAY_SIZE(m->clk); i++)
		clk_put(m->clk[i]);
	i2c_put_adapter(m->slave);
}

static const struct component_ops mga2_rgb_ops = {
	.bind	= mga2_rgb_bind,
	.unbind	= mga2_rgb_unbind,
};

static int mga2_rgb_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device *parent = dev->parent;
	struct device_node *np = dev->of_node;
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);

	struct mga2_rgb *m = devm_kzalloc(dev, sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;

	m->dev_id = mga2_get_version(parent);
	m->dev = dev;
	m->dual_edge = of_property_read_bool(np, "dual-edge-data");


	m->regs = devm_ioremap_resource(dev, res);
	if (IS_ERR(m->regs))
		return PTR_ERR(m->regs);

	dev_set_drvdata(dev, m);

	return component_add(&pdev->dev, &mga2_rgb_ops);
}

static int mga2_rgb_remove(struct platform_device *pdev)
{
	component_del(&pdev->dev, &mga2_rgb_ops);
	return 0;
}

static const struct of_device_id mga2_rgb_dt_ids[] = {
	{ .compatible = "mcst,mga2x-rgb", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, mga2_rgb_dt_ids);

struct platform_driver mga2_rgb_driver = {
	.probe  = mga2_rgb_probe,
	.remove = mga2_rgb_remove,
	.driver = {
		.name = "mga2-rgb",
		.of_match_table = mga2_rgb_dt_ids,
	},
};
