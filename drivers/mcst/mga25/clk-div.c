/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#define DEBUG
#include "drv.h"


#define __rcrtc(__offset)	 ({				\
	unsigned __v = 0;					\
	__v = readl(m->regs + MGA2_DC0_ ## __offset);	\
	__v;				\
})
#define __wcrtc(__val, __offset)	do {		\
	writel(__val, m->regs + MGA2_DC0_ ## __offset); \
} while (0)


#ifdef DEBUG
#define rcrtc(__offset)						\
({								\
	unsigned __val = __rcrtc(__offset);			\
	DRM_DEV_DEBUG_KMS(m->dev, "R: %x: %s\n", __val, # __offset);	\
	__val;							\
})

#define wcrtc(__val, __offset) do {				\
	unsigned __val2 = __val;				\
	DRM_DEV_DEBUG_KMS(m->dev, "W: %x: %s\n", __val2, # __offset);	\
	__wcrtc(__val2, __offset);				\
} while(0)

#else
#define		rcrtc		__rcrtc
#define		wcrtc		__wcrtc
#endif


#define	 MGA2_DC0_CLKCTRL		0x00000

struct mmux {
	struct clk_hw hw;
	struct device *dev;
	void __iomem *regs;
	int dev_id;
	const struct clk_div_table *tlb;
	u32 shift;
	u32 width;
};

#define to_mga2(m) container_of(m, struct mmux, hw)

static unsigned mga25_get_table_val(const struct clk_div_table *table,
							unsigned int div)
{
	const struct clk_div_table *clkt;

	for (clkt = table; clkt->div; clkt++)
		if (clkt->div == div)
			return clkt->val;
	return 0;
}

static struct clk_div_table *mga25_get_div_table(struct device *dev)
{
	struct device_node *np = dev->of_node;
	struct clk_div_table *t;
	u32 v, d;
	int i, n;

	if (!of_get_property(np, "div-table", &n))
		return NULL;
	if (!of_get_property(np, "val-table", &n))
		return NULL;

	n /= 4;
	t = devm_kcalloc(dev, n + 1, sizeof(*t), GFP_KERNEL);
	if (!t)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < n; i++) {
		of_property_read_u32_index(np, "div-table", i, &d);
		of_property_read_u32_index(np, "val-table", i, &v);
		t[i].div = d;
		t[i].val = v;
	}
	return t;
}

static int mga25_pll_enable(struct clk_hw *hw)
{
	return 0;
}

static void mga25_pll_disable(struct clk_hw *hw)
{
}
static unsigned long mga25_pll_recalc_rate(struct clk_hw *hw,
				unsigned long parent_rate)
{
	return parent_rate;
}

static long mga25_pll_round_rate(struct clk_hw *hw, unsigned long rate,
		unsigned long *parent_rate)
{
	return rate;
}


static int mga25_pll_set_rate(struct clk_hw *hw, unsigned long rate,
		unsigned long parent_rate)
{
	struct mmux *m = to_mga2(hw);
	u32 v = mga25_get_table_val(m->tlb, rate);
	u32 val = rcrtc(CLKCTRL);
	if (WARN_ON(!v))
		return -EINVAL;

	val &= ~(clk_div_mask(m->width) << m->shift);
	val |= v << m->shift;
	wcrtc(val, CLKCTRL);

	return 0;
}


static const struct clk_ops mga25_pll_ops = {
	.enable      = mga25_pll_enable,
	.disable     = mga25_pll_disable,
	.set_rate    = mga25_pll_set_rate,
	.recalc_rate = mga25_pll_recalc_rate,
	.round_rate  = mga25_pll_round_rate,
};

static int mga25_clk_mux_probe(struct platform_device *pdev)
{
	int ret = 0;
	struct clk *clk;
	struct device *dev = &pdev->dev;
	struct device *parent = dev->parent;
	struct device_node *np = dev->of_node;
	const char *name = dev_name(dev);
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	struct mmux *m = devm_kzalloc(dev, sizeof(*m), GFP_KERNEL);
	struct clk_init_data init = {
		.name = name,
		.ops = &mga25_pll_ops,
	};
	if (WARN_ON(!m))
		return -ENOMEM;
	if (WARN_ON(!res))
		return -ENXIO;
	m->dev_id = mga25_get_version(parent);
	m->dev = dev;

	m->regs = devm_ioremap(dev, res->start, resource_size(res));
	if (WARN_ON(IS_ERR(m->regs)))
		return PTR_ERR(m->regs);
	m->tlb = mga25_get_div_table(dev);
	of_property_read_u32(np, "shift", &m->shift);
	of_property_read_u32(np, "width", &m->width);

	m->hw.init = &init;
	clk = devm_clk_register(dev, &m->hw);
	if (WARN_ON(IS_ERR(clk)))
		return PTR_ERR(clk);

	ret = of_clk_add_provider(np, of_clk_src_simple_get, clk);

	return ret;
}

static int mga25_clk_mux_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	of_clk_del_provider(np);
	return 0;
}

static const struct of_device_id __maybe_unused mga25_clk_mux_dt_ids[] = {
	{
		.compatible = "mcst,clk-mux-mga2",
	},
	{ }
};
MODULE_DEVICE_TABLE(of, mga25_clk_mux_dt_ids);

struct platform_driver mga25_clk_mux_driver = {
	.driver = {
		   .name = "mga2-clk-mux",
		   .of_match_table = of_match_ptr(mga25_clk_mux_dt_ids),
		    },
	.probe = mga25_clk_mux_probe,
	.remove = mga25_clk_mux_remove,
};

