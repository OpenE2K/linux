/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#define DEBUG
#include "drv.h"


#define to_mga2(m) container_of(m, struct cy22394, hw)

struct cy22394 {
	struct clk_hw hw;
	struct device *dev;
	struct i2c_client *i2c;
	struct regmap *regm;
	int pll_nr;
};



static inline void __wcrtc(struct cy22394 *m, u32 val, u32 reg)
{
	int ret = regmap_write(m->regm, reg, val);
	WARN(ret, "w:ret = %d\n", ret);
}

static inline u32 __rcrtc(struct cy22394 *m, u32 reg)
{
	unsigned val = 0;
	int ret = regmap_read(m->regm, reg, &val);
	WARN(ret, "w:ret = %d\n", ret);
	return val;
}

#define rcrtc(__offset)						\
({								\
	unsigned __val = __rcrtc(m, __offset);			\
	DRM_DEV_DEBUG_KMS(m->dev, "R: %x: %s\n", __val, # __offset);	\
	__val;							\
})

#define wcrtc(__offset, __val) do {				\
	unsigned __val2 = __val;				\
	DRM_DEV_DEBUG_KMS(m->dev, "W: %x: %s\n", __val2, # __offset);	\
	__wcrtc(m, __val2, __offset);				\
} while(0)

/*
 *******************************************************************************
 * CY2239, Three-PLL, Serial-Programmable, Flash-Programmable Clock Generator
 *******************************************************************************
 */

#define FS_REF		0x0	/* Reference clock [000] */
#define FS_PLL1_0	0x2	/* PLL1 0* Phase   */
#define FS_PLL1_180	0x3	/* PLL1 180* Phase */
#define FS_PLL2_0	0x4	/* PLL2 0* Phase   */
#define FS_PLL2_180	0x5	/* PLL2 180* Phase */
#define FS_PLL3_0	0x6	/* PLL3 0* Phase   */
#define FS_PLL3_180	0x7	/* PLL3 180* Phase */

/*
 * Assumes:
 *    DivSel = 0
 */
static void __set_clk_fs(struct cy22394 *m, u8 a, u8 b, u8 c)
{
	u8 d = FS_REF;

	/* ClkA_FS[2:0] */
	wcrtc(0x08, (rcrtc(0x08) & 0x7F)
		     | ((a & 0x01) << 7));
	wcrtc(0x0E, (rcrtc(0x0E) & 0xFC)
		     | ((a & 0x06) >> 1));
	/* ClkB_FS[2:0] */
	wcrtc(0x0A, (rcrtc(0x0A) & 0x7F)
		     | ((b & 0x01) << 7));
	wcrtc(0x0E, (rcrtc(0x0E) & 0xF3)
		     | ((b & 0x06) << 1));
	/* ClkC_FS[2:0] */
	wcrtc(0x0C, (rcrtc(0x0C) & 0x7F)
		     | ((c & 0x01) << 7));
	wcrtc(0x0E, (rcrtc(0x0E) & 0xCF)
		     | ((c & 0x06) << 3));
	/* ClkD_FS[2:0] */
	wcrtc(0x0D, (rcrtc(0x0D) & 0x7F)
		     | ((d & 0x01) << 7));
	wcrtc(0x0E, (rcrtc(0x0E) & 0x3F)
		     | ((d & 0x06) << 5));
}

static inline unsigned pll_to_reg_offset(int pll)
{
	unsigned base;

	switch (pll) {
	case 1:
		base = 0x40;
		break;
	case 2:
		base = 0x11;
		break;
	case 3:
		base = 0x14;
		break;
	default:
		DRM_ERROR("Invalid PLL index %d\n", pll);
		return 0x11;
	}
	return base;
}

static void
__cy22394_set_pll(struct cy22394 *m, int base, u8 Q, uint16_t P,
	       u8 PO)
{
	/* PLL*_Q[7:0] */
	wcrtc(base + 0, Q);

	/* PLL*_P[7:0] */
	wcrtc(base + 1, P & 0xFF);
	{
		u8 val;
		u8 LF = 0x0;

		int P_T = (2 * ((P & 0x3FF) + 3)) + (PO & 0x01);

		if (P_T <= 231)
			LF = 0x0;
		else if (P_T <= 626)
			LF = 0x1;
		else if (P_T <= 834)
			LF = 0x2;
		else if (P_T <= 1043)
			LF = 0x3;
		else if (P_T <= 1600)
			LF = 0x4;

		/* PLL*_En, PLL*_LF, PLL*_PO, PLL*_P[9:8] */
		val = (P & 0x300) >> 8;
		val |= (PO & 0x1) << 2;
		val |= LF << 3;
		/* val |= (enabled & 0x01) << 6; */

		wcrtc(base + 2, val);
	}
}

static void
cy22394_set_pll(struct cy22394 *m, int pll, u8 Q, uint16_t P, u8 PO)
{
	unsigned base = pll_to_reg_offset(pll);
	int i;
	int nr = (pll == 1) ? 8 : 1;
	for (i = 0; i < nr; i++, base += 3)
		__cy22394_set_pll(m, base, Q, P, PO);

}

static void
__cy22394_set_pll_enabled(struct cy22394 *m, u32 base, u8 enabled)
{
	u8 val;
	val = rcrtc(base + 2);
	val = val & (~(0x01 << 6));
	val |= (enabled & 0x01) << 6;
	wcrtc(base + 2, val);
}

static void
cy22394_set_pll_enabled(struct cy22394 *m, int pll, u8 enabled)
{
	unsigned base = pll_to_reg_offset(pll);
	int i;
	int nr = (pll == 1) ? 8 : 1;
	for (i = 0; i < nr; i++, base += 3)
		__cy22394_set_pll_enabled(m, base, enabled);

}

struct mclk {
	int div;		/* [6:0] Linear output divider */

	int q;			/* [7:0] PPL*_Q */
	int p;			/* [9:0] PPL*_P */
	int po;			/* [0:0] PPL_PO */
};

/* Fpll = Fref * (Pt / Qt) */
static const struct mga25_pll cy22394_pll = {
	.reference_freq = 14.31818e+6 / 1000,
	.min_feedback_div = 2 * (0 + 3) + 0, /* Pt, Pt = 2 * (P + 3) + PO */
	.max_feedback_div = 2 * (0x7ff + 3) + 1,
	.min_ref_div = 0 + 2, /* Qt = Q + 2 */
	.max_ref_div = 0xff + 2,
	.pll_out_min = 10e+06 / 1000,
	.pll_out_max = 375e+06 / 1000,
	.min_post_div = 1,  /* use PLL1 (CLKE) PECL output */
	.max_post_div = 1,
};

static long mga25_calc_pll(unsigned long rate,
				struct mclk *clk, bool verbose)
{
	u32 clock = rate / 1000;
	long err, ret;
	u32 pll_clock = ~0;
	u32 ref_div = 0, fb_div = 0, frac_fb_div = 0, post_div = 0;
	if (!clock)
		return 0;

	ret = mga25_pll_compute(&cy22394_pll, clock, &pll_clock,
			    &fb_div, &frac_fb_div, &ref_div, &post_div);

	err = abs((long)clock - (long)pll_clock);
	if (verbose) {
		DRM_DEBUG_KMS("Calculated: clock: %d -> %d\n"
			"(err: %ld.%02ld%%);\n"
			"\tdividers - M: %d.%d N: %d, postdiv: %d\n",
			clock, pll_clock,
			err * 100 / pll_clock,
			err * 10000 / pll_clock % 100,
			fb_div, frac_fb_div, ref_div, post_div);
	}

	clk->po = fb_div % 2 ? 1 : 0;
	clk->p = (fb_div - clk->po) / 2  - 3;
	clk->q = ref_div - 2;
	clk->div = post_div;

	if (ret) {
		if (verbose)
			DRM_ERROR("failed to calculate PLL setup.\n");
		return ret;
	}
	return pll_clock * 1000;
}

static void cy22394_pll_init_pixclock(struct cy22394 *m)
{
	int reg = 0;

	/* Init all i2c */
	for (reg = 0x08; reg <= 0x17; reg++)
		wcrtc(reg, 0x0);

	for (reg = 0x40; reg <= 0x57; reg++)
		wcrtc(reg, 0x0);

	wcrtc(0x17, 0x0);
	wcrtc(0x0F, (0x01 << 6) | (0x01 << 4) | (0x01 << 2) | 0x01);
	wcrtc(0x0D, 0x01);
	wcrtc(0x10, 0);
}

static int cy22394_ext_pll_set_pixclock(struct cy22394 *m, int pll,
			struct mclk *c)
{
	switch (pll) {
	case 2:
		wcrtc(0x08, 0x0);
		__set_clk_fs(m, FS_REF, FS_REF, FS_PLL3_0);
		{
			/* Reset vidclk enabled bit */
			cy22394_set_pll_enabled(m, 2, 0);
			cy22394_set_pll(m, 2, c->q, c->p, c->po);
		}
		__set_clk_fs(m, FS_PLL2_0, FS_REF, FS_PLL3_0);
		wcrtc(0x08, ((FS_PLL2_0 & 0x01) << 7)
			     | (c->div & 0x7F));

		/* Set vidclk enabled bit */
		cy22394_set_pll_enabled(m, 2, 1);
		break;

	case 3:
		wcrtc(0x0C, 0x0);
		__set_clk_fs(m, FS_PLL2_0, FS_REF, FS_REF);
		{
			/* Reset vidclk enabled bit */
			cy22394_set_pll_enabled(m, 3, 0);
			cy22394_set_pll(m, 3, c->q, c->p,
				     c->po);
		}
		__set_clk_fs(m, FS_PLL2_0, FS_REF, FS_PLL3_0);
		wcrtc(0x0C, ((FS_PLL3_0 & 0x01) << 7)
			     | (c->div & 0x7F));

		/* Set vidclk enabled bit */
		cy22394_set_pll_enabled(m, 3, 1);
		break;
	case 1:
		wcrtc(0x0A, 0x0);
		__set_clk_fs(m, FS_REF, FS_PLL1_0, FS_REF);
		/* Reset vidclk enabled bit */
		cy22394_set_pll_enabled(m, 1, 0);
		cy22394_set_pll(m, 1, c->q, c->p, c->po);

		__set_clk_fs(m, FS_PLL2_0, FS_PLL1_0, FS_PLL3_0);
		wcrtc(0x0A, ((FS_PLL1_0 & 0x01) << 7)
			     | (c->div & 0x7F));

		/* Set vidclk enabled bit */
		cy22394_set_pll_enabled(m, 1, 1);
		break;
	}

	return 0;
}

/********************************************************/

static int cy22394_pll_enable(struct clk_hw *hw)
{
	return 0;
}

static void cy22394_pll_disable(struct clk_hw *hw)
{
}
static unsigned long cy22394_pll_recalc_rate(struct clk_hw *hw,
				unsigned long parent_rate)
{
	return parent_rate;
}

static long cy22394_pll_round_rate(struct clk_hw *hw, unsigned long rate,
		unsigned long *parent_rate)
{
	return rate;
}


static int cy22394_pll_set_rate(struct clk_hw *hw, unsigned long rate,
		unsigned long parent_rate)
{
	struct mclk clk;
	struct cy22394 *m = to_mga2(hw);
	
	long ret = mga25_calc_pll(rate, &clk, true);
	if (ret < 0)
		return ret;
	return cy22394_ext_pll_set_pixclock(m, m->pll_nr, &clk);
}


static const struct clk_ops cy22394_pll_ops = {
	.enable      = cy22394_pll_enable,
	.disable     = cy22394_pll_disable,
	.set_rate    = cy22394_pll_set_rate,
	.recalc_rate = cy22394_pll_recalc_rate,
	.round_rate  = cy22394_pll_round_rate,
};

/********************************************************/
static const struct regmap_range cy22394_volatile_ranges[] = {
	{ .range_min = 0, .range_max = 0xff },
};

static const struct regmap_access_table cy22394_volatile_table = {
	.yes_ranges = cy22394_volatile_ranges,
	.n_yes_ranges = ARRAY_SIZE(cy22394_volatile_ranges),
};

static const struct regmap_config cy22394_regmap_config = {
	.reg_bits = 8,
	.val_bits = 8,
	.max_register = 0x57,
	.volatile_table = &cy22394_volatile_table,
	.cache_type = REGCACHE_NONE,
};
/********************************************************/

static int cy22394_probe(struct i2c_client *client,
			 const struct i2c_device_id *id)
{

	int ret = 0;
	struct clk *clk;
	struct device *dev = &client->dev;
	struct device_node *np = dev->of_node;
	const char *name = dev_name(dev);
	struct cy22394 *m = devm_kzalloc(dev, sizeof(*m), GFP_KERNEL);
	struct clk_init_data init = {
		.name = name,
		.ops = &cy22394_pll_ops,
	};
	if (WARN_ON(!m))
		return -ENOMEM;
	m->dev = dev;
	m->pll_nr = 1;

	m->i2c = client;
	m->regm = devm_regmap_init_i2c(client, &cy22394_regmap_config);
	if (IS_ERR(m->regm))
		return PTR_ERR(m->regm);

	m->hw.init = &init;
	cy22394_pll_init_pixclock(m);
	clk = devm_clk_register(dev, &m->hw);
	if (WARN_ON(IS_ERR(clk)))
		return PTR_ERR(clk);

	ret = of_clk_add_provider(np, of_clk_src_simple_get, clk);
	return ret;
}

static int cy22394_remove(struct i2c_client *client)
{
	struct device *dev = &client->dev;
	struct device_node *np = dev->of_node;
	of_clk_del_provider(np);
	return 0;
}

static const struct of_device_id cy22394_dt_ids[] = {
	{ .compatible = "cypress,cy22394", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, cy22394_dt_ids);

static const struct i2c_device_id cy22394_i2c_ids[] = {
	{ "cy22394", 0 },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(i2c, cy22394_i2c_ids);

struct i2c_driver cy22394_driver = {
	.probe = cy22394_probe,
	.remove = cy22394_remove,
	.driver = {
		.name = "cy22394",
		.of_match_table = cy22394_dt_ids,
	},
	.id_table = cy22394_i2c_ids,
};
