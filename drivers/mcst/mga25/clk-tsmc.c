/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#define DEBUG
#include "drv.h"

#define	 MGA2_DC0_CLKCTRL		0x00000
#define MGA2_DC_B_ARST          (1 << 31)
#define MGA2_DC_B_AUTOCLK       (1 << 30)
#define MGA2_DC_B_EXTDIV_ENA    (1 << 29)
#define MGA2_DC_B_EXTDIV_BYPASS (1 << 28)
#define MGA2_DC_B_EXTDIV_UPD    (1 << 27)
#define MGA2_DC_B_EXTDIV_SEL_OFFSET    25
#define MGA2_DC_B_PIXDIV_ENA    (1 << 24)
#define MGA2_DC_B_PIXDIV_BYPASS (1 << 23)
#define MGA2_DC_B_PIXDIV_UPD    (1 << 22)
#define MGA2_DC_B_PIXDIV_SEL_OFFSET    20
#define MGA2_DC_B_AUXDIV_ENA    (1 << 19)
#define MGA2_DC_B_AUXDIV_BYPASS (1 << 18)
#define MGA2_DC_B_AUXDIV_UPD    (1 << 17)
#define MGA2_DC_B_AUXDIV_SEL_OFFSET    15
#define MGA2_DC_B_PLLMUX_BYPASS (1 << 14)
#define MGA2_DC_B_PLLMUX_UPD    (1 << 13)
#define MGA2_DC_B_PLLMUX_SENSE0 (1 << 10)
#define MGA2_DC_B_PIXMUX_BYPASS (1 << 9)
#define MGA2_DC_B_PIXMUX_UPD    (1 << 8)
#define MGA2_DC_B_PIXMUX_SEL_OFFSET	7
#define MGA2_DC_B_PIXMUX_SENSE1 (1 << 6)
#define MGA2_DC_B_PIXMUX_SENSE0 (1 << 5)
#define MGA2_DC_B_AUXMUX_BYPASS (1 << 4)
#define MGA2_DC_B_AUXMUX_UPD    (1 << 3)
#define MGA2_DC_B_AUXMUX_SEL_OFFSET	2
#define MGA2_DC_B_AUXMUX_SENSE1 (1 << 1)
#define MGA2_DC_B_AUXMUX_SENSE0 (1 << 0)

#define MGA2_DC_B_CLKDIV_ALL	3
#define MGA2_DC_B_CLKDIV_DIV2	0
#define MGA2_DC_B_CLKDIV_DIV4	1
#define MGA2_DC_B_CLKDIV_DIV6	2
#define MGA2_DC_B_CLKDIV_DIV7	3
#define MGA2_DC_B_CLKMUX_ALL	1
#define MGA2_DC_B_CLKMUX_SELPLL	1
#define MGA2_DC_B_CLKMUX_SELEXT	0

# define MGA25_DC_B_INPROGRESS    (1 << 31)
# define MGA25_DC_B_AUTOCLK       (1 << 30)
# define MGA25_DC_B_ACLKON        (1 << 29)

# define MGA25_DC_B_FAUXENA       (1 << 15)
# define MGA25_DC_B_FAUXSEL_OFFSET    12
# define MGA25_DC_B_FAUX_REF       (0 << MGA25_DC_B_FAUXSEL_OFFSET)
# define MGA25_DC_B_FAUX_OUT       (2 << MGA25_DC_B_FAUXSEL_OFFSET)
# define MGA25_DC_B_FAUX_DIVOUT    (3 << MGA25_DC_B_FAUXSEL_OFFSET)
# define MGA25_DC_B_FAUXDIV_OFFSET       8

# define MGA25_DC_B_FPIXENA       (1 << 7)
# define MGA25_DC_B_FPIXSEL_OFFSET    4
# define MGA25_DC_B_FPIX_REF       (0 << MGA25_DC_B_FPIXSEL_OFFSET)
# define MGA25_DC_B_FPIX_OUT       (2 << MGA25_DC_B_FPIXSEL_OFFSET)
# define MGA25_DC_B_FPIX_DIVOUT    (3 << MGA25_DC_B_FPIXSEL_OFFSET)
# define MGA25_DC_B_FPIXDIV_OFFSET       0

#define	 MGA2_DC0_CLKCTRL_ACLKON	0x00004
#define	 MGA2_DC0_INTPLLCTRL		0x00010
#define	 MGA2_DC0_INTPLLCLKF0		0x00020
#define	 MGA2_DC0_INTPLLCLKR0		0x00024
#define	 MGA2_DC0_INTPLLCLKOD0		0x00028
#define	 MGA2_DC0_INTPLLBWADJ0		0x0002C
#define	 MGA2_DC0_INTPLLCLKF1		0x00030
#define	 MGA2_DC0_INTPLLCLKR1		0x00034
#define	 MGA2_DC0_INTPLLCLKOD1		0x00038
#define	 MGA2_DC0_INTPLLBWADJ1		0x0003C

#define MGA2_DC_B_INTPLL_TEST	(1 << 0)
#define MGA2_DC_B_INTPLL_BYPASS	(1 << 8)
#define MGA2_DC_B_INTPLL_RESET	(1 << 16)
#define MGA2_DC_B_INTPLL_PWRDN	(1 << 24)
#define MGA2_DC_B_INTPLL_LOCK	(1 << 31)
#define MGA2_DC_B_INTPLL_ACLKON	(1 << 0)

#define MGA2_25175_CLKF		430
#define MGA2_25175_CLKR		61
#define MGA2_25175_CLKOD	14
#define MGA2_25175_BWADJ	215
#define MGA2_28322_CLKF		341
#define MGA2_28322_CLKR		43
#define MGA2_28322_CLKOD	14
#define MGA2_28322_BWADJ	170

#define MGA2_DC0_PLLCTRL_25		0x004
#define MGA2_DC0_PLLCLKF0INT_25		0x00C
#define MGA2_DC0_PLLCLKF0FRAC_25	0x008
#define MGA2_DC0_PLLCLKR0_25		0x010
#define MGA2_DC0_PLLCLKOD0_25		0x014

# define MGA2_DC_EXTPLLI2C_RD            (0 << 31)
# define MGA2_DC_EXTPLLI2C_WR            (1 << 31)
# define MGA2_DC_EXTPLLI2C_ADDR_OFFSET   8L


#define to_mga2(m) container_of(m, struct mga25_clk, hw)

struct mga25_clk {
	struct clk_hw hw;
	struct device *dev;
	void __iomem *regs;
	int dev_id;
	const struct mga25_pll *pll;
};

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


struct mclk {
	int nr, od, nb;
	long long nf_i, nf_f;
};

static long mga25_calc_pll(const struct mga25_pll *pll, unsigned long rate,
				struct mclk *clk, bool verbose)
{
	u32 clock = rate / 1000;
	long err, ret;
	u32 pll_clock = ~0;
	u32 ref_div = 0, fb_div = 0, frac_fb_div = 0, post_div = 0;
	if (!clock)
		return 0;

	ret = mga25_pll_compute(pll, clock, &pll_clock,
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

	clk->nf_i = fb_div;
	clk->nf_f = frac_fb_div;
	clk->nr = ref_div;
	clk->od = post_div;
	clk->nb = 1;

	if (ret) {
		if (verbose)
			DRM_ERROR("failed to calculate PLL setup.\n");
		return ret;
	}
	return pll_clock * 1000;
}

#define TIMEOUT_PLL_USEC	(50 * 1000)

#define mga25_wait_bit(__reg, __bitmask) do {		\
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

#define mga25_wait_bit_clear(__reg, __bitmask) do {	\
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

static int __mga20_set_pll(struct clk_hw *hw, struct mclk *clk)
{
	unsigned val;
	int ret = 0;
	struct mga25_clk *m = to_mga2(hw);

	/* enabling gpll0 */
	val = rcrtc(CLKCTRL) & ~MGA2_DC_B_ARST;
	wcrtc(val, CLKCTRL);

	/* switching PIXMUX & AUXMUX to reference */
	mga25_wait_bit_clear(CLKCTRL, MGA2_DC_B_PIXMUX_UPD
					| MGA2_DC_B_AUXMUX_UPD);
	val = rcrtc(CLKCTRL);
	val &= ~(MGA2_DC_B_CLKMUX_ALL << MGA2_DC_B_PIXMUX_SEL_OFFSET);
	val |= MGA2_DC_B_PIXMUX_BYPASS;
	val &= ~(MGA2_DC_B_CLKMUX_ALL << MGA2_DC_B_AUXMUX_SEL_OFFSET);
	val |= MGA2_DC_B_AUXMUX_BYPASS;
	wcrtc(val, CLKCTRL);
	val |= MGA2_DC_B_PIXMUX_UPD | MGA2_DC_B_AUXMUX_UPD;
	wcrtc(val, CLKCTRL);
	mga25_wait_bit_clear(CLKCTRL, MGA2_DC_B_PIXMUX_UPD
					| MGA2_DC_B_AUXMUX_UPD);

	/* resetting PLL */
	wcrtc(MGA2_DC_B_INTPLL_RESET, INTPLLCTRL);
	/* configuring channel #0 */
	wcrtc(clk->nf_i - 1, INTPLLCLKF0);
	wcrtc(clk->nr - 1, INTPLLCLKR0);
	wcrtc(clk->od - 1, INTPLLCLKOD0);
	wcrtc(clk->nb - 1, INTPLLBWADJ0);

	udelay(5);
	/* clearing reset and waiting for lock */
	wcrtc(0, INTPLLCTRL);
	udelay(5);
	mga25_wait_bit(INTPLLCTRL, MGA2_DC_B_INTPLL_LOCK);
	/* waiting for clock sense */
	mga25_wait_bit(CLKCTRL, MGA2_DC_B_AUXMUX_SENSE1 |
				MGA2_DC_B_PIXMUX_SENSE1);
out:
	return ret;
}

static int mga20_set_pll(struct clk_hw *hw, struct mclk *clk)
{
	u32 val;
	int ret = 0;
	int int_pll = 1;
	struct mga25_clk *m = to_mga2(hw);

	ret = __mga20_set_pll(hw, clk);
	if (ret)
		goto out;

	mga25_wait_bit_clear(CLKCTRL, MGA2_DC_B_PIXMUX_UPD);
	val = rcrtc(CLKCTRL) & ~(MGA2_DC_B_PIXMUX_BYPASS |
			(MGA2_DC_B_CLKMUX_ALL << MGA2_DC_B_PIXMUX_SEL_OFFSET));
	val |= (int_pll << MGA2_DC_B_PIXMUX_SEL_OFFSET);
	wcrtc(val, CLKCTRL);
	val |= MGA2_DC_B_PIXMUX_UPD;
	wcrtc(val, CLKCTRL);
	mga25_wait_bit_clear(CLKCTRL, MGA2_DC_B_PIXMUX_UPD);

	mga25_wait_bit_clear(CLKCTRL, MGA2_DC_B_AUXMUX_UPD);
	val = rcrtc(CLKCTRL) & ~(MGA2_DC_B_AUXMUX_BYPASS |
		(MGA2_DC_B_CLKMUX_ALL << MGA2_DC_B_AUXMUX_SEL_OFFSET));
	val |= (int_pll << MGA2_DC_B_AUXMUX_SEL_OFFSET);
	wcrtc(val, CLKCTRL);
	val |= MGA2_DC_B_AUXMUX_UPD;
	wcrtc(val, CLKCTRL);
	mga25_wait_bit_clear(CLKCTRL, MGA2_DC_B_AUXMUX_UPD);

out:
	return ret;
}

static int mga25_set_pll(struct clk_hw *hw, struct mclk *clk)
{
	unsigned v;
	int ret = 0;
	struct mga25_clk *m = to_mga2(hw);

	/* switching PIXMUX & AUXMUX to reference */
	mga25_wait_bit_clear(CLKCTRL, MGA25_DC_B_INPROGRESS);
	v = rcrtc(CLKCTRL);
	v |= MGA25_DC_B_FPIXENA;
	wcrtc(v, CLKCTRL);
	mga25_wait_bit_clear(CLKCTRL, MGA25_DC_B_INPROGRESS);

	/* resetting PLL */
	wcrtc(MGA2_DC_B_INTPLL_RESET, PLLCTRL_25);

	wcrtc(clk->nf_i, PLLCLKF0INT_25);
	wcrtc((clk->nf_f) >> 1, PLLCLKF0FRAC_25);
	wcrtc(clk->nr - 1, PLLCLKR0_25);
	wcrtc(clk->od - 1, PLLCLKOD0_25);

	udelay(5);
	/* clearing reset and waiting for lock */
	wcrtc(0, PLLCTRL_25);
	udelay(5);
	mga25_wait_bit(PLLCTRL_25, MGA2_DC_B_INTPLL_LOCK);
out:
	return ret;
}

static int mga25_pll_enable(struct clk_hw *hw)
{
	/* Wait until LVDS PLL is locked and ready */
/*	while (!mdp4_read(mdp4_kms, REG_MDP4_LVDS_PHY_PLL_LOCKED))
		cpu_relax();
*/
	return 0;
}

static void mga25_pll_disable(struct clk_hw *hw)
{
}

static unsigned long mga25_pll_recalc_rate(struct clk_hw *hw,
				unsigned long parent_rate)
{
	struct mclk clk;
	struct mga25_clk *m = to_mga2(hw);
	return parent_rate;
	return mga25_calc_pll(m->pll, parent_rate, &clk, false);
}

static long mga25_pll_round_rate(struct clk_hw *hw, unsigned long rate,
		unsigned long *parent_rate)
{
	struct mclk clk;
	struct mga25_clk *m = to_mga2(hw);
	return rate;
	return mga25_calc_pll(m->pll, rate, &clk, false);
}

static int mga20_pll_set_rate(struct clk_hw *hw, unsigned long rate,
		unsigned long parent_rate)
{
	struct mclk clk;
	struct mga25_clk *m = to_mga2(hw);
	long ret = mga25_calc_pll(m->pll, rate, &clk, true);
	if (ret < 0)
		return ret;
	ret = mga20_set_pll(hw, &clk);
	if (ret < 0)
		return ret;
	return 0;
}

static int mga25_pll_set_rate(struct clk_hw *hw, unsigned long rate,
		unsigned long parent_rate)
{
	struct mclk clk;
	struct mga25_clk *m = to_mga2(hw);
	long ret = mga25_calc_pll(m->pll, rate, &clk, true);
	if (ret < 0)
		return ret;
	ret = mga25_set_pll(hw, &clk);
	if (ret < 0)
		return ret;
	return 0;
}

static const struct clk_ops mga20_pll_ops = {
	.enable      = mga25_pll_enable,
	.disable     = mga25_pll_disable,
	.recalc_rate = mga25_pll_recalc_rate,
	.round_rate  = mga25_pll_round_rate,
	.set_rate    = mga20_pll_set_rate,
};

static const struct clk_ops mga25_pll_ops = {
	.enable      = mga25_pll_enable,
	.disable     = mga25_pll_disable,
	.recalc_rate = mga25_pll_recalc_rate,
	.round_rate  = mga25_pll_round_rate,
	.set_rate    = mga25_pll_set_rate,
};

static int mga25_pll_probe(struct platform_device *pdev)
{
	int ret = 0;
	struct clk *clk;
	struct device *dev = &pdev->dev;
	struct device *parent = dev->parent;
	struct device_node *np = dev->of_node;
	const char *name = dev_name(dev);
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	struct mga25_clk *m = devm_kzalloc(dev, sizeof(*m), GFP_KERNEL);
	struct clk_init_data init = {
		.name = name,
		.ops = &mga25_pll_ops,
	};
	if (!m)
		return -ENOMEM;
	m->dev_id = mga25_get_version(parent);
	m->dev = dev;
	m->pll = of_device_get_match_data(dev);

	m->regs = devm_ioremap(dev, res->start, resource_size(res));
	if (IS_ERR(m->regs))
		return PTR_ERR(m->regs);

	if (mga20(m->dev_id))
		init.ops = &mga20_pll_ops;

	m->hw.init = &init;
	clk = devm_clk_register(dev, &m->hw);
	if (WARN_ON(IS_ERR(clk)))
		return PTR_ERR(clk);

	ret = of_clk_add_provider(np, of_clk_src_simple_get, clk);

	return ret;
}

static int mga25_pll_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	of_clk_del_provider(np);
	return 0;
}

static const struct mga25_pll tcitsmcn40 = {
	.reference_freq = 100 * 1000,
	.min_feedback_div = 1, /* NF */
	.max_feedback_div = 4096,
	.min_ref_div = 1, /* NR */
	.max_ref_div =  5 /*64*/, /* e1c+ does not like more then that */
	.pll_out_min = 6.8e+08 / 1000 / 16, /*Fvco_min / max_post_div kHz*/
	.pll_out_max = 3.4e+09 / 1000,
	.min_post_div = 1,  /* OD */
	.max_post_div = 16,
};

static const struct mga25_pll tcitsmcn16 = {
	.reference_freq = 100 * 1000,
	.min_feedback_div = 1, /* NF */
	.max_feedback_div = 262144,
	.min_ref_div = 1, /* NR */
	.max_ref_div =  3 /*4096*/,
	.pll_out_min = 1.5e+07 / 1000 / 2048, /*Fvco_min / max_post_div kHz*/
 #ifdef CONFIG_E2K /*bug 130125: PLL losing lock*/
	.pll_out_max = 3.0e+09 / 1000,
#elif CONFIG_E90S /*bug 140648: PLL losing lock*/
	.pll_out_max = 2.5e+09 / 1000,
#else
	.pll_out_max = 3.25e+09 / 1000,
#endif
	.min_post_div = 1,  /* OD */
	.max_post_div = 2048,
	/*.flags = MGA2_PLL_USE_FRAC_FB_DIV,*/
};

static const struct of_device_id __maybe_unused mga25_pll_dt_ids[] = {
	{
	.compatible = "mcst,tcitsmcn40",
	  .data = &tcitsmcn40,
	},
	{
	.compatible = "mcst,tcitsmcn16",
	  .data = &tcitsmcn16,
	},
	{ }
};

MODULE_DEVICE_TABLE(of, mga25_pll_dt_ids);

struct platform_driver mga25_pll_driver = {
	.driver = {
		.name = "tcitsmc-pll",
		.of_match_table = of_match_ptr(mga25_pll_dt_ids),
	},
	.probe = mga25_pll_probe,
	.remove = mga25_pll_remove,
};

