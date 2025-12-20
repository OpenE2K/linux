/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#define DEBUG

#include "drv.h"

#include <drm/bridge/dw_mipi_dsi.h>
#include <drm/drm_mipi_dsi.h>

struct mga25_dsi {
	struct drm_encoder base;
	struct device *dev;
	void __iomem *regs;
	int dev_id;

	struct dw_mipi_dsi *dsi;
	struct dw_mipi_dsi_plat_data pdata;
	unsigned lane_mbps; /* per lane */
	u16 input_div;
	u16 feedback_div;
	union {
		struct clk *clk[MGA2_MAX_CRTS_NR * 3];
		struct {
			struct clk *pll;
			struct clk *pix;
			struct clk *aux;
		} clks[MGA2_MAX_CRTS_NR];
	};
};

#define to_mga25_dsi(x)	container_of(x, struct mga25_dsi, base)


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
	DRM_DEV_DEBUG_KMS(m->dev, "W: %x: %s\n", __val2, # __offset);	\
	__wvidc(__val2, __offset);				\
} while(0)

#else
#define		rvidc		__rvidc
#define		wvidc		__wvidc
#endif

#define	 MGA2_VID0_CTRL		0x00010
# define MGA2_VID12_B_HS_CONV_OFFSET     2
# define MGA2_VID12_B_VS_CONV_OFFSET     4
# define MGA2_VID12_B_DE_CONV_OFFSET     6
# define MGA2_VID12_B_CONV_ALL           3
# define MGA2_VID12_B_CONV_NON_INV       0
# define MGA2_VID12_B_CONV_INV           1
# define MGA2_VID12_B_CONV_DIRECT        2

# define MGA2_VID12_B_UPDATECFG          (1 << 8)
# define MGA2_VID12_B_COLORM             (1 << 9)
# define MGA2_VID12_B_SHUTDOWNN           (1 << 10)

# define MGA2_VID12_B_CFGCLKFREQRANGE_OFFSET	16
# define MGA2_VID12_B_CFGCLKFREQRANGE_MASK	(0x7f << MGA2_VID12_B_CFGCLKFREQRANGE_OFFSET)

# define MGA2_VID12_B_HSFREQRANGE_OFFSET	24
# define MGA2_VID12_B_HSFREQRANGE_MASK	(0x7f << MGA2_VID12_B_HSFREQRANGE_OFFSET)

# define MGA2_VID12_B_ENABLE             (1 << 31)

# define MGA2_VID0_B_ENABLE              (1 << 31)

#define	 MGA2_VID0_MUX		0x00000
# define MGA25_VID0_B_AUENA      (1 << 7)
# define MGA25_VID0_B_AUSEL_OFFSET      4
# define MGA25_VID0_B_PXENA      (1 << 3)
# define MGA25_VID0_B_PXSEL_OFFSET      0

#define	 MGA2_VID0_APBADDR	0x014
#define	 MGA2_VID0_APBDATA	0x018

#define	 MGA2_VID0_GPIO_MUX		0x00040
#define MGA2_VID0_B_GPIOMUX_I2C		3

static void mga25_dsi_init_hw(struct mga25_dsi *m)
{
	u32 val = rvidc(CTRL);
	wvidc(val, CTRL);
	val |= MGA2_VID0_B_ENABLE;
	wvidc(val, CTRL);
#if 0 /*i2c is broken, bug # 138248 */
	/* turn on tx-i2c for transmiter */
	wvidc(MGA2_VID0_B_GPIOMUX_I2C, GPIO_MUX);
#endif
}

static void mga25_dsi_encoder_disable(struct drm_encoder *e)
{
	struct mga25_dsi *m = to_mga25_dsi(e);
	u32 ctrl = rvidc(CTRL);
	u32 octrl = ctrl & ~MGA2_VID0_B_ENABLE;

	if (ctrl == octrl) /*everything is already set */
		return;
	wvidc(octrl, CTRL);
}

static void mga25_dsi_encoder_enable(struct drm_encoder *e)
{
	struct mga25_dsi *m = to_mga25_dsi(e);
	u32 mux, ctrl = rvidc(CTRL);
	struct drm_display_mode *mode = &e->crtc->state->adjusted_mode;
	int crtc = drm_of_encoder_active_endpoint_id(m->dev->of_node, e);

	WARN_ON(clk_set_rate(m->clks[crtc].pll, mode->clock * 1000));
	WARN_ON(clk_set_rate(m->clks[crtc].pix, 1));

	mux = crtc | MGA25_VID0_B_PXENA;

	ctrl &= ~((MGA2_VID12_B_CONV_ALL << MGA2_VID12_B_DE_CONV_OFFSET) |
		(MGA2_VID12_B_CONV_ALL << MGA2_VID12_B_HS_CONV_OFFSET) |
		(MGA2_VID12_B_CONV_ALL << MGA2_VID12_B_VS_CONV_OFFSET));

	ctrl |= (MGA2_VID12_B_CONV_DIRECT << MGA2_VID12_B_DE_CONV_OFFSET) |
		(MGA2_VID12_B_CONV_DIRECT << MGA2_VID12_B_HS_CONV_OFFSET) |
		(MGA2_VID12_B_CONV_DIRECT << MGA2_VID12_B_VS_CONV_OFFSET);
	wvidc(mux, MUX);
	wvidc(ctrl | MGA2_VID0_B_ENABLE, CTRL);

}

static int mga25_dsi_reg_read(void *context, unsigned reg,
				  unsigned *result)
{
	struct mga25_dsi *m = context;
	__wvidc(reg, APBADDR);
	*result = __rvidc(APBDATA);
	return 0;
}

static int mga25_dsi_reg_write(void *context, unsigned reg,
				  unsigned value)
{
	struct mga25_dsi *m = context;
	__wvidc(reg, APBADDR);
	 __wvidc(value, APBDATA);
	return 0;
}

static struct regmap_config mga25_dsi_regmap_config = {
	.name = "dsi-regs",
	.reg_bits	= 32,
	.val_bits	= 32,
	.reg_stride	= 4,
	.max_register	= 0x2b4,
	.fast_io = true,

	.reg_read = mga25_dsi_reg_read,
	.reg_write = mga25_dsi_reg_write,
};

static enum drm_mode_status
mga25_dsi_mode_valid(struct drm_encoder *e,
				const struct drm_display_mode *mode)
{
	unsigned clock = mode->clock;
	unsigned bpp = 24;
	unsigned lanes = 4;
	if (mode->clock < 10000)
		return MODE_CLOCK_LOW;

	/* take 1 / 0.8, since mbps must big than bandwidth of RGB */
	clock = clock * (bpp / lanes) * 10 / 8;
	/* The data rate is given by the double of the PLL output clock phases frequency:
	 *	 Data rate (Gbps) = PLL Fout (GHz) * 2 */
	clock /= 2;
	/* if (clock < 80 * 1000) TODO:
		return MODE_CLOCK_LOW; */
	if (clock > 1250 * 1000)
		return MODE_CLOCK_HIGH;
	return MODE_OK;
}

static const struct drm_encoder_helper_funcs mga25_dsi_encoder_helper_funcs = {
	.enable		= mga25_dsi_encoder_enable,
	.disable	= mga25_dsi_encoder_disable,
	.mode_valid	= mga25_dsi_mode_valid,
};

static const struct drm_encoder_funcs mga25_dsi_encoder_funcs = {
	.destroy = drm_encoder_cleanup,
};
#if 0
static u32 dsi_read(struct mga25_dsi *m, u32 reg)
{
	u32 val;
	WARN_ON_ONCE(regmap_read(m->pdata.regm, reg, &val));
	return val;
}
#endif
static void dsi_write(struct mga25_dsi *m, u32 reg, u32 val)
{
	WARN_ON_ONCE(regmap_write(m->pdata.regm, reg, val));
}

#define DSI_PHY_TST_CTRL0		0xb4
#define PHY_TESTCLK			BIT(1)
#define PHY_UNTESTCLK			0
#define PHY_TESTCLR			BIT(0)
#define PHY_UNTESTCLR			0

#define DSI_PHY_TST_CTRL1		0xb8
#define PHY_TESTEN			BIT(16)
#define PHY_UNTESTEN			0
#define PHY_TESTDOUT_SHIFT		8
#define PHY_TESTDOUT_MASK		0xff
#define PHY_TESTDOUT(n)			(((n) & PHY_TESTDOUT_MASK) << \
						PHY_TESTDOUT_SHIFT)
#define PHY_TESTDIN(n)			(((n) & 0xff) << 0)


static void mga25_dsi_phy_set_addr(struct mga25_dsi *m,
				  u16 test_code)
{

	/* 1. For writing the 4-bit testcode MSBs:*/
	/* a.  Ensure that testclk and testen is set to low */
	dsi_write(m, DSI_PHY_TST_CTRL0, 0);
	dsi_write(m, DSI_PHY_TST_CTRL1, 0);
	/* b. Set testen to high
	 * d. Place 0x00 in testdin */
	dsi_write(m, DSI_PHY_TST_CTRL1, PHY_TESTEN | PHY_TESTDIN(0));
	/* c. Set testclk to high */
	dsi_write(m, DSI_PHY_TST_CTRL0, PHY_TESTCLK);
	/* e. Set testclk to low (with the falling edge on testclk,
	 *    the testdin signal content is latched internally) */
	dsi_write(m, DSI_PHY_TST_CTRL0, PHY_UNTESTCLK);
	/* f. Set testen to low
	 * g. Place the 8-bit word corresponding to
	 *    the testcode MSBs in testdin */
	dsi_write(m, DSI_PHY_TST_CTRL1,
		  PHY_UNTESTEN | PHY_TESTDIN(test_code >> 8));
	/* h. Set testclk to high */
	dsi_write(m, DSI_PHY_TST_CTRL0, PHY_TESTCLK);
	/* For writing the 8-bit testcode LSBs: */
	/* a. Set testclk to low */
	dsi_write(m, DSI_PHY_TST_CTRL0, PHY_UNTESTCLK);
	/* b. Set testen to high
	 * d. Place the 8-bit word test data in testdin */
	dsi_write(m, DSI_PHY_TST_CTRL1,
		  PHY_TESTEN | PHY_TESTDIN(test_code));
	/* c. Set testclk to high */
	dsi_write(m, DSI_PHY_TST_CTRL0, PHY_TESTCLK);
	/* e. Set testclk to low (with the falling edge on testclk,
	 * the testdin signal content is latched internally)*/
	dsi_write(m, DSI_PHY_TST_CTRL0, PHY_UNTESTCLK);
	/* f. Set testen to low */
	dsi_write(m, DSI_PHY_TST_CTRL1,
		  PHY_UNTESTEN);
}

static void __mga25_dsi_phy_write(struct mga25_dsi *m,
				  u16 test_code,
				  u8 test_data)
{

	mga25_dsi_phy_set_addr(m, test_code);
	/* f. Set testen to low
	 * For writing the data:
	 * a. Place the 8-bit word corresponding to
	 * the page offset in testdin*/
	dsi_write(m, DSI_PHY_TST_CTRL1,
		  PHY_UNTESTEN | PHY_TESTDIN(test_data));
	/* b. Set testclk to high (test data is programmed internally)*/
	dsi_write(m, DSI_PHY_TST_CTRL0, PHY_TESTCLK);
}

#define mga25_dsi_phy_write(__dsi, __offset, __val) do {			\
	unsigned __val2 = __val;					\
	unsigned __off = __offset;					\
	DRM_DEBUG_KMS("pW:%04x: %02x\n", __off, __val2);		\
	__mga25_dsi_phy_write(__dsi, __offset, __val);			\
} while (0)

#if 0
static u8 mga25_dsi_phy_read(struct mga25_dsi *m, u16 test_code)
{
	u32 v;
	mga25_dsi_phy_set_addr(m, test_code);
	v = dsi_read(m, DSI_PHY_TST_CTRL1);
	return (v >> PHY_TESTDOUT_SHIFT) & PHY_TESTDOUT_MASK;
}

static int mga25_dsi_rm_phy_read(void *context, unsigned reg,
				  unsigned *result)
{
	struct mga25_dsi *m = context;
	*result = mga25_dsi_phy_read(m, reg);
	return 0;
}

static int mga25_dsi_rm_phy_write(void *context, unsigned reg,
				  unsigned value)
{
	struct mga25_dsi *m = context;
	__mga25_dsi_phy_write(m, reg, value);
	return 0;
}

static struct regmap_config mga25_dsi_regmap_phy_config = {
	.name = "dsi-phy-regs",
	.reg_bits	= 16, /* Number of bits in a register address */
	.val_bits	=  8, /* Number of bits in a register value */
	.reg_stride	=  1, /* The register address stride. */
	.max_register	= 0xb5b,
	.fast_io = true,

	.reg_read = mga25_dsi_rm_phy_read,
	.reg_write = mga25_dsi_rm_phy_write,
};
#endif
struct mga25_dsi_phy_hsfreqrange {
	unsigned long max_mbps;/*Default Bit Rate (Mbps)*/
	unsigned char hsfreqrange;

};

static const struct mga25_dsi_phy_hsfreqrange mga25_dsi_phy_hsfreqrange[] = {
	{  85, 0x00 },
	{  95, 0x10 },
	{ 105, 0x20 },
	{ 115, 0x30 },
	{ 125, 0x01 },
	{ 135, 0x11 },
	{ 145, 0x21 },
	{ 155, 0x31 },
	{ 165, 0x02 },
	{ 175, 0x12 },
	{ 185, 0x22 },
	{ 195, 0x32 },
	{ 210, 0x03 },
	{ 230, 0x13 },
	{ 240, 0x23 },
	{ 260, 0x33 },
	{ 293, 0x04 },
	{ 313, 0x14 },
	{ 337, 0x25 },
	{ 375, 0x35 },
	{ 425, 0x05 },
	{ 475, 0x16 },
	{ 525, 0x26 },
	{ 575, 0x37 },
	{ 625, 0x07 },
	{ 675, 0x18 },
	{ 725, 0x28 },
	{ 775, 0x39 },
	{ 825, 0x09 },
	{ 875, 0x19 },
	{ 925, 0x29 },
	{ 975, 0x3a },
	{ 1025, 0x0a },
	{ 1075, 0x1a },
	{ 1125, 0x2a },
	{ 1175, 0x3b },
	{ 1225, 0x0b },
	{ 1275, 0x1b },
	{ 1325, 0x2b },
	{ 1375, 0x3c },
	{ 1425, 0x0c },
	{ 1475, 0x1c },
	{ 1525, 0x2c },
	{ 1575, 0x3d },
	{ 1625, 0x0d },
	{ 1675, 0x1d },
	{ 1725, 0x2e },
	{ 1775, 0x3e },
	{ 1825, 0x0e },
	{ 1875, 0x1e },
	{ 1925, 0x2f },
	{ 1975, 0x3f },
	{ 2025, 0x0f },
	{ 2075, 0x40 },
	{ 2125, 0x41 },
	{ 2175, 0x42 },
	{ 2225, 0x43 },
	{ 2275, 0x44 },
	{ 2325, 0x45 },
	{ 2375, 0x46 },
	{ 2425, 0x47 },
	{ 2475, 0x48 },
	{ 2501, 0x49 },
};
struct mga25_dsi_phy_params {
	unsigned vco_freq; /* Output frequency,[MHz]*/
	unsigned char vco_cntrl; /* vco_cntrl[5:0]*/
	unsigned char cpbias_cntrl; /* cpbias_cntrl[6:0]*/
	unsigned char gmp_cntrl; /* gmp_cntrl[1:0]*/
	unsigned char int_cntrl; /* int_cntrl[5:0]*/
	unsigned char prop_cntrl; /* prop_cntrl[5:0]*/
};

static const struct mga25_dsi_phy_params mga25_dsi_phy_params[] = {
	{   53, 0x3f, 0x10, 0, 1, 0xc, },
	{   80, 0x39, 0x10, 0, 1, 0xc, },
	{  105, 0x2f, 0x10, 0, 1, 0xc, },
	{  160, 0x29, 0x10, 0, 1, 0xc, },
	{  210, 0x1f, 0x10, 0, 1, 0xc, },
	{  320, 0x19, 0x10, 0, 1, 0xc, },
	{  420, 0x0f, 0x10, 0, 1, 0xc, },
	{  630, 0x05, 0x10, 0, 1, 0xc, },
	{ 1100, 0x03, 0x10, 0, 1, 0xc, },
	{ 1150, 0x01, 0x10, 0, 1, 0xc, },
	{ 1251, 0x01, 0x10, 0, 1, 0xc, },
};


static int mga25_dsi_pll_init(struct mga25_dsi *m)
{
	int i;
	u8 mm, n;
	const struct mga25_dsi_phy_params *p;

	if (WARN_ON(m->lane_mbps < 40 * 2 || m->lane_mbps > 1250 * 2))
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(mga25_dsi_phy_params); i++) {
		if (mga25_dsi_phy_params[i].vco_freq * 2 > m->lane_mbps)
			break;
	}
	if (i)
		i--;

	p = &mga25_dsi_phy_params[i];

	mga25_dsi_phy_write(m, 0x17b, (1 << 7) | (p->vco_cntrl << 1));
	mga25_dsi_phy_write(m, 0x15e, p->cpbias_cntrl);
	mga25_dsi_phy_write(m, 0x162, (p->int_cntrl << 2) | p->gmp_cntrl);
	mga25_dsi_phy_write(m, 0x16e, p->prop_cntrl);

	mm = m->feedback_div - 2;
	n = m->input_div - 1;
	mga25_dsi_phy_write(m, 0x179, mm);
	mga25_dsi_phy_write(m, 0x17a, mm >> 8);
	mga25_dsi_phy_write(m, 0x17b, (1 << 7) | (p->vco_cntrl << 1) | 1);
	mga25_dsi_phy_write(m, 0x178, (1 << 7) | (n << 3));

	return 0;
}

#define FCFG_CLK_MHZ 25
static int mga25_dsi_phy_init(void *priv_data)
{
	int i, ret;
	struct mga25_dsi *m = priv_data;
	u32 cfgclkfreqrange, hsfreqrange;
	u32 ctrl = rvidc(CTRL);
	/* Case 2 (slew rate calibration bypass)*/

	/* this is done dw_mipi_dsi_dphy_init():
	 * 1. Set rstz = 1'b0;
	 * 2. Set shutdownz= 1'b0;
	 * 3. Set testclr = 1'b1;
	 */
	/* 4. Wait for 15 ns; */
	udelay(1);
	/* 5. Set testclr to low; */
	dsi_write(m, DSI_PHY_TST_CTRL0, 0);

	/* 6. Set hsfreqrange[6:0]; */
	if (WARN_ON(m->lane_mbps < 40 * 2 || m->lane_mbps > 1250 * 2))
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(mga25_dsi_phy_hsfreqrange); i++) {
		if (mga25_dsi_phy_hsfreqrange[i].max_mbps > m->lane_mbps)
			break;
	}
	if (i)
		i--;
	hsfreqrange = mga25_dsi_phy_hsfreqrange[i].hsfreqrange;

	ctrl &= ~(MGA2_VID12_B_HSFREQRANGE_MASK |
			MGA2_VID12_B_CFGCLKFREQRANGE_MASK);
	ctrl |= hsfreqrange << MGA2_VID12_B_HSFREQRANGE_OFFSET;
	wvidc(ctrl, CTRL);

	/* 7. Set bit [2] of address 0x26B to 1 and
	 * bit [5:4] of address 0x272 to 2'b00 to bypass slew rate
	 * calibration; */
	mga25_dsi_phy_write(m, 0x26B, 1 << 2);
	mga25_dsi_phy_write(m, 0x272, 0);

	/* 8. Set cfgclkfreqrange[7:0] = round[ (Fcfg_clk(MHz)-17)*4]; */
	cfgclkfreqrange = (FCFG_CLK_MHZ - 17) * 4;
	ctrl |= cfgclkfreqrange << MGA2_VID12_B_CFGCLKFREQRANGE_OFFSET;
	wvidc(ctrl, CTRL);

	/* 9. Apply cfg_clk signal with the appropriate frequency; */

	/* 10. Configure PLL operating frequency through D-PHY test control
	 * registers or through PLL SoC shadow registers interface
	 * as described in section 'Initialization' on page 54 */
	if ((ret = mga25_dsi_pll_init(m)))
		return ret;
	/* this is done dw_mipi_dsi_dphy_init():
	 *11. Set basedir_0 = 1'b0;
	  12. Set all requests inputs to zero;
	13. Wait for 15 ns;
	14. Set enable_n and enableclk=1'b1;
	15. Wait 5ns;
	16. Set shutdownz=1'b1;
	17. Wait 5ns;
	18. Set rstz=1'b1;
	19. Wait until stopstatedata_n and stopstateclk outputs are
	asserted indicating PHY is driving LP11 in
	enabled datalanes and clocklane. */

	return 0;
}

static void mga25_dsi_phy_power_on(void *priv_data)
{
}

static void mga25_dsi_phy_power_off(void *priv_data)
{
}

static int mga25_dsi_get_lane_mbps(void *priv_data, const struct drm_display_mode *mode,
			  unsigned long mode_flags, u32 lanes, u32 format,
			  unsigned int *lane_mbps)
{
	int bpp, vco_cntrl_div = 1;
	struct mga25_dsi *m = priv_data;
	u32 clock, mclock = mode->clock;
	long err, ret;
	u32 pll_clock = 0;
	u32 ref_div = 0, fb_div = 0, frac_fb_div = 0, post_div = 0;
	struct mga25_pll pll = {
		.reference_freq = FCFG_CLK_MHZ * 1000,
		.min_feedback_div = 64, /*M*/
		.max_feedback_div = 625,
		.min_ref_div = max(DIV_ROUND_UP(FCFG_CLK_MHZ, 8), 1), /* N*/
		.max_ref_div = min(FCFG_CLK_MHZ / 2, 16),
		.pll_out_min = 320 * 1000, /*kHz*/
		.pll_out_max = 1250 * 1000,
		.flags = MGA2_PLL_USE_POST_DIV,
		.post_div = 1,
	};

	bpp = mipi_dsi_pixel_format_to_bpp(format);
	if (bpp < 0) {
		DRM_DEV_ERROR(m->dev,
			      "failed to get bpp for pixel format %d\n",
			      format);
		return bpp;
	}
	/* take 1 / 0.8, since mbps must big than bandwidth of RGB */
	clock = mclock * (bpp / lanes) * 10 / 8;
	/* The data rate is given by the double of the PLL output clock phases frequency:
	 *	 Data rate (Gbps) = PLL Fout (GHz) * 2 */
	clock /= 2;

	if (clock < 80 * 1000)
		return -1;
	if (clock <= 160 * 1000) /* post divider will be set in vco_cntrl */
		vco_cntrl_div = 4;
	else  if (clock <= 320 * 1000)
		vco_cntrl_div = 2;

	clock *= vco_cntrl_div;

	ret = mga25_pll_compute(&pll, clock, &pll_clock,
			    &fb_div, &frac_fb_div, &ref_div, &post_div);

	if (pll_clock) {
		m->lane_mbps = DIV_ROUND_UP(pll_clock * 2 / vco_cntrl_div,
							1000);
		*lane_mbps = m->lane_mbps;
		m->input_div = ref_div;
		m->feedback_div = fb_div;
	}
	err = abs((long)clock - (long)pll_clock);
	DRM_DEBUG_KMS("Calculated: clock: %d -> %d (%d bpp / %d lanes),\n"
			" pll clock: %d (mbps: %d) "
			"(err: %ld.%02ld%%);\n"
			"\tdividers - M: %d.%d N: %d, postdiv: %d\n",
			mclock, clock, bpp, lanes,
			pll_clock, m->lane_mbps,
			err * 100 / pll_clock,
			err * 10000 / pll_clock % 100,
			fb_div, frac_fb_div, ref_div, vco_cntrl_div);

	if (ret || !pll_clock) {
		DRM_DEV_ERROR(m->dev, "Can not find best_freq for DPHY\n");
		return -EINVAL;
	}

	return 0;
}

static const struct dw_mipi_dsi_phy_ops mga25_dsi_phy_ops = {
	.init = mga25_dsi_phy_init,
	.power_on = mga25_dsi_phy_power_on,
	.power_off = mga25_dsi_phy_power_off,
	.get_lane_mbps = mga25_dsi_get_lane_mbps,
};

static const struct dw_mipi_dsi_plat_data mga25_dsi_plat_data = {
	.max_data_lanes = 4,
	.phy_ops = &mga25_dsi_phy_ops,
};

static int mga25_dsi_bind(struct device *dev, struct device *master,
			    void *data)
{
	int ret, i;
	struct drm_device *drm = data;
	struct mga25_dsi *m = dev_get_drvdata(dev);
	struct drm_encoder *e = &m->base;

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
	drm_encoder_helper_add(e, &mga25_dsi_encoder_helper_funcs);
	drm_encoder_init(drm, e, &mga25_dsi_encoder_funcs,
			 DRM_MODE_ENCODER_TMDS, NULL);

	ret = dw_mipi_dsi_bind(m->dsi, e);
	if (ret) {
		DRM_DEV_ERROR(dev, "Failed to bind: %d\n", ret);
		goto err_enc;
	}

	return ret;
err_enc:
	drm_encoder_cleanup(e);
err:
	for (i = 0; i < ARRAY_SIZE(m->clk); i++)
		clk_put(m->clk[i]);
	return ret;
}

static void mga25_dsi_unbind(struct device *dev, struct device *master,
			       void *data)
{
	int i;
	struct mga25_dsi *m = dev_get_drvdata(dev);
	if (!m)
		return;
	dw_mipi_dsi_unbind(m->dsi);
	for (i = 0; i < ARRAY_SIZE(m->clk); i++)
		clk_put(m->clk[i]);
}

static const struct component_ops mga25_dsi_ops = {
	.bind	= mga25_dsi_bind,
	.unbind	= mga25_dsi_unbind,
};

static int mga25_dsi_resume(struct platform_device *pdev)
{
	struct mga25_dsi *m = dev_get_drvdata(&pdev->dev);
	mga25_dsi_init_hw(m);
	return 0;
}

static int mga25_dsi_probe(struct platform_device *pdev)
{
	int ret;
	struct device *dev = &pdev->dev;
	struct dw_mipi_dsi_plat_data *pdata;
	struct device *parent = dev->parent;
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	struct mga25_dsi *m = devm_kzalloc(dev, sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;

	pdata = &m->pdata;
	memcpy(pdata, &mga25_dsi_plat_data, sizeof(*pdata));

	m->dev_id = mga25_get_version(parent);
	m->dev = dev;

	m->regs = devm_ioremap_resource(dev, res);
	if (IS_ERR(m->regs))
		return PTR_ERR(m->regs);
#if 0
	m->rm_phy = regmap_init(NULL, NULL, m,
					 &mga25_dsi_regmap_phy_config);
	if (WARN_ON(IS_ERR(m->rm_phy))) {
		ret = PTR_ERR(m->rm_phy);
		goto err;
	}
#endif
	mga25_dsi_init_hw(m);

	pdata->regm = devm_regmap_init(dev, NULL, m, &mga25_dsi_regmap_config);
	if (WARN_ON(IS_ERR(pdata->regm))) {
		ret = PTR_ERR(pdata->regm);
		goto err;
	}

	pdata->priv_data = m;
	dev_set_drvdata(dev, m);

	m->dsi = dw_mipi_dsi_probe(pdev, pdata);
	if (IS_ERR(m->dsi)) {
		ret = PTR_ERR(m->dsi);
		m->dsi = NULL;
		DRM_ERROR("Failed to initialize mipi dsi host: %d\n", ret);
		goto err;
	}
	ret = component_add(&pdev->dev, &mga25_dsi_ops);
	if (WARN_ON(ret))
		goto err;

	return ret;
err:
	if (m->dsi)
		dw_mipi_dsi_remove(m->dsi);

	return ret;
}

static int mga25_dsi_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mga25_dsi *m = dev_get_drvdata(dev);
	component_del(&pdev->dev, &mga25_dsi_ops);
	dw_mipi_dsi_remove(m->dsi);
#if 0
	regmap_exit(m->rm_phy);
#endif
	return 0;
}

static const struct of_device_id mga25_dsi_dt_ids[] = {
	{ .compatible = "mcst,mga2x-dsi", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, mga25_dsi_dt_ids);

struct platform_driver mga25_dsi_driver = {
	.probe  = mga25_dsi_probe,
	.remove = mga25_dsi_remove,
	.resume = mga25_dsi_resume,
	.driver = {
		.name = "mga2-dsi",
		.of_match_table = mga25_dsi_dt_ids,
	},
};

