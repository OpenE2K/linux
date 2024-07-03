/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * DesignWare Cores Ethernet PCS controller (DWC_xpcs)
 * E2C3, E12C, E16C, R2000+
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mdio.h>
#include <linux/phy.h>
#include <linux/of_mdio.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/delay.h>
#include <asm/io.h>

#ifndef MODULE
#undef CONFIG_DEBUG_FS
#endif
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif

#include "eldwcxpcs.h"


#define DRV_VERSION		"1.6"
#define DRV_RELDATE		"2023-07-13"

#define PHY_WAIT_NUM		1000

/* port_addr[4:0] */
#define PCS_ADDR_DEF		1
#define PCS_ADDR_PROTO		2	/* e2k and sparc proto */

#ifndef __sparc__
/* e2k e12g phy */
#define PCS_DEV_ID_1G_2G5	0x7996CED0
#define PCS_DEV_ID_1G_2G5_10G	0x7996CED1
#else /* sparc */
/* sparc e16g phy */
#define PCS_DEV_ID_1G_2G5	0x7996CED2
#define PCS_DEV_ID_1G_2G5_10G	0x7996CED3
#endif

/* e2k ang sparc proto */
#define PCS_DEV_ID_PROTO_1G_2G5	0x7996CED4
#define PCS_DEV_ID_PROTO_10G	0x7996CED5

/* MPLL MODE - eldwcxpcs_get_mpll_mode */
#define MPLL_MODE_10G		0
#define MPLL_MODE_1G		1
#define MPLL_MODE_2G5		2
#define MPLL_MODE_1G_BIF	3
#define MPLL_MODES		(MPLL_MODE_1G_BIF + 1)

/* PCS MODE */
#define PCS_MODE_1G_1G		0	/* normal */
#define PCS_MODE_1GBIF_1GBIF	1	/* bifurcation */
#define PCS_MODE_2G5_1GBIF	2
#define PCS_MODE_1GBIF_2G5	3
#define PCS_MODE_2G5_2G5	4
#define PCS_MODE_10G_1GBIF	5	/* R2000+ and E16C */
#define PCS_MODE_10G_2G5	6	/* E16C only */
#define PCS_MODES		(PCS_MODE_10G_2G5 + 1)


#ifndef __sparc__
/*
 * E16C/E2C3
 * 0:    eth1g_double_pcs_regs_config_ver2.txt
 * 1..6: eth10g_eth1g_eth2dot5_pcs_regs_config_ver2.txt
 */
static const u16 mpll_a[PCS_MODES][4] = {
/* MPLLA  CTRL0,  CTRL1,  CTRL2,  CTRL3 */
	{0x0020, 0x0000, 0x0200, 0x003A}, /* 0: f0+f1 - PCS_MODE_1G_1G */
	{0x8000, 0x0000, 0x0200, 0x0000}, /* 1: dis   - PCS_MODE_1GBIF_1GBIF */
	{0x8000, 0x0000, 0x0200, 0x0000}, /* 2: dis   - PCS_MODE_2G5_1GBIF */
	{0x8000, 0x0000, 0x0200, 0x0000}, /* 3: dis   - PCS_MODE_1GBIF_2G5 */
	{0x8000, 0x0000, 0x0200, 0x0000}, /* 4: dis   - PCS_MODE_2G5_2G5 */
	{0x0021, 0x0000, 0x0600, 0x0004}, /* 5: f0    - PCS_MODE_10G_1GBIF */
	{0x0021, 0x0000, 0x0600, 0x0004}  /* 6: f0    - PCS_MODE_10G_2G5 */
};
static const u16 mpll_b[PCS_MODES][4] = {
/* MPLLB  CTRL0,  CTRL1,  CTRL2,  CTRL3 */
	{0x8000, 0x0000, 0x0200, 0x0000}, /* 0: dis   - PCS_MODE_1G_1G */
	{0x0028, 0x0000, 0x0200, 0x0007}, /* 1: f0+f1 - PCS_MODE_1GBIF_1GBIF */
	{0x0028, 0x0000, 0x0200, 0x0007}, /* 2: f0+f1 - PCS_MODE_2G5_1GBIF */
	{0x0028, 0x0000, 0x0200, 0x0007}, /* 3: f0+f1 - PCS_MODE_1GBIF_2G5 */
	{0x0028, 0x0000, 0x0200, 0x0007}, /* 4: f0+f1 - PCS_MODE_2G5_2G5 */
	{0x0028, 0x0000, 0x0200, 0x0007}, /* 5: f1    - PCS_MODE_10G_1GBIF */
	{0x0028, 0x0000, 0x0200, 0x0007}  /* 6: f1    - PCS_MODE_10G_2G5 */
};
#else /* sparc */
/*
 * R2000+
 * 0:    eth1g_s1_double_pcs_regs_config.txt
 * 1..4: eth1g_eth2dot5_s1_pcs_regs_config.txt
 * 5:    eth10g_eth1g_s1_pcs_regs_config.txt
 */
static const u16 mpll_a[PCS_MODES][4] = {
/* MPLLA  CTRL0,  CTRL1,  CTRL2,  CTRL3 */
	{0x0020, 0x0000, 0x0200, 0xA047}, /* 0: f0+f1 - PCS_MODE_1G_1G */
	{0x8000, 0x0000, 0x0200, 0x0000}, /* 1: dis   - PCS_MODE_1GBIF_1GBIF */
	{0x0028, 0x0000, 0x0200, 0xA047}, /* 2: f0    - PCS_MODE_2G5_1GBIF */
	{0x0028, 0x0000, 0x0200, 0xA047}, /* 3: f1    - PCS_MODE_1GBIF_2G5 */
	{0x0028, 0x0000, 0x0200, 0xA047}, /* 4: f0+f1 - PCS_MODE_2G5_2G5 */
	{0x0021, 0x0000, 0x0600, 0xA056}, /* 5: f0    - PCS_MODE_10G_1GBIF */
	{0x0021, 0x0000, 0x0600, 0xA056}  /* 6: unsupported */
};
static const u16 mpll_b[PCS_MODES][4] = {
/* MPLLB  CTRL0,  CTRL1,  CTRL2,  CTRL3 */
	{0x8000, 0x0000, 0x0200, 0x0000}, /* 0: dis   - PCS_MODE_1G_1G */
	{0x0030, 0x0000, 0x0200, 0xA057}, /* 1: f0+f1 - PCS_MODE_1GBIF_1GBIF */
	{0x0030, 0x0000, 0x0200, 0xA057}, /* 2: f1    - PCS_MODE_2G5_1GBIF */
	{0x0030, 0x0000, 0x0200, 0xA057}, /* 3: f0    - PCS_MODE_1GBIF_2G5 */
	{0x8000, 0x0000, 0x0200, 0x0000}, /* 4: dis   - PCS_MODE_2G5_2G5 */
	{0x0030, 0x0000, 0x0200, 0xA057}, /* 5: f1    - PCS_MODE_10G_1GBIF */
	{0x0030, 0x0000, 0x0200, 0xA057}  /* 6: unsupported */
};
#endif

struct reg_phy {
	u32 addr;
	u16 dat[MPLL_MODES]; /* {10G},{1G},{2G5},{1Gbif} */
};

static struct reg_phy regphy[] = {
	{SR_XS_PCS_CTRL2, {
		0x0000, /* 10G */
		0x0001, /* 1G    PCS_TYPE_SEL(1) */
		0x0001, /* 2G5   PCS_TYPE_SEL(1) */
		0x0001  /* 1Gbif PCS_TYPE_SEL(1) */
	} },
	{VR_XS_PCS_DIG_CTRL1, {
		0x2000, /* 10G   EN_VSMMD1 */
		0x2000, /* 1G    EN_VSMMD1 */
		0x2004, /* 2G5   EN_VSMMD1 | EN_2_5G_MODE */
		0x2000  /* 1Gbif EN_VSMMD1 */
	} }, /* w/o VR_RST */
#ifndef __sparc__
	/*
	 *         f0    f1
	 *   10G: MPLLA  ---
	 *    1G: MPLLA MPLLA
	 *   2G5: MPLLB MPLLB
	 * 1Gbif: MPLLB MPLLB
	 */
	{VR_XS_PMA_Gen5_12G_16G_MPLL_CMN_CTRL, {
		0x0001, /* 10G   MPLL_EN_0 */
		0x0001, /* 1G    MPLL_EN_0 */
		0x0011, /* 2G5   MPLL_EN_0 */
		0x0011  /* 1Gbif MPLLB_SEL_0 | MPLL_EN_0 */
	} },
	{VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL1, {
		0x1510, /* 10G   TX_CLK_RDY_0 | VBOOST_LVL (5) | VBOOST_EN_0 */
		0x1500, /* 1G    TX_CLK_RDY_0 | VBOOST_LVL (5) */
		0x1510, /* 2G5   TX_CLK_RDY_0 | VBOOST_LVL (5) | VBOOST_EN_0 */
		0x1500  /* 1Gbif TX_CLK_RDY_0 | VBOOST_LVL (5) */
	} },/* TODO: VBOOST_EN_0 for 1G SFP */
	{VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL2, {
		0x0300, /* 10G   TX0_WIDTH(3) */
		0x0100, /* 1G    TX0_WIDTH(1) */
		0x0100, /* 2G5   TX0_WIDTH(1) */
		0x0100  /* 1Gbif TX0_WIDTH(1) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_TX_BOOST_CTRL, {
		0x000F, /* 10G   TX0_IBOOST(F) */
		0x000F, /* 1G    TX0_IBOOST(F) */
		0x000F, /* 2G5   TX0_IBOOST(F) */
		0x000F  /* 1Gbif TX0_IBOOST(F) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_TX_RATE_CTRL, {
		0x0000, /* 10G */
		0x0003, /* 1G    TX0_RATE(3) */
		0x0002, /* 2G5   TX0_RATE(2) */
		0x0007  /* 1Gbif TX0_RATE(7) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL0, {
#ifndef TX_EQ_CTRL_VER2 /* TODO: module param */
		0x1C10, /* 10G   TX_EQ_MAIN(1C) | TX_EQ_PRE(10) */
#else
		0x1B08, /* 10G   TX_EQ_MAIN(1B) | TX_EQ_PRE(08) */
#endif
		0x2800, /* 1G    TX_EQ_MAIN(28) */ /* alt: 0x1400 */
		0x2000, /* 2G5   TX_EQ_MAIN(20) */
		0x2800  /* 1Gbif TX_EQ_MAIN(28) */ /* alt: 0x1400 */
	} },/* TODO: TX_EQ_MAIN(28) for 1G SFP */
	{VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL1, {
#ifndef TX_EQ_CTRL_VER2 /* TODO: module param */
		0x0060, /* 10G   TX_EQ_OVR_RIDE | TX_EQ_POST(20) */
#else
		0x006C, /* 10G   TX_EQ_OVR_RIDE | TX_EQ_POST(2C) */
#endif
		0x0040, /* 1G    TX_EQ_OVR_RIDE */
		0x0060, /* 2G5   TX_EQ_OVR_RIDE | TX_EQ_POST(20) */
		0x0040  /* 1Gbif TX_EQ_OVR_RIDE */
	} },
	{VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL2, {
		0x0300, /* 10G   RX0_WIDTH(3) */
		0x0100, /* 1G    RX0_WIDTH(1) */
		0x0100, /* 2G5   RX0_WIDTH(1) */
		0x0100  /* 1Gbif RX0_WIDTH(1) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL3, {
		0x0003, /* 10G   LOS_TRSHLD_0(3) */
		0x0003, /* 1G    LOS_TRSHLD_0(3) */
		0x0002, /* 2G5   LOS_TRSHLD_0(2) */
		0x0003  /* 1Gbif LOS_TRSHLD_0(3) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_RX_RATE_CTRL, {
		0x0000, /* 10G */
		0x0003, /* 1G    RX0_RATE(3) */
		0x0002, /* 2G5   RX0_RATE(2) */
		0x0003  /* 1Gbif RX0_RATE(3) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_RX_CDR_CTRL, {
		0x0101, /* 10G   VCO_LOW_FREQ_0 | CDR_TRACK_EN_0 */
		0x0101, /* 1G    VCO_LOW_FREQ_0 | CDR_TRACK_EN_0 */
		0x0101, /* 2G5   VCO_LOW_FREQ_0 | CDR_TRACK_EN_0 */
		0x0101  /* 1Gbif VCO_LOW_FREQ_0 | CDR_TRACK_EN_0 */
	} },
	{VR_XS_PMA_Gen5_12G_16G_RX_ATTN_CTRL, {
		0x0000, /* 10G */
		0x0000, /* 1G */
		0x0000, /* 2G5 */
		0x0000  /* 1Gbif */
	} },
	{VR_XS_PMA_Gen5_12G_RX_EQ_CTRL0, {
		0x77CA, /* 10G   VGA1_GAIN_0(7) | VGA2_GAIN_0(7) |
				 CTLE_POLE_0(6) | CTLE_BOOST_0(10) */
		0x77A6, /* 1G    VGA1_GAIN_0(7) | VGA2_GAIN_0(7) |
				 CTLE_POLE_0(5) | CTLE_BOOST_0(6) */
		0x77A6, /* 2G5   VGA1_GAIN_0(7) | VGA2_GAIN_0(7) |
				 CTLE_POLE_0(5) | CTLE_BOOST_0(6) */
		0x77A6  /* 1Gbif VGA1_GAIN_0(7) | VGA2_GAIN_0(7) |
				 CTLE_POLE_0(5) | CTLE_BOOST_0(6) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_RX_EQ_CTRL4, {
		0x0011, /* 10G   CONT_OFF_CAN_0 | CONT_ADAPT_0 */
		0x0010, /* 1G    CONT_OFF_CAN_0 */
		0x0010, /* 2G5   CONT_OFF_CAN_0 */
		0x0010  /* 1Gbif CONT_OFF_CAN_0 */
	} },
	{VR_XS_PMA_Gen5_12G_AFE_DFE_EN_CTRL, {
		0x0011, /* 10G   DFE_EN_0 | AFE_EN_0 */
		0x0000, /* 1G */
		0x0000, /* 2G5 */
		0x0000  /* 1Gbif */
	} },
	{VR_XS_PMA_Gen5_12G_16G_MISC_CTRL0, {
		0x5100, /* 10G   CR_PARA_SEL | RX_VREF_CTRL(11) */
		0x5100, /* 1G    CR_PARA_SEL | RX_VREF_CTRL(11) */
		0x5100, /* 2G5   CR_PARA_SEL | RX_VREF_CTRL(11) */
		0x5100  /* 1Gbif CR_PARA_SEL | RX_VREF_CTRL(11) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_REF_CLK_CTRL, {
		0x00F1, /* 10G   REF_MPLLB_DIV2 | REF_MPLLA_DIV2 |
				 REF_RANGE(6) | REF_CLK_EN */
		0x00F1, /* 1G    REF_MPLLB_DIV2 | REF_MPLLA_DIV2 |
				 REF_RANGE(6) | REF_CLK_EN */
		0x00F1, /* 2G5   REF_MPLLB_DIV2 | REF_MPLLA_DIV2 |
				 REF_RANGE(6) | REF_CLK_EN */
		0x00F1  /* 1Gbif REF_MPLLB_DIV2 | REF_MPLLA_DIV2 |
				 REF_RANGE(6) | REF_CLK_EN */
	} },
	{VR_XS_PMA_Gen5_12G_16G_VCO_CAL_LD0, {
		0x0549, /* 10G   VCO_LD_VAL_0(549) */
		0x0540, /* 1G    VCO_LD_VAL_0(540) */
		0x0550, /* 2G5   VCO_LD_VAL_0(550) */
		0x0540  /* 1Gbif VCO_LD_VAL_0(540) */
	} },
	{VR_XS_PMA_Gen5_12G_VCO_CAL_REF0, {
		0x0029, /* 10G   VCO_REF_LD_0(29) */
		0x002A, /* 1G    VCO_REF_LD_0(2A) */
		0x0022, /* 2G5   VCO_REF_LD_0(22) */
		0x002A  /* 1Gbif VCO_REF_LD_0(2A) */
	} },
#else /* __sparc__ */
	/*
	 *         f0    f1
	 *   10G: MPLLA  ---
	 *    1G: MPLLA MPLLA
	 *   2G5: MPLLA MPLLA
	 * 1Gbif: MPLLB MPLLB
	 */
	{VR_XS_PMA_Gen5_12G_16G_MPLL_CMN_CTRL, {
		0x0001, /* 10G   MPLL_EN_0 */
		0x0001, /* 1G    MPLL_EN_0 */
		0x0001, /* 2G5   MPLL_EN_0 */
		0x0011  /* 1Gbif MPLLB_SEL_0 | MPLL_EN_0 */
	} },
	{VR_XS_PMA_Gen5_12G_16G_RX_EQ_CTRL4, {
		0x0011, /* 10G   CONT_OFF_CAN_0 | CONT_ADAPT_0 */
		0x0010, /* 1G    CONT_OFF_CAN_0 */
		0x0010, /* 2G5   CONT_OFF_CAN_0 */
		0x0010  /* 1Gbif CONT_OFF_CAN_0 */
	} },
	{VR_XS_PMA_Gen5_12G_16G_TX_RATE_CTRL, {
		0x0000, /* 10G */
		0x0003, /* 1G    TX0_RATE(3) */
		0x0002, /* 2G5   TX0_RATE(2) */
		0x0006  /* 1Gbif TX0_RATE(6) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_RX_RATE_CTRL, {
		0x0000, /* 10G */
		0x0003, /* 1G    RX0_RATE(3) */
		0x0002, /* 2G5   RX0_RATE(2) */
		0x0003  /* 1Gbif RX0_RATE(3) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL2, {
		0x0300, /* 10G   TX0_WIDTH(3) */
		0x0100, /* 1G    TX0_WIDTH(1) */
		0x0100, /* 2G5   TX0_WIDTH(1) */
		0x0100  /* 1Gbif TX0_WIDTH(1) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL2, {
		0x0300, /* 10G   RX0_WIDTH(3) */
		0x0100, /* 1G    RX0_WIDTH(1) */
		0x0100, /* 2G5   RX0_WIDTH(1) */
		0x0100  /* 1Gbif RX0_WIDTH(1) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL0, {
#ifndef PMATXEQCTRLv2 /* TODO: module param */
		0x1C10, /* 10G   TX_EQ_MAIN(1C) | TX_EQ_PRE(10) */
#else
		0x1B08, /* 10G   TX_EQ_MAIN(1B) | TX_EQ_PRE(08) */
#endif
		0x2800, /* 1G    TX_EQ_MAIN(28) */
		0x2000, /* 2G5   TX_EQ_MAIN(20) */
		0x2800  /* 1Gbif TX_EQ_MAIN(28) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL1, {
#ifndef PMATXEQCTRLv2 /* TODO: module param */
		0x0060, /* 10G   TX_EQ_OVR_RIDE | TX_EQ_POST(20) */
#else
		0x006C, /* 10G   TX_EQ_OVR_RIDE | TX_EQ_POST(2C) */
#endif
		0x0040, /* 1G    TX_EQ_OVR_RIDE */
		0x0060, /* 2G5   TX_EQ_OVR_RIDE | TX_EQ_POST(20) */
		0x0040  /* 1Gbif TX_EQ_OVR_RIDE */
	} },
	{VR_XS_PMA_Gen5_12G_16G_REF_CLK_CTRL, {
		0x00F1, /* 10G   REF_MPLLB_DIV2 | REF_MPLLA_DIV2 |
				 REF_RANGE(6) | REF_CLK_EN */
		0x00F1, /* 1G    REF_MPLLB_DIV2 | REF_MPLLA_DIV2 |
				 REF_RANGE(6) | REF_CLK_EN */
		0x00F1, /* 2G5   REF_MPLLB_DIV2 | REF_MPLLA_DIV2 |
				 REF_RANGE(6) | REF_CLK_EN */
		0x00F1  /* 1Gbif REF_MPLLB_DIV2 | REF_MPLLA_DIV2 |
				 REF_RANGE(6) | REF_CLK_EN */
	} },
	{VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL1, {
		0x1510, /* 10G   TX_CLK_RDY_0 | VBOOST_LVL(5) | VBOOST_EN_0 */
		0x1510, /* 1G    TX_CLK_RDY_0 | VBOOST_LVL(5) | VBOOST_EN_0 */
		0x1510, /* 2G5   TX_CLK_RDY_0 | VBOOST_LVL(5) | VBOOST_EN_0 */
		0x1510  /* 1Gbif TX_CLK_RDY_0 | VBOOST_LVL(5) | VBOOST_EN_0 */
	} },
	{VR_XS_PMA_Gen5_12G_16G_MISC_CTRL0, {
		0x5100, /* 10G   CR_PARA_SEL | RX_VREF_CTRL(11) */
		0x5100, /* 1G    CR_PARA_SEL | RX_VREF_CTRL(11) */
		0x5100, /* 2G5   CR_PARA_SEL | RX_VREF_CTRL(11) */
		0x5100  /* 1Gbif CR_PARA_SEL | RX_VREF_CTRL(11) */
	} },
	{VR_XS_PMA_Gen5_16G_MISC_CTRL2, {
		0x0003, /* 10G   SUP_MISC(3) */
		0x0003, /* 1G    SUP_MISC(3) */
		0x0003, /* 2G5   SUP_MISC(3) */
		0x0003  /* 1Gbif SUP_MISC(3) */
	} },
	{VR_XS_PMA_Gen5_16G_VCO_CAL_REF0, {
		0x0029, /* 10G   VCO_REF_LD_0(29) */
		0x002A, /* 1G    VCO_REF_LD_0(2A) */
		0x0022, /* 2G5   VCO_REF_LD_0(22) */
		0x002A  /* 1Gbif VCO_REF_LD_0(2A) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_VCO_CAL_LD0, {
		0x0549, /* 10G   VCO_LD_VAL_0(549) */
		0x0540, /* 1G    VCO_LD_VAL_0(540) */
		0x0550, /* 2G5   VCO_LD_VAL_0(550) */
		0x0540  /* 1Gbif VCO_LD_VAL_0(540) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_TX_BOOST_CTRL, {
		0x000F, /* 10G   TX0_IBOOST(F) */
		0x000F, /* 1G    TX0_IBOOST(F) */
		0x000F, /* 2G5   TX0_IBOOST(F) */
		0x000F  /* 1Gbif TX0_IBOOST(F) */
	} },
	{VR_XS_PMA_Gen5_16G_RX_EQ_CTRL0, {
		0x5510, /* 10G   VGA1_GAIN_0(5) | VGA2_GAIN_0(5) |
				 CTLE_BOOST_0(10) */
		0x4406, /* 1G    VGA1_GAIN_0(4) | VGA2_GAIN_0(4) |
				 CTLE_BOOST_0(6) */
		0x4406, /* 2G5   VGA1_GAIN_0(4) | VGA2_GAIN_0(4) |
				 CTLE_BOOST_0(6) */
		0x4406  /* 1Gbif VGA1_GAIN_0(4) | VGA2_GAIN_0(4) |
				 CTLE_BOOST_0(6) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL3, {
		0x0007, /* 10G   LOS_TRSHLD_0(7) */
		0x0003, /* 1G    LOS_TRSHLD_0(3) */
		0x0003, /* 2G5   LOS_TRSHLD_0(3) */
		0x0003  /* 1Gbif LOS_TRSHLD_0(3) */
	} },
	{VR_XS_PMA_Gen5_12G_16G_RX_ATTN_CTRL, {
		0x0000, /* 10G */
		0x0000, /* 1G */
		0x0000, /* 2G5 */
		0x0000  /* 1Gbif */
	} },
	{VR_XS_PMA_Gen5_16G_RX_CDR_CTRL1, {
		0x0111, /* 10G   VCO_FRQBAND_0(1) | VCO_STEP_CTRL_0 |
				 VCO_TEMP_COMP_EN_0 */
		0x0111, /* 1G    VCO_FRQBAND_0(1) | VCO_STEP_CTRL_0 |
				 VCO_TEMP_COMP_EN_0 */
		0x0211, /* 2G5   VCO_FRQBAND_0(2) | VCO_STEP_CTRL_0 |
				 VCO_TEMP_COMP_EN_0 */
		0x0111  /* 1Gbif VCO_FRQBAND_0(1) | VCO_STEP_CTRL_0 |
				 VCO_TEMP_COMP_EN_0 */
	} },
	{VR_XS_PMA_Gen5_16G_RX_MISC_CTRL0, {
		0x0000, /* 10G */
		0x0006, /* 1G    RX0_MISC(6) */
		0x0007, /* 2G5   RX0_MISC(7) */
		0x0006  /* 1Gbif RX0_MISC(6) */
	} },
	{VR_XS_PMA_Gen5_16G_RX_GEN_CTRL4, {
		0x0000, /* 10G */
		0x0100, /* 1G    RX_DFE_BYP_0 */
		0x0100, /* 2G5   RX_DFE_BYP_0 */
		0x0100  /* 1Gbif RX_DFE_BYP_0 */
	} },
	{VR_XS_PMA_Gen5_16G_RX_IQ_CTRL0, {
		0x0000, /* 10G */
		0x0000, /* 1G */
		0x0000, /* 2G5 */
		0x0000  /* 1Gbif */
	} },
	{VR_XS_PMA_Gen5_16G_RX_EQ_CTRL5, {
		0x0030, /* 10G   RX0_ADPT_MODE(3) */
		0x0000, /* 1G */
		0x0000, /* 2G5 */
		0x0000  /* 1Gbif */
	} },
#endif /* sparc */
	{0xFFFFFFFF, { 0, 0, 0, 0 } }
};

static int pcs_mode[MAX_NUMNODES] = { 0 };
static int pcs_mode_argc = 0;
module_param_array(pcs_mode, int, &pcs_mode_argc, 0444);
MODULE_PARM_DESC(pcs_mode,
	"An array of PCS MPLL mode - "
	"0:1G+1G 1:1G+1Gbif 2:2G5+1G 3:1G+2G5 4:2G5+2G5 5:10G+1G 6:10G+2G5");


int eldwcxpcs_get_mpll_mode(struct pci_dev *pdev)
{
	int ret = -ENODEV;

	if (pdev) {
		int node = dev_to_node(&pdev->dev);

		if (node < 0)
			node = 0; /* nn */

		if (node >= MAX_NUMNODES) {
			dev_dbg(&pdev->dev,
				"eldwcxpcs: node = %d >= MAX_NUMNODES (%d)\n",
				node, MAX_NUMNODES);
			goto out;
		}

		if (pcs_mode[node] >= PCS_MODES)
			pcs_mode[node] = PCS_MODE_1G_1G; /* default */

		ret = MPLL_MODE_1G; /* default */
		if (PCI_FUNC(pdev->devfn) != 0) {
			switch (pcs_mode[node]) { /* ch1 */
			case PCS_MODE_1G_1G:
				ret = MPLL_MODE_1G;
				break;
			case PCS_MODE_1GBIF_1GBIF:
				ret = MPLL_MODE_1G_BIF;
				break;
			case PCS_MODE_2G5_1GBIF:
				ret = MPLL_MODE_1G_BIF;
				break;
			case PCS_MODE_1GBIF_2G5:
				ret = MPLL_MODE_2G5;
				break;
			case PCS_MODE_2G5_2G5:
				ret = MPLL_MODE_2G5;
				break;
			case PCS_MODE_10G_1GBIF:
				ret = MPLL_MODE_1G_BIF;
				break;
			case PCS_MODE_10G_2G5:
				ret = MPLL_MODE_2G5;
				break;
			}
		} else {
			switch (pcs_mode[node]) { /* ch0 */
			case PCS_MODE_1G_1G:
				ret = MPLL_MODE_1G;
				break;
			case PCS_MODE_1GBIF_1GBIF:
				ret = MPLL_MODE_1G_BIF;
				break;
			case PCS_MODE_2G5_1GBIF:
				ret = MPLL_MODE_2G5;
				break;
			case PCS_MODE_1GBIF_2G5:
				ret = MPLL_MODE_1G_BIF;
				break;
			case PCS_MODE_2G5_2G5:
				ret = MPLL_MODE_2G5;
				break;
			case PCS_MODE_10G_1GBIF:
				ret = MPLL_MODE_10G;
				break;
			case PCS_MODE_10G_2G5:
				ret = MPLL_MODE_10G;
				break;
			}
		}
		dev_dbg(&pdev->dev,
			 "eldwcxpcs: MPLL mode (%d) %s\n", ret,
			 (ret == MPLL_MODE_10G)    ? "10G" :
			 (ret == MPLL_MODE_1G)     ? "1G" :
			 (ret == MPLL_MODE_2G5)    ? "2.5G" :
			 (ret == MPLL_MODE_1G_BIF) ? "1Gbif" :
						     "unknown");
	}

out:
	return ret;
}
EXPORT_SYMBOL(eldwcxpcs_get_mpll_mode);

static inline bool my_is_eiohub_proto(struct pci_dev *pdev)
{
	if (is_iohub_asic(pdev))
		return false;
	else
		return true;
}

/** TITLE: mdio driver stuff */

enum eldwcxpcs_pcs_mode {
	DWCXPCS_MODE_SGMII_AN,		/* external phy */
	DWCXPCS_MODE_1000BASEX_AN,	/* SFP: 1G, 2G5, 10G */
};

struct eldwcxpcs_priv {
	struct mdio_device	*mdiodev;
	enum eldwcxpcs_pcs_mode	mode;
	u32			pcs_dev_id;
};

static int eldwcxpcs_probe(struct mdio_device *mdiodev)
{
	struct device *dev = &mdiodev->dev;
	struct device_node *np = dev->of_node;
	struct device_node *phy_node;
	struct eldwcxpcs_priv *priv;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	/* Handle mdio_device registered through devicetree */
	phy_node = of_parse_phandle(np, "phy-handle", 0);
	if (!phy_node) {
		dev_info(&mdiodev->dev, "use SFP: 1G, 2G5, 10G\n");
		priv->mode = DWCXPCS_MODE_1000BASEX_AN;
	} else {
		dev_info(&mdiodev->dev, "external phy node - %p\n", phy_node);
		priv->mode = DWCXPCS_MODE_SGMII_AN;
	}

	priv->mdiodev = mdiodev;

	dev_dbg(&mdiodev->dev, "DWC XPCS mdio device probed successful\n");

	return 0;
} /* eldwcxpcs_probe */


/** TITLE: DEBUG_FS stuff */

#ifdef CONFIG_DEBUG_FS
/* Usage: mount -t debugfs none /sys/kernel/debug */
/* for debug level: */
/* echo 8 > /proc/sys/kernel/printk */

/* /sys/kernel/debug/eldwcxpcs/ */
static struct dentry *eldwcxpcs_dbg_root = NULL;

#endif /* CONFIG_DEBUG_FS */


/** TITLE: PCI RAW read/write */

#define MGB_TOTAL_SIZE	0x40 /* Size of Regs Pool */

#define MGIO_CSR	0x10 /* MGIO   Control/Status Register */
#define MGIO_DATA	0x14 /* MGIO   Data Register */
/* MGIO_CSR Register Fields */
#define MG_CPLS		(1 << 31) /* R/W1C,CHANGED PCS LINK STATUS */
#define MG_PINT		(1 << 30) /* RO,   PCS Interrupt */
#define MG_PLST		(1 << 29) /* RO,   PCS Link Status */
#define MG_EMST		(1 << 28) /* RO,   2.5G Ethernet Mode Status */
#define MG_CTFL		(1 << 27) /* R/W1C,CHANGED TRANSMITTER FAULT */
#define MG_TFLT		(1 << 26) /* R,    TRANSMITTER FAULT */
#define MG_CRLS		(1 << 25) /* R/W1C,CHANGED RECEIVER LOSS */
#define MG_RLOS		(1 << 24) /* R,    RECIEVER LOSS */
#define MG_ECPL		(1 << 23) /* RW,   ENABLE ON CPLS */
#define MG_FEPL		(1 << 22) /* RW***,FAST ETHERNET POLARITY */
#define MG_GEPL		(1 << 21) /* RW***,GIGABIT ETHERNET POLARITY */
#define MG_LSTS1	(1 << 20) /* RW,   LINK STATUS SELECT 1 */
#define MG_SLST		(1 << 19) /* RW,   SOFT LINK STATUS */
#define MG_LSTS0	(1 << 18) /* RW,   LINK STATUS SELECT 0 */
#define MG_FDUP		(1 << 17) /* RW/R*,FULL DUPLEX */
#define MG_FETH		(1 << 16) /* RW/R*,FAST ETHERNET */
#define MG_GETH		(1 << 15) /* RW/R* GIGABIT ETHERNET */
#define MG_HARD		(1 << 14) /* RW,   HARD/SOFT */
#define MG_RRDY		(1 << 13) /* R/W1C,RESULT READY */
#define MG_CMAB		(1 << 12) /* R/W1C,CHANGED MODULE ABSENT */
#define MG_MABS		(1 << 11) /* R,    MODULE ABSENT */
#define MG_CLST		(1 << 10) /* R/W1C,CHANGED LINK STATUS */
#define MG_LSTA		(1 <<  9) /* R,    LINK STATUS */
#define MG_EFTC		(1 <<  8) /* RW,   ENABLE CTFL INTR */
#define MG_OUTS		(1 <<  7) /* RW,   DISABLE TRANSMIT / SAVE POWER */
#define MG_RSTP(p)	((p) << 6)/* RW    RESET POLARITY */
#define MG_ERDY		(1 <<  5) /* RW,   ENABLE RRDY INTR */
#define MG_ECRL		(1 <<  4) /* RW,   ENABLE CRLS INTR */
#define MG_ECST		(1 <<  3) /* RW,   ENABLE CLST INTR */
#define MG_SRST		(1 <<  2) /* RW,   SOFTWARE RESET */
#define MG_ECMB		(1 <<  1) /* RW,   ENABLE CMAB INTR */
#define MG_SINT		(1 <<  0) /* R,    Status Interrupt */
#define MG_W1C_MASK (MG_CLST | MG_CMAB | MG_RRDY | MG_CRLS | MG_CTFL | MG_CPLS)
/* MGIO_DATA registers shifts*/
#define MGIO_DATA_OFF		0
#define MGIO_CS_OFF		16
#define MGIO_REG_AD_OFF		18
#define MGIO_PHY_AD_OFF		23
#define MGIO_OP_CODE_OFF	28
#define MGIO_ST_OF_F_OFF	30

static inline int wait_rrdy(unsigned char *mgb_ioaddr)
{
	int i;

	for (i = 0; i < PHY_WAIT_NUM; i++) {
		if (readl(mgb_ioaddr + MGIO_CSR) & MG_RRDY)
			break;
		udelay(1);
	}

	return i == PHY_WAIT_NUM;
} /* wait_rrdy */

static int pcs_read_c45(struct pci_dev *pdev, unsigned char *mgb_ioaddr,
			int reg_num)
{
	u32 rd;
	int mii_id = my_is_eiohub_proto(pdev) ? PCS_ADDR_PROTO : PCS_ADDR_DEF;

	writel((readl(mgb_ioaddr + MGIO_CSR) & ~MG_W1C_MASK) | MG_RRDY,
	       mgb_ioaddr + MGIO_CSR);
	rd = (0x2UL << MGIO_CS_OFF) |
	     (reg_num & ((0x1fUL << MGIO_REG_AD_OFF) | 0xffff)) |
	     ((mii_id & 0x1f) << MGIO_PHY_AD_OFF);
	writel(rd, mgb_ioaddr + MGIO_DATA);
	if (wait_rrdy(mgb_ioaddr))
		goto bad_result;

	writel((readl(mgb_ioaddr + MGIO_CSR) & ~MG_W1C_MASK) | MG_RRDY,
	       mgb_ioaddr + MGIO_CSR);
	rd |= 0x3UL << MGIO_OP_CODE_OFF;
	writel(rd, mgb_ioaddr + MGIO_DATA);
	if (wait_rrdy(mgb_ioaddr))
		goto bad_result;

	rd = readl(mgb_ioaddr + MGIO_DATA) & 0xffff;

	return (int)rd;

bad_result:
	pr_err(KBUILD_MODNAME ": %s: Unable to read from MGIO_DATA reg 0x%x\n",
	       __func__, reg_num);

	return -1;
} /* pcs_read_c45 */

static void pcs_write_c45(struct pci_dev *pdev, unsigned char *mgb_ioaddr,
			  int reg_num, int val)
{
	u32 wr;
	int mii_id = my_is_eiohub_proto(pdev) ? PCS_ADDR_PROTO : PCS_ADDR_DEF;


	writel((readl(mgb_ioaddr + MGIO_CSR) & ~MG_W1C_MASK) | MG_RRDY,
	       mgb_ioaddr + MGIO_CSR);
	wr = (0x2 << MGIO_CS_OFF) |
	     (reg_num & ((0x1f << MGIO_REG_AD_OFF) | 0xffff)) |
	     ((mii_id & 0x1f) << MGIO_PHY_AD_OFF);
	writel(wr, mgb_ioaddr + MGIO_DATA);
	if (wait_rrdy(mgb_ioaddr))
		goto bad_result;

	wr &= ~0xffff;
	wr |= (0x2 << MGIO_CS_OFF) |
	      (0x1 << MGIO_OP_CODE_OFF) |
	      (val & 0xffff);
	writel((readl(mgb_ioaddr + MGIO_CSR) & ~MG_W1C_MASK) | MG_RRDY,
	       mgb_ioaddr + MGIO_CSR);
	writel(wr, mgb_ioaddr + MGIO_DATA);
	if (wait_rrdy(mgb_ioaddr))
		goto bad_result;

	return;

bad_result:
	pr_err(KBUILD_MODNAME ": %s: Unable to write MGIO_DATA reg 0x%x\n",
	       __func__, reg_num);

	return;
} /* pcs_write_c45 */

/* Initiate the Vendor specific software reset */
/* reset for both controllers are configured via func 0 */
static void pcs0_vs_reset(struct pci_dev *pdev, unsigned char *mgb_ioaddr)
{
	int i;
	u16 val;

	if (PCI_FUNC(pdev->devfn) != 0)
		return;

	val = pcs_read_c45(pdev, mgb_ioaddr, VR_XS_PCS_DIG_CTRL1);
	pcs_write_c45(pdev, mgb_ioaddr, VR_XS_PCS_DIG_CTRL1, val | VR_RST(1));
	val = pcs_read_c45(pdev, mgb_ioaddr, VR_XS_PCS_DIG_CTRL1);
	for (i = 0; i < PHY_WAIT_NUM; i++) {
		if ((pcs_read_c45(pdev, mgb_ioaddr,
				  VR_XS_PCS_DIG_CTRL1) & VR_RST(1)) == 0) {
			break;
		}
		udelay(1);
	}
	if (i >= PHY_WAIT_NUM) {
		pr_warn(KBUILD_MODNAME
			" %s: error on vendor specific reset "
			"(VR_XS_PCS_DIG_CTRL1.15)\n",
			dev_name(&pdev->dev));
	} else {
		pr_info(KBUILD_MODNAME
			" %s: vendor specific reset "
			"(VR_XS_PCS_DIG_CTRL1.15) - done\n",
			dev_name(&pdev->dev));
	}
} /* pcs0_vs_reset */

static int pcs0_wait1reset(struct pci_dev *pdev, unsigned char *mgb_ioaddr)
{
	int i;

	for (i = 0; i <= PHY_WAIT_NUM; i++) {
		if ((pcs_read_c45(pdev, mgb_ioaddr, SR_XS_PCS_CTRL1)
		    & SR_XS_RST(1)) == 0)
			break;
		udelay(1);
	}
	if (i >= PHY_WAIT_NUM) {
		pr_warn(KBUILD_MODNAME
			" %s: could't reset PCS0(SR_XS_PCS_CTRL1.15)\n",
			dev_name(&pdev->dev));
			return -1;
	}

	return 0;
} /* pcs0_wait1reset */

static void pcs_configure(struct pci_dev *pdev, unsigned char *mgb_ioaddr,
			 int mpll_mode)
{
	int i = 0;

	while (regphy[i].addr != 0xFFFFFFFF) {
		pcs_write_c45(pdev, mgb_ioaddr, regphy[i].addr,
			      regphy[i].dat[mpll_mode]);
		i += 1;
	}
} /* pcs_configure */

static void pcs_raw_init_rst(struct pci_dev *pdev, unsigned char *mgb_ioaddr,
			     int node)
{
	int r;
	u16 val;
	u32 pcs_dev_id;
	int pcsaddr;

	if (pcs_mode[node] >= PCS_MODES)
		pcs_mode[node] = PCS_MODE_1G_1G; /* default */

	if (PCI_FUNC(pdev->devfn) == 0) {
		pr_info(KBUILD_MODNAME
			" %s: configure PCS MPLL on node %d: %s\n",
			dev_name(&pdev->dev), node,
			(pcs_mode[node] == PCS_MODE_1G_1G) ? "1G+1G norm" :
			(pcs_mode[node] == PCS_MODE_1GBIF_1GBIF) ? "1G+1G bif" :
			(pcs_mode[node] == PCS_MODE_2G5_1GBIF) ? "2.5G+1G" :
			(pcs_mode[node] == PCS_MODE_1GBIF_2G5) ? "1G+2.5G" :
			(pcs_mode[node] == PCS_MODE_2G5_2G5) ? "2.5G+2.5G" :
			(pcs_mode[node] == PCS_MODE_10G_1GBIF) ? "10G+1G" :
			(pcs_mode[node] == PCS_MODE_10G_2G5) ? "10G+2.5G" :
								"unknown");
	}

	pr_debug(KBUILD_MODNAME
		 " %s: clean MGIO_CSR W1C bits and start soft reset\n",
		 dev_name(&pdev->dev));
	/* reset_mgio */
	/*raw_spin_lock_irqsave(&ep->mgio_lock, flags);*/
	r = readl(mgb_ioaddr + MGIO_CSR);
	r &= ~MG_W1C_MASK;
	r |= MG_SRST; /* RST */
	writel(r, mgb_ioaddr + MGIO_CSR); /* software reset */
	r &= ~MG_SRST; /* ~RST */
	mdelay(20); /* 10ms min */
	writel(r, mgb_ioaddr + MGIO_CSR);
	/*raw_spin_unlock_irqrestore(&ep->mgio_lock, flags);*/
	mdelay(100); /* wait for reset min 15ms@156 */

	if (PCI_FUNC(pdev->devfn) != 0)
		return;

	/* 1./2. Wait RST to 1'h0 */
	pcs0_wait1reset(pdev, mgb_ioaddr);

	/* 1. Initializing the DWC_xpcs Core */
	/* PCS Reset */
	val = pcs_read_c45(pdev, mgb_ioaddr, SR_XS_PCS_CTRL1);
	pcs_write_c45(pdev, mgb_ioaddr, SR_XS_PCS_CTRL1, val | SR_XS_RST(1));
	val = pcs_read_c45(pdev, mgb_ioaddr, SR_XS_PCS_CTRL1);
	/* Wait RST (SR_XS_PCS_CTRL1) to 1'h0 */
	if (pcs0_wait1reset(pdev, mgb_ioaddr) == 0) {
		pr_debug(KBUILD_MODNAME
			 " %s: reset PCS0(SR_XS_PCS_CTRL1.15) - done\n",
			 dev_name(&pdev->dev));
	}
	mdelay(1);

	pcsaddr = my_is_eiohub_proto(pdev) ? PCS_ADDR_PROTO : PCS_ADDR_DEF;

	pcs_dev_id = pcs_read_c45(pdev, mgb_ioaddr, SR_XS_PCS_DEV_ID1) << 16 |
		     pcs_read_c45(pdev, mgb_ioaddr, SR_XS_PCS_DEV_ID2);
	pr_info(KBUILD_MODNAME " %s: PCS0[%d] phy id: 0x%08x - %s\n",
		dev_name(&pdev->dev),
		pcsaddr, pcs_dev_id,
		(pcs_dev_id == PCS_DEV_ID_1G_2G5_10G) ? "1G/2.5G/10G" :
		(pcs_dev_id == PCS_DEV_ID_1G_2G5) ? "1G/2.5G" : "unknown");
} /* pcs_raw_init_rst */

static void pcs_raw_init_pll(struct pci_dev *pdev, unsigned char *mgb_ioaddr,
			     int node)
{
	int mpll_mode;

	if (PCI_FUNC(pdev->devfn) != 0)
		goto ch0andch1;

	/* 3. Configuration MPLL Registers */
	/* !!! mpll registers for both controllers are configured via PCS0 */
	pcs_write_c45(pdev, mgb_ioaddr, VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL0,
		      mpll_a[pcs_mode[node]][0]);
#ifndef __sparc__
	pcs_write_c45(pdev, mgb_ioaddr, VR_XS_PMA_Gen5_12G_MPLLA_CTRL1,
		      mpll_a[pcs_mode[node]][1]);
#else /* __sparc__ */
	pcs_write_c45(pdev, mgb_ioaddr, VR_XS_PMA_Gen5_16G_MPLLA_CTRL1,
		      mpll_a[pcs_mode[node]][1]);
#endif /* sparc */
	pcs_write_c45(pdev, mgb_ioaddr, VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL2,
		      mpll_a[pcs_mode[node]][2]);
	pcs_write_c45(pdev, mgb_ioaddr, VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL0,
		      mpll_b[pcs_mode[node]][0]);
#ifndef __sparc__
	pcs_write_c45(pdev, mgb_ioaddr, VR_XS_PMA_Gen5_12G_MPLLB_CTRL1,
		      mpll_b[pcs_mode[node]][1]);
#else /* __sparc__ */
	pcs_write_c45(pdev, mgb_ioaddr, VR_XS_PMA_Gen5_16G_MPLLB_CTRL1,
		      mpll_b[pcs_mode[node]][1]);
#endif /* sparc */
	pcs_write_c45(pdev, mgb_ioaddr, VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL2,
		      mpll_b[pcs_mode[node]][2]);
#ifndef __sparc__
	pcs_write_c45(pdev, mgb_ioaddr, VR_XS_PMA_Gen5_12G_MPLLA_CTRL3,
		      mpll_a[pcs_mode[node]][3]);
	pcs_write_c45(pdev, mgb_ioaddr, VR_XS_PMA_Gen5_12G_MPLLB_CTRL3,
		      mpll_b[pcs_mode[node]][3]);
#else /* __sparc__ */
	pcs_write_c45(pdev, mgb_ioaddr, VR_XS_PMA_Gen5_16G_MPLLA_CTRL3,
		      mpll_a[pcs_mode[node]][3]);
	pcs_write_c45(pdev, mgb_ioaddr, VR_XS_PMA_Gen5_16G_MPLLB_CTRL3,
		      mpll_b[pcs_mode[node]][3]);
#endif /* sparc */

	pr_debug(KBUILD_MODNAME " %s: PLLA CTRL: 0=%04X 1=%04X 2=%04X 3=%04X\n",
		 dev_name(&pdev->dev),
		 pcs_read_c45(pdev, mgb_ioaddr,
			      VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL0),
		 pcs_read_c45(pdev, mgb_ioaddr,
			      VR_XS_PMA_Gen5_12G_MPLLA_CTRL1),
		 pcs_read_c45(pdev, mgb_ioaddr,
			      VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL2),
		 pcs_read_c45(pdev, mgb_ioaddr,
			      VR_XS_PMA_Gen5_12G_MPLLA_CTRL3));
	pr_debug(KBUILD_MODNAME " %s: PLLB CTRL: 0=%04X 1=%04X 2=%04X 3=%04X\n",
		 dev_name(&pdev->dev),
		 pcs_read_c45(pdev, mgb_ioaddr,
			      VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL0),
		 pcs_read_c45(pdev, mgb_ioaddr,
			      VR_XS_PMA_Gen5_12G_MPLLB_CTRL1),
		 pcs_read_c45(pdev, mgb_ioaddr,
			      VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL2),
		 pcs_read_c45(pdev, mgb_ioaddr,
			      VR_XS_PMA_Gen5_12G_MPLLB_CTRL3));

	/* Disable Clause 73 Auto-Negotiation */
	/* RSTRT_AN to 1'h0 / LPM to 1'h0 / AN_EN to 1'h0
	 * EXT_NP_CTL to 1'h1 / AN_RST to 1'h0 */
	pcs_write_c45(pdev, mgb_ioaddr, SR_AN_CTRL, 0x2000);


ch0andch1:
	mpll_mode = eldwcxpcs_get_mpll_mode(pdev);
	if (mpll_mode < 0)
		mpll_mode = MPLL_MODE_1G; /* default */

	pcs_configure(pdev, mgb_ioaddr, mpll_mode);
} /* pcs_raw_init_pll */


/** TITLE: module stuff */

static int chk_cmdline(void)
{
	pr_debug(KBUILD_MODNAME ": nodes %d, PCS modes argc %d\n",
		 num_online_nodes(), pcs_mode_argc);

	if (!pcs_mode_argc) {
		pr_info(KBUILD_MODNAME
			": no PCS modes in cmdline, use default 1G+1G");
		return 0;
	}

	if (num_online_nodes() != pcs_mode_argc) {
		pr_err(KBUILD_MODNAME
		       ": nodes (%d) != PCS modes argc (%d) in cmdline\n",
			num_online_nodes(), pcs_mode_argc);
		return -1;
	}

	return 0;
} /* chk_cmdline */

static const struct of_device_id eldwcxpcs_of_match[] = {
	{ .compatible = "mcst,eldwcxpcs" },
	{},
};
MODULE_DEVICE_TABLE(of, eldwcxpcs_of_match);

static struct mdio_driver eldwcxpcs_driver = {
	.probe = eldwcxpcs_probe,
	.mdiodrv.driver = {
		.name = KBUILD_MODNAME,
		.of_match_table = eldwcxpcs_of_match,
	},
};

#define MAX_PCS (MAX_NUMNODES * 2)
struct mgb_pcs {
	struct pci_dev *pdev;
	resource_size_t res0;
	unsigned char *mgb_ioaddr;
	int node;
};

static int __init mdio_module_init(void)
{
	int ret;
	struct pci_dev *pdev = NULL;
	struct mgb_pcs pcs[MAX_PCS];
	int pnum = 0;
	int i;

	pr_info(KBUILD_MODNAME ": DWC XPCS Ethernet PHY driver v"
		DRV_VERSION " " DRV_RELDATE "\n");

	ret = chk_cmdline();
	if (ret)
		return -1;

#ifdef CONFIG_DEBUG_FS
	eldwcxpcs_dbg_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (eldwcxpcs_dbg_root == NULL)
		pr_warn(KBUILD_MODNAME ": Init of debugfs failed\n");
#endif /* CONFIG_DEBUG_FS */

	/* get mgb pci resource */
	while ((pdev = pci_get_device(PCI_VENDOR_ID_MCST_TMP,
				     PCI_DEVICE_ID_MCST_MGB, pdev))) {
		ret = pci_enable_device(pdev);
		if (ret < 0) {
			dev_err(&pdev->dev,
				"failed to enable device -- err=%d\n", ret);
			continue;
		}

		pcs[pnum].pdev = pdev;
		pcs[pnum].node = dev_to_node(&pdev->dev);
		if (pcs[pnum].node < 0) {
			pcs[pnum].node = 0; /* nn */
		}
		pcs[pnum].res0 = pci_resource_start(pdev, 0);
		request_mem_region(pcs[pnum].res0, MGB_TOTAL_SIZE,
				   KBUILD_MODNAME);
		pcs[pnum].mgb_ioaddr = ioremap(pcs[pnum].res0, MGB_TOTAL_SIZE);

		pnum += 1;
		if (pnum >= MAX_PCS)
			break;
	}

	for (i = 0; i < pnum; i++) {
		pcs_raw_init_rst(pcs[i].pdev, pcs[i].mgb_ioaddr, pcs[i].node);
	}
	for (i = 0; i < pnum; i++) {
		pcs_raw_init_pll(pcs[i].pdev, pcs[i].mgb_ioaddr, pcs[i].node);

		/* Vendor specific software reset 1! */
		pcs0_vs_reset(pcs[i].pdev, pcs[i].mgb_ioaddr);

		/* wait for MPLL started */
		if (PCI_FUNC(pcs[i].pdev->devfn) == 0) {
			u16 reg;

			mdelay(100); /* FIXME: read MPLL status */
			reg = (u16)pcs_read_c45(pcs[i].pdev, pcs[i].mgb_ioaddr,
					VR_XS_PMA_Gen5_12G_16G_MISC_STS);
			pr_info(KBUILD_MODNAME ": MPLL A%s B%s (0x%04X)",
				((reg >> 9) & 1) ? "+" : "-",
				((reg >> 10) & 1) ? "+" : "-",
				reg);
		}
	}

	for (i = 0; i < pnum; i++) {
		/* Vendor specific software reset 2! */
		pcs0_vs_reset(pcs[i].pdev, pcs[i].mgb_ioaddr);
	}

	/* release mgb pci resource */
	for (i = 0; i < pnum; i++) {
		iounmap(pcs[i].mgb_ioaddr);
		release_mem_region(pcs[i].res0, MGB_TOTAL_SIZE);
	}

	ret = mdio_driver_register(&eldwcxpcs_driver);
	if (ret != 0) {
		pr_err(KBUILD_MODNAME ": Could not register driver\n");
#ifdef CONFIG_DEBUG_FS
		if (eldwcxpcs_dbg_root)
			debugfs_remove_recursive(eldwcxpcs_dbg_root);
#endif /* CONFIG_DEBUG_FS */
	}

	return ret;
} /* mdio_module_init */

static void __exit mdio_module_exit(void)
{
	mdio_driver_unregister(&eldwcxpcs_driver);

#ifdef CONFIG_DEBUG_FS
	if (eldwcxpcs_dbg_root)
		debugfs_remove_recursive(eldwcxpcs_dbg_root);
#endif /* CONFIG_DEBUG_FS */
} /* mdio_module_exit */

module_init(mdio_module_init);
module_exit(mdio_module_exit);


MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("MCST DWC XPCS Ethernet PHY driver");
MODULE_VERSION(DRV_VERSION);
