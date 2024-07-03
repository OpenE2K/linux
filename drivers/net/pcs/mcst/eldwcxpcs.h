/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef ELDWCXPCS_H__
#define ELDWCXPCS_H__

/* SRC: DWC_xpcs_uvm_altRegister_1g10g.ralf */

/* Block: map_PMA_MMD */

#define SR_PMA_CTRL1	((map_PMA_MMD) + 0x0000)
#  define LB(d)	(((d) & 0x1) << 0)
#  define SS_5_2(d)	(((d) & 0xF) << 2)
#  define SS6(d)	(((d) & 0x1) << 6)
#  define LPM(d)	(((d) & 0x1) << 11)
#  define SR_PMA_SS13(d)	(((d) & 0x1) << 13)
#  define SR_PMA_RST(d)	(((d) & 0x1) << 15)

#define SR_PMA_STATUS1	((map_PMA_MMD) + 0x0001)
#  define LPMS(d)	(((d) & 0x1) << 1)
#  define RLU(d)	(((d) & 0x1) << 2)
#  define FLT(d)	(((d) & 0x1) << 7)

#define SR_PMA_DEV_ID_1	((map_PMA_MMD) + 0x0002)
#  define PMA_DEV_OUI_3_18(d)	(((d) & 0xFFFF) << 0)

#define SR_PMA_DEV_ID_2	((map_PMA_MMD) + 0x0003)
#  define PMA_DEV_RN_3_0(d)	(((d) & 0xF) << 0)
#  define PMA_DEV_MMN_5_0(d)	(((d) & 0x3F) << 4)
#  define PMA_DEV_OUI_19_24(d)	(((d) & 0x3F) << 10)

#define SR_PMA_SPD_ABL	((map_PMA_MMD) + 0x0004)
#  define XGC(d)	(((d) & 0x1) << 0)
#  define GC(d)	(((d) & 0x1) << 4)

#define SR_PMA_DEV_PKG1	((map_PMA_MMD) + 0x0005)
#  define CLS22(d)	(((d) & 0x1) << 0)
#  define PMA_PMD(d)	(((d) & 0x1) << 1)
#  define WIS(d)	(((d) & 0x1) << 2)
#  define PCS(d)	(((d) & 0x1) << 3)
#  define PHYXS(d)	(((d) & 0x1) << 4)
#  define DTEXS(d)	(((d) & 0x1) << 5)
#  define TC(d)	(((d) & 0x1) << 6)
#  define AN(d)	(((d) & 0x1) << 7)

#define SR_PMA_DEV_PKG2	((map_PMA_MMD) + 0x0006)
#  define VSD1(d)	(((d) & 0x1) << 14)
#  define VSD2(d)	(((d) & 0x1) << 15)

#define SR_PMA_CTRL2	((map_PMA_MMD) + 0x0007)
#  define PMA_TYPE(d)	(((d) & 0x3F) << 0)

#define SR_PMA_STATUS2	((map_PMA_MMD) + 0x0008)
#  define PMA_LOOP(d)	(((d) & 0x1) << 0)
#  define XGEWEN(d)	(((d) & 0x1) << 1)
#  define XGLWEN(d)	(((d) & 0x1) << 2)
#  define XGSWEN(d)	(((d) & 0x1) << 3)
#  define LX4_ABL(d)	(((d) & 0x1) << 4)
#  define ER_ABL(d)	(((d) & 0x1) << 5)
#  define LR_ABL(d)	(((d) & 0x1) << 6)
#  define SR_ABL(d)	(((d) & 0x1) << 7)
#  define TD_ABL(d)	(((d) & 0x1) << 8)
#  define EXT_ABL(d)	(((d) & 0x1) << 9)
#  define SR_PMA_RF(d)	(((d) & 0x1) << 10)
#  define TF(d)	(((d) & 0x1) << 11)
#  define PRFA(d)	(((d) & 0x1) << 12)
#  define PTFA(d)	(((d) & 0x1) << 13)
#  define DP(d)	(((d) & 0x3) << 14)

#define SR_PMA_TX_DIS	((map_PMA_MMD) + 0x0009)
#  define GTD(d)	(((d) & 0x1) << 0)
#  define PMA_TX_DIS_0(d)	(((d) & 0x1) << 1)
#  define PMA_TX_DIS_3_1(d)	(((d) & 0x7) << 2)

#define SR_PMA_RX_SIG_DET	((map_PMA_MMD) + 0x000A)
#  define RX_DET(d)	(((d) & 0x1) << 0)
#  define PMA_RX_DET_0(d)	(((d) & 0x1) << 1)
#  define PMA_RX_DET_3_1(d)	(((d) & 0x7) << 2)

#define SR_PMA_EXT_ABL	((map_PMA_MMD) + 0x000B)
#  define XGBCX4_ABL(d)	(((d) & 0x1) << 0)
#  define XGBLRM_ABL(d)	(((d) & 0x1) << 1)
#  define XGBT_ABL(d)	(((d) & 0x1) << 2)
#  define XGKX4_ABL(d)	(((d) & 0x1) << 3)
#  define XGBKR_ABL(d)	(((d) & 0x1) << 4)
#  define GBT_ABL(d)	(((d) & 0x1) << 5)
#  define R_100BKX_ABL(d)	(((d) & 0x1) << 6)
#  define R_100BT_ABL(d)	(((d) & 0x1) << 7)
#  define R_10BT_ABL(d)	(((d) & 0x1) << 8)

#define SR_PMA_PKG1	((map_PMA_MMD) + 0x000E)
#  define PMA_PKG_OUI_3_18(d)	(((d) & 0xFFFF) << 0)

#define SR_PMA_PKG2	((map_PMA_MMD) + 0x000F)
#  define PMA_PKG_RN_3_0(d)	(((d) & 0xF) << 0)
#  define PMA_PKG_MMN_5_0(d)	(((d) & 0x3F) << 4)
#  define PMA_PKG_OUI_19_24(d)	(((d) & 0x3F) << 10)

#define SR_PMA_2PT5G_5G_EXT_ABL	((map_PMA_MMD) + 0x0015)
#  define ABL_2PT5GT(d)	(((d) & 0x1) << 0)
#  define ABL_5GT(d)	(((d) & 0x1) << 1)
#  define ABL_2PT5GKX(d)	(((d) & 0x1) << 2)
#  define ABL_5GKR(d)	(((d) & 0x1) << 3)

#define SR_PMA_KR_PMD_CTRL	((map_PMA_MMD) + 0x0096)
#  define RS_TR(d)	(((d) & 0x1) << 0)
#  define TR_EN(d)	(((d) & 0x1) << 1)
#  define Reserve_15_2(d)	(((d) & 0x3FFF) << 2)

#define SR_PMA_KR_PMD_STS	((map_PMA_MMD) + 0x0097)
#  define RCV_STS(d)	(((d) & 0x1) << 0)
#  define FRM_LCK(d)	(((d) & 0x1) << 1)
#  define SU_PR_DTD(d)	(((d) & 0x1) << 2)
#  define TR_FAIL(d)	(((d) & 0x1) << 3)

#define SR_PMA_KR_LP_CEU	((map_PMA_MMD) + 0x0098)
#  define LP_CFF_UPDTM1(d)	(((d) & 0x3) << 0)
#  define LP_CFF_UPDT0(d)	(((d) & 0x3) << 2)
#  define LP_CFF_UPDT1(d)	(((d) & 0x3) << 4)
#  define LP_INIT(d)	(((d) & 0x1) << 12)
#  define LP_PRST(d)	(((d) & 0x1) << 13)

#define SR_PMA_KR_LP_CESTS	((map_PMA_MMD) + 0x0099)
#  define LP_CFF_STSM0(d)	(((d) & 0x3) << 0)
#  define LP_CFF_STS0(d)	(((d) & 0x3) << 2)
#  define LP_CFF_STS1(d)	(((d) & 0x3) << 4)
#  define LP_RR(d)	(((d) & 0x1) << 15)

#define SR_PMA_KR_LD_CEU	((map_PMA_MMD) + 0x009A)
#  define CFF_UPDTM1(d)	(((d) & 0x3) << 0)
#  define CFF_UPDT0(d)	(((d) & 0x3) << 2)
#  define CFF_UPDT1(d)	(((d) & 0x3) << 4)
#  define SR_PMA_INIT(d)	(((d) & 0x1) << 12)
#  define LD_PRST(d)	(((d) & 0x1) << 13)

#define SR_PMA_KR_LD_CESTS	((map_PMA_MMD) + 0x009B)
#  define CFF_STSM0(d)	(((d) & 0x3) << 0)
#  define CFF_STS0(d)	(((d) & 0x3) << 2)
#  define CFF_STS1(d)	(((d) & 0x3) << 4)
#  define RR(d)	(((d) & 0x1) << 15)

#define SR_PMA_KX_CTRL	((map_PMA_MMD) + 0x00A0)
#  define TOC(d)	(((d) & 0x1) << 0)

#define SR_PMA_KX_STS	((map_PMA_MMD) + 0x00A1)
#  define SD(d)	(((d) & 0x1) << 0)
#  define PMA_TDA(d)	(((d) & 0x1) << 8)
#  define RX_F(d)	(((d) & 0x1) << 10)
#  define TX_F(d)	(((d) & 0x1) << 11)
#  define RFA(d)	(((d) & 0x1) << 12)
#  define TFA(d)	(((d) & 0x1) << 13)

#define SR_PMA_TIME_SYNC_PMA_ABL	((map_PMA_MMD) + 0x0708)
#  define PMA_RX_DLY_ABL(d)	(((d) & 0x1) << 0)
#  define PMA_TX_DLY_ABL(d)	(((d) & 0x1) << 1)

#define SR_PMA_TIME_SYNC_TX_MAX_DLY_LWR	((map_PMA_MMD) + 0x0709)
#  define PMA_TX_MAX_DLY_LWR(d)	(((d) & 0xFFFF) << 0)

#define SR_PMA_TIME_SYNC_TX_MAX_DLY_UPR	((map_PMA_MMD) + 0x070A)
#  define PMA_TX_MAX_DLY_UPR(d)	(((d) & 0xFFFF) << 0)

#define SR_PMA_TIME_SYNC_TX_MIN_DLY_LWR	((map_PMA_MMD) + 0x070B)
#  define PMA_TX_MIN_DLY_LWR(d)	(((d) & 0xFFFF) << 0)

#define SR_PMA_TIME_SYNC_TX_MIN_DLY_UPR	((map_PMA_MMD) + 0x070C)
#  define PMA_TX_MIN_DLY_UPR(d)	(((d) & 0xFFFF) << 0)

#define SR_PMA_TIME_SYNC_RX_MAX_DLY_LWR	((map_PMA_MMD) + 0x070D)
#  define PMA_RX_MAX_DLY_LWR(d)	(((d) & 0xFFFF) << 0)

#define SR_PMA_TIME_SYNC_RX_MAX_DLY_UPR	((map_PMA_MMD) + 0x070E)
#  define PMA_RX_MAX_DLY_UPR(d)	(((d) & 0xFFFF) << 0)

#define SR_PMA_TIME_SYNC_RX_MIN_DLY_LWR	((map_PMA_MMD) + 0x070F)
#  define PMA_RX_MIN_DLY_LWR(d)	(((d) & 0xFFFF) << 0)

#define SR_PMA_TIME_SYNC_RX_MIN_DLY_UPR	((map_PMA_MMD) + 0x0710)
#  define PMA_RX_MIN_DLY_UPR(d)	(((d) & 0xFFFF) << 0)

#define VR_PMA_DIG_CTRL1	((map_PMA_MMD) + 0x8000)
#  define BYP_PWRUP(d)	(((d) & 0x1) << 1)
#  define DTXLANED_0(d)	(((d) & 0x1) << 4)
#  define DTXLANED_3_1(d)	(((d) & 0x7) << 5)
#  define PWRSV(d)	(((d) & 0x1) << 11)
#  define VR_RST(d)	(((d) & 0x1) << 15)

#define VR_PMA_KRTR_PRBS_CTRL0	((map_PMA_MMD) + 0x8003)
#  define PRBS_MODE_EN(d)	(((d) & 0x1) << 0)
#  define PRBS31_EN(d)	(((d) & 0x1) << 1)

#define VR_PMA_KRTR_PRBS_CTRL1	((map_PMA_MMD) + 0x8004)
#  define PRBS_TIM_LMT(d)	(((d) & 0xFFFF) << 0)

#define VR_PMA_KRTR_PRBS_CTRL2	((map_PMA_MMD) + 0x8005)
#  define PRBS_ERR_LMT(d)	(((d) & 0xFFFF) << 0)

#define VR_PMA_KRTR_TIMER_CTRL0	((map_PMA_MMD) + 0x8006)
#  define MAX_WAIT_TIME(d)	(((d) & 0xFFFF) << 0)

#define VR_PMA_KRTR_TIMER_CTRL1	((map_PMA_MMD) + 0x8007)
#  define WAIT_TIME(d)	(((d) & 0xFFFF) << 0)

#define VR_PMA_KRTR_TIMER_CTRL2	((map_PMA_MMD) + 0x8008)
#  define RX_TRAIN_TIME(d)	(((d) & 0xFFFF) << 0)

#define VR_PMA_KRTR_RX_EQ_CTRL	((map_PMA_MMD) + 0x8009)
#  define CFF_UPDTM1(d)	(((d) & 0x3) << 0)
#  define CFF_UPDT0(d)	(((d) & 0x3) << 2)
#  define CFF_UPDT1(d)	(((d) & 0x3) << 4)
#  define VR_PMA_INIT(d)	(((d) & 0x1) << 6)
#  define RX_PRST(d)	(((d) & 0x1) << 7)
#  define RR_RDY(d)	(((d) & 0x1) << 8)
#  define RX_EQ_MM(d)	(((d) & 0x1) << 15)

#define VR_PMA_KRTR_TX_EQ_STS_CTRL	((map_PMA_MMD) + 0x800B)
#  define CFF_STSM1(d)	(((d) & 0x3) << 0)
#  define CFF_STS0(d)	(((d) & 0x3) << 2)
#  define CFF_STS1(d)	(((d) & 0x3) << 4)
#  define TX_EQ_MM(d)	(((d) & 0x1) << 15)

#define VR_PMA_KRTR_TX_EQ_CFF_CTRL	((map_PMA_MMD) + 0x800C)
#  define CFF_UPDTM1(d)	(((d) & 0x3) << 0)
#  define CFF_UPDT0(d)	(((d) & 0x3) << 2)
#  define CFF_UPDT1(d)	(((d) & 0x3) << 4)
#  define CFF_INIT(d)	(((d) & 0x1) << 12)
#  define CFF_PRST(d)	(((d) & 0x1) << 13)

#define VR_PMA_PHY_TX_EQ_STS	((map_PMA_MMD) + 0x800D)
#  define EQ_STSM1(d)	(((d) & 0x3) << 0)
#  define EQ_STS0(d)	(((d) & 0x3) << 2)
#  define EQ_STS1(d)	(((d) & 0x3) << 4)
#  define STSM1_VLD(d)	(((d) & 0x1) << 8)
#  define STS0_VLD(d)	(((d) & 0x1) << 9)
#  define STS1_VLD(d)	(((d) & 0x1) << 10)

#define VR_PMA_PHY_RX_EQ_CEU	((map_PMA_MMD) + 0x800E)
#  define CFF_UPDTM1(d)	(((d) & 0x3) << 0)
#  define CFF_UPDT0(d)	(((d) & 0x3) << 2)
#  define CFF_UPDT1(d)	(((d) & 0x3) << 4)
#  define CFF_UPDTM1_VLD(d)	(((d) & 0x1) << 8)
#  define CFF_UPDT0_VLD(d)	(((d) & 0x1) << 9)
#  define CFF_UPDT1_VLD(d)	(((d) & 0x1) << 10)

#define VR_PMA_DIG_STS	((map_PMA_MMD) + 0x8010)
#  define LB_ACTIVE(d)	(((d) & 0x1) << 1)
#  define PSEQ_STATE(d)	(((d) & 0x7) << 2)


/* Block: map_XS_PMA_MMD */

#define VR_XS_PMA_RX_LSTS	((map_XS_PMA_MMD) + 0x0000)
#  define SIG_DET_0(d)	(((d) & 0x1) << 4)
#  define SIG_DET_3_1(d)	(((d) & 0x7) << 5)
#  define RX_PLL_STATE_0(d)	(((d) & 0x1) << 8)
#  define RX_PLL_STATE_3_1(d)	(((d) & 0x7) << 9)
#  define RX_VALID_0(d)	(((d) & 0x1) << 12)
#  define RX_VALID_3_1(d)	(((d) & 0x7) << 13)

#define VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL0	((map_XS_PMA_MMD) + 0x0010)
#  define TXBCN_EN_0(d)	(((d) & 0x1) << 0)
#  define TXBCN_EN_3_1(d)	(((d) & 0x7) << 1)
#  define TX_INV_0(d)	(((d) & 0x1) << 4)
#  define TX_INV_3_1(d)	(((d) & 0x7) << 5)
#  define TX_RST_0(d)	(((d) & 0x1) << 8)
#  define TX_RST_3_1(d)	(((d) & 0x7) << 9)
#  define TX_DT_EN_0(d)	(((d) & 0x1) << 12)
#  define TX_DT_EN_3_1(d)	(((d) & 0x7) << 13)

#define VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL1	((map_XS_PMA_MMD) + 0x0011)
#  define DET_RX_REQ_0(d)	(((d) & 0x1) << 0)
#  define DET_RX_REQ_3_1(d)	(((d) & 0x7) << 1)
#  define VBOOST_EN_0(d)	(((d) & 0x1) << 4)
#  define VBOOST_EN_3_1(d)	(((d) & 0x7) << 5)
#  define VBOOST_LVL(d)	(((d) & 0x7) << 8)
#  define TX_CLK_RDY_0(d)	(((d) & 0x1) << 12)
#  define TX_CLK_RDY_3_1(d)	(((d) & 0x7) << 13)

#define VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL2	((map_XS_PMA_MMD) + 0x0012)
#  define TX_REQ_0(d)	(((d) & 0x1) << 0)
#  define TX_REQ_3_1(d)	(((d) & 0x7) << 1)
#  define TX_LPD_0(d)	(((d) & 0x1) << 4)
#  define TX_LPD_3_1(d)	(((d) & 0x7) << 5)
#  define TX0_WIDTH(d)	(((d) & 0x3) << 8)
#  define TX1_WIDTH(d)	(((d) & 0x3) << 10)
#  define TX2_WIDTH(d)	(((d) & 0x3) << 12)
#  define TX3_WIDTH(d)	(((d) & 0x3) << 14)

#define VR_XS_PMA_Gen5_12G_16G_TX_BOOST_CTRL	((map_XS_PMA_MMD) + 0x0013)
#  define TX0_IBOOST(d)	(((d) & 0xF) << 0)
#  define TX1_IBOOST(d)	(((d) & 0xF) << 4)
#  define TX2_IBOOST(d)	(((d) & 0xF) << 8)
#  define TX3_IBOOST(d)	(((d) & 0xF) << 12)

#define VR_XS_PMA_Gen5_12G_16G_TX_RATE_CTRL	((map_XS_PMA_MMD) + 0x0014)
#  define TX0_RATE(d)	(((d) & 0x7) << 0)
#  define TX1_RATE(d)	(((d) & 0x7) << 4)
#  define TX2_RATE(d)	(((d) & 0x7) << 8)
#  define TX3_RATE(d)	(((d) & 0x7) << 12)

#define VR_XS_PMA_Gen5_12G_16G_TX_POWER_STATE_CTRL	((map_XS_PMA_MMD) + 0x0015)
#  define TX0_PSTATE(d)	(((d) & 0x3) << 0)
#  define TX1_PSTATE(d)	(((d) & 0x3) << 2)
#  define TX2_PSTATE(d)	(((d) & 0x3) << 4)
#  define TX3_PSTATE(d)	(((d) & 0x3) << 6)
#  define TX_DISABLE_0(d)	(((d) & 0x1) << 8)
#  define TX_DISABLE_3_1(d)	(((d) & 0x7) << 9)

#define VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL0	((map_XS_PMA_MMD) + 0x0016)
#  define TX_EQ_PRE(d)	(((d) & 0x3F) << 0)
#  define TX_EQ_MAIN(d)	(((d) & 0x3F) << 8)

#define VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL1	((map_XS_PMA_MMD) + 0x0017)
#  define TX_EQ_POST(d)	(((d) & 0x3F) << 0)
#  define TX_EQ_OVR_RIDE(d)	(((d) & 0x1) << 6)
#  define TX_EQ_DEF_CTRL(d)	(((d) & 0x1) << 7)
#  define CA_TX_EQ(d)	(((d) & 0x1) << 8)

#define VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL2	((map_XS_PMA_MMD) + 0x0018)
#  define PRE_MAX_LMT(d)	(((d) & 0xF) << 0)
#  define POST_MAX_LMT(d)	(((d) & 0xF) << 4)
#  define LMAIN_MIN_LMT(d)	(((d) & 0x3F) << 8)

#define VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL3	((map_XS_PMA_MMD) + 0x0019)
#  define NATTEN_MAX_LMT(d)	(((d) & 0x3F) << 0)
#  define MISC_LMT(d)	(((d) & 0x3F) << 8)

#define VR_XS_PMA_Gen5_12G_16G_EQ_INIT_CTRL0	((map_XS_PMA_MMD) + 0x001A)
#  define PRE_INIT(d)	(((d) & 0x3F) << 0)
#  define LMAIN_INIT(d)	(((d) & 0xFF) << 8)

#define VR_XS_PMA_Gen5_12G_16G_EQ_INIT_CTRL1	((map_XS_PMA_MMD) + 0x001B)
#  define POST_INIT(d)	(((d) & 0x3F) << 0)

#define VR_XS_PMA_Gen5_12G_16G_TX_STS	((map_XS_PMA_MMD) + 0x0020)
#  define TX_ACK_0(d)	(((d) & 0x1) << 0)
#  define TX_ACK_3_1(d)	(((d) & 0x7) << 1)
#  define DETRX_RSLT_0(d)	(((d) & 0x1) << 4)
#  define DETRX_RSLT_3_1(d)	(((d) & 0x7) << 5)

#define VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL0	((map_XS_PMA_MMD) + 0x0030)
#  define RX_TERM_EN_0(d)	(((d) & 0x1) << 0)
#  define RX_TERM_EN_3_1(d)	(((d) & 0x7) << 1)
#  define RX_ALIGN_EN_0(d)	(((d) & 0x1) << 4)
#  define RX_ALIGN_EN_3_1(d)	(((d) & 0x7) << 5)
#  define RX_DT_EN_0(d)	(((d) & 0x1) << 8)
#  define RX_DT_EN_3_1(d)	(((d) & 0x7) << 9)
#  define RX_CLKSFT_0(d)	(((d) & 0x1) << 12)
#  define RX_CLKSFT_3_1(d)	(((d) & 0x7) << 13)

#define VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL1	((map_XS_PMA_MMD) + 0x0031)
#  define RX_INV_0(d)	(((d) & 0x1) << 0)
#  define RX_INV_3_1(d)	(((d) & 0x7) << 1)
#  define RX_RST_0(d)	(((d) & 0x1) << 4)
#  define RX_RST_3_1(d)	(((d) & 0x7) << 5)
#  define RX_TERM_ACDC_0(d)	(((d) & 0x1) << 8)
#  define RX_TERM_ACDC_3_1(d)	(((d) & 0x7) << 9)
#  define RX_DIV16P5_CLK_EN_0(d)	(((d) & 0x1) << 12)
#  define RX_DIV16P5_CLK_EN_3_1(d)	(((d) & 0x7) << 13)

#define VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL2	((map_XS_PMA_MMD) + 0x0032)
#  define RX_REQ_0(d)	(((d) & 0x1) << 0)
#  define RX_REQ_3_1(d)	(((d) & 0x7) << 1)
#  define RX_LPD_0(d)	(((d) & 0x1) << 4)
#  define RX_LPD_3_1(d)	(((d) & 0x7) << 5)
#  define RX0_WIDTH(d)	(((d) & 0x3) << 8)
#  define RX1_WIDTH(d)	(((d) & 0x3) << 10)
#  define RX2_WIDTH(d)	(((d) & 0x3) << 12)
#  define RX3_WIDTH(d)	(((d) & 0x3) << 14)

#define VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL3	((map_XS_PMA_MMD) + 0x0033)
#  define LOS_TRSHLD_0(d)	(((d) & 0x7) << 0)
#  define LOS_TRSHLD_1(d)	(((d) & 0x7) << 3)
#  define LOS_TRSHLD_2(d)	(((d) & 0x7) << 6)
#  define LOS_TRSHLD_3(d)	(((d) & 0x7) << 9)
#  define LOS_LFPS_EN_0(d)	(((d) & 0x1) << 12)
#  define LOS_LFPS_EN_3_1(d)	(((d) & 0x7) << 13)

#define VR_XS_PMA_Gen5_12G_16G_RX_RATE_CTRL	((map_XS_PMA_MMD) + 0x0034)
#  define RX0_RATE(d)	(((d) & 0x3) << 0)
#  define RX1_RATE(d)	(((d) & 0x3) << 4)
#  define RX2_RATE(d)	(((d) & 0x3) << 8)
#  define RX3_RATE(d)	(((d) & 0x3) << 12)

#define VR_XS_PMA_Gen5_12G_16G_RX_POWER_STATE_CTRL	((map_XS_PMA_MMD) + 0x0035)
#  define RX0_PSTATE(d)	(((d) & 0x3) << 0)
#  define RX1_PSTATE(d)	(((d) & 0x3) << 2)
#  define RX2_PSTATE(d)	(((d) & 0x3) << 4)
#  define RX3_PSTATE(d)	(((d) & 0x3) << 6)
#  define RX_DISABLE_0(d)	(((d) & 0x1) << 8)
#  define RX_DISABLE_3_1(d)	(((d) & 0x7) << 9)
#  define EEE_OVR_RIDE(d)	(((d) & 0x1) << 12)

#define VR_XS_PMA_Gen5_12G_16G_RX_CDR_CTRL	((map_XS_PMA_MMD) + 0x0036)
#  define CDR_TRACK_EN_0(d)	(((d) & 0x1) << 0)
#  define CDR_TRACK_EN_3_1(d)	(((d) & 0x7) << 1)
#  define CDR_SSC_EN_0(d)	(((d) & 0x1) << 4)
#  define CDR_SSC_EN_3_1(d)	(((d) & 0x7) << 5)
#  define VCO_LOW_FREQ_0(d)	(((d) & 0x1) << 8)
#  define VCO_LOW_FREQ_3_1(d)	(((d) & 0x7) << 9)

#define VR_XS_PMA_Gen5_12G_16G_RX_ATTN_CTRL	((map_XS_PMA_MMD) + 0x0037)
#  define RX0_EQ_ATT_LVL(d)	(((d) & 0x7) << 0)
#  define RX1_EQ_ATT_LVL(d)	(((d) & 0x7) << 4)
#  define RX2_EQ_ATT_LVL(d)	(((d) & 0x7) << 8)
#  define RX3_EQ_ATT_LVL(d)	(((d) & 0x7) << 12)

#define VR_XS_PMA_Gen5_16G_RX_EQ_CTRL0	((map_XS_PMA_MMD) + 0x0038)
#define VR_XS_PMA_Gen5_12G_RX_EQ_CTRL0	((map_XS_PMA_MMD) + 0x0038)
#  define CTLE_BOOST_0(d)	(((d) & 0x1F) << 0)
#  define CTLE_POLE_0(d)	(((d) & 0x7) << 5)
#  define VGA2_GAIN_0(d)	(((d) & 0xF) << 8)
#  define VGA1_GAIN_0(d)	(((d) & 0xF) << 12)

#define VR_XS_PMA_Gen5_12G_16G_RX_EQ_CTRL4	((map_XS_PMA_MMD) + 0x003C)
#  define CONT_ADAPT_0(d)	(((d) & 0x1) << 0)
#  define CONT_ADAPT_3_1(d)	(((d) & 0x7) << 1)
#  define CONT_OFF_CAN_0(d)	(((d) & 0x1) << 4)
#  define CONT_OFF_CAN_3_1(d)	(((d) & 0x7) << 5)
#  define SEQ_EQ_EN(d)	(((d) & 0x1) << 8)
#  define PING_PONG_EN(d)	(((d) & 0x1) << 9)
#  define SELF_MAIN_EN(d)	(((d) & 0x1) << 10)
#  define RX_EQ_STRT_CTRL(d)	(((d) & 0x1) << 11)
#  define RX_AD_REQ(d)	(((d) & 0x1) << 12)

#define VR_XS_PMA_Gen5_12G_AFE_DFE_EN_CTRL	((map_XS_PMA_MMD) + 0x003D)
#  define AFE_EN_0(d)	(((d) & 0x1) << 0)
#  define AFE_EN_3_1(d)	(((d) & 0x7) << 1)
#  define DFE_EN_0(d)	(((d) & 0x1) << 4)
#  define DFE_EN_3_1(d)	(((d) & 0x7) << 5)

#define VR_XS_PMA_Gen5_16G_RX_EQ_CTRL5	((map_XS_PMA_MMD) + 0x003D)

#define VR_XS_PMA_Gen5_12G_16G_DFE_TAP_CTRL0	((map_XS_PMA_MMD) + 0x003E)
#  define DFE_TAP1_0(d)	(((d) & 0xFF) << 0)
#  define DFE_TAP1_1(d)	(((d) & 0xFF) << 8)

#define VR_XS_PMA_Gen5_12G_16G_RX_STS	((map_XS_PMA_MMD) + 0x0040)
#  define RX_ACK_0(d)	(((d) & 0x1) << 0)
#  define RX_ACK_3_1(d)	(((d) & 0x7) << 1)

#define VR_XS_PMA_Gen5_16G_RX_CDR_CTRL1	((map_XS_PMA_MMD) + 0x0044)

#define VR_XS_PMA_Gen5_16G_RX_GEN_CTRL4	((map_XS_PMA_MMD) + 0x0048)

#define VR_XS_PMA_Gen5_16G_RX_MISC_CTRL0	((map_XS_PMA_MMD) + 0x0049)

#define VR_XS_PMA_Gen5_16G_RX_IQ_CTRL0	((map_XS_PMA_MMD) + 0x004B)

#define VR_XS_PMA_Gen5_12G_16G_MPLL_CMN_CTRL	((map_XS_PMA_MMD) + 0x0050)
#  define MPLL_EN_0(d)	(((d) & 0x1) << 0)
#  define MPLL_EN_3_1(d)	(((d) & 0x7) << 1)
#  define MPLLB_SEL_0(d)	(((d) & 0x1) << 4)
#  define MPLLB_SEL_3_1(d)	(((d) & 0x7) << 5)

#define VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL0	((map_XS_PMA_MMD) + 0x0051)
#  define MPLLA_MULTIPLIER(d)	(((d) & 0xFF) << 0)
#  define MPLLA_SSC_CLK_SEL_0(d)	(((d) & 0x7) << 8)
#  define MPLLA_CAL_DISABLE(d)	(((d) & 0x1) << 15)

#define VR_XS_PMA_Gen5_16G_MPLLA_CTRL1	((map_XS_PMA_MMD) + 0x0052)
#define VR_XS_PMA_Gen5_12G_MPLLA_CTRL1	((map_XS_PMA_MMD) + 0x0052)
#  define MPLLA_SSC_EN(d)	(((d) & 0x1) << 0)
#  define MPLLA_SSC_RANGE(d)	(((d) & 0x7) << 1)
#  define MPLLA_SSC_CLK_SEL_1(d)	(((d) & 0x7) << 4)
#  define MPLLA_FRACN_CTRL(d)	(((d) & 0x1FF) << 7)

#define VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL2	((map_XS_PMA_MMD) + 0x0053)
#  define MPLLA_DIV_MULT(d)	(((d) & 0x7F) << 0)
#  define MPLLA_DIV_CLK_EN(d)	(((d) & 0x1) << 7)
#  define MPLLA_DIV8_CLK_EN(d)	(((d) & 0x1) << 8)
#  define MPLLA_DIV10_CLK_EN(d)	(((d) & 0x1) << 9)
#  define MPLLA_DIV16P5_CLK_EN(d)	(((d) & 0x1) << 10)
#  define MPLLA_TX_CLK_DIV(d)	(((d) & 0x3) << 11)
#  define MPLLA_RECAL_BANK_SEL(d)	(((d) & 0x3) << 13)

#define VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL0	((map_XS_PMA_MMD) + 0x0054)
#  define MPLLB_MULTIPLIER(d)	(((d) & 0xFF) << 0)
#  define MPLLB_SSC_CLK_SEL_0(d)	(((d) & 0x7) << 8)
#  define MPLLB_CAL_DISABLE(d)	(((d) & 0x1) << 15)

#define VR_XS_PMA_Gen5_16G_MPLLB_CTRL1	((map_XS_PMA_MMD) + 0x0055)
#define VR_XS_PMA_Gen5_12G_MPLLB_CTRL1	((map_XS_PMA_MMD) + 0x0055)
#  define MPLLB_SSC_EN(d)	(((d) & 0x1) << 0)
#  define MPLLB_SSC_RANGE(d)	(((d) & 0x7) << 1)
#  define MPLLB_SSC_CLK_SEL_1(d)	(((d) & 0x7) << 4)
#  define MPLLB_FRACN_CTRL(d)	(((d) & 0x1FF) << 7)

#define VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL2	((map_XS_PMA_MMD) + 0x0056)
#  define MPLLB_DIV_MULT(d)	(((d) & 0x7F) << 0)
#  define MPLLB_DIV_CLK_EN(d)	(((d) & 0x1) << 7)
#  define MPLLB_DIV8_CLK_EN(d)	(((d) & 0x1) << 8)
#  define MPLLB_DIV10_CLK_EN(d)	(((d) & 0x1) << 9)
#  define MPLLB_TX_CLK_DIV(d)	(((d) & 0x3) << 11)
#  define MPLLB_RECAL_BANK_SEL(d)	(((d) & 0x3) << 13)

#define VR_XS_PMA_Gen5_16G_MPLLA_CTRL3	((map_XS_PMA_MMD) + 0x0057)
#define VR_XS_PMA_Gen5_12G_MPLLA_CTRL3	((map_XS_PMA_MMD) + 0x0057)
#  define MPLLA_BANDWIDTH(d)	(((d) & 0x7FF) << 0)

#define VR_XS_PMA_Gen5_16G_MPLLB_CTRL3	((map_XS_PMA_MMD) + 0x0058)
#define VR_XS_PMA_Gen5_12G_MPLLB_CTRL3	((map_XS_PMA_MMD) + 0x0058)
#  define MPLLB_BANDWIDTH(d)	(((d) & 0x7FF) << 0)

#define VR_XS_PMA_Gen5_12G_16G_MISC_CTRL0	((map_XS_PMA_MMD) + 0x0070)
#  define TX2RX_LB_EN_0(d)	(((d) & 0x1) << 0)
#  define TX2RX_LB_EN_3_1(d)	(((d) & 0x7) << 1)
#  define RX2TX_LB_EN_0(d)	(((d) & 0x1) << 4)
#  define RX2TX_LB_EN_3_1(d)	(((d) & 0x7) << 5)
#  define RX_VREF_CTRL(d)	(((d) & 0x1F) << 8)
#  define RTUNE_REQ(d)	(((d) & 0x1) << 13)
#  define CR_PARA_SEL(d)	(((d) & 0x1) << 14)
#  define PLL_CTRL(d)	(((d) & 0x1) << 15)

#define VR_XS_PMA_Gen5_12G_16G_REF_CLK_CTRL	((map_XS_PMA_MMD) + 0x0071)
#  define REF_CLK_EN(d)	(((d) & 0x1) << 0)
#  define REF_USE_PAD(d)	(((d) & 0x1) << 1)
#  define REF_CLK_DIV2(d)	(((d) & 0x1) << 2)
#  define REF_RANGE(d)	(((d) & 0x7) << 3)
#  define REF_MPLLA_DIV2(d)	(((d) & 0x1) << 6)
#  define REF_MPLLB_DIV2(d)	(((d) & 0x1) << 7)
#  define REF_RPT_CLK_EN(d)	(((d) & 0x1) << 8)

#define VR_XS_PMA_Gen5_12G_16G_VCO_CAL_LD0	((map_XS_PMA_MMD) + 0x0072)
#  define VCO_LD_VAL_0(d)	(((d) & 0x1FFF) << 0)

#define VR_XS_PMA_Gen5_16G_VCO_CAL_REF0	((map_XS_PMA_MMD) + 0x0076)
#define VR_XS_PMA_Gen5_12G_VCO_CAL_REF0	((map_XS_PMA_MMD) + 0x0076)
#  define VCO_REF_LD_0(d)	(((d) & 0x3F) << 0)
#  define VCO_REF_LD_1(d)	(((d) & 0x3F) << 8)

#define VR_XS_PMA_Gen5_12G_16G_MISC_STS	((map_XS_PMA_MMD) + 0x0078)
#  define FOM(d)	(((d) & 0xFF) << 0)
#  define RTUNE_ACK(d)	(((d) & 0x1) << 8)
#  define MPLLA_STS(d)	(((d) & 0x1) << 9)
#  define MPLLB_STS(d)	(((d) & 0x1) << 10)
#  define REF_CLKDET_RESULT(d)	(((d) & 0x1) << 11)

#define VR_XS_PMA_Gen5_12G_16G_MISC_CTRL1	((map_XS_PMA_MMD) + 0x0079)
#  define RX_LNK_UP_TIME(d)	(((d) & 0xFFFF) << 0)

#define VR_XS_PMA_Gen5_12G_16G_SRAM	((map_XS_PMA_MMD) + 0x007B)
#  define INIT_DN(d)	(((d) & 0x1) << 0)
#  define EXT_LD_DN(d)	(((d) & 0x1) << 1)

#define VR_XS_PMA_Gen5_16G_MISC_CTRL2	((map_XS_PMA_MMD) + 0x007C)

#define VR_XS_PMA_SNPS_CR_CTRL	((map_XS_PMA_MMD) + 0x0080)
#  define START_BUSY(d)	(((d) & 0x1) << 0)
#  define WR_RDN(d)	(((d) & 0x1) << 1)
#  define MMD_ADDR(d)	(((d) & 0x1F) << 2)
#  define LANE_SEL(d)	(((d) & 0xF) << 8)

#define VR_XS_PMA_SNPS_CR_ADDR	((map_XS_PMA_MMD) + 0x0081)
#  define ADDRESS(d)	(((d) & 0xFFFF) << 0)

#define VR_XS_PMA_SNPS_CR_DATA	((map_XS_PMA_MMD) + 0x0082)
#  define VR_XS_DATA(d)	(((d) & 0xFFFF) << 0)


/* Block: map_XS_PCS_MMD */

#define SR_XS_PCS_CTRL1	((map_XS_PCS_MMD) + 0x0000)
#  define SS_5_2(d)	(((d) & 0xF) << 2)
#  define SS6(d)	(((d) & 0x1) << 6)
#  define XAUI_STOP(d)	(((d) & 0x1) << 9)
#  define CS_EN(d)	(((d) & 0x1) << 10)
#  define LPM(d)	(((d) & 0x1) << 11)
#  define SR_XS_SS13(d)	(((d) & 0x1) << 13)
#  define LBE(d)	(((d) & 0x1) << 14)
#  define SR_XS_RST(d)	(((d) & 0x1) << 15)

#define SR_XS_PCS_STS1	((map_XS_PCS_MMD) + 0x0001)
#  define LPMS(d)	(((d) & 0x1) << 1)
#  define RLU(d)	(((d) & 0x1) << 2)
#  define CSC(d)	(((d) & 0x1) << 6)
#  define FLT(d)	(((d) & 0x1) << 7)
#  define RXLPII(d)	(((d) & 0x1) << 8)
#  define TXLPII(d)	(((d) & 0x1) << 9)
#  define RXLPIR(d)	(((d) & 0x1) << 10)
#  define TXLPIR(d)	(((d) & 0x1) << 11)

#define SR_XS_PCS_DEV_ID1	((map_XS_PCS_MMD) + 0x0002)
#  define PCS_DEV_OUI_3_18(d)	(((d) & 0xFFFF) << 0)

#define SR_XS_PCS_DEV_ID2	((map_XS_PCS_MMD) + 0x0003)
#  define PCS_DEV_RN_3_0(d)	(((d) & 0xF) << 0)
#  define PCS_DEV_MMN_5_0(d)	(((d) & 0x3F) << 4)
#  define PCS_DEV_OUI_19_24(d)	(((d) & 0x3F) << 10)

#define SR_XS_PCS_SPD_ABL	((map_XS_PCS_MMD) + 0x0004)
#  define XGC(d)	(((d) & 0x1) << 0)

#define SR_XS_PCS_DEV_PKG1	((map_XS_PCS_MMD) + 0x0005)
#  define CLS22(d)	(((d) & 0x1) << 0)
#  define PMA_PMD(d)	(((d) & 0x1) << 1)
#  define WIS(d)	(((d) & 0x1) << 2)
#  define PCS(d)	(((d) & 0x1) << 3)
#  define PHYXS(d)	(((d) & 0x1) << 4)
#  define DTEXS(d)	(((d) & 0x1) << 5)
#  define TC(d)	(((d) & 0x1) << 6)
#  define AN(d)	(((d) & 0x1) << 7)

#define SR_XS_PCS_DEV_PKG2	((map_XS_PCS_MMD) + 0x0006)
#  define VSD1(d)	(((d) & 0x1) << 14)
#  define VSD2(d)	(((d) & 0x1) << 15)

#define SR_XS_PCS_CTRL2	((map_XS_PCS_MMD) + 0x0007)
#  define PCS_TYPE_SEL(d)	(((d) & 0xF) << 0)

#define SR_XS_PCS_STS2	((map_XS_PCS_MMD) + 0x0008)
#  define CAP_EN(d)	(((d) & 0x1) << 0)
#  define CAP_10_1GC(d)	(((d) & 0x1) << 1)
#  define CAP_10GBW(d)	(((d) & 0x1) << 2)
#  define CAP_10GBT(d)	(((d) & 0x1) << 3)
#  define SR_XS_RF(d)	(((d) & 0x1) << 10)
#  define TF(d)	(((d) & 0x1) << 11)
#  define DS(d)	(((d) & 0x3) << 14)

#define SR_XS_PCS_STS3	((map_XS_PCS_MMD) + 0x0009)
#  define CAP_200GR(d)	(((d) & 0x1) << 0)
#  define CAP_400GR(d)	(((d) & 0x1) << 1)
#  define CAP_2PT5GX(d)	(((d) & 0x1) << 2)
#  define CAP_5GR(d)	(((d) & 0x1) << 3)

#define SR_XS_PCS_PKG1	((map_XS_PCS_MMD) + 0x000E)
#  define PCS_PKG_OUI_3_18(d)	(((d) & 0xFFFF) << 0)

#define SR_XS_PCS_PKG2	((map_XS_PCS_MMD) + 0x000F)
#  define PCS_PKG_RN_3_0(d)	(((d) & 0xF) << 0)
#  define PCS_PKG_MMN_5_0(d)	(((d) & 0x3F) << 4)
#  define PCS_PKG_OUI_19_24(d)	(((d) & 0x3F) << 10)

#define SR_XS_PCS_LSTS	((map_XS_PCS_MMD) + 0x0018)
#  define LNS(d)	(((d) & 0xF) << 0)
#  define LBA(d)	(((d) & 0x1) << 10)
#  define TPA(d)	(((d) & 0x1) << 11)
#  define LA(d)	(((d) & 0x1) << 12)

#define SR_XS_PCS_TCTRL	((map_XS_PCS_MMD) + 0x0019)
#  define TP(d)	(((d) & 0x3) << 0)
#  define TPE(d)	(((d) & 0x1) << 2)

#define SR_XS_PCS_KR_STS1	((map_XS_PCS_MMD) + 0x0020)
#  define RPCS_BKLK(d)	(((d) & 0x1) << 0)
#  define RPCS_HIBER(d)	(((d) & 0x1) << 1)
#  define PRBS31ABL(d)	(((d) & 0x1) << 2)
#  define PRBS9ABL(d)	(((d) & 0x1) << 3)
#  define PLU(d)	(((d) & 0x1) << 12)

#define SR_XS_PCS_KR_STS2	((map_XS_PCS_MMD) + 0x0021)
#  define ERR_BLK(d)	(((d) & 0xFF) << 0)
#  define BER_CNT(d)	(((d) & 0x3F) << 8)
#  define LAT_HBER(d)	(((d) & 0x1) << 14)
#  define LAT_BL(d)	(((d) & 0x1) << 15)

#define SR_XS_PCS_TP_A0	((map_XS_PCS_MMD) + 0x0022)
#  define TP_SA0(d)	(((d) & 0xFFFF) << 0)

#define SR_XS_PCS_TP_A1	((map_XS_PCS_MMD) + 0x0023)
#  define TP_SA1(d)	(((d) & 0xFFFF) << 0)

#define SR_XS_PCS_TP_A2	((map_XS_PCS_MMD) + 0x0024)
#  define TP_SA2(d)	(((d) & 0xFFFF) << 0)

#define SR_XS_PCS_TP_A3	((map_XS_PCS_MMD) + 0x0025)
#  define TP_SA3(d)	(((d) & 0x3FF) << 0)

#define SR_XS_PCS_TP_B0	((map_XS_PCS_MMD) + 0x0026)
#  define TP_SB0(d)	(((d) & 0xFFFF) << 0)

#define SR_XS_PCS_TP_B1	((map_XS_PCS_MMD) + 0x0027)
#  define TP_SB1(d)	(((d) & 0xFFFF) << 0)

#define SR_XS_PCS_TP_B2	((map_XS_PCS_MMD) + 0x0028)
#  define TP_SB2(d)	(((d) & 0xFFFF) << 0)

#define SR_XS_PCS_TP_B3	((map_XS_PCS_MMD) + 0x0029)
#  define TP_SB3(d)	(((d) & 0x3FF) << 0)

#define SR_XS_PCS_TP_CTRL	((map_XS_PCS_MMD) + 0x002A)
#  define DP_SEL(d)	(((d) & 0x1) << 0)
#  define TP_SEL(d)	(((d) & 0x1) << 1)
#  define RTP_EN(d)	(((d) & 0x1) << 2)
#  define TTP_EN(d)	(((d) & 0x1) << 3)
#  define PRBS31T_EN(d)	(((d) & 0x1) << 4)
#  define PRBS31R_EN(d)	(((d) & 0x1) << 5)
#  define PRBS9T_EN(d)	(((d) & 0x1) << 6)

#define SR_XS_PCS_TP_ERRCTR	((map_XS_PCS_MMD) + 0x002B)
#  define TP_ERR_CNT(d)	(((d) & 0xFFFF) << 0)

#define SR_PCS_TIME_SYNC_PCS_ABL	((map_XS_PCS_MMD) + 0x0708)
#  define PCS_RX_DLY_ABL(d)	(((d) & 0x1) << 0)
#  define PCS_TX_DLY_ABL(d)	(((d) & 0x1) << 1)

#define SR_PCS_TIME_SYNC_TX_MAX_DLY_LWR	((map_XS_PCS_MMD) + 0x0709)
#  define PCS_TX_MAX_DLY_LWR(d)	(((d) & 0xFFFF) << 0)

#define SR_PCS_TIME_SYNC_TX_MAX_DLY_UPR	((map_XS_PCS_MMD) + 0x070A)
#  define PCS_TX_MAX_DLY_UPR(d)	(((d) & 0xFFFF) << 0)

#define SR_PCS_TIME_SYNC_TX_MIN_DLY_LWR	((map_XS_PCS_MMD) + 0x070B)
#  define PCS_TX_MIN_DLY_LWR(d)	(((d) & 0xFFFF) << 0)

#define SR_PCS_TIME_SYNC_TX_MIN_DLY_UPR	((map_XS_PCS_MMD) + 0x070C)
#  define PCS_TX_MIN_DLY_UPR(d)	(((d) & 0xFFFF) << 0)

#define SR_PCS_TIME_SYNC_RX_MAX_DLY_LWR	((map_XS_PCS_MMD) + 0x070D)
#  define PCS_RX_MAX_DLY_LWR(d)	(((d) & 0xFFFF) << 0)

#define SR_PCS_TIME_SYNC_RX_MAX_DLY_UPR	((map_XS_PCS_MMD) + 0x070E)
#  define PCS_RX_MAX_DLY_UPR(d)	(((d) & 0xFFFF) << 0)

#define SR_PCS_TIME_SYNC_RX_MIN_DLY_LWR	((map_XS_PCS_MMD) + 0x070F)
#  define PCS_RX_MIN_DLY_LWR(d)	(((d) & 0xFFFF) << 0)

#define SR_PCS_TIME_SYNC_RX_MIN_DLY_UPR	((map_XS_PCS_MMD) + 0x0710)
#  define PCS_RX_MIN_DLY_UPR(d)	(((d) & 0xFFFF) << 0)

#define VR_XS_PCS_DIG_CTRL1	((map_XS_PCS_MMD) + 0x8000)
#  define DSKBYP(d)	(((d) & 0x1) << 0)
#  define BYP_PWRUP(d)	(((d) & 0x1) << 1)
#  define EN_2_5G_MODE(d)	(((d) & 0x1) << 2)
#  define CR_CJN(d)	(((d) & 0x1) << 3)
#  define DTXLANED_0(d)	(((d) & 0x1) << 4)
#  define DTXLANED_3_1(d)	(((d) & 0x7) << 5)
#  define VR_XS_INIT(d)	(((d) & 0x1) << 8)
#  define USXG_EN(d)	(((d) & 0x1) << 9)
#  define USRA_RST(d)	(((d) & 0x1) << 10)
#  define PWRSV(d)	(((d) & 0x1) << 11)
#  define CL37_BP(d)	(((d) & 0x1) << 12)
#  define EN_VSMMD1(d)	(((d) & 0x1) << 13)
#  define R2TLBE(d)	(((d) & 0x1) << 14)
#  define VR_RST(d)	(((d) & 0x1) << 15)

#define VR_XS_PCS_DIG_CTRL2	((map_XS_PCS_MMD) + 0x8001)
#  define RX_POL_INV_0(d)	(((d) & 0x1) << 0)
#  define RX_POL_INV_3_1(d)	(((d) & 0x7) << 1)
#  define TX_POL_INV_0(d)	(((d) & 0x1) << 4)
#  define TX_POL_INV_3_1(d)	(((d) & 0x7) << 5)
#  define PRX_LN_DIS_3_1(d)	(((d) & 0x7) << 9)
#  define PTX_LN_DIS_3_1(d)	(((d) & 0x7) << 13)

#define VR_XS_PCS_DIG_ERRCNT_SEL	((map_XS_PCS_MMD) + 0x8002)
#  define COR(d)	(((d) & 0x1) << 0)
#  define reserved_3_1(d)	(((d) & 0x7) << 1)
#  define INV_EC_EN(d)	(((d) & 0x1) << 4)
#  define CHKEND_EC_EN(d)	(((d) & 0x1) << 5)
#  define DSKW_EC_EN(d)	(((d) & 0x1) << 6)
#  define TP_MIS_EN(d)	(((d) & 0x1) << 7)

#define VR_XS_PCS_XAUI_CTRL	((map_XS_PCS_MMD) + 0x8004)
#  define XAUI_MODE(d)	(((d) & 0x1) << 0)
#  define MRVL_RXAUI(d)	(((d) & 0x1) << 1)

#define VR_XS_PCS_DEBUG_CTRL	((map_XS_PCS_MMD) + 0x8005)
#  define RESTAR_SYNC_0(d)	(((d) & 0x1) << 0)
#  define RESTAR_SYNC_3_1(d)	(((d) & 0x7) << 1)
#  define SUPRESS_LOS_DET(d)	(((d) & 0x1) << 4)
#  define SUPRESS_EEE_LOS_DET(d)	(((d) & 0x1) << 5)
#  define RX_DT_EN_CTL(d)	(((d) & 0x1) << 6)
#  define RX_SYNC_CTL(d)	(((d) & 0x1) << 7)
#  define TX_PMBL_CTL(d)	(((d) & 0x1) << 8)
#  define RX_PMBL_CTL(d)	(((d) & 0x1) << 9)

#define VR_XS_PCS_KR_CTRL	((map_XS_PCS_MMD) + 0x8007)
#  define VR_TP_EN(d)	(((d) & 0x1) << 0)
#  define PR_DATA(d)	(((d) & 0x7) << 1)
#  define NVAL_SEL(d)	(((d) & 0x7) << 4)
#  define PRBS9RXEN(d)	(((d) & 0x1) << 7)
#  define DIS_SCR(d)	(((d) & 0x1) << 8)
#  define DIS_DESCR(d)	(((d) & 0x1) << 9)
#  define USXG_MODE(d)	(((d) & 0x7) << 10)

#define VR_XS_PCS_DIG_STS	((map_XS_PCS_MMD) + 0x8010)
#  define LB_ACTIVE(d)	(((d) & 0x1) << 1)
#  define PSEQ_STATE(d)	(((d) & 0x7) << 2)
#  define RXFIFO_UNDF(d)	(((d) & 0x1) << 5)
#  define RXFIFO_OVF(d)	(((d) & 0x1) << 6)
#  define INV_XGM_SOP(d)	(((d) & 0x1) << 7)
#  define INV_XGM_T(d)	(((d) & 0x1) << 8)
#  define INV_XGM_CHAR(d)	(((d) & 0x1) << 9)
#  define LRX_STATE(d)	(((d) & 0x7) << 10)
#  define LTX_STATE(d)	(((d) & 0x7) << 13)

#define VR_XS_PCS_ICG_ERRCNT1	((map_XS_PCS_MMD) + 0x8011)
#  define EC0(d)	(((d) & 0xFF) << 0)
#  define EC1(d)	(((d) & 0xFF) << 8)


/* Block: map_AN_MMD */

#define SR_AN_CTRL	((map_AN_MMD) + 0x0000)
#  define RSTRT_AN(d)	(((d) & 0x1) << 9)
#  define LPM(d)	(((d) & 0x1) << 11)
#  define AN_EN(d)	(((d) & 0x1) << 12)
#  define EXT_NP_CTL(d)	(((d) & 0x1) << 13)
#  define AN_RST(d)	(((d) & 0x1) << 15)

#define SR_AN_STS	((map_AN_MMD) + 0x0001)
#  define LP_AN_ABL(d)	(((d) & 0x1) << 0)
#  define AN_LS(d)	(((d) & 0x1) << 2)
#  define AN_ABL(d)	(((d) & 0x1) << 3)
#  define AN_RF(d)	(((d) & 0x1) << 4)
#  define ANC(d)	(((d) & 0x1) << 5)
#  define PR(d)	(((d) & 0x1) << 6)
#  define EXT_NP_STS(d)	(((d) & 0x1) << 7)
#  define PDF(d)	(((d) & 0x1) << 9)

#define SR_AN_DEV_ID1	((map_AN_MMD) + 0x0002)
#  define AN_DEV_OUI_3_18(d)	(((d) & 0xFFFF) << 0)

#define SR_AN_DEV_ID2	((map_AN_MMD) + 0x0003)
#  define AN_DEV_RN_3_0(d)	(((d) & 0xF) << 0)
#  define AN_DEV_MMN_5_0(d)	(((d) & 0x3F) << 4)
#  define AN_DEV_OUI_19_24(d)	(((d) & 0x3F) << 10)

#define SR_AN_DEV_PKG1	((map_AN_MMD) + 0x0005)
#  define CLS22(d)	(((d) & 0x1) << 0)
#  define PMA_PMD(d)	(((d) & 0x1) << 1)
#  define WIS(d)	(((d) & 0x1) << 2)
#  define PCS(d)	(((d) & 0x1) << 3)
#  define PHYXS(d)	(((d) & 0x1) << 4)
#  define DTEXS(d)	(((d) & 0x1) << 5)
#  define TC(d)	(((d) & 0x1) << 6)
#  define AN(d)	(((d) & 0x1) << 7)

#define SR_AN_DEV_PKG2	((map_AN_MMD) + 0x0006)
#  define VSD1(d)	(((d) & 0x1) << 14)
#  define VSD2(d)	(((d) & 0x1) << 15)

#define SR_AN_PKG1	((map_AN_MMD) + 0x000E)
#  define AN_PKG_OUI_3_18(d)	(((d) & 0xFFFF) << 0)

#define SR_AN_PKG2	((map_AN_MMD) + 0x000F)
#  define AN_PKG_RN_3_0(d)	(((d) & 0xF) << 0)
#  define AN_PKG_MMN_5_0(d)	(((d) & 0x3F) << 4)
#  define AN_PKG_OUI_19_24(d)	(((d) & 0x3F) << 10)

#define SR_AN_ADV1	((map_AN_MMD) + 0x0010)
#  define AN_ADV_SF(d)	(((d) & 0x1F) << 0)
#  define AN_ADV_DATA(d)	(((d) & 0x7F) << 5)
#  define AN_ADV_RF_13(d)	(((d) & 0x1) << 13)
#  define AN_ADV_ACK(d)	(((d) & 0x1) << 14)
#  define AN_ADV_NP(d)	(((d) & 0x1) << 15)

#define SR_AN_ADV2	((map_AN_MMD) + 0x0011)
#  define DATA_31_16(d)	(((d) & 0xFFFF) << 0)

#define SR_AN_ADV3	((map_AN_MMD) + 0x0012)
#  define DATA_47_32(d)	(((d) & 0xFFFF) << 0)

#define SR_AN_LP_ABL1	((map_AN_MMD) + 0x0013)
#  define AN_LP_ADV_SF(d)	(((d) & 0x1F) << 0)
#  define AN_LP_DATA(d)	(((d) & 0x7F) << 5)
#  define AN_LP_ADV_RF(d)	(((d) & 0x1) << 13)
#  define AN_LP_ADV_ACK(d)	(((d) & 0x1) << 14)
#  define AN_LP_ADV_NP(d)	(((d) & 0x1) << 15)

#define SR_AN_LP_ABL2	((map_AN_MMD) + 0x0014)
#  define DATA_31_16(d)	(((d) & 0xFFFF) << 0)

#define SR_AN_LP_ABL3	((map_AN_MMD) + 0x0015)
#  define DATA_47_32(d)	(((d) & 0xFFFF) << 0)

#define SR_AN_XNP_TX1	((map_AN_MMD) + 0x0016)
#  define MCF(d)	(((d) & 0x7FF) << 0)
#  define TB(d)	(((d) & 0x1) << 11)
#  define AN_XNP_ACK2(d)	(((d) & 0x1) << 12)
#  define AN_XNP_MP(d)	(((d) & 0x1) << 13)
#  define AN_XNP_NP(d)	(((d) & 0x1) << 15)

#define SR_AN_XNP_TX2	((map_AN_MMD) + 0x0017)
#  define UMCF1(d)	(((d) & 0xFFFF) << 0)

#define SR_AN_XNP_TX3	((map_AN_MMD) + 0x0018)
#  define UMCF2(d)	(((d) & 0xFFFF) << 0)

#define SR_AN_LP_XNP_ABL1	((map_AN_MMD) + 0x0019)
#  define MCF(d)	(((d) & 0x7FF) << 0)
#  define TB(d)	(((d) & 0x1) << 11)
#  define AN_LP_XNP_ACK2(d)	(((d) & 0x1) << 12)
#  define AN_LP_XNP_MP(d)	(((d) & 0x1) << 13)
#  define AN_LP_XNP_ACK(d)	(((d) & 0x1) << 14)
#  define AN_LP_XNP_NP(d)	(((d) & 0x1) << 15)

#define SR_AN_LP_XNP_ABL2	((map_AN_MMD) + 0x001A)
#  define UCF1(d)	(((d) & 0xFFFF) << 0)

#define SR_AN_LP_XNP_ABL3	((map_AN_MMD) + 0x001B)
#  define UCF2(d)	(((d) & 0xFFFF) << 0)

#define SR_AN_COMP_STS	((map_AN_MMD) + 0x0030)
#  define BP_AN_ABL(d)	(((d) & 0x1) << 0)
#  define AN_COMP_KX(d)	(((d) & 0x1) << 1)
#  define AN_COMP_KX4(d)	(((d) & 0x1) << 2)
#  define AN_COMP_KR(d)	(((d) & 0x1) << 3)
#  define AN_COMP_FEC(d)	(((d) & 0x1) << 4)
#  define AN_COMP_2PT5G(d)	(((d) & 0x1) << 14)
#  define AN_COMP_5G(d)	(((d) & 0x1) << 15)

#define VR_AN_DIG_CTRL1	((map_AN_MMD) + 0x8000)
#  define BYP_PWRUP(d)	(((d) & 0x1) << 1)
#  define BYP_NONCE_MAT(d)	(((d) & 0x1) << 2)
#  define CL73_TMR_OVR_RIDE(d)	(((d) & 0x1) << 3)
#  define PWRSV(d)	(((d) & 0x1) << 11)
#  define VR_RST(d)	(((d) & 0x1) << 15)

#define VR_AN_INTR_MSK	((map_AN_MMD) + 0x8001)
#  define AN_INT_CMPLT_IE(d)	(((d) & 0x1) << 0)
#  define AN_INC_LINK_IE(d)	(((d) & 0x1) << 1)
#  define AN_PG_RCV_IE(d)	(((d) & 0x1) << 2)

#define VR_AN_INTR	((map_AN_MMD) + 0x8002)
#  define AN_INT_CMPLT(d)	(((d) & 0x1) << 0)
#  define AN_INC_LINK(d)	(((d) & 0x1) << 1)
#  define AN_PG_RCV(d)	(((d) & 0x1) << 2)

#define VR_AN_KR_MODE_CTRL	((map_AN_MMD) + 0x8003)
#  define PDET_EN(d)	(((d) & 0x1) << 0)

#define VR_AN_TIMER_CTRL0	((map_AN_MMD) + 0x8004)
#  define BRK_LINK_TIME(d)	(((d) & 0xFFFF) << 0)

#define VR_AN_TIMER_CTRL1	((map_AN_MMD) + 0x8005)
#  define INHBT_OR_WAIT_TIME(d)	(((d) & 0xFFFF) << 0)


/* Block: map_VS_MMD1 */

#define SR_VSMMD_PMA_ID1	((map_VS_MMD1) + 0x0000)
#  define PMADOUI_3_18(d)	(((d) & 0xFFFF) << 0)

#define SR_VSMMD_PMA_ID2	((map_VS_MMD1) + 0x0001)
#  define PMADRN_3_0(d)	(((d) & 0xF) << 0)
#  define PMADMMN_5_0(d)	(((d) & 0x3F) << 4)
#  define PMADOUI_19_24(d)	(((d) & 0x3F) << 10)

#define SR_VSMMD_DEV_ID1	((map_VS_MMD1) + 0x0002)
#  define VSDOUI_3_18(d)	(((d) & 0xFFFF) << 0)

#define SR_VSMMD_DEV_ID2	((map_VS_MMD1) + 0x0003)
#  define VSDRN_3_0(d)	(((d) & 0xF) << 0)
#  define VSDMMN_5_0(d)	(((d) & 0x3F) << 4)
#  define VSDOUI_19_24(d)	(((d) & 0x3F) << 10)

#define SR_VSMMD_PCS_ID1	((map_VS_MMD1) + 0x0004)
#  define PCSDOUI_3_18(d)	(((d) & 0xFFFF) << 0)

#define SR_VSMMD_PCS_ID2	((map_VS_MMD1) + 0x0005)
#  define PCSDRN_3_0(d)	(((d) & 0xF) << 0)
#  define PCSDMMN_5_0(d)	(((d) & 0x3F) << 4)
#  define PCSDOUI_19_24(d)	(((d) & 0x3F) << 10)

#define SR_VSMMD_AN_ID1	((map_VS_MMD1) + 0x0006)
#  define ANDOUI_3_18(d)	(((d) & 0xFFFF) << 0)

#define SR_VSMMD_AN_ID2	((map_VS_MMD1) + 0x0007)
#  define ANDRN_3_0(d)	(((d) & 0xF) << 0)
#  define ANDMMN_5_0(d)	(((d) & 0x3F) << 4)
#  define ANDOUI_19_24(d)	(((d) & 0x3F) << 10)

#define SR_VSMMD_STS	((map_VS_MMD1) + 0x0008)
#  define VSDP(d)	(((d) & 0x3) << 14)

#define SR_VSMMD_CTRL	((map_VS_MMD1) + 0x0009)
#  define AN_MMD_EN(d)	(((d) & 0x1) << 0)
#  define PCS_XS_MMD_EN(d)	(((d) & 0x1) << 1)
#  define MII_MMD_EN(d)	(((d) & 0x1) << 2)
#  define PMA_MMD_EN(d)	(((d) & 0x1) << 3)
#  define FASTSIM(d)	(((d) & 0x1) << 4)
#  define PD_CTRL(d)	(((d) & 0x1) << 5)

#define SR_VSMMD_PKGID1	((map_VS_MMD1) + 0x000E)
#  define MMDPOUI_3_18(d)	(((d) & 0xFFFF) << 0)

#define SR_VSMMD_PKGID2	((map_VS_MMD1) + 0x000F)
#  define MMDPRN_3_0(d)	(((d) & 0xF) << 0)
#  define MMDPMMN_5_0(d)	(((d) & 0x3F) << 4)
#  define MMDPOUI_19_24(d)	(((d) & 0x3F) << 10)


/* Block: map_VS_MII_MMD */

#define SR_MII_CTRL	((map_VS_MII_MMD) + 0x0000)
#  define SS5(d)	(((d) & 0x1) << 5)
#  define SS6(d)	(((d) & 0x1) << 6)
#  define DUPLEX_MODE(d)	(((d) & 0x1) << 8)
#  define RESTART_AN(d)	(((d) & 0x1) << 9)
#  define LPM(d)	(((d) & 0x1) << 11)
#  define AN_ENABLE(d)	(((d) & 0x1) << 12)
#  define SR_MII_SS13(d)	(((d) & 0x1) << 13)
#  define LBE(d)	(((d) & 0x1) << 14)
#  define SR_MII_RST(d)	(((d) & 0x1) << 15)

#define SR_MII_STS	((map_VS_MII_MMD) + 0x0001)
#  define EXT_REG_CAP(d)	(((d) & 0x1) << 0)
#  define LINK_STS(d)	(((d) & 0x1) << 2)
#  define AN_ABL(d)	(((d) & 0x1) << 3)
#  define STS_RF(d)	(((d) & 0x1) << 4)
#  define AN_CMPL(d)	(((d) & 0x1) << 5)
#  define MF_PRE_SUP(d)	(((d) & 0x1) << 6)
#  define UN_DIR_ABL(d)	(((d) & 0x1) << 7)
#  define EXT_STS_ABL(d)	(((d) & 0x1) << 8)
#  define HD100T(d)	(((d) & 0x1) << 9)
#  define FD100T(d)	(((d) & 0x1) << 10)
#  define HD10ABL(d)	(((d) & 0x1) << 11)
#  define FD10ABL(d)	(((d) & 0x1) << 12)
#  define HD100ABL(d)	(((d) & 0x1) << 13)
#  define FD100ABL(d)	(((d) & 0x1) << 14)
#  define ABL100T4(d)	(((d) & 0x1) << 15)

#define SR_MII_DEV_ID1	((map_VS_MII_MMD) + 0x0002)
#  define VS_MII_DEV_OUI_3_18(d)	(((d) & 0xFFFF) << 0)

#define SR_MII_DEV_ID2	((map_VS_MII_MMD) + 0x0003)
#  define VS_MMD_DEV_RN_3_0(d)	(((d) & 0xF) << 0)
#  define VS_MMD_DEV_MMN_5_0(d)	(((d) & 0x3F) << 4)
#  define VS_MMD_DEV_OUI_19_24(d)	(((d) & 0x3F) << 10)

#define SR_MII_AN_ADV	((map_VS_MII_MMD) + 0x0004)
#  define FD(d)	(((d) & 0x1) << 5)
#  define HD(d)	(((d) & 0x1) << 6)
#  define PAUSE(d)	(((d) & 0x3) << 7)
#  define AN_ADV_RF(d)	(((d) & 0x3) << 12)
#  define NP(d)	(((d) & 0x1) << 15)

#define SR_MII_LP_BABL	((map_VS_MII_MMD) + 0x0005)
#  define LP_FD(d)	(((d) & 0x1) << 5)
#  define LP_HD(d)	(((d) & 0x1) << 6)
#  define LP_PAUSE(d)	(((d) & 0x3) << 7)
#  define LP_RF(d)	(((d) & 0x3) << 12)
#  define LP_ACK(d)	(((d) & 0x1) << 14)
#  define LP_NP(d)	(((d) & 0x1) << 15)

#define SR_MII_AN_EXPN	((map_VS_MII_MMD) + 0x0006)
#  define PG_RCVD(d)	(((d) & 0x1) << 1)
#  define LD_NP_ABL(d)	(((d) & 0x1) << 2)

#define SR_MII_EXT_STS	((map_VS_MII_MMD) + 0x000F)
#  define CAP_1G_T_HD(d)	(((d) & 0x1) << 12)
#  define CAP_1G_T_FD(d)	(((d) & 0x1) << 13)
#  define CAP_1G_X_HD(d)	(((d) & 0x1) << 14)
#  define CAP_1G_X_FD(d)	(((d) & 0x1) << 15)

#define VR_MII_DIG_CTRL1	((map_VS_MII_MMD) + 0x8000)
#  define PHY_MODE_CTRL(d)	(((d) & 0x1) << 0)
#  define BYP_PWRUP(d)	(((d) & 0x1) << 1)
#  define EN_2_5G_MODE(d)	(((d) & 0x1) << 2)
#  define CL37_TMR_OVR_RIDE(d)	(((d) & 0x1) << 3)
#  define DTXLANED_0(d)	(((d) & 0x1) << 4)
#  define PRE_EMP(d)	(((d) & 0x1) << 6)
#  define MSK_RD_ERR(d)	(((d) & 0x1) << 7)
#  define VR_MII_INIT(d)	(((d) & 0x1) << 8)
#  define MAC_AUTO_SW(d)	(((d) & 0x1) << 9)
#  define CS_EN(d)	(((d) & 0x1) << 10)
#  define PWRSV(d)	(((d) & 0x1) << 11)
#  define CL37_BP(d)	(((d) & 0x1) << 12)
#  define EN_VSMMD1(d)	(((d) & 0x1) << 13)
#  define R2TLBE(d)	(((d) & 0x1) << 14)
#  define VR_RST(d)	(((d) & 0x1) << 15)

#define VR_MII_AN_CTRL	((map_VS_MII_MMD) + 0x8001)
#  define MII_AN_INTR_EN(d)	(((d) & 0x1) << 0)
#  define PCS_MODE(d)	(((d) & 0x3) << 1)
#  define TX_CONFIG(d)	(((d) & 0x1) << 3)
#  define SGMII_LINK_STS(d)	(((d) & 0x1) << 4)
#  define MII_CTRL(d)	(((d) & 0x1) << 8)

#define VR_MII_AN_INTR_STS	((map_VS_MII_MMD) + 0x8002)
#  define CL37_ANCMPLT_INTR(d)	(((d) & 0x1) << 0)
#  define CL37_ANSGM_STS(d)	(((d) & 0xF) << 1)
#  define LP_EEE_CAP(d)	(((d) & 0x1) << 5)
#  define LP_CK_STP(d)	(((d) & 0x1) << 6)
#  define USXG_AN_STS(d)	(((d) & 0x7F) << 8)

#define VR_MII_LINK_TIMER_CTRL	((map_VS_MII_MMD) + 0x800A)
#  define CL37_LINK_TIME(d)	(((d) & 0xFFFF) << 0)


/* System: eioh_1g10gsyn_DWC_xpcs */
#define map_PMA_MMD		(((0x01) << 18) | 0x0000)
#define map_XS_PMA_MMD		(((0x01) << 18) | 0x8020)
#define map_XS_PCS_MMD		(((0x03) << 18) | 0x0000)
#define map_AN_MMD		(((0x07) << 18) | 0x0000)
#define map_VS_MMD1		(((0x1E) << 18) | 0x0000)
#define map_VS_MII_MMD		(((0x1F) << 18) | 0x0000)

#endif /* ELDWCXPCS_H__ */
