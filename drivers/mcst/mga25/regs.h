/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __MGA2_REGS_H__
#define __MGA2_REGS_H__


#define	MGA2_DC0_REG_SZ		0x400


#define  MGA2_VDID		0x00000
#define  MGA2_REVISION_ID	0x00004
#define  MGA2_POSSIB0		0x00008
#define  MGA2_POSSIB1		0x0000C
#define	 MGA2_VID0_SZ		0x400



# define MGA25_VID0_B_AUENA      (1 << 7)
# define MGA25_VID0_B_AUSEL_OFFSET      4
# define MGA25_VID0_B_PXENA      (1 << 3)
# define MGA25_VID0_B_PXSEL_OFFSET      0

# define MGA25_VID3_B_SCALER_OFF      (2 << 30)

# define MGA25_VID0_B_ENABLE (1 << 31)
# define MGA25_VID0_B_DDRCPY (1 << 16)
# define MGA25_VID0_B_MSSWAP (1 << 12)
# define MGA25_VID0_B_RESYNC (1 << 11)
# define MGA25_VID0_B_LHSWAP (1 << 10)
# define MGA25_VID0_B_CKDLY  (1 << 9:8)
# define MGA25_VID0_SYNC_CHK (1 << 7)
# define MGA25_VID0_B_MODE   (1 << 1:0)

# define MGA2_VID3_B_ENABLE    (1 << 31)
# define MGA2_VID3_B_RESYNC    (1 << 30)
# define MGA2_VID3_B_10BIT    (1 << 28)
# define MGA2_VID3_B_CHAN_MASK      3
# define MGA2_VID3_B_P3CHAN_OFFSET    22
# define MGA2_VID3_B_P2CHAN_OFFSET    20
# define MGA2_VID3_B_P1CHAN_OFFSET    18
# define MGA2_VID3_B_P0CHAN_OFFSET    16
# define MGA2_VID3_B_P3ENA     (1 << 11)
# define MGA2_VID3_B_P2ENA     (1 << 10)
# define MGA2_VID3_B_P1ENA     (1 << 9)
# define MGA2_VID3_B_P0ENA     (1 << MGA2_VID3_B_P0ENA_OFFSET)
# define MGA2_VID3_B_P0ENA_OFFSET     8
# define MGA2_VID3_B_MODE_OFFSET      1
# define MGA2_VID3_B_MODE_MASK      3


# define MGA2_VID3_B_BCINCR_OFFSET    (1 << 31)
# define MGA2_VID3_B_BCADDR_OFFSET    8
# define MGA2_VID3_B_BCDATA_OFFSET    0

# define MGA2_VID3_B_P3_ENB   (1 << 15)
# define MGA2_VID3_B_P3_ENPD  (1 << 14)
# define MGA2_VID3_B_P3_ENREF (1 << 13)
# define MGA2_VID3_B_P3_OEB   (1 << 12)
# define MGA2_VID3_B_P2_ENB   (1 << 11)
# define MGA2_VID3_B_P2_ENPD  (1 << 10)
# define MGA2_VID3_B_P2_ENREF (1 << 9)
# define MGA2_VID3_B_P2_OEB   (1 << 8)
# define MGA2_VID3_B_P1_ENB   (1 << 7)
# define MGA2_VID3_B_P1_ENPD  (1 << 6)
# define MGA2_VID3_B_P1_ENREF (1 << 5)
# define MGA2_VID3_B_P1_OEB   (1 << 4)
# define MGA2_VID3_B_P0_ENB   (1 << 3)
# define MGA2_VID3_B_P0_ENPD  (1 << 2)
# define MGA2_VID3_B_P0_ENREF (1 << 1)
# define MGA2_VID3_B_P0_OEB   (1 << 0)


#define	 MGA2_VID3_BITCTRL	0x03018
#define	 MGA2_VID0_BITCTRL	0x00018
# define MGA2_VID3_B_ADDR_OFFSET	8

# define	 LVDS_R7	 0
# define	 LVDS_R6	 1
# define	 LVDS_R5	 2
# define	 LVDS_R4	 3
# define	 LVDS_R3	 4
# define	 LVDS_R2	 5
# define	 LVDS_R1	 6
# define	 LVDS_R0	 7

# define	 LVDS_G7	 8
# define	 LVDS_G6	 9
# define	 LVDS_G5	 10
# define	 LVDS_G4	 11
# define	 LVDS_G3	 12
# define	 LVDS_G2	 13
# define	 LVDS_G1	 14
# define	 LVDS_G0	 15

# define	 LVDS_B7	 16
# define	 LVDS_B6	 17
# define	 LVDS_B5	 18
# define	 LVDS_B4	 19
# define	 LVDS_B3	 20
# define	 LVDS_B2	 21
# define	 LVDS_B1	 22
# define	 LVDS_B0	 23

# define	 LVDS_01	 24
# define	 LVDS_00	 25
# define	 LVDS_DE	 26
# define	 LVDS_VS	 27
# define	 LVDS_HS	 28
# define	 LVDS_CS	 29

# define	 LVDS25_R9	 0
# define	 LVDS25_R8	 1
# define	 LVDS25_R7	 2
# define	 LVDS25_R6	 3
# define	 LVDS25_R5	 4
# define	 LVDS25_R4	 5
# define	 LVDS25_R3	 6
# define	 LVDS25_R2	 7
# define	 LVDS25_R1	 8
# define	 LVDS25_R0	 9

# define	 LVDS25_G9	 10
# define	 LVDS25_G8	 11
# define	 LVDS25_G7	 12
# define	 LVDS25_G6	 13
# define	 LVDS25_G5	 14
# define	 LVDS25_G4	 15
# define	 LVDS25_G3	 16
# define	 LVDS25_G2	 17
# define	 LVDS25_G1	 18
# define	 LVDS25_G0	 19

# define	 LVDS25_B9	 20
# define	 LVDS25_B8	 21
# define	 LVDS25_B7	 22
# define	 LVDS25_B6	 23
# define	 LVDS25_B5	 24
# define	 LVDS25_B4	 25
# define	 LVDS25_B3	 26
# define	 LVDS25_B2	 27
# define	 LVDS25_B1	 28
# define	 LVDS25_B0	 29

# define	 LVDS25_00	 32
# define	 LVDS25_01	 33
# define	 LVDS25_DE	 34
# define	 LVDS25_VS	 35
# define	 LVDS25_HS	 36
# define	 LVDS25_CS	 37

#define	 MGA2_VID0_RESYNC_CTRL		0x00014
#define	 MGA2_VID0_TXI2C		0x00020
#define	 MGA2_VID0_DDCI2C		0x00030

#define MGA2_6_VMMUX_OFFSETH	(0x03400 + 0x0104)
#define MGA2_6_FBMUX_OFFSETH	(0x03800 + 0x0104)

#endif	/*__MGA2_REGS_H__*/
