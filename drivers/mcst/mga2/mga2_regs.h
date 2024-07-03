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

#define	 MGA2_DC0_CTRL		0x00000
#define MGA2_DC_B_NO_FETCH	(1 << 16)
#define MGA2_DC_CTRL_NATIVEMODE        (1 << 0)
#define MGA2_DC_CTRL_DIS_VGAREGS       (1 << 1)
#define MGA2_DC_CTRL_LINEARMODE        (1 << 2)
#define MGA2_DC_CTRL_NOSCRRFRSH        (1 << 16)
#define MGA2_DC_CTRL_SOFT_RESET        (1 << 31)
#define MGA2_DC_CTRL_DEFAULT	(MGA2_DC_CTRL_NATIVEMODE | MGA2_DC_CTRL_DIS_VGAREGS)

#define	 MGA2_DC0_VGAWINOFFS		0x00004
#define	 MGA2_DC0_VGABASE		0x00008
#define	 MGA2_DC0_VGAREGS		0x00000
#define	 MGA2_DC0_TMPADDR		0x00010

#define	 MGA2_DC0_PIXFMT		0x00020
#define MGA2_DC_B_EXT_TXT		(1 << 31)
#define MGA2_DC_B_BGR			(0x24 << 4)
#define MGA2_DC_B_RGB			(6 << 4)
#define MGA2_DC_B_RGBX_FMT		(2 << 2)

#define MGA2_DC_B_1555_FMT		(0 << 2)
#define MGA2_DC_B_565_FMT		(1 << 2)
#define MGA2_DC_B_4444_FMT		(2 << 2)
#define MGA2_DC_B_RGB_16SWAP		(2 << 4)

#define MGA2_DC_B_8BPP			0
#define MGA2_DC_B_16BPP			1
#define MGA2_DC_B_24BPP			2
#define MGA2_DC_B_32BPP			3

#define	 MGA2_DC0_WSTART	0x00030
#define	 MGA2_DC0_WOFFS		0x00034
#define	 MGA2_DC0_WCRSADDR	0x00038
#define	 MGA2_DC0_WCRSCOORD	0x0003C
#define	 MGA2_DC0_WPALID	0x00040
#define	 MGA2_DC0_NSTART	0x00050
#define	 MGA2_DC0_NOFFS		0x00054

#define	 MGA2_DC0_NCRSADDR	0x00058
#define	 MGA2_DC_B_CRS_ENA	(1 << 0)

#define	 MGA2_DC0_NCRSCOORD	0x0005C
#define	 MGA2_DC0_NPALID	0x00060
#define	 MGA2_DC0_DISPCTRL	0x00064
#define MGA2_DC_B_STROB        (1 << 31)

#define	 MGA2_DC0_HVCTRL	0x00070

#define MGA2_DC_B_CSYNC_MODE    (1 << 16)
#define MGA2_DC_B_HSYNC_ENA     (1 << 11)
#define MGA2_DC_B_VSYNC_ENA     (1 << 10)
#define MGA2_DC_B_CSYNC_ENA     (1 << 9)
#define MGA2_DC_B_DE_ENA        (1 << 8)
#define MGA2_DC_B_HSYNC_POL     (1 << 3)
#define MGA2_DC_B_VSYNC_POL     (1 << 2)
#define MGA2_DC_B_CSYNC_POL     (1 << 1)
#define MGA2_DC_B_DE_POL        (1 << 0)

#define	 MGA2_DC0_HSYNC		0x00074
#define	 MGA2_DC0_HDELAY	0x00078
#define	 MGA2_DC0_HVIS		0x0007C
#define	 MGA2_DC0_HTOT		0x00080
#define	 MGA2_DC0_VSYNC		0x00084
#define	 MGA2_DC0_VDELAY	0x00088
#define	 MGA2_DC0_VVIS		0x0008C
#define	 MGA2_DC0_VTOT		0x00090
#define	 MGA2_DC0_HCOUNT	0x00094
#define	 MGA2_DC0_VCOUNT	0x00098
#define	 MGA2_DC0_PALADDR	0x000A0

#define	 MGA2_DC_B_AUTOINC       (1 << 31)

#define	 MGA2_DC0_PALDATA	0x000A4
#define	 MGA2_DC0_GAMCTRL	0x000A8
#define MGA2_DC_GAMCTRL_ENABLE	(1 << 31)

#define	MGA2_DC0_GAMSET			0x000AC
#define MGA2_DC_GAMSET_SEL_BLUE        (1 << 8)
#define MGA2_DC_GAMSET_SEL_GREEN       (1 << 9)
#define MGA2_DC_GAMSET_SEL_RED         (1 << 10)
#define MGA2_DC_GAMSET_SEL_ALL         (7 << 8)
#define MGA2_DC_GAMSET_ADDR_OFFSET     16

#define	 MGA2_DC0_DITCTRL		0x000B0
#define MGA2_DC_DITCTRL_ENABLE         (1 << 31)
#define MGA2_DC_DITCTRL_DISABLE        (0 << 31)

#define	 MGA2_DC0_DITSET0		0x000B4
#define	 MGA2_DC0_DITSET1		0x000B8

#define	 MGA2_DC0_CLKCTRL		0x000C0
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

#define	 MGA2_DC0_CLKCTRL_ACLKON	0x000C4
#define	 MGA2_DC0_INTPLLCTRL		0x000D0
#define	 MGA2_DC0_INTPLLCLKF0		0x000E0
#define	 MGA2_DC0_INTPLLCLKR0		0x000E4
#define	 MGA2_DC0_INTPLLCLKOD0		0x000E8
#define	 MGA2_DC0_INTPLLBWADJ0		0x000EC
#define	 MGA2_DC0_INTPLLCLKF1		0x000F0
#define	 MGA2_DC0_INTPLLCLKR1		0x000F4
#define	 MGA2_DC0_INTPLLCLKOD1		0x000F8
#define	 MGA2_DC0_INTPLLBWADJ1		0x000FC

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

#define MGA2_DC0_PLLCTRL_25	0x0C4
#define MGA2_DC0_PLLCLKF0INT_25	0x0CC
#define MGA2_DC0_PLLCLKF0FRAC_25	0x0C8
#define MGA2_DC0_PLLCLKR0_25	0x0D0
#define MGA2_DC0_PLLCLKOD0_25	0x0D4

# define MGA2_DC_EXTPLLI2C_RD            (0 << 31)
# define MGA2_DC_EXTPLLI2C_WR            (1 << 31)
# define MGA2_DC_EXTPLLI2C_ADDR_OFFSET   8L

#define	MGA2_DC0_GPIO_MUX		0x00120
#define MGA2_DC_B_GPIOMUX_CS1		(1 << 1)
#define MGA2_DC_B_GPIOMUX_CS0		(1 << 0)
#define	MGA2_DC0_GPIO_MUXSETRST		0x00124
#define	 MGA2_DC0_GPIO_PUP		0x00128
#define	 MGA2_DC0_GPIO_PUPSETRST	0x0092C
#define	 MGA2_DC0_GPIO_DIR		0x00130
#define	 MGA2_DC0_GPIO_DIRSETRST	0x00934
#define	 MGA2_DC0_GPIO_OUT		0x00138
#define	 MGA2_DC0_GPIO_OUTSETRST	0x0093C
#define	 MGA2_DC0_GPIO_IN		0x00140


#define MGA2_DC0_OVL_CTRL       (0x60 * 4)
# define MGA2_DC0_OVL_UPD_BUSY  (1 << 31)
# define MGA2_DC0_OVL_ENABLE    (1 << 0)
# define MGA2_DC0_OVL_ALPHA_SHIFT    8
#define MGA2_DC0_OVL_XY         (0x61 * 4)
#define MGA2_DC0_OVL_KEY_MIN    (0x62 * 4)
#define MGA2_DC0_OVL_KEY_MAX    (0x63 * 4)
#define MGA2_DC0_OVL_BASE0      (0x64 * 4)
#define MGA2_DC0_OVL_BASE1      (0x65 * 4)
#define MGA2_DC0_OVL_BASE2      (0x66 * 4)
#define MGA2_DC0_OVL_STRIDE0    (0x67 * 4)
#define MGA2_DC0_OVL_STRIDE1    (0x68 * 4)
#define MGA2_DC0_OVL_STRIDE2    (0x69 * 4)
#define MGA2_DC0_OVL_GEOMETRY   (0x6A * 4)
#define MGA2_DC0_OVL_MODE       (0x6B * 4)
# define  MGA2_DC_B_MODE_RGB		0x00
# define  MGA2_DC_B_MODE_ARGB		0x08
# define  MGA2_DC_B_MODE_YUYV		0x10
# define  MGA2_DC_B_MODE_AYUV		0X0C
# define  MGA2_DC_B_MODE_YUV		0X04
# define  MGA2_DC_B_MODE_NV12		0x42
# define  MGA2_DC_B_MODE_NV21		0x43
# define  MGA2_DC_B_MODE_NV16		0x40
# define  MGA2_DC_B_MODE_NV61		0x41
# define  MGA2_DC_B_MODE_NV24		0x44
# define  MGA2_DC_B_MODE_NV42		0x45
# define  MGA2_DC_B_MODE_YUV420		0x22
# define  MGA2_DC_B_MODE_YUV422		0x20
# define  MGA2_DC_B_MODE_YUV444		0x24
# define  MGA2_DC_B_MODE_ENDIAN_SHIFT	8
# define MGA_MODE_ENDIAN(_a, _b, _c, _d) (( \
	(((_a)&3) << 6) | (((_b)&3) << 4) | \
	(((_c)&3) << 2) | (((_d)&3) << 0))  \
	    << MGA2_DC_B_MODE_ENDIAN_SHIFT)



#define MGA2_DC0_ZOOM_DSTGEOM   (0x6C * 4)
#define MGA2_DC0_ZOOM_SRCGEOM   (0x6D * 4)
#define MGA2_DC0_ZOOM_HPITCH    (0x6E * 4)
#define MGA2_DC0_ZOOM_VPITCH    (0x6F * 4)
#define MGA2_DC0_ZOOM_IHVSUM    (0x70 * 4)
#define MGA2_DC0_ZOOM_CTRL      (0x71 * 4)
#define MGA2_DC0_ZOOM_FTAP0     (0x72 * 4)
#define MGA2_DC0_ZOOM_FTAP1     (0x73 * 4)
#define MGA2_DC0_ZOOM_FTAP2     (0x74 * 4)
#define MGA2_DC0_ZOOM_FTAP3     (0x75 * 4)
#define MGA2_DC0_ZOOM_FTAP4     (0x76 * 4)
#define MGA2_DC0_ZOOM_FWRITE    (0x77 * 4)
# define MGA2_DC0_ZOOM_COORD_SHIFT	4


#define MGA2_DC0_Y2R_YPRE       (0x78 * 4)
#define MGA2_DC0_Y2R_UPRE       (0x79 * 4)
#define MGA2_DC0_Y2R_VPRE       (0x7A * 4)
#define MGA2_DC0_Y2R_MATRIX     (0x7B * 4)
#define MGA2_DC0_Y2R_RSH        (0x7C * 4)
#define MGA2_DC0_Y2R_GSH        (0x7D * 4)
#define MGA2_DC0_Y2R_BSH        (0x7E * 4)

#define	 MGA2_VID0_SZ		0x400

#define MGA2_VID0_B_MODE_OFFSET	0
#define MGA2_VID0_B_MODE_ALL	3
#define MGA2_VID0_B_MODE_2XDDR	2
#define MGA2_VID0_B_MODE_1XDDR	1
#define MGA2_VID0_B_MODE_SDR	0
#define MGA2_VID0_B_STROBE_DELAY_OFFSET	8
#define MGA2_VID0_B_STROBE_DELAY_ALL	3
#define MGA2_VID0_B_STROBE_DELAY_0	0
#define MGA2_VID0_B_STROBE_DELAY_1_4	1
#define MGA2_VID0_B_STROBE_DELAY_1_2	2
#define MGA2_VID0_B_STROBE_DELAY_3_4	3
#define MGA2_VID0_B_DDR_LOW_FIRST	(1 << 10)
#define MGA2_VID0_B_2XDDR_EN_RESYNC	(1 << 11)
#define MGA2_VID0_B_1XDDR_EN_COPY	(1 << 16)
#define MGA2_VID0_B_ENABLE	(1 << 31)

#define MGA2_VID_B_SAFE_EXC_WR	(1 << 0)
#define MGA2_VID_B_SAFE_EXC_RD	(1 << 1)
#define MGA2_VID_B_EXC_WR	(1 << 2)
#define MGA2_VID_B_EXC_RD	(1 << 3)
#define MGA2_VID_B_SAFE_MODESET	(1 << 31)

#define	 MGA2_VID0_MUX		0x00000

#define MGA2_VID_B_MUX_OFFSET	0
#define MGA2_VID_B_MUX_ALL	3
#define MGA2_VID_B_MUX_NONE	0
#define MGA2_VID_B_MUX_DC0	2
#define MGA2_VID_B_MUX_DC1	3
#define MGA2_VID0_B_GPIOMUX_I2C	3
#define MGA2_VID0_B_GPIOMUX_GPIO	0


# define MGA25_VID0_B_AUENA      (1 << 7)
# define MGA25_VID0_B_AUSEL_OFFSET      4
# define MGA25_VID0_B_PXENA      (1 << 3)
# define MGA25_VID0_B_PXSEL_OFFSET      0

# define MGA25_VID3_B_SCALER_OFF      (2 << 30)

#define	 MGA2_VID0_CTRL		0x00010
# define MGA2_VID12_B_USE_MGA2_DDC       (1 << 0)
# define MGA2_VID12_B_HS_CONV_OFFSET     2
# define MGA2_VID12_B_VS_CONV_OFFSET     4
# define MGA2_VID12_B_DE_CONV_OFFSET     6
# define MGA2_VID12_B_CEC_IN_INVERT      (1 << 8)
# define MGA2_VID12_B_CEC_ACT_LEVEL      (1 << 9)
# define MGA2_VID12_B_CEC_OUT_LEVEL      (1 << 10)
# define MGA2_VID12_B_HDMI_RSTZ          (1 << 12)
# define MGA2_VID12_B_EN_SFRCLK          (1 << 13)
# define MGA2_VID12_B_EN_CECCLK          (1 << 14)
# define MGA2_VID12_B_EN_I2SCLK          (1 << 15)
# define MGA2_VID12_B_ENABLE             (1 << 31)

# define MGA2_VID12_B_CONV_ALL           3
# define MGA2_VID12_B_CONV_NON_INV       0
# define MGA2_VID12_B_CONV_INV           1
# define MGA2_VID12_B_CONV_DIRECT        2

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

#define	 MGA2_VID0_CLKCTRL25	0x000a0

#define MGA2_VID3_PWM0_CTRL	0x03080
/* PWB bits are common for PWM0 and PWM1 */
# define MGA2_VID3_B_PWMENABLE (1 << 31)
# define MGA2_VID3_B_PWMINVERT (1 << 30)
# define MGA2_VID3_B_PWMVALUE_OFFSET  0

#define MGA2_VID3_PWM0_PERIOD	0x03084
# define MGA2_VID3_B_PWMPRESCL_OFFSET 16
# define MGA2_VID3_B_PWMPERIOD_OFFSET 0

#define MGA2_VID3_PWM_PERIOD_MASK 0xffff
#define MGA2_VID3_PWM_REGS_SZ	0x10
#define MGA2_PWM_MAX_DIVISION	(1 << 16)
#define MGA2_PWM_MAX_CYCLE	(1 << 16)

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
#define	 MGA2_VID0_GPIO_MUX		0x00040
#define	 MGA2_VID0_GPIO_MUXSETRST	0x00044
#define	 MGA2_VID0_GPIO_PUP		0x00048
#define	 MGA2_VID0_GPIO_PUPSETRST	0x0004C
#define	 MGA2_VID0_GPIO_DIR		0x00050
#define	 MGA2_VID0_GPIO_DIRSETRST	0x00054


#define	 MGA2_VID0_GPIO_OUT		0x00058
# define	MGA2_VID0_GPIO_RSTPIN	(1 << 2)
# define	MGA2_VID0_GPIO_HTPLG	(1 << 4)
# define	MGA2_VID0_GPIO_MSEN	(1 << 5)

#define	 MGA2_VID0_GPIO_OUTSETRST	0x0005C
#define	 MGA2_VID0_GPIO_IN		0x00060

#define	 MGA2_VID3_GPIO_DIR		0x03050
#define	 MGA2_VID3_GPIO_OUT		0x03058
#define	 MGA2_VID3_GPIO_IN		0x03060



#define	 MGA2_INTENA		0x00000
#define	 MGA2_INTREQ		0x00004
#define	 MGA2_INTLEVEL		0x00008
#define	 MGA2_INTMODE		0x0000C

#	define MGA2_INT_B_SETRST (1U << 31)

#	define MGA2_INT_B_VGA0_V (1 << 0)
#	define MGA2_INT_B_VGA1_V (1 << 1)

#	define MGA2_INT_B_DC0_V (1 << 2)
#	define MGA2_INT_B_DC1_V (1 << 3)
#	define MGA2_INT_B_DC0_H (1 << 4)
#	define MGA2_INT_B_DC1_H (1 << 5)

#	define MGA2_INT_B_DC0_WLOAD (1 << 6)
#	define MGA2_INT_B_DC1_WLOAD (1 << 7)

#	define MGA2_INT_B_ROP2_IDLE     (1 << 8)
#	define MGA2_INT_B_ROP2_CANSTART (1 << 9)

#	define MGA2_INT_B_AUC (1 << 10)

#	define MGA2_INT_B_SOFTINT (1 << 11)

#	define MGA2_INT_B_DC0I2C   (1 << 30)
#	define MGA2_INT_B_DC1I2C   (1 << 29)

#	define MGA2_INT_B_V0DDCI2C (1 << 28)
#	define MGA2_INT_B_V1DDCI2C (1 << 27)
#	define MGA2_INT_B_V2DDCI2C (1 << 26)
#	define MGA2_INT_B_V3DDCI2C (1 << 25)

#	define MGA2_INT_B_V0TXI2C (1 << 24)
#	define MGA2_INT_B_V3TXI2C (1 << 23)

#	define MGA2_INT_B_V1HDMI     (1 << 22)
#	define MGA2_INT_B_V1HDMIWUP  (1 << 21)
#	define MGA2_INT_B_V2HDMI     (1 << 20)
#	define MGA2_INT_B_V2HDMIWUP  (1 << 19)

#	define MGA25_INT_B_DC0_V		(1 << 3)
#	define MGA25_INT_B_DC1_V		(1 << 4)
#	define MGA25_INT_B_DC2_V		(1 << 5)
#	define MGA25_INT_B_SOFTINT2		(1 << 16)
#	define MGA25_INT_B_SOFTINT		(1 << 17)
#	define MGA25_INT_B_V1HDMI		(1 << 24)
#	define MGA25_INT_B_V1HDMI_WAKEUP	(1 << 25)
#	define MGA25_INT_B_V2HDMI		(1 << 26)
#	define MGA25_INT_B_V2HDMI_WAKEUP	(1 << 27)
#	define MGA25_INT_B_HDA1		(1 << 28)
#	define MGA25_INT_B_HDA2		(1 << 29)


#define MGA2_6_VMMUX_OFFSETH	(0x03400 + 0x0104)
#define MGA2_6_FBMUX_OFFSETH	(0x03800 + 0x0104)

#endif	/*__MGA2_REGS_H__*/
