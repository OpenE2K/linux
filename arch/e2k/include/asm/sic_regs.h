/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef	_E2K_SIC_REGS_H_
#define	_E2K_SIC_REGS_H_

#include <linux/align.h>
#include <linux/types.h>

#include <asm/base_regs_types.h>


#define	E2K_SIC_ALIGN_RT_MSI	20	/* 1 Mb */

#define SIC_IO_LINKS_COUNT	2

/*
 * NBSR registers addresses (offsets in NBSR area)
 */

#define SIC_st_p	0x00

#define SIC_rt_ln	0x08
#define SIC_rt_lcfg0	0x10
#define SIC_rt_lcfg1	0x14
#define SIC_rt_lcfg2	0x18
#define SIC_rt_lcfg3	0x1c

#define SIC_rt_mhi0	0x20
#define SIC_rt_mhi1	0x24
#define SIC_rt_mhi2	0x28
#define SIC_rt_mhi3	0x2c
#define SIC_rt_mhi_nr(nr)	(0x20 + 4 * (nr))

#define SIC_rt_mlo0	0x30
#define SIC_rt_mlo1	0x34
#define SIC_rt_mlo2	0x38
#define SIC_rt_mlo3	0x3c
#define SIC_rt_mlo_nr(nr)	(0x30 + 4 * (nr))

#define SIC_rt_pcim0	0x40
#define SIC_rt_pcim1	0x44
#define SIC_rt_pcim2	0x48
#define SIC_rt_pcim3	0x4c

#define SIC_rt_pciio0	0x50
#define SIC_rt_pciio1	0x54
#define SIC_rt_pciio2	0x58
#define SIC_rt_pciio3	0x5c

#define SIC_rt_ioapic0	0x60
#define SIC_rt_ioapic1	0x64
#define SIC_rt_ioapic2	0x68
#define SIC_rt_ioapic3	0x6c

#define SIC_rt_pcimp_b0	0x70
#define SIC_rt_pcimp_b1	0x74
#define SIC_rt_pcimp_b2	0x78
#define SIC_rt_pcimp_b3	0x7c

#define SIC_rt_pcimp_e0	0x80
#define SIC_rt_pcimp_e1	0x84
#define SIC_rt_pcimp_e2	0x88
#define SIC_rt_pcimp_e3	0x8c


#define	SIC_rt_pcicfgb		0x90
#define SIC_rt_ioapicintb	0x94
#define	SIC_rt_pcicfged		0x98 /* for v7 e8v7 only */
#define	SIC_rt_vgamemed		0x9c /* >= v6, e8v7 only */
#define SIC_rt_vgamem_ext	0xa0 /* v7 */

#define SIC_rt_lapicintb	0xa0 /* <= v5 */

#define	SIC_rt_msi	0xb0	/* >= v6 */
#define	SIC_rt_msi_h	0xb4	/* >= v6 */

#define	SIC_st_ipl	0xe0	/* v7 */
#define	SIC_st_xmu	0xf0	/* v7 */

#define	SIC_st_core0	0x100
#define	SIC_st_core1	0x104
#define	SIC_st_core2	0x108
#define	SIC_st_core3	0x10c
#define	SIC_st_core4	0x110
#define	SIC_st_core5	0x114
#define	SIC_st_core6	0x118
#define	SIC_st_core7	0x11c
#define	SIC_st_core8	0x120
#define	SIC_st_core9	0x124
#define	SIC_st_core10	0x128
#define	SIC_st_core11	0x12c
#define	SIC_st_core12	0x130
#define	SIC_st_core13	0x134
#define	SIC_st_core14	0x138
#define	SIC_st_core15	0x13c
#define SIC_st_core(num) (0x100 + (num) * 4)

/* >= v7 registers */
#define SIC_rt_pcim0_xmu_l	0x220
#define SIC_rt_pcim0_xmu_a	0x224
#define SIC_rt_pcim0_xmu_b	0x228
#define SIC_rt_pcim0_xmu_c	0x22c
#define SIC_rt_pcim0_xmu_d	0x230

#define SIC_rt_pciio0_xmu_l	0x240
#define SIC_rt_pciio0_xmu_a	0x244
#define SIC_rt_pciio0_xmu_b	0x248
#define SIC_rt_pciio0_xmu_c	0x24c
#define SIC_rt_pciio0_xmu_d	0x250

#define SIC_rt_pcimp0_xmu_l_bgn	0x260
#define SIC_rt_pcimp0_xmu_a_bgn	0x264
#define SIC_rt_pcimp0_xmu_b_bgn	0x268
#define SIC_rt_pcimp0_xmu_c_bgn	0x26c
#define SIC_rt_pcimp0_xmu_d_bgn	0x270

#define SIC_rt_pcimp0_xmu_l_end	0x280
#define SIC_rt_pcimp0_xmu_a_end	0x284
#define SIC_rt_pcimp0_xmu_b_end	0x288
#define SIC_rt_pcimp0_xmu_c_end	0x28c
#define SIC_rt_pcimp0_xmu_d_end	0x290

#define SIC_rt_pcimp0_xmu_l_m32_bgn	0x2a0
#define SIC_rt_pcimp0_xmu_a_m32_bgn	0x2a4
#define SIC_rt_pcimp0_xmu_b_m32_bgn	0x2a8
#define SIC_rt_pcimp0_xmu_c_m32_bgn	0x2ac
#define SIC_rt_pcimp0_xmu_d_m32_bgn	0x2b0

#define SIC_rt_pcimp0_xmu_l_m32_end	0x2c0
#define SIC_rt_pcimp0_xmu_a_m32_end	0x2c4
#define SIC_rt_pcimp0_xmu_b_m32_end	0x2c8
#define SIC_rt_pcimp0_xmu_c_m32_end	0x2cc
#define SIC_rt_pcimp0_xmu_d_m32_end	0x2d0

/* end of >= v7 registers */

/* Power management */
#define SIC_pwr_mgr		0x280	/* <= v5 */
#define SIC_pwr_mgr1		0x284	/* <= v5 */

/* >= v6 registers */
/* Host Controller */
#define HC_CTRL			0x0340

/* HC monitors */
#define HC_MCR			0x360
#define HC_MID			0x364
#define HC_MAR0_LO		0x368
#define HC_MAR0_HI		0x36c
#define HC_MAR1_LO		0x370
#define HC_MAR1_HI		0x374
/* end v6 registers */

/* < v6 registers */

/* IOMMU */
#define SIC_iommu_ctrl		0x380
#define SIC_iommu_ba_lo		0x390
#define SIC_iommu_ba_hi		0x394
#define SIC_iommu_dtba_lo	0x398
#define SIC_iommu_dtba_hi	0x39c
#define SIC_iommu_flush		0x3a0
#define SIC_iommu_flushP	0x3a4
#define SIC_iommu_cmd_c_lo	0x3a0
#define SIC_iommu_cmd_c_hi	0x3a4
#define SIC_iommu_cmd_d_lo	0x3a8
#define SIC_iommu_cmd_d_hi	0x3ac
#define SIC_iommu_err		0x3b0 /* <= v5 */
#define SIC_iommu_err1		0x3b4 /* <= v5 */
/* >=v6 registers */
#define CIC_iommu_err_lo	0x3b0
#define CIC_iommu_err_hi	0x3b4
#define SIC_iommu_err_info_lo	0x3b8
#define SIC_iommu_err_info_hi	0x3bc
#define SIC_iommu_mcr		0x3c0
#define SIC_iommu_mid		0x3c4
#define SIC_iommu_mar0_lo	0x3c8
#define SIC_iommu_mar0_hi	0x3cc
#define SIC_iommu_mar1_lo	0x3d0
#define SIC_iommu_mar1_hi	0x3d4
/* >= v7 registers */
#define SIC_iommu_cmd_bar_lo	0x3d8
#define SIC_iommu_cmd_bar_hi	0x3dc
#define SIC_iommu_cmd_hpr	0x3e0
#define SIC_iommu_cmd_tpr	0x3e4
#define SIC_iommu_el_bar_lo	0x3e8
#define SIC_iommu_el_bar_hi	0x3ec
#define SIC_iommu_el_hpr	0x3f0
#define SIC_iommu_el_tpr	0x3f4

#define SIC_iommu_reg_base	SIC_iommu_ctrl
#define SIC_iommu_reg_size	0x0080
#define SIC_e2c3_iommu_nr	0x0007
#define SIC_embedded_iommu_base	0x5d00
#define	SIC_embedded_iommu_size	SIC_iommu_reg_size


/* MC */
#define SIC_MAX_MC_COUNT	E16C_SIC_MC_COUNT
#define SIC_MC_COUNT		(machine.sic_mc_count)
#define SIC_MC_BASE		0x400
#define SIC_MC_SIZE		(machine.sic_mc_size)

/* < v6 refisters */

#define SIC_mc0_ecc		0x400
#define SIC_mc1_ecc		0x440
#define SIC_mc2_ecc		0x480
#define SIC_mc3_ecc		0x4c0

#define SIC_mc0_opmb		0x414
#define SIC_mc1_opmb		0x454
#define SIC_mc2_opmb		0x494
#define SIC_mc3_opmb		0x4d4

#define SIC_mc0_cfg		0x418
#define SIC_mc1_cfg		0x458
#define SIC_mc2_cfg		0x498
#define SIC_mc3_cfg		0x4d8
/* >= v6 registers */
#define MC_CH			0x400
#define MC_CTL			0x404
#define MC_CFG			0x418
#define MC_PERF			0x41c
#define MC_OPMB			0x424
#define MC_PWR			0x430
#define MC_ECC			0x440
/* Use e2k suffix to avoid conflict with Radeon */
#define MC_STATUS_E2K		0x44c
#define MC_MON_CTL		0x450
#define MC_MON_CTR0		0x454
#define MC_MON_CTR1		0x458
#define MC_MON_CTRext		0x45c
/*  >=v7 registers */
#define MC_ECCDIAG		0x444
#define MCNA_CTRL		0x4c0
#define MCNA_INT		0x4c4
#define MCNA_DIAG_ADDR		0x4c8
#define MCNA_DIAG_DATA		0x4cc

#define MCNA_REG(reg) ((reg == MC_ECCDIAG) || ((reg >= MCNA_CTRL) && (reg <= MCNA_DIAG_DATA)))
/* end of MC */


#define SIC_sccfg		0xc00 /* <= v5 */
#define SIC_esclkr		0xc00 /* >= v7 */




/* IPCC */
#define SIC_IPCC_LINKS_COUNT	3
#define SIC_ipcc_csr1		0x604 /* <=v6 */
#define SIC_ipcc_csr2		0x644 /* <=v6 */
#define SIC_ipcc_csr3		0x684 /* <=v6 */
#define SIC_ipcc_str1		0x60c /* <=v6 */
#define SIC_ipcc_str2		0x64c /* <=v6 */
#define SIC_ipcc_str3		0x68c /* <=v6 */

/* IO link & RDMA . <= v5 */
#define	SIC_io_vid		0x700
#define	SIC_io_csr		0x704
#define	SIC_io_str		0x70c
#define	SIC_io_str_hi		0x72c
#define	SIC_rdma_vid		0x880
#define	SIC_rdma_cs		0x888
#define	SIC_iol_csr		0x900

/* v7 MHIO_* registers */
#define SIC_rt_mhio_mc		0x700
#define SIC_rt_mhio_cxl_a	0x704
#define SIC_rt_mhio_cxl_b	0x708
#define SIC_rt_mhio_cxl_c	0x70c
#define SIC_rt_mhio_cxl_d	0x710

#define SIC_rt_mhio_cxl_a_0	0x720
#define SIC_rt_mhio_cxl_a_1	0x724
#define SIC_rt_mhio_cxl_a_2	0x728
#define SIC_rt_mhio_cxl_a_3	0x726

#define SIC_rt_mhio_cxl_b_0	0x740
#define SIC_rt_mhio_cxl_b_1	0x744
#define SIC_rt_mhio_cxl_b_2	0x748
#define SIC_rt_mhio_cxl_b_3	0x746

#define SIC_rt_mhio_cxl_c_0	0x760
#define SIC_rt_mhio_cxl_c_1	0x764
#define SIC_rt_mhio_cxl_c_2	0x768
#define SIC_rt_mhio_cxl_c_3	0x766

#define SIC_rt_mhio_cxl_d_0	0x780
#define SIC_rt_mhio_cxl_d_1	0x784
#define SIC_rt_mhio_cxl_d_2	0x788
#define SIC_rt_mhio_cxl_d_3	0x786

/* Monitors. <= v5 */
#define SIC_sic_mcr		0xc30
#define SIC_sic_mar0_lo		0xc40
#define SIC_sic_mar0_hi		0xc44
#define SIC_sic_mar1_lo		0xc48
#define SIC_sic_mar1_hi		0xc4c

/* Interrupt register */
#define SIC_sic_int		0xc60 /* <=v5 */
#define SIC_xmu_int		0xc60 /* v6 */
#define SIC_xmu_l_int		0xc60 /* v7 */

#define SIC_xmu_l_int_m		0xc64 /* >=v6 */
#define SIC_xmu_l_la_ctl	0xc70 /* v7 */
#define SIC_xmu_l_hw		0xc80 /* >=v6 */
#define SIC_xmu_l_dda_lo	0xc88 /* >=v6 */
#define SIC_xmu_l_dda_hi	0xc8c /* >=v6 */

#define SIC_err_addr_lo		0xc68 /* <=v5 */
#define SIC_err_addr_hi		0xc6c /* <= v5 */
#define SIC_hw0			0xc80 /* <= v5 */
#define SIC_hw1			0xc84 /* <= v5 */
#define SIC_hw2			0xc88 /* <= v5 */
#define SIC_hw3			0xc8c /* <= v5 */

#define SIC_fuse_ram_addr	0xcc0 /* >=v6 */
#define SIC_fuse_ram_data	0xcc4 /* >=v6 */



/* HMU monitors, v6 only */
#define HMU_MIC		0xd00
#define HMU_MCR		0xd14
#define HMU0_INT	0xd40
#define HMU0_MAR0_LO	0xd44
#define HMU0_MAR0_HI	0xd48
#define HMU0_MAR1_LO	0xd4c
#define HMU0_MAR1_HI	0xd50
#define HMU1_INT	0xd70
#define HMU1_MAR0_LO	0xd74
#define HMU1_MAR0_HI	0xd78
#define HMU1_MAR1_LO	0xd7c
#define HMU1_MAR1_HI	0xd80
#define HMU2_INT	0xda0
#define HMU2_MAR0_LO	0xda4
#define HMU2_MAR0_HI	0xda8
#define HMU2_MAR1_LO	0xdac
#define HMU2_MAR1_HI	0xdb0
#define HMU3_INT	0xdd0
#define HMU3_MAR0_LO	0xdd4
#define HMU3_MAR0_HI	0xdd8
#define HMU3_MAR1_LO	0xddc
#define HMU3_MAR1_HI	0xde0

/* HA regs in v7 */
#define HA_BASC		0xd00 /* v7 */
#define HA_MCR		0xd14 /* v7 */

/* Local HA regs offsets */
#define LOC_HA_BASC(ha_bank) (0xd40 + (ha_bank << 2))
#define HA_INT		0
#define HA_MAR_LO(i)	(4 + 8 * (i))
#define HA_MAR_HI(i)	(8 + 8 * (i))

#define PMC_INFO			0x1000 /* v6+ only */
/* E12C/E16C/E2C3 Power Control System (PCS) registers
 * PMC_INFO = 0x1000 is added */
#define _PMC_TERM_CONV			0x8
#define _PMC_TERM_CTRL			0xc
#define _PMC_TERM_TS0			0x10
#define _PMC_TERM_TS1			0x14
#define _PMC_TERM_TS2			0x18
#define _PMC_TERM_TS3			0x1c
#define _PMC_TERM_TS4			0x20
#define _PMC_TERM_TS5			0x24
#define _PMC_TERM_TS6			0x28
#define _PMC_TERM_TS7			0x2c
#define _PMC_FREQ_CFG			0x100
#define _PMC_FREQ_STEPS			0x104
#define _PMC_FREQ_C2			0x108
#define _PMC_FREQ_BND			0x10c
#define _PMC_FREQ_CORE_FLOAT		0x110
#define _PMC_FREQ_OCN_FLOAT		0x114
#define _PMC_FREQ_CORE_TABLE0		0x120
#define _PMC_FREQ_CORE_TABLE1		0x124
#define _PMC_FREQ_CORE_TABLE2		0x128
#define _PMC_FREQ_CORE_TABLE3		0x12c
#define _PMC_FREQ_CORE_TABLE4		0x130
#define _PMC_FREQ_CORE_TABLE5		0x134
#define _PMC_FREQ_CORE_TABLE6		0x138
#define _PMC_FREQ_CORE_TABLE7		0x13c
#define _PMC_FREQ_OCN_TABLE0		0x140
#define _PMC_FREQ_OCN_TABLE1		0x144
#define _PMC_FREQ_OCN_TABLE2		0x148
#define _PMC_FREQ_OCN_TABLE3		0x14c
#define _PMC_FREQ_OCN_TABLE4		0x150
#define _PMC_FREQ_OCN_TABLE5		0x154
#define _PMC_FREQ_OCN_TABLE6		0x158
#define _PMC_FREQ_OCN_TABLE7		0x15c
#define _PMC_FREQ_CFG_OFFS_V7		0x300
#define _PMC_FREQ_STEPS_OFFS_V7		0x304
#define _PMC_FREQ_C2_OFFS_V7		0x308
#define _PMC_FREQ_BND_OFFS_V7		0x30c
#define _PMC_FREQ_OCN_MON_V7		0x380
#define _PMC_FREQ_OCN_CTRL_V7		0x384
#define _PMC_FREQ_OCN_MON		0x400
#define _PMC_FREQ_OCN_CTRL		0x404
#define _PMC_SYS_MON_0			0x500
#define _PMC_SYS_MON_1			0x504
#define _PMC_FAN_CFG			0x540
#define _PMC_FREQ_OCN_MON_OFFS_V7	0x800
#define _PMC_FREQ_OCN_CTRL_OFFS_V7	0x804
#define _PMC_UC_ENABLE_V7		0x860
#define _PMC_SYS_MON_0_OFFS_V7		0x900
#define _PMC_SYS_MON_1_OFFS_V7		0x904
#define _PMC_FAN_CFG_OFFS_V7		0x940
#define _PMC_FREQ_CORE_MON(n, is_v7)		(((is_v7) ? 0x400 : 0x200) + (n) * 0x10)
#define _PMC_FREQ_CORE_CTRL(n, is_v7)		(((is_v7) ? 0x404 : 0x204) + (n) * 0x10)
#define _PMC_FREQ_CORE_SLEEP(n, is_v7)	(((is_v7) ? 0x408 : 0x208) + (n) * 0x10)
#define _PMC_FREQ_GRAPHIC_MON(n, is_v7)	(((is_v7) ? 0x3c0 : 0x410) + (n) * 0x10)
#define _PMC_FREQ_GRAPHIC_CTRL(n, is_v7)	(((is_v7) ? 0x3c4 : 0x414) + (n) * 0x10)


#define PMC_TERM_CONV			(PMC_INFO + _PMC_TERM_CONV)
#define PMC_TERM_CTRL			(PMC_INFO + _PMC_TERM_CTRL)
#define PMC_TERM_TS0			(PMC_INFO + _PMC_TERM_TS0)
#define PMC_TERM_TS1			(PMC_INFO + _PMC_TERM_TS1)
#define PMC_TERM_TS2			(PMC_INFO + _PMC_TERM_TS2)
#define PMC_TERM_TS3			(PMC_INFO + _PMC_TERM_TS3)
#define PMC_TERM_TS4			(PMC_INFO + _PMC_TERM_TS4)
#define PMC_TERM_TS5			(PMC_INFO + _PMC_TERM_TS5)
#define PMC_TERM_TS6			(PMC_INFO + _PMC_TERM_TS6)
#define PMC_TERM_TS7			(PMC_INFO + _PMC_TERM_TS7)
#define PMC_FREQ_CFG			(PMC_INFO + _PMC_FREQ_CFG)
#define PMC_FREQ_STEPS			(PMC_INFO + _PMC_FREQ_STEPS)
#define PMC_FREQ_C2			(PMC_INFO + _PMC_FREQ_C2)
#define PMC_FREQ_BND			(PMC_INFO + _PMC_FREQ_BND)
#define PMC_FREQ_CORE_FLOAT		(PMC_INFO + _PMC_FREQ_CORE_FLOAT)
#define PMC_FREQ_OCN_FLOAT		(PMC_INFO + _PMC_FREQ_OCN_FLOAT)
#define PMC_FREQ_CORE_TABLE0		(PMC_INFO + _PMC_FREQ_CORE_TABLE0)
#define PMC_FREQ_CORE_TABLE1		(PMC_INFO + _PMC_FREQ_CORE_TABLE1)
#define PMC_FREQ_CORE_TABLE2		(PMC_INFO + _PMC_FREQ_CORE_TABLE2)
#define PMC_FREQ_CORE_TABLE3		(PMC_INFO + _PMC_FREQ_CORE_TABLE3)
#define PMC_FREQ_CORE_TABLE4		(PMC_INFO + _PMC_FREQ_CORE_TABLE4)
#define PMC_FREQ_CORE_TABLE5		(PMC_INFO + _PMC_FREQ_CORE_TABLE5)
#define PMC_FREQ_CORE_TABLE6		(PMC_INFO + _PMC_FREQ_CORE_TABLE6)
#define PMC_FREQ_CORE_TABLE7		(PMC_INFO + _PMC_FREQ_CORE_TABLE7)
#define PMC_FREQ_OCN_TABLE0		(PMC_INFO + _PMC_FREQ_OCN_TABLE0)
#define PMC_FREQ_OCN_TABLE1		(PMC_INFO + _PMC_FREQ_OCN_TABLE1)
#define PMC_FREQ_OCN_TABLE2		(PMC_INFO + _PMC_FREQ_OCN_TABLE2)
#define PMC_FREQ_OCN_TABLE3		(PMC_INFO + _PMC_FREQ_OCN_TABLE3)
#define PMC_FREQ_OCN_TABLE4		(PMC_INFO + _PMC_FREQ_OCN_TABLE4)
#define PMC_FREQ_OCN_TABLE5		(PMC_INFO + _PMC_FREQ_OCN_TABLE5)
#define PMC_FREQ_OCN_TABLE6		(PMC_INFO + _PMC_FREQ_OCN_TABLE6)
#define PMC_FREQ_OCN_TABLE7		(PMC_INFO + _PMC_FREQ_OCN_TABLE7)
#define PMC_FREQ_CORE_MON(n, is_v7)	(PMC_INFO + _PMC_FREQ_CORE_MON((n), (is_v7)))
#define PMC_FREQ_CORE_CTRL(n, is_v7)	(PMC_INFO + _PMC_FREQ_CORE_CTRL((n), (is_v7)))
#define PMC_FREQ_CORE_SLEEP(n, is_v7)	(PMC_INFO + _PMC_FREQ_CORE_SLEEP((n), (is_v7)))
#define PMC_FREQ_CFG_OFFS_V7		(PMC_INFO + _PMC_FREQ_CFG_OFFS_V7)
#define PMC_FREQ_STEPS_OFFS_V7		(PMC_INFO + _PMC_FREQ_STEPS_OFFS_V7)
#define PMC_FREQ_C2_OFFS_V7		(PMC_INFO + _PMC_FREQ_C2_OFFS_V7)
#define PMC_FREQ_BND_OFFS_V7		(PMC_INFO + _PMC_FREQ_BND_OFFS_V7)
#define PMC_FREQ_OCN_MON		(PMC_INFO + _PMC_FREQ_OCN_MON)
#define PMC_FREQ_OCN_CTRL		(PMC_INFO + _PMC_FREQ_OCN_CTRL)
#define PMC_FREQ_OCN_MON_V7		(PMC_INFO + _PMC_FREQ_OCN_MON_V7)
#define PMC_FREQ_OCN_CTRL_V7		(PMC_INFO + _PMC_FREQ_OCN_CTRL_V7)
#define PMC_FREQ_GRAPHIC_MON(n, is_v7)  (PMC_INFO + _PMC_FREQ_GRAPHIC_MON((n), (is_v7)))
#define PMC_FREQ_GRAPHIC_CTRL(n, is_v7) (PMC_INFO + _PMC_FREQ_GRAPHIC_CTRL((n), (is_v7)))
#define PMC_SYS_MON_0			(PMC_INFO + _PMC_SYS_MON_0)
#define PMC_SYS_MON_1			(PMC_INFO + _PMC_SYS_MON_1)
#define PMC_FAN_CFG			(PMC_INFO + _PMC_FAN_CFG)
#define PMC_FREQ_OCN_MON_OFFS_V7	(PMC_INFO + _PMC_FREQ_OCN_MON_OFFS_V7)
#define PMC_FREQ_OCN_CTRL_OFFS_V7	(PMC_INFO + _PMC_FREQ_OCN_CTRL_OFFS_V7)
#define PMC_UC_ENABLE_V7		(PMC_INFO + _PMC_UC_ENABLE_V7)
#define PMC_SYS_MON_0_OFFS_V7		(PMC_INFO + _PMC_SYS_MON_0_OFFS_V7)
#define PMC_SYS_MON_1_OFFS_V7		(PMC_INFO + _PMC_SYS_MON_1_OFFS_V7)
#define PMC_FAN_CFG_OFFS_V7		(PMC_INFO + _PMC_FAN_CFG_OFFS_V7)

static inline bool is_pmc_freq_core_mon(u64 reg_offset, bool is_v7)
{
	u64 max_regs = (is_v7) ? 64 : 16;
	u64 offset = reg_offset - PMC_FREQ_CORE_MON(0, is_v7);
	u64 n = offset / 0x10;

	return IS_ALIGNED(offset, 0x10) && n < max_regs;
}

static inline bool is_pmc_freq_core_ctrl(u64 reg_offset, bool is_v7)
{
	u64 max_regs = (is_v7) ? 64 : 16;
	u64 offset = reg_offset - PMC_FREQ_CORE_CTRL(0, is_v7);
	u64 n = offset / 0x10;

	return IS_ALIGNED(offset, 0x10) && n < max_regs;
}

static inline bool is_pmc_freq_core_sleep(u64 reg_offset, bool is_v7)
{
	u64 max_regs = (is_v7) ? 64 : 16;
	u64 offset = reg_offset - PMC_FREQ_CORE_SLEEP(0, is_v7);
	u64 n = offset / 0x10;

	return IS_ALIGNED(offset, 0x10) && n < max_regs;
}

static inline bool is_pmc_freq_graphic_mon(u64 reg_offset, bool is_v7)
{
	u64 offset = reg_offset - PMC_FREQ_GRAPHIC_MON(0, is_v7);
	u64 n = offset / 0x10;

	return IS_ALIGNED(offset, 0x10) && n < 4;
}

static inline bool is_pmc_freq_graphic_ctrl(u64 reg_offset, bool is_v7)
{
	u64 offset = reg_offset - PMC_FREQ_GRAPHIC_CTRL(0, is_v7);
	u64 n = offset / 0x10;

	return IS_ALIGNED(offset, 0x10) && n < 4;
}

/* L3 global regs */
#define L3_BASC		0x300c
#define L3_IMSK		0x3024
#define L3_PMON_UCTL	0x3050
#define L3_PMON_FLT0	0x3054
#define L3_PMON_FLT1	0x3058
#define L3_PMON_CTL0_V6	0x3060
#define L3_PMON_CTL0_V7	0x305c
#define L3_PMON_CTL1_V6	0x3064
#define L3_PMON_CTL1_V7	0x3060
#define L3_BASR(i)	(0x3100 + ((i) << 2))

/* L3 local regs */
#define L3_INT			0
#define L3_ECC			0x04
#define L3_PMON_CNT0_LO		0x10
#define L3_PMON_CNT0_HI		0x14
#define L3_PMON_CNT1_LO		0x18
#define L3_PMON_CNT1_HI		0x1c
#define L3_EMRG0                0x40 /* >= v7 */
#define L3_EMRG1                0x44 /* >= v7 */
#define L3_EMRG2                0x48 /* >= v7 */
#define L3_EMRG3                0x4c /* >= v7 */

/* OCN regs */
#define OCN_MIL		0x3804
#define OCN_L3EN0	0x3810
#define OCN_L3EN1	0x3814
#define OCN_LASC	0x3840
#define OCN_LASR(i)	(0x3a00 + ((i) << 2))
#define OCN_PAR(i)	(0 + ((i) << 2))


/* Additional IOMMU monitors - e2c3, e8v7 only.
 * EDBC_IOMMU_* registers are used only to broadcast
 * writing into ED{26-31}_IOMMU_* registers. */
#define EDBC_IOMMU_CTRL		0x5080
#define EDBC_IOMMU_BA_LO	0x5090
#define EDBC_IOMMU_BA_HI	0x5094
#define EDBC_IOMMU_DTBA_LO	0x5098
#define EDBC_IOMMU_DTBA_HI	0x509c
#define EDBC_IOMMU_CMD_C_LO	0x50a0
#define EDBC_IOMMU_CMD_C_HI	0x50a4
#define EDBC_IOMMU_ERR		0x50b0
#define EDBC_IOMMU_ERR1		0x50b4
#define EDBC_IOMMU_ERR_INFO_LO	0x50b8
#define EDBC_IOMMU_ERR_INFO_HI	0x50bc
#define EDBC_IOMMU_MCR		0x50c0
#define EDBC_IOMMU_MID		0x50c4
#define EDBC_IOMMU_MAR0_LO	0x50c8
#define EDBC_IOMMU_MAR0_HI	0x50cc
#define EDBC_IOMMU_MAR1_LO	0x50d0
#define EDBC_IOMMU_MAR1_HI	0x50d4
#define ED26_IOMMU_MCR		0x5d40
#define ED26_IOMMU_MID		0x5d44
#define ED26_IOMMU_MAR0_LO	0x5d48
#define ED26_IOMMU_MAR0_HI	0x5d4c
#define ED26_IOMMU_MAR1_LO	0x5d50
#define ED26_IOMMU_MAR1_HI	0x5d54
#define ED27_IOMMU_MCR		0x5dc0
#define ED27_IOMMU_MID		0x5dc4
#define ED27_IOMMU_MAR0_LO	0x5dc8
#define ED27_IOMMU_MAR0_HI	0x5dcc
#define ED27_IOMMU_MAR1_LO	0x5dd0
#define ED27_IOMMU_MAR1_HI	0x5dd4
#define ED28_IOMMU_MCR		0x5e40
#define ED28_IOMMU_MID		0x5e44
#define ED28_IOMMU_MAR0_LO	0x5e48
#define ED28_IOMMU_MAR0_HI	0x5e4c
#define ED28_IOMMU_MAR1_LO	0x5e50
#define ED28_IOMMU_MAR1_HI	0x5e54
#define ED29_IOMMU_MCR		0x5ec0
#define ED29_IOMMU_MID		0x5ec4
#define ED29_IOMMU_MAR0_LO	0x5ec8
#define ED29_IOMMU_MAR0_HI	0x5ecc
#define ED29_IOMMU_MAR1_LO	0x5ed0
#define ED29_IOMMU_MAR1_HI	0x5ed4
#define ED30_IOMMU_MCR		0x5f40
#define ED30_IOMMU_MID		0x5f44
#define ED30_IOMMU_MAR0_LO	0x5f48
#define ED30_IOMMU_MAR0_HI	0x5f4c
#define ED30_IOMMU_MAR1_LO	0x5f50
#define ED30_IOMMU_MAR1_HI	0x5f54
#define ED31_IOMMU_MCR		0x5fc0
#define ED31_IOMMU_MID		0x5fc4
#define ED31_IOMMU_MAR0_LO	0x5fc8
#define ED31_IOMMU_MAR0_HI	0x5fcc
#define ED31_IOMMU_MAR1_LO	0x5fd0
#define ED31_IOMMU_MAR1_HI	0x5fd4


/* PREPIC, >=v6 */
#define	SIC_prepic_version	0x8000
#define	SIC_prepic_ctrl		0x8010
#define	SIC_prepic_id		0x8020
#define	SIC_prepic_ctrl2	0x8030
#define	SIC_prepic_err_stat	0x8040
#define	SIC_prepic_err_msg_lo	0x8050
#define	SIC_prepic_err_msg_hi	0x8054
#define	SIC_prepic_err_int	0x8060
#define	SIC_prepic_mcr		0x8070
#define	SIC_prepic_mid		0x8074
#define	SIC_prepic_mar0_lo	0x8080
#define	SIC_prepic_mar0_hi	0x8084
#define	SIC_prepic_mar1_lo	0x8090
#define	SIC_prepic_mar1_hi	0x8094
#define	SIC_prepic_linp0	0x8c00
#define	SIC_prepic_linp1	0x8c04
#define	SIC_prepic_linp2	0x8c08
#define	SIC_prepic_linp3	0x8c0c
#define	SIC_prepic_linp4	0x8c10
#define	SIC_prepic_linp5	0x8c14
#define	SIC_prepic_linp6	0x8c18
#define	SIC_prepic_linp7	0x8c1c
#define	SIC_prepic_linp8	0x8c20
#define	SIC_prepic_linp9	0x8c24
#define	SIC_prepic_linp10	0x8c28
#define	SIC_prepic_linp11	0x8c2c
#define	SIC_prepic_linp12	0x8c30
#define	SIC_prepic_linp13	0x8c34
#define	SIC_prepic_linp14	0x8c38
#define	SIC_prepic_linp15	0x8c3c


/* Host Controller, v7 */
#define SIC_xmu_a_hc_ctrl	0xa340
#define SIC_xmu_b_hc_ctrl	0xb340
#define SIC_xmu_c_hc_ctrl	0xc340
#define SIC_xmu_d_hc_ctrl	0xd340

#define HC_CTRL_DCAE	BIT(7)
#define HC_CTRL_WL3STE	BIT(15)

/* PMC_FREQ_CORE_0_SLEEP fields: */
typedef union {
	struct {
		u32 cmd			: 3;
		u32 pad1		: 13;
		u32 status		: 3;
		u32 pad2		: 8;
		u32 ctrl_enable		: 1;
		u32 alter_disable	: 1;
		u32 bfs_bypass		: 1;
		u32 pin_en		: 1;
		u32 pad3		: 1;
	};
	e2k_reg_t;
} freq_core_sleep_t;

/* PMC_FREQ_CORE_0_MON fields: */
typedef union {
	struct {
		u32 divF_curr		: 6;
		u32 divF_target		: 6;
		u32 divF_limit_hi	: 6;
		u32 divF_limit_lo	: 6;
		u32 divF_init		: 6;
		u32 bfs_bypass		: 1;
		u32			: 1;
	};
	e2k_reg_t;
} freq_core_mon_t;

/* PMC_FREQ_CORE_0_CTRL fields: */
typedef union {
	struct {
		u32 enable		: 1;
		u32 mode		: 3;
		u32 progr_divF		: 6;
		u32 progr_divF_max	: 6;
		u32 decr_dsbl		: 1;
		u32 pin_en		: 1;
		u32 clk_en		: 1;
		u32 log_en		: 1;
		u32 sleep_c2		: 1;
		u32 w_trap		: 1;
		u32 ev_term		: 1;
		u32 mon_Fmax		: 1;
		u32 divF_curr		: 6;
		u32 bfs_bypass		: 1;
		u32 rmwen		: 1;
	} v6;
	struct {
		u32 enable		: 1;
		u32 progr_limits_en	: 1;
		u32 rsv1		: 2;
		u32 progr_divF		: 6;
		u32 progr_divF_max	: 6;
		u32 decr_dsbl		: 1;
		u32 rsv2		: 5;
		u32 ev_term		: 1;
		u32 mon_Fmax		: 1;
		u32 divF_curr		: 6;
		u32 bfs_bypass		: 1;
		u32 rmwen		: 1;
	} v7;
	u32 word;
} freq_core_ctrl_t;

/* PMC_SYS_MON_1 fields: */
typedef union {
	struct {
		u32 machine_gen_alert		: 1;
		u32 machine_pwr_alert		: 1;
		u32 cpu_pwr_alert		: 1;
		u32 mc47_pwr_alert		: 1;
		u32 mc03_pwr_alert		: 1;
		u32 mc47_dimm_event		: 1;
		u32 mc03_dimm_event		: 1;
		u32				: 2;
		u32 mc7_fault			: 1;
		u32 mc6_fault			: 1;
		u32 mc5_fault			: 1;
		u32 mc4_fault			: 1;
		u32 mc3_fault			: 1;
		u32 mc2_fault			: 1;
		u32 mc1_fault			: 1;
		u32 mc0_fault			: 1;
		u32 cpu_fault			: 1;
		u32 pin_sataeth_config		: 1;
		u32 pin_iplc_pe_pre_det		: 2;
		u32 pin_iplc_pe_config		: 2;
		u32 pin_ipla_flip_en		: 1;
		u32 pin_iowl_pe_pre_det		: 4;
		u32 pin_iowl_pe_config		: 2;
		u32 pin_efuse_mode		: 2;
	};
	e2k_reg_t;
} sys_mon_1_t;

/* E8C2 Power Control System (PCS) registers */

#define SIC_pcs_ctrl0		0x0cb0
#define SIC_pcs_ctrl1		0x0cb4
#define SIC_pcs_ctrl2		0x0cb8
#define SIC_pcs_ctrl3		0x0cbc
#define SIC_pcs_ctrl4		0x0cc0
#define SIC_pcs_ctrl5		0x0cc4
#define SIC_pcs_ctrl6		0x0cc8
#define SIC_pcs_ctrl7		0x0ccc
#define SIC_pcs_ctrl8		0x0cd0
#define SIC_pcs_ctrl9		0x0cd4

/* PCS_CTRL1 fields: */
typedef union {
	struct {
		u32 pcs_mode	: 4;
		u32 n_fprogr	: 6;
		u32 n_fmin	: 6;
		u32 n_fminmc	: 6;
		u32 n		: 6;
		u32		: 4;
	};
	u32 word;
} pcs_ctrl1_t;

 /* PCS_CTRL2 fields E8C */
typedef union {
	struct {
		u32 t_fatal_fract	: 3;
		u32 t_fatal_int		: 9;
		u32 time_const		: 8;
		u32			: 12;
	};
	u32 word;
} pcs_ctrl2_e8c_t;

/* PCS_CTRL2 fields E8C2 */
typedef union {
	struct {
		u32 t_work_min		: 9;
		u32 t_work_max		: 9;
		u32 t_fatal		: 9;
		u32 t_period		: 3;
		u32			: 2;
	};
	u32 word;
} pcs_ctrl2_e8c2_t;

/* PCS_CTRL3 fields: */
typedef union {
	struct {
		u32 n_fpin	    : 6;
		u32		    : 2;
		u32 bfs_freq	    : 4;
		u32 pll_bw	    : 3;
		u32		    : 1;
		u32 pll_mode	    : 3;
		u32		    : 1;
		u32 iol_bitrate	    : 3;
		u32		    : 1;
		u32 ipl_bitrate	    : 3;
		u32		    : 1;
		u32 l_equaliz	    : 1;
		u32 l_preemph	    : 1;
		u32 bfs_adj_dsbl    : 1;
		u32		    : 1;
	};
	u32 word;
} pcs_ctrl3_t;

/* Cache L3 */
#define	SIC_l3_ctrl		0x3000
#define	SIC_l3_serv		0x3004
#define	SIC_l3_diag_ac		0x3008
#define	SIC_l3_bnda		0x300c
#define	SIC_l3_bndb		0x3010
#define	SIC_l3_bndc		0x3014
#define	SIC_l3_seal		0x3018
#define	SIC_l3_l3tl		0x301c
#define	SIC_l3_emrg		0x3020
/* bank #0 */
#define	SIC_l3_b0_diag_dw	0x3100
#define	SIC_l3_b0_eccd_ld	0x3108
#define	SIC_l3_b0_eccd_dm	0x310c
#define	SIC_l3_b0_eerr		0x3110
#define	SIC_l3_b0_bist0		0x3114
#define	SIC_l3_b0_bist1		0x3118
#define	SIC_l3_b0_bist2		0x311c
#define	SIC_l3_b0_emrg_r0	0x3120
#define	SIC_l3_b0_emrg_r1	0x3124
/* bank #1 */
#define	SIC_l3_b1_diag_dw	0x3140
#define	SIC_l3_b1_eccd_ld	0x3148
#define	SIC_l3_b1_eccd_dm	0x314c
#define	SIC_l3_b1_eerr		0x3150
#define	SIC_l3_b1_bist0		0x3154
#define	SIC_l3_b1_bist1		0x3158
#define	SIC_l3_b1_bist2		0x315c
#define	SIC_l3_b1_emrg_r0	0x3160
#define	SIC_l3_b1_emrg_r1	0x3164
/* bank #2 */
#define	SIC_l3_b2_diag_dw	0x3180
#define	SIC_l3_b2_eccd_ld	0x3188
#define	SIC_l3_b2_eccd_dm	0x318c
#define	SIC_l3_b2_eerr		0x3190
#define	SIC_l3_b2_bist0		0x3194
#define	SIC_l3_b2_bist1		0x3198
#define	SIC_l3_b2_bist2		0x319c
#define	SIC_l3_b2_emrg_r0	0x31a0
#define	SIC_l3_b2_emrg_r1	0x31a4
/* bank #3 */
#define	SIC_l3_b3_diag_dw	0x31c0
#define	SIC_l3_b3_eccd_ld	0x31c8
#define	SIC_l3_b3_eccd_dm	0x31cc
#define	SIC_l3_b3_eerr		0x31d0
#define	SIC_l3_b3_bist0		0x31d4
#define	SIC_l3_b3_bist1		0x31d8
#define	SIC_l3_b3_bist2		0x31dc
#define	SIC_l3_b3_emrg_r0	0x31e0
#define	SIC_l3_b3_emrg_r1	0x31e4
/* bank #4 */
#define	SIC_l3_b4_diag_dw	0x3200
#define	SIC_l3_b4_eccd_ld	0x3208
#define	SIC_l3_b4_eccd_dm	0x320c
#define	SIC_l3_b4_eerr		0x3210
#define	SIC_l3_b4_bist0		0x3214
#define	SIC_l3_b4_bist1		0x3218
#define	SIC_l3_b4_bist2		0x321c
#define	SIC_l3_b4_emrg_r0	0x3220
#define	SIC_l3_b4_emrg_r1	0x3224
/* bank #5 */
#define	SIC_l3_b5_diag_dw	0x3240
#define	SIC_l3_b5_eccd_ld	0x3248
#define	SIC_l3_b5_eccd_dm	0x324c
#define	SIC_l3_b5_eerr		0x3250
#define	SIC_l3_b5_bist0		0x3254
#define	SIC_l3_b5_bist1		0x3258
#define	SIC_l3_b5_bist2		0x325c
#define	SIC_l3_b5_emrg_r0	0x3260
#define	SIC_l3_b5_emrg_r1	0x3264
/* bank #6 */
#define	SIC_l3_b6_diag_dw	0x3280
#define	SIC_l3_b6_eccd_ld	0x3288
#define	SIC_l3_b6_eccd_dm	0x328c
#define	SIC_l3_b6_eerr		0x3290
#define	SIC_l3_b6_bist0		0x3294
#define	SIC_l3_b6_bist1		0x3298
#define	SIC_l3_b6_bist2		0x329c
#define	SIC_l3_b6_emrg_r0	0x32a0
#define	SIC_l3_b6_emrg_r1	0x32a4
/* bank #7 */
#define	SIC_l3_b7_diag_dw	0x32c0
#define	SIC_l3_b7_eccd_ld	0x32c8
#define	SIC_l3_b7_eccd_dm	0x32cc
#define	SIC_l3_b7_eerr		0x32d0
#define	SIC_l3_b7_bist0		0x32d4
#define	SIC_l3_b7_bist1		0x32d8
#define	SIC_l3_b7_bist2		0x32dc
#define	SIC_l3_b7_emrg_r0	0x32e0
#define	SIC_l3_b7_emrg_r1	0x32e4

/* Host Controller */
#define	SIC_hc_mcr	0x360
#define	SIC_hc_mid	0x364
#define	SIC_hc_mar0_lo	0x368
#define	SIC_hc_mar0_hi	0x36c
#define	SIC_hc_mar1_lo	0x370
#define	SIC_hc_mar1_hi	0x374
#define	SIC_hc_ioapic_eoi	0x37c

/* Binary compiler Memory protection registers */
#define	BC_MM_CTRL		0x0800
#define	BC_MM_MLO_LB		0x0808
#define	BC_MM_MLO_HB		0x080c
#define	BC_MM_MHI_BASE		0x0810
#define	BC_MM_MHI_BASE_H	0x0814
#define	BC_MM_MHI_MASK		0x0818
#define	BC_MM_MHI_MASK_H	0x081c
#define	BC_MM_MHI_LB		0x0820
#define	BC_MM_MHI_LB_H		0x0824
#define	BC_MM_MHI_HB		0x0828
#define	BC_MM_MHI_HB_H		0x082c
#define	BC_MP_CTRL		0x0830
#define	BC_MP_STAT		0x0834
#define	BC_MP_T_BASE		0x0838
#define	BC_MP_T_BASE_H		0x083c
#define	BC_MP_T_H_BASE		0x0840
#define	BC_MP_T_H_BASE_H	0x0844
#define	BC_MP_T_HB		0x0848
#define	BC_MP_T_H_LB		0x0850
#define	BC_MP_T_H_LB_H		0x0854
#define	BC_MP_T_H_HB		0x0858
#define	BC_MP_T_H_HB_H		0x085c
#define	BC_MP_T_CORR		0x0860
#define	BC_MP_T_CORR_H		0x0864
#define	BC_MP_B_BASE		0x0868
#define	BC_MP_B_BASE_H		0x086c
#define	BC_MP_B_HB		0x0870
#define	BC_MP_B_PUT		0x0874
#define	BC_MP_B_GET		0x0878
#define	BC_MM_REG_END		(BC_MP_B_GET + 4)

#define	BC_MM_REG_BASE		BC_MM_CTRL
#define	BC_MM_REG_SIZE		(BC_MM_REG_END - BC_MM_REG_BASE)
#define	BC_MM_REG_NUM		(BC_MM_REG_SIZE / 4)

#define EFUSE_RAM_ADDR          0x0cc0
#define EFUSE_RAM_DATA          0x0cc4
#define EFUSE_RAM_LINES         256

/*
 *   Read/Write RT_LCFGj Regs
 */
#define E2S_CLN_BITS	4	/* 4 bits - cluster # */
#define E8C_CLN_BITS	2	/* 2 bits - cluster # */

#if CONFIG_CPU_ISET_MIN < 4
# define E2K_MAX_CL_NUM	((1 << E2S_CLN_BITS) - 1)
#elif CONFIG_CPU_ISET_MIN == 4
# define E2K_MAX_CL_NUM	((1 << E8C_CLN_BITS) - 1)
#else /* iset >= 5 : field 'cln' is unused */
# define E2K_MAX_CL_NUM	0
#endif

/* SCCFG */
#define SIC_sccfg	0xc00

typedef union {			/* Structure of lower word */
	struct {
		u32 vp		: 1;	/* [0] */
		u32 vb		: 1;	/* [1] */
		u32 vics	: 1;	/* [2] */
		u32 vio		: 1;	/* [3] */
		u32 pln		: 2;	/* [5:4] */
	};
	struct {
		u32		: 6;
		u32 cln		: 4;
	} e2s;
	struct {
		u32		: 6;
		u32 cln		: 2;
	} e8c;
	e2k_reg_t;
} e2k_rt_lcfg_t;


/*
 *   Read/Write RT_PCIIOj Regs
 */
typedef union {
	struct {
		u32		: 12;	/* [11:0] */
		u32 bgn		: 4;	/* [15:12] */
		u32		: 12;	/* [27:16] */
		u32 end		: 4;	/* [31:28] */
	};
	e2k_reg_t;
} e2k_rt_pciio_t;

typedef union {
	struct {
		u32 bgn		: 8;	/* [ 7: 0] */
		u32		: 8;	/* [15: 8] */
		u32 end		: 8;	/* [23:16] */
		u32		: 8;	/* [31:24] */
	};
	e2k_reg_t;
} e2k_rt_pciio_v7_t;
typedef e2k_rt_pciio_v7_t	rt_pciio_v7_t;	/* short alias */

#define	E2K_SIC_ALIGN_RT_PCIIO	12	/* 4 Kb */
#define	E2K_SIC_SIZE_RT_PCIIO	(1 << E2K_SIC_ALIGN_RT_PCIIO)

/*
 *   Read/Write RT_PCIMj Regs
 */
typedef union {
	struct {
		u32		: 11;	/* [10:0] */
		u32 bgn		: 5;	/* [15:11] */
		u32		: 11;	/* [26:16] */
		u32 end		: 5;	/* [31:27] */
	};
	e2k_reg_t;
} e2k_rt_pcim_t;

#define	E2K_SIC_ALIGN_RT_PCIM	27	/* 128 Mb */
#define	E2K_SIC_SIZE_RT_PCIM	(1 << E2K_SIC_ALIGN_RT_PCIM)

/*
 *   Read/Write RT_PCIMPj Regs
 */
typedef union {
	u32 bgn;		/* [PA_MSB: 0] */
	u32 end;		/* [PA_MSB: 0] */
	e2k_reg_t;
} e2k_rt_pcimp_t;

#define	E2K_SIC_ALIGN_RT_PCIMP	27	/* 128 Mb */
#define	E2K_SIC_SIZE_RT_PCIMP	(1 << E2K_SIC_ALIGN_RT_PCIMP)

/*
 *   Read/Write RT_PCICFGB Reg
 */
typedef union {
	struct {
		u32		: 3;		/* [2:0] */
		u32 bgn		: 18;	/* [20:3] */
		u32		: 11;	/* [31:21] */
	};
	e2k_reg_t;
} e2k_rt_pcicfgb_t;

#define	E2K_SIC_ALIGN_RT_PCICFGB	28	/* 256 Mb */
#define	E2K_SIC_SIZE_RT_PCICFGB		(1 << E2K_SIC_ALIGN_RT_PCICFGB)

typedef union {
	struct {
		u32 bgn		: 16;	/* [16:0] */
		u32		: 16;	/* [31:17] */
	};
	e2k_reg_t;
} e2k_rt_pcicfg_bgn_t;

#define	E2K_SIC_ALIGN_RT_PCICFG_BGN	32	/* 4 Gb */
#define	E2K_SIC_SIZE_RT_PCICFG_BGN	(1 << E2K_SIC_ALIGN_RT_PCICFG_BGN_V7)

/*
 *   Read/Write RT_MLOj Regs
 */
typedef union {
	struct {
		u32		: 11;	/* [10:0] */
		u32 bgn		: 5;	/* [15:11] */
		u32		: 11;	/* [26:16] */
		u32 end		: 5;	/* [31:27] */
	};
	e2k_reg_t;
} e2k_rt_mlo_t;

#define	E2K_RT_MLO_BGN_SHIFT	11
#define	E2k_RT_MLO_END_SHIFT	27
#define	E2K_SIC_ALIGN_RT_MLO	27	/* 128 Mb */
#define	E2K_SIC_SIZE_RT_MLO	(1 << E2K_SIC_ALIGN_RT_MLO)

/* memory *bank minimum size, so base address of bank align */
#define	E2K_SIC_MIN_MEMORY_BANK	(256 * 1024 * 1024)	/* 256 Mb */

/*
 *   Read/Write RT_MHIj Regs
 */
typedef union {
	struct {
		u16 bgn;
		u16 end;
	};
	e2k_reg_t;
} e2k_rt_mhi_t;

#define	E2K_SIC_ALIGN_RT_MHI	32	/* 4 Gb */
#define	E2K_SIC_SIZE_RT_MHI	(1UL << E2K_SIC_ALIGN_RT_MHI)

/*
 *   Read/Write RT_MHI0_MC Regs
 */
typedef union {
	struct {
		u16 bgn;
		u16 end;
	};
	e2k_reg_t;
} e2k_rt_mhio_mc_t;

/*
 *   Read/Write RT_IOAPICj Regs
 */
typedef union {
	struct {
		u32		: 12;	/* [11:0] */
		u32 bgn		: 9;	/* [20:12] */
		u32		: 11;	/* [31:21] */
	};
	e2k_reg_t;
} e2k_rt_ioapic_t;

#define	E2K_SIC_ALIGN_RT_IOAPIC	12	/* 4 Kb */
#define	E2K_SIC_SIZE_RT_IOAPIC	(1 << E2K_SIC_ALIGN_RT_IOAPIC)
#define	E2K_SIC_IOAPIC_SIZE	E2K_SIC_SIZE_RT_IOAPIC
#define	E2K_SIC_IOAPIC_FIX_ADDR_SHIFT	21
#define	E2K_SIC_IOAPIC_FIX_ADDR_MASK	\
		~((1UL << E2K_SIC_IOAPIC_FIX_ADDR_SHIFT) - 1)

/*
 *   Read/Write RT_MSI Regs
 */

typedef union {			/* Structure of lower word */
	struct {
		u32		:E2K_SIC_ALIGN_RT_MSI;
		u32 bgn		:(32 - E2K_SIC_ALIGN_RT_MSI);
	};
	e2k_reg_t;
} e2k_rt_msi_t;

typedef union {			/* Structure of higher word */
	u32 bgn;		/* as fields */
	e2k_reg_t;		/* as entire register */
} e2k_rt_msi_h_t;

#define	E2K_SIC_SIZE_RT_MSI	(1 << E2K_SIC_ALIGN_RT_MSI)
#define	E2K_RT_MSI_ISA_BASE	0x120000000UL	/* Default RT_MSI, as defined by v6 ISA */
#define	E2K_RT_MSI_DEFAULT_BASE	0xf8000000UL	/* Some devices don't support 64-bit MSI addr */

/*
 *   Read/Write ST_P Regs
 */
typedef union {
	struct {
		u32 type	: 4;	/* [3:0] */
		u32 id		: 8;	/* [11:4] */
		u32 pn		: 8;	/* [19:12] */
		u32 coh_on	: 1;	/* [20] */
		u32 pl_val	: 3;	/* [23:21] */
		u32 mlc		: 1;	/* [24] */
		u32		: 7;	/* [31:25] */
	};
	e2k_reg_t;
} e2k_st_p_t;

/*
 *   ST_CORE core state register
 */
typedef union {
	struct {
		u32 val		: 1;	/* [0] */
		u32 wait_init	: 1;	/* [1] */
		u32 wait_trap	: 1;	/* [2] */
		u32 stop_dbg	: 1;	/* [3] */
		u32 clk_off	: 1;	/* [4] */
		u32 pmc_rst	: 1;	/* E1C */
		u32		: 26;	/* [31:5] */
	};
	e2k_reg_t;
} e2k_st_core_t;

/*
 * ST_XMU eXternal Memory Unit state register
 */
typedef union {
	struct {
		/* interprocessor links availability */
		u32 en_A	: 1;
		u32 en_B	: 1;
		u32 en_C	: 1;
		u32 en_D	: 1;

		u32		: 4;

		/* CXL availability */
		u32 vect_A	: 1;
		u32 vect_B	: 1;
		u32 vect_C	: 1;
		u32 vect_D	: 1;
	};
	e2k_reg_t;
} e2k_st_xmu_t;

/*
 * ST_IPL InterProcessor Links register
 */
typedef union {
	struct {
		/* interprocessor links availability
		 * (initialized by hardware from ST_XMU) */
		u32 en_A	: 1;
		u32 en_B	: 1;
		u32 en_C	: 1;
		u32 en_D	: 1;

		u32		: 4;

		/* CXL direction (set for Root Complex) */
		u32 type_A	: 1;
		u32 type_B	: 1;
		u32 type_C	: 1;
		u32 type_D	: 1;
	};
	e2k_reg_t;
} e2k_st_ipl_t;

/*
 *   IO Link control state register
 */
typedef union {
	struct {
		u32 mode	: 1;	/* [0] */
		u32 abtype	: 7;	/* [7:1] */
		u32		: 24;	/* [31:8] */
	};
	e2k_reg_t;
} e2k_iol_csr_t;

#define	IOHUB_IOL_MODE		1	/* controller is IO HUB */
#define	RDMA_IOL_MODE		0	/* controller is RDMA */
#define	IOHUB_ONLY_IOL_ABTYPE	1	/* abonent has only IO HUB */
					/* controller */
#define	RDMA_ONLY_IOL_ABTYPE	2	/* abonent has only RDMA */
					/* controller */
#define	RDMA_IOHUB_IOL_ABTYPE	3	/* abonent has RDMA and */
					/* IO HUB controller */

/*
 *   IO channel control/status register
 */
typedef union {
	struct {
		u32 srst	: 1;	/* [0] */
		u32		: 3;	/* [3:1] */
		u32 bsy_ie	: 1;	/* [4] */
		u32 err_ie	: 1;	/* [5] */
		u32 to_ie	: 1;	/* [6] */
		u32 lsc_ie	: 1;	/* [7] */
		u32		: 4;	/* [11:8] */
		u32 bsy_ev	: 1;	/* [12] */
		u32 err_ev	: 1;	/* [13] */
		u32 to_ev	: 1;	/* [14] */
		u32 lsc_ev	: 1;	/* [15] */
		u32		: 14;	/* [29:16] */
		u32 link_tu	: 1;	/* [30] */
		u32 ch_on	: 1;	/* [31] */
	};
	e2k_reg_t;
} e2k_io_csr_t;

#define	IO_IS_ON_IO_CSR		1		/* IO controller is ready */
						/* and online */
/*
 *   IO channel statistic register
 */
typedef union {
	struct {
		u32 rc		: 24;	/* [23:0] */
		u32 rcol	: 1;	/* [24] */
		u32		: 4;	/* [28:25] */
		u32 bsy_rce	: 1;	/* [29] */
		u32 err_rce	: 1;	/* [30] */
		u32 to_rce	: 1;	/* [31] */
	};
	struct {
		u32:29;
		u32 events:3;
	};
	e2k_reg_t;
} e2k_io_str_t;

/*
 *   RDMA controller state register
 */
typedef union {
	struct {
		u32 ptocl	: 16;	/* [15:0] */
		u32		: 10;	/* [25:16] */
		u32 srst	: 1;	/* [26] */
		u32 mor		: 1;	/* [27] */
		u32 mow		: 1;	/* [28] */
		u32 fch_on	: 1;	/* [29] */
		u32 link_tu	: 1;	/* [30] */
		u32 ch_on	: 1;	/* [31] */
	};
	e2k_reg_t;
} e2k_rdma_cs_t;

/*
 *   Read/Write PWR_MGR0 register
 */
typedef union {
	struct {
		u32 core0_clk	: 1;	/* [0] */
		u32 core1_clk	: 1;	/* [1] */
		u32 ic_clk	: 1;	/* [2] */
		u32		: 13;	/* [15:3] */
		u32 snoop_wait	: 2;	/* [17:16] */
		u32		: 14;	/* [31:18] */
	};
	e2k_reg_t;		/* as entire register */
} e2k_pwr_mgr_t;

/*
 * Monitor control register (SIC_MCR)
 */
typedef union {
	struct {
		u32 v0		: 1;	/* [0] */
		u32		: 1;	/* [1] */
		u32 es0		: 6;	/* [7:2] */
		u32 v1		: 1;	/* [8] */
		u32		: 1;	/* [9] */
		u32 es1		: 6;	/* [15:10] */
		u32 mcn		: 5;	/* [20:16] */
		u32 mcnmo	: 1;	/* [21:21] */
		u32		: 10;	/* [31:22] */
	};
	e2k_reg_t;
} e2k_sic_mcr_t;

/*
 * SIC_HW* registers
 */
typedef union {
	struct {
		u32 independent_rdma	: 1;
		u32 snrd32		: 1;
		u32 dpack64		: 1;
		u32 i2ri		: 2;
		u32 scrqprior		: 1;
		u32			: 26;
	};
	struct {
		u32			: 6;
		u32 dcindscr		: 3;
		u32 b63761wa		: 1;
		u32			: 22;
	} e4c; /* e4c only */
	struct {
		u32			: 6;
		u32 trwm_sc3		: 3;
		u32 dma_wr_glue_en	: 1;
		u32 us_tc_vc1_map	: 2;
		u32 ds_tc_vc1_map	: 2;
		u32 iol_ermo		: 1;
		u32			: 17;
	} v4_v5; /* iset: v4, v5 */
	struct {
		u32			: 15;
		u32 hc_dma_rfo_en	: 1;
		u32 ddrrsync_en		: 1;
		u32 ddrrsync_delay	: 3;
		u32 ddrrsync_rst	: 1;
		u32			: 11;
	} v5; /* iset: v5 */
	e2k_reg_t;
} e2k_sic_hw1_t;

/*
 * Monitor accumulator register hi part (SIC_MAR0_hi, SIC_MAR1_hi)
 */
typedef union {
	struct {
		u32 val	: 31;	/* [30:0] */
		u32 of	: 1;	/* [31] */
	};
	e2k_reg_t;
} e2k_sic_mar_hi_t;

/*
 * Monitor accumulator register lo part (SIC_MAR0_lo, SIC_MAR1_lo)
 */
typedef union {
	u32 val;
	e2k_reg_t;
} e2k_sic_mar_lo_t;		/* single word (32 bits) */

/*
 * Read/Write MCX_ECC (X={0, 1, 2, 3}) registers
 */
typedef union {
	struct {
		u32 ee		: 1;	/* [0] */
		u32 dmode	: 1;	/* [1] */
		u32 of		: 1;	/* [2] */
		u32 ue		: 1;	/* [3] */
		u32		: 12;	/* [15:4] */
		u32 secnt	: 16;	/* [31:16] */
	};
	struct {
		u32		: 2;
		u32 v6_uecnt	: 14;
	};
	e2k_reg_t;
} e2k_mc_ecc_t;

#define E2K_MC_ECC_DISABLED	((e2k_mc_ecc_t) { .word = 0 })

e2k_mc_ecc_t sic_get_mc_ecc(int node, int num);
void sic_set_mc_ecc(int node, int num, e2k_mc_ecc_t value);

/*
 * Read/Write MCX_OPMb (X={0, 1, 2, 3}) registers
 * ! only for P1 processor type !
 */
typedef union {
	struct {
		u32 ct0		: 3;	/* [0:2] */
		u32 ct1		: 3;	/* [3:5] */
		u32 pbm		: 4;	/* [6:9] */
		u32 rm		: 1;	/* [10] */
		u32 rdodt	: 1;	/* [11] */
		u32 wrodt	: 1;	/* [12] */
		u32 bl8int	: 1;	/* [13] */
		u32 mi_fast	: 1;	/* [14] */
		u32 mt		: 1;	/* [15] */
		u32 il		: 1;	/* [16] */
		u32 rcven_del	: 2;	/* [17:18] */
		u32 mc_ps	: 1;	/* [19] */
		u32 arp_en	: 1;	/* [20] */
		u32 flt_brop	: 1;	/* [21] */
		u32 flt_rdpr	: 1;	/* [22] */
		u32 flt_blk	: 1;	/* [23] */
		u32 parerr	: 1;	/* [24] */
		u32 cmdpack	: 1;	/* [25] */
		u32 sldwr	: 1;	/* [26] */
		u32 sldrd	: 1;	/* [27] */
		u32 mirr	: 1;	/* [28] */
		u32 twrwr	: 2;	/* [29:30] */
		u32 mcln	: 1;	/* [31] */
	};
	e2k_reg_t;
} e2k_mc_opmb_t;

/*
 * Read/Write MCX_CFG (X={0, 1, 2, 3}) registers
 * P9, E2C3, E12 and E16 processor type
 */
typedef union {
	struct {
		u32 ct0		: 3;	/* [0:2] */
		u32 ct1		: 3;	/* [3:5] */
		u32 pbm		: 4;	/* [6:9] */
		u32 rm		: 1;	/* [10] */
		u32 ds3		: 2;	/* [11:12] */
		u32 mirr	: 1;	/* [13] */
		u32 sf		: 3;	/* [14:16] */
		u32 mt		: 1;	/* [17] */
		u32 poison_dsbl	: 1;	/* [18] */
		u32 ptrr_mode	: 2;	/* [19:20] */
		u32 mcrc	: 1;	/* [21] */
		u32 odt_ext	: 2;	/* [22:23] */
		u32 pbswap	: 1;	/* [24] */
		u32 dqw		: 2;	/* [25:26] */
		u32 pda_sel	: 5;	/* [27:31] */
	};
	struct {
		u32 v7_ct0		: 4; /* [ 3: 0] */
		u32 v7_ct1		: 4; /* [ 7: 4] */
		u32 v7_pbm		: 4; /* [11: 8] */
		u32 v7_rm		: 1; /* [12:12] */
		u32 v7_3ds		: 2; /* [14:13] */
		u32 mtag_dsbl		: 1; /* [15:15] */
		u32 v7_sf		: 4; /* [19:16] */
		u32 other_fields1	: 5;
		u32 v7_poison_dsbl	: 1; /* [25:25] */
	};
	e2k_reg_t;
} e2k_mc_cfg_t;

/*
 * Read/Write IPCC_CSRX (X={1, 2, 3}) registers
 */
typedef union {
	struct {
		u32 link_scale		: 4;	/* [3:0] */
		u32 cmd_code		: 3;	/* [6:4] */
		u32 cmd_active		: 1;	/* [7] */
		u32			: 1;	/* [8] */
		u32 terr_vc_num		: 3;	/* [11:9] */
		u32 rx_oflw_uflw	: 1;	/* [12] */
		u32 event_imsk		: 3;	/* [15:13] */
		u32 ltssm_state		: 5;	/* [20:16] */
		u32 cmd_cmpl_sts	: 3;	/* [23:21] */
		u32 link_width		: 4;	/* [27:24] */
		u32 event_sts		: 3;	/* [30:28] */
		u32 link_state		: 1;	/* [31] */
	};
	e2k_reg_t;
} e2k_ipcc_csr_t;

/*
 * Read/Write IPCC_STRX (X={1, 2, 3}) registers
 */
typedef union {
	struct {
		u32 ecnt	: 29;	/* [28:0] */
		u32 eco		: 1;	/* [29] */
		u32 ecf		: 2;	/* [31:30] */
	};
	e2k_reg_t;
} e2k_ipcc_str_t;

/*
 * Read/Write SIC_SCCFG register
 */
typedef union {
	struct {
		u32 diren	: 1;	/* [0] */
		u32 dircacheen	: 1;	/* [1] */
		u32		: 30;	/* [31:2] */
	};
	 e2k_reg_t;
} e2k_sic_sccfg_t;

/*
 * Cache L3 registers structures
 */
/* Control register */
typedef unsigned int l3_reg_t;	/* Read/write register (32 bits) */
typedef union {
	struct {
		u32 fl			: 1;	/* [0] flush L3 */
		u32 cl			: 1;	/* [1] clear L3 */
		u32 rdque		: 1;	/* [2] read queues */
		u32 rnc_rrel		: 1;	/* [3] wait RREL for Rnc */
		u32 lru_separate	: 1;	/* [4] LRU separate */
		u32 pipe_ablk_s1	: 1;	/* [5] pipe address block S1 */
		u32 pipe_ablk_s2	: 1;	/* [6] pipe address block S2 */
		u32 sleep_blk		: 1;	/* [7] sleep block */
		u32 wbb_forced		: 1;	/* [8] WBB forced */
		u32 wbb_refill		: 1;	/* [9] WBB refill */
		u32 wbb_timeron		: 1;	/* [10] WBB release on timer */
		u32 wbb_timer		: 7;	/* [17:11] WBB timer set */
		u32 wbb_tfullon		: 1;	/* [18] WBB release on timer */
						/*      at full state */
		u32 wbb_tfull		: 7;	/* [25:19] WBB timer at full */
						/*         state set */
		u32 seal_gblk		: 1;	/* [26] sealed global block */
		u32 seal_lblk		: 1;	/* [27] sealed local block */
		u32			: 4;	/* [31:28] reserved bits */
	};
	e2k_reg_t;
} l3_ctrl_t;

/*
 * Read/Write BC_MP_T_CORR register
 */
typedef union {
	struct {
		u32 corr	: 1;	/* [0] */
		u32 value	: 1;	/* [1] */
		u32		: 10;	/* [11:2] */
		u32 addr	: 20;	/* [31:12] */
	};
	e2k_reg_t;
} bc_mp_t_corr_t;

/*
 * Read/Write BC_MP_T_CORR_H
 */
typedef union {
	u32 addr;
	e2k_reg_t;
} bc_mp_t_corr_h_t;

/*
 * Read/Write BC_MP_CTRL register
 */
typedef union {
	struct {
		u32		: 12;	/* [11:0] */
		u32 mp_en	: 1;	/* [12] */
		u32 b_en	: 1;	/* [13] */
		u32		: 18;	/* [31:14] */
	};
	e2k_reg_t;
} bc_mp_ctrl_t;

/*
 * Read/Write BC_MP_STAT register
 */
typedef union {
	struct {
		u32		: 12;	/* [11:0] */
		u32 b_ne	: 1;	/* [12] */
		u32 b_of	: 1;	/* [13] */
		u32		: 18;	/* [31:14] */
	};
	e2k_reg_t;
} bc_mp_stat_t;



typedef union {
	struct {
		u32 ocn_par_irq		: 1;
		u32 ocn_par_srq		: 1;
		u32 ocn_par_ack		: 1;
		u32 ocn_par_rls		: 1;
		u32 ocn_par_hak		: 1;
		u32 ocn_par_dat_h	: 1;
		u32 ocn_par_dat_b	: 1;
		u32			: 4;
		u32 ipcc_A		: 1;	/* 10 */
		u32 ipcc_B		: 1;
		u32 ipcc_C		: 1;
		u32 ipcc_D		: 1;
	};
	u32 word;
} xmu_l_int_m_t;


typedef union {
	struct {
		u32 ld_cnt		: 13;
		u32 ld_sed		:  1;
		u32 ded			:  1;
		u32			:  1;
		u32 dm_cnt		: 13;
		u32 dm_sed		:  1;
		u32 dm_ded		:  1;
		u32 dm_ded_poison	:  1;
	};
	u32 word;
} e2k_l3_ecc_t;

typedef union {	/* iset V7 */
	struct {
		u32 ecc_dm		:  1;
		u32 ecc_ld		:  1;
		u32 ecc_sed_dm		:  1;
		u32 ecc_sed_ld		:  1;
		u32 emrg		:  1;
		u32			:  3;
		u32 par_irq		:  1;
		u32 par_srq		:  1;
		u32 par_dat_hdr;
		u32 par_dat_bdy		:  1;
		u32 par_ack		:  1;
		u32 par_hak		:  1;
		u32 par_rls		:  1;
		u32			:  1;
		u32 pmon		:  1;
	};
	u32 word;
} e2k_l3_imsk_t;

typedef e2k_l3_imsk_t e2k_l3_int_t;


/*
 * HC monitor control register (HC_MCR)
 */
typedef union {
	struct {
		u32 v0		: 1;
		u32 __unused1	: 1;
		u32 es0		: 6;
		u32 v1		: 1;
		u32 __unused2	: 1;
		u32 es1		: 6;
		u32 __unused3	: 16;
	};
	u32 word;
} e2k_hc_mcr_t;

/*
 * HC monitor ID register (HC_MID)
 */
typedef union {
	struct {
		u32 id0 : 16;
		u32 id1 : 16;
	};
	u32 word;
} e2k_hc_mid_t;

/*
 * IOMMU monitor control register (IOMMU_MCR)
 */
typedef union {
	struct {
		u32 v0		: 1;
		u32 __unused1	: 1;
		u32 es0		: 6;
		u32 v1		: 1;
		u32 __unused2	: 1;
		u32 es1		: 6;
		u32 __unused3	: 16;
	};
	u32 word;
} e2k_iommu_mcr_t;

/*
 * IOMMU monitor ID register (IOMMU_MID)
 */
typedef union {
	struct {
		u32 id0 : 16;
		u32 id1 : 16;
	};
	u32 word;
} e2k_iommu_mid_t;

/*
 * MC status register (MC_STATUS_E2K)
 */
typedef union {
	struct {
		u32 ecc_err		: 1;
		u32 ddrint_err		: 1;
		u32 phyccm_par_err	: 1;
		u32 dmem_par_err	: 1;
		u32 bridge_par_err	: 1;
		u32 phy_interrupt	: 1;
		u32 phy_init_complete	: 1;
		u32 dfi_par_err		: 1;
		u32 meminit_finish	: 1;
		u32 mon0_of		: 1;
		u32 mon1_of		: 1;
		u32 dfi_err		: 1;
		u32 dfi_err_info	: 1;
		u32 par_alert_delay	: 6;
		u32 rst_done		: 1;
		u32 wrcrc_aleert_delay	: 6;
		u32 ce_int		: 1;	/* from v7 */
		u32 __unused		: 5;
	};
	u32 word;
} e2k_mc_status_t;

#define MC_STATUS_REG_GOOD	0x80040
/*
 * MC channel select register (MC_CH)
 */
typedef union {
	struct {
		u32 n : 4;
		u32   : 28;
	};
	u32 word;
} e2k_mc_ch_t;

/*
 * MC control register (MC_CTL)
 */
typedef union {
	struct {
		u32 mcen         : 1;
		u32 phyupd       : 1;
		u32 mcinitreq    : 1;
		u32 phyinitreq   : 1;
		u32 mc_ps        : 1;
		u32 lpreq        : 1;
		u32 lpwkup       : 4;
		u32 upd0_en      : 1;
		u32 parint_en    : 1;
		u32 phyint_en    : 1;
		u32 mi_bg        : 1;
		u32 mrs_en       : 1;
		u32 dfi_freq     : 5;
		u32 phyreset_cfg : 1;
		u32 phy_reset    : 1;
		u32 trwm         : 3;
		u32 tdly         : 3;
		u32 dmemint_en   : 1;
		u32 bridgeint_en : 1;
		u32 mcln         : 1;
		u32 mcstart      : 1;

		u32   : 28;
	};
	u32 word;
} e2k_mc_ctl_t;

/*
 * MC performance register (MC_PERF)
 */
typedef union {
	struct {
		u32 reg_nr0       : 1; /* == 0 for MC_PERF0 */
		u32 pbmask        : 1;
		u32 arp_en        : 1;
		u32 flt_rdpr_type : 1;
		u32 flt_rdpr_sign : 2;
		u32 flt_brop      : 1;
		u32 cmdpack       : 1;
		u32 sldrd_fast    : 1;
		u32 rd_weight     : 3;
		u32 flt_prio      : 1;
		u32 apen          : 1;
		u32 pt            : 1;
		u32 rdpr_l        : 6;
		u32 rdpr_h        : 6;
		u32 rd_prio_rsv   : 5;
	} reg0;
	struct {
		u32 reg_nr1 : 1; /* == 1 for MC_PERF0 */
		u32         : 1;
		u32 ap_mgn  : 6;
		u32         : 1;
		u32 sldrd   : 8;
		u32 sldwr   : 8;
		u32         : 8;
	} reg1;
	u32 word;
} e2k_mc_perf_t;

/*
 * MC power control register (MC_PWR)
 */
typedef union {
	struct {
		u32 pdmod           : 3;
		u32 memhot_en       : 1;
		u32 memhot_sense    : 3;
		u32 pdg             : 1;
		u32 pdtmr           : 21;
		u32 memhot_throttle : 3;
	};
	u32 word;
} e2k_mc_pwr_t;

/*
 * MC monitor control register (MC_MON_CTL)
 */
typedef union {
	struct {
		u32 rst0 : 1;
		u32 rst1 : 1;
		u32 frz0 : 1;
		u32 frz1 : 1;
		u32 ld0  : 1;
		u32 ld1  : 1;
		u32 es0  : 5;
		u32 es1  : 5;
		u32 lb0  : 8;
		u32 lb1  : 8;
	};
	struct {
		u32 __pad : 16;
		u32 ba0  : 2;
		u32 bg0  : 2;
		u32 cid0 : 3;
		u32 all0 : 1;
		u32 ba1  : 2;
		u32 bg1  : 2;
		u32 cid1 : 3;
		u32 all1 : 1;
	};
	u32 word;
} e2k_mc_mon_ctl_t;

/*
 * MC monitor #0,1 counter high (MC_MON_CTRext)
 */
typedef union {
	u16 cnt[2];
	u32 word;
} e2k_mc_mon_ctrext_t;


/*
 * HMU memory interleaving control register (HMU_MIC)
 */
typedef union {
	struct {
		u32 mcil_bit0	: 6;
		u32 mcil_bit1	: 6;
		u32 mcil_bit2	: 6;
		u32 mcil_bit3	: 6;
		u32 mcen	: 8;
	};
	u32 word;
} e2k_hmu_mic_t;

/*
 * HMU monitor control register (HMU_MCR)
 */
typedef union {
	struct {
		u32 v0		: 1;
		u32 __unused1	: 1;
		u32 es0		: 6;
		u32 v1		: 1;
		u32 __unused2	: 1;
		u32 es1		: 6;
		u32 flt0_off	: 1;
		u32 flt0_rqid	: 7;
		u32 flt0_cid	: 1;
		u32 flt0_bid	: 1;
		u32 flt0_xid	: 1;
		u32 flt1_off	: 1;
		u32 flt1_node	: 2;
		u32 flt1_rnode	: 1;
		u32 __unused3	: 1;
	};
	u32 word;
} e2k_hmu_mcr_t;

/*
 * PREPIC monitor control register (PREPIC_MCR)
 */
typedef union {
	struct {
		u32 vc0		: 1;
		u32 __unused1	: 1;
		u32 es0		: 6;
		u32 vc1		: 1;
		u32 __unused2	: 1;
		u32 es1		: 6;
		u32 __unused3	: 16;
	};
	u32 word;
} e2k_prepic_mcr_t;

/*
 * PREPIC monitor ID register (PREPIC_MID)
 */
typedef union {
	struct {
		u32 id0 : 16;
		u32 id1 : 16;
	};
	u32 word;
} e2k_prepic_mid_t;







/* V7 regs */

typedef union {
	struct {
		u32			: 8;
		u32 regnum		: 2;
		u32 cid			: 3;
		u32 pb			: 2;
		u32 clr			: 1;
		u32 ce_ins		: 1;
		u32 ue_ins		: 1;
		u32 ce_int_en		: 1;
	};
	u32 word;
} e2k_mc_eccdiag1_t;


typedef union {
	struct {
		u32 mil_bit0	:  6;
		u32 mil_bit1	:  6;
		u32 mil_bit2	:  6;
		u32		:  6;
		u32 mc_en	:  8;
	};
	u32 word;
} e2k_ocn_mil_t;


typedef union {
	struct {
		u32 phys_addr		: 24;
		u32 data_word		:  3;
		u32 addr_half		:  1;
		u32 rddata_val		:  1;
		u32 data_type		:  1;
		u32 req_type		:  1;
		u32 req_gen		:  1;
	};
	struct {
		u32			: 29;
		u32 rddata_poison	:  1;
	};
	u32 word;
} e2k_mcna_diag_addr_t;

typedef union {
	struct {
		u32 v0			: 1;
		u32			: 1;
		u32 es0			: 6;
		u32 v1			: 1;
		u32 es1			: 6;
		u32 flt0_off		: 1; /* [15] */
		u32 flt0_rqid		: 8;
		u32 flt0_cid		: 1;
		u32 flt0_bid		: 1;
		u32 flt0_xid		: 1;
		u32 flt1_off		: 1; /* [27] */
		u32 flt1_node		: 2;
		u32 flt1_rnode		: 1; /* [30] */
	};
	u32 word;
} e2k_ha_mcr_t;


typedef union {
	struct {
		u32 rst_cnt		: 1;
		u32 rst_cfg		: 1;
		u32 frz			: 1;
		u32			: 29;
	};
	u32 word;
} e2k_l3_pmon_uctl;

typedef union {
	struct {
		u32 en			: 1;
		u32 rst			: 1;
		u32 sbnk		: 2;
		u32 rqf			: 1;
		u32 stf			: 1;
		u32 edg			: 1;
		u32 inv			: 1;
		u32 sel			: 8;
		u32 msk			: 8;
		u32 thr			: 8;
	};
	u32 word;
} e2k_l3_pmon_ctl_v6;

typedef union {
	struct {
		u32 en			: 1;
		u32 rst			: 1;
		u32 sbnk		: 2;
		u32 rqf			: 1;
		u32 stf			: 1;
		u32 edg			: 1;
		u32 inv			: 1;
		u32 sel			: 6;
		u32 msk			: 10;
		u32 thr			: 8;
	};
	u32 word;
} e2k_l3_pmon_ctl_v7;

typedef union {
	struct {
		u32 rqf			: 9;
		u32			: 3;
		u32 rqf_mask		: 2;
		u32			: 2;
		u32 stf			: 10;
		u32			: 6;
	};
	u32 word;
} e2k_l3_pmon_flt0_v6;

typedef union {
	struct {
		u32 rqf			: 7;
		u32			: 1;
		u32 rqf_mask		: 3;
		u32			: 5;
		u32 stf			: 10;
		u32			: 6;
	};
	u32 word;
} e2k_l3_pmon_flt0_v7;

typedef union {
	struct {
		u32 en			: 1;
		u32			: 3;
		u32 code		: 1;
		u32 data		: 1;
		u32 loc			: 1;
		u32 rem			: 1;
		u32 opf			: 8;
		u32 opc0		: 8;
		u32 opc1		: 8;
	};
	u32 word;
} e2k_l3_pmon_flt1_v6;

typedef union {
	struct {
		u32 en			: 1;
		u32 code		: 1;
		u32 data		: 1;
		u32 loc			: 1;
		u32 rem			: 1;
		u32 opf			: 10;
		u32			: 2;
		u32 opc_injc		: 3;
		u32 opc_injc_en		: 1;
		u32 opc_srq		: 3;
		u32 opc_srq_en		: 1;
		u32 opc_irq		: 6;
		u32 opc_irq_en		: 1;
	};
	u32 word;
} e2k_l3_pmon_flt1_v7;

typedef union {
	u32 val;
	u32 word;
} e2k_l3_pmon_cnt_lo;

typedef union {
	struct {
		u32 val			: 24;
		u32			: 8;
	};
	u32 word;
} e2k_l3_pmon_cnt_hi;

#endif /* _E2K_SIC_REGS_H_ */
