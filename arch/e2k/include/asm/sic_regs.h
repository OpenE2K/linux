/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef	_E2K_SIC_REGS_H_
#define	_E2K_SIC_REGS_H_

#ifdef __KERNEL__

#include <asm/types.h>
#include <asm/cpu_regs.h>
#include <asm/e2k_sic.h>

#ifndef __ASSEMBLY__
#include <asm/e2k_api.h>
#endif /* __ASSEMBLY__ */


#define	E2K_SIC_ALIGN_RT_MSI	20	/* 1 Mb */

#define SIC_IO_LINKS_COUNT	2

/*
 * NBSR registers addresses (offsets in NBSR area)
 */

#define SIC_st_p	0x00

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

#define	SIC_st_ipl	0x0e0
#define	SIC_st_xmu	0x0f0

#define SIC_rt_ln	0x08
#define SIC_rt_lcfg0	0x10
#define SIC_rt_lcfg1	0x14
#define SIC_rt_lcfg2	0x18
#define SIC_rt_lcfg3	0x1c

#define SIC_rt_mhi0	0x20
#define SIC_rt_mhi1	0x24
#define SIC_rt_mhi2	0x28
#define SIC_rt_mhi3	0x2c

#define SIC_rt_mlo0	0x30
#define SIC_rt_mlo1	0x34
#define SIC_rt_mlo2	0x38
#define SIC_rt_mlo3	0x3c

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

#define SIC_esclkr		0xc00

#define SIC_rt_ioapic10	0x1060
#define SIC_rt_ioapic11	0x1064
#define SIC_rt_ioapic12	0x1068
#define SIC_rt_ioapic13	0x106c

#define SIC_rt_ioapicintb 0x94
#define SIC_rt_lapicintb 0xa0

#define	SIC_rt_pcicfgb	0x90
#define	SIC_rt_pcicfged	0x98
#define	SIC_rt_vgamemed	0x9c

/* PREPIC */
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


/* Host Controller */
#define SIC_xmu_a_hc_ctrl	0xa340
#define SIC_xmu_b_hc_ctrl	0xb340
#define SIC_xmu_c_hc_ctrl	0xc340
#define SIC_xmu_d_hc_ctrl	0xd340

#define HC_CTRL_DCAE	BIT(7)
#define HC_CTRL_WL3STE	BIT(15)

/* IOMMU */
#define SIC_iommu_ctrl		0x0380
#define SIC_iommu_ba_lo		0x0390
#define SIC_iommu_ba_hi		0x0394
#define SIC_iommu_dtba_lo	0x0398
#define SIC_iommu_dtba_hi	0x039c
#define SIC_iommu_flush		0x03a0
#define SIC_iommu_flushP	0x03a4
#define SIC_iommu_cmd_c_lo	0x03a0
#define SIC_iommu_cmd_c_hi	0x03a4
#define SIC_iommu_cmd_d_lo	0x03a8
#define SIC_iommu_cmd_d_hi	0x03ac
#define SIC_iommu_err		0x03b0
#define SIC_iommu_err1		0x03b4
#define SIC_iommu_err_info_lo	0x03b8
#define SIC_iommu_err_info_hi	0x03bc
#define SIC_iommu_mcr		0x03c0
#define SIC_iommu_mid		0x03c4
#define SIC_iommu_mar0_lo	0x03c8
#define SIC_iommu_mar0_hi	0x03cc
#define SIC_iommu_mar1_lo	0x03d0
#define SIC_iommu_mar1_hi	0x03d4

#define SIC_iommu_reg_base	SIC_iommu_ctrl
#define SIC_iommu_reg_size	0x0080
#define SIC_e2c3_iommu_nr	0x0007
#define SIC_embedded_iommu_base	0x5d00
#define	SIC_embedded_iommu_size	SIC_iommu_reg_size

/* IO link & RDMA */
#define	SIC_iol_csr		0x900
#define	SIC_io_vid		0x700
#define	SIC_io_csr		0x704
#define	SIC_io_str		0x70c
#define	SIC_io_str_hi		0x72c
#define	SIC_rdma_vid		0x880
#define	SIC_rdma_cs		0x888

/* Second IO link */
#define	SIC_iol_csr1	0x1900
#define	SIC_io_vid1	0x1700
#define	SIC_io_csr1	0x1704
#define	SIC_io_str1	0x170c
#define	SIC_rdma_vid1	0x1880
#define	SIC_rdma_cs1	0x1888

/* DSP */
#define SIC_ic_ir0	0x2004
#define SIC_ic_ir1      0x2008
#define SIC_ic_mr0      0x2010
#define SIC_ic_mr1      0x2014

/* Monitors */
#define SIC_sic_mcr	0xc30
#define SIC_sic_mar0_lo	0xc40
#define SIC_sic_mar0_hi	0xc44
#define SIC_sic_mar1_lo	0xc48
#define SIC_sic_mar1_hi	0xc4c

/* Interrupt register */
#define SIC_sic_int	0xc60

/* MC */

#define SIC_MAX_MC_COUNT	E48C_SIC_MC_COUNT
#define SIC_MC_COUNT		(machine.sic_mc_count)

#define SIC_MC_BASE		0x400
#define SIC_MC_SIZE		(machine.sic_mc_size)

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

/* IPCC */
#define SIC_IPCC_LINKS_COUNT	3
#define SIC_ipcc_csr1		0x604
#define SIC_ipcc_csr2		0x644
#define SIC_ipcc_csr3		0x684
#define SIC_ipcc_str1		0x60c
#define SIC_ipcc_str2		0x64c
#define SIC_ipcc_str3		0x68c

#define SIC_hw0			0xc80
#define SIC_hw1			0xc84
#define SIC_hw2			0xc88
#define SIC_hw3			0xc8c

/* Power management */
#define SIC_pwr_mgr		0x280

/* E12C/E16C/E2C3 Power Control System (PCS) registers
 * PMC base = 0x1000 is added */
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
#define _PMC_FREQ_CORE_0_MON		0x200
#define _PMC_FREQ_CORE_0_CTRL		0x204
#define _PMC_FREQ_CORE_0_SLEEP		0x208
#define _PMC_FREQ_CORE_N_MON(n)		(_PMC_FREQ_CORE_0_MON +  n * 16)
#define _PMC_FREQ_CORE_N_CTRL(n)	(_PMC_FREQ_CORE_0_CTRL +  n * 16)
#define _PMC_FREQ_CORE_N_SLEEP(n)	(_PMC_FREQ_CORE_0_SLEEP +  n * 16)
#define _PMC_FREQ_CORE_0_MON_V7	0x400
#define _PMC_FREQ_CORE_0_CTRL_V7	0x404
#define _PMC_FREQ_CORE_0_SLEEP_V7	0x408
#define _PMC_FREQ_CORE_N_MON_V7(n)	(_PMC_FREQ_CORE_0_MON_V7 +  n * 16)
#define _PMC_FREQ_CORE_N_CTRL_V7(n)	(_PMC_FREQ_CORE_0_CTRL_V7 +  n * 16)
#define _PMC_FREQ_CORE_N_SLEEP_V7(n)	(_PMC_FREQ_CORE_0_SLEEP_V7 +  n * 16)
#define _PMC_FREQ_OCN_MON		0x400
#define _PMC_FREQ_OCN_CTRL		0x404
#define _PMC_FREQ_GRAPHIC_0_MON	0x410
#define _PMC_FREQ_GRAPHIC_0_CTRL	0x414
#define _PMC_FREQ_GRAPHIC_N_MON(n)	(_PMC_FREQ_GRAPHIC_0_MON +  n * 16)
#define _PMC_FREQ_GRAPHIC_N_CTRL(n)	(_PMC_FREQ_GRAPHIC_0_CTRL +  n * 16)
#define _PMC_FREQ_OCN_MON_V7		0x380
#define _PMC_FREQ_OCN_CTRL_V7		0x384
#define _PMC_FREQ_GRAPHIC_0_MON_V7	0x3c0
#define _PMC_FREQ_GRAPHIC_0_CTRL_V7	0x3c4
#define _PMC_FREQ_GRAPHIC_N_MON_V7(n)	(_PMC_FREQ_GRAPHIC_0_MON_V7 +  n * 16)
#define _PMC_FREQ_GRAPHIC_N_CTRL_V7(n)	(_PMC_FREQ_GRAPHIC_0_CTRL_V7 +  n * 16)
#define _PMC_SYS_MON_0			0x500
#define _PMC_SYS_MON_1			0x504
#define _PMC_FAN_CFG			0x540

#define PMC_INFO			0x1000

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
#define PMC_FREQ_CORE_0_MON		(PMC_INFO + _PMC_FREQ_CORE_0_MON)
#define PMC_FREQ_CORE_0_CTRL		(PMC_INFO + _PMC_FREQ_CORE_0_CTRL)
#define PMC_FREQ_CORE_0_SLEEP		(PMC_INFO + _PMC_FREQ_CORE_0_SLEEP)
#define PMC_FREQ_CORE_N_MON(n)		(PMC_INFO + _PMC_FREQ_CORE_N_MON(n))
#define PMC_FREQ_CORE_N_CTRL(n)	(PMC_INFO + _PMC_FREQ_CORE_N_CTRL(n))
#define PMC_FREQ_CORE_N_SLEEP(n)	(PMC_INFO + _PMC_FREQ_CORE_N_SLEEP(n))
#define PMC_FREQ_CORE_0_MON_V7		(PMC_INFO + _PMC_FREQ_CORE_0_MON_V7)
#define PMC_FREQ_CORE_0_CTRL_V7	(PMC_INFO + _PMC_FREQ_CORE_0_CTRL_V7)
#define PMC_FREQ_CORE_0_SLEEP_V7	(PMC_INFO + _PMC_FREQ_CORE_0_SLEEP_V7)
#define PMC_FREQ_CORE_N_MON_V7(n)	(PMC_INFO + _PMC_FREQ_CORE_N_MON_V7(n))
#define PMC_FREQ_CORE_N_CTRL_V7(n)	(PMC_INFO + _PMC_FREQ_CORE_N_CTRL_V7(n))
#define PMC_FREQ_CORE_N_SLEEP_V7(n)	(PMC_INFO + _PMC_FREQ_CORE_N_SLEEP_V7(n))
#define PMC_FREQ_OCN_MON		(PMC_INFO + _PMC_FREQ_OCN_MON)
#define PMC_FREQ_OCN_CTRL		(PMC_INFO + _PMC_FREQ_OCN_CTRL)
#define PMC_FREQ_OCN_MON_V7		(PMC_INFO + _PMC_FREQ_OCN_MON_V7)
#define PMC_FREQ_OCN_CTRL_V7		(PMC_INFO + _PMC_FREQ_OCN_CTRL_V7)
#define PMC_FREQ_GRAPHIC_0_MON		(PMC_INFO + _PMC_FREQ_GRAPHIC_0_MON)
#define PMC_FREQ_GRAPHIC_0_CTRL	(PMC_INFO + _PMC_FREQ_GRAPHIC_0_CTRL)
#define PMC_FREQ_GRAPHIC_N_MON(n)	(PMC_INFO + _PMC_FREQ_GRAPHIC_N_MON(n))
#define PMC_FREQ_GRAPHIC_N_CTRL(n)	(PMC_INFO + _PMC_FREQ_GRAPHIC_N_CTRL(n))
#define PMC_FREQ_GRAPHIC_0_MON_V7	(PMC_INFO + _PMC_FREQ_GRAPHIC_0_MON_V7)
#define PMC_FREQ_GRAPHIC_0_CTRL_V7	(PMC_INFO + _PMC_FREQ_GRAPHIC_0_CTRL_V7)
#define PMC_FREQ_GRAPHIC_N_MON_V7(n)	(PMC_INFO + _PMC_FREQ_GRAPHIC_N_MON_V7(n))
#define PMC_FREQ_GRAPHIC_N_CTRL_V7(n)	(PMC_INFO + _PMC_FREQ_GRAPHIC_N_CTRL_V7(n))
#define PMC_SYS_MON_0			(PMC_INFO + _PMC_SYS_MON_0)
#define PMC_SYS_MON_1			(PMC_INFO + _PMC_SYS_MON_1)
#define PMC_FAN_CFG			(PMC_INFO + _PMC_FAN_CFG)

#ifndef __ASSEMBLY__
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
	};
	e2k_reg_t;
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
#endif	/* __ASSEMBLY__ */

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

#ifndef __ASSEMBLY__
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

#endif /* ! __ASSEMBLY__ */
#endif /* __KERNEL__ */
#endif /* _E2K_SIC_REGS_H_ */
