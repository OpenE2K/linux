#ifndef	_E2K_SIC_REGS_H_
#define	_E2K_SIC_REGS_H_

#ifdef __KERNEL__

#include <asm/types.h>
#include <asm/cpu_regs.h>
#include <asm/e2k_sic.h>
#include <asm/sic_regs_access.h>

#ifndef __ASSEMBLY__
#include <asm/e2k_api.h>
#endif	/* __ASSEMBLY__ */

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

#define SIC_rt_ioapic10	0x1060
#define SIC_rt_ioapic11	0x1064
#define SIC_rt_ioapic12	0x1068
#define SIC_rt_ioapic13	0x106c

#define SIC_rt_ioapicintb 0x94
#define SIC_rt_lapicintb 0xa0

#define	SIC_rt_msi	0xb0
#define	SIC_rt_msi_h	0xb4

#define	SIC_rt_pcicfgb	0x90
#define	SIC_rt_pcicfged	0x98

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

/* Host Controller */
#define SIC_hc_ctrl		0x0340

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

#define SIC_edbc_iommu_ctrl		0x5080
#define SIC_edbc_iommu_ba_lo		0x5090
#define SIC_edbc_iommu_ba_hi		0x5094
#define SIC_edbc_iommu_dtba_lo		0x5098
#define SIC_edbc_iommu_dtba_hi		0x509c
#define SIC_edbc_iommu_cmd_c_lo		0x50a0
#define SIC_edbc_iommu_cmd_c_hi		0x50a4
#define SIC_edbc_iommu_err		0x50b0
#define SIC_edbc_iommu_err1		0x50b4
#define SIC_edbc_iommu_err_info_lo	0x50b8
#define SIC_edbc_iommu_err_info_hi	0x50bc

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

#define SIC_MAX_MC_COUNT	E16C_SIC_MC_COUNT
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

/* Power management */
#define SIC_pwr_mgr		0x280

/* E12C/E16C/E2C3 Power Control System (PCS) registers
 * PMC base =0x1000 is added */
#define PMC_FREQ_CFG			0x1100
#define PMC_FREQ_STEPS			0x1104
#define PMC_FREQ_C2			0x1108
#define PMC_FREQ_CORE_0_MON		0x1200
#define PMC_FREQ_CORE_0_CTRL		0x1204
#define PMC_FREQ_CORE_0_SLEEP		0x1208
#define PMC_FREQ_CORE_N_MON(n)	(PMC_FREQ_CORE_0_MON +  n * 16)
#define PMC_FREQ_CORE_N_CTRL(n)	(PMC_FREQ_CORE_0_CTRL +  n * 16)
#define PMC_FREQ_CORE_N_SLEEP(n)	((PMC_FREQ_CORE_0_SLEEP) +  n * 16)
#define PMC_SYS_MON_1			0x1504
/* PMC_FREQ_CORE_0_SLEEP fields: */
typedef union {
	struct {
		u32 cmd           : 3;
		u32 pad1          : 13;
		u32 status        : 3;
		u32 pad2          : 8;
		u32 ctrl_enable   : 1;
		u32 alter_disable : 1;
		u32 bfs_bypass    : 1;
		u32 pin_en        : 1;
		u32 pad3          : 1;
	};
	u32 word;
} freq_core_sleep_t;

/* PMC_FREQ_CORE_0_MON fields: */
typedef union {
	struct {
		u32 divF_curr     : 6;
		u32 divF_target   : 6;
		u32 divF_limit_hi : 6;
		u32 divF_limit_lo : 6;
		u32 divF_init     : 6;
		u32 bfs_bypass    : 1;
		u32               : 1;
	};
	u32 word;
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
	u32 word;
} freq_core_ctrl_t;

/* PMC_SYS_MON_1 fields: */
typedef union {
	struct {
		u32 machine_gen_alert	: 1;
		u32 machine_pwr_alert	: 1;
		u32 cpu_pwr_alert	: 1;
		u32 mc47_pwr_alert	: 1;
		u32 mc03_pwr_alert	: 1;
		u32 mc47_dimm_event	: 1;
		u32 mc03_dimm_event	: 1;
		u32  reserved		: 2;
		u32 mc7_fault		: 1;
		u32 mc6_fault		: 1;
		u32 mc5_fault		: 1;
		u32 mc4_fault		: 1;
		u32 mc3_fault		: 1;
		u32 mc2_fault		: 1;
		u32 mc1_fault		: 1;
		u32 mc0_fault		: 1;
		u32 cpu_fault		: 1;
		u32 pin_sataeth_config	: 1;
		u32 pin_iplc_pe_pre_det	: 2;
		u32 pin_iplc_pe_config	: 2;
		u32 pin_ipla_flip_en	: 1;
		u32 pin_iowl_pe_pre_det	: 4;
		u32 pin_iowl_pe_config	: 2;
		u32 pin_efuse_mode	: 2;
	};
	u32 word;
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

#ifndef __ASSEMBLY__
/*
 *   Read/Write RT_LCFGj Regs
 */
#define E2S_CLN_BITS	4	/* 4 bits - cluster # */
#define E8C_CLN_BITS	2	/* 2 bits - cluster # */
#if	defined(CONFIG_E2S)
#define	E2K_MAX_CL_NUM	((1 << E2S_CLN_BITS) - 1)
#elif	defined(CONFIG_E8C) || defined(CONFIG_E8C2)
#define	E2K_MAX_CL_NUM	((1 << E8C_CLN_BITS) - 1)
#elif	defined(CONFIG_E12C) || defined(CONFIG_E16C) || defined(CONFIG_E2C3)
#define	E2K_MAX_CL_NUM	0	/* Cluster number field was deleted */
#endif	/* CONFIG_E2S */

/* SCCFG */
#define SIC_sccfg	0xc00

typedef	unsigned int	e2k_rt_lcfg_t;	/* Read/write pointer (32 bits) */
typedef	struct e2s_rt_lcfg_fields {
	e2k_rt_lcfg_t   vp	:  1;			/* [0] */
	e2k_rt_lcfg_t   vb	:  1;			/* [1] */
	e2k_rt_lcfg_t   vics	:  1;			/* [2] */
	e2k_rt_lcfg_t   vio	:  1;			/* [3] */
	e2k_rt_lcfg_t   pln	:  2;			/* [5:4] */
	e2k_rt_lcfg_t   cln	:  4;			/* [9:6] */
	e2k_rt_lcfg_t   unused	:  22;			/* [31:10] */
} e2s_rt_lcfg_fields_t;
typedef	struct e8c_rt_lcfg_fields {
	e2k_rt_lcfg_t   vp	:  1;			/* [0] */
	e2k_rt_lcfg_t   vb	:  1;			/* [1] */
	e2k_rt_lcfg_t   vics	:  1;			/* [2] */
	e2k_rt_lcfg_t   vio	:  1;			/* [3] */
	e2k_rt_lcfg_t   pln	:  2;			/* [5:4] */
	e2k_rt_lcfg_t   cln	:  2;			/* [7:6] */
	e2k_rt_lcfg_t   unused	:  24;			/* [31:8] */
} e8c_rt_lcfg_fields_t;
typedef	union e2k_rt_lcfg_struct {		/* Structure of lower word */
	e2s_rt_lcfg_fields_t	e2s_fields;	/* as fields */
	e8c_rt_lcfg_fields_t	e8c_fields;	/* as fields */
	e2k_rt_lcfg_t		word;		/* as entire register */
} e2k_rt_lcfg_struct_t;

#define	E2S_RT_LCFG_vp(__reg)	((__reg).e2s_fields.vp)
#define	E2S_RT_LCFG_vb(__reg)	((__reg).e2s_fields.vb)
#define	E2S_RT_LCFG_vics(__reg)	((__reg).e2s_fields.vics)
#define	E2S_RT_LCFG_vio(__reg)	((__reg).e2s_fields.vio)
#define	E2S_RT_LCFG_pln(__reg)	((__reg).e2s_fields.pln)
#define	E2S_RT_LCFG_cln(__reg)	((__reg).e2s_fields.cln)
#define	E2S_RT_LCFG_reg(__reg)	((__reg).word)

#define	E8C_RT_LCFG_vp(__reg)	((__reg).e8c_fields.vp)
#define	E8C_RT_LCFG_vb(__reg)	((__reg).e8c_fields.vb)
#define	E8C_RT_LCFG_vics(__reg)	((__reg).e8c_fields.vics)
#define	E8C_RT_LCFG_vio(__reg)	((__reg).e8c_fields.vio)
#define	E8C_RT_LCFG_pln(__reg)	((__reg).e8c_fields.pln)
#define	E8C_RT_LCFG_cln(__reg)	((__reg).e8c_fields.cln)
#define	E8C_RT_LCFG_reg(__reg)	((__reg).word)

/* FIXME: now as on e8c, but can be changed need DOCs */
#define	E12C_RT_LCFG_vp(__reg)	E8C_RT_LCFG_vp(__reg)
#define	E12C_RT_LCFG_vb(__reg)	E8C_RT_LCFG_vb(__reg)
#define	E12C_RT_LCFG_vics(__reg) E8C_RT_LCFG_vics(__reg)
#define	E12C_RT_LCFG_vio(__reg)	E8C_RT_LCFG_vio(__reg)
#define	E12C_RT_LCFG_pln(__reg)	E8C_RT_LCFG_pln(__reg)
#define	E12C_RT_LCFG_cln(__reg)	E8C_RT_LCFG_cln(__reg)
#define	E12C_RT_LCFG_reg(__reg)	E8C_RT_LCFG_reg(__reg)

#define	E2K_RT_LCFG_vp		E2S_RT_LCFG_vp
#define	E2K_RT_LCFG_vb		E2S_RT_LCFG_vb
#define	E2K_RT_LCFG_vics	E2S_RT_LCFG_vics
#define	E2K_RT_LCFG_vio		E2S_RT_LCFG_vio
#if	defined(CONFIG_E2S)
#define	E2K_RT_LCFG_pln		E2S_RT_LCFG_pln
#define	E2K_RT_LCFG_cln		E2S_RT_LCFG_cln
#elif	defined(CONFIG_E8C) || defined(CONFIG_E8C2)
#define	E2K_RT_LCFG_pln		E8C_RT_LCFG_pln
#define	E2K_RT_LCFG_cln		E8C_RT_LCFG_cln
#elif	defined(CONFIG_E12C) || defined(CONFIG_E16C) || defined(CONFIG_E2C3)
#define	E2K_RT_LCFG_pln		E12C_RT_LCFG_pln
#define	E2K_RT_LCFG_cln		E12C_RT_LCFG_cln
#endif	/* CONFIG_E2S */
#define	E2K_RT_LCFG_reg		E2S_RT_LCFG_reg

/*
 *   Read/Write RT_PCIIOj Regs
 */
typedef	unsigned int	e2k_rt_pciio_t;	/* Read/write pointer (32 bits) */
typedef	struct e2k_rt_pciio_fields {
	e2k_rt_pciio_t   unused1 :  12;			/* [11:0] */
	e2k_rt_pciio_t   bgn	 :  4;			/* [15:12] */
	e2k_rt_pciio_t   unused2 :  12;			/* [27:16] */
	e2k_rt_pciio_t   end	 :  4;			/* [31:28] */
} e2k_rt_pciio_fields_t;
typedef	union e2k_rt_pciio_struct {		/* Structure of lower word */
	e2k_rt_pciio_fields_t	fields;		/* as fields */
	e2k_rt_pciio_t		word;		/* as entire register */
} e2k_rt_pciio_struct_t;

#define	E2K_SIC_ALIGN_RT_PCIIO	12			/* 4 Kb */
#define	E2K_SIC_SIZE_RT_PCIIO	(1 << E2K_SIC_ALIGN_RT_PCIIO)
#define	E2K_RT_PCIIO_bgn	fields.bgn
#define	E2K_RT_PCIIO_end	fields.end
#define	E2K_RT_PCIIO_reg	word

/*
 *   Read/Write RT_PCIMj Regs
 */
typedef	unsigned int	e2k_rt_pcim_t;	/* Read/write pointer (32 bits) */
typedef	struct e2k_rt_pcim_fields {
	e2k_rt_pcim_t   unused1 :  11;			/* [10:0] */
	e2k_rt_pcim_t   bgn	:  5;			/* [15:11] */
	e2k_rt_pcim_t   unused2 :  11;			/* [26:16] */
	e2k_rt_pcim_t   end	:  5;			/* [31:27] */
} e2k_rt_pcim_fields_t;
typedef	union e2k_rt_pcim_struct {		/* Structure of lower word */
	e2k_rt_pcim_fields_t	fields;		/* as fields */
	e2k_rt_pcim_t		word;		/* as entire register */
} e2k_rt_pcim_struct_t;

#define	E2K_SIC_ALIGN_RT_PCIM	27			/* 128 Mb */
#define	E2K_SIC_SIZE_RT_PCIM	(1 << E2K_SIC_ALIGN_RT_PCIM)
#define	E2K_RT_PCIM_bgn		fields.bgn
#define	E2K_RT_PCIM_end		fields.end
#define	E2K_RT_PCIM_reg		word

/*
 *   Read/Write RT_PCIMPj Regs
 */
typedef	unsigned int	e2k_rt_pcimp_t; /* Read/write pointer (32 bits) */
typedef	struct e2k_rt_pcimp_struct {
	e2k_rt_pcimp_t	addr;		/* [PA_MSB: 0] */
} e2k_rt_pcimp_struct_t;

#define	E2K_SIC_ALIGN_RT_PCIMP	27			/* 128 Mb */
#define	E2K_SIC_SIZE_RT_PCIMP	(1 << E2K_SIC_ALIGN_RT_PCIMP)
#define	E2K_RT_PCIMP_bgn	addr
#define	E2K_RT_PCIMP_end	addr
#define	E2K_RT_PCIMP_reg	addr

/*
 *   Read/Write RT_PCICFGB Reg
 */
typedef	unsigned int	e2k_rt_pcicfgb_t;	/* Read/write pointer (32 bits) */
typedef	struct e2k_rt_pcicfgb_fields {
	e2k_rt_pcicfgb_t	unused1	:  3;			/* [2:0] */
	e2k_rt_pcicfgb_t	bgn	:  18;			/* [20:3] */
	e2k_rt_pcicfgb_t	unused2 :  11;			/* [31:21] */
} e2k_rt_pcicfgb_fields_t;
typedef	union e2k_rt_pcicfgb_struct {		/* Structure of lower word */
	e2k_rt_pcicfgb_fields_t	fields;		/* as fields */
	e2k_rt_pcicfgb_t	word;		/* as entire register */
} e2k_rt_pcicfgb_struct_t;

#define	E2K_SIC_ALIGN_RT_PCICFGB	28		/* 256 Mb */
#define	E2K_SIC_SIZE_RT_PCICFGB		(1 << E2K_SIC_ALIGN_RT_PCICFGB)
#define	E2K_RT_PCICFGB_bgn		fields.bgn
#define	E2K_RT_PCICFGB_reg		word

/*
 *   Read/Write RT_MLOj Regs
 */
typedef	unsigned int	e2k_rt_mlo_t;	/* Read/write pointer (32 bits) */
typedef	struct e2k_rt_mlo_fields {
	e2k_rt_mlo_t   unused1 	:  11;			/* [10:0] */
	e2k_rt_mlo_t   bgn	:  5;			/* [15:11] */
	e2k_rt_mlo_t   unused2 	:  11;			/* [26:16] */
	e2k_rt_mlo_t   end	:  5;			/* [31:27] */
} e2k_rt_mlo_fields_t;
typedef	union e2k_rt_mlo_struct {		/* Structure of lower word */
	e2k_rt_mlo_fields_t	fields;		/* as fields */
	e2k_rt_mlo_t		word;		/* as entire register */
} e2k_rt_mlo_struct_t;

#define	E2K_SIC_ALIGN_RT_MLO	27		/* 128 Mb */
#define	E2K_SIC_SIZE_RT_MLO	(1 << E2K_SIC_ALIGN_RT_MLO)
#define E2K_RT_MLO_bgn		fields.bgn
#define E2K_RT_MLO_end		fields.end
#define E2K_RT_MLO_reg		word

/* memory *bank minimum size, so base address of bank align */
#define	E2K_SIC_MIN_MEMORY_BANK	(256 * 1024 * 1024)	/* 256 Mb */

/*
 *   Read/Write RT_MHIj Regs
 */
typedef	unsigned int	e2k_rt_mhi_t;	/* Read/write pointer (32 bits) */
typedef	struct e2k_rt_mhi_fields {
	e2k_rt_mhi_t	bgn	: 16;			/* [15: 0] */
	e2k_rt_mhi_t	end	: 16;			/* [31:16] */
} e2k_rt_mhi_fields_t;
typedef	union e2k_rt_mhi_struct {		/* Structure of lower word */
	e2k_rt_mhi_fields_t	fields;		/* as fields */
	e2k_rt_mhi_t		word;		/* as entire register */
} e2k_rt_mhi_struct_t;

#define	E2K_SIC_ALIGN_RT_MHI	32		/* 4 Gb */
#define	E2K_SIC_SIZE_RT_MHI	(1UL << E2K_SIC_ALIGN_RT_MHI)
#define E2K_RT_MHI_bgn		fields.bgn
#define E2K_RT_MHI_end		fields.end
#define E2K_RT_MHI_reg		word

/*
 *   Read/Write RT_IOAPICj Regs
 */
typedef	unsigned int	e2k_rt_ioapic_t;	/* Read/write pointer (32 bits) */
typedef	struct e2k_rt_ioapic_fields {
	e2k_rt_ioapic_t   unused1 : 12;			/* [11:0] */
	e2k_rt_ioapic_t	  bgn	  : 9;			/* [20:12] */
	e2k_rt_ioapic_t   unused2 : 11;			/* [31:21] */
} e2k_rt_ioapic_fields_t;
typedef	union e2k_rt_ioapic_struct {		/* Structure of lower word */
	e2k_rt_ioapic_fields_t	fields;		/* as fields */
	e2k_rt_ioapic_t		word;		/* as entire register */
} e2k_rt_ioapic_struct_t;

#define	E2K_SIC_ALIGN_RT_IOAPIC	12		/* 4 Kb */
#define	E2K_SIC_SIZE_RT_IOAPIC	(1 << E2K_SIC_ALIGN_RT_IOAPIC)
#define	E2K_SIC_IOAPIC_SIZE	E2K_SIC_SIZE_RT_IOAPIC
#define	E2K_SIC_IOAPIC_FIX_ADDR_SHIFT	21
#define	E2K_SIC_IOAPIC_FIX_ADDR_MASK	\
		~((1UL << E2K_SIC_IOAPIC_FIX_ADDR_SHIFT) - 1)
#define	E2K_RT_IOAPIC_bgn	fields.bgn
#define	E2K_RT_IOAPIC_reg	word

/*
 *   Read/Write RT_MSI Regs
 */
#define	E2K_SIC_ALIGN_RT_MSI	20		/* 1 Mb */

typedef	unsigned int	e2k_rt_msi_t;	/* Read/write pointer (low 32 bits) */
typedef	unsigned int	e2k_rt_msi_h_t;	/* Read/write pointer (high 32 bits) */
typedef	struct e2k_rt_msi_fields {
	e2k_rt_msi_t	unused	: E2K_SIC_ALIGN_RT_MSI;		/* [19:0] */
	e2k_rt_msi_t	bgn	: (32 - E2K_SIC_ALIGN_RT_MSI);	/* [31:20] */
} e2k_rt_msi_fields_t;
typedef	struct e2k_rt_msi_h_fields {
	e2k_rt_msi_h_t	bgn	: 32;				/* [63:32] */
} e2k_rt_msi_h_fields_t;
typedef	union e2k_rt_msi_struct {		/* Structure of lower word */
	e2k_rt_msi_fields_t	fields;		/* as fields */
	e2k_rt_msi_t		word;		/* as entire register */
} e2k_rt_msi_struct_t;
typedef	union e2k_rt_msi_h_struct {		/* Structure of higher word */
	e2k_rt_msi_h_fields_t	fields;		/* as fields */
	e2k_rt_msi_h_t		word;		/* as entire register */
} e2k_rt_msi_h_struct_t;

#define	E2K_SIC_SIZE_RT_MSI	(1 << E2K_SIC_ALIGN_RT_MSI)
#define	E2K_RT_MSI_bgn		fields.bgn
#define	E2K_RT_MSI_end		E2K_RT_MSI_bgn
#define	E2K_RT_MSI_reg		word
#define	E2K_RT_MSI_H_bgn	fields.bgn
#define	E2K_RT_MSI_H_end	E2K_RT_MSI_H_bgn
#define	E2K_RT_MSI_H_reg	word
#define	E2K_RT_MSI_DEFAULT_BASE	0x120000000UL

/*
 *   Read/Write ST_P Regs
 */
typedef	unsigned int	e2k_st_p_t;		/* Read/write pointer (32 bits) */
typedef	struct e2s_st_p_fields {
	e2k_st_p_t   	type 		: 4;		/* [3:0] */
	e2k_st_p_t	id		: 8;		/* [11:4] */
	e2k_st_p_t   	pn	 	: 8;		/* [19:12] */
	e2k_st_p_t   	coh_on	 	: 1;		/* [20] */
	e2k_st_p_t   	pl_val 		: 3;		/* [23:21] */
	e2k_st_p_t   	mlc 		: 1;		/* [24] */
	e2k_st_p_t   	unused 		: 7;		/* [31:25] */
} e2s_st_p_fields_t;
typedef e2s_st_p_fields_t	e8c_st_p_fields_t;
typedef	union e2k_st_p_struct {			/* Structure of lower word */
	e2s_st_p_fields_t	e2s_fields;	/* as fields for e2s */
	e2k_st_p_t		word;		/* as entire register */
} e2k_st_p_struct_t;

#define	E2S_ST_P_type		e2s_fields.type
#define	E2S_ST_P_id		e2s_fields.id
#define	E2S_ST_P_coh_on		e2s_fields.coh_on
#define	E2S_ST_P_pl_val		e2s_fields.pl_val
#define	E2S_ST_P_mlc		e2s_fields.mlc
#define	E2S_ST_P_pn		e2s_fields.pn 
#define	E2S_ST_P_reg		word

#define	E8C_ST_P_type		E2S_ST_P_type
#define	E8C_ST_P_id		E2S_ST_P_id
#define	E8C_ST_P_coh_on		E2S_ST_P_coh_on
#define	E8C_ST_P_pl_val		E2S_ST_P_pl_val
#define	E8C_ST_P_mlc		E2S_ST_P_mlc
#define	E8C_ST_P_pn		E2S_ST_P_pn
#define	E8C_ST_P_reg		E2S_ST_P_reg

#define	E2K_ST_P_type		E2S_ST_P_type
#define	E2K_ST_P_reg		E2S_ST_P_reg

#define	E2K_ST_P_pl_val		E2S_ST_P_pl_val
#define	E2K_ST_P_mlc		E2S_ST_P_mlc
#define	E2K_ST_P_pn		E2S_ST_P_pn

/*
 *   ST_CORE core state register
 */
struct e2k_st_core_fields {
	u32 val		:  1;	/* [0] */
	u32 wait_init	:  1;	/* [1] */
	u32 wait_trap	:  1;	/* [2] */
	u32 stop_dbg	:  1;	/* [3] */
	u32 clk_off	:  1;	/* [4] */
	u32 unused	: 27;	/* [31:5] */
};
typedef	union {
	struct {
		u32 : 5;
		u32 pmc_rst	: 1; /* [5] */
		u32 : 26;
	} e1cp;
	struct {
		u32 val		:  1;	/* [0] */
		u32 wait_init	:  1;	/* [1] */
		u32 wait_trap	:  1;	/* [2] */
		u32 stop_dbg	:  1;	/* [3] */
		u32 clk_off	:  1;	/* [4] */
		u32 unused	: 27;	/* [31:5] */
	};
	struct e2k_st_core_fields fields;	/* as fields for e2k */
	u32 word;				/* as entire register */
} e2k_st_core_t;

#define	E2K_ST_CORE_val(__reg)		((__reg).fields.val)
#define	E2K_ST_CORE_wait_init(__reg)	((__reg).fields.wait_init)
#define	E2K_ST_CORE_wait_trap(__reg)	((__reg).fields.wait_trap)
#define	E2K_ST_CORE_stop_dbg(__reg)	((__reg).fields.stop_dbg)
#define	E2K_ST_CORE_clk_off(__reg)	((__reg).fields.clk_off)
#define	E2K_ST_CORE_reg(__reg)		((__reg).word)

#define	E2S_ST_CORE_val		E2K_ST_CORE_val
#define	E2S_ST_CORE_wait_init	E2K_ST_CORE_wait_init
#define	E2S_ST_CORE_wait_trap	E2K_ST_CORE_wait_trap
#define	E2S_ST_CORE_stop_dbg	E2K_ST_CORE_stop_dbg
#define	E2S_ST_CORE_clk_off	E2K_ST_CORE_clk_off
#define	E2S_ST_CORE_reg		E2K_ST_CORE_reg

#define	E8C_ST_CORE_val		E2K_ST_CORE_val
#define	E8C_ST_CORE_wait_init	E2K_ST_CORE_wait_init
#define	E8C_ST_CORE_wait_trap	E2K_ST_CORE_wait_trap
#define	E8C_ST_CORE_stop_dbg	E2K_ST_CORE_stop_dbg
#define	E8C_ST_CORE_clk_off	E2K_ST_CORE_clk_off
#define	E8C_ST_CORE_reg		E2K_ST_CORE_reg

#define E1CP_ST_CORE_val         E2K_ST_CORE_val
#define E1CP_ST_CORE_wait_init   E2K_ST_CORE_wait_init
#define E1CP_ST_CORE_wait_trap   E2K_ST_CORE_wait_trap
#define E1CP_ST_CORE_stop_dbg    E2K_ST_CORE_stop_dbg
#define E1CP_ST_CORE_clk_off     E2K_ST_CORE_clk_off
#define E1CP_ST_CORE_pmc_rst(__reg)	((__reg).fields.pmc_rst)
#define E1CP_ST_CORE_reg         E2K_ST_CORE_reg

/*
 *   IO Link control state register
 */
typedef	unsigned int	e2k_iol_csr_t;		/* single word (32 bits) */
typedef	struct e2k_iol_csr_fields {
	e2k_iol_csr_t	mode 		: 1;		/* [0] */
	e2k_iol_csr_t	abtype		: 7;		/* [7:1] */
	e2k_iol_csr_t  	unused 		: 24;		/* [31:8] */
} e2k_iol_csr_fields_t;
typedef	union e2k_iol_csr_struct {		/* Structure of word */
	e2k_iol_csr_fields_t	fields;		/* as fields */
	e2k_iol_csr_t		word;		/* as entire register */
} e2k_iol_csr_struct_t;

#define	E2K_IOL_CSR_mode	fields.mode	/* type of controller */
						/* on the link */
#define	E2K_IOL_CSR_abtype	fields.abtype	/* type of abonent */
						/* on the link */
#define	E2K_IOL_CSR_reg		word
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
typedef	unsigned int	e2k_io_csr_t;		/* single word (32 bits) */
typedef	struct e2k_io_csr_fields {
	e2k_io_csr_t	srst 		: 1;		/* [0] */
	e2k_io_csr_t	unused1		: 3;		/* [3:1] */
	e2k_io_csr_t	bsy_ie		: 1;		/* [4] */
	e2k_io_csr_t	err_ie		: 1;		/* [5] */
	e2k_io_csr_t	to_ie		: 1;		/* [6] */
	e2k_io_csr_t	lsc_ie		: 1;		/* [7] */
	e2k_io_csr_t	unused2		: 4;		/* [11:8] */
	e2k_io_csr_t	bsy_ev		: 1;		/* [12] */
	e2k_io_csr_t	err_ev		: 1;		/* [13] */
	e2k_io_csr_t	to_ev		: 1;		/* [14] */
	e2k_io_csr_t	lsc_ev		: 1;		/* [15] */
	e2k_io_csr_t	unused3		: 14;		/* [29:16] */
	e2k_io_csr_t	link_tu		: 1;		/* [30] */
	e2k_io_csr_t	ch_on		: 1;		/* [31] */
} e2k_io_csr_fields_t;
typedef	union e2k_io_csr_struct {		/* Structure of word */
	e2k_io_csr_fields_t	fields;		/* as fields */
	e2k_io_csr_t		word;		/* as entire register */
} e2k_io_csr_struct_t;

#define	E2K_IO_CSR_srst		fields.srst	/* sofrware reset flag */
#define	E2K_IO_CSR_bsy_ie	fields.bsy_ie	/* flag of interrupt enable */
						/* on receiver busy */
#define	E2K_IO_CSR_err_ie	fields.err_ie	/* flag of interrupt enable */
						/* on CRC-error */
#define	E2K_IO_CSR_to_ie	fields.to_ie	/* flag of interrupt enable */
						/* on timeout */
#define	E2K_IO_CSR_lsc_ie	fields.lsc_ie	/* flag of interrupt enable */
						/* on link state changed */
#define	E2K_IO_CSR_bsy_ev	fields.bsy_ev	/* flag of interrupt */
						/* on receiver busy */
#define	E2K_IO_CSR_err_ev	fields.err_ev	/* flag of interrupt */
						/* on CRC-error */
#define	E2K_IO_CSR_to_ev	fields.to_ev	/* flag of interrupt */
						/* on timeout */
#define	E2K_IO_CSR_lsc_ev	fields.lsc_ev	/* flag of interrupt */
						/* on link state changed */
#define	E2K_IO_CSR_link_tu	fields.link_tu	/* flag of trening */
						/* in progress */
#define	E2K_IO_CSR_ch_on	fields.ch_on	/* flag of chanel */
						/* is ready and online */
#define	E2K_IO_CSR_reg		word
#define	IO_IS_ON_IO_CSR		1		/* IO controller is ready */
						/* and online */
/*
 *   IO channel statistic register
 */
typedef	unsigned int	e2k_io_str_t;		/* single word (32 bits) */
typedef	struct e2k_io_str_fields {
	e2k_io_str_t	rc		: 24;		/* [23:0] */
	e2k_io_str_t	rcol		: 1;		/* [24] */
	e2k_io_str_t	reserved	: 4;		/* [28:25] */
	e2k_io_str_t	bsy_rce		: 1;		/* [29] */
	e2k_io_str_t	err_rce		: 1;		/* [30] */
	e2k_io_str_t	to_rce		: 1;		/* [31] */
} e2k_io_str_fields_t;
typedef	union e2k_io_str_struct {		/* Structure of word */
	e2k_io_str_fields_t	fields;		/* as fields */
	e2k_io_str_t		word;		/* as entire register */
} e2k_io_str_struct_t;

#define	E2K_IO_STR_rc		fields.rc	/* repeat counter */
#define	E2K_IO_STR_rcol		fields.rcol	/* repeat counter overload */
#define	E2K_IO_STR_bsy_rce	fields.bsy_rce	/* busy repeat count enable */
#define	E2K_IO_STR_err_rce	fields.err_rce	/* CRC-error repeat count */
						/* enable */
#define	E2K_IO_STR_to_rce	fields.to_rce	/* TO repeat count enable */
#define	E2K_IO_STR_reg		word

/*
 *   RDMA controller state register
 */
typedef	unsigned int	e2k_rdma_cs_t;		/* single word (32 bits) */
typedef	struct e2k_rdma_cs_fields {
	e2k_rdma_cs_t	ptocl		: 16;		/* [15:0] */
	e2k_rdma_cs_t	unused1		: 10;		/* [25:16] */
	e2k_rdma_cs_t	srst 		: 1;		/* [26] */
	e2k_rdma_cs_t	mor		: 1;		/* [27] */
	e2k_rdma_cs_t	mow		: 1;		/* [28] */
	e2k_rdma_cs_t	fch_on		: 1;		/* [29] */
	e2k_rdma_cs_t	link_tu		: 1;		/* [30] */
	e2k_rdma_cs_t	ch_on		: 1;		/* [31] */
} e2k_rdma_cs_fields_t;
typedef	union e2k_rdma_cs_struct {		/* Structure of word */
	e2k_rdma_cs_fields_t	fields;		/* as fields */
	e2k_rdma_cs_t		word;		/* as entire register */
} e2k_rdma_cs_struct_t;

#define	E2K_RDMA_CS_ptocl	fields.ptocl	/* timeout clock */
#define	E2K_RDMA_CS_srst	fields.srst	/* sofrware reset flag */
#define	E2K_RDMA_CS_mor		fields.mor	/* flag of not completed */
						/* readings */
#define	E2K_RDMA_CS_mow		fields.mow	/* flag of not completed */
						/* writings */
#define	E2K_RDMA_CS_fch_on	fields.fch_on	/* flag of chanel */
						/* forced set on */
#define	E2K_RDMA_CS_link_tu	fields.link_tu	/* flag of trenning */
						/* in progress */
#define	E2K_RDMA_CS_ch_on	fields.ch_on	/* flag of chanel */
						/* is ready and online */
#define	E2K_RDMA_CS_reg		word

/*
 *   Read/Write PWR_MGR0 register
 */
struct e2k_pwr_mgr_fields {
	u32 core0_clk	:  1;	/* [0] */
	u32 core1_clk	:  1;	/* [1] */
	u32 ic_clk	:  1;	/* [2] */
	u32 unused1	:  13;	/* [15:3] */
	u32 snoop_wait	:  2;	/* [17:16] */
	u32 unused2	:  14;	/* [31:18] */
};
typedef union {
	struct {
		u32 core0_clk	:  1;	/* [0] */
		u32 core1_clk	:  1;	/* [1] */
		u32 ic_clk	:  1;	/* [2] */
		u32 unused1	:  13;	/* [15:3] */
		u32 snoop_wait	:  2;	/* [17:16] */
		u32 unused2	:  14;	/* [31:18] */
	};
	struct e2k_pwr_mgr_fields fields;	/* as fields */
	u32 word;				/* as entire register */
} e2k_pwr_mgr_t;

#define E2K_PWR_MGR0_core0_clk	fields.core0_clk    /* core #0 clock on/off  */
#define E2K_PWR_MGR0_core1_clk	fields.core1_clk    /* core #1 clock on/off  */
#define E2K_PWR_MGR0_ic_clk	fields.ic_clk       /* dsp clock on/off   */
#define E2K_PWR_MGR0_snoop_wait	fields.snoop_wait   /* delay before off   */
                                                    /* for snoop-requests */
                                                    /* handling           */
#define E2K_PWR_MGR0_reg	word

/*
 * Monitor control register (SIC_MCR)
 */
typedef unsigned int	e2k_sic_mcr_t;		/* single word (32 bits) */
typedef struct e2k_sic_mcr_fields {
	e2k_sic_mcr_t	v0		: 1;		/* [0] */
	e2k_sic_mcr_t	unused1		: 1;		/* [1] */
	e2k_sic_mcr_t	es0		: 6;		/* [7:2] */
	e2k_sic_mcr_t	v1		: 1;		/* [8] */
	e2k_sic_mcr_t	unused2		: 1;		/* [9] */
	e2k_sic_mcr_t	es1		: 6;		/* [15:10] */
	e2k_sic_mcr_t	mcn		: 5;		/* [20:16] */
	e2k_sic_mcr_t	mcnmo		: 1;		/* [21:21] */
	e2k_sic_mcr_t	unused3		: 10;		/* [31:22] */
} e2k_sic_mcr_fields_t;
typedef union e2k_sic_mcr_struct {		/* Structure of word */
	e2k_sic_mcr_fields_t	fields;		/* as fields */
	e2k_sic_mcr_t		word;		/* as entire register */
} e2k_sic_mcr_struct_t;

#define E2K_SIC_MCR_v0		fields.v0	/* monitor #0 valid */
#define E2K_SIC_MCR_es0		fields.es0	/* monitor #0 event */
						/* specifier */
#define E2K_SIC_MCR_v1		fields.v1	/* monitor #1 valid */
#define E2K_SIC_MCR_es1		fields.es1	/* monitor #1 event */
						/* specifier */
#define E2K_SIC_MCR_reg		word

/*
 * Monitor accumulator register hi part (SIC_MAR0_hi, SIC_MAR1_hi)
 */
typedef unsigned int	e2k_sic_mar_hi_t;	/* single word (32 bits) */
typedef struct e2k_sic_mar_hi_fields {
	e2k_sic_mar_hi_t	val	: 31;	/* [30:0] */
	e2k_sic_mar_hi_t	of	: 1;	/* [31] */
} e2k_sic_mar_hi_fields_t;
typedef union e2k_sic_mar_hi_struct {		/* Structure of word */
	e2k_sic_mar_hi_fields_t	fields;		/* as fields */
	e2k_sic_mar_hi_t	word;		/* as entire register */
} e2k_sic_mar_hi_struct_t;

#define E2K_SIC_MAR_HI_val	fields.val	/* high part of events */
						/* counter */
#define E2K_SIC_MAR_HI_of	fields.of	/* overflow flag */
#define E2K_SIC_MAR_HI_reg	word

/*
 * Monitor accumulator register lo part (SIC_MAR0_lo, SIC_MAR1_lo)
 */
typedef unsigned int	e2k_sic_mar_lo_t;	/* single word (32 bits) */

#define E2K_SIC_MAR_LO_val	fields.val	/* low part of events */
						/* counter */
#define E2K_SIC_MAR_LO_reg	word

/*
 * Read/Write MCX_ECC (X={0, 1, 2, 3}) registers
 */
typedef	unsigned int	e2k_mc_ecc_t;	/* single word (32 bits) */
typedef	struct e2k_mc_ecc_fields {
	e2k_mc_ecc_t	ee		: 1;	/* [0] */
	e2k_mc_ecc_t	dmode		: 1;	/* [1] */
	e2k_mc_ecc_t	of		: 1;	/* [2] */
	e2k_mc_ecc_t	ue		: 1;	/* [3] */
	e2k_mc_ecc_t	reserved	: 12;	/* [15:4] */
	e2k_mc_ecc_t	secnt		: 16;	/* [31:16] */
} e2k_mc_ecc_fields_t;
typedef	union e2k_mc_ecc_struct {		/* Structure word */
	e2k_mc_ecc_fields_t	fields;		/* as fields */
	e2k_mc_ecc_t		word;		/* as entire register */
} e2k_mc_ecc_struct_t;

#define E2K_MC_ECC_ee		fields.ee	/* ECC mode on/off */
#define E2K_MC_ECC_dmode	fields.dmode	/* diagnostic mode on/off */
#define E2K_MC_ECC_of		fields.of	/* single error counter */
						/* overflow flag */
#define E2K_MC_ECC_ue		fields.ue	/* multiple-error flag */
#define E2K_MC_ECC_secnt	fields.secnt	/* single error counter */
#define E2K_MC_ECC_reg		word


/*
 * Read/Write MCX_OPMb (X={0, 1, 2, 3}) registers
 * ! only for P1 processor type !
 */
typedef	unsigned int	e2k_mc_opmb_t;	/* single word (32 bits) */
typedef	struct e2k_mc_opmb_fields {
	e2k_mc_opmb_t	ct0		: 3;	/* [0:2] */
	e2k_mc_opmb_t	ct1		: 3;	/* [3:5] */
	e2k_mc_opmb_t	pbm0		: 2;	/* [6:7] */
	e2k_mc_opmb_t	pbm1		: 2;	/* [8:9] */
	e2k_mc_opmb_t	rm		: 1;	/* [10] */
	e2k_mc_opmb_t	rdodt		: 1;	/* [11] */
	e2k_mc_opmb_t	wrodt		: 1;	/* [12] */
	e2k_mc_opmb_t	bl8int		: 1;	/* [13] */
	e2k_mc_opmb_t	mi_fast		: 1;	/* [14] */
	e2k_mc_opmb_t	mt		: 1;	/* [15] */
	e2k_mc_opmb_t	il		: 1;	/* [16] */
	e2k_mc_opmb_t	rcven_del	: 2;	/* [17:18] */
	e2k_mc_opmb_t	mc_ps		: 1;	/* [19] */
	e2k_mc_opmb_t	arp_en		: 1;	/* [20] */
	e2k_mc_opmb_t	flt_brop	: 1;	/* [21] */
	e2k_mc_opmb_t	flt_rdpr	: 1;	/* [22] */
	e2k_mc_opmb_t	flt_blk		: 1;	/* [23] */
	e2k_mc_opmb_t	parerr		: 1;	/* [24] */
	e2k_mc_opmb_t	cmdpack		: 1;	/* [25] */
	e2k_mc_opmb_t	sldwr		: 1;	/* [26] */
	e2k_mc_opmb_t	sldrd		: 1;	/* [27] */
	e2k_mc_opmb_t	mirr		: 1;	/* [28] */
	e2k_mc_opmb_t	twrwr		: 2;	/* [29:30] */
	e2k_mc_opmb_t	mcln		: 1;	/* [31] */
} e2k_mc_opmb_fields_t;
typedef	union e2k_mc_opmb_struct {		/* Structure word */
	e2k_mc_opmb_fields_t	fields;		/* as fields */
	e2k_mc_opmb_t		word;		/* as entire register */
} e2k_mc_opmb_struct_t;

#define E2K_MC_OPMB_pbm0	fields.pbm0	/* physycal bank map slot 0 */
#define E2K_MC_OPMB_pbm1	fields.pbm1	/* physycal bank map slot 1 */
#define E2K_MC_OPMB_reg		word

/*
 * Read/Write MCX_CFG (X={0, 1, 2, 3}) registers
 * P9, E2C3, E12 and E16 processor type
 */
typedef	unsigned int	e2k_mc_cfg_t;	/* single word (32 bits) */
typedef	struct e2k_mc_cfg_fields {
	e2k_mc_cfg_t	ct0		: 3;	/* [0:2] */
	e2k_mc_cfg_t	ct1		: 3;	/* [3:5] */
	e2k_mc_cfg_t	pbm0		: 2;	/* [6:7] */
	e2k_mc_cfg_t	pbm1		: 2;	/* [8:9] */
	e2k_mc_cfg_t	rm		: 1;	/* [10] */
	e2k_mc_cfg_t	reserve1	: 2;	/* [11:12] */
	e2k_mc_cfg_t	mirr		: 1;	/* [13] */
	e2k_mc_cfg_t	sf		: 3;	/* [14:16] */
	e2k_mc_cfg_t	mt		: 1;	/* [17] */
	e2k_mc_cfg_t	cs8		: 1;	/* [18] */
	e2k_mc_cfg_t	ptrr_mode	: 2;	/* [19:20] */
	e2k_mc_cfg_t	mcrc		: 1;	/* [21] */
	e2k_mc_cfg_t	odt_ext		: 2;	/* [22:23] */
	e2k_mc_cfg_t	pbswap		: 1;	/* [24] */
	e2k_mc_cfg_t	dqw		: 2;	/* [25:26] */
	e2k_mc_cfg_t	pda_sel		: 5;	/* [27:31] */
} e2k_mc_cfg_fields_t;
typedef	union e2k_mc_cfg_struct {		/* Structure word */
	e2k_mc_cfg_fields_t	fields;		/* as fields */
	e2k_mc_cfg_t		word;		/* as entire register */
} e2k_mc_cfg_struct_t;

#define E2K_MC_CFG_pbm0		fields.pbm0	/* physycal bank map slot 0 */
#define E2K_MC_CFG_pbm1		fields.pbm1	/* physycal bank map slot 1 */
#define E2K_MC_CFG_reg		word

/*
 * Read/Write IPCC_CSRX (X={1, 2, 3}) registers
 */
typedef	unsigned int	e2k_ipcc_csr_t;	/* single word (32 bits) */
typedef	struct e2k_ipcc_csr_fields {
	e2k_ipcc_csr_t	link_scale	: 4;	/* [3:0] */
	e2k_ipcc_csr_t	cmd_code	: 3;	/* [6:4] */
	e2k_ipcc_csr_t	cmd_active	: 1;	/* [7] */
	e2k_ipcc_csr_t	reserved	: 1;	/* [8] */
	e2k_ipcc_csr_t	terr_vc_num	: 3;	/* [11:9] */
	e2k_ipcc_csr_t	rx_oflw_uflw	: 1;	/* [12] */
	e2k_ipcc_csr_t	event_imsk	: 3;	/* [15:13] */
	e2k_ipcc_csr_t	ltssm_state	: 5;	/* [20:16] */
	e2k_ipcc_csr_t	cmd_cmpl_sts	: 3;	/* [23:21] */
	e2k_ipcc_csr_t	link_width	: 4;	/* [27:24] */
	e2k_ipcc_csr_t	event_sts	: 3;	/* [30:28] */
	e2k_ipcc_csr_t	link_state	: 1;	/* [31] */
} e2k_ipcc_csr_fields_t;
typedef	union e2k_ipcc_csr_struct {		/* Structure word */
	e2k_ipcc_csr_fields_t	fields;		/* as fields */
	e2k_ipcc_csr_t		word;		/* as entire register */
} e2k_ipcc_csr_struct_t;

#define E2K_IPCC_CSR_link_scale		fields.link_scale
#define E2K_IPCC_CSR_cmd_code		fields.cmd_code
#define E2K_IPCC_CSR_cmd_active		fields.cmd_active
#define E2K_IPCC_CSR_terr_vc_num	fields.terr_vc_num
#define E2K_IPCC_CSR_rx_oflw_uflw	fields.rx_oflw_uflw
#define E2K_IPCC_CSR_event_imsk		fields.event_imsk
#define E2K_IPCC_CSR_ltssm_state	fields.ltssm_state
#define E2K_IPCC_CSR_cmd_cmpl_sts	fields.cmd_cmpl_sts
#define E2K_IPCC_CSR_link_width		fields.link_width
#define E2K_IPCC_CSR_event_sts		fields.event_sts
#define E2K_IPCC_CSR_link_state		fields.link_state
#define E2K_IPCC_CSR_reg		word

/*
 * Read/Write IPCC_STRX (X={1, 2, 3}) registers
 */
typedef	unsigned int	e2k_ipcc_str_t;	/* single word (32 bits) */
typedef	struct e2k_ipcc_str_fields {
	e2k_ipcc_str_t	ecnt		: 29;	/* [28:0] */
	e2k_ipcc_str_t	eco		: 1;	/* [29] */
	e2k_ipcc_str_t	ecf		: 2;	/* [31:30] */
} e2k_ipcc_str_fields_t;
typedef	union e2k_ipcc_str_struct {		/* Structure word */
	e2k_ipcc_str_fields_t	fields;		/* as fields */
	e2k_ipcc_str_t		word;		/* as entire register */
} e2k_ipcc_str_struct_t;

#define E2K_IPCC_STR_ecnt	fields.ecnt	/* event counter */
#define E2K_IPCC_STR_eco	fields.eco	/* event counter overflow */
#define E2K_IPCC_STR_ecf	fields.ecf	/* event counter filter */
#define E2K_IPCC_STR_reg	word

/*
 * Read/Write SIC_SCCFG register
 */
typedef	unsigned int	e2k_sic_sccfg_t;	/* single word (32 bits) */
typedef	struct e2k_sic_sccfg_fields {
	e2k_sic_sccfg_t	diren		: 1;	/* [0] */
	e2k_sic_sccfg_t	dircacheen	: 1;	/* [1] */
	e2k_sic_sccfg_t	unused		: 30;	/* [31:2] */
} e2k_sic_sccfg_fields_t;
typedef	union e2k_sic_sccfg_struct {		/* Structure word */
	e2k_sic_sccfg_fields_t	fields;		/* as fields */
	e2k_sic_sccfg_t		word;		/* as entire register */
} e2k_sic_sccfg_struct_t;

#define E2K_SIC_SCCFG_diren	 fields.diren	   /* directory enabled */
#define E2K_SIC_SCCFG_dircacheen fields.dircacheen /* directory cache enabled */
#define E2K_SIC_SCCFG_reg	 word

/*
 * Cache L3 registers structures
 */
/* Control register */
typedef	unsigned int	l3_reg_t;	/* Read/write register (32 bits) */
typedef	struct l3_ctrl_fields {
	l3_reg_t fl		:  1;	/* [0] flush L3 */
	l3_reg_t cl		:  1;	/* [1] clear L3 */
	l3_reg_t rdque		:  1;	/* [2] read queues */
	l3_reg_t rnc_rrel	:  1;	/* [3] wait RREL for Rnc */
	l3_reg_t lru_separate	:  1;	/* [4] LRU separate */
	l3_reg_t pipe_ablk_s1	:  1;	/* [5] pipe address block S1 */
	l3_reg_t pipe_ablk_s2	:  1;	/* [6] pipe address block S2 */
	l3_reg_t sleep_blk	:  1;	/* [7] sleep block */
	l3_reg_t wbb_forced	:  1;	/* [8] WBB forced */
	l3_reg_t wbb_refill	:  1;	/* [9] WBB refill */
	l3_reg_t wbb_timeron	:  1;	/* [10] WBB release on timer */
	l3_reg_t wbb_timer	:  7;	/* [17:11] WBB timer set */
	l3_reg_t wbb_tfullon	:  1;	/* [18] WBB release on timer */
					/*      at full state */
	l3_reg_t wbb_tfull	:  7;	/* [25:19] WBB timer at full */
					/*         state set */
	l3_reg_t seal_gblk	:  1;	/* [26] sealed global block */
	l3_reg_t seal_lblk	:  1;	/* [27] sealed local block */
	l3_reg_t reserved	:  4;	/* [31:28] reserved bits */
} l3_ctrl_fields_t;
typedef	union l3_ctrl {		/* Structure word */
	l3_ctrl_fields_t	fields;		/* as fields */
	l3_reg_t		word;		/* as entire register */
} l3_ctrl_t;

#define E2K_L3_CTRL_fl			fields.fl
#define E2K_L3_CTRL_cl			fields.cl
#define E2K_L3_CTRL_rdque		fields.rdque
#define E2K_L3_CTRL_rnc_rrel		fields.rnc_rrel
#define E2K_L3_CTRL_lru_separate	fields.lru_separate
#define E2K_L3_CTRL_pipe_ablk_s1	fields.pipe_ablk_s1
#define E2K_L3_CTRL_pipe_ablk_s2	fields.pipe_ablk_s2
#define E2K_L3_CTRL_sleep_blk		fields.sleep_blk
#define E2K_L3_CTRL_wbb_forced		fields.wbb_forced
#define E2K_L3_CTRL_wbb_refill		fields.wbb_refill
#define E2K_L3_CTRL_wbb_timeron		fields.wbb_timeron
#define E2K_L3_CTRL_wbb_timer		fields.wbb_timer
#define E2K_L3_CTRL_wbb_tfullon		fields.wbb_tfullon
#define E2K_L3_CTRL_wbb_tfull		fields.wbb_tfull
#define E2K_L3_CTRL_seal_gblk		fields.seal_gblk
#define E2K_L3_CTRL_seal_lblk		fields.seal_lblk
#define	E2K_L3_CTRL_reg			word

/*
 * Read/Write BC_MP_T_CORR register
 */
typedef unsigned int bc_mp_t_corr_t;	/* single word (32 bits) */
typedef struct bc_mp_t_corr_fields {
	bc_mp_t_corr_t corr	: 1;	/* [0] */
	bc_mp_t_corr_t value	: 1;	/* [1] */
	bc_mp_t_corr_t unused	: 10;	/* [11:2] */
	bc_mp_t_corr_t addr	: 20;	/* [31:12] */
} bc_mp_t_corr_fields_t;
typedef union bc_mp_t_corr_struct {	/* Structure word */
	bc_mp_t_corr_fields_t	fields;	/* as fields */
	bc_mp_t_corr_t		word;	/* as entire register */
} bc_mp_t_corr_struct_t;

#define E2K_MP_T_CORR_corr	fields.corr
#define E2K_MP_T_CORR_value	fields.value
#define E2K_MP_T_CORR_addr	fields.addr
#define E2K_MP_T_CORR_reg	word

/*
 * Read/Write BC_MP_T_CORR_H
 */
typedef unsigned int bc_mp_t_corr_h_t;	/* single word (32 bits) */
typedef struct bc_mp_t_corr_h_fields {
	bc_mp_t_corr_h_t addr;		/* [31:0]*/
} bc_mp_t_corr_h_fields_t;
typedef union bc_mp_t_corr_h_struct {	/* Structure word */
	bc_mp_t_corr_h_fields_t	fields;	/* as fields */
	bc_mp_t_corr_h_t	word;	/* as entire register */
} bc_mp_t_corr_h_struct_t;

#define E2K_MP_T_CORR_H_addr	fields.addr
#define E2K_MP_T_CORR_H_reg	word

/*
 * Read/Write BC_MP_CTRL register
 */
typedef unsigned int bc_mp_ctrl_t;	/* single word (32 bits) */
typedef struct bc_mp_ctrl_fields {
	bc_mp_ctrl_t unused0	: 12;	/* [11:0] */
	bc_mp_ctrl_t mp_en	: 1;	/* [12] */
	bc_mp_ctrl_t b_en	: 1;	/* [13] */
	bc_mp_ctrl_t unused1	: 18;	/* [31:14] */
} bc_mp_ctrl_fields_t;
typedef union bc_mp_ctrl_struct {	/* Structure word */
	bc_mp_ctrl_fields_t	fields;	/* as fields */
	bc_mp_ctrl_t		word;	/* as entire register */
} bc_mp_ctrl_struct_t;

#define E2K_MP_CTRL_mp_en	fields.mp_en
#define E2K_MP_CTRL_b_en	fields.b_en
#define E2K_MP_CTRL_reg		word

/*
 * Read/Write BC_MP_STAT register
 */
typedef unsigned int bc_mp_stat_t;	/* single word (32 bits) */
typedef struct bc_mp_stat_fields {
	bc_mp_stat_t unused0	: 12;	/* [11:0] */
	bc_mp_stat_t b_ne	: 1;	/* [12] */
	bc_mp_stat_t b_of	: 1;	/* [13] */
	bc_mp_stat_t unused1	: 18;	/* [31:14] */
} bc_mp_stat_fields_t;
typedef union bc_mp_stat_struct {	/* Structure word */
	bc_mp_stat_fields_t	fields;	/* as fields */
	bc_mp_stat_t		word;	/* as entire register */
} bc_mp_stat_struct_t;

#define E2K_MP_STAT_b_ne	fields.b_ne
#define E2K_MP_STAT_b_of	fields.b_of
#define E2K_MP_STAT_reg		word

#endif /* ! __ASSEMBLY__ */
#endif /* __KERNEL__ */
#endif  /* _E2K_SIC_REGS_H_ */
