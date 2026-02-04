/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

#include <asm/types.h>


#define	SIC_rt_msi	0xb0
#define	SIC_rt_msi_h	0xb4

/* Host Controller */
#define HC_CTRL		0x0340

/* HC monitors */
#define HC_MCR		0x360
#define HC_MID		0x364
#define HC_MAR0_LO	0x368
#define HC_MAR0_HI	0x36c
#define HC_MAR1_LO	0x370
#define HC_MAR1_HI	0x374

/* IOMMU monitors - all processors */
#define IOMMU_MCR	0x3c0
#define IOMMU_MID	0x3c4
#define IOMMU_MAR0_LO	0x3c8
#define IOMMU_MAR0_HI	0x3cc
#define IOMMU_MAR1_LO	0x3d0
#define IOMMU_MAR1_HI	0x3d4

/* Additional IOMMU monitors - e2c3 only.
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

/* MC monitors */
#define MC_CH		0x400
#define MC_CTL		0x404
#define MC_CFG		0x418
#define MC_PERF		0x41c
#define MC_OPMB		0x424
#define MC_PWR		0x430
#define MC_ECC		0x440
/* Use e2k suffix to avoid conflict with Radeon */
#define MC_STATUS_E2K	0x44c
#define MC_MON_CTL	0x450
#define MC_MON_CTR0	0x454
#define MC_MON_CTR1	0x458
#define MC_MON_CTRext	0x45c
/* Added in v7 */
#define MC_ECCDIAG	0x444
#define MCNA_CTRL	0x4c0
#define MCNA_INT	0x4c4
#define MCNA_DIAG_ADDR	0x4c8
#define MCNA_DIAG_DATA	0x4cc

/* HMU monitors */
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

/* HMU regs replaced in v7 */
#define HA_BASC		0xd00
#define HA_MCR		0xd14

/* Local HA regs offsets */
#define LOC_HA_BASC(ha_bank) (0xd40 + (ha_bank << 2))
#define HA_INT		0
#define HA_MAR_LO(i)	(4 + 8 * (i))
#define HA_MAR_HI(i)	(8 + 8 * (i))

/* XMU regs */
#define XMU_L_INT_M	0xc64

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

/* OCN regs */
#define OCN_MIL		0x3804
#define OCN_L3EN0	0x3810
#define OCN_L3EN1	0x3814
#define OCN_LASC	0x3840
#define OCN_LASR(i)	(0x3a00 + ((i) << 2))
#define OCN_PAR(i)	(0 + ((i) << 2))

/* PREPIC monitors */
#define PREPIC_MCR	0x8070
#define PREPIC_MID	0x8074
#define PREPIC_MAR0_LO	0x8080
#define PREPIC_MAR0_HI	0x8084
#define PREPIC_MAR1_LO	0x8090
#define PREPIC_MAR1_HI	0x8094

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
		u32 ct0		: 4;
		u32 ct1		: 4;
		u32 pbm0	: 2;
		u32 pbm1	: 2; /* [11 : 10] */
		u32 rm		: 1;
		u32 ds3		: 2; /* 3ds */
		u32 mtad_dsbl	: 1;
		u32 sf		: 4;
		u32		: 1; /* [20] */
		u32 ptrr_mode	: 2;
		u32 oddpb_crc_calc_alt_dis	: 1;
		u32 ca_sdr_en	: 1;
		u32 poison_dsbl	: 1;
		u32 pbswap	: 1;
		u32 pda_sel	: 5;
	};
	struct {
		u32		: 8;
		u32 pbm		: 4;
	};
	u32 word;
} e2k_e48c_mc_cfg_t;

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
