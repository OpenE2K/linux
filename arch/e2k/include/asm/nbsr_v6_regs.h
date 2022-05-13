#pragma once

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
#define MC_CFG		0x418
#define MC_OPMB		0x424
#define MC_ECC		0x440
#define MC_STATUS	0x44c
#define MC_MON_CTL	0x450
#define MC_MON_CTR0	0x454
#define MC_MON_CTR1	0x458
#define MC_MON_CTRext	0x45c

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
 * MC status register (MC_STATUS)
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
		u32 __unused		: 6;
	};
	u32 word;
} e2k_mc_status_t;

/*
 * MC channel select register (MC_CH)
 */
typedef union {
	struct {
		u32 n	     : 4;
		u32 __unused : 28;
	};
	u32 word;
} e2k_mc_ch_t;

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
