/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * HW_CHECK kernel module for e2k platforms
 * e8c, e8c2, e16c, e2c3, e12c, e8v7
 */

#define EFUSE_START_ADDR 0x0
#define EFUSE_END_ADDR 0xff
#define EFUSE_RAM_ADDR_SHIFT 0x0
#define EFUSE_RAM_DATA_SHIFT 0x4

#define FIRST_SUB_BLOCK				(1 << 5)
#define SECOND_SUB_BLOCK			(1 << 6)
#define THIRD_SUB_BLOCK				(1 << 7)
#define FOURTH_SUB_BLOCK			(1 << 8)
#define F_REF						100
#define DEF_PLL_CLKR_E8V7			0x0
#define DEF_PLL_CLKOD_E8V7			0x0
#define DEF_PLL_CORE_CLKF_E8V7		0x2800000000
#define DEF_PLL_UNCORE_CLKF_E8V7	0x2400000000
#define EFUSE_END_ADDR_E8V7			0x1fff
#define PARTNUM_5					5
#define PARTNUM_6					6
#define PARTNUM_7					7
#define PARTNUM_8					8
#define PARTNUM_9					9
#define PARTNUM_5_FLAG				(1 << 5)
#define PARTNUM_6_FLAG				(1 << 6)
#define PARTNUM_7_FLAG				(1 << 7)
#define PARTNUM_8_FLAG				(1 << 8)
#define PARTNUM_9_FLAG				(1 << 9)
#define PLL_BFS_CORE_ADDR_V7		0x0f
#define PLL_BFS_UNCORE_ADDR_V7		0x10

#define MEMSIZE 100
#define CHECKTIME 30
#define WORKTIME 900

#define IPCC_CSR1 0x604
#define IPCC_CSR2 0x644
#define IPCC_CSR3 0x684
#define IPCC_CSR1_SHIFT 0x0
#define IPCC_CSR2_SHIFT 0x40
#define IPCC_CSR3_SHIFT 0x80
#define IPCC_CSR1_SPARC 0x4004
#define IPCC_CSR2_SPARC 0x5004
#define IPCC_CSR3_SPARC 0x6004
#define IPCC_CSR1_SPARC_SHIFT 0x0
#define IPCC_CSR2_SPARC_SHIFT 0x1000
#define IPCC_CSR3_SPARC_SHIFT 0x2000

#define IPCC_A_0_3 0x14
#define IPCC_A_4_7 0x15
#define IPCC_A_8_11 0x16
#define IPCC_A_12_15 0x17
#define IPCC_B_0_3 0x18
#define IPCC_B_4_7 0x19
#define IPCC_B_8_11 0x1a
#define IPCC_B_12_15 0x1b
#define IPCC_C_0_3 0x1c
#define IPCC_C_4_7 0x1d
#define IPCC_C_8_11 0x1e
#define IPCC_C_12_15 0x1f

#define PCI_VIRT_BRIDGE_DEVICE_ID	0x8017
#define PCI_VIRT_GX6650_DEVICE_ID	0x802a
#define PCI_VIRT_E5810_DEVICE_ID	0x802b
#define PCI_VIRT_D5520_DEVICE_ID	0x802c
#define PCI_VIRT_MGA25_DEVICE_ID	0x8031
#define PCI_VIRT_BRIDGE_VENDOR_ID	0x1fff

#define PCI_VIRT_3DGPU_DEVICE_ID	0x8058
#define PCI_VIRT_MGA27_DEVICE_ID	0x8057
#define PCI_VIRT_DEC_DEVICE_ID		0x805A

#define PCIBIOS_SUCCESSFUL 0x00

#define SUP_DIG_MPLLA_ASIC_IN_0 0xe
#define SUP_DIG_MPLLB_ASIC_IN_0 0x11
#define SUP_DIG_ASIC_IN 0x15
#define LANEN_DIG_ASIC_RX_ASIC_IN_0 0x1011
#define ST_P 0x0004
#define ST_P_SHIFT 0x0004
#define MULTILINK_SHIFT 25
#define MULTILINK_MASK 0x1
#define MLC_SHIFT 24
#define MLC_MASK 0x1

#define MPLLA_SHIFT 5
#define MPLLA_MASK 0xFF
#define MPLLA_DIV2_SHIFT 1
#define MPLLA_DIV2_MASK 0x1
#define CLK_DIV2_EN_SHIFT 2
#define CLK_DIV2_EN_MASK 0x1
#define RX_RATE_SHIFT 7
#define RX_RATE_MASK 0x3

#define IPCC_STR1 0x60c
#define IPCC_STR2 0x64c
#define IPCC_STR3 0x68c
#define IPCC_STR1_SHIFT 0x8
#define IPCC_STR2_SHIFT 0x48
#define IPCC_STR3_SHIFT 0x88
#define IPCC_STR1_SPARC 0x400c
#define IPCC_STR2_SPARC 0x500c
#define IPCC_STR3_SPARC 0x600c
#define IPCC_STR1_SPARC_SHIFT 0x8
#define IPCC_STR2_SPARC_SHIFT 0x1008
#define IPCC_STR3_SPARC_SHIFT 0x2008

#define MC0_ECC 0x400
#define MC1_ECC 0x440
#define MC2_ECC 0x480
#define MC3_ECC 0x4C0
#define MC0_ECC_SHIFT 0x0
#define MC1_ECC_SHIFT 0x40
#define MC2_ECC_SHIFT 0x80
#define MC3_ECC_SHIFT 0xC0

#define MC_CH 0x400
#define MC_ECC 0x440
#define MC_CH_SHIFT 0x0
#define MC_ECC_SHIFT 0x40
#define MC_ECC_R1000 0x0000

#define ACTIVE_MASK 0x80000000
#define WIDTH_MASK  0x0F000000
#define STATE_MASK  0x00070000
#define CNT_MASK    0x1FFFFFFF
#define OVER_CNT_MASK 0x20000000
#define ERR_CNT_MASK 0x7FF
#define ERR_OV_MASK 0x800
#define ERR_OV_SHIFT 11
#define ERR_MD_MASK 0x3000
#define ERR_MD_SHIFT 12
#define CNT_LIMIT 1000
#define IOL_DLL_STSR 0x70C
#define IOL_DLL_STSR_SHIFT 0x108
#define IOL_DLL_STSR_SHIFT_SPARC 0x8
#define IOL_DLL_STSR_SHIFT_PCI 0xC

#define MC_ENABLE_MASK 0x1
#define MC_SECNT_MASK 0xFFFF
#define MC_UECNT_MASK 0x3FFF
#define MC_UECNT_MASK_E8V7 0x1FFF
#define MC_DMODE_MASK 0x1

#define MC_SECNT_SHIFT 16
#define MC_UECNT_SHIFT 2
#define MC_UECNT_SHIFT_E8V7 3
#define MC_DMODE_SHIFT 1

#define MC_CTL_SHIFT 0x4
#define MC_CTL0_SHIFT 0x4
#define MC_CTL1_SHIFT 0x44
#define MC_CTL2_SHIFT 0x84
#define MC_CTL3_SHIFT 0xc4

#define MC_STATUS_SHIFT 0x4c
#define PMC_SYS_MON_0_SHIFT 0x500
#define PMC_SYS_MON_1_SHIFT 0x504
#define PMC_SYS_MON_0_SHIFT_E8V7 0x900
#define PMC_SYS_MON_1_SHIFT_E8V7 0x904
#define MC_MON_CTL_SHIFT 0x50
#define MC_MON_CTR0_SHIFT 0x54
#define MC_MON_CTRext_SHIFT 0x5c

#define MC_MNT0_MASK 0xFFFF
#define MC_MNT0_SHIFT 32

#define MC_CTL_MCEN_MASK 0x1
#define MC_ST_RST_DONE_SHIFT 19
#define MC_ST_RST_DONE_MASK 0x1
#define MC_FREQ_SPARC 0x708c
#define MC_FREQ_SPARC_SHIFT 0x3088
#define MC_ECCCFG0 0x70
#define MC_ECCSTAT 0x78
#define MC_DDR_PHY_REGISTER_ADDRESS 0x0
#define MC_REGISTER_DATA 0x4

#define ECC_STAT_CECNT_MASK 0xF00
#define ECC_STAT_CECNT_SHIFT 8
#define ECC_STAT_UECNT_MASK 0xF0000
#define ECC_STAT_UECNT_SHIFT 16
#define ECC_MODE_MASK 0x7

#define E2C3_size 7
#define E8V7_size 13
#define DIVF_LIM_LO_MASK 0x00FC0000
#define DIVF_LIM_LO_SHIFT 18
#define DIVF_LIM_HI_MASK 0x0003F000
#define DIVF_LIM_HI_SHIFT 12
#define DIVF_CURR_MASK 0x0000003F
#define BFS_BYPASS_MASK 0x40000000
#define BFS_BYPASS_SHIFT 30
#define CORE_MPLL_FREQ 2000
#define UNCORE_MPLL_FREQ 1600
#define GRAPHIC_MPLL_FREQ 2000
#define MASK 0x1
#define BFS_BYPASS_MASK 0x40000000
#define BFS_BYPASS_SHIFT 30
#define CTRL_CLK_MASK 0x00020000
#define CTRL_CLK_SHIFT 17
#define CTRL_MODE_MASK 0x0000000E
#define CTRL_MODE_SHIFT 1
#define CTRL_EN_MASK 0x00000001
#define FLOAT_LO_MASK 0x000001FF
#define FLOAT_HI_MASK 0x001FF000
#define FLOAT_HI_SHIFT 12
#define PMC_VERSION_MASK 0x00000F00
#define PMC_VERSION_SHIFT 8
#define PMC_MODEL_MASK   0x000000FF
#define CFG_ALTER_MASK 0x40000000
#define CFG_ALTER_SHIFT 30
#define E12C_ID 10
#define E16C_ID 11
#define E2C3_ID 12
#define RT_LCFG0_SHIFT 0x10
#define RT_LCFG1_SHIFT 0x14
#define RT_LCFG2_SHIFT 0x18
#define RT_LCFG3_SHIFT 0x1c
#define RT_LCFG_VP_MASK 0x1
#define RT_LCFG_PN_SHIFT 4
#define RT_LCFG_PN_MASK 0x3
#define IOL_MASK 0x00000008
#define IOL_SHIFT 3

#define DOUBLE_MC_NUM 2
#define OCN_MIL_SHIFT 24
#define OCN_MIL_MASK 0xFF

#define HMU_MCEN_SHIFT 24
#define HMU_MCEN_MASK 0xFF
#define HMU_ENABLE 0x1

#define PIN_IPLA_PRE_DET_SHIFT 5
#define PIN_ATE_MODE_SHIFT 11
#define PIN_DBG_RST_DSBL_SHIFT 12
#define PIN_DBG_STOP_SHIFT 13
#define PIN_IPL_MULTILINK_SHIFT 14
#define PIN_IPL_GEN2_ADAPT_SHIFT 15
#define PIN_WLCC_SPEED_PRESETS_SHIFT 16
#define PIN_LIMIT_PHYS_SHIFT 19
#define PIN_LIMIT_CORES_SHIFT 21
#define PIN_CORE_ENBL_SHIFT 25
#define PIN_FREQ_MODE_SHIFT 27
#define PIN_SYS_KPI2BOOT_ENA_SHIFT 29
#define PIN_CPU_BSP_SHIFT 30
#define PIN_CPU_DISABLE_SOFT_RST_SHIFT 31

#define PIN_IPLA_PRE_DET_MASK 0xF
#define PIN_ATE_MODE_MASK 0x1
#define PIN_DBG_RST_DSBL_MASK 0x1
#define PIN_DBG_STOP_MASK 0x1
#define PIN_IPL_MULTILINK_MASK 0x1
#define PIN_IPL_GEN2_ADAPT_MASK 0x1
#define PIN_WLCC_SPEED_PRESETS_MASK 0x7
#define PIN_LIMIT_PHYS_MASK 0x3
#define PIN_LIMIT_CORES_MASK 0xF
#define PIN_CORE_ENBL_MASK 0x3
#define PIN_FREQ_MODE_MASK 0x3
#define PIN_SYS_KPI2BOOT_ENA_MASK 0x1
#define PIN_CPU_BSP_MASK 0x1
#define PIN_CPU_DISABLE_SOFT_RST_MASK 0x1

#define MACHINE_GEN_ALERT_SHIFT 0
#define MACHINE_PWR_ALERT_SHIFT 1
#define CPU_PWR_ALERT_SHIFT 2
#define MC47_PWR_ALERT_SHIFT 3
#define MC1_PWR_ALERT_SHIFT 3
#define MC03_PWR_ALERT_SHIFT 4
#define MC0_PWR_ALERT_SHIFT 4
#define MC_PWR_ALERT_SHIFT 4
#define MC47_DIMM_EVENT_SHIFT 5
#define MC1_DIMM_EVENT_SHIFT 5
#define MC1_DIMM_EVENT_SHIFT_E8V7 3
#define MC03_DIMM_EVENT_SHIFT 6
#define MC0_DIMM_EVENT_SHIFT 6
#define MC0_DIMM_EVENT_SHIFT_E8V7 4
#define NMI_CPU_SW_SHIFT 5
#define PCIE_B_CLK_SELECT_SHIFT 6
#define PCIE_A_CLK_SELECT_SHIFT 7
#define GFX_DP_CLK_SELECT_SHIFT 8
#define PIN_MNTR_SA0_SHIFT 9
#define PIN_PCIE_SATA_CONFIG_SHIFT 22
#define USB31_CLK_SELECT_SHIFT 24
#define CPU_DBG_RST_DSBL_SHIFT 25
#define CPU_DBG_STOP_SHIFT 26
#define MC_DIMM_EVENT_SHIFT 6
#define PIN_PCIE_PRE_DET0_SHIFT 16
#define PIN_PCIE_PRE_DET1_SHIFT 20
#define SMBUS_ALERT0_SHIFT 1
#define SMBUS_ALERT1_SHIFT 2
#define MC7_FAULT_SHIFT 9
#define MC6_FAULT_SHIFT 10
#define MC5_FAULT_SHIFT 11
#define MC4_FAULT_SHIFT 12
#define MC3_FAULT_SHIFT 13
#define MC2_FAULT_SHIFT 14
#define MC1_FAULT_SHIFT 15
#define MC0_FAULT_SHIFT 16
#define CPU_FAULT_SHIFT 17
#define PIN_SATAETH_CONFIG_SHIFT 18
#define PIN_IPLC_PRE_DET_SHIFT 19
#define PIN_IPLC_PE_CONFIG_SHIFT 21
#define PIN_IPLA_PE_CONFIG_SHIFT 21
#define PIN_IPLA_FLIP_EN_SHIFT 23
#define PIN_IOWL_PE_PRE_DET_SHIFT 24
#define PIN_IOWL_PE_CONFIG_SHIFT 28
#define PIN_EFUSE_MODE_SHIFT 30

#define MACHINE_GEN_ALERT_MASK 0x1
#define MACHINE_PWR_ALERT_MASK 0x1
#define CPU_PWR_ALERT_MASK  0x1
#define MC47_PWR_ALERT_MASK 0x1
#define MC1_PWR_ALERT_MASK 0x1
#define MC03_PWR_ALERT_MASK 0x1
#define MC0_PWR_ALERT_MASK 0x1
#define MC_PWR_ALERT_MASK 0x1
#define MC47_DIMM_EVENT_MASK 0x1
#define MC1_DIMM_EVENT_MASK 0x1
#define MC1_DIMM_EVENT_MASK_E8V7 0x1
#define MC03_DIMM_EVENT_MASK 0x1
#define MC0_DIMM_EVENT_MASK 0x1
#define MC0_DIMM_EVENT_MASK_E8V7 0x1
#define NMI_CPU_SW_MASK 0x1
#define PCIE_B_CLK_SELECT_MASK 0x1
#define PCIE_A_CLK_SELECT_MASK 0x1
#define GFX_DP_CLK_SELECT_MASK 0x1
#define PIN_MNTR_SA0_MASK 0x1
#define PIN_PCIE_SATA_CONFIG_MASK 0x3
#define USB31_CLK_SELECT_MASK 0x1
#define CPU_DBG_RST_DSBL_MASK 0x1
#define CPU_DBG_STOP_MASK 0x1
#define MC_DIMM_EVENT_MASK 0x1
#define MC7_FAULT_MASK 0x1
#define MC6_FAULT_MASK 0x1
#define MC5_FAULT_MASK 0x1
#define MC4_FAULT_MASK 0x1
#define MC3_FAULT_MASK 0x1
#define MC2_FAULT_MASK 0x1
#define MC1_FAULT_MASK 0x1
#define MC0_FAULT_MASK 0x1
#define CPU_FAULT_MASK 0x1
#define PIN_SATAETH_CONFIG_MASK 0x1
#define PIN_IPLC_PRE_DET_MASK 0x3
#define PIN_IPLC_PE_CONFIG_MASK 0x3
#define PIN_IPLA_PE_CONFIG_MASK 0x3
#define PIN_IPLA_FLIP_EN_MASK 0x1
#define PIN_IOWL_PE_PRE_DET_MASK 0xF
#define PIN_IOWL_PE_CONFIG_MASK 0x3
#define PIN_EFUSE_MODE_MASK 0x3
#define PIN_PCIE_PRE_DET0_MASK 0xF
#define PIN_PCIE_PRE_DET1_MASK 0xF
#define SMBUS_ALERT0_MASK 0x1
#define SMBUS_ALERT1_MASK 0x1

#define PIN_FREQ_MODE_NUM 4
#define PIN_CORE_ENABLE_NUM 13
#define MACHINE_GEN_ALERT_NUM 14
#define PIN_EFUSE_MODE_NUM 22

#define MC_MON_DELAY_MS 10000

#define IPCC_STR_MODE_LERR  0x1
#define IPCC_STR_MODE_RTRY  0x2

#define ACTIVE_SHIFT 31
#define WIDTH_SHIFT 24
#define STATE_SHIFT 16
#define ERR_MODE_MASK 0xC0000000
#define ERR_MODE_SHIFT 30
#define LINK_NOT_ACTIVE 0
#define LINK_ACTIVE 1

#define POWEROFF_STATE 0
#define DISABLE_STATE 1
#define SLEEP_STATE 2
#define LINKUP_STATE 3
#define SERVICE_STATE 4
#define REINIT_STATE 5
#define FULL_WIDTH 0xf

#define MPLL_MASK 0x00700000
#define MPLL_SHIFT 20
#define MPLL_LINK_MASK 0x07000000
#define MPLL_LINK_SHIFT 24
#define IOL_PLM_CTLR_SHIFT 0x104
#define IOL_PLM_CTLR_SHIFT_SPARC 0x4
#define IOL_PLM_CTLR_SHIFT_PCI 0x8
#define WLCC_RATE_MASK 0x20000000
#define WLCC_RATE_SHIFT 29
#define IOL_PLS_CTLR_SHIFT 0x100
#define IOL_PLS_CTLR_SHIFT_PCI 0x4
#define WLCC_ACTIVE_MASK 0x80000000
#define WLCC_ACTIVE_SHIFT 31
#define WLCC_STATE_MASK 0x07000000
#define WLCC_STATE_SHIFT 24
#define WLCC_WIDTH_MASK 0x000F0000
#define WLCC_WIDTH_SHIFT 16

#define PWR_MGR2_SHIFT 0x4
#define RST_MASK 0x00000001
#define OUTENA_MASK 0x00000002
#define OUTENA_SHIFT 1
#define CLKR_MASK 0x000000FC
#define CLKR_SHIFT 2
#define CLKF_MASK 0x001FFF00
#define CLKF_SHIFT 8
#define CLKOD_MASK 0x01E00000
#define CLKOD_SHIFT 21
#define LOCK_MASK 0x80000000
#define LOCK_SHIFT 31
#define PCI_KPI_SIZE 0x1000
#define PCI_IOL_SIZE 0x1000

#define PCI_BIST_SIZE 0x1000

#define MEM_LINKS 8
#define IPCC_LINKS 3

#define MAX_NODES 4
#define MAX_GPU 13
#define MAX_VXE 10
#define MAX_VXD 5
#define MAX_MGA 10
#define MAX_GPU0_E8V7 32
#define MAX_GPU1_E8V7 8
#define MAX_VXD_E8V7 14
#define MAX_MGA_E8V7 7
#define WORD_SIZE_E8V7 30
#define WORD_SIZE 20
#define MAX_BASE_NUM 6
#define SPARC_BASE_NUM 3
#define E2K_BASE_NUM 5
#define E2C3_BASE_NUM 6

#define ADDR_FIRST_CORE_SUB_BLOCK 0x45
#define ADDR_SECOND_CORE_SUB_BLOCK 0x46
#define ADDR_THIRD_CORE_SUB_BLOCK 0x47
#define ADDR_FOURTH_CORE_SUB_BLOCK 0x48

#define ADDR_FIRST_UNCORE_SUB_BLOCK 0x55
#define ADDR_SECOND_UNCORE_SUB_BLOCK 0x56
#define ADDR_THIRD_UNCORE_SUB_BLOCK 0x57
#define ADDR_FOURTH_UNCORE_SUB_BLOCK 0x58

enum mode_for_get_pll {
	CORE,
	UNCORE
};

typedef union {
	struct {
		u32 data		:21;
		u32 broadcast		:1;
		u32 addr		:7;
		u32 parity		:1;
		u32 disable		:1;
		u32 val			:1;
	} string_from_efuse;
	struct {
		u32 empty		:5;
		u32 pll_clkod		:11;
		u32 pll_clkf_lo		:5;
		u32 empty2		:11;
	} first_sub_block;
	struct {
		u32 pll_clkf_med_lo	:21;
		u32 empty		:11;
	} second_sub_block;
	struct {
		u32 pll_clkf_med_hi	:21;
		u32 empty		:11;
	} third_sub_block;
	struct {
		u32 pll_clkf_hi		:7;
		u32 pll_clkr		:12;
		u32 empty		:13;
	} fourth_sub_block;
	struct {
		u32 data		:20;
		u32 part_num	:4;
		u32 addr		:5;
		u32	parity		:1;
		u32 disable		:1;
		u32 val			:1;
	} v7;
	struct {
		u32 empty		:16;
		u32 pll_clkod_lo	:4;
		u32 empty2		:12;
	} e8v7_partnum5;
	struct {
		u32 pll_clkod_hi	:7;
		u32 pll_clkf_lo		:13;
		u32 empty		:12;
	} e8v7_partnum6;
	struct {
		u32 pll_clkf_med_lo :20;
		u32 empty			:12;
	} e8v7_partnum7;
	struct {
		u32 pll_clkf_med_hi :20;
		u32 empty			:12;
	} e8v7_partnum8;
	struct {
		u32 pll_clkf_hi		:1;
		u32 pll_clkr		:12;
		u32 empty			:19;
	} e8v7_partnum9;
	u32 word;
} efuse_data_t;

typedef union {
	struct {
		u32 reserved_1		: 4;
		u32 NS_dsbl		: 1;
		u32 IOMMU_dsbl		: 1;
		u32 Reset		: 1;
		u32 Prio_req_dsbl	: 1;
		u32 SLC2		: 1;
		u32 TA_UVS		: 1;
		u32 tornado		: 1;
		u32 texas_ph0		: 1;
		u32 raterisation_ph0	: 1;
		u32 USC0_dustA_ph0	: 1;
		u32 USC1_dustA_ph0	: 1;
		u32 USC0_dustB_ph0	: 1;
		u32 USC1_dustB_ph0	: 1;
		u32 texas_ph1		: 1;
		u32 raterisation_ph1	: 1;
		u32 USC0_dustA_ph1	: 1;
		u32 USC1_dustA_ph1	: 1;
		u32 reserved_2		: 11;
	};
	u32 word;
} hw_ctrl_gx6650_t;

typedef union {
	struct {
		u32 reserved_1		: 5;
		u32 IOMMU_dsbl		: 1;
		u32 Reset		: 1;
		u32 Prio_req_dsbl	: 1;
		u32 front_end_p0	: 1;
		u32 cache_p0		: 1;
		u32 back_end_p0		: 1;
		u32 front_end_p1	: 1;
		u32 cache_p1		: 1;
		u32 back_end_p1		: 1;
		u32 front_end_p2	: 1;
		u32 cache_p2		: 1;
		u32 back_end_p2		: 1;
		u32 sys_if		: 1;
		u32 bist_reserved	: 3;
		u32 reserved_2		: 11;
	};
	u32 word;
} hw_ctrl_e5810_t;

typedef union {
	struct {
		u32 reserved_1		: 5;
		u32 IOMMU_dsbl		: 1;
		u32 Reset		: 1;
		u32 Prio_req_dsbl	: 1;
		u32 mmu_cache		: 1;
		u32 mtx_core_ram	: 1;
		u32 pipe1		: 1;
		u32 pipe2		: 1;
		u32 pipe3		: 1;
		u32 bist_reserved	: 8;
		u32 reserved_2		: 11;

	};
	u32 word;
} hw_ctrl_d5520_t;

typedef union {
	struct {
		u32 bist_0		: 1;
		u32 bist_1		: 1;
		u32 bist_2		: 1;
		u32 bist_3		: 1;
		u32 bist_4		: 1;
		u32 bist_5		: 1;
		u32 bist_6		: 1;
		u32 bist_7		: 1;
		u32 bist_8		: 1;
		u32 bist_9		: 1;
		u32 reserved		: 22;
	};
	u32 word;
} mga25_bist_t;

typedef union {
	struct {
		u32 hi_mmu_slave_cache_u_mem_3		: 1;
		u32 hi_mmu_slave_cache_u_mem_2		: 1;
		u32 hi_mmu_slave_cache_u_mem_1		: 1;
		u32 hi_mmu_slave_cache_u_mem_0		: 1;
		u32 pe_color_src_3			: 1;
		u32 tx_LodAddressRam_3		: 1;
		u32 tx_fast_cache_3			: 1;
		u32 LFIFO_3					: 1;
		u32 us_dirbank_cache_3		: 1;
		u32 pixel_input_buffer_3	: 1;
		u32 a0_ram_3				: 1;
		u32 context_ram_3			: 1;
		u32 temporary_register_3	: 1;
		u32 pe_color_src_2			: 1;
		u32 tx_LodAddressRam_2		: 1;
		u32 tx_fast_cache_2			: 1;
		u32 LFIFO_2					: 1;
		u32 us_dirbank_cache_2		: 1;
		u32 pixel_input_buffer_2	: 1;
		u32 a0_ram_2				: 1;
		u32 context_ram_2			: 1;
		u32 temporary_register_2	: 1;
		u32 pe_color_src_1			: 1;
		u32 tx_LodAddressRam_1		: 1;
		u32 tx_fast_cache_1			: 1;
		u32 LFIFO_1					: 1;
		u32 us_dirbank_cache_1		: 1;
		u32 pixel_input_buffer_1	: 1;
		u32 a0_ram_1				: 1;
		u32 context_ram_1			: 1;
		u32 temporary_register_1	: 1;
		u32 pe_color_src_0			: 1;
	};
	u32 word;
} bist_sig0_gpu_t;

typedef union {
	struct {
		u32 tx_LodAddressRam_0		: 1;
		u32 tx_fast_cache_0			: 1;
		u32 LFIFO_0					: 1;
		u32 us_dirbank_cache_0		: 1;
		u32 pixel_input_buffer_0	: 1;
		u32 a0_ram_0				: 1;
		u32 context_ram_0			: 1;
		u32 temporary_register_0	: 1;
		u32 reserved				: 24;
	};
	u32 word;
} bist_sig1_gpu_t;

typedef union {
	struct {
		u32 prefetch_cache_3		: 1;
		u32 emd_ctrl_frame_cdf_3	: 1;
		u32 mvd_above0_ambc0_3		: 1;
		u32 pred_ambc_3				: 1;
		u32 ref_bwd_ref_fwd_3		: 1;
		u32 filter_above_bs_data_2		: 1;
		u32 filter_above_df_data_2		: 1;
		u32 sao_filter_shared_ram_2		: 1;
		u32 dec_400_ch_lu_ts_0		: 1;
		u32 sca_row_0				: 1;
		u32 cache_data_0			: 1;
		u32 reorder_row_0			: 1;
		u32 stile_row_0				: 1;
		u32 shaper_0				: 1;
		u32 reserved				: 18;
	};
	u32 word;
} bist_sig0_vxd_t;

typedef union {
	struct {
		u32 bist_0		: 1;
		u32 bist_1		: 1;
		u32 bist_2		: 1;
		u32 bist_3		: 1;
		u32 bist_4		: 1;
		u32 bist_5		: 1;
		u32 bist_6		: 1;
		u32 reserved		: 25;
	};
	u32 word;
} mga27_bist_t;

struct ctrl_info {
	int offset;
};

static const struct ctrl_info mc_ctls_off[] = {
	{ MC_CTL0_SHIFT },
	{ MC_CTL1_SHIFT },
	{ MC_CTL2_SHIFT },
	{ MC_CTL3_SHIFT }
};

static const struct ctrl_info mc_ctrls[] = {
	{ MC0_ECC },
	{ MC1_ECC },
	{ MC2_ECC },
	{ MC3_ECC },
	{ MC_CH },
	{ MC_ECC }
};

static const struct ctrl_info mc_ctrls_off[] = {
	{ MC0_ECC_SHIFT },
	{ MC1_ECC_SHIFT },
	{ MC2_ECC_SHIFT },
	{ MC3_ECC_SHIFT },
	{ MC_CH_SHIFT },
	{ MC_ECC_SHIFT }
};

static const struct ctrl_info ipcc_ctrls[] = {
	{ IPCC_CSR1 },
	{ IPCC_CSR2 },
	{ IPCC_CSR3 },
	{ IPCC_STR1 },
	{ IPCC_STR2 },
	{ IPCC_STR3 }
};

static const struct ctrl_info ipcc_ctrls_off[] = {
	{ IPCC_CSR1_SHIFT },
	{ IPCC_CSR2_SHIFT },
	{ IPCC_CSR3_SHIFT },
	{ IPCC_STR1_SHIFT },
	{ IPCC_STR2_SHIFT },
	{ IPCC_STR3_SHIFT }
};

static const struct ctrl_info ipcc_sparc_ctrls[] = {
	{ IPCC_CSR1_SPARC },
	{ IPCC_CSR2_SPARC },
	{ IPCC_CSR3_SPARC },
	{ IPCC_STR1_SPARC },
	{ IPCC_STR2_SPARC },
	{ IPCC_STR3_SPARC }
};

static const struct ctrl_info ipcc_sparc_ctrls_off[] = {
	{ IPCC_CSR1_SPARC_SHIFT },
	{ IPCC_CSR2_SPARC_SHIFT },
	{ IPCC_CSR3_SPARC_SHIFT },
	{ IPCC_STR1_SPARC_SHIFT },
	{ IPCC_STR2_SPARC_SHIFT },
	{ IPCC_STR3_SPARC_SHIFT }
};

static const struct ctrl_info ipcc_rate_ctrls[] = {
	{ IPCC_A_0_3 },
	{ IPCC_A_4_7 },
	{ IPCC_A_8_11 },
	{ IPCC_A_12_15 },
	{ IPCC_B_0_3 },
	{ IPCC_B_4_7 },
	{ IPCC_B_8_11 },
	{ IPCC_B_12_15 },
	{ IPCC_C_0_3 },
	{ IPCC_C_4_7 },
	{ IPCC_C_8_11 },
	{ IPCC_C_12_15 }
};

struct th_info {
	struct work_struct work;
	int node;
	int mode;
	struct mutex mutex_measure;
	struct completion rate_done;
};

struct hwmon_data {
	struct platform_device *pdev;
	struct device *hdev;
	int node;
	void __iomem *base[MAX_BASE_NUM];
	struct workqueue_struct *wq;
	struct th_info th_info_var;
};

struct link_data {
	int active[IPCC_LINKS];
	int width[IPCC_LINKS];
	int state[IPCC_LINKS];
	int cnt_err[IPCC_LINKS];
	int multilink;
	int vp[IPCC_LINKS];
	int pn[IPCC_LINKS];
	int csr_reg[IPCC_LINKS];
	int str_reg[IPCC_LINKS];
	int str_val[IPCC_LINKS];
	int err_mode[IPCC_LINKS];
	int mlc;
	int st_p;
	int link_bitrate[IPCC_LINKS];
	int io_mpll;
	int ip_mpll;
	int wlcc_rate;
	int wlcc_active;
	int wlcc_state;
	int wlcc_width;
	int iol;
	int kpi_rate;
	int kpi_active;
	int kpi_state;
	int kpi_width;
	int kpi_cnt;
	int kpi_ov;
	int kpi_md;
	int wlcc_cnt;
	int wlcc_ov;
	int wlcc_md;

};

struct mem_data {
	int mem_reg[MEM_LINKS];
	int mem_mode[MEM_LINKS];
	int mem_secnt[MEM_LINKS];
	int mem_uecnt[MEM_LINKS];
	int mem_dmode[MEM_LINKS];
	int mem_reg_val[MEM_LINKS];
	int mem_rst_done[MEM_LINKS];
	int mem_ctl_mcen[MEM_LINKS];
	int mem_ctl_val[MEM_LINKS];
	int mem_status_val[MEM_LINKS];
	int mem_freq[MEM_LINKS];
	int mem_ddr_rate[MEM_LINKS];
	int mem_hmu_mcen;
	int mem_freq_e8c_mgr1;
	int mem_ddr_e8c_mgr1;
	int mem_freq_e8c_mgr2;
	int mem_ddr_e8c_mgr2;

};

struct pins_data {
	int vp;
	int pn;
	int sys_mon_0;
	int sys_mon_1;
	int pmc_info;
};

struct cpu_data_e8v7 {
	int base_freq[E8V7_size];
	int mon_divF_curr[E8V7_size];
	int mon_divF_lim_lo[E8V7_size];
	int mon_divF_lim_hi[E8V7_size];
	int mon_freq_curr[E8V7_size];
	int mon_freq_lim_hi[E8V7_size];
	int mon_freq_lim_lo[E8V7_size];
	int mon_bfs_bypass[E8V7_size];
	int graph_ctrl_bfs_bypass[E8V7_size];
	int graph_ctrl_en[E8V7_size];
	int graph_ctrl_clk_mux[E8V7_size];
	int graph_ctrl_mode[E8V7_size];
	int ctrl_bfs_bypass[E8V7_size];
	int ctrl_en[E8V7_size];
	int ctrl_mode[E8V7_size];
	int pmc_freq_cfg_alter_disable[E8V7_size];
};

struct cpu_data {
	int base_freq[E2C3_size];
	int mon_divF_curr[E2C3_size];
	int mon_divF_lim_lo[E2C3_size];
	int mon_divF_lim_hi[E2C3_size];
	int mon_freq_curr[E2C3_size];
	int mon_freq_lim_hi[E2C3_size];
	int mon_freq_lim_lo[E2C3_size];
	int mon_bfs_bypass[E2C3_size];
	int graph_ctrl_bfs_bypass[E2C3_size];
	int graph_ctrl_en[E2C3_size];
	int graph_ctrl_clk_mux[E2C3_size];
	int graph_ctrl_mode[E2C3_size];
	int ctrl_bfs_bypass[E2C3_size];
	int ctrl_en[E2C3_size];
	int ctrl_mode[E2C3_size];
	int pmc_freq_gra_float_T_lo_dec[E2C3_size];
	int pmc_freq_gra_float_T_hi_dec[E2C3_size];
	int pmc_freq_cfg_alter_disable[E2C3_size];
	int pmc_freq_core_float_T_lo_dec[E2C3_size];
	int pmc_freq_core_float_T_hi_dec[E2C3_size];
	int pmc_freq_ocn_float_T_lo_dec[E2C3_size];
	int pmc_freq_ocn_float_T_hi_dec[E2C3_size];
};

struct pins_info {
	int shift;
	int mask;
	char *name;

};

struct bist_data {
	hw_ctrl_gx6650_t GPU;
	hw_ctrl_e5810_t VXE;
	hw_ctrl_d5520_t VXD;
	mga25_bist_t MGA;
	bool MGA_present;
	bist_sig0_gpu_t GPU0_E8V7;
	bist_sig1_gpu_t GPU1_E8V7;
	bist_sig0_vxd_t VXD_E8V7;
	mga27_bist_t MGA_E8V7;
	bool GPU_present;
	bool VXD_present;
	bool VXE_present;
};

static const struct pins_info pins_ctrls[] = {
	{ PIN_ATE_MODE_SHIFT, PIN_ATE_MODE_MASK,
					"pin_ate_mode" },
	{ PIN_DBG_RST_DSBL_SHIFT, PIN_DBG_RST_DSBL_MASK,
					"pin_dbg_rst_dsbl" },
	{ PIN_DBG_STOP_SHIFT, PIN_DBG_STOP_MASK,
					"pin_dbg_stop" },
	{ PIN_WLCC_SPEED_PRESETS_SHIFT, PIN_WLCC_SPEED_PRESETS_MASK,
					"pin_wlcc_speed_presets" },
	{ PIN_FREQ_MODE_SHIFT, PIN_FREQ_MODE_MASK,
					"pin_freq_mode"},
	{ PIN_SYS_KPI2BOOT_ENA_SHIFT, PIN_SYS_KPI2BOOT_ENA_MASK,
					"pin_sys_kpi2boot_ena" },
	{ PIN_CPU_BSP_SHIFT, PIN_CPU_BSP_MASK,
					"pin_cpu_bsp"},
	{ PIN_CPU_DISABLE_SOFT_RST_SHIFT, PIN_CPU_DISABLE_SOFT_RST_MASK,
					"pin_cpu_disable_soft_rst" },
	{ PIN_IPLA_PRE_DET_SHIFT, PIN_IPLA_PRE_DET_MASK,
					"pin_ipla_pre_det" },
	{ PIN_IPL_GEN2_ADAPT_SHIFT, PIN_IPL_GEN2_ADAPT_MASK,
					"pin_ipl_gen2_adapt" },
	{ PIN_IPL_MULTILINK_SHIFT, PIN_IPL_MULTILINK_MASK,
					"pin_ipl_multilink" },
	{ PIN_LIMIT_PHYS_SHIFT, PIN_LIMIT_PHYS_SHIFT,
					"pin_limit_phys" },
	{ PIN_LIMIT_CORES_SHIFT, PIN_LIMIT_CORES_MASK,
					"pin_limit_cores" },
	{ PIN_CORE_ENBL_SHIFT, PIN_CORE_ENBL_MASK,
					"pin_core_enbl" },
	{ MACHINE_GEN_ALERT_SHIFT, MACHINE_GEN_ALERT_MASK,
					"machine_gen_alert" },
	{ MACHINE_PWR_ALERT_SHIFT, MACHINE_PWR_ALERT_MASK,
					"machine_pwr_alert" },
	{ CPU_PWR_ALERT_SHIFT, CPU_PWR_ALERT_MASK,
					"cpu_pwr_alert" },
	{ MC1_FAULT_SHIFT, MC1_FAULT_MASK,
					"mc1_fault" },
	{ MC0_FAULT_SHIFT, MC0_FAULT_MASK,
					"mc0_fault" },
	{ CPU_FAULT_SHIFT, CPU_FAULT_MASK,
					"cpu_fault" },
	{ PIN_IOWL_PE_PRE_DET_SHIFT, PIN_IOWL_PE_PRE_DET_MASK,
					"pin_iowl_pe_pre_det" },
	{ PIN_IOWL_PE_CONFIG_SHIFT, PIN_IOWL_PE_CONFIG_MASK,
					"pin_iowl_pe_config" },
	{ PIN_EFUSE_MODE_SHIFT, PIN_EFUSE_MODE_MASK,
					"pin_efuse_mode" },
	{ MC1_PWR_ALERT_SHIFT, MC1_PWR_ALERT_MASK,
					"mc1_pwr_alert" },
	{ MC0_PWR_ALERT_SHIFT, MC0_PWR_ALERT_MASK,
					"mc0_pwr_alert" },
	{ MC1_DIMM_EVENT_SHIFT, MC1_DIMM_EVENT_MASK,
					"mc1_dimm_event" },
	{ MC0_DIMM_EVENT_SHIFT, MC0_DIMM_EVENT_MASK,
					"mc0_dimm_event" },
	{ PIN_IPLA_PE_CONFIG_SHIFT, PIN_IPLA_PE_CONFIG_MASK,
					"pin_ipla_pe_config" },
	{ MC47_PWR_ALERT_SHIFT, MC47_PWR_ALERT_MASK,
					"mc47_pwr_alert" },
	{ MC03_PWR_ALERT_SHIFT, MC03_PWR_ALERT_MASK,
					"mc03_pwr_alert" },
	{ MC47_DIMM_EVENT_SHIFT, MC47_DIMM_EVENT_MASK,
					"mc47_dimm_event" },
	{ MC03_DIMM_EVENT_SHIFT, MC03_DIMM_EVENT_MASK,
					"mc03_dimm_event" },
	{ MC7_FAULT_SHIFT, MC7_FAULT_MASK, "mc7_fault" },
	{ MC6_FAULT_SHIFT, MC6_FAULT_MASK, "mc6_fault" },
	{ MC5_FAULT_SHIFT, MC5_FAULT_MASK, "mc5_fault" },
	{ MC4_FAULT_SHIFT, MC4_FAULT_MASK, "mc4_fault" },
	{ MC3_FAULT_SHIFT, MC3_FAULT_MASK, "mc3_fault" },
	{ MC2_FAULT_SHIFT, MC2_FAULT_MASK, "mc2_fault" },
	{ PIN_IPLC_PRE_DET_SHIFT, PIN_IPLC_PRE_DET_MASK,
					"pin_iplc_pre_det" },
	{ PIN_IPLC_PE_CONFIG_SHIFT, PIN_IPLC_PE_CONFIG_MASK,
					"pin_iplc_pe_config" },
	{ PIN_IPLA_FLIP_EN_SHIFT, PIN_IPLA_FLIP_EN_MASK,
					"pin_ipla_flip_en" },
	{ PIN_SATAETH_CONFIG_SHIFT, PIN_SATAETH_CONFIG_MASK,
					"pin_sataeth_config" },
	{ MC_PWR_ALERT_SHIFT, MC_PWR_ALERT_MASK,
					"mc_pwr_alert" },
	{ MC_DIMM_EVENT_SHIFT, MC_DIMM_EVENT_MASK,
					"mc_dimm_event" },
	{ PIN_PCIE_PRE_DET0_SHIFT, PIN_PCIE_PRE_DET0_MASK,
					"pin_pcie_pre_det0" },
	{ PIN_PCIE_PRE_DET1_SHIFT, PIN_PCIE_PRE_DET1_MASK,
					"pin_pcie_pre_det1" },
	{ SMBUS_ALERT0_SHIFT, SMBUS_ALERT0_MASK,
					"smbus_alert0" },
	{ SMBUS_ALERT1_SHIFT, SMBUS_ALERT1_MASK,
					"smbus_alert1" },
	{ MC1_DIMM_EVENT_SHIFT_E8V7, MC1_DIMM_EVENT_MASK_E8V7,
					"mc1_dimm_event" },
	{ MC0_DIMM_EVENT_SHIFT_E8V7, MC0_DIMM_EVENT_MASK_E8V7,
					"mc0_dimm_event" },
	{ NMI_CPU_SW_SHIFT, NMI_CPU_SW_MASK,
					"nmi_cpu_sw" },
	{ PCIE_B_CLK_SELECT_SHIFT, PCIE_B_CLK_SELECT_MASK,
					"pcie_B_clk_select" },
	{ PCIE_A_CLK_SELECT_SHIFT, PCIE_A_CLK_SELECT_MASK,
					"pcie_A_clk_select" },
	{ GFX_DP_CLK_SELECT_SHIFT, GFX_DP_CLK_SELECT_MASK,
					"gfx_dp_clk_select" },
	{ PIN_MNTR_SA0_SHIFT, PIN_MNTR_SA0_MASK,
					"pin_mntr_sa0" },
	{ PIN_PCIE_SATA_CONFIG_SHIFT, PIN_PCIE_SATA_CONFIG_MASK,
					"pin_pcie_sata_config" },
	{ USB31_CLK_SELECT_SHIFT, USB31_CLK_SELECT_MASK,
					"usb31_clk_select" },
	{ CPU_DBG_RST_DSBL_SHIFT, CPU_DBG_RST_DSBL_MASK,
					"cpu_dbg_rst_dsbl" },
	{ CPU_DBG_STOP_SHIFT, CPU_DBG_STOP_MASK,
					"cpu_dbg_stop" },
};
