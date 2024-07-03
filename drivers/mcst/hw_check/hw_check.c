/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * HW_CHECK kernel module for e2k platforms
 * e8c, e8c2, e16c, e2c3, e12c
 */

#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/node.h>
#include <linux/cpu.h>
#include <linux/mod_devicetable.h>
#include <linux/hwmon-sysfs.h>
#include <linux/hwmon.h>
#include <linux/thermal.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/kthread.h>

#include <asm/sic_regs.h>
#ifdef CONFIG_E2K
#include <asm/nbsr_v6_regs.h>
#include <asm/sic_regs_access.h>
#endif

#define MEMSIZE 100
#define CHECKTIME 30
#define WORKTIME 900

#define IPCC_CSR1 0x604
#define IPCC_CSR2 0x644
#define IPCC_CSR3 0x684
#define IPCC_CSR1_SPARC 0x4004
#define IPCC_CSR2_SPARC 0x5004
#define IPCC_CSR3_SPARC 0x6004

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

#define PCI_VIRT_BRIDGE_DEVICE_ID 0x8017
#define PCI_VIRT_GX6650_DEVICE_ID 0x802a
#define PCI_VIRT_E5810_DEVICE_ID 0x802b
#define PCI_VIRT_D5520_DEVICE_ID 0x802c
#define PCI_VIRT_MGA25_DEVICE_ID 0x8031
#define PCI_VIRT_BRIDGE_VENDOR_ID 0x1fff

#define PCIBIOS_SUCCESSFUL 0x00

#define SUP_DIG_MPLLA_ASIC_IN_0 0xe
#define SUP_DIG_MPLLB_ASIC_IN_0 0x11
#define SUP_DIG_ASIC_IN 0x15
#define LANEN_DIG_ASIC_RX_ASIC_IN_0 0x1011
#define ST_P 0x0004
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
#define IPCC_STR1_SPARC 0x400c
#define IPCC_STR2_SPARC 0x500c
#define IPCC_STR3_SPARC 0x600c

#define MC0_ECC 0x400
#define MC1_ECC 0x440
#define MC2_ECC 0x480
#define MC3_ECC 0x4C0

#define MC_CH 0x400
#define MC_ECC 0x440
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
#define IOL_DLL_STSR_SHIFT 0xC

#define MC_ENABLE_MASK 0x1
#define MC_SECNT_MASK 0xFFFF
#define MC_UECNT_MASK 0x3FFF
#define MC_DMODE_MASK 0x1

#define MC_SECNT_SHIFT 16
#define MC_UECNT_SHIFT 2
#define MC_DMODE_SHIFT 1

#define MC_CTL 0x404
#define MC_STATUS 0x44c
#define MC_MON_CTL 0x450
#define MC_MON_CTR0 0x454
#define MC_MON_CTR1 0x458
#define MC_MON_CTRext 0x45c

#define MC_MNT0_MASK 0xFFFF
#define MC_MNT0_SHIFT 32

#define MC_CTL_MCEN_MASK 0x1
#define MC_ST_RST_DONE_SHIFT 19
#define MC_ST_RST_DONE_MASK 0x1
#define MC_FREQ_SPARC 0x708c
#define MC_ECCCFG0 0x70
#define MC_ECCSTAT 0x78
#define MC_DDR_PHY_REGISTER_ADDRESS 0x0
#define MC_REGISTER_DATA 0x4

#define ECC_STAT_CECNT_MASK 0xF00
#define ECC_STAT_CECNT_SHIFT 8
#define ECC_STAT_UECNT_MASK 0xF0000
#define ECC_STAT_UECNT_SHIFT 16
#define ECC_MODE_MASK 0x7

#define PCS_PMC_REGS_base 0x1000
#define PMC_INFO 0x000
#define PMC_FREQ_CORE_FLOAT 0x110
#define PMC_FREQ_OCN_FLOAT 0x114
#define PMC_FREQ_GRAPHIC_FLOAT 0x600
#define PMC_FREQ_CORE_TABLE 0x120
#define PMC_FREQ_OCN_TABLE 0x140
#define PMC_FREQ_GRAPHIC_TABLE 0x620
#define PMC_SYS_MON_0_REG 0x500
#define PMC_SYS_MON_1_REG 0x504
#define PMC_FREQ_TABLE_DEPTH 8
#define E2C3_size 7
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
#define RT_LCFG0 0x0010
#define RT_LCFG1 0x0014
#define RT_LCFG2 0x0018
#define RT_LCFG3 0x001c
#define RT_LCFG_VP_MASK 0x1
#define RT_LCFG_PN_SHIFT 4
#define RT_LCFG_PN_MASK 0x3
#define IOL_MASK 0x00000008
#define IOL_SHIFT 3

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
#define MC03_DIMM_EVENT_SHIFT 6
#define MC0_DIMM_EVENT_SHIFT 6
#define MC_DIMM_EVENT_SHIFT 6
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
#define MC03_DIMM_EVENT_MASK 0x1
#define MC0_DIMM_EVENT_MASK 0x1
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

#define PCS_CTRL3 0xCBC
#define MPLL_MASK 0x00700000
#define MPLL_SHIFT 20
#define MPLL_LINK_MASK 0x07000000
#define MPLL_LINK_SHIFT 24
#define IOL_PLM_CTLR 0x708
#define IOL_PLM_CTLR_SHIFT 0x8
#define WLCC_RATE_MASK 0x20000000
#define WLCC_RATE_SHIFT 29
#define IOL_PLS_CTLR 0x704
#define IOL_PLS_CTLR_SHIFT 0x4
#define WLCC_ACTIVE_MASK 0x80000000
#define WLCC_ACTIVE_SHIFT 31
#define WLCC_STATE_MASK 0x07000000
#define WLCC_STATE_SHIFT 24
#define WLCC_WIDTH_MASK 0x000F0000
#define WLCC_WIDTH_SHIFT 16

#define PWR_MGR1 0x284
#define PWR_MGR2 0x288
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
#define WORD_SIZE 20

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

struct ctrl_info {
	int offset;
};

static const struct ctrl_info mc_ctrls[] = {
	{ MC0_ECC },
	{ MC1_ECC },
	{ MC2_ECC },
	{ MC3_ECC },
	{ MC_CH },
	{ MC_ECC }
};

static const struct ctrl_info ipcc_ctrls[] = {
	{ IPCC_CSR1 },
	{ IPCC_CSR2 },
	{ IPCC_CSR3 },
	{ IPCC_STR1 },
	{ IPCC_STR2 },
	{ IPCC_STR3 }
};

static const struct ctrl_info ipcc_sparc_ctrls[] = {
	{ IPCC_CSR1_SPARC },
	{ IPCC_CSR2_SPARC },
	{ IPCC_CSR3_SPARC },
	{ IPCC_STR1_SPARC },
	{ IPCC_STR2_SPARC },
	{ IPCC_STR3_SPARC }
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

struct hwmon_data {
	struct platform_device *pdev;
	struct device *hdev;
	int node;
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
					"mc_dimm_event" }
};
#ifdef CONFIG_E2K
static int CalcFreq(int base, int div)
{
	int divF;
	int bfs_M;
	int bfs_N;

	if (div >= 0x30) {
		divF = 0x2F;
	} else {
		divF = div;
	}
	bfs_M = (1 << ((divF & 0x30) >> 4));
	bfs_N = (divF & 0xF) + 0x10;

	return base * 16 / bfs_M / bfs_N;
}

static int CalcTemp(int T_data)
{
	int Temp;
	int T_sign = (T_data >> 8) & 0x1;

	if (T_sign == 1) {
		Temp = (0x1FF) | (T_data & 0x1FF);
	} else {
		Temp = T_data & 0x1FF;
	}

	return Temp;
}

int e2c3_block[E2C3_size] = {0, 1, 32, 33, 34, 35, 36};
static struct cpu_data read_cpu_data(int node)
{
	struct cpu_data a;
	int i;
	int rr_addr;
	int block_addr_shift;
	int rr_data;
	int block_is_graphic;
	int graphic_num;
	int ctrl_addr;
	int ctrl_data;
	int graph_addr;
	int graph_data;
	int pmc_freq_addr;
	int pmc_freq_data;
	int pmc_freq_gra_float_T_lo[E2C3_size];
	int pmc_freq_gra_float_T_hi[E2C3_size];
	int core_addr;
	int core_data;
	int pmc_freq_core_float_T_lo[E2C3_size];
	int pmc_freq_core_float_T_hi[E2C3_size];
	int ocn_addr;
	int ocn_data;
	int pmc_freq_ocn_float_T_lo[E2C3_size];
	int pmc_freq_ocn_float_T_hi[E2C3_size];

	for (i = 0; i < E2C3_size; i++) {
		block_addr_shift = 0x10 * e2c3_block[i];
		graphic_num = e2c3_block[i] - 33;
		if (e2c3_block[i] < 16) {
			a.base_freq[i] = CORE_MPLL_FREQ;
			block_is_graphic = 0;
		} else if (e2c3_block[i] < 32) {
			a.base_freq[i] = 0;
			block_is_graphic = 0;
		} else if (e2c3_block[i] == 32) {
			a.base_freq[i] = UNCORE_MPLL_FREQ;
			block_is_graphic = 0;
		} else if (e2c3_block[i] < 37) {
			a.base_freq[i] = GRAPHIC_MPLL_FREQ;
			block_is_graphic = 1;

		} else {
			a.base_freq[i] = 0;
			block_is_graphic = 0;
		}
		rr_addr = (PCS_PMC_REGS_base + 0x200 + block_addr_shift);
		rr_data = sic_read_node_nbsr_reg(node, rr_addr);
		a.mon_divF_curr[i] = rr_data & DIVF_CURR_MASK;
		a.mon_divF_lim_lo[i] = (rr_data & DIVF_LIM_LO_MASK) >>
							DIVF_LIM_LO_SHIFT;
		a.mon_divF_lim_hi[i] = (rr_data & DIVF_LIM_HI_MASK) >>
							DIVF_LIM_HI_SHIFT;
		a.mon_bfs_bypass[i] = (rr_data & BFS_BYPASS_MASK) >>
							BFS_BYPASS_SHIFT;
		a.mon_freq_curr[i] = CalcFreq(a.base_freq[i],
						a.mon_divF_curr[i]);
		a.mon_freq_lim_hi[i] = CalcFreq(a.base_freq[i],
						a.mon_divF_lim_hi[i]);
		a.mon_freq_lim_lo[i] = CalcFreq(a.base_freq[i],
						a.mon_divF_lim_lo[i]);

		ctrl_addr = (PCS_PMC_REGS_base + 0x204 + block_addr_shift);
		ctrl_data = sic_read_node_nbsr_reg(node, ctrl_addr);

		if (block_is_graphic == 1) {
			a.graph_ctrl_bfs_bypass[i] = (ctrl_data &
				BFS_BYPASS_MASK) >> BFS_BYPASS_SHIFT;
			a.graph_ctrl_en[i] = (ctrl_data & CTRL_EN_MASK);
			a.graph_ctrl_clk_mux[i] = (ctrl_data & CTRL_CLK_MASK)
							>> CTRL_CLK_SHIFT;
			a.graph_ctrl_mode[i] = (ctrl_data & CTRL_MODE_MASK)
							>> CTRL_MODE_SHIFT;
			graph_addr = PCS_PMC_REGS_base + 0x600 + (0x4 * graphic_num);
			graph_data = sic_read_node_nbsr_reg(node, graph_addr);
			pmc_freq_gra_float_T_lo[i] = graph_data & FLOAT_LO_MASK;
			pmc_freq_gra_float_T_hi[i] = (graph_data & FLOAT_HI_MASK)
							>> FLOAT_HI_SHIFT;
			a.pmc_freq_gra_float_T_lo_dec[i] = CalcTemp(pmc_freq_gra_float_T_lo[i]);
			a.pmc_freq_gra_float_T_hi_dec[i] = CalcTemp(pmc_freq_gra_float_T_hi[i]);
		}
		a.ctrl_bfs_bypass[i] = (ctrl_data & BFS_BYPASS_MASK) >> BFS_BYPASS_SHIFT;
		a.ctrl_en[i] = (ctrl_data & CTRL_EN_MASK);
		a.ctrl_mode[i] = (ctrl_data & CTRL_MODE_MASK) >> CTRL_MODE_SHIFT;
		core_addr = PCS_PMC_REGS_base + 0x110;
		core_data = sic_read_node_nbsr_reg(node, core_addr);
		pmc_freq_core_float_T_lo[i] = core_data & FLOAT_LO_MASK;
		pmc_freq_core_float_T_hi[i] = (core_data & FLOAT_HI_MASK)
						>> FLOAT_HI_SHIFT;
		a.pmc_freq_core_float_T_lo_dec[i] = CalcTemp(pmc_freq_core_float_T_lo[i]);
		a.pmc_freq_core_float_T_hi_dec[i] = CalcTemp(pmc_freq_core_float_T_hi[i]);
		pmc_freq_addr = PCS_PMC_REGS_base + 0x100;
		pmc_freq_data = sic_read_node_nbsr_reg(node, pmc_freq_addr);
		a.pmc_freq_cfg_alter_disable[i] = (pmc_freq_data & CFG_ALTER_MASK)
						>> CFG_ALTER_SHIFT;
		ocn_addr = PCS_PMC_REGS_base + 0x114;
		ocn_data = sic_read_node_nbsr_reg(node, ocn_addr);
		pmc_freq_ocn_float_T_lo[i] = ocn_data & FLOAT_LO_MASK;
		pmc_freq_ocn_float_T_hi[i] = (ocn_data & FLOAT_HI_MASK)
						>> FLOAT_HI_SHIFT;
		a.pmc_freq_ocn_float_T_lo_dec[i] = CalcTemp(pmc_freq_ocn_float_T_lo[i]);
		a.pmc_freq_ocn_float_T_hi_dec[i] = CalcTemp(pmc_freq_ocn_float_T_hi[i]);
	}

	return a;
}

static ssize_t show_cpu_data(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct cpu_data b = read_cpu_data(hwmon->node);
	int j = 0;
	int i;
	int graphic_num;
	int block_is_graphic;
	int graph_ctrl_freq_bypassed;
	char block_name[20];
	char *GRAPHIC_NAME[] = {"MGA", "GPU", "ENCODERs", "DECODERs"};
	int GRAPHIC_DIV_0[4] = {3, 3, 4, 4};
	int GRAPHIC_DIV_1[4] = {2, 2, 3, 3};
	int simple_div[2];
	int block_is_core;
	int block_is_uncore;

	for (i = 0; i < E2C3_size; i++) {
		graphic_num = e2c3_block[i] - 33;
		if (e2c3_block[i] < 16) {
			block_is_core = 1;
			block_is_uncore = 0;
			block_is_graphic = 0;
			sprintf(block_name, "CORE_%d", e2c3_block[i]);
			simple_div[0] = 1;
			simple_div[1] = 1;
		} else if (e2c3_block[i] < 32) {
			block_is_core = 0;
			block_is_uncore = 0;
			block_is_graphic = 0;
			sprintf(block_name, "reserved");
			simple_div[0] = 1;
			simple_div[1] = 1;
		} else if (e2c3_block[i] == 32) {
			block_is_core = 0;
			block_is_uncore = 1;
			block_is_graphic = 0;
			sprintf(block_name, "OCI");
			simple_div[0] = 1;
			simple_div[1] = 1;
		} else if (e2c3_block[i] < 37) {
			block_is_core = 0;
			block_is_uncore = 0;
			block_is_graphic = 1;
			sprintf(block_name, "%s", GRAPHIC_NAME[graphic_num]);
			simple_div[0] = GRAPHIC_DIV_0[graphic_num];
			simple_div[1] = GRAPHIC_DIV_1[graphic_num];
		} else {
			block_is_core = 0;
			block_is_uncore = 0;
			block_is_graphic = 0;
			sprintf(block_name, "reserved");
			simple_div[0] = 1;
			simple_div[1] = 1;
		}
		j += sprintf(buf + j, "NODE_%d: Checking block %s\n", hwmon->node, block_name);
		if (b.mon_bfs_bypass[i]) {
			if (block_is_graphic == 1) {
				j += sprintf(buf + j, " - presence of a controlled frequency ");
				j += sprintf(buf + j, "divider: simple divider 1/%d or 1/%d\n",
							simple_div[0], simple_div[1]);
			} else {
				j += sprintf(buf + j, " - presence of a controlled frequency ");
				j += sprintf(buf + j, "divider: absent (BFS bypass)\n");
				j += sprintf(buf + j, " - current frequency: %d MHz (BFS bypass)\n",
										b.base_freq[i]);
				j += sprintf(buf + j, " - hardware allowed frequency range:");
				j += sprintf(buf + j, " absent (BFS bypass)\n");
			}
		} else {
			j += sprintf(buf + j, " - presence of a controlled frequency divider:");
			j += sprintf(buf + j, " standard (BFS bypass)\n");
			j += sprintf(buf + j, " - current frequency: %d MHz (divF=0x%x)\n",
						b.mon_freq_curr[i], b.mon_divF_curr[i]);
			j += sprintf(buf + j, " - hardware allowed frequency range:");
			j += sprintf(buf + j, " from %d MHz to %d MHz (0x%x>=divF>=0x%x)\n",
						b.mon_freq_lim_hi[i], b.mon_freq_lim_lo[i],
						b.mon_divF_lim_hi[i], b.mon_divF_lim_lo[i]);
		}

		if (block_is_graphic) {
			if (b.graph_ctrl_bfs_bypass[i]) {
				graph_ctrl_freq_bypassed = b.base_freq[i];
				graph_ctrl_freq_bypassed /= simple_div[b.graph_ctrl_clk_mux[i]];
				j += sprintf(buf + j, " - current frequency: %d MHz",
							graph_ctrl_freq_bypassed);
				j += sprintf(buf + j, " (clk_mux=%d, simple_divider=1/%d",
							b.graph_ctrl_clk_mux[i],
							simple_div[b.graph_ctrl_clk_mux[i]]);
			} else {
				if ((!b.pmc_freq_cfg_alter_disable[i]) && (b.graph_ctrl_en[i])) {
					if ((b.graph_ctrl_mode[i] == 4) ||
								(b.graph_ctrl_mode[i] == 5)) {
						j += sprintf(buf + j, " - thermal control window");
						j += sprintf(buf + j, " with floating divider:");
						j += sprintf(buf + j, " T_lo = %d, T_hi = %d\n",
								b.pmc_freq_gra_float_T_lo_dec[i],
								b.pmc_freq_gra_float_T_hi_dec[i]);
					}
				}
			}
		} else {
			if ((!b.pmc_freq_cfg_alter_disable[i]) && (b.ctrl_en[i])) {
				if ((b.ctrl_mode[i] == 4) || (b.ctrl_mode[i] == 5)) {
					if (block_is_core) {
						j += sprintf(buf + j, " - thermal control window");
						j += sprintf(buf + j, " with floating divider:");
						j += sprintf(buf + j, " T_lo = %d, T_hi = %d\n",
								b.pmc_freq_core_float_T_lo_dec[i],
								b.pmc_freq_core_float_T_hi_dec[i]);
					} else if (block_is_uncore) {
						j += sprintf(buf + j, " - thermal control window");
						j += sprintf(buf + j, " with floating divider:");
						j += sprintf(buf + j, " T_lo = %d, T_hi = %d\n",
								b.pmc_freq_ocn_float_T_lo_dec[i],
								b.pmc_freq_ocn_float_T_hi_dec[i]);
					  }
				}
			}
		}
	}

	return sprintf(buf, "%s", buf);
}

static u32 read_reg(void)
{
	u32 value;
	struct pci_dev *dev;

	dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
				PCI_VIRT_BRIDGE_DEVICE_ID, NULL);
	pci_read_config_dword(dev, 0x70, &value);
	/* To read needed info I use this shift and mask,
	   just like it's done in the script  */
	value = (value >> 16) & 0xffff;
	return value;

}

#ifdef CONFIG_E2K
static int prev_str_err_mode[IPCC_LINKS] = {-1, -1, -1};
#endif

static int read_wlcc_data(struct link_data *data, int node)
{
	struct link_data *a = data;
	struct pci_dev *dev;
	static void __iomem *base_addr;
	int iol_pls;
	int wlcc_err_val;
	int cpu_type = machine.native_id;

	if ((cpu_type == MACHINE_ID_E16C) || (cpu_type == MACHINE_ID_E12C)
						|| (cpu_type == MACHINE_ID_E2C3)) {
		dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
					PCI_VIRT_BRIDGE_DEVICE_ID, NULL);
		base_addr = pci_iomap(dev, 0, PCI_IOL_SIZE);
		if (!base_addr) {
			pci_release_regions(dev);
			return -EFAULT;
		}

		/* iol_bitrate[22:20] from PCS_CTRL3 reg (v5) moved
		 * to pin_wlcc_speed_presets[18:16] PMC_SYS_MON_0 reg (v6)
		 * */
		a->io_mpll = (sic_read_node_nbsr_reg(node, PCS_PMC_REGS_base + PMC_SYS_MON_0_REG)
				& PIN_WLCC_SPEED_PRESETS_MASK) >> PIN_WLCC_SPEED_PRESETS_SHIFT;

		a->wlcc_rate = (readl(base_addr + IOL_PLM_CTLR_SHIFT)
							& WLCC_RATE_MASK) >> WLCC_RATE_SHIFT;
		iol_pls = readl(base_addr) + IOL_PLS_CTLR_SHIFT;
		wlcc_err_val = readl(base_addr + IOL_DLL_STSR_SHIFT);
		pci_iounmap(dev, base_addr);
	}

	if ((cpu_type == MACHINE_ID_E8C) ||
				(cpu_type == MACHINE_ID_E8C2)) {
		a->io_mpll = (sic_read_node_nbsr_reg(node, PCS_CTRL3)
					& MPLL_MASK) >> MPLL_SHIFT;
		a->ip_mpll = (sic_read_node_nbsr_reg(node, PCS_CTRL3)
				& MPLL_LINK_MASK) >> MPLL_LINK_SHIFT;
		a->wlcc_rate = (sic_read_node_nbsr_reg(node, IOL_PLM_CTLR)
					& WLCC_RATE_MASK) >> WLCC_RATE_SHIFT;
		iol_pls = sic_read_node_nbsr_reg(node, IOL_PLS_CTLR);
		wlcc_err_val = sic_read_node_nbsr_reg(node, IOL_DLL_STSR);
	}

	a->wlcc_active = (iol_pls & WLCC_ACTIVE_MASK) >>
			WLCC_ACTIVE_SHIFT;
	a->wlcc_state = (iol_pls & WLCC_STATE_MASK) >>
			WLCC_STATE_SHIFT;
	a->wlcc_width = (iol_pls & WLCC_WIDTH_MASK) >>
			WLCC_WIDTH_SHIFT;
	a->wlcc_cnt = wlcc_err_val & ERR_CNT_MASK;
	a->wlcc_ov = (wlcc_err_val & ERR_OV_MASK) >>
					 ERR_OV_SHIFT;
	a->wlcc_md = (wlcc_err_val & ERR_MD_MASK) >>
					 ERR_MD_SHIFT;

	return 0;
}

static int read_kpi_data(struct link_data *data, int node)
{
	struct link_data *a = data;
	struct pci_dev *dev;
	static void __iomem *base_addr;
	int kpi_err_val;
	u32 pls_ctrl;

	a->iol = (sic_read_node_nbsr_reg(node, RT_LCFG0) &
					IOL_MASK) >> IOL_SHIFT;
	if (a->iol == 1) {
		dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
					PCI_VIRT_BRIDGE_DEVICE_ID, NULL);
		base_addr = pci_iomap(dev, 0, PCI_KPI_SIZE);
		if (!base_addr) {
			pci_release_regions(dev);
			return -EFAULT;
		}

		a->kpi_rate = (readl(base_addr + 0x8) & WLCC_RATE_MASK) >>
							 WLCC_RATE_SHIFT;
		pls_ctrl = readl(base_addr + 0x4);
		a->kpi_active = ((pls_ctrl) &	WLCC_ACTIVE_MASK) >>
						 WLCC_ACTIVE_SHIFT;
		a->kpi_state = ((pls_ctrl) & WLCC_STATE_MASK) >>
						WLCC_STATE_SHIFT;
		a->kpi_width = ((pls_ctrl) & WLCC_WIDTH_MASK) >>
						WLCC_WIDTH_SHIFT;
		kpi_err_val = readl(base_addr + 0xC);
		a->kpi_cnt = kpi_err_val & ERR_CNT_MASK;
		a->kpi_ov = (kpi_err_val & ERR_OV_MASK) >>
							ERR_OV_SHIFT;
		a->kpi_md = (kpi_err_val & ERR_MD_MASK) >>
							 ERR_MD_SHIFT;
		pci_iounmap(dev, base_addr);
	}

	return 0;
}

static void read_ipcc_data(struct link_data *data, int node)
{
	struct link_data *a = data;
	int curr_LCFG;
	int str_shift = 3; /*This shift is used to read from str regs*/
	int lanes = 1;
	int rt_lcfg_val;
	int ipcc_csr[IPCC_LINKS];
	int ipcc_str[IPCC_LINKS];
	struct pci_dev *dev;
	u32 ref_clk_div2_en;
	u32 clk_div2_en_val;
	u32 rx_rate;
	u32 rx_rate_val;
	u32 mplla_multiplier_and_clk_mplla;
	u32 mplla_val;
	u32 mplla_mult_val;
	u32 mplla_div2_val;
	int bitrate, bitrate_mean = 0, lnum = 0;
	int b, i, j;
	int cpu_type = machine.native_id;

	a->multilink = ((sic_read_node_nbsr_reg(node, ST_P)) >>
				 MULTILINK_SHIFT) & MULTILINK_MASK;
	a->mlc = (sic_read_node_nbsr_reg(node, ST_P) >>
				 MLC_SHIFT) & MLC_MASK;
	a->st_p = sic_read_node_nbsr_reg(node, ST_P);

	/*Depending on the number of ipcc link, reading from definite regs */
	for (i = 0; i < IPCC_LINKS; i++) {
		switch (i) {
		case 0:
			curr_LCFG = RT_LCFG1;
			break;
		case 1:
			curr_LCFG = RT_LCFG2;
			break;
		case 2:
			curr_LCFG = RT_LCFG3;
			break;
		}
		rt_lcfg_val = sic_read_node_nbsr_reg(node, curr_LCFG);
		a->vp[i] = rt_lcfg_val & RT_LCFG_VP_MASK;
		a->pn[i] = (rt_lcfg_val >>
				RT_LCFG_PN_SHIFT)&RT_LCFG_PN_MASK;
		ipcc_str[i] = sic_read_node_nbsr_reg(node,
					ipcc_ctrls[i+str_shift].offset);
		a->str_val[i] = ipcc_str[i];
		ipcc_csr[i] = sic_read_node_nbsr_reg(node,
						ipcc_ctrls[i].offset);
		a->csr_reg[i] = ipcc_csr[i];
		a->str_reg[i] = ipcc_ctrls[i+str_shift].offset;
		a->active[i] = (ipcc_csr[i] & ACTIVE_MASK) >> ACTIVE_SHIFT;
		a->width[i] = (ipcc_csr[i] & WIDTH_MASK) >> WIDTH_SHIFT;
		a->state[i] = (ipcc_csr[i] & STATE_MASK) >> STATE_SHIFT;
		a->cnt_err[i] = (ipcc_str[i] & CNT_MASK);
		a->err_mode[i] = (ipcc_str[i] & ERR_MODE_MASK) >> ERR_MODE_SHIFT;

		/* The IPCC_STR register bits [31:30] are responsible for err_mode and
		 * if the value of the previous reading is different, then write 1 to bit [29]
		 * to reset the cnt_err counter [28:0].*/

		if (prev_str_err_mode[i] >=  0 && prev_str_err_mode[i] != a->err_mode[i]) {
			sic_write_node_nbsr_reg(node, ipcc_ctrls[i+str_shift].offset,
								a->str_val[i] | OVER_CNT_MASK);
		}
		prev_str_err_mode[i] = a->err_mode[i];

		if ((cpu_type == MACHINE_ID_E16C) || (cpu_type == MACHINE_ID_E12C)
							|| (cpu_type == MACHINE_ID_E2C3)) {
			/*Depening on bitrate link*/
			switch (i) {
			case 0:
				b = 0;
				break;
			case 1:
				b = 4;
				break;
			case 2:
				b = 8;
				break;
			}

			dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
						PCI_VIRT_BRIDGE_DEVICE_ID, NULL);
			for (j = 0; j < lanes; j++) {
				lnum++;
				/* All magical numbers were got from engineer scripts */
				mplla_multiplier_and_clk_mplla = ((0x80 << 24)|
						(ipcc_rate_ctrls[b+j].offset << 16)|
								 SUP_DIG_MPLLA_ASIC_IN_0);

				pci_write_config_dword(dev, 0x6c,
							mplla_multiplier_and_clk_mplla);
				mplla_val = read_reg();

				mplla_mult_val = (mplla_val >> MPLLA_SHIFT) & MPLLA_MASK;
				mplla_div2_val = (mplla_val >> MPLLA_DIV2_SHIFT) &
									MPLLA_DIV2_MASK;

				ref_clk_div2_en = ((0x80 << 24)|
						(ipcc_rate_ctrls[b+j].offset << 16)|
									SUP_DIG_ASIC_IN);
				pci_write_config_dword(dev, 0x6c, ref_clk_div2_en);
				clk_div2_en_val = read_reg();
				clk_div2_en_val = (clk_div2_en_val >> CLK_DIV2_EN_SHIFT) &
									CLK_DIV2_EN_MASK;

				rx_rate = ((0x80 << 24) | (ipcc_rate_ctrls[b+j].offset << 16) |
								LANEN_DIG_ASIC_RX_ASIC_IN_0);

				pci_write_config_dword(dev, 0x6c, rx_rate);
				rx_rate_val = read_reg();
				rx_rate_val = (rx_rate_val >> RX_RATE_SHIFT) & RX_RATE_MASK;

				bitrate = 2 * 100 * (mplla_mult_val & 0x7f);

				if (((mplla_mult_val >> 7) & 1) == 1) {
					bitrate = bitrate*2;
				}

				if (rx_rate_val == 0) {
					bitrate = bitrate*2;
				}

				if (rx_rate_val == 2) {
					bitrate = bitrate/2;
				}

				if (clk_div2_en_val == 1) {
					bitrate = bitrate/2;
				}

				if (mplla_div2_val == 1) {
					bitrate = bitrate/2;
				}
				bitrate_mean += bitrate;
			}
			bitrate_mean /= lnum;
			a->link_bitrate[i] = bitrate_mean;
			bitrate_mean = 0;
			lnum = 0;
		}
	}
}

static struct link_data read_link_data(int node)
{
	struct link_data a;
	int cpu_type = machine.native_id;
	int ret;

	ret = read_wlcc_data(&a, node);
	if (ret < 0) {
		a.wlcc_state = ret;
	}

	ret = read_kpi_data(&a, node);
	if (ret < 0) {
		a.kpi_state = ret;
	}

	if (cpu_type != MACHINE_ID_E2C3) {
		read_ipcc_data(&a, node);
	}

	return a;
}

static void convert_mbit2gbit(char *buf, int mbit_link_bitrate)
{
	int mod, j = 0;

	j += sprintf(buf, "%d", mbit_link_bitrate / 1000);
	mod = mbit_link_bitrate % 1000;
	if (mod && !(mod % 100)) {
		j += sprintf(buf + j, ".%d", mod / 100);
	} else if (mod && !(mod % 10)) {
		j += sprintf(buf + j, ".%02d", mod / 10);
	} else if (mod) {
		j += sprintf(buf + j, ".%03d", mod);
	}
}

static int get_kpi_information(struct link_data *data, char *buf,
					struct hwmon_data *hwmon, int j)
{
	struct link_data *b = data;

	j += sprintf(buf + j, "NODE%d-kpi2: ",
				hwmon->node);
	if (b->kpi_rate == 1) {
		j += sprintf(buf + j, "full rate, ");
	} else {
		j += sprintf(buf + j, "half rate, ");
	}

	switch (b->kpi_state) {
	case POWEROFF_STATE:
		j += sprintf(buf + j, "state(%d): Poweroff",
					b->kpi_state);
		break;
	case DISABLE_STATE:
		j += sprintf(buf + j, "state(%d): Disable",
					 b->kpi_state);
		break;
	case SLEEP_STATE:
		j += sprintf(buf + j, "state(%d): Sleep",
					 b->kpi_state);
		break;
	case LINKUP_STATE:
		j += sprintf(buf + j, "state(%d): Work ",
					 b->kpi_state);
		j += sprintf(buf + j, "width=0x%x",
					b->kpi_width);
		if (b->kpi_width != FULL_WIDTH) {
			j += sprintf(buf + j, "WARNING (not full wlcc width)");
		}
		break;
	}

	j += sprintf(buf + j, " err_mode=0x%x ", b->kpi_md);
	if (b->kpi_state == LINKUP_STATE) {
		switch (b->kpi_md) {
		case 0:
			j += sprintf(buf + j, "- ERROR\n");
			break;
		case 1:
			j += sprintf(buf + j, "- WARNING ");
			break;
		case 2:
			j += sprintf(buf + j, "- OK ");
			break;
		}
	}

	if ((b->kpi_state == LINKUP_STATE) && (b->kpi_md != 0)) {
		j += sprintf(buf + j, "err_ov=0x%x ", b->kpi_ov);
		if (b->kpi_ov != 0) {
			j += sprintf(buf + j, "- overflown (!!!)");
		}

		j += sprintf(buf + j, "err_cnt=0x%x ", b->kpi_cnt);
		if (b->kpi_cnt == CNT_LIMIT) {
			j += sprintf(buf + j, "- too much errors (!!!)\n");
		} else if (b->kpi_cnt != 0) {
			j += sprintf(buf + j, "- found some errors (!!!)\n");
		} else {
			j += sprintf(buf + j, "- OK\n");
		}
	} else {
		j += sprintf(buf + j, "\n");
	}

	return j;
}

static int get_wlcc_information(struct link_data *data, char *buf,
					struct hwmon_data *hwmon, int j)
{
	struct link_data *b = data;
	int cpu_type = machine.native_id;
	char *wlcc_half_rate[] = {"2.5", "3", "2.5", "3", "1.25", "1.5", "2", "4"};
	char *wlcc_full_rate[] = {"5", "6", "5", "6", "2.5", "3", "4", "8"};
	char *wlcc_half_rate_v6[] = {"1.25", "1.5", "2.5", "3", "1", "2", "2.25", "2.75"};
	char *wlcc_full_rate_v6[] = {"2.5", "3", "5", "6", "2", "4", "4.5", "5.5"};

	j += sprintf(buf + j, "NODE%d-wlcc: ", hwmon->node);
	if (b->wlcc_rate == 1) {
		if ((cpu_type == MACHINE_ID_E16C) || (cpu_type == MACHINE_ID_E12C) ||
							 (cpu_type == MACHINE_ID_E2C3)) {
			j += sprintf(buf + j, "%s Gbit/s (mpll=0x%x full rate), ",
						wlcc_full_rate_v6[b->io_mpll], b->io_mpll);
		} else {
			j += sprintf(buf + j, "%s Gbit/s (mpll=0x%x full rate), ",
						wlcc_full_rate[b->io_mpll], b->io_mpll);
		}
	} else {
		if ((cpu_type == MACHINE_ID_E16C) || (cpu_type == MACHINE_ID_E12C) ||
							 (cpu_type == MACHINE_ID_E2C3)) {
			j += sprintf(buf + j, "%s Gbit/s (mpll=0x%x half rate), ",
						 wlcc_half_rate_v6[b->io_mpll], b->io_mpll);
		} else {
			j += sprintf(buf + j, "%s Gbit/s (mpll=0x%x half rate), ",
						 wlcc_half_rate[b->io_mpll], b->io_mpll);
		}
	}

	switch (b->wlcc_active) {
	case LINK_NOT_ACTIVE:
		j += sprintf(buf + j, "wlcc not active(%d), ",
				 b->wlcc_active);
		break;
	case LINK_ACTIVE:
		j += sprintf(buf + j, "wlcc is active(%d), ",
				 b->wlcc_active);
		break;
	}

	switch (b->wlcc_state) {
	case POWEROFF_STATE:
		j += sprintf(buf + j, "state(%d): Poweroff",
					b->wlcc_state);
		break;
	case DISABLE_STATE:
		j += sprintf(buf + j, "state(%d): Disable",
					 b->wlcc_state);
		break;
	case SLEEP_STATE:
		j += sprintf(buf + j, "state(%d): Sleep",
					 b->wlcc_state);
		break;
	case LINKUP_STATE:
		j += sprintf(buf + j, "state(%d): Work ",
					 b->wlcc_state);
		j += sprintf(buf + j, "width=0x%x", b->wlcc_width);
		if (b->wlcc_width != FULL_WIDTH) {
			j += sprintf(buf + j,
				"WARNING (not full wlcc width)");
		}
		break;
	}

	j += sprintf(buf + j, " err_mode=0x%x ", b->wlcc_md);
	if (b->wlcc_state == LINKUP_STATE) {
		switch (b->wlcc_md) {
		case 0:
			j += sprintf(buf + j, "- ERROR\n");
			break;
		case 1:
			j += sprintf(buf + j, "- WARNING ");
			break;
		case 2:
			j += sprintf(buf + j, "- OK ");
			break;
		}
	}
	if ((b->wlcc_state == LINKUP_STATE) && (b->wlcc_md != 0)) {
		j += sprintf(buf + j, "err_ov=0x%x ", b->wlcc_ov);
		if (b->wlcc_ov != 0) {
			j += sprintf(buf + j, "- overflown (!!!)");
		}

		j += sprintf(buf + j, "err_cnt=0x%x ", b->wlcc_cnt);
		if (b->wlcc_cnt == CNT_LIMIT) {
			j += sprintf(buf + j, "- too much errors (!!!)\n");
		} else if (b->wlcc_cnt != 0) {
			j += sprintf(buf + j, "- found some errors (!!!)\n");
		} else {
			j += sprintf(buf + j, "- OK\n");
		}
	} else {
		j += sprintf(buf + j, "\n");
	}

	return j;
}

static int get_ipcc_information(struct link_data *data, char *buf,
					struct hwmon_data *hwmon, int j)
{
	struct link_data *b = data;
	char *ip_rate[] = {"2.5", "3", "4", "4.5", "5", "5.5", "6", "6.25"};
	int i, cpu_type = machine.native_id;
	char gbit_link_bitrate[10];
	char letter;

	for (i = 0; i < IPCC_LINKS; i++) {
		switch (ipcc_ctrls[i].offset) {
		case IPCC_CSR1:
			letter = 'A';
			break;
		case IPCC_CSR2:
			letter = 'B';
			break;
		case IPCC_CSR3:
			letter = 'C';
			break;
		}

		j += sprintf(buf + j, "NODE%d-ipcc-%c-csr(0x%x) width=0x%x, ",
					 hwmon->node, letter, ipcc_ctrls[i].offset, b->width[i]);
		if ((cpu_type == MACHINE_ID_E8C) ||
					(cpu_type == MACHINE_ID_E8C2)) {
			j += sprintf(buf + j, "%s Gbit/s(mpll=0x%x), ",
						ip_rate[b->ip_mpll], b->ip_mpll);
		} else if ((cpu_type == MACHINE_ID_E16C) ||
					(cpu_type == MACHINE_ID_E12C) ||
						 (cpu_type == MACHINE_ID_E2C3)) {
			convert_mbit2gbit(gbit_link_bitrate, b->link_bitrate[i]);
			j += sprintf(buf + j, "%s Gbit/s, ", gbit_link_bitrate);
		}
		if (b->width[i] != FULL_WIDTH) {
			j += sprintf(buf + j,
					"WARNING (not full width), ");
		}

		switch (b->active[i]) {
		case LINK_NOT_ACTIVE:
			j += sprintf(buf + j, "link not active(%d), ",
						 b->active[i]);
			break;
		case LINK_ACTIVE:
			j += sprintf(buf + j, "link is active(%d), ",
						 b->active[i]);
			break;
		}

		switch (b->state[i]) {
		case POWEROFF_STATE:
			j += sprintf(buf + j, "state(%d): Poweroff",
						b->state[i]);
			break;
		case DISABLE_STATE:
			j += sprintf(buf + j, "state(%d): Disable",
						 b->state[i]);
			break;
		case SLEEP_STATE:
			j += sprintf(buf + j, "state(%d): Sleep",
						 b->state[i]);
			break;
		case LINKUP_STATE:
			j += sprintf(buf + j, "state(%d): Work",
						 b->state[i]);
			break;
		case SERVICE_STATE:
			j += sprintf(buf + j, "state(%d): Service",
						 b->state[i]);
			break;
		case REINIT_STATE:
			j += sprintf(buf + j, "state(%d): Reinit",
						 b->state[i]);
			break;
		}

		if (b->vp[i] == 1) {
			j += sprintf(buf + j,
				", connected with NODE_%d\n", b->pn[i]);
		}

		else {
			j += sprintf(buf + j,
				", without connection\n");
		}

		if (machine.native_id != MACHINE_ID_E16C) {
			if ((b->multilink != 0) || (b->mlc != 0)) {
				j += sprintf(buf + j,
					"ERROR!!! Multilink is not supported for this ");
				j += sprintf(buf + j,
					"CPU, but mlp=0x%x and mlc=0x%x  (ST_P=0x%x)\n",
					b->multilink, b->mlc, b->st_p);
			}
		}

		else if ((b->multilink == 0) && (b->mlc == 1)) {
			j += sprintf(buf + j,
				"ERROR!!! Multilink is not connected on motherboard");
			j += sprintf(buf + j,
				", but enabled by software (ST_P=0x%x)\n", b->st_p);
		}

		else if ((b->multilink == 1) && (b->mlc == 0)) {
			j += sprintf(buf + j,
				"(multilink is disabled by software)\n");
		}

		else if ((b->multilink == 1) && (b->mlc == 1)) {
			j += sprintf(buf + j,
				"(multilink is enabled)\n");
		}
		if (b->state[i] == LINKUP_STATE) {
			switch (b->err_mode[i]) {
			case IPCC_STR_MODE_LERR:
				j += sprintf(buf + j,
					"NODE%d-ipcc-%c-str(0x%x) err_mode=%d - WARNING(0x%x)\n",
						hwmon->node, letter, b->str_reg[i],
						b->err_mode[i], b->str_val[i]);
				j += sprintf(buf + j,
					"amount of errors in cnt_err -  %d\n", b->cnt_err[i]);
				break;
			case IPCC_STR_MODE_RTRY:
				j += sprintf(buf + j,
					"NODE%d-ipcc-%c-str(0x%x) err_mode=%d - OK(0x%x)\n",
						hwmon->node, letter, b->str_reg[i],
						b->err_mode[i], b->str_val[i]);
				j += sprintf(buf + j,
					"amount of errors in cnt_err -  %d\n", b->cnt_err[i]);

				break;
			default:
				j += sprintf(buf + j,
					"NODE%d-ipcc-%c-str(0x%x) err_mode=%d - ERROR(0x%x)\n",
						hwmon->node, letter,  b->str_reg[i],
						b->err_mode[i], b->str_val[i]);
			}
		} else {
			j += sprintf(buf + j,
				"NODE%d-ipcc-%c-str(0x%x) err_mode=%d - OFF(0x%x - CSR)\n",
						hwmon->node, letter,  b->str_reg[i],
						b->err_mode[i], b->csr_reg[i]);
		}
	}

	return j;
}

static ssize_t show_link_data(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct link_data b = read_link_data(hwmon->node);
	int cpu_type = machine.native_id;
	int j = 0;

	/* KPI INFORMATION */
	if (b.iol) {
		j = get_kpi_information(&b, buf, hwmon, j);
	}

	/* WLCC INFORMATION */
	if (b.wlcc_state >= 0) {
		j = get_wlcc_information(&b, buf, hwmon, j);
	}

	/* IPCC INFORMATION */
	if (cpu_type != MACHINE_ID_E2C3) {
		j = get_ipcc_information(&b, buf, hwmon, j);
	}

	return sprintf(buf, "%s", buf);
}

static int get_mem_channels(void)
{
	int mem_channels;
	int cpu_type = machine.native_id;

	switch (cpu_type) {
	case MACHINE_ID_E16C:
		mem_channels = 8;
		break;
	case MACHINE_ID_E12C:
		mem_channels = 2;
		break;
	case MACHINE_ID_E2C3:
		mem_channels = 2;
		break;
	case MACHINE_ID_E8C2:
		mem_channels = 4;
		break;
	case MACHINE_ID_E8C:
		mem_channels = 4;
		break;
	}

	return mem_channels;
}

static struct mem_data read_mem(int node)
{
	struct mem_data a;
	int val;
	int num_link[MEM_LINKS] = {0, 1, 2, 3, 4, 5, 6, 7};
	int i;
	int mem_channels = get_mem_channels();

	/* Reading information from MC in case of e12c, e16c, e2c3 */
	if (((machine.native_id == MACHINE_ID_E16C) ||
			 (machine.native_id == MACHINE_ID_E12C)) ||
				(machine.native_id == MACHINE_ID_E2C3)) {
		for (i = 0; i < mem_channels; i++) {
			sic_write_node_nbsr_reg(node,
					mc_ctrls[4].offset, num_link[i]);
			val = sic_read_node_nbsr_reg(node,
					mc_ctrls[5].offset);
			a.mem_mode[i] = val & MC_ENABLE_MASK;
			a.mem_secnt[i] = (val >> MC_SECNT_SHIFT) &
							 MC_SECNT_MASK;
			a.mem_uecnt[i] = (val >> MC_UECNT_SHIFT) &
							MC_UECNT_MASK;
			a.mem_dmode[i] = (val >> MC_DMODE_SHIFT) &
							MC_DMODE_MASK;
			a.mem_reg_val[i] = val;
			a.mem_ctl_val[i] = sic_read_node_nbsr_reg(node,
								MC_CTL);
			a.mem_ctl_mcen[i] = sic_read_node_nbsr_reg(node,
						MC_CTL) & MC_CTL_MCEN_MASK;
			a.mem_status_val[i] = sic_read_node_nbsr_reg(node,
								MC_STATUS);
			a.mem_rst_done[i] = (sic_read_node_nbsr_reg(node,
				MC_STATUS) >> MC_ST_RST_DONE_SHIFT)
						& MC_ST_RST_DONE_MASK;
			a.mem_reg[i] = mc_ctrls[5].offset;
			a.mem_hmu_mcen = (sic_read_node_nbsr_reg(node,
				HMU_MIC) >> HMU_MCEN_SHIFT) & HMU_MCEN_MASK;
		}
	}

	/* Reading information from MC in case of e8c, e8c2 */
	else if ((machine.native_id == MACHINE_ID_E8C) ||
			 (machine.native_id == MACHINE_ID_E8C2)) {
		for (i = 0; i < mem_channels; i++) {
			val = sic_read_node_nbsr_reg(node, mc_ctrls[i].offset);
			a.mem_mode[i] = val & MC_ENABLE_MASK;
			a.mem_secnt[i] = (val >> MC_SECNT_SHIFT)
							& MC_SECNT_MASK;
			a.mem_uecnt[i] = (val >> MC_UECNT_SHIFT)
							& MC_UECNT_MASK;
			a.mem_dmode[i] = (val >> MC_DMODE_SHIFT)
							& MC_DMODE_MASK;
			a.mem_reg_val[i] = val;
			a.mem_ctl_val[i] = sic_read_node_nbsr_reg(node,
							MC_CTL);
			a.mem_ctl_mcen[i] = sic_read_node_nbsr_reg(node,
						MC_CTL) & MC_CTL_MCEN_MASK;
			a.mem_status_val[i] = sic_read_node_nbsr_reg(node,
						MC_STATUS);
			a.mem_rst_done[i] = (sic_read_node_nbsr_reg(node,
				MC_STATUS) >> MC_ST_RST_DONE_SHIFT) &
							 MC_ST_RST_DONE_MASK;
			a.mem_reg[i] = mc_ctrls[i].offset;
		}
	}

	return a;
}

static ssize_t show_mem_data(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct mem_data b = read_mem(hwmon->node);
	int j;
	int i;
	int mem_channels = get_mem_channels();
	int cpu_type = machine.native_id;
	int mc_enabled;

	for (i = 0; i < mem_channels; i++) {
		j += sprintf(buf + j,
			"NODE-%d_MC%d_ECC(0x%x): mem_mode=%d, secnt=0x%x, uecnt=0x%x, dmode=0x%x\n",
						hwmon->node, i, b.mem_reg[i],
						b.mem_mode[i], b.mem_secnt[i],
						b.mem_uecnt[i], b.mem_dmode[i]);
		if ((b.mem_ctl_mcen[i] != 1) && ((cpu_type == MACHINE_ID_E8C) ||
					 (cpu_type == MACHINE_ID_E8C2))) {
			j += sprintf(buf + j,
				"warning!!! MC%d IS DISABLED, MCEN IS OFF\n", i);
		}
		mc_enabled = (b.mem_hmu_mcen >> i) & HMU_ENABLE;
		if ((mc_enabled == 0) &&
			((cpu_type == MACHINE_ID_E16C) ||
				 (cpu_type == MACHINE_ID_E2C3) ||
					      (cpu_type == MACHINE_ID_E12C))) {
			j += sprintf(buf + j,
				"warning!!! MC%d IS DISABLED, HMU_MIC_MCEN IS OFF\n", i);
		}


		if (b.mem_mode[i] != 1) {
			j += sprintf(buf + j,
				"Warning!!! ECC control is disabled\n");
		}

		if (b.mem_dmode[i] != 0) {
			j += sprintf(buf + j,
				"Warning!!! ECC debug mode is set\n");
		}

		if (b.mem_uecnt[i] != 0) {
			j += sprintf(buf + j,
				"Warning!!! ECC multi-error counter (uecnt = 0x%x)\n",
							b.mem_uecnt[i]);
		}

		if (b.mem_secnt[i] != 0) {
			j += sprintf(buf + j,
				"Warning!!! ECC single-error counter (secnt = 0x%x)\n",
							b.mem_secnt[i]);
		}

		if (b.mem_ctl_mcen[i] != 1) {
			j += sprintf(buf + j,
				"Warning!!! controller is disabled (MC_CTL = 0x%x)\n",
							b.mem_ctl_val[i]);
		}
		if ((cpu_type == MACHINE_ID_E16C) ||
				(cpu_type == MACHINE_ID_E12C) ||
						(cpu_type == MACHINE_ID_E2C3)) {
			if (b.mem_rst_done[i] == 0) {
				j += sprintf(buf + j,
					"Warning!!! status rst_done = 0x%x (MC_STATUS = 0x%x)\n",
							b.mem_rst_done[i],
							b.mem_status_val[i]);
			}
		}
	}

	return sprintf(buf, "%s", buf);
}

static struct mem_data read_mem_rate(int node)
{
	struct mem_data a;
	int i;
	int num_link[MEM_LINKS] = {0, 1, 2, 3, 4, 5, 6, 7};
	int mc_freq;
	int mc_ddr_rate;
	long long int mc_mon_ctr0;
	int mc_mon_ctr_ext;
	long long int mc_mnt0;
	int ref = 125;
	long int pwr_mgr1;
	long int pwr_mgr2;
	int mc_rst;
	int mc_outena;
	int mc_clkr;
	int mc_clkf;
	int mc_clkod;
	int mc_lock;
	int cpu_type = machine.native_id;
	int mem_channels = get_mem_channels();

	if ((cpu_type == MACHINE_ID_E2C3) ||
		(cpu_type == MACHINE_ID_E12C) ||
			(cpu_type == MACHINE_ID_E16C)) {
		sic_write_node_nbsr_reg(node, MC_CH, 0xF);
		sic_write_node_nbsr_reg(node, MC_MON_CTL, 0xFFFF000F);
		sic_write_node_nbsr_reg(node, MC_MON_CTL, 0XFFFF0000);
		mdelay(MC_MON_DELAY_MS);
		sic_write_node_nbsr_reg(node, MC_CH, 0xF);
		sic_write_node_nbsr_reg(node, MC_MON_CTL, 0x0000000C);
		sic_write_node_nbsr_reg(node, MC_CH, 0X0);

		for (i = 0; i < mem_channels; i++) {
			sic_write_node_nbsr_reg(node, MC_CH, num_link[i]);
			mc_mon_ctr0 = sic_read_node_nbsr_reg(node,
			MC_MON_CTR0);
			mc_mon_ctr_ext = sic_read_node_nbsr_reg(node,
			MC_MON_CTRext);

			mc_mnt0 = mc_mon_ctr_ext & MC_MNT0_MASK;
			mc_mnt0 = (mc_mnt0 << MC_MNT0_SHIFT) + mc_mon_ctr0;

			mc_freq = mc_mnt0/10/1000000;
			mc_ddr_rate = mc_freq * 2 * 2;
			a.mem_freq[i] = mc_freq;
			a.mem_ddr_rate[i] = mc_ddr_rate;
			a.mem_ctl_val[i] = sic_read_node_nbsr_reg(node,
							MC_CTL);
			a.mem_ctl_mcen[i] = sic_read_node_nbsr_reg(node,
					MC_CTL) & MC_CTL_MCEN_MASK;
			}
		a.mem_hmu_mcen = (sic_read_node_nbsr_reg(node,
				HMU_MIC) >> HMU_MCEN_SHIFT) & HMU_MCEN_MASK;
	} else if ((cpu_type == MACHINE_ID_E8C) ||
			 (cpu_type == MACHINE_ID_E8C2)) {
		/* Here I get memory freq from mgr1 */
		pwr_mgr1 = sic_read_node_nbsr_reg(node, PWR_MGR1);
		mc_rst = pwr_mgr1 & RST_MASK;
		mc_outena = (pwr_mgr1 & OUTENA_MASK) >> OUTENA_SHIFT;
		mc_clkr = (pwr_mgr1 & CLKR_MASK) >> CLKR_SHIFT;
		mc_clkf = (pwr_mgr1 & CLKF_MASK) >> CLKF_SHIFT;
		mc_clkod = (pwr_mgr1 & CLKOD_MASK) >> CLKOD_SHIFT;
		mc_lock = (pwr_mgr1 & LOCK_MASK) >> LOCK_SHIFT;
		a.mem_freq_e8c_mgr1 = ref / (mc_clkr + 1) * (mc_clkf + 1) /
						(mc_clkod + 1);
		a.mem_ddr_e8c_mgr1 = 4 * ref / (mc_clkr + 1) * (mc_clkf + 1) /
						(mc_clkod + 1);

		/* Here I do th same thing but from mgr2 */
		pwr_mgr2 = sic_read_node_nbsr_reg(node, PWR_MGR2);
		mc_rst = pwr_mgr2 & RST_MASK;
		mc_outena = (pwr_mgr2 & OUTENA_MASK) >> OUTENA_SHIFT;
		mc_clkr = (pwr_mgr2 & CLKR_MASK) >> CLKR_SHIFT;
		mc_clkf = (pwr_mgr2 & CLKF_MASK) >> CLKF_SHIFT;
		mc_clkod = (pwr_mgr2 & CLKOD_MASK) >> CLKOD_SHIFT;
		mc_lock = (pwr_mgr2 & LOCK_MASK) >> LOCK_SHIFT;
		a.mem_freq_e8c_mgr2 = ref / (mc_clkr + 1) * (mc_clkf + 1) /
						(mc_clkod + 1);
		a.mem_ddr_e8c_mgr2 = 4 * ref / (mc_clkr + 1) *
						(mc_clkf + 1) / (mc_clkod + 1);
	}

	return a;
}

static ssize_t show_mem_rate(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	int idx = to_sensor_dev_attr(attr)->index;
	struct mem_data b = read_mem_rate(hwmon->node);
	int j = 0;
	int curr_ch;
	int mc_enabled;
	int mem_channels = get_mem_channels();

	for (curr_ch = 0; curr_ch < mem_channels; curr_ch++) {
		mc_enabled = ((b.mem_hmu_mcen >> curr_ch) & HMU_ENABLE);
		if (mc_enabled == 0) {
			j += sprintf(buf + j,
				"WARNING!!! NODE_%d: MC_%d: controller is disabled (MIC_HMU_MCEN=%d)\n",
					hwmon->node, curr_ch, b.mem_hmu_mcen);
		} else {
			j += sprintf(buf + j,
				"NODE_%d: MC_%d: DDR4: %d (MC_freq %d MHz) likely!\n",
						hwmon->node, curr_ch, b.mem_ddr_rate[curr_ch],
									b.mem_freq[curr_ch]);
		}
	}

	return sprintf(buf, "%s", buf);
}

uint8_t mem_flag;
static struct mem_data save[MAX_NODES];
static ssize_t show_mem_rate_saved(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	int j = 0;
	int curr_ch;
	int mc_enabled;
	int mem_channels = get_mem_channels();

	for (curr_ch = 0; curr_ch < mem_channels; curr_ch++) {
		mc_enabled = ((save[hwmon->node].mem_hmu_mcen >> curr_ch) & HMU_ENABLE);
		if (mc_enabled == 0) {
			j += sprintf(buf + j,
				"WARNING!!! NODE_%d: MC_%d: controller is disabled (MIC_HMU_MCEN=%d)\n",
					hwmon->node, curr_ch, save[hwmon->node].mem_hmu_mcen);
		} else {
			j += sprintf(buf + j,
				"NODE_%d: MC_%d: DDR4: %d (MC_freq %d MHz) likely!\n",
					hwmon->node, curr_ch,
						save[hwmon->node].mem_ddr_rate[curr_ch],
						save[hwmon->node].mem_freq[curr_ch]);
		}
	}

	return sprintf(buf, "%s", buf);
}

#ifdef CONFIG_E2K
static struct task_struct *kthread[MAX_NODES];
#endif
static int t[MAX_NODES] = {1, 2, 3, 4};

int thread_function(void *thread_nr)
{
	int t_nr = *(int *)thread_nr;
	int curr_node;

	curr_node = t_nr - 1;
	save[curr_node] = read_mem_rate(curr_node);

	return 0;
}

static ssize_t show_mem_rate_e8c(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct mem_data b = read_mem_rate(hwmon->node);
	int mem_channels = get_mem_channels();
	int i;
	int j = 0;

	for (i = 0; i < mem_channels; i++) {
		if ((i == 0) || (i == 1)) {
			j += sprintf(buf + j,
				"NODE_%d: MC_%d: DDR4: %d (MC_freq %d MHz): MGR1\n",
					hwmon->node, i, b.mem_ddr_e8c_mgr1,
							b.mem_freq_e8c_mgr1);
		} else if ((i == 2) || (i == 3)) {
			j += sprintf(buf + j,
				"NODE_%d: MC_%d: DDR4: %d (MC_freq %d MHz): MGR2\n",
					hwmon->node, i, b.mem_ddr_e8c_mgr2,
							b.mem_freq_e8c_mgr2);
		}
	}

	return sprintf(buf, "%s", buf);
}

static struct pins_data read_pins(int node)
{
	struct pins_data a;
	int PMC_ADDR = PCS_PMC_REGS_base + PMC_INFO;
	int pmc_inform = sic_read_node_nbsr_reg(node, PMC_ADDR);
	int rt_lcfg_val;
	int sys_mon_0_reg = PCS_PMC_REGS_base + PMC_SYS_MON_0_REG;
	int sys_mon_0 = sic_read_node_nbsr_reg(node, sys_mon_0_reg);
	int sys_mon_1_reg = PCS_PMC_REGS_base + PMC_SYS_MON_1_REG;
	int sys_mon_1 = sic_read_node_nbsr_reg(node, sys_mon_1_reg);
	int curr_LCFG;

	switch (node) {
	case 0:
		curr_LCFG = RT_LCFG0;
		break;
	case 1:
		curr_LCFG = RT_LCFG1;
		break;
	case 2:
		curr_LCFG = RT_LCFG2;
		break;
	case 3:
		curr_LCFG = RT_LCFG3;
		break;
	}

	rt_lcfg_val = sic_read_node_nbsr_reg(node, curr_LCFG);
	a.vp = rt_lcfg_val & RT_LCFG_VP_MASK;
	a.pn = (rt_lcfg_val >> RT_LCFG_PN_SHIFT) & RT_LCFG_PN_MASK;
	a.sys_mon_0 = sic_read_node_nbsr_reg(node, sys_mon_0_reg);
	a.sys_mon_1 = sic_read_node_nbsr_reg(node, sys_mon_1_reg);
	a.pmc_info = pmc_inform;

	return a;
}

static ssize_t show_pins(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct pins_data b = read_pins(hwmon->node);
	int i;
	char *machine_model;
	int cpu_type = machine.native_id;
	int pin;
	int id_model = b.pmc_info & PMC_MODEL_MASK;
	int id_version = (b.pmc_info & PMC_VERSION_MASK) >> PMC_VERSION_SHIFT;
	int j;

	switch (cpu_type) {
	case MACHINE_ID_E16C:
		machine_model = "Elbrus-16C";
		break;
	case MACHINE_ID_E12C:
		machine_model = "Elbrus-12C";
		break;
	case MACHINE_ID_E2C3:
		machine_model = "Elbrus-E2C3";
		break;
	}

	j = sprintf(buf, "Identificator PMC: 0x%x\n", b.pmc_info);
	j += sprintf(buf + j,
		" - cpu model: %s (0x%x)\n", machine_model, id_model);
	j += sprintf(buf + j,
		" - cpu version: %x\n", id_version);
	j += sprintf(buf + j,
		"NODE_%d: Register PMC_SYS_MON_0=0x%x\n",
				hwmon->node, b.sys_mon_0);

	/* Here depending on cpu type, I'm printing config of pins */
	for (i = 0; i < 8; i++) {
		pin = (b.sys_mon_0 >> pins_ctrls[i].shift) &
						pins_ctrls[i].mask;
		j += sprintf(buf + j, " - %s=0x%x",
					pins_ctrls[i].name, pin);
		if ((i == 0 || i == 1 || i == 2 || i == 4) &&  (pin == 1)) {
			j += sprintf(buf + j, " (warning!!!)");
		}
		j += sprintf(buf + j, "\n");
	}

	if (cpu_type == MACHINE_ID_E12C) {
		for (i = 8; i < 10; i++) {
			pin = (b.sys_mon_0 >> pins_ctrls[i].shift) &
							pins_ctrls[i].mask;
			j += sprintf(buf + j, " - %s=0x%x",
						pins_ctrls[i].name, pin);
		}
	}

	if (cpu_type == MACHINE_ID_E16C) {
		for (i = 9; i < 13; i++) {
			pin = (b.sys_mon_0 >> pins_ctrls[i].shift) &
							pins_ctrls[i].mask;
			j += sprintf(buf + j, " - %s=0x%x",
					pins_ctrls[i].name, pin);
			if ((i == 11 || i == 12) && (pin == 1)) {
				j += sprintf(buf + j, " (warning!!!)");
			}
		j += sprintf(buf + j, "\n");
		}
	}

	if (cpu_type == MACHINE_ID_E2C3) {
		pin = (b.sys_mon_0 >> pins_ctrls[i].shift) &
					pins_ctrls[13].mask;
		j += sprintf(buf + j, " - %s=0x%x",
				pins_ctrls[13].name, pin);
		if (pin == 1) {
			j += sprintf(buf + j, " (warning!!!)");
		}
		j += sprintf(buf + j, "\n");
	}

	j += sprintf(buf + j,
			"NODE_%d: Register PMC_SYS_MON_1=0x%x\n",
					hwmon->node, b.sys_mon_1);
	for (i = 14; i < 23; i++) {
		pin = (b.sys_mon_1 >> pins_ctrls[i].shift) &
						 pins_ctrls[i].mask;
		j += sprintf(buf + j, " - %s=0x%x",
				pins_ctrls[i].name, pin);

		if ((i != 20 && i != 21 && i != 22) && (pin == 1)) {
			j += sprintf(buf + j, " (warning!!!)");
		}
		j += sprintf(buf + j, "\n");
	}

	if (cpu_type == MACHINE_ID_E12C) {
		for (i = 23; i < 28; i++) {
			pin = (b.sys_mon_1 >> pins_ctrls[i].shift) &
							pins_ctrls[i].mask;
			j += sprintf(buf + j, " - %s=0x%x",
					pins_ctrls[i].name, pin);
			if ((i != 27) && (pin == 1)) {
				j += sprintf(buf + j, " (warning!!!)");
			}
			j += sprintf(buf + j, "\n");
		}
	}

	if (cpu_type == MACHINE_ID_E16C) {
		for (i = 28; i < 42; i++) {
			pin = (b.sys_mon_1 >> pins_ctrls[i].shift) &
					pins_ctrls[i].mask;
			j += sprintf(buf + j, " - %s=0x%x",
						pins_ctrls[i].name, pin);
			if ((i != 38 && i != 39 && i != 40 && i != 41)
								&& (pin == 1)) {
				j += sprintf(buf + j, " (warning!!!)");
			}
			j += sprintf(buf + j, "\n");
		}
	}

	if (cpu_type == MACHINE_ID_E2C3) {
		for (i = 41; i < 44; i++) {
			pin = (b.sys_mon_1 >> pins_ctrls[i].shift) &
							pins_ctrls[i].mask;
			j += sprintf(buf + j,
				" - %s=0x%x", pins_ctrls[i].name, pin);

			if ((i != 41) && (pin == 1)) {
				j += sprintf(buf + j, " (warning!!!)");
			}
			j += sprintf(buf + j, "\n");
		}
	}

	return sprintf(buf, "%s", buf);
}

static struct bist_data read_bist(int node)
{
	struct bist_data a;
	struct pci_dev *dev;
	static void __iomem *base_addr;
	/* GPU_BIST READ */
	dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
				PCI_VIRT_GX6650_DEVICE_ID, NULL);
	pci_read_config_dword(dev, 0x40, &a.GPU.word);
	/* VXE_BIST READ */
	dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
				PCI_VIRT_E5810_DEVICE_ID, NULL);
	pci_read_config_dword(dev, 0x40, &a.VXE.word);
	/* VXD_BIST READ */
	dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
				PCI_VIRT_D5520_DEVICE_ID, NULL);
	pci_read_config_dword(dev, 0x40, &a.VXD.word);
	/* MGA2_BIST READ (READING FROM BAR0) */
	dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
			PCI_VIRT_MGA25_DEVICE_ID, NULL);
	base_addr = pci_iomap(dev, 0, PCI_BIST_SIZE);
	if (!base_addr) {
		pci_release_regions(dev);
		a.MGA_present = false;
	} else {
		a.MGA.word = readl(base_addr + 0x3F8);
		a.MGA_present = true;
	}
	pci_iounmap(dev, base_addr);

	return a;
}


static ssize_t show_bist_info(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct bist_data a = read_bist(hwmon->node);
	int i;
	int j = 0;
	int GPU_BIST_bits[MAX_GPU] = {a.GPU.SLC2, a.GPU.TA_UVS, a.GPU.tornado, a.GPU.texas_ph0,
			  a.GPU.raterisation_ph0, a.GPU.USC0_dustA_ph0, a.GPU.USC1_dustA_ph0,
			  a.GPU.USC0_dustB_ph0, a.GPU.USC1_dustB_ph0, a.GPU.texas_ph1,
			  a.GPU.raterisation_ph1, a.GPU.USC0_dustA_ph1, a.GPU.USC1_dustA_ph1};
	char GPU_BIST_name[MAX_GPU][WORD_SIZE] = {"SLC2", "TA_UVS", "tornado", "texas_ph0",
				"raterisation_ph0", "USC0_dustA_ph0", "USC1_dustA_ph0",
				"USC0_dustB_ph0", "USC1_dustB_ph0", "texas_ph1",
				"raterisation_ph1", "USC0_dustA_ph1", "USC1_dustA_ph1"};
	int VXE_BIST_bits[MAX_VXE] = {a.VXE.front_end_p0, a.VXE.cache_p0, a.VXE.back_end_p0,
				a.VXE.front_end_p1, a.VXE.cache_p1, a.VXE.back_end_p1,
				a.VXE.front_end_p2, a.VXE.cache_p2, a.VXE.back_end_p2,
				a.VXE.sys_if};
	char VXE_BIST_name[MAX_VXE][WORD_SIZE] = {"front_end_p0", "cache_p0", "back_end_p0",
				"front_end_p1", "cache_p1", "back_end_p1",
				"front_end_p2", "cache_p2", "back_end_p2", "sys_if"};
	int VXD_BIST_bits[MAX_VXD] = {a.VXD.mmu_cache, a.VXD.mtx_core_ram,
			a.VXD.pipe1, a.VXD.pipe2, a.VXD.pipe3};
	char VXD_BIST_name[MAX_VXD][WORD_SIZE] = {"mmu_cache", "mtx_core_ram", "pipe1",
							 "pipe2", "pipe3"};
	int MGA_BIST_bits[MAX_MGA] = {a.MGA.bist_0, a.MGA.bist_1, a.MGA.bist_2,
				a.MGA.bist_3, a.MGA.bist_4, a.MGA.bist_5,
				a.MGA.bist_6, a.MGA.bist_7, a.MGA.bist_8,
				a.MGA.bist_9};
	char MGA_BIST_name[MAX_MGA][WORD_SIZE] = {"bist_0", "bist_1", "bist_2", "bist_3", "bist_4",
				 "bist_5", "bist_6", "bist_7", "bist_8", "bist_9"};

	/*Checking GPU_BIST*/
	j += sprintf(buf + j, "GPU_BIST:\n");
	for (i = 0; i < MAX_GPU; i++) {
		if (GPU_BIST_bits[i]) {
			j += sprintf(buf + j, "%s=%d -- ERROR in memory\n",
						GPU_BIST_name[i], GPU_BIST_bits[i]);
		} else {
			j += sprintf(buf + j, "%s=%d\n", GPU_BIST_name[i], GPU_BIST_bits[i]);
		}
	}

	/*Checking VXE_BIST*/
	j += sprintf(buf + j, "\nVXE_BIST:\n");
	for (i = 0; i < MAX_VXE; i++) {
		if (VXE_BIST_bits[i]) {
			j += sprintf(buf + j, "%s=%d -- ERROR in memory\n",
						VXE_BIST_name[i], VXE_BIST_bits[i]);
		} else {
			j += sprintf(buf + j, "%s=%d\n", VXE_BIST_name[i], VXE_BIST_bits[i]);
		}
	}

	/*Checking VXD_BIST*/
	j += sprintf(buf + j, "\nVXD_BIST:\n");
	for (i = 0; i < MAX_VXD; i++) {
		if (VXD_BIST_bits[i]) {
			j += sprintf(buf + j, "%s=%d -- ERROR in memory\n",
						VXD_BIST_name[i], VXD_BIST_bits[i]);
		} else {
			j += sprintf(buf + j, "%s=%d\n", VXD_BIST_name[i], VXD_BIST_bits[i]);
		}
	}

	/*Checking MGA25_BIST*/
	if (a.MGA_present) {
		j += sprintf(buf + j, "\nMGA2.5_BIST:\n");
		for (i = 0; i < MAX_MGA; i++) {
			if (MGA_BIST_bits[i]) {
				j += sprintf(buf + j, "%s=%d -- ERROR in memory\n",
							MGA_BIST_name[i], MGA_BIST_bits[i]);
			} else {
				j += sprintf(buf + j, "%s=%d\n",
							MGA_BIST_name[i], MGA_BIST_bits[i]);
			}
		}
	}
	return sprintf(buf, "%s", buf);
}
#endif

static ssize_t show_node(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	return sprintf(buf, "NODE_%d\n", hwmon->node);
}

#ifdef CONFIG_E90S

#define CC0_MC_ECC(node) (NODE_PFREG_AREA_BASE(node) | (1 << 25) | (0 << 8))
#define CC1_MC_ECC(node) (CC0_MC_ECC(node) | (1 << 26))

__u64 pf_reg_read(int node, int nr)
{
	u64 base = CC0_MC_ECC(node);
	if (nr)
		base = CC1_MC_ECC(node);
	return __raw_readq((void *)base);
}

typedef union {
	struct {
		u32 McPllLock		: 1;
		u32 McPllReset		: 1;
		u32 McPllNbw		: 2;
		u32 McPllGated		: 1;
		u32 Reserved_2		: 2;
		u32 McPllNf		: 13;
		u32 Reserved_1		: 2;
		u32 McPllNr		: 6;
		u32 McPllNod		: 4;
};
	u32 word;
} mc_freq_sparc_t;

typedef union {
	struct {
		u64 unused		: 60;
		u32 ECC_DMODE		: 1;
		u32 ECC_CINT		: 1;
		u32 ECC_CORR		: 1;
		u32 ECC_DET		: 1;
};
	u64 word;
} pf_mc_ecc_r2000_t;

typedef union {
	struct {
		u32 unused		: 28;
		u32 ECC_DMODE		: 1;
		u32 ECC_CINT		: 1;
		u32 ECC_CORR		: 1;
		u32 ECC_DET		: 1;
};
	u32 word;
} pf_mc_ecc_r1000_t;

static ssize_t show_mem_info_sparc(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	pf_mc_ecc_r1000_t mc_ecc_r1000;
	pf_mc_ecc_r2000_t cc0_mc_ecc_r2000;
	pf_mc_ecc_r2000_t cc1_mc_ecc_r2000;
	int j = 0;
	int ecc_mode;
	int regval;
	int cecnt;
	int uecnt;
	switch (e90s_get_cpu_type()) {
	case E90S_CPU_R1000:
		mc_ecc_r1000.word = sic_read_node_nbsr_reg(hwmon->node, MC_ECC_R1000);
		sprintf(buf, "NODE-%d DMODE=0x%x CINT=0x%x CORR=0x%X DET=0x%x\n",
				hwmon->node, mc_ecc_r1000.ECC_DMODE, mc_ecc_r1000.ECC_CINT,
				mc_ecc_r1000.ECC_CORR, mc_ecc_r1000.ECC_DET);
		break;
	case E90S_CPU_R2000:
		cc0_mc_ecc_r2000.word = pf_reg_read(hwmon->node, 0);
		cc1_mc_ecc_r2000.word = pf_reg_read(hwmon->node, 1);
		j += sprintf(buf + j, "NODE-%d CC-0 DMODE=0x%x CINT=0x%x CORR=0x%X DET=0x%x\n",
				hwmon->node, cc0_mc_ecc_r2000.ECC_DMODE, cc0_mc_ecc_r2000.ECC_CINT,
				cc0_mc_ecc_r2000.ECC_CORR, cc0_mc_ecc_r2000.ECC_DET);
		j += sprintf(buf + j, "NODE-%d CC-1 DMODE=0x%x CINT=0x%x CORR=0x%X DET=0x%x\n",
				hwmon->node, cc1_mc_ecc_r2000.ECC_DMODE, cc1_mc_ecc_r2000.ECC_CINT,
				cc1_mc_ecc_r2000.ECC_CORR, cc1_mc_ecc_r2000.ECC_DET);
		break;
	case E90S_CPU_R2000P:
		nbsr_writel(MC_ECCCFG0, MC_DDR_PHY_REGISTER_ADDRESS, 0);
		ecc_mode = nbsr_readl(MC_REGISTER_DATA, 0) & ECC_MODE_MASK;
		nbsr_writel(MC_ECCSTAT, MC_DDR_PHY_REGISTER_ADDRESS, 0);
		regval = nbsr_readl(MC_REGISTER_DATA, 0);
		cecnt = (regval & ECC_STAT_CECNT_MASK) >> ECC_STAT_CECNT_SHIFT;
		uecnt = (regval & ECC_STAT_UECNT_MASK) >> ECC_STAT_UECNT_SHIFT;
		j += sprintf(buf + j, "NODE-%d ECC_MODE=0x%x CECNT=0x%x UECNT=0x%x\n",
						hwmon->node, ecc_mode, cecnt, uecnt);
		break;
	}
	return sprintf(buf, "%s", buf);
}


static int read_mem_rate_sparc(int node)
{
	int Nf;
	int Nod;
	int Nr;
	int Fmc;
	mc_freq_sparc_t mc_freq_reg;
	switch (e90s_get_cpu_type()) {
	case E90S_CPU_R1000:
		/* There is no register with pll parameters */
		Fmc = 250;
		break;
	case E90S_CPU_R2000:
		mc_freq_reg.word = sic_read_node_nbsr_reg(node, MC_FREQ_SPARC);
		Nf = mc_freq_reg.McPllNf + 1;
		Nod = mc_freq_reg.McPllNod + 1;
		Nr = mc_freq_reg.McPllNr + 1;
		Fmc = (100 * Nf) / (Nod * Nr);
		break;
	case E90S_CPU_R2000P:
		/* Soon counting from PMC will be added */
		break;
	}
	return Fmc;
}

static ssize_t show_mem_rate_sparc(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	int Fmc = read_mem_rate_sparc(hwmon->node);
	int j = 0;
	if (e90s_get_cpu_type() == E90S_CPU_R1000)
		j += sprintf(buf + j, "For R1000 frequency is just printed, not from register:\n");
	j += sprintf(buf + j, "MC_freq = %d MHz\n", Fmc);
	return sprintf(buf, "%s", buf);
}

static struct link_data read_link_info_sparc(int node)
{
	struct link_data a;
	int str_shift = 3;
	int ipcc_csr;
	int ipcc_str;
	int i;
	int wlcc_err_val;
	int iol_pls;
	for (i = 0; i < IPCC_LINKS; i++) {
		ipcc_csr = sic_read_node_nbsr_reg(node, ipcc_sparc_ctrls[i].offset);
		ipcc_str = sic_read_node_nbsr_reg(node, ipcc_sparc_ctrls[i+str_shift].offset);
		a.csr_reg[i] = ipcc_csr;
		a.str_reg[i] = ipcc_sparc_ctrls[i+str_shift].offset;
		a.active[i] = (ipcc_csr & ACTIVE_MASK) >> ACTIVE_SHIFT;
		a.width[i] = (ipcc_csr & WIDTH_MASK) >> WIDTH_SHIFT;
		a.state[i] = (ipcc_csr & STATE_MASK) >> STATE_SHIFT;
		a.str_val[i] = ipcc_str;
		a.cnt_err[i] = (ipcc_str & CNT_MASK);
		a.err_mode[i] = (ipcc_str & ERR_MODE_MASK) >> ERR_MODE_SHIFT;
	}
	a.wlcc_rate = (sic_read_node_nbsr_reg(node, IOL_PLM_CTLR) & WLCC_RATE_MASK) >>
					 WLCC_RATE_SHIFT;
	iol_pls = sic_read_node_nbsr_reg(node, IOL_PLS_CTLR);
	a.wlcc_active = (iol_pls & WLCC_ACTIVE_MASK) >> WLCC_ACTIVE_SHIFT;
	a.wlcc_state = (iol_pls & WLCC_STATE_MASK) >> WLCC_STATE_SHIFT;
	a.wlcc_width = (iol_pls & WLCC_WIDTH_MASK) >> WLCC_WIDTH_SHIFT;
	a.iol = (sic_read_node_nbsr_reg(node, RT_LCFG0) & IOL_MASK) >> IOL_SHIFT;
	wlcc_err_val = sic_read_node_nbsr_reg(node, IOL_DLL_STSR);
	a.wlcc_cnt = wlcc_err_val & ERR_CNT_MASK;
	a.wlcc_ov = (wlcc_err_val & ERR_OV_MASK) >> ERR_OV_SHIFT;
	a.wlcc_md = (wlcc_err_val & ERR_MD_MASK) >> ERR_MD_SHIFT;
	return a;
}

static int get_wlcc_information_sparc(struct link_data *data, char *buf,
					struct hwmon_data *hwmon, int j)
{
	struct link_data *b = data;

	j += sprintf(buf + j, "NODE%d-wlcc: ", hwmon->node);

	switch (b->wlcc_active) {
	case LINK_NOT_ACTIVE:
		j += sprintf(buf + j, "wlcc not active(%d), ",
				 b->wlcc_active);
		break;
	case LINK_ACTIVE:
		j += sprintf(buf + j, "wlcc is active(%d), ",
				 b->wlcc_active);
		break;
	}

	switch (b->wlcc_state) {
	case POWEROFF_STATE:
		j += sprintf(buf + j, "state(%d): Poweroff",
					b->wlcc_state);
		break;
	case DISABLE_STATE:
		j += sprintf(buf + j, "state(%d): Disable",
					 b->wlcc_state);
		break;
	case SLEEP_STATE:
		j += sprintf(buf + j, "state(%d): Sleep",
					 b->wlcc_state);
		break;
	case LINKUP_STATE:
		j += sprintf(buf + j, "state(%d): Work ",
					 b->wlcc_state);
		j += sprintf(buf + j, "width=0x%x", b->wlcc_width);
		if (b->wlcc_width != FULL_WIDTH)
			j += sprintf(buf + j, "WARNING (not full wlcc width)");
		break;
	}

	j += sprintf(buf + j, " err_mode=0x%x ", b->wlcc_md);

	if (b->wlcc_state == LINKUP_STATE) {
		switch (b->wlcc_md) {
		case 0:
			j += sprintf(buf + j, "- ERROR\n");
			break;
		case 1:
			j += sprintf(buf + j, "- WARNING ");
			break;
		case 2:
			j += sprintf(buf + j, "- OK ");
			break;
		}
	}

	if ((b->wlcc_state == LINKUP_STATE) && (b->wlcc_md != 0)) {
		j += sprintf(buf + j, "err_ov=0x%x ", b->wlcc_ov);
		if (b->wlcc_ov != 0)
			j += sprintf(buf + j, "- overflown (!!!)");

		j += sprintf(buf + j, "err_cnt=0x%x ", b->wlcc_cnt);

		if (b->wlcc_cnt == CNT_LIMIT)
			j += sprintf(buf + j, "- too much errors (!!!)\n");
		else if (b->wlcc_cnt != 0)
			j += sprintf(buf + j, "- found some errors (!!!)\n");
		else
			j += sprintf(buf + j, "- OK\n");

	} else {
		j += sprintf(buf + j, "\n");
	}

	return j;
}

static int get_ipcc_information_sparc(struct link_data *data, char *buf,
					struct hwmon_data *hwmon, int j)
{
	struct link_data *b = data;
	char letter;
	int i;

	for (i = 0; i < IPCC_LINKS; i++) {
		switch (ipcc_sparc_ctrls[i].offset) {
		case IPCC_CSR1_SPARC:
			letter = 'A';
			break;
		case IPCC_CSR2_SPARC:
			letter = 'B';
			break;
		case IPCC_CSR3_SPARC:
			letter = 'C';
			break;
		}
		j += sprintf(buf + j, "NODE%d-ipcc-%c-csr(0x%x) width=0x%x, ",
				 hwmon->node, letter, ipcc_sparc_ctrls[i].offset, b->width[i]);
		if (b->width[i] != FULL_WIDTH)
			j += sprintf(buf + j, "WARNING (not full width), ");

		switch (b->active[i]) {
		case LINK_NOT_ACTIVE:
			j += sprintf(buf + j, "link not active(%d), ", b->active[i]);
			break;
		case LINK_ACTIVE:
			j += sprintf(buf + j, "link is active(%d), ", b->active[i]);
			break;
		}

		switch (b->state[i]) {
		case POWEROFF_STATE:
			j += sprintf(buf + j, "state(%d): Poweroff\n", b->state[i]);
			break;
		case DISABLE_STATE:
			j += sprintf(buf + j, "state(%d): Disable\n", b->state[i]);
			break;
		case SLEEP_STATE:
			j += sprintf(buf + j, "state(%d): Sleep\n", b->state[i]);
			break;
		case LINKUP_STATE:
			j += sprintf(buf + j, "state(%d): Work\n", b->state[i]);
			break;
		case SERVICE_STATE:
			j += sprintf(buf + j, "state(%d): Service\n", b->state[i]);
			break;
		case REINIT_STATE:
			j += sprintf(buf + j, "state(%d): Reinit\n", b->state[i]);
			break;
		}


		if (b->state[i] == LINKUP_STATE) {
			switch (b->err_mode[i]) {
			case IPCC_STR_MODE_LERR:
				j += sprintf(buf + j,
					"NODE%d-ipcc-%c-str(0x%x) err_mode=%d - WARNING(0x%x)\n",
						hwmon->node, letter, b->str_reg[i],
						b->err_mode[i], b->str_val[i]);
				j += sprintf(buf + j,
					"amount of errors in cnt_err -  %d\n", b->cnt_err[i]);
				break;
			case IPCC_STR_MODE_RTRY:
				j += sprintf(buf + j,
					"NODE%d-ipcc-%c-str(0x%x) err_mode=%d - OK(0x%x)\n",
						hwmon->node, letter, b->str_reg[i],
						b->err_mode[i], b->str_val[i]);
				j += sprintf(buf + j,
					"amount of errors in cnt_err -  %d\n", b->cnt_err[i]);

				break;
			default:
				j += sprintf(buf + j,
					"NODE%d-ipcc-%c-str(0x%x) err_mode=%d - ERROR(0x%x)\n",
						hwmon->node, letter,  b->str_reg[i],
						b->err_mode[i], b->str_val[i]);
			}
		} else {
			j += sprintf(buf + j,
				"NODE%d-ipcc-%c-str(0x%x) err_mode=%d - OFF(0x%x - CSR)\n",
						hwmon->node, letter,  b->str_reg[i],
						b->err_mode[i], b->csr_reg[i]);
		}
	}

	return j;
}

static ssize_t show_link_info_sparc(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct link_data b = read_link_info_sparc(hwmon->node);
	int j = 0;

	/* WLCC INFORMATION */
	j = get_wlcc_information_sparc(&b, buf, hwmon, j);

	/*IPCC INFORMATION*/
	j = get_ipcc_information_sparc(&b, buf, hwmon, j);

	return sprintf(buf, "%s", buf);
}

#endif

#define MAX_NAME  18
static int num_attrs = 0;

struct hwmon_device_attribute {
	struct sensor_device_attribute s_attrs;
	char name[MAX_NAME];
};

static struct attribute_group hwmon_group = {
	.attrs = NULL,
};

static const struct attribute_group *hwmon_groups[] = {
	&hwmon_group,
	NULL,
};

static struct hwmon_device_attribute *hwmon_attrs;

static int create_info_device_attr(struct device *dev)
{
	int num_files;
#ifdef CONFIG_E2K
	int cpu_type = machine.native_id;
#endif
	int mult_link = ((sic_read_nbsr_reg(ST_P)) >> MULTILINK_SHIFT) & MULTILINK_MASK;

#ifdef CONFIG_E2K
	switch (cpu_type) {
	case MACHINE_ID_E16C:
		num_files = 6;
		break;
	case MACHINE_ID_E12C:
		num_files = 6;
		break;
	case MACHINE_ID_E2C3:
		num_files = 7;
		break;
	case MACHINE_ID_E8C:
		num_files = 4;
		break;
	case MACHINE_ID_E8C2:
		num_files = 4;
		break;
	}
#endif

#ifdef CONFIG_E90S
	switch (e90s_get_cpu_type()) {
	case E90S_CPU_R1000:
		num_files = 4;
		break;
	case E90S_CPU_R2000:
		num_files = 4;
		break;
	case E90S_CPU_R2000P:
		num_files = 2;
		break;
	}
#endif

	hwmon_attrs = devm_kzalloc(dev,
			(num_files)*sizeof(struct hwmon_device_attribute),
								GFP_KERNEL);
	if (!hwmon_attrs) {
		return -ENOMEM;
	}

	struct hwmon_device_attribute *pattr;

#ifdef CONFIG_E2K
	pattr = hwmon_attrs + num_attrs;
	snprintf(pattr->name, MAX_NAME, "link_info");
	pattr->s_attrs.dev_attr.attr.name = pattr->name;
	pattr->s_attrs.dev_attr.attr.mode = 0444;
	pattr->s_attrs.dev_attr.show = show_link_data;
	pattr->s_attrs.dev_attr.store = NULL;
	sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
	num_attrs++;

	pattr = hwmon_attrs + num_attrs;
	snprintf(pattr->name, MAX_NAME, "mem_info");
	pattr->s_attrs.dev_attr.attr.name = pattr->name;
	pattr->s_attrs.dev_attr.attr.mode = 0444;
	pattr->s_attrs.dev_attr.show = show_mem_data;
	pattr->s_attrs.dev_attr.store = NULL;
	sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
	num_attrs++;

	if (machine.native_id == MACHINE_ID_E2C3) {
		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "cpu_info");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_cpu_data;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;

		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "bist_info");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_bist_info;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;
	}

	if ((machine.native_id == MACHINE_ID_E8C) ||
			(machine.native_id == MACHINE_ID_E8C2)) {
		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "mem_rate");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_mem_rate_e8c;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;
	}

	if ((machine.native_id == MACHINE_ID_E16C) ||
		(machine.native_id == MACHINE_ID_E12C) ||
			 (machine.native_id == MACHINE_ID_E2C3)) {
		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "config_pins");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_pins;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;

		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "mem_rate_measure");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_mem_rate;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;

		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "mem_rate");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_mem_rate_saved;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;
	}
#endif

#ifdef CONFIG_E90S
	if (e90s_get_cpu_type() != E90S_CPU_R2000P) {
		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "mem_rate_sparc");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_mem_rate_sparc;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;

		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "link_info_sparc");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_link_info_sparc;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;
	}

	pattr = hwmon_attrs + num_attrs;
	snprintf(pattr->name, MAX_NAME, "mem_info_sparc");
	pattr->s_attrs.dev_attr.attr.name = pattr->name;
	pattr->s_attrs.dev_attr.attr.mode = 0444;
	pattr->s_attrs.dev_attr.show = show_mem_info_sparc;
	pattr->s_attrs.dev_attr.store = NULL;
	sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
	num_attrs++;
#endif
	pattr = hwmon_attrs + num_attrs;
	snprintf(pattr->name, MAX_NAME, "curr_node");
	pattr->s_attrs.dev_attr.attr.name = pattr->name;
	pattr->s_attrs.dev_attr.attr.mode = 0444;
	pattr->s_attrs.dev_attr.show = show_node;
	pattr->s_attrs.dev_attr.store = NULL;
	sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
	num_attrs++;

	return 0;
}

static struct attribute **attrs;
static int create_hwmon_group(struct device *dev)
{

	int i;
	attrs = devm_kzalloc(dev, (num_attrs + 1) * sizeof(struct attribute *),
							GFP_KERNEL);
	if (!attrs) {
		return -ENOMEM;
	}

	for (i = 0; i < num_attrs; i++) {
		*(attrs + i) = &((hwmon_attrs + i)->s_attrs.dev_attr.attr);
		hwmon_group.attrs = attrs;
	}

	return 0;
}

#define MAX_NODE 4

struct hwmon_data *p_hwmon[MAX_NODE];
static int online_num_node = 0;

static int __init hwmon_probe(void)
{
	int node;
#ifdef CONFIG_E2K
	int curr_node;
	int cpu_type = machine.native_id;
#endif
	struct hwmon_data *hwmon;
	struct device *dev = cpu_subsys.dev_root;
	struct platform_device *pdev;
	struct device *hwmon_dev;
	int ret;

#ifdef CONFIG_E2K
	if (cpu_type != MACHINE_ID_E8C && cpu_type != MACHINE_ID_E8C2 &&
			cpu_type != MACHINE_ID_E12C && cpu_type != MACHINE_ID_E16C &&
			cpu_type != MACHINE_ID_E2C3)
		return -ENODEV;
#endif

	ret = create_info_device_attr(dev);
	if (ret)
		return -ENOMEM;

	ret = create_hwmon_group(dev);
	if (ret)
		return -ENOMEM;

	for_each_online_node(node) {
		pdev = platform_device_register_data(dev, "hw_check", node, NULL, 0);
		if (IS_ERR(pdev)) {
			dev_err(dev, "failed to create hw_check platform device");
			return PTR_ERR(pdev);
		}

		hwmon = devm_kzalloc(&pdev->dev, sizeof(*hwmon), GFP_KERNEL);
		if (!hwmon) {
			platform_device_unregister(pdev);
			return -ENOMEM;
		}

		hwmon->pdev = pdev;
		hwmon->node = node;

		hwmon_dev = hwmon_device_register_with_groups(&pdev->dev,
								KBUILD_MODNAME,
								hwmon,
								hwmon_groups);
		if (IS_ERR(hwmon_dev)) {
			platform_device_unregister(pdev);
			return PTR_ERR(hwmon_dev);
		}

		hwmon->hdev = hwmon_dev;
		p_hwmon[node] = hwmon;

		online_num_node++;
	}

#ifdef CONFIG_E2K
	if ((cpu_type == MACHINE_ID_E2C3) || (cpu_type == MACHINE_ID_E12C) ||
						(cpu_type == MACHINE_ID_E16C)) {
		for (curr_node = 0; curr_node < online_num_node; curr_node++) {
			kthread[curr_node] = kthread_create(thread_function,
						&t[curr_node], "kthread");
			if (kthread[curr_node] != NULL) {
				wake_up_process(kthread[curr_node]);
			} else {
				return -1;
			}
		}
	}
#endif
	return 0;
}

static void __exit hwmon_remove(void)
{
	int node;

	for_each_online_node(node) {
		hwmon_device_unregister(p_hwmon[node]->hdev);
		platform_device_unregister(p_hwmon[node]->pdev);
	}
}

module_init(hwmon_probe);
module_exit(hwmon_remove);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("Engineer scripts driver");
