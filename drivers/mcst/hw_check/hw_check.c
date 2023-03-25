/*
 * HW_CHECK kernel module for e2k platforms
 * e8c, e8c2, e16c, e2c3, e12c
 *
 * Author: Maxim Erkhov <erhov_m@mcst.ru>
 * 2022 (c) MCST
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/node.h>
#include <linux/cpu.h>
#include <linux/mod_devicetable.h>
#include <linux/hwmon-sysfs.h>
#include <linux/hwmon.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <linux/thermal.h>
#include <linux/pci.h>
#include <linux/delay.h>

#define MEMSIZE 100
#define CHECKTIME 30
#define WORKTIME 900

#define IPCC_CSR1 0x604
#define IPCC_CSR2 0x644
#define IPCC_CSR3 0x684

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

#define PCI_VIRTUAL_BRIDGE_DEVICE_ID 0x8017
#define PCI_VIRTUAL_BRIDGE_VENDOR_ID 0x1fff

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

#define IPCC_STR1 0x60c
#define IPCC_STR2 0x64c
#define IPCC_STR3 0x68c

#define MC0_ECC 0x400
#define MC1_ECC 0x440
#define MC2_ECC 0x480
#define MC3_ECC 0x4C0

#define MC_CH 0x0400
#define MC_ECC 0x440

#define ACTIVE_MASK 0x80000000
#define WIDTH_MASK  0x0F000000
#define STATE_MASK  0x00070000
#define CNT_MASK    0x20000000
#define OVER_CNT_MASK 0xDFFFFFFF

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

#define PCS_PMC_REGS_base 0x1000
#define PMC_INFO 0x000
#define PMC_SYS_MON_0_REG 0x500
#define PMC_SYS_MON_1_REG 0x504
#define MASK 0x1
#define PMC_VERSION_MASK 0x00000F00
#define PMC_VERSION_SHIFT 8
#define PMC_MODEL_MASK   0x000000FF
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

#define IPCC_STR_FILTER_MASK  0xC0000000
#define IPCC_STR_FILTER_SHIFT  30

#define IPCC_STR_FILTER_LERR  0x1
#define IPCC_STR_FILTER_RTRY  0x2

#define ACTIVE_SHIFT 31
#define WIDTH_SHIFT 24
#define STATE_SHIFT 16

#define LINK_NOT_ACTIVE 0
#define LINK_ACTIVE 1

#define POWEROFF_STATE 0
#define DISABLE_STATE 1
#define SLEEP_STATE 2
#define LINKUP_STATE 3
#define SERVICE_STATE 4
#define REINIT_STATE 5
#define FULL_WIDTH 0xf

#define MEM_LINKS 8
#define IPCC_LINKS 3

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
	int str[IPCC_LINKS];
	int cnt_err[IPCC_LINKS];
	int multilink;
	int vp[IPCC_LINKS];
	int pn[IPCC_LINKS];
	int mlc;
	int st_p;
	int link_bitrate;
};

struct mem_data {
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
};

struct pins_data {
	int vp;
	int pn;
	int sys_mon_0;
	int sys_mon_1;
	int pmc_info;
};


struct pins_info {
	int shift;
	int mask;
	char *name;

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

struct link_data read_link_data(int node)
{
	struct link_data a, *ptr;

	ptr = &a;
	int prom;
	int i;
	int ipcc_csr[IPCC_LINKS];
	int ipcc_str[IPCC_LINKS];
	int inter_val;
	int curr_LCFG;
	int rt_lcfg_val;
	int str_shift = 3; /*This shift is used to read from str regs*/
	bool inter = true;

	ptr->multilink = ((sic_read_node_nbsr_reg(node, ST_P)) >>
				 MULTILINK_SHIFT)&MULTILINK_MASK;
	ptr->mlc = (sic_read_node_nbsr_reg(node, ST_P) >>
				 MLC_SHIFT)&MLC_MASK;
	ptr->st_p = sic_read_node_nbsr_reg(node, ST_P);

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
		ptr->vp[i] = rt_lcfg_val & RT_LCFG_VP_MASK;
		ptr->pn[i] = (rt_lcfg_val >>
				RT_LCFG_PN_SHIFT)&RT_LCFG_PN_MASK;
		ipcc_str[i] = sic_read_node_nbsr_reg(node,
					ipcc_ctrls[i+str_shift].offset);
		ipcc_csr[i] = sic_read_node_nbsr_reg(node,
						ipcc_ctrls[i].offset);
		ptr->active[i] = (ipcc_csr[i] & ACTIVE_MASK) >>
						ACTIVE_SHIFT;
		ptr->width[i] = (ipcc_csr[i] & WIDTH_MASK) >>
						WIDTH_SHIFT;
		ptr->state[i] = (ipcc_csr[i] & STATE_MASK) >>
						STATE_SHIFT;
		ptr->str[i] = (ipcc_str[i] & IPCC_STR_FILTER_MASK) >>
						IPCC_STR_FILTER_SHIFT;
		ptr->cnt_err[i] = (ipcc_str[i] & CNT_MASK);

		if (inter == true) {
			inter_val = a.str[i];
			inter = false;
		}

		if (inter_val != a.str[i]) {
			prom = sic_read_node_nbsr_reg(node,
					ipcc_ctrls[i+str_shift].offset);
			prom = prom || OVER_CNT_MASK;
			sic_write_node_nbsr_reg(node,
					ipcc_ctrls[i+str_shift].offset, prom);
			inter = true;
		}
	}

return a;

}

static ssize_t show_link_data(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct link_data b = read_link_data(hwmon->node);

	int i;
	int j;
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

		j += sprintf(buf + j, "NODE%d-ipcc-%c width 0x%x, ",
					hwmon->node, letter, b.width[i]);

		if (b.width[i] != FULL_WIDTH) {
			j += sprintf(buf + j,
					"WARNING (not full width), ");
		}

		switch (b.active[i]) {
		case LINK_NOT_ACTIVE:
			j += sprintf(buf + j, "link not active, ");
			break;
		case LINK_ACTIVE:
			j += sprintf(buf + j, "link active, ");
			break;
		}

		switch (b.state[i]) {
		case POWEROFF_STATE:
			j += sprintf(buf + j, "state: Poweroff");
			break;
		case DISABLE_STATE:
			j += sprintf(buf + j, "state: Disable");
			break;
		case SLEEP_STATE:
			j += sprintf(buf + j, "state: Sleep");
			break;
		case LINKUP_STATE:
			j += sprintf(buf + j, "state: Work");
			break;
		case SERVICE_STATE:
			j += sprintf(buf + j, "state: Service");
			break;
		case REINIT_STATE:
			j += sprintf(buf + j, "state: Reinit");
			break;

		}

		if (b.vp[i] == 1) {
			j += sprintf(buf + j,
			", connected with NODE_%d\n", b.pn[i]);
		}

		else {
			j += sprintf(buf + j,
			", without connection\n");
		}

		if (machine.native_id != MACHINE_ID_E16C) {
			if ((b.multilink != 0) || (b.mlc != 0)) {
				j += sprintf(buf + j,
				"ERROR!!! Multilink is not supported for this ");
				j += sprintf(buf + j,
				"CPU, but mlp=0x%x and mlc=0x%x  (ST_P=0x%x)\n",
				b.multilink, b.mlc, b.st_p);
			}
		}

		else if ((b.multilink == 0) && (b.mlc == 1)) {
			j += sprintf(buf + j,
			"ERROR!!! Multilink is not connected on motherboard");
			j += sprintf(buf + j,
			", but enabled by software (ST_P=0x%x)\n", b.st_p);
		}

		else if ((b.multilink == 1) && (b.mlc == 0)) {
			j += sprintf(buf + j,
			"(multilink is disabled by software)\n");
		}

		else if ((b.multilink == 1) && (b.mlc == 1)) {
			j += sprintf(buf + j,
			"(multilink is enabled)\n");
		}

		switch (b.str[i]) {
		case IPCC_STR_FILTER_LERR:
			j += sprintf(buf + j, "ipcc-str - WARNING\n");
			break;
		case IPCC_STR_FILTER_RTRY:
			j += sprintf(buf + j, "ipcc-str -  OK\n");
			break;
		default:
			j += sprintf(buf + j, "ipcc-str - ERROR\n");
		}

		j += sprintf(buf + j,
		"amount of errors in cnt_err -  %d\n", b.cnt_err[i]);
	}

	return sprintf(buf, "%s", buf);
}

struct mem_data read_mem(int node)
{
	struct mem_data a, *ptr;

	ptr = &a;
	int val;
	int num_link[MEM_LINKS] = {0, 1, 2, 3, 4, 5, 6, 7};
	int i;
	int num_links;
	int cpu_type = machine.native_id;

	switch (cpu_type) {
	case MACHINE_ID_E16C:
		num_links = 8;
		break;
	case MACHINE_ID_E12C:
		num_links = 8;
		break;
	case MACHINE_ID_E2C3:
		num_links = 8;
		break;
	case MACHINE_ID_E8C2:
		num_links = 4;
		break;
	case MACHINE_ID_E8C:
		num_links = 4;
		break;
	}

/*Reading information from MC in case of e12c, e16c, e2c3*/
	if (((machine.native_id == MACHINE_ID_E16C) ||
			 (machine.native_id == MACHINE_ID_E12C)) ||
				(machine.native_id == MACHINE_ID_E2C3)) {
		for (i = 0; i < num_links; i++) {
			sic_write_node_nbsr_reg(node,
					mc_ctrls[4].offset, num_link[i]);
			val = sic_read_node_nbsr_reg(node,
					mc_ctrls[5].offset);
			ptr->mem_mode[i] = val & MC_ENABLE_MASK;
			ptr->mem_secnt[i] = (val >> MC_SECNT_SHIFT)
					& MC_SECNT_MASK;
			ptr->mem_uecnt[i] = (val >> MC_UECNT_SHIFT)
					& MC_UECNT_MASK;
			ptr->mem_dmode[i] = (val >> MC_DMODE_SHIFT)
					& MC_DMODE_MASK;
			ptr->mem_reg_val[i] = val;
			ptr->mem_ctl_val[i] = sic_read_node_nbsr_reg(node,
					MC_CTL);
			ptr->mem_ctl_mcen[i] = sic_read_node_nbsr_reg(node,
					MC_CTL)&MC_CTL_MCEN_MASK;
			ptr->mem_status_val[i] = sic_read_node_nbsr_reg(node,
					MC_STATUS);
			ptr->mem_rst_done[i] = (sic_read_node_nbsr_reg(node,
					MC_STATUS)>>MC_ST_RST_DONE_SHIFT)
					& MC_ST_RST_DONE_MASK;
		}
	}
/*Reading information from MC in case of e8c, e8c2*/
	else if ((machine.native_id == MACHINE_ID_E8C) ||
			 (machine.native_id == MACHINE_ID_E8C2)) {
		for (i = 0; i < num_links; i++) {
			val = sic_read_node_nbsr_reg(node, mc_ctrls[i].offset);
			ptr->mem_mode[i] = val & MC_ENABLE_MASK;
			ptr->mem_secnt[i] = (val >> MC_SECNT_SHIFT)
							& MC_SECNT_MASK;
			ptr->mem_uecnt[i] = (val >> MC_UECNT_SHIFT)
							& MC_UECNT_MASK;
			ptr->mem_dmode[i] = (val >> MC_DMODE_SHIFT)
							& MC_DMODE_MASK;
			ptr->mem_reg_val[i] = val;
			ptr->mem_ctl_val[i] = sic_read_node_nbsr_reg(node,
							MC_CTL);
			ptr->mem_ctl_mcen[i] = sic_read_node_nbsr_reg(node,
						MC_CTL)&MC_CTL_MCEN_MASK;
			ptr->mem_status_val[i] = sic_read_node_nbsr_reg(node,
						MC_STATUS);
			ptr->mem_rst_done[i] = (sic_read_node_nbsr_reg(node,
				MC_STATUS) >> MC_ST_RST_DONE_SHIFT)
				& MC_ST_RST_DONE_MASK;
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
	int num_links;
	int cpu_type = machine.native_id;

	switch (cpu_type) {
	case MACHINE_ID_E16C:
		num_links = 8;
		break;
	case MACHINE_ID_E12C:
		num_links = 8;
		break;
	case MACHINE_ID_E2C3:
		num_links = 8;
		break;
	case MACHINE_ID_E8C2:
		num_links = 4;
		break;
	case MACHINE_ID_E8C:
		num_links = 4;
		break;
	}

	for (i = 0; i < num_links; i++) {
		j += sprintf(buf + j,
"NODE%d_MC%d_ECC: mem_mode=%d, secnt=0x%x, uecnt=0x%x, dmode=0x%x\n",
			hwmon->node, i, b.mem_mode[i], b.mem_secnt[i],
			b.mem_uecnt[i], b.mem_dmode[i]);

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

	if (b.mem_rst_done[i] == 0) {
		j += sprintf(buf + j,
			"Warning!!! status rst_done = 0x%x (MC_STATUS = 0x%x)\n",
			b.mem_rst_done[i], b.mem_status_val[i]);
	}
	}
	return sprintf(buf, "%s", buf);

}



struct mem_data read_mem_rate(int node)
{
	struct mem_data a, *ptr;

	ptr = &a;
	int i;
	int num_link[MEM_LINKS] = {0, 1, 2, 3, 4, 5, 6, 7};
	int mc_freq;
	int mc_ddr_rate;
	int mc_mon_ctr0;
	int mc_mon_ctr_ext;
	long long mc_mnt0;

	sic_write_node_nbsr_reg(node, MC_CH, 0xF);
	sic_write_node_nbsr_reg(node, MC_MON_CTL, 0xFFFF000F);
	sic_write_node_nbsr_reg(node, MC_MON_CTL, 0XFFFF0000);
	mdelay(MC_MON_DELAY_MS);
	sic_write_node_nbsr_reg(node, MC_CH, 0xF);
	sic_write_node_nbsr_reg(node, MC_MON_CTL, 0x0000000C);
	sic_write_node_nbsr_reg(node, MC_CH, 0X0);

	for (i = 0; i < MEM_LINKS; i++) {
		sic_write_node_nbsr_reg(node, MC_CH, num_link[i]);
		mc_mon_ctr0 = sic_read_node_nbsr_reg(node,
		MC_MON_CTR0);
		mc_mon_ctr_ext = sic_read_node_nbsr_reg(node,
		MC_MON_CTRext);

		mc_mnt0 = (mc_mon_ctr_ext & MC_MNT0_MASK);
		mc_mnt0 = (mc_mnt0<<MC_MNT0_SHIFT) + mc_mon_ctr0;

		mc_freq = mc_mnt0/10/1000000;
		mc_ddr_rate = mc_freq * 2 * 2;
		ptr->mem_freq[i] = mc_freq;
		ptr->mem_ddr_rate[i] = mc_ddr_rate;
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
	int i;

	for (i = 0; i < MEM_LINKS; i++) {
		j += sprintf(buf + j,
"NODE_%d: MC_%d: likely DDR4-%d (MC_freq likely %d MHz)\n",
		hwmon->node, i, b.mem_ddr_rate[i], b.mem_freq[i]);
	}

	return sprintf(buf, "%s", buf);
}


static struct mem_data mem;
uint8_t mem_flag;
static ssize_t show_mem_rate_tmp(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);

	if (!mem_flag) {
		mem = read_mem_rate(hwmon->node);
		mem_flag++;
	}
	int j = 0;
	int i;

	for (i = 0; i < MEM_LINKS; i++) {
		j += sprintf(buf + j,
"NODE_%d: MC_%d: likely DDR4-%d (MC_freq likely %d MHz)\n",
		hwmon->node, i, mem.mem_ddr_rate[i], mem.mem_freq[i]);

	}

	return sprintf(buf, "%s", buf);
}

u32 read_reg(void)
{
	u32 value;
	struct pci_dev *dev;

	dev = pci_get_device(PCI_VIRTUAL_BRIDGE_VENDOR_ID,
				PCI_VIRTUAL_BRIDGE_DEVICE_ID, NULL);
	pci_read_config_dword(dev, 0x70, &value);
	value = (value >> 16) & 0xffff;
	return value;

}

struct link_data read_bitrate(int node, int idx)
{
	struct link_data a, *ptr;

	ptr = &a;
	struct pci_dev *dev;

	int lanes = 1;
	int i;
	u32 mplla_multiplier_and_clk_mplla;
	u32 ref_clk_div2_en;
	u32 rx_rate;
	u32 mplla_val;
	u32 mplla_mult_val;
	u32 mplla_div2_val;
	u32 clk_div2_en_val;
	u32 rx_rate_val;

	int b;
	int bitrate;
	int bitrate_mean = 0;
	int lnum = 0;

	/*Depening on bitrate link*/
	switch (idx) {
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

	dev = pci_get_device(PCI_VIRTUAL_BRIDGE_VENDOR_ID,
				PCI_VIRTUAL_BRIDGE_DEVICE_ID, NULL);

	for (i = 0; i < lanes; i++) {
		lnum++;

		mplla_multiplier_and_clk_mplla = ((0x80 << 24)|
			(ipcc_rate_ctrls[b+i].offset << 16)|
				 SUP_DIG_MPLLA_ASIC_IN_0);

		pci_write_config_dword(dev, 0x6c,
		mplla_multiplier_and_clk_mplla);
		mplla_val = read_reg();

		mplla_mult_val = (mplla_val>>5)&0xff;
		mplla_div2_val = (mplla_val>>1)&1;

		ref_clk_div2_en = ((0x80 << 24)|
			(ipcc_rate_ctrls[b+i].offset << 16)|
				SUP_DIG_ASIC_IN);
		pci_write_config_dword(dev, 0x6c, ref_clk_div2_en);
		clk_div2_en_val = read_reg();
		clk_div2_en_val = (clk_div2_en_val>>2)&1;

		rx_rate = ((0x80 << 24) |
			(ipcc_rate_ctrls[b+i].offset << 16) |
				LANEN_DIG_ASIC_RX_ASIC_IN_0);

		pci_write_config_dword(dev, 0x6c, rx_rate);
		rx_rate_val = read_reg();
		rx_rate_val = (rx_rate_val>>7)&0x3;

		bitrate = 2 * 100 * (mplla_mult_val & 0x7f);

		if (((mplla_mult_val >> 7)&1) == 1) {
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
	ptr->link_bitrate = bitrate_mean;
	return a;

}

static ssize_t show_bitrate(struct device *dev,
			 struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	int idx = to_sensor_dev_attr(attr)->index;
	struct link_data b = read_bitrate(hwmon->node, idx);

	int j = 0;
	char letter;

	switch (ipcc_ctrls[idx].offset) {
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

	j = sprintf(buf + j,
	"CPU %d Link %c, bitrate - %d Mbit/s\n", hwmon->node,
	letter, b.link_bitrate);

	return sprintf(buf, "%s", buf);
}


struct pins_data read_pins(int node)
{
	struct pins_data a, *ptr;

	ptr = &a;
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
	ptr->vp = rt_lcfg_val & RT_LCFG_VP_MASK;
	ptr->pn = (rt_lcfg_val >> RT_LCFG_PN_SHIFT)&RT_LCFG_PN_MASK;
	ptr->sys_mon_0 = sic_read_node_nbsr_reg(node, sys_mon_0_reg);
	ptr->sys_mon_1 = sic_read_node_nbsr_reg(node, sys_mon_1_reg);
	ptr->pmc_info = pmc_inform;

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

	int id_model = b.pmc_info & PMC_MODEL_MASK;
	int id_version = (b.pmc_info & PMC_VERSION_MASK) >>
	PMC_VERSION_SHIFT;
	int j;

	j = sprintf(buf, "Identificator PMC: 0x%x\n", b.pmc_info);
	j += sprintf(buf + j,
		" - cpu model: %s (0x%x)\n", machine_model, id_model);
	j += sprintf(buf + j,
		" - cpu version: %x\n", id_version);
	j += sprintf(buf + j,
		"NODE_%d: Register PMC_SYS_MON_0=0x%x\n",
				hwmon->node, b.sys_mon_0);

/*Here depending on cpu type, I'm printing config of pins*/
	for (i = 0; i < 8; i++) {
		pin = (b.sys_mon_0 >> pins_ctrls[i].shift)&
			pins_ctrls[i].mask;
		j += sprintf(buf + j, " - %s=0x%x",
		pins_ctrls[i].name, pin);
		if ((i == 0 || i == 1 || i == 2 || i == 4) &&
						 (pin == 1)) {
			j += sprintf(buf + j, " (warning!!!)");
		}
		j += sprintf(buf + j, "\n");
	}

	if (cpu_type == MACHINE_ID_E12C) {
		for (i = 8; i < 10; i++) {
			pin = (b.sys_mon_0 >> pins_ctrls[i].shift)&
				pins_ctrls[i].mask;
			j += sprintf(buf + j, " - %s=0x%x",
			pins_ctrls[i].name, pin);
		}
	}

	if (cpu_type == MACHINE_ID_E16C) {
		for (i = 9; i < 13; i++) {
			pin = (b.sys_mon_0 >> pins_ctrls[i].shift)&
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
		pin = (b.sys_mon_0 >> pins_ctrls[i].shift)&
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
		pin = (b.sys_mon_1 >>
			pins_ctrls[i].shift)&pins_ctrls[i].mask;
		j += sprintf(buf + j, " - %s=0x%x",
			pins_ctrls[i].name, pin);

		if ((i != 20 && i != 21 && i != 22) &&
					 (pin == 1)) {
			j += sprintf(buf + j, " (warning!!!)");
		}
		j += sprintf(buf + j, "\n");
	}

	if (cpu_type == MACHINE_ID_E12C) {
		for (i = 23; i < 28; i++) {
			pin = (b.sys_mon_1 >>
				pins_ctrls[i].shift)&pins_ctrls[i].mask;
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
			pin = (b.sys_mon_1 >>
				pins_ctrls[i].shift)&pins_ctrls[i].mask;
			j += sprintf(buf + j, " - %s=0x%x",
				pins_ctrls[i].name, pin);

			if ((i != 38 && i != 39 &&
				i != 40 && i != 41) && (pin == 1)) {
				j += sprintf(buf + j, " (warning!!!)");
			}
			j += sprintf(buf + j, "\n");
		}
	}

	if (cpu_type == MACHINE_ID_E2C3) {
		for (i = 41; i < 44; i++) {
			pin = (b.sys_mon_1 >>
				pins_ctrls[i].shift)&pins_ctrls[i].mask;
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


static ssize_t show_node(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);

	return sprintf(buf, "NODE_%d\n", hwmon->node);
}

#define MAX_NAME    16
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
	int bitrate_files = 3;
	int num_files;
	int cpu_type = machine.native_id;
	int mult_link = ((sic_read_nbsr_reg(ST_P)) >>
				MULTILINK_SHIFT)&MULTILINK_MASK;

	switch (cpu_type) {
	case MACHINE_ID_E16C:
		num_files = 9;
		break;
	case MACHINE_ID_E12C:
		num_files = 6;
		break;
	case MACHINE_ID_E2C3:
		num_files = 6;
		break;
	case MACHINE_ID_E8C:
		num_files = 3;
		break;
	case MACHINE_ID_E8C2:
		num_files = 3;
		break;
	}

	int i = 0;
	hwmon_attrs = devm_kzalloc(dev,
	(num_files)*sizeof(struct hwmon_device_attribute),
	GFP_KERNEL);

	if (!hwmon_attrs) {
		return -ENOMEM;
	}

	struct hwmon_device_attribute *pattr;

	if (machine.native_id == MACHINE_ID_E16C) {
		for (i = 0; i < bitrate_files; i++) {
			pattr = hwmon_attrs + num_attrs;
			snprintf(pattr->name, MAX_NAME, "link_bitrate%d",
			i+1);
			pattr->s_attrs.dev_attr.attr.name = pattr->name;
			pattr->s_attrs.dev_attr.attr.mode = 0444;
			pattr->s_attrs.dev_attr.show = show_bitrate;
			pattr->s_attrs.dev_attr.store = NULL;
			pattr->s_attrs.index = i;
			sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
			num_attrs++;
		}
	}

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

	pattr = hwmon_attrs + num_attrs;
	snprintf(pattr->name, MAX_NAME, "curr_node");
	pattr->s_attrs.dev_attr.attr.name = pattr->name;
	pattr->s_attrs.dev_attr.attr.mode = 0444;
	pattr->s_attrs.dev_attr.show = show_node;
	pattr->s_attrs.dev_attr.store = NULL;
	sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
	num_attrs++;

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
		snprintf(pattr->name, MAX_NAME, "mem_rate");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_mem_rate;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;

		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "mem_rate_tmp");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_mem_rate_tmp;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;
	}

	return 0;
}

static struct attribute **attrs;

static int create_hwmon_group(struct device *dev)
{

	int i;
	attrs = devm_kzalloc(dev, num_attrs * sizeof(struct attribute *),
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

static int __init hwmon_probe(void)
{
	int node;
	struct hwmon_data *hwmon;
	struct device *dev = cpu_subsys.dev_root;
	struct platform_device *pdev;
	struct device *hwmon_dev;
	int ret;

	ret = create_info_device_attr(dev);

	if (ret) {
		return -ENOMEM;
	}

	ret = create_hwmon_group(dev);

	if (ret) {
		return -ENOMEM;
	}

	for_each_online_node(node) {
		pdev = platform_device_register_data(dev, "lkm", node,
		NULL, 0);

		if (IS_ERR(pdev)) {
			dev_err(dev, "failed to create lkm platform device");
			return PTR_ERR(pdev);
		}
		hwmon = devm_kzalloc(dev, sizeof(*hwmon), GFP_KERNEL);

		if (!hwmon) {
			platform_device_unregister(pdev);
			return -ENOMEM;
		}

		hwmon->pdev = pdev;
		hwmon->node = node;


		hwmon_dev = devm_hwmon_device_register_with_groups(&pdev->dev,
								KBUILD_MODNAME,
								hwmon,
								hwmon_groups);

		if (IS_ERR(hwmon_dev)) {
			platform_device_unregister(pdev);
			return PTR_ERR(hwmon_dev);
		}

		hwmon->hdev = hwmon_dev;
		p_hwmon[node] = hwmon;

	}
	return 0;

}

static void __exit hwmon_remove(void)
{
	int node;

	for_each_online_node(node) {
		sysfs_remove_group(&p_hwmon[node]->hdev->kobj, &hwmon_group);
		hwmon_device_unregister(p_hwmon[node]->hdev);
		platform_device_unregister(p_hwmon[node]->pdev);

	}
}

module_init(hwmon_probe);
module_exit(hwmon_remove);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maxim Erkhov erhov_m@mcst.ru");
MODULE_DESCRIPTION("Engineer scripts driver");
