/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef PCSM_H_
#define PCSM_H_

/*
 * V6, V7 Power Control System (PCS) registers
 * PMC_TERM_* Temperature sensors
 * PMC base = 0x1000 + PMC_TERM_CONV_OFFSET(0x8)
 * */
#define REG_OFFSET_PMC_TERM_CONV	0x0
#define REG_OFFSET_PMC_TERM_CTRL	0x4
#define REG_OFFSET_PMC_TERM_TS0		0x8
#define REG_OFFSET_PMC_TERM_TS1		0xc
#define REG_OFFSET_PMC_TERM_TS2		0x10
#define REG_OFFSET_PMC_TERM_TS3		0x14
#define REG_OFFSET_PMC_TERM_TS4		0x18
#define REG_OFFSET_PMC_TERM_TS5		0x1c
#define REG_OFFSET_PMC_TERM_TS6		0x20
#define REG_OFFSET_PMC_TERM_TS7		0x24
/*
 * V6, V7 PWMs registers
 * */
#define FRST_INST                       0x0 /* inst in pwmc - 0x1 */
#define SCND_INST                       0x1 /* inst in pwmc - 0x2 */

#define INST_COUNT                      0x2

/* common control and pwm */
#define PCSM_RO_ID_LO			0x00
#define PCSM_RO_ID_HI			0x01
#define PCSM_RW_CONTROL			0x02
#define PCSM_RW_PWM_FIXED		0x03
#define PCSM_RW_PWM_CURRENT		0x04
#define PCSM_RW_TIME_INTERVAL		0x05

/* lut sections */
#define PCSM_RW_LUT0_TEMP		0x06
#define PCSM_RW_LUT0_PWM		0x07
#define PCSM_RW_LUT0_HYST		0x08
#define PCSM_RW_LUT1_TEMP		0x09
#define PCSM_RW_LUT1_PWM		0x0a
#define PCSM_RW_LUT1_HYST		0x0b
#define PCSM_RW_LUT2_TEMP		0x0c
#define PCSM_RW_LUT2_PWM		0x0d
#define PCSM_RW_LUT2_HYST		0x0e
#define PCSM_RW_LUT3_TEMP		0x0f
#define PCSM_RW_LUT3_PWM		0x10
#define PCSM_RW_LUT3_HYST		0x11
#define PCSM_RW_LUT4_TEMP		0x12
#define PCSM_RW_LUT4_PWM		0x13
#define PCSM_RW_LUT4_HYST		0x14
#define PCSM_RW_LUT5_TEMP		0x15
#define PCSM_RW_LUT5_PWM		0x16
#define PCSM_RW_LUT5_HYST		0x17
#define PCSM_RW_LUT6_TEMP		0x18
#define PCSM_RW_LUT6_PWM		0x19
#define PCSM_RW_LUT6_HYST		0x1a
#define PCSM_RW_LUT7_TEMP		0x1b
#define PCSM_RW_LUT7_PWM		0x1c
#define PCSM_RW_LUT7_HYST		0x1d
#define PCSM_RW_LUT8_TEMP		0x1e
#define PCSM_RW_LUT8_PWM		0x1f
#define PCSM_RW_LUT8_HYST		0x20
#define PCSM_RW_LUT9_TEMP		0x21
#define PCSM_RW_LUT9_PWM		0x22
#define PCSM_RW_LUT9_HYST		0x23

/* tachometr and setup regs */
#define PCSM_RO_TACH_LO			0x24
#define PCSM_RO_TACH_HI			0x25
#define PCSM_MX_TACH_CTRL		0x26
#define PCSM_RW_ALERT_CTRL		0x27
#define PCSM_RW_PWM_MIN			0x28
#define PCSM_RW_PWM_MAX			0x29
#define PCSM_RW_TACH_MIN_LO		0x2a
#define PCSM_RW_TACH_MIN_HI		0x2b
#define PCSM_RW_TACH_MAX_LO		0x2c
#define PCSM_RW_TACH_MAX_HI		0x2d
#define PCSM_RW_ALERT_STATUS		0x2e

#define PCSM_PWM_REGS_COUNT		0x2f
/* max value for pwm and temp registers */
#define PCSM_THERM_MAX			0xFF
#define PCSM_PWM_MAX			0x80

#define PCSM_LUT_COUNT			10

#define MANUFACTURER_ID_LO		0xC3
#define MANUFACTURER_ID_HI		0xE2



/*
 * V6, V7 Power System Events
 * */
typedef union {
	struct {
		u32 mc03_dimm_event	: 1;
		u32 mc47_dimm_event	: 1;
		u32 mc03_pwr_alert	: 1;
		u32 mc47_pwr_alert	: 1;
		u32 cpu_pwr_alert	: 1;
		u32 machine_pwr_alert	: 1;
		u32 machine_gen_alert	: 1;
		u32 pcs_fan0_alert	: 1;
		u32 pcs_fan1_alert	: 1;
		u32 term_nomax		: 1;
		u32 term_fault		: 1;
		u32 term_diag		: 1;
		u32 cpu_hot		: 1;
		u32 ts_all_int		: 1;
		u32 ts_alarma		: 1;
		u32 ts_alarmb		: 1;
		u32 vm_all_int		: 1;
		u32 vm_alarma		: 1;
		u32 vm_alarmb		: 1;
		u32 pd_all_int		: 1;
		u32 pd_alarma		: 1;
		u32 pd_alarmb		: 1;
		u32 mc03_throttle	: 1;
		u32 mc47_throttle	: 1;
		u32 cpu_forcepr		: 1;
		u32 rsv			: 7;
	} v6;
	struct {
		u32 mc0_dimm_event	  : 1;
		u32 mc1_dimm_event	  : 1;
		u32 machine_gen_alert	  : 1;
		u32 nmi_cpu_sw		  : 1;
		u32 smbus_alert_0	  : 1;
		u32 smbus_alert_1	  : 1;
		u32 board_event		  : 1;
		u32 cpu_hot		  : 1;
		u32 mc0_throttle	  : 1;
		u32 mc1_throttle	  : 1;
		u32 cpu_forcepr		  : 1;
		u32 term_nomax		  : 1;
		u32 term_fault		  : 1;
		u32 term_diag		  : 1;
		u32 volt_no_minmax	  : 1;
		u32 volt_fault		  : 1;
		u32 volt_diag		  : 1;
		u32 uC_int		  : 1;
		u32 ts_alarma		  : 1;
		u32 ts_alarmb		  : 1;
		u32 vm_alarma		  : 1;
		u32 vm_alarmb		  : 1;
		u32 pd_alarma		  : 1;
		u32 pd_alarmb		  : 1;
		u32 pvt_all_int		  : 1;
		u32 rsv0		  : 1;
		u32 rsv1		  : 1;
		u32 core_cc_lo		  : 1; /* CORE0-CORE7 */
		u32 rsv2		  : 1;
		u32 core_cu_lo		  : 1; /* CORE0-CORE7 */
		u32 rsv3		  : 1;
		u32 rsv4		  : 1;
	} e8v7;
	u32 reg;
} pcs_sys_events_t;

#define EVENTS_MASK_V6		0x01c6dfff
#define EVENTS_MASK_E8V7	0x28ffffff

#define PCS_EVENTS_MAX			31
#define PCS_EVENTS_COUNT_V6		25

typedef struct event_info {
	unsigned long count;
	time64_t time;
} event_info_t;

#define PCS_ADJUST_MIN_PERIOD 1000 /* ms */
#define PCS_ADJUST_MAX_PERIOD 3600000 /* ms */
static int PCS_ADJUST_PERIOD = 300000; /* ms */
static int PCS_UPDATE_PERIOD = 200; /* ms */

#define PMC_TEPM_MIN	(-256000)
#define PMC_TERM_TS_MAX	8
#undef PMC_FAN_CFG
#define PMC_FAN_CFG 0x0
/*
 * V7
 * VOLT_CONV = PMC_BASE_ADDR(0x1000) + PMC_VOLT_CONV(0x0d0)
 * VOLT_MON0 = PMC_BASE_ADDR(0x1000) + PMC_VOLT_MON0(0x0d4)
 * VOLT_VM0_CTRL = PMC_BASE_ADDR(0x1000) + PMC_VOLT_VM0_CTRL(0x0dc)
 * VM = PMC_BASE_ADDR(0x1000) + PCS_PVT_REGS_VM_BASE(0x100)
 * FAN = PMC_BASE_ADDR(0x1000) + PMC_FAN_CFG(0x950)
 * SYS_EVENTS = PMC_BASE_ADDR(0x1000) + PMC_SYS_EVENTS_POLLING(0x910)
 */
#define PMC_REGS_VM_BASE	0x100
#define PMC_VOLT_VMN_CH(n, i) ((0x020 * (n)) + (0x004 * ((i) >> 1)))
#define PMC_VOLT_CONV			0x0
#define PMC_VOLT_MON0_CTRL		0x4
#define PMC_VOLT_MON1_CTRL		0x8
#define PMC_VOLT_VM0_CTRL		0xc
#define PMC_VOLT_VM1_CTRL		0x10
#define PMC_VOLT_VM2_CTRL		0x14
#define PMC_VOLT_VM3_CTRL		0x18
#define PMC_VOLT_VM4_CTRL		0x1c
#define PMC_VOLT_VM5_CTRL		0x20
#define PMC_VOLT_VM6_CTRL		0x24
#define PMC_VOLT_VM7_CTRL		0x28
#define PMC_VOLT_VM0_CH0		0x30


#define PMC_SYS_EVENTS_POLLING_0_V7	0x0
#define PMC_SYS_EVENTS_POLLING_1_V7	0x4
#define PMC_SYS_EVENTS_MASK_0_V7	0x8
#define PMC_SYS_EVENTS_MASK_1_V7	0xc
#define PMC_SYS_EVENTS_INT_0_V7		0x10
#define PMC_SYS_EVENTS_INT_1_V7		0x14
#define PMC_SYS_EVENTS_UC_ALL0_MASK_V7	0x18
#define PMC_SYS_EVENTS_UC_ALL0_INT_V7	0x1c
#define PMC_SYS_EVENTS_HW_V7		0x20
#define PMC_SYS_EVENTS_CFG_V7		0x24
/*
 * V6
 * VM = PVT_BASE_ADDR(0x2000) + PCS_PVT_REGS_VM_BASE(0x184) + PCS_VM0_DATA_OFFSET(0x34)
 * FAN = PMC_BASE_ADDR(0x1000) + PMC_FAN_CFG(0x540)
 * SYS_EVENTS = PMC_BASE_ADDR(0x1000) + PMC_SYS_EVENTS_POLLING(0x510)
 */
#define PCS_PVT_REGS_VM_BASE    0x184
#define PCS_VM0_DATA_OFFSET     0x034
#define PCS_VM_N_CH_DATA(n, ch)	((n*16 + ch)*4)

#define PMC_SYS_EVENTS_POLLING_V6	0x0
#define PMC_SYS_EVENTS_MASK_V6		0x4
#define PMC_SYS_EVENTS_INT_V6		0x8
#define PMC_SYS_EVENTS_HW_V6		0xc
#define PMC_SYS_EVENTS_CFG_V6		0x10

#define NO_EXIST    -1
#define VCORE       0
#define VDDR        1
#define VEXT        2

#define VM_MAX_CHANNELS 16
#define VM_MAX_SENSORS  8

#define ACCURACY 10

struct ts {
	char *name;
	unsigned int addr;
};

struct cpu_sensors {
	struct ts ts_map[PMC_TERM_TS_MAX];
	s8 vm_table_type[VM_MAX_CHANNELS][VM_MAX_SENSORS];
};

static const char * const pmc_sys_events_v6[] = {
	"mc03_dimm_event",
	"mc47_dimm_event",
	"mc03_pwr_alert",
	"mc47_pwr_alert",
	"cpu_pwr_alert",
	"machine_pwr_alert",
	"machine_gen_alert",
	"pcs_fan0_alert",
	"pcs_fan1_alert",
	"term_nomax",
	"term_fault",
	"term_diag",
	"cpu_hot",
	"ts_all_int",
	"ts_alarma",
	"ts_alarmb",
	"vm_all_int",
	"vm_alarma",
	"vm_alarmb",
	"pd_all_int",
	"pd_alarma",
	"pd_alarmb",
	"mc03_throttle",
	"mc47_throttle",
	"cpu_forcepr"
};

static const char * const pmc_sys_events_e8v7[] = {
	"mc0_dimm_event",
	"mc1_dimm_event",
	"machine_gen_alert",
	"nmi_cpu_sw",
	"smbus_alert_0",
	"smbus_alert_1",
	"board_event",
	"cpu_hot",
	"mc0_throttle",
	"mc1_throttle",
	"cpu_forcepr",
	"term_nomax",
	"term_fault",
	"term_diag",
	"volt_no_minmax",
	"volt_fault",
	"volt_diag",
	"uC_int",
	"ts_alarma",
	"ts_alarmb",
	"vm_alarma",
	"vm_alarmb",
	"pd_alarma",
	"pd_alarmb",
	"pvt_all_int",
	NULL,
	NULL,
	"core_cc_lo", /* CORE0-CORE7 */
	NULL,
	"core_cu_lo", /* CORE0-CORE7 */
	NULL
};

struct cpufreq_policy;
extern unsigned int pcsm_l_cpufreq_get(unsigned int cpu);
extern int pcsm_l_cpufreq_init(struct cpufreq_policy *policy);

typedef union pwm_regs {
    struct {
	u32 val:        1;
	u32 cop:        1;
	u32 sel:        2;
	u32 addr:       8;
	u32 wdata:      8;
	u32 rsv:        3;
	u32 rdata_val:  1;
	u32 rdata:      8;
    };
    u32 word;
} pwm_regs_t;

typedef union pmc_term_ts_regs {
    struct {
	short temp:    12; /* 9.3 fixed point */
	u32 valid:      1;
	u32 diag:       1;
	u32 fault:      1;
	u32 rsv:        1;
	u32 addr:      12;
	u32 rsv2:       2;
	u32 enable:     1;
	u32 rmwen:      1;
    };
    u32 word;
} term_ts_regs_t;

typedef union pvt_vm_regs {
    struct {
	u32 data:      14;
	u32 rsv1:       2;
	u32 type:       1;
	u32 fault:      1;
	u32 rsv2:      14;
    };
    u32 word;
} pvt_vm_regs_t;

typedef union pmc_vm_regs {
    struct {
	u32 v_i:         11;
	u32 v_val_i:      1;
	u32 v_diag_i:     1;
	u32 v_fault_i:    1;
	u32 rsv1:         2;
	u32 v_j:         11;
	u32 v_val_j:      1;
	u32 v_diag_j:     1;
	u32 v_fault_j:    1;
	u32 rsv2:         2;
    };
    u32 word;
} pmc_vm_regs_t;

typedef union pwm_tach_control_regs {
    struct {
	u8 enable:	    1;
	u8 valid:	    1;
	u8 time_interval:   1;
	u8 posedge:	    1;
	u8 negedge:	    1;
	u8 reserv:	    3;
    };
    u8 byte;
} __packed pwm_tach_control_regs_t;

#endif /* _PCSM_H_ */
