/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef PCSM_H_
#define PCSM_H_

#define MAX_NODE 4

#define PCSM_BASE_ADDR                  0x1000
#define PVT_BASE_ADDR                   0x2000

#define FRST_INST                       0x1
#define SCND_INST                       0x2

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

#define PMC_SYS_EVENTS_POLLING		0x510
#define PMC_SYS_EVENTS_MASK		0x514
#define PMC_SYS_EVENTS_INT		0x518
#define PMC_SYS_EVENTS_HW		0x51c
#define PMC_SYS_EVENTS_CFG		0x520

#define MC03_DIMM_EVENT		    (1 << 0)
#define MC47_DIMM_EVENT		    (1 << 1)
#define MC03_PWR_ALERT		    (1 << 2)
#define MC47_PWR_ALERT		    (1 << 3)
#define CPU_PWR_ALERT		    (1 << 4)
#define MACHINE_PWR_ALERT	    (1 << 5)
#define MACHINE_GEN_ALERT	    (1 << 6)
#define PCS_FAN0_ALERT		    (1 << 7)
#define PCS_FAN1_ALERT		    (1 << 8)
#define TERM_NOMAX		    (1 << 9)
#define TERM_FAULT		    (1 << 10)
#define TERM_DIAG		    (1 << 11)
#define CPU_HOT			    (1 << 12)
#define TS_ALL_INT		    (1 << 13)
#define TS_ALARMA		    (1 << 14)
#define TS_ALARMB		    (1 << 15)
#define VM_ALL_INT		    (1 << 16)
#define VM_ALARMA		    (1 << 17)
#define VM_ALARMB		    (1 << 18)
#define PD_ALL_INT		    (1 << 19)
#define PD_ALARMA		    (1 << 20)
#define PD_ALARMB		    (1 << 21)
#define MC03_THROTTLE		    (1 << 22)
#define MC47_THROTTLE		    (1 << 23)
#define CPU_FORCEPR		    (1 << 24)

#define PCS_EVENTS_MAX			25

#define CONTINUOUS_EVENTS_MASK		\
	    (				\
		MC03_DIMM_EVENT	    |	\
		MC47_DIMM_EVENT	    |	\
		MC03_PWR_ALERT	    |	\
		MC47_PWR_ALERT	    |	\
		CPU_PWR_ALERT	    |	\
		MACHINE_PWR_ALERT   |	\
		MACHINE_GEN_ALERT   |	\
		PCS_FAN0_ALERT	    |	\
		PCS_FAN1_ALERT	    |	\
		TERM_NOMAX	    |	\
		TERM_FAULT	    |	\
		TERM_DIAG		\
	    )

#define THROTTLING_EVENTS_MASK		\
	    (				\
		CPU_HOT		    |	\
		MC03_THROTTLE	    |	\
		MC47_THROTTLE	    |	\
		CPU_FORCEPR		\
	    )

#define ALARM_EVENTS_MASK		\
	    (				\
		TS_ALARMA	    |	\
		TS_ALARMB	    |	\
		VM_ALARMA	    |	\
		VM_ALARMB		\
	    )


#define ALL_EVENTS_MASK			\
	(CONTINUOUS_EVENTS_MASK | THROTTLING_EVENTS_MASK | ALARM_EVENTS_MASK)

typedef struct event_info {
	int count;
	time64_t time;
} event_info_t;

event_info_t pcs_events[MAX_NODE][PCS_EVENTS_MAX];

static int PCS_ADJUST_PERIOD = 300000; /* ms */

#define PMC_FAN_CFG                     0x540

/* */
#define PMC_TERM_CONV                   0x008
#define PMC_TERM_CTRL                   0x00c
#define PMC_TERM_TS0                    0x010
#define PMC_TERM_TS1                    0x014
#define PMC_TERM_TS2                    0x018
#define PMC_TERM_TS3                    0x01c
#define PMC_TERM_TS4                    0x020
#define PMC_TERM_TS5                    0x024
#define PMC_TERM_TS6                    0x028
#define PMC_TERM_TS7                    0x02c

#define PCS_PVT_REGS_VM_BASE    0x184
#define PCS_VM0_DATA_OFFSET     0x034

#define PCS_VM_N_CH_DATA(n, ch)	\
	(PVT_BASE_ADDR + PCS_PVT_REGS_VM_BASE + PCS_VM0_DATA_OFFSET + (n*16 + ch)*4)

#define NO_EXIST    -1
#define VCORE       0
#define VDDR        1

/* max value for pwm and temp registers */
#define PCSM_THERM_MAX			0xFF
#define PCSM_PWM_MAX			0x80

#define PCSM_LUT_COUNT			10

#define MANUFACTURER_ID_LO		0xC3
#define MANUFACTURER_ID_HI		0xE2

#define VM_MAX_CHANNELS 16
#define VM_MAX_SENSORS  8

#define ACCURACY 10

enum vm_values {
	VM1,
	VM2,
	VM3,
	VM4,
	VM5,
	VM6
};

enum ts_values {
	TS1,
	TS2,
	TS3,
	TS4,
	TS5,
	TS6,
	TS7
};

struct ts {
	char *name;
	int addr;
};

static const struct ts ts_e16c_map[] = {
	{"CORE_0",  PMC_TERM_TS5},
	{"CORE_1",  PMC_TERM_TS1},
	{"CORE_14", PMC_TERM_TS2},
	{"CORE_15", PMC_TERM_TS3},
	{"EIOH",    PMC_TERM_TS4},
	{"TEST",    PMC_TERM_TS0},
	{"Tmax",    PMC_TERM_TS6}
};

static const struct ts ts_e12c_map[] = {
	{"CORE_0",  PMC_TERM_TS1},
	{"CORE_1",  PMC_TERM_TS0},
	{"CORE_10", PMC_TERM_TS2},
	{"CORE_11", PMC_TERM_TS3},
	{"EIOH",    PMC_TERM_TS4},
	{"",	    PMC_TERM_TS5},
	{"Tmax",    PMC_TERM_TS6}
};

static const struct ts ts_e2c3_map[] = {
	{"CORE_0",  PMC_TERM_TS2},
	{"CORE_1",  PMC_TERM_TS1},
	{"MC0",	    PMC_TERM_TS3},
	{"MC1",	    PMC_TERM_TS0},
	{"EIOH",    PMC_TERM_TS4},
	{"",	    PMC_TERM_TS5},
	{"Tmax",    PMC_TERM_TS6}
};


static const char * const pmc_sys_events[] = {
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

int vm_table_e16c[VM_MAX_CHANNELS][VM_MAX_SENSORS] = {
	{VCORE, VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, },
	{VCORE, VDDR,  VDDR,  VDDR,  VCORE, VDDR,  NO_EXIST, NO_EXIST, },
	{VCORE, VDDR,  VDDR,  VDDR,  VCORE, VDDR,  NO_EXIST, NO_EXIST, },
	{VCORE, VDDR,  VDDR,  VDDR,  VCORE, VDDR,  NO_EXIST, NO_EXIST, },
	{VCORE, VDDR,  VDDR,  VDDR,  VCORE, VDDR,  NO_EXIST, NO_EXIST, },
	{VCORE, VDDR,  VDDR,  VDDR,  VCORE, VDDR,  NO_EXIST, NO_EXIST, },
	{VCORE, VDDR,  VDDR,  VDDR,  VCORE, VDDR,  NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, },
};

int vm_table_e2c3[VM_MAX_CHANNELS][VM_MAX_SENSORS] = {
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VDDR,  VCORE, VCORE, VDDR,  VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VDDR,  VCORE, VCORE, VDDR,  VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VDDR,  VCORE, VCORE, VDDR,  VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
};

int vm_table_e12c[VM_MAX_CHANNELS][VM_MAX_SENSORS] = {
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VDDR,  VDDR,  VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VDDR,  VDDR,  VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VDDR,  VDDR,  VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
	{VCORE, VCORE, VCORE, VCORE, VCORE, NO_EXIST, NO_EXIST, NO_EXIST, },
};

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
	u32 temp:       12;
	u32 val:        1;
	u32 diag:       1;
	u32 fault:      1;
	u32 rsv:        1;
	u32 addr:       12;
	u32 rsv2:       2;
	u32 enable:     1;
	u32 rmwen:      1;
    };
    u32 word;
} term_ts_regs_t;

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
} pwm_tach_control_regs_t;

#endif /* _PCSM_H_ */
