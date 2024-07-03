/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/node.h>
#include <linux/cpu.h>
#include <linux/mod_devicetable.h>
#include <linux/hwmon-sysfs.h>
#include <linux/cpufreq.h>
#include <linux/bits.h>
#include <linux/kthread.h>
#include <linux/jiffies.h>
#include <linux/sched.h>

#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/epic.h>

#include "pcsm.h"

struct delayed_work pcsm_monitor;

struct pcsm_data {
	struct platform_device *pdev;
	struct device *hdev;
	int node;
};

int (*vm_table_type)[VM_MAX_SENSORS];
struct pcsm_data *p_pcsm[MAX_NODE];

static const struct ts *ts_map;

#ifdef DEBUG
static void print_pwm_regs(pwm_regs_t *regs)
{
    pr_err("val         0x%x\n", regs->val);
    pr_err("cop         0x%x\n", regs->cop);
    pr_err("sel         0x%x\n", regs->sel);
    pr_err("addr        0x%x\n", regs->addr);
    pr_err("wdata       0x%x\n", regs->wdata);
    pr_err("rsv         0x%x\n", regs->rsv);
    pr_err("rdata_val   0x%x\n", regs->rdata_val);
    pr_err("rdata       0x%x\n", regs->rdata);
}
#endif

static void pwm_wait_val(int node)
{
    int i = 0;
    pwm_regs_t regs;

    regs.val = 1;

    while (regs.val && i < 100) {
	regs.word = sic_read_node_nbsr_reg(node, PCSM_BASE_ADDR + PMC_FAN_CFG);
	i++;
    }
}

static void pwm_wait_rdata_val(int node)
{
    int i = 0;
    pwm_regs_t regs = {.word = 0};

    while (!regs.rdata_val && i < 100) {
	regs.word = sic_read_node_nbsr_reg(node, PCSM_BASE_ADDR + PMC_FAN_CFG);
	i++;
    }
}

static u8 read_pwm_data(int node, int sel, u8 addr)
{
    pwm_regs_t regs = {.word = sic_read_node_nbsr_reg(node,
	    PCSM_BASE_ADDR + PMC_FAN_CFG)};

    regs.val = 1;
    regs.cop = 0;
    regs.sel = sel;
    regs.addr = addr;
    regs.wdata = 0;

    sic_write_node_nbsr_reg(node, PCSM_BASE_ADDR + PMC_FAN_CFG, regs.word);

    pwm_wait_rdata_val(node);

    regs.word = sic_read_node_nbsr_reg(node, PCSM_BASE_ADDR + PMC_FAN_CFG);

    return regs.rdata;
}

static void write_pwm_data(int node, int sel, u8 addr, u8 data)
{
    pwm_regs_t regs = {.word = sic_read_node_nbsr_reg(node,
	    PCSM_BASE_ADDR + PMC_FAN_CFG)};

    regs.val = 1;
    regs.cop = 1;
    regs.sel = sel;
    regs.addr = addr;
    regs.wdata = data;

    sic_write_node_nbsr_reg(node, PCSM_BASE_ADDR + PMC_FAN_CFG, regs.word);

    pwm_wait_val(node);
}

#define PWM_TO_PROCENT(v) (((v) * 78125) / 100000)
#define PROCENT_TO_PWM(v) (((v) * 100000) / 78125)

#define PWM_TEMP_TO_HWMON(v) ((v)/2 * 1000 + ((v)%2 ? 500 : 0))

static ssize_t show_fan(struct device *dev,
	struct device_attribute *devattr,
	char *buf)
{
    struct sensor_device_attribute_2 *attr = to_sensor_dev_attr_2(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);
    pwm_tach_control_regs_t control;

    int nr = attr->nr;
    int addr = attr->index;

    u8 val_lo = read_pwm_data(data->node, nr, addr);
    u8 val_hi = read_pwm_data(data->node, nr, addr + 1);

    u16 val = (val_hi << 8) + val_lo;

    control.byte = read_pwm_data(data->node, nr, PCSM_MX_TACH_CTRL);

    if (control.posedge + control.negedge > 0)
	val = val * ((control.time_interval) ? 6 : 60) / (2 * (control.posedge + control.negedge));
    else
	val = 0;

    return snprintf(buf, PAGE_SIZE - 1, "%d\n", val);
}

static int DIV_TO_REG(unsigned long val)
{
    int answer = 0;

    while (answer < 7 && (val >>= 1))
	answer++;
    return answer;
}

#define DIV_FROM_REG(val) BIT(val)

static ssize_t show_fan_div(struct device *dev,
	struct device_attribute *devattr,
	char *buf)
{
    struct sensor_device_attribute_2 *attr = to_sensor_dev_attr_2(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);

    unsigned long val = read_pwm_data(data->node, attr->nr, attr->index);

    return snprintf(buf, PAGE_SIZE - 1, "%ld\n", DIV_FROM_REG(val));
}

static ssize_t set_fan_div(struct device *dev,
	struct device_attribute *devattr,
	const char *buf, size_t count)
{
    struct sensor_device_attribute_2 *attr = to_sensor_dev_attr_2(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);
    unsigned long val;

    int err = kstrtoul(buf, 10, &val);
    if (err) {
	return err;
    }

    val = clamp_val(PROCENT_TO_PWM(val), 0, 0x80);

    write_pwm_data(data->node, attr->nr,
	    attr->index, DIV_TO_REG(val));

    return count;
}


static ssize_t show_pwm(struct device *dev,
	struct device_attribute *devattr,
	char *buf)
{
    struct sensor_device_attribute_2 *attr = to_sensor_dev_attr_2(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);

    int nr = attr->nr;
    int addr = attr->index;

    addr = addr ? addr : PCSM_RW_PWM_CURRENT;

    u8 val = read_pwm_data(data->node, nr, addr);

    return snprintf(buf, PAGE_SIZE - 1, "%d\n", PWM_TO_PROCENT(val));
}


static ssize_t set_pwm(struct device *dev,
	struct device_attribute *devattr,
	const char *buf, size_t count)
{
    struct sensor_device_attribute_2 *attr = to_sensor_dev_attr_2(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);
    unsigned long val;
    int err;

    int nr = attr->nr;
    int addr = attr->index;

    addr = addr ? addr : PCSM_RW_PWM_FIXED;

    err = kstrtoul(buf, 10, &val);
    if (err) {
	return err;
    }

    val = clamp_val(val, 0, 0x80);

    write_pwm_data(data->node, nr, addr, PROCENT_TO_PWM(val));

    return count;
}


static ssize_t show_pwm_byte(struct device *dev,
	struct device_attribute *devattr,
	char *buf)
{
    struct sensor_device_attribute_2 *attr = to_sensor_dev_attr_2(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);

    int nr = attr->nr;
    int addr = attr->index;

    u8 val = read_pwm_data(data->node, nr, addr);

    return snprintf(buf, PAGE_SIZE - 1, "0x%x\n", val);
}

static ssize_t set_pwm_byte(struct device *dev,
	struct device_attribute *devattr,
	const char *buf, size_t count)
{
    struct sensor_device_attribute_2 *attr = to_sensor_dev_attr_2(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);
    unsigned long val;
    int err;

    int nr = attr->nr;
    int addr = attr->index;

    err = kstrtoul(buf, 10, &val);
    if (err) {
	return err;
    }

    write_pwm_data(data->node, nr, addr, val);

    return count;
}

static ssize_t set_fan(struct device *dev,
	struct device_attribute *devattr,
	const char *buf, size_t count)
{
    struct sensor_device_attribute_2 *attr = to_sensor_dev_attr_2(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);
    unsigned long val;
    pwm_tach_control_regs_t control;
    int err;

    int nr = attr->nr;
    int addr = attr->index;

    err = kstrtoul(buf, 10, &val);
    if (err) {
	return err;
    }

    control.byte = read_pwm_data(data->node, nr, PCSM_MX_TACH_CTRL);

    val = val * 2 * (control.posedge + control.negedge) / ((control.time_interval) ? 6 : 60);

    u8 val_lo = val & 0xff;
    u8 val_hi = (val >> 8) & 0xff;

    write_pwm_data(data->node, nr, addr, val_lo);
    write_pwm_data(data->node, nr, addr + 1, val_hi);

    return count;
}

static ssize_t pwm_show_temp(struct device *dev,
	struct device_attribute *devattr,
	char *buf)
{
    struct sensor_device_attribute_2 *attr = to_sensor_dev_attr_2(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);

    int nr = attr->nr;
    int addr = attr->index;

    u8 temp = read_pwm_data(data->node, nr, addr);

    /* attr specific */
    if (temp < 0) {
	snprintf(buf, PAGE_SIZE - 1, "error\n");
    } else {
	if (temp >= PCSM_THERM_MAX) {
	    snprintf(buf, PAGE_SIZE - 1, "128000\n");
	} else if (temp <= 0) {
	    snprintf(buf, PAGE_SIZE - 1, "0\n");
	} else {
	    snprintf(buf, PAGE_SIZE - 1, "%d\n",
		    PWM_TEMP_TO_HWMON(temp));
	}
    }

    return strlen(buf);
}

static ssize_t pwm_set_temp(struct device *dev,
	struct device_attribute *devattr,
	const char *buf, size_t count)
{
    struct sensor_device_attribute_2 *attr = to_sensor_dev_attr_2(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);

    unsigned long value;

    int nr = attr->nr;
    int addr = attr->index;
    u8 temp;

    int err = kstrtoul(buf, 10, &value);
    if (err) {
	return err;
    }

    value = clamp_val(value, 0, 128000);
    temp = value % 1000 ? 1 : 0;
    value = value / 1000;
    temp += value*2;

    write_pwm_data(data->node, nr, addr, temp);

    return count;
}

#define TEMP_TO_HWMON(v) (((v)/8)* 1000 + (((v) & 0x7) * 125))

static ssize_t pmc_show_temp(struct device *dev,
	struct device_attribute *devattr,
	char *buf)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);

    int addr = ts_map[attr->index].addr;

    term_ts_regs_t regs = { .word = sic_read_node_nbsr_reg(data->node,
	    PCSM_BASE_ADDR + addr) };

    return snprintf(buf, PAGE_SIZE - 1, "%d\n", TEMP_TO_HWMON(regs.temp));
}

static ssize_t pmc_show_temp_max(struct device *dev,
	struct device_attribute *devattr,
	char *buf)
{
    struct pcsm_data *data = dev_get_drvdata(dev);
    int index;
    int ts_max = 0;
    int ts_count = 5;

    if (IS_MACHINE_E16C) {
	ts_count++;
    }

    for (index = 0; index < ts_count; index++) {
	term_ts_regs_t regs = { .word = sic_read_node_nbsr_reg(data->node,
		PCSM_BASE_ADDR + ts_map[index].addr) };
	int ts_val = TEMP_TO_HWMON(regs.temp);

	if (ts_val > ts_max)
	    ts_max = ts_val;
    }


    return snprintf(buf, PAGE_SIZE - 1, "%d\n", ts_max);
}

#define VREF    1213
#define N_TO_V(N) (VREF*ACCURACY*(6*N - 3 - (1 << 14))/((1 << 14)*5))

static void pvt_read_vm_data(int (*vm_table_val)[VM_MAX_SENSORS], int node)
{
    int ch, sn;

    memset(vm_table_val[0], 0, sizeof(int)*VM_MAX_CHANNELS*VM_MAX_SENSORS);

    for (ch = 0; ch < VM_MAX_CHANNELS; ch++) {
	for (sn = 0; sn < VM_MAX_SENSORS; sn++) {
	    if (vm_table_e16c[ch][sn] != NO_EXIST) {
		int val = sic_read_node_nbsr_reg(node, PCS_VM_N_CH_DATA(sn, ch));
#ifdef DEBUG
		pr_err("DEBUG: addr 0x%x sn %d ch %d val %d volt %d",
			PCS_VM_N_CH_DATA(sn, ch), sn, ch, val, N_TO_V(val));
#endif
		vm_table_val[ch][sn] = N_TO_V(val);
	    }
	}
    }
}

static int pvt_in_avg(int (*vm_table_val)[VM_MAX_SENSORS], int index)
{
    int ch, sn, sum = 0;
    unsigned int count = 0;

    for (ch = 0; ch < VM_MAX_CHANNELS; ch++) {
	for (sn = 0; sn < VM_MAX_SENSORS; sn++) {
	    if (vm_table_type[ch][sn] == index) {
		count++;
		sum += vm_table_val[ch][sn];
	    }
	}
    }

    return (count > 0) ? sum/count : 0;
}

static ssize_t pvt_show_in_avg(struct device *dev,
	struct device_attribute *devattr,
	char *buf)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);
    int vm_table_val[VM_MAX_CHANNELS][VM_MAX_SENSORS];

    pvt_read_vm_data(vm_table_val, data->node);

    return snprintf(buf, PAGE_SIZE - 1, "%d.%d\n",
	pvt_in_avg(vm_table_val, attr->index)/ACCURACY,
	pvt_in_avg(vm_table_val, attr->index)%ACCURACY);
}

static int pvt_in_min(int (*vm_table_val)[VM_MAX_SENSORS], int index)
{
    int ch, sn, lowest = INT_MAX;

    for (ch = 0; ch < VM_MAX_CHANNELS; ch++) {
	for (sn = 0; sn < VM_MAX_SENSORS; sn++) {
	    if (vm_table_type[ch][sn] == index) {
		if (vm_table_val[ch][sn] < lowest) {
		    lowest = vm_table_val[ch][sn];
		}
	    }
	}
    }

    return lowest;
}

static ssize_t pvt_show_in_min(struct device *dev,
    struct device_attribute *devattr,
    char *buf)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);
    int vm_table_val[VM_MAX_CHANNELS][VM_MAX_SENSORS];

    pvt_read_vm_data(vm_table_val, data->node);

    return snprintf(buf, PAGE_SIZE - 1, "%d.%d\n",
	pvt_in_min(vm_table_val, attr->index)/ACCURACY,
	pvt_in_min(vm_table_val, attr->index)%ACCURACY);
}

static int pvt_in_max(int (*vm_table_val)[VM_MAX_SENSORS], int index)
{
    int ch, sn, highest = INT_MIN;

    for (ch = 0; ch < VM_MAX_CHANNELS; ch++) {
	for (sn = 0; sn < VM_MAX_SENSORS; sn++) {
	    if (vm_table_type[ch][sn] == index) {
		if (vm_table_val[ch][sn] > highest) {
		    highest = vm_table_val[ch][sn];
		}
	    }
	}
    }

    return highest;
}

static ssize_t pvt_show_in_max(struct device *dev,
    struct device_attribute *devattr,
    char *buf)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);
    int vm_table_val[VM_MAX_CHANNELS][VM_MAX_SENSORS];

    pvt_read_vm_data(vm_table_val, data->node);

    return snprintf(buf, PAGE_SIZE - 1, "%d.%d\n",
	pvt_in_max(vm_table_val, attr->index)/ACCURACY,
	pvt_in_max(vm_table_val, attr->index)%ACCURACY);
}

static int vddr_sensor_exist(int (*vm_table_val)[VM_MAX_SENSORS], int sensor)
{
    int ch;

    for (ch = 0; ch < VM_MAX_CHANNELS; ch++) {
	if (vm_table_type[ch][sensor] == VDDR) {
	    return 1;
	}
    }

    return 0;
}

#define INFO_BRIEF  0
#define INFO_ALL    1

static ssize_t pvt_show_vm_info(struct device *dev,
    struct device_attribute *devattr,
    char *buf)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);
    int vm_table_val[VM_MAX_CHANNELS][VM_MAX_SENSORS];
    int ch, sn;
    int pos = 0;

    pvt_read_vm_data(vm_table_val, data->node);

    if (attr->index == INFO_ALL) {
	for (sn = 0; sn < VM_MAX_SENSORS; sn++) {
	    if (vm_table_type[0][sn] != NO_EXIST) {
		pos += snprintf(&buf[pos], PAGE_SIZE - 1,  "VM[%d] VCORE mV: ", sn);
		for (ch = 0; ch < VM_MAX_CHANNELS; ch++) {
		    if (vm_table_type[ch][sn] == VCORE) {
			pos += snprintf(&buf[pos], PAGE_SIZE - 1, "%d.%d ",
			vm_table_val[ch][sn]/ACCURACY, vm_table_val[ch][sn]%ACCURACY);
		    }
		}
		if (vddr_sensor_exist(vm_table_type, sn)) {
		    pos += snprintf(&buf[pos], PAGE_SIZE - 1,  "\nVM[%d] VDDR  mV: ", sn);
		    for (ch = 0; ch < VM_MAX_CHANNELS; ch++) {
			if (vm_table_type[ch][sn] == VDDR) {
			    pos += snprintf(&buf[pos], PAGE_SIZE - 1, "%d.%d ",
			    vm_table_val[ch][sn]/ACCURACY, vm_table_val[ch][sn]%ACCURACY);
			}
		    }
		}
		pos += snprintf(&buf[pos], PAGE_SIZE - 1, "\n");
	    }
	}
    }

    pos += snprintf(&buf[pos], PAGE_SIZE - 1, "VCORE avg: %d.%d min: %d.%d max: %d.%d\n",
	    pvt_in_avg(vm_table_val, VCORE)/ACCURACY, pvt_in_avg(vm_table_val, VCORE)%ACCURACY,
	    pvt_in_min(vm_table_val, VCORE)/ACCURACY, pvt_in_min(vm_table_val, VCORE)%ACCURACY,
	    pvt_in_max(vm_table_val, VCORE)/ACCURACY, pvt_in_max(vm_table_val, VCORE)%ACCURACY);

    pos += snprintf(&buf[pos], PAGE_SIZE - 1, "VDDR  avg: %d.%d min: %d.%d max: %d.%d\n",
	    pvt_in_avg(vm_table_val, VDDR)/ACCURACY, pvt_in_avg(vm_table_val, VDDR)%ACCURACY,
	    pvt_in_min(vm_table_val, VDDR)/ACCURACY, pvt_in_min(vm_table_val, VDDR)%ACCURACY,
	    pvt_in_max(vm_table_val, VDDR)/ACCURACY, pvt_in_max(vm_table_val, VDDR)%ACCURACY);

    return pos;
}

static const char * const input_names[] = {
	[VM1] = "Vcore average",
	[VM2] = "Vcore min",
	[VM3] = "Vcore max",
	[VM4] = "Vddr  average",
	[VM5] = "Vddr  min",
	[VM6] = "Vddr  max",
};

static ssize_t in_label_show(struct device *dev,
	struct device_attribute *devattr,
	char *buf)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);

    return sprintf(buf, "%s\n", input_names[attr->index]);
}

static ssize_t ts_label_show(struct device *dev,
	struct device_attribute *devattr,
	char *buf)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    const char *ts_name;

    if (IS_MACHINE_E16C || IS_MACHINE_E12C || IS_MACHINE_E2C3)
	ts_name = ts_map[attr->index].name;
    else
	ts_name = "unsupported CPU";

    return sprintf(buf, "%s\n", ts_name);
}

static ssize_t show_pcs_adjust_period(struct device *dev,
    struct device_attribute *devattr,
    char *buf)
{
    return snprintf(buf, PAGE_SIZE - 1, "%d\n", PCS_ADJUST_PERIOD);
}

static ssize_t set_pcs_adjust_period(struct device *dev,
	struct device_attribute *devattr,
	const char *buf, size_t count)
{
    struct pcsm_data *data = dev_get_drvdata(dev);
    unsigned long value;

    int err = kstrtoul(buf, 10, &value);
    if (err) {
	return err;
    }

    PCS_ADJUST_PERIOD = value;

    flush_delayed_work(&pcsm_monitor);

    return count;
}

static ssize_t show_pcs_events(struct device *dev,
    struct device_attribute *devattr,
    char *buf)
{
    struct pcsm_data *data = dev_get_drvdata(dev);
    int pos = 0;
    int i = 0;

    pos += snprintf(&buf[pos], PAGE_SIZE - 1, "%-20s %-5s %-19s\n", "name", "count", "date");

    for (i = 0; i < PCS_EVENTS_MAX; i++) {
	    struct tm tm_event;

	    if (pcs_events[data->node][i].count != 0) {
		time64_to_tm(pcs_events[data->node][i].time, 0, &tm_event);

		pos += snprintf(&buf[pos], PAGE_SIZE - 1, "%-20s %5d %04ld-%02d-%02d %02d:%02d:%02d\n",
			pmc_sys_events[i], pcs_events[data->node][i].count,
			tm_event.tm_year + 1900, tm_event.tm_mon + 1, tm_event.tm_mday,
			tm_event.tm_hour, tm_event.tm_min, tm_event.tm_sec);
	    } else {
		pos += snprintf(&buf[pos], PAGE_SIZE - 1, "%-20s %25s\n", pmc_sys_events[i], "no");
	    }
    }

    return pos;
}

void pcsm_interrupt(void)
{
    int node = numa_node_id(), i;
    int reg = 0;

    reg = sic_read_node_nbsr_reg(node, PCSM_BASE_ADDR + PMC_SYS_EVENTS_POLLING);

    for (i = 0; i < PCS_EVENTS_MAX; i++) {
	if (reg & (1 << i)) {
	    pcs_events[node][i].count++;
	    pcs_events[node][i].time = ktime_get_real_seconds();
	}
    }
}

#ifdef CONFIG_EPIC
static void pcs_events_enable(int node)
{
    sic_write_node_nbsr_reg(node, PCSM_BASE_ADDR + PMC_SYS_EVENTS_MASK, ALL_EVENTS_MASK);
}
#endif

#define MATTR (S_IWUSR | S_IRUGO)

/* TEMP */
static SENSOR_DEVICE_ATTR(temp1_input, MATTR,
		pmc_show_temp, NULL, TS1);
static SENSOR_DEVICE_ATTR(temp2_input, MATTR,
		pmc_show_temp, NULL, TS2);
static SENSOR_DEVICE_ATTR(temp3_input, MATTR,
		pmc_show_temp, NULL, TS3);
static SENSOR_DEVICE_ATTR(temp4_input, MATTR,
		pmc_show_temp, NULL, TS4);
static SENSOR_DEVICE_ATTR(temp5_input, MATTR,
		pmc_show_temp, NULL, TS5);
static SENSOR_DEVICE_ATTR(temp6_input, MATTR,
		pmc_show_temp, NULL, TS6);
static DEVICE_ATTR(temp7_input, MATTR,
		pmc_show_temp_max, NULL);


static SENSOR_DEVICE_ATTR_RO(temp1_label, ts_label, TS1);
static SENSOR_DEVICE_ATTR_RO(temp2_label, ts_label, TS2);
static SENSOR_DEVICE_ATTR_RO(temp3_label, ts_label, TS3);
static SENSOR_DEVICE_ATTR_RO(temp4_label, ts_label, TS4);
static SENSOR_DEVICE_ATTR_RO(temp5_label, ts_label, TS5);
static SENSOR_DEVICE_ATTR_RO(temp6_label, ts_label, TS6);
static SENSOR_DEVICE_ATTR_RO(temp7_label, ts_label, TS7);


/* VOLT */
static SENSOR_DEVICE_ATTR(in1_input, MATTR,
		pvt_show_in_avg, NULL, VCORE);
static SENSOR_DEVICE_ATTR(in2_input, MATTR,
		pvt_show_in_min, NULL, VCORE);
static SENSOR_DEVICE_ATTR(in3_input, MATTR,
		pvt_show_in_max, NULL, VCORE);

static SENSOR_DEVICE_ATTR(in4_input, MATTR,
		pvt_show_in_avg, NULL, VDDR);
static SENSOR_DEVICE_ATTR(in5_input, MATTR,
		pvt_show_in_min, NULL, VDDR);
static SENSOR_DEVICE_ATTR(in6_input, MATTR,
		pvt_show_in_max, NULL, VDDR);

static SENSOR_DEVICE_ATTR(vcore_table, MATTR,
		pvt_show_vm_info, NULL, INFO_ALL);
static SENSOR_DEVICE_ATTR(vcore_brief, MATTR,
		pvt_show_vm_info, NULL, INFO_BRIEF);
static DEVICE_ATTR(pcs_events, MATTR,
		show_pcs_events, NULL);
static DEVICE_ATTR(pcs_adjust_period, MATTR,
		show_pcs_adjust_period, set_pcs_adjust_period);

static SENSOR_DEVICE_ATTR_RO(in1_label, in_label, VM1);
static SENSOR_DEVICE_ATTR_RO(in2_label, in_label, VM2);
static SENSOR_DEVICE_ATTR_RO(in3_label, in_label, VM3);
static SENSOR_DEVICE_ATTR_RO(in4_label, in_label, VM4);
static SENSOR_DEVICE_ATTR_RO(in5_label, in_label, VM5);
static SENSOR_DEVICE_ATTR_RO(in6_label, in_label, VM6);

/* FIRST INSTANCE */
/* FAN */
static SENSOR_DEVICE_ATTR_2(fan1_min, MATTR,
		show_fan, set_fan, FRST_INST, PCSM_RW_TACH_MIN_LO);
static SENSOR_DEVICE_ATTR_2(fan1_max, MATTR,
		show_fan, set_fan, FRST_INST, PCSM_RW_TACH_MAX_LO);
static SENSOR_DEVICE_ATTR_2(fan1_input, MATTR,
		show_fan, NULL, FRST_INST, PCSM_RO_TACH_LO);
static SENSOR_DEVICE_ATTR_2(fan1_div, MATTR,
		show_fan_div, set_fan_div, FRST_INST, PCSM_RW_TIME_INTERVAL);
static SENSOR_DEVICE_ATTR_2(tach1_control, MATTR,
		show_pwm_byte, set_pwm_byte, FRST_INST, PCSM_MX_TACH_CTRL);

/* PWM */
static SENSOR_DEVICE_ATTR_2(pwm1, MATTR,
		show_pwm, set_pwm, FRST_INST, 0);
static SENSOR_DEVICE_ATTR_2(pwm1_mode, MATTR,
		show_pwm_byte, set_pwm_byte, FRST_INST, PCSM_RW_CONTROL);

/* ALERT */
static SENSOR_DEVICE_ATTR_2(alert1_control, MATTR,
		show_pwm_byte, set_pwm_byte, FRST_INST, PCSM_RW_ALERT_CTRL);
static SENSOR_DEVICE_ATTR_2(alert1_status, MATTR,
		show_pwm_byte, set_pwm_byte, FRST_INST, PCSM_RW_ALERT_STATUS);

/* AUTO POINTS */
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point1_temp, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT0_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point1_pwm, MATTR,
		show_pwm,  set_pwm,  FRST_INST, PCSM_RW_LUT0_PWM);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point1_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT0_HYST);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point2_temp, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT1_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point2_pwm, MATTR,
		show_pwm,  set_pwm,  FRST_INST, PCSM_RW_LUT1_PWM);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point2_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT1_HYST);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point3_temp, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT2_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point3_pwm, MATTR,
		show_pwm,  set_pwm,  FRST_INST, PCSM_RW_LUT2_PWM);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point3_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT2_HYST);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point4_temp, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT3_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point4_pwm, MATTR,
		show_pwm,  set_pwm,  FRST_INST, PCSM_RW_LUT3_PWM);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point4_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT3_HYST);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point5_temp, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT4_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point5_pwm, MATTR,
		show_pwm,  set_pwm,  FRST_INST, PCSM_RW_LUT4_PWM);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point5_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT4_HYST);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point6_temp, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT5_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point6_pwm, MATTR,
		show_pwm,  set_pwm,  FRST_INST, PCSM_RW_LUT5_PWM);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point6_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT5_HYST);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point7_temp, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT6_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point7_pwm, MATTR,
		show_pwm,  set_pwm,  FRST_INST, PCSM_RW_LUT6_PWM);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point7_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT6_HYST);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point8_temp, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT7_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point8_pwm, MATTR,
		show_pwm,  set_pwm,  FRST_INST, PCSM_RW_LUT7_PWM);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point8_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT7_HYST);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point9_temp, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT8_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point9_pwm, MATTR,
		show_pwm,  set_pwm,  FRST_INST, PCSM_RW_LUT8_PWM);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point9_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT8_HYST);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point10_temp, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT9_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point10_pwm, MATTR,
		show_pwm,  set_pwm,  FRST_INST, PCSM_RW_LUT9_PWM);
static SENSOR_DEVICE_ATTR_2(pwm1_auto_point10_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST, PCSM_RW_LUT9_HYST);

/* SECOND INSTANCE */
/* FAN */
static SENSOR_DEVICE_ATTR_2(fan2_min, MATTR,
		show_fan, set_fan, SCND_INST, PCSM_RW_TACH_MIN_LO);
static SENSOR_DEVICE_ATTR_2(fan2_max, MATTR,
		show_fan, set_fan, SCND_INST, PCSM_RW_TACH_MAX_LO);
static SENSOR_DEVICE_ATTR_2(fan2_input, MATTR,
		show_fan, NULL, SCND_INST, PCSM_RO_TACH_LO);
static SENSOR_DEVICE_ATTR_2(fan2_div, MATTR,
		show_fan_div, set_fan_div, SCND_INST, PCSM_RW_TIME_INTERVAL);
static SENSOR_DEVICE_ATTR_2(tach2_control, MATTR,
		show_pwm_byte, set_pwm_byte, SCND_INST, PCSM_MX_TACH_CTRL);

/* PWM */
static SENSOR_DEVICE_ATTR_2(pwm2, MATTR,
		show_pwm, set_pwm, SCND_INST, 0);
static SENSOR_DEVICE_ATTR_2(pwm2_mode, MATTR,
		show_pwm_byte, set_pwm_byte, SCND_INST, PCSM_RW_CONTROL);


/* ALERT */
static SENSOR_DEVICE_ATTR_2(alert2_control, MATTR,
		show_pwm_byte, set_pwm_byte, SCND_INST, PCSM_RW_ALERT_CTRL);
static SENSOR_DEVICE_ATTR_2(alert2_status, MATTR,
		show_pwm_byte, set_pwm_byte, SCND_INST, PCSM_RW_ALERT_STATUS);

/* AUTO POINTS */
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point1_temp, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT0_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point1_pwm, MATTR,
		show_pwm,  set_pwm, SCND_INST, PCSM_RW_LUT0_PWM);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point1_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT0_HYST);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point2_temp, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT1_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point2_pwm, MATTR,
		show_pwm,  set_pwm, SCND_INST, PCSM_RW_LUT1_PWM);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point2_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT1_HYST);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point3_temp, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT2_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point3_pwm, MATTR,
		show_pwm,  set_pwm, SCND_INST, PCSM_RW_LUT2_PWM);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point3_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT2_HYST);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point4_temp, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT3_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point4_pwm, MATTR,
		show_pwm,  set_pwm, SCND_INST, PCSM_RW_LUT3_PWM);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point4_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT3_HYST);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point5_temp, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT4_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point5_pwm, MATTR,
		show_pwm,  set_pwm, SCND_INST, PCSM_RW_LUT4_PWM);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point5_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT4_HYST);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point6_temp, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT5_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point6_pwm, MATTR,
		show_pwm,  set_pwm, SCND_INST, PCSM_RW_LUT5_PWM);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point6_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT5_HYST);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point7_temp, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT6_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point7_pwm, MATTR,
		show_pwm,  set_pwm, SCND_INST, PCSM_RW_LUT6_PWM);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point7_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT6_HYST);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point8_temp, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT7_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point8_pwm, MATTR,
		show_pwm,  set_pwm, SCND_INST, PCSM_RW_LUT7_PWM);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point8_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT7_HYST);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point9_temp, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT8_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point9_pwm, MATTR,
		show_pwm,  set_pwm, SCND_INST, PCSM_RW_LUT8_PWM);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point9_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT8_HYST);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point10_temp, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT9_TEMP);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point10_pwm, MATTR,
		show_pwm,  set_pwm, SCND_INST, PCSM_RW_LUT9_PWM);
static SENSOR_DEVICE_ATTR_2(pwm2_auto_point10_temp_hyst, MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST, PCSM_RW_LUT9_HYST);

static struct attribute *temp_attrs[] = {
	&sensor_dev_attr_temp1_input.dev_attr.attr,
	&sensor_dev_attr_temp2_input.dev_attr.attr,
	&sensor_dev_attr_temp3_input.dev_attr.attr,
	&sensor_dev_attr_temp4_input.dev_attr.attr,
	&sensor_dev_attr_temp5_input.dev_attr.attr,
	&sensor_dev_attr_temp1_label.dev_attr.attr,
	&sensor_dev_attr_temp2_label.dev_attr.attr,
	&sensor_dev_attr_temp3_label.dev_attr.attr,
	&sensor_dev_attr_temp4_label.dev_attr.attr,
	&sensor_dev_attr_temp5_label.dev_attr.attr,
	&dev_attr_temp7_input.attr,
	&sensor_dev_attr_temp7_label.dev_attr.attr,
	NULL
};

static const struct attribute_group temp_group = {
	.attrs = temp_attrs,
};


static struct attribute *temp_e16c_attrs[] = {
	&sensor_dev_attr_temp6_input.dev_attr.attr,
	&sensor_dev_attr_temp6_label.dev_attr.attr,
	NULL
};

static const struct attribute_group temp_e16c_group = {
	.attrs = temp_e16c_attrs,
};

static struct attribute *pcs_event_attrs[] = {
	&dev_attr_pcs_events.attr,
	&dev_attr_pcs_adjust_period.attr,
	NULL
};

static const struct attribute_group pcs_event_group = {
	.attrs = pcs_event_attrs,
};

static struct attribute *in_attrs[] = {
	&sensor_dev_attr_in1_input.dev_attr.attr,
	&sensor_dev_attr_in2_input.dev_attr.attr,
	&sensor_dev_attr_in3_input.dev_attr.attr,
	&sensor_dev_attr_in4_input.dev_attr.attr,
	&sensor_dev_attr_in5_input.dev_attr.attr,
	&sensor_dev_attr_in6_input.dev_attr.attr,
	&sensor_dev_attr_in1_label.dev_attr.attr,
	&sensor_dev_attr_in2_label.dev_attr.attr,
	&sensor_dev_attr_in3_label.dev_attr.attr,
	&sensor_dev_attr_in4_label.dev_attr.attr,
	&sensor_dev_attr_in5_label.dev_attr.attr,
	&sensor_dev_attr_in6_label.dev_attr.attr,
	&sensor_dev_attr_vcore_table.dev_attr.attr,
	&sensor_dev_attr_vcore_brief.dev_attr.attr,
	NULL
};

static const struct attribute_group in_group = {
    .attrs = in_attrs,
};

static struct attribute *pwm1_attrs[] = {
	&sensor_dev_attr_fan1_min.dev_attr.attr,
	&sensor_dev_attr_fan1_max.dev_attr.attr,
	&sensor_dev_attr_fan1_input.dev_attr.attr,
	&sensor_dev_attr_fan1_div.dev_attr.attr,
	&sensor_dev_attr_tach1_control.dev_attr.attr,
	&sensor_dev_attr_pwm1.dev_attr.attr,
	&sensor_dev_attr_pwm1_mode.dev_attr.attr,
	&sensor_dev_attr_alert1_control.dev_attr.attr,
	&sensor_dev_attr_alert1_status.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point1_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point1_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point1_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point2_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point2_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point2_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point3_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point3_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point3_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point4_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point4_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point4_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point5_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point5_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point5_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point6_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point6_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point6_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point7_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point7_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point7_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point8_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point8_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point8_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point9_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point9_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point9_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point10_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point10_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_auto_point10_temp_hyst.dev_attr.attr,
	NULL
};

static const struct attribute_group pwm1_group = {
	.attrs = pwm1_attrs,
};

static struct attribute *pwm2_attrs[] = {
	&sensor_dev_attr_fan2_min.dev_attr.attr,
	&sensor_dev_attr_fan2_max.dev_attr.attr,
	&sensor_dev_attr_fan2_input.dev_attr.attr,
	&sensor_dev_attr_fan2_div.dev_attr.attr,
	&sensor_dev_attr_tach2_control.dev_attr.attr,
	&sensor_dev_attr_pwm2.dev_attr.attr,
	&sensor_dev_attr_pwm2_mode.dev_attr.attr,
	&sensor_dev_attr_alert2_control.dev_attr.attr,
	&sensor_dev_attr_alert2_status.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point1_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point1_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point1_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point2_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point2_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point2_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point3_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point3_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point3_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point4_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point4_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point4_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point5_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point5_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point5_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point6_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point6_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point6_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point7_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point7_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point7_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point8_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point8_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point8_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point9_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point9_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point9_temp_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point10_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point10_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_auto_point10_temp_hyst.dev_attr.attr,
	NULL
};

static const struct attribute_group pwm2_group = {
	.attrs = pwm2_attrs,
};

static const struct attribute_group *pcsm_attr_groups[7];

#ifdef CONFIG_EPIC
static void do_pcsm_monitor(struct work_struct *work)
{
	int node;
	for_each_online_node(node) {
		sic_write_node_nbsr_reg(node,
			PCSM_BASE_ADDR + PMC_SYS_EVENTS_INT, ALL_EVENTS_MASK);
	}

	queue_delayed_work(system_power_efficient_wq, &pcsm_monitor,
			   msecs_to_jiffies(PCS_ADJUST_PERIOD));
}
#endif

static const struct pcs_handle handle = {
    .pcs_interrupt = pcsm_interrupt
};

static int pcsm_drv_probe(struct platform_device *pdev)
{
    int error = 0;
	int node = dev_to_node(&pdev->dev);
	struct pcsm_data *pcsm_drv;
	struct device *hwmon_dev;

	if (node < 0)
		node = 0;

	pcsm_drv = devm_kzalloc(&pdev->dev, sizeof(*pcsm_drv), GFP_KERNEL);
	if (!pcsm_drv)
		return -ENOMEM;

	pcsm_drv->pdev = pdev;
	pcsm_drv->node = node;

	hwmon_dev = hwmon_device_register_with_groups(&pdev->dev,
					KBUILD_MODNAME, pcsm_drv, pcsm_attr_groups);

	if (IS_ERR(hwmon_dev))
		return PTR_ERR(hwmon_dev);

	pcsm_drv->hdev = hwmon_dev;
	platform_set_drvdata(pdev, pcsm_drv);

#ifdef CONFIG_EPIC
	pcs_events_enable(node);

	if (pcsm_adjust_enable) {
		register_pcs_handle(&handle);

		INIT_DEFERRABLE_WORK(&pcsm_monitor, do_pcsm_monitor);

		queue_delayed_work(system_power_efficient_wq, &pcsm_monitor, 0);
	}
#endif

	return error;
} /* pcsm_drv_probe */

static int pcsm_drv_remove(struct platform_device *pdev)
{
	int error = 0;
	struct pcsm_data *pcsm_drv = platform_get_drvdata(pdev);

#ifdef CONFIG_EPIC
	if (pcsm_adjust_enable) {
		unregister_pcs_handle();
		cancel_delayed_work(&pcsm_monitor);
	}
#endif

	hwmon_device_unregister(pcsm_drv->hdev);
	return error;
} /* pcsm_drv_remove */

static struct platform_driver pcsm_drv_driver = {
	.probe = pcsm_drv_probe,
	.remove = pcsm_drv_remove,
	.driver = { .name = "pcsm_drv" }
};

static const struct platform_device_id pcsm_drv_id[] = {
	{ "pcsm_drv" },
	{}
};
MODULE_DEVICE_TABLE(platform, pcsm_drv_id);

static int pcsm_drv_init(void)
{
	if (!(IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C))
		return -ENODEV;

	int group = 0;

	if (IS_MACHINE_E16C) {
		vm_table_type = vm_table_e16c;
		ts_map = ts_e16c_map;
	} else if (IS_MACHINE_E12C) {
		vm_table_type = vm_table_e12c;
		ts_map = ts_e12c_map;
	} else if (IS_MACHINE_E2C3) {
		vm_table_type = vm_table_e2c3;
		ts_map = ts_e2c3_map;
	}

	pcsm_attr_groups[group++] = &temp_group;

	if (IS_MACHINE_E16C)
		pcsm_attr_groups[group++] = &temp_e16c_group;

	pcsm_attr_groups[group++] = &in_group;
	pcsm_attr_groups[group++] = &pwm1_group;
	pcsm_attr_groups[group++] = &pwm2_group;

#ifdef CONFIG_EPIC
	if (pcsm_adjust_enable)
		pcsm_attr_groups[group++] = &pcs_event_group;
#endif

	pcsm_attr_groups[group++] = NULL;

	return platform_driver_register(&pcsm_drv_driver);
} /* pcsm_drv_init */

static void pcsm_drv_exit(void)
{
	if (IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C)
		platform_driver_unregister(&pcsm_drv_driver);
} /* pcsm_drv_exit */

module_init(pcsm_drv_init);
module_exit(pcsm_drv_exit);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("Module for Power Control System. For E2C3, E12C, E16C");
MODULE_LICENSE("GPL v2");
