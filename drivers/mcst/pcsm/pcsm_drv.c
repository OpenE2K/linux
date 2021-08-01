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

#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>

#include "pcsm.h"

struct pcsm_data {
	struct device *hdev;
	int node;
};

int (*vm_table_type)[VM_MAX_SENSORS];

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
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);

    u8 instance = attr->index & 0x3;
    u8 addr = attr->index >> 8;

    u8 val = read_pwm_data(data->node, instance, addr);

    return snprintf(buf, PAGE_SIZE - 1, "%d\n", PWM_TO_PROCENT(val));
}

static ssize_t set_fan(struct device *dev,
	struct device_attribute *devattr,
	const char *buf, size_t count)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);
    unsigned long val;
    int err;

    u8 instance = attr->index & 0x3;
    u8 addr = attr->index >> 8;

    err = kstrtoul(buf, 10, &val);
    if (err) {
	return err;
    }

    val = clamp_val(PROCENT_TO_PWM(val), 0, 0x80);

    write_pwm_data(data->node, instance, addr, val);

    return count;
}

static int DIV_TO_REG(int val)
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
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);

    unsigned long val = read_pwm_data(data->node, attr->index & 0x3, PCSM_RW_TIME_INTERVAL);

    return snprintf(buf, PAGE_SIZE - 1, "%d\n", DIV_FROM_REG(val));
}

static ssize_t set_fan_div(struct device *dev,
	struct device_attribute *devattr,
	const char *buf, size_t count)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);
    unsigned long val;

    int err = kstrtoul(buf, 10, &val);
    if (err) {
	return err;
    }

    val = clamp_val(PROCENT_TO_PWM(val), 0, 0x80);

    write_pwm_data(data->node, attr->index & 0x3,
	    PCSM_RW_TIME_INTERVAL, DIV_TO_REG(val));

    return count;
}


static ssize_t show_pwm(struct device *dev,
	struct device_attribute *devattr,
	char *buf)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);

    u8 instance = attr->index & 0x3;

    u8 val = read_pwm_data(data->node, instance, PCSM_RW_PWM_CURRENT);

    return snprintf(buf, PAGE_SIZE - 1, "%d\n", PWM_TO_PROCENT(val));
}


static ssize_t set_pwm(struct device *dev,
	struct device_attribute *devattr,
	const char *buf, size_t count)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);
    unsigned long val;
    int err;

    u8 instance = attr->index & 0x3;

    err = kstrtoul(buf, 10, &val);
    if (err) {
	return err;
    }

    val = clamp_val(val, 0, 0x80);

    write_pwm_data(data->node, instance, PCSM_RW_PWM_FIXED, PROCENT_TO_PWM(val));

    return count;
}


static ssize_t show_pwm_byte(struct device *dev,
	struct device_attribute *devattr,
	char *buf)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);

    u8 addr = attr->index >> 8;
    u8 instance = attr->index & 0x3;

    u8 val = read_pwm_data(data->node, instance, addr);

    return snprintf(buf, PAGE_SIZE - 1, "0x%x\n", val);
}

static ssize_t set_pwm_byte(struct device *dev,
	struct device_attribute *devattr,
	const char *buf, size_t count)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);
    unsigned long val;
    int err;

    u8 addr = attr->index >> 8;
    u8 instance = attr->index & 0x3;

    err = kstrtoul(buf, 10, &val);
    if (err) {
	return err;
    }

    write_pwm_data(data->node, instance, addr, val);

    return count;
}

static ssize_t show_pwm_word(struct device *dev,
	struct device_attribute *devattr,
	char *buf)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);

    u8 addr = attr->index >> 8;
    u8 instance = attr->index & 0x3;

    u8 val_lo = read_pwm_data(data->node, instance, addr);
    u8 val_hi = read_pwm_data(data->node, instance, addr + 1);

    return snprintf(buf, PAGE_SIZE - 1, "0x%x\n", val_lo + (val_hi << 8));
}

static ssize_t set_pwm_word(struct device *dev,
	struct device_attribute *devattr,
	const char *buf, size_t count)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);
    unsigned long val;
    int err;

    u8 addr = attr->index >> 8;
    u8 instance = attr->index & 0x3;

    err = kstrtoul(buf, 10, &val);
    if (err) {
	return err;
    }

    u8 val_lo = val & 0xff;
    u8 val_hi = (val >> 8) & 0xff;

    write_pwm_data(data->node, instance, addr, val_lo);
    write_pwm_data(data->node, instance, addr + 1, val_hi);

    return count;
}

static ssize_t pwm_show_temp(struct device *dev,
	struct device_attribute *devattr,
	char *buf)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);

    u8 addr = attr->index >> 8;
    u8 instance = attr->index & 0x3;
    u8 temp = read_pwm_data(data->node, instance, addr);

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
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);

    unsigned long value;

    u8 addr = attr->index >> 8;
    u8 instance = attr->index & 0x3;
    u8 temp;

    int err = kstrtoul(buf, 10, &value);
    if (err) {
	return err;
    }

    value = clamp_val(value, 0, 128000);
    temp = value % 1000 ? 1 : 0;
    value = value / 1000;
    temp += value*2;

    write_pwm_data(data->node, instance, addr, temp);

    return count;
}

#define TEMP_TO_HWMON(v) (((v)/8)* 1000 + (((v) & 0x7) * 125))

static ssize_t pmc_show_temp(struct device *dev,
	struct device_attribute *devattr,
	char *buf)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
    struct pcsm_data *data = dev_get_drvdata(dev);

    int addr = attr->index;

    term_ts_regs_t regs = { .word = sic_read_node_nbsr_reg(data->node,
	    PCSM_BASE_ADDR + addr) };

    return snprintf(buf, PAGE_SIZE - 1, "0x%x\n", TEMP_TO_HWMON(regs.temp));
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
    int (*vm_table_type)[VM_MAX_SENSORS] = vm_table_e16c;
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
    [VM1] = "average Vcore",
    [VM2] = "min     Vcore",
    [VM3] = "max     Vcore",
    [VM4] = "average Vddr",
    [VM5] = "min     Vddr",
    [VM6] = "max     Vddr",
};

static ssize_t in_label_show(struct device *dev,
	struct device_attribute *devattr,
	char *buf)
{
    struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);

    return sprintf(buf, "%s\n", input_names[attr->index]);
}

#define MATTR (S_IWUSR | S_IRUGO)

/* TEMP */
static SENSOR_DEVICE_ATTR(temp1_input, MATTR,
		pmc_show_temp, NULL, PMC_TERM_TS0);
static SENSOR_DEVICE_ATTR(temp2_input, MATTR,
		pmc_show_temp, NULL, PMC_TERM_TS1);
static SENSOR_DEVICE_ATTR(temp3_input, MATTR,
		pmc_show_temp, NULL, PMC_TERM_TS2);
static SENSOR_DEVICE_ATTR(temp4_input, MATTR,
		pmc_show_temp, NULL, PMC_TERM_TS3);
static SENSOR_DEVICE_ATTR(temp5_input, MATTR,
		pmc_show_temp, NULL, PMC_TERM_TS4);

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

static SENSOR_DEVICE_ATTR_RO(in1_label, in_label, VM1);
static SENSOR_DEVICE_ATTR_RO(in2_label, in_label, VM2);
static SENSOR_DEVICE_ATTR_RO(in3_label, in_label, VM3);
static SENSOR_DEVICE_ATTR_RO(in4_label, in_label, VM4);
static SENSOR_DEVICE_ATTR_RO(in5_label, in_label, VM5);
static SENSOR_DEVICE_ATTR_RO(in6_label, in_label, VM6);

/* FIRST INSTANCE */
/* FAN */
static SENSOR_DEVICE_ATTR(fan1_min, MATTR,
		show_fan, set_fan, FRST_INST + (PCSM_RW_PWM_MIN << 8));
static SENSOR_DEVICE_ATTR(fan1_max, MATTR,
		show_fan, set_fan, FRST_INST + (PCSM_RW_PWM_MAX << 8));
static SENSOR_DEVICE_ATTR(fan1_input, MATTR,
		show_fan, NULL, FRST_INST + (PCSM_RW_PWM_CURRENT << 8));
static SENSOR_DEVICE_ATTR(fan1_div, MATTR,
		show_fan_div, set_fan_div, FRST_INST + (PCSM_RW_TIME_INTERVAL << 8));
static SENSOR_DEVICE_ATTR(fan1_target, MATTR,
		NULL, set_fan, FRST_INST);

/* PWM */
static SENSOR_DEVICE_ATTR(pwm1, MATTR,
		show_pwm, set_pwm, FRST_INST);
static SENSOR_DEVICE_ATTR(pwm1_mode, MATTR,
		show_pwm_byte, set_pwm_byte, FRST_INST + (PCSM_RW_CONTROL << 8));

/* TACH */
static SENSOR_DEVICE_ATTR(tach1_cnt, MATTR,
		show_pwm_word, set_pwm_word, FRST_INST + (PCSM_RO_TACH_LO << 8));
static SENSOR_DEVICE_ATTR(tach1_control, MATTR,
		show_pwm_byte, set_pwm_byte, FRST_INST + (PCSM_MX_TACH_CTRL << 8));
static SENSOR_DEVICE_ATTR(tach1_min, MATTR,
		show_pwm_word, set_pwm_word, FRST_INST + (PCSM_RW_TACH_MIN_LO << 8));
static SENSOR_DEVICE_ATTR(tach1_max, MATTR,
		show_pwm_word, set_pwm_word, FRST_INST + (PCSM_RW_TACH_MAX_LO << 8));

/* ALERT */
static SENSOR_DEVICE_ATTR(alert1_control, MATTR,
		show_pwm_byte, set_pwm_byte, FRST_INST + (PCSM_RW_ALERT_CTRL << 8));
static SENSOR_DEVICE_ATTR(alert1_status, MATTR,
		show_pwm_byte, NULL, FRST_INST + (PCSM_RW_ALERT_STATUS << 8));

/* AUTO POINTS */
static SENSOR_DEVICE_ATTR(pwm1_auto_point1_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT0_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point1_pwm,  MATTR,
		show_fan,  set_fan,  FRST_INST + (PCSM_RW_LUT0_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point1_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT0_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point2_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT1_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point2_pwm,  MATTR,
		show_fan,  set_fan,  FRST_INST + (PCSM_RW_LUT1_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point2_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT1_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point3_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT2_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point3_pwm,  MATTR,
		show_fan,  set_fan,  FRST_INST + (PCSM_RW_LUT2_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point3_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT2_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point4_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT3_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point4_pwm,  MATTR,
		show_fan,  set_fan,  FRST_INST + (PCSM_RW_LUT3_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point4_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT3_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point5_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT4_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point5_pwm,  MATTR,
		show_fan,  set_fan,  FRST_INST + (PCSM_RW_LUT4_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point5_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT4_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point6_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT5_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point6_pwm,  MATTR,
		show_fan,  set_fan,  FRST_INST + (PCSM_RW_LUT5_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point6_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT5_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point7_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT6_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point7_pwm,  MATTR,
		show_fan,  set_fan,  FRST_INST + (PCSM_RW_LUT6_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point7_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT6_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point8_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT7_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point8_pwm,  MATTR,
		show_fan,  set_fan,  FRST_INST + (PCSM_RW_LUT7_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point8_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT7_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point9_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT8_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point9_pwm,  MATTR,
		show_fan,  set_fan,  FRST_INST + (PCSM_RW_LUT8_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point9_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT8_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point10_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT9_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point10_pwm,  MATTR,
		show_fan,  set_fan,  FRST_INST + (PCSM_RW_LUT9_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm1_auto_point10_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, FRST_INST + (PCSM_RW_LUT9_HYST << 8));

/* SECOND INSTANCE */
/* FAN */
static SENSOR_DEVICE_ATTR(fan2_min, MATTR,
		show_fan, set_fan, SCND_INST + (PCSM_RW_PWM_MIN << 8));
static SENSOR_DEVICE_ATTR(fan2_max, MATTR,
		show_fan, set_fan, SCND_INST + (PCSM_RW_PWM_MAX << 8));
static SENSOR_DEVICE_ATTR(fan2_input, MATTR,
		show_fan, NULL, SCND_INST + (PCSM_RW_PWM_CURRENT << 8));
static SENSOR_DEVICE_ATTR(fan2_div, MATTR,
		show_fan_div, set_fan_div, SCND_INST + (PCSM_RW_TIME_INTERVAL << 8));
static SENSOR_DEVICE_ATTR(fan2_target, MATTR,
		NULL, set_fan, SCND_INST);

/* PWM */
static SENSOR_DEVICE_ATTR(pwm2, MATTR,
		show_pwm, set_pwm, SCND_INST);
static SENSOR_DEVICE_ATTR(pwm2_mode, MATTR,
		show_pwm_byte, set_pwm_byte, SCND_INST + (PCSM_RW_CONTROL << 8));

/* TACH */
static SENSOR_DEVICE_ATTR(tach2_cnt, MATTR,
		show_pwm_word, set_pwm_word, SCND_INST + (PCSM_RO_TACH_LO << 8));
static SENSOR_DEVICE_ATTR(tach2_control, MATTR,
		show_pwm_byte, set_pwm_byte, SCND_INST + (PCSM_MX_TACH_CTRL << 8));
static SENSOR_DEVICE_ATTR(tach2_min, MATTR,
		show_pwm_word, set_pwm_word, SCND_INST + (PCSM_RW_TACH_MIN_LO << 8));
static SENSOR_DEVICE_ATTR(tach2_max, MATTR,
		show_pwm_word, set_pwm_word, SCND_INST + (PCSM_RW_TACH_MAX_LO << 8));

/* ALERT */
static SENSOR_DEVICE_ATTR(alert2_control, MATTR,
		show_pwm_byte, set_pwm_byte, SCND_INST + (PCSM_RW_ALERT_CTRL << 8));
static SENSOR_DEVICE_ATTR(alert2_status, MATTR,
		show_pwm_byte, NULL, SCND_INST + (PCSM_RW_ALERT_STATUS << 8));

/* AUTO POINTS */
static SENSOR_DEVICE_ATTR(pwm2_auto_point1_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT0_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point1_pwm,  MATTR,
		show_fan,  set_fan,  SCND_INST + (PCSM_RW_LUT0_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point1_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT0_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point2_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT1_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point2_pwm,  MATTR,
		show_fan,  set_fan,  SCND_INST + (PCSM_RW_LUT1_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point2_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT1_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point3_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT2_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point3_pwm,  MATTR,
		show_fan,  set_fan,  SCND_INST + (PCSM_RW_LUT2_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point3_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT2_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point4_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT3_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point4_pwm,  MATTR,
		show_fan,  set_fan,  SCND_INST + (PCSM_RW_LUT3_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point4_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT3_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point5_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT4_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point5_pwm,  MATTR,
		show_fan,  set_fan,  SCND_INST + (PCSM_RW_LUT4_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point5_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT4_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point6_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT5_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point6_pwm,  MATTR,
		show_fan,  set_fan,  SCND_INST + (PCSM_RW_LUT5_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point6_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT5_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point7_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT6_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point7_pwm,  MATTR,
		show_fan,  set_fan,  SCND_INST + (PCSM_RW_LUT6_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point7_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT6_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point8_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT7_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point8_pwm,  MATTR,
		show_fan,  set_fan,  SCND_INST + (PCSM_RW_LUT7_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point8_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT7_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point9_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT8_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point9_pwm,  MATTR,
		show_fan,  set_fan,  SCND_INST + (PCSM_RW_LUT8_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point9_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT8_HYST << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point10_temp,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT9_TEMP << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point10_pwm,  MATTR,
		show_fan,  set_fan,  SCND_INST + (PCSM_RW_LUT9_PWM  << 8));
static SENSOR_DEVICE_ATTR(pwm2_auto_point10_temp_hyst,  MATTR,
		pwm_show_temp, pwm_set_temp, SCND_INST + (PCSM_RW_LUT9_HYST << 8));

static struct attribute *temp_attrs[] = {
	&sensor_dev_attr_temp1_input.dev_attr.attr,
	&sensor_dev_attr_temp2_input.dev_attr.attr,
	&sensor_dev_attr_temp3_input.dev_attr.attr,
	&sensor_dev_attr_temp4_input.dev_attr.attr,
	&sensor_dev_attr_temp5_input.dev_attr.attr,
	NULL
};

static const struct attribute_group temp_group = {
	.attrs = temp_attrs,
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
	&sensor_dev_attr_fan1_target.dev_attr.attr,
	&sensor_dev_attr_pwm1.dev_attr.attr,
	&sensor_dev_attr_pwm1_mode.dev_attr.attr,
	&sensor_dev_attr_tach1_cnt.dev_attr.attr,
	&sensor_dev_attr_tach1_control.dev_attr.attr,
	&sensor_dev_attr_tach1_min.dev_attr.attr,
	&sensor_dev_attr_tach1_max.dev_attr.attr,
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
	&sensor_dev_attr_fan2_target.dev_attr.attr,
	&sensor_dev_attr_pwm2.dev_attr.attr,
	&sensor_dev_attr_pwm2_mode.dev_attr.attr,
	&sensor_dev_attr_tach2_cnt.dev_attr.attr,
	&sensor_dev_attr_tach2_control.dev_attr.attr,
	&sensor_dev_attr_tach2_min.dev_attr.attr,
	&sensor_dev_attr_tach2_max.dev_attr.attr,
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

static const struct attribute_group *pcsm_attr_groups[5];

#define	MAX_NODE	4

struct device *hwmon_dev[MAX_NODE];

static int __init pcsm_probe(void)
{
    int node;
    struct pcsm_data *pcsm;
    struct device *dev = cpu_subsys.dev_root;
    int group = 0;

    if (IS_MACHINE_E16C) {
	vm_table_type = vm_table_e16c;
    } else if (IS_MACHINE_E12C) {
	vm_table_type = vm_table_e12c;
    } else if (IS_MACHINE_E2C3) {
	vm_table_type = vm_table_e2c3;
    }

    if (IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C) {
	pcsm_attr_groups[group++] = &temp_group;
	pcsm_attr_groups[group++] = &in_group;
	pcsm_attr_groups[group++] = &pwm1_group;

	if (IS_MACHINE_E12C || IS_MACHINE_E16C) {
	    pcsm_attr_groups[group++] = &pwm2_group;
	}

	pcsm_attr_groups[group++] = NULL;

	for_each_online_node(node) {
	    pcsm = devm_kzalloc(dev, sizeof(*pcsm), GFP_KERNEL);
	    if (!pcsm)
		return -ENOMEM;
	    pcsm->node = node;

	    hwmon_dev[node] = devm_hwmon_device_register_with_groups(dev,
		    KBUILD_MODNAME,
		    pcsm,
		    pcsm_attr_groups);
	    if (IS_ERR(hwmon_dev))
		return PTR_ERR(hwmon_dev);

	    pcsm->hdev = hwmon_dev[node];
	}
    }

    return 0;
} /* pcsm_probe */

static void __exit pcsm_remove(void)
{
    if (IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C) {
	int node;

	for_each_online_node(node) {
	    sysfs_remove_groups(&hwmon_dev[node]->kobj, pcsm_attr_groups);
	    hwmon_device_unregister(hwmon_dev[node]);
	}
    }
}

MODULE_AUTHOR("Arseniy.A.Demidov@mcst.ru");
MODULE_DESCRIPTION("Module for Power Control System");
MODULE_LICENSE("GPL v2");

module_init(pcsm_probe);
module_exit(pcsm_remove);
