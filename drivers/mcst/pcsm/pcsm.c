/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Power Control System (PCS)
 * hwmon, pwm, pcs module
 */

/*#define DEBUG*/
/* echo 8 > /proc/sys/kernel/printk */

#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/hwmon-sysfs.h>
#include <linux/hwmon.h>
#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/node.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/power_supply.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <asm/cpu_regs_types.h>
#include <asm/bootinfo.h>

#ifndef MODULE
#undef CONFIG_DEBUG_FS
#endif
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif

#define DRIVER_VERSION		"0.9"

/*---------------------------------------------------------------------------*/

/* PCSM registers */

/* fan and hwmon chapter for externel manager */

/* offset for devices
 * in each control - two identical device */
#define PCSM_ONE_OFFSET			0x00
#define PCSM_TWO_OFFSET			0x40

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

#define PCSM_MIXED_START (PCSM_RO_TACH_LO)
#define PCSM_MIXED_COUNT (PCSM_RW_ALERT_STATUS - PCSM_RO_TACH_LO + 1)

/* PMC i2c chapter */

/* offset for i2c */
#define PMCM_OFFSET			0x80

#define PMCM_RO_INFO_LO			0x00
#define PMCM_RO_INFO_HI			0x01
#define PMCM_RO_TERM			0x02
#define PMCM_RW_FORCEPR			0x03
#define PMCM_RW_CFG_LO			0x04
#define PMCM_RW_CFG_HI			0x05
#define PMCM_RO_CFG_DAT0		0x06
#define PMCM_RO_CFG_DAT1		0x07
#define PMCM_RO_CFG_DAT2		0x08
#define PMCM_RO_CFG_DAT3		0x09
#define PMCM_RO_MON_0			0x0a
#define PMCM_RWC_HIST_0			0x0b
#define PMCM_RO_MON_1			0x0c
#define PMCM_RWC_HIST_1			0x0d
#define PMCM_RO_MON_2			0x0e
#define PMCM_RWC_HIST_2			0x0f

#define PMCM_REG_END (PMCM_RWC_HIST_2)
#define PMCM_REG_CNT (PMCM_REG_END + 1)

#define PCSM_REG_END (PCSM_RW_ALERT_STATUS)
#define PCSM_REG_CNT (PCSM_REG_END + 1)

#define PCSM0_REG(v) (v + PCSM_ONE_OFFSET)
#define PCSM1_REG(v) (v + PCSM_TWO_OFFSET)
#define PMCM_REG(v) (v + PMCM_OFFSET)

/** PCSM specific bitfields */

/* max value for pwm and temp registers */
#define PCSM_THERM_MAX			0xFF
#define PCSM_PWM_MAX			0x80

#define PCSM_LUT_COUNT			10

#define MANUFACTURER_ID_LO		0xC3
#define MANUFACTURER_ID_HI		0xE2

/*---------------------------------------------------------------------------*/

enum events { ecc_id = 1, main_id, therm_id };

struct event_data {
	u8 id;
	u8 monitor;
	u8 monitor_st;
	u8 event;
	u8 event_st;
	u8 table_size;
	const char **names;
};

/* Client data (each client gets its own) */
struct pcsm_data {
	struct i2c_client *client;
	struct mutex update_lock;
	struct mutex core_lock;

	u32 core_address;
	u8  use_rcn;

	unsigned long last_updated, rate;	/* in jiffies */
	char valid;				/* zero until following
						   fields are valid */

	/* registers values */
	u8 model;				/* model CPU */
	u8 revision;				/* revision CPU */
	u8 temp, temp_st;			/* hwmon pmcm temp*/
	struct event_data ecc;			/* events ecc for pmcm */
	struct event_data main;			/* events main for pmcm */
	struct event_data therm;		/* events therm for pmcm */
	u8 pwm[2], pwm_st[2];			/* hwmon fixed pwm */
	u8 pwm_ct[2][2], pwm_ct_st[2][2];	/* hwmon for control[*][0]
						   and smooth[*][1] */

	u8 temp_lut[2][PCSM_LUT_COUNT];		/* hwmon lut temp*/
	u8 temp_lut_st[2][PCSM_LUT_COUNT];	/* hwmon lut temp store */
	u8 pwm_lut[2][PCSM_LUT_COUNT];		/* hwmon lut pwm */
	u8 pwm_lut_st[2][PCSM_LUT_COUNT];	/* hwmon lut pwm store */
	u8 hyst_lut[2][PCSM_LUT_COUNT];		/* hwmon lut hyst */
	u8 hyst_lut_st[2][PCSM_LUT_COUNT];	/* hwmon lut hyst store */

	u8 mixed[2][PCSM_MIXED_COUNT];		/* save all regs */
	u8 mixed_st[2][PCSM_MIXED_COUNT];	/*   from PCSM_RO_TACH_LO */
						/*   to PCSM_RW_ALERT_STATUS */

#ifdef CONFIG_DEBUG_FS
	struct dentry *pcsm_dbg;
#endif
};

static s32 pcsm_read_byte(struct i2c_client *client, u8 command)
{
	return i2c_smbus_read_byte_data(client, command);
} /* pcsm_read_byte */

#define PCSM_UPDATE_FLAGS(REG, VAL, VAL_ST)			\
	do {							\
		data->VAL_ST = pcsm_read_byte(client, (REG));	\
		if (data->VAL_ST < 0)				\
			data->VAL = 0;				\
		else						\
			data->VAL = data->VAL_ST;		\
} while (0)

#define PCSM_UPDATE_VAL(REG, VAL, VAL_ST, MAX)			\
	do {							\
		data->VAL_ST = pcsm_read_byte(client, (REG));	\
		if (data->VAL_ST > MAX)				\
			data->VAL = (MAX);			\
		else						\
			data->VAL = data->VAL_ST;		\
} while (0)

#ifdef DEBUG

static void dump_all_regs(struct pcsm_data *data)
{
	int i, k, z;
	s32 val;
	struct i2c_client *client = data->client;

	dev_info(&client->dev, "first controller\n");
	mutex_lock(&data->update_lock);
	for (k = 0; k < 3; k++) {
		dev_info(&client->dev, "-- %d part of regs -----\n", k);
		for (i = PCSM_RO_ID_LO; i <= PCSM_REG_END; i++) {
			if (k == 2 && i > PMCM_REG_END) {
				/* only for third< PMC part */
				break;
			}
			z = i + k * 0x40;
			val = pcsm_read_byte(client, z);
			if (val < 0) {
				dev_err(&client->dev,
					"pcsm: reg[%02d] - read_error (%d)\n",
					z, val);
			} else {
				dev_info(&client->dev,
					 "pcsm: reg[%02d 0x%02x] = 0x%02x (%u)\n",
					 z, z, (u8)val, (u8)val);
			}
		}
	}
	mutex_unlock(&data->update_lock);
} /* dump_all_regs */

#endif /* DEBUG */

static void pcsm_update_data(struct pcsm_data *data)
{
	struct i2c_client *client = data->client;
	int i;

	if (!client) {
		return;
	}

	mutex_lock(&data->update_lock);

	if (time_after(jiffies, data->last_updated + data->rate) ||
	    !data->valid) {

		/* read and save all regs */

		PCSM_UPDATE_VAL(PMCM_REG(PMCM_RO_TERM),
				temp, temp_st,
				PCSM_THERM_MAX);

		PCSM_UPDATE_VAL(PMCM_REG(PMCM_RO_MON_0),
				ecc.monitor,
				ecc.monitor_st,
				0xff);
		PCSM_UPDATE_VAL(PMCM_REG(PMCM_RWC_HIST_0),
				ecc.event,
				ecc.event_st,
				0xff);

		PCSM_UPDATE_VAL(PMCM_REG(PMCM_RO_MON_1),
				main.monitor,
				main.monitor_st,
				0xff);
		PCSM_UPDATE_VAL(PMCM_REG(PMCM_RWC_HIST_1),
				main.event,
				main.event_st,
				0xff);

		PCSM_UPDATE_VAL(PMCM_REG(PMCM_RO_MON_2),
				therm.monitor,
				therm.monitor_st,
				0xff);
		PCSM_UPDATE_VAL(PMCM_REG(PMCM_RWC_HIST_2),
				therm.event,
				therm.event_st,
				0xff);

		PCSM_UPDATE_VAL(PCSM0_REG(PCSM_RW_PWM_CURRENT),
				pwm[0], pwm_st[0],
				PCSM_PWM_MAX);
		PCSM_UPDATE_VAL(PCSM1_REG(PCSM_RW_PWM_CURRENT),
				pwm[1], pwm_st[1],
				PCSM_PWM_MAX);

		PCSM_UPDATE_VAL(PCSM0_REG(PCSM_RW_CONTROL),
				pwm_ct[0][0], pwm_ct_st[0][0],
				0xff);
		PCSM_UPDATE_VAL(PCSM1_REG(PCSM_RW_CONTROL),
				pwm_ct[1][0], pwm_ct_st[1][0],
				0xff);
		PCSM_UPDATE_VAL(PCSM0_REG(PCSM_RW_TIME_INTERVAL),
				pwm_ct[0][1], pwm_ct_st[0][1],
				0xff);
		PCSM_UPDATE_VAL(PCSM1_REG(PCSM_RW_TIME_INTERVAL),
				pwm_ct[1][1], pwm_ct_st[1][1],
				0xff);

		for (i = 0; i < PCSM_MIXED_COUNT; i++) {
			PCSM_UPDATE_VAL(PCSM0_REG(PCSM_RO_TACH_LO + i),
					mixed[0][i], mixed_st[0][i],
					PCSM_PWM_MAX);
			PCSM_UPDATE_VAL(PCSM1_REG(PCSM_RO_TACH_LO + i),
					mixed[1][i], mixed_st[1][i],
					PCSM_PWM_MAX);
		}

		for (i = 0; i < PCSM_LUT_COUNT; i++) {
			PCSM_UPDATE_VAL(PCSM_RW_LUT0_TEMP + i*3, temp_lut[0][i],
					temp_lut_st[0][i], PCSM_THERM_MAX);
			PCSM_UPDATE_VAL(PCSM_RW_LUT0_PWM + i*3, pwm_lut[0][i],
					pwm_lut_st[0][i], PCSM_PWM_MAX);
			PCSM_UPDATE_VAL(PCSM_RW_LUT0_HYST + i*3, hyst_lut[0][i],
					hyst_lut_st[0][i], PCSM_THERM_MAX);

			PCSM_UPDATE_VAL(PCSM1_REG(PCSM_RW_LUT0_TEMP + i*3),
					temp_lut[1][i], temp_lut_st[1][i],
					PCSM_THERM_MAX);
			PCSM_UPDATE_VAL(PCSM1_REG(PCSM_RW_LUT0_PWM + i*3),
					pwm_lut[1][i], pwm_lut_st[1][i],
					PCSM_PWM_MAX);
			PCSM_UPDATE_VAL(PCSM1_REG(PCSM_RW_LUT0_HYST + i*3),
					hyst_lut[1][i], hyst_lut_st[1][i],
					PCSM_THERM_MAX);
		}

		/* update status */
		data->last_updated = jiffies;
		data->valid = 1;
	}

	mutex_unlock(&data->update_lock);
} /* pcsm_update_data */

/*---------------------------------------------------------------------------*/
/* Debugfs part                                                              */
/* Usage: mount -t debugfs none /sys/kernel/debug                            */
/*---------------------------------------------------------------------------*/

#ifdef CONFIG_DEBUG_FS

static const char *pcsm_dbg_regs_name[PCSM_REG_CNT] = {
	"PCSM_RO_ID_LO",
	"PCSM_RO_ID_HI",
	"PCSM_RW_CONTROL",
	"PCSM_RW_PWM_FIXED",
	"PCSM_RW_PWM_CURRENT",
	"PCSM_RW_TIME_INTERVAL",
	"PCSM_RW_LUT0_TEMP",
	"PCSM_RW_LUT0_PWM",
	"PCSM_RW_LUT0_HYST",
	"PCSM_RW_LUT1_TEMP",
	"PCSM_RW_LUT1_PWM",
	"PCSM_RW_LUT1_HYST",
	"PCSM_RW_LUT2_TEMP",
	"PCSM_RW_LUT2_PWM",
	"PCSM_RW_LUT2_HYST",
	"PCSM_RW_LUT3_TEMP",
	"PCSM_RW_LUT3_PWM",
	"PCSM_RW_LUT3_HYST",
	"PCSM_RW_LUT4_TEMP",
	"PCSM_RW_LUT4_PWM",
	"PCSM_RW_LUT4_HYST",
	"PCSM_RW_LUT5_TEMP",
	"PCSM_RW_LUT5_PWM",
	"PCSM_RW_LUT5_HYST",
	"PCSM_RW_LUT6_TEMP",
	"PCSM_RW_LUT6_PWM",
	"PCSM_RW_LUT6_HYST",
	"PCSM_RW_LUT7_TEMP",
	"PCSM_RW_LUT7_PWM",
	"PCSM_RW_LUT7_HYST",
	"PCSM_RW_LUT8_TEMP",
	"PCSM_RW_LUT8_PWM",
	"PCSM_RW_LUT8_HYST",
	"PCSM_RW_LUT9_TEMP",
	"PCSM_RW_LUT9_PWM",
	"PCSM_RW_LUT9_HYST",
	"PCSM_RO_TACH_LO",
	"PCSM_RO_TACH_HI",
	"PCSM_MX_TACH_CTRL",
	"PCSM_RW_ALERT_CTRL",
	"PCSM_RW_PWM_MIN",
	"PCSM_RW_PWM_MAX",
	"PCSM_RW_TACH_MIN_LO",
	"PCSM_RW_TACH_MIN_HI",
	"PCSM_RW_TACH_MAX_LO",
	"PCSM_RW_TACH_MAX_HI",
	"PCSM_RW_ALERT_STATUS",
};

static char pcsm_dbg_regs_buf[PAGE_SIZE] = "";
static char pcsm_dbg_core_buf[PAGE_SIZE] = "";

static const char *pmcm_dbg_regs_name[PMCM_REG_CNT] = {
	"PMCM_RO_INFO_LO",
	"PMCM_RO_INFO_HI",
	"PMCM_RO_TERM",
	"PMCM_RW_FORCEPR",
	"PMCM_RW_CFG_LO",
	"PMCM_RW_CFG_HI",
	"PMCM_RO_CFG_DAT0",
	"PMCM_RO_CFG_DAT1",
	"PMCM_RO_CFG_DAT2",
	"PMCM_RO_CFG_DAT3",
	"PMCM_RO_MON_0",
	"PMCM_RWC_HIST_0",
	"PMCM_RO_MON_1",
	"PMCM_RWC_HIST_1",
	"PMCM_RO_MON_2",
	"PMCM_RWC_HIST_2",
};

/**
 * pcsm_dbg_regs_read - read for regs datum
 * @filp: the opened file
 * @buffer: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 **/
static ssize_t pcsm_dbg_regs_read(struct file *filp, char __user *buffer,
				  size_t count, loff_t *ppos,
				  int end, int off,
				  const char **table_name)
{
	int i = 0, r = 0;
	s32 val;
	char *buf = pcsm_dbg_regs_buf;
	int offs = 0;
	struct pcsm_data *data = filp->private_data;
	struct i2c_client *client = data->client;
	struct i2c_adapter *adapter = client->adapter;

	/* don't allow partial reads */
	if (*ppos != 0) {
		return 0;
	}

	mutex_lock(&data->update_lock);
	for (i = 0; i < end; i++) {
		r = i + off;
		val = pcsm_read_byte(client, r);
		if (val < 0) {
			dev_err(&adapter->dev,
				"reg[%02d] - read_error (%d)\n",
				r, val);
		} else {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "reg[0x%02x] = 0x%02x (%5u) - %s\n",
					  r, (u8)val, (u8)val,
					  table_name[i]);
		}
	}
	mutex_unlock(&data->update_lock);

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	return simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));
} /* pcsm_dbg_regs_read */

static ssize_t pcsm_dbg_regs_fan0_read(struct file *filp, char __user *buffer,
				       size_t count, loff_t *ppos)
{
	return pcsm_dbg_regs_read(filp, buffer, count, ppos,
				  PCSM_REG_CNT, PCSM_ONE_OFFSET,
				  pcsm_dbg_regs_name);
}

static ssize_t pcsm_dbg_regs_fan1_read(struct file *filp, char __user *buffer,
				       size_t count, loff_t *ppos)
{
	return pcsm_dbg_regs_read(filp, buffer, count, ppos,
				  PCSM_REG_CNT, PCSM_TWO_OFFSET,
				  pcsm_dbg_regs_name);
}

static ssize_t pcsm_dbg_regs_pmcm_read(struct file *filp, char __user *buffer,
				       size_t count, loff_t *ppos)
{
	return pcsm_dbg_regs_read(filp, buffer, count, ppos,
				  PMCM_REG_CNT, PMCM_OFFSET,
				  pmcm_dbg_regs_name);
}

static ssize_t pcsm_dbg_core_address_read(struct file *filp,
					  char __user *buffer,
					  size_t count, loff_t *ppos)
{
	struct pcsm_data *data = filp->private_data;
	char *buf = pcsm_dbg_core_buf;
	int offs = 0;
	mutex_lock(&data->core_lock);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "0x%x\n", data->core_address);
	mutex_unlock(&data->core_lock);
	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	return simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));
}

#define CORE_STR_MAX_SIZE 256

static ssize_t pcsm_dbg_core_address_write(struct file *filp,
					   const char __user *buffer,
					   size_t count, loff_t *ppos)
{
	struct pcsm_data *data = filp->private_data;
	struct i2c_adapter *adapter = data->client->adapter;
	char core_buffer[CORE_STR_MAX_SIZE];
	int  ret;
	u32  addr;

	memset(core_buffer, 0, sizeof(char) * CORE_STR_MAX_SIZE);
	if (count > CORE_STR_MAX_SIZE - 1) {
		ret = -EINVAL;
	} else if (copy_from_user(core_buffer, buffer, count)) {
		ret = -EFAULT;
	} else {
		ret = sscanf(core_buffer, "0x%X\n", &addr);
		if (ret != 1) {
			dev_err(&adapter->dev,
				"Failed to write address (invalid string).\n");
			ret = -EINVAL;
		} else {
			mutex_lock(&data->core_lock);
			data->core_address = addr;
			mutex_unlock(&data->core_lock);
			ret = count;
		}
	}

	return ret;
}

static ssize_t pcsm_dbg_use_rcn_read(struct file *filp,
				     char __user *buffer,
				     size_t count, loff_t *ppos)
{
	struct pcsm_data *data = filp->private_data;
	char *buf = pcsm_dbg_core_buf;
	int offs = 0;

	mutex_lock(&data->core_lock);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "%d\n", data->use_rcn);
	mutex_unlock(&data->core_lock);
	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	return simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));
}

static ssize_t pcsm_dbg_use_rcn_write(struct file *filp,
				      const char __user *buffer,
				      size_t count, loff_t *ppos)
{
	struct pcsm_data *data = filp->private_data;
	struct i2c_adapter *adapter = data->client->adapter;
	char input[CORE_STR_MAX_SIZE];
	int  ret;
	u32  value;

	memset(input, 0, sizeof(char) * CORE_STR_MAX_SIZE);
	if (count > CORE_STR_MAX_SIZE - 1) {
		ret = -EINVAL;
	} else if (copy_from_user(input, buffer, count)) {
		ret = -EFAULT;
	} else {
		ret = sscanf(input, "%d\n", &value);
		if (ret != 1) {
			dev_err(&adapter->dev,
				"Failed to write value (invalid string).\n");
			ret = -EINVAL;
		} else {
			mutex_lock(&data->core_lock);
			data->use_rcn = (value > 0) ? 1 : 0;
			mutex_unlock(&data->core_lock);
			ret = count;
		}
	}

	return ret;
}

static ssize_t pcsm_dbg_forcepr_read(struct file *filp,
				     char __user *buffer,
				     size_t count, loff_t *ppos)
{
	struct pcsm_data *data = filp->private_data;
	struct i2c_client *client = data->client;
	struct i2c_adapter *adapter = client->adapter;
	char *buf = pcsm_dbg_core_buf;
	s32 val;
	int offs = 0;

	if (*ppos != 0) {
		return 0;
	}

	mutex_lock(&data->core_lock);
	val = pcsm_read_byte(client, PMCM_REG(PMCM_RW_FORCEPR));
	if (val < 0) {
		dev_err(&adapter->dev,
			"reg[%02d] - read_error (%d)\n",
			PMCM_REG(PMCM_RW_FORCEPR), val);
	} else {
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "0x%x\n", (u8)val);
	}
	mutex_unlock(&data->core_lock);
	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	return simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));
}

static ssize_t pcsm_dbg_forcepr_write(struct file *filp,
				      const char __user *buffer,
				      size_t count, loff_t *ppos)
{
	struct pcsm_data *data = filp->private_data;
	struct i2c_client *client = data->client;
	struct i2c_adapter *adapter = client->adapter;
	char input[CORE_STR_MAX_SIZE];
	int  ret;
	u32  value;

	memset(input, 0, sizeof(char) * CORE_STR_MAX_SIZE);
	if (count > CORE_STR_MAX_SIZE - 1) {
		ret = -EINVAL;
	} else if (copy_from_user(input, buffer, count)) {
		ret = -EFAULT;
	} else {
		ret = sscanf(input, "0x%X\n", &value);
		if (ret != 1) {
			dev_err(&adapter->dev,
				"Failed to write forcepr (invalid string).\n");
			ret = -EINVAL;
		} else {
			mutex_lock(&data->core_lock);
			i2c_smbus_write_byte_data(client,
						  PMCM_REG(PMCM_RW_FORCEPR),
						  value);
			mutex_unlock(&data->core_lock);
			ret = count;
		}
	}

	return ret;
}

/*
 * Check for "enable" - if not set - nothing to do.
 * Set "use_rcn" - area of work: with existing cores or all space.
 * Check for "val" - if set - wait for clear.
 * Set addr_lo[5:2] and addr_li[11:6].
 * Set "val" and wait for "rdata_val".
 * Read PMC_I2C_CFG_DAT[0-3]
*/

static void core_request_process(struct pcsm_data *data, char *data_string)
{
	unsigned char cfg_lo;
	unsigned char cfg_hi;
	struct i2c_client *client = data->client;
	struct i2c_adapter *adapter = client->adapter;
	u8 core_data[4];

	mutex_lock(&data->core_lock);

	/* wait operation if set bit */
	cfg_lo = pcsm_read_byte(client, PMCM_REG(PMCM_RW_CFG_LO));
	if (cfg_lo < 0) {
		goto end_with_error;
	}

	/* check bit[2] for enabled access to regs */
	if (!(cfg_lo & 0x4)) {
		dev_warn(&adapter->dev,
			 "Access to the registers PMC is disabled.\n");
		return;
	}

	/* check bit[0] for waiting other operation */
	while (cfg_lo & 0x1) {
		udelay(1000);
		cfg_lo = pcsm_read_byte(client, PMCM_REG(PMCM_RW_CFG_LO));
		if (cfg_lo < 0) {
			goto end_with_error;
		}
	}

	cfg_lo = ((data->core_address >> 2) & 0xF) << 4; /* setup low addr */
	cfg_hi = ((data->core_address >> 6) & 0xF);
	if (data->use_rcn) {
		cfg_lo |= 2;
	}
	cfg_lo |= 1; /* setup "val", for start exchange */

	/* write regs */
	i2c_smbus_write_byte_data(client, PMCM_REG(PMCM_RW_CFG_HI), cfg_hi);
	i2c_smbus_write_byte_data(client, PMCM_REG(PMCM_RW_CFG_LO), cfg_lo);

	do {
		udelay(1000);
		cfg_lo = pcsm_read_byte(client, PMCM_REG(PMCM_RW_CFG_LO));
		if (cfg_lo < 0) {
			goto end_with_error;
		}
	} while (!(cfg_lo & 0x8)); /* wait bit[3] operation complete */

	core_data[0] = pcsm_read_byte(client, PMCM_REG(PMCM_RO_CFG_DAT0));
	core_data[1] = pcsm_read_byte(client, PMCM_REG(PMCM_RO_CFG_DAT1));
	core_data[2] = pcsm_read_byte(client, PMCM_REG(PMCM_RO_CFG_DAT2));
	core_data[3] = pcsm_read_byte(client, PMCM_REG(PMCM_RO_CFG_DAT3));

	mutex_unlock(&data->core_lock);

	snprintf(data_string, CORE_STR_MAX_SIZE - 1, "0x%02x%02x%02x%02x 0x%x",
		 core_data[3], core_data[2],
		 core_data[1], core_data[0],
		 data->core_address);

	dev_dbg(&adapter->dev, "lo:0x%x\n", cfg_lo);
	dev_dbg(&adapter->dev, "hi:0x%x\n", cfg_hi);

	return;
end_with_error:
	mutex_unlock(&data->core_lock);
	dev_err(&adapter->dev, "reg[%02d] - read_error (%d)\n",
		PMCM_REG(PMCM_RW_CFG_LO), cfg_lo);
}

static ssize_t pcsm_dbg_core_data_read(struct file *filp,
				       char __user *buffer,
				       size_t count, loff_t *ppos)
{
	struct pcsm_data *data = filp->private_data;
	char *buf = pcsm_dbg_core_buf;
	int offs = 0;
	char data_string[CORE_STR_MAX_SIZE];

	core_request_process(data, data_string);
	mutex_lock(&data->core_lock);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "%s\n", data_string);
	mutex_unlock(&data->core_lock);
	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	return simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));
}

static const struct file_operations pcsm_dbg_regs_fan0_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = pcsm_dbg_regs_fan0_read,
};

static const struct file_operations pcsm_dbg_regs_fan1_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = pcsm_dbg_regs_fan1_read,
};

static const struct file_operations pcsm_dbg_regs_pmcm_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = pcsm_dbg_regs_pmcm_read,
};

static const struct file_operations pcsm_dbg_core_address_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = pcsm_dbg_core_address_read,
	.write = pcsm_dbg_core_address_write,
};

static const struct file_operations pcsm_dbg_core_data_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = pcsm_dbg_core_data_read,
};

static const struct file_operations pcsm_dbg_use_rcn_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = pcsm_dbg_use_rcn_read,
	.write = pcsm_dbg_use_rcn_write,
};

static const struct file_operations pcsm_dbg_forcepr_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = pcsm_dbg_forcepr_read,
	.write = pcsm_dbg_forcepr_write,
};

/* /sys/kernel/debug/pcsm */
static struct dentry *pcsm_dbg_root = NULL;

/**
 * pcsm_dbgfs_init - setup the debugfs directory
 **/
static void pcsm_dbgfs_init(struct pcsm_data *data)
{
	struct dentry *pfile;
	struct i2c_client *client = data->client;
	struct device *dev = &client->dev;

	dev_dbg(dev, "%s()\n", __func__);

	if (!pcsm_dbg_root) {
		dev_warn(dev, "debugfs parent dir not created\n");
		return;
	}

	data->pcsm_dbg = debugfs_create_dir(dev_name(dev), pcsm_dbg_root);
	if (data->pcsm_dbg) {
		pfile = debugfs_create_file("regs_fan0", 0600,
					    data->pcsm_dbg, data,
					    &pcsm_dbg_regs_fan0_fops);
		if (!pfile) {
			dev_warn(dev, "debugfs create file regs_fan0 failed\n");
		}
		pfile = debugfs_create_file("regs_fan1", 0600,
					    data->pcsm_dbg, data,
					    &pcsm_dbg_regs_fan1_fops);
		if (!pfile) {
			dev_warn(dev, "debugfs create file regs_fan1 failed\n");
		}
		pfile = debugfs_create_file("regs_pmcm", 0600,
					    data->pcsm_dbg, data,
					    &pcsm_dbg_regs_pmcm_fops);
		if (!pfile) {
			dev_warn(dev, "debugfs create file regs_pmcm failed\n");
		}

		/* create files for raw/debug read PMC regs */
		pfile = debugfs_create_file("core_address", 0600,
					    data->pcsm_dbg, data,
					    &pcsm_dbg_core_address_fops);
		if (!pfile) {
			dev_warn(dev, "debugfs create file core_address failed\n");
		}
		pfile = debugfs_create_file("core_data", 0600,
					    data->pcsm_dbg, data,
					    &pcsm_dbg_core_data_fops);
		if (!pfile) {
			dev_warn(dev, "debugfs create file core_data failed\n");
		}
		pfile = debugfs_create_file("core_use_rcn", 0600,
					    data->pcsm_dbg, data,
					    &pcsm_dbg_use_rcn_fops);
		if (!pfile) {
			dev_warn(dev, "debugfs create file core_use_rcn failed\n");
		}
		pfile = debugfs_create_file("forcepr", 0600,
					    data->pcsm_dbg, data,
					    &pcsm_dbg_forcepr_fops);
		if (!pfile) {
			dev_warn(dev, "debugfs create file forcepr failed\n");
		}
	} else {
		dev_warn(dev, "debugfs create_dir failed\n");
	}
} /* pcsm_dbgfs_init */

/**
 * pcsm_dbgfs_exit - clear out debugfs entries
 **/
static void pcsm_dbgfs_exit(struct pcsm_data *data)
{
	pr_debug(KBUILD_MODNAME ": %s()\n", __func__);

	if (data->pcsm_dbg) {
		debugfs_remove_recursive(data->pcsm_dbg);
		data->pcsm_dbg = NULL;
	}
} /* pcsm_dbgfs_exit */

#endif /* CONFIG_DEBUG_FS */


/*---------------------------------------------------------------------------*/
/* HWMON                                                                     */
/*---------------------------------------------------------------------------*/

static struct pcsm_data *pcsm_update_device(struct device *dev)
{
	struct pcsm_data *data = dev_get_drvdata(dev);

	pcsm_update_data(data);

	return data;
} /* pcsm_update_device */

static ssize_t show_cpuinfo(struct device *dev,
			struct device_attribute *devattr,
			char *buf)
{
	struct pcsm_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;

	data->model = pcsm_read_byte(client, PMCM_REG(PMCM_RO_INFO_LO));
	data->revision = pcsm_read_byte(client, PMCM_REG(PMCM_RO_INFO_HI));
	/*
	  id              : 0xb
	  cpu family      : 6
	  model           : 11
	  model name      : E16C
	  revision        : 0
	*/
	return snprintf(buf, PAGE_SIZE - 1,
		       "id\t\t: 0x%x\n"			\
/*		       "cpu family\t: %d\n"		\ */
		       "model\t\t: %d\n"		\
		       "model name\t: %s\n"		\
		       "revision\t: %d\n",
		       (data->revision << 8) | data->model,
/*		       -1,*/
		       data->model,
		       GET_CPU_TYPE_NAME(data->model),
		       data->revision);
}

/*
 * how to convert hex to percent
 * 0x00 - 0%
 * 0x40 - 50%
 * 0x80 - 100%
 * step - 1/1.28 = 0.78125
 */
#define PWM_TO_PROCENT(v) (((v) * 78125) / 100000)
#define PROCENT_TO_PWM(v) (((v) * 100000) / 78125)

#define TEMP_TO_HWMON(v) ((v)/2 * 1000 + ((v)%2 ? 500 : 0))

/* convert index from SENSOR_DEVICE_ATTR(..., index) to [i][k] */
#define GET_MIXED_i(n) (n%10)
#define GET_MIXED_k(n) ((n/100)-1)

static ssize_t show_pwm(struct device *dev,
			struct device_attribute *devattr,
			char *buf)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct pcsm_data *data = pcsm_update_device(dev);

	snprintf(buf, PAGE_SIZE - 1, "%d\n",
		 PWM_TO_PROCENT(data->pwm_st[attr->index]));

	return strlen(buf);
}

static ssize_t set_pwm(struct device *dev,
		       struct device_attribute *devattr,
			const char *buf, size_t count)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct pcsm_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	unsigned long val;
	int err;
	u8 reg;

	err = kstrtoul(buf, 10, &val);
	if (err) {
		return err;
	}

	reg = PCSM_RW_PWM_FIXED + attr->index * PCSM_TWO_OFFSET;
	val = clamp_val(PROCENT_TO_PWM(val), 0, 0x80);

	mutex_lock(&data->update_lock);
	data->pwm[attr->index] = val;
	data->pwm_st[attr->index] = val;
	i2c_smbus_write_byte_data(client, reg, val);
	mutex_unlock(&data->update_lock);

	return count;
}

static ssize_t show_word(struct device *dev,
			struct device_attribute *devattr,
			char *buf)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct pcsm_data *data = pcsm_update_device(dev);

	int i = GET_MIXED_i(attr->index);
	int k = GET_MIXED_k(attr->index);
	u16 r = (data->mixed_st[i][k+1] << 8) | data->mixed_st[i][k];

	return snprintf(buf, PAGE_SIZE - 1, "0x%x\n", r);
}

static ssize_t set_word(struct device *dev,
		       struct device_attribute *devattr,
			const char *buf, size_t count)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct pcsm_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;

	u8 v_lo, v_hi;
	unsigned long value;
	int i = GET_MIXED_i(attr->index);
	int k = GET_MIXED_k(attr->index);

	int err = kstrtoul(buf, 16, &value);
	if (err) {
		return err;
	}

	value = clamp_val(value, 0, 0xffff);
	v_lo = value & 0xff;
	v_hi = (value >> 8) & 0xff;

	mutex_lock(&data->update_lock);
	data->mixed[i][k] = v_lo;
	data->mixed_st[i][k] = v_lo;
	data->mixed[i][k+1] = v_hi;
	data->mixed_st[i][k+1] = v_hi;
	i2c_smbus_write_byte_data(client,
				  (i * PCSM_TWO_OFFSET) +
				  PCSM_MIXED_START + k,
				  v_lo);
	i2c_smbus_write_byte_data(client,
				  (i * PCSM_TWO_OFFSET) +
				  PCSM_MIXED_START + k + 1,
				  v_hi);
	mutex_unlock(&data->update_lock);

	return count;
}

static ssize_t show_byte(struct device *dev,
			struct device_attribute *devattr,
			char *buf)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct pcsm_data *data = pcsm_update_device(dev);
	int i = GET_MIXED_i(attr->index);
	int k = GET_MIXED_k(attr->index);

	return snprintf(buf, PAGE_SIZE - 1, "0x%x\n", data->mixed_st[i][k]);
}

static ssize_t set_byte(struct device *dev,
			struct device_attribute *devattr,
			const char *buf, size_t count)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct pcsm_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	unsigned long value;

	int i = GET_MIXED_i(attr->index);
	int k = GET_MIXED_k(attr->index);

	int err = kstrtoul(buf, 16, &value);
	if (err) {
		return err;
	}

	value = clamp_val(value, 0, 0xff);

	mutex_lock(&data->update_lock);
	data->mixed[i][k] = (u8)value;
	data->mixed_st[i][k] = (u8)value;
	i2c_smbus_write_byte_data(client,
				  (i * PCSM_TWO_OFFSET) +
				  PCSM_MIXED_START + k,
				  data->mixed_st[i][k]);
	mutex_unlock(&data->update_lock);

	return count;
}



static ssize_t show_l_pwm(struct device *dev,
			    struct device_attribute *devattr,
			    char *buf)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct pcsm_data *data = pcsm_update_device(dev);

	int number = (attr->index >= 10) ? 1 : 0;
	int index = number ? attr->index - 10 : attr->index;

	snprintf(buf, PAGE_SIZE - 1, "%d\n",
		 PWM_TO_PROCENT(data->pwm_lut[number][index]));

	return strlen(buf);
}

static ssize_t set_l_pwm(struct device *dev,
			struct device_attribute *devattr,
			const char *buf, size_t count)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct pcsm_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int number, index;
	unsigned long val;
	int err;
	u8 reg;

	err = kstrtoul(buf, 10, &val);
	if (err) {
		return err;
	}

	number = (attr->index >= 10) ? 1 : 0;
	index = number ? attr->index - 10 : attr->index;

	reg = PCSM_TWO_OFFSET * number + PCSM_RW_LUT0_PWM + index * 3;
	val = clamp_val(PROCENT_TO_PWM(val), 0, 0x80);

	mutex_lock(&data->update_lock);
	data->pwm_lut[number][index] = val;
	data->pwm_lut_st[number][index] = val;
	i2c_smbus_write_byte_data(client, reg, val);
	mutex_unlock(&data->update_lock);

	return count;
}

static ssize_t show_temp(struct device *dev,
			 struct device_attribute *devattr,
			 char *buf)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct pcsm_data *data = pcsm_update_device(dev);

	int temp = data->temp;

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
				 TEMP_TO_HWMON(temp));
		}
	}

	return strlen(buf);
}

static ssize_t common_show_l_temp(struct device *dev,
				  struct device_attribute *devattr,
				  char *buf, int flag)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct pcsm_data *data = pcsm_update_device(dev);

	int number = (attr->index >= 10) ? 1 : 0;
	int index = number ? attr->index - 10 : attr->index;
	u8 temp;

	if (flag) {
		temp = data->temp_lut[number][index];
	} else {
		temp = data->hyst_lut[number][index];
	}

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
				 TEMP_TO_HWMON(temp));
		}
	}

	return strlen(buf);
}

static ssize_t common_set_l_temp(struct device *dev,
				 struct device_attribute *devattr,
				 const char *buf, size_t count, int flag)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct pcsm_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	unsigned long value;

	int number = (attr->index >= 10) ? 1 : 0;
	int index = number ? attr->index - 10 : attr->index;
	u8 temp;
	u8 reg;

	int err = kstrtoul(buf, 10, &value);
	if (err) {
		return err;
	}

	if (flag) {
		reg = PCSM_TWO_OFFSET * number + PCSM_RW_LUT0_TEMP + index * 3;
	} else {
		reg = PCSM_TWO_OFFSET * number + PCSM_RW_LUT0_HYST + index * 3;
	}

	value = clamp_val(value, 0, 128000);
	temp = value%1000 ? 1 : 0;
	value = value / 1000;
	temp += value*2;
	mutex_lock(&data->update_lock);
	if (flag) {
		data->temp_lut[number][index] = (u8)temp;
		data->temp_lut_st[number][index] = (u8)temp;
	} else {
		data->hyst_lut[number][index] = (u8)temp;
		data->hyst_lut_st[number][index] = (u8)temp;
	}

	i2c_smbus_write_byte_data(client, reg, temp);
	mutex_unlock(&data->update_lock);
	return count;
}

static ssize_t show_l_temp(struct device *dev,
				  struct device_attribute *devattr,
				  char *buf)
{
	return common_show_l_temp(dev, devattr, buf, 1);
}

static ssize_t show_l_hyst(struct device *dev,
				  struct device_attribute *devattr,
				  char *buf)
{
	return common_show_l_temp(dev, devattr, buf, 0);
}

static ssize_t set_l_temp(struct device *dev,
				 struct device_attribute *devattr,
			  const char *buf, size_t count)
{
	return common_set_l_temp(dev, devattr, buf, count, 1);
}

static ssize_t set_l_hyst(struct device *dev,
				 struct device_attribute *devattr,
			  const char *buf, size_t count)
{
	return common_set_l_temp(dev, devattr, buf, count, 0);
}

static ssize_t show_pwm_ct(struct device *dev,
		      struct device_attribute *devattr,
		      char *buf)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct pcsm_data *data = pcsm_update_device(dev);
	int i = GET_MIXED_i(attr->index);
	int k = GET_MIXED_k(attr->index);
	return snprintf(buf, PAGE_SIZE - 1, "0x%x\n", data->pwm_ct_st[i][k]);
}

static ssize_t set_pwm_ct(struct device *dev,
			  struct device_attribute *devattr,
			  const char *buf, size_t count)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct pcsm_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	unsigned long value;

	int i = GET_MIXED_i(attr->index);
	int k = GET_MIXED_k(attr->index);
	int reg = 0;

	int err = kstrtoul(buf, 16, &value);
	if (err) {
		return err;
	}

	if (k == 0) {
		reg = (i * PCSM_TWO_OFFSET) + PCSM_RW_CONTROL;
	} else {
		reg = (i * PCSM_TWO_OFFSET) + PCSM_RW_TIME_INTERVAL;
	}

	mutex_lock(&data->update_lock);
	data->pwm_ct[i][k] = (u8)value;
	data->pwm_ct_st[i][k] = (u8)value;
	i2c_smbus_write_byte_data(client, reg,
				  data->pwm_ct_st[i][k]);
	mutex_unlock(&data->update_lock);

	return count;
}

static const char *events_ecc_name[8] = {
	"Memory controller 0 Error",
	"Memory controller 1 Error",
	"Memory controller 2 Error",
	"Memory controller 3 Error",
	"Memory controller 4 Error",
	"Memory controller 5 Error",
	"Memory controller 6 Error",
	"Memory controller 7 Error"
};

static const char *events_main_name[8] = {
	"MC[0-3] DIMM Error",
	"MC[4-7] DIMM Error",
	"MC[0-3] Power Error",
	"MC[4-7] Power Error",
	"CPU Power (except MC) Error",
	"MotherBoard Power Error",
	"MotherBoard Error",
	"CPU Fault"
};

static const char *events_therm_name[6] = {
	"PCS FAN0 Error",
	"PCS FAN1 Error",
	"CPU state HOT",
	"MC[0-3] Throttle",
	"MC[4-7] Throttle",
	"CPU Force Power Mode"
};

static ssize_t show_event(struct device *dev,
			 struct device_attribute *devattr,
			 char *buf)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct pcsm_data *data = pcsm_update_device(dev);

	int i, offs = 0;
	struct event_data *ptr = NULL;

	switch (attr->index) {
	case ecc_id:
		ptr = &data->ecc;
		break;
	case main_id:
		ptr = &data->main;
		break;
	case therm_id:
		ptr = &data->therm;
		break;
	}

	if (!ptr) {
		return 0;
	}

	offs += snprintf(buf + offs, PAGE_SIZE - 1 - offs,
			 "0x%x 0x%x\n\n",
			 ptr->monitor, ptr->event);
	offs += snprintf(buf + offs, PAGE_SIZE - 1 - offs,
			 "%-30s: %-7s: %-7s\n",
			 "event name", "current", "history");
	for (i = 0; i < ptr->table_size; i++) {
		offs += snprintf(buf + offs, PAGE_SIZE - 1 - offs,
			 "%-30s: %-7s: %-7s\n", ptr->names[i],
			 ((ptr->monitor >> i) & 1) ? "present" : "clear",
			 ((ptr->event >> i) & 1) ? "present" : "clear");
	}

	return strlen(buf);
}

static ssize_t reset_event(struct device *dev,
			struct device_attribute *devattr,
			const char *buf, size_t count)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct pcsm_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;

	u8 reg = 0;

	switch (attr->index) {
	case ecc_id:
		reg = PMCM_REG(PMCM_RWC_HIST_0);
		break;
	case main_id:
		reg = PMCM_REG(PMCM_RWC_HIST_1);
		break;
	case therm_id:
		reg = PMCM_REG(PMCM_RWC_HIST_2);
		break;
	}

	if (!reg) {
		return count;
	}

	mutex_lock(&data->update_lock);
	i2c_smbus_write_byte_data(client, reg, 1);
	mutex_unlock(&data->update_lock);

	return count;
}

#define MATTR (S_IWUSR | S_IRUGO)

static SENSOR_DEVICE_ATTR(cpuinfo, MATTR, show_cpuinfo, NULL, 0);
static SENSOR_DEVICE_ATTR(temp1_input, MATTR, show_temp, NULL, 0);
static SENSOR_DEVICE_ATTR(event_ecc, MATTR, show_event, reset_event, ecc_id);
static SENSOR_DEVICE_ATTR(event_main, MATTR, show_event, reset_event, main_id);
static SENSOR_DEVICE_ATTR(event_therm, MATTR, show_event, reset_event,therm_id);

/*
  for show/set_pwm
  for show/set_word
  for show/set_byte
  regs[i][k]
  (k+1)*100 + i
*/

static SENSOR_DEVICE_ATTR(pwm1, MATTR, show_pwm, set_pwm, 0);
static SENSOR_DEVICE_ATTR(pwm1_control, MATTR, show_pwm_ct,set_pwm_ct, 100 + 0);
static SENSOR_DEVICE_ATTR(pwm1_smooth, MATTR, show_pwm_ct, set_pwm_ct, 200 + 0);

static SENSOR_DEVICE_ATTR(pwm2, MATTR, show_pwm, set_pwm, 1);
static SENSOR_DEVICE_ATTR(pwm2_control, MATTR, show_pwm_ct,set_pwm_ct, 100 + 1);
static SENSOR_DEVICE_ATTR(pwm2_smooth, MATTR, show_pwm_ct, set_pwm_ct, 200 + 1);

static SENSOR_DEVICE_ATTR(tach1_cnt, MATTR, show_word, set_word, 100 + 0);
static SENSOR_DEVICE_ATTR(tach1_control, MATTR, show_byte, set_byte, 300 + 0);
static SENSOR_DEVICE_ATTR(alert1_control, MATTR, show_byte, set_byte, 400 + 0);
static SENSOR_DEVICE_ATTR(pwm1_min, MATTR, show_byte, set_byte, 500 + 0);
static SENSOR_DEVICE_ATTR(pwm1_max, MATTR, show_byte, set_byte, 600 + 0);
static SENSOR_DEVICE_ATTR(tach1_min, MATTR, show_word, set_word, 700 + 0);
static SENSOR_DEVICE_ATTR(tach1_max, MATTR, show_word, set_word, 900 + 0);
static SENSOR_DEVICE_ATTR(alert1_status, MATTR, show_byte, NULL, 1100 + 0);

static SENSOR_DEVICE_ATTR(tach2_cnt, MATTR, show_word, set_word, 100 + 1);
static SENSOR_DEVICE_ATTR(tach2_control, MATTR, show_byte, set_byte, 300 + 1);
static SENSOR_DEVICE_ATTR(alert2_control, MATTR, show_byte, set_byte, 400 + 1);
static SENSOR_DEVICE_ATTR(pwm2_min, MATTR, show_byte, set_byte, 500 + 1);
static SENSOR_DEVICE_ATTR(pwm2_max, MATTR, show_byte, set_byte, 600 + 1);
static SENSOR_DEVICE_ATTR(tach2_min, MATTR, show_word, set_word, 700 + 1);
static SENSOR_DEVICE_ATTR(tach2_max, MATTR, show_word, set_word, 900 + 1);
static SENSOR_DEVICE_ATTR(alert2_status, MATTR, show_byte, NULL, 1100 + 1);


static SENSOR_DEVICE_ATTR(pwm1_lut1_pwm,  MATTR, show_l_pwm,  set_l_pwm,  0);
static SENSOR_DEVICE_ATTR(pwm1_lut1_temp, MATTR, show_l_temp, set_l_temp, 0);
static SENSOR_DEVICE_ATTR(pwm1_lut1_hyst, MATTR, show_l_hyst, set_l_hyst, 0);
static SENSOR_DEVICE_ATTR(pwm1_lut2_pwm,  MATTR, show_l_pwm,  set_l_pwm,  1);
static SENSOR_DEVICE_ATTR(pwm1_lut2_temp, MATTR, show_l_temp, set_l_temp, 1);
static SENSOR_DEVICE_ATTR(pwm1_lut2_hyst, MATTR, show_l_hyst, set_l_hyst, 1);
static SENSOR_DEVICE_ATTR(pwm1_lut3_pwm,  MATTR, show_l_pwm,  set_l_pwm,  2);
static SENSOR_DEVICE_ATTR(pwm1_lut3_temp, MATTR, show_l_temp, set_l_temp, 2);
static SENSOR_DEVICE_ATTR(pwm1_lut3_hyst, MATTR, show_l_hyst, set_l_hyst, 2);
static SENSOR_DEVICE_ATTR(pwm1_lut4_pwm,  MATTR, show_l_pwm,  set_l_pwm,  3);
static SENSOR_DEVICE_ATTR(pwm1_lut4_temp, MATTR, show_l_temp, set_l_temp, 3);
static SENSOR_DEVICE_ATTR(pwm1_lut4_hyst, MATTR, show_l_hyst, set_l_hyst, 3);
static SENSOR_DEVICE_ATTR(pwm1_lut5_pwm,  MATTR, show_l_pwm,  set_l_pwm,  4);
static SENSOR_DEVICE_ATTR(pwm1_lut5_temp, MATTR, show_l_temp, set_l_temp, 4);
static SENSOR_DEVICE_ATTR(pwm1_lut5_hyst, MATTR, show_l_hyst, set_l_hyst, 4);
static SENSOR_DEVICE_ATTR(pwm1_lut6_pwm,  MATTR, show_l_pwm,  set_l_pwm,  5);
static SENSOR_DEVICE_ATTR(pwm1_lut6_temp, MATTR, show_l_temp, set_l_temp, 5);
static SENSOR_DEVICE_ATTR(pwm1_lut6_hyst, MATTR, show_l_hyst, set_l_hyst, 5);
static SENSOR_DEVICE_ATTR(pwm1_lut7_pwm,  MATTR, show_l_pwm,  set_l_pwm,  6);
static SENSOR_DEVICE_ATTR(pwm1_lut7_temp, MATTR, show_l_temp, set_l_temp, 6);
static SENSOR_DEVICE_ATTR(pwm1_lut7_hyst, MATTR, show_l_hyst, set_l_hyst, 6);
static SENSOR_DEVICE_ATTR(pwm1_lut8_pwm,  MATTR, show_l_pwm,  set_l_pwm,  7);
static SENSOR_DEVICE_ATTR(pwm1_lut8_temp, MATTR, show_l_temp, set_l_temp, 7);
static SENSOR_DEVICE_ATTR(pwm1_lut8_hyst, MATTR, show_l_hyst, set_l_hyst, 7);
static SENSOR_DEVICE_ATTR(pwm1_lut9_pwm,  MATTR, show_l_pwm,  set_l_pwm,  8);
static SENSOR_DEVICE_ATTR(pwm1_lut9_temp, MATTR, show_l_temp, set_l_temp, 8);
static SENSOR_DEVICE_ATTR(pwm1_lut9_hyst, MATTR, show_l_hyst, set_l_hyst, 8);
static SENSOR_DEVICE_ATTR(pwm1_lut10_pwm, MATTR, show_l_pwm,  set_l_pwm,  9);
static SENSOR_DEVICE_ATTR(pwm1_lut10_temp,MATTR, show_l_temp, set_l_temp, 9);
static SENSOR_DEVICE_ATTR(pwm1_lut10_hyst,MATTR, show_l_hyst, set_l_hyst, 9);


static SENSOR_DEVICE_ATTR(pwm2_lut1_pwm,  MATTR, show_l_pwm,  set_l_pwm,  10);
static SENSOR_DEVICE_ATTR(pwm2_lut1_temp, MATTR, show_l_temp, set_l_temp, 10);
static SENSOR_DEVICE_ATTR(pwm2_lut1_hyst, MATTR, show_l_hyst, set_l_hyst, 10);
static SENSOR_DEVICE_ATTR(pwm2_lut2_pwm,  MATTR, show_l_pwm,  set_l_pwm,  11);
static SENSOR_DEVICE_ATTR(pwm2_lut2_temp, MATTR, show_l_temp, set_l_temp, 11);
static SENSOR_DEVICE_ATTR(pwm2_lut2_hyst, MATTR, show_l_hyst, set_l_hyst, 11);
static SENSOR_DEVICE_ATTR(pwm2_lut3_pwm,  MATTR, show_l_pwm,  set_l_pwm,  12);
static SENSOR_DEVICE_ATTR(pwm2_lut3_temp, MATTR, show_l_temp, set_l_temp, 12);
static SENSOR_DEVICE_ATTR(pwm2_lut3_hyst, MATTR, show_l_hyst, set_l_hyst, 12);
static SENSOR_DEVICE_ATTR(pwm2_lut4_pwm,  MATTR, show_l_pwm,  set_l_pwm,  13);
static SENSOR_DEVICE_ATTR(pwm2_lut4_temp, MATTR, show_l_temp, set_l_temp, 13);
static SENSOR_DEVICE_ATTR(pwm2_lut4_hyst, MATTR, show_l_hyst, set_l_hyst, 13);
static SENSOR_DEVICE_ATTR(pwm2_lut5_pwm,  MATTR, show_l_pwm,  set_l_pwm,  14);
static SENSOR_DEVICE_ATTR(pwm2_lut5_temp, MATTR, show_l_temp, set_l_temp, 14);
static SENSOR_DEVICE_ATTR(pwm2_lut5_hyst, MATTR, show_l_hyst, set_l_hyst, 14);
static SENSOR_DEVICE_ATTR(pwm2_lut6_pwm,  MATTR, show_l_pwm,  set_l_pwm,  15);
static SENSOR_DEVICE_ATTR(pwm2_lut6_temp, MATTR, show_l_temp, set_l_temp, 15);
static SENSOR_DEVICE_ATTR(pwm2_lut6_hyst, MATTR, show_l_hyst, set_l_hyst, 15);
static SENSOR_DEVICE_ATTR(pwm2_lut7_pwm,  MATTR, show_l_pwm,  set_l_pwm,  16);
static SENSOR_DEVICE_ATTR(pwm2_lut7_temp, MATTR, show_l_temp, set_l_temp, 16);
static SENSOR_DEVICE_ATTR(pwm2_lut7_hyst, MATTR, show_l_hyst, set_l_hyst, 16);
static SENSOR_DEVICE_ATTR(pwm2_lut8_pwm,  MATTR, show_l_pwm,  set_l_pwm,  17);
static SENSOR_DEVICE_ATTR(pwm2_lut8_temp, MATTR, show_l_temp, set_l_temp, 17);
static SENSOR_DEVICE_ATTR(pwm2_lut8_hyst, MATTR, show_l_hyst, set_l_hyst, 17);
static SENSOR_DEVICE_ATTR(pwm2_lut9_pwm,  MATTR, show_l_pwm,  set_l_pwm,  18);
static SENSOR_DEVICE_ATTR(pwm2_lut9_temp, MATTR, show_l_temp, set_l_temp, 18);
static SENSOR_DEVICE_ATTR(pwm2_lut9_hyst, MATTR, show_l_hyst, set_l_hyst, 18);
static SENSOR_DEVICE_ATTR(pwm2_lut10_pwm, MATTR, show_l_pwm,  set_l_pwm,  19);
static SENSOR_DEVICE_ATTR(pwm2_lut10_temp,MATTR, show_l_temp, set_l_temp, 19);
static SENSOR_DEVICE_ATTR(pwm2_lut10_hyst,MATTR, show_l_hyst, set_l_hyst, 19);


static struct attribute *pcsm_attrs[] = {
/* from PCM */
	&sensor_dev_attr_cpuinfo.dev_attr.attr,
	&sensor_dev_attr_event_ecc.dev_attr.attr,
	&sensor_dev_attr_event_main.dev_attr.attr,
	&sensor_dev_attr_event_therm.dev_attr.attr,
	&sensor_dev_attr_temp1_input.dev_attr.attr,

/* from I2C */
	&sensor_dev_attr_pwm1.dev_attr.attr,
	&sensor_dev_attr_pwm1_control.dev_attr.attr,
	&sensor_dev_attr_pwm1_smooth.dev_attr.attr,
	&sensor_dev_attr_pwm1_min.dev_attr.attr,
	&sensor_dev_attr_pwm1_max.dev_attr.attr,
	&sensor_dev_attr_tach1_cnt.dev_attr.attr,
	&sensor_dev_attr_tach1_min.dev_attr.attr,
	&sensor_dev_attr_tach1_max.dev_attr.attr,
	&sensor_dev_attr_tach1_control.dev_attr.attr,
	&sensor_dev_attr_alert1_control.dev_attr.attr,
	&sensor_dev_attr_alert1_status.dev_attr.attr,

	&sensor_dev_attr_pwm1_lut1_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut1_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut1_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut2_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut2_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut2_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut3_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut3_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut3_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut4_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut4_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut4_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut5_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut5_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut5_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut6_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut6_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut6_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut7_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut7_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut7_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut8_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut8_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut8_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut9_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut9_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut9_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut10_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut10_temp.dev_attr.attr,
	&sensor_dev_attr_pwm1_lut10_hyst.dev_attr.attr,


	&sensor_dev_attr_pwm2.dev_attr.attr,
	&sensor_dev_attr_pwm2_control.dev_attr.attr,
	&sensor_dev_attr_pwm2_smooth.dev_attr.attr,
	&sensor_dev_attr_pwm2_min.dev_attr.attr,
	&sensor_dev_attr_pwm2_max.dev_attr.attr,
	&sensor_dev_attr_tach2_cnt.dev_attr.attr,
	&sensor_dev_attr_tach2_min.dev_attr.attr,
	&sensor_dev_attr_tach2_max.dev_attr.attr,
	&sensor_dev_attr_tach2_control.dev_attr.attr,
	&sensor_dev_attr_alert2_control.dev_attr.attr,
	&sensor_dev_attr_alert2_status.dev_attr.attr,

	&sensor_dev_attr_pwm2_lut1_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut1_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut1_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut2_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut2_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut2_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut3_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut3_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut3_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut4_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut4_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut4_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut5_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut5_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut5_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut6_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut6_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut6_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut7_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut7_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut7_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut8_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut8_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut8_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut9_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut9_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut9_hyst.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut10_pwm.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut10_temp.dev_attr.attr,
	&sensor_dev_attr_pwm2_lut10_hyst.dev_attr.attr,

	NULL
};

ATTRIBUTE_GROUPS(pcsm);


/*---------------------------------------------------------------------------*/
/* I2C driver part                                                           */
/*---------------------------------------------------------------------------*/

/* Return 0 if detection is successful, -ENODEV otherwise */
static int pcsm_detect(struct i2c_client *new_client,
		       struct i2c_board_info *info)
{
	struct i2c_adapter *adapter = new_client->adapter;
	int address = new_client->addr;
	s32 idlo, idhi;

	dev_dbg(&adapter->dev, "%s()\n", __func__);

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE_DATA)) {
		dev_err(&adapter->dev, "!i2c_check_functionality\n");
		return -ENODEV;
	}

	idlo = pcsm_read_byte(new_client, PCSM_RO_ID_LO);
	idhi = pcsm_read_byte(new_client, PCSM_RO_ID_HI);
	if (idlo != MANUFACTURER_ID_LO &&
	    idhi != MANUFACTURER_ID_HI) {
		dev_err(&adapter->dev,
			"pcsm detection failed: "
			"bad manufacturer id 0x%02x%02x at 0x%02x\n",
			(u8)idlo,
			(u8)idhi,
			address);
		dev_err(&adapter->dev,
			"pcsm manufacturer id must be: 0x%02x%02x\n",
			MANUFACTURER_ID_LO,
			MANUFACTURER_ID_HI);
		return -ENODEV;
	}
	dev_info(&adapter->dev, "pcsm detected at 0x%02x\n", address);

	/* Fill the i2c board info */
	strlcpy(info->type, KBUILD_MODNAME, I2C_NAME_SIZE);

	return 0;
} /* pcsm_detect */

/*
 * Now used for get values from RO registers
 * and store it in "struct pcsm_data",
 * for init events and monitors from PMCM
 */
static void pcsm_init_data(struct pcsm_data *data)
{
	struct i2c_client *client = data->client;

	dev_dbg(&client->dev, "%s()\n", __func__);

	data->model = pcsm_read_byte(client, PMCM_REG(PMCM_RO_INFO_LO));
	data->revision = pcsm_read_byte(client, PMCM_REG(PMCM_RO_INFO_HI));

	data->ecc.id = ecc_id;
	data->ecc.monitor = pcsm_read_byte(client, PMCM_REG(PMCM_RO_MON_0));
	data->ecc.event = pcsm_read_byte(client, PMCM_REG(PMCM_RWC_HIST_0));
	data->ecc.table_size = 8;
	data->ecc.names = events_ecc_name;

	data->main.id = main_id;
	data->main.monitor = pcsm_read_byte(client, PMCM_REG(PMCM_RO_MON_1));
	data->main.event = pcsm_read_byte(client, PMCM_REG(PMCM_RWC_HIST_1));
	data->main.table_size = 8;
	data->main.names = events_main_name;

	data->therm.id = therm_id;
	data->therm.monitor = pcsm_read_byte(client, PMCM_REG(PMCM_RO_MON_2));
	data->therm.event = pcsm_read_byte(client, PMCM_REG(PMCM_RWC_HIST_2));
	data->therm.table_size = 6;
	data->therm.names = events_therm_name;
}

static int pcsm_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct device *dev = &client->dev;
	struct device *hwmon_dev;
	struct pcsm_data *data;

	dev_dbg(dev, "%s()\n", __func__);

	data = devm_kzalloc(dev, sizeof(struct pcsm_data), GFP_KERNEL);
	if (!data) {
		return -ENOMEM;
	}

	data->client = client;
	mutex_init(&data->update_lock);
	mutex_init(&data->core_lock);

	data->core_address = 0;
	data->use_rcn = 0;
	data->rate = HZ;	/* 1 sec default */
	data->valid = 0;

	pcsm_init_data(data);

	/* hwmon */
	hwmon_dev = devm_hwmon_device_register_with_groups(dev, client->name,
							   data, pcsm_groups);
	if (IS_ERR(hwmon_dev)) {
		return PTR_ERR(hwmon_dev);
	}
	dev_info(dev, "registered: %s\n", dev_name(hwmon_dev));

#ifdef DEBUG
	dump_all_regs(data);
#endif

#ifdef CONFIG_DEBUG_FS
	pcsm_dbgfs_init(data);
#endif

	return 0;
} /* pcsm_probe */

#ifdef CONFIG_DEBUG_FS
static int pcsm_remove(struct i2c_client *client)
{
	struct pcsm_data *data = i2c_get_clientdata(client);

	dev_dbg(&client->dev, "%s()\n", __func__);

	if (data) {
		/* don't remove check if(data) !!! */
		pcsm_dbgfs_exit(data);
	}

	return 0;
}
#endif


/*---------------------------------------------------------------------------*/
/* Module part                                                               */
/*---------------------------------------------------------------------------*/

static const unsigned short normal_i2c[] = { 0x4c, I2C_CLIENT_END };

#ifdef CONFIG_OF
static const struct of_device_id pcsm_of_match[] = {
	{ .compatible = "mcst,pcsm" },
	{ }
};
MODULE_DEVICE_TABLE(of, pcsm_of_match);
#endif

/* Driver data (common to all clients) */
static const struct i2c_device_id pcsm_id[] = {
	{ KBUILD_MODNAME, 0 /*id*/ },
	{ }
};
MODULE_DEVICE_TABLE(i2c, pcsm_id);

static struct i2c_driver pcsm_driver = {
	.class		= I2C_CLASS_HWMON,
	.driver = {
		.name	= KBUILD_MODNAME,
#ifdef CONFIG_OF
		.of_match_table = of_match_ptr(pcsm_of_match),
#endif
		.owner	= THIS_MODULE,
	},
	.probe		= pcsm_probe,
#ifdef CONFIG_DEBUG_FS
	.remove		= pcsm_remove,
#endif
	.id_table	= pcsm_id,
	.detect		= pcsm_detect,
	.address_list	= normal_i2c,
};

static int __init pcsm_init(void)
{
	int err;

	pr_debug(KBUILD_MODNAME ": %s()\n", __func__);
	pr_info(KBUILD_MODNAME ": version %s\n", DRIVER_VERSION);

#ifdef CONFIG_DEBUG_FS
	pcsm_dbg_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (pcsm_dbg_root == NULL)
		pr_warn(KBUILD_MODNAME ": Init of debugfs failed\n");
#endif

	err = i2c_add_driver(&pcsm_driver);
	if (err) {
		pr_err(KBUILD_MODNAME ": Could not register driver\n");
#ifdef CONFIG_DEBUG_FS
		if (pcsm_dbg_root)
			debugfs_remove_recursive(pcsm_dbg_root);
#endif
	}

	return err;
}
module_init(pcsm_init);

static void __exit pcsm_exit(void)
{
	pr_debug(KBUILD_MODNAME ": %s()\n", __func__);

#ifdef CONFIG_DEBUG_FS
	if (pcsm_dbg_root) {
		debugfs_remove_recursive(pcsm_dbg_root);
	}
#endif
	i2c_del_driver(&pcsm_driver);
}
module_exit(pcsm_exit);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("Module for Power Control System. For E2C3, E12C, E16C. I2C client for external monitoring");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRIVER_VERSION);
