/*
 *  l_p1mon.c - Linux kernel module for
 * 	MCST designed Processor-1 i2c-slave monitoring module.
 *
 *  Copyright (c) 2013 Evgeny Kravtsunov <kravtsunov_e@mcst.ru>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/mutex.h>
#include <linux/delay.h>

#define L_P1MON_DRV_NAME	"l_p1mon"
#define DRIVER_VERSION		"1.0"

/* 64 Entries available */
#define L_P1MON_DATA_0_IN	0x00
#define L_P1MON_DATA_1_IN	0x01
#define L_P1MON_DATA_2_IN	0x02
#define L_P1MON_DATA_3_IN	0x03
#define L_P1MON_DATA_4_IN	0x04
#define L_P1MON_DATA_5_IN	0x05
#define L_P1MON_DATA_6_IN	0x06
#define L_P1MON_DATA_7_IN	0x07
#define L_P1MON_DATA_8_IN	0x08
#define L_P1MON_DATA_9_IN	0x09
#define L_P1MON_DATA_10_IN	0x0a
#define L_P1MON_DATA_11_IN	0x0b
#define L_P1MON_DATA_12_IN	0x0c
#define L_P1MON_DATA_13_IN	0x0d
#define L_P1MON_DATA_14_IN	0x0e
#define L_P1MON_DATA_15_IN	0x0f
#define L_P1MON_DATA_16_IN	0x10
#define L_P1MON_DATA_17_IN	0x11
#define L_P1MON_DATA_18_IN	0x12
#define L_P1MON_DATA_19_IN	0x13
#define L_P1MON_DATA_20_IN	0x14
#define L_P1MON_DATA_21_IN	0x15
#define L_P1MON_DATA_22_IN	0x16
#define L_P1MON_DATA_23_IN	0x17
#define L_P1MON_DATA_24_IN	0x18
#define L_P1MON_DATA_25_IN	0x19
#define L_P1MON_DATA_26_IN	0x1a
#define L_P1MON_DATA_27_IN	0x1b
#define L_P1MON_DATA_28_IN	0x1c
#define L_P1MON_DATA_29_IN	0x1d
#define L_P1MON_DATA_30_IN	0x1e
#define L_P1MON_DATA_31_IN	0x1f
#define L_P1MON_DATA_32_IN	0x20
#define L_P1MON_DATA_33_IN	0x21
#define L_P1MON_DATA_34_IN	0x22
#define L_P1MON_DATA_35_IN	0x23
#define L_P1MON_DATA_36_IN	0x24
#define L_P1MON_DATA_37_IN	0x25
#define L_P1MON_DATA_38_IN	0x26
#define L_P1MON_DATA_39_IN	0x27
#define L_P1MON_DATA_40_IN	0x28
#define L_P1MON_DATA_41_IN	0x29
#define L_P1MON_DATA_42_IN	0x2a
#define L_P1MON_DATA_43_IN	0x2b
#define L_P1MON_DATA_44_IN	0x2c
#define L_P1MON_DATA_45_IN	0x2d
#define L_P1MON_DATA_46_IN	0x2e
#define L_P1MON_DATA_47_IN	0x2f
#define L_P1MON_DATA_48_IN	0x30
#define L_P1MON_DATA_49_IN	0x31
#define L_P1MON_DATA_50_IN	0x32
#define L_P1MON_DATA_51_IN	0x33
#define L_P1MON_DATA_52_IN	0x34
#define L_P1MON_DATA_53_IN	0x35
#define L_P1MON_DATA_54_IN	0x36
#define L_P1MON_DATA_55_IN	0x37
#define L_P1MON_DATA_56_IN	0x38
#define L_P1MON_DATA_57_IN	0x39
#define L_P1MON_DATA_58_IN	0x3a
#define L_P1MON_DATA_59_IN	0x3b
#define L_P1MON_DATA_60_IN	0x3c
#define L_P1MON_DATA_61_IN	0x3d
#define L_P1MON_DATA_62_IN	0x3e
#define L_P1MON_DATA_63_IN	0x3f

/* addr_inc bit - OR him to entry address 
 * for autoincrement: 
 */
#define L_P1MON_INC_VAL		0x80

static int l_p1mon_init_client(struct i2c_client *client);
static struct l_p1mon_data *l_p1mon_update_data(struct device *dev);

struct l_p1mon_data {
	struct i2c_client *client;
	struct mutex lock;
	int autoincrement;
	unsigned long last_updated, rate; /* in jiffies */
	char valid; /* zero until following fields are valid */

	/* data from entries: */
	int data_0_in, data_1_in, data_2_in, data_3_in;
	int data_4_in, data_5_in, data_6_in, data_7_in;
	int data_8_in, data_9_in, data_10_in, data_11_in;
	int data_12_in, data_13_in, data_14_in, data_15_in;
	int data_16_in, data_17_in, data_18_in, data_19_in;
	int data_20_in, data_21_in, data_22_in, data_23_in;
	int data_24_in, data_25_in, data_26_in, data_27_in;
	int data_28_in, data_29_in, data_30_in, data_31_in;
	int data_32_in, data_33_in, data_34_in, data_35_in;
	int data_36_in, data_37_in, data_38_in, data_39_in;
	int data_40_in, data_41_in, data_42_in, data_43_in;
	int data_44_in, data_45_in, data_46_in, data_47_in;
	int data_48_in, data_49_in, data_50_in, data_51_in;
	int data_52_in, data_53_in, data_54_in, data_55_in;
	int data_56_in, data_57_in, data_58_in, data_59_in;
	int data_60_in, data_61_in, data_62_in, data_63_in;
};

/* Sysfs stuff */
#define show_entry(value)						\
static ssize_t show_##value(struct device *dev,				\
    struct device_attribute *attr, char *buf)				\
{									\
	struct l_p1mon_data *data = l_p1mon_update_data(dev);		\
									\
	if (data->value##_in < 0)					\
	   snprintf(buf, PAGE_SIZE - 1, "Error\n");			\
	else								\
	   snprintf(buf, PAGE_SIZE - 1, "%d\n",				\
				data->value##_in);			\
	return strlen(buf);						\
}

show_entry(data_0);
show_entry(data_1);
show_entry(data_2);
show_entry(data_3);
show_entry(data_4);
show_entry(data_5);
show_entry(data_6);
show_entry(data_7);
show_entry(data_8);
show_entry(data_9);
show_entry(data_10);
show_entry(data_11);
show_entry(data_12);
show_entry(data_13);
show_entry(data_14);
show_entry(data_15);
show_entry(data_16);
show_entry(data_17);
show_entry(data_18);
show_entry(data_19);
show_entry(data_20);
show_entry(data_21);
show_entry(data_22);
show_entry(data_23);
show_entry(data_24);
show_entry(data_25);
show_entry(data_26);
show_entry(data_27);
show_entry(data_28);
show_entry(data_29);
show_entry(data_30);
show_entry(data_31);
show_entry(data_32);
show_entry(data_33);
show_entry(data_34);
show_entry(data_35);
show_entry(data_36);
show_entry(data_37);
show_entry(data_38);
show_entry(data_39);
show_entry(data_40);
show_entry(data_41);
show_entry(data_42);
show_entry(data_43);
show_entry(data_44);
show_entry(data_45);
show_entry(data_46);
show_entry(data_47);
show_entry(data_48);
show_entry(data_49);
show_entry(data_50);
show_entry(data_51);
show_entry(data_52);
show_entry(data_53);
show_entry(data_54);
show_entry(data_55);
show_entry(data_56);
show_entry(data_57);
show_entry(data_58);
show_entry(data_59);
show_entry(data_60);
show_entry(data_61);
show_entry(data_62);
show_entry(data_63);

static DEVICE_ATTR(entry_0_value, S_IRUGO, show_data_0, NULL);
static DEVICE_ATTR(entry_1_value, S_IRUGO, show_data_1, NULL);
static DEVICE_ATTR(entry_2_value, S_IRUGO, show_data_2, NULL);
static DEVICE_ATTR(entry_3_value, S_IRUGO, show_data_3, NULL);
static DEVICE_ATTR(entry_4_value, S_IRUGO, show_data_4, NULL);
static DEVICE_ATTR(entry_5_value, S_IRUGO, show_data_5, NULL);
static DEVICE_ATTR(entry_6_value, S_IRUGO, show_data_6, NULL);
static DEVICE_ATTR(entry_7_value, S_IRUGO, show_data_7, NULL);
static DEVICE_ATTR(entry_8_value, S_IRUGO, show_data_8, NULL);
static DEVICE_ATTR(entry_9_value, S_IRUGO, show_data_9, NULL);
static DEVICE_ATTR(entry_10_value, S_IRUGO, show_data_10, NULL);
static DEVICE_ATTR(entry_11_value, S_IRUGO, show_data_11, NULL);
static DEVICE_ATTR(entry_12_value, S_IRUGO, show_data_12, NULL);
static DEVICE_ATTR(entry_13_value, S_IRUGO, show_data_13, NULL);
static DEVICE_ATTR(entry_14_value, S_IRUGO, show_data_14, NULL);
static DEVICE_ATTR(entry_15_value, S_IRUGO, show_data_15, NULL);
static DEVICE_ATTR(entry_16_value, S_IRUGO, show_data_16, NULL);
static DEVICE_ATTR(entry_17_value, S_IRUGO, show_data_17, NULL);
static DEVICE_ATTR(entry_18_value, S_IRUGO, show_data_18, NULL);
static DEVICE_ATTR(entry_19_value, S_IRUGO, show_data_19, NULL);
static DEVICE_ATTR(entry_20_value, S_IRUGO, show_data_20, NULL);
static DEVICE_ATTR(entry_21_value, S_IRUGO, show_data_21, NULL);
static DEVICE_ATTR(entry_22_value, S_IRUGO, show_data_22, NULL);
static DEVICE_ATTR(entry_23_value, S_IRUGO, show_data_23, NULL);
static DEVICE_ATTR(entry_24_value, S_IRUGO, show_data_24, NULL);
static DEVICE_ATTR(entry_25_value, S_IRUGO, show_data_25, NULL);
static DEVICE_ATTR(entry_26_value, S_IRUGO, show_data_26, NULL);
static DEVICE_ATTR(entry_27_value, S_IRUGO, show_data_27, NULL);
static DEVICE_ATTR(entry_28_value, S_IRUGO, show_data_28, NULL);
static DEVICE_ATTR(entry_29_value, S_IRUGO, show_data_29, NULL);
static DEVICE_ATTR(entry_30_value, S_IRUGO, show_data_30, NULL);
static DEVICE_ATTR(entry_31_value, S_IRUGO, show_data_31, NULL);
static DEVICE_ATTR(entry_32_value, S_IRUGO, show_data_32, NULL);
static DEVICE_ATTR(entry_33_value, S_IRUGO, show_data_33, NULL);
static DEVICE_ATTR(entry_34_value, S_IRUGO, show_data_34, NULL);
static DEVICE_ATTR(entry_35_value, S_IRUGO, show_data_35, NULL);
static DEVICE_ATTR(entry_36_value, S_IRUGO, show_data_36, NULL);
static DEVICE_ATTR(entry_37_value, S_IRUGO, show_data_37, NULL);
static DEVICE_ATTR(entry_38_value, S_IRUGO, show_data_38, NULL);
static DEVICE_ATTR(entry_39_value, S_IRUGO, show_data_39, NULL);
static DEVICE_ATTR(entry_40_value, S_IRUGO, show_data_40, NULL);
static DEVICE_ATTR(entry_41_value, S_IRUGO, show_data_41, NULL);
static DEVICE_ATTR(entry_42_value, S_IRUGO, show_data_42, NULL);
static DEVICE_ATTR(entry_43_value, S_IRUGO, show_data_43, NULL);
static DEVICE_ATTR(entry_44_value, S_IRUGO, show_data_44, NULL);
static DEVICE_ATTR(entry_45_value, S_IRUGO, show_data_45, NULL);
static DEVICE_ATTR(entry_46_value, S_IRUGO, show_data_46, NULL);
static DEVICE_ATTR(entry_47_value, S_IRUGO, show_data_47, NULL);
static DEVICE_ATTR(entry_48_value, S_IRUGO, show_data_48, NULL);
static DEVICE_ATTR(entry_49_value, S_IRUGO, show_data_49, NULL);
static DEVICE_ATTR(entry_50_value, S_IRUGO, show_data_50, NULL);
static DEVICE_ATTR(entry_51_value, S_IRUGO, show_data_51, NULL);
static DEVICE_ATTR(entry_52_value, S_IRUGO, show_data_52, NULL);
static DEVICE_ATTR(entry_53_value, S_IRUGO, show_data_53, NULL);
static DEVICE_ATTR(entry_54_value, S_IRUGO, show_data_54, NULL);
static DEVICE_ATTR(entry_55_value, S_IRUGO, show_data_55, NULL);
static DEVICE_ATTR(entry_56_value, S_IRUGO, show_data_56, NULL);
static DEVICE_ATTR(entry_57_value, S_IRUGO, show_data_57, NULL);
static DEVICE_ATTR(entry_58_value, S_IRUGO, show_data_58, NULL);
static DEVICE_ATTR(entry_59_value, S_IRUGO, show_data_59, NULL);
static DEVICE_ATTR(entry_60_value, S_IRUGO, show_data_60, NULL);
static DEVICE_ATTR(entry_61_value, S_IRUGO, show_data_61, NULL);
static DEVICE_ATTR(entry_62_value, S_IRUGO, show_data_62, NULL);
static DEVICE_ATTR(entry_63_value, S_IRUGO, show_data_63, NULL);


static ssize_t l_p1mon_show_rate(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct l_p1mon_data *data;

	data = i2c_get_clientdata(client);
        return sprintf(buf, "%ld\n", data->rate);
}

static ssize_t l_p1mon_store_rate(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct l_p1mon_data *data;
	unsigned long val;

	data = i2c_get_clientdata(client);

	if (strict_strtoul(buf, 10, &val) <= 0)
		return -EINVAL;

	data->rate = val;
	return count;
}

static DEVICE_ATTR(rate, S_IWUSR | S_IRUGO, l_p1mon_show_rate, 
						l_p1mon_store_rate);

static ssize_t l_p1mon_show_autoincrement(struct device *dev,
				struct device_attribute *attr, char *buf)
{
        struct i2c_client *client = to_i2c_client(dev);
        struct l_p1mon_data *data;

        data = i2c_get_clientdata(client);
        return sprintf(buf, "%d\n", data->autoincrement);
}

static ssize_t l_p1mon_store_autoincrement(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct l_p1mon_data *data;
	unsigned long val;

	data = i2c_get_clientdata(client);

	if (strict_strtoul(buf, 10, &val) < 0 || val > 1)
		return -EINVAL;

	data->autoincrement= val;
	return count;
}

static DEVICE_ATTR(autoincrement, S_IWUSR | S_IRUGO,
		l_p1mon_show_autoincrement, l_p1mon_store_autoincrement);

static struct attribute *l_p1mon_attributes[] = {
	&dev_attr_entry_0_value.attr,
	&dev_attr_entry_1_value.attr,
	&dev_attr_entry_2_value.attr,
	&dev_attr_entry_3_value.attr,
	&dev_attr_entry_4_value.attr,
	&dev_attr_entry_5_value.attr,
	&dev_attr_entry_6_value.attr,
	&dev_attr_entry_7_value.attr,
	&dev_attr_entry_8_value.attr,
	&dev_attr_entry_9_value.attr,
	&dev_attr_entry_10_value.attr,
	&dev_attr_entry_11_value.attr,
	&dev_attr_entry_12_value.attr,
	&dev_attr_entry_13_value.attr,
	&dev_attr_entry_14_value.attr,
	&dev_attr_entry_15_value.attr,
	&dev_attr_entry_16_value.attr,
	&dev_attr_entry_17_value.attr,
	&dev_attr_entry_18_value.attr,
	&dev_attr_entry_19_value.attr,
	&dev_attr_entry_20_value.attr,
	&dev_attr_entry_21_value.attr,
	&dev_attr_entry_22_value.attr,
	&dev_attr_entry_23_value.attr,
	&dev_attr_entry_24_value.attr,
	&dev_attr_entry_25_value.attr,
	&dev_attr_entry_26_value.attr,
	&dev_attr_entry_27_value.attr,
	&dev_attr_entry_28_value.attr,
	&dev_attr_entry_29_value.attr,
	&dev_attr_entry_30_value.attr,
	&dev_attr_entry_31_value.attr,
	&dev_attr_entry_32_value.attr,
	&dev_attr_entry_33_value.attr,
	&dev_attr_entry_34_value.attr,
	&dev_attr_entry_35_value.attr,
	&dev_attr_entry_36_value.attr,
	&dev_attr_entry_37_value.attr,
	&dev_attr_entry_38_value.attr,
	&dev_attr_entry_39_value.attr,
	&dev_attr_entry_40_value.attr,
	&dev_attr_entry_41_value.attr,
	&dev_attr_entry_42_value.attr,
	&dev_attr_entry_43_value.attr,
	&dev_attr_entry_44_value.attr,
	&dev_attr_entry_45_value.attr,
	&dev_attr_entry_46_value.attr,
	&dev_attr_entry_47_value.attr,
	&dev_attr_entry_48_value.attr,
	&dev_attr_entry_49_value.attr,
	&dev_attr_entry_50_value.attr,
	&dev_attr_entry_51_value.attr,
	&dev_attr_entry_52_value.attr,
	&dev_attr_entry_53_value.attr,
	&dev_attr_entry_54_value.attr,
	&dev_attr_entry_55_value.attr,
	&dev_attr_entry_56_value.attr,
	&dev_attr_entry_57_value.attr,
	&dev_attr_entry_58_value.attr,
	&dev_attr_entry_59_value.attr,
	&dev_attr_entry_60_value.attr,
	&dev_attr_entry_61_value.attr,
	&dev_attr_entry_62_value.attr,
	&dev_attr_entry_63_value.attr,
	&dev_attr_rate.attr,
	&dev_attr_autoincrement.attr,
        NULL
};

static const struct attribute_group l_p1mon_group = {
        .attrs = l_p1mon_attributes,
};

/*
 * I2C layer
 */
static struct l_p1mon_data *l_p1mon_update_data(struct device *dev) 
{
	struct i2c_client *client = to_i2c_client(dev);
	struct l_p1mon_data *data = i2c_get_clientdata(client);

	mutex_lock(&data->lock);

	if (time_after(jiffies, data->last_updated + data->rate) ||
	   !data->valid) {
		dev_dbg(&client->dev, "Updating l_p1mon_data.\n");
		if (data->autoincrement) { 
		   dev_dbg(&client->dev, "Ignore autoincrement: bad idea.\n");
		}

		data->data_0_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_0_IN);
		data->data_1_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_1_IN);
		data->data_2_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_2_IN);
		data->data_3_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_3_IN);
		data->data_4_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_4_IN);
		data->data_5_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_5_IN);
		data->data_6_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_6_IN);
		data->data_7_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_7_IN);
		data->data_8_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_8_IN);
		data->data_9_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_9_IN);
		data->data_10_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_10_IN);
		data->data_11_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_11_IN);
		data->data_12_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_12_IN);
		data->data_13_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_13_IN);
		data->data_14_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_14_IN);
		data->data_15_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_15_IN);
		data->data_16_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_16_IN);
		data->data_17_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_17_IN);
		data->data_18_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_18_IN);
		data->data_19_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_19_IN);
		data->data_20_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_20_IN);
		data->data_21_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_21_IN);
		data->data_22_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_22_IN);
		data->data_23_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_23_IN);
		data->data_24_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_24_IN);
		data->data_25_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_25_IN);
		data->data_26_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_26_IN);
		data->data_27_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_27_IN);
		data->data_28_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_28_IN);
		data->data_29_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_29_IN);
		data->data_30_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_30_IN);
		data->data_31_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_31_IN);
		data->data_32_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_32_IN);
		data->data_33_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_33_IN);
		data->data_34_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_34_IN);
		data->data_35_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_35_IN);
		data->data_36_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_36_IN);
		data->data_37_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_37_IN);
		data->data_38_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_38_IN);
		data->data_39_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_39_IN);
		data->data_40_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_40_IN);
		data->data_41_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_41_IN);
		data->data_42_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_42_IN);
		data->data_43_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_43_IN);
		data->data_44_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_44_IN);
		data->data_45_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_45_IN);
		data->data_46_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_46_IN);
		data->data_47_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_47_IN);
		data->data_48_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_48_IN);
		data->data_49_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_49_IN);
		data->data_50_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_50_IN);
		data->data_51_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_51_IN);
		data->data_52_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_52_IN);
		data->data_53_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_53_IN);
		data->data_54_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_54_IN);
		data->data_55_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_55_IN);
		data->data_56_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_56_IN);
		data->data_57_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_57_IN);
		data->data_58_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_58_IN);
		data->data_59_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_59_IN);
		data->data_60_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_60_IN);
		data->data_61_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_61_IN);
		data->data_62_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_62_IN);
		data->data_63_in = i2c_smbus_read_word_data(client, L_P1MON_DATA_63_IN);

		data->last_updated = jiffies;
                data->valid = 1;
        }

        mutex_unlock(&data->lock);

        return data;
}

static int l_p1mon_init_client(struct i2c_client *client)
{
	struct l_p1mon_data *data = i2c_get_clientdata(client);

	data->rate = HZ;    /* 1 sec default */
	data->valid = 0;
	data->autoincrement = 0;

	return 0;
}

static int __devinit l_p1mon_probe(struct i2c_client *client,
				    const struct i2c_device_id *id)
{
	struct i2c_adapter *adapter = to_i2c_adapter(client->dev.parent);
	struct l_p1mon_data *data;
	int err = 0;

	if (!i2c_check_functionality(adapter,  I2C_FUNC_SMBUS_WORD_DATA))
		return -EIO;

	data = kzalloc(sizeof(struct l_p1mon_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->client = client;
	i2c_set_clientdata(client, data);
	mutex_init(&data->lock);

	err = l_p1mon_init_client(client);
	if (err)
		goto exit_kfree;

	/* register sysfs hooks */
	err = sysfs_create_group(&client->dev.kobj, &l_p1mon_group);
	if (err)
		goto exit_kfree;

	dev_info(&client->dev, "l_p1mon driver version %s enabled\n", DRIVER_VERSION);
	return 0;

exit_kfree:
	kfree(data);
	return err;
}

static int __devexit l_p1mon_remove(struct i2c_client *client)
{
	sysfs_remove_group(&client->dev.kobj, &l_p1mon_group);
	kfree(i2c_get_clientdata(client));
	return 0;
}

static const struct i2c_device_id l_p1mon_id[] = {
	{ "l_p1mon", 0 },
	{}
};
MODULE_DEVICE_TABLE(i2c, l_p1mon_id);

static struct i2c_driver l_p1mon_driver = {
	.driver = {
		.name	= L_P1MON_DRV_NAME,
		.owner	= THIS_MODULE,
	},
	.probe	= l_p1mon_probe,
	.remove	= __devexit_p(l_p1mon_remove),
	.id_table = l_p1mon_id,
};

static int __init l_p1mon_init(void)
{
	return i2c_add_driver(&l_p1mon_driver);
}

static void __exit l_p1mon_exit(void)
{
	i2c_del_driver(&l_p1mon_driver);
}

MODULE_AUTHOR("Evgeny Kravtsunov <kravtsunov_e@mcst.ru>");
MODULE_DESCRIPTION("Processor-1 I2C slave driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRIVER_VERSION);

module_init(l_p1mon_init);
module_exit(l_p1mon_exit);

