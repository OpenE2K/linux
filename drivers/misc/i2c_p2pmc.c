/*
 * i2c_p2pmc.c - Support i2c p2pmc device.
 *
 * Copyright (C) 2013 Evgeny Kravtsunov <kravtsunov_e@mcst.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/err.h>
#include <linux/sysfs.h>
#include <linux/kernel.h>

#define I2C_P2PMC_WRITE_OP	0x80

#define I2C_P2PMC_REG_ADDR_0	0x0
#define I2C_P2PMC_REG_ADDR_1	0x1
#define I2C_P2PMC_REG_DATA_0	0x2
#define I2C_P2PMC_REG_DATA_1	0x3
#define I2C_P2PMC_REG_DATA_2	0x4
#define I2C_P2PMC_REG_DATA_3	0x5
#define I2C_P2PMC_REG_MASK	0x6

#define I2C_P2PMC_ADDR_BYTES	2
#define I2C_P2PMC_DATA_BYTES	4
#define I2C_P2PMC_MASK_BYTES	1

#define I2C_P2PMC_SIZE	(I2C_P2PMC_ADDR_BYTES + \
			 I2C_P2PMC_DATA_BYTES + \
			 I2C_P2PMC_MASK_BYTES)

#define I2C_MAX_BUFFER_SIZE	64

/* Internal address of PMC regs */
#define I2C_PMC_L_P_STATE_CNTRL_REG	0x9008
#define	I2C_PMC_L_TEMP_RG_CUR_REG_0	0x9020
#define I2C_PMC_L_TEMP_RG_CUR_REG_1	0x9024

/* Moortec temperature sensor values */
#define PMC_MOORTEC_TEMP_VALID		0x1000
#define PMC_MOORTEC_TEMP_VALUE_MASK	0xfff
#define PMC_MOORTEC_TEMP_K		63
#define PMC_MOORTEC_TEMP_VALUE_SHIFT	12

struct i2c_p2pmc_data {
	u8 address_0;
	u8 address_1;
	u8 data_0;
	u8 data_1;
	u8 data_2;
	u8 data_3;
	u8 bmask;
	u8 dbuffer[I2C_MAX_BUFFER_SIZE];
};

/* sysfs */
static ssize_t i2c_p2pmc_addr_read(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	u32 addr;
	u32 addr0;
	u32 addr1;
	struct i2c_p2pmc_data *data;

	data = i2c_get_clientdata(client);
	addr0 = (u32)(data->address_0);
	addr0 <<= 8;
	addr1 = (u32)(data->address_1);
	addr = addr0 + addr1;

	return sprintf(buf, "%d\n", addr);
}

static ssize_t i2c_p2pmc_addr_write(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long address;
	struct i2c_p2pmc_data *data;

	data = i2c_get_clientdata(client);

	if ((strict_strtoul(buf, 10, &address) < 0))
		return -EINVAL;

	data->address_0 = (address >> 8) & 0xFF;
	data->address_1 = address & 0xFF;

	return count;
}

static ssize_t i2c_p2pmc_data_read(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	u32 dvalue;
	u32 dvalue0;
	u32 dvalue1;
	u32 dvalue2;
	u32 dvalue3;
	struct i2c_p2pmc_data *data;

	data = i2c_get_clientdata(client);
	dvalue0 = (u32)(data->data_0);
	dvalue0 <<= 24;
	dvalue1 = (u32)(data->data_1);
	dvalue1 <<= 16;
	dvalue2 = (u32)(data->data_2);
	dvalue2 <<= 8;
	dvalue3 = (u32)(data->data_3);
	dvalue = dvalue3 + dvalue2 + dvalue1 + dvalue0;

	return sprintf(buf, "%d\n", dvalue);
}

static ssize_t i2c_p2pmc_data_write(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long val;
	struct i2c_p2pmc_data *data;

	data = i2c_get_clientdata(client);
	if ((strict_strtoul(buf, 10, &val) < 0))
		return -EINVAL;

	data->data_0 = (val >> 24) & 0xFF;
	data->data_1 = (val >> 16) & 0xFF;
	data->data_2 = (val >> 8) & 0xFF;
	data->data_3 = val & 0xFF;

	return count;
}

static ssize_t i2c_p2pmc_mask_read(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	s32 mask;
	struct i2c_p2pmc_data *data;

	data = i2c_get_clientdata(client);
	mask = (s32)(data->bmask);

	return sprintf(buf, "%d\n", mask);
}

static ssize_t i2c_p2pmc_mask_write(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long mask;
	struct i2c_p2pmc_data *data;

	data = i2c_get_clientdata(client);
	if ((strict_strtoul(buf, 10, &mask) < 0)) {
		return -EINVAL;
	}

	data->bmask = mask & 0xFF;
	return count;
}

static s32 i2c_p2pmc_do_read(struct device *dev, unsigned short pmcaddr)
{
	struct i2c_client *client = to_i2c_client(dev);
	s32 ret;
	u32 dvalue;
	u32 dvalue0;
	u32 dvalue1;
	u32 dvalue2;
	u32 dvalue3;
	struct i2c_p2pmc_data *data;

	data = i2c_get_clientdata(client);

	if (pmcaddr == 0) {
		/* Get preset addr and data values and write them to target */
		data->dbuffer[0] = data->address_0;
		data->dbuffer[1] = data->address_1;
	} else {
		data->dbuffer[0] = (pmcaddr >> 8) & 0xFF;
		data->dbuffer[1] = pmcaddr & 0xFF;
	}

	ret = i2c_smbus_write_block_data(client,
				I2C_P2PMC_REG_ADDR_0 & (~I2C_P2PMC_WRITE_OP),
				2,
				data->dbuffer);
	if (ret < 0) {
		printk(KERN_ERR "Failed to write addr to slave\n");
		return ret;
	}

	ret = i2c_smbus_read_i2c_block_data(client, I2C_P2PMC_REG_DATA_0,
							4, data->dbuffer);
	if (ret < 0) {
		printk(KERN_ERR "Failed to do reading ret = %d\n", ret);
		return ret;
	}

	data->data_0 = data->dbuffer[0];
	data->data_1 = data->dbuffer[1];
	data->data_2 = data->dbuffer[2];
	data->data_3 = data->dbuffer[3];

	dvalue0 = (u32)(data->dbuffer[0]);
	dvalue0 <<= 24;
	dvalue1 = (u32)(data->dbuffer[1]);
	dvalue1 <<= 16;
	dvalue2 = (u32)(data->dbuffer[2]);
	dvalue2 <<= 8;
	dvalue3 = (u32)(data->dbuffer[3]);
	dvalue = dvalue3 + dvalue2 + dvalue1 + dvalue0;

	return (s32) dvalue;
}

static ssize_t i2c_p2pmc_read_pmcaddr(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	s32 ret;

	ret = i2c_p2pmc_do_read(dev, 0);
	if (ret < 0)
		return sprintf(buf, "Error\n");
	else
		return sprintf(buf, "%d\n", ret);
}

static ssize_t i2c_p2pmc_pstate_read(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	s32 ret;

	ret = i2c_p2pmc_do_read(dev, I2C_PMC_L_P_STATE_CNTRL_REG);
	if (ret < 0)
		return sprintf(buf, "Error\n");
	else
		return sprintf(buf, "%d\n", ret);
}

static ssize_t i2c_p2pmc_temp0_read(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	s32 ret;
	u32 temp;
	u32 frac;

	ret = i2c_p2pmc_do_read(dev, I2C_PMC_L_TEMP_RG_CUR_REG_0);
	if (ret < 0) {
		return sprintf(buf, "Error\n");
	} else {
		temp = (u32) ret;
		if (temp & PMC_MOORTEC_TEMP_VALID) {
			temp &= PMC_MOORTEC_TEMP_VALUE_MASK;
			frac = (temp * 233) & PMC_MOORTEC_TEMP_VALUE_MASK;
			temp = ((temp * 233) >> PMC_MOORTEC_TEMP_VALUE_SHIFT) -
							PMC_MOORTEC_TEMP_K;

			return sprintf(buf, "%d.%d\n", temp, frac);
		}
		return sprintf(buf, "Bad value\n");
	}
}

static ssize_t i2c_p2pmc_temp1_read(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	s32 ret;
	u32 temp;
	u32 frac;

	ret = i2c_p2pmc_do_read(dev, I2C_PMC_L_TEMP_RG_CUR_REG_1);
	if (ret < 0) {
		return sprintf(buf, "Error\n");
	} else {
		temp = (u32) ret;
		if (temp & PMC_MOORTEC_TEMP_VALID) {
			temp &= PMC_MOORTEC_TEMP_VALUE_MASK;
			frac = (temp * 233) & PMC_MOORTEC_TEMP_VALUE_MASK;
			temp = ((temp * 233) >> PMC_MOORTEC_TEMP_VALUE_SHIFT) -
							PMC_MOORTEC_TEMP_K;

			return sprintf(buf, "%d.%d\n", temp, frac);
		}
		return sprintf(buf, "Bad value\n");
	}
}

static DEVICE_ATTR(data, S_IRWXU, i2c_p2pmc_data_read, i2c_p2pmc_data_write);
static DEVICE_ATTR(address, S_IRWXU, i2c_p2pmc_addr_read, i2c_p2pmc_addr_write);
static DEVICE_ATTR(mask, S_IRWXU, i2c_p2pmc_mask_read, i2c_p2pmc_mask_write);
static DEVICE_ATTR(read, S_IRUSR, i2c_p2pmc_read_pmcaddr, NULL);
static DEVICE_ATTR(pstate, S_IRUSR, i2c_p2pmc_pstate_read, NULL);
static DEVICE_ATTR(temp0, S_IRUSR, i2c_p2pmc_temp0_read, NULL);
static DEVICE_ATTR(temp1, S_IRUSR, i2c_p2pmc_temp1_read, NULL);

static struct attribute *i2c_p2pmc_attributes[] = {
	&dev_attr_data.attr,
	&dev_attr_address.attr,
	&dev_attr_mask.attr,
	&dev_attr_read.attr,
	&dev_attr_pstate.attr,
	&dev_attr_temp0.attr,
	&dev_attr_temp1.attr,
	NULL
};

static const struct attribute_group i2c_p2pmc_attr_group = {
	.attrs = i2c_p2pmc_attributes,
};

static int i2c_p2pmc_probe(struct i2c_client *client,
						const struct i2c_device_id *id)
{
	struct i2c_adapter *adapter = to_i2c_adapter(client->dev.parent);
	struct i2c_p2pmc_data *data;
	int err = 0;

	if (!i2c_check_functionality(adapter, (I2C_FUNC_SMBUS_BYTE |
			I2C_FUNC_SMBUS_BLOCK_DATA | I2C_FUNC_10BIT_ADDR)))
		return -EIO;

	data = kzalloc(sizeof(struct i2c_p2pmc_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	i2c_set_clientdata(client, data);

	err = sysfs_create_group(&client->dev.kobj, &i2c_p2pmc_attr_group);
	if (err) {
		kfree(data);
		return err;
	}

	return 0;
}

static int i2c_p2pmc_remove(struct i2c_client *client)
{
	struct i2c_p2pmc_data *data;

	data = i2c_get_clientdata(client);
	if (data) {
		sysfs_remove_group(&client->dev.kobj, &i2c_p2pmc_attr_group);
		kfree(data);
	}
	return 0;
}

static const struct i2c_device_id i2c_p2pmc_id[] = {
	{ "i2c_p2pmc", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, i2c_p2pmc_id);

static struct i2c_driver i2c_p2pmc_driver = {
	.driver = {
		.name   = "i2c_p2pmc",
	},
	.probe          = i2c_p2pmc_probe,
	.remove         = i2c_p2pmc_remove,
	.id_table       = i2c_p2pmc_id,
};

static int __init i2c_p2pmc_init(void)
{
	return i2c_add_driver(&i2c_p2pmc_driver);
}

static void __exit i2c_p2pmc_exit(void)
{
	i2c_del_driver(&i2c_p2pmc_driver);
}

MODULE_AUTHOR("Evgeny Kravtsunov <kravtsunov_e@mcst.ru>");
MODULE_DESCRIPTION("i2c p2pmc device driver");
MODULE_LICENSE("GPL");

module_init(i2c_p2pmc_init);
module_exit(i2c_p2pmc_exit);
