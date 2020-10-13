/*
 *  ucd9080.c - Linux kernel module for
 *  Texas Instruments 8-channel power-supply sequencer and monitor.
 *
 *  Copyright (c) 2012-2013 Andrey Kuyan <kuyan_a@mcst.ru>
 *  		  2012-2013 Evgeny Kravtsunov <kravtsunov_e@mcst.ru>
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
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/mutex.h>

#define UCD9080_DRV_NAME                "ucd9080"
#define DRIVER_VERSION                  "0.01"

/* RAIL registers: |--RAIL1H--|--RAIL1L--|...|--RAIL8L--|
 * adjustment (+1) when reading RAIL1H - RAIL8H,
 * or (-15) when reading RAIL8L */
#define UCD9080_RAIL_START_R_REG	0x00
#define UCD9080_RAILS_TOTAL		16
/* ERROR registers: |--ERROR1--|--ERROR2--|...|--ERROR6--| */
#define UCD9080_ERRORSTART_R_REG	0x20
/* Status: */
#define UCD9080_STATUS_R_REG		0x26
/* Version: */
#define UCD9080_VERSION_R_REG		0x27
/* Railstatus: |--RAILSTATUS2--|--RAILSTATUS1--| */
#define UCD9080_RAILSTATUS_START_R_REG	0x29
/* Flashlock (cachable): */
#define UCD9080_FLASHLOCK_RW_REG	0x2E
/* Restart: */
#define UCD9080_RESTART_W_REG		0x2F
/* Waddr (cachable): |--WADDR2--|--WADDR1--| */
#define UCD9080_WADDR_START_RW_REG	0x31
/* Wdata (cachable): |--WDATA2--|--WDATA1--| */
#define UCD9080_WDATA_START_RW_REG	0x33

/* Common */
/* Flashstates: */
#define UCD9080_FLASHSTATE_LOCK		0x00
#define UCD9080_FLASHSTATE_UNLOCK	0x02

/* Restart value: */
#define UCD9080_RESTART_VALUE		0x00

/* Configuration values */
#define UCD9080_CONF_WADDR_START	0xE000
#define UCD9080_CONF_WDATA_UPDATE	0xBADC

/* I2C Write block size (in bytes) */
#define UCD9080_I2C_WRITE_BLOCK_SIZE	32
#define UCD9080_I2C_READ_BLOCK_SIZE	UCD9080_I2C_WRITE_BLOCK_SIZE

/* Total conf buffer size */
#define UCD9080_CONF_BUFFER_SIZE	512
#define UCD9080_CONF_ITERATIONS		(UCD9080_CONF_BUFFER_SIZE / \
						UCD9080_I2C_WRITE_BLOCK_SIZE)

/* Init sequence: ranges 0xE080-0xE0A8 and 0xE100-0xE188 are tunable */
static const unsigned char ucd9080_initseq[UCD9080_CONF_BUFFER_SIZE] = {
/* 0xE000 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE008 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE010 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE018 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE020 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE028 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE030 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE038 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE040 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE048 */	0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE050 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE058 */	0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x02,
/* 0xE060 */	0x00, 0x00, 0x00, 0x0f, 0x00, 0x02, 0x00, 0x02,
/* 0xE068 */	0xff, 0x0f, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
/* 0xE070 */	0x00, 0x00, 0xc0, 0x20, 0x00, 0x00, 0x00, 0x00,
/* 0xE078 */	0x00, 0x00, 0x00, 0x00, 0x00, 0xa8, 0xdc, 0xba,
/* 0xE080 */	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
/* 0xE088 */	0x00, 0x49, 0x4a, 0x4b, 0x01, 0x00, 0x01, 0x04,
/* 0xE090 */	0x01, 0x04, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00,
/* 0xE098 */	0x05, 0xe0, 0x05, 0xa0, 0x32, 0xe0, 0x33, 0xe0,
/* 0xE0A0 */	0x33, 0xe0, 0x35, 0xe0, 0x35, 0xe0, 0x00, 0x00,
/* 0xE0A8 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE0B0 */	0xff, 0x7f, 0xff, 0x7f, 0xff, 0x7f, 0xff, 0x7f,
/* 0xE0B8 */	0xff, 0x7f, 0xff, 0x7f, 0xff, 0x7f, 0xff, 0x7f,
/* 0xE0C0 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE0C8 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE0D0 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE0D8 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE0E0 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE0E8 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE0F0 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE0F8 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE100 */	0x7f, 0x00, 0x01, 0x00, 0x02, 0x00, 0x04, 0x00,
/* 0xE108 */	0x08, 0x00, 0x10, 0x00, 0x20, 0x00, 0x40, 0x00,
/* 0xE110 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE118 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE120 */	0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04,
/* 0xE128 */	0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04,
/* 0xE130 */	0xa0, 0x0f, 0xa0, 0x0f, 0xa0, 0x0f, 0xa0, 0x0f,
/* 0xE138 */	0xa0, 0x0f, 0xa0, 0x0f, 0xa0, 0x0f, 0xa0, 0x0f,
/* 0xE140 */	0x10, 0x00, 0x10, 0x00, 0x10, 0x00, 0x10, 0x00,
/* 0xE148 */	0x10, 0x00, 0x10, 0x00, 0x10, 0x00, 0x10, 0x00,
/* 0xE150 */	0xff, 0xc0, 0xff, 0xc1, 0xff, 0xc2, 0xff, 0xc3,
/* 0xE158 */	0xff, 0xc4, 0xff, 0xc5, 0xff, 0xc6, 0xff, 0xc7,
/* 0xE160 */	0x00, 0x00, 0x00, 0xc0, 0x00, 0xc0, 0x00, 0xc0,
/* 0xE168 */	0x04, 0x20, 0x08, 0x20, 0x04, 0x18, 0x02, 0x18,
/* 0xE170 */	0x08, 0x18, 0x10, 0x18, 0x20, 0x18, 0x10, 0x20,
/* 0xE178 */	0x00, 0x20, 0x20, 0x20, 0x40, 0x20, 0x80, 0x20,
/* 0xE180 */	0x00, 0x00, 0x00, 0x04, 0x94, 0x02, 0xf2, 0x08,
/* 0xE188 */	0x10, 0x03, 0x05, 0xc0, 0x40, 0x00, 0xff, 0x08,
/* 0xE190 */	0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE198 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE1A0 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE1A8 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE1B0 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE1B8 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE1C0 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE1C8 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE1D0 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE1D8 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE1E0 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE1E8 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE1F0 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0xE1F8 */	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

struct ucd9080_data {
	struct i2c_client *client;
	struct mutex lock;
	int adapter_supports_blocks;
};

/*
 * sysfs layer
 */

/* rail values */
static ssize_t ucd9080_show_railvalues(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	int len;
	int value;
	unsigned char railvalues[UCD9080_I2C_READ_BLOCK_SIZE];
	struct ucd9080_data *data;
	int i;

	data = i2c_get_clientdata(client);
	if (data->adapter_supports_blocks) {
		len = i2c_smbus_read_block_data(client,
						UCD9080_RAIL_START_R_REG,
						railvalues);
		if (len < 0)
			return sprintf(buf, "Error\n");
	} else { /* adapter does not support block reads */
		len = 0;
		for (i = 0; i < (UCD9080_RAILS_TOTAL>>1); i++) {
			value = i2c_smbus_read_word_data(client,
						UCD9080_RAIL_START_R_REG);
			if (value < 0)
				return sprintf(buf, "Error\n");

			((unsigned short *)railvalues)[i] =
							(unsigned short) value;
			len += 2;
		}
	}

	if (len != UCD9080_RAILS_TOTAL)
		return sprintf(buf, "Error\n");

	return sprintf(buf, "%i %i %i %i %i %i %i %i\n",
			((unsigned short *)railvalues)[0],
			((unsigned short *)railvalues)[1],
			((unsigned short *)railvalues)[2],
			((unsigned short *)railvalues)[3],
			((unsigned short *)railvalues)[4],
			((unsigned short *)railvalues)[5],
			((unsigned short *)railvalues)[6],
			((unsigned short *)railvalues)[7]);
}
static DEVICE_ATTR(railvalues, S_IRUSR, ucd9080_show_railvalues, NULL);

/* TODO: reading out errors FIFO buffer and parsing them */

/* status */
static ssize_t ucd9080_show_status(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	int status;

	status = i2c_smbus_read_byte_data(client, UCD9080_STATUS_R_REG);
	if (status < 0)
		return sprintf(buf, "Error\n");

	return sprintf(buf, "%i\n", status);
}
static DEVICE_ATTR(status, S_IRUSR, ucd9080_show_status, NULL);

/* version */
static ssize_t ucd9080_show_version(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	int version;

	version = i2c_smbus_read_byte_data(client, UCD9080_VERSION_R_REG);
	if (version < 0)
		return sprintf(buf, "Error\n");

	return sprintf(buf, "%i\n", version);
}
static DEVICE_ATTR(version, S_IRUSR, ucd9080_show_version, NULL);

/* railstatus */
static ssize_t ucd9080_show_railstatus(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	int railstatus;

	railstatus = i2c_smbus_read_word_data(client,
					UCD9080_RAILSTATUS_START_R_REG);
	if (railstatus < 0)
		return sprintf(buf, "Error\n");

	return sprintf(buf, "%i\n", railstatus);
}
static DEVICE_ATTR(railstatus, S_IRUSR, ucd9080_show_railstatus, NULL);

/* restart */
static ssize_t ucd9080_store_restart(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long val;
	int ret;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	ret = i2c_smbus_write_byte_data(client, UCD9080_RESTART_W_REG,
						UCD9080_RESTART_VALUE);
	if (ret < 0)
		return ret;

	return count;
}
static DEVICE_ATTR(restart, S_IWUSR, NULL, ucd9080_store_restart);

static struct attribute *ucd9080_attributes[] = {
	&dev_attr_railvalues.attr,
	&dev_attr_status.attr,
	&dev_attr_version.attr,
	&dev_attr_railstatus.attr,
	&dev_attr_restart.attr,
	NULL
};

static const struct attribute_group ucd9080_attr_group = {
	.attrs = ucd9080_attributes,
};

static int ucd9080_init_chip(struct i2c_client *client)
{
	struct ucd9080_data *data = i2c_get_clientdata(client);
	int i, ii;
	unsigned short waddr = UCD9080_WADDR_START_RW_REG;
	unsigned char write_block[I2C_SMBUS_BLOCK_MAX + 2];
	int err = 0;

	/* Flashstate unlock */
	err = i2c_smbus_write_byte_data(client, UCD9080_FLASHLOCK_RW_REG,
						UCD9080_FLASHSTATE_UNLOCK);
	if (err)
		return err;
	/* Write WADDR start */
	err = i2c_smbus_write_word_data(client, UCD9080_WADDR_START_RW_REG,
						UCD9080_CONF_WADDR_START);
	if (err)
		return err;
	/* Write WDATA memory update constant */
	err = i2c_smbus_write_word_data(client, UCD9080_WDATA_START_RW_REG,
						UCD9080_CONF_WDATA_UPDATE);
	if (err)
		return err;

	for (i = 0; i < UCD9080_CONF_ITERATIONS; i++) {
		/* WADDR */
		err = i2c_smbus_write_word_data(client,
					UCD9080_WADDR_START_RW_REG,
					waddr);
		if (err)
			return err;

		if (data->adapter_supports_blocks) {
			/* WDATA (block) */
			write_block[0] = UCD9080_I2C_WRITE_BLOCK_SIZE;
			memcpy(&write_block[1], 
					(ucd9080_initseq + 
					(i*UCD9080_I2C_WRITE_BLOCK_SIZE)),
					UCD9080_I2C_WRITE_BLOCK_SIZE);
			err = i2c_smbus_write_block_data(client,
						UCD9080_WDATA_START_RW_REG,
						UCD9080_I2C_WRITE_BLOCK_SIZE,
						write_block);
			 if (err)
				return err;
		} else { /* adapter supports word only */
			for (ii = 0; ii < (UCD9080_I2C_WRITE_BLOCK_SIZE>>1);
								    ii += 2) {
				err = i2c_smbus_write_word_data(client,
					UCD9080_WDATA_START_RW_REG,
					((unsigned short *)ucd9080_initseq)[ii]);
				if (err)
					return err;
			}
		}

		waddr += UCD9080_I2C_WRITE_BLOCK_SIZE;
	}
	/* Flashstate lock */
	err = i2c_smbus_write_byte_data(client, UCD9080_FLASHLOCK_RW_REG,
						UCD9080_FLASHSTATE_LOCK);
	return err;
}

/*
 * I2C layer
 */

static int ucd9080_probe(struct i2c_client *client,
				const struct i2c_device_id *id)
{
	struct i2c_adapter *adapter = to_i2c_adapter(client->dev.parent);
	struct ucd9080_data *data;
	int err = 0;
	int adapter_supports_blocks = 1;

	if (!i2c_check_functionality(adapter, (I2C_FUNC_SMBUS_BYTE |
						I2C_FUNC_SMBUS_BLOCK_DATA))) {
		adapter_supports_blocks = 0;
		if (!i2c_check_functionality(adapter, (I2C_FUNC_SMBUS_BYTE |
						I2C_FUNC_SMBUS_WORD_DATA))) {
			return -EIO;
		}
	}

	data = kzalloc(sizeof(struct ucd9080_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->client = client;
	data->adapter_supports_blocks = adapter_supports_blocks;
	i2c_set_clientdata(client, data);
	mutex_init(&data->lock);

	/* initialization of UCD9080 chip */
	err = ucd9080_init_chip(client);
	if (err)
		goto exit_kfree;

	/* register sysfs hooks  */
	err = sysfs_create_group(&client->dev.kobj, &ucd9080_attr_group);
	if (err)
		goto exit_kfree;

	dev_info(&client->dev, "driver version %s enable\n", DRIVER_VERSION);
	return 0;

exit_kfree:
	kfree(data);
	return err;
}

static int ucd9080_remove(struct i2c_client *client)
{
	struct ucd9080_data *data;

	data = i2c_get_clientdata(client);
	if (data) {
		sysfs_remove_group(&client->dev.kobj, &ucd9080_attr_group);
		kfree(data);
	}
	return 0;
}

#define ucd9080_suspend		NULL
#define ucd9080_resume		NULL

static const struct i2c_device_id ucd9080_id[] = {
	{ "ucd9080", 0},
	{}
};
MODULE_DEVICE_TABLE(i2c, ucd9080_id);

static struct i2c_driver ucd9080_driver = {
	.driver = {
		.name  = UCD9080_DRV_NAME,
		.owner = THIS_MODULE,
	},
	.suspend = ucd9080_suspend,
	.resume = ucd9080_resume,
	.probe = ucd9080_probe,
	.remove = ucd9080_remove,
	.id_table = ucd9080_id,
};

static int __init ucd9080_init(void)
{
	return i2c_add_driver(&ucd9080_driver);
}

static void __exit ucd9080_exit(void)
{
	i2c_del_driver(&ucd9080_driver);
}

MODULE_AUTHOR("Andrey Kuyan <kuyan_a@mcst.ru>");
MODULE_DESCRIPTION("TI 8-channel power-supply sequencer and monitor");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRIVER_VERSION);

module_init(ucd9080_init);
module_exit(ucd9080_exit);
