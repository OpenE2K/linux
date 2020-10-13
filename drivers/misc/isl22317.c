/*
 *  isl22317.c - Linux kernel module for
 * 	Intersil ISL22317 precision single digitally controlled potentiometer.
 *
 *  Copyright (c) 2012 Evgeny Kravtsunov <kravtsunov_e@mcst.ru>
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

#define ISL22317_DRV_NAME	"isl22317"
#define DRIVER_VERSION		"1.0"

#define ISL22317_WIPER_REG	0x00 /* if (ACR.VOL) { WR accesible }
					else { IVR accessible } */
#define ISL22317_MSR_REG	0x01
#define ISL22317_ACR_REG	0x02

#define ISL22317_VIRT_IVR_REG	0x03

/* WR (Wiper Register) bits: */
#define ISL22317_WR_MASK	0x7f
#define ISL22317_WR_RL		0x00
#define ISL22317_WR_RH		0x7f

/* IVR (Initial Value Register) bits: */
#define ISL22317_IVR_MASK	0x7f
#define ISL22317_IVR_DEFAULT	0x40

/* ACR (Access Control Register) bits: */
#define ISL22317_ACR_VOL_SHIFT		7
#define ISL22317_ACR_VOL_MASK		(1 << ISL22317_ACR_VOL_SHIFT)
#define ISL22317_ACR_SHDN_SHIFT		6
#define ISL22317_ACR_SHDN_MASK		(1 <<  ISL22317_ACR_SHDN_SHIFT)
#define ISL22317_ACR_WIP_SHIFT		5
#define ISL22317_ACR_WIP_MASK		(1 << ISL22317_ACR_WIP_SHIFT)

/* MSR (Mode Select Register) bits: */
#define ISL22317_MSR_MODE_SHIFT		7
#define ISL22317_MSR_MODE_MASK		(1 << ISL22317_MSR_MODE_SHIFT)
#define ISL22317_MSR_PRECISION_SHIFT	6
#define ISL22317_MSR_PRECISION_MASK	(1 << ISL22317_MSR_PRECISION_SHIFT)

/* Common */
#define ISL22317_WIP_ATTEMPTS		10
#define ISL22317_NUM_REGS		3
#define ISL22317_NUM_CACHABLE_REGS	4 /* both IVR and WR have address 0x1
					   * we'll store MSR at 0x1 in cache,
					   * IVR - at 0x3 in cache	
					   */

struct isl22317_data {
	struct i2c_client *client;
	struct mutex lock;
	u8 reg_cache[ISL22317_NUM_CACHABLE_REGS];
};

/*
 * register access helpers
 */

static int __isl22317_read_reg(struct i2c_client *client,
			       u32 reg, u8 mask, u8 shift)
{
	struct isl22317_data *data = i2c_get_clientdata(client);
	return (data->reg_cache[reg] & mask) >> shift;
}

static int __isl22317_write_reg(struct i2c_client *client,
				u32 reg, u8 mask, u8 shift, u8 val)
{
	struct isl22317_data *data = i2c_get_clientdata(client);
	int ret = 0;
	u8 tmp;

	if (reg >= ISL22317_NUM_CACHABLE_REGS)
		return -EINVAL;

	mutex_lock(&data->lock);

	tmp = data->reg_cache[reg];
	tmp &= ~mask;
	tmp |= val << shift;

	if (reg == ISL22317_VIRT_IVR_REG)
		ret = i2c_smbus_write_byte_data(client, ISL22317_WIPER_REG, 
									tmp);
	else
		ret = i2c_smbus_write_byte_data(client, reg, tmp);

	if (!ret)
		data->reg_cache[reg] = tmp;

	mutex_unlock(&data->lock);
	return ret;
}

/*
 * internally used functions
 */

/* wip */
static u8 isl22317_get_wip(struct i2c_client *client)
{
	int ret = 0;

	ret = i2c_smbus_read_byte_data(client, ISL22317_ACR_REG);
	if (ret < 0)
		return -ENODEV;

	return (((u8)ret) & ISL22317_ACR_WIP_MASK) >> ISL22317_ACR_WIP_SHIFT;
}

static int isl22317_check_wip(struct i2c_client *client) 
{
	int count = 0;
retry:
	if (isl22317_get_wip(client)) {
		count++;
		if (count >= ISL22317_WIP_ATTEMPTS)
			return -EAGAIN;
		goto retry;
	}
	return 0;
}

/* vol */
static u8 isl22317_get_vol(struct i2c_client *client)
{
	return __isl22317_read_reg(client, ISL22317_ACR_REG,
		ISL22317_ACR_VOL_MASK, ISL22317_ACR_VOL_SHIFT);
}

static int isl22317_set_vol(struct i2c_client *client, u8 vol)
{
	return __isl22317_write_reg(client, ISL22317_ACR_REG,
		ISL22317_ACR_VOL_MASK, ISL22317_ACR_VOL_SHIFT, vol);
}

/* power_state */
static int isl22317_set_power_state(struct i2c_client *client, u8 state)
{
	if (isl22317_check_wip(client))
		return -EAGAIN;
	
	return __isl22317_write_reg(client, ISL22317_ACR_REG,
				ISL22317_ACR_SHDN_MASK, ISL22317_ACR_SHDN_SHIFT,
				state ? 1 : 0);
}

static u8 isl22317_get_power_state(struct i2c_client *client)
{
	struct isl22317_data *data = i2c_get_clientdata(client);
	u8 cmdreg = data->reg_cache[ISL22317_ACR_REG];
	return ((cmdreg & ISL22317_ACR_SHDN_MASK) >> ISL22317_ACR_SHDN_SHIFT);
}

/* wiper position */
static int isl22317_get_wiper(struct i2c_client *client)
{
	if (!isl22317_get_vol(client)) {
		if (!isl22317_check_wip(client)) {
			if (0 > isl22317_set_vol(client, 1))
				return -EINVAL;
		} else {
			return -EAGAIN;
		}
	}
	return __isl22317_read_reg(client, ISL22317_WIPER_REG,
		ISL22317_WR_MASK, 0);
}

static int isl22317_set_wiper(struct i2c_client *client, u8 wiper)
{
	if (!isl22317_get_vol(client)) {
		if (!isl22317_check_wip(client)) {
			if (0 > isl22317_set_vol(client, 1))
				return -EINVAL;
		} else {
			return -EAGAIN;
		}		
	}
	return __isl22317_write_reg(client, ISL22317_WIPER_REG,
		ISL22317_WR_MASK, 0, wiper);
}

/* initial value */
static int isl22317_get_ivalue(struct i2c_client *client)
{
	if (isl22317_get_vol(client)) {
		if (!isl22317_check_wip(client)) {
			if (0 > isl22317_set_vol(client, 0))
				return -EINVAL;
		} else {
			return -EAGAIN;
		}
	}
	return __isl22317_read_reg(client, ISL22317_VIRT_IVR_REG,
		ISL22317_IVR_MASK, 0);
}

static int isl22317_set_ivalue(struct i2c_client *client, u8 ivalue)
{
	if (isl22317_get_vol(client)) {
		if (!isl22317_check_wip(client)) {
			if (0 > isl22317_set_vol(client, 0))
				return -EINVAL;
		} else {
			return -EAGAIN;
		}
	}
	return __isl22317_write_reg(client, ISL22317_VIRT_IVR_REG,
		ISL22317_IVR_MASK, 0, ivalue);
}

/* precision */
static int isl22317_get_precision(struct i2c_client *client)
{
	if (isl22317_get_vol(client)) {
		if (!isl22317_check_wip(client)) {
			if (0 > isl22317_set_vol(client, 0))
				return -EINVAL;
		} else {
			return -EAGAIN;
		}
	}
	return __isl22317_read_reg(client, ISL22317_MSR_REG,
		ISL22317_MSR_PRECISION_MASK, ISL22317_MSR_PRECISION_SHIFT);
}

static int isl22317_set_precision(struct i2c_client *client, u8 precision)
{
	if (isl22317_get_vol(client)) {
		if (!isl22317_check_wip(client)) {
			if (0 > isl22317_set_vol(client, 0))
				return -EINVAL;
		} else {
			return -EAGAIN;
		}
	}
	return __isl22317_write_reg(client, ISL22317_MSR_REG,
		ISL22317_MSR_PRECISION_MASK, ISL22317_MSR_PRECISION_SHIFT,
		precision);
}

/* mode */
static int isl22317_get_mode(struct i2c_client *client)
{
	if (isl22317_get_vol(client)) {
		if (!isl22317_check_wip(client)) {
			if (0 > isl22317_set_vol(client, 0))
				return -EINVAL;
		} else {
			return -EAGAIN;
		}
	}
	return __isl22317_read_reg(client, ISL22317_MSR_REG,
		ISL22317_MSR_MODE_MASK, ISL22317_MSR_MODE_SHIFT);
}

static int isl22317_set_mode(struct i2c_client *client, u8 mode)
{
	if (isl22317_get_vol(client)) {
		if (!isl22317_check_wip(client)) {
			if (0 > isl22317_set_vol(client, 0))
				return -EINVAL;
		} else {
			return -EAGAIN;
		}
	}
	return __isl22317_write_reg(client, ISL22317_MSR_REG,
		ISL22317_MSR_MODE_MASK, ISL22317_MSR_MODE_SHIFT,
		mode);
}

/*
 * sysfs layer
 */

/* wiper */
static ssize_t isl22317_show_wiper(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	return sprintf(buf, "%i\n", isl22317_get_wiper(client));
}

static ssize_t isl22317_store_wiper(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long val;
	int ret;

	if ((strict_strtoul(buf, 10, &val) < ISL22317_WR_RL) || 
						(val > ISL22317_WR_RH))
		return -EINVAL;

	ret = isl22317_set_wiper(client, val);
	if (ret < 0)
		return ret;

	return count;
}

static DEVICE_ATTR(wiper, S_IWUSR | S_IRUGO,
		   isl22317_show_wiper, isl22317_store_wiper);


/* ivalue */
static ssize_t isl22317_show_ivalue(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	return sprintf(buf, "%i\n", isl22317_get_ivalue(client));
}

static ssize_t isl22317_store_ivalue(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long val;
	int ret;

	if ((strict_strtoul(buf, 10, &val) < ISL22317_WR_RL) ||
						(val > ISL22317_WR_RH))
		return -EINVAL;

	ret = isl22317_set_ivalue(client, val);
	if (ret < 0)
		return ret;

	return count;
}

static DEVICE_ATTR(ivalue, S_IWUSR | S_IRUGO,
		isl22317_show_ivalue, isl22317_store_ivalue);

/* precision */
static ssize_t isl22317_show_precision(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	return sprintf(buf, "%d\n", isl22317_get_precision(client));
}

static ssize_t isl22317_store_precision(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long val;
	int ret;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	ret = isl22317_set_precision(client, val);
	if (ret < 0)
		return ret;

	return count;
}

static DEVICE_ATTR(precision, S_IWUSR | S_IRUGO,
		   isl22317_show_precision, isl22317_store_precision);

/* mode */
static ssize_t isl22317_show_mode(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	return sprintf(buf, "%d\n", isl22317_get_mode(client));
}

static ssize_t isl22317_store_mode(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long val;
	int ret;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	ret = isl22317_set_mode(client, val);
	if (ret < 0)
		return ret;

	return count;
}

static DEVICE_ATTR(mode, S_IWUSR | S_IRUGO,
		   isl22317_show_mode, isl22317_store_mode);


/* power state */
static ssize_t isl22317_show_power_state(struct device *dev,
					 struct device_attribute *attr,
					 char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	return sprintf(buf, "%d\n", (int)isl22317_get_power_state(client));
}

static ssize_t isl22317_store_power_state(struct device *dev,
					  struct device_attribute *attr,
					  const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long val;
	int ret;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	ret = isl22317_set_power_state(client, val);
	return ret ? ret : count;
}

static DEVICE_ATTR(power_state, S_IWUSR | S_IRUGO,
		   isl22317_show_power_state, isl22317_store_power_state);

static int isl22317_init_client(struct i2c_client *client)
{
	int v;
	struct isl22317_data *data = i2c_get_clientdata(client);

	/* read all the registers once to fill the cache.
	 * if one of the reads fails, we consider the init failed */


	/* read ACR */
	v = i2c_smbus_read_byte_data(client, ISL22317_ACR_REG);
	if (v < 0)
		return -ENODEV;

	data->reg_cache[ISL22317_ACR_REG] = (u8)v;

	/* read MSR and IVR */
	if (isl22317_get_vol(client)) {
		if (!isl22317_check_wip(client)) {
			if (0 > isl22317_set_vol(client, 0))
				return -EINVAL;
		} else {
			return -EAGAIN;
		}
	}

	v = i2c_smbus_read_byte_data(client, ISL22317_MSR_REG);
	if (v < 0)
		return -ENODEV;

	data->reg_cache[ISL22317_MSR_REG] = (u8)v;

	v = i2c_smbus_read_byte_data(client, ISL22317_WIPER_REG);
	if (v < 0)
		return -ENODEV;

	data->reg_cache[ISL22317_VIRT_IVR_REG] = (u8)v;

	/* read WR */
	if (!isl22317_get_vol(client)) {
		if (!isl22317_check_wip(client)) {
			if (0 > isl22317_set_vol(client, 1))
				return -EINVAL;
		} else {
			return -EAGAIN;
		}
	}
	
	v = i2c_smbus_read_byte_data(client, ISL22317_WIPER_REG);
	if (v < 0)
		return -ENODEV;

	data->reg_cache[ISL22317_WIPER_REG] = (u8)v;

	/* set defaults */
	isl22317_set_wiper(client, ISL22317_IVR_DEFAULT);
	isl22317_set_precision(client, 1);
	isl22317_set_mode(client, 1);
	isl22317_set_power_state(client, 1);

	return 0;
}

static ssize_t isl22317_store_reinit_chip(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	int ret;

	ret = isl22317_init_client(client);

	return ret ? ret : count;
}

static DEVICE_ATTR(reinit_chip, S_IWUSR,
			NULL, isl22317_store_reinit_chip);

static struct attribute *isl22317_attributes[] = {
	&dev_attr_wiper.attr,
	&dev_attr_ivalue.attr,
	&dev_attr_precision.attr,
	&dev_attr_mode.attr,
	&dev_attr_power_state.attr,
	&dev_attr_reinit_chip.attr,
	NULL
};

static const struct attribute_group isl22317_attr_group = {
	.attrs = isl22317_attributes,
};

/*
 * I2C layer
 */

static int isl22317_probe(struct i2c_client *client,
				    const struct i2c_device_id *id)
{
	struct i2c_adapter *adapter = to_i2c_adapter(client->dev.parent);
	struct isl22317_data *data;
	int err = 0;

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE))
		return -EIO;

	data = kzalloc(sizeof(struct isl22317_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->client = client;
	i2c_set_clientdata(client, data);
	mutex_init(&data->lock);

	/* initialize the ISL22317 chip */
	err = isl22317_init_client(client);
	if (err)
		goto exit_kfree;

	/* register sysfs hooks */
	err = sysfs_create_group(&client->dev.kobj, &isl22317_attr_group);
	if (err)
		goto exit_kfree;

	dev_info(&client->dev, "driver version %s enabled\n", DRIVER_VERSION);
	return 0;

exit_kfree:
	kfree(data);
	return err;
}

static int isl22317_remove(struct i2c_client *client)
{
	sysfs_remove_group(&client->dev.kobj, &isl22317_attr_group);
	isl22317_set_power_state(client, 0);
	kfree(i2c_get_clientdata(client));
	return 0;
}

#ifdef CONFIG_PM
static int isl22317_suspend(struct i2c_client *client, pm_message_t mesg)
{
	return isl22317_set_power_state(client, 0);
}

static int isl22317_resume(struct i2c_client *client)
{
	return isl22317_set_power_state(client, 1);
}

#else
#define isl22317_suspend	NULL
#define isl22317_resume		NULL
#endif /* CONFIG_PM */

static const struct i2c_device_id isl22317_id[] = {
	{ "isl22317", 0 },
	{}
};
MODULE_DEVICE_TABLE(i2c, isl22317_id);

static struct i2c_driver isl22317_driver = {
	.driver = {
		.name	= ISL22317_DRV_NAME,
		.owner	= THIS_MODULE,
	},
	.suspend = isl22317_suspend,
	.resume	= isl22317_resume,
	.probe	= isl22317_probe,
	.remove	= isl22317_remove,
	.id_table = isl22317_id,
};

static int __init isl22317_init(void)
{
	return i2c_add_driver(&isl22317_driver);
}

static void __exit isl22317_exit(void)
{
	i2c_del_driver(&isl22317_driver);
}

MODULE_AUTHOR("Evgeny Kravtsunov <kravtsunov_e@mcst.ru>");
MODULE_DESCRIPTION("ISL22317 digitally controlled potentiometer driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRIVER_VERSION);

module_init(isl22317_init);
module_exit(isl22317_exit);

