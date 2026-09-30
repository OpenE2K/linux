/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * ds125df111.c - Multi-Protocol 2-Channel 9.8 - 12.5 Gb/s Retimer
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/mod_devicetable.h>
#include <linux/mutex.h>
#include <linux/of_device.h>
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif


#define DRIVER_VERSION "1.0.0"


struct ds125df111_data {
	struct mutex lock;
	struct i2c_client *client;
#ifdef CONFIG_DEBUG_FS
	struct dentry *ds125df111_dbg;
#endif
	u8 reg_last_value;
};


static int read_reg(struct ds125df111_data *data, u8 reg)
{
	int ret;

	ret = i2c_smbus_read_byte_data(data->client, reg);
	if (ret < 0)
		dev_err(&data->client->dev, "read_reg (0x%X) error\n", reg);

	return ret;
}

static int write_reg(struct ds125df111_data *data, u8 reg, u8 val)
{
	int ret;

	ret = i2c_smbus_write_byte_data(data->client, reg, val);
	if (ret < 0)
		dev_err(&data->client->dev, "write_reg (0x%X) error\n", reg);

	return ret;
}

struct reg_data {
	u8 cmd;		/* 0 - write, 2 - delay, 0xFF - last record */
	u8 reg;		/* sec for delay */
	u8 val;		/* ms  gor delay */
	u8 mask;
};

static struct reg_data regdat[] = {
	/* cmd   reg   val  mask */
	/* -= chipreset=- */
	{ 0x00, 0xFF, 0x00, 0xFF }, /* select shared register */
	{ 0x00, 0x04, 0x40, 0xFF }, /* reset (W1C) */
	{ 0x02, 0x00, 0x10, 0x00 }, /* sleep 1 */
	{ 0x00, 0xFF, 0x0C, 0xFF }, /* enable broadcast (A+B) */
	{ 0x00, 0x00, 0x04, 0x04 }, /* channel reset (W1C) */
	{ 0x02, 0x00, 0x10, 0x00 }, /* sleep 1 */
	{ 0x00, 0xFF, 0x00, 0xFF }, /* select shared register */
	/* -= sequence =- */
	{ 0x00, 0xFF, 0x0C, 0xFF }, /* enable broadcast (A+B) */
	{ 0x00, 0x00, 0x04, 0x04 }, /* channel reset (W1C) */
	{ 0x02, 0x00, 0x10, 0x00 }, /* sleep 1 */
	/* sequence3 */
	{ 0x00, 0x09, 0x24, 0xFF }, /* Enable override 0x18, 0x1E */
	{ 0x00, 0x18, 0x00, 0xFF }, /* 7.1.5.14 - VCO Devider - Full-Rate */
	{ 0x00, 0x1E, 0x01, 0xFF }, /* 7.5.1.13 - Output Mux - RAW Data */
	/* sequence4 */
	{ 0x00, 0x2F, 0x06, 0xFF }, /* 7.5.1.11 - RATE|SUBRATE - 8|1 */
	{ 0x00, 0x60, 0x00, 0xFF }, /* Table 12 */
	{ 0x00, 0x61, 0xB2, 0xFF }, /* >>> */
	{ 0x00, 0x62, 0x90, 0xFF }, /* VCC0 G0/G1: */
	{ 0x00, 0x63, 0xB3, 0xFF }, /* 10.0/10.3125 */
	{ 0x00, 0x64, 0xCD, 0xFF }, /* <<< */
	{ 0x00, 0x2D, 0x80, 0xFF }, /* 7.5.1.12 - VOD = 600mV (default) */
	{ 0x00, 0x15, 0x10, 0xFF }, /* Table 25 - De-emphasis = 0dB (default) */
	{ 0x00, 0x0A, 0x1C, 0xFF }, /* 7.5.1.10 - CDR Reset */
	{ 0x02, 0x00, 0x10, 0x00 }, /* sleep 1 */
	{ 0x00, 0x0A, 0x10, 0xFF }, /* Clean CDR Reset */
	{ 0x00, 0xFF, 0x00, 0xFF }, /* select shared register */
	/* end */
	{ 0xFF, 0x00, 0x00, 0x00 }  /* end */
};

static int first_init(struct ds125df111_data *data)
{
	int ret = 0;
	int i = 0;
	u8 val, pval;

	mutex_lock(&data->lock);

	while (regdat[i].cmd != 0xFF) {
		switch (regdat[i].cmd) {
		case 0x00: /* write */
			ret = read_reg(data, regdat[i].reg);
			if (ret < 0) {
				break;
			} else {
				pval = (u8)ret;
				val = (pval & ~regdat[i].mask) | regdat[i].val;
				dev_dbg(&data->client->dev,
					"init: write %02x %02x\n",
					regdat[i].reg, val);
				ret = write_reg(data, regdat[i].reg, val);
				if (ret < 0)
					break;
			}
			break;
		case 0x02:
			mutex_unlock(&data->lock);
			dev_dbg(&data->client->dev,
				"init: sleep %d\n",
				(regdat[i].reg * 1000) + regdat[i].val);
			mdelay((regdat[i].reg * 1000) + regdat[i].val);
			mutex_lock(&data->lock);
			break;
		default:
			break;
		} /* switch */
		i += 1;
	} /* while */

	mutex_unlock(&data->lock);

	return ret;
}


/** TITLE: DEBUG_FS stuff */

#ifdef CONFIG_DEBUG_FS
/* Usage: mount -t debugfs none /sys/kernel/debug */
/* for debug level: */
/* echo 8 > /proc/sys/kernel/printk */

/* /sys/kernel/debug/ds125df111/<dev>/reg_ops */
static char ds125df111_dbg_regs_buf[256] = "";

static ssize_t dbg_regs_read(struct file *filp, char __user *buffer,
			     size_t count, loff_t *ppos)
{
	struct ds125df111_data *data = filp->private_data;
	char *buf;
	int len;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	buf = kasprintf(GFP_KERNEL, "0x%02x\n", data->reg_last_value);
	if (!buf)
		return -ENOMEM;

	if (count < strlen(buf)) {
		kfree(buf);
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	kfree(buf);
	return len;
}

static ssize_t dbg_regs_write(struct file *filp, const char __user *buffer,
			      size_t count, loff_t *ppos)
{
	struct ds125df111_data *data = filp->private_data;
	int len;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;

	if (count >= sizeof(ds125df111_dbg_regs_buf))
		return -ENOSPC;

	len = simple_write_to_buffer(ds125df111_dbg_regs_buf,
				     sizeof(ds125df111_dbg_regs_buf)-1,
				     ppos,
				     buffer,
				     count);
	if (len < 0)
		return len;

	ds125df111_dbg_regs_buf[len] = '\0';

	if (strncmp(ds125df111_dbg_regs_buf, "write", 5) == 0) {
		u8 reg, pval, val, mask;
		int ret;
		int cnt;

		cnt = sscanf(&ds125df111_dbg_regs_buf[5], "%hhi %hhi %hhi",
			     &reg, &val, &mask);
		if (cnt == 3) {
			mutex_lock(&data->lock);
			ret = read_reg(data, reg);
			if (ret < 0) {
				data->reg_last_value = 0xFF;
			} else {
				pval = (u8)ret;
				val = (pval & ~mask) | val;
				data->reg_last_value = val;
				ret = write_reg(data, reg, val);
				if (ret < 0) {
					data->reg_last_value = 0xFF;
				}
			}
			mutex_unlock(&data->lock);
		} else {
			data->reg_last_value = 0xFF;
			dev_warn(&data->client->dev,
				 "reg_ops usage: write <reg> <val> <mask>\n");
		}
	} else if (strncmp(ds125df111_dbg_regs_buf, "read", 4) == 0) {
		u8 reg;
		int ret;
		int cnt;

		cnt = sscanf(&ds125df111_dbg_regs_buf[4], "%hhi", &reg);
		if (cnt == 1) {
			mutex_lock(&data->lock);
			ret = read_reg(data, reg);
			if (ret < 0) {
				data->reg_last_value = 0xFF;
			} else {
				data->reg_last_value = (u8)ret;
			}
			mutex_unlock(&data->lock);
		} else {
			data->reg_last_value = 0xFF;
			dev_warn(&data->client->dev,
				 "debugfs reg_ops usage: read <reg>\n");
		}
	} else {
		data->reg_last_value = 0xFF;
		dev_warn(&data->client->dev,
			 "debugfs reg_ops: Unknown command %s\n",
			 ds125df111_dbg_regs_buf);
		pr_cont("    Available commands (fields size 1 byte):\n");
		pr_cont("      read <reg>\n");
		pr_cont("      write <reg> <val> <mask>\n");
	}

	return count;
}

static const struct file_operations ds125df111_dbg_regs_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = dbg_regs_read,
	.write = dbg_regs_write,
};

/* /sys/kernel/debug/ds125df111/ */
static struct dentry *ds125df111_dbg_root = NULL;

static void dbgfs_init(struct i2c_client *client, const char *label)
{
	struct dentry *pfile;
	struct ds125df111_data *data = i2c_get_clientdata(client);

	data->ds125df111_dbg = debugfs_create_dir(label, ds125df111_dbg_root);
	if (data->ds125df111_dbg) {
		/* regs */
		pfile = debugfs_create_file("reg_ops", 0600,
					    data->ds125df111_dbg, data,
					    &ds125df111_dbg_regs_fops);
		if (!pfile) {
			dev_err(&client->dev,
				"debugfs reg_ops for %s failed\n", label);
		}
	} else {
		dev_err(&client->dev, "debugfs entry for %s failed\n", label);
	}
}

static void dbgfs_exit(struct i2c_client *client)
{
	struct ds125df111_data *data = i2c_get_clientdata(client);

	if (data->ds125df111_dbg)
		debugfs_remove_recursive(data->ds125df111_dbg);

	data->ds125df111_dbg = NULL;
}

#endif /* CONFIG_DEBUG_FS */


/** TITLE: I2C driver stuff */

static int probe(struct i2c_client *client)
{
	struct ds125df111_data *data;
	struct device *dev = &client->dev;
	const char *label = dev_name(dev);
	int ret;

	data = devm_kzalloc(dev, sizeof(struct ds125df111_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	mutex_init(&data->lock);
	data->client = client;

	if (device_property_present(dev, "label"))
		device_property_read_string(dev, "label", &label);

	i2c_set_clientdata(client, data);

	/* Check DS125DF111 ID == 0x61 */

	ret = write_reg(data, 0xFF, 0); /* select shared registers */
	if (ret < 0)
		return -ENODEV;

	ret = read_reg(data, 0x01); /* ID */
	if (ret < 0)
		return -ENODEV;

	if ((u8)ret != 0x61) {
		dev_err(dev, "DS125DF111 chip not found, exit");
		return -ENODEV;
	}

	dev_info(dev, "found %s %s\n", client->name, label);

	ret = first_init(data);
	if (ret == 0) {
		dev_info(dev, "first init - done");
	} else {
		dev_warn(dev, "error on first init");
	}

#ifdef CONFIG_DEBUG_FS
	dbgfs_init(client, label);
#endif

	return 0;
}

static int remove(struct i2c_client *client)
{
	struct ds125df111_data *data = i2c_get_clientdata(client);

#ifdef CONFIG_DEBUG_FS
	dbgfs_exit(client);
#endif

	mutex_destroy(&data->lock);

	return 0;
}


/** TITLE: module stuff */

static const unsigned short normal_i2c[] = {0x18, I2C_CLIENT_END};

static const struct i2c_device_id ds125df111_ids[] = {
	{ KBUILD_MODNAME, 0 },
	{ },
};
MODULE_DEVICE_TABLE(i2c, ds125df111_ids);

#ifdef CONFIG_OF
static const struct of_device_id ds125df111_of_match[] = {
	{ .compatible = "ti,ds125df111" },
	{ },
};
MODULE_DEVICE_TABLE(of, ds125df111_of_match);
#endif

static struct i2c_driver ds125df111_driver = {
	.driver = {
		.name = KBUILD_MODNAME,
#ifdef CONFIG_OF
		.of_match_table = of_match_ptr(ds125df111_of_match),
#endif
		.owner	= THIS_MODULE,
	},
	.probe_new = probe,
	.remove = remove,
	.id_table = ds125df111_ids,
	.address_list = normal_i2c,
};

static int __init ds125df111_init(void)
{
	int ret;

	pr_info(KBUILD_MODNAME ": Retimer driver v" DRIVER_VERSION "\n");

#ifdef CONFIG_DEBUG_FS
	ds125df111_dbg_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (ds125df111_dbg_root == NULL)
		pr_warn(KBUILD_MODNAME ": Init of debugfs failed\n");
#endif

	ret = i2c_add_driver(&ds125df111_driver);
	if (ret != 0) {
		pr_err(KBUILD_MODNAME ": Could not register driver\n");
#ifdef CONFIG_DEBUG_FS
		if (ds125df111_dbg_root)
			debugfs_remove_recursive(ds125df111_dbg_root);
#endif
	}

	return ret;
}
module_init(ds125df111_init);

static void __exit ds125df111_exit(void)
{
	i2c_del_driver(&ds125df111_driver);

#ifdef CONFIG_DEBUG_FS
	if (ds125df111_dbg_root)
		debugfs_remove_recursive(ds125df111_dbg_root);
#endif
}
module_exit(ds125df111_exit);


MODULE_DESCRIPTION("Driver for DS125DF111 Multi-Protocol 2-Channel Retimer");
MODULE_AUTHOR("MCST");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRIVER_VERSION);
