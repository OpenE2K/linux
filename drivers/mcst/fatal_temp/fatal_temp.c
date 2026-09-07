/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>
#include <linux/io.h>
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>

#define PMC_BASE 0x1000
#define PMC_TERM_CTRL_ADDR 0x00C
#define PMC_TEMP_SHIFT 20
#define PMC_TEMP_MASK 0x1FF00000
#define PMC_TEMP_NULL_MASK 0xF00FFFFF
#define PMC_SAVE_MASK 0x7FFFFFFF
#define T_FATAL_MIN 40
#define T_FATAL_MAX 255
#define T_FATAL_NORMAL 110

static DEFINE_MUTEX(write_reg_mutex);

struct fatal_temp_data {
	int node;
	void __iomem *base;
#ifdef CONFIG_DEBUG_FS
	struct dentry *dbgfs_fatal;
#endif
};

#ifdef CONFIG_DEBUG_FS
static ssize_t fatal_temp_read(struct file *filp, char __user *buffer,
			      size_t count, loff_t *ppos)
{
	char str[300];
	size_t len = 0;
	int T_fatal = 0;
	int PMC_DBG_val;
	pcs_ctrl2_e8c2_t ctrl_e8c2;
	pcs_ctrl2_e8c_t ctrl_e8c;
	void __iomem *base_addr;
	struct fatal_temp_data *ftdata = file_inode(filp)->i_private;

	if (!ftdata)
		return -ENODEV;

	base_addr = ftdata->base;

	if (IS_MACHINE_E8C2) {
		ctrl_e8c2.word = readl(base_addr);
		T_fatal = ctrl_e8c2.t_fatal;
	} else if (IS_MACHINE_E8C) {
		ctrl_e8c.word = readl(base_addr);
		T_fatal = ctrl_e8c.t_fatal_int;
	} else if (IS_MACHINE_E16C || IS_MACHINE_E12C || IS_MACHINE_E2C3) {
		PMC_DBG_val = readl(base_addr) & PMC_SAVE_MASK;
		T_fatal = (PMC_DBG_val & PMC_TEMP_MASK) >> PMC_TEMP_SHIFT;
	}
	len += snprintf(str + len, sizeof(str) - len,
		"NODE-%d: The fatal temperature is set to %d degrees\n",
							ftdata->node, T_fatal);
	len += snprintf(str + len, sizeof(str) - len,
			"Please enter fatal temperature between 40 and 255 degrees\n");
	return simple_read_from_buffer(buffer, count, ppos, str, strlen(str));
}

static ssize_t fatal_temp_write(struct file *filp, const char __user *buffer,
			      size_t count, loff_t *ppos)
{
	long ret;
	int write_value;
	int PMC_DBG_val;
	long set_temp;
	pcs_ctrl2_e8c2_t ctrl_e8c2;
	pcs_ctrl2_e8c_t ctrl_e8c;
	void __iomem *base_addr;
	struct fatal_temp_data *ftdata = file_inode(filp)->i_private;

	if (!ftdata)
		return -ENODEV;

	base_addr = ftdata->base;
	ret = kstrtol_from_user(buffer, count, 10, &set_temp);
	if (ret) {
		pr_warn("Temperature scan failed");
		return -EFAULT;
	}

	if (set_temp < T_FATAL_MIN) {
		set_temp = T_FATAL_MIN;
	} else if (set_temp > T_FATAL_MAX) {
		set_temp = T_FATAL_MAX;
	}
	mutex_lock(&write_reg_mutex);
	if (IS_MACHINE_E8C2) {
		ctrl_e8c2.word = readl(base_addr);
		ctrl_e8c2.t_fatal = set_temp;
		writel(ctrl_e8c2.word, base_addr);
	} else if (IS_MACHINE_E8C) {
		ctrl_e8c.word = readl(base_addr);
		ctrl_e8c.t_fatal_int = set_temp;
		writel(ctrl_e8c.word, base_addr);
	} else if (IS_MACHINE_E16C || IS_MACHINE_E12C || IS_MACHINE_E2C3) {
		PMC_DBG_val = readl(base_addr) & PMC_SAVE_MASK;
		write_value = (PMC_DBG_val & PMC_TEMP_NULL_MASK) |
						(set_temp << PMC_TEMP_SHIFT);
		writel(write_value, base_addr);
	}
	mutex_unlock(&write_reg_mutex);
	return count;
}

static const struct file_operations fatal_file = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = fatal_temp_read,
	.write = fatal_temp_write,

};
#endif


static ssize_t fatal_show(struct device *dev, struct device_attribute *attr, char *buffer)
{
	int T_fatal = 0;
	int PMC_DBG_val;
	char *str;
	pcs_ctrl2_e8c2_t ctrl_e8c2;
	pcs_ctrl2_e8c_t ctrl_e8c;
	void __iomem *base_addr;
	struct fatal_temp_data *ftdata = dev_get_drvdata(dev);

	if (!ftdata)
		return -ENODEV;

	base_addr = ftdata->base;

	if (IS_MACHINE_E8C2) {
		ctrl_e8c2.word = readl(base_addr);
		T_fatal = ctrl_e8c2.t_fatal;
	} else if (IS_MACHINE_E8C) {
		ctrl_e8c.word = readl(base_addr);
		T_fatal = ctrl_e8c.t_fatal_int;
	} else if (IS_MACHINE_E16C || IS_MACHINE_E12C || IS_MACHINE_E2C3) {
		PMC_DBG_val = readl(base_addr) & PMC_SAVE_MASK;
		T_fatal = (PMC_DBG_val & PMC_TEMP_MASK) >> PMC_TEMP_SHIFT;
	}

	if (T_fatal == T_FATAL_MAX) {
		str = "Fatal temperature is maximum";
	} else if (T_fatal == T_FATAL_NORMAL) {
		str = "Fatal temperature is normal";
	} else {
		str = "Debug mode is enabled";
	}

	return sprintf(buffer, "NODE-%d: %s\n", ftdata->node, str);
}

static ssize_t fatal_store(struct device *dev, struct device_attribute *attr,
						const char *buffer, size_t count)
{
	int PMC_TERM_CTRL_val;
	int write_value;
	long int in_val;
	long int ret;
	pcs_ctrl2_e8c2_t ctrl_e8c2;
	pcs_ctrl2_e8c_t ctrl_e8c;
	void __iomem *base_addr;
	struct fatal_temp_data *ftdata = dev_get_drvdata(dev);

	if (!ftdata)
		return -ENODEV;

	base_addr = ftdata->base;
	ret = kstrtol(buffer, 10, &in_val);
	if (ret) {
		pr_warn("Input value scan failed");
		return -EFAULT;
	}

	if (in_val) {
		mutex_lock(&write_reg_mutex);
		if (IS_MACHINE_E8C2) {
			ctrl_e8c2.word = readl(base_addr);
			ctrl_e8c2.t_fatal = T_FATAL_MAX;
			writel(ctrl_e8c2.word, base_addr);
		} else if (IS_MACHINE_E8C) {
			ctrl_e8c.word = readl(base_addr);
			ctrl_e8c.t_fatal_int = T_FATAL_MAX;
			writel(ctrl_e8c.word, base_addr);
		} else if (IS_MACHINE_E16C || IS_MACHINE_E12C || IS_MACHINE_E2C3) {
			PMC_TERM_CTRL_val = readl(base_addr) & PMC_SAVE_MASK;
			write_value = (PMC_TERM_CTRL_val & PMC_TEMP_NULL_MASK) |
							(T_FATAL_MAX << PMC_TEMP_SHIFT);
			writel(write_value, base_addr);
		}
		mutex_unlock(&write_reg_mutex);
	} else if (!in_val) {
		mutex_lock(&write_reg_mutex);
		if (IS_MACHINE_E8C2) {
			ctrl_e8c2.word = readl(base_addr);
			ctrl_e8c2.t_fatal = T_FATAL_NORMAL;
			writel(ctrl_e8c2.word, base_addr);
		} else if (IS_MACHINE_E8C) {
			ctrl_e8c.word = readl(base_addr);
			ctrl_e8c.t_fatal_int = T_FATAL_NORMAL;
			writel(ctrl_e8c.word, base_addr);
		} else if (IS_MACHINE_E16C || IS_MACHINE_E12C || IS_MACHINE_E2C3) {
			PMC_TERM_CTRL_val = readl(base_addr) & PMC_SAVE_MASK;
			write_value = (PMC_TERM_CTRL_val & PMC_TEMP_NULL_MASK) |
							(T_FATAL_NORMAL << PMC_TEMP_SHIFT);
			writel(write_value, base_addr);
		}
		mutex_unlock(&write_reg_mutex);
	}
	return count;
}

static DEVICE_ATTR(fatal_temp, 0600, fatal_show, fatal_store);

static struct attribute *fatal_attrs[] = {
	&dev_attr_fatal_temp.attr,
	NULL,
};

static const struct attribute_group fatal_group = {
	.attrs = fatal_attrs,
};

static int fatal_init(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct fatal_temp_data *ftdata;
	struct dentry *dbgfs_fatal;
	void __iomem *base;
	struct resource *r;
	int node;
	int ret;

	if (!IS_MACHINE_E8C && !IS_MACHINE_E8C2 && !IS_MACHINE_E2C3 && !IS_MACHINE_E16C &&
			!IS_MACHINE_E12C)
		return 0;

	ftdata = devm_kzalloc(dev, sizeof(*ftdata), GFP_KERNEL);
	if (!ftdata)
		return -ENOMEM;

	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!r) {
		dev_err(dev, "failed to get mem resource\n");
		return -ENOMEM;
	}
	base = devm_ioremap(dev, r->start, resource_size(r));
	if (IS_ERR(base)) {
		dev_err(dev, "failed to map resource\n");
		return PTR_ERR(base);
	}

	ftdata->base = base;
	node = dev_to_node(dev);

	if (node == -1)
		node++;

	ftdata->node = node;
	dev_set_drvdata(dev, ftdata);

#ifdef CONFIG_DEBUG_FS
	struct dentry *pfile;
	char name[32];
	snprintf(name, sizeof(name), "fatal_temp_dbg_%d", node);

	dbgfs_fatal = debugfs_create_dir(name, NULL);
	if (dbgfs_fatal) {
		pfile = debugfs_create_file("fatal_temp_dbg", 0600,
						dbgfs_fatal, ftdata, &fatal_file);
		if (!pfile) {
			pr_warn("debugfs create file fatal failed\n");
		}
	} else {
		pr_warn("debugfs create_dir failed\n");
	}
	ftdata->dbgfs_fatal = dbgfs_fatal;
#endif

	ret = devm_device_add_group(dev, &fatal_group);
	if (ret) {
		dev_err(dev, "Failed to create sysfs group %d\n", ret);
#ifdef CONFIG_DEBUG_FS
		debugfs_remove_recursive(ftdata->dbgfs_fatal);
		ftdata->dbgfs_fatal = NULL;
#endif
		return ret;
	}
	return 0;
}

static int fatal_exit(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct fatal_temp_data *ftdata = dev_get_drvdata(dev);

	if (!ftdata)
		return -ENODEV;

	if (!IS_MACHINE_E8C && !IS_MACHINE_E8C2 && !IS_MACHINE_E2C3 && !IS_MACHINE_E16C &&
			!IS_MACHINE_E12C)
		return 0;

#ifdef CONFIG_DEBUG_FS
	if (ftdata->dbgfs_fatal) {
		debugfs_remove_recursive(ftdata->dbgfs_fatal);
		ftdata->dbgfs_fatal = NULL;
	}
#endif
	return 0;
}

static const struct of_device_id fatal_temp_of_match[] = {
	{ .compatible = "mcst,fatal_temp", },
	{},
};

static struct platform_driver fatal_temp_driver = {
	.driver = {
		.name = "fatal_temp",
		.of_match_table = fatal_temp_of_match,
	},
	.probe = fatal_init,
	.remove = fatal_exit,
};

module_platform_driver(fatal_temp_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("Module for setting fatal temperature");
