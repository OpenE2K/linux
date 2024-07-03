/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <asm/sic_regs.h>
#include <linux/err.h>
#include <linux/mutex.h>
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif

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

#ifdef CONFIG_DEBUG_FS
static ssize_t fatal_temp_read(struct file *filp, char __user *buffer,
			      size_t count, loff_t *ppos)
{
	char str[300];
	size_t len;
	int curr_node;
	int T_fatal;
	int PMC_DBG_val;
	pcs_ctrl2_e8c2_t ctrl_e8c2;
	pcs_ctrl2_e8c_t ctrl_e8c;

	for_each_online_node(curr_node) {
		if (IS_MACHINE_E8C2) {
			ctrl_e8c2.word = sic_read_node_nbsr_reg(curr_node, SIC_pcs_ctrl2);
			T_fatal = ctrl_e8c2.t_fatal;
		} else if (IS_MACHINE_E8C) {
			ctrl_e8c.word = sic_read_node_nbsr_reg(curr_node, SIC_pcs_ctrl2);
			T_fatal = ctrl_e8c.t_fatal_int;
		} else if (IS_MACHINE_E16C || IS_MACHINE_E12C || IS_MACHINE_E2C3) {
			PMC_DBG_val = sic_read_node_nbsr_reg(curr_node,
						PMC_BASE + PMC_TERM_CTRL_ADDR) & PMC_SAVE_MASK;
			T_fatal = (PMC_DBG_val & PMC_TEMP_MASK) >> PMC_TEMP_SHIFT;
		}
		len += snprintf(str + len, sizeof(str) - len,
			"NODE-%d: The fatal temperature is set to %d degrees\n",
								curr_node, T_fatal);
	}
	len += snprintf(str + len, sizeof(str) - len,
			"Please enter fatal temperature between 40 and 255 degrees\n");
	return simple_read_from_buffer(buffer, count, ppos, str, strlen(str));
}

static ssize_t fatal_temp_write(struct file *filp, const char __user *buffer,
			      size_t count, loff_t *ppos)
{
	long ret;
	int curr_node;
	int write_value;
	int PMC_DBG_val;
	long set_temp;
	pcs_ctrl2_e8c2_t ctrl_e8c2;
	pcs_ctrl2_e8c_t ctrl_e8c;

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
	for_each_online_node(curr_node) {
		if (IS_MACHINE_E8C2) {
			ctrl_e8c2.word = sic_read_node_nbsr_reg(curr_node, SIC_pcs_ctrl2);
			ctrl_e8c2.t_fatal = set_temp;
			sic_write_node_nbsr_reg(curr_node, SIC_pcs_ctrl2, ctrl_e8c2.word);
		} else if (IS_MACHINE_E8C) {
			ctrl_e8c.word = sic_read_node_nbsr_reg(curr_node, SIC_pcs_ctrl2);
			ctrl_e8c.t_fatal_int = set_temp;
			sic_write_node_nbsr_reg(curr_node, SIC_pcs_ctrl2, ctrl_e8c.word);
		} else if (IS_MACHINE_E16C || IS_MACHINE_E12C || IS_MACHINE_E2C3) {
			PMC_DBG_val = sic_read_node_nbsr_reg(curr_node,
						PMC_BASE + PMC_TERM_CTRL_ADDR) & PMC_SAVE_MASK;
			write_value = (PMC_DBG_val & PMC_TEMP_NULL_MASK) |
							(set_temp << PMC_TEMP_SHIFT);
			sic_write_node_nbsr_reg(curr_node,
						PMC_BASE + PMC_TERM_CTRL_ADDR, write_value);
		}
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
static struct dentry *dbgfs_fatal;
#endif

static struct kobject *fatal_kobj;

static ssize_t fatal_show(struct kobject *kobj, struct kobj_attribute *attr, char *buffer)
{
	int T_fatal;
	int PMC_DBG_val;
	char *str;
	pcs_ctrl2_e8c2_t ctrl_e8c2;
	pcs_ctrl2_e8c_t ctrl_e8c;

	if (IS_MACHINE_E8C2) {
		ctrl_e8c2.word = sic_read_node_nbsr_reg(first_online_node, SIC_pcs_ctrl2);
		T_fatal = ctrl_e8c2.t_fatal;
	} else if (IS_MACHINE_E8C) {
		ctrl_e8c.word = sic_read_node_nbsr_reg(first_online_node, SIC_pcs_ctrl2);
		T_fatal = ctrl_e8c.t_fatal_int;
	} else if (IS_MACHINE_E16C || IS_MACHINE_E12C || IS_MACHINE_E2C3) {
		PMC_DBG_val = sic_read_node_nbsr_reg(first_online_node,
					PMC_BASE + PMC_TERM_CTRL_ADDR) & PMC_SAVE_MASK;
		T_fatal = (PMC_DBG_val & PMC_TEMP_MASK) >> PMC_TEMP_SHIFT;
	}

	if (T_fatal == T_FATAL_MAX) {
		str = "Fatal temperature is maximum";
	} else if (T_fatal == T_FATAL_NORMAL) {
		str = "Fatal temperaturee is normal";
	} else {
		str = "Debug mode is enabled";
	}

	return sprintf(buffer, "%s\n", str);
}

static ssize_t fatal_store(struct kobject *kobj, struct kobj_attribute *attr,
						const char *buffer, size_t count)
{
	int PMC_TERM_CTRL_val;
	int curr_node;
	int write_value;
	long int in_val;
	long int ret;
	pcs_ctrl2_e8c2_t ctrl_e8c2;
	pcs_ctrl2_e8c_t ctrl_e8c;

	ret = kstrtol(buffer, 10, &in_val);
	if (ret) {
		pr_warn("Input value scan failed");
		return -EFAULT;
	}

	if (in_val) {
		mutex_lock(&write_reg_mutex);
		for_each_online_node(curr_node) {
			if (IS_MACHINE_E8C2) {
				ctrl_e8c2.word = sic_read_node_nbsr_reg(curr_node, SIC_pcs_ctrl2);
				ctrl_e8c2.t_fatal = T_FATAL_MAX;
				sic_write_node_nbsr_reg(curr_node, SIC_pcs_ctrl2, ctrl_e8c2.word);
			} else if (IS_MACHINE_E8C) {
				ctrl_e8c.word = sic_read_node_nbsr_reg(curr_node, SIC_pcs_ctrl2);
				ctrl_e8c.t_fatal_int = T_FATAL_MAX;
				sic_write_node_nbsr_reg(curr_node, SIC_pcs_ctrl2, ctrl_e8c.word);
			} else if (IS_MACHINE_E16C || IS_MACHINE_E12C || IS_MACHINE_E2C3) {
				PMC_TERM_CTRL_val = sic_read_node_nbsr_reg(curr_node,
						PMC_BASE + PMC_TERM_CTRL_ADDR) & PMC_SAVE_MASK;
				write_value = (PMC_TERM_CTRL_val & PMC_TEMP_NULL_MASK) |
								(T_FATAL_MAX << PMC_TEMP_SHIFT);
				sic_write_node_nbsr_reg(curr_node,
							PMC_BASE + PMC_TERM_CTRL_ADDR, write_value);
			}
		}
		mutex_unlock(&write_reg_mutex);
	} else if (!in_val) {
		mutex_lock(&write_reg_mutex);
		for_each_online_node(curr_node) {
			if (IS_MACHINE_E8C2) {
				ctrl_e8c2.word = sic_read_node_nbsr_reg(curr_node, SIC_pcs_ctrl2);
				ctrl_e8c2.t_fatal = T_FATAL_NORMAL;
				sic_write_node_nbsr_reg(curr_node, SIC_pcs_ctrl2, ctrl_e8c2.word);
			} else if (IS_MACHINE_E8C) {
				ctrl_e8c.word = sic_read_node_nbsr_reg(curr_node, SIC_pcs_ctrl2);
				ctrl_e8c.t_fatal_int = T_FATAL_NORMAL;
				sic_write_node_nbsr_reg(curr_node, SIC_pcs_ctrl2, ctrl_e8c.word);
			} else if (IS_MACHINE_E16C || IS_MACHINE_E12C || IS_MACHINE_E2C3) {
				PMC_TERM_CTRL_val = sic_read_node_nbsr_reg(curr_node,
						PMC_BASE + PMC_TERM_CTRL_ADDR) & PMC_SAVE_MASK;
				write_value = (PMC_TERM_CTRL_val & PMC_TEMP_NULL_MASK) |
								(T_FATAL_NORMAL << PMC_TEMP_SHIFT);
				sic_write_node_nbsr_reg(curr_node,
							PMC_BASE + PMC_TERM_CTRL_ADDR, write_value);
			}
		}
		mutex_unlock(&write_reg_mutex);
	}
	return count;
}

static struct kobj_attribute fatal_attr = __ATTR(fatal_temp, 0660, fatal_show, fatal_store);

static int __init fatal_init(void)
{

	fatal_kobj = kobject_create_and_add("fatal_temp", kernel_kobj);
	if (!fatal_kobj) {
		return -ENOMEM;
	}

	if (sysfs_create_file(fatal_kobj, &fatal_attr.attr)) {
		kobject_put(fatal_kobj);
		return -ENOMEM;
	}

#ifdef CONFIG_DEBUG_FS
	struct dentry *pfile;
	dbgfs_fatal = debugfs_create_dir("fatal_temp_dbg", 0);
	if (dbgfs_fatal) {
		pfile = debugfs_create_file("fatal_temp_dbg", 0600,
						dbgfs_fatal, NULL, &fatal_file);
		if (!pfile) {
			pr_warn("debugfs create file fatal failed\n");
		}
	} else {
		pr_warn("debugfs create_dir failed\n");
	}
#endif
	return 0;
}

static void __exit fatal_exit(void)
{
	sysfs_remove_file(fatal_kobj, &fatal_attr.attr);
	kobject_put(fatal_kobj);
#ifdef CONFIG_DEBUG_FS
	if (dbgfs_fatal) {
		debugfs_remove_recursive(dbgfs_fatal);
		dbgfs_fatal = NULL;
	}
#endif
}

module_init(fatal_init);
module_exit(fatal_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("Module for setting fatal temperature");
