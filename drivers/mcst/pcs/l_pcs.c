/*
 * E8C/E8C2 Power Control System (PCS)
 * hwmon driver
 * (c) MCST, 2020
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/node.h>
#include <linux/cpu.h>
#include <linux/mod_devicetable.h>
#include <linux/hwmon-sysfs.h>

#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>


#define DRIVER_VERSION		"1.2"
#undef PCS_PLATFORM_DRIVER

/* Regs index */
#define PCS_CTRL5	0x0CC4
#define PCS_CTRL6	0x0CC8
#define PCS_CTRL7	0x0CCC
#define PCS_CTRL8	0x0CD0
#define PCS_CTRL9	0x0CD4

/* Number of sensors for each CPU type */
#define SENSORS_E8C	9
#define SENSORS_E8C2	8

static int sensors = 0;

struct pcs_ctrl_info {
	int offset;
	int shift;
};

static const struct pcs_ctrl_info pcs_ctrls[] = {
	{ PCS_CTRL5,  0}, /* Temp_r_scan0 */
	{ PCS_CTRL5, 12}, /* Temp_r_scan1 */
	{ PCS_CTRL6,  0}, /* Temp_r_scan2 */
	{ PCS_CTRL6, 12}, /* Temp_r_scan3 */
	{ PCS_CTRL7,  0}, /* Temp_r_scan4 */
	{ PCS_CTRL7, 12}, /* Temp_r_scan5 */
	{ PCS_CTRL8,  0}, /* Temp_r_scan6 */
	{ PCS_CTRL8, 12}, /* Temp_r_scan7 */
	{ PCS_CTRL9, 14}, /* T_max_cr */
	{ 0x0000, 0}
};

#define PCS_CTRL_MASK	0x0FFF

struct pcs_data {
	struct device *hdev;
	int node;
};

static int read_temp(int node, int idx)
{
	int val;

	val = sic_read_node_nbsr_reg(node, pcs_ctrls[idx].offset);
	val = (val >> pcs_ctrls[idx].shift) & PCS_CTRL_MASK;

	int temp_mc = val; /* 12b signed integer temperature value in 125 mC */
	temp_mc = ((temp_mc << 20) / 0x100000) * 125;

	return temp_mc;
} /* read_temp */

static ssize_t show_temp(struct device *dev,
			 struct device_attribute *attr, char *buf)
{
	struct pcs_data *pcs = dev_get_drvdata(dev);
	int idx = to_sensor_dev_attr(attr)->index;

	return sprintf(buf, "%d\n", read_temp(pcs->node, idx));
} /* show_temp */

static ssize_t show_label(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	struct pcs_data *pcs = dev_get_drvdata(dev);
	int idx = to_sensor_dev_attr(attr)->index;
	if (sensors == SENSORS_E8C) {
		if (idx == 0 || idx == 2)
			return sprintf(buf, "Sensor T%d (Core %d)\n", idx, idx + 1);
		else if (idx == 1)
			return sprintf(buf, "Sensor T%d (Cores %d, %d)\n", idx, 0, 2);
		else if (idx == 3 || idx == 5)
			return sprintf(buf, "Sensor T%d (Core %d)\n", idx, idx + 2);
		else if (idx == 4)
			return sprintf(buf, "Sensor T%d (Cores %d, %d)\n", idx, 4, 6);
		else if (idx == 6)
			return sprintf(buf, "Sensor T%d (Memory Controllers %d, %d)\n",
									idx, 2, 3);
		else if (idx == 7)
			return sprintf(buf, "Sensor T%d (Memory Controllers %d, %d)\n",
									idx, 0, 1);
		else if (idx == 8)
			return sprintf(buf, "Node %d Max\n", pcs->node);
	} else if (sensors == SENSORS_E8C2) {
		if (idx < 4)
			return sprintf(buf, "Sensor T%d (Cores %d, %d)\n",
							 idx, idx * 2, idx * 2 + 1);
		else if (idx == 4)
			return sprintf(buf, "Sensor T%d (Memory Controllers %d, %d)\n",
									idx, 0, 1);
		else if (idx == 5)
			return sprintf(buf, "Sensor T%d (Memory Controllers %d, %d)\n",
									idx, 2, 3);
		else if (idx == 6)
			return sprintf(buf, "Sensor T%d (System Commutator)\n", idx);
		else if (idx == 8)
			return sprintf(buf, "Node %d Max\n", pcs->node);
	}
	return sprintf(buf, "\n");
} /* show_label */

static ssize_t show_type(struct device *dev,
			 struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", 1); /* 1: CPU embedded diode */
} /* show_type */

static ssize_t show_node(struct device *dev,
			 struct device_attribute *attr, char *buf)
{
	struct pcs_data *pcs = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", pcs->node);
} /* show_node */

#define MAX_NAME	16

static int num_attrs = 0;

struct pcs_device_attribute {
	struct sensor_device_attribute s_attrs;
	char name[MAX_NAME];
};

static struct attribute_group pcs_group = {
	.attrs = NULL,
};

static const struct attribute_group *pcs_groups[] = {
	&pcs_group,
	NULL,
};

static struct pcs_device_attribute *pcs_attrs;

static int create_sensor_device_attr(struct device *dev)
{
	int i;
	pcs_attrs = devm_kzalloc(dev, (3 * sensors) *
			sizeof(struct pcs_device_attribute), GFP_KERNEL);
	if (!pcs_attrs)
		return -ENOMEM;
	for (i = 0; i < sensors; i++) {
		struct pcs_device_attribute *pattr;

		pattr = pcs_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "temp%d_input", i + 1);
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = S_IRUGO;
		pattr->s_attrs.dev_attr.show = show_temp;
		pattr->s_attrs.dev_attr.store = NULL;
		if ((sensors == SENSORS_E8C2) && (i == sensors - 1))
			pattr->s_attrs.index = i + 1;
		else
			pattr->s_attrs.index = i;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;

		pattr = pcs_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "temp%d_label", i + 1);
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = S_IRUGO;
		pattr->s_attrs.dev_attr.show = show_label;
		pattr->s_attrs.dev_attr.store = NULL;
		if ((sensors == SENSORS_E8C2) && (i == sensors - 1))
			pattr->s_attrs.index = i + 1;
		else
			pattr->s_attrs.index = i;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;

		pattr = pcs_attrs + num_attrs;
		if (i == sensors - 1)
			snprintf(pattr->name, MAX_NAME, "node");
		else
			snprintf(pattr->name, MAX_NAME, "temp%d_type", i + 1);
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = S_IRUGO;
		if (i == sensors - 1)
			pattr->s_attrs.dev_attr.show = show_node;
		else
			pattr->s_attrs.dev_attr.show = show_type;
		pattr->s_attrs.dev_attr.store = NULL;
		if ((sensors == SENSORS_E8C2) && (i == sensors - 1))
			pattr->s_attrs.index = i + 1;
		else
			pattr->s_attrs.index = i;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;
	}
	return 0;
}

static struct attribute **attrs;

static int create_pcs_group(struct device *dev)
{
	int i;

	attrs = devm_kzalloc(dev, num_attrs * sizeof(struct attribute *),
			GFP_KERNEL);
	if (!attrs)
		return -ENOMEM;
	for (i = 0; i < num_attrs; i++)
		*(attrs + i) = &((pcs_attrs + i)->s_attrs.dev_attr.attr);
	pcs_group.attrs = attrs;

	return 0;
}

#define	MAX_NODE	4

struct device *hwmon_dev[MAX_NODE];

#ifndef PCS_PLATFORM_DRIVER
static int __init pcs_probe(void)
#else /* PCS_PLATFORM_DRIVER */
static int pcs_probe(struct platform_device *pdev)
#endif /* PCS_PLATFORM_DRIVER */
{
	int node;
	struct pcs_data *pcs;
#ifdef PCS_PLATFORM_DRIVER
	struct device *dev = &pdev->dev;
#else /* !PCS_PLATFORM_DRIVER */
	struct device *dev = cpu_subsys.dev_root;
	int ret;

	if (machine.native_id != MACHINE_ID_E8C &&
			machine.native_id != MACHINE_ID_E8C2)
		return -ENODEV;

	if (machine.native_id == MACHINE_ID_E8C)
		sensors = SENSORS_E8C;
	else if (machine.native_id == MACHINE_ID_E8C2)
		sensors = SENSORS_E8C2;

	ret = create_sensor_device_attr(dev);
	if (ret)
		return -ENOMEM;
	ret = create_pcs_group(dev);
	if (ret)
		return -ENOMEM;

#endif /* PCS_PLATFORM_DRIVER */

	for_each_online_node(node) {
		pcs = devm_kzalloc(dev, sizeof(*pcs), GFP_KERNEL);
		if (!pcs)
			return -ENOMEM;
		pcs->node = node;
		hwmon_dev[node] = devm_hwmon_device_register_with_groups(dev,
								KBUILD_MODNAME,
								pcs,
								pcs_groups);
		if (IS_ERR(hwmon_dev))
			return PTR_ERR(hwmon_dev);

		pcs->hdev = hwmon_dev[node];

		dev_info(dev, "node %d hwmon device enabled - %s",
			 pcs->node, dev_name(pcs->hdev));
	}

	return 0;
} /* pcs_probe */

#ifndef PCS_PLATFORM_DRIVER
static void __exit pcs_remove(void)
#else
static void pcs_remove(struct platform_device *pdev)
#endif
{
	int node;

	for_each_online_node(node) {
		sysfs_remove_group(&hwmon_dev[node]->kobj, &pcs_group);
		hwmon_device_unregister(hwmon_dev[node]);
	}
}

#ifndef PCS_PLATFORM_DRIVER

module_init(pcs_probe);
module_exit(pcs_remove);

#else /* PCS_PLATFORM_DRIVER */

static const struct of_device_id pcs_of_match[] = {
	{.compatible = "mcst,l_pcs"},
	{},
};

static struct platform_driver pcs_driver = {
	.probe = pcs_probe,
	.driver = {
		.name = KBUILD_MODNAME,
		.of_match_table = pcs_of_match,
	},
	.remove = pcs_remove,
};

module_platform_driver(pcs_driver);

MODULE_DEVICE_TABLE(of, pcs_of_match);

#endif /* PCS_PLATFORM_DRIVER */

MODULE_AUTHOR("Andrey.V.Kalita@mcst.ru");
MODULE_DESCRIPTION("e8c/e8c2 pcs driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRIVER_VERSION);
