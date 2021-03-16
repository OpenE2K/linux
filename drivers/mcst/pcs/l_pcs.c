/*
 * E8C/E8C2 Power Control System (PCS)
 * hwmon driver
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

#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>


#define DRIVER_VERSION		"1.1"
#undef PCS_PLATFORM_DRIVER


/* Regs index */
#define PCS_CTRL5	0x0CC4
#define PCS_CTRL6	0x0CC8
#define PCS_CTRL7	0x0CCC
#define PCS_CTRL8	0x0CD0
#define PCS_CTRL9	0x0CD4

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

	if (idx == 8)
		return sprintf(buf, "Node %d Max\n", pcs->node);
	else
		return sprintf(buf, "Core %d\n", idx);
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

SENSOR_DEVICE_ATTR(temp1_input, S_IRUGO, show_temp, NULL, 0);
SENSOR_DEVICE_ATTR(temp2_input, S_IRUGO, show_temp, NULL, 1);
SENSOR_DEVICE_ATTR(temp3_input, S_IRUGO, show_temp, NULL, 2);
SENSOR_DEVICE_ATTR(temp4_input, S_IRUGO, show_temp, NULL, 3);
SENSOR_DEVICE_ATTR(temp5_input, S_IRUGO, show_temp, NULL, 4);
SENSOR_DEVICE_ATTR(temp6_input, S_IRUGO, show_temp, NULL, 5);
SENSOR_DEVICE_ATTR(temp7_input, S_IRUGO, show_temp, NULL, 6);
SENSOR_DEVICE_ATTR(temp8_input, S_IRUGO, show_temp, NULL, 7);
SENSOR_DEVICE_ATTR(temp9_input, S_IRUGO, show_temp, NULL, 8);

SENSOR_DEVICE_ATTR(temp1_label, S_IRUGO, show_label, NULL, 0);
SENSOR_DEVICE_ATTR(temp2_label, S_IRUGO, show_label, NULL, 1);
SENSOR_DEVICE_ATTR(temp3_label, S_IRUGO, show_label, NULL, 2);
SENSOR_DEVICE_ATTR(temp4_label, S_IRUGO, show_label, NULL, 3);
SENSOR_DEVICE_ATTR(temp5_label, S_IRUGO, show_label, NULL, 4);
SENSOR_DEVICE_ATTR(temp6_label, S_IRUGO, show_label, NULL, 5);
SENSOR_DEVICE_ATTR(temp7_label, S_IRUGO, show_label, NULL, 6);
SENSOR_DEVICE_ATTR(temp8_label, S_IRUGO, show_label, NULL, 7);
SENSOR_DEVICE_ATTR(temp9_label, S_IRUGO, show_label, NULL, 8);

SENSOR_DEVICE_ATTR(temp1_type, S_IRUGO, show_type, NULL, 0);
SENSOR_DEVICE_ATTR(temp2_type, S_IRUGO, show_type, NULL, 1);
SENSOR_DEVICE_ATTR(temp3_type, S_IRUGO, show_type, NULL, 2);
SENSOR_DEVICE_ATTR(temp4_type, S_IRUGO, show_type, NULL, 3);
SENSOR_DEVICE_ATTR(temp5_type, S_IRUGO, show_type, NULL, 4);
SENSOR_DEVICE_ATTR(temp6_type, S_IRUGO, show_type, NULL, 5);
SENSOR_DEVICE_ATTR(temp7_type, S_IRUGO, show_type, NULL, 6);
SENSOR_DEVICE_ATTR(temp8_type, S_IRUGO, show_type, NULL, 7);
/*SENSOR_DEVICE_ATTR(temp9_type, S_IRUGO, show_type, NULL, 8);*/

SENSOR_DEVICE_ATTR(node, S_IRUGO, show_node, NULL, 9);

static struct attribute *pcs_attrs[] = {
	&sensor_dev_attr_temp1_input.dev_attr.attr,
	&sensor_dev_attr_temp2_input.dev_attr.attr,
	&sensor_dev_attr_temp3_input.dev_attr.attr,
	&sensor_dev_attr_temp4_input.dev_attr.attr,
	&sensor_dev_attr_temp5_input.dev_attr.attr,
	&sensor_dev_attr_temp6_input.dev_attr.attr,
	&sensor_dev_attr_temp7_input.dev_attr.attr,
	&sensor_dev_attr_temp8_input.dev_attr.attr,
	&sensor_dev_attr_temp9_input.dev_attr.attr,

	&sensor_dev_attr_temp1_label.dev_attr.attr,
	&sensor_dev_attr_temp2_label.dev_attr.attr,
	&sensor_dev_attr_temp3_label.dev_attr.attr,
	&sensor_dev_attr_temp4_label.dev_attr.attr,
	&sensor_dev_attr_temp5_label.dev_attr.attr,
	&sensor_dev_attr_temp6_label.dev_attr.attr,
	&sensor_dev_attr_temp7_label.dev_attr.attr,
	&sensor_dev_attr_temp8_label.dev_attr.attr,
	&sensor_dev_attr_temp9_label.dev_attr.attr,

	&sensor_dev_attr_temp1_type.dev_attr.attr,
	&sensor_dev_attr_temp2_type.dev_attr.attr,
	&sensor_dev_attr_temp3_type.dev_attr.attr,
	&sensor_dev_attr_temp4_type.dev_attr.attr,
	&sensor_dev_attr_temp5_type.dev_attr.attr,
	&sensor_dev_attr_temp6_type.dev_attr.attr,
	&sensor_dev_attr_temp7_type.dev_attr.attr,
	&sensor_dev_attr_temp8_type.dev_attr.attr,
	/*&sensor_dev_attr_temp9_type.dev_attr.attr,*/

	&sensor_dev_attr_node.dev_attr.attr,

	NULL,
};

ATTRIBUTE_GROUPS(pcs);


#ifndef PCS_PLATFORM_DRIVER
static int __init pcs_probe(void)
#else /* PCS_PLATFORM_DRIVER */
static int pcs_probe(struct platform_device *pdev)
#endif /* PCS_PLATFORM_DRIVER */
{
	int node;
	struct pcs_data *pcs;
	struct device *hwmon_dev;
#ifdef PCS_PLATFORM_DRIVER
	struct device *dev = &pdev->dev;
#else /* !PCS_PLATFORM_DRIVER */
	struct device *dev = cpu_subsys.dev_root;

	if (!(IS_MACHINE_E8C || IS_MACHINE_E8C2))
		return -ENODEV;
#endif /* PCS_PLATFORM_DRIVER */

	for_each_online_node(node) {
		pcs = devm_kzalloc(dev, sizeof(*pcs), GFP_KERNEL);
		if (!pcs)
			return -ENOMEM;
		pcs->node = node;

		hwmon_dev = devm_hwmon_device_register_with_groups(dev,
								KBUILD_MODNAME,
								pcs,
								pcs_groups);
		if (IS_ERR(hwmon_dev))
			return PTR_ERR(hwmon_dev);

		pcs->hdev = hwmon_dev;

		dev_info(dev, "node %d hwmon device enabled - %s",
			 pcs->node, dev_name(pcs->hdev));
	}

	return 0;
} /* pcs_probe */

#ifndef PCS_PLATFORM_DRIVER

module_init(pcs_probe);

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
};

module_platform_driver(pcs_driver);

MODULE_DEVICE_TABLE(of, pcs_of_match);

#endif /* PCS_PLATFORM_DRIVER */

MODULE_AUTHOR("Andrey.V.Kalita@mcst.ru");
MODULE_DESCRIPTION("e8c pcs driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRIVER_VERSION);
