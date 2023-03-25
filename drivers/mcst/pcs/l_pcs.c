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
#include <linux/thermal.h>

#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>


#define DRIVER_VERSION		"1.2"

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
	struct platform_device *pdev;
	struct device *hdev;
	struct thermal_zone_device *tz;
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

static int pcs_get_temp(void *data, int *temp)
{
	struct pcs_data *pcs = data;
	int val;

	val = sic_read_node_nbsr_reg(pcs->node, pcs_ctrls[8].offset);
	val = (val >> pcs_ctrls[8].shift) & PCS_CTRL_MASK;

	*temp = ((val << 20) / 0x100000) * 125;

	return 0;
}

static const struct thermal_zone_of_device_ops pcs_tz_ops = {
	.get_temp = pcs_get_temp,
};

static void pcs_init_thermal(struct pcs_data *pcs)
{
	struct platform_device *pdev = pcs->pdev;

	pcs->tz = devm_thermal_zone_of_sensor_register(&pdev->dev,
					 0, pcs, &pcs_tz_ops);
	if (IS_ERR(pcs->tz)) {
		dev_warn(&pdev->dev, "unable to register thermal sensor %ld\n",
			 PTR_ERR(pcs->tz));
	}
}

#define	MAX_NODE	4

struct pcs_data *p_pcs[MAX_NODE];

static int __init pcs_probe(void)
{
	int node;
	struct device_node *np;
	struct pcs_data *pcs;
	struct device *dev = cpu_subsys.dev_root;
	struct platform_device *pdev;
	struct device *hwmon_dev;
	int ret;
	char s[64];

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

	for_each_online_node(node) {
		pdev = platform_device_register_data(dev, "pcs", node,
								NULL, 0);
		if (IS_ERR(pdev)) {
			dev_err(dev, "failed to create PCS platform device");
			return PTR_ERR(pdev);
		}
		pcs = devm_kzalloc(dev, sizeof(*pcs), GFP_KERNEL);
		if (!pcs) {
			platform_device_unregister(pdev);
			return -ENOMEM;
		}
		/*
		 * binding pcs thermal-zone block for each node from device tree with
		 * pcs platform device registered above.
		 */
#ifdef CONFIG_OF
		sprintf(s, "/pcs@%d", node);
		np = of_find_node_by_path(s);
		if (np)
			pdev->dev.of_node = np;
#endif
		pcs->pdev = pdev;
		pcs->node = node;
		hwmon_dev = devm_hwmon_device_register_with_groups(&pdev->dev,
								KBUILD_MODNAME,
								pcs,
								pcs_groups);
		if (IS_ERR(hwmon_dev)) {
			platform_device_unregister(pdev);
			return PTR_ERR(hwmon_dev);
		}

		pcs->hdev = hwmon_dev;
		p_pcs[node] = pcs;

#ifdef CONFIG_OF
		if (np)
			pcs_init_thermal(pcs);
#endif

		dev_info(dev, "node %d hwmon device enabled - %s",
			 pcs->node, dev_name(pcs->hdev));
	}

	return 0;
} /* pcs_probe */

static void __exit pcs_remove(void)
{
	int node;

	for_each_online_node(node) {
		sysfs_remove_group(&p_pcs[node]->hdev->kobj, &pcs_group);
		hwmon_device_unregister(p_pcs[node]->hdev);
		platform_device_unregister(p_pcs[node]->pdev);
	}
}

module_init(pcs_probe);
module_exit(pcs_remove);

MODULE_AUTHOR("Andrey.V.Kalita@mcst.ru");
MODULE_DESCRIPTION("e8c/e8c2 pcs driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRIVER_VERSION);
