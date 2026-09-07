/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/cpufreq.h>
#include <linux/sysfs.h>
#include <linux/irq.h>
#include <linux/node.h>
#include <linux/cpu.h>
#include <linux/pci.h>
#include <linux/platform_data/i2c-l-i2c2.h>
#include <linux/platform_device.h>

#include <asm-l/l_pmc.h>


#include <linux/platform_device.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>


#include "pmc.h"

struct pmcmon_data {
	int node;
	void __iomem *cntrl_base;
	struct device *hdev;
	struct platform_device *pdev;
	struct thermal_zone_device *thermal;
	int trip_temp[LPMC_TRIP_NUM];
	int trip_hyst[LPMC_TRIP_NUM];
	raw_spinlock_t thermal_lock;
};

static struct pmc_temp_coeff {
	long y, k;
} pmc_temp_coeff[] = {
	{344700, 108300}, /*e1cp*/
	{237700,  79925}, /*r2000*/
};
static int pmc_temp_coeff_index;

static void __iomem *pmc_regs(struct device *dev)
{
	struct pmcmon_data *pmcmon = dev_get_drvdata(dev);
	return pmcmon->cntrl_base;
}

static long spmc_input_to_celsius_millidegrees(unsigned int in)
{
	struct pmc_temp_coeff *c = &pmc_temp_coeff[pmc_temp_coeff_index];

	return in * c->y / 4096 - c->k;
}

/* Additional sysfs interface for Moortec temp sensor */
static ssize_t spmc_show_temp_cur0(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	unsigned int x;
	int temp;
	unsigned int frac;
	void __iomem *regs = pmc_regs(dev);

	x = __raw_readl(regs + PMC_L_TEMP_RG_CUR_REG_0);
	if (x & PMC_MOORTEC_TEMP_VALID) {
		x &= PMC_MOORTEC_TEMP_VALUE_MASK;
		temp = spmc_input_to_celsius_millidegrees(x);
		frac = abs(temp % 1000);
		temp /= 1000;
		return sprintf(buf, "%d.%d\n", temp, frac);
	}
	return sprintf(buf, "Bad value\n");
}

static ssize_t spmc_show_temp_cur1(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	unsigned int x;
	int temp;
	unsigned int frac;
	void __iomem *regs = pmc_regs(dev);

	x = __raw_readl(regs + PMC_L_TEMP_RG_CUR_REG_1);
	if (x & PMC_MOORTEC_TEMP_VALID) {
		x &= PMC_MOORTEC_TEMP_VALUE_MASK;
		temp = spmc_input_to_celsius_millidegrees(x);
		frac = abs(temp % 1000);
		temp /= 1000;
		return sprintf(buf, "%d.%d\n", temp, frac);
	}
	return sprintf(buf, "Bad value\n");
}

static ssize_t spmc_show_nbs0(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	unsigned int x;
	unsigned int temp;
	void __iomem *regs = pmc_regs(dev);

	x = __raw_readl(regs + PMC_L_TEMP_RG_CUR_REG_0);
	temp = x;
	if (temp & PMC_MOORTEC_TEMP_VALID) {
		temp &= PMC_MOORTEC_TEMP_VALUE_MASK;
		return sprintf(buf, "%d\n", temp);
	}
	return sprintf(buf, "Bad value\n");
}

static ssize_t spmc_show_nbs1(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	unsigned int x;
	unsigned int temp;
	void __iomem *regs = pmc_regs(dev);

	x = __raw_readl(regs + PMC_L_TEMP_RG_CUR_REG_1);
	temp = x;
	if (temp & PMC_MOORTEC_TEMP_VALID) {
		temp &= PMC_MOORTEC_TEMP_VALUE_MASK;
		return sprintf(buf, "%d\n", temp);
	}
	return sprintf(buf, "Bad value\n");
}

unsigned int load_threshold = 63;
EXPORT_SYMBOL(load_threshold);

static ssize_t spmc_show_load_threshold(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", load_threshold);
}

static ssize_t spmc_store_load_threshold(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned long input;

	if (kstrtoul(buf, 10, &input) > 63)
		return -EINVAL;

	load_threshold = (unsigned int)input;

	return count;
}

static DEVICE_ATTR(temp_cur0, S_IRUGO, spmc_show_temp_cur0, NULL);
static DEVICE_ATTR(temp_cur1, S_IRUGO, spmc_show_temp_cur1, NULL);

static DEVICE_ATTR(nbs0, S_IRUGO, spmc_show_nbs0, NULL);
static DEVICE_ATTR(nbs1, S_IRUGO, spmc_show_nbs1, NULL);

static DEVICE_ATTR(load_threshold, S_IRUGO|S_IWUSR, spmc_show_load_threshold,
						spmc_store_load_threshold);

static struct attribute *pmc_tmoortec_attributes[] = {
	&dev_attr_temp_cur0.attr,	/* 0 */
	&dev_attr_temp_cur1.attr,	/* 1 */
	&dev_attr_nbs0.attr,		/* 2 */
	&dev_attr_nbs1.attr,		/* 3 */
	&dev_attr_load_threshold.attr,	/* 4 */
	NULL,				/* 5: for: dev_attr_temp_cur2 */
	NULL,				/* 6: for: dev_attr_nbs2 */
	NULL
};

static int hwmon_read_temp(struct device *dev, int idx)
{
	unsigned int x;
	int temp;
	void __iomem *regs = pmc_regs(dev);

	switch (idx) {
	case 0:
		x = __raw_readl(regs + PMC_L_TEMP_RG_CUR_REG_0);
		break;
	case 1:
		x = __raw_readl(regs + PMC_L_TEMP_RG_CUR_REG_1);
		break;

	default:
		return 0;
	}

	if (x & PMC_MOORTEC_TEMP_VALID) {
		x &= PMC_MOORTEC_TEMP_VALUE_MASK;
		temp = spmc_input_to_celsius_millidegrees(x);
		return temp;
	}
	return 0; /* Bad value */
} /* hwmon_read_temp */

static ssize_t hwmon_show_temp(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n",
		       hwmon_read_temp(dev, to_sensor_dev_attr(attr)->index));
} /* hwmon_show_temp */

static ssize_t hwmon_show_label(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	switch (to_sensor_dev_attr(attr)->index) {
	case 0:
		return sprintf(buf, "Core\n");
	case 1:
		return sprintf(buf, "GPU\n");
	}
	return sprintf(buf, "temp%d\n", to_sensor_dev_attr(attr)->index);
} /* hwmon_show_label */

static ssize_t hwmon_show_type(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", 1); /* 1: CPU embedded diode */
} /* hwmon_show_type */

static ssize_t show_node(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct pmcmon_data *pmcmon_dev = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", pmcmon_dev->node);
} /* show_node */


static SENSOR_DEVICE_ATTR(temp1_input, S_IRUGO, hwmon_show_temp, NULL, 0);
static SENSOR_DEVICE_ATTR(temp2_input, S_IRUGO, hwmon_show_temp, NULL, 1);

static SENSOR_DEVICE_ATTR(temp1_label, S_IRUGO, hwmon_show_label, NULL, 0);
static SENSOR_DEVICE_ATTR(temp2_label, S_IRUGO, hwmon_show_label, NULL, 1);

static SENSOR_DEVICE_ATTR(temp1_type, S_IRUGO, hwmon_show_type, NULL, 0);
static SENSOR_DEVICE_ATTR(temp2_type, S_IRUGO, hwmon_show_type, NULL, 1);

static SENSOR_DEVICE_ATTR(node, S_IRUGO, show_node, NULL, 3);

static struct attribute *pmcmon_attrs[] = {
	&sensor_dev_attr_temp1_input.dev_attr.attr,
	&sensor_dev_attr_temp2_input.dev_attr.attr,
	&sensor_dev_attr_temp1_label.dev_attr.attr,
	&sensor_dev_attr_temp2_label.dev_attr.attr,
	&sensor_dev_attr_temp1_type.dev_attr.attr,
	&sensor_dev_attr_temp2_type.dev_attr.attr,
	&sensor_dev_attr_node.dev_attr.attr,
	NULL,
};

ATTRIBUTE_GROUPS(pmcmon);

#define LPMC_POLLING_DELAY		0
#define LPMC_PASSIVE_DELAY		0 /* millisecond */

#define LPMC_TEMP_PASSIVE		100000 /* millicelsius */
#define LPMC_TEMP_CRITICAL		105000

#define LPMC_TEMP_HYSTERESIS		1500

#define pmcmon_dev_read(__offset)						\
({									\
	unsigned int __val = __raw_readl(pmcmon_dev->cntrl_base + __offset);	\
	dev_dbg(&pmcmon_dev->pdev->dev, "R:%x:%x: %s\t%s:%d\n",		\
		__offset, __val, # __offset, __func__, __LINE__);	\
	__val;								\
})

#define pmcmon_dev_write(__val, __offset)	do {			\
	unsigned int __val2 = __val;				\
	dev_dbg(&pmcmon_dev->pdev->dev, "W:%x:%x: %s\t%s:%d\n",	\
		__offset, __val2, # __offset, __func__, __LINE__);\
	__raw_writel(__val2, pmcmon_dev->cntrl_base + __offset);	\
} while (0)


static const struct attribute_group pmc_tmoortec_attr_group = {
	.attrs = pmc_tmoortec_attributes,
};


static int pmc_l_raw_to_millicelsius(unsigned v)
{
	v &= PMC_MOORTEC_TEMP_VALUE_MASK;
	return (int)(v * 344700 / 4096) - 108300;
}

static unsigned int pmc_l_millicelsius_to_raw(int t)
{
	return (t + 108300) * 4096 / 344700;
}

static int l_pmc_get_temp(struct thermal_zone_device *tz, int *ptemp)
{
	struct pmcmon_data *pmcmon_dev  = (struct pmcmon_data *)tz->devdata;
	unsigned int x = pmcmon_dev_read(PMC_L_TEMP_RG_CUR_REG_0);
#ifdef DEBUG
	pmcmon_dev_read(PMC_L_TEMP_RG_CUR_REG_1);
#endif
	if (!(x & PMC_MOORTEC_TEMP_VALID))
		return -1;
	*ptemp = pmc_l_raw_to_millicelsius(x);
	dev_dbg(&pmcmon_dev->pdev->dev, "t: %d mC\n", *ptemp);

#ifdef DEBUG
	pmcmon_dev_read(PMC_L_GPE0_STS_REG);
	pmcmon_dev_read(PMC_L_GPE0_EN_REG);
#endif
	return 0;
}

static int l_pmc_change_mode(struct thermal_zone_device *tz,
			enum thermal_device_mode mode)
{
	struct pmcmon_data *pmcmon_dev  = (struct pmcmon_data *)tz->devdata;
	unsigned long flags;

	raw_spin_lock_irqsave(&pmcmon_dev->thermal_lock, flags);

	pmcmon_dev_write(0, PMC_L_GPE0_EN_REG);
	if (mode != THERMAL_DEVICE_ENABLED) {
		raw_spin_unlock_irqrestore(&pmcmon_dev->thermal_lock, flags);
		return 0;
	}

	pmcmon_dev_write(0xf, PMC_L_GPE0_EN_REG);
	pmcmon_dev_read(PMC_L_GPE0_STS_REG);

	raw_spin_unlock_irqrestore(&pmcmon_dev->thermal_lock, flags);

	return 0;
}

static int l_pmc_get_trip_type(struct thermal_zone_device *tz, int trip,
			     enum thermal_trip_type *type)
{
	*type = (trip == LPMC_TRIP_PASSIVE) ? THERMAL_TRIP_PASSIVE :
					     THERMAL_TRIP_CRITICAL;
	return 0;
}

static int l_pmc_get_trip_temp(struct thermal_zone_device *tz, int trip,
			     int *temp)
{
	struct pmcmon_data *pmcmon_dev = (struct pmcmon_data *)tz->devdata;

	if (trip >= LPMC_TRIP_NUM)
		return -EINVAL;
	*temp = pmcmon_dev->trip_temp[trip];
	return 0;
}

static void pmc_l_set_alarm(struct thermal_zone_device *tz, int nr)
{
	struct pmcmon_data *pmcmon_dev = (struct pmcmon_data *)tz->devdata;
	unsigned int e;
	unsigned int temp1 = pmc_l_millicelsius_to_raw(pmcmon_dev->trip_temp[nr] -
						pmcmon_dev->trip_hyst[nr]);
	unsigned int temp2 = pmc_l_millicelsius_to_raw(pmcmon_dev->trip_temp[nr]);
	unsigned long flags;

	raw_spin_lock_irqsave(&pmcmon_dev->thermal_lock, flags);
	e = pmcmon_dev_read(PMC_L_GPE0_EN_REG);

	pmcmon_dev_write(0, PMC_L_GPE0_EN_REG);

	temp1 |= PMC_L_TEMP_RGX_FALL;
	temp2 |= PMC_L_TEMP_RGX_RISE;

	pmcmon_dev_write(temp1, PMC_L_TEMP_RG0_REG + nr * 2 * 4);
	pmcmon_dev_write(temp2, PMC_L_TEMP_RG0_REG + nr * 2 * 4 + 4);
	pmcmon_dev_write(PMC_L_GPE0_STS_CLR, PMC_L_GPE0_STS_REG);

	pmcmon_dev_write(e, PMC_L_GPE0_EN_REG);
	pmcmon_dev_read(PMC_L_GPE0_STS_REG);
	raw_spin_unlock_irqrestore(&pmcmon_dev->thermal_lock, flags);
}

static int l_pmc_set_trip_temp(struct thermal_zone_device *tz, int trip,
			     int temp)
{
	struct pmcmon_data *pmcmon_dev = (struct pmcmon_data *)tz->devdata;

	pmcmon_dev->trip_temp[trip] = temp;
	pmc_l_set_alarm(tz, trip);
	return 0;
}

static int l_pmc_get_crit_temp(struct thermal_zone_device *tz, int *temp)
{
	return l_pmc_get_trip_temp(tz, THERMAL_TRIP_CRITICAL, temp);
}

static int l_pmc_bind(struct thermal_zone_device *tz,
		    struct thermal_cooling_device *cdev)
{
	int ret;
	unsigned int max_state = THERMAL_NO_LIMIT;

	ret = thermal_zone_bind_cooling_device(tz, LPMC_TRIP_PASSIVE, cdev,
					       max_state,
					       max_state,
					       THERMAL_WEIGHT_DEFAULT);
	if (ret) {
		dev_err(&tz->device,
			"binding zone %s with cdev %s failed:%d\n",
			tz->type, cdev->type, ret);
		return ret;
	}

	return 0;
}

static int l_pmc_unbind(struct thermal_zone_device *tz,
		      struct thermal_cooling_device *cdev)
{
	int ret;

	ret = thermal_zone_unbind_cooling_device(tz, LPMC_TRIP_PASSIVE, cdev);
	if (ret) {
		dev_err(&tz->device,
			"unbinding zone %s with cdev %s failed:%d\n",
			tz->type, cdev->type, ret);
		return ret;
	}

	return 0;
}


static int l_pmc_get_trip_hyst(struct thermal_zone_device *tz, int trip,
				    int *hyst)
{
	struct pmcmon_data *pmcmon_dev = (struct pmcmon_data *)tz->devdata;
	*hyst = pmcmon_dev->trip_hyst[trip];
	return 0;
}

static int l_pmc_set_trip_hyst(struct thermal_zone_device *tz, int trip,
				int hyst)
{
	struct pmcmon_data *pmcmon_dev = (struct pmcmon_data *)tz->devdata;

	pmcmon_dev->trip_hyst[trip] = hyst;
	pmc_l_set_alarm(tz, trip);
	return 0;
}

static irqreturn_t l_pmc_thermal_alarm_irq(int irq, void *dev)
{
	struct pmcmon_data *pmcmon_dev = (struct pmcmon_data *)dev;
	struct thermal_zone_device *tz = pmcmon_dev->thermal;
	int t = 0, i, ret = IRQ_HANDLED;
	unsigned int s, e;
	unsigned long flags;

	raw_spin_lock_irqsave(&pmcmon_dev->thermal_lock, flags);

	s = pmcmon_dev_read(PMC_L_GPE0_STS_REG);
	e = pmcmon_dev_read(PMC_L_GPE0_EN_REG);

	l_pmc_get_temp(tz, &t);
	for (i = 0; i < 4; i++) {
		if (!(s & (1 << i)))
			continue;

		if (!(i & 1)) { /*falling threshold*/
			if (t >= pmcmon_dev->trip_temp[i / 2] -
					pmcmon_dev->trip_hyst[i / 2])
				continue;
			e &= ~(1 << i);
			e |= 1 << (i + 1);

			if (i / 2 == LPMC_TRIP_PASSIVE)
				tz->passive_delay_jiffies = 0;
		} else {
			if (t < pmcmon_dev->trip_temp[i / 2])
				continue;
			e &= ~(1 << i);
			e |= 1 << (i - 1);

			if (i / 2 == LPMC_TRIP_PASSIVE)
				tz->passive_delay_jiffies =
					msecs_to_jiffies(LPMC_PASSIVE_DELAY);

			dev_crit(&pmcmon_dev->pdev->dev,
				"THERMAL ALARM: T %d > %d mC\n",
					t, pmcmon_dev->trip_temp[i / 2]);
		}
		ret = IRQ_WAKE_THREAD;
	}

	pmcmon_dev_write(0, PMC_L_GPE0_EN_REG);
	pmcmon_dev_write(PMC_L_GPE0_STS_CLR, PMC_L_GPE0_STS_REG);
	pmcmon_dev_write(e, PMC_L_GPE0_EN_REG);
	pmcmon_dev_read(PMC_L_GPE0_STS_REG);
	raw_spin_unlock_irqrestore(&pmcmon_dev->thermal_lock, flags);

	return ret;
}

static irqreturn_t l_pmc_thermal_alarm_irq_thread(int irq, void *dev)
{
	struct pmcmon_data *pmcmon_dev = (struct pmcmon_data *)dev;

	pr_debug("%s:THERMAL ALARM\n", pmcmon_dev->pdev->name);

	thermal_zone_device_update(pmcmon_dev->thermal, THERMAL_EVENT_UNSPECIFIED);

	return IRQ_HANDLED;
}

static int thermal_get_trend(struct thermal_zone_device *tz,
				int trip, enum thermal_trend *trend)
{
	int trip_temp;

	if (tz->ops->get_trip_temp(tz, trip, &trip_temp))
		return -EINVAL;

	if (tz->temperature > trip_temp) {
		*trend = THERMAL_TREND_RAISING;
		return 0;
	} else {
		*trend = THERMAL_TREND_DROPPING;
		return 0;
	}

	if (tz->temperature > tz->last_temperature)
		*trend = THERMAL_TREND_RAISING;
	else if (tz->temperature < tz->last_temperature)
		*trend = THERMAL_TREND_DROPPING;
	else
		*trend = THERMAL_TREND_STABLE;

	return 0;
}

static struct thermal_zone_device_ops l_pmc_tz_ops = {
	.bind = l_pmc_bind,
	.unbind = l_pmc_unbind,
	.get_temp = l_pmc_get_temp,
	.change_mode = l_pmc_change_mode,
	.get_trend = thermal_get_trend,
	.get_trip_type = l_pmc_get_trip_type,
	.get_trip_temp = l_pmc_get_trip_temp,
	.get_crit_temp = l_pmc_get_crit_temp,
	.set_trip_temp = l_pmc_set_trip_temp,
	.get_trip_hyst = l_pmc_get_trip_hyst,
	.set_trip_hyst = l_pmc_set_trip_hyst,
};



static int pmc_l_thermal_probe(struct pmcmon_data *pmcmon_dev)
{
	int ret = 0;
	struct platform_device *pdev = pmcmon_dev->pdev;
	struct resource *r = platform_get_resource(pdev, IORESOURCE_MEM, 0);

	pmcmon_dev->cntrl_base = devm_ioremap(&pmcmon_dev->pdev->dev, r->start, resource_size(r));

	pr_err("pmc_init: pmcmon_dev=%p", pmcmon_dev);
	pr_err("pmc_init: pmcmon_dev->cntrl_base=%p\n",
							pmcmon_dev->cntrl_base);


	ret = sysfs_create_group(&pdev->dev.kobj,
				&pmc_tmoortec_attr_group);

	if (ret)
		return ret;

	raw_spin_lock_init(&pmcmon_dev->thermal_lock);

	pmcmon_dev->trip_temp[LPMC_TRIP_PASSIVE] = LPMC_TEMP_PASSIVE;
	pmcmon_dev->trip_temp[LPMC_TRIP_CRITICAL] = LPMC_TEMP_CRITICAL;
	pmcmon_dev->trip_hyst[LPMC_TRIP_PASSIVE] = LPMC_TEMP_HYSTERESIS;
	pmcmon_dev->trip_hyst[LPMC_TRIP_CRITICAL] = LPMC_TEMP_HYSTERESIS;

	pmcmon_dev_write(0, PMC_L_GPE0_EN_REG);

	pmcmon_dev->thermal = thermal_zone_device_register("l_thermal",
				LPMC_TRIP_NUM, LPMC_TRIP_POINTS_MSK,
					pmcmon_dev, &l_pmc_tz_ops, NULL, 0, 0);

	if (IS_ERR(pmcmon_dev->thermal)) {
		dev_err(&pdev->dev,
			"Failed to register thermal zone device\n");
		ret = PTR_ERR(pmcmon_dev->thermal);
		return ret;
	}

	ret = thermal_zone_device_enable(pmcmon_dev->thermal);
	if (ret) {
		dev_err(&pdev->dev, "Cannot enable thermal zone device");
		thermal_zone_device_unregister(pmcmon_dev->thermal);
		return ret;
	}

	r = platform_get_resource(pdev, IORESOURCE_IRQ, 0);

	ret = devm_request_threaded_irq(&pdev->dev, r->start,
			l_pmc_thermal_alarm_irq, l_pmc_thermal_alarm_irq_thread,
			0, "l_pmc_thermal", pmcmon_dev);

	if (ret < 0) {
		dev_err(&pdev->dev, "failed to request alarm irq %lld: %d\n",
				r->start, ret);
		thermal_zone_device_unregister(pmcmon_dev->thermal);
		return ret;
	}

	pmc_l_set_alarm(pmcmon_dev->thermal, LPMC_TRIP_CRITICAL);
	pmc_l_set_alarm(pmcmon_dev->thermal, LPMC_TRIP_PASSIVE);

	return ret;
}

static void pmc_l_thermal_remove(struct pmcmon_data *pmcmon_dev)
{
	thermal_zone_device_unregister(pmcmon_dev->thermal);
	sysfs_remove_group(&pmcmon_dev->pdev->dev.kobj, &pmc_tmoortec_attr_group);
}

static int pmc_hwmon_probe(struct platform_device *pdev)
{
	int node = dev_to_node(&pdev->dev);
	int result = 0;
	struct device *hwmon_dev;

	struct pmcmon_data *pmcmon_dev = (struct pmcmon_data *)devm_kzalloc(&pdev->dev,
			sizeof(struct pmcmon_data), GFP_KERNEL);

	if (!pmcmon_dev)
		return -ENOMEM;

	if (node < 0)
		node = 0;

	pmcmon_dev->pdev = pdev;
	pmcmon_dev->node = node;

	result = pmc_l_thermal_probe(pmcmon_dev);
	if (result)
		return result;

	hwmon_dev = devm_hwmon_device_register_with_groups(
			&pdev->dev,
			KBUILD_MODNAME,
			pmcmon_dev,
			pmcmon_groups);

	if (IS_ERR(hwmon_dev)) {
		dev_err(&pdev->dev, "failed to create PMC hwmon device");
		return PTR_ERR(hwmon_dev);
	}

/*
 *  R2000 has 3 temperature sensors (Core 0-3, Core 4-7, NB)
 *  embedded in chips's die, access to sensors (and other
 *  PMC functions) provided by NB registers;
 *
 *  E1C+ has PMC device embedded in root hub of
 *  SoC, access to two temp. sensors (Core & GPU)
 *  performed through PCI.
 *
 */

	hwmon_dev->init_name = "pmcmon";
	pmcmon_dev->hdev = hwmon_dev;

	dev_info(hwmon_dev, "node %d hwmon device enabled - %s",
			pmcmon_dev->node, dev_name(pmcmon_dev->hdev));

	platform_set_drvdata(pdev, pmcmon_dev);

	return result;
}

static int pmc_hwmon_remove(struct platform_device *pdev)
{
	struct pmcmon_data *pmcmon_dev = platform_get_drvdata(pdev);

	pmc_l_thermal_remove(pmcmon_dev);
	hwmon_device_unregister(pmcmon_dev->hdev);

	return 0;
}

static struct platform_driver pmc_hwmon_driver = {
	.driver		= { .name = "pmc_hwmon" },
	.probe		= pmc_hwmon_probe,
	.remove     = pmc_hwmon_remove,
};

int pmc_hwmon_init(void)
{
	return platform_driver_register(&pmc_hwmon_driver);
}

void pmc_hwmon_exit(void)
{
	platform_driver_unregister(&pmc_hwmon_driver);
}
