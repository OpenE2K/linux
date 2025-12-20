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

#ifdef CONFIG_E90S
#include <asm/e90s.h>
#endif

#define PMC_HWMON
#ifdef PMC_HWMON
#include <linux/platform_device.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#endif /* PMC_HWMON */

#include "pmc.h"

#ifdef PMC_HWMON
struct pmcmon_data {
	struct device *hdev;
	int node;
};
struct pmcmon_data *pmcmon_dev;
#endif /* PMC_HWMON */

static struct pmc_temp_coeff {
	long y, k;
} pmc_temp_coeff[] = {
	{344700, 108300}, /*e1cp*/
	{237700,  79925}, /*r2000*/
};
static int pmc_temp_coeff_index;

#ifdef CONFIG_NUMA
static void __iomem *hwmon_pmc_regs(struct device *dev)
{
	struct pmcmon_data *pmcmon = dev_get_drvdata(dev);
	return __pmc_regs(pmcmon->node);
}

static void __iomem *pmc_regs(struct device *dev)
{
	return __pmc_regs(dev_to_node(dev));
}
#else
#define pmc_regs(dev)	 __pmc_regs(0)
#define hwmon_pmc_regs(dev)	 __pmc_regs(0)
#endif /* CONFIG_NUMA */

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

int spmc_get_temp_cur0(void)
{
	unsigned int x;
	int temp;
	unsigned int frac;
	void __iomem *regs = __pmc_regs(numa_node_id());

	x = __raw_readl(regs + PMC_L_TEMP_RG_CUR_REG_0);
	if (x & PMC_MOORTEC_TEMP_VALID) {
		x &= PMC_MOORTEC_TEMP_VALUE_MASK;
		temp = spmc_input_to_celsius_millidegrees(x);
		frac = abs(temp % 1000);
		temp /= 1000;
		if (frac >= 500)
			temp++;

		return temp;
	}

	return SPMC_TEMP_BAD_VALUE;
}
EXPORT_SYMBOL(spmc_get_temp_cur0);

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

#ifdef CONFIG_E90S
static ssize_t spmc_show_temp_cur2(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	unsigned int x;
	int temp;
	unsigned int frac;
	void __iomem *regs = pmc_regs(dev);

	x = __raw_readl(regs + PMC_L_TEMP_RG_CUR_REG_2);
	if (x & PMC_MOORTEC_TEMP_VALID) {
		x &= PMC_MOORTEC_TEMP_VALUE_MASK;
		temp = spmc_input_to_celsius_millidegrees(x);
		frac = abs(temp % 1000);
		temp /= 1000;
		return sprintf(buf, "%d.%d\n", temp, frac);
	}
	return sprintf(buf, "Bad value\n");
}
#endif /* CONFIG_E90S */

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

#ifdef CONFIG_E90S
static ssize_t spmc_show_nbs2(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	unsigned int x;
	unsigned int temp;
	void __iomem *regs = pmc_regs(dev);

	x = __raw_readl(regs + PMC_L_TEMP_RG_CUR_REG_2);
	temp = x;
	if (temp & PMC_MOORTEC_TEMP_VALID) {
		temp &= PMC_MOORTEC_TEMP_VALUE_MASK;
		return sprintf(buf, "%d\n", temp);
	}
	return sprintf(buf, "Bad value\n");
}
#endif /* CONFIG_E90S */

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
#ifdef CONFIG_E90S
static DEVICE_ATTR(temp_cur2, S_IRUGO, spmc_show_temp_cur2, NULL);
#endif /* CONFIG_E90S */
static DEVICE_ATTR(nbs0, S_IRUGO, spmc_show_nbs0, NULL);
static DEVICE_ATTR(nbs1, S_IRUGO, spmc_show_nbs1, NULL);
#ifdef CONFIG_E90S
static DEVICE_ATTR(nbs2, S_IRUGO, spmc_show_nbs2, NULL);
#endif /* CONFIG_E90S */
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

static const struct attribute_group pmc_tmoortec_attr_group = {
	.attrs = pmc_tmoortec_attributes,
};


#ifdef PMC_HWMON
static int hwmon_read_temp(struct device *dev, int idx)
{
	unsigned int x;
	int temp;
	void __iomem *regs = hwmon_pmc_regs(dev);

	switch (idx) {
	case 0:
		x = __raw_readl(regs + PMC_L_TEMP_RG_CUR_REG_0);
		break;
	case 1:
		x = __raw_readl(regs + PMC_L_TEMP_RG_CUR_REG_1);
		break;
#ifdef CONFIG_E90S
	case 2:
		x = __raw_readl(regs + PMC_L_TEMP_RG_CUR_REG_2);
		break;
#endif /* CONFIG_E90S */
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
#ifndef CONFIG_E90S /* E1CP */
	switch (to_sensor_dev_attr(attr)->index) {
	case 0:
		return sprintf(buf, "Core\n");
	case 1:
		return sprintf(buf, "GPU\n");
	}
#else /* CONFIG_E90S - R2000 */
	switch (to_sensor_dev_attr(attr)->index) {
	case 0:
		return sprintf(buf, "NB\n");
	case 1:
		return sprintf(buf, "Core 0-3\n");
	case 2:
		return sprintf(buf, "Core 4-7\n");
	}
#endif /* CONFIG_E90S */
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


SENSOR_DEVICE_ATTR(temp1_input, S_IRUGO, hwmon_show_temp, NULL, 0);
SENSOR_DEVICE_ATTR(temp2_input, S_IRUGO, hwmon_show_temp, NULL, 1);
#ifdef CONFIG_E90S
SENSOR_DEVICE_ATTR(temp3_input, S_IRUGO, hwmon_show_temp, NULL, 2);
#endif /* CONFIG_E90S */

SENSOR_DEVICE_ATTR(temp1_label, S_IRUGO, hwmon_show_label, NULL, 0);
SENSOR_DEVICE_ATTR(temp2_label, S_IRUGO, hwmon_show_label, NULL, 1);
#ifdef CONFIG_E90S
SENSOR_DEVICE_ATTR(temp3_label, S_IRUGO, hwmon_show_label, NULL, 2);
#endif /* CONFIG_E90S */

SENSOR_DEVICE_ATTR(temp1_type, S_IRUGO, hwmon_show_type, NULL, 0);
SENSOR_DEVICE_ATTR(temp2_type, S_IRUGO, hwmon_show_type, NULL, 1);
#ifdef CONFIG_E90S
SENSOR_DEVICE_ATTR(temp3_type, S_IRUGO, hwmon_show_type, NULL, 2);
#endif /* CONFIG_E90S */
SENSOR_DEVICE_ATTR(node, S_IRUGO, show_node, NULL, 3);

static struct attribute *pmcmon_attrs[] = {
	&sensor_dev_attr_temp1_input.dev_attr.attr,
	&sensor_dev_attr_temp2_input.dev_attr.attr,
#ifdef CONFIG_E90S
	&sensor_dev_attr_temp3_input.dev_attr.attr,
#endif /* CONFIG_E90S */

	&sensor_dev_attr_temp1_label.dev_attr.attr,
	&sensor_dev_attr_temp2_label.dev_attr.attr,
#ifdef CONFIG_E90S
	&sensor_dev_attr_temp3_label.dev_attr.attr,
#endif /* CONFIG_E90S */

	&sensor_dev_attr_temp1_type.dev_attr.attr,
	&sensor_dev_attr_temp2_type.dev_attr.attr,
#ifdef CONFIG_E90S
	&sensor_dev_attr_temp3_type.dev_attr.attr,
#endif /* CONFIG_E90S */
	&sensor_dev_attr_node.dev_attr.attr,
	NULL,
};

ATTRIBUTE_GROUPS(pmcmon);

#endif /* PMC_HWMON */

#define LPMC_POLLING_DELAY		0
#define LPMC_PASSIVE_DELAY		0 /* millisecond */

#define LPMC_TEMP_PASSIVE		100000 /* millicelsius */
#define LPMC_TEMP_CRITICAL		105000

#define LPMC_TEMP_HYSTERESIS		1500

#define l_pmc_read(__offset)						\
({									\
	unsigned int __val = __raw_readl(l_pmc->cntrl_base + __offset);	\
	dev_dbg(&l_pmc->pdev->dev, "R:%x:%x: %s\t%s:%d\n",		\
		__offset, __val, # __offset, __func__, __LINE__);	\
	__val;								\
})

#define l_pmc_write(__val, __offset)	do {			\
	unsigned int __val2 = __val;				\
	dev_dbg(&l_pmc->pdev->dev, "W:%x:%x: %s\t%s:%d\n",	\
		__offset, __val2, # __offset, __func__, __LINE__);\
	__raw_writel(__val2, l_pmc->cntrl_base + __offset);	\
} while (0)

#ifndef CONFIG_E90S
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
	struct l_pmc *l_pmc  = tz->devdata;
	unsigned int x = l_pmc_read(PMC_L_TEMP_RG_CUR_REG_0);
#ifdef DEBUG
	l_pmc_read(PMC_L_TEMP_RG_CUR_REG_1);
#endif
	if (!(x & PMC_MOORTEC_TEMP_VALID))
		return -1;
	*ptemp = pmc_l_raw_to_millicelsius(x);
	dev_dbg(&l_pmc->pdev->dev, "t: %d mC\n", *ptemp);

#ifdef DEBUG
	l_pmc_read(PMC_L_GPE0_STS_REG);
	l_pmc_read(PMC_L_GPE0_EN_REG);
#endif
	return 0;
}

static int l_pmc_change_mode(struct thermal_zone_device *tz,
			enum thermal_device_mode mode)
{
	struct l_pmc *l_pmc  = tz->devdata;
	unsigned long flags;

	raw_spin_lock_irqsave(&l_pmc->thermal_lock, flags);

	l_pmc_write(0, PMC_L_GPE0_EN_REG);
	if (mode != THERMAL_DEVICE_ENABLED)
		goto out;

	l_pmc_write(0xf, PMC_L_GPE0_EN_REG);
	l_pmc_read(PMC_L_GPE0_STS_REG);
out:
	raw_spin_unlock_irqrestore(&l_pmc->thermal_lock, flags);

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
	struct l_pmc *l_pmc = tz->devdata;

	if (trip >= LPMC_TRIP_NUM)
		return -EINVAL;
	*temp = l_pmc->trip_temp[trip];
	return 0;
}

static void pmc_l_set_alarm(struct thermal_zone_device *tz, int nr)
{
	struct l_pmc *l_pmc = tz->devdata;
	unsigned int e;
	unsigned int temp1 = pmc_l_millicelsius_to_raw(l_pmc->trip_temp[nr] -
						l_pmc->trip_hyst[nr]);
	unsigned int temp2 = pmc_l_millicelsius_to_raw(l_pmc->trip_temp[nr]);
	unsigned long flags;

	raw_spin_lock_irqsave(&l_pmc->thermal_lock, flags);
	e = l_pmc_read(PMC_L_GPE0_EN_REG);

	l_pmc_write(0, PMC_L_GPE0_EN_REG);

	temp1 |= PMC_L_TEMP_RGX_FALL;
	temp2 |= PMC_L_TEMP_RGX_RISE;

	l_pmc_write(temp1, PMC_L_TEMP_RG0_REG + nr * 2 * 4);
	l_pmc_write(temp2, PMC_L_TEMP_RG0_REG + nr * 2 * 4 + 4);
	l_pmc_write(PMC_L_GPE0_STS_CLR, PMC_L_GPE0_STS_REG);

	l_pmc_write(e, PMC_L_GPE0_EN_REG);
	l_pmc_read(PMC_L_GPE0_STS_REG);
	raw_spin_unlock_irqrestore(&l_pmc->thermal_lock, flags);
}

static int l_pmc_set_trip_temp(struct thermal_zone_device *tz, int trip,
			     int temp)
{
	struct l_pmc *l_pmc = tz->devdata;

	l_pmc->trip_temp[trip] = temp;
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

	ret = thermal_zone_bind_cooling_device(tz, LPMC_TRIP_PASSIVE, cdev,
					       THERMAL_NO_LIMIT,
					       THERMAL_NO_LIMIT,
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
	struct l_pmc *l_pmc = tz->devdata;
	*hyst = l_pmc->trip_hyst[trip];
	return 0;
}

static int l_pmc_set_trip_hyst(struct thermal_zone_device *tz, int trip,
				int hyst)
{
	struct l_pmc *l_pmc = tz->devdata;

	l_pmc->trip_hyst[trip] = hyst;
	pmc_l_set_alarm(tz, trip);
	return 0;
}

static irqreturn_t l_pmc_thermal_alarm_irq(int irq, void *dev)
{
	struct l_pmc *l_pmc = dev;
	struct thermal_zone_device *tz = l_pmc->thermal;
	int t = 0, i, ret = IRQ_HANDLED;
	unsigned int s, e;
	unsigned long flags;

	raw_spin_lock_irqsave(&l_pmc->thermal_lock, flags);

	s = l_pmc_read(PMC_L_GPE0_STS_REG);
	e = l_pmc_read(PMC_L_GPE0_EN_REG);

	l_pmc_get_temp(tz, &t);
	for (i = 0; i < 4; i++) {
		if (!(s & (1 << i)))
			continue;

		if (!(i & 1)) { /*falling threshold*/
			if (t >= l_pmc->trip_temp[i / 2] -
					l_pmc->trip_hyst[i / 2])
				continue;
			e &= ~(1 << i);
			e |= 1 << (i + 1);

			if (i / 2 == LPMC_TRIP_PASSIVE)
				tz->passive_delay = 0;
		} else {
			if (t < l_pmc->trip_temp[i / 2])
				continue;
			e &= ~(1 << i);
			e |= 1 << (i - 1);

			if (i / 2 == LPMC_TRIP_PASSIVE)
				tz->passive_delay = LPMC_PASSIVE_DELAY;

			dev_crit(&l_pmc->pdev->dev,
				"THERMAL ALARM: T %d > %d mC\n",
					t, l_pmc->trip_temp[i / 2]);
		}
		ret = IRQ_WAKE_THREAD;
	}

	l_pmc_write(0, PMC_L_GPE0_EN_REG);
	l_pmc_write(PMC_L_GPE0_STS_CLR, PMC_L_GPE0_STS_REG);
	l_pmc_write(e, PMC_L_GPE0_EN_REG);
	l_pmc_read(PMC_L_GPE0_STS_REG);
	raw_spin_unlock_irqrestore(&l_pmc->thermal_lock, flags);

	return ret;
}

static irqreturn_t l_pmc_thermal_alarm_irq_thread(int irq, void *dev)
{
	struct l_pmc *l_pmc = dev;

	pr_debug("%s:THERMAL ALARM\n", pci_name(l_pmc->pdev));

	thermal_zone_device_update(l_pmc->thermal, THERMAL_EVENT_UNSPECIFIED);

	return IRQ_HANDLED;
}

static int thermal_get_trend(struct thermal_zone_device *tz,
				int trip, enum thermal_trend *trend)
{
	int trip_temp;

	if (tz->ops->get_trip_temp(tz, trip, &trip_temp))
		return -EINVAL;

	if (tz->temperature > trip_temp) {
		*trend = THERMAL_TREND_RAISE_FULL;
		return 0;
	} else {
		*trend = THERMAL_TREND_DROP_FULL;
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

static int pmc_l_thermal_probe(struct l_pmc *l_pmc)
{
	int ret = 0;
	struct pci_dev *pdev = l_pmc->pdev;

	ret = sysfs_create_group(&(l_pmc[0].pdev)->dev.kobj,
				&pmc_tmoortec_attr_group);
	if (ret)
		return ret;

	raw_spin_lock_init(&l_pmc->thermal_lock);

	l_pmc->trip_temp[LPMC_TRIP_PASSIVE] = LPMC_TEMP_PASSIVE;
	l_pmc->trip_temp[LPMC_TRIP_CRITICAL] = LPMC_TEMP_CRITICAL;
	l_pmc->trip_hyst[LPMC_TRIP_PASSIVE] = LPMC_TEMP_HYSTERESIS;
	l_pmc->trip_hyst[LPMC_TRIP_CRITICAL] = LPMC_TEMP_HYSTERESIS;

	l_pmc_write(0, PMC_L_GPE0_EN_REG);

	l_pmc->policy = cpufreq_cpu_get(cpumask_first(cpu_online_mask));
	if (!l_pmc->policy) {
		dev_err(&pdev->dev, "CPUFreq policy not found\n");
		ret = -EPROBE_DEFER;
		goto out_group;
	}

	l_pmc->cdev = cpufreq_cooling_register(l_pmc->policy);
	if (IS_ERR(l_pmc->cdev)) {
		ret = PTR_ERR(l_pmc->cdev);
		if (ret != -EPROBE_DEFER)
			dev_err(&pdev->dev,
				"failed to register cpufreq cooling device: %d\n",
				ret);
		goto out_policy;
	}

	l_pmc->thermal = thermal_zone_device_register("l_thermal",
				 LPMC_TRIP_NUM, LPMC_TRIP_POINTS_MSK,
					l_pmc, &l_pmc_tz_ops, NULL, 0, 0);
	if (IS_ERR(l_pmc->thermal)) {
		dev_err(&pdev->dev,
			"Failed to register thermal zone device\n");
		ret = PTR_ERR(l_pmc->thermal);
		goto out_cooling;
	}

	ret = thermal_zone_device_enable(l_pmc->thermal);
	if (ret) {
		dev_err(&pdev->dev, "Cannot enable thermal zone device");
		goto out_dev;
	}

	ret = devm_request_threaded_irq(&pdev->dev, pdev->irq,
			l_pmc_thermal_alarm_irq, l_pmc_thermal_alarm_irq_thread,
			0, "l_pmc_thermal", l_pmc);
	if (ret < 0) {
		dev_err(&pdev->dev, "failed to request alarm irq %d: %d\n",
				pdev->irq, ret);
		goto out_dev;
	}

	pmc_l_set_alarm(l_pmc->thermal, LPMC_TRIP_CRITICAL);
	pmc_l_set_alarm(l_pmc->thermal, LPMC_TRIP_PASSIVE);

	return ret;

out_dev:
	thermal_zone_device_unregister(l_pmc->thermal);
out_cooling:
	cpufreq_cooling_unregister(l_pmc->cdev);
out_policy:
	cpufreq_cpu_put(l_pmc->policy);
out_group:
	sysfs_remove_group(&(l_pmc[0].pdev)->dev.kobj, &pmc_tmoortec_attr_group);
	return ret;
}

static void pmc_l_thermal_remove(struct l_pmc *l_pmc)
{
	thermal_zone_device_unregister(l_pmc->thermal);
	cpufreq_cooling_unregister(l_pmc->cdev);
	cpufreq_cpu_put(l_pmc->policy);
	sysfs_remove_group(&(l_pmc[0].pdev)->dev.kobj, &pmc_tmoortec_attr_group);
}

static int pmc_l_probe(struct pci_dev *dev,
				  const struct pci_device_id *ent)
{
	return pmc_l_thermal_probe(&l_pmc[0]);
}

static void pmc_l_remove(struct pci_dev *dev)
{
	pmc_l_thermal_remove(&l_pmc[0]);
}


static const struct pci_device_id pmc_l_devices[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_HB) },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, pmc_l_devices);

static struct pci_driver pmc_l_driver = {
	.name		= "l-pmc",
	.id_table	= pmc_l_devices,
	.probe		= pmc_l_probe,
	.remove         = pmc_l_remove,
};
#endif

#ifdef PMC_HWMON
static struct platform_device *pmc_hwmon_pdev[MAX_NUMNODES];

int pmc_hwmon_init(void)
{
	int node;
	struct device *dev;
	struct platform_device *vdev;
	struct device *hwmon_dev;

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
	for_each_online_node(node) {
#ifdef CONFIG_E90S /* R2000 */
#ifdef CONFIG_NUMA
		dev = &node_devices[node]->dev;
#else
		dev = cpu_subsys.dev_root;
#endif /* CONFIG_NUMA */
#else /* E1C+ */
		dev = &(l_pmc[0].pdev)->dev;
#endif /* CONFIG_E90S */

		/* Create platform device to be parent of hwmon dev */
		vdev = platform_device_register_data(dev, "pmc_hwmon", node,
								NULL, 0);
		if (IS_ERR(vdev)) {
			dev_err(dev, "failed to create PMC platform device");
			return PTR_ERR(vdev);
		}

		pmcmon_dev = devm_kzalloc(dev, sizeof(*pmcmon_dev), GFP_KERNEL);
		if (!pmcmon_dev)
			return -ENOMEM;

		pmcmon_dev->node = node;
		hwmon_dev = devm_hwmon_device_register_with_groups(
				&vdev->dev,
				KBUILD_MODNAME,
				pmcmon_dev,
				pmcmon_groups);
		if (IS_ERR(hwmon_dev)) {
			dev_err(dev, "failed to create PMC hwmon device");
			return PTR_ERR(hwmon_dev);
		}
		pmcmon_dev->hdev = hwmon_dev;
		hwmon_dev->init_name = "pmcmon";
		dev_info(hwmon_dev, "node %d hwmon device enabled - %s",
				pmcmon_dev->node, dev_name(pmcmon_dev->hdev));

		pmc_hwmon_pdev[node] = vdev;
	}
	return 0;
}

void pmc_hwmon_exit(void)
{
	int node;

	for_each_online_node(node)
		platform_device_unregister(pmc_hwmon_pdev[node]);
}
#endif /* PMC_HWMON */

#ifdef CONFIG_E90S
static struct platform_device *pmc_temp_pdev[MAX_NUMNODES];
#endif

int pmc_temp_sensors_init(void)
{
#ifdef CONFIG_E90S
	int err = 0;
	int node;
	struct resource r[] = {
		{
			.flags	= IORESOURCE_MEM,
		},
	};
	struct l_i2c2_platform_data pmc_i2c = {
		.base_freq_hz    = 100 * 1000 * 1000,
		.desired_freq_hz = 100 * 1000,
	};

	pmc_temp_coeff_index = 1;
	pmc_tmoortec_attributes[5] = &dev_attr_temp_cur2.attr;
	pmc_tmoortec_attributes[6] = &dev_attr_nbs2.attr;

	for_each_online_node(node) {
#ifdef CONFIG_NUMA
		struct device *d = &node_devices[node]->dev;
#else
		struct device *d = cpu_subsys.dev_root;
#endif /* CONFIG_NUMA */
		struct platform_device *a;

		r[0].start = BASE_NODE0 +
			(BASE_NODE1 - BASE_NODE0) * node + 0x9400;
		r[0].end   = r[0].start + 20 - 1;
		pmc_i2c.bus_nr = node + 16, /* after KPI2 i2c controllers */
		a  = platform_device_register_resndata(NULL,
				"pmc-i2c", node, r,
				ARRAY_SIZE(r),
				&pmc_i2c, sizeof(pmc_i2c));
		if (!a)
			continue;
		/* Create sysfs interface for Moortec temp sensor */
		err = sysfs_create_group(&d->kobj,
				      &pmc_tmoortec_attr_group);
		if (err) {
			platform_device_unregister(a);
			return err;
		}
		pmc_temp_pdev[node] = a;
	}
	return 0;
#else /* E1C+ */
	return pci_register_driver(&pmc_l_driver);
#endif /* CONFIG_E90S */
}

void pmc_temp_sensors_exit(void)
{
#ifdef CONFIG_E90S
	int node;

	for_each_online_node(node) {
#ifdef CONFIG_NUMA
		struct device *d = &node_devices[node]->dev;
#else
		struct device *d = cpu_subsys.dev_root;
#endif /* CONFIG_NUMA */
		if (!pmc_temp_pdev[node])
			continue;
		sysfs_remove_group(&d->kobj,
				&pmc_tmoortec_attr_group);
		platform_device_unregister(pmc_temp_pdev[node]);
	}
#else /* E1C+ */
	sysfs_remove_group(&(l_pmc[0].pdev)->dev.kobj,
				&pmc_tmoortec_attr_group);
	pci_unregister_driver(&pmc_l_driver);
#endif /* CONFIG_E90S */
}
