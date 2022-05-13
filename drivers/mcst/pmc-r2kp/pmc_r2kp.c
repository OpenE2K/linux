/*
 * R2000+ PMC (PMC-R2KP) driver
 * hwmon driver included
 * (c) MCST, 2022
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/cpufreq.h>
#include <linux/smp.h>
#include <linux/topology.h>
#include <linux/node.h>
#include <linux/cpu.h>
#include <linux/sysfs.h>
#include <linux/irq.h>
#include <linux/cpu.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <asm/io.h>
#include <asm/sic_regs.h>
#include <asm/e90s.h>
#include <asm/l_pmc.h>


#undef DebugPMC
#undef PMC_DEBUG
#ifdef PMC_DEBUG
#define DebugPMC(x, ...) do {					\
	pr_err("PMC-R2KP DEBUG: %s: %d: " x,			\
			__func__, __LINE__, ##__VA_ARGS__);	\
} while (0)
#else
#define DebugPMC(...) do {} while (0)
#endif /* PMC_DEBUG */

/* PMC registers (offsets) */
#define PMC_R2KP_REG_PARAM_BASE	0x10
#define PMC_R2KP_REG_DOORBELL	0x24
#define PMC_R2KP_REG_PARAM(arg)	(PMC_R2KP_REG_PARAM_BASE + 0x04*(arg))

/* PMC doorbell register fields */
#define PMC_R2KP_REG_DOORBELL_REQ_NUM_MASK	(0x0000FFFF)
#define PMC_R2KP_REG_DOORBELL_PMC_REQUEST	(0x1 << 16)
#define PMC_R2KP_REG_DOORBELL_REQ_BUSY		(0x1 << 17)
#define PMC_R2KP_REG_DOORBELL_REQ_DONE		(0x1 << 18)

/* List of R2000+ PMC services */
#define PMC_R2KP_SRV_GET_FREQ		0x07
#define PMC_R2KP_SRV_GET_DEV_ATTR	0x0A

/* HW errors: from -1 to -6 */
#define PMC_R2KP_STATUS_BUSY		(-7)
#define PMC_R2KP_STATUS_NOT_AVAIL	(-8)

#define PMC_R2KP_REG_PARAM_NUMBER	4
#define PMC_R2KP_REG_TEMP			0x0C
#define PMC_R2KP_REG_TEMP_MAX		0x08

/*
 *  0 = the first access to pmc service
 *  1 = available
 * -1 = not available
 */
static int pmc_service_ok;
static unsigned long first_service_access; /* In jiffies */
#define PMC_SERVICE_TIMEOUT	(HZ)	/* In jiffies */

static DEFINE_MUTEX(r2kp_pmc_service_lock);

static void __iomem *__pmc_regs(int node)
{
	node = node >= 0 ? node : 0;
	return (void *)(BASE_NODE0 +
			(BASE_NODE1 - BASE_NODE0) * node + 0x9000);
}

static int r2kp_call_doorbell(unsigned int serv, void __iomem *regs)
{
	if (unlikely(pmc_service_ok < 0))
		return PMC_R2KP_STATUS_NOT_AVAIL;

	if (__raw_readl(regs + PMC_R2KP_REG_DOORBELL) &
					PMC_R2KP_REG_DOORBELL_REQ_BUSY) {
		return PMC_R2KP_STATUS_BUSY;
	} else {
		__raw_writel(PMC_R2KP_REG_DOORBELL_PMC_REQUEST |
				(serv & PMC_R2KP_REG_DOORBELL_REQ_NUM_MASK),
				regs + PMC_R2KP_REG_DOORBELL);
	}

	if (unlikely(pmc_service_ok == 0))
		first_service_access = jiffies;

	while (!(__raw_readl(regs + PMC_R2KP_REG_DOORBELL) &
			PMC_R2KP_REG_DOORBELL_REQ_DONE)) {
		if (pmc_service_ok == 0 &&
			time_after(jiffies, first_service_access +
			PMC_SERVICE_TIMEOUT)) {
			/* The first access to pmc service.
			 * Check for availability.
			 */
			pmc_service_ok = -1;
			return PMC_R2KP_STATUS_NOT_AVAIL;
		}
	}
	if (unlikely(pmc_service_ok == 0))
		pmc_service_ok = 1;

	return (int)((s16)(__raw_readl(regs + PMC_R2KP_REG_DOORBELL) &
					PMC_R2KP_REG_DOORBELL_REQ_NUM_MASK));
}

static int r2kp_get_service(int node, unsigned int serv, uint32_t *param)
{
	int i, rc;
	void __iomem *regs = __pmc_regs(node);

	DebugPMC("in params: %d %d %d %d\n",
			*param, *(param+1), *(param+2), *(param+3));
	for (i = 0; i < PMC_R2KP_REG_PARAM_NUMBER; i++)
		__raw_writel(*(param + i), regs + PMC_R2KP_REG_PARAM(i));

	rc = r2kp_call_doorbell(serv, regs);

	if (rc >= 0) {
		for (i = 0; i < PMC_R2KP_REG_PARAM_NUMBER; i++)
			*(param + i) = __raw_readl(regs + PMC_R2KP_REG_PARAM(i));
	}
	DebugPMC("out params: %d %d %d %d rc: %d\n",
			*param, *(param+1), *(param+2), *(param+3), rc);
	return rc;
}

uint32_t r2kp_get_freq_mult(int cpu)
{
	uint32_t param[PMC_R2KP_REG_PARAM_NUMBER] = {};
	int rc;

	mutex_lock(&r2kp_pmc_service_lock);
	rc = r2kp_get_service(cpu_to_node(cpu),
				PMC_R2KP_SRV_GET_FREQ, &param[0]);
	mutex_unlock(&r2kp_pmc_service_lock);
	if (rc < 0)
		return 0;
	return param[0];
}

/*
 * Must be called with r2kp_pmc_service_lock held.
 */
static int r2kp_get_dev_attr(int node, int index, uint32_t *param)
{
	*param = index;
	return r2kp_get_service(node, PMC_R2KP_SRV_GET_DEV_ATTR, param);
}

struct pmcmon_data {
	const struct attribute_group *groups[3];	/* 2 groups + NULL */
	unsigned long last_updated;	/* In jiffies */
	char valid;			/* 1 if fields below are valid */
	u8 has_sensor;		/* Bitfield, up to 6 sensors can be available */
	u32 in[6];			/* In mV */
	u32 curr[6];		/* In mA */
	s32 temp[3];		/* In millidegrees */
	u8 temp_max;		/* Register value, degrees */
	u8 temp_hyst;		/* Register value, degrees */
	u8 temp_crit;		/* Register value, degrees */
};

/* How often we reread registers/sensors values (In jiffies) */
#define SENSOR_REFRESH_INTERVAL	(2 * HZ)

static struct pmcmon_data *r2kp_update_device(struct device *dev)
{
	struct pmcmon_data *data = dev_get_drvdata(dev);

	mutex_lock(&r2kp_pmc_service_lock);

	if (time_after(jiffies, data->last_updated +
			SENSOR_REFRESH_INTERVAL) ||
			!data->valid) {
		int i;
		void __iomem *regs = __pmc_regs(0);
		unsigned int x = __raw_readl(regs + PMC_R2KP_REG_TEMP);

		/* Register returns degrees, sysfs requires millidegrees. */
		data->temp[0] = ((s8)(x & 0xFF)) * 1000;
		data->temp[1] = ((s8)(x >> 8 & 0xFF)) * 1000;
		data->temp[2] = ((s8)(x >> 16 & 0xFF)) * 1000;

		x = __raw_readl(regs + PMC_R2KP_REG_TEMP_MAX);

		/* Register returns degrees */
		data->temp_crit = (u8)(x & 0xFF);
		data->temp_max  = (u8)(x >> 8 & 0xFF);
		data->temp_hyst = (u8)(x >> 16 & 0xFF);

		for (i = 0; i < 6; i++) {
			if (data->has_sensor & BIT(i)) {
				uint32_t param[PMC_R2KP_REG_PARAM_NUMBER] = {};

				if (r2kp_get_dev_attr(0, i, &param[0]) < 0) {
					data->in[i] = 0;
					data->curr[i] = 0;
				} else {
					data->in[i] = param[0];
					data->curr[i] = param[1];
				}
			}
		}
		data->last_updated = jiffies;
		data->valid = 1;
	}

	mutex_unlock(&r2kp_pmc_service_lock);
	return data;
}

/* Sysfs stuff */

static ssize_t r2kp_show_in(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct pmcmon_data *data = r2kp_update_device(dev);
	struct sensor_device_attribute *sensor_attr = to_sensor_dev_attr(attr);
	int i = sensor_attr->index;

	return sprintf(buf, "%d\n", data->in[i]);
}

static ssize_t r2kp_show_curr(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct pmcmon_data *data = r2kp_update_device(dev);
	struct sensor_device_attribute *sensor_attr = to_sensor_dev_attr(attr);
	int i = sensor_attr->index;

	return sprintf(buf, "%d\n", data->curr[i]);
}

static ssize_t r2kp_show_temp(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct pmcmon_data *data = r2kp_update_device(dev);
	struct sensor_device_attribute *sensor_attr = to_sensor_dev_attr(attr);
	int i = sensor_attr->index;

	return sprintf(buf, "%d\n", data->temp[i]);
}

static inline long temp_from_reg(u8 reg)
{
	return reg * 1000;
}

static ssize_t r2kp_show_temp_max(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct pmcmon_data *data = r2kp_update_device(dev);

	return sprintf(buf, "%ld\n", temp_from_reg(data->temp_max));
}

static ssize_t r2kp_show_temp_hyst(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct pmcmon_data *data = r2kp_update_device(dev);

	return sprintf(buf, "%ld\n", temp_from_reg(data->temp_hyst));
}

static ssize_t r2kp_show_temp_crit(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct pmcmon_data *data = r2kp_update_device(dev);

	return sprintf(buf, "%ld\n", temp_from_reg(data->temp_crit));
}

#define R2KP_MIN_TEMP (20)
#define R2KP_MAX_TEMP (105)

static inline u8 temp_to_reg(long val)
{
	if (val <= 1000 * R2KP_MIN_TEMP)
		return R2KP_MIN_TEMP;
	if (val >= 1000 * R2KP_MAX_TEMP)
		return R2KP_MAX_TEMP;
	return val / 1000;
}

static inline unsigned int get_temp_to_reg(struct pmcmon_data *data)
{
	return data->temp_crit +
		(data->temp_max << 8) +
		(data->temp_hyst << 16);
}

static ssize_t r2kp_set_temp_max(struct device *dev, struct device_attribute
			*attr, const char *buf, size_t count)
{
	struct pmcmon_data *data = r2kp_update_device(dev);
	long val;
	int err;
	void __iomem *regs = __pmc_regs(0);

	err = kstrtol(buf, 10, &val);
	if (err)
		return err;

	mutex_lock(&r2kp_pmc_service_lock);
	data->temp_max = temp_to_reg(val);
	__raw_writel(get_temp_to_reg(data), regs + PMC_R2KP_REG_TEMP_MAX);
	mutex_unlock(&r2kp_pmc_service_lock);

	return count;
}

static ssize_t r2kp_set_temp_crit(struct device *dev, struct device_attribute
			*attr, const char *buf, size_t count)
{
	struct pmcmon_data *data = r2kp_update_device(dev);
	long val;
	int err;
	void __iomem *regs = __pmc_regs(0);

	err = kstrtol(buf, 10, &val);
	if (err)
		return err;

	mutex_lock(&r2kp_pmc_service_lock);
	data->temp_crit = temp_to_reg(val);
	__raw_writel(get_temp_to_reg(data), regs + PMC_R2KP_REG_TEMP_MAX);
	mutex_unlock(&r2kp_pmc_service_lock);

	return count;
}

static ssize_t r2kp_set_temp_hyst(struct device *dev, struct device_attribute
			*attr, const char *buf, size_t count)
{
	struct pmcmon_data *data = r2kp_update_device(dev);
	long val;
	int err;
	void __iomem *regs = __pmc_regs(0);

	err = kstrtol(buf, 10, &val);
	if (err)
		return err;

	mutex_lock(&r2kp_pmc_service_lock);
	data->temp_hyst = temp_to_reg(val);
	__raw_writel(get_temp_to_reg(data), regs + PMC_R2KP_REG_TEMP_MAX);
	mutex_unlock(&r2kp_pmc_service_lock);

	return count;
}

static const char * const input_names[6] = {
	[0] = "gfx",
	[1] = "eioh",
	[2] = "ddr",
	[3] = "mc",
	[4] = "1v8",
	[5] = "core",
};

static const char * const temp_names[3] = {
	[0] = "core 0-1",
	[1] = "nb",
	[2] = "gpu",
};

static ssize_t r2kp_show_in_label(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	int i = to_sensor_dev_attr(attr)->index;

	return sprintf(buf, "vout_%s\n", input_names[i]);
}

static ssize_t r2kp_show_curr_label(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	int i = to_sensor_dev_attr(attr)->index;

	return sprintf(buf, "iout_%s\n", input_names[i]);
}

static umode_t r2kp_is_visible(struct kobject *kobj,
			struct attribute *attr, int index)
{
	struct device *dev = container_of(kobj, struct device, kobj);
	struct pmcmon_data *data = dev_get_drvdata(dev);

	if ((index < 24) && data->has_sensor & BIT(index/4))
		return attr->mode;

	return 0;
}

static ssize_t r2kp_show_temp_label(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	int i = to_sensor_dev_attr(attr)->index;

	return sprintf(buf, "temp_%s\n", temp_names[i]);
}

static SENSOR_DEVICE_ATTR(in1_input, S_IRUGO, r2kp_show_in, NULL, 0);
static SENSOR_DEVICE_ATTR(in2_input, S_IRUGO, r2kp_show_in, NULL, 1);
static SENSOR_DEVICE_ATTR(in3_input, S_IRUGO, r2kp_show_in, NULL, 2);
static SENSOR_DEVICE_ATTR(in4_input, S_IRUGO, r2kp_show_in, NULL, 3);
static SENSOR_DEVICE_ATTR(in5_input, S_IRUGO, r2kp_show_in, NULL, 4);
static SENSOR_DEVICE_ATTR(in6_input, S_IRUGO, r2kp_show_in, NULL, 5);

static SENSOR_DEVICE_ATTR(in1_label, S_IRUGO, r2kp_show_in_label, NULL, 0);
static SENSOR_DEVICE_ATTR(in2_label, S_IRUGO, r2kp_show_in_label, NULL, 1);
static SENSOR_DEVICE_ATTR(in3_label, S_IRUGO, r2kp_show_in_label, NULL, 2);
static SENSOR_DEVICE_ATTR(in4_label, S_IRUGO, r2kp_show_in_label, NULL, 3);
static SENSOR_DEVICE_ATTR(in5_label, S_IRUGO, r2kp_show_in_label, NULL, 4);
static SENSOR_DEVICE_ATTR(in6_label, S_IRUGO, r2kp_show_in_label, NULL, 5);

static SENSOR_DEVICE_ATTR(curr1_input, S_IRUGO, r2kp_show_curr, NULL, 0);
static SENSOR_DEVICE_ATTR(curr2_input, S_IRUGO, r2kp_show_curr, NULL, 1);
static SENSOR_DEVICE_ATTR(curr3_input, S_IRUGO, r2kp_show_curr, NULL, 2);
static SENSOR_DEVICE_ATTR(curr4_input, S_IRUGO, r2kp_show_curr, NULL, 3);
static SENSOR_DEVICE_ATTR(curr5_input, S_IRUGO, r2kp_show_curr, NULL, 4);
static SENSOR_DEVICE_ATTR(curr6_input, S_IRUGO, r2kp_show_curr, NULL, 5);

static SENSOR_DEVICE_ATTR(curr1_label, S_IRUGO, r2kp_show_curr_label, NULL, 0);
static SENSOR_DEVICE_ATTR(curr2_label, S_IRUGO, r2kp_show_curr_label, NULL, 1);
static SENSOR_DEVICE_ATTR(curr3_label, S_IRUGO, r2kp_show_curr_label, NULL, 2);
static SENSOR_DEVICE_ATTR(curr4_label, S_IRUGO, r2kp_show_curr_label, NULL, 3);
static SENSOR_DEVICE_ATTR(curr5_label, S_IRUGO, r2kp_show_curr_label, NULL, 4);
static SENSOR_DEVICE_ATTR(curr6_label, S_IRUGO, r2kp_show_curr_label, NULL, 5);

static struct attribute *r2kp_attrs[] = {
	&sensor_dev_attr_in1_input.dev_attr.attr,
	&sensor_dev_attr_in1_label.dev_attr.attr,
	&sensor_dev_attr_curr1_input.dev_attr.attr,
	&sensor_dev_attr_curr1_label.dev_attr.attr, /* 3 */
	&sensor_dev_attr_in2_input.dev_attr.attr,
	&sensor_dev_attr_in2_label.dev_attr.attr,
	&sensor_dev_attr_curr2_input.dev_attr.attr,
	&sensor_dev_attr_curr2_label.dev_attr.attr, /* 7 */
	&sensor_dev_attr_in3_input.dev_attr.attr,
	&sensor_dev_attr_in3_label.dev_attr.attr,
	&sensor_dev_attr_curr3_input.dev_attr.attr,
	&sensor_dev_attr_curr3_label.dev_attr.attr, /* 11 */
	&sensor_dev_attr_in4_input.dev_attr.attr,
	&sensor_dev_attr_in4_label.dev_attr.attr,
	&sensor_dev_attr_curr4_input.dev_attr.attr,
	&sensor_dev_attr_curr4_label.dev_attr.attr, /* 15 */
	&sensor_dev_attr_in5_input.dev_attr.attr,
	&sensor_dev_attr_in5_label.dev_attr.attr,
	&sensor_dev_attr_curr5_input.dev_attr.attr,
	&sensor_dev_attr_curr5_label.dev_attr.attr, /* 19 */
	&sensor_dev_attr_in6_input.dev_attr.attr,
	&sensor_dev_attr_in6_label.dev_attr.attr,
	&sensor_dev_attr_curr6_input.dev_attr.attr,
	&sensor_dev_attr_curr6_label.dev_attr.attr, /* 23 */
	NULL,
};

static const struct attribute_group r2kp_group = {
	.attrs = r2kp_attrs,
	.is_visible = r2kp_is_visible,
};

static SENSOR_DEVICE_ATTR(temp1_input, S_IRUGO, r2kp_show_temp, NULL, 0);
static SENSOR_DEVICE_ATTR(temp1_label, S_IRUGO, r2kp_show_temp_label, NULL, 0);
static SENSOR_DEVICE_ATTR(temp1_max, S_IRUGO | S_IWUSR,
				r2kp_show_temp_max, r2kp_set_temp_max, 0);
static SENSOR_DEVICE_ATTR(temp1_max_hyst, S_IRUGO | S_IWUSR,
				r2kp_show_temp_hyst, r2kp_set_temp_hyst, 0);
static SENSOR_DEVICE_ATTR(temp1_crit, S_IRUGO | S_IWUSR,
				r2kp_show_temp_crit, r2kp_set_temp_crit, 0);
static SENSOR_DEVICE_ATTR(temp2_input, S_IRUGO, r2kp_show_temp, NULL, 1);
static SENSOR_DEVICE_ATTR(temp2_label, S_IRUGO, r2kp_show_temp_label, NULL, 1);
static SENSOR_DEVICE_ATTR(temp2_max, S_IRUGO | S_IWUSR,
				r2kp_show_temp_max, r2kp_set_temp_max, 1);
static SENSOR_DEVICE_ATTR(temp2_max_hyst, S_IRUGO | S_IWUSR,
				r2kp_show_temp_hyst, r2kp_set_temp_hyst, 1);
static SENSOR_DEVICE_ATTR(temp2_crit, S_IRUGO | S_IWUSR,
				r2kp_show_temp_crit, r2kp_set_temp_crit, 1);
static SENSOR_DEVICE_ATTR(temp3_input, S_IRUGO, r2kp_show_temp, NULL, 2);
static SENSOR_DEVICE_ATTR(temp3_label, S_IRUGO, r2kp_show_temp_label, NULL, 2);
static SENSOR_DEVICE_ATTR(temp3_max, S_IRUGO | S_IWUSR,
				r2kp_show_temp_max, r2kp_set_temp_max, 2);
static SENSOR_DEVICE_ATTR(temp3_max_hyst, S_IRUGO | S_IWUSR,
				r2kp_show_temp_hyst, r2kp_set_temp_hyst, 2);
static SENSOR_DEVICE_ATTR(temp3_crit, S_IRUGO | S_IWUSR,
				r2kp_show_temp_crit, r2kp_set_temp_crit, 2);

static struct attribute *r2kp_attrs_temp[] = {
	&sensor_dev_attr_temp1_input.dev_attr.attr,
	&sensor_dev_attr_temp1_label.dev_attr.attr,
	&sensor_dev_attr_temp1_max.dev_attr.attr,
	&sensor_dev_attr_temp1_max_hyst.dev_attr.attr,
	&sensor_dev_attr_temp1_crit.dev_attr.attr,
	&sensor_dev_attr_temp2_input.dev_attr.attr,
	&sensor_dev_attr_temp2_label.dev_attr.attr,
	&sensor_dev_attr_temp2_max.dev_attr.attr,
	&sensor_dev_attr_temp2_max_hyst.dev_attr.attr,
	&sensor_dev_attr_temp2_crit.dev_attr.attr,
	&sensor_dev_attr_temp3_input.dev_attr.attr,
	&sensor_dev_attr_temp3_label.dev_attr.attr,
	&sensor_dev_attr_temp3_max.dev_attr.attr,
	&sensor_dev_attr_temp3_max_hyst.dev_attr.attr,
	&sensor_dev_attr_temp3_crit.dev_attr.attr,
	NULL,
};

static const struct attribute_group r2kp_group_temp = {
	.attrs = r2kp_attrs_temp,
};

static int pmc_r2kp_hwmon_init(struct platform_device *pdev)
{
	struct pmcmon_data *data;
	static struct device *hdev;
	int i;

	data = devm_kzalloc(&pdev->dev, sizeof(struct pmcmon_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->has_sensor = 0;
	data->valid = 0;
	data->last_updated = jiffies;
	/* Check and mark available V/A sensors */
	for (i = 0; i < 6; i++) {
		uint32_t param[PMC_R2KP_REG_PARAM_NUMBER] = {};
		int rc;

		mutex_lock(&r2kp_pmc_service_lock);
		rc = r2kp_get_dev_attr(0, i, &param[0]);
		if (rc == PMC_R2KP_STATUS_NOT_AVAIL) {
			mutex_unlock(&r2kp_pmc_service_lock);
			return -ENODEV;
		}
		mutex_unlock(&r2kp_pmc_service_lock);
		if ((rc < 0) || (param[0] == 0 && param[1] == 0))
			continue;
		data->has_sensor |= BIT(i);
	}
	data->groups[0] = &r2kp_group;
	data->groups[1] = &r2kp_group_temp;

	hdev = devm_hwmon_device_register_with_groups(
				&pdev->dev,
				KBUILD_MODNAME,
				data,
				data->groups);

	if (IS_ERR(hdev))
		return PTR_ERR(hdev);

	DebugPMC("pmc hwmon device enabled");

	return 0;
}

static struct platform_device *pdev;

static int __init pmc_r2kp_init(void)
{
	int err;
	struct device *dev = cpu_subsys.dev_root;

	if (e90s_get_cpu_type() != E90S_CPU_R2000P)
		return 0;

	pdev = platform_device_register_data(dev, "pmc", -1,
						NULL, 0);
	if (IS_ERR(pdev)) {
		dev_err(dev, "failed to create pmc platform device");
		return PTR_ERR(pdev);
	}

	err = pmc_r2kp_hwmon_init(pdev);
	if (err) {
		platform_device_unregister(pdev);
		dev_err(dev, "failed to create pmc hwmon device");
	}
	return err;
}

static void __exit pmc_r2kp_exit(void)
{
	platform_device_unregister(pdev);
}

MODULE_AUTHOR("Alexander.S.Kupriyanov@mcst.ru");
MODULE_DESCRIPTION("PMC for R2000+");
MODULE_LICENSE("GPL v2");

module_init(pmc_r2kp_init);
module_exit(pmc_r2kp_exit);
