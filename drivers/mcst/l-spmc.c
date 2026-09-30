/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Driver for SPMC controller that is part of IOHub-2/EIOHub.
 */

#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mtd/mtd.h>
#include <linux/irq.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/printk.h>
#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/freezer.h>
#include <linux/suspend.h>
#include <linux/cpufreq.h>
#include <linux/sched/signal.h>
#include <linux/input.h>
#include <linux/power_supply.h>

#include <asm/bootinfo.h>
#include <asm/hw_prefetchers.h>
#include <asm/pci.h>
#include <asm/spmc_regs.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/l_spmc.h>

#ifdef CONFIG_E2K
#include <asm/boot_recovery.h>
#include <asm/e2k_sic.h>
#endif

/* Sleep types: */
#define SLP_TYP_S0	0x0
#define SLP_TYP_S3	0x3
#define SLP_TYP_S4	0x4
#define SLP_TYP_S5	0x5

/* USB_CNTRL: */
/* Place then here. */
#define ACPI_SPMC_USB_CNTRL_WAKEUP_EN	(3 << 2)
#define ACPI_SPMC_USB_ISOL_CNTRL	(3 << 0)

#define DRV_NAME "l-spmc"

struct spmc_data {
	struct pci_dev *pdev;
	struct input_dev *input;
	raw_spinlock_t lock;
	bool s3_supported;
	struct power_supply *psy_ac;
	struct power_supply *psy_battery;
	bool ac_online;
	bool battery_low;
	struct work_struct psy_work;
	bool ac_notify;
	bool battery_notify;
};

#define BUTTON_DEVICE_NAME_POWER	"Power Button"
#define BUTTON_TYPE_POWER		0x01

/* Power Supply Interface for AC adapter */
static enum power_supply_property ac_props[] = {
	POWER_SUPPLY_PROP_ONLINE,
};

static int ac_get_property(struct power_supply *psy, enum power_supply_property psp,
							union power_supply_propval *val)
{
	struct spmc_data *data = power_supply_get_drvdata(psy);
	unsigned long flags;
	int ret = 0;

	raw_spin_lock_irqsave(&data->lock, flags);
	switch (psp) {
	case POWER_SUPPLY_PROP_ONLINE:
		val->intval = data->ac_online;
		break;
	default:
		ret = -EINVAL;
	}
	raw_spin_unlock_irqrestore(&data->lock, flags);
	return ret;
}

static const struct power_supply_desc ac_psy_desc = {
	.name = "mcst-ac",
	.type = POWER_SUPPLY_TYPE_MAINS,
	.properties = ac_props,
	.num_properties = ARRAY_SIZE(ac_props),
	.get_property = ac_get_property,
};

/* Power Supply Interface for Battery status */
static enum power_supply_property battery_props[] = {
	POWER_SUPPLY_PROP_CAPACITY_LEVEL,
};

static int battery_get_property(struct power_supply *psy, enum power_supply_property psp,
								union power_supply_propval *val)
{
	struct spmc_data *data = power_supply_get_drvdata(psy);
	unsigned long flags;
	int ret = 0;

	raw_spin_lock_irqsave(&data->lock, flags);
	switch (psp) {
	case POWER_SUPPLY_PROP_CAPACITY_LEVEL:
		if (data->ac_online) /* AC power */
			val->intval = POWER_SUPPLY_CAPACITY_LEVEL_UNKNOWN;
		else if (data->battery_low)
			val->intval = POWER_SUPPLY_CAPACITY_LEVEL_LOW;
		else
			val->intval = POWER_SUPPLY_CAPACITY_LEVEL_NORMAL;
		break;
	default:
		ret = -EINVAL;
	}
	raw_spin_unlock_irqrestore(&data->lock, flags);
	return ret;
}

static const struct power_supply_desc battery_psy_desc = {
	.name = "mcst-battery",
	.type = POWER_SUPPLY_TYPE_BATTERY,
	.properties = battery_props,
	.num_properties = ARRAY_SIZE(battery_props),
	.get_property = battery_get_property,
};

static void psy_worker(struct work_struct *work)
{
	struct spmc_data *data = container_of(work, struct spmc_data, psy_work);
	unsigned long flags;
	bool ac_notify = false;
	bool battery_notify = false;

	raw_spin_lock_irqsave(&data->lock, flags);
	if (data->ac_notify) {
		ac_notify = true;
		data->ac_notify = false;
	}
	if (data->battery_notify) {
		battery_notify = true;
		data->battery_notify = false;
	}
	raw_spin_unlock_irqrestore(&data->lock, flags);

	if (ac_notify && data->psy_ac)
		power_supply_changed(data->psy_ac);
	if (battery_notify && data->psy_battery)
		power_supply_changed(data->psy_battery);
}

/* handler for irq line 1 (spmc) */
static irqreturn_t spmc_irq_handler(int irq, void *dev_id)
{
	unsigned long flags;
	spmc_pm1_sts_t pm1_sts;
	struct spmc_data *c = (struct spmc_data *) dev_id;
	bool psy_need_update = false;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_STS, &pm1_sts.reg);

	/* Get the source of interrupt */
	if (pm1_sts.tmr_sts) {
		/* SCI interrupt form PM timer */
		/* handle it here */
		/* printk(KERN_ERR "SCI interrupt from PM timer.\n"); */
	} else if (pm1_sts.ac_power_sts) {
		/* SCI interrupt due change of ac_power_psnt */
		/* handle it here */
		/* printk(KERN_ERR "SCI interrupt from ac_power_psnt.\n"); */
		/* 1) check power source ac or battery */
		bool new_ac_state = pm1_sts.ac_power_state;

		psy_need_update = true;
		c->ac_notify = true;
		c->ac_online = new_ac_state;
#ifdef CONFIG_CPU_FREQ_GOV_PSTATES
		if (new_ac_state)
			set_cpu_pwr_limit(battery_pwr);
		else
			set_cpu_pwr_limit(init_cpu_pwr_limit);
#endif
	} else if (pm1_sts.batlow_sts) {
		/* SCI interrupt due change of ac_power_psnt */
		/* handle it here */
		/* printk(KERN_ERR "SCI interrupt from batlow.\n"); */
		bool is_low = pm1_sts.batlow_state;

		psy_need_update = true;
		c->battery_notify = true;
		c->battery_low = is_low;
	} else if (pm1_sts.pwrbtn_sts) {
		/* SCI interrupt due to power button */
		/* handle it here */
		/* printk(KERN_ERR "SCI interrupt from power button.\n"); */
		if (c->input != NULL) {
			input_report_key(c->input, KEY_POWER, 1);
			input_sync(c->input);
			input_report_key(c->input, KEY_POWER, 0);
			input_sync(c->input);
		}
	} else if (pm1_sts.wak_sts) {
		/* SCI interrupt due to wakeup event */
		/* handle it here */
		/* printk(KERN_ERR "SCI interrupt from wakeup event.\n"); */
	}

	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_STS, pm1_sts.reg);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	if (psy_need_update)
		schedule_work(&c->psy_work);

	return IRQ_HANDLED;
}

/* Sysfs layer */
/* sci */
static ssize_t spmc_show_sci(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	unsigned long flags;
	spmc_pm1_cnt_t pm1_cnt;
	struct spmc_data *c = dev_get_drvdata(dev);

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, &pm1_cnt.reg);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return sprintf(buf, "%i\n", pm1_cnt.sci_en);
}

static ssize_t spmc_store_sci(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long flags, val;
	spmc_pm1_cnt_t pm1_cnt;
	struct spmc_data *c = dev_get_drvdata(dev);

	if ((kstrtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, &pm1_cnt.reg);
	pm1_cnt.sci_en = !!val;
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, pm1_cnt.reg);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return count;
}

/* tmr */
static ssize_t spmc_store_tmr(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long flags, val;
	spmc_pm1_en_t pm1_en;
	struct spmc_data *c = dev_get_drvdata(dev);

	if ((kstrtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_EN, &pm1_en.reg);
	pm1_en.tmr_en = !!val;
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_EN, pm1_en.reg);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return count;
}

/* tmr32 */
static ssize_t spmc_show_tmr32(struct device *dev,
				struct device_attribute *attr, char *buf)
{

	unsigned long flags;
	spmc_pm1_en_t pm1_en;
	struct spmc_data *c = dev_get_drvdata(dev);

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_EN, &pm1_en.reg);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return sprintf(buf, "%i\n", pm1_en.tmr_32);
}

static ssize_t spmc_store_tmr32(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long flags, val;
	spmc_pm1_en_t pm1_en;
	struct spmc_data *c = dev_get_drvdata(dev);

	if ((kstrtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_EN, &pm1_en.reg);
	pm1_en.tmr_32 = !!val;
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_EN, pm1_en.reg);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return count;
}

/* ac_pwr */
static ssize_t spmc_store_ac_pwr(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long flags, val;
	spmc_pm1_en_t pm1_en;
	struct spmc_data *c = dev_get_drvdata(dev);

	if ((kstrtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_EN, &pm1_en.reg);
	pm1_en.ac_pwr_en = !!val;
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_EN, pm1_en.reg);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return count;
}

/* batlow */
static ssize_t spmc_store_batlow(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long flags, val;
	spmc_pm1_en_t pm1_en;
	struct spmc_data *c = dev_get_drvdata(dev);

	if ((kstrtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_EN, &pm1_en.reg);
	pm1_en.batlow_en = !!val;
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_EN, pm1_en.reg);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return count;
}

/* pwrbtn */
static ssize_t spmc_store_pwrbtn(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long flags, val;
	spmc_pm1_en_t pm1_en;
	struct spmc_data *c = dev_get_drvdata(dev);

	if ((kstrtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_EN, &pm1_en.reg);
	pm1_en.pwrbtn_en = !!val;
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_EN, pm1_en.reg);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return count;
}

/* slptyp */
static ssize_t spmc_show_slptyp(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	unsigned long flags;
	spmc_pm1_cnt_t pm1_cnt;
	struct spmc_data *c = dev_get_drvdata(dev);

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, &pm1_cnt.reg);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return sprintf(buf, "%i\n", pm1_cnt.slp_typx);
}

static ssize_t spmc_store_slptyp(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	unsigned long flags, val;
	spmc_pm1_cnt_t pm1_cnt;
	struct spmc_data *c = dev_get_drvdata(dev);
	int ret;

	ret = kstrtoul(buf, 10, &val);
	if (ret < 0)
		return ret;

	if (val != SLP_TYP_S0 &&
		val != SLP_TYP_S3 &&
		val != SLP_TYP_S4 &&
		val != SLP_TYP_S5)
		return -EINVAL;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, &pm1_cnt.reg);
	pm1_cnt.slp_typx = val;
	pm1_cnt.slp_en = 1;
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, pm1_cnt.reg);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return count;
}

/* pm_tmr */
static ssize_t spmc_show_pm_tmr(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	unsigned long flags;
	unsigned int x;
	struct spmc_data *c = dev_get_drvdata(dev);

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM_TMR, &x);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return sprintf(buf, "0x%x\n", x);
}

/* pm1_sts */
static ssize_t spmc_show_pm1_sts(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	unsigned long flags;
	unsigned int x;
	struct spmc_data *c = dev_get_drvdata(dev);

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_STS, &x);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return sprintf(buf, "0x%x\n", x);
}

/* pm1_en */
static ssize_t spmc_show_pm1_en(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	unsigned long flags;
	unsigned int x;
	struct spmc_data *c = dev_get_drvdata(dev);

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_EN, &x);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return sprintf(buf, "0x%x\n", x);
}

/* pm1_cnt */
static ssize_t spmc_show_pm1_cnt(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	unsigned long flags;
	unsigned int x;
	struct spmc_data *c = dev_get_drvdata(dev);

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, &x);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return sprintf(buf, "0x%x\n", x);
}

static DEVICE_ATTR(sci, S_IWUSR | S_IRUGO, spmc_show_sci, spmc_store_sci);
static DEVICE_ATTR(tmr, S_IWUSR, NULL, spmc_store_tmr);
static DEVICE_ATTR(tmr32, S_IWUSR | S_IRUGO, spmc_show_tmr32, spmc_store_tmr32);
static DEVICE_ATTR(ac_pwr, S_IWUSR, NULL, spmc_store_ac_pwr);
static DEVICE_ATTR(batlow, S_IWUSR, NULL, spmc_store_batlow);
static DEVICE_ATTR(pwrbtn, S_IWUSR, NULL, spmc_store_pwrbtn);
static DEVICE_ATTR(slptyp, S_IWUSR | S_IRUGO, spmc_show_slptyp, spmc_store_slptyp);

/* Debug monitors */
static DEVICE_ATTR(pm_tmr, S_IRUGO, spmc_show_pm_tmr, NULL);
static DEVICE_ATTR(pm1_sts, S_IRUGO, spmc_show_pm1_sts, NULL);
static DEVICE_ATTR(pm1_en, S_IRUGO, spmc_show_pm1_en, NULL);
static DEVICE_ATTR(pm1_cnt, S_IRUGO, spmc_show_pm1_cnt, NULL);

static struct attribute *spmc_attributes[] = {
	&dev_attr_sci.attr,
	&dev_attr_tmr.attr,
	&dev_attr_tmr32.attr,
	&dev_attr_ac_pwr.attr,
	&dev_attr_batlow.attr,
	&dev_attr_pwrbtn.attr,
	&dev_attr_slptyp.attr,
	&dev_attr_pm_tmr.attr,
	&dev_attr_pm1_sts.attr,
	&dev_attr_pm1_en.attr,
	&dev_attr_pm1_cnt.attr,
	NULL
};

static const struct attribute_group spmc_attr_group = {
	.attrs = spmc_attributes,
};

static struct pci_dev *l_spmc_pdev;

#ifdef CONFIG_SUSPEND
/* S3 (suspend to RAM support) */

static struct mtd_s3_context {
	struct mtd_info *mtd;
} s3_ctx;

static void mtd_s3_notify_add(struct mtd_info *mtd)
{
	if (strcmp(mtd->name, "S3"))
		return;

	if (!(mtd->flags & MTD_NO_ERASE) && mtd->size < mtd->erasesize) {
		pr_err("mtd_s3: MTD partition %d not big enough\n", mtd->index);
		return;
	}

	s3_ctx.mtd = mtd;
	pr_info("mtd_s3: attached to MTD device #%d: %s\n", mtd->index, mtd->name);
}

static void mtd_s3_notify_remove(struct mtd_info *mtd)
{
	if (s3_ctx.mtd && s3_ctx.mtd->index == mtd->index) {
		s3_ctx.mtd = NULL;
		pr_info("mtd_s3: removed MTD device %d\n", mtd->index);
	}
}

static struct mtd_notifier mtd_s3_notifier = {
	.add	= mtd_s3_notify_add,
	.remove	= mtd_s3_notify_remove,
};

static int __init mtd_s3_init(void)
{
	/* Setup the MTD device to use */
	if (IS_MACHINE_E2C3)
		register_mtd_user(&mtd_s3_notifier);

	return 0;
}
module_init(mtd_s3_init);

static void __exit mtd_s3_exit(void)
{
	if (IS_MACHINE_E2C3)
		unregister_mtd_user(&mtd_s3_notifier);
}
module_exit(mtd_s3_exit);


static int l_spmc_suspend_valid(suspend_state_t state)
{
	/* Since v6 secondary CPUs must be stopped in C3 so that they won't
	 * issue any memory accesses that can interfere with entering S3
	 * (see SPMC_EIOH documentation) */
	struct spmc_data *data = NULL;

	if (cpu_has(CPU_FEAT_ISET_V6) && state == PM_SUSPEND_MEM && cpu_has(CPU_HWBUG_C3))
		return false;

	if (state == PM_SUSPEND_MEM) {
		if (l_spmc_pdev)
			data = dev_get_drvdata(&l_spmc_pdev->dev);
		if (!data || !READ_ONCE(data->s3_supported))
			return false;
	}

	return state == PM_SUSPEND_TO_IDLE || state == PM_SUSPEND_MEM;
}

static void l_spmc_s3_enter(void *arg)
{
	spmc_pm1_cnt_t pm1_cnt;
	struct pci_dev *pdev = arg;

	/* Give other CPUs some time to enter C3 and stop issuing memory accesses */
	if (IS_ENABLED(CONFIG_SMP)) {
		if (cpu_has(CPU_HWBUG_C3)) {
			pr_emerg("WARNING: C3 is not supported, so S3 might work unreliably");
			pr_flush(1000, true);
		}
		udelay(10000);
	}

	if (IS_MACHINE_E1CP) {
		/* On e1c+ can just power everything down after flushing cache */
		local_write_back_cache_all();

		pci_read_config_dword(pdev, ACPI_SPMC_PM1_CNT, &pm1_cnt.reg);
		pm1_cnt.sci_en = 1;
		pci_write_config_dword(pdev, ACPI_SPMC_PM1_CNT, pm1_cnt.reg);

		pm1_cnt.slp_typx = SLP_TYP_S3;
		pm1_cnt.slp_en = 1;

		pci_write_config_dword(pdev, ACPI_SPMC_PM1_CNT, pm1_cnt.reg);
		pci_read_config_dword(pdev, ACPI_SPMC_PM1_CNT, &pm1_cnt.reg);
	} else if (IS_MACHINE_E2C3) {
		/* On e2c3 must also switch memory into special self-refresh
		 * mode after which must not issue any memory accesses;
		 * see 5.8 of SPMC_EIOH documentation. */
		u64 cycles_10us = 10 * loops_per_jiffy * HZ / USEC_PER_SEC;
		u64 cycles_100ns = 100 * loops_per_jiffy * HZ / NSEC_PER_SEC;
		int node = numa_node_id();
		e2k_hmu_mic_t hmu_mic;
		e2k_mmu_cr_t mmu_cr;
		e2k_mc_ch_t mc_ch_write = (e2k_mc_ch_t) { .n = 0xf };
		e2k_mc_pwr_t mc_pwr = { .word = sic_read_node_nbsr_reg(node, MC_PWR) };
		e2k_mc_ctl_t mc_ctl = { .word = sic_read_node_nbsr_reg(node, MC_CTL) };
		phys_addr_t node_nbsr = sic_get_node_nbsr_phys_base(node);
		phys_addr_t addr_spmc_pm1_cnt = domain_pci_conf_base(pci_domain_nr(pdev->bus)) +
				CONFIG_CMD(pdev->bus->number, pdev->devfn, ACPI_SPMC_PM1_CNT);

		/* Find active memory channels */
		AW(hmu_mic) = sic_read_node_nbsr_reg(numa_node_id(), HMU_MIC);
		if (WARN_ONCE(!hmu_mic.mcen, "HMU_MIC.mcen=0"))
			pr_flush(1000, true);

		/* Prepare SPMC */
		pci_read_config_dword(pdev, ACPI_SPMC_PM1_CNT, &pm1_cnt.reg);
		pm1_cnt.sci_en = 1;
		pci_write_config_dword(pdev, ACPI_SPMC_PM1_CNT, pm1_cnt.reg);
		pm1_cnt.slp_typx = SLP_TYP_S3;
		pm1_cnt.slp_en = 1;

		/* SPMC 5.8 1a) Set MC_CH */
		sic_write_node_nbsr_reg(node, MC_CH, AW(mc_ch_write));

		/* SPMC 5.8 1b) Set MC_PERF0 */
		if (cpu_has(CPU_HWBUG_RAM_SELF_REFRESH)) {
			e2k_mc_perf_t mc_perf0 = (e2k_mc_perf_t) {
				.reg0.reg_nr0 = 0,
				.reg0.pbmask = 1,
				/* CPU_HWBUG_RAM_SELF_REFRESH: clear arp_en.
				 * MC_PERF is not available for reading so
				 * set default values for other fields. */
				.reg0.arp_en = 0,
				.reg0.flt_brop = 1,
				.reg0.cmdpack = 1,
				.reg0.rd_weight = 3,
				.reg0.flt_prio = !!IS_MACHINE_E2C3,
				.reg0.apen = !IS_MACHINE_E2C3,
				.reg0.pt = 1,
				.reg0.rdpr_h = (IS_MACHINE_E2C3) ? 0xa : 0x14,
				.reg0.rd_prio_rsv = (IS_MACHINE_E2C3) ? 0x3 : 0,
			};

			sic_write_node_nbsr_reg(node, MC_PERF, AW(mc_perf0));
		}

		mc_pwr.pdmod = 4;
		/* If C3 is not available then we cannot guarantee that
		 * other CPUs won't issue memory accesses.  Do the second
		 * best thing by entering S3 as soon as possible. */
		mc_pwr.pdtmr = (cpu_has(CPU_HWBUG_C3)) ? 0 : 0xff;

		hw_prefetchers_save();

		/* Order is important: disable caching before flush */
		mmu_cr = get_MMU_CR();
		mmu_cr.cd = 3;
		set_MMU_CR(mmu_cr);
		local_write_back_cache_all();

		/* Other S3 entry code must be done without memory accesses */
		s3_entry_complete_e2c3(node, node_nbsr, cycles_10us, cycles_100ns,
				mc_pwr, mc_ctl, mc_ch_write,
				addr_spmc_pm1_cnt, pm1_cnt, hmu_mic.mcen);
	}
}

static int l_spmc_suspend_enter(suspend_state_t state)
{
	/* S3 powers off CPUs so save/restore their state */
	struct spmc_data *data = NULL;

	if (state == PM_SUSPEND_MEM) {
		if (l_spmc_pdev)
			data = dev_get_drvdata(&l_spmc_pdev->dev);
		if (!data || !READ_ONCE(data->s3_supported)) {
			dev_err(&l_spmc_pdev->dev, "L-SPMC: S3 entry is not supported on this board\n");
			return -EOPNOTSUPP;
		}
	}

	save_processor_state();

	restart_system(l_spmc_s3_enter, l_spmc_pdev);

	restore_processor_state();

	return 0;
}

static const struct platform_suspend_ops l_spmc_suspend_ops = {
	.valid = l_spmc_suspend_valid,
	.enter = l_spmc_suspend_enter,
};

static int l_power_event(struct notifier_block *this,
			   unsigned long event, void *ptr)
{
#ifdef CONFIG_E2K
	if (IS_MACHINE_E2C3 && event == PM_SUSPEND_PREPARE) {
		struct boot_info *boot_info = &bootblock_virt->info;
		struct mtd_info *mtd = s3_ctx.mtd;
		size_t retlen;
		int ret;

		if (!mtd) {
			pr_err("mtd_s3: spi-nor flash not found\n");
			return notifier_from_errno(-ENODEV);
		}

		if (boot_info->s3_info.ram_addr == -1ULL || boot_info->s3_info.size == -1ULL) {
			pr_err("mtd_s3: bad parameters for saving RAM settings: ram=0x%llx, size=0x%llx\n",
				boot_info->s3_info.ram_addr, boot_info->s3_info.size);
			return notifier_from_errno(-EINVAL);
		}

		if (mtd->size < boot_info->s3_info.size) {
			pr_err("mtd_s3: S3 MTD partition size 0x%llx is less than RAM parameters size 0x%llx\n",
				mtd->size, boot_info->s3_info.size);
			return notifier_from_errno(-EINVAL);
		}

		if (!(mtd->flags & MTD_NO_ERASE)) {
			struct erase_info erase_info = {
				.addr = 0,
				.len = roundup(boot_info->s3_info.size, mtd->erasesize),
			};
			ret = mtd_erase(mtd, &erase_info);
			if (ret) {
				pr_err("mtd_s3: erase failure at 0x%llx (0x%llx of 0x%llx erased), error %d\n",
					erase_info.fail_addr,
					erase_info.fail_addr - erase_info.addr,
					erase_info.len, ret);
				return notifier_from_errno(ret);
			}
		}

		ret = mtd_write(mtd, 0, boot_info->s3_info.size, &retlen,
				__va(boot_info->s3_info.ram_addr));
		if (retlen != boot_info->s3_info.size || ret < 0) {
			pr_err("mtd_s3: write failure (0x%lx of 0x%llx written), error %d\n",
				retlen, boot_info->s3_info.size, ret);
			if (!ret)
				ret = -EIO;
			return notifier_from_errno(ret);
		}
	} else if (!IS_MACHINE_E1CP && !IS_MACHINE_E2C3) {
		/* Suspend-to-ram requires support from both boot and
		 * hardware; hardware has support since iset v4 but boot
		 * has support only for e1cp and e2c3. So for everything
		 * but e1cp and e2c3 we allow only suspend-to-disk. */
		if (event != PM_HIBERNATION_PREPARE &&
		    event != PM_POST_HIBERNATION &&
		    event != PM_RESTORE_PREPARE &&
		    event != PM_POST_RESTORE)
			return notifier_from_errno(-EOPNOTSUPP);
	}
#endif
	return notifier_from_errno(0);
}

static struct notifier_block l_power_notifier = {
	.notifier_call = l_power_event,
};

#endif /*CONFIG_SUSPEND*/

/* If board contains IOHUB-2, SPMC can be used for implementing "halt"
 * by writing S5 to slptyp. This function is to be called from
 * l_halt_machine().
 */

void do_spmc_halt(void)
{
	spmc_pm1_cnt_t pm1_cnt;
	struct spmc_data *c;

	if (!l_spmc_pdev)
		return;

	c = dev_get_drvdata(&l_spmc_pdev->dev);
	if (!c)
		return;

	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, &pm1_cnt.reg);
	pm1_cnt.sci_en = 1;
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, pm1_cnt.reg);

	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, &pm1_cnt.reg);
	pm1_cnt.slp_typx = SLP_TYP_S0;
	pm1_cnt.slp_en = 1;
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, pm1_cnt.reg);

	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, &pm1_cnt.reg);
	pm1_cnt.slp_typx = SLP_TYP_S5;
	pm1_cnt.slp_en = 1;
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, pm1_cnt.reg);
	while (true) {
		cpu_relax();
	}
}
EXPORT_SYMBOL(do_spmc_halt);

static int input_button_register(struct pci_dev *pdev,
				  struct spmc_data *c)
{
	struct input_dev *input;
	int error;

	input = input_allocate_device();
	if (!input) {
		error = -ENOMEM;
		dev_err(&pdev->dev, "L-SPMC: Not enough memory\n");
		goto fail;
	}

	input->name = BUTTON_DEVICE_NAME_POWER;
	input->phys = "LNXPWRBN/button/input0";
	input->id.bustype = BUS_HOST;
	input->id.product = BUTTON_TYPE_POWER;
	input->dev.parent = &pdev->dev;
	c->input = input;

	set_bit(EV_KEY, input->evbit);
	set_bit(KEY_POWER, input->keybit);

	error = input_register_device(input);
	if (error)
		goto fail;

	return 0;

fail:
	input_free_device(input);
	c->input = NULL;
	return error;
}

static int spmc_probe(struct pci_dev *pdev,
				  struct spmc_data *c)
{
	struct device_node *np;
	int err;
	char *dsc = "SCI";
	unsigned x;
	struct power_supply_config psy_cfg = {};
	spmc_pm1_sts_t pm1_sts;
	spmc_pm1_en_t pm1_en;

	err = pcim_enable_device(pdev);
	if (err)
		return err;

	c->pdev = pdev;

	raw_spin_lock_init(&(c->lock));

	pci_read_config_dword(pdev, ACPI_SPMC_PM1_STS, &pm1_sts.reg);
	c->ac_online = pm1_sts.ac_power_state;
	c->battery_low = pm1_sts.batlow_state;

	INIT_WORK(&c->psy_work, psy_worker);

	psy_cfg.drv_data = c;

	/* Register AC Adapter */
	c->psy_ac = devm_power_supply_register(&pdev->dev, &ac_psy_desc, &psy_cfg);
	if (IS_ERR(c->psy_ac)) {
		err = PTR_ERR(c->psy_ac);
		dev_err(&pdev->dev, "Failed to register AC adapter! Error: %d\n", err);
		goto done;
	}

	/* Register Battery */
	c->psy_battery = devm_power_supply_register(&pdev->dev, &battery_psy_desc, &psy_cfg);
	if (IS_ERR(c->psy_battery)) {
		err = PTR_ERR(c->psy_battery);
		dev_err(&pdev->dev, "Failed to register Battery! Error: %d\n", err);
		goto done;
	}

	/* Default settings: */
	/* 1) ACPI (SCI enable or disable) & force S0 state */
	pci_write_config_dword(pdev, ACPI_SPMC_PM1_CNT,
			((spmc_pm1_cnt_t) {
				.slp_typx = SLP_TYP_S0,
				.slp_en = 1,
				.sci_en = 1
			}).reg);

	/* 2) TMR_32 */
	pci_write_config_dword(pdev, ACPI_SPMC_PM1_EN,
			((spmc_pm1_en_t) { .tmr_32 = 1 }).reg);

	/* 3) enable wakeup from usb */
	pci_read_config_dword(pdev, ACPI_SPMC_USB_CNTRL, &x);
	pci_write_config_dword(pdev, ACPI_SPMC_USB_CNTRL,
				x | ACPI_SPMC_USB_CNTRL_WAKEUP_EN);

	/* 4) PWRBTN enable */
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_EN, &pm1_en.reg);
	pm1_en.pwrbtn_en = 1;
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_EN, pm1_en.reg);

	np = pdev->dev.of_node;
	if (np) {
		/* S3 support enable if flag present in device tree */
		c->s3_supported = of_property_read_bool(np, "s3_support");
	} else {
		/* S3 support disable without device tree */
		c->s3_supported = false;
	}
	/* register sysfs entries */
	err = sysfs_create_group(&pdev->dev.kobj, &spmc_attr_group);
	if (err)
		goto done;

	/* SCI IRQ, Line 1: */
	err = request_irq(pdev->irq, spmc_irq_handler,
				IRQF_ONESHOT | IRQF_SHARED,
				dsc, c);
	if (err) {
		dev_err(&pdev->dev,
				"L-SPMC: unable to claim irq %d; err %d\n",
				pdev->irq, err);
		goto cleanup;
	}

	err = input_button_register(pdev, c);
	if (err)
		dev_err(&pdev->dev,
			"L-SPMC: Failed input_button_register err %d\n", err);

	dev_info(&pdev->dev,
		 DRV_NAME ": L-SPMC support successfully loaded.\n");

#ifdef CONFIG_SUSPEND
	suspend_set_ops(&l_spmc_suspend_ops);
#endif

	return 0;

cleanup:
	sysfs_remove_group(&pdev->dev.kobj, &spmc_attr_group);

done:
	return err;
}

static void spmc_remove(struct spmc_data *p)
{
	struct pci_dev *pdev = p->pdev;

	cancel_work_sync(&p->psy_work);
	free_irq(pdev->irq, p);
	sysfs_remove_group(&pdev->dev.kobj, &spmc_attr_group);

	if (p->input != NULL)
		input_unregister_device(p->input);
}

static int l_spmc_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int err = -ENODEV;
	struct spmc_data *idata;

	if (l_spmc_pdev)
		return 0;

	idata = devm_kzalloc(&pdev->dev, sizeof(*idata), GFP_KERNEL);
	if (!idata)
		return -ENOMEM;
	dev_set_drvdata(&pdev->dev, idata);
	l_spmc_pdev = pdev;

	err = spmc_probe(pdev, idata);
	if (err) {
		l_spmc_pdev = NULL;
		dev_set_drvdata(&pdev->dev, NULL);
		return err;
	}

#ifdef CONFIG_SUSPEND
	err = register_pm_notifier(&l_power_notifier);
	if (err) {
		l_spmc_pdev = NULL;
		spmc_remove(idata);
		dev_set_drvdata(&pdev->dev, NULL);
		return err;
	}
#endif
	return err;
}

static void __exit l_spmc_pci_remove(struct pci_dev *pdev)
{
	struct spmc_data *c = dev_get_drvdata(&pdev->dev);

#ifdef CONFIG_SUSPEND
	unregister_pm_notifier(&l_power_notifier);
#endif

	l_spmc_pdev = NULL;

	if (!c)
		return;

	spmc_remove(c);
	dev_set_drvdata(&pdev->dev, NULL);
}

static const struct pci_device_id l_spmc_pci_id_list[] = {
	{ PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_SPMC },
	{},
};
MODULE_DEVICE_TABLE(pci, l_spmc_pci_id_list);

static struct pci_driver l_spmc_pci_driver = {
	.name = DRV_NAME,
	.id_table = l_spmc_pci_id_list,
	.probe = l_spmc_pci_probe,
	.remove = l_spmc_pci_remove,
};
module_pci_driver(l_spmc_pci_driver);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("IOHub-2/EIOHub SPMC driver");
MODULE_LICENSE("GPL v2");
