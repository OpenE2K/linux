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
#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/freezer.h>
#include <linux/suspend.h>
#include <linux/cpufreq.h>
#include <linux/sched/signal.h>

#include <asm/bootinfo.h>
#include <asm/hw_prefetchers.h>
#include <asm/pci.h>
#include <asm/spmc_regs.h>
#include <asm/io_apic.h>
#include <asm/sic_regs.h>

#ifdef CONFIG_E2K
#include <asm/boot_recovery.h>
#include <asm/e2k_sic.h>
#endif

/* Offsets from BAR for ACPI-MCST registers */
#define ACPI_SPMC_DEVICE_ID	0x00

/* Sleep types: */
#define SLP_TYP_S0	0x0
#define SLP_TYP_S3	0x3
#define SLP_TYP_S4	0x4
#define SLP_TYP_S5	0x5

/* USB_CNTRL: */
/* Place then here. */
#define ACPI_SPMC_USB_CNTRL_WAKEUP_EN	(3 << 2)
#define ACPI_SPMC_USB_ISOL_CNTRL	(3 << 0)

#define DRV_NAME "acpi-spmc"
#define IOAPIC_SPMC_IRQ	1

struct acpi_spmc_data {
	struct pci_dev *pdev;
	raw_spinlock_t lock;
};

static struct acpi_spmc_data *gdata;


/* ACPI tainted interfaces and variables */

struct kobject *acpi_kobj;

#define ACPI_BUS_FILE_ROOT      "acpi"
struct proc_dir_entry   *acpi_root_dir;
#define ACPI_MAX_STRING		80

/* Global vars for handling event proc entry */
static DEFINE_SPINLOCK(acpi_system_event_lock);
int event_is_open = 0;
static DEFINE_SPINLOCK(acpi_bus_event_lock);

LIST_HEAD(acpi_bus_event_list);
DECLARE_WAIT_QUEUE_HEAD(acpi_bus_event_queue);

typedef char acpi_bus_id[8];
typedef char acpi_device_name[40];
typedef char acpi_device_class[20];

struct acpi_bus_event {
	struct list_head node;
	acpi_device_class device_class;
	acpi_bus_id bus_id;
	u32 type;
	u32 data;
};

/* Event related staff */
#define ACPI_AC_EVENT		0x1
#define ACPI_BATTERY_EVENT	0x2
#define ACPI_BUTTON_EVENT	0x3
#define ACPI_PMTIMER_EVENT	0x4
#define ACPI_UNKNOWN_EVENT	0xff

#define ACPI_AC_CLASS		"ac_adapter"
#define ACPI_BATTERY_CLASS	"battery"
#define ACPI_BUTTON_CLASS	"button"
#define ACPI_PMTIMER_CLASS	"pmtimer"

#define ACPI_BUSID_CLASS	"spmc"

#define ACPI_FIXED_HARDWARE_EVENT	0x00

int acpi_bus_generate_proc_event(const char *device_class, const char *bus_id, u8 type, int data)
{      
	struct acpi_bus_event *event;
	unsigned long flags = 0;
       
	/* drop event on the floor if no one's listening */
	if (!event_is_open)
		return 0;
       
	event = kmalloc(sizeof(struct acpi_bus_event), GFP_ATOMIC);
	if (!event)
		return -ENOMEM;

	strcpy(event->device_class, device_class);
	strcpy(event->bus_id, bus_id);
	event->type = type;
	event->data = data;

	spin_lock_irqsave(&acpi_bus_event_lock, flags);
	list_add_tail(&event->node, &acpi_bus_event_list);
	spin_unlock_irqrestore(&acpi_bus_event_lock, flags);

	wake_up_interruptible(&acpi_bus_event_queue);

	return 0;
}

int acpi_bus_receive_event(struct acpi_bus_event *event)
{
	unsigned long flags = 0;
	struct acpi_bus_event *entry = NULL;

	DECLARE_WAITQUEUE(wait, current);

	if (!event)
		return -EINVAL;

	if (list_empty(&acpi_bus_event_list)) {

		set_current_state(TASK_INTERRUPTIBLE);
		add_wait_queue(&acpi_bus_event_queue, &wait);

		if (list_empty(&acpi_bus_event_list))
			schedule();

		remove_wait_queue(&acpi_bus_event_queue, &wait);
		set_current_state(TASK_RUNNING);

		if (signal_pending(current))
			return -ERESTARTSYS;
	}

	spin_lock_irqsave(&acpi_bus_event_lock, flags);
	if (!list_empty(&acpi_bus_event_list)) {
		entry = list_entry(acpi_bus_event_list.next,
				   struct acpi_bus_event, node);
		list_del(&entry->node);
	}
	spin_unlock_irqrestore(&acpi_bus_event_lock, flags);

	if (!entry)
		return -ENODEV;

	memcpy(event, entry, sizeof(struct acpi_bus_event));

	kfree(entry);

	return 0;
}

static int acpi_system_open_event(struct inode *inode, struct file *file)
{
	spin_lock_irq(&acpi_system_event_lock);

	if (event_is_open)
		goto out_busy;

	event_is_open = 1;

	spin_unlock_irq(&acpi_system_event_lock);
	return 0;

 out_busy:
	spin_unlock_irq(&acpi_system_event_lock);
	return -EBUSY;
}

static ssize_t
acpi_system_read_event(struct file *file, char __user * buffer, size_t count,
			loff_t * ppos)
{
	int result = 0;
	struct acpi_bus_event event;
	static char str[ACPI_MAX_STRING];
	static int chars_remaining = 0;
	static char *ptr;

	if (!chars_remaining) {
		memset(&event, 0, sizeof(struct acpi_bus_event));

		if ((file->f_flags & O_NONBLOCK)
		    && (list_empty(&acpi_bus_event_list)))
			return -EAGAIN;

		result = acpi_bus_receive_event(&event);
		if (result)
			return result;

		chars_remaining = sprintf(str, "%s %s %08x %08x\n",
					  event.device_class ? event.
					  device_class : "<unknown>",
					  event.bus_id ? event.
					  bus_id : "<unknown>", event.type,
					  event.data);
		ptr = str;
	}

	if (chars_remaining < count) {
		count = chars_remaining;
	}

	if (copy_to_user(buffer, ptr, count))
		return -EFAULT;

	*ppos += count;
	chars_remaining -= count;
	ptr += count;

	return count;
}

static int acpi_system_close_event(struct inode *inode, struct file *file)
{
	spin_lock_irq(&acpi_system_event_lock);
	event_is_open = 0;
	spin_unlock_irq(&acpi_system_event_lock);
	return 0;
}

static unsigned int acpi_system_poll_event(struct file *file, poll_table * wait)
{
	poll_wait(file, &acpi_bus_event_queue, wait);
	if (!list_empty(&acpi_bus_event_list))
		return POLLIN | POLLRDNORM;
	return 0;
}

static const struct proc_ops acpi_system_event_ops = {
	.proc_open = acpi_system_open_event,
	.proc_read = acpi_system_read_event,
	.proc_release = acpi_system_close_event,
	.proc_poll = acpi_system_poll_event,
};

/* handler for irq line 1 (acpi-spmc) */
static irqreturn_t acpi_spmc_irq_handler(int irq, void *dev_id)
{
	unsigned long flags;
	spmc_pm1_sts_t pm1_sts;
	unsigned int event_id = ACPI_UNKNOWN_EVENT;
	unsigned int event_data = 0;
	struct acpi_spmc_data *c = (struct acpi_spmc_data *) dev_id;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_STS, &pm1_sts.reg);

	/* Get the source of interrupt */
	if (pm1_sts.tmr_sts) {
		/* SCI interrupt form PM timer */
		/* handle it here */
		/* printk(KERN_ERR "SCI interrupt from PM timer.\n"); */
		event_id = ACPI_PMTIMER_EVENT;
	} else if (pm1_sts.ac_power_sts) {
		/* SCI interrupt due change of ac_power_psnt */
		/* handle it here */
		/* printk(KERN_ERR "SCI interrupt from ac_power_psnt.\n"); */
		/* 1) check power source ac or battery */
		event_id = ACPI_AC_EVENT;
		if (pm1_sts.ac_power_state) {
			event_data = 1; /* ac on */
#ifdef CONFIG_CPU_FREQ_GOV_PSTATES
			set_cpu_pwr_limit(battery_pwr);
#endif
		} else {
			event_data = 0; /* ac off */
#ifdef CONFIG_CPU_FREQ_GOV_PSTATES
			set_cpu_pwr_limit(init_cpu_pwr_limit);
#endif
		}
	} else if (pm1_sts.batlow_sts) {
		/* SCI interrupt due change of ac_power_psnt */
		/* handle it here */
		/* printk(KERN_ERR "SCI interrupt from batlow.\n"); */
		event_id = ACPI_BATTERY_EVENT;
		/* battery low or ok */
		event_data = pm1_sts.batlow_state;
	} else if (pm1_sts.pwrbtn_sts) {
		/* SCI interrupt due to power button */
		/* handle it here */
		/* printk(KERN_ERR "SCI interrupt from power button.\n"); */
		event_id = ACPI_BUTTON_EVENT;
	} else if (pm1_sts.wak_sts) {
		/* SCI interrupt due to wakeup event */
		/* handle it here */
		/* printk(KERN_ERR "SCI interrupt from wakeup event.\n"); */
	} 

	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_STS, pm1_sts.reg);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	/* notify acpid on event */
	if (event_id == ACPI_PMTIMER_EVENT) {
		acpi_bus_generate_proc_event(ACPI_PMTIMER_CLASS,
					ACPI_BUSID_CLASS,
					ACPI_FIXED_HARDWARE_EVENT,
					1);
	} else if (event_id == ACPI_BUTTON_EVENT) {
		acpi_bus_generate_proc_event(ACPI_BUTTON_CLASS,
                                        ACPI_BUSID_CLASS,
                                        ACPI_FIXED_HARDWARE_EVENT,
                                        1);
	} else if (event_id == ACPI_AC_EVENT) {
		acpi_bus_generate_proc_event(ACPI_AC_CLASS,
                                        ACPI_BUSID_CLASS,
                                        ACPI_FIXED_HARDWARE_EVENT,
                                        event_data);
	} else if (event_id == ACPI_BATTERY_EVENT) {
		acpi_bus_generate_proc_event(ACPI_BATTERY_CLASS,
                                        ACPI_BUSID_CLASS,
                                        ACPI_FIXED_HARDWARE_EVENT,
                                        event_data);
	}

	return IRQ_HANDLED;
}

/* Sysfs layer */
/* sci */
static ssize_t spmc_show_sci(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	unsigned long flags;
	spmc_pm1_cnt_t pm1_cnt;
	struct acpi_spmc_data *c = gdata;

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
	struct acpi_spmc_data *c = gdata;

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
	struct acpi_spmc_data *c = gdata;

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
	struct acpi_spmc_data *c = gdata;

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
	struct acpi_spmc_data *c = gdata;

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
	struct acpi_spmc_data *c = gdata;

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
	struct acpi_spmc_data *c = gdata;

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
	struct acpi_spmc_data *c = gdata;

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
	struct acpi_spmc_data *c = gdata;

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
	struct acpi_spmc_data *c = gdata;
	int ret;

	ret = kstrtoul(buf, 10, &val);
	if (ret < 0)
		return ret;

	if (val < SLP_TYP_S0 || val > SLP_TYP_S5)
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
	struct acpi_spmc_data *c = gdata;

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
	struct acpi_spmc_data *c = gdata;

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
	struct acpi_spmc_data *c = gdata;

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
	struct acpi_spmc_data *c = gdata;

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

static struct attribute *acpi_spmc_attributes[] = {
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

static const struct attribute_group acpi_spmc_attr_group = {
	.attrs = acpi_spmc_attributes,
};

#ifdef CONFIG_SUSPEND
/* S3 (suspend to RAM support) */

static struct mtd_s3_context {
	struct mtd_info *mtd;
} s3_ctx;

static void mtd_s3_notify_add(struct mtd_info *mtd)
{
	if (strcmp(mtd->name, "rS3S4"))
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


static struct pci_dev *l_spmc_pdev;

static int l_spmc_suspend_valid(suspend_state_t state)
{
	/* Since v6 secondary CPUs must be stopped in C3 so that they won't
	 * issue any memory accesses that can interfere with entering S3
	 * (see SPMC_EIOH documentation) */
	if (cpu_has(CPU_FEAT_ISET_V6) && state == PM_SUSPEND_MEM && cpu_has(CPU_HWBUG_C3))
		return false;

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
	restart_system(l_spmc_s3_enter, l_spmc_pdev);
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
		struct bios_info *bios_info = &bootblock_virt->info.bios;
		struct mtd_info *mtd = s3_ctx.mtd;
		size_t retlen;
		int ret;

		if (!mtd) {
			pr_err("mtd_s3: spi-nor flash not found\n");
			return notifier_from_errno(-ENODEV);
		}

		if (bios_info->s3_info.ram_addr == -1ULL || bios_info->s3_info.size == -1ULL) {
			pr_err("mtd_s3: bad parameters for saving RAM settings: ram=0x%llx, size=0x%llx\n",
				bios_info->s3_info.ram_addr, bios_info->s3_info.size);
			return notifier_from_errno(-EINVAL);
		}

		if (mtd->size < bios_info->s3_info.size) {
			pr_err("mtd_s3: rS3S4 MTD partition size 0x%llx is less than RAM parameters size 0x%llx\n",
				mtd->size, bios_info->s3_info.size);
			return notifier_from_errno(-EINVAL);
		}

		if (!(mtd->flags & MTD_NO_ERASE)) {
			struct erase_info erase_info = {
				.addr = 0,
				.len = roundup(bios_info->s3_info.size, mtd->erasesize),
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

		ret = mtd_write(mtd, 0, bios_info->s3_info.size, &retlen,
				__va(bios_info->s3_info.ram_addr));
		if (retlen != bios_info->s3_info.size || ret < 0) {
			pr_err("mtd_s3: write failure (0x%lx of 0x%llx written), error %d\n",
				retlen, bios_info->s3_info.size, ret);
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

static int __init acpi_spmc_probe(struct pci_dev *pdev,
				  struct acpi_spmc_data *c)
{
	struct device_node *np;
	int err, ret;
	char *dsc = "SCI";
	unsigned x;
	u32 prop;

	err = pci_enable_device(pdev);
	if (err)
		return err;

	c->pdev = pdev;

	raw_spin_lock_init(&(c->lock));

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

	np = of_find_node_by_name(NULL, "acpi-spmc");
	if (np) {
		/* 5) SCI value from device tree (enable or disable) */
		ret = of_property_read_u32(np, "sci", &prop);
		if ((!ret) && (prop < 2)) {
			spmc_pm1_cnt_t pm1_cnt;
			pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, &pm1_cnt.reg);
			pm1_cnt.sci_en = !!prop;
			pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, pm1_cnt.reg);
		}
		/* 6) PWRBTN value from device tree (enable or disable) */
		ret = of_property_read_u32(np, "pwrbtn", &prop);
		if ((!ret) && (prop < 2)) {
			spmc_pm1_en_t pm1_en;
			pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_EN, &pm1_en.reg);
			pm1_en.pwrbtn_en = !!prop;
			pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_EN, pm1_en.reg);
		}
		/* 7) SLPTYP value from device tree (0-5) */
		ret = of_property_read_u32(np, "slptyp", &prop);
		if ((!ret) && (prop <= SLP_TYP_S5)) {
			spmc_pm1_cnt_t pm1_cnt;
			pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, &pm1_cnt.reg);
			pm1_cnt.slp_typx = prop;
			pm1_cnt.slp_en = 1;
			pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, pm1_cnt.reg);
		}
	} else {
		/* 8) PWRBTN enable without device tree */
		spmc_pm1_en_t pm1_en;
		pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_EN, &pm1_en.reg);
		pm1_en.pwrbtn_en = 1;
		pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_EN, pm1_en.reg);
	}

	/* register sysfs entries */
	err = sysfs_create_group(&pdev->dev.kobj, &acpi_spmc_attr_group);
	if (err)
		goto done;

	/* SCI IRQ, Line 1: */
	err = request_irq(IOAPIC_SPMC_IRQ, acpi_spmc_irq_handler,
				IRQF_ONESHOT | IRQF_SHARED,
				dsc, c);
	if (err) {
		dev_err(&pdev->dev,
				"ACPI-SPMC: unable to claim irq %d; err %d\n",
				IOAPIC_SPMC_IRQ, err);
		goto cleanup;
	}

	dev_info(&pdev->dev,
		 DRV_NAME ": ACPI-SPMC support successfully loaded.\n");

#ifdef CONFIG_SUSPEND
	suspend_set_ops(&l_spmc_suspend_ops);
	l_spmc_pdev = pdev;
#endif

	return 0;

cleanup:
	sysfs_remove_group(&pdev->dev.kobj, &acpi_spmc_attr_group);	

done:
	return err;
}

static void __exit acpi_spmc_remove(struct acpi_spmc_data *p)
{
	struct pci_dev *pdev = p->pdev;

	free_irq(IOAPIC_SPMC_IRQ, p);
	sysfs_remove_group(&pdev->dev.kobj, &acpi_spmc_attr_group);
}

static int __init acpi_spmc_init(void)
{
	struct pci_dev *pdev = NULL;
	int err = -ENODEV;
	struct acpi_spmc_data *idata;
	struct proc_dir_entry *entry;

#ifdef CONFIG_SUSPEND
	err = register_pm_notifier(&l_power_notifier);
	if (err)
		return err;
#endif
	/* Implementation for single IOHUB-2 on board (no domains) */

	pdev = pci_get_device(PCI_VENDOR_ID_MCST_TMP,
			      PCI_DEVICE_ID_MCST_SPMC,
			      pdev);
	if (!pdev)
		return 0;

	if (!(idata = kzalloc(sizeof(*idata), GFP_KERNEL)))
		return -ENOMEM;

	err = acpi_spmc_probe(pdev, idata);
	if (err) {
		pci_dev_put(pdev);
		return err;
	}

	gdata = idata;

	/* Long initialization process of ACPI tainted interfaces */

	/* ACPI sysfs top dir */
	acpi_kobj = kobject_create_and_add("acpi", firmware_kobj);
	if (!acpi_kobj) {
		printk(KERN_WARNING "%s: kset create error\n", __func__);
		acpi_kobj = NULL;
	}

	/* Create the top ACPI proc directory */
	acpi_root_dir = proc_mkdir(ACPI_BUS_FILE_ROOT, NULL);

	/* /proc/acpi/event [R] */
        entry = proc_create("event", S_IRUSR, acpi_root_dir,
                            &acpi_system_event_ops);
        if (!entry) {

		pci_dev_put(pdev);
		gdata = NULL;
                return -ENODEV;
	}
	return err;
}

static void __exit acpi_spmc_exit(void)
{
	proc_remove(acpi_root_dir);
	kobject_put(acpi_kobj);
	acpi_spmc_remove(gdata);
	pci_dev_put(gdata->pdev);
	kfree(gdata);
	gdata = NULL;
}

device_initcall(acpi_spmc_init);
/* module_init(acpi_spmc_init); */
/* module_exit(acpi_spmc_exit); */


/* If board contains IOHUB-2, SPMC can be used for implementing "halt"
 * by writing S5 to slptyp. This function is to be called from 
 * l_halt_machine().
 */

void do_spmc_halt(void)
{
	spmc_pm1_cnt_t pm1_cnt;
	struct acpi_spmc_data *c = gdata;
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

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("IOHub-2/EIOHub SPMC driver");
MODULE_LICENSE("GPL v2");
