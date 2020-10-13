/*
 * arch/l/kernel/acpi/l_spmc.c
 *
 * Copyright (C) 2015 Evgeny Kravtsunov MCST.
 *
 * Driver for SPMC controller that is part of Processor-8 (KPI-2).
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <linux/slab.h>

#include <asm/pci.h>
#include <asm/io_apic.h>

/* Offsets from BAR for ACPI-MCST registers */
#define ACPI_SPMC_DEVICE_ID	0x00

/* ACPI 4.0 regs: */
#define ACPI_SPMC_PM_TMR	0x40
#define ACPI_SPMC_PM1_STS	0x44
#define ACPI_SPMC_PM1_EN	0x48
#define ACPI_SPMC_PM1_CNT	0x4c

/* Additional regs: */
#define ACPI_SPMC_ATNSUS_CNT	0x50
#define ACPI_SPMC_PURST_CNT	0x54
#define ACPI_SPMC_USB_CNTRL	0x58

/* Control area size: */
#define ACPI_SPMC_CNTRL_AREA_SIZE	0x5c

/* Define bit shifts for regs */
/* PM1_STS: */
#define SPMC_PM1_STS_TMR_STS		0	/* R/W1C */
#define SPMC_PM1_STS_AC_PWR_STATE	1	/* RO */
#define SPMC_PM1_STS_AC_PWR_STS		2	/* R/W1C */
#define SPMC_PM1_STS_BATLOW_STATE	3	/* RO */
#define SPMC_PM1_STS_BATLOW_STS		4	/* R/W1C */
#define SPMC_PM1_STS_ATN_STS		5	/* RO */
#define SPMC_PM1_STS_PWRBTN_STS		8	/* R/W1C */
#define SPMC_PM1_STS_WAK_STS		15	/* R/W1C */

/* PM1_EN: */
#define SPMC_PM1_EN_TMR_EN		0	/* WO */
#define SPMC_PM1_EN_TMR_32		1	/* RW */
#define SPMC_PM1_EN_AC_PWR_EN		2	/* WO */
#define SPMC_PM1_EN_BATLOW_EN		4	/* WO */
#define SPMC_PM1_EN_PWRBTN_EN		8	/* WO */

/* PM1_CNT: */
#define SPMC_PM1_CNT_SCI_EN		0	/* RW */
#define SPMC_PM1_CNT_SLP_TYP		10	/* RW */
#define SPMC_PM1_CNT_SLP_EN		13	/* WO */

/* Sleep types: */
#define SLP_TYP_S0	0x0
#define SLP_TYP_S1	SLP_TYP_S0
#define SLP_TYP_S2	SLP_TYP_S0
#define SLP_TYP_S3	0x3
#define SLP_TYP_S4	0x4
#define SLP_TYP_S5	0x5
#define SLP_TYP_S6	SLP_TYP_S0
#define SLP_TYP_S7	SLP_TYP_S0

/* USB_CNTRL: */
/* Place then here. */

/* Bit access helpers: */
#define ACPI_SPMC_ONE_MASK(x)		(1 << (x))
#define ACPI_SPMC_ZERO_MASK(x)		(~(1 << (x)))
#define ACPI_SPMC_SET_SLP_TYP(x)	((x & 7) << SPMC_PM1_CNT_SLP_TYP)
#define ACPI_SPMC_GET_SLP_TYP(x)        ((x >> SPMC_PM1_CNT_SLP_TYP) & 7)

/* Initial configuration values: */
#define SPMC_LEGACY_PM1_CNT_DEF		0x00000000	
#define SPMC_TMR32_PM1_EN_DEF		0x00000002

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

static const struct file_operations acpi_system_event_ops = {
	.owner = THIS_MODULE,
	.open = acpi_system_open_event,
	.read = acpi_system_read_event,
	.release = acpi_system_close_event,
	.poll = acpi_system_poll_event,
};

/* handler for irq line 1 (acpi-spmc) */
static irqreturn_t acpi_spmc_irq_handler(int irq, void *dev_id)
{
	unsigned long flags;
	unsigned int x;

	unsigned int event_id = ACPI_UNKNOWN_EVENT;
	unsigned int event_data = 0;
	

	struct acpi_spmc_data *c = (struct acpi_spmc_data *)dev_id;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_STS, &x);

	/* Get the source of interrupt */
	if (x & ACPI_SPMC_ONE_MASK(SPMC_PM1_STS_TMR_STS)) {
		/* SCI interrupt form PM timer */
		/* handle it here */
		/* printk(KERN_ERR "SCI interrupt from PM timer.\n"); */
		event_id = ACPI_PMTIMER_EVENT;
	} else if (x & ACPI_SPMC_ONE_MASK(SPMC_PM1_STS_AC_PWR_STS)) {
		/* SCI interrupt due change of ac_power_psnt */
		/* handle it here */
		/* printk(KERN_ERR "SCI interrupt from ac_power_psnt.\n"); */
		/* 1) check power source ac or battery */
		event_id = ACPI_AC_EVENT;
		if (x & ACPI_SPMC_ONE_MASK(SPMC_PM1_STS_AC_PWR_STATE)) {
			event_data = 1; /* ac on */
		} else {
			event_data = 0; /* ac off */
		}
	} else if (x & ACPI_SPMC_ONE_MASK(SPMC_PM1_STS_BATLOW_STS)) {
		/* SCI interrupt due change of ac_power_psnt */
		/* handle it here */
		/* printk(KERN_ERR "SCI interrupt from batlow.\n"); */
		event_id = ACPI_BATTERY_EVENT;
		if (x & ACPI_SPMC_ONE_MASK(SPMC_PM1_STS_BATLOW_STATE)) {
			event_data = 1; /* battery low */
		} else {
			event_data = 0; /* battery ok */
		}
	} else if (x & ACPI_SPMC_ONE_MASK(SPMC_PM1_STS_PWRBTN_STS)) {
		/* SCI interrupt due to power button */
		/* handle it here */
		/* printk(KERN_ERR "SCI interrupt from power button.\n"); */
		event_id = ACPI_BUTTON_EVENT;
	} else if (x & ACPI_SPMC_ONE_MASK(SPMC_PM1_STS_WAK_STS)) {
		/* SCI interrupt due to wakeup event */
		/* handle it here */
		/* printk(KERN_ERR "SCI interrupt from wakeup event.\n"); */
	} 

	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_STS, x);
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
	unsigned int x;
	unsigned int val;
	struct acpi_spmc_data *c = gdata;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, &x);
	raw_spin_unlock_irqrestore(&c->lock, flags);
	
	if ( x & ACPI_SPMC_ONE_MASK(SPMC_PM1_CNT_SCI_EN))
		val = 1;
	else
		val = 0;
	
	return sprintf(buf, "%i\n", val);
}

static ssize_t spmc_store_sci(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long flags;
	unsigned int x;
	unsigned long val;
	struct acpi_spmc_data *c = gdata;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, &x);
	if (val) {
		x |= ACPI_SPMC_ONE_MASK(SPMC_PM1_CNT_SCI_EN);
	} else {
		x &= ~(ACPI_SPMC_ONE_MASK(SPMC_PM1_CNT_SCI_EN));
	}
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, x);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return count;
}

/* tmr */
static ssize_t spmc_store_tmr(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long flags;
	unsigned int x;
	unsigned long val;
	struct acpi_spmc_data *c = gdata;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_EN, &x);
	if (val) {
		x |= ACPI_SPMC_ONE_MASK(SPMC_PM1_EN_TMR_EN);
	} else {
		x &= ~(ACPI_SPMC_ONE_MASK(SPMC_PM1_EN_TMR_EN));
	}
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_EN, x);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return count;
}

/* tmr32 */
static ssize_t spmc_show_tmr32(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	unsigned long flags;
	unsigned int x;
	unsigned int val;
	struct acpi_spmc_data *c = gdata;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_EN, &x);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	if ( x & ACPI_SPMC_ONE_MASK(SPMC_PM1_EN_TMR_32))
		val = 1;
	else
		val = 0;

	return sprintf(buf, "%i\n", val);
}

static ssize_t spmc_store_tmr32(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long flags;
	unsigned int x;
	unsigned long val;
	struct acpi_spmc_data *c = gdata;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_EN, &x);
	if (val) {
		x |= ACPI_SPMC_ONE_MASK(SPMC_PM1_EN_TMR_32);
	} else {
		x &= ~(ACPI_SPMC_ONE_MASK(SPMC_PM1_EN_TMR_32));
	}
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_EN, x);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return count;
}

/* ac_pwr */
static ssize_t spmc_store_ac_pwr(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long flags;
	unsigned int x;
	unsigned long val;
	struct acpi_spmc_data *c = gdata;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_EN, &x);
	if (val) {
		x |= ACPI_SPMC_ONE_MASK(SPMC_PM1_EN_AC_PWR_EN);
	} else {
		x &= ~(ACPI_SPMC_ONE_MASK(SPMC_PM1_EN_AC_PWR_EN));
	}
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_EN, x);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return count;
}

/* batlow */
static ssize_t spmc_store_batlow(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long flags;
	unsigned int x;
	unsigned long val;
	struct acpi_spmc_data *c = gdata;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_EN, &x);
	if (val) {
		x |= ACPI_SPMC_ONE_MASK(SPMC_PM1_EN_BATLOW_EN);
	} else {
		x &= ~(ACPI_SPMC_ONE_MASK(SPMC_PM1_EN_BATLOW_EN));
	}
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_EN, x);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return count;
}

/* pwrbtn */
static ssize_t spmc_store_pwrbtn(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long flags;
	unsigned int x;
	unsigned long val;
	struct acpi_spmc_data *c = gdata;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_EN, &x);
	if (val) {
		x |= ACPI_SPMC_ONE_MASK(SPMC_PM1_EN_PWRBTN_EN);	
	} else {
		x &= ~(ACPI_SPMC_ONE_MASK(SPMC_PM1_EN_PWRBTN_EN));
	}
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_EN, x);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	return count;
}

/* slptyp */
static ssize_t spmc_show_slptyp(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	unsigned long flags;
	unsigned int x;
	unsigned int val;
	struct acpi_spmc_data *c = gdata;

	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, &x);
	raw_spin_unlock_irqrestore(&c->lock, flags);

	val = ACPI_SPMC_GET_SLP_TYP(x);

	return sprintf(buf, "%i\n", val);
}

static ssize_t spmc_store_slptyp(struct device *dev,
                                    struct device_attribute *attr,
                                    const char *buf, size_t count)
{
	unsigned long flags;
	unsigned int x;
	unsigned long val;
	struct acpi_spmc_data *c = gdata;

	if ((strict_strtoul(buf, 10, &val) < SLP_TYP_S0) ||
						(val > SLP_TYP_S5))
		return -EINVAL;


	raw_spin_lock_irqsave(&c->lock, flags);
	pci_read_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, &x);
	x &= ~(ACPI_SPMC_SET_SLP_TYP(0x7));
	x |= (ACPI_SPMC_SET_SLP_TYP((unsigned int)val));
	x |= (ACPI_SPMC_ONE_MASK(SPMC_PM1_CNT_SLP_EN)); 
	pci_write_config_dword(c->pdev, ACPI_SPMC_PM1_CNT, x);
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

static int __init acpi_spmc_probe(struct pci_dev *pdev,
				  struct acpi_spmc_data *c)
{
	int err;
	char *dsc = "SCI";

	c->pdev = pdev;

	raw_spin_lock_init(&(c->lock));

	/* Default settings: */
	/* 1) Legacy/ACPI (SCI enable or disable) */
	pci_write_config_dword(pdev, ACPI_SPMC_PM1_CNT, 
						SPMC_LEGACY_PM1_CNT_DEF);

	/* 2) TMR_32 */
	pci_write_config_dword(pdev, ACPI_SPMC_PM1_EN, 
						SPMC_TMR32_PM1_EN_DEF); 

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

	/* Implementation for single KPI-2 on board (no domains) */

	pdev = pci_get_device(PCI_VENDOR_ID_MCST_TMP,
			      PCI_DEVICE_ID_MCST_SPMC,
			      pdev);
	if (!pdev)
		return err;

	printk(KERN_ERR "acpi_spmc_init got pdev = %lx\n", pdev);

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
}

module_init(acpi_spmc_init);
module_exit(acpi_spmc_exit);

MODULE_AUTHOR("Evgeny Kravtsunov <kravtsunov_e@mcst.ru>");
MODULE_DESCRIPTION("Processor-8 SPMC driver");
MODULE_LICENSE("GPL");
