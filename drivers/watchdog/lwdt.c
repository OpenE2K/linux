/*
 * drivers/watchdog/lwdt.c
 * 
 * Elbrus watchdog reset driver.
 *
 * Copyright (C) 2009-2014 Pavel V. Panteleev (panteleev_p@mcst.ru)
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#ifdef CONFIG_MCST_RT
#include <linux/sched.h>
#endif
#include <linux/watchdog.h>

#include <asm/uaccess.h>
#include <asm/l_timer.h>
#include <asm/console.h>

#ifdef	__e2k__
#include <asm/mmu_regs_access.h>
#endif	/* __e2k__ */

#define DEBUG_WD		0
#define dbgwd			if (DEBUG_WD) printk

#define WD_SEC_DEFAULT		10

typedef struct wd_opts {
	int (*lwdt_start)(void);
	int (*lwdt_stop)(void);
	void (*lwdt_ping)(void);
} lwdt_opts_t;

static unsigned int heartbeat = WD_SEC_DEFAULT;
module_param(heartbeat, int, 0);
MODULE_PARM_DESC(heartbeat,
	"Watchdog heartbeat in seconds (default="
				__MODULE_STRING(WD_SEC_DEFAULT) ")");

static int nowayout = WATCHDOG_NOWAYOUT;
module_param(nowayout, int, 0);
MODULE_PARM_DESC(nowayout,
	"Watchdog cannot be stopped once started (default="
				__MODULE_STRING(WATCHDOG_NOWAYOUT) ")");

static lwdt_opts_t	*lwdt_opts;
static unsigned long	lwdt_is_open;
static char		expect_close;

#ifdef	__e2k__
static unsigned long	wd_init_value;
#endif	/* __e2k__ */

/*
 * E3M
 */

#ifdef	__e2k__

static void start_apic_watchdog(void *unused)
{
	unsigned long flags;
	unsigned int tmp_value;
	
	dbgwd("wd: enter start_apic_watchdog()\n");
	raw_local_irq_save(flags);

	/*
	 * Set Apic NM_TIMER mask
	 */

	tmp_value = apic_read(APIC_M_ERM);
	tmp_value |= APIC_NM_TIMER;
	apic_write(APIC_M_ERM, tmp_value);
	
	/*
	 * Unset Apic NM_TIMER request
	 */

	tmp_value = APIC_NM_TIMER;
	apic_write(APIC_NM, tmp_value);

	tmp_value = APIC_LVT_TIMER_PERIODIC;
	apic_write(APIC_NM_TIMER_LVTT, tmp_value);
	
	tmp_value = apic_read(APIC_NM_TIMER_DIVIDER);
	apic_write(APIC_NM_TIMER_DIVIDER, 
		(tmp_value & ~(APIC_TDR_DIV_1 | APIC_TDR_DIV_TMBASE)) |
			APIC_TDR_DIV_1);

	wd_init_value = ((long) lapic_timer_frequency * heartbeat * HZ);
	wd_init_value >>= 1;
	
	apic_write(APIC_NM_TIMER_INIT_COUNT, wd_init_value);
	
	tmp_value = apic_read(APIC_M_ERM);
	tmp_value |= APIC_NM_WATCHDOG;
	apic_write(APIC_M_ERM, tmp_value);

	raw_local_irq_restore(flags);
	dbgwd("wd: exit start_apic_watchdog()\n");
} 

static int start_apic_watchdogs(void)
{
	dbgwd("wd: start_apic_watchdogs()\n");
	on_each_cpu(start_apic_watchdog, 0, 1);
	return 0;
}

static void stop_apic_watchdog(void *unused)
{
	unsigned long flags;
	unsigned int tmp_value;

	dbgwd("wd: enter stop_apic_watchdog()\n");
	raw_local_irq_save(flags);
	
	/*
	 * Set Apic NM_TIMER mask
	 */

	tmp_value = apic_read(APIC_M_ERM);
	tmp_value |= APIC_NM_TIMER;
	tmp_value &= (~APIC_NM_WATCHDOG);
	apic_write(APIC_M_ERM, tmp_value);
	
	/*
	 * Unset Apic NM_TIMER request
	 */

	tmp_value = APIC_NM_TIMER;
	apic_write(APIC_NM, tmp_value);

	apic_write(APIC_NM_TIMER_INIT_COUNT, 0);
	
	tmp_value = 0;
	apic_write(APIC_NM_TIMER_LVTT, tmp_value);
	
	raw_local_irq_restore(flags);
	dbgwd("wd: exit stop_apic_watchdog()\n");
}

static int stop_apic_watchdogs(void)
{
	dbgwd("wd: stop_apic_watchdogs()\n");
	on_each_cpu(stop_apic_watchdog, 0, 1);
	return 0;
}

static void ping_apic_watchdog(void *unused)
{
	dbgwd("wd: enter ping_apic_watchdog()\n");
	apic_write(APIC_NM_TIMER_INIT_COUNT, wd_init_value);
	apic_write(APIC_NM, APIC_NM_TIMER);
	dbgwd("wd: exit ping_apic_watchdog()\n");
}

static void ping_apic_watchdogs(void)
{
	dbgwd("wd: ping_apic_watchdogs()\n");
	on_each_cpu(ping_apic_watchdog, 0, 1);
}

#endif	/* __e2k__ */

/*
 * IOHUB
 */

static int start_i2c_watchdogs(void)
{
	dbgwd("wd: start_i2c_watchdogs()\n");

	if (lt_regs == NULL) {
		dbgwd("wd: start_i2c_watchdogs() Elbrus timer registers base "
			"address is not mapped to virtual space\n");
		return (-ENODEV);
	}

	writel(0, &lt_regs->wd_prescaler);
	writel(WD_SET_COUNTER_VAL(heartbeat), &lt_regs->wd_limit);
	writel(WD_EVENT, &lt_regs->wd_control);
	writel(WD_ENABLE, &lt_regs->wd_control);

	return 0;
}

static int stop_i2c_watchdogs(void)
{
	dbgwd("wd: stop_i2c_watchdogs()\n");

	if (lt_regs == NULL) {
		dbgwd("wd: stop_i2c_watchdogs() Elbrus timer registers base "
			"address is not mapped to virtual space\n");
		return (-ENODEV);
	}

	writel(WD_EVENT, &lt_regs->wd_control);
	writel(WD_SET_COUNTER_VAL(0), &lt_regs->wd_limit);

	return 0;
}

static void ping_i2c_watchdogs(void)
{
	writel(0, &lt_regs->wd_counter);
}

/*
 * DRIVER
 */

static struct watchdog_info ident = {
	.options = WDIOF_SETTIMEOUT |
		   WDIOF_KEEPALIVEPING |
		   WDIOF_MAGICCLOSE,
	.identity = "Elbrus Watchdog Timer",
};

static long lwdt_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int __user *p = argp;
	int ret = -ENOTTY;

	dbgwd("wd: enter wd_ioctl()\n");

	switch (cmd) {
	case WDIOC_GETSUPPORT:
		ret = 0;
		if (copy_to_user(argp, &ident, sizeof(ident)))
			ret = -EFAULT;
		break;

	case WDIOC_GETSTATUS:
	case WDIOC_GETBOOTSTATUS:
		ret = put_user(0, p);
		break;

	case WDIOC_KEEPALIVE:
		lwdt_opts->lwdt_ping();
		ret = 0;
		break;

	case WDIOC_SETTIMEOUT:
		ret = get_user(heartbeat, p);
		if (ret)
			break;
		lwdt_opts->lwdt_stop();
		lwdt_opts->lwdt_start();
		/* Fall */

	case WDIOC_GETTIMEOUT:
		ret = put_user(heartbeat, p);
		break;
	}

	return ret;
}

static ssize_t lwdt_write(struct file *file, const char __user *buf,
						size_t count, loff_t *ppos)
{
	dbgwd("wd: lwdt_write()\n");

	if (count) {
		if (!nowayout) {
			size_t i;

			expect_close = 0;

			for (i = 0; i != count; i++) {
				char c;

				if (get_user(c, buf + i))
					return -EFAULT;
				if (c == 'V')
					expect_close = 42;
			}
		}
		lwdt_opts->lwdt_ping();
	}
	return count;
}

static int lwdt_open(struct inode *inode, struct file *file)
{
	dbgwd("wd: lwdt_open()\n");
	if (test_and_set_bit(0, &lwdt_is_open))
		return -EBUSY;
	lwdt_opts->lwdt_start();
	return nonseekable_open(inode, file);
}

static int lwdt_release(struct inode *inode, struct file *file)
{
	dbgwd("wd: lwdt_release()\n");
	if (expect_close == 42) {
		lwdt_opts->lwdt_stop();
	} else {
		printk(KERN_CRIT
			"wd: unexpected close, not stopping watchdog\n");
		lwdt_opts->lwdt_ping();
	}
	expect_close = 0;
	clear_bit(0, &lwdt_is_open);
	return 0;
}
	
const struct file_operations lwdt_fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.write		= lwdt_write,
	.unlocked_ioctl	= lwdt_ioctl,
	.open		= lwdt_open,
	.release	= lwdt_release,
};

static struct miscdevice lwdt_miscdev = {
	.minor		= WATCHDOG_MINOR,
	.name		= "watchdog",
	.fops		= &lwdt_fops,
};

static int __init lwdt_init(void)
{
	int rval = 0;

	printk("wd: ");

	lwdt_opts = kmalloc(sizeof(lwdt_opts_t), GFP_KERNEL);
	if (!lwdt_opts) {
		printk("couldn't allocate memory\n");
		return -ENOMEM;
	}

#ifdef	__e2k__
	if (HAS_MACHINE_E2K_IOHUB) {
#endif	/* __e2k__ */
		lwdt_opts->lwdt_start = start_i2c_watchdogs;
		lwdt_opts->lwdt_stop = stop_i2c_watchdogs;
		lwdt_opts->lwdt_ping = ping_i2c_watchdogs;
		printk("set I2C-SPI watchdog timer\n");
#ifdef	__e2k__
	} else {
		lwdt_opts->lwdt_start = start_apic_watchdogs;
		lwdt_opts->lwdt_stop = stop_apic_watchdogs;
		lwdt_opts->lwdt_ping = ping_apic_watchdogs;
		printk("set APIC NM-timer\n");
	}
#endif	/* __e2k__ */

	rval = misc_register(&lwdt_miscdev);
	if (rval) {
		printk("wd: cannot register miscdev on "
			"minor=%d (err=%d)\n",
			WATCHDOG_MINOR, rval);
		kfree(lwdt_opts);
	}

	return rval;
}

static void __exit lwdt_exit(void)
{
	dbgwd("wd: enter lwdt_exit()\n");
	kfree(lwdt_opts);
	misc_deregister(&lwdt_miscdev);
	dbgwd("wd: exit lwdt_exit()\n");
}

module_init(lwdt_init);
module_exit(lwdt_exit);

MODULE_AUTHOR("Pavel V. Panteleev");
MODULE_DESCRIPTION("Elbrus watchdog driver");
MODULE_ALIAS_MISCDEV(WATCHDOG_MINOR);
MODULE_LICENSE("GPL");
