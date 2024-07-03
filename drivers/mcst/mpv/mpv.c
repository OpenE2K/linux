/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/of.h>
#if defined(CONFIG_PCI2SBUS) || defined(CONFIG_PCI2SBUS_MODULE) || \
		defined(CONFIG_SBUS)
#include <linux/of_platform.h>
#if defined(CONFIG_PCI2SBUS) || defined(CONFIG_PCI2SBUS_MODULE)
#include <linux/mcst/p2ssbus.h>
#endif
#ifdef CONFIG_SBUS
#include <asm/sbus.h>
#endif
#endif
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/mod_devicetable.h>
#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/interrupt.h>
#include <linux/timex.h>
#include <linux/el_posix.h>
#include <linux/pps_kernel.h>
#include <linux/sched/signal.h>
#include <linux/sched/clock.h>
#include <asm/uaccess.h>

#include "mpv.h"

#ifdef CONFIG_MCST_SELF_TEST
#include <linux/mcst/mcst_selftest.h>
#endif

int mpv_debug_more = 0;

#define DBGMPVDETAIL_MODE
#undef DBGMPVDETAIL_MODE

#ifdef CONFIG_MCST
/* /proc/sys/debug/pps_debug mask: 1 wait int; 8 pps; 4 rw&pps morie */
#define dbgmpv(x...)		do { if (pps_debug) printk(x); } while (0)
#define dbgmpv_rw(x...)		do { if (pps_debug & 2) printk(x); } while (0)
#define dbgmpv_pps(x...)	do { if (pps_debug & 4) printk(x); } while (0)
#endif

#if defined(DBGMPVDETAIL_MODE)
#define dbgmpvdetail(x...)	do { printk(x); } while (0)
#else
#define dbgmpvdetail(x...)	do {if (mpv_debug_more)  printk(x); } while (0)
#endif

#define chekpoint_mpv	pr_err("%s:%s():%d\n", __FILE__, __func__, __LINE__);

#define PCI_COMPLEMENT		0x40	/* 8 bits */
#define PSEC_PER_USEC	1000000
#define PSEC_PER_SEC	1000000000000LL

#define SBUS_DEV 	1
#define PCI_DEV  	2

static int pirq = 0;
module_param(pirq , int , 0);
MODULE_PARM_DESC(pirq, "Used for set PIRQ=0,1,2,3 (A, B, C, D). Default =0");

static int mpv_status[MAX_MPV_INSTANCES] = {[0 ... MAX_MPV_INSTANCES - 1] = 2};
module_param_array(mpv_status, int, NULL, 0444);
MODULE_PARM_DESC(mpv_status, " Array: 0 - disable, 1 - enable, other - use devtree");

atomic_t mpv_instances = ATOMIC_INIT(0);

static struct pci_dev *cur_pdev;
static int major_base = 0; /* first =0, furher - dynamically received from OS */
static int minor_base = 0; /* 0-192, on one major - 4 instance */
static int minor_max;      /* for print info on the module */

static mpv_state_t	*mpv_states[MAX_MPV_INSTANCES];

/*
 * get_mpv_instance : for couple 'major & minor'
 *	return - instance, and
 *	calculates number bus.
 */
static int get_mpv_instance(int major, int minor, int *bus) {
	int	minor_base = minor & ~63;
	int	instance = 0;
	mpv_state_t	*mpv_st;

	for (instance = 0; instance < atomic_read(&mpv_instances); instance++) {
		mpv_st = mpv_states[instance];
		if (mpv_st->major == major &&
					mpv_st->minor_base == minor_base) {
			*bus = MPV_IN(minor) ?  minor & 0x1f : minor & 0xf;
			if (mpv_st->inst != instance)
				printk("%s !!! mpv_st->inst =%d, "
					"instance =%d d_path !!!\n",
					__func__, mpv_st->inst, instance);
			break;
		}
	}
	return instance;
} /* END ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ get_mpv_instance */

static struct class *mpv_class = NULL;
static int rev_module_param = -1;

#if defined(CONFIG_MPV_MODULE) && \
	(defined(CONFIG_PCI2SBUS) || defined(CONFIG_PCI2SBUS_MODULE) || \
		defined(CONFIG_SBUS))
static int mpv_sbus_probe(struct of_device *op,
			const struct of_device_id *match);
static int mpv_sbus_remove(struct of_device *op);
#endif
#ifdef CONFIG_PCI
static int mpv_pci_probe(struct pci_dev *pdev,
			const struct pci_device_id *pci_ent);
static void mpv_pci_remove(struct pci_dev *pci_dev);
#endif

static	int	mpv_open(struct inode *inode, struct file *file);
static  ssize_t mpv_read (struct file *file, char *buf, size_t sz, loff_t *f_pos);
static  ssize_t mpv_write (struct file *file, const char *buf, size_t sz, loff_t *f_pos);
static	int	mpv_close(struct inode *inode, struct file *file);
static	long	mpv_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
static	long	mpv_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
#endif
static  unsigned int  mpv_chpoll(struct file *file, struct poll_table_struct *wait);

static int mpv_check_initial_value_reg(mpv_state_t *mpv_st);
static irqreturn_t mpv_intr_handler(int irq, void *arg);
static irqreturn_t mpv_threaded_handler(int irq, void *arg);
static void mpv_reset_module(mpv_state_t *mpv_st);
static void mpv_shutdown(struct pci_dev *dev);
static int mpv_send_pps(u32 bus, int enable);
static int mpv_get_freq(u32 bus);

/* number of msecs for psecs_per_corr_clck calculating
 * Should be less then 131 ms for 32 MHz MPV and 20-bit MPV_REG_CHECK */
#define	measure_sleep_time_ms	100
int	stv_num_msrms = 0;

static struct file_operations mpv_fops = {
	owner:		THIS_MODULE,
	open:		mpv_open,
	read:		mpv_read,
	write:		mpv_write,
	release:	mpv_close,
	poll:		mpv_chpoll,
	unlocked_ioctl:	mpv_ioctl,
#ifdef CONFIG_COMPAT
	compat_ioctl:	mpv_compat_ioctl,
#endif
};

#if defined(CONFIG_SBUS) || defined(CONFIG_P2S_TWISTING)
static inline void
mpv_write_regl(mpv_state_t *mpv_st, int addr_reg, int v)
{
	if (mpv_st->dev_type == SBUS_DEV) {
		sbus_writel(v, mpv_st->regs_base + addr_reg);
		return;
	}
	writel(v, mpv_st->regs_base + addr_reg);
}
static inline int
mpv_read_regl(mpv_state_t *mpv_st, int addr_reg)
{
	if (mpv_st->dev_type == SBUS_DEV) {
		return sbus_readl(mpv_st->regs_base + addr_reg);
	}
	return readl(mpv_st->regs_base + addr_reg);
}
#else
#define mpv_write_regl(mpv_st, a, v)	writel(v, mpv_st->regs_base + a)
#define mpv_read_regl(mpv_st, a)	readl(mpv_st->regs_base + a)
#endif

long	dbg_avg_getcor = 0;
int	dbg_max_atpt_getcor = 0;
int	dbg_sum_atpt = 0;
int	dbg_num_get_cc = 0;
int	dbg_num_intr = 0;
int	do_log_stv1 = 0;
extern	int	do_log_stv;

#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>

static ctl_table mpv_table[] = {
#ifdef CONFIG_MCST
	{
		.procname	= "pps_debug",
		.data		= &pps_debug,
		.maxlen		= sizeof(pps_debug),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
#endif
	{
		.procname	= "mpv_debug_more",
		.data		= &mpv_debug_more, 
		.maxlen		= sizeof(mpv_debug_more),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{ }
};
static ctl_table mpv_root_table[] = {
	{
		.procname	= "debug",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= mpv_table,
	},
	{ }
};

static struct ctl_table_header *mpv_sysctl_header;

static void mpv_sysctl_register(void)
{
	mpv_sysctl_header = register_sysctl_table(mpv_root_table);
}

static void mpv_sysctl_unregister(void)
{
	if ( mpv_sysctl_header )
		unregister_sysctl_table(mpv_sysctl_header);
}

#else /* CONFIG_SYSCTL */

static void mpv_sysctl_register(void)
{
}

static void mpv_sysctl_unregister(void)
{
}
#endif

static long long get_usec_tod(void) {
	struct timespec64 ts;
	long long retval;

	ktime_get_real_ts64(&ts);
	retval = (long long)ts.tv_sec * USEC_PER_SEC
		+ (long long)ts.tv_nsec / NSEC_PER_USEC;
	return retval;
}

#if defined(CONFIG_MPV_MODULE) && \
	(defined(CONFIG_PCI2SBUS) || defined(CONFIG_PCI2SBUS_MODULE) || \
		defined(CONFIG_SBUS))
static const struct of_device_id mpv_sbus_match[] = {
	{
		.name           = MPV_NAME,
	},
	{},
};

MODULE_DEVICE_TABLE(of, mpv_sbus_match);

static struct of_platform_driver mpv_sbus_driver = {
	.name           = MPV_NAME,
	.match_table    = mpv_sbus_match,
	.probe          = mpv_sbus_probe,
	.remove         = mpv_sbus_remove,
};
#endif

#ifdef CONFIG_PCI
static struct pci_device_id mpv_pci_tbl[] = {
	{ 0x5453, MPV_CARD_DEVID, PCI_ANY_ID, PCI_ANY_ID, },
	{ 0x1fff, MPV_KPI2_DEVID, PCI_ANY_ID, },
	{ 0x1fff, MPV_EIOH_DEVID, PCI_ANY_ID, },
	{ 0x1fff, MPV4_DEVID, PCI_ANY_ID, },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, mpv_pci_tbl);

static struct pci_driver mpv_pci_driver = {
	.name =     MPV_NAME,
	.probe =    mpv_pci_probe,
	.remove =   mpv_pci_remove,
	.shutdown = mpv_shutdown,
	.id_table = mpv_pci_tbl,
};
#endif

static int
mpv_init(void)
{
	int res = 0;

	mpv_sysctl_register();
	dbgmpv("********* MPV_INIT: START for %s *********\n", MPV_NAME);
	atomic_set(&mpv_instances, 0);
	mpv_class = class_create(THIS_MODULE, "mpv");
	if (!mpv_class || IS_ERR(mpv_class)) {
		pr_err("Error creating class: /sys/class/mpv mpv_class=%p\n",
			mpv_class);
	}
#if defined(CONFIG_MPV_MODULE) && \
	(defined(CONFIG_PCI2SBUS) || defined(CONFIG_PCI2SBUS_MODULE) || \
		defined(CONFIG_SBUS))
	if (of_platform_bus_type.p) {
		int	res_sbus;
		res_sbus = of_register_driver(&mpv_sbus_driver,
			&of_platform_bus_type);
		if (res_sbus) {
			pr_info("MPV SBUS register error=%d\n", res_sbus);
			res = res_sbus;
		}
	}
#endif
#ifdef CONFIG_PCI
	{
		int	res_pci = pci_register_driver(&mpv_pci_driver);
		if (!res_pci) {
			res = 0; /* pci is main */
		} else {
			pr_info("MPV PCI register error=%d\n", res_pci);
			res = res_pci;
		}
	}
#endif
	return res;
}

/********************************************************************************************/
static void
mpv_exit(void)
{
	dbgmpv("********* MPV_EXIT: START *********\n");

#ifdef CONFIG_PCI
	pci_unregister_driver(&mpv_pci_driver);
#endif
#if defined(CONFIG_MPV_MODULE) && \
	(defined(CONFIG_PCI2SBUS) || defined(CONFIG_PCI2SBUS_MODULE) || \
		defined(CONFIG_SBUS))
	if (of_platform_bus_type.p)
		of_unregister_driver(&mpv_sbus_driver);
#endif
	if (!mpv_class || IS_ERR(mpv_class)) {
		pr_err("Error mpv_class=%p\n", mpv_class);
	}
	if (mpv_class && !IS_ERR(mpv_class))
		class_destroy(mpv_class);
	dbgmpv("********* MPV_EXIT: FINISH *********\n");

	mpv_sysctl_unregister();
}

static int
mpv_common_probe(struct device *dev, mpv_state_t **mpv_stp, void *r_base,
		int mpv_new, int revision_id, int dev_type)
{
	mpv_state_t	*mpv_st;
	int		i;
	int		instance;
	int		rval;
	int		major;
	int		minor = 0;
	unsigned int	mpv_time_cnt0, mpv_time_cnt;
	struct device	*device;
	s64 start_tm1, start_tm2, fin_tm1, fin_tm2, measure_time_ns;

	instance = atomic_inc_return(&mpv_instances) - 1;
	if (instance >= MAX_MPV_INSTANCES) {
		pr_err("MPV: number of instances > MAX_MPV_INSTANCES=%d\n",
			MAX_MPV_INSTANCES);
		return 1;
	}
	if (mpv_status[instance] == 1) {
		dev_info(dev, "device %d enabled in cmdline\n", instance);
	} else if (mpv_status[instance] == 0) {
		dev_info(dev, "device %d disabled in cmdline\n", instance);
		return -ECANCELED;
	} else if (dev->of_node && !of_device_is_available(dev->of_node)) {
		dev_info(dev, "device %d disabled in device tree\n", instance);
		return -ECANCELED;
	}
	mpv_st = kmalloc(sizeof(mpv_state_t), GFP_KERNEL);
	if ( mpv_st == NULL )
		return 1;
	memset(mpv_st, 0, sizeof(mpv_state_t));
	*mpv_stp = mpv_st;
	init_waitqueue_head(&(mpv_st->pollhead));
	mpv_st->inst	= instance;
	mpv_st->stv_in_number= -1;
	mpv_st->pps4mgb_nunber = -1;
	mpv_st->major	= -1;
	mpv_st->open_in	= 0;
	mpv_st->open_out	= 0;
	mpv_st->open_st	= 0;
	mpv_st->open_in_excl	= 0;
	mpv_st->open_out_excl	= 0;
	mpv_st->open_st_excl	= 0;
	mpv_st->intr_assemble = 0;
	mpv_st->mpv_new = mpv_new;
	mpv_st->revision_id = revision_id;
	mpv_st->dev_type = dev_type;
	mpv_st->current_st = 0;
	mpv_st->current_out = 0;
	mpv_st->regs_base = r_base;
	if (mpv_new == MPV_KPI2 || mpv_new == MPV_EIOH) {
		mpv_st->num_time_regs = num_time_regs_ioh2[revision_id];
		mpv_st->gen_mode_reg = gen_mode_reg_ioh2[revision_id];
		mpv_st->num_in_bus = num_inputs_ioh2[revision_id];
	} else if (mpv_new == MPV_4) {
		mpv_st->num_time_regs = 4;
		mpv_st->gen_mode_reg = gen_mode_reg_ioh2[revision_id];
		mpv_st->num_in_bus = 4;
	} else {
		mpv_st->num_time_regs = num_time_regs_v2[revision_id];
		mpv_st->gen_mode_reg = gen_mode_reg_v2[revision_id];
		mpv_st->num_in_bus = num_inputs_v2[revision_id];
	}
	for (i = 0; i < mpv_st->num_in_bus; i++) {
		if (i < mpv_st->num_time_regs) {
			if (mpv_new) {
				mpv_st->corr_cnt_reg[i] =
						corr_cnt_reg_new[i];
				mpv_st->gen_period_reg[i] =
						gen_period_reg_new[i];
				mpv_st->intpts_cnt_reg[i] =
						intpts_cnt_reg_new[i];
				mpv_st->prev_time_reg[i] =
						prev_time_reg_new[i];
				mpv_st->mpv_time_reg[i] =
						mpv_time_reg_new[i];
			} else {
				mpv_st->corr_cnt_reg[i] =
						corr_cnt_reg_v2[i];
				mpv_st->gen_period_reg[i] =
						gen_period_reg_v2[i];
				mpv_st->intpts_cnt_reg[i] =
						intpts_cnt_reg_v2[i];
				mpv_st->prev_time_reg[i] =
						prev_time_reg_v2[i];
			}
		}
		mpv_st->kdata_intr[i].num_reciv_intr = 0;
		mpv_st->kdata_intr[i].correct_counter_nsec = 0;
		mpv_st->kdata_intr[i].irq_enter_clks = 0;
		mpv_st->kdata_intr[i].intr_appear_nsec = 0;
		mpv_st->kdata_intr[i].intr_appear_nsec_mono = 0;
		mpv_st->kdata_intr[i].prev_time_clk = 0;
		mpv_st->kdata_intr[i].intpts_cnt = 0;
		mpv_st->kdata_intr[i].interv_gen_ns = 0;
		mpv_st->kdata_intr[i].period_ns = 0;
		mpv_st->kdata_intr[i].wait_on_cpu = 0;
		mpv_st->kdata_intr[i].timeout_jif =
					MAX_SCHEDULE_TIMEOUT;
		mpv_st->kdata_intr[i].time_prev_intrpt = 0;
		mpv_st->open_in_count[i] = 0;
		INIT_LIST_HEAD(&mpv_st->kdata_intr[i].wait1_task_list);
	}
	if (!mpv_new && revision_id == 0) {
		for (i = 0; i < 4; i++)
			mpv_st->corr_cnt_reg[i] = corr_cnt_reg_v0[i];
	}
	if (mpv_st->mpv_new == MPV_KPI2 || mpv_st->mpv_new == MPV_EIOH) {
		mpv_st->base_polar = 0x7;
	} else if (mpv_st->mpv_new == MPV_4) {
		mpv_st->base_polar = 0xf;
	} else
		mpv_st->base_polar = MPV_IN_MASK;
	mpv_reset_module(mpv_st);
	mpv_st->listen_alive = 0;

	rval = mpv_check_initial_value_reg(mpv_st);
	if (major_base)
		major = major_base;
	else
/*
		major = __register_chrdev(major_base, 0, 512,
				MPV_NAME, &mpv_fops);
*/
		major = register_chrdev(major_base, MPV_NAME, &mpv_fops);

	if (major < 0) {
		pr_err("MPV-%d, %s: major=%d <0\n",
			instance, pci_name(cur_pdev), major);
		return 1;
	}
	if (!major_base) {
		dbgmpv("%d %s ->register_chrdev :"
			"received major for 'MPV' =%d\n",
			instance, __func__, major);
		major_base = major;
	}
	else
		dbgmpv("%d %s :major =%d, minor =%d\n",
			instance, __func__, major, minor_base);
	mpv_st->major = major;
	mpv_st->minor_base = minor_base;
	minor_base += 64;
	if (minor_base >= 256) {
		major_base = 0;
		minor_base = 0;
	}
	raw_spin_lock_init(&mpv_st->mpv_lock);
	INIT_LIST_HEAD(&mpv_st->any_in_task_list);

	dbgmpv("%s inst. %d polar= %x\n", __func__, instance, mpv_st->polar);
	if (mpv_new) {
		start_tm1 = sched_clock();
		mpv_time_cnt0 = mpv_read_regl(mpv_st, MPV_REG_BASE_CNT);
		start_tm2 = sched_clock();
		schedule_timeout_interruptible(msecs_to_jiffies(measure_sleep_time_ms));
		fin_tm1 = sched_clock();
		mpv_time_cnt = mpv_read_regl(mpv_st, MPV_REG_BASE_CNT) -
			mpv_time_cnt0;
		fin_tm2 = sched_clock();
	} else {
		mpv_write_regl(mpv_st, MPV_REG_CHECK, 0);
		mpv_read_regl(mpv_st, MPV_REG_CHECK);
		start_tm1 = sched_clock();
		mpv_write_regl(mpv_st, MPV_REG_CHECK, 0);
		start_tm2 = sched_clock();
		schedule_timeout_interruptible(msecs_to_jiffies(measure_sleep_time_ms));
		fin_tm1 = sched_clock();
		mpv_time_cnt = mpv_read_regl(mpv_st, MPV_REG_CHECK);
		fin_tm2 = sched_clock();
	}
	measure_time_ns = (fin_tm1 + fin_tm2 - start_tm2 - start_tm1) >> 1;
	/* Picoseconds per corr.clock is culculated */
	if (mpv_time_cnt != 0) {
#if BITS_PER_LONG == 64
		mpv_st->psecs_per_corr_clck =
			measure_time_ns * 1000 / mpv_time_cnt;
#else
		{unsigned long long long_res =
			(unsigned long long)measure_time_ns * 1000LL;
			do_div(long_res, mpv_time_cnt);
			mpv_st->psecs_per_corr_clck = long_res;
		}
#endif
	} else {
		/* FIXME 40000 ? */
		pr_err("mpv_time_cnt == 0\n");
		mpv_st->psecs_per_corr_clck = mpv_new ? 40000 : 120000;
	}
	pr_warn("%d-MPV mpv_time_cnt = %u measure_time_ns=%lld register_reading_ns=%lld\n",
		instance, mpv_time_cnt, measure_time_ns,
		(start_tm2 - start_tm1 + fin_tm2 - fin_tm1) >> 1);
	mpv_states[instance] = mpv_st;
	for (i = 0; i < mpv_st->num_in_bus; i++) {
		minor = MPV_MINOR(mpv_st->minor_base, MPV_IO_IN, i);
		device = device_create(mpv_class, NULL,
				MKDEV(major, minor),
				NULL, "mpv_%d_in:%d", instance, i);
		if (device == NULL || IS_ERR(device))
			pr_err("inst. %d %s device_create :"
				"not create device 'IN' N %d, MINOR =0X%X.\n",
				instance, __func__, i, minor);
	};
	if (!mpv_new) {
		for (i = 0; i < MPV_NUM_OUT_INTR; i++) {
			minor = MPV_MINOR(mpv_st->minor_base, MPV_IO_OUT, i);
			device = device_create(mpv_class, NULL,
					MKDEV(major, minor),
					NULL, "mpv_%d_out:%d", instance, i);
			if (device == NULL || IS_ERR(device))
				pr_err("inst. %d %s device_create :not create"
					"device 'OUT' N %d, MINOR =0X%X.\n",
					instance, __func__, i, minor);
		};
		for (i = 0; i < MPV_NUM_OUT_STAT; i++) {
			minor = MPV_MINOR(mpv_st->minor_base, MPV_IO_OS, i);
			device = device_create(mpv_class, NULL,
					MKDEV(major, minor),
					NULL, "mpv_%d_st:%d", instance, i);
			if (device == NULL || IS_ERR(device))
				pr_err("inst. %d %s device_create :not create"
					"device 'ST' N %d, MINOR =0X%X.\n",
					instance, __func__, i, minor);
		};
	}
	minor_max = minor;
	if (!send_pps_mpv)
		send_pps_mpv = &mpv_send_pps;
	mpv_get_freq_ptr = &mpv_get_freq;


	return 0;
}

static void
mpv_common_remove(mpv_state_t *mpv_st)
{
	int		major = mpv_st->major;
	int		minor;
	int		i;

	unregister_chrdev(major, MPV_NAME);
	for (i = 0; i < mpv_st->num_in_bus; i++) {
		minor = MPV_MINOR(mpv_st->minor_base, MPV_IO_IN, i);
		device_destroy(mpv_class, MKDEV(mpv_st->major, minor));
	};
	if (mpv_st->mpv_new == MPV_KPI2 || mpv_st->mpv_new == MPV_EIOH) {
		mpv_write_regl(mpv_st, mpv_st->gen_mode_reg, 0xc0);
	} else if (mpv_st->mpv_new == MPV_4) {
		mpv_write_regl(mpv_st, mpv_st->gen_mode_reg, 0);
	} else {
		if (mpv_st->mpv_new || mpv_st->revision_id >= 2)
			mpv_write_regl(mpv_st, mpv_st->gen_mode_reg, 0);
		for (i = 0; i < MPV_NUM_OUT_INTR; i++) {
			minor = MPV_MINOR(mpv_st->minor_base, MPV_IO_OUT, i);
			device_destroy(mpv_class, MKDEV(mpv_st->major, minor));
		};
		for (i = 0; i < MPV_NUM_OUT_STAT; i++) {
			minor = MPV_MINOR(mpv_st->minor_base, MPV_IO_OS, i);
			device_destroy(mpv_class, MKDEV(mpv_st->major, minor));
		};
	};
	kfree(mpv_st);
}

#ifdef CONFIG_PCI
static void
_mpv_pci_remove(struct pci_dev *pci_dev, mpv_state_t *mpv_st)
{
	int		bar = 0;

	if (mpv_st == NULL)
		return;
	mpv_common_remove(mpv_st);
	iounmap(mpv_st->regs_base);
	if (mpv_st->mpv_new == MPV_KPI2 || mpv_st->mpv_new == MPV_EIOH) {
		bar = 1;
	}
	pci_release_region(pci_dev, bar);
	pci_set_drvdata(pci_dev, NULL);
	dbgmpv("inst. %d %s: finished.\n", mpv_st->inst, __func__);
}

static int
mpv_pci_probe(struct pci_dev *pdev, const struct pci_device_id *pci_ent)
{
	mpv_state_t	*mpv_st = NULL;
	u8		mpv_new = 0;
	u8		revision_id;
	u16		vendor_id, device_id;
	void		*regs_base;
	u8		compl_reg;
	int		rval;
	int		bar = 0;
	int		dev_id = MPV_CARD_DEVID;

	rval = pci_enable_device(pdev);
	if (rval) {
		pr_err("%s: cannot enable pci device\n",
				pdev->bus->name);
		return rval;
	}
	pci_set_master(pdev);
	pci_read_config_byte(pdev, PCI_REVISION_ID, &revision_id);
	if (revision_id == 0xff) {
		dbgmpv("revision_id was 0xff. set revision_id=1\n");
		revision_id = 1;
	}
	pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor_id);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device_id);
	if (vendor_id == 0x1fff) {
		if (device_id == MPV4_DEVID) {
			mpv_new = MPV_4;
			revision_id = 0;
		}
		if (device_id == MPV_KPI2_DEVID ||
				device_id == MPV_EIOH_DEVID) {
			pci_write_config_byte(pdev, GPIO_MPV_SW, 1);
			bar = 1;
			if (device_id == MPV_KPI2_DEVID)
				mpv_new = MPV_KPI2;
			else
				mpv_new = MPV_EIOH;
		}
	}
	dbgmpv("MPV DEV_ID=0x%x vendor_id=0x%x bar=%d\n",
		dev_id, vendor_id, bar);
	rval = pci_request_region(pdev, bar, MPV_NAME);
	if (rval) {
		pr_err("can't alloc PCI BAR %d for mpv\n", bar);
		return rval;
	}
	regs_base = pci_iomap(pdev, bar, 0);
	dbgmpv("%s %s revision_id=%d bar=%d, regs_base=%p\n",
			__func__, mpv_new ? "MPViohub2" : "MPV",
			revision_id, bar, regs_base);
	if (regs_base == NULL) {
		pr_err("%s(): Unable to map registers\n", __func__);
		return -EFAULT;
	}
	cur_pdev = pdev;
	rval = mpv_common_probe(&pdev->dev, &mpv_st, regs_base, mpv_new, revision_id,
								PCI_DEV);
	if (rval) {
		if (rval == -ECANCELED) { /*device is disabled*/
			pci_iounmap(pdev, regs_base);
			rval = 0;
		}
		goto err_unmap;
	}
#define PCI_HW_REV_ID	0x44
	pci_read_config_byte(pdev, PCI_HW_REV_ID, &(mpv_st->hw_rev_id));
	mpv_st->pdev = pdev;
	pci_set_drvdata(pdev, (void *)mpv_st);
	mpv_st->irq_orig = pdev->irq;
	mpv_st->irq = pdev->irq;
	if (pirq) {
		pci_read_config_byte(pdev, PCI_COMPLEMENT, &compl_reg);
		pci_write_config_byte(pdev, PCI_COMPLEMENT, compl_reg | 1);
		pci_write_config_byte(pdev, PCI_INTERRUPT_PIN, pirq);
		pci_write_config_byte(pdev, PCI_COMPLEMENT, compl_reg & ~1);
		mpv_st->irq = ((mpv_st->irq_orig - 16) + pirq - 1) % 4 + 16;
	}
	if (mpv_new == MPV_KPI2) {
		rval = request_threaded_irq(mpv_st->irq, &mpv_intr_handler,
			&mpv_threaded_handler,
			IRQF_SHARED | IRQF_NO_THREAD, MPV_NAME, (void *)mpv_st);
		if (rval) {
			pr_err("MPV-%d: Can't get irq %d, err [%d]\n",
				mpv_st->inst, mpv_st->irq, rval);
			goto err_unmap;
		}
		rval = request_threaded_irq(mpv_st->irq + 3, &mpv_intr_handler,
			&mpv_threaded_handler,
			IRQF_SHARED | IRQF_NO_THREAD, MPV_NAME, (void *)mpv_st);
		if (rval) {
			pr_err("MPV-%d: Can't get irq %d, err [%d]\n",
				mpv_st->inst, mpv_st->irq + 3, rval);
			goto err_unmap;
		}
	} else if (mpv_new == MPV_EIOH) {
		rval = request_threaded_irq(mpv_st->irq, &mpv_intr_handler,
			&mpv_threaded_handler,
			IRQF_SHARED | IRQF_NO_THREAD, MPV_NAME, (void *)mpv_st);
		if (rval) {
			pr_err("MPV-%d: Can't get 1-st irq %d, err [%d]\n",
				mpv_st->inst, mpv_st->irq, rval);
			goto err_unmap;
		}
		rval = request_threaded_irq(mpv_st->irq + 1, &mpv_intr_handler,
			&mpv_threaded_handler,
			IRQF_SHARED | IRQF_NO_THREAD, MPV_NAME, (void *)mpv_st);
		if (rval) {
			pr_err("MPV-%d: Can't get 2-nd irq %d, err [%d]\n",
				mpv_st->inst, mpv_st->irq, rval);
			goto err_unmap;
		}
		rval = request_threaded_irq(mpv_st->irq + 2, &mpv_intr_handler,
			&mpv_threaded_handler,
			IRQF_SHARED | IRQF_NO_THREAD, MPV_NAME, (void *)mpv_st);
		if (rval) {
			pr_err("MPV-%d: Can't get 3-rd irq %d, err [%d]\n",
				mpv_st->inst, mpv_st->irq, rval);
			goto err_unmap;
		}
	} else {
		rval = request_threaded_irq(mpv_st->irq, &mpv_intr_handler,
			&mpv_threaded_handler,
			IRQF_SHARED | IRQF_NO_THREAD, MPV_NAME, (void *)mpv_st);
		if (rval) {
			pr_err("MPV-%d: Can't get irq %d, err [%d]\n",
				mpv_st->inst, mpv_st->irq, rval);
			goto err_unmap;
		}
	}
#ifdef CONFIG_MCST
	mk_hndl_first(mpv_st->irq, MPV_NAME);
#endif
	if (mpv_st->mpv_new == MPV_KPI2) {
		printk("%d-MPV KPI-2 DEV=0x%x VEND=0x%x REV=0x%x "
			"drv.ver.%d IRQ 0=%d IRQ 1,2=%d, BUS =%s, "
			"picoseconds per counter clock = %d\n",
			mpv_st->inst,
			MPV_KPI2_DEVID, vendor_id, mpv_st->revision_id,
			MPV_DRV_VER, mpv_st->irq, mpv_st->irq + 3,
			pci_name(pdev), mpv_st->psecs_per_corr_clck);
	} else
		if (mpv_st->mpv_new == MPV_EIOH) {
			printk("%d-MPV EIOH DEV=0x%x VEND=0x%x REV=0x%x "
				"drv.ver.%d IRQ 0=%d IRQ 1=%d IRQ 2=%d, "
				"BUS =%s, picoseconds per counter clock = %d\n",
				mpv_st->inst,
				MPV_KPI2_DEVID, vendor_id, mpv_st->revision_id,
				MPV_DRV_VER, mpv_st->irq, mpv_st->irq + 1,
								mpv_st->irq + 2,
				pci_name(pdev), mpv_st->psecs_per_corr_clck);
	} else {
		if (mpv_st->mpv_new == MPV_4)
			dev_id = MPV4_DEVID;
		printk("%d-MPV DEV=0x%x VEND=0x%x REV=0x%x HWREV=0x%x. "
			"drv.ver.%d IRQ=%d (pirq=%d), BUS =%s, "
			"picoseconds per counter clock = %d\n",
			mpv_st->inst, dev_id, vendor_id, mpv_st->revision_id,
			mpv_st->hw_rev_id, MPV_DRV_VER, mpv_st->irq, pirq,
			pci_name(pdev), mpv_st->psecs_per_corr_clck);
	}
	dbgmpv("MPV inst. =%d :MAJOR =%d, MINOR =%03d-%03d\n",
		mpv_st->inst, mpv_st->major, mpv_st->minor_base, minor_max);
	return 0;
err_unmap:
	pci_disable_device(pdev);
	_mpv_pci_remove(pdev, mpv_st);
	return rval;
}
static void
mpv_pci_remove(struct pci_dev *pci_dev)
{
	mpv_state_t	*mpv_st = pci_get_drvdata(pci_dev);

	if (mpv_st == NULL) {
		pr_err("%s(): device instance = %d isn't loaded.\n",
			__func__, mpv_st->inst);
		return;
	}
	if (mpv_st->mpv_new == MPV_KPI2) {
		pci_write_config_byte(mpv_st->pdev, GPIO_MPV_SW, 0);
		free_irq(mpv_st->irq, mpv_st);
		free_irq(mpv_st->irq + 3, mpv_st);
	} else if (mpv_st->mpv_new == MPV_EIOH) {
		pci_write_config_byte(mpv_st->pdev, GPIO_MPV_SW, 0);
		free_irq(mpv_st->irq, mpv_st);
		free_irq(mpv_st->irq + 1, mpv_st);
		free_irq(mpv_st->irq + 2, mpv_st);
	} else {
		free_irq(mpv_st->irq, mpv_st);
	}
	_mpv_pci_remove(pci_dev, mpv_st);
	dbgmpv("inst. %d %s: finished.\n", mpv_st->inst, __func__);
}
static void
mpv_shutdown(struct pci_dev *pci_dev)
{
	mpv_state_t	*mpv_st = pci_get_drvdata(pci_dev);

	if (mpv_st == NULL)
		return;

	mpv_reset_module(mpv_st);
	if (mpv_st->mpv_new == MPV_KPI2) {
		pci_write_config_byte(mpv_st->pdev, GPIO_MPV_SW, 0);
		free_irq(mpv_st->irq, mpv_st);
		free_irq(mpv_st->irq + 3, mpv_st);
	} else if (mpv_st->mpv_new == MPV_EIOH) {
		pci_write_config_byte(mpv_st->pdev, GPIO_MPV_SW, 0);
		free_irq(mpv_st->irq, mpv_st);
		free_irq(mpv_st->irq + 1, mpv_st);
		free_irq(mpv_st->irq + 2, mpv_st);
	} else {
		free_irq(mpv_st->irq, mpv_st);
	}
	dbgmpv("inst. %d %s: finished.\n", mpv_st->inst, __func__);
}
#endif /* pci */

#if defined(CONFIG_MPV_MODULE) && \
	(defined(CONFIG_PCI2SBUS) || defined(CONFIG_PCI2SBUS_MODULE) || \
		defined(CONFIG_SBUS))
static int
mpv_sbus_probe(struct of_device *op,
			const struct of_device_id *match)
{
	mpv_state_t	*mpv_st = NULL;
	char		*regs_base;
	u8		revision_id;
	int		rval;
	u_int		config_intr;

	dbgmpv("%s() start. name=%s\n", __func__, match->name);
	regs_base = of_ioremap(&op->resource[0], 0,
		op->resource[0].end - op->resource[0].start + 1,
		MPV_NAME);
	if (regs_base == NULL) {
		pr_err("%s(): Unable to map of-registers\n", __func__);
		return -EFAULT;
	}
	if (rev_module_param >= 0) {
		revision_id = rev_module_param;
	} else {
		u32 mpv_sbus_ver = (u32)readl(regs_base + MPV_SBUS_VER);
		pr_warn("%s() MPV_SBUS_VER=0x%04x\n", __func__,
			mpv_sbus_ver);
		if (mpv_sbus_ver >= 0x50000 && mpv_sbus_ver < 0xffffffff)
			revision_id  = 2;
		else
			revision_id  = 1;
	}
	rval = mpv_common_probe(op->dev, &mpv_st, regs_base, 0, revision_id, SBUS_DEV);
	if (rval) {
		if (rval == -ECANCELED) /*device is disabled*/
			rval = 0;
		goto err_unmap;
	}

	dev_set_drvdata(&op->dev, (void *)mpv_st);
	mpv_st->conf_inter = 1 << (MPV_CPU_INTR - 2);
	mpv_write_regl(mpv_st, MPV_REG_CONFIG_INTR, mpv_st->conf_inter);
	config_intr = mpv_read_regl(mpv_st, MPV_REG_CONFIG_INTR);
	if (mpv_st->conf_inter != config_intr) {
		pr_warn("%s(): inst. %d written in"
			"MPV_REG_CONFIG_INTR = 0x%x\n"
			"read from MPV_REG_CONFIG_INTR = 0x%x.\n", __func__,
			mpv_st->inst, mpv_st->conf_inter, config_intr);
		goto err_unmap;
	}
	dbgmpv("inst. %d %s: conf. of interrupts installed = %d. %#x\n",
		__func__, mpv_st->inst, MPV_CPU_INTR, mpv_st->irq);
#if defined(CONFIG_PCI2SBUS) || defined(CONFIG_PCI2SBUS_MODULE)
	mpv_st->irq = ((op->irqs[0]>> 8) << 8) + MPV_CPU_INTR - 1;
	if (sbus_request_irq(mpv_st->irq, &mpv_intr_handler,
		&mpv_threaded_handler, IRQF_SHARED | IRQF_NO_THREAD,
		MPV_NAME, (void *)mpv_st)) {
		pr_err("MPV-%d: Can't get irq 0x%x\n", mpv_st->inst);
		goto err_unmap;
	}
#else	/* SBUS */
	mpv_st->irq = (op->irqs[0] & 0xff00) | (SBUS_IRQ_MIN + MPV_CPU_INTR);
	rval = request_threaded_irq(mpv_st->irq, &mpv_intr_handler,
			&mpv_threaded_handler, IRQF_SHARED | IRQF_NO_THREAD,
			MPV_NAME, (void *)mpv_st);
	if (rval) {
		pr_err("MPV-%d: Can't get irq %d, err [%d]\n",
			mpv_st->inst, mpv_st->irq, rval);
		goto err_unmap;
	}
#endif /* P2S */
	mpv_st->irq_orig = mpv_st->irq;
	pr_warn("MPV-sbus attach: sbusIRQ=%d revision_id=%x "
		"picoseconds per counter clock = %d\n",
		mpv_st->irq, mpv_st->revision_id,
		mpv_st->psecs_per_corr_clck);
	return 0;
err_unmap:
	of_iounmap(&op->resource[0], mpv_st->regs_base,
		op->resource[0].end - op->resource[0].start + 1);
	if (mpv_st) {
		if (mpv_st->major > 0)
			unregister_chrdev(mpv_st->major, MPV_NAME);
		kfree(mpv_st);
	}
	if (mpv_st && rval)
		pr_err("%s:inst: %d  finished with error.", __func__, mpv_st->inst);
	return rval;
}

static int
mpv_sbus_remove(struct of_device *op)
{
	mpv_state_t	*mpv_st = (mpv_state_t *)dev_get_drvdata(&op->dev);

	if (mpv_st == NULL) {
		pr_err("%s(): device isn't loaded.", __func__);
		return -1;
	}
#if defined(CONFIG_SBUS)
	free_irq(mpv_st->irq, mpv_st);
#endif
#if defined(CONFIG_PCI2SBUS) || defined(CONFIG_PCI2SBUS_MODULE)
	sbus_free_irq(mpv_st->irq, mpv_st);
	of_iounmap(&op->resource[0], mpv_st->regs_base,
		op->resource[0].end - op->resource[0].start + 1);
#endif
	mpv_common_remove(mpv_st);
	dev_set_drvdata(&op->dev, NULL);
	dbgmpv("inst. %d %s: finished.\n", __func__, mpv_st->inst);
	return 0;
}
#endif    /* pci2sbus  || sbus*/

static unsigned int
mpv_chpoll(struct file *file, struct poll_table_struct *wait)
{
	dev_t	dev = (dev_t)(long)file->private_data;
	int	intr;
	int	mask;
	int	instance = get_mpv_instance(MAJOR(dev), MINOR(dev), &intr);
	mpv_state_t	*mpv_st = mpv_states[instance];
	unsigned long   flags;

	if ( mpv_st == NULL )
		return ENXIO;
	if ( !MPV_IN(dev) )
		return EINVAL;
	mask = 1 << intr;
	raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
	if ((mpv_st->intr_assemble & mask) != 0) {
		mpv_st->intr_assemble &= ~mask;
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
		return POLLIN;
	} else {
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
		poll_wait(file, &(mpv_st->pollhead),  wait);
		return 0;
	}
}

static int
mpv_open(struct inode *inode, struct file *file)
{
	int		instance;
	int		bus;
	int		disposal_bit;
	mpv_state_t	*mpv_st;
	dev_t		dev = inode->i_rdev;
	unsigned long	flags;
	char		nm[32], *name;

	if ( !dev ) {
		printk("%s(): !dev\n", __func__);
		return -EFAULT;
	}
	instance = get_mpv_instance(MAJOR(dev), MINOR(dev), &bus);
	mpv_st = mpv_states[instance];

	name = d_path(&file->f_path, nm, 32);
	if (IS_ERR(name)) {
		pr_err("inst. %d %s !!! error d_path !!!\n",
			instance, __func__);
		sprintf(nm, "???");
		name = nm;
	}
	dbgmpv("inst. %d %s :MAJOR,MINOR =%d,%03d,\tBUS =%2d,\tMPV_TYPE =%d"
		",\tname =%s\n", instance,
		__func__, MAJOR(dev), MINOR(dev), bus, MPV_INOUT(dev), name);

	if ( mpv_st == NULL ) {
		pr_err("mpv_open: unloaded instance opening %d.", instance);
		return -ENXIO;
	}
	raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
	disposal_bit = 1 << bus;
	if (MPV_IN(dev)) {
		if ((bus >= mpv_st->num_in_bus) || bus > MPV_NUM_IN_INTR) {
			pr_err("ERROR: MPV_IN = %d > %d\n",
				bus, mpv_st->num_in_bus);
			raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
			return -EINVAL;
		}
		if (mpv_st->open_in_count[bus] == 0) {
			mpv_st->intr_assemble &= ~disposal_bit;
			mpv_st->open_in_excl = file->f_flags & O_EXCL;
		} else {
			if (mpv_st->open_in_excl) {
				pr_err("inst. %d "
					"mpv_open: attempt of opennig instance"
					"that already oppened exclusively.",
				    instance);
				raw_spin_unlock_irqrestore(&mpv_st->mpv_lock,
								flags);
				return -EBUSY;
			}
			if (file->f_flags & O_EXCL) {
				raw_spin_unlock_irqrestore(&mpv_st->mpv_lock,
								flags);
				return -EBUSY;
			}
		}
		mpv_st->open_in_count[bus]++;
		mpv_st->open_in = mpv_st->open_in | disposal_bit;
		mpv_st->polar = (mpv_st->polar & ~disposal_bit) |
			(mpv_st->base_polar & disposal_bit);
		if (file->f_flags & O_TRUNC) {
			mpv_st->listen_alive |= disposal_bit;
		} else {
			mpv_write_regl(mpv_st, MPV_REG_MASK, mpv_st->open_in);
		}
		dbgmpv( "inst. %d mpv_open: "
			"external interrupts recieving bus = %d.\n",
			instance, bus);
	} else if (MPV_OUT(dev)) {
		if (mpv_st->open_out_excl) {
			pr_err("inst. %d  mpv_open: attempt of opennig"
				"instance that already oppened exclusively.",
				instance);
			raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
			return -EBUSY;
		}
		mpv_st->open_out_excl = file->f_flags & O_EXCL;
		mpv_st->open_out = mpv_st->open_out | disposal_bit;
		dbgmpv( "inst. %d mpv_open: outgoing interrupts sending bus = %d.\n",
			instance, bus);
	} else {
		if (mpv_st->open_st_excl) {
			pr_err("inst. %d mpv_open: attempt of opennig"
				"instance that already oppened exclusively.",
				instance);
			raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
			return -EBUSY;
		}
		mpv_st->open_st_excl = file->f_flags & O_EXCL;
		mpv_st->open_st = mpv_st->open_st | disposal_bit;
		dbgmpv( "inst. %d mpv_open: mpv bus = %d.\n", instance, bus);
	}
	raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
	file->private_data = (void *)(unsigned long)dev;
	dbgmpv( "inst. %d mpv_open: finish.\n", instance);
	return 0;
}
static inline void
copy_mpv_st(mpv_intr_t *intr_user, mpv_state_t *mpv_st, int mpv_in)
{
	intr_user->correct_counter_nsec[mpv_in] =
		mpv_st->kdata_intr[mpv_in].correct_counter_nsec;
	if (mpv_st->mpv_new)
		intr_user->mpv_time[mpv_in] =
			mpv_st->kdata_intr[mpv_in].mpv_time;
	intr_user->irq_enter_ns[mpv_in] =
		cycles_2nsec(mpv_st->kdata_intr[mpv_in].irq_enter_clks);
	intr_user->read_cc_ns[mpv_in] =
		mpv_st->kdata_intr[mpv_in].read_cc_ns;
	intr_user->intr_appear_nsec[mpv_in] =
		mpv_st->kdata_intr[mpv_in].intr_appear_nsec;
	intr_user->intr_appear_nsec_mono[mpv_in] =
		mpv_st->kdata_intr[mpv_in].intr_appear_nsec_mono;
	intr_user->num_reciv_intr[mpv_in] =
		mpv_st->kdata_intr[mpv_in].num_reciv_intr;
	intr_user->time_generation_intr[mpv_in] = mpv_st->time_gener_intr;
	intr_user->intr_timeout =
		jiffies_to_usecs(mpv_st->kdata_intr[mpv_in].timeout_jif);
	if (mpv_in < mpv_st->num_time_regs) {
		intr_user->intpts_cnt[mpv_in] =
			mpv_st->kdata_intr[mpv_in].intpts_cnt;
		intr_user->prev_time_clk[mpv_in] =
			mpv_st->kdata_intr[mpv_in].prev_time_clk;
	}
}

/*
 * Called via read(2).
 * The buffer  given  to  read(2) returns  a struct mpv_intr.
 * 
 * A read(2) will fail with the error EINVAL if  the  size  of  the
 * supplied buffer is less than sizeof (mpv_intr_t).
 */
static	ssize_t
mpv_read (struct file *file, char *buf, size_t sz, loff_t *f_pos)
{
	mpv_state_t	*mpv_st;
	int		instance;
	int		disposal_bit;
	dev_t		dev = (dev_t)(long)file->private_data;
	int		bus;
	mpv_rd_inf_t	uinf_read;
	int min_sz	= sizeof (mpv_rd_inf_t);
	int		corr_cnt = 0;
	int interrupts;
	unsigned long long clock_limit, prev_cycl, cur_cycl;
	struct	timespec64 intr_real_tm;
	unsigned long	expire;

	instance = get_mpv_instance(MAJOR(dev), MINOR(dev), &bus);
	mpv_st = mpv_states[instance];
	uinf_read.mpv_drv_ver = MPV_DRV_VER;
	dbgmpv_rw("mpv_read: bus = %d:%d sz=%lld sizeof mpv_rd_inf=%lld.\n",
		MPV_INOUT(dev), bus, (long long)sz,
		(long long)sizeof(mpv_rd_inf_t));
	disposal_bit = 1 << bus;
	if (mpv_st == NULL) {
		printk(	"mpv_read: device isn't loaded. bus=%d\n", bus);
		return (-ENXIO);
	};
	if (MPV_IN(dev)) {
		dbgmpv_rw("mpv_read: IN-bus = %d; start sz=%lld "
			"sizeof mpv_rd_inf=%lld.\n",
			bus, (long long)sz, (long long)sizeof (mpv_rd_inf_t));
		if (!(mpv_st->open_in & disposal_bit)) {
			dbgmpv_rw("mpv_read: file is closed\n");
			return -EINVAL;
		}
		raw_spin_lock_irq(&mpv_st->mpv_lock);
		if (mpv_st->kdata_intr[bus].wait_on_cpu) {
			/* handler could mask this input if 'alive' */
			if (mpv_st->listen_alive & disposal_bit)
				mpv_write_regl(mpv_st, MPV_REG_MASK,
					mpv_read_regl(mpv_st, MPV_REG_MASK)
						| disposal_bit);
			prev_cycl = get_cycles();
			clock_limit = prev_cycl +
			    usecs_2cycles(mpv_st->kdata_intr[bus].wait_on_cpu);
			do {
				if (mpv_st->mpv_new) {
					interrupts = mpv_read_regl(mpv_st,
						MPV_RPV);
					mpv_write_regl(mpv_st, MPV_RPV,
						interrupts);
					interrupts &=
						((mpv_st->mpv_new) == MPV_4) ?
							0xf : 0x7;
				} else {
					interrupts = mpv_read_regl(mpv_st,
						MPV_REG_INTR_NULL);
				}
				if (interrupts & disposal_bit)
					goto got;
				prev_cycl = get_cycles();
			} while (prev_cycl < clock_limit);
			raw_spin_unlock_irq(&mpv_st->mpv_lock);
			return -ETIME;
got:
			cur_cycl = get_cycles();
			if (mpv_st->num_time_regs >= bus) {
				corr_cnt = mpv_read_regl(mpv_st,
						mpv_st->corr_cnt_reg[bus]);
			}
			mpv_st->kdata_intr[bus].num_reciv_intr++;
#ifdef CONFIG_MCST
			mpv_st->kdata_intr[bus].irq_enter_clks =
				cycles_2nsec(cur_cycl - prev_cycl);
#endif
			ktime_get_real_ts64(&intr_real_tm);
			mpv_st->kdata_intr[bus].intr_appear_nsec =
					timespec64_to_ns(&intr_real_tm);
			mpv_st->kdata_intr[bus].intr_appear_nsec_mono =
				ktime_to_ns(ktime_get());
			mpv_st->kdata_intr[bus].correct_counter_nsec =
				corr_cnt * mpv_st->psecs_per_corr_clck / 1000;
			if (mpv_st->mpv_new || mpv_st->revision_id >= 2)
				mpv_st->kdata_intr[bus].intpts_cnt =
					mpv_read_regl(mpv_st,
						mpv_st->intpts_cnt_reg[bus]);
			mpv_st->non_oncpu_irq |= interrupts & ~disposal_bit;
			current->waken_tm = sched_clock();
			goto finish;
		}	/* wait_on_cpu */
		if (file->f_flags & O_NONBLOCK &&
				!(mpv_st->intr_assemble & disposal_bit)) {
			raw_spin_unlock_irq(&mpv_st->mpv_lock);
			return -EAGAIN;
		}
		/* wait in scheduler: */
		while (!(mpv_st->intr_assemble & disposal_bit)) {
			raw_wqueue_t wait_el = {.task = current};

			list_add(&wait_el.task_list,
				&mpv_st->kdata_intr[bus].wait1_task_list);
			set_current_state(TASK_INTERRUPTIBLE);
			/* handler could mask this input if 'alive' */
			if (mpv_st->listen_alive & disposal_bit)
				mpv_write_regl(mpv_st, MPV_REG_MASK,
					mpv_read_regl(mpv_st, MPV_REG_MASK)
						| disposal_bit);
			raw_spin_unlock(&mpv_st->mpv_lock);
			/* It is exected user will call el_poix(EL_USER_TICK)
			 * instead of calling do_postpone_tick() in this point*/
			expire = schedule_timeout(
					mpv_st->kdata_intr[bus].timeout_jif);
			raw_spin_lock_irq(&mpv_st->mpv_lock);
			list_del(&wait_el.task_list);
			set_current_state(TASK_RUNNING);
			if (signal_pending(current)) {
				raw_spin_unlock_irq(&mpv_st->mpv_lock);
				return -EINTR;
			}
			if (!expire) {
				raw_spin_unlock_irq(&mpv_st->mpv_lock);
				return -ETIME;
			}
		}
finish:
		uinf_read.irq_enter_ns =
			cycles_2nsec(mpv_st->kdata_intr[bus].irq_enter_clks);
		uinf_read.correct_counter_nsec = mpv_st->kdata_intr[bus].correct_counter_nsec;
		if (mpv_st->mpv_new)
			uinf_read.mpv_time = mpv_st->kdata_intr[bus].mpv_time;
		uinf_read.intr_appear_nsec = mpv_st->kdata_intr[bus].intr_appear_nsec;
		uinf_read.intr_appear_nsec_mono =
			mpv_st->kdata_intr[bus].intr_appear_nsec_mono;
		uinf_read.num_reciv_intr = mpv_st->kdata_intr[bus].num_reciv_intr;
		uinf_read.time_generation_intr = mpv_st->time_gener_intr;
		if (bus < mpv_st->num_time_regs) {
			uinf_read.intpts_cnt = mpv_st->kdata_intr[bus].intpts_cnt;
			uinf_read.prev_time_clk = mpv_st->kdata_intr[bus].prev_time_clk;
		}
		uinf_read.intr_assemble = mpv_st->intr_assemble;
		uinf_read.mpv_drv_ver = MPV_DRV_VER;
		uinf_read.mpv_dev_rev = mpv_st->revision_id;
		if (list_empty(&mpv_st->kdata_intr[bus].wait1_task_list))
				mpv_st->intr_assemble &= ~disposal_bit;
		raw_spin_unlock_irq(&mpv_st->mpv_lock);
		if (sz < sizeof(mpv_rd_inf_t))
			min_sz = sz;
		if (copy_to_user((void *)buf, (void *)&uinf_read, min_sz))
			return -EFAULT;
		return min_sz;
	}
	if (MPV_OS(dev)) {
		int st;
		dbgmpv_rw("inst. %d mpv_read: mpv on bus = %d.\n",
			instance, bus);
		st = !!(mpv_read_regl(mpv_st, MPV_REG_OUT_STAT) & disposal_bit);
		if (sz >= sizeof (int)){
			return copy_to_user((void *)buf, (void *)&st, sizeof (int)) ? -EFAULT : 0;
		} else {
			dbgmpv_rw("mpv_read: buf size =%lld; expected %lld\n",
				(long long)sz, (long long)sizeof (int));
		}
	};
	return (-EINVAL);
}

static	ssize_t
mpv_write (struct file *file, const char *buf, size_t sz, loff_t *f_pos)
{
	int		rval;
	int		instance;
	mpv_state_t	*mpv_st;
	dev_t		dev = (dev_t)(long)file->private_data;
	int		bus;
	int		disposal_bit;
	unsigned long	flags;
	int st;

	instance = get_mpv_instance(MAJOR(dev), MINOR(dev), &bus);
	disposal_bit = 1 << bus;
	dbgmpv_rw("mpv_write: bus = %d; start.\n", bus);
	mpv_st = mpv_states[instance];
	if (mpv_st == NULL) {
		return (-ENXIO);
	};
	rval = copy_from_user((void *)&st, (void *)buf, sizeof(int));
	if (rval != 0) {
		pr_err("mpv_write: copy_from_user() finished with error.");
		return -EFAULT;
	};
	if (MPV_OUT(dev)) {
		dbgmpv_rw("inst. %d mpv_write: external interrupt sending "
			"on bus = %d.\n", instance, bus);
		raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
		mpv_st->current_out &= ~disposal_bit;
		if (st)
			mpv_st->current_out |= disposal_bit;
		mpv_write_regl(mpv_st, MPV_REG_OUT_INTR, mpv_st->current_out);
		mpv_st->time_gener_intr = get_usec_tod();
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
		return sizeof(int);
	};
	if (MPV_OS(dev)) {
		dbgmpv_rw("inst. %d mpv_write: mpv on bus = %d.\n",
			instance, bus);
		raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
		mpv_st->current_st &= ~disposal_bit;
		if (st)
			mpv_st->current_st |= disposal_bit;
		mpv_write_regl(mpv_st, MPV_REG_OUT_STAT, mpv_st->current_st);
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
		return sizeof(int);
	};
	return -EINVAL;
}
static int
mpv_close(struct inode *inode, struct file *file)
{
	mpv_state_t	*mpv_st;
	int		instance;
	int		bus;
	int		disposal_bit;
	dev_t		dev = inode->i_rdev;
	unsigned long	flags;
	struct	list_head *tmp, *next;
	raw_wqueue_t	*waiter_item;

	instance = get_mpv_instance(MAJOR(dev), MINOR(dev), &bus);
	mpv_st = mpv_states[instance];
	if ( mpv_st == NULL ) {
		return -ENXIO;
	}
	raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
	if (MPV_IN(dev)) {
		if (bus >= mpv_st->num_in_bus) {
			pr_err("ERROR: MPV_IN close = %d > %d\n",
				bus, mpv_st->num_in_bus - 1);
			raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
			return -EINVAL;
		}
		mpv_st->open_in_excl = 0;
		if (mpv_st->stv_in_number == bus) {
			raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);   
			return (-EBUSY);
		}
		if (mpv_st->pps4mgb_nunber == bus) {
			raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
			return 0;
		}
		disposal_bit = 1 << bus;
		if ((mpv_st->open_in_count[bus]--) == 1) {
			mpv_st->open_in = mpv_st->open_in & (~disposal_bit);
			if (list_empty(&mpv_st->kdata_intr[bus].wait1_task_list)
				&& list_empty(&mpv_st->any_in_task_list)
				&& !waitqueue_active(&mpv_st->pollhead))
					mpv_st->intr_assemble &= ~disposal_bit;
			if (mpv_st->mpv_new) {
				mpv_write_regl(mpv_st, mpv_st->gen_mode_reg,
					mpv_read_regl(mpv_st,
							mpv_st->gen_mode_reg) &
						~((1<<bus) | (1<<(bus +
						    mpv_st->num_time_regs))));
			} else if (mpv_st->mpv_new ||
					 mpv_st->revision_id >= 2) {
				mpv_write_regl(mpv_st, mpv_st->gen_mode_reg,
					mpv_read_regl(mpv_st,
						mpv_st->gen_mode_reg) &
					~((1<<bus) | (1<<(bus + 16))));
				mpv_write_regl(mpv_st, MPV_REG_OUT_INTR,
					mpv_read_regl(mpv_st, MPV_REG_OUT_INTR)
					 & ~(1<<(bus + 16)));
			}
			mpv_st->listen_alive &= ~disposal_bit;
		}
		list_for_each_safe(tmp, next,
				&mpv_st->kdata_intr[bus].wait1_task_list) {
			waiter_item = list_entry(tmp, raw_wqueue_t, task_list);
			if (current == waiter_item->task)
				list_del(&waiter_item->task_list);
		}
		list_for_each_safe(tmp, next, &mpv_st->any_in_task_list) {
			waiter_item = list_entry(tmp, raw_wqueue_t, task_list);
			if (current == waiter_item->task)
				list_del(&waiter_item->task_list);
		}
		mpv_write_regl(mpv_st, MPV_REG_MASK, mpv_st->open_in);
		mpv_st->kdata_intr[bus].correct_counter_nsec = 0;
		mpv_st->kdata_intr[bus].intr_appear_nsec = 0;
		mpv_st->kdata_intr[bus].intr_appear_nsec_mono = 0;
		mpv_st->kdata_intr[bus].prev_time_clk = 0;
		mpv_st->kdata_intr[bus].intpts_cnt = 0;
		mpv_st->kdata_intr[bus].interv_gen_ns = 0;
		mpv_st->kdata_intr[bus].period_ns = 0;
		mpv_st->kdata_intr[bus].wait_on_cpu = 0;
		mpv_st->kdata_intr[bus].timeout_jif =
					MAX_SCHEDULE_TIMEOUT;
		dbgmpv("inst. %d mpv_close: "
			"external interrupts recieving bus = %d.\n",
			instance, bus);
	} else if (MPV_OUT(dev)) {
		mpv_st->open_out_excl = 0;
		disposal_bit = 1 << bus;
		mpv_st->open_out = mpv_st->open_out & (~disposal_bit);
		dbgmpv( "inst. %d mpv_close: "
			"outgoing interrupts sending bus = %d.\n",
			instance, bus);

	} else if (MPV_OS(dev)) {
		mpv_st->open_st_excl = 0;
		disposal_bit = 1 << bus;
		mpv_st->open_st = mpv_st->open_st & (~disposal_bit);
		dbgmpv( "inst. %d mpv_close: mpvbus = %d.\n", instance, bus);
	}
	mpv_st->time_gener_intr = 0;
	raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
	dbgmpvdetail( "mpv_close: finish.\n");
	return 0;
}

static long
mpv_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int	rval = 0;
	dev_t	dev = (dev_t)(long)file->private_data;
	int	bus;
	int	instance = get_mpv_instance(MAJOR(dev), MINOR(dev), &bus);
	int	disposal_bit = 1 << bus;
	unsigned long 	flags;
	mpv_state_t	*mpv_st = mpv_states[instance];
	unsigned long long	interval;
	int	i;

	dbgmpv_rw("%s cmd %d: inst. %d, bus = %d; start.\n", __func__,
		cmd & 0xff, instance, bus);

	if ( mpv_st == NULL ) {
		pr_err("%s(): device isn't loaded inst=%d bus=%d\n",
			__func__, instance, bus);
		return -ENXIO;
	}
	switch (cmd) {
#ifdef CONFIG_MCST_SELF_TEST
		case MCST_SELFTEST_MAGIC:
		{
			selftest_t st;
#if defined(CONFIG_SBUS)
			selftest_sbus_t *st_sbus = &st.info.sbus;
			char *tmp, *sl_n;
			int slot_num, addr;
			struct device_node *dn = mpv_st->op->node;
			size_t rval;

			st.bus_type = BUS_SBUS;
			st_sbus->bus = 0;
			strcpy(st_sbus->name, MPV_NAME);

			st_sbus->major = MAJOR(dev);
			st_sbus->minor = MINOR(dev);

			tmp = strrchr(dn->full_name, '@');
			if (tmp) {
				/* Remove @ from the string */
				tmp = &tmp[1];
				sl_n = strrchr(tmp, ',');
				if (sl_n) {
					sscanf(tmp, "%d", &slot_num);
					sscanf(&sl_n[1], "%x", &addr);

					if ((addr >> 28) != 0) {
						st_sbus->br_slot = slot_num;
						st_sbus->slot = addr >> 28;
					} else {
						st_sbus->br_slot = -1;
						st_sbus->slot = slot_num;
					}

					st_sbus->address = addr & 0x0FFFFFFF;
				}
			} else {
				st.error = 1;
			}

#elif defined(CONFIG_PCI2SBUS) || defined(CONFIG_PCI2SBUS_MODULE) ||\
	defined(CONFIG_PCI)
			int rval;
			selftest_pci_t *st_pci = &st.info.pci;
#if defined(CONFIG_PCI2SBUS) || defined(CONFIG_PCI2SBUS_MODULE)
			int irq = mpv_st->irq;
			p2s_info_t *p2s_info = get_p2s_info(irq >> 8);

			if (!p2s_info) {
				pr_err("%s: MCST_SELFTEST_MAGIC: Cannot get"
					"p2s_info struct corresponded"
					"to IRQ=%d\n", __func__, irq);
				return -EFAULT;
			}

			struct pci_dev *pdev = p2s_info->pdev;
#else
			struct pci_dev *pdev = mpv_st->pdev;
#endif
			st_pci->vendor = pdev->vendor;
			st_pci->device = pdev->device;

			st.bus_type = BUS_PCI;

			strcpy(st_pci->name, MPV_NAME);
			st_pci->bus = pdev->bus->number;
			st_pci->slot = PCI_SLOT(pdev->devfn);
			st_pci->func = PCI_FUNC(pdev->devfn);
			st_pci->class = pdev->class;

			st_pci->major = MAJOR(dev);
			st_pci->minor = MINOR(dev);

#else
			printk("%s: MCST_SELFTEST_MAGIC: neither CONFIG_SBUS nor CONFIG_PCI2SBUS(CONFIG_PCI2SBUS_MODULE) is defined!! Strange...\n");
			return -EFAULT;
#endif

			rval = copy_to_user((void *)arg, (void *)&st, sizeof(selftest_t));
			if ( rval != 0 ) {
				printk( "%s: MCST_SELFTEST_MAGIC: copy_to_user() failed\n", __func__);
				return -EFAULT;
			}
		}
		return 0;
#endif // CONFIG_MCST_SELF_TEST
	case MPVIO_SEND_INTR:
	{
		int current_out, reg_num;

		if (!MPV_OS(dev) && !MPV_OUT(dev)) {
			printk("mpv_ioctl (MPVIO_SEND_INTR): external "
				"interrupt sending to MPV_IN");
			return (-EINVAL);
		};
		dbgmpv_rw("inst. %d mpv_ioctl(MPVIO_SEND_INTR): external "
			"interrupt sending on bus = %d.\n",
			instance, bus);
		if (arg) {
			unsigned long clock;
			clock = get_cycles();
			rval = copy_to_user((void *)arg, (void *)&clock, sizeof (clock));
			if (rval != 0) {
				printk( "inst. %d mpv_ioctl (MPVIO_SEND_INTR): "
					"copy_to_user() finish with error.\n",
					instance);
				return (-EFAULT);
			};
		}
		reg_num = MPV_OUT(dev) ? MPV_REG_OUT_INTR : MPV_REG_OUT_STAT;
		raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
		current_out = mpv_read_regl(mpv_st, reg_num);
		current_out ^= disposal_bit;
		mpv_write_regl(mpv_st, reg_num, current_out);
		current_out ^= disposal_bit;
		mpv_write_regl(mpv_st, reg_num, current_out);
		mpv_st->time_gener_intr = get_usec_tod();
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
		break;
	}
	case MPVIO_SET_POLAR:
	{
		if (!MPV_IN(dev)) {
			pr_err("MPVIO_SET_POLAR !MPV_IN minor=%x.\n",
					MINOR(dev));
			return (-EINVAL);
		};
		dbgmpv( "inst. %d mpv_ioctl (MPVIO_SET_POLAR): "
			"external interrupts polarity bus = %d.\n",
			instance, bus);
		raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
		if ((unsigned long)arg == 0) {
			mpv_st->polar &= ~disposal_bit;
		} else {
			mpv_st->polar |= disposal_bit;
		};
		mpv_write_regl(mpv_st, MPV_REG_POLARITY, mpv_st->polar);
		mpv_write_regl(mpv_st, MPV_REG_MASK,
			mpv_read_regl(mpv_st, MPV_REG_MASK));
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
		dbgmpv( "mpv_ioctl (MPVIO_SET_POLAR): mpv_st->polar = 0x%x.\n", mpv_st->polar);
		break;
	}

/* The busses STATE and OUT may be set to level 0|1.
 * Using MPVIO_SET_STATE, you may set short pulde signal
 * if arg = 2, then posotive pulse is given,
 * if arg = 3, then negetive pulse is given,
 * It shoud be noted that in the last case th signal
 * rmains at the level 1.
 * It is expected that before setting arg=2 user had set arg=0
 * by means of MPVIO_SET_STATE.
 * And  before setting arg=3 user had set arg=1
 * Initial stat os each bus is 0.
 */
	case MPVIO_SET_STATE : {
	int	arg0;
	int	argw;
		if ((MPV_OS(dev) == 0) && (MPV_OUT(dev) == 0)){
			printk( "inst. %d mpv_ioctl (MPVIO_SET_STATE): "
				"outgoing state bus adjusting. MPV_OS|OUT(dev) = 0.\n",
				instance);
			return (-EINVAL);
		};
		dbgmpv( "inst. %d mpv_ioctl (MPVIO_SET_STATE): "
			"outgoing mpvbus is installed = %d.\n", instance, bus);
		arg0 = argw = arg;
		raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);

	REPEAD_SET_STATE :
		if (arg0 != argw)
			arg0 = argw = !argw;
		else if (arg0 > 1)
			argw = arg0 == 2 ? 1 : 0;

		if (MPV_OS(dev)) {
			if (argw == 0) {
				mpv_st->current_st &= ~disposal_bit;
			} else {
				mpv_st->current_st |= disposal_bit;
			}
			mpv_write_regl(mpv_st, MPV_REG_OUT_STAT, mpv_st->current_st);
		}
		else {
			if (argw == 0) {
				mpv_st->current_out &= ~disposal_bit;
			} else {
				mpv_st->current_out |= disposal_bit;
			}
			mpv_write_regl(mpv_st, MPV_REG_OUT_INTR, mpv_st->current_out);
		}
		if (arg0 > 1)
			goto REPEAD_SET_STATE;

		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
		break;
	}

	case MPVIO_SET_CONFIG_INTR:
	{
		int	int_num;
		u8	compl_reg;
		struct pci_dev *pdev = mpv_st->pdev;

		rval = copy_from_user((void *)&int_num, (void *)arg, sizeof (int));
		if ( rval != 0 ) {
			printk( "inst. %d mpv_ioctl: "
				"copy_from_user() finished with error.\n",
				instance);
			rval = -EFAULT;
			break;
		}
		raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
		if (mpv_st->dev_type == PCI_DEV) {
			if (int_num < 1 ||  int_num > 4) {
				pr_err("MPVIO_SET_CONFIG_INTR:"
					"int(%d)should be 1-4\n", int_num);
				raw_spin_unlock_irqrestore(&mpv_st->mpv_lock,
					flags);
				return -EINVAL;
			}
			pirq = int_num;
			free_irq(mpv_st->irq, mpv_st);
			pci_read_config_byte(pdev, PCI_COMPLEMENT, &compl_reg);
			pci_write_config_byte(pdev, PCI_COMPLEMENT,
				compl_reg | 1);
			pci_write_config_byte(pdev, PCI_INTERRUPT_PIN, pirq);
			pci_write_config_byte(pdev, PCI_COMPLEMENT,
				compl_reg & ~1);
			mpv_st->irq = ((mpv_st->irq_orig - 16) +
					pirq - 1) % 4 + 16;
			pr_warn("MPVIO_SET_CONFIG_INTR: new irq=%d\n",
				mpv_st->irq);
			rval = request_threaded_irq(mpv_st->irq,
					&mpv_intr_handler,
					&mpv_threaded_handler,
					IRQF_SHARED | IRQF_NO_THREAD, MPV_NAME,
					(void *)mpv_st);
			if (rval) {
				pr_err("MPV:Can't get irq %d err %d\n",
					mpv_st->irq, rval);
				raw_spin_unlock_irqrestore(&mpv_st->mpv_lock,
					flags);
				return -EAGAIN;
			}
		}
#if defined(CONFIG_MPV_MODULE) && \
	(defined(CONFIG_PCI2SBUS) || defined(CONFIG_PCI2SBUS_MODULE) || \
		defined(CONFIG_SBUS))
		if (mpv_st->dev_type == SBUS_DEV) {
			u_int	config_intr = 0;
			u_int	old_irq = mpv_st->irq;
			u_int	num_line = 0;

			if (int_num > 7) {
				pr_err("inst. %d mpv_ioctl: interrupt %d > 7\n",
					instance, int_num);
				raw_spin_unlock_irqrestore(&mpv_st->mpv_lock,
					flags);
				return -EFAULT;
			}
			mpv_st->irq = ((old_irq >> 8) << 8) + int_num;
			mpv_write_regl(mpv_st, MPV_REG_NULL_INTR, 0);
			num_line = int_num - 1;
			mpv_st->conf_inter = 1 << num_line;
			mpv_write_regl(mpv_st, MPV_REG_CONFIG_INTR,
				mpv_st->conf_inter);
#if defined(CONFIG_SBUS)
			free_irq(old_irq, mpv_st);
			rval = request_threaded_irq(mpv_st->irq,
					&mpv_intr_handler,
					&mpv_threaded_handler,
					IRQF_SHARED | IRQF_NO_THREAD,
					MPV_NAME, (void *)mpv_st);
			if (rval) {
				pr_err("MPV-%d: Can't get irq 0x%x, err=%d\n",
					instance, mpv_st->irq, rval);
				raw_spin_unlock_irqrestore(&mpv_st->mpv_lock,
					flags);
				return -EAGAIN;
			}
#else  /* PCI2SBUS */
			sbus_free_irq(old_irq, mpv_st);
			if (sbus_request_irq(mpv_st->irq, &mpv_intr_handler,
					&mpv_threaded_handler,
					IRQF_SHARED,
					MPV_NAME, (void *)mpv_st)) {
				pr_err("MPV-%d: Can't get irq 0x%x\n",
					instance, mpv_st->irq);
				raw_spin_unlock_irqrestore(&mpv_st->mpv_lock,
								flags);
				return -EAGAIN;
			}
#endif /* PCI2SBUS */
			config_intr = mpv_read_regl(mpv_st,
				MPV_REG_CONFIG_INTR);
			if (mpv_st->conf_inter != config_intr) {
				pr_warn("mpv_ioctl(MPVIO_SET_CONFIG_INTR):"
					"written in  "
					"MPV_REG_CONFIG_INTR = 0x%x\n"
					"read from MPV_REG_CONFIG_INTR = 0x%x.",
					mpv_st->conf_inter, config_intr);
				raw_spin_unlock_irqrestore(&mpv_st->mpv_lock,
								flags);
				return -EINVAL;
			}
		}
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
#endif /* SBUS or PCI2SBUS */
		break;
	}
	case MPVIO_RUN_DEVICE:
		break;
	case MPVIO_CLEAR_OPTIONS:
		if (mpv_st->open_in_count[bus] > 1)
			return -EBUSY;
		raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
		mpv_st->intr_assemble &= ~disposal_bit;
		mpv_st->kdata_intr[bus].num_reciv_intr = 0;
		mpv_st->listen_alive = 0;
		if (bus < mpv_st->num_time_regs) {
			mpv_st->kdata_intr[bus].correct_counter_nsec = 0;
			mpv_st->kdata_intr[bus].intr_appear_nsec = 0;
			mpv_st->kdata_intr[bus].intr_appear_nsec_mono = 0;
			mpv_st->kdata_intr[bus].prev_time_clk = 0;
			mpv_st->kdata_intr[bus].intpts_cnt = 0;
			mpv_st->kdata_intr[bus].interv_gen_ns = 0;
			mpv_st->kdata_intr[bus].period_ns = 0;
			mpv_st->kdata_intr[bus].wait_on_cpu = 0;
			mpv_st->kdata_intr[bus].timeout_jif =
						MAX_SCHEDULE_TIMEOUT;
			mpv_write_regl(mpv_st, mpv_st->gen_period_reg[bus],
				(mpv_st->mpv_new) ?  0xffffffff : 0xfffff);
			mpv_write_regl(mpv_st, mpv_st->corr_cnt_reg[bus], 0);
			mpv_write_regl(mpv_st, mpv_st->intpts_cnt_reg[bus], 0);
			if (mpv_st->mpv_new || mpv_st->revision_id >= 2)
				mpv_write_regl(mpv_st,
						mpv_st->prev_time_reg[bus], 0);
		}
		mpv_st->time_gener_intr = 0;
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
		dbgmpv( "mpv_ioctl (MPVIO_CLEAR_OPTIONS): outgoing parametrs is now in initial mpv.\n");
		break;
	case MPVIO_WAIT_INTR :
	{
		mpv_intr_t	intr_user;
		int		i;
		long long	wait_time = get_usec_tod();
		
		rval = copy_from_user((caddr_t)&intr_user, (caddr_t)arg, sizeof (mpv_intr_t));
		if (rval != 0) {
			printk( "mpv_ioctl (MPVIO_WAIT_INTR): copy_from_user() finished with error.");
   			return (-EFAULT);
		};
		raw_spin_lock_irq(&mpv_st->mpv_lock);
		if (mpv_st->intr_assemble == 0) {
			unsigned long   	expire;
			raw_wqueue_t wait_el = {.task = current};

			set_current_state(TASK_INTERRUPTIBLE);
			list_add(&wait_el.task_list, &mpv_st->any_in_task_list);
			/* handler could mask some input if it is 'alive' */
			if (mpv_st->listen_alive & disposal_bit)
				mpv_write_regl(mpv_st, MPV_REG_MASK,
					mpv_read_regl(mpv_st, MPV_REG_MASK)
						| disposal_bit);
			raw_spin_unlock_irq(&mpv_st->mpv_lock);
			expire = schedule_timeout(
				usecs_to_jiffies(intr_user.intr_timeout));
			raw_spin_lock_irq(&mpv_st->mpv_lock);
			list_del(&wait_el.task_list);
			set_current_state(TASK_RUNNING);
			if (signal_pending(current)) {
				raw_spin_unlock_irq(&mpv_st->mpv_lock);
				return -EINTR;
			}
			if (!expire) {
#ifdef CONFIG_MCST
				if (pps_debug & 1) {
					pr_warn("MPVIO_WAIT_INTR:"
						"cv_timedwait_sig() waiting"
						"time is elapsed. (= %d).\n",
						 (int )intr_user.intr_timeout);
					pr_warn("mpv_ioctl (MPVIO_WAIT_INTR):"
						"mpv_st->intr_assemble = 0x%x.\n",
						mpv_st->intr_assemble);
				};
#endif
				raw_spin_unlock_irq(&mpv_st->mpv_lock);   
   				return (-ETIME);
			}
		} else {
			/* handler could mask some input if it is 'alive' */
			if (mpv_st->listen_alive & disposal_bit)
				mpv_write_regl(mpv_st, MPV_REG_MASK,
					mpv_read_regl(mpv_st, MPV_REG_MASK)
						| disposal_bit);
		};
		intr_user.mpv_drv_ver = MPV_DRV_VER;
		intr_user.time_get_comm = wait_time;
		for (i = 0; i < mpv_st->num_in_bus; i++) {
			copy_mpv_st(&intr_user, mpv_st, i);
		}
		intr_user.intr_assemble = mpv_st->intr_assemble;
		if (list_empty(&mpv_st->kdata_intr[bus].wait1_task_list)
			&& list_empty(&mpv_st->any_in_task_list)
			&& !waitqueue_active(&mpv_st->pollhead))
				mpv_st->intr_assemble = 0;
		mpv_st->time_gener_intr = 0;
		raw_spin_unlock_irq(&mpv_st->mpv_lock);
		rval = copy_to_user((void *)arg, (void *)&intr_user, sizeof (mpv_intr_t));
		if (rval != 0) {
			printk( "mpv_ioctl (MPVIO_WAIT_INTR): copy_to_user() finished with error.\n");
			return (-EFAULT);
		};
		return rval;
	}


	case MPVIO_GET_INTR :
	case MPVIO_GET_INTR_ALL :
	{
		u_int	state_in;
		u_int	state_in_;

		if (MPV_IN(dev) == 0) {
			pr_err("%d ERROR mpv_ioctl %s MPV_IN(dev) = 0.\n",
				instance, cmd == MPVIO_GET_INTR
					? "GET_INTR" : "GET_INTR_ALL");
			return -EINVAL;
		};
		if (mpv_st->mpv_new) {
			pr_err("%d ERROR mpv_ioctl(%s) old mpv only has"
				"MPV_RAW_IN register.\n",
				instance, cmd == MPVIO_GET_INTR
					? "GET_INTR" : "GET_INTR_ALL");
			return -EINVAL;
		};
		state_in_ = mpv_read_regl(mpv_st, MPV_RAW_IN) & MPV_IN_MASK;
		state_in = state_in_;
		if (cmd == MPVIO_GET_INTR)
			state_in &= (1 << bus);

		rval = copy_to_user((void *)arg,
					(void *)&state_in, sizeof(u_int));
		if (cmd == MPVIO_GET_INTR)
			dbgmpv( "%d mpv_ioctl GET_INTR N%d=%05X (%05X)\n",
				instance, bus, state_in, state_in_);
		else
			dbgmpv("%d mpv_ioctl GET_INTR_ALL =%05X\n",
				instance, state_in);
		return rval;
		break;
	}

	case MPVIO_GET_INTR_INFO :
	{
		mpv_intr_t	intr_user;
		int		i;
		
		raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
		for (i = 0; i < mpv_st->num_in_bus; i++)
			copy_mpv_st (&intr_user, mpv_st, i);
		intr_user.intr_assemble = mpv_st->intr_assemble;
		intr_user.mpv_drv_ver = MPV_DRV_VER;
		intr_user.mpv_dev_rev = mpv_st->revision_id;
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);   
		rval = copy_to_user((void *)arg, (void *)&intr_user, sizeof (mpv_intr_t));
		if (rval != 0) {
			printk( "mpv_ioctl (MPVIO_GET_INTR_INFO copy_to_user() finished with error.\n");
			return (-EFAULT);
		};
		return rval;
	}
	case MPVIO_SET_STV :
		raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
		mpv_st->listen_alive &= ~disposal_bit;
		if ((int) arg >= 1) {
			dbg_max_atpt_getcor = 0;
			dbg_sum_atpt = 0;
			dbg_num_get_cc = 0;
			dbg_num_intr = 0;
			mpv_st->stv_in_number = bus;
			mpv_st->stv_in_mask = 1 << bus;
			mpv_write_regl(mpv_st, MPV_REG_MASK,
				mpv_read_regl(mpv_st, MPV_REG_MASK)
					| mpv_st->stv_in_mask);
			stv_num_msrms = 0;
			set_pps_stat2(STA_PPSTIME | STA_PPSFREQ);
		} else {
			set_pps_stat2(0);
			mpv_st->kdata_intr[bus].period_ns = 0;
			mpv_st->kdata_intr[bus].wait_on_cpu = 0;
			mpv_st->stv_in_number = -1;
			mpv_st->stv_in_mask = 0;
		}
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
		return 0;
	case MPVIO_SET_INTERV: /* arg - interval as usec */
		if (!(mpv_st->mpv_new || mpv_st->revision_id >= 2)) {
			printk(KERN_ERR "Can't set generate interval for instance %d with revision_id %d\n",
				instance, mpv_st->revision_id);
			return -EINVAL;
		}
		if (bus >= mpv_st->num_time_regs) {
			pr_err("MPVIO_SET_INTERV may not be set for in:%d\n",
				bus);
			return -EINVAL;
		}
#if BITS_PER_LONG == 64
		interval = (unsigned long long)arg * PSEC_PER_USEC /
				mpv_st->psecs_per_corr_clck;
#else
		interval = (unsigned long long)arg * PSEC_PER_USEC;
		do_div(interval, mpv_st->psecs_per_corr_clck);
#endif
		dbgmpv("%s() cmd=%d Beg gen_period_reg[%d] \t0x%x =0x%x"
				" mod=0x%x raw_intrv=0x%lld arg=0x%lld\n",
			__func__, cmd, bus, mpv_st->gen_period_reg[bus],
			mpv_read_regl(mpv_st, mpv_st->gen_period_reg[bus]),
			mpv_read_regl(mpv_st, mpv_st->gen_mode_reg),
			interval, (unsigned long long)arg);
		if (mpv_st->mpv_new) {
			/* psecs_per_gen_clck is differ in IOH2 */
			interval = (interval >> 1);
			if (interval > 0xffffffff) {
				pr_err("MPV interval is too long %lld > (1<<32)\n",
					interval);
				return -EINVAL;
			}
		} else {
			if (interval > 0xfffff) {
				pr_err("MPV interval is too long %lld > (1<<20)]\n",
					interval);
				return -EINVAL;
			}
		}
		mpv_st->kdata_intr[bus].interv_gen_ns = (long long)arg *
						NSEC_PER_USEC;
		raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
		if (interval == 0) {
			mpv_st->polar = (mpv_st->polar & ~disposal_bit) |
				(mpv_st->base_polar & disposal_bit);
			mpv_write_regl(mpv_st, MPV_REG_POLARITY, mpv_st->polar);
			mpv_write_regl(mpv_st, MPV_REG_MASK,
				mpv_read_regl(mpv_st, MPV_REG_MASK));
			mpv_write_regl(mpv_st,
					mpv_st->gen_period_reg[bus],
				(mpv_st->mpv_new) ?
					0xffffffff : 0xfffff);
			if (mpv_st->mpv_new) {
				mpv_write_regl(mpv_st,
					mpv_st->gen_mode_reg,
					mpv_read_regl(mpv_st,
					    mpv_st->gen_mode_reg) &
						~((1<<bus) |
						(1<<(bus +
						 mpv_st->num_time_regs))));
			} else {
				mpv_write_regl(mpv_st,
					mpv_st->gen_mode_reg,
					mpv_read_regl(mpv_st,
					    mpv_st->gen_mode_reg) &
						~((1<<bus) |
						(1<<(bus + 16))));
				mpv_write_regl(mpv_st, MPV_REG_OUT_INTR,
					mpv_read_regl(mpv_st,
						MPV_REG_OUT_INTR)
						    & ~(1<<(bus + 16)));
			}
		} else {
			/* it is need for MPVIO_RESET_GENS correct function */
			mpv_st->polar = mpv_st->polar & (~disposal_bit);
			mpv_write_regl(mpv_st, MPV_REG_POLARITY, mpv_st->polar);
			mpv_write_regl(mpv_st, MPV_REG_MASK,
				mpv_read_regl(mpv_st, MPV_REG_MASK));
			mpv_write_regl(mpv_st,
				mpv_st->gen_period_reg[bus],
				(int)interval);
			/* it is not need for alive signal actually */
			mpv_write_regl(mpv_st, mpv_st->gen_mode_reg,
				mpv_read_regl(mpv_st,
				    mpv_st->gen_mode_reg)
					    | (1<<bus));
		}
		dbgmpv("%s() cmd=%d Fin period_reg[%d] 0x%x =0x%x mod=0x%x\n",
			__func__, cmd, bus, mpv_st->gen_period_reg[bus],
			mpv_read_regl(mpv_st, mpv_st->gen_period_reg[bus]),
			mpv_read_regl(mpv_st, mpv_st->gen_mode_reg));
		mpv_st->kdata_intr[bus].period_ns =
			mpv_st->kdata_intr[bus].interv_gen_ns;
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
		return 0;
	case MPVIO_GET_PSPCC: /* get picoseconds per counter clock */
		return mpv_st->psecs_per_corr_clck;
	case MPVIO_SET_PERIOD:
		/* set period (ns) to inform driver that mpv-in is periodic.
		 * Drive mpv will be able to pospone timer interrupt functionsi
		 * performig and do it after next mpv interrupt if next timer
		 * and mpv interrupt will clash/
		 */
		mpv_st->kdata_intr[bus].period_ns = (long) arg;
		return 0;
	case MPVIO_WAIT_ONCPU: /* arg - waiting time as usec */
		mpv_st->kdata_intr[bus].wait_on_cpu = (long) arg;
		return 0;
	case MPVIO_SET_PSPCC: /* set picoseconds per counter clock */
	    {
		long new_psecs = (long) arg;
		mpv_st->psecs_per_corr_clck = new_psecs;
		return 0;
	    }
	case MPVIO_SET_GENOUT:
		/* the signal ganarated by mpv will be send to output pin */
	    { int mode = (int)arg;
		if (mpv_st->mpv_new == MPV_4) {
			pr_err("MPVIO_SET_GENOUT is not supported in MPV4\n");
			return -EINVAL;
		}
		if (mpv_st->mpv_new) {
			if (bus >= mpv_st->num_time_regs) {
				pr_err("ERROR: MPVIO_SET_GENOUT: in= %d > %d\n",
					bus, mpv_st->num_time_regs - 1);
				return -EINVAL;
			}
			raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
			mpv_write_regl(mpv_st, mpv_st->gen_mode_reg,
				(mpv_read_regl(mpv_st, mpv_st->gen_mode_reg) &
				    ~(1<<(bus + mpv_st->num_time_regs)))
				    | (mode << (bus + mpv_st->num_time_regs)));
			raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
			return 0;
		} else {
			if (mpv_st->revision_id >= 3) {
				raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
				mpv_write_regl(mpv_st, MPV_REG_OUT_INTR,
				    (mpv_read_regl(mpv_st, MPV_REG_OUT_INTR) &
					 ~(1 << (bus + 16)))
					 | (mode << (bus + 16)));
				raw_spin_unlock_irqrestore(&mpv_st->mpv_lock,
							flags);
				return 0;
			} else {
				return -EINVAL;
			}
		}
	    }
	case MPVIO_LSTN_ALIVE:
	/* Listen for reserve alive signals. */
	    {
		if (mpv_st->revision_id < 3) {
			printk(KERN_ERR "The is no MPVIO_LSTN_ALIVE"
					" for revision_id %d\n",
				mpv_st->revision_id);
			return -EINVAL;
		}
		if (bus >= mpv_st->num_time_regs) {
			pr_err("MPVIO_LSTN_ALIVE may not be set for in:%d\n",
				bus);
			return -EINVAL;
		}
		if (!(mpv_st->listen_alive & disposal_bit)) {
			pr_err("MPVIO_LSTN_ALIVE: you should open "
				"file with O_TRUNC\n");
			return -EINVAL;
		}
#if BITS_PER_LONG == 64
		interval = (unsigned long long)arg * PSEC_PER_USEC /
				mpv_st->psecs_per_corr_clck;
#else
		interval = (unsigned long long)arg * PSEC_PER_USEC;
		do_div(interval, mpv_st->psecs_per_corr_clck);
#endif
		if (mpv_st->mpv_new) {
			/* psecs_per_gen_clck is differ in IOH2 */
			interval = (interval >> 1);
			if (interval > 0xffffffff) {
				pr_err("MPV interval is too long %lld > (1<<32)\n",
					interval);
				return -EINVAL;
			}
		} else {
			if (interval > 0xfffff) {
				pr_err("MPV interval is too long %lld > (1<<20)]\n",
					interval);
				return -EINVAL;
			}
		}
		raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
		for (i = 0; i < 10; i++) {
			while (!(mpv_st->intr_assemble & disposal_bit)) {
				raw_wqueue_t wait_el = {.task = current};

				set_current_state(TASK_INTERRUPTIBLE);
				list_add(&wait_el.task_list,
					&mpv_st->kdata_intr[bus].
							wait1_task_list);
				/* interrupt handler had masked this input */
				mpv_write_regl(mpv_st, MPV_REG_MASK,
					mpv_read_regl(mpv_st, MPV_REG_MASK)
						| disposal_bit);
				mpv_read_regl(mpv_st, MPV_REG_MASK);
				raw_spin_unlock(&mpv_st->mpv_lock);
				schedule();
				raw_spin_lock_irq(&mpv_st->mpv_lock);
				list_del(&wait_el.task_list);
				set_current_state(TASK_RUNNING);
				if (signal_pending(current)) {
					raw_spin_unlock_irq(&mpv_st->mpv_lock);
					return -EINTR;
				}
			}
			if (list_empty(&mpv_st->kdata_intr[bus].wait1_task_list)
				&& list_empty(&mpv_st->any_in_task_list)
				&& !waitqueue_active(&mpv_st->pollhead))
					mpv_st->intr_assemble &= ~disposal_bit;
		}

		mpv_st->kdata_intr[bus].interv_gen_ns = (long long)arg *
						NSEC_PER_USEC;
		mpv_write_regl(mpv_st, MPV_REG_MASK,
			mpv_read_regl(mpv_st, MPV_REG_MASK) & ~disposal_bit);
		mpv_read_regl(mpv_st, MPV_REG_MASK);
		mpv_write_regl(mpv_st, mpv_st->gen_period_reg[bus],
			(int)interval);
		/* wait for write finish */
		mpv_read_regl(mpv_st, mpv_st->gen_period_reg[bus]);
		mpv_write_regl(mpv_st, mpv_st->gen_mode_reg,
			mpv_read_regl(mpv_st,
				mpv_st->gen_mode_reg) | (1<<(bus + 16)));
		/* wait for write finish */
		mpv_read_regl(mpv_st, mpv_st->gen_mode_reg);
		if (mpv_st->mpv_new) {
			pr_err("There is no MPVIO_LSTN_ALIVE in mpv_new, mpv4\n");
			return -EINVAL;
		}
		/* to get other interrupts for other mpv users */
		mpv_st->intr_assemble |= ~disposal_bit &
			mpv_read_regl(mpv_st, MPV_REG_INTR_NULL);
		/* once more to get from RPPV : */
		mpv_st->intr_assemble |= ~disposal_bit &
			mpv_read_regl(mpv_st, MPV_REG_INTR_NULL);
		/* wait for disappear signal 'alive' */
		for (i = 0; i < 2; i++) { /* we should miss first signal */
			while (!(mpv_st->intr_assemble & disposal_bit)) {
				raw_wqueue_t wait_el = {.task = current};

				set_current_state(TASK_INTERRUPTIBLE);
				list_add(&wait_el.task_list,
				    &mpv_st->kdata_intr[bus].wait1_task_list);
				/* interrupt handler had masked this input */
				mpv_write_regl(mpv_st, MPV_REG_MASK,
					mpv_read_regl(mpv_st, MPV_REG_MASK)
						| disposal_bit);
				mpv_read_regl(mpv_st, MPV_REG_MASK);
				raw_spin_unlock(&mpv_st->mpv_lock);
				schedule();
				raw_spin_lock_irq(&mpv_st->mpv_lock);
				list_del(&wait_el.task_list);
				set_current_state(TASK_RUNNING);
				if (signal_pending(current)) {
					raw_spin_unlock_irq(&mpv_st->mpv_lock);
					return -EINTR;
				}
			}
			if (list_empty(&mpv_st->kdata_intr[bus].wait1_task_list)
				&& list_empty(&mpv_st->any_in_task_list)
				&& !waitqueue_active(&mpv_st->pollhead))
					mpv_st->intr_assemble &= ~disposal_bit;
		}

		/* turn off listen for alive signal*/
		mpv_write_regl(mpv_st, MPV_REG_MASK,
			mpv_read_regl(mpv_st, MPV_REG_MASK) & ~disposal_bit);
		mpv_read_regl(mpv_st, MPV_REG_MASK);
		mpv_write_regl(mpv_st, mpv_st->gen_mode_reg,
			mpv_read_regl(mpv_st,
				mpv_st->gen_mode_reg) & (1<<(bus + 16)));
		mpv_read_regl(mpv_st, mpv_st->gen_mode_reg);
		if (mpv_st->mpv_new) {
			pr_err("There is not MPVIO_LSTN_ALIVE yet\n");
			return -EINVAL;
		}
		/* to get other interrupts for other mpv users */
		mpv_st->intr_assemble |= ~disposal_bit &
			mpv_read_regl(mpv_st, MPV_REG_INTR_NULL);
		/* once more to get from RPPV : */
		mpv_st->intr_assemble |= ~disposal_bit &
			mpv_read_regl(mpv_st, MPV_REG_INTR_NULL);
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
		return 0;
	    }
	case MPVIO_SEND_ALIVE:
	    {
		if (mpv_st->revision_id < 3) {
			printk(KERN_ERR "The is no MPVIO_SEND_ALIVE:"
					" for revision_id %d\n",
				mpv_st->revision_id);
			return -EINVAL;
		}
		if (bus >= mpv_st->num_time_regs) {
			pr_err("MPVIO_LSTN_ALIVE may not be set for in:%d\n",
				bus);
			return -EINVAL;
		}
#if BITS_PER_LONG == 64
		interval = (unsigned long long)arg * PSEC_PER_USEC /
				mpv_st->psecs_per_corr_clck;
#else
		interval = (unsigned long long)arg * PSEC_PER_USEC;
		do_div(interval, mpv_st->psecs_per_corr_clck);
#endif
		if (mpv_st->mpv_new) {
			printk(KERN_ERR "The is no MPVIO_SEND_ALIVE:"
					" for revision_id %d\n",
				mpv_st->revision_id);
			return -EINVAL;
		} else {
			if (interval > 0xfffff) {
				pr_err("MPV interval is too long %lld > (1<<20)]\n",
					interval);
				return -EINVAL;
			}
		}
		raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
		mpv_st->kdata_intr[bus].interv_gen_ns = (long long)arg *
						NSEC_PER_USEC;
		mpv_write_regl(mpv_st, MPV_REG_MASK,
			mpv_read_regl(mpv_st, MPV_REG_MASK) & ~disposal_bit);
		mpv_read_regl(mpv_st, MPV_REG_MASK);
		mpv_write_regl(mpv_st, mpv_st->gen_period_reg[bus],
			(int)interval);
		/* wait for write finish */
		mpv_read_regl(mpv_st, mpv_st->gen_period_reg[bus]);
		/* the signal ganarated by mpv will be send to output pin */
		if (mpv_st->mpv_new) {
			printk(KERN_ERR "The is no MPVIO_SEND_ALIVE:"
					" for revision_id %d\n",
				mpv_st->revision_id);
			return -EINVAL;
		} else {
			mpv_write_regl(mpv_st, MPV_REG_OUT_INTR,
				mpv_read_regl(mpv_st, MPV_REG_OUT_INTR)
				 | (1<<(bus + 16)));
		}
		/* This bus interrupts still masked */
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
		return 0;
	    }
	case MPVIO_RESET_GENS:
	{
		int	prev_gen_mode;

		raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
		prev_gen_mode = mpv_read_regl(mpv_st, mpv_st->gen_mode_reg);
		mpv_write_regl(mpv_st, mpv_st->gen_mode_reg, 0);
		mpv_write_regl(mpv_st, mpv_st->gen_mode_reg, prev_gen_mode);
		mpv_st->intr_assemble &= (prev_gen_mode & 0x2ff);
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
		return 0;
	}
	case MPVIO_RAW_INTRV: {/* arg - interval as register value */
		int raw_intrv;
		if (!(mpv_st->mpv_new || mpv_st->revision_id >= 2)) {
			printk(KERN_ERR "Can't set generate interval for instance %d with revision_id %d\n",
				instance, mpv_st->revision_id);
			return -EINVAL;
		}
		if (bus >= mpv_st->num_time_regs) {
			pr_err("MPVIO_RAW_INTRV may not be set for in:%d\n",
				bus);
			return -EINVAL;
		}
		raw_intrv = (int)(arg & 0xffffffff);
		if (mpv_st->mpv_new) {
			/* psecs_per_gen_clck is differ in IOH2, MPV_4*/
			raw_intrv = (raw_intrv >> 1);
			if (raw_intrv > 0xffffffff) {
				pr_err("MPV raw_intrv is too long %d > (1<<32)\n",
					raw_intrv);
				return -EINVAL;
			}
		} else {
			if (raw_intrv > 0xfffff) {
				pr_err("MPV raw_intrv is too long %d > (1<<20)]\n",
					raw_intrv);
				return -EINVAL;
			}
		}
		dbgmpv("%s() cmd=%d Beg gen_period_reg[%d] \t0x%x =0x%x"
				" mod=0x%x raw_intrv=0x%x arg=0x%x\n",
			__func__, cmd, bus, mpv_st->gen_period_reg[bus],
			mpv_read_regl(mpv_st, mpv_st->gen_period_reg[bus]),
			mpv_read_regl(mpv_st, mpv_st->gen_mode_reg),
			raw_intrv, (int) arg);
		mpv_st->kdata_intr[bus].interv_gen_ns = raw_intrv *
				mpv_st->psecs_per_corr_clck / PSEC_PER_USEC;
		raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
		if (raw_intrv == 0) {
			mpv_st->polar = (mpv_st->polar & ~disposal_bit) |
				(mpv_st->base_polar & disposal_bit);
			mpv_write_regl(mpv_st, MPV_REG_POLARITY, mpv_st->polar);
			mpv_write_regl(mpv_st, MPV_REG_MASK,
				mpv_read_regl(mpv_st, MPV_REG_MASK));
			mpv_write_regl(mpv_st,
					mpv_st->gen_period_reg[bus],
				(mpv_st->mpv_new) ?
					0xffffffff : 0xfffff);
			if (mpv_st->mpv_new) { /* mask */
				mpv_write_regl(mpv_st,
					mpv_st->gen_mode_reg,
					mpv_read_regl(mpv_st,
					    mpv_st->gen_mode_reg) &
						~((1<<bus) | (1<<(bus +
						    mpv_st->num_time_regs))));
			} else {
				mpv_write_regl(mpv_st,
					mpv_st->gen_mode_reg,
					mpv_read_regl(mpv_st,
					    mpv_st->gen_mode_reg) &
						~((1<<bus) |
						(1<<(bus + 16))));
				mpv_write_regl(mpv_st, MPV_REG_OUT_INTR,
					mpv_read_regl(mpv_st,
						MPV_REG_OUT_INTR)
						    & ~(1<<(bus + 16)));
			}
		} else {	/* raw_intrv != 0 */
			/* it is need for MPVIO_RESET_GENS correct function */
			mpv_st->polar = mpv_st->polar & (~disposal_bit);
			mpv_write_regl(mpv_st, MPV_REG_POLARITY, mpv_st->polar);
			mpv_write_regl(mpv_st, MPV_REG_MASK,
				mpv_read_regl(mpv_st, MPV_REG_MASK));
			mpv_write_regl(mpv_st,
				mpv_st->gen_period_reg[bus],
				raw_intrv);
			/* it is not need for alive signal actually */
			mpv_write_regl(mpv_st, mpv_st->gen_mode_reg,
				mpv_read_regl(mpv_st, mpv_st->gen_mode_reg)
					    | disposal_bit);
		}
		mpv_st->kdata_intr[bus].period_ns =
			mpv_st->kdata_intr[bus].interv_gen_ns;
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
		dbgmpv("%s() cmd=%d Fin period_reg[%d] 0x%x =0x%x mod=0x%x\n",
			__func__, cmd, bus, mpv_st->gen_period_reg[bus],
			mpv_read_regl(mpv_st, mpv_st->gen_period_reg[bus]),
			mpv_read_regl(mpv_st, mpv_st->gen_mode_reg));
		return 0;
	}
	case MPVIO_SET_NOISE: {
		unsigned int noise_m = (unsigned int)arg;
		if (!MPV_IN(dev)) {
			pr_err("MPVIO_SET_NOISE !MPV_IN minor=%x.\n",
					MINOR(dev));
			return -EINVAL;
		};
		if (!mpv_st->mpv_new && mpv_st->revision_id >= 2) {
			if (noise_m > 2) {
				pr_err("noise_m =%d > 2.\n", noise_m);
				return -EINVAL;
			};
			dbgmpv("mpv_ioctl (MPVIO_SET_NOISE): mode = %d.\n",
					noise_m);
			mpv_write_regl(mpv_st, MPV_NOISE_GUARD_TIME, noise_m);
		} else if (mpv_st->mpv_new == MPV_4) {
			if (noise_m > 255) {
				pr_err("noise_m =%d > 255.\n", noise_m);
				return -EINVAL;
			};
			mpv_write_regl(mpv_st, MPV_NOISE_GUARD_MPV4,
				(mpv_read_regl(mpv_st, MPV_NOISE_GUARD_MPV4) &
					~(0xff << (bus * 8))) ||
				(noise_m << (bus * 8)));
		} else {
			pr_err("MPVIO_SET_NOISE impossible for this MPV\n");
			return -EINVAL;
		}
		break;
	}
	case MPVIO_SEND_ETHER: {
		unsigned int ether_mode = (unsigned int)arg;
		/* the signal send to Ethernet controler */
		if (mpv_st->mpv_new != MPV_EIOH) {
			pr_err("MPVIO_SEND_ETHER is possible for mpv-eioh "
				" only (DevId=0x8025)\n");
			return -EINVAL;
		}
		if (ether_mode > 4) {
			pr_err("MPVIO_SEND_ETHER %d > 3\n", ether_mode);
			return -EINVAL;
		}
		if (ether_mode) {
			mpv_write_regl(mpv_st, mpv_st->gen_mode_reg,
				(mpv_read_regl(mpv_st, mpv_st->gen_mode_reg) &
					0x3f) | (bus << 6));
			have_pps_mpv = 1;
			mpv_st->pps4mgb_nunber = bus;
		} else {
			mpv_write_regl(mpv_st, mpv_st->gen_mode_reg,
				(mpv_read_regl(mpv_st, mpv_st->gen_mode_reg) &
					0x3f) | (3 << 6));
			mpv_st->pps4mgb_nunber = -1;
			have_pps_mpv = 0;
		}
		return 0;
	}
	case MPVIO_SET_TIMEOUT: {
		/* set timeout for all read()'s for this mpv_in
		MAX_SCHEDULE_TIMEOUT == LONG_MAX */
		mpv_st->kdata_intr[bus].timeout_jif =
			usecs_to_jiffies((long) arg);
		return 0;
	    }
	case MPVIO_SET_DBG :
		if (do_log_stv) {
			do_log_stv1 = 1;
			printk( "v7 avg_gcor*1000= %ld _max_atpt_gcor= %d avrg_atpt_gcor*100= %d\n", 
				dbg_avg_getcor, dbg_max_atpt_getcor, dbg_sum_atpt*100/(stv_num_msrms?:1));
		};

		do_log_stv = (long long) arg;
		return 0;
	default:
		rval = -EINVAL;
		break;
	}
	return (rval);
}

/* to send pps to Ethernet controller */
static int mpv_send_pps(u32 bus, int enable)
{
	mpv_state_t *mpv_st;
	unsigned long flags;

	if (!atomic_read(&mpv_instances)) {
		pr_err("MPV: mpv_send_pps FAIL mpv_instances == 0\n");
		return -ENXIO;
	}

	mpv_st = mpv_states[0];
	if (mpv_st == NULL) {
		pr_err("MPV: mpv_send_pps FAIL mpv_states[0] == 0\n");
		return -ENXIO;
	}

	if (mpv_st->mpv_new != MPV_EIOH) {
		pr_err("MPV: To send pps is possible for mpv-eioh "
			" only (DevId=0x8025)\n");
		return -EINVAL;
	}
	if (bus > 2) {
		pr_err("MPV: invalid bus number: %d\n", bus);
		return -EINVAL;
	}

	raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
	if (enable) {
		mpv_write_regl(mpv_st, mpv_st->gen_mode_reg,
			(mpv_read_regl(mpv_st, mpv_st->gen_mode_reg) &
				0x3f) | (bus << 6));
		have_pps_mpv = 1;
		mpv_write_regl(mpv_st, MPV_REG_MASK,
			mpv_read_regl(mpv_st, MPV_REG_MASK) | (1 << bus));
		mpv_st->pps4mgb_nunber = bus; /* close() will not unset MPV_REG_MASK */
	} else {
		mpv_write_regl(mpv_st, mpv_st->gen_mode_reg,
			(mpv_read_regl(mpv_st, mpv_st->gen_mode_reg) &
				0x3f) | (3 << 6));
		have_pps_mpv = 0;
		mpv_st->pps4mgb_nunber = -1;
	}
	raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);

	pr_info("MPV: pps mpv_in:%d is %s.\n",
			 bus, !!(enable) ? "enabled" : "disabled");

	return 0;
}

/* Get mpv frequency for mgb driver */
static int mpv_get_freq(u32 bus)
{
	mpv_state_t *mpv_st;
	int freq;

	if (!atomic_read(&mpv_instances))
		return -ENXIO;
	mpv_st = mpv_states[0];
	if (mpv_st == NULL) {
		pr_err("MPV: mpv_get_freq() requer mpv-eioh\n");
		return -ENXIO;
	}
	freq = mpv_read_regl(mpv_st, mpv_st->prev_time_reg[bus]);
	return freq;
}

#ifdef CONFIG_COMPAT
static long mpv_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return mpv_ioctl(filp, cmd, arg);
}
#endif

static irqreturn_t
mpv_threaded_handler(int irq, void *arg)
{
	mpv_state_t	*mpv_st = (mpv_state_t *)(arg);
	if (waitqueue_active(&mpv_st->pollhead))
		wake_up_interruptible(&mpv_st->pollhead);
	return IRQ_HANDLED;
}
static irqreturn_t
mpv_intr_handler(int irq, void *arg)
{
	mpv_state_t	*mpv_st = (mpv_state_t *)(arg);
	int		interrupts;
	int		i;
	unsigned long	flags;
	raw_wqueue_t	*waiter_item;
	long long	corr_count_ns = 0;
	struct	timespec64 intr_real_tm, stv_raw_tm;
	struct	timespec64 corr_tm = {0, 0};
	struct	list_head *tmp, *next;
	unsigned long long cycl1;
	int	read_cc_ns = 0;
	int stv_in_nmb = mpv_st->stv_in_number;
	struct pps_event_time ts;
	long prv_clk;
	unsigned long long psecs_per_clck;
	long long prev_interv = 0;

#ifdef CONFIG_MCST
	long long	irq_enter_clks;
	irq_enter_clks = get_cycles() - current_thread_info()->irq_enter_clk;
#endif
#if 0
	for (i = 0; i < mpv_st->num_in_bus; i++) {
		__builtin_prefetch(&mpv_st->kdata_intr[i].wait_on_cpu);
	}
#endif
	dbgmpvdetail(" === mpv_intr_handl\n");
	if (mpv_st == NULL) {
		return IRQ_NONE;
	};
	raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
	if (mpv_st->mpv_new) {
		interrupts = mpv_read_regl(mpv_st, MPV_RPV);
		interrupts &= ((mpv_st->mpv_new) == MPV_4) ? 0xf : 0x7;
	} else {
		interrupts = mpv_read_regl(mpv_st, MPV_REG_INTR_NULL);
	}
	interrupts |= mpv_st->non_oncpu_irq;
	mpv_st->non_oncpu_irq = 0;
	if (interrupts == 0) {
		for (i = 0; i < mpv_st->num_in_bus; i++) {
			if (mpv_st->kdata_intr[i].wait_on_cpu) {
				raw_spin_unlock_irqrestore(&mpv_st->mpv_lock,
					flags);
				return IRQ_HANDLED;
			}
		}
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
		return IRQ_NONE;
	};
	mpv_st->intr_assemble |= interrupts;
	/* processing of PPS before other interrupts to avoid jitters */
	if (interrupts & mpv_st->stv_in_mask) {
		pps_get_ts(&ts);
		intr_real_tm = ts.ts_real;
		stv_raw_tm = ts.ts_raw;
		if (mpv_st->mpv_new)
			mpv_write_regl(mpv_st, MPV_RPV, mpv_st->stv_in_mask);
		if (mpv_st->mpv_new || mpv_st->revision_id >= 2) {
			prv_clk = mpv_read_regl(mpv_st,
				mpv_st->prev_time_reg[stv_in_nmb]);
			mpv_st->kdata_intr[stv_in_nmb].prev_time_clk = prv_clk;
			if (mpv_st->kdata_intr[stv_in_nmb].num_reciv_intr > 8 &&
					prv_clk != 0) {
#if BITS_PER_LONG == 64
				psecs_per_clck = PSEC_PER_SEC / prv_clk;
#else
				psecs_per_clck = PSEC_PER_SEC;
				do_div(psecs_per_clck, prv_clk);
#endif
				mpv_st->psecs_per_corr_clck = psecs_per_clck;
			}
		}
		if (stv_in_nmb < mpv_st->num_time_regs) {
			cycl1 = get_cycles();
			corr_count_ns =
				mpv_read_regl(mpv_st,
					mpv_st->corr_cnt_reg[stv_in_nmb]) *
					mpv_st->psecs_per_corr_clck / 1000;
			read_cc_ns = (int)(cycles_2nsec(get_cycles() - cycl1));
		}
		mpv_st->kdata_intr[stv_in_nmb].correct_counter_nsec =
			(int)corr_count_ns;
		mpv_st->kdata_intr[stv_in_nmb].read_cc_ns = (int)read_cc_ns;
		corr_tm.tv_nsec = corr_count_ns;
		timespec64_sub(stv_raw_tm, corr_tm);
		timespec64_sub(intr_real_tm, corr_tm);
		mpv_st->kdata_intr[stv_in_nmb].intr_appear_nsec =
		    timespec64_to_ns(&intr_real_tm);
		mpv_st->kdata_intr[stv_in_nmb].intr_appear_nsec_mono =
			ktime_to_ns(ktime_get()) - corr_count_ns;
#ifdef	CONFIG_NTP_PPS
#define READ_CC_LIM	15000 /* nanosec */
#define CORR_CNT_LIM	300000 /* nanosec */
		if (read_cc_ns < READ_CC_LIM &&
					corr_count_ns < CORR_CNT_LIM) {
			set_pps_stat2(STA_PPSTIME | STA_PPSFREQ);
			dbgmpv_pps("MPV: hardpps %lld.%9ld, %lld.%9ld\n",
				(s64)intr_real_tm.tv_sec, intr_real_tm.tv_nsec,
				(s64)stv_raw_tm.tv_sec, intr_real_tm.tv_nsec);
			hardpps(&intr_real_tm, &stv_raw_tm);
		} else {
			if (read_cc_ns >=  READ_CC_LIM)
				dbgmpv("MPV: time is not corrected by PPS. "
					"CorCnt Reading %d > %d ns\n",
					read_cc_ns, READ_CC_LIM);
			else
				dbgmpv("MPV: time is not corrected by PPS. "
					"CorCnt %lld > %d ns [0x%x]=0x%x\n",
					corr_count_ns, CORR_CNT_LIM,
					mpv_st->corr_cnt_reg[stv_in_nmb],
					mpv_read_regl(mpv_st,
					    mpv_st->corr_cnt_reg[stv_in_nmb]));
		}
#endif
#ifdef CONFIG_MCST
		mpv_st->kdata_intr[stv_in_nmb].irq_enter_clks = irq_enter_clks;
#endif
		if (mpv_st->mpv_new || mpv_st->revision_id >= 2)
			mpv_st->kdata_intr[stv_in_nmb].intpts_cnt =
				mpv_read_regl(mpv_st,
					mpv_st->intpts_cnt_reg[stv_in_nmb]);
		mpv_st->kdata_intr[stv_in_nmb].num_reciv_intr++;
		/* wake up for read() */
		list_for_each_safe(tmp, next,
			&mpv_st->kdata_intr[stv_in_nmb].wait1_task_list) {
			waiter_item = list_entry(tmp, raw_wqueue_t, task_list);
			wake_up_process(waiter_item->task);
		}
		interrupts &= !(mpv_st->stv_in_mask);
		if (interrupts == 0)
			goto out;
	}
	for (i = 0; i < mpv_st->num_in_bus; i++) {
		if (!(interrupts & (1 << i)))
			continue;
		if (mpv_st->mpv_new)
			mpv_write_regl(mpv_st, MPV_RPV, 1 << i);
		if (mpv_st->kdata_intr[i].wait_on_cpu) {
			mpv_st->oncpu_irq |= (1 << i);
			continue;
		}
		ktime_get_real_ts64(&intr_real_tm);
		if (mpv_st->kdata_intr[i].time_prev_intrpt) {
			prev_interv = timespec64_to_ns(&intr_real_tm) -
				mpv_st->kdata_intr[i].time_prev_intrpt;
		}
		mpv_st->kdata_intr[i].time_prev_intrpt = timespec64_to_ns(&intr_real_tm);
		if (i < mpv_st->num_time_regs) {
			/* there is corr count reg in MPV */
			cycl1 = get_cycles();
			corr_count_ns =
				mpv_read_regl(mpv_st,
					mpv_st->corr_cnt_reg[i]) *
					mpv_st->psecs_per_corr_clck / 1000;
			read_cc_ns = (int)(cycles_2nsec(get_cycles() - cycl1));
			mpv_st->kdata_intr[i].correct_counter_nsec =
				(int)corr_count_ns;
			mpv_st->kdata_intr[i].read_cc_ns = (int)read_cc_ns;
			if (mpv_st->mpv_new == MPV_KPI2 ||
					mpv_st->mpv_new == MPV_EIOH) {
				mpv_st->kdata_intr[i].mpv_time =
					mpv_read_regl(mpv_st,
						mpv_st->mpv_time_reg[i]);
			}
			mpv_st->kdata_intr[i].intr_appear_nsec =
				    timespec64_to_ns(&intr_real_tm) -
					    corr_count_ns;
			mpv_st->kdata_intr[i].intr_appear_nsec_mono =
				ktime_to_ns(ktime_get()) - corr_count_ns;
			if (mpv_st->mpv_new || mpv_st->revision_id >= 2) {
				mpv_st->kdata_intr[i].prev_time_clk =
					mpv_read_regl(mpv_st,
						mpv_st->prev_time_reg[i]);
			}
		} else{ /* no time regs */
			mpv_st->kdata_intr[i].intr_appear_nsec =
			    timespec64_to_ns(&intr_real_tm);
			mpv_st->kdata_intr[i].intr_appear_nsec_mono =
				ktime_to_ns(ktime_get());
			read_cc_ns = 0;
			corr_count_ns = 0;
			mpv_st->kdata_intr[i].correct_counter_nsec = 0;
			mpv_st->kdata_intr[i].read_cc_ns = 0;
		}
#ifdef CONFIG_MCST
		mpv_st->kdata_intr[i].irq_enter_clks = irq_enter_clks;
#endif
		if (mpv_st->mpv_new || mpv_st->revision_id >= 2)
			mpv_st->kdata_intr[i].intpts_cnt =
				mpv_read_regl(mpv_st,
						mpv_st->intpts_cnt_reg[i]);
		mpv_st->kdata_intr[i].num_reciv_intr++;
		if (mpv_st->listen_alive & (1 << i)) {
			mpv_write_regl(mpv_st, MPV_REG_MASK,
			    mpv_read_regl(mpv_st, MPV_REG_MASK) & ~(1 << i));
			mpv_read_regl(mpv_st, MPV_REG_MASK);
		}
		/* wake up for read() */
		list_for_each_safe(tmp, next,
				&mpv_st->kdata_intr[i].wait1_task_list) {
			waiter_item = list_entry(tmp, raw_wqueue_t, task_list);
			wake_up_process(waiter_item->task);
		}
		do_postpone_tick(prev_interv);
	};
	/* wake up for ioctl(MPVIO_WAIT_INTR) -- any interrupt */
out:	list_for_each_safe(tmp, next, &mpv_st->any_in_task_list) {
		waiter_item = list_entry(tmp, raw_wqueue_t, task_list);
		wake_up_process(waiter_item->task);
	}
	raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
	if (waitqueue_active(&mpv_st->pollhead))
		return IRQ_WAKE_THREAD;
	return IRQ_HANDLED;
}

static int
mpv_check_initial_value_reg(mpv_state_t	*mpv_st)
{
	int		i, r = 0;
	uint		rval;

	if (mpv_st->mpv_new || mpv_st->revision_id >= 2)
		dbgmpv("%s() gen_mode_reg 0x%x=0x%x\n",
			__func__, mpv_st->gen_mode_reg,
			mpv_read_regl(mpv_st, mpv_st->gen_mode_reg));
	for (i = 0; i < mpv_st->num_time_regs; i++) {
		dbgmpv("%s() corr_cnt_reg[%d] \t0x%x =0x%x\n",
			__func__, i, mpv_st->corr_cnt_reg[i],
			mpv_read_regl(mpv_st, mpv_st->corr_cnt_reg[i]));
		if (mpv_st->mpv_new || mpv_st->revision_id >= 2) {
			dbgmpv("%s() gen_period_reg[%d] \t0x%x =0x%x\n",
				__func__, i, mpv_st->gen_period_reg[i],
				mpv_read_regl(mpv_st,
						mpv_st->gen_period_reg[i]));
			dbgmpv("%s() intpts_cnt_reg[%d] \t0x%x =0x%x\n",
				__func__, i, mpv_st->intpts_cnt_reg[i],
				mpv_read_regl(mpv_st,
						mpv_st->intpts_cnt_reg[i]));
			dbgmpv("%s() prev_time_reg[%d]  \t0x%x =0x%x\n",
				__func__, i, mpv_st->prev_time_reg[i],
				mpv_read_regl(mpv_st,
						mpv_st->prev_time_reg[i]));
		}
		if (mpv_st->mpv_new)
			dbgmpv("%s() mpv_time[%d] 0x%x =0x%x base =0x%x\n",
				__func__, i, mpv_st->mpv_time_reg[i],
				mpv_read_regl(mpv_st, mpv_st->mpv_time_reg[i]),
				mpv_read_regl(mpv_st, 0x18));
	}
	rval = mpv_read_regl(mpv_st, MPV_REG_POLARITY);
	if (mpv_st->base_polar != rval) {
		dbgmpv("%s(): inst. %d written in MPV_REG_POLARITY = 0x%x\n"
			"got from MPV_REG_POLARITY = 0x%x.\n",
			__func__, mpv_st->inst, mpv_st->base_polar, rval);
	}
	rval = mpv_read_regl(mpv_st, MPV_REG_MASK);
	if (mpv_st->mpv_new == MPV_KPI2 || mpv_st->mpv_new == MPV_EIOH)
		rval &= 0x7;
	if (mpv_st->mpv_new == MPV_4)
		rval &= 0xf;
	if (rval != 0) {
		printk( "inst. %d "
			"mpv_check_initial_value_reg.: after clearing "
			"MPV_REG_MASK 0x%x = 0x%x\n",
			mpv_st->inst,  MPV_REG_MASK, rval);
	}
	if (!mpv_st->mpv_new) {
		for (i = 0; i < mpv_st->num_time_regs; i++) {
			rval = mpv_read_regl(mpv_st, mpv_st->corr_cnt_reg[i]);
			if (rval != 0) {
				printk("inst. %d "
				"mpv_check_initial_value_reg.: after clearing "
				"MPV_REG TIME INTER%d 0x%x = 0x%x\n",
				mpv_st->inst, i, mpv_st->corr_cnt_reg[i], rval);
			}
		}
		rval = mpv_read_regl(mpv_st, MPV_REG_OUT_STAT);
		if (rval != 0) {
			printk("inst. %d "
				"mpv_check_initial_value_reg.: after clearing "
				"MPV_REG_OUT_STAT = 0x%x awaiting 0x%x.\n",
				mpv_st->inst, rval, 0);
		}
		rval = mpv_read_regl(mpv_st, MPV_REG_OUT_INTR);
		if (rval != 0) {
			r++;
			pr_err("inst. %d "
				"mpv_check_initial_value_reg.: after clearing "
				"MPV_REG_OUT_INTR = 0x%x awating 0x%x\n",
				mpv_st->inst, rval, 0);
		}
	}
	if (r != 0) {
		pr_err("inst. %d mpv_check_initial_value_reg.:"
			"Hardware MPV parts work wrong!\n",
			mpv_st->inst);
		return (1);
	};
	return (0);
}
static void
mpv_reset_module(mpv_state_t *mpv_st)
{
	int		i;
	
	if (mpv_st->intr_assemble != 0) {
		printk("%s: inst. %d interrupts = 0x%x != 0\n",
			__func__, mpv_st->inst, mpv_st->intr_assemble);
	};
	mpv_st->polar = mpv_st->base_polar;
	mpv_write_regl(mpv_st, MPV_REG_POLARITY, mpv_st->polar);
	mpv_write_regl(mpv_st, MPV_REG_MASK,
		mpv_read_regl(mpv_st, MPV_REG_MASK));
	if (mpv_st->mpv_new) {
		mpv_write_regl(mpv_st, MPV_RESET_IOHUB2, 0);
		dbgmpv("%s(): write 0 in MPV_RESET_REG 0x%x\n",
			__func__, MPV_RESET_IOHUB2);
	} else {
		mpv_write_regl(mpv_st, MPV_RESET_V2, 0);
		mpv_write_regl(mpv_st, MPV_REG_OUT_INTR, 0);
		mpv_read_regl(mpv_st, MPV_REG_INTR_NULL);
		if (mpv_st->revision_id >= 2)
			for (i = 0; i < mpv_st->num_time_regs; i++) {
				mpv_write_regl(mpv_st,
					mpv_st->gen_period_reg[i], 0xfffff);
				mpv_write_regl(mpv_st,
					mpv_st->intpts_cnt_reg[i], 0);
			}
	}
	mpv_write_regl(mpv_st, MPV_REG_MASK, 0);
	dbgmpv("%s(): write MPV_IN_MASK=0x%x  in MPV_REG_POLARITY=0x%x\n",
		__func__, MPV_IN_MASK, MPV_REG_POLARITY);
	dbgmpv("%s(): write 0 in MPV_REG_MASK 0x%x\n", __func__, MPV_REG_MASK);
	dbgmpv( "inst. %d mpv_reset_module: "
		"device registers are now in initial state.\n", mpv_st->inst);
}
module_param_named(rev, rev_module_param, int, 0444);
MODULE_PARM_DESC(rev, "Forced mpv-revision number");
module_init(mpv_init);
module_exit(mpv_exit);
MODULE_AUTHOR("MCST");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("MPV driver");
