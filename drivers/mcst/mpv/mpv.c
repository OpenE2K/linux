#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
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
#include <asm/uaccess.h>
#include <linux/time.h>
#include <linux/interrupt.h>
#include <linux/timex.h>
#include <linux/el_posix.h>
#include "mpv.h"

#ifdef CONFIG_MCST_SELF_TEST
#include <linux/mcst/mcst_selftest.h>
#endif

// /proc/sys/debug/mpv_debug trigger
int mpv_debug = 0;
int mpv_debug_more = 0;

#define DBGMPV_MODE
#undef DBGMPV_MODE

#define DBGMPVDETAIL_MODE
#undef DBGMPVDETAIL_MODE

#if defined(DBGMPV_MODE)
#define dbgmpv			printk
#else
#define dbgmpv			if ( mpv_debug ) printk
#endif

#if defined(DBGMPVDETAIL_MODE)
#define dbgmpvdetail		printk
#else
#define dbgmpvdetail		if ( mpv_debug_more ) printk
#endif

#define chekpoint_mpv	pr_err("%s:%s():%d\n", __FILE__, __func__, __LINE__);

#define PCI_COMPLEMENT		0x40	/* 8 bits */
#define PSEC_PER_USEC	1000000

#define SBUS_DEV 	1
#define PCI_DEV  	2

static int pirq = 0;
module_param(pirq , int , 0);
MODULE_PARM_DESC(pirq, "Used for set PIRQ=0,1,2,3 (A, B, C, D). Default =0");

/*atomic_t mpv_instances; TODO*/
static int mpv_instances;
static mpv_state_t	*mpv_states[MAX_MPV_INSTANCES];
static struct class *mpv_class = NULL;
static int rev = -1;

#if defined(CONFIG_MPV_MODULE) && \
	(defined(CONFIG_PCI2SBUS) || defined(CONFIG_PCI2SBUS_MODULE) || \
		defined(CONFIG_SBUS))
static int __init mpv_sbus_probe(struct of_device *op,
			const struct of_device_id *match);
static int __exit mpv_sbus_remove(struct of_device *op);
#endif
#ifdef CONFIG_PCI
static int __init mpv_pci_probe(struct pci_dev *pdev,
			const struct pci_device_id *pci_ent);
static void __exit mpv_pci_remove(struct pci_dev *pci_dev);
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

static int mpv_check_initial_value_reg(mpv_state_t	*mpv_st);
static irqreturn_t mpv_intr_handler(int irq, void *arg);
static irqreturn_t mpv_threaded_handler(int irq, void *arg);
static void mpv_reset_module(mpv_state_t *mpv_st);

/* number of usecs for psecs_per_corr_clck calculating */
int	measure_time = 10000;
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
extern int	do_log_stv;

#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>

static ctl_table mpv_table[] = {
	{
		.procname	= "mpv_debug",
		.data		= &mpv_debug, 
		.maxlen		= sizeof(mpv_debug),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
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

static void __init mpv_sysctl_register(void)
{
	mpv_sysctl_header = register_sysctl_table(mpv_root_table);
}

static void mpv_sysctl_unregister(void)
{
	if ( mpv_sysctl_header )
		unregister_sysctl_table(mpv_sysctl_header);
}

#else /* CONFIG_SYSCTL */

static void __init mpv_sysctl_register(void)
{
}

static void mpv_sysctl_unregister(void)
{
}
#endif

static long long get_usec_tod(void) {
	struct timeval tv;
	long long retval;

	do_gettimeofday(&tv);
	retval = (long long)tv.tv_sec * USEC_PER_SEC
		+ (long long)tv.tv_usec;
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
	.remove         = __exit_p(mpv_sbus_remove),
};
#endif

#ifdef CONFIG_PCI
static struct pci_device_id mpv_pci_tbl[] = {
	{ 0x5453, MPV_CARD_DEVID, PCI_ANY_ID, PCI_ANY_ID, },
	{ 0x1fff, MPV_KPI2_DEVID, PCI_ANY_ID, },
	{ 0x1fff, MPV4_DEVID, PCI_ANY_ID, },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, mpv_pci_tbl);

static struct pci_driver mpv_pci_driver = {
	.name =     MPV_NAME,
	.probe =    mpv_pci_probe,
	.remove =   __exit_p(mpv_pci_remove),
	.id_table = mpv_pci_tbl,
};
#endif

static int
__init mpv_init(void)
{
	int res = 0;

	mpv_sysctl_register();
	dbgmpv("********* MPV_INIT: START for %s *********\n", MPV_NAME);
	/*atomic_set(&mpv_instances, 1);*/
	mpv_instances = 0;
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
static void __exit
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
static int __init
mpv_common_probe(mpv_state_t **mpv_stp, void *r_base,
		int mpv_new, int revision_id, int dev_type)
{
	mpv_state_t	*mpv_st;
	int		i;
	int		instance;
	int		rval;
	unsigned long	flags;
	int		major;
	int		minor;
	char		name[64];
	unsigned int	mpv_time_cnt0, mpv_time_cnt;

/*	instance = atomic_add_return(1, &mpv_instances); */
	instance = mpv_instances++;
	if (instance >= MAX_MPV_INSTANCES) {
		pr_err("MPV: number of instances > MAX_MPV_INSTANCES=%d\n",
			MAX_MPV_INSTANCES);
		return 1;
	}
	mpv_st = kmalloc(sizeof(mpv_state_t), GFP_KERNEL);
	if ( mpv_st == NULL )
		return 1;
	memset(mpv_st, 0, sizeof(mpv_state_t));
	*mpv_stp = mpv_st;
	init_waitqueue_head(&(mpv_st->pollhead));
	mpv_st->inst	= instance;
	mpv_st->stv_in_number= -1;
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
	if (mpv_new == MPV_KPI2) {
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
		mpv_st->kdata_intr[i].prev_time_clk = 0;
		mpv_st->kdata_intr[i].intpts_cnt = 0;
		mpv_st->kdata_intr[i].interv_gen_ns = 0;
		mpv_st->kdata_intr[i].period_ns = 0;
		mpv_st->kdata_intr[i].wait_on_cpu = 0;
		mpv_st->open_in_count[i] = 0;
		INIT_LIST_HEAD(&mpv_st->kdata_intr[i].wait1_task_list);
	}
	if (!mpv_new && revision_id == 0) {
		for (i = 0; i < 4; i++)
			mpv_st->corr_cnt_reg[i] = corr_cnt_reg_v0[i];
	}
	if (mpv_st->mpv_new == MPV_KPI2) {
		mpv_st->base_polar = 0x7;
	} else if (mpv_st->mpv_new == MPV_4) {
		mpv_st->base_polar = 0xf;
	} else
		mpv_st->base_polar = MPV_IN_MASK;
	mpv_reset_module(mpv_st);
	mpv_st->listen_alive = 0;

	rval = mpv_check_initial_value_reg(mpv_st);
	major = register_chrdev(0, MPV_NAME, &mpv_fops);
	if (major < 0) {
		pr_err("MPV-%d: major=%d <0\n", instance, major);
		return 1;
	}
	mpv_st->major	= major;
	raw_spin_lock_init(&mpv_st->mpv_lock);
	INIT_LIST_HEAD(&mpv_st->any_in_task_list);

	dbgmpv("%s inst. %d. polar= %x\n", __func__, instance, mpv_st->polar);
	raw_local_irq_save(flags);
#define CALIBR_IN	0
#define CALIBR_PERIOD	0xffffff	/* 8 ns * 2^24 = 128 ms */
#define WAIT_CALIBR	100
	if (mpv_new) {
		mpv_time_cnt0 = mpv_read_regl(mpv_st, MPV_REG_BASE_CNT);
		udelay(measure_time);
		mpv_time_cnt = mpv_read_regl(mpv_st, MPV_REG_BASE_CNT) -
			mpv_time_cnt0;
	} else {
		mpv_write_regl(mpv_st, MPV_REG_CHECK, 0);
		mpv_read_regl(mpv_st, MPV_REG_CHECK);
		mpv_write_regl(mpv_st, MPV_REG_CHECK, 0);
		udelay(measure_time);
		mpv_time_cnt = mpv_read_regl(mpv_st, MPV_REG_CHECK);
	}
	raw_local_irq_restore(flags);
	/* Picoseconds per corr.clock is culculated */
	if (mpv_time_cnt != 0) {
#if BITS_PER_LONG == 64
		mpv_st->psecs_per_corr_clck =
			((long long)measure_time * PSEC_PER_USEC) /
							mpv_time_cnt;
#else
		{unsigned long long long_res =
			(unsigned long long)measure_time * PSEC_PER_USEC;
			do_div(long_res, mpv_time_cnt);
			mpv_st->psecs_per_corr_clck = long_res;
		}
#endif
	} else {
		/* FIXME 40000 ? */
		pr_err("mpv_time_cnt == 0\n");
		mpv_st->psecs_per_corr_clck = mpv_new ? 40000 : 120000;
	}
	mpv_states[instance] = mpv_st;
	for (i = 0; i < mpv_st->num_in_bus; i++) {
		minor = MPV_MINOR(instance, MPV_IO_IN, i);
		(void)sprintf(name, "mpv_%d_in:%d", instance, i);
		device_create(mpv_class, NULL,
				  MKDEV(major, minor), NULL, name);
	};
	if (!mpv_new) {
		for (i = 0; i < MPV_NUM_OUT_INTR; i++) {
			minor = MPV_MINOR(instance, MPV_IO_OUT, i);
			(void)sprintf(name, "mpv_%d_out:%d", instance, i);
			device_create(mpv_class, NULL,
					  MKDEV(major, minor), NULL, name);
		};
		for (i = 0; i < MPV_NUM_OUT_STAT; i++) {
			minor = MPV_MINOR(instance, MPV_IO_OS, i);
			(void)sprintf(name, "mpv_%d_st:%d", instance, i);
			device_create(mpv_class, NULL,
					  MKDEV(major, minor), NULL, name);
		};
	}
	return 0;
}

static void __exit
mpv_common_remove(mpv_state_t *mpv_st)
{
	int		major = mpv_st->major;
	int		minor;
	char		name[64];
	int		i;
	int		instance = mpv_st->inst;

	unregister_chrdev(major, MPV_NAME);
	for (i = 0; i < mpv_st->num_in_bus; i++) {
		minor = MPV_MINOR(instance, MPV_IO_IN, i);
		(void)sprintf(name, "mpv_%d_in:%d", instance, i);
		device_destroy(mpv_class, MKDEV(mpv_st->major, minor));
	};
	if (mpv_st->mpv_new == MPV_KPI2) {
		mpv_write_regl(mpv_st, mpv_st->gen_mode_reg, 0xc0);
	} else if (mpv_st->mpv_new == MPV_4) {
		mpv_write_regl(mpv_st, mpv_st->gen_mode_reg, 0);
	} else {
		mpv_write_regl(mpv_st, mpv_st->gen_mode_reg, 0);
		for (i = 0; i < MPV_NUM_OUT_INTR; i++) {
			minor = MPV_MINOR(instance, MPV_IO_OUT, i);
			(void)sprintf(name, "mpv_%d_out:%d", instance, i);
			device_destroy(mpv_class, MKDEV(mpv_st->major, minor));
		};
		for (i = 0; i < MPV_NUM_OUT_STAT; i++) {
			minor = MPV_MINOR(instance, MPV_IO_OS, i);
			(void)sprintf(name, "mpv_%d_st:%d", instance, i);
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

	if (mpv_st == NULL) {
		pr_err("%s(): device instance = %d isn't loaded.\n",
			__func__, mpv_st->inst);
		return;
	}
	mpv_common_remove(mpv_st);
	iounmap(mpv_st->regs_base);
	if (mpv_st->mpv_new == MPV_KPI2) {
		bar = 1;
	}
	pci_release_region(pci_dev, bar);
	pci_set_drvdata(pci_dev, NULL);
	dbgmpv("inst. %d. %s: finished.\n", mpv_st->inst, __func__);
}

static int __init
mpv_pci_probe(struct pci_dev *pdev, const struct pci_device_id *pci_ent)
{
	mpv_state_t	*mpv_st = NULL;
	u8		mpv_new = 0;
	u8		revision_id;
	u16		vendor_id, devise_id;
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
		revision_id = 1;
	}
	pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor_id);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &devise_id);
	if (vendor_id == 0x1fff && devise_id == MPV4_DEVID) {
		mpv_new = MPV_4;
		revision_id = 0;
	}
	if (vendor_id == 0x1fff && devise_id == MPV_KPI2_DEVID) {
		pci_write_config_byte(pdev, GPIO_MPV_SW, 1);
		mpv_new = MPV_KPI2;
		bar = 1;
	}
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
		pr_err("%s(): Unable to map registers of %d instance\n",
			__func__, mpv_st->inst);
		return -EFAULT;
	}
	rval = mpv_common_probe(&mpv_st, regs_base, mpv_new, revision_id,
								PCI_DEV);
	if (rval) {
		goto err_unmap;
	}
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
		mpv_st->irq = IOHUB2_IRQ1;
		rval = request_threaded_irq(mpv_st->irq, &mpv_intr_handler,
			&mpv_threaded_handler,
			IRQF_DISABLED | IRQF_SHARED, MPV_NAME, (void *)mpv_st);
		if (rval) {
			pr_err("MPV-%d: Can't get irq %d, err [%d]\n",
				mpv_st->inst, mpv_st->irq, rval);

			goto err_unmap;
		}
		mpv_st->irq = IOHUB2_IRQ2;
		rval = request_threaded_irq(mpv_st->irq, &mpv_intr_handler,
			&mpv_threaded_handler,
			IRQF_DISABLED | IRQF_SHARED, MPV_NAME, (void *)mpv_st);
		if (rval) {
			pr_err("MPV-%d: Can't get irq %d, err [%d]\n",
				mpv_st->inst, mpv_st->irq, rval);

			goto err_unmap;
		}
	} else {
		rval = request_threaded_irq(mpv_st->irq, &mpv_intr_handler,
			&mpv_threaded_handler,
			IRQF_DISABLED | IRQF_SHARED, MPV_NAME, (void *)mpv_st);
		if (rval) {
			pr_err("MPV-%d: Can't get irq %d, err [%d]\n",
				mpv_st->inst, mpv_st->irq, rval);

			goto err_unmap;
		}
	}
#ifdef CONFIG_MCST_RT
	mk_hndl_first(mpv_st->irq, MPV_NAME);
#endif
	if (mpv_st->mpv_new == MPV_KPI2)
		pr_warning("MPV KPI-2:  DEV_ID=0x%x rev.id=0x%x drv.ver.%d "
			"IRQ 0=%d IRQ 1,2=%d "
			"picoseconds per counter clock = %d\n",
			MPV_KPI2_DEVID, mpv_st->revision_id, MPV_DRV_VER,
			IOHUB2_IRQ1, IOHUB2_IRQ2,
			mpv_st->psecs_per_corr_clck);
	else {
		if (mpv_st->mpv_new == MPV_4)
			dev_id = MPV4_DEVID;
		pr_warning("MPV DEV_ID=0x%x rev.id=0x%x drv.ver.%d attach: IRQ=%d (pirq=%d) "
			"picoseconds per counter clock = %d\n",
			dev_id, mpv_st->revision_id, MPV_DRV_VER,
			mpv_st->irq, pirq,
			mpv_st->psecs_per_corr_clck);
	}
	return 0;
err_unmap:
	_mpv_pci_remove(pdev, mpv_st);
	printk("%s(): inst. %d. finished with error.\n",
		__func__, mpv_st->inst);
	return -EFAULT;
}
static void __exit
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
		free_irq(IOHUB2_IRQ1, mpv_st);
		free_irq(IOHUB2_IRQ2, mpv_st);
	} else {
		free_irq(mpv_st->irq, mpv_st);
	}
	_mpv_pci_remove(pci_dev, mpv_st);
	dbgmpv("inst. %d. %s: finished.\n", mpv_st->inst, __func__);
}
#endif /* pci */

#if defined(CONFIG_MPV_MODULE) && \
	(defined(CONFIG_PCI2SBUS) || defined(CONFIG_PCI2SBUS_MODULE) || \
		defined(CONFIG_SBUS))
static int
__init mpv_sbus_probe(struct of_device *op,
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
	if (rev >= 0) {
		revision_id = rev;
	} else {
		u32 mpv_sbus_ver = (u32)readl(regs_base + MPV_SBUS_VER);
		pr_warning("%s() MPV_SBUS_VER=0x%04x\n", __func__,
			mpv_sbus_ver);
		if (mpv_sbus_ver >= 0x50000 && mpv_sbus_ver < 0xffffffff)
			revision_id  = 2;
		else
			revision_id  = 1;
	}
	rval = mpv_common_probe(&mpv_st, regs_base, 0, revision_id, SBUS_DEV);
	if (rval) {
		goto err_unmap;
	}

	dev_set_drvdata(&op->dev, (void *)mpv_st);
	mpv_st->conf_inter = 1 << (MPV_CPU_INTR - 2);
	mpv_write_regl(mpv_st, MPV_REG_CONFIG_INTR, mpv_st->conf_inter);
	config_intr = mpv_read_regl(mpv_st, MPV_REG_CONFIG_INTR);
	if (mpv_st->conf_inter != config_intr) {
		pr_warning("%s(): inst. %d. written in"
			"MPV_REG_CONFIG_INTR = 0x%x\n"
			"read from MPV_REG_CONFIG_INTR = 0x%x.\n", __func__,
			mpv_st->inst, mpv_st->conf_inter, config_intr);
		goto err_unmap;
	}
	dbgmpv("%s(): inst. %d. #conf. of interrupts installed = %d. %#x\n",
		__func__, mpv_st->inst, MPV_CPU_INTR, mpv_st->irq);
#if defined(CONFIG_PCI2SBUS) || defined(CONFIG_PCI2SBUS_MODULE)
	mpv_st->irq = ((op->irqs[0]>> 8) << 8) + MPV_CPU_INTR - 1;
	if (sbus_request_irq(mpv_st->irq, &mpv_intr_handler,
		&mpv_threaded_handler, IRQF_DISABLED | IRQF_SHARED,
		MPV_NAME, (void *)mpv_st)) {
		pr_err("MPV-%d: Can't get irq 0x%x\n", mpv_st->inst);
		goto err_unmap;
	}
#else	/* SBUS */
	mpv_st->irq = (op->irqs[0] & 0xff00) | (SBUS_IRQ_MIN + MPV_CPU_INTR);
	rval = request_threaded_irq(mpv_st->irq, &mpv_intr_handler,
			&mpv_threaded_handler, IRQF_DISABLED | IRQF_SHARED,
			MPV_NAME, (void *)mpv_st);
	if (rval) {
		pr_err("MPV-%d: Can't get irq %d, err [%d]\n",
			mpv_st->inst, mpv_st->irq, rval);
		goto err_unmap;
	}
#endif /* P2S */
	mpv_st->irq_orig = mpv_st->irq;
	pr_warning("MPV-sbus attach: sbusIRQ=%d revision_id=%x "
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
	pr_err("%s(): inst. %d. finished with error.", __func__, mpv_st->inst);
	return -EFAULT;
}

static int __exit
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
	dbgmpv("inst. %s: finished.\n", __func__);
	return 0;
}
#endif    /* pci2sbus  || sbus*/

static unsigned int
mpv_chpoll(struct file *file, struct poll_table_struct *wait)
{
	dev_t		dev = (dev_t)(long)file->private_data;
	mpv_state_t	*mpv_st = mpv_states[MPV_INST(dev)];
	int	intr;
	int	mask;
	unsigned long   flags;

	if ( mpv_st == NULL )
		return ENXIO;
	intr = MPV_BUS(dev);
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
	int		bus = MINOR( inode->i_rdev ) & 0x1f;
	int		disposal_bit;
	mpv_state_t	*mpv_st;
	dev_t		dev = inode->i_rdev;
	unsigned long	flags;

	if ( !dev ) {
		printk("%s(): !dev\n", __func__);
		return -EFAULT;
	}
	instance = MPV_INST(dev);
	mpv_st = mpv_states[instance];
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
				pr_err("inst. %d. "
					"mpv_open: attempt of opennig instance"
					"that already oppened exclusively.",
				    instance);
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
		dbgmpv( "inst. %d. mpv_open: external interrupts recieving bus = %d.\n",
				instance, bus);
	} else if (MPV_OUT(dev)) {
		if (mpv_st->open_out_excl) {
			pr_err("inst. %d.  mpv_open: attempt of opennig"
				"instance that already oppened exclusively.",
				instance);
			raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
			return -EBUSY;
		}
		mpv_st->open_out_excl = file->f_flags & O_EXCL;
		mpv_st->open_out = mpv_st->open_out | disposal_bit;
		dbgmpv( "inst. %d. mpv_open: outgoing interrupts sending bus = %d.\n",
				instance, bus);
	} else {
		if (mpv_st->open_st_excl) {
			pr_err("inst. %d. "
				"mpv_open: attempt of opennig instance that already oppened"
			    "exclusively.",
			    instance);
			raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
			return -EBUSY;
		}
		mpv_st->open_st_excl = file->f_flags & O_EXCL;
		mpv_st->open_st = mpv_st->open_st | disposal_bit;
		dbgmpv( "inst. %d. mpv_open: mpv bus = %d.\n",
				instance, bus);
	}
	raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
	file->private_data = (void *)(unsigned long)dev;
	dbgmpv( "inst. %d. mpv_open: finish.\n", instance);
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
	intr_user->num_reciv_intr[mpv_in] =
		mpv_st->kdata_intr[mpv_in].num_reciv_intr;
	intr_user->time_generation_intr[mpv_in] = mpv_st->time_gener_intr;
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
	int		disposal_bit;
	dev_t		dev = (dev_t)(long)file->private_data;
	int		bus = MPV_BUS(dev);
	mpv_rd_inf_t	uinf_read;
	int min_sz	= sizeof (mpv_rd_inf_t);
	int		corr_cnt = 0;
	int interrupts;
	unsigned long long clock_limit, prev_cycl;

	uinf_read.mpv_drv_ver = MPV_DRV_VER;
	dbgmpv("mpv_read: bus = %d:%d sz=%lld sizeof mpv_rd_inf=%lld.\n",
		MPV_INOUT(dev), bus, (long long)sz,
		(long long)sizeof(mpv_rd_inf_t));
	disposal_bit = 1 << bus;
	mpv_st = mpv_states[MPV_INST(dev)];
	if (mpv_st == NULL) {
		printk(	"mpv_read: device isn't loaded. bus=%d\n", bus);
		return (-ENXIO);
	};
	if (MPV_IN(dev)) {
		dbgmpv( "mpv_read: IN-bus = %d; start sz=%lld sizeof mpv_rd_inf=%lld.\n",
			bus, (long long)sz, (long long)sizeof (mpv_rd_inf_t));
		if (!(mpv_st->open_in & disposal_bit)) {
			dbgmpv( "mpv_read: file is closed\n");
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
			current->wakeup_tm = get_cycles();
			if (mpv_st->num_time_regs >= bus) {
				corr_cnt = mpv_read_regl(mpv_st,
						mpv_st->corr_cnt_reg[bus]);
/* It's expensive. Is it need?
				uinf_read.mpv_time_reg = mpv_read_regl(mpv_st,
						mpv_time_reg[bus]);
				uinf_read.intpts_cnt = mpv_read_regl(mpv_st,
						mpv_st->intpts_cnt_reg[bus]);
*/
			}
#ifdef CONFIG_MCST
			uinf_read.irq_enter_ns =
				cycles_2nsec(current->wakeup_tm - prev_cycl);
#endif
			uinf_read.intr_appear_nsec = 0;
			uinf_read.correct_counter_nsec = corr_cnt *
				mpv_st->psecs_per_corr_clck / 1000;
			mpv_st->non_oncpu_irq |= interrupts & ~disposal_bit;
			current->waken_tm = get_cycles();
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
			set_task_state(current, TASK_INTERRUPTIBLE);
			/* handler could mask this input if 'alive' */
			if (mpv_st->listen_alive & disposal_bit)
				mpv_write_regl(mpv_st, MPV_REG_MASK,
					mpv_read_regl(mpv_st, MPV_REG_MASK)
						| disposal_bit);
			raw_spin_unlock(&mpv_st->mpv_lock);
#ifdef CONFIG_MCST_RT
			if (rts_act_mask & RTS_POSTP_TICK &&
					mpv_st->kdata_intr[bus].period_ns) {
				do_postpone_tick(mpv_st->
					kdata_intr[bus].period_ns);
			}
#endif
			schedule();
			raw_spin_lock_irq(&mpv_st->mpv_lock);
			list_del(&wait_el.task_list);
			set_task_state(current, TASK_RUNNING);
			if (signal_pending(current)) {
				raw_spin_unlock_irq(&mpv_st->mpv_lock);
				return -EINTR;
			}
		}
		uinf_read.irq_enter_ns =
			cycles_2nsec(mpv_st->kdata_intr[bus].irq_enter_clks);
		uinf_read.correct_counter_nsec = mpv_st->kdata_intr[bus].correct_counter_nsec;
		if (mpv_st->mpv_new)
			uinf_read.mpv_time = mpv_st->kdata_intr[bus].mpv_time;
		uinf_read.intr_appear_nsec = mpv_st->kdata_intr[bus].intr_appear_nsec;
		uinf_read.num_reciv_intr = mpv_st->kdata_intr[bus].num_reciv_intr;
		uinf_read.time_generation_intr = mpv_st->time_gener_intr;
		if (bus < mpv_st->num_time_regs) {
			uinf_read.intpts_cnt = mpv_st->kdata_intr[bus].intpts_cnt;
			uinf_read.prev_time_clk = mpv_st->kdata_intr[bus].prev_time_clk;
		}
finish:
		if (list_empty(&mpv_st->kdata_intr[bus].wait1_task_list)
			&& list_empty(&mpv_st->any_in_task_list)
			&& !waitqueue_active(&mpv_st->pollhead))
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
		dbgmpv( "inst. mpv_read: mpv on bus = %d.\n", bus);
		st = !!(mpv_read_regl(mpv_st, MPV_REG_OUT_STAT) & disposal_bit);
		if (sz >= sizeof (int)){
			return copy_to_user((void *)buf, (void *)&st, sizeof (int)) ? -EFAULT : 0;
		} else {
			dbgmpv( "mpv_read: buf size =%lld; expected %lld\n",
				(long long)sz, (long long)sizeof (int));
		}
	};
	return (-EINVAL);
}

static	ssize_t
mpv_write (struct file *file, const char *buf, size_t sz, loff_t *f_pos)
{
	int		rval;
	mpv_state_t	*mpv_st;
	dev_t		dev = (dev_t)(long)file->private_data;
	int		bus;
	int		disposal_bit;
	unsigned long	flags;
	int st;

	bus = MPV_BUS(dev);
	disposal_bit = 1 << bus;
	dbgmpv( "mpv_write: bus = %d; start.\n", bus);
	mpv_st = mpv_states[MPV_INST(dev)];
	if (mpv_st == NULL) {
		return (-ENXIO);
	};
	rval = copy_from_user((void *)&st, (void *)buf, sizeof(int));
	if (rval != 0) {
		pr_err("mpv_write: copy_from_user() finished with error.");
		return -EFAULT;
	};
	if (MPV_OUT(dev)) {
		dbgmpv( "inst. mpv_write: external interrupt sending on bus = %d.\n", bus);
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
		dbgmpv( "inst. mpv_write: mpv on bus = %d.\n", bus);
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
	int		bus;
	int		disposal_bit;
	dev_t		dev = inode->i_rdev;
	unsigned long	flags;
	struct	list_head *tmp, *next;
	raw_wqueue_t	*waiter_item;

	bus = MPV_BUS(dev);
	mpv_st = mpv_states[MPV_INST(dev)];
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
			} else {
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
#ifdef CONFIG_MCST_RT
		if (mpv_st->kdata_intr[bus].period_ns) {
			do_postpone_tick(0);
		}
#endif
		mpv_write_regl(mpv_st, MPV_REG_MASK, mpv_st->open_in);
		mpv_st->kdata_intr[bus].correct_counter_nsec = 0;
		mpv_st->kdata_intr[bus].intr_appear_nsec = 0;
		mpv_st->kdata_intr[bus].prev_time_clk = 0;
		mpv_st->kdata_intr[bus].intpts_cnt = 0;
		mpv_st->kdata_intr[bus].interv_gen_ns = 0;
		mpv_st->kdata_intr[bus].period_ns = 0;
		mpv_st->kdata_intr[bus].wait_on_cpu = 0;
		dbgmpv("inst. mpv_close: external interrupts recieving bus = %d.\n", bus);
	} else if (MPV_OUT(dev)) {
		mpv_st->open_out_excl = 0;
		disposal_bit = 1 << bus;
		mpv_st->open_out = mpv_st->open_out & (~disposal_bit);
		dbgmpv( "inst. mpv_close: outgoing interrupts sending bus = %d.\n", bus);

	} else if (MPV_OS(dev)) {
		mpv_st->open_st_excl = 0;
		disposal_bit = 1 << bus;
		mpv_st->open_st = mpv_st->open_st & (~disposal_bit);
		dbgmpv( "mpv_close: mpvbus = %d.\n", bus);
	}
	mpv_st->time_gener_intr = 0;
	raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
	dbgmpvdetail( "mpv_close: finish.\n");
	return 0;
}

static long
mpv_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int		rval = 0;
	dev_t		dev = (dev_t)(long)file->private_data;
	int		bus = MPV_BUS(dev);
	int		disposal_bit = 1 << bus;
	int		instance = MPV_INST(dev);
	unsigned long 	flags;
	mpv_state_t	*mpv_st = mpv_states[instance];
	unsigned long long	interval;
	int		i;

	dbgmpv("%s cmd %d: inst. %d. bus = %d; start.\n", __func__,
		cmd & 0xff, instance, bus);

	if ( mpv_st == NULL ) {
		printk("%s(): device isn't loaded inst=%d bus=%d\n", __func__, MPV_INST(dev), MPV_BUS(dev));
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
#endif // CONFIG_MCST_SELF_TEST

			return 0;
	case MPVIO_SEND_INTR:
	{
		int current_out, reg_num;

		if (!MPV_OS(dev) && !MPV_OUT(dev)) {
			printk("mpv_ioctl (MPVIO_SEND_INTR): external "
				"interrupt sending to MPV_IN");
			return (-EINVAL);
		};
		dbgmpv( "inst. mpv_ioctl(MPVIO_SEND_INTR): external interrupt sending "
			"on bus = %d.\n", bus);
		if (arg) {
			unsigned long clock;
			clock = get_cycles();
			rval = copy_to_user((void *)arg, (void *)&clock, sizeof (clock));
			if (rval != 0) {
				printk( "inst. mpv_ioctl (MPVIO_SEND_INTR): copy_to_user() finish with "
               				"error.\n");
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
		dbgmpv( "inst. mpv_ioctl (MPVIO_SET_POLAR): external interrupts "
				"polarity bus = %d.\n", bus);
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
			printk( "inst. %d. "
				"mpv_ioctl (MPVIO_SET_STATE): outgoing state bus adjusting. MPV_OS|OUT(dev) = 0.\n",
				instance);
			return (-EINVAL);
		};
		dbgmpv( "mpv_ioctl (MPVIO_SET_STATE): outgoing mpvbus "
                				"is installed = %d.\n", bus);
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
			printk( "inst. mpv_ioctl: copy_from_user() finished with error." );
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
			pr_warning("MPVIO_SET_CONFIG_INTR: new irq=%d\n",
				mpv_st->irq);
			rval = request_threaded_irq(mpv_st->irq,
					&mpv_intr_handler,
					&mpv_threaded_handler,
					IRQF_DISABLED | IRQF_SHARED, MPV_NAME,
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
				pr_err("inst. mpv_ioctl: interrupt %d > 7\n",
					int_num);
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
					IRQF_DISABLED | IRQF_SHARED,
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
					IRQF_DISABLED | IRQF_SHARED,
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
				pr_warning("mpv_ioctl(MPVIO_SET_CONFIG_INTR):"
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
#if defined(CONFIG_MCST_RT) && defined(CONFIG_PCI)
		mk_hndl_first(mpv_st->irq, MPV_NAME);
#endif
		break;
	}
	case MPVIO_RUN_DEVICE:
	case MPVIO_CLEAR_OPTIONS:
		raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
		mpv_st->intr_assemble &= ~disposal_bit;
		mpv_st->kdata_intr[bus].num_reciv_intr = 0;
		mpv_st->listen_alive = 0;
		if (bus < mpv_st->num_time_regs) {
			mpv_st->kdata_intr[bus].correct_counter_nsec = 0;
			mpv_st->kdata_intr[bus].intr_appear_nsec = 0;
			mpv_st->kdata_intr[bus].prev_time_clk = 0;
			mpv_st->kdata_intr[bus].intpts_cnt = 0;
			mpv_st->kdata_intr[bus].interv_gen_ns = 0;
			mpv_st->kdata_intr[bus].period_ns = 0;
			mpv_st->kdata_intr[bus].wait_on_cpu = 0;
			mpv_write_regl(mpv_st, mpv_st->gen_period_reg[bus],
				(mpv_st->mpv_new) ?  0xffffffff : 0xfffff);
			mpv_write_regl(mpv_st, mpv_st->corr_cnt_reg[bus], 0);
			mpv_write_regl(mpv_st, mpv_st->intpts_cnt_reg[bus], 0);
			mpv_write_regl(mpv_st, mpv_st->prev_time_reg[bus], 0);
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
#ifdef CONFIG_MCST_RT
			if (rts_act_mask & RTS_POSTP_TICK &&
					mpv_st->kdata_intr[bus].period_ns) {
#ifdef CONFIG_FTRACE
				trace_printk("MPVCTL peri =%lld\n",
				    mpv_st->kdata_intr[bus].period_ns);
#endif
				do_postpone_tick(mpv_st->
					kdata_intr[bus].period_ns);
			}
#endif
			expire = schedule_timeout(
				usecs_to_jiffies(intr_user.intr_timeout));
			raw_spin_lock_irq(&mpv_st->mpv_lock);
			list_del(&wait_el.task_list);
			set_task_state(current, TASK_RUNNING);
			if (signal_pending(current)) {
				raw_spin_unlock_irq(&mpv_st->mpv_lock);
				return -EINTR;
			}
			if (!expire) {
				if (mpv_debug == 1) {
					pr_warning("MPVIO_WAIT_INTR:"
						"cv_timedwait_sig() waiting"
						"time is elapsed. (= %d).\n",
						 (int )intr_user.intr_timeout);
					pr_warning("mpv_ioctl (MPVIO_WAIT_INTR):"
						"mpv_st->intr_assemble = 0x%x.\n",
						mpv_st->intr_assemble);
				};
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
		if (mpv_st->mpv_new == MPV_4) {
			pr_err("%d ERROR mpv_ioctl(%s) old mpv only has"
				"MPV_RAW_IN register.\n",
				instance, cmd == MPVIO_GET_INTR
					? "GET_INTR" : "GET_INTR_ALL");
			return -EINVAL;
		};
		raw_spin_lock_irqsave(&mpv_st->mpv_lock, flags);
		state_in_ = mpv_read_regl(mpv_st, MPV_RAW_IN);
		raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);

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
		mpv_st->stv_in_number = ((int) arg >= 1) ? bus : -1;
		mpv_st->listen_alive &= ~disposal_bit;
		if ((int) arg >= 1) {
			dbg_max_atpt_getcor = 0;
			dbg_sum_atpt = 0;
			dbg_num_get_cc = 0;
			dbg_num_intr = 0;
			mpv_st->stv_in_number = bus;
			mpv_write_regl(mpv_st, MPV_REG_MASK,
				mpv_read_regl(mpv_st, MPV_REG_MASK)
					| (1<<mpv_st->stv_in_number));
			stv_num_msrms = 0;
			set_pps_stat2(STA_PPSTIME | STA_PPSFREQ);
		} else {
			set_pps_stat2(0);
			mpv_st->kdata_intr[bus].period_ns = 0;
			mpv_st->kdata_intr[bus].wait_on_cpu = 0;
			mpv_st->stv_in_number = -1;
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
#ifdef CONFIG_MCST_RT
			if (mpv_st->kdata_intr[bus].period_ns) {
				do_postpone_tick(0);
			}
#endif
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
		//long old_psecs = mpv_st->psecs_per_corr_clck;
		//printk("old_psecs =%ld new_psecs= %ld \n", old_psecs, new_psecs);
		//if (new_psecs && abs(new_psecs * 100 / old_psecs - 100) > 10) return -EINVAL;
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
				set_task_state(current, TASK_RUNNING);
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
				set_task_state(current, TASK_RUNNING);
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
#ifdef CONFIG_MCST_RT
			if (mpv_st->kdata_intr[bus].period_ns) {
				do_postpone_tick(0);
			}
#endif
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
		if (mpv_st->mpv_new != 1) {
			pr_err("MPVIO_SEND_ETHER is possible for mpv-iohub2 only\n");
			return -EINVAL;
		}
		if (ether_mode > 4) {
			pr_err("MPVIO_SEND_ETHER %d > 3\n", ether_mode);
			return -EINVAL;
		}
		if (ether_mode)
			mpv_write_regl(mpv_st, mpv_st->gen_mode_reg,
				(mpv_read_regl(mpv_st, mpv_st->gen_mode_reg) &
					0x3f) | (bus << 6));
		else
			mpv_write_regl(mpv_st, mpv_st->gen_mode_reg,
				(mpv_read_regl(mpv_st, mpv_st->gen_mode_reg) &
					0x3f) | (3 << 6));
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
	int		stv_intr = 0;
	unsigned long	flags;
	long long	irq_enter_clocks;
	raw_wqueue_t	*waiter_item;
	long long	corr_count_ns;
	struct	timespec intr_real_tm, stv_real_tm, stv_raw_tm;
	struct	timespec corr_tm = {0, 0};
	struct	list_head *tmp, *next;
	unsigned long long cycl1;
	int	read_cc_ns = 0, read_cc_stv_ns = 0;

#ifdef CONFIG_MCST
	irq_enter_clocks = get_cycles() - current_thread_info()->irq_enter_clk;
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
	for (i = 0; i < mpv_st->num_in_bus; i++) {
		if (!(interrupts & (1 << i)))
			continue;
		if (mpv_st->mpv_new)
			mpv_write_regl(mpv_st, MPV_RPV, 1 << i);
		if (mpv_st->kdata_intr[i].wait_on_cpu) {
			mpv_st->oncpu_irq |= (1 << i);
			continue;
		}
		if (mpv_st->stv_in_number == i) {
			getnstime_raw_and_real(&stv_raw_tm, &intr_real_tm);
			stv_intr = 1;
		} else {
			getnstimeofday(&intr_real_tm);
		}
		if (i < mpv_st->num_time_regs) {
			cycl1 = get_cycles();
			/* there is corr count reg in MPV */
			corr_count_ns =
				mpv_read_regl(mpv_st,
					mpv_st->corr_cnt_reg[i]) *
					mpv_st->psecs_per_corr_clck / 1000;
			read_cc_ns = (int)(cycles_2nsec(get_cycles() - cycl1));
			mpv_st->kdata_intr[i].correct_counter_nsec =
				(int)corr_count_ns;
			mpv_st->kdata_intr[i].read_cc_ns = (int)read_cc_ns;
			if (mpv_st->stv_in_number == i)
				read_cc_stv_ns = read_cc_ns;
			if (mpv_st->mpv_new == MPV_KPI2)
				mpv_st->kdata_intr[i].mpv_time =
					mpv_read_regl(mpv_st,
						mpv_st->mpv_time_reg[i]);
			if (unlikely(mpv_st->stv_in_number == i)) {
				corr_tm.tv_nsec = corr_count_ns;
				timespec_sub(stv_raw_tm, corr_tm);
				timespec_sub(intr_real_tm, corr_tm);
				stv_real_tm = intr_real_tm;
				mpv_st->kdata_intr[i].intr_appear_nsec =
				    timespec_to_ns(&intr_real_tm);
			} else {
				mpv_st->kdata_intr[i].intr_appear_nsec =
					    timespec_to_ns(&intr_real_tm) -
						    corr_count_ns;
			}
			mpv_st->kdata_intr[i].prev_time_clk =
				mpv_read_regl(mpv_st, mpv_st->prev_time_reg[i]);
		} else{ /* no time regs */
			mpv_st->kdata_intr[i].intr_appear_nsec =
			    timespec_to_ns(&intr_real_tm);
			stv_real_tm = intr_real_tm;
			read_cc_ns = 0;
			corr_count_ns = 0;
			mpv_st->kdata_intr[i].correct_counter_nsec = 0;
			mpv_st->kdata_intr[i].read_cc_ns = 0;
			if (mpv_st->stv_in_number == i)
				read_cc_stv_ns = 0;
		}
#ifdef CONFIG_MCST
		mpv_st->kdata_intr[i].irq_enter_clks = irq_enter_clocks;
#endif
		mpv_st->kdata_intr[i].intpts_cnt =
			mpv_read_regl(mpv_st, mpv_st->intpts_cnt_reg[i]);
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
#ifdef CONFIG_FTRACE
			trace_printk("MPVWUPpid %d\n", waiter_item->task->pid);
#endif
			wake_up_process(waiter_item->task);
		}
	};
	mpv_st->intr_assemble |= interrupts;
	/* wake up for ioctl(MPVIO_WAIT_INTR) -- any interrupt */
	list_for_each_safe(tmp, next, &mpv_st->any_in_task_list) {
		waiter_item = list_entry(tmp, raw_wqueue_t, task_list);
		wake_up_process(waiter_item->task);
	}
	raw_spin_unlock_irqrestore(&mpv_st->mpv_lock, flags);
#ifdef CONFIG_MCST_RT
	for (i = 0; i < mpv_st->num_in_bus; i++) {
		if ((interrupts & (1 << i)) &&
				mpv_st->kdata_intr[i].period_ns &&
				rts_act_mask & RTS_POSTP_TICK) {
#ifdef CONFIG_FTRACE
			trace_printk("MPVintHNDL cc=%d\n",
				mpv_st->kdata_intr[i].correct_counter_nsec);
#endif
			do_postpone_tick(mpv_st->kdata_intr[i].period_ns -
				mpv_st->kdata_intr[i].correct_counter_nsec);
		}
	}
#endif
#ifdef	CONFIG_NTP_PPS
	if (stv_intr) {
		if (read_cc_stv_ns < 10000 && corr_count_ns < 20000) {
			hardpps(&stv_real_tm, &stv_raw_tm);
		} else {
			pr_warning("MPV: at %ld s CorCnt rdur=%d val=%lld ns\n",
				intr_real_tm.tv_sec, read_cc_stv_ns,
				corr_count_ns);
		}
	}
#endif
	if (waitqueue_active(&mpv_st->pollhead))
		return IRQ_WAKE_THREAD;
	return IRQ_HANDLED;
}

static int
mpv_check_initial_value_reg(mpv_state_t	*mpv_st)
{
	int		i, r = 0;
	uint		rval;

	dbgmpv("%s() gen_mode_reg 0x%x=0x%x\n",
			__func__, mpv_st->gen_mode_reg,
			mpv_read_regl(mpv_st, mpv_st->gen_mode_reg));
	for (i = 0; i < mpv_st->num_time_regs; i++) {
		dbgmpv("%s() gen_period_reg[%d] \t0x%x =0x%x\n",
			__func__, i, mpv_st->gen_period_reg[i],
			mpv_read_regl(mpv_st, mpv_st->gen_period_reg[i]));
		dbgmpv("%s() intpts_cnt_reg[%d] \t0x%x =0x%x\n",
			__func__, i, mpv_st->intpts_cnt_reg[i],
			mpv_read_regl(mpv_st, mpv_st->intpts_cnt_reg[i]));
		dbgmpv("%s() corr_cnt_reg[%d] \t0x%x =0x%x\n",
			__func__, i, mpv_st->corr_cnt_reg[i],
			mpv_read_regl(mpv_st, mpv_st->corr_cnt_reg[i]));
		dbgmpv("%s() prev_time_reg[%d]  \t0x%x =0x%x\n",
			__func__, i, mpv_st->prev_time_reg[i],
			mpv_read_regl(mpv_st, mpv_st->prev_time_reg[i]));
		if (mpv_st->mpv_new)
			dbgmpv("%s() mpv_time[%d] 0x%x =0x%x base =0x%x\n",
				__func__, i, mpv_st->mpv_time_reg[i],
				mpv_read_regl(mpv_st, mpv_st->mpv_time_reg[i]),
				mpv_read_regl(mpv_st, 0x18));
	}
	rval = mpv_read_regl(mpv_st, MPV_REG_POLARITY);
	if (mpv_st->base_polar != rval) {
		pr_err("%s(): inst. %d. written in MPV_REG_POLARITY = 0x%x\n"
			"got from MPV_REG_POLARITY = 0x%x.\n",
			__func__, mpv_st->inst, mpv_st->base_polar, rval);
	}
	rval = mpv_read_regl(mpv_st, MPV_REG_MASK);
	if (mpv_st->mpv_new == MPV_KPI2)
		rval &= 0x7;
	if (mpv_st->mpv_new == MPV_4)
		rval &= 0xf;
	if (rval != 0) {
		printk( "inst. %d. "
        	"mpv_check_initial_value_reg.: after clearing "
		    "MPV_REG_MASK = 0x%x awaiting 0x%x.\n",
            mpv_st->inst,
            rval, 0);
	}
	if (!mpv_st->mpv_new) {
		for (i = 0; i < mpv_st->num_time_regs; i++) {
			rval = mpv_read_regl(mpv_st, mpv_st->corr_cnt_reg[i]);
			if (rval != 0) {
				printk("inst. %d. "
				"mpv_check_initial_value_reg.: after clearing "
				    "MPV_REG TIME INTER%d = 0x%x awaiting 0x%x.\n",
					    mpv_st->inst, i, rval, 0);
			}
		}
		rval = mpv_read_regl(mpv_st, MPV_REG_OUT_STAT);
		if (rval != 0) {
			printk("inst. %d. "
			"mpv_check_initial_value_reg.: after clearing "
			    "MPV_REG_OUT_STAT = 0x%x awaiting 0x%x.\n",
		    mpv_st->inst,
		    rval, 0);
		}
		rval = mpv_read_regl(mpv_st, MPV_REG_OUT_INTR);
		if (rval != 0) {
			r++;
			pr_err("inst. %d. "
				"mpv_check_initial_value_reg.: after clearing "
				"MPV_REG_OUT_INTR = 0x%x awating 0x%x\n",
				mpv_st->inst, rval, 0);
		}
	}
	if (r != 0) {
		pr_err("inst. %d. mpv_check_initial_value_reg.:"
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
		printk("%s: inst. %d. interrupts = 0x%x != 0\n",
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
				mpv_write_regl(mpv_st,
					mpv_st->prev_time_reg[i], 0);
			}
	}
	mpv_write_regl(mpv_st, MPV_REG_MASK, 0);
	dbgmpv("%s(): write MPV_IN_MASK=0x%x  in MPV_REG_POLARITY=0x%x\n",
		__func__, MPV_IN_MASK, MPV_REG_POLARITY);
	dbgmpv("%s(): write 0 in MPV_REG_MASK 0x%x\n", __func__, MPV_REG_MASK);
	dbgmpv( "inst. %d. "
		"mpv_reset_module: device registers are now in initial state.\n",
		mpv_st->inst);
}
module_param(rev, int, 0444);
module_init(mpv_init);
module_exit(mpv_exit);
MODULE_AUTHOR("Copyright by MCST 2008");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MPV driver");
