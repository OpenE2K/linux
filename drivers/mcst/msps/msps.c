#include <asm/io.h>
#include <asm/uaccess.h>

#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/cdev.h>
#include <linux/ioctl.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>

#include <asm/e2k.h>
#include <asm/sic_regs.h>

/* /proc/sys/debug/msps_debug trigger */
int msps_debug = 0;

#include "msps.h"

#define MSPS_VERSION "0.0.4.03"

#ifdef CONFIG_MSPS_MODULE

#include <linux/audit.h>
#include <linux/err.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/security.h>

#endif

//#define _PRINT_IOAPIC_REGS_ /* for special kernel with export: print_IPs() */

#define MSPS_PRINT_FULL_REGS_OFF	/* for on - remove suffix _OFF */
#define MSPS_SWITCH_BUFFER_OFF		/* for on - remove suffix _OFF */
#define MSPS_FILL_DBG_MODE_OFF		/* for on - remove suffix _OFF */

#define MSPS_USING_IRQ

#define __USE_PROC__

#define MCST_INCLUDE_IOCTL
#ifdef MCST_INCLUDE_IOCTL
#include <linux/mcst/mcst_selftest.h>
#endif


#define MSPS_WAIT	0
#define MSPS_NON_WAIT	1
#define MSPS_USER	1

/* Globals */

#define MSPS_NUMBERS	64
#define MSPS_PCI_BAR	0x5

static char		msps_dev_name[] = "MCST,msps";
static const char	msps_fs_dev_name[] = "msps"; /*for mknod*/
#ifndef MSPS_MAJOR
#define MSPS_MAJOR 45
#endif
static int		major = MSPS_MAJOR;
static msps_dev_t	*msps_devices[MAX_MSPS] = {0}; /* all devices */
static unsigned long	phys_addr; /* phys mem */
static unsigned char	*base_addr = NULL; /* virt mem */
static unsigned long	pci_src_len;
static int		irq;
static struct cdev	cdev;
static int		msps_probe_result = 0; /* if < 0 - driver unregister */

#define UDEV_ON
#undef UDEV_ON
#ifdef UDEV_ON
static struct class	*msps_class;
#endif

SPINLOCK_T		dma_lock;

/********************/
msps_hrtime_t msps_gethrtime(void) {
	struct timeval tv;
	msps_hrtime_t retval;

	do_gettimeofday(&tv);

	retval = (msps_hrtime_t)((msps_hrtime_t)tv.tv_sec * 1000000000l)
		+ (msps_hrtime_t)((msps_hrtime_t)tv.tv_usec * 1000);

	return retval;
}
/******************/


MODULE_AUTHOR     ("Alexey A. Mukhin");
MODULE_LICENSE    ("GPL");
MODULE_DESCRIPTION("driver for MSPS v. " MSPS_VERSION);

static const struct pci_device_id msps_pci_table[] = {
	{
		.vendor	= PCI_VENDOR_ID_MSPS,
		.device	= PCI_DEVICE_ID_MSPS,
		.class	= 0x118000, /* get from developers */
	},
	{0, }
};

MODULE_DEVICE_TABLE (pci, msps_pci_table);


static struct pci_driver msps_driver = {
	.name	= msps_dev_name,
	.id_table = msps_pci_table,
	.probe	= msps_probe_pci,
	.remove	= msps_remove_one,
};

#if defined(CONFIG_SYSCTL)
#include <linux/sysctl.h>

static ctl_table msps_table[] = {
	{
		.procname	= "msps_debug",
		.data		= &msps_debug,
		.maxlen		= sizeof(msps_debug),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static ctl_table msps_root_table[] = {
	{
		.procname	= "debug",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= msps_table,
	},
	{ }
};

static struct ctl_table_header *msps_sysctl_header;

static void __init msps_sysctl_register(void)
{
	msps_sysctl_header = register_sysctl_table(msps_root_table);
}

static void msps_sysctl_unregister(void)
{
	if (msps_sysctl_header)
		unregister_sysctl_table(msps_sysctl_header);
}

#else /* CONFIG_SYSCTL */

static void __init msps_sysctl_register(void)
{
}

static void msps_sysctl_unregister(void)
{
}
#endif

#ifdef __USE_PROC__
#ifndef CONFIG_PROC_FS

static int create_msps_proc(void)
{
	return 0;
}

static void remove_msps_proc(void)
{
}

#else

struct proc_dir_entry *msps_proc_entry = NULL;

static ssize_t
msps_read_proc(struct file *file, char __user *buf, size_t count, loff_t *off)
{
	int i = 0;
#if DEBUG_MODE
	int j = 0;
#endif
	ssize_t len = 0;
	char tmpstr[256];
	msps_dev_t *dev = NULL;

	snprintf(tmpstr, 256, "MSPS driver info (v. %s):\n", MSPS_VERSION);
	if ((strlen(tmpstr) + len) > count)
		goto end_proc;
	if (copy_to_user(buf + len, &tmpstr, strlen(tmpstr)))
		return -EFAULT;
	len += strlen(tmpstr);

	if (msps_debug) {
		snprintf(tmpstr, 256, "Debug print mode: ON.\n");
		if ((strlen(tmpstr) + len) > count)
			goto end_proc;
		if (copy_to_user(buf + len, &tmpstr, strlen(tmpstr)))
			return -EFAULT;
		len += strlen(tmpstr);
	}

#if ERROR_MODE == 0
	snprintf(tmpstr, 256, "Driver was compiled without ERROR print !\n");
	if ((strlen(tmpstr) + len) > count)
		goto end_proc;
	if (copy_to_user(buf + len, &tmpstr, strlen(tmpstr)))
		return -EFAULT;
	len += strlen(tmpstr);
#endif

#if DEBUG_MODE
	snprintf(tmpstr, 256, "Driver was compiled with DEBUG print.\n");
	if ((strlen(tmpstr) + len) > count)
		goto end_proc;
	if (copy_to_user(buf + len, &tmpstr, strlen(tmpstr)))
		return -EFAULT;
	len += strlen(tmpstr);
#endif

#if DEBUG_DETAIL_MODE
	snprintf(tmpstr, 256, "Driver was compiled with DETAIL DEBUG print.\n");
	if ((strlen(tmpstr) + len) > count)
		goto end_proc;
	if (copy_to_user(buf + len, &tmpstr, strlen(tmpstr)))
		return -EFAULT;
	len += strlen(tmpstr);
#endif

#ifndef __ALL_ONLINE_NODE__
	snprintf(tmpstr, 256,
		 "All nodes (except zero-node) are off manually in driver.\n");
	if ((strlen(tmpstr) + len) > count)
		goto end_proc;
	if (copy_to_user(buf + len, &tmpstr, strlen(tmpstr)))
		return -EFAULT;
	len += strlen(tmpstr);
#endif

	snprintf(tmpstr, 256,
		 "major:\t%d\n"
		 "irq:\t%d\n"
		 "pci phys area: 0x%x\n"
		 "pci mmap area: 0x%x\n",
		 major, irq, phys_addr, BASE);
	if ((strlen(tmpstr) + len) > count)
		goto end_proc;
	if (copy_to_user(buf + len, &tmpstr, strlen(tmpstr)))
		return -EFAULT;
	len += strlen(tmpstr);
	for (i = 0; i < MAX_MSPS; i++) {
		dev = msps_devices[i];
		if (dev != NULL) {
			snprintf(tmpstr, 256,
				 "\ndevice for %s data\n",
				 "minor:\t\t%d\n"
				 "present:\t%s\n"
				 "opened:\t\t%s\n"
				 "mknod /dev/%s%d c %d %d\n",
				 (i%2) ? "output" : " input",
				 dev->minor,
				 dev->present ? "yes" : "no",
				 dev->open ? "yes" : "no",
				 msps_fs_dev_name, dev->minor,
				 major, dev->minor);
			if ((strlen(tmpstr) + len) > count)
				goto end_proc;
			if (copy_to_user(buf + len, &tmpstr, strlen(tmpstr)))
				return -EFAULT;
			len += strlen(tmpstr);
#if DEBUG_MODE
			for (j = 0; j < 2; j++) {
				snprintf(tmpstr, 256,
					 "\tDMA channel %d: virt 0x%p, "
					 "phys 0x%lx size %d rsize %d\n",
					 j,
					 dev->dma.mem[j].virt,
					 dev->dma.mem[j].phys,
					 dev->dma.mem[j].size,
					 dev->dma.mem[j].real_size);
				if ((strlen(tmpstr) + len) > count)
					goto end_proc;
				if (copy_to_user(buf + len, &tmpstr, strlen(tmpstr)))
					return -EFAULT;
				len += strlen(tmpstr);
			}
#endif
		}
	}

	snprintf(tmpstr, 256, "\n");
	if ((strlen(tmpstr) + len) > count)
		goto end_proc;
	if (copy_to_user(buf + len, &tmpstr, strlen(tmpstr)))
		return -EFAULT;
	len += strlen(tmpstr);

end_proc:
	*off += len;
	return len;
}

static ssize_t
msps_write_proc(struct file *file, const char __user *buf,
	       size_t count, loff_t *off)
{
	return -ENODEV;
}

static unsigned int msps_poll_proc(struct file *file, poll_table *wait)
{
	return POLLERR;
}

static int msps_open_proc(struct inode *inode, struct file *file)
{
	return nonseekable_open(inode, file);
}

static int msps_close_proc(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations msps_proc_fops = {
	.owner   = THIS_MODULE,
	.llseek  = no_llseek,
	.read    = msps_read_proc,
	.write   = msps_write_proc,
	.poll    = msps_poll_proc,
	.open    = msps_open_proc,
	.release = msps_close_proc
};

static int create_msps_proc(void)
{
	msps_proc_entry = proc_create("driver/msps", 0, NULL, &msps_proc_fops);
	if (!msps_proc_entry) {
		return 0;
	}
	return 1;
}

static void remove_msps_proc(void)
{
	if (msps_proc_entry) {
		remove_proc_entry("driver/msps", NULL);
		msps_proc_entry = NULL;
	}
}

#endif /* CONFIG_PROC_FS */
#endif /* __USE_PROC__ */

#define MY_VM_RESERVED	(VM_DONTEXPAND | VM_DONTDUMP)

static int msps_mmap(struct file *filp, struct vm_area_struct *vma)
{

	msps_dev_t	*dev;
	unsigned long	 off;
	dma_addr_t	 phys;
	dma_addr_t	 *virt;
	int		 choice;
	int		pminor;
#ifdef MSPS_FILL_DBG_MODE
	unsigned char	*tmpbuf;
	int i; /* for dbg */
#endif

	dev = (msps_dev_t *)filp->private_data;
	pminor = dev->minor;

	off = vma->vm_pgoff << PAGE_SHIFT;

	vma->vm_pgoff = 0;
	vma->vm_flags |= (VM_READ | VM_WRITE | VM_IO | MY_VM_RESERVED);
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	switch (off) {
		/* remap read DMA buffer to user */
	case MSPS_DMA_MMAP_0:
		phys = dev->dma.mem[0].phys;
		virt = dev->dma.mem[0].virt;

#ifdef MSPS_FILL_DBG_MODE
		tmpbuf = (unsigned char *)dev->dma.mem[0].virt;
		for (i = 0; i < MSPS_DMA_SIZE; i++) {
			tmpbuf[i] = 0x10;
		}
#endif
		choice = 1;
		break;
	case MSPS_DMA_MMAP_1:
		phys = dev->dma.mem[1].phys;
		virt = dev->dma.mem[1].virt;

#ifdef MSPS_FILL_DBG_MODE
		tmpbuf = (unsigned char *)dev->dma.mem[1].virt;
		for (i = 0; i < MSPS_DMA_SIZE; i++) {
			tmpbuf[i] = 0x21;
		}
#endif
		choice = 2;
		break;
	default:
		ERROR_PRINT("mmap:\terror mmap page choice\n");
		return -EAGAIN;
		break;
	}

	DETAIL_PRINT("mmap:\tMSPS_DMA_MMAP: "
		     "vm_off [%d]  0x%p, off 0x%lx >> 0x%lx\n",
		     choice,
		     virt,
		     phys,
		     phys >> PAGE_SHIFT);

	if ( remap_pfn_range(vma,
			     vma->vm_start,
			     phys >> PAGE_SHIFT,
			     MSPS_DMA_SIZE,
			     vma->vm_page_prot) < 0)
	{
		ERROR_PRINT("mmap:\terror mmap DMA memory to user\n");
		return -EAGAIN;
	}

	return 0;
}


/*
 * write bit 24 in register MSPS_TEST
 * after reset done - bit 24 must be 0x0
 * we wait that
 * warning: must be mutex external
 */
int msps_reset_channels()
{
	volatile union test_register test;
	int dbg_count = 0;
	test.b.reset = 1;
	SET_MSPS_REG(MSPS_TEST, test.r);
	while (test.b.reset != 0 && dbg_count < 999999) {
		test.r = GET_MSPS_REG(MSPS_TEST);
		dbg_count++;
	}
	return dbg_count;
}


/*
 * reset 3 registers and all channels
 */
int msps_reset(msps_dev_t *dev)
{
	int dbg_count;
	int pminor, i;
	unsigned int treg;
	pminor = dev->minor;
	/* warning: !!!
	   stop DMA exchange at all channels
	*/
	MLOCK(&dev->mutex);
	SET_MSPS_REG(MSPS_LCTL, 0x0);
	treg = GET_MSPS_REG(MSPS_INTR);
	for (i = 0; i < MAX_MSPS; i++) {
		SET_MSPS_REG(MSPS_C(i), 0x0);
	}
	dbg_count = msps_reset_channels();
	SET_MSPS_REG(MSPS_TEST, 0);
	MUNLOCK(&dev->mutex);

	DBG_PRINT("MSPS_RESET (%d) [0x%x]\n",
		dbg_count, treg);
	return 0;
}


/*
 * stoped target DMA exchange
 */
void msps_stop_dma(u_int chn_num)
{
	volatile union lctl_byte lbyte;
	lbyte.r = GET_MSPS_REG_B(MSPS_LCTL, PAIR_NUMBER(chn_num));
	if (chn_num%2) {
		lbyte.b.chn1 = 0;
	} else {
		lbyte.b.chn0 = 0;
	}
	SET_MSPS_REG_B(MSPS_LCTL, PAIR_NUMBER(chn_num), lbyte.r);
	SET_MSPS_REG(MSPS_C(chn_num), 0);
	msps_devices[chn_num]->dma.start = 0;
}


static unsigned int msps_poll(struct file *filp, struct poll_table_struct *wait)
{
	msps_dev_t	*dev;
	unsigned int	mask = 0;
	int		pminor;

	dev = (msps_dev_t *)filp->private_data;
	pminor = dev->minor;

	MLOCK(&dev->mutex);

	if (dev->dma.done) {
		DBG_PRINT("poll - dma done\n");
		dev->poll_flag = 0;
		if (dev->minor == 1 || dev->minor == 3 || dev->minor == 5)
			mask |= POLLOUT;
		else
			mask |= POLLIN;
		dev->dma.e = msps_gethrtime();
		dev->dma.wtime = (dev->dma.e - dev->dma.s)/1000;
	} else {
		if (dev->poll_flag) {
			DBG_PRINT("poll timeout\n");
			dev->poll_flag = 0;
			SLOCK(&dma_lock);
			dev->dma.done = MSPS_DMA_TIMEOUT;
			msps_stop_dma(dev->minor);
			SUNLOCK(&dma_lock);

			dev->dma.e = msps_gethrtime();
			dev->dma.wtime = (dev->dma.e - dev->dma.s)/1000;
		} else {
			DBG_PRINT("poll wait\n");
			dev->poll_flag = 1;
		}
	}

	MUNLOCK(&dev->mutex);

	if (mask == 0)
		poll_wait(filp, &dev->dma.wait_queue, wait);

	DBG_PRINT("msps: poll: mask - %d, flag %d\n", mask, dev->poll_flag);

	return mask;
}


static int msps_open(struct inode *inode, struct file *filp)
{
	msps_dev_t	*dev;
	int		minor = MINOR(inode->i_rdev);
	int		pminor;
	pminor = minor;

	dev = (msps_dev_t *)filp->private_data;
	if (!dev) {
		dev = msps_devices[minor];
		if (dev->present) {
			if (dev->open) {
				WARNING_PRINT("open:\tre-open device\n");
				return -EBUSY;
			} else {
				dev->open = 1;
			}

			filp->private_data = dev;
		} else {
			WARNING_PRINT("open:\tdevice is absent\n");
			return -EBUSY;
		}
	}

	DBG_PRINT("open.\n");

	return 0;
}

static int msps_release(struct inode *inode, struct file *filp)
{
	msps_dev_t *dev;
	int pminor;
	dev = (msps_dev_t *)filp->private_data;
	pminor = dev->minor;
	SLOCK(&dma_lock);
	if (dev->dma.start) {
		dev->dma.done = MSPS_DMA_ABORT;
		msps_stop_dma(dev->minor);
	}
	SUNLOCK(&dma_lock);
	dev->open = 0;
	DBG_PRINT("close.\n");

	return 0;
}


static ssize_t msps_read(struct file *filp, char *buf,
			 size_t count, loff_t *f_pos)
{
	msps_dev_t *dev;
	int pminor;
	dev = (msps_dev_t *)filp->private_data;
	pminor = dev->minor;
	WARNING_PRINT("read[%d]: Read not implemented.\n", dev->minor);
	return -EINVAL;
}


static ssize_t msps_write(struct file *filp, const char *buf,
			  size_t count, loff_t *f_pos)
{
	msps_dev_t *dev;
	int pminor;
	dev = (msps_dev_t *)filp->private_data;
	pminor = dev->minor;
	WARNING_PRINT("write[%d]: Write not implemented.\n", dev->minor);
	return -EINVAL;
}


static int msps_exchange(int who, msps_setup_t *task, int *time,
			 int non_wait, int user_flag)
{
	volatile union lctl_register lctl;
	union lctl_register reg_lctl;
	union intr_register reg_intr;
	volatile union lctl_byte lbyte;
	volatile union lctl_byte lext;
	u_int chn_num = 0, size = 0, size_in_words = 0, dec = 0;
	u_long t_count = 0;
	u_long reg = 0;
	dma_pool_t *dma;
	int ret = 0;
	int pminor;

	msps_dev_t *dev = msps_devices[who];

	pminor = dev->minor;

	if (time == NULL)
		DETAIL_PRINT("exchange with interrupt.\n");
	else
		DETAIL_PRINT("exchange without interrupt.\n");

	if (non_wait)
		DETAIL_PRINT("exchange without waiting: minor: %d.\n", who);

	dev->dma.key = task->key; /* for dbg */

	/* setup cfg */
	size = task->size;
	if (task->size > MSPS_DMA_SIZE)
		size = MSPS_DMA_SIZE;

	chn_num = dev->minor;
	dma = &dev->dma;
	dma->mem[dma->buffer].user_size = size;

	if (size%4) dec++;
	size_in_words = size/4 + dec;

	task->status.state = 1;

	task->status.size = size;
	task->status.buffer = dma->buffer;

	MLOCK(&dev->mutex);

#if DEBUG_MODE
	reg = GET_MSPS_REG(MSPS_II(chn_num));
	DETAIL_PRINT("register II%d before write: 0x%x\n", chn_num, reg);
#endif

	/* set buf address */
	SET_MSPS_REG(MSPS_II(chn_num), dma->mem[dma->buffer].phys);

#if DEBUG_MODE
	reg = GET_MSPS_REG(MSPS_II(chn_num));
	DETAIL_PRINT("register II%d  after write: 0x%x\n", chn_num, reg);
#endif


#ifdef MSPS_SWITCH_BUFFER
	/* switch buffers for get data */
	if (dma->buffer)
		dma->buffer = 0;
	else
		dma->buffer = 1;
#endif

	SET_MSPS_REG(MSPS_C(chn_num), 0);
#if DEBUG_MODE
	reg = GET_MSPS_REG(MSPS_C(chn_num));
	DETAIL_PRINT("register C%d before write: 0x%x, siw: 0x%x\n",
		     chn_num,
		     reg,
		     size_in_words);
#endif

	/* set size */
	SET_MSPS_REG(MSPS_C(chn_num), size_in_words);

#if DEBUG_MODE
	reg = GET_MSPS_REG(MSPS_C(chn_num));
	DETAIL_PRINT("register C%d  after write: 0x%x\n", chn_num, reg);
#endif

	/* start exchange */
	dma->done = 0;
	SLOCK(&dma_lock);

	if (user_flag) {
		dma->start = dev->dma.rele;
		if (dev->dma.rele == 1)
			dev->dma.rele = 2;
		else
			dev->dma.rele = 1;
	}

	lctl.r = GET_MSPS_REG(MSPS_LCTL);
	lbyte.r = GET_MSPS_REG_B(MSPS_LCTL, PAIR_NUMBER(chn_num));
	lext.r = GET_MSPS_REG_B(MSPS_LCTL, MSPS_LCTL_EXT);

#if DEBUG_MODE
	DETAIL_PRINT("get resgister lctl: %d 0x%x (%x %x %x %x %x %x) b: %x e: %x\n",
		     dev->minor, lctl.r,
		     lctl.b.chn0, lctl.b.chn1, lctl.b.chn2,
		     lctl.b.chn3, lctl.b.chn4, lctl.b.chn5,
		     lbyte.r, lext.r);
#endif

	if (chn_num%2)
		lbyte.b.chn1 = MSPS_START_DMA;
	else
		lbyte.b.chn0 = MSPS_START_DMA;

	if (task->extended_flag)
		lext.r |= (1 << chn_num);
	else
		lext.r &= ~(1 << chn_num);

	SET_MSPS_REG_B(MSPS_LCTL, MSPS_LCTL_EXT, lext.r);
	SET_MSPS_REG_B(MSPS_LCTL, PAIR_NUMBER(chn_num), lbyte.r);
	SUNLOCK(&dma_lock);

#if DEBUG_MODE
	lctl.r = GET_MSPS_REG(MSPS_LCTL);
	lbyte.r = GET_MSPS_REG_B(MSPS_LCTL, PAIR_NUMBER(chn_num));
	lext.r = GET_MSPS_REG_B(MSPS_LCTL, MSPS_LCTL_EXT);

	DETAIL_PRINT("set resgister lctl: %d 0x%x (%x %x %x %x %x %x) b: %x e: %x\n",
		     dev->minor, lctl.r,
		     lctl.b.chn0, lctl.b.chn1, lctl.b.chn2,
		     lctl.b.chn3, lctl.b.chn4, lctl.b.chn5,
		     lbyte.r, lext.r);
#endif

	dma->s = msps_gethrtime();

	if (non_wait) {
		MUNLOCK(&dev->mutex);
		task->status.state = 0;
		goto end_exch;
	}

	if (time != NULL) {
		int work = 1;
		dma->done = MSPS_DMA_DONE;
		DETAIL_PRINT("time wait: %ld microseconds\n", *time);
		dma->s = msps_gethrtime();
		do {
			lbyte.r = GET_MSPS_REG_B(MSPS_LCTL, PAIR_NUMBER(chn_num));
			if (chn_num%2)
				work = lbyte.b.chn1 & MSPS_START_DMA;
			else
				work = lbyte.b.chn0 & MSPS_START_DMA;

			dma->e = msps_gethrtime();
			reg = GET_MSPS_REG(MSPS_C(chn_num));
			t_count++;
			if (t_count > 999999 || ((dma->e - dma->s)/1000) >= *time) {
				dma->done = MSPS_DMA_TIMEOUT;
				break;
			}
		} while (work);
		dma->e = msps_gethrtime();
	} else {
		int r;
		long timeout = 0;
		int needed_print = 0;

		while (dma->done == 0) {
			MUNLOCK(&dev->mutex);

			dma->twice = 0;
			/*
			 * I assume that timeout is set in microseconds,
			 * but not know how correct
			 * translate it for wait..interruptible()
			 * let it be as it is
			 */
			if (task->timeout > 0) {
				timeout = task->timeout;
				DBG_PRINT("waiting interrupt and timeout: %d\n", timeout);
				r = wait_event_interruptible_timeout(dma->wait_queue, (dma->done != 0), timeout/10);
			} else {
				DBG_PRINT("waiting only interrupt\n");
				r = wait_event_interruptible(dma->wait_queue, dma->done);
			}

			SLOCK(&dma_lock);
			reg = GET_MSPS_REG(MSPS_C(chn_num));
			reg_lctl.r = GET_MSPS_REG(MSPS_LCTL);
			SUNLOCK(&dma_lock);

			if (r == 0 && timeout) {
				needed_print = 1;
				SLOCK(&dma_lock);
				/* ATTETNTION: this read cleared ALL bits */
				reg_intr.r = GET_MSPS_REG(MSPS_INTR);
				dma->done = MSPS_DMA_TIMEOUT;
				msps_stop_dma(chn_num);
				SUNLOCK(&dma_lock);
				DBG_PRINT("timeout was reached: %d\n", timeout);
				ret = -ETIMEDOUT;
			} else if (r == -ERESTARTSYS && dma->done == 0) {
				needed_print = 1;
				SLOCK(&dma_lock);
				/* ATTETNTION: this read cleared ALL bits */
				reg_intr.r = GET_MSPS_REG(MSPS_INTR);
				dma->done = MSPS_DMA_ABORT;
				msps_stop_dma(chn_num);
				SUNLOCK(&dma_lock);
				DBG_PRINT("get other interrupt\n");
				ret = -ERESTARTSYS;
			}

			if (needed_print) {
				needed_print = 0;
				unsigned int ii;
				int start[MAX_MSPS];
				int key[MAX_MSPS];

				for (ii = 0; ii < MAX_MSPS; ii++) {
					start[ii] = msps_devices[ii]->dma.start;
					key[ii] = msps_devices[ii]->dma.key;
				}

#ifdef _PRINT_IOAPIC_REGS_
				/* for print IOAPIC registers */
				DBG_PRINT("must be print IOAPIC\n");
				print_ICs();
#endif

#if DEBUG_MODE
				DBG_PRINT("**********: lctl: 0x%x intr: 0x%x\n"
					  "       [0 1 2 3 4 5]\n"
					  "start: [%d %d %d %d %d %d]\n"
					  "key  : {%4d %4d %4d %4d %4d %4d}\n",
					  reg_lctl.r, reg_intr.r,
					  start[0], start[1], start[2],
					  start[3], start[4], start[5],
					  key[0], key[1], key[2],
					  key[3], key[4], key[5]);
#endif
			}
			MLOCK(&dev->mutex);
		}
		t_count = 0;
		dma->e = msps_gethrtime();
	}

	dma->start = 0;

	MUNLOCK(&dev->mutex);

#if DEBUG_MODE
	lctl.r = GET_MSPS_REG(MSPS_LCTL);
	lbyte.r = GET_MSPS_REG_B(MSPS_LCTL, PAIR_NUMBER(chn_num));
	lext.r = GET_MSPS_REG_B(MSPS_LCTL, MSPS_LCTL_EXT);
	DETAIL_PRINT("register C%d  after  work: 0x%x\n", chn_num, reg);
	DETAIL_PRINT("end resgister lctl: %d 0x%x (%x %x %x %x %x %x) b: %x e: %x\n",
		     dev->minor, lctl.r,
		     lctl.b.chn0, lctl.b.chn1, lctl.b.chn2,
		     lctl.b.chn3, lctl.b.chn4, lctl.b.chn5,
		     lbyte.r,
		     lext.r);
#endif

	task->status.state = dma->done;
	dma->wtime = (dma->e - dma->s)/1000;
	task->status.wtime = dma->wtime;
	task->status.Cx = reg; /* only for dbg */
	task->status.Lctl = reg_lctl.r; /* only for dbg */
	task->status.Intr = reg_intr.r; /* only for dbg */
	task->status.twice = dma->twice;
	dma->twice = 0;
	if (time != NULL)
		*time = (int)((dma->e - dma->s)/1000000);

	DETAIL_PRINT("%s: count: %03ld, %ld nanosec, buf: %d size: %d\n",
		     __func__,
		     t_count,
		     dma->e - dma->s,
		     task->status.buffer,
		     task->status.size);

	DETAIL_PRINT("mem 0: [0x%016lx 0x%016lx]\n",
		     *((u64 *)(dma->mem[0].virt + 0)),
		     *((u64 *)(dma->mem[0].virt + 1)));
	DETAIL_PRINT("mem 1: [0x%016lx 0x%016lx]\n",
		     *((u64 *)(dma->mem[1].virt + 0)),
		     *((u64 *)(dma->mem[1].virt + 1)));
	/*
	DETAIL_PRINT("mem: {0x%lx 0x%lx}\n",
		     __cpu_to_be64(*((u64 *)(dma->mem[dma->buffer].virt + 0))),
		     __cpu_to_be64(*((u64 *)(dma->mem[dma->buffer].virt + 1))));
	*/

end_exch:
	return ret;
}


#ifdef __DEVELOPMENT__
static int msps_batch_exchange(msps_dev_t *dev, msps_batch_t batch)
{

	/*
	 * 1 string = 64 bytes
	 * 64 string = 4096 bytes = 1 page
	 * all pages = 4
	 * MSPS_MAX_BATCH_SIZE   1024*256 = 4096*64 = 4096*4*16
	 * batch = N in Kbytes
	 */

	msps_setup_t task;
	int i = 0;
	int pages = batch/4;
	int count = 0, tmp;
	char *begin_array = (char *)dev->user_array;

	if (batch%4) pages++; /* count numbers of pages for exchange */

	memset(dev->user_array, 0, MSPS_MAX_BATCH_SIZE);
	DETAIL_PRINT(" * msps_batch_exchange: batch: %d (Kb), pages: %d \n",
				batch, pages);
	/*not needed*/
	task.status.strings = -1;
	task.status.page = -1;

	while (count < pages) {
		task.start_page = 0;
		tmp = pages - count;
		if (tmp > 3) {
			task.strings = 63 * 4;
			task.stop_page = 3;
		} else {
			task.strings = 63 * tmp;
			task.stop_page = tmp - 1;
		}
		msps_exchange(dev->minor, &task, NULL, MSPS_WAIT, MSPS_USER);
		memcpy(begin_array + count*PAGE_SIZE, dev->virt_dma[0], PAGE_SIZE * 4);
		/*memcpy(&begin_array[count * PAGE_SIZE], dev->virt_dma[0], PAGE_SIZE * 4);*/
		count = count + 4;
		i++;
	}
	return 0;
}
#endif


#ifdef MSPS_PRINT_FULL_REGS
void print_full_regs()
{
	volatile union lctl_register lctl;
	volatile u_long test_reg = 0;
	int i;
	volatile u_long ii, im, c, cp;
	int pminor = 9;

	lctl.r = GET_MSPS_REG(MSPS_LCTL);
	test_reg = GET_MSPS_REG(MSPS_TEST);

	DETAIL_PRINT("registers:\n"
		     "\tlctl: 0x%x (0x%x 0x%x 0x%x 0x%x 0x%x 0x%x)\n"
		     "\ttest: 0x%x\n",
		     lctl.r,
		     lctl.b.chn0,
		     lctl.b.chn1,
		     lctl.b.chn2,
		     lctl.b.chn3,
		     lctl.b.chn4,
		     lctl.b.chn5,
		     test_reg);
	for (i = 0; i < MAX_MSPS; i++) {
		ii = GET_MSPS_REG(MSPS_II(i));
		im = GET_MSPS_REG(MSPS_IM(i));
		c  = GET_MSPS_REG(MSPS_C(i));
		cp = GET_MSPS_REG(MSPS_CP(i));
		DETAIL_PRINT("\tII%d: 0x%x IM%d: 0x%x C%d: 0x%x CP%d: 0x%x\n",
			     i, ii, i, im, i, c, i, cp);
	}
}
#endif

/*
 * 0X[31-16][14         ][13-8][6          ][5-0]
 * 0X[ cntr][masktimeout][mask][intrtimeout][intr]
 * if set masktimeout then double interrupt are off
 */
void msps_twice_intr_on()
{
	union intr_register reg;
#if DEBUG_DETAIL_MODE
	int pminor = 8;
#endif
	SLOCK(&dma_lock);
	reg.r = GET_MSPS_REG(MSPS_INTR);
	reg.b.masktimeout = 0;
	SET_MSPS_REG(MSPS_INTR, reg.r);
	SUNLOCK(&dma_lock);
	DETAIL_PRINT("MSPS_TWICE_INTR_ON : 0x%08x\n", reg.r);
}


void msps_twice_intr_off()
{
	union intr_register reg;
#if DEBUG_DETAIL_MODE
	int pminor = 8;
#endif
	SLOCK(&dma_lock);
	reg.r = GET_MSPS_REG(MSPS_INTR);
	reg.b.masktimeout = 1;
	SET_MSPS_REG(MSPS_INTR, reg.r);
	SUNLOCK(&dma_lock);
	DETAIL_PRINT("MSPS_TWICE_INTR_ON : 0x%08x\n", reg.r);
}


void msps_test_mode_on(msps_dev_t *dev)
{
	volatile int reg = 0;
	int offset = 0;
#if DEBUG_DETAIL_MODE
	int pminor;
	pminor = dev->minor;
#endif
	offset = (int)(dev->minor / 2);
	MLOCK(&dev->mutex);
	reg = GET_MSPS_REG(MSPS_TEST);
	reg |= (1 << (offset * 8));
	SET_MSPS_REG(MSPS_TEST, reg);
	MUNLOCK(&dev->mutex);
	DETAIL_PRINT("MSPS_TEST_MODE_ON : 0x%08x [%d]\n", reg, offset);
}


void msps_test_mode_off(msps_dev_t *dev)
{
	volatile int reg = 0, oreg = 0;
	int offset = 0;
#if DEBUG_DETAIL_MODE
	int pminor;
	pminor = dev->minor;
#endif
	offset = (int)(dev->minor / 2);
	MLOCK(&dev->mutex);
	reg = GET_MSPS_REG(MSPS_TEST);
	reg &= ~(1 << (offset * 8));
	SET_MSPS_REG(MSPS_TEST, reg);
	MUNLOCK(&dev->mutex);
	DETAIL_PRINT("MSPS_TEST_MODE_OFF: 0x%08x [%d]\n", reg, offset);
}


static  long msps_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int		err = 0;
	msps_dev_t	*dev = (msps_dev_t *)filp->private_data;
	int		retval = 0;
	int pminor;
	pminor = dev->minor;

	//DBG_PRINT("ioctl:\tdev[%d, %d]: cpu: node: %d, id: %d\n",
	DETAIL_PRINT("ioctl:\tdev[%d, %d]: cpu: node: %d, id: %d\n",
		     major, (dev->minor & 0x0f),
		     numa_node_id(), raw_smp_processor_id());

	MLOCK(&dev->ioctl_mutex);

#ifdef MCST_INCLUDE_IOCTL
	if ( cmd == MCST_SELFTEST_MAGIC ) {
		selftest_t st;
		selftest_pci_t *st_pci = &st.info.pci;
		struct pci_dev *pdev = dev->pdev;

		DETAIL_PRINT("ioctl:\tSELFTEST\n");

		st.bus_type = BUS_PCI;
		st.error = 0; /* temporary unused */

		st_pci->vendor = pdev->vendor;
		st_pci->device = pdev->device;

		st_pci->major = major;
		st_pci->minor = dev->minor;

		st_pci->bus = pdev->bus->number;
		st_pci->slot = PCI_SLOT(pdev->devfn);
		st_pci->func = PCI_FUNC(pdev->devfn);
		st_pci->class = pdev->class;

		strncpy(st_pci->name, msps_dev_name, 255);
		DBG_PRINT("%s: [%d][%d][%s]. vendor: %#x, device: %#x, bus: %d, slot: %d, func: %d, class: %#x\n",
		       __func__,
		       st_pci->major, st_pci->minor,
		       st_pci->name, st_pci->vendor, st_pci->device,
		       st_pci->bus, st_pci->slot,
		       st_pci->func, st_pci->class);

		if (copy_to_user((selftest_t __user *)arg,
				 &st,
				 sizeof(selftest_t))) {
			ERROR_PRINT( "%s: MCST_SELFTEST_MAGIC: copy_to_user() failed\n",
				     __func__);
			retval = -EFAULT;
		}
		goto ioctl_end;
	}
#endif

	if (_IOC_TYPE(cmd) != MSPS_IOC_MAGIC) {retval = -ENOTTY; goto ioctl_end;}
	if (_IOC_NR(cmd) > MSPS_IOC_MAXNR) {retval = -ENOTTY; goto ioctl_end;}
	if (_IOC_DIR(cmd) & _IOC_READ)
		err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		err =  !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
	if (err) {retval = -EFAULT; goto ioctl_end;}


	switch(cmd)
	{

	case MSPS_GET_STATUS:
	{
		volatile union lctl_register lctl;
		u_long test_reg = 0;

		msps_status_t s;
		DETAIL_PRINT("ioctl:\tMSPS_GET_STATUS\n");

		MLOCK(&dev->mutex);

		lctl.r = GET_MSPS_REG(MSPS_LCTL);
		test_reg = GET_MSPS_REG(MSPS_TEST);

		s.state  = dev->dma.done;
		s.buffer = dev->dma.buffer;
		s.size   = dev->dma.mem[dev->dma.buffer].user_size;
		s.wtime  = dev->dma.wtime;

		if (copy_to_user((msps_status_t __user *)arg,
				 &s,
				 sizeof(msps_status_t))) {
			MUNLOCK(&dev->mutex);
			ERROR_PRINT("ioctl: MSPS_GET_STATUS\n");
			retval = -EFAULT;
			break;
		}
		MUNLOCK(&dev->mutex);
		DETAIL_PRINT("resgister lctl for stat: %d 0x%x (%x %x %x %x %x %x) test: 0x%x\n",
			     dev->minor, lctl.r,
			     lctl.b.chn0, lctl.b.chn1, lctl.b.chn2,
			     lctl.b.chn3, lctl.b.chn4, lctl.b.chn5,
			     test_reg);
	}
	break;


	case MSPS_GET_DATA_BY_REGS:
	{
		msps_get_by_regs_t task;

		DETAIL_PRINT("ioctl:\tMSPS_GET_DATA_BY_REGS\n");
		if (copy_from_user(&task,
				   (msps_get_by_regs_t __user *)arg,
				   sizeof(msps_get_by_regs_t)))
		{
			ERROR_PRINT("ioctl: GET_BY_REGS copy from user\n");
			retval = -EFAULT;
			break;
		}

		DETAIL_PRINT("ioctl:\tMSPS_GET_DATA_BY_REGS: buf: %d, size %d.\n",
			  task.buf_number, task.size);
#ifdef __DEVELOPMENT__
		/* setup and run exchange */
		if (msps_exchange_by_regs(dev, &task, NULL)) {
			retval = -EFAULT;
			break;
		}
#endif
	}
	break;

	case MSPS_EXCH_DATA:
	{
		msps_setup_t		task;

		DETAIL_PRINT("ioctl:\tMSPS_EXCH_DATA\n");
		if (copy_from_user(&task,
				   (msps_setup_t __user *)arg,
				   sizeof(msps_setup_t)))
		{
			ERROR_PRINT("ioctl: GET copy from user\n");
			retval = -EFAULT;
			break;
		}

		DBG_PRINT("ioctl:\tMSPS_EXCH_DATA: size %d.\n", task.size);
		if (dev->minor == 1 || dev->minor == 3 || dev->minor == 5)
			DBG_PRINT("ioctl:\twrite data\n");
		else
			DBG_PRINT("ioctl:\tread data\n");

		/* setup and run exchange */
		if (msps_exchange(dev->minor, &task, NULL, MSPS_WAIT, MSPS_USER)) {
			retval = -EFAULT;
			break;
		}

		/* return bufer number, who used, and time exchange */
		/* if task.size more than dma array - > set flag override
		   and bufers used as circle  */
		if (copy_to_user((msps_setup_t __user *)arg,
				  &task,
				  sizeof(msps_setup_t)))
		{
			ERROR_PRINT("ioctl: MSPS_GET_DATA copy to user\n");
			retval = -EFAULT;
			break;
		}
	}
	break;


	case MSPS_EXCH_DATA_NW:
	{
		msps_setup_t		task;

		DETAIL_PRINT("ioctl:\tMSPS_EXCH_DATA without waiting\n");
		if (copy_from_user(&task,
				   (msps_setup_t __user *)arg,
				   sizeof(msps_setup_t)))
		{
			ERROR_PRINT("ioctl: GET copy from user\n");
			retval = -EFAULT;
			break;
		}

		DBG_PRINT("ioctl:\tMSPS_EXCH_DATA: size %d.\n", task.size);
		if (dev->minor == 1 || dev->minor == 3 || dev->minor == 5)
			DBG_PRINT("ioctl:\twrite data\n");
		else
			DBG_PRINT("ioctl:\tread data\n");

		/* setup and run exchange */
		if (msps_exchange(dev->minor, &task, NULL, MSPS_NON_WAIT, MSPS_USER)) {
			retval = -EFAULT;
			break;
		}
	}
	break;


	case MSPS_EXCH_DATA_ACTIVE:
	{
		msps_setup_a_t		task;

		DETAIL_PRINT("ioctl:\tMSPS_EXCH_DATA_ACTIVE\n");

		task.s.size = 8;
		task.time = 1000;

		if (copy_from_user(&task,
				   (msps_setup_a_t __user *)arg,
				   sizeof(msps_setup_a_t)))
		{
			ERROR_PRINT("ioctl: GET copy from user\n");
			retval = -EFAULT;
			break;
		}

		DBG_PRINT("ioctl:\tMSPS_EXCH_DATA_ACTIVE: size %d.\n", task.s.size);
		if (dev->minor == 1 || dev->minor == 3 || dev->minor == 5)
			DBG_PRINT("ioctl:\twrite data\n");
		else
			DBG_PRINT("ioctl:\tread data\n");

		/* setup and run exchange */
		if (msps_exchange(dev->minor, &task.s, &task.time, MSPS_WAIT, MSPS_USER)) {
			retval = -EFAULT;
			break;
		}

		/* return bufer number, who used, and time exchange */
		/* if task.size more than dma array - > set flag override
		   and bufers used as circle  */
		if (copy_to_user((msps_setup_a_t __user *)arg,
				  &task,
				  sizeof(msps_setup_a_t)))
		{
			ERROR_PRINT("ioctl: MSPS_GET_DATA_ACTIVE copy to user\n");
			retval = -EFAULT;
			break;
		}
	}
	break;


	case MSPS_GET_BATCH:
	{
		retval = -EFAULT;
#ifdef __DEVELOPMENT__
		msps_batch_t batch;

		DETAIL_PRINT("ioctl:\tMSPS_GET_BATCH\n\n");
		if (copy_from_user(&batch,
				   (msps_batch_t __user *)arg,
				   sizeof(msps_batch_t)))
		{
			ERROR_PRINT("ioctl: GET_BATCH copy from user\n");
			retval = -EFAULT;
			break;
		}


		if (batch <= 0 || batch*1024 > MSPS_MAX_BATCH_SIZE) {
			ERROR_PRINT("ioctl: MSPS_GET_BATCH error in "
				    "msps_batch_t: out of boundares\n");
			retval = -EFAULT;
			break;
		}


		/* setup and run exchange */
		if (msps_batch_exchange(dev, batch)) {
			retval = -EFAULT;
			break;
		}
#endif
	}
	break;

	case MSPS_RESET:
	{
		msps_reset(dev);
	}
	break;

	case MSPS_TEST_MODE_ON:
	{
		msps_test_mode_on(dev);
	}
	break;

	case MSPS_TEST_MODE_OFF:
	{
		msps_test_mode_off(dev);
	}
	break;

	case MSPS_TWICE_INTR_ON:
	{
		msps_twice_intr_on();
	}
	break;

	case MSPS_TWICE_INTR_OFF:
	{
		msps_twice_intr_off();
	}
	break;

	case MSPS_TEST_EXCH:
	{
		msps_setup_t task;
		msps_setup_t task_tmp;
		int wrnum = 0, rdnum = 0;
		unsigned char *wrbuf, *rdbuf;
		int nbuf = 0;
#ifdef MSPS_FILL_DBG_MODE
		int i;
#endif

		DETAIL_PRINT("ioctl:\tMSPS_EXCH_DATA - internal test\n");
		if (copy_from_user(&task,
				   (msps_setup_t __user *)arg,
				   sizeof(msps_setup_t)))
		{
			ERROR_PRINT("ioctl: GET copy from user\n");
			retval = -EFAULT;
			break;
		}

		DETAIL_PRINT("ioctl:\tMSPS_EXCH_DATA: size %d.\n", task.size);

		switch (dev->minor) {
		case 0:
		case 1:
			wrnum = 1;
			rdnum = 0;
			break;
		case 2:
		case 3:
			wrnum = 3;
			rdnum = 2;
			break;
		case 4:
		case 5:
			wrnum = 5;
			rdnum = 4;
			break;
		}

		nbuf = msps_devices[wrnum]->dma.buffer;
		wrbuf = (unsigned char *)(msps_devices[wrnum]->dma.mem[nbuf].virt);
		rdbuf = (unsigned char *)(msps_devices[rdnum]->dma.mem[nbuf].virt);
#ifdef MSPS_FILL_DBG_MODE
		for (i = 0; i < 64; i++) {
			wrbuf[i] = 0x80 + i;
			rdbuf[i] = 0x50 + i;
		}
#endif
		DETAIL_PRINT("dev %d: [0: 0x%016lx 0x%016lx | 1: 0x%016lx 0x%016lx]\n",
			     rdnum,
			     *((u64 *)(msps_devices[rdnum]->dma.mem[0].virt + 0)),
			     *((u64 *)(msps_devices[rdnum]->dma.mem[0].virt + 1)),
			     *((u64 *)(msps_devices[rdnum]->dma.mem[1].virt + 0)),
			     *((u64 *)(msps_devices[rdnum]->dma.mem[1].virt + 1)));
		DETAIL_PRINT("dev %d: [0: 0x%016lx 0x%016lx | 1: 0x%016lx 0x%016lx]\n",
			     wrnum,
			     *((u64 *)(msps_devices[wrnum]->dma.mem[0].virt + 0)),
			     *((u64 *)(msps_devices[wrnum]->dma.mem[0].virt + 1)),
			     *((u64 *)(msps_devices[wrnum]->dma.mem[1].virt + 0)),
			     *((u64 *)(msps_devices[wrnum]->dma.mem[1].virt + 1)));

		msps_test_mode_on(dev);

		DETAIL_PRINT("test exch: /dev/msps%d -> /dev/msps%d [48: %s]\n",
			     wrnum, rdnum,
			     task.extended_flag ? "YES" : "NO");

		/* setup and run exchange */

#ifdef MSPS_PRINT_FULL_REGS
		print_full_regs();
#endif

		task_tmp.size = task.size;
		task_tmp.extended_flag = task.extended_flag;
		task_tmp.key = task.key; /* for dbg */

#ifdef __DEVELOPMENT_DBG_
		/* dbg: mask all intr, except read channel */
		if (0) {
			unsigned int rintr = GET_MSPS_REG(MSPS_INTR);
			unsigned int wintr = 0x0;
			int q;
			wintr = rintr;
			for (q = 0; q < 6; q++) {
				if (q != rdnum) {
					wintr |= (1 << (8 + q));
				}
			}
			DBG_PRINT("intr reg: 0x%08x -> 0x%08x\n",
				  rintr, wintr);
			SET_MSPS_REG(MSPS_INTR, wintr);
		}
#endif
		//if (msps_exchange(wrnum, &task_tmp, NULL, MSPS_NON_WAIT, 0)) {
		if (msps_exchange(wrnum, &task_tmp, NULL, MSPS_NON_WAIT, MSPS_USER)) {
			ERROR_PRINT("WTF in test exch?\n");
		}

#ifdef MSPS_PRINT_FULL_REGS
		print_full_regs();
#endif

		if (msps_exchange(rdnum, &task, NULL, MSPS_WAIT, MSPS_USER)) {
			retval = -EFAULT;
			break;
		}

#ifdef MSPS_PRINT_FULL_REGS
		print_full_regs();
#endif

		DETAIL_PRINT("dev %d: [0: 0x%016lx 0x%016lx | 1: 0x%016lx 0x%016lx]\n",
			     rdnum,
			     *((u64 *)(msps_devices[rdnum]->dma.mem[0].virt + 0)),
			     *((u64 *)(msps_devices[rdnum]->dma.mem[0].virt + 1)),
			     *((u64 *)(msps_devices[rdnum]->dma.mem[1].virt + 0)),
			     *((u64 *)(msps_devices[rdnum]->dma.mem[1].virt + 1)));
		DETAIL_PRINT("dev %d: [0: 0x%016lx 0x%016lx | 1: 0x%016lx 0x%016lx]\n",
			     wrnum,
			     *((u64 *)(msps_devices[wrnum]->dma.mem[0].virt + 0)),
			     *((u64 *)(msps_devices[wrnum]->dma.mem[0].virt + 1)),
			     *((u64 *)(msps_devices[wrnum]->dma.mem[1].virt + 0)),
			     *((u64 *)(msps_devices[wrnum]->dma.mem[1].virt + 1)));

		msps_test_mode_off(dev);

		/* return bufer number, who used, and time exchange */
		/* if task.size more than dma array - > set flag override
		   and bufers used as circle  */
		if (copy_to_user((msps_setup_t __user *)arg,
				 &task,
				 sizeof(msps_setup_t)))
		{
			ERROR_PRINT("ioctl: MSPS_GET_DATA copy to user\n");
			retval = -EFAULT;
			break;
		}
	}
	break;

	default:
		ERROR_PRINT("ioctl:\tUnknown command: 0x%08x\n", cmd);
		retval = -EINVAL;
	}

ioctl_end:
	MUNLOCK(&dev->ioctl_mutex);

	//DBG_PRINT("ioctl:\tend\n");
	DETAIL_PRINT("ioctl:\tend\n");

	return retval;
}

static struct file_operations msps_fops = {
	.owner   = THIS_MODULE,
	.open    = msps_open,
	.release = msps_release,
	.read    = msps_read,	/*not implemented*/
	.write   = msps_write,	/*not implemented*/
	.unlocked_ioctl = msps_ioctl,
	.poll    = msps_poll,
	.mmap    = msps_mmap,
};


#ifdef __CATCH_INTERRUPT_ON__
#endif


static inline void remove_msps(struct pci_dev *pdev, int step)
{
	int i, j, k;
	int pminor = 9;

	DBG_PRINT("remove_msps\n");

	switch (step) {
	default:
	case 9:
		DBG_PRINT("step 9\n");
#ifdef MSPS_USING_IRQ
		free_irq(irq, (void *)msps_devices[0]);
#endif
		/* pci_set_drvdata(dev->pdev, NULL); - needed ? */
		cdev_del(&cdev);
	case 8:
		DBG_PRINT("step 8\n");
	case 7:
		DBG_PRINT("step 7\n");
		unregister_chrdev_region(MKDEV(major, 0), MSPS_NUMBERS);
	case 6:
		DBG_PRINT("step 6\n");
	case 5:
	{
		DBG_PRINT("step 5\n");
		/* free DMA buffers, if set */
		struct page *map, *mapend;
		int order = get_order(MSPS_DMA_SIZE);
		msps_dev_t *dev;

		for (j = 0; j < MAX_MSPS; j++) {
			dev = msps_devices[j];
			if (dev != NULL) {
				for (k = 0; k < 2; k++) {
					if (dev->dma.mem[k].page != 0) {
						mapend = virt_to_page(dev->dma.mem[k].page +
								      (PAGE_SIZE << order) - 1);
						for (map = virt_to_page(dev->dma.mem[k].page);
						     map <= mapend;
						     map++)
							ClearPageReserved(map);

						free_pages(dev->dma.mem[k].page, order);
					} else {
						break;
					}
				}
			}
		}
	}
	case 4:
		DBG_PRINT("step 4\n");
		iounmap(BASE);
	case 3:
		DBG_PRINT("step 3\n");
		release_mem_region(phys_addr, pci_src_len);
	case 2:
		DBG_PRINT("step 2\n");
		pci_disable_device(pdev);

		for (i = 0; i < MAX_MSPS; i++) {
#ifdef UDEV_ON
			device_destroy(msps_class, MKDEV(major, i));
#endif
			kfree(msps_devices[i]);
			msps_devices[i] = NULL;
		}
#ifdef UDEV_ON
		class_destroy(msps_class);
#endif
	case 1:
		DBG_PRINT("step 1\n");
	case 0:
		DBG_PRINT("step 0\n");
		break;
	}
}


static irqreturn_t msps_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{

	union lctl_register lctl;
	union intr_register intr;
	static long count = 0;
	unsigned int i, tmp = 0;
	msps_dev_t *dev;
	unsigned long flags;
	int pminor = 9;

	int start[MAX_MSPS];
	int end[MAX_MSPS];
	int key[MAX_MSPS];

	int twice = 0;

	DBG_PRINT("Interrupt count: %d\n", count);
	SLOCK_IRQSAVE(&dma_lock, flags);
	lctl.r = GET_MSPS_REG(MSPS_LCTL);
	intr.r = GET_MSPS_REG(MSPS_INTR);

	for (i = 0; i < MAX_MSPS; i++) {
		start[i] = msps_devices[i]->dma.start;
		key[i] = msps_devices[i]->dma.key;
	}
	SUNLOCK_IRQREST(&dma_lock, flags);

	if (intr.r == 0) {
		DBG_PRINT("Get double interrupt: lctl: 0x%x intr: 0x%x\n",
			  lctl.r, intr.r);
		return IRQ_HANDLED;
	}

	twice = 0;
	for (i = 0; i < MAX_MSPS; i++) { /* each device */
		dev = msps_devices[i];
		end[i] = 0;
		if (start[i]) {
			tmp = intr.r & (1 << i);
			if (tmp) { /* dma end */
				end[i] = 1;
				if (intr.b.intrtimeout) {
					dev->dma.twice = 1;
					twice = 1;
				}
				dev->dma.start = 0;
				dev->dma.done = MSPS_DMA_DONE;
				wake_up_interruptible(&dev->dma.wait_queue);
			}
		}
	}
	count++;

#if DEBUG_MODE
	DBG_PRINT("interrupt twice: %s\n", twice ? "YES" : "NO");
	DBG_PRINT("get interrupt: lctl: 0x%x intr: 0x%x count: %d\n"
		  "       [0 1 2 3 4 5]\n"
		  "start: [%d %d %d %d %d %d]\n"
		  "end  : [%d %d %d %d %d %d]\n"
		  "key  : {%4d %4d %4d %4d %4d %4d}\n",
		  lctl.r, intr.r, count,
		  start[0], start[1], start[2],
		  start[3], start[4], start[5],
		  end[0], end[1], end[2],
		  end[3], end[4], end[5],
		  key[0], key[1], key[2],
		  key[3], key[4], key[5]);
#endif

	return IRQ_HANDLED;
}


static int create_msps_device(msps_dev_t *dev, struct pci_dev *pdev, int minor)
{
	int order, i;
	struct page *map, *mapend;
	int pminor = minor;
	memset((void*)dev, 0, sizeof(msps_dev_t));

	dev->minor = minor;
	MINIT(&dev->mutex);

	DBG_PRINT("Allocate memory for DMA, minor: %d\n", dev->minor);

	/* input buffers */
	for (i = 0; i < 2; i++) {
		order = get_order(MSPS_DMA_SIZE);
		dev->dma.mem[i].page = __get_free_pages(GFP_KERNEL | GFP_DMA, order);
		if (!dev->dma.mem[i].page) {
			ERROR_PRINT("init: MSPS: error allocate DMA buffer, %2d - %2d\n",
				    minor, i);
			return -ENOMEM;
		}

		mapend = virt_to_page(dev->dma.mem[i].page + (PAGE_SIZE << order) - 1);
		for (map = virt_to_page(dev->dma.mem[i].page); map <= mapend; map++)
			SetPageReserved(map);

		dev->dma.mem[i].virt = (dma_addr_t *)dev->dma.mem[i].page;
		dev->dma.mem[i].phys = virt_to_phys((char *)(dev->dma.mem[i].virt));

		memset(dev->dma.mem[i].virt, 0, MSPS_DMA_SIZE);
		dev->dma.mem[i].size = MSPS_DMA_SIZE;
		dev->dma.mem[i].real_size = PAGE_SIZE << order;

		DETAIL_PRINT("msps: DMA channel %d:%d: virt 0x%p, phys 0x%lx size %d rsize %d\n",
			     minor, i,
			     dev->dma.mem[i].virt,
			     dev->dma.mem[i].phys,
			     dev->dma.mem[i].size,
			     dev->dma.mem[i].real_size);
	}

#ifndef MSPS_SWITCH_BUFFER
	dev->dma.buffer = 0;
#endif
	init_waitqueue_head(&dev->dma.wait_queue);

	dev->pdev = pdev;

	return 0;
}


static int msps_probe_pci(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	msps_dev_t *dev;
	dev_t dev_number;
	int err = 0;
	int step = 0;
	int i = 0;
	unsigned int irq_flags = 0;
	int pminor = 9;

	DBG_PRINT("msps: step: %d.\n", step);

	err = pci_enable_device(pdev);
	if (err < 0) {
		ERROR_PRINT("msps: failed to enable device: err = %d\n", err);
		return err;
	}

	step = 2;
	DBG_PRINT("msps: step: %d.\n", step);

	pci_set_master(pdev);

	phys_addr = pci_resource_start(pdev, MSPS_PCI_BAR);
	if (!phys_addr) {
		ERROR_PRINT("msps: card has no PCI IO resources, aborting\n");
		err = -ENODEV;
		goto error;
	}

	irq = pdev->irq;

	if (!pci_dma_supported(pdev, MSPS_DMA_MASK)) {
		ERROR_PRINT("msps: architecture does not "
			    "support 32bit PCI busmaster DMA\n");
		err = -ENODEV;
		goto error;
	}

	pci_src_len = pci_resource_len(pdev, MSPS_PCI_BAR);
	if (request_mem_region(phys_addr, pci_src_len, "msps_probe_pci") == NULL) {
		ERROR_PRINT("msps: memio address range already allocated\n");
		err = -EBUSY;
		goto error;
	}

	step = 3;
	DBG_PRINT("msps: step: %d.\n", step);

	BASE = ioremap(phys_addr, pci_src_len);
	if (BASE == NULL) {
		ERROR_PRINT("msps: Unable to map base addr = 0x%lx\n",
			    phys_addr);
		err = -ENOMEM;
		goto error;
	} else {
		DETAIL_PRINT("msps: map base addr: phys = 0x%x, virt = 0x%p\n",
			     phys_addr, BASE);
	}

	step = 4;
	DBG_PRINT("msps: step: %d.\n", step);

	for (i = 0; i < MAX_MSPS; i++) {
		dev = kmalloc(sizeof(msps_dev_t), GFP_KERNEL);
		if ( dev < 0 ) {
			ERROR_PRINT("msps: Cannot allocate memory for msps_dev_t.\n");
			pci_disable_device(pdev);
			err = -ENOMEM;
			goto error;
		}
		memset(dev, 0, sizeof(msps_dev_t));
		msps_devices[i] = dev;
		err = create_msps_device(dev, pdev, i);
		if (err)
			goto error;

		step = 5;
		DBG_PRINT("msps: step: %d.%d .\n", step, i);
	}

	step = 6;
	DBG_PRINT("msps: step: %d.\n", step);

	SINIT(&dma_lock);

	if (!major) {
		err = alloc_chrdev_region(&dev_number,
					  0,
					  MSPS_NUMBERS,
					  msps_dev_name);
		if (!err) {
			major = MAJOR(dev_number);
		}
	} else {
		dev_number = MKDEV(major, 0);
		err = register_chrdev_region(dev_number,
					     MSPS_NUMBERS,
					     msps_dev_name);
	}

	if ( err < 0 ) {
		ERROR_PRINT("msps: Can not register char device region.\n");
		goto error;
	}

	step = 7;
	DBG_PRINT("msps: step: %d.\n", step);

#ifdef MSPS_USING_IRQ
        irq_flags = IRQF_SHARED;
	/*
	  #ifdef CONFIG_MCST_RT
	  irq_flags |=  IRQF_DISABLED;
	  #endif
	*/

	if (request_irq(irq,
			(void *)msps_interrupt,
			irq_flags,
			msps_dev_name,
			(void *)msps_devices[0])) {
		ERROR_PRINT("msps: cannot register IRQ %d\n", irq);
		err = -ENOMEM;
		goto error;
	} else
		DBG_PRINT("msps: assigned IRQ %d\n", irq);
#else
		WARNING_PRINT("msps: IRQ disabled\n");
#endif

	step = 8;
	DBG_PRINT("msps: step: %d.\n", step);

	cdev_init(&cdev, &msps_fops);
	cdev.owner = THIS_MODULE;
	cdev.ops = &msps_fops; /* needed ??? */
	err = cdev_add(&cdev, dev_number, MSPS_NUMBERS);
	if (err) {
		printk("msps: Can not added char device.\n");
		goto error;
	}

	/* pci_set_drvdata(pdev, dev); */ /* not needed - using global info */

	step = 9;
	DBG_PRINT("msps: step: %d.\n", step);

	/* clear registers */
	msps_reset(msps_devices[0]);

	/* check devices for realy present */
	for (i = 0; i < MAX_MSPS; i++) {
		msps_setup_a_t t;
		t.s.size = 80;
		t.s.extended_flag = 1;
		t.time = 10000; /* wait 10 milisec*/
		msps_devices[i]->dma.rele = 1; /* only for dbg */
		if (i == 1 || i == 3 || i == 5) {
			DBG_PRINT("init:\tMSPS check device: %d\n", i);
			if (msps_exchange(i, &t.s, &t.time, MSPS_WAIT, 0)) {
				ERROR_PRINT("init:\terror at check channel: %d\n", i);
				continue;
			}

			if (msps_devices[i]->dma.done == MSPS_DMA_DONE) {
				NOTE_PRINT("init:\tchannels: %d and %d - present\n",
					   i-1, i);
				msps_devices[i]->present = 1;
				msps_devices[i-1]->present = 1;
			} else {
				WARNING_PRINT("init:\tchannels: %d and %d - absent\n",
					      i-1, i);
			}
		}
		msps_devices[i]->dma.key = 0; /* for dbg */
	}

	/* clear registers */
	msps_reset(msps_devices[0]);

	DBG_PRINT("msps: attached: major: %d.\n", major);

#ifdef MSPS_SWITCH_BUFFER
	DBG_PRINT("msps: switched dma buffer - ON\n");
#else
	DBG_PRINT("msps: switched dma buffer - OFF: %d\n",
		     msps_devices[0]->dma.buffer);
#endif

#ifdef MCST_MKNOD_INSIDE

	/* Create nodes */
	{
		int	mode;
		dev_t	devt;
		char	nod[128];

#ifdef UDEV_ON
		DBG_PRINT("init:\tcreate nodes\n");

		msps_class = class_create(THIS_MODULE, "msps");
		if (IS_ERR(msps_class)) {
			pr_err("Error creating class: /sys/class/msps.\n");
		}

		for (i = 0; i < MAX_MSPS; i++) {
			sprintf(nod, "%s%d", msps_fs_dev_name, i);
			if (!IS_ERR(msps_class)) {
				pr_info("make node /sys/class/msps/%s\n", nod);
				if (device_create(msps_class, NULL,
				    MKDEV(major, i), NULL, nod) == NULL)
					pr_err("create a node %d failed\n", i);
			}

		}
#endif
	}
#endif

#ifdef __USE_PROC__
	DBG_PRINT("init:\tcreate file in /proc/driver/msps\n");
	if (!create_msps_proc()) {
		ERROR_PRINT("init: can't create /proc/driver/msps\n");
	}
#endif

	return 0;

error:
	DBG_PRINT("step: %d\n", step);
	remove_msps(pdev, step);
	msps_probe_result = -1;
	return err;
}


static void msps_remove_one(struct pci_dev *pdev)
{

#ifdef __USE_PROC__
	remove_msps_proc();
#endif

	remove_msps(pdev, 99); /* just max number for step */
}


static int __init msps_init (void)
{
	int result;
	int pminor = 9;

	NOTE_PRINT("Hello world from MSPS driver. cpu: node: %d, id: %d.\n",
		   numa_node_id(), raw_smp_processor_id());

	msps_sysctl_register();

	if (! IS_MACHINE_ES2) {
		ERROR_PRINT("init:\tCan not find MSPS.\n");
		return -ENXIO;
	}
	else
		DBG_PRINT ("CPU's numbers: x, node: %d.\n",
			   num_online_nodes());

	result = pci_register_driver(&msps_driver);
	if  (result != 0) {
		ERROR_PRINT("init:\tCan not register MSPS: %d.\n", result);
		return -ENODEV;
	}

	if (msps_devices[0] == NULL  || msps_probe_result < 0) {
		ERROR_PRINT("init:\tDevice MSPS did not attached.\n");
		pci_unregister_driver(&msps_driver);
		DBG_PRINT("init:\tUnregister device driver.\n");
		return -ENODEV;
	}

	return result;
}


static void __exit msps_cleanup(void)
{
	int pminor = 9;
	DBG_PRINT("exit:\tunregister device driver\n");
	pci_unregister_driver(&msps_driver);
	msps_sysctl_unregister();
}


module_init(msps_init);
module_exit(msps_cleanup);
