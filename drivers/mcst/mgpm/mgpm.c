/*
*
*
*
*/
#include <linux/poll.h>
#include <linux/cdev.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/security.h>

// for mknod
#include <linux/err.h>
#include <linux/namei.h>
#include <linux/audit.h>
// end for mknod

/*
#ifndef CONFIG_PCI
#  error "This driver needs PCI support to be available"
#endif
*/
#include <linux/mcst/mgpm_io.h>
#include <linux/mcst/mgpm.h>
#include <linux/mcst/mcst_selftest.h>

#define	MAX_DRV_NM_SZ	64

// /proc/sys/debug/mgpm_debug trigger
int mgpm_debug = 0;

#define	DBGMGPM_MODE
#undef DBGMGPM_MODE

#if defined(DBGMGPM_MODE)
#define	dbgmgpm			printk
#else
#define	dbgmgpm			if ( mgpm_debug ) printk
#endif

extern struct dentry *lookup_hash(struct nameidata *nd);

int drv_unlink(char *dir, char *filename);
static int drv_mknod(char *filename, int mode, dev_t dev);
static int drv_mkdir(char *pathname, int mode);
static int drv_create_dir(char *dir);
int drv_create_minor(char *dir, char *name, int type, dev_t dev);
static int may_mknod(mode_t mode);

#if defined(VER_2614)
int mk_mknod(char *filename, int mode, dev_t dev);
int mk_mkdir(char *pathname, int mode);
int mk_rm_dir(char *dir);
int mk_unlink(char *filename);
#endif

#if defined(CONFIG_SYSCTL)
#include <linux/sysctl.h>

static ctl_table mgpm_table[] = {
	{
		.procname	= "mgpm_debug",
		.data		= &mgpm_debug, 
		.maxlen		= sizeof(mgpm_debug),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static ctl_table mgpm_root_table[] = {
	{
		.procname	= "debug",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= mgpm_table,
	},
	{ }
};

static struct ctl_table_header *mgpm_sysctl_header;

static void __init mgpm_sysctl_register(void)
{
	mgpm_sysctl_header = register_sysctl_table(mgpm_root_table);
}

static void mgpm_sysctl_unregister(void)
{
	if ( mgpm_sysctl_header )
		unregister_sysctl_table(mgpm_sysctl_header);
}

#else /* CONFIG_SYSCTL */

static void __init mgpm_sysctl_register(void)
{
}

static void mgpm_sysctl_unregister(void)
{
}
#endif

/* Regs acces to mgpm regs */
void put_mgpm_reg(mgpm_dev_t *dev,int reg,int val) {
	char	*addr = (char *)dev->device_mem_start;
	u32	*reg_adr = (u32 *)(addr + reg);
	*reg_adr = val;
	wmb();
	//printk("put_mgpm_reg reg 0x%x val 0x%x\n",(int)reg_adr,val);
}

int get_mgpm_reg(mgpm_dev_t *dev,int reg) {
	char *addr = (char *)dev->device_mem_start;
	int  value;
	addr += reg;
	value = *(u32*)addr;
	//printk("get_mgpm_reg reg 0x%x val 0x%x\n",(int)addr,value);
	return (value);
}

/**/
irqreturn_t mgpm_intr_handler(int irq, void *arg);
static ssize_t mgpm_write(struct file *filp, const char *buf, size_t count, loff_t *f_pos);

//static char dev_name[] = "MCST,mgpm";
#define MGPM_NAME	"MCST,mgpm"
#define MGPM_DIR	"mgpm"

static int  mgpm_nr_devs;
mgpm_dev_t *mgpm_devices[MAX_MGPM];

static int major = 0;		/* default to dynamic major */
module_param(major, int, 0);
MODULE_PARM_DESC(major, "Major device number");


/********************/
/*typedef long long hrtime_t;*/

hrtime_t gethrtime(int p) 
{
	struct timeval tv;
	hrtime_t val;

	do_gettimeofday(&tv);
	val = tv.tv_sec * 1000000000LL + tv.tv_usec * 1000LL;
	return (val);
}
/******************/



static int mgpm_open(struct inode *inode, struct file *filp)
{
	mgpm_dev_t *dev;
	int minor = MINOR(inode->i_rdev);

	dbgmgpm("Open\n");
	dev = (mgpm_dev_t *)filp->private_data;
	if (!dev) {
		if ( minor >= mgpm_nr_devs )
			return -ENODEV;
		dev = mgpm_devices[minor];
		if ( dev->opened ) {
			printk("WARNING:open:\tre-open device\n");
			return -EBUSY;
		} else {
			dev->opened = 1;
		}

		filp->private_data = dev;
	}
	dbgmgpm("Open. Ok.%s %s\n",__TIME__,__DATE__);

    return 0;
}

static int mgpm_release(struct inode *inode, struct file *filp)
{
	mgpm_dev_t *dev;
	int minor = MINOR(inode->i_rdev);
	
	dbgmgpm("Close\n");
	if ( minor >= mgpm_nr_devs )
	        return -ENODEV;
	dev = mgpm_devices[minor];
	dev->opened = 0;
	filp->private_data = NULL;

	put_mgpm_reg(dev, MGPM_INTR_FEQ_REG,0);
	put_mgpm_reg(dev, MGPM_CLR_INTR_MASK,0);
	put_mgpm_reg(dev, MGPM_CLEAR_INTR_CNT,0);
	put_mgpm_reg(dev, MGPM_CLEAR_INTR_DMA,0);
	put_mgpm_reg(dev, MGPM_RESET,1);

	dbgmgpm("Close. Ok.\n");

    return 0;
}

static long mgpm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	mgpm_dev_t                *dev;
	long ret;

	lock_kernel();

	dev = (mgpm_dev_t *)filp->private_data;
	switch (cmd) {
		case MCST_SELFTEST_MAGIC:
		{
			int rval;
			selftest_t st;
			selftest_pci_t *st_pci = &st.info.pci;

			st.bus_type = BUS_PCI;

			struct pci_dev *pdev = dev->pdev;
			st_pci->vendor = pdev->vendor;
			st_pci->device = pdev->device;

			st_pci->major = MAJOR(inode->i_rdev);
			st_pci->minor = MINOR(inode->i_rdev);

			st_pci->bus = pdev->bus->number; 
			st_pci->slot = PCI_SLOT(pdev->devfn);
			st_pci->func = PCI_FUNC(pdev->devfn);
			st_pci->class = pdev->class;

			strcpy(st_pci->name, MGPM_NAME);

//			printk("%s: name [%s]. vendor = %#x, device = %#x. major = %d, minor = %d. bus = %d, slot = %d, func = %d, class = %#x\n", __func__,
//				st_pci->name, st_pci->vendor, st_pci->device, st_pci->major, st_pci->minor, st_pci->bus, st_pci->slot, st_pci->func, st_pci->class);

			rval = copy_to_user((void *)arg, (void *)&st, sizeof(selftest_t));
			if ( rval != 0 ) {
				printk( "%s: MCST_SELFTEST_MAGIC: copy_to_user() failed\n", __func__);
				ret = -EFAULT;
				goto out;
			}
			ret = 0;
			goto out;
		}

		case MGPM_IOC_RESET_DEVICE:
			put_mgpm_reg(dev, U0KMKP_REG_ADR,1);		
			ret = 0;
			goto out;

		case MGPM_IOC_WAIT_MODE: {
			int mode;
			dbgmgpm("MGPM_IOC_WAIT_MODE\n");
			if ( copy_from_user( (void *)&mode, (const void __user *)arg, sizeof (int)) ) {
				printk("WARNING:mgpm_ioctl :MGPM_IOC_WAIT_MODE "
							"drv_copyin failure\n");
				ret = -EINVAL;
				goto out;
			}
			/* TODO: only ioctl wait mode is implemented now.*/
			if(mode == 1) {
				mode = 0;
			} else {
				mode = 0;
			}
			if (copy_to_user((int __user *)arg, &mode, sizeof(int))) {
				printk("WARNING:mgpm_ioctl :MGPM_IOC_WAIT_MODE "
							"drv_copyout failure\n");
				ret = -EFAULT;
				goto out;
			}
			ret = 0;
			goto out;
		}
		
		case MGPM_IOC_IOCTL_WAIT: {
			long time_out;
			dbgmgpm("MGPM_IOC_IOCTL_WAIT\n");
			if ( copy_from_user( (void *)&time_out, (const void __user *)arg, sizeof (long)) ) {
				printk("WARNING:mgpm_ioctl :MGPM_IOC_IOCTL_WAIT drv_copyoin failure\n");
				ret = -EINVAL;
				goto out;
			}
			dbgmgpm("MGPM_IOC_IOCTL_WAIT set_timeout %ld\n",time_out);
			while (dev->intr_in_completed == 0) {
#if 0
				int timed_out;
				timed_out = interruptible_sleep_on_timeout(&dev->wait_intr_fin_queue,time_out*HZ*10);
				if (timed_out) {
					printk("MGPM_IOC_IOCTL_WAIT ERROR - TIME OUT\n");
					return -ERESTARTSYS;
				}
#else
				interruptible_sleep_on(&dev->wait_intr_fin_queue);
#endif
			}

			dev->times[dev->stat_size].ptime = gethrtime(0);
			//printk("r = %lld\n", get_usec_from_start_sync());
	//  		printk("int : %lld\n",dev->times[dev->stat_size].btime);

	// 		if (dev->stat_size < MAX_NUM_EL)
	// 			dev->stat_size++;

			dev->intr_in_completed = 0;
			dbgmgpm("MGPM_IOC_IOCTL_WAIT OK CPU %d\n",smp_processor_id());
			ret = 0;
			goto out;
		}

		case 0x111111: {
			
			printk("!!!!!! MGPM_CLEAR_INTR_CNT %x, MGPM_INTR_REG %x MGPM_INTR_FEQ_REG %x\n", 
					get_mgpm_reg(dev, MGPM_CLEAR_INTR_CNT),
					get_mgpm_reg(dev, MGPM_INTR_REG),
					get_mgpm_reg(dev,MGPM_INTR_FEQ_REG));

			ret = 0;
			goto out;
		}

		case MGPM_IOC_START_TR: {
			dev->stat_size = 0;
			ret = 0;
			goto out;
		}

		case MGPM_IOC_GET_TR_SZ: {
			int size = dev->stat_size;
			if (copy_to_user((int __user *)arg, &size, sizeof(int))) {
				printk("WARNING:mgpm_ioctl :MGPM_IOC_GET_TR_SZ "
							"drv_copyout failure\n");
				ret = -EFAULT;
				goto out;
			}

			ret = 0;
			goto out;
		}

		case MGPM_IOC_SET_FREQUENCY: {
			/* Set freq and start generate interrupts */
			int freq;
			dbgmgpm("MGPM_IOC_SET_FREQUENCY\n");
			if ( copy_from_user( (void *)&freq, (const void __user *)arg, sizeof (int)) ) {
				printk("WARNING:mgpm_ioctl :MGPM_IOC_SET_FREQUENCY "
							"drv_copyoin failure\n");
				ret = -EINVAL;
				goto out;
			}

			if ( freq <= 0 ) {
				printk("WARNING:mgpm_ioctl :MGPM_IOC_SET_FREQUENCY: "
							"Frequency must be >= 0\n");
				ret = -EINVAL;
				goto out;
			}

			dbgmgpm("Freq = %d Hz\n",freq);
			/**XXX: This is hardware adjust hack */
			freq = (int)(20000/freq);
			if ( freq <= 0 ) {
				printk("WARNING:mgpm_ioctl :MGPM_IOC_SET_FREQUENCY: "
							"Frequency must be >= 0\n");
				ret = -EINVAL;
				goto out;
			}

			dbgmgpm("Freq = %d for mgpm\n",freq);

			put_mgpm_reg(dev, MGPM_INTR_FEQ_REG,freq);
			put_mgpm_reg(dev, MGPM_CLR_INTR_MASK,1);

			dbgmgpm("MGPM_INTR_FEQ_REG 0x%x\n", get_mgpm_reg(dev,MGPM_INTR_FEQ_REG));

			ret = 0;
			goto out;
		}

		case MGPM_IOC_SET_DEBUG_MODE: {
			int debug_mode;
			
			dbgmgpm("WARNING:mgpm_ioctl :MGPM_IOC_SET_DEBUG_MODE \n");
			if ( copy_from_user( (void *)&debug_mode, (const void __user *)arg, sizeof (int)) ) {
				printk("WARNING:mgpm_ioctl :MGPM_IOC_SET_DEBUG_MODE "
							"drv_copyoin failure\n");
				ret = -EINVAL;
				goto out;
			}
			if ( debug_mode >= 0 ) {
				dbgmgpm("WARNING:mgpm_ioctl :MGPM_IOC_SET_DEBUG_MODE set debug mode 0x%x\n",debug_mode);
				mgpm_debug = debug_mode;
			} else {
				mgpm_debug = 0;
				dbgmgpm("WARNING:mgpm_ioctl :MGPM_IOC_SET_DEBUG_MODE "
							"invalid debug mode. %d\n",debug_mode);
			}
			ret = 0;
			goto out;
		}

		case MGPM_IOC_HALT_DEVICE:
			dev->device_type = NONE_TYPE;
			put_mgpm_reg(dev, MGPM_RESET,1);

			ret = 0;
		default:
			ret = -ENOTTY;
	}
out:
	unlock_kernel();
	return ret;
}

static ssize_t mgpm_read(struct file *filp, char *buf, size_t count, loff_t *f_pos)
{
	int		i;
	int		size_or_code;
	mgpm_dev_t	*dev = (mgpm_dev_t *)filp->private_data;
// 	int		timed_out;

	dbgmgpm("mgpm_read start\n");
	if (down_interruptible(&dev->sem))
		return -ERESTARTSYS;

	size_or_code = (count<DEVICE_BUF_BYTE_SIZE)?count:DEVICE_BUF_BYTE_SIZE;
	count = size_or_code;

	/* translate bytes to words */
	
	if ( size_or_code % sizeof(int) != 0 || size_or_code < sizeof(int)) {
		size_or_code = size_or_code / sizeof(int);
		size_or_code++;
	} else {
		size_or_code = size_or_code / sizeof(int);
	}

	/*local_irq_disable();*/

        while (dev->trans_completed == 0) {
		up(&dev->sem);
// 		interruptible_sleep_on_timeout(&dev->wait_trans_fin_queue,100*HZ);
		interruptible_sleep_on(&dev->wait_trans_fin_queue);
/*		if (dev->trans_completed == 0) {
			printk("DMA READ ERROR - TIME OUT\n");
			return -ERESTARTSYS;
		}
*/
		if (down_interruptible(&dev->sem))
			return -ERESTARTSYS;
	}

	dev->trans_completed = 0;
	
	for(i = 0;i < (int)size_or_code; i++) {
		int *point = (int*)(dev->buf_dma_adr[1]);
		dbgmgpm("READ 0x%x \n",point[i]);
	}
	if (copy_to_user(buf, dev->buf_dma_adr[1], count)) {
		up(&dev->sem);
		return -EFAULT;
	}

	up(&dev->sem);
	dbgmgpm("mgpm_read finish\n");
	return count;
}

static ssize_t mgpm_write(struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
	int 		i;
	int		size_or_code;
	mgpm_dev_t	*dev = (mgpm_dev_t *)filp->private_data;
	
	dbgmgpm("mgpm_write start\n");
	if (down_interruptible(&dev->sem)) {
	    return -ERESTARTSYS;
	}wmb();
	
	if (copy_from_user(dev->buf_dma_adr[0], buf, count)) {
	    up(&dev->sem);
	    return -EFAULT;
	}
	
	size_or_code = (count<DEVICE_BUF_BYTE_SIZE)?count:DEVICE_BUF_BYTE_SIZE;
	count = size_or_code;

	/* translate bytes to words */
	if ( size_or_code % sizeof(int) != 0 || size_or_code < sizeof(int)) {
		size_or_code = size_or_code / sizeof(int);
		size_or_code++;
	} else {
		size_or_code = size_or_code / sizeof(int);
	}
	if(mgpm_debug) {
		printk("mgpm_write: size_or_code %d\n",size_or_code);
		for(i = 0; i < size_or_code; i++) {
			printk("%d: wrb 0x%x\n",i,dev->buf_dma_adr[0][i]);
		}
		for(i = 0;i < (int)size_or_code; i++) {
			int *point = (int*)(dev->buf_dma_adr[1]);
			point[i] = 0xfefefefe;
			printk("rd 0x%x \n",point[i]);
		}	
	}

	dev->batch_dma_adr[0] = 0x40000000 | size_or_code;
	dev->batch_dma_adr[1] = 0xa0000000 | size_or_code;

	put_mgpm_reg(dev, BATCH_CMD_ADR_REG_ADR,dev->batch_bus_addr);
	
	put_mgpm_reg(dev, MGPM_ADDR_WRITE,dev->bus_addr[0]);
	put_mgpm_reg(dev, MGPM_ADDR_READ,dev->bus_addr[1]);
	
	local_irq_disable();
	put_mgpm_reg(dev, BATCH_CMD_QUANTITY_REG_ADR,1);
	dev->times[dev->stat_size].s_dma_t = gethrtime(0);// gethrtime();

	if(mgpm_debug) {
		printk("\n#####mgpm_write BK (0x%x)0: 0x%x 1: 0x%x\n",
					get_mgpm_reg(dev,BATCH_CMD_ADR_REG_ADR),
					get_mgpm_reg(dev,0x1000),get_mgpm_reg(dev,0x1004));
		printk("mgpm_write START TRANSFER\n");
	}

	up(&dev->sem);

	if(mgpm_debug) {
		printk("mgpm_write BK 0: 0x%x 1: 0x%x\n",
				get_mgpm_reg(dev, 0x1000),get_mgpm_reg(dev, 0x1004));

		printk("W 0x%x R 0x%x\n", get_mgpm_reg(dev, 0x1600),get_mgpm_reg(dev, 0x1604));
		printk("mgpm_write finish\n");
	}

	local_irq_enable();
	return count;
}

static unsigned int mgpm_poll(struct file *filp, struct poll_table_struct *wait)
{
    mgpm_dev_t       *dev;
    mgpm_io_word_t   command_word;
    unsigned int     mask = 0;

    dev = (mgpm_dev_t *)filp->private_data;
    poll_wait(filp, &dev->wait_trans_fin_queue, wait);
    if ( dev->trans_completed == 1 ) {
	dev->trans_completed = 0;
	command_word = (dev->batch_dma_adr[0] & 0xffff0000) >> 16;       /**** REMEMBER: FOR ONE COMMAND ****/
	dev->term_dev_adress = (command_word & TERM_DEV_ADR_POS) >> 11;
	dev->subadress = (command_word & SUBADRESS_POS) >> 5;
	if (dev->subadress == MIN_SUBADRESS  ||  dev->subadress == MAX_SUBADRESS)
	    dev->size_or_code.cntrl_com_code = command_word & SIZE_CODE_POS;
	else
	    dev->size_or_code.byte_msg_size = 2*((command_word & SIZE_CODE_POS) == 0 ? MAX_CHANNEL_MSG_SIZE : command_word & SIZE_CODE_POS);
	if ( (command_word & COMMAND_BIT_POS) == 0 )
	    dev->term_trans_direction = TERM_DEV_READ;
	else
	    dev->term_trans_direction = TERM_DEV_WRITE;
	mask |= POLLIN;
    }
    return mask;
}

static int mgpm_mmap(struct file *filp, struct vm_area_struct *vma)
{
	mgpm_dev_t	*dev;
	unsigned long	mem_start;
	unsigned long	offset = (vma->vm_pgoff << PAGE_SHIFT);
   	unsigned long 	vm_start;

	dev = (mgpm_dev_t *)filp->private_data;
	dbgmgpm("mgpm mmap: start\n");
	mem_start = virt_to_phys((char *)dev->times);
	mem_start += (vma->vm_pgoff << PAGE_SHIFT);
   	vm_start = vma->vm_start;
 
   	vma->vm_flags |= (VM_READ | VM_WRITE | VM_IO | VM_RESERVED);


	dbgmgpm("mgpm mmap:\tmem: %#x; off: %#x; off_r: %#x; st: %#x; en: %#x\n"
	       "\t\t\tmof: %#x; sof: %#x; st_en: %#x; sz: %#x; \n",
	       (u_int)mem_start,
	       (u_int)vma->vm_pgoff,
	       (u_int)offset,
	       (u_int)vma->vm_start,
	       (u_int)vma->vm_end,
	       (u_int)(mem_start + offset),
	       (u_int)(vma->vm_start + offset),
	       (u_int)(vma->vm_end - vma->vm_start),
	       (u_int) MGPM_ST_TIMES_SIZE);

	dbgmgpm("pol time  %lld\nbeg time %lld\n endint %lld (%d)(%x)\n",
				dev->times[dev->stat_size].ptime,
				dev->times[dev->stat_size].btime,
				dev->times[dev->stat_size].time,
				(int)(dev->times[dev->stat_size].time - dev->times[dev->stat_size].btime),(int)(dev->times[dev->stat_size].ptime));


	if ( (vma->vm_start + offset) > vma->vm_end ) {
		printk("mmap:\terror offset more than size\n");    
		return -ENXIO;
	}

	if (remap_pfn_range(vma, vm_start, (mem_start >> PAGE_SHIFT), 
					vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
		printk("mgpm mmap:\terror remap memory to user\n");    
		return -EAGAIN;
	}

	return 0;
}


/*static void*/
irqreturn_t
mgpm_intr_handler(int irq, void *arg)
{
	mgpm_dev_t	*dev = (mgpm_dev_t *) arg;
	u_int		reg,timereg;
	hrtime_t	t_beg = gethrtime(1);

	if ( dev == NULL )
		return (IRQ_NONE);

	/* Get current time and check for interrupt. */
	timereg = get_mgpm_reg(dev, MGPM_CLEAR_INTR_CNT);
	reg = get_mgpm_reg(dev, MGPM_INTR_REG);

	//dbgmgpm("mgpm_intr_handler MGPM_INTR_REG 0x%8x \n",get_mgpm_reg(dev, MGPM_INTR_REG));

	if ( (reg & 0xC0) == 0 ) {
		/* Must be not for us */
		return (IRQ_NONE);
	}

	if ( reg & 0x80 /*CNTR*/) {
		/* Get time in nano sec */
		dev->times[dev->stat_size].intr_time = ((timereg >> 8) & 0x7FFF);
		dev->times[dev->stat_size].intr_counter = (( timereg >> 24 ) & 0x7f);
		dev->times[dev->stat_size].intr_num++;

		/* Clear interrupt */
		put_mgpm_reg(dev, MGPM_CLEAR_INTR_CNT,0);

 		dev->times[dev->stat_size].time = gethrtime(1);
		dev->times[dev->stat_size].btime = t_beg;

		//dbgmgpm("MGPM_INTR_FEQ_REG 0x%x timereg 0x%x (time %lld)\n",	get_mgpm_reg(dev, MGPM_INTR_FEQ_REG),timereg,dev->times[dev->stat_size].time);

/** TODO: do mutex here */
		dev->intr_in_completed = 1;
/** */
		wake_up_interruptible(&dev->wait_intr_fin_queue);
	}

	if ( reg & 0x40 /* DMA */) {
		dbgmgpm("DMA Interrupt.\n");
		dev->times[dev->stat_size].e_dma_t = 0;//gethrtime(1);
		put_mgpm_reg(dev, MGPM_CLEAR_INTR_DMA,0);
/** TODO: do mutex here */
		dev->trans_completed = 1;
/** */
		wake_up_interruptible(&dev->wait_trans_fin_queue);
	}
	return IRQ_HANDLED;
}

void __you_cannot_kmalloc_that_much(void) 
{
/* If one will compile this driver with -O2 optimisation
 * then remove this declaration. This one is usefull only when 
 * optimisationless compile in use.
 */
}

static void * mgpm_rvmalloc(unsigned long size)
{
	void * mem;
	struct page *map, *mapend;
	unsigned long order;

	size=PAGE_ALIGN(size);
	order = get_order(size);
	size  = PAGE_SIZE << order;	

	mem = (void *) __get_free_pages(GFP_KERNEL | GFP_DMA, order);

	if (!mem)
		return NULL;
	memset(mem, 0, size); /* Clear the ram out, no junk to the user */
	
	mapend = virt_to_page (mem + (PAGE_SIZE << order) - 1);
	for (map = virt_to_page(mem); map <= mapend; map++) {
			SetPageReserved(map);
	}

	return mem;
}
 
static void mgpm_rvfree(void * mem, unsigned long size)
{
	unsigned long order;
	struct page *map, *mapend;
 
	if (!mem) 
		return;
	size=PAGE_ALIGN(size);
	order = get_order(size);
	size  = PAGE_SIZE << order;

	order = get_order(size);
	mapend = virt_to_page(mem + (PAGE_SIZE << order) - 1);
	for (map = virt_to_page(mem); map <= mapend; map++) {
		ClearPageReserved(map);
	}
	free_pages((unsigned long)mem, order);
}
 
static struct file_operations mgpm_fops = {
    owner:   THIS_MODULE,
    open:    mgpm_open,
    release: mgpm_release,
    read:    mgpm_read,
    write:   mgpm_write,
    unlocked_ioctl:   mgpm_ioctl,
    poll:    mgpm_poll,
    mmap:    mgpm_mmap,
};


static int __init mgpm_init(void)
{
    struct pci_dev *pdev = NULL;
    mgpm_dev_t   *dev;
    dev_t	dev_mn;
    int result = 0;
    int cur_word;
    int cur_buf_num;

    int i;

	mgpm_sysctl_register();

    dbgmgpm("\t\tINSTALLATION  MGPM  DEVICE DRIVER\n");

  /*  if (!pci_present())
        return -ENODEV;*/
    result = alloc_chrdev_region(&dev_mn, 0, MAX_MGPM, MGPM_NAME);
    if (result < 0) {
    	printk(KERN_WARNING "mgpm: can't get major %d\n", major);
    	return result;
    }

    if (!major) {
		major = MAJOR(dev_mn);
		printk(KERN_DEBUG pci_dev_name ": got dynamic major %d\n", major);
    }
    mgpm_nr_devs = 0;
    while ((pdev = pci_get_device(VENDOR_MCST, MGPM_DEVICE_ID, pdev)) != NULL) {
#ifdef __sparc__
	pci_write_config_dword(pdev, 0x40, 1);
#endif
	if ( pci_set_dma_mask(pdev, 0xffffffff) != 0 ) {
	    printk("!!! pci_set_dma_mask cannot set mask 0xffffffff.\n");
	    continue;
	}

	if ( (dev = kmalloc(sizeof(mgpm_dev_t), GFP_KERNEL)) < 0 ) {
	    printk("!!! Cannot allocate memory for mgpm_dev_t.\n");
	    return -ENOMEM;
	}

	memset(dev, 0, sizeof(mgpm_dev_t));
	dev->pdev = pdev;
	dev->dev = dev_mn;
	dev->device_type = NONE_TYPE;
	dev->opened = 0;
	//dev->irq = pdev->irq | 0x20;
	dev->irq = pdev->irq;
	dev->trans_completed = 0;
	dbgmgpm("%d DEV IRQ = x%x PDEV = 0x%x.\n", mgpm_nr_devs,dev->irq ,pdev->irq);

	/* allocate memory for time results */
	dev->times = mgpm_rvmalloc((unsigned long)MGPM_ST_TIMES_SIZE*MAX_NUM_EL);
	if (dev->times == NULL) {
        	printk(KERN_WARNING "MGPM: Can't alloc memory for stat.\n");
		return 0;
	}
	
	dev->stat_size = 0;
	/* No Junk for user */
	memset(dev->times, 0x0, MGPM_ST_TIMES_SIZE*MAX_NUM_EL);

	/* Semafor init */
	init_waitqueue_head(&dev->wait_trans_fin_queue);
	init_waitqueue_head(&dev->wait_intr_fin_queue);
	
	sema_init(&dev->sem, 1);

	/*Regs map*/
	dev->device_mem_start = (u32*) ioremap( pci_resource_start(pdev, 0), pci_resource_len(pdev, 0) );

	dev->batch_dma_adr = (u32*) pci_alloc_consistent(pdev, BATCH_BUF_BYTE_SIZE, &dev->batch_bus_addr);
	if ( dev->batch_dma_adr == NULL )
		printk("!!! Cannot pci_alloc_consistent for command batch buffer, device #%d\n", mgpm_nr_devs);

	dev->buf_dma_adr[0] = (u32*) pci_alloc_consistent(pdev, 
						DEVICE_BUF_BYTE_SIZE*DEVICE_BUF_QUANTITY, &dev->bus_addr[0]);
	if ( dev->buf_dma_adr[0] == NULL )
		printk("!!! Cannot pci_alloc_consistent for device buffer, device #%d, buffer #%d\n", mgpm_nr_devs, 0);

	for ( cur_buf_num = 1; cur_buf_num < DEVICE_BUF_QUANTITY; cur_buf_num++ ) {
		dev->buf_dma_adr[cur_buf_num] = dev->buf_dma_adr[0] + DEVICE_BUF_BYTE_SIZE / sizeof(u32) * cur_buf_num;
		dev->bus_addr[cur_buf_num] = dev->bus_addr[0] + DEVICE_BUF_BYTE_SIZE * cur_buf_num;
	}

	put_mgpm_reg(dev, U0KMKP_REG_ADR, 1);
	for ( cur_word = 0; cur_word < DEVICE_MEM_WORD_SIZE; cur_word++ )
		put_mgpm_reg(dev, cur_word,DEVICE_MEM_CLEAR);

	{ 
		int devno = MKDEV(major, mgpm_nr_devs);
		cdev_init(&dev->cdev, &mgpm_fops);
		dev->cdev.owner = THIS_MODULE;
		dev->cdev.ops = &mgpm_fops;

		result = cdev_add (&dev->cdev, devno, 1);

		if ( result != 0 ) {
	    		printk(KERN_WARNING "mgpm: cannot add device to the system \n");
	    		return result;
		}
	}
	mgpm_devices[mgpm_nr_devs] = dev;

	/* INCREMENT DEVICE NUMBER */
	mgpm_nr_devs++;
    }

    dbgmgpm("%d MGPM DEVICES ARE AVAILABLE.\n", mgpm_nr_devs);
    if ( mgpm_nr_devs > 0 ) {
	if ( major == 0 )
	    major = result;
	dbgmgpm("MGPM MAJOR NUMBER IS %d.\n", major);
    }
    else {
        printk(KERN_WARNING "MGPM: REGISTER_CHRDEV DID NOT EXECUTE.\n");
	return 0;
    }

    for ( i = 0; i < mgpm_nr_devs; i++ )
    {
	if ( request_threaded_irq(mgpm_devices[i]->irq, &mgpm_intr_handler, NULL, IRQF_SHARED, MGPM_NAME, (void *)mgpm_devices[i]) ) {
	    printk("Cannot register interrupt handler %s.\n", MGPM_NAME);
	    return -EAGAIN;
        }
	if(1){ // Create nodes
		int mode;
		dev_t	devt;
		char nod[128];
		mode = (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

		devt = (MAJOR(dev_mn) << 8) | i;

#if defined(VER_2614)
		sprintf(nod,"/dev/mgpm%d", i);

		mode |= S_IFCHR;

		if (mk_mknod(nod, mode, devt)  == -EEXIST) {
// 			printk("mknod: node %s exist, removing in and then creating again\n", nod);

			mk_unlink(nod);
			if (mk_mknod(nod, mode, devt) != 0)  {
				printk("mk_create_minor: creating node %s failed\n", nod);
				return -1;
			}
		}
#else
		sprintf(nod, "mgpm_%d", i);
	
		if (drv_create_minor(MGPM_DIR, nod, S_IFCHR, devt)) {
			printk(KERN_ERR "INST %d. "
				"%s(): mod_create_minor() failed\n",
				mgpm_nr_devs, __func__);
			return -1;
		}
#endif


		
	}
    }
	return 0;
}

static void __exit mgpm_exit(void)
{
     int i;

     for (i = 0; i < mgpm_nr_devs; i++)

     unregister_chrdev_region(mgpm_devices[0]->dev, MAX_MGPM);

     for (i = 0; i < mgpm_nr_devs; i++) {
	free_irq(mgpm_devices[i]->irq, mgpm_devices[i]);
	pci_free_consistent(mgpm_devices[i]->pdev, BATCH_BUF_BYTE_SIZE, (void *)mgpm_devices[i]->batch_dma_adr, mgpm_devices[i]->batch_bus_addr);

	pci_free_consistent(mgpm_devices[i]->pdev, DEVICE_BUF_BYTE_SIZE*DEVICE_BUF_QUANTITY, (void *)mgpm_devices[i]->buf_dma_adr[0], mgpm_devices[i]->bus_addr[0]);

	/* clear pages reserved & free mem */
	mgpm_rvfree(mgpm_devices[i]->times, (unsigned long)MGPM_ST_TIMES_SIZE*MAX_NUM_EL);

	kfree(mgpm_devices[i]);
    }

	mgpm_sysctl_unregister();

    return;
}

/****************************** !!!!!!!!!!! *******************/

#if defined(VER_2614)
int mk_unlink(char *filename)
{	
	int error = 0;
	char *name;
	struct dentry *dentry;
	struct nameidata nd;
	struct inode *inode = NULL;


	name = __getname();
	audit_getname(name);
	if (!name){
		name = ERR_PTR(-ENOMEM);
		error = PTR_ERR(name);
	}
	if(IS_ERR(name))
		return PTR_ERR(name);

	sprintf(name, "%s", filename);
	error = path_lookup(name, LOOKUP_PARENT, &nd);
	if (error) {
		printk("mk_unlink: path_lookup() ret error %s %d\n", name, error);
		goto exit;
	}
	error = -EISDIR;
	if (nd.last_type != LAST_NORM)
		goto exit1;
	down(&nd.dentry->d_inode->i_sem);
	dentry = lookup_hash(&nd.last, nd.dentry);
	error = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
		/* Why not before? Because we want correct error value */
		if (nd.last.name[nd.last.len])
			goto slashes;
		inode = dentry->d_inode;
		if (inode)
			atomic_inc(&inode->i_count);
		error = vfs_unlink(nd.dentry->d_inode, dentry);
	exit2:
		dput(dentry);
	}
	up(&nd.dentry->d_inode->i_sem);
exit1:
	path_release(&nd);
exit:
	putname(name);

	if (inode)
		iput(inode);	/* truncate the inode here */
	return error;

slashes:
	error = !dentry->d_inode ? -ENOENT :
		S_ISDIR(dentry->d_inode->i_mode) ? -EISDIR : -ENOTDIR;
	goto exit2;
}


int mk_rm_dir(char *dir)
{
	int error = 0;
	char * name;
	struct dentry *dentry;
	struct nameidata nd;
	
	if (dir == NULL) {
		printk("mk_rm_dir: dir == NULL\n");
		return -EFAULT;
	}

	name = __getname();
	audit_getname(name);
	if (!name){
		name = ERR_PTR(-ENOMEM);
		error = PTR_ERR(name);
	}

	if(IS_ERR(name))
		return PTR_ERR(name);

	sprintf(name, "%s", dir);

	error = path_lookup(name, LOOKUP_PARENT, &nd);
	if (error) {
		printk("mk_rm_dir: path_lookup() ret error %s %d\n", name, error);
		goto exit;
	}
	
	switch(nd.last_type) {
		case LAST_DOTDOT:
			error = -ENOTEMPTY;
			goto exit1;
		case LAST_DOT:
			error = -EINVAL;
			goto exit1;
		case LAST_ROOT:
			error = -EBUSY;
			goto exit1;
	}

	down(&nd.dentry->d_inode->i_sem);

	dentry = lookup_hash(&nd.last, nd.dentry);
	error = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
		error = vfs_rmdir(nd.dentry->d_inode, dentry);
		dput(dentry);
	}
	up(&nd.dentry->d_inode->i_sem);
exit1:	
	path_release(&nd);
exit:
	putname(name);
	return error;
}

int mk_mkdir(char *pathname, int mode)
{
	int 			error = 0;
	char 			*tmp;
	struct dentry 		*dentry;
	struct nameidata 	nd;

	if (pathname == NULL) {
		printk("mk_mkdir: pathname == NULL ret -EFAULT\n");
		return -EFAULT;
	}

	tmp = __getname();
	audit_getname(tmp);
	if (!tmp) {
		tmp = ERR_PTR(-ENOMEM);
		error = PTR_ERR(tmp);
	}
	if (!IS_ERR(tmp)) {
		sprintf(tmp, "%s", pathname);
		error = path_lookup(tmp, LOOKUP_PARENT, &nd);
		if (error) {
			printk("mk_mkdir: path_lookup() ret error %d\n", error);
			goto out;
		}
		dentry = lookup_create(&nd, 1);
		error = PTR_ERR(dentry);
		if (!IS_ERR(dentry)) {
			if (!IS_POSIXACL(nd.dentry->d_inode))
				mode &= ~current->fs->umask;
			error = vfs_mkdir(nd.dentry->d_inode, dentry, mode);
			dput(dentry);
		}
		up(&nd.dentry->d_inode->i_sem);
		path_release(&nd);
out:
		putname(tmp);
	}
		return error;
}


extern asmlinkage long sys_mknod(const char * filename, int mode, dev_t dev);
int mk_mknod(char *filename, int mode, dev_t dev)
{
	int error = 0;
	char *tmp;
	struct dentry * dentry;
	struct nameidata nd;
	
	if (filename == NULL) {
		printk("mk_mknod: filename == NULL\n"); 
		return -EINVAL;
	}
	if (S_ISDIR(mode)) {
		printk("mk_mknod: S_ISDIR\n"); 
		return -EPERM;
	}

	tmp = __getname();
	audit_getname(tmp);
	if (!tmp){
		tmp = ERR_PTR(-ENOMEM);
		error = PTR_ERR(tmp);
	}
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	sprintf(tmp, "%s", filename);
	error = path_lookup(tmp, LOOKUP_PARENT, &nd);
	if (error){	
		printk("mk_mknod: path_lookup() ret error %s %d\n", tmp, error);
		goto out;
	}
	dentry = lookup_create(&nd, 0);
	error = PTR_ERR(dentry);
	if (!IS_POSIXACL(nd.dentry->d_inode))
		mode &= ~current->fs->umask;
	if (!IS_ERR(dentry)) {
		switch (mode & S_IFMT) {
		case 0: case S_IFREG:
				error = vfs_create(nd.dentry->d_inode,dentry,mode,&nd);
				break;
		case S_IFCHR: case S_IFBLK: 
				error = vfs_mknod(nd.dentry->d_inode,dentry,mode,new_decode_dev(dev));
				break;
		case S_IFIFO: case S_IFSOCK:
				error = vfs_mknod(nd.dentry->d_inode,dentry,mode,0);
				break;
		case S_IFDIR:
				error = -EPERM;
				break;
		default:
				error = -EINVAL;
		}
		dput(dentry);
	}
	up(&nd.dentry->d_inode->i_sem);
	path_release(&nd);
out:
	putname(tmp);

	return error;
}
#endif

//------------------------------------------------------------------------------------------------------------------------------------//

int drv_create_minor(char *dir, char *name, int type, dev_t dev) 
{
	int rval;
        char    node[MAX_DRV_NM_SZ];
	int mode;

        if ( strlen(dir) + strlen(name) + 2 > MAX_DRV_NM_SZ) {
                printk("len_name > MAX_DRV_NM_SZ\n");
                return -EFAULT;
        }
        rval = drv_create_dir(dir);
        if (rval) {
                printk("drv_create_minor: drv_create_dir failed rval %d\n",
                                                        rval);
                return (rval);
        }
        sprintf(node, "/dev/%s/%s", dir, name);
        mode = type | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
        rval = drv_mknod(node, mode, dev);
        if (rval) {
		if (rval == -EEXIST) {
			printk("drv_create_minor: node %s exist, removing then creating again\n", node);
			rval = drv_unlink(dir, name);
			if (rval) {
				printk("drv_create_minor: removing node %s failed\n", node);
			}
			rval = drv_mknod(node, mode, dev);
			if (rval) {
				printk("drv_create_minor: creating node %s failed\n", node);
			}
			return rval;
		}
	}

	return rval;	
}

static int drv_create_dir(char *dir)
{
	int	rval;
	mode_t 	mode;
	char	str[MAX_DRV_NM_SZ];

	if (dir == NULL) {
		printk("drv_create_dir: dir == NULL\n");
		return -EFAULT;
	}
	mode = (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);	
	sprintf(str, "/dev/%s", dir);

	rval = drv_mkdir(str, mode);
	if (rval) {
		if (rval == -EEXIST) {
			printk("drv_create_dir: directory %s exist\n", str);
			return 0;
		}	
		printk("drv_create_dir for %s rval %d\n", str, rval);
		return (rval);
	}
	
	return 0;
}

static int drv_mkdir(char *pathname, int mode)
{
	int 			error = 0;
	char 			*tmp;
	struct dentry 		*dentry;
	struct nameidata 	nd;

	if (pathname == NULL) {
		printk("drv_mkdir: pathname == NULL ret -EFAULT\n");
		return -EFAULT;
	}
/* getname */
	tmp = __getname();
	if (!tmp) {
		tmp = ERR_PTR(-ENOMEM);
		error = PTR_ERR(tmp);
	}
        audit_getname(tmp);
        if (IS_ERR(tmp))
		return PTR_ERR(tmp);
/**/
        sprintf(tmp, "%s", pathname);
	error = path_lookup(tmp, LOOKUP_PARENT, &nd);
	if (error) {
		printk("drv_mkdir: path_lookup() ret error %d\n", error);
		goto out;
	}
        
        dentry = lookup_create(&nd, 1);
	error = PTR_ERR(dentry);
        if (IS_ERR(dentry))
		goto out_unlock;

	if (!IS_POSIXACL(nd.path.dentry->d_inode))
		mode &= ~current_umask();
	error = mnt_want_write(nd.path.mnt);
	if (error)
		goto out_dput;
	error = security_path_mkdir(&nd.path, dentry, mode);
	if (error)
		goto out_drop_write;
	error = vfs_mkdir(nd.path.dentry->d_inode, dentry, mode);
out_drop_write:
	mnt_drop_write(nd.path.mnt);
out_dput:
	dput(dentry);
out_unlock:
        mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
	path_put(&nd.path);
out:        
	putname(tmp);
	return error;
}

static int drv_mknod(char *filename, int mode, dev_t dev)
{
	int error = 0;
	char *tmp;
	struct dentry * dentry;
	struct nameidata nd;
	
	if (filename == NULL) {
		printk("drv_mknod: filename == NULL\n"); 
		return -EINVAL;
	}
	if (S_ISDIR(mode)) {
		printk("drv_mknod: S_ISDIR\n"); 
		return -EPERM;
	}
/* getname */
	tmp = __getname();
	if (!tmp){
		tmp = ERR_PTR(-ENOMEM);
		error = PTR_ERR(tmp);
	}
        audit_getname(tmp);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);
/**/
	sprintf(tmp, "%s", filename);
	error = path_lookup(tmp, LOOKUP_PARENT, &nd);
	if (error){	
		printk("drv_mknod: path_lookup() ret error %d\n", error);
		goto out;
	}
	dentry = lookup_create(&nd, 0);
        if (IS_ERR(dentry)) {
		error = PTR_ERR(dentry);
		goto out_unlock;
	}
	if (!IS_POSIXACL(nd.path.dentry->d_inode))
		mode &= ~current_umask();
        error = may_mknod(mode);
	if (error)
		goto out_dput;
	error = mnt_want_write(nd.path.mnt);
	if (error)
		goto out_dput;
        error = security_path_mknod(&nd.path, dentry, mode, dev);
	if (error)
		goto out_drop_write;
	switch (mode & S_IFMT) {
	        case 0: case S_IFREG:
		        error = vfs_create(nd.path.dentry->d_inode,dentry,mode,&nd);
			break;
	        case S_IFCHR: case S_IFBLK: 
			error = vfs_mknod(nd.path.dentry->d_inode,dentry,mode,new_decode_dev(dev));
			break;
	        case S_IFIFO: case S_IFSOCK:
			error = vfs_mknod(nd.path.dentry->d_inode,dentry,mode,0);
			break;
	        case S_IFDIR:
			error = -EPERM;
			break;
	        default:
			error = -EINVAL;
	}

out_drop_write:
	mnt_drop_write(nd.path.mnt);
out_dput:
        dput(dentry);
out_unlock:
        mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
	path_put(&nd.path);
out:
        putname(tmp);

	return error;
}

int drv_unlink(char *dir, char *filename)
{
        int error = 0;
        char *name;
        struct dentry *dentry;
        struct nameidata nd;
        struct inode *inode = NULL;

	name = __getname();
	audit_getname(name);
	if (!name){
		name = ERR_PTR(-ENOMEM);
		error = PTR_ERR(name);
	}
	if(IS_ERR(name))
		return PTR_ERR(name);

	sprintf(name, "/dev/%s/%s", dir, filename);	
	error = path_lookup(name, LOOKUP_PARENT, &nd);
	if (error) {
		printk("drv_unlink: path_lookup() ret error %d\n", error);
		goto exit;
	}
	error = -EISDIR;
	if (nd.last_type != LAST_NORM)
		goto exit1;
	mutex_lock(&nd.path.dentry->d_inode->i_mutex);
	dentry = lookup_hash(&nd);
	error = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
		/* Why not before? Because we want correct error value */
		if (nd.last.name[nd.last.len])
			goto slashes;
		inode = dentry->d_inode;
		if (inode)
			atomic_inc(&inode->i_count);
		error = vfs_unlink(nd.path.dentry->d_inode, dentry);
	exit2:
		dput(dentry);
	}
	mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
exit1:
	path_put(&nd.path);
exit:
	putname(name);
	if (inode)
		iput(inode);	/* truncate the inode here */
	return error;

slashes:
	error = !dentry->d_inode ? -ENOENT :
		S_ISDIR(dentry->d_inode->i_mode) ? -EISDIR : -ENOTDIR;
	goto exit2;
}

static int may_mknod(mode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
	case 0: /* zero mode translates to S_IFREG */
		return 0;
	case S_IFDIR:
		return -EPERM;
	default:
		return -EINVAL;
	}
}


/****************************** !!!!!!!!!!! *******************/
module_init(mgpm_init);
module_exit(mgpm_exit);
MODULE_PARM_DESC  (major, "i");
MODULE_LICENSE    ("GPL");
MODULE_AUTHOR     ("Denis Fedotov");
MODULE_DESCRIPTION("MGPM device driver");

