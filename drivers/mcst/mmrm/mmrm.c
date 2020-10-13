/*
*
*
*
*/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/ioport.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/ioctl.h>
#include <linux/device.h>
/*
#ifndef CONFIG_PCI
#  error "This driver needs PCI support to be available"
#endif
*/
#ifdef __sparc__
#include <asm/idprom.h>
#include <asm/openprom.h>
#include <asm/oplib.h>
#include <asm/auxio.h>
#ifndef __sparc_v9__
#include <asm/io-unit.h>
#endif
#endif

#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/dma.h>
#include <asm/bitops.h>
#include <asm/byteorder.h>
#include <linux/mcst/ddi.h>

#include <linux/pci.h>
#ifdef __sparc__
#include <asm/pbm.h>
#endif

#include <linux/mcst/mmrm_io.h>
#include "mmrm.h"
#include <linux/mcst/mcst_selftest.h>

// /proc/sys/debug/mmrm_debug trigger
int mmrm_debug = 0;

#define	DBGMMRM_MODE
#undef DBGMMRM_MODE

#if defined(DBGMMRM_MODE)
#define	dbgmmrm			printk
#else
#define	dbgmmrm			if ( mmrm_debug ) printk
#endif

#define device_memory  dev->device_mem_start

#if defined(CONFIG_SYSCTL)
#include <linux/sysctl.h>

static ctl_table mmrm_table[] = {
	{
		.procname	= "mmrm_debug",
		.data		= &mmrm_debug, 
		.maxlen		= sizeof(mmrm_debug),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static ctl_table mmrm_root_table[] = {
	{
		.procname	= "debug",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= mmrm_table,
	},
	{ }
};

static struct ctl_table_header *mmrm_sysctl_header;


static void __init mmrm_sysctl_register(void)
{
	mmrm_sysctl_header = register_sysctl_table(mmrm_root_table);
}

static void mmrm_sysctl_unregister(void)
{
	if ( mmrm_sysctl_header )
		unregister_sysctl_table(mmrm_sysctl_header);
}

#else /* CONFIG_SYSCTL */

static void __init mmrm_sysctl_register(void)
{
}

static void mmrm_sysctl_unregister(void)
{
}
#endif

#if 1
static inline u32 _flip_dword(u32 l)
{
#if !defined(__e2k__)
	return ((l&0xff)<<24) | (((l>>8)&0xff)<<16) | (((l>>16)&0xff)<<8)| ((l>>24)&0xff);
#else
	return l;
#endif
}

void
mmrm_iowrite32(u32 b, void __iomem *addr)
{
	u32 fliped_b = _flip_dword(b);

	iowrite32(fliped_b, addr);
}

u32
mmrm_ioread32(void __iomem *addr)
{
	return _flip_dword(ioread32(addr));
}
#else
#define mmrm_iowrite32	iowrite32
#define mmrm_ioread32	ioread32
#endif

static char MMRM_NAME[] = "MCST,mmrm";
static int  mmrm_nr_devs;
mmrm_dev_t *mmrm_devices[MAX_MMRM];
int major = MMRM_MAJOR_DEFAULT;
static struct class *mmrm_class;

static int
mmrm_open(struct inode *inode, struct file *filp)
{
	mmrm_dev_t *dev;
	int minor = MINOR(inode->i_rdev);

	dev = (mmrm_dev_t *)filp->private_data;
    if ( !dev ) {
		if ( minor >= mmrm_nr_devs )
			return -ENODEV;
		dev = mmrm_devices[minor];
		dev->opened = 1;
		filp->private_data = dev;
    }
//    MOD_INC_USE_COUNT;
    return 0;
}

static int
mmrm_release(struct inode *inode, struct file *filp)
{
	mmrm_dev_t *dev;
	int minor = MINOR(inode->i_rdev);

	if ( minor >= mmrm_nr_devs )
		return -ENODEV;

	dev = mmrm_devices[minor];
	dev->opened = 0;
	filp->private_data = NULL;
//    MOD_DEC_USE_COUNT;
	
	return 0;
}

static long
mmrm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	mmrm_dev_t			*dev;
	unsigned int			channel;
	unsigned short			regim;
	mmrm_term_dev_adr_t		term_dev_adress;
	mmrm_cnt_sent_fields_t		sent_inform;
	desk_result_t			desk_result;
	mmrm_received_com_word_t	received_com_word;
	u_long				cur_clock_ticks;
	u_long				etime_clock_ticks;
	int				rval;

	dev = (mmrm_dev_t *)filp->private_data;

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

			strcpy(st_pci->name, MMRM_NAME);

//			printk("%s: name [%s]. vendor = %#x, device = %#x. major = %d, minor = %d. bus = %d, slot = %d, func = %d, class = %#x\n", __func__, st_pci->name, st_pci->vendor, st_pci->device, st_pci->major, st_pci->minor, st_pci->bus, st_pci->slot, st_pci->func, st_pci->class);

			rval = copy_to_user((void *)arg, (void *)&st, sizeof(selftest_t));
			if ( rval != 0 ) {
				printk( "%s: MCST_SELFTEST_MAGIC: copy_to_user() failed\n", __func__);
				return -EFAULT;
			}

			return 0;
		}
	    case MMRM_IOC_RESET_DEVICE:
			mmrm_iowrite32(1, &device_memory[U0KMKP_REG_ADR]);

			return 0;
	
		case MMRM_IOC_INIT_AS_CONTROLLER:
			channel = (unsigned int) arg;
			if (channel == 0)
				regim = CONTROLLER_TYPE | BLOCK_1_CHANNEL;
			else
			if (channel == 1)
				regim = CONTROLLER_TYPE | BLOCK_0_CHANNEL;
			else
				return -EINVAL;

			dev->device_type = CONTROLLER_TYPE;

			mmrm_iowrite32(regim, &device_memory[DEVICE_REGIM_REG_ADR]);

			return 0;

		case MMRM_IOC_INIT_AS_TERMINAL:
			term_dev_adress = (mmrm_term_dev_adr_t) arg;
			if ( term_dev_adress > MAX_TERM_DEV_ADRESS )
				return -EINVAL;
			regim = TERMINAL_TYPE | term_dev_adress << 11;
			dev->device_type = TERMINAL_TYPE;
			dev->term_dev_adress = term_dev_adress;
			mmrm_iowrite32(regim, &device_memory[DEVICE_REGIM_REG_ADR]);
			mmrm_iowrite32(1, &device_memory[BATCH_CMD_QUANTITY_REG_ADR]);

			return 0;

		case MMRM_IOC_INIT_AS_MONITOR:
			regim = MONITOR_TYPE;
			dev->device_type = MONITOR_TYPE;
			mmrm_iowrite32(regim, &device_memory[DEVICE_REGIM_REG_ADR]);

			return 0;

		case MMRM_IOC_HALT_DEVICE:
			dev->device_type = NONE_TYPE;
			mmrm_iowrite32(1, &device_memory[U0KMKP_REG_ADR]);

			return 0;

		case MMRM_IOC_WRITE_SENT_INFORM:
			if (copy_from_user(&sent_inform, (void *)arg,
					sizeof(mmrm_cnt_sent_fields_t))) {
				printk(KERN_ERR "%s: mmrm_%d "
					"MMRM_IOC_WRITE_SENT_INFORM: "
					"copy_from_user failed.\n", __func__,
					    dev->instance);
				return -EINVAL;
			}

			if ( sent_inform.term_dev_adress > MAX_TERM_DEV_ADRESS  ||  sent_inform.subadress > MAX_SUBADRESS )
				return -EINVAL;

			switch (sent_inform.fields_number) {
				case 3: dev->size_or_code.cntrl_com_code = sent_inform.cntrl_com_code;
				case 2: dev->term_dev_adress = sent_inform.term_dev_adress;
				case 1: dev->subadress = sent_inform.subadress;
					break;
				default:
					return -EINVAL;
			}

			return 0;

		case MMRM_IOC_GET_DESK_RESULT:
		{
			int batch_result_n = 0;
			unsigned char str_type[16];
			int error_was = 0;

			if (dev->device_type == CONTROLLER_TYPE) {
				batch_result_n = 8;
				strcpy(str_type, "controller");
			} else if (dev->device_type == TERMINAL_TYPE) {
				batch_result_n = 0;
				strcpy(str_type, "terminal");
			}
			if ((dev->batch_dma_adr[batch_result_n] &
					COMPLET_DESK_RES_SPOOL) != 0) {
				printk(KERN_ERR "mmrm_%d: %s "
					"MMRM_IOC_GET_DESK_RESULT "
					"is not completed.\n",
					dev->instance, str_type);
			    error_was = 1;
			}
			if (copy_from_user(&desk_result, (void *)arg,
					sizeof(desk_result_t))) {
				printk("%s: mmrm_%d MMRM_IOC_GET_DESK_RESULT: "
					"copy_from_user failed.\n", __func__,
					dev->instance);
				error_was = 1;
			}
			if ( dev->device_type == CONTROLLER_TYPE ) {
				/**** REMEMBER: FOR ONE COMMAND ****/
			    desk_result.high_half_desk_res.answer_word = (dev->batch_dma_adr[8] & 0xffff0000) >> 16;
			    desk_result.channel_check_word =
				dev->batch_dma_adr[8] & 0x0000ffff;
			} else if (dev->device_type == TERMINAL_TYPE) {
				/**** REMEMBER: FOR ONE COMMAND ****/
				desk_result.high_half_desk_res.command_word =
				(dev->batch_dma_adr[0] & 0xffff0000) >> 16;
				desk_result.channel_check_word =
					dev->batch_dma_adr[0] & 0x0000ffff;
			}
			if (copy_to_user((void *)arg, &desk_result,
					sizeof(desk_result_t))) {
				printk(KERN_ERR "%s: mmrm_%d "
					"MMRM_IOC_GET_DESK_RESULT: "
					"copy_to_user failed.\n", __func__,
					dev->instance);
			    error_was = 1;
			}
			dev->batch_dma_adr[batch_result_n] =
				COMPLET_DESK_RES_SPOOL;
			return (error_was == 0) ? 0 : -EFAULT;
		}

		case MMRM_IOC_GET_RECEIVED_COM:
			if ( copy_from_user(&received_com_word, (void *)arg, sizeof(mmrm_received_com_word_t)) ) {
				printk(KERN_ERR "%s: mmrm_%d "
					"MMRM_IOC_GET_RECEIVED_COM: "
					"copy_from_user failed.\n", __func__,
					    dev->instance);
				return -EINVAL;
			}

			received_com_word.term_dev_adress = dev->term_dev_adress;
			received_com_word.term_trans_direction = dev->term_trans_direction;
			received_com_word.subadress = dev->subadress;
			if (dev->subadress == MIN_SUBADRESS  ||  dev->subadress == MAX_SUBADRESS)
				received_com_word.size_or_code.cntrl_com_code = dev->size_or_code.cntrl_com_code;
			else
				received_com_word.size_or_code.byte_msg_size = dev->size_or_code.byte_msg_size;

			if ( copy_to_user((void *)arg, &received_com_word, sizeof(mmrm_received_com_word_t)) ) {
				printk(KERN_ERR "%s: mmrm_%d "
					"MMRM_IOC_GET_RECEIVED_COM: "
					"copy_to_user failed.\n", __func__,
					    dev->instance);
				return -EFAULT;
			}

			return 0;

		case MMRM_IOC_CNTRL_COM_SENDING:
			spin_mutex_enter(&dev->lock);
			dev->batch_dma_adr[0] = ((dev->subadress == 0) ? 0x00010000 : 0x003f0000) | dev->term_dev_adress << 24 | 2*dev->size_or_code.cntrl_com_code;
			drv_getparm(LBOLT, &cur_clock_ticks);
			etime_clock_ticks = cur_clock_ticks + drv_usectohz(MAX_COMMAND_TIME);
			mmrm_iowrite32(1, &device_memory[BATCH_CMD_QUANTITY_REG_ADR]);

			while (dev->trans_completed == 0) {
				rval = cv_spin_timedwait(&dev->intr_cv, &dev->lock, etime_clock_ticks);
				if (rval == -1) {
					printk(KERN_ERR "mmrm_%d: control command is not completed.\n"
							"Interrupt register %08x\n",
						dev->instance,
						mmrm_ioread32(&device_memory
							[INTERRUPT_REG_ADR]));
					spin_mutex_exit(&dev->lock);
					return -ETIME;
				}
			}
			spin_mutex_exit(&dev->lock);
			dev->trans_completed = 0;
			return 0;

		case MMRM_IOC_PRINT_HISTORY:
			printk(KERN_ERR "NOT IMPLEMENTED\n");
			return 0;

		case MMRM_IOC_BUFFER_MEM_CLEAR:
		{
			int cur_word;
			int buffer_number;
			int buffer_adress;
			unsigned int buffer_word;

			if (copy_from_user(&buffer_number,
					(void *)arg, sizeof(int))) {
				printk(KERN_ERR "%s: mmrm_%d "
					"MMRM_IOC_BUFFER_MEM_CLEAR: "
					"copy_from_user failed.\n", __func__,
						dev->instance);
				return -EINVAL;
			}
			buffer_adress = 16 * buffer_number;
		/* !!! absolute nonsense, but otherwise it is impossible !!! */
			buffer_word = (buffer_adress << 16) +
				(buffer_number << 8);
			for (cur_word = 0; cur_word < 16; cur_word++) {
				mmrm_iowrite32(buffer_word,
					&device_memory[buffer_adress +
								cur_word]);
			    buffer_word += 0x00010000;
			}
			return 0;
		}

		case MMRM_IOC_ONE_WORD_WRITING:
		{
			one_word_writing_t num;
			unsigned int writing_word;

			if (copy_from_user(&num, (void *)arg,
					sizeof(one_word_writing_t))) {
				printk(KERN_ERR "%s: mmrm_%d "
					"MMRM_IOC_ONE_WORD_WRITING: "
					"copy_from_user failed.\n", __func__,
						dev->instance);
				return -EINVAL;
			}
		/* !!! absolute nonsense, but otherwise it is impossible !!! */
			writing_word = ((num.value & 0x0000FFFF) << 16) |
				((num.value & 0xFFFF0000) >> 16);
			mmrm_iowrite32(writing_word,
					&device_memory[num.adress]);
			return 0;
		}

		default:
			printk(KERN_ERR "mmrm_%d: ioctl invalid command 0x%x\n",
				dev->instance, cmd);
			return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
static int
do_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    int ret;
    ret = mmrm_ioctl(f, cmd, arg);
    return ret;
}

static long
mmrm_compat_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    return do_ioctl(f, cmd, arg);
}
#endif

static ssize_t
mmrm_read(struct file *filp, char *buf, size_t count, loff_t *f_pos)
{
	mmrm_dev_t		*dev;
	unsigned char	size_or_code;
	u_long			cur_clock_ticks;
	u_long			etime_clock_ticks;
	int				rval;

	dev = (mmrm_dev_t *)filp->private_data;
/*    if (f_pos != &filp->f_pos)
	return -ESPIPE;
*//*sasha*/
	if ( dev->device_type == CONTROLLER_TYPE ) {
		spin_mutex_enter(&dev->lock);

		size_or_code = (unsigned char)((dev->subadress > MIN_SUBADRESS  &&  dev->subadress < MAX_SUBADRESS) ? count : 2*dev->size_or_code.cntrl_com_code);
		dev->batch_dma_adr[0] = 0x80000000 | dev->term_dev_adress << 24 | (2*dev->subadress + 1) << 16 | size_or_code;
		drv_getparm(LBOLT, &cur_clock_ticks);
		etime_clock_ticks = cur_clock_ticks + drv_usectohz(MAX_COMMAND_TIME);

		mmrm_iowrite32(1, &device_memory[BATCH_CMD_QUANTITY_REG_ADR]);

		while ( dev->trans_completed == 0 ) {
			rval = cv_spin_timedwait(&dev->intr_cv, &dev->lock, etime_clock_ticks);
			if (rval == -1) {
				printk(KERN_ERR "mmrm_%d: controller reading command is not completed.\n"
						"Interrupt register %08x\n",
					dev->instance,
					mmrm_ioread32(&device_memory
						[INTERRUPT_REG_ADR]));
				spin_mutex_exit(&dev->lock);
				return -ETIME;
			}
		}

		dev->trans_completed = 0;
		spin_mutex_exit(&dev->lock);
		if ((dev->batch_dma_adr[8] & 0x00080000) == 0) {
			/* not "abonent busy" */
		    if (copy_to_user(buf,
				dev->buf_dma_adr[2*dev->subadress + 1],
				count)) {
			printk(KERN_ERR "mmrm_%d: in controller reading command copy_to_user failed.\n",
					dev->instance);
			return -EFAULT;
		    }
		}

	} else {
		if ( copy_to_user(buf, dev->buf_dma_adr[2*dev->subadress + 1], count) ) {
			printk(KERN_ERR "mmrm_%d: in terminal reading command copy_to_user failed.\n",
					dev->instance);
			return -EFAULT;
		}
	}

	return count;
}

static ssize_t
mmrm_write(struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
	mmrm_dev_t		*dev;
	unsigned char	size_or_code;
	u_long			cur_clock_ticks;
	u_long			etime_clock_ticks;
	int				rval;

	dev = (mmrm_dev_t *)filp->private_data;
/*    if (f_pos != &filp->f_pos)
	return -ESPIPE;
*//*sasha*/ 
	if ( dev->device_type == CONTROLLER_TYPE ) {
		if ( copy_from_user(dev->buf_dma_adr[2*dev->subadress], buf, count) ) {
			printk(KERN_ERR "mmrm_%d: in controller writing command copy_from_user failed.\n",
					dev->instance);
			return -EFAULT;
		}
		spin_mutex_enter(&dev->lock);

		size_or_code = (unsigned char)((dev->subadress > MIN_SUBADRESS  &&  dev->subadress < MAX_SUBADRESS) ? count : 2*dev->size_or_code.cntrl_com_code);
		dev->batch_dma_adr[0] = 0x40000000 | dev->term_dev_adress << 24 | 2*dev->subadress << 16 | size_or_code;
		drv_getparm(LBOLT, &cur_clock_ticks);
		etime_clock_ticks = cur_clock_ticks + drv_usectohz(MAX_COMMAND_TIME);
		mmrm_iowrite32(1, &device_memory[BATCH_CMD_QUANTITY_REG_ADR]);

		while ( dev->trans_completed == 0 ) {
			rval = cv_spin_timedwait(&dev->intr_cv, &dev->lock, etime_clock_ticks);
			if ( rval == -1 ) {
				printk(KERN_ERR "mmrm_%d: controller writing command is not completed.\n"
						"Interrupt register %08x\n",
					dev->instance,
					mmrm_ioread32(&device_memory
						[INTERRUPT_REG_ADR]));
				spin_mutex_exit(&dev->lock);
				return -ETIME;
			}
		}

		spin_mutex_exit(&dev->lock);
		dev->trans_completed = 0;
	} else {
		if ( copy_from_user(dev->buf_dma_adr[2*dev->subadress], buf, count) ) {
			printk(KERN_ERR "mmrm_%d: in terminal writing command copy_from_user failed.\n",
					dev->instance);
			return -EFAULT;
		}
	}

	return count;
}

static unsigned int
mmrm_poll(struct file *filp, struct poll_table_struct *wait)
{
	mmrm_dev_t       *dev;
	mmrm_io_word_t   command_word;
	unsigned int     mask = 0;

	dev = (mmrm_dev_t *)filp->private_data;
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

static int
mmrm_mmap(struct file *filp, struct vm_area_struct *vma)
{
	mmrm_dev_t       *dev;
	struct pci_dev   *pdev;
	unsigned long    offset;
	unsigned long    addr;

	dev = (mmrm_dev_t *)filp->private_data;
	pdev = dev->pdev;

	if ( (pci_resource_flags(pdev, 0) & IORESOURCE_MEM) == 0 )
		return -EINVAL;

	if ( vma->vm_end - vma->vm_start > pci_resource_len(pdev, 0) )
		return -EINVAL;

	offset = vma->vm_pgoff << PAGE_SHIFT;
	if ( vma->vm_start + offset > vma->vm_end )
		return -ENXIO;

	addr = pci_resource_start(pdev, 0) + offset;
	vma->vm_flags |= (VM_READ | VM_WRITE | VM_IO | VM_DONTEXPAND | VM_DONTDUMP);
    /*if ( io_remap_page_range(vma->vm_start, addr, vma->vm_end - vma->vm_start, vma->vm_page_prot, 0xA) )*/

//	if ( io_remap_pfn_range(vma,vma->vm_start, MK_IOSPACE_PFN(0xa, addr >> PAGE_SHIFT) ,
	if ( io_remap_pfn_range(vma,vma->vm_start, addr >> PAGE_SHIFT, vma->vm_end - vma->vm_start, vma->vm_page_prot) )
		return -EAGAIN;

	return 0;
}

static struct file_operations mmrm_fops = {
	owner:   THIS_MODULE,
	open:    mmrm_open,
	release: mmrm_release,
	read:    mmrm_read,
	write:   mmrm_write,
	unlocked_ioctl:   mmrm_ioctl,
#ifdef CONFIG_COMPAT
	compat_ioctl: mmrm_compat_ioctl,
#endif
	poll:    mmrm_poll,
	mmap:    mmrm_mmap,
};

static int __init
mmrm_init(void)
{
	struct pci_dev *pdev = NULL;
	struct pci_dev *bdev = NULL;
	mmrm_dev_t   *dev;
	int result = 0;
	int cur_word;
	int cur_buf_num;

#if defined(VER_2614)
	int    mode;
#endif

	int i;

	mmrm_sysctl_register();

	printk("\t\tINSTALLATION  MMRM  DEVICE DRIVER\n");

/*    if (!pci_present())
        return -ENODEV;
*/ /*sasha*/

	mmrm_nr_devs = 0;

	while ( (pdev = pci_get_device(VENDOR_MCST, MMRM_DEVICE_ID, pdev)) != NULL ) {
#if defined(CONFIG_E90) || defined(CONFIG_E90S)
			pci_write_config_dword(pdev, 0x40, 1);
#else
			pci_write_config_dword(pdev, 0x40, 2);
#endif // CONFIG_E90
		if ( pci_set_dma_mask(pdev, 0xffffffff) != 0 ) {
			printk("!!! pci_set_dma_mask cannot set mask 0xffffffff.\n");
			continue;
		}

		pci_set_master(pdev);

		if ( (dev = kmalloc(sizeof(mmrm_dev_t), GFP_KERNEL)) < 0 ) {
			printk("!!! Cannot allocate memory for mmrm_dev_t.\n");
			return -ENOMEM;
		}

		memset(dev, 0, sizeof(mmrm_dev_t));
		dev->pdev = pdev;
		dev->instance = mmrm_nr_devs;
		dev->device_type = NONE_TYPE;
		dev->opened = 0;
		dev->irq = pdev->irq;
		dev->trans_completed = 0;

		init_waitqueue_head(&dev->wait_trans_fin_queue);
		cv_init(&dev->intr_cv);
		spin_mutex_init(&dev->lock);

		dev->device_mem_start = (u32*)ioremap(pci_resource_start(pdev, 0), pci_resource_len(pdev, 0));

		dev->batch_dma_adr = (u32*)pci_alloc_consistent(pdev, BATCH_BUF_BYTE_SIZE, &dev->batch_bus_addr);
		if ( dev->batch_dma_adr == NULL )
			printk("!!! Cannot pci_alloc_consistent for command batch buffer, device #%d\n", mmrm_nr_devs);

/******
		for ( cur_buf_num = 0; cur_buf_num < DEVICE_BUF_QUANTITY; cur_buf_num++ ) {
			dev->buf_dma_adr[cur_buf_num] = (u32*) pci_alloc_consistent(pdev, DEVICE_BUF_BYTE_SIZE, &dev->bus_addr[cur_buf_num]);
			if ( dev->buf_dma_adr[cur_buf_num] == NULL )
			printk("!!! Cannot pci_alloc_consistent for device buffer, device #%d, buffer #%d\n", mmrm_nr_devs, cur_buf_num);
		}
******/
		dev->buf_dma_adr[0] = (u32*)pci_alloc_consistent(pdev, DEVICE_BUF_BYTE_SIZE, &dev->bus_addr[0]);
		if ( dev->buf_dma_adr[0] == NULL )
			printk("!!! Cannot pci_alloc_consistent for device buffer, device #%d, buffer #%d\n", mmrm_nr_devs, 0);

		for ( cur_buf_num = 1; cur_buf_num < DEVICE_BUF_QUANTITY; cur_buf_num++ ) {
			dev->buf_dma_adr[cur_buf_num] = dev->buf_dma_adr[0] + DEVICE_BUF_BYTE_SIZE / sizeof(u32) * cur_buf_num;
			dev->bus_addr[cur_buf_num] = dev->bus_addr[0] + DEVICE_BUF_BYTE_SIZE * cur_buf_num;
		}

		/*****   BRIDGE   *****/
		bdev = pdev->bus->self;
		if (!bdev)
			printk(KERN_ERR "The mmrm_%d module is not established "
				"on the bridge of pci_pci.\n", mmrm_nr_devs);
		else {
		    if (bdev->vendor == VENDOR_MCST &&
				bdev->device == BRIDGE_DEVICE_ID) {
			u8 trans_size;
			u8 revision;
			pci_read_config_byte(bdev, PCI_REVISION_ID, &revision);
			printk("The mmrm_%d module is established on the bridge of pci_pci of the version %02xh.\n", mmrm_nr_devs, revision);
			pci_read_config_byte(bdev, PR_READ_SIZE_REG, &trans_size);
	
			if ( trans_size != MMRM_READ_SIZE ) {
				pci_write_config_byte(bdev, PR_READ_SIZE_REG, MMRM_READ_SIZE);
				printk("mmrm_%d: Have replaced value \"Memory Read\" %02xh on %02xh.\n", mmrm_nr_devs, trans_size, MMRM_READ_SIZE);
			}
		    } else
			printk(KERN_ERR "The mmrm_%d module is established on "
				"UNKNOWN bridge: VENDOR 0x%x, "
				"DEVICE_ID 0x%x.\n",
				mmrm_nr_devs, bdev->vendor, bdev->device);
		}

		mmrm_devices[mmrm_nr_devs++] = dev;
		mmrm_iowrite32(1, &device_memory[U0KMKP_REG_ADR]);

		for ( cur_word = 0; cur_word < DEVICE_MEM_WORD_SIZE; cur_word++ )
			mmrm_iowrite32(DEVICE_MEM_CLEAR, &device_memory[cur_word]);

		for ( cur_buf_num = 0; cur_buf_num < DEVICE_BUF_QUANTITY; cur_buf_num++ ) {
			mmrm_iowrite32(dev->bus_addr[cur_buf_num], &device_memory[MEM_IVA + cur_buf_num]);

			mmrm_iowrite32(dev->bus_addr[cur_buf_num], &device_memory[MEM_VADD + cur_buf_num]);
		}

		mmrm_iowrite32(dev->batch_bus_addr, &device_memory[BATCH_CMD_ADR_REG_ADR]);
	}

	printk("%d MMRM DEVICES ARE AVAILABLE.\n", mmrm_nr_devs);
	if ( mmrm_nr_devs > 0 ) {
		result = register_chrdev(major, MMRM_NAME, &mmrm_fops);
		if ( result < 0 ) {
			printk(KERN_WARNING "mmrm: cannot get major %d\n", major);
			return result;
		}

		if ( major == 0 )
			major = result;

		printk("MMRM MAJOR NUMBER IS %d.\n", major);
	} else {
		printk(KERN_WARNING "MMRM: REGISTER_CHRDEV DID NOT EXECUTE.\n");
		return 0;
	}

	for ( i = 0; i < mmrm_nr_devs; i++ ) {
		if (request_threaded_irq(mmrm_devices[i]->irq,
				&pre_mmrm_handler, mmrm_intr_handler,
				IRQF_SHARED | IRQF_ONESHOT, MMRM_NAME,
				(void *)mmrm_devices[i])) {
#ifdef CONFIG_E90
			if (request_threaded_irq(mmrm_devices[i]->irq,
					&pre_mmrm_handler, mmrm_intr_handler,
					IRQF_SHARED | IRQF_ONESHOT, MMRM_NAME,
					(void *)mmrm_devices[i])) {
				printk("Cannot register interrupt handler %s.\n", MMRM_NAME);
				return -EAGAIN;
			}
#else
			printk("Cannot register interrupt handler %s.\n", MMRM_NAME);
			return -EAGAIN;
#endif // CONFIG_E90
		}
		pr_warning("Make %s handler first for irq %d.\n",
			MMRM_NAME, mmrm_devices[i]->irq);
#ifdef CONFIG_MCST_RT
		mk_hndl_first(mmrm_devices[i]->irq, MMRM_NAME);
#endif
	}

	mmrm_class = class_create(THIS_MODULE, "mmrm");
	if (IS_ERR(mmrm_class)) {
		pr_err("Error creating class: /sys/class/mmrm.\n");
	}


	for ( i = 0; i < mmrm_nr_devs; i++ ) {

		char nod[128];

		if (!IS_ERR(mmrm_class)) {
			sprintf(nod, "mmrm_%d", i);
			pr_info("make node /sys/class/mmrm/%s\n", nod);
			if (device_create(mmrm_class, NULL,
					  MKDEV(major, i), NULL, nod) == NULL)
				pr_err("create a node %d failed\n", i);
		}
	}

	return 0;
}

irqreturn_t
pre_mmrm_handler(int irq, void *arg)
{
	mmrm_dev_t  *dev = (mmrm_dev_t *) arg;
	unsigned long flags;

	raw_spin_lock_irqsave(&dev->lock, flags);

	if ((mmrm_ioread32(&device_memory[INTERRUPT_REG_ADR]) &
			0x00000001) == 0) {
		raw_spin_unlock_irqrestore(&dev->lock, flags);
		return IRQ_NONE;
	}
	raw_spin_unlock_irqrestore(&dev->lock, flags);
	return IRQ_WAKE_THREAD;
}

irqreturn_t
mmrm_intr_handler(int irq, void *arg)
{
	mmrm_dev_t  *dev = (mmrm_dev_t *) arg;
	unsigned long flags;

	raw_spin_lock_irqsave(&dev->lock, flags);

	if ( (mmrm_ioread32(&device_memory[INTERRUPT_REG_ADR]) & 0x00000001) == 0 ) {
		raw_spin_unlock_irqrestore(&dev->lock, flags);
		return IRQ_NONE;
	}

	mmrm_iowrite32(0, &device_memory[INTERRUPT_REG_ADR]);

	dev->trans_completed = 1;

	if (dev->device_type == CONTROLLER_TYPE) {
		cv_broadcast(&dev->intr_cv);
		raw_spin_unlock_irqrestore(&dev->lock, flags);
	} else if (dev->device_type == TERMINAL_TYPE) {
		raw_spin_unlock_irqrestore(&dev->lock, flags);
		wake_up_interruptible(&dev->wait_trans_fin_queue);
	} else {
		raw_spin_unlock_irqrestore(&dev->lock, flags);
	}

	return IRQ_HANDLED;
}

static void __exit
mmrm_cleanup(void)
{
	int i;

	for ( i = 0; i < mmrm_nr_devs; i++ )
		free_irq(mmrm_devices[i]->irq, (void*) mmrm_devices[i]);

	unregister_chrdev(major, MMRM_NAME);

	for ( i = 0; i < mmrm_nr_devs; i++ ) {
		device_destroy(mmrm_class, MKDEV(major, i));
/*
	pci_free_consistent(mmrm_devices[i]->pdev, BATCH_BUF_BYTE_SIZE, (void *)mmrm_devices[i]->batch_dma_adr, mmrm_devices[i]->batch_bus_addr);
	pci_free_consistent(mmrm_devices[i]->pdev, DEVICE_BUF_BYTE_SIZE, (void *)mmrm_devices[i]->buf_dma_adr[0], mmrm_devices[i]->bus_addr[0]);
*/
		kfree(mmrm_devices[i]);

	}

	class_destroy(mmrm_class);

	mmrm_sysctl_unregister();

	return;
}

module_init(mmrm_init);
module_exit(mmrm_cleanup);

//MODULE_PARM(major, "i");
MODULE_PARM_DESC(major, "i");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MMRM driver");
/*EXPORT_NO_SYMBOLS;*/

