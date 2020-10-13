
/*
 * Copyright (c) 2009 by MCST->
 */


/* WARNING!!!  ONLY FOR APORIY            */


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <asm/uaccess.h>

#undef __DEBUG_INT
#undef __DEBUG
#include <linux/mcst/gpio_ac97.h>

#define DRIVER_AUTHOR  "GPIO_AC97, (c) 2009, Sparc ver. by niki"
#define DRIVER_DESC    "GPIO_AC97 pci device."


#define VENDOR_GPIO_ID		0x8086
#define DEVICE_GPIO_ID		0x4d55
#define RESOURCE_GPIO_NUM	1

static int  _MAJOR = 147;

static int gpio_count = 0;
static gpio_state_t *gpio_pcidev[256];


static void gpio_remove(struct pci_dev *pci_dev);
static int gpio_probe(struct pci_dev *pcidev,
				const struct pci_device_id *pciid);
static long gpio_ioctl(struct file *filp, unsigned int ioctl_num,
		      unsigned long ioctl_param);
static int gpio_open(struct inode *inode, struct file *filp);
static int gpio_close(struct inode *inode, struct file *filp);


/*
 * file_operations of gpio
 */
static struct file_operations gpio_fops = {
      owner:THIS_MODULE,
      unlocked_ioctl:gpio_ioctl,
      open:gpio_open,
      release:gpio_close,
};

static int gpio_open(struct inode *inode, struct file *filp)
{
	unsigned long *dop;
	int minor = MINOR(inode->i_rdev);
	gpio_state_t *device = gpio_pcidev[MINOR(inode->i_rdev)];


	if ((gpio_count - 1) < minor) {
		printk("gpio - No device with major %d minor %d\n",
		       MAJOR(inode->i_rdev), MINOR(inode->i_rdev));
		return -ENODEV;
	}

	down(&device->mux);

#ifdef __DEBUG
	printk("gpio - Open major &d minor = %d\n", MAJOR(inode->i_rdev),
	       MINOR(inode->i_rdev));
#endif
	if (filp->private_data == NULL) {
		dop = (unsigned long *) kmalloc(4, GFP_KERNEL);
		if (dop == NULL) {
			printk
			    ("gpio - Error while trying alloc memory.\n");
			return -ENOMEM;
		}
		*dop = MINOR(inode->i_rdev);
		filp->private_data = dop;
#ifdef __DEBUG
		printk("gpio - Save MAJOR in private_data.\n");
#endif
	}

	up(&device->mux);
	return 0;
}

/*
 */
static int gpio_close(struct inode *inode, struct file *filp)
{
	gpio_state_t *device = gpio_pcidev[MINOR(inode->i_rdev)];
	gpio_status_t *st = (gpio_status_t *) device->start_io;
	down(&device->mux);
	st->gpio_int_en = 0;
	kfree(filp->private_data);
	filp->private_data = NULL;
#ifdef __DEBUG
	printk("GPIO - DEVICE RELEASE\n");
#endif
	up(&device->mux);

	return 0;
}


/*
 *
 */
static long gpio_ioctl(struct file *filp, unsigned int ioctl_num,
		       unsigned long ioctl_param)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	gpio_status_t *par = (gpio_status_t *) ioctl_param;

	gpio_state_t *device;
	volatile gpio_status_t *st;
	int ret = 0;


	device = gpio_pcidev[MINOR(inode->i_rdev)];

	down(&device->mux);
	st = (gpio_status_t *) device->start_io;


	switch (ioctl_num) {
		gpio_status_t tm;
	case IOCTL_GPIO_GET_STATUS:
#ifdef __DEBUG
		printk("GPIO - IOCTL_GPIO_GET_STATUS\n");
		printk("ctrl %#x\n", le32_to_cpu(st->gpio_ctrl));
		printk("data %#x\n", le32_to_cpu(st->gpio_data));
		printk("cls %#x\n", le32_to_cpu(st->gpio_int_cls));
		printk("lvl %#x\n", le32_to_cpu(st->gpio_int_lvl));
		printk("en %#x\n", le32_to_cpu(st->gpio_int_en));
#endif

		tm.gpio_ctrl = le32_to_cpu(st->gpio_ctrl);
		tm.gpio_data = le32_to_cpu(st->gpio_data);
		tm.gpio_int_cls = le32_to_cpu(st->gpio_int_cls);
		tm.gpio_int_lvl = le32_to_cpu(st->gpio_int_lvl);
		tm.gpio_int_en = le32_to_cpu(st->gpio_int_en);
		if (copy_to_user(par, &tm, sizeof(tm))) {
			ret = -EFAULT;
			break;
		}

		break;

	case IOCTL_GPIO_SET_STATUS:


		if (copy_from_user(&tm, par, sizeof(tm))) {
			ret = -EFAULT;
			break;
		}
#ifdef __DEBUG
		printk("GPIO - IOCTL_GPIO_SET_STATUS 1\n");
		printk("ctrl %#x %#x\n", le32_to_cpu(st->gpio_ctrl),
		       tm.gpio_ctrl);
		printk("data %#x %#x\n", le32_to_cpu(st->gpio_data),
		       tm.gpio_data);
		printk("cls %#x\n", le32_to_cpu(st->gpio_int_cls));
		printk("lvl %#x\n", le32_to_cpu(st->gpio_int_lvl));
		printk("en %#x\n", le32_to_cpu(st->gpio_int_en));
#endif
		st->gpio_ctrl = cpu_to_le32(tm.gpio_ctrl);
		st->gpio_data = cpu_to_le32(tm.gpio_data);
		st->gpio_int_cls = cpu_to_le32(tm.gpio_int_cls);
		st->gpio_int_lvl = cpu_to_le32(tm.gpio_int_lvl);
		st->gpio_int_en = cpu_to_le32(tm.gpio_int_en);

#ifdef __DEBUG
		printk("GPIO - IOCTL_GPIO_SET_STATUS 2\n");
		printk("ctrl %#x %#x\n", le32_to_cpu(st->gpio_ctrl),
		       tm.gpio_ctrl);
		printk("data %#x %#x\n", le32_to_cpu(st->gpio_data),
		       tm.gpio_data);
		printk("cls %#x\n", le32_to_cpu(st->gpio_int_cls));
		printk("lvl %#x\n", le32_to_cpu(st->gpio_int_lvl));
		printk("en %#x\n", le32_to_cpu(st->gpio_int_en));
#endif

		break;
	case IOCTL_GPIO_WAIT_INTERRUPT:{
			wait_int_t w;
#ifdef __DEBUG
			printk("GPIO - IOCTL_GPIO_WAIT_INTERRUPT\n");
#endif
			if (copy_from_user(&w, par, sizeof(w))) {
				ret = -EFAULT;
				break;
			};
			if (w.pin >= LINES_NUM) {
				ret = -EINVAL;
				break;
			}
			if (w.disable)
				device->line_st[w.pin] |= GPIO_DSBL_INT;
			up(&device->mux);
			if (!interruptible_sleep_on_timeout
			    (&device->pollhead[w.pin],
			     w.timeout * HZ / 1000000))
				ret = -ETIME;
			down(&device->mux);

		}
		break;
	default:
#ifdef __DEBUG
		printk("GPIO - unknown IOCTL\n");
#endif
		ret = -EINVAL;
	}
	up(&device->mux);

	return ret;
}

static irqreturn_t gpio_intr_handler(int irq, void *arg)
{
	gpio_state_t *device = (gpio_state_t *) arg;
	volatile gpio_status_t *st = (gpio_status_t *) device->start_io;
	int i;
	unsigned int_st = st->gpio_int_sts, tmp;
	if (!int_st)
		return IRQ_NONE;
	int_st = le32_to_cpu(int_st);

#ifdef __DEBUG_INT
	printk("GPIO - interrupt\n");
	printk("ctrl %#x\n", le32_to_cpu(st->gpio_ctrl));
	printk("data %#x\n", le32_to_cpu(st->gpio_data));
	printk("cls %#x\n", le32_to_cpu(st->gpio_int_cls));
	printk("lvl %#x\n", le32_to_cpu(st->gpio_int_lvl));
	printk("en %#x\n", le32_to_cpu(st->gpio_int_en));
	printk("int_st %#x\n", int_st);
#endif

	for (i = 0, tmp = 0; i < LINES_NUM; i++) {
		unsigned mask = 1 << i;
		if (int_st & mask) {
			if (device->line_st[i] & GPIO_DSBL_INT)
				tmp |= mask;
			wake_up_interruptible(&device->pollhead[i]);
		}
	}
	if (tmp) {
		st->gpio_int_en &= ~cpu_to_le32(tmp);
	}

	st->gpio_int_sts = le32_to_cpu(int_st);
#ifdef __DEBUG
	printk("GPIO - interrupt exit\n");
#endif

	return IRQ_HANDLED;
}

static struct pci_device_id gpio_pci_tbl[] = {
	{VENDOR_GPIO_ID, DEVICE_GPIO_ID, PCI_ANY_ID, PCI_ANY_ID, 0, 0},
	{0,}
};

MODULE_DEVICE_TABLE(pci, gpio_pci_tbl);
struct pci_driver gpio_pci_driver = {
      name:DEV_NAME,
      id_table:gpio_pci_tbl,
      probe:gpio_probe,
      remove:gpio_remove,
};


static int gpio_probe(struct pci_dev *pcidev,
			const struct pci_device_id *pciid)
{
	gpio_state_t *devices;
	int i;
	int rval;
	struct resource *res = &pcidev->resource[RESOURCE_GPIO_NUM];
	if (pci_enable_device(pcidev)) {
		printk("GPIO - Cannot enable PCI device.\n");
		return -1;
	}
	if (!res->start || !res->end || (res->end - res->start) <= 0) {
		printk("GPIO - Cannot claime PCI resource #%d\n",
		       RESOURCE_GPIO_NUM);
		return -1;
	}

	devices =
	    (gpio_state_t *) kmalloc(sizeof(gpio_state_t), GFP_KERNEL);
	if (devices == NULL) {
		printk("GPIO - Error while trying alloc memory.\n");
		return -ENOMEM;
	}

	memset(devices, 0, sizeof(gpio_state_t));

	devices->dev = pcidev;

#ifdef __DEBUG
	printk("GPIO - Enable PCI device success.\n");
#endif

	devices->start_io = (unsigned long)
	    ioremap(pci_resource_start(devices->dev, RESOURCE_GPIO_NUM),
		    pci_resource_len(devices->dev, RESOURCE_GPIO_NUM));

	devices->len_io =
	    pci_resource_len(devices->dev, RESOURCE_GPIO_NUM);
	devices->end_io = devices->start_io + devices->len_io;


#ifdef __DEBUG
	printk("GPIO - io_start= 0x%08x io_end=0x%08x io_len=0x%08x\n",
	       devices->start_io, devices->end_io, devices->len_io);
#endif

	if (pci_read_config_byte
	    (devices->dev, PCI_REVISION_ID, &devices->revision_id)) {
		printk("GPIO - Can't read PCI_REVISION_ID.\n");
		goto release_device;
	}
	sema_init(&(devices->mux), 1);
	for (i = 0; i < LINES_NUM; i++)
		init_waitqueue_head(&devices->pollhead[i]);

	rval =
	    request_irq(pcidev->irq, gpio_intr_handler, IRQF_SHARED,
			"GPIO_AC97", devices);

	if (rval) {
		printk("request_irq fail\n");
		goto release_device;
	}

	gpio_pcidev[gpio_count] = devices;
	gpio_count++;
	return gpio_count;

      release_device:

	pci_set_drvdata(pcidev, NULL);
	kfree(devices);
	return -1;
}

/*
 *  
 */
static int __init gpio_init_module(void)
{
	int ret;
	struct pci_dev *pcidev;

	memset(gpio_pcidev, 0, sizeof(gpio_pcidev));
	pcidev = pci_get_device(VENDOR_GPIO_ID, DEVICE_GPIO_ID, NULL);

	if (!pcidev) {
		printk
		    ("GPIO: Unable to locate any shared_mem device with valid IDs 0x%x-0x%x\n",
		     VENDOR_GPIO_ID, DEVICE_GPIO_ID);
		return -1;
	} else {
		if (gpio_probe(pcidev, NULL) <= 0)
			return -1;
#ifdef __DEBUG
		printk("GPIO - PCI present. count %d\n", gpio_count);
#endif
	}
	if ((ret = register_chrdev(_MAJOR, DEV_NAME, &gpio_fops)) < 0) {
		printk("GPIO - Can't create char device.\n");
		pci_unregister_driver(&gpio_pci_driver);
		return -1;
	}

	return 0;
}

static void gpio_remove(struct pci_dev *pci_dev)
{
	int i;
	gpio_state_t *devices;
	for (i = 0; i < gpio_count && gpio_pcidev[i]->dev != pci_dev; i++);

	devices = gpio_pcidev[i];

	free_irq(pci_dev->irq, devices);
	iounmap((void *)devices->start_io);
	kfree(devices);

}

/* 
 */
static void gpio_exit_module(void)
{
	int i;
	unregister_chrdev(_MAJOR, DEV_NAME);
	for (i = 0; i < gpio_count; i++)
		gpio_remove(gpio_pcidev[i]->dev);
}

module_init(gpio_init_module);
module_exit(gpio_exit_module);

module_param(_MAJOR, int, 0);
MODULE_PARM_DESC(_MAJOR, " - set MAJOR number for GPIO devices.");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
