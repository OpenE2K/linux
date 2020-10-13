/*
 * Copyright (c) 2014 by INEUM
 * Output discrete signals via LPT-port
 * parport and parport_povozka modules running required before starting this module
 * Developed for INEUM-BCVM module
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/semaphore.h>
#include <linux/time.h>
#include <linux/ioctl.h>
#include <linux/version.h>

//#include <linux/parport.h>
//#include <linux/parport_pc.h>
#include <linux/via.h>
//#include <asm/parport.h>

#define LPTOUTS_INIT_VALUE		0xFF

#define PCI_DEVICE_ID_PAR_SER	0x8000
#define E3M_MULTIFUNC_VENDOR	0x8086

#define PCI_DEVICE_ID_PARPORTMCST	0x0121//0x8007
#define PCI_VENDOR_ID_MCST		0x14F2//0x1fff

struct pci_parport_data {
	int num;
	int driver_data;
	struct parport *ports[2];
};

struct pci_dev *pcidev = NULL;
void *pIO = NULL;
unsigned long lpt_io_lo, lpt_io_hi;

#define MAX_LPTOUT_DEVICES	9
static struct device* lpt_devices[MAX_LPTOUT_DEVICES];


/////////////////////// LINUX KERNEL MODULE /////////////////////////////////////

#define VERSION			"1.0"
#define LAST_UPDATE		"25.08.2014"

#define SUCCESS 0
#define DEVICE_NAME "lptouts"
#define BUF_LEN 80



static int Major;
static int Device_Open = 0;

static dev_t first_dev; // Global variable for the first device number
static struct class *dev_class;

static int lpt_probe(struct pci_dev *dev, const struct pci_device_id *ids)
{
	int err;
	int lo = 0;
	int irq;
	
	err = pci_enable_device(dev);
	if (err)
		return err;
	
	//accessing lpt port device
	pIO = ioremap_nocache(pci_resource_start(dev, lo), pci_resource_len(dev, lo));
	if(pIO == NULL) 
	{
		printk(KERN_INFO"%s: ERROR! Can`t ioremap. \n", DEVICE_NAME);
		pci_disable_device(pcidev);
		pcidev = NULL;
		return -1;
	}
	lpt_io_lo = pci_resource_start(dev, lo);
	lpt_io_hi = 0;
	
	irq = dev->irq;
	
	//reset device
	outb(0x01, lpt_io_lo + 0x0A);
	udelay(1000);
	outb(0x20, lpt_io_lo + 0x0A);

	udelay(1000);
	
	//out startup data
	outb(LPTOUTS_INIT_VALUE, lpt_io_lo);
	
	//data can be read
	//printk("0x%X \n", inb(lpt_io_lo));
	
	return 0;
}

static int init_lpt(void)
{
	int res = 0;
	struct pci_device_id id;
	
	id.vendor = E3M_MULTIFUNC_VENDOR;
	id.device = PCI_DEVICE_ID_PAR_SER;
	id.subvendor = 0x8086;
	id.subdevice = 0x8001;
	id.class = 0;
	id.class_mask = 0;
	id.driver_data = 0;//mcst_pp_iee1284;
	
	pcidev = pci_get_device(E3M_MULTIFUNC_VENDOR, PCI_DEVICE_ID_PAR_SER, NULL);
	
	if (!pcidev) {
		printk("lptouts: %s: Unable to locate any shared_mem device with valid IDs 0x%x-0x%x\n", __FUNCTION__, PCI_VENDOR_ID_MCST, PCI_DEVICE_ID_PARPORTMCST);
		return -1;
	}
	
	res = lpt_probe(pcidev, &id);
	if(res != 0)
	{
		
	}

	return res;
}

static int device_open(struct inode *inode, struct file *file)
{
	int fd = 0;

	if(MINOR(inode->i_rdev) > 0)
	{
		fd = MINOR(inode->i_rdev);
	}
	else
	{
	  Device_Open++;
	}
	try_module_get(THIS_MODULE);

  return SUCCESS;
}

static int device_release(struct inode *inode, struct file *file)
{
	int fd = 0;
	if(MINOR(inode->i_rdev) > 0)
	{
		fd = MINOR(inode->i_rdev);
	}
	else
	{
		Device_Open--;
	}

	module_put(THIS_MODULE);

  return 0;
}

static long device_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
  int fd = 0, ret = 0;

  fd = MINOR(file->f_dentry->d_inode->i_rdev);

  if(fd > 0)
  {
		fd --;
		switch(ioctl_num)
		{
			default:
				break;
		}
	}
	else
	{
		switch(ioctl_num)
		{
			default:
				break;
		}
	}

  return ret;
}


static ssize_t device_read(struct file *filp, char *buffer, size_t length, loff_t * offset)
{
  struct inode* inode;
  int bytes_read = 0;
  int fd;

  inode = filp->f_dentry->d_inode;

  fd = MINOR(inode->i_rdev);

	if(fd > 0)
	{
		fd--;
	}
	else
	{
	}

  return bytes_read;
}

static ssize_t device_write(struct file *filp, const char *buff, size_t len, loff_t * off)
{
	struct inode* inode;
	int i = 0, fd = -1, len_to_read = len;
	char szbuf[255];

	inode = filp->f_dentry->d_inode;

	fd = MINOR(inode->i_rdev);
	
	if(len > 255)
			len_to_read = 255;

	if(fd > 0)
	{
		fd --;
	}
	else
	{
		for (i = 0; i < len_to_read; i++)
		{
			get_user(szbuf[i], buff + i);
		}
	}

  return i;
}

static ssize_t sys_write_value(struct device* dev, struct device_attribute* attr, const char* buf, size_t count)
{
	int fd, ret = 0;
	unsigned long state = 0;
	unsigned char reg = 0;
	
	//reading out number
	fd = MINOR(dev->devt);
	
	if(fd > 0 && fd < MAX_LPTOUT_DEVICES)
	{
		ret = strict_strtoul(buf, 0, &state);
		if (ret)
			return ret;
		
		if(pcidev != NULL && pIO != NULL)
		{
		  //out state value to fd output
		  //reading current value
		  reg = inb(lpt_io_lo);
		  if(state == 1)
		  	reg |= ((unsigned char)0x01) << (fd - 1);
		  else if(state == 0)
		  	reg &= ~(((unsigned char)0x01)<<(fd - 1));
		  
			//out value to lpt port
			outb(reg, lpt_io_lo);
			//printk("out 0x%X to 0x%X\n", reg, lpt_io_lo);
		}
	}
	else if(fd == 0) //working with root device
	{
		ret = strict_strtoul(buf, 0, &state);
		if (ret)
			return ret;
		if(pcidev != NULL && pIO != NULL)
		{
			outb((unsigned char)state, lpt_io_lo);
		}
	}
	
	
	return count;
}

static ssize_t sys_read_value(struct device* dev, struct device_attribute* attr, char* buf)
{
	int fd;
	
	//reading out number
	fd = MINOR(dev->devt);
	
	if(fd > 0 && fd < MAX_LPTOUT_DEVICES)
	{
		if(pcidev != NULL && pIO != NULL)
		{
			return sprintf(buf, "%d\n", inb(lpt_io_lo)&(0x00000001 << (fd-1)));
		}
	}
	else if(fd == 0) //working with root device
	{
		if(pcidev != NULL && pIO != NULL)
		{
			return sprintf(buf, "0x%02X\n", inb(lpt_io_lo));
		}
	}
	
	return sprintf(buf,"unknown\n");
}

static struct file_operations fops = {
  .read = device_read,
  .write = device_write,
  .open = device_open,
  .release = device_release,
  .unlocked_ioctl = device_ioctl
};

static DEVICE_ATTR(value, 0644/*S_IWUSR | S_IRUSR*/, sys_read_value, sys_write_value);

static int __init lptouts_init(void)
{
	int i = 0, retval = 0;

	printk(KERN_INFO "%s: driver started\n", DEVICE_NAME);

	//registering device...
	Major = register_chrdev(0, DEVICE_NAME, &fops);
	if (Major < 0)
	{
		printk("Registering the character device failed with %dn \n", Major);
		return -EINVAL;
	}

	dev_class = class_create(THIS_MODULE, DEVICE_NAME);
	if(dev_class == NULL)
	{
		printk("udev is unavailable\n");
	}
	else
	{
		//creating devices
		first_dev = MKDEV(Major, i);
		lpt_devices[0] = device_create(dev_class, NULL, first_dev, NULL, DEVICE_NAME);
		retval = device_create_file(lpt_devices[0], &dev_attr_value);
		if (retval < 0) {
		  printk(KERN_INFO "%s: failed to create write /sys endpoint - continuing without (0)\n", DEVICE_NAME);
		}
		
		//creating out devices
		for(i = 1; i < MAX_LPTOUT_DEVICES; i++) {
			lpt_devices[i] = device_create(dev_class, NULL, MKDEV(Major, i), NULL, "lptout%d", i);
			retval = device_create_file(lpt_devices[i], &dev_attr_value);
			if (retval < 0) {
			  printk(KERN_INFO "%s: failed to create write /sys endpoint - continuing without (%d)\n", DEVICE_NAME, i);
			}
		}
	}

	printk(KERN_INFO "%s: driver was assigned major number %d.\n", DEVICE_NAME, Major);
	
	if(init_lpt() < 0)
	{
		return -EINVAL;
	}

	return 0;
}

static void __exit lptouts_exit(void)
{
    int i = 0;
    
    for (i=0; i < MAX_LPTOUT_DEVICES; i++) {
    	device_remove_file(lpt_devices[i], &dev_attr_value);
    	device_destroy(dev_class, MKDEV(Major, i));
    }
    device_destroy(dev_class, first_dev);

  	class_destroy(dev_class);

    unregister_chrdev(Major, DEVICE_NAME);
    
    
    //disabling pci device
    if(pcidev != NULL) {
    	//freeing resources
    	if(pIO != NULL)
    		iounmap(pIO);
    	//disabling device
    	pci_disable_device(pcidev);
    	
    	pcidev = NULL;
    }

    printk(KERN_INFO "%s: module exit\n", DEVICE_NAME);
}



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anton V. Glukhov");
module_init(lptouts_init)
module_exit(lptouts_exit)
