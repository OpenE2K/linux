#include <linux/module.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/string.h>
#include <linux/fcntl.h>
#include <linux/ptrace.h>
//#include <linux/cyclades.h>
#include <linux/mm.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/bitops.h>
#include <linux/proc_fs.h>

#include <asm/system.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/uaccess.h>

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/pci.h>

#define DEV_NAME "i2c_spd"

#define I2C_CTRL	0x14
#define I2C_STATUS	0x18
#define I2C_MODE	0x1c

struct i2c_dev {
	int bus;
	int _addr;
};

struct i2c_spd_info_t {

	struct pci_dev *pcidev;
	void __iomem *dev;
	struct i2c_dev adrdev[256];
	void __iomem *base_io;
	struct proc_dir_entry *proc_dev;
	int count;
	spinlock_t spd_lock;
};

static int count = 0;

static int i2c_spd_probe(struct pci_dev *pcidev,
				    const struct pci_device_id *pciid);
static void i2c_spd_remove(struct pci_dev *pci_dev);
inline int i2c_read_reg(struct pci_dev *dev, char *base, unsigned char reg,
			int bus, int adr);
inline int i2c_write_reg(struct pci_dev *dev, char *base, unsigned char reg,
			 int bus, int adr);

#define SPD_SZ	128
static int proc_read_i2c_spd(char *page, char **start,
			      off_t off, int count, int *eof, void *data)
{
	int len = 0;
	struct i2c_spd_info_t *device = (struct i2c_spd_info_t *)data;
	struct pci_dev *dev = device->pcidev;
	int i, j;
	unsigned char dt;
	int bus, adr;

	spin_lock(&device->spd_lock);
	for (i = 0; i < device->count; i++) {
		bus = device->adrdev[i].bus;
		adr = device->adrdev[i]._addr;
		len += sprintf(&page[len], "Module %d", i);

		for (j = 0; j < SPD_SZ; j++) {
			if(!(j % 16))
				len += sprintf(&page[len], "\n\t");
			if (i2c_read_reg(dev, &dt, j, bus, adr) <= 0) {	// read status reg
				len = sprintf(page, "Error read spd unit\n");
				goto l_1;
			}
			len += sprintf(&page[len], "%02x ", dt);
		}
		len += sprintf(&page[len], "\n\n");
	}
      l_1:
	spin_unlock(&device->spd_lock);
	return len;
}

int i2c_base_write(struct pci_dev *dev, char *base, int sz, int bus, int adr,
		   int reg)
{
	struct i2c_spd_info_t *device = pci_get_drvdata(dev);
	// sz < 63
	volatile u32 i2c_ctrl =
	    0x1 | (sz << 1) | (adr << 15) | (bus << 24) | (0 << 26) | (1 << 28)
	    | (reg << 7) | (0 << 22) | (1 << 23);
	// write | size | 7bit addr | 0 -phase data | bus number | start byte on | start 
	volatile u32 i2c_mode = 0;
	int k = 0;
	int i;
	int ret;

	for (i = 1000000; i; i--) {
		if (readl(device->dev + I2C_STATUS) & 0x1) {
			udelay(1);
			continue;
		}
		break;
	}

	if (!i)
		return 0;

	for (k = 0; k < sz; k++) {
		writeb(*(base + k), device->base_io + k);
	}

	writel(i2c_mode, device->dev + I2C_MODE);
	writel(0x1e, device->dev + I2C_STATUS);
	writel(i2c_ctrl, device->dev + I2C_CTRL);

	// data transfer

	for (i = 1000000; i; i--) {
		ret = readl(device->dev + I2C_STATUS);
		if (ret & 0x1) {
			udelay(1);
			continue;
		}
		if (ret & 0x2 && (!(ret & 0x1c))) {
			return sz;
		}
		if (ret & 0x1c) {
			break;
		}
	}

	if (!i) {
		writel((1 << 27), device->dev + I2C_CTRL);	//kill task
		writel(0x1e, device->dev + I2C_STATUS);	//clean error bits 
	}

	return -1;
}

int i2c_base_read(struct pci_dev *dev, char *base, int sz, int bus, int adr,
		  int reg)
{

	struct i2c_spd_info_t *device = pci_get_drvdata(dev);
	// sz < 63 //0x1 | (sz << 1) | (adr << 15) | (bus << 24) | (0 << 26) | (1 << 28) | (reg << 7) | (0 << 22) | (1 << 23);
	volatile u32 i2c_ctrl =
	    0x0 | (sz << 1) | (adr << 15) | (bus << 24) | (0 << 26) | (1 << 28)
	    | (reg << 7) | (1 << 23) | (0 << 22);
	volatile u32 i2c_mode = 0;

	int i;
	int ret;

	// start transfer data

	for (i = 1000000; i; i--) {
		if (readl(device->dev + I2C_STATUS) & 0x1) {
			udelay(1);
			continue;
		}

		break;
	}
	if (!i)
		return -1;

	writel(i2c_mode, device->dev + I2C_MODE);
	writel(0x1e, device->dev + I2C_STATUS);

	writel(i2c_ctrl, device->dev + I2C_CTRL);

	// check transfer

	for (i = 1000000; i; i--) {
		ret = readl(device->dev + I2C_STATUS);
		if (ret & 0x1) {
			udelay(1);
			continue;
		}

		if (ret & 0x2 && (!(ret & 0x1c))) {
			int j = 0;

			for (j = 0; j < sz; j++) {
				char b = readb(device->base_io + j);
				*(base + j) = b;
			}
			return sz;
		}

		if (ret & 0x1c)
			break;
	}

	if (!i) {
		writel((i2c_ctrl = (1 << 27)), device->dev + I2C_CTRL);
		writel(0x1e, device->dev + I2C_STATUS);	//clean error bits
	}

	return -1;

}

inline int i2c_read_reg(struct pci_dev *dev, char *base, unsigned char reg,
			int bus, int adr)
{
	int ret = i2c_base_write(dev, &reg, 1, bus, adr, 00);

	if (ret == -1)
		return ret;

	return i2c_base_read(dev, base, 1, bus, adr, 00);
}

inline int i2c_write_reg(struct pci_dev *dev, char *base, unsigned char reg,
			 int bus, int adr)
{
	char ctm[2];
	ctm[0] = reg;
	ctm[1] = *base;
	return i2c_base_write(dev, &ctm[0], 2, bus, adr, 00);
}

static int i2c_find_spd_dev(struct i2c_spd_info_t *device)
{
	char adr = 0x50;
	struct pci_dev *pcidev = device->pcidev;
	int j, f, k = 0;
	char ctm[64];

	for (j = 0; j < 1; j++) {
		for (f = 0; f < 8; f++) {
			if (i2c_read_reg(pcidev, &ctm[0], 0, j, adr + f) > 0) {
				printk("spd chip found at %d:%x\n",j, adr + f);
				device->adrdev[k].bus = j;
				device->adrdev[k]._addr = adr + f;
				k++;
			}
		}
	}
	return k;

}

static int i2c_spd_probe(struct pci_dev *pcidev,
				    const struct pci_device_id *pciid)
{
	struct i2c_spd_info_t *device;
	static char fflag = 0;

	device =
	    (struct i2c_spd_info_t *)kmalloc(sizeof(struct i2c_spd_info_t),
					      GFP_KERNEL);
	if (device == NULL) {
		printk(KERN_ALERT "I2C - Error while trying alloc memory.\n");
		return -ENOMEM;
	}
	memset(device, 0, sizeof(struct i2c_spd_info_t));

	memset(device->adrdev, -1, sizeof(struct i2c_dev) * 256);

	device->pcidev = pcidev;
	spin_lock_init(&device->spd_lock);


	device->dev = pci_iomap(device->pcidev, 0, 0);
	device->base_io = pci_iomap(device->pcidev, 1, 0);

	pci_set_drvdata(pcidev, device);

	//check i2c 
	device->count = i2c_find_spd_dev(device);

	if (device->count == 0)
		goto release_device;

	printk("%d spd chips was found\n", device->count);

	device->proc_dev = create_proc_entry("i2c_spd", 0444, NULL);
	if (device->proc_dev == NULL) {
		goto release_device;
	}
	strcpy((char *)device->proc_dev->name, "i2c_spd");
	device->proc_dev->data = device;
	device->proc_dev->read_proc = proc_read_i2c_spd;
	device->proc_dev->write_proc = NULL;
	fflag++;
	count = fflag;

	return 0;

      release_device:
	pci_set_drvdata(pcidev, NULL);
	kfree(device);
	return -1;

}

static int __init i2c_spd_init_module(void)
{
	int ret = 0;
	struct pci_dev *dev = NULL;

	do {
		dev = pci_get_device(0x8086, 0x0002, dev);
		if (dev) {
			if (i2c_spd_probe(dev, NULL) == 0)
				ret++;
		}
	} while (dev != NULL);

	if (ret == 0) {
		printk ("i2c_spd: Unable to locate any i2c_spd"
				" device with valid IDs\n");
		return -ENODEV;
	}

	return 0;
}

static void i2c_spd_remove(struct pci_dev *pci_dev1)
{
	struct i2c_spd_info_t *device;	// = pci_get_drvdata(pci_dev);
	struct pci_dev *pcidev = 0;	// = device->pcidev;

	do {
		pcidev = pci_get_device(0x8086, 0x0002, pcidev);
		if (pcidev) {
			device = pci_get_drvdata(pcidev);
			pci_set_drvdata(pcidev, NULL);
			remove_proc_entry("i2c_spd", device->proc_dev);
			pci_iounmap(pcidev, device->dev);
			pci_iounmap(pcidev, device->base_io);
			kfree(device);
		}
	} while (pcidev != NULL);
}

static void i2c_spd_exit_module(void)
{
	i2c_spd_remove(NULL);
}

module_init(i2c_spd_init_module);
module_exit(i2c_spd_exit_module);

MODULE_DESCRIPTION("I2C Driver for dumping spd");
MODULE_LICENSE("GPL");
