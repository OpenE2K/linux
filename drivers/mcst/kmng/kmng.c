#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>
#include <linux/mcst/kmng.h>

#define KMNG_FIELD_SHIFT	0x8
#define KMNG_FIELD_SZ	(1 << KMNG_FIELD_SHIFT)

#define KMNG_REG	0	/* значение, считанное из I2C-клиента/для записи в I2C-клиент */
#define KMNG_VAL1N	0x100	/* нижняя граница гистерезиса 1-го значения для сравнения */
#define KMNG_VAL1V	0x200	/* верхняя граница гистерезиса 1-го значения для сравнения */
#define KMNG_VAL2N	0x300	/* нижняя граница гистерезиса 2-го значения для сравнения */
#define KMNG_VAL2V	0x400	/* верхняя граница гистерезиса 2-го значения для сравнения */
#define KMNG_VAL3N	0x500	/* нижняя граница гистерезиса 3-го значения для сравнения */
#define KMNG_VAL3V	0x600	/* верхняя граница гистерезиса 3-го значения для сравнения */
#define KMNG_VAL4N	0x700	/* нижняя граница гистерезиса 4-го значения для сравнения */
#define KMNG_VAL4V	0x800	/* верхняя граница гистерезиса 4-го значения для сравнения */
#define KMNG_VAL5N	0x900	/* нижняя граница гистерезиса 5-го значения для сравнения */
#define KMNG_VAL5V	0xa00	/* верхняя граница гистерезиса 5-го значения для сравнения */
#define KMNG_VAL6N	0xb00	/* нижняя граница гистерезиса 6-го значения для сравнения */
#define KMNG_VAL6V	0xc00	/* верхняя граница гистерезиса 6-го значения для сравнения */
#define KMNG_MASK	0xd00	/* маска значимых бит в регистре */
#define KMNG_ASSIG	0xe00	/* адрес регистра в I2C-клиенте */
#define KMNG_INT	0xf00
#define KMNG_DO_READ	0x1

#define KMNG_SIGNAL	0x1000
#define KMNG_DO_WRITE	0x1

#define KMNG_SIGNAL_TYPE	0x1100
#define KMNG_UNSIGNED	(1 << 1)
#define KMNG_MULTIPLE	(1 << 0)

#define KMNG_I2C_BUS	0x1200
#define KMNG_I2C_BUS_LE	(1 << 7)
#define KMNG_I2C_ADDR	0x1300	/* адрес I2C-клиента на шине */
#define KMNG_I2C_SIZE	0x1400	/* размер регистра в I2C-клиенте в байтах */
#define KMNG_ERRORS	0x1500	/* количества ошибок доступа к I2C-клиенту */

#define KMNG_MODE	0x2008

#define KMNG_ENABLE_RW		(1 << 7)
#define KMNG_PWR_OK		(1 << 6)
#define KMNG_ENABLE_CHECK	(1 << 5)
#define KMNG_ENABLE_INHIBIT	(1 << 4)
#define KMNG_INHIBIT		(7 << 0)

#define KMNG_SIGNALS	0x200c
#define KMNG_READ_DONE	(1 << 0)

#define DRV_NAME	"kmng"
static int REGS_NR = 0x2000;

struct kmng_info {
	void __iomem *regs;
	spinlock_t k_lock;
	struct list_head list;
	struct pci_dev *pcidev;
	struct device *dev;
	int nr;
};

#define KMNG_ID_SHIFT	3

struct kmng_id {
	unsigned zero:32 - KMNG_ID_SHIFT - KMNG_FIELD_SHIFT;
	unsigned reg_nr:KMNG_FIELD_SHIFT;
	unsigned sz:KMNG_ID_SHIFT;
} __attribute__ ((packed));

#define KMNG_DEVCOUNT 4

static dev_t kmng_dev;
static struct cdev *kmng_cdev_p;
static LIST_HEAD(kmng_list);

static struct kmng_info *kmng_get_by_minor(unsigned index)
{
	struct kmng_info *info;
	int i = 0;
	list_for_each_entry(info, &kmng_list, list) {
		if (i == index)
			goto found;
		i++;
	}
	info = NULL;
      found:
	return info;
}

static void inline disable_sensor(void __iomem * r)
{
	writeb(0, r + KMNG_SIGNAL);
	writeb(0, r + KMNG_INT);
}

static void inline disable_rw(void __iomem * r)
{
	writeb(readb(r + KMNG_MODE) & ~(KMNG_ENABLE_CHECK | KMNG_ENABLE_RW),
	       r + KMNG_MODE);
}

static void inline enable_rw(void __iomem * r)
{
	writeb(readb(r + KMNG_MODE) | KMNG_ENABLE_CHECK | KMNG_ENABLE_RW,
	       r + KMNG_MODE);
}

static int kmng_open(struct inode *inode, struct file *filp)
{
	unsigned int minor = iminor(inode);
	struct kmng_info *info = kmng_get_by_minor(minor);
	if (!info)
		return -ENODEV;
	filp->private_data = info;	/* for other methods */
	return 0;
}

static int kmng_close(struct inode *inode, struct file *filp)
{
	struct kmng_info *info = filp->private_data;
	void __iomem *r = info->regs;
	filp->private_data = NULL;
	disable_rw(r);
	return 0;
}

#define KMNG_TIMEOUT	(2*HZ)
static ssize_t
kmng_read(struct file *filp, char __user * buf, size_t count, loff_t * ppos)
{
	struct kmng_info *info = filp->private_data;
	void __iomem *r = info->regs;
	int i;
	u32 v = (u32) count;
	struct kmng_id id;
	memcpy(&id, &v, sizeof(v));
	if (id.zero != 0)
		return -EINVAL;

	for (i = 0;
	     i < KMNG_TIMEOUT && !(readb(r + KMNG_SIGNALS) & KMNG_READ_DONE);
	     i++) {
		if (schedule_timeout_interruptible(1))
			return -EINTR;
	}
	if (i == KMNG_TIMEOUT)
		return -ETIME;
	for (v = i = 0, r += id.reg_nr; i < id.sz; r++, i++) {
		if (readb(r + KMNG_ERRORS)) {
			writeb(0, r + KMNG_ERRORS);
			return -EIO;
		}
		v |= readb(r + KMNG_REG) << 8 * i;
	}
	if (copy_to_user(buf, &v, sizeof(v)))
		return -EFAULT;

	return sizeof(v);
}

static ssize_t kmng_write(struct file *filp, const char __user *buf,
			  size_t count, loff_t *offset)
{
	struct kmng_info *info = filp->private_data;
	void __iomem *r = info->regs;
	int i;
	u32 v = (u32) count;
	struct kmng_id id;
	memcpy(&id, &v, sizeof(v));
	if (id.zero != 0)
		return -EINVAL;

	if (copy_from_user(&v, buf, sizeof(v)))
		return -EFAULT;

	for (v = i = 0, r += id.reg_nr; i < id.sz; r++, i++)
		writeb((v >> (8 * i)) & 0xff, r + KMNG_REG);

	return sizeof(v);
}

static void set_sensor(void __iomem * reg, struct kmng_data *s)
{
	int i;
	u8 v, inter = 0;
	void __iomem *r = reg;
	for (i = 0; i < s->reg_nr * s->reg_sz; i++, r++) {
		int j, k;
		for (j = 0; j < KMNG_THRESHOLDS_NR; j++) {
			if (s->LowThreshold[j] != KMNG_MAX_INT) {
				writeb((s->LowThreshold[j] >> 8 *
					i) & 0xff,
				       r + KMNG_VAL1N + j * KMNG_FIELD_SZ);

				writeb(((s->LowThreshold[j] -
					 s->NegThdHysteresis) >> 8 *
					i) & 0xff,
				       r + KMNG_VAL1V + j * KMNG_FIELD_SZ);

				inter |= 1 << (j + 1);
			}
		}
		for (k = 0, j = KMNG_THRESHOLDS_NR;
		     j < 2 * KMNG_THRESHOLDS_NR; j++, k++) {
			if (s->UpThreshold[k] != KMNG_MAX_INT) {
				writeb(((s->UpThreshold[k] -
					 s->PosThdHysteresis) >> 8 *
					i) & 0xff,
				       r + KMNG_VAL1N + j * KMNG_FIELD_SZ);

				writeb((s->UpThreshold[k] >> 8 *
					i) & 0xff,
				       r + KMNG_VAL1V + j * KMNG_FIELD_SZ);
				inter |= 1 << (j + 1);
			}
		}
		writeb((s->mask >> 8 * i) & 0xff, r + KMNG_MASK);
		writeb(s->reg[i], r + KMNG_ASSIG);
		if (i == s->reg_nr * s->reg_sz - 1)
			writeb(KMNG_UNSIGNED, r + KMNG_SIGNAL_TYPE);
		else
			writeb(KMNG_UNSIGNED | KMNG_MULTIPLE,
			       r + KMNG_SIGNAL_TYPE);
		if (s->rw)
			writeb((s->value >> 8 * i) & 0xff, r);
		else
			writeb(0x5a, r);
	}
	r = reg;

	v = s->little_endian ? KMNG_I2C_BUS_LE : 0;
	writeb(v | (1 << s->bus), r + KMNG_I2C_BUS);
	writeb(s->addr, r + KMNG_I2C_ADDR);
	writeb(s->reg_sz, r + KMNG_I2C_SIZE);

	if (s->rw) {
		writeb(KMNG_DO_WRITE, r + KMNG_SIGNAL);
	} else {
		writeb(0, r + KMNG_SIGNAL);
	}

	writeb(inter | KMNG_DO_READ, r + KMNG_INT);
	writeb(0, r + KMNG_ERRORS);
}

static ssize_t kmng_set_monitor(struct file *filp, const char __user *buf)
{
	struct kmng_info *info = filp->private_data;
	struct kmng_data d, zero = { };
	struct kmng_data *m = &d;
	struct kmng_data __user *u = (struct kmng_data __user *)buf;
	int i, j;

	disable_rw(info->regs);
	for (j = i = 0; i < KMNG_MAX_WRITES; i++) {
		struct kmng_id id;
		int sz;
		if (copy_from_user(m, &u[i], sizeof(*m)))
			return -EFAULT;
		if (!memcmp(m, &zero, sizeof(zero)))
			break;
		sz = m->reg_nr * m->reg_sz;
		j = ALIGN(j, sz);
		set_sensor(info->regs + j, m);
		id.zero = 0;
		id.sz = sz;
		id.reg_nr = j;
		if (copy_to_user(&u[i].offset, &id, sizeof(u[i].offset)))
			return -EFAULT;
		j += sz;
	}
	if (i == KMNG_MAX_WRITES)
		return -EINVAL;

	for (; j < KMNG_FIELD_SZ; j++)
		disable_sensor(info->regs + j);
	enable_rw(info->regs);
	return 0;
}

static long kmng_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *u = (void __user *)arg;
	int ret = 0;
	struct kmng_info *info = filp->private_data;
	void __iomem *r = info->regs;
	switch (cmd) {
	case KMNG_IOCTL_POWER_ON:
		{
			writeb(readb(r + KMNG_MODE)
			       | KMNG_ENABLE_INHIBIT | KMNG_INHIBIT,
			       r + KMNG_MODE);
		}
		break;
	case KMNG_IOCTL_POWER_OFF:
		{
			writeb((readb(r + KMNG_MODE)
				| KMNG_ENABLE_INHIBIT) & ~KMNG_INHIBIT,
			       r + KMNG_MODE);
		}
		break;
	case KMNG_IOCTL_RESET:
		{
			u8 m = readb(r + KMNG_MODE);
			writeb(m | KMNG_PWR_OK, r + KMNG_MODE);
			mdelay(10);
			writeb(m & ~KMNG_PWR_OK, r + KMNG_MODE);
		}
		break;
	case KMNG_IOCTL_RESET_ASSERT:
		{
			u8 m = readb(r + KMNG_MODE);
			writeb(m | KMNG_PWR_OK, r + KMNG_MODE);
		}
		break;
	case KMNG_IOCTL_RESET_DEASSERT:
		{
			u8 m = readb(r + KMNG_MODE);
			writeb(m & ~KMNG_PWR_OK, r + KMNG_MODE);
		}
		break;
	case KMNG_IOCTL_SET_MONITOR:
		{
			return kmng_set_monitor(filp, u);
		}
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations kmng_fops = {
	.owner = THIS_MODULE,
	.open = kmng_open,	/* open */
	.release = kmng_close,	/* release */
	.read = kmng_read,
	.write = kmng_write,
	.unlocked_ioctl = kmng_ioctl,

};

#define FMT	"0x%04x:\t %02x %02x %02x %02x  %02x %02x %02x %02x    " \
			  "%02x %02x %02x %02x  %02x %02x %02x %02x\n"
#define FMT_LEN		(16*3 + 6 + 8 + 1)

static int proc_read_kmng(char *page, char **start,
			  off_t off, int count, int *eof, void *data)
{
	int len, i;
	struct kmng_info *info = (struct kmng_info *)data;

	for (i = (off / FMT_LEN) * 16, len = 0; i < REGS_NR
	     && len < ((count - 1) / FMT_LEN) * FMT_LEN;
	     i += 16, len += FMT_LEN) {
		void __iomem *r = info->regs;
		int l = snprintf(page + len, FMT_LEN + 1, FMT, i,
				 readb(r + i + 0), readb(r + i + 1),
				 readb(r + i + 2), readb(r + i + 3),
				 readb(r + i + 4), readb(r + i + 5),
				 readb(r + i + 6), readb(r + i + 7),
				 readb(r + i + 8), readb(r + i + 9),
				 readb(r + i + 10), readb(r + i + 11),
				 readb(r + i + 12), readb(r + i + 13),
				 readb(r + i + 14), readb(r + i + 15));

		memset(page + len + l, ' ', FMT_LEN - l);
	}
	if (i == REGS_NR)
		*eof = 1;
	else
		*((unsigned long *)start) = len;

	return len;
}

static int proc_write_kmng(struct file *file,
			   const char __user *buffer,
			   unsigned long count, void *data)
{
	char b[128];
	struct kmng_info *info = (struct kmng_info *)data;
	int reg, val;
	if (copy_from_user(b, buffer, count))
		return -EFAULT;
	sscanf(b, "0x%x=0x%x", &reg, &val);
	if (reg > REGS_NR)
		return -EINVAL;

	printk(" %x => %x\n", val, reg);
	writeb(val, info->regs + reg);
	return count;
}

static ssize_t show_adapter_name(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct kmng_info *info = kmng_get_by_minor(MINOR(dev->devt));

	if (!info)
		return -ENODEV;
	return sprintf(buf, DRV_NAME "%d\n", info->nr);
}

static DEVICE_ATTR(name, S_IRUGO, show_adapter_name, NULL);

static struct class *kmng_class;

static int kmng_probe(struct pci_dev *pcidev,
				const struct pci_device_id *pciid)
{
	static int kmng_dev_count;
	char name[64];
	struct proc_dir_entry *entry;
	struct kmng_info *info =
	    (struct kmng_info *)kzalloc(sizeof(struct kmng_info),
					GFP_KERNEL);
	if (info == NULL)
		return -ENOMEM;

	info->pcidev = pcidev;
	spin_lock_init(&info->k_lock);
	info->regs = pci_iomap(info->pcidev, 0, 0);
	if (!info->regs)
		goto iomap;

	REGS_NR = pci_resource_len(info->pcidev, 0);
	info->nr = kmng_dev_count;
	sprintf(name, "driver/" DRV_NAME "%d", info->nr);
	entry = create_proc_entry(name, 0, NULL);
	if (entry == NULL)
		goto proc;

	entry->data = info;
	entry->read_proc = proc_read_kmng;
	entry->write_proc = proc_write_kmng;

	list_add_tail(&info->list, &kmng_list);
	pci_set_drvdata(info->pcidev, info);

	info->dev = device_create(kmng_class, NULL,
				  MKDEV(MAJOR(kmng_dev), info->nr),
				  NULL, DRV_NAME "%d", info->nr);
	if (IS_ERR(info->dev))
		goto device_create;

	if (device_create_file(info->dev, &dev_attr_name))
		goto create_file;

	kmng_dev_count++;
	return 0;

      create_file:
	device_destroy(kmng_class, MKDEV(MAJOR(kmng_dev), info->nr));
      device_create:
	remove_proc_entry(name, NULL);
	pci_set_drvdata(info->pcidev, NULL);
      proc:
	pci_iounmap(info->pcidev, info->regs);
      iomap:
	kfree(info);
	return -1;
}

static void kmng_remove(struct pci_dev *pdev)
{
	char name[64];
	struct kmng_info *info = pci_get_drvdata(pdev);
	sprintf(name, "driver/" DRV_NAME "%d", info->nr);

	device_remove_file(info->dev, &dev_attr_name);
	device_destroy(kmng_class, MKDEV(MAJOR(kmng_dev), info->nr));

	remove_proc_entry(name, NULL);
	pci_set_drvdata(pdev, NULL);
	pci_iounmap(info->pcidev, info->regs);
	kfree(info);
}

static struct pci_device_id kmng_pci_tbl[] = {
	{PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_KMNG, PCI_ANY_ID,
	 PCI_ANY_ID, 0, 0, 0},
	{0,},			/* terminate list */
};

MODULE_DEVICE_TABLE(pci, kmng_pci_tbl);

static struct pci_driver kmng_pci_driver = {
	.name = DRV_NAME,
	.id_table = kmng_pci_tbl,
	.probe = kmng_probe,
	.remove = kmng_remove,
};

static int __init kmng_init(void)
{
	kmng_class = class_create(THIS_MODULE, DRV_NAME);
	if (IS_ERR(kmng_class)) {
		return 1;
	}

	if (alloc_chrdev_region(&kmng_dev, 0, KMNG_DEVCOUNT, DRV_NAME) < 0)
		return 1;

	kmng_cdev_p = cdev_alloc();
	kmng_cdev_p->ops = &kmng_fops;
	if (cdev_add(kmng_cdev_p, kmng_dev, KMNG_DEVCOUNT)) {
		unregister_chrdev_region(kmng_dev, KMNG_DEVCOUNT);
		return 1;
	}
	return pci_register_driver(&kmng_pci_driver);
}

static void __exit kmng_exit(void)
{
	cdev_del(kmng_cdev_p);
	unregister_chrdev_region(kmng_dev, KMNG_DEVCOUNT);
	pci_unregister_driver(&kmng_pci_driver);
	class_destroy(kmng_class);
}

module_init(kmng_init);
module_exit(kmng_exit);

MODULE_LICENSE("GPL");
