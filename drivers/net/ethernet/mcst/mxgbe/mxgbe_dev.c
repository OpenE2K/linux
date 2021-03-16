/**
 * mxgbe_dev.c - MXGBE module device driver
 *
 * Char Device part
 */

#include <linux/idr.h>
#include <linux/poll.h>
#include <linux/cred.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/dma-mapping.h>
#include <linux/pagemap.h>

#include "mxgbe.h"
#include "mxgbe_dbg.h"
#include "mxgbe_hw.h"
#include "mxgbe_txq.h"
#include "mxgbe_rxq.h"
#ifdef DEBUG
#include "mxgbe_io.h"
#else
#if 1
#include "mxgbe_io.h"
#else
#include <linux/mcst/mxgbe_io.h>
#endif
#endif
#include "kcompat.h"


/* DEBUG: */
int mxgbe_txq_dbg_test_s(mxgbe_priv_t *priv, int qn, uint64_t buf, int len);
int mxgbe_txq_dbg_test_r(mxgbe_priv_t *priv, int qn);

int mxgbe_rxq_dbg_test_s(mxgbe_priv_t *priv, int qn, uint64_t buf, int len);
int mxgbe_rxq_dbg_test_r(mxgbe_priv_t *priv, int qn);


/**
 ******************************************************************************
 * Buffer/skb alloc/free/init
 ******************************************************************************
 */

#if 0
static int cdev_rxq_alloc_buff(mxgbe_priv_t *priv, mxgbe_rx_buff_t *rxq_buff)
{
	int err;
	struct pci_dev *pdev = priv->pdev; /* for DMA_*_RAM macro */

	DMA_ALLOC_RAM(rxq_buff->size,
		rxq_buff->addr,
		rxq_buff->dma,
		MXGBE_MAXFRAMESIZE,
		err_free_ring,
		"RXQ Ring");

	rxq_buff->skb = NULL;

	return 0;

err_free_ring:
	return err;
} /* rxq_alloc_buff */

static void cdev_rxq_clean_buff(mxgbe_priv_t *priv, mxgbe_rx_buff_t *rxq_buff)
{
	struct pci_dev *pdev = priv->pdev; /* for DMA_*_RAM macro */

	DMA_FREE_RAM(rxq_buff->size, rxq_buff->addr, rxq_buff->dma);
} /* rxq_clean_buff */

/**
 * Last Init RXQ[qn] at end of probe
 */
static void cdev_rxq_init_buff(mxgbe_priv_t *priv, int qn,
			       mxgbe_rx_buff_t *rxq_buff)
{
	mxgbe_descr_t descr;

	descr.ctrl.r = 0;
	descr.ctrl.RC.BUFSIZE = (rxq_buff->size >> 3) - 1;
	descr.addr.r = 0;
	descr.addr.RC.BUFPTR = rxq_buff->dma;
	descr.addr.RC.OWNER = XX_OWNER_HW;

	/* return */ mxgbe_rxq_request(priv, qn, &descr);
} /* cdev_rxq_init_buff */

#endif /* 0 */


/**
 ******************************************************************************
 * DMA mem
 ******************************************************************************
 */

static long dma_mem_alloc(mxgbe_priv_t *priv, mxgbe_mem_ptrs_t *mem_ptrs)
{
	long ret = 0;
	int i;

	struct scatterlist *sglist;
	int nents;

	uint64_t first_page, last_page, fp_offset;
	unsigned int npages;
	struct page **pages;

	struct pci_dev *pdev = priv->pdev;

	uint64_t uaddr = mem_ptrs->useraddr;
	size_t bytecount = mem_ptrs->bytes;


	FDEBUG;

	/* clean */
	mem_ptrs->dmaaddr = 0;
	mem_ptrs->len = 0;
	mem_ptrs->pages = 0;
	mem_ptrs->npages = 0;
	mem_ptrs->nents = 0;
	mem_ptrs->sg = 0;

	DEV_DBG(MXGBE_DBG_MSK_CDEV, priv->dev,
		"useraddr=0x%llX, bytecount=0x%zX(%zu)\n",
		uaddr, bytecount, bytecount);
	if (0 == uaddr || 0 == bytecount) {
		return -EINVAL;
	}

	/* get_user_pages */

	first_page = (uaddr & PAGE_MASK) >> PAGE_SHIFT;
	last_page = ((uaddr+bytecount-1) & PAGE_MASK) >> PAGE_SHIFT;
	fp_offset = uaddr & ~PAGE_MASK;
	npages = last_page - first_page + 1;

	DEV_DBG(MXGBE_DBG_MSK_CDEV, priv->dev,
		"first_p=%llu, last_p=%llu, fp_offset=%llu(%llX), npages=%u\n",
		first_page, last_page, fp_offset, fp_offset, npages);

	pages = kmalloc_node(sizeof(struct page *) * npages, GFP_KERNEL,
			      dev_to_node(&pdev->dev));
	if (!pages) {
		dev_err(priv->dev,
			"kmalloc for pages failure\n");
		return -ENOMEM;
	}

	down_read(&current->mm->mmap_sem);
	/* KERNEL_VERSION < 4, 5, 0
	ret = get_user_pages(current, current->mm, uaddr & PAGE_MASK,
			     npages, 1, 0, pages, NULL);
	*/
	ret = get_user_pages(uaddr & PAGE_MASK,
			     npages, FOLL_WRITE, pages, NULL);
	up_read(&current->mm->mmap_sem);
	if (ret != npages) {
		dev_err(priv->dev,
			"get_user_pages failure\n");
		npages = ret; /* for SetPageDirty & page_cache_release */
		ret = -EINVAL;
		goto out_unpage;
	}
	ret = 0;
	/* save for dma_mem_free */
	mem_ptrs->pages = pages;
	mem_ptrs->npages = npages;

	/* map pages */

	sglist = kcalloc(npages, sizeof(*sglist), GFP_KERNEL);
	if (NULL == sglist) {
		dev_err(priv->dev,
			"kcalloc for sglist failure\n");
		ret = -ENOMEM;
		goto out_unpage;
	}

	/* per-page */
	for (i = 0; i < npages; i++) {
		if (i == 0) { /* first */
			sg_set_page(&sglist[i], pages[i],
				    PAGE_SIZE - fp_offset, fp_offset);
			DEV_DBG(MXGBE_DBG_MSK_CDEV, priv->dev,
				"first page[%d]=%p, offset=0x%X, len=%u\n",
				i, pages[i], sglist[i].offset,
				sglist[i].length);
		} else if (i == npages-1) { /* last */
			sg_set_page(&sglist[i], pages[i],
				    bytecount-(PAGE_SIZE-fp_offset)-
				    ((npages-2)*PAGE_SIZE), 0);
			DEV_DBG(MXGBE_DBG_MSK_CDEV, priv->dev,
				"last page[%d]=%p, offset=0x%X, len=%u\n",
				i, pages[i], sglist[i].offset,
				sglist[i].length);
		} else { /* middle */
			sg_set_page(&sglist[i], pages[i],
				    PAGE_SIZE, 0);
			/*DEV_DBG(MXGBE_DBG_MSK_CDEV, priv->dev,
				"middle page[%d]=%p, offset=0x%X, len=%u\n",
				i, pages[i], sglist[i].offset,
				sglist[i].length);*/
		}
	} /* for (i) */

	nents = dma_map_sg(&priv->pdev->dev, sglist, npages, DMA_BIDIRECTIONAL);
	if (0 == nents) {
		dev_err(priv->dev, "map1 sglist error - npages=%d, nents=%d\n",
			npages, nents);
		ret = -ENOMEM;
		goto out_unalloc;
	}
#if 0  /* move chk if (1!=nents) to user */
	if (1 != nents) {
		dev_err(priv->dev, "map1 sglist error nents%d != 1\n", nents);
		ret = -ENOMEM;
		goto out_unmap;
	}
#endif /* 0 */

	DEV_DBG(MXGBE_DBG_MSK_CDEV, priv->dev,
		"map sglist - npages=%d, nents=%d\n", npages, nents);
	/* save for dma_mem_free */
	mem_ptrs->nents = nents;
	mem_ptrs->sg = sglist;

	/* To User */
	mem_ptrs->dmaaddr = sg_dma_address(sglist);
	mem_ptrs->len = sg_dma_len(sglist);

	return 0;


#if 0  /* move chk if (1!=nents) to user */
out_unmap:
	if (nents) {
		dma_unmap_sg(&priv->pdev->dev, sglist, npages,
			     DMA_BIDIRECTIONAL);
	}
#endif /* 0 */
out_unalloc:
	kfree(sglist);
out_unpage:
	for (i = 0; i < npages; i++) {
		if (!PageReserved(pages[i]))
			SetPageDirty(pages[i]);
		/* KERNEL_VERSION < 4, 5, 0
		page_cache_release(pages[i]);
		*/
		put_page(pages[i]);
	}

	kfree(pages);
	return ret;
} /* dma_mem_alloc */


static void dma_mem_free(mxgbe_priv_t *priv, mxgbe_mem_ptrs_t *mem_ptrs)
{
	int i;
	unsigned int npages = mem_ptrs->npages;
	struct page **pages = mem_ptrs->pages;

	struct scatterlist *sglist = mem_ptrs->sg;


	FDEBUG;

	if (npages) {
		dma_unmap_sg(&priv->pdev->dev, sglist, npages,
			     DMA_BIDIRECTIONAL);
	}
	kfree(sglist);

	for (i = 0; i < npages; i++) {
		if (!PageReserved(pages[i]))
			SetPageDirty(pages[i]);
		/* KERNEL_VERSION < 4, 5, 0
		page_cache_release(pages[i]);
		*/
		put_page(pages[i]);
	}

	kfree(pages);
} /* dma_mem_free */


/**
 ******************************************************************************
 * read/write
 ******************************************************************************
 */

static long cdev_write(mxgbe_priv_t *priv, mxgbe_mem_ptrs_t *mem_ptrs)
{
	long err = 0;
	uint64_t t_addr;
	int qn = 0;

	FDEBUG;

	t_addr = mem_ptrs->dmaaddr;

	DEV_DBG(MXGBE_DBG_MSK_CDEV, priv->dev,
		"cdev_write: qn=%d, addr=%016llX size=%zu\n",
		qn, t_addr, mem_ptrs->bytes);

	err = mxgbe_txq_dbg_test_s(priv, qn, t_addr, mem_ptrs->bytes);
	if (err)
		return err;

	/* wait for Tx */
	err = mxgbe_txq_dbg_test_r(priv, qn);

	return err;
} /* cdev_write */


static long cdev_read_req(mxgbe_priv_t *priv, mxgbe_mem_ptrs_t *mem_ptrs)
{
	long err = 0;
	uint64_t t_addr;
	int qn = 0;

	FDEBUG;

	t_addr = mem_ptrs->dmaaddr;

	DEV_DBG(MXGBE_DBG_MSK_CDEV, priv->dev,
		"cdev_read_req: qn=%d, addr=%016llX size=%zu\n",
		qn, t_addr, mem_ptrs->bytes);

	err = mxgbe_rxq_dbg_test_s(priv, qn, t_addr, mem_ptrs->bytes);

	return err;
} /* cdev_read_req */


static long cdev_read_ind(mxgbe_priv_t *priv, mxgbe_mem_ptrs_t *mem_ptrs)
{
	long err = 0;
	uint64_t t_addr;
	int qn = 0;

	FDEBUG;

	t_addr = mem_ptrs->dmaaddr;

	DEV_DBG(MXGBE_DBG_MSK_CDEV, priv->dev,
		"cdev_read_ind: qn=%d, addr=%016llX size=%zu\n",
		qn, t_addr, mem_ptrs->bytes);

	/* chk for Rx */
	err = mxgbe_rxq_dbg_test_r(priv, qn);

	return err;
} /* cdev_read_ind */


/**
 ******************************************************************************
 * file operation part (Char device methods)
 ******************************************************************************
 */

typedef struct {
	mxgbe_priv_t *priv;
} cdev_priv_t;


#define FIOCTL_COPY_FROM_USER(val) \
do { \
	if (copy_from_user((caddr_t)&(val), uarg, _IOC_SIZE(cmd))) { \
		dev_err(priv->dev, "IOCTL: copy_from_user failure\n"); \
		ret = -EFAULT; \
		break; \
	} \
} while (0)

#define FIOCTL_COPY_TO_USER(val) \
do { \
	if (copy_to_user(uarg, (caddr_t)&(val), _IOC_SIZE(cmd))) { \
		dev_err(priv->dev, "IOCTL: copy_to_user failure\n"); \
		ret = -EFAULT; \
	} \
} while (0)


/**
 * ioctl file operation
 */
static long cdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	cdev_priv_t *cpriv;
	mxgbe_priv_t *priv;
	void __user *uarg = (void __user *) arg;


	FDEBUG;

	cpriv = (cdev_priv_t *)filp->private_data;
	assert(cpriv);
	if (!cpriv)
		return -ENODEV;

	priv = (mxgbe_priv_t *)(cpriv->priv);
	assert(priv);
	if (!priv)
		return -ENODEV;


	if ((_IOC_TYPE(cmd) != MXGBE_IOC_MAGIC)) {
		dev_err(priv->dev, "IOCTL ERROR: invalid command 0x%X(%d)\n",
			cmd, cmd);
		return -ENOTTY;
	}

	DEV_DBG(MXGBE_DBG_MSK_CDEV, priv->dev, "CDEV_IOCTL: 0x%X(%d)\n",
		cmd, cmd);

	switch (cmd) {

	case MXGBE_IOCTL_WRITE:
	{
		mxgbe_mem_ptrs_t mem_ptrs;

		FIOCTL_COPY_FROM_USER(mem_ptrs);
		ret = dma_mem_alloc(priv, &mem_ptrs);
		if (ret)
			break;
		ret = cdev_write(priv, &mem_ptrs);
		dma_mem_free(priv, &mem_ptrs);
		break;
	}

	case MXGBE_IOCTL_READ_REQ:
	{
		mxgbe_mem_ptrs_t mem_ptrs;

		FIOCTL_COPY_FROM_USER(mem_ptrs);
		ret = dma_mem_alloc(priv, &mem_ptrs);
		if (ret)
			break;
		ret = cdev_read_req(priv, &mem_ptrs);
		FIOCTL_COPY_TO_USER(mem_ptrs);
		break;
	}

	case MXGBE_IOCTL_READ_IND:
	{
		mxgbe_mem_ptrs_t mem_ptrs;

		FIOCTL_COPY_FROM_USER(mem_ptrs);
		ret = cdev_read_ind(priv, &mem_ptrs);
		if (ret)
			break;
		dma_mem_free(priv, &mem_ptrs);
		break;
	}

	/* FUTURE: MCST_SELFTEST_MAGIC
	case MCST_SELFTEST_MAGIC:
	{
		if (copy_to_user(uarg, (caddr_t)&?, _IOC_SIZE(cmd))) {
			dev_err(priv->dev,
				"%s MCST_SELFTEST: copy_to_user failure\n",
				__func__);
			ret = -EFAULT;
		}
		break;
	}
	*/

	default:
	{
		dev_err(priv->dev, "IOCTL ERROR: invalid command 0x%X(%d)\n",
			cmd, cmd);
		return -ENOTTY;
	}
	} /* switch( cmd ) */

	return ret;
} /* cdev_ioctl */


#ifdef CONFIG_COMPAT

static int do_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	FDEBUG;

	return cdev_ioctl(filp, cmd, arg);
}

static long compat_ioctl(struct file *filp, unsigned int cmd,
			 unsigned long arg)
{
	FDEBUG;

	return do_ioctl(filp, cmd, arg);
}

#endif /* CONFIG_COMPAT */


/**
 * open file operation
 */
static int cdev_open(struct inode *inode, struct file *filp)
{
	cdev_priv_t *cpriv;
	mxgbe_priv_t *priv;

	FDEBUG;

	priv = container_of(inode->i_cdev, mxgbe_priv_t, cdev);
	assert(priv);
	if (!priv)
		return -ENODEV;

	spin_lock(&priv->cdev_open_lock);
	if (1 == priv->device_open) {
		spin_unlock(&priv->cdev_open_lock);
		DEV_DBG(MXGBE_DBG_MSK_CDEV, priv->dev,
			"CDEV_OPEN WARNING: device busy!\n");
		return -EBUSY;
	}
	spin_unlock(&priv->cdev_open_lock);

	filp->private_data = kzalloc(sizeof(cdev_priv_t), GFP_KERNEL);
	cpriv = (cdev_priv_t *)filp->private_data;
	assert(cpriv);
	if (!cpriv)
		return -ENOMEM;
	cpriv->priv = priv;

	kobject_get(&priv->dev->kobj);

	DEV_DBG(MXGBE_DBG_MSK_CDEV, priv->dev, "CDEV_OPEN\n");

	return 0;
} /* cdev_open */


/**
 * close file operation
 */
static int cdev_release(struct inode *inode, struct file *filp)
{
	cdev_priv_t *cpriv;
	mxgbe_priv_t *priv;

	FDEBUG;

	cpriv = (cdev_priv_t *)filp->private_data;
	assert(cpriv);
	if (!cpriv)
		return -ENODEV;

	priv = cpriv->priv;
	assert(priv);
	if (!priv)
		return -ENODEV;

	DEV_DBG(MXGBE_DBG_MSK_CDEV, priv->dev, "CDEV_CLOSE\n");

	kobject_put(&priv->dev->kobj);

	kfree(filp->private_data);
	filp->private_data = NULL;

	return 0;
} /* cdev_release */


/**
 * file operation
 */
static const struct file_operations dev_fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.unlocked_ioctl	= cdev_ioctl,
    #ifdef CONFIG_COMPAT
	.compat_ioctl	= compat_ioctl,
    #endif
	.open		= cdev_open,
	.release	= cdev_release,
};


/**
 ******************************************************************************
 * GLOBAL
 ******************************************************************************
 */

#define DEVICE_FIRST	  0
#define ALL_DEVICE_COUNT  (1U << MINORBITS)        /* max minor num */
#define MAX_DEVICE_COUNT  (ALL_DEVICE_COUNT >> 2)  /* ==max/4 - ... */
#define DEVICE_COUNT	  ((MAX_DEVICE_COUNT > 32) ? 32 : MAX_DEVICE_COUNT)


static struct class *DevClass;

static int Major = 0;

static DEFINE_MUTEX(minor_lock);
static int last_minor = 0;
static int minors[DEVICE_COUNT] = {-1};
static char bus_name[DEVICE_COUNT][20] = { {0} };


/**
 ******************************************************************************
 * Minor part of cdev
 ******************************************************************************
 */

/*
 * Allocate minor for current PCI device
 */
static int get_minor(mxgbe_priv_t *priv, unsigned int *minor)
{
	int ret = -EINVAL;
	int i;
	struct pci_dev *pdev = priv->pdev;

	FDEBUG;

	mutex_lock(&minor_lock);
	/* find prev minor for busname */
	for (i = 0; i < last_minor; i++) {
		if (0 == strcmp(dev_name(&pdev->dev), bus_name[i])) {
			*minor = minors[i];
			DEV_DBG(MXGBE_DBG_MSK_CDEV, &pdev->dev,
				"Found saved minor: %d (%s)\n",
				*minor, dev_name(&pdev->dev));
			ret = 0;
			break;
		}
	}
	if (ret != 0) {
		if (DEVICE_COUNT == last_minor) {
			dev_err(&pdev->dev, "ERROR: too many char devices\n");
		} else {
			/* new busname */
			minors[last_minor] = last_minor;
			strcpy(bus_name[last_minor], dev_name(&pdev->dev));
			*minor = last_minor;
			last_minor += 1;
			ret = 0;
			DEV_DBG(MXGBE_DBG_MSK_CDEV, &pdev->dev,
				"Save minor %d for bus %s\n",
				*minor, bus_name[*minor]);
		}
	}
	mutex_unlock(&minor_lock);

	return ret;
} /* get_minor */


static void free_minor(unsigned int minor)
{
	FDEBUG;

	/*
	mutex_lock(&minor_lock);
	mutex_unlock(&minor_lock);
	*/
} /* free_minor */


/**
 * Create cdev for IRQ or DMA
 */
int mxgbe_cdev_register(mxgbe_priv_t *priv)
{
	int ret = 0;
	dev_t devt;
	unsigned int minor;
	char name[20];
	struct pci_dev *pdev;

	FDEBUG;

	assert(priv);
	if (!priv)
		return -ENODEV;

	pdev = priv->pdev;
	assert(pdev);
	if (!pdev)
		return -ENODEV;

	ret = get_minor(priv, &minor);
	if (ret) {
		dev_err(&pdev->dev, "ERROR: get_minor failed\n");
		goto err_exit;
	}

	sprintf(name, "%s%d", MXGBE_DEVNAME, minor);
	devt = MKDEV(Major, minor);
	DEV_DBG(MXGBE_DBG_MSK_CDEV, &pdev->dev,
		"try to register char device (%d:%d)\n", Major, minor);

	cdev_init(&priv->cdev, &dev_fops);
	priv->cdev.owner = THIS_MODULE;
	priv->minor = minor;

	ret = cdev_add(&priv->cdev, devt, 1);
	if (ret) {
		dev_err(&pdev->dev,
			"ERROR: failed to add char device %d:%d\n",
			Major, minor);
		goto err_free_idr;
	}

	priv->dev = device_create(DevClass, &pdev->dev, devt,
				  NULL, name);
	if (IS_ERR(priv->dev)) {
		dev_err(&pdev->dev,
			"ERROR: char device register failed\n");
		ret = PTR_ERR(priv->dev);
		goto err_del_cdev;
	}
	dev_info(&pdev->dev, "char device %s (%d:%d) installed\n",
		 name, Major, minor);

	minor += DEVICE_COUNT;
	return 0;

err_del_cdev:
	cdev_del(&priv->cdev);
err_free_idr:
	free_minor(minor);
err_exit:
	return ret;
} /* mxgbe_cdev_register */


/**
 * Remove cdev
 */
void mxgbe_cdev_remove(mxgbe_priv_t *priv)
{
	FDEBUG;

	assert(priv);
	if (!priv)
		return;

	DEV_DBG(MXGBE_DBG_MSK_CDEV, priv->dev,
		"char device (%d:%d) removed\n", Major, priv->minor);

	device_destroy(DevClass, MKDEV(Major, priv->minor));
	cdev_del(&priv->cdev);
	free_minor(priv->minor);
} /* mxgbe_cdev_remove */


/**
 ******************************************************************************
 * Major part of cdev
 ******************************************************************************
 */

static int major_init(void)
{
	int ret = 0;
	dev_t devt = 0;

	FDEBUG;

	ret = alloc_chrdev_region(&devt, DEVICE_FIRST, ALL_DEVICE_COUNT,
				  DRIVER_NAME);
	if (ret) {
		ERR_MSG("ERROR: Could not register char device region\n");
		goto err_exit;
	}

	Major = MAJOR(devt);

	PDEBUG(MXGBE_DBG_MSK_CDEV,
	       "chrdev_region registered: major %d\n",
	       Major);

	return 0;

err_exit:
	return ret;
} /* major_init */


static void major_delete(void)
{
	FDEBUG;

	unregister_chrdev_region(MKDEV(Major, 0), ALL_DEVICE_COUNT);

	PDEBUG(MXGBE_DBG_MSK_CDEV,
	       "chrdev_region unregistered (major %d)\n",
	       Major);
} /* major_delete */


/**
 * Get Major and register class for cdev
 */
int __init mxgbe_dev_init(void)
{
	int ret;

	FDEBUG;

	ret = major_init();
	if (ret)
		goto err_exit;

	/* class register */
	DevClass = class_create(THIS_MODULE, DRIVER_NAME);
	if (IS_ERR(DevClass)) {
		ERR_MSG("ERROR: couldn't create class %s\n", DRIVER_NAME);
		ret = PTR_ERR(DevClass);
		goto err_class_register;
	}
	PDEBUG(MXGBE_DBG_MSK_CDEV, "class %s created\n", DRIVER_NAME);

	return 0;

err_class_register:
	major_delete();
err_exit:
	return ret;
} /* mxgbe_dev_init */


/**
 * Deregister class for cdev and free major
 */
void mxgbe_dev_exit(void)
{
	FDEBUG;

	class_destroy(DevClass);
	major_delete();

	PDEBUG(MXGBE_DBG_MSK_CDEV, "class %s destroyed\n", DRIVER_NAME);
} /* mxgbe_dev_exit */



#if 0

/**
 * First Init RXQ# at start of probe
 * called from mxgbe_cdev_register
 */
int cdev_rxq_init_q(mxgbe_priv_t *priv, int qn)
{
	int err;
	int i;
	mxgbe_rx_buff_t *rxq_buff;

	FDEBUG;

	DEV_DBG(MXGBE_DBG_MSK_CDEV, &priv->pdev->dev,
		"rxq_init(qn=%d): alloc %d buffers for Rx\n",
		qn, priv->rxq[qn].descr_cnt);

	rxq_buff = priv->rxq[qn].rx_buff;
	for (i = 0; i < priv->rxq[qn].descr_cnt; i++) {
		/* Alloc RAM for RX Data */
		err = cdev_rxq_alloc_buff(priv, rxq_buff);
		if (err)
			goto err_free_ring;
		rxq_buff++;
	}

	/* Init Rx ring */
	rxq_buff = priv->rxq[qn].rx_buff;
	for (i = 0; i < priv->rxq[qn].descr_cnt - 1; i++) {
		cdev_rxq_init_buff(priv, qn, rxq_buff);
		rxq_buff++;
	}

	return 0;

err_free_ring:
	return err;
} /* rxq_init_q */

void cdev_rxq_clean_q(mxgbe_priv_t *priv, int qn)
{
	int i;
	mxgbe_rx_buff_t *rxq_buff;

	FDEBUG;

	rxq_buff = priv->rxq[qn].rx_buff;
	for (i = 0; i < priv->rxq[qn].descr_cnt; i++) {
		cdev_rxq_clean_buff(priv, rxq_buff);
		rxq_buff++;
	}
} /* rxq_clean_q */
#endif


#if 0
/* mxgbe_txq_free_all(mxgbe_priv_t *priv) */
/* FIXME: move to net or cdev -> mxgbe_cdev_remove */
		/* Free RAM for RX Data */
		rxq_clean_q(priv, qn);
/* mxgbe_txq_free_all */
#endif

#if 0
/* int mxgbe_rxq_init_all(mxgbe_priv_t *priv) */
/* FIXME: move to cdev -> mxgbe_cdev_register 1 */
		if (rxq_init_q(priv, qn)) {
			dev_err(&priv->pdev->dev,
				"ERROR: DMA_ALLOC_RAM qn=%d\n", qn);
			/* ? mxgbe_txq_free_all(priv); */
			return -ENOMEM;
		}
/* mxgbe_rxq_init_all */
#endif

#if 0
/* mxgbe_rxq_start(mxgbe_priv_t *priv, int qn) */
	int i;
	mxgbe_rx_buff_t *rxq_buff;
/* FIXME: move to cdev -> mxgbe_cdev_register 2 */
	/* Init Rx ring */
	rxq_buff = priv->rxq[qn].rx_buff;
	for (i = 0; i < priv->rxq[qn].descr_cnt - 1; i++) {
		rxq_init_buff(priv, qn, rxq_buff);
		rxq_buff++;
	}
/* mxgbe_rxq_start */
#endif


/**
 ******************************************************************************
 * DEBUG
 ******************************************************************************
 */

int mxgbe_txq_dbg_test_s(mxgbe_priv_t *priv, int qn, uint64_t buf, int len)
{
	mxgbe_descr_t descr;

	FDEBUG;

	descr.ctrl.r = 0;
	descr.ctrl.TC.IPV6 = 0;
	descr.ctrl.TC.IPCSUM = 0;
	descr.ctrl.TC.L4CSUM = 0;
	descr.ctrl.TC.BUFSIZE = (len >> 3);
	descr.ctrl.TC.MSS = TC_MSS_NOSPLIT;
	descr.ctrl.TC.NTCP_UDP = 0;
	descr.ctrl.TC.TCPHDR = 0;
	descr.ctrl.TC.IPHDR = 0;
	descr.ctrl.TC.L4HDR = 0;
	descr.ctrl.TC.FRMSIZE = len - 1;

	descr.addr.TC.BUFPTR = buf;
	descr.addr.TC.SPLIT = TC_SPLIT_NO;
	descr.addr.TC.OWNER = XX_OWNER_HW;

	return mxgbe_txq_send(priv, qn, &descr, NULL);
} /* mxgbe_txq_dbg_test_s */


int mxgbe_txq_dbg_test_r(mxgbe_priv_t *priv, int qn)
{
	int err = 0;
	void __iomem *base = priv->bar0_base;
	unsigned long timestart;
	u16 head;
	u16 tail;

	FDEBUG;

	timestart = jiffies;

	/* wait for Tx */
	do {
		head = Q_HEAD_GET_PTR(mxgbe_rreg32(base,
						   TXQ_REG_ADDR(qn, Q_HEAD)));
		/* FIXME: must readed only from IRQ -> priv->txq[qn].tail */
		tail = Q_TAIL_GET_PTR(mxgbe_rreg32(base,
						   TXQ_REG_ADDR(qn, Q_TAIL)));
		if (time_after(jiffies, timestart + HZ)) {
			err = -EAGAIN;
			break;
		}
	} while (head != tail);

	DEV_DBG(MXGBE_DBG_MSK_CDEV, &priv->pdev->dev,
		"txq_dbg_test_r %s: head=%u, tail=%u\n",
		(err) ? "Error" : "Ok", head, tail);

	return err;
} /* mxgbe_txq_dbg_test_r */


int mxgbe_rxq_dbg_test_s(mxgbe_priv_t *priv, int qn, uint64_t buf, int len)
{
	mxgbe_descr_t descr;

	FDEBUG;

	descr.ctrl.r = 0;
	descr.ctrl.RC.BUFSIZE = (len >> 3) - 1;

	descr.addr.r = 0;
	descr.addr.RC.BUFPTR = buf;
	descr.addr.RC.OWNER = XX_OWNER_HW;

	return mxgbe_rxq_request(priv, qn, &descr, 0/*FIXME: head*/);
} /* mxgbe_rxq_dbg_test_s */

int mxgbe_rxq_dbg_test_r(mxgbe_priv_t *priv, int qn)
{
	int err = 0;
	void __iomem *base = priv->bar0_base;
	unsigned long timestart;
	u16 head;
	u16 tail;

	FDEBUG;

	timestart = jiffies;

	/* wait for Rx */
	do {
		head = Q_HEAD_GET_PTR(mxgbe_rreg32(base,
						   RXQ_REG_ADDR(qn, Q_HEAD)));
		/* FIXME: read only from IRQ */
		tail = Q_TAIL_GET_PTR(mxgbe_rreg32(base,
						   RXQ_REG_ADDR(qn, Q_TAIL)));
		if (time_after(jiffies, timestart + HZ)) {
			err = -EAGAIN;
			break;
		}
	} while (head != tail);

	DEV_DBG(MXGBE_DBG_MSK_CDEV, &priv->pdev->dev,
		"rxq_dbg_test_r: %s head=%u, tail=%u\n",
		(err) ? "Error" : "Ok", head, tail);

	return err;
} /* mxgbe_rxq_dbg_test_r */
