/**
 * m2mlc_dev.c - M2MLC module device driver
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

#include "m2mlc.h"


#ifndef VM_RESERVED
    #define VM_RESERVED 0
#endif


/* extern */
u32 m2mlc_read_reg32(void __iomem *base_addr, u32 port);
void m2mlc_write_reg32(void __iomem *base_addr, u32 port, u32 val);
void m2mlc_hw_print_all_regs(m2mlc_priv_t *priv, uint32_t regmsk);
void m2mlc_hw_pio_start(m2mlc_priv_t *priv, int ep, m2mlc_pio_cmd_t *pio_cmd);
void m2mlc_hw_pio_getstat(m2mlc_priv_t *priv, int ep, uint8_t *piostat/*,
			  int complete*/);
void m2mlc_hw_mb_getptrs_mail(m2mlc_priv_t *priv, int ep,
			      m2mlc_mb_ptrs_t *mbptrs);
void m2mlc_hw_mb_getptrs_done(m2mlc_priv_t *priv, int ep,
			       m2mlc_mb_ptrs_t *mbptrs);
void m2mlc_hw_mb_settailptr_mail(m2mlc_priv_t *priv, int ep,
				 uint16_t tail_ptr);
void m2mlc_hw_mb_settailptr_done(m2mlc_priv_t *priv, int ep,
				 uint16_t tail_ptr);
void m2mlc_hw_db_getptrs(m2mlc_priv_t *priv, int ep, m2mlc_db_ptrs_t *dbptrs);
void m2mlc_hw_db_settailptr(m2mlc_priv_t *priv, int ep, uint16_t tail_ptr);
void m2mlc_hw_int_setmask(m2mlc_priv_t *priv, int ep,
			  m2mlc_interrupt_t intmask);
void m2mlc_hw_int_clear(m2mlc_priv_t *priv, int ep,
			m2mlc_interrupt_t intclr);
void m2mlc_hw_int_getstat(m2mlc_priv_t *priv, int ep,
			  m2mlc_int_stat_t *intstat);
void m2mlc_hw_dma_getptrs_str(m2mlc_priv_t *priv, int ep,
			      m2mlc_dma_str_ptrs_t *dmaptrs);
void m2mlc_hw_dma_getptrs_done(m2mlc_priv_t *priv, int ep,
			       m2mlc_dma_done_ptrs_t *dmaptrs);
void m2mlc_hw_dma_setheadptr_str(m2mlc_priv_t *priv, int ep,
				 uint16_t head_ptr);
void m2mlc_hw_dma_settailptr_done(m2mlc_priv_t *priv, int ep,
				  uint16_t tail_ptr);


/**
 ******************************************************************************
 * Mem alloc for DMA
 ******************************************************************************
 */

static long dma_mem_alloc(m2mlc_priv_t *priv, m2mlc_mem_ptrs_t *mem_ptrs)
{
	long ret = 0;
	int i;

	struct scatterlist *sglist;
	int nents;
#ifdef USE_DUALIOLINK
	int nentsf;
#endif /* USE_DUALIOLINK */

	uint64_t first_page, last_page, fp_offset;
	unsigned int npages;
	struct page **pages;

	uint64_t uaddr = mem_ptrs->useraddr;
	size_t bytecount = mem_ptrs->bytes;

	/* clean */
	mem_ptrs->dmaaddr = 0;
	mem_ptrs->len = 0;
	/* TODO: move to internal list */
	mem_ptrs->pages = 0;
	mem_ptrs->npages = 0;
	mem_ptrs->nents = 0;
	mem_ptrs->sg = 0;

	DEV_DBG(M2MLC_DBG_MSK_CDEV, priv->dev,
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

	DEV_DBG(M2MLC_DBG_MSK_CDEV, priv->dev,
		"first_p=%llu, last_p=%llu, fp_offset=%llu(%llX), npages=%u\n",
		first_page, last_page, fp_offset, fp_offset, npages);

	pages = kmalloc(sizeof(struct page *) * npages, GFP_KERNEL);
	if (!pages) {
		dev_err(priv->dev,
			"kmalloc for pages failure\n");
		return -ENOMEM;
	}

	down_read(&current->mm->mmap_sem);
	ret = get_user_pages(current, current->mm, uaddr & PAGE_MASK,
			     npages, 1, 0, pages, NULL);
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
			DEV_DBG(M2MLC_DBG_MSK_CDEV, priv->dev,
				"first page[%d]=%p, offset=0x%X, len=%u\n",
				i, pages[i], sglist[i].offset,
				sglist[i].length);
		} else if (i == npages-1) { /* last */
			sg_set_page(&sglist[i], pages[i],
				    bytecount-(PAGE_SIZE-fp_offset)-
				    ((npages-2)*PAGE_SIZE), 0);
			DEV_DBG(M2MLC_DBG_MSK_CDEV, priv->dev,
				"last page[%d]=%p, offset=0x%X, len=%u\n",
				i, pages[i], sglist[i].offset,
				sglist[i].length);
		} else { /* middle */
			sg_set_page(&sglist[i], pages[i],
				    PAGE_SIZE, 0);
			/*DEV_DBG(M2MLC_DBG_MSK_CDEV, priv->dev,
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
	if (1 != nents) {
		dev_err(priv->dev, "map1 sglist error nents%d != 1\n", nents);
		ret = -ENOMEM;
		goto out_unmap;
	}

#ifdef USE_DUALIOLINK
	nentsf = dma_map_sg(&priv->fakedev->dev, sglist, npages,
			   DMA_BIDIRECTIONAL);
	if (0 == nentsf) {
		dev_err(priv->dev, "map2 sglist error - npages=%d, nents=%d\n",
			npages, nentsf);
		ret = -ENOMEM;
		goto out_unalloc;
	}
	if (nentsf != nents) {
		dev_err(priv->dev, "map1 nents(%d) != map2 nents(%d)\n",
			nents, nentsf);
		ret = -EINVAL;
		goto out_unalloc;
	}
#endif /* USE_DUALIOLINK */

	DEV_DBG(M2MLC_DBG_MSK_CDEV, priv->dev,
		"map sglist - npages=%d, nents=%d\n", npages, nents);
	/* save for dma_mem_free */
	mem_ptrs->nents = nents;
	mem_ptrs->sg = sglist;

	/* To User */
	mem_ptrs->dmaaddr = sg_dma_address(sglist);
	mem_ptrs->len = sg_dma_len(sglist);

	return 0;


out_unmap:
	if (nents) {
		dma_unmap_sg(&priv->pdev->dev, sglist, npages,
			     DMA_BIDIRECTIONAL);
#ifdef USE_DUALIOLINK
		dma_unmap_sg(&priv->fakedev->dev, sglist, npages,
			     DMA_BIDIRECTIONAL);
#endif
	}
out_unalloc:
	kfree(sglist);
out_unpage:
	for (i = 0; i < npages; i++) {
		if (!PageReserved(pages[i]))
			SetPageDirty(pages[i]);
		page_cache_release(pages[i]);
	}

	kfree(pages);
	return ret;
} /* dma_mem_alloc */

static void dma_mem_free(m2mlc_priv_t *priv, m2mlc_mem_ptrs_t *mem_ptrs)
{
	int i;
	unsigned int npages = mem_ptrs->npages;
	struct page **pages = mem_ptrs->pages;

	struct scatterlist *sglist = mem_ptrs->sg;

	if (npages) {
		dma_unmap_sg(&priv->pdev->dev, sglist, npages,
			     DMA_BIDIRECTIONAL);
#ifdef USE_DUALIOLINK
		dma_unmap_sg(&priv->fakedev->dev, sglist, npages,
			     DMA_BIDIRECTIONAL);
#endif /* USE_DUALIOLINK */
	}
	kfree(sglist);

	for (i = 0; i < npages; i++) {
		if (!PageReserved(pages[i]))
			SetPageDirty(pages[i]);
		page_cache_release(pages[i]);
	}

	kfree(pages);
} /* dma_mem_free */


/**
 ******************************************************************************
 * file operation part (Char device methods)
 ******************************************************************************
 */

/* .mmap_id */
#define MMAP_ENDPOINT_REGS_ID	0x001
#define MMAP_PIO_PAYLOAD_ID	0x002
#define MMAP_PIO_DONE_QUEUE_ID	0x004
#define MMAP_PIO_DATA_QUEUE_ID	0x008
#define MMAP_DONE_REGS_COPY_ID	0x020
#define MMAP_DB_QUEUE_ID	0x040
#define MMAP_DMA_DESCR_QUEUE_ID	0x080
#define MMAP_DMA_DONE_QUEUE_ID	0x100
#define MMAP_MB_DONE_QUEUE_ID	0x200
#define MMAP_MB_MAIL_ID		0x400


typedef struct {
	m2mlc_priv_t *priv;
	int endpoint;
	unsigned int mmap_id;
} cdev_priv_t;


#define FIOCTL_CHECK_ENDPOINT_NONE \
do { \
	if (cpriv->endpoint == CDEV_ENDPOINT_NONE) { \
		dev_err(priv->dev, "IOCTL ERROR: endpoint not opened\n"); \
		ret = -EFAULT; \
		break; \
	} \
} while (0)

#define FIOCTL_CHECK_MMAP_REGS \
do { \
	if (cpriv->mmap_id & MMAP_ENDPOINT_REGS_ID) { \
		dev_err(priv->dev, "IOCTL ERROR: registers mmaped\n"); \
		ret = -EFAULT; \
		break; \
	} \
} while (0)

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
	m2mlc_priv_t *priv;
	struct pci_dev *pdev;
	void __user *uarg = (void __user *) arg;


	cpriv = (cdev_priv_t *)filp->private_data;
	assert(cpriv);
	if (!cpriv)
		return -ENODEV;

	priv = cpriv->priv;
	assert(priv);
	if (!priv)
		return -ENODEV;

	pdev = priv->pdev;
	assert(pdev);
	if (!pdev)
		return -ENODEV;

	if ((_IOC_TYPE(cmd) != M2MLC_IOC_MAGIC)) {
		dev_err(priv->dev, "IOCTL ERROR: invalid command 0x%X(%d)\n",
			cmd, cmd);
		return -ENOTTY;
	}

	DEV_DBG(M2MLC_DBG_MSK_CDEV, priv->dev, "CDEV_IOCTL: 0x%X(%d)\n",
		cmd, cmd);


	switch (cmd) {

	/* Open/Close Endpoint */

	case M2MLC_IOCTL_OPEN_ENDPOINT:
	{
		m2mlc_resource_t res;

		if (cpriv->endpoint != CDEV_ENDPOINT_NONE) {
			dev_err(priv->dev,
				"IOCTL_OPEN_ENDPOINT ERROR: " \
				"used endpoint %d\n", cpriv->endpoint);
			ret = -EAGAIN;
			break;
		}

		FIOCTL_COPY_FROM_USER(res);

		if (res.num > priv->niccpb_procval) {
			dev_err(priv->dev,
				"IOCTL_OPEN_ENDPOINT ERROR: " \
				"wrong endpoint number %d\n", res.num);
			ret = -EFAULT;
			break;
		}

		if (res.num == CDEV_ENDPOINT_NET) {
			dev_err(priv->dev,
				"IOCTL_OPEN_ENDPOINT ERROR: " \
				"endpoint number %d reserved\n", res.num);
			ret = -EFAULT;
			break;
		}

		if ((res.num > CDEV_ENDPOINT_UMAX) ||
		   (res.num < CDEV_ENDPOINT_UMIN)) {
			if (__kuid_val(current_euid()) != 0) {
				dev_err(priv->dev,
					"IOCTL_OPEN_ENDPOINT ERROR: " \
					"endpoint number %d, for root only\n",
					res.num);
				ret = -EACCES;
				break;
			}
		}

		spin_lock(&priv->cdev_open_lock);
		if (priv->pid[res.num] != 0) {
			spin_unlock(&priv->cdev_open_lock);
			dev_err(priv->dev,
				"IOCTL_OPEN_ENDPOINT ERROR: " \
				"endpoint busy\n");
			ret = -EBUSY;
			break;
		}
		cpriv->endpoint = res.num;
		priv->signal[res.num] = res.signal;
		priv->pid[res.num] = (int)current->pid;
		priv->tsk[res.num] = current;
		spin_unlock(&priv->cdev_open_lock);
		break;
	}

	case M2MLC_IOCTL_CLOSE_ENDPOINT:
	{
		if (cpriv->endpoint != CDEV_ENDPOINT_NONE) {
			spin_lock(&priv->cdev_open_lock);
			priv->signal[cpriv->endpoint] = 0;
			priv->pid[cpriv->endpoint] = 0;
			priv->tsk[cpriv->endpoint] = NULL;
			cpriv->endpoint = CDEV_ENDPOINT_NONE;
			spin_unlock(&priv->cdev_open_lock);
		}
		break;
	}

	/* PIO */

	case M2MLC_IOCTL_PIO_START:
	{
		uint8_t piostat;
		m2mlc_pio_cmd_t pio_cmd;

		FIOCTL_CHECK_ENDPOINT_NONE;
		FIOCTL_CHECK_MMAP_REGS;
		FIOCTL_COPY_FROM_USER(pio_cmd);
		m2mlc_hw_pio_getstat(priv, cpriv->endpoint, &piostat/*, 0*/);
		if (M2MLC_PIO_BLOCK_BUSY & piostat) {
			dev_err(priv->dev, "IOCTL ERROR: resource busy\n");
			ret = -EBUSY;
			break;
		}
		m2mlc_hw_pio_start(priv, cpriv->endpoint, &pio_cmd);
		break;
	}

	case M2MLC_IOCTL_PIO_GETSTAT:
	{
		uint8_t piostat;

		FIOCTL_CHECK_ENDPOINT_NONE;
		m2mlc_hw_pio_getstat(priv, cpriv->endpoint, &piostat/*, 1*/);
		FIOCTL_COPY_TO_USER(piostat);
		break;
	}

	/* Mailbox */

	case M2MLC_IOCTL_MB_GETPTRS_MAIL:
	{
		m2mlc_mb_ptrs_t mbptrs;

		FIOCTL_CHECK_ENDPOINT_NONE;
		m2mlc_hw_mb_getptrs_mail(priv, cpriv->endpoint, &mbptrs);
		FIOCTL_COPY_TO_USER(mbptrs);
		break;
	}

	case M2MLC_IOCTL_MB_SETTAILPTR_MAIL:
	{
		uint16_t tail_ptr;

		FIOCTL_CHECK_ENDPOINT_NONE;
		FIOCTL_CHECK_MMAP_REGS;
		FIOCTL_COPY_FROM_USER(tail_ptr);
		m2mlc_hw_mb_settailptr_mail(priv, cpriv->endpoint, tail_ptr);
		break;
	}

	case M2MLC_IOCTL_MB_GETPTRS_DONE:
	{
		m2mlc_mb_ptrs_t mbptrs;

		FIOCTL_CHECK_ENDPOINT_NONE;
		m2mlc_hw_mb_getptrs_done(priv, cpriv->endpoint, &mbptrs);
		FIOCTL_COPY_TO_USER(mbptrs);
		break;
	}

	case M2MLC_IOCTL_MB_SETTAILPTR_DONE:
	{
		uint16_t tail_ptr;

		FIOCTL_CHECK_ENDPOINT_NONE;
		FIOCTL_CHECK_MMAP_REGS;
		FIOCTL_COPY_FROM_USER(tail_ptr);
		m2mlc_hw_mb_settailptr_done(priv, cpriv->endpoint, tail_ptr);
		break;
	}

	/* DoorBell */

	case M2MLC_IOCTL_DB_GETPTRS:
	{
		m2mlc_db_ptrs_t dbptrs;

		FIOCTL_CHECK_ENDPOINT_NONE;
		m2mlc_hw_db_getptrs(priv, cpriv->endpoint, &dbptrs);
		FIOCTL_COPY_TO_USER(dbptrs);
		break;
	}

	case M2MLC_IOCTL_DB_SETTAILPTR:
	{
		uint16_t tail_ptr;

		FIOCTL_CHECK_ENDPOINT_NONE;
		FIOCTL_CHECK_MMAP_REGS;
		FIOCTL_COPY_FROM_USER(tail_ptr);
		m2mlc_hw_db_settailptr(priv, cpriv->endpoint, tail_ptr);
		break;
	}

	/* Interrupt */

	case M2MLC_IOCTL_INT_SETMASK:
	{
		m2mlc_interrupt_t intmask;

		FIOCTL_CHECK_ENDPOINT_NONE;
		FIOCTL_CHECK_MMAP_REGS;
		FIOCTL_COPY_FROM_USER(intmask);
		m2mlc_hw_int_setmask(priv, cpriv->endpoint, intmask);
		break;
	}

#if 0
	case M2MLC_IOCTL_INT_CLEAR:
	{
		m2mlc_interrupt_t intclr;

		FIOCTL_CHECK_ENDPOINT_NONE;
		FIOCTL_CHECK_MMAP_REGS;
		FIOCTL_COPY_FROM_USER(intclr);
		m2mlc_hw_int_clear(priv, cpriv->endpoint, intclr);
		break;
	}
#endif /* 0 */

	case M2MLC_IOCTL_INT_GETSTATUS:
	{
		m2mlc_int_stat_t intstat;

		FIOCTL_CHECK_ENDPOINT_NONE;
		m2mlc_hw_int_getstat(priv, cpriv->endpoint, &intstat);
#if 0
		/* TODO: lock & clean fromirq */
		/* intstat->fromirq.r = 0; */ /* TODO: new RTL */
#endif /* 0 */
		FIOCTL_COPY_TO_USER(intstat);
		break;
	}

	/* DMA */

	case M2MLC_IOCTL_DMA_GETPTRS_STR:
	{
		m2mlc_dma_str_ptrs_t dmaptrs;

		FIOCTL_CHECK_ENDPOINT_NONE;
		m2mlc_hw_dma_getptrs_str(priv, cpriv->endpoint, &dmaptrs);
		FIOCTL_COPY_TO_USER(dmaptrs);
		break;
	}

	case M2MLC_IOCTL_DMA_SETHEADPTR_STR:
	{
		uint16_t head_ptr;

		FIOCTL_CHECK_ENDPOINT_NONE;
		FIOCTL_CHECK_MMAP_REGS;
		FIOCTL_COPY_FROM_USER(head_ptr);
		m2mlc_hw_dma_setheadptr_str(priv, cpriv->endpoint, head_ptr);
		break;
	}

	case M2MLC_IOCTL_DMA_GETPTRS_DONE:
	{
		m2mlc_dma_done_ptrs_t dmaptrs;

		FIOCTL_CHECK_ENDPOINT_NONE;
		m2mlc_hw_dma_getptrs_done(priv, cpriv->endpoint, &dmaptrs);
		FIOCTL_COPY_TO_USER(dmaptrs);
		break;
	}

	case M2MLC_IOCTL_DMA_SETTAILPTR_DONE:
	{
		uint16_t tail_ptr;

		FIOCTL_CHECK_ENDPOINT_NONE;
		FIOCTL_CHECK_MMAP_REGS;
		FIOCTL_COPY_FROM_USER(tail_ptr);
		m2mlc_hw_dma_settailptr_done(priv, cpriv->endpoint, tail_ptr);
		break;
	}

	/* MEM for DMA */

	case M2MLC_IOCTL_MEM_LOC:
	{
		m2mlc_mem_ptrs_t mem_ptrs;

		FIOCTL_CHECK_ENDPOINT_NONE;
		FIOCTL_COPY_FROM_USER(mem_ptrs);

		ret = dma_mem_alloc(priv, &mem_ptrs);
		if (ret)
			break;

		FIOCTL_COPY_TO_USER(mem_ptrs);
		break;
	}

	case M2MLC_IOCTL_MEM_REL:
	{
		m2mlc_mem_ptrs_t mem_ptrs;

		FIOCTL_CHECK_ENDPOINT_NONE;
		FIOCTL_COPY_FROM_USER(mem_ptrs);

		dma_mem_free(priv, &mem_ptrs);
		break;
	}

	/* ECS */

	case M2MLC_IOCTL_ECS_READ_REG:
	{
		m2mlc_ecs_reg_t reg;

		if (copy_from_user((caddr_t)&reg, uarg, _IOC_SIZE(cmd))) {
			dev_err(priv->dev,
				"IOCTL_ECS_READ_REG: " \
				"copy_from_user failure\n");
			ret = -EFAULT;
			break;
		}

		switch (reg.id) {
		case ECS_DEVID_CAR:
		case ECS_DEVINF_CAR:
		case ECS_ASMBLID_CAR:
		case ECS_ASMBLINF_CAR:
		case ECS_PEF_CAR:
		case ECS_PELLCTRL_CSR:
		case ECS_GPSTAT_CSR:
		case ECS_BASEDEVID_CSR:
		case ECS_HBASEDEVIDLOCK_CSR:
		case ECS_ROUTE_RESP:
		case ECS_PHYSTAT_CTRL:
		case ECS_RTACCSTAT_0:
		case ECS_RTACCSTAT_1:
		case ECS_RTACCSTAT_2:
		case ECS_RTACCSTAT_3:
		case ECS_RTACCSTAT_4:
		case ECS_RTACCSTAT_5:
		case ECS_RTACCSTAT_6:
		case ECS_RTACCSTAT_7:
			reg.val = m2mlc_read_reg32(priv->ecs_base, reg.id);
			break;
		default:
			dev_err(priv->dev,
				"IOCTL_ECS_READ_REG: " \
				"wrong register ID\n");
			ret = -EINVAL;
			break;
		}

		if (copy_to_user(uarg, (caddr_t)&reg, _IOC_SIZE(cmd))) {
			dev_err(priv->dev,
				"IOCTL_ECS_READ_REG: " \
				"copy_to_user failure\n");
			ret = -EFAULT;
		}
		break;
	}

	case M2MLC_IOCTL_ECS_WRITE_REG:
	{
		m2mlc_ecs_reg_t reg;

		if (__kuid_val(current_euid()) != 0) {
			dev_err(priv->dev,
				"IOCTL_ECS_WRITE_REG ERROR: " \
				"for root only\n");
			ret = -EACCES;
			break;
		}

		if (copy_from_user((caddr_t)&reg, uarg, _IOC_SIZE(cmd))) {
			dev_err(priv->dev,
				"IOCTL_ECS_WRITE_REG: " \
				"copy_from_user failure\n");
			ret = -EFAULT;
			break;
		}

		switch (reg.id) {
		case ECS_PELLCTRL_CSR:
		case ECS_GPSTAT_CSR:
		case ECS_BASEDEVID_CSR:
		case ECS_HBASEDEVIDLOCK_CSR:
		case ECS_ROUTE_RESP:
			m2mlc_write_reg32(priv->ecs_base, reg.id, reg.val);
			break;
		default:
			dev_err(priv->dev,
				"IOCTL_ECS_WRITE_REG: " \
				"wrong register ID\n");
			ret = -EINVAL;
			break;
		}
		break;
	}

	/* debug */

	case M2MLC_IOCTL_PRINT_REGS:
	{
		uint32_t regmsk;

		if (copy_from_user((caddr_t)&regmsk, uarg, _IOC_SIZE(cmd))) {
			dev_err(priv->dev,
				"IOCTL_PRINT_REGS: " \
				"copy_from_user failure\n");
			ret = -EFAULT;
			break;
		}

		m2mlc_hw_print_all_regs(priv, regmsk);
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
	return cdev_ioctl(filp, cmd, arg);
}

static long compat_ioctl(struct file *filp, unsigned int cmd,
			 unsigned long arg)
{
	return do_ioctl(filp, cmd, arg);
}

#endif /* CONFIG_COMPAT */


/**
 * mmap file operation
 * Remap DMA memory to user
 */
static int cdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	cdev_priv_t *cpriv;
	m2mlc_priv_t *priv;

	phys_addr_t base_bus;
	void *ram_buff;
	unsigned long base_size;

	unsigned long off = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long long pfn;
	unsigned long vsize;
	unsigned long psize;


	cpriv = (cdev_priv_t *)filp->private_data;
	assert(cpriv);
	if (!cpriv)
		return -ENODEV;

	priv = cpriv->priv;
	assert(priv);
	if (!priv)
		return -ENODEV;

	if (cpriv->endpoint == CDEV_ENDPOINT_NONE) {
		dev_err(priv->dev, "MMAP ERROR: endpoint not opened\n");
		return -ENODEV;
	}

	DEV_DBG(M2MLC_DBG_MSK_CDEV, priv->dev, "off=%ld\n", off);
	if (off < M2MLC_MMAP_PIO_DONE_QUEUE_BASE) {
		/* 0..8k: mmap HW bufs */
		if (off == M2MLC_MMAP_ENDPOINT_REGS_BASE) {
			base_bus = priv->reg_base_bus +
				   (cpriv->endpoint * PAGE_SIZE);
			base_size = M2MLC_MMAP_ENDPOINT_REGS_SIZE;
			cpriv->mmap_id |= MMAP_ENDPOINT_REGS_ID;
		} else if (off == M2MLC_MMAP_PIO_PAYLOAD_BASE) {
			base_bus = priv->buf_base_bus +
				   (cpriv->endpoint * PAGE_SIZE);
			base_size = M2MLC_MMAP_PIO_PAYLOAD_SIZE;
			cpriv->mmap_id |= MMAP_PIO_PAYLOAD_ID;
		} else {
			dev_err(priv->dev,
				"MMAP ERROR: Wrong offset: 0x%lX\n", off);
			return -EINVAL;
		}

		/* FIXME: x86
		pfn = page_to_pfn(virt_to_page(bus_to_virt(base_bus)));
		*/
    #ifdef CONFIG_E90
		pfn = MK_IOSPACE_PFN(0xa, (base_bus >> PAGE_SHIFT));
    #else
		pfn = base_bus >> PAGE_SHIFT;
    #endif

		vsize = vma->vm_end - vma->vm_start;
		psize = (PAGE_SIZE > base_size) ? PAGE_SIZE : base_size;

		DEV_DBG(M2MLC_DBG_MSK_CDEV, priv->dev,
			"mmap HW bufs: pfn=%#llx (off=%ld, bus=%#llx), "
			"vsize=%#lx, psize=%#lx\n",
			pfn, off, (u64)base_bus, vsize, psize);

		if (vsize > psize) {
			dev_err(priv->dev,
				"MMAP ERROR: vsize > psize\n");
			return -EINVAL;
		}

		vma->vm_pgoff = 0;
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		vma->vm_flags |= (VM_READ | VM_WRITE | VM_IO |
				  VM_DONTCOPY | VM_RESERVED);

		if (io_remap_pfn_range(vma, vma->vm_start, pfn, vsize,
		    vma->vm_page_prot)) {
			dev_err(priv->dev,
				"MMAP ERROR: Error remap memory to user\n");
			return -EAGAIN;
		}
	} else {
		/* mmap RAM bufs */
		if (off == M2MLC_MMAP_PIO_DONE_QUEUE_BASE) {
			ram_buff = priv->pio_done_que_buff +
#ifdef USE_MUL2ALIGN
				   priv->pio_done_que_offset +
#endif /* USE_MUL2ALIGN */
				   (cpriv->endpoint * PAGE_SIZE);
			base_size = M2MLC_MMAP_PIO_DONE_QUEUE_SIZE;
			cpriv->mmap_id |= MMAP_PIO_DONE_QUEUE_ID;
		} else if (off == M2MLC_MMAP_PIO_DATA_QUEUE_BASE) {
			ram_buff = priv->pio_data_que_buff +
#ifdef USE_MUL2ALIGN
				   priv->pio_data_que_offset +
#endif /* USE_MUL2ALIGN */
				   (cpriv->endpoint * PAGE_SIZE);
			base_size = M2MLC_MMAP_PIO_DATA_QUEUE_SIZE;
			cpriv->mmap_id |= MMAP_PIO_DATA_QUEUE_ID;
		} else if (off == M2MLC_MMAP_DONE_REGS_COPY_BASE) {
			ram_buff = priv->mdd_ret_buff[cpriv->endpoint];
			base_size = M2MLC_MMAP_DONE_REGS_COPY_SIZE;
			cpriv->mmap_id |= MMAP_DONE_REGS_COPY_ID;
		} else if (off == M2MLC_MMAP_DB_QUEUE_BASE) {
			ram_buff = priv->db_start_buff[cpriv->endpoint];
			base_size = M2MLC_MMAP_DB_QUEUE_SIZE;
			cpriv->mmap_id |= MMAP_DB_QUEUE_ID;
		} else if (off == M2MLC_MMAP_DMA_DESCR_QUEUE_BASE) {
#ifdef USE_MUL2ALIGN
			ram_buff = priv->dma_start_buff[cpriv->endpoint] +
				   priv->dma_start_offset;
#else
			ram_buff = priv->dma_start_buff[cpriv->endpoint];
#endif /* USE_MUL2ALIGN */
			base_size = M2MLC_MMAP_DMA_DESCR_QUEUE_SIZE;
			cpriv->mmap_id |= MMAP_DMA_DESCR_QUEUE_ID;
		} else if (off == M2MLC_MMAP_DMA_DONE_QUEUE_BASE) {
#ifdef USE_MUL2ALIGN
			ram_buff = priv->dma_done_que_buff[cpriv->endpoint] +
				   priv->dma_done_offset;
#else
			ram_buff = priv->dma_done_que_buff[cpriv->endpoint];
#endif /* USE_MUL2ALIGN */
			base_size = M2MLC_MMAP_DMA_DONE_QUEUE_SIZE;
			cpriv->mmap_id |= MMAP_DMA_DONE_QUEUE_ID;
		} else if (off == M2MLC_MMAP_MB_DONE_QUEUE_BASE) {
#ifdef USE_MUL2ALIGN
			ram_buff = priv->mb_done_que_buff[cpriv->endpoint] +
				   priv->mb_done_offset;
#else
			ram_buff = priv->mb_done_que_buff[cpriv->endpoint];
#endif /* USE_MUL2ALIGN */
			base_size = M2MLC_MMAP_MB_DONE_QUEUE_SIZE;
			cpriv->mmap_id |= MMAP_MB_DONE_QUEUE_ID;
		} else if (off == M2MLC_MMAP_MB_MAIL_BASE) {
#ifdef USE_MUL2ALIGN
			ram_buff = priv->mb_struct_buff[cpriv->endpoint] +
				   priv->mb_struct_offset;
#else
			ram_buff = priv->mb_struct_buff[cpriv->endpoint];
#endif /* USE_MUL2ALIGN */
			base_size = M2MLC_MMAP_MB_MAIL_SIZE;
			cpriv->mmap_id |= MMAP_MB_MAIL_ID;
		} else {
			dev_err(priv->dev,
				"MMAP ERROR: Wrong offset: 0x%lX\n", off);
			return -EINVAL;
		}

		pfn = ((u64)virt_to_phys(ram_buff)) >> PAGE_SHIFT;
		vsize = vma->vm_end - vma->vm_start;
		psize = base_size;

		DEV_DBG(M2MLC_DBG_MSK_CDEV, priv->dev,
			"mmap RAM bufs: pfn=%#llx (off=%ld, phys_mem=%#llx, "
			"vsize=%#lx, psize=%#lx\n",
			pfn, off, (u64)virt_to_phys(ram_buff),
			vsize, psize);

		if (vsize > psize) {
			dev_err(priv->dev,
				"MMAP ERROR: vsize > psize\n");
			return -EINVAL;
		}

		vma->vm_pgoff = 0;
		vma->vm_flags |= (VM_READ | VM_WRITE |
				  VM_DONTCOPY | VM_RESERVED);

		if (remap_pfn_range(vma, vma->vm_start, pfn, vsize,
		    vma->vm_page_prot)) {
			dev_err(priv->dev,
				"MMAP ERROR: Error remap memory to user\n");
			return -EAGAIN;
		}
	}

	return 0;
} /* cdev_mmap */


#define RPRINT(fmt, args...) \
do { \
	len += sprintf(l_buf + len, fmt, ## args); \
} while (0)

/**
 * read file operation
 * Read device info and current status
 *
 * Returns:
 *   -ENODEV
 *   -EFAULT - copy_from/to_user failure
 *   >0 - bytes readed
 */
static ssize_t cdev_read(struct file *filp, char *buf, size_t count,
			 loff_t *ppos)
{
	size_t len;
	char *l_buf;
	cdev_priv_t *cpriv;
	m2mlc_priv_t *priv;
	int i, j;
	u_int32_t reg_id[] = {
		/*
		ECS_DEVID_CAR,
		ECS_DEVINF_CAR,
		ECS_ASMBLID_CAR,
		ECS_ASMBLINF_CAR,
		ECS_PEF_CAR,
		ECS_PELLCTRL_CSR,
		*/
		ECS_GPSTAT_CSR,
		ECS_BASEDEVID_CSR,
		ECS_HBASEDEVIDLOCK_CSR,
		ECS_ROUTE_RESP,
		ECS_PHYSTAT_CTRL
	};
	char *reg_name[] = {
		/*
		"Device_Identity_CAR           ",
		"Device_Information_CAR        ",
		"Assembly_Identity_CAR         ",
		"Assembly_Information_CAR      ",
		"Processing_Elem_Features_CAR  ",
		"Processing_Elem_LogLayCtrl_CSR",
		*/
		"General_Port_Status_CSR       ",
		"Base_Device_ID_CSR            ",
		"Host_Base_Device_ID_Lock_CSR  ",
		"Responce Route Field          ",
		"PHY_Port_Pn_Status_Control    ",
		"                              "
	};
	u_int32_t reg_id_rtacc[] = {
		ECS_RTACCSTAT_0,
		ECS_RTACCSTAT_1,
		ECS_RTACCSTAT_2,
		ECS_RTACCSTAT_3,
		ECS_RTACCSTAT_4,
		ECS_RTACCSTAT_5,
		ECS_RTACCSTAT_6,
		ECS_RTACCSTAT_7
	};
	u_int32_t reg_val;
	ecs_devid_car_reg_t ecs_devid_car;
	ecs_devinf_car_reg_t ecs_devinf_car;
	ecs_asmblid_car_reg_t ecs_asmblid_car;
	ecs_asmblinf_car_reg_t ecs_asmblinf_car;
	ecs_pef_car_reg_t ecs_pef_car;
	ecs_pellctrl_csr_reg_t ecs_pellctrl_csr;
	ecs_gpstat_csr_reg_t ecs_gpstat_csr;
	ecs_basedevid_csr_reg_t ecs_basedevid_csr;
	ecs_hbasedevidlock_csr_reg_t ecs_hbasedevidlock_csr;
	ecs_route_resp_reg_t ecs_route_resp;
	ecs_phystat_ctrl_reg_t ecs_phystat_ctrl;
	u_int32_t u32i;


	cpriv = (cdev_priv_t *)filp->private_data;
	assert(cpriv);
	if (!cpriv)
		return -ENODEV;

	priv = cpriv->priv;
	assert(priv);
	if (!priv)
		return -ENODEV;

	if (*ppos != 0)
		return 0; /* EOF */

	l_buf = kzalloc(M2MLC_READ_BUF_SIZE, GFP_KERNEL);
	if (!priv) {
		dev_err(priv->dev,
			"ERROR: Cannot allocate memory, aborting\n");
		return -ENOMEM;
	}

	/* -= read =- */

	len = 0;
	/*01*/
	RPRINT(" -= M2MLC device %s%d =-\n", M2MLC_DEVNAME, priv->minor);
	/*02*/
	RPRINT("EP         PID\t SIG\t\tEP         PID\t SIG\n");
	for (i = 0; i < priv->niccpb_procval; i += 2) {
		/*03..12*/
		RPRINT("%2d: %s %8d\t %d\t\t%2d: %s %8d\t %d\n",
		       i,     ((i       > 16) | (i       == 0)) ? "S" : " ",
		       priv->pid[i],     priv->signal[i],
		       i + 1, (((i + 1) > 16) | ((i + 1) == 0)) ? "S" : " ",
		       priv->pid[i + 1], priv->signal[i + 1]);
	}

	/*13*/
	RPRINT("\n");
	/*14*/
	RPRINT("  Element Config Space:\n");
	for (i = 0; i < ARRAY_SIZE(reg_id); i++) {
		reg_val = m2mlc_read_reg32(priv->ecs_base, reg_id[i]);
		/*15..25*/
		RPRINT("%s: ", reg_name[i]);
		switch (reg_id[i]) {
		case ECS_DEVID_CAR:
			ecs_devid_car.r = reg_val;
			RPRINT("Device_ID=0x%04X ",
			       ecs_devid_car.p.Device_Identity);
			RPRINT("Device_Vendor_ID=0x%04X ",
			       ecs_devid_car.p.Device_Vendor_Identity);
			break;
		case ECS_DEVINF_CAR:
			ecs_devinf_car.r = reg_val;
			RPRINT("Device_Revision=0x%04X ",
			       ecs_devinf_car.p.Device_Revision);
			break;
		case ECS_ASMBLID_CAR:
			ecs_asmblid_car.r = reg_val;
			RPRINT("Assembly_ID=0x%04X ",
			       ecs_asmblid_car.p.Assy_Identity);
			RPRINT("Assembly_Vendor_ID=0x%04X ",
			       ecs_asmblid_car.p.Assy_Vendor_Identity);
			break;
		case ECS_ASMBLINF_CAR:
			ecs_asmblinf_car.r = reg_val;
			RPRINT("Assembly_Revision=0x%04X ",
			       ecs_asmblinf_car.p.Assy_Revision);
			RPRINT("Ext_Feat_Ptr=0x%04X ",
			       ecs_asmblinf_car.p.Extended_Features_Ptr);
			break;
		case ECS_PEF_CAR:
			ecs_pef_car.r = reg_val;
			RPRINT("Bridge%s ",
			       (ecs_pef_car.p.Bridge) ? "+" : "-");
			RPRINT("Memory%s ",
			       (ecs_pef_car.p.Memory) ? "+" : "-");
			RPRINT("Processor%s ",
			       (ecs_pef_car.p.Processor) ? "+" : "-");
			RPRINT("Switch%s ",
			       (ecs_pef_car.p.Switch) ? "+" : "-");
			/*26*/
			RPRINT("\n%s: ", reg_name[ARRAY_SIZE(reg_id)]);
			RPRINT("StdRouteTblCFg%s ",
			       (ecs_pef_car.p.Std_Route_Tbl_CFg_Sup) ? \
				"+" : "-");
			RPRINT("ExtFeat%s ",
			       (ecs_pef_car.p.Extended_Features) ? "+" : "-");
			u32i = ecs_pef_car.p.Extended_Addr_Suport;
			RPRINT("ExtAddrSup=%s/%s/%s ",
			       (u32i & ECS_PEF_CAR_EXTADDRSUP_66) ? "66" : "-",
			       (u32i & ECS_PEF_CAR_EXTADDRSUP_50) ? "50" : "-",
			       (u32i & ECS_PEF_CAR_EXTADDRSUP_34) ? "34" : "-");
			break;
		case ECS_PELLCTRL_CSR:
			ecs_pellctrl_csr.r = reg_val;
			u32i = ecs_pellctrl_csr.p.Extended_Addr_Control;
			RPRINT("Extended_Addr_Control=%s/%s ",
			       (u32i & ECS_PELLCTRL_CSR_EXTADDRCTRL_64) ? \
				"64" : "-",
			       (u32i & ECS_PELLCTRL_CSR_EXTADDRCTRL_32) ? \
				"32" : "-");
			break;
		case ECS_GPSTAT_CSR:
			ecs_gpstat_csr.r = reg_val;
			RPRINT("Auto_Enable%s ",
			       (ecs_gpstat_csr.p.Auto_Enable) ? "+" : "-");
			RPRINT("Discovered%s ",
			       (ecs_gpstat_csr.p.Discovered) ? "+" : "-");
			RPRINT("Host%s ",
			       (ecs_gpstat_csr.p.Host) ? "+" : "-");
			break;
		case ECS_BASEDEVID_CSR:
			ecs_basedevid_csr.r = reg_val;
			RPRINT("Base_DeviceID=0x%02X ",
			       ecs_basedevid_csr.p.Base_DeviceID);
			break;
		case ECS_HBASEDEVIDLOCK_CSR:
			ecs_hbasedevidlock_csr.r = reg_val;
			RPRINT("Host_Base_DeviceID=0x%04X ",
			       ecs_hbasedevidlock_csr.p.Host_Base_DeviceID);
			break;
		case ECS_ROUTE_RESP:
			ecs_route_resp.r = reg_val;
			RPRINT("Msg_Route=0x%01X ",
			       ecs_route_resp.p.Msg_Route);
			RPRINT("RDMA_Route=0x%01X ",
			       ecs_route_resp.p.RDMA_Route);
			break;
		case ECS_PHYSTAT_CTRL:
			ecs_phystat_ctrl.r = reg_val;
			RPRINT("Port_OK%s ",
			       (ecs_phystat_ctrl.p.Port_OK) ? "+" : "-");
			break;
		default:
			RPRINT("=0x%08X ", reg_val);
			break;
		}
		RPRINT("\n");
	}

	/*27*/
	RPRINT("\n");
	/*28*/
	RPRINT("  RT Access Status:\n");
	RPRINT("      0123456789ABCDEF  ");
	/*29*/
	RPRINT("      0123456789ABCDEF\n");
	for (i = 0; i < ARRAY_SIZE(reg_id_rtacc); i++) {
		reg_val = m2mlc_read_reg32(priv->ecs_base, reg_id_rtacc[i]);
		for (j = 0; j < 32; j++) {
			if (0 == j)
				RPRINT("0x%02X: ", i * 32);
			if (16 == j)
				RPRINT("  0x%02X: ", (i * 32) + 16);
			RPRINT("%s", ((reg_val >> j) & 1) ? "*" : ".");
			if (31 == j)
				RPRINT("  - 0x%08X", reg_val);
		}
		/*30..37*/
		RPRINT("\n");
	}
	/*_38_*/
	RPRINT("\n");

	/* set _38_ to M2MLC_READ_BUF_SIZE in m2mlc_io.h */
	/* -= read =- */

	if (count < len) {
		dev_err(priv->dev,
			"READ ERROR: needed %zu bytes for read\n", len);
		kfree(l_buf);
		return -EINVAL;
	}

	if (copy_to_user(buf, l_buf, len)) {
		dev_err(priv->dev,
			"READ ERROR: copy_to_user failure\n");
		kfree(l_buf);
		return -EFAULT;
	}
	*ppos = len;

	DEV_DBG(M2MLC_DBG_MSK_CDEV, priv->dev,
		"CDEV_READ: readed %zu bytes\n", len);

	kfree(l_buf);
	return len;
} /* cdev_read */


/**
 * write file operation
 * Write mask for print regs dump to syslog
 *
 * Returns:
 *   -ENODEV
 *   -EFAULT - copy_from/to_user failure
 *   >0 - bytes written
 */
static ssize_t cdev_write(struct file *filp, const char *buf, size_t count,
			  loff_t *ppos)
{
	size_t len;
	cdev_priv_t *cpriv;
	m2mlc_priv_t *priv;
	char l_buf[M2MLC_WRITE_BUF_SIZE+1];
	uint32_t regmsk;

	cpriv = (cdev_priv_t *)filp->private_data;
	assert(cpriv);
	if (!cpriv)
		return -ENODEV;

	priv = cpriv->priv;
	assert(priv);
	if (!priv)
		return -ENODEV;

	/* max to write */
	len = M2MLC_WRITE_BUF_SIZE;
	len = (count < len) ? count : len;

	if (copy_from_user((void *)l_buf, (void *)buf, len)) {
		dev_err(priv->dev,
			"WRITE ERROR: copy_from_user failure\n");
		return -EFAULT;
	}
	l_buf[len] = 0;

	sscanf(l_buf, "%x", &regmsk);
	DEV_DBG(M2MLC_DBG_MSK_CDEV, priv->dev,
		"CDEV_WRITE: regmsk = 0x%08X\n", regmsk);

	if (regmsk) {
		m2mlc_hw_print_all_regs(priv, regmsk);
	}

	return count; /*len;*/
} /* cdev_write */


/**
 * open file operation
 */
static int cdev_open(struct inode *inode, struct file *filp)
{
	cdev_priv_t *cpriv;
	m2mlc_priv_t *priv;

	priv = container_of(inode->i_cdev, m2mlc_priv_t, cdev);
	assert(priv);
	if (!priv)
		return -ENODEV;

	spin_lock(&priv->cdev_open_lock);
	if (1 == priv->device_open) {
		spin_unlock(&priv->cdev_open_lock);
		DEV_DBG(M2MLC_DBG_MSK_CDEV, priv->dev,
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
	cpriv->endpoint = CDEV_ENDPOINT_NONE;

	kobject_get(&priv->dev->kobj);

	DEV_DBG(M2MLC_DBG_MSK_CDEV, priv->dev, "CDEV_OPEN\n");

	return 0;
} /* cdev_open */

/**
 * close file operation
 */
static int cdev_release(struct inode *inode, struct file *filp)
{
	cdev_priv_t *cpriv;
	m2mlc_priv_t *priv;

	cpriv = (cdev_priv_t *)filp->private_data;
	assert(cpriv);
	if (!cpriv)
		return -ENODEV;

	priv = cpriv->priv;
	assert(priv);
	if (!priv)
		return -ENODEV;

	DEV_DBG(M2MLC_DBG_MSK_CDEV, priv->dev, "CDEV_CLOSE\n");

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
	.read		= cdev_read,
	.write		= cdev_write,
	.mmap		= cdev_mmap,
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
static int get_minor(m2mlc_priv_t *priv, unsigned int *minor)
{
	int ret = -EINVAL;
	int i;
	struct pci_dev *pdev = priv->pdev;

	mutex_lock(&minor_lock);
	/* find prev minor for busname */
	for (i = 0; i < last_minor; i++) {
		if (0 == strcmp(dev_name(&pdev->dev), bus_name[i])) {
			*minor = minors[i];
			DEV_DBG(M2MLC_DBG_MSK_CDEV, &pdev->dev,
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
			DEV_DBG(M2MLC_DBG_MSK_CDEV, &pdev->dev,
				"Save minor %d for bus %s\n",
				*minor, bus_name[*minor]);
		}
	}
	mutex_unlock(&minor_lock);

	return ret;
} /* get_minor */

static void free_minor(unsigned int minor)
{
	/*
	mutex_lock(&minor_lock);
	mutex_unlock(&minor_lock);
	*/
} /* free_minor */


/**
 * Create cdev for IRQ or DMA
 */
int m2mlc_cdev_register(m2mlc_priv_t *priv)
{
	int ret = 0;
	dev_t devt;
	unsigned int minor;
	char name[20];
	struct pci_dev *pdev;

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

	sprintf(name, "%s%d", M2MLC_DEVNAME, minor);
	devt = MKDEV(Major, minor);
	DEV_DBG(M2MLC_DBG_MSK_CDEV, &pdev->dev,
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
} /* m2mlc_cdev_register */

/**
 * Remove cdev
 */
void m2mlc_cdev_remove(m2mlc_priv_t *priv)
{
	assert(priv);
	if (!priv)
		return;

	DEV_DBG(M2MLC_DBG_MSK_CDEV, priv->dev,
		"char device (%d:%d) removed\n", Major, priv->minor);

	device_destroy(DevClass, MKDEV(Major, priv->minor));
	cdev_del(&priv->cdev);
	free_minor(priv->minor);
} /* m2mlc_cdev_remove */


/**
 ******************************************************************************
 * Major part of cdev
 ******************************************************************************
 */

static int major_init(void)
{
	int ret = 0;
	dev_t devt = 0;

	ret = alloc_chrdev_region(&devt, DEVICE_FIRST, ALL_DEVICE_COUNT,
				  DRIVER_NAME);
	if (ret) {
		ERR_MSG("ERROR: Could not register char device region\n");
		goto err_exit;
	}

	Major = MAJOR(devt);

	PDEBUG(M2MLC_DBG_MSK_CDEV,
	       "chrdev_region registered: major %d\n",
	       Major);

	return 0;

err_exit:
	return ret;
} /* major_init */

static void major_delete(void)
{
	unregister_chrdev_region(MKDEV(Major, 0), ALL_DEVICE_COUNT);

	PDEBUG(M2MLC_DBG_MSK_CDEV,
	       "chrdev_region unregistered (major %d)\n",
	       Major);
} /* major_delete */


/**
 * Get Major and register class for cdev
 */
int __init m2mlc_dev_init(void)
{
	int ret;

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
	PDEBUG(M2MLC_DBG_MSK_CDEV, "class %s created\n", DRIVER_NAME);

	return 0;

err_class_register:
	major_delete();
err_exit:
	return ret;
} /* m2mlc_dev_init */

/**
 * Deregister class for cdev and free major
 */
void m2mlc_dev_exit(void)
{
	class_destroy(DevClass);
	major_delete();

	PDEBUG(M2MLC_DBG_MSK_CDEV, "class %s destroyed\n", DRIVER_NAME);
} /* m2mlc_dev_exit */
