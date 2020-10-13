/*
 * Copyright (c) 1997 by MCST.
 */

/*
 *	mbk3.c
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/miscdevice.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/gfp.h>

#include <linux/mm.h>
#include <linux/mcst/ddi.h>
#include <linux/mcst/p2ssbus.h>
#include <linux/timex.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/of_platform.h>

#include <linux/delay.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/dma.h>
#include <asm/irq.h>
#include <asm/string.h>
#include <asm/of_device.h>
#include <linux/vmalloc.h>
#include "bk3.h"

#define MAX_MVP_MINORS	16
#if IS_ENABLED(CONFIG_PCI2SBUS)
#define board_name1	"mbk3"	/* should be same as FCODE.name without "MCST," prefix */
#define board_name2	"mbk3e"	/* should be same as FCODE.name without "MCST," prefix */
#else
#define board_name1	"MCST,mbk3"	/* should be same as FCODE.name */
#define board_name2	"MCST,mbk3e"	/* should be same as FCODE.name */
#endif

#define DEV_DEVN(d)	(getminor(d))		/* dev_t -> minor (dev_num) */
#define DEV_CHAN(d)	DEV_chan(DEV_DEVN(d)) 	/* dev_t -> channel */
#define DEV_inst(m)	(m >> 3)		/* minor -> instance */
#define DEV_chan(m)	(m & 0x7)		/* minor -> channel */
#define DEV_MINOR(i, c)	((i << 3) | (c))	/* instance + channel -> minor*/
#define DEV_INST(d)	DEV_inst(DEV_DEVN(d))	/* dev_t -> instance */

/*--------    struct for class mbk3 in sysfs --------------------------------*/
static struct class *mbk3_class;

/*--------    DMA attributes of BK3    --------------------------------------*/

static u_char	burst_codes[] = {0x0, 0x0, 0x0, 0x7, 0x4, 0x5, 0x6}; 


/*--------    Driver entry points    ----------------------------------------*/

static int bk3_sbus_remove(struct of_device *op);
static int bk3_sbus_probe(struct of_device *op, const struct of_device_id *match);

static int  bk3_open(struct inode *inode, struct file *file);
static int  bk3_close(struct inode *inode, struct file *file);
static int  bk3_mmap (struct file *file, struct vm_area_struct *vma);
static long  bk3_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
/*---------------------------------------------------------------------------*/


/*
 *
 * file_operations
 *
 */
static struct file_operations bk3_fops = {
	.owner   = THIS_MODULE,
	.open    = bk3_open,  /* open*/
	.release = bk3_close, /* close */
	.mmap    = bk3_mmap,  /* mmap */
	.unlocked_ioctl   = bk3_ioctl, /* ioctl */
};

static const struct of_device_id bk3_sbus_match[] = {
        {
                .name = board_name1,
        },
        {
                .name = board_name2,
        },
        {},
};

MODULE_DEVICE_TABLE(of, bk3_sbus_match);

static struct of_platform_driver bk3_sbus_driver = {
        .name           = "MCST,bk3 sbus",
        .match_table    = bk3_sbus_match,
        .probe          = bk3_sbus_probe,
        .remove         = bk3_sbus_remove,
};

static int bk3_sbus_major;

/* Find all the lance cards on the system and initialize them */
static int __init bk3_init(void)
{
        bk3_sbus_major = register_chrdev(0, "MCST,bk3 sbus", &bk3_fops);
        return of_register_driver(&bk3_sbus_driver, &of_platform_bus_type);
}

static void __exit bk3_exit(void)
{
        of_unregister_driver(&bk3_sbus_driver);
	unregister_chrdev(bk3_sbus_major, "MCST,bk3 sbus");
}

/*--------    Auxuliary functions    ----------------------------------------*/

static int my_bk3_detach(struct of_device *op, int step);

/*
 *
 * For Linux add these lines
 *
 */

module_init(bk3_init);
module_exit(bk3_exit);
MODULE_AUTHOR("Copyright by MCST 2004");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MBK3 driver");

struct bk3_file_private {
        int             count;
	int		instance;
        dev_t           dev;
};

#define MX_BK3_INSTANCES	32
static bk3_devstate_t *bk3_states[MX_BK3_INSTANCES];


#define	file_bk3_state(file)	\
	bk3_states[((struct bk3_file_private*)file->private_data)->instance]

static int bk3_sbus_probe(struct of_device *op, const struct of_device_id *match)
{
	bk3_devstate_t *bks = NULL;
	int	inst;
	int	rval = 0;
	int	step = 0;
        int     flags = 0;
        int	burstes;
	u_int	int_reg;
	char name[30];

        for (inst = 0; inst < MAX_MVP_MINORS; inst++) {
                if (bk3_states[inst] == NULL) {
                        break;
                }
        }
        if (inst >= MX_BK3_INSTANCES) {
                printk("Too many mvps in system (max = %d)\n", MX_BK3_INSTANCES);
                return -EINVAL;
        }
        bks = ddi_malloc(sizeof (bk3_devstate_t));
        memset(bks, 0, sizeof (*bks));
        dev_set_drvdata(&op->dev, bks);

	bks->instance = inst;
        if (strcmp(match->name, board_name2) == 0) {
                bks->type = MBK3_OPTIC;
        }
	if (strcmp(match->name, board_name2) == 0) {
		bks->type = MBK3_ELECTRIC;
	}
	bks->op = op;
	bks->io_modes      = BK3_IO_MODES_DEFAULT;
	bks->reset_time    = BK3_RESET_TIME_DEFAULT;
	bks->rd_wait_usecs = BK3_RD_WAIT_DEFAULT;
	bks->wr_wait_usecs = BK3_WR_WAIT_DEFAULT;
	bks->buf_size      = SZ_BUF_BK3;

#if 0
        bkw = kzalloc(sizeof (*bkw), GFP_KERNEL);
        INIT_WORK(&(bks->interrupt_tqueue), bk3_interrupt);
	bkw->bks = bks;
        queue_work(&bks->interrupt_tqueue, &bkw->work);
	
        bkw = kzalloc(sizeof (*bkw), GFP_KERNEL);
	INIT_WORK(&bks->D0_intr_tqueue, bk3_D0_intr_handle);
        bkw->bks = bks;
        queue_work(&bks->D0_intr_tqueue, &bkw->work);
#endif
	mutex_init(&bks->mutex);

	cv_init( &bks->cv_wait_peer_reset);
	cv_init( &bks->cv_reset);
	cv_init( &bks->cv_D0_reset);
	cv_init( &bks->cv_cmd);
	cv_init( &bks->cv_no_read_buffers);
	cv_init( &bks->cv_no_write_buffers); 	
	cv_init( &bks->cv_msg_in);
	cv_init( &bks->cv_msg_out);
	raw_spin_lock_init(&bks->interrupt_lock);  

	bks->bk3_regs_p = (bk3_regs_t *)of_ioremap(&op->resource[0], 0,
                               BK3_REG_SIZE, "MCST,bk3/sbus");
        if (!bks->bk3_regs_p) {
		printk("bk3_attach: MVP-%d: Could not map regs\n", inst);
		return -EINVAL;
	}
	step = 1;

        sprintf(name, "mbk3_%d_0", inst);

        flags = IRQF_SHARED;
#ifdef CONFIG_MCST_RT
        flags |=  IRQF_ONESHOT;
#endif        
#if defined(CONFIG_SBUS)
        rval = request_threaded_irq(op->irqs[0], &bk3_intr, &bk3_interrupt,
			flags, name, bks);
#elif IS_ENABLED(CONFIG_PCI2SBUS)
        rval = sbus_request_irq(op->irqs[0], &bk3_intr, &bk3_interrupt, 
                                flags, name, (void *)bks);
#else
        printk("BK3 driver may be loaded only under SBUS || PCI2SBUS || PCI2SBUS_MODULE configs\n");
        rval -EAGAIN;
        goto failed;
#endif
	if (rval != 0) {
		printk(KERN_ERR "BK3-%d: Can't get irq %d\n", bks->instance, op->irqs[0]);
                rval = -EAGAIN;
		goto failed;
	} else {
                printk("BK3-%d: request_irq is ok\n", bks->instance);
        }
	step = 2;

	burstes = 0x20;
	bks->burst = fls(burstes);
	bks->siz = burst_codes[bks->burst - 1];
	bks->burstes = burstes;

	mbk3_class = class_create(THIS_MODULE, "mbk3");
	if (IS_ERR(mbk3_class)) {
		pr_err("Error creating class: /sys/class/mbk3.\n");
	}
	if (!IS_ERR(mbk3_class)) {
		pr_info("make node /sys/class/mbk3/%s\n", name);
		if (device_create(mbk3_class, NULL,
		    MKDEV(bk3_sbus_major, inst), NULL, name) == NULL)
			pr_err("create a node %d failed\n", inst);
	}

	step = 3;

	SET_BK3_REG(bks, arst, 0);
	int_reg = GET_BK3_REG(bks, intr);
	SET_BK3_MASK(bks, BK3_IM_ALL);
 
	{
		u_int	bk3_mask = GET_BK3_REG(bks, mask);
		udelay(5);
		if ((bk3_mask >> 16) == 0xef7a /* "bk" */)
			bks->version_mbk3 = 1;
		else
			bks->version_mbk3 = 0;
	}
	cmn_err(CE_NOTE, "%s: version:%d (%s)",
			name, bks->version_mbk3,
		bks->version_mbk3 ? "NEW" : "OLD");

/* инициализируем буфера */
	if (bk3_init_pool_buf(bks)) {
                printk("BK3-%d: Could not alloc memory for buffers\n", inst);
                rval = -ENOMEM;
                goto failed;
        }
        step = 4;
	
	bk3_states[inst] = bks;
	mutex_enter(&bks->mutex);

	RESET_STATUS(bks);

	/*
	 * 1 буфер сразу ставим в обмен на прием информации
	 */
	bks->stat.rsize = bks->buf_size;
	bks->stat.r_all_time = 0;
	bks->stat.w_all_time = 0;
	bks->stat.r_start = 0;
	bks->stat.w_start = 0;
	bks->stat.intrs = 0;
	bks->stat.true_intrs = 0;	

	ON_STATUS(bks, PEER_READ_IS_OVER);
	ON_STATUS(bks, PEER_READ_IS_OVER);
	ON_STATUS(bks, WRITE_IS_OVER);

#if 0 /* Недочеты в запуске устройства на чтение */
	{
		bk3_pool_buf_t *pool_buf = &bks->read_pool;
		pool_buf->work_buf = 
			list_entry(pool_buf->free_list.next, bk3_buf_t, list);
		list_del1(pool_buf->free_list.next);
		printk("rstart init = %lld\n", bks->stat.r_start);
		bks->stat.r_start = gethrtime();
		SET_BK3_REG(bks, rcwd, pool_buf->work_buf->address);
		SET_BK3_REG(bks, rcnt, TRANSF_CNT);
	}
#endif
	mutex_exit(&bks->mutex);

	return 0;

failed:
	(void) my_bk3_detach(op, step);
	return (rval);
}

static int bk3_sbus_remove(struct of_device *op)
{
	return my_bk3_detach(op, INT_MAX);
}


static int my_bk3_detach(struct of_device *op, int step)
{	
        bk3_devstate_t *bks = dev_get_drvdata(&op->dev);
        int     inst;
	
	char 		name[256];

	if (bks == NULL) {
		return 0;
	}
	dev_set_drvdata(&op->dev, NULL);
	inst = bks->instance;
	bk3_states[inst] = NULL;
	switch(step) {
	  default:
		 dma_free_coherent(&op->dev, SZ_OF_ALL_BUFFERS_BK3,
                                  bks->buffer, bks->dma_addr);
		 bks->buffer = NULL;
		 bks->dma_addr = 0;		
	  case 3 :
	         (void) sprintf(name, "mbk3_%d_%d", inst, 0);
		 device_destroy(mbk3_class, MKDEV(bk3_sbus_major, inst));
		if (!inst) {
			pr_info("deleting mbk3 class\n");
			class_destroy(mbk3_class);
		 }
	  case 2 :
#if defined(CONFIG_SBUS)                
		 free_irq(op->irqs[0], bks);
#elif IS_ENABLED(CONFIG_PCI2SBUS)
                 sbus_free_irq(op->irqs[0], bks);
#else
                 printk("BK3-%d, Really crazy behavoir ...\n", inst);
#endif                  
	  case 1 :
		  of_iounmap(&bks->op->resource[0],
			  (void *)bks->bk3_regs_p, BK3_REG_SIZE);
          case 0 :
                 if (bks)
                        kfree(bks);
	}
	

	return 0;
}/* END ======================================================= my_bk3_detach */


static int bk3_open(struct inode *inode, struct file *file)  
{
        register bk3_devstate_t *bks;
	int inst = iminor(inode);
        dev_t dev = MKDEV(bk3_sbus_major, iminor(inode));
	struct bk3_file_private *pdata;

	if (inst >= MX_BK3_INSTANCES) {
		printk("%s: Minor %d is too big\n", __FUNCTION__, inst); 
		return -ENOMEM;
	}
	bks = bk3_states[inst];
	if (bks == NULL) {
		printk("bk3_open: unattached instance %d\n", inst);
		return (-ENXIO);
	}	
        mutex_enter(&bks->mutex);
        pdata = file->private_data;
        if (pdata) {
                if (pdata->instance != inst) {
                        mutex_exit(&bks->mutex);
                        printk("Dismatch instance of file and inode\n");
                        return -EINVAL;
                }
                pdata->count++;
        } else {
                pdata = ddi_malloc(sizeof (*pdata));
                pdata->count = 1;
                pdata->instance = inst;
                pdata->dev = dev;
                file->private_data = pdata;
        }
	mutex_exit(&bks->mutex);
	return 0;
}/* END ============================================================ bk3_open */


static int 
bk3_close(struct inode *inode, struct file *file)
{
	register bk3_devstate_t *bks;
	int			inst = iminor(inode);
        struct bk3_file_private *pdata;

	bks = bk3_states[inst];
	if (bks == NULL) {
		return (-ENXIO);
	}
        mutex_enter(&bks->mutex);
	pdata = file->private_data;
        if (pdata){
	        if (--pdata->count == 0) {
		        file->private_data = NULL;
		        kfree(pdata);
                }        
	} else {
		printk(KERN_ERR "%s: file private data == NULL\n", __FUNCTION__);
                mutex_exit(&bks->mutex);
                return EINVAL;
	}
        mutex_exit(&bks->mutex);

	return 0;
}
/* END =========================================================== bk3_close */


int bk3_postd1( bk3_devstate_t *bks, u_int messg)
{
	long		abstime;
	long		timeout;
 	int		try_once_more = 1;
	int		inst = bks->instance;
	u_int		int_mask;
	
	(void) drv_getparm(LBOLT, (unsigned long *) &abstime);
	timeout = drv_usectohz(bks->reset_time) + abstime;

	if (bk3_debug & BK3_DBG_SEND_CMD)
		cmn_err(CE_NOTE, 
			"bk3 %d: postd start. status 0x%x"
			,inst,bks->status);	
	
	while (IS_ON_STATUS(bks, CMD_IS_ACTIVE) &&
				IS_OFF_STATUS(bks, RESET_NEEDED) &&
				IS_OFF_STATUS(bks, RESET_IN_PROGRESS)) {

		if (bk3_debug & BK3_DEBUG_WAITING) {
			cmn_err(CE_NOTE, "bk3 %d: waiting in bk3_postd"
				" status 0x%x", inst, bks->status);
		}
		int_mask = GET_BK3_REG(bks, mask);
			
		if (int_mask & 1){	/* Tриггер SVободы Bуфера Kоманд TSVBK */
			 if (bk3_debug & BK3_DBG_SEND_CMD)
			 cmn_err(CE_NOTE,"bk3 %d: postd mask & 1 ",inst);
			 
			if(IS_OFF_STATUS(bks, CMD_WAIT_FREE)){
				/* Посылая депешу попадаем сюда. Прерывания BK3_I_CMDFREE нет */
				goto l_send_cmd;
			}else{
				OFF_STATUS(bks, CMD_WAIT_FREE);
				cv_broadcast(&bks->cv_cmd);
			}
		}else{
			if (bk3_debug & BK3_DBG_SEND_CMD)
			 cmn_err(CE_NOTE,
			 "bk3 %d: postd mask & 0 ",inst);
		}

		ON_STATUS(bks, CMD_WAIT_FREE);

				/* Вып. cv_timedwait */
		if (cv_timedwait(&bks->cv_cmd, &bks->mutex, timeout) == -1) {
			if (bk3_debug & BK3_DBG_ERR_RETURNS)
			 cmn_err(CE_NOTE,
			 "bk3 %d: postd cv_timedwait == -1",inst);		
			if (IS_ON_STATUS(bks,
					(RESET_NEEDED | RESET_IN_PROGRESS))) {
				if (bk3_debug & BK3_DBG_RESET)
			 	cmn_err(CE_NOTE,
			 	"bk3 %d:STATUS(RESET_NEEDED | RESET_IN_PROGRESS)",
			 	inst);	
				break;
			}
			if (try_once_more) {
				if (bk3_debug & BK3_DBG_ERR_RETURNS){
					cmn_err(CE_NOTE,
					  "BK3 %d: postd long wait repeat cmd "
					  "%08x, status %x, timeout %ld;",
					  inst, bks->last_cmd,
					  bks->status, bks->reset_time);
				}
				try_once_more = 0;
				(void) drv_getparm(LBOLT,
					(unsigned long *) &abstime);
				timeout = drv_usectohz(bks->reset_time) +
									abstime;
				bks->last_cmd &= ~BK3_C_TAG_MASK;
				bks->last_snd_cmd_tag ^= BK3_C_TAG_MASK;
				bks->last_cmd |= bks->last_snd_cmd_tag;

				/* ! try_once_more SET_BK3_REG ]wctl */

				SET_BK3_REG(bks, wctl, bks->last_cmd);
				bks->stat.cmd_rpt++;
				continue;
			}
			if (bk3_debug & BK3_DBG_ERR_RETURNS) {
				cmn_err(CE_NOTE,
				   "bk3 %d: postd long wait - reset needed "
				   "c:0x%08x s:0x%08x"
				   "  %d/%d", inst,
				   bks->last_cmd, bks->status,
				   bks->stat.cmd_sent, bks->stat.cmd_free);
			}
			
			ON_STATUS(bks, RESET_NEEDED);	
			if (bk3_debug & BK3_DBG_ERR_RETURNS)
			cmn_err(CE_NOTE,
				"bk3 %d:postd long wait. return 1;",inst);
			return (1);
		}
		if (bk3_debug & BK3_DEBUG_WAITING){
			cmn_err(CE_NOTE, "bk3 %d: postd continued", inst);
			
		}
	}
	if (IS_ON_STATUS(bks, (RESET_NEEDED | RESET_IN_PROGRESS)) && 
				(messg != BK3_C_PEER_RESET)) {
		if (bk3_debug & (BK3_DBG_SEND_CMD | BK3_DBG_ERR_RETURNS)) {
			cmn_err(CE_NOTE,
				"bk3 %d: cmd 0x%8x not sent due reset"
				". status0x%x", inst, messg, bks->status);
		}
		return (1);
	}

l_send_cmd :
	ON_STATUS(bks, CMD_IS_ACTIVE);
	
	bks->last_cmd_rpt_cnt = 0;
	if (messg == BK3_C_PEER_RESET) {
		bks->last_snd_cmd_tag = BK3_C_TAG_MASK;
	} else {
		bks->last_snd_cmd_tag ^= BK3_C_TAG_MASK;
	}
	bks->stat.cmd_sent++;
	bks->last_cmd = messg | bks->last_snd_cmd_tag;

	/* SET_BK3_REG wctl */
	SET_BK3_REG(bks, wctl, bks->last_cmd);

	if (bk3_debug & (BK3_DBG_SEND_CMD | BK3_REG_WR)) 
		cmn_err(CE_NOTE, "bk3 %d: cmd 0x%8x sent", inst, bks->last_cmd);

		 /* finish */
	return (0);
}
/* END =========================================================== bk3_postd */

static inline int check_reset_status(bk3_devstate_t *bks)
{
	long	abstime;
	long	timeout;
	int res=0;

	if (IS_ON_STATUS(bks, RESET_IN_PROGRESS)) {
		if (bk3_debug & BK3_DEBUG_WAITING) {
			printk("bk3 %d :RESET_IN_PROGRESS", bks->instance);
		}
		res = -EBUSY;
		drv_getparm(LBOLT, (unsigned long *) &abstime);
		timeout = drv_usectohz(bks->reset_time) + abstime;
		if (cv_timedwait(&bks->cv_D0_reset, &bks->mutex, timeout) < 0) {
			/* timeout time was reached */
			if (bk3_debug & BK3_DEBUG_WAITING) {
				printk("bk3 reset_device %d:timeout time was reached",
					bks->instance);
			}
			return res;
		}
	}

	if (IS_ON_STATUS(bks, RESET_NEEDED)) {
		res = -EBUSY;
		if(bk3_debug & BK3_DBG_ERR_RETURNS) {
			printk("BK3_IOC_GET_BUF %d: RESET_NEEDED", bks->instance);
		}
		if (bk3_reset_device(bks) != 0) {
			return res;
		}
	}
	return res;
}

static long bk3_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	register bk3_devstate_t *bks;
	int	ret = 0;
	int	r;
	long	abstime;
	long	timeout;
	int	inst = iminor(inode);

	lock_kernel();

	bks = bk3_states[inst];

	switch (cmd) {
/*!!!*/	case BK3_IOC_GET_BUF :
	{
	  	int n = 0;
		
		bk3_pool_buf_t* pool_buf = &bks->write_pool;
		bk3_buf_t *tmp;

		mutex_enter(&bks->mutex);

		if((ret = check_reset_status(bks))){
			mutex_exit(&bks->mutex);
			break;
		}
		if(bk3_debug & BK3_DBG_IOCTL)
		cmn_err(CE_NOTE, "bk3 :BK3_IOC_GET_BUF %d:Start" ,inst);

		(void) drv_getparm(LBOLT, (unsigned long *) &abstime);
		timeout = drv_usectohz(bks->wr_wait_usecs) + abstime;

		while(list_empty(&pool_buf->free_list)){
 			if (bk3_debug & BK3_DEBUG_WAITING) {
				cmn_err(CE_NOTE,
				  "bk3 %d: wait free buffer", inst);
 			}

			ON_STATUS(bks,WRITE_IS_ACTIVE);
			r = cv_timedwait(&bks->cv_no_write_buffers, &bks->mutex, timeout);
			OFF_STATUS(bks,WRITE_IS_ACTIVE);
			if (r < 0) {
				if (bk3_debug & BK3_DBG_ERR_RETURNS)
					cmn_err(CE_NOTE,
						"%d bk3 ioctl :BK3_IOC_GET_BUF "
						"no free buf", inst);
				ret = ENOBUFS;
				goto error_get_buf;
			}
			if (IS_ON_STATUS(bks, (RESET_IN_PROGRESS | RESET_NEEDED))){
					ret = EAGAIN;
					cv_broadcast(&bks->cv_reset);
					goto error_get_buf;
			}
		}

		tmp = list_entry(pool_buf->free_list.next, bk3_buf_t, list);
		n = tmp->num;

    		if (ddi_copyout(&n, (caddr_t)arg, sizeof(n))) {
			if (bk3_debug & BK3_DBG_ERR_RETURNS)
				cmn_err(CE_WARN,
					"%d bk3 ioctl :BK3_IOC_GET_BUF "
					"ddi_copyout failure", inst);
			ret = EINVAL;
			goto error_get_buf;
		}
		list_move_tail1(pool_buf->free_list.next, &pool_buf->busy_list);

		if(bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, "BK3_IOC_GET_BUF %d: Finish",inst);
error_get_buf:
		mutex_exit(&bks->mutex);
		break;
	}
		
	case BK3_IOC_RD_BUF :/*считать буфер*/
	{
		bk3_pool_buf_t*	pool_buf = &bks->read_pool;
		bk3_buf_t*	tmp;
		int n;

		mutex_enter(&bks->mutex);
		if((ret = check_reset_status(bks))){
			mutex_exit(&bks->mutex);
			break;
		}

 		if(bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, 
				"BK3_IOC_RD_BUF %d:Start.",inst);		

		if (bks->rd_wait_usecs == 0 &&
				list_empty(&pool_buf->ready_list)) {
			ret = ETIMEDOUT;
			goto end_read;
		}
		(void) drv_getparm(LBOLT, (unsigned long *) &abstime);
		timeout = drv_usectohz(bks->rd_wait_usecs) + abstime;
		while(list_empty(&pool_buf->ready_list)) {/* нет принятых буф. обмена */
			bks->stat.r_start = gethrtime();
			ON_STATUS(bks, READ_IS_ACTIVE);
			r = cv_timedwait(&bks->cv_no_read_buffers, &bks->mutex, timeout);	
			OFF_STATUS(bks, READ_IS_ACTIVE);
	
			if (r < 0) {
				/* timeout time was reached */
				if (bk3_debug & BK3_DEBUG_WAITING){
					cmn_err(CE_NOTE,
					"bk3 %d:BK3_IOC_RD_BUF :timeout time was reached", inst);
				}
				ret = ETIMEDOUT;
				goto end_read;
			}
			if (IS_ON_STATUS(bks, (RESET_IN_PROGRESS | RESET_NEEDED))){
					ret = EAGAIN;
					cv_broadcast(&bks->cv_reset);
					goto error_get_buf;
			}
		}

		tmp = list_entry(pool_buf->ready_list.next, bk3_buf_t, list);
		n = tmp->num;

		if (ddi_copyout(&n , (caddr_t)arg, sizeof(n))) {
			if (bk3_debug & BK3_DBG_ERR_RETURNS)
				cmn_err(CE_WARN,
					"%d bk3 ioctl :BK3_IOC_RD_BUF "
					"ddi_copyout failure", inst);
			ret = EFAULT;
			goto end_read;
		}
		list_move_tail1(&tmp->list, &pool_buf->busy_list);

		if(bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, "BK3_IOC_RD_BUF %d: Finish; read %d buf",
					inst,tmp->num);

end_read:	
		if(bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, "BK3_IOC_RD_BUF %d: Finish, ret = %d",
				inst, ret);
		mutex_exit(&bks->mutex);
 		break;
 	}
	case BK3_IOC_PUT_BUF :/*освободить считанный буфер с номером num.*/
	{
		bk3_pool_buf_t*	pool_buf = &bks->read_pool;
		int	n_buf = arg;
		struct list_head* entry;
		mutex_enter(&bks->mutex);
		if((ret = check_reset_status(bks))){
		mutex_exit(&bks->mutex);
			break;
		}
		if(bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, "BK3_IOC_PUT_BUF : Start");

		entry = search_in_list(&pool_buf->busy_list, n_buf);

		if (entry == 0) {
 			if(bk3_debug & BK3_DBG_ERR_RETURNS)
			cmn_err(CE_NOTE,
					"bk3 %d ioctl: BK3_IOC_PUT_BUF "
					"не существует буфера с #%d", inst, n_buf);
			ret = EINVAL;
			goto error_put_buf;
		}
		
		list_move_tail1(entry,	&bks->read_pool.free_list);
		
		if(IS_ON_STATUS(bks, NO_RECEIVING_BUFFERS)){
			bk3_pool_buf_t* pool_buf = &bks->read_pool;
			pool_buf->work_buf = 
				list_entry(pool_buf->free_list.next, bk3_buf_t, list);
			list_del1(pool_buf->free_list.next);
			bks->stat.r_start = gethrtime();
			SET_BK3_REG(bks, rcwd, pool_buf->work_buf->address);
			SET_BK3_REG(bks, rcnt, TRANSF_CNT);
			bk3_postd(bks, BK3_C_RASK);
			OFF_STATUS(bks, NO_RECEIVING_BUFFERS);
		}

		if(bk3_debug & BK3_DBG_IOCTL)
		cmn_err(CE_NOTE, "BK3_IOC_PUT_BUF : Finish");
error_put_buf:	
		mutex_exit(&bks->mutex);
		break;
		
	}

/*!!!*/	case BK3_IOC_WR_BUF :/*записать буфер с номером num*/
	{
		bk3_pool_buf_t *pool_buf = &bks->write_pool;
		int	n_buf = arg;
		struct list_head* list_tmp;

		mutex_enter(&bks->mutex);
		if((ret = check_reset_status(bks))){
			mutex_exit(&bks->mutex);
			break;
		}		

		list_tmp = search_in_list(&pool_buf->busy_list, n_buf);
		if (list_tmp == 0) {
			if(bk3_debug & BK3_DBG_ERR_RETURNS)
			cmn_err(CE_NOTE,
					"bk3 %d ioctl: BK3_IOC_WR_BUF "
					"не существует буфера с #%d", inst, n_buf);
			ret = EINVAL;
			goto end_write;
		}

		list_move_tail1(list_tmp, &pool_buf->ready_list);

		if (IS_ON_STATUS(bks, PEER_READ_IS_OVER) && IS_ON_STATUS(bks, WRITE_IS_OVER))
		{
			OFF_STATUS(bks, PEER_READ_IS_OVER | WRITE_IS_OVER);
			pool_buf->work_buf = list_entry(pool_buf->ready_list.next, bk3_buf_t, list);
			list_del1(pool_buf->ready_list.next);
			bks->stat.w_start = gethrtime();
			SET_BK3_REG(bks, tcwd, pool_buf->work_buf->address);
			SET_BK3_REG(bks, tcnt, TRANSF_CNT);
		}
end_write:	
		if(bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, "BK3_IOC_WR_BUF %d: Finish. ret =%d",inst,ret);
		mutex_exit(&bks->mutex);
		break;
	}

	case BK3_IOC_RESET :
		if(bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, "BK3_IOC_RESET %d:",inst);
		mutex_enter(&bks->mutex);
		ret = bk3_reset_device(bks);
		mutex_exit(&bks->mutex);
		break;

	case BK3_IOC_GET_ACKN :
		if(bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, "BK3_IOC_GET_ACKN %d:",inst);
		ret = bks->prots_matched;
		break;

	case BK3_IOC_0_IO_REG :
		/*
		 * Reset I/O channel register.
		 * Should make it separatly. 
		 */
		if(bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, "BK3_IOC_0_IO_REG %d:",inst);
		SET_BK3_REG(bks, arst, 0); 
		break;

	case BK3_IOC_ACKNOLEDGE :
	{
 		if (bks->prots_matched && (arg != 0))
 			break;

		if(bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, "bk3 %d: make BK3_IOC_ACKNOLEDGE",inst);
		mutex_enter(&bks->mutex);

      /* ACKNLDG :bf bk3_reset_device */
		ret = bk3_reset_device(bks);
		if (ret != 0) {
			mutex_exit(&bks->mutex);
			cmn_err(CE_WARN, "bk3 %d: BK3_IOC_ACKNOLEDGE "
				"bk3_reset_device == %d !!!!",
				inst, ret);
			break;
		}

		if(bk3_debug & BK3_DBG_IOCTL)	
			cmn_err(CE_NOTE, "bk3 %d:  ACKNLDG :bf normal exit",inst);		
		mutex_exit(&bks->mutex);
	}
		break;
			
	case BK3_IOC_GET_STAT :
	{	
		struct list_head *h;
		bks->stat.n_free_w_buf=0;
		bks->stat.n_free_r_buf=0;		

  		if(bk3_debug & BK3_DBG_IOCTL){
			cmn_err(CE_NOTE,"w_all_time=%lld(%llx), wsize_all=%ld,n_w=%d",
				bks->stat.w_all_time,bks->stat.w_all_time,
					(u_long)bks->stat.wsize_all,bks->stat.n_w);
			cmn_err(CE_NOTE,"r_all_time=%lld,(%llx) rsize_all=%ld,n_r=%d",
				bks->stat.r_all_time,bks->stat.r_all_time,
					(u_long)bks->stat.rsize_all,bks->stat.n_r);
		}

		list_for_each(h, &bks->write_pool.free_list)
			bks->stat.n_free_w_buf++;
		list_for_each(h, &bks->read_pool.free_list)
			bks->stat.n_free_r_buf++;
		if (ddi_copyout((caddr_t)&bks->stat, (caddr_t)arg, sizeof(bk3_stat_t)) != 0) {
		cmn_err(CE_WARN, "bk3 %d ioctl cmd 0x%x ddi_copyout failure", inst, cmd);
			ret = EFAULT; 
			break;
		}
		break;
	}	
	case BK3_IOC_CLEAR_STAT :
	{
/* Поскольку в ячейке есть возмлжность работать сама на себя - то r_start и w_start одновременно
   обнулять нельзя. Пример: тест на чтение запустился установив r_start в значение gethrtime и ждет
   прерывания. затем пускается тест на запись (2 разных потока) который обнуляет как свое значение w_start
   так и r_start. Эти значения вообще не требуют обнуления*/	
		hrtime_t r_start_tmp = bks->stat.r_start;
		hrtime_t w_start_tmp = bks->stat.w_start;
		if(bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, "BK3_IOC_CLEAR_STAT %d:",inst);
		bzero((caddr_t)&bks->stat, sizeof(bk3_stat_t));
                bks->stat.r_start = r_start_tmp;
                bks->stat.w_start = w_start_tmp;		
		break;
	}	
	case BK3_IOC_SND_MSG :
	{
		bk3_msg_snd_t	msg_snd;
		if(bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, "bk3 %d BK3_IOC_SND_MSG: start",inst);

		if (ddi_copyin((caddr_t)arg, (caddr_t)&msg_snd, sizeof (bk3_msg_snd_t))) {
		     if (bk3_debug & BK3_DBG_ERR_RETURNS)
        		cmn_err(CE_WARN, "%d bk3 BK3_IOC_SND_MSG: ddi_copyoin failure", inst);
				ret = EINVAL;
				break;
		}

		/* старт BK3_IOC_SND_MSG */
		mutex_enter(&bks->mutex);
		if((ret = check_reset_status(bks))){
			mutex_exit(&bks->mutex);
			break;
		}
		r = bk3_postd(bks, BK3_C_SND_MSG | (msg_snd.info & BK3_C_ARG_MASK));
		if (r != 0) {
			mutex_exit(&bks->mutex);
					/* ОШ! SND_MSG: res bk3_postd != 0 */
			if(bk3_debug & BK3_DBG_ERR_RETURNS)
				cmn_err(CE_WARN, "bk3 %d BK3_C_SND_MSG :bk3_postd =%d !",
					inst, r);
			ret = r;
			break;
		}

		(void) drv_getparm(LBOLT, (unsigned long *) &abstime);
		timeout = drv_usectohz(msg_snd.t_wait) + abstime;

		if (cv_timedwait(&bks->cv_msg_out, &bks->mutex, timeout) == -1){
			if (bk3_debug & BK3_DBG_ERR_RETURNS)
				cmn_err(CE_NOTE,
					"bk3 %d BK3_IOC_SND_MSG: ETIME",
					inst);
			ret = ETIME;
		}

		mutex_exit(&bks->mutex);
		if (bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, "bk3 %d BK3_IOC_SND_MSG: 0x%lX finish",
				inst, arg);
		break;
	}

	case BK3_IOC_RCV_MSG : {
		bk3_msg_rcv_t	msg_rcv;
		if(bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, "bk3 %d BK3_IOC_RCV_MSG: start",inst);

		if (ddi_copyin((caddr_t)arg, (caddr_t)&msg_rcv,
			sizeof (bk3_msg_rcv_t)/*, mode*/)) {
				if (bk3_debug & BK3_DBG_ERR_RETURNS)
					cmn_err(CE_WARN,
						"%d bk3 ioctl :BK3_IOC_RCV_MSG "
						"ddi_copyoin failure", inst);
				ret = EINVAL;
				break;
		}

		mutex_enter(&bks->mutex);
		if((ret = check_reset_status(bks))){
			mutex_exit(&bks->mutex);
			break;
		}

		(void) drv_getparm(LBOLT, (unsigned long *) &abstime);
		timeout = drv_usectohz(msg_rcv.t_wait) + abstime;

		while(IS_OFF_STATUS(bks,WE_GOT_MESSAGE)){
			if(cv_timedwait(&bks->cv_msg_in, &bks->mutex, timeout) == -1){
				if (bk3_debug & BK3_DBG_ERR_RETURNS)
					cmn_err(CE_NOTE,
						"bk3 %d ioctl BK3_IOC_RCV_MSG :ETIME",
						inst);
				ret = ETIME;
				goto end_rcv_msg;
			}
		}

		if (ddi_copyout((caddr_t)&bks->msg_rcv, (caddr_t)arg, sizeof(bk3_msg_rcv_t))) {
		mutex_exit(&bks->mutex);
		if (bk3_debug & BK3_DBG_ERR_RETURNS)
			cmn_err(CE_WARN, "%d bk3 ioctl :BK3_IOC_RCV_MSG ddi_copyout failure", inst);
			ret = EINVAL;
			break;
		}

		OFF_STATUS(bks,WE_GOT_MESSAGE);
		r = bk3_postd(bks, BK3_C_RCV_MSG);
		if (r != 0) {
			mutex_exit(&bks->mutex);
			/* ОШ! RCV_MSG: res bk3_postd != 0 */
			printk("bk3 %d BK3_C_RCV_MSG : bk3_postd == %d !!!!", inst, r);
			ret = r;
			break;
		}
end_rcv_msg:
		mutex_exit(&bks->mutex);
		if (bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, "bk3 %d BK3_IOC_RCV_MSG: %x finish",
				inst, bks->msg_rcv.info);
		break;
	}

	case BK3_IOC_GET_RD_WAIT :
		if(bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, "BK3_IOC_GET_RD_WAIT %d:",inst);
		ret = -(int)bks->rd_wait_usecs;
		break;
	case BK3_IOC_GET_WR_WAIT :
		if(bk3_debug & BK3_DBG_IOCTL)
			cmn_err(CE_NOTE, "BK3_IOC_GET_WR_WAIT %d:",inst);
		ret = -(int)bks->wr_wait_usecs;
		break;
	case BK3_IOC_SET_RD_WAIT :
		if(bk3_debug & BK3_DBG_INTR)
			cmn_err(CE_NOTE, "BK3_IOC_SET_RD_WAIT %d:",inst);
		bks->rd_wait_usecs = (long)arg;
		break;
	case BK3_IOC_SET_WR_WAIT :
		if(bk3_debug & BK3_DBG_INTR)
			cmn_err(CE_NOTE, "BK3_IOC_SET_WR_WAIT %d:",inst);
		bks->wr_wait_usecs = (long)arg;
		break;
	case BK3_IOC_GET_RESET_TIME :
		ret = -(int)bks->reset_time;
		break;
	case BK3_IOC_SET_RESET_TIME :
		bks->reset_time = arg ? (long)arg : BK3_RESET_TIME_DEFAULT;
		break;

	default :	
		if (bk3_debug & BK3_DBG_IOCTL) {
			cmn_err(CE_WARN, "bk3 %d. unknown ioctl cmd = 0x%x",
				inst, cmd);
		}
		ret = EINVAL;
		break;
	}

	unlock_kernel();

	return -(ret);
}
/* END =========================================================== bk3_ioctl */


#if 0
static void bk3_vma_open(struct vm_area_struct *vma)
{
 ;
}

static void bk3_vma_close(struct vm_area_struct *vma)
{
  ;
}

struct page *bk3_vma_nopage(struct vm_area_struct *vma,
                            unsigned long address, int *type)
{
	unsigned long pageptr = 0;
	struct page *page = NOPAGE_SIGBUS;
	unsigned long offset;
	
	offset = (address - vma->vm_start) + (vma->vm_pgoff << PAGE_SHIFT);
	
	pageptr = (unsigned long)vma->vm_private_data + offset;
	if (!pageptr) {
		printk("error pageptr");
		goto out;
	}

	page = virt_to_page(pageptr);
	
	get_page(page);
	
	if (type)
		*type = VM_FAULT_MINOR;

out:
	return page;
}

struct vm_operations_struct bk3_vm_ops = {
    .open   = bk3_vma_open,
    .close  = bk3_vma_close,
    .nopage = bk3_vma_nopage,
};
#endif

static int bk3_mmap(struct file *file, struct vm_area_struct *vma)
{
	bk3_devstate_t *bks = file_bk3_state(file);
	unsigned long size = vma->vm_end - vma->vm_start;
        int rval = 0;

	vma->vm_flags |= (VM_IO | VM_LOCKED | VM_READ | VM_WRITE | VM_RESERVED);
	if (size > SZ_OF_ALL_BUFFERS_BK3) {
		size = SZ_OF_ALL_BUFFERS_BK3;
	}
        printk("bk3_mmap: start for size = 0x%x, buffer = 0x%x\n", size, bks->buffer);
        rval = ddi_remap_page(bks->buffer, size, vma);
        printk("bk3_mmap: finish with rval = %d\n", rval);
	return (rval);
}
/* END ======================================================== mbk3_mmap */


int
bk3_init_pool_buf(bk3_devstate_t *bks)
{
	int i;
	bk3_pool_buf_t* pool_buf;

	if (bks->buffer == NULL) {
		bks->buffer = dma_alloc_coherent(&bks->op->dev,
                                           SZ_OF_ALL_BUFFERS_BK3,
                                           &bks->dma_addr, GFP_ATOMIC);
		if (bks->buffer == NULL) {
			return -ENOMEM;
		}
	}
	pool_buf = &bks->read_pool;
        INIT_LIST_HEAD(&pool_buf->ready_list);
        INIT_LIST_HEAD(&pool_buf->free_list);
        INIT_LIST_HEAD(&pool_buf->busy_list);
	for (i = 0; i < NUM_BUF_BK3; i++) {
		pool_buf->buffer[i].address = bks->dma_addr + SZ_BUF_BK3*i;
		pool_buf->buffer[i].num = i;
		list_add_tail1(&pool_buf->buffer[i].list, &pool_buf->free_list);
	}
        pool_buf = &bks->write_pool;
        INIT_LIST_HEAD(&pool_buf->ready_list);
        INIT_LIST_HEAD(&pool_buf->free_list);
        INIT_LIST_HEAD(&pool_buf->busy_list);
        for (i = 0; i < NUM_BUF_BK3; i++) {
                pool_buf->buffer[i].address = bks->dma_addr + SZ_BUF_BK3 * (i + NUM_BUF_BK3);
                pool_buf->buffer[i].num = NUM_BUF_BK3 + i;
                list_add_tail1(&pool_buf->buffer[i].list, &pool_buf->free_list);
        }
	return 0;
}
/* END =================================================== bk3_init_pool_buf */

int bk3_debug = (0x10 | 0x40 | 0x08 | 0x02 | 0x01);

module_param(bk3_debug, int, 0644);
MODULE_PARM_DESC(bk3_debug,"debug messages mask\n"
		"\twaiting         0x01\n"
		"\tstart transfer  0x02\n"
		"\terror returns   0x04\n"
		"\tinterrupts      0x08\n"
		"\tioctl           0x10\n"
		"\treset           0x20\n"
		"\tsend cmd        0x40\n"
		"\tattach          0x100"
);
