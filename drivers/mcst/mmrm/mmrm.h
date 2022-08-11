/*
 * MCST Copyright
 */
#ifndef _MMRM_DRV_H
#define _MMRM_DRV_H

#define VENDOR_MCST			0x1FFF
#define MMRM_DEVICE_ID			0x8002
#define BRIDGE_DEVICE_ID		0x8001
#define MIN_REVISION			0x80
#define PR_READ_SIZE_REG		0x41
#define MMRM_READ_SIZE			0x04

#define MMRM_MAJOR_DEFAULT		0
#define MAX_MMRM			8
#define DEVICE_BUF_QUANTITY		64
#define DEVICE_BUF_BYTE_SIZE		64
#define BATCH_BUF_BYTE_SIZE		64
#define DEVICE_MEM_CLEAR		0xF4F4F4F4
#define MMRM_REGISTERS_ADR		0x800
#define BATCH_CMD_QUANTITY_REG_ADR	(MMRM_REGISTERS_ADR + 0x00)
#define BATCH_CMD_ADR_REG_ADR		(MMRM_REGISTERS_ADR + 0x02)
#define DEVICE_REGIM_REG_ADR		(MMRM_REGISTERS_ADR + 0x09)
#define U0KMKP_REG_ADR			(MMRM_REGISTERS_ADR + 0x20)
#define INTERRUPT_REG_ADR		(MMRM_REGISTERS_ADR + 0x21)
#define MAX_COMMAND_TIME		1000000
#define BLOCK_1_CHANNEL			0x0100
#define BLOCK_0_CHANNEL			0x0080
#define COMPLET_DESK_RES_SPOOL		0x00000004


/*
 * get from ddi.h, ddi_cv.c
 */
struct __raw_wait_queue {
	struct task_struct *task;
	struct list_head task_list;
};

#define DECLARE_RAW_WAIT_QUEUE(name) raw_wait_queue_t name = {.task = current}

typedef struct __raw_wait_queue raw_wait_queue_t;

struct __raw_wait_queue_head {
	raw_spinlock_t lock;
	struct list_head task_list;
};

typedef struct __raw_wait_queue_head raw_wait_queue_head_t;

#define spin_mutex_enter	raw_spin_lock_irq
#define spin_mutex_exit		raw_spin_unlock_irq
#define kcondvar_t		raw_wait_queue_head_t
static inline void raw_init_waitqueue_head(raw_wait_queue_head_t *q)
{
	raw_spin_lock_init(&q->lock);
	INIT_LIST_HEAD(&q->task_list);
}
#define spin_mutex_init		raw_spin_lock_init

#define cv_init(cvp) raw_init_waitqueue_head(cvp);

#define LBOLT	4


int drv_getparm(unsigned long parm, unsigned long *valuep)
{
	switch (parm) {
	case LBOLT:
		*valuep = (unsigned long)jiffies;
		break;
	default:
		printk(KERN_ERR "drv_get_parm: Unknown parm %ld\n", parm);
		return -1;
	}
	return 0;
}

clock_t drv_usectohz(register clock_t mksec)
{
	clock_t		clock;
	struct timespec rqtp;

	rqtp.tv_nsec = ((mksec % 1000000L) * 1000L);
	rqtp.tv_sec  = mksec / 1000000L;
	clock = timespec_to_jiffies(&rqtp);
	return clock;
}

static inline void __raw_add_wait_queue(raw_wait_queue_head_t *head,
					raw_wait_queue_t *new)
{
	list_add(&new->task_list, &head->task_list);
}

void raw_add_wait_queue(raw_wait_queue_head_t *q, raw_wait_queue_t *wait)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&q->lock, flags);
	__raw_add_wait_queue(q, wait);
	raw_spin_unlock_irqrestore(&q->lock, flags);
}

static inline void __raw_remove_wait_queue(raw_wait_queue_head_t *head,
					   raw_wait_queue_t *old)
{
	list_del(&old->task_list);
}

void raw_remove_wait_queue(raw_wait_queue_head_t *q, raw_wait_queue_t *wait)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&q->lock, flags);
	__raw_remove_wait_queue(q, wait);
	raw_spin_unlock_irqrestore(&q->lock, flags);
}

int cv_spin_wait(kcondvar_t *cvp, raw_spinlock_t *lock)
{
	struct task_struct *tsk = current;
	int rval = 0;
	int spin_locking_done = 0;
	DECLARE_RAW_WAIT_QUEUE(wait);

	tsk->state = TASK_INTERRUPTIBLE;
	raw_add_wait_queue(cvp, &wait);
	spin_locking_done = raw_spin_is_locked(lock);
	if (spin_locking_done) {
		spin_mutex_exit(lock);
	}
	schedule();
	raw_remove_wait_queue(cvp, &wait);

	tsk->state = TASK_RUNNING;
	if (signal_pending(current)) {
		rval = -1;
	}
	if (spin_locking_done)
		spin_mutex_enter(lock);
	return rval;

}


int cv_spin_timedwait(kcondvar_t *cvp, raw_spinlock_t *lock, long tim)
{
	unsigned long		expire;
	int			rval = 0;
	int			spin_locking_done	= 0;
	struct task_struct	*tsk = current;
	DECLARE_RAW_WAIT_QUEUE(wait);

	expire = tim - jiffies;
	tsk->state = TASK_INTERRUPTIBLE;
	raw_add_wait_queue(cvp, &wait);
	spin_locking_done = raw_spin_is_locked(lock);
	if (spin_locking_done) {
		spin_mutex_exit(lock);
	}

	expire = schedule_timeout(expire);
	raw_remove_wait_queue(cvp, &wait);
	tsk->state = TASK_RUNNING;
	if (spin_locking_done) {
		spin_mutex_enter(lock);
	}
	if (expire) {
		if (signal_pending(current)) {
			rval = -2;
		}
	} else {
		rval = -1;
	}
	return rval;
}


static void __raw_wake_up_common(raw_wait_queue_head_t *q)
{
	struct list_head *tmp, *next;
	raw_wait_queue_t *curr;

	list_for_each_safe(tmp, next, &q->task_list) {
		curr = list_entry(tmp, raw_wait_queue_t, task_list);
		wake_up_state(curr->task,
			      TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE);
	}
}

/**
 * __wake_up - wake up threads blocked on a waitqueue.
 * @q: the waitqueue
 * @mode: which threads
 */
void  __raw_wake_up(raw_wait_queue_head_t *q)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&q->lock, flags);
	__raw_wake_up_common(q);
	raw_spin_unlock_irqrestore(&q->lock, flags);
}


int cv_broadcast(kcondvar_t *cvp)
{
	__raw_wake_up(cvp);
	return 0;
}

/* end of ddi.h, ddi_cv.h */

typedef struct mmrm_dev {
	int			instance;
	int			opened;
	struct pci_dev		*pdev;
	int			irq;
	u32			*device_mem_start;
	u32			*batch_dma_adr;
	u32			*buf_dma_adr[DEVICE_BUF_QUANTITY];
	dma_addr_t		batch_bus_addr;
	dma_addr_t		bus_addr[DEVICE_BUF_QUANTITY];
	int			device_type;
	mmrm_term_dev_adr_t	term_dev_adress;
	mmrm_term_trans_t	term_trans_direction;
	mmrm_subadress_t	subadress;
	size_or_code_t		size_or_code;
	wait_queue_head_t	wait_trans_fin_queue;
	int			trans_completed;
	raw_spinlock_t		lock;
	kcondvar_t		intr_cv;
} mmrm_dev_t;

irqreturn_t pre_mmrm_handler(int irq, void *arg);
irqreturn_t mmrm_intr_handler(int irq, void *arg);

#endif  /* !(_MMRM_DRV_H) */
