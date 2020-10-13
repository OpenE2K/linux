/*
 * BUGS:
 * - CUBIC: rfsm mode can not be used in a table mode.
 */

#include "mokx_iocc.h"
#include "mokx_mok.h"
#include "mokx_iocc_error.h"
#include "mokx_mok_error.h"
#include "mokx_iocc_regs.h"
#include "mokx_mok_regs.h"

#ifndef VM_RESERVED
#define VM_RESERVED (VM_DONTEXPAND | VM_DONTDUMP)
#endif

#define SETTING_OVER_INTERRUPT 1
#define SET_ENABLE_RECEIVE_BIT 1

#if SETTING_OVER_INTERRUPT
unsigned int wait_answer_msg = 0x0;
#endif

#ifdef UNX_TRWD
unsigned int REPEAT_TRWD = 0;
#endif


#define DSF_NO			0
#define ALLOC_MEM_DRIVER	1
#define SMALL_CHANGE		0x0
#define TX_RX_WAIT_DMA		1000000

int busy_rdma_boot_mem = 0;
#ifdef CONFIG_RDMA_BOOT_MEM_ALLOC
extern unsigned int R_M_NODE;
extern unsigned int R_M_SH;
extern volatile void *rdma_link_mem[MAX_NUMNODES];
extern volatile void *rdma_share_mem;
#endif

MODULE_AUTHOR("Copyright by MCST 2013-2014");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MOKX driver");

/*
 * Parametr's driver
 */
#ifndef LMS
#ifdef CONFIG_RDMA_BOOT_MEM_ALLOC
#define MAX_SIZE_BUFF		0x800000
#define LIMIT_SIZE_BUFF 	0x40000000
#else
#define MAX_SIZE_BUFF		0x800000
#define LIMIT_SIZE_BUFF		0x2000000
#endif
#define MAX_SIZE_BUFF_TM	0xC800000
#else
#ifdef CONFIG_RDMA_BOOT_MEM_ALLOC
#define MAX_SIZE_BUFF		0x10000
#else
#define MAX_SIZE_BUFF		0x8000
#define LIMIT_SIZE_BUFF		0x200000
#endif
#define MAX_SIZE_BUFF_TM	0x80000
#endif

/*
 * Struct for class rdma in sysfs
 */
static struct class *mokx_class;

/*
 * Set ATL
 */
#if 0
unsigned int tr_atl;
static int atl_v = TR_ATL_B;
module_param(atl_v, int, 0);
MODULE_PARM_DESC(atl_v, "Changes the value of ATL (alive timer limit) "
		 "reg CAM.");
#endif 

/*
 * Mode ( 0 - single mode , 1 - table mode )
 */
static int tm_mode = 0x1;
module_param(tm_mode, int, 0);

/*
 * Max size buf for single mode
 */
static int align_buf_tm = 1;
module_param(align_buf_tm, int, 0);

/*
 * Max size buf for single mode
 */
static int max_size_buf = MAX_SIZE_BUFF;
module_param(max_size_buf, int, 0);

/*
 * Max size buf for table mode
 */
static int max_size_buf_tm = MAX_SIZE_BUFF_TM;
module_param(max_size_buf_tm, int, 0);

/*
 * The number of buffers
 */
static int num_buf = RDMA_BUF_NUM;
module_param(num_buf, int, 0);

/*
 * Allocate memory on its node
 */
static int node_mem_alloc = 0x0;
module_param(node_mem_alloc, int, 0);

/*
 * Develop for multy channel 
 */
static int count_rdma_vc = RDMA_NODE_DEV;

/*
 * Print events
 */
static int ev_pr = 0;
module_param(ev_pr, int, 0);

/*
 * Enable RFSM - rfsm.
 *  rfsm  = ENABLE_RFSM  - RFSM disable (default).
 *  rfsm  = DMA_RCS_RFSM - RFSM enable.
 */
#define CLEAR_RFSM 	 DISABLE_RFSM
unsigned int rfsm = CLEAR_RFSM;

struct rdma_reg_state rdma_reg_state[RDMA_MAX_NUMIOLINKS];
struct rdma_state *rdma_state;

struct pci_dev	*rdma_dev;
link_id_t	rdma_link_id;
unsigned long	time_ID_REQ;
unsigned long	time_ID_ANS;
unsigned long	flags_s;
unsigned char	*e0regad;
unsigned char	*e1regad;
unsigned int	count_read_sm_max = 800;
unsigned int	intr_rdc_count[RDMA_MAX_NUMIOLINKS];
unsigned int	msg_cs_dmrcl = MSG_CS_DMRCL;
unsigned int	state_cam = 0;
unsigned int	state_GP0;

unsigned int	SHIFT_IO_VID;
unsigned int	SHIFT_VID;	/* RDMA VID 			*/
unsigned int	SHIFT_IOL_CSR;
unsigned int	SHIFT_IO_CSR;
unsigned int	SHIFT_CH0_IDT;	/* RDMA ID/Type E90/E3M1	*/
unsigned int	SHIFT_CH1_IDT;	/* RDMA ID/Type E90/E3M1	*/
unsigned int	SHIFT_CH_IDT;	/* RDMA ID/Type E3S/E90S	*/
unsigned int	SHIFT_CS;	/* RDMA Control/Status 000028a0	*/
unsigned int	SHIFT_DD_ID;	/* Data Destination ID 		*/
unsigned int	SHIFT_DMD_ID;	/* Data Message Destination ID 	*/
unsigned int	SHIFT_N_IDT;	/* Neighbour ID/Type 		*/
unsigned int	SHIFT_ES;	/* Event Status 		*/
unsigned int	SHIFT_IRQ_MC;	/* Interrupt Mask Control 	*/
unsigned int	SHIFT_DMA_TCS;	/* DMA Tx Control/Status 	*/
unsigned int	SHIFT_DMA_TSA;	/* DMA Tx Start Address 	*/
unsigned int	SHIFT_DMA_HTSA;	/* DMA Tx Start Address 	*/
unsigned int	SHIFT_DMA_TBC;	/* DMA Tx Byte Counter 		*/
unsigned int	SHIFT_DMA_RCS;	/* DMA Rx Control/Status 	*/
unsigned int	SHIFT_DMA_RSA;	/* DMA Rx Start Address 	*/
unsigned int	SHIFT_DMA_HRSA;	/* DMA Rx Start Address 	*/
unsigned int	SHIFT_DMA_RBC;	/* DMA Rx Byte Counter 		*/
unsigned int	SHIFT_MSG_CS;	/* Messages Control/Status 	*/
unsigned int	SHIFT_TDMSG;	/* Tx Data_Messages Buffer 	*/
unsigned int	SHIFT_RDMSG;	/* Rx Data_Messages Buffer 	*/
unsigned int	SHIFT_CAM;	/* CAM - channel alive management */


int MCG_CS_SEND_ALL_MSG =	(MSG_CS_SD_Msg	|
				MSG_CS_SGP0_Msg	|
				MSG_CS_SGP1_Msg	|
				MSG_CS_SGP2_Msg	|
				MSG_CS_SGP3_Msg	|
				MSG_CS_SL_Msg	|
				MSG_CS_SUL_Msg	|
				MSG_CS_SIR_Msg);

int MSG_CS_MSF_ALL =		MSG_CS_DMPS_Err	|
				MSG_CS_MPCRC_Err	|
				MSG_CS_MPTO_Err	|
				MSG_CS_DMPID_Err;

unsigned int	irq_mc_1 =	IRQ_RGP1M,
		irq_mc_rdc =	IRQ_RDC,
		irq_mc_03 =	
				IRQ_RGP0M	|
				IRQ_RGP3M,
		irq_mc =	IRQ_RDM		|
				IRQ_RGP3M	|
				IRQ_RGP2M	|
				IRQ_RGP1M	|
				IRQ_RGP0M	|
				IRQ_RIAM	|
				IRQ_RIRM	|
				IRQ_RULM	|
				IRQ_RLM		|
				IRQ_MSF		|
#if DSF_NO
				//IRQ_DSF	|
#else
				IRQ_DSF		|
#endif
				IRQ_TDC		|
				IRQ_RDC		|
				IRQ_CMIE;

unsigned int count_loop_send_msg_max = 10;
unsigned int count_wait_rdm_max = 64;
dev_rdma_sem_t *msg_snd_dev[2];

#define RESET_DMA_MEMMORY 1
#ifdef RESET_DMA_MEMMORY
unsigned long reset_dma_memory_r, reset_dma_memory_w;
unsigned int reset_size_r;
unsigned int reset_size_w;
int reset_order_r, reset_order_w;
#endif

#ifdef CONFIG_COMPAT
static int do_ioctl(struct file *f, unsigned cmd, unsigned long arg);
static long rdma_compat_ioctl(struct file *f, unsigned cmd, unsigned long arg);
#endif
static long rdma_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
static ssize_t rdma_read(struct file *, char *, size_t, loff_t *);
static ssize_t rdma_write(struct file *, const char *, size_t, loff_t *);
static int rdma_open(struct inode *inode, struct file *file);
static int rdma_close(struct inode *inode, struct file *file);
static int rdma_mmap(struct file *file, struct vm_area_struct *vma);
void test_send_msg_rdma(unsigned int i, unsigned int msg);
int get_file_minor(struct file *file);
void init_reg(void);
void rdma_mem_free(size_t size, dma_addr_t dev_memory, unsigned long dma_memory);
void rdma_link_init(int link);
void read_regs_rdma(int);
int rdma_mem_alloc(int node, size_t size, dma_addr_t *mem, 
		   size_t *real_size, unsigned long *dma_memory, int node_mem_alloc);
int write_buf(int link, rdma_ioc_parm_t *parm, unsigned int f_flags);
int read_buf(int link, rdma_ioc_parm_t *parm, unsigned int f_flags);
int rdma_remap_page(void *va, size_t sz, struct vm_area_struct *vma);
int rdma_remap_page_tbl(void *va, size_t sz, struct vm_area_struct *vma,
			int align);
long wait_time_rdma(struct rdma_reg_state *rdma_reg_state,
		    signed long timeout);
int rdma_check_buf(unsigned long addr_buf, unsigned int cnst,
		   unsigned int need_free_page, char *prefix);
unsigned long join_curr_clock( void );
unsigned int RDR_rdma(unsigned int reg, unsigned int node);
void WRR_rdma(unsigned int reg, unsigned int node, unsigned int val);
int create_dev_mokx(int major);
int remove_dev_mokx(int major);
int init_buff(int link, int rw);
int rdma_mem_alloc_pool(rdma_pool_buf_t *);
void rdma_mem_free_pool(rdma_pool_buf_t *);
static void rdma_cleanup(void);
int send_msg_check(unsigned int msg, unsigned int link, unsigned int cmd,
		   dev_rdma_sem_t *dev, int print_enable);
unsigned long __get_free_pages_rdma(int node, gfp_t gfp_mask, 
				    unsigned int order, int node_mem_alloc);
int mok_x_unset_mode4(link);

#if RESET_THREAD_DMA
int rst_thr_action(void *arg);
#endif

DEFINE_RAW_SPINLOCK(mu_fix_event);

static struct file_operations rdma_fops = {
	.owner		= THIS_MODULE,
	.read		= rdma_read,
	.write		= rdma_write,
	.unlocked_ioctl = rdma_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= rdma_compat_ioctl,
#endif
	.mmap		= rdma_mmap,
	.open		= rdma_open,
	.release 	= rdma_close,
};

void init_regs(void)
{
	SHIFT_IO_VID	= IO_VID;
	SHIFT_IOL_CSR	= IOL_CSR;
	SHIFT_IO_CSR	= IO_CSR;
	SHIFT_VID	= RDMA_VID;
	SHIFT_CH_IDT	= RDMA_CH_IDT;
	SHIFT_CS	= RDMA_CS;
	SHIFT_DD_ID	= RDMA_DD_ID;
	SHIFT_DMD_ID	= RDMA_DMD_ID;
	SHIFT_N_IDT	= RDMA_N_IDT;
	SHIFT_ES	= RDMA_ES;
	SHIFT_IRQ_MC	= RDMA_IRQ_MC;
	SHIFT_DMA_TCS	= RDMA_DMA_TCS;
	SHIFT_DMA_TSA	= RDMA_DMA_TSA;
	SHIFT_DMA_TBC	= RDMA_DMA_TBC;
	SHIFT_DMA_RCS	= RDMA_DMA_RCS;
	SHIFT_DMA_RSA	= RDMA_DMA_RSA;	
	SHIFT_DMA_RBC	= RDMA_DMA_RBC;	
	SHIFT_MSG_CS	= RDMA_MSG_CS;
	SHIFT_TDMSG	= RDMA_TDMSG;
	SHIFT_RDMSG	= RDMA_RDMSG;
	SHIFT_DMA_HTSA	= RDMA_DMA_HTSA;
	SHIFT_DMA_HRSA	= RDMA_DMA_HRSA;
	SHIFT_CAM	= RDMA_CAM;
}

/*
 * Read/write reg's CPU RDMA and allign dma
 * ============================================================================
 */

static inline void sic_write_node_nbsr_reg_rdma(int node_id,
						unsigned int reg_offset,
						unsigned int reg_value)
{
	sic_write_node_iolink_nbsr_reg(NUM_NODE_RDMA(node_id),
				       NUM_LINK_IN_NODE_RDMA(node_id),
				       reg_offset, reg_value );
}

static inline unsigned int sic_read_node_nbsr_reg_rdma(int node_id,
						       int reg_offset)
{
	unsigned int reg_value;

	reg_value = sic_read_node_iolink_nbsr_reg(NUM_NODE_RDMA(node_id),
						  NUM_LINK_IN_NODE_RDMA(node_id),
						  reg_offset );
	return (reg_value);
}

void WRR_rdma(unsigned int reg, unsigned int node, unsigned int val)
{
	sic_write_node_nbsr_reg_rdma(node, reg, val);
	fix_event(node, WRR_EVENT, reg, val);
}

unsigned int RDR_rdma(unsigned int reg, unsigned int node)
{
	unsigned int val;
	val = sic_read_node_nbsr_reg_rdma(node, reg);
	fix_event(node, RDR_EVENT, reg, val);
	return val;
}

unsigned int allign_dma(unsigned int n)
{
	if (n&(ALLIGN_RDMA-1)) {
		n += ALLIGN_RDMA;
		n = n&(~(ALLIGN_RDMA-1));
	}
        return n;
}

#define ALLIGN_RDMA_BUF 16 * PAGE_SIZE
unsigned int allign_dma_buf(unsigned int n)
{
	if (n&(ALLIGN_RDMA_BUF-1)) {
		n += ALLIGN_RDMA_BUF;
		n = n&(~(ALLIGN_RDMA_BUF-1));
	}
	return n;
}

/*
 * List search
 * ============================================================================
 */
static rdma_buf_t* search_in_list(struct list_head* list1, int num1)
{
	struct list_head* tmp;
	rdma_buf_t* ret = NULL;

	list_for_each(tmp, list1) {
		ret = list_entry(tmp, rdma_buf_t, list);
		if(ret->num == num1) 
			return (ret);
	}
	return (NULL);
} 

/*
 * Clock
 * ============================================================================
 */
unsigned long join_curr_clock(void)
{
	unsigned long ret;
	ret = get_cycles();
	return ret;
}

/*
 * Schedule
 * ============================================================================
 */
static inline void __raw_add_wait_queue_from_ddi(raw_wait_queue_head_t *head,
						 raw_wait_queue_t *new)
{
        list_add(&new->task_list, &head->task_list);
}
static inline void __raw_remove_wait_queue_from_ddi(raw_wait_queue_head_t *head,
						    raw_wait_queue_t *old)
{
        list_del(&old->task_list);
}

void raw_add_wait_queue_from_ddi(raw_wait_queue_head_t *q,
				 raw_wait_queue_t *wait)
{
        unsigned long flags;

        raw_spin_lock_irqsave(&q->lock, flags);
        __raw_add_wait_queue_from_ddi(q, wait);
        raw_spin_unlock_irqrestore(&q->lock, flags);
}

void raw_remove_wait_queue_from_ddi(raw_wait_queue_head_t *q,
				    raw_wait_queue_t *wait)
{
        unsigned long flags;

        raw_spin_lock_irqsave(&q->lock, flags);
        __raw_remove_wait_queue_from_ddi(q, wait);
        raw_spin_unlock_irqrestore(&q->lock, flags);
}

hrtime_t rdma_gethrtime(void)
{
	struct timeval tv;
	hrtime_t val;
	do_gettimeofday(&tv);
	val = tv.tv_sec * 1000000000LL + tv.tv_usec * 1000LL;
	return (val);
}

static void __raw_wake_up_common_from_ddi(raw_wait_queue_head_t *q)
{
	struct list_head *tmp, *next;
	raw_wait_queue_t *curr;

	list_for_each_safe(tmp, next, &q->task_list) {
		curr = list_entry(tmp, raw_wait_queue_t, task_list);
		//wake_up_state(curr->task, TASK_UNINTERRUPTIBLE |
		//			  TASK_INTERRUPTIBLE);
		wake_up_process(curr->task);
	}
}

void __raw_wake_up_from_ddi(raw_wait_queue_head_t *q)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&q->lock, flags);
	__raw_wake_up_common_from_ddi(q);
	raw_spin_unlock_irqrestore(&q->lock, flags);
}

int cv_broadcast_from_ddi(raw_wait_queue_head_t *cvp)
{
	__raw_wake_up_from_ddi(cvp);
        return 0;
}

int rdma_cv_broadcast_rdma(void* dev_rdma_sem, unsigned int link)
{
	rdma_addr_struct_t p_xxb;
	dev_rdma_sem_t *dev = dev_rdma_sem;
	
	dev->irq_count_rdma ++;
	dev->time_broadcast = join_curr_clock();
	p_xxb.addr = (unsigned long)dev;
	fix_event(link, RDMA_BROADCAST, p_xxb.fields.laddr,
		  dev->irq_count_rdma);
	cv_broadcast_from_ddi(&dev->cond_var);
	return (0);
}

/* 
 * Convert mksec to HZ 
 */
clock_t drv_usectohz_from_ddi(register clock_t mksec)
{
        clock_t clock;
	struct timespec rqtp;

	rqtp.tv_nsec = ((mksec % 1000000L) * 1000L);
	rqtp.tv_sec  = mksec / 1000000L;
	clock = timespec_to_jiffies(&rqtp);
	return (clock);
}

int cv_spin_timedwait_from_ddi(raw_wait_queue_head_t *cvp,
				   raw_spinlock_t *lock, long tim)
{
	struct task_struct *tsk = current;
	unsigned long expire;
	int raw_spin_locking_done = 0;
	int rval = 0;
	
	DECLARE_RAW_WAIT_QUEUE(wait);
        expire = tim - jiffies;
        tsk->state = TASK_INTERRUPTIBLE;
	raw_add_wait_queue_from_ddi(cvp, &wait);
	raw_spin_locking_done = raw_spin_is_locked(lock);
	if(raw_spin_locking_done)
 	       spin_mutex_exit(lock);
	fix_event(0, WAIT_TRY_SCHTO_EVENT, (unsigned int)expire, 0);
        expire = schedule_timeout(expire);
	raw_remove_wait_queue_from_ddi(cvp, &wait);
        tsk->state = TASK_RUNNING;
	if(raw_spin_locking_done)
		spin_mutex_enter(lock);
        if (expire) {
                if (signal_pending(current)) {
                        rval = -2;
                }
        } else {
                rval = -1;
        }
        return rval;
}

int wait_for_irq_rdma_sem(void* dev_rdma_sem, signed long usec_timeout,
			  unsigned int link)
{
	rdma_addr_struct_t p_xxb;
	dev_rdma_sem_t *dev = dev_rdma_sem;
	unsigned int time_current;
	unsigned int delta_time;
	signed long timeout_tick;
	int ret = 0;
	
	if (!raw_spin_is_locked(&dev->lock)) {
		printk("%s: spin is NOT locked:dev: %p\n", __FUNCTION__, dev);
		return -3;
	}
	if (dev->irq_count_rdma) {
	        printk("%s(%p): dev->irq_count_rdma: %u"
		       "num_obmen: %u\n", __FUNCTION__, &dev->lock,
	 	       dev->irq_count_rdma, (unsigned int)dev->num_obmen);
		delta_time = 0;
		if (dev->time_broadcast) {
			time_current = join_curr_clock();
			if (time_current > dev->time_broadcast) {
				delta_time = (unsigned int)(time_current -
						dev->time_broadcast);
			} else {
				delta_time = (unsigned int)(time_current +
						(~0U - dev->time_broadcast));
			}
			delta_time |= (1<<31);
			fix_event(link, WAIT_RET_SCHT0_EVENT, delta_time,
				  dev->num_obmen);
			fix_event(link, WAIT_RET_SCHT0_EVENT,
				  dev->irq_count_rdma, dev->num_obmen);
			dev->time_broadcast = 0;
		}
		return(1);
	}
	p_xxb.addr = usec_timeout;
	fix_event(link, WAIT_TRY_SCHTO_EVENT, p_xxb.fields.laddr, dev->num_obmen);
	timeout_tick = (unsigned long)jiffies;
	timeout_tick += usec_timeout;
	ret = cv_spin_timedwait_from_ddi(&dev->cond_var, &dev->lock,
					     timeout_tick);
	delta_time = 0;
	if (dev->time_broadcast) {
		time_current = join_curr_clock();
		if (time_current > dev->time_broadcast) {
			delta_time = (unsigned int)(time_current -
					dev->time_broadcast);
		} else {
			delta_time = (unsigned int)(time_current +
					(~0U - dev->time_broadcast));
		}
		fix_event(link, WAIT_RET_SCHT1_EVENT, ret, dev->num_obmen);
		dev->time_broadcast = 0;
	} else {
		fix_event(dev->irq_count_rdma, WAIT_RET_SCHT2_EVENT, ret,
				dev->num_obmen);
	}

	return ret;
}

/*
 * Fixed event
 * ============================================================================
 */

rdma_event_t rdma_event;
int rdma_event_init = 0;
#include "mokx_get_event.c"

void fix_event_proc(unsigned int channel, unsigned int event,
		    unsigned int val1, unsigned int val2)
{
	struct event_cur *event_cur;
	unsigned long flags;

	if (!rdma_event_init)
		return;
	raw_spin_lock_irqsave(&mu_fix_event, flags);
	event_cur = &rdma_event.event[rdma_event.event_cur];
	event_cur->clkr = join_curr_clock();
	event_cur->event = event;
	event_cur->channel = channel;
	event_cur->val1 = val1;
	event_cur->val2 = val2;
	rdma_event.event_cur++;
	if (SIZE_EVENT == rdma_event.event_cur) {
		rdma_event.event_cur = 0;
	}
	raw_spin_unlock_irqrestore(&mu_fix_event, flags);
	return;
}

#include "mokx_ext_mode.c"
#include "mokx_intrrupt.c"
#include "mokx_read_buf.c"
#include "mokx_write_buf.c"
#include "mokx_send_msg.c"


/*
 * Set ID and mask
 * ============================================================================
 */
/*
 * Set ID for device
 */
void set_id_link(int link)
{
	unsigned cs;
	
	//WRR_rdma(SHIFT_CH_IDT, link, (base_ip_addr[3] + link) |
	//		((base_ip_addr[4] + link) << 8));
	cs = RDR_rdma(SHIFT_CS, link);
	if (IS_MACHINE_E2S)
		WRR_rdma(SHIFT_CS, link, cs | CS_DSM | E2S_CS_PTOCL );
	else
		WRR_rdma(SHIFT_CS, link, cs | CS_DSM );
	INFO_MSG("SHIFT_CS: 0x%08x\n", RDR_rdma(SHIFT_CS, link));
	//INFO_MSG("SHIFT_CH_IDT: 0x%08x\n", RDR_rdma(SHIFT_CH_IDT, link));
	//INFO_MSG("SHIFT_N_IDT: 0x%08x\n", RDR_rdma(SHIFT_N_IDT, link));
	
}

/*
 * Set/unset mask interrupt
 */
int set_mask(int link, unsigned int irq_mask)
{
	int ret = SUCCES_MOK_X;
	
	WRR_rdma(SHIFT_IRQ_MC, link, irq_mask);
	if (RDR_rdma(SHIFT_IRQ_MC, link) != irq_mask)
		ret = FAILED_MOK_X;
	return ret;
}

/*
 * Send messages
 * ============================================================================
 */

int send_msg_check(unsigned int msg, unsigned int link, unsigned int cmd,
		   dev_rdma_sem_t *dev, int print_enable)
{
	rdma_state_link_t *rdma_link;
	int ret_send_msg, i, count_repeat = 10;
	unsigned long flags_s;
	
	rdma_link = &rdma_state->rdma_link[link];
	raw_spin_lock_irqsave(&rdma_link->mutex_send_msg, flags_s);
	for (i = 0; i < count_repeat; i++) {
		ret_send_msg = send_msg(rdma_link, msg, link, cmd, 0);
		if (ret_send_msg > 0) 
			break;
		if (ret_send_msg < 0) {
			if (print_enable)
				ERROR_MSG("%s: FAIL send msg: 0x%08x "
					  "cmd: 0x%08x from link: %d ret: %d\n",
					  __FUNCTION__, msg, cmd, link, ret_send_msg);
		} else if (ret_send_msg == 0) {
			if (print_enable)
				DEBUG_MSG("%s: FAIL send msg: 0x%08x "
					  "cmd: 0x%08x from link: %d "
					  "ret: %d. SM is absent. "
					  "MSG_CS: 0x%08x \n",
					  __FUNCTION__, msg, cmd, link,
					  ret_send_msg,
					  RDR_rdma(SHIFT_MSG_CS, link));
		}
	}
	raw_spin_unlock_irqrestore(&rdma_link->mutex_send_msg, flags_s);
	if (ret_send_msg > 0) {
		fix_event(link, SNDMSGOK_EVENT, ret_send_msg, count_repeat);
		fix_event(link, SNDMSGOK_EVENT, 0xff, raw_smp_processor_id());
	} else {
		fix_event(link,	SNDMSGBAD_EVENT, ret_send_msg, count_repeat);
		fix_event(link, SNDMSGBAD_EVENT, 0xff, raw_smp_processor_id());
	}
	return ret_send_msg;
}

/*
 * Send SIR (start CAM)
 */
int send_SIR_Msg(int link)
{
	int ret = SUCCES_MOK_X;

	ret = send_msg_check(0, link, MSG_CS_SIR_Msg, 0, 0);
	if (ret < 0) {
		ERROR_MSG("%s: FAIL send MSG_CS_SIR_Msg from link: 0x%08x "
			  "ret: %d\n", __FUNCTION__, link, ret);
	} else if (ret == 0) {
		ERROR_MSG("%s: FAIL send MSG_CS_SIR_Msg from link: 0x%08x. "
			  "SM is absent\n", __FUNCTION__, link);
	}
	return ret;
}

/*
 * Send GP0 (reset)
 */
int send_SGP0_Msg(int link)
{
	int ret = SUCCES_MOK_X;
	
	ret = send_msg_check(0, link, MSG_CS_SGP0_Msg, 0, 0);
	if (ret < 0) {
		ERROR_MSG("%s: FAIL send MSG_CS_SGP0_Msg from link: 0x%08x "
			  "ret: %d\n", __FUNCTION__, link, ret);
	} else if (ret == 0) {
		ERROR_MSG("%s: FAIL send MSG_CS_SGP0_Msg from link: 0x%08x. "
			  "SM is absent\n", __FUNCTION__, link);
	}
	return ret;
}

/*
 * Send GP1 (change mode)
 */
int send_SGP1_Msg(int link)
{
	int ret = SUCCES_MOK_X;
	
	ret = send_msg_check(0, link, MSG_CS_SGP1_Msg, 0, 0);
	if (ret < 0) {
		ERROR_MSG("%s: FAIL send MSG_CS_SGP1_Msg from link: 0x%08x "
			  "ret: %d\n", __FUNCTION__, link, ret);
	} else if (ret == 0) {
		ERROR_MSG("%s: FAIL send MSG_CS_SGP1_Msg from link: 0x%08x. "
			  "SM is absent\n", __FUNCTION__, link);
	}
	return ret;
}

/*
 * Send GP2 (reset)
 */
int send_SGP2_Msg(int link)
{
	int ret = SUCCES_MOK_X;
	
	ret = send_msg_check(0, link, MSG_CS_SGP2_Msg, 0, 0);
	if (ret < 0) {
		ERROR_MSG("%s: FAIL send MSG_CS_SGP2_Msg from link: 0x%08x "
			  "ret: %d\n", __FUNCTION__, link, ret);
	} else if (ret == 0) {
		ERROR_MSG("%s: FAIL send MSG_CS_SGP2_Msg from link: 0x%08x. "
			  "SM is absent\n", __FUNCTION__, link);
	}
	return ret;
}

/*
 * Reset link
 * ============================================================================
 */

int link_soft_reset(int link)
{
	unsigned int cs;
	int i;
	
	cs = RDR_rdma(SHIFT_CS, link);
	printk("%s: link #%d. Register CS: %x.\n", __FUNCTION__, link, cs);
	printk("%s: link #%d. Reset link.\n", __FUNCTION__, link);
	WRR_rdma(SHIFT_CS, link, cs | CS_SRst);
	for (i = 0; i < 10; i ++) {
		mdelay(1);
		cs = RDR_rdma(SHIFT_CS, link);
		printk("%s: link #%d. Register CS: %x.\n", __FUNCTION__, link, cs);
	}
	return cs | CS_SRst;
}

#ifdef RESET_DMA_MEMMORY
int null_change(int link)
{
	rdma_addr_struct_t p_xxb_pa_r, p_xxb_pa_w;
	unsigned int es;
	
	p_xxb_pa_r.addr = (unsigned long)__pa(reset_dma_memory_r);	
	p_xxb_pa_w.addr = (unsigned long)__pa(reset_dma_memory_w);	
	WRR_rdma(SHIFT_IRQ_MC, link , 0x0);
	//read_regs_rdma(link);
	
#if 0
	unsigned int i;
	for (i = 0; i < 10; i++) {
		WRR_rdma(SHIFT_DMA_RCS, link, DMA_RCS_Rx_Rst);
		udelay(1000);
	}
	WRR_rdma(SHIFT_DMA_TCS, link, DMA_TCS_Tx_Rst);
	WRR_rdma(SHIFT_DMA_RCS, link, RDR_rdma(SHIFT_DMA_RCS, link) & ~DMA_RCS_RTM);
#endif
	mok_x_unset_mode4(link);
	//printk("---------------------Receive null wait...\n");
	//read_regs_rdma(link);
	
	WRR_rdma(SHIFT_DMA_TCS, link, RCode_64);
	WRR_rdma(SHIFT_DMA_RCS, link, WCode_64);
	WRR_rdma(SHIFT_DMA_HRSA, link, p_xxb_pa_r.fields.haddr);
	WRR_rdma(SHIFT_DMA_RSA, link, p_xxb_pa_r.fields.laddr);
	WRR_rdma(SHIFT_DMA_RBC, link, reset_size_r);
	WRR_rdma(SHIFT_DMA_RCS, link, WCode_64 | DMA_RCS_RFSM | DMA_RCS_RE );

	//printk("Receive null wait...\n");
	//read_regs_rdma(link);
	udelay(10000);
	//printk("Receive wait end.\n");
	//read_regs_rdma(link);
	WRR_rdma(SHIFT_DMA_RCS, link,
		 RDR_rdma(SHIFT_DMA_RCS, link) & (~DMA_RCS_RE));
#if 1	
	unsigned int i;
	for (i = 0; i < 10; i++) {
		WRR_rdma(SHIFT_DMA_RCS, link, DMA_RCS_Rx_Rst);
		udelay(1000);
	}
	WRR_rdma(SHIFT_DMA_TCS, link, RCode_64);
	WRR_rdma(SHIFT_DMA_RCS, link, WCode_64);
#endif
	es = RDR_rdma(SHIFT_ES, link);
	if (es & ES_RDC_Ev)
		WRR_rdma(SHIFT_ES, link, es & ES_RDC_Ev);
	WRR_rdma(SHIFT_IRQ_MC, link ,irq_mc);
	//read_regs_rdma(link);
	return 0;
}
#endif

#if RESET_THREAD_DMA

#define RST_THR_ACT_DBG 1
#define RST_THR_ACT_DEBUG_MSG(x...)\
		if (RST_THR_ACT_DBG) DEBUG_MSG(x)
int rst_thr_action(void *arg)
{
	rdma_state_link_t *rdma_link = (rdma_state_link_t *) arg;
	struct sched_param param = { .sched_priority = MAX_RT_PRIO/4 };
	unsigned long flags;
	int link = rdma_link->link;
	int count = 0;
	int ret_smsg, file_reciver_open = 0;
	unsigned int sending_msg;
	rw_state_p pd = NULL;
	dev_rdma_sem_t *dev_sem;
	rdma_pool_buf_t *r_pool_buf;
	unsigned int es;

	RST_THR_ACT_DEBUG_MSG("%s: START link:%d rdma_link: %p\n", __FUNCTION__,
				 link, rdma_link);
	//sys_sched_setscheduler(current->pid, SCHED_FIFO, &param);
	sched_setscheduler(current, SCHED_FIFO, &param);
	pd = &rdma_link->rw_states_d[READER];
	dev_sem = &pd->dev_rdma_sem;
	r_pool_buf = &rdma_link->read_pool;
	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		raw_spin_lock_irqsave(&dev_sem->lock, flags);
		if (pd->state_open_close) {
			file_reciver_open = 1;
		}
		else 
			file_reciver_open = 0;
		raw_spin_unlock_irqrestore(&dev_sem->lock, flags);
		raw_spin_lock_irqsave(&rdma_link->rst_thr_lock, flags);
		if ( rdma_link->start_rst_thr == 0) { 
			raw_spin_unlock_irqrestore(&rdma_link->rst_thr_lock, flags);
			RST_THR_ACT_DEBUG_MSG("%s: link:%d rdma_link: %p no reset\n", 
					__FUNCTION__, link, rdma_link);
			schedule();
			continue;
		}
#if RST_THR_ACT_DBG
		read_regs_rdma(link);
#endif		
		rdma_link->start_rst_thr = 0;
		raw_spin_unlock_irqrestore(&rdma_link->rst_thr_lock, flags);
		WRR_rdma(SHIFT_IRQ_MC, link , irq_mc_03);
#define DELAY_DMA 10
#define COUNT_DMA 100
		for (count = 1; count < COUNT_DMA; count++) {
					
			RST_THR_ACT_DEBUG_MSG("Repeat reg prog.\n");
			read_regs_rdma(link);
			es = RDR_rdma(SHIFT_ES, link);
			if (es & ES_DSF_Ev) {
				WRR_rdma(SHIFT_DMA_TCS, link, RDR_rdma(SHIFT_DMA_TCS, link) & (~DMA_TCS_TE));
				WRR_rdma(SHIFT_ES, link, es & ES_DSF_Ev);
				WRR_rdma(SHIFT_DMA_TCS, link, RCode_64 | DMA_TCS_DRCL |
					DMA_TCS_TE );
			}
			mdelay(COUNT_DMA);
		}
		es = RDR_rdma(SHIFT_ES, link);
		if (es & ES_DSF_Ev) {
			WRR_rdma(SHIFT_DMA_TCS, link, RDR_rdma(SHIFT_DMA_TCS, link) & (~DMA_TCS_TE));
			WRR_rdma(SHIFT_ES, link, es & ES_DSF_Ev);
		}
		WRR_rdma(SHIFT_DMA_TCS, link, RDR_rdma(SHIFT_DMA_TCS, link) & (~DMA_TCS_TE));
		WRR_rdma(SHIFT_DMA_RCS, link, RDR_rdma(SHIFT_DMA_RCS, link) & (~DMA_RCS_RE));
		es = RDR_rdma(SHIFT_ES, link);
		WRR_rdma(SHIFT_ES, link, es & ~ES_SM_Ev & ~ES_DSF_Ev);
#define DELAY_RESET 10
#define COUNT_RESET_RCS 10
		for (count = 1; count < COUNT_RESET_RCS; count++) {
			WRR_rdma(SHIFT_DMA_RCS, link, DMA_RCS_Rx_Rst);
			mdelay(DELAY_RESET);
		}
		WRR_rdma(SHIFT_DMA_RCS, link, RDR_rdma(SHIFT_DMA_RCS, link) | 
				WCode_64);
#define COUNT_RESET_TCS 10		
		for (count = 1; count < COUNT_RESET_TCS; count++) {
			WRR_rdma(SHIFT_DMA_TCS, link, DMA_TCS_Tx_Rst);
			mdelay(DELAY_RESET);
		}
		WRR_rdma(SHIFT_DMA_TCS, link, 
			 RDR_rdma(SHIFT_DMA_TCS, link) | RCode_64 | DMA_TCS_DRCL);
		//rdma_link->start_rst_thr = 0;
#if RST_THR_ACT_DBG
		read_regs_rdma(link);
#endif		
		/*
		 * If file reciver open && transmiter reset
		 */
		if (file_reciver_open) {
			unsigned long flags_r;
			raw_spin_lock_irqsave(&pd->lock_rd, flags_r);
			/*
			 * The release of buffers
			 */
			while (!list_empty(&r_pool_buf->ready_list)) {
				list_move_tail(r_pool_buf->ready_list.next, 
					       &r_pool_buf->free_list);
				r_pool_buf->num_free_buf ++;
			}
			//while (!list_empty(&r_pool_buf->busy_list)) {
			//	list_move_tail(r_pool_buf->busy_list.next, 
			//		       &r_pool_buf->free_list);
			//}
			//r_pool_buf->num_free_buf = num_buf;
			raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);			
			/*
			 * Create MSG_READY_DMA 
			 */
			sending_msg = MSG_READY_DMA | r_pool_buf->num_free_buf;
			/*
			 * Send TRWD 
			 */
			if ((ret_smsg = send_msg_check(sending_msg, link,
		     		0, dev_sem, 0)) <= 0) {
			     	fix_event(link, READ_SNDMSGBAD_EVENT, 
					  sending_msg, dev_sem->num_obmen);
		     	} else {
				fix_event(link, READ_SNDNGMSG_EVENT, 
					  sending_msg, dev_sem->num_obmen);
		     	}
		}
		WRR_rdma(SHIFT_IRQ_MC, link ,irq_mc);

		RST_THR_ACT_DEBUG_MSG("%s: link:%d rdma_link: %p reset mask: %x \n", 
					__FUNCTION__, link, rdma_link, 
      					RDR_rdma(SHIFT_IRQ_MC, link));
	}
	__set_current_state(TASK_RUNNING);
	RST_THR_ACT_DEBUG_MSG("%s: STOP link:%d rdma_link: %p\n", __FUNCTION__,
				 link, rdma_link);
	return 0;
	
}
#endif


/*
 * Create thread for reset link, init lock thread reset
 */
#if RESET_THREAD_DMA
int thread_reset_start(int link)
{
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[link];
	
	raw_spin_lock_init(&rdma_link->rst_thr_lock);
	rdma_link->start_rst_thr = 0;
	rdma_link->rst_thr = kthread_create(rst_thr_action, rdma_link,
					    "%d-mokx-rx-rst-thr", link);
	if (!rdma_link->rst_thr) {
		ERROR_MSG("%s: could not create %d-mokx-rst-thr\n",
			  __FUNCTION__, link);
		rdma_link->rst_thr = NULL;
		return FAILED_MOK_X;
	}
	return SUCCES_MOK_X;
}
#endif

/*
 * Reset when the channel error and driver initialization
 */
void link_error_reset_start(int link)
{
#if RESET_THREAD_DMA
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[link];
	unsigned long flags;
	
	raw_spin_lock_irqsave(&rdma_link->rst_thr_lock, flags);
	rdma_link->start_rst_thr = 1;
	raw_spin_unlock_irqrestore(&rdma_link->rst_thr_lock, flags);
	wake_up_process(rdma_link->rst_thr);
#else
#if 0	
	WRR_rdma(SHIFT_DMA_TCS, link, DMA_TCS_Tx_Rst);
	WRR_rdma(SHIFT_DMA_TCS, link, RDR_rdma(SHIFT_DMA_TCS, link) |
			RCode_64 | DMA_TCS_DRCL);
#define COUNT_RESET_RCS 10
	int count = 0;
	for (count = 1; count < COUNT_RESET_RCS; count++)
		WRR_rdma(SHIFT_DMA_RCS, link, DMA_RCS_Rx_Rst);
	WRR_rdma(SHIFT_DMA_RCS, link, RDR_rdma(SHIFT_DMA_RCS, link) | WCode_64);
#endif
#endif
}

#if RESET_THREAD_DMA
/*
 * Stop thread for reset link
 */
void thread_reset_stop(int link)
{
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[link];
	
	if (rdma_link->rst_thr) {
		kthread_stop(rdma_link->rst_thr);
		rdma_link->rst_thr = NULL;
	}
}
#endif

/*
 * Memory
 * ============================================================================
 */

#define INIT_POOL_BUF_DBG 0
#define INIT_POOL_BUF_DEBUG_MSG(x...)\
		if (INIT_POOL_BUF_DBG) DEBUG_MSG(x)
static int pool_buf_init(int link, int rw)
{
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[link];
	rdma_tbl_64_struct_t *peltbl, *peltbl_tmp;
	rdma_addr_struct_t pxx;
	rdma_pool_buf_t *pool_buf;
	rdma_buf_t *r_buf;
	int buf_size_page;
	int buf_size;
	int i;
	
	INIT_POOL_BUF_DEBUG_MSG("%s: buffer(%s) START \n", __FUNCTION__,
				rw ? "write" : "read");
	INIT_POOL_BUF_DEBUG_MSG("=========================================\n");
	INIT_POOL_BUF_DEBUG_MSG("rdma_link->num_buf: %x\n", rdma_link->num_buf);
	INIT_POOL_BUF_DEBUG_MSG("rdma_link->tm_mode: %x\n", rdma_link->tm_mode);
	INIT_POOL_BUF_DEBUG_MSG("rdma_link->max_size_buf_tm: %x\n", rdma_link->max_size_buf_tm);
	INIT_POOL_BUF_DEBUG_MSG("rdma_link->align_buf_tm: %x\n", rdma_link->align_buf_tm);
	INIT_POOL_BUF_DEBUG_MSG("rdma_link->node_mem_alloc: %x\n", rdma_link->node_mem_alloc);
	INIT_POOL_BUF_DEBUG_MSG("rdma_link->type_alloc: %x\n", rdma_link->type_alloc);
	INIT_POOL_BUF_DEBUG_MSG("=========================================\n");
	
	
	rw ? (pool_buf = &rdma_link->write_pool) :
	     (pool_buf = &rdma_link->read_pool);
	pool_buf->alloc = RDMA_BUF_EMPTY;
	/*
	 * Alloc memory for pool (get user access address and DMA address)
	 */
	if (rdma_link->type_alloc) {
#ifdef CONFIG_RDMA_BOOT_MEM_ALLOC
		if (R_M_NODE && rdma_link_mem[NUM_NODE_RDMA(link)]) {
			buf_size = allign_dma(rdma_link->max_size_buf);
			if ((buf_size * rdma_link->num_buf) > R_M_NODE)
				goto failed;
			INIT_POOL_BUF_DEBUG_MSG("%s: alloc bootmem rdma_link_mem[%d]: %p\n",
				 __FUNCTION__, NUM_NODE_RDMA(link),
			rdma_link_mem[NUM_NODE_RDMA(link)]);
			rdma_link->buf_size = buf_size;
			rdma_link->tm_mode = 0;
			pool_buf->buf_size = buf_size;
			pool_buf->size = buf_size * rdma_link->num_buf;
			pool_buf->tm_mode = rdma_link->tm_mode;
			pool_buf->vdma = (caddr_t)(rdma_link_mem[NUM_NODE_RDMA(link)] +
						   pool_buf->size * busy_rdma_boot_mem);
			pool_buf->fdma = (dma_addr_t)virt_to_phys(pool_buf->vdma);
			pool_buf->dma_size = pool_buf->size;
		} else
			goto failed;
#else
		goto failed;
#endif	
	} else {
		rdma_link->tm_mode ? (buf_size = ALIGN(rdma_link->max_size_buf_tm,
						       rdma_link->align_buf_tm * PAGE_SIZE)) :
				     (buf_size = allign_dma(rdma_link->max_size_buf));
		if (rdma_link->tm_mode)
			buf_size = ALIGN(buf_size, 32 * rdma_link->align_buf_tm * PAGE_SIZE);
		buf_size_page = buf_size / (rdma_link->align_buf_tm * PAGE_SIZE);
		if (rdma_link->tm_mode) {
			INIT_POOL_BUF_DEBUG_MSG("%s: max_size_buf_tm: 0x%08x "
						"buf_size: 0x%08x buf_size_page: %d\n",
						__FUNCTION__, rdma_link->max_size_buf_tm,
						buf_size, buf_size_page);
		} else
			INIT_POOL_BUF_DEBUG_MSG("%s: max_size_buf: 0x%08x "
						"buf_size: 0x%08x buf_size_page: %d\n",
						__FUNCTION__, rdma_link->max_size_buf,
						buf_size, buf_size_page); 
		rdma_link->buf_size = buf_size;
		pool_buf->buf_size = buf_size;
		pool_buf->size = buf_size * rdma_link->num_buf;
		pool_buf->node_mem_alloc = rdma_link->node_mem_alloc;
		pool_buf->node_for_memory = NUM_NODE_RDMA(link);
		pool_buf->tm_mode = rdma_link->tm_mode;
		pool_buf->align_buf_tm = rdma_link->align_buf_tm;
		INIT_POOL_BUF_DEBUG_MSG("%s: buffer(%s) buf_size: 0x%016lx tm_mode: %d "
				"node_for_memory: 0x%08x\n", __FUNCTION__,
    				rw ? "write" : "read", pool_buf->size,
    				pool_buf->tm_mode, pool_buf->node_for_memory);
		
		if (rdma_mem_alloc_pool(pool_buf)) {
			ERROR_MSG("%s: ERROR: Cannot alloc device buffer "
					"for link: %d buf: %s\n", __FUNCTION__,
					link, rw ? "write" : "read");
			goto failed;
		}
	}
	pool_buf->alloc = RDMA_BUF_ALLOCED;
	
	/*
	 * Init list's
	 */
	INIT_LIST_HEAD(&pool_buf->ready_list);
	INIT_LIST_HEAD(&pool_buf->free_list);
	INIT_LIST_HEAD(&pool_buf->busy_list);
	
	if (pool_buf->tm_mode)
		peltbl = (rdma_tbl_64_struct_t *)pool_buf->vdma;
	for(i = 0; i < rdma_link->num_buf; i++) {
		r_buf = &pool_buf->buf[i];
		INIT_POOL_BUF_DEBUG_MSG("%s: ADDR BUFF[%d]: %p\n", __FUNCTION__, 
					i, r_buf);
		INIT_POOL_BUF_DEBUG_MSG("%s: alloc buf[%d]\n", __FUNCTION__, i);
		pool_buf->buf[i].num = i;
		INIT_POOL_BUF_DEBUG_MSG("%s: pool_buf->buf[%d].num : 0x%08x\n",
					__FUNCTION__, i, pool_buf->buf[i].num);
		pool_buf->buf[i].st = RDMA_BUF_ST_FREE;
		INIT_POOL_BUF_DEBUG_MSG("%s: pool_buf->buf[%d].st: 0x%08x\n",
					__FUNCTION__, i, pool_buf->buf[i].st);
		if (pool_buf->tm_mode) {
			peltbl_tmp = peltbl + i * buf_size_page;
			pool_buf->buf[i].buf_addr =
					(caddr_t)((unsigned long)peltbl_tmp);
			/**
			 * For small changes 
			 */
			pool_buf->buf[i].buf_addr_small = 
					(dma_addr_t)peltbl_tmp->addr;
			pxx.addr = (unsigned long)pool_buf->buf[i].buf_addr_small;
			INIT_POOL_BUF_DEBUG_MSG("%s: SMALL 0x%08x%08x pool_buf->buf[%d].buf_addr_small\n",
			      __FUNCTION__, pxx.fields.haddr, pxx.fields.laddr, i);
			pool_buf->buf[i].dma_addr = (dma_addr_t)
					virt_to_phys(pool_buf->buf[i].buf_addr);
			pxx.addr = (unsigned long)peltbl_tmp;
			INIT_POOL_BUF_DEBUG_MSG("%s: 0x%08x%08x peltbl : %p buf[%d]\n",
			       __FUNCTION__, pxx.fields.haddr, pxx.fields.laddr,
			       peltbl_tmp, i);
			pxx.addr = peltbl_tmp->addr;
			INIT_POOL_BUF_DEBUG_MSG("%s: 0x%08x%08x peltbl->addr buf[%d]\n",
			       __FUNCTION__, pxx.fields.haddr,
			       pxx.fields.laddr, i);
			INIT_POOL_BUF_DEBUG_MSG("%s: 0x%llx peltbl->sz buf[%d]\n", __FUNCTION__,
			       peltbl_tmp->sz, i);
		} else {
			pool_buf->buf[i].buf_addr = 
				(caddr_t)((unsigned long)pool_buf->vdma
				+ buf_size * i);
			pool_buf->buf[i].dma_addr =
				(dma_addr_t)virt_to_phys(pool_buf->buf[i].buf_addr);
			pool_buf->buf[i].buf_addr_small =
					pool_buf->buf[i].dma_addr;
			/**
			 * For small changes 
			 */
			pxx.addr = (unsigned long)pool_buf->buf[i].buf_addr_small;
			INIT_POOL_BUF_DEBUG_MSG("%s: SMALL 0x%08x%08x pool_buf->buf[%d].buf_addr_small\n",
			      __FUNCTION__, pxx.fields.haddr, pxx.fields.laddr, i);			
			
		}
		pool_buf->buf[i].size = pool_buf->buf_size;
		INIT_POOL_BUF_DEBUG_MSG("%s: pool_buf->buf[%d].size: 0x%016lx\n",
					__FUNCTION__, i, pool_buf->buf[i].size);
		pxx.addr = (unsigned long) pool_buf->buf[i].buf_addr;
		INIT_POOL_BUF_DEBUG_MSG("%s: 0x%08x%08x "
					"pool_buf->buf[%d].buf_addr\n",
					__FUNCTION__, pxx.fields.haddr,
     					pxx.fields.laddr, i);
		pxx.addr = pool_buf->buf[i].dma_addr;
		INIT_POOL_BUF_DEBUG_MSG("%s: 0x%08x%08x "
					"pool_buf->buf[%d].dma_addr\n",
					__FUNCTION__, pxx.fields.haddr,
	  				pxx.fields.laddr, i);
		list_add_tail(&pool_buf->buf[i].list, &pool_buf->free_list);
	}
	pool_buf->num_free_buf = rdma_link->num_buf;
	INIT_POOL_BUF_DEBUG_MSG("%s: buffer(%s) STOP \n", __FUNCTION__,
				rw ? "write" : "read");
	return 0;
failed:
	return -1;
}

#define FREE_POOL_BUF_DBG 0
#define FREE_POOL_BUF_DEBUG_MSG(x...)\
		if (FREE_POOL_BUF_DBG) DEBUG_MSG(x)
static int free_pool_buf(int link, int rw)
{
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[link];
	rdma_addr_struct_t pxx;
	rdma_pool_buf_t *pool_buf;
	int i;
		
	FREE_POOL_BUF_DEBUG_MSG("%s: buffer(%s) START \n", __FUNCTION__,
				rw ? "write" : "read");
	rw ? (pool_buf = &rdma_link->write_pool) :
 	     (pool_buf = &rdma_link->read_pool);
	
	/*
	 * Free memory for pool (get user access address and DMA address)
	 */
	if (!rdma_link->type_alloc)	
		rdma_mem_free_pool(pool_buf);
	for(i = 0; i < rdma_link->num_buf; i++) {
		if (pool_buf->buf[i].size) {
		FREE_POOL_BUF_DEBUG_MSG("%s: free buf[%d]\n", __FUNCTION__, i);
		pool_buf->buf[i].size = 0;
		FREE_POOL_BUF_DEBUG_MSG("%s: pool_buf->buf[%d].size: 0x%016lx\n",
				__FUNCTION__, i, pool_buf->buf[i].size);
		pool_buf->buf[i].buf_addr = NULL;
		pxx.addr = (unsigned long) pool_buf->buf[i].buf_addr;
		FREE_POOL_BUF_DEBUG_MSG("%s: 0x%08x%08x "
					"pool_buf->buf[%d].buf_addr\n",
					__FUNCTION__, pxx.fields.haddr,
					pxx.fields.laddr, i);
		pool_buf->buf[i].dma_addr = 0;
		pxx.addr = pool_buf->buf[i].dma_addr;
		FREE_POOL_BUF_DEBUG_MSG("%s: 0x%08x%08x "
					"pool_buf->buf[%d].dma_addr\n",
					__FUNCTION__, pxx.fields.haddr,
					pxx.fields.laddr, i);
		}
	}
	return 0;
}

/*
 * Init buff's
 */
int bufs_init(int link)
{
	busy_rdma_boot_mem = 0;
	if (pool_buf_init(link, READER))
		goto failed;
	busy_rdma_boot_mem = 1;
	if (pool_buf_init(link, WRITER))
		goto failed;
	return 0;
failed:
	return 1;
}

/*
 * Free buff's
 */
void bufs_free(int link)
{
	free_pool_buf(link, READER);
	free_pool_buf(link, WRITER);
}

#define MOK_X_SET_MODE_DBG 0
#define MOK_X_SET_MODE_DEBUG_MSG(x...)\
		if (MOK_X_SET_MODE_DBG) printk(x)

/*
 * Set default mode
 * ============================================================================
 */

int set_mode_default(int link)
{
	int ret;
	
	MOK_X_SET_MODE_DEBUG_MSG("Unset bit enable status reg: ");
	if (ret = unset_mok_x_SR_enable(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset bit master status reg: ");
	if (ret = unset_mok_x_SR_master(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset bit slave status reg: ");
	if (ret = unset_mok_x_SR_slave(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset bit enable_transmit status reg: ");
	if (ret = unset_mok_x_SR_enable_trasmit(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset bit enable_receive status reg: ");
	if (ret = unset_mok_x_SR_enable_receive(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset bit ready_to_receive status reg: ");
	if (ret = unset_mok_x_SR_ready_to_receive(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset bit granted_packet status reg: ");
	if (ret = unset_mok_x_SR_granted_packet(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset bit granted_last_packet status reg: ");
	if (ret = unset_mok_x_SR_granted_last_packet(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset bit mode1 status reg: ");
	if (ret = unset_mok_x_SR_mode1(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset bit mode2 status reg: ");
	if (ret = unset_mok_x_SR_mode2(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset bit mode3 status reg: ");
	if (ret = unset_mok_x_SR_mode3(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset bit mode4 status reg: ");
	if (ret = unset_mok_x_SR_mode4(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
fail:
	return ret;
}

int set_mode_default_remote(int link)
{
	int ret;
	
	MOK_X_SET_MODE_DEBUG_MSG("Unset remote bit enable status reg: ");
	if (ret = unset_mok_x_remote_SR_enable(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset remote bit master status reg: ");
	if (ret = unset_mok_x_remote_SR_master(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset remote bit slave status reg: ");
	if (ret = unset_mok_x_remote_SR_slave(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset remote bit enable_transmit status reg: ");
	if (ret = unset_mok_x_remote_SR_enable_trasmit(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset remote bit enable_receive status reg: ");
	if (ret = unset_mok_x_remote_SR_enable_receive(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset remote bit ready_to_receive status reg: ");
	if (ret = unset_mok_x_remote_SR_ready_to_receive(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset remote bit granted_packet status reg: ");
	if (ret = unset_mok_x_remote_SR_granted_packet(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset remote bit granted_last_packet status reg: ");
	if (ret = unset_mok_x_remote_SR_granted_last_packet(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset remote bit mode1 status reg: ");
	if (ret = unset_mok_x_remote_SR_mode1(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset remote bit mode2 status reg: ");
	if (ret = unset_mok_x_remote_SR_mode2(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset remote bit mode3 status reg: ");
	if (ret = unset_mok_x_remote_SR_mode3(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Unset remote bit mode4 status reg: ");
	if (ret = unset_mok_x_remote_SR_mode4(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
fail:
	return ret;
}

int check_mode_default(int link)
{
	int ret;
	
	MOK_X_SET_MODE_DEBUG_MSG("Get bit enable status reg: ");
	if ((ret = get_mok_x_SR_enable(link)) < 1) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Get bit master status reg: ");
	if ((ret = get_mok_x_SR_master(link)) < 1) {
		printk("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Get bit slave status reg: ");
	if ((ret = get_mok_x_SR_slave(link)) < 1) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Get bit enable_transmit status reg: ");
	if ((ret = get_mok_x_SR_enable_trasmit(link)) < 1) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Get bit enable_receive status reg: ");
	if ((ret = get_mok_x_SR_enable_receive(link)) < 1) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Get bit ready_to_receive status reg: ");
	if ((ret = get_mok_x_SR_ready_to_receive(link)) < 1) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Get bit granted_packet status reg: ");
	if ((ret = get_mok_x_SR_granted_packet(link)) < 1) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Get bit granted_last_packet status reg: ");
	if ((ret = get_mok_x_SR_granted_last_packet(link)) < 1) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Get bit mode1 status reg: ");
	if ((ret = get_mok_x_SR_mode1(link)) < 1) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Get bit mode2 status reg: ");
	if ((ret = get_mok_x_SR_mode2(link)) < 1) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Get bit mode3 status reg: ");
	if ((ret = get_mok_x_SR_mode3(link)) < 1) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Get bit mode4 status reg: ");
	if ((ret = get_mok_x_SR_mode4(link)) < 1) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
fail:
	return ret;
}

/*
 * Set native mode
 * ============================================================================
 */

int set_mode_native(int link)
{
	int ret;
	
	MOK_X_SET_MODE_DEBUG_MSG("Set bit enable status reg: ");
	if (ret = set_mok_x_SR_enable(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Set bit enable_transmit status reg: ");
	if (ret = set_mok_x_SR_enable_trasmit(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Set bit enable_receive status reg: ");
	if (ret = set_mok_x_SR_enable_receive(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Set bit ready_to_receive status reg: ");
	if (ret = set_mok_x_SR_ready_to_receive(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Set bit granted_packet status reg: ");
	if (ret = set_mok_x_SR_granted_packet(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
fail:
	return ret;
}

int check_mode_native(int link)
{
	int ret;
	
	MOK_X_SET_MODE_DEBUG_MSG("Get bit enable status reg: ");
	if ((ret = get_mok_x_SR_enable(link)) < 1) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Get bit enable_transmit status reg: ");
	if ((ret = get_mok_x_SR_enable_trasmit(link)) < 1) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Get bit enable_receive status reg: ");
	if ((ret = get_mok_x_SR_enable_receive(link)) < 1) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Get bit ready_to_receive status reg: ");
	if ((ret = get_mok_x_SR_ready_to_receive(link)) < 1) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Get bit granted_packet status reg: ");
	if ((ret = get_mok_x_SR_granted_packet(link)) < 1) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG(" %d\n", ret);
	return 0;
fail:
	return 1;
}

int mok_x_set_native_mode(int link, int *error)
{
#if RESET_THREAD_DMA
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[link];
	unsigned long flags;
#endif
	int ret = SUCCES_MOK_X;
#ifdef SETTING_OVER_INTERRUPT
	if (set_mask(link, irq_mc)) {
		*error = ERRDMA_SET_MASK;
		ret = FAILED_MOK_X;
		goto filed_set_mode_native;
	}
#endif	
	if (ret = set_mode_native(link)) {
		*error = ret;
		ret = FAILED_MOK_X;
		goto filed_set_mode_native;
	}
	INFO_MSG("MOKX set to native mode. Error(%d).\n", ret);
	if (ret = check_mode_native(link))  {
		if (!ret)
			*error = ERROR_MOK_X_NOT_SET_BIT;
		else
			*error = ret;
		ret = FAILED_MOK_X;
		goto filed_set_mode_native;
	}
	INFO_MSG("MOKX check native mode. Error(%d).\n", ret);
#if RESET_THREAD_DMA
	if (thread_reset_start(link)) {
		*error = ERRDMA_THREAD_RESET_START;
		ret = FAILED_MOK_X;
		goto filed_set_mode_native;
	}
	if (send_SGP2_Msg(link) < 1) {
		*error = ERRDMA_GP0_SEND;
		ret = FAILED_MOK_X;
		goto filed_set_mode_native;
	}
	if (set_mask(link, irq_mc_03)) {
		*error = ERRDMA_SET_MASK;
		ret = FAILED_MOK_X;
		goto filed_set_mode_native;
	}
	raw_spin_lock_irqsave(&rdma_link->rst_thr_lock, flags);
	rdma_link->start_rst_thr = 1;
	raw_spin_unlock_irqrestore(&rdma_link->rst_thr_lock, flags);
	wake_up_process(rdma_link->rst_thr);
	INFO_MSG("MOKX start reset thread. Error(%d).\n", ret);
#else
#ifndef SETTING_OVER_INTERRUPT
	if (set_mask(link, irq_mc)) {
		*error = ERRDMA_SET_MASK;
		ret = FAILED_MOK_X;
		goto filed_set_mode_native;
	}
#endif	
#endif	
#if 0	
	if (send_SIR_Msg(link) < 1) {
		*error = ERRDMA_ID_SEND;
		ret = FAILED_MOK_X;
		goto filed_set_mode_native;
	}
	INFO_MSG("MOKX send SIR. Error(%d).\n", ret);
#endif
	return ret;
filed_set_mode_native:
	set_mask(link, 0x0);
#if RESET_THREAD_DMA
	thread_reset_stop(link);
#endif
	return ret;
}

int mok_x_unset_native_mode(int link, int *error)
{
	int ret = SUCCES_MOK_X;
	
	if (set_mask(link, MASK_INTERRUPT_NULL)) {
		*error = ERRDMA_SET_MASK;
		ret = FAILED_MOK_X;
	};
#if RESET_THREAD_DMA
	thread_reset_stop(link);
#endif	
	return ret;
}


#define MOK_X_EX_MODE_INIT_DBG 0
#define MOK_X_EX_MODE_INIT_DEBUG_MSG(x...)\
		if (MOK_X_EX_MODE_INIT_DBG) DEBUG_MSG(x)

#define IS_NOT_SET_REMOTE_SYSTEM_SLAVE	11
#define IS_NOT_SET_REMOTE_MODE4		12
#define IS_NOT_SET_SYSTEM_MASTER	13
#define IS_NOT_SET_MODE3		14
#define IS_NOT_SET_SIZE			15
#define IS_NOT_SET_ENABLE_RECEIVE	16
#define IS_NOT_SET_ENABLE_TRANSMIT	17
#define IS_NOT_SET_READY_TO_RECEIVE	18
#define IS_NOT_SET_GRANTED_PACKET	19

int mok_x_prog_recieve_dma(int link, int lock)
{
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[link];
	//unsigned long flags, flags_r;
	unsigned long flags_r;
	rdma_addr_struct_t p_xxb, p_xxb_pa;
	dev_rdma_sem_t *dev_sem;
	rw_state_p pd = NULL;
	rdma_pool_buf_t *r_pool_buf;
	rdma_buf_t *r_buf;
	size_t size;
	int ret = 0;
			
	pd = &rdma_link->rw_states_d[READER];
	dev_sem = &pd->dev_rdma_sem;
	p_xxb.addr = (unsigned long)pd;
	r_pool_buf = &rdma_link->read_pool;
	
	if (lock)
		raw_spin_lock_irqsave(&pd->lock_rd, flags_r);
	/*
	 * Search free for read buffer
	 */
	if (list_empty(&r_pool_buf->free_list)) {
		r_buf = NULL;
		ret = -1;
	} else {
		r_buf = list_entry(r_pool_buf->free_list.next,
				   rdma_buf_t, list);
		list_move_tail(&r_buf->list,
			       &r_pool_buf->ready_list);
		r_pool_buf->num_free_buf --;
		/*
		 * Programming dma reciver
		 */
		size = rdma_link->mok_x_buf_size;
		/*
		 * Check on bad size. TODO ???
		 */
		if (size > r_buf->size) {
			event_intr(link, READ_BADSIZE_EVENT, 
				   size, dev_sem->num_obmen);
			event_intr(link, READ_BADSIZE_EVENT, r_buf->size,
				   dev_sem->num_obmen);
				size = r_buf->size;
			}
		r_buf->real_size = size;
		WRR_rdma(SHIFT_DMA_RCS, link, WCode_64 );
		if (size > SMALL_CHANGE) {
			p_xxb_pa.addr = (unsigned long)r_buf->dma_addr;
		} else {
			p_xxb_pa.addr = (unsigned long)r_buf->buf_addr_small;
		}
		WRR_rdma(SHIFT_DMA_HRSA, link, 
				 p_xxb_pa.fields.haddr);
		WRR_rdma(SHIFT_DMA_RSA, link, 
			 p_xxb_pa.fields.laddr);
		if (size > SMALL_CHANGE) {
			pd->size_trans = (r_pool_buf->tm_mode ? 
				ALIGN(size, (rdma_link->align_buf_tm * PAGE_SIZE)) : (rfsm ? 
				r_buf->size : allign_dma(size)));
			WRR_rdma(SHIFT_DMA_RBC, link, pd->size_trans);
			//read_regs_rdma(link); ///
			WRR_rdma(SHIFT_DMA_RCS, link, WCode_64 | 
				DMA_RCS_RE | 
				(r_pool_buf->tm_mode ? DMA_RCS_RTM : 0) |
				(r_pool_buf->tm_mode ? 0 : DMA_RCS_RFSM));
			if (rdma_link->mok_x_mode_number_link == MODE3_LINK)
				set_mok_x_SR_ready_to_receive(link);
			//read_regs_rdma(link); ///
		}  else {
			pd->size_trans = allign_dma(size);
			WRR_rdma(SHIFT_DMA_RCS, link, WCode_64 );
			WRR_rdma(SHIFT_DMA_RBC, link, pd->size_trans);
			//read_regs_rdma(link); ///
			WRR_rdma(SHIFT_DMA_RCS, link, WCode_64 | 
				DMA_RCS_RE | DMA_RCS_RFSM);
			if (rdma_link->mok_x_mode_number_link == MODE3_LINK)
				set_mok_x_SR_ready_to_receive(link);
			//read_regs_rdma(link); ///
		}
	}
	r_pool_buf->work_buf = r_buf;
	if (lock)
		raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
	return ret;
}

//int mok_x_set_mode4(int link, int test_generator)
int mok_x_set_mode4(int link)
{
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[link];
	int ret = 0;
	
#if RESET_THREAD_DMA
	unsigned long flags;
	
	raw_spin_lock_irqsave(&rdma_link->rst_thr_lock, flags);
	rdma_link->start_rst_thr = 1;
	raw_spin_unlock_irqrestore(&rdma_link->rst_thr_lock, flags);
	wake_up_process(rdma_link->rst_thr);
	mdelay(1000);	
	//thread_reset_stop(link);
#endif
#ifdef SET_ENABLE_RECEIVE_BIT
#ifdef SETTING_OVER_INTERRUPT
	WRR_rdma(SHIFT_IRQ_MC, link , ES_RDM_Ev);
#endif
#endif
	MOK_X_SET_MODE_DEBUG_MSG("Set bit granted_packet status reg remote controller: ");
	if (ret = set_mok_x_remote_SR_granted_packet(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Set bit enable status reg remote controller: ");
	if (ret = set_mok_x_remote_SR_enable(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Set bit enable_receive status reg remote controller:: ");
	if (ret = set_mok_x_remote_SR_enable_receive(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	MOK_X_SET_MODE_DEBUG_MSG("Set bit enable_transmit status reg remote controller: ");
	if (ret = set_mok_x_remote_SR_enable_trasmit(link)) {
		MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
		goto fail;
	}
	MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	if (rdma_link->mok_x_mode_number_link == MODE3_LINK) {
		MOK_X_SET_MODE_DEBUG_MSG("Set bit mode3 status reg controller: ");
		if (ret = set_mok_x_SR_mode3(link)) {
			MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
			goto fail;
		}
		MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
		MOK_X_SET_MODE_DEBUG_MSG("Set size (%x) buffer your controller: ", 
			 rdma_link->mok_x_buf_size);
		if (ret = set_mok_x_SIZE(link, rdma_link->mok_x_buf_size)) {
			MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
			goto fail;
		}
		MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	}
	if (rdma_link->generator_mode) {
		MOK_X_SET_MODE_DEBUG_MSG("Set bit slave status reg remote controller: ");
		if (ret = set_mok_x_remote_SR_slave(link)) {
			MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
			goto fail;
		}
		MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
		MOK_X_SET_MODE_DEBUG_MSG("Set bit mode4 status reg remote controller: ");
		if (ret = set_mok_x_remote_SR_mode4(link)) {
			MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
			goto fail;
		}
		MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	}
	set_mask(link, irq_mc_rdc);
fail:
	return ret;
}

int mok_x_unset_mode4(int link)
{
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[link];
	int ret = 0;

#ifdef SET_ENABLE_RECEIVE_BIT
#ifdef SETTING_OVER_INTERRUPT
	WRR_rdma(SHIFT_IRQ_MC, link , ES_RDM_Ev);
#endif
#endif
	if (rdma_link->generator_mode) {
		MOK_X_SET_MODE_DEBUG_MSG("Unset bit mode4 status reg remote controller: ");
		if (ret = unset_mok_x_remote_SR_mode4(link)) {
			MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
			goto fail;
		}
		MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
		MOK_X_SET_MODE_DEBUG_MSG("Unset bit slave status reg remote controller: ");
		if (ret = unset_mok_x_remote_SR_slave(link)) {
			MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
			goto fail;
		}
		MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
#if 0
		unsigned type_msg;
		type_msg = (2 * 1 + 1) << RDMA_MOK_X_MSG_SHIFT;
		//ret = WRR_mok_x(link, type_msg, MOK_X_COMMAND,
		ret = WRR_mok_x(link, RDMA_MOK_X_REMOTE_REG_WRITE, MOK_X_COMMAND,
				MOK_X_COMMAND_RESET);
		INFO_MSG("RESET TRANSMIT: %d\n", ret);
#endif
	}
	if (rdma_link->mok_x_mode_number_link == MODE3_LINK) {
		MOK_X_SET_MODE_DEBUG_MSG("Unset bit mode3 status reg controller: ");
		if (ret = unset_mok_x_SR_mode3(link)) {
			MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
			goto fail;
		}
		MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
		MOK_X_SET_MODE_DEBUG_MSG("Set bit ready_to_receive status reg: ");
		if (ret = set_mok_x_SR_ready_to_receive(link)) {
			MOK_X_SET_MODE_DEBUG_MSG("error (%d)\n", ret);
			goto fail;
		}
		MOK_X_SET_MODE_DEBUG_MSG("ok (%d)\n", ret);
	}
fail:
#ifdef SET_ENABLE_RECEIVE_BIT	
#ifdef SETTING_OVER_INTERRUPT
	WRR_rdma(SHIFT_IRQ_MC, link , 0x0);
#endif
#endif		
	//set_mask(link, irq_mc);	
	rdma_link->generator_mode = 0;
#if RESET_THREAD_DMA
	unsigned long flags;
	mdelay(1000);	
	raw_spin_lock_irqsave(&rdma_link->rst_thr_lock, flags);
	rdma_link->start_rst_thr = 1;
	raw_spin_unlock_irqrestore(&rdma_link->rst_thr_lock, flags);
	wake_up_process(rdma_link->rst_thr);
#endif	
	return ret;
}

#define RDMA_INIT_DBG 0
#define RDMA_INIT_DEBUG_MSG(x...)\
		if (RDMA_INIT_DBG) DEBUG_MSG(x)

static int __init rdma_init(void)
{
	size_t size_rdma_state;
	int link;
	int node;
	int major;
	int ret = SUCCES_MOK_X;
	
	if (!rdma_present) {
		rdma_present = 1;
	} else {
		ERROR_MSG("%s: RDMA registers busy. \n", __FUNCTION__);
		ret = -EBUSY;
		goto rdma_init_failed;
	}
	init_regs();
	if (HAS_MACHINE_L_SIC) {
		if (!num_possible_rdmas()) {
			ERROR_MSG("%s: hard rdma is absent\n", __FUNCTION__);
			rdma_present = 0;
			ret = -ENODEV;
			goto rdma_init_failed_0;
		}
		/*
		 *  Not hot plugging
		 */
		if (!num_online_rdmas()) {
			ERROR_MSG("%s: RDMA does not support hot plugging."
				  "Connect the cable and reboot machine.\n",
				  __FUNCTION__);
			rdma_present = 0;
			ret = -ENODEV;
			goto rdma_init_failed_0;
		}
	}
	INFO_MSG("I am worked on CUBIC, NODE_NUMIOLINKS: %d "
		 "MAX_NUMIOLINKS: %d\n", RDMA_NODE_IOLINKS,
		 RDMA_MAX_NUMIOLINKS);
	if (num_buf >  RDMA_BUF_NUM) {
		ERROR_MSG("%s: num_buf(%d) > max_buf(%d).\n", __FUNCTION__,
			  num_buf, RDMA_BUF_NUM);
		rdma_present = 0;
		ret = -EINVAL;
		goto rdma_init_failed_0;
	}
	if (!tm_mode) {
		if (max_size_buf > MAX_SIZE_BUFF) {
			ERROR_MSG("%s: max_size_buf(0x%x) > MAX_SIZE_BUFF(0x%x).\n",
				  __FUNCTION__, max_size_buf, MAX_SIZE_BUFF);
			rdma_present = 0;
			ret = -ENOMEM;
			goto rdma_init_failed_0;
		}
	} else {
		if (max_size_buf_tm > MAX_SIZE_BUFF_TM) {
			ERROR_MSG("%s: max_size_buf_tm(0x%x) > MAX_SIZE_BUFF_TM(0x%x).\n",
				  __FUNCTION__, max_size_buf_tm, MAX_SIZE_BUFF_TM);
			rdma_present = 0;
			ret = -ENOMEM;
			goto rdma_init_failed_0;
		}
	}
#if 0	
	if (!tm_mode) {
		if ((max_size_buf * num_buf ) > LIMIT_SIZE_BUFF){
			ERROR_MSG("%s: The large size of the buffer. "
				  "The buffer must be: max_size_buf * "
				  "num_buf <= 0x%08x. \n", 
				  __FUNCTION__, LIMIT_SIZE_BUFF);
			rdma_present = 0;
			ret = -EINVAL;
			goto rdma_init_failed;
		}
	}
#endif
	INFO_MSG("Table mode: %s\n", tm_mode ? "set" : "unset");
	INFO_MSG("Number buffers: %d\n", num_buf);
	if (tm_mode)
		INFO_MSG("Max size buffer in table mode : 0x%x\n",
			 max_size_buf_tm);
	else 
		INFO_MSG("Max size buffer: 0x%x\n", max_size_buf);
	INFO_MSG("Align row in table: 0x%x\n", align_buf_tm);
	INFO_MSG("Your node alloc memory: %s\n", node_mem_alloc ? "yes" : "no");
	INFO_MSG("Type create device: %s\n", "sysfs");
	rdma_event_init = 1;
	INFO_MSG("Print event's mode: %s\n", ev_pr ? "set" : "unset");
	node = numa_node_id();
	fix_event(node, RDMA_INIT, START_EVENT, 0);
	major = register_chrdev(0, board_name, &rdma_fops);
	if ( major < 0 ) {
		ERROR_MSG("%s: There isn't free major\n", __FUNCTION__);
		rdma_present = 0;
		ret = -EINVAL;
		goto rdma_init_failed_0;
	}
	RDMA_INIT_DEBUG_MSG("%s: major: %d\n", __FUNCTION__, major);
	RDMA_INIT_DEBUG_MSG("%s: I am on %d numa_node_id\n", __FUNCTION__,
			    node);
	RDMA_INIT_DEBUG_MSG("%s: %lx: sizeof (nodemask_t)\n", __FUNCTION__,
			    sizeof (nodemask_t));
	size_rdma_state = sizeof (struct rdma_state);
	rdma_state = (struct rdma_state *)kmalloc(size_rdma_state, GFP_KERNEL);
	if (rdma_state == (struct rdma_state *)NULL) {
		ERROR_MSG("%s: rdma_state == NULL\n", __FUNCTION__);
		unregister_chrdev(major, board_name);
		rdma_present = 0;
		ret = -ENOMEM;
		goto rdma_init_failed_0;
	}
	memset(rdma_state, 0, size_rdma_state);
	RDMA_INIT_DEBUG_MSG("%s: sizeof (struct rdma_state): 0x%016lx\n",
			    __FUNCTION__, size_rdma_state);
	rdma_state->size_rdma_state = size_rdma_state;
	rdma_state->major = major;
#ifdef MODULE
	if (create_dev_mokx(major))
		ERROR_MSG("%s: Error creating devices. "
			  "Create a device manually.", __FUNCTION__);
#endif
	/*
	 * Set atl (rezerv)
	 */
#if 0	
	tr_atl = ATL_B | (atl_v & ATL);
	INFO_MSG("Reg CAM ATL: %x\n", tr_atl);
#endif
	/*
	 * While memory alloceted boot time
	 */
#if 0
#ifdef CONFIG_RDMA_BOOT_MEM_ALLOC
	if (R_M_NODE) {
		INFO_MSG("%s: check alloc bootmem R_M: %x\n",
			 __FUNCTION__, R_M_NODE);
		if ((long)R_M_NODE < (long)(PAGE_ALIGN(max_size_buf) * num_buf)) {
			ERROR_MSG("%s: Error alloc bootmem for rdma. "
				  "R_M(%x) < max_size_buf * num_buf(%x)\n",
				  __FUNCTION__, R_M_NODE,
				  PAGE_ALIGN(max_size_buf) * num_buf);
			ret = -ENOMEM;
			goto rdma_init_failed;
		}
	}
#endif
#endif
#ifdef RESET_DMA_MEMMORY
	reset_size_r = allign_dma(0x2000000);
	reset_size_w = allign_dma(0x1000);
	reset_order_r = get_order(reset_size_r);
	reset_order_w = get_order(reset_size_w);
	reset_dma_memory_r = __get_free_pages_rdma(0, GFP_KERNEL , reset_order_r, 0);
	reset_dma_memory_w = __get_free_pages_rdma(0, GFP_KERNEL , reset_order_w, 0);
#endif
	/*
	 * Init link and memory
	 */
	if (HAS_MACHINE_L_SIC) {
		for_each_online_rdma(link) {
			set_id_link(link);
			rdma_link_init(link);
#ifdef ALLOC_MEM_DRIVER
			if (bufs_init(link))
				goto rdma_init_failed;
#endif
		}
	}
	/*
	 * Register's interrupt
	 */
	rdma_interrupt_p = rdma_interrupt;
	/*
	 * Native mode
	 */
	for_each_online_rdma(link) {
		rdma_state_link_t *rdma_link;
		rdma_link = &rdma_state->rdma_link[link];
		int err = 0, res = 0;
		
		res = mok_x_set_native_mode(link, &err);
		printk("%s: link init: %d res: %d err: %d\n", 
		       __FUNCTION__, link, res, err);
		//null_change(link);
	}
	return 0;
rdma_init_failed:
	rdma_cleanup();
rdma_init_failed_0:	
	RDMA_INIT_DEBUG_MSG("%s: FINISH\n", __FUNCTION__);
	return -ENODEV;
}

#define RDMA_CLEANUP_DBG 0
#define RDMA_CLEANUP_DEBUG_MSG(x...)\
		if (RDMA_CLEANUP_DBG) DEBUG_MSG(x)
static void rdma_cleanup(void)
{
	rdma_state_link_t *rdma_link;
	int link, major;
	
	major = (int)rdma_state->major;
	RDMA_CLEANUP_DEBUG_MSG("%s: START rdma_state->major %d\n", __FUNCTION__, 
			       major);
	if (HAS_MACHINE_L_SIC)
		for_each_online_rdma(link) {
			set_mask(link, MASK_INTERRUPT_NULL);
			bufs_free(link);
#if RESET_THREAD_DMA
			thread_reset_stop(link);
#endif
			rdma_link = &rdma_state->rdma_link[link];
			rdma_link->mok_x_mode_link = STATE_LINK_DEFAULT; 
		}
	rdma_interrupt_p = (void *) NULL;
#ifdef MODULE
	remove_dev_mokx(major);
#endif
	unregister_chrdev(rdma_state->major, board_name);
	rdma_event_init = 0;
	kfree(rdma_state);
	if (rdma_present)
		rdma_present = 0;
#ifdef RESET_DMA_MEMMORY
	if (reset_dma_memory_r)
		free_pages(reset_dma_memory_r, reset_order_r);
	if (reset_dma_memory_w)
		free_pages(reset_dma_memory_w, reset_order_w);
#endif	
	RDMA_CLEANUP_DEBUG_MSG("%s:  FINISH\n", __FUNCTION__);
	return;
}

#define RDMA_CLOSE_DBG 0
#define RDMA_CLOSE_DEBUG_MSG(x...)\
		if (RDMA_CLOSE_DBG) DEBUG_MSG(x)
static int rdma_close(struct inode *inode, struct file *file)
{
	rdma_state_link_t *rdma_link;
	dev_rdma_sem_t *dev_sem;
	rw_state_t *rdma_private_data;
	rw_state_p pd;
	unsigned long flags, flags_w, flags_r;
	int minor, file_eys = 0, i;
	int link, file_open_mode;

	/* TODO Сделать все красиво через rdma_private_data */
	RDMA_CLOSE_DEBUG_MSG("%s: START\n", __FUNCTION__);
	minor = MINOR(inode->i_rdev);
	if (minor < 0) {
		ERROR_MSG("%s: minor(%d) < 0\n", __FUNCTION__, minor);
		return (-EINVAL);
	}
	link = DEV_inst(minor);
	if (HAS_MACHINE_L_SIC) {
		for_each_online_rdma(i)
			if (i == link)
				file_eys++;
	} else {
		if (0 == link)
			file_eys++;
	}
	if (!file_eys) {
		ERROR_MSG("%s: link %d not support RDMA\n", __FUNCTION__, 
			  link);
		return (-EINVAL);
	}
	rdma_link = &rdma_state->rdma_link[link];
	file_open_mode = minor % 2; 
	rdma_private_data = &rdma_link->rw_states_d[file_open_mode];
	RDMA_CLOSE_DEBUG_MSG("%s: mode close %s (minor: 0x%08x)\n", 
			     __FUNCTION__, file_open_mode ? "WRITE" : "READ", minor);
	mutex_enter(&rdma_link->mu);
	rdma_link->opened &= ~(1 << rdma_private_data->open_mode);
	rdma_private_data->open_mode = 0;
	file->private_data = NULL;
	RDMA_CLOSE_DEBUG_MSG("%s: opened.minor.link.channel: 0x%x.%d.%d.%d\n",
			    __FUNCTION__, rdma_link->opened, minor, link, 
       			    rdma_private_data->open_mode);
	mutex_exit(&rdma_link->mu);
	
	pd = &rdma_link->rw_states_d[file_open_mode];
	dev_sem = &pd->dev_rdma_sem;
	
	/*
	 * File open as READER
	 */
	if (!file_open_mode) {
		rdma_pool_buf_t	*r_pool_buf;
		unsigned int ret_wait_rdc;
		unsigned int sending_msg;
		unsigned int ret_smsg;
		int count_wait_rdc = TX_RX_WAIT_DMA;
		
		r_pool_buf = &rdma_link->read_pool;
		/*
		 * Unset mode4
		 */
		
		
		if (rdma_link->mok_x_mode_link == STATE_LINK_ONLY_RECIVE) {
			unsigned int tmp_reg;
			
			raw_spin_lock_irqsave(&dev_sem->lock, flags);
			rdma_link->generator_stop = 1;
			raw_spin_unlock_irqrestore(&dev_sem->lock, flags);
			mdelay(1000);
			WRR_rdma(SHIFT_IRQ_MC, link , 0x0);
			mdelay(1000);
			//mok_x_unset_mode4(link);
			//get_event_rdma(1);
			//WRR_rdma(SHIFT_IRQ_MC, link , 0x0);
			//INFO_MSG("%s: Stop generator. Stack reg.\n",
			//	 __FUNCTION__);
			//read_regs_rdma(link);
			tmp_reg = RDR_rdma(SHIFT_ES, link);
			WRR_rdma(SHIFT_ES, link, tmp_reg & ES_RDC_Ev);
			//WRR_rdma(SHIFT_IRQ_MC, link ,irq_mc);
			
			tmp_reg = RDR_rdma(SHIFT_DMA_RCS, link);
			WRR_rdma(SHIFT_DMA_RCS, link, tmp_reg & (~DMA_RCS_RE));
			//WRR_rdma(SHIFT_DMA_RBC, link, 0x0);
			RDMA_CLOSE_DEBUG_MSG("%s: link %d reset recive. RCS: 0x%08x "
				 "RBC: 0x%08x\n", __FUNCTION__, link,
				 RDR_rdma(SHIFT_DMA_RCS, link),
				 RDR_rdma(SHIFT_DMA_RBC, link));
			null_change(link);
			rdma_link->mok_x_mode_link = STATE_LINK_NATIVE;
			WRR_rdma(SHIFT_IRQ_MC, link ,irq_mc);
		} else {
			//INFO_MSG("%s: Stop VK-VK. Stack reg.\n",
			//	 __FUNCTION__);
			//read_regs_rdma(link);
			;;
		}
#ifdef UNX_TRWD
		raw_spin_lock_irqsave(&dev_sem->lock, flags);
		rdma_link->unexpected_trwd_size = 0x0;
		rdma_link->unexpected_trwd = 0x0;
		raw_spin_unlock_irqrestore(&dev_sem->lock, flags);
#endif		
		/*
		 * Reciver wait dma
		 */ 
		while (count_wait_rdc--) {
			ret_wait_rdc = RDR_rdma(SHIFT_DMA_RCS, link);
			if (!(ret_wait_rdc & DMA_RCS_RE)) {
				goto end_wait_rdc;
			}
		}
		ERROR_MSG("%s: link %d ret_wait_rdc: 0x%08x "
			  "count_wait_rdc: %d\n", __FUNCTION__, link,
			  ret_wait_rdc, count_wait_rdc);
		
end_wait_rdc:
		raw_spin_lock_irqsave(&pd->lock_rd, flags_r);
		/*
		 * The release of buffers
		*/
		while (!list_empty(&r_pool_buf->ready_list)) {
			list_move_tail(r_pool_buf->ready_list.next, 
				       &r_pool_buf->free_list);
		}
		while (!list_empty(&r_pool_buf->busy_list)) {
			list_move_tail(r_pool_buf->busy_list.next, 
				       &r_pool_buf->free_list);
		}
		r_pool_buf->num_free_buf = 0;
		raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
		/*
		 * Send READY_DMA
		 */
		if (rdma_link->mok_x_mode_link != STATE_LINK_ONLY_RECIVE) {
			sending_msg = MSG_READY_DMA | r_pool_buf->num_free_buf;
			if ((ret_smsg = send_msg_check(sending_msg, link, 0, 
			     dev_sem, 0)) <= 0) {
				     fix_event(link, READ_SNDMSGBAD_EVENT,
					       sending_msg, dev_sem->num_obmen);
			} else {
				     fix_event(link, READ_SNDNGMSG_EVENT,
					       sending_msg, dev_sem->num_obmen);
			}
		}
#ifdef UNX_TRWD
		//printk("%s: REPEAT_TRWD: %x\n", __FUNCTION__, REPEAT_TRWD);
#endif
	} else {
		/*
		 * File open as WRITER
		 */
		rdma_pool_buf_t	*w_pool_buf;
		unsigned int	ret_wait_tdc;
		int	count_wait_tdc = TX_RX_WAIT_DMA;
		
		w_pool_buf = &rdma_link->write_pool;
		/*
		 * Sender wait dma
		 */
		while (count_wait_tdc--)
		{	
			ret_wait_tdc = RDR_rdma(SHIFT_DMA_TCS, link);
			if (!(ret_wait_tdc & DMA_TCS_TE)) {
				     goto end_wait_tdc;
			}
		}
		ERROR_MSG("%s: link %d ret_wait_tdc: 0x%08x count_wait_tdc: %d\n", 
			  __FUNCTION__, link, ret_wait_tdc, count_wait_tdc);	
end_wait_tdc:		
		raw_spin_lock_irqsave(&pd->lock_wr, flags_w);
		/*
		 * The release of buffers
		*/
		while (!list_empty(&w_pool_buf->ready_list)) {
			list_move_tail(w_pool_buf->ready_list.next, 
		       &w_pool_buf->free_list);
		}
		while (!list_empty(&w_pool_buf->busy_list)) {
			list_move_tail(w_pool_buf->busy_list.next, 
				       &w_pool_buf->free_list);
		}
		raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
		//printk("rdma_link->trwd_lock_err: %x\n", 
		//       rdma_link->trwd_lock_err);
	}
#if 0	
#ifdef SET_ENABLE_RECEIVE_BIT	
	/**
	 * Set enable recieve after reset
	 */
#ifndef SETTING_OVER_INTERRUPT
	WRR_rdma(SHIFT_IRQ_MC, link , 0x0);
#endif
	set_mode_native(link);
	//udelay(1000);
#ifndef SETTING_OVER_INTERRUPT
	WRR_rdma(SHIFT_IRQ_MC, link ,irq_mc);
#endif
#endif
#endif
	raw_spin_lock_irqsave(&dev_sem->lock, flags);
	pd->state_open_close = 0;
	raw_spin_unlock_irqrestore(&dev_sem->lock, flags);
	RDMA_CLOSE_DEBUG_MSG("%s: FINISH\n", __FUNCTION__);
	return 0;
}

#define RDMA_OPEN_DBG 0
#define RDMA_OPEN_DEBUG_MSG(x...)\
		if (RDMA_OPEN_DBG) DEBUG_MSG(x)
static int rdma_open(struct inode *inode, struct file *file)
{
	rdma_state_link_t *rdma_link;
	rw_state_t *rdma_private_data;
	dev_rdma_sem_t *dev_sem;
	rw_state_p pd;
	unsigned long flags, flags_w, flags_r;
	int minor, file_eys = 0, i, file_open_mode;
	int link;
	int firstopen = 0;
	/* TODO Сделать все красиво через rdma_private_data */
	RDMA_OPEN_DEBUG_MSG("%s: START\n",  __FUNCTION__);
	if (file == (struct file *)NULL) {
		ERROR_MSG("%s: file is NULL\n", __FUNCTION__);
		return (-EINVAL);
	}
 	minor = MINOR(inode->i_rdev);
	if (minor < 0) {
		ERROR_MSG("%s: minor(%d) < 0\n", __FUNCTION__, minor);
		return (-EINVAL);
	}
	link = DEV_inst(minor);
	if (HAS_MACHINE_L_SIC) {
		for_each_online_rdma(i)
			if (i == link)
				file_eys++;
	} else {
		if (0 == link)
			file_eys++;
	}
	if (!file_eys) {
		ERROR_MSG("%s: link %d not support RDMA\n", __FUNCTION__, 
				link);
		return (-EINVAL);
	}
	file->private_data = NULL;
	rdma_link = &rdma_state->rdma_link[link];
	/*
	 * File open mode.
	 */
	file_open_mode = minor % 2; 
	rdma_private_data = &rdma_link->rw_states_d[file_open_mode];
	rdma_private_data->open_mode = file_open_mode;
	RDMA_OPEN_DEBUG_MSG("%s: mode open %s (minor: %x)\n", 
			     __FUNCTION__, file_open_mode ? "WRITE" : "READ", minor);
	rdma_private_data->link = link;
	file->private_data = rdma_private_data;
	mutex_enter(&rdma_link->mu);
	firstopen = (((1 << rdma_private_data->open_mode) & rdma_link->opened) == 0);
	if (firstopen == 0) {
		ERROR_MSG("%s: device EBUSY: minor: %d link: %d channel: %d\n", 
			  __FUNCTION__, minor, link, rdma_private_data->open_mode);
		mutex_exit(&rdma_link->mu);
		return (-EBUSY);
	}
	rdma_link->opened |= (1 << rdma_private_data->open_mode);
	RDMA_OPEN_DEBUG_MSG("%s: opened.minor.link.channel: 0x%x.%d.%d.%d\n",
				__FUNCTION__, rdma_link->opened, minor, link, 
				rdma_private_data->open_mode);
	mutex_exit(&rdma_link->mu);
	pd = &rdma_link->rw_states_d[file_open_mode];
	dev_sem = &pd->dev_rdma_sem;
	raw_spin_lock_irqsave(&dev_sem->lock, flags);
	pd->state_open_close = 1;

#ifdef SET_ENABLE_RECEIVE_BIT	
	/**
	 * Set enable recieve after reset
	 */
#ifndef SETTING_OVER_INTERRUPT
	WRR_rdma(SHIFT_IRQ_MC, link , 0x0);
#endif
	set_mode_native(link);
	//udelay(1000);
#ifndef SETTING_OVER_INTERRUPT
	WRR_rdma(SHIFT_IRQ_MC, link ,irq_mc);
#endif
#endif	
	/*
	 * File opened as READER
	 */
	if (!file_open_mode) {
		rdma_pool_buf_t *r_pool_buf;
		unsigned int sending_msg;
		unsigned int ret_smsg, ret_wait_rdc;
		int count_wait_rdc = TX_RX_WAIT_DMA;
		
		pd->first_open++;
		rdma_link->generator_stop = 0;
		raw_spin_unlock_irqrestore(&dev_sem->lock, flags);
		
		r_pool_buf = &rdma_link->read_pool;
		raw_spin_lock_irqsave(&pd->lock_rd, flags_r);
		r_pool_buf->num_free_buf = rdma_link->num_buf;
		/*
		 * The release of buffers
		 */
		while (!list_empty(&r_pool_buf->ready_list)) {
			list_move_tail(r_pool_buf->ready_list.next, 
				       &r_pool_buf->free_list);
		}
		while (!list_empty(&r_pool_buf->busy_list)) {
			list_move_tail(r_pool_buf->busy_list.next, 
				       &r_pool_buf->free_list);
		}
		raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
#ifdef RESET_DMA_MEMMORY
		/*
		 * Reset dma
		 */
		//null_change(link);
#endif		
		/*
		 * Waiting for the end of the last dma
		 */
		while (count_wait_rdc --) {
			ret_wait_rdc = RDR_rdma(SHIFT_DMA_RCS, link);
			if (!(ret_wait_rdc & DMA_RCS_RE)) {
				goto end_wait_rdc;
			}
		}
		/**
		 * TODO. Error.
		 */
		ERROR_MSG("%s: link %d ret_wait_rdc: 0x%08x "
			  "count_wait_rdc: %d\n", __FUNCTION__, link,
			  ret_wait_rdc, count_wait_rdc);
end_wait_rdc:;
		/*
		 * Create MSG_READY_DMA
		 */
		sending_msg = MSG_READY_DMA |
			      r_pool_buf->num_free_buf;
		/*
		 * Send MSG_READY_DMA
		 */
		if ((ret_smsg = send_msg_check(sending_msg,
		     link, 0, dev_sem, 0)) <= 0) {
			fix_event(link,
				  READ_SNDMSGBAD_EVENT,
				  sending_msg,
				  dev_sem->num_obmen);
		} else {
			fix_event(link,
				  READ_SNDNGMSG_EVENT,
				  sending_msg,
				  dev_sem->num_obmen);
		}
#ifdef UNX_TRWD
		REPEAT_TRWD = 0;
		//printk("%s: REPEAT_TRWD: %x\n", __FUNCTION__, REPEAT_TRWD);
#endif
	} else {
		/*
		 * File opened as WRITER
		 */
		rdma_pool_buf_t	*w_pool_buf;
		unsigned int	ret_wait_tdc;
		int	count_wait_tdc = TX_RX_WAIT_DMA;
		
		rdma_link->trwd_lock_err = 0;	
		raw_spin_unlock_irqrestore(&dev_sem->lock, flags);
		
		w_pool_buf = &rdma_link->write_pool;
		/*
		 * The release of buffers
		 */
		raw_spin_lock_irqsave(&pd->lock_wr, flags_w);
		while (!list_empty(&w_pool_buf->ready_list)) {
			list_move_tail(w_pool_buf->ready_list.next, 
				       &w_pool_buf->free_list);
		}
		while (!list_empty(&w_pool_buf->busy_list)) {
			list_move_tail(w_pool_buf->busy_list.next, 
				       &w_pool_buf->free_list);
		}
		raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
		/* 
		 * Waiting for the end of the last dma 
		 */
		while (count_wait_tdc--)
		{	
			ret_wait_tdc = RDR_rdma(SHIFT_DMA_TCS, link);
			if (!(ret_wait_tdc & DMA_TCS_TE)) {
				goto end_wait_tdc;
			}
		}
		/**
		 * TODO. Error.
		 */
		ERROR_MSG("%s: link %d ret_wait_tdc: 0x%08x count_wait_tdc: %d\n", 
			  __FUNCTION__, link, ret_wait_tdc, count_wait_tdc);	
end_wait_tdc:;
	}
	RDMA_OPEN_DEBUG_MSG("%s: FINISH\n", __FUNCTION__);
	return 0;
}

#define RDMA_READ_DBG 0
#define RDMA_READ_DEBUG_MSG(x...)\
		if (RDMA_READ_DBG) DEBUG_MSG(x)
static ssize_t rdma_read(struct file *filp, char __user *buf, size_t size,
			 loff_t *pos)
{
	RDMA_READ_DEBUG_MSG("%s: read call is not supported!", __FUNCTION__);
	return 0;
}

#define RDMA_WRITE_DBG 0
#define RDMA_WRITE_DEBUG_MSG(x...)\
		if (RDMA_WRITE_DBG) DEBUG_MSG(x)
static ssize_t rdma_write(struct file *filp, const char __user *buf, 
			  size_t size, loff_t *pos)
{
	RDMA_READ_DEBUG_MSG("%s: write call is not supported!", __FUNCTION__);
	return 0;
}

#define RDMA_IOCTL_DBG 0
#define RDMA_IOCTL_DEBUG_MSG(x...)\
		if (RDMA_IOCTL_DBG) DEBUG_MSG(x)
#define IOC_SUCCESFULL 0
#define IOC_FAIL -1

static long rdma_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	rdma_state_link_t *rdma_link;
	rdma_ioc_parm_t	parm;
	dev_rdma_sem_t *dev_sem;
	rw_state_t *rdma_private_data;
	rw_state_p pd;
	size_t rval;
	//unsigned long flags, flags_w, flags_r;
	unsigned long flags_w, flags_r;
	unsigned int open_mode;
	int ret = IOC_SUCCESFULL; 
	int minor;
	int link;
	int res = 0;
	
	minor = get_file_minor(filp);
	if (minor < 0) {
		ERROR_MSG("%s: minor(%d) < 0 cmd: 0x%08x\n", __FUNCTION__, 
			  (int)minor, cmd);
		return minor;
	}
	link = DEV_inst(minor);
	RDMA_IOCTL_DEBUG_MSG("%s: link: %d cmd: 0x%08x. START\n", __FUNCTION__, 
			     link, cmd);
	rdma_link = &rdma_state->rdma_link[link];
	rval = copy_from_user(&parm, (void __user *)arg, 
			       sizeof (rdma_ioc_parm_t));
	if (rval) {
		ERROR_MSG("%s: link: %d cmd: 0x%08x. Copy_from_user failed.\n", 
			  __FUNCTION__, link, cmd);
		ret = -EINVAL;
	}
	RDMA_IOCTL_DEBUG_MSG("%s: in :\n"
			     "	parm.reqlen: 0x%08x\n"
			     "	parm.acclen: 0x%08x\n"
			     "	parm.err_no: 0x%08x\n"
			     "	parm.rwmode: 0x%08x\n"
			     "	parm.msg   : 0x%08x\n"
			     "	parm.clkr  : %llx\n"
			     "	parm.clkr1 : %llx\n"
			     "	parm.type_mode : 0x%08x\n"
			     "	parm.type_oper : 0x%08x\n"
			     "	parm.reg_addr0 : 0x%08x\n"
			     "	parm.reg_addr1 : 0x%08x\n"
			     "	parm.reg_addr2 : 0x%08x\n"
			     "	parm.reg_data  : 0x%08x\n",
			     __FUNCTION__, parm.reqlen,
			     parm.acclen, parm.err_no, parm.rwmode, parm.msg,
			     parm.clkr, parm.clkr1, parm.type_mode,
			     parm.type_oper,  parm.reg_addr0, parm.reg_addr1,
			     parm.reg_addr2, parm.reg_data);
	
	rdma_private_data = filp->private_data;
	open_mode = rdma_private_data->open_mode;
	parm.err_no = res = 0;
	
	switch (cmd) {
	case RDMA_IOC_GET_neighbour_map:
	{
		if (copy_to_user((void __user *)arg, &node_online_neighbour_map, 
		    sizeof (nodemask_t))) {
			ERROR_MSG("%s: link %d cmd: RDMA_IOC_GET_neighbour_map "
					"copy_to_user failed\n", __FUNCTION__, link);
			return -EINVAL;
		}
		return 0;
		break;
	}
	
	case RDMA_IOC_GET_ID:
	{
		int i;
		rdma_link_id.count_links = MAX_NUMIOLINKS;
		if (HAS_MACHINE_L_SIC) {
			for_each_online_rdma(i) {
				rdma_link_id.link_id[i][0] = 1;
				rdma_link_id.link_id[i][1] = RDR_rdma(SHIFT_CH_IDT, i);
				rdma_link_id.link_id[i][2] = RDR_rdma(SHIFT_N_IDT, i);
			}
		} else { 
			i = 0;
			rdma_link_id.link_id[i][0] = 1;
			rdma_link_id.link_id[i][1] = RDR_rdma(SHIFT_CH_IDT, i);
			rdma_link_id.link_id[i][2] = RDR_rdma(SHIFT_N_IDT, i);
		}
		if (copy_to_user((void __user *)arg, &rdma_link_id, 
		    sizeof(link_id_t)) == -1) {
			ERROR_MSG("%s:RDMA_IOC_GET_ID: copy_to_user failed\n", 
				      __FUNCTION__);
			return EINVAL;
		}
		return 0;
		break;
	}
#if 0	
	case RDMA_SET_ATL:
	{
		unsigned int atl;

		tr_atl = ATL_B | (parm.reqlen & ATL);
		WRR_rdma(SHIFT_CAM, link, tr_atl);
		atl = RDR_rdma(SHIFT_CAM, link);
		parm.acclen = atl;
		break;
	}
#endif		
	case RDMA_IOC_GET_BUF_NUM:
	{
		parm.acclen = rdma_link->num_buf;
		ret = IOC_SUCCESFULL;
		break;
	}
	
	case RDMA_IOC_SET_BUF_NUM:
	{
		if (parm.reqlen <= RDMA_BUF_NUM) {
			rdma_link->num_buf = parm.reqlen;
			parm.acclen = rdma_link->num_buf;
			ret = IOC_SUCCESFULL;
		} else {
			parm.acclen = RDMA_BUF_NUM;
			ret = IOC_FAIL;
		}
		break;
	}
		
	
	case RDMA_IOC_GET_TM_MODE:
	{
		parm.acclen = rdma_link->tm_mode;
		ret = IOC_SUCCESFULL;
		break;
	}

	case RDMA_IOC_SET_TM_MODE:
	{
		rdma_link->tm_mode = parm.reqlen;
		parm.acclen = rdma_link->tm_mode;
		ret = IOC_SUCCESFULL;
		break;
	}
	
	case RDMA_IOC_GET_ALIGN_BUF_TM:
	{
		parm.acclen = rdma_link->align_buf_tm;
		ret = IOC_SUCCESFULL;
		break;
	}
	
	case RDMA_IOC_GET_PAGE_SIZE:
	{
		parm.acclen = PAGE_SIZE;
		ret = IOC_SUCCESFULL;
		break;
	}

	case RDMA_IOC_SET_ALIGN_BUF_TM:
	{
		rdma_link->align_buf_tm = parm.reqlen;
		parm.acclen = rdma_link->align_buf_tm;
		ret = IOC_SUCCESFULL;
		break;
	}
	
	case RDMA_IOC_GET_NODE_MEM_ALLOC:
	{
		parm.acclen = rdma_link->node_mem_alloc;
		ret = IOC_SUCCESFULL;
		break;
	}

	case RDMA_IOC_SET_NODE_MEM_ALLOC:
	{
		rdma_link->node_mem_alloc = parm.reqlen;
		parm.acclen = rdma_link->node_mem_alloc;
		ret = IOC_SUCCESFULL;
		break;
	}
	
	case RDMA_IOC_GET_MAX_SIZE_BUFF:
	{
		parm.acclen = rdma_link->max_size_buf;
		ret = IOC_SUCCESFULL;
		break;
	}

	case RDMA_IOC_SET_MAX_SIZE_BUFF:
	{
		if ((max_size_buf * num_buf ) > LIMIT_SIZE_BUFF) {
			parm.acclen = LIMIT_SIZE_BUFF;
		} else {
			rdma_link->max_size_buf = parm.reqlen;
			parm.acclen = rdma_link->max_size_buf;
			ret = IOC_SUCCESFULL;
		}
		break;
	}
	case RDMA_IOC_GET_MAX_SIZE_BUFF_TM:
	{
		parm.acclen = rdma_link->max_size_buf_tm;
		ret = IOC_SUCCESFULL;
		break;
	}

	case RDMA_IOC_SET_MAX_SIZE_BUFF_TM:
	{
		rdma_link->max_size_buf_tm = parm.reqlen;
		parm.acclen = rdma_link->max_size_buf;
		ret = IOC_SUCCESFULL;
		break;
	}
	
	case RDMA_IOC_GET_BUF_SIZE:
	{
		parm.acclen = rdma_link->buf_size;
		ret = IOC_SUCCESFULL;
		break;
	}
	
	case RDMA_IOC_ALLOC_TYPE:
	{
#ifdef CONFIG_RDMA_BOOT_MEM_ALLOC
		parm.acclen = R_M_NODE;
#else		
		parm.acclen = 0;
#endif
		ret = IOC_SUCCESFULL;
		break;
	}
	
	case RDMA_IOC_MEMRY_ALLOC:
	{
		/**
		 * parm.reqlen = size;	// max_size_buf
		 * parm.reqlen1 = 4;	// num buf
		 * parm.reqlen2 = 1;	// tm mode
		 * parm.reqlen3 = 1;	// num PAGE_SIZE in row table
		 * parm.reqlen4 = 0;	// alloc memory our node
		 *parm.reqlen5 = 0;	// type alloc
		 */	
		bufs_free(link);
		rdma_link->type_alloc = parm.reqlen5;
		if (rdma_link->type_alloc) {
			rdma_link->max_size_buf = parm.reqlen;
			rdma_link->num_buf = parm.reqlen1;
		} else {
			rdma_link->num_buf = parm.reqlen1;
			rdma_link->tm_mode = parm.reqlen2;
			if (rdma_link->tm_mode) {
				rdma_link->max_size_buf_tm = parm.reqlen;
			} else {
				rdma_link->max_size_buf = parm.reqlen;
			}
			rdma_link->align_buf_tm = parm.reqlen3;
			rdma_link->node_mem_alloc = parm.reqlen4;
		}
		if (!bufs_init(link)) {
			parm.acclen = rdma_link->buf_size;
			ret = IOC_SUCCESFULL;
		} else {
			bufs_free(link);
			parm.acclen = 0;
			ret = IOC_FAIL;
		}
		break;
	}
	
	case RDMA_IOC_SET_MODE_RFSM:
	{
		if (parm.reqlen == DISABLE_RFSM) {
			rfsm = CLEAR_RFSM;
		} else {
			rfsm = DMA_RCS_RFSM;
		}
		parm.acclen = rfsm;
		break;
	}
	
	case RDMA_IOC_GET_WR_BUF:
	{
		rdma_pool_buf_t *w_pool_buf;
		rdma_buf_t *w_buf;
		
		if (open_mode == READER) {
			ERROR_MSG("%s: link: %d cmd: RDMA_IOC_GET_WR_BUF. "
				  "File open as READER.\n", __FUNCTION__, link);
			ret = -EBADF;
			break;
		}
		w_pool_buf = &rdma_link->write_pool;
		pd = &rdma_link->rw_states_d[WRITER];
		/*
		 * Search free buffer to write
		 */
		raw_spin_lock_irqsave(&pd->lock_wr, flags_w);
		if (list_empty(&w_pool_buf->free_list)) {
			raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_GET_WR_BUF(0x%08x). "
				  "Search free for write buf failed.\n",
     				  __FUNCTION__, link, cmd);
			ret = -EBUSY;
			break;
		}
		w_buf = list_entry(w_pool_buf->free_list.next, rdma_buf_t,
				   list);
		list_move_tail(&w_buf->list, &w_pool_buf->ready_list);
		raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
		parm.acclen = w_buf->num;
		ret = IOC_SUCCESFULL;
		break;
	}
	
	case RDMA_IOC_WR_BUF:
	{
		rdma_pool_buf_t *w_pool_buf;
		rdma_buf_t *w_buf; 

		if (open_mode == READER) {
			ERROR_MSG("%s: link: %d cmd: RDMA_IOC_WR_BUF(0x%08x). "
				  "File open as READER.\n", __FUNCTION__, link, cmd);
			ret = -EBADF;
			break;
		}
		w_pool_buf = &rdma_link->write_pool;
		pd = &rdma_link->rw_states_d[WRITER];
		/*
		 * Find user buffer
		 */
		raw_spin_lock_irqsave(&pd->lock_wr, flags_w);
		w_buf = search_in_list(&w_pool_buf->ready_list, parm.acclen);
		if (w_buf == NULL) {
			raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
			ERROR_MSG("%s: link: %d cmd: RDMA_IOC_WR_BUF(0x%08x). "
				  "Cant find buf.\n", __FUNCTION__, link, cmd);
			parm.err_no = RDMA_E_BAD_BUFFER;
			/*ret = -EAGAIN;*/
			ret = -EFAULT;
			break;
		}
        	/*
		 * Mark this buf as busy and place in the end of queue
		 */
		list_move_tail(&w_buf->list, &w_pool_buf->busy_list);
		w_pool_buf->work_buf = w_buf;
		raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
		/*
		 * Call write function's
		 */
		ret = write_buf(link, &parm, filp->f_flags);
#if 0		
		// Move ioctl RDMA_IOC_PUT_WR_BUF
		// /*
		//  * Remove buf from busy and move free list
		//  */
		// raw_spin_lock_irqsave(&pd->lock_wr, flags_w);
		// list_move_tail(&w_buf->list, &w_pool_buf->free_list);
		// w_pool_buf->work_buf = NULL;
		// raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
#endif		
		break;
	}

	case RDMA_IOC_PUT_WR_BUF:
	{
		rdma_pool_buf_t *w_pool_buf;
		rdma_buf_t *w_buf; 
		
		if (open_mode == READER) {
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_PUT_WR_BUF(0x%08x). "
				  "File open as READER.\n", __FUNCTION__,
				  link, cmd);
			ret = -EBADF;
			break;
		}
		if ( parm.acclen < 0 || parm.acclen > rdma_link->num_buf ) {
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_PUT_WR_BUF(0x%08x). "
				  "Wrong num buf: 0x%08x.\n", __FUNCTION__,
				  link, cmd, parm.acclen);
			ret = -ERANGE;
			break;
		}
		w_pool_buf = &rdma_link->write_pool;
		pd = &rdma_link->rw_states_d[WRITER];
		/*
		 * Remove buf from busy and move free list
		 */
		raw_spin_lock_irqsave(&pd->lock_wr, flags_w);
		w_buf = search_in_list(&w_pool_buf->busy_list, parm.acclen);
		if (w_buf == NULL) {
			raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_PUT_WR_BUF(0x%08x). "
				  "Cant find buf.\n", __FUNCTION__, link, cmd);
			ret = -EFAULT;
			break;
		}		
		list_move_tail(&w_buf->list, &w_pool_buf->free_list);
		w_pool_buf->work_buf = NULL;
		raw_spin_unlock_irqrestore(&pd->lock_wr, flags_w);
		ret = IOC_SUCCESFULL;
		break;
	}
		
	case RDMA_IOC_GET_RD_BUF:
	{
		rdma_pool_buf_t *r_pool_buf;
		rdma_buf_t *r_buf; 
		
		if (open_mode == WRITER) {
			ERROR_MSG("%s: link: %d cmd: RDMA_IOC_GET_RD_BUF. "
					"File open as WRITER.\n", __FUNCTION__,
					link);
			ret = -EBADF;
			break;
		}
		r_pool_buf = &rdma_link->read_pool;
		pd = &rdma_link->rw_states_d[READER];
		/*
		* Search free buffer to write
		*/
		raw_spin_lock_irqsave(&pd->lock_rd, flags_r);
		if (list_empty(&r_pool_buf->free_list)) {
			raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
			ERROR_MSG("%s: link: %d "
					"cmd: RDMA_IOC_GET_RD_BUF(0x%08x). "
					"Search free for read buf failed.\n",
					__FUNCTION__, link, cmd);
			ret = -EBUSY;
			break;
		}
		r_buf = list_entry(r_pool_buf->free_list.next, rdma_buf_t,
				   list);
		list_move_tail(&r_buf->list, &r_pool_buf->ready_list);
		raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
		parm.acclen = r_buf->num;
		ret = IOC_SUCCESFULL;
		break;
		
	}
	
	case RDMA_IOC_RD_BUF:
	{
		rdma_pool_buf_t *r_pool_buf;
		rdma_buf_t *r_buf; 
				
		if (open_mode == WRITER) {
			ERROR_MSG("%s: link: %d cmd: RDMA_IOC_RD_BUF(0x%08x). "
				  "File open as WRITER.", __FUNCTION__,
				  link, cmd);
			ret = -EBADF;
			break;
		}
		r_pool_buf = &rdma_link->read_pool;
		pd = &rdma_link->rw_states_d[READER];
		dev_sem = &pd->dev_rdma_sem;
		/*
		 * Call read function's
		 */
		ret = read_buf(link, &parm, filp->f_flags);
		if ( ret < 0)  {
			ERROR_MSG("%s: link: %d cmd: RDMA_IOC_RD_BUF(0x%08x). "
				  "Error read_buf.\n", __FUNCTION__, link, cmd);
			parm.acclen = -1;
			/*ret = -EAGAIN;*/
			break;
		}
		/*
		 * Time for reserve
		 */
		parm.clkr = join_curr_clock();
		/*
		 * Find user buffer
		 */
		raw_spin_lock_irqsave(&pd->lock_rd, flags_r);
		/*r_buf = list_entry(r_pool_buf->ready_list.next, rdma_buf_t, list);*/
		r_buf = list_entry(r_pool_buf->busy_list.next, rdma_buf_t, list);
		raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
		if (r_buf == NULL) {
			ERROR_MSG("%s: link: %d cmd: RDMA_IOC_RD_BUF(0x%08x). "
				  "Cant find buf. \n", __FUNCTION__, link, cmd);
			event_ioctl(link, READ_BAD2_EVENT, 0,
				   dev_sem->num_obmen);
			parm.acclen = -1;
			parm.err_no = RDMA_E_BAD_BUFFER;
			ret = -EFAULT;
			break;
		}
		if ( r_buf->num < 0 || r_buf->num > rdma_link->num_buf ) {
			ERROR_MSG("%s: link: %d cmd: RDMA_IOC_RD_BUF(0x%08x). "
				  "Wrong num buf: %d.\n", __FUNCTION__,
     				  link, cmd, r_buf->num);
			event_ioctl(link, READ_BAD3_EVENT, r_buf->num,
				   dev_sem->num_obmen);
			parm.acclen = r_buf->num;
			parm.err_no = RDMA_E_BAD_BUFFER;
			ret = -ERANGE;
			break;
		}
		parm.acclen = r_buf->num;
		/*
		 * Cleanup: join rfsm_size & r_buf->real_size.
		 */
		if (rfsm)
			parm.reqlen = r_buf->rfsm_size;
		else
			parm.reqlen = r_buf->real_size;
		break;
	}
	
	case RDMA_IOC_PUT_RD_BUF:
	{
		rdma_pool_buf_t *r_pool_buf;
		rdma_buf_t *r_buf;
		unsigned int sending_msg;
		int ret_smsg;

		if (open_mode == WRITER) {
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_PUT_RD_BUF(0x%08x). "
				  "File open as WRITER.", __FUNCTION__,
     				  link, cmd);
			ret = -EBADF;
			break;
		}
		if (parm.acclen < 0 || parm.acclen > rdma_link->num_buf) {
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_PUT_RD_BUF(0x%08x). "
				  "Wrong num buf: 0x%08x.\n", __FUNCTION__,
				  link, cmd, parm.acclen);
			ret = -ERANGE;
			break;
		}
		r_pool_buf = &rdma_link->read_pool;
		pd = &rdma_link->rw_states_d[READER];
		/*
		 * Find user buffer
		 */
		raw_spin_lock_irqsave(&pd->lock_rd, flags_r);
		r_buf = search_in_list(&r_pool_buf->busy_list, parm.acclen);
		if (r_buf == NULL) {
			raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_PUT_RD_BUF(0x%08x). "
				  "Cant find buf.\n", __FUNCTION__, link, cmd);
			ret = -EFAULT;
			break;
		}
        	/*
		 * Mark this buf as free and place in the end of queue
		 */
		list_move_tail(&r_buf->list, &r_pool_buf->free_list);
		if (!r_pool_buf->num_free_buf) {
			r_pool_buf->num_free_buf ++;
			if (rdma_link->mok_x_mode_link != STATE_LINK_ONLY_RECIVE) {
				/*
		 		 * Create MSG_READY_DMA 
				 */
				sending_msg = MSG_READY_DMA |
						r_pool_buf->num_free_buf;
				/*
				 * Send READY_DMA
				 */
				if ((ret_smsg = send_msg_check(sending_msg,
				     link, 0, 0, 0)) <= 0) {
					fix_event(link, READ_SNDMSGBAD_EVENT,
						  ret_smsg,
						  r_pool_buf->num_free_buf);
				} else {
					fix_event(link, READ_SNDNGMSG_EVENT,
						  ret_smsg,
						  r_pool_buf->num_free_buf);
				}
			}
		} else {
			r_pool_buf->num_free_buf ++;
		}
		if ((rdma_link->mok_x_mode_link == STATE_LINK_ONLY_RECIVE) &&
			(r_pool_buf->work_buf == NULL)) {
			mok_x_prog_recieve_dma(link, 0);
			if (rdma_link->mok_x_mode_number_link == MODE3_LINK) {
				/*
				 * Enable recive
				 */
				set_mok_x_SR_ready_to_receive(link);
			}
		}
		raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
		ret = IOC_SUCCESFULL;
		break;
	}
	
	case RDMA_IOC_SET_TIMEOUT_RD:
	{
		if (open_mode == WRITER) {
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_SET_TIMEOUT_RD(0x%08x). "
				  "File open as READER.\n", __FUNCTION__,
				  link, cmd);
			ret = -EBADF;
			break;
		}
		pd = &rdma_link->rw_states_d[READER];
		dev_sem = &pd->dev_rdma_sem;
		dev_sem->timeout = parm.reqlen;
		parm.acclen = dev_sem->timeout;
		ret = IOC_SUCCESFULL;
		break;
	}
	
	case RDMA_IOC_SET_TIMEOUT_WR:
	{
		if (open_mode == READER) {
			ERROR_MSG("%s: link: %d "
				  "cmd: RDMA_IOC_SET_TIMEOUT_WR(0x%08x). "
				  "File open as READER.\n", __FUNCTION__,
				  link, cmd);
			ret = -EBADF;
			break;
		}
		pd = &rdma_link->rw_states_d[WRITER];
		dev_sem = &pd->dev_rdma_sem;
		dev_sem->timeout = parm.reqlen;
		parm.acclen = dev_sem->timeout;
		ret = IOC_SUCCESFULL;
		break;
	}
		
	case RDMA_SET_STAT:
	{
		memset(&rdma_link->stat_rdma, 0, sizeof (struct stat_rdma));
		parm.acclen = 0;
		ret = IOC_SUCCESFULL;
		break;
	}
#if 0	
	case RDMA_IS_CAM_YES :
	{
		dev_rdma_sem_t *dev_sem;
		rw_state_p pcam;
		unsigned int atl;
		int ret_time_dwait = 0;
			
		event_ioctl(link, RDMA_IS_CAM_YES_EVENT, 1, 0);
		pcam = &rdma_link->ralive;
		dev_sem = &pcam->dev_rdma_sem;
		ret_time_dwait = 0;
		atl = RDR_rdma(SHIFT_CAM, link);
		if (atl) {
			parm.acclen = atl;
			parm.err_no = 0;
			goto end_RDMA_IS_CAM_YES;
		}
		raw_spin_lock_irqsave(&dev_sem->lock, flags);
		dev_sem->irq_count_rdma = 0;
		pcam->stat = 1;
		ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, IO_TIMEOUT, link);
		pcam->stat = 0;
		raw_spin_unlock_irqrestore(&dev_sem->lock, flags);
		parm.acclen = RDR_rdma(SHIFT_CAM, link);
		if (ret_time_dwait == -2) {
			parm.err_no = -RDMA_E_SIGNAL;
		} else
			if (ret_time_dwait == -1) {
				parm.err_no = -RDMA_E_TIMER;
			} else
				if (ret_time_dwait > 0) {
					parm.err_no = ret_time_dwait;
				} else
					parm.err_no = 0;
end_RDMA_IS_CAM_YES:
		event_ioctl(0, RDMA_IS_CAM_YES_EVENT, 0, 0);
		break;
	}	
	case RDMA_IS_CAM_NO :
	{
		dev_rdma_sem_t *dev_sem;
		rw_state_p pcam;
		unsigned int atl;
		int ret_time_dwait = 0;

		event_ioctl(link, RDMA_IS_CAM_NO_EVENT, 1, 0);
		pcam = &rdma_link->talive;
		dev_sem = &pcam->dev_rdma_sem;
		atl = RDR_rdma(SHIFT_CAM, link);
		if (!atl) {
			parm.acclen = 0;
			parm.err_no = 0;
			goto end_RDMA_IS_CAM_NO;
		}
		raw_spin_lock_irqsave(&dev_sem->lock, flags);
		dev_sem->irq_count_rdma = 0;
		pcam->stat = 1;
		ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, IO_TIMEOUT, link);
		pcam->stat = 0;
		raw_spin_unlock_irqrestore(&dev_sem->lock, flags);
		parm.acclen = RDR_rdma(SHIFT_CAM, link);
		if (ret_time_dwait == -2) {
			parm.err_no = -RDMA_E_SIGNAL;
		} else
			if (ret_time_dwait == -1) {
				parm.err_no = -RDMA_E_TIMER;
			} else
				if (ret_time_dwait > 0) {
					parm.err_no = ret_time_dwait;
				} else
					parm.err_no = 0;
end_RDMA_IS_CAM_NO:
		parm.clkr = join_curr_clock();
		parm.clkr1 = pcam->clkr;
		parm.reqlen = pcam->int_cnt;
		}
		event_ioctl(0, RDMA_IS_CAM_NO_EVENT, 0, 0);
		break;
#endif
	case MOK_X_IOC_CHANGE_MODE:
	{
	
		if (send_SGP1_Msg(link) > 0 ) {
			ret = IOC_SUCCESFULL;
			RDMA_IOCTL_DEBUG_MSG("%s: link: %d "
				     "cmd: MOK_X_IOC_CHANGE_MODE(0x%08x). "
				     "Change mode. \n", __FUNCTION__, link, cmd);
		} else {
			ret = -1;
			RDMA_IOCTL_DEBUG_MSG("%s: link: %d "
				     "cmd: MOK_X_IOC_CHANGE_MODE(0x%08x). "
				     "Change not mode. \n", __FUNCTION__, link, cmd);
		}
		break;
	}

	case MOK_X_IOC_READ_REG:
	{
		unsigned int type_msg;
		
#ifndef SETTING_OVER_INTERRUPT
		set_mask(link, 0x0);
#endif	
		type_msg = (2 * parm.type_mode +
			   parm.type_oper) << RDMA_MOK_X_MSG_SHIFT;
		RDMA_IOCTL_DEBUG_MSG("%s: link: %d "
				     "cmd: MOK_X_IOC_READ_REG(0x%08x). "
				     "type_msg: %x.\n", __FUNCTION__, link, cmd,
				     type_msg);
		ret = RDR_mok_x(link, type_msg, parm.reg_addr0, &parm.reg_data);
#ifndef SETTING_OVER_INTERRUPT
		set_mask(link, irq_mc);
#endif	
		break;
	}
	
	case MOK_X_IOC_WRITE_REG:
	{
		unsigned int type_msg;
		
#ifndef SETTING_OVER_INTERRUPT
		set_mask(link, 0x0);
#endif	
		type_msg = (2 * parm.type_mode +
			   parm.type_oper) << RDMA_MOK_X_MSG_SHIFT;
		RDMA_IOCTL_DEBUG_MSG("%s: link: %d "
				     "cmd: MOK_X_IOC_WRITE_REG(0x%08x). "
				     "type_msg: %x.\n", __FUNCTION__, link, cmd,
				     type_msg);
		ret = WRR_mok_x(link, type_msg, parm.reg_addr0, parm.reg_data);
#ifndef SETTING_OVER_INTERRUPT
		set_mask(link, irq_mc);
#endif	
		break;
	}
	
	case MOK_X_IOC_READ_MDIO_REG:
	{
		unsigned int type_msg;
		
#ifndef SETTING_OVER_INTERRUPT
		set_mask(link, 0x0);
#endif	
		type_msg = (2 * parm.type_mode +
			   parm.type_oper) << RDMA_MOK_X_MSG_SHIFT;
		RDMA_IOCTL_DEBUG_MSG("%s: link: %d "
				     "cmd: MOK_X_IOC_READ_MDIO_REG(0x%08x). "
				     "type_msg: %x.\n", __FUNCTION__, link, cmd,
				     type_msg);
		ret = get_mok_x_mdio_reg(link, type_msg, parm.reg_addr0,
					 parm.reg_addr1, parm.reg_addr2,
					 &parm.reg_data);
#ifndef SETTING_OVER_INTERRUPT
		set_mask(link, irq_mc);
#endif	
		break;
	}
	
	case MOK_X_IOC_WRITE_MDIO_REG:
	{
		unsigned int type_msg;
		
#ifndef SETTING_OVER_INTERRUPT
		set_mask(link, 0x0);
#endif	
		type_msg = (2 * parm.type_mode +
			   parm.type_oper) << RDMA_MOK_X_MSG_SHIFT;
		RDMA_IOCTL_DEBUG_MSG("%s: link: %d "
				     "cmd: MOK_X_IOC_WRITE_MDIO_REG(0x%08x). "
				     "type_msg: %x.\n", __FUNCTION__, link, cmd,
				     type_msg);
		ret = set_mok_x_mdio_reg(link, type_msg, parm.reg_addr0,
					 parm.reg_addr1, parm.reg_addr2,
					 parm.reg_data);
#ifndef SETTING_OVER_INTERRUPT
		set_mask(link, irq_mc);
#endif	
		break;
	}
	
	/*
	 * Get value link
	 */
	case MOK_X_IOC_GET_LINK:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_SR_link(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_SR_link(link);
			break;
		default:
			ret = -ENODEV;
		}
		parm.acclen = ret;
		if (ret >= 0 || ret <= 1)
			ret = 0;
		break;
	}
	
	/*
	 * Set enable
	 */
	case MOK_X_IOC_SET_ENABLE:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = set_mok_x_SR_enable(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = set_mok_x_remote_SR_enable(link);
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	/*
	 * Unset enable
	 */
	case MOK_X_IOC_UNSET_ENABLE:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = unset_mok_x_SR_enable(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = unset_mok_x_remote_SR_enable(link);
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	/*
	 * Get value enable
	 */
	case MOK_X_IOC_GET_ENABLE:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_SR_enable(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_SR_enable(link);
			break;
		default:
			ret = -ENODEV;
		}
		parm.acclen = ret;
		if (ret >= 0 || ret <= 1)
			ret = 0;
		break;
	}
	
	/*
	 * Set master
	 */
	case MOK_X_IOC_SET_MASTER:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = set_mok_x_SR_master(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = set_mok_x_remote_SR_master(link);
			break;
		default:
			ret = -ENODEV;
		} 
		break;
	}
	/*
	 * Unset master
	 */
	case MOK_X_IOC_UNSET_MASTER:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = unset_mok_x_SR_master(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = unset_mok_x_remote_SR_master(link);
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	/*
	 * Get value master
	 */
	case MOK_X_IOC_GET_MASTER:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_SR_master(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_SR_master(link);
			break;
		default:
			ret = -ENODEV;
		}
		parm.acclen = ret;
		if (ret >= 0 || ret <= 1)
			ret = 0;
		break;
	}
	
	/*
	 * Set slave
	 */
	case MOK_X_IOC_SET_SLAVE:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = set_mok_x_SR_slave(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = set_mok_x_remote_SR_slave(link);
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	/*
	 * Unset slave
	 */
	case MOK_X_IOC_UNSET_SLAVE:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = unset_mok_x_SR_slave(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = unset_mok_x_remote_SR_slave(link);
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	/*
	 * Get value master
	 */
	case MOK_X_IOC_GET_SLAVE:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_SR_slave(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_SR_slave(link);
			break;
		default:
			ret = -ENODEV;
		}
		parm.acclen = ret;
		if (ret >= 0 || ret <= 1)
			ret = 0;
		break;
	}
	
	/*
	 * Set enable transmit
	 */
	case MOK_X_IOC_SET_ENABLE_TRANSMIT:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = set_mok_x_SR_enable_trasmit(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = set_mok_x_remote_SR_enable_trasmit(link);
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	/*
	 * Get value enable transmit
	 */
	case MOK_X_IOC_GET_ENABLE_TRANSMIT:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_SR_enable_trasmit(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_SR_enable_trasmit(link);
			break;
		default:
			ret = -ENODEV;
		}
		parm.acclen = ret;
		if (ret >= 0 || ret <= 1)
			ret = 0;
		break;
	}
	
	/*
	 * Set enable receive
	 */
	case MOK_X_IOC_SET_ENABLE_RECEIVE:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = set_mok_x_SR_enable_receive(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = set_mok_x_remote_SR_enable_receive(link);
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	/*
	 * Get value enable receive
	 */
	case MOK_X_IOC_GET_ENABLE_RECEIVE:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_SR_enable_receive(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_SR_enable_receive(link);
			break;
		default:
			ret = -ENODEV;
		}
		parm.acclen = ret;
		if (ret >= 0 || ret <= 1)
			ret = 0;
		break;
	}
	
	/*
	 * Set ready to receive
	 */
	case MOK_X_IOC_SET_READY_TO_RECEIVE:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = set_mok_x_SR_ready_to_receive(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = set_mok_x_remote_SR_ready_to_receive(link);
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	/*
	 * Get value ready to receive
	 */
	case MOK_X_IOC_GET_READY_TO_RECEIVE:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_SR_ready_to_receive(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_SR_ready_to_receive(link);
			break;
		default:
			ret = -ENODEV;
		}
		parm.acclen = ret;
		if (ret >= 0 || ret <= 1)
			ret = 0;
		break;
	}
	
	/*
	 * Set granted last packet
	 */
	case MOK_X_IOC_SET_GRANTED_LAST_PACKET:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = set_mok_x_SR_granted_last_packet(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = set_mok_x_remote_SR_granted_last_packet(link);
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	
	/*
	 * Unset granted last packet
	 */
	case MOK_X_IOC_UNSET_GRANTED_LAST_PACKET:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = unset_mok_x_SR_granted_last_packet(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = unset_mok_x_remote_SR_granted_last_packet(link);
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	
	/*
	 * Get value granted last packet
	 */
	case MOK_X_IOC_GET_GRANTED_LAST_PACKET:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_SR_granted_last_packet(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_SR_granted_last_packet(link);
			break;
		default:
			ret = -ENODEV;
		}
		parm.acclen = ret;
		if (ret >= 0 || ret <= 1)
			ret = 0;
		break;
	}
	
	/*
	 * Set granted packet
	 */
	case MOK_X_IOC_SET_GRANTED_PACKET:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = set_mok_x_SR_granted_packet(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = set_mok_x_remote_SR_granted_packet(link);
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	
	/*
	 * Unset granted packet
	 */
	case MOK_X_IOC_UNSET_GRANTED_PACKET:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = unset_mok_x_SR_granted_packet(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = unset_mok_x_remote_SR_granted_packet(link);
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	
	/*
	 * Get value granted packet
	 */
	case MOK_X_IOC_GET_GRANTED_PACKET:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_SR_granted_packet(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_SR_granted_packet(link);
			break;
		default:
			ret = -ENODEV;
		}
		parm.acclen = ret;
		if (ret >= 0 || ret <= 1)
			ret = 0;
		break;
	}
	
	/*
	 * Get value in ready to receive
	 */
	case MOK_X_IOC_GET_IN_READY_TO_RECEIVE:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_SR_in_ready_to_receive(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_SR_in_ready_to_receive(link);
			break;
		default:
			ret = -ENODEV;
		}
		parm.acclen = ret;
		if (ret >= 0 || ret <= 1)
			ret = 0;
		break;
	}
	
	/*
	 * Set size buffer from mode1, mode2, mode3
	 */
	case MOK_X_IOC_SET_SIZE_FOR_MODE:
	{
		if (parm.reqlen <= rdma_link->buf_size) {
			switch (parm.rwmode) {
			case TYPE_OPER_NATIVE:
				ret = set_mok_x_SIZE(link,
						     rdma_link->mok_x_buf_size);
				rdma_link->mok_x_buf_size = parm.reqlen;
				break;
			case TYPE_OPER_REMOTE:
				ret = set_mok_x_remote_SIZE(link,
						rdma_link->mok_x_buf_size);
				rdma_link->mok_x_remote_buf_size = parm.reqlen;
				break;
			default:
				ret = -ENODEV;
			}
		} else {
			parm.acclen = rdma_link->buf_size;
			ret = -EMSGSIZE;
		}
		break;
	}
	/*
	 * Get size buffer from mode1, mode2, mode3
	 */
	case MOK_X_IOC_GET_SIZE_FOR_MODE:
	{
		int mok_x_buf_size = 0;
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_SIZE(link, &mok_x_buf_size);
			parm.acclen = (int) mok_x_buf_size;
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_SIZE(link, &mok_x_buf_size);
			parm.acclen = (int) mok_x_buf_size;
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	
	/*
	 * Set mode1
	 */
	case MOK_X_IOC_SET_MODE1:
	{
		parm.acclen = rdma_link->mok_x_buf_size;
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			if (!(ret = set_mok_x_SR_mode1(link))) 
				rdma_link->mok_x_mode1 = 1;
			break;
		case TYPE_OPER_REMOTE:
			if (!(ret = set_mok_x_SR_mode1(link)))
				rdma_link->mok_x_remote_mode1 = 1;
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	/*
	 * Unset mode1
	 */
	case MOK_X_IOC_UNSET_MODE1:
	{
		parm.acclen = rdma_link->mok_x_buf_size;
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			if (!(ret = unset_mok_x_SR_mode1(link))) 
				rdma_link->mok_x_mode1 = 0;
			break;
		case TYPE_OPER_REMOTE:
			if (!(ret = unset_mok_x_SR_mode1(link)))
				rdma_link->mok_x_remote_mode1 = 0;
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	/*
	 * Get mode1
	 */
	case MOK_X_IOC_GET_MODE1:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_SR_mode1(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_SR_mode1(link);
			break;
		default:
			ret = -ENODEV;
		}
		parm.acclen = ret;
		if (ret >= 0 || ret <= 1)
			ret = 0;
		break;
	}
	/*
	 * Set mode2
	 */
	case MOK_X_IOC_SET_MODE2:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			if (!(ret = set_mok_x_SR_mode2(link)))
				rdma_link->mok_x_mode2 = 1;
			break;
		case TYPE_OPER_REMOTE:
			if (!(ret = set_mok_x_remote_SR_mode2(link)))
				rdma_link->mok_x_remote_mode2 = 1;
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	/*
	 * Unset mode2
	 */
	case MOK_X_IOC_UNSET_MODE2:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			if (!(ret = unset_mok_x_SR_mode2(link)))
				rdma_link->mok_x_mode2 = 1;
			break;
		case TYPE_OPER_REMOTE:
			if (!(ret = unset_mok_x_SR_mode2(link)))
				rdma_link->mok_x_remote_mode2 = 1;
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	/*
	 * Get mode2
	 */
	case MOK_X_IOC_GET_MODE2:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_SR_mode2(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_SR_mode2(link);
			break;
		default:
			ret = -ENODEV;
		}
		parm.acclen = ret;
		if (ret >= 0 || ret <= 1)
			ret = 0;
		break;
	}
	
	/*
	 * Set mode3
	 */
	case MOK_X_IOC_SET_MODE3:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			if (!(ret = set_mok_x_SR_mode3(link)))
				rdma_link->mok_x_mode3 = 1;
			break;
		case TYPE_OPER_REMOTE:
			if (!(ret = set_mok_x_remote_SR_mode3(link)))
				rdma_link->mok_x_remote_mode3 = 1;
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	/*
	 * Unset mode3
	 */
	case MOK_X_IOC_UNSET_MODE3:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			if (!(ret = unset_mok_x_SR_mode3(link)))
				rdma_link->mok_x_mode3 = 0;
			break;
		case TYPE_OPER_REMOTE:
			if (!(ret = unset_mok_x_SR_mode2(link)))
				rdma_link->mok_x_remote_mode3 = 0;
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	/*
	 * Get mode3
	 */
	case MOK_X_IOC_GET_MODE3:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_SR_mode3(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_SR_mode3(link);
			break;
		default:
			ret = -ENODEV;
		}
		parm.acclen = ret;
		if (ret >= 0 || ret <= 1)
			ret = 0;
		break;
	}
	
	/*
	 * Set mode4
	 */
	case MOK_X_IOC_SET_MODE4:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			if (!(ret = set_mok_x_SR_mode4(link))) {
				rdma_link->mok_x_mode4 = 1;
			}
			break;
		case TYPE_OPER_REMOTE:
			if (!(ret = set_mok_x_remote_SR_mode4(link))) {
				rdma_link->mok_x_remote_mode4 = 1;
			}
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	case MOK_X_IOC_UNSET_MODE4:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			if (!(ret = unset_mok_x_SR_mode4(link))) {
				rdma_link->mok_x_mode4 = 0;
			}
			break;
		case TYPE_OPER_REMOTE:
			if (!(ret = unset_mok_x_SR_mode2(link))) {
				rdma_link->mok_x_remote_mode4 = 0;
			}
			break;
		default:
			ret = -ENODEV;
		}
		break;
	}
	/*
	 * Get mode4
	 */
	case MOK_X_IOC_GET_MODE4:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_SR_mode4(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_SR_mode4(link);
			break;
		default:
			ret = -ENODEV;
		}
		parm.acclen = ret;
		if (ret >= 0 || ret <= 1)
			ret = 0;
		break;
	}
	
	/*
	 * Get value timeout message receive
	 */
	case MOK_X_IOC_GET_TIMEOUT_MSG_RECEIVE:
	{
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_SR_in_ready_to_receive(link);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_SR_in_ready_to_receive(link);
			break;
		default:
			ret = -ENODEV;
		}
		parm.acclen = ret;
		if (ret >= 0 || ret <= 1)
			ret = 0;
		break;
	}
	
	/*
	 * Get value transmitted packets counter
	 */
	case MOK_X_IOC_TRANSMITTED_PACKET_COUNTER:
	{
		unsigned int data = 0;
		unsigned int reg_addr = MOK_X_TRANSMITTED_PACKET_COUNTER0;
		
		if (parm.reqlen > 3 || parm.reqlen < 0) {
			ret = -ERANGE;
			goto failed_transmit;
		}
		reg_addr = reg_addr + parm.reqlen;
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_reg_counters(link, reg_addr, &data);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_reg_counters(link, reg_addr, &data);
			break;
		default:
			ret = -ENODEV;
		}
	failed_transmit:
		parm.reg_data = data;
		break;
	}
	
	/*
	 * Get value received packets counter
	 */
	case MOK_X_IOC_RECEIVED_PACKET_COUNTER:
	{
		unsigned int data = 0;
		unsigned int reg_addr = MOK_X_RECEIVED_PACKET_COUNTER0;
		
		if (parm.reqlen > 3 || parm.reqlen < 0) {
			ret = -ERANGE;
			goto failed_received;
		}
		reg_addr = reg_addr + parm.reqlen;
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_reg_counters(link, reg_addr, &data);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_reg_counters(link, reg_addr, &data);
			break;
		default:
			ret = -ENODEV;
		}
	failed_received:
		parm.reg_data = data;
		break;
	}
	
	/*
	 * Get value received packets with error counter
	 */
	case MOK_X_IOC_RECEIVED_PACKET_ERR_COUNTER:
	{
		unsigned int data = 0;
		unsigned int reg_addr = MOK_X_RECEIVED_PACKET_ERR_COUNTER0;
		
		if (parm.reqlen > 3 || parm.reqlen < 0) {
			ret = -ERANGE;
			goto failed_err_received;
		}
		reg_addr = reg_addr + parm.reqlen;
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_reg_counters(link, reg_addr, &data);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_reg_counters(link, reg_addr, &data);
			break;
		default:
			ret = -ENODEV;
		}
	failed_err_received:
		parm.reg_data = data;
		break;
	}
	
	/*
	 * Get value not received packets counter
	 */
	case MOK_X_IOC_RECEIVED_PACKET_NOT_COUNTER:
	{
		unsigned int data = 0;
		unsigned int reg_addr = MOK_X_RECEIVED_PACKET_ERR_COUNTER0;
		
		if (parm.reqlen > 3 || parm.reqlen < 0) {
			ret = -ERANGE;
			goto failed_not_received;
		}
		reg_addr = reg_addr + parm.reqlen;
		switch (parm.rwmode) {
		case TYPE_OPER_NATIVE:
			ret = get_mok_x_reg_counters(link, reg_addr, &data);
			break;
		case TYPE_OPER_REMOTE:
			ret = get_mok_x_remote_reg_counters(link, reg_addr, &data);
			break;
		default:
			ret = -ENODEV;
		}
	failed_not_received:
		parm.reg_data = data;
		break;
	}
	
	case MOK_X_IOC_SET_NATIVE_MODE:
	{
		ret = mok_x_set_native_mode(link, &parm.acclen);
		break;
	}
	
	case MOK_X_IOC_UNSET_NATIVE_MODE:
	{
		ret = mok_x_unset_native_mode(link, &parm.acclen);
		break;
	}
	
	/*
	 * Mode set link
	 */
	case MOK_X_IOC_SET_MODE_LINK:
	{
		if (rdma_link->mok_x_config_sem_link == CONFIG_SEM_LINK_DOWN) {
			parm.acclen = CONFIG_SEM_LINK_DOWN;
			ret = IOC_SUCCESFULL;
			goto exit_set_mode_link;
		}
		rdma_link->mok_x_config_sem_link = CONFIG_SEM_LINK_DOWN;
		if (parm.reqlen == STATE_LINK_NATIVE) {
			ret = mok_x_set_native_mode(link, &parm.err_no);
			if (ret) {
				ERROR_MSG("Error native mode set. Errno: %d\n",
					  ret, parm.err_no);
			} else {
				ERROR_MSG("Native mode set. Errno: %d\n",
					  ret, parm.err_no);
			}
		}
		if (parm.reqlen == STATE_LINK_ONLY_RECIVE) {
			//ret = mok_x_unset_native_mode(link, &parm.err_no);
			rdma_link->mok_x_mode_number_link = parm.rwmode;
			if (parm.reqlen1 <= rdma_link->buf_size) {
				rdma_link->mok_x_buf_size = 
					(rdma_link->tm_mode ? 
						ALIGN(parm.reqlen1, (rdma_link->align_buf_tm * PAGE_SIZE)) : 
						(rfsm ? rdma_link->buf_size : allign_dma(parm.reqlen1)));
			} else {
				parm.reqlen1 = rdma_link->buf_size;
				ret = -EMSGSIZE;
				ERROR_MSG("%s: Ordered size: %x larger buffer: %x\n",
					  __FUNCTION__, parm.reqlen1, rdma_link->buf_size);
				goto exit_set_mode_link;
			}
			parm.reqlen1 = rdma_link->mok_x_buf_size;
			rdma_link->generator_mode = parm.reqlen2;
			ret = mok_x_set_mode4(link);
			if (ret) {
				mok_x_unset_mode4(link);
				set_mask(link, irq_mc);	
				ERROR_MSG("Error only receive mode set. Errno: %d\n",
					  ret, parm.err_no);
			} else {
				ERROR_MSG("Only receive mode set. Errno: %d\n",
					  ret, parm.err_no);
			}
		}
		if (!ret)
			rdma_link->mok_x_mode_link = parm.reqlen;
		parm.acclen = rdma_link->mok_x_mode_link;
exit_set_mode_link:;;
		rdma_link->mok_x_config_sem_link = CONFIG_SEM_LINK_UP;
		break;
	}
	
	/*
	 * Mode reset link
	 */
	case MOK_X_IOC_RESET_MODE_LINK:
	{
		ret = set_mode_default_remote(link);
		ret = set_mode_default(link);
		rdma_link->mok_x_mode_link = STATE_LINK_DEFAULT;
		parm.acclen = rdma_link->mok_x_mode_link;
		break;
	}
	
	/*
	 * Mode get link
	 */
	case MOK_X_IOC_GET_MODE_LINK:
	{
		if (rdma_link->mok_x_config_sem_link == CONFIG_SEM_LINK_DOWN) {
			parm.acclen = CONFIG_SEM_LINK_DOWN;
			goto exit_get_mode_link;
		}
		rdma_link->mok_x_config_sem_link = CONFIG_SEM_LINK_DOWN;
		parm.acclen = rdma_link->mok_x_mode_link;
		rdma_link->mok_x_config_sem_link = CONFIG_SEM_LINK_UP;
exit_get_mode_link:;;
		ret = IOC_SUCCESFULL;
		break;
	}
	
	/*
	 * Set sem link
	 */
	case MOK_X_IOC_SET_CONFIG_SEM_LINK:
	{
		rdma_link->mok_x_config_sem_link = parm.reqlen;
		parm.acclen = rdma_link->mok_x_config_sem_link;
		ret = 0;
		break;
	}
	
	/*
	 * Get sem link
	 */
	case MOK_X_IOC_GET_CONFIG_SEM_LINK:
	{
		parm.acclen = rdma_link->mok_x_config_sem_link;
		ret = 0;
		break;
	}
	
	/*
	 * Start DMA in extented mode
	 */
	case MOK_X_IOC_START_DMA:
	{
		
		/*
		 * Set mask only RDC enable
		 */
		set_mask(link, irq_mc_rdc);
		/*
		 * Programming dma
		 */
		mok_x_prog_recieve_dma(link, 0);
		
		ret = IOC_SUCCESFULL;
		break;
	}
	
	default :
		ERROR_MSG("%s: link: %d unknown cmd: 0x%08x\n", __FUNCTION__,
			  link, cmd);
		ret = -EFAULT; 
		break;
	}
	
	rval = copy_to_user((rdma_ioc_parm_t __user *)arg, &parm, 
			     sizeof (rdma_ioc_parm_t));
	if (rval) {
		ERROR_MSG("%s: link: %d cmd: 0x%08x copy_to_user failed\n", 
			  __FUNCTION__, link, cmd);
		ret = -EINVAL;
	}
	RDMA_IOCTL_DEBUG_MSG("%s: link: %d cmd: 0x%08x FINISH\n", __FUNCTION__, 
			     link, cmd);
	return ret;
}

#ifdef CONFIG_COMPAT
static int do_ioctl(struct file *f, unsigned cmd, unsigned long arg)
{
	int ret;
	ret = rdma_ioctl(f, cmd, arg);
	return ret;
}

static long rdma_compat_ioctl(struct file *f, unsigned cmd, unsigned long arg)
{
	switch (cmd) {

	case RDMA_IOC_DUMPREG0:
	case RDMA_IOC_DUMPREG1:
	case RDMA_IOC_WRR:
	case RDMA_IOC_RDR:
	case RDMA_IOC_GET_neighbour_map:
	case RDMA_CLEAN_TDC_COUNT:
	case RDMA_GET_CLKR:
	case RDMA_GET_MAX_CLKR:
	case RDMA_CLEAN_RDC_COUNT:
	case RDMA_TIMER_FOR_READ :
	case RDMA_TIMER_FOR_WRITE:
	case RDMA_IOC_ALLOCB:
	case RDMA_GET_STAT:
	case RDMA_GET_EVENT:
	case RDMA_SET_STAT:
	case RDMA_SET_ATL:
	case RDMA_IS_CAM_YES:
	case RDMA_IS_CAM_NO:
	case RDMA_WAKEUP_WRITER:
	case RDMA_WAKEUP_READER:
	case RDMA_IOC_GET_ID:
	case RDMA_IOC_RESET_DMA:
	case RDMA_IOC_SET_MODE_RFSM:
	case RDMA_IOC_SET_MODE_EXIT_GP0:
	case RDMA_IOC_RESET_TCS:
	case RDMA_IOC_RESET_RCS:
	case RDMA_IOC_SET_MODE_LOOP:
	case RDMA_IOC_GET_BUF_NUM:
	case RDMA_IOC_SET_BUF_NUM:
	case RDMA_IOC_GET_BUF_SIZE:
	case RDMA_IOC_RD_BUF:
	case RDMA_IOC_WR_BUF:
	case RDMA_IOC_GET_RD_BUF:
	case RDMA_IOC_GET_WR_BUF:
	case RDMA_IOC_PUT_RD_BUF:
	case RDMA_IOC_PUT_WR_BUF:
	case RDMA_IOC_SET_TIMEOUT_RD:
	case RDMA_IOC_SET_TIMEOUT_WR:
	case MOK_X_IOC_SET_ONLY_RECEIVE_MODE:
	case MOK_X_IOC_SET_NATIVE_MODE:
	case MOK_X_IOC_READ_REG:
	case MOK_X_IOC_WRITE_REG:
	case MOK_X_IOC_READ_MDIO_REG:
	case MOK_X_IOC_WRITE_MDIO_REG:
	case MOK_X_IOC_CHANGE_MODE:
	case MOK_X_IOC_SET_MODE_LINK:
	case MOK_X_IOC_RESET_MODE_LINK:
	case RDMA_IOC_GET_TM_MODE:
	case RDMA_IOC_SET_TM_MODE:
	case RDMA_IOC_GET_ALIGN_BUF_TM:
	case RDMA_IOC_SET_ALIGN_BUF_TM:
	case RDMA_IOC_GET_PAGE_SIZE:
	case RDMA_IOC_GET_NODE_MEM_ALLOC:
	case RDMA_IOC_SET_NODE_MEM_ALLOC:
	case RDMA_IOC_GET_MAX_SIZE_BUFF:
	case RDMA_IOC_SET_MAX_SIZE_BUFF:
	case RDMA_IOC_GET_MAX_SIZE_BUFF_TM:
	case RDMA_IOC_SET_MAX_SIZE_BUFF_TM:
	case RDMA_IOC_MEMRY_ALLOC:
	case RDMA_IOC_ALLOC_TYPE:
		return do_ioctl(f, cmd, arg);
	default:
		return -ENOIOCTLCMD;
	}
}
#endif

#define GET_FILE_MINOR_DBG 0
#define GET_FILE_MINOR_DEBUG_MSG(x...)\
		if (GET_FILE_MINOR_DBG) DEBUG_MSG(x)
int get_file_minor(struct file *file)
{
	int	major;
	struct dentry	*f_dentry_rdma;
	struct inode	*d_inode;

	f_dentry_rdma = file->f_dentry;
	if (!f_dentry_rdma) {
		ERROR_MSG( "get_file_minor: file->f_dentry is NULL\n");
		return -EBADF;
	}
	d_inode = f_dentry_rdma->d_inode;
	if (!d_inode) {
		ERROR_MSG( "get_file_minor: f_dentry->d_inode is NULL\n");
		return -EBADF;
	}
	major = MAJOR(d_inode->i_rdev);
	GET_FILE_MINOR_DEBUG_MSG("get_file_minor:d_inode->i_rdev: 0x%08u "
			"major: %d minor:%u\n", d_inode->i_rdev, major, 
   			MINOR(d_inode->i_rdev));
	return MINOR(d_inode->i_rdev);
}

#define RDMA_REMAP_DBG 0
#define RDMA_REMAP_DEBUG_MSG(x...)\
		if (RDMA_REMAP_DBG) DEBUG_MSG(x)
#define REMAP RDMA_REMAP_DEBUG_MSG		
int rdma_remap_page(void *va, size_t sz, struct vm_area_struct *vma)
{
   	unsigned long pha;
 	unsigned long vm_end;
	unsigned long vm_start;
	unsigned long vm_pgoff;
	size_t size;

	REMAP("%s: START\n", __FUNCTION__);
	if (!sz) return -EINVAL;
	pha = virt_to_phys(va);
	size = (long )PAGE_ALIGN((pha & ~PAGE_MASK) + sz);
	if ((vma->vm_pgoff << PAGE_SHIFT) > size) return -ENXIO;
	pha += (vma->vm_pgoff << PAGE_SHIFT);
	vm_end = vma->vm_end;
	vm_start = vma->vm_start;
	vm_pgoff = vma->vm_pgoff;

	if ((vm_end - vm_start) < size)
		size = vm_end - vm_start;
	vma->vm_flags |= (VM_READ | VM_WRITE | VM_RESERVED | VM_IO);
	vma->vm_page_prot = __pgprot(pgprot_val(vma->vm_page_prot) | 
					_PAGE_CD_DIS | _PAGE_PWT );
	if (remap_pfn_range(vma, vm_start, (pha >> PAGE_SHIFT), size, 
	    vma->vm_page_prot)) {
		ERROR_MSG("%s: FAIL remap_pfn_range\n", __FUNCTION__);
		return -EAGAIN;
	}
	REMAP("%s: FINISH\n", __FUNCTION__);
	return 0;
}

#define RDMA_REMAP_T_DBG 0
#define RDMA_REMAP_T_DEBUG_MSG(x...)\
		if (RDMA_REMAP_T_DBG) DEBUG_MSG(x)
#define REMAP_T RDMA_REMAP_T_DEBUG_MSG		
int rdma_remap_page_tbl(void *va, size_t sz, struct vm_area_struct *vma, int align)
{
	rdma_tbl_64_struct_t *ptbl;
	unsigned long vm_start;
	unsigned long vm_pgoff;
	unsigned long sz_pha;
	unsigned long vm_end;
	unsigned long pha;
	size_t size;

	REMAP_T("%s: START size(sz): 0x%016lx\n", __FUNCTION__, sz);
	if (!sz) return -EINVAL;
	if (vma->vm_pgoff) {
		ERROR_MSG("%s: vma->vm_pgoff: 0x%lx\n", __FUNCTION__,
			  vma->vm_pgoff);
		return -EINVAL;
	}
	//size = (long)PAGE_ALIGN(sz);
	size = (long)ALIGN(sz, align * PAGE_SIZE); 
   	vm_end = vma->vm_end;
   	vm_start = vma->vm_start;
   	vm_pgoff = vma->vm_pgoff;
	if ((vm_end - vm_start) < size) {
      		size = vm_end - vm_start;
		REMAP_T("%s: vm_end(%lx) - vm_start(%lx) < size(%lx)\n", 
			__FUNCTION__, vm_end, vm_start, size);
	}
   	vma->vm_flags |= (VM_READ | VM_WRITE | VM_RESERVED | VM_IO);
	vma->vm_page_prot = __pgprot(pgprot_val(vma->vm_page_prot) | 
					_PAGE_CD_DIS | _PAGE_PWT );
	for (ptbl = (rdma_tbl_64_struct_t *)va; ptbl; ptbl++) {
		rdma_addr_struct_t pxx;
		pxx.addr = (unsigned long)ptbl;
		REMAP_T("%s: 0x%08x%08x ptbl\n", __FUNCTION__, pxx.fields.haddr,
			pxx.fields.laddr);
		pxx.addr = ptbl->addr;
		REMAP_T("%s: 0x%08x%08x ptbl->addr\n", __FUNCTION__, 
			pxx.fields.haddr, pxx.fields.laddr);
		pha = (unsigned long)ptbl->addr;
		pxx.addr = (unsigned long)phys_to_virt(pha);
		REMAP_T("%s: 0x%08x%08x __va(ptbl->addr)\n", 
			__FUNCTION__, pxx.fields.haddr, pxx.fields.laddr);
		pxx.addr = pha;
		REMAP_T("%s: 0x%08x%08x __fa(ptbl->addr)\n", 
			__FUNCTION__, pxx.fields.haddr, pxx.fields.laddr);
		sz_pha = ptbl->sz;
		//sz_pha = cpu_to_le64(sz_pha);
		REMAP_T("%s: sz_pha: %lx\n", __FUNCTION__, sz_pha);
		if (remap_pfn_range(vma, vm_start, (pha >> PAGE_SHIFT), sz_pha,
		    vma->vm_page_prot)) {
			ERROR_MSG("%s: FAIL remap_pfn_range\n", __FUNCTION__);
       			return -EAGAIN;
       		}
		vm_start += sz_pha;
		REMAP_T("%s: vm_start: %lx vm_end: %lx sz_pha: %lx \n", 
			__FUNCTION__, vm_start, vm_end, sz_pha);
		if (vm_start >= vm_end) {
			REMAP_T("%s: vm_start(%lx) >= vm_end(%lx)\n", __FUNCTION__, 
				vm_start, vm_end);
			break;
		}
	}
	REMAP_T("%s: FINISH\n", __FUNCTION__);
	return 0;
}

#define RDMA_MMAP_DBG 0
#define RDMA_MMAP_DEBUG_MSG(x...)\
		if (RDMA_MMAP_DBG) DEBUG_MSG(x)
static int rdma_mmap(struct file *file, struct vm_area_struct *vma)
{
	rdma_pool_buf_t *pool_buf;
	rdma_state_link_t *rdma_link;
	rw_state_t *rdma_private_data;
	int minor, rw;
	int link;
	int rval;

	RDMA_MMAP_DEBUG_MSG("%s: START\n", __FUNCTION__);
	minor = get_file_minor(file);
 	//minor = MINOR(inode->i_rdev);
	if (minor < 0)
		return minor;
	link = DEV_inst(minor);
	rdma_link = &rdma_state->rdma_link[link];
	rdma_private_data = file->private_data;
	rw = rdma_private_data->open_mode;
	rw ? (pool_buf = &rdma_link->write_pool) : 
	     (pool_buf = &rdma_link->read_pool);
#if 0	
	if (pool_buf->alloc != RDMA_BUF_ALLOCED) { 
		ERROR_MSG("%s : pool_buf->alloc != RDMA_BUF_ALLOCED\n", 
					  __FUNCTION__);
		return -EAGAIN;
	}
#endif
	if (pool_buf->tm_mode) {
		rval = rdma_remap_page_tbl((void *)pool_buf->vdma, 
					    pool_buf->dma_size,
					    vma, pool_buf->align_buf_tm);
	} else {
		rval = rdma_remap_page((void *)pool_buf->vdma, 
		//rval = rdma_remap_page((unsigned long)pool_buf->fdma, 
			pool_buf->dma_size, vma);
	}
	if (rval) {
		ERROR_MSG("%s: FAIL\n", __FUNCTION__);
		return -EAGAIN;
	}
	pool_buf->alloc = RDMA_BUF_MMAP;
	RDMA_MMAP_DEBUG_MSG("%s: FINISH\n", __FUNCTION__);
	return 0;
}

unsigned long __get_free_pages_rdma(int node, gfp_t gfp_mask, 
				    unsigned int order, int node_mem_alloc)
{
	struct page *page;
	if (node_mem_alloc)
		page = alloc_pages_node(node, gfp_mask, order);
	else 
		page = alloc_pages(gfp_mask, order);
	if (!page)
		return (unsigned long)NULL;
	return (unsigned long) page_address(page);
}

#define RDMA_MEM_ALLOC_DBG 0
#define RDMA_MEM_ALLOC_DEBUG_MSG(x...)\
		if (RDMA_MEM_ALLOC_DBG) DEBUG_MSG(x)
int rdma_mem_alloc(int node, size_t size, dma_addr_t *mem, size_t *real_size,
		    unsigned long *dma_memory, int node_mem_alloc)
{
	struct page *map, *mapend;
	int order;

	RDMA_MEM_ALLOC_DEBUG_MSG("%s: START\n", __FUNCTION__);
	order = get_order(size);
	*dma_memory = __get_free_pages_rdma(node, GFP_KERNEL , order,
					    node_mem_alloc);
	if (!(*dma_memory)) {
		ERROR_MSG("%s: Cannot bind DMA address order: %d"
			  " size: 0x%lx\n", __FUNCTION__, order, size);
	      return -1;
	}
	mapend = virt_to_page((*dma_memory) + (PAGE_SIZE << order) - 1);
	for (map = virt_to_page((*dma_memory)); map <= mapend; map++)
		SetPageReserved(map);
	*mem = __pa(*dma_memory);
	
	*real_size = PAGE_SIZE << order;
	RDMA_MEM_ALLOC_DEBUG_MSG("%s: FINISH va: 0x%lx fa: 0x%llx size: 0x%lx "
		  		 "real_size: 0x%lx\n", __FUNCTION__, *dma_memory,
				 *mem, size, *real_size);
	return 0;
	
}

/* 
 * Size table element SIZE_TLB_EL: 64 bit's addr and 64 bit's size 
 */	
#define RDMA_MEM_ALLOC_POOL_DBG 0
#define RDMA_MEM_ALLOC_POOL_DEBUG_MSG(x...)\
		if (RDMA_MEM_ALLOC_POOL_DBG) DEBUG_MSG(x)
int rdma_mem_alloc_pool(rdma_pool_buf_t *pool_buf)
{
	rdma_tbl_64_struct_t *peltbl;
	rdma_addr_struct_t pxx;
	size_t size_tm;
	char *err_msg = NULL;
	int SIZE_TLB, max_size, rest;
	
	RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: START \n", __FUNCTION__);
	if (pool_buf->tm_mode) {
		max_size = pool_buf->size;
		//SIZE_TLB = ((PAGE_ALIGN(max_size) / PAGE_SIZE + 1) * SIZE_TLB_EL);
		SIZE_TLB = ((PAGE_ALIGN(max_size) / (pool_buf->align_buf_tm * PAGE_SIZE) + 1) * SIZE_TLB_EL);
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: table mode ALIGN PAGE_SIZE: 0x%016lx\n",
				    	      __FUNCTION__,
					      pool_buf->align_buf_tm * PAGE_SIZE);
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: try alloc for tm size "
					      "SIZE_TLB : 0x%08x\n", 
					      __FUNCTION__, SIZE_TLB);
		if (rdma_mem_alloc(pool_buf->node_for_memory, SIZE_TLB, 
		    (dma_addr_t *)&pool_buf->fdma, &size_tm, 
		     (unsigned long *)&pool_buf->vdma, pool_buf->node_mem_alloc )) {
			err_msg = "rdma_mem_alloc for tm";
			goto failed;
		}
		pxx.addr = (unsigned long)pool_buf->vdma;
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: 0x%08x%08x virt_mem table\n", 
					__FUNCTION__,
					pxx.fields.haddr, pxx.fields.laddr);
		pxx.addr = pool_buf->fdma;
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: 0x%08x%08x phys_mem table\n", 
					__FUNCTION__, 
				    	pxx.fields.haddr, pxx.fields.laddr);
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: size table: 0x%016lx \n", 
					      __FUNCTION__, size_tm);
		pool_buf->size_tm = size_tm;
		rest = (int)pool_buf->size;
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: rest: 0x%08x pool_buf->size: 0x%016lx\n", 
					      __FUNCTION__, rest, pool_buf->size);
		pool_buf->dma_size = 0;
		for (peltbl = (rdma_tbl_64_struct_t *)pool_buf->vdma; rest > 0;
			       peltbl++){
			size_t size_el;
			unsigned long addr;		
			if (rdma_mem_alloc(pool_buf->node_for_memory, 
					   pool_buf->align_buf_tm * PAGE_SIZE,
					   (dma_addr_t *)&peltbl->addr,
					   &size_el, (unsigned long *)&addr,
					   pool_buf->node_mem_alloc)) {
				goto failed;
			}
			pxx.addr = (unsigned long)peltbl;
			RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: 0x%08x%08x peltbl\n", 
					__FUNCTION__, 
					pxx.fields.haddr, pxx.fields.laddr);
			//peltbl->addr = le64_to_cpu(peltbl->addr);
			pxx.addr = peltbl->addr;
			RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: 0x%08x%08x peltbl->addr\n", 
					    	__FUNCTION__, pxx.fields.haddr,	
	  					pxx.fields.laddr);
			peltbl->sz = (unsigned long)size_el;
			//peltbl->sz = le64_to_cpu(peltbl->sz);
			rest -= size_el;
			pool_buf->dma_size += size_el;
		}
		peltbl->sz = 0;
	} else {
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: single mode PAGE_SIZE: 0x%016lx\n", 
				   	       __FUNCTION__, PAGE_SIZE);
		//if (pool_buf->size > num_buf * allign_dma(MAX_SIZE_BUFF)) {
		//	ERROR_MSG("%s: The large size of the buffer. "
		//			"The buffer must be <= 0x%08x.\n", 
     		//			__FUNCTION__, MAX_SIZE_BUFF);
		//	goto failed;
		//}
		if (rdma_mem_alloc(pool_buf->node_for_memory, pool_buf->size, 
		    (dma_addr_t *)&pool_buf->fdma, &pool_buf->dma_size, 
		     (unsigned long *)&pool_buf->vdma, pool_buf->node_mem_alloc)) {
			err_msg = "rdma_mem_alloc";
			goto failed;
		}
		pxx.addr = (unsigned long)pool_buf->vdma;
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: 0x%08x%08x virt_mem\n", 
					      __FUNCTION__, 
	   				      pxx.fields.haddr, pxx.fields.laddr);
		pxx.addr = pool_buf->fdma;
		RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: 0x%08x%08x phys_mem\n", 
					      __FUNCTION__, 
					      pxx.fields.haddr, pxx.fields.laddr);
	}
	RDMA_MEM_ALLOC_POOL_DEBUG_MSG("%s: FINISH buf real size: 0x%016lx\n", 
				      __FUNCTION__, pool_buf->dma_size);
	return 0;

failed:
	ERROR_MSG("%s: %s FAILED ****\n", __FUNCTION__, err_msg);
	return (-1);
}

#define RDMA_MEM_FREE_DBG 0
#define RDMA_MEM_FREE_DEBUG_MSG(x...)\
		if (RDMA_MEM_FREE_DBG) DEBUG_MSG(x)
void rdma_mem_free(size_t size, dma_addr_t dev_memory, 
		   unsigned long dma_memory)
{
	struct page *map, *mapend;
	caddr_t mem;
	int order;

	RDMA_MEM_FREE_DEBUG_MSG("%s: START\n", __FUNCTION__);
	mem = (caddr_t)dma_memory;
	order = get_order(size);
	mapend = virt_to_page(mem + (PAGE_SIZE << order) - 1);
	for (map = virt_to_page(mem); map <= mapend; map++)
		ClearPageReserved(map);
	free_pages(dma_memory, order);
	RDMA_MEM_FREE_DEBUG_MSG("%s: FINISH va: 0x%lx, fa: 0x%llx size: 0x%lx\n",
				__FUNCTION__, dma_memory, dev_memory, size);
}

#define RDMA_MEM_FREE_POOL_DBG 0
#define RDMA_MEM_FREE_POOL_DEBUG_MSG(x...)\
		if (RDMA_MEM_FREE_POOL_DBG) DEBUG_MSG(x)
void rdma_mem_free_pool(rdma_pool_buf_t *pool_buf)
{
	signed int rest;
	
	RDMA_MEM_FREE_POOL_DEBUG_MSG("%s: START\n", __FUNCTION__);
	if (pool_buf->alloc) {
		if (pool_buf->tm_mode) {
			rdma_tbl_64_struct_t	*peltbl;
			for (peltbl = (rdma_tbl_64_struct_t *)pool_buf->vdma,
			    	rest = pool_buf->dma_size; rest > 0; peltbl++) {
				rdma_mem_free(peltbl->sz, (dma_addr_t) peltbl->addr, 
					      (unsigned long) __va(peltbl->addr));
				rest -= peltbl->sz;
			}
			rdma_mem_free(pool_buf->size_tm, pool_buf->fdma,
				      (unsigned long)pool_buf->vdma);
		}  else {
			//if (pool_buf->size) {
			//if (pool_buf->alloc) {
			rdma_mem_free(pool_buf->dma_size, pool_buf->fdma,
					      (unsigned long)pool_buf->vdma);
		}
	}
	pool_buf->size = 0;
	pool_buf->dma_size = 0;
	pool_buf->alloc = RDMA_BUF_EMPTY;
	pool_buf->vdma = NULL;
	pool_buf->fdma = 0;
	RDMA_MEM_FREE_POOL_DEBUG_MSG("%s: FINISH\n", __FUNCTION__);
}

#define INIT_RDMA_LINK_DBG 0
#define INIT_RDMA_LINK_DEBUG_MSG(x...)\
		if (INIT_RDMA_LINK_DBG) DEBUG_MSG(x)
void rdma_link_init(int link)
{
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[link];
	dev_rdma_sem_t *dev_sem;
	rw_state_t *pd, *pm;
	rdma_addr_struct_t p_xxb;
	int i;

	INIT_RDMA_LINK_DEBUG_MSG("%s: START\n", __FUNCTION__);
	p_xxb.addr = (unsigned long)rdma_link;
	INIT_RDMA_LINK_DEBUG_MSG("%s: link: %d rdma_link: 0x%08x%08x\n",
				 __FUNCTION__, link, p_xxb.fields.haddr,
     				p_xxb.fields.laddr);
	rdma_link->link = link;
	rdma_link->tm_mode = tm_mode;
	rdma_link->align_buf_tm = align_buf_tm;
	rdma_link->max_size_buf = max_size_buf;
	rdma_link->max_size_buf_tm = max_size_buf_tm;
	rdma_link->num_buf = num_buf;
	rdma_link->node_mem_alloc = node_mem_alloc;
	rdma_link->type_alloc = 0;
	rdma_link->trwd_lock = 0;
	rdma_link->trwd_lock_err = 0;
	mutex_init(&rdma_link->mu);
	pm = &rdma_link->talive;
	mutex_init(&pm->mu);
	raw_spin_lock_init(&pm->mu_spin);
	pm->stat = 0;
	pm->timer = TIMER_MIN;
	dev_sem = &pm->dev_rdma_sem;
	raw_spin_lock_init(&dev_sem->lock);
	cv_init(&dev_sem->cond_var);
	dev_sem->irq_count_rdma = 0;
	pm = &rdma_link->ralive;
	mutex_init(&pm->mu);
	raw_spin_lock_init(&pm->mu_spin);
	pm->stat = 0;
	pm->timer = TIMER_MIN;
	dev_sem = &pm->dev_rdma_sem;
	raw_spin_lock_init(&dev_sem->lock);
	cv_init(&dev_sem->cond_var);
	dev_sem->irq_count_rdma = 0;
	for (i = 0; i < 2; i++) {
		pm = &rdma_link->rw_states_m[i];
		mutex_init(&pm->mu);
		raw_spin_lock_init(&pm->mu_spin);
		pm->stat = 0;
		pm->timer = TIMER_MIN;
		dev_sem = &pm->dev_rdma_sem;
		raw_spin_lock_init(&dev_sem->lock);
		cv_init(&dev_sem->cond_var);
		dev_sem->irq_count_rdma = 0;
		pd = &rdma_link->rw_states_d[i];
		mutex_init(&pd->mu);
		raw_spin_lock_init(&pd->mu_spin);
		raw_spin_lock_init(&pd->lock_wr);
		raw_spin_lock_init(&pd->lock_rd);
		dev_sem = &pd->dev_rdma_sem;
		raw_spin_lock_init(&dev_sem->lock);
		cv_init(&dev_sem->cond_var);
		dev_sem->irq_count_rdma = 0;
		pd->trwd_was = 0;
		pd->clock_receive_trwd = 0;
		pd->clock_begin_read = 0;
		pd->clock_end_read_old = 0;
		pd->clock_begin_read_old = 0;
		pd->trwd_send_count = 0;
		pd->ready_send_count = 0;
		pd->trwd_rec_count = 0;
		pd->ready_rec_count = 0;
		pd->n_ready = 0;
		pd->stat = 0;
		pd->timer_read = TIMER_MIN;
		pd->timer_write = TIMER_MIN;
		pd->timer_for_read = TIMER_FOR_READ_MIN;
		pd->timer_for_write = TIMER_FOR_WRITE_MIN;
		pd->state_open_close = 0;
		pd->first_open = 0;
	}
	raw_spin_lock_init(&rdma_link->mutex_send_msg);
	rdma_link = &rdma_state->rdma_link[link];
	rdma_link->mok_x_config_sem_link = CONFIG_SEM_LINK_UP;
	rdma_link->mok_x_mode_link = STATE_LINK_DEFAULT;
	rdma_link->mok_x_mode_number_link == MODE0_LINK;
#ifdef UNX_TRWD
	rdma_link->unexpected_trwd = 0;
	rdma_link->unexpected_trwd_size = 0;
#endif	
	INIT_RDMA_LINK_DEBUG_MSG("%s: FINISH\n", __FUNCTION__);
}

void read_regs_rdma(int i)
{
	printk("%d 0x%08x - 0x0 SHIFT_IOL_CSR\n",  i, 
	       RDR_rdma(SHIFT_IOL_CSR, i));
	printk("%d 0x%08x - 0x0 SHIFT_IO_CSR\n",   i,
	        RDR_rdma(SHIFT_IO_CSR, i));
	printk("%d 0x%08x - 0x0 SHIFT_VID\n", 	   i, 
	       RDR_rdma(SHIFT_VID, i));
	printk("%d 0x%08x - 0x4 SHIFT_CH_IDT\n",   i, 
	       RDR_rdma(SHIFT_CH_IDT, i));
	printk("%d 0x%08x - 0x8 SHIFT_CS\n",       i, 
	       RDR_rdma(SHIFT_CS, i));
	printk("%d 0x%08x 0x00 - SHIFT_DD_ID\n",   i, 
	       RDR_rdma(SHIFT_DD_ID, i));
	printk("%d 0x%08x 0x04 - SHIFT_DMD_ID\n",  i, 
	       RDR_rdma(SHIFT_DMD_ID, i));
	printk("%d 0x%08x 0x08 - SHIFT_N_IDT\n",   i, 
	       RDR_rdma(SHIFT_N_IDT, i));
	printk("%d 0x%08x 0x0c - SHIFT_ES\n",      i, 
	       RDR_rdma(SHIFT_ES, i));
	printk("%d 0x%08x 0x10 - SHIFT_IRQ_MC\n",  i, 
	       RDR_rdma(SHIFT_IRQ_MC, i));
	printk("%d 0x%08x 0x14 - SHIFT_DMA_TCS\n", i, 
	       RDR_rdma(SHIFT_DMA_TCS, i));
	printk("%d 0x%08x 0x18 - SHIFT_DMA_TSA\n", i, 
	       RDR_rdma(SHIFT_DMA_TSA, i));
	printk("%d 0x%08x 0x1c - SHIFT_DMA_TBC\n", i, 
	       RDR_rdma(SHIFT_DMA_TBC, i));
	printk("%d 0x%08x 0x20 - SHIFT_DMA_RCS\n", i, 
	       RDR_rdma(SHIFT_DMA_RCS, i));
	printk("%d 0x%08x 0x24 - SHIFT_DMA_RSA\n", i, 
	       RDR_rdma(SHIFT_DMA_RSA, i));
	printk("%d 0x%08x 0x28 - SHIFT_DMA_RBC\n", i, 
	       RDR_rdma(SHIFT_DMA_RBC, i));
	printk("%d 0x%08x 0x2c - SHIFT_MSG_CS\n",  i, 
	       RDR_rdma(SHIFT_MSG_CS, i));
	printk("%d 0x%08x 0x30 - SHIFT_TDMSG\n",   i, 
	       RDR_rdma(SHIFT_TDMSG, i));
	/*
	printk("%d 0x%08x 0x34 - SHIFT_RDMSG\n",   i, 
	       RDR_rdma(SHIFT_RDMSG, i));
	*/
	printk("%d 0x%08x 0x38 - SHIFT_CAM\n",     i, 
	       RDR_rdma(SHIFT_CAM, i));
}

void del_dev_mokx(int major, int i)
{
	int i_mokx = 0;
	char nod[128];
	int minor;
	
	for (i_mokx = 0; i_mokx < RDMA_NODE_DEV; i_mokx ++) {
		minor = RDMA_NODE_IOLINKS * i * RDMA_NODE_DEV + i_mokx;
		(void) sprintf(nod,"mokx_%d_:%d_r", i, i_mokx);
		device_destroy(mokx_class, MKDEV(major, minor));
		minor ++;
		(void) sprintf(nod,"mokx_%d_:%d_w", i, i_mokx);
		device_destroy(mokx_class, MKDEV(major, minor));
	}
}

int add_dev_mokx(int major, int mode,  int i)
{
	int i_mokx = 0;
	char nod[128];
	int ret = 0;
	int minor;
	
	for (i_mokx= 0; i_mokx < RDMA_NODE_DEV; i_mokx ++) {
		minor = RDMA_NODE_IOLINKS * i * RDMA_NODE_DEV + i_mokx;
		sprintf(nod,"mokx_%d_:%d_r", i, i_mokx);
		pr_info("make node /sys/class/mokx/%s\n", nod);
		if (device_create(mokx_class, NULL, MKDEV(major,
		    minor), NULL, nod) == NULL) {
			pr_err("create dev: %s a node: %d failed\n", 
			       nod, i);
			return -1;
		}
		minor ++;
		sprintf(nod,"mokx_%d_:%d_w", i, i_mokx);
		pr_info("make node /sys/class/mokx/%s\n", nod);
		if (device_create(mokx_class, NULL, MKDEV(major,
		    minor), NULL, nod) == NULL) {
			pr_err("create dev: %s a node: %d failed\n", 
			       nod, i);
			return -1;
		}
	}	
	return ret;
}

int create_dev_mokx(int major)
{
	int i = 0,
	    mode = 0,
	    ret = 0;
	
	/* 
	 * Create mokx nodes in /sysfs 
	 */
	mokx_class = class_create(THIS_MODULE, "mokx");
	if (IS_ERR(mokx_class)) {
		pr_err("Error creating class: /sys/class/mokx.\n");
	}
	//for_each_rdma(i) {
	for_each_online_rdma(i) 
		if (add_dev_mokx(major, mode,  i))
			ret = -1;
	return ret;
}

int remove_dev_mokx(int major)
{
	int i = 0;
	
	/*
	 * Remove rdma nodes in /sysfs 
	 */
	for_each_rdma(i) 
		del_dev_mokx(major, i);
	class_destroy(mokx_class);
	return 0;
}	

module_init(rdma_init);
module_exit(rdma_cleanup);
