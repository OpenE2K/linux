#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/fb.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/apic.h>
#include <asm/uaccess.h>
#include <linux/pci.h>
#include <linux/mcst/ddi.h>
#include <asm-l/bootinfo.h>
#include <linux/mcst/rdma_user_intf.h>
#include <asm/setup.h>
#ifdef CONFIG_E90S
#include <asm/e90s.h>
#ifndef LINUX_2_33_DBG
#include <asm/mpspec.h>
#endif
#endif
#ifdef CONFIG_E2K
#include <asm/e2k.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/e2k_sic.h>
#include <asm/uaccess.h>
#endif
#ifndef LINUX_2_33_DBG
#include <asm/iolinkmask.h>
#include <linux/topology.h>
#endif
#include "rdma_regs.h"
#include "rdma.h"
#include "rdma_error.h"

#define NUM_NODE_RDMA(num_link_rdma)	(int)(num_link_rdma/NODE_NUMIOLINKS)
#define NUM_LINK_IN_NODE_RDMA(num_link_rdma)\
	(num_link_rdma - ((int)(num_link_rdma/NODE_NUMIOLINKS))*NODE_NUMIOLINKS)

#define DSF_NO 1

#ifndef VM_RESERVED
#define VM_RESERVED (VM_DONTEXPAND | VM_DONTDUMP)
#endif

MODULE_LICENSE("GPL");

/* Set ATL */
unsigned int tr_atl;
static int  atl_v = TR_ATL_B;
module_param(atl_v, int, 0);
MODULE_PARM_DESC(atl_v, "Changes the value of ATL (alive timer limit) reg CAM.");

/* Struct for class rdma in sysfs */
static struct class *rdma_class;

/*********************************************************************/ 
/* Enable RFSM - rfsm.				             	     */
/* 		 rfsm  = ENABLE_RFSM  - RFSM disable (default).      */
/* 		 rfsm  = DMA_RCS_RFSM - RFSM enable.		     */
/*********************************************************************/ 
#define CLEAR_RFSM 	 DISABLE_RFSM
unsigned int rfsm = CLEAR_RFSM;

/*********************************************************************/ 
/* Enable exit GP0 - enable_exit_gp0.				     */
/* 		 enable_exit_gp0  = 0 - disable (default).    	     */
/* 		 enable_exit_gp0  = 1 - RFSM enable.		     */
/*********************************************************************/ 
unsigned int enable_exit_gp0 = DISABLE_EXIT_GP0;

extern int rdma_present;
unsigned int e0regad;
unsigned int e1regad;
unsigned int count_read_sm_max = 800;
unsigned int intr_rdc_count[MAX_NUMIOLINKS];
unsigned int msg_cs_dmrcl;
unsigned int state_cam = 0;
unsigned long time_ID_REQ;
unsigned long time_ID_ANS;
unsigned int state_GP0;
link_id_t rdma_link_id;

#ifdef CONFIG_COMPAT
static int 	do_ioctl(struct file *f, unsigned cmd, unsigned long arg);
static long 	rdma_compat_ioctl(struct file *f, unsigned cmd,
				   unsigned long arg);
#endif
static long 	rdma_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg);
/* static int	rdma_ioctl(struct inode *inode, struct file *filp, 
			   unsigned int cmd, unsigned long arg); */
static ssize_t	rdma_read(struct file *, char *, size_t, loff_t *);
static ssize_t	rdma_write(struct file *, const char *, size_t, loff_t *);
static int	rdma_open(struct inode *inode, struct file *file);
static int	rdma_close(struct inode *inode, struct file *file);
static int 	rdma_mmap(struct file *file, struct vm_area_struct *vma);
void		test_send_msg_rdma(unsigned int i, unsigned int msg);
int		get_file_minor(struct file *file);
void		init_reg(void);
void		free_chan(dma_chan_t *chd);
void		rdma_mem_free(size_t size, dma_addr_t dev_memory,
			       unsigned long dma_memory);
void		init_rdma_sti(int instance);
void		read_regs_rdma(int);
int		rdma_mem_alloc(int node, size_t size, dma_addr_t *mem,
			        size_t *real_size, unsigned long *dma_memory);
int		init_chan(dma_chan_t *chd, int reqlen, int tm);
int		write_buf(rdma_state_inst_t *xsp, const char *buf,
			unsigned int size, int instance, int channel,
    			rdma_ioc_parm_t *parm);
int		read_buf(rdma_state_inst_t *xsp, const char *buf, int size,
			  int instance, int channel, rdma_ioc_parm_t *parm);
int		rdma_remap_page(void *va, size_t sz, 
				struct vm_area_struct *vma);
int		rdma_remap_page_tbl(void *va, size_t sz, 
				    struct vm_area_struct *vma);
long		wait_time_rdma(struct rdma_reg_state *rdma_reg_state, 
			       signed long timeout);
int		rdma_check_buf(unsigned long addr_buf, unsigned int cnst,
				unsigned int need_free_page, char *prefix);

int 		mk_unlink(char *filename);
int 		mk_rm_dir(char *dir);
int 		mk_mkdir(char *pathname, int mode);
int 		mk_mknod(char *filename, int mode, dev_t dev);
unsigned long	join_curr_clock( void );
unsigned int	RDR_rdma(unsigned int reg, unsigned int node);
void 		WRR_rdma(unsigned int reg, unsigned int node, unsigned int val);

int 		create_dev_rdma(int major);
int 		remove_dev_rdma(int major);


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

#ifdef CONFIG_E90S
#define NBSR_INF_CFG	   	0x7088    /* 4 Node Configuration Information */
#define IO_HAB_FLAG 		0x00000080
#define E90_IO_CSR_ch_on 	0x80000000
#define E90_RDMA_CS_ch_on	0x80000000
#define	IOHUB_IOL_MODE		0 /* controller is IO HUB */
#define	RDMA_IOL_MODE		1 /* controller is RDMA */
#define	IOHUB_ONLY_IOL_ABTYPE	1 /* abonent has only IO HUB controller */
#define	RDMA_ONLY_IOL_ABTYPE	2 /* abonent has only RDMA  controller */
#define	RDMA_IOHUB_IOL_ABTYPE	3 /* abonent has RDMA and IO HUB controller */
#define E90_IOL_CSR_abtype_mask	0x007f0000
#undef  numa_node_id
#define	numa_node_id()		e90s_cpu_to_node(raw_smp_processor_id())
#undef  num_possible_rdmas
#define num_possible_rdmas()	node_rdma_num
#undef  num_online_rdmas
#define num_online_rdmas()	node_online_rdma_num
#undef  for_each_rdma
#define for_each_rdma(node)	\
	for (node = 0; node < MAX_NUMIOLINKS; node++)	\
		if (!((node_rdma_map >> node) & 0x00000001))	\
			continue; else
#undef  for_each_online_rdma
#define for_each_online_rdma(node)	\
	for (node = 0; node < MAX_NUMIOLINKS; node++ )	\
		if (!((node_online_rdma_map >> node) & 0x00000001))	\
			continue; else
#undef	SIC_io_reg_offset	/* FIXME: defined at e90s.h */
#define	SIC_io_reg_offset(io_link, reg)	((reg) + 0x1000 * (io_link))

static inline unsigned int
sic_read_node_iolink_nbsr_reg(int node_id, unsigned int io_link, int reg_offset)
{
	unsigned int reg_value;

	reg_value =  __raw_readl(BASE_NODE0 + node_id * NODE_OFF + 
			SIC_io_reg_offset(io_link, reg_offset));
	return (reg_value);
}

static inline void
sic_write_node_iolink_nbsr_reg(int node_id, int io_link, 
			       unsigned int reg_offset, unsigned int reg_value)
{
	__raw_writel(reg_value, BASE_NODE0 + node_id * NODE_OFF + 
			SIC_io_reg_offset(io_link, reg_offset));
}

#if 0
static inline unsigned int
sic_read_nbsr_reg(int reg_offset)
{
	return (sic_read_node_nbsr_reg(numa_node_id(), reg_offset));
}

static inline void
sic_write_nbsr_reg(int reg_offset, unsigned int reg_value)
{
	sic_write_node_nbsr_reg(numa_node_id(), reg_offset, reg_value);
}
#endif


unsigned int	node_rdma_map = 0;
unsigned int	node_online_rdma_map = 0;
int		node_rdma_num = 0;
int		node_online_rdma_num = 0;


void init_node_e90s( void )
{
/* Until no support NUMA for sparc V9 in kernel*/
	unsigned int 	node_iohub_map = 0;
	unsigned int	node_online_iohub_map = 0;
	int		node_iohub_num = 0;
	int		node_online_iohub_num = 0;
	unsigned int	node_mask = 0, cpu_mask = 0, i;
	int 		node;
	int 		link_on;
	unsigned int 	reg;

	for_each_online_cpu(node) {
		cpu_mask = cpu_mask | (1 << node);
	}
	for (i = 0; i < MAX_NUMIOLINKS; i++ ) {
		if ((cpu_mask >> E90S_MAX_NR_NODE_CPUS*i) & 0x0000000f)
			node_mask = node_mask | (1 << i);
	}
	for (i = 0; i < MAX_NUMIOLINKS; i++ )
	{
		if ((node_mask >> i) & 0x00000001)
		node = i;
			else continue;
#define DBG_REG_RDMA 0
#if DBG_REG_RDMA
		reg = RDR_rdma( NBSR_INT_CFG, node);
		printk("NBSR_INT_CFG: %x \n", reg);
		reg = RDR_rdma(NBSR_INF_CFG, node);
		printk("NBSR_INF_CFG: %x \n", reg);
		reg = RDR_rdma(NBSR_NODE_CFG, node);
		printk("NBSR_NODE_CFG: %x \n", reg);
		reg = RDR_rdma(SHIFT_IO_CSR,node);
		printk("SHIFT_IO_CSR: %x \n",  reg);
		reg = RDR_rdma(SHIFT_CS, node);
		printk("SHIFT_CS: %x \n", reg);
#endif
		link_on = 0;
		reg = RDR_rdma(NBSR_NODE_CFG, node);
		printk("Node #%d IO LINK is", node);

		if ((reg & IO_HAB_FLAG) == IOHUB_IOL_MODE) {
			node_iohub_map = node_iohub_map | (1 << node);
			node_iohub_num ++;
			printk(" IO HUB controller");
			reg =
				RDR_rdma(SHIFT_IO_CSR, node);
			if (reg & E90_IO_CSR_ch_on) {
				node_online_iohub_map = node_online_iohub_map |
						 (1 << node);
				node_online_iohub_num ++;
				link_on = 1;
				printk(" ON");
			} else {
				printk(" OFF");
			}
		} else {
			node_rdma_map = node_rdma_map | (1 << node);
			node_rdma_num ++;
			printk(" RDMA controller");
			reg = RDR_rdma(SHIFT_CS, node);
			if (reg & E90_RDMA_CS_ch_on) {
				node_online_rdma_map = node_online_rdma_map |
						 (1 << node);
				node_online_rdma_num ++;
				link_on = 1;
				printk(" ON");
			} else {
				printk(" OFF");
			}
		}

		if (link_on) {
			reg = RDR_rdma(	NBSR_INF_CFG, node);
			int ab_type = (reg & E90_IOL_CSR_abtype_mask) >> 16 ;

			printk(" connected to");
			switch (ab_type) {
			case IOHUB_ONLY_IOL_ABTYPE:
				printk(" IO HUB controller");
				break;
			case RDMA_ONLY_IOL_ABTYPE:
				printk(" RDMA controller");
				break;
			case RDMA_IOHUB_IOL_ABTYPE:
				printk(" IO HUB/RDMA controller");
				break;
			default:
				printk(" unknown controller");
				break;
			}
		}

	printk(" \n");
	}
}
#endif


static inline void
sic_write_node_nbsr_reg_rdma(int node_id, unsigned int reg_offset,
			      unsigned int reg_value)
{
	sic_write_node_iolink_nbsr_reg(NUM_NODE_RDMA(node_id), 
				       NUM_LINK_IN_NODE_RDMA(node_id),
				       reg_offset, reg_value );
}

static inline unsigned int
sic_read_node_nbsr_reg_rdma(int node_id, int reg_offset)
{
	unsigned int reg_value;
	reg_value = sic_read_node_iolink_nbsr_reg(NUM_NODE_RDMA(node_id), 
			NUM_LINK_IN_NODE_RDMA(node_id), reg_offset );
	return (reg_value);
}

unsigned long join_curr_clock( void )
{
	unsigned long ret;
#ifdef CONFIG_E90S	/* E90S */
	ret = get_cycles();
#else 			/* E3S */
	ret = E2K_GET_DSREG(clkr);
#endif 			/* E90S */
	return ret;
}

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
unsigned int	rdc_byte;

void WRR_rdma(unsigned int reg, unsigned int node, unsigned int val)
{
	/* sic_write_node_iolink_nbsr_reg(node, io_link, reg, val); */
	sic_write_node_nbsr_reg_rdma(node, reg, val);
	fix_event(node, WRR_EVENT, reg, val);
}

EXPORT_SYMBOL(WRR_rdma);

unsigned int RDR_rdma(unsigned int reg, unsigned int node)
{
	unsigned int	val;

	/* val = sic_read_node_iolink_nbsr_reg(node, io_link, reg); */
	val = sic_read_node_nbsr_reg_rdma(node, reg);
	fix_event(node, RDR_EVENT, reg, val);
	return val;
}

EXPORT_SYMBOL(RDR_rdma);

#if defined(TRACE_LATENCY) || defined(TRACE_LATENCY_MSG) || \
    defined(TRACE_LATENCY_SM)
void	user_trace_stop_my(void)
{
#ifdef CONFIG_FUNCTION_TRACER
	tracing_stop();
#endif
}

void	user_trace_start_my(void)
{
#ifdef CONFIG_FUNCTION_TRACER
	tracing_start();
#endif
}
#endif

unsigned int allign_dma(unsigned int n)
{
	if (n&(ALLIGN_RDMA-1)) {
		n += ALLIGN_RDMA;
		n = n&(~(ALLIGN_RDMA-1));
	}
        return n;
}

int	MCG_CS_SEND_ALL_MSG =
		(MSG_CS_SD_Msg  | MSG_CS_SGP0_Msg | MSG_CS_SGP1_Msg |
		MSG_CS_SGP2_Msg | MSG_CS_SGP3_Msg | MSG_CS_SL_Msg   |
		MSG_CS_SUL_Msg  | MSG_CS_SIR_Msg);
int	MSG_CS_MSF_ALL = MSG_CS_DMPS_Err | MSG_CS_MPCRC_Err | MSG_CS_MPTO_Err |
		 	 MSG_CS_DMPID_Err;
unsigned int	count_loop_send_msg_max = 10;
unsigned int	count_wait_rdm_max = 64;

dev_rdma_sem_t *msg_snd_dev[2];

hrtime_t
rdma_gethrtime(void)
{
	struct timeval tv;
	hrtime_t val;
	do_gettimeofday(&tv);
	val = tv.tv_sec * 1000000000LL + tv.tv_usec * 1000LL;
	return (val);
}

extern int wake_up_state(struct task_struct *p, unsigned int state);

static void __raw_wake_up_common_from_ddi(raw_wait_queue_head_t *q)
{
	struct list_head *tmp, *next;
	raw_wait_queue_t *curr;

	list_for_each_safe(tmp, next, &q->task_list) {
		curr = list_entry(tmp, raw_wait_queue_t, task_list);
		//wake_up_state(curr->task, TASK_UNINTERRUPTIBLE |
		//		TASK_INTERRUPTIBLE);
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

int ddi_cv_broadcast_from_ddi(kcondvar_t *cvp)
{
	__raw_wake_up_from_ddi(cvp);
        return 0;
}

int rdma_cv_broadcast_rdma(void* dev_rdma_sem, unsigned int instance)
{
	rdma_addr_struct_t	p_xxb;

	dev_rdma_sem_t 	*dev = dev_rdma_sem;
	dev->irq_count_rdma++;
	dev->time_broadcast = join_curr_clock();
	p_xxb.addr = (unsigned long)dev;
	fix_event(instance, RDMA_BROADCAST, p_xxb.fields.laddr, 
		  dev->irq_count_rdma);
	ddi_cv_broadcast_from_ddi(&dev->cond_var);
	return (0);
}

/* Convert mksec to HZ */
clock_t
drv_usectohz_from_ddi(register clock_t mksec)
{
        clock_t  	clock;
	struct timespec rqtp;

	rqtp.tv_nsec = ((mksec % 1000000L) * 1000L);
	rqtp.tv_sec  = mksec / 1000000L;
	DEBUG_MSG("drv_usectohz: start, mksec = 0x%lx\n", mksec);
	DEBUG_MSG("drv_usectohz: rqtp.tv_nsec = 0x%lx, rqtp.tv_sec  = 0x%lx\n",
		rqtp.tv_nsec, rqtp.tv_sec);
	clock = timespec_to_jiffies(&rqtp);
	return (clock);
}
int
ddi_cv_spin_timedwait_from_ddi(kcondvar_t *cvp, raw_spinlock_t *lock, long tim)
{
        unsigned long   	expire;
        int            	 	rval = 0;
	int 			raw_spin_locking_done	= 0;
        struct task_struct 	*tsk = current;
	DECLARE_RAW_WAIT_QUEUE(wait);
        expire = tim - jiffies;
        tsk->state = TASK_INTERRUPTIBLE;
	raw_add_wait_queue_from_ddi(cvp, &wait);
	raw_spin_locking_done = raw_spin_is_locked(lock);
	if(raw_spin_locking_done)
 	       spin_mutex_exit(lock);

	fix_event(0, WAIT_TRY_SCHTO_EVENT,
		(unsigned int)expire, 0);
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
			   unsigned int instance)
{
	unsigned int	time_current;
	unsigned int	delta_time;
	dev_rdma_sem_t 	*dev = dev_rdma_sem;
	rdma_addr_struct_t	p_xxb;
	int		ret = 0;
	signed long	timeout_tick;

	if (!raw_spin_is_locked(&dev->lock)) {
	        printk("wait_for_irq_rdma_sem: spin is NOT locked:dev: %p\n",
		       dev);
		return -3;
	}
	if (dev->irq_count_rdma) {
	        printk("wait_for_irq_rdma_sem(%p): dev->irq_count_rdma: %u"
		       "num_obmen: %u\n", &dev->lock, dev->irq_count_rdma, 
	 		(unsigned int)dev->num_obmen);
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
			fix_event(instance, WAIT_RET_SCHT0_EVENT, delta_time, 
				  dev->num_obmen);
			fix_event(instance, WAIT_RET_SCHT0_EVENT, 
				  dev->irq_count_rdma,
					dev->num_obmen);
			dev->time_broadcast = 0;
		}
		return(1);
	}
	p_xxb.addr = usec_timeout;
	fix_event(instance, WAIT_TRY_SCHTO_EVENT,
		p_xxb.fields.laddr, dev->num_obmen);
	timeout_tick = (unsigned long)jiffies;
	timeout_tick += usec_timeout;
	ret = ddi_cv_spin_timedwait_from_ddi(&dev->cond_var, &dev->lock,
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
		fix_event(instance, WAIT_RET_SCHT1_EVENT, ret, dev->num_obmen);
		dev->time_broadcast = 0;
	} else {
		fix_event(dev->irq_count_rdma, WAIT_RET_SCHT2_EVENT, ret,
				dev->num_obmen);
	}

	return ret;
}

rdma_event_t 	rdma_event;
int		rdma_event_init = 0;

#include "get_event_rdma.c"

void	fix_event_proc(unsigned int channel, unsigned int event, 
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

DECLARE_WAIT_QUEUE_HEAD(wqh_1);

#include "rdma_intr.c"
#include "rdma_read_buf.c"
#include "rdma_write_buf.c"
#include "rdma_send_msg.c"

struct rdma_state *rdma_state;

int	irq_mc;

struct rdma_reg_state rdma_reg_state[MAX_NUMIOLINKS];

static int __init rdma_init(void)
{
	unsigned int			i;
	int				node;
	int				major;
	size_t				size_rdma_state;
	rdma_addr_struct_t		p_xxb;
	DEBUG_MSG("rdma_init: START\n");
	DEBUG_MSG("rdma_init: %lx - raw_spinlock_t\n", sizeof (raw_spinlock_t));
	DEBUG_MSG("rdma_init: %lx - spinlock_t\n", sizeof (spinlock_t));

#if RDMA_PRN_ADDR_FUN
	printk("ADDR_FUN: %p - static rdma_ioctl\n", rdma_ioctl);
	printk("ADDR_FUN: %p - static rdma_read\n",  rdma_read);
	printk("ADDR_FUN: %p - static rdma_write\n", rdma_write);
	printk("ADDR_FUN: %p - static rdma_open\n",  rdma_open);
	printk("ADDR_FUN: %p - static rdma_close\n", rdma_close);
	printk("ADDR_FUN: %p - static rdma_mmap\n",  rdma_mmap);
	printk("ADDR_FUN: %p - get_file_minor\n",    get_file_minor);
	printk("ADDR_FUN: %p - free_chan\n",         free_chan);
	printk("ADDR_FUN: %p - rdma_mem_free\n",     rdma_mem_free);
	printk("ADDR_FUN: %p - init_rdma_sti\n",     init_rdma_sti);
	printk("ADDR_FUN: %p - read_regs_rdma\n",    read_regs_rdma);
	printk("ADDR_FUN: %p - rdma_mem_alloc\n",    rdma_mem_alloc);
	printk("ADDR_FUN: %p - init_chan\n",         init_chan);
	printk("ADDR_FUN: %p - write_buf\n",         write_buf);
	printk("ADDR_FUN: %p - read_buf\n",          read_buf);
	printk("ADDR_FUN: %p - rdma_remap_page\n",   rdma_remap_page);
#endif

	if (!HAS_MACHINE_E2K_FULL_SIC) {
		ERROR_MSG("rdma_init: sorry, I am worked on e3s/e90s/e2s\n");
		DEBUG_MSG("rdma_init: FINISH\n");
		return -ENODEV;
	}
	if (!rdma_present) {
		rdma_present = 1;
	} else {
		ERROR_MSG("rdma_init: RDMA registers busy. \n");
		return -ENODEV;
	}
#ifdef CONFIG_E90S
	init_node_e90s();
#endif
	if (!num_possible_rdmas()) {
		ERROR_MSG("rdma_init: hard rdma is absent\n");
		rdma_present = 0;
		return -ENODEV;
	}
	if (!num_online_rdmas()) {
		ERROR_MSG("rdma_init: RDMA does not support hot plugging."
		          "Connect the cable and reboot machine.\n");
		rdma_present = 0;
		return -ENODEV;
	}
	rdma_event_init = 1;
#ifdef CONFIG_E90S
	INFO_MSG("RDMA: I am worked on E90S, NODE_NUMIOLINKS: %d"
		 "MAX_NUMIOLINKS: %d\n ", NODE_NUMIOLINKS, MAX_NUMIOLINKS);
	INFO_MSG("E90S. Loopback mode is not implemented.\n");
#else /* E3S */
	INFO_MSG("I am worked on E3S/CUBIC/E2S, NODE_NUMIOLINKS: %d "
		 "MAX_NUMIOLINKS: %d\n", NODE_NUMIOLINKS, MAX_NUMIOLINKS);
	if (IS_MACHINE_E3S) {
		INFO_MSG("E3S. Loopback mode is not implemented.\n");
	}
	if (IS_MACHINE_ES2) {
		INFO_MSG("CUBIC. Loopback mode is not implemented.\n");
	}
	if (IS_MACHINE_E2S) {
		INFO_MSG("E2S. Loopback mode implemented.\n");
		INFO_MSG("E2S. IS_MACHINE_E2S: %d IS_MACHINE_E2S: %x.\n",
			 IS_MACHINE_E2S, IS_MACHINE_E2S);
	}
#endif
	node = numa_node_id();
	fix_event(node, RDMA_INIT, START_EVENT, 0);
	major = register_chrdev(0, board_name, &rdma_fops);
	if ( major < 0 ) {
		ERROR_MSG("rdma_init: There isn't free major\n");
		goto failed;
	}
	DEBUG_MSG("rdma_init: major: %d\n", major);
	DEBUG_MSG("rdma_init: I am on %d numa_node_id\n", node);
	DEBUG_MSG("rdma_init: %lx: sizeof (nodemask_t)\n", sizeof (nodemask_t));

	rdma_interrupt_p = rdma_interrupt;

	size_rdma_state = sizeof (struct rdma_state);
	rdma_state = (struct rdma_state *)kmalloc(size_rdma_state, GFP_KERNEL);
	if (rdma_state == (struct rdma_state *)NULL) {
		ERROR_MSG("rdma_init: rdma_state == NULL\n");
		unregister_chrdev(major, board_name);
		rdma_present = 0;
		return (-EFAULT);
	}
	memset(rdma_state, 0, size_rdma_state);
	DEBUG_MSG("rdma_init: sizeof (struct rdma_state): %x\n",
		   size_rdma_state);
	rdma_state->size_rdma_state = size_rdma_state;
	rdma_state->major = major;
	for_each_online_rdma(i) {
		WRR_rdma(SHIFT_CH_IDT, i, (l_base_mac_addr[3] + i) |
		 ((l_base_mac_addr[4] + i) << 8));
		init_rdma_sti(i);
	}
	for_each_online_rdma(i) {
		unsigned int cs;
		cs = RDR_rdma(SHIFT_CS, i);
#ifdef CONFIG_E2K		
		if (IS_MACHINE_E2S) 
			WRR_rdma(SHIFT_CS, i, cs | CS_DSM | E2S_CS_PTOCL );
		else
			WRR_rdma(SHIFT_CS, i, cs | CS_DSM );
#else		 
		WRR_rdma(SHIFT_CS, i, cs | CS_DSM );
#endif			 
		printk("SHIFT_CS: %x\n", RDR_rdma(SHIFT_CS, i));
		
		WRR_rdma(SHIFT_DMA_TCS, i, DMA_TCS_Tx_Rst);
		WRR_rdma(SHIFT_DMA_TCS, i, 
			 RDR_rdma(SHIFT_DMA_TCS, i) | RCode_64 | DMA_TCS_DRCL);
#define COUNT_RESET_RCS 10		
		int count = 0;
		for (count = 1; count < COUNT_RESET_RCS; count++)
			WRR_rdma(SHIFT_DMA_RCS, i, DMA_RCS_Rx_Rst);
		WRR_rdma(SHIFT_DMA_RCS, i, RDR_rdma(SHIFT_DMA_RCS, i) | WCode_64);
	}
	tr_atl = ATL_B | (atl_v & ATL);
	printk("Reg CAM ATL: %x\n", tr_atl);
	irq_mc =
			IRQ_RDM		|
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
			/* IRQ_DSF	| */
#else
			IRQ_DSF		|
#endif						
			IRQ_TDC		|
			IRQ_RDC		|
			IRQ_CMIE
			;
	for_each_online_rdma(i) {
		WRR_rdma(SIC_rdma_irq_mc, i ,irq_mc);
		//read_regs_rdma(i);
	}
	msg_cs_dmrcl = MSG_CS_DMRCL;
	for_each_online_rdma(i) {
		rdma_state_inst_t	*xsp;
		int			ret = 0;

		p_xxb.addr = (unsigned long)&rdma_state->rdma_sti[i];
		DEBUG_MSG("rdma_init:link:%d rdma_state->rdma_sti:0x%08x%08x\n",
		i, p_xxb.fields.haddr, p_xxb.fields.laddr);
		xsp = &rdma_state->rdma_sti[i];
		ret = send_msg(xsp, 0, i, MSG_CS_SIR_Msg, 0);
		if (ret < 0) {
			ERROR_MSG("rdma_init: FAIL send MSG_CS_SIR_Msg from"
				  "link: %x ret: %d\n", i, ret);
		} else
			if (ret == 0) {
				printk("rdma_init: FAIL send MSG_CS_SIR_Msg"
				       "from link: %x. SM is absent\n", i);
			}
	}
#ifdef MODULE
	if (create_dev_rdma(major))
		printk("rdma_init: Error creating devices. "
				"Create a device manually.");
#endif
	return 0;
failed:
	DEBUG_MSG("rdma_init: FINISH\n");
	fix_event(node, RDMA_INIT, RETURN_EVENT, 0);
	rdma_present = 0;
	return -ENODEV;
}

long wait_time_rdma(struct rdma_reg_state *rdma_reg_state, signed long timeout)
{
	DECLARE_WAITQUEUE(wait, current);
	long ret;

	add_wait_queue(&rdma_reg_state->wqh_d, &wait);
	set_task_state(current, TASK_INTERRUPTIBLE);
	ret = schedule_timeout(timeout);
	__set_current_state(TASK_RUNNING);
	remove_wait_queue(&rdma_reg_state->wqh_d, &wait);
	return ret;
}

unsigned char	bus_number_rdma, devfn_rdma;

static void rdma_cleanup(void)
{
	int	i, major;
	DEBUG_MSG("rdma_cleanup: START\n");
	DEBUG_MSG("rdma_cleanup: rdma_state->major %d \n",
		   (int)rdma_state->major);
	major = (int)rdma_state->major;
	for_each_online_rdma(i) {
		WRR_rdma(SIC_rdma_irq_mc, i,  0x0);
	}
	rdma_interrupt_p = (void *) NULL;
#ifdef MODULE
	remove_dev_rdma(rdma_state->major);
#endif
	unregister_chrdev(rdma_state->major, board_name);
	rdma_event_init = 0;
	kfree(rdma_state);
	if (rdma_present)
		rdma_present = 0;
	DEBUG_MSG("rdma_cleanup: FINISH\n");
    return;
}

static int rdma_close(struct inode *inode, struct file *file)
{
	int		minor;
	int		instance;
	int		channel;
	dma_chan_t	*chd;
	rdma_state_inst_t	*rdma_sti;

	DEBUG_MSG("rdma_close: START\n");
	minor = get_file_minor(file);
	if (minor < 0) {
		ERROR_MSG("rdma_close: minor < 0: %d \n",
			minor);
		return minor;
	}
	instance = DEV_inst(minor);
	channel = DEV_chan(minor);
	DEBUG_MSG("rdma_close: instance: %d channel: %d\n", instance, channel);
	rdma_sti = &rdma_state->rdma_sti[instance];
	mutex_enter(&rdma_sti->mu);
	rdma_sti->opened &= ~(1 << channel);
	if (channel < 7) {
		chd = &rdma_sti->dma_chans[channel];
		free_chan(chd);
	}
/* to properly complete the exchange */
/*
	for (i = 0; i < 2; i++){
		pd = &rdma_sti->rw_states_d[i];
		pd->trwd_was = 0;
		pd->clock_receive_trwd = 0;
		pd->clock_begin_read = 0;
		pd->clock_end_read_old = 0;
		pd->clock_begin_read_old = 0;
		pd->trwd_send_count = 0;
		pd->ready_send_count = 0;
		pd->trwd_rec_count = 0;
		pd->ready_rec_count = 0;
//		pd->n_ready = 0;
		pd->stat = 0;
		pd->timer_read = TIMER_MIN;
		pd->timer_write = TIMER_MIN;
		pd->timer_for_read = TIMER_FOR_READ_MIN;
		pd->timer_for_write = TIMER_FOR_WRITE_MIN;
	}
*/
	DEBUG_MSG("rdma_close: opened.minor.instance.channel: 0x%x.%d.%d.%d\n",
		rdma_sti->opened, minor, instance, channel);
	mutex_exit(&rdma_sti->mu);
	DEBUG_MSG("rdma_close: FINISH\n");
	return 0;
}

static int rdma_open(struct inode *inode, struct file *file)
{
	int	minor, file_eys = 0, i;
	int	instance;
	int	firstopen = 0;
	int	channel;
	rdma_state_inst_t	*rdma_sti;

	DEBUG_MSG("rdma_open: START\n");
	if (file == (struct file *)NULL) {
		ERROR_MSG("rdma_open: file is NULL\n");
		return (-EINVAL);
	}
	minor = get_file_minor(file);
	if (minor < 0) {
		ERROR_MSG("rdma_open: minor(%d) < 0\n", minor);
		return (-EINVAL);
	}
	instance = DEV_inst(minor);
	for_each_online_rdma(i)
		if (i == instance)
			file_eys++;
	if (!file_eys) {
		ERROR_MSG("rdma_open:instance %d not support RDMA\n", instance);
		return (-EINVAL);
	}
	channel = DEV_chan(minor);
	DEBUG_MSG("rdma_open: instance: %d channel: %d\n", instance, channel);
	rdma_sti = &rdma_state->rdma_sti[instance];
	mutex_enter(&rdma_sti->mu);
	firstopen = (((1 << channel) & rdma_sti->opened) == 0);
	if (firstopen == 0) {
		ERROR_MSG("rdma_open: device EBUSY: minor: %d inst: %d "
			  "channel: %d\n", minor, instance, channel);
		mutex_exit(&rdma_sti->mu);
		return (-EBUSY);
	}
	rdma_sti->opened |= (1 << channel);
	DEBUG_MSG("rdma_open: opened.minor.instance.channel: 0x%x.%d.%d.%d\n",
		rdma_sti->opened, minor, instance, channel);
	mutex_exit(&rdma_sti->mu);
	DEBUG_MSG("rdma_open FINISH\n");
	return 0;
}

/*static int rdma_ioctl(struct inode *inode, struct file *filp,
                 unsigned int cmd, unsigned long arg) */
static long rdma_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int			minor;
	int			instance;
	int			channel;
	int			res = 0;
	dma_chan_t		*chd;
	rdma_state_inst_t	*rdma_sti;
	rdma_ioc_parm_t 	parm;
	size_t			rval;
	dev_rdma_sem_t		*dev_sem;
	rw_state_p		pd;
//	long ret;
	DEBUG_MSG("rdma_ioctl: START cmd %x\n", cmd);
	minor = get_file_minor(filp);
	if (minor < 0) {
		ERROR_MSG("rdma_ioctl: minor(%d) < 0 cmd: %x\n", 
			  (int)minor, cmd);
		return minor;
	}
	instance = DEV_inst(minor);
	channel = DEV_chan(minor);
	rdma_sti = &rdma_state->rdma_sti[instance];
	switch (cmd) {
	case RDMA_IOC_GET_neighbour_map:
	{
		if (copy_to_user((void __user *)arg, &node_online_neighbour_map,
		    sizeof (nodemask_t)) == -1) {
			ERROR_MSG("rdma_ioctl: RDMA_IOC_GET_neighbour_map: "
				  "copy_to_user failed\n");
			return EINVAL;
		}
		return 0;
		break;
	}
	case RDMA_IOC_GET_ID:
	{
		int	i;
/*
		rdma_state_inst_t	*xsp;
		int	ret;
		for_each_online_rdma(i) {
			xsp = &rdma_state->rdma_sti[i];
			ret = send_msg(xsp, 0, i, MSG_CS_SIR_Msg, 0);
			if (ret < 0) {
				ERROR_MSG("rdma_ioctl: FAIL send MSG_CS_SIR_Msg"
					  "from link: %x ret: %d\n", i, ret);
			} else if (ret == 0) {
				printk("rdma_ioctl: FAIL send MSG_CS_SIR_Msg"
				       "from link: %x. " "SM is absent\n", i);
			}
		}
		mdelay(30);
*/		
		rdma_link_id.count_links = MAX_NUMIOLINKS;
		for_each_online_rdma(i) {
			rdma_link_id.link_id[i][0] = 1;
			rdma_link_id.link_id[i][1] = RDR_rdma(SHIFT_CH_IDT, i);
			rdma_link_id.link_id[i][2] = RDR_rdma(SHIFT_N_IDT, i);
			if (copy_to_user((void __user *)arg, &rdma_link_id,
			    sizeof(link_id_t)) == -1) {
				ERROR_MSG("rdma_ioctl:RDMA_IOC_GET_ID:"
					  "copy_to_user failed\n");
				return EINVAL;
			}
		}
		return 0;
		break;
	}
	/* Reset DMA */	
	case RDMA_IOC_RESET_DMA:
	{
		reset_link_t reset_link;
		rw_state_p pd = NULL;
		dev_rdma_sem_t *dev_sem;
		rdma_state_inst_t	*xsp;
		
		xsp = &rdma_state->rdma_sti[instance];

		rval = copy_from_user(&reset_link, (void __user *)arg, 
				       sizeof (reset_link_t));
		if (rval) {
			ERROR_MSG("rdma_ioctl(%d, %d, %x): copy_from_user"
					"failed size: %lx rval: %lx\n", 
     					instance, channel, cmd, 
	  				sizeof (reset_link_t), rval);
			return -EINVAL;
		}
		if (reset_link.tcs_reset == 1) {
			/* Enable exit gp0 */	
			if (enable_exit_gp0) {	
				int ret_send_msg, j;
				for (j = 0; j < 10; j++) {
					ret_send_msg = send_msg(xsp, 0, 
								instance, 
								MSG_CS_SGP0_Msg,
								0);
					if (ret_send_msg > 0) 
						break;
					if (ret_send_msg < 0) {
						ERROR_MSG("rdma_ioctl:"
						"FAIL send MSG_CS_SGP0_Msg "
						"from link: %x ret: %d\n",
       						instance, ret_send_msg);
					} else if (ret_send_msg == 0) {
						DEBUG_MSG("rdma_ioctl: FAIL send"
						" MSG_CS_SGP0_Msg "
						"from link: %x. SM is absent: %x "
						"MSG_CS: %x \n", 
      						instance, ret_send_msg, 
      						RDR_rdma(SHIFT_MSG_CS, instance));
					}
				}
			}
		}
		if (reset_link.rcs_reset == 1) {
			/* Enable exit gp0 */	
			if (enable_exit_gp0) {	
				pd = &rdma_sti->rw_states_d[READER];
				dev_sem = &pd->dev_rdma_sem;
				raw_spin_lock_irq(&dev_sem->lock);
				pd->state_GP0 = 0;
				raw_spin_unlock_irq(&dev_sem->lock);
			}
		}
		reset_link.tcs = RDR_rdma(SHIFT_DMA_TCS, instance);
		reset_link.rcs = RDR_rdma(SHIFT_DMA_RCS, instance);
		rval = copy_to_user((reset_link_t __user *)arg, &reset_link, 
				     sizeof (reset_link));
		return 0;
		break;
	}
	
	}
	DEBUG_MSG("rdma_ioctl: minor: %d\n", minor);
	DEBUG_MSG("rdma_ioctl: sizeof (rdma_ioc_parm_t): %x," 
		  "sizeof (parm): %x\n", sizeof (rdma_ioc_parm_t),
			sizeof (parm));
	rval = copy_from_user(&parm, (void __user *)arg, 
			       sizeof (rdma_ioc_parm_t));
	if (rval) {
		ERROR_MSG("rdma_ioctl(%d, %d, %x): copy_from_user failed size:"
			  "%lx rval: %lx\n", instance, channel, cmd, 
     				sizeof (rdma_ioc_parm_t), rval);
		return -EINVAL;
	}
	
	parm.err_no = res = 0;
	switch (cmd) {
	case RDMA_IOC_RESET_TCS:
	{	
#define COUNT_RESET_TCS 100		
#define DELAY_RESET_TCS 10		
		unsigned tcs, es, i;
	
		for (i = 0; i < COUNT_RESET_TCS; i++) {
			WRR_rdma(SHIFT_DMA_TCS, instance, DMA_TCS_Tx_Rst);
			mdelay(DELAY_RESET_TCS);
			tcs = RDR_rdma(SHIFT_DMA_TCS, instance);
			es = RDR_rdma(SHIFT_ES, instance);
		}
		WRR_rdma(SHIFT_DMA_TCS, instance, RCode_64 | DMA_TCS_DRCL);		
		tcs = RDR_rdma(SHIFT_DMA_TCS, instance);
		parm.acclen = tcs;
		break;
	}
	
	case RDMA_IOC_RESET_RCS:
	{	unsigned rcs, es, i;
#define COUNT_RESET_RCS 10		
	for (i = 0; i < COUNT_RESET_RCS; i++) {
			WRR_rdma(SHIFT_DMA_RCS, instance, DMA_RCS_Rx_Rst);
			rcs = RDR_rdma(SHIFT_DMA_RCS, instance);
			es = RDR_rdma(SHIFT_ES, instance);
		}
		WRR_rdma(SHIFT_DMA_RCS, instance, WCode_64);		
		rcs = RDR_rdma(SHIFT_DMA_RCS, instance);
		parm.acclen = rcs;
		break;
	}

	case RDMA_IOC_SET_MODE_LOOP:
	{
		int rdma_loopback_mode;
#ifdef CONFIG_E2K
		if (IS_MACHINE_E2S) {
			if (parm.reqlen == DISABLE_LOOP) {
				WRR_rdma(SHIFT_CS, instance, 
				RDR_rdma(SHIFT_CS, instance) & ~E2S_CS_LOOP);
			} else {
				WRR_rdma(SHIFT_CS, instance, 
				RDR_rdma(SHIFT_CS, instance) | E2S_CS_LOOP);
			}
			rdma_loopback_mode = RDR_rdma(SHIFT_CS, instance) &
					E2S_CS_LOOP;
		} else {
			/* INFO_MSG("Loopback mode not release.\n"); */
			rdma_loopback_mode = 0;
		}
#else	
			/* INFO_MSG("Loopback mode not release.\n");*/
			rdma_loopback_mode = 0;
#endif	
		
			parm.acclen = rdma_loopback_mode;
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
	case RDMA_IOC_SET_MODE_EXIT_GP0:
	{
		if (parm.reqlen == DISABLE_EXIT_GP0) {
			enable_exit_gp0 = DISABLE_EXIT_GP0;
		} else {
			enable_exit_gp0 = ENABLE_EXIT_GP0;
		}
		parm.acclen = enable_exit_gp0;
		break;
	}
	case RDMA_IOC_DUMPREG0:
	case RDMA_IOC_DUMPREG1:
		read_regs_rdma(instance);
		break;

	case RDMA_IOC_WRR:
	{
#ifdef CONFIG_E90S
		if ((parm.reqlen == 0x900) ||
		    ((parm.reqlen >= 0x2000) && (parm.reqlen <= 0x2004)) ||
		    ((parm.reqlen >= 0x3000) && (parm.reqlen <= 0x3088))) {
			/* sic_write_node_nbsr_reg(instance, parm.reqlen,
			  parm.acclen); */
			WRR_rdma( parm.reqlen, instance, parm.acclen);
		} else {
			return -EINVAL;
		}
#else
		if ((parm.reqlen == 0x900) ||
		    ((parm.reqlen >= 0x700) && (parm.reqlen <= 0x704)) ||
		    ((parm.reqlen >= 0x800) && (parm.reqlen <= 0x888))) {
			/* sic_write_node_nbsr_reg(instance, parm.reqlen,
					parm.acclen); */
			WRR_rdma( parm.reqlen, instance, parm.acclen);
		} else {
			return -EINVAL;
		}
#endif
		break;
	}

	case RDMA_IOC_RDR:
	{
#ifdef CONFIG_E90S
		if ((parm.reqlen <= 0x900) ||
		    ((parm.reqlen >= 0x2000) && (parm.reqlen <= 0x2004)) ||
		    ((parm.reqlen >= 0x3000) && (parm.reqlen <= 0x3088))) {
			/* parm.acclen = sic_read_node_nbsr_reg(instance, 
					parm.reqlen); */
			parm.acclen = RDR_rdma(parm.reqlen, instance);
		} else {
			return -EINVAL;
		}
#else
		if ((parm.reqlen == 0x900) ||
		    ((parm.reqlen >= 0x700) && (parm.reqlen <= 0x704)) ||
		    ((parm.reqlen >= 0x800) && (parm.reqlen <= 0x888))) {
			/* sic_write_node_nbsr_reg(instance, parm.reqlen,
					parm.acclen); */
			WRR_rdma( parm.reqlen, instance, parm.acclen);
		} else {
			return  -EINVAL;
		}
#endif
		break;
	}

	case RDMA_WAKEUP_WRITER:
	{
		dev_rdma_sem_t	*dev_sem;
		rw_state_p	pd;

		pd = &rdma_sti->rw_states_d[WRITER];
		dev_sem = &pd->dev_rdma_sem;
		raw_spin_lock_irq(&dev_sem->lock);
		rdma_cv_broadcast_rdma(&pd->dev_rdma_sem, instance);
		raw_spin_unlock_irq(&dev_sem->lock);
		break;
	}

	case RDMA_WAKEUP_READER:
	{
		dev_rdma_sem_t	*dev_sem;
		rw_state_p	pd;

		pd = &rdma_sti->rw_states_d[READER];
		dev_sem = &pd->dev_rdma_sem;
		raw_spin_lock_irq(&dev_sem->lock);
		rdma_cv_broadcast_rdma(&pd->dev_rdma_sem, instance);
		raw_spin_unlock_irq(&dev_sem->lock);
		break;
	}

	case  RDMA_CLEAN_TDC_COUNT:
	{
		switch (channel) {
		case 0:
		case 1:
		case 2:
		case 3:
			pd = &rdma_sti->rw_states_d[WRITER];
			break;
		default:
			ERROR_MSG("rdma_ioctl: CLEAN_TDC: (%d,%d):"
				  "Unexpected channel\n", instance, channel);
			return -EIO;
		}
		dev_sem = &pd->dev_rdma_sem;
		dev_sem->num_obmen = 0;
		dev_sem->irq_count_rdma = 0;
		dbg_ioctl("CLEAN_TDC:  %d dev_sem->num_obmen: %x\n",
			instance, dev_sem->num_obmen);
	}
		break;
#define COUNT_CLK 10
	case  RDMA_GET_CLKR:
	{
		u64		time[COUNT_CLK];
		int		i;

		for (i = 0; i < COUNT_CLK; i++)
			time[i] = join_curr_clock();
		for (i = 0; i < COUNT_CLK; i++)
		printk("0x%llx\n", time[i]);
	}
		break;
	case  RDMA_GET_MAX_CLKR:
	{
        	u64		time[COUNT_CLK];
		u64		max_clk = 0;
        	u64		max_clk_all = 0;
		int		i;
		int		count_rep_clk = 0;

#define COUNT_REP_CLK 100
rep_max_clk:
		for (i = 0; i < COUNT_CLK; i++)
			time[i] = join_curr_clock();
		for (i = 0; i < COUNT_CLK; i++) {
			if (max_clk < time[i])
				max_clk = time[i];
		}
		if (max_clk_all < max_clk) {
			max_clk_all = max_clk;
			printk("0x%llx - max_clk_all\n", max_clk_all);
			count_rep_clk++;
			if (count_rep_clk < COUNT_REP_CLK)
				goto rep_max_clk;
		}
	}
		break;

	case  RDMA_CLEAN_RDC_COUNT:
	{
		intr_rdc_count[instance] = 0;
		switch (channel) {
		case 0:
		case 1:
		case 2:
		case 3:
			pd = &rdma_sti->rw_states_d[READER];
			break;
		default:
			ERROR_MSG("rdma_ioctl: CLEAN_RDC: (%d,%d):"
				  "Unexpected channel\n", instance, channel);
			return -EIO;
		}
		dev_sem = &pd->dev_rdma_sem;
		dev_sem->num_obmen = 0;
		dev_sem->irq_count_rdma = 0;
		dbg_ioctl("CLEAN_RDC: intr_rdc_count[%d]: %u "
			  "dev_sem->num_obmen: %x\n", instance, 
     				intr_rdc_count[instance], dev_sem->num_obmen);
	}
		break;
	
	case RDMA_TIMER_FOR_READ :
		dbg_ioctl("cmd = RDMA_TIMER_FOR_READ, "
			"reqlen (mksec) = 0x%x\n",
			MIN_min(TIMER_FOR_READ_MAX, parm.reqlen));
	        parm.acclen = (&rdma_sti->rw_states_d[READER])->timer_for_read;
	        (&rdma_sti->rw_states_d[READER])->timer_for_read =
	        	MAX_max(TIMER_FOR_READ_MIN, MIN_min(TIMER_FOR_READ_MAX, 
				parm.reqlen));
	        parm.reqlen = (&rdma_sti->rw_states_d[READER])->timer_for_read;
		break;

	case RDMA_TIMER_FOR_WRITE:
		dbg_ioctl("cmd = RDMA_TIMER_FOR_WRITE, "
			"reqlen (mksec) = 0x%x\n",
			MIN_min(TIMER_FOR_WRITE_MAX, parm.reqlen));
	        parm.acclen = (&rdma_sti->rw_states_d[WRITER])->timer_for_write;
	        (&rdma_sti->rw_states_d[WRITER])->timer_for_write =
	        	MAX_max(TIMER_FOR_WRITE_MIN,MIN_min(TIMER_FOR_WRITE_MAX,
				parm.reqlen));
	        parm.reqlen = (&rdma_sti->rw_states_d[WRITER])->timer_for_write;
		break;
	
	case RDMA_IOC_ALLOCB:
		DEBUG_MSG("rdma_ioctl: cmd = RDMA_IOC_ALLOCB, "
			"reqlen = 0x%lx\n",
			(long)parm.reqlen);
		chd = &rdma_sti->dma_chans[channel];
		chd->node_for_memory = NUM_NODE_RDMA(instance);
		if (chd->allocs != RCS_EMPTY) {
			ERROR_MSG("rdma_ioctl: RDMA_IOC_ALLOCB:  "
					"WRONGLY finish: channel : %d "
					"chd->allocs: %i\n", channel, chd->allocs);
			res = -1;
			parm.err_no = RDMA_E_ALLOC;
			parm.acclen = chd->allocs;
			break;
		}
		parm.acclen = init_chan(chd, parm.reqlen, parm.rwmode);
		if (parm.acclen < -1) {
			ERROR_MSG("rdma_ioctl: RDMA_IOC_ALLOCB: channel : %d "
					"WRONGLY finish: parm.acclen: %d\n",
     					channel, parm.acclen);
			res = -1; parm.err_no = -parm.acclen;
			break;
		}
		if (parm.acclen < 0) {
			ERROR_MSG("rdma_ioctl: RDMA_IOC_ALLOCB:  "
				"WRONGLY finish: RDMA_E_NOBUF\n");
			res = -1; parm.err_no = RDMA_E_NOBUF;
			break;
		}
		parm.rwmode = chd->full;
		DEBUG_MSG("rdma_ioctl: phys: 0x%llx full: 0x%08x\n", chd->dma,
			  chd->full);
		break;
	case  RDMA_GET_STAT:
		rdma_sti->stat_rdma.cur_clock = jiffies;
		if (copy_to_user((void __user *)arg, &rdma_sti->stat_rdma,
			sizeof (struct stat_rdma)) == -1) {
			ERROR_MSG("rdma_ioctl: copy_to_user failed\n");
			return (EINVAL);
		}
		return 0;
	case  RDMA_GET_EVENT:
	{
		get_event_rdma(1);
	}
		return 0;

	case RDMA_SET_STAT:
		memset(&rdma_sti->stat_rdma, 0, sizeof (struct stat_rdma));
		parm.acclen = 0;
		break;
	case RDMA_IS_CAM_YES :
	{
		unsigned int	atl;
		int		ret_time_dwait = 0;
		dev_rdma_sem_t 	*dev_sem;
		rw_state_p	pcam;

		event_ioctl(instance, RDMA_IS_CAM_YES_EVENT, 1, 0);
		pcam = &rdma_sti->ralive;
		dev_sem = &pcam->dev_rdma_sem;
		ret_time_dwait = 0;
		atl = RDR_rdma(SHIFT_CAM, instance);
		if (atl) {
			parm.acclen = atl;
			parm.err_no = 0;
			goto end_RDMA_IS_CAM_YES;
		}
		raw_spin_lock_irq(&dev_sem->lock);
		dev_sem->irq_count_rdma = 0;
		pcam->stat = 1;
		ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, IO_TIMEOUT,
							instance);
		pcam->stat = 0;
		raw_spin_unlock_irq(&dev_sem->lock);
		parm.acclen = RDR_rdma(SHIFT_CAM, instance);
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
	}
		break;
	case RDMA_IS_CAM_NO :
	{
		unsigned int	atl;
		int		ret_time_dwait = 0;
		dev_rdma_sem_t 	*dev_sem;
		rw_state_p	pcam;

		event_ioctl(instance, RDMA_IS_CAM_NO_EVENT, 1, 0);
		pcam = &rdma_sti->talive;
		dev_sem = &pcam->dev_rdma_sem;
		atl = RDR_rdma(SHIFT_CAM, instance);
		if (!atl) {
			parm.acclen = 0;
			parm.err_no = 0;
			goto end_RDMA_IS_CAM_NO;
		}
		raw_spin_lock_irq(&dev_sem->lock);
		dev_sem->irq_count_rdma = 0;
		pcam->stat = 1;
		ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, IO_TIMEOUT,
							instance);
		pcam->stat = 0;
		raw_spin_unlock_irq(&dev_sem->lock);
		parm.acclen = RDR_rdma(SHIFT_CAM, instance);
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
	
	case RDMA_SET_ATL :
	{
		unsigned int atl;

		tr_atl = ATL_B | (parm.reqlen & ATL);
		WRR_rdma(SHIFT_CAM, instance, tr_atl);
		atl = RDR_rdma(SHIFT_CAM, instance);
		parm.acclen = atl;
	}
		break;		
	default :
		ERROR_MSG("rdma_ioctl(%d, %d): default operation NOT EXPECTED"
			  "cmd: %x\n", instance, channel, cmd);
		res = -1;
		parm.err_no = RDMA_E_INVOP;
	}

	rval = copy_to_user((rdma_ioc_parm_t __user *)arg, &parm, 
			     sizeof (rdma_ioc_parm_t));
	if (rval) {
		ERROR_MSG("rdma_ioctl(%d, %d, %x): copy_to_user failed"
			  "size: %lx rval: %lx\n", instance, channel, cmd,
      				sizeof (rdma_ioc_parm_t), rval);
		return (-EINVAL);
	}
	if (res == 0) {
		DEBUG_MSG("rdma_ioctl(%d, %d): NORMAL_END: acclen=%x *****\n\n",
				instance, channel, parm.acclen);
		DEBUG_MSG("rdma_ioctl: FINISH\n");
		return 0;
	}

	ERROR_MSG("rdma_ioctl: FAIL\n");
	DEBUG_MSG("rdma_ioctl: FINISH\n");
	return -EINVAL; 	/* !? return l>0 == return -1 !?*/
}



#ifdef CONFIG_COMPAT
static int do_ioctl(struct file *f, unsigned cmd, unsigned long arg)
{
	int ret;
	ret = rdma_ioctl(f, cmd, arg);
/*	ret = rdma_ioctl(f->f_dentry->d_inode, f, cmd, arg); */
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
	case RDMA_IS_CAM_YES :
	case RDMA_IS_CAM_NO :
	case RDMA_SET_ATL:
	case RDMA_WAKEUP_WRITER:
	case RDMA_WAKEUP_READER:
	case RDMA_IOC_GET_ID:
	case RDMA_IOC_RESET_DMA:
	case RDMA_IOC_SET_MODE_RFSM:
	case RDMA_IOC_SET_MODE_EXIT_GP0:
	case RDMA_IOC_RESET_TCS:
	case RDMA_IOC_RESET_RCS:
	case RDMA_IOC_SET_MODE_LOOP:
		return do_ioctl(f, cmd, arg);
	default:
		return -ENOIOCTLCMD;
	}
}
#endif

/* ssize_t (*read) (struct file *, char __user *, size_t, loff_t *); */
static ssize_t rdma_read(struct file *filp, char __user *buf, size_t size,
			  loff_t *pos)
{
	int			minor;
	int			instance;
	int			channel;
	int			ret = 0;
	rdma_state_inst_t	*rdma_sti;
	rdma_ioc_parm_t 	PRM;
	size_t			rval;

	DEBUG_MSG("rdma_read: START\n");
	if (filp == (struct file *)NULL) {
		ERROR_MSG("rdma_read: filp is NULL\n");
		return 0;
	}
	minor = get_file_minor(filp);
	DEBUG_MSG("rdma_read: minor: %d\n", minor);
	if (minor < 0) {
		ERROR_MSG("rdma_read: minor(%d) < 0\n", minor);
		return (-EINVAL);
	}
	instance = DEV_inst(minor);
	channel = DEV_chan(minor);
	DEBUG_MSG("rdma_read: instance: %d channel: %d\n", instance, channel);
	rdma_sti = &rdma_state->rdma_sti[instance];
	rval = copy_from_user(&PRM, (rdma_ioc_parm_t __user *)buf,
			        sizeof (rdma_ioc_parm_t));
	if (rval) {
		ERROR_MSG("rdma_read(%d, %d): copy_from_user failed size: %lx"
			  "rval: %lx\n", instance, channel, 
     				sizeof (rdma_ioc_parm_t), rval);
		return (-EINVAL);
	}
	
	PRM.reqlen = 0;
	ret = read_buf(rdma_sti, buf, size, instance, channel, &PRM);
	PRM.clkr = join_curr_clock();
	
	rval = copy_to_user((rdma_ioc_parm_t __user *)buf, &PRM, 
			     sizeof (rdma_ioc_parm_t));
	if (rval) {
		ERROR_MSG("rdma_read(%d, %d): copy_to_user failed size: %lx"
			  "rval: %lx\n", instance, channel, 
     				sizeof (rdma_ioc_parm_t), rval);
		return (-EINVAL);
	}
	DEBUG_MSG("rdma_read: FINISH\n");
	return ret;
}

static ssize_t rdma_write(struct file *filp, const char __user *buf, 
			  size_t size, loff_t *pos)
{
	int			minor;
	int			instance;
	int			channel;
	int			ret = 0;
	rdma_state_inst_t	*rdma_sti;
	rdma_ioc_parm_t 	PRM;
	size_t			rval;

	DEBUG_MSG("rdma_write: START\n");
	minor = get_file_minor(filp);
	if (minor < 0)
		return 0;
	instance = DEV_inst(minor);
	channel = DEV_chan(minor);
	DEBUG_MSG("rdma_write: instance: %d channel: %d\n", instance, channel);
	rdma_sti = &rdma_state->rdma_sti[instance];
	DEBUG_MSG("rdma_write: &rdma_state->rdma_sti[%d]: %p\n", instance, 
		  rdma_sti);
	rval = copy_from_user(&PRM, (rdma_ioc_parm_t __user *)buf, 
			       sizeof(rdma_ioc_parm_t));
	DEBUG_MSG("rdma_write: copy_from_user PRM: %p sizeof(PRM):%x"
		  "sizeof(rdma_ioc_parm_t):%x\n", &PRM, sizeof(PRM), 
			sizeof(rdma_ioc_parm_t));
	if (rval) {
		ERROR_MSG("rdma_read(%d, %d): copy_from_user failed size: %lx"
			  "rval: %lx\n", instance, channel, 
     				sizeof (rdma_ioc_parm_t), rval);
		return (-EINVAL);
	}
	ret = write_buf(rdma_sti, buf, size, instance, channel, &PRM);
	PRM.clkr = join_curr_clock();
	rval = copy_to_user((rdma_ioc_parm_t __user *)buf, &PRM, 
			     sizeof (rdma_ioc_parm_t));
	if (rval) {
		ERROR_MSG("rdma_write(%d, %d): copy_to_user failed size: %lx"
			  "rval: %lx\n", instance, channel, 
     				sizeof (rdma_ioc_parm_t), rval);
		return (-EINVAL);
	}

	return ret;
}

static int rdma_mmap(struct file *file, struct vm_area_struct *vma)
{
	int			minor;
	int			instance;
	int			channel;
	int			rval;
	rdma_state_inst_t	*rdma_sti;
	dma_chan_t		*chd;

	DEBUG_MSG("rdma_mmap: START\n");
	minor = get_file_minor(file);
	if (minor < 0)
		return minor;
	instance = DEV_inst(minor);
	channel = DEV_chan(minor);
	rdma_sti = &rdma_state->rdma_sti[instance];
	chd = &rdma_sti->dma_chans[channel];
	if (chd->allocs != RCS_ALLOCED) { 
		ERROR_MSG("rdma_mmap : chd->allocs != RCS_ALLOCED\n");
		return -EAGAIN;
	}
	if (chd->tm) {
		rval = rdma_remap_page_tbl((void *)chd->vdma_tm, chd->real_size,
					    vma);
	} else {
		rval = rdma_remap_page((void *)chd->prim_buf_addr, 
					chd->real_size, vma);
	}
	if (rval) {
		ERROR_MSG("rdma: rdma_mmap ddi_remap_page FAIL\n");
		return -EAGAIN;
	}
	chd->allocs = RCS_MAPPED;
	DEBUG_MSG("rdma_mmap: minor: %d\n", minor);
	DEBUG_MSG("rdma_mmap: FINISH\n");
	return 0;
}

int rdma_remap_page(void *va, size_t sz, struct vm_area_struct *vma)
{
   	unsigned long 	pha;
 	unsigned long 	vm_end;
	unsigned long 	vm_start;
	unsigned long 	vm_pgoff;
	size_t  	size;

	DEBUG_MSG("rdma_remap_page: START\n");
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

   	vma->vm_flags |= (VM_READ | VM_WRITE | VM_RESERVED);

#ifdef __e2k__
	if (vma->vm_flags & VM_IO)
		vma->vm_page_prot = __pgprot(pgprot_val(vma->vm_page_prot) |
					_PAGE_CD_DIS | _PAGE_PWT );
#endif
	if (remap_pfn_range(vma, vm_start, (pha >> PAGE_SHIFT), size, 
	    vma->vm_page_prot)) {
		ERROR_MSG("rdma_remap_page: FAIL remap_pfn_range\n");
       		return -EAGAIN;
       	}
	DEBUG_MSG("rdma_remap_page: FINISH\n");
       	return 0;
}

int rdma_remap_page_tbl(void *va, size_t sz, struct vm_area_struct *vma)
{
   	unsigned long 	pha;
   	unsigned long 	sz_pha;
 	unsigned long 	vm_end;
	unsigned long 	vm_start;
	unsigned long 	vm_pgoff;
	size_t  	size;
	rdma_tbl_64_struct_t	*ptbl;

	DEBUG_MSG("rdma_remap_page_tbl: START\n");
	if (!sz) return -EINVAL;
	if (vma->vm_pgoff) {
		ERROR_MSG("rdma_remap_page_tbl: vma->vm_pgoff: 0x%lx\n", 
			  vma->vm_pgoff);
		return -EINVAL;
	}
	size = (long)PAGE_ALIGN(sz);
   	vm_end = vma->vm_end;
   	vm_start = vma->vm_start;
   	vm_pgoff = vma->vm_pgoff;

	if ((vm_end - vm_start) < size) {
      		size = vm_end - vm_start;
		DEBUG_MSG("rdma_remap_page_tbl: vm_end(%lx) - vm_start(%lx) < "
			  "size(%lx)\n", vm_end, vm_start, size);
	}

   	vma->vm_flags |= (VM_READ | VM_WRITE | VM_RESERVED);

#ifdef __e2k__
	if (vma->vm_flags & VM_IO)
		vma->vm_page_prot = __pgprot(pgprot_val(vma->vm_page_prot) |
					_PAGE_CD_DIS | _PAGE_PWT );
#endif
	for (ptbl = (rdma_tbl_64_struct_t *)va; ptbl; ptbl++) {
		rdma_addr_struct_t pxx;
		pxx.addr = (unsigned long)ptbl;
		DEBUG_MSG("rdma_remap_page_tbl: 0x%08x%08x ptbl\n",
			  pxx.fields.haddr, pxx.fields.laddr);
		pxx.addr = ptbl->addr;
		DEBUG_MSG("rdma_remap_page_tbl: 0x%08x%08x ptbl->addr\n",
			  pxx.fields.haddr, pxx.fields.laddr);
#ifdef CONFIG_E90S
		pha = (unsigned long)(cpu_to_le64(ptbl->addr));
		DEBUG_MSG("rdma_remap_page_tbl: pha cpu_to_le64(pha): %lx \n",
			  pha);
#else /* E3S */
		pha = (unsigned long)ptbl->addr;
#endif
		pxx.addr = (unsigned long)phys_to_virt(pha);
		DEBUG_MSG("rdma_remap_page_tbl: 0x%08x%08x __va(ptbl->addr)\n",
			  pxx.fields.haddr, pxx.fields.laddr);
		pxx.addr = pha;
		DEBUG_MSG("rdma_remap_page_tbl: 0x%08x%08x __fa(ptbl->addr)\n",
			  pxx.fields.haddr, pxx.fields.laddr);
		sz_pha = ptbl->sz;
#ifdef CONFIG_E90S
		sz_pha = cpu_to_le64(sz_pha);
		DEBUG_MSG("rdma_remap_page_tbl:"
			  "sz_pha cpu_to_le64(sz_pha): %lx\n", sz_pha);
#endif
		if (remap_pfn_range
			(vma, vm_start,
			(pha >> PAGE_SHIFT), sz_pha, vma->vm_page_prot)) {
			ERROR_MSG("rdma_remap_page_tbl:FAIL remap_pfn_range\n");
       			return -EAGAIN;
       		}
		vm_start += sz_pha;
		DEBUG_MSG("rdma_remap_page_tbl: vm_start: %lx vm_end: %lx "
			  "sz_pha: %lx \n", vm_start, vm_end, sz_pha);
		if (vm_start >= vm_end) {
			DEBUG_MSG("rdma_remap_page_tbl: "
				  "vm_start(%lx) >= vm_end(%lx)\n", vm_start,
       					vm_end);
			break;
		}
	}
	DEBUG_MSG("rdma_remap_page_tbl: FINISH\n");
	return 0;
}

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
	DEBUG_MSG("get_file_minor:d_inode->i_rdev: 0x%08u major: %d minor:%u\n",
		d_inode->i_rdev, major, MINOR(d_inode->i_rdev));
	return MINOR(d_inode->i_rdev);
}


void init_rdma_sti(int instance)
{
	rw_state_t	*pd, *pm;
	int		i;
	dev_rdma_sem_t 	*dev_sem;
	rdma_state_inst_t *rdma_sti = &rdma_state->rdma_sti[instance];
	rdma_addr_struct_t	p_xxb;

	DEBUG_MSG("init_rdma_sti: START\n");
	p_xxb.addr = (unsigned long)rdma_sti;
	DEBUG_MSG("init_rdma_sti: node: %d rdma_sti: 0x%08x%08x\n",
		instance, p_xxb.fields.haddr, p_xxb.fields.laddr);
	rdma_sti->instance = instance;
	mutex_init(&rdma_sti->mu);
	pm = &rdma_sti->talive;
	mutex_init(&pm->mu);
	raw_spin_lock_init(&pm->mu_spin);
	pm->stat = 0;
	pm->timer = TIMER_MIN;
	dev_sem = &pm->dev_rdma_sem;
	raw_spin_lock_init(&dev_sem->lock);
	cv_init(&dev_sem->cond_var);
	dev_sem->irq_count_rdma = 0;
	pm = &rdma_sti->ralive;
	mutex_init(&pm->mu);
	raw_spin_lock_init(&pm->mu_spin);
	pm->stat = 0;
	pm->timer = TIMER_MIN;
	dev_sem = &pm->dev_rdma_sem;
	raw_spin_lock_init(&dev_sem->lock);
	cv_init(&dev_sem->cond_var);
	dev_sem->irq_count_rdma = 0;
	for (i = 0; i < 2; i++) {
		pm = &rdma_sti->rw_states_m[i];
		mutex_init(&pm->mu);
		raw_spin_lock_init(&pm->mu_spin);
		pm->stat = 0;
		pm->timer = TIMER_MIN;
		dev_sem = &pm->dev_rdma_sem;
		raw_spin_lock_init(&dev_sem->lock);
		cv_init(&dev_sem->cond_var);
		dev_sem->irq_count_rdma = 0;
		pd = &rdma_sti->rw_states_d[i];
		mutex_init(&pd->mu);
		raw_spin_lock_init(&pd->mu_spin);
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
		pd->trwd_was = 0;
		pd->timer_read = TIMER_MIN;
		pd->timer_write = TIMER_MIN;
		pd->timer_for_read = TIMER_FOR_READ_MIN;
		pd->timer_for_write = TIMER_FOR_WRITE_MIN;
	}
	DEBUG_MSG("init_rdma_sti: FINISH\n");
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
	printk("%d 0x%08x 0x34 - SHIFT_RDMSG\n",   i, 
	       RDR_rdma(SHIFT_RDMSG, i));
	printk("%d 0x%08x 0x38 - SHIFT_CAM\n",     i, 
	       RDR_rdma(SHIFT_CAM, i));
}

void test_send_msg_rdma(unsigned int i, unsigned int msg)
{
	read_regs_rdma(i);
	WRR_rdma(SHIFT_TDMSG, i, msg);
	read_regs_rdma(i);
}

void free_chan(dma_chan_t *chd)
{
	signed int rest;
	DEBUG_MSG("free_chan: START\n");
	if (chd->allocs > RCS_ALLOCED_B) {
		if (chd->size_tm) {
			rdma_tbl_64_struct_t	*peltbl;
			for (peltbl = (rdma_tbl_64_struct_t *)chd->vdma_tm,
			     rest = chd->real_size; rest > 0; peltbl++) {
#ifdef CONFIG_E90S
				peltbl->addr = cpu_to_le64(peltbl->addr);
				peltbl->sz = cpu_to_le64(peltbl->sz);
#endif
				rdma_mem_free(peltbl->sz, 
					(dma_addr_t) peltbl->addr,
					(unsigned long) __va(peltbl->addr));
				rest -= peltbl->sz;
			}
			rdma_mem_free(chd->size_tm, chd->fdma_tm,
				      (unsigned long)chd->vdma_tm);
		} else
		if (chd->real_size) {
			rdma_mem_free(chd->real_size, chd->dma,
				(unsigned long)chd->prim_buf_addr);
		}
		chd->tm = 0;
		chd->allocs = 0;
		chd->vdma_tm = 0;
		chd->size_tm = 0;
		chd->dma_busa = 0;
		chd->prim_buf_addr = 0;
		chd->real_size = 0;
	}
	DEBUG_MSG("free_chan: FINISH\n");
}

void rdma_mem_free(size_t size, dma_addr_t dev_memory, 
		   unsigned long dma_memory)
{
	int		order;
	caddr_t		mem;
	struct page	*map, *mapend;

	DEBUG_MSG("rdma_mem_free: START\n");
	mem = (caddr_t)dma_memory;
	order = get_order(size);
	mapend = virt_to_page(mem + (PAGE_SIZE << order) - 1);
	for (map = virt_to_page(mem); map <= mapend; map++)
		ClearPageReserved(map);
	free_pages(dma_memory, order);
	DEBUG_MSG("rdma_mem_free: FINISH va: 0x%lx, fa: 0x%llx size: 0x%lx\n",
		dma_memory, dev_memory, size);
}

unsigned long __get_free_pages_rdma(int node, gfp_t gfp_mask, 
				    unsigned int order)
{
	struct page *page;

	page = alloc_pages_node(node, gfp_mask, order);
	if (!page)
		return (unsigned long)NULL;
	return (unsigned long) page_address(page);
}

int rdma_mem_alloc(int node, size_t size, dma_addr_t *mem, size_t *real_size,
		    unsigned long *dma_memory)
{
	int		order;
	struct page	*map, *mapend;

	DEBUG_MSG("rdma_mem_alloc: START\n");
	order = get_order(size);
	*dma_memory = __get_free_pages_rdma(node, GFP_KERNEL , order);
	if (!(*dma_memory)) {
		ERROR_MSG("rdma_mem_alloc: Cannot bind DMA address order: %d"
			  "size: 0x%lx\n", order, size);
	      return -1;
	}
	mapend = virt_to_page((*dma_memory) + (PAGE_SIZE << order) - 1);
	for (map = virt_to_page((*dma_memory)); map <= mapend; map++)
		SetPageReserved(map);

	*mem = __pa(*dma_memory);
	*real_size = PAGE_SIZE << order;
	DEBUG_MSG("rdma_mem_alloc: FINISH va: 0x%lx fa: 0x%llx size: 0x%lx"
		  "real_size: 0x%lx\n", *dma_memory, *mem, size, *real_size);
	return 0;
}

int init_chan(dma_chan_t *chd, int reqlen, int tm)
{
	char			*err_msg = NULL;
	rdma_tbl_64_struct_t	*peltbl;
	signed int		rest, tmp_size;
	rdma_addr_struct_t 	pxx;
	int 			SIZE_TLB;
	
	DEBUG_MSG("init_chan: START\n");
	if (chd->allocs) {
		ERROR_MSG("init_chan: chd->allocs already %d\n", chd->allocs);
		return -1;
	}
#define SIZE_TLB_EL 128	
	SIZE_TLB = ((PAGE_ALIGN(reqlen) / PAGE_SIZE + 1) * SIZE_TLB_EL);
	
	chd->allocs = RCS_ALLOCED_B;
	DEBUG_MSG("init_chan: try alloc 0x%x\n", reqlen);
	if (tm) {
		DEBUG_MSG("init_chan: table mode PAGE_SIZE: %x\n", PAGE_SIZE);
		DEBUG_MSG("init_chan: try alloc for tm size SIZE_TLB : 0x%x\n",
			  SIZE_TLB);
		if (rdma_mem_alloc
			(chd->node_for_memory, SIZE_TLB,
			(dma_addr_t *)&chd->fdma_tm, &chd->size_tm,
			(unsigned long *)&chd->vdma_tm)) {
			err_msg = "rdma_mem_alloc for tm";
			goto failed;
		}
		pxx.addr = (unsigned long)chd->vdma_tm;
		DEBUG_MSG("init_chan: 0x%08x%08x vdma_tm\n", pxx.fields.haddr,
			  pxx.fields.laddr);
		pxx.addr = chd->fdma_tm;
		DEBUG_MSG("init_chan: 0x%08x%08x fdma_tm\n", pxx.fields.haddr,
			  pxx.fields.laddr);
		rest = reqlen;
		/* rest = allign_dma((unsigned int)reqlen);
		rest = PAGE_ALIGN(reqlen); */
		
		DEBUG_MSG("init_chan: reqlen: 0x%08x rest: 0x%08x\n",
			  reqlen, rest);
		chd->real_size = 0;
		for (peltbl = (rdma_tbl_64_struct_t *)chd->vdma_tm;
				   rest > 0; peltbl++)
		{
			size_t		size_el;
			unsigned long	addr;		/* address */
			if (rdma_mem_alloc
				(chd->node_for_memory, SIZE_EL_TBL64_RDMA,
				 (dma_addr_t *)&peltbl->addr, &size_el,
				(unsigned long *)&addr)) {
				err_msg = "rdma_mem_alloc for tm element";
				if (chd->real_size) {
					peltbl->sz = 0;
					chd->dma = chd->fdma_tm;
					chd->tm = 1;
					chd->allocs = RCS_ALLOCED;
					goto failed1;
				} else 
					goto failed;
			}
			pxx.addr = (unsigned long)peltbl;
			DEBUG_MSG("init_chan: 0x%08x%08x peltbl\n",
				  pxx.fields.haddr, pxx.fields.laddr);
#ifdef CONFIG_E90S
			peltbl->addr = le64_to_cpu(peltbl->addr);
#endif
			pxx.addr = peltbl->addr;
			DEBUG_MSG("init_chan: 0x%08x%08x peltbl->addr\n", 
				  pxx.fields.haddr, pxx.fields.laddr);
			tmp_size = ((rest >= size_el)?size_el:
					(unsigned int)rest); 
			
			peltbl->sz = (unsigned long)size_el;
			/* peltbl->sz = (unsigned long)tmp_size; */
#ifdef CONFIG_E90S
			peltbl->sz = le64_to_cpu(peltbl->sz);
#endif
			rest -= size_el;
			/* DEBUG_MSG("init_chan: tmp_size: 0x%08x rest: 0x%08x\n",
				  tmp_size, rest); */
			chd->real_size += size_el;
			/* chd->real_size += tmp_size; */
		}
		peltbl->sz = 0;
		chd->dma = chd->fdma_tm;
		chd->tm = 1;

	} else {
		DEBUG_MSG("init_chan: single mode PAGE_SIZE: %x\n", PAGE_SIZE);
		int rfsm_size;
		if (reqlen > 0x800000){
			ERROR_MSG("init_chan: The large size of the buffer. "
					"The buffer must be <= 0x0800000. "
					"Use table mode.\n");
			goto failed;
		}
		if (rfsm) {
#ifdef CONFIG_E2K
			if (IS_MACHINE_E2S) 
				rfsm_size = reqlen;
			else
				rfsm_size = PAGE_ALIGN(reqlen);
#else			
			rfsm_size = PAGE_ALIGN(reqlen);
#endif				
		}  else {
			rfsm_size = reqlen;
		}
		
		if (rdma_mem_alloc(chd->node_for_memory, (unsigned long)rfsm_size,
		    (dma_addr_t *)&chd->dma_busa, &chd->real_size,
		    (unsigned long *)&chd->prim_buf_addr)) {
			err_msg = "rdma_mem_alloc";
			goto failed;
		}
		chd->dma = chd->dma_busa;
		pxx.addr = chd->dma;
		DEBUG_MSG("init_chan: 0x%08x%08x chd->dma\n", pxx.fields.haddr,
			  pxx.fields.laddr);
		chd->tm = 0;
	}
	chd->full = (uint_t)chd->dma;
	chd->allocs = RCS_ALLOCED;
	DEBUG_MSG("init_chan: FINISH chd->real_size: %lx\n", chd->real_size);
	return chd->real_size;

failed:
	chd->allocs = RCS_EMPTY;
failed1:
	ERROR_MSG("init_chan: %s FAILED ****\n", err_msg);
	return (-1);
}

/******************* create devices *************************/

int create_dev_rdma(int major)
{
	char nod[128];
	int i = 0, i_rdma;
	int minor;
	
	/* Create rdma nodes in /sysfs */
	rdma_class = class_create(THIS_MODULE, "rdma");
	if (IS_ERR(rdma_class)) {
		pr_err("Error creating class: /sys/class/rdma.\n");
	}
	for_each_online_rdma(i) {
	/* for_each_rdma(i) { */
		for (i_rdma= 0; i_rdma < RDMA_NODE_DEV; i_rdma++) {
			minor = i * RDMA_NODE_DEV + i_rdma;
			sprintf(nod,"rdma_%d_:%d", i, i_rdma);
			pr_info("make node /sys/class/rdma/%s\n", nod);
			if (device_create(rdma_class, NULL,
			    MKDEV(major, minor), NULL, nod) == NULL) {
				     pr_err("create dev: %s a node: %d "
						     "failed\n", nod, i);
				     return -1;
			     }
		}
	}	
	return 0;
}

int remove_dev_rdma(int major)
{
	char nod[128];
	int i = 0, i_rdma;
	int minor;
	
	/* Remove rdma nodes in /sysfs */
	for_each_rdma(i) {
		for (i_rdma= 0; i_rdma < RDMA_NODE_DEV; i_rdma++) {
			minor = i * RDMA_NODE_DEV + i_rdma;
			(void) sprintf(nod,"rdma_%d_:%d", i, i_rdma);
			device_destroy(rdma_class, MKDEV(major, minor));
		}
	}
	class_destroy(rdma_class);
	return 0;
}	

module_init(rdma_init);
module_exit(rdma_cleanup);

