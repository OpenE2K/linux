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
#include <linux/pci.h>
#include <asm/apic.h>
#include <asm/uaccess.h>
#include <asm/setup.h>

#include <linux/mcst/ddi.h>
#include <linux/mcst/rdma_user_intf.h>
#include "rdma_regs.h"
#include "rdma.h"
#include "rdma_error.h"

#ifndef VM_RESERVED
#define VM_RESERVED (VM_DONTEXPAND | VM_DONTDUMP)
#endif

#define	RDMA_NODE_DEV 	7

/* Struct for class rdma in sysfs */
static struct class *rdma_class;

/******************************************************************************/
/* OLD VERSION (version_mem_alloc  = 0) - mem_alloc over __get_free_pages.    */
/* NEW VERSION (version_mem_alloc != 0) - mem_alloc over dma_alloc_coherent.  */
/* Default OLD VERSION.							      */
/******************************************************************************/
static int version_mem_alloc = 0;
module_param(version_mem_alloc, int, 0);

unsigned int tr_atl;
static int  atl_v = TR_ATL_B;
module_param(atl_v, int, 0);
MODULE_PARM_DESC(atl_v, "Changes the value of ATL (alive timer limit) reg CAM.");

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

DEFINE_RAW_SPINLOCK(mu_fix_event);

unsigned char *rdma_reg_VID;		/* RDMA VID 			*/
unsigned char *rdma_reg_CH0_IDT;	/* RDMA ID/Type 		*/
unsigned char *rdma_reg_CS;		/* RDMA Control/Status 000028a0	*/
unsigned char *rdma_reg_CH1_IDT;	/* RDMA ID/Type 		*/
unsigned char *rdma_reg_DD_ID_0;	/* Data Destination ID 		*/
unsigned char *rdma_reg_DMD_ID_0;	/* Data Message Destination ID 	*/
unsigned char *rdma_reg_N_IDT_0;	/* Neighbour ID/Type 		*/
unsigned char *rdma_reg_ES_0;		/* Event Status 		*/
unsigned char *rdma_reg_IRQ_MC_0;	/* Interrupt Mask Control 	*/
unsigned char *rdma_reg_DMA_TCS_0;	/* DMA Tx Control/Status 	*/
unsigned char *rdma_reg_DMA_TSA_0;	/* DMA Tx Start Address 	*/
unsigned char *rdma_reg_DMA_TBC_0;	/* DMA Tx Byte Counter 		*/
unsigned char *rdma_reg_DMA_RCS_0;	/* DMA Rx Control/Status 	*/
unsigned char *rdma_reg_DMA_RSA_0;	/* DMA Rx Start Address 	*/
unsigned char *rdma_reg_DMA_RBC_0;	/* DMA Rx Byte Counter 		*/
unsigned char *rdma_reg_MSG_CS_0;	/* Messages Control/Status 	*/
unsigned char *rdma_reg_TDMSG_0;	/* Tx Data_Messages Buffer 	*/
unsigned char *rdma_reg_RDMSG_0;	/* Rx Data_Messages Buffer 	*/
unsigned char *rdma_reg_CAM_0;		/* CAM - channel alive management */

unsigned char *rdma_reg_DD_ID_1;	/* Data Destination ID 		*/
unsigned char *rdma_reg_DMD_ID_1;	/* Data Message Destination ID 	*/
unsigned char *rdma_reg_N_IDT_1;	/* Neighbour ID/Type 		*/
unsigned char *rdma_reg_ES_1;		/* Event Status 		*/
unsigned char *rdma_reg_IRQ_MC_1;	/* Interrupt Mask Control 	*/
unsigned char *rdma_reg_DMA_TCS_1;	/* DMA Tx Control/Status 	*/
unsigned char *rdma_reg_DMA_TSA_1;	/* DMA Tx Start Address 	*/
unsigned char *rdma_reg_DMA_TBC_1;	/* DMA Tx Byte Counter 		*/
unsigned char *rdma_reg_DMA_RCS_1;	/* DMA Rx Control/Status 	*/
unsigned char *rdma_reg_DMA_RSA_1;	/* DMA Rx Start Address 	*/
unsigned char *rdma_reg_DMA_RBC_1;	/* DMA Rx Byte Counter 		*/
unsigned char *rdma_reg_MSG_CS_1;	/* Messages Control/Status 	*/
unsigned char *rdma_reg_TDMSG_1;	/* Tx Data_Messages Buffer 	*/
unsigned char *rdma_reg_RDMSG_1;	/* Rx Data_Messages Buffer 	*/
unsigned char *rdma_reg_CAM_1;		/* CAM - channel alive management */

struct stat_rdma stat_rdma;
unsigned char	*e0regad;
unsigned int	count_read_sm_max = 80;
unsigned int	intr_rdc_count[2];
unsigned int	msg_cs_dmrcl;
unsigned int	state_cam = 0;
unsigned long	time_ID_REQ;
unsigned long	time_ID_ANS;

link_id_t 		rdma_link_id ;
extern int rdma_present;

static long	rdma_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long arg);
#ifdef CONFIG_COMPAT
static int do_ioctl(struct file *f, unsigned cmd, unsigned long arg);
static long rdma_compat_ioctl(struct file *f, unsigned cmd, unsigned long arg);
#endif
static ssize_t rdma_read(struct file *, char *, size_t, loff_t *);
static ssize_t rdma_write(struct file *, const char *, size_t, loff_t *);
static int rdma_open(struct inode *inode, struct file *file);
static int rdma_close(struct inode *inode, struct file *file);
static int rdma_mmap(struct file *file, struct vm_area_struct *vma);
void test_reg_rdma(void);
int get_file_minor(struct file *file);
void init_reg(void);
void free_chan(dma_chan_t *chd);
void rdma_mem_free(size_t size, dma_addr_t dev_memory,
		   unsigned long dma_memory);
void init_rdma_sti(int instance);
void read_regs_rdma(void);
int rdma_mem_alloc(size_t size, dma_addr_t *mem, size_t *real_size,
		    unsigned long *dma_memory);
int init_chan(dma_chan_t *chd, int reqlen, int tm);
int write_buf(rdma_state_inst_t *xsp, const char *buf, unsigned int size,
	      int instance, int channel, rdma_ioc_parm_t *parm);
int read_buf(rdma_state_inst_t *xsp, const char *buf, int size, int instance,
	      int channel, rdma_ioc_parm_t *parm);
int rdma_remap_page(void *va, size_t sz, struct vm_area_struct *vma);

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
	for (i_rdma= 0; i_rdma < RDMA_NODE_DEV; i_rdma++) {
		minor = i * RDMA_NODE_DEV + i_rdma;
		sprintf(nod,"rdma_%d_:%d",i, i_rdma);
		pr_info("make node /sys/class/rdma/%s\n", nod);
		if (device_create(rdma_class, NULL, MKDEV(major, minor),
		    NULL, nod) == NULL) {
			pr_err("create dev: %s a node: %d failed\n",
			       nod, i);
			return -1;
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
	for (i_rdma= 0; i_rdma < RDMA_NODE_DEV; i_rdma++) {
		minor = i * RDMA_NODE_DEV + i_rdma;
		(void) sprintf(nod, "rdma_%d_:%d", i, i_rdma);
		device_destroy(rdma_class, MKDEV(major, minor));
		pr_info("remove node /sys/class/rdma/%s\n", nod);
	}
	class_destroy(rdma_class);
	return 0;
}


static struct file_operations rdma_fops = {
	.owner	 	= THIS_MODULE,
	.read		= rdma_read,
	.write		= rdma_write,
	.unlocked_ioctl = rdma_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl 	=  rdma_compat_ioctl,
#endif
	.mmap		= rdma_mmap,
	.open	 	= rdma_open,
	.release 	= rdma_close,
};

unsigned int	rdc_byte;

#ifdef RDMA_REG_TRACE

void WRR_rdma(unsigned char *reg, unsigned int val)
{
	int ddd = (int)(reg-e0regad);
	int inst;

	writel(val, reg);
	inst = ((ddd & 0xf00)>>8);
	switch (inst) {
	case 0: inst = 2; break;
	case 1: inst = 0; break;
	case 2: inst = 1; break;
	}
	fix_event(inst, WRR_EVENT, ddd & 0xff, val);
}

unsigned int RDR_rdma(unsigned char *reg)
{
	unsigned int val = readl(reg);
	int ddd = (int)(reg-e0regad);
	int inst;

	inst = ((ddd & 0xf00)>>8);
	switch (inst) {
	case 0: inst = 2; break;
	case 1: inst = 0; break;
	case 2: inst = 1; break;
	}
	fix_event(inst, RDR_EVENT, ddd & 0xff, val);
	return val;
}
#endif
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

int pcibios_read_config_dword (unsigned char bus, unsigned char devfn,
			       unsigned char where, u32 *val)
{
	outl(CONFIG_CMD_RDMA(bus, devfn, where), 0xCF8);
	*val = inl(0xCFC);
	return 0;
}

int pcibios_write_config_dword (unsigned char bus, unsigned char devfn,
				unsigned char where, u32 val)
{
	outl(CONFIG_CMD_RDMA(bus, devfn, where), 0xCF8);
	outl(val, 0xCFC);
	return 0;
}

static struct pci_device_id rdma_devices[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_RDMA, PCI_DEVICE_ID_MCST_RDMA) },
	{ 0, }
};

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


/* From ddi */
int
drv_getparm_from_ddi(unsigned long parm, unsigned long *valuep)
{
        switch (parm) {
        case LBOLT:
                *valuep = (unsigned long)jiffies;
                break;
        default:
                printk("drv_getparm_from_ddi: Unknown parm %ld\n", parm);
                return (-1);
        }
        return 0;
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

/* Convert mksec to HZ */
clock_t
drv_usectohz_from_ddi(register clock_t mksec)
{
        clock_t  	clock;
	struct timespec rqtp;

	rqtp.tv_nsec = ((mksec % 1000000L) * 1000L);
	rqtp.tv_sec  = mksec / 1000000L;
	clock = timespec_to_jiffies(&rqtp);
	return (clock);
}

extern int wake_up_state(struct task_struct *p, unsigned int state);

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
int
ddi_cv_broadcast_from_ddi(kcondvar_t *cvp)
{
	__raw_wake_up_from_ddi(cvp);
        return 0;
}

int rdma_cv_broadcast_rdma(void* dev_rdma_sem)
{
	dev_rdma_sem_t 	*dev = dev_rdma_sem;
	dev->irq_count_rdma++;
	dev->time_broadcast = E2K_GET_DSREG(clkr);
	ddi_cv_broadcast_from_ddi(&dev->cond_var);
	return (0);
}

int
ddi_cv_spin_timedwait_from_ddi(kcondvar_t *cvp, raw_spinlock_t *lock, long tim)
{
      	/*   unsigned long flags; */
        unsigned long expire;
        int rval = 0;
	int spin_locking_done	= 0;
        struct task_struct *tsk = current;
	DECLARE_RAW_WAIT_QUEUE(wait);
        expire = tim - jiffies;
        tsk->state = TASK_INTERRUPTIBLE;
	raw_add_wait_queue_from_ddi(cvp, &wait);
	spin_locking_done = raw_spin_is_locked(lock);
	if(spin_locking_done)
 	       spin_mutex_exit(lock);
	fix_event(0, WAIT_TRY_SCHTO_EVENT,
		(unsigned int)expire, 0);
        expire = schedule_timeout(expire);
	raw_remove_wait_queue_from_ddi(cvp, &wait);
        tsk->state = TASK_RUNNING;
	if(spin_locking_done)
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

/* From ddi */

hrtime_t
rdma_gethrtime(void)
{
	struct timeval tv;
	hrtime_t val;
	do_gettimeofday(&tv);
	val = tv.tv_sec * 1000000000LL + tv.tv_usec * 1000LL;
	return (val);
}

int wait_for_irq_rdma_sem(void* dev_rdma_sem, signed long usec_timeout)
{
	unsigned long expire = 0;
	unsigned long time_current;
	unsigned int delta_time;
	dev_rdma_sem_t *dev = dev_rdma_sem;
	int ret = 0;
	signed long timeout_tick;

	if (!raw_spin_is_locked(&dev->lock)) {
	        printk("wait_for_irq_rdma_sem: spin is NOT locked:dev: %p\n",
		       dev);
		return -3;
	}
	if (dev->irq_count_rdma) {
	        printk("wait_for_irq_rdma_sem(%p): dev->irq_count_rdma: %d"
				"num_obmen: %d\n", &dev->lock,
    				(int)dev->irq_count_rdma,
				(unsigned int)dev->num_obmen);
		delta_time = 0;
		if (dev->time_broadcast) {
			time_current = E2K_GET_DSREG(clkr);
			if (time_current > dev->time_broadcast) {
				delta_time = (unsigned int)(time_current -
						dev->time_broadcast);
			} else {
				delta_time = (unsigned int)(time_current +
						(~0U - dev->time_broadcast));
			}
			delta_time |= (1<<31);
			event_ddi_cv(delta_time, WAIT_RET_SCHT0_EVENT, expire,
				     (unsigned int)dev->num_obmen);
			dev->time_broadcast = 0;
		}
		return(1);
	}
	usec_timeout *= 10000;
	event_ddi_cv(0, WAIT_TRY_SCHTO_EVENT, usec_timeout,
		     (unsigned int)dev->num_obmen);
	drv_getparm_from_ddi(LBOLT, &timeout_tick);
	timeout_tick += drv_usectohz_from_ddi(usec_timeout);
	ret = ddi_cv_spin_timedwait_from_ddi(&dev->cond_var, &dev->lock,
					      timeout_tick);
	delta_time = 0;
	if (dev->time_broadcast) {
		time_current = E2K_GET_DSREG(clkr);
		if (time_current > dev->time_broadcast) {
			delta_time = (unsigned int)(time_current -
					dev->time_broadcast);
		} else {
			delta_time = (unsigned int)(time_current +
					(~0U - dev->time_broadcast));
		}
		event_ddi_cv(delta_time, WAIT_RET_SCHT0_EVENT, expire,
			     (unsigned int)dev->num_obmen);
		dev->time_broadcast = 0;
	} else
		event_ddi_cv(dev->irq_count_rdma, WAIT_RET_SCHT0_EVENT, expire,
			     (unsigned int)dev->num_obmen);
	DEBUG_MSG("wait_for_irq_rdma_sem FINISH\n");
	return ret;
}

rdma_event_t rdma_event;

int	rdma_event_init = 0;
void	fix_event_proc(unsigned int channel, unsigned int event,
		       unsigned int val1, unsigned int val2)
{
	unsigned long flags;
	struct event_cur *event_cur;

	if (!rdma_event_init)
		return;

	raw_spin_lock_irqsave(&mu_fix_event, flags);
	event_cur = &rdma_event.event[rdma_event.event_cur];
	event_cur->clkr = E2K_GET_DSREG(clkr);
	event_cur->event = event;
	event_cur->channel = channel;
	event_cur->val1 = val1;
	event_cur->val2 = val2;
	rdma_event.event_cur++;
	if (SIZE_EVENT == rdma_event.event_cur)
		rdma_event.event_cur = 0;
	raw_spin_unlock_irqrestore(&mu_fix_event, flags);
	return;
}

#include "rdma_intr.c"
#include "rdma_read_buf.c"
#include "rdma_write_buf.c"
#include "rdma_send_msg.c"

static void __exit rdma_remove(struct pci_dev *dev);
static int __init rdma_probe(struct pci_dev *dev,
			     const struct pci_device_id *ent);

static struct pci_driver rdma_driver = {
	.name	  = "MCST,rdma",
	.id_table = rdma_devices,
	.probe	  = rdma_probe,
	.remove	  = rdma_remove
};

/*
 * Main structutre RDMA
 */
struct rdma_state *rdma_state;

static int __init rdma_init(void)
{
	int pci_ret = 0;

	if (HAS_MACHINE_E2K_FULL_SIC) {
		ERROR_MSG("Sorry, I am worked on e3m, use rdma_sic.\n");
		return -ENODEV;
	}

	if (!rdma_present) {
		rdma_present = 1;
	} else {
		ERROR_MSG("RDMA registers busy. \n");
		return -ENODEV;
	}

	if (!rdma_apic_init) {
		ERROR_MSG("Hard rdma is absent\n");
		rdma_present = 0;
		return -ENODEV;
	}
	rdma_event_init = 1;
	pci_ret = pci_register_driver(&rdma_driver);
	if (pci_ret) {
		ERROR_MSG("Module rdma FAIL initialization: %d\n", pci_ret);
	}

	return pci_ret;
}

unsigned char	bus_number_rdma, devfn_rdma;
int	irq_mc;

static int rdma_probe(struct pci_dev *dev,
				const struct pci_device_id *ent)
{
	struct pci_bus	*bus;
	int	ret = -EINVAL;
	int	id;
	int	val;
	int	i;
	int	major;
	int	size_rdma_state;

	DEBUG_MSG("rdma_probe: START\n");
#if RDMA_PRN_ADDR_FUN
	printk("ADDR_FUN: %p - static rdma_ioctl\n", rdma_ioctl);
	printk("ADDR_FUN: %p - static rdma_read\n", rdma_read);
	printk("ADDR_FUN: %p - static rdma_write\n", rdma_write);
	printk("ADDR_FUN: %p - static rdma_open\n", rdma_open);
	printk("ADDR_FUN: %p - static rdma_close\n", rdma_close);
	printk("ADDR_FUN: %p - static rdma_mmap\n", rdma_mmap);
	printk("ADDR_FUN: %p - test_reg_rdma\n", test_reg_rdma);
	printk("ADDR_FUN: %p - get_file_minor\n", get_file_minor);
	printk("ADDR_FUN: %p - init_reg\n", init_reg);
	printk("ADDR_FUN: %p - free_chan\n", free_chan);
	printk("ADDR_FUN: %p - rdma_mem_free\n", rdma_mem_free);
	printk("ADDR_FUN: %p - init_rdma_sti\n", init_rdma_sti);
	printk("ADDR_FUN: %p - read_regs_rdma\n", read_regs_rdma);
	printk("ADDR_FUN: %p - rdma_mem_alloc\n", rdma_mem_alloc);
	printk("ADDR_FUN: %p - init_chan\n", init_chan);
	printk("ADDR_FUN: %p - write_buf\n", write_buf);
	printk("ADDR_FUN: %p - read_buf\n", read_buf);
	printk("ADDR_FUN: %p - rdma_remap_page\n", rdma_remap_page);
	printk("ADDR_FUN: %p - rdma_fops->read rdma_fops->read: %x\n",
	       rdma_fops.read, *rdma_fops.read);
	printk("ADDR_FUN: %p - rdma_fops->write rdma_fops->write: %x\n",
	       rdma_fops.write, *rdma_fops.write);
	printk("ADDR_FUN: %p - rdma_fops->unlocked_ioctl "
			"rdma_fops->unlocked_ioctl: %x\n",
   			rdma_fops.unlocked_ioctl, *rdma_fops.unlocked_ioctl);
	printk("ADDR_FUN: %p - rdma_fops->compat_ioctl "
			"rdma_fops->compat_ioctl: %x\n", rdma_fops.compat_ioctl,
    			*rdma_fops.compat_ioctl);
	printk("ADDR_FUN: %p - rdma_fops->mmap rdma_fops->mmap: %x\n",
	       		rdma_fops.mmap, *rdma_fops.mmap);
	printk("ADDR_FUN: %p - rdma_fops->open rdma_fops->open: %x\n",
	       		rdma_fops.open, *rdma_fops.open);
	printk("ADDR_FUN: %p - rdma_fops->release rdma_fops->release: %x\n",
	        rdma_fops.release, *rdma_fops.release);
#endif
	if ( (ret = pci_enable_device(dev)) ) {
		ERROR_MSG( KERN_ERR "rdma_probe: cannot enable pci "
				"device err: %d\n", ret);
		DEBUG_MSG("rdma_probe: FINISH\n");
		rdma_present = 0;
		return ret;
	}
	DEBUG_MSG("rdma_probe: dev->dev.init_name: %s \n", dev->dev.init_name);
	DEBUG_MSG("rdma_probe: dev->devfn: %x \n", dev->devfn);
	DEBUG_MSG("rdma_probe: dev->vendor: %x \n", dev->vendor);
	DEBUG_MSG("rdma_probe: dev->device: %x \n", dev->device);
	DEBUG_MSG("rdma_probe: dev->subsystem_vendor: %x \n",
		   dev->subsystem_vendor);
	DEBUG_MSG("rdma_probe: dev->subsystem_device: %x \n",
		   dev->subsystem_device);
	DEBUG_MSG("rdma_probe: dev->devfn: %x \n", dev->devfn);
	if (!(bus = dev->bus)) {
		ERROR_MSG("rdma_probe: bus is NULL\n");
		goto failed;
	}
	for (devfn_rdma = 0; devfn_rdma < 0xff; devfn_rdma++) {
		pcibios_read_config_dword(bus->number, devfn_rdma, 0, &id);
		if (id == 0x71918086) {
			bus_number_rdma = bus->number;
			DEBUG_MSG("rdma_probe: EDBUS-RDMA config space\n");
			for (i = 0; i < 7; i++) {
				pcibios_read_config_dword(bus->number,
						devfn_rdma, i<<2, &val);
				DEBUG_MSG("rdma_probe: %2d 0x%08x\n", i<<2,val);
			}
			break;
		}
	}
	if (devfn_rdma == 0xff) {
		ERROR_MSG("rdma_probe: devfn_rdma == 0xff\n");
		goto failed;
	}
	pcibios_write_config_dword(bus->number, devfn_rdma, 4, 0x7);
	pcibios_read_config_dword(bus->number, devfn_rdma, 4, &val);

	major = register_chrdev(0, board_name, &rdma_fops);
	if ( !major) {
		ERROR_MSG("rdma_probe: There isn't free major\n");
		goto failed;
	}
	DEBUG_MSG("rdma_probe: major: %d\n", major);

	size_rdma_state = sizeof (struct rdma_state);
	rdma_state = (struct rdma_state *)kmalloc(size_rdma_state, GFP_KERNEL);
	if (rdma_state == (struct rdma_state *)NULL) {
		pci_disable_device(dev);
		ERROR_MSG("rdma_probe: rdma_state == NULL\n");
		ret = -EFAULT;
		goto failed;
	}
	memset(rdma_state, 0, size_rdma_state);
	rdma_state->dev_rdma = dev;
	rdma_state->size_rdma_state = size_rdma_state;
	rdma_state->major = major;
	rdma_state->mmio_base = pci_resource_start(dev, PCI_MMIO_BAR);
	rdma_state->mmio_len = pci_resource_len(dev, PCI_MMIO_BAR);

	if ( (ret = pci_request_region(dev, PCI_MMIO_BAR, "rdma MMIO")) )
		goto fail_mmio;

	rdma_state->mmio_vbase = ioremap(rdma_state->mmio_base,
					 rdma_state->mmio_len);
	if ( !rdma_state->mmio_vbase )
	{
		ERROR_MSG("rdma_probe: cannot ioremap MMIO (0x%08lx:0x%x)\n",
			  rdma_state->mmio_base, rdma_state->mmio_len);
		ret = -ENOMEM;
		goto fail_mmio_ioremap;
	}
	DEBUG_MSG("rdma_probe: mmio_vbase: %p mmio_base: 0x%ld mmio_len: %d\n",
			rdma_state->mmio_vbase, rdma_state->mmio_base,
  			rdma_state->mmio_len);

	e0regad = (unsigned char *)rdma_state->mmio_vbase;

	mutex_init(&rdma_state->mu);
	init_rdma_sti(0);
	init_reg();

	rdma_interrupt_p = rdma_interrupt;

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
			/*IRQ_SM	|*/
			IRQ_DSF		|
			IRQ_TDC		|
			IRQ_RDC		|
			IRQ_CMIE
		;
	tr_atl = ATL_B | (atl_v & ATL);
	printk("Reg CAM ATL: %x\n", tr_atl);
	WRR_rdma(SHIFT_CH_IDT(0), ( l_base_mac_addr[3] | (l_base_mac_addr[4] ) << 8));
	time_ID_REQ = 0;
	time_ID_ANS = 0;
	WRR_rdma(SHIFT_CS, 0x2a00);
	msg_cs_dmrcl = 0x1000;
	WRR_rdma(SHIFT_IRQ_MC(0), irq_mc); /* 0x07fe000f */
	WRR_rdma(SHIFT_MSG_CS(0), msg_cs_dmrcl | MSG_CS_SIR_Msg);
	printk("ES: 0x%x MSG_CS: 0x%x\n",
		RDR_rdma(SHIFT_ES(0)), RDR_rdma(SHIFT_MSG_CS(0)));
	printk("ES: 0x%x MSG_CS: 0x%x\n",
		RDR_rdma(SHIFT_ES(0)), RDR_rdma(SHIFT_MSG_CS(0)));
	DEBUG_MSG("SHIFT_IRQ_MC(0): %p 0x%08x (0x%08x)\n",
		SHIFT_IRQ_MC(0), RDR_rdma(SHIFT_IRQ_MC(0)), irq_mc);
	WRR_rdma(SHIFT_ES(0), ES_SM_Ev);
	pci_set_drvdata(dev, rdma_state);
	pci_set_master(dev);
#ifdef MODULE
	if (create_dev_rdma(major))
		goto error_create_dev;
#endif
	if (!version_mem_alloc) {
		printk("RDMA_ALLOC_MEMMORY: OLD VERSION.\n");
	} else {
		printk("RDMA_ALLOC_MEMMORY: NEW VERSION\n");
	}
	DEBUG_MSG("rdma_probe: FINISH\n");
	return 0;
error_create_dev:
	rdma_interrupt_p = NULL;
fail_mmio_ioremap:
	pci_release_region(rdma_state->dev_rdma, PCI_MMIO_BAR);
	pci_disable_device(rdma_state->dev_rdma);
fail_mmio:
failed:
	rdma_present = 0;
	return -1;
}

static void rdma_remove(struct pci_dev *dev)
{
	struct rdma_state *rdma_st = pci_get_drvdata(dev);

	WRR_rdma(SHIFT_IRQ_MC(0), 0);
	WRR_rdma(SHIFT_CAM(0), 0);
	DEBUG_MSG("rdma_remove: START\n");
	if (rdma_st) {
		DEBUG_MSG("rdma_remove rdma_st yes\n");
		iounmap(rdma_st->mmio_vbase);
		pci_release_region(dev, PCI_MMIO_BAR);
		pci_set_drvdata(dev, NULL);
	}
	unregister_chrdev(rdma_state->major, board_name);
	pci_disable_device(rdma_state->dev_rdma);
#ifdef MODULE
	remove_dev_rdma(rdma_state->major);
#endif
	DEBUG_MSG("rdma_remove: FINISH\n");
}

static void __exit rdma_cleanup(void)
{
	DEBUG_MSG("rdma_cleanup: START\n");
	WRR_rdma(SHIFT_IRQ_MC(0), 0);
	WRR_rdma(SHIFT_CAM(0), 0);
	rdma_interrupt_p = NULL;
	pci_unregister_driver(&rdma_driver);
	rdma_event_init = 0;
	kfree(rdma_state);
	rdma_present = 0;
	DEBUG_MSG("rdma_cleanup: FINISH\n");
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
	DEBUG_MSG("rdma_close:  minor:%d\n", minor);
	if (minor < 0) {
		ERROR_MSG("rdma_close: minor < 0\n");
		return minor;
	}
	instance = DEV_inst(minor);
	channel = DEV_chan(minor);
	rdma_sti = &rdma_state->rdma_sti[instance];
	mutex_enter(&rdma_sti->mu);
	rdma_sti->opened &= ~(1 << channel);
	if (channel < 4) {
		chd = &rdma_sti->dma_chans[channel];
		free_chan(chd);
	}
	DEBUG_MSG("rdma_close: opened.minor.instance.channel: 0x%x.%d.%d.%d\n",
		rdma_sti->opened, minor, instance, channel);
	mutex_exit(&rdma_sti->mu);
	DEBUG_MSG("rdma_close: FINISH\n");
	return 0;
}

static int rdma_open(struct inode *inode, struct file *file)
{
	int	minor;
	int	instance;
	int	firstopen = 0;
	int	channel;
	rdma_state_inst_t	*rdma_sti;
	DEBUG_MSG("rdma_open: START\n");
	minor = get_file_minor(file);
	DEBUG_MSG("rdma_open:  minor:%d\n", minor);
	if (minor < 0){
		ERROR_MSG("rdma_open: minor < 0\n");
		return minor;
	}
	instance = DEV_inst(minor);
	channel = DEV_chan(minor);
	if (channel >= MAX_CHANNEL_RDMA) {
		ERROR_MSG("rdma_open: channel(%d) >= MAX_CHANNEL_RDMA(%d)\n",
			  channel, MAX_CHANNEL_RDMA);
		return (-EINVAL);
	}
	rdma_sti = &rdma_state->rdma_sti[instance];
	mutex_enter(&rdma_sti->mu);
	firstopen = (((1 << channel) & rdma_sti->opened) == 0);
	if (firstopen == 0) {
		ERROR_MSG("rdma_open: device EBUSY: minor: %d inst: %d"
				"channel: %d\n", minor, instance, channel);
		mutex_exit(&rdma_sti->mu);
		return (-EBUSY);
	}
	rdma_sti->opened |= (1 << channel);
	DEBUG_MSG("rdma_open: opened.minor.instance.channel: 0x%x.%d.%d.%d\n",
		   rdma_sti->opened, minor, instance, channel);
	mutex_exit(&rdma_sti->mu);
	DEBUG_MSG("rdma_open: FINISH\n");
	return 0;
}

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

	DEBUG_MSG("rdma_ioctl: START cmd %x\n", cmd);
	minor = get_file_minor(filp);
	if (minor < 0) {
		ERROR_MSG("rdma_ioctl: minor(%d) < 0 cmd: %d\n", minor, cmd);
		return minor;
	}
	instance = DEV_inst(minor);
	channel = DEV_chan(minor);
	rdma_sti = &rdma_state->rdma_sti[instance];
	DEBUG_MSG("rdma_ioctl: minor: %d\n", minor);
	/* Get ID link rdma */

	switch (cmd) {
	case RDMA_IOC_GET_ID:
	{
		rdma_link_id.count_links = MAX_NUMIOLINKS;
		rdma_link_id.link_id[0][0] = 1;
		rdma_link_id.link_id[0][1] = RDR_rdma(SHIFT_CH_IDT(0));
		rdma_link_id.link_id[0][2] = RDR_rdma(SHIFT_N_IDT(0));
		if (copy_to_user((void __user *)arg, &rdma_link_id,
		    sizeof (link_id_t)) == -1) {
			    ERROR_MSG("rdma_ioctl:RDMA_IOC_GET_ID: \
					    copy_to_user failed\n");
			    return (-EINVAL);
		    }
		    return 0;
	}
	break;
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
					ret_send_msg = send_msg(xsp,
							MSG_CS_SGP0_Msg							,
							instance, 1, dev_sem);
					if (ret_send_msg > 0)
						break;
					if (ret_send_msg < 0) {
						ERROR_MSG("rdma_ioctl:"
						"FAIL send MSG_CS_SGP0_Msg "
						"from link: %x ret: %d\n",
						instance, ret_send_msg);
					} else if (ret_send_msg == 0) {
						printk("rdma_ioctl: FAIL send"
						" MSG_CS_SGP0_Msg "
						"from link: %x. SM is absent "
						"MSG_CS: %x \n",
						instance, ret_send_msg,
						 RDR_rdma(SHIFT_MSG_CS(0)));
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
		reset_link.tcs = RDR_rdma(SHIFT_DMA_TCS(0));
		reset_link.rcs = RDR_rdma(SHIFT_DMA_RCS(0));
		rval = copy_to_user((reset_link_t __user *)arg, &reset_link,
				     sizeof (reset_link));
		return 0;
	}
	break;
	}

	rval = copy_from_user((caddr_t)&parm, (caddr_t)arg,
			       sizeof (rdma_ioc_parm_t));
	if (rval) {
		ERROR_MSG("rdma_ioctl(%d, %d, %d): copy_from_user failed "
				"size: %ld rval: %ld\n",instance, channel, cmd,
     				sizeof (rdma_ioc_parm_t), rval);
		return (-EINVAL);
	}
	parm.err_no = res = 0;
	switch (cmd) {
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

	case RDMA_IOC_WRR:
	{
		if ((parm.reqlen <= 0xc) ||
		    ((parm.reqlen >= 0x100) && (parm.reqlen <= 0x138)) ||
		    ((parm.reqlen >= 0x200) && (parm.reqlen <= 0x238))) {
#if defined(TRACE_LATENCY_SM)
			user_trace_start_my();
#endif
//			*(unsigned int *)(e0regad+parm.reqlen) = parm.acclen;
			WRR_rdma(e0regad+parm.reqlen, parm.acclen);

#if defined(TRACE_LATENCY_SM)
			user_trace_stop_my();
#endif
		} else
			return (-EINVAL);
		break;
	}

	case RDMA_IOC_RDR:
	{
		if ((parm.reqlen <= 0xc) ||
		    ((parm.reqlen >= 0x100) && (parm.reqlen <= 0x138)) ||
		    ((parm.reqlen >= 0x200) && (parm.reqlen <= 0x238))) {
#if defined(TRACE_LATENCY_SM)
			user_trace_start_my();
#endif
//			*(unsigned int *)(e0regad+parm.reqlen) = parm.acclen;
			parm.acclen = RDR_rdma(e0regad+parm.reqlen);
#if defined(TRACE_LATENCY_SM)
			user_trace_stop_my();
#endif
		} else
			return (-EINVAL);
		break;
	}

	case RDMA_WAKEUP_WRITER:
	{
		dev_rdma_sem_t	*dev_sem;
		rw_state_p	pd;

		pd = &rdma_sti->rw_states_d[WRITER];
		dev_sem = &pd->dev_rdma_sem;
		raw_spin_lock_irq(&dev_sem->lock);
		rdma_cv_broadcast_rdma(&pd->dev_rdma_sem);
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
		rdma_cv_broadcast_rdma(&pd->dev_rdma_sem);
		raw_spin_unlock_irq(&dev_sem->lock);
		break;
	}
	case RDMA_IOC_DUMPREG0:
	case RDMA_IOC_DUMPREG1:
		read_regs_rdma();
		break;
	case RDMA_IOC_BROAD:
	{
		dev_rdma_sem_t *dev_sem;
		rdma_state_inst_t *xspi = &rdma_state->rdma_sti[0];
		rw_state_p pcam;

		pcam = &xspi->rw_states_m[0];
		dev_sem = &pcam->dev_rdma_sem;
		raw_spin_lock_irq(&dev_sem->lock);
		parm.reqlen = 0;
		if (pcam->stat) {
			rdma_cv_broadcast_rdma(dev_sem);
			parm.reqlen = 1;
		}
		raw_spin_unlock_irq(&dev_sem->lock);
	}
		break;
	case RDMA_IOC_WAITD:
	{
		dev_rdma_sem_t *dev_sem;
		rdma_state_inst_t *xspi = &rdma_state->rdma_sti[0];
		rw_state_p pcam;
		int ret_time_dwait;

		pcam = &xspi->rw_states_m[0];
		dev_sem = &pcam->dev_rdma_sem;
		raw_spin_lock_irq(&dev_sem->lock);
		pcam->stat = 1;
		dev_sem->num_obmen++;
		ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, IO_TIMEOUT);
		parm.reqlen = ret_time_dwait;
		parm.acclen = dev_sem->irq_count_rdma;
		pcam->stat = dev_sem->irq_count_rdma = 0;
		raw_spin_unlock_irq(&dev_sem->lock);
	}
		break;
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
			ERROR_MSG("rdma_ioctl: CLEAN_TDC: (%d,%d): "
				  "Unexpected channel\n", instance, channel);
			return -EIO;
		}
		dev_sem = &pd->dev_rdma_sem;
		dev_sem->num_obmen = 0;
		dev_sem->irq_count_rdma = 0;
		dbg_ioctl("CLEAN_TDC:  %d dev_sem->num_obmen: %d\n",
			instance, dev_sem->num_obmen);
	}
		break;
#define COUNT_CLK 1000
	case  RDMA_GET_CLKR:
	{
        	u64 time[COUNT_CLK];
		int i;

		for (i = 0; i < COUNT_CLK; i++)
			time[i] = E2K_GET_DSREG(clkr);
		for (i = 0; i < COUNT_CLK; i++)
			printk("0x%lx\n", time[i]);
	}
		break;
	case  RDMA_GET_MAX_CLKR:
	{
        	u64 time[COUNT_CLK];
        	u64 max_clk = 0;
        	u64 max_clk_all = 0;
		int i;
		int count_rep_clk = 0;

#define COUNT_REP_CLK 100
rep_max_clk:
		for (i = 0; i < COUNT_CLK; i++)
			time[i] = E2K_GET_DSREG(clkr);
		for (i = 0; i < COUNT_CLK; i++) {
			if (max_clk < time[i])
				max_clk = time[i];
		}
		if (max_clk_all < max_clk) {
			max_clk_all = max_clk;
			printk("0x%lx - max_clk_all\n", max_clk_all);
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
			ERROR_MSG("rdma_ioctl: CLEAN_RDC: (%d,%d): "
				  "Unexpected channel\n", instance, channel);
			return -EIO;
		}
		dev_sem = &pd->dev_rdma_sem;
		dev_sem->num_obmen = 0;
		dev_sem->irq_count_rdma = 0;
		dbg_ioctl("CLEAN_RDC: intr_rdc_count[%d]: %x "
				"dev_sem->num_obmen: %d\n", instance,
     				intr_rdc_count[instance], dev_sem->num_obmen);
	}
		break;
	case RDMA_TIMER_FOR_READ :
	{
		dbg_ioctl("cmd = RDMA_TIMER_FOR_READ, "
			"reqlen (mksec) = 0x%x\n",
			MIN_min(TIMER_FOR_READ_MAX, parm.reqlen));
	        parm.acclen = (&rdma_sti->rw_states_d[READER])->timer_for_read;
	        (&rdma_sti->rw_states_d[READER])->timer_for_read =
	        	MAX_max(TIMER_FOR_READ_MIN, MIN_min(TIMER_FOR_READ_MAX,
				parm.reqlen));
	        parm.reqlen = (&rdma_sti->rw_states_d[READER])->timer_for_read;
	}
		break;

	case RDMA_TIMER_FOR_WRITE:
	{
		dbg_ioctl("cmd = RDMA_TIMER_FOR_WRITE, "
			"reqlen (mksec) = 0x%x\n",
			MIN_min(TIMER_FOR_WRITE_MAX, parm.reqlen));
	        parm.acclen = (&rdma_sti->rw_states_d[WRITER])->timer_for_write;
	        (&rdma_sti->rw_states_d[WRITER])->timer_for_write =
	        	MAX_max(TIMER_FOR_WRITE_MIN,
				MIN_min(TIMER_FOR_WRITE_MAX, parm.reqlen));
	        parm.reqlen = (&rdma_sti->rw_states_d[WRITER])->timer_for_write;
	}
		break;
	case RDMA_IOC_ALLOCB:
	{
		DEBUG_MSG("cmd = RDMA_IOC_ALLOCB, "
			"reqlen = 0x%lx\n",
			(long)parm.reqlen);
		chd = &rdma_sti->dma_chans[channel];
		if (chd->allocs != RCS_EMPTY) {
			ERROR_MSG("rdma_ioctl: RDMA_IOC_ALLOCB:  "
				"WRONGLY finish: chd->allocs: %i\n",
    				chd->allocs);
			res = -1;
			parm.err_no = RDMA_E_ALLOC;
			parm.acclen = chd->allocs;
			break;
		}
		parm.acclen = init_chan(chd, parm.reqlen, parm.rwmode);
		if (parm.acclen < -1) {
			ERROR_MSG("rdma_ioctl: RDMA_IOC_ALLOCB:  "
					"WRONGLY finish: chd->allocs: %i\n",
      					chd->allocs);
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
		DEBUG_MSG("rdma_ioctl: phys: 0x%x full: 0x%08x\n", chd->dma,
			  chd->full);
	}
		break;
	case  RDMA_GET_STAT:
	{
		stat_rdma.cur_clock = jiffies;
		if (copy_to_user((caddr_t)arg, (caddr_t)&stat_rdma,
			sizeof (struct stat_rdma)) == -1) {
			ERROR_MSG("rdma_ioctl: RDMA_GET_STAT:"
					"copy_to_user failed\n");
			return (EINVAL);
		}
		return 0;
	}
	case  RDMA_GET_EVENT:
	{
		unsigned long flags;

		raw_spin_lock_irqsave(&mu_fix_event, flags);
		if (copy_to_user((caddr_t)arg, (caddr_t)(&rdma_event),
			sizeof (rdma_event_t)) == -1) {
			raw_spin_unlock_irqrestore(&mu_fix_event, flags);
			ERROR_MSG("rdma_ioctl: RDMA_GET_EVENT: "
					"copy_to_user failed\n");
			return (EINVAL);
		}
		raw_spin_unlock_irqrestore(&mu_fix_event, flags);
		return 0;
	}

	case RDMA_SET_STAT:
	{
		memset(&stat_rdma, 0, sizeof (struct stat_rdma));
	}
		break;
	case RDMA_GET_CAM :
	{
		unsigned int atl;

		atl = RDR_rdma(SHIFT_CAM(0));
		parm.acclen = atl;
		event_ioctl(0, RDMA_GET_CAM_EVENT, 0, atl);
	}
		break;
	case RDMA_IS_CAM_YES :
	{
		unsigned int	atl;
		int		ret_time_dwait = 0;
		dev_rdma_sem_t 	*dev_sem;
		rw_state_p	pcam;

		event_ioctl(0, RDMA_IS_CAM_YES_EVENT, 1, 0);
		pcam = &rdma_sti->ralive;
		dev_sem = &pcam->dev_rdma_sem;
		ret_time_dwait = 0;
		atl = RDR_rdma(SHIFT_CAM(0));
		if (atl) {
			parm.acclen = atl;
			parm.err_no = 0;
			goto end_RDMA_IS_CAM_YES;
		}
		raw_spin_lock_irq(&dev_sem->lock);
		dev_sem->irq_count_rdma = 0;
		pcam->stat = 1;
		ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, IO_TIMEOUT);
		pcam->stat = 0;
		raw_spin_unlock_irq(&dev_sem->lock);
		parm.acclen = RDR_rdma(SHIFT_CAM(0));
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
		unsigned int atl;
		int ret_time_dwait = 0;
		dev_rdma_sem_t *dev_sem;
		rw_state_p pcam;

		event_ioctl(0, RDMA_IS_CAM_NO_EVENT, 1, 0);
		dbg_ioctl("RDMA_IS_CAM_NO\n");
		pcam = &rdma_sti->talive;
		dev_sem = &pcam->dev_rdma_sem;
		atl = RDR_rdma(SHIFT_CAM(0));
		if (!atl) {
			parm.acclen = 0;
			parm.err_no = 0;
			goto end_RDMA_IS_CAM_NO;
		}
		raw_spin_lock_irq(&dev_sem->lock);
		dev_sem->irq_count_rdma = 0;
		pcam->stat = 1;
		ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, IO_TIMEOUT);
		pcam->stat = 0;
		raw_spin_unlock_irq(&dev_sem->lock);
		parm.acclen = RDR_rdma(SHIFT_CAM(0));
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
		parm.clkr = E2K_GET_DSREG(clkr);
		parm.clkr1 = pcam->clkr;
		parm.reqlen = pcam->int_cnt;
	}
		event_ioctl(0, RDMA_IS_CAM_NO_EVENT, 0, 0);
		break;
	case RDMA_UNSET_CAM :
	{
		unsigned int atl;
		dbg_ioctl("RDMA_UNSET_CAM(%d)\n", instance);
		atl = RDR_rdma(SHIFT_CAM(0));
		state_cam = RDMA_UNSET_CAM;
		event_ioctl(0, RDMA_UNSET_CAM_EVENT, 1, atl);
		parm.clkr = E2K_GET_DSREG(clkr);
		parm.reqlen = atl;
		/* dbg_ioctl("SHIFT_CAM(%d): 0x%08x\n", instance, atl);*/
		WRR_rdma(SHIFT_CAM(0), 0);
		event_ioctl(atl, RDMA_UNSET_CAM_EVENT, 0,
			    RDR_rdma(SHIFT_CAM(instance)));
	}
		break;
	case RDMA_SET_CAM :
	{
		unsigned int atl;
		dbg_ioctl("RDMA_SET_CAM(%d)\n", instance);
		atl = RDR_rdma(SHIFT_CAM(0));
		state_cam = RDMA_SET_CAM;
		event_ioctl(0, RDMA_SET_CAM_EVENT, 1, atl);
		parm.clkr = E2K_GET_DSREG(clkr);
		parm.reqlen = atl;
		WRR_rdma(SHIFT_CAM(0), tr_atl);
		event_ioctl(atl, RDMA_SET_CAM_EVENT, 0,
			    RDR_rdma(SHIFT_CAM(instance)));
	}
		break;
	case RDMA_SET_ATL :
	{
		unsigned int atl;

		dbg_ioctl("RDMA_SET_ATL(%d): reqlen: 0x%x mksec: %d\n",
					instance, parm.reqlen, parm.reqlen*10);
		event_ioctl(0, RDMA_SET_ATL_EVENT, 1, parm.reqlen);
		atl = RDR_rdma(SHIFT_CAM(instance));
		dbg_ioctl("SHIFT_CAM(%d): 0x%08x\n", instance, atl);
		tr_atl = ATL_B | (parm.reqlen & ATL);
		WRR_rdma(SHIFT_CAM(instance), tr_atl);
		atl = RDR_rdma(SHIFT_CAM(instance));
		event_ioctl(0, RDMA_SET_ATL_EVENT, 0, atl);
		parm.acclen = atl;
	}
		break;
#if 0
/****************************************************************/
/* 1. На основной запускается RDMA_SET_RAlive.			*/
/* По этой команде устанавливается xspi->ralive->stat = 1 и	*/
/* начинается ожидание.						*/
/*								*/
/* 2. по приходу GP3 без просыпания устанавливается		*/
/* xspi->ralive->stat = 2 и RAlive. 				*/
/* Это означает, что резерв есть.				*/
/*								*/
/* 3. При пропадании GP3 без просыпания устанавливается 	*/
/* spi->ralive->stat = 1 и снимается RAlive.			*/
/* Это означает, что резерва нет.				*/
/* Далее - п. 2							*/
/* Проснуться можно только по сигналу.				*/
/*								*/
/* 1. На резервной запускается RDMA_SET_TAlive.			*/
/* По этой команде устанавливаются xspi->talive->stat = 1 и 	*/
/* TAlive и начинается ожидание.				*/
/* Если основная запущена,начинается обмен GP3.			*/
/* Если обмен прекратился или не начался, будет возврат из 	*/
/* ожидания с установкой xspi->talive->stat = 0 и гашением 	*/
/* TAlive.							*/
/* Это означает, что основной нет.				*/
/*								*/
/* Запрос состояния - команда GET_STAT_ALIVE			*/
/* В parm.reqlen возвращается интервал посылки импульсов	*/
/* В parm.acclen возвращается состояние:			*/
/* MAIN_REZERV_YES - основная, резерв есть			*/
/* MAIN_REZERV_NOT - основная, резерва нет			*/
/* REZERV_MAIN_YES - резервная, основная есть			*/
/* REZERV_MAIN_NOT - неопределенное состояние			*/
/****************************************************************/

	case GET_STAT_ALIVE :
	{
		unsigned int atl;
		rw_state_p	pcamr, pcamt;

		event_ioctl(0, GET_STAT_ALIVE_EVENT, 1, 0);
		dbg_ioctl("GET_STAT_ALIVE(%d)\n", instance);
		atl = RDR_rdma(SHIFT_CAM(instance));
		parm.reqlen = atl & ATL;
		pcamt = &rdma_sti->talive;
		pcamr = &rdma_sti->ralive;
		dbg_ioctl("SHIFT_CAM(%d): 0x%08x\n", instance, atl);
		if (atl && (pcamr->stat == 1)) {
			parm.acclen = MAIN_REZERV_NOT;
		} else
		if (atl && (pcamr->stat == 2)) {
			parm.acclen = MAIN_REZERV_YES;
		} else
		if (atl && (pcamt->stat == 1)) {
			parm.acclen = REZERV_MAIN_YES;
		} else
			parm.acclen = REZERV_MAIN_NOT;
		event_ioctl(atl, GET_STAT_ALIVE_EVENT, 0, parm.acclen);
}

//#define MAIN_REZERV_YES	1	// - основная, резерв есть
//#define MAIN_REZERV_NOT	2	// - основная, резерва нет
//#define REZERV_MAIN_YES	3	// - резервная, основная есть
//#define REZERV_MAIN_NOT	4	// - неопределенное состояние
		break;

	case RDMA_SET_TAlive :
	{
		unsigned int	atl;
		int		ret_time_dwait = 0;
		dev_rdma_sem_t 	*dev_sem;
		rw_state_p	pcam;

		event_ioctl(0, RDMA_SET_TAlive_EVENT, 1, 0);
		dbg_ioctl("RDMA_SET_TAlive(%d)\n", instance);
		pcam = &rdma_sti->talive;
		dev_sem = &pcam->dev_rdma_sem;
		ret_time_dwait = 0;
		raw_spin_lock_irq(&dev_sem->wait_head.lock);
		if (pcam->stat) {
			dbg_ioctl("RDMA_SET_TAlive(%d): ERROR pcam->stat: %d\n",
					   instance, pcam->stat);
			parm.err_no = RDMA_E_INVAL;
			goto end_set_talive;
		}
		atl = RDR_rdma(SHIFT_CAM(instance));
		dbg_ioctl("SHIFT_CAM(%d): 0x%08x\n", instance, atl);
		dev_sem->irq_count_rdma = 0;
//		mcg_cs = RDR_rdma(SHIFT_MSG_CS(instance));
//		WRR_rdma(SHIFT_MSG_CS(instance), 1);
//		WRR_rdma(SHIFT_MSG_CS(instance), msg_cs_dmrcl);
		WRR_rdma(SHIFT_CAM(instance), atl | TAlive);
		pcam->stat = 1;
		ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, IO_TIMEOUT);
		if (ret_time_dwait == -2) {
			pcam->stat = 0;
			parm.err_no = RDMA_E_SIGNAL;
			parm.reqlen = RDR_rdma(SHIFT_CAM(instance));
			parm.rwmode = ret_time_dwait;
			parm.acclen = ret_time_dwait;

			raw_spin_unlock_irq(&dev_sem->wait_head.lock);
			goto unset_talive;
		}
		if (pcam->stat == ES_MSF_Ev)
			parm.err_no = RDMA_E_MSF_WRD;
		else
			parm.err_no = RDMA_E_INVOP;
		pcam->stat = 0;
		parm.reqlen = RDR_rdma(SHIFT_CAM(instance));
		parm.acclen = ret_time_dwait;
end_set_talive:
		raw_spin_unlock_irq(&dev_sem->wait_head.lock);
		event_ioctl(ret_time_dwait, RDMA_SET_TAlive_EVENT, 0,
					   parm.reqlen);
			goto unset_talive;
	}
		break;
	case RDMA_SET_RAlive :
	{
		unsigned int atl;
		int ret_time_dwait;
		dev_rdma_sem_t 	*dev_sem;
		rw_state_p	pcam;

		event_ioctl(0, RDMA_SET_RAlive_EVENT, 1, 0);
		dbg_ioctl("RDMA_SET_RAlive(%d)\n", instance);
		pcam = &rdma_sti->ralive;
		dev_sem = &pcam->dev_rdma_sem;
		raw_spin_lock_irq(&dev_sem->wait_head.lock);
		if (pcam->stat) {
			dbg_ioctl("RDMA_SET_RAlive(%d): ERROR pcam->stat: %d\n",
					   instance, pcam->stat);
			parm.err_no = 1;
			goto wait_set_ralive;
//			goto end_set_ralive;
		}
		dbg_ioctl("RDMA_SET_RAlive(%d):pcam->int_ac == 0,change to 1\n",
					   instance);
		atl = RDR_rdma(SHIFT_CAM(instance));
//		mcg_cs = RDR_rdma(SHIFT_MSG_CS(instance));
//		WRR_rdma(SHIFT_MSG_CS(instance), 1);
//		WRR_rdma(SHIFT_MSG_CS(instance), msg_cs_dmrcl);
		WRR_rdma(SHIFT_CAM(instance), atl & ATL);
		pcam->stat = 1;
wait_set_ralive:
		dev_sem->irq_count_rdma = 0;
		ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, IO_TIMEOUT);
		if (ret_time_dwait == -2) {
			pcam->stat = 0;
			parm.err_no = 0;
			parm.reqlen = RDR_rdma(SHIFT_CAM(instance));
			parm.acclen = ret_time_dwait;
			raw_spin_unlock_irq(&dev_sem->wait_head.lock);
			goto unset_ralive;
		}
		dev_sem->irq_count_rdma = 0;
//		parm.err_no = 0;
//		pcam->stat = 0;
//end_set_ralive:
		atl = RDR_rdma(SHIFT_CAM(instance));
		dbg_ioctl("SHIFT_CAM(%d): 0x%08x\n", instance, atl);
		raw_spin_unlock_irq(&dev_sem->wait_head.lock);
		event_ioctl(ret_time_dwait, RDMA_SET_RAlive_EVENT, 0, atl);
	}
		break;
unset_talive:
	case RDMA_UNSET_TAlive :
	{
		unsigned int atl;
		event_ioctl(0, RDMA_UNSET_TAlive_EVENT, 1, 0);
		dbg_ioctl("RDMA_SET_TAlive(%d)\n", instance);
		atl = RDR_rdma(SHIFT_CAM(instance));
		dbg_ioctl("SHIFT_CAM(%d): 0x%08x\n", instance, atl);
		WRR_rdma(SHIFT_CAM(instance), atl & ~TAlive);
		event_ioctl(atl, RDMA_UNSET_TAlive_EVENT, 0,
					  RDR_rdma(SHIFT_CAM(instance)));
	}
		break;
unset_ralive:
	case RDMA_UNSET_RAlive :
	{
		unsigned int atl;
		event_ioctl(0, RDMA_UNSET_RAlive_EVENT, 1, 0);
		dbg_ioctl("RDMA_SET_RAlive(%d)\n", instance);
		atl = RDR_rdma(SHIFT_CAM(instance));
		dbg_ioctl("SHIFT_CAM(%d): 0x%08x\n", instance, atl);
		WRR_rdma(SHIFT_CAM(instance), atl & ~RAlive);
		event_ioctl(atl, RDMA_UNSET_RAlive_EVENT, 0,
					  RDR_rdma(SHIFT_CAM(instance)));
	}
		break;
#endif
	default :
		ERROR_MSG("rdma_ioctl(%d, %d): default operation NOT EXPECTED "
				"cmd: %i\n", instance, channel, cmd);
		res = -1;
		parm.err_no = RDMA_E_INVOP;
	}

	rval = copy_to_user((caddr_t)arg, (caddr_t)&parm,
			     sizeof (rdma_ioc_parm_t));
	if (rval) {
		ERROR_MSG("rdma_ioctl(%d, %d, %d): copy_to_user failed "
				"size: %ld rval: %ld\n", instance, channel, cmd,
     				sizeof (rdma_ioc_parm_t), rval);
		return (-EINVAL);
	}
	if (res == 0) {
		DEBUG_MSG("rdma_ioctl(%d, %d): NORMAL_END: acclen=%x *****\n\n",
				instance, channel, parm.acclen);
		DEBUG_MSG("rdma_ioctl FINISH\n");
		return 0;
	}
	ERROR_MSG("rdma_ioctl: FAIL\n");
		DEBUG_MSG("rdma_ioctl FINISH\n");
	return -EINVAL; 	/* !? return l>0 == return -1 !?*/
}

#ifdef CONFIG_COMPAT
static int do_ioctl(struct file *f, unsigned cmd, unsigned long arg)
{
	int ret;
	ret = rdma_ioctl( f, cmd, arg);
	return ret;
}

static long rdma_compat_ioctl(struct file *f, unsigned cmd, unsigned long arg)
{
	switch (cmd) {
	case RDMA_IOC_DUMPREG0:
	case RDMA_IOC_DUMPREG1:
	case RDMA_IOC_WRR:
	case RDMA_IOC_RDR:
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
	case RDMA_WAKEUP_WRITER:
	case RDMA_WAKEUP_READER:
	case RDMA_IOC_GET_ID:
	case RDMA_IOC_RESET_DMA:
	case RDMA_IOC_SET_MODE_RFSM:
	case RDMA_IOC_SET_MODE_EXIT_GP0:
		return do_ioctl(f, cmd, arg);
	default:
		return -ENOIOCTLCMD;
	}
}
#endif

static ssize_t rdma_read(struct file *filp, char *buf, size_t size, loff_t *pos)
{
	int			minor;
	int			instance;
	int			channel;
	int			ret;
	rdma_state_inst_t	*rdma_sti;
	rdma_ioc_parm_t 	PRM;
	size_t			rval;

	DEBUG_MSG("rdma_read: START\n");
	minor = get_file_minor(filp);
	if (minor < 0)
		return 0;
	instance = DEV_inst(minor);
	channel = DEV_chan(minor);
	rdma_sti = &rdma_state->rdma_sti[instance];
	rval = copy_from_user((caddr_t)&PRM, (caddr_t)buf,
			       sizeof (rdma_ioc_parm_t));
	if (rval) {
		ERROR_MSG("rdma_read(%d, %d): copy_from_user failed size: %ld"
				"rval: %ld\n", instance, channel,
    				sizeof (rdma_ioc_parm_t), rval);
		return (-EINVAL);
	}
	PRM.reqlen = 0;
	ret = read_buf(rdma_sti, buf, size, instance, channel, &PRM);
	PRM.clkr = E2K_GET_DSREG(clkr);
	rval = copy_to_user((caddr_t)buf, (caddr_t)&PRM,
			     sizeof (rdma_ioc_parm_t));
	if (rval) {
		ERROR_MSG("rdma_read(%d, %d): copy_to_user failed size: %ld"
				"rval: %ld\n", instance, channel,
    				sizeof (rdma_ioc_parm_t), rval);
		return (-EINVAL);
	}
	DEBUG_MSG("rdma_read: FINISH\n");
	return ret;
}

static ssize_t rdma_write(struct file *filp, const char *buf, size_t size,
			  loff_t *pos)
{
	int minor;
	int instance;
	int channel;
	int ret;
	rdma_state_inst_t *rdma_sti;
	rdma_ioc_parm_t PRM;
	size_t rval;

	DEBUG_MSG("rdma_write: START\n");
	minor = get_file_minor(filp);
	if (minor < 0)
		return 0;
	instance = DEV_inst(minor);
	channel = DEV_chan(minor);
	rdma_sti = &rdma_state->rdma_sti[instance];
	rval = copy_from_user((caddr_t)&PRM, (caddr_t)buf,
			       sizeof (rdma_ioc_parm_t));
	if (rval) {
		ERROR_MSG("rdma_write(%d, %d): copy_from_user failed size: %ld"
				"rval: %ld\n", instance, channel,
     				sizeof (rdma_ioc_parm_t), rval);
		return (-EINVAL);
	}
	PRM.reqlen = 0;
	ret = write_buf(rdma_sti, buf, size, instance, channel, &PRM);
	PRM.clkr = E2K_GET_DSREG(clkr);
	rval = copy_to_user((caddr_t)buf, (caddr_t)&PRM,
			     sizeof (rdma_ioc_parm_t));
	if (rval) {
		ERROR_MSG("rdma_write(%d, %d): copy_to_user failed size: %ld"
				"rval: %ld\n", instance, channel,
    				sizeof (rdma_ioc_parm_t), rval);
		return (-EINVAL);
	}
	DEBUG_MSG("rdma_write: FINISH\n");
	return ret;
}

int rdma_remap_page_tbl(void *va, size_t sz, struct vm_area_struct *vma)
{
	unsigned long 	pha;
	unsigned long 	sz_pha;
	unsigned long 	vm_end;
	unsigned long 	vm_start;
	unsigned long 	vm_pgoff;
	size_t  	size;
	rdma_tbl_32_struct_t	*ptbl;

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
	for (ptbl = (rdma_tbl_32_struct_t *)va; ptbl; ptbl++) {
		rdma_addr_struct_t pxx;
		pxx.addr = (unsigned long)ptbl;
		DEBUG_MSG("rdma_remap_page_tbl: 0x%08x%08x ptbl\n",
			  pxx.fields.haddr, pxx.fields.laddr);
		pxx.addr = ptbl->laddr;
		DEBUG_MSG("rdma_remap_page_tbl: 0x%08x%08x ptbl->addr\n",
			  pxx.fields.haddr, pxx.fields.laddr);
		pha = (unsigned long)ptbl->laddr;
		pxx.addr = (unsigned long)phys_to_virt(pha);
		DEBUG_MSG("rdma_remap_page_tbl: 0x%08x%08x __va(ptbl->addr)\n",
			  pxx.fields.haddr, pxx.fields.laddr);
		pxx.addr = pha;
		DEBUG_MSG("rdma_remap_page_tbl: 0x%08x%08x __fa(ptbl->addr)\n",
			  pxx.fields.haddr, pxx.fields.laddr);
		sz_pha = ptbl->sz;
		if (remap_pfn_range(vma, vm_start, (pha >> PAGE_SHIFT), sz_pha,
		    vma->vm_page_prot)) {
			    ERROR_MSG("rdma_remap_page_tbl:FAIL remap_pfn_range\n");
			    return -EAGAIN;
		    }
		    vm_start += sz_pha;
		    DEBUG_MSG("rdma_remap_page_tbl: vm_start: %lx vm_end: %lx "
				    "sz_pha: %lx \n", vm_start, vm_end, sz_pha);
		    if (vm_start >= vm_end) {
			    DEBUG_MSG("rdma_remap_page_tbl: "
					    "vm_start(%lx) >= vm_end(%lx)\n", vm_start, vm_end);
			    break;
		    }
	}
	DEBUG_MSG("rdma_remap_page_tbl: FINISH\n");
	return 0;
}

int rdma_remap_page(void *va, size_t sz,
		    struct vm_area_struct *vma)
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
//  	if ((vma->vm_pgoff << PAGE_SHIFT) > size) return -ENXIO;
	pha += (vma->vm_pgoff << PAGE_SHIFT);
	vm_end = vma->vm_end;
	vm_start = vma->vm_start;
	vm_pgoff = vma->vm_pgoff;

	if ((vm_end - vm_start) < size)
		size = vm_end - vm_start;

//   	vma->vm_flags |= (VM_READ | VM_WRITE | VM_SHM);
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

int get_file_minor(struct file *file)
{
	int	major;
	struct dentry	*f_dentry_rdma;
	struct inode *d_inode;

	f_dentry_rdma = file->f_dentry;
	DEBUG_MSG("get_file_minor: START f_dentry_rdma: %p file->f_dentry:%p\n",
		   f_dentry_rdma, file->f_dentry);
	if (!f_dentry_rdma) {
		ERROR_MSG( "get_file_major: file->f_dentry is NULL\n");
		return -EBADF;
	}
	d_inode = f_dentry_rdma->d_inode;
	if (!d_inode) {
		ERROR_MSG( "get_file_major: f_dentry->d_inode is NULL\n");
		return -EBADF;
	}
	major = MAJOR(d_inode->i_rdev);
	if (major != rdma_state->major) {
		ERROR_MSG( "get_file_major: major(%d)!=rdma_state->major(%d)\n",
			   major, rdma_state->major);
		return -EBADF;
	}
	DEBUG_MSG("get_file_minor: FINISH\n");
	return MINOR(d_inode->i_rdev);
}

void init_reg(void)
{
	rdma_reg_VID       = ADDR_VID;	    /* RDMA VID 		*/
	rdma_reg_CH0_IDT   = ADDR_CH0_IDT;  /* RDMA ID/Type 		*/
	rdma_reg_CS        = ADDR_CS;	    /* RDMA Control/Status 000028a0 */
	rdma_reg_CH1_IDT   = ADDR_CH1_IDT;  /* RDMA ID/Type 		*/
	rdma_reg_DD_ID_0   = ADDR_DD_ID(0); /* Data Destination ID 	*/
	rdma_reg_DMD_ID_0  = ADDR_DMD_ID(0);/* Data Message Destination ID */
	rdma_reg_N_IDT_0   = ADDR_N_IDT(0); /* Neighbour ID/Type 	*/
	rdma_reg_ES_0	   = ADDR_ES(0);    /* Event Status 		*/
	rdma_reg_IRQ_MC_0  = ADDR_IRQ_MC(0);/* Interrupt Mask Control 	*/
	rdma_reg_DMA_TCS_0 = ADDR_DMA_TCS(0);/* DMA Tx Control/Status 	*/
	rdma_reg_DMA_TSA_0 = ADDR_DMA_TSA(0);/* DMA Tx Start Address 	*/
	rdma_reg_DMA_TBC_0 = ADDR_DMA_TBC(0);/* DMA Tx Byte Counter 	*/
	rdma_reg_DMA_RCS_0 = ADDR_DMA_RCS(0);/* DMA Rx Control/Status 	*/
	rdma_reg_DMA_RSA_0 = ADDR_DMA_RSA(0);/* DMA Rx Start Address 	*/
	rdma_reg_DMA_RBC_0 = ADDR_DMA_RBC(0);/* DMA Rx Byte Counter 	*/
	rdma_reg_MSG_CS_0  = ADDR_MSG_CS(0); /* Messages Control/Status */
	rdma_reg_TDMSG_0   = ADDR_TDMSG(0);  /* Tx Data_Messages Buffer */
	rdma_reg_RDMSG_0   = ADDR_RDMSG(0);  /* Rx Data_Messages Buffer */
	rdma_reg_CAM_0	   = ADDR_CAM(0);    /* CAM - channel alive management*/

	rdma_reg_DD_ID_1	= ADDR_DD_ID(1); /* Data Destination ID */
	rdma_reg_DMD_ID_1	= ADDR_DMD_ID(1);/*Data Message Destination ID*/
	rdma_reg_N_IDT_1	= ADDR_N_IDT(1); /* Neighbour ID/Type 	*/
	rdma_reg_ES_1		= ADDR_ES(1);	 /* Event Status 	*/
	rdma_reg_IRQ_MC_1	= ADDR_IRQ_MC(1);/* Interrupt Mask Control */
	rdma_reg_DMA_TCS_1	= ADDR_DMA_TCS(1);/* DMA Tx Control/Status */
	rdma_reg_DMA_TSA_1	= ADDR_DMA_TSA(1);/* DMA Tx Start Address */
	rdma_reg_DMA_TBC_1	= ADDR_DMA_TBC(1);/* DMA Tx Byte Counter */
	rdma_reg_DMA_RCS_1	= ADDR_DMA_RCS(1);/* DMA Rx Control/Status */
	rdma_reg_DMA_RSA_1	= ADDR_DMA_RSA(1);/* DMA Rx Start Address */
	rdma_reg_DMA_RBC_1	= ADDR_DMA_RBC(1);/* DMA Rx Byte Counter */
	rdma_reg_MSG_CS_1	= ADDR_MSG_CS(1); /* Messages Control/Status */
	rdma_reg_TDMSG_1	= ADDR_TDMSG(1);  /* Tx Data_Messages Buffer */
	rdma_reg_RDMSG_1	= ADDR_RDMSG(1);  /* Rx Data_Messages Buffer */
	rdma_reg_CAM_1		= ADDR_CAM(1);/* CAM-channel alive management */
}

void init_rdma_sti(int instance)
{
	rw_state_t	*pd, *pm;
	int		i;
	dev_rdma_sem_t 	*dev_sem;
	rdma_state_inst_t *rdma_sti = &rdma_state->rdma_sti[instance];

	printk("%ld - raw_spinlock_t\n", sizeof (raw_spinlock_t));
	printk("%ld - spinlock_t\n", sizeof (spinlock_t));
	rdma_sti->instance = instance;
	mutex_init(&rdma_sti->mu);
	memset(&rdma_event, 0, sizeof (struct rdma_event));
	/* spin_lock_init(&mu_fix_event); */
	memset(&stat_rdma, 0, sizeof (struct stat_rdma));
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
}

void read_regs_rdma(void)
{
	printk("0x%08x - 0x0 SHIFT_VID\n", RDR_rdma(SHIFT_VID));
	printk("0x%08x - 0x4 SHIFT_CH0_IDT\n", RDR_rdma(SHIFT_CH0_IDT));
	printk("0x%08x - 0x8 SHIFT_CS\n", RDR_rdma(SHIFT_CS));
	printk("0x%08x - 0xc SHIFT_CH1_IDT\n", RDR_rdma(SHIFT_CH1_IDT));
	printk("0x%08x 0x100 - SHIFT_DD_ID\n", RDR_rdma(SHIFT_DD_ID(0)));
	printk("0x%08x 0x104 - SHIFT_DMD_ID\n", RDR_rdma(SHIFT_DMD_ID(0)));
	printk("0x%08x 0x108 - SHIFT_N_IDT\n", RDR_rdma(SHIFT_N_IDT(0)));
	printk("0x%08x 0x10c - SHIFT_ES\n", RDR_rdma(SHIFT_ES(0)));
	printk("0x%08x 0x110 - SHIFT_IRQ_MC\n", RDR_rdma(SHIFT_IRQ_MC(0)));
	printk("0x%08x 0x114 - SHIFT_DMA_TCS\n", RDR_rdma(SHIFT_DMA_TCS(0)));
	printk("0x%08x 0x118 - SHIFT_DMA_TSA\n", RDR_rdma(SHIFT_DMA_TSA(0)));
	printk("0x%08x 0x11c - SHIFT_DMA_TBC\n", RDR_rdma(SHIFT_DMA_TBC(0)));
	printk("0x%08x 0x120 - SHIFT_DMA_RCS\n", RDR_rdma(SHIFT_DMA_RCS(0)));
	printk("0x%08x 0x124 - SHIFT_DMA_RSA\n", RDR_rdma(SHIFT_DMA_RSA(0)));
	printk("0x%08x 0x128 - SHIFT_DMA_RBC\n", RDR_rdma(SHIFT_DMA_RBC(0)));
	printk("0x%08x 0x12c - SHIFT_MSG_CS\n", RDR_rdma(SHIFT_MSG_CS(0)));
	printk("0x%08x 0x130 - SHIFT_TDMSG\n", RDR_rdma(SHIFT_TDMSG(0)));
	printk("0x%08x 0x134 - SHIFT_RDMSG\n", RDR_rdma(SHIFT_RDMSG(0)));
	printk("0x%08x 0x138 - SHIFT_CAM\n", RDR_rdma(SHIFT_CAM(0)));
}

void test_reg_rdma(void)
{
	read_regs_rdma();
	WRR_rdma(SHIFT_TDMSG(0), 0xabcd);
	read_regs_rdma();
}

void free_chan(dma_chan_t *chd)
{
	signed int rest;
	DEBUG_MSG("free_chan: START\n");
	if (chd->allocs > RCS_ALLOCED_B) {
		if (chd->size_tm) {
			rdma_tbl_32_struct_t	*peltbl;
			for (peltbl = (rdma_tbl_32_struct_t *)chd->vdma_tm,
			     rest = chd->real_size; rest > 0; peltbl++) {
				rdma_mem_free(peltbl->sz,
				(dma_addr_t) peltbl->laddr,
				(unsigned long) __va(peltbl->laddr));
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

void rdma_mem_free(size_t size, dma_addr_t dev_memory, unsigned long dma_memory)
{
	int		order;
	caddr_t		mem;
	struct page	*map, *mapend;

	order = get_order(size);
	mem = (caddr_t)dma_memory;
	DEBUG_MSG("rdma_mem_free: START\n");
	if (!version_mem_alloc) {
		mapend = virt_to_page(mem + (PAGE_SIZE << order) - 1);
		for (map = virt_to_page(mem); map <= mapend; map++) {
			ClearPageReserved(map);
		}
		pci_unmap_single((struct pci_dev *)rdma_state->dev_rdma,
				  dev_memory, size, PCI_DMA_FROMDEVICE);
		free_pages(dma_memory, order);
	} else {
		dma_free_coherent(NULL, size, mem, dev_memory);
	}
	DEBUG_MSG("rdma_mem_free: FINISH va: 0x%lx, fa: 0x%x size: 0x%lx\n",
		dma_memory, dev_memory, size);
}

int rdma_mem_alloc(size_t size, dma_addr_t *mem, size_t *real_size,
		   unsigned long *dma_memory)
{
	int		order;
	struct page	*map, *mapend;

	DEBUG_MSG("rdma_mem_alloc: START\n");
	order = get_order(size);
	if (!version_mem_alloc) {
		*dma_memory = __get_free_pages(GFP_KERNEL | GFP_DMA, order);
		mapend = virt_to_page((*dma_memory) + (PAGE_SIZE << order) - 1);
		for (map = virt_to_page((*dma_memory)); map <= mapend; map++)
			SetPageReserved(map);
		*mem = pci_map_single((struct pci_dev *)rdma_state->dev_rdma,
				       (void *)*dma_memory, size,
					PCI_DMA_FROMDEVICE);
	} else {
		*dma_memory = (unsigned long)dma_alloc_coherent(
			       NULL, size, mem, GFP_KERNEL);
	}
	if (!(*dma_memory)) {
	      ERROR_MSG("rdma_mem_alloc: Cannot bind DMA address order: %d"
			       "size: 0x%lx\n", order, size);
	      return -1;
	}
  	*real_size = PAGE_SIZE << order;
	DEBUG_MSG("rdma_mem_alloc: FINISH va: 0x%lx fa: 0x%x size: 0x%lx"
			 "real_size: 0x%lx\n",
		*dma_memory, *mem, size, *real_size);
	return 0;
}

int init_chan(dma_chan_t *chd, int reqlen, int tm)
{
	char *err_msg = NULL;
	rdma_tbl_32_struct_t *peltbl;
	signed int rest;
	rdma_addr_struct_t pxx;
	int tmp_tm = 0; /* Disable for e3m */

	DEBUG_MSG("init_chan: START\n");
	if (chd->allocs) {
		ERROR_MSG("init_chan: chd->allocs already %d\n", chd->allocs);
		return -1;
	}
	if (reqlen > 0x800000){
		ERROR_MSG("init_chan: The large size of the buffer. "
				"The buffer must be <= 0x0800000 \n");
		goto failed;
	}

	chd->allocs = RCS_ALLOCED_B;
	DEBUG_MSG("init_chan: try alloc 0x%x\n", reqlen);
	if (tmp_tm) {
		DEBUG_MSG("init_chan: table mode PAGE_SIZE: %x\n", PAGE_SIZE);
		DEBUG_MSG("init_chan: try alloc for tm size: 0x%x\n",
			  SIZE_TBL64_RDMA);
		if (rdma_mem_alloc(SIZE_TBL32_RDMA,
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
		DEBUG_MSG("init_chan: reqlen: 0x%08x"
			   " rest: 0x%08x\n", reqlen, rest);
		chd->real_size = 0;
		for (peltbl = (rdma_tbl_32_struct_t *)chd->vdma_tm; rest > 0;
			peltbl++) {
			size_t size_el;
			unsigned long addr;	/* address */

			if (rdma_mem_alloc(PAGE_SIZE /*SIZE_EL_TBL64_RDMA*/,
				(dma_addr_t *)&peltbl->laddr, &size_el,
				(unsigned long *)&addr)) {
				err_msg = "rdma_mem_alloc for tm";
				goto failed;
			}
			pxx.addr = (unsigned long)peltbl;
			DEBUG_MSG("init_chan: 0x%08x%08x peltbl\n",
			pxx.fields.haddr, pxx.fields.laddr);
			pxx.addr = peltbl->laddr;
			DEBUG_MSG("init_chan: 0x%08x%08x peltbl->addr\n",
			pxx.fields.haddr, pxx.fields.laddr);
			rest -= size_el;
			peltbl->sz = (unsigned int)size_el;
			DEBUG_MSG("init_chan: peltbl->sz: 0x%08x "
					"rest: 0x%08x\n", peltbl->sz, rest);
			chd->real_size += size_el;
		}
		peltbl->sz = 0x0;
		chd->dma = (unsigned int)chd->fdma_tm;
		chd->tm = 1;
	} else {
		DEBUG_MSG("init_chan: single mode PAGE_SIZE: %x\n", PAGE_SIZE);
		if (rdma_mem_alloc((unsigned long)reqlen,
		    (dma_addr_t *)&chd->dma_busa, &chd->real_size,
		     (unsigned long *)&chd->prim_buf_addr)) {
			     err_msg = "rdma_mem_alloc";
			     goto failed;
		     }
		     chd->dma = chd->dma_busa;
		     pxx.addr = chd->dma;
		     DEBUG_MSG("init_chan: 0x%08x%08x chd->dma\n",
			       pxx.fields.haddr, pxx.fields.laddr);
		     chd->tm = 0;
	}
	chd->full = (uint_t)chd->dma;
	chd->allocs = RCS_ALLOCED;
	DEBUG_MSG("init_chan: FINISH chd->real_size: %lx\n", chd->real_size);
	return chd->real_size;

failed:
	chd->allocs = RCS_EMPTY;
	ERROR_MSG("init_chan: %s FAILED ****\n", err_msg);
	return (-1);

}

module_init(rdma_init);
module_exit(rdma_cleanup);

MODULE_LICENSE("GPL");


