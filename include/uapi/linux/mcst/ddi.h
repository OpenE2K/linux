/*
 * 
 * Supported by Alexey V. Sitnikov, alexmipt@mcst.ru, MCST
 *
 */

#ifndef	__DDI_H__
#define	__DDI_H__

#ifdef __KERNEL__
#include <asm/poll.h>
#include <linux/poll.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/namei.h>
#include <linux/interrupt.h>
#endif

/*
 * Important: Don't change this to 256.  Major number 255 is and must be
 * reserved for future expansion into a larger dev_t space.
 */
#define MAX_CHRDEV	255
#define MAX_BLKDEV	255

#define MCST_MAX_DRV		MAX_CHRDEV + 1  

#ifdef __KERNEL__

typedef struct file_operations 	file_operations_t;

typedef struct bus_base {
  	long 		base_addr[DEVICE_COUNT_RESOURCE];	/* Virtual address */
  	size_t 		size[DEVICE_COUNT_RESOURCE];	/* Size of areas */
} bus_base_t;

typedef struct dev_info {
	int		instance;
	int		major;
//	int		dir_created;
	int		drv_nr;
	char		*prom_name;
	unsigned short vendor, device;		/* Vendor and device ID or PCI_ANY_ID */
	unsigned short subvendor, subdevice;	/* Subsystem ID's or PCI_ANY_ID */
	void		*soft_state;
	size_t		soft_state_sz;
	int		dev_type;
	void            *dev;			/* sdev, pcidev for example */
	void		*bus_base;
//	long		base_addr[DEVICE_COUNT_RESOURCE];	/* Virtual address */	
	unsigned long	base_addr[DEVICE_COUNT_RESOURCE];	/* Virtual address */
  	size_t	 	size[DEVICE_COUNT_RESOURCE];	/* Size of areas */
} dev_info_t;

/*
 * Types of devices
 */
 
#define SBUS_SPARC	1
#define PCI_SPARC	2
#define PCI_E2K		3


extern dev_info_t ddi_dev_info[];

typedef struct ddi_private {
	dev_t		dev;
	dev_info_t	*dip;
	int		count;
} ddi_private_t;

/***********************************************************/

/*
 *    Defines and typedefes for compatibility with solaris
 *    Alarm mutex_init & cv_timedwait & cv_init & cv_timedwait
 *    have different args
 *    and should be changed when use for Linux
 */

#define DBG_SPIN_MUTEX 0

#define DDI_SUCCESS     (0)
#define DDI_FAILURE     (-1)
#if 1
struct __raw_wait_queue {
	struct task_struct *task;
        struct list_head task_list;
};

#define DECLARE_RAW_WAIT_QUEUE(name)					\
	raw_wait_queue_t name = {.task = current}

typedef struct __raw_wait_queue raw_wait_queue_t;

struct __raw_wait_queue_head {
        raw_spinlock_t lock;
        struct list_head task_list;
};

typedef struct __raw_wait_queue_head raw_wait_queue_head_t;

struct raw_compat_semaphore {
        atomic_t count;
        int sleepers;
        raw_wait_queue_head_t wait;
#ifdef CONFIG_E2K
        unsigned int sem_type;
#endif
};

static inline void raw_init_waitqueue_head(raw_wait_queue_head_t *q)
{
	raw_spin_lock_init(&q->lock);
	INIT_LIST_HEAD(&q->task_list);
}

#define ddi_cv_init(cvp) raw_init_waitqueue_head(cvp);

static inline void raw_compat_sema_init (struct raw_compat_semaphore *sem, int val)
{
	atomic_set(&sem->count, val);
	sem->sleepers = 0;
	raw_init_waitqueue_head(&sem->wait);
}

static inline void raw_compat_init_MUTEX_LOCKED (struct raw_compat_semaphore *sem)
{
	raw_compat_sema_init(sem, 0);
}
typedef struct raw_compat_semaphore	semaphore_t;
//typedef struct compat_semaphore		kmutex_t;
typedef struct mutex   kmutex_t;

#define kcondvar_t 		raw_wait_queue_head_t
#endif

#define	getminor(d) 		MINOR(d)
#define clock_t 		long

/* Fast semaphores with task blocking and without disabling interrupts */

//#define mutex_init 		init_MUTEX
#define mutex_enter	 	mutex_lock
#define mutex_exit	 	mutex_unlock

/* Slow semaphores without task blocking and with disabling interrupts,
 * they are similar to mutexes in Solaris
 */
#define spin_mutex_init		raw_spin_lock_init

#if DBG_SPIN_MUTEX
#define spin_mutex_enter(lock)	do {printk("lock task = 0x%lx, at %s:%d\n", (unsigned long)current, __FILE__, __LINE__); \
					if (raw_spin_is_locked(lock)) printk("entering spin_mutex when locked\n"); \
					raw_spin_lock_irq(lock);} while (0)
#define spin_mutex_exit(lock)	do {printk("unlock task = 0x%lx, at %s:%d\n", (unsigned long)current, __FILE__, __LINE__); \
					raw_spin_unlock_irq(lock);} while (0)
#else
#define spin_mutex_enter	raw_spin_lock_irq
#define spin_mutex_exit		raw_spin_unlock_irq
#endif /* DBG_SPIN_MUTEX */

#define	PAGESIZE		PAGE_SIZE

//#define mutex_destroy(arg)

#define cv_init 		ddi_cv_init

/* Conditions with semaphore  */ 
#define cv_wait 		ddi_cv_wait

#define cv_timedwait 		ddi_cv_timedwait

/* Conditions with spinlock, analog Solaris  */ 
#define cv_spin_wait 		ddi_cv_spin_wait

#define cv_spin_timedwait 	ddi_cv_spin_timedwait

#define cv_broadcast 		ddi_cv_broadcast
#define cv_signal 		ddi_cv_broadcast

#define cond_destroy(cvp)	{}

/* #define min(a,b)		((a < b) ? a : b) */

typedef unsigned long   	ulong_t;
typedef unsigned int   		uint_t;
typedef unsigned char   	uchar_t;
typedef unsigned short   	ushort_t;
typedef long long 		hrtime_t;

extern int 		ddi_copyout(void *from, void *to, size_t size);
extern int 		ddi_copyin(void *from, void *to, size_t size);

extern int		ddi_init_soft(dev_info_t *dip, size_t size);
#define LBOLT   	4	
extern int 		drv_getparm(unsigned long parm, unsigned long *valuep);

extern int 		ddi_getl(int dev_type, ulong_t *p);
extern void 		ddi_putl(int dev_type, ulong_t *p, ulong_t b);
extern void		ddi_write_long(int dev_type, ulong_t *p, ulong_t b);
extern int		ddi_read_long(int dev_type, ulong_t *p, ulong_t b);
extern int		ddi_dma_mem_alloc(struct device *dev, size_t len,
				dma_addr_t *dev_memory, size_t *real_size, unsigned long *dma_memory);

extern void		ddi_dma_mem_free(struct device *dev, size_t size, 
				dma_addr_t dev_memory, unsigned long dma_memory);

extern int 		ddi_dma_mem_map(struct device *dev, size_t len, 
				dma_addr_t *dev_memory, size_t *real_size, unsigned long dma_memory);

extern void    		ddi_dma_mem_unmap(struct device *dev, size_t size, 
				dma_addr_t dev_memory, unsigned long dma_memory);

extern dma_addr_t	ddi_dev_alloc_mem(struct device *dev, size_t size, unsigned long *dma_memory);

extern void		ddi_dev_free_mem(struct device *dev, size_t size, 
				unsigned long dma_memory, dma_addr_t dev_memory);

extern dma_addr_t	ddi_dev_map_mem(struct device *dev, size_t size, unsigned long dma_memory);

extern void		ddi_dev_unmap_mem(struct device *dev, size_t size,
				unsigned long dma_memory, dma_addr_t dev_memory);

extern int 		ddi_max_drv_nr(void);
extern int 		ddi_max_drv_nr(void);
extern int 		ddi_get_drv_nr(char *prom_name, int instance);
extern int      	ddi_fls(register long mask);

extern clock_t		drv_usectohz(register clock_t mksec);
extern hrtime_t 	ddi_gethrtime(void);

extern int		ddi_remap_page(void *va, size_t sz, struct vm_area_struct *vma);
extern int		ddi_dma_sync(struct device *dev, dma_addr_t addr, size_t size, int direction);
extern int    		_ddi_dma_sync(struct device *dev, dma_addr_t addr, size_t size, int direction);

extern int		ddi_cv_wait(kcondvar_t *cvp, kmutex_t *semp);
extern int		ddi_cv_timedwait(kcondvar_t *cvp, kmutex_t *semp, long tim);
extern int		ddi_cv_spin_wait(kcondvar_t *cvp, raw_spinlock_t *lock);
extern int		ddi_cv_spin_timedwait(kcondvar_t *cvp, raw_spinlock_t *lock, long tim);
extern int		ddi_cv_broadcast(kcondvar_t *cvp);


extern void 		*ddi_malloc(size_t sz);
extern int 		ddi_get_order(size_t sz);

extern void 		ddi_poll_wait(struct file * filp, wait_queue_head_t * wait_address, poll_table *p);

extern void             raw_add_wait_queue(raw_wait_queue_head_t *q, raw_wait_queue_t * wait);
extern void             raw_remove_wait_queue(raw_wait_queue_head_t *q, raw_wait_queue_t * wait);
extern void             __raw_wake_up(raw_wait_queue_head_t *q);
#define raw_wake_up(x)                      __raw_wake_up(x)

#define			ddi_get_instance(dip) dip->instance

#endif /* __KERNEL__ */

#define DDI_SET_ALL_MAJOR	1
#define DDI_GET_MAJOR		2

#define DDI_SBUS_SPARC 	1
#define DDI_PCI_SPARC  	2
#define DDI_PCI_E2K    	3

#define DDI_MAX_DRV_NM_SZ	64

#endif /* __DDI_H__ */
