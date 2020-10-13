/*
 * DDI for Linux. (SVS)
 * 
 * Supported by Alexey V. Sitnikov, alexmipt@mcst.ru, MCST
 *
 */

#include <linux/mcst/ddi.h>
#include <linux/slab.h>  
#include <asm/io.h> 	
#include <asm/current.h>
#include <linux/poll.h>	
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/security.h>
#if IS_ENABLED(CONFIG_PCI2SBUS)
#include <linux/mcst/p2ssbus.h>
#endif

extern struct dentry *lookup_hash(struct nameidata *nd);

EXPORT_SYMBOL(ddi_copyout);
EXPORT_SYMBOL(ddi_copyin);

EXPORT_SYMBOL(ddi_init_soft);
EXPORT_SYMBOL(drv_getparm);

EXPORT_SYMBOL(ddi_getl);
EXPORT_SYMBOL(ddi_putl);
EXPORT_SYMBOL(ddi_write_long);
EXPORT_SYMBOL(ddi_read_long);
EXPORT_SYMBOL(ddi_dma_mem_alloc);
EXPORT_SYMBOL(ddi_dma_mem_free);
EXPORT_SYMBOL(ddi_dma_mem_map);
EXPORT_SYMBOL(ddi_dma_mem_unmap);

EXPORT_SYMBOL(drv_usectohz);
EXPORT_SYMBOL(ddi_gethrtime);

EXPORT_SYMBOL(ddi_remap_page);
EXPORT_SYMBOL(ddi_dma_sync);

EXPORT_SYMBOL(ddi_cv_wait);
EXPORT_SYMBOL(ddi_cv_timedwait);
EXPORT_SYMBOL(ddi_cv_spin_wait);
EXPORT_SYMBOL(ddi_cv_spin_timedwait);
EXPORT_SYMBOL(ddi_cv_broadcast);

EXPORT_SYMBOL(ddi_poll_wait);
EXPORT_SYMBOL(poll_wait);

EXPORT_SYMBOL(ddi_fls);
EXPORT_SYMBOL(ddi_malloc);

#define __FFS			0

#define	DBGDDI_MODE 		0
#define DBGDDIDETAIL_MODE	0
#define	dbgddi			if (DBGDDI_MODE) 	printk
#define	dbgddidetail		if (DBGDDIDETAIL_MODE) 	printk

int			curr_drv_nr = 0;
dev_info_t		ddi_dev_info[MCST_MAX_DRV];

/*
 * All MCST driver's names (as "MCST,<drv_name>" and dirs as "drv_name")
 * It is mcst drv rooles (see ddi_create_minor())
 */

char *ddi_drivers[MCST_MAX_DRV];
char *ddi_drv_dir[MCST_MAX_DRV];

unsigned short ddi_vendors[MCST_MAX_DRV];
unsigned short ddi_devices[MCST_MAX_DRV];

int
ddi_max_drv_nr(void)
{
	int i = 0;
	
	for (;;) {
		if (ddi_drivers[i] == NULL) return i - 1;
		i++;
	}
	return 0;
}

int
ddi_max_drv_dir_nr(void)
{
	int i = 0;
	
	for (;;) {
		if (ddi_drv_dir[i] == NULL) return i - 1;
		i++;
	}
	return 0;
}

int
ddi_get_drv_nr(char *prom_name, int inst)
{
	int i = 0;
	int j = 0; // added	

	dbgddi("ddi_get_drv_nr: start\n");
	for (;;) {
		if (ddi_drivers[i] == NULL) return 0;
		if (strcmp(ddi_drivers[i], prom_name) == 0) {
		        if (j == inst) {	
				dbgddi("ddi_get_drv_nr: ret %d for %s\n", i, prom_name);
				return i;
			}
			j++;
		}
		i++;
	}
	dbgddi("ddi_get_drv_nr: ret 0 for %s\n", prom_name);
	return 0;
}

/* Find the first bit set in I.  */
#if __FFS
int
__ffs (int i)
{
  static const unsigned char table[] =
    {
      0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
      6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
      7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
      7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
      8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
      8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
      8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
      8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8
    };
  unsigned int a;
  unsigned int x = i & -i;

  a = x <= 0xffff ? (x <= 0xff ? 0 : 8) : (x <= 0xffffff ?  16 : 24);

  return table[x >> a] + a;
}
#endif /* __FFS */

int
ddi_fls(register long mask)
{
#if __FFS
	extern int ffs(long);
#endif /* __FFS */
	while (mask) {
		register long nx;

		if ((nx = (mask & (mask - 1))) == 0)
			break;
		mask = nx;
	}
	return (__ffs(mask));
}

void *
ddi_malloc(size_t sz)
{
	void *p;
	dbgddi("ddi_malloc: start\n");
	p = kmalloc(sz, GFP_KERNEL);
	if (p) {
		memset((char *)p, 0, sz);
	}
	return p;
}

int
ddi_init_soft(dev_info_t *dip, size_t size)
{
   	
	dbgddi("ddi_init_soft: start\n");
	if (dip == NULL) {
		printk("ddi_init_soft: dip == NULL\n");
		return -EFAULT;
	}
   	dip->soft_state = ddi_malloc(size);
   	if (dip->soft_state == NULL) {
		printk("ddi_init_soft: dip->soft_state == NULL\n");
   		return (-EFAULT);
   	}
   	dip->soft_state_sz = size;
	
	dbgddi("ddi_init_soft: before memset operation\n");
   	memset(dip->soft_state, 0, dip->soft_state_sz);
	dbgddi("ddi_init_soft: finish\n");
   	return 0;
}
int 
ddi_dma_mem_map(struct device *dev, size_t len, dma_addr_t *dev_memory, size_t *real_size,
			unsigned long dma_memory)
{
	size_t		size;
  	dma_addr_t	mem;
  	
	dbgddi("*** ddi_dma_mem_map: start ***\n");
  	size = *real_size; 	
  	mem = ddi_dev_map_mem(dev, size, dma_memory);
  	if (!mem) return -1;
  	*dev_memory = mem;
	dbgddi("*** ddi_dma_mem_map: finish ***\n");
  	return 0;
}

int
ddi_dma_sync(struct device *dev, dma_addr_t addr, size_t size, int direction)
{
	return(_ddi_dma_sync(dev, addr, size, direction));
}

/* *dev_memory - О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
/* *dma_memory - О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
int
ddi_dma_mem_alloc(struct device *dev, size_t len, dma_addr_t *dev_memory, size_t *real_size,
			unsigned long *dma_memory)
{
  	dma_addr_t	mem;
  	
	dbgddi("*** ddi_dma_mem_alloc: start, len = %ld ***\n", (u_long)len);
  	mem = ddi_dev_alloc_mem(dev, len, dma_memory);
  	if (!mem) return -1;
  	*dev_memory = mem;
	dbgddi("*** ddi_dma_mem_alloc: finish ***\n");
  	return 0;
}
/* dev_memory - О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
/* dma_memory - О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */

void
ddi_dma_mem_free(struct device *dev, size_t size, dma_addr_t dev_memory, unsigned long dma_memory)
{
	dbgddi("ddi_dma_mem_free: start\n");
      	ddi_dev_free_mem(dev, size, dma_memory, dev_memory);
	dbgddi("ddi_dma_mem_free: finish\n");
}

/* dev_memory - О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
/* dma_memory - О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */

void
ddi_dma_mem_unmap(struct device *dev, size_t size, dma_addr_t dev_memory, unsigned long dma_memory)
{
  	int 		order;
  	caddr_t		mem;
  	struct page 	*map, *mapend;
  	
	dbgddi("ddi_dma_mem_unmap: start\n");
	mem = (caddr_t)dma_memory;
	order = ddi_get_order(size);
    	mapend = virt_to_page(mem + (PAGE_SIZE << order) - 1);
    	for (map = virt_to_page(mem); map <= mapend; map++) {
      		ClearPageReserved(map);
      	}
      	ddi_dev_unmap_mem(dev, size, dma_memory, dev_memory);
	dbgddi("ddi_dma_mem_unmap: finish\n");
}

int
ddi_copyin(void *from, void *to, size_t size)
{
	size_t rval;

	dbgddi("*** ddi_copyin: start, size = %lx ***\n", (u_long)size);
	rval = copy_from_user(to, from, size);
	dbgddi("ddi_copyin: rval = copy_from_user = %lx\n", (u_long)rval);
	dbgddi("*** ddi_copyin: finish ***\n");
	return rval;
}
int
ddi_copyout(void *from, void *to, size_t size)
{
	size_t rval;
	rval = copy_to_user(to, from, size);
	return rval;
}

int
ddi_remap_page(void *va, size_t sz, struct vm_area_struct *vma)
{
   	unsigned long 	pha;
   	unsigned long 	vm_end;
   	unsigned long 	vm_start;
   	unsigned long 	vm_pgoff;
   	size_t  	size;
	
	dbgddi("**** ddi_remap_page: START ****\n");
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
   	
   	vma->vm_flags |= (VM_READ | VM_WRITE);

#if defined(CONFIG_E90) && !defined(STRICT_MM_TYPECHECKS)
	dbgddidetail("ddi_remap_page: vm_start = 0x%lx, pha = 0x%lx, \n"
		    "		     size = %x, vma->vm_page_prot = %lx\n", 
				(unsigned long)vm_start, (unsigned long)pha, 
				(int)size, vma->vm_page_prot);
#else
	dbgddidetail("ddi_remap_page: vm_start = 0x%lx, pha = 0x%lx, \n"
		    "		     size = %x, vma->vm_page_prot = %lx\n", 
				(unsigned long)vm_start, (unsigned long)pha, 
				(int)size, vma->vm_page_prot.pgprot);
#endif
#ifdef __e2k__
	if (vma->vm_flags & VM_IO)
		vma->vm_page_prot = __pgprot(pgprot_val(vma->vm_page_prot) | _PAGE_CD_DIS | _PAGE_PWT );
#endif

        if (remap_pfn_range(vma, vma->vm_start, (pha >> PAGE_SHIFT), size, vma->vm_page_prot)){
                printk("ddi_remap_page: remap_pfn_range failed\n");
                return -EAGAIN;
        }        

        dbgddi("**** ddi_remap_page: FINISH ****\n");
       	return 0;
}
int
drv_getparm(unsigned long parm, unsigned long *valuep)
{
	dbgddi("drv_getparm: start\n");
        switch (parm) {
        case LBOLT:
                *valuep = (unsigned long)jiffies;
                break;
        default:
                printk("drv_get_parm: Unknown parm %ld\n", parm);
                return (-1);
        }
	dbgddi("drv_getparm: finish\n");
        return 0;
 }
void ddi_settime(struct timespec *tick, long mksec)
{
	time_t bt,ht;
	
	dbgddi("ddi_settime: start\n");
	bt = mksec % 1000000;
	ht = mksec / 1000000;
	tick->tv_sec = ht;
	tick->tv_nsec = bt * 1000;
}
/* Convert mksec to HZ */
clock_t
drv_usectohz(register clock_t mksec)
{
        clock_t  	clock;
	struct timespec rqtp; 

	dbgddi("drv_usectohz: start, mksec = 0x%lx\n", mksec);
	rqtp.tv_nsec = ((mksec % 1000000L) * 1000L);
	rqtp.tv_sec  = mksec / 1000000L;
	dbgddi("drv_usectohz: rqtp.tv_nsec = 0x%lx, rqtp.tv_sec  = 0x%lx\n",
		rqtp.tv_nsec, rqtp.tv_sec);
	clock = timespec_to_jiffies(&rqtp);
	return (clock);
}

/* Returns nanoseconds */
hrtime_t
ddi_gethrtime(void)
{ 
	struct timeval tv;
	hrtime_t val;
	do_gettimeofday(&tv);
	val = tv.tv_sec * 1000000000LL + tv.tv_usec * 1000LL;
	return (val);
}

extern int _ddi_read_long(int dev_type, ulong_t *p);
int
ddi_getl(int t, ulong_t *p)
{
	return (_ddi_read_long(t,p));
}

extern void _ddi_write_long(int dev_type, ulong_t *p, ulong_t b);
void
ddi_putl(int t, ulong_t *p, ulong_t b)
{
	return (_ddi_write_long(t, p, b));
}
int
ddi_read_long(int t, ulong_t *p, ulong_t b)
{
	return (_ddi_read_long(t, p));
}
void
ddi_write_long(int t, ulong_t *p, ulong_t b)
{
	return (_ddi_write_long(t, p, b));
}

void
ddi_poll_wait(struct file * filp,
	      wait_queue_head_t *wait_address,
	      poll_table *p)
{
	poll_wait(filp, wait_address, p);
}

extern int  wake_up_state(struct task_struct *p, unsigned int state);
static void __raw_wake_up_common(raw_wait_queue_head_t *q)
{
	struct list_head *tmp, *next;
	raw_wait_queue_t *curr;

	list_for_each_safe(tmp, next, &q->task_list) {
		curr = list_entry(tmp, raw_wait_queue_t, task_list);
		wake_up_state(curr->task, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE);
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

EXPORT_SYMBOL(__raw_wake_up);

static inline void __raw_add_wait_queue(raw_wait_queue_head_t *head, raw_wait_queue_t *new)
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
EXPORT_SYMBOL(raw_add_wait_queue);

static inline void __raw_remove_wait_queue(raw_wait_queue_head_t *head, raw_wait_queue_t *old)
{
        list_del(&old->task_list);
}
void  raw_remove_wait_queue(raw_wait_queue_head_t *q, raw_wait_queue_t *wait)
{
        unsigned long flags;

        raw_spin_lock_irqsave(&q->lock, flags);
        __raw_remove_wait_queue(q, wait);
        raw_spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL(raw_remove_wait_queue);


static int __init pci_ddi_init(void)
{
	return 0;
}

static void __exit pci_ddi_exit(void)
{
}

MODULE_DESCRIPTION( "Device driver interface for PCI" );
MODULE_AUTHOR     ( "Alexey Sitnikov" );
MODULE_LICENSE    ( "GPL" );

module_init( pci_ddi_init );
module_exit( pci_ddi_exit ); 

