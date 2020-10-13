#include <asm/e2k.h>
#include <asm/io.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/uaccess.h>

#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ioctl.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/device.h>

#ifdef CONFIG_ELDSP_MODULE

#include <linux/audit.h>
#include <linux/err.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/security.h>

#endif


#define __DMA_ON__
#define __DMA_INTERRUPTS_ON__
#define __CATCH_INTERRUPT_ON__
#define __ALL_ONLINE_NODE__
#define __USE_PROC__
#define __DSP_RUN_HACK_FOR_MEMORY__
#define __CHAIN_MODE_ON__off /* temporary off */

#ifndef __DMA_ON__
#warning DMA are - OFF ! ! !
#endif

#ifndef __DMA_INTERRUPTS_ON__
#warning DMA interrupts are - OFF ! ! !
#endif

#ifndef __CATCH_INTERRUPT_ON__
#warning catch interrupt are - OFF ! ! !
#endif

#ifndef __ALL_ONLINE_NODE__
#warning All nodes (expect zero) are - OFF ! ! !
#endif

#ifndef __USE_PROC__
#warning Use proc fs are - OFF ! ! !
#endif


/* /proc/sys/debug/eldsp_debug trigger */
int dsp_debug = 0;

#include "eldsp.h"

#define MCST_INCLUDE_IOCTL
#ifdef MCST_INCLUDE_IOCTL
#include <linux/mcst/mcst_selftest.h>
#endif

#define DSP_VERSION "0.10.1.3"

/* for /dev, /sys/class, /proc nodes and files */
#define DSP_NAME "eldsp"

static const char	dsp_dev_name[] = "MCST,eldsp";
static int	dsp_numbers_devs = 0;
int		node_numbers;
int		dsp_minors[MAX_DSP * MAX_NODE] = {0}; /* all devices */
int		on_nodes[MAX_NODE] = {0}; /* all nodes */
dsp_dev_t	*dsp_devices[MAX_DSP * MAX_NODE]; /* all devices */
dsp_node_t	dsp_node[MAX_NODE]; /* dma_channels + dsp_devices */
int		major = ELDSP_MAJOR;
static struct class *dsp_class;

SPINLOCK_T	interrupt_lock;
SPINLOCK_T	global_lock;
SPINLOCK_T	dma_lock;


void dsp_dma_processing(dsp_dev_t *dev);
void dsp_interrupt_processing(dsp_dev_t *dev);
#ifdef __CHAIN_MODE_ON__
void delete_dma_chain(dsp_dev_t *dev);
int add_link_to_dma_chain(dsp_dev_t *dev, int pages);
#endif /*__CHAIN_MODE_ON__*/

/********************/

#include <linux/time.h>
typedef long hrtime_t;

hrtime_t gethrtime(void) {
	struct timeval tv;
	hrtime_t retval;

	do_gettimeofday(&tv);

	retval = (hrtime_t)((hrtime_t)tv.tv_sec * 1000000000l)
		+ (hrtime_t)((hrtime_t)tv.tv_usec * 1000);

	return retval;
}
/******************/

#if defined(CONFIG_SYSCTL)
#include <linux/sysctl.h>

static ctl_table dsp_table[] = {
	{
		.procname	= "eldsp_debug",
		.data		= &dsp_debug,
		.maxlen		= sizeof(dsp_debug),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static ctl_table dsp_root_table[] = {
	{
		.procname	= "debug",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= dsp_table,
	},
	{ }
};

static struct ctl_table_header *dsp_sysctl_header = NULL;

static void __init dsp_sysctl_register(void)
{
	dsp_sysctl_header = register_sysctl_table(dsp_root_table);
}

static void dsp_sysctl_unregister(void)
{
	unregister_sysctl_table(dsp_sysctl_header);
}

#else /* CONFIG_SYSCTL */

static void __init dsp_sysctl_register(void)
{
}

static void dsp_sysctl_unregister(void)
{
}
#endif

#ifdef __USE_PROC__
#ifdef CONFIG_PROC_FS

extern struct proc_dir_entry *ldsp_entry;
extern const struct file_operations *ldsp_proc_fops_pointer;
static struct proc_dir_entry *dsp_proc_entry;

static int eldsp_seq_show(struct seq_file *s, void *v)
{
	int i = *((int *)v);
	int k;
	if (dsp_node[i].present) {
		seq_printf(s, "  node: %d\n", i);
		for (k = 0; k < MAX_DSP; k++) {
			unsigned long	offset_b;
			seq_printf(s, "    number: %d, minor: %d, state: on\n",
				   dsp_node[i].dsp[k]->number,
				   dsp_node[i].dsp[k]->minor);
			seq_printf(s, "\tmknod /dev/%s%d c %d %d\n",
				   DSP_NAME,
				   dsp_node[i].dsp[k]->id,
				   major,
				   dsp_node[i].dsp[k]->minor);
			seq_printf(s, "\topened: %s\n",
				   dsp_node[i].dsp[k]->opened ?
				   "yes" :
				   "no");
			offset_b = (unsigned long)(nNODE_PHYS_ADR(i) +
						   (0x400000 * k));
#if DEBUG_MODE
			seq_printf(s,
				   "\t  xyram  0x%lx <- 0x%lx"
				   "\n\t   pram  0x%lx <- 0x%lx"
				   "\n\t   regs  0x%lx <- 0x%lx\n",
				   BASE[i].xyram[k], offset_b,
				   BASE[i].pram[k],  offset_b + 0x40000,
				   BASE[i].regs[k],  offset_b + 0x80000
			);
#endif
		}
	} else {
		/* node online, but DSP are off */
		if (dsp_node[i].online)
			seq_printf(s, "    state: off\n");
	}

	return 0;
}

static void *eldsp_seq_start(struct seq_file *s, loff_t *pos)
{
	seq_printf(s, "- ELDSP device info - number: %d, online: %d.\n",
		   num_online_nodes() * 4,
		   dsp_numbers_devs);
	seq_printf(s, "  Module loaded: version - %s.\n", DSP_VERSION);
	seq_printf(s, "  Major number: %d\n", major);
	seq_printf(s, "  Status for each DSP on each node:\n");

	if (dsp_debug)
		seq_printf(s, "  Debug print mode: ON.\n");

#if ERROR_MODE == 0
	seq_printf(s, "  Module was compiled without ERROR print !\n");
#endif
#if DEBUG_MODE
	seq_printf(s, "  Module was compiled with DEBUG print.\n");
#endif
#if DEBUG_DETAIL_MODE
	seq_printf(s, "  Module was compiled with DETAIL DEBUG print.\n");
#endif
#ifndef __ALL_ONLINE_NODE__
	seq_printf(s, "All nodes (except zero-node) "
		   "are off manually in driver.\n");
#endif

	if (*pos == MAX_NODE) {
		return 0;
	}

	return (void *)pos;
}

static void *eldsp_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	/* not sure that increase correct ! */
	*pos = (int)*pos + 1;
	if (*pos == MAX_NODE)
		return 0;

	return (void *)pos;
}

static void eldsp_seq_stop(struct seq_file *s, void *v)
{
}

static const struct seq_operations eldsp_seq_ops = {
	.start = eldsp_seq_start,
	.next  = eldsp_seq_next,
	.stop  = eldsp_seq_stop,
	.show  = eldsp_seq_show
};

static int eldsp_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &eldsp_seq_ops);
}

static const struct file_operations *save_eldsp_proc_ops = NULL;
static const struct file_operations eldsp_proc_ops = {
	.owner   = THIS_MODULE,
	.open    = eldsp_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};

#endif /* CONFIG_PROC_FS */

#endif /* __USE_PROC__ */

#ifndef VM_RESERVED
# define  VM_RESERVED   (VM_DONTEXPAND | VM_DONTDUMP)
#endif

static int dsp_mmap(struct file *filp, struct vm_area_struct *vma)
{

	dsp_dev_t       *dev;
	unsigned long    mem_start;
	unsigned long    off;

	dev = (dsp_dev_t *)filp->private_data;

	/* WARNING: not check memory area size and limit !!! */

	off = vma->vm_pgoff << PAGE_SHIFT;

	vma->vm_flags |= (VM_READ | VM_WRITE | VM_RESERVED);
	if (off >= ADD_DMA_CHAIN) {
		off = ADD_DMA_CHAIN;
	} else if (off == DSP_DMA_MMAP) {
		;
	} else {
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	}

	switch (off) {
		/* remap DMA buffer to user */
	case DSP_DMA_MMAP:
	{
		vma->vm_pgoff = 0;
		vma->vm_flags |= VM_IO | VM_RESERVED;

		DETAIL_PRINT("mmap[%d:%d:%d]:\tDSP_DMA_MMAP: vm_off 0x%lx, "
			     "off 0x%lx 0x%lx, size 0x%x, dev %d\n",
			     dev->node, dev->number, dev->minor,
			     vma->vm_pgoff << PAGE_SHIFT,
			     dev->dma.phys_mem >> PAGE_SHIFT,
			     dev->dma.page_adr >> PAGE_SHIFT,
			     DMA_EXCHANGE_SIZE,
			     dev->number);

		/*
		  if ((vma->vm_end - vma->vm_start) > DMA_EXCHANGE_SIZE)
		  {
		  ERROR_PRINT("mmap:\terror mmap DMA memory to user, "
			      "size is too long\n");
		  ERROR_PRINT("mmap:\t size can't be more than: %d. "
			      "Current size: %ld\n",
		  DMA_EXCHANGE_SIZE, (vma->vm_end - vma->vm_start));
		  return -EFAULT;
		  }
		*/

		if (remap_pfn_range(vma,
				     vma->vm_start,
				     dev->dma.phys_mem >> PAGE_SHIFT,
				     DMA_EXCHANGE_SIZE,
				     vma->vm_page_prot) < 0)
		{
			ERROR_PRINT("mmap:\terror mmap DMA memory to user\n");
			return -EAGAIN;
		}
	}
	break;

	/* mmap DSP local registers area */
	case REG_LOCAL_MMAP:
	{
		vma->vm_pgoff = 0;

		mem_start =  PHYS_NODE(REGS_OFFSET + 0x0);

		DETAIL_PRINT("mmap[%d:%d:%d]:\tREG_LOCAL_MMAP: "
			     "vm_off 0x%lx, off 0x%lx, size 0x%x, dev %d\n",
			     dev->node, dev->number, dev->minor,
			     vma->vm_pgoff << PAGE_SHIFT,
			     mem_start,
			     REG_LOCAL_SIZE,
			     dev->number);

		if (io_remap_pfn_range(vma,
					vma->vm_start, /* virtual for user */
					mem_start >> PAGE_SHIFT,
					REG_LOCAL_SIZE,
					vma->vm_page_prot) < 0)
		{
			ERROR_PRINT("mmap:\tmmap local registers to user\n");
			return -EAGAIN;
		}
	}
	break;

	/* mmap DSP global registers area */
	case REG_GLOBAL_MMAP:
	{
		vma->vm_pgoff = 0;

		mem_start =  nPHYS_NODE(dev->node, 0, REGS_OFFSET + 0x1000);

		DETAIL_PRINT("mmap[%d:%d:%d]:\tREG_GLOBAL_MMAP: "
			     "vm_off 0x%lx, off 0x%lx, size 0x%x, dev %d\n",
			     dev->node, dev->number, dev->minor,
			     vma->vm_pgoff << PAGE_SHIFT,
			     mem_start,
			     REG_GLOBAL_SIZE,
			     dev->number);

		if (io_remap_pfn_range(vma,
					vma->vm_start, /*virtual for user*/
					mem_start >> PAGE_SHIFT,
					REG_GLOBAL_SIZE,
					vma->vm_page_prot) < 0)
		{
			ERROR_PRINT("mmap:\tmmap global registers to user\n");
			return -EAGAIN;
		}
	}
	break;

	/* allocate memory for DMA and mmap this memory to user */
	case ADD_DMA_CHAIN:
	{
#ifdef __CHAIN_MODE_ON__
		int res = 0;
		int found = 0;
		vma->vm_pgoff = 0;
		vma->vm_flags |= VM_IO | VM_RESERVED;

		res = add_link_to_dma_chain(dev, dev->link_size);
		if (res > 0) {
			struct chain_list *tmp;
			list_for_each_entry(tmp, &dev->dma_chain, list) {
				if (tmp->link.lnumber == res) {
					DETAIL_PRINT("found chain: %d\n",
						     tmp->link.lnumber);
					found = 1;
					break;
				}
			}

			if (found) {
				DETAIL_PRINT("mmap[%d:%d:%d]:\t"
					     "ADD_DMA_CHAIN: vm_off 0x%lx, "
					     "[vm_start: 0x%lx]"
					     "off 0x%lx 0x%lx, sz %d, dev %d\n",
					     dev->node, dev->number, dev->minor,
					     vma->vm_start,
					     vma->vm_pgoff << PAGE_SHIFT,
					     tmp->link.phys_mem >> PAGE_SHIFT,
					     tmp->link.page_adr >> PAGE_SHIFT,
					     tmp->link.size,
					     dev->number);

				if (remap_pfn_range(vma,
						    vma->vm_start,
						    tmp->link.phys_mem >> PAGE_SHIFT,
						    tmp->link.size,
						    vma->vm_page_prot) < 0)
				{
					ERROR_PRINT("mmap:\terror mmap DMA memory to user\n");
					return -EAGAIN;
				}
			}
		} else {
			DBG_PRINT("add link FAILED !\n");
			return -ENOMEM;
		}
#else
		WARNING_PRINT("Chain mode are - OFF !\n");
		return -ENOMEM;
#endif
	}
	break;

	/* mmap DSP code and data area */
	default:
	{
		mem_start =  PHYS_NODE(off);

		DETAIL_PRINT("mmap[%d:%d:%d]:\tRAM: "
			     "vm_off 0x%lx, off 0x%lx, size 0x%lx, dev %d\n",
			     dev->node, dev->number, dev->minor,
			     vma->vm_pgoff << PAGE_SHIFT,
			     mem_start,
			     (vma->vm_end - vma->vm_start),
			     dev->number);

		if (io_remap_pfn_range(vma,
				       vma->vm_start, /*virtual for user*/
				       mem_start >> PAGE_SHIFT,
				       vma->vm_end - vma->vm_start,
				       vma->vm_page_prot) < 0)
		{
			ERROR_PRINT("mmap:\terror mmap memory to user\n");
			return -EAGAIN;
		}
	}
	break;
	}

	return 0;
}


static unsigned int dsp_poll(struct file *filp, struct poll_table_struct *wait)
{
	dsp_dev_t       *dev;
	/* poll disable - wake_up() not work on random stack */
	/* unsigned int     mask = 0; */

	dev = (dsp_dev_t *)filp->private_data;
	WARNING_PRINT("poll[%d]: Poll not implemented.\n", dev->minor);
	return -EINVAL;

	/* poll disable - wake_up() not work on random stack */
	/*
	DETAIL_PRINT("poll:\tdsp number: %d:%d:%d\n",
		     dev->node, dev->number, dev->minor);

	poll_wait(filp, &dev->wait_queue, wait);

	if (dev->mem_error)
		mask |= POLLERR;
	else if (dev->run == 0)
		mask |= POLLIN;

	return mask;
	*/
}


static int dsp_open(struct inode *inode, struct file *filp)
{
	dsp_dev_t *dev;
#ifdef __THIS_SECTION_ARE_OFF__
	unsigned long flags;
	unsigned int dspmask = 0, cpumask = 0, dmamask = 0;
	unsigned int dspmasko = 0, cpumasko = 0;//dbg
#endif
	int minor = MINOR(inode->i_rdev), i, not_found = 1;

	for (i = 0; i < dsp_numbers_devs; i++) {
		if (minor == dsp_minors[i]) {
			not_found = 0;
			break;
		}
	}

	if (not_found)	{
		ERROR_PRINT("open:\tdevice with minor number: "
			    "%d - not exist.\n", minor);
		return -ENODEV;
	}

	dev = (dsp_dev_t *)filp->private_data;
	if (!dev) {
		dev = dsp_devices[minor];
		if (dev->opened) {
			WARNING_PRINT("open:\tre-open device: %d:%d:%d\n",
				      dev->node, dev->number, dev->minor);
			return -EBUSY;
		} else {
			dev->opened = 1;
		}
		dev->reason = 0;
		dev->dcsr_i = 0;
		dev->sp_i   = 0;


#ifdef __THIS_SECTION_ARE_OFF__
#ifdef __CATCH_INTERRUPT_ON__
		DETAIL_PRINT("open:\ton interupts\n");
		SLOCK_IRQSAVE(&global_lock, flags);
		dspmasko = dspmask = (GET_CLUSTER_REG(MASKR_DSP));
		dspmask |= (0x3f << (8 * dev->number));
		dspmask |= 0x40; /* INT_MEM_ERR - on */
		SET_CLUSTER_REG(MASKR_DSP, dspmask);

		/* on interrupts only at cpu0  */
		cpumasko = cpumask = GET_APIC_REG(IC_MR0);
#  ifdef __DMA_INTERRUPTS_ON__
		dmamask = 0xff;
#  else
		dmamask = 0x0;
#  endif /*__DMA_INTERRUPTS_ON__*/
		cpumask |= dmamask;
		cpumask |= mask_intr[dev->number];
		SET_APIC_REG(IC_MR0, cpumask);
		SUNLOCK_IRQREST(&global_lock, flags);
		DETAIL_PRINT("old intr mask: dsp: 0x%08x cpu: 0x%04x"
			     "\tnew:dsp: 0x%08x cpu: 0x%04x\n",
			    dspmasko, cpumasko, dspmask, cpumask);
#endif /*__CATCH_INTERRUPT_ON__*/
#endif /*__THIS_SECTION_ARE_OFF__*/
		filp->private_data = dev;
	}

	DBG_PRINT("open: done\n");

	return 0;
}


static int dsp_release(struct inode *inode, struct file *filp)
{
	dsp_dev_t *dev;
	int minor = MINOR(inode->i_rdev);
	unsigned int i, not_found = 1;
#ifdef __THIS_SECTION_ARE_OFF__
	unsigned long flags;
	unsigned int dspmask = 0, cpumask = 0
	unsigned int dspmasko = 0, cpumasko = 0;//dbg
#endif /*__THIS_SECTION_ARE_OFF__*/

	for (i = 0; i < dsp_numbers_devs; i++) {
		if (minor == dsp_minors[i]) {
			not_found = 0;
			break;
		}
	}

	if (not_found)	{
		ERROR_PRINT("open:\tminor numbers more than exists\n");
		return -ENODEV;
	}

	dev = (dsp_dev_t *)filp->private_data;

#ifdef __THIS_SECTION_ARE_OFF__
#ifdef __CATCH_INTERRUPT_ON__
	DETAIL_PRINT("open:\toff interupts\n");
	SLOCK_IRQSAVE(&global_lock, flags);
	dspmasko = dspmask = (GET_CLUSTER_REG(MASKR_DSP));
	dspmask &= ~(0x3f << (8 * dev->number));
	if ((dspmask & 0xffffffbf) == 0)
		dspmask = 0x0; /* all and INT_MEM_ERR - off */
	SET_CLUSTER_REG(MASKR_DSP, dspmask);

	/* off interrupts on both cpu */
	cpumasko = cpumask = GET_APIC_REG(IC_MR0);
	cpumask &= ~(mask_intr[dev->number]);
	if ((cpumask & 0xff00) == 0) /* nothing */
		cpumask = 0; /* off all, include dma */
	SET_APIC_REG(IC_MR0, cpumask);
	SUNLOCK_IRQREST(&global_lock, flags);
	DETAIL_PRINT("old intr mask: dsp: 0x%08x cpu: 0x%04x"
		     "\tnew:dsp: 0x%08x cpu: 0x%04x\n",
		    dspmasko, cpumasko, dspmask, cpumask);
#endif /*__CATCH_INTERRUPT_ON__*/
#endif /*__THIS_SECTION_ARE_OFF__*/
	dev->opened = 0;
	DBG_PRINT("closed\n");

	return 0;
}


static ssize_t dsp_write(struct file *f, const char *b, size_t c, loff_t *f_pos)
{
	dsp_dev_t *dev;
	dev = (dsp_dev_t *)f->private_data;
	WARNING_PRINT("write[%d]: Write not implemented.\n", dev->minor);
	return -EINVAL;
}


static ssize_t dsp_read(struct file *filp, char *b, size_t c, loff_t *f_pos)
{
	dsp_dev_t *dev;
	dev = (dsp_dev_t *)filp->private_data;
	WARNING_PRINT("read[%d]: Read not implemented.\n", dev->minor);
	return -EINVAL;
}


int dsp_run(dsp_dev_t *dev, unsigned int adr)
{

	dev->run = 1;
	dev->reason = 0;
	dev->state = 0;
	dev->mem_error = 0;

	SET_DSP_REG(PC, adr);/* set start adress */
	SETBIT(DCSR, 14);    /* start */

	return 0;
}


int dsp_stop(dsp_dev_t *dev)
{

	dev->run = 0;
	dev->reason = (GET_DSP_REG(DCSR) & 0x1f); /* reason or nothing ??? */
	dev->state = GET_DSP_REG(SR) & 0xff;

	CLRBIT(DCSR, 14); /* stop */

	return 0;
}


int dsp_reset(dsp_dev_t *dev)
{
	dsp_stop(dev);

	dev->state  = 0;
	dev->reason = 0;
	dev->dcsr_i = 0;
	dev->sp_i   = 0;

	/* It is unclear what registers need to clean. */
	SET_DSP_REG(SR, 0x0);
	SET_DSP_REG(DCSR, 0x0);
	SET_DSP_REG(CNTR, 0x0);

	return 0;
}


/*
 * clear local XYRAM and PRAM
 * memory area for current DSP
 */
void dsp_clear_memory(dsp_dev_t *dev)
{
	memset(XYRAM, 0, XYRAM_SIZE);
	memset(PRAM, 0, PRAM_SIZE);
}


/**
 * internal function for alloc dma memory
 * old-style
 * \param s - size
 */
int alloc_dma(unsigned long *page, dma_addr_t **virt, dma_addr_t *phys, int s)
{
	int order = 0;
	struct page *map, *mapend;

	order = get_order(s);
	(*page) = __get_free_pages(GFP_KERNEL | GFP_DMA, order);
	if ((*page) == 0) {
		return -ENOMEM;
	}

	mapend = virt_to_page((*page) + (PAGE_SIZE << order) - 1);
	for (map = virt_to_page((*page)); map <= mapend; map++)
		SetPageReserved(map);

	(*virt) = (dma_addr_t *)(*page);
	memset((*virt), 0, s);
	(*phys) = virt_to_phys((char *)((*virt)));

	return PAGE_SIZE << order;
}


/* free DMA buffers */
void free_dma(unsigned long padr, int size)
{
	struct page *map, *mapend;
	int order = get_order(size);
	mapend = virt_to_page(padr + (PAGE_SIZE << order) - 1);
	for (map = virt_to_page(padr); map <= mapend; map++) {
		ClearPageReserved(map);
	}
	free_pages(padr, order);
}


#ifdef __DMA_ON__
int lock_channel(int node, int dsp_number, int channel)
{
	unsigned long flags;

	DETAIL_PRINT("lock channel: %d %d %d\n", node, dsp_number, channel);

	SLOCK_IRQSAVE(&dma_lock, flags);

	if (dsp_node[node].dma_channel_lock[channel] != -1) {
		SUNLOCK_IRQREST(&dma_lock, flags);
		return -1;
	}

	dsp_node[node].dma_channel_lock[channel] = dsp_number;

	SUNLOCK_IRQREST(&dma_lock, flags);

	DETAIL_PRINT("lock channel done\n");

	return 0;
}


int unlock_channel(int node, int dsp_number, int channel)
{
	unsigned long flags;

	DETAIL_PRINT("unlock channel: %d %d %d\n", node, dsp_number, channel);

	SLOCK_IRQSAVE(&dma_lock, flags);

	if (dsp_node[node].dma_channel_lock[channel] != dsp_number) {
		SUNLOCK_IRQREST(&dma_lock, flags);
		ERROR_PRINT("DMA: ELDSP[%d:%d] unlock wrong channel: "
			    "lock from DSP[%d]\n",
			    node, dsp_number,
			    dsp_node[node].dma_channel_lock[channel]);
		return -1;
	}

	dsp_node[node].dma_channel_lock[channel] = -1;

	SUNLOCK_IRQREST(&dma_lock, flags);

	DETAIL_PRINT("unlock channel done\n");

	return 0;
}


int check_channel(int node, int channel)
{
	unsigned long flags;
	int dsp_number;

	DETAIL_PRINT("check channel\n");

	SLOCK_IRQSAVE(&dma_lock, flags);
	dsp_number = dsp_node[node].dma_channel_lock[channel];
	SUNLOCK_IRQREST(&dma_lock, flags);

	DETAIL_PRINT("check channel done: %d %d %d\n",
		     node, dsp_number, channel);

	return dsp_number;
}


/* dma exchange - write and read */
int dma_exchange(dsp_dev_t *dev, dsp_dma_setup_t *set, int dir)
{
	union csr_register csr, reg_csr, old_csr;
	union ior_register ior0, ior1;
	int while_count = 0;
	hrtime_t all_s, all_e, s, e;
	unsigned long flags;

	DETAIL_PRINT("dma:\tDSP_EXCHANGE_DATA: "
		     "0x%x 0x%x 0x%x 0x%x (%d) mem: 0x%lx 0x%lx 0x%lx\n",
		     set->words,
		     (unsigned int)set->size,
		     set->run,
		     set->channel,
		     set->mode,
		     dev->dma.phys_mem + sizeof(dsp_dma_setup_t),
		     set->offset_mem0,
		     set->offset_mem1);

	if (lock_channel(dev->node, dev->number, set->channel)) {
		ERROR_PRINT("dma: DMA lock channel error, "
			    "channel %d already busy\n",
			    set->channel);
		return -EFAULT;
	}

	all_s = gethrtime();

	/* set up DMA transaction */
	csr.r = reg_csr.r = old_csr.r = 0L;
	ior0.r = ior1.r = 0L;
	csr.b.wn   = set->words;
	csr.b.wcx  = set->size; /* word = 64 bit */

	/*  direction and offset memory:
	 *  0: CPU -> DSP (TO_DSP)
	 *  1: CPU <- DSP (FROM_DSP)
	 *  2: DSP -> DSP (DSP_DSP)
	 *
	 *  ir0 - always using for CPU memory phys area (except DSP->DSP)
	 *  ir1 - always using for DSP memory phys area
	 */
	if (dir < DSP_DSP) {
		ior0.b.ir = dev->dma.phys_mem;
		csr.b.dir  = dir;
		ior0.b.sel = 1;      /* where memory addres 0 - DSP, 1 - CPU */
	} else {
		ior0.b.ir = set->offset_mem0;
	}

	ior0.b.or = 1;	/* ir = ir + (or * 8) */
	ior1.b.ir = set->offset_mem1; /* set DSP_trg adress */
	//ior1.b.sel = 0;	/* where memory addres 0 - DSP, 1 - CPU */
	ior1.b.or = 1;	/* ir = ir + (or * 8) */

	DBG_PRINT("dma:\tDSP_EXCHANGE_DATA: 0x%lx 0x%lx 0x%lx\n",
		  csr.r,
		  (unsigned long)ior0.r,
		  (unsigned long)ior1.r);

	s = gethrtime();
	SLOCK_IRQSAVE(&dev->spinlock, flags);

	dev->dma.run = 1;
	dev->dma.channel = set->channel;

	SET_DMA_REG(IOR0, set->channel, ior0.r);
	SET_DMA_REG(IOR1, set->channel, ior1.r);
	SET_DMA_REG(CSR, set->channel,  csr.r);
	SET_DMA_REG(DMA_RUN, set->channel, 1);

#ifdef __DMA_INTERRUPTS_ON__
	/* waiting ending DMA work */
	while (dev->dma.done == 0) {
		while_count++;

		raw_wqueue_t wait_el = {.task = current};
		current->state = TASK_INTERRUPTIBLE;
		list_add(&wait_el.task_list, &dev->dma.wait_task_list);
		SUNLOCK_IRQREST(&dev->spinlock, flags);
		schedule();
		SLOCK_IRQSAVE(&dev->spinlock, flags);
		list_del(&wait_el.task_list);
		current->state = TASK_RUNNING;
		if (signal_pending(current)) {
			SUNLOCK_IRQREST(&dev->spinlock, flags);
			unlock_channel(dev->node, dev->number, set->channel);
			return -ERESTARTSYS;
		}
	}
#else
	SUNLOCK_IRQREST(&dev->spinlock, flags);
	/* for debug without interrupts */
	while (!reg_csr.b.done) {
		old_csr.r = reg_csr.r;
		reg_csr.r = GET_DMA_REG(CSR, set->channel);
		while_count++;
		if (while_count > 9999999)
			break;
	}
	SLOCK_IRQSAVE(&dev->spinlock, flags);
#endif

	dev->dma.done = 0;
	dev->dma.run = 0;
	dev->dma.channel = -1;

	SUNLOCK_IRQREST(&dev->spinlock, flags);
	e = gethrtime();

	unlock_channel(dev->node, dev->number, set->channel);

	all_e = gethrtime();

	DETAIL_PRINT("exchange: event count %d\n", while_count);
	DETAIL_PRINT("dma:\tDSP DMA done: "
		     "time: DMA - %lu, DMA plus system - %lu\n",
		     e - s,
		     all_e - all_s);

	return 0;
}


#ifdef __CHAIN_MODE_ON__
///\todo: needed add check for chain exist!!!
void setup_target_link(dsp_dev_t *dev, setup_link_t *link)
{
	chain_link_t regs;
	unsigned long long phys = 0;
	unsigned long phys_base = ((unsigned long)(dev->link_regs.phys_mem));
	unsigned long *ptr = 0;
	unsigned long *ptr_base = ((unsigned long *)(dev->link_regs.virt_mem));
	struct chain_list *tmp;

	DBG_PRINT("chain: setup target link: %d\n", link->link);
	DETAIL_PRINT("(%d %d) intr: %d mode: %s 0x%lx 0x%lx size: %d\n",
		     link->dma_pause, link->dsp_run,
		     link->intr, link->mode ? "DSP->CPU" : "CPU->DSP",
		     link->offset_mem0, link->offset_mem1,
		     link->size);

	phys = phys_base + (sizeof(chain_link_t) * (link->link - 1));
	ptr = ptr_base + (4 * (link->link - 1));

	DETAIL_PRINT("regs phys: 0x%lx off: 0x%lx\n", phys_base, phys);
	DETAIL_PRINT("regs ptr: 0x%lx off: 0x%lx\n", ptr_base, ptr);

	regs.ir0.r = regs.ir1.r = regs.cp.r = regs.csr.r = 0L;
	/* IR0 */
	list_for_each_entry(tmp, &dev->dma_chain, list) {
		if (tmp->link.lnumber == link->link) {
			link->offset_mem0 = tmp->link.phys_mem;
			break;
		}
	}
	regs.ir0.b.ir  = link->offset_mem0;
	regs.ir0.b.sel = 1; /* always CPU */
	regs.ir0.b.or  = 1; /* ir = ir + (or * 8) */
	/* IR1 */
	regs.ir1.b.ir  = link->offset_mem1;//PHYS_NODE(link->offset_mem1);
	regs.ir1.b.sel = 0; /* always DSP */
	regs.ir1.b.or  = 1; /* ir = ir + (or * 8) */
	/* CP */
	regs.cp.b.adr  = phys + sizeof(chain_link_t);
	regs.cp.b.sel  = 1; /* regs always in CPU */
	//regs.cp.b.run  = 1; //not sure - needed or not
	/* CSR */
	/* one word = 64 bit */
	regs.csr.b.wn  = 0xf; /* words - by default 16 words at once send */
	regs.csr.b.wcx = (link->size)/(128); /* 128 = (64bits/8bits)*16words */
	regs.csr.b.dir = link->mode; /* 0 = IOR0->IOR1, 1 = IOR0<-IOR1 */
	regs.csr.b.im  = link->intr;
	/* regs.csr.b.start_dsp = link->dsp_run; */
	regs.csr.b.chen  = link->terminate ? 0 : 1;

	DBG_PRINT("dma:\tSETUP_LINK_REG: 0x%lx 0x%lx 0x%lx 0x%x\n",
		  regs.ir0.r,
		  regs.ir1.r,
		  regs.cp.r,
		  regs.csr.r);

	ptr[0] = regs.ir0.r;
	ptr[1] = regs.ir1.r;
	ptr[2] = regs.cp.r;
	ptr[3] = regs.csr.r;
}


int check_chain_regs(dsp_dev_t *dev)
{
	unsigned long *ptr = NULL;
	unsigned long *ptr_base = ((unsigned long *)(dev->link_regs.virt_mem));
	int i = 0;

	DETAIL_PRINT("dma:\tCHECK_LINK_REG\n");
	for (i = 0; i < dev->chain_present; i++) {
		ptr = ptr_base + (i * 4);
		DBG_PRINT("[%03d]: 0x%lx 0x%lx 0x%lx 0x%x\n",
			  i,
			  ptr[0], ptr[1],
			  ptr[2], ptr[3]);
	}

	return 0;
}


/*

: 0x101001c180000 0x1000000000000               0x3fff001c
: 0x101001c180000 0x1000000040000               0x0fff001c
! 0x101001c154000 0x10001c0000000 0x3001c0cb020 0x0080303c

*/



/* dma exchange - write and read in chain mode  */
int dma_chain_exchange(dsp_dev_t *dev)
{
#ifdef __ALL_IN_REG__
	unsigned long *ptr_base = ((unsigned long *)(dev->link_regs.virt_mem));
	union ior_register ir0, ir1;
	union csr_register csr;
#endif
	union cp_register cp;
	unsigned long flags;

	int while_count = 0;
	hrtime_t all_s, all_e, s, e;

	if (lock_channel(dev->node, dev->number, dev->chain_channel)) {
		ERROR_PRINT("DMA: lock channel error, channel %d - busy\n",
			    dev->chain_channel);
		return -EFAULT;
	}

	all_s = gethrtime();

	DETAIL_PRINT("self:\tCP - 0x%lx 0x%lx\n",
		     dev->link_regs.virt_mem,
		     dev->link_regs.phys_mem);

#ifdef __ALL_IN_REG__
	csr.r = ir0.r = ir1.r = cp.r = 0L;

	ir0.r = ptr_base[0];
	ir1.r = ptr_base[1];
	cp.r = ptr_base[2];
	csr.r = ptr_base[3];

	DETAIL_PRINT("REGS: 0x%lx 0x%lx 0x%lx 0x%lx\n",
		     ir0.r, ir1.r,
		     cp.r, csr.r);
#else
	cp.b.adr  = dev->link_regs.phys_mem;
	cp.b.sel  = 1; /* regs always in CPU */
	cp.b.run  = 1;
	DETAIL_PRINT("CP: 0x%lx\n", cp.r);
#endif /*__ALL_IN_REG__*/

	/* run exchange */
	s = gethrtime();
	SLOCK_IRQSAVE(&dev->spinlock, flags);

	dev->dma.run = 1;
	dev->dma.channel = dev->chain_channel;
	dev->dma.chain = 1;

#ifdef __ALL_IN_REG__
	SET_DMA_REG(IOR0, dev->chain_channel, ir0.r);
	SET_DMA_REG(IOR1, dev->chain_channel, ir1.r);
	SET_DMA_REG(CP, dev->chain_channel, cp.r);
	SET_DMA_REG(CSR, dev->chain_channel,  csr.r);
#else
	SET_DMA_REG(CP, dev->chain_channel, cp.r);
#endif /*__ALL_IN_REG__*/

#ifdef __DMA_INTERRUPTS_ON__
	/* waiting ending DMA work */
	while (dev->dma.done == 0) {
		while_count++;

		raw_wqueue_t wait_el = {.task = current};
		current->state = TASK_INTERRUPTIBLE;
		list_add(&wait_el.task_list, &dev->dma.wait_task_list);
		SUNLOCK_IRQREST(&dev->spinlock, flags);
		DETAIL_PRINT("while:\t %d\n", while_count);
		schedule();
		DETAIL_PRINT("while:\t %d\n", while_count);
		SLOCK_IRQSAVE(&dev->spinlock, flags);
		list_del(&wait_el.task_list);
		current->state = TASK_RUNNING;
		if (signal_pending(current)) {
			SUNLOCK_IRQREST(&dev->spinlock, flags);
			unlock_channel(dev->node, dev->number, dev->chain_channel);
			dev->dma.end = 0;//repeat not needed
			dev->dma.done = 0;
			dev->dma.run = 0;
			dev->dma.chain = 0;
			dev->dma.channel = -1;
			return -ERESTARTSYS;
		}
	}
#else
	SUNLOCK_IRQREST(&dev->spinlock, flags);
	/* for debug without interrupts */
	while (!reg_csr.b.done) {
		old_csr.r = reg_csr.r;
		reg_csr.r = GET_DMA_REG(CSR, dev->chain_channel);
		while_count++;
		if (while_count > 9999999)
			break;
	}
#endif

	dev->dma.end = 0;//repeat not needed
	dev->dma.done = 0;
	dev->dma.run = 0;
	dev->dma.chain = 0; // off chain mode
	dev->dma.channel = -1;

	SUNLOCK_IRQREST(&dev->spinlock, flags);
	e = gethrtime();

	unlock_channel(dev->node, dev->number, dev->chain_channel);

	all_e = gethrtime();

	DETAIL_PRINT("dma selfinit: event count %d\n", while_count);
	DETAIL_PRINT("dma:\tDSP DMA done: time: DMA - %lu, "
		     "DMA plus system - %lu\n",
		     e - s,
		     all_e - all_s);

	return 0;
}


void delete_dma_chain(dsp_dev_t *dev)
{
	struct list_head *entry, *tent;
	struct chain_list *tmp;

	DETAIL_PRINT("before delete chain\n");

	if (dev->chain_present <= 0) {
		DBG_PRINT("chain not exists\n");
		return;
	}

	free_dma(dev->link_regs.page_adr, dev->link_regs.size);

	list_for_each_safe(entry, tent, &dev->dma_chain) {
		tmp = list_entry(entry, struct chain_list, list);
		DETAIL_PRINT("delete chain: %d\n", tmp->link.lnumber);
		free_dma(tmp->link.page_adr, tmp->link.size);
		list_del(entry);
		kfree(tmp);
	}
	DETAIL_PRINT("after delete chain\n");
	dev->chain_present = 0;
	return;
}


int add_link_to_dma_chain(dsp_dev_t *dev, int pages)
{
	chain_list_t *tchain = NULL;

	//dbg: later move create regs pool in other place
	if (dev->chain_present == 0) {
		dma_state_t *l = &dev->link_regs;
		DETAIL_PRINT("kmalloc for chain_regs\n");
		l->size = PAGE_SIZE;
		l->real_size = alloc_dma(&l->page_adr,
					 &l->virt_mem,
					 &l->phys_mem,
					 l->size);
		DETAIL_PRINT("after create poll for links regs: %d %d\n",
			     l->real_size,
			     l->size);
		if (l->real_size <= 0) {
			ERROR_PRINT("DMA: DSP[%d]: error allocate buffer\n",
				    dev->number);
			return -ENOMEM;
		}
	}

	DETAIL_PRINT("kmalloc for tchain\n");
	tchain = kmalloc(sizeof(chain_list_t), GFP_KERNEL);
	if (tchain == NULL) {
		ERROR_PRINT("chain:\tDSP: %d. "
			    "Can't allocate memory for chain_list_t.\n",
			    dev->number);
		free_dma(dev->link_regs.page_adr, dev->link_regs.size);
		return -ENOMEM;
	}

	DETAIL_PRINT("before create link to chain\n");
	/* create and setup new DMA buffers */
	tchain->link.size = PAGE_SIZE * pages;
	tchain->link.real_size = alloc_dma(&tchain->link.page_adr,
					   &tchain->link.virt_mem,
					   &tchain->link.phys_mem,
					   tchain->link.size);
	DETAIL_PRINT("after create link to chain: %d %d\n",
		     tchain->link.real_size,
		     tchain->link.size);
	if (tchain->link.real_size <= 0) {
		ERROR_PRINT("init: DSP[%d]: error allocate DMA buffer\n",
			    dev->number);
		free_dma(dev->link_regs.page_adr, dev->link_regs.size);
		kfree(tchain);
		return -ENOMEM;
	}

	dev->chain_present++;
	tchain->link.lnumber = dev->chain_present;

	DETAIL_PRINT("chain DMA allocate[%d:%d:%2d]: 0x%lx 0x%lx 0x%lx %d %d\n",
		     dev->node, dev->number, dev->minor,
		     (unsigned long)tchain->link.virt_mem,
		     tchain->link.page_adr,
		     tchain->link.phys_mem,
		     tchain->link.size,
		     tchain->link.real_size);

	list_add_tail(&tchain->list, &dev->dma_chain);

	return tchain->link.lnumber;
}
#endif /*__CHAIN_MODE_ON__*/
#endif /*__DMA_ON__*/


void get_status(dsp_dev_t *dev, dsp_status_t *tstatus)
{
	tstatus->number	= dev->minor;
	tstatus->run	= GETBIT(DCSR, 14);
	tstatus->wait	= GETBIT(DCSR, 4);
	tstatus->reason	= dev->reason;
	tstatus->state	= (GET_DSP_REG(SR) & 0xff);
	tstatus->mail	= GET_DSP_REG(EFR); /* needed ??? */
}


static long dsp_ioctl(struct file *filp,
		     unsigned int cmd, unsigned long arg)
{
	int		err = 0;
	dsp_dev_t	*dev = (dsp_dev_t *)filp->private_data;
	int		tmp = 0;
	int		retval = 0;
	unsigned long	flags;

	DETAIL_PRINT("ioctl:\tdev[%d, %d]: node: %d, number: %d, minor: %d. "
		     "(cpu: node: %d, id: %d)\n",
		     major, (dev->minor & 0x0f),
		     dev->node, dev->number, dev->minor,
		     numa_node_id(), raw_smp_processor_id());

	MLOCK(&dev->ioctl_mutex);

#ifdef MCST_INCLUDE_IOCTL
	if (cmd == MCST_SELFTEST_MAGIC) {
		selftest_t st;
		selftest_nonbus_t *st_nbus = &st.info.nonbus;

		DETAIL_PRINT("ioctl:\tSELFTEST\n");

		st.bus_type = BUS_NONE;
		st.error = 0; /* temporary unused */

		st_nbus->major = major;
		st_nbus->minor = dev->minor;

		strncpy(st_nbus->name, dsp_dev_name, 255);
		DBG_PRINT("%s: [%d][%d][%s].\n",
			  __func__,
			  st_nbus->major, st_nbus->minor, st_nbus->name);

		if (copy_to_user((selftest_t __user *)arg,
				 &st,
				 sizeof(selftest_t))) {
			ERROR_PRINT("%s: MCST_SELFTEST_MAGIC: "
				    "copy_to_user() failed\n",
				     __func__);
			retval = -EFAULT;
		}
		goto ioctl_end;
	}
#endif

	if (_IOC_TYPE(cmd) != DSP_IOC_MAGIC) {retval = -ENOTTY; goto ioctl_end;}
	if (_IOC_NR(cmd) > DSP_IOC_MAXNR) {retval = -ENOTTY; goto ioctl_end;}
	if (_IOC_DIR(cmd) & _IOC_READ)
		err = !access_ok(VERIFY_WRITE,
				 (void __user *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		err =  !access_ok(VERIFY_READ,
				  (void __user *)arg, _IOC_SIZE(cmd));
	if (err) {retval = -EFAULT; goto ioctl_end;}


	switch(cmd) {

	case DSP_GET_STATUS:
	{
		dsp_status_t tstatus;
		DETAIL_PRINT("ioctl:\tDSP_GET_STATUS\n");

		SLOCK_IRQSAVE(&dev->spinlock, flags);
		get_status(dev, &tstatus);
		SUNLOCK_IRQREST(&dev->spinlock, flags);

		if (copy_to_user((dsp_status_t __user *)arg,
				  &tstatus,
				  sizeof(dsp_status_t)))
		{
			ERROR_PRINT("ioctl: DSP_GET_STATUS\n");
			retval = -EFAULT;
			break;
		}
	}
	break;

	case DSP_GET_FULL_STATUS:
	{
		dsp_fstatus_t fstatus;
		DETAIL_PRINT("ioctl:\tDSP_GET_FULL_STATUS\n");

		SLOCK_IRQSAVE(&dev->spinlock, flags);
		fstatus.dcsr = GET_DSP_REG(DCSR);
		fstatus.dcsr_i	= dev->dcsr_i;
		fstatus.irqr = GET_DSP_REG(IRQR);
		fstatus.imaskr = GET_DSP_REG(IMASKR);
		SUNLOCK_IRQREST(&dev->spinlock, flags);

		fstatus.sp_i	= dev->sp_i;
		fstatus.sr   = GET_DSP_REG(SR);
		fstatus.idr  = GET_DSP_REG(IDR);
		fstatus.efr  = GET_DSP_REG(EFR);
		fstatus.tmr  = GET_DSP_REG(TMR);
		fstatus.arbr = GET_DSP_REG(ARBR);
		fstatus.pc   = GET_DSP_REG(PC);
		fstatus.ss   = GET_DSP_REG(SS);
		fstatus.la   = GET_DSP_REG(LA);
		fstatus.csl  = GET_DSP_REG(CSL);
		fstatus.lc   = GET_DSP_REG(LC);
		fstatus.csh  = GET_DSP_REG(CSH);
		fstatus.sp   = GET_DSP_REG(SP);
		fstatus.sar  = GET_DSP_REG(SAR);
		fstatus.cntr = GET_DSP_REG(CNTR);

		if (copy_to_user((dsp_fstatus_t __user *)arg,
				  &fstatus,
				  sizeof(dsp_fstatus_t)))
		{
			ERROR_PRINT("ioctl: DSP_GET_FULL_STATUS\n");
			retval = -EFAULT;
			break;
		}
	}
	break;

	/* use chain DMA exchange */
	case DSP_RUN_CHAIN:
	{
		DETAIL_PRINT("ioctl:\tDSP_RUN_CHAIN\n");
#ifdef __CHAIN_MODE_ON__
#ifdef __DMA_ON__

		retval = check_chain_regs(dev);
		retval = dma_chain_exchange(dev);
#endif /*__DMA_ON__*/
#else
		WARNING_PRINT("Chain mode are - OFF !\n");
		retval = -EFAULT;
#endif /*__CHAIN_MODE_ON__*/
	}
	break;


	/* create chain DMA exchange */
	case DSP_SETUP_CHAIN:
	{
		DETAIL_PRINT("ioctl:\tDSP_SETUP_CHAIN\n");
#ifdef __CHAIN_MODE_ON__
#ifdef __DMA_ON__
		setup_chain_t chain;
		if (copy_from_user(&chain,
				    (void __user *)arg,
				   sizeof(setup_chain_t)))
		{
			ERROR_PRINT("ioctl: DMA copy from user\n");
			retval = -EFAULT;
			break;
		} else {
			DETAIL_PRINT("chain: send at %d channel\n",
				     chain.channel);
			if (chain.channel < 0 || chain.channel > MAX_DMA) {
				dev->chain_channel = dev->number * 2 + 1;
				WARNING_PRINT("DMA channel wrong: %d - "
					      "setup channel: %d\n",
					      chain.channel,
					      dev->chain_channel);
			} else {
				dev->chain_channel = chain.channel;
				DETAIL_PRINT("DMA channel for chain: %d\n",
					     dev->chain_channel);
			}

			if (chain.size_in_pages > 0) {
				dev->link_size = chain.size_in_pages;
				DETAIL_PRINT("size one link of chain "
					     "setup in %d pages\n",
					     dev->link_size);
			} else {
				WARNING_PRINT("size link of chain can not be "
					      "less then one page: %d. size = %d\n",
					      chain.size_in_pages, dev->link_size);
			}
		}
#endif /*__DMA_ON__*/
#else
		WARNING_PRINT("Chain mode are - OFF !\n");
		retval = -EFAULT;
#endif /*__CHAIN_MODE_ON__*/
	}
	break;


	/* delete chain DMA */
	case DSP_DELETE_CHAIN:
	{
		DETAIL_PRINT("ioctl:\tDSP_DELETE_CHAIN\n");
#ifdef __CHAIN_MODE_ON__
#ifdef __DMA_ON__
		delete_dma_chain(dev);
#endif /*__DMA_ON__*/
#else
		WARNING_PRINT("Chain mode are - OFF !\n");
		retval = -EFAULT;
#endif /*__CHAIN_MODE_ON__*/
	}
	break;


	/* create chain DMA exchange */
	case DSP_SETUP_LINK:
	{
		DETAIL_PRINT("ioctl:\tDSP_SETUP_LINK\n");
#ifdef __CHAIN_MODE_ON__
#ifdef __DMA_ON__
		setup_link_t link;
		if (copy_from_user(&link,
				   (void __user *)arg,
				   sizeof(setup_link_t)))
		{
			ERROR_PRINT("ioctl: DMA copy from user\n");
			retval = -EFAULT;
			break;
		} else {
			setup_target_link(dev, &link);
		}
#endif /*__DMA_ON__*/
#else
		WARNING_PRINT("Chain mode are - OFF !\n");
		retval = -EFAULT;
#endif /*__CHAIN_MODE_ON__*/
	}
	break;


	/* DBG: test chain DMA exchange */
	case DSP_TEST_CHAIN:
	{
		DETAIL_PRINT("ioctl:\tDSP_TEST_CHAIN\n");
#ifdef __CHAIN_MODE_ON__
#ifdef __DMA_ON__
		if (dev->chain_present > 0) {
			struct chain_list *tmp;
			list_for_each_entry(tmp, &dev->dma_chain, list) {
				DETAIL_PRINT("chain: %d [0x%08x] [0x%08x]\n",
					     tmp->link.lnumber,
					     tmp->link.virt_mem[0],
					     tmp->link.virt_mem[9]);
			}
		} else {
			DBG_PRINT("chain not exists\n");
		}
#endif /*__DMA_ON__*/
#else
		WARNING_PRINT("Chain mode are - OFF !\n");
		retval = -EFAULT;
#endif /*__CHAIN_MODE_ON__*/
	}
	break;


	/* DMA exchange between DSP */
	case DSP_TO_DSP_WRITE:
	{
		DETAIL_PRINT("ioctl:\tDSP_TO_DSP_WRITE\n");
#ifdef __DMA_ON__
		dsp_dma_setup_t setup;
		if (copy_from_user(&setup,
				    (void __user *)arg,
				    sizeof(dsp_dma_setup_t)))
		{
			ERROR_PRINT("ioctl: DMA copy from user\n");
			retval = -EFAULT;
			break;
		}

		/* offset must be DSP memory */
		setup.offset_mem0 = setup.offset_mem0;
		setup.offset_mem1 = setup.offset_mem1;

		retval = dma_exchange(dev, &setup, DSP_DSP);
#endif /*__DMA_ON__*/
	}
	break;

	/* data must be writing to DMA-area from user */
	case DSP_DMA_WRITE:
	{
		DETAIL_PRINT("ioctl:\tDSP_DMA_WRITE\n");
#ifdef __DMA_ON__
		dsp_dma_setup_t setup;
		if (copy_from_user(&setup,
				   (void __user *)arg,
				   sizeof(dsp_dma_setup_t)))
		{
			ERROR_PRINT("ioctl: DMA copy from user\n");
			retval = -EFAULT;
			break;
		}

		/* offset must be DSP memory */
		setup.offset_mem0 = setup.offset_mem0; /* now not used */
		setup.offset_mem1 = setup.offset_mem1; /* offset in DSP memory*/

		dma_exchange(dev, &setup, TO_DSP);

		/*
		if (copy_to_user((void __user *)arg,
				 &setup,
				 sizeof(dsp_dma_setup_t)))
		{
			ERROR_PRINT("ioctl: DMA copy to user\n");
			retval = -EFAULT;
			break;
		}
		*/
#endif /*__DMA_ON__*/
	}
	break;


	/* data from DMA-area must be reading at user */
	case DSP_DMA_READ:
	{
		DETAIL_PRINT("ioctl:\tDSP_DMA_READ\n");
#ifdef __DMA_ON__
		dsp_dma_setup_t setup;
		if (copy_from_user(&setup,
				   (void __user *)arg,
				   sizeof(dsp_dma_setup_t)))
		{
			ERROR_PRINT("ioctl: DMA copy from user\n");
			retval = -EFAULT;
			break;
		}

		/* offset must be DSP memory */
		setup.offset_mem0 = setup.offset_mem0; /* now not used */
		setup.offset_mem1 = setup.offset_mem1; /* offsetin DSP memory */

		dma_exchange(dev, &setup, FROM_DSP);

		/*
		if (copy_to_user((void __user *)arg,
				 &setup,
				 sizeof(dsp_dma_setup_t)))
		{
			ERROR_PRINT("ioctl: DMA copy to user\n");
			retval = -EFAULT;
			break;
		}
		*/
#endif /*__DMA_ON__*/
	}
	break;

	case DSP_RUN:
		DETAIL_PRINT("ioctl:\tDSP_RUN:\t %d %d %d\n",
			     dev->node, dev->number, dev->minor);
		retval = __get_user(tmp, (unsigned int __user *)arg);
		SLOCK_IRQSAVE(&dev->spinlock, flags);
		dsp_run(dev, tmp);
		SUNLOCK_IRQREST(&dev->spinlock, flags);
		retval = 0;
		break;

	case DSP_RUN_ALL:
	{
		dsp_run_all_setup_t setup;
		int i;
		dsp_dev_t   *tmp_dev;

		DETAIL_PRINT("ioctl:\tDSP_RUN_ALL\n");

		if (copy_from_user(&setup,
				   (void __user *)arg,
				   sizeof(dsp_run_all_setup_t)))
		{
			ERROR_PRINT("ioctl: DSP_RUN_ALL copy from user\n");
			retval = -EFAULT;
			break;
		}

		SLOCK_IRQSAVE(&dev->spinlock, flags);
		for (i = 0; i < dsp_numbers_devs; i++) {
			if ((setup.adr[i] != -1) &&
			    (dsp_devices[dsp_minors[i]]->run != 1)) {
				tmp_dev = dsp_devices[dsp_minors[i]];

				tmp_dev->run = 1;
				tmp_dev->mem_error = 0;

				DETAIL_PRINT("ioctl: RUN_ALL %d: adr - 0x%x\n",
					     i, setup.adr[i]);
				/* may be bug - check it */
				nSET_DSP_REG(PC, tmp_dev->node,
					     tmp_dev->number, setup.adr[i]);
			}
		}

		for (i = 0; i < node_numbers; i++)
			SETBIT_node(CSR_DSP, on_nodes[i], 0);

		SUNLOCK_IRQREST(&dev->spinlock, flags);

		retval = 0;
	}
	break;

	case DSP_WAIT:
	{
		hrtime_t s, e;
		int err = 0;

		DETAIL_PRINT("ioctl:\tDSP_WAIT: 0x%x\n", DSP_WAIT);

		s = gethrtime();
		SLOCK_IRQSAVE(&dev->spinlock, flags);
		while (dev->run == 1) {
			raw_wqueue_t wait_el = {.task = current};
			current->state = TASK_INTERRUPTIBLE;
			list_add(&wait_el.task_list, &dev->wait_task_list);
			SUNLOCK_IRQREST(&dev->spinlock, flags);
			schedule();
			SLOCK_IRQSAVE(&dev->spinlock, flags);
			list_del(&wait_el.task_list);
			current->state = TASK_RUNNING;
			if (signal_pending(current)) {
				dsp_status_t tstatus;
				get_status(dev, &tstatus);
				SUNLOCK_IRQREST(&dev->spinlock, flags);
				retval = -ERESTARTSYS;
				DETAIL_PRINT("ioctl:\tDSP_WAIT end "
					     "on signal pending\n");
				DETAIL_PRINT("ioctl:\tstate: run: %d wait: "
					     "0x%x rs: 0x%x st 0x%x\n",
					     tstatus.run,
					     tstatus.wait,
					     tstatus.reason,
					     tstatus.state);
				goto ioctl_end;
			}
			if (dev->run == 0)
				break;
			/*
			SUNLOCK_IRQREST(&dev->spinlock, flags);
			if (wait_event_interruptible(dev->wait_queue,
						     (dev->run == 0)))
			{
				retval = -ERESTARTSYS;
				goto ioctl_end;
			}
			SLOCK_IRQSAVE(&dev->spinlock, flags);
			*/
		}
		err = dev->mem_error;
		SUNLOCK_IRQREST(&dev->spinlock, flags);
		e = gethrtime();

		//DETAIL_PRINT("ioctl:\tDSP_WAIT end.\n");
		if (err) {
			DETAIL_PRINT("ioctl:\tDSP_WAIT end on error, "
				"wait time: %lu\n", e - s);
			retval = -EIO;
			break;
		}
		DETAIL_PRINT("ioctl:\tDSP_WAIT end, wait time: %lu\n", e - s);
	}

	retval = 0;
	break;

	case DSP_WAIT_ACTIVE:
	{
		int run = dev->run;
		int t_count = 0;
		hrtime_t s, e;
		DETAIL_PRINT("ioctl:\tDSP_WAIT_ACTIVE: %d\n", run);

		retval = __get_user(tmp, (unsigned int __user *)arg);

		DBG_PRINT("ioctl:\tDSP_WAIT_ACTIVE: time_wait: %d\n", tmp);

		s = gethrtime();
		while(1) {
			e = gethrtime();
			if (((e - s)/1000000) >= tmp)
				break;
		}
		s = gethrtime();
		while (run) {
			run = GETBIT(DCSR, 14);
			t_count++;
			if (t_count > 9999999)
				break;
		}
		e = gethrtime();

		SLOCK_IRQSAVE(&dev->spinlock, flags);
		dev->run = 0;
		SUNLOCK_IRQREST(&dev->spinlock, flags);

		DETAIL_PRINT("ioctl:\tDSP_WAIT_ACTIVE end: %d %d, time: %lu\n",
			     run, t_count, e - s);
	}

	retval = 0;
	break;

	case DSP_STOP:
		DETAIL_PRINT("ioctl:\tDSP_STOP\n");
		SLOCK_IRQSAVE(&dev->spinlock, flags); //trylock ?
		dsp_stop(dev);
		SUNLOCK_IRQREST(&dev->spinlock, flags);
		retval = 0;
		break;

	case DSP_RESET:
		DETAIL_PRINT("ioctl:\tDSP_RESET\n");
		SLOCK_IRQSAVE(&dev->spinlock, flags);
		retval = dsp_reset(dev);
		if (retval)
			retval = -EBUSY;
		else
			retval = 0;
		SUNLOCK_IRQREST(&dev->spinlock, flags);
		dsp_clear_memory(dev);
		break;

	case DSP_SET_TIMER:
	{
		DETAIL_PRINT("ioctl:\tDSP_SET_TIMER\n");

		retval = __get_user(tmp, (unsigned int __user *)arg);

		SLOCK_IRQSAVE(&dev->spinlock, flags);
		SET_DSP_REG(TMR, tmp);
		SUNLOCK_IRQREST(&dev->spinlock, flags);

		DETAIL_PRINT("ioctl:\tDSP_SET_TIMER: %u\n", tmp);
	}
	break;

	case DSP_SET_MAIL_MODE:
	{
		retval = __get_user(tmp, (unsigned int __user *)arg);

		DETAIL_PRINT("ioctl:\tDSP_SET_MAIL_MODE: %s\n",
			     tmp ? "SYNC" : "NORMAL");
		SLOCK_IRQSAVE(&dev->spinlock, flags);
		if (tmp) {
			SETBIT_node(CSR_DSP, dev->node, 1);
		} else {
			CLRBIT_node(CSR_DSP, dev->node, 1);
		}
		SUNLOCK_IRQREST(&dev->spinlock, flags);
	}
	break;

	case DSP_SEND_MAIL:
	{
		dsp_mail_box_t mail;

		if (copy_from_user(&mail,
				    (struct dsp_mail_box __user *)arg,
				    sizeof(struct dsp_mail_box)))
		{
			ERROR_PRINT("ioctl: MAIL copy from user\n");
			retval = -EFAULT;
			break;
		}

		DETAIL_PRINT("ioctl:\tDSP_SEND_MAIL: %u 0x%lx\n",
			     mail.box,
			     mail.value);

		if (mail.box > 63) {
			retval = -EFAULT;
			break;
		}

		SLOCK_IRQSAVE(&dev->spinlock, flags);
		writeq(mail.value, XBUF(mail.box)); /* send */
		SUNLOCK_IRQREST(&dev->spinlock, flags);
	}
	break;

	case DSP_GET_MAIL:
	{
		dsp_mail_box_t mail;
		DETAIL_PRINT("ioctl:\tDSP_GET_MAIL\n");
		if (copy_from_user(&mail,
				   (dsp_mail_box_t __user *)arg,
				   sizeof(dsp_mail_box_t)))
		{
			ERROR_PRINT("ioctl: MAIL copy from user\n");
			retval = -EFAULT;
			break;
		}

		if (mail.box > 63) {
			retval = -EFAULT;
			break;
		}

		SLOCK_IRQSAVE(&dev->spinlock, flags);
		mail.value = readq(XBUF(mail.box)); /* get */
		SUNLOCK_IRQREST(&dev->spinlock, flags);

		DETAIL_PRINT("ioctl:\tDSP_GET_MAIL: %u 0x%lx\n",
			     mail.box,
			     mail.value);

		if (copy_to_user((dsp_mail_box_t __user *)arg,
				  &mail,
				  sizeof(dsp_mail_box_t)))
		{
			ERROR_PRINT("ioctl: MAIL copy to user\n");
			retval = -EFAULT;
			break;
		}
	}
	break;

	case DSP_SET_APIC_MASK:
	{
		dsp_apic_mask_t mask;

		DETAIL_PRINT("ioctl:\tIOCTL SET_APIC_MASK\n");
		DETAIL_PRINT("ioctl:\tget masks: "
			     "node: %d: cpu0: 0x%x, cpu1: 0x%x\n",
			     dev->node,
			     GET_APIC_REG(IC_MR0),
			     GET_APIC_REG(IC_MR1));

		if (copy_from_user(&mask,
				    (dsp_apic_mask_t __user *)arg,
				    sizeof(dsp_apic_mask_t)))
		{
			ERROR_PRINT("ioctl: SET_APIC_MASK copy from user\n");
			retval = -EFAULT;
			break;
		} else {
			DBG_PRINT("ioctl:\tget from user masks: "
				  "cpu0: 0x%x, cpu1: 0x%x\n",
				  mask.cpu0, mask.cpu1);
		}

		SLOCK_IRQSAVE(&global_lock, flags);
		SET_APIC_REG(IC_MR0, mask.cpu0);
		/*
		 * LCC compilator bug workaround: second register set is
		 * compiled as speculative read/wrtite ti IO space, so
		 * 'nop' separator command temporary is added
		 */
		E2K_CMD_SEPARATOR;
		SET_APIC_REG(IC_MR1, mask.cpu1);
		SUNLOCK_IRQREST(&global_lock, flags);

		DETAIL_PRINT("ioctl:\tset masks: cpu0: 0x%x, cpu1: 0x%x\n",
			     GET_APIC_REG(IC_MR0),
			     GET_APIC_REG(IC_MR1));
	}
	break;

	case DSP_GET_APIC_MASK:
	{
		dsp_apic_mask_t mask;

		DETAIL_PRINT("ioctl:\tIOCTL GET_APIC_MASK\n");

		SLOCK_IRQSAVE(&dev->spinlock, flags);
		mask.cpu0 = GET_APIC_REG(IC_MR0);
		mask.cpu1 = GET_APIC_REG(IC_MR1);
		SUNLOCK_IRQREST(&dev->spinlock, flags);

		DETAIL_PRINT("ioctl:\tget masks: "
			     "node: %d: cpu0: 0x%x, cpu1: 0x%x\n",
			     dev->node,
			     mask.cpu0,
			     mask.cpu1);

		if (copy_to_user((dsp_apic_mask_t __user *)arg,
				  &mask,
				  sizeof(dsp_apic_mask_t)))
		{
			ERROR_PRINT("ioctl: GET_APIC_MASK copy from user\n");
			retval = -EFAULT;
			break;
		}
	}
	break;


	case DSP_SET_INTR_MASK:
	{
		unsigned int tdsp;

		DETAIL_PRINT("ioctl:\tIOCTL SET_INTR_MASK\n");
		DETAIL_PRINT("ioctl:\tget masks: node: %d, intr: 0x%x\n",
			     dev->node,
			     GET_CLUSTER_REG(MASKR_DSP));

		__get_user(tdsp, (unsigned int __user *)arg);
		SLOCK_IRQSAVE(&global_lock, flags);
		SET_CLUSTER_REG(MASKR_DSP, tdsp);
		SUNLOCK_IRQREST(&global_lock, flags);

		DETAIL_PRINT("ioctl:\tget masks: node: %d, intr: 0x%x\n",
			     dev->node,
			     GET_CLUSTER_REG(MASKR_DSP));
		retval = 0;
	}
	break;


	case DSP_GET_INTR_MASK:
	{
		unsigned int tdsp;

		DETAIL_PRINT("ioctl:\tIOCTL GET_INTR_MASK\n");
		tdsp = GET_CLUSTER_REG(MASKR_DSP);
		DETAIL_PRINT("ioctl:\tget masks: node: %d, intr: 0x%x\n",
			     dev->node,
			     tdsp);

		__put_user(tdsp, (unsigned int __user *)arg);
		retval = 0;
	}
	break;


	/*next cases must be DELETE for release !!!*/
	case DSP_SETIRQ_IOCTL:
		DETAIL_PRINT("ioctl:\tSET IRQ\n");
		__get_user(tmp, (unsigned int __user *)arg);

		SLOCK_IRQSAVE(&dev->spinlock, flags);
		SET_DSP_REG(CNTR, tmp);
		SUNLOCK_IRQREST(&dev->spinlock, flags);

		retval = 0;
		break;


	case DSP_TEST_MEMORY:
	{
		__get_user(tmp, (unsigned int __user *)arg);

		SLOCK_IRQSAVE(&dev->spinlock, flags);
		if (tmp >= 0 && tmp <= 0xc47ff8) {
			if      (tmp >= 0xc40000)
				retval = (int)readl(nPRAM(dev->node, 3) +
						    (tmp - 0xc40000));
			else if (tmp >= 0xc00000)
				retval = (int)readl(nXYRAM(dev->node, 3) +
						    (tmp - 0xc00000));
			else if (tmp >= 0x840000)
				retval = (int)readl(nPRAM(dev->node, 2) +
						    (tmp - 0x840000));
			else if (tmp >= 0x800000)
				retval = (int)readl(nXYRAM(dev->node, 2) +
						    (tmp - 0x800000));
			else if (tmp >= 0x440000)
				retval = (int)readl(nPRAM(dev->node, 1) +
						    (tmp - 0x440000));
			else if (tmp >= 0x400000)
				retval = (int)readl(nXYRAM(dev->node, 1) +
						    (tmp - 0x400000));
			else if (tmp >= 0x040000)
				retval = (int)readl(nPRAM(dev->node, 0) +
						    (tmp - 0x040000));
			else if (tmp >= 0x000000)
				retval = (int)readl(nXYRAM(dev->node, 0) +
						    (tmp - 0x000000));
		} else {
			retval = (int)0x12345;
		}

		SUNLOCK_IRQREST(&dev->spinlock, flags);
		DETAIL_PRINT("ioctl:\tdsp memory check:\t: "
			     "offset: 0x%x, [0x%x]\n",
			     tmp, (int)(retval));
	}
	break;

	default:
		ERROR_PRINT("ioctl:\tUnknown command: 0x%x\n", cmd);
		retval = -EINVAL;
	}

ioctl_end:
	MUNLOCK(&dev->ioctl_mutex);

	DETAIL_PRINT("ioctl:\tend\n");

	return retval;
}

static const struct file_operations dsp_fops = {
	.owner   = THIS_MODULE,
	.open    = dsp_open,
	.release = dsp_release,
	.read    = dsp_read,    /*not implemented*/
	.write   = dsp_write,   /*not implemented*/
	.unlocked_ioctl = dsp_ioctl,
	.poll    = dsp_poll,
	.mmap    = dsp_mmap,
};


#ifdef __CATCH_INTERRUPT_ON__
/* collect mask */
static inline int interrupt_analyze(int interrupt)
{
	int i, mask = 0;

	for (i = 0; i < MAX_DSP; i++) {
		if (interrupt & mask_intr[i])
			mask |= (1 << i);
	}

	return mask;
}


/*
 * interrupts to DSP and from DSP haven't priority
 * all interrupts execute by sequence ?
 */
void dsp_interrupt_handler(struct pt_regs *regs)
{
	int i;
	int receiver = 0;     /* bitmask */
	int DMA_receiver = 0; /* bitmask */
	static unsigned long long icount = 0;

/* defines for short strings */
#define TN dsp_node[node.number]

#if DEBUG_MODE
	static int count_error = 0;
#endif
	interrupt_t node;
	int mem_error = 0;
	unsigned long flags;

	SLOCK_IRQSAVE(&interrupt_lock, flags);
	node.number = numa_node_id();
	SUNLOCK_IRQREST(&interrupt_lock, flags);

	node.r[0] = nGET_APIC_REG(IC_IR0, node.number);
	node.r[1] = nGET_APIC_REG(IC_IR1, node.number);
	node.generic = node.r[0] | node.r[1];

	icount++;

#ifndef __ALL_ONLINE_NODE__
	if (node.number > 0) {
		WARNING_PRINT("intr:\t\tnode: %d: impossible, "
			      "this node are OFF for interrupts\n",
			      node.number);
	}
#endif

	/* impossible situation */
	if (node.generic == 0) {
#if DEBUG_MODE
		count_error++;
		if (count_error > 1000)	{
			WARNING_PRINT("intr:\t\tnode: %d: impossible, "
				      "IC_IR0 & IC_IR1 == 0\n", node.number);
			count_error = 0;
		}
#endif

		/*
		 * there must be clear interrupt in APIC:
		 * ack_APIC_irq();
		 * but now it called in e2k.c
		 */
		return;
	}

	DBG_PRINT("intr:\t[%08ld] handler: 0x%x |= (0x%x | 0x%x). cpu: "
		  "node: %d, id: %d\n",
		  icount, node.generic, node.r[0], node.r[1],
		  node.number, raw_smp_processor_id());

	/* check for DMA */
	if (node.generic & 0x00ff) {
		int i = 0;
		unsigned long flags;
		DETAIL_PRINT("intr:\tDMA interrupt, generic: 0x%x\n",
			     node.generic);
		for (i = 0; i < MAX_DMA; i++)
			if ((node.generic >> i) & 1) {
				DETAIL_PRINT("intr:\tchannel: %d\n", i);
				SLOCK_IRQSAVE(&interrupt_lock, flags);
				/*for DMA_receiver: 0,1 - DSP0; 2,3 - DSP1 ...*/
				DMA_receiver |= processing_DMA(node.number, i);
				SUNLOCK_IRQREST(&interrupt_lock, flags);
				DETAIL_PRINT("intr:\tDMA receiver: 0x%x "
					     "(chn: %d)\n",
					     DMA_receiver, i);
			}
		node.generic &= 0xff00;/* needed clear ??? */
	}


	/*
	 * get mask for DSP, who set interrupt
	 * receiver for node.number
	 */
	receiver = interrupt_analyze(node.generic);

	DBG_PRINT("intr:\t[%08ld] receiver: 0x%x, QSTR: 0x%x, DMA: 0x%x\n",
		  icount, receiver,
		  nGET_CLUSTER_REG(QSTR_DSP, node.number),
		  DMA_receiver);

	if (receiver == 0)
		goto done;

	/* added interupts to device mask */
	SLOCK_IRQSAVE(&interrupt_lock, flags);
	for (i = 0; i < MAX_DSP; i++) {
		if (receiver & (1 << i)) {
			TN.dsp[i]->interrupts |= (node.generic & mask_intr[i]);
			TN.dsp[i]->tmp_all_intr |= node.generic;
		}
	}
	SUNLOCK_IRQREST(&interrupt_lock, flags);

	if (node.generic & 0x0f00) {
		int i = 0;
		unsigned int i_tmp = (node.generic >> 8) & 0xf;
		DBG_PRINT("intr:\t[%08ld] STOP interrupt\n", icount);
		for (i = 0; i < MAX_DSP; i++)
			if ((i_tmp >> i) & 1) {
				DETAIL_PRINT("intr:\tstop device: %d:%d:%d\n",
					     node.number, i,
					     (node.number * MAX_NODE) + i);
				SLOCK_IRQSAVE(&interrupt_lock, flags);
				TN.dsp[i]->state =
					nGET_DSP_REG(SR, node.number, i) & 0xff;
				TN.dsp[i]->run = 0;
				/* stop */
				nSET_DSP_REG(DCSR, node.number, i, 0x0);
				SUNLOCK_IRQREST(&interrupt_lock, flags);
			}
	}

	if (node.generic & 0xf000) {
		int i = 0;
		unsigned int i_tmp = (node.generic >> 12);
		DBG_PRINT("intr:\t[%08ld] DSP interrupt\n", icount);
		for (i = 0; i < MAX_DSP; i++)
			if ((i_tmp >> i) & 1) {
				DETAIL_PRINT("intr:\tdevice: %d\n",
					     (node.number * MAX_NODE) + i);
				SLOCK_IRQSAVE(&interrupt_lock, flags);
				processing_other_reason(TN.dsp[i]);
				SUNLOCK_IRQREST(&interrupt_lock, flags);
			}
		mem_error = TN.dsp[0]->mem_error;
	}

done:

	for (i = 0; i < MAX_DSP; i++) {
		if (DMA_receiver & (1 << i)) {
			dsp_dma_processing(TN.dsp[i]);
		}

		if (receiver & (1 << i)) {
			dsp_interrupt_processing(TN.dsp[i]);
		}
	}

	/*
	 * there must be clear interrupt in APIC:
	 * ack_APIC_irq();
	 * but now it called in e2k.c
	 */

	return;
}


static inline void processing_other_reason(dsp_dev_t *dev)
{
	unsigned int reason = 0;
	int not_clear = 1; /* flag for mark reason */
	static unsigned int count_error = 0;
	/*unsigned long flags;*/

	//SLOCK_IRQSAVE(&interrupt_lock, flags);
	reason = (GET_CLUSTER_REG(QSTR_DSP) >> (8 * dev->number)) & 0xff;
	dev->reason = reason;
	dev->mem_error = 0;
	dev->dcsr_i = GET_DSP_REG(DCSR);
	dev->sp_i   = GET_DSP_REG(SP);

	switch(reason) {
	case (1 << 0): /* PI - write in IDR anything */
		SET_DSP_REG(IDR, 0x1); /* clear == write in IDR anything */
		not_clear = 0;
		break;
	case (1 << 1): /* SE - clear SP */
		SET_DSP_REG(SP, 0x0);   /* for clear needed write zero in SP */
		SET_DSP_REG(DCSR, 0x0); /* and may be DCSR */
		not_clear = 0;
		dev->run = 0;
		break;
	case (1 << 2): /* BREAK - clear DCSR */
		SET_DSP_REG(DCSR, 0x0);
		not_clear = 0;
		dev->run = 0;
		break;
	case (1 << 3): /* STOP - clear DCSR */
		SET_DSP_REG(DCSR, 0x0);
		not_clear = 0;
		dev->run = 0;
		break;
	case (1 << 7): /* dbDCSR - clear dbDCSR */
		SET_DSP_REG(dbDCSR, 0x0);
		not_clear = 0;
		dev->run = 0;
		break;
	}
	//SUNLOCK_IRQREST(&interrupt_lock, flags);

	DBG_PRINT("other reason: QSTR_DSP (with mask): "
		  "[0x%d], DCSR: [0x%x], SP: [0x%x]\n",
		  reason, dev->dcsr_i, dev->sp_i);

	/* this switch only for dbg print */
	switch(reason) {
	case (1 << 0): /* PI - write in IDR anything */
		DBG_PRINT("reason:\tPI\n");
		break;
	case (1 << 1): /* SE - clear SP */
		DBG_PRINT("reason:\tSE\n");
		break;
	case (1 << 2): /* BREAK - clear DCSR */
		DBG_PRINT("reason:\tBREAK\n");
		break;
	case (1 << 3): /* STOP - clear DCSR */
		DBG_PRINT("reason:\tSTOP\n");
		break;
	case (1 << 7): /* dbDCSR - clear dbDCSR */
		DBG_PRINT("reason:\tdBREAK\n");
		break;
	}

	/* all DSPs wait or parity error or dbDCSR in DSP[0] at each cluster */
	if (not_clear && (dev->number == 0)) {
		DBG_PRINT("[%d:%d:%02d]:\tintr - reason: 0x%08x; "
			  "REGS: QSTR: 0x%08x, CSR_DSP: 0x%08x, "
			  "IC_IR0: 0x%08x, IC_IR1: 0x%08x\n",
			    dev->node, dev->number, dev->minor,
			    reason,
			    GET_CLUSTER_REG(QSTR_DSP),
			    GET_CLUSTER_REG(CSR_DSP),
			    nGET_APIC_REG(IC_IR0, dev->node),
			    nGET_APIC_REG(IC_IR1, dev->node));

#define RIGHT_RULE_DSP_INTERRUPT_CATCH
#ifdef RIGHT_RULE_DSP_INTERRUPT_CATCH
		if (reason & (1 << 4)) { /* WAIT = clear CSR_DSP */
			int i;
			int dcsr_t = 0;
			/* clear all DCSR, bit 4, in current node */
			//SLOCK_IRQSAVE(&interrupt_lock, flags);
			for (i = 0; i < 4; i++) {
				/*
				  WARNING_PRINT("%d, DCSR: 0x%08x\n",
						i, GET_DSP_REG(DCSR));
				*/
				dcsr_t |= (nGETBIT(DCSR, dev->node, i, 4)) << i;
				nCLRBIT(DCSR, dev->node, i, 4); /* clear WT */
			}
			SET_CLUSTER_REG(CSR_DSP, 0x0);
			//SUNLOCK_IRQREST(&interrupt_lock, flags);
			not_clear = 0;
			WARNING_PRINT("reason:\t"
				      "all DSP wait XBUF exchange: 0x%x\n",
				      dcsr_t);
		} else if (reason & (1 << 5)) { /* parity error */
			//SLOCK_IRQSAVE(&interrupt_lock, flags);
			dev->mem_error = GET_CLUSTER_REG(MEM_ERR_CSR);
			dev->run = 0;
			SET_CLUSTER_REG(MEM_ERR_CSR, 0x4);
			//SUNLOCK_IRQREST(&interrupt_lock, flags);
			not_clear = 0;
			ERROR_PRINT("intr:\t[%d:%d:%02d]:MEM PARITY ERROR: "
				    "ctrl 0x%x, memerr %d, dspX 0x%x - 0x%x\n",
				    dev->node, dev->number, dev->minor,
				    dev->mem_error & 0x3,
				    dev->mem_error & 0x4,
				    (dev->mem_error >> 4) & 0xf,
				    dev->mem_error);
		}
#else /* debug rule */
		/*
		 WAIT - clear CSR_DSP and PARITY_ERROR - set 0x4 in MEM_ERR_CSR
		 */
		if (reason & 0x30) { //01110000 - check 2-bits for any happens
			int i;
			int dcsr_t = 0;
			/* clear all DCSR, bit 4, in current node */
			//SLOCK_IRQSAVE(&interrupt_lock, flags);
			for (i = 0; i < 4; i++) {
				/*
				  WARNING_PRINT("%d, DCSR: 0x%08x\n",
						i, GET_DSP_REG(DCSR));
				*/
				dcsr_t |= (nGETBIT(DCSR, dev->node, i, 4)) << i;
				nCLRBIT(DCSR, dev->node, i, 4); /* clear WT */
			}
			SET_CLUSTER_REG(CSR_DSP, 0x0);
			dev->mem_error = GET_CLUSTER_REG(MEM_ERR_CSR);
			dev->run = 0;
			SET_CLUSTER_REG(MEM_ERR_CSR, 0x4);
			//SUNLOCK_IRQREST(&interrupt_lock, flags);
			not_clear = 0;
			ERROR_PRINT("intr:\tWAIT: "
				    "0x%x or PARITY ERROR: MEM_ERR_CSR 0x%x\n",
				dcsr_t,
				dev->mem_error);
		}
#endif
	}

	if (not_clear) {
		count_error++;
		if (count_error > 1000 || count_error == 1) {
			if (count_error > 1000) count_error = 0;
			ERROR_PRINT("intr:\t"
				    "impossible - interrupt not cleared !\n");
			ERROR_PRINT("[%d:%d:%02d]:\treason: 0x%x; "
				    "QSTR: 0x%08x, CSR: 0x%08x, "
				    "IC_IR0: 0x%08x, IC_IR1: 0x%08x\n",
				    dev->node, dev->number, dev->minor,
				    reason,
				    GET_CLUSTER_REG(QSTR_DSP),
				    GET_CLUSTER_REG(CSR_DSP),
				    nGET_APIC_REG(IC_IR0, dev->node),
				    nGET_APIC_REG(IC_IR1, dev->node));
		}
	}

	return;
}


static inline int processing_DMA(unsigned int node, unsigned int channel)
{

	int number = -1;
	union csr_register csr;
	static unsigned int count_error = 0;
	/*unsigned long flags;*/

	number = check_channel(node, channel);

	//SLOCK_IRQSAVE(&interrupt_lock, flags);
	/* clear interrupt */
	csr.r = nGET_DMA_REG(CSR, node, channel);

	if (number == -1) {
		count_error++;
		//SUNLOCK_IRQREST(&interrupt_lock, flags);
		if (count_error > 1000 || count_error == 1) {
			if (count_error > 1000) count_error = 0;
			ERROR_PRINT("DMA: get interrupt "
				    "for unused channel: %d:%d, err: %u\n",
				    node, channel, count_error);
		}
		return number; //what needed return for this error-situation ?
	}

	/* if csr.b.done != 0 then we get csr.b.end (one block data exchange) */
	dsp_node[node].dsp[number]->dma.end = csr.b.end;
	dsp_node[node].dsp[number]->dma.done = csr.b.done;
	dsp_node[node].dsp[number]->dma.run = 0;
	//SUNLOCK_IRQREST(&interrupt_lock, flags);

	DBG_PRINT("proceesing_DMA: get interrupt: node: %d, chn: %d, dsp: %d\n",
		  node, channel, number);

	return (1 << number);
}


inline void wakeup_each_dsp(struct list_head *list)
{
	struct list_head *tmp, *next;
	raw_wqueue_t *waiter_item;
	list_for_each_safe(tmp, next, list) {
		waiter_item = list_entry(tmp, raw_wqueue_t, task_list);
		wake_up_process(waiter_item->task);
	}
}


void dsp_dma_processing(dsp_dev_t *dev)
{
	static unsigned long dma_intr = 0;

	dma_intr++;

	DETAIL_PRINT("dma :\t [%d:%d:%d] mask: 0x%x, all: 0x%x, intr: %lu\n",
		     dev->node, dev->number, dev->minor,
		     dev->interrupts, dev->tmp_all_intr, dma_intr);

	if (dev->dma.done == 0) {
		dev->dma.end++;
		DBG_PRINT("DMA: end for block exchange: %ld %d\n",
			  dma_intr, dev->dma.end);
	}

	if (dev->dma.done) {
		DBG_PRINT("DMA: wake up dsp[%d:%d:%d]\n",
			  dev->node, dev->number, dev->minor);
		dev->dma.end = 0;
		wakeup_each_dsp(&dev->dma.wait_task_list);
	}

	return;
}


void dsp_interrupt_processing(dsp_dev_t *dev)
{
	dsp_dev_t *dsp_dev;
	int i;
	static unsigned long count_intr = 0;

	count_intr++;

	DETAIL_PRINT("intr:\t [%d:%d:%d] "
		     "mask: 0x%x, all: 0x%x, err %d, intr: %lu\n",
		     dev->node, dev->number, dev->minor,
		     dev->interrupts, dev->tmp_all_intr,
		     dev->mem_error, count_intr);

	if (dev->run == 0) {
		DBG_PRINT("DSP: wake up dsp[%d:%d:%d]\n",
			  dev->node, dev->number, dev->minor);
		wakeup_each_dsp(&dev->wait_task_list);
	}
	if (dev->mem_error) {
		for (i = 0; i < MAX_DSP; i ++) {
			if (dev->number == i)
				continue;
			dsp_dev = dsp_node[dev->node].dsp[i];
			if (dsp_dev->run) {
				dsp_dev->run = 0;
				dsp_dev->mem_error = 1;
				DBG_PRINT("DSP: "
					  "wake up on error dsp[%d:%d:%d]\n",
					  dsp_dev->node, dsp_dev->number,
					  dsp_dev->minor);
				wakeup_each_dsp(&dsp_dev->wait_task_list);
			}
		}
	}
	return;
}
#endif /*__CATCH_INTERRUPT_ON__*/


void free_memory_from_dsp_allocate(void)
{
	int i;

	if (dsp_numbers_devs) {
		/* free all DMA buffers */
		for (i = 0; i < dsp_numbers_devs; i++) {
#ifdef __CHAIN_MODE_ON__
			delete_dma_chain(dsp_devices[dsp_minors[i]]);
#endif /*__CHAIN_MODE_ON__*/
			free_dma(dsp_devices[dsp_minors[i]]->dma.page_adr,
				 DMA_EXCHANGE_SIZE);
		}

		for (i = 0; i < dsp_numbers_devs; i++) {
			int node = dsp_devices[dsp_minors[i]]->node;
			/* clear mask interrupts */
			if (dsp_devices[dsp_minors[i]]->number == 0) {
				nSET_CLUSTER_REG(MASKR_DSP, node, 0x0);
			}
			kfree(dsp_devices[dsp_minors[i]]);
		}

		/* unmap phys memory */
#ifdef __ALL_ONLINE_NODE__
		for (i = 0; i < MAX_NODE; i++)

#endif
		{
			if (dsp_node[i].present) {
				int m;
				/* clear masks all interupts */
				nSET_APIC_REG(IC_MR0, i, 0x0);   /*CPU0*/
				/*
				 * LCC compilator bug workaround: second
				 * register set is compiled as speculative
				 * read/wrtite ti IO space, so 'nop' separator
				 * command temporary is added
				 */
				E2K_CMD_SEPARATOR;

				nSET_APIC_REG(IC_MR1, i, 0x0);   /*CPU1*/

				/* unmap phys memory */
				for (m = 0; m < MAX_DSP; m++) {
					iounmap(BASE[i].xyram[m]);
					iounmap(BASE[i].pram[m]);
					iounmap(BASE[i].regs[m]);
				}

				iounmap(BASE[i].xbuf);
			}
		}
		DETAIL_PRINT("End clear memory and mask's.\n");
	}
}


int create_dsp_device(int node, int number, dsp_dev_t *dev, int *all_dev_number)
{
	memset(dev, 0, sizeof(dsp_dev_t));

	SINIT(&dev->spinlock);
	MINIT(&dev->ioctl_mutex);

	/* setup queue */
#ifdef __CATCH_INTERRUPT_ON__
	INIT_LIST_HEAD(&dev->wait_task_list);
	INIT_LIST_HEAD(&dev->dma.wait_task_list);

#ifdef __CHAIN_MODE_ON__
	/* chain */
	INIT_LIST_HEAD(&dev->dma_chain);
	dev->chain_present = 0; /* set chain empty */
	dev->link_size = 4;
#endif /*__CHAIN_MODE_ON__*/
#endif /*__CATCH_INTERRUPT_ON__*/

	dev->node = node;
	dev->number = number;
	dev->id = (*all_dev_number);
	dev->minor = node*MAX_NODE + number;
	dev->dma.channel = -1;

	(*all_dev_number)++; /* increase: dsp_numbers_devs++ */

	/* create and setup DMA buffer */
	dev->dma.real_size = alloc_dma(&dev->dma.page_adr,
				       &dev->dma.virt_mem,
				       &dev->dma.phys_mem,
				       DMA_EXCHANGE_SIZE);
	if (dev->dma.real_size <= 0) {
		ERROR_PRINT("init: DSP[%d]: error allocate DMA buffer\n",
			    dev->number);
		return -ENOMEM;
	}

	DETAIL_PRINT("DMA allocate[%d:%d:%2d]: 0x%lx 0x%lx 0x%lx %d %d\n",
		  dev->node, dev->number, dev->minor,
		  (unsigned long)dev->dma.virt_mem,
		  dev->dma.page_adr,
		  dev->dma.phys_mem,
		  (unsigned int)DMA_EXCHANGE_SIZE,
		  dev->dma.real_size);

	return 0;
}


void hardcore_clear_all_memory() {

/* on interrupts only at cpu0 each nodes */
	uint32_t maskr_dsp[128];
	uint32_t ic_mr0[128];
	uint32_t ic_mr1[128];
	int i = 0;

	/* save target regs for all possible nodes */
#ifdef __ALL_ONLINE_NODE__
	for (i = 0; i < MAX_NODE; i++)
#endif
	{
		if (dsp_node[i].present) {
			maskr_dsp[i] = nGET_CLUSTER_REG(MASKR_DSP, i);
			ic_mr0[i] = nGET_CLUSTER_REG(IC_MR0, i);
			ic_mr1[i] = nGET_CLUSTER_REG(IC_MR1, i);
		}
	}

	/* clear target regs for all possible nodes */
#ifdef __ALL_ONLINE_NODE__
	for (i = 0; i < MAX_NODE; i++)
#endif
	{
		if (dsp_node[i].present) {
			nSET_CLUSTER_REG(MASKR_DSP, i, 0x0);
			nSET_CLUSTER_REG(IC_MR0, i, 0x0);
			nSET_CLUSTER_REG(IC_MR1, i, 0x0);
		}
	}

	/* clear mem-interrupts for all possible nodes */
#ifdef __ALL_ONLINE_NODE__
	for (i = 0; i < MAX_NODE; i++)
#endif
	{
		if (dsp_node[i].present) {
			nSET_CLUSTER_REG(MEM_ERR_CSR, i, 0x4);
			nSET_CLUSTER_REG(CSR_DSP, i, 0x0);
		}
	}

	/* clear XYRAM and PRAM */
#ifdef __ALL_ONLINE_NODE__
	for (i = 0; i < MAX_NODE; i++)
#endif
	{
		if (dsp_node[i].present) {
			int m;
			for (m = 0; m < MAX_DSP; m++) {
				memset(nXYRAM(i, m), 0, XYRAM_SIZE);
				memset(nPRAM(i, m), 0, PRAM_SIZE);
			}
		}
	}

	/* clear mem-interrupts for all possible nodes */
#ifdef __ALL_ONLINE_NODE__
	for (i = 0; i < MAX_NODE; i++)
#endif
	{
		if (dsp_node[i].present) {
			nSET_CLUSTER_REG(MEM_ERR_CSR, i, 0x4);
			nSET_CLUSTER_REG(CSR_DSP, i, 0x0);
		}
	}

	/* restore target regs for all possible nodes */
#ifdef __ALL_ONLINE_NODE__
	for (i = 0; i < MAX_NODE; i++)
#endif
	{
		if (dsp_node[i].present) {
			nSET_CLUSTER_REG(MASKR_DSP, i, maskr_dsp[i]);
			nSET_CLUSTER_REG(IC_MR0, i, ic_mr0[i]);
			nSET_CLUSTER_REG(IC_MR1, i, ic_mr1[i]);
		}
	}
}


/* #define FOR_DBG 0 */
static int __init dsp_init (void)
{
	dsp_dev_t   *dev;
	int result, nod_i = 0, j, dsp_i, node_count = 0;
	int dsp_on = 0; /* counter for online DSP-clusters */
	char name[128];
	int i, ret = 0, meminit = 0;

	DBG_PRINT ("Hello world from DSP driver. cpu: node: %d, id: %d\n",
		   numa_node_id(), raw_smp_processor_id());

	dsp_sysctl_register();

#ifdef FOR_DBG
	if (FOR_DBG) { /* for dbg */
		int nid = 0;
		unsigned long long phys_base_tmp;
		for_each_online_node(nid) {
			phys_base_tmp = THE_NODE_NBSR_PHYS_BASE(nid);
			ERROR_PRINT("sys: 0x%llx -> %p\n",
				phys_base_tmp,
				nodes_nbsr_base[nid]);

			ERROR_PRINT("node: "
				    "%d [0x%0lx:0x%0lx - 0x%0lx] - {0x%0lx}\n",
				    nid, THE_NODE_NBSR_PHYS_BASE(nid),
				    THE_NODE_NBSR_PHYS_BASE(nid) + 0xb0000000L,
				    THE_NODE_COPSR_PHYS_BASE(nid),
#ifdef _MANUAL_CONTROL_AREA_SIZE_
				    BASE_PHYS_ADR + (nid * DSP_MEM_SIZE));
#else
				    0x01c0000000UL + (nid * 0x1000000UL));
#endif
		}
	}
#endif

#ifndef __DMA_INTERRUPTS_ON__
	WARNING_PRINT("init: NO interrupts DMA mode\n");
#endif /*__DMA_INTERRUPTS_ON__*/

	if (!IS_MACHINE_ES2) {
		ERROR_PRINT("init:\tCan't find DSP lapic\n");
		ret = -ENODEV;
		goto dsp_init_end;
	} else {
		node_numbers = num_online_nodes();
		DBG_PRINT ("CPU's numbers: %d, node: %d\n",
			   node_numbers*2, node_numbers);
	}

	for (nod_i = 0; nod_i < MAX_NODE; nod_i++) {
		dsp_node[nod_i].online = 0;
		dsp_node[nod_i].present = 0;
	}

	nod_i = 0;
#ifdef __ALL_ONLINE_NODE__
	for_each_online_node(nod_i)
#endif /*__ALL_ONLINE_NODE__*/
	{
		unsigned long	offset_b;

		/* for each online node check on/off dsp */
		e2k_pwr_mgr_struct_t pwr;
		pwr.word = nGET_APIC_REG(IC_PWR, nod_i);

		if (!pwr.fields.ic_clk)	{
			dsp_node[nod_i].online = 0;
			DBG_PRINT("DSP for node: %d - OFF\n", nod_i);
#ifdef __ALL_ONLINE_NODE__
			continue;
#endif
		} else {
			meminit = 1; /* memory clear flag at error */
			on_nodes[node_count] = nod_i;
			node_count++;

			DBG_PRINT("DSP for node: %d - ON\n", nod_i);
			dsp_on++;

			for (dsp_i = 0; dsp_i < MAX_DSP; dsp_i++) {

				offset_b = (unsigned long)(nNODE_PHYS_ADR(nod_i)
							   + (0x400000 *
							      dsp_i));

				BASE[nod_i].xyram[dsp_i] = ioremap(offset_b +
								   XYRAM_OFFSET,
								   XYRAM_SIZE);
				BASE[nod_i].pram[dsp_i]  = ioremap(offset_b +
								   PRAM_OFFSET,
								   PRAM_SIZE);
				BASE[nod_i].regs[dsp_i]  = ioremap(offset_b +
								   REGS_OFFSET,
								   dsp_i ?
								   (0x1000) :
								   (0x3000));

				DETAIL_PRINT("%d xyram 0x%lx <- 0x%lx,"
					     "\n\t\t\t  pram  0x%lx <- 0x%lx,"
					     "\n\t\t\t  regs  0x%lx <- 0x%lx\n",
					     dsp_i,
					     BASE[nod_i].xyram[dsp_i],
					     offset_b,
					     BASE[nod_i].pram[dsp_i],
					     offset_b + 0x40000,
					     BASE[nod_i].regs[dsp_i],
					     offset_b + 0x80000
					);
			}

			BASE[nod_i].xbuf = (char *)ioremap(nNODE_PHYS_ADR(nod_i) + 0x3fff00, PAGE_SIZE);

			for (dsp_i = 0; dsp_i < MAX_DSP; dsp_i++) {
				dev = kmalloc(sizeof(dsp_dev_t), GFP_KERNEL);
				if (dev == NULL) {
					ERROR_PRINT("init:\tDSP: %d. "
						    "Can't allocate memory "
						    "for dsp_dev_t.\n",
						    dsp_i + nod_i);
					ret = -ENOMEM;
					goto dsp_init_end;
				}

				if (create_dsp_device(nod_i, dsp_i,
						      dev, &dsp_numbers_devs)) {
					ret = -ENOMEM;
					goto dsp_init_end;
				}

				dsp_devices[nod_i*MAX_NODE + dsp_i] = dev;
				dsp_node[nod_i].dsp[dsp_i] = dev;
				dsp_minors[dsp_numbers_devs-1] = dev->minor;
			} /* end creating four DSP in i-node */

			for (j = 0; j < MAX_DMA; j++)
				dsp_node[nod_i].dma_channel_lock[j] = -1;

			dsp_node[nod_i].present = 1;
			dsp_node[nod_i].online = 1;

			/* off all interrupts for all DSP-node */
			/* off interupts in DSP-mask */
			nSET_CLUSTER_REG(MASKR_DSP, nod_i, 0x0);
			/* off interupts in CPU-mask */
			nSET_APIC_REG(IC_MR0, nod_i, 0x0);
			/*
			 * LCC compilator bug workaround: second register set is
			 * compiled as speculative read/wrtite ti IO space, so
			 * 'nop' separator command temporary is added
			 */
			E2K_CMD_SEPARATOR;

			nSET_APIC_REG(IC_MR1, nod_i, 0x0);

		} /* end for check on/off DSP */
	} /* end "for_each_online_node" */


/* temporary hack */
#ifdef __ALL_ONLINE_NODE__
	for (nod_i = 0; nod_i < MAX_NODE; nod_i++)
#endif
	{
		if (dsp_node[nod_i].present) {
			/* off interupts in CPU-mask */
			nSET_APIC_REG(IC_MR0, nod_i, 0x0);
			/*
			 * LCC compilator bug workaround: second register set is
			 * compiled as speculative read/wrtite ti IO space, so
			 * 'nop' separator command temporary is added
			 */
			E2K_CMD_SEPARATOR;
			nSET_APIC_REG(IC_MR1, nod_i, 0x0);
		}
	}

	if (!dsp_on) {
		WARNING_PRINT("Not found DSP-clusters online.\n");
		ret = -ENODEV;
		goto dsp_init_end;
	}

	if (node_numbers != dsp_on) {
		WARNING_PRINT("Some DSP-clusters are off.\n");
	}

	SINIT(&dma_lock);
	SINIT(&interrupt_lock);
	SINIT(&global_lock);

	/* for clear memory interrupts before work */
	{
		unsigned long flags = 0;
		DETAIL_PRINT("hack:\tmemory clear\n");
		SLOCK_IRQSAVE(&interrupt_lock, flags);
		hardcore_clear_all_memory();
		SUNLOCK_IRQREST(&interrupt_lock, flags);
	}

#ifdef __CATCH_INTERRUPT_ON__
	/* Save our interupt to global kernel pointer */
	eldsp_interrupt_p = dsp_interrupt_handler;
#endif

	if (dsp_numbers_devs > 0) {
		result = register_chrdev(major, dsp_dev_name, &dsp_fops);
		if (result < 0) {
			ERROR_PRINT("init:\tCannot get major %d\n", major);
			ret = -ENODEV;
			goto dsp_init_end;
		}
		if (major == 0)
			major = result;
		DETAIL_PRINT("init:\tmajor number is %d.\n", major);
	} else {
		ERROR_PRINT("init:\tregister_chrdev did not execute.\n");
		ret = -ENODEV;
		goto dsp_init_end;
	}


#ifdef __USE_PROC__
#ifdef CONFIG_PROC_FS

	if (!ldsp_entry) {
		dsp_proc_entry = proc_create("dspinfo", S_IRUGO,
					     NULL, &eldsp_proc_ops);
		if (!dsp_proc_entry)
			ERROR_PRINT("init: can't create /proc/dspinfo\n");
	} else {
		save_eldsp_proc_ops = ldsp_proc_fops_pointer;
		ldsp_proc_fops_pointer = &eldsp_proc_ops;
	}
#endif /* CONFIG_PROC_FS */
#endif /* __USE_PROC__ */

#ifdef FOR_DBG
	if (FOR_DBG) { /* for dbg */
		int nid = 0;
		for (nid = 0; nid < MAX_NODE; nid++) {
			if (dsp_node[nid].present) {
				ERROR_PRINT("IR0: 0x%x\n",
					    nGET_APIC_REG(IC_IR0, nid));
				ERROR_PRINT("IR1: 0x%x\n",
					    nGET_APIC_REG(IC_IR1, nid));
				ERROR_PRINT("IDR: 0x%x\n",
					    nGET_DSP_REG(IDR, nid, 0));
			}
		}
	}
#endif


#ifdef __DSP_RUN_HACK_FOR_MEMORY__
	for (nod_i = 0; nod_i < MAX_NODE; nod_i++) {
		if (dsp_node[nod_i].present) {
			for (dsp_i = 0; dsp_i < MAX_DSP; dsp_i++) {
				/* set run bit */
				nSETBIT(DCSR, nod_i, dsp_i, 14);
				/* clear run bit */
				nCLRBIT(DCSR, nod_i, dsp_i, 14);
			}
		}
	}
#endif

/* now interrupts ON -  only by open() device and only for target DSP */
#ifdef __CATCH_INTERRUPT_ON__

	/* on interrupts only at cpu0 each nodes */
	DETAIL_PRINT("init:\tbefore interupts\n");
#ifdef __ALL_ONLINE_NODE__
	for (nod_i = 0; nod_i < MAX_NODE; nod_i++)
#endif
	{
		if (dsp_node[nod_i].present) {
			 /* DSP[0-3] */
			nSET_CLUSTER_REG(MASKR_DSP, nod_i, 0xffffffff);
			/* 0xffffffdf - of bit 5 -  off wait interrupt: DBG ! */

#  ifdef __DMA_INTERRUPTS_ON__
			nSET_APIC_REG(IC_MR0, nod_i, 0xffff);   /*CPU0*/
#  else
			nSET_APIC_REG(IC_MR0, nod_i, 0xff00);   /*CPU0 DMA OFF*/
#  endif /*__DMA_INTERRUPTS_ON__*/
			DETAIL_PRINT("init:\tinterupts for node - %d\n", nod_i);
		}
	}

#endif /*__CATCH_INTERRUPT_ON__*/


#ifdef FOR_DBG
	if (FOR_DBG) { /* for dbg */
		for (i = 0; i < dsp_numbers_devs; i++) {
			ERROR_PRINT("dsp: %d -> %d\n", i, dsp_minors[i]);
		}

		for (i = 0; i < node_numbers; i++) {
			ERROR_PRINT("node: %d -> %d\n", i, on_nodes[i]);
		}
	}
#endif
	/* we register class in sysfs... */
	dsp_class = class_create(THIS_MODULE, DSP_NAME);
	if (IS_ERR(dsp_class)) {
		ERROR_PRINT("Error creating class: /sys/class/" DSP_NAME ".\n");
	}

	/* ...and create devices in /sys/class/eldsp */
	for (i = 0; i < dsp_numbers_devs; ++i) {
		if (!IS_ERR(dsp_class)) {
			sprintf(name, "%s%d", DSP_NAME, i);
			/*
			pr_info("make node /sys/class/%s/%s\n",
				DSP_NAME, name);
			*/
			if (device_create(dsp_class, NULL,
			    MKDEV(major, dsp_minors[i]), NULL, name) == NULL)
				ERROR_PRINT("create a node %d failed\n", i);
		}
	}

dsp_init_end:
	if (ret) {
		if (meminit)
			free_memory_from_dsp_allocate();
		dsp_sysctl_unregister();
	}

	return ret;

}


static void __exit dsp_cleanup(void)
{
	int i;

#ifdef __USE_PROC__
#ifdef CONFIG_PROC_FS
	if (!ldsp_entry) {
		proc_remove(dsp_proc_entry);
	} else {
		ldsp_proc_fops_pointer = save_eldsp_proc_ops;
	}
#endif /* CONFIG_PROC_FS */
#endif /* __USE_PROC__ */

	/* we need to remove the device...*/
	for (i = 0; i < dsp_numbers_devs; ++i) {
		device_destroy(dsp_class, MKDEV(major, dsp_minors[i]));
	}

	/* ...and class */
	class_destroy(dsp_class);

	free_memory_from_dsp_allocate();
	unregister_chrdev(major, dsp_dev_name);
	dsp_sysctl_unregister();
	DBG_PRINT("exit:\tcleanup device driver\n");

	return;
}


module_init(dsp_init);
module_exit(dsp_cleanup);

MODULE_AUTHOR     ("Alexey Mukhin");
MODULE_LICENSE    ("GPL");
MODULE_DESCRIPTION("driver for Elbrus Digital Signal Processors v. " DSP_VERSION);
