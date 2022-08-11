#include <linux/types.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/kernel_stat.h>
#include <linux/tty.h>
#include <linux/string.h>
#include <linux/mman.h>
#include <linux/proc_fs.h>
#include <linux/ioport.h>
/* #include <linux/config.h> */
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/signal.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/times.h>
#include <linux/profile.h>
#include <linux/blkdev.h>
#include <linux/hugetlb.h>
#include <linux/jiffies.h>
#include <linux/sysrq.h>
#include <linux/vmalloc.h>
#include <linux/crash_dump.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/tlb.h>
#include <asm/div64.h>
#include "rdma_user_intf_net.h"
#include "rdma_reg_net.h"


static int	rdma_event_open(struct inode *inode, struct file *file);
static int	show_rdma_event(struct seq_file *m, void *__unused);
static void	*c_start(struct seq_file *m, loff_t *pos);
static void	*c_next(struct seq_file *m, void *v, loff_t *pos);
static void	c_stop(struct seq_file *m, void *v);
void		print_event(struct seq_file *m, struct rdma_event_entry *ree);

struct proc_dir_entry *entry;





static int show_rdma_event(struct seq_file *m, void *__unused)
{
	unsigned long			flags;
	struct	rdma_event		*re;
	struct	rdma_event_entry	*ree;
	int				i;
	int				i_end;

	if (!rdma_event_init)
		return -1;
	re = &rdma_event;
	raw_spin_lock_irqsave(&re->mu_fix_event, flags);
	ree = (struct rdma_event_entry *)(&(re->event[re->event_cur]));
	i_end = (SIZE_EVENT - re->event_cur)/SIZE_ENTRY;
	for (i = 0; i < i_end; i++, ree++) {
		print_event(m, ree);
	}
	ree = (struct rdma_event_entry *)(&(re->event[0]));
	i_end = re->event_cur/SIZE_ENTRY;
	for (i = 0; i < i_end; i++, ree++) {
		print_event(m, ree);
	}
	raw_spin_unlock_irqrestore(&re->mu_fix_event, flags);
	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	/* The pointer we are returning is arbitrary,
	 * it just has to be non-NULL and not IS_ERR
	 * in the success case.
	 */
	return *pos == 0 ? &c_start : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v)
{
}


struct seq_operations rdma_event_op = {
	.start = c_start,
	.next =	c_next,
	.stop =	c_stop,
	.show =	show_rdma_event,
};


static int rdma_event_open(struct inode *inode, struct file *filp)
{
        return seq_open(filp, &rdma_event_op);
}

static const struct file_operations proc_wp_operations = {
        .open           = rdma_event_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = seq_release,
};


//void __init proc_rdma_event_init(void)
void proc_rdma_event_init(void)
{
	printk("proc_rdma_event_init start\n");
	proc_create("rdma_event", 0, NULL, &proc_wp_operations);

}

void proc_rdma_event_close(void)
{
	if (entry)
		remove_proc_entry("rdma_event", entry);
}

void print_event(struct seq_file *m, struct rdma_event_entry *ree)
{
	char	*p1;

	sdvk[0] = '\0';
	prw = preg = NULL;
	if (parse_reg(ree)) {
		seq_printf(m,
			"0x%08x %08u %s\t\t\t%s\t\t0x%08x %s\n",
			ree->channel, ree->hrtime, prw, preg, ree->val2, sdvk);
		return;
	}
	p1 = get_event(ree->event);
	if (p1)
		seq_printf(m,
			"0x%08x %08u %s\t0x%08x\t0x%08x\n",
			ree->channel, ree->hrtime, p1, ree->val1, ree->val2);
}
