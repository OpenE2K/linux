/*
 * arch/sparc/kernel/procpfreg_e90s.c
 *
 * This file contains implementation of functions to read and write PFREG
 * registers through proc fs.
 *
 * Copyright (C) 2010-2015 Pavel V. Panteleev (panteleev_p@mcst.ru)
 */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <asm/io.h>


#define PFREGREGS_FILENAME	"pfregs"
#define PFREGREAD_FILENAME	"pfread"
#define PFREGWRITE_FILENAME	"pfwrite"

#define PFREGREAD_STR_MAX_SIZE	16
#define PFREGWRITE_STR_MAX_SIZE	32

static DEFINE_RAW_SPINLOCK(pfregreg_lock);
static int pfregreg_offset = 0;


/*
 * PFREG read
 */

static int pfregregs_seq_show(struct seq_file *s, void *v)
{
	int node = (int)(*((loff_t *)v));
	int offset;
	unsigned long val;
	unsigned long flags;

	raw_spin_lock_irqsave(&pfregreg_lock, flags);
	offset = pfregreg_offset;
	raw_spin_unlock_irqrestore(&pfregreg_lock, flags);

	if (offset > NODE_PFREG_AREA_SIZE)
			return -EINVAL;

	val = __raw_readq((void *)NODE_PFREG_AREA_BASE(node) + offset);

	seq_printf(s, "node: %d reg (0x%X): 0x%lX\n", node, offset, val);

	return 0;
}

static void *pfregregs_seq_start(struct seq_file *s, loff_t *pos)
{
	if (!node_online(*pos))
		*pos = next_online_node(*pos);
	if (*pos == MAX_NUMNODES)
		return 0;
	return (void *)pos;
}

static void *pfregregs_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	*pos = next_online_node(*pos);
	if (*pos == MAX_NUMNODES)
		return 0;
	return (void *)pos;
}

static void pfregregs_seq_stop(struct seq_file *s, void *v)
{
}

static const struct seq_operations pfregregs_seq_ops = {
	.start = pfregregs_seq_start,
	.next  = pfregregs_seq_next,
	.stop  = pfregregs_seq_stop,
	.show  = pfregregs_seq_show
};

static int pfregregs_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &pfregregs_seq_ops);
}

static const struct file_operations pfregregs_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = pfregregs_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};


/*
 * PFREG adjust read
 */

static inline void pfregread_write_reg(char *str)
{
	int offset, res;
	unsigned long flags;

	res = sscanf(str, "0x%X\n", &offset);
	if (res != 1) {
		pr_err("Failed to save PFREG register to read (invalid string).\n");
		return;
	}

	raw_spin_lock_irqsave(&pfregreg_lock, flags);
	pfregreg_offset = offset;
	raw_spin_unlock_irqrestore(&pfregreg_lock, flags);
}

static ssize_t pfregread_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *ppos)
{
	char pfregread_buffer[PFREGREAD_STR_MAX_SIZE];
	long  ret;

	memset(pfregread_buffer, 0, sizeof(char) * PFREGREAD_STR_MAX_SIZE);

	if (count + 1 > PFREGREAD_STR_MAX_SIZE) {
		pr_err("Failed to save PFREG register to read (too long string).\n");
		ret = -EINVAL;
	} else if (copy_from_user(pfregread_buffer, buffer,
				min(sizeof(pfregread_buffer), count))) {
		pr_err("Failed to save PFREG register to read (kernel error).\n");
		ret = -EFAULT;
	} else {
		pfregread_write_reg(pfregread_buffer);
		ret = count;
	}

	return ret;
}

static int pfregread_proc_show(struct seq_file *m, void *v)
{
	return 0;
}

static int pfregread_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, pfregread_proc_show, NULL);
}

static const struct file_operations pfregread_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = pfregread_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.write   = pfregread_write,
	.release = seq_release
};


/*
 * PFREG write
 */

static inline void pfregwrite_write_reg(char *str)
{
	int node, reg, res;
	unsigned long val;

	if (!capable(CAP_SYS_ADMIN)) {
		pr_err("Failed to write PFREG register (no permissions).\n");
		return;
	}

	res = sscanf(str, "%d 0x%X 0x%lX\n", &node, &reg, &val);
	if (res != 3) {
		pr_err("Failed to write PFREG register (invalid string).\n");
		return;
	} else if (!node_online(node)) {
		pr_err("Failed to write PFREG register (invalid node number).\n");
		return;
	} else if (reg > NODE_PFREG_AREA_SIZE) {
		pr_err("Failed to write PFREG register (invalid register).\n");
		return;
	}
	__raw_writeq(val, (void *)NODE_PFREG_AREA_BASE(node) + reg);

}

static ssize_t pfregwrite_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *ppos)
{
	char pfregwrite_buffer[PFREGWRITE_STR_MAX_SIZE];
	long  ret;

	memset(pfregwrite_buffer, 0, sizeof(char) * PFREGWRITE_STR_MAX_SIZE);

	if (count + 1 > PFREGWRITE_STR_MAX_SIZE) {
		pr_err("Failed to write PFREG register (too long string).\n");
		ret = -EINVAL;
	} else if (copy_from_user(pfregwrite_buffer, buffer,
				min(sizeof(pfregwrite_buffer), count))) {
		pr_err("Failed to write PFREG register (kernel error).\n");
		ret = -EFAULT;
	} else {
		pfregwrite_write_reg(pfregwrite_buffer);
		ret = count;
	}

	return ret;
}

static int pfregwrite_proc_show(struct seq_file *m, void *v)
{
	return 0;
}

static int pfregwrite_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, pfregwrite_proc_show, NULL);
}

static const struct file_operations pfregwrite_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = pfregwrite_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.write   = pfregwrite_write,
	.release = seq_release
};


/*
 * Init
 */

static int __init init_procpfreg(void)
{
	if (e90s_get_cpu_type() != E90S_CPU_R2000)
		return 0;

	proc_create(PFREGREGS_FILENAME, S_IRUGO, NULL, &pfregregs_proc_fops);
	proc_create(PFREGREAD_FILENAME, S_IRUGO, NULL, &pfregread_proc_fops);
	proc_create(PFREGWRITE_FILENAME, S_IRUGO, NULL, &pfregwrite_proc_fops);

	return 0;
}

module_init(init_procpfreg);
