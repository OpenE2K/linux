/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains implementation of functions to read and write hw
 * registers through proc fs.
 */

#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <asm/sic_regs.h>
#ifdef CONFIG_E2K
#include <asm/sic_regs_access.h>
#endif


#define MASREAD_FILENAME	"masread"
#define MASWRITE_FILENAME	"maswrite"
#define SICREAD_FILENAME	"sicread"
#define SICWRITE_FILENAME	"sicwrite"

#define MASREAD_STR_MAX_SIZE	64
#define MASWRITE_STR_MAX_SIZE	64
#define SICREAD_STR_MAX_SIZE	16
#define SICWRITE_STR_MAX_SIZE	32
#define LDRD_STR_MAX_SIZE	32


enum {
	SICREG_FORMAT_W,
	SICREG_FORMAT_L
};

static raw_spinlock_t sicreg_lock;
static u32 sicreg_offset;
static u32 sicreg_format;


#ifdef CONFIG_E2K
/*
 * Use such default values to prevent panic due sporadic access from stupid user utilities
 */

static atomic64_t masread_addr;
static atomic64_t masread_mas = ATOMIC64_INIT(MAS_DCACHE_L2_REG);


static ssize_t common_proc_write(const char *__user buffer, size_t count, size_t maxcount,
				 char *msg, void (*func)(char *))
{
	char proc_buffer[maxcount];
	long ret;

	memset(proc_buffer, 0, sizeof(char) * maxcount);

	if (count > maxcount - 1) {
		pr_err("Failed to %s (too long string).\n", msg);
		ret = -EINVAL;
	} else if (copy_from_user(proc_buffer, buffer, count)) {
		pr_err("Failed to %s (kernel error).\n", msg);
		ret = -EFAULT;
	} else {
		func(proc_buffer);
		ret = count;
	}

	return ret;
}


/*
 * Read with MAS
 */

static int masread_proc_show(struct seq_file *s, void *v)
{
	u64 val, mas = atomic64_read(&masread_mas);

	switch (mas) {
	case MAS_MMU_REG:
		val = NATIVE_READ_MAS_D(atomic64_read(&masread_addr), MAS_MMU_REG);
		break;
	case MAS_DCACHE_L2_REG:
		val = NATIVE_READ_MAS_D(atomic64_read(&masread_addr), MAS_DCACHE_L2_REG);
		break;
	default:
		BUG();
	}

	seq_printf(s, "0x%llx", val);

	return 0;
}

static int masread_proc_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return single_open(file, masread_proc_show, NULL);
}

static void masread_write_reg(char *str)
{
	u64 addr, mas;
	int res;

	res = sscanf(str, "0x%llX 0x%llX\n", &addr, &mas);
	if (res != 2) {
		pr_err("Failed to save address and MAS to read (invalid string).\n");
		return;
	}

	if (mas != MAS_MMU_REG && mas != MAS_DCACHE_L2_REG) {
		pr_err("Failed to save address and MAS to read (invalid MAS).\n");
		return;
	}

	atomic64_set(&masread_addr, addr);
	atomic64_set(&masread_mas, mas);
}

static ssize_t masread_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *ppos)
{
	return common_proc_write(buffer, count, MASREAD_STR_MAX_SIZE,
			"save address and MAS to read", masread_write_reg);
}

static const struct proc_ops masread_proc_ops = {
	.proc_open    = masread_proc_open,
	.proc_write   = masread_write,
	.proc_read    = seq_read,
	.proc_lseek  = seq_lseek,
	.proc_release = single_release
};


/*
 * Write with MAS
 */

static void maswrite_write_reg(char *str)
{
	u64 addr, val, mas;
	int res;

	res = sscanf(str, "0x%llX 0x%llX 0x%llX\n", &addr, &mas, &val);
	if (res != 3) {
		pr_err("Failed to write with MAS (invalid string).\n");
		return;
	}

	if (mas != MAS_MMU_REG && mas != MAS_DCACHE_L2_REG) {
		pr_err("Failed to write with MAS (invalid MAS).\n");
		return;
	}

	switch (mas) {
	case MAS_MMU_REG:
		NATIVE_WRITE_MAS_D(addr, val, MAS_MMU_REG);
		break;
	case MAS_DCACHE_L2_REG:
		NATIVE_WRITE_MAS_D(addr, val, MAS_DCACHE_L2_REG);
		break;
	default:
		BUG();
	}
}

static ssize_t maswrite_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *ppos)
{
	return common_proc_write(buffer, count, MASWRITE_STR_MAX_SIZE, "write with MAS",
			maswrite_write_reg);
}

static int maswrite_proc_show(struct seq_file *s, void *v)
{
	return 0;
}

static int maswrite_proc_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return single_open(file, maswrite_proc_show, NULL);
}

static const struct proc_ops maswrite_proc_ops = {
	.proc_open    = maswrite_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_write   = maswrite_write,
	.proc_release = single_release
};
#endif


/*
 * SIC read
 */

static int sicread_seq_show(struct seq_file *s, void *v)
{
	int node = (int)(*((loff_t *)v));
	int offset, format;
	unsigned int val;
	unsigned long flags;

	raw_spin_lock_irqsave(&sicreg_lock, flags);
	offset = sicreg_offset;
	format = sicreg_format;
	raw_spin_unlock_irqrestore(&sicreg_lock, flags);

	switch (format) {
	case SICREG_FORMAT_W:
		val = sic_readw_node_nbsr_reg(node, offset);
		break;
	case SICREG_FORMAT_L:
		val = sic_read_node_nbsr_reg(node, offset);
		break;
	default:
		pr_err("Failed to write SIC register (invalid format).\n");
		return 0;
	}

	seq_printf(s, "node: %d reg (0x%X): 0x%X\n", node, offset, val);

	return 0;
}

static void *sicread_seq_start(struct seq_file *s, loff_t *pos)
{
	if (!node_online(*pos))
		*pos = next_online_node(*pos);
	if (*pos == MAX_NUMNODES)
		return 0;
	return (void *)pos;
}

static void *sicread_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	*pos = next_online_node(*pos);
	if (*pos == MAX_NUMNODES)
		return 0;
	return (void *)pos;
}

static void sicread_seq_stop(struct seq_file *s, void *v)
{
}

static const struct seq_operations sicread_seq_ops = {
	.start = sicread_seq_start,
	.next  = sicread_seq_next,
	.stop  = sicread_seq_stop,
	.show  = sicread_seq_show
};

static int sicread_proc_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return seq_open(file, &sicread_seq_ops);
}

static inline void sicread_write_reg(char *str)
{
	int offset, format;
	char format_sym;
	unsigned long flags;

	if (sscanf(str, "0x%X%c\n", &offset, &format_sym) != 2) {
		pr_err("Failed to save SIC register to read (invalid string).\n");
		return;
	}

	switch (format_sym) {
	case 'w':
		format = SICREG_FORMAT_W;
		break;
	case 'l':
	case '\n':
		format = SICREG_FORMAT_L;
		break;
	default:
		pr_err("Failed to save SIC register to read (invalid format).\n");
		return;
	}

	raw_spin_lock_irqsave(&sicreg_lock, flags);
	sicreg_offset = offset;
	sicreg_format = format;
	raw_spin_unlock_irqrestore(&sicreg_lock, flags);
}

static ssize_t sicread_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *ppos)
{
	char sicread_buffer[SICREAD_STR_MAX_SIZE];
	long ret;

	memset(sicread_buffer, 0, sizeof(char) * SICREAD_STR_MAX_SIZE);

	if (count + 1 > SICREAD_STR_MAX_SIZE) {
		pr_err("Failed to save SIC register to read (too long string).\n");
		ret = -EINVAL;
	} else if (copy_from_user(sicread_buffer, buffer,
					min(sizeof(sicread_buffer), count))) {
		pr_err("Failed to save SIC register to read (kernel error).\n");
		ret = -EFAULT;
	} else {
		sicread_write_reg(sicread_buffer);
		ret = count;
	}

	return ret;
}

static const struct proc_ops sicread_proc_ops = {
	.proc_open    = sicread_proc_open,
	.proc_write   = sicread_write,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = seq_release
};


/*
 * SIC write
 */

static inline void sicwrite_write_reg(char *str)
{
	int node, reg, val, res;
	char format_sym, space[2];

	res = sscanf(str, "%d 0x%X%c%1[ ] 0x%X\n",
			&node, &reg, &format_sym, space, &val);
	if (res != 5) {
		res = sscanf(str, "%d 0x%X 0x%X\n", &node, &reg, &val);
		if (res != 3) {
			pr_err("Failed to write SIC register (invalid string).\n");
			return;
		}
		format_sym = 'l';
	}

	if (!node_online(node)) {
		pr_err("Failed to write SIC register (invalid node number).\n");
		return;
	}

	switch (format_sym) {
	case 'w':
		sic_writew_node_nbsr_reg(node, reg, val);
		break;
	case 'l':
		sic_write_node_nbsr_reg(node, reg, val);
		break;
	default:
		pr_err("Failed to write SIC register (invalid format).\n");
		return;
	}
}

static ssize_t sicwrite_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *ppos)
{
	char sicwrite_buffer[SICWRITE_STR_MAX_SIZE];
	long ret;

	memset(sicwrite_buffer, 0, sizeof(char) * SICWRITE_STR_MAX_SIZE);

	if (count + 1 > SICWRITE_STR_MAX_SIZE) {
		pr_err("Failed to write SIC register (too long string).\n");
		ret = -EINVAL;
	} else if (copy_from_user(sicwrite_buffer, buffer, 
				min(sizeof(sicwrite_buffer), count))) {
		pr_err("Failed to write SIC register (kernel error).\n");
		ret = -EFAULT;
	} else {
		sicwrite_write_reg(sicwrite_buffer);
		ret = count;
	}

	return ret;
}

static int sicwrite_proc_show(struct seq_file *s, void *v)
{
	return 0;
}

static int sicwrite_proc_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return single_open(file, sicwrite_proc_show, NULL);
}

static const struct proc_ops sicwrite_proc_ops = {
	.proc_open    = sicwrite_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_write   = sicwrite_write,
	.proc_release = single_release
};


/*
 * Init
 */

static int __init init_procregs(void)
{
	if (HAS_MACHINE_L_SIC) {
		proc_create(SICREAD_FILENAME, S_IRUGO, NULL,
			&sicread_proc_ops);
		proc_create(SICWRITE_FILENAME, S_IRUGO, NULL,
			&sicwrite_proc_ops);
	}

#ifdef CONFIG_E2K
	proc_create(MASREAD_FILENAME, S_IRUGO, NULL, &masread_proc_ops);
	proc_create(MASWRITE_FILENAME, S_IRUGO, NULL, &maswrite_proc_ops);
#endif

	return 0;
}

module_init(init_procregs);
