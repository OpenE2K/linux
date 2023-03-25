/*
 * arch/e2k/kernel/procsic.c
 *
 * This file contains implementation of functions to read and write hw
 * registers through proc fs.
 *
 * Copyright (C) 2010-2018 Pavel V. Panteleev (panteleev_p@mcst.ru)
 */

#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <asm/sic_regs.h>
#ifdef CONFIG_E2K
#include <asm/sic_regs_access.h>
#endif


#define L2READ_FILENAME		"l2cacheread"
#define L2WRITE_FILENAME	"l2cahcewrite"
#define SICREAD_FILENAME	"sicread"
#define SICWRITE_FILENAME	"sicwrite"
#define LDRD_FILENAME		"ldrd"

#define L2READ_STR_MAX_SIZE	32
#define L2WRITE_STR_MAX_SIZE	64
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
static atomic64_t l2addr;

/*
 * Use KERNEL_BASE as default for ldrd_val to prevent panic due sporadic access
 * from stupid user utilities
 */
static atomic64_t ldrd_val = ATOMIC_INIT(KERNEL_BASE);


/*
 * L2 cache register read
 */

static int l2read_proc_show(struct seq_file *s, void *v)
{
	u64 val = NATIVE_READ_MAS_D(atomic64_read(&l2addr), MAS_DCACHE_L2_REG);

	seq_printf(s, "0x%llx", val);

	return 0;
}

static int l2read_proc_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return single_open(file, l2read_proc_show, NULL);
}

static inline void l2read_write_reg(char *str)
{
	u64 addr;
	int res;

	res = sscanf(str, "0x%llX\n", &addr);
	if (res != 1) {
		pr_err("Failed to save L2 cache address to read (invalid string).\n");
		return;
	}

	atomic64_set(&l2addr, addr);
}

static ssize_t l2read_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *ppos)
{
	char l2read_buffer[L2READ_STR_MAX_SIZE];
	long ret;

	memset(l2read_buffer, 0, sizeof(char) * L2READ_STR_MAX_SIZE);

	if (count > L2READ_STR_MAX_SIZE - 1) {
		pr_err("Failed to save L2 cache address to read (too long string).\n");
		ret = -EINVAL;
	} else if (copy_from_user(l2read_buffer, buffer, count)) {
		pr_err("Failed to save L2 cache address to read (kernel error).\n");
		ret = -EFAULT;
	} else {
		l2read_write_reg(l2read_buffer);
		ret = count;
	}

	return ret;
}

static const struct file_operations l2read_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = l2read_proc_open,
	.write   = l2read_write,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release
};


/*
 * L2 cache register write
 */

static inline void l2write_write_reg(char *str)
{
	u64 addr, val;
	int res;

	res = sscanf(str, "0x%llX 0x%llX\n", &addr, &val);
	if (res != 2) {
		pr_err("Failed to write L2 cache address (invalid string).\n");
		return;
	}

	NATIVE_WRITE_MAS_D(addr, val, MAS_DCACHE_L2_REG);
}

static ssize_t l2write_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *ppos)
{
	char l2write_buffer[SICWRITE_STR_MAX_SIZE];
	long ret;

	memset(l2write_buffer, 0, sizeof(char) * L2WRITE_STR_MAX_SIZE);

	if (count + 1 > L2WRITE_STR_MAX_SIZE) {
		pr_err("Failed to write L2 cache address (too long string).\n");
		ret = -EINVAL;
	} else if (copy_from_user(l2write_buffer, buffer, count)) {
		pr_err("Failed to write L2 cache address (kernel error).\n");
		ret = -EFAULT;
	} else {
		l2write_write_reg(l2write_buffer);
		ret = count;
	}

	return ret;
}

static int l2write_proc_show(struct seq_file *s, void *v)
{
	return 0;
}

static int l2write_proc_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return single_open(file, l2write_proc_show, NULL);
}

static const struct file_operations l2write_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = l2write_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.write   = l2write_write,
	.release = single_release
};


/*
 * LDRD read
 */

static int ldrd_proc_show(struct seq_file *s, void *v)
{
	seq_printf(s, "0x%lx", LDRD(atomic64_read(&ldrd_val)));
	return 0;
}

static int ldrd_proc_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return single_open(file, ldrd_proc_show, NULL);
}

static inline void ldrd_write_reg(char *str)
{
	int ldrd, res;

	res = sscanf(str, "0x%X\n", &ldrd);
	if (res != 1) {
		pr_err("Failed to save LDRD value (invalid string).\n");
		return;
	}

	atomic64_set(&ldrd_val, ldrd);
}

static ssize_t ldrd_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *ppos)
{
	char ldrd_buffer[LDRD_STR_MAX_SIZE];
	long ret;

	memset(ldrd_buffer, 0, sizeof(char) * LDRD_STR_MAX_SIZE);

	if (count > LDRD_STR_MAX_SIZE - 1) {
		pr_err("Failed to save LDRD value (too long string).\n");
		ret = -EINVAL;
	} else if (copy_from_user(ldrd_buffer, buffer, count)) {
		pr_err("Failed to save LDRD value (kernel error).\n");
		ret = -EFAULT;
	} else {
		ldrd_write_reg(ldrd_buffer);
		ret = count;
	}

	return ret;
}

static const struct file_operations ldrd_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = ldrd_proc_open,
	.write   = ldrd_write,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release
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

static const struct file_operations sicread_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = sicread_proc_open,
	.write   = sicread_write,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
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

static const struct file_operations sicwrite_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = sicwrite_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.write   = sicwrite_write,
	.release = single_release
};


/*
 * Init
 */

static int __init init_procregs(void)
{
	if (HAS_MACHINE_L_SIC) {
		proc_create(SICREAD_FILENAME, S_IRUGO, NULL,
			&sicread_proc_fops);
		proc_create(SICWRITE_FILENAME, S_IRUGO, NULL,
			&sicwrite_proc_fops);
	}

#ifdef CONFIG_E2K
	proc_create(L2READ_FILENAME, S_IRUGO, NULL, &l2read_proc_fops);
	proc_create(L2WRITE_FILENAME, S_IRUGO, NULL, &l2write_proc_fops);
	proc_create(LDRD_FILENAME, S_IRUGO, NULL, &ldrd_proc_fops);
#endif

	return 0;
}

module_init(init_procregs);
