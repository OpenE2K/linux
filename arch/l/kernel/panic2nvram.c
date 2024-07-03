/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/ioport.h>
#include <linux/mc146818rtc.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/spi/spi.h>
#include <linux/panic2nvram.h>

unsigned int   start_nvram_panic_area;
unsigned int   size_nvram_panic_area = 0;
int (*panic2nvram_read) (unsigned int off, unsigned char *addr, int sz);
void (*panic2nvram_write) (unsigned int off, unsigned char *addr, int sz);
int (*panic2nvram_raw_write) (unsigned int off, unsigned char *addr, int sz);


static unsigned int   cur_nvram_panic = 0;
static u_char output_header[] = "This is nvram panic output\n";
static u_char Output_header[] = "This is nvram panic Output\n";



int inline read_from_nvram(unsigned int off, unsigned char *addr, int sz)
{
	if (panic2nvram_read)
		return panic2nvram_read(off, addr, sz);
	else
		printk("NO panic2nvram_read\n");
	return -1;
}

void inline write_to_nvram(unsigned int off, unsigned char *addr, int sz)
{
	if (!panic2nvram_write) {
		goto no_write;
	}
	if (off < start_nvram_panic_area) {
		goto no_write;
	}
	if (off + sz > start_nvram_panic_area + size_nvram_panic_area) {
		goto no_write;
	}
	panic2nvram_write(off, addr, sz);
	return; 
no_write:
	printk("NO panic2nvram_write =%px, off = 0x%x, sz = 0x%x\n",
		panic2nvram_write, off, sz);
}


static inline int raw_write_to_nvram(u_int off, u_char *addr, int sz)
{
	if (panic2nvram_write) {
		panic2nvram_write(off, addr, sz);
		return sz;
	}
//	if (panic2nvram_raw_write) {
//		return panic2nvram_raw_write(off, addr, sz);
//	}
	return 0;
}


void write_to_nvram_panic_area(const char *str, int len)
{
	if (len + cur_nvram_panic >= size_nvram_panic_area) {
		return;
	}
	if (!cur_nvram_panic) {
		cur_nvram_panic +=
			raw_write_to_nvram(start_nvram_panic_area,
				output_header, strlen(output_header));
	}
	cur_nvram_panic +=
		raw_write_to_nvram(start_nvram_panic_area + cur_nvram_panic,
			(u_char *)str, len);
	
}



static void *nvram_panic_seq_start(struct seq_file *f, loff_t *pos)
{

	/* The pointer we are returning is arbitrary,
	 * it just has to be non-NULL and not IS_ERR
	 * in the success case.
	*/
        return *pos == 0 ? &nvram_panic_seq_start: NULL;
}

static void *nvram_panic_seq_next(struct seq_file *f, void *v, loff_t *pos)
{
	++*pos;
	return nvram_panic_seq_start(f, pos);
}

static void nvram_panic_seq_stop(struct seq_file *f, void *v)
{
	/* Nothing to do */
}

static ssize_t nvram_panic_seq_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	char c;
	unsigned char cc[3];
	if (count == 0) {
		return 0;
	}
	if (get_user(c, buf)) {
		return -EFAULT;
	}
	if (c == 'c') {
		int l;
		long zeroes = 0;
		for (l = 0; l < size_nvram_panic_area; l += sizeof(long)) {
			write_to_nvram(start_nvram_panic_area + l,
				(char *)&zeroes, sizeof(long));
		}
		cur_nvram_panic = 0;
		return count;
	}
	if (c == 'p') {
		panic("This is juct panic call\n");
		return count;
	}
#if 0
	if (c == 't') {
//		int i = 0;
		char c = 'G';
		int s = strlen(output_header);
		cur_nvram_panic = 0;
//		for (i = 0; i < size_nvram_panic_area + s; i += s)
			write_to_nvram(start_nvram_panic_area, &c, 1);
		return count;
	}
#endif
	if (c == 'T') {
		int i = 0;
		int s = strlen(Output_header);
		cur_nvram_panic = 0;
		for (i = 0; i < size_nvram_panic_area + s; i += s)
			write_to_nvram_panic_area(Output_header, s);
		return count;
	}
	if (c == '0') {
		cur_nvram_panic = 0;
		return count;
	}

	cc[0] = c;
	cc[1] = '\n';
	cc[2] = 0;
	write_to_nvram(start_nvram_panic_area + cur_nvram_panic, cc, 3);
	cur_nvram_panic++;

	return count;
//	return -EINVAL;
}
		


int show_nvram_panic(struct seq_file *p, void *v)
{
	char *data = kmalloc(size_nvram_panic_area, GFP_KERNEL);
	char *l;

	if (data == NULL) {
		return -ENOMEM;
	}
	read_from_nvram(start_nvram_panic_area, data, size_nvram_panic_area);
	*(data + size_nvram_panic_area -1) = 0;
//	read_from_nvram(start_nvram_panic_area, data, 32);
//	*(data + 30) = '\n';
//	*(data + 31) = 0;
printk("show_nvram_panic: 0x%08x, 0x%08x, 0x%08x, 0x%08x\n", *((int *)data), *((int *)data+4), *((int *)data+8), *((int *)data+12));
	l = memchr(data, 0, size_nvram_panic_area);
	seq_write(p, data, l - data);
	kfree(data);
	return 0;
}

static const struct seq_operations nvram_panic_seq_ops = {
	.start = nvram_panic_seq_start,
	.next  = nvram_panic_seq_next,
	.stop  = nvram_panic_seq_stop,
	.show  = show_nvram_panic,
};

static int nvram_panic_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &nvram_panic_seq_ops);
}

static const struct proc_ops proc_nvram_panic_operations = {
	.proc_open    = nvram_panic_open,
	.proc_read    = seq_read,
	.proc_write   = nvram_panic_seq_write,
	.proc_lseek   = seq_lseek,
	.proc_release = seq_release,
};

static int __init start_nvram_panic_area_setup(char *str)
{
        start_nvram_panic_area = memparse(str, &str);
        return 1;
}

__setup("panic2nvram-start=", start_nvram_panic_area_setup);


static int __init size_nvram_panic_area_setup(char *str)
{
        size_nvram_panic_area = memparse(str, &str);
        return 1;
}

__setup("panic2nvram-size=", size_nvram_panic_area_setup);


static int  __init nvram_panic_init(void)
{
	char buf[32];
	buf[0] = 0;
	read_from_nvram(start_nvram_panic_area, buf, 32);
	if (!strncmp(buf, output_header, strlen(output_header))) {
		if (proc_create("driver/nvram_panic", S_IWUSR | S_IROTH,
			NULL, &proc_nvram_panic_operations) == NULL) {
			pr_warn("%s: Could not create "
				"/proc/sys/kernel/nvram_panic\n", __func__);
			return -EINVAL;
		}
	}

	return 0;
}

late_initcall(nvram_panic_init);
	

