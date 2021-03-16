/*
 * arch/l/kernel/procmmpddiag.c
 *
 * Support for 32-bit mmpd test and diag status value.
 * 32-bit value is stored in kernel's ram and available
 * for reading and writing from userspace (from init and FPO)
 * through /proc/mmpddiag interface.
 *
 * Copyright (C) 2014 Evgeny M. Kravtsunov (kravtsunov_e@mcst.ru)
 */

#include <linux/proc_fs.h>
#include <linux/module.h>
#include <asm/uaccess.h>

#define MMPDDIAG_FILENAME	"mmpddiag"
static struct proc_dir_entry	*dir_mmpddiag;

/* mmpdstatus value format:
 *
 * bit 0: 1 - was hw reset; 0 - was sw reset;
 * bit 1: 1/0 - mem test passed/failed;
 * bit 2: 1/0 - cpu test passed/failed;
 * bits 3-31: reserved
 *
 */
static uint32_t mmpdstatus = 0;

/* Status bits */
#define MMPD_RESET_HW	0x00000001
#define MMPD_MEM_BIT	0x00000002
#define MMPD_CPU_BIT	0x00000004

static ssize_t write_mmpddiag(struct file *file, const char *buf,
					size_t len, loff_t *off)
{
	char val[10] = {0};
	ssize_t ret = 0;
	ret = simple_write_to_buffer(&val, sizeof(val),
					off, buf, sizeof(val));
	if (ret < 0)
		return -EINVAL;
	/*
	* 000(bin) = 0(val): SW reset ("hot start"), no tests
	* 001(bin) = 1(val): HW reset, tests mem and cpu failed
	* 011(bin) = 3(val): HW reset, test mem passed, test cpu failed
	* 111(bin) = 7(val): HW reset, test mem passed, test cpu passed
	*/
	if (val[0] == '0') {
		/* SW reset ("hot start"), no tests */
		mmpdstatus = 0;
	} else if (val[0] == '1') {
		/* HW reset, tests mem and cpu failed */
		mmpdstatus = MMPD_RESET_HW;
	} else if (val[0] == '3') {
		/* HW reset, test mem passed, test cpu failed */
		mmpdstatus = (MMPD_MEM_BIT | MMPD_RESET_HW);
	} else if (val[0] == '5') {
		/* HW reset, test cpu passed, test mem failed */
		mmpdstatus = (MMPD_CPU_BIT | MMPD_RESET_HW);
	} else if (val[0] == '7') {
		/* HW reset, test mem passed, test cpu failed */
		mmpdstatus = (MMPD_CPU_BIT | MMPD_MEM_BIT | MMPD_RESET_HW);
	} else {
		/* Invalid case */
		return -EFAULT;
	}
	return ret;
}

static ssize_t read_mmpddiag(struct file *file, char *buf, size_t len,
								loff_t *off)
{
	return simple_read_from_buffer(buf, len, off, &mmpdstatus,
							sizeof(mmpdstatus));
}


static const struct file_operations mmpddiag_proc_fops = {
	.owner = THIS_MODULE,
	.read = read_mmpddiag,
	.write = write_mmpddiag,
};

static int __init init_mmpddiag(void)
{
	dir_mmpddiag = proc_create(MMPDDIAG_FILENAME,
			S_IFREG | S_IWUGO | S_IRUGO, NULL, &mmpddiag_proc_fops);

	if (!dir_mmpddiag)
		return -ENOMEM;
	return 0;
}

static void __exit exit_mmpddiag(void)
{
	remove_proc_entry(MMPDDIAG_FILENAME, NULL);
}
module_init(init_mmpddiag);
module_exit(exit_mmpddiag);

