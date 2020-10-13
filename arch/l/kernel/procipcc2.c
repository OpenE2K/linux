/*
 * arch/l/kernel/procipcc2.c
 *
 * Support for iplink switching off/on through IPCC2 write
 * available registers. This works for E2K machines, that
 * have SIC on board.
 *
 * Copyright (C) 2014 Evgeny M. Kravtsunov (kravtsunov_e@mcst.ru)
 */

#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/module.h>

#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/uaccess.h>

#define IPLINKMASK_FILENAME	"iplinkmask"
static struct proc_dir_entry	*iplinkmask_entry;

/* LTSSM states */
#define IPCC2_LTSSM_POWEROFF	0x000
#define IPCC2_LTSSM_DISABLE	0x001
#define IPCC2_LTSSM_SLEEP	0x010
#define IPCC2_LTSSM_LINKUP	0x011
#define IPCC2_LTSSM_SERVICE	0x100
#define IPCC2_LTSSM_REINIT	0x101

static ssize_t write_iplinkmask_ipcc2(struct file *file,
		const char __user *buffer, size_t count, loff_t *data)
{
	char val[10];
	int nid;
	e2k_ipcc_csr_struct_t ipcc_csr;
	int i;

	if (copy_from_user(val, buffer, count))
		return -EFAULT;

	nid = cpu_to_node(raw_smp_processor_id());

	for (i = 1; i < SIC_IPCC_LINKS_COUNT + 1; i++) {
		ipcc_csr.E2K_IPCC_CSR_reg = sic_get_ipcc_csr(nid, i);
		if (val[0] == '0') {
			/* Switch off iplinks (power off) */
			ipcc_csr.E2K_IPCC_CSR_cmd_code = IPCC2_LTSSM_POWEROFF;
		} else if (val[0] == '1') {
			/* Switch off iplinks (disable) */
			ipcc_csr.E2K_IPCC_CSR_cmd_code = IPCC2_LTSSM_DISABLE;
		} else if (val[0] == '2') {
			/* Switch off iplinks (sleep) */
			ipcc_csr.E2K_IPCC_CSR_cmd_code = IPCC2_LTSSM_SLEEP;
		} else {
			/* Reinit iplinks */
			ipcc_csr.E2K_IPCC_CSR_cmd_code = IPCC2_LTSSM_REINIT;
		}
		sic_set_ipcc_csr(nid, i, ipcc_csr.E2K_IPCC_CSR_reg);
	}

	return count;
}

static int iplinkmask_proc_show(struct seq_file *m, void *data)
{
	/* Not implemented */
	return 0;
}

static int iplinkmask_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, iplinkmask_proc_show, NULL);
}

static const struct file_operations iplinkmask_proc_fops = {
	.open    = iplinkmask_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = write_iplinkmask_ipcc2
};

static int __init init_procipcc2(void)
{
	if (IS_MACHINE_E2S) {
		iplinkmask_entry = proc_create(IPLINKMASK_FILENAME,
					S_IFREG | S_IWUGO, NULL,
					&iplinkmask_proc_fops);
		if (!iplinkmask_entry)
			return -ENOMEM;
	}

	return 0;
}
module_init(init_procipcc2);

static void __exit exit_procipcc2(void)
{
	if (IS_MACHINE_E2S) {
		proc_remove(iplinkmask_entry);
	}
}
module_exit(exit_procipcc2);

