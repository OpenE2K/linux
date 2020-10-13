/*
 * arch/e2k/kernel/procsic.c
 *
 * This file contains implementation of functions to read and write SIC
 * registers through proc fs.
 *
 * Copyright (C) 2010-2014 Pavel V. Panteleev (panteleev_p@mcst.ru)
 */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/module.h>

#include <asm/uaccess.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>

#define SICREGS_FILENAME	"sicregs"
static struct proc_dir_entry *sicregs_entry;

#define SICWRITE_FILENAME	"sicwrite"
static struct proc_dir_entry *sicwrite_entry;

#define SICWRITE_STR_MAX_SIZE	32

int sicwrite_regs[] = {0x414, 0x454, 0x494};

static void sicregs_print_MC_ECC(struct seq_file *s, int node)
{
	e2k_mc_ecc_struct_t ecc;
	int i;

	for (i = 0; i < SIC_MC_COUNT; i++) {
		ecc.E2K_MC_ECC_reg = sic_get_mc_ecc(node, i);

		seq_printf(s, "\tMC%d_ECC=0x%x (ee=%d dmode=%d of=%d "
			"ue=%d secnt=%d)\n",
			i, ecc.E2K_MC_ECC_reg, ecc.E2K_MC_ECC_ee,
			ecc.E2K_MC_ECC_dmode, ecc.E2K_MC_ECC_of,
			ecc.E2K_MC_ECC_ue, ecc.E2K_MC_ECC_secnt);
	}
}

static void sicregs_print_MC_OPMB(struct seq_file *s, int node)
{
	e2k_mc_opmb_struct_t opmb;
	int i;

	if (IS_MACHINE_E2S || IS_MACHINE_E8C) {
		for (i = 0; i < SIC_MC_COUNT; i++) {
			opmb.E2K_MC_OPMB_reg = sic_get_mc_opmb(node, i);

			seq_printf(s, "\tMC%d_OPMB=0x%x (ct0=%d ct1=%d pbm0=%d "
				"pbm1=%d rm=%d rdodt=%d wrodt=%d bl8int=%d "
				"mi_fast=%d mt=%d il=%d rcven_del=%d mc_ps=%d "
				"arp_en=%d flt_brop=%d flt_rdpr=%d flt_blk=%d "
				"parerr=%d cmdpack=%d sldwr=%d sldrd=%d "
				"mirr=%d twrwr=%d mcln=%d)\n",
				i, opmb.E2K_MC_OPMB_reg, opmb.E2K_MC_OPMB_ct0,
				opmb.E2K_MC_OPMB_ct1, opmb.E2K_MC_OPMB_pbm0,
				opmb.E2K_MC_OPMB_pbm1, opmb.E2K_MC_OPMB_rm,
				opmb.E2K_MC_OPMB_rdodt, opmb.E2K_MC_OPMB_wrodt,
				opmb.E2K_MC_OPMB_bl8int,
				opmb.E2K_MC_OPMB_mi_fast, opmb.E2K_MC_OPMB_mt,
				opmb.E2K_MC_OPMB_il, opmb.E2K_MC_OPMB_rcven_del,
				opmb.E2K_MC_OPMB_mc_ps, opmb.E2K_MC_OPMB_arp_en,
				opmb.E2K_MC_OPMB_flt_brop,
				opmb.E2K_MC_OPMB_flt_rdpr,
				opmb.E2K_MC_OPMB_flt_blk,
				opmb.E2K_MC_OPMB_parerr,
				opmb.E2K_MC_OPMB_cmdpack,
				opmb.E2K_MC_OPMB_sldwr,
				opmb.E2K_MC_OPMB_sldrd, opmb.E2K_MC_OPMB_mirr,
				opmb.E2K_MC_OPMB_twrwr, opmb.E2K_MC_OPMB_mcln);
		}
	}
}

static void sicregs_print_IPCC_CSR(struct seq_file *s, int node)
{
	e2k_ipcc_csr_struct_t ipcc_csr;
	int i;

	if (IS_MACHINE_E2S || IS_MACHINE_E8C) {
		for (i = 1; i < SIC_IPCC_LINKS_COUNT + 1; i++) {
			ipcc_csr.E2K_IPCC_CSR_reg = sic_get_ipcc_csr(node, i);

			seq_printf(s, "\tIPCC_CSR%d=0x%x (link_scale=0x%x "
				"cmd_code=0x%x cmd_active=%d terr_vc_num=0x%x "
				"rx_oflw_uflw=%d event_imsk=0x%x "
				"ltssm_state=0x%x cmd_cmpl_sts=0x%x "
				"link_width=0x%x event_sts=0x%x "
				"link_state=%d)\n",
				i, ipcc_csr.E2K_IPCC_CSR_reg,
				ipcc_csr.E2K_IPCC_CSR_link_scale,
				ipcc_csr.E2K_IPCC_CSR_cmd_code,
				ipcc_csr.E2K_IPCC_CSR_cmd_active,
				ipcc_csr.E2K_IPCC_CSR_terr_vc_num,
				ipcc_csr.E2K_IPCC_CSR_rx_oflw_uflw,
				ipcc_csr.E2K_IPCC_CSR_event_imsk,
				ipcc_csr.E2K_IPCC_CSR_ltssm_state,
				ipcc_csr.E2K_IPCC_CSR_cmd_cmpl_sts,
				ipcc_csr.E2K_IPCC_CSR_link_width,
				ipcc_csr.E2K_IPCC_CSR_event_sts,
				ipcc_csr.E2K_IPCC_CSR_link_state);
		}
	}
}

static void sicregs_print_IPCC_PMR(struct seq_file *s, int node)
{
	e2k_ipcc_pmr_struct_t ipcc_pmr;
	int i;

	if (IS_MACHINE_E2S || IS_MACHINE_E8C) {
		for (i = 1; i < SIC_IPCC_LINKS_COUNT + 1; i++) {
			ipcc_pmr.E2K_IPCC_PMR_reg = sic_get_ipcc_pmr(node, i);

			seq_printf(s, "\tIPCC_PMR%d=0x%x (force_rxdet=%d "
				"ctc_en=%d scramble=%d rcvr_tmrl=0x%x "
				"phle_lmt=%d dlle_lmt=0x%x irqpp=0x%x "
				"crqpp=0x%x drqpp=0x%x)\n",
				i, ipcc_pmr.E2K_IPCC_PMR_reg,
				ipcc_pmr.E2K_IPCC_PMR_force_rxdet,
				ipcc_pmr.E2K_IPCC_PMR_ctc_en,
				ipcc_pmr.E2K_IPCC_PMR_scramble,
				ipcc_pmr.E2K_IPCC_PMR_rcvr_tmrl,
				ipcc_pmr.E2K_IPCC_PMR_phle_lmt,
				ipcc_pmr.E2K_IPCC_PMR_dlle_lmt,
				ipcc_pmr.E2K_IPCC_PMR_irqpp,
				ipcc_pmr.E2K_IPCC_PMR_crqpp,
				ipcc_pmr.E2K_IPCC_PMR_drqpp);
		}
	}
}

static void sicregs_print_IPCC_STR(struct seq_file *s, int node)
{
	e2k_ipcc_str_struct_t ipcc_str;
	int i;

	if (IS_MACHINE_E2S || IS_MACHINE_E8C) {
		for (i = 1; i < SIC_IPCC_LINKS_COUNT + 1; i++) {
			ipcc_str.E2K_IPCC_STR_reg = sic_get_ipcc_str(node, i);

			seq_printf(s, "\tIPCC_STR%d=0x%x (ecnt=0x%x eco=%d "
				"ecf=0x%x)\n",
				i, ipcc_str.E2K_IPCC_STR_reg,
				ipcc_str.E2K_IPCC_STR_ecnt,
				ipcc_str.E2K_IPCC_STR_eco,
				ipcc_str.E2K_IPCC_STR_ecf);
		}
	}
}

static void sicregs_print_IO_CSR(struct seq_file *s, int node)
{
	e2k_io_csr_struct_t io_csr;
	int i;

	if (IS_MACHINE_E3S || IS_MACHINE_ES2 || IS_MACHINE_E2S ||
			IS_MACHINE_E1CP) {
		for (i = 0; i < SIC_IO_LINKS_COUNT; i++) {
			io_csr.E2K_IO_CSR_reg = sic_get_io_csr(node, i);

			if (!i)
				seq_printf(s, "\tIO_CSR");
			else if (IS_MACHINE_E2S)
				seq_printf(s, "\tIO_CSR_HI");
			else
				seq_printf(s, "\tIO_CSR1");

			seq_printf(s, "=0x%x (srst=%d bsy_ie=%d err_ie=%d "
				"to_ie=%d lsc_ie=%d bsy_ev=%d err_ev=%d "
				"to_ev=%d lsc_ev=%d link_tu=%d ch_on=%d)\n",
				io_csr.E2K_IO_CSR_reg,
				io_csr.E2K_IO_CSR_srst,
				io_csr.E2K_IO_CSR_bsy_ie,
				io_csr.E2K_IO_CSR_err_ie,
				io_csr.E2K_IO_CSR_to_ie,
				io_csr.E2K_IO_CSR_lsc_ie,
				io_csr.E2K_IO_CSR_bsy_ev,
				io_csr.E2K_IO_CSR_err_ev,
				io_csr.E2K_IO_CSR_to_ev,
				io_csr.E2K_IO_CSR_lsc_ev,
				io_csr.E2K_IO_CSR_link_tu,
				io_csr.E2K_IO_CSR_ch_on);
		}
	}
}

static void sicregs_print_IO_TMR(struct seq_file *s, int node)
{
	e2k_io_tmr_struct_t io_tmr;
	int i;

	if (IS_MACHINE_E3S || IS_MACHINE_ES2 || IS_MACHINE_E2S ||
			IS_MACHINE_E1CP) {
		for (i = 0; i < SIC_IO_LINKS_COUNT; i++) {
			io_tmr.E2K_IO_TMR_reg = sic_get_io_tmr(node, i);

			if (!i)
				seq_printf(s, "\tIO_TMR");
			else if (IS_MACHINE_E2S)
				seq_printf(s, "\tIO_TMR_HI");
			else
				seq_printf(s, "\tIO_TMR1");

			seq_printf(s, "=0x%x (ptocl=0x%x pbrn=0x%x)\n",
				io_tmr.E2K_IO_TMR_reg,
				io_tmr.E2K_IO_TMR_ptocl,
				io_tmr.E2K_IO_TMR_pbrn);
		}
	}
}

static void sicregs_print_IO_STR(struct seq_file *s, int node)
{
	e2k_io_str_struct_t io_str;
	int i;

	if (IS_MACHINE_E3S || IS_MACHINE_ES2 || IS_MACHINE_E2S ||
			IS_MACHINE_E1CP) {
		for (i = 0; i < SIC_IO_LINKS_COUNT; i++) {
			io_str.E2K_IO_STR_reg = sic_get_io_str(node, i);

			if (!i)
				seq_printf(s, "\tIO_STR");
			else if (IS_MACHINE_E2S)
				seq_printf(s, "\tIO_STR_HI");
			else
				seq_printf(s, "\tIO_STR1");

			seq_printf(s, "=0x%x (rc=0x%x rcol=%d bsy_rce=%d "
				"err_rce=%d to_rce=%d)\n",
				io_str.E2K_IO_STR_reg,
				io_str.E2K_IO_STR_rc,
				io_str.E2K_IO_STR_rcol,
				io_str.E2K_IO_STR_bsy_rce,
				io_str.E2K_IO_STR_err_rce,
				io_str.E2K_IO_STR_to_rce);
		}
	}
}

static void sicregs_print_PL_CSR(struct seq_file *s, int node)
{
	e2k_pl_csr_struct_t pl_csr;
	int i;

	if (IS_MACHINE_E3S || IS_MACHINE_ES2) {
		for (i = 0; i < SIC_CPU_LINKS_COUNT; i++) {
			pl_csr.E2K_PL_CSR_reg = sic_get_pl_csr(node, i);

			seq_printf(s, "\tPL_CSR%d=0x%x (rc=0x%x rcol=%d rce=%d "
				"link_tu=%d ch_on=%d lerr=%d srst=%d)\n",
				i,
				pl_csr.E2K_PL_CSR_reg,
				pl_csr.E2K_PL_CSR_rc,
				pl_csr.E2K_PL_CSR_rcol,
				pl_csr.E2K_PL_CSR_rce,
				pl_csr.E2K_PL_CSR_link_tu,
				pl_csr.E2K_PL_CSR_ch_on,
				pl_csr.E2K_PL_CSR_lerr,
				pl_csr.E2K_PL_CSR_srst);
		}
	}
}

static int sicregs_seq_show(struct seq_file *s, void *v)
{
	int node = *((int *)v);

	seq_printf(s, "node: %d\n", node);

	sicregs_print_MC_ECC(s, node);
	sicregs_print_MC_OPMB(s, node);
	sicregs_print_IPCC_CSR(s, node);
	sicregs_print_IPCC_PMR(s, node);
	sicregs_print_IPCC_STR(s, node);
	sicregs_print_IO_CSR(s, node);
	sicregs_print_IO_TMR(s, node);
	sicregs_print_IO_STR(s, node);
	sicregs_print_PL_CSR(s, node);

	return 0;
}

static void *sicregs_seq_start(struct seq_file *s, loff_t *pos)
{
	if (!node_online(*pos))
		*pos = next_online_node(*pos);
	if (*pos == MAX_NUMNODES)
		return 0;
	return (void *)pos;
}

static void *sicregs_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	*pos = next_online_node(*pos);
	if (*pos == MAX_NUMNODES)
		return 0;
	return (void *)pos;
}

static void sicregs_seq_stop(struct seq_file *s, void *v)
{
}

static const struct seq_operations sicregs_seq_ops = {
	.start = sicregs_seq_start,
	.next  = sicregs_seq_next,
	.stop  = sicregs_seq_stop,
	.show  = sicregs_seq_show
};

static int sicregs_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &sicregs_seq_ops);
}

static const struct file_operations sicregs_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = sicregs_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};

static inline int sicwrite_reg_possible(int reg)
{
	int count = sizeof(sicwrite_regs) / sizeof(int);
	int i = 0;

	for (; i < count; i++)
		if (sicwrite_regs[i] == reg)
			return 1;
	return 0;
}

static inline void sicwrite_write_reg(char *str)
{
	int node, reg, val, res;

	res = sscanf(str, "%d 0x%X 0x%X\n", &node, &reg, &val);
	if (res != 3) {
		pr_err("Failed to write SIC register (invalid string).\n");
		return;
	} else if (!node_online(node)) {
		pr_err("Failed to write SIC register (invalid node number).\n");
		return;
	} else if (!sicwrite_reg_possible(reg)) {
		pr_err("Failed to write SIC register (invalid register).\n");
		return;
	}

	sic_write_node_nbsr_reg(node, reg, val);
}

static ssize_t sicwrite_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *ppos)
{
	char sicwrite_buffer[SICWRITE_STR_MAX_SIZE];
	long  ret;

	memset(sicwrite_buffer, 0, sizeof(char) * SICWRITE_STR_MAX_SIZE);

	if (count + 1 > SICWRITE_STR_MAX_SIZE) {
		pr_err("Failed to write SIC register (too long string).\n");
		ret = -EINVAL;
	} else if (copy_from_user(sicwrite_buffer, buffer, count)) {
		pr_err("Failed to write SIC register (kernel error).\n");
		ret = -EFAULT;
	} else {
		sicwrite_write_reg(sicwrite_buffer);
		ret = count;
	}

	return ret;
}

static int sicwrite_proc_show(struct seq_file *m, void *v)
{
	return 0;
}		

static int sicwrite_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, sicwrite_proc_show, NULL);
}

static const struct file_operations sicwrite_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = sicwrite_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.write   = sicwrite_write,
	.release = seq_release
};

static int __init init_procsic(void)
{
	if (!HAS_MACHINE_L_SIC)
		return 0;

	sicregs_entry = proc_create(SICREGS_FILENAME, S_IRUGO,
				    NULL, &sicregs_proc_fops);
	if (!sicregs_entry)
		return -ENOMEM;

	sicwrite_entry = proc_create(SICWRITE_FILENAME, S_IRUGO,
				     NULL, &sicwrite_proc_fops);
	if (!sicwrite_entry)
		return -ENOMEM;

	return 0;
}

static void __exit exit_procsic(void)
{
	if (HAS_MACHINE_L_SIC) {
		proc_remove(sicregs_entry);
		proc_remove(sicwrite_entry);
	}
}

module_init(init_procsic);
module_exit(exit_procsic);
