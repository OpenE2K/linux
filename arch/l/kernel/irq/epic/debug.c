#include <linux/printk.h>
#include <asm/nmi.h>

#include "epic.h"

struct saved_cepic_regs {
	bool valid;
	u32 cepic_id;
	u32 cepic_cpr;
	u32 cepic_esr;
	u32 cepic_esr2;
	u32 cepic_cir;
	u64 cepic_pmirr[CEPIC_PMIRR_NR_DREGS];
	u32 cepic_pnmirr_mask;
	u32 cepic_icr;
	u32 cepic_icr2;
	u32 cepic_timer_lvtt;
	u32 cepic_timer_init;
	u32 cepic_timer_cur;
	u32 cepic_timer_div;
	u32 cepic_nm_timer_lvtt;
	u32 cepic_nm_timer_init;
	u32 cepic_nm_timer_cur;
	u32 cepic_nm_timer_div;
	u32 cepic_svr;
};

static __cold void save_cepic(void *cepic_regs)
{
	struct saved_cepic_regs *regs = cepic_regs;

	regs->cepic_id = epic_read_w(CEPIC_ID);
	regs->cepic_cpr = epic_read_w(CEPIC_CPR);
	regs->cepic_esr = epic_read_w(CEPIC_ESR);
	regs->cepic_esr2 = epic_read_w(CEPIC_ESR2);

	/* CEPIC_EOI is write-only */

	regs->cepic_cir = epic_read_w(CEPIC_CIR);
	for (int i = 0; i < CEPIC_PMIRR_NR_DREGS; i++) {
		regs->cepic_pmirr[i] = epic_read_d(CEPIC_PMIRR + i * 8);
	}

	/* Reading CEPIC_PNMIRR starts NMI handling */

	regs->cepic_pnmirr_mask = epic_read_w(CEPIC_PNMIRR_MASK);
	regs->cepic_icr = epic_read_w(CEPIC_ICR);
	regs->cepic_icr2 = epic_read_w(CEPIC_ICR2);
	regs->cepic_timer_lvtt = epic_read_w(CEPIC_TIMER_LVTT);
	regs->cepic_timer_init = epic_read_w(CEPIC_TIMER_INIT);
	regs->cepic_timer_cur = epic_read_w(CEPIC_TIMER_CUR);
	regs->cepic_timer_div = epic_read_w(CEPIC_TIMER_DIV);
	regs->cepic_nm_timer_lvtt = epic_read_w(CEPIC_NM_TIMER_LVTT);
	regs->cepic_nm_timer_init = epic_read_w(CEPIC_NM_TIMER_INIT);
	regs->cepic_nm_timer_cur = epic_read_w(CEPIC_NM_TIMER_CUR);
	regs->cepic_nm_timer_div = epic_read_w(CEPIC_NM_TIMER_DIV);
	regs->cepic_svr = epic_read_w(CEPIC_SVR);

	regs->valid = true;
}

static __cold void print_saved_cepic(int cpu, struct saved_cepic_regs *regs)
{
	if (!regs->valid)
		return;

	pr_info("Printing CEPIC contents on CPU#%d:\n", cpu);
	pr_info("... CEPIC_ID: 0x%x\n", regs->cepic_id);
	pr_info("... CEPIC_CPR: 0x%x\n", regs->cepic_cpr);
	pr_info("... CEPIC_ESR: 0x%x\n", regs->cepic_esr);
	pr_info("... CEPIC_ESR2: 0x%x\n", regs->cepic_esr2);

	/* CEPIC_EOI is write-only */

	pr_info("... CEPIC_CIR: 0x%x\n", regs->cepic_cir);
	for (int i = 0; i < CEPIC_PMIRR_NR_DREGS; i++) {
		pr_info("... CEPIC_PMIRR[%d]: 0x%llx\n", i, regs->cepic_pmirr[i]);
	}

	/* Reading CEPIC_PNMIRR starts NMI handling */

	pr_info("... CEPIC_PNMIRR_MASK: 0x%x\n", regs->cepic_pnmirr_mask);
	pr_info("... CEPIC_ICR: 0x%x\n", regs->cepic_icr);
	pr_info("... CEPIC_ICR2: 0x%x\n", regs->cepic_icr2);
	pr_info("... CEPIC_TIMER_LVTT: 0x%x\n", regs->cepic_timer_lvtt);
	pr_info("... CEPIC_TIMER_INIT: 0x%x\n", regs->cepic_timer_init);
	pr_info("... CEPIC_TIMER_CUR: 0x%x\n", regs->cepic_timer_cur);
	pr_info("... CEPIC_TIMER_DIV: 0x%x\n", regs->cepic_timer_div);
	pr_info("... CEPIC_NM_TIMER_LVTT: 0x%x\n",
			regs->cepic_nm_timer_lvtt);
	pr_info("... CEPIC_NM_TIMER_INIT: 0x%x\n",
			regs->cepic_nm_timer_init);
	pr_info("... CEPIC_NM_TIMER_CUR: 0x%x\n", regs->cepic_nm_timer_cur);
	pr_info("... CEPIC_NM_TIMER_DIV: 0x%x\n", regs->cepic_nm_timer_div);
	pr_info("... CEPIC_SVR: 0x%x\n", regs->cepic_svr);
}

__cold void print_cepic(void)
{
	unsigned int v;

	pr_info("Printing CEPIC contents on CPU#%d:\n",
		smp_processor_id());
	v = epic_read_w(CEPIC_ID);
	pr_info("... CEPIC_ID: 0x%x\n", v);

	v = epic_read_w(CEPIC_CPR);
	pr_info("... CEPIC_CPR: 0x%x\n", v);

	v = epic_read_w(CEPIC_ESR);
	pr_info("... CEPIC_ESR: 0x%x\n", v);

	v = epic_read_w(CEPIC_ESR2);
	pr_info("... CEPIC_ESR2: 0x%x\n", v);

	/* CEPIC_EOI is write-only */

	v = epic_read_w(CEPIC_CIR);
	pr_info("... CEPIC_CIR: 0x%x\n", v);

	/* Reading CEPIC_PNMIRR starts NMI handling */

	v = epic_read_w(CEPIC_ICR);
	pr_info("... CEPIC_ICR: 0x%x\n", v);

	v = epic_read_w(CEPIC_ICR2);
	pr_info("... CEPIC_ICR2: 0x%x\n", v);

	v = epic_read_w(CEPIC_TIMER_LVTT);
	pr_info("... CEPIC_TIMER_LVTT: 0x%x\n", v);

	v = epic_read_w(CEPIC_TIMER_INIT);
	pr_info("... CEPIC_TIMER_INIT: 0x%x\n", v);

	v = epic_read_w(CEPIC_TIMER_CUR);
	pr_info("... CEPIC_TIMER_CUR: 0x%x\n", v);

	v = epic_read_w(CEPIC_TIMER_DIV);
	pr_info("... CEPIC_TIMER_DIV: 0x%x\n", v);

	v = epic_read_w(CEPIC_NM_TIMER_LVTT);
	pr_info("... CEPIC_NM_TIMER_LVTT: 0x%x\n", v);

	v = epic_read_w(CEPIC_NM_TIMER_INIT);
	pr_info("... CEPIC_NM_TIMER_INIT: 0x%x\n", v);

	v = epic_read_w(CEPIC_NM_TIMER_CUR);
	pr_info("... CEPIC_NM_TIMER_CUR: 0x%x\n", v);

	v = epic_read_w(CEPIC_NM_TIMER_DIV);
	pr_info("... CEPIC_NM_TIMER_DIV: 0x%x\n", v);

	v = epic_read_w(CEPIC_SVR);
	pr_info("... CEPIC_SVR: 0x%x\n", v);

	v = epic_read_w(CEPIC_PNMIRR_MASK);
	pr_info("... CEPIC_PNMIRR_MASK: 0x%x\n", v);
}

static __cold void print_prepics(void)
{
	int node;
	unsigned int v;

	for_each_online_node(node) {
		pr_info("Printing PREPIC#%d:\n", node);

		v = prepic_node_read_w(node, SIC_prepic_version);
		pr_info("... PREPIC_VERSION: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_ctrl);
		pr_info("... PREPIC_CTRL: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_id);
		pr_info("... PREPIC_ID: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_ctrl2);
		pr_info("... PREPIC_CTRL2: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_err_int);
		pr_info("... PREPIC_ERR_INT: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_linp0);
		pr_info("... PREPIC_LINP0: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_linp1);
		pr_info("... PREPIC_LINP1: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_linp2);
		pr_info("... PREPIC_LINP2: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_linp3);
		pr_info("... PREPIC_LINP3: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_linp4);
		pr_info("... PREPIC_LINP4: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_linp5);
		pr_info("... PREPIC_LINP5: 0x%x\n", v);
	}
}

void __cold print_epics(void)
{
	int cpu;

	preempt_disable();
	for_each_online_cpu(cpu) {
		struct saved_cepic_regs regs;

		if (cpu == smp_processor_id()) {
			print_cepic();
			continue;
		}

		regs.valid = false;
		/* This function can be called through SysRq under
		 * disabled interrupts, so we have to be careful
		 * and use nmi_call_function() with a timeout
		 * instead of smp_call_function(). */
		nmi_call_function_single(cpu, save_cepic, &regs, 1, 30000);
		if (regs.valid)
			print_saved_cepic(cpu, &regs);
	}
	preempt_enable();

	print_prepics();
}