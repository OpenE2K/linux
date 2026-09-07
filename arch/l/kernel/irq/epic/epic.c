/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <linux/syscore_ops.h>

#include "epic.h"
#include <asm/pic.h>
#include "../pic.h"

/* Enable CEPIC debugging from kernel cmdline */
bool epic_debug = false;

bool epic_bgi_mode;

/*
 * EPIC Masked interrupt handling starts with reading CEPIC_VECT_INTA.
 * Value read from CEPIC_VECT_INTA also contains Core Priority bits,
 * which have to be saved to be written to CEPIC_EOI later
 */
int epic_get_vector(void)
{
	union cepic_vect_inta reg;

	reg.raw = epic_read_w(CEPIC_VECT_INTA);

	set_current_epic_core_priority(reg.cpr);

	return reg.vect;
}

/* Core priority is read from CEPIC_VECT_INTA in native_do_interrupt */
void ack_epic_irq(void)
{
	union cepic_eoi reg;
	BUG_ON(!cpu_has_epic());
	reg.raw = 0;
	reg.rcpr = get_current_epic_core_priority();
	epic_write_w(CEPIC_EOI, reg.raw);
}

#ifdef CONFIG_SMP
bool epic_check_vector_to_be_cleaned(unsigned vector)
{
	unsigned int irr;
	/*
	* Paranoia: Check if the vector that needs to be cleaned
	* up is registered at the APICs IRR. If so, then this is
	* not the best time to clean it up. Clean it up in the
	* next attempt by sending another IRQ_MOVE_CLEANUP_VECTOR
	* to this CPU. IRQ_MOVE_CLEANUP_VECTOR is the lowest
	* priority external vector, so on return from this
	* interrupt the device interrupt will happen first.
	*/
	irr = epic_read_w(CEPIC_PMIRR + vector / 32 * 0x4);
	if (irr & (1U << (vector % 32))) {
		epic_send_IPI_self(irq_move_cleanup_vector);
		return true;
	}
	return false;
}
#endif
/*
 * E2K depends on the "hard" cpu number to determine NUMA node,
 * so we must exclude the influence of the order in which all
 * processors get here.
 */
int __init epic_processor_info(int epicid, int version, unsigned int cepic_freq)
{
	unsigned int bsp_id = read_epic_id();
	bool boot_cpu_detected = physid_isset(bsp_id, phys_cpu_present_map);
	int cpu;
	static unsigned int epic_num_processors;

	boot_cpu_physical_apicid = bsp_id;

	/*
	 * If boot cpu has not been detected yet, then only allow upto
	 * nr_cpu_ids - 1 processors and keep one slot free for boot cpu
	 */
	if (!boot_cpu_detected && epic_num_processors >= nr_cpu_ids - 1 &&
	    epicid != bsp_id) {
		pr_warn("NR_CPUS=%d limit was reached", nr_cpu_ids);
		pr_warn("Ignoring CPU#%d to keep a slot for boot CPU", epicid);
		return -EEXIST;
	}

	if (epic_num_processors >= nr_cpu_ids) {
		pr_warn("NR_CPUS=%d limit was reached", nr_cpu_ids);
		pr_warn("Ignoring CPU#%d", epicid);
		return -EOVERFLOW;
	}

	epic_num_processors++;

	if (epicid == boot_cpu_physical_apicid) {
		/* Logical cpuid 0 is reserved for BSP. */
		cpu = 0;
		cpuid_to_picid[0] = epicid;
	} else {
		cpu = allocate_logical_cpuid(epicid);
	}

	if (epicid >= MAX_PHYSID_NUM)
		panic("EPIC id from MP table exceeds %d\n", MAX_PHYSID_NUM);

	physid_set(epicid, phys_cpu_present_map);

	early_per_cpu(cpu_to_picid, cpu) = epicid;

	set_cpu_possible(cpu, true);
	set_cpu_present(cpu, true);

	if (cepic_freq) {
		pr_info_once("EPIC timer frequency is %d.%d MHz\n",
			cepic_freq / 1000000, cepic_freq % 1000000 / 100000);
		cepic_timer_freq = cepic_freq;
	}

	return cpu;
}

static int __init epic_set_bgi_mode(char *arg)
{
	epic_bgi_mode = true;
	return 0;
}
early_param("epic_bgi_mode", epic_set_bgi_mode);

/* Stop generating timer interrupts and mask them */
static int cepic_timer_shutdown(struct clock_event_device *evt)
{
	union cepic_timer_lvtt reg;

	reg.raw = epic_read_w(CEPIC_TIMER_LVTT);
	reg.mask = 1;
	epic_write_w(CEPIC_TIMER_LVTT, reg.raw);
	epic_write_w(CEPIC_TIMER_INIT, 0);

	return 0;
}

#ifdef CONFIG_PM

struct cepic_timer {
	u32 lvtt;
	u32 init;
	u32 cur;
	u32 div;
};

static struct {
	u32 id;
	u32 cpr;
	u32 svr;
	struct cepic_timer timer;
	struct cepic_timer nm_timer;
} cepic_pm_state;

static int cepic_suspend(void)
{
	union cepic_ctrl reg_ctrl;
	unsigned long flags;

	local_irq_save(flags);

	cepic_pm_state.id = epic_read_w(CEPIC_ID);
	cepic_pm_state.cpr = epic_read_w(CEPIC_CPR);
	cepic_pm_state.svr = epic_read_w(CEPIC_SVR);
	cepic_pm_state.timer = (struct cepic_timer) {
		.lvtt = epic_read_w(CEPIC_TIMER_LVTT),
		.init = epic_read_w(CEPIC_TIMER_INIT),
		.cur = epic_read_w(CEPIC_TIMER_CUR),
		.div = epic_read_w(CEPIC_TIMER_DIV),
	};
	cepic_pm_state.nm_timer = (struct cepic_timer) {
		.lvtt = epic_read_w(CEPIC_NM_TIMER_LVTT),
		.init = epic_read_w(CEPIC_NM_TIMER_INIT),
		.cur = epic_read_w(CEPIC_NM_TIMER_CUR),
		.div = epic_read_w(CEPIC_NM_TIMER_DIV),
	};

	/* Disable CEPIC */
	reg_ctrl.raw = epic_read_w(CEPIC_CTRL);
	reg_ctrl.soft_en = 0;
	epic_write_w(CEPIC_CTRL, reg_ctrl.raw);

	local_irq_restore(flags);

	return 0;
}

static void cepic_resume(void)
{
	union cepic_ctrl reg_ctrl;
	unsigned long flags;

	local_irq_save(flags);

	epic_write_w(CEPIC_ID, cepic_pm_state.id);
	epic_write_w(CEPIC_CPR, cepic_pm_state.cpr);
	epic_write_w(CEPIC_SVR, cepic_pm_state.svr);
	epic_write_w(CEPIC_TIMER_LVTT, cepic_pm_state.timer.lvtt);
	epic_write_w(CEPIC_TIMER_INIT, cepic_pm_state.timer.init);
	epic_write_w(CEPIC_TIMER_CUR, cepic_pm_state.timer.cur);
	epic_write_w(CEPIC_TIMER_DIV, cepic_pm_state.timer.div);
	epic_write_w(CEPIC_NM_TIMER_LVTT, cepic_pm_state.nm_timer.lvtt);
	epic_write_w(CEPIC_NM_TIMER_INIT, cepic_pm_state.nm_timer.init);
	epic_write_w(CEPIC_NM_TIMER_CUR, cepic_pm_state.nm_timer.cur);
	epic_write_w(CEPIC_NM_TIMER_DIV, cepic_pm_state.nm_timer.div);

	/* Enable CEPIC */
	reg_ctrl.raw = epic_read_w(CEPIC_CTRL);
	reg_ctrl.soft_en = 1;
	epic_write_w(CEPIC_CTRL, reg_ctrl.raw);

	local_irq_restore(flags);
}

static struct syscore_ops cepic_syscore_ops = {
	.resume		= cepic_resume,
	.suspend	= cepic_suspend,
};

static int __init init_cepic_ops(void)
{
	if (cpu_has_epic())
		register_syscore_ops(&cepic_syscore_ops);

	return 0;
}

/* cepic needs to resume before other devices access its registers. */
core_initcall(init_cepic_ops);
#endif	/* CONFIG_PM */

void cepic_disable(void)
{
	union cepic_ctrl reg_ctrl;

	cepic_timer_shutdown(NULL);

	/* Disable CEPIC */
	reg_ctrl.raw = epic_read_w(CEPIC_CTRL);
	reg_ctrl.soft_en = 0;
	epic_write_w(CEPIC_CTRL, reg_ctrl.raw);
}

void cpuinfo_epic(struct seq_file *m)
{
	if (cpu_has(CPU_FEAT_EPIC)) {
		seq_printf(m, " epic=%lu", cepic_timer_freq);
	}
}

unsigned int get_irr_epic(unsigned int vector)
{
	return epic_read_w(CEPIC_PMIRR + vector / 32 * 0x4);
}
