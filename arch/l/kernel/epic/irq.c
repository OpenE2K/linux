/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/seq_file.h>
#include <linux/types.h>
#include <linux/sysfs.h>
#include <linux/cpu.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <asm/irq_regs.h>

#include <trace/events/irq.h>

#include <asm/epic.h>
#include <asm/console.h>
#include <asm/hw_irq.h>
#include <asm/io_apic.h>
#include <asm/nmi.h>

#include <asm-l/l_timer.h>

__init_recv
void epic_init_system_handlers_table(void)
{
	/*
	 * Initialize interrupt[] array of system interrupts' handlers.
	 */

#ifdef CONFIG_SMP
	/*
	 * The reschedule interrupt is a CPU-to-CPU reschedule-helper
	 * IPI, driven by wakeup.
	 */
	setup_PIC_vector_handler(EPIC_RESCHEDULE_VECTOR,
			epic_smp_reschedule_interrupt, 1,
			"epic_smp_reschedule_interrupt");

	/* IPI for generic function call */
	setup_PIC_vector_handler(EPIC_CALL_FUNCTION_VECTOR,
			epic_smp_call_function_interrupt, 1,
			"epic_smp_call_function_interrupt");

	/* IPI for generic single function call */
	setup_PIC_vector_handler(EPIC_CALL_FUNCTION_SINGLE_VECTOR,
			epic_smp_call_function_single_interrupt, 1,
			"epic_smp_call_function_single_interrupt");

	/* Low priority IPI to cleanup after moving an irq (IOAPIC) */
	setup_PIC_vector_handler(IRQ_MOVE_CLEANUP_VECTOR,
			epic_smp_irq_move_cleanup_interrupt, 0,
			"epic_smp_irq_move_cleanup_interrupt");
#endif
	/* self generated IPI for CEPIC timer */
	setup_PIC_vector_handler(CEPIC_TIMER_VECTOR,
			epic_smp_timer_interrupt, 1,
			"epic_smp_timer_interrupt");

	/* IPI vectors for EPIC spurious and error interrupts */
	setup_PIC_vector_handler(SPURIOUS_EPIC_VECTOR,
			epic_smp_spurious_interrupt, 1,
			"epic_smp_spurious_interrupt");
	setup_PIC_vector_handler(ERROR_EPIC_VECTOR,
			epic_smp_error_interrupt, 1,
			"epic_smp_error_interrupt");

	setup_PIC_vector_handler(EPIC_IRQ_WORK_VECTOR,
			epic_smp_irq_work_interrupt, 1,
			"epic_smp_irq_work_interrupt");

	/* PREPIC error handler */
	setup_PIC_vector_handler(PREPIC_ERROR_VECTOR,
			prepic_smp_error_interrupt, 1,
			"prepic_error_interrupt");

	/* IPI delivery to inactive guest (virtualization only) */
	setup_PIC_vector_handler(CEPIC_EPIC_INT_VECTOR,
			cepic_epic_interrupt, 1,
			"cepic_epic_interrupt");

#ifdef CONFIG_KVM_ASYNC_PF
	if (IS_HV_GM()) {
		setup_PIC_vector_handler(ASYNC_PF_WAKE_VECTOR,
				epic_pv_apf_wake, 1,
				"async_pf_wake_interrupt");
	}
#endif /* CONFIG_KVM_ASYNC_PF */

#ifdef CONFIG_E2K
	/* PREPIC LINP handlers */
	setup_PIC_vector_handler(LINP0_INTERRUPT_VECTOR,
			epic_hc_emerg_interrupt, 1,
			"hc_emerg_interrupt");

	setup_PIC_vector_handler(LINP1_INTERRUPT_VECTOR,
			e2k_iommu_error_interrupt, 1,
			"iommu_interrupt");

	setup_PIC_vector_handler(LINP2_INTERRUPT_VECTOR,
			epic_uncore_interrupt, 1,
			"uncore_interrupt");

	setup_PIC_vector_handler(LINP3_INTERRUPT_VECTOR,
			epic_ipcc_interrupt, 1,
			"ipcc_interrupt");

	setup_PIC_vector_handler(LINP4_INTERRUPT_VECTOR,
			epic_hc_interrupt, 1,
			"hc_interrupt");

	setup_PIC_vector_handler(LINP5_INTERRUPT_VECTOR,
			epic_pcs_interrupt, 1,
			"pcs_interrupt");
#endif
}

static void unknown_nmi_error(unsigned int reason, struct pt_regs *regs)
{
	pr_warn("NMI received for unknown reason %x on CPU %d.\n",
			reason, smp_processor_id());
}

noinline notrace void epic_do_nmi(struct pt_regs *regs)
{
	union cepic_pnmirr reason;
#ifdef CONFIG_EARLY_PRINTK
	int console_switched;
#endif

	reason.raw = epic_read_w(CEPIC_PNMIRR);

	/*
	 * Immediately allow receiving of next NM interrupts.
	 * Must be done before handling to avoid losing interrupts like this:
	 *
	 * cpu0			cpu1
	 * --------------------------------------------
	 *			set flag for cpu 0
	 *			and send an NMI
	 * enter handler and
	 * clear the flag
	 *			because flag is cleared,
	 *			set it again and send
	 *			the next NMI
	 * clear CEPIC_PNMIRR
	 *
	 * In this example cpu0 will never receive the second NMI.
	 */
	epic_write_w(CEPIC_PNMIRR, CEPIC_PNMIRR_BIT_MASK);

#ifdef CONFIG_EARLY_PRINTK
	/* We should not use normal printk() from inside the NMI handler */
	console_switched = switch_to_early_dump_console();
#endif

	if (reason.bits.nmi) {
#ifdef CONFIG_E2K
		/* NMI IPIs are used only by nmi_call_function() */
		nmi_call_function_interrupt();
#endif
		reason.bits.nmi = 0;
	}

	if (reason.raw & CEPIC_PNMIRR_BIT_MASK)
		unknown_nmi_error(reason.raw, regs);

#ifdef CONFIG_EARLY_PRINTK
	if (console_switched)
		switch_from_early_dump_console();
#endif
}
