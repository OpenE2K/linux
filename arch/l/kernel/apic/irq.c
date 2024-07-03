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

#include <asm/apic.h>
#include <asm/console.h>
#include <asm/hw_irq.h>
#include <asm/io_apic.h>
#include <asm/nmi.h>

#include <asm-l/l_timer.h>

/* 
 * This file holds code that is common for e2k and e90s APIC implementation
 * but which did not originate in arch/x86/kernel/apic/ folder.
 *
 * Corresponding declarations can be found in asm-l/hw_irq.h
 */

#if IS_ENABLED(CONFIG_RDMA) || IS_ENABLED(CONFIG_RDMA_SIC)
#ifdef CONFIG_NUMA
int rdma_node[MAX_NUMNODES] = {0};
#else
int rdma_node[1] = {0};
#endif
int rdma_apic_init;
EXPORT_SYMBOL(rdma_apic_init);

void (*rdma_interrupt_p)(struct pt_regs *regs) = NULL;
EXPORT_SYMBOL(rdma_interrupt_p);

static void rdma_interrupt(struct pt_regs *regs)
{
	static int int_rdma_error = 0;

	ack_APIC_irq();
	l_irq_enter();
	if (rdma_interrupt_p)
		rdma_interrupt_p(regs);
	else {
		if (!int_rdma_error)
			printk("rdma: attempt calling null handler\n");
		int_rdma_error++;
	}
	inc_irq_stat(irq_rdma_count);
	l_irq_exit();
}
#endif

__init_recv
void l_init_system_handlers_table(void)
{
	/* 
	 * Initialize interrupt[] array of system interrupts' handlers.
	 */

#ifdef CONFIG_SMP
	/*
	 * The reschedule interrupt is a CPU-to-CPU reschedule-helper
	 * IPI, driven by wakeup.
	 */
	setup_PIC_vector_handler(RESCHEDULE_VECTOR,
			smp_reschedule_interrupt, 1,
			"smp_reschedule_interrupt");

	/* IPI for generic function call */
	setup_PIC_vector_handler(CALL_FUNCTION_VECTOR,
			smp_call_function_interrupt, 1,
			"smp_call_function_interrupt");

	/* IPI for generic single function call */
	setup_PIC_vector_handler(CALL_FUNCTION_SINGLE_VECTOR,
			smp_call_function_single_interrupt, 1,
			"smp_call_function_single_interrupt");

	/* Low priority IPI to cleanup after moving an irq. */
	setup_PIC_vector_handler(IRQ_MOVE_CLEANUP_VECTOR,
			smp_irq_move_cleanup_interrupt, 0,
			"smp_irq_move_cleanup_interrupt");

#endif
	/* self generated IPI for local APIC timer */
	setup_PIC_vector_handler(LOCAL_TIMER_VECTOR,
			smp_apic_timer_interrupt, 1,
			"smp_apic_timer_interrupt");

	/* IPI vectors for APIC spurious and error interrupts */
	setup_PIC_vector_handler(SPURIOUS_APIC_VECTOR,
			smp_spurious_interrupt, 1,
			"smp_spurious_interrupt");
	setup_PIC_vector_handler(ERROR_APIC_VECTOR,
			smp_error_interrupt, 1,
			"smp_error_interrupt");

#if IS_ENABLED(CONFIG_RDMA) || IS_ENABLED(CONFIG_RDMA_SIC)
	setup_PIC_vector_handler(RDMA_INTERRUPT_VECTOR,
			rdma_interrupt, 1,
			"rdma_interrupt");
#endif

	setup_PIC_vector_handler(IRQ_WORK_VECTOR,
			smp_irq_work_interrupt, 1,
			"smp_irq_work_interrupt");
}

static void unknown_nmi_error(unsigned int reason, struct pt_regs *regs)
{
	printk("Uhhuh. NMI received for unknown reason %x on CPU %d.\n",
			reason, smp_processor_id());
	printk("Dazed and confused, but trying to continue\n");
}


/*
 * How NMIs work:
 *
 * 1) After receiving NMI corresponding bit in APIC_NM is set.
 *
 * 2) An exception is passed to CPU as soon as the following
 * condition holds true:
 *
 *      APIC_NM != 0 && (!PSR.unmie && PSR.nmie || PSR.unmie && UPSR.nmie)
 *
 * 3) CPU reads APIC_NM register which has a bit set for each
 * successfully received NMI.  At this moment all further NMI
 * exceptions are blocked until APIC_NMI is written with any value.
 *
 * 4) CPU writes APIC_NM thus allowing receive of next NMI and
 * also clearing corresponding bits:
 *
 *      APIC_NM &= ~written_value
 */
noinline notrace void apic_do_nmi(struct pt_regs *regs)
{
	unsigned int reason;
#ifdef CONFIG_EARLY_PRINTK
	int console_switched;
#endif

	reason = arch_apic_read(APIC_NM);

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
	 * clear APIC_NM
	 *
	 * In this example cpu0 will never receive the second NMI.
	 */
	arch_apic_write(APIC_NM, APIC_NM_BIT_MASK);

#ifdef CONFIG_EARLY_PRINTK
	/* We should not use normal printk() from inside the NMI handler */
	console_switched = switch_to_early_dump_console();
#endif

	if (reason & APIC_NM_NMI) {
#ifdef CONFIG_E2K
		/* NMI IPIs are used only by nmi_call_function() */
		nmi_call_function_interrupt();
#endif
		reason &= ~APIC_NM_NMI;
	}

	if (APIC_NM_MASK(reason) != 0)
		unknown_nmi_error(reason, regs);

#ifdef CONFIG_EARLY_PRINTK
	if (console_switched)
		switch_from_early_dump_console();
#endif
}
