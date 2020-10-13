#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/seq_file.h>
#include <linux/types.h>

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

DEFINE_PER_CPU(vector_irq_t, vector_irq) = {
	[0 ... NR_VECTORS - 1] = -1
};

/*
 * Array of handlers for system interrupts (local timer, IPI, etc).
 */
void (*interrupt[NR_VECTORS])(struct pt_regs *regs) = {
	[0 ... NR_VECTORS - 1] = NULL
};

/*
 * Array is  used for ltt tracing (local timer, IPI, etc).
 */
struct irqaction trace_dummy_action[NR_VECTORS] = {
		[0 ... NR_VECTORS - 1] = {NULL}
};

atomic_t irq_err_count;
DEFINE_PER_CPU_SHARED_ALIGNED(irq_cpustat_t, irq_stat) ____cacheline_internodealigned_in_smp;
EXPORT_PER_CPU_SYMBOL(irq_stat);


#if IS_ENABLED(CONFIG_RDMA) || IS_ENABLED(CONFIG_RDMA_SIC) || \
    IS_ENABLED(CONFIG_RDMA_NET)
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
	irq_enter();
	if (rdma_interrupt_p)
		rdma_interrupt_p(regs);
	else {
		if (!int_rdma_error)
			printk("rdma: attempt calling null handler\n");
		int_rdma_error++;
	}
	inc_irq_stat(irq_rdma_count);
	irq_exit();
}
#endif

#ifndef CONFIG_RECOVERY
__init
#endif
void setup_APIC_vector_handler(int vector,
		void (*handler)(struct pt_regs *), bool system, char *name)
{
	if (test_bit(vector, used_vectors) || interrupt[vector])
		BUG();

	set_bit(vector, used_vectors);
	if (system && first_system_vector > vector)
		first_system_vector = vector;
	interrupt[vector] = handler;
	trace_dummy_action[vector].handler = (irq_handler_t)handler;
	trace_dummy_action[vector].name  = name;
}

#ifndef CONFIG_RECOVERY
__init
#endif
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
	setup_APIC_vector_handler(RESCHEDULE_VECTOR,
			smp_reschedule_interrupt, 1,
			"smp_reschedule_interrupt");

	/* IPI for generic function call */
	setup_APIC_vector_handler(CALL_FUNCTION_VECTOR,
			smp_call_function_interrupt, 1,
			"smp_call_function_interrupt");

	/* IPI for generic single function call */
	setup_APIC_vector_handler(CALL_FUNCTION_SINGLE_VECTOR,
			smp_call_function_single_interrupt, 1,
			"smp_call_function_single_interrupt");

	/* Low priority IPI to cleanup after moving an irq. */
	setup_APIC_vector_handler(IRQ_MOVE_CLEANUP_VECTOR,
			smp_irq_move_cleanup_interrupt, 0,
			"smp_irq_move_cleanup_interrupt");

#endif
	/* self generated IPI for local APIC timer */
	setup_APIC_vector_handler(LOCAL_TIMER_VECTOR,
			smp_apic_timer_interrupt, 1,
			"smp_apic_timer_interrupt");

	/* IPI vectors for APIC spurious and error interrupts */
	setup_APIC_vector_handler(SPURIOUS_APIC_VECTOR,
			smp_spurious_interrupt, 1,
			"smp_spurious_interrupt");
	setup_APIC_vector_handler(ERROR_APIC_VECTOR,
			smp_error_interrupt, 1,
			"smp_error_interrupt");

#if IS_ENABLED(CONFIG_RDMA) || IS_ENABLED(CONFIG_RDMA_SIC) || \
    IS_ENABLED(CONFIG_RDMA_NET)
	setup_APIC_vector_handler(RDMA_INTERRUPT_VECTOR,
			rdma_interrupt, 1,
			"rdma_interrupt");
#endif

	setup_APIC_vector_handler(IRQ_WORK_VECTOR,
			smp_irq_work_interrupt, 1,
			"smp_irq_work_interrupt");
}

static void unknown_nmi_error(unsigned int reason, struct pt_regs *regs)
{
	printk("Uhhuh. NMI received for unknown reason %x on CPU %d.\n",
			reason, smp_processor_id());
	printk("Dazed and confused, but trying to continue\n");
}


/* Detailed description on how to work with NMIs
 * can be found in comment #6 bug #50153 */
noinline notrace void do_nmi(struct pt_regs *regs)
{
	unsigned int reason;
#ifdef CONFIG_SERIAL_PRINTK
	int old_use_boot_printk_all;
#endif
	nmi_enter();

	inc_irq_stat(__nmi_count);

	reason = arch_apic_read(APIC_NM);

#ifdef CONFIG_SERIAL_PRINTK
	/* We should not use normal printk() from inside the NMI handler */
	old_use_boot_printk_all = use_boot_printk_all;
	use_boot_printk_all = 1;
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

#ifdef CONFIG_SERIAL_PRINTK
	use_boot_printk_all = old_use_boot_printk_all;
#endif

	arch_apic_write(APIC_NM, APIC_NM_BIT_MASK);

	nmi_exit();
}


#define irq_stats(cpu)		(&per_cpu(irq_stat, cpu))

/*
 * /proc/interrupts printing:
 */
int arch_show_interrupts(struct seq_file *p, int prec)
{
	int j;

	seq_printf(p, "%*s: ", prec, "NMI");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->__nmi_count);
	seq_printf(p, "  Non-maskable interrupts\n");
	seq_printf(p, "%*s: ", prec, "LOC");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->apic_timer_irqs);
	seq_printf(p, "  Local timer interrupts\n");

	seq_printf(p, "%*s: ", prec, "SPU");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->irq_spurious_count);
	seq_printf(p, "  Spurious interrupts\n");
//TODO
#if 0
	seq_printf(p, "%*s: ", prec, "IWI");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->apic_irq_work_irqs);
	seq_printf(p, "  IRQ work interrupts\n");
#endif
	seq_printf(p, "%*s: ", prec, "RTR");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->icr_read_retry_count);
	seq_printf(p, "  read retries\n");
#ifdef CONFIG_SMP
	seq_printf(p, "%*s: ", prec, "RES");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->irq_resched_count);
	seq_printf(p, "  Rescheduling interrupts\n");
# ifdef CONFIG_E2K
	seq_printf(p, "%*s: ", prec, "CAL");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->irq_call_count -
					irq_stats(j)->irq_tlb_count);
	seq_printf(p, "  Function call interrupts\n");
	seq_printf(p, "%*s: ", prec, "TLB");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->irq_tlb_count);
	seq_printf(p, "  TLB shootdowns\n");
# else
	seq_printf(p, "%*s: ", prec, "CAL");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->irq_call_count);
	seq_printf(p, "  Function call interrupts\n");
# endif
#endif
#ifdef CONFIG_E2K
# if IS_ENABLED(CONFIG_RDMA) || IS_ENABLED(CONFIG_RDMA_SIC) || \
     IS_ENABLED(CONFIG_RDMA_NET)
	seq_printf(p, "v%*d: ", prec - 1, RDMA_INTERRUPT_VECTOR);
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->irq_rdma_count);
	seq_printf(p, "  RDMA interrupts\n");
# endif
# if IS_ENABLED(CONFIG_ELDSP)
	if (IS_MACHINE_ES2) {
		seq_printf(p, "v%*d: ", prec - 1, LVT3_INTERRUPT_VECTOR);
		for_each_online_cpu(j)
			seq_printf(p, "%10u ", irq_stats(j)->irq_eldsp_count);
		seq_printf(p, "  Elbrus DSP interrupts\n");
	}
# endif
#endif
	seq_printf(p, "%*s: %10u\n", prec, "ERR", atomic_read(&irq_err_count));
	seq_printf(p, "%*s: %10u\n", prec, "MIS", atomic_read(&irq_mis_count));
	return 0;
}


/*
 * do_IRQ handles all normal device IRQ's (the special
 * SMP cross-CPU interrupts have their own specific
 * handlers).
 */
void do_IRQ(struct pt_regs * regs, unsigned int vector)
{
	struct pt_regs *old_regs = set_irq_regs(regs);
	struct irq_desc *desc;
	int irq;

	irq = __raw_get_cpu_var(vector_irq)[vector];

#ifdef CONFIG_E2K
	/*It works under CONFIG_PROFILING flag only */
	store_do_irq_ticks();
#endif

	irq_enter();

	desc = irq_to_desc(irq);

	if (likely(desc)) {
		generic_handle_irq_desc(irq, desc);
	} else {
		ack_APIC_irq();
		if (printk_ratelimit())
			pr_emerg("%s: %d No irq handler for vector "
					"%d (irq %d)\n", __func__,
					smp_processor_id(), vector, irq);
	}

#ifdef CONFIG_E2K
	/*It works under CONFIG_PROFILING flag only */
	define_time_of_do_irq(irq);
#endif

	irq_exit();

	set_irq_regs(old_regs);
}

void ack_bad_irq(unsigned int irq)
{
	printk("unexpected IRQ trap at vector %02x\n", irq);
	/*
	 * Currently unexpected vectors happen only on SMP and APIC.
	 * We _must_ ack these because every local APIC has only N
	 * irq slots per priority level, and a 'hanging, unacked' IRQ
	 * holds up an irq slot - in excessive cases (when multiple
	 * unexpected vectors occur) that might lock up the APIC
	 * completely.
	 */
	ack_APIC_irq();
}

#ifdef CONFIG_SMP
void __inquire_remote_apic(int apicid)
{
	unsigned i, regs[] = { APIC_ID >> 4, APIC_LVR >> 4, APIC_SPIV >> 4 };
	char *names[] = { "ID", "VERSION", "SPIV" };
	int timeout;
	u32 status;

	printk(KERN_INFO "Inquiring remote APIC 0x%x...\n", apicid);

	for (i = 0; i < ARRAY_SIZE(regs); i++) {
		printk(KERN_INFO "... APIC 0x%x %s: ", apicid, names[i]);

		/*
		 * Wait for idle.
		 */
		status = safe_apic_wait_icr_idle();
		if (status)
			printk(KERN_CONT
			       "a previous APIC delivery may have failed\n");

		apic_icr_write(APIC_DM_REMRD | regs[i], apicid);

		timeout = 0;
		do {
			udelay(100);
			status = apic_read(APIC_ICR) & APIC_ICR_RR_MASK;
		} while (status == APIC_ICR_RR_INPROG && timeout++ < 1000);

		switch (status) {
		case APIC_ICR_RR_VALID:
			status = apic_read(APIC_RRR);
			printk(KERN_CONT "%08x\n", status);
			break;
		default:
			printk(KERN_CONT "failed\n");
		}
	}
}
#endif


/*
 * /proc/stat helpers
 */
u64 arch_irq_stat_cpu(unsigned int cpu)
{
	u64 sum = irq_stats(cpu)->__nmi_count;

	sum += irq_stats(cpu)->apic_timer_irqs;
	sum += irq_stats(cpu)->irq_spurious_count;
#ifdef CONFIG_SMP
	sum += irq_stats(cpu)->irq_resched_count;
	sum += irq_stats(cpu)->irq_call_count;
#endif
#ifdef CONFIG_E2K
# if IS_ENABLED(CONFIG_RDMA) || IS_ENABLED(CONFIG_RDMA_SIC) || \
     IS_ENABLED(CONFIG_RDMA_NET)
	sum += irq_stats(cpu)->irq_rdma_count;
# endif
# if IS_ENABLED(CONFIG_ELDSP)
	if (IS_MACHINE_ES2) {
		sum += irq_stats(cpu)->irq_eldsp_count;
	}
# endif
#endif

	return sum;
}

u64 arch_irq_stat(void)
{
	u64 sum = atomic_read(&irq_err_count) + atomic_read(&irq_mis_count);

	return sum;
}

