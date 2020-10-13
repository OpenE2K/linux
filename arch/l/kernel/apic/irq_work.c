#include <linux/kernel.h>
#include <linux/irq.h>
#include <linux/irq_work.h>
#include <linux/hardirq.h>
#include <asm/apic.h>
#include <asm/irq_vectors.h>

static inline void irq_work_entering_irq(void)
{
	irq_enter();
	ack_APIC_irq();
}

static inline void __smp_irq_work_interrupt(void)
{
	inc_irq_stat(apic_irq_work_irqs);
	irq_work_run();
}

__visible void smp_irq_work_interrupt(struct pt_regs *regs)
{
	irq_work_entering_irq();
	__smp_irq_work_interrupt();
	exiting_irq();
}

#if 0
__visible void smp_trace_irq_work_interrupt(struct pt_regs *regs)
{
	irq_work_entering_irq();
	trace_irq_work_entry(IRQ_WORK_VECTOR);
	__smp_irq_work_interrupt();
	trace_irq_work_exit(IRQ_WORK_VECTOR);
	exiting_irq();
}
#endif

void arch_irq_work_raise(void)
{
	apic->send_IPI_self(IRQ_WORK_VECTOR);
	apic_wait_icr_idle();
}
