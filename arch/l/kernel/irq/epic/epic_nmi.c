#include <linux/interrupt.h>
#include <linux/irq.h>
#include <asm/nmi.h>

#include "epic.h"

static void unknown_nmi_error(unsigned int reason, struct pt_regs *regs)
{
	pr_warn("NMI received for unknown reason %x on CPU %d.\n",
			reason, smp_processor_id());
}

noinline notrace void epic_do_nmi(struct pt_regs *regs)
{
	union cepic_pnmirr reason;

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

	if (reason.nmi) {
#ifdef CONFIG_E2K
		/* NMI IPIs are used only by nmi_call_function() */
		nmi_call_function_interrupt();
#endif
		reason.nmi = 0;
	}

	if (reason.raw & CEPIC_PNMIRR_BIT_MASK)
		unknown_nmi_error(reason.raw, regs);
}
