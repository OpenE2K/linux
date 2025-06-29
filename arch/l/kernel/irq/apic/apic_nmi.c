#include <linux/interrupt.h>
#include <linux/irq.h>
#include <asm/nmi.h>

#include "apic.h"


static void unknown_nmi_error(unsigned int reason, struct pt_regs *regs)
{
	pr_emerg("Uhhuh. NMI received for unknown reason %x on CPU %d.\n",
			reason, smp_processor_id());
	pr_emerg("Dazed and confused, but trying to continue\n");
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

	reason = apic_read(APIC_NM);

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
	apic_write(APIC_NM, APIC_NM_BIT_MASK);

	if (reason & APIC_NM_NMI) {
#ifdef CONFIG_E2K
		/* NMI IPIs are used only by nmi_call_function() */
		nmi_call_function_interrupt();
#endif
		reason &= ~APIC_NM_NMI;
	}

	if (APIC_NM_MASK(reason) != 0)
		unknown_nmi_error(reason, regs);
}
