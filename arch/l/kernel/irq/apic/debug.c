#include <linux/printk.h>
#include <asm/nmi.h>
#include <asm/smp.h>

#include "apic.h"

static __cold void save_APIC_field(int base, u32 saved_reg[])
{
	int i;

	for (i = 0; i < 8; i++)
		saved_reg[i] = apic_read(base + i*0x10);
}

static __cold void print_saved_APIC_field(const u32 saved_reg[])
{
	int i, j, bit = 0;
	u32 reg;

	for (i = 0; i < 8; i++) {
		reg = saved_reg[i];
		for (j = 0; j < 32; j++) {
			if (reg & 1)
				pr_cont("0x%x ", bit);
			reg = reg >> 1;
			bit++;
		}
	}
	pr_cont("\n");
}

static __cold void print_APIC_field(int base)
{
	int i, j, bit = 0;
	u32 reg;

	for (i = 0; i < 8; i++) {
		reg = apic_read(base + i*0x10);
		for (j = 0; j < 32; j++) {
			if (reg & 1)
				pr_cont("0x%x ", bit);
			reg = reg >> 1;
			bit++;
		}
	}
	pr_cont("\n");
}

struct saved_apic_regs {
	bool valid;
	int hard_cpu;
	int maxlvt;
	u64 icr;
	u32 ver;
	u32 apic_id;
	u32 apic_lvr;
	u32 apic_taskpri;
	u32 apic_arbpri;
	u32 apic_procpri;
	u32 apic_ldr;
	u32 apic_dfr;
	u32 apic_spiv;
	u32 apic_esr;
	u32 apic_lvtt;
	u32 apic_lvtpc;
	u32 apic_lvt0;
	u32 apic_lvt1;
	u32 apic_lvterr;
	u32 apic_tmict;
	u32 apic_tmcct;
	u32 apic_tdcr;
	u32 apic_isr[8];
	u32 apic_tmr[8];
	u32 apic_irr[8];
};

static __cold void print_saved_local_APIC(int cpu, const struct saved_apic_regs *regs)
{
	if (regs->valid)
		return;

	pr_info("printing local APIC contents on CPU#%d/%d:\n",
			cpu, regs->hard_cpu);
	pr_info("... APIC ID:      %08x (%01x)\n", regs->apic_id,
			default_get_apic_id(regs->apic_id));
	pr_info("... APIC VERSION: %08x\n", regs->apic_lvr);
	pr_info("... APIC TASKPRI: %08x (%02x)\n", regs->apic_taskpri,
			regs->apic_taskpri & APIC_TPRI_MASK);

	if (!APIC_XAPIC(regs->ver)) {
		pr_info("... APIC ARBPRI: %08x (%02x)\n", regs->apic_arbpri,
				regs->apic_arbpri & APIC_ARBPRI_MASK);
	}
	pr_info("... APIC PROCPRI: %08x\n", regs->apic_procpri);

	pr_info("... APIC LDR: %08x\n", regs->apic_ldr);
	pr_info("... APIC DFR: %08x\n", regs->apic_dfr);
	pr_info("... APIC SPIV: %08x\n", regs->apic_spiv);

	pr_info("... APIC ISR field: ");
	print_saved_APIC_field(regs->apic_isr);
	pr_info("... APIC TMR field: ");
	print_saved_APIC_field(regs->apic_tmr);
	pr_info("... APIC IRR field: ");
	print_saved_APIC_field(regs->apic_irr);

	pr_info("... APIC ESR: %08x\n", regs->apic_esr);

	pr_info("... APIC ICR: %08x\n", (u32) regs->icr);
	pr_info("... APIC ICR2: %08x\n", (u32) (regs->icr >> 32));

	pr_info("... APIC LVTT: %08x\n", regs->apic_lvtt);

	if (regs->maxlvt > 3)                       /* PC is LVT#4. */
		pr_info("... APIC LVTPC: %08x\n", regs->apic_lvtpc);
	pr_info("... APIC LVT0: %08x\n", regs->apic_lvt0);
	pr_info("... APIC LVT1: %08x\n", regs->apic_lvt1);

	if (regs->maxlvt > 2)			/* ERR is LVT#3. */
		pr_info("... APIC LVTERR: %08x\n", regs->apic_lvterr);

	pr_info("... APIC TMICT: %08x\n", regs->apic_tmict);
	pr_info("... APIC TMCCT: %08x\n", regs->apic_tmcct);
	pr_info("... APIC TDCR: %08x\n", regs->apic_tdcr);
}

static __cold void save_local_APIC(void *apic_regs)
{
	struct saved_apic_regs *regs = apic_regs;

	regs->hard_cpu = hard_smp_processor_id();
	regs->apic_id = apic_read(APIC_ID);
	regs->apic_lvr = apic_read(APIC_LVR);
	regs->ver = GET_APIC_VERSION(regs->apic_lvr);
	/* Note that we don't have APIC_RRR even though maxlvt is 3 */
	regs->maxlvt = lapic_get_maxlvt();

	regs->apic_taskpri = apic_read(APIC_TASKPRI);

	if (!APIC_XAPIC(regs->ver))
		regs->apic_arbpri = apic_read(APIC_ARBPRI);
	regs->apic_procpri = apic_read(APIC_PROCPRI);

	regs->apic_ldr = apic_read(APIC_LDR);
	regs->apic_dfr = apic_read(APIC_DFR);
	regs->apic_spiv = apic_read(APIC_SPIV);

	save_APIC_field(APIC_ISR, regs->apic_isr);
	save_APIC_field(APIC_TMR, regs->apic_tmr);
	save_APIC_field(APIC_IRR, regs->apic_irr);

	if (regs->maxlvt > 3)     /* Due to the Pentium erratum 3AP. */
		apic_write(APIC_ESR, 0);

	regs->apic_esr = apic_read(APIC_ESR);

	regs->icr = apic_icr_read();

	regs->apic_lvtt = apic_read(APIC_LVTT);

	if (regs->maxlvt > 3)                       /* PC is LVT#4. */
		regs->apic_lvtpc = apic_read(APIC_LVTPC);
	regs->apic_lvt0 = apic_read(APIC_LVT0);
	regs->apic_lvt1 = apic_read(APIC_LVT1);

	if (regs->maxlvt > 2)			/* ERR is LVT#3. */
		regs->apic_lvterr = apic_read(APIC_LVTERR);

	regs->apic_tmict = apic_read(APIC_TMICT);
	regs->apic_tmcct = apic_read(APIC_TMCCT);
	regs->apic_tdcr = apic_read(APIC_TDCR);

	regs->valid = true;
}

__cold void print_local_APIC(void)
{
	unsigned int v, ver, maxlvt;
	u64 icr;

	pr_info("printing local APIC contents on CPU#%d/%d:\n",
			smp_processor_id(), hard_smp_processor_id());
	v = apic_read(APIC_ID);
	pr_info("... APIC ID:      %08x (%01x)\n", v, read_apic_id());
	v = apic_read(APIC_LVR);
	pr_info("... APIC VERSION: %08x\n", v);
	ver = GET_APIC_VERSION(v);
	/* Note that we don't have RRR even though maxlvt is 3 */
	maxlvt = lapic_get_maxlvt();

	v = apic_read(APIC_TASKPRI);
	pr_info("... APIC TASKPRI: %08x (%02x)\n", v, v & APIC_TPRI_MASK);

	if (!APIC_XAPIC(ver)) {
		v = apic_read(APIC_ARBPRI);
		pr_info("... APIC ARBPRI: %08x (%02x)\n", v,
				v & APIC_ARBPRI_MASK);
	}
	v = apic_read(APIC_PROCPRI);
	pr_info("... APIC PROCPRI: %08x\n", v);

	v = apic_read(APIC_LDR);
	pr_info("... APIC LDR: %08x\n", v);
	v = apic_read(APIC_DFR);
	pr_info("... APIC DFR: %08x\n", v);
	v = apic_read(APIC_SPIV);
	pr_info("... APIC SPIV: %08x\n", v);

	pr_info("... APIC ISR field: ");
	print_APIC_field(APIC_ISR);
	pr_info("... APIC TMR field: ");
	print_APIC_field(APIC_TMR);
	pr_info("... APIC IRR field: ");
	print_APIC_field(APIC_IRR);

	if (maxlvt > 3)         /* Due to the Pentium erratum 3AP. */
		apic_write(APIC_ESR, 0);

	v = apic_read(APIC_ESR);
	pr_info("... APIC ESR: %08x\n", v);

	icr = apic_icr_read();
	pr_info("... APIC ICR: %08x\n", (u32)icr);
	pr_info("... APIC ICR2: %08x\n", (u32)(icr >> 32));

	v = apic_read(APIC_LVTT);
	pr_info("... APIC LVTT: %08x\n", v);

	if (maxlvt > 3) {                       /* PC is LVT#4. */
		v = apic_read(APIC_LVTPC);
		pr_info("... APIC LVTPC: %08x\n", v);
	}
	v = apic_read(APIC_LVT0);
	pr_info("... APIC LVT0: %08x\n", v);
	v = apic_read(APIC_LVT1);
	pr_info("... APIC LVT1: %08x\n", v);

	if (maxlvt > 2) {			/* ERR is LVT#3. */
		v = apic_read(APIC_LVTERR);
		pr_info("... APIC LVTERR: %08x\n", v);
	}

	v = apic_read(APIC_TMICT);
	pr_info("... APIC TMICT: %08x\n", v);
	v = apic_read(APIC_TMCCT);
	pr_info("... APIC TMCCT: %08x\n", v);
	v = apic_read(APIC_TDCR);
	pr_info("... APIC TDCR: %08x\n", v);
}

void __cold print_local_APICs(void)
{
	int cpu;

	preempt_disable();
	for_each_online_cpu(cpu) {
		struct saved_apic_regs regs;

		if (cpu == smp_processor_id()) {
			print_local_APIC();
			continue;
		}

		regs.valid = false;
		/* This function can be called through SysRq under
		 * disabled interrupts, so we have to be careful
		 * and use nmi_call_function() with a timeout
		 * instead of smp_call_function(). */
		nmi_call_function_single(cpu, save_local_APIC, &regs, 1, 30000);
		if (regs.valid)
			print_saved_local_APIC(cpu, &regs);
	}
	preempt_enable();
}