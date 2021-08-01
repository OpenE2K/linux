/*
 * KVM guest kernel processes support
 * Copyright 2011 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_KVM_VCPU_REGS_DEBUG_INLINE_H
#define _E2K_KVM_VCPU_REGS_DEBUG_INLINE_H

#include <linux/types.h>
#include <asm/e2k_api.h>
#include <asm/kvm/guest.h>

#ifdef	VCPU_REGS_DEBUG

static inline void init_vcpu_regs_trace(void)
{
	vcpu_regs_trace_t *trace;

	trace = get_vcpu_regs_trace_struct();
	atomic_set(&trace->count, 0);
	vcpu_regs_trace_on = true;
}

static inline void dump_vcpu_regs_entry(vcpu_regs_t *regs, int entry_no)
{
	u32 updated = regs->updated;

	pr_alert("[%02d] : PSR %02x\tUPSR %03x\tunder UPSR %d\n",
		entry_no, regs->psr, regs->upsr, regs->under_upsr);
	pr_alert("       updated : %s %s %s %s\n",
		(updated & PSR_UPDATE_MASK) ? "PSR" : "",
		(updated & UPSR_UPDATE_MASK) ? "UPSR" : "",
		(updated & UNDER_UPSR_UPDATE_MASK) ? "under UPSR" : "",
		(regs->injected) ? "injected IRQs" : "");
	pr_alert("       IP %pF called from IP %pF\n",
		(void *)regs->IP, (void *)regs->IP_from);
	pr_alert("       clock : start 0x%llx end 0x%llx delta 0x%llx\n",
		regs->clock_start, regs->clock_end,
		regs->clock_end - regs->clock_start);
}

static inline void dump_vcpu_regs_trace(void)
{
	vcpu_regs_trace_t *trace;
	vcpu_regs_t *regs;
	int count, ent, num, entries;

	/* stop tracing */
	vcpu_regs_trace_on = false;

	trace = get_vcpu_regs_trace_struct();
	count = atomic_read(&trace->count);
	pr_alert("CPU #%d : Trace of VCPU #%d some registers update history\n",
		raw_smp_processor_id(), KVM_READ_VCPU_ID());
	if (count == 0) {
		pr_alert("   trace is empty\n");
		return;
	}

	entries = (count > MAX_VCPU_REGS_TRACE_NUM) ?
					MAX_VCPU_REGS_TRACE_NUM : count;
	for (ent = VCPU_REGS_TRACE_INDEX(count), num = 0;
			num < entries;
				ent = VCPU_REGS_TRACE_INDEX(ent - 1), num++) {
		regs = &trace->regs[ent];
		dump_vcpu_regs_entry(regs, ent);
	}
}
#else	/* !VCPU_REGS_DEBUG */

#define	vcpu_regs_trace_on	false

static inline void init_vcpu_regs_trace(void)
{
}

#define trace_vcpu_upsr_update(upsr_val, injected_irqs)
#define trace_vcpu_psr_update(psr_val, under_upsr)

static inline void dump_vcpu_regs_trace(void)
{
}

#endif	/* VCPU_REGS_DEBUG */

#endif /* ! _E2K_KVM_VCPU_REGS_DEBUG_INLINE_H */
