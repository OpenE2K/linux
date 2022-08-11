#ifndef __ASM_PARAVIRT_MMU_CONTEXT_H
#define __ASM_PARAVIRT_MMU_CONTEXT_H

#ifdef __KERNEL__

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

static inline void
pv_activate_mm(struct mm_struct *active_mm, struct mm_struct *mm)
{
	pv_mmu_ops.activate_mm(active_mm, mm);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */
static inline void
activate_mm(struct mm_struct *active_mm, struct mm_struct *mm)
{
	pv_activate_mm(active_mm, mm);
}

static inline void call_switch_mm(struct mm_struct *prev_mm,
		struct mm_struct *next_mm, struct task_struct *next,
		int switch_pgd, int switch_mm)
{
	if (!paravirt_enabled() || IS_HV_GM())
		native_call_switch_mm(prev_mm, next_mm, next,
				switch_pgd, switch_mm);
	else
		kvm_call_switch_mm(prev_mm, next_mm, next,
				switch_pgd, switch_mm);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* __KERNEL__ */
#endif	/* __ASM_PARAVIRT_MMU_CONTEXT_H */
