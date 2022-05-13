#ifndef _ASM_PARAVIRT_MACHDEP_H_
#define _ASM_PARAVIRT_MACHDEP_H_

#include <linux/kernel.h>
#include <asm/paravirt/pv_ops.h>

static inline void
pv_arch_setup_machine(void)
{
	pv_cpu_ops.arch_setup_machine();
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
static inline void arch_setup_machine(void)
{
	pv_arch_setup_machine();
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* _ASM_PARAVIRT_MACHDEP_H_ */
