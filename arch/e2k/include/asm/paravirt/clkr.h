#ifndef _ASM_E2K_PARAVIRT_CLKR_H
#define _ASM_E2K_PARAVIRT_CLKR_H

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

static inline unsigned long long pv_do_sched_clock(void)
{
	return pv_time_ops.do_sched_clock();
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized guest and host kernel */
static inline unsigned long long do_sched_clock(void)
{
	return pv_do_sched_clock();
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* _ASM_E2K_PARAVIRT_CLKR_H */
