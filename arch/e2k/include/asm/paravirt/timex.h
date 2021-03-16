#ifndef __ASM_E2K_PARAVIRT_TIMEX_H
#define __ASM_E2K_PARAVIRT_TIMEX_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

static inline void
pv_time_init(void)
{
	pv_time_ops.time_init();
}

static inline int
pv_read_current_timer(unsigned long *timer_val)
{
	return pv_time_ops.read_current_timer(timer_val);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized guest and host kernel */
static inline void
time_init(void)
{
	pv_time_init();
}
static inline int
read_current_timer(unsigned long *timer_val)
{
	return pv_read_current_timer(timer_val);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* __KERNEL__ */

#endif	/* __ASM_E2K_PARAVIRT_TIMEX_H */
