#ifndef __ASM_E2K_PARAVIRT_TIME_H
#define __ASM_E2K_PARAVIRT_TIME_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

extern struct static_key paravirt_steal_enabled;

static inline void
pv_arch_clock_init(void)
{
	return pv_time_ops.clock_init();
}
static inline unsigned long
pv_steal_clock(int cpu)
{
	return pv_time_ops.steal_clock(cpu);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized guest and host kernel */
static inline void
arch_clock_init(void)
{
	pv_arch_clock_init();
}
static inline u64
paravirt_steal_clock(int cpu)
{
	return pv_steal_clock(cpu);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* __KERNEL__ */

#endif	/* __ASM_E2K_PARAVIRT_TIME_H */
