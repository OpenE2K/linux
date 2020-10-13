#ifndef _ASM_L_CLKR_H
#define _ASM_L_CLKR_H

extern struct clocksource clocksource_clkr;

#ifdef CONFIG_E2K
extern __interrupt cycle_t fast_syscall_read_clkr(void);
#endif

#endif
