#ifndef _ARCH_PMC_H_
#define _ARCH_PMC_H_

#include <asm-l/l_pmc.h>

/* Available working frequencies (in kHz) */
#define PMC_L_FREQUENCY_1       500000
#define PMC_L_FREQUENCY_2       400000
#define PMC_L_FREQUENCY_3       300000
#define PMC_L_FREQUENCY_4       200000

/*
 * Implementation of e2k processor sleep states (enters)
 */
static inline void pmc_l_enter_C1(void)
{
	/* Stub: must be wtrap */
	while (!need_resched()) {
		default_idle();
	}
}

static inline void pmc_l_enter_C3(void)
{
	/* Stub: must be wtrap+clk gating */
	while (!need_resched()) {
		default_idle();
	}
}

static inline void pmc_l_enter_C6(void)
{
	/* Stub: must be save to retention */
	while (!need_resched()) {
		default_idle();
	}
}
#endif /*_ARCH_PMC_H_*/
