#ifndef _ARCH_PMC_H_
#define _ARCH_PMC_H_

#ifdef CONFIG_E90S

#include <asm-l/l_pmc.h>
#include <asm/io.h>

/* Available working frequencies (in kHz) */
#define PMC_L_FREQUENCY_1	50000
#define PMC_L_FREQUENCY_2	40000
#define PMC_L_FREQUENCY_3	30000
#define PMC_L_FREQUENCY_4	20000

/* ASI Regs: */
#define E90S_EMERALD_PWRCTRL_REG_ADDR	0x38

/* Values for sleep states:  */
#define E90S_EMERALD_C1		1
#define E90S_EMERALD_C3		3
#define E90S_EMERALD_C6		6

/*
 * Implementation of e90s processor sleep states (enters)
 */
static inline void pmc_l_enter_C1(void)
{
	/* wtrap */
	writeq_asi(E90S_EMERALD_C1, E90S_EMERALD_PWRCTRL_REG_ADDR,
							ASI_LSU_CONTROL);
}

static inline void pmc_l_enter_C3(void)
{
	/* wtrap+clk gating */
/*	writeq_asi(E90S_EMERALD_C3, E90S_EMERALD_PWRCTRL_REG_ADDR,
							ASI_LSU_CONTROL); */
	 writeq_asi(E90S_EMERALD_C1, E90S_EMERALD_PWRCTRL_REG_ADDR,
							ASI_LSU_CONTROL);
}

static inline void pmc_l_enter_C6(void)
{
	/* save to retention */
/*	writeq_asi(E90S_EMERALD_C3, E90S_EMERALD_PWRCTRL_REG_ADDR,
							ASI_LSU_CONTROL); */
	/* Stub: must be save to retention */
	while (!need_resched()) {
		default_idle();
	}
}
#endif /* CONFIG_E90S */
#endif /*_ARCH_PMC_H_*/
