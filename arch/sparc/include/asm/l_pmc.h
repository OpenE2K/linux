#ifndef _ARCH_PMC_H_
#define _ARCH_PMC_H_
#ifdef CONFIG_E90S

/* PMC registers */
#define PMC_L_COVFID_STATUS_REG_CL0     0x0
#define PMC_L_P_STATE_STATUS_REG_CL0    0xc
#define PMC_L_P_STATE_CNTRL_REG_CL0     0x8
#define PMC_L_P_STATE_VALUE_0_REG_CL0   0x10
#define PMC_L_P_STATE_VALUE_1_REG_CL0   0x14
#define PMC_L_P_STATE_VALUE_2_REG_CL0   0x18
#define PMC_L_P_STATE_VALUE_3_REG_CL0   0x1c
#define PMC_L_COVFID_STATUS_REG_CL1     0x168
#define PMC_L_P_STATE_STATUS_REG_CL1    0x170
#define PMC_L_P_STATE_CNTRL_REG_CL1     0x174
#define PMC_L_P_STATE_VALUE_0_REG_CL1   0x178
#define PMC_L_P_STATE_VALUE_1_REG_CL1   0x17c
#define PMC_L_P_STATE_VALUE_2_REG_CL1   0x180
#define PMC_L_P_STATE_VALUE_3_REG_CL1   0x184


unsigned s2_get_freq_mult(int cpu);

#include <asm-l/l_pmc.h>
#endif /* CONFIG_E90S */
#endif /*_ARCH_PMC_H_*/
