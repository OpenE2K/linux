#pragma once

/* Available working frequencies (in kHz) */
#define PMC_L_FREQUENCY_1       1000000
#define PMC_L_FREQUENCY_2       400000
#define PMC_L_FREQUENCY_3       200000
#define PMC_L_FREQUENCY_4       143000

/* PMC registers */
#define PMC_L_COVFID_STATUS_REG		0x0
#define PMC_L_P_STATE_CNTRL_REG		0x8
#define PMC_L_P_STATE_STATUS_REG	0xc
#define PMC_L_P_STATE_VALUE_0_REG	0x10
#define PMC_L_P_STATE_VALUE_1_REG	0x14
#define PMC_L_P_STATE_VALUE_2_REG	0x18
#define PMC_L_P_STATE_VALUE_3_REG	0x1c

#include <asm-l/l_pmc.h>
