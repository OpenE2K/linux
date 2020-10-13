#ifndef __L_ASM_PMC_H__
#define __L_ASM_PMC_H__

#include <asm/mpspec.h>

#define PMC_L_MAX_IDLE_STATES	4

/* PMC registers */
#define PMC_L_COVFID_STATUS_REG		0x0
#define PMC_L_P_STATE_CNTRL_REG		0x8
#define PMC_L_P_STATE_STATUS_REG	0xc
#define PMC_L_P_STATE_VALUE_0_REG	0x10
#define PMC_L_P_STATE_VALUE_1_REG	0x14
#define PMC_L_P_STATE_VALUE_2_REG	0x18
#define PMC_L_P_STATE_VALUE_3_REG	0x1c
#define PMC_L_TEMP_RG_CUR_REG_0		0x20
#define PMC_L_TEMP_RG_CUR_REG_1		0x24
#define PMC_L_GPE0_STS_REG		0x28
#define PMC_L_GPE0_EN_REG		0x2c
#define PMC_L_TEMP_RG0_REG		0x30
#define PMC_L_TEMP_RG1_REG		0x34
#define PMC_L_TEMP_RG2_REG		0x38
#define PMC_L_TEMP_RG3_REG		0x3c

#define PMC_L_PC_S0_REG			0x100
#define PMC_L_PC_S1_REG			0x104

/* Bits in PMC registers: */
/* P_State_value_X (RW): */
#define PMC_L_P_STATE_VALUE_VID_MASK	0x0000fe00
#define PMC_L_P_STATE_VALUE_VID_SHIFT	9
#define PMC_L_P_STATE_VALUE_DID_MASK	0x000001f0
#define PMC_L_P_STATE_VALUE_DID_SHIFT	4
#define PMC_L_P_STATE_VALUE_FID_MASK	0x0000000f
#define PMC_L_P_STATE_VALUE_FID_SHIFT	0

/* P_State_Cntrl (RW): */
#define PMC_L_P_STATE_CNTRL_MASK	0x3
#define PMC_L_P_STATE_CNTRL_SHIFT	0
#define PMC_L_P_STATE_CNTRL_P0_VAL	0x0
#define PMC_L_P_STATE_CNTRL_P1_VAL	0x1
#define PMC_L_P_STATE_CNTRL_P2_VAL	0x2
#define PMC_L_P_STATE_CNTRL_P3_VAL	0x3

/* P_State_status (RO): */
#define PMC_L_P_STATE_STATUS_MASK	0x3
#define PMC_L_P_STATE_STATUS_SHIFT	0

/* COVFID_status (contains RW, Status, RM, RO bits): */
#define PMC_L_COVFID_STATUS_PMCEN_VAL	0x20000000000 /* RW - 41 Bit */
#define PMC_L_COVFID_STATUS_RMWEN_VAL	0x10000000000 /* Status - 40 Bit */
#define PMC_L_COVFID_STATUS_VMAX_MASK	0x0fc00000000 /* RM - 39:34 Bits */
#define PMC_L_COVFID_STATUS_VMAX_SHIFT	34
#define PMC_L_COVFID_STATUS_VMIN_MASK	0x003f8000000 /* RM - 33:27 Bits */
#define PMC_L_COVFID_STATUS_VMIN_SHIFT	27
#define PMC_L_COVFID_STATUS_FMAX_MASK	0x00007f00000 /* RM - 26:20 Bits */
#define PMC_L_COVFID_STATUS_FMAX_SHIFT	20
#define PMC_L_COVFID_STATUS_TRANS_VAL	0x00000080000 /* RO - 19 Bit */
#define PMC_L_COVFID_STATUS_PNUM_MASK	0x00000070000 /* RO - 18:16 Bits */
#define PMC_L_COVFID_STATUS_PNUM_SHIFT	16
#define PMC_L_COVFID_STATUS_VID_MASK	0x0000000fe00 /* RO - 15:9 Bits */
#define PMC_L_COVFID_STATUS_VID_SHIFT	9
#define PMC_L_COVFID_STATUS_DID_MASK	0x000000001f0 /* RO - 8:4 Bits */
#define PMC_L_COVFID_STATUS_DID_SHIFT	4
#define PMC_L_COVFID_STATUS_FID_MASK	0x0000000000f /* RO - 3:0 Bits */
#define PMC_L_COVFID_STATUS_FID_SHIFT	0

#define PMC_L_COVFID_RM_MASK	(PMC_L_COVFID_STATUS_VMAX_MASK |	\
				 PMC_L_COVFID_STATUS_VMIN_MASK |	\
				 PMC_L_COVFID_STATUS_FMAX_MASK)

#define PMC_L_MAX_PSTATES	4
#define PMC_L_PRECISION		10

struct l_pmc {
	unsigned char type;
	unsigned char version;
	void __iomem *cntrl_base;
	void __iomem *data_base;
	unsigned long vrange; /* VMAX 40:34, VMIN 33:27, FMAX 26:20 */
	unsigned int data_size;
	unsigned int p_state[PMC_L_MAX_PSTATES]; /* VID 15:9,
						  * DID 8:4,
						  * FID 3:0
						  */
	unsigned int freq; /* Frequency in KHz */
};

extern struct l_pmc l_pmc;
#endif /* __L_ASM_PMC_H__ */

