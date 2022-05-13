#ifndef __L_ASM_PMC_H__
#define __L_ASM_PMC_H__

#include <linux/thermal.h>
#include <linux/cpu_cooling.h>
#include <linux/i2c.h>
#include <asm/mpspec.h>

#define PMC_L_MAX_IDLE_STATES	4

#define PMC_L_TEMP_RG_CUR_REG_0		0x20
#define PMC_L_TEMP_RG_CUR_REG_1		0x24
#define PMC_L_GPE0_STS_REG		0x28
#define PMC_L_GPE0_STS_CLR		0xf
#define PMC_L_GPE0_EN_REG		0x2c
#define PMC_L_TEMP_RG0_REG		0x30
#define PMC_L_TEMP_RG1_REG		0x34
#define PMC_L_TEMP_RG2_REG		0x38
#define PMC_L_TEMP_RG3_REG		0x3c
#define PMC_L_TEMP_RG_CUR_REG_2		0x40
#define PMC_L_TEMP_RGX_FALL		(0x0 <<  12)
#define PMC_L_TEMP_RGX_RISE		(0x3 <<  12)
#define PMC_L_PC_S0_REG			0x100
#define PMC_L_PC_S1_REG			0x104

#define PMC_L_COFVID_3D_STATUS_REG	0x140
#define PMC_L_P_STATE_3D_CNTRL_REG	0x148
#define PMC_L_P_STATE_3D_STATUS_REG	0x14c
#define PMC_L_P_STATE_3D_VALUE_0_REG	0x150
#define PMC_L_P_STATE_3D_VALUE_1_REG	0x154
#define PMC_L_P_STATE_3D_VALUE_2_REG	0x158
#define	PMC_L_P_STATE_3D_VALUE_3_REG	0x15c
#define PMC_L_C_STATE_3D_REG		0x160
#define PMC_L_2D_FC_REG			0x164

#define PMC_L_REGS_AREA_SIZE		0x168

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

/* P_State_3D_Cntrl (RW): */
#define PMC_L_P_STATE_3D_CNTRL_MASK	0x3
#define PMC_L_P_STATE_3D_CNTRL_SHIFT	0
#define PMC_L_P_STATE_3D_CNTRL_P0_VAL	0x0
#define PMC_L_P_STATE_3D_CNTRL_P1_VAL	0x1
#define PMC_L_P_STATE_3D_CNTRL_P2_VAL	0x2
#define PMC_L_P_STATE_3D_CNTRL_P3_VAL	0x3

/* COVFID_status (contains RW, Status, RM, RO bits): */
#define PMC_L_COVFID_STATUS_PMCEN_VAL	0x0000000000000001 /* RW - 0 Bit */
#define PMC_L_COVFID_STATUS_RMWEN_VAL	0x4000000000000000 /* RM - 62 Bit */
#define PMC_L_COVFID_STATUS_VMAX_MASK	0x3f80000000000000 /* RM - 61:55 Bits */
#define PMC_L_COVFID_STATUS_VMAX_SHIFT	55
#define PMC_L_COVFID_STATUS_VMIN_MASK	0x007f000000000000 /* RM - 54:48 Bits */
#define PMC_L_COVFID_STATUS_VMIN_SHIFT	48
#define PMC_L_COVFID_STATUS_FMAX_MASK	0x0000ff0000000000 /* RM - 26:20 Bits */
#define PMC_L_COVFID_STATUS_FMAX_SHIFT	40
#define PMC_L_COVFID_STATUS_TRANS_VAL	0x0000000000000002 /* RO - 1 Bit */
#define PMC_L_COVFID_STATUS_PNUM_MASK	0x000000000000000c /* RO - 3:2 Bits */
#define PMC_L_COVFID_STATUS_PNUM_SHIFT	2
#define PMC_L_COVFID_STATUS_VID_MASK	0x000000000003f000 /* RO - 18:12 Bits */
#define PMC_L_COVFID_STATUS_VID_SHIFT	12
#define PMC_L_COVFID_STATUS_FID_MASK	0x0000000000000ff0 /* RO - 11:4 Bits */
#define PMC_L_COVFID_STATUS_FID_SHIFT	4

#define PMC_L_COVFID_RM_MASK	(PMC_L_COVFID_STATUS_VMAX_MASK |	\
				 PMC_L_COVFID_STATUS_VMIN_MASK |	\
				 PMC_L_COVFID_STATUS_FMAX_MASK)

#define PMC_L_MAX_PSTATES	4
#define PMC_L_PRECISION		10
#define MAX_NUM_PMCS		1
#define SPMC_TEMP_BAD_VALUE	-1000

/* The driver supports 1 passive trip point and 1 critical trip point */
enum l_pmc_thermal_trip {
	LPMC_TRIP_PASSIVE,
	LPMC_TRIP_CRITICAL,
	LPMC_TRIP_NUM,
};

#define LPMC_TRIP_POINTS_MSK	((1 << LPMC_TRIP_NUM) - 1)

struct l_pmc {
	unsigned char type;
	unsigned char version;
	void __iomem *cntrl_base;
	void __iomem *data_base;
	unsigned long vrange; /* VMAX, VMIN, FMAX */
	unsigned int data_size;
	unsigned int p_state[PMC_L_MAX_PSTATES]; /* VID,
						  * DID,
						  * FID
						  */
	unsigned int freq; /* Frequency in KHz */
	struct pci_dev *pdev;
	struct platform_device *i2c_chan;
	struct thermal_zone_device *thermal;
	enum thermal_device_mode thermal_mode;
	int trip_temp[LPMC_TRIP_NUM];
	int trip_hyst[LPMC_TRIP_NUM];
	raw_spinlock_t thermal_lock;
	struct thermal_cooling_device *cdev;
	struct cpufreq_policy *policy;
};

extern struct l_pmc l_pmc[MAX_NUM_PMCS];

#if defined(CONFIG_L_PMC_MODULE) || defined(CONFIG_L_PMC) || defined(CONFIG_S2_PMC)
extern int spmc_get_temp_cur0(void);
int pmc_l_gpufreq_set_scale(unsigned char scale);
int pmc_l_gpufreq_get_scale(void);
int pmc_l_gpufreq_get_frequency(void);
extern unsigned int load_threshold;
#else
int spmc_get_temp_cur0(void) { return SPMC_TEMP_BAD_VALUE; }
#endif /* CONFIG_L_PMC || CONFIG_S2_PMC */

#if defined(CONFIG_PMC_R2KP)
uint32_t r2kp_get_freq_mult(int cpu);
#endif

#endif /* __L_ASM_PMC_H__ */

