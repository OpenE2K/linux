/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _PMC_H_
#define _PMC_H_

#include <asm-l/l_pmc.h>

/* FID's and BFS bypass */
#define HB_BFS_PCI_CONF_REG	0x70
#define HB_BFS_BYPASS_MASK	0x80

/*
 *  S2: Global storage for NBSR_NODE_CFG_INFO, same for all nodes,
 *  initialized in s2_pmc_init for
 *  E1CP: global for HB_BFS_PCI_CONF_REG, initialized in
 *  pmc_l_cpufreq_init throug pci read
 */
extern unsigned int bfs_bypass_val;

enum PStateValRegs {
	PMC_PSTATEVAL_REG0, /* 0 */
	PMC_PSTATEVAL_REG1, /* 1 */
	PMC_PSTATEVAL_REG2, /* 2 */
	PMC_PSTATEVAL_REG3, /* 3 */
	PMC_MAX_STATES,	    /* 4 */
};

#define Fcpu(fbfs, mii_inv, nii) ((fbfs) * 16 / ((mii_inv) * (nii)))
#define Mii_inv(fid) ((((fid) & 0xc0) >> 6) ?			\
		     1 << ((((fid) & 0xc0) >> 6) - 1) : 0)
#define Nii(fid) ((fid) & 0x3f)

#ifdef CONFIG_E90S  /* E90S */
/* From R2000 (S2) */

/* We consider that 100 MHz is base freq for all R2000 boards */
#define S2_BASE_FREQ		100
#define S2_MAX_PSTATES  	(PMC_L_MAX_PSTATES + 1)
#define S2_MAX_AV_PSTATES	60
#define S2_MAX_AV_ID    	(S2_MAX_AV_PSTATES-1)
#define S2_MAX_FREQ		2000
#define S2_MIN_FREQ		200

#define S2_TRANSITION_LATENCY	6000
#define PMC_TRANSITION_LATENCY	S2_TRANSITION_LATENCY

#define BASE_FREQ		S2_BASE_FREQ
#define MAX_PSTATES		S2_MAX_PSTATES
#define MAX_AV_PSTATES		S2_MAX_AV_PSTATES
#define MAX_AV_ID	 	S2_MAX_AV_ID
#define MAX_FREQ 		S2_MAX_FREQ
#define MIN_FREQ 		S2_MIN_FREQ

/* return 0 if cpu in CL0 and 1 if cpu in CL1 */
#define cpu_to_cluster(cpu)  (((cpu) & 0x4) ? 1 : 0)
#define Fbfs(fref, cfgclksys) ((fref) * ((cfgclksys) + 10))

#else /* E2K */

/* From E1CP */
/* PMC's bar is 2 in host bridge */
#define E1CP_PMC_BAR		2
#define E1CP_BASE_FREQ		100
#define E1CP_MAX_PSTATES        (PMC_L_MAX_PSTATES + 1)
#define E1CP_MAX_AV_PSTATES     60
#define E1CP_MAX_AV_ID          (E1CP_MAX_AV_PSTATES-1)
#define E1CP_MAX_FREQ		1100
#define E1CP_MIN_FREQ		143
#define E1CP_MAX_3D_CLK1X_FREQ	533
#define E1CP_MIN_3D_CLK1X_FREQ	143
#define E1CP_MAX_3D_CLKSH_FREQ	800
#define E1CP_MIN_3D_CLKSH_FREQ	143

#define E1CP_TRANSITION_LATENCY	60000

/* Bypass FIDs */
#define E1CP_BYPASS_FID_P0	0xe0
#define E1CP_BYPASS_FID_P1	0x00
#define E1CP_BYPASS_FID_P2	0x20
#define E1CP_BYPASS_FID_P3	0x60

#define BASE_FREQ		E1CP_BASE_FREQ
#define MAX_FREQ		E1CP_MAX_FREQ
#define MIN_FREQ		E1CP_MIN_FREQ
#define MAX_PSTATES		E1CP_MAX_PSTATES
#define MAX_AV_PSTATES		E1CP_MAX_AV_PSTATES
#define MAX_AV_ID		E1CP_MAX_AV_ID
#define PMC_TRANSITION_LATENCY	E1CP_TRANSITION_LATENCY

#define Fbfs(fref, cfgclksys) (((fref) * (cfgclksys + 10)) / 2)

/* cpufreq subsystem: */
extern struct cpufreq_frequency_table pmc_l_3d_clkSh_freqs[E1CP_MAX_PSTATES];
extern struct cpufreq_frequency_table pmc_l_3d_clk1x_freqs[E1CP_MAX_PSTATES];
/* available frequencies */
extern struct cpufreq_frequency_table
			pmc_l_3d_clk1x_available_freqs[E1CP_MAX_AV_PSTATES];
extern struct cpufreq_frequency_table
			pmc_l_3d_clkSh_available_freqs[E1CP_MAX_AV_PSTATES];
/* dvfs subsystem */
extern struct regulator *vout_regulator;

#endif /* CONFIG_E90S */


/* Moortec temperature sensor values */
#define PMC_MOORTEC_TEMP_VALID          0x1000
#define PMC_MOORTEC_TEMP_VALUE_MASK     0xfff
#define PMC_MOORTEC_TEMP_K              1083
#define PMC_MOORTEC_TEMP_VALUE_SHIFT    12

/* 3D core target registers flags */
#define PMC_L_TARGET_CLK1X	1
#define PMC_L_TARGET_CLKSH	2

/* PMC I2C master */
#define PMC_I2C_REGS_BASE		0x1000
/* From E1CP */

#ifdef CONFIG_E90S
typedef enum pmc_access_regs {
	PMC_L_COVFID_STATUS_REG,   /* 0 */
	PMC_L_P_STATE_CNTRL_REG,   /* 1 */
	PMC_L_P_STATE_STATUS_REG,  /* 2 */
	PMC_L_P_STATE_VALUE_0_REG, /* 3 */
	PMC_L_P_STATE_VALUE_1_REG, /* 4 */
	PMC_L_P_STATE_VALUE_2_REG, /* 5 */
	PMC_L_P_STATE_VALUE_3_REG, /* 6 */
} pmc_reg;

unsigned int s2_reg_to_addr(pmc_reg reg, unsigned int cpu);
void __iomem *__pmc_regs(int node);
unsigned s2_get_freq_mult(int cpu);
#else /* E2K */
extern void __iomem *pmc_cbase; /*Global for e1cp, init in pmc_l_cpufreq_init*/
void __iomem *__pmc_regs(int node);

#endif /* CONFIG_E90S */

/* PMC common function */
#if 0
int  pmc_l_cpufreq_get_state(unsigned int cpu);
void pmc_l_cpufreq_set_state(unsigned int state, unsigned int cpu);
int pmc_l_cpufreq_set_target(struct cpufreq_policy *policy,
				unsigned int target_freq, unsigned int relation);
void pmc_l_cpufreq_update_state_reg(unsigned int state,
				 unsigned int fid, unsigned int cpu);
int pmc_l_cpufreq_verify_policy(struct cpufreq_policy *policy);
unsigned int pmc_l_cpufreq_get(unsigned int cpu);
unsigned int pmc_l_cpufreq_resolve_freq(struct cpufreq_policy *policy,
						unsigned int target_freq);
#endif
int pmc_l_cpufreq_init(struct cpufreq_policy *policy);
int pmc_l_calc_freq_tables(struct cpufreq_policy *policy,
					unsigned int cfgclksys);

/* hwmon */
int  pmc_hwmon_init(void);
void pmc_hwmon_exit(void);

/* legacy sensors interface */
int  pmc_temp_sensors_init(void);
void pmc_temp_sensors_exit(void);

#ifdef CONFIG_E90S
#define pmc_reg_readl(__reg, __cpu)					\
({									\
	int __node = cpu_to_node(__cpu);				\
	void __iomem *__pmc_cbase = __pmc_regs(__node);			\
	unsigned int  __reg_addr  = s2_reg_to_addr(__reg, __cpu);	\
	unsigned int __ret = __raw_readl(__pmc_cbase + __reg_addr);	\
	__ret;								\
})
#define pmc_reg_writel(__val, __reg, __cpu) do { 			\
	int __node = cpu_to_node(__cpu);				\
	void __iomem *__pmc_cbase = __pmc_regs(__node);			\
	unsigned int  __reg_addr  = s2_reg_to_addr(__reg, __cpu);	\
	__raw_writel(__val, __pmc_cbase + __reg_addr);			\
} while (0)
#else /* E2K */
#define pmc_reg_readl(__reg, __cpu) __raw_readl(pmc_cbase + __reg);
#define pmc_reg_writel(__val, __reg, __cpu) __raw_writel(__val, pmc_cbase + __reg);
#endif /* CONFIG_E90S */

/* cpufreq subsystem: */
extern struct cpufreq_frequency_table pmc_l_freqs[MAX_PSTATES];
/* available frequencies */
extern struct cpufreq_frequency_table
			pmc_l_available_freqs[MAX_AV_PSTATES];

#ifndef CONFIG_E90S
extern struct cpufreq_frequency_table
			pmc_l_3d_clk1x_available_freqs[E1CP_MAX_AV_PSTATES];
extern struct cpufreq_frequency_table
			pmc_l_3d_clkSh_available_freqs[E1CP_MAX_AV_PSTATES];
#endif /* !CONFIG_E90S */

#endif /* _PMC_H_ */
