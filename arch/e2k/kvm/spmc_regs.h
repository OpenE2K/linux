#ifndef _KVM_SPMC_REGS_H
#define _KVM_SPMC_REGS_H

#include <linux/types.h>

/*
 * System Power Management Controller registers offsets into configuration space
 */
#define SPMC_PM_TMR_OFF		0x40
#define SPMC_PM1_STS_OFF	0x44
#define SPMC_PM1_EN_OFF		0x48
#define SPMC_PM1_CNT_OFF	0x4c
#define SPMC_ATNSUS_CNT_OFF	0x50
#define SPMC_PURST_CNT_OFF	0x54

#define	SPMC_REGS_CFG_OFFSET	SPMC_PM_TMR_OFF
#define	SPMC_REGS_CFG_LENGTH	(SPMC_PURST_CNT_OFF + 4 - SPMC_PM_TMR_OFF)

/*
 * System Power Management Controller registers structures
 */

typedef union spmc_pm_tmr {
	u32	reg;
	struct {			/* as fields	*/
		u32 counter		: 32;	/* [31: 0] */
	};
	struct {			/* as fields	*/
		u32 counter_0_22	: 23;	/* [22: 0] */
		u32 counter_23		:  1;	/* [23] */
		u32 counter_24_31	:  8;	/* [31:24] */
	};
	struct {			/* as fields	*/
		u32 counter_0_30	: 31;	/* [30: 0] */
		u32 counter_31		:  1;	/* [31] */
	};
} spmc_pm_tmr_t;

typedef union spmc_pm1_sts {
	u32	reg;
	struct {			/* as fields	*/
		u32 tmr_sts		:  1;	/* [ 0] */
		u32 ac_power_state	:  1;	/* [ 1] */
		u32 ac_power_sts	:  1;	/* [ 2] */
		u32 batlow_state	:  1;	/* [ 3] */
		u32 batlow_sts		:  1;	/* [ 4] */
		u32 atn_sts		:  1;	/* [ 5] */
		u32 reserved1		:  2;	/* [ 7: 6} */
		u32 pwrbtn_sts		:  1;	/* [ 8] */
		u32 reserved2		:  6;	/* [14: 9} */
		u32 wak_sts		:  1;	/* [15] */
		u32 reserved3		: 16;	/* {31:16] */
	};
} spmc_pm1_sts_t;

typedef union spmc_pm1_en {
	u32	reg;
	struct {			/* as fields	*/
		u32 tmr_en		:  1;	/* [ 0] */
		u32 tmr_32		:  1;	/* [ 1] */
		u32 ac_pwr_en		:  1;	/* [ 2] */
		u32 reserved1		:  1;	/* [ 3} */
		u32 batlow_en		:  1;	/* [ 4] */
		u32 reserved2		:  3;	/* [ 7: 5} */
		u32 pwrbtn_en		:  1;	/* [ 8] */
		u32 reserved3		: 23;	/* {31: 9] */
	};
} spmc_pm1_en_t;

typedef union spmc_pm1_cnt {
	u32	reg;
	struct {			/* as fields	*/
		u32 sci_en		:  1;	/* [ 0] */
		u32 reserved1		:  9;	/* [ 9: 1} */
		u32 slp_typx		:  3;	/* [12:10] */
		u32 slp_en		:  1;	/* [13] */
		u32 reserved2		: 18;	/* {31:14] */
	};
} spmc_pm1_cnt_t;

typedef union spmc_atnsus_cnt {		/* attention suspend counter */
	u32	reg;
	struct {			/* as fields	*/
		u32 counter		: 32;	/* [31: 0] */
	};
} spmc_atnsus_cnt_t;

typedef union spmc_pu_rst_cnt {		/* power up reset counter */
	u32	reg;
	struct {			/* as fields	*/
		u32 counter		: 32;	/* [31: 0] */
	};
} spmc_pu_rst_cnt_t;

#define	SPMC_PU_RST_CNT_MIN	0x00004000UL	/* minimal value: ~4.5 msk */

typedef enum spmc_sleep_state {
	SPMC_S0_SLEEP_STATE	= 0,	/* G0 */
	SPMC_S3_SLEEP_STATE	= 3,	/* G1 */
	SPMC_S4_SLEEP_STATE	= 4,	/* G1 */
	SPMC_S5_SLEEP_STATE	= 5,	/* G2 */
	/* states 1, 2, 6, 7 - are not supported and == S0 (G0) */
} spmc_sleep_state_t;

typedef enum spmc_g_state {
	SPMC_G0_STATE	= 0,	/* G0 */
	SPMC_G1_STATE	= 1,	/* G1 */
	SPMC_G2_state	= 2,	/* G2 */
} spmc_g_state_t;

typedef enum spmc_irq_map {
	SPMC_SCI_IRQ_ID	=  1,
} spmc_irq_map_t;

#define	EIOH_SPMC_PM_TIMER_FREQ		3579545		/* Herz */

#endif	/* _KVM_SPMC_REGS_H */
