/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _L_ASM_L_TIMER_REGS_H
#define _L_ASM_L_TIMER_REGS_H

#include <linux/types.h>

/*
 * Elbrus System timer Registers (litlle endian)
 */

typedef union {
	struct {
		u32	unused 	: 9;	/* [8:0] 	*/
		u32	c_l	: 22;	/* [30:9] 	*/
		u32	l	: 1;	/* [31]		*/ 	
	};
	u32 word;
} counter_limit_t;

typedef union {
	struct {
		u32	w_m	: 1;	/* [0] */
		u32	w_out_e	: 1;	/* [1] */
		u32	w_evn	: 1;	/* [2] */
		u32	unused	: 29;	/* [31:3] */
	};
	u32	word;
} wd_control_t;

#endif	/* _L_ASM_L_TIMER_REGS_H */
