#ifndef _L_ASM_L_TIMER_REGS_H
#define _L_ASM_L_TIMER_REGS_H

#include <linux/types.h>

/*
 * Elbrus System timer Registers
 */

#define COUNTER_LIMIT		0x00
typedef struct counter_limit_fields {
	u32	unused 	: 9;	/* [8:0] 	*/
	u32	c_l	: 22;	/* [30:9] 	*/
	u32	l	: 1;	/* [31]		*/ 	
} counter_limit_fields_t;
typedef union counter_limit {
	u32	word;
	counter_limit_fields_t fields;
} counter_limit_t;
#define COUNTER_START_VALUE	0x04
typedef struct counter_st_v_fields {
	u32	unused 	: 9;	/* [8:0] 	*/
	u32	c_st_v	: 22;	/* [30:9] 	*/
	u32	l	: 1;	/* [31]		*/ 	
} counter_st_v_fields_t;
typedef union counter_st_v {
	u32	word;
	counter_st_v_fields_t fields;
} counter_st_v_t;
#define COUNTER			0x08
typedef struct counter_fields {
	u32	unused 	: 9;	/* [8:0] 	*/
	u32	c	: 22;	/* [30:9] 	*/
	u32	l	: 1;	/* [31]		*/ 	
} counter_fields_t;
typedef union counter {
	u32	word;
	counter_fields_t fields;
} counter_t;
#define COUNTER_CONTROL		0x0c
typedef struct counter_control_fields {
	u32	s_s	: 1;	/* [0] */
	u32	inv_l	: 1;	/* [1] */
	u32	l_ini	: 1;	/* [2] */
	u32	unused	: 29;	/* [31:3] */
} counter_control_fields_t;
typedef union counter_control {
	u32	word;
	counter_control_fields_t fields;
} counter_control_t;
#define WD_COUNTER_L		0x10
typedef struct wd_counter_l_fields {
	u32	wd_c	: 32;	/* [31:0] */	
} wd_counter_l_fields_t;
typedef	union wd_counter_l {
	u32	word;
	wd_counter_l_fields_t fields;
} wd_counter_l_t;
#define WD_COUNTER_H		0x14
typedef struct wd_counter_h_fields {
	u32	wd_c	: 32;	/* [31:0] */	
} wd_counter_h_fields_t;
typedef	union wd_counter_h {
	u32	word;
	wd_counter_h_fields_t fields;
} wd_counter_h_t;
#define WD_LIMIT		0x18
typedef struct wd_limit_fields {
	u32	wd_l	: 32;	/* [31:0] */	
} wd_limit_fields_t;
typedef	union wd_limit {
	u32	word;
	wd_limit_fields_t fields;
} wd_limit_t;	
#define POWER_COUNTER_L		0x1c
typedef struct power_counter_l_fields {
	u32	pw_c	: 32;	/* [31:0] */	
} power_counter_l_fields_t;
typedef	union power_counter_l {
	u32	word;
	power_counter_l_fields_t fields;
} power_counter_l_t;
#define POWER_COUNTER_H		0x20
typedef struct power_counter_h_fields {
	u32	pw_c	: 32;	/* [31:0] */	
} power_counter_h_fields_t;
typedef	union power_counter_h {
	u32	word;
	power_counter_h_fields_t fields;
} power_counter_h_t;	
#define WD_CONTROL		0x24
typedef struct wd_control_fields {
	u32	w_m	: 1;	/* [0] */
	u32	w_out_e	: 1;	/* [1] */
	u32	w_evn	: 1;	/* [2] */
	u32	unused	: 29;	/* [31:3] */
} wd_control_fields_t;
typedef union wd_control {
	u32	word;
	wd_control_fields_t fields;
} wd_control_t;
#define RESET_COUNTER_L		0x28
typedef struct reset_counter_l_fields {
	u32	rst	: 32;	/* [31:0] */	
} reset_counter_l_fields_t;
typedef	union reset_counter_l {
	u32	word;
	reset_counter_l_fields_t fields;
} reset_counter_l_t;
#define RESET_COUNTER_H		0x2c
typedef struct reset_counter_h_fields {
	u32	rst	: 32;	/* [31:0] */	
} reset_counter_h_fields_t;
typedef	union reset_counter_h {
	u32	word;
	reset_counter_h_fields_t fields;
} reset_counter_h_t;

#endif	/* _L_ASM_L_TIMER_REGS_H */
