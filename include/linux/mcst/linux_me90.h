/*
 * Copyright (c) 1996 by MCST.
 */

#ifndef	__LINUX_ME90_H__
#define	__LINUX_ME90_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include <linux/mcst/linux_me90_def.h>

/*
 * Defines and structures useable by both the driver
 * and user application go here.
 */

/*
 * Timeout processing definitions
 */

typedef enum   timeout_type_t_
{
	no_timeout_type,		/* no any timeout */
	read_timeout_type,		/* read I/O command */
	write_timeout_type,		/* write I/O command */
	batch_timeout_type,		/* batch of I?O operations */
	terminate_timeout_type		/* termination of I/O transfer */
} timeout_type_t;

typedef long	timeout_value_t;

#define ME90_WATCHDOG_DEF_VALUE			(1000000)	/* 1 seconds */

#define	ME90_CHANNEL_FREE_TIMEOUT_DEF_VALUE	(10000000)	/* 10 seconds */
#define	ME90_DRV_COMM_FREE_TIMEOUT_DEF_VALUE	(1000000)	/*  1 seconds */
#define	ME90_TERMINATE_TIMEOUT_DEF_VALUE	(2 * 1000000)	/*  2 sec */

/*
 * Interdriver communication waiting times
 */

#define ME90_INTR_RESET_BY_MP_TIME		( 1000)
#define ME90_INTR_RESET_BY_MP_TRYON		  1000
#define ME90_INTR_RESET_BY_MP_DELAY_TIME	(    1)
#define ME90_TASK_ACCEPT_BY_MP_TIME		( 1000)		/* usec */
#define ME90_TASK_ACCEPT_BY_MP_TRYON		 10000		/* times */
#define ME90_TASK_ACCEPT_BY_MP_DELAY_TIME	(   10)		/* usec */

/*
 * Local definitions, for clarity of code
 */

#define ME90_DEVN(d)	(getminor(d))		/* dev_t -> minor (dev_num) */
#define ME90_inst(m)	(m >> 4)		/* minor -> instance */
#if	!defined(__CNTR_DEV_BOARD_TYPE__) && !defined(__INTR_DEV_BOARD_TYPE__)
#define ME90_chan(m)	(m & 0xf)		/* minor -> channel */
#define ME90_MINOR(i,c)	((i << 4) | (c))	/* instance+channel -> minor */
#define ME90_INST(d)	ME90_inst(ME90_DEVN(d))	/* dev_t -> instance */
#define ME90_CHAN(d)	ME90_chan(ME90_DEVN(d))	/* dev_t -> channel */
#elif	defined(__CNTR_DEV_BOARD_TYPE__)
#define ME90_module(m)		(m & 0xf)	/* minor -> module */
#define	ME90_mod_chan(m)	(m & 0x7)	/* module -> channel */
						/* module -> controller flag */
#define	ME90_mod_cntr(m)	((m >> 3) & 0x1)
						/* minor -> channel */
#define ME90_chan(m)		ME90_mod_chan(ME90_module(m))
						/* minor -> controller */
#define ME90_cntr(m)		ME90_mod_cntr(ME90_module(m))
						/* channel+controller flag -> */
						/* module */
#define ME90_MODULE(chn,cnt)	((chn) | ((cnt) << 3))
						/* instance+module -> minor */
#define ME90_MINOR_mod(i,mod)	((i << 4) | (mod))
						/* instance+ channel+cntr -> */
						/* module */
#define ME90_MINOR(i,chn,cnt)	ME90_MINOR_mod(i,ME90_MODULE(chn,cnt))
						/* dev_t -> instance */
#define ME90_INST(d)		ME90_inst(ME90_DEVN(d))
						/* dev_t -> module */
#define ME90_MOD(d)		ME90_module(ME90_DEVN(d))
						/* dev_t -> channel */
#define ME90_CHAN(d)		ME90_mod_chan(ME90_MOD(d))
						/* dev_t -> controller */
#define ME90_CNTR(d)		ME90_mod_cntr(ME90_MOD(d))
#elif	defined(__INTR_DEV_BOARD_TYPE__)
#define ME90_module(m)		(m & 0xf)	/* minor -> module */
#define	ME90_mod_chan(m)	(m & 0x7)	/* module -> channel */
						/* module -> interrupt flag */
#define	ME90_mod_intr_flag(m)	((m >> 3) & 0x1)
#define	ME90_mod_intr_num(m)	(m & 0x7)	/* module -> interrupt # */
						/* minor -> channel */
#define ME90_chan(m)		ME90_mod_chan(ME90_module(m))
						/* minor -> interrupt flag */
#define ME90_intr_flag(m)	ME90_mod_intr_flag(ME90_module(m))
						/* minor -> interrupt # */
#define ME90_intr_num(m)	ME90_mod_intr_num(ME90_module(m))
						/* # of channel or interrupt */
						/* + flag of interrupt -> */
						/* module */
#define ME90_MODULE(num,flag)	((num) | ((flag) << 3))
						/* channel -> module */
#define ME90_CHNL_MODULE(chnl)	ME90_MODULE(chnl, 0)
						/* interrupt # -> module */
#define ME90_INTR_MODULE(intr)	ME90_MODULE(intr, 1)
						/* instance+module -> minor */
#define ME90_MINOR_mod(i,mod)	((i << 4) | (mod))
						/* instance + # of channel or */
						/* interrupt + flag of intr */
						/* -> minor */
#define ME90_MINOR(i,num,flag)	ME90_MINOR_mod(i, ME90_MODULE(num, flag))
						/* instance + # of channel */
						/* -> minor */
#define ME90_CHNL_MINOR(i,chnl)	ME90_MINOR_mod(i, ME90_CHNL_MODULE(chnl))
						/* instance + # of interrupt */
						/* -> minor */
#define ME90_INTR_MINOR(i,intr)	ME90_MINOR_mod(i, ME90_INTR_MODULE(intr))
						/* dev_t -> instance */
#define ME90_INST(d)		ME90_inst(ME90_DEVN(d))
						/* dev_t -> module */
#define ME90_MOD(d)		ME90_module(ME90_DEVN(d))
						/* dev_t -> channel */
#define ME90_CHAN(d)		ME90_mod_chan(ME90_MOD(d))
						/* dev_t -> interrupt flag */
#define ME90_INTR_flag(d)	ME90_mod_intr_flag(ME90_MOD(d))
						/* dev_t -> interrupt # */
#define ME90_INTR_num(d)	ME90_mod_intr_num(ME90_MOD(d))
#endif	/* __CNTR_DEV_BOARD_TYPE__ or __INTR_DEV_BOARD_TYPE__ */

#define	CHNL_NUM_TO_MASK(chnl)		(1 << chnl)
#define	CHNL_NUM_TO_CNTR_MASK(chnl)	CHNL_NUM_TO_MASK(chnl)
#define	CHANNEL_IS_CNTR(state,chnl)	((state -> cntr_flag_map &	\
					 CHNL_NUM_TO_CNTR_MASK(chnl)) != 0)

#define	INTR_NUM_TO_MASK(intr)		(1 << intr)

/*
 * Interrupts mask operations encoding
 */

#define	open_intr_mask_op		1	/* open the mask of intr */
#define	close_intr_mask_op		2	/* close the mask of intr */
#define	write_intr_mask_op		3	/* write the mask of intr */
#define	assign_intr_mask_op		4	/* assign the mask of intr */
						/* only current mask state */
						/* is changed not real mask */
						/* of device */

/*
 *  Internal error codes list
 */

#define	ESTRMHALT	230	/* Streaming transfer was halted already */
#define	EMPRESTART	231	/* MP restart and transfer retrieval occured */
#define	EMULTIBUF	232	/* multi-buffered transfer cannot be used */

/*
 *  Transfer states list
 */

typedef enum   trans_state_t_           /* list of channel transfer states */
{
	no_trans_state,                 /* no any transfer */
	started_trans_state,		/* transfer started */
	in_progress_trans_state,	/* transfer in progress */
	timeout_trans_state,	        /* transfer desisted by timeout */
	aborted_trans_state,		/* transfer aborted */
	completed_trans_state		/* transfer completed */
} trans_state_t;

/*
 *  MP of module states list
 */

typedef enum	mp_state_t_
{
	undef_mp_state,                 /* undefined state of MP */
	halted_mp_state,		/* MP is in the halted state */
	started_mp_state,		/* MP was started and in the action */
	hangup_mp_state,		/* hangup of MP */
	crash_mp_state,			/* crash of MP */
	fault_mp_state,			/* board or MP internal fault occured */
	adapter_abend_mp_state,		/* adapter internal abend occured */
	locked_mp_state,		/* MP is in the locked state */
	restarted_mp_state		/* MP is restarted */
} mp_state_t;

/*
 *  E90 module restart types list
 */

typedef	enum me90_restart_type {
	check_and_do_restart_type,
	start_restart_type,
	do_restart_type,
	continue_restart_type
} me90_restart_type_t;

/*
 *  E90 module restart states list
 */

typedef	enum me90_restart_state {
	no_restart_state,
	started_restart_state,
	started_mp_restart_state,
	wait_mp_restart_state,
	finished_mp_restart_state,
	recovery_restart_state,
	wait_recovery_restart_state,
	recovered_restart_state,
	
} me90_restart_state_t;

/*
 * Bit fields for attach_flags:
 */

#define SOFT_STATE_ALLOCATED		0x0001
#define INTERRUPT_ADDED			0x0002
#define MUTEX_ADDED			0x0004
#define CHANNEL_CV_ADDED		0x0008
#define REGS_MAPPED			0x0010
#define MINOR_NODE_CREATED		0x0020
#define IOPB_ALLOCED			0x0040
#define ERRORS_SIGN			0x0080
#define IBLOCK_COOKIE_ADDED		0x0200
#define	INTR_IBLOCK_COOKIE_ADDED	0x0400
#define	INTR_MUTEX_ADDED		0x0800
#define	TRANS_HALTED_CV_ADDED		0x1000
#define	CNCT_POLLING_CV_ADDED		0x2000
#define	TRANS_STATE_CV_ADDED		0x4000

/*
 * Debug level and message log definitions
 */

#define CE_CONT		6 //KERN_INFO
#define CE_NOTE		5 //KERN_NOTICE
#define CE_WARN 	4 //KERN_WARNING
#define CE_PANIC	3 //KERN_ERR

#define	ME90_DL_ERROR		((1 << 8) | CE_CONT)	/* 1 - errors */
#define	ME90_DL_WARNING		((2 << 8) | CE_CONT)	/* 2 - errors */
#define	ME90_DL_TRACE		((3 << 8) | CE_CONT)	/* 3 - trace */
#define	ME90_DL_REGS_MAP	((4 << 8) | CE_CONT)	/* 4 - reg maping */
#define	ME90_DL_MINOR		((4 << 8) | CE_CONT)	/* 4 - minor node */
#define	ME90_DL_REGS_OP		((4 << 8) | CE_CONT)	/* 4 - reg rd/wr */

#define	ME90_LOG		if (me90drv_debug) me90_log

/*
 * Device properties name
 */

#define SBUS_INTR_L_NAME_OF_PROP 	"interrupts"

#ifdef	__cplusplus
}
#endif

#endif	/* __LINUX_ME90_H__ */
