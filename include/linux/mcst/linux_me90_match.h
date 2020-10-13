/*
 * Copyright (c) 1998 by MCST.
 */

/*
 * E90 modules shared interface matching
 */


#ifndef	__LINUX_ME90_MATCH_H__
#define	__LINUX_ME90_MATCH_H__

#ifdef	__cplusplus
extern "C" {
#endif

typedef	trans_buf_t			me90drv_trans_buf_t;
typedef	trbuf_desc_t			me90drv_trbuf_desc_t;
typedef	trans_spec_t			me90drv_trans_spec_t;
typedef	trans_info_t			me90drv_trans_info_t;
typedef	aiotrans_wait_t			me90drv_aiotrans_wait_t;
typedef	drv_intercom_t			me90drv_drv_intercom_t;
typedef	mc_cntr_st_reg_t		me90drv_cntr_st_reg_t;
typedef	mc_rd_reg_t			me90drv_rd_reg_t;
typedef	mc_wr_reg_t			me90drv_wr_reg_t;
typedef	mp_drv_args_t			me90drv_mp_drv_args_t;
typedef	sparc_drv_args_t		me90drv_sparc_drv_args_t;

#ifdef	__MCPM_BOARD_DRIVER__
typedef	mcb_halt_trans_t		me90drv_halt_trans_t;
#endif	/* __MCPM_BOARD_DRIVER__ */

#define	me90drv_state			mcb_state
#define	me90drv_dev_ops			mcb_dev_ops

#define	me90drv_debug			mcb_debug
#define	me90drv_log_msg_num		mcb_log_msg_num
#define	me90drv_max_log_msg_num		mcb_max_log_msg_num

/*
 *  E-90 module registers access
 */

#define	ME90DRV_CNTR_ST_REGS		MC_CNTR_ST_REGS
#define	ME90DRV_RGEN_read		RGEN_read
#define	ME90DRV_RGEN_write		RGEN_write
#define	ME90DRV_TI_reg_type		TI_mc_reg_type
#define	ME90DRV_RERR_reg_type		RERR_mc_reg_type
#define ME90DRV_RGENS_read		MC_RGENS_read
#define ME90DRV_RERR_write		MC_RERR_RNC_write
#define ME90DRV_RGEN_RERR_read		RERR_read
#define ME90DRV_RGEN_RERR_write		RERR_write
#define ME90DRV_RGEN_RERR_get_to_write	RGEN_write
#define ME90DRV_RGEN_TI_read		TI_read
#define ME90DRV_RGEN_TI_write		TI_write
#define ME90DRV_RGEN_TMI_read		TMI_read

/*
 *  E-90 module base memory structure
 */

#define	ME90DRV_BMEM			MC_BMEM
#define	ME90DRV_BMEM_REG_SET_LEN	MC_BMEM_REG_SET_LEN
#define	ME90DRV_INTERDRV_COMN_AREA	ME90DRV_BMEM[TR_CNTR_BUF_BMEM_ADDR]
#define	ME90DRV_MP_HALT_OPCODE		MP_HALT_OPCODE

/*
 *  E-90 module MP-driver communication
 */

#define	me90drv_no_mp_task		no_mp_task
#define	me90drv_no_sparc_task		no_sparc_task

/*
 *  Timeouts default values
 */

#define	ME90DRV_READ_TIMEOUT_DEF_VALUE		READ_TIMEOUT_DEF_VALUE
#define	ME90DRV_WRITE_TIMEOUT_DEF_VALUE		WRITE_TIMEOUT_DEF_VALUE
#define	ME90DRV_BATCH_TIMEOUT_DEF_VALUE		0
#define	ME90DRV_TERMINATE_TIMEOUT_DEF_VALUE	TERMINATE_TIMEOUT_DEF_VALUE
#define	ME90DRV_WATCHDOG_DEF_VALUE		MCB_WATCHDOG_DEF_VALUE

/*
 *  Interrupts handling
 */

#define	ME90DRV_INTR_RESET_BY_MP_TIME		INTR_RESET_BY_MP_TIME
#define	ME90DRV_INTR_RESET_BY_MP_TRYON		INTR_RESET_BY_MP_TRYON
#define	ME90DRV_TASK_ACCEPT_BY_MP_TIME		TASK_ACCEPT_BY_MP_TIME
#define	ME90DRV_TASK_ACCEPT_BY_MP_TRYON		TASK_ACCEPT_BY_MP_TRYON
#define	ME90DRV_TASK_ACCEPT_BY_MP_DELAY_TIME	TASK_ACCEPT_BY_MP_DELAY_TIME

/*
 *  E-90 and private driver function matching
 */

#define	me90drv_reset_general_regs	reset_general_regs
#define	me90drv_submit_mp_task		submit_mp_task
#define	me90drv_init_reg_sets_pointers	init_reg_sets_pointers
#define	me90drv_get_reg_sets_number	get_reg_sets_number
#define	me90drv_put_reg_set_pointer	put_reg_set_pointer
#define	me90drv_init_drv_state		mcb_init_drv_state
#define	me90drv_attach_add		mcb_attach_add
#define	me90drv_detach_add		mcb_detach_add
#define	me90drv_unmap_reg_sets		Unmap_reg_sets
#define	me90drv_intr			mcb_intr
#define	me90drv_finish_dma_engine	finish_mcb_dma_engine
#define	me90drv_delete_trans_header	mcb_delete_trans_header
#define	me90drv_finish_drv_buf_trans	mcb_finish_drv_buf_trans
#define	me90drv_release_async_trans	mcb_release_async_trans
#define	me90drv_abort_dma_transfer	abort_dma_transfer
#define	me90drv_start_new_trans		mcb_start_new_trans
#define	me90drv_handle_trans_finish	mcb_handle_trans_finish
#define	me90drv_set_trans_results	mcb_set_trans_results
#define	me90drv_recover_trans_state	mcb_recover_trans_state
#define	me90drv_read_general_regs	read_general_regs
#define	me90drv_write_general_regs	write_general_regs

#ifdef	__MCPM_BOARD_DRIVER__
#define	me90drv_halt_trans_state	mcb_halt_trans_state
#endif	/* __MCPM_BOARD_DRIVER__ */

#if	defined(__MCKA_BOARD_DRIVER__) || defined(__MCKK_BOARD_DRIVER__) || defined(__MCKP_BOARD_DRIVER__)
#define	me90drv_delete_connection_polling	mcb_delete_connection_polling
#endif	/* defined(__MCKA_BOARD_DRIVER__) || defined(__MCKK_BOARD_DRIVER__) */

#ifdef	_STREAMING_TRANSFER_USED_
#define	me90drv_finish_pseudo_trans	finish_mcb_pseudo_trans
#define	me90drv_finish_str_buf_trans	finish_mcb_drv_buf_trans
#define	me90drv_halt_streaming_trans	mcb_halt_streaming_trans
#define	me90drv_restart_all_stream_channel	mcb_restart_all_stream_channel
#endif	/* _STREAMING_TRANSFER_USED_ */

/*
 *  E-90 and private driver hardware parameters matching
 */

#define	MAX_ME90DRV_BOARD_CHANNEL_NUM	MAX_MC_BOARD_CHANNEL_NUM

#ifdef	__cplusplus
}
#endif

#endif /* __LINUX_ME90_MATCH_H__ */
