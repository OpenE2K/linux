#ifndef	__LINUX_MCKA_H__
#define	__LINUX_MCKA_H__

#include <linux/mcst/ddi.h>
#include <linux/mcst/linux_mcb.h>

/*
 * Defines and structures useable by both the driver
 * and user application go here.
 */

#define	mod_name	"mcka"
#define MCKA_DIR	"mcka"
#define MCKA_NAME	"MCST,mcka" /* should be same as FCODE.name */

/*
 * Device request queuing
 */

typedef struct drq_trans_spec
{
//	buf_t *				bp;
	uio_t *				uio_p;
	struct drq_trans_spec *		next_trans_spec;
} drq_trans_spec_t;

/*
 * Internal driver state per channel
 */

typedef struct mcka_chnl_state {
	int		busy;			/* channel is busy by I/O */
						/* operation */
	int		in_progress;		/* chanel has transfer in */
						/* progress */
	int		streaming;		/* continuous streaming */
						/* channel type flag */
	trans_buf_t *	wait_list_start;	/* start of list of buffers */
						/* waiting for transfer or */
						/* free buffers  */
	trans_buf_t *	wait_list_end;		/* end of list of buffers */
						/* waiting for transfer or */
						/* free buffers  */
	int		wait_list_size;		/* size of list of buffers */
						/* waiting for transfer or */
						/* free buffers  */
/*	buf_t *		multi_buf_lock;	*/	/* system buffer pointer of */
	uio_t *		multi_buf_lock;		/* multi-buffers transfer */
						/* which locks other until */
						/* all buffers will be */
						/* transfered */
	trans_buf_t *	in_progress_start; 	/* buffer of transfer in */
						/* progress list start */
	trans_buf_t *	in_progress_end; 	/* buffer of transfer in */
						/* progress list end */
	int		in_progress_size; 	/* buffer of transfer in */
						/* progress list size */
	trans_buf_t *	completed_trans_start;	/* start of list of completed */
						/* transfers */
	trans_buf_t *	completed_trans_end;	/* end of list of completed */
						/* transfers */
	int		completed_trans_size;	/* size of list of completed */
						/* transfers */
	trans_buf_t *	ready_atrans_start;	/* start of list of ready */
						/* asynchronous transfers */
	trans_buf_t *	ready_atrans_end;	/* end of list of ready */
						/* asynchronous transfers */
	int		ready_atrans_size;	/* size of list of ready */
						/* asynchronous transfers */
	int		async_trans_num;	/* currnet number of */
						/* asynchronous request in */
						/* services */
	int		term_trans_processed;	/* completed transfers are */
						/* processing now flag */
	trans_buf_t *	last_term_trans_buf;	/* header of last terminated */
						/* transfer */
#ifdef	_STREAMING_TRANSFER_USED_
    streaming_spec_t     streaming_specs ; /* streaming specifications */
    int			 cur_trans_buf_num;/* current number of existent
					      transfer buffers */
    trans_buf_t *        ready_list_start; /* start of list of ready buffers */
    trans_buf_t *        ready_list_end  ; /* end of list of ready buffers */
    int                  ready_list_size ; /* size of list of ready buffers */
    trans_buf_t *        next_trans_buf  ; /* next transfer buffer */
    mcb_drv_buf_t *	 wait_data_start ; /* start of list of transfers wait
					      for ready data from streaming */
    mcb_drv_buf_t *	 wait_data_end   ; /* end of list of transfers wait
					      for ready data from streaming */
    int			 wait_data_size  ; /* size of list of transfers wait
					      for ready data from streaming */
    int			 missed_data_size;      /* missed data size to pseudo
					           buffers transfer */
    mc_rd_reg_t	         miss_reg_state;        /* general register of board
                                                   state for miss of data */
    u_char	         miss_mp_error_code;	/* MP detected errors code 
                                                   for data miss */
    u_char	         miss_sparc_error_code;	/* SPARC driver detected errors
                                                   code for data miss */
    u_char               miss_board_state_byte;	/* byte of board or device
                                                   state for data miss */
    u_char		 miss_sp_state_byte;    /* state byte of SYNCHRO-PLIC */
    int                  streaming_is_init; /* streaming transfer is inited */
    int                  streaming_is_halt; /* streaming transfer is halted */
    int                  streaming_error;   /* channel is in error mode */
    int			 last_trans_finish; /* last (halt) transfer finished */
#endif	/* _STREAMING_TRANSFER_USED_ */
    int                  pseudostreaming  ; /* pseudostreaming mode flag */
	int		dma_intr_handled;	/* interrupt is handled just */
	u_short		trans_num;		/* unique # of batch I/O */
						/* transfer */
	trans_state_t	transfer_state;		/* channel transfer state */
	timeout_type_t	timeout_type;		/* channel timeout type */
	timeout_value_t	timeout_rem;		/* channel timeout remainder */
	timeout_type_t	last_timeout_type;	/* last channel timeout type */
	timeout_value_t	last_timeout_value;	/* channel timeout value */
	int		drq_queue_size;		/* number of transfer in */
						/* queue */
	drq_trans_spec_t
			*drq_queue_start;	/* DRQ waiting transfer queue */
	drq_trans_spec_t
			*drq_queue_end;		/* DRQ waiting transfer */
						/* queue end */
} mcka_chnl_state_t;

/*
 * Internal driver state per instance
 */

typedef struct mcka_state {
	struct of_device	*op;
	int				inst;
	dev_t			dev;
	int				major;
	int				opened;			/* open state. */
	int				open_flags;		/* opened with flag state. */
	u_int			open_channel_map;	/* mask of open channels */
	u_int			cntr_flag_map;		/* mask of channels is controller */
	kmutex_t		mutex;		/* mutex. */
	raw_spinlock_t	lock;
	kcondvar_t		channel_cv;	/* channel condition variable */
	kcondvar_t		trans_start_cv;	/* transfer started event */
						/* condition variable */
	kcondvar_t		atrans_end_cv;	/* asynchronous transfer end */
						/* event condition variable */
	kcondvar_t		drv_comm_cv;	/* driver communication area */
						/* busy free condition */
						/* variable */
//  pid_t pid_state_mcka_intr_handler;
//  pid_t pid_mcka_watchdog_handler;
//  wait_queue_head_t	state_mcka_intr_handler;
//  wait_queue_head_t	mcka_watchdog_handler;
	struct work_struct 	interrupt_tqueue;
	struct work_struct  watchdog_tqueue; 

	mc_rd_reg_t       read_value;

//	int waking_up_mcka_intr_handler;
//	int state_mcka_intr_handler_shutdown;
//	int waking_up_mcka_watchdog_handler;
//	int mcka_watchdog_handler_shutdown;

	/* ddi_iblock_cookie_t  iblock_cookie   ;*/ /* for mutexes. */
	int			drv_comm_busy;		/* driver communication area busy flag */
	int			drv_general_modes;	/* driver general mode flafs */
	e90_unit_t	type_unit;			/* type of board. */
	char		intr_seted;			/* interrupt seted. */
	char		intr_number;		/* number of interrupts. */
	int			system_burst;		/* DMA burst sizes allowed by SBUS */
	char		mp_drv_loaded;		/* MP deriver was loaded */
	char		mp_debug_drv_flag;	/* debug driver startuped flag */
	char		mp_rom_drv_enable;	/* MP ROM driver is enable flag */
	mp_state_t	mp_state;			/* MP current state */
	char		mp_drv_started;		/* MP driver was been started up */
	char		set_tlrm;			/* set reset module on error lock */
	char		trans_mode_inited;	/* transfer mode inited */
	char		trans_mode_init_error; /* error detected by MP in transfer mode initialization */
	bmem_trans_desk_t	mp_init_code;/* MP start up code descriptor */
	char		mp_init_area_copy[MP_INIT_AREA_BMEM_SIZE];                                 /* MP start up code */
	mp_drv_args_t	 mp_drv_init_info;	/* MP driver init info */
#ifdef	_STREAMING_TRANSFER_USED_
	trans_buf_t		*pseudo_trans_buf;	/* pointer of real system pseudo
					        streaming transfer  buffer */
	trans_buf_t		*free_pseudo_start;	/* start of list of free pseudo                    buffers */
	trans_buf_t		*free_pseudo_end;	/* end of list of free pseudo buffers */
	int				free_pseudo_size;	/* size of list of free pseudo buffers */
	kcondvar_t		trans_halted_cv;	/* all transfer halted condition variable */
#endif	/* _STREAMING_TRANSFER_USED_ */

	int			connection_state;			/* current connection state */

	int			cnct_polling_error;			/* error detected by */
						/* connection polling */
	kcondvar_t	cnct_polling_cv;			/* connection polling state */
						/* condition variable */
	hrtime_t	alive_intr_time;			/* time of last interrupt to */
						/* set alive connection state */
	hrtime_t	refused_intr_time;			/* time of last interrupt to */
						/* set refused state */
	poll_event_info_t	*connection_events;	/* connection state polling */
						/* events info */
	int			max_cnct_events_num;		/* max number of connection */
						/* events */
	int			cur_cnct_events_num;		/* max number of connection */
						/* events */
	int			losed_events_num;			/* number of losed connection */
						/* events */
	int			timeouts_num;				/* current total timeouts number */
	struct timer_list	timeout_idnt;		/* timeout identifier */
	timeout_type_t		timeout_type;		/* General timeout type */
	timeout_value_t		timeout_rem;		/* General timeout remainder */
	volatile mcb_reg_sets_t	mcb_reg_sets;	/* all board register sets */
    mcka_chnl_state_t	all_channels_state[MAX_MC_BOARD_CHANNEL_NUM];	/* all board channel states */
    mp_intr_spec_t       mp_timer_intrs;   /* MP timer interrupts processing */
} mcka_state_t;

extern	void	*mcka_state;	/* driver state list pointer */

/*
 *  The driver function prototypes
 */

int	mcb_rdwr(
	dev_t		dev,
	struct uio	*uio_p,
	int		flag,
	trans_spec_t	*transfer_spec
);
#ifdef	__MCPM_BOARD_DRIVER__
int	mcb_init_trans_state(
	mcka_state_t	*mcb,
	int		channel,
	mcb_init_trans_t	*init_state_args,
	int		drv_comm_area_locked,
	int		*error_code,
	int		state_recover
);
int	mcb_halt_trans_state(
	mcka_state_t	*mcb,
	int		channel,
	mcb_halt_trans_t	*halt_trans_state,
	int		drv_comm_area_locked,
	int		user_request,
	int		mutex_locked
);
#endif	/* __MCPM_BOARD_DRIVER__ */
#ifdef	_STREAMING_TRANSFER_USED_
int	mcb_init_streaming(
	mcka_state_t		*state,
	int			channel,
	streaming_spec_t	*streaming_specs
);
int	mcb_halt_streaming_trans(
	mcka_state_t	*state,
	int		channel,
	int		*trans_rem_size_p,
	int		mutex_locked
);
#endif	/* _STREAMING_TRANSFER_USED_ */
#if	defined(__MCKP_BOARD_DRIVER__) || defined(__MCAP_BOARD_DRIVER__)
int	mcb_init_trans_mode(
	mcka_state_t	*mcb,
	int		drv_comm_area_locked
);
#endif	/* defined(__MCKP_BOARD_DRIVER__) || defined(__MCAP_BOARD_DRIVER__) */

#ifdef	__MCKP_BOARD_DRIVER__
int	mcb_set_work_timetable(
	mcka_state_t	*mcb,
	int		channel,
	int		drv_comm_area_locked
);
int	mcb_halt_trans_mode(mcka_state_t		*mcb);
#endif	/* __MCKP_BOARD_DRIVER__ */
void	mcb_release_async_trans(
	mcka_state_t	*state,
	int		channel,
	trans_buf_t	*trans_buf_p
);
int	get_reg_sets_number(
	e90_unit_t	type_unit,
	char		get_max_num
);
void	init_reg_sets_pointers(
	mcka_state_t	*state,
	e90_unit_t	type_unit
);
int	put_reg_set_pointer(
	mcka_state_t	*state,
	u_int		i_reg_gr,
	caddr_t		regs_mass
);
void	Unmap_reg_sets(
	mcka_state_t	*state
);
void 	mcb_init_drv_state(
	mcka_state_t	*state
);
int	mcb_attach_add(
	mcka_state_t	*state,
	int		*add_attach_flags
);
void	mcb_detach_add(
	mcka_state_t	*state,
	int		add_attach_flags,
	int		uncondit_detach
);
void	mcb_interrupt(
	int irq, 
	caddr_t arg, 
	struct pt_regs *regs
);
void	finish_mcb_dma_engine(
	mcka_state_t	*mcb,
	int		channel,
	trans_buf_t	*trans_buf_p,
	int		mutex_locked
);
void	mcb_handle_trans_finish(
	mcka_state_t	*state,
	int		channel,
	trans_result_t	*trans_results,
	mc_rd_reg_t	gen_reg_state,
#ifdef	_MP_TIME_USE_
	u_int		intr_transfer_end,
#else
	hrtime_t	intr_transfer_end,
#endif	/* _MP_TIME_USE_ */
	int		trans_aborted
);
#ifdef	_STREAMING_TRANSFER_USED_
void	finish_mcb_pseudo_trans(
	mcka_state_t	*state,
	int		channel,
	trans_buf_t	*trans_buf_p,
	int		mutex_locked
);
void	finish_mcb_drv_buf_trans(
	mcka_state_t	*state,
	int		channel,
	trans_buf_t	*trans_buf_p,
	int		mutex_locked
);
int	mcb_restart_all_stream_channel(
	mcka_state_t	*state,
	int		drv_comm_area_locked
);
#endif	/* _STREAMING_TRANSFER_USED_ */
int	abort_dma_transfer(
	mcka_state_t	*state,
	int		channel
);
void	mcb_delete_trans_header(
	mcka_state_t	*state,
	trans_buf_t	*trans_buf_p
);
int	mcb_finish_drv_buf_trans(
	mcka_state_t	*state,
	int		channel,
	trans_buf_t	*trans_buf_p
);
void	mcb_start_new_trans(
	mcka_state_t	*state,
	int		channel
);
int	mcb_recover_trans_state(
	mcka_state_t	*state,
	int		drv_comm_area_locked,
	int		mutex_locked
);
void	mcb_delete_connection_polling(
	mcka_state_t	*state,
	int		reset_error
);
int	handle_mp_timer_intr_request(
	mcka_state_t		*state,
	mp_tm_intr_info_t	*mp_timer_intr_info
);
void	remove_mp_timer_intr(
	mcka_state_t	*state
);
int	mcb_set_connection_polling(
	mcka_state_t	*state,
	cnct_poll_set_t	*polling_setup_spec
);
int	mcb_reset_connection_polling(
	mcka_state_t	*state,
	int		reset_error
);
int	mcb_poll_connection_state(
	mcka_state_t		*state,
	poll_cnct_state_t	*state_spec
);
int	reset_general_regs(
	mcka_state_t	*state,
  	int		mp_state
);
void	read_general_regs(
	volatile mc_cntr_st_reg_t	*general_regs,
	mc_reg_type_t			read_regs_mask, 
	mc_rd_reg_t			*read_value
);
void	write_general_regs(
	volatile mc_cntr_st_reg_t	*general_regs,
	mc_reg_type_t			write_regs_mask,
	mc_wr_reg_t			TLRM_write_value,
	mc_rd_reg_t			*benchmark_value
);
int	submit_mp_task(
	mcka_state_t		*state,
	mp_task_t		mp_task,
	mp_drv_args_t		*task_args,
	int			mutex_enter_done,
	trans_info_t		*trans_res_info,
	sparc_drv_args_t	*mp_task_results,
	int			restart
);

#ifndef	__MCPM_BOARD_DRIVER__
int	mcb_set_trans_results(
	mcka_state_t		*mcb,
	trans_info_t		*drv_trans_res_info_p,
	trans_info_t		*drv_results_p,
	trans_info_t		*user_trans_res_info_p,
	int			mode
);
#elif	defined(__MCPM_BOARD_DRIVER__)
int	mcb_set_trans_results(
	mcka_state_t		*mcb,
	trans_info_t		*drv_trans_res_info_p,
	mcpm_trinfo_t		*drv_results_p,
	mcpm_trinfo_t		*user_trans_res_info_p,
	int			mode
);
#endif	/* defined(__MCPM_BOARD_DRIVER__) or other board types */

#endif	/* __LINUX_MCKA_H__ */
