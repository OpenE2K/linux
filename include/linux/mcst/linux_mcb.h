/*
 * Copyright (c) 1996 by MCST.
 */

#ifndef	__LINUX_MCB_H__
#define	__LINUX_MCB_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include <linux/mcst/linux_mcb_def.h>
#include <linux/mcst/linux_me90.h>

#ifndef kmem_alloc
#define 	kmem_alloc(arg1,arg2) 	kmalloc(arg1,GFP_KERNEL)
#define 	kmem_free(arg1,arg2) 	kfree(arg1)
#endif

#define cv_wait_sig	cv_wait
#define cv_destroy      cond_destroy

/*
 * Interrupts reason list
 */

typedef enum   intr_rsn
{
	undefined_intr_reason,		/* undefined reason */
	reject_intr_reason,		/* interrupts does not wait */
	dma_trans_end_intr_reason,	/* DMA data transfer end */
	aborted_intr_reason,		/* aborted transfer interrupt */
	drq_receive_intr_reason,	/* device request received */
	mp_timer_expired_intr_reason,	/* MP timer expired interrupt */
	board_error_intr_reason,	/* board internal error occure */
	dma_trans_halt_intr_reason,	/* DMA data transfer halted */
	init_trans_mode_end_intr_reason,/* end of init transfer mode */
	cnct_polling_good_intr_reason,	/* connection polling good interrupt */
					/* comity connection installed and */
					/* no connection errors detected */
	cnct_polling_bad_intr_reason	/* connection polling bad interrupt */
					/* detected connection refusal */
} intr_reason_t;

/*
 * Timeout processing definitions
 */

#ifdef	__MCAP_BOARD_DRIVER__
#define	READ_TIMEOUT_DEF_VALUE		(10 * 1000000)	/* 10 sec */
#define	WRITE_TIMEOUT_DEF_VALUE		(10 * 1000000)	/* 10 sec */
#elif	defined(__MCKP_BOARD_DRIVER__)
#define	READ_TIMEOUT_DEF_VALUE		(25 * 1000000)	/* 25 sec */
#define	WRITE_TIMEOUT_DEF_VALUE		(25 * 1000000)	/* 25 sec */
#else
#define	READ_TIMEOUT_DEF_VALUE		(3 * 1000000)	/*  3 sec */
#define	WRITE_TIMEOUT_DEF_VALUE		(3 * 1000000)	/*  3 sec */
#endif	/* __MCAP_BOARD_DRIVER__ */

#define HALT_TIMEOUT_DEF_VALUE		(10000000)	/* 10 seconds */
#define HALT_STRM_TIMEOUT_DEF_VALUE	(10000000)	/* 10 seconds */
#define INIT_TRANS_MODE_TIMEOUT_DEF	(10000000)	/*  3 seconds */

#define	TERMINATE_TIMEOUT_DEF_VALUE	ME90_TERMINATE_TIMEOUT_DEF_VALUE
#define MCB_WATCHDOG_DEF_VALUE		ME90_WATCHDOG_DEF_VALUE
#define	CHANNEL_FREE_TIMEOUT_DEF_VALUE	ME90_CHANNEL_FREE_TIMEOUT_DEF_VALUE
#define	DRV_COMM_FREE_TIMEOUT_DEF_VALUE	ME90_DRV_COMM_FREE_TIMEOUT_DEF_VALUE

#define	TRANS_IN_PROGRESS_MP_ABORT_TIME	100		/* loop of waiting # */

/*
 * Interdriver communication waiting times
 */

#define INTR_RESET_BY_MP_TIME		ME90_INTR_RESET_BY_MP_TIME
#define INTR_RESET_BY_MP_TRYON		ME90_INTR_RESET_BY_MP_TRYON
#define INTR_RESET_BY_MP_DELAY_TIME	ME90_INTR_RESET_BY_MP_DELAY_TIME
#define TASK_ACCEPT_BY_MP_TIME		ME90_TASK_ACCEPT_BY_MP_TIME
#define TASK_ACCEPT_BY_MP_TRYON		ME90_TASK_ACCEPT_BY_MP_TRYON
#define TASK_ACCEPT_BY_MP_DELAY_TIME	ME90_TASK_ACCEPT_BY_MP_DELAY_TIME

/*
 * Local definitions, for clarity of code
 */

#define MCB_DEVN(d)		ME90_DEVN(d)	/* dev_t -> minor (dev_num) */
#define MCB_inst(m)		ME90_inst(m)	/* minor -> instance */
#ifndef	__CNTR_DEV_BOARD_TYPE__
#define MCB_chan(m)		ME90_chan(m)	/* minor -> channel */
#define MCB_MINOR(i,c)		ME90_MINOR(i,c)	/* instance+channel -> minor */
#define MCB_INST(d)		ME90_INST(d)	/* dev_t -> instance */
#define MCB_CHAN(d)		ME90_CHAN(d)	/* dev_t -> channel */
#else	/* __CNTR_DEV_BOARD_TYPE__ */
#define MCB_module(m)		ME90_module(m)	/* minor -> module */
						/* module -> channel */
#define	MCB_mod_chan(m)		ME90_mod_chan(m)
						/* module -> controller flag */
#define	MCB_mod_cntr(m)		ME90_mod_cntr(m)
						/* minor -> channel */
#define MCB_chan(m)		ME90_chan(m)
						/* minor -> controller */
#define MCB_cntr(m)		ME90_cntr(m)
						/* channel+controller flag -> */
						/* module */
#define MCB_MODULE(chn,cnt)	ME90_MODULE(chn,cnt)
						/* instance+module -> minor */
#define MCB_MINOR_mod(i,mod)	ME90_MINOR_mod(i,mod)
						/* instance+ channel+cntr -> */
						/* module */
#define MCB_MINOR(i,chn,cnt)	ME90_MINOR(i,chn,cnt)
						/* dev_t -> instance */
#define MCB_INST(d)		ME90_INST(d)
						/* dev_t -> module */
#define MCB_MOD(d)		ME90_MOD(d)
						/* dev_t -> channel */
#define MCB_CHAN(d)		ME90_CHAN(d)
						/* dev_t -> controller */
#define MCB_CNTR(d)		ME90_CNTR(d)
#endif	/* __CNTR_DEV_BOARD_TYPE__ */

/*
 * Debug level and message log definitions
 */

#define	MCB_DL_ERROR		ME90_DL_ERROR		/* debug level 1 - errors */
#define	MCB_DL_WARNING		ME90_DL_WARNING		/* debug level 2 - warnings */
#define	MCB_DL_TRACE		ME90_DL_TRACE		/* debug level 3 - trace */
#define	MCB_DL_REGS_MAP		ME90_DL_REGS_MAP	/* debug level 4 - reg maping */
#define	MCB_DL_MINOR		ME90_DL_MINOR		/* debug level 4 - minor node */
#define	MCB_DL_REGS_OP		ME90_DL_REGS_OP		/* debug level 4 - reg rd/wr */

#define	MCB_LOG			ME90_LOG

extern	int	mcb_debug;			/* debug level */
extern	int	mcb_log_msg_num;		/* current # of log msg */
extern	int	mcb_max_log_msg_num;		/* max # of log msg */

/*
 * MP timer interrupts processing
 */

typedef struct mp_intr_t {
   struct mp_intr_t *	next_mp_intr;	/* reference to next item of queue */
   int			intr_num;	/* number of interrup */
   u_int		timer_interval;	/* interval from previous timer */
					/* interrupt */
#ifdef	_MP_TIME_USE_
   u_int		enqueue_time;	/* MP time when interrupt was been */
					/* enqueued */
#else
   hrtime_t		enqueue_time;	/* MP time when interrupt was been */
					/* enqueued */
#endif	/* _MP_TIME_USE_ */
} mp_intr_t;

typedef struct intr_req_t {
   struct intr_req_t *	next_intr_request;	/* reference to next item of */
						/* queue */
   kcondvar_t   	intr_received_cv;       /* MP interrupt received */
						/* condition variable */
#ifdef	_MP_TIME_USE_
   u_int		enqueue_time;		/* MP time when request was */
						/* been enqueued */
#else
   hrtime_t		enqueue_time;		/* MP time when request was */
						/* been enqueued */
#endif	/* _MP_TIME_USE_ */
   mp_tm_intr_info_t *	intr_info;		/* MP timer interrupt info */
} intr_req_t;

typedef struct mp_intr_spec {
   int		mp_intr_mode_on;	/* MP timer interrupts mode turns on */
   int		interval;		/* interval microseconds after the */
					/* timer expires and will be interr */
   int		max_queue_size;		/* max size of unclaimed interrupts */
   int		cur_queue_size;		/* current size of interrupts queue */
   int		losed_intr_num;		/* number of losed interrupts */
   int		total_intr_num;		/* total number of MP timer intrs */
#ifdef	_MP_TIME_USE_
   u_int	last_intr_time;		/* MP time of last interrupt */
#else
   hrtime_t	last_intr_time;		/* MP time of last interrupt */
#endif	/* _MP_TIME_USE_ */
   mp_intr_t *	mp_intr_queue_start;	/* first item of unclaimed interrupts */
					/* queue */
   mp_intr_t *	mp_intr_queue_end;	/* last item of unclaimed interrupts */
					/* queue */
   int		cur_request_num;	/* current number of requests waiting */
					/* for MP timer interrupts */
   int		total_request_num;	/* total number of MP intr requests */
#ifdef	_MP_TIME_USE_
   u_int	last_request_time;	/* MP time of last interrupt requests */
#else
   hrtime_t	last_request_time;	/* MP time of last interrupt requests */
#endif	/* _MP_TIME_USE_ */
   intr_req_t *	intr_req_queue_start;	/* first item of requests waiting for */
					/* MP timer interrupts */
   intr_req_t *	intr_req_queue_end;	/* first item of requests waiting for */
					/* MP timer interrupts */
} mp_intr_spec_t;

/*
 * Structure of I/O data transfer with using of Driver Private DMA buffers
 */

typedef struct mcb_drv_buf {
    struct
	mcb_drv_buf	*next_drv_buf;	/* link to next buffer in the list */
    uio_t *		uio_p;		/* uio structure of the transfer */
    int			op_flags;	/* I/O operation (direction) flag */
    int			trans_error;	/* I/O data transfer operation error */
    int			trans_completed;/* I/O data transfer completed */
    kcondvar_t		trans_finish_cv;/* transfer finished event condition
					   variable */
    struct trans_spec *	transfer_spec;	/* transfer specifications pointer */
} mcb_drv_buf_t;

/*
 *  Transfer buffer descroption
 */

typedef struct dma_struct {
	caddr_t		 prim_buf_addr;
	size_t		 real_size;
        dma_addr_t       prim_dev_mem;         /* Address in the SBus space */
    	unsigned long	 dma; 			/* Address in the processor space */
} dma_struct_t;

typedef struct trbuf_desc {
	char			only_link;	/* buffer is only link */
						/* structure */
	char			drv_buf_used;	/* driver private DMA buffers */
						/* used */
/*	buf_t			*bp;*/		/* sysstem buffer header */
	uio_t *			uio_p;		/* associated with block I/O */
						/* data transfer, if used */
	caddr_t			buf_address;	/* virtual address of I/O */
						/* buffer */
	size_t			buf_size;	/* byte size of I/O buffer */
//	ddi_acc_handle_t	acc_handle;	/* buffer access handle */
//	ddi_dma_handle_t	dma_handle;	/* buffer DMA handle */
//	ddi_dma_cookie_t	cookie;		/* buffer DMA cookie */
	dma_struct_t            dma;
	uint_t			ccount;		/* number of buffer DMA */
						/* cookies */
} trbuf_desc_t;

/*
 * Synchronous and Streaming transfer header descroption
 */

typedef struct trans_buf {
	struct trans_buf
			*next_trans_buf;/* link to next buffer in the list */
	char		pseudobuf;	/* thr buffer is pseudo */
	trbuf_desc_t	trans_buf_desc;	/* the transfer buffer descroption */
	size_t		trans_size;	/* byte size of I/O transfer */
	char		multi_buf_flag;	/* the multi-buf transfer flag */
	char		batch_flag;	/* batch transfer buffer used */
	mcb_drv_buf_t	*drv_buf_p;	/* driver buffer header associated */
					/* with I/O transfer, if used */
	size_t		buf_offset;	/* current offset of data into the */
					/* buffer (for streaming transfer) */
	size_t		real_trans_size;/* real byte size of transfered data */
	mc_rd_reg_t	gen_reg_state;	/* general register of board state */
	u_short		mp_error_code;	/* MP detected errors code */
	u_short		sparc_error_code;/* SPARC driver detected errors code */
#ifndef	__MCPM_BOARD_DRIVER__
	u_char		board_state_byte;	/* byte of board or device */
						/* state */
	u_char		sp_state_byte;		/* state byte of SYNCHRO-PLIC */
#else	/* __MCPM_BOARD_DRIVER__ */
	mcpm_bcw_t	channel_check_word;	/* MCPM channel hardware  */
						/* built-in check word state */
#endif	/* __MCPM_BOARD_DRIVER__ */
	u_short		trans_num;		/* unique number of transfer */
						/* associated with buf */
	int		trans_error;		/* I/O data transfer oper */
						/* error (return value as */
						/* result of I/O) */
#ifdef	_MP_TIME_USE_
	u_int		intr_transfer_end;	/* interrupt on transfer end */
						/* on SPARC */
#else
	hrtime_t	intr_transfer_end;	/* interrupt on transfer end */
						/* on SPARC */
#endif	/* _MP_TIME_USE_ */
#ifdef	__TRANS_SPEC_INTO_BUF__
	trans_info_t	trans_res_info;	/* transfer results info */
#endif /* __TRANS_SPEC_INTO_BUF__ */
#ifndef __BLOCK_BUFFER_USE__
	int		trans_completed;/* I/O data transfer completed */
    	kcondvar_t	trans_finish_cv;/* transfer finished event condition
					   variable */
	struct trans_spec *	transfer_spec;	/* transfer specifications pointer */
#endif /* __BLOCK_BUFFER_USE__ */
} trans_buf_t;

/*
 * Internal driver state per instance
 */

#define MC_EPROM                mcb_reg_sets.MC_EPROM_regs
#define MC_EPROM_CHAR           MC_EPROM.MC_EPROM_char
#define MC_EPROM_U_CHAR         MC_EPROM.MC_EPROM_u_char
#define MC_EPROM_LONG           MC_EPROM.MC_EPROM_long
#define MC_EPROM_U_LONG         MC_EPROM.MC_EPROM_u_long
#define MC_EPROM_CADDR          MC_EPROM.MC_EPROM_caddr
#define MC_CNTR_ST_REGS         mcb_reg_sets.MC_CNTR_ST_regs
#define MC_BMEM                 mcb_reg_sets.MC_BMEM_regs

#if 0
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
	mcb_state_t	*mcb,
	int		channel,
	mcb_init_trans_t	*init_state_args,
	int		drv_comm_area_locked,
	int		*error_code,
	int		state_recover
);
int	mcb_halt_trans_state(
	mcb_state_t	*mcb,
	int		channel,
	mcb_halt_trans_t	*halt_trans_state,
	int		drv_comm_area_locked,
	int		user_request,
	int		mutex_locked
);
#endif	/* __MCPM_BOARD_DRIVER__ */
#ifdef	_STREAMING_TRANSFER_USED_
int	mcb_init_streaming(
	mcb_state_t		*state,
	int			channel,
	streaming_spec_t	*streaming_specs
);
int	mcb_halt_streaming_trans(
	mcb_state_t	*state,
	int		channel,
	int		*trans_rem_size_p,
	int		mutex_locked
);
#endif	/* _STREAMING_TRANSFER_USED_ */
#if	defined(__MCKP_BOARD_DRIVER__) || defined(__MCAP_BOARD_DRIVER__)
int	mcb_init_trans_mode(
	mcb_state_t	*mcb,
	int		drv_comm_area_locked
);
#endif	/* defined(__MCKP_BOARD_DRIVER__) || defined(__MCAP_BOARD_DRIVER__) */

#ifdef	__MCKP_BOARD_DRIVER__
int	mcb_set_work_timetable(
	mcb_state_t	*mcb,
	int		channel,
	int		drv_comm_area_locked
);
int	mcb_halt_trans_mode(mcb_state_t		*mcb);
#endif	/* __MCKP_BOARD_DRIVER__ */
void	mcb_release_async_trans(
	mcb_state_t	*state,
	int		channel,
	trans_buf_t	*trans_buf_p
);
int	get_reg_sets_number(
	e90_unit_t	type_unit,
	char		get_max_num
);
void	init_reg_sets_pointers(
	mcb_state_t	*state,
	e90_unit_t	type_unit
);
int	put_reg_set_pointer(
	mcb_state_t	*state,
	u_int		i_reg_gr,
	caddr_t		regs_mass
);
void	Unmap_reg_sets(
	mcb_state_t	*state
);
void 	mcb_init_drv_state(
	mcb_state_t	*state
);
int	mcb_attach_add(
	mcb_state_t	*state,
	int		*add_attach_flags
);
void	mcb_detach_add(
	mcb_state_t	*state,
	int		add_attach_flags,
	int		uncondit_detach
);
u_int	mcb_interrupt(
	int irq, 
	caddr_t arg, 
	struct pt_regs *regs
);
void	finish_mcb_dma_engine(
	mcb_state_t	*mcb,
	int		channel,
	trans_buf_t	*trans_buf_p,
	int		mutex_locked
);
void	mcb_handle_trans_finish(
	mcb_state_t	*state,
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
	mcb_state_t	*state,
	int		channel,
	trans_buf_t	*trans_buf_p,
	int		mutex_locked
);
void	finish_mcb_drv_buf_trans(
	mcb_state_t	*state,
	int		channel,
	trans_buf_t	*trans_buf_p,
	int		mutex_locked
);
int	mcb_restart_all_stream_channel(
	mcb_state_t	*state,
	int		drv_comm_area_locked
);
#endif	/* _STREAMING_TRANSFER_USED_ */
int	abort_dma_transfer(
	mcb_state_t	*state,
	int		channel
);
void	mcb_delete_trans_header(
	mcb_state_t	*state,
	trans_buf_t	*trans_buf_p
);
int	mcb_finish_drv_buf_trans(
	mcb_state_t	*state,
	int		channel,
	trans_buf_t	*trans_buf_p
);
void	mcb_start_new_trans(
	mcb_state_t	*state,
	int		channel
);
int	mcb_recover_trans_state(
	mcb_state_t	*state,
	int		drv_comm_area_locked,
	int		mutex_locked
);
void	mcb_delete_connection_polling(
	mcb_state_t	*state,
	int		reset_error
);
int	handle_mp_timer_intr_request(
	mcb_state_t		*state,
	mp_tm_intr_info_t	*mp_timer_intr_info
);
void	remove_mp_timer_intr(
	mcb_state_t	*state
);
int	mcb_set_connection_polling(
	mcb_state_t	*state,
	cnct_poll_set_t	*polling_setup_spec
);
int	mcb_reset_connection_polling(
	mcb_state_t	*state,
	int		reset_error
);
int	mcb_poll_connection_state(
	mcb_state_t		*state,
	poll_cnct_state_t	*state_spec
);
int	reset_general_regs(
	mcb_state_t	*state,
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
	mcb_state_t		*state,
	mp_task_t		mp_task,
	mp_drv_args_t		*task_args,
	int			mutex_enter_done,
	trans_info_t		*trans_res_info,
	sparc_drv_args_t	*mp_task_results,
	int			restart
);

#ifndef	__MCPM_BOARD_DRIVER__
int	mcb_set_trans_results(
	mcb_state_t		*mcb,
	trans_info_t		*drv_trans_res_info_p,
	trans_info_t		*drv_results_p,
	trans_info_t		*user_trans_res_info_p,
	int			mode
);
#elif	defined(__MCPM_BOARD_DRIVER__)
int	mcb_set_trans_results(
	mcb_state_t		*mcb,
	trans_info_t		*drv_trans_res_info_p,
	mcpm_trinfo_t		*drv_results_p,
	mcpm_trinfo_t		*user_trans_res_info_p,
	int			mode
);
#endif	/* defined(__MCPM_BOARD_DRIVER__) or other board types */

#endif

#ifdef	__cplusplus
}
#endif

#endif /* __LINUX_MCB_H__ */
