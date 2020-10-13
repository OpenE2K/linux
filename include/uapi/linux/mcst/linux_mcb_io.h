
/*
 * Copyright (c) 1997 by MCST.
 */

/*
 * Defines and structures used by both the driver
 * and user application
 */

#ifndef	_UAPI__LINUX_MCB_IO_H__
#define	_UAPI__LINUX_MCB_IO_H__

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef __KERNEL__
#include <sys/types.h>
#include <time.h>
#endif /* __KERNEL__ */

#include <linux/mcst/define.h>
#include <linux/mcst/linux_me90_io.h>

/*
 * Commands for 'ioctl' entry of mcb driver
 */
#define MCB_IO			('C' << 8)

#define	MCBIO_LOAD_MP_DRV_CODE			ME90IO_LOAD_MP_DRV_CODE
#define	MCBIO_STARTUP_MP_DRV			ME90IO_STARTUP_MP_DRV
#define	MCBIO_STARTUP_MP_ROM_DRV		ME90IO_STARTUP_MP_ROM_DRV
#define	MCBIO_SPECIFIED_TRANSFER		(MCB_IO | 3)
#define	MCBIO_RESET_MP				ME90IO_RESET_MP
#define	MCBIO_DRQ_WAITING_TRANSFER_NUM		(MCB_IO | 5)
#define	MCBIO_SET_MP_TIMER_INTR			(MCB_IO | 6)
#define	MCBIO_RESET_MP_TIMER_INTR		(MCB_IO | 7)
#define	MCBIO_WAIT_MP_TIMER_INTR		(MCB_IO | 8)
#define	MCBIO_GET_DRIVER_INFO			ME90IO_GET_DRIVER_INFO
#define	MCBIO_LOCK_RESET_MODULE_ON_ERROR		\
		ME90IO_LOCK_RESET_MODULE_ON_ERROR
#define	MCBIO_UNLOCK_RESET_MODULE_ON_ERROR		\
		ME90IO_UNLOCK_RESET_MODULE_ON_ERROR
#define	MCBIO_WAIT_FOR_TRANSFER_IN_PROGRESS		\
		ME90IO_WAIT_FOR_TRANSFER_IN_PROGRESS
#define	MCBIO_STARTUP_MP_CODE			ME90IO_STARTUP_MP_CODE
#define	MCBIO_SET_MP_STATE			ME90IO_SET_MP_STATE
#define	MCBIO_INIT_STREAMING_CHANNEL		(MCB_IO | 15)
#define	MCBIO_HALT_STREAMING_CHANNEL		(MCB_IO | 16)
#define	MCBIO_RESET_SBUS_LOGER			(MCB_IO | 17)
#define	MCBIO_OUT_LAST_TRANS_STATE		ME90IO_OUT_LAST_TRANS_STATE
#define	MCBIO_GET_DRIVER_TRACE_MSG		ME90IO_GET_DRIVER_TRACE_MSG
#define	MCBIO_RESTART_BOARD			(MCB_IO | 20)
#define	MCBIO_INIT_TRANSFER_MODES		(MCB_IO | 21)
#define	MCBIO_HALT_TRANSFER_MODES		(MCB_IO | 22)
#define	MCBIO_SET_WORK_TIMETABLE_MASK		(MCB_IO | 23)
#define	MCBIO_WRITE_DEV_ADAPTER_REG		ME90IO_WRITE_DEV_ADAPTER_REG
#define	MCBIO_READ_DEV_ADAPTER_REG		ME90IO_READ_DEV_ADAPTER_REG
#define	MCBIO_SET_CONNECTION_POLLING		(MCB_IO | 26)
#define	MCBIO_RESET_CONNECTION_POLLING		(MCB_IO | 27)
#define	MCBIO_POLL_CONNECTION_STATE		(MCB_IO | 28)
#define	MCBIO_SET_DRV_GENERAL_MODE		ME90IO_SET_DRV_GENERAL_MODE
#define	MCBIO_RESET_DRV_GENERAL_MODE		ME90IO_RESET_DRV_GENERAL_MODE
#define	MCBIO_GET_DRV_GENERAL_MODES		ME90IO_GET_DRV_GENERAL_MODES
#define	MCBIO_PUT_DRV_GENERAL_MODES		ME90IO_PUT_DRV_GENERAL_MODES
#define	MCBIO_WAIT_FOR_ASYNC_TRANS_END		ME90IO_WAIT_FOR_ASYNC_TRANS_END

/*
 *  I/O mode flags
 */

#define	PROG_TRANSFER_IO_MODE		0x0001	/* programmed I/O transfer */
#define	DMA_TRANSFER_IO_MODE		0x0002	/* DMA transfer */
#define	BMEM_TRANSFER_IO_MODE		0x0004	/* transfer to or from BMEM */
#define	PROG1_TRANSFER_IO_MODE		0x0008	/* programmed I/O transfer */
#define	TIMING_TRANSFER_IO_MODE		0x0010	/* transfer with timing */
#define	TEST_TRANSFER_IO_MODE		0x0020	/* test mode of I/O transfer */
#define	ONLY_UNBUF_IO_MODE		0x0100	/* I/O transfer cannot use */
						/* any private system bufs */
#define	KEEP_LAST_BUF_IO_MODE		0x0200	/* keep buffer of last I/O */
						/* transfer */

/*
 *  I/O device access mode flags
 */

#define	DIRECT_DEV_ACCESS_MODE		1	/* direct I/O transfer */
#define	WITH_DEMAND_DEV_ACCESS_MODE	2	/* I/O transfer but before */
                                                /* device request sending  */
#define	ON_DEMAND_DEV_ACCESS_MODE	3	/* I/O transfer after device */
                                                /* request receiving */

typedef struct streaming_spec		/* streaming channel specifications */
{
   int		min_free_buf_num;	/* min number of items in the list of
					   free buffers at any time */
   int		max_trans_buf_num;	/* max number of system buffers for
					   channel transfer */
   size_t	buf_byte_size;		/* size of system transfer buffer */
   int		burst_sizes;		/* allowed burst sizes for DMA */
} streaming_spec_t;

/*
 *  Optimum default value of streaming specifications
 */

#define	MIN_FREE_BUF_NUM_DEFAULT	2 /* 1 for immediately switch after */
					  /* current transfer completion + */
					  /* 1 in the list of free bufers */
#define	MAX_TRANSFER_BUF_NUM_DEFAULT   -1 /* unlimited */
#define	MIN_PSEUDO_BUF_NUM_ON_CHANNEL	2 /* in progress + next */
					  /* (pseudostreaming mode) */
#define	MIN_TOTALTRANSFER_BUF_NUM	3 /* in progress + next + free */
#define	TRANSFER_BUF_BYTE_SIZE_DEFAULT	(128 * 4)
#define	PSEUDOSTREAMING_BUF_BYTE_SIZE	(32 * 4)


/*
 *  Default value of timeots which may be specified by user
 */

#define STREAMING_DATA_WAITING_TIME_DEF	(0)	/* 0 usec - no waiting */

/*
 *  Map of error code detected by MP driver (mp_error_code field of ioctl
 *  commands)
 */

/*
 *  Error codes detected by MCKP MP driver
 */

#define	MULTIPLE_INIT_MCKP_ERROR	1
#define	BAD_TRANS_MODE_MCKP_ERROR	2
#define	BAD_RING_OFFSET_MCKP_ERROR	3
#define	ADAPTER_ABEND_MCKP_ERROR	4
#define	NOT_INIT_MCKP_ERROR		5
#define	NOT_SET_TIMETABLE_MCKP_ERROR	6
#define	NO_INIT_TC_MCKP_ERROR		7
#define	MODE_INIT_ERROR_MCKP_ERROR	8
#define	MODE_INIT_TB_MISS_MCKP_ERROR	9
#define	TB_MISS_MCKP_ERROR		10
#define	NOT_RESET_TB_MCKP_ERROR		11
#define	BAD_T0_MCKP_ERROR		12
#define	BIG_TRANS_SIZE_MCKP_ERROR	13
#define	MULTI_TRANS_MCKP_ERROR		14

/*
 *  Error codes detected by MCAP MP driver
 */

#define	EMPTY_PRD_MCAP_ERROR		0x01
#define	OK_MISS_MCAP_ERROR		0x02
#define	OK_REMISS_MCAP_ERROR		0x04
#define	BMEM_ABEND_MCAP_ERROR		0x08
#define	RECEIVED_TEF_MCAP_ERROR		0x10
#define	TRANSMITED_WORD_MCAP_ERROR	0x20
#define	TRANSMITED_QUIET_MCAP_ERROR	0x40

#define	MOD3_ERROR_MCAP_ERROR		0x01
#define	MOD3_REERROR_MCAP_ERROR		0x02
#define	WORNING_RECEIVED_MCAP_ERROR	0x04
#define	NO_RECEIVER_FREQ_MCAP_ERROR	0x08
#define	RECEIVED_WORD_MCAP_ERROR	0x10
#define	MP_MISS_WORD_MCAP_ERROR		0x20

#define	HARDWARE_MCAP_ERROR		(EMPTY_PRD_MCAP_ERROR    	| \
					OK_MISS_MCAP_ERROR		| \
					OK_REMISS_MCAP_ERROR		| \
					BMEM_ABEND_MCAP_ERROR		| \
	 				RECEIVED_TEF_MCAP_ERROR		| \
					TRANSMITED_WORD_MCAP_ERROR	| \
					TRANSMITED_QUIET_MCAP_ERROR	| \
					MOD3_ERROR_MCAP_ERROR		| \
					MOD3_REERROR_MCAP_ERROR		| \
					WORNING_RECEIVED_MCAP_ERROR	| \
					NO_RECEIVER_FREQ_MCAP_ERROR	| \
					RECEIVED_WORD_MCAP_ERROR	| \
					MP_MISS_WORD_MCAP_ERROR)

#define	MIN_PROG_NUM_MCAP_ERROR		0x80

#define	YC19_OFF_MCAP_ERROR		0x81
#define	UNKNOWN_TASK_MCAP_ERROR		0x82
#define	BAD_DEVICE_NUM_MCAP_ERROR	0x83
#define	NOT_TRANS_BURST0_MCAP_ERROR	0x84

#define	MAX_PROG_NUM_MCAP_ERROR		0xff

/*
 *  Error codes detected by MCKA/MCKK MP driver
 */

#define	CHANNEL_PARITY_MCKA_ERROR	0x01
#define	BYTE0_PARITY_MCKA_ERROR		0x02
#define	BYTE1_PARITY_MCKA_ERROR		0x04
#define	TG_ABEND_MCKA_ERROR		0x08

#define	ABEND_FLAG_MCKK_ERROR		0x01
#define	BUS_BV_ABEND_MCKK_ERROR		0x02
#define	BUS_A_PARITY_MCKK_ERROR		0x04

#define	HARDWARE_MCKA_ERROR		(CHANNEL_PARITY_MCKA_ERROR    	| \
					BYTE0_PARITY_MCKA_ERROR		| \
					BYTE1_PARITY_MCKA_ERROR		| \
					TG_ABEND_MCKA_ERROR)

#define	HARDWARE_MCKK_ERROR		(ABEND_FLAG_MCKK_ERROR		| \
					BUS_A_PARITY_MCKK_ERROR    	| \
					BUS_BV_ABEND_MCKK_ERROR)


#define	MIN_PROG_NUM_MCK_ERROR		0x10

#define	UNKNOWN_TASK_MCK_ERROR		0x10
#define	BIG_TRANS_SIZE_MCK_ERROR	0x20
#define	BAD_MODE_MCK_ERROR		0x30
#define	INIT_HANDUP_MCK_ERROR		0x50
#define	TRANS_HANDUP_MCK_ERROR		0x60
#define	FINISH_HANDUP_MCK_ERROR		0x70
#define	BAD_DEVICE_NUM_MCK_ERROR	0x80

#define	INIT_STATE_BYTE_MCKK_ERROR	0x90
#define	BAD_OPCODE_MCKA_ERROR		0x90

#define	MAX_PROG_NUM_MCK_ERROR		0xff

/*
 *  I/O transfer results 
 */

typedef	struct trans_info			/* some info about transfer */
{
	u_char		mp_error_code;		/* I/O transfer code of error */
						/* detected by MP driver */
	u_char		state_byte;		/* I/O transfer byte of state */
	u_char		board_error_code;	/* the board internal error */
						/* code */
	u_char		sp_state_byte;		/* I/O transfer state byte of */
						/* SYNCHRO-PLIC */
	u_int		channel_check_word;	/* MCPM channel hardware  */
						/* built-in check word state */
	size_t		real_byte_size;		/* byte size of actually */
						/* transfered set by driver */
						/* and return I/O transfer */
						/* result */
	int		trans_errno;		/* value of errno for I/O */
						/* request, if zero then no */
						/* errors detected */
	u_short		trans_num;		/* unique number of transfer */
						/* associated with buf */
	size_t		missed_data_size;	/* byte size of missed data */
						/* after previous transfer */
						/* request (valid only for */
						/* streaming transfers) */
	int		burst_byte_size;        /* used I/O transfer burst */
						/* bytes size */
#ifdef	_MP_TIME_USE_
	u_int		req_receive_time;	/* transfer request receiving */
						/* time (from uxer) */
	u_int		intr_drq_received;	/* interrupt on DRQ receiving */
						/* by SPARC */
	u_int		intr_transfer_end;	/* interrupt on transfer end */
						/* on SPARC */
	u_int		transfer_start;		/* transfer start time on */
						/* SPARC */
	u_int		transfer_finish;	/* transfer finish time on */
						/* SPARC */
	u_int		event_start_time;	/* some event start time */
	u_int		event_end_time;		/* some event end time */
#else
	hrtime_t	req_receive_time;	/* transfer request receiving */
						/* time (from uxer) */
	hrtime_t	intr_drq_received;	/* interrupt on DRQ receiving */
						/* by SPARC */
	hrtime_t	intr_transfer_end;	/* interrupt on transfer end */
						/* on SPARC */
	hrtime_t	transfer_start;		/* transfer start time on */
						/* SPARC */
	hrtime_t	transfer_finish;	/* transfer finish time on */
						/* SPARC */
	hrtime_t	event_start_time;	/* some event start time */
	hrtime_t	event_end_time;		/* some event end time */
#endif	/* _MP_TIME_USE_ */
}	trans_info_t;

typedef struct trans_spec
{
	caddr_t		buf_base;		/* memory data transfer base */
						/* address */
	size_t		buf_byte_size;		/* byte size of transfered */
						/* data array */
	int		read_write_flag;	/* Read/write flag (B_READ / */
						/* B_WRITE) */
	int		async_trans;		/* asynchronous transfer mode */
	int		io_mode_flags;		/* I/O mode flags */
	int		dev_access_mode;	/* device access mode flag */
	int		burst_sizes;		/* allowed burst sizes for */
						/* DMA */
	int		main_device_num;	/* device number */
						/* (only as MCPM controller */
						/* of channel used */
	int		sub_device_num;		/* subdevice number */
						/* (only as MCPM controller */
						/* of channel used */
	int		repeation_num;		/* transfer repeation number */
	int		timer_interval;		/* timer interval of waiting */
						/* for the I/O transfer end */
						/* (usec) */
	clock_t		data_waiting_time;	/* time of waiting for ready */
						/* I/O data, only by buffered */
						/* streaming transfer used */
						/* (usec) */
	int		timing_interval_t0;	/* the value of timing */
						/* interval for transfer with */
						/* timing */
	trans_info_t	*trans_res_info;	/* transfer results info */
	caddr_t		user_results_p;		/* pointer of I/O data */
						/* transfer results recieved */
						/* from user */
}	trans_spec_t;

typedef struct mp_tm_intr_set
{
   int		interval;		/* interval microseconds after the */
					/* timer expires and will be interr */
   int		max_queue_size;		/* max size of unclaimed interrupts */
}	mp_tm_intr_set_t;

typedef struct mp_tm_intr_reset
{
   int		total_intr_num;		/* total number of MP timer intrs */
   int		unclaimed_intr_num;	/* number of unclaimed interrupts */
   int		losed_intr_num;		/* number of losed interrupts */
}	mp_tm_intr_reset_t;

typedef struct mp_tm_intr_info
{
   int		intr_num;		/* number of the interrupt */
   u_int	timer_interval;		/* interval from previous  */
					/* timer interrupt */
   int		request_num;		/* number of MP intr requests */
   int		request_interval;	/* interval from previous request */
   int		request_enqueued;	/* the request was enqueued */
   u_int	waiting_time;		/* time of request waiting for */
					/* MP interrupt receiving */
   int		unclaimed_intr_num;	/* number of received and not */
					/* claimed still interrupts */
   int		losed_intr_num;		/* number of losed interrupts */
   hrtime_t     request_start_time;	/* start time of request */
					/* (can be seted by user) */
   hrtime_t     request_end_time;	/* end time of request */
					/* (can be seted by user) */
#ifdef	_MP_TIME_USE_
   u_int        drv_request_start_time;	/* start time of request in driver */
   u_int        drv_request_end_time;	/* end time of request in driver */
#else
   hrtime_t     drv_request_start_time;	/* start time of request in driver */
   hrtime_t     drv_request_end_time;	/* end time of request in driver */
#endif	/* _MP_TIME_USE_ */
}	mp_tm_intr_info_t;

typedef me90_drv_info_t			mcb_drv_info_t;

/*
 *  Device 'ioctl' structures, defines and default value
 */

#define MCKP_TIMETABLE_MASK_BYTE_SIZE	20

typedef struct mckp_init_trans_spec
{
   u_char	offset;			/* the device offset in the ring */
   u_char	test_mode_flag;		/* test mode: internal ring */
   u_char	mp_error_code;		/* code of error returned by MP */
                                        /* driver if one occured */
}	mckp_init_trans_spec_t;

typedef struct mcap_init_trans_spec
{
	u_short	board_mode;		/* the board mode of work */
	u_int	watchdog_value;		/* MP watchdog timer value */
	u_short	timer1_value;		/* MP timer # 1 value */
	u_short	timer2_value;		/* MP timer # 2 value */
	u_char	mp_error_code;		/* code of error returned by MP */
                                        /* driver if one occured */
}	mcap_init_trans_spec_t;

typedef union init_trans_spec
{
   mckp_init_trans_spec_t  mckp;	/* MCKP boaard initial args */
   mcap_init_trans_spec_t  mcap;	/* MCAP boaard initial args */
}	init_trans_spec_t;

typedef caddr_t				timetable_mask_t;

/*
 * Connection polling mode setting and resetting
 */

typedef struct cnct_poll_set		/* connection polling setup */
{
	int	interval;		/* connection polling interval */
					/* in microsecons (usec) */
	char	cpu_polling;		/* CPU polling flag, if sets polling */
					/* of CPU state will be included */
	int	setup_timeout;		/* waiting time for comity connection */
					/* polling will be set */
					/* in milliseconds (msec) */
	int	connection_events_num;	/* number of connection polling */
					/* events (size of buffer) */
}	cnct_poll_set_t;

#define CNCT_POLLING_INTERVAL_DEF	(     100)	/* 100 microseconds */
#define CNCT_POLLING_SETUP_TIMEL_DEF	( 1000000)	/*   1 seconds */

/*
 * Connection state flags 
 */

#define	MODE_ON_CONNECTION_STATE	0x01	/* mode of connection state */
						/* polling turn ON */
#define	MODE_OFF_CONNECTION_STATE	0x02	/* mode of connection state */
						/* polling turn OFF */
#define	IS_SET_CONNECTION_STATE		0x04	/* initial connection is set */
#define	IS_RESET_CONNECTION_STATE	0x08	/* connection is reset */
#define	ALIVE_CONNECTION_STATE		0x10	/* connection is alive */
#define	REFUSED_CONNECTION_STATE	0x20	/* connection refused */
#define	MP_TAKE_CONNECTION_STATE	0x40	/* initial connection take MP */

/*
 * Connection state polling ioctl arg structure 
 */

typedef	struct poll_time_info		/* poll connection state time info */
{
	hrtime_t	alive_intr;	/* time of last interrupt of */
					/* alive connection state */
	hrtime_t	refused_intr;	/* time of last interrupt of */
					/* refused connection state */
	hrtime_t	drv_return;	/* time of return from connection */
					/* state change handler of driver */
	hrtime_t	lib_return;	/* time of return from connection */
					/* polling function of E90 library */
	int		change_interval;/* interval time: from last alive or */
					/* refused state to new refused or */
					/* alive state (failure detect time) */
	int		drv_interval;	/* driver interval time: from */
					/* interrupt receiving to return */
					/* from driver 'ioctl' function */
	int		switch_interval;/* switch interval time: */
					/* from driver 'ioctl' to */
					/* E90 library function */
	int		total_interval;	/* total poll handler interval */
					/* time: from interrupt receiving to */
					/* return from E90 library function */
}	poll_time_info_t;

typedef	enum	poll_event_code		/* list of poll connection events */
{
	undefined_poll_event_code,	/* undefined event */
	is_set_poll_event_code,		/* connection is set */
	cpu_alive_poll_event_code,	/* CPU state interrupt is received */
	refused_poll_event_code,	/* connection refused interrupt is */
					/* received */
	recovered_poll_event_code,	/* connection recovered interrupt is */
					/* received */
	interrupted_poll_event_code,	/* connection set is interrupted */
	reset_poll_event_code		/* connection is reset */
}	poll_event_code_t;

typedef	struct	poll_event_info		/* poll connection events info */
{
	poll_event_code_t	event;	/* event of connection polling */
	hrtime_t		time;	/* time of event */
}	poll_event_info_t;

typedef struct poll_cnct_state		/* poll connection state */
{
	int	state_mask;		/* mask of requested connection state */
					/* to be  examined: any sensible  */
					/* combination of state flags defined */
					/* above, including null mask */
	int	timeout;		/* waiting time for at least one of */
					/* the requested state to occur */
					/* in microsecons (msec) */
					/* if timeout == 0 then the polling */
					/* returns immediately, */
					/* if timeout == INFTIM (or -1) then */
					/* the polling blocks until a */
					/* requested state occurs or polling */
					/* mode will be off */
	int	rstate_mask;		/* mask of returned connection state */
					/* if state_mask == 0 then polling */
					/* returns immediately with the mask */
					/* of current state */
					/* if polling timeouted rstate_mask */
					/* is the mask of current state */
					/* if polling mode is or will be off */
					/* then the mask of current state */
					/* returns */
					/* if some of requested states occur */
					/* then rstate_mask is the mask of */
					/* current state & state_mask */
	poll_time_info_t
		*time_info;		/* connection state polling time info */
	poll_event_info_t
		*connection_events;	/* connection state polling events */
					/* info */
	int	connection_events_num;	/* number of connection events */
	int	losed_events_num;	/* number of losed connection events */
}	poll_cnct_state_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _UAPI__LINUX_MCB_IO_H__ */
