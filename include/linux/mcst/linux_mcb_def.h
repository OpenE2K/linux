/*
 * Copyright (c) 1997 by MCST.
 */

#ifndef	__LINUX_MCB_DEF_H__
#define	__LINUX_MCB_DEF_H__

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef __KERNEL__
#include <sys/types.h>
#endif /* __KERNEL__ */

#include <linux/mcst/linux_mcb_io.h>
#include <linux/mcst/linux_me90_def.h>
#include <linux/mcst/linux_mcb_reg.h>
#include <linux/mcst/linux_mcpm_io.h>

/*
 * Defines and structures useable by both the driver
 * and user application go here.
 */

#define DDI_DMA_WRITE           0x0001  /* Direction memory --> IO      */
#define DDI_DMA_READ            0x0002  /* Direction IO --> memory      */
#define DDI_DMA_RDWR            (DDI_DMA_READ | DDI_DMA_WRITE)
#define DDI_DMA_STREAMING       0x0040

#define UIO_WRITE           	1
#define UIO_READ            	2
#define UIO_USERSPACE   	1 
#define UIO_SYSSPACE      	2

#ifndef B_READ
#define B_READ  		2
#define B_WRITE 		1
#endif

/*
 * Some atributes of the boards
 */

#if	defined(__MCAP_BOARD_DRIVER__)
#define MAX_MC_BOARD_CHANNEL_NUM	MAX_MCAP_BOARD_DEVICE_NUM
#elif	defined(__MCKP_BOARD_DRIVER__)
#define MAX_MC_BOARD_CHANNEL_NUM	MAX_MCKP_BOARD_DEVICE_NUM
#elif	defined(__MCKA_BOARD_DRIVER__)
#define MAX_MC_BOARD_CHANNEL_NUM	MAX_MCKA_BOARD_DEVICE_NUM
#elif	defined(__MCKK_BOARD_DRIVER__)
#define MAX_MC_BOARD_CHANNEL_NUM	MAX_MCKK_BOARD_DEVICE_NUM
#elif	defined(__MCPM_BOARD_DRIVER__)
#define MAX_MC_BOARD_CHANNEL_NUM	MAX_MCPM_BOARD_DEVICE_NUM
#else
#define MAX_MC_BOARD_CHANNEL_NUM	16  /* max number of channel/device */
#endif	/* __MCAP_BOARD_DRIVER__ */

#define MCB_ENABLE_BURST_SIZES		ME90_ENABLE_BURST_SIZES
#define MCB_64_BURTS_SIZE_CODE		ME90_64_BURTS_SIZE_CODE
#define MCB_32_BURTS_SIZE_CODE		ME90_32_BURTS_SIZE_CODE
#define MCB_16_BURTS_SIZE_CODE		ME90_16_BURTS_SIZE_CODE
#define MCB_8_BURTS_SIZE_CODE		ME90_8_BURTS_SIZE_CODE
#define MCB_4_BURTS_SIZE_CODE		ME90_4_BURTS_SIZE_CODE

#define MCB_64_BURTS_SIZE_DCW_CODE	ME90_64_BURTS_SIZE_DCW_CODE
#define MCB_32_BURTS_SIZE_DCW_CODE	ME90_32_BURTS_SIZE_DCW_CODE
#define MCB_16_BURTS_SIZE_DCW_CODE	ME90_16_BURTS_SIZE_DCW_CODE
#define MCB_8_BURTS_SIZE_DCW_CODE	ME90_8_BURTS_SIZE_DCW_CODE
#define MCB_4_BURTS_SIZE_DCW_CODE	ME90_4_BURTS_SIZE_DCW_CODE

/*
 * Base memory mapping attributes
 */

#define MC_BOARD_DEVICE_NUM		MAX_MC_BOARD_CHANNEL_NUM
#define DEV_HALF_BUF_BMEM_SIZE		0x00040 /* byte size of device buf */
#define DEV_FULL_BUF_BMEM_SIZE		DEV_HALF_BUF_BMEM_SIZE * 2
#define DEV_CNTR_BMEM_SIZE		sizeof(dev_trans_words_t)
#define MP_HALF_BUF_BMEM_SIZE		DEV_HALF_BUF_BMEM_SIZE
#define MP_FULL_BUF_BMEM_SIZE		DEV_FULL_BUF_BMEM_SIZE
#define MP_CNTR_BMEM_SIZE		DEV_CNTR_BMEM_SIZE
#define MP_INIT_AREA_BMEM_SIZE		ME90_MP_INIT_AREA_BMEM_SIZE

/*
 * Base memory area structures
 */

typedef enum _mp_task_t                 /* list of MP task number */
{
   no_mp_task,                          /* MP is waiting a task */
   drv_load_mp_task,                    /* MP driver load in progress */
   data_transfer_mp_task,               /* data transfer */
   transfer_abort_mp_task,		/* abort data transfer */
   drq_data_transfer_mp_task,           /* data transfer with device request */
   unused_mp_task,                      /* unused still */
   mp_timer_intr_set_mp_task,		/* set/reset MP timer interrupts */
   halt_streaming_mp_task,		/* halt streaming transfer channel */
   init_streaming_mp_task,		/* init streaming transfer channel */
   init_trans_mode_mp_task,		/* init and set transfer modes */
   set_timetable_mp_task,		/* set timetable of works */
   device_adapter_write_mp_task,	/* write device adapter regs */
   device_adapter_read_mp_task,		/* read device adapter regs */
   halt_trans_mode_mp_task,		/* halt the transfers for devices */
   set_cnct_polling_mp_task,		/* set connection polling mode */
   reset_cnct_polling_mp_task,		/* reset connection polling mode */
   init_trans_state_mp_task,		/* init channel transfer state */
   halt_trans_state_mp_task		/* halt channel transfer state */
} mp_task_t;

typedef enum _sparc_task_t              /* list of SPARC task number */
{
   no_sparc_task,                       /* SPARC is waiting interrupt & task */
   drv_load_end_mp_task,                /* MP driver load is completed */
   transfer_end_mp_task,                /* data transfer end */
   transfer_abort_end_mp_task,          /* data transfer abort end */
   drq_transfer_end_mp_task,            /* data transfer with DRQ end */
   drq_receive_mp_task,                 /* device request received */
   mp_timer_expired_mp_task,		/* MP timer exipered interrupt */
   transfer_halted_mp_task,		/* streaming transfer halted */
   init_streaming_end_mp_task,		/* end of streaming transfer init */
   init_trans_mode_end_mp_task,		/* end of init and set transfer modes */
   set_timetable_end_mp_task,		/* end of set timetable of works */
   device_adapter_write_end_mp_task,	/* end of write device adapter regs */
   device_adapter_read_end_mp_task,	/* end of read device adapter regs */
   halt_trans_mode_end_mp_task,		/* end of halt device transfers */
   cnct_polling_good_mp_task,		/* connection polling good interrupt */
					/* comity connection installed and */
					/* no connection errors detected */
   cnct_polling_bad_mp_task,		/* connection polling bad interrupt */
					/* detected connection refusal */
   init_trans_state_end_mp_task,	/* end of init channel transfer state */
   halt_trans_state_end_mp_task		/* end of halt channel transfer state */
} sparc_task_t;

typedef enum _trans_opcode_t            /* list of data transfer opcodes */
{
   check_io_trans_opcode     =  0,      /* check Input/Output */
   write_trans_opcode        =  1,      /* write data */
   read_trans_opcode         =  2,      /* read data */
   empty_trans_opcode        =  3,      /* empty command */
   get_state_opcode          =  4       /* get state */
} trans_opcode_t;

typedef enum _trans_mode_t              /* list of data transfer modes */
{
   dma_trans_mode            =  0,      /* DMA data transfer mode */
   progr_trans_mode          =  1,      /* Programmed data transfer mode */
   only_bmem_trans_mode      =  2,      /* data transfer to or from BMEM only */
   progr1_trans_mode         =  3,      /* Programmed # 1 data transfer mode */
   timing_trans_mode         =  4       /* data transfer mode with timing */
} trans_mode_t;

#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct _trans_desk_t            /* data transfer desription */
{
#ifndef	__MCAP_BOARD_DRIVER__
	u_char		opcode;		/* I/O transfer opcode */
	u_char		dev_num;	/* device number */
	u_char		mode;		/* I/O transfer mode */
	u_char		burst_size;	/* DMA burst size */
#else	/* __MCAP_BOARD_DRIVER__ */
	u_short		opcode;		/* I/O transfer opcode */
	u_short		dev_num;	/* device number */
	u_short		mode;		/* I/O transfer mode */
	u_short		burst_size;	/* DMA burst size */
#endif	/* __MCAP_BOARD_DRIVER__ */
	u_int		address;	/* I/O transfer address */
	u_int		size;		/* I/O transfer size */
#ifdef	__MCKP_BOARD_DRIVER__
	int		timing_interval_t0;	/* timing interval value */
#elif	defined(__MCPM_BOARD_DRIVER__)
	u_char		unused1;	/* unused field */
	u_char		unused2;	/* unused field */
	u_char		main_addr;	/* main address of device */
	u_char		sub_addr;	/* subaddress of device */
	u_short		unused3;	/* unused field */
	u_short		trans_num;	/* unique number of transfer */
					/* associated with it */
#else
	int		repeation_num;	/* I/O transfer repeation number */
#endif	/* __MCKP_BOARD_DRIVER__ or __MCPM_BOARD_DRIVER__ */
} trans_desk_t;
#else
typedef struct _trans_desk_t            /* data transfer desription */
{
#ifndef	__MCAP_BOARD_DRIVER__
	u_char		burst_size;	/* DMA burst size */
	u_char		mode;		/* I/O transfer mode */
	u_char		dev_num;	/* device number */
	u_char		opcode;		/* I/O transfer opcode */	
#else	/* __MCAP_BOARD_DRIVER__ */
	u_short		dev_num;	/* device number */
	u_short		opcode;		/* I/O transfer opcode */
	u_short		burst_size;	/* DMA burst size */
	u_short		mode;		/* I/O transfer mode */	
#endif	/* __MCAP_BOARD_DRIVER__ */
	u_int		address;	/* I/O transfer address */
	u_int		size;		/* I/O transfer size */
#ifdef	__MCKP_BOARD_DRIVER__
	int		timing_interval_t0;	/* timing interval value */
#elif	defined(__MCPM_BOARD_DRIVER__)
	u_char		sub_addr;	/* subaddress of device */
	u_char		main_addr;	/* main address of device */
	u_char		unused2;	/* unused field */
	u_char		unused1;	/* unused field */
	u_short		trans_num;	/* unique number of transfer */
					/* associated with it */
	u_short		unused3;	/* unused field */
#else
	int		repeation_num;	/* I/O transfer repeation number */
#endif	/* __MCKP_BOARD_DRIVER__ or __MCPM_BOARD_DRIVER__ */
} trans_desk_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct init_strm                /* init streaming transfer desription */
{
   u_short       opcode;                /* I/O transfer opcode */
   u_short       dev_num;               /* device number */
   u_short       unused;                /* unused field */
   u_short       burst_size;            /* DMA burst size (in words) */
   u_int         address;               /* current transfer buffer address */
   u_int         size;                  /* transfer buffer size (in words) */
} init_strm_t;
#else
typedef struct init_strm                /* init streaming transfer desription */
{
   u_short       dev_num;                /* I/O transfer opcode */
   u_short       opcode;               /* device number */
   u_short       burst_size;                /* unused field */
   u_short       unused;            /* DMA burst size (in words) */
   u_int         address;               /* current transfer buffer address */
   u_int         size;                  /* transfer buffer size (in words) */
} init_strm_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct halt_strm                /* halt streaming transfer desription */
{
   u_short       unused;                /* unused field */
   u_short       dev_num;               /* device number */
} halt_strm_t;
#else
typedef struct halt_strm                /* halt streaming transfer desription */
{
   u_short       dev_num;                /* unused field */
   u_short       unused;               /* device number */
} halt_strm_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

#ifdef MY_DRIVER_BIG_ENDIAN
#if	defined(__MCKP_BOARD_DRIVER__) || defined(__MCAP_BOARD_DRIVER__)
typedef struct init_trans_mode		/* init transfer modes desription */
{
#ifdef	__MCKP_BOARD_DRIVER__
	u_char	unused0;		/* unused field */
	u_char	unused1;		/* unused field */
	u_char	offset;			/* the device offset in the ring */
	u_char	test_mode;		/* test mode: internal ring */
#elif	defined(__MCAP_BOARD_DRIVER__)
	u_short	unused0;		/* unused field */
	u_short	board_mode;		/* the board mode of work */
	u_int	watchdog;		/* MP watchdog timer value */
	u_short	timer1_value;		/* MP timer # 1 value */
	u_short	timer2_value;		/* MP timer # 2 value */
#endif	/* __MCKP_BOARD_DRIVER__ || __MCAP_BOARD_DRIVER__ */

} init_trans_mode_t;
#endif	/* defined(__MCKP_BOARD_DRIVER__) || defined(__MCAP_BOARD_DRIVER__) */
#else
#if	defined(__MCKP_BOARD_DRIVER__) || defined(__MCAP_BOARD_DRIVER__)
typedef struct init_trans_mode		/* init transfer modes desription */
{
#ifdef	__MCKP_BOARD_DRIVER__
	u_char	test_mode;		/* test mode: internal ring */
	u_char	offset;			/* the device offset in the ring */
	u_char	unused1;		/* unused field */
	u_char	unused0;		/* unused field */
#elif	defined(__MCAP_BOARD_DRIVER__)
	u_short	board_mode;		/* the board mode of work */
	u_short	unused0;		/* unused field */
	u_int	watchdog;		/* MP watchdog timer value */
	u_short	timer2_value;		/* MP timer # 2 value */
	u_short	timer1_value;		/* MP timer # 1 value */
#endif	/* __MCKP_BOARD_DRIVER__ || __MCAP_BOARD_DRIVER__ */

} init_trans_mode_t;
#endif	/* defined(__MCKP_BOARD_DRIVER__) || defined(__MCAP_BOARD_DRIVER__) */
#endif /* MY_DRIVER_BIG_ENDIAN */

#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct init_trst			/* init channel transfer */
						/* state */
{
	u_char		device_num;		/* the device address if */
						/* channel must be device */
						/* rathe controller */
	u_char		channel_num;		/* # of channel */
	u_char		cntr_flag;		/* channel must be controller */
						/* else as device */
	mcpm_adp_mode_t	cntr_mode_state;	/* channel adapter hardware */
						/* control-state mode bits */
	u_int		timer_interval;		/* hangup of I/O transfer */
						/* timer interval (usec) */
} init_trst_t;
#else
typedef struct init_trst			/* init channel transfer */
						/* state */
{
	mcpm_adp_mode_t	cntr_mode_state;	/* channel adapter hardware */
						/* control-state mode bits */
	u_char		cntr_flag;		/* channel must be controller */
						/* else as device */
	u_char		channel_num;		/* # of channel */
	
	u_char		device_num;		/* the device address if */
						/* channel must be device */
						/* rathe controller */
	u_int		timer_interval;		/* hangup of I/O transfer */
						/* timer interval (usec) */
} init_trst_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct halt_trst			/* halt channel transfer */
						/* state */
{
	u_char		unused0;		/* unused byte */
	u_char		channel_num;		/* # of channel */
	u_char		unused2;		/* unused byte */
	u_char		unused3;		/* unused byte */
} halt_trst_t;
#else
typedef struct halt_trst			/* halt channel transfer */
						/* state */
{
	u_char		unused3;		/* unused byte */
	u_char		unused2;		/* unused byte */
	u_char		channel_num;		/* # of channel */
	u_char		unused0;		/* unused byte */
} halt_trst_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct set_timetable		/* set timetable of works desription */
{
   u_char	 unused0;		/* unused field */
   u_char	 dev_num;               /* device number */
   u_char	 unused2;		/* unused field */
   u_char	 unused3;		/* unused field */
   char		 timetable[MCKP_TIMETABLE_MASK_BYTE_SIZE];	/* timetable mask of works */
} set_timetable_t;
#else
typedef struct set_timetable		/* set timetable of works desription */
{
   u_char	 unused3;		/* unused field */
   u_char	 unused2;		/* unused field */	
   u_char	 dev_num;               /* device number */
   u_char	 unused0;		/* unused field */
   char		 timetable[MCKP_TIMETABLE_MASK_BYTE_SIZE];	/* timetable mask of works */
} set_timetable_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

typedef struct _mp_tm_set_t             /* MP timer interrupts set */
{
   int           unused0;
   int           unused1;
   int           unused2;
   int           unused3;
   int           timer_interval;        /* timer interval for MP watchdog */
} mp_tm_set_t;

typedef struct cnct_poll_args		/* set connection polling desription */
{
   int		interval;		/* connection polling interval */
					/* in microsecons (usec) */
   int		cpu_polling;		/* CPU polling flag, if sets polling */
					/* of CPU state will be included */
} cnct_poll_args_t;

typedef union _mp_drv_args_t			/* MP driver arguments of */
						/* task */
{
	trans_desk_t	transfer;		/* data transfer desription,   (4 ints) */
	init_strm_t	init_streaming;		/* init streaming transfer ,   (4 ints) */
						/* channel */
	halt_strm_t	halt_streaming;		/* init streaming transfer ,   (1 int ) */
						/* channel */
	mp_tm_set_t	mp_timer_set;		/* MP timer interrupt setting, (5 ints) */

#if	defined(__MCKP_BOARD_DRIVER__) || defined(__MCAP_BOARD_DRIVER__)
	init_trans_mode_t init_trans_modes;	/* init module transfer modes */
#endif	/* defined(__MCKP_BOARD_DRIVER__) || defined(__MCAP_BOARD_DRIVER__) */

	init_trst_t	init_chnl_trans;	/* init channel transfer      ,(2 ints) */
						/* state */
	halt_trst_t	halt_chnl_trans;	/* halt channel transfer      ,(1 int ) */
						/* state */
	set_timetable_t	 set_work_timetable;	/* set timetable of works     ,(6 ints) */
	adapter_access_t dev_adapter_access;	/* device adpter access       ,(2 ints) */
	cnct_poll_args_t set_cnct_polling;	/* set connection polling     ,(2 ints)*/
						/* args */
#ifdef	__HIGH_INTERDRIVER_AREA_USED__
	u_int		args_area[15];		/* max area of MP task */
						/* arguments */
#else	/* __LOWINTERDRIVER_AREA_USED__ */
	u_int		args_area[27];		/* max area of MP task */
						/* arguments */
#endif	/* __HIGH_INTERDRIVER_AREA_USED__ */
} mp_drv_args_t;

typedef struct _mp_init_result_t        /* MP driver init results */
{
   u_int         unused;                /* unused field */
   u_short       mp_error_code;         /* MP driver init error code */
} mp_init_result_t;

#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct _trans_result_t          /* data transfer results */
{
#ifdef	__MCAP_BOARD_DRIVER__
	u_int		dev_num;	/* device number */
	u_char		unused1;	/* unused field */
	u_char		mp_error_code;	/* I/O transfer code of error */
					/* detected by MP driver */
	u_char		unused2;	/* unused field */
	u_char		state_byte;	/* I/O transfer byte of state */
#elif	defined(__MCPM_BOARD_DRIVER__)
	u_char		mp_error_code;	/* I/O transfer code of error */
					/* detected by MP driver */
	u_char		dev_num;	/* device number */
	u_short		ch_check_word;	/* MCPM channel hardware  */
					/* built-in check word state */
#else	/* ! __MCAP_BOARD_DRIVER__ && ! __MCPM_BOARD_DRIVER__ */
	u_char		mp_error_code;	/* I/O transfer code of error */
					/* detected by MP driver */
	u_char		state_byte;	/* I/O transfer byte of state */
	u_char		dev_num;	/* device number */
	u_char		sp_state_byte;	/* I/O transfer state byte of */
					/* SYNCHRO-PLIC */
#endif	/* __MCAP_BOARD_DRIVER__ */
	u_int		real_size;	/* I/O transfer real size */
	u_short		unused3;	/* unused field */
	u_short		trans_num;	/* unique number of transfer */
					/* associated with it */
} trans_result_t;
#else
typedef struct _trans_result_t          /* data transfer results */
{
#ifdef	__MCAP_BOARD_DRIVER__
	u_int		dev_num;	/* device number */
	u_char		state_byte;	/* I/O transfer byte of state */
	u_char		unused2;	/* unused field */
	u_char		mp_error_code;	/* I/O transfer code of error */
					/* detected by MP driver */
	u_char		unused1;	/* unused field */
#elif	defined(__MCPM_BOARD_DRIVER__)
	u_short		ch_check_word;	/* MCPM channel hardware  */
					/* built-in check word state */
	u_char		dev_num;	/* device number */
	u_char		mp_error_code;	/* I/O transfer code of error */
					/* detected by MP driver */
#else	/* ! __MCAP_BOARD_DRIVER__ && ! __MCPM_BOARD_DRIVER__ */
	u_char		sp_state_byte;	/* I/O transfer state byte of */
					/* SYNCHRO-PLIC */
	u_char		dev_num;	/* device number */
	u_char		state_byte;	/* I/O transfer byte of state */
	u_char		mp_error_code;	/* I/O transfer code of error */
					/* detected by MP driver */
#endif	/* __MCAP_BOARD_DRIVER__ */
	u_int		real_size;	/* I/O transfer real size */
	u_short		trans_num;	/* unique number of transfer */
					/* associated with it */
	u_short		unused3;	/* unused field */
} trans_result_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct _dev_req_t               /* device request */
{
   u_char        mp_error_code;         /* I/O transfer code of error */
					/* detected by MP driver */
   u_char        state_byte;            /* I/O transfer byte of state */
   u_char        dev_num;               /* device number */
} dev_req_t;
#else
typedef struct _dev_req_t               /* device request */
{
   u_char        dev_num;               /* device number */
   u_char        state_byte;            /* I/O transfer byte of state */
   u_char        mp_error_code;         /* I/O transfer code of error */
					/* detected by MP driver */
} dev_req_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

#ifdef  MY_DRIVER_BIG_ENDIAN
typedef struct init_trans_res		/* init transfer modes results */
{
#ifndef	__MCAP_BOARD_DRIVER__
   u_char        mp_error_code;         /* init transfer modes error code */
   u_char	 unused1;		/* unused field */
   u_char	 unused2;		/* unused field */
   u_char	 unused3;		/* unused field */
#else	/* __MCAP_BOARD_DRIVER__ */
   u_int         unused;                /* unused field */
   u_short       mp_error_code;         /* MP driver init error code */
#endif	/* __MCAP_BOARD_DRIVER__ */
} init_trans_res_t;
#else
typedef struct init_trans_res		/* init transfer modes results */
{
#ifndef	__MCAP_BOARD_DRIVER__
   u_char	 unused3;		/* unused field */
   u_char	 unused2;		/* unused field */
   u_char	 unused1;		/* unused field */
   u_char        mp_error_code;         /* init transfer modes error code */
#else	/* __MCAP_BOARD_DRIVER__ */
   u_int         unused;                /* unused field */
   u_short       mp_error_code;         /* MP driver init error code */
#endif	/* __MCAP_BOARD_DRIVER__ */
} init_trans_res_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct init_trst_res		/* init channel transfer state */
					/* results */
{
   u_char        mp_error_code;         /* code of error detected by MP */
					/* driver */
   u_char	 unused1;		/* unused field */
   u_char	 unused2;		/* unused field */
   u_char	 unused3;		/* unused field */
} init_trst_res_t;
#else
typedef struct init_trst_res		/* init channel transfer state */
					/* results */
{
   u_char	 unused3;		/* unused field */
   u_char	 unused2;		/* unused field */
   u_char	 unused1;		/* unused field */
   u_char        mp_error_code;         /* code of error detected by MP */
					/* driver */
} init_trst_res_t;
#endif /* MY_DRIVER_BIG_ENDIAN */
typedef struct adapter_access_res	/* device adapter access results */
{
   u_int	 read_value;		/* readed value */
#ifndef	__MCAP_BOARD_DRIVER__
   u_char        mp_error_code;         /* MP driver init error code */
#else	/* __MCAP_BOARD_DRIVER__ */
   u_short       mp_error_code;         /* MP driver init error code */
#endif	/* __MCAP_BOARD_DRIVER__ */
} adapter_access_res_t;

typedef union _sparc_drv_args_t			/* SPARC driver arguments of */
						/* task */
{
	mp_init_result_t     mp_init_results;	/* MP driver init results   , (2 ints, 2nd is alined) */
	trans_result_t	     transfer;		/* I/O transfer results     , (3 ints)  */
	dev_req_t	     drq;		/* I/O device request       , (3 chars) */
	init_trans_res_t     init_trans_results;/* init module transfer mode, (1 int) */
						/* results */
	init_trst_res_t	     init_state_res;	/* init channel transfer    , (1 int) */
						/* state results */
	adapter_access_res_t reg_read_results;	/* results of adapter       , (2 ints, 2nd is alined)*/
						/* register read */
#ifdef	__HIGH_INTERDRIVER_AREA_USED__
	u_int		args_area[15];		/* max area of SPARC task */
						/* arguments */
#else	/* __LOWINTERDRIVER_AREA_USED__ */
	u_int		args_area[ 3];		/* max area of SPARC task */
						/* arguments */
#endif	/* __HIGH_INTERDRIVER_AREA_USED__ */
} sparc_drv_args_t;

#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct _mp_state_diag_t         /* MP state diagnostic information */
{
   u_char        stage;                 /* last stage of MP driver execution */
   u_char        step;                  /* last step of the last stage */
} mp_state_diag_t;
#else
typedef struct _mp_state_diag_t         /* MP state diagnostic information */
{
   u_char        step;                 /* last stage of MP driver execution */
   u_char        stage;                  /* last step of the last stage */
} mp_state_diag_t;
#endif /* MY_DRIVER_BIG_ENDIAN  */

typedef union _mp_drv_state_t          /* MP driver state info */
{
   mp_state_diag_t diagnostic;         /* MP drv diagnostic info, 		(2 chars) */
   u_int          diag_area[ 1];       /* max area of MP drv diagnostic info ,  (1 int) */
} mp_drv_state_t;

typedef struct _proc_time_t             /* transfer processing time */
{
   u_int         mp_timer;              /* current MP time (in waiting mode) */
   u_int         mp_drq_receiving;      /* MP DRQ receiving time */
   u_int         mp_intr_drq_received;  /* interrupt on DRQ receiving from MP */
   u_int         mp_transfer_start;     /* transfer start on MP */
   u_int         mp_drq0_start;         /* DRQ0 mode start up on MP */
   u_int         mp_drq0_end;           /* DRQ0 mode end on MP */
   u_int         mp_drq3_start;         /* DRQ3 mode start up on MP */
   u_int         mp_transfer_finish;    /* transfer finish time on MP */
   u_int         mp_intr_transfer_end;  /* interrupt on transfer end from MP */
} proc_time_t;

#ifdef	__HIGH_INTERDRIVER_AREA_USED__
typedef struct drv_intercom_t_ 		/* SPARC and MP drivers communication */
{
   sparc_task_t      sparc_task;        /* current task from MP to SPARC */
   sparc_drv_args_t  sparc_args;        /* SPARC driver arguments of task */
   mp_task_t         mp_task;           /* current task from SPARC to MP */
   mp_drv_args_t     mp_args;           /* MP driver arguments of task */
   mp_drv_state_t    mp_drv_state;      /* MP driver state info */
   proc_time_t       processing_time;   /* transfer processing time */
} drv_intercom_t;
#else	/* __LOWINTERDRIVER_AREA_USED__ */
typedef struct drv_intercom_t_ 		/* SPARC and MP drivers communication */
{
   mp_task_t         mp_task;           /* current task from SPARC to MP */
   mp_drv_args_t     mp_args;           /* MP driver arguments of task */
   sparc_task_t      sparc_task;        /* current task from MP to SPARC */
   sparc_drv_args_t  sparc_args;        /* SPARC driver arguments of task */
   mp_drv_state_t    mp_drv_state;      /* MP driver state info */
   proc_time_t       processing_time;   /* transfer processing time */
} drv_intercom_t;
#endif	/* __HIGH_INTERDRIVER_AREA_USED__ */

#define  MP_INIT_AREA_char    	        ME90_MP_INIT_AREA_char
#define  MP_INIT_AREA_u_char            ME90_MP_INIT_AREA_u_char
#define  MP_INIT_AREA_long              ME90_MP_INIT_AREA_long
#define  MP_INIT_AREA_u_long            ME90_MP_INIT_AREA_u_long

/*
 * MicroProcessor commands
 */

#define MP_HALT_OPCODE			ME90_MP_HALT_OPCODE
#define MP_INIT_DEFAULT_CODE		ME90_MP_INIT_DEFAULT_CODE

/*
 * Next symbol define offset of JUMP operation address into MP init code above,
 * and must be edit if init code is changed 
 */
#define MP_INIT_JUMP_ADDR_OFF		ME90_MP_INIT_JUMP_ADDR_OFF

#ifdef	__cplusplus
}
#endif

#endif	/* __LINUX_MCB_DEF_H__ */
