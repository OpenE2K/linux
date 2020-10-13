
/* Редакция: ИМВС - 25.04.03; МЦСТ - 24.02.03 */

/*
 * Defines and structures used by both the driver
 * and user application
 */

#ifndef	_UAPI__LINUX_ME90_IO_H__
#define	_UAPI__LINUX_ME90_IO_H__

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef __KERNEL__
#include <sys/types.h>
#endif /*__KERNEL__ */

#include <linux/mcst/define.h>

/*
 * Commands for 'ioctl' entry of E90 device driver
 */

#define ME90_IO			('E' << 8)

#define	ME90IO_LOAD_MP_DRV_CODE			(ME90_IO | 1)
#define	ME90IO_STARTUP_MP_DRV			(ME90_IO | 2)
#define	ME90IO_STARTUP_MP_ROM_DRV		(ME90_IO | 102)
#define	ME90IO_RESET_MP				(ME90_IO | 4)
#define	ME90IO_GET_DRIVER_INFO			(ME90_IO | 9)
#define	ME90IO_LOCK_RESET_MODULE_ON_ERROR	(ME90_IO | 10)
#define	ME90IO_UNLOCK_RESET_MODULE_ON_ERROR	(ME90_IO | 11)
#define	ME90IO_WAIT_FOR_TRANSFER_IN_PROGRESS	(ME90_IO | 12)
#define	ME90IO_STARTUP_MP_CODE			(ME90_IO | 13)
#define	ME90IO_SET_MP_STATE			(ME90_IO | 14)
#define	ME90IO_OUT_LAST_TRANS_STATE		(ME90_IO | 18)
#define	ME90IO_GET_DRIVER_TRACE_MSG		(ME90_IO | 19)
#define	ME90IO_RESTART_BOARD			(ME90_IO | 20)
#define	ME90IO_WRITE_DEV_ADAPTER_REG		(ME90_IO | 24)
#define	ME90IO_READ_DEV_ADAPTER_REG		(ME90_IO | 25)
#define	ME90IO_SET_DRV_GENERAL_MODE		(ME90_IO | 29)
#define	ME90IO_RESET_DRV_GENERAL_MODE		(ME90_IO | 30)
#define	ME90IO_GET_DRV_GENERAL_MODES		(ME90_IO | 31)
#define	ME90IO_PUT_DRV_GENERAL_MODES		(ME90_IO | 32)
#define	ME90IO_WAIT_FOR_ASYNC_TRANS_END		(ME90_IO | 33)
#define	ME90IO_CHECK_RESTART_BOARD		(ME90_IO | 34)
#define	ME90IO_START_RESTART_BOARD		(ME90_IO | 35)
#define	ME90IO_CONTINUE_RESTART_BOARD		(ME90_IO | 36)

/*
 * Type and name of boards
 */

typedef	enum e90_unit
{
	UNDEF_UT,
	MVP_UT,		/* "mvp" */
	MBK_UT,		/* "mbk" */
	MCKA_UT,	/* "mcka" */
	MCKK_UT,	/* "mckk */
	MC53_UT,	/* "mckp" */
	MKNP_UT,	/* "mknp" */
	MKOM_UT,	/* "mkom" */
	MCPM_UT,	/* "mcpm" */
	MCTC_UT,	/* "mctc" */
	MCFU_UT,	/* "mcfu" */
	MCEV_UT,	/* "mcev" */
	MKI26_UT,	/* "mki26" */
	MCAP_UT,	/* "mcap" */
	MMR_UT		/* "mmr" */
} e90_unit_t;

#define	MVP_BOARD_NAME		"mvp"
#define	MBK_BOARD_NAME		"mbk3"
#define	MCKA_BOARD_NAME		"mcka"
#define	MCKK_BOARD_NAME		"mckk"
#define	MC53_BOARD_NAME		"mckp"
#define	MKNP_BOARD_NAME		"mknp"
#define	MKOM_BOARD_NAME		"mkom"
#define	MCPM_BOARD_NAME		"mcpm"
#define	MCTC_BOARD_NAME		"mctc"
#define	MCFU_BOARD_NAME		"mcfu"
#define	MCEV_BOARD_NAME		"mcev"
#define	MKI26_BOARD_NAME	"mki26"
#define	MCAP_BOARD_NAME		"mcap"
#define	MMR_BOARD_NAME		"mmr"

#define	MCB_BOARD_NAME		"mcb"
#define	MKB_BOARD_NAME		"mkb"

#define	MVP_EPROM_BOARD_NAME	"MCST,mvp"
#define	MBK_EPROM_BOARD_NAME	"MCST,mbk3"
#define	MCKA_EPROM_BOARD_NAME	"MCST,mcka"
#define	MCKK_EPROM_BOARD_NAME	"MCST,mckk"
#define	MC53_EPROM_BOARD_NAME	"MCST,mckp"
#define	MKNP_EPROM_BOARD_NAME	"MCST,mknp"
#define	MKOM_EPROM_BOARD_NAME	"MCST,mkom"
#define	MCPM_EPROM_BOARD_NAME	"MCST,mcpm"
#define	MCTC_EPROM_BOARD_NAME	"MCST,mctc"
#define	MCFU_EPROM_BOARD_NAME	"MCST,mcfu"
#define	MCEV_EPROM_BOARD_NAME	"MCST,mcev"
#define	MKI26_EPROM_BOARD_NAME	"MCST,mki26"
#define	MCAP_EPROM_BOARD_NAME	"MCST,mcap"
#define	MMR_EPROM_BOARD_NAME	"MCST,mmr"

#define	MCB_EPROM_BOARD_NAME	"mcb"
#define	MKB_EPROM_BOARD_NAME	"mkb"

/*
 * Some atributes of the boards
 */

#define MAX_MCKA_BOARD_DEVICE_NUM	 2  /* max number of MCKA board */
					    /* device */
#define MAX_MCKK_BOARD_DEVICE_NUM	16  /* max number of MCKK board */
					    /* device */
#define MAX_MCKP_BOARD_CHANNEL_NUM	 2  /* max number of MCKP board */
					    /* channel (transmitter&receiver */
#define MAX_MCKP_BOARD_DEVICE_NUM	 4  /* max number of MCKP board */
					    /* device (transmitter | receiver */
#define MAX_MKNP_BOARD_DEVICE_NUM	 1  /* max number of MKNP board */
					    /* device */
#define MAX_MKOM_BOARD_DEVICE_NUM	 1  /* max number of MKOM board */
					    /* device */
#define MAX_MKOM_BOARD_INTERRUPT_NUM	 4  /* max number of MKOM supported */
					    /* clock interrupts */
#define MAX_MCPM_BOARD_DEVICE_NUM	 2  /* max number of MCPM board */
					    /* device */
#define MAX_MCTC_BOARD_DEVICE_NUM	 1  /* мак. номер устройства */
					    /* платы MCTC */
#define MAX_MKI26_BOARD_DEVICE_NUM	 1  /* мак. кол-во устройств */
					    /* платы MKI26 */
#define MAX_MCAP_BOARD_DEVICE_NUM	 1  /* мак. номер устройства */
					    /* платы MCAP */
#define MAX_MMR_BOARD_DEVICE_NUM	 1  /* мак. номер устройства */
					    /* платы MMR */
/*
 *  'ioctl' arguments structures
 */

typedef struct bmem_trans_desk
{
   caddr_t      mem_address;		/* SPARC memory address */
   caddr_t      mp_bmem_address;	/* MP base memory address */
   size_t       byte_size;		/* byte size of loaded code */
   caddr_t	mp_drv_init_info;	/* pointer of MP driver init info */
   size_t	mp_drv_init_info_size;	/* size of MP driver init info */
   caddr_t      mp_drv_init_info_addr;	/* MP driver init info base memory */
                                        /* address */
}	bmem_trans_desk_t;

/*
 *  DMA mapping burst sizes
 */

#define ME90_ENABLE_BURST_SIZES		0x3c	/* the supported burst sizes */
/* if burst 16 implemented
#define ME90_ENABLE_BURST_SIZES		0x7c
*/

#define	DMA_BURST_SIZE_4_BYTES		0x04	/* 4 bytes (1 word) */
#define	DMA_BURST_SIZE_8_BYTES		0x08	/* 8 bytes (2 words) */
#define	DMA_BURST_SIZE_16_BYTES		0x10	/* 16 bytes (4 words) */
#define	DMA_BURST_SIZE_32_BYTES		0x20	/* 32 bytes (8 words) */
#define	DMA_BURST_SIZE_64_BYTES		0x40	/* 64 bytes (16 words) */
#define	DMA_MAX_BURST_SIZE_BYTES	DMA_BURST_SIZE_64_BYTES

/*
 *  MP state flags
 */

#define	HALTED_MP_STATE			1	/* MP must be in the halted */
						/* state */
#define	CLEAN_BMEM_MP_STATE		2	/* base memory of MP must be */
						/* cleaned */

/*
 * Base memory mapping
 */

#define	MC_BMEM_REG_SET_OFFSET		0x00040000  /* Base Memory offset */
typedef	volatile caddr_t		mc_base_mem_t;	/* memory address */
#define	MC_BMEM_REG_SET_LEN		0x00020000 /* base memory length */

#define	MK_BMEM_REG_SET_OFFSET		0x00040000 /* Base Memory offset */
typedef	volatile caddr_t		mk_base_mem_t;	/* memory address */
#define	MK_BMEM_REG_SET_LEN		0x00010000 /* base memory length */

/*
 * General area of base memory mapping
 */

#define ME90_TRAP_TABLE_BMEM_ADDR	0x00000	/* trap taable */
#define ME90_TRAP_TABLE_BMEM_SIZE	0x00400 /* size of trap table */
#define	ME90_MP_ROM_DRV_INIT_ADDR	0x00400 /* Mp ROM driver init area */
						/* address */

#define ME90_MP_CODE_AREA_BMEM_ADDR	0x02000	/* default address of BMEM   */
						/* to load MP code	     */

#define MC_MP_INIT_AREA_BMEM_ADDR	0x1fff0	/* MP initialization area */

#define MK_MP_INIT_AREA_BMEM_ADDR	0x0fff0	/* MP initialization area */
#define ME90_MP_INIT_AREA_BMEM_SIZE	0x00010 /* size of MP init area */

typedef union mp_init_area_t_ 		/* MP initialization area */
{
   char		as_chars  [ME90_MP_INIT_AREA_BMEM_SIZE];
   u_char       as_u_chars[ME90_MP_INIT_AREA_BMEM_SIZE];
   int          as_longs  [ME90_MP_INIT_AREA_BMEM_SIZE / sizeof(int)];
   u_int        as_u_longs[ME90_MP_INIT_AREA_BMEM_SIZE / sizeof(u_int)];
} mp_init_area_t;

#define  ME90_MP_INIT_AREA_char		as_chars
#define  ME90_MP_INIT_AREA_u_char	as_u_chars
#define  ME90_MP_INIT_AREA_long		as_longs
#define  ME90_MP_INIT_AREA_u_long	as_u_longs

typedef struct me90_mp_rom_drv {	/* MP ROM driver init structute */
	int	debug_drv_start;	/* debug driver from main */
					/* memory rather then ROM */
	int	rom_disable;		/* ROM is disable flag */
} me90_mp_rom_drv_t;

/*
 * MicroProcessor commands
 */

#define ME90_MP_HALT_OPCODE		0xf4f4f4f4   /* HALT command opcode */
#define ME90_MP_INIT_DEFAULT_CODE	{ 0xfaea0000,  /* CLI JUMP */          \
					  0x00000000   /* JUMP_address end */  \
					}
#define ME90_MP_ROM_DRV_INIT_CODE	{ 0xfa33c08e,	/* CLI; _ES = 0; */  \
					  0xc0c60604,	/* mov byte ptr  */  \
					  0x0401f4f4	/* ES:[404], 1 */    \
					}

/*
 * Next symbol define offset of JUMP operation address into MP init code above,
 * and must be edit if init code is changed 
 */
#define ME90_MP_INIT_JUMP_ADDR_OFF	2

/*
 * Max size of memory page for SPARC platforms 
 */
#define MAX_SPARC_PAGE_SIZE		(8 * 1024)
#define MAX_SPARC_DRV_BUF_SIZE		(0x10000)

/*
 *  I/O operations <errno> error codes list extension
 */

#define	EMPHANGUP	240	/* MP of board hanguped */
#define	EMPCRASH	241	/* MP of board crash and failure to restart */
#define	EDEVFAULT	242	/* internal board fault occurs */
#define	EADPTABEND	243	/* the board adapter fault occurs */
#define	EMPROMDISABLE	244	/* MP ROM driver is disable */


/*
 *  Map of error code detected by MP driver (mp_error_code field of ioctl
 *  commands)
 */

/*
 *  Error codes detected by SPARC driver when MP driver services SPARC
 *  commands
 */

#define	NO_MP_DRIVER_ERROR		0
#define	NOT_COMPLETE_TASK_BY_MP_ERROR	230

/*
 *  Driver general mode flags 
 */

					/* reset the board and retrive */
					/* transfer mode if MP hanguped */
#define	RETRIEVE_MP_HANGUP_DRV_MODE	0x00000001
					/* reset the board and retrive */
					/* transfer mode if board internal */
					/* fault occured */
#define	RETRIEVE_DEV_FAULT_DRV_MODE	0x00000002
					/* retrive the board transfer mode */
					/* if adapter abend occurs */
#define	RETRIEVE_ADPT_ABEND_DRV_MODE	0x00000100
					/* default value of general mode */
					/* to be set by driver attache */
#define	FILL_BUF_SPACE_DRV_MODE		0x00008000
					/* fill buffer space to transfer */
					/* before usage */
#define	ONLY_BUF_IO_DRV_MODE		0x00010000
					/* only buffered transfer must be */
					/* used to transfer data (unbuffered */
					/* I/O physio() not used */
#define	MULTI_REQ_CHANNEL_DRV_MODE	0x00020000
					/* the channel can services a few */
					/* I/O request simultaneously */
#define	DATA_CACHE_FLUSH_DRV_MODE	0x00040000
					/* flush data cache of CPU before */
					/* any DMA I/O operation */
#ifdef	__MKOM_BOARD_DRIVER__
#define	DEFAULT_GENERAL_DRV_MODE	RETRIEVE_MP_HANGUP_DRV_MODE   |	\
					RETRIEVE_DEV_FAULT_DRV_MODE   |	\
					MULTI_REQ_CHANNEL_DRV_MODE    |	\
					RETRIEVE_ADPT_ABEND_DRV_MODE
#else	/* __MKNP_BOARD_DRIVER__ */
#define	DEFAULT_GENERAL_DRV_MODE	RETRIEVE_MP_HANGUP_DRV_MODE   |	\
					RETRIEVE_DEV_FAULT_DRV_MODE   |	\
					RETRIEVE_ADPT_ABEND_DRV_MODE
#endif	/* __MKOM_BOARD_DRIVER__ */

/*
 * An asynchronous I/O request waiting for the completion structure
 */

typedef struct aiotrans_wait {			/* asynchronous transfer end */
						/* waiting for */
	int		waiting_time;		/* timer interval of waiting */
						/* for an asynchronous */
						/* request will be finished */
						/* (usec) */
						/* if time is < 0 then */
						/* waiting is indefinite */
						/* if time is zero then */
						/* return immediately */
	caddr_t		*trans_res_info_pp;	/* pointer to place to store */
						/* the pointer to transfer */
						/* results info used when the */
						/* completed asynchronous I/O */
						/* operation was requested */
} aiotrans_wait_t;

/*
 *  The driver private buffers management (support and strategy of buffer
 *  transfer from/to main memory and to/from user  requests.
 *  Структура определяющая поддержку и обслуживание собственных буферов
 *  драйвера в основной памяти и памяти МП (если они необходимы).
 */

typedef struct me90_buf_man {			/* driver buffers management */
						/* specifications */
						/* параметры стратегии */
						/* поддержки буферов драйвера */
	int		min_free_buf_num;	/* min number of items in the */
						/* list of free buffers at */
						/* any time to reflect state */
						/* of driver buffers */
						/* минимальное число буферов, */
						/* которое должно */
						/* поддерживаться в списке */
						/* свободных для обеспечения */
						/* работы с буферами */
						/* если < 0, то берется */
						/* значение по умолчанию */
						/* (см. далее) */
	int		max_buf_num;		/* max number of buffers to */
						/* reflect state of driver */
						/* buffers in the main driver */
						/* максимально допустимое */
						/* число используемых буферов */
						/* (ограничение сверху) */
						/* если <= 0, то число */
						/* буферов не ограничивается */
						/* сверху */
	int		min_buf_num;		/* min number of buffers to */
						/* reflect state of driver */
						/* buffers in the main driver */
						/* минимальное число */
						/* создаваемых буферов */
						/* (ограничение снизу) */
						/* если <= 0, то берется */
						/* значение по умолчанию */
						/* (см. далее) */
} me90_buf_man_t;

/*
 *  Optimum default value of driver main memory buffers management args
 *  Значения по умолчанию параметров обслуживания буферов в основной памяти
 */

#define	MIN_ME90_FREE_BUF_NUM_DEF	1	/* 1 for next transfer */
						/* 1 свободный для */
						/* следующего обмена */
#define	MAX_ME90_BUF_NUM_DEF		1 	/* only 1 transfer available */
						/* at any time */
						/* только 1 обмен может быть */
						/* в любой момент */
#define	MIN_ME90_TOTAL_BUF_NUM_DEF	1	/* in progress + next + free */
						/* 1 для текущего + */
						/* 0 для следующего + */
						/* 0 для завершенного */

typedef struct me90_drv_info
{
	int		sbus_clock_freq;	/* SBus clock frequency */
	int		sbus_nsec_cycle;	/* SBus clock in nsec */
	int		mp_clock_freq;		/* MP clock frequency */
	int		mp_nsec_cycle;		/* MP clock in nsec */
	e90_unit_t	device_type;		/* type of the board (device) */
	int		mp_rom_drv_enable;	/* MP ROM driver is enable */
#ifdef	_MP_TIME_USE_
	u_int        cur_hr_time;		/* currenr hi resolution time */
#else
	hrtime_t     cur_hr_time;		/* currenr hi resolution time */
#endif	/* _MP_TIME_USE_ */
}	me90_drv_info_t;

typedef struct drv_trace_msg
{
   char *	msg_buf_addr;	/* buffer for tracer messages */
   int		msg_buf_size;	/* byte size of buffer */
   int		msg_line_num;	/* number of line writed into buffer */
   int		msg_line_size;	/* byte size of each message line */
}	drv_trace_msg_t;

typedef struct dev_reg_spec		/* device adapter regs access */
{
   u_int	address;		/* device adapter register address */
   u_int	reg_value;		/* readed value or to write */
   u_char	mp_error_code;		/* code of error returned by MP */
                                        /* driver if one occured */
}	dev_reg_spec_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _UAPI__LINUX_ME90_IO_H__ */

