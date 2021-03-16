/* 
*
*/

#ifndef _UAPI_MGPM_IO_H
#define _UAPI_MGPM_IO_H


#define MEM_IVA                    0x500
#define MEM_VADD                   0x580
#define MEM_ABN                    0x600
#define MEM_PCI                    0x680

#define DEVICE_MEM_BYTE_SIZE       0x1C00
#define DEVICE_MEM_WORD_SIZE       DEVICE_MEM_BYTE_SIZE / 4
#define MAPPING_BYTE_SIZE          0x3000

#define NONE_TYPE                  0
#define CONTROLLER_TYPE            1
#define TERMINAL_TYPE              2
#define MONITOR_TYPE               4

#define DEVICE_BUF_BYTE_SIZE       4096*sizeof(int)
#define BATCH_BUF_BYTE_SIZE        4096*sizeof(int)

#ifndef hrtime_t
typedef long long		hrtime_t;
#endif
/** Size of statistic: trass*/
#define MAX_NUM_EL	100000

#define MGPM_IOC_MAGIC		('P' << 8)
#define MGPM_IOC_RESET_DEVICE	MGPM_IOC_MAGIC | 1
#define MGPM_IOC_DEBUG		MGPM_IOC_MAGIC | 3
#define MGPM_IOC_SET_FREQUENCY	MGPM_IOC_MAGIC | 4
#define MGPM_IOC_IOCTL_WAIT	MGPM_IOC_MAGIC | 5
#define MGPM_IOC_POLL_WAIT_ON	MGPM_IOC_MAGIC | 7
#define MGPM_IOC_IOCTL_WAIT_ON	MGPM_IOC_MAGIC | 8
#define MGPM_IOC_WAIT_MODE	MGPM_IOC_MAGIC | 9

#define MGPM_IOC_IOCTL_SPINWAIT_ON	MGPM_IOC_MAGIC | 10
#define MGPM_IOC_GET_TIME	MGPM_IOC_MAGIC | 11

#define MGPM_IOC_SET_DEBUG_MODE	MGPM_IOC_MAGIC | 12
#define MGPM_IOC_HALT_DEVICE	MGPM_IOC_MAGIC | 13
#define MGPM_IOC_START_TR	MGPM_IOC_MAGIC | 14
#define MGPM_IOC_GET_TR_SZ	MGPM_IOC_MAGIC | 15

#define	MGPM_ST_TIMES_OFFSET	0X1000000	/* offset to be mapped	*/
						/* size to be mapped	*/
#define	MGPM_ST_TIMES_SIZE	sizeof(mgpm_op_t)	

#define	MGPM_ST_TIMER_OFFSET	0X2000000	/* offset to be mapped	*/
						/* size to be mapped	*/
#define	MGPM_ST_TIMER_SIZE	sizeof(int)*2	

#define MGPM_DEB_ATTACH	0x01	/* attach debug		*/
#define MGPM_DEB_IOCTL	0x02	/* ioctl debug		*/
#define MGPM_DEB_INTR	0x04	/* interrupt debug	*/
#define MGPM_DEB_MMAP	0x08	/* memmap debug		*/
#define MGPM_DEB_RDWR	0x10	/* read/write debug	*/
#define MGPM_DEB_OPCL	0x10	/* open/close debug	*/
#define MGPM_DEB_ALL	0xFF	/* debug all		*/

typedef struct mgpm_op {
	uint		intr_time;	/* intr time processing		*/
	volatile hrtime_t	ptime;	/* in intr poll time		*/
	volatile hrtime_t	btime;	/* in intr begin time		*/
	volatile hrtime_t	time;	/* in intr end time		*/
	volatile hrtime_t	stime;	/* soft intr end time		*/
	volatile hrtime_t	sbtime;	/* soft intr begin time		*/
	volatile hrtime_t	s_dma_t;/* start DMA time		*/
	volatile hrtime_t	e_dma_t;/* end DMA time			*/
	uint		intr_counter;	/* number unprocessing inters	*/
	uint		intr_num;	/* number of generated inters	*/
	hrtime_t	timer;		/* mgpm timer			*/
} mgpm_op_t;

typedef unsigned char		mgpm_term_dev_adr_t;
typedef unsigned char		mgpm_subadress_t;
typedef unsigned char		mgpm_term_trans_t;
typedef unsigned char		mgpm_byte_msg_size_t;
typedef unsigned int		mgpm_io_word_t;
typedef unsigned short		channel_check_word_t;
typedef unsigned int		mgpm_channel_msg_size_t;
typedef unsigned char		mgpm_cntrl_com_code_t;

#define MIN_TERM_DEV_ADRESS        0
#define MAX_TERM_DEV_ADRESS        31
#define MIN_SUBADRESS              0
#define MAX_SUBADRESS              31
#define MIN_CHANNEL_MSG_SIZE       1
#define MAX_CHANNEL_MSG_SIZE       32

#define TERM_DEV_ADR_POS           0xF800
#define COMMAND_BIT_POS            0x0400
#define SUBADRESS_POS              0x03E0
#define SIZE_CODE_POS              0x001F
#define TERM_DEV_READ              2
#define TERM_DEV_WRITE             1

typedef struct mgpm_cnt_sent_fields {
    int                      fields_number;
    mgpm_term_dev_adr_t      term_dev_adress;
    mgpm_subadress_t         subadress;
    mgpm_cntrl_com_code_t    cntrl_com_code;
} mgpm_cnt_sent_fields_t;

typedef union {
    mgpm_byte_msg_size_t     byte_msg_size;
    mgpm_cntrl_com_code_t    cntrl_com_code;
} size_or_code_t;

typedef struct mgpm_received_com_word {
    mgpm_term_dev_adr_t      term_dev_adress;
    mgpm_term_trans_t        term_trans_direction;
    mgpm_subadress_t         subadress;
    size_or_code_t           size_or_code;
} mgpm_received_com_word_t;

typedef union {
    mgpm_io_word_t           answer_word;
    mgpm_io_word_t           command_word;
} high_half_desk_res_t;

typedef struct desk_result {
    high_half_desk_res_t     high_half_desk_res;
    channel_check_word_t     channel_check_word;
} desk_result_t;

typedef struct mtst_dma_read {
	int*	addr;
	u_int	size;
	int	fd;
	int	filler;
} mgpm_dma_read_t;

#endif  /* !(_UAPI_MGPM_IO_H) */

