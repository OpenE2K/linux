/* 
*
*/

#ifndef _UAPI_MMRM_IO_H
#define _UAPI_MMRM_IO_H

#define MEM_IVA                    0x500
#define MEM_VADD                   0x580
#define MEM_ABN                    0x600
#define MEM_PCI                    0x680

#define DEVICE_MEM_BYTE_SIZE       0x1C00
#define DEVICE_MEM_WORD_SIZE       DEVICE_MEM_BYTE_SIZE / 4

#define NONE_TYPE                  0
#define CONTROLLER_TYPE            1
#define TERMINAL_TYPE              2
#define MONITOR_TYPE               4

#define MMRM_IOC_MAGIC             ('R' << 8)
#define MMRM_IOC_RESET_DEVICE        MMRM_IOC_MAGIC | 1
#define MMRM_IOC_INIT_AS_CONTROLLER  MMRM_IOC_MAGIC | 2
#define MMRM_IOC_INIT_AS_TERMINAL    MMRM_IOC_MAGIC | 3
#define MMRM_IOC_INIT_AS_MONITOR     MMRM_IOC_MAGIC | 4
#define MMRM_IOC_HALT_DEVICE         MMRM_IOC_MAGIC | 5
#define MMRM_IOC_WRITE_SENT_INFORM   MMRM_IOC_MAGIC | 6
#define MMRM_IOC_GET_DESK_RESULT     MMRM_IOC_MAGIC | 7
#define MMRM_IOC_GET_RECEIVED_COM    MMRM_IOC_MAGIC | 8
#define MMRM_IOC_CNTRL_COM_SENDING   MMRM_IOC_MAGIC | 9
#define MMRM_IOC_PRINT_HISTORY       MMRM_IOC_MAGIC | 10
#define MMRM_IOC_BUFFER_MEM_CLEAR    MMRM_IOC_MAGIC | 11
#define MMRM_IOC_ONE_WORD_WRITING    MMRM_IOC_MAGIC | 12

typedef unsigned char              mmrm_term_dev_adr_t;
typedef unsigned char              mmrm_subadress_t;
typedef unsigned char              mmrm_term_trans_t;
typedef unsigned char              mmrm_byte_msg_size_t;
typedef unsigned short             mmrm_io_word_t;
typedef unsigned short             channel_check_word_t;
typedef unsigned char              mmrm_channel_msg_size_t;
typedef unsigned char              mmrm_cntrl_com_code_t;

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

typedef struct mmrm_cnt_sent_fields {
    int                      fields_number;
    mmrm_term_dev_adr_t      term_dev_adress;
    mmrm_subadress_t         subadress;
    mmrm_cntrl_com_code_t    cntrl_com_code;
} mmrm_cnt_sent_fields_t;

typedef union {
    mmrm_byte_msg_size_t     byte_msg_size;
    mmrm_cntrl_com_code_t    cntrl_com_code;
} size_or_code_t;

typedef struct mmrm_received_com_word {
    mmrm_term_dev_adr_t      term_dev_adress;
    mmrm_term_trans_t        term_trans_direction;
    mmrm_subadress_t         subadress;
    size_or_code_t           size_or_code;
} mmrm_received_com_word_t;

typedef union {
    mmrm_io_word_t           answer_word;
    mmrm_io_word_t           command_word;
} high_half_desk_res_t;

typedef struct desk_result {
    high_half_desk_res_t     high_half_desk_res;
    channel_check_word_t     channel_check_word;
} desk_result_t;

typedef struct one_word_writing {
	unsigned int	adress;
	unsigned int	value;
} one_word_writing_t;





#endif  /* !(_UAPI_MMRM_IO_H) */

