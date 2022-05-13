/**
 * Copyright (c) 2010 by MCST.
 */
#ifndef _UAPI_MCST_MOKM_H
#define _UAPI_MCST_MOKM_H

#ifndef TRUE
    #define TRUE 1
#endif
#ifndef FALSE
    #define FALSE 0
#endif


/**
 *  IOCTL COMMANDS
 */
#define MOKM_IOC                (0xDAF5 << 8)
#define MOKM_IOC_RESET          (MOKM_IOC | 0x01)
#define MOKM_IOC_GET_STAT       (MOKM_IOC | 0x02)
#define MOKM_IOC_GET_MAXXFER    (MOKM_IOC | 0x03)
#define MOKM_IOC_CLEAR_STAT     (MOKM_IOC | 0x04)
#define MOKM_IOC_SND_MSG        (MOKM_IOC | 0x05)   //func
#define MOKM_IOC_RCV_MSG        (MOKM_IOC | 0x06)   //func
#define MOKM_IOC_SET_DBG        (MOKM_IOC | 0x07)
#define MOKM_IOC_WR_BUF         (MOKM_IOC | 0x0b)   //func
#define MOKM_IOC_GET_RD_WAIT    (MOKM_IOC | 0x0c)
#define MOKM_IOC_GET_WR_WAIT    (MOKM_IOC | 0x0d)
#define MOKM_IOC_SET_RD_WAIT    (MOKM_IOC | 0x0e)
#define MOKM_IOC_SET_WR_WAIT    (MOKM_IOC | 0x0f)
#define MOKM_IOC_PUT_RD_BUF     (MOKM_IOC | 0x10)   //func
#define MOKM_IOC_RD_BUF         (MOKM_IOC | 0x11)   //func
#define MOKM_IOC_DBG_POINT      (MOKM_IOC | 0x12)   //
#define MOKM_IOC_GET_WR_BUF     (MOKM_IOC | 0x13)   //func
#define MOKM_IOC_PUT_WR_BUF     (MOKM_IOC | 0x14)   //func

// ioctl MOKM_IOC_WR_BUF
typedef struct {
    int size; // Must be the first in this struct
    int buf_num;
} mokm_bufwr_t;


/**
 *  Statistics for MOKM
 */
typedef struct {
    // interrupts
    u_int       rsv_reset;          // Reset request
    u_int       lost_connect;       // Connection lost
    u_int       pear_optic_error;   // Pear optic error
    u_int       optic_error;        // Our optic error
    // -cmd
    u_int       rx_cmd_buf_full;    // Receive CMD buffer full
    u_int       tx_cmd_error;       // ERROR transmit CMD
    u_int       tx_cmd_buf_busy;    // Transmit CMD buffer busy
    u_int       rx_cmd_int;         // We recieved CMD
    // -rx
    u_int       rx_buf_ok;          // Reciever Done
    uint64_t    rx_size_all;        // Received bytes
    u_int       rx_buf_lost;        // Reciever Done with empty buf ptr
    u_int       rx_buf_pci_err;     // PCI ERROR on RCV DATA
    u_int       rx_buf_error;       // DATA recieve ERROR
    // -tx
    u_int       tx_buf_ok;          // Transmitter Done
    uint64_t    tx_size_all;        // Transmitted bytes
    u_int       tx_unknown_buf;     // Transmiter Done with empty buf ptr
    u_int       tx_buf_pci_err;     // PCI ERROR on TRANSMIT DATA
    u_int       tx_buf_error;       // DATA transmit ERROR
    u_int       tx_channel_error;   // Transmiter channel error
    //
    u_int       tx_remote_req;      // Remote request
    u_int       exception;          // EXCEPTION
    u_int       exception_code;

    // last write error
    u_int       lwr_pearrd;         // Pear still not ready (TRC.b.pearrd_rdy == 0)
    u_int       lwr_cfu_fail;       // copy_from_user failure
    u_int       lwr_nobuf;          // can't find requested buf
    u_int       lwr_timeout;        // timeout was reached (wait_event_interruptible_timeout)
    u_int       lwr_cantxmit;       // cant xmit buf

    // cur buf stat
    u_int       n_free_r_buf;
    u_int       n_free_w_buf;
} mokm_stat_t;


/**
 *  BUFFERS
 */
#ifndef PAGE_SIZE
	#error PAGE_SIZE
#endif
// Number of buffers in one pool (read or write) & One buffer size (max(x*y)==512)
#define MOKM_BUF_NUM    10
#define MOKM_BUF_SIZE   (PAGE_SIZE) // 4k
//
//#define MOKM_BUF_NUM    4
//#define MOKM_BUF_SIZE   (PAGE_SIZE*128) // 512k
//
#define POOLBUFS (MOKM_BUF_SIZE*MOKM_BUF_NUM) // must be pow of 2 // max==2Mb


/**
 *  Debug
 */
#undef PDEBUG
#ifdef MOKMDEBUG  // defined in makefile
# ifdef __KERNEL__  // This one if debugging is on, and kernel space
#  define PDEBUG(fmt, args...) printk( KERN_DEBUG "MOKM=" fmt, ## args)
# else // This one for user space
#  define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
# endif
#else // not debugging: nothing
# define PDEBUG(fmt, args...)
#endif
#undef nPDEBUG
#define nPDEBUG(fmt, args...) // nothing: it's a placeholder


#ifdef __KERNEL__ // ----------------------------------------------------------

#define ERROR_MSG(fmt, args...) printk( KERN_ERR "MOKM=" fmt, ## args)
#define WARNING_MSG(fmt, args...) printk( KERN_WARNING "MOKM=" fmt, ## args)
#define LOG_MSG(fmt, args...) printk( KERN_INFO "MOKM=" fmt, ## args)

/**
 *  Debug flags
 */
#define MOKM_DBG_RESET          0x001
#define MOKM_DBG_RX             0x002
#define MOKM_DBG_TX             0x004
#define MOKM_DBG_INTR           0x008
#define MOKM_DBG_IOCTL          0x010
#define MOKM_DBG_MEM            0x020


/**
 *  tools
 */
#define bzero(d, n) memset((d), 0, (n))
//#define MIN(A,B) ((A) < (B) ? (A) : (B))


/**
 *  Registers definitions
 */

/* R/W Transmit control Reg */
typedef struct	tcr_reg {
    u32     _dummy      : 5; // 27-31
    u32     size_pci    :11; // 16-26 R/W Data size on PCI in 4byte word, default=8
    u32     size_ch     :11; // 05-15 R/W Data size in channel in 4byte words, default=512
    u32     nrtry       : 5; // 00-04 R/W Num of retry if error occured, default=5
} tcr_reg_t;
typedef union tcr_r {
    tcr_reg_t   b;
    u32         r;
}tcr_r_t;

/* R/W Receive control Reg */
typedef struct	rcr_v1_reg {
    u32     cmd_bufsize : 5; // 27-31 R/W Size of cmd buf, default=16
    u32     size_pci    :11; // 16-26 R/W Data size on PCI in 4byte word, default=8
    u32     size_ch     :11; // 05-15 R/W Data size in channel in 4byte words, default=512
    u32     nrtry       : 5; // 00-04 R/W Num of retry if error occured, default=2
} rcr_v1_reg_t;
typedef struct  rcr_v2_reg {
    u32     cmd_bufsize : 5; // 27-31 R/W Size of cmd buf, default=16
    u32     size_pci    :11; // 16-26 R/W Data size on PCI in 4byte word, default=8
    u32     pci_retry   :11; // 05-15 R/W PCI retry on error cnt, default=100
    u32     reserv1     : 5; // 00-04
} rcr_v2_reg_t;
typedef union rcr_r {
    rcr_v1_reg_t    b1;
    rcr_v2_reg_t    b2;
    u32             r;
}rcr_r_t;

/* RC  Interrupt status Reg | Base + 0x0018 */
#define MOKM_ISR_RCV_RESET      (1 <<  0)   // Peer whant us to reset (need Reset TX & RX)
#define MOKM_ISR_RCV_CMD        (1 <<  1)   // We recieved CMD
#define MOKM_ISR_RCV_BUF        (1 <<  2)   // Reciever Done
#define MOKM_ISR_XMT_BUF        (1 <<  3)   // Transmiter Done
#define MOKM_ISR_PCIBUS_RCV_ERR (1 <<  4)   // ERROR PCI on RCV DATA
#define MOKM_ISR_PCIBUS_XMT_ERR (1 <<  5)   // ERROR PCI on TRANSMIT DATA
#define MOKM_ISR_RCV_NUM_ERR    (1 <<  6)   // ERROR recieve pkt num
#define MOKM_ISR_CMD_XMT_ERR    (1 <<  7)   // ERROR transmit CMD
#define MOKM_ISR_RCV_DATA_ERR   (1 <<  8)   // ERROR DATA recieve
#define MOKM_ISR_XMT_DATA_ERR   (1 <<  9)   // ERROR DATA transmit
#define MOKM_ISR_XMT_ERR        (1 << 10)   // ERROR Transmiter channel (need Reset TX)
#define MOKM_ISR_PEAR_FIBER_ERR (1 << 11)   // ERROR Pear optic (for stat only)
#define MOKM_ISR_FIBER_ERR      (1 << 12)   // FATAL Our optic error (AFBR5701)
#define MOKM_ISR_CMD_BUF_BUSY   (1 << 13)   // ERROR Comand(CMD) transmit buffer busy
#define MOKM_ISR_CONECT         (1 << 14)   // Lost/Find conect (see TRC.wr_rdy)
#define MOKM_ISR_CMD_BUF_FULL   (1 << 15)   // Receive CMD buffer full
#define MOKM_ISR_PEAR_READY_RCV (1 << 16)   // We ready to Transmit / Remote ready to receive
#define MOKM_ISR_REMOTE_REQ     (1 << 17)	/* ERROR Transmitter resp. wait timeout.
						 * Request for data transfer from remote module.
						 * Receiver requires initialization.
						 */
#define MOKM_ISR_EXCEPTION      (1 << 18)   /* EXCEPTION (num in TET reg) */

#define MOKM_ISR_ALL_TX (MOKM_ISR_XMT_BUF|MOKM_ISR_PCIBUS_XMT_ERR|MOKM_ISR_XMT_DATA_ERR|MOKM_ISR_XMT_ERR)
#define MOKM_ISR_ALL_RX (MOKM_ISR_RCV_BUF|MOKM_ISR_PCIBUS_RCV_ERR|MOKM_ISR_RCV_NUM_ERR|MOKM_ISR_RCV_DATA_ERR)
#define MOKM_ISR_CMD_STAT (MOKM_ISR_RCV_CMD|MOKM_ISR_CMD_XMT_ERR|MOKM_ISR_CMD_BUF_BUSY|MOKM_ISR_CMD_BUF_FULL)
#define MOKM_ISR_ANY_ERR (MOKM_ISR_PEAR_FIBER_ERR|MOKM_ISR_FIBER_ERR)

#define MOKM_ISR_ALL (MOKM_ISR_RCV_RESET|MOKM_ISR_CONECT|MOKM_ISR_PEAR_READY_RCV|MOKM_ISR_REMOTE_REQ|MOKM_ISR_EXCEPTION | MOKM_ISR_ALL_TX|MOKM_ISR_ALL_RX|MOKM_ISR_CMD_STAT|MOKM_ISR_ANY_ERR)

/* R/W Inturrupt Mask Reg   | Base + 0x001c */
#define MOKM_IMR_ALL_ENABLE (MOKM_ISR_ALL)

/* R/W Command Reg          | Base + 0x0020 */
#define MOKM_CR_RESET       (1)
#define MOKM_CR_PEAR_RESET  (2)
#define MOKM_CR_RESET_XMT   (3)
#define MOKM_CR_RESET_RCV   (4)
/* Request for h05 data transfer ??? */
#ifdef __sparc__ /* ARCH: e90, e90s */
  #if defined(VER_2614)
    #define MOKM_CR_ENDIAN    (0x00ffff00)  /* register rotation */
    #define MOKM_TRC_ENDIAN   (1<<11)       /* rotation for DMA  */
  #else
    #define MOKM_CR_ENDIAN    (0)       /* don't rotate, write with iowrite32() */
    #define MOKM_TRC_ENDIAN   (1<<11)   /* rotation for DMA */
  #endif /* VER_2614 */
#else /* ARCH: e2k */
    #define MOKM_CR_ENDIAN    (0)       /* don't rotate, write with iowrite32() */
    #define MOKM_TRC_ENDIAN   (0)       /* direct DMA */
#endif /* __sparc__ */

#define MOKM_CR_CMD_NUM     (0xff << 24)
#define MOKM_GET_CMD_NUM(__intr) (__intr >> 24)

/* R/W PC8374 Ctrl Reg      | Base + 0x0030 */
typedef struct  trc_reg {
	u32     _dummy1     : 1; /* 31    R   TDAR address validity flag (0 = trans. finished) */
	u32     cmdbufwbusy : 1; /* 30    R   out CMD buffer busy flag */
	u32     wr_rdy      : 1; /*+29    R   Channel ready to write (link Ok) */
	u32     pearrd_rdy  : 1; /*+28    R   Pear ready to read */
	u32     raddr_valid : 1; /* 27    R   RDAR address validity flag (0 = trans. finished) */
	u32     cmdbufrfull : 1; /* 26    R   input CMD buffer full flag */
	u32     _dummy2     : 1; /*+25    R   TX_ACT */
    /* next ReadModifyWrite only ! */
	u32     dbg_point   : 1; /* 24    R/W enable "TET" - request for data transfer is set ??? */
	u32     rtr_cnt     : 8; /* 16-23 R   retry count */
	u32     version     : 4; /* 12-15 R   version */
	u32     endian      : 1; /* 11    R/W enable endian <- MOKM_TRC_ENDIAN */
	u32     crc_deny    : 1; /* 10    R/W disable CRC */
	u32     EN_PLPBK    : 1; /* 09    R/W */
	u32     INS_DEL_DIS : 1; /* 08    R/W */
	u32     MODE        : 2; /* 06-07 R/W */
	u32     POEN        : 1; /* 05    R/W */
	u32     DEC_ENC_EN  : 1; /* 04    R/W */
	u32     CV_DIS_EN   : 1; /* 03    R/W */
	u32     EN_SLPBL    : 1; /* 02    R/W */
	u32     GEMOD       : 1; /* 01    R/W */
	u32     BMOD        : 1; /* 00    R/W */
} trc_reg_t;
typedef union trc_r {
    trc_reg_t   b;
    u32         r;
}trc_r_t;
#define TRC_B_WR_RDY        (1UL<<29)
#define TRC_B_PEARRD_RDY    (1UL<<28)
#define TRC_TX_ACT  (1<<25)

/* R/W Time Control         | Base + 0x0034 */
typedef struct  tc_reg {
    u32     XMT_TO      :16; // 16-31 R/W State message xmit period (ticks on 26,5MHz)
    u32     RCV_TO      :16; // 00-15 R/W Receive timeout (ticks on 26,5MHz)
} tc_reg_t;
typedef union tc_r {
    tc_reg_t    b;
    u32         r;
}tc_r_t;


typedef struct mokm_regs {  /* All regs 32b wide */
/*01:0x00*/  u32        TDAR;   /* R/W Transmit DMA Addr Reg| Base + 0x0000 */
/*02:0x04*/  u32        TDCR;   /* R/W Transmit DMA CNT Reg | Base + 0x0004 */
/*03:0x08*/  tcr_r_t    TCR;    /* R/W Transmit control Reg | Base + 0x0008 */
/*04:0x0C*/  u32        RDAR;   /* R/W Receive DMA Addr Reg | Base + 0x000c */
/*05:0x10*/  u32        RTR;    /* R   Receive CNT Reg      | Base + 0x0010 */
/*06:0x14*/  rcr_r_t    RCR;    /* R/W Receive control Reg  | Base + 0x0014 */
/*07:0x18*/  u32        ISR;    /* RC  Interrupt status Reg | Base + 0x0018 */
/*08:0x1C*/  u32        IMR;    /* R/W Inturrupt Mask Reg   | Base + 0x001c */
/*09:0x20*/  u32        CR;     /* R/W Command Reg          | Base + 0x0020 */
/*10:0x24*/  u32        PMR;    /* R/W Programm Message Reg | Base + 0x0024 */
/*11:0x28*/  u32        DR1;    /* R   Diag Reg 1           | Base + 0x0028 */
/*12:0x2C*/  u32        DR2;    /* R   Diag Reg 2           | Base + 0x002c */
/*13:0x30*/  trc_r_t    TRC;    /* R/W PC8374 Ctrl Reg      | Base + 0x0030 | defailt 0È000001b8*/
/*14:0x34*/  tc_r_t     TC;     /* R/W Time Control         | Base + 0x0034 */
/*15:0x38*/  u32        RDCR;   /* R   Receive DMA CNT Reg  | Base + 0x0038 */
/*16:0x3C*/  u32        TET;    /* R/W Error Test Timer     | Base + 0x003c */
} mokm_regs_t;


/**
 *  Private data of driver
 */

typedef struct mokm_buf {
    struct list_head list;
    u_int32_t   st;         // buffer state
    u_int32_t   num;        // buffer id
    u_int32_t   size;       // buffer size
    caddr_t     buf_addr;   // user access addr
    dma_addr_t  dma_addr;   // hardware DMA access
} mokm_buf_t;

typedef struct mokm_pool_buf {
    mokm_buf_t  buf[MOKM_BUF_NUM];  // Buffer list

    struct list_head free_list;     // list of free buffers
    struct list_head ready_list;    // list of ready for user buffers
    struct list_head busy_list;     // list of buffers used by user

    int         n_free;
    int         m_free;
    mokm_buf_t  *work_buf;          // In RCV or TRSM buff point
} mokm_pool_buf_t;

/* mokm_buf_t.st */
#define MOKM_BUF_ST_FREE    1

/** Private data of each instance of driver */
typedef struct mokm_dev {
    dev_t               dev;                    //
    struct cdev         cdev;                   // Char device structure
    struct pci_dev      *pdev;                  //
    unsigned int        irq;                    // Store irq number
    int                 attach_level;           // foe init end exit
    int                 instance;               // /dev/mokm/mokm(#)

    mokm_regs_t         *regs;                  // MMAP Regs here

    // parameters
    int                 sync_mode;              // wait for transmit end
    long                rd_wait_usecs;          // read must wait usecs for peer activity
    long                wr_wait_usecs;          // write must wait usecs for peer activity
    u_int               debug;                  //

    // MOKM_ISR_* / wake_up_interruptible
    wait_queue_head_t   wq_ready_rcmd;          // CMD_BUF_FULL, RCV_CMD
    wait_queue_head_t   wq_ready_rbuf;          // PCIBUS_RCV_ERR, PACK_NUM_ERR, RCV_DATA_ERR, RCV_BUF
    wait_queue_head_t   wq_ready_wbuf;          // PCIBUS_XMT_ERR, (CMD_XMT_ERR), XMT_DATA_ERR. XMT_ERR, XMT_BUF

    // buffers
    mokm_pool_buf_t     read_pool;              // buffers pool for receive
    mokm_pool_buf_t     write_pool;             // buffers pool for transmit
    caddr_t             rbuff;                  // user access base address (virt_memory from __get_free_pages)
    caddr_t             wbuff;                  // user access base address (virt_memory from __get_free_pages)

    // spinlock vvv
    spinlock_t          mutex_r;
#ifndef SINGLE_MUTEX
    spinlock_t          mutex_w;
#endif

    mokm_buf_t          *in_rcv;                // current receive buffer
    mokm_buf_t          *in_trm;                // current transmit buffer
    int                 rcv_err;                // error on last receive
    int                 xmit_err;               // error on last transmit

    u32                 intr_mask;              // Store interrupts mask

    u_char              open;                   //
    // spinlock ^^^

    mokm_stat_t         stat;                   // statistics
} mokm_dev_t;


/**
 * I/O
 */

#ifdef __sparc__
#if defined(VER_2614)

static inline void iowrite32 (u32 b, volatile void __iomem *addr)
{
    *(volatile u32 __force *) addr = b;
}

static inline u32 ioread32 (const volatile void __iomem *addr)
{
    return *(const volatile u32 __force *) addr;
}

#endif // VER_2614
#endif // __sparc__


#endif // __KERNEL__ // -------------------------------------------------------
#ifndef __KERNEL__ // ---------------------------------------------------------

/**
 * OPEN
 *
 * Returns buffer number on success,
 * negative on failure:
 *  -ENODEV - no device found
 *  -EBUSY - MOKM allready open and busy. Try again later.
 */


/**
 *  IOCTL
 */

/**
 * Move buffer from free_list to ready_list
 * @fd: device file handle
 * @pool: write pool (from mmap)
 * @write_array: return start of selected buffer
 *
 * Returns buffer number on success,
 * negative on failure:
 *  -EAGAIN - No Free Bufs (free buf list empty)
 */
int mokm_get_write_buf (int fd, int *pool, int **write_array)
{
	int res;
	if ((res = ioctl(fd, MOKM_IOC_GET_WR_BUF, NULL)) < 0 ) {
		*write_array = NULL;
		return res;
	}

	*write_array = pool+(res*MOKM_BUF_SIZE)/sizeof(u_int32_t);
	return res;
}

/**
 * Move buffer from ready_list to busy_list and try to transmit
 * @fd: device file handle
 * @buf_num: buffer number
 * @size: bytes to transmit
 *
 * Returns real transmitted bytes, 0 if request is buffered,
 * negative on failure:
 *  -EBUSY - Transmitter is busy
 *  -ENOLINK - Not connected (link down)
 *  -ENOSPC - Pear still not ready (TRC.b.pearrd_rdy == 0)
 *  -EINVAL - copy_from_user failure
 *  -EAGAIN - can't find requested buf
 *  -ETIMEDOUT - timeout was reached (wait_event_interruptible_timeout)
 *  -EFAULT - cant xmit buf
 */
int mokm_write (int fd, int buf_num, int size)
{
    mokm_bufwr_t buffer;

    buffer.buf_num = buf_num;
    buffer.size = size;
    return (ioctl(fd, MOKM_IOC_WR_BUF, &buffer));
}

/**
 * Wait while current transmit done and move buffer from ready_list to free_list
 * @fd: device file handle
 * @buf_num: buffer number
 *
 * Returns 0 on success,
 * negative on failure:
 *  -EAGAIN - can't find buf
 */
int mokm_put_write_buf (int fd, int buf_num)
{
    return (ioctl(fd, MOKM_IOC_PUT_WR_BUF, buf_num));
}

/**
 * Get buffer with received data (and move buffer from ready_list to busy_list)
 * @fd: device file handle
 * @pool: read pool (from mmap)
 * @read_array: return start of received buffer
 * @buf_num: return received buffer number
 *
 * Returns real received bytes,
 * negative on failure:
 *  -EAGAIN - nothing to read (ready list empty)
 *  -EFAULT - BUFF == NULL / Rcv wrong buff_num
 *  -EINVAL - copy_to_user failure
 */
int mokm_read (int fd, int* pool, int** read_array, int* buf_num)
{
	int res;
	int num;

	*buf_num = -1;
	if ((res = ioctl(fd, MOKM_IOC_RD_BUF, &num)) < 0) {
        *buf_num = -1;
        *read_array = NULL;
		return res;
	}

	*buf_num = num;
	*read_array = pool+(num*MOKM_BUF_SIZE)/sizeof(u_int32_t);
	return res;
}

/**
 * Move buffer from busy_list to free_list
 * @fd: device file handle
 * @buf_num: buffer number
 *
 * Returns 0 on success,
 * negative on failure:
 *  -EAGAIN - can't find buf
 */
int mokm_put_read_buf (int fd, int buf_num)
{
    return (ioctl(fd, MOKM_IOC_PUT_RD_BUF, buf_num));
}


/**
 * Send message
 * @fd: device file handle
 * @cmd: message
 *
 * Returns transmitted status, 0 if Ok,
 * negative on failure:
 *  -EBUSY - Tranmiter NOT ready (TRC.b.wr_rdy == 0)
 */
int mokm_write_cmd (int fd, u_int32_t cmd)
{
	return (ioctl(fd, MOKM_IOC_SND_MSG, cmd));
}

/**
 * Receive message
 * @fd: device file handle
 * @cmd: return message
 *
 * Returns received status, 0 if Ok,
 * negative on failure:
 *  -ETIMEDOUT - timeout was reached (wait_event_interruptible_timeout)
 *  -EINTR - Interrupted/Error
 *  -EINVAL - copy_to_user failure
 */
int mokm_read_cmd (int fd, u_int32_t* cmd)
{
    return (ioctl(fd, MOKM_IOC_RCV_MSG, cmd));
}


/**
 * Get statistics information
 * @fd: device file handle
 * @stat: return statistics
 *
 * Returns 0 if Ok,
 * negative on failure:
 *  -EINVAL - copy_to_user failure
 */
int mokm_get_stat (int fd, mokm_stat_t *stat)
{
    return (ioctl(fd, MOKM_IOC_GET_STAT, stat));
}

/**
 * Clear statistics information
 * @fd: device file handle
 *
 */
void mokm_clear_stat (int fd)
{
    ioctl(fd, MOKM_IOC_CLEAR_STAT, NULL);
}


#endif // !__KERNEL__ // ------------------------------------------------------

#endif // _UAPI_MCST_MOKM_H
