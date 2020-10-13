#ifndef _BK3_H_
#define _BK3_H_

/*
 * Copyright (c) 1997 by MCST.
 */
#include <linux/mcst/bk3_def.h>
#include <linux/workqueue.h> /* maks */

/*
 *  Уровни отладки
 */
#undef BK3_LIST_DEBUG
#undef BK3_REG_DEBUG
#undef BK3_STATUS_DEBUG
#undef BK3_POSTD_DEBUG
#undef BK3_WAIT_DEBUG

/* 
 *		Version and release of protocol
 */
#define	BK3_PROT_VER          1
#define	BK3_PROT_REL          2
#define	BK3_PROT_VER_SHIFT    8
#define	BK3_PROT_REL_VER_MASK	0xFFFF
#define	PRN_FAIL_ADDR_COUNT   5
#define my_rel_ver (BK3_PROT_REL | (BK3_PROT_VER << BK3_PROT_VER_SHIFT))

/*
 *	Interrupts
 */

  /*  Maximum valuable bit in interrupt reg */
#define	BK3_MAX_INTERRUPT       (1 << 11)
#define	BK3_POSSIBLE_INTERRUPTS 0xFFF
#define	BK3_I_CMDFREE	 (1 << 11) /* Command buffer free */
#define	BK3_I_RPTCMD	 (1 << 10) /* we are asked to repeat command */
#define BK3_I_SBUSPRTY (1 << 9)	 /* S-bus parity control */
#define BK3_I_RCVFLT   (1 << 8)	 /* rcvr fault  */
#define BK3_I_ISCMD	   (1 << 7)	 /* There is command to read */
#define BK3_I_OPTPRTY  (1 << 6)	 /* Optic parity failure */
#define BK3_I_TRMZERO  (1 << 5)	 /* IO count of transmitter == 0 */
#define BK3_I_RCVZERO  (1 << 4)	 /* IO count of reciever == 0 */		
#define BK3_I_LSRFAILR (1 << 3)	 /* Laser failure */
#define	BK3_I_CMDFLT   (1 << 2)	 /* cmd has been read with error */
#define	BK_I_PKTERR    (1 << 1)	 /* bad type of packet */
#define BK3_I_RESET    (1 << 0)	 /* Request to reset */

	/* Interrupt mask */
#define	BK3_IM_M1	    (1 << 1)
#define	BK3_IM_M2	    (1 << 2)
#define	BK3_IM_ALL    (BK3_IM_M1 | BK3_IM_M2)

#define	BK3_IM1_INTRS	(BK3_I_RESET  | BK3_I_RCVZERO | BK3_I_TRMZERO | \
                       BK3_I_CMDFLT | BK3_I_RPTCMD  | BK3_I_CMDFREE | BK3_I_ISCMD)

#define	BK3_IM2_INTRS	(BK_I_PKTERR  | BK3_I_LSRFAILR | BK3_I_OPTPRTY | \
                       BK3_I_RCVFLT | BK3_I_SBUSPRTY)

/*
 *	TCNT/RCNT structure
 */
				
#define BK3_SIZE_MASK	0x0000ffff /* Number of blocks field mask */
#define BK3_BLK_MASK	0x00070000 /* Block size field mask       */
#define	BK3_BLK_SHIFT	16
#define	BK3_HW_BLK_SZ    64   /* Hardware minimum block size to transfer */
#define	BK3_HW_BLK_SHIFT 6
#define	BK3_ALIGN_MASK   0x3F /* To check alignment and padding of I/O array */


/*
 *    Registers definitions   ( u_int = 32b == caddr_t)
 */
 
typedef struct	{	/* All regs 32b wide */
	u_int	dummy00;
	u_int	dummy04;
	u_int	tcwd;	   /* Transmitter address register 0x-x008 */
	u_int	dummy0c;
	u_int	rcwd;	   /* Reciever address register	   0x-x010 */
	u_int	dummy14;
	u_int	mask;	   /* Interrupt mask register	     0x-x018 */ 
	u_int	dummy1c;
	u_int	wctl;	   /* Transmit Command register	   0x-x020 */
	u_int	dummy24;
	u_int	wcmd;	   /* Not used			               0x-x028 */
	u_int	dummy2c;
	u_int	intr;	   /* Interrupt register		       0x-x030 */
	u_int	dummy34;
	u_int	rctl;      /* Recieve command register	   0x-x038 */
	u_int	dummy3c;
	u_int	arst;      /* Reset I/O channel register	 0x-x040 */
	u_int	dummy44;
	u_int	prst;      /* Raise D[0] intr for mate	   0x-x048 */
	u_int	dummy4c;
	u_int	rcnt;      /* Reciever counter/blksz reg	 0x-x050 */
	u_int	dummy54;
	u_int	trst;      /* Reset Transmitter I/O buf	   0x-x058 */
	u_int	dummy5c;
	u_int	tcnt;      /* Tramsmitter cntr/blksz reg	 0x-x060 */
	u_int	dummy64;
	u_int	rswcnl;    /* Switch channel (base == 0 | reserve == 1) 0x-x068 */
	u_int	dummy6c;
	u_int	rptcmd;    /* Sends request to repeat cmd	 0x-x070 */
	u_int	r_fifo;    /* Recieve register fifo (выполнить 256 раз) 0x-x078 */
} bk3_regs_t;

#define BK3_REG_SIZE	sizeof (bk3_regs_t)
/*
 *  Буфер
 */
typedef struct bk3_buf {
	struct list_head list;
	dma_addr_t	 address;
	void		*kvaddr;
	int num;
} bk3_buf_t;

#define search_in_list( list1,  num1) ({ \
	struct list_head* tmp; \
	struct list_head* ret=0; \
	list_for_each(tmp, list1) { \
		if( list_entry(tmp, bk3_buf_t, list)->num == num1) { \
			ret = tmp;\
			break;\
		} \
	} \
	ret;})

#ifdef BK3_LIST_DEBUG

#define CHECK_LIST(list) ({\
	int check = ((list)->next && (list)->prev);\
	if(check == 0)\
		printk("list " #list " corrupted; pid:%d %s:%d\n",\
			in_interrupt()?0:current->pid, __FUNCTION__, __LINE__);\
		check;})

#define list_del1(entry) do{\
		DPRINTK("%-64s #%d", "list_del(" #entry ")",\
				list_entry((entry), bk3_buf_t, list)->num );\
		list_del(entry); } while(0)


#define list_add_tail1(new3, head3) do{\
			DPRINTK("%-64s #%d", "list_add_tail("#new3 "," #head3 ")",\
					list_entry((new3), bk3_buf_t, list)->num );\
					list_add_tail( new3, head3); } while(0)

#define list_move_tail1(list3, head3) do { \
	if(	CHECK_LIST(head3) && \
			CHECK_LIST(list3) && \
			CHECK_LIST((list3)->prev) && \
			CHECK_LIST((list3)->next)){ \
		DPRINTK("%-64s #%d", "list_move_tail("#list3 "," #head3 ")", \
					list_entry((list3), bk3_buf_t, list)->num); \
		 			list_move_tail( list3, head3); \
	}\
} while(0)
 
#else /*BK3_LIST_DEBUG*/

#define list_del1(entry)              list_del(entry)
#define list_add_tail1(new3, head3)   list_add_tail(new3, head3)
#define list_move_tail1(list3, head3) list_move_tail( list3, head3)

#endif /*BK3_LIST_DEBUG*/


typedef struct bk3_pool_buf {
	bk3_buf_t         	buffer[NUM_BUF_BK3];
	struct list_head	free_list;	/* список свободных */
	struct list_head	ready_list;	/* список готовых на выдачу */
	struct list_head	busy_list;	/* список занятых пользователем */
	bk3_buf_t         	*work_buf;	/* в обмене */
} bk3_pool_buf_t;

	/* Private data of each instance of driver */

typedef struct {

	struct of_device	*op;
	int			instance;
	struct mutex     mutex;
	
	kcondvar_t   cv_wait_peer_reset;
	kcondvar_t   cv_reset;
	kcondvar_t   cv_D0_reset;

	kcondvar_t   cv_cmd;
 	kcondvar_t   cv_no_read_buffers;
 	kcondvar_t   cv_no_write_buffers; 

	kcondvar_t   cv_msg_in;
	kcondvar_t   cv_msg_out;

 	size_t 	     buf_size;

	u_int       work_mask;

	volatile bk3_regs_t  *bk3_regs_p;  /* регистры устройства */
	volatile u_int	    status;       /* см. флаги ниже */
	u_int	    io_modes;     /* см. флаги ниже */
	long	    reset_time;	  /* time to wait for real IO */

				   /* to complete (usexs)*/
	long	    rd_wait_usecs; /* read must wait usecs for */

				   /* peer activity */
	long	    wr_wait_usecs; /* write must wait usecs for */

				   /* peer activity */
	u_int	    last_cmd;
	u_int	    last_cmd_rpt_cnt;
	u_int	    last_snd_cmd_tag;

	int         version_mbk3;
	u_int       type;	  /* MBK3_OPTIC | MBK3_ELECTRIC */
	u_int       channel; /* channel base == 0, reserve == 1 */

#define	bk3_io_buf	(bks->io_buf)

	u_int	    burstes;
	u_char	    prots_matched;
	u_char	    burst; /* power of 2 of using burst */
	u_char	    siz; 
	u_char		rd_ready;
 	bk3_stat_t	stat;
	bk3_msg_rcv_t	msg_rcv;

	bk3_pool_buf_t	read_pool;
	bk3_pool_buf_t	write_pool;

	struct work_struct D0_intr_tqueue;
	struct work_struct interrupt_tqueue;
	
	dma_addr_t 	dma_addr;  /* адрес буфера преобразованый в dma-адрес */
	unsigned int 	*buffer;   /* Буферы приёма/передачи */

	raw_spinlock_t interrupt_lock;
 	int interrupts;
	
} bk3_devstate_t;


	/* io_modes field flags */
#define	NO_DUPLEX           0x04
#define	RD_RESET_BEFORE_IO  0x08
#define	WR_RESET_BEFORE_IO  0x10

	/** default values of some fields **/

#define	BK3_IO_MODES_DEFAULT	(NO_DUPLEX | RD_RESET_BEFORE_IO | \
					WR_RESET_BEFORE_IO)

#define	BK3_RESET_TIME_DEFAULT (3 * 1000000)
#define	BK3_RD_WAIT_DEFAULT    (5 * 1000000)
#define	BK3_WR_WAIT_DEFAULT    (5 * 1000000)

#define	BK3_NUM_RESTART_DEFAULT 0
#define	BK3_NUM_RESET_TRY       5

	/*  status field flags  */
#define	PEER_IS_DEAD         0x0000001 /* мы решили что абонент в отказе */
#define	READ_IS_ACTIVE       0x0000002 /* драйвер исполняет чтение	*/
#define	WRITE_IS_ACTIVE      0x0000004 /* драйвер исполняет запись	*/
#define	READ_IS_OVER         0x0000040 /* устройство выполнило чтение */
#define	WRITE_IS_OVER        0x0000400 /* устройство выполнило запись */
#define	PEER_READ_IS_OVER	   0x0000800 /* aбонент выполнил чтение */
#define	WE_RAISED_RESET      0x0010000 /* мы решили что устройство зависло и */
                                       /* инициировали У0 устройства и абонента */
#define	RESET_IN_PROGRESS    0x0020000 /* драйвер занимается нулением аналов */
#define	PEER_RESET_DONE      0x0080000 /* выполнен У0 абонента	*/
#define	CMD_IS_ACTIVE        0x0100000 /* команда послана абоненту и мы */
					                             /* ждем подтверждения получения  */
#define	CMD_WAIT_FREE        0x0200000 /* somebody is going to send cmd */
                                       /* and waiting for cmd free */
#define	CONFIRM_PEER_RESET   0x0400000 /* peer done reset and asked us */
                                       /* to confirm our reset */
#define	RESET_NEEDED         0x0800000
#define	WE_SND_MSG           0x1000000 /* мы послали СБЩ */
#define	NO_RECEIVING_BUFFERS 0x0001000 /* Отсутствуют буфера на приём */
#define	WE_GOT_MESSAGE			 0x0002000 /* Мы получили сообщение */


#ifdef BK3_STATUS_DEBUG


#define	ON_STATUS(bks,M)	do{bks->status |=  (M);DPRINTK("%-40s:ON 	bk3 %d",#M,inst);}while(0)
#define	OFF_STATUS(bks,M)	do{bks->status &= ~(M);DPRINTK("%-40s:OFF	bk3 %d",#M,inst);}while(0)

#else /* BK3_STATUS_DEBUG */
#define	ON_STATUS(bks,M)	(bks->status |= (M))
#define	OFF_STATUS(bks,M)	(bks->status &= ~(M))

#endif /*BK3_STATUS_DEBUG*/

#define	IS_ON_STATUS(bks,M)  (bks->status & (M))
#define	IS_OFF_STATUS(bks,M) (!(bks->status & (M)))

#define	RESET_STATUS(bks)	(bks->status = 0);
#define	NEW_VERS(bks)		(bks->version_mbk3 == 1)
#define	OLD_VERS(bks)		(bks->version_mbk3 == 0)

  /* Registers handling */
#ifdef BK3_REG_DEBUG
#define	SET_BK3_REG(bks,reg,what)  do { \
		   bks->bk3_regs_p->reg = what; \
			 DPRINTK("bk3 %d SET_BK3_REG(%-40s): *%p = %08lX	", inst, #reg ",  " #what, &bks->bk3_regs_p->reg, (unsigned int)what); \
		} while(0)

#define	GET_BK3_REG(bks, reg) ({ \
		   unsigned int res = bks->bk3_regs_p->reg; \
		   DPRINTK("bk3 %d GET_BK3_REG(%-40s):           = %08lX	", inst, #reg, res); \
			 res;})

#else /* BK3_REG_DEBUG */
#define	SET_BK3_REG(bks, reg, what)	bks->bk3_regs_p->reg = what
#define	GET_BK3_REG(bks, reg)		    bks->bk3_regs_p->reg
#endif /* BK3_REG_DEBUG */

#define	SET_RRST_REG(bks,what)	bks->bk3_regs_p->rcnt = what;\
				drv_usecwait(50)

#define	SET_TRST_REG(bks,what)	bks->bk3_regs_p->tcnt = what;\
				drv_usecwait(50)

#define	SET_BK3_MASK(bks, VAL_MASK) { \
  bks->work_mask = VAL_MASK; \
  SET_BK3_REG(bks, mask, bks->work_mask); \
}

#define	GET_BK3_MASK(bks) {	\
	bks->work_mask = GET_BK3_REG(bks, mask); \
}

#define	BK3_MASK(bks)	bks->work_mask

/*
 *    Commands
 */

/* Command structure */
#define BK3_C_ARG_MASK		0x00ffffff
#define BK3_C_CMD_MASK		0x7f000000
#define	BK3_C_TAG_MASK		0x80000000


/*
 *    Read ask. Reciever initiates I/O.
 *    Argument : number of 16-byte blocks to be able to recieve
 */
 
#define BK3_C_RASK       0x05000000 /* у абонента готов приёмный буфер */
#define BK3_C_PEER_RESET 0x40000000 /* абонент перезагрузился */


#define BK3_C_SND_MSG		0x50000000 /* мы послали сообщение */
#define BK3_C_RCV_MSG		0x51000000 /* м*/
#define BK3_C_SND_RD		0x77000000

#define	PEER_ON_SYNC_MODE  0x76000000 /* aбонент включил синхронизацию  */
#define	PEER_OFF_SYNC_MODE 0x78000000 /* aбонент выключил синхронизацию */

#define	WE_SND_CMD 0x79300000 /* we send cmd */


/*
 *		TYPE MBK3
 */
#define	MBK3_OPTIC    0
#define	MBK3_ELECTRIC 1


/*
 *		WORK CHANNEL MBK3_ELECTRIC
 */
#define	MBK3_CHANNEL_BASE    0
#define	MBK3_CHANNEL_RESERVE 1

extern int bk3_debug;
/*
 *		Debug flags
 */
#define	BK3_DEBUG_WAITING       0x01
#define	BK3_DBG_START_TRANSFER  0x02
#define	BK3_DBG_ERR_RETURNS     0x04
#define	BK3_DBG_INTR            0x08
#define	BK3_DBG_IOCTL           0x10
#define	BK3_DBG_RESET           0x20
#define	BK3_DBG_SEND_CMD        0x40
#define	BK3_REG_WR              0x80
#define	BK3_ATTACH              0x100

#define	CE_CONT  KERN_EMERG		/* continuation */
#define	CE_NOTE  KERN_NOTICE	/* notice       */
#define	CE_WARN	 KERN_WARNING	/* warning      */
#define	CE_PANIC KERN_EMERG		/* panic        */

#define cmn_err(level, fmt, args...) printk(level fmt "\n", ## args)

#define gethrtime   ddi_gethrtime
#define bzero(d, n) memset((d), 0, (n))

#define DPRINTK(fmt, args...) \
		printk(KERN_EMERG fmt ":%-21s #%d	pid: %d\n",## args, __FUNCTION__, __LINE__, current->pid)

#define dprt(fmt, args...) printk(  KERN_EMERG fmt "\n", ## args)

#define TRACE(arg) ({\
			int res;\
			printk(KERN_EMERG __FUNCTION__ ":%d:\n" #arg,__LINE__);\
			res =  arg; res;})

#ifdef BK3_WAIT_DEBUG
#undef	cv_timedwait
#define	cv_timedwait(args...) ({\
			int res;\
			res = ddi_cv_timedwait(args);\
			DPRINTK("cv_timedwait(%50s) == %2d	bk3 %d", #args, res, inst);\
			res;})

#undef	cv_broadcast
#define	cv_broadcast(cv) do{\
			ddi_cv_broadcast(cv);\
			DPRINTK("cv_broadcast(" #cv ")					bk3 %d", inst);\
			}while(0)

#else /*BK3_WAIT_DEBUG*/
#endif /*BK3_WAIT_DEBUG*/

#define  TRANSF_CNT ((bks->siz << BK3_BLK_SHIFT) | (bks->buf_size >> (bks->burst - 1)))

void bk3_D0_intr_handle(void * arg);
int bk3_reset_device(bk3_devstate_t *bks);
irqreturn_t bk3_intr(int irq, void *arg);
irqreturn_t bk3_interrupt(int irq, void *arg);
int bk3_postd1( bk3_devstate_t *bks, u_int messg);
int bk3_init_pool_buf(bk3_devstate_t *bks);

#ifdef BK3_POSTD_DEBUG

#define bk3_postd( bks, messg) ({\
	int res;DPRINTK("bk3_postd("#messg")		bk3 %d", inst);\
	res = bk3_postd1( bks, messg);\
 res;})
 
#else /* BK3_POSTD_DEBUG */
#define bk3_postd bk3_postd1
#endif /* BK3_POSTD_DEBUG */

#endif /*_BK3_H_*/
