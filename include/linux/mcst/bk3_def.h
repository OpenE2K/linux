#ifndef _BK3_DEF_H_
#define _BK3_DEF_H_

#include <asm/page.h>

#ifdef __KERNEL__
#include <linux/time.h>
typedef unsigned long long u_longlong_t;
typedef struct timespec timestruc_t;
#else
typedef struct bk3_buf{
	unsigned long reseved1;
	unsigned long reseved2;
	unsigned long reseved3;
	int num;
} bk3_buf_t;
#endif /*__KERNEL__*/


/**
 *		IOCTL COMMANDS
 **/

#define MBK3_IOC_MAGIC  'K'

#define	BK3_IOC_RESET          _IOWR(MBK3_IOC_MAGIC,  1, unsigned long)
#define	BK3_IOC_GET_STAT       _IOWR(MBK3_IOC_MAGIC,  2, unsigned long)
#define	BK3_IOC_GET_MAXXFER    _IOWR(MBK3_IOC_MAGIC,  3, unsigned long)
#define	BK3_IOC_SET_BURST      _IOWR(MBK3_IOC_MAGIC,  4, unsigned long)
#define	BK3_IOC_GET_BURST      _IOWR(MBK3_IOC_MAGIC,  5, unsigned long)
#define	BK3_IOC_SET_IO_MODES   _IOWR(MBK3_IOC_MAGIC,  6, unsigned long)
#define	BK3_IOC_GET_IO_MODES   _IOWR(MBK3_IOC_MAGIC,  7, unsigned long)
#define	BK3_IOC_SET_DBG			   _IOWR(MBK3_IOC_MAGIC,  8, unsigned long)
#define	BK3_IOC_GET_BURSTES    _IOWR(MBK3_IOC_MAGIC,  9, unsigned long)
#define	BK3_IOC_GET_RD_WAIT    _IOWR(MBK3_IOC_MAGIC, 10, unsigned long)
#define	BK3_IOC_GET_WR_WAIT    _IOWR(MBK3_IOC_MAGIC, 11, unsigned long)
#define	BK3_IOC_SET_RD_WAIT    _IOWR(MBK3_IOC_MAGIC, 12, unsigned long)
#define	BK3_IOC_SET_WR_WAIT    _IOWR(MBK3_IOC_MAGIC, 13, unsigned long)
#define	BK3_IOC_GET_RESET_TIME _IOWR(MBK3_IOC_MAGIC, 14, unsigned long)
#define	BK3_IOC_SET_RESET_TIME _IOWR(MBK3_IOC_MAGIC, 15, unsigned long)
#define	BK3_IOC_ACKNOLEDGE     _IOWR(MBK3_IOC_MAGIC, 16, unsigned long)
#define	BK3_IOC_GET_ACKN       _IOWR(MBK3_IOC_MAGIC, 17, unsigned long)
#define	BK3_IOC_TEST_DEVICE    _IOWR(MBK3_IOC_MAGIC, 18, unsigned long)
#define	BK3_IOC_0_IO_REG       _IOWR(MBK3_IOC_MAGIC, 19, unsigned long)
#define	BK3_IOC_SET_SWITCH     _IOWR(MBK3_IOC_MAGIC, 20, unsigned long)
#define	BK3_IOC_READ_TYPE      _IOWR(MBK3_IOC_MAGIC, 21, unsigned long)
#define	BK3_IOC_LOOP_READ_REG  _IOWR(MBK3_IOC_MAGIC, 22, unsigned long)

#define	BK3_IOC_SET_SWITCH_0   _IOWR(MBK3_IOC_MAGIC, 23, unsigned long)
#define	BK3_IOC_SET_SWITCH_1   _IOWR(MBK3_IOC_MAGIC, 24, unsigned long)

#define	BK3_IOC_SET_TRASS      _IOWR(MBK3_IOC_MAGIC, 25, unsigned long)
#define	BK3_IOC_GET_TRASS      _IOWR(MBK3_IOC_MAGIC, 26, unsigned long)
#define	BK3_IOC_SET_TRASST     _IOWR(MBK3_IOC_MAGIC, 27, unsigned long)

#define	BK3_IOC_reserv         _IOWR(MBK3_IOC_MAGIC, 28, unsigned long)
#define	BK3_IOC_reserv2        _IOWR(MBK3_IOC_MAGIC, 29, unsigned long)
#define	BK3_IOC_reserv3        _IOWR(MBK3_IOC_MAGIC, 30, unsigned long)
#define	BK3_IOC_reserv4        _IOWR(MBK3_IOC_MAGIC, 31, unsigned long)

#define	BK3_IOC_SND_MSG        _IOWR(MBK3_IOC_MAGIC, 32, unsigned long)
#define	BK3_IOC_RCV_MSG        _IOWR(MBK3_IOC_MAGIC, 33, unsigned long)


#define	BK3_IOC_GET_BUF        _IOWR(MBK3_IOC_MAGIC, 34, unsigned long)
#define	BK3_IOC_WR_BUF         _IOWR(MBK3_IOC_MAGIC, 35, unsigned long)
#define	BK3_IOC_RD_BUF         _IOWR(MBK3_IOC_MAGIC, 36, unsigned long)
#define	BK3_IOC_PUT_BUF        _IOWR(MBK3_IOC_MAGIC, 37, unsigned long)
#define	BK3_IOC_ON_SYNC        _IOWR(MBK3_IOC_MAGIC, 38, unsigned long)
#define	BK3_IOC_OFF_SYNC       _IOWR(MBK3_IOC_MAGIC, 39, unsigned long)
#define BK3_IOC_CLEAR_STAT     _IOWR(MBK3_IOC_MAGIC, 40, unsigned long)
#define BK3_IOC_GET_STATUS     _IOWR(MBK3_IOC_MAGIC, 41, unsigned long)
#define BK3_IOC_CLR_STATUS     _IOWR(MBK3_IOC_MAGIC, 42, unsigned long)
#define BK3_IOC_TEST_TW        _IOWR(MBK3_IOC_MAGIC, 43, unsigned long)
#define BK3_IOC_BRC_TW         _IOWR(MBK3_IOC_MAGIC, 44, unsigned long)
#define BK3_IOC_MAKE_DAMP      _IOWR(MBK3_IOC_MAGIC, 45, unsigned long)


/** Размеры Буферов **/
#define	SZ_BUF_BK3           (8 * PAGE_SIZE)
#define	NUM_BUF_BK3           8
#define	SZ_OF_ALL_BUFFERS_BK3 (2 * NUM_BUF_BK3 * SZ_BUF_BK3)


/**	Statistics for BK3 **/
typedef struct {
	hrtime_t	r_all_time;    /*Полное время чтения в мкс*/
	hrtime_t	w_all_time;    /*Полное время записи в мкс*/
	hrtime_t	r_start;       /*Начало последнего чтения в мкс*/
	hrtime_t	w_start;		   /*Начало последней записи в мкс*/
	size_t		rsize_all; /*Размер считанной информации в байтах*/
	size_t		wsize_all; /*Размер записанной информации в байтах*/
	size_t		rsize;         /*Размер последнего считанного буфера в байтах*/
	size_t		wsize;         /*Размер последнего записанного буфера в байтах*/
	u_int		n_r;           /*Число считанных буферов*/
	u_int		n_w;           /*Число записанных буферов*/

	u_int	cmd_sent;     /*Число посланных сообщений*/
	u_int	cmd_recieved; /*Число принятых сообщений*/
	u_int	cmd_rpt;      /*Число повторных отправок команд*/
	u_int	cmd_free;     /*Число прерываний по свободе буфера команд*/

	u_int	my_resets;   /*Число собственных обнулений*/
	u_int	peer_resets; /*Число обнулений по запросу соседа*/

	u_int	sbusintrf; /*Ошибки по контролю четности типа приемника*/
	u_int   may_be_hidden; /* возможность затоптать предыдущюю ошибку */
	u_int	sbusprty;  /*Ошибки по контролю четности Sbus*/
	u_int	rcvflt;    /*Ошибки приёмника*/
	u_int	optprty;   /*ошибки оптики*/
	u_int	lsrfailr;  /*Ошибки  по контролю оптики*/

	u_int	r_fail_addr_count; /*Число ошибок приёма*/
	u_int	t_fail_addr_count; /*Число ошибок передачи*/
	u_int 	n_free_r_buf;      /*Число свободных для чтения буферов*/
	u_int 	n_free_w_buf;      /*Число свободных для записи буферов*/
	unsigned long intrs;
	unsigned long true_intrs;
	unsigned long rask;          /* Число прерываний RASK (депеш) */ 
	unsigned long intr_both_rw;  /* Число прерываний по чт и зп, которые пришли одновременно */
	unsigned long intr_single_r; /* Число прерываний только по чтению */
	unsigned long intr_single_w; /* Число прерываний только по записи */
} bk3_stat_t;

/**	Info for SND_MSG **/
typedef struct {
	u_long		t_wait;		/* тайм-аут в микросек. */
	u_int		info;		/* что передать (3 байта) */
} bk3_msg_snd_t;

/**	Info for RCV_MSG **/
typedef struct {
	u_long		t_wait;		/* тайм-аут в микросек. */
	u_int		info;		/* что принял (3 байта) */
} bk3_msg_rcv_t;


#endif  /*_BK3_DEF_H_*/
