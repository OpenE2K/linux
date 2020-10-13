#ifndef	__RDMA_H__
#define	__RDMA_H__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/fb.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/apic.h>
#include <asm/uaccess.h>
#include <linux/pci.h>
#include <linux/mcst/ddi.h>
#include <asm-l/bootinfo.h>
#include <linux/sched/rt.h>
#include <linux/mcst/rdma_user_intf.h>
#ifdef CONFIG_E90S
#include <asm/e90s.h>
#include <asm/sic_regs.h>
#include <asm-l/iolinkmask.h>
#ifndef LINUX_2_33_DBG
#include <asm/mpspec.h>
#endif
#endif
#ifdef CONFIG_E2K
#include <asm/e2k.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/e2k_sic.h>
#include <asm/uaccess.h>
#endif
#ifndef LINUX_2_33_DBG
#include <asm/iolinkmask.h>
#include <linux/topology.h>
#endif
#include <linux/kthread.h>

/*
 * For e2s proto 
 */
#if 0
#define PROTO	
#endif 

/*
 * Init for SIC_machine
 */

#ifdef CONFIG_E2K
#define RDMA_NODE_IOLINKS \
		(IS_MACHINE_E2S ? ( NODE_NUMIOLINKS * 2) : NODE_NUMIOLINKS)
#else
#define	RDMA_NODE_IOLINKS	NODE_NUMIOLINKS
#endif

#define RDMA_MAX_NUMIOLINKS	MAX_NUMIOLINKS

#define NUM_NODE_RDMA(num_link_rdma)	(int)(num_link_rdma/RDMA_NODE_IOLINKS)
#define NUM_LINK_IN_NODE_RDMA(num_link_rdma)\
	(num_link_rdma - ((int)(num_link_rdma/RDMA_NODE_IOLINKS))*RDMA_NODE_IOLINKS)

/*
 *  Redefined macros
 */

#define E2S_OFFSET	0x200
#ifdef CONFIG_E2K
typedef	unsigned int filds_t;
typedef	struct sic_hw1_fields {
	filds_t	mode	: 1;	/* [0]    */
	filds_t	unused	: 31;	/* [31:1] */
} sic_hw1_fields_t;
typedef	union sic_hw1_struct {		/* Structure of word  */
	sic_hw1_fields_t	fields;	/* as fields          */
	filds_t			word;	/* as entire register */
} sic_hw1_struct_t;
#define	HW1_reg		word
#define	HW1_mode	fields.mode
#define SIC_HW1_ADDR	0xc84
#endif
typedef struct { DECLARE_BITMAP(bits, RDMA_MAX_NUMIOLINKS); } _RDMA_iolinkmask_t;
#define _RDMA_IOLINK_MASK_NONE							\
((_RDMA_iolinkmask_t) { {							\
	[0 ... BITS_TO_LONGS(RDMA_MAX_NUMIOLINKS)-1] =  0UL			\
} })

#define	_RDMA_node_iolink_to_domain(node, link)	\
		((node) * (RDMA_NODE_IOLINKS) + (link))
#define _RDMA_iolink_set(domain, dst) _RDMA__iolink_set((domain), &(dst))
#define _RDMA_rdma_set(domain, dst) _RDMA_iolink_set((domain), (dst))
#define	_RDMA_node_rdma_to_domain(node, link) _RDMA_node_iolink_to_domain((node), (link))
#define _RDMA_node_rdma_set(node, link, dst)	\
		_RDMA_rdma_set(_RDMA_node_rdma_to_domain((node), (link)), (dst))
static inline void _RDMA__iolink_set(int domain, 
				     volatile _RDMA_iolinkmask_t *dstp)
{
	set_bit(domain, dstp->bits);
}

#define _RDMA_first_iolink(src) _RDMA__first_iolink(&(src))
static inline int _RDMA__first_iolink(const _RDMA_iolinkmask_t *srcp)
{
	return min_t(int, RDMA_MAX_NUMIOLINKS, find_first_bit(srcp->bits,
		     RDMA_MAX_NUMIOLINKS));
}
#define _RDMA_next_iolink(n, src) _RDMA__next_iolink((n), &(src))
static inline int _RDMA__next_iolink(int n, const _RDMA_iolinkmask_t *srcp)
{
	return min_t(int, RDMA_MAX_NUMIOLINKS, find_next_bit(srcp->bits,
		     RDMA_MAX_NUMIOLINKS, n+1));
}
#define _RDMA_for_each_iolink_mask(domain, mask)			\
		for ((domain) = _RDMA_first_iolink(mask);		\
			(domain) < RDMA_MAX_NUMIOLINKS;			\
			(domain) = _RDMA_next_iolink((domain), (mask)))
#define _RDMA_for_each_rdma(domain)		_RDMA_for_each_iolink_mask((domain), \
						_RDMA_iolink_rdma_map)
#define _RDMA_for_each_online_rdma(domain)	_RDMA_for_each_iolink_mask((domain), \
						_RDMA_iolink_online_rdma_map)
#define _RDMA_num_possible_rdmas()		_RDMA_iolink_rdma_num
#define _RDMA_num_online_rdmas()		_RDMA_iolink_online_rdma_num


#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
#define RDMA_2_6_14	1
#endif

#ifdef RDMA_2_6_14
#define raw_spin_lock_init		spin_lock_init
#define raw_spin_unlock			spin_unlock
#define raw_spin_lock			spin_lock
#define raw_spin_is_locked		spin_is_locked
#define raw_spin_lock_irqsave		spin_lock_irqsave
#define raw_spin_unlock_irqrestore	spin_unlock_irqrestore
#define pr_err				printk
#endif

/*
 * Vendor, id, indexes of pci_dev.resource[]
 */
#define board_name		"MCST,rdma" /* should be same as FCODE.name */
#define PCI_VENDOR_ID_MCST_RDMA	0x8086
#define PCI_DEVICE_ID_MCST_RDMA	0x7191
#define PCI_MMIO_BAR		0
#define PCI_MEM_BAR		1
#define CONFIG_CMD_RDMA(bus, devfn, where)   (0x80000000 | (bus << 16) | \
						(devfn << 8) | (where & ~3))

/*
 * Link in dev
 */
#define	RDMA_NODE_DEV 		1
#define DEV_inst(m)		(int)(m/(2 * count_rdma_vc))
#define DEV_chan(m)		(int)(m%(2 * count_rdma_vc))

/*
 * Prefix
 */
#define RDMA_PFX		"rdma: "
#define INFO_MSG(x...) 		printk(RDMA_PFX x)
#define WARN_MSG(x...) 		printk(RDMA_PFX x)
#define ERROR_MSG(x...) 	printk(RDMA_PFX x)

/*
 * Debug
 */
#define RDMA_PRN_ADDR_FUN	0
#define PRN_ADDR_FUN(x...)	if (RDMA_PRN_ADDR_FUN) printk(x)
#define RDMA_DEBUG		1
#define DEBUG_MSG(x...)		if (RDMA_DEBUG)	printk(RDMA_PFX x)
#define RDMA_TRACE		0
#define TRACE_MSG(x...) 	if (RDMA_TRACE) printk(RDMA_PFX x)

/*
 * Events's
 */
#define GET_EVENT_RDMA_PRINT	1
#define EVENT			1
#define fix_event		if (EVENT) fix_event_proc
#define EVENT_IOCTL		1
#define event_ioctl		if (EVENT_IOCTL) fix_event
#define EVENT_INTR		1
#define event_intr		if (EVENT_INTR) fix_event
#define EVENT_READ		1
#define event_read		if (EVENT_READ) fix_event
#define EVENT_WRITE		1
#define event_write		if (EVENT_WRITE) fix_event
#define EVENT_SNDMSG		1
#define event_sndmsg		if (EVENT_SNDMSG) fix_event
#define EVENT_DDI_CV		1
#define event_ddi_cv 		if (EVENT_DDI_CV) fix_event
#define EVENT_LOOP		1
#define event_loop		if (EVENT_LOOP) fix_event

/*
 * Type messages
 */
#define MSG_OPER		0xc0000000	/* Messages OPER */
#define MSG_TRWD		0x80000000	/* Messages TRWD */
#define MSG_READY		0x00000000	/* Messages READY RECEIVER */
#define MSG_READY_DMA		0x40000000	/* Messages READY RECEIVER */
#define ALLIGN_RDMA		256

/*
 * Mask's messages
 */
#define MSG_USER		0x0fffffff	/* Messages for user */
#define MSG_ABONENT		0x70000000
#define SHIFT_ABONENT		28

/*
 * Type thread
 */
#define	RESET_THREAD_DMA	1
#define READER			0
#define WRITER			1

/*
 * Const
 */
#define MAX_CHANNEL		8
#define MAX_CHANNEL_RDMA	12
#define MAX_max(a, b)		((a) > (b) ? (a) : (b))
#define MIN_min(a, b) 	 	((a) > (b) ? (b) : (a))
#define MAX_TIMER		15000000
#define IO_TIMEOUT		10000000 /* n000000: n sec i/o timeout */
#define SHIFT_TO		10
#define REPEAT_TRWD_MAX		5
#define REPEAT_WAIT_RD_MAX	50
#define TIME_OUT_WAIT_RD	30 /* test rdma ok. Old 30. Change muw. */
#define TIME_OUT_WAIT_WR	40 /* test rdma ok */
#ifdef PROTO
#define TIME_OUT_WAIT_WR_SEC	100  /* time sec */
#else
#define TIME_OUT_WAIT_WR_SEC	4  /* time sec */
#endif
#define TIME_OUT_WAIT_FS	100
#define TIMER_FOR_WRITE_MAX	1000000
#define TIMER_FOR_READ_MAX	1000000
#define TIMER_FOR_WRITE_MIN	0
#define TIMER_FOR_READ_MIN	100000
#define TIMER_MAX		1000000
#define TIMER_MIN 		100000
#define TIMER_READ_MAX 		2000000
#define TIMER_READ_MIN		200000
#define TIMER_WRITE_MAX 	1000000
#define TIMER_WRITE_MIN		100000
#define REPEAT_READY_MAX	10
#define MAX_COUNT_RDR_RBC	300
#define WAIT_SND_MSG		100
#define	SIZE_TBL64_RDMA		4096
#define	NR_ENTRY_TBL64_RDMA	(SIZE_TBL64_RDMA >> 4)
#define	RDMA_TXR_FREE		0x00000001
#define	RDMA_RXR_FREE		0x00000002
#define	RDMA_RX_TRWD		0x00000004
#define	RDMA_TX_TRWD		0x00000008
#define	RDMA_TRY_RDMA		0x00000010
#define	RDMA_TRY_TDMA		0x00000020
#define	RDMA_RX_READY		0x00000040
#define	RDMA_TX_READY		0x00000080
#define RDMA_XX_STRUCTS_NR	4
#define WAY_32			0
#define WAY_64			1
#define WAY_TBL_32		2
#define WAY_TBL_64		3
#define RDMA_RBC_COUNT		10
#define RDMA_WRITE_WAITING_TRWD_TIMEOUT 36000000L
#define RDMA_READ_START		0
#define RDMA_READ_WAITING_RDC	1
#define RDMA_WRITE_START	2
#define RDMA_WRITE_WAITING_TRWD	3
#define RDMA_TRWD		0x80000000
#define RDMA_READY		0x40000000
#define RDMA_SIZE_32		0x400000
#define RDMA_SIZE_E_TBL		0x4000
#define RDMA_NR_E_TBL		0x100
#define RDMA_SIZE_TBL		(RDMA_NR_E_TBL * RDMA_SIZE_E_TBL)
#ifdef RDMA_E3S_LMS
#define RDMA_WAIT_TEST_STATE	10L
#define RDMA_PRINT_STAT_HEADER	0xff
#define RDMA_PRINT_STAT		50L
#endif
#ifdef RDMA_E3S_MAKET
#define RDMA_WAIT_TEST_STATE	20L
#define RDMA_PRINT_STAT_HEADER	0xff
#define RDMA_PRINT_STAT		40L
#endif

typedef struct rdma_parms_e3m {
	unsigned long	mmio_base;	/* phys address    */
	uint8_t		*mmio_vbase;	/* virtual address */
	unsigned int	mmio_len;
} rdma_parms_e3m_t;

typedef struct dev_rdma_sem {
	char *dev_name;
	unsigned long		waited2_clkr;
	unsigned long		waited1_clkr;
	unsigned long		broadcast_clkr;
	unsigned long		timeout;
	unsigned int		irq_count_rdma;
	unsigned int		num_obmen;
	unsigned long		time_broadcast;
	raw_spinlock_t		lock;
	raw_wait_queue_head_t	cond_var;
} dev_rdma_sem_t;

typedef struct rdma_private_data {
	int	open_mode;
} rdma_private_data_t;

typedef struct rdma_buf {
	struct list_head list;
	u_int32_t	st;		/* buffer state		*/
	u_int32_t   	num;		/* buffer id		*/
	size_t   	size;		/* buffer size		*/
	size_t		dma_size;	/* buffer dma size	*/
	size_t		real_size;	/* reciv buffer size	*/
	size_t		rfsm_size;	/* rfsm buffer size	*/
	caddr_t		buf_addr;	/* user access addr	*/
	dma_addr_t	dma_addr;	/* hardware DMA access	*/
} rdma_buf_t;

#define RDMA_BUF_NUM 4
typedef struct rdma_pool_buf {
	rdma_buf_t		buf[RDMA_BUF_NUM];	/* Buffer list			*/
	struct list_head	free_list;     		/* list of free buffers		*/
	struct list_head 	ready_list;        	/* list of ready for user buffers*/
	struct list_head 	busy_list;         	/* list of buffers used by user	*/	
	int			n_free;
	int			m_free;
	caddr_t			vdma;              	/* user access addr		*/
	dma_addr_t 		fdma;              	/* hardware DMA access		*/
	size_t			size;
	size_t			buf_size;
	size_t			dma_size;
	int 			node_for_memory;
	int 			tm_mode;           	/* table mode			*/
	size_t 			size_tm;           	/* size table			*/
	int			alloc;
	rdma_buf_t		*work_buf;         	/* In RCV or TRSM buff point	*/
	int 			num_free_buf;
} rdma_pool_buf_t;

typedef struct rw_state {
	raw_spinlock_t	lock_wr;
	raw_spinlock_t	lock_rd;
	raw_spinlock_t	mu_spin;
	//kmutex_t	mc;
	struct dev_rdma_sem	dev_rdma_sem;
	kmutex_t	mu;
	// uchar_t	stat;
	uint_t		stat;
	uint_t		int_ac;
	uchar_t		trwd_was;
	uint_t		evs;
	uint_t		msg_cs;
	uint_t		tcs;
	uint_t		dsf;
	uint_t		msf;
	uint_t		msg;
	uint_t		err_no;
	uint_t		acclen;
	uint_t		dma_tcs;
	uint_t		rbc;
	size_t		real_size;
	uint_t		size_trans;
	uint_t		size_trb;
	uint_t		errno;
	dma_addr_t	dma_busa;
	dma_addr_t	*prim_buf_addr;
	dma_addr_t	*vdma_tm;
	dma_addr_t	fdma_tm;
	uint_t		tm;
	dma_addr_t	dma;
	dma_addr_t	fdma;
	uint_t		n_ready;
	int		clock_begin_read;
	int		clock_end_read_old;
	int		clock_begin_read_old;
	int		trwd_send_count;
	int		ready_send_count;
	int		trwd_rec_count;
	int		ready_rec_count;
	uint_t		clock_receive_ready;
	unsigned long	clock_receive_trwd;
	uint_t		clock_send_ready;
	uint_t		clock_send_trwd;
	uint_t		clock_rdc;
	uint_t		clock_tdc;
	uint_t		rdma_intr;
	long		tv_sec;
	long		tv_usec;
	unsigned long 	clkr;
	int		int_cnt;
	int		timer_for_read;
	int		timer_for_write;
	int		timer;
	int		timer_read;
	int		timer_write;
	int		node_src;
	unsigned int	open_mode;
	int		state_open_close;
	int		first_open;
	unsigned int	link;
	int 		rdma_loop_buff_free;
} rw_state_t;

typedef rw_state_t * rw_state_p;

/* 
 * Structure descriptor link rdma
 */
typedef struct rdma_state_link {
	unsigned int		link;
	struct stat_rdma 	stat_rdma;
	kmutex_t		mu;
	unsigned int		opened;
	rw_state_t 		rw_states_d[2];
	rw_state_t 		rw_states_m[2];
	rw_state_t 		ralive;
	rw_state_t 		talive;
	rw_state_t 		*rw_states_wr;
	rw_state_t 		*rw_states_rd;
	rdma_pool_buf_t     	read_pool;    	/* buffers pool for receive					*/
	rdma_pool_buf_t     	write_pool;   	/* buffers pool for transmit					*/
	caddr_t             	rbuff;        	/* user access base address (virt_memory from __get_free_pages)	*/
	caddr_t             	wbuff;        	/* user access base address (virt_memory from __get_free_pages)	*/
#ifdef RESET_THREAD_DMA
	struct task_struct      *rst_thr;
	raw_spinlock_t		rst_thr_lock;
	raw_spinlock_t		mutex_send_msg;
	int 			start_rst_thr;
#endif	
	rdma_parms_e3m_t	parms_e3m;
	int			mode_loop;
} rdma_state_link_t;

/* 
 * Main struct 
 */
struct rdma_state {
	struct pci_dev *dev_rdma;	
	unsigned int	major;
	//kmutex_t	mu;
	//unsigned long mmio_base;	/* phys address    */
	//uint8_t*	mmio_vbase;	/* virtual address */
	//unsigned int	mmio_len;
	unsigned int	inited;
	size_t		size_rdma_state;
	rdma_state_link_t	rdma_link[RDMA_MAX_NUMIOLINKS];
	
};

struct rdma_reg_state {
	unsigned int	cs;
	unsigned int	es;
	unsigned int	tcs;
	unsigned int	rcs;
	unsigned int	tdc;
	unsigned int	rdc;
	unsigned int	tbc_count;
	unsigned int	tbc;
	unsigned int	rbc;
	unsigned int	msg_cs;
	unsigned int	node;
	unsigned int	irq_count;
	unsigned int	irq_all_count;
	unsigned int	irq_all_100_count;
	unsigned int	trwd_was;
	unsigned int	rx_trwd;
	unsigned int	rx_ready;
	unsigned int	tx_trwd;
	unsigned int	tx_ready;
	unsigned int	try_rdma;
	unsigned int	try_tdma;
	unsigned int	int_ac;
	unsigned int	msg[32];
	unsigned int	count_msg;
	unsigned int	big_count_msg;
	long		tdc_jiffies;
	long		rdc_jiffies;
	long		rxr_free_jiffies;
	int		rxr_free0_count;
	long		txr_free_jiffies;
	int		txr_free0_count;
	long		rx_trwd_jiffies;
	int		rx_trwd_count;
	long		rx_ready_jiffies;
	int		rx_ready_count;
	long		tx_trwd_jiffies;
	long		tx_ready_jiffies;
	int		tx_ready_count;
	long		try_rdma_jiffies;
	int		try_rdma_count;
	long		try_tdma_jiffies;
	int		try_tdma_count;
	unsigned int	rdma_state;
};

typedef	unsigned int	half_addr_t;	/* single word (32 bits) */
typedef	struct rdma_addr_fields {
#if defined(CONFIG_E90S)
	half_addr_t	haddr;		/* [31 :  0] */
	half_addr_t	laddr;		/* [63 : 32] */
#else /* E3S */
	half_addr_t	laddr;		/* [31 :  0] */
	half_addr_t	haddr;		/* [63 : 32] */
#endif
} rdma_addr_fields_t;

typedef	union rdma_addr_struct {	/* Structure of word */
	rdma_addr_fields_t	fields;	/* as fields */
	unsigned long		addr;	/* as entier register */
} rdma_addr_struct_t;
typedef	struct rdma_xx_structs {	/* struct for rdma */
	void		*pb;		/* pointer on buffer */
	unsigned int	lpa;		/* l addess */
	unsigned int	hpa;		/* h address */
	unsigned int	sz;		/* size buffers */
	long		order;		/* size buffers */
	unsigned int	nr;		/* number buffer's */
	unsigned int	way;		/* number buffers  */
} rdma_xx_structs_t;

typedef	struct rdma_xx_struct {
	rdma_xx_structs_t	*xxs;	/* pointer on structs for rdma */
	unsigned int		nr_xxs;	/* count structs for rdma */
} rdma_xx_struct_t;

typedef	struct rdma_tbl_32_struct {	/* struct for rdma tbl 32 */
	unsigned int	laddr;		/* l addess */
	unsigned int	sz;		/* size buffers */
} rdma_tbl_32_struct_t;

typedef	struct rdma_tbl_64_struct {	/* struct for rdma tbl 64 */
	unsigned long	addr;		/* address */
	unsigned long	sz;		/* size buffers */
} rdma_tbl_64_struct_t;


extern struct rdma_state *rdma_state;
extern struct rdma_reg_state rdma_reg_state[RDMA_MAX_NUMIOLINKS];
extern unsigned char bus_number_rdma, devfn_rdma;
extern unsigned long time_ID_REQ;
extern unsigned long time_ID_ANS;
extern unsigned int msg_cs_dmrcl;
extern nodemask_t node_online_neighbour_map;
extern rdma_event_t rdma_event;
extern int node_neighbour_num;
extern int rdma_event_init;
extern int irq_mc;

extern unsigned int RDR_rdma(unsigned int reg, unsigned int node);
extern void WRR_rdma(unsigned int reg, unsigned int node, unsigned int val);
extern int wait_for_irq_rdma_sem(void* dev_rdma_sem, signed long timeout,
				 unsigned int instance);
extern void __wake_up_common(wait_queue_head_t *q, unsigned int mode,
			     int nr_exclusive, int sync, void *key);
extern void (*rdma_interrupt_p)(struct pt_regs *regs);
extern void fix_event_proc(unsigned int channel, unsigned int event, 
			   unsigned int val1, unsigned int val2);
extern int send_msg(rdma_state_link_t *xsp, unsigned int msg,
		    unsigned int instance, unsigned int cmd,
		    dev_rdma_sem_t *dev);

#endif /* __RDMA_H__ */
