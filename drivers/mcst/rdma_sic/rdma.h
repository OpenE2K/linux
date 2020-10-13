#ifndef	__RDMA_H__
#define	__RDMA_H__

/* #define RDMA_E3S_LMS */
/* #define RDMA_E3S_MAKET */

#define PCI_VENDOR_ID_MCST_RDMA	0x8086
#define PCI_DEVICE_ID_MCST_RDMA	0x7191

/* Indexes of pci_dev.resource[] */
#define PCI_MMIO_BAR		0
#define PCI_MEM_BAR		1

#define RDMA_PFX		"rdma: "
#define RDMA_PFX_READ		"rdma: read_buf: "
#define RDMA_PFX_WRITE		"rdma: write_buf: "
#define RDMA_PFX_SEND_MSG	"rdma: send_msg: "
#define RDMA_PFX_IOCTL		"rdma: rdma_ioctl: "

#define	RDMA_NODE_DEV 	7

/*
#ifdef CONFIG_E2K
#ifdef LINUX_2_33_DBG
extern nodemask_t	node_online_rdma_map;
#define MAX_NODES		MAX_NUMNODES
#define MAX_CPUS_PER_NODE	4
#define MAX_NUMIOLINKS		MAX_NODES
#define NODE_NUMIOLINKS		1
#undef  num_possible_rdmas
#define num_possible_rdmas()	node_rdma_num
#undef  num_online_rdmas
#define num_online_rdmas()	node_online_rdma_num
#undef  for_each_online_rdma
#define for_each_online_rdma(node)	\
				for_each_node_mask((node), node_online_rdma_map)
#endif
#endif

#ifdef CONFIG_E90S
#ifdef LINUX_2_33_DBG
#define MAX_NODES		MAX_NUMNODES
#define MAX_NUMIOLINKS		MAX_NODES
#define MAX_CPUS_PER_NODE	4
#define NODE_NUMIOLINKS		1
#endif
#endif
*/

#define INFO_MSG(x...) 		printk(  RDMA_PFX x )
#define WARN_MSG(x...) 		printk(  RDMA_PFX x )
#define ERROR_MSG(x...) 	printk(  RDMA_PFX x )

/* #define RDMA_REG_TRACE 	1 */ 
/* #define TRACE_LATENCY	1 */ 
/* #define TRACE_LATENCY_MSG 	1 */ 
/* #define TRACE_LATENCY_SM 	1 */ 

#define GET_EVENT_RDMA_PRINT	0	/*print event*/

#define RDMA_PRN_ADDR_FUN	0
#define PRN_ADDR_FUN(x...)	if (RDMA_PRN_ADDR_FUN) printk( x )

#define RDMA_DEBUG		0
#define DEBUG_MSG(x...)		if (RDMA_DEBUG)	printk(RDMA_PFX x )

#define RDMA_TRACE		0
#define TRACE_MSG(x...) 	if (RDMA_TRACE) printk(RDMA_PFX x )

#define RDMA_DEBUG_READ		0
#define dbg_read_buf(x...)	if (RDMA_DEBUG_READ) printk(RDMA_PFX_READ x )

#define RDMA_DEBUG_SEND_MSG	0
#define dbg_send_msg(x...)	if (RDMA_DEBUG_SEND_MSG) \
 					printk(RDMA_PFX_SEND_MSG x )

#define RDMA_DEBUG_WRITE_BUF	0
#define dbg_write_buf(x...)	if (RDMA_DEBUG_WRITE_BUF) \
					printk(RDMA_PFX_WRITE x )

#define RDMA_DEBUG_IOCTL	0
#define dbg_ioctl(x...)		if (RDMA_DEBUG_IOCTL) printk(RDMA_PFX_IOCTL x )

#define EVENT			1
#define fix_event		if(EVENT) fix_event_proc

#define EVENT_IOCTL		1
#define event_ioctl		if(EVENT_IOCTL) fix_event

#define EVENT_INTR		1
#define event_intr		if(EVENT_INTR) fix_event

#define EVENT_READ		1
#define event_read		if(EVENT_READ) fix_event

#define EVENT_WRITE		1
#define event_write		if(EVENT_WRITE) fix_event

#define EVENT_SNDMSG		1
#define event_sndmsg		if(EVENT_SNDMSG) fix_event

#define EVENT_DDI_CV		1
#define event_ddi_cv 		if (EVENT_DDI_CV) fix_event

#define DEBUG 			0
#define	dbgprn 			if (DEBUG) printk 

#define CONFIG_CMD_RDMA(bus,devfn, where)   (0x80000000 | (bus << 16) | \
 						(devfn << 8) | (where & ~3))

#define MAX_TIMER 		15000000	
#define IO_TIMEOUT 		10000000 /* n000000: n sec i/o timeout */
#define SHIFT_TO		10
#define REPEAT_TRWD_MAX		5
#define REPEAT_WAIT_RD_MAX	50
#define TIME_OUT_WAIT_RD	30 /* test rdma ok. Old 30. Change muw. */
#define TIME_OUT_WAIT_WR	40 /* test rdma ok */
#define TIME_OUT_WAIT_FS	100

#define MSG_OPER  		0x80000000	/* Messages OPER */
#define MSG_TRWD		0x80000000	/* Messages TRWD */
#define MSG_READY		0x00000000	/* Messages READY RECEIVER */
#define ALLIGN_RDMA     	256

#define MAX_max(a, b) 	 	(a)>(b)?(a):(b)
#define MIN_min(a, b) 	 	(a)>(b)?(b):(a)

#define TIMER_FOR_WRITE_MAX	1000000	
#define TIMER_FOR_READ_MAX	1000000	
#define TIMER_FOR_WRITE_MIN	0	
#define TIMER_FOR_READ_MIN	100000	
#define TIMER_MAX		1000000	
#define TIMER_MIN 		100000	
#define TIMER_READ_MAX 		2000000	
#define TIMER_READ_MIN		200000	
#define TIMER_WRITE_MAX 	1000000	
#define TIMER_WRITE_MIN 	100000	
#define REPEAT_READY_MAX	10
#define MAX_COUNT_RDR_RBC 	300
#define WAIT_SND_MSG		100


#define board_name		"MCST,rdma" /* should be same as FCODE.name */

/* #ifdef CONFIG_E90S */
/* minor -> instance */
/* #define DEV_inst(m)	((m < 7)?0:(m < 14)?1:(m < 21)?2:3) */
/* minor -> channel */
/* #define DEV_chan(m)	((m < 7)?m:(m < 14)?m - 7:(m < 21)?m -14:m - 21) */
/* #endif */

/*#ifdef CONFIG_E2K
#define DEV_inst(m)	(HAS_MACHINE_E2K_SIC)?((m < 7)?0:(m < 14)?1:\
				(m < 21)?2:3):((m > 6)?1:0)	
#define DEV_chan(m)	(HAS_MACHINE_E2K_SIC)?((m < 7)?m:(m < 14)?m - 7:\
				(m < 21)?m -14:m - 21):((m > 6)?m - 7:m) 
#endif
*/

#define DEV_inst(m)	(int)(m/RDMA_NODE_DEV)
#define DEV_chan(m)	(int)(m%RDMA_NODE_DEV)

#define MAX_CHANNEL		8
#define MAX_CHANNEL_RDMA	12

#define READER	0
#define WRITER	1

#define MSG_USER		0x0fffffff	/* Messages for user */
#define MSG_ABONENT		0x70000000
#define SHIFT_ABONENT		28

extern void WRR_rdma(unsigned int reg, unsigned int node, unsigned int val);
extern unsigned int RDR_rdma(unsigned int reg, unsigned int node);


extern	raw_spinlock_t	mu_fix_event;
extern	raw_spinlock_t	cam_lock;
extern	raw_spinlock_t	rdma_printk_lock;

typedef struct dev_rdma_sem {
	char *dev_name;
	unsigned long	waited2_clkr;
	unsigned long	waited1_clkr;
	unsigned long	broadcast_clkr;
	unsigned long	timeout;
	unsigned int	irq_count_rdma;	
	unsigned int	num_obmen; 
	unsigned long	time_broadcast; 
	raw_spinlock_t	lock;
	kcondvar_t	cond_var;
} dev_rdma_sem_t;

typedef struct dma_chan {
   	uchar_t channel; /* channel index in slot 	 */
        uchar_t allocs;	 /* chan res alloc statbit stack */
	dma_addr_t	dma_busa;
	dma_addr_t	fdma;
	dma_addr_t	dma;
	dma_addr_t	*prim_buf_addr;
	size_t		real_size;
	uint_t		tm;
	uint_t		tm_inited;
	size_t		size_tm;
	uint_t		full;
	dma_addr_t	*vdma_tm;
	dma_addr_t	fdma_tm;
	int node_for_memory;
} dma_chan_t;

typedef struct rw_state {
	raw_spinlock_t	lock_wr;
	raw_spinlock_t	lock_rd;
	raw_spinlock_t	mu_spin;
	kmutex_t	mc;
	struct dev_rdma_sem	dev_rdma_sem;
	kmutex_t	mu;
	struct sk_buff	*skb;
	/* uchar_t	stat; */
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
	dma_addr_t	dma; /* for E3M uint_t*/
	dma_addr_t	fdma;
	uint_t		n_ready;
	dma_chan_t	*chd;
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
	///!!!
	int 		state_GP0;
	int 		state_GP1;
	int 		state_GP2;
	int 		send_state_GP0;
	int 		send_state_GP1;
	int 		send_state_GP2;
	int		ret_GP0;
	int		ret_GP1;
	int		ret_GP2;
} rw_state_t;

typedef rw_state_t * rw_state_p;

typedef struct rdma_state_inst {
	unsigned int	instance;
	struct stat_rdma stat_rdma;
	kmutex_t	mu;
	unsigned int	opened;
	dma_chan_t	dma_chans[MAX_CHANNEL_RDMA]; /* DMA channels vector */
	rw_state_t 	rw_states_d[2];
	rw_state_t 	rw_states_m[2];
	rw_state_t 	ralive;
	rw_state_t 	talive;
	rw_state_t 	*rw_states_wr;
	rw_state_t 	*rw_states_rd;
} rdma_state_inst_t;

struct rdma_state {
	unsigned int	major;
	kmutex_t	mu;
	unsigned long 	mmio_base;		/* phys address    */
	uint8_t*	mmio_vbase;		/* virtual address */
	unsigned int	mmio_len;
	unsigned int	inited;
	size_t		size_rdma_state;
	rdma_state_inst_t	rdma_sti[MAX_NUMIOLINKS];
	
};

extern struct rdma_state *rdma_state;

extern int wait_for_irq_rdma_sem(void* dev_rdma_sem, signed long timeout,
				  unsigned int instance);
extern void __wake_up_common(wait_queue_head_t *q, unsigned int mode,
			     /* muvlad */int nr_exclusive, int sync, void *key);
extern void (*rdma_interrupt_p)(struct pt_regs *regs);
extern void fix_event_proc(unsigned int channel, unsigned int event,
			    unsigned int val1, unsigned int val2);
extern int send_msg(rdma_state_inst_t *xsp, unsigned int msg, 
		    unsigned int instance, unsigned int cmd, 
      		    dev_rdma_sem_t *dev);
extern unsigned int	msg_cs_dmrcl;

extern rdma_event_t	rdma_event;

extern int 		rdma_event_init;
extern int		irq_mc;
extern nodemask_t	node_online_neighbour_map;
extern int		node_neighbour_num;

struct rdma_reg_state {
	wait_queue_head_t	wqh;		/* handler */
	wait_queue_head_t	wqh_d;		/* driver */
	spinlock_t		lock_top_botton;
	spinlock_t		lock_botton_driver;
	unsigned int		cs;
	unsigned int		es;
	unsigned int		tcs;
	unsigned int		rcs;
	unsigned int		tdc;
	unsigned int		rdc;
	unsigned int		tbc_count;
	unsigned int		tbc;
	unsigned int		rbc;
	unsigned int		msg_cs;
	unsigned int		node;
	unsigned int		irq_count;
	unsigned int		irq_all_count;
	unsigned int		irq_all_100_count;
	unsigned int		trwd_was;
	unsigned int		rx_trwd;
	unsigned int		rx_ready;
	unsigned int		tx_trwd;
	unsigned int		tx_ready;
	unsigned int		try_rdma;
	unsigned int		try_tdma;
	unsigned int		int_ac;
	unsigned int		msg[32];
	unsigned int		count_msg;
	unsigned int		big_count_msg;
	long			tdc_jiffies;
	long			rdc_jiffies;
	long			rxr_free_jiffies;
	int			rxr_free0_count;
	long			txr_free_jiffies;
	int			txr_free0_count;
	long			rx_trwd_jiffies;
	int			rx_trwd_count;
	long			rx_ready_jiffies;
	int			rx_ready_count;
	long			tx_trwd_jiffies;
	long			tx_ready_jiffies;
	int			tx_ready_count;
	long			try_rdma_jiffies;
	int			try_rdma_count;
	long			try_tdma_jiffies;
	int			try_tdma_count;
	unsigned int		rdma_state;
};

extern struct rdma_reg_state rdma_reg_state[MAX_NUMIOLINKS];

#if defined(TRACE_LATENCY) || defined(TRACE_LATENCY_MSG)
extern void user_trace_stop_my(void);
extern	void user_trace_start_my(void);
#endif

extern unsigned long	time_ID_REQ;
extern unsigned long	time_ID_ANS;
extern unsigned char	bus_number_rdma, devfn_rdma;

#define RCode_32 	0x00000000
#define RCode_64	0x02000000
#define WCode_32 	0x04000000
#define WCode_64 	0x06000000
#define OCode_xx 	0x0ff00000

typedef	unsigned int	half_addr_t;	/* single word (32 bits) */
typedef	struct rdma_addr_fields {
#if defined(CONFIG_E90S)
	half_addr_t	haddr;		/* [31:0] */ 
	half_addr_t	laddr;		/* [63:32] */ 
#else /* E3S */
	half_addr_t	laddr;		/* [31:0] */ 
	half_addr_t	haddr;		/* [63:32] */ 
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
	unsigned int	sz;	 	/* size buffers */ 
	long		order;	 	/* size buffers */
	unsigned int	nr;	 	/* number buffer's */ 
	unsigned int	way;	 	/* number buffers  */
} rdma_xx_structs_t;

typedef	struct rdma_xx_struct {
	rdma_xx_structs_t	*xxs;	/* pointer on structs for rdma */
	unsigned int		nr_xxs;	/* count structs for rdma */
} rdma_xx_struct_t;

typedef	struct rdma_tbl_32_struct {	/* struct for rdma tbl 32 */
	unsigned int	laddr;		/* l addess */
	unsigned int	sz;	 	/* size buffers */
} rdma_tbl_32_struct_t;

typedef	struct rdma_tbl_64_struct {	/* struct for rdma tbl 64 */
	unsigned long	addr;		/* address */
	unsigned long	sz;	 	/* size buffers */
} rdma_tbl_64_struct_t;

#define	SIZE_TBL64_RDMA		4096 /*4096*/
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
#define RDMA_SIZE_TBL		RDMA_NR_E_TBL * RDMA_SIZE_E_TBL
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

#endif /* __RDMA_H__ */
