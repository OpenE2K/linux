#define PCI_VENDOR_ID_MCST_RDMA	0x8086
#define PCI_DEVICE_ID_MCST_RDMA	0x7191

/* Indexes of pci_dev.resource[] */
#define PCI_MMIO_BAR		0
#define PCI_MEM_BAR		1

#define RDMA_PFX		"rdma: "
#define RDMA_PFX_READ		"rdma: read_buf: "
#define RDMA_PFX_WRITE		"rdma: write_buf: "
#define RDMA_PFX_SEND_MSG	"rdma: send_msg: "
#define RDMA_PFX_IOCTL		"rdma_ioctl: "
#define RDMA_PFX_IOCTL		"rdma_ioctl: "

//#define RDMA_REG_TRACE 1
//#define RDMA_PRN_ADDR_FUN 1
//#define TRACE_LATENCY 1
//#define TRACE_LATENCY_MSG 1
//#define TRACE_LATENCY_SM 1

#ifndef RDMA_PRN_ADDR_FUN
#define RDMA_PRN_ADDR_FUN	0
#endif
#define PRN_ADDR_FUN(x...)	if(RDMA_PRN_ADDR_FUN) \
				printk( x )

#ifndef RDMA_DEBUG
#define RDMA_DEBUG		0
#endif
#define DEBUG_MSG(x...)		if(RDMA_DEBUG)	\
				printk(RDMA_PFX x )

#ifndef RDMA_TRACE
#define RDMA_TRACE		1
#endif
#define TRACE_MSG(x...)		if(RDMA_TRACE)	\
				printk(RDMA_PFX x )

#define INFO_MSG(x...) 		printk(  RDMA_PFX x )
#define WARN_MSG(x...) 		printk(  RDMA_PFX x )
#define ERROR_MSG(x...) 	printk(  RDMA_PFX x )


#ifndef RDMA_DEBUG_READ
#define RDMA_DEBUG_READ		0
#endif
#define dbg_read_buf(x...)	if(RDMA_DEBUG_READ)	\
				printk(RDMA_PFX_READ x )

#ifndef RDMA_DEBUG_SEND_MSG
#define RDMA_DEBUG_SEND_MSG	0
#endif
#define dbg_send_msg(x...)	if(RDMA_DEBUG_SEND_MSG)	\
				printk(RDMA_PFX_SEND_MSG x )

#ifndef RDMA_DEBUG_WRITE_BUF
#define RDMA_DEBUG_WRITE_BUF	0
#endif
#define dbg_write_buf(x...)	if(RDMA_DEBUG_WRITE_BUF)\
				printk(RDMA_PFX_WRITE x )

#ifndef RDMA_DEBUG_IOCTL
#define RDMA_DEBUG_IOCTL	0
#endif
#define dbg_ioctl(x...)		if(RDMA_DEBUG_IOCTL)	\
				printk(RDMA_PFX_IOCTL x )

#define EVENT			1
#define fix_event		if(EVENT_IOCTL) fix_event_proc

#define EVENT_IOCTL	1
#ifndef EVENT_IOCTL
#define EVENT_IOCTL	0
#endif /* RDMA_DBG */

#define event_ioctl		if(EVENT_IOCTL) fix_event

#define EVENT_INTR	1
#ifndef EVENT_INTR
#define EVENT_INTR	0
#endif /* RDMA_DBG */

#define event_intr		if(EVENT_INTR) fix_event

#define EVENT_READ	1
#ifndef EVENT_READ
#define EVENT_READ	0
#endif /* RDMA_DBG */

#define event_read		if(EVENT_READ) fix_event

#define EVENT_WRITE	1
#ifndef EVENT_WRITE
#define EVENT_WRITE	0
#endif /* RDMA_DBG */

#define event_write		if(EVENT_WRITE) fix_event

#define EVENT_SNDMSG	1
#ifndef EVENT_SNDMSG
#define EVENT_SNDMSG	0
#endif /* RDMA_DBG */

#define event_sndmsg		if(EVENT_SNDMSG) fix_event

#define EVENT_DDI_CV 1
#define event_ddi_cv 		if (EVENT_DDI_CV) fix_event

#define DEBUG 0
#define	dbgprn if (DEBUG) 	printk 

#define CONFIG_CMD_RDMA(bus,devfn, where)   (0x80000000 | (bus << 16) | (devfn << 8) | (where & ~3))

#define MAX_TIMER 15000000	/*   не более xxx сек	      */
#define IO_TIMEOUT 10000000 	/* n000000: n sec i/o timeout */
#define SHIFT_TO	10
#define REPEAT_TRWD_MAX		5
#define REPEAT_WAIT_RD_MAX	50
#define TIME_OUT_WAIT_RD	30 // test rdma ok 
#define TIME_OUT_WAIT_WR	40 // test rdma ok
#define TIME_OUT_WAIT_FS	100

#define MSG_OPER  	0x80000000	/* Messages OPER */
#define MSG_TRWD	0x80000000	/* Messages TRWD */
#define MSG_READY	0x00000000	/* Messages READY RECEIVER */
#define ALLIGN_RDMA     256

#define MAX_max(a, b) 	 (a)>(b)?(a):(b)
#define MIN_min(a, b) 	 (a)>(b)?(b):(a)

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
#define MAX_COUNT_RDR_RBC 300
#define WAIT_SND_MSG		100


#define board_name	"MCST,rdma"	/* should be same as FCODE.name */

///#define DEV_inst(m)	((m > 6)?1:0)		/* minor -> instance */
#define DEV_inst(m)	(0)		/* minor -> instance */
///#define DEV_chan(m)	((m > 6)?m - 7:m)	/* minor -> channel */
#define DEV_chan(m)	(m)	/* minor -> channel */

#define MAX_CHANNEL		8
#define MAX_CHANNEL_RDMA	12


#define READER	0
#define WRITER	1

#define MSG_USER	0x0fffffff	/* Messages for user */
#define MSG_ABONENT	0x70000000
#define SHIFT_ABONENT	28

#ifdef RDMA_REG_TRACE
extern void WRR_rdma(unsigned char *reg, unsigned int val);
extern unsigned int RDR_rdma(unsigned char *reg);
#else
#define WRR_rdma(reg, val)	writel(val, reg)
#define RDR_rdma(reg)		readl(reg)
#endif

extern	raw_spinlock_t	mu_fix_event;
extern	raw_spinlock_t	cam_lock;

typedef struct dev_rdma_sem {
	char *dev_name;
	unsigned long	waited2_clkr;
	unsigned long	waited1_clkr;
	unsigned long	broadcast_clkr;
	unsigned long timeout;
	long irq_count_rdma;		/* счетчик еще не обработанных прерываний, как правило 1 */
	unsigned int	num_obmen; 	/* номер обмена */
	unsigned long	time_broadcast; /* момент подачи команды на пробуждение */

	raw_spinlock_t	lock;
	kcondvar_t	cond_var;
} dev_rdma_sem_t;

typedef struct dma_chan {
   	uchar_t channel;	 	 /*      channel index in slot 	 */
        uchar_t allocs;	 		 /* chan res alloc statbit stack */

	dma_addr_t	 dma_busa;
	dma_addr_t	 dma;
	dma_addr_t	 fdma;
	dma_addr_t	 *prim_buf_addr;
	size_t		 real_size;
	uint_t		tm;
	uint_t		tm_inited;
	size_t		size_tm;
	uint_t		full;
	dma_addr_t	*vdma_tm;
	dma_addr_t	fdma_tm;
} dma_chan_t;

typedef struct rw_state {
	raw_spinlock_t	lock_wr;
	raw_spinlock_t	lock_rd;
	raw_spinlock_t	mu_spin;
	kmutex_t	mc;
	struct dev_rdma_sem 	dev_rdma_sem;
	kmutex_t	mu;
	struct sk_buff *skb;
	uchar_t		stat;
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
	uint_t		real_size;
	uint_t		size_trans;
	uint_t		size_trb;
	uint_t		errno;
	uint_t		dma_busa;
	dma_addr_t	*prim_buf_addr;
	uint_t		vdma_tm;
	uint_t		fdma_tm;
	uint_t		tm;
	uint_t		dma;
	uint_t		fdma;
	uint_t		n_ready;
	dma_chan_t     *chd;
	int	clock_begin_read;
	int	clock_end_read_old;
	int	clock_begin_read_old;
	int	trwd_send_count;
	int	ready_send_count;
	int	trwd_rec_count;
	int	ready_rec_count;
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
	kmutex_t	mu;
	unsigned int	opened;
	dma_chan_t	dma_chans[MAX_CHANNEL_RDMA];	/* DMA channels vector */
	rw_state_t rw_states_d[2];
	rw_state_t rw_states_m[2];
	rw_state_t ralive;
	rw_state_t talive;
	rw_state_t *rw_states_wr;
	rw_state_t *rw_states_rd;
} rdma_state_inst_t;

struct rdma_state {
	struct pci_dev *dev_rdma;	
	unsigned int	major;
	kmutex_t	mu;
	unsigned long 	mmio_base;		// phys address
	uint8_t*	mmio_vbase;		// virtual address
	unsigned int	mmio_len;
	unsigned int	inited;
	int		size_rdma_state;
	rdma_state_inst_t	rdma_sti[2];
	
};

typedef	unsigned int	half_addr_t;	/* single word (32 bits) */
typedef	struct rdma_addr_fields {
	half_addr_t	laddr;		/* [31:0] */ 
	half_addr_t	haddr;		/* [63:32] */ 
} rdma_addr_fields_t;

typedef	union rdma_addr_struct {	/* Structure of word */
	rdma_addr_fields_t	fields;	/* as fields */
	unsigned long		addr;	/* as entier register */
} rdma_addr_struct_t;

typedef	struct rdma_tbl_32_struct {	/* struct for rdma tbl 32 */
	unsigned int	laddr;		/* l addess */
	unsigned int	sz;	 	/* size buffers */
} rdma_tbl_32_struct_t;

typedef	struct rdma_tbl_64_struct {	/* struct for rdma tbl 64 */
	unsigned long	addr;		/* address */
	unsigned long	sz;	 	/* size buffers */
} rdma_tbl_64_struct_t;

#define	SIZE_TBL64_RDMA		4096 /*4096*/
#define	SIZE_TBL32_RDMA		4096 /*4096*/
#define	NR_ENTRY_TBL64_RDMA	(SIZE_TBL64_RDMA >> 4)


extern struct rdma_state *rdma_state;

extern int	wait_for_irq_rdma_sem(void* dev_rdma_sem, signed long timeout);
extern void __wake_up_common(wait_queue_head_t *q, unsigned int mode,//muvlad
			     int nr_exclusive, int sync, void *key);

extern void	(*rdma_interrupt_p)(struct pt_regs *regs);
extern void	fix_event_proc(unsigned int channel, unsigned int event, unsigned int val1, unsigned int val2);
extern int send_msg(rdma_state_inst_t *xsp, unsigned int msg, int instance, unsigned int cmd, dev_rdma_sem_t *dev);
extern unsigned int	msg_cs_dmrcl;

extern rdma_event_t rdma_event;

extern int rdma_event_init;
extern int	irq_mc;

#if defined(TRACE_LATENCY) || defined(TRACE_LATENCY_MSG)
extern void	user_trace_stop_my(void);
extern	void	user_trace_start_my(void);
#endif

extern unsigned long	time_ID_REQ;
extern unsigned long	time_ID_ANS;
extern unsigned char	bus_number_rdma, devfn_rdma;
extern unsigned int 	tr_atl;

