#ifndef	_UAPI_MPV_IO_H_
#define	_UAPI_MPV_IO_H_

#ifdef	__cplusplus
extern "C" {
#endif

#define	VERSION_MODULE_MPV	0x24030801 /* for using in STDP only */
/*#define MPV_DRV_VER	20301	// format xxyyzz */
/*#define MPV_DRV_VER	20302	PPS (for STV GLONASS) is remaked */
/*#define MPV_DRV_VER	20403	MPVIO_SET_TIMEOUT is added
				psecs_per_corr_clck calculated for each PPS */
#define MPV_DRV_VER	20404	/* setting mpv_st is added while
				WAIT_ON_CPU read();
				multi KPI-2 support and instens culkulaition
				are added */

#define	MPV_IOC				('M' << 8)
#define	MPVIO_SEND_INTR			(MPV_IOC | 1)   // send output bus signal 
#define	MPVIO_SET_POLAR			(MPV_IOC | 2)   // set signal polarity
#define	MPVIO_SET_STATE			(MPV_IOC | 3)   // set state bus
#define	MPVIO_RESET_REG			(MPV_IOC | 4)   // obsolite depricated
#define	MPVIO_SET_CONFIG_INTR		(MPV_IOC | 5)   // set irq number for SBUS
#define	MPVIO_CLEAR_OPTIONS		(MPV_IOC | 6)   // clear options
#define	MPVIO_RUN_DEVICE		(MPV_IOC | 7)   // clear device
#define	MPVIO_WAIT_INTR			(MPV_IOC | 8)   // wait interrupt
#define MPVIO_GET_INTR_INFO		(MPV_IOC | 10)  // get info about previous interrupt
#define MPVIO_SET_STV			(MPV_IOC | 11)  // set mode: corretn kernel time by driver MPV
#define MPVIO_SET_DBG			(MPV_IOC | 12)  // for debug
#define MPVIO_SET_INTERV		(MPV_IOC | 13)  // set interval of signals ganarated by MPV
#define MPVIO_GET_PSPCC			(MPV_IOC | 14)  // get picoseconds per counter clock
#define MPVIO_SET_PSPCC			(MPV_IOC | 15)  // set picoseconds per counter clock

/* set period if known for fast driver work */
#define MPVIO_SET_PERIOD	(MPV_IOC | 16)
/* set allowable jitter for correct couner reading latency */
#define MPVIO_SET_JIT		(MPV_IOC | 17)
/* set "do not leave cpu while waiting" */
#define MPVIO_WAIT_ONCPU	(MPV_IOC | 18)
/* for mpv-iohub: set generated signal as output */
#define MPVIO_SET_GENOUT	(MPV_IOC | 19)

/* get current state     in signal */
#define	MPVIO_GET_INTR		(MPV_IOC | 25)
/* get current state all in signal */
#define	MPVIO_GET_INTR_ALL	(MPV_IOC | 26)

/* reserve computer listens alive signal */
#define	MPVIO_LSTN_ALIVE	(MPV_IOC | 27)
/* reserved computer sends alive signal */
#define	MPVIO_SEND_ALIVE	(MPV_IOC | 28)
/* reset for generated signals to be synchronous */
#define	MPVIO_RESET_GENS	(MPV_IOC | 29)
/* as MPVIO_SET_INTERV but not as usec - as register value */
#define	MPVIO_RAW_INTRV		(MPV_IOC | 30)
/* set noise mode: 0(default) - 1641 ns; 1 - 39 ns; 2 - 5 ns */
#define	MPVIO_SET_NOISE		(MPV_IOC | 31)
/* set mode sending signal to Ethernet controler. (mpv_ioh2 only)
 * 0 - from line 0; 1 - from line 1; 2 - from line 2; 3 - do not send */
#define	MPVIO_SEND_ETHER	(MPV_IOC | 32)
/* get number of inputs */
#define MPVIO_IN_NUM            (MPV_IOC | 33)
/* get number of time correction counters */
#define MPVIO_CNT_NUM           (MPV_IOC | 34)
/* set timeout for all read()'s for a mpv_in
   MAX_SCHEDULE_TIMEOUT == LONG_MAX */
#define MPVIO_SET_TIMEOUT	(MPV_IOC | 35)

#define	MPV_NUM_IN_INTR		20
#define	MPV_NUM_IN_IOH2		3
#define	MPV_NUM_OUT_INTR	16
#define	MPV_NUM_OUT_STAT	16

typedef struct mpv_rd_inf
{
	int		intr_timeout;  	// limit time wating for interrupt (mcs)
	int		intr_assemble;	/* assembling of got interrupts */
	int		num_reciv_intr;	// number of got interrupts by driver
	int		correct_counter_nsec;	// time from sinal appear to driver enter (ns)
	long long	intr_appear_nsec;  // ns timeofday when interrupt was appear in controler
	long long	time_get_comm;	// The time when driver have sent interrupt (ns)
	/* time_of_day as mcs when intrrupt was sent */
	long long	time_generation_intr;
	long long	intr_appear_clk;  // clock source value when interrupt was got by driver
	int		prev_time_clk;   // previous correct counter register value
	int		intpts_cnt;  // common number of interrupts register value
//	struct timespec intr_appear_raw;  // monotonic time when interrupt was appear in controler
//	struct timespec intr_appear_real;  // real time when interrupt was appear in controler
	long long	irq_enter_ns; /* driver enter minus OS enter time */
	/* interrupt appear time as basic mpv counter cklocks */
	unsigned int	mpv_time;
	int		mpv_drv_ver;
	/* corr.count reading duration */
	int		read_cc_ns;
	int		mpv_dev_id;
	int		mpv_dev_rev;
} mpv_rd_inf_t;

typedef struct mpv_intr
{
	int		intr_timeout;  	// limit time wating for interrupt (mcs)
	int		intr_assemble;	// assemling of got interrupts
	int		num_reciv_intr[MPV_NUM_IN_INTR];	// number of got interrupts by driver
	int		correct_counter_nsec[MPV_NUM_IN_INTR];	// time from sinal appear to driver enter (ns)
	long long	intr_appear_nsec[MPV_NUM_IN_INTR];  // ns timeofday when interrupt was appear in controler
	long long	time_get_comm;	// The time when driver have sent interrupt (ns)
	long long	time_generation_intr[MPV_NUM_IN_INTR];
	/* time_of_day  as mcs when intrrupt was sent */
	long long	intr_appear_clk[MPV_NUM_IN_INTR];  // clock source value when interrupt was got by driver
	int		prev_time_clk[MPV_NUM_IN_INTR];   // previous correct counter register value
	int		intpts_cnt[MPV_NUM_IN_INTR];  // common number of interrupts register value
	/* driver enter minus OS enter time */
	long long	irq_enter_ns[MPV_NUM_IN_INTR];
	/* interrupt appear time as basic mpv counter cklocks */
	unsigned int	mpv_time[MPV_NUM_IN_INTR];
	int		mpv_drv_ver;
	/* corr.count reading duration */
	int		read_cc_ns[MPV_NUM_IN_INTR];
	int		mpv_dev_id;
	int		mpv_dev_rev;
} mpv_intr_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _UAPI_MPV_IO_H_ */
