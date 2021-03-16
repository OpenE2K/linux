#ifndef __USER_INTF_H__
#define __USER_INTF_H__

#ifdef	__cplusplus
extern "C" {
#endif

/* Register Event Status ES 0x07fcfffd cbfc 0x07fc000f*/
#define ES_RDMC		  0xf8000000	/* ES:31-27: Received Data_Messages Counter RO */
#define ES_RDM_Ev	  0x04000000	/* ES:26: Received Data_Message Event RO */
#define ES_RGP3M_Ev	  0x02000000	/* ES:25: Received GP3_Message Event R/WC */
#define ES_RGP2M_Ev	  0x01000000	/* ES:24: Received GP2_Message Event R/WC */
#define ES_RGP1M_Ev	  0x00800000	/* ES:23: Received GP1_Message Event R/WC */
#define ES_RGP0M_Ev	  0x00400000	/* ES:22: Received GP0_Message Event R/WC */
#define ES_RIAM_Ev	  0x00200000	/* ES:21: Received ID_Answer_Message Event R/WC */
#define ES_RIRM_Ev	  0x00100000	/* ES:20: Received ID_Request_Message Event R/WC */
#define ES_RULM_Ev	  0x00080000	/* ES:19: Received UnLock_Message Event R/WC */
#define ES_RLM_Ev	  0x00040000	/* ES:18: Received Lock_Message Event R/WC */
#define ES_MSF_Ev	  0x00020000	/* ES:17: Message Send Failed Event R/WC */
#define ES_SM_Ev	  0x00010000	/* ES:16: Send Message Event R/WC */
#define ES_DSF_Ev	  0x00000008	/* ES:3: Data Send Failed Event R/WC */
#define ES_TDC_Ev	  0x00000004	/* ES:2: Transmitter DMA Complete Event R/WC */
#define ES_RDC_Ev	  0x00000002	/* ES:1: Receiver DMA Complete Event R/WC */
#define ES_CMIE_Ev	  0x00000001	/* ES:0: Channel Master Interface Error Event R/WC */
#define ES_DEF	          0x0000fff0	/* ES:15-4: Not usage */
#define ES_ALT	          0xffff000f	/* ES:15-4: Not usage */
#define ES_SMSG	          (ES_MSF_Ev | ES_SM_Ev)	/* Send Message */
#define ES_SD	          (ES_DSF_Ev | ES_TDC_Ev)	/* Send Date */
#define ES_CLEAR_ALL_EVENT	0x03fc000f
#define	ES_CLEAR_SMF (ES_DEF | ES_SM_Ev | ES_MSF_Ev)

/* Register Interrupt Mask Control 0x07fc000d*/
#define IRQ_RDM	    0x04000000   /* IRQ_MC:26: Received Data_Message IRQ Enable R/W */
#define IRQ_RGP3M   0x02000000   /* IRQ_MC:25: Received GP3_Message IRQ Enable R/W */
#define IRQ_RGP2M   0x01000000   /* IRQ_MC:24: Received GP2_Message IRQ Enable R/W */
#define IRQ_RGP1M   0x00800000   /* IRQ_MC:23: Received GP1_Message IRQ Enable R/W */
#define IRQ_RGP0M   0x00400000   /* IRQ_MC:22: Received GP0_Message IRQ Enable R/W */
#define IRQ_RIAM    0x00200000   /* IRQ_MC:21: Received ID_Answer_Message IRQ Enable R/W */
#define IRQ_RIRM    0x00100000   /* IRQ_MC:20: Received Request_Message IRQ Enable R/W */
#define IRQ_RULM    0x00080000   /* IRQ_MC:19: Received UnLock_Message IRQ Enable R/W */
#define IRQ_RLM	    0x00040000   /* IRQ_MC:18: Received Lock_Message IRQ Enable R/W */
#define IRQ_MSF	    0x00020000   /* IRQ_MC:17: Message Send Failed IRQ Enable R/W */
#define IRQ_SM	    0x00010000   /* IRQ_MC:16: Send Message IRQ Enable R/W */
#define IRQ_DSF	    0x00000008   /* IRQ_MC:3:  Data Send Failed IRQ Enable R/W */
#define IRQ_TDC	    0x00000004   /* IRQ_MC:2:  Transmitter DMA Complete IRQ Enable R/W */
#define IRQ_RDC	    0x00000002   /* IRQ_MC:1:  Receiver DMA Complete IRQ Enable R/W */
#define IRQ_CMIE    0x00000001   /* IRQ_MC:0:  Channel Master Interface Error IRQ Enable R/W */
#define IRQ_def     0xf800fff0   /* IRQ_MC:    Not usage */
#define IRQ_ALT     0x07ff000f   /* IRQ_MC:    Not usage */

/* Register DMA Transmitter Control/Status DMA_TCS 8007fff4 0000fff4*/
#define DMA_TCS_DPS_Err        0x80000000   /* DMA_TCS:31: Data Packet Stall Error RO */
#define DMA_TCS_DPCRC_Err      0x40000000   /* DMA_TCS:30: Data Packet CRC Error RO */
#define DMA_TCS_DPTO_Err       0x20000000   /* DMA_TCS:29: Data Packet Time Out Error RO */
#define DMA_TCS_DPID_Err       0x10000000   /* DMA_TCS:28: Data Packet Invalid Destination Error RO */
#define DMA_TCS_TTM            0x00040000   /* DMA_TCS:18: Transmit Table Mode R/W */
#define DMA_TCS_TDMA_On        0x00020000   /* DMA_TCS:17: Transmit DMA On RO */
#define DMA_TCS_TALD           0x00010000   /* DMA_TCS:16: Transmit Address Loaded RO */
#define DMA_TCS_DRCL           0x0000fff0   /* DMA_TCS:15:4: Data Repeat Counter Loaded R/W */
#define DMA_TCS_DRCL_w(r,n)    (r & 0xffff0fff | n << 12)   /* DMA_TCS:15-4: Data Repeat Counter Loaded R/W */
#define DMA_TCS_TTM            0x00040000   /* DMA_TCS:18: Transmit Tabel Mode R/W */
#define DMA_TCS_TE             0x00000004   /* DMA_TCS:2:  Transmit Enable R/W */
#define DMA_TCS_TE_0           0x0000000b   /* DMA_TCS:2:  Transmit Disable R/W */
#define DMA_TCS_TCO            0x00000002   /* DMA_TCS:1:  Transmit Coherent DMA Operation R/W */
#define DMA_TCS_TCO_0          0x0000000d   /* DMA_TCS:1:  Transmit NonCoherent DMA Operation R/W */
#define DMA_TCS_Tx_Rst         0x00000001   /* DMA_TCS:0:  Reset Transmitter R/W */
#define DMA_TCS_def            0x0ffc0ff8   /* DMA_TCS:    Not usage */

/* Register DMA Tx Start Address DMA_TCA */
#define DMA_TSA        0xffffffff   /* DMA_TCA:31-0: DMA Tx Start Address R/W */

/* Register DMA Tx Byte Count DMA_TBC */
#define DMA_TBC        0xffffffff   /* DMA_TBC:31-0: DMA Tx Byte Counter R/W */

/* Register DMA Receiver Control/Status DMA_RCS 00040004*/
#define DMA_RCS_RTM            0x00040000   /* DMA_RCS:18: Receive DMA Table Mode R/W */
#define DMA_RCS_RDMA_On        0x00020000   /* DMA_RCS:17: Receive DMA On RO */
#define DMA_RCS_RALD           0x00010000   /* DMA_RCS:16: Receive Address Loaded RO */
#define DMA_RCS_RFSM           0x00000008   /* DMA_RCS:3:  Receive Floating Size Mode R/W */
#define DMA_RCS_RE             0x00000004   /* DMA_RCS:2:  Receive Enable R/W */
#define DMA_RCS_RCO            0x00000002   /* DMA_RCS:1:  Receive Coherent DMA opration R/W */
#define DMA_RCS_Rx_Rst         0x00000001   /* DMA_RCS:0:  Reset Receive R/W */
#define DMA_RCS_def            0xfffcfff8   /* DMA_RCS:    Not usage */

/* Register DMA Rx Start Address DMA_RSA */
#define DMA_RSA        0xffffffff   /* DMA_RSA:31-0: DMA Rx Start Address */

/* Register DMA Rx Byte Count DMA_RBC */
#define DMA_RBC        0xffffffff	/* DMA_RBC:31-0: DMA Rx Byte Counter */

/* Register Message Control/Status MSG_CS */
#define MSG_CS_DMPS_Err         0x80000000	/* MSG_CS:31: Data_Message Packet Stall Error RO */
#define MSG_CS_MPCRC_Err        0x40000000	/* MSG_CS:30: Message Packet CRC Error RO */
#define MSG_CS_MPTO_Err         0x20000000	/* MSG_CS:29: Message Packet Time Out Error RO */
#define MSG_CS_DMPID_Err        0x10000000	/* MSG_CS:28: Data_Message Packet Invalid ID Error RO */
#define MSG_CS_IAMP_Err         0x08000000	/* MSG_CS:27: Id_Answer_Message Packet Error RO */
#define MSG_CS_SD_Msg           0x04000000	/* MSG_CS:26: Send Data_Message RO */
#define MSG_CS_DMRCL            0x0000fff0	/* MSG_CS:15:4: Data_Message Repeat Counter Load  R/W */
//#define MSG_CS_SIR_Msg          0x00000008	/* MSG_CS:3: Send ID_Request_Message R/W */
#define MSG_CS_SIR_Msg        0x00000002	/* MSG_CS:1: Send ID Request Message R/W */
#define MSG_CS_SL_Msg         0x00000004	/* MSG_CS:2: Send Lock Message R/W */
#define MSG_CS_SUL_Msg        0x00000006	/* MSG_CS:3: Send Unlock Message R/W */
#define MSG_CS_SGP0_Msg       0x00000008	/* MSG_CS:4: Send GP0 Message R/W */
#define MSG_CS_SGP1_Msg       0x0000000a	/* MSG_CS:5: Send GP1 Message R/W */
#define MSG_CS_SGP2_Msg       0x0000000c	/* MSG_CS:6: Send GP2 Message R/W */
#define MSG_CS_SGP3_Msg       0x0000000e	/* MSG_CS:7: Send GP3 Message R/W */
#define MSG_CS_Msg_Rst          0x00000001	/* MSG_CS:0: Reset Message Block R/W */
#define MSG_CS_def              0x0fff0ff0	/* MSG_CS:   Not usage */
//#define __KERNEL__
//#define MODULE
#define RDMA_SMC
#define RDMA_CACHE
#define RDMA_CACHE_USER
#define EXPORT_SYMTAB
#define EVENT_SCHED
#define RDMA_TRWD_WAS
#define RDMA_SEM
#define RDMA_SPIN_SEM_INTR
#define EXPORT_SYMTAB 
//#define RX_RFSM 
//#define RDMA_LVNET

#define	SIZE_EVENT		0x400

typedef struct rdma_ioc_parm {
	int	reqlen;
	int	acclen;
	int	err_no;
	int	rwmode;
	int	msg;
} rdma_ioc_parm_t;

#define NR_rdma_intr		1
#define NR_add_rdma_queue	2
#define NR_drx			3
#define NR_dtx			4
#define NR_send_skb_pio		5
#define NR___lvnet_tx		6
#define NR_lvnet_tx_timeout	7
#define NR_lvnet_stop		8

#define RDMA_IOC_WAIT	     1
#define RDMA_IOC_NOWAIT	     2
#define RDMA_IOC_CHECK	     3
#define RDMA_IOC_POLL	     4


#define RDMA_IOC_ALLOCB	     2 
#define RDMA_IOC_VALLOCB	52 
#define RDMA_IOC_ARP		53 
#define RDMA_IOC_CH_ALLOCB   30

#define RDMA_IOC_READ	     3
#define RDMA_IOC_READ_1	     34
#define RDMA_IOC_READM	     32
#define RDMA_IOC_WRITE	     33
#define RDMA_IOC_INTR	     89
#define RDMA_IOC_WRITEM	     4
#define RDMA_TIMER_FOR_READ  5
#define RDMA_TIMER_FOR_WRITE 6
#define RDMA_TIMER_READ      48
#define RDMA_TIMER_WRITE     49
#define RDMA_IOC_DE 	     7
#define RDMA_IOC_DW	     8
#define RDMA_IOC_DR	     9
#define RDMA_IOC_RSR	    18
#define RDMA_IOC_RSR1	    19
#define RDMA_IOC_RSR2	    20
#define RDMA_IOC_RSR3	    21
#define RDMA_IOC_RSR5	    22
#define RDMA_IOC_RSR6	    24
#define RDMA_IOC_WTSGNL	    25
#define RDMA_IOC_WTSGNL1	    26
#define RDMA_IOC_WTSGNL2	    27
#define RDMA_IOC_SETRES		10
#define RDMA_IOC_RETMAIN	11
#define RDMA_IOC_SETTRBA	12
#define RDMA_IOC_WRCMD		14

#define RDMA_IOC_RDR		15
#define RDMA_IOC_WRR		16
#define RDMA_IOC_MUT 		17

#define RDMA_IOC_RDALT		23
#define RDMA_IOC_RDESCALT	29

#define RDMA_IOC_DEBUG		30

#define RDMA_IOC_IOTIME		28
#define RDMA_IOC_PHYS1		31
#define RDMA_IOC_PHYS2      	32
#define RDMA_IOC_DUMPREG0	35
#define RDMA_IOC_DUMPREG1	36
#define RDMA_IOC_LM		37
#define RDMA_IOC_DWL		38
#define RDMA_IOC_PRN_STAT	39
#define RDMA_IOC_DUMP_FUNC	40
#define RDMA_TEST_PA		41
#define RDMA_CLEAN_CASH2	42
#define RDMA_READ_CASH2		44
#define RDMA_SET_STAT		45
#define RDMA_GET_STAT		47
#define RDMA_USECTOHZ		50
#define RDMA_BP_ENABLE		51
#define RDMA_READ_NET		54
#define RDMA_WRITE_NET		55
#define RDMA_INIT_NET_RX	56
#define RDMA_INIT_NET_TX	57
#define RDMA_GET_LOG_BUF	58
#define RDMA_INIT_LOG_BUF	59
#define RDMA_SET_DELTA_READ	60
#define RDMA_GET_DELTA_READ	61
#define RDMA_SET_DELTA_WRITE	62
#define RDMA_GET_DELTA_WRITE	63
#define RDMA_IOC_GET_TAIL_READ	64
#define RDMA_IOC_GET_TAIL_WRITE	65
#define RDMA_GET_EVENT		66
#define RDMA_FIND_ETALON	67
#define RDMA_INIT_ALL_MEM	68
#define RDMA_TEST_ALLOC		69
#define RDMA_CHECK_CP_CHEREPANOV	70
#define RDMA_GET_INT_AC		71
#define RDMA_FIND_ERROR_BUF	72
#define RDMA_NEED_BYPASS	73
#define RDMA_UNNEED_BYPASS	74
#define RDMA_IOC_RDR_GL		75
#define RDMA_READ_KERNEL	76
#define RDMA_GETVF_ERROR_BUF	77
#define RDMA_CLEAN_TDC_COUNT	78
#define RDMA_CLEAN_RDC_COUNT	79
#define RDMA_TEST_WRITE_FS	80
#define RDMA_TEST_READ_FS	81
#define RDMA_TEST_WRITE_FS_Y	83
#define RDMA_TEST_READ_FS_Y	84
#define RDMA_TEST_VA_TO_PA_ASM	82
#define RDMA_TEST_ALLOC_MEM	85
#define RDMA_TEST_RDWR_BUS	86
#define RDMA_TEST_DMA_BUS	87
#define	RDMA_TEST_YIELD		88
#define	RDMA_DYMP_VIRTUAL	89
#define	BAD_NOCACHE_READ	90
#define	RDMA_READ_ARP		94

#define SIZE_BUF_NET	0x10000
#define SIZE_MTU_DEV	SIZE_BUF_NET - 0x100
#define SIZE_MTU	SIZE_BUF_NET - 0x100

//#define RDMA_IO_FINISHED    0x0100
#define LOG_BUF_LEN	(16384)
#define	ET_LAST_CACHE_LINE	0xf1f2f3f4

#define RDMA_E_NORMAL 	 0
#define RDMA_E_INVOP  	 1
#define RDMA_E_INVAL  	 2
#define RDMA_E_NOBUF 	 5
#define RDMA_E_ALLOC 	 6

#define RDMA_E_URGENT 	10
#define RDMA_E_PENDING 	11
#define RDMA_E_TIMER_IO 	78
#define RDMA_E_TIMER 	12
#define RDMA_E_DMPS 	31
#define RDMA_E_MPCRC 	32
#define RDMA_E_MPTO 	33
#define RDMA_E_SIGNAL 	34
#define RDMA_E_SIGNAL_READ_1 	58
#define RDMA_E_SIGNAL_READ_2 	59
#define INTR_E_SIZE 	35
#define RDMA_E_SIZE 	57
#define RDMA_E_SIZE_0 	36
#define RDMA_E_SIZE_1 	41
#define RDMA_E_SIZE_2 	42
#define RDMA_E_SUCCESS 	37
#define RDMA_E_MSF_WRD 	38
#define RDMA_E_CRSM_WRD	39
#define RDMA_E_MEMOUT	40
#define RDMA_IOC_NOTRUN 14
#define RDMA_IOC_DIFCH  15
#define RDMA_DESC_DISABLED 16
#define INTR_CS_MOW	43
#define RDMA_CS_MOW	44
#define RDMA_CS_MOR	60
#define RDMA_CS_BM	45
#define RDMA_CS_SIE	46
#define RDMA_ERREAD  20
#define RDMA_ERREAD4  68
#define RDMA_ERREAD_1  53
#define RDMA_ERREAD_2  54
#define RDMA_ERREAD_3  56
#define RDMA_ERREAD_4  61
#define RDMA_E_READ_TIMEOUT  60
#define RDMA_E_WRITE_TIMEOUT  62
#define RDMA_ERWRITE 21
#define RDMA_E_WRITE_1 68
#define RDMA_E_WRITE_2 69
#define RDMA_E_MISS	48
#define RDMA_ERREAD1 30
#define MASK_MOW	49
#define MASK_MOR	55
#define RCS_EN		50
#define RDMA_E_READY	51
#define RCS_EMPTY	0	/* rdma channel empty		*/
#define RCS_ALLOCED_B   1 	/* chan res alloc stat bit masks */
#define RCS_ALLOCED	2	/* rdma channel alloced		*/
#define RCS_MAPPED	3	/* rdma channel mapped		*/
#define RCS_REQUEST	4	/* rdma channel requested	*/
#define RDMA_E_TIMER_MAX 52
#define RDMA_E_GP0	57
#define RDMA_E_REPWR	58
#define RDMA_E_REPRD	59
#define READ_E_24	63
#define READ_E_44	64
#define WRITE_E_4	67
#define TRWD_E_SIZE	65
#define RDMA_E_MAKE_TM	66
#define RDMA_E_READ_LOSS 70
#define RDMA_E_SEM_1	71
#define RDMA_E_SEM	75
#define RDMA_E_SPIN	72
#define ENV_rdma_write_net	0x0
#define RDMA_E_RD_1_ERR	73
#define RDMA_E_RD1ERR	79
#define RDMA_E_IRQ_COUNT1	74
#define RDMA_E_IRQ_COUNT2	84
#define RDMA_E_BAD_BUFFER	80
#define RDMA_E_NEED_BYPASS	81
#define RDMA_E_CS_SL_Msg	82
#define RDMA_E_CS_SUL_Msg	83
#define RDMA_E_CS_SIR_Msg	84
#define RDMA_E_BAD_SYNHR	100

#define	SIZE_ENTRY		5

struct	rdma_event_entry {
	unsigned int	hrtime;
	unsigned int	event;
	unsigned int	channel;
	unsigned int	val1;
	unsigned int	val2;
};

extern char		sdvk[100];
extern char		*preg;
extern char		*prw;
extern int parce_rcs(unsigned int rcs, char *p);
extern int parce_tcs(unsigned int tcs, char *p);
extern int parce_msg(unsigned int msg, char *p);
extern int parce_es(unsigned int es, char *p);
extern int parce_msg_cs(unsigned int msg_cs, char *p);
extern char *get_event(int event);
extern int parse_reg(struct rdma_event_entry *ree);

struct code_msg {
	int code;
	char * msg;
};

typedef struct code_msg code_msg_t;

struct stat_rdma {
	int	stop_queue;
	int	wake_queue;
	int	stop_wake_queue;
	int	lance_wake_1;
	int	lance_wake_2;
	int	lance_wake_3;
	int	lance_wake_4;
	int	lance_stop_1;
	int	lance_stop_2;
	int	lance_stop_3;
	int	lance_stop_4;
	int	lance_stop_5;
	int	fail_snd_ready_rt;
	int	fail_snd_ready_tr;
	int	fail_snd_ready_bc;
	int	fail_snd_ready_def;
	int	nfor_rec_trwd_rt;
	int	nfor_rec_trwd_tr;
	int	nfor_rec_trwd_bc;
	int	nfor_rec_trwd_def;
	int	nfor_snd_trwd_tx;
	int	nfor_snd_trwd_tr;
	int	nfor_snd_trwd_bc;
	int	nfor_snd_trwd_def;
	int	fail_lvnet_tx;
	int	rdc_waste;
	int	trwd_was_timeout;
	int	rec_transmit;
	int	rec_in_steck;
	int	rec_broad_steck;
	int	rec_broad;
	int	cur_clock;
	int	send_trwd;
	int	send_ready;
	int	rec_trwd;
	int	rec_ready;
	int	cs_bm;
	int	cs_bus;
	int	cs_sie;
	int	es_cmie;
	int	es_rdm;
	int	rdm;
	int	READY;
	int	TRWD;
	int	rdm_UNXP;
	int	rdm_EXP;
	int	es_sm;
	int	es_rdc;
	int	bad_synhr;
	int	wait_r;
	int	wr_1;
	int	wait_rr;
	int	pd_rd;
	int	bg_wr;
	int	rp_wr;
	int	rep_wr;
	int	rbc1;
	int	rdc_unxp;
	int	miss;
	int	TRWD_UNXP;
	int	trwd;
	int	ready;
	int	snd_ready;
	int	snd_trwd;
	int	trwd_was;
	int	miss_TRWD_2;
	int	miss_TRWD_3;
	int	miss_TRWD_4;
	int	READY_UNXP;
	int	miss_READY_2;
	int	miss_READY_3;
	int	tdc_1_1;
	int	tdc_3_1;
	int	tdc_3_2;
	int	nrbc;
	int	TE;
	int	TErr;
	int	TALD;
	int	TDMA_On;
	int	mask_mow;
	int	mask_mor;
	int	rdc_kbyte;
	int	try_RDMA;
	int	_nr_tx;
	int	_nr_rx;
	int	try_RDMA_tm;
	int	SYNC_WRITE1;
	int	SYNC_READ1;
	int	dtx_irq_count;
	int	count_va_to_pa;
	int	Ttbc0;
	int	Ttbc1;
	int	Ttbc2;
	int	Rtimeout;
	int	Ttimeout;
	int	repeate_TRWD;
	int	repeate_write;
	int	repeate_intr;
	int	es_dsf;
	int	es_dsf_unxp;
	int	count_dsf;
	int	count_dsf_err;
	int	count_timer_tcs;
	int	msf;
	int	rdma_intr;
	int	pr_rd_was;
	int	dma_tcs_dps_err;
	int	dma_tcs_dpcrc_err;
	int	dma_tcs_dpto_err;
	int	dma_tcs_dpid_err;
	int	es_tdc;
	int	es_tdc_unxp;
	int	es_dsf_tdc;
	int	try_TDMA;
	int	try_TDMA_1;
	int	try_TDMA_2;
	int	try_TDMA_3;
	int	try_TDMA_4;
	int	try_TDMA_5;
	int	try_TDMA_tm;
	int	try_TDMA_err;
	int	T_int_ac;
	int	T_int_ac_dsf;
	int	R_int_ac;
	int	td_urg;
	int	td_murg;
	int	Tspin;
	int	T_signal;
	int	R_signal;
	int	es_rlm;
	int	es_rulm;
	int	es_riam;
	int	es_rirm;
	int	es_rgp3;
	int	es_rgp2;
	int	es_rgp1;
	int	es_rgp0;
	int	es_msf;
	int	send_msg_SM_0;
	int	send_msg_MSF_0;
	int	send_msg_DMRCL_0;
	int	send_msg_SD_Msg_0;
	int	send_msg_CRMAX;
	int	wait_write;
	int	waited_write;
	int	wait_read;
	int	waited_read;
	int	flags;
	int	GP0_0;
	int	GP0_1;
	int	GP0_2;
	int	GP0_3;
	int	GP1_0;
	int	GP1_1;
	int	GP1_2;
	int	GP1_3;
	int	GP2_0;
	int	GP2_1;
	int	GP2_2;
	int	GP2_3;
	int	GP3_0;
	int	GP3_1;
	int	GP3_2;
	int	GP3_3;
	int	msf_0;
	int	msf_2;
	int	msf_3;
	int	msf_4;
	int	repwr;
	int	reprd;
	int	rep_read;
	int	TRWD_SIZE;
	int	RDMA_MSF_WRD;
	int	RDMA_CRSM_WRD;
	int	RDMA_MAKE_TM;
	int	net_rx_cn_low;
	int	net_rx_cn_mod;
	int	net_rx_cn_high;
	int	net_rx_cn_drop;
	int	bad_stat_tx;
	int	tdc_dsf_unxp;
	int	netif_queue_running_unexp;
	int	send_skb_pio_err_1;
	int	send_skb_pio_err_2;
	int	send_skb_pio_err_3;
	int	send_skb_pio_err_4;
	int	transmit;
	int	rx_dropped;
	int	gp;
	int	send_gp;
	int	send_gp0_1;
	int	send_gp0_2;
	int	send_gp0_3;
	int	send_gp0_4;
	int	send_gp0_5;
	int	puting_in_tx_gp0;
	int	send_skb_pio_gp0;
	int	TDC_gp0;
	int	send_gp1;
	int	wastb;
	int	try_wastb;
	int	res0;
	int	nr_bh;
	int	bh_0;
	int	bh_1;
	int	bh_2;
	int	bh_3;
	int	bh_4;
	int	bh_5;
	int	bh_6;
	int	bh_7;
	int	bh_8;
	int	bh_9;
	int	bh_10;
	int	bh_11;
	int	bh_12;
	int	bh_13;
	int	bh_14;
	int	bh_15;
	int	bh_d;
	int	nr_bh_s;
	int	er_busy_rdc;
	int	er_size_bh;
	int	nr_in_steck;
	int	sz_in_steck;
	int	rx_avail;
	int	tx_avail;
	int	tr_avail;
	int	bc_avail;
	int	tx_timeout;
	int	ngp1;
	int	bcast;
	int	host;
	int	err_busy_tdc;
	int	err_tdc_fe_fb;
	int	err_worked_tdc;
	int	err_stat_tdc;
	int	er_tcs_gp1;
	int	er_busy_gp1;
	int	er_worked_gp1;
	int	netif;
	int	spin_lvnet_tx_rdma_intr;
	int	spin_lvnet_tx_lvnet_tx;
	int	spin_rdma_intr_lvnet_tx;
	int	spin_rdma_intr_rdma_intr;
	int	rec_trwd_tx_bc;
	int	rec_trwd_bc_bc;
	int	rec_trwd_tx_rt;
	int	rec_trwd_tr_rt;
	int	rec_trwd_tx_tr;
};

extern struct stat_rdma *stat_rdma[2];

#define	END_RDC_READ		0
#define	END_RDC_INTR_READ	END_RDC_READ + 15
#define	TRWD_READY_READ		END_RDC_INTR_READ + 15
#define	READY_RDC_READ		TRWD_READY_READ + 15
#define	BEGIN_END_READ		READY_RDC_READ + 15
#define	BEGIN_BEGIN_READ	BEGIN_END_READ + 15
#define	DELTA_READ		BEGIN_BEGIN_READ + 15
#define	DELTA_WRITE		DELTA_READ



#define	SIZE_TAIL		0x100

//extern	int tail_read[SIZE_TAIL];
//extern	int tail_write[SIZE_TAIL];
//extern	int tail_read_cur;
//extern	int tail_write_cur;

#define	RDMA_EVENT			0

#define	MASK_SIZE 0x000fffff
#define SHIFT_NMBR_PACKET 20
#define MASK_NMBR_PACKET 0x0ff00000


#define	INTR_TRWD_UNXP_EVENT		(0x9  + RDMA_EVENT)
#define	INTR_TRWD_EVENT			(0xa  + RDMA_EVENT)
#define	INTR_READY_EVENT		(0xb  + RDMA_EVENT)
#define	INTR_TDMA_EVENT			(0xc  + RDMA_EVENT)
#define	INTR_SIGN1_READ_EVENT		(0xd  + RDMA_EVENT)
#define	INTR_RMSG_EVENT			(0xe  + RDMA_EVENT)
#define	INTR_RMSG_UNXP_EVENT		(0xf  + RDMA_EVENT)
#define	INTR_RDC_EVENT			(0x10 + RDMA_EVENT)
#define	INTR_TDC_DSF_PD_NULL_EVENT	(0x11 + RDMA_EVENT)
#define	INTR_DSF_EVENT			(0x12 + RDMA_EVENT)
#define	INTR_TDC_EVENT			(0x13 + RDMA_EVENT)
#define	INTR_TDC_UNXP_EVENT		(0x8  + RDMA_EVENT)
#define	INTR_SIGN1_WRITE_EVENT		(0x14 + RDMA_EVENT)
#define	INTR_RGP3M_EVENT		(0x15 + RDMA_EVENT)
#define	INTR_RGP2M_EVENT		(0x16 + RDMA_EVENT)
#define	INTR_RGP1M_EVENT		(0x17 + RDMA_EVENT)
#define	INTR_SIGN3_READ_EVENT		(0x18 + RDMA_EVENT)
#define	INTR_RGP0M_EVENT		(0x19 + RDMA_EVENT)
#define	INTR_SIGN2_WRITE_EVENT		(0x1a + RDMA_EVENT)

#define	WRITE_1_EVENT			(0x1b + RDMA_EVENT)
#define	WRITE_11_EVENT			(0x4a + RDMA_EVENT)
#define	WRITE_111_EVENT			(0x4b + RDMA_EVENT)
#define	WRITE_PMSTAT_EVENT		(0x1c + RDMA_EVENT)
#define	WRITE_SNDMSGBAD_EVENT		(0x1d + RDMA_EVENT)
#define	WRITE_SNDNGMSG_EVENT		(0x1e + RDMA_EVENT)
#define	WRITE_BAD1_EVENT		(0x1f + RDMA_EVENT)
#define	WRITE_0_EVENT			(0x20 + RDMA_EVENT)
#define	WRITE_00_EVENT			(0x4c + RDMA_EVENT)
#define	WRITE_000_EVENT			(0x4d + RDMA_EVENT)
#define	WRITE_ISDSF_EVENT		(0x21 + RDMA_EVENT)

#define	READ_1_EVENT			(0x22 + RDMA_EVENT)
#define	READ_11_EVENT			(0x51 + RDMA_EVENT)
#define	READ_111_EVENT			(0x52 + RDMA_EVENT)
#define	READ_TRWD_WAS_EVENT		(0x23 + RDMA_EVENT)
#define	READ_TRWD_WAS_LONG_EVENT	(0x24 + RDMA_EVENT)
#define	READ_TRWD_WAS_TIMEOUT_EVENT	(0x25 + RDMA_EVENT)
#define	READ_BAD1_EVENT			(0x26 + RDMA_EVENT)
#define	READ_BAD2_EVENT			(0x27 + RDMA_EVENT)
#define	READ_BADSIZE_EVENT		(0x28 + RDMA_EVENT)
#define	READ_PMSTAT_EVENT		(0x29 + RDMA_EVENT)
#define	READ_SNDMSGBAD_EVENT		(0x2a + RDMA_EVENT)
#define	READ_SNDNGMSG_EVENT		(0x2b + RDMA_EVENT)
#define	READ_BAD3_EVENT			(0x2c + RDMA_EVENT)
#define	READ_0_EVENT			(0x2d + RDMA_EVENT)
#define	READ_00_EVENT			(0x49 + RDMA_EVENT)
#define	READ_000_EVENT			(0x50 + RDMA_EVENT)
#define	INTR_RGP3M_UNXP_EVENT		(0x2e + RDMA_EVENT)
#define	INTR_RGP1M_UNXP_EVENT		(0x2f + RDMA_EVENT)
#define	INTR_START_EVENT		(0x54 + RDMA_EVENT)
#define	INTR_EXIT_EVENT			(0x55 + RDMA_EVENT)
#define	SNDMSG_PMSTAT_EVENT		(0x30 + RDMA_EVENT)
#define	SNDMSG_BAD_EVENT		(0x31 + RDMA_EVENT)
#define	SNDNGMSG_EVENT			(0x32 + RDMA_EVENT)
#define	INTR_FAIL_SND_SGP3_EVENT	(0x33 + RDMA_EVENT)
#define	INTR_FAIL_SND_SGP1_EVENT	(0x34 + RDMA_EVENT)
#define	WRITE_FAIL_SND_SGP2_EVENT	(0x35 + RDMA_EVENT)
#define	READ_FAIL_SND_SGP0_EVENT	(0x36 + RDMA_EVENT)
#define	MSG_RST_EVENT			(0x39 + RDMA_EVENT)
#define	WRITE_IRQ_COUNT_EVENT		(0x40 + RDMA_EVENT)
#define	READ_IRQ_COUNT1_EVENT		(0x41 + RDMA_EVENT)
#define	READ_IRQ_COUNT2_EVENT		(0x42 + RDMA_EVENT)
#define	WRR_EVENT			(0x37 + RDMA_EVENT)
#define	RDR_EVENT			(0x38 + RDMA_EVENT)
#define	READ_SIGN2_EVENT		(0x56 + RDMA_EVENT)
#define	READ_SIGN1_EVENT		(0x57 + RDMA_EVENT)
#define	INTR_ERR_BAD_BUFFER_EVENT	(0x58 + RDMA_EVENT)
#define	INTR_FAIL_SND_MSG_BAD_BUFFER_EVENT	(0x59 + RDMA_EVENT)
#define	MAIN_FAIL_SND_NEED_BYPASS_EVENT	(0x5a + RDMA_EVENT)
#define	MAIN_FAIL_SND_CS_SL_Msg_EVENT	(0x5b + RDMA_EVENT)
#define	MAIN_FAIL_SND_CS_SUL_Msg_EVENT	(0x5c + RDMA_EVENT)
#define	MAIN_FAIL_SND_CS_SIR_Msg_EVENT	(0x62 + RDMA_EVENT)
#define	INTR_SIGN2_READ_EVENT		(0x5d + RDMA_EVENT)
#define	INTR_UNEXP2_READ_EVENT		(0x5e + RDMA_EVENT)
#define	READ_BAD_SYNHR_EVENT		(0x5f + RDMA_EVENT)
#define	READ_TIMEOUT_EVENT		(0x94 + RDMA_EVENT)
#define	READ_DEF2_EVENT			(0x60 + RDMA_EVENT)
#define	WRITE_DSF_EVENT			(0x61 + RDMA_EVENT)
#define	NET_QUEUE_STOP_EVENT		(0xc0 + RDMA_EVENT)
#define	NET_QUEUE_START_EVENT		(0xc1 + RDMA_EVENT)
#define	INTR_START_NULL_EVENT		(0xc2 + RDMA_EVENT)
#define	NET_QUEUE_FULL_EVENT		(0xc3 + RDMA_EVENT)
#define	NET_QUEUE_REFILL_EVENT		(0xc4 + RDMA_EVENT)
#define	START_CHECK_MEM_EVENT		(0xc5 + RDMA_EVENT)
#define	STOP_CHECK_MEM_EVENT		(0xc6 + RDMA_EVENT)
#define	TRY_SEND_TRWD_EVENT		(0xc7 + RDMA_EVENT)
#define	TRY_SEND_READY_EVENT		(0xc8 + RDMA_EVENT)
#define	MEMCPY_EVENT			(0xc9 + RDMA_EVENT)
#define	SKB_COPY_EVENT			(0xca + RDMA_EVENT)
#define	TIME_TDC_EVENT			(0xcb + RDMA_EVENT)
#define	TIME_RDC_EVENT			(0xcc + RDMA_EVENT)

/* defined in ddi.h
#define	BROAD_TRY_WAKEUP_EVENT	(0x43  + RDMA_EVENT)
#define	BROAD_RUNNING_EVENT	(0x44  + RDMA_EVENT)
#define	WAIT_TRY_SCHTO_EVENT	(0x45  + RDMA_EVENT)
#define	WAIT_RET_SCHTO_EVENT	(0x46  + RDMA_EVENT)
#define	DO_SCHED_EVENT		(0x53  + RDMA_EVENT)
#define	START_HANDLER_IRQ	(0x67  + RDMA_EVENT)
*/

#define	INTR_SIE_EVENT			(0x47 + RDMA_EVENT)
#define	INTR_CMIE_EVENT			(0x48 + RDMA_EVENT)
#define	RDMA_BAD_RDC_EVENT		(0x63 + RDMA_EVENT)

#define	RDMA_INTER1_EVENT		(0x64 + RDMA_EVENT)
#define	RDMA_INTER2_EVENT		(0x65 + RDMA_EVENT)
#define	RDMA_INTER3_EVENT		(0x66 + RDMA_EVENT)
#define	READ_LOSS_EVENT			(0x68 + RDMA_EVENT)

#define	READ_NOT_PROCESS_EVENT		(0x69 + RDMA_EVENT)
#define	READ_NOT_SELF_PROCESS_EVENT	(0x6a + RDMA_EVENT)
#define	READ_WAIT_SELF_PROCESS_EVENT	(0x6b + RDMA_EVENT)
#define	READ_TRY_SIGNAL_PROCESS_EVENT	(0x6c + RDMA_EVENT)
#define	READ_PROCESS_EVENT		(0x6d + RDMA_EVENT)
#define	READ_SELF_PROCESS_EVENT		(0x6e + RDMA_EVENT)
#define	READ_SELF_WAIT_EVENT		(0x6f + RDMA_EVENT)
#define	READ_BAD_WAIT_EVENT		(0x70 + RDMA_EVENT)
#define	READ_TRY_RDMA_EVENT		(0x71 + RDMA_EVENT)
#define	READ_NULL_IRQ_EVENT_EVENT	(0x72 + RDMA_EVENT)
#define	READ_DEF_IRQ_EVENT_EVENT	(0x73 + RDMA_EVENT)
#define	READ_NULLED_SELF_PROCESS_EVENT		(0x74 + RDMA_EVENT)
#define	READ_NULLED_WAIT_SELF_PROCESS_EVENT	(0x75 + RDMA_EVENT)
#define	READ_TRY_SIGNAL_EXIT_EVENT		(0x76 + RDMA_EVENT)
#define	RDMA_1_rdfs		(0x77 + RDMA_EVENT)
#define	RDMA_11_rdfs		(0x78 + RDMA_EVENT)
#define	RDMA_111_rdfs		(0x79 + RDMA_EVENT)
#define	RDMA_0_rdfs		(0x7a + RDMA_EVENT)
#define	RDMA_00_rdfs		(0x7b + RDMA_EVENT)
#define	RDMA_0_OPEN		(0x7c + RDMA_EVENT)
#define	RDMA_00_OPEN		(0x7d + RDMA_EVENT)
#define	RDMA_000_OPEN		(0x7e + RDMA_EVENT)
#define	RDMA_1_OPEN		(0x7f + RDMA_EVENT)
#define	RDMA_1_RDFS		(0x80 + RDMA_EVENT)
#define	RDMA_11_RDFS		(0x81 + RDMA_EVENT)
#define	RDMA_111_RDFS		(0x82 + RDMA_EVENT)
#define	RDMA_0_RDFS		(0x83 + RDMA_EVENT)
#define	RDMA_00_RDFS		(0x84 + RDMA_EVENT)
#define	TRY_EXIT_1_SMC		(0x85 + RDMA_EVENT)
#define	TRY_EXIT_0_SMC		(0x86 + RDMA_EVENT)
#define	TRY_SIGN_1_TRW		(0x87 + RDMA_EVENT)
#define	TRY_SIGN_0_TRW		(0x88 + RDMA_EVENT)
#define	RD_BUS_EVENT			(0x89 + RDMA_EVENT)
#define	WR_BUS_EVENT			(0x90 + RDMA_EVENT)
#define	DMA_BUS_RD_EVENT		(0x91 + RDMA_EVENT)
#define	INTR_RGP0M_UNXP_EVENT		(0x92 + RDMA_EVENT)
#define	DMA_BUS_WR_EVENT		(0x93 + RDMA_EVENT)
#define	RDMA_TEST_YIELD_EVENT		(0x95 + RDMA_EVENT)
#define	READ_BAD_PMSTAT_EVENT		(0x96 + RDMA_EVENT)
#define	READ_LOSS_DMAON_EVENT		(0x97 + RDMA_EVENT)
#define	READ_RET_WAIT_EVENT		(0x98 + RDMA_EVENT)
#define	WRITE_TDMA_On_EVENT		(0x99 + RDMA_EVENT)
#define	WRITE_DMA_TBC_EVENT		(0x9a + RDMA_EVENT)
#define	WRITE_NOTDMA_EVENT		(0x9a + RDMA_EVENT)
#define	READ_RDMA_On_EVENT		(0x9b + RDMA_EVENT)
#define	READ_DMA_RBC_EVENT		(0x9c + RDMA_EVENT)
#define	TX_START_EVENT			(0x9d + RDMA_EVENT)
#define	NETIF_RX_EVENT			(0x9e + RDMA_EVENT)
#define	REBUILD_HEADER_EVENT		(0x9f + RDMA_EVENT)
#define	LVNET_HEADER_EVENT		(0xa0 + RDMA_EVENT)
#define	TX_TIMEOUT_EVENT		(0xa1 + RDMA_EVENT)
#define	DTX_IRQ_COUNT_EVENT		(0xa2 + RDMA_EVENT)
#define	DTX_BAD1_EVENT			(0xa3 + RDMA_EVENT)
#define	DTX_BADWR_EVENT			(0xa4 + RDMA_EVENT)
#define	DTX_SKB_0_EVENT			(0xa5 + RDMA_EVENT)
#define	DRX_BADRD_EVENT			(0xa6 + RDMA_EVENT)
#define	DTX_QUEUE_BUSY_EVENT		(0xa7 + RDMA_EVENT)
#define	NETIF_STOP_QUEUE		(0xa8 + RDMA_EVENT)
#define	NETIF_WAKE_QUEUE		(0xa9 + RDMA_EVENT)
#define	ADD_QUEUE_EVENT			(0xaa + RDMA_EVENT)
#define	DEC_QUEUE_EVENT			(0xab + RDMA_EVENT)
#define	LVNET_TDMA_EVENT		(0xb6 + RDMA_EVENT)
#define	LVNET_OPEN_EVENT		(0xb7 + RDMA_EVENT)
#define	LVNET_STOP_EVENT		(0xb8 + RDMA_EVENT)
#define	LVNET_TX_EVENT			(0xb9 + RDMA_EVENT)
#define	LVNET_TIMEOUT_EVENT		(0xba + RDMA_EVENT)

#define MSG_USER	0x0000ffff	/* Messages for user */
#define MSG_ABONENT	0x70000000
#define SHIFT_ABONENT	28
#define MSG_OPER  	0x80000000	/* Messages OPER */
#define MSG_TRWD	0x80000000	/* Messages TRWD */
#define MSG_READY	0x00000000	/* Messages READY RECEIVER */
#define MSG_NET_RD	0x40000000	/* Messages NET */
#define MSG_HD_RD	0x50000000	/* Messages HD */
#define MSG_NET_WR	0x60000000	/* Messages NET */
#define MSG_HD_WR	0x70000000	/* Messages HD */
#define BROADCAST_RDMA	0x01000000
#define NEXT_RDMA	0x02000000
#define DEST_MASK_RDMA	0x03000000
#define TRANSIT_RDMA	0x03000000
#define SNDRC_MASK_RDMA	0x00030000
#define SND_RDMA	0x00010000
#define REC_RDMA	0x00020000

#define CHANN_NET_RDMA  0x00700000
#define NEXT_RX         0x00100000
#define TCP_TX          0x00200000
#define CAST_RX         0x00300000
#define TRANS_RX        0x00400000
#define NICH_RX         0x00500000

//#define	SIZE_EVENT		0x10000
//#define	MASK_EVENT		0x10001

extern code_msg_t iocerrs[];
extern code_msg_t ioctls[];
extern code_msg_t rwmods[];
extern char * msg_by_code (int code, code_msg_t * v, int len);

struct get_int_ac {
	int	int_ac_rd_0;
	int	int_ac_wr_0;
	int	trwd_was_0;

	int	int_ac_rd_1;
	int	int_ac_wr_1;
	int	trwd_was_1;
};

#define LEN_ERROR 32

#ifdef	__cplusplus
}
#endif

#endif /* __USER_INTF_H__ */
