#ifndef	_UAPI__RDMA_USER_INTF_H__
#define	_UAPI__RDMA_USER_INTF_H__

#ifdef	__cplusplus
extern "C" {
#endif

#define NEW_VERSION	0.1
	
#define RCS_EMPTY		0 /* rdma channel empty	*/
#define RCS_ALLOCED_B		1 /* chan res alloc stat bit masks */
#define RCS_ALLOCED		2 /* rdma channel alloced */
#define RCS_MAPPED		3 /* rdma channel mapped */
#define RCS_REQUEST		4 /* rdma channel requested */
#define RDMA_E_ALLOC		6 /* buffer RDMA_IOC_ALLOCB allocation error */
#define RDMA_E_NOBUF		5 /* refused to allocate RDMA_IOC_ALLOCB buffer */

#define RDMA_BUF_EMPTY		0 /* rdma buf empty	*/
#define RDMA_BUF_ALLOCED	1 /* rdma buf allocs	*/
#define RDMA_BUF_MMAP		2 /* rdma buf mmap	*/
	
#define	SIZE_EVENT		0x400
#define	SIZE_EL_TBL64_RDMA	PAGE_SIZE	
#define	SIZE_EL_TBL64_RDMA_USER	0x100000

#define RDMA_IO_FINISHED	0x0100	
#define LOG_BUF_LEN		(16384)	/* This must be a power of two */
#define	ET_LAST_CACHE_LINE	0xf1f2f3f4

/*
 *  IOCTL command codes
 */
#ifdef RDMA_OLD_IOCTL	
#define	RDMA_IOC_PREF			
#else
#define	RDMA_IOC			('R' << 8)
#define	RDMA_IOC_PREF			RDMA_IOC |
#endif
	
#define RDMA_IOC_ALLOCB	    		(RDMA_IOC_PREF 2  )
#define RDMA_IOC_READ	     		(RDMA_IOC_PREF 3  ) 
#define RDMA_IOC_WRITEM	     		(RDMA_IOC_PREF 4  )
#define RDMA_TIMER_FOR_READ  		(RDMA_IOC_PREF 5  )
#define RDMA_TIMER_FOR_WRITE 		(RDMA_IOC_PREF 6  ) 
#define RDMA_IOC_DE 	     		(RDMA_IOC_PREF 7  )
#define RDMA_IOC_DW	     		(RDMA_IOC_PREF 8  )
#define RDMA_IOC_DR	     		(RDMA_IOC_PREF 9  )
#define RDMA_IOC_SETRES			(RDMA_IOC_PREF 10 ) 
#define RDMA_IOC_RETMAIN		(RDMA_IOC_PREF 11 )
#define RDMA_IOC_SETTRBA		(RDMA_IOC_PREF 12 )
#define RDMA_IOC_WRCMD			(RDMA_IOC_PREF 14 )
#define RDMA_IOC_RDR			(RDMA_IOC_PREF 15 )
#define RDMA_IOC_WRR			(RDMA_IOC_PREF 16 )
#define RDMA_IOC_MUT 			(RDMA_IOC_PREF 17 )
#define RDMA_IOC_RSR	    		(RDMA_IOC_PREF 18 )
#define RDMA_IOC_RSR1	    		(RDMA_IOC_PREF 19 )
#define RDMA_IOC_RSR2	    		(RDMA_IOC_PREF 20 )
#define RDMA_IOC_RSR3	    		(RDMA_IOC_PREF 21 )
#define RDMA_IOC_RSR5	    		(RDMA_IOC_PREF 22 )
#define RDMA_IOC_RDALT			(RDMA_IOC_PREF 23 )
#define RDMA_IOC_RSR6	    		(RDMA_IOC_PREF 24 )
#define RDMA_IOC_WTSGNL	    		(RDMA_IOC_PREF 25 )
#define RDMA_IOC_WTSGNL1		(RDMA_IOC_PREF 26 )
#define RDMA_IOC_WTSGNL2		(RDMA_IOC_PREF 27 )
#define RDMA_IOC_IOTIME			(RDMA_IOC_PREF 28 )
#define RDMA_IOC_READM	     		(RDMA_IOC_PREF 29 ) 
#define RDMA_IOC_CH_ALLOCB   		(RDMA_IOC_PREF 30 )
#define RDMA_IOC_PHYS1			(RDMA_IOC_PREF 31 )
#define RDMA_IOC_PHYS2      		(RDMA_IOC_PREF 32 )
#define RDMA_IOC_WRITE	     		(RDMA_IOC_PREF 33 )
#define RDMA_IOC_READ_1	     		(RDMA_IOC_PREF 34 ) 
#define RDMA_IOC_DUMPREG0		(RDMA_IOC_PREF 35 )
#define RDMA_IOC_DUMPREG1		(RDMA_IOC_PREF 36 )
#define RDMA_IOC_LM			(RDMA_IOC_PREF 37 )
#define RDMA_IOC_DWL			(RDMA_IOC_PREF 38 )
#define RDMA_IOC_PRN_STAT		(RDMA_IOC_PREF 39 )
#define RDMA_IOC_DUMP_FUNC		(RDMA_IOC_PREF 40 )
#define RDMA_TEST_PA			(RDMA_IOC_PREF 41 )
#define RDMA_CLEAN_CASH2		(RDMA_IOC_PREF 42 )
#define RDMA_READ_CASH2			(RDMA_IOC_PREF 44 )
#define RDMA_SET_STAT			(RDMA_IOC_PREF 45 )
#define RDMA_GET_STAT			(RDMA_IOC_PREF 47 )
#define RDMA_TIMER_READ      		(RDMA_IOC_PREF 48 ) 
#define RDMA_TIMER_WRITE     		(RDMA_IOC_PREF 49 )
#define RDMA_USECTOHZ			(RDMA_IOC_PREF 50 )
#define RDMA_BP_ENABLE			(RDMA_IOC_PREF 51 )
#define RDMA_IOC_VALLOCB		(RDMA_IOC_PREF 52 ) 
#define RDMA_IOC_ARP			(RDMA_IOC_PREF 53 ) 
#define RDMA_READ_NET			(RDMA_IOC_PREF 54 )
#define RDMA_WRITE_NET			(RDMA_IOC_PREF 55 )
#define RDMA_INIT_NET_RX		(RDMA_IOC_PREF 56 )
#define RDMA_INIT_NET_TX		(RDMA_IOC_PREF 57 )
#define RDMA_GET_LOG_BUF		(RDMA_IOC_PREF 58 )
#define RDMA_INIT_LOG_BUF		(RDMA_IOC_PREF 59 )
#define RDMA_SET_DELTA_READ		(RDMA_IOC_PREF 60 )
#define RDMA_GET_DELTA_READ		(RDMA_IOC_PREF 61 )
#define RDMA_SET_DELTA_WRITE		(RDMA_IOC_PREF 62 )
#define RDMA_GET_DELTA_WRITE		(RDMA_IOC_PREF 63 )
#define RDMA_IOC_GET_TAIL_READ		(RDMA_IOC_PREF 64 )
#define RDMA_IOC_GET_TAIL_WRITE		(RDMA_IOC_PREF 65 )
#define RDMA_GET_EVENT			(RDMA_IOC_PREF 66 )
#define RDMA_FIND_ETALON		(RDMA_IOC_PREF 67 )
#define RDMA_INIT_ALL_MEM		(RDMA_IOC_PREF 68 )
#define RDMA_TEST_ALLOC			(RDMA_IOC_PREF 69 )
#define RDMA_CHECK_CP_CHEREPANOV	(RDMA_IOC_PREF 70 )
#define RDMA_GET_INT_AC			(RDMA_IOC_PREF 71 )
#define RDMA_FIND_ERROR_BUF		(RDMA_IOC_PREF 72 )
#define RDMA_NEED_BYPASS		(RDMA_IOC_PREF 73 )
#define RDMA_UNNEED_BYPASS		(RDMA_IOC_PREF 74 )
#define RDMA_IOC_RDR_GL			(RDMA_IOC_PREF 75 )
#define RDMA_READ_KERNEL		(RDMA_IOC_PREF 76 )
#define RDMA_GETVF_ERROR_BUF		(RDMA_IOC_PREF 77 )
#define RDMA_CLEAN_TDC_COUNT		(RDMA_IOC_PREF 78 )
#define RDMA_CLEAN_RDC_COUNT		(RDMA_IOC_PREF 79 )
#define RDMA_TEST_WRITE_FS		(RDMA_IOC_PREF 80 )
#define RDMA_TEST_READ_FS		(RDMA_IOC_PREF 81 )
#define RDMA_TEST_WRITE_FS_Y		(RDMA_IOC_PREF 83 )
#define RDMA_TEST_READ_FS_Y		(RDMA_IOC_PREF 84 )
#define RDMA_TEST_VA_TO_PA_ASM		(RDMA_IOC_PREF 82 )
#define RDMA_TEST_ALLOC_MEM		(RDMA_IOC_PREF 85 )
#define RDMA_TEST_RDWR_BUS		(RDMA_IOC_PREF 86 )
#define RDMA_TEST_DMA_BUS		(RDMA_IOC_PREF 87 )
#define	RDMA_TEST_YIELD			(RDMA_IOC_PREF 88 )
#define RDMA_IOC_INTR	     		(RDMA_IOC_PREF 89 )
#define	RDMA_DYMP_VIRTUAL		(RDMA_IOC_PREF 90 )
#define	RDMA_SET_ATL			(RDMA_IOC_PREF 91 )
#define	RDMA_SET_TAlive			(RDMA_IOC_PREF 92 )
#define	RDMA_SET_RAlive			(RDMA_IOC_PREF 93 )
#define	RDMA_UNSET_TAlive		(RDMA_IOC_PREF 94 )
#define	RDMA_UNSET_RAlive		(RDMA_IOC_PREF 95 )
#define	GET_STAT_ALIVE			(RDMA_IOC_PREF 96 )
#define	RDMA_IOC_MAKE_DEV		(RDMA_IOC_PREF 97 )
#define	RDMA_GET_CLKR			(RDMA_IOC_PREF 98 )
#define	RDMA_GET_MAX_CLKR		(RDMA_IOC_PREF 99 )
#define	RDMA_GET_CAM			(RDMA_IOC_PREF 100)
#define	RDMA_IS_CAM_YES			(RDMA_IOC_PREF 101)
#define	RDMA_IS_CAM_NO			(RDMA_IOC_PREF 102)
#define RDMA_SET_CAM			(RDMA_IOC_PREF 103)
#define RDMA_UNSET_CAM			(RDMA_IOC_PREF 104)
#define RDMA_IOC_GET_neighbour_map	(RDMA_IOC_PREF 105)
#define RDMA_WAKEUP_WRITER		(RDMA_IOC_PREF 106)
#define RDMA_WAKEUP_READER		(RDMA_IOC_PREF 107)
#define RDMA_IOC_DEBUG			(RDMA_IOC_PREF 108)
#define RDMA_IOC_RDESCALT		(RDMA_IOC_PREF 109) 
#define RDMA_IOC_WAIT	     		(RDMA_IOC_PREF 110) 
#define RDMA_IOC_NOWAIT	     		(RDMA_IOC_PREF 111) 
#define RDMA_IOC_CHECK	     		(RDMA_IOC_PREF 112) 
#define RDMA_IOC_POLL	     		(RDMA_IOC_PREF 113) 
#define RDMA_IOC_GET_ID			(RDMA_IOC_PREF 114)
#define	RDMA_IOC_RESET_DMA		(RDMA_IOC_PREF 115)
#define	RDMA_IOC_SET_MODE_RFSM		(RDMA_IOC_PREF 116)
#define	RDMA_IOC_SET_MODE_EXIT_GP0	(RDMA_IOC_PREF 117)
#define	RDMA_IOC_RESET_TCS		(RDMA_IOC_PREF 118)
#define	RDMA_IOC_RESET_RCS		(RDMA_IOC_PREF 119)
#define	RDMA_IOC_SET_MODE_LOOP		(RDMA_IOC_PREF 120)
#define	RDMA_IOC_RD_BUF			(RDMA_IOC_PREF 121)
#define	RDMA_IOC_WR_BUF			(RDMA_IOC_PREF 122)
#define	RDMA_IOC_GET_RD_BUF		(RDMA_IOC_PREF 123)
#define	RDMA_IOC_GET_WR_BUF		(RDMA_IOC_PREF 124)
#define	RDMA_IOC_PUT_RD_BUF		(RDMA_IOC_PREF 125)
#define	RDMA_IOC_PUT_WR_BUF		(RDMA_IOC_PREF 126)
#define	RDMA_IOC_SET_TIMEOUT_RD		(RDMA_IOC_PREF 127)
#define	RDMA_IOC_SET_TIMEOUT_WR		(RDMA_IOC_PREF 128)
#define	RDMA_IOC_GET_BUF_SIZE		(RDMA_IOC_PREF 129)
#define	RDMA_IOC_GET_BUF_NUM		(RDMA_IOC_PREF 130)

/*
 *  Value's for IOCTL
 */
#define ENABLE_RFSM      0x1
#define DISABLE_RFSM     0x0
#define ENABLE_EXIT_GP0  0x1
#define DISABLE_EXIT_GP0 0x0
#define ENABLE_LOOP      0x1
#define DISABLE_LOOP     0x0
#define NOT_SUPPORTED_LOOP  0x3
#define E2S_CS_LOOP    	 0x00020000 

#define RDMA_BUF_ST_FREE    1	
#define RDMA_BUF_ST_FULL    2	
	
/*
 *  Error's codes
 */
#define RDMA_E_NORMAL 0 
#define RDMA_E_INVOP 1 
#define RDMA_E_INVAL 2 
#define RDMA_E_NOBUF 5 
#define RDMA_E_ALLOC 6 
#define RDMA_E_URGENT 10
#define RDMA_E_PENDING 11
#define RDMA_E_TIMER 12
#define RDMA_IOC_NOTRUN 14
#define RDMA_IOC_DIFCH 15
#define RDMA_DESC_DISABLED 16
#define RDMA_ERREAD 20
#define RDMA_ERWRITE 21
#define RDMA_ERREAD1 30
#define RDMA_E_DMPS 31
#define RDMA_E_MPCRC 32
#define RDMA_E_MPTO 33
#define RDMA_E_SIGNAL 34
#define INTR_E_SIZE 35
#define RDMA_E_SIZE_0 36
#define RDMA_E_SUCCESS 37
#define RDMA_E_MSF_WRD 38
#define RDMA_E_CRSM_WRD 39
#define RDMA_E_MEMOUT 40
#define RDMA_E_SIZE_1 41
#define RDMA_E_SIZE_2 42
#define INTR_CS_MOW 43
#define RDMA_CS_MOW 44
#define RDMA_CS_BM 45
#define RDMA_CS_SIE 46
#define RDMA_E_MISS 48
#define MASK_MOW 49
#define RCS_EN 50
#define RDMA_E_READY 51
#define RDMA_E_TIMER_MAX 52
#define RDMA_ERREAD_1 53
#define RDMA_ERREAD_2 54
#define MASK_MOR 55
#define RDMA_ERREAD_3 56
#define RDMA_E_SIZE 57
#define RDMA_E_SIGNAL_READ_1 58
#define RDMA_E_SIGNAL_READ_2 59
#define RDMA_E_READ_TIMEOUT 60
#define RDMA_ERREAD_4 61
#define RDMA_E_WRITE_TIMEOUT 62
#define READ_E_24 63
#define READ_E_44 64
#define TRWD_E_SIZE 65
#define RDMA_E_MAKE_TM 66
#define WRITE_E_4 67
#define RDMA_E_WRITE_1 68
#define RDMA_E_WRITE_2 69
#define RDMA_E_READ_LOSS 70
#define RDMA_E_SEM_1 71
#define RDMA_E_SPIN 72
#define RDMA_E_RD_1_ERR 73
#define RDMA_E_IRQ_COUNT1 74
#define RDMA_E_SEM 75
#define RDMA_E_TIMER_IO 78
#define RDMA_E_RD1ERR 79
#define RDMA_E_BAD_BUFFER 80
#define RDMA_E_NEED_BYPASS 81
#define RDMA_E_CS_SL_Msg 82
#define RDMA_E_CS_SUL_Msg 83
#define RDMA_E_IRQ_COUNT2 84
#define RDMA_E_CS_SIR_Msg 85
#define RDMA_ERREAD4 95
#define RDMA_CS_MOR 96
#define RDMA_E_REPRD 97
#define RDMA_E_REPWR 98
#define RDMA_E_GP0 99
#define RDMA_E_BAD_SYNHR 100
#define ENV_rdma_write_net 101
#define RDMA_E_GP0_EXIT 102
#define RDMA_E_DMA 103
#define RDMA_E_CLOSE_RECIVER_FILE 104
#define	RDMA_E_NULL_BUFFER 105
#define	RDMA_E_READ_LOOP_NO_OPEN 106
#define	RDMA_E_READ_LOOP_NO_FREE_BUFF 107
#define	RDMA_E_READ_LOOP_BAD_SIZE 108
#define	RDMA_E_WRITE_LOOP_NO_READY_BUF 109

/*
 *  Events codes
 */
#define	RDMA_EVENT				(0)
#define	START_EVENT				(0x1)
#define	RETURN_EVENT				(0x2)
#define	TRY_SLEEP_EVENT				(0x3)
#define	WAKE_UPPED_EVENT			(0x4)
#define	TIME_OUT_EVENT				(0x5)
#define	BAD_IRC_COUNT_EVENT			(0x6)
#define	BAD_COUNT_MSG				(0x7)
#define	TRY_WAKE_UP_EVENT			(0x8)
#define	E2K_HALT_OK_EVENT			(0x9)
#define	TEST_SEND_MSG_START			(0xa)
#define	TEST_SEND_MSG_FINISH			(0xb)
#define	BIG_COUNT_MSG				(0xc)
#define	TDC_EVENT				(0xd)
#define	RDC_EVENT				(0xe)
#define	RDM_EVENT				(0xf)
#define	RX_TRWD_EVENT				(0x10)
#define	TRY_RDMA_EVENT				(0x11)
#define	RX_READY_EVENT				(0x12)
#define	TX_READY_EVENT				(0x13)
#define	TRY_TDMA_EVENT				(0x14)
#define	TX_TRWD_EVENT				(0x15)
#define	MSG_CS_ERROR_EVENT			(0x16)
#define	ES_ERROR_EVENT				(0x17)
#define	TCS_ERROR_EVENT				(0x18)
#define	TDC_TRY_TDMA0_UNEXPECT_EVENT		(0x19)
#define	TDC_TXR_FREE_UNEXPECT_EVENT		(0x1a)
#define	RDC_TRY_RDMA0_UNEXPECT_EVENT		(0x1b)
#define	RDC_RXR_FREE_UNEXPECT_EVENT		(0x1c)
#define	RDC_TX_READY0_UNEXPECT_EVENT		(0x34)
#define	RX_TRWD_RX_TRWD_UNEXPECT_EVENT		(0x1d)
#define	RX_TRWD_RXR_FREE0_UNEXPECT_EVENT	(0x1e)
#define	RX_TRWD_TRY_RDMA_UNEXPECT_EVENT		(0x1f)
#define	RX_READY_RX_READY_UNEXPECT_EVENT	(0x20)
#define	RX_READY_TX_TRWD0_UNEXPECT_EVENT	(0x21)
#define	TX_READY_TX_READY_UNEXPECT_EVENT	(0x22)
#define	TX_READY_RX_TRWD0_UNEXPECT_EVENT	(0x23)
#define	TX_TRWD_TX_TRWD_UNEXPECT_EVENT		(0x24)
#define	TX_TRWD_RX_READY1_UNEXPECT_EVENT	(0x25)
#define	TX_TRWD_RX_READY2_UNEXPECT_EVENT	(0x32)
#define	TX_TRWD_TRY_TDMA_UNEXPECT_EVENT		(0x26)
#define	TX_TRWD_TXR_FREE0_UNEXPECT_EVENT	(0x27)
#define	TRY_TDMA_TRY_TDMA_UNEXPECT_EVENT	(0x28)
#define	TRY_TDMA_TXR_FREE0_UNEXPECT_EVENT	(0x29)
#define	TRY_TDMA_RX_READY0_UNEXPECT_EVENT	(0x33)
#define	TIME_OUT_TXR_FREE_UNEXPECT_EVENT	(0x2a)
#define	TIME_OUT_RXR_FREE_UNEXPECT_EVENT	(0x2b)
#define	TIME_OUT_TXR_FREE0_UNEXPECT_EVENT	(0x3e)
#define	TIME_OUT_RXR_FREE0_UNEXPECT_EVENT	(0x3f)
#define	TIME_OUT_RX_TRWD_UNEXPECT_EVENT		(0x2c)
#define	TIME_OUT_TX_TRWD_UNEXPECT_EVENT		(0x2d)
#define	TIME_OUT_TRY_RDMA_UNEXPECT_EVENT	(0x2e)
#define	TIME_OUT_TRY_TDMA_UNEXPECT_EVENT	(0x2f)
#define	TIME_OUT_RX_READY_UNEXPECT_EVENT	(0x30)
#define	TIME_OUT_TX_READY_UNEXPECT_EVENT	(0x31)
#define	TIME_out_TXR_FREE_UNEXPECT_EVENT	(0x35)
#define	TIME_out_RXR_FREE_UNEXPECT_EVENT	(0x36)
#define	TIME_out_RX_TRWD_UNEXPECT_EVENT		(0x37)
#define	TIME_out_TX_TRWD_UNEXPECT_EVENT		(0x38)
#define	TIME_out_TRY_RDMA_UNEXPECT_EVENT	(0x39)
#define	TIME_out_TRY_TDMA_UNEXPECT_EVENT	(0x3a)
#define	TIME_out_RX_READY_UNEXPECT_EVENT	(0x3b)
#define	TIME_out_TX_READY_UNEXPECT_EVENT	(0x3c)
#define	RIRM_EVENT				(0x40)
#define	RIAM_EVENT				(0x41)
#define	SEND_ALL_UNEXPECT_EVENT			(0x42)
#define	MSF_ALL_UNEXPECT_EVENT			(0x43)
#define	DMRCL0_UNEXPECT_EVENT			(0x44)
#define	MSF_COUNT_MAX_UNEXPECT_EVENT		(0x45)
#define	INTR_TRWD_UNXP_EVENT			(0x9  + RDMA_EVENT)
#define	INTR_TRWD_EVENT				(0xa  + RDMA_EVENT)
#define	INTR_READY_EVENT			(0xb  + RDMA_EVENT)
#define	INTR_TDMA_EVENT				(0xc  + RDMA_EVENT)
#define	INTR_SIGN1_READ_EVENT			(0xd  + RDMA_EVENT)
#define	INTR_RMSG_EVENT				(0xe  + RDMA_EVENT)
#define	INTR_RMSG_UNXP_EVENT			(0xf  + RDMA_EVENT)
#define	INTR_RDC_EVENT				(0x10 + RDMA_EVENT)
#define	INTR_TDC_DSF_PD_NULL_EVENT		(0x11 + RDMA_EVENT)
#define	INTR_DSF_EVENT				(0x12 + RDMA_EVENT)
#define	INTR_TDC_EVENT				(0x13 + RDMA_EVENT)
#define	INTR_TDC_UNXP_EVENT			(0x8  + RDMA_EVENT)
#define	INTR_SIGN1_WRITE_EVENT			(0x14 + RDMA_EVENT)
#define	INTR_RGP3M_EVENT			(0x15 + RDMA_EVENT)
#define	INTR_RGP2M_EVENT			(0x16 + RDMA_EVENT)
#define	INTR_RGP1M_EVENT			(0x17 + RDMA_EVENT)
#define	INTR_SIGN3_READ_EVENT			(0x18 + RDMA_EVENT)
#define	INTR_RGP0M_EVENT			(0x19 + RDMA_EVENT)
#define	INTR_SIGN2_WRITE_EVENT			(0x1a + RDMA_EVENT)
#define	WRITE_1_EVENT				(0x1b + RDMA_EVENT)
#define	WRITE_11_EVENT				(0x4a + RDMA_EVENT)
#define	WRITE_111_EVENT				(0x4b + RDMA_EVENT)
#define	WRITE_PMSTAT_EVENT			(0x1c + RDMA_EVENT)
#define	WRITE_SNDMSGBAD_EVENT			(0x1d + RDMA_EVENT)
#define	WRITE_SNDNGMSG_EVENT			(0x1e + RDMA_EVENT)
#define	WRITE_BAD1_EVENT			(0x1f + RDMA_EVENT)
#define	WRITE_0_EVENT				(0x20 + RDMA_EVENT)
#define	WRITE_00_EVENT				(0x4c + RDMA_EVENT)
#define	WRITE_000_EVENT				(0x4d + RDMA_EVENT)
#define	WRITE_ISDSF_EVENT			(0x21 + RDMA_EVENT)
#define	READ_1_EVENT				(0x22 + RDMA_EVENT)
#define	READ_11_EVENT				(0x51 + RDMA_EVENT)
#define	READ_111_EVENT				(0x52 + RDMA_EVENT)
#define	READ_TRWD_WAS_EVENT			(0x23 + RDMA_EVENT)
#define	READ_TRWD_WAS_LONG_EVENT		(0x24 + RDMA_EVENT)
#define	READ_TRWD_WAS_TIMEOUT_EVENT		(0x25 + RDMA_EVENT)
#define	READ_BAD1_EVENT				(0x26 + RDMA_EVENT)
#define	READ_BAD2_EVENT				(0x27 + RDMA_EVENT)
#define	READ_BADSIZE_EVENT			(0x28 + RDMA_EVENT)
#define	READ_PMSTAT_EVENT			(0x29 + RDMA_EVENT)
#define	READ_SNDMSGBAD_EVENT			(0x2a + RDMA_EVENT)
#define	READ_SNDNGMSG_EVENT			(0x2b + RDMA_EVENT)
#define	READ_BAD3_EVENT				(0x2c + RDMA_EVENT)
#define	READ_0_EVENT				(0x2d + RDMA_EVENT)
#define	READ_00_EVENT				(0x49 + RDMA_EVENT)
#define	READ_000_EVENT				(0x50 + RDMA_EVENT)
#define	INTR_RGP3M_UNXP_EVENT			(0x2e + RDMA_EVENT)
#define	INTR_RGP1M_UNXP_EVENT			(0x2f + RDMA_EVENT)
#define	INTR_START_EVENT			(0x54 + RDMA_EVENT)
#define	INTR_EXIT_EVENT				(0x55 + RDMA_EVENT)
#define	SNDMSG_PMSTAT_EVENT			(0x30 + RDMA_EVENT)
#define	SNDMSG_BAD_EVENT			(0x31 + RDMA_EVENT)
#define	SNDNGMSG_EVENT				(0x32 + RDMA_EVENT)
#define	INTR_FAIL_SND_SGP3_EVENT		(0x33 + RDMA_EVENT)
#define	INTR_FAIL_SND_SGP1_EVENT		(0x34 + RDMA_EVENT)
#define	WRITE_FAIL_SND_SGP2_EVENT		(0x35 + RDMA_EVENT)
#define	READ_FAIL_SND_SGP0_EVENT		(0x36 + RDMA_EVENT)
#define	MSG_RST_EVENT				(0x39 + RDMA_EVENT)
#define	WRITE_IRQ_COUNT_EVENT			(0x40 + RDMA_EVENT)
#define	READ_IRQ_COUNT1_EVENT			(0x41 + RDMA_EVENT)
#define	READ_IRQ_COUNT2_EVENT			(0x42 + RDMA_EVENT)
#define	WRR_EVENT				(0x37 + RDMA_EVENT)
#define	RDR_EVENT				(0x38 + RDMA_EVENT)
#define	READ_SIGN2_EVENT			(0x56 + RDMA_EVENT)
#define	READ_SIGN1_EVENT			(0x57 + RDMA_EVENT)
#define	INTR_ERR_BAD_BUFFER_EVENT		(0x58 + RDMA_EVENT)
#define	INTR_FAIL_SND_MSG_BAD_BUFFER_EVENT	(0x59 + RDMA_EVENT)
#define	MAIN_FAIL_SND_NEED_BYPASS_EVENT		(0x5a + RDMA_EVENT)
#define	MAIN_FAIL_SND_CS_SL_Msg_EVENT		(0x5b + RDMA_EVENT)
#define	MAIN_FAIL_SND_CS_SUL_Msg_EVENT		(0x5c + RDMA_EVENT)
#define	MAIN_FAIL_SND_CS_SIR_Msg_EVENT		(0x62 + RDMA_EVENT)
#define	INTR_SIGN2_READ_EVENT			(0x5d + RDMA_EVENT)
#define	INTR_UNEXP2_READ_EVENT			(0x5e + RDMA_EVENT)
#define	READ_BAD_SYNHR_EVENT			(0x5f + RDMA_EVENT)
#define	READ_TIMEOUT_EVENT			(0x94 + RDMA_EVENT)
#define	READ_DEF2_EVENT				(0x60 + RDMA_EVENT)
#define	WRITE_DSF_EVENT				(0x61 + RDMA_EVENT)
#define	RDMA_SET_ATL_EVENT			(0xab + RDMA_EVENT)
#define	GET_STAT_ALIVE_EVENT			(0xac + RDMA_EVENT)
#define	RDMA_SET_TAlive_EVENT			(0xad + RDMA_EVENT)
#define	RDMA_SET_RAlive_EVENT			(0xae + RDMA_EVENT)
#define	RDMA_UNSET_TAlive_EVENT			(0xaf + RDMA_EVENT)
#define	RDMA_UNSET_RAlive_EVENT			(0xb0 + RDMA_EVENT)
#define	INTR_MSF_EVENT				(0xb1 + RDMA_EVENT)
#define	RDMA_IOC_BROAD				(0xb2 + RDMA_EVENT)
#define	RDMA_IOC_WAITD				(0xb3 + RDMA_EVENT)
#define	INTR_SIE_EVENT				(0x47 + RDMA_EVENT)
#define	INTR_CMIE_EVENT				(0x48 + RDMA_EVENT)
#define	RDMA_BAD_RDC_EVENT			(0x63 + RDMA_EVENT)
#define	INTR_BUS_EVENT				(0xb4 + RDMA_EVENT)
#define	RDMA_INTER1_EVENT			(0x64 + RDMA_EVENT)
#define	RDMA_INTER2_EVENT			(0x65 + RDMA_EVENT)
#define	RDMA_INTER3_EVENT			(0x66 + RDMA_EVENT)
#define	READ_LOSS_EVENT				(0x68 + RDMA_EVENT)
#define	READ_NOT_PROCESS_EVENT			(0x69 + RDMA_EVENT)
#define	READ_NOT_SELF_PROCESS_EVENT		(0x6a + RDMA_EVENT)
#define	READ_WAIT_SELF_PROCESS_EVENT		(0x6b + RDMA_EVENT)
#define	READ_TRY_SIGNAL_PROCESS_EVENT		(0x6c + RDMA_EVENT)
#define	READ_PROCESS_EVENT			(0x6d + RDMA_EVENT)
#define	READ_SELF_PROCESS_EVENT			(0x6e + RDMA_EVENT)
#define	READ_SELF_WAIT_EVENT			(0x6f + RDMA_EVENT)
#define	READ_BAD_WAIT_EVENT			(0x70 + RDMA_EVENT)
#define	READ_TRY_RDMA_EVENT			(0x71 + RDMA_EVENT)
#define	READ_NULL_IRQ_EVENT_EVENT		(0x72 + RDMA_EVENT)
#define	READ_DEF_IRQ_EVENT_EVENT		(0x73 + RDMA_EVENT)
#define	READ_NULLED_SELF_PROCESS_EVENT		(0x74 + RDMA_EVENT)
#define	READ_NULLED_WAIT_SELF_PROCESS_EVENT	(0x75 + RDMA_EVENT)
#define	READ_TRY_SIGNAL_EXIT_EVENT		(0x76 + RDMA_EVENT)
#define	RDMA_1_rdfs				(0x77 + RDMA_EVENT)
#define	RDMA_11_rdfs				(0x78 + RDMA_EVENT)
#define	RDMA_111_rdfs				(0x79 + RDMA_EVENT)
#define	RDMA_0_rdfs				(0x7a + RDMA_EVENT)
#define	RDMA_00_rdfs				(0x7b + RDMA_EVENT)
#define	RDMA_0_OPEN				(0x7c + RDMA_EVENT)
#define	RDMA_00_OPEN				(0x7d + RDMA_EVENT)
#define	RDMA_000_OPEN				(0x7e + RDMA_EVENT)
#define	RDMA_1_OPEN				(0x7f + RDMA_EVENT)
#define	RDMA_1_RDFS				(0x80 + RDMA_EVENT)
#define	RDMA_11_RDFS				(0x81 + RDMA_EVENT)
#define	RDMA_111_RDFS				(0x82 + RDMA_EVENT)
#define	RDMA_0_RDFS				(0x83 + RDMA_EVENT)
#define	RDMA_00_RDFS				(0x84 + RDMA_EVENT)
#define	TRY_EXIT_1_SMC				(0x85 + RDMA_EVENT)
#define	TRY_EXIT_0_SMC				(0x86 + RDMA_EVENT)
#define	TRY_SIGN_1_TRW				(0x87 + RDMA_EVENT)
#define	TRY_SIGN_0_TRW				(0x88 + RDMA_EVENT)
#define	RD_BUS_EVENT				(0x89 + RDMA_EVENT)
#define	WR_BUS_EVENT				(0x90 + RDMA_EVENT)
#define	DMA_BUS_RD_EVENT			(0x91 + RDMA_EVENT)
#define	INTR_RGP0M_UNXP_EVENT			(0x92 + RDMA_EVENT)
#define	DMA_BUS_WR_EVENT			(0x93 + RDMA_EVENT)
#define	RDMA_TEST_YIELD_EVENT			(0x95 + RDMA_EVENT)
#define	READ_BAD_PMSTAT_EVENT			(0x96 + RDMA_EVENT)
#define	READ_LOSS_DMAON_EVENT			(0x97 + RDMA_EVENT)
#define	READ_RET_WAIT_EVENT			(0x98 + RDMA_EVENT)
#define	WRITE_TDMA_On_EVENT			(0x99 + RDMA_EVENT)
#define	WRITE_DMA_TBC_EVENT			(0x9a + RDMA_EVENT)
#define	WRITE_NOTDMA_EVENT			(0x9a + RDMA_EVENT)
#define	READ_RDMA_On_EVENT			(0x9b + RDMA_EVENT)
#define	READ_DMA_RBC_EVENT			(0x9c + RDMA_EVENT)
#define	TX_START_EVENT				(0x9d + RDMA_EVENT)
#define	NETIF_RX_EVENT				(0x9e + RDMA_EVENT)
#define	REBUILD_HEADER_EVENT			(0x9f + RDMA_EVENT)
#define	LVNET_HEADER_EVENT			(0xa0 + RDMA_EVENT)
#define	TX_TIMEOUT_EVENT			(0xa1 + RDMA_EVENT)
#define	DTX_IRQ_COUNT_EVENT			(0xa2 + RDMA_EVENT)
#define	DTX_BAD1_EVENT				(0xa3 + RDMA_EVENT)
#define	DTX_BADWR_EVENT				(0xa4 + RDMA_EVENT)
#define	DTX_SKB_0_EVENT				(0xa5 + RDMA_EVENT)
#define	DRX_BADRD_EVENT				(0xa6 + RDMA_EVENT)
#define	WRR_EVENT				(0x37 + RDMA_EVENT)
#define	RDR_EVENT				(0x38 + RDMA_EVENT)
#define	INTR_RDC_PD_NULL_EVENT			(0xa7 + RDMA_EVENT)
#define	INTR_MSG_READY_UNXP_EVENT		(0xa8 + RDMA_EVENT)
#define	INTR_MSG_TRWD_UNXP_EVENT		(0xa9 + RDMA_EVENT)
#define	INTR_GP3_EVENT				(0xaa + RDMA_EVENT)
#define	INTR_RIRM_EVENT				(0xb2 + RDMA_EVENT)
#define	INTR_RIAM_EVENT				(0xb3 + RDMA_EVENT)
#define	RDMA_GET_CAM_EVENT			(0xb5 + RDMA_EVENT)
#define	RDMA_IS_CAM_YES_EVENT			(0xb6 + RDMA_EVENT)
#define	RDMA_IS_CAM_NO_EVENT			(0xb7 + RDMA_EVENT)
#define RDMA_SET_CAM_EVENT			(0xb8 + RDMA_EVENT)
#define RDMA_UNSET_CAM_EVENT			(0xb9 + RDMA_EVENT)
#define	BROAD_TRY_WAKEUP_EVENT			(0x43  + RDMA_EVENT)
#define	BROAD_RUNNING_EVENT			(0x44  + RDMA_EVENT)
#define	WAIT_TRY_SCHTO_EVENT			(0x45  + RDMA_EVENT)
#define	WAIT_RET_SCHT0_EVENT			(0x46  + RDMA_EVENT)
#define	WAIT_RET_SCHT1_EVENT			(0xbb  + RDMA_EVENT)
#define	WAIT_RET_SCHT2_EVENT			(0xbc  + RDMA_EVENT)
#define	DO_SCHED_EVENT				(0xb4  + RDMA_EVENT)
#define	START_HANDLER_IRQ			(0xb5  + RDMA_EVENT)
/*
 *  New 
 */	
#define	RDMA_INIT				(0xc1  + RDMA_EVENT)
#define	RDMA_TEST_STAT				(0xc2  + RDMA_EVENT)
#define	RDMA_INTR				(0xc3  + RDMA_EVENT)
#define	RDMA_SEND_MSG				(0xc4  + RDMA_EVENT)
#define	RDMA_BROADCAST				(0xc5  + RDMA_EVENT)
#define	INTR_GP0_EVENT				(0xc6  + RDMA_EVENT)
#define	NO_FREE_BUFF_EVENT			(0xc7  + RDMA_EVENT)
#define	RDMA_E_TIMER_IO_EVENT			(0xc8  + RDMA_EVENT)
#define	WRITE_BAD2_EVENT			(0xc9  + RDMA_EVENT)
#define	INTR_READY_DMA_EVENT			(0xd0  + RDMA_EVENT)
#define	INTR_MSG_READY_DMA_UNXP_EVENT		(0xd1  + RDMA_EVENT)
#define	SNDMSGOK_EVENT				(0xd2  + RDMA_EVENT)
#define	SNDMSGBAD_EVENT				(0xd3  + RDMA_EVENT)
#define	CLOSE_RECIVER_FILE_EVENT		(0xd4  + RDMA_EVENT)
#define	READ_SIGN_EVENT				(0xd5  + RDMA_EVENT)

/*
#define	RDMA_TXR_FREE	0x00000001
#define	RDMA_RXR_FREE	0x00000002
#define	RDMA_RX_TRWD	0x00000004
#define	RDMA_TX_TRWD	0x00000008
#define	RDMA_TRY_RDMA	0x00000010
#define	RDMA_TRY_TDMA	0x00000020
#define	RDMA_RX_READY	0x00000040
#define	RDMA_TX_READY	0x00000080
*/

#define MAIN_REZERV_YES		1	/* - main, reserved available */
#define MAIN_REZERV_NOT		2	/* - main, out of reserved */
#define REZERV_MAIN_YES		3	/* - reserved, main available */
#define REZERV_MAIN_NOT		4	/* - undefined state */

typedef unsigned long long 	u_longlong_t;  
typedef long long       	longlong_t;

#ifdef __KERNEL__
extern nodemask_t	node_online_neighbour_map;
#else
u_longlong_t		node_online_neighbour_map;
#endif

struct event_cur {
	u_longlong_t	clkr;
	unsigned int	event;
	unsigned int	channel;
	unsigned int	val1;
	unsigned int	val2;
};

typedef struct	rdma_event {
	struct event_cur event[SIZE_EVENT];
	unsigned	int event_cur;
	unsigned	int event_last_get;
} rdma_event_t;

typedef struct rdma_ioc_parm {
	int	reqlen;		/* size of allocated I/O buffer		*/
	int	acclen;		/* size of requested I/O buffer		*/
	int	err_no;		/* RDMA_E_... exchange error code 	*/
	int	rwmode;		/* ioctl() modification 		*/
	int	msg;
	u_longlong_t	clkr;
	u_longlong_t	clkr1;
} rdma_ioc_parm_t;

typedef struct {
	int size; 
	int buf_num;
} rdma_buf_parm_t;

struct stat_rdma {
	int	trwd_was_timeout;
	u_longlong_t	cur_clock;
	int	send_trwd;
	int	send_ready;
	int	rec_trwd;
	int	rec_ready;
	int	cs_bm;
	int	cs_bus;
	int	cs_sie;
	int	es_cmie;
	int	es_rdm;
	int	es_sm;
	int	es_rdc;
	int	es_dsf;
	int	es_dsf_unxp;
	int	es_tdc;
	int	es_tdc_unxp;
	int	es_dsf_tdc;
	int	es_rlm;
	int	es_rulm;
	int	es_riam;
	int	es_rirm;
	int	es_rgp3;
	int	es_rgp2;
	int	es_rgp1;
	int	es_rgp0;
	int	rdm;
	int	READY;
	int	TRWD;
	int	rdm_UNXP;
	int	rdm_EXP;
	int	bad_synhr;
	int	pd_rd;
	int	bg_wr;
	int	rdc_unxp;
	int	TRWD_UNXP;
	int	trwd_was;
	int	miss_TRWD_2;
	int	miss_TRWD_3;
	int	miss_TRWD_4;
	int	READY_UNXP;
	int	miss_READY_2;
	int	miss_READY_3;
	int	tdc_3_1;
	int	TDMA_On;
	int	rdc_kbyte;
	int	try_RDMA;
	int	try_RDMA_tm;
	int	SYNC_WRITE1;
	int	SYNC_READ1;
	int	Ttbc2;
	int	Rtimeout;
	int	Ttimeout;
	int	count_dsf_err;
	int	msf;
	int	rdma_intr;
	int	dma_tcs_dps_err;
	int	dma_tcs_dpcrc_err;
	int	dma_tcs_dpto_err;
	int	dma_tcs_dpid_err;
	int	try_TDMA;
	int	try_TDMA_tm;
	int	try_TDMA_err;
	int	td_urg;
	int	td_murg;
	int	rd_murg;
	int	Tspin;
	int	T_signal;
	int	R_signal;
	int	send_msg_SM_0;
	int	send_msg_MSF_0;
	int	send_msg_DMRCL_0;
	int	send_msg_SD_Msg_0;
	int	send_msg_CRMAX;
	int	GP0_0;
	int	GP0_1;
	int	GP0_2;
	int	GP0_3;
	int	msf_0;
	int	RDMA_MSF_WRD;
	int	RDMA_CRSM_WRD;
	int	RDMA_MAKE_TM;
	int	tdc_dsf_unxp;
	int	rcs;
	int	tcs;
	int	rbc;
	int	tbc;
	int	rsa;
	int	tsa;
};

typedef struct link_id {
	unsigned int	count_links;
	unsigned int	link_id[64][3];
} link_id_t;

typedef struct reset_link{
	unsigned int	tcs;
	unsigned int	rcs;
	unsigned int	tcs_reset;
	unsigned int	rcs_reset;
} reset_link_t;

#ifndef __KERNEL__
/* 
 * Interfice functions
 */

/**
 * Get mask nodes 
 * @fd: device file handle
 *
 * Returns on success 
 * - node_online_neighbour_map - mask nodes
 * negative on failure:
 * - EINVAL - error copy_from_user or copy_to_user in ioctl()
 */
int rdma_get_nodemask(int fd)
{	
	int ret;
	ret = ioctl(fd, RDMA_IOC_GET_neighbour_map, &node_online_neighbour_map);
	return ret;
}

/**
 * Get size buffer 
 * @fd: device file handle
 *
 * Returns on success 
 * - parm.acclen -  size buffer
 * negative on failure:
 * - EINVAL - error copy_from_user or copy_to_user in ioctl()
 */
int rdma_get_buf_size(int fd)
{
	rdma_ioc_parm_t parm;
	int ret;
		
	memset(&parm, 0, sizeof(rdma_ioc_parm_t));
	if ((ret = ioctl(fd, RDMA_IOC_GET_BUF_SIZE, &parm)) < 0) 
		return ret;
	return parm.acclen;
}

/**
 * Get number buffer 
 * @fd: device file handle
 *
 * Returns on success
 * - parm.acclen - number buffers
 * negative on failure:
 * - EINVAL - error copy_from_user or copy_to_user in ioctl()
 */
int rdma_get_buf_num(int fd)
{
	rdma_ioc_parm_t parm;
	int ret;
	
	memset(&parm, 0, sizeof(rdma_ioc_parm_t));
	if ((ret = ioctl(fd, RDMA_IOC_GET_BUF_NUM, &parm)) < 0) {
		return ret;
	}
	return parm.acclen;
}

/**
 * Get the address of the current buffer
 * @num_buf: number of the current buffer
 * @pool_buf: address pool buf's
 * size_buf_alloc: result rdma_get_buf_size()
 *
 * Returns on success
 * - buf - the address of the current buffer to write 
 */

char * rdma_get_address_buf(int num_buf, char *pool_buf, int size_buf_alloc)
{	
	char *buf;
	buf = pool_buf + (num_buf * size_buf_alloc) / sizeof(char);
	return buf;
}

/**
 * Get current buffer for write 
 * @fd: device file handle
 *
 * Returns on success
 * - parm.acclen - the number of the current buffer to write
 * negative on failure:
 * - EBADF - file open as READER
 * - EBUSY - no free Bufs (free buf list empty)
 * - EINVAL - error copy_from_user or copy_to_user in ioctl()
 */
int rdma_get_write_buf(int fd)
{
	rdma_ioc_parm_t parm;
	int ret;
	
	memset(&parm, 0, sizeof(rdma_ioc_parm_t));
	if ((ret = ioctl(fd, RDMA_IOC_GET_WR_BUF, &parm)) < 0) {
		return ret;
	}
	return parm.acclen;
}

/**
 * Move buffer from ready_list to busy_list and try to transmit
 * @fd: device file handle
 * @parm: param's
 *  - parm->acclen - buffer number;
 *  - parm->reqlen - bytes to transmit
 * Returns the actual number of bytes transferred
 * negative on failure:
 *   errno:      parm.err_no:    
 * - EBADF                           - file open as READER
 * - EMSGSIZE &  RDMA_E_SIZE         - invalid size  
 * - EAGAIN   &  RDMA_E_NULL_BUFFER  - no write-made buffers for writing (O_NONBLOCK) 
 * - ETIME    &  RDMA_E_READ_TIMEOUT - interrupted by a time  
 * - EINTR    &  RDMA_E_SIGNAL       - interrupted by a signal 
 * - EAGAIN   &  RDMA_E_SPIN         - 
 * - EIO      &  RDMA_E_MSF_WRD	     - not send msg(TRWD)		
 * - ETIME    &  RDMA_E_TIMER_IO     - interrupted by a time during dma  
 * - EFAULT   &  RDMA_E_BAD_BUFFER   - cant find write-made buffer
 * - EINVAL                          - error copy_from_user or copy_to_user in ioctl()
 */
int rdma_write(int fd, rdma_ioc_parm_t *parm)
{
	int ret;

	return ioctl(fd, RDMA_IOC_WR_BUF, parm); 
}

/**
 * Put buffer for write 
 * @fd: device file handle
 * @cur_buf: current buffer
 *
 * Returns on success
 * - IOC_SUCCESFULL(0) - ok
 * negative on failure:
 * - EBADF - file open as READER
 *  -EFAULT - not found a buffer to release
 *  -ERANGE - an invalid buffer number
 * - EINVAL - error copy_from_user or copy_to_user in ioctl()
 */
int rdma_put_write_buf(int fd, int cur_buf)
{
	rdma_ioc_parm_t parm;
	int ret = 0;
	
	memset(&parm, 0, sizeof(rdma_ioc_parm_t));
	parm.acclen = cur_buf; 
	if ((ret = ioctl(fd, RDMA_IOC_PUT_WR_BUF, &parm)) < 0) {
		return ret;
	}
	return ret;
}

/**
 * Get buffer from busy_list to reciver
 * @fd: device file handle
 * @parm: param's
 * 	- parm->reqlen - bytes to recive
 * Returns the actual number of bytes received and the current buffer
 * 	- parm->acclen - current buffer
 * 	- parm->reqlen - the actual number of bytes to recive
 * negative on failure:
 *   errno:      parm.err_no:
 * - EBADF                           - file open as WRITER
 * - EMSGSIZE &  RDMA_E_SIZE         - invalid size  
 * - EAGAIN   &  RDMA_E_NULL_BUFFER  - no ready-made buffers for reading (O_NONBLOCK) 
 * - ETIME    &  RDMA_E_READ_TIMEOUT - interrupted by a time  
 * - EINTR    &  RDMA_E_SIGNAL       - interrupted by a signal 
 * - EAGAIN   &  RDMA_E_RD_1_ERR     - 
 * - EFAULT   &  RDMA_E_BAD_BUFFER   - cant find ready-made buffer
 * - ERANGE   &  RDMA_E_BAD_BUFFER   - an invalid buffer number
 * - ERANGE   &  RDMA_E_BAD_BUFFER   - an invalid buffer number
 * - EINVAL 			     - error copy_from_user or copy_to_user in ioctl()
 */
int rdma_read(int fd, rdma_ioc_parm_t *parm)
{
	int ret;
	
	if ((ret = ioctl(fd, RDMA_IOC_RD_BUF, parm)) < 0) {
		return ret;
	}
	return parm->reqlen; 
}

/**
 * Put current buffer for read 
 * @fd: device file handle
 * @cur_buf: current buffer
 *
 * Returns on success
 * - IOC_SUCCESFULL(0) - ok
 * negative on failure:
 *  -EFAULT - not found a buffer to release
 *  -ERANGE - an invalid buffer number
 * - EINVAL - error copy_from_user or copy_to_user in ioctl()
 */

int rdma_put_read_buf(int fd, int cur_buf)
{
	rdma_ioc_parm_t parm;
	int ret = 0;
	
	memset(&parm, 0, sizeof(rdma_ioc_parm_t));
	parm.acclen = cur_buf; 
	if ((ret = ioctl(fd, RDMA_IOC_PUT_RD_BUF, &parm)) < 0) {
		return ret;
	}
	return ret;
}

/**
 * Set timeout
 * @fd: device file handle
 * @timeout: timeout (sek)
 * @r_w: read/write
 *
 * Returns on success
 * - set timeout value
 * negative on failure:
 * - EINVAL - error copy_from_user or copy_to_user in ioctl()
 */
int rdma_set_timeout(int fd, int timeout, int r_w)
{
	rdma_ioc_parm_t parm;
	unsigned int cmd;
	int ret = 0;
	
	memset(&parm, 0, sizeof(rdma_ioc_parm_t));
	cmd = (r_w ? RDMA_IOC_SET_TIMEOUT_WR : RDMA_IOC_SET_TIMEOUT_RD);
	parm.reqlen = timeout; 
	if ((ret = ioctl(fd, cmd, &parm)) < 0) {
		return ret;
	}
	return parm.acclen;
}
#endif

#ifdef	__cplusplus
}
#endif
#endif  /*_UAPI__RDMA_USER_INF_H__*/
