#ifndef	__MOKX_IOCC_REGS_H__
#define	__MOKX_IOCC_REGS_H__

/*
 * RDMA reg's IOCC
 */

extern unsigned char	*e0regad;
extern unsigned char	*e1regad;
extern unsigned int	SHIFT_VID;	/* RDMA VID 			*/
extern unsigned int	SHIFT_IOL_CSR;
extern unsigned int	SHIFT_IO_CSR;
extern unsigned int	SHIFT_CH0_IDT;	/* RDMA ID/Type E90/E3M1	*/
extern unsigned int	SHIFT_CH1_IDT;	/* RDMA ID/Type E90/E3M1	*/
extern unsigned int	SHIFT_CH_IDT;	/* RDMA ID/Type E3S/E90S	*/
extern unsigned int	SHIFT_CS;	/* RDMA Control/Status 000028a0	*/
extern unsigned int	SHIFT_DD_ID;	/* Data Destination ID 		*/
extern unsigned int	SHIFT_DMD_ID;	/* Data Message Destination ID 	*/
extern unsigned int	SHIFT_N_IDT;	/* Neighbour ID/Type 		*/
extern unsigned int	SHIFT_ES;	/* Event Status 		*/
extern unsigned int	SHIFT_IRQ_MC;	/* Interrupt Mask Control 	*/
extern unsigned int	SHIFT_DMA_TCS;	/* DMA Tx Control/Status 	*/
extern unsigned int	SHIFT_DMA_TSA;	/* DMA Tx Start Address 	*/
extern unsigned int	SHIFT_DMA_HTSA;	/* DMA Tx Start Address 	*/
extern unsigned int	SHIFT_DMA_TBC;	/* DMA Tx Byte Counter 		*/
extern unsigned int	SHIFT_DMA_RCS;	/* DMA Rx Control/Status 	*/
extern unsigned int	SHIFT_DMA_RSA;	/* DMA Rx Start Address 	*/
extern unsigned int	SHIFT_DMA_HRSA;	/* DMA Rx Start Address 	*/
extern unsigned int	SHIFT_DMA_RBC;	/* DMA Rx Byte Counter 		*/
extern unsigned int	SHIFT_MSG_CS;	/* Messages Control/Status 	*/
extern unsigned int	SHIFT_TDMSG;	/* Tx Data_Messages Buffer 	*/
extern unsigned int	SHIFT_RDMSG;	/* Rx Data_Messages Buffer 	*/
extern unsigned int	SHIFT_CAM;	/* CAM - channel alive management */


#ifdef CONFIG_E2K
#define	IOL_CSR		0x900
#define	IO_VID		0x700
#define	IO_CSR		0x704
#define	RDMA_VID	0x880
#define	RDMA_CH_IDT	0x884
#define	RDMA_CS		0x888
#define	RDMA_DD_ID	0x800
#define	RDMA_DMD_ID	0x804
#define	RDMA_N_IDT	0x808
#define RDMA_ES		0x80c	/* Event Status 		*/
#define RDMA_IRQ_MC	0x810	/* Interrupt Mask Control 	*/
#define RDMA_DMA_TCS	0x814	/* DMA Tx Control/Status 	*/
#define RDMA_DMA_TSA	0x818	/* DMA Tx Start Address 	*/
#define RDMA_DMA_TBC	0x81c	/* DMA Tx Byte Counter 		*/
#define RDMA_DMA_RCS	0x820	/* DMA Rx Control/Status 	*/
#define RDMA_DMA_RSA	0x824	/* DMA Rx Start Address 	*/
#define RDMA_DMA_RBC	0x828	/* DMA Rx Byte Counter 		*/
#define RDMA_MSG_CS	0x82c	/* Messages Control/Status 	*/
#define RDMA_TDMSG	0x830	/* Tx Data_Messages Buffer 	*/
#define RDMA_RDMSG	0x834	/* Rx Data_Messages Buffer 	*/
#define RDMA_CAM	0x838	/* CAM - channel alive management */
#define RDMA_DMA_HTSA	0x858	/* DMA Tx Start Address 	*/
#define RDMA_DMA_HRSA	0x864	/* DMA Tx Start Address		*/
#endif 

#define CS_CH_ON		0x80000000	/* CS:31: Channel is on R/O */
#define CS_Link_tu		0x40000000	/* CS:30: Link is tunning R/O */
#define CS_FCH_ON		0x20000000	/* CS:29: Set CS_CH_ON R/W */
#define CS_DSM			0x00010000	/* CS:16: 1 - 64, 0 - 32. R/W */
#define CS_MOW			0x10000000	/* CS:28: Master Outstanding Write R/O */
#define CS_MOR			0x08000000	/* CS:27: Master Outstanding Read R/O */
#define CS_SRst			0x04000000	/* CS:26: Soft reset -> set CS_Link_tu R/W */
#define CS_SIE     		0x80000000	/* CS:31: Slave Interface Error R/WC */
#define CS_C0_MOW  		0x40000000	/* CS:30: Channel 0: Master Outstanding Write R/O */
#define CS_C0_MOR 		0x20000000	/* CS:29: Channel 0: Master Outstanding Read R/O */
#define CS_C1_MOW    		0x10000000	/* CS:28: Channel 1: Master Outstanding Write R/O */
#define CS_C1_MOR    		0x08000000	/* CS:27: Channel 1: Master Outstanding Read R/O */
#define CS_BUS	     		0x00020000	/* CS:17: BUS Mode R/W */
#define CS_BM        		0x00010000	/* CS:16: Bypass Mode 1 - Bypass, 0 - DMA. RO */
#define CS_C0ILN     		0x0000e000	/* CS:15-13: Channel 0 Interrupt Line Number R/W */
#define CS_C1ILN     		0x00001c00	/* CS:12-10: Channel 1 Interrupt Line Number R/W */
#define CS_PTOCL     		0x000003fe	/* CS:9-1: Packet Time Out Counter Load R/W */
#define CS_BME       		0x00000001	/* CS:0: Bypass Mode Enable R/W */

/*
 * Bits reg CS for e2s
 */
#define E2S_CS_CH_ON		0x80000000	/* CS:31: Channel is on R/O */
#define E2S_CS_Link_tu		0x40000000	/* CS:30: Link is tunning R/O */
#define E2S_CS_LSC		0x20000000	/* CS:29: Change state link signal R/WC */
#define E2S_CS_LSC_Irq_Enable   0x10000000	/* CS:28: Enable IRQ for LSC_Ev R/W */
#define E2S_CS_RESERVED		0x00000000 	/* CS:27: Reserved */
#define E2S_CS_SRst		0x04000000	/* CS:26: Soft reset -> set CS_Link_tu R/W */
#define E2S_CS_RESERVED		0x00000000 	/* CS:25-18: Reserved */
#define E2S_CS_LOOP    		0x00020000 	/* CS:17: Loopback R/W */
#define E2S_CS_DSM   		0x00010000 	/* CS:16: 1 - 64, 0 - 32. R/W */
#define E2S_CS_RESERVED		0x00000000 	/* CS:15-10: Reserved  */
#define E2S_CS_PTOCL     	0x000003fe 	/* CS:9-1: Packet Time Out Counter Load R/W */
#define E2S_CS_RESERVED		0x00000000 	/* CS:0: Reserved */

/*
 * Register Event Status ES 0x07fcfffd 0x3fe000f
 */
#define ES_RDMC		 	0xf8000000	/* ES:31-27: Received Data_Messages Counter RO */
#define ES_RDM_Ev	 	0x04000000	/* ES:26: Received Data_Message Event RO */
#define ES_RGP3M_Ev	  	0x02000000	/* ES:25: Received GP3_Message Event R/WC */
#define ES_RGP2M_Ev	  	0x01000000	/* ES:24: Received GP2_Message Event R/WC */
#define ES_RGP1M_Ev	  	0x00800000	/* ES:23: Received GP1_Message Event R/WC */
#define ES_RGP0M_Ev	  	0x00400000	/* ES:22: Received GP0_Message Event R/WC */
#define ES_RIAM_Ev	  	0x00200000	/* ES:21: Received ID_Answer_Message Event R/WC */
#define ES_RIRM_Ev	  	0x00100000	/* ES:20: Received ID_Request_Message Event R/WC */
#define ES_RULM_Ev	  	0x00080000	/* ES:19: Received UnLock_Message Event R/WC */
#define ES_RLM_Ev	  	0x00040000	/* ES:18: Received Lock_Message Event R/WC */
#define ES_MSF_Ev	  	0x00020000	/* ES:17: Message Send Failed Event R/WC */
#define ES_SM_Ev	  	0x00010000	/* ES:16: Send Message Event R/WC */
#define ES_DSF_Ev	  	0x00000008	/* ES:3: Data Send Failed Event R/WC */
#define ES_TDC_Ev	 	0x00000004	/* ES:2: Transmitter DMA Complete Event R/WC */
#define ES_RDC_Ev	  	0x00000002	/* ES:1: Receiver DMA Complete Event R/WC */
#define ES_CMIE_Ev	  	0x00000001	/* ES:0: Channel Master Interface Error Event R/WC */
#define ES_DEF	          	0x0000fff0	/* ES:15-4: Not usage */
#define ES_ALT	          	0xffff000f	/* ES:15-4: Not usage */
#define ES_SMSG	          	(ES_MSF_Ev | ES_SM_Ev)	/* Send Message */
#define ES_SD	          	(ES_DSF_Ev | ES_TDC_Ev)	/* Send Date */

#define ES_CLEAR_ALL_EVENT	(ES_RDM_Ev	|	\
				ES_RGP3M_Ev	|	\
				ES_RGP2M_Ev	|	\
				ES_RGP1M_Ev	|	\
				ES_RGP0M_Ev	|	\
				ES_RIAM_Ev	|	\
				ES_RIRM_Ev	|	\
				ES_RULM_Ev	|	\
				ES_RLM_Ev	|	\
				ES_DSF_Ev	|	\
				ES_TDC_Ev	|	\
				ES_RDC_Ev	|	\
				ES_CMIE_Ev)

#define	ES_CLEAR_SMF		(ES_DEF		|	\
				ES_SM_Ev	|	\
				ES_MSF_Ev	|	\
				ES_DSF_Ev	|	\
				ES_TDC_Ev	|	\
				ES_RDC_Ev)

/*
 * Register Interrupt Mask Control 0x07fc000d 0x7fc000f 0x5ff000f
 */
#define IRQ_RDM	    		0x04000000	/* IRQ_MC:26: Received Data_Message IRQ Enable R/W */
#define IRQ_RGP3M   		0x02000000 	/* IRQ_MC:25: Received GP3_Message IRQ Enable R/W */
#define IRQ_RGP2M   		0x01000000 	/* IRQ_MC:24: Received GP2_Message IRQ Enable R/W */
#define IRQ_RGP1M   		0x00800000  	/* IRQ_MC:23: Received GP1_Message IRQ Enable R/W */
#define IRQ_RGP0M   		0x00400000	/* IRQ_MC:22: Received GP0_Message IRQ Enable R/W */
#define IRQ_RIAM    		0x00200000   	/* IRQ_MC:21: Received ID_Answer_Message IRQ Enable R/W */
#define IRQ_RIRM    		0x00100000   	/* IRQ_MC:20: Received Request_Message IRQ Enable R/W */
#define IRQ_RULM    		0x00080000   	/* IRQ_MC:19: Received UnLock_Message IRQ Enable R/W */
#define IRQ_RLM	    		0x00040000   	/* IRQ_MC:18: Received Lock_Message IRQ Enable R/W */
#define IRQ_MSF	    		0x00020000   	/* IRQ_MC:17: Message Send Failed IRQ Enable R/W */
#define IRQ_SM	    		0x00010000   	/* IRQ_MC:16: Send Message IRQ Enable R/W */
#define IRQ_DSF	    		0x00000008   	/* IRQ_MC:3:  Data Send Failed IRQ Enable R/W */
#define IRQ_TDC	    		0x00000004   	/* IRQ_MC:2:  Transmitter DMA Complete IRQ Enable R/W */
#define IRQ_RDC	    		0x00000002   	/* IRQ_MC:1:  Receiver DMA Complete IRQ Enable R/W */
#define IRQ_CMIE    		0x00000001   	/* IRQ_MC:0:  Channel Master Interface Error IRQ Enable R/W */
#define IRQ_def     		0xf800fff0   	/* IRQ_MC:    Not usage */
#define IRQ_ALT     		0x07ff000f   	/* IRQ_MC:    Not usage */

/*
 * Register Message Control Registers 0x07fc000d 0x7fc000f 0x5ff000f
 */
#define MSG_CS_DMPS_Err         0x80000000	/* MSG_CS:31: Data_Message Packet Stall Error RO */
#define MSG_CS_MPCRC_Err        0x40000000	/* MSG_CS:30: Message Packet CRC Error RO */
#define MSG_CS_MPTO_Err         0x20000000	/* MSG_CS:29: Message Packet Time Out Error RO */
#define MSG_CS_DMPID_Err        0x10000000	/* MSG_CS:28: Data_Message Packet Invalid ID Error RO */
#define MSG_CS_IAMP_Err         0x08000000	/* MSG_CS:27: Id_Answer_Message Packet Error RO */
#define MSG_CS_SD_Msg           0x04000000	/* MSG_CS:26: Send Data_Message RO */
#define MSG_CS_DMRCL            0x0000fff0	/* MSG_CS:15:4: Data_Message Repeat Counter Load  R/W */
//#define MSG_CS_SIR_Msg          0x00000008	/* MSG_CS:3: Send ID_Request_Message R/W */
#define MSG_CS_SIR_Msg   	0x00000002	/* MSG_CS:1: Send ID Request Message R/W */
#define MSG_CS_SL_Msg     	0x00000004	/* MSG_CS:2: Send Lock Message R/W */
#define MSG_CS_SUL_Msg    	0x00000006	/* MSG_CS:3: Send Unlock Message R/W */
#define MSG_CS_SGP0_Msg     	0x00000008	/* MSG_CS:4: Send GP0 Message R/W */
#define MSG_CS_SGP1_Msg 	0x0000000a	/* MSG_CS:5: Send GP1 Message R/W */
#define MSG_CS_SGP2_Msg  	0x0000000c	/* MSG_CS:6: Send GP2 Message R/W */
#define MSG_CS_SGP3_Msg  	0x0000000e	/* MSG_CS:7: Send GP3 Message R/W */
#define MSG_CS_Msg_Rst  	0x00000001	/* MSG_CS:0: Reset Message Block R/W */
#define MSG_CS_def      	0x0fff0ff0	/* MSG_CS:   Not usage */

#define DMA_RCS_RTM     	0x00040000   	/* DMA_RCS:18: Receive DMA Table Mode R/W */
#define DMA_RCS_RDMA_On        	0x00020000   	/* DMA_RCS:17: Receive DMA On RO */
#define DMA_RCS_RALD           	0x00010000   	/* DMA_RCS:16: Receive Address Loaded RO */
#define DMA_RCS_RFSM           	0x00000008   	/* DMA_RCS:3:  Receive Floating Size Mode R/W */
#define DMA_RCS_RE             	0x00000004   	/* DMA_RCS:2:  Receive Enable R/W */
#define DMA_RCS_RCO            	0x00000002   	/* DMA_RCS:1:  Receive Coherent DMA opration R/W */
#define DMA_RCS_Rx_Rst         	0x00000001   	/* DMA_RCS:0:  Reset Receive R/W */
#define DMA_RCS_def            	0xfffcfff8   	/* DMA_RCS:    Not usage */

#define DMA_TCS_DPS_Err        	0x80000000   	/* DMA_TCS:31: Data Packet Stall Error RO */
#define DMA_TCS_DPCRC_Err      	0x40000000   	/* DMA_TCS:30: Data Packet CRC Error RO */
#define DMA_TCS_DPTO_Err      	0x20000000   	/* DMA_TCS:29: Data Packet Time Out Error RO */
#define DMA_TCS_DPID_Err     	0x10000000   	/* DMA_TCS:28: Data Packet Invalid Destination Error RO */
#define DMA_TCS_TTM        	0x00040000   	/* DMA_TCS:18: Transmit Table Mode R/W */
#define DMA_TCS_TDMA_On      	0x00020000   	/* DMA_TCS:17: Transmit DMA On RO */
#define DMA_TCS_TALD        	0x00010000   	/* DMA_TCS:16: Transmit Address Loaded RO */
#define DMA_TCS_DRCL        	0x0000fff0   	/* DMA_TCS:15:4: Data Repeat Counter Loaded R/W */
#define DMA_TCS_DRCL_w(r,n)    (r & 0xffff0fff | n << 12)   /* DMA_TCS:15-4: Data Repeat Counter Loaded R/W */
#define DMA_TCS_TTM          	0x00040000   	/* DMA_TCS:18: Transmit Tabel Mode R/W */
#define DMA_TCS_TE             	0x00000004   	/* DMA_TCS:2:  Transmit Enable R/W */
#define DMA_TCS_TCO            	0x00000002  	/* DMA_TCS:1:  Transmit Coherent DMA Operation R/W */
#define DMA_TCS_Tx_Rst         	0x00000001   	/* DMA_TCS:0:  Reset Transmitter R/W */
#define DMA_TCS_def            	0x0ffc0ff8   	/* DMA_TCS:    Not usage */

#define TAlive       	  	0x80000000   	/* CAM:31:    Transmit Alive mode */
#define RAlive         		0x40000000   	/* CAM:30:    Receive Alive mode */
#define ATL           		0x3fffffff   	/* CAM:29:0:  ATL Alive Timer Limit 10 mks*/
#define ATL_1         		0x1          	/* CAM:29:0:  ATL Alive Timer Limit 10 mks*/

#define ATL_B             	0xc0000000	/* CAM:29:0:  ATL Alive Timer Limit 10 mks*/
#define TR_ATL_B             	0x00000005
#define TR_ATL            	0xc0000005

#define RCode_32 	0x00000000
#define RCode_64	0x02000000
#define WCode_32 	0x04000000
#define WCode_64 	0x06000000
#define OCode_xx 	0x0ff00000

#endif  /*__MOKX_IOCC_REGS_H__*/
