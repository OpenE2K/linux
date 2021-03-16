

#ifdef __KERNEL__

#include "rdma_user_intf_net.h"
#include "rdma_reg_net.h"
#include "rdma_error_net.h"
#ifdef CONFIG_E90S
#include <asm/e90s.h>
#endif

#define printf printk
unsigned int *evnt;
void prnt_event(struct rdma_event_entry *ree);
unsigned int *evnt;
int init_mem_for_event(void);
void clear_mem_for_event(void);

#else

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include "rdma_user_intf_net.h"
#include "rdma_user_intf_gl_net.h"

#define	MASK_EVENT		0x10001
#define	BROAD_TRY_WAKEUP_EVENT		(0x43  + RDMA_EVENT)
#define	BROAD_RUNNING_EVENT		(0x44  + RDMA_EVENT)
#define	WAIT_TRY_SCHTO_EVENT		(0x45  + RDMA_EVENT)
#define	WAIT_RET_SCHTO_EVENT		(0x46  + RDMA_EVENT)
#define	DO_SCHED_EVENT			(0x53  + RDMA_EVENT)
#define	START_HANDLER_IRQ		(0x67  + RDMA_EVENT)
#define	NEW_SETUP_FRAME_ILL			(0xb1  + 0)
#define	NEW_SETUP_FRAME_SEGV			(0xb2  + 0)
#define	WRITE_TSA_C1_EVENT		(0xae  + RDMA_EVENT)
#define	DTX_TIME_EVENT			(0xaf  + RDMA_EVENT)
#define	DRX_TIME_EVENT			(0xb0  + RDMA_EVENT)
#define	ILLEGAL_INSTR_C1_EVENT		(0xac  + RDMA_EVENT)
#define	SIGSEGV_C1_EVENT		(0xad  + RDMA_EVENT)

unsigned int	evnt[SIZE_EVENT+1];
void prnt_event(struct rdma_event_entry *ree);

int dev_open(char * name)
{
	int fd;

	errno = 0;
	fd = open(name, O_RDWR);
	if (fd < 0) {
		printf("dev_open fail for dev: %s, err=%u: %s\n",
			name, errno, strerror(errno));
		exit(1);
	}
	return (fd);
}

void my_close(int fd)
{
	errno = 0;
	close(fd);
	return;
}
#endif /* KERNEL */

/*
#define	PARSE_E90_E3M	case 0x10:				\
				preg = "IRQ_MC\0";		\
				break;				\
			case 0x14:				\
				preg = "DMA_TCS\0";		\
				parce_tcs(ree->val2, sdvk);	\
				break;				\
			case 0x18:				\
				preg = "DMA_TSA\0";		\
				break;				\
			case 0x1c:				\
				preg = "DMA_TBC\0";		\
				break;				\
			case 0x20:				\
				preg = "DMA_RCS\0";		\
				parce_rcs(ree->val2, sdvk);	\
				break;				\
			case 0x24:				\
				preg = "DMA_RSA\0";		\
				break;				\
			case 0x28:				\
				preg = "DMA_RBC\0";		\
				break;				\
			case 0x2c:				\
				preg = "MSG_CS\0";		\
				parce_msg_cs(ree->val2, sdvk);	\
				break;				\
			case 0x30:				\
				preg = "TDMSG\0";		\
				parce_msg(ree->val2, sdvk);	\
				break;				\
			case 0x34:				\
				preg = "RDMSG\0";		\
				parce_msg(ree->val2, sdvk);	\
				break;				
*/

long flags; 
/*
#define TRY_PRINT						\
		p_ret = s_ret + l_curr;				\
		if (l_ret - l_curr < L_STRING) {		\
			spin_lock_irqsave(&rdma_printk_lock, flags); \
			printf("<1>%s", s_ret);			\
			spin_unlock_irqrestore(&rdma_printk_lock, flags); \
			*s_ret = '\0';				\
			p_ret = s_ret;				\
			l_curr = 0;				\
		}						\
*/


#define TRY_PRINT						\
		p_ret = s_ret + l_curr;				\
		if (l_ret - l_curr < L_STRING) {		\
			printf("<1>%s", s_ret);			\
			*s_ret = '\0';				\
			p_ret = s_ret;				\
			l_curr = 0;				\
		}						\


unsigned char	*s_ret;
char		p_DEFAULT[100];
int		n_print;
int		parce_msg(unsigned int msg, char *p);
char		sdvk[100];
char		*preg;
char		*prw;

char *get_event(int event)
{
	char	*p;

	switch (event) {
	case 0:
		p = NULL;
		break;

	case INTR_TRWD_EVENT:
		p = "INTR_TRWD\t";
		break;
	case INTR_TRWD_UNXP_EVENT:
		p = "INTR_TRWD_UNXP\t";
		break;
	case INTR_READY_EVENT:
		p = "INTR_READY\t";
		break;
	case INTR_TDMA_EVENT:
		p = "INTR_TDMA\t\t";
		break;
	case INTR_SIGN1_READ_EVENT:
		p = "INTR_SIGN1_READ\t";
		break;
	case INTR_RMSG_EVENT:
		p = "INTR_RMSG\t\t";
		break;
	case INTR_RMSG_UNXP_EVENT:
		p = "INTR_RMSG_UNXP\t";
		break;
	case INTR_RDC_EVENT:
		p = "INTR_RDC\t\t";
		break;
	case INTR_TDC_UNXP_EVENT:
		p = "INTR_TDC_UNXP\t";
		break;
	case INTR_TDC_DSF_PD_NULL_EVENT:
		p = "INTR_TDCDSFPDNULL\t";
		break;
	case INTR_DSF_EVENT:
		p = "INTR_DSF\t\t";
		break;
	case INTR_TDC_EVENT:
		p = "INTR_TDC\t\t";
		break;
	case INTR_SIGN1_WRITE_EVENT:
		p = "INTR_SIGN1_WRITE\t";
		break;
	case INTR_RGP3M_EVENT:
		p = "INTR_RGP3M\t";
		break;
	case INTR_RGP2M_EVENT:
		p = "INTR_RGP2M\t";
		break;
	case INTR_RGP1M_EVENT:
		p = "INTR_RGP1M\t";
		break;
	case INTR_SIGN3_READ_EVENT:
		p = "INTR_SIGN3_READ\t";
		break;
	case INTR_RGP0M_EVENT:
		p = "INTR_RGP0M\t";
		break;
	case INTR_SIGN2_WRITE_EVENT:
		p = "INTR_SIGN2_WRITE\t";
		break;
	case INTR_RGP3M_UNXP_EVENT:
		p = "INTR_RGP3M_UNXP\t";
		break;
	case INTR_RGP1M_UNXP_EVENT:
		p = "INTR_RGP1M_UNXP\t";
		break;
	case WRITE_1_EVENT:
		p = "WRITE_1_\t\t";
		break;
	case WRITE_11_EVENT:
		p = "WRITE_11_\t";
		break;
	case WRITE_111_EVENT:
		p = "WRITE_111_\t";
		break;
	case WRITE_PMSTAT_EVENT:
		p = "WRITE_PMSTAT\t";
		break;
	case WRITE_SNDMSGBAD_EVENT:
		p = "WRITE_SNDMSGBAD\t";
		break;
	case WRITE_SNDNGMSG_EVENT:
		p = "WRITE_SNDNGMSG\t";
		break;
	case WRITE_BAD1_EVENT:
		p = "WRITE_BAD1\t";
		break;
	case WRITE_0_EVENT:
		p = "WRITE_0_\t\t";
		break;
	case WRITE_00_EVENT:
		p = "WRITE_00_\t\t";
		break;
	case WRITE_000_EVENT:
		p = "WRITE_000_\t";
		break;
	case WRITE_ISDSF_EVENT:
		p = "WRITE_ISDSF\t";
		break;
	case READ_1_EVENT:
		p = "READ_1_\t\t";
		break;
	case READ_11_EVENT:
		p = "READ_11_\t\t";
		break;
	case READ_111_EVENT:
		p = "READ_111_\t\t";
		break;
	case READ_TRWD_WAS_EVENT:
		p = "READ_TRWD_WAS\t";
		break;
	case READ_TRWD_WAS_LONG_EVENT:
		p = "READ_TRWD_WAS_LONG\t";
		break;
	case READ_TRWD_WAS_TIMEOUT_EVENT:
		p = "READ_TRWD_WAS_TIMEOUT\t";
		break;
	case READ_BAD1_EVENT:
		p = "READ_BAD1\t";
		break;
	case READ_BAD2_EVENT:
		p = "READ_BAD2\t";
		break;
	case READ_BADSIZE_EVENT:
		p = "READ_BADSIZE\t";
		break;
	case READ_PMSTAT_EVENT:
		p = "READ_PMSTAT\t";
		break;
	case READ_SNDMSGBAD_EVENT:
		p = "READ_SNDMSGBAD\t";
		break;
	case READ_SNDNGMSG_EVENT:
		p = "READ_SNDNGMSG\t";
		break;
	case READ_BAD3_EVENT:
		p = "READ_BAD3\t";
		break;
	case SNDMSG_PMSTAT_EVENT:
		p = "SNDMSG_PMSTAT\t";
		break;
	case SNDMSG_BAD_EVENT:
		p = "SNDMSG_BAD\t";
		break;
	case SNDNGMSG_EVENT:
		p = "SNDNGMSG\t\t";
		break;
	case INTR_FAIL_SND_SGP3_EVENT:
		p = "INTR_FAIL_SND_SGP3\t";
		break;
	case INTR_FAIL_SND_SGP1_EVENT:
		p = "INTR_FAIL_SND_SGP1\t";
		break;
	case WRITE_FAIL_SND_SGP2_EVENT:
		p = "WRITE_FAIL_SND_SGP2\t";
		break;
	case READ_FAIL_SND_SGP0_EVENT:
		p = "READ_FAIL_SND_SGP0\t";
		break;
	case WRR_EVENT:
		p = "WRR_EVENT\t\t";
		break;
	case RDR_EVENT:
		p = "RDR_EVENT\t\t";
		break;
	case READ_0_EVENT:
		p = "READ_0_\t\t";
		break;
	case READ_00_EVENT:
		p = "READ_00_\t\t";
		break;
	case READ_000_EVENT:
		p = "READ_000_\t";
		break;
	case MSG_RST_EVENT:
		p = "MSG_RST\t\t";
		break;
	case WRITE_IRQ_COUNT_EVENT:
		p = "WRITE_IRQ_COUNT\t";
		break;
	case READ_IRQ_COUNT1_EVENT:
		p = "READ_IRQ_COUNT1\t";
		break;
	case READ_IRQ_COUNT2_EVENT:
		p = "READ_IRQ_COUNT2\t";
		break;
/*
	case BROAD_TRY_WAKEUP_EVENT:
		p = "BROAD_TRY_WAKEUP\t";
		break;
	case BROAD_RUNNING_EVENT:
		p = "BROAD_RUNNING\t";
		break;
	case WAIT_TRY_SCHTO_EVENT:
		p = "WAIT_TRY_SCHTO\t";
		break;
	case WAIT_RET_SCHTO_EVENT:
		p = "WAIT_RET_SCHTO\t";
		break;
*/
	case INTR_SIE_EVENT:
		p = "INTR_SIE\t\t";
		break;
	case INTR_CMIE_EVENT:
		p = "INTR_CMIE\t";
		break;
/*
	case DO_SCHED_EVENT:
		p = "DO_SCHED_EVENT\t";
		break;
*/
	case INTR_START_EVENT:
		p = "INTR_START\t";
		break;
	case INTR_EXIT_EVENT:
		p = "INTR_EXIT\t";
		break;
	case MAIN_FAIL_SND_CS_SUL_Msg_EVENT:
		p = "FAIL_SND_SUL_Msg\t";
		break;
	case MAIN_FAIL_SND_CS_SL_Msg_EVENT:
		p = "FAIL_SND_SL_Msg\t";
		break;
	case MAIN_FAIL_SND_NEED_BYPASS_EVENT:
		p = "FAIL_SND_NEED_BYPASS\t";
		break;
	case INTR_FAIL_SND_MSG_BAD_BUFFER_EVENT:
		p = "FAIL_SND_MSG_BAD_BUF\t";
		break;
	case INTR_ERR_BAD_BUFFER_EVENT:
		p = "ERR_BAD_BUFFER\t";
		break;
	case READ_SIGN1_EVENT:
		p = "READ_SIGN1\t";
		break;
	case INTR_UNEXP2_READ_EVENT:
		p = "INTR_UNEXP2_READ\t";
		break;
	case READ_BAD_SYNHR_EVENT:
		p = "READ_BAD_SYNHR\t";
		break;
	case READ_DEF2_EVENT:
		p = "READ_DEF2_\t";
		break;
	case WRITE_DSF_EVENT:
		p = "WRITE_DSF_\t";
		break;
	case INTR_SIGN2_READ_EVENT:
		p = "INTR_SIGN2_READ\t";
		break;
	case MAIN_FAIL_SND_CS_SIR_Msg_EVENT:
		p = "MAIN_FAIL_SND_CS_SIR_Msg\t";
		break;
	case RDMA_BAD_RDC_EVENT:
		p = "BAD_RDC_EVENT\t";
		break;
	case RDMA_INTER1_EVENT:
		p = "INTER1_EVENT\t";
		break;
	case RDMA_INTER2_EVENT:
		p = "INTER2_EVENT\t";
		break;
	case RDMA_INTER3_EVENT:
		p = "INTER3_EVENT\t";
		break;
	case READ_LOSS_EVENT:
		p = "READ_LOSS_EVENT\t";
		break;
/*
	case START_HANDLER_IRQ:
		p = "START_HANDLER_IRQ\t";
		break;
*/
	case READ_NOT_PROCESS_EVENT:
		p = "READ_NOT_PROCESS\t";
		break;
	case READ_NOT_SELF_PROCESS_EVENT:
		p = "NOT_SELF_PROCESS\t";
		break;
	case READ_WAIT_SELF_PROCESS_EVENT:
		p = "WAIT_SELF_PROCESS\t";
		break;
	case READ_TRY_SIGNAL_PROCESS_EVENT:
		p = "TRY_SIGNAL_PROCESS\t";
		break;
	case READ_PROCESS_EVENT:
		p = "READ_PROCESS\t";
		break;
	case READ_SELF_PROCESS_EVENT:
		p = "READ_SELF_PROCESS\t";
		break;
	case READ_SELF_WAIT_EVENT:
		p = "READ_SELF_WAIT\t";
		break;
	case READ_BAD_WAIT_EVENT:
		p = "READ_BAD_WAIT\t";
		break;
	case READ_TRY_RDMA_EVENT:
		p = "READ_TRY_RDMA\t";
		break;
	case READ_NULL_IRQ_EVENT_EVENT:
		p = "READ_NULL_IRQ\t";
		break;
	case READ_DEF_IRQ_EVENT_EVENT:
		p = "READ_DEF_IRQ\t";
		break;
	case READ_NULLED_SELF_PROCESS_EVENT:
		p = "NULLED_SELF_PROCESS\t";
		break;
	case READ_NULLED_WAIT_SELF_PROCESS_EVENT:
		p = "NULLED_WAIT_SELF_PROCESS\t";
		break;
	case READ_TRY_SIGNAL_EXIT_EVENT:
		p = "TRY_SIGNAL_EXIT\t";
		break;
	case RDMA_1_rdfs:
		p = "RDMA_1_rdfs\t";
		break;
	case RDMA_11_rdfs:
		p = "RDMA_11_rdfs\t";
		break;
	case RDMA_111_rdfs:
		p = "RDMA_111_rdfs\t";
		break;
	case RDMA_0_rdfs:
		p = "RDMA_0_rdfs\t";
		break;
	case RDMA_00_rdfs:
		p = "RDMA_00_rdfs\t";
		break;
	case RDMA_0_OPEN:
		p = "RDMA_0_OPEN\t";
		break;
	case RDMA_00_OPEN:
		p = "RDMA_00_OPEN\t";
		break;
	case RDMA_000_OPEN:
		p = "RDMA_000_OPEN\t";
		break;
	case RDMA_1_OPEN:
		p = "RDMA_1_OPEN\t";
		break;
	case RDMA_1_RDFS:
		p = "RDMA_1_RDFS\t";
		break;
	case RDMA_11_RDFS:
		p = "RDMA_11_RDFS\t";
		break;
	case RDMA_111_RDFS:
		p = "RDMA_111_RDFS\t";
		break;
	case RDMA_0_RDFS:
		p = "RDMA_0_RDFS\t";
		break;
	case RDMA_00_RDFS:
		p = "RDMA_00_RDFS\t";
		break;
	case TRY_EXIT_1_SMC:
		p = "TRY_EXIT_1_SMC\t";
		break;
	case TRY_EXIT_0_SMC:
		p = "TRY_EXIT_0_SMC\t";
		break;
	case TRY_SIGN_1_TRW:
		p = "TRY_SIGN_1_TRW\t";
		break;
	case TRY_SIGN_0_TRW:
		p = "TRY_SIGN_0_TRW\t";
		break;
	case RD_BUS_EVENT:
		p = "RD_BUS_EVENT\t";
		break;
	case WR_BUS_EVENT:
		p = "WR_BUS_EVENT\t";
		break;
	case DMA_BUS_RD_EVENT:
		p = "DMA_BUS_RD_EVENT\t";
		break;
	case INTR_RGP0M_UNXP_EVENT:
		p = "INTR_RGP0M_UNXP_EVENT\t";
		break;
	case DMA_BUS_WR_EVENT:
		p = "DMA_BUS_WR_EVENT\t";
		break;
	case RDMA_TEST_YIELD_EVENT:
		p = "RDMA_TEST_YIELD\t";
		break;
	case READ_BAD_PMSTAT_EVENT:
		p = "READ_BAD_PMSTAT\t";
		break;
	case READ_TIMEOUT_EVENT:
		p = "READ_TIMEOUT_\t";
		break;
	case READ_RET_WAIT_EVENT:
		p = "READ_RET_WAIT_\t";
		break;
	case WRITE_TDMA_On_EVENT:
		p = "WRITE_TDMA_On_\t";
		break;
	case WRITE_DMA_TBC_EVENT:
		p = "WRITE_DMA_TBC_\t";
		break;
	case READ_RDMA_On_EVENT:
		p = "READ_RDMA_On_\t";
		break;
	case READ_DMA_RBC_EVENT:
		p = "READ_DMA_RBC_\t";
		break;
	case TX_START_EVENT:
		p = "TX_START_EVENT\t";
		break;
	case NETIF_RX_EVENT:
		p = "NETIF_RX_EVENT\t";
		break;
	case REBUILD_HEADER_EVENT:
		p = "REBUILD_HEADER_\t";
		break;
	case LVNET_HEADER_EVENT:
		p = "LVNET_HEADER_\t";
		break;
	case TX_TIMEOUT_EVENT:
		p = "TX_TIMEOUT_\t";
		break;
	case DTX_IRQ_COUNT_EVENT:
		p = "DTX_IRQ_COUNT_\t";
		break;
	case DTX_BAD1_EVENT:
		p = "DTX_BAD1_EVENT\t";
		break;
	case DTX_BADWR_EVENT:
		p = "DTX_BADWR_EVENT\t";
		break;
	case DTX_SKB_0_EVENT:
		p = "DTX_SKB_0_EVENT\t";
		break;
	case DRX_BADRD_EVENT:
		p = "DRX_BADRD_EVENT\t";
		break;
	case READ_SIGN2_EVENT:
		p = "READ_SIGN2_EVENT\t";
		break;
	case DTX_QUEUE_BUSY_EVENT:
		p = "DTX_QUEUE_BUSY\t";
		break;
	case NETIF_STOP_QUEUE:
		p = "NETIF_STOP_QUEUE\t";
		break;
	case NETIF_WAKE_QUEUE:
		p = "NETIF_WAKE_QUEUE\t";
		break;
	case ADD_QUEUE_EVENT:
		p = "ADD_QUEUE_EVENT\t";
		break;
	case DEC_QUEUE_EVENT:
		p = "DEC_QUEUE_EVENT\t";
		break;
	case LVNET_TDMA_EVENT:
		p = "LVNET_TDMA_EVENT\t";
		break;
	case LVNET_OPEN_EVENT:
		p = "LVNET_OPEN_EVENT\t";
		break;
	case LVNET_STOP_EVENT:
		p = "LVNET_STOP_EVENT\t";
		break;
	case LVNET_TX_EVENT:
		p = "LVNET_TX_EVENT\t";
		break;
	case LVNET_TIMEOUT_EVENT:
		p = "LVNET_TIMEOUT_EVENT\t";
		break;
	case NET_QUEUE_STOP_EVENT:
		p = "NET_QUEUE_STOP\t";
		break;
	case NET_QUEUE_START_EVENT:
		p = "NET_QUEUE_START\t";
		break;
	case INTR_START_NULL_EVENT:
		p = "INTR_START_NULL\t";
		break;
	case NET_QUEUE_FULL_EVENT:
		p = "NET_QUEUE_FULL\t";
		break;
	case NET_QUEUE_REFILL_EVENT:
		p = "NET_QUEUE_REFILL\t";
		break;
	case START_CHECK_MEM_EVENT:
		p = "START_CHECK_MEM\t";
		break;
	case STOP_CHECK_MEM_EVENT:
		p = "STOP_CHECK_MEM\t";
		break;
	case TRY_SEND_TRWD_EVENT:
		p = "TRY_SEND_TRWD\t";
		break;
	case TRY_SEND_READY_EVENT:
		p = "TRY_SEND_READY\t";
		break;
	case MEMCPY_EVENT:
		p = "MEMCPY\t";
		break;
	case SKB_COPY_EVENT:
		p = "SKB_COPY\t";
		break;
	case TIME_TDC_EVENT:
		p = "TIME_TDC\t";
		break;
	case TIME_RDC_EVENT:
		p = "TIME_RDC\t";
		break;
	default:
		n_print = sprintf(p_DEFAULT, "0x%x\t", event);
		p_DEFAULT[n_print] = 0;
		p = p_DEFAULT;
	}
	return p;
}

int parce_msg_cs(unsigned int msg_cs, char *p)
{
	if (p == NULL) {
		return 1;
	}
	*p = '\0';
	if (msg_cs & MSG_CS_DMPS_Err) {
		strcat(p, "Stall Error ");
	}
	if (msg_cs & MSG_CS_MPCRC_Err) {
		strcat(p, "CRC Error ");
	}
	if (msg_cs & MSG_CS_MPTO_Err) {
		strcat(p, "Time Out Error ");
	}
	if (msg_cs & MSG_CS_DMPID_Err) {
		strcat(p, "Invalid ID Error ");
	}
	if (msg_cs & MSG_CS_IAMP_Err) {
		strcat(p, "Id_Answer Error ");
	}
	if (msg_cs & MSG_CS_SD_Msg) {
		strcat(p, "Send Data_Message ");
	}
	if ((msg_cs & MSG_CS_SIR_Msg) == MSG_CS_SIR_Msg) {
		strcat(p, "Send ID Request ");
	}
	if ((msg_cs & MSG_CS_SL_Msg) == MSG_CS_SL_Msg) {
		strcat(p, "Send Lock Message ");
	}
	if ((msg_cs & MSG_CS_SUL_Msg) == MSG_CS_SUL_Msg) {
		strcat(p, "Send UnLock Message ");
	}
	if ((msg_cs & MSG_CS_SGP0_Msg) == MSG_CS_SGP0_Msg) {
		strcat(p, "Send GP0 Message ");
	}
	if ((msg_cs & MSG_CS_SGP1_Msg) == MSG_CS_SGP1_Msg) {
		strcat(p, "Send GP1 Message ");
	}
	if ((msg_cs & MSG_CS_SGP2_Msg) == MSG_CS_SGP2_Msg) {
		strcat(p, "Send GP2 Message ");
	}
	if ((msg_cs & MSG_CS_SGP3_Msg) == MSG_CS_SGP3_Msg) {
		strcat(p, "Send GP3 Message ");
	}
	if (msg_cs & MSG_CS_Msg_Rst) {
		strcat(p, "Reset Message ");
	}
	return 0;
}

int parce_es(unsigned int es, char *p)
{
	char rdm[10];

	if (p == NULL) {
		return 1;
	}
	*p = '\0';
	if (es & ES_RDM_Ev) {
		sprintf(rdm, "%s %u ", "RDM", (es & ES_RDMC) >> 27);
		strcat(p, rdm);
	}
	if (es & ES_RGP3M_Ev) {
		strcat(p, "GP3 ");
	}
	if (es & ES_RGP2M_Ev) {
		strcat(p, "GP2 ");
	}
	if (es & ES_RGP1M_Ev) {
		strcat(p, "GP1 ");
	}
	if (es & ES_RGP0M_Ev) {
		strcat(p, "GP0 ");
	}
	if (es & ES_RIAM_Ev) {
		strcat(p, "RIAM ");
	}
	if (es & ES_RIRM_Ev) {
		strcat(p, "RIRM ");
	}
	if (es & ES_RLM_Ev) {
		strcat(p, "RLM ");
	}
	if (es & ES_MSF_Ev) {
		strcat(p, "MSF ");
	}
	if (es & ES_SM_Ev) {
		strcat(p, "SM ");
	}
	if (es & ES_DSF_Ev) {
		strcat(p, "DSF ");
	}
	if (es & ES_TDC_Ev) {
		strcat(p, "TDC ");
	}
	if (es & ES_RDC_Ev) {
		strcat(p, "RDC ");
	}
	if (es & ES_CMIE_Ev) {
		strcat(p, "CMIE ");
	}
	return 0;
}

int parce_msg(unsigned int msg, char *p)
{
	char sabonent[10];
	char soper[10];
	char sdest[10];
	char schann[10];
	char ssndrc[10];
	char slen[10];

	if (p == NULL) {
		return 1;
	}
	switch (msg & MSG_ABONENT) {
	case MSG_NET_WR:
		sprintf(sabonent, "%s", "NET_WR");
		break;
	case MSG_NET_RD:
		sprintf(sabonent, "%s", "NET_RD");
		break;

	default:
		sprintf(sabonent, "abonent: 0x%x", msg & MSG_ABONENT);
	}
	switch (msg & MSG_OPER) {
	case MSG_TRWD:
		sprintf(soper, "%s", "TRWD ");
		break;
	case MSG_READY:
		sprintf(soper, "%s", "READY");
		break;
	default:
		sprintf(soper, "oper: 0x%x", msg & MSG_OPER);
	}
	switch (msg & DEST_MASK_RDMA) {
	case BROADCAST_RDMA:
		sprintf(sdest, "%s", "BROADCAST");
		break;
	case NEXT_RDMA:
		sprintf(sdest, "%s", "NEXT     ");
		break;
	case TRANSIT_RDMA:
		sprintf(sdest, "%s", "TRANSIT  ");
		break;
	default:
		sprintf(sdest, "dest: 0x%x", msg & DEST_MASK_RDMA);
	}
	switch (msg & CHANN_NET_RDMA) {
	case NEXT_RX:
		sprintf(schann, "%s", "NEXT_RX ");
		break;
	case TCP_TX:
		sprintf(schann, "%s", "TCP_TX  ");
		break;
	case CAST_RX:
		sprintf(schann, "%s", "CAST_RX ");
		break;
	case TRANS_RX:
		sprintf(schann, "%s", "TRANS_RX");
		break;
	case NICH_RX:
		sprintf(schann, "%s", "NICH_RX ");
		break;
	default:
		sprintf(schann, "dest: 0x%x", msg & CHANN_NET_RDMA);
	}
	switch (msg & SNDRC_MASK_RDMA) {
	case SND_RDMA:
		sprintf(ssndrc, "%s", "SND");
		break;
	case REC_RDMA:
		sprintf(ssndrc, "%s", "REC");
		break;
	default:
		sprintf(ssndrc, "sndrc: 0x%x", msg & SNDRC_MASK_RDMA);
	}
	sprintf(slen, "len: 0x%x", msg & MSG_USER);
	sprintf(p, "%s %s %s %s %s %s", sabonent, soper, sdest, schann, ssndrc, slen);
	return 0;
}

int parce_tcs(unsigned int tcs, char *p)
{
	if (p == NULL) {
		return 1;
	}
	if (tcs & DMA_TCS_DPS_Err) {
		strcat(p, "Stall Error ");
	}
	if (tcs & DMA_TCS_DPCRC_Err) {
		strcat(p, "CRC Error ");
	}
	if (tcs & DMA_TCS_DPTO_Err) {
		strcat(p, "Time Out Error ");
	}
	if (tcs & DMA_TCS_DPID_Err) {
		strcat(p, "Invalid Destination Error ");
	}
	if (tcs & DMA_TCS_TTM) {
		strcat(p, "Table Mode ");
	}
	if (tcs & DMA_TCS_TDMA_On) {
		strcat(p, "DMA On ");
	}
	if (tcs & DMA_TCS_TALD) {
		strcat(p, "Address Loaded ");
	}
	if (tcs & DMA_TCS_TE) {
		strcat(p, "Transmit Enable ");
	}
	if (tcs & DMA_TCS_TCO) {
		strcat(p, "Coherent DMA ");
	}
	if (tcs & DMA_TCS_Tx_Rst) {
		strcat(p, "Reset Transmitter ");
	}
	return 0;
}

int parce_rcs(unsigned int rcs, char *p)
{
	if (p == NULL) {
		return 1;
	}
	if (rcs & DMA_RCS_RTM) {
		strcat(p, "Table Mode ");
	}
	if (rcs & DMA_RCS_RDMA_On) {
		strcat(p, "DMA On ");
	}
	if (rcs & DMA_RCS_RALD) {
		strcat(p, "Address Loaded ");
	}
	if (rcs & DMA_RCS_RFSM) {
		strcat(p, "Floating Size Mode ");
	}
	if (rcs & DMA_RCS_RE) {
		strcat(p, "Receive Enable ");
	}
	if (rcs & DMA_RCS_RCO) {
		strcat(p, "Coherent DMA ");
	}
	if (rcs & DMA_RCS_Rx_Rst) {
		strcat(p, "Reset Receiver ");
	}
	return 0;
}

int parse_reg(struct rdma_event_entry *ree)
{
	switch (ree->event) {
	case RDR_EVENT:
		prw = "RDR_EVENT";
		break;
	case WRR_EVENT:
		prw = "WRR_EVENT";
		break;
	default:
		prw = NULL;
		return 0;
	}
#ifdef CONFIG_E90
	int	inst = ree->channel;
	switch (ree->val1) {
	case 0x00:
		if (inst == 2)
			preg = "VID\0";
		else
			preg = "DD_ID\0";
		break;
	case 0x04:
		if (inst == 2)
			preg = "CH0_IDT\0";
		else
			preg = "DMD_ID\0";
		break;
	case 0x08:
		if (inst == 2)
			preg = "CS\0";
		else
			preg = "N_IDT\0";
		break;
	case 0x0c:
		if (inst == 2)
			preg = "CH1_IDT\0";
		else {
			preg = "ES\0";
			parce_es(ree->val2, sdvk);
		}
		break;
	case 0x10:
		preg = "IRQ_MC\0";
		break;
	case 0x14:
		preg = "DMA_TCS\0";
		parce_tcs(ree->val2, sdvk);
		break;
	case 0x18:
		preg = "DMA_TSA\0";
		break;
	case 0x1c:
		preg = "DMA_TBC\0";
		break;
	case 0x20:
		preg = "DMA_RCS\0";
		parce_rcs(ree->val2, sdvk);
		break;
	case 0x24:
		preg = "DMA_RSA\0";
		break;
	case 0x28:
		preg = "DMA_RBC\0";
		break;
	case 0x2c:
		preg = "MSG_CS\0";
		parce_msg_cs(ree->val2, sdvk);
		break;
	case 0x30:
		preg = "TDMSG\0";
		parce_msg(ree->val2, sdvk);
		break;
	case 0x34:
		preg = "RDMSG\0";
		parce_msg(ree->val2, sdvk);
		break;
	default:
		preg = "UNKN\0";
	}
#else
	if (HAS_MACHINE_E2K_FULL_SIC)
		switch (ree->val1) {
		case RDMA_VID:
			preg = "VID\0";
			break;
		case RDMA_CH_IDT:
			preg = "CH_IDT\0";
			break;
		case RDMA_CS:
			preg = "CS\0";
			break;
		case RDMA_DD_ID:
			preg = "DD_ID\0";
			break;
		case RDMA_DMD_ID:
			preg = "DMD_ID\0";
			break;
		case RDMA_N_IDT:
			preg = "N_IDT\0";
			break;
		case RDMA_ES:
			preg = "ES\0";
			parce_es(ree->val2, sdvk);
			break;
		case RDMA_IRQ_MC:
			preg = "IRQ_MC\0";
			break;
		case RDMA_DMA_TCS:
			preg = "DMA_TCS\0";
			parce_tcs(ree->val2, sdvk);
			break;
		case RDMA_DMA_TSA:
			preg = "DMA_TSA\0";
			break;
		case RDMA_DMA_HTSA:
			preg = "DMA_HTSA\0";
			break;
		case RDMA_DMA_TBC:
			preg = "DMA_TBC\0";
			break;
		case RDMA_DMA_RCS:
			preg = "DMA_RCS\0";
			parce_rcs(ree->val2, sdvk);
			break;
		case RDMA_DMA_RSA:
			preg = "DMA_RSA\0";
			break;
		case RDMA_DMA_HRSA:
			preg = "DMA_HRSA\0";
			break;
		case RDMA_DMA_RBC:
			preg = "DMA_RBC\0"; 
			break;
		case RDMA_MSG_CS:
			preg = "MSG_CS\0";
			parce_msg_cs(ree->val2, sdvk);
			break;
		case RDMA_TDMSG: preg = "TDMSG\0";
			parce_msg(ree->val2, sdvk);
			break;
		case RDMA_RDMSG:
			preg = "RDMSG\0";
			parce_msg(ree->val2, sdvk);
			break;
		default:
			preg = "UNKN\0";
	} else {
#ifdef CONFIG_E2K
	switch (ree->val1) {
	case 0x00:
		preg = "VID\0";
		break;
	case 0x04:
		preg = "CH0_IDT\0";
		break;
	case 0x08:
		preg = "CS\0";
		break;
	case 0x0c:
		preg = "CH1_IDT\0";
		break;
	case 0x100:
		preg = "DD_ID\0";
		break;
	case 0x104:
		preg = "DMD_ID\0";
		break;
	case 0x108:
		preg = "N_IDT\0";
		break;
	case 0x10c:
		preg = "ES\0";
		parce_es(ree->val2, sdvk);
		break;
	case 0x110:
		preg = "IRQ_MC\0";
		break;
	case 0x114:
		preg = "DMA_TCS\0";
		parce_tcs(ree->val2, sdvk);
		break;
	case 0x118:
		preg = "DMA_TSA\0";
		break;
	case 0x11c:
		preg = "DMA_TBC\0";
		break;
	case 0x120:
		preg = "DMA_RCS\0";
		parce_rcs(ree->val2, sdvk);
		break;
	case 0x24:
		preg = "DMA_RSA\0";
		break;
	case 0x128:
		preg = "DMA_RBC\0";
		break;
	case 0x12c:
		preg = "MSG_CS\0";
		parce_msg_cs(ree->val2, sdvk);
		break;
	case 0x130:
		preg = "TDMSG\0";
		parce_msg(ree->val2, sdvk);
		break;
	case 0x134:
		preg = "RDMSG\0";
		parce_msg(ree->val2, sdvk);
		break;
	default:
		preg = "UNKN\0";
	}

#endif
	}
#endif
	return 1;
}

#define L_STRING 100
int	l_curr = 0;
char	*p_ret;
int	l_ret = SIZE_EVENT/SIZE_ENTRY*L_STRING;



//muw
#ifdef __KERNEL__
int init_mem_for_event(void)
{
	int	order = get_order(l_ret);
	s_ret =(unsigned char *) __get_free_pages(GFP_KERNEL, order);
	if (!s_ret) {
		printf("get_event_rdma: memory alloc l_ret: 0x%x SIZE_EVENT: 0x%x SIZE_ENTRY: 0x%x L_STRING: 0x%x\n",
			l_ret, SIZE_EVENT, SIZE_ENTRY, L_STRING);
		return -1;
	}
	return 0;

}

void clear_mem_for_event(void)
{
	int	order = get_order(l_ret);
	free_pages((unsigned long ) s_ret, order);
}
#endif
//muw

#ifndef __KERNEL__
int get_event_rdma(int fd)
#else
int get_event_rdma(void)
#endif
{
	int	i;
	struct	rdma_event		*re;
	struct	rdma_event_entry	*ree;

#ifndef __KERNEL__
	int	ret, inst;
	char	*p1;
	s_ret = (unsigned char *)malloc(l_ret);
	if (!s_ret) {
		printf("get_event_rdma: memory alloc l_ret: 0x%x SIZE_EVENT: 0x%x SIZE_ENTRY: 0x%x L_STRING: 0x%x\n",
			l_ret, SIZE_EVENT, SIZE_ENTRY, L_STRING);
		return 1;
	}
	*s_ret = '\0';
	p_ret = s_ret;
	ret = ioctl(fd, RDMA_GET_EVENT, &evnt);
	if (ret < 0) {
		printf("RDMA_GET_EVENT_READ: %d: %s\n", ret, strerror(errno));
		return 1;
	}
	l_curr += sprintf(p_ret, "************RDMA_GET_EVENT_READ START curr: %d*****************\n",
		evnt[SIZE_EVENT]/SIZE_ENTRY);
	TRY_PRINT
	sdvk[0] = '\0';
	ree = (struct rdma_event_entry *)&evnt;
	for (i = 0; i < SIZE_EVENT/SIZE_ENTRY; i++, ree++) {
		if (parse_reg(ree)) {
			l_curr += sprintf(p_ret, "0x%08x %08u %s\t\t\t%s\t\t0x%08x %s\n", ree->channel,
				ree->hrtime, prw, preg, ree->val2, sdvk);
			TRY_PRINT
			sdvk[0] = '\0';
			continue;
		}
		p1 = get_event(ree->event);
		if (p1 == NULL) {
			l_curr += sprintf(p_ret, "0x%04x null 0x%08x 0x%08x\n",
				i, ree->event, ree->event - RDMA_EVENT);
			TRY_PRINT
			continue;
		}
		l_curr += sprintf(p_ret, "0x%08x %08u %s\t0x%08x\t0x%08x\n", ree->channel,
			ree->hrtime, p1, ree->val1, ree->val2);
		TRY_PRINT
	}
	sprintf(p_ret, "************RDMA_GET_EVENT_READ FINISH********************************************\n");
	printf("%s", s_ret);
	free(s_ret);
#else
	int	i_end;
	*s_ret = '\0';
	p_ret = s_ret;
	evnt = rdma_event.event;
	l_curr += sprintf(p_ret, "************RDMA_GET_EVENT_READ START curr: %u*****************\n",
		rdma_event.event_cur/SIZE_ENTRY);
	TRY_PRINT
	re = &rdma_event;
	ree = (struct rdma_event_entry *)(&(re->event[re->event_cur]));
	i_end = (SIZE_EVENT - re->event_cur)/SIZE_ENTRY;
	for (i = 0; i < i_end; i++, ree++) {
		prnt_event(ree);
	}
	ree = (struct rdma_event_entry *)(&(re->event[0]));
	i_end = re->event_cur/SIZE_ENTRY;
	for (i = 0; i < i_end; i++, ree++) {
		prnt_event(ree);
	}
	*p_ret = '\0';
	int index = 0;
	while ( s_ret[index] != '\0') {
		printf("%c", s_ret[index]);
		index++;
	}
	printf("\n*************************END**************************\n");
#endif
	return 0;
}

#ifndef __KERNEL__

int main(int argc, char **argv)
{
	char	sin[L_STRING];
	int	fd;

	if (argc == 2) {
		FILE	*fin;
		fin = fopen(argv[1], "r");
		if (fin < 0) {
			printf("fopen(%s): %s\n", argv[1], strerror(errno));
			return 1;
		}
		while (fgets(sin, L_STRING, fin)) {
			printf("%s", sin);
		}
	} else {
		fd = dev_open(argv[1]);
		get_event_rdma(fd);
	}
	return 0;
}
#else
void prnt_event(struct rdma_event_entry *ree)
{
	char	*p1 = NULL;

	sdvk[0] = '\0';
	prw = preg = NULL;
	if (parse_reg(ree)) {
		l_curr += sprintf(p_ret, "0x%08x %08u %s\t0x%08x\t0x%08x\n", ree->channel,
			ree->hrtime, prw, ree->val1, ree->val2);
		TRY_PRINT
		return;
	}
	p1 = get_event(ree->event);
	if (p1) {
		l_curr += sprintf(p_ret, "0x%08x %08u %s\t0x%08x\t0x%08x\n", ree->channel,
			ree->hrtime, p1, ree->val1, ree->val2);
		TRY_PRINT
	}
}
#endif
