
char *p_DEFAULT = "default";

char *get_event(int event)
{
	char	*p;
	int	n_print;

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
	case INTR_READY_DMA_EVENT:
		p = "INTR_READY_DMA\t";
		break;
	case INTR_MSG_READY_UNXP_EVENT:
		p = "INTR_MSG_READY_UNXP\t";
		break;
	case INTR_MSG_READY_DMA_UNXP_EVENT:
		p = "INTR_MSG_READY_DMA_UNXP\t";
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
	case SNDMSGOK_EVENT:
		p = "SNDMSGOK\t";
		break;
	case SNDMSGBAD_EVENT:
		p = "SNDMSGBAD\t";
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
	case BROAD_TRY_WAKEUP_EVENT:
		p = "BROAD_TRY_WAKEUP\t";
		break;
	case BROAD_RUNNING_EVENT:
		p = "BROAD_RUNNING\t";
		break;
	case WAIT_TRY_SCHTO_EVENT:
		p = "WAIT_TRY_SCHTO\t";
		break;
	case WAIT_RET_SCHT0_EVENT:
		p = "WAIT_RET_SCHT0\t";
		break;
	case WAIT_RET_SCHT1_EVENT:
		p = "WAIT_RET_SCHT1\t";
		break;
	case WAIT_RET_SCHT2_EVENT:
		p = "WAIT_RET_SCHT2\t";
		break;
	case RDMA_BROADCAST:
		p = "RDMA_BROADCAST\t";
		break;
	case INTR_SIE_EVENT:
		p = "INTR_SIE\t\t";
		break;
	case INTR_CMIE_EVENT:
		p = "INTR_CMIE\t";
		break;
	case INTR_START_EVENT:
		p = "INTR_START_EVENT\t";
		break;
	case INTR_EXIT_EVENT:
		p = "INTR_EXIT_EVENT\t";
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
	case START_HANDLER_IRQ:
		p = "START_HANDLER_IRQ\t";
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
	case INTR_RGP0M_UNXP_EVENT:
		p = "INTR_RGP0M_UNXP_EVENT\t";
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
	case READ_SIGN2_EVENT:
		p = "READ_SIGN2_EVENT\t";
		break;
	case RDMA_INIT:
		p = "RDMA_INIT\t";
		break;
	case RDMA_TEST_STAT:
		p = "RDMA_TEST_STAT\t";
		break;
	case RDMA_INTR:
		p = "RDMA_INTR\t";
		break;
	case INTR_GP0_EVENT:
		p = "INTR_GP0\t";
		break;
	case NO_FREE_BUFF_EVENT:
		p = "NO_FREE_BUFF\t";
		break;
	case RDMA_E_TIMER_IO_EVENT:
		p = "RDMA_E_TIMER_IO\t";
		break;
	default:
		n_print = sprintf(p_DEFAULT, "0x%x\t", event);
		p_DEFAULT[n_print] = 0;
		p = p_DEFAULT;
	}
	return p;
}

void get_event_rdma(int need_lock)
{
	unsigned int		event_cur;
	rdma_addr_struct_t	clkr;
	unsigned long		flags = 0;
	char			*p1, *p2, *preg;


	if (need_lock)
		raw_spin_lock_irqsave(&mu_fix_event, flags);
	printk("************get_event_rdma START*****************************"
		"***************\n");
	if (rdma_event.event_last_get)
		event_cur = rdma_event.event_last_get;
	else
		event_cur = rdma_event.event_cur;
	while (1) {
		clkr.addr = rdma_event.event[event_cur].clkr;
		if (clkr.addr == 0L)
			goto contin;
		switch (rdma_event.event[event_cur].event) {
			case RDMA_INIT:
				p1 = "RDMA_INIT";
				break;
			case RDMA_TEST_STAT:
				p1 = "RDMA_TEST_STAT";
				break;
			case RDMA_INTR:
				p1 = "RDMA_INTR";
				break;
			case RDMA_SEND_MSG:
				p1 = "RDMA_SEND_MSG";
				break;

			default:
				goto not_fun;
		}
		switch (rdma_event.event[event_cur].val1) {
			case START_EVENT:
				p2 = "START_EVENT";
				break;
			case RETURN_EVENT:
				p2 = "RETURN_EVENT";
				break;
			case TRY_SLEEP_EVENT:
				p2 = "TRY_SLEEP";
				break;
			case WAKE_UPPED_EVENT:
				p2 = "WAKE_UPPED";
				break;
			case TIME_OUT_EVENT:
				p2 = "TIME_OUT";
				break;
			case BAD_IRC_COUNT_EVENT:
				p2 = "BAD_IRC_COUNT";
				break;
			case BAD_COUNT_MSG:
				p2 = "BAD_COUNT_MSG";
				break;
			case TRY_WAKE_UP_EVENT:
				p2 = "TRY_WAKE_UP";
				break;
			case E2K_HALT_OK_EVENT:
				p2 = "E2K_HALT_OK";
				break;
			case TEST_SEND_MSG_START:
				p2 = "TEST_SEND_MSG_START";
				break;
			case TEST_SEND_MSG_FINISH:
				p2 = "TEST_SEND_MSG_FINISH";
				break;
			case BIG_COUNT_MSG:
				p2 = "BIG_COUNT_MSG";
				break;
			case TDC_EVENT:
				p2 = "TDC_EVENT";
				break;
			case RDC_EVENT:
				p2 = "RDC_EVENT";
				break;
			case RDM_EVENT:
				p2 = "RDM_EVENT";
				break;
			case RX_TRWD_EVENT:
				p2 = "RX_TRWD_EVENT";
				break;
			case TRY_RDMA_EVENT:
				p2 = "TRY_RDMA_EVENT";
				break;
			case RX_READY_EVENT:
				p2 = "RX_READY_EVENT";
				break;
			case TX_READY_EVENT:
				p2 = "TX_READY_EVENT";
				break;
			case TRY_TDMA_EVENT:
				p2 = "TRY_TDMA_EVENT";
				break;
			case TX_TRWD_EVENT:
				p2 = "TX_TRWD_EVENT";
				break;
			case MSG_CS_ERROR_EVENT:
				p2 = "MSG_CS_ERROR";
				break;
			case ES_ERROR_EVENT:
				p2 = "ES_ERROR";
				break;
			case TCS_ERROR_EVENT:
				p2 = "TCS_ERROR";
				break;
			case TDC_TRY_TDMA0_UNEXPECT_EVENT:
				p2 = "TDC_TRY_TDMA0_UNEXP";
				break;
			case TDC_TXR_FREE_UNEXPECT_EVENT:
				p2 = "TDC_TXR_FREE_UNEXP";
				break;
			case RDC_TRY_RDMA0_UNEXPECT_EVENT:
				p2 = "RDC_TRY_RDMA0_UNEXP";
				break;
			case RDC_RXR_FREE_UNEXPECT_EVENT:
				p2 = "RDC_RXR_FREE_UNEXP";
				break;
			case RDC_TX_READY0_UNEXPECT_EVENT:
				p2 = "RDC_TRDMA_TX_READY0_UNEXP";
				break;
			case RX_TRWD_RX_TRWD_UNEXPECT_EVENT:
				p2 = "RX_TRWD_RX_TRWD_UNEXP";
				break;
			case RX_TRWD_RXR_FREE0_UNEXPECT_EVENT:
				p2 = "RX_TRWD_RXR_FREE0_UNEXP";
				break;
			case RX_TRWD_TRY_RDMA_UNEXPECT_EVENT:
				p2 = "RX_TRWD_TRY_RDMA_UNEXP";
				break;
			case RX_READY_RX_READY_UNEXPECT_EVENT:
				p2 = "RX_READY_RX_READY_UNEXP";
				break;
			case RX_READY_TX_TRWD0_UNEXPECT_EVENT:
				p2 = "RX_READY_TX_TRWD0_UNEXP";
				break;
			case TX_READY_TX_READY_UNEXPECT_EVENT:
				p2 = "TX_READY_TX_READY_UNEXP";
				break;
			case TX_READY_RX_TRWD0_UNEXPECT_EVENT:
				p2 = "TX_READY_RX_TRWD0_UNEXP";
				break;
			case TX_TRWD_TX_TRWD_UNEXPECT_EVENT:
				p2 = "TX_TRWD_TX_TRWD_UNEXP";
				break;
			case TX_TRWD_RX_READY1_UNEXPECT_EVENT:
				p2 = "TX_TRWD_RX_READY1_UNEXP";
				break;
			case TX_TRWD_RX_READY2_UNEXPECT_EVENT:
				p2 = "TX_TRWD_RX_READY2_UNEXP";
				break;
			case TX_TRWD_TRY_TDMA_UNEXPECT_EVENT:
				p2 = "TX_TRWD_TRY_TDMA_UNEXP";
				break;
			case TX_TRWD_TXR_FREE0_UNEXPECT_EVENT:
				p2 = "TX_TRWD_TXR_FREE0_UNEXP";
				break;
			case TRY_TDMA_TRY_TDMA_UNEXPECT_EVENT:
				p2 = "TRY_TDMA_TRY_TDMA_UNEXP";
				break;
			case TRY_TDMA_TXR_FREE0_UNEXPECT_EVENT:
				p2 = "TRY_TDMA_TXR_FREE0_UNEXP";
				break;
			case TRY_TDMA_RX_READY0_UNEXPECT_EVENT:
				p2 = "TRY_TDMA_RX_READY0_UNEXP";
				break;
			case TIME_OUT_TXR_FREE_UNEXPECT_EVENT:
				p2 = "TIME_OUT_TXR_FREE_UNEXP";
				break;
			case TIME_OUT_RXR_FREE_UNEXPECT_EVENT:
				p2 = "TIME_OUT_RXR_FREE_UNEXP";
				break;
			case TIME_OUT_TXR_FREE0_UNEXPECT_EVENT:
				p2 = "TIME_OUT_TXR_FREE0_UNEXP";
				break;
			case TIME_OUT_RXR_FREE0_UNEXPECT_EVENT:
				p2 = "TIME_OUT_RXR_FREE0_UNEXP";
				break;
			case TIME_OUT_RX_TRWD_UNEXPECT_EVENT:
				p2 = "TIME_OUT_RX_TRWD_UNEXP";
				break;
			case TIME_OUT_TX_TRWD_UNEXPECT_EVENT:
				p2 = "TIME_OUT_TX_TRWD_UNEXP";
				break;
			case TIME_OUT_TRY_RDMA_UNEXPECT_EVENT:
				p2 = "TIME_OUT_TRY_RDMA_UNEXP";
				break;
			case TIME_OUT_TRY_TDMA_UNEXPECT_EVENT:
				p2 = "TIME_OUT_TRY_TDMA_UNEXP";
				break;
			case TIME_OUT_RX_READY_UNEXPECT_EVENT:
				p2 = "TIME_OUT_RX_READY_UNEXP";
				break;
			case TIME_OUT_TX_READY_UNEXPECT_EVENT:
				p2 = "TIME_OUT_TX_READY_UNEXP";
				break;

			case TIME_out_TXR_FREE_UNEXPECT_EVENT:
				p2 = "TIME_out_TXR_FREE_UNEXP";
				break;
			case TIME_out_RXR_FREE_UNEXPECT_EVENT:
				p2 = "TIME_out_RXR_FREE_UNEXP";
				break;
			case TIME_out_RX_TRWD_UNEXPECT_EVENT:
				p2 = "TIME_out_RX_TRWD_UNEXP";
				break;
			case TIME_out_TX_TRWD_UNEXPECT_EVENT:
				p2 = "TIME_out_TX_TRWD_UNEXP";
				break;
			case TIME_out_TRY_RDMA_UNEXPECT_EVENT:
				p2 = "TIME_out_TRY_RDMA_UNEXP";
				break;
			case TIME_out_TRY_TDMA_UNEXPECT_EVENT:
				p2 = "TIME_out_TRY_TDMA_UNEXP";
				break;
			case TIME_out_RX_READY_UNEXPECT_EVENT:
				p2 = "TIME_out_RX_READY_UNEXP";
				break;
			case TIME_out_TX_READY_UNEXPECT_EVENT:
				p2 = "TIME_out_TX_READY_UNEXP";
				break;
			case INTR_MSG_READY_UNXP_EVENT:
				p2 = "INTR_MSG_READY_UNXP";
				break;
			case RIRM_EVENT:
				p2 = "RIRM_EVENT";
				break;
			case RIAM_EVENT:
				p2 = "RIAM_EVENT";
				break;
			case SEND_ALL_UNEXPECT_EVENT:
				p2 = "SEND_ALL_UNEXPECT";
				break;
			case MSF_ALL_UNEXPECT_EVENT:
				p2 = "MSF_ALL_UNEXPECT";
				break;
			case DMRCL0_UNEXPECT_EVENT:
				p2 = "DMRCL0_UNEXPECT";
				break;
			case MSF_COUNT_MAX_UNEXPECT_EVENT:
				p2 = "MSF_COUNT_MAX_UNEXPECT";
				break;

			default:
				printk("%u 0x%08x%08x %s\t\t\t0x%08x\t\t0x%08x\n",
					rdma_event.event[event_cur].channel,
					clkr.fields.haddr, clkr.fields.laddr,
					p1, rdma_event.event[event_cur].val1,
					rdma_event.event[event_cur].val2);
				goto contin;
			}
			printk("%u 0x%08x%08x %s\t\t%s\t\t0x%08x\n",
				rdma_event.event[event_cur].channel,
				clkr.fields.haddr, clkr.fields.laddr,
				p1, p2,
				rdma_event.event[event_cur].val2);
			goto contin;
not_fun:
		switch (rdma_event.event[event_cur].event) {
			case RDR_EVENT:
				p1 = "RDR_EVENT";
				break;
			case WRR_EVENT:
				p1 = "WRR_EVENT";
				break;
			default:
				goto not_reg;
		}
		/*
		switch (rdma_event.event[event_cur].val1) {
			case SHIFT_IOL_CSR	: preg = "IOL_CSR\0";	break;
			case SHIFT_IO_CSR	: preg = "IO_CSR\0";	break;
			case SHIFT_IO_VID	: preg = "IO_VID\0";	break;
			case SHIFT_VID		: preg = "VID\0";	break;
			case SHIFT_DD_ID	: preg = "DD_ID\0";	break;
			case SHIFT_CH_IDT	: preg = "CH_IDT\0";	break;
			case SHIFT_DMD_ID	: preg = "DMD_ID\0";	break;
			case SHIFT_CS		: preg = "CS\0";	break;
			case SHIFT_N_IDT	: preg = "N_IDT\0";	break;
			case SHIFT_ES		: preg = "ES\0";	break;
			case SHIFT_IRQ_MC	: preg = "IRQ_MC\0";	break;
			case SHIFT_DMA_TCS	: preg = "DMA_TCS\0";	break;
			case SHIFT_DMA_TSA	: preg = "DMA_TSA\0";	break;
			case SHIFT_DMA_TBC	: preg = "DMA_TBC\0";	break;
			case SHIFT_DMA_RCS	: preg = "DMA_RCS\0";	break;
			case SHIFT_DMA_RSA	: preg = "DMA_RSA\0";	break;
			case SHIFT_DMA_RBC	: preg = "DMA_RBC\0";	break;
			case SHIFT_MSG_CS	: preg = "MSG_CS\0";	break;
			case SHIFT_TDMSG	: preg = "TDMSG\0";	break;
			case SHIFT_RDMSG	: preg = "RDMSG\0";	break;
			case SHIFT_DMA_HTSA	: preg = "DMA_HTSA\0";	break;
			case SHIFT_DMA_HRSA	: preg = "DMA_HRSA\0";	break;
			case SHIFT_CAM		: preg = "CAM\0";	break;
			default			: preg = "UNKN\0";
		}
		*/
		
		if (rdma_event.event[event_cur].val1 == SHIFT_IOL_CSR)
			preg = "IOL_CSR\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_IO_VID)
			preg = "IO_VID\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_DD_ID)
			preg = "DD_ID\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_CH_IDT)
			preg = "CH_IDT\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_DMD_ID)
			preg = "DMD_ID\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_CS)
			preg = "CS\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_N_IDT)
			preg = "N_IDT\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_ES)
			preg = "ES\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_IRQ_MC)
			preg = "IRQ_MC\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_DMA_TCS)
			preg = "DMA_TCS\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_DMA_TSA)
			preg = "DMA_TSA\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_DMA_TBC)
			preg = "DMA_TBC\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_DMA_RCS)
			preg = "DMA_RCS\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_DMA_RSA)
			preg = "DMA_RSA\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_DMA_RBC)
			preg = "DMA_RBC\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_MSG_CS)
			preg = "MSG_CS\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_TDMSG)
			preg = "TDMSG\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_RDMSG)
			preg = "RDMSG\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_DMA_HTSA)
			preg = "DMA_HTSA\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_DMA_HRSA)
			preg = "DMA_HRSA\0";
		else if (rdma_event.event[event_cur].val1 == SHIFT_CAM)
			preg = "CAM\0";	
		else
			preg = "UNKN\0";
		
		printk("%u 0x%08x%08x %s\t\t\t%s\t\t0x%08x\n",
			rdma_event.event[event_cur].channel,
			clkr.fields.haddr, clkr.fields.laddr,
			p1, preg, rdma_event.event[event_cur].val2);
		goto contin;
not_reg:
		p1 = get_event(rdma_event.event[event_cur].event);
		if (p1 == NULL) {
			printk("0x%08x 0x%08x%08x 0x%08x 0x%08x 0x%08x\n",
				rdma_event.event[event_cur].channel,
				clkr.fields.haddr, clkr.fields.laddr,
				rdma_event.event[event_cur].event,
				rdma_event.event[event_cur].val1,
				rdma_event.event[event_cur].val2);
		} else {
			printk("%u 0x%08x%08x %s 0x%08x 0x%08x\n",
				rdma_event.event[event_cur].channel,
				clkr.fields.haddr, clkr.fields.laddr,
				p1, rdma_event.event[event_cur].val1,
				rdma_event.event[event_cur].val2);
		}
contin:
		if (event_cur == (SIZE_EVENT - 1))
			event_cur = 0;
		else
			event_cur += 1;
		if (event_cur == rdma_event.event_cur)
			break;
	}
	printk("************get_event_rdma FINISH**************************"
		"******************\n");
	if (need_lock)
		raw_spin_unlock_irqrestore(&mu_fix_event, flags);
}
