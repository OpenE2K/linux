/*
 * Extented mode
 * Bugs: change cycle on time in wait function
 */

extern void intr_channel(unsigned int es, unsigned int tcs, unsigned int mcs, 
		  unsigned int link, unsigned int msg_ext);


/*
 * Create msg for MOK-X
 * msg_addr -> reg_addr | (RDMA_MOK_X_LOW_REG or RDMA_MOK_X_HIGH_REG)
 * ============================================================================
 */
unsigned int create_message_mok_x(unsigned int msg_type, unsigned int msg_addr,
				  unsigned int msg_data)
{
	return  (msg_type & RDMA_MOK_X_TYPE_MSG_MASK) |
		((msg_addr << MOK_X_SHIFT_ADDR) & RDMA_MOK_X_ADDR_MSG_MASK) |
		(msg_data & RDMA_MOK_X_DATA_MSG_MASK);
}

/*
 *  Transcript msg for MOK-X
 * ============================================================================
 */
void transcript_message_mok_x(unsigned int msg, unsigned int *msg_type,
			      unsigned int *msg_addr, unsigned int *msg_data)
{
	*msg_type = msg & RDMA_MOK_X_TYPE_MSG_MASK;
	*msg_addr = (msg & RDMA_MOK_X_ADDR_MSG_MASK) >> MOK_X_SHIFT_ADDR;
	*msg_data = msg & RDMA_MOK_X_DATA_MSG_MASK;
}

/*
 * Wait answer RDR_*
 * ============================================================================
 */
#define MOK_X_RDR_ANSWER_WAIT_DBG 0
#define MOK_X_RDR_ANSWER_WAIT_DEBUG_MSG(x...)\
		if (MOK_X_RDR_ANSWER_WAIT_DBG) MOK_X_DBG_MSG(x)
#define RDR_ANS_WAIT_DBG MOK_X_RDR_ANSWER_WAIT_DEBUG_MSG

#ifdef SETTING_OVER_INTERRUPT
int RDR_answer_wait(int link, unsigned int msg_type,
                    unsigned int msg_addr, unsigned int *msg_data)
{
        unsigned int answer_msg_type = RDMA_MOK_X_REG_READ;
        unsigned int tmp_msg_type, tmp_msg_addr, tmp_msg_data;
        //unsigned int es;
        int ret = SUCCES_MOK_X;

        switch (msg_type) {
        case RDMA_MOK_X_REG_READ:
                answer_msg_type = RDMA_MOK_X_REG_READ;
                RDR_ANS_WAIT_DBG("%s: link #%d. Message type: "
                                 "RDMA_MOK_X_REG_READ (%x)\n",
                                 __FUNCTION__, link, answer_msg_type);
                break;
        case RDMA_MOK_X_REMOTE_REG_READ:
                answer_msg_type = RDMA_MOK_X_REMOTE_REG_RESPONSE;
                RDR_ANS_WAIT_DBG("%s: link #%d. Message type: "
                                 "RDMA_MOK_X_REMOTE_REG_READ (%x)\n",
                                 __FUNCTION__, link, answer_msg_type);
                break;
        case RDMA_MOK_X_REMOTE_SYSTEM_REG_READ:
                answer_msg_type = RDMA_MOK_X_REMOTE_SYSTEM_REG_RESPONSE;
                RDR_ANS_WAIT_DBG("%s: link #%d. Message type: "
                                 "RDMA_MOK_X_REMOTE_SYSTEM_REG_READ (%x)\n",
                                 __FUNCTION__, link, answer_msg_type);
                break;
        default:
                MOK_X_PLD_DBG_ERROR_MSG("%s: link #%d. Unknown type messages of "
                                    "request(%x)\n", __FUNCTION__, link,
                                    msg_type);
                ret = ERROR_MOK_X_REG_UNKNOWN_TYPE_MSG;
                break;
        }
        if (ret)
                goto exit_RDR_answer_wait;
        ret = ERROR_MOK_X_REG_NULL;
#define EXIT_WAIT_ANSWER 10000
        int wait_answer = 0;
        while(1) {
		unsigned int msg = 0x0;
		if (wait_answer_msg) {
			msg = wait_answer_msg;
			wait_answer_msg = 0x0;
                        RDR_ANS_WAIT_DBG("%s: link #%d. Reg RDMSG: %x\n",
                                         __FUNCTION__, link, msg);
			transcript_message_mok_x(msg, &tmp_msg_type,
                                                         &tmp_msg_addr,
                                                         &tmp_msg_data);
			if (tmp_msg_type == answer_msg_type) {
                                ret = SUCCES_MOK_X;
                                *msg_data = tmp_msg_data;
				goto exit_RDR_answer_wait;
                        }
                }
		udelay(10);
                wait_answer ++;
                if (wait_answer > EXIT_WAIT_ANSWER) {
                        //MOK_X_PLD_DBG_ERROR_MSG("%s: link #%d. Timeout: %d "
                        RDR_ANS_WAIT_DBG("%s: link #%d. Timeout: %d "
                                         "wait answer.\n",
                                         __FUNCTION__, link, wait_answer);
                        goto exit_RDR_answer_wait;
                }
        }
exit_RDR_answer_wait:
        //RDR_ANS_WAIT_DBG("%s: link #%d. Reg ES: %x\n", __FUNCTION__, link,
        //                 RDR_rdma(SHIFT_ES, link));
        return ret;
}
#else
int RDR_answer_wait(int link, unsigned int msg_type,
		    unsigned int msg_addr, unsigned int *msg_data)
{
	unsigned int answer_msg_type = RDMA_MOK_X_REG_READ;
	unsigned int tmp_msg_type, tmp_msg_addr, tmp_msg_data;
	unsigned int es;
	int ret = SUCCES_MOK_X;

	switch (msg_type) {
	case RDMA_MOK_X_REG_READ:
		answer_msg_type = RDMA_MOK_X_REG_READ;
		RDR_ANS_WAIT_DBG("%s: link #%d. Message type: "
				 "RDMA_MOK_X_REG_READ (%x)\n",
				 __FUNCTION__, link, answer_msg_type);
		break;
	case RDMA_MOK_X_REMOTE_REG_READ:
		answer_msg_type = RDMA_MOK_X_REMOTE_REG_RESPONSE;
		RDR_ANS_WAIT_DBG("%s: link #%d. Message type: "
				 "RDMA_MOK_X_REMOTE_REG_READ (%x)\n",
				 __FUNCTION__, link, answer_msg_type);
		break;
	case RDMA_MOK_X_REMOTE_SYSTEM_REG_READ:
		answer_msg_type = RDMA_MOK_X_REMOTE_SYSTEM_REG_RESPONSE;
		RDR_ANS_WAIT_DBG("%s: link #%d. Message type: "
				 "RDMA_MOK_X_REMOTE_SYSTEM_REG_READ (%x)\n",
				 __FUNCTION__, link, answer_msg_type);
		break;
	default:
		MOK_X_PLD_DBG_ERROR_MSG("%s: link #%d. Unknown type messages of "
				    "request(%x)\n", __FUNCTION__, link,
				    msg_type);
		ret = ERROR_MOK_X_REG_UNKNOWN_TYPE_MSG;
		break;
	}
	if (ret)
		goto exit_RDR_answer_wait;
	ret = ERROR_MOK_X_REG_NULL;
#define EXIT_WAIT_ANSWER 1000000
	int wait_answer = 0;
	while(1) {
		es = RDR_rdma(SHIFT_ES, link);
		if (es & ES_RDM_Ev) {
			int rdmc = (es & ES_RDMC) >> 27;
			unsigned int msg;

			RDR_ANS_WAIT_DBG("%s: link #%d. rdmc: %x\n",
					 __FUNCTION__, link, rdmc);
			if (rdmc == 0)
				rdmc = 32;
			while (rdmc--) {
				msg = RDR_rdma(SHIFT_RDMSG, link);
#ifdef SET_ENABLE_RECEIVE_BIT
				if (msg & 0xf0000000) {
					intr_channel(ES_RDM_Ev, 0x0, 0x0, link, msg);
					printk("intr_channel: 0x%x\n", msg);
					continue;
				}
#endif
				RDR_ANS_WAIT_DBG("%s: link #%d. Reg RDMSG: %x\n",
						 __FUNCTION__, link, msg);
				transcript_message_mok_x(msg, &tmp_msg_type,
							 &tmp_msg_addr,
							 &tmp_msg_data);
				if (tmp_msg_type == answer_msg_type) {
					ret = SUCCES_MOK_X;
					*msg_data = tmp_msg_data;
				}
			}
			goto exit_RDR_answer_wait;
		}
		wait_answer ++;
		if (wait_answer > EXIT_WAIT_ANSWER) {
			MOK_X_PLD_DBG_ERROR_MSG("%s: link #%d. Timeout: %d "
						"wait answer.\n",
						__FUNCTION__, link, wait_answer);
			goto exit_RDR_answer_wait;
		}
	}
exit_RDR_answer_wait:
	RDR_ANS_WAIT_DBG("%s: link #%d. Reg ES: %x\n", __FUNCTION__, link,
			 RDR_rdma(SHIFT_ES, link));
	return ret;
}
#endif


/*
 *  Read MOK-X registers
 * ============================================================================
 */
#define MOK_X_RDR_DBG 0
#define MOK_X_RDR_DEBUG_MSG(x...)\
		if (MOK_X_RDR_DBG) MOK_X_DBG_MSG(x)
int RDR_mok_x(int link, unsigned int msg_type, unsigned int reg,
	      unsigned int *data)
{
	unsigned int cmd = 0;
	unsigned int msg;
	int ret = SUCCES_MOK_X, ret_send;

#if 1
	switch (msg_type) {
	case RDMA_MOK_X_REG_READ:
		MOK_X_RDR_DEBUG_MSG("%s: link #%d. Message type: "
				    "RDMA_MOK_X_REG_READ (%x)\n",
				    __FUNCTION__, link, msg_type);
		break;
	case RDMA_MOK_X_REMOTE_REG_READ:
		MOK_X_RDR_DEBUG_MSG("%s: link #%d. Message type: "
				    "RDMA_MOK_X_REMOTE_REG_READ (%x)\n",
				    __FUNCTION__, link, msg_type);
		break;
	case RDMA_MOK_X_REMOTE_SYSTEM_REG_READ:
		MOK_X_RDR_DEBUG_MSG("%s: link #%d. Message type: "
				    "RDMA_MOK_X_REMOTE_SYSTEM_REG_READ (%x)\n",
				    __FUNCTION__, link, msg_type);
		break;
	default:
		MOK_X_RDR_DEBUG_MSG("%s: link #%d. Unknown type messages of "
					"request(%x)\n", __FUNCTION__, link,
					msg_type);
		ret = ERROR_MOK_X_REG_UNKNOWN_TYPE_MSG;
		return ret;
		break;
	}
#endif
	msg = create_message_mok_x(msg_type, reg, 0x0);
	MOK_X_RDR_DEBUG_MSG("%s: link #%d. Created msg: %x\n",
			    __FUNCTION__, link, msg);
#if SETTING_OVER_INTERRUPT
        wait_answer_msg = 0x0;
#endif
	ret_send = send_msg_check(msg, link, cmd, 0, 0);
	if (ret_send > 0) {
		MOK_X_RDR_DEBUG_MSG("%s: link #%d. Wait answer: %x \n",
				    __FUNCTION__, link, ret_send);

		ret = RDR_answer_wait(link, msg_type, reg, data);
	} else {
		MOK_X_PLD_DBG_ERROR_MSG("%s: link #%d. Read mok_x register "
					"(addr: %x). Error(%x)\n", __FUNCTION__,
					link, reg, ret_send);
		ret = ERROR_MOK_X_REG_READ;
	}
	return ret;
}

/*
 * Write MOK-X registers
 * ============================================================================
 */
#define MOK_X_WRR_DBG 0
#define MOK_X_WRR_DEBUG_MSG(x...)\
		if (MOK_X_WRR_DBG) MOK_X_DBG_MSG(x)
int WRR_mok_x(int link, unsigned int msg_type, unsigned int reg,
	      unsigned int data)
{
	unsigned int cmd = 0;
	unsigned int msg;
	int ret = SUCCES_MOK_X, ret_send;

#if 1
	switch (msg_type) {
	case RDMA_MOK_X_REG_WRITE:
		MOK_X_WRR_DEBUG_MSG("%s: link #%d. Message type: "
				    "RDMA_MOK_X_REG_WRITE (%x)\n",
				    __FUNCTION__, link, msg_type);
		break;
	case RDMA_MOK_X_REMOTE_REG_WRITE:
		MOK_X_WRR_DEBUG_MSG("%s: link #%d. Message type: "
				    "RDMA_MOK_X_REMOTE_REG_WRITE (%x)\n",
				    __FUNCTION__, link, msg_type);
		break;
	case RDMA_MOK_X_REMOTE_SYSTEM_REG_WRITE:
		MOK_X_WRR_DEBUG_MSG("%s: link #%d. Message type: "
				    "RDMA_MOK_X_REMOTE_SYSTEM_REG_WRITE (%x)\n",
				    __FUNCTION__, link, msg_type);
		break;
	default:
		MOK_X_PLD_DBG_ERROR_MSG("%s: link #%d. Unknown type messages of "
					"request(%x)\n", __FUNCTION__, link,
					msg_type);
		ret = ERROR_MOK_X_REG_UNKNOWN_TYPE_MSG;
		return ret;
		break;
	}
#endif
	msg = create_message_mok_x(msg_type, reg, data);
	MOK_X_WRR_DEBUG_MSG("%s: link #%d. Write mok_x register(addr: %x). "
			    "msg(%x)\n", __FUNCTION__, link, reg, msg);
	ret_send = send_msg_check(msg, link, cmd, 0, 0);
	if (ret_send <= 0) {
		MOK_X_PLD_DBG_ERROR_MSG("%s: link #%d: Write mok_x register "
					"(addr: %x). Error(%x)\n", __FUNCTION__,
					link, reg, ret_send);
		ret = ERROR_MOK_X_REG_WRITE;
	}
	return ret;
}

/*
 * Read/write register config/status MOK_X
 * ============================================================================
 */

int set_mok_x_status_reg(int link, unsigned int msg_type, unsigned int data)
{
	return WRR_mok_x(link, msg_type, MOK_X_CFG_STATUS, data);
}

int get_mok_x_status_reg(int link, unsigned int msg_type, unsigned int *data)
{
	return RDR_mok_x(link, msg_type, MOK_X_CFG_STATUS, data);
}

/*
 * Set register config/status MOK_X
 * ============================================================================
 */
#define FIELD_SET_MOK_X_STATUS_REG_DBG 0
#define FIELD_SET_MOK_X_STATUS_REG_MSG(x...)\
		if (FIELD_SET_MOK_X_STATUS_REG_DBG) MOK_X_DBG_MSG(x)
#define F_SET_STATUS_MSG FIELD_SET_MOK_X_STATUS_REG_MSG
#define MOK_X_STATUS_REG_BIT_SET 0x1
#define MOK_X_STATUS_REG_BIT_UNSET 0x0
int field_set_mok_x_status_reg(int link, unsigned int msg_type,
			       unsigned int field, int type)
{
	mok_x_status_reg_struct_t status_reg;
	unsigned int answer_msg_type = RDMA_MOK_X_REG_READ;
	unsigned int data;
	int ret = SUCCES_MOK_X;

	switch (msg_type) {
	case RDMA_MOK_X_REG_WRITE:
		answer_msg_type = RDMA_MOK_X_REG_READ;
		break;
	case RDMA_MOK_X_REMOTE_REG_WRITE:
		answer_msg_type = RDMA_MOK_X_REMOTE_REG_READ;
		break;
	default:
		MOK_X_PLD_DBG_ERROR_MSG("%s: link #%d. Unknown type messages of "
					"request: %x\n", __FUNCTION__, link,
					msg_type);
		ret = ERROR_MOK_X_REG_UNKNOWN_TYPE_MSG;
		break;
	}
	F_SET_STATUS_MSG("%s: link #%d. answer_msg_type: %x field: %x\n",
			 __FUNCTION__, link, answer_msg_type, field);
	if (ret) {
		goto exit_field_set_mok_x_status_reg;
	}
	F_SET_STATUS_MSG("%s: link #%d. Read previos status_reg.\n",
				 __FUNCTION__, link);
	if (!(ret = get_mok_x_status_reg(link, answer_msg_type, &data))) {
		status_reg.word = (unsigned short) data;
		F_SET_STATUS_MSG("%s: link #%d. Read data status_reg: %x\n",
				 __FUNCTION__, link, data);
		type ? (data = data | field) : (data = data & (~field));
		F_SET_STATUS_MSG("%s: link #%d. Write data status_reg: %x\n",
				 __FUNCTION__, link, data);
		ret = set_mok_x_status_reg(link, msg_type, data);
	}
exit_field_set_mok_x_status_reg:
	return ret;
}

/*
 * bit enable
 * ============================================================================
 */
int set_mok_x_status_reg_enable(int link, unsigned int msg_type, int type)
{
	return field_set_mok_x_status_reg(link, msg_type,
				MOK_X_CFG_ENABLE, type);
}
/*
 * Interfeis bit enable
 */
int set_mok_x_SR_enable(int link)
{
	return set_mok_x_status_reg_enable(link, RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_SR_enable(int link)
{
	return set_mok_x_status_reg_enable(link, RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}
int set_mok_x_remote_SR_enable(int link)
{
	return set_mok_x_status_reg_enable(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_remote_SR_enable(int link)
{
	return set_mok_x_status_reg_enable(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}

/*
 * bit master
 * ============================================================================
 */
int set_mok_x_status_reg_master(int link, unsigned int msg_type, int type)
{
	return field_set_mok_x_status_reg(link, msg_type,
				MOK_X_CFG_MASTER, type);
}
/*
 * Interfeis bit master
 */
int set_mok_x_SR_master(int link)
{
	return set_mok_x_status_reg_master(link, RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_SR_master(int link)
{
	return set_mok_x_status_reg_master(link, RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}
int set_mok_x_remote_SR_master(int link)
{
	return set_mok_x_status_reg_master(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_remote_SR_master(int link)
{
	return set_mok_x_status_reg_master(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}

/*
 * bit slave
 * ============================================================================
 */
int set_mok_x_status_reg_slave(int link, unsigned int msg_type, int type)
{
	return field_set_mok_x_status_reg(link, msg_type,
				MOK_X_CFG_SLAVE, type);
}
/*
 * Interfeis bit slave
 */
int set_mok_x_SR_slave(int link)
{
	return set_mok_x_status_reg_slave(link, RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_SR_slave(int link)
{
	return set_mok_x_status_reg_slave(link, RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}
int set_mok_x_remote_SR_slave(int link)
{
	return set_mok_x_status_reg_slave(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_remote_SR_slave(int link)
{
	return set_mok_x_status_reg_slave(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}

/*
 * bit enable_trasmit
 * ============================================================================
 */

int set_mok_x_status_reg_enable_trasmit(int link, unsigned int msg_type,
					int type)
{
	return field_set_mok_x_status_reg(link, msg_type,
				MOK_X_CFG_ENABLE_TRANSMIT, type);
}
/*
 * Interfeis bit enable_trasmit
 */
int set_mok_x_SR_enable_trasmit(int link)
{
	return set_mok_x_status_reg_enable_trasmit(link,
				RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_SR_enable_trasmit(int link)
{
	return set_mok_x_status_reg_enable_trasmit(link,
				RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}
int set_mok_x_remote_SR_enable_trasmit(int link)
{
	return set_mok_x_status_reg_enable_trasmit(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_remote_SR_enable_trasmit(int link)
{
	return set_mok_x_status_reg_enable_trasmit(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}

/*
 * bit enable_receive
 * ============================================================================
 */
int set_mok_x_status_reg_enable_receive(int link, unsigned int msg_type,
				int type)
{
	return field_set_mok_x_status_reg(link, msg_type,
				MOK_X_CFG_ENABLE_RECEIVE, type);
}
/*
 * Interfeis bit enable_receive
 */
int set_mok_x_SR_enable_receive(int link)
{
	return set_mok_x_status_reg_enable_receive(link, RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_SR_enable_receive(int link)
{
	return set_mok_x_status_reg_enable_receive(link, RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}
int set_mok_x_remote_SR_enable_receive(int link)
{
	return set_mok_x_status_reg_enable_receive(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_remote_SR_enable_receive(int link)
{
	return set_mok_x_status_reg_enable_receive(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}

/*
 * bit ready_to_receive
 * ============================================================================
 */
int set_mok_x_status_reg_ready_to_receive(int link, unsigned int msg_type,
					  int type)
{
	return field_set_mok_x_status_reg(link, msg_type,
					 MOK_X_CFG_READY_TO_RECEIVE, type);
}
/*
 * Interfeis bit ready_to_receive
 */
int set_mok_x_SR_ready_to_receive(int link)
{
	return set_mok_x_status_reg_ready_to_receive(link, RDMA_MOK_X_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_SR_ready_to_receive(int link)
{
	return set_mok_x_status_reg_ready_to_receive(link, RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}
int set_mok_x_remote_SR_ready_to_receive(int link)
{
	return set_mok_x_status_reg_ready_to_receive(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_remote_SR_ready_to_receive(int link)
{
	return set_mok_x_status_reg_ready_to_receive(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}

/*
 * bit granted_last_packet
 * ============================================================================
 */
int set_mok_x_status_reg_granted_last_packet(int link, unsigned int msg_type,
					     int type)
{
	return field_set_mok_x_status_reg(link, msg_type,
				MOK_X_CFG_GRANTED_LAST_PACKET, type);
}
/*
 * Interfeis bit granted_last_packet
 */
int set_mok_x_SR_granted_last_packet(int link)
{
	return set_mok_x_status_reg_granted_last_packet(link,
				RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_SR_granted_last_packet(int link)
{
	return set_mok_x_status_reg_granted_last_packet(link,
				RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}
int set_mok_x_remote_SR_granted_last_packet(int link)
{
	return set_mok_x_status_reg_granted_last_packet(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_remote_SR_granted_last_packet(int link)
{
	return set_mok_x_status_reg_granted_last_packet(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}

/*
 * bit granted_packet
 * ============================================================================
 */
int set_mok_x_status_reg_granted_packet(int link, unsigned int msg_type,
					int type)
{
	return field_set_mok_x_status_reg(link, msg_type,
					 MOK_X_CFG_GRANTED_PACKET, type);
}
/*
 * Interfeis bit granted_packet
 */
int set_mok_x_SR_granted_packet(int link)
{
	return set_mok_x_status_reg_granted_packet(link, RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_SR_granted_packet(int link)
{
	return set_mok_x_status_reg_granted_packet(link, RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}
int set_mok_x_remote_SR_granted_packet(int link)
{
	return set_mok_x_status_reg_granted_packet(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_remote_SR_granted_packet(int link)
{
	return set_mok_x_status_reg_granted_packet(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}

/*
 * bit in_ready_to_recive
 * ============================================================================
 */
int set_mok_x_status_reg_in_ready_to_recive(int link, unsigned int msg_type,
					    int type)
{
	return field_set_mok_x_status_reg(link, msg_type,
					 MOK_X_CFG_IN_READY_TO_RECEIVE, type);
}
/*
 * Interfeis bit ready_to_recive
 */
int set_mok_x_SR_in_ready_to_recive(int link)
{
	return set_mok_x_status_reg_in_ready_to_recive(link,
				RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_SR_in_ready_to_recive(int link)
{
	return set_mok_x_status_reg_in_ready_to_recive(link,
				RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}
int set_mok_x_remote_SR_in_ready_to_recive(int link)
{
	return set_mok_x_status_reg_in_ready_to_recive(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_remote_SR_in_ready_to_recive(int link)
{
	return set_mok_x_status_reg_in_ready_to_recive(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_UNSET);
}

/*
 * bit mode1
 * ============================================================================
 */
int set_mok_x_status_reg_mode1(int link, unsigned int msg_type, int type)
{
	return field_set_mok_x_status_reg(link, msg_type,
					 MOK_X_CFG_MODE1, type);
}
/*
 * Interfeis bit mode1
 */
int set_mok_x_SR_mode1(int link)
{
	return set_mok_x_status_reg_mode1(link, RDMA_MOK_X_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_SR_mode1(int link)
{
	return set_mok_x_status_reg_mode1(link, RDMA_MOK_X_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_UNSET);
}
int set_mok_x_remote_SR_mode1(int link)
{
	return set_mok_x_status_reg_mode1(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_remote_SR_mode1(int link)
{
	return set_mok_x_status_reg_mode1(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_UNSET);
}

/*
 * bit mode2
 * ============================================================================
 */
int set_mok_x_status_reg_mode2(int link, unsigned int msg_type, int type)
{
	return field_set_mok_x_status_reg(link, msg_type,
					 MOK_X_CFG_MODE2, type);
}
/*
 * Interfeis bit mode2
 */
int set_mok_x_SR_mode2(int link)
{
	return set_mok_x_status_reg_mode2(link, RDMA_MOK_X_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_SR_mode2(int link)
{
	return set_mok_x_status_reg_mode2(link, RDMA_MOK_X_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_UNSET);
}
int set_mok_x_remote_SR_mode2(int link)
{
	return set_mok_x_status_reg_mode2(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_remote_SR_mode2(int link)
{
	return set_mok_x_status_reg_mode2(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_UNSET);
}

/*
 * bit mode3
 * ============================================================================
 */
int set_mok_x_status_reg_mode3(int link, unsigned int msg_type, int type)
{
	return field_set_mok_x_status_reg(link, msg_type,
					 MOK_X_CFG_MODE3, type);
}
/*
 * Interfeis bit mode3
 */
int set_mok_x_SR_mode3(int link)
{
	return set_mok_x_status_reg_mode3(link, RDMA_MOK_X_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_SR_mode3(int link)
{
	return set_mok_x_status_reg_mode3(link, RDMA_MOK_X_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_UNSET);
}
int set_mok_x_remote_SR_mode3(int link)
{
	return set_mok_x_status_reg_mode3(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_remote_SR_mode3(int link)
{
	return set_mok_x_status_reg_mode3(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_UNSET);
}

/*
 * bit mode4
 * ============================================================================
 */
int set_mok_x_status_reg_mode4(int link, unsigned int msg_type, int type)
{
	return field_set_mok_x_status_reg(link, msg_type,
					 MOK_X_CFG_MODE4, type);
}
/*
 * Interfeis bit mode4
 */
int set_mok_x_SR_mode4(int link)
{
	return set_mok_x_status_reg_mode4(link, RDMA_MOK_X_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_SR_mode4(int link)
{
	return set_mok_x_status_reg_mode4(link, RDMA_MOK_X_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_UNSET);
}
int set_mok_x_remote_SR_mode4(int link)
{
	return set_mok_x_status_reg_mode4(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}
int unset_mok_x_remote_SR_mode4(int link)
{
	return set_mok_x_status_reg_mode4(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_UNSET);
}

#if 1
/*
 * Get register config/status MOK_X
 * ============================================================================
 */
#define FIELD_GET_MOK_X_STATUS_REG_DBG 0
#define FIELD_GET_MOK_X_STATUS_REG_MSG(x...)\
		if (FIELD_GET_MOK_X_STATUS_REG_DBG) MOK_X_DBG_MSG(x)
#define F_GET_STATUS_MSG FIELD_GET_MOK_X_STATUS_REG_MSG
int field_get_mok_x_status_reg(int link, unsigned int msg_type,
			       unsigned int field, int type)
{
	mok_x_status_reg_struct_t status_reg;
	unsigned int answer_msg_type = RDMA_MOK_X_REG_READ;
	unsigned int data;
	int ret = SUCCES_MOK_X;

	switch (msg_type) {
		case RDMA_MOK_X_REG_WRITE:
			answer_msg_type = RDMA_MOK_X_REG_READ;
			break;
		case RDMA_MOK_X_REMOTE_REG_WRITE:
			answer_msg_type = RDMA_MOK_X_REMOTE_REG_READ;
			break;
		default:
			MOK_X_PLD_DBG_ERROR_MSG("%s: link #%d Unknown type "
						"messages of request: %x\n",
						__FUNCTION__, link, msg_type);
			ret = ERROR_MOK_X_REG_UNKNOWN_TYPE_MSG;
			break;
	}
	if (ret) {
		goto exit_field_get_mok_x_status_reg;
	}
	if ((ret = get_mok_x_status_reg(link, answer_msg_type, &data)) == 0) {
		status_reg.word = (unsigned short) data;
		switch (field) {
		case MOK_X_CFG_ENABLE:
			F_GET_STATUS_MSG("%s: link: %d SR enable-bit.\n",
					  __FUNCTION__, link);
			ret = status_reg.fields.enable;
		break;
		case MOK_X_CFG_MASTER:
			F_GET_STATUS_MSG("%s: link: %d SR master-bit.\n",
					  __FUNCTION__, link);
			ret = status_reg.fields.master;
		break;
		case MOK_X_CFG_SLAVE:
			F_GET_STATUS_MSG("%s: link: %d SR slave-bit.\n",
					  __FUNCTION__, link);
			ret = status_reg.fields.slave;
		break;
		case MOK_X_CFG_ENABLE_TRANSMIT:
			F_GET_STATUS_MSG("%s: link: %d SR transmit_enable-bit.\n",
					  __FUNCTION__, link);
			ret = status_reg.fields.transmit_enable;
		break;
		case MOK_X_CFG_ENABLE_RECEIVE:
			F_GET_STATUS_MSG("%s: link: %d SR receive_enable-bit.\n",
					  __FUNCTION__, link);
			ret = status_reg.fields.receive_enable;
		break;
		case MOK_X_CFG_READY_TO_RECEIVE:
			F_GET_STATUS_MSG("%s: link: %d SR ready_to_receive-bit.\n",
					  __FUNCTION__, link);
			ret = status_reg.fields.ready_to_receive;
		break;
		case MOK_X_CFG_GRANTED_LAST_PACKET:
			F_GET_STATUS_MSG("%s: link: %d SR granted_last_packet-bit.\n",
					  __FUNCTION__, link);
			ret = status_reg.fields.granted_last_packet;
		break;
		case MOK_X_CFG_GRANTED_PACKET:
			F_GET_STATUS_MSG("%s: link: %d SR granted_packet-bit.\n",
					  __FUNCTION__, link);
			ret = status_reg.fields.granted_packet;
		break;
		case MOK_X_CFG_IN_READY_TO_RECEIVE:
			F_GET_STATUS_MSG("%s: link: %d SR in_ready_to_receive-bit.\n",
					  __FUNCTION__, link);
			ret = status_reg.fields.in_ready_to_receive;
		break;
		case MOK_X_CFG_MODE1:
			F_GET_STATUS_MSG("%s: link: %d SR mode1-bit.\n",
					  __FUNCTION__, link);
			ret = status_reg.fields.mode1;
		break;
		case MOK_X_CFG_MODE2:
			F_GET_STATUS_MSG("%s: link: %d SR mode2-bit.\n",
					  __FUNCTION__, link);
			ret = status_reg.fields.mode2;
		break;
		case MOK_X_CFG_MODE3:
			F_GET_STATUS_MSG("%s: link: %d SR mode3-bit.\n",
					  __FUNCTION__, link);
			ret = status_reg.fields.mode3;
		break;
		case MOK_X_CFG_MODE4:
			F_GET_STATUS_MSG("%s: link: %d SR mode4-bit.\n",
					  __FUNCTION__, link);
			ret = status_reg.fields.mode4;
		break;
		case MOK_X_CFG_TIMEOUT_MSG_RECEIVE:
			F_GET_STATUS_MSG("%s: link: %d SR timeout_msg_receive-bit.\n",
					  __FUNCTION__, link);
			ret = status_reg.fields.timeout_msg_receive;
		break;
		
		default:
			MOK_X_PLD_DBG_ERROR_MSG("%s: link #%d.Unknown field of "
						"request: %x\n",
						__FUNCTION__, link, field);
			ret = ERROR_MOK_X_STATUS_REG_UNKNOWN_FIELD_MSG;
			break;
		}
	}
exit_field_get_mok_x_status_reg:
	return ret;
}

/*
 * Get register config/status MOK_X
 * ============================================================================
 */
/*
 * bit enable
 * ============================================================================
 */
int get_mok_x_status_reg_enable(int link, unsigned int msg_type, int type)
{
	return field_get_mok_x_status_reg(link, msg_type,
				MOK_X_CFG_ENABLE, type);
}
/*
 * Interfeis bit enable
 */
int get_mok_x_SR_enable(int link)
{
	return get_mok_x_status_reg_enable(link, RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}

int get_mok_x_remote_SR_enable(int link)
{
	return get_mok_x_status_reg_enable(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}

/*
 * bit master
 * ============================================================================
 */
int get_mok_x_status_reg_master(int link, unsigned int msg_type, int type)
{
	return field_get_mok_x_status_reg(link, msg_type,
				MOK_X_CFG_MASTER, type);
}
/*
 * Interfeis bit master
 */
int get_mok_x_SR_master(int link)
{
	return get_mok_x_status_reg_master(link, RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}

int get_mok_x_remote_SR_master(int link)
{
	return get_mok_x_status_reg_master(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}

/*
 * bit slave
 * ============================================================================
 */
int get_mok_x_status_reg_slave(int link, unsigned int msg_type, int type)
{
	return field_get_mok_x_status_reg(link, msg_type,
				MOK_X_CFG_SLAVE, type);
}
/*
 * Interfeis bit slave
 */
int get_mok_x_SR_slave(int link)
{
	return get_mok_x_status_reg_slave(link, RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}

int get_mok_x_remote_SR_slave(int link)
{
	return get_mok_x_status_reg_slave(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}

/*
 * bit enable_trasmit
 * ============================================================================
 */

int get_mok_x_status_reg_enable_trasmit(int link, unsigned int msg_type,
					int type)
{
	return field_get_mok_x_status_reg(link, msg_type,
				MOK_X_CFG_ENABLE_TRANSMIT, type);
}
/*
 * Interfeis bit enable_trasmit
 */
int get_mok_x_SR_enable_trasmit(int link)
{
	return get_mok_x_status_reg_enable_trasmit(link,
				RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int get_mok_x_remote_SR_enable_trasmit(int link)
{
	return get_mok_x_status_reg_enable_trasmit(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}

/*
 * bit enable_receive
 * ============================================================================
 */
int get_mok_x_status_reg_enable_receive(int link, unsigned int msg_type,
					int type)
{
	return field_get_mok_x_status_reg(link, msg_type,
					  MOK_X_CFG_ENABLE_RECEIVE, type);
}
/*
 * Interfeis bit enable_receive
 */
int get_mok_x_SR_enable_receive(int link)
{
	return get_mok_x_status_reg_enable_receive(link, RDMA_MOK_X_REG_WRITE,
						   MOK_X_STATUS_REG_BIT_SET);
}
int get_mok_x_remote_SR_enable_receive(int link)
{
	return get_mok_x_status_reg_enable_receive(link,
						   RDMA_MOK_X_REMOTE_REG_WRITE,
						   MOK_X_STATUS_REG_BIT_SET);
}

/*
 * bit ready_to_receive
 * ============================================================================
 */
int get_mok_x_status_reg_ready_to_receive(int link, unsigned int msg_type,
					  int type)
{
	return field_get_mok_x_status_reg(link, msg_type,
					  MOK_X_CFG_READY_TO_RECEIVE, type);
}
/*
 * Interfeis bit ready_to_receive
 */
int get_mok_x_SR_ready_to_receive(int link)
{
	return get_mok_x_status_reg_ready_to_receive(link, RDMA_MOK_X_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}
int get_mok_x_remote_SR_ready_to_receive(int link)
{
	return get_mok_x_status_reg_ready_to_receive(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}

/*
 * bit granted_last_packet
 * ============================================================================
 */
int get_mok_x_status_reg_granted_last_packet(int link, unsigned int msg_type,
					     int type)
{
	return field_get_mok_x_status_reg(link, msg_type,
				MOK_X_CFG_GRANTED_LAST_PACKET, type);
}
/*
 * Interfeis bit granted_last_packet
 */
int get_mok_x_SR_granted_last_packet(int link)
{
	return get_mok_x_status_reg_granted_last_packet(link,
				RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int get_mok_x_remote_SR_granted_last_packet(int link)
{
	return get_mok_x_status_reg_granted_last_packet(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}

/*
 * bit granted_packet
 * ============================================================================
 */
int get_mok_x_status_reg_granted_packet(int link, unsigned int msg_type,
					int type)
{
	return field_get_mok_x_status_reg(link, msg_type,
					 MOK_X_CFG_GRANTED_PACKET, type);
}
/*
 * Interfeis bit granted_packet
 */
int get_mok_x_SR_granted_packet(int link)
{
	return get_mok_x_status_reg_granted_packet(link, RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int get_mok_x_remote_SR_granted_packet(int link)
{
	return get_mok_x_status_reg_granted_packet(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}

/*
 * bit in_ready_to_recive
 * ============================================================================
 */
int get_mok_x_status_reg_in_ready_to_receive(int link, unsigned int msg_type,
					    int type)
{
	return field_get_mok_x_status_reg(link, msg_type,
					 MOK_X_CFG_IN_READY_TO_RECEIVE, type);
}
/*
 * Interfeis bit ready_to_recive
 */
int get_mok_x_SR_in_ready_to_receive(int link)
{
	return get_mok_x_status_reg_in_ready_to_receive(link,
				RDMA_MOK_X_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}
int get_mok_x_remote_SR_in_ready_to_receive(int link)
{
	return get_mok_x_status_reg_in_ready_to_receive(link,
				RDMA_MOK_X_REMOTE_REG_WRITE,
				MOK_X_STATUS_REG_BIT_SET);
}

/*
 * bit mode1
 * ============================================================================
 */
int get_mok_x_status_reg_mode1(int link, unsigned int msg_type, int type)
{
	return field_get_mok_x_status_reg(link, msg_type,
					 MOK_X_CFG_MODE1, type);
}
/*
 * Interfeis bit mode1
 */
int get_mok_x_SR_mode1(int link)
{
	return get_mok_x_status_reg_mode1(link, RDMA_MOK_X_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}
int get_mok_x_remote_SR_mode1(int link)
{
	return get_mok_x_status_reg_mode1(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}

/*
 * bit mode2
 * ============================================================================
 */
int get_mok_x_status_reg_mode2(int link, unsigned int msg_type, int type)
{
	return field_get_mok_x_status_reg(link, msg_type,
					 MOK_X_CFG_MODE2, type);
}
/*
 * Interfeis bit mode2
 */
int get_mok_x_SR_mode2(int link)
{
	return get_mok_x_status_reg_mode2(link, RDMA_MOK_X_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}
int get_mok_x_remote_SR_mode2(int link)
{
	return get_mok_x_status_reg_mode2(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}

/*
 * bit mode3
 * ============================================================================
 */
int get_mok_x_status_reg_mode3(int link, unsigned int msg_type, int type)
{
	return field_get_mok_x_status_reg(link, msg_type,
					 MOK_X_CFG_MODE3, type);
}
/*
 * Interfeis bit mode3
 */
int get_mok_x_SR_mode3(int link)
{
	return get_mok_x_status_reg_mode3(link, RDMA_MOK_X_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}
int get_mok_x_remote_SR_mode3(int link)
{
	return get_mok_x_status_reg_mode3(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}

/*
 * bit mode4
 * ============================================================================
 */
int get_mok_x_status_reg_mode4(int link, unsigned int msg_type, int type)
{
	return field_get_mok_x_status_reg(link, msg_type,
					 MOK_X_CFG_MODE4, type);
}
/*
 * Interfeis bit mode4
 */
int get_mok_x_SR_mode4(int link)
{
	return get_mok_x_status_reg_mode4(link, RDMA_MOK_X_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}
int get_mok_x_remote_SR_mode4(int link)
{
	return get_mok_x_status_reg_mode4(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				   MOK_X_STATUS_REG_BIT_SET);
}

/*
 * bit link
 * ============================================================================
 */
int get_mok_x_status_reg_link(int link, unsigned int msg_type,
					     int type)
{
	return field_get_mok_x_status_reg(link, msg_type,
					  MOK_X_CFG_LINK, type);
}

/*
 * Interfeis link
 */
int get_mok_x_SR_link(int link)
{
	return get_mok_x_status_reg_link(link, RDMA_MOK_X_REG_WRITE,
					 MOK_X_STATUS_REG_BIT_SET);
}
int get_mok_x_remote_SR_link(int link)
{
	return get_mok_x_status_reg_link(link, RDMA_MOK_X_REMOTE_REG_WRITE,
					 MOK_X_STATUS_REG_BIT_SET);
}


/*
 * bit timeout message receive
 * ============================================================================
 */
int get_mok_x_status_reg_timeout_msg_receive(int link, unsigned int msg_type,
					     int type)
{
	return field_get_mok_x_status_reg(link, msg_type,
					  MOK_X_CFG_TIMEOUT_MSG_RECEIVE, type);
}
/*
 * Interfeis timeout message receive
 */
int get_mok_x_SR_timeout_msg_receive(int link)
{
	return get_mok_x_status_reg_timeout_msg_receive(link, RDMA_MOK_X_REG_WRITE,
							MOK_X_STATUS_REG_BIT_SET);
}
int get_mok_x_remote_SR_timeout_msg_receive(int link)
{
	return get_mok_x_status_reg_timeout_msg_receive(link, RDMA_MOK_X_REMOTE_REG_WRITE,
							MOK_X_STATUS_REG_BIT_SET);
}

#endif

/*
 * Read/write register size MOK_X
 * ============================================================================
 */

int set_mok_x_size_reg_h(int link, unsigned int msg_type, unsigned int data)
{
	return WRR_mok_x(link, msg_type, MOK_X_BURST_SIZE_H, data);
}
int set_mok_x_size_reg_l(int link, unsigned int msg_type, unsigned int data)
{
	return WRR_mok_x(link, msg_type, MOK_X_BURST_SIZE_L, data);
}

int get_mok_x_size_reg_h(int link, unsigned int msg_type, unsigned int *data)
{
	return RDR_mok_x(link, msg_type, MOK_X_BURST_SIZE_H, data);
}
int get_mok_x_size_reg_l(int link, unsigned int msg_type, unsigned int *data)
{
	return RDR_mok_x(link, msg_type, MOK_X_BURST_SIZE_L, data);
}
/*
 * Interfeis register size MOK_X
 */
int set_mok_x_SIZE(int link, unsigned int data)
{
	unsigned int data_h, data_l;
	int ret;

	data_l = data & 0x0000ffff;
	data_h = data & 0xffff0000;
	data_h = data >> 16; ///30
	printk("data_l: %x data_h: %x", data_l, data_h);

	if ((ret = set_mok_x_size_reg_l(link, RDMA_MOK_X_REG_WRITE, data_l)) > 0)
		return ret;
	mdelay(10);
	ret = set_mok_x_size_reg_h(link, RDMA_MOK_X_REG_WRITE, data_h);
	return ret;
}
int set_mok_x_remote_SIZE(int link, unsigned int data)
{
	unsigned int data_h, data_l;
	int ret;

	data_l = data & 0x0000ffff;
	data_h = data & 0xffff0000;
	data_h = data >> 16; ///30

	printk("data_l: %x data_h: %x", data_l, data_h);
	if ((ret = set_mok_x_size_reg_l(link,
	    			       RDMA_MOK_X_REMOTE_REG_WRITE, data_l)) > 0)
		return ret;
	mdelay(10);
	ret = set_mok_x_size_reg_h(link, RDMA_MOK_X_REMOTE_REG_WRITE, data_h);
	return ret;
}

int get_mok_x_SIZE(int link, unsigned int *data)
{
	unsigned int data_h, data_l;
	int ret = 0;

	*data = 0;
	if ((ret = get_mok_x_size_reg_l(link, RDMA_MOK_X_REG_READ, &data_l)) > 0) {
		return ret;
	}
	if ((ret = get_mok_x_size_reg_h(link, RDMA_MOK_X_REG_READ, &data_h)) < 1) {
		*data = data_h << 16;
		*data = *data | data_l;
	};
	return ret;
}
int get_mok_x_remote_SIZE(int link, unsigned int *data)
{
	unsigned int data_h, data_l;
	int ret;

	*data = 0;
	if ((ret = get_mok_x_size_reg_l(link,
				       RDMA_MOK_X_REMOTE_REG_READ,
				       &data_l)) > 0)
		return ret;
	if ((ret = get_mok_x_size_reg_h(link,
				       RDMA_MOK_X_REMOTE_REG_READ,
				       &data_h)) < 1) {
		*data = data_h << 16;
		*data = *data | data_l;
	};
	return ret;
}

/*
 * Test's register config/status MOK_X
 * ============================================================================
 */
void print_mok_x_status_reg(int link, unsigned int msg_type)
{
	mok_x_status_reg_struct_t status_reg;
	unsigned int data = 0x0;
	int ret;

	ret = get_mok_x_status_reg(link, msg_type, &data);
	MOK_X_INFO_MSG("\n========== PULL REG'S MOK_X(%x) ==========\n", data);
	if (!ret) {
		status_reg.word = data;
		MOK_X_INFO_MSG("status_reg.unused31: %s\n",
			       status_reg.fields.unused31 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.unused30: %s\n",
			       status_reg.fields.unused30 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.unused29: %s\n",
			       status_reg.fields.unused29 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.unused28: %s\n",
			       status_reg.fields.unused28 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.unused27: %s\n",
			       status_reg.fields.unused27 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.unused26: %s\n",
			       status_reg.fields.unused26 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.unused25: %s\n",
			       status_reg.fields.unused25 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.unused24: %s\n",
			       status_reg.fields.unused24 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.unused23: %s\n",
			       status_reg.fields.unused23 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.unused22: %s\n",
			       status_reg.fields.unused22 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.unused21: %s\n",
			       status_reg.fields.unused21 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.unused20: %s\n",
			       status_reg.fields.unused20 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.unused19: %s\n",
			       status_reg.fields.unused19 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.unused18: %s\n",
			       status_reg.fields.unused18 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.unused17: %s\n",
			       status_reg.fields.unused17 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.unused16: %s\n",
			       status_reg.fields.unused16 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.link bit: %s\n",
			       status_reg.fields.link ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.enable bit: %s\n",
			       status_reg.fields.enable ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.master bit: %s\n",
			       status_reg.fields.master ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.slave bit: %s\n",
			       status_reg.fields.slave ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.transmit_enable bit: %s\n",
			       status_reg.fields.transmit_enable ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.receive_enable bit: %s\n",
			       status_reg.fields.receive_enable ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.ready_to_receive bit: %s\n",
			       status_reg.fields.ready_to_receive ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.granted_last_packet bit: %s\n",
			       status_reg.fields.granted_last_packet ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.granted_packet bit: %s\n",
			       status_reg.fields.granted_packet ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.in_ready_to_receive bit: %s\n",
			       status_reg.fields.in_ready_to_receive ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.mode1 bit: %s\n",
			       status_reg.fields.mode1 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.mode2 bit: %s\n",
			       status_reg.fields.mode2 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.mode3 bit: %s\n",
			       status_reg.fields.mode3 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.mode4 bit: %s\n",
			       status_reg.fields.mode4 ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.reserv_1 bit: %s\n",
			       status_reg.fields.timeout_msg_receive ? "SET" : "UNSET");
		MOK_X_INFO_MSG("status_reg.reserv_0 bit: %s\n",
			       status_reg.fields.reserv0 ? "SET" : "UNSET");
	} else
		MOK_X_ERROR_MSG("%s: link # %d. Error(%d) read MOK_X "
				"STATUS REGISTER.\n", __FUNCTION__, link, ret);
		MOK_X_INFO_MSG("==========================================\n");
}

/*
 * Get registers counter MOK_X
 * ============================================================================
 */

int __get_mok_x_reg_counters(int link, unsigned int reg_addr,
			   unsigned int msg_type, unsigned int *data)
{
	return RDR_mok_x(link, msg_type, reg_addr, data);
}

int get_mok_x_reg_counters(int link, unsigned int reg_addr, unsigned int *data)
{
	return __get_mok_x_reg_counters(link, RDMA_MOK_X_REG_WRITE,
					reg_addr, data);
}
int get_mok_x_remote_reg_counters(int link, unsigned int reg_addr,
				  unsigned int *data)
{
	return __get_mok_x_reg_counters(link, RDMA_MOK_X_REMOTE_REG_WRITE,
					reg_addr, data);
}

/*
 * Register MDIO MOK_X
 * ============================================================================
 */

/*
 * Create msg for MGIO_DATA MOK-X
 * ============================================================================
 */
/*
 * phy dev ad 5 (prtad)
 * reg ad 2 (devad)
 * reg 0x0000 (адрес)
 * data 0100_0000_0000_0001 (данные)
 * Нужно прочитать по адресу, записать по адресу и снова прочитать.
 * Чтение по адресу.
 * 1. Записать адрес как данные.
 * 2. Прочитать.
 * Запись по адресу.
 * 1. Записать адрес как данные.
 * 2. Записать данные.
 */

#define MGIO_MODE_ADDRESS	0
#define MGIO_MODE_WRITE		1
#define MGIO_MODE_READ		2
#define MGIO_MODE_READ_INC	3
#define MGIO_MODE_EMPTY_MSG	0xffffffff

#define MOK_X_MDIO_REG_DBG 0
#define MOK_X_MDIO_REG_MSG(x...)\
		if (MOK_X_MDIO_REG_DBG) MOK_X_DBG_MSG(x)
unsigned int create_message_mgio_data_mok_x(int rw, unsigned int msg_phy_addr,
					      unsigned int msg_reg_addr)
{
	unsigned int msg_type = MOK_X_MGIO_DATA_OPER_CODE_ADDR;
	unsigned int phy_addr, reg_addr;

#define MASK_MDIO_ADDR	0x0000001f
	phy_addr = (msg_phy_addr & MASK_MDIO_ADDR) << 23;
	reg_addr = (msg_reg_addr & MASK_MDIO_ADDR) << 18;

	switch (rw) {
	case MGIO_MODE_ADDRESS:
		msg_type = MOK_X_MGIO_DATA_OPER_CODE_ADDR;
		break;
	case MGIO_MODE_WRITE:
		msg_type = MOK_X_MGIO_DATA_OPER_CODE_WR;
		break;
	case MGIO_MODE_READ:
		msg_type = MOK_X_MGIO_DATA_OPER_CODE_RD;
		break;
	case MGIO_MODE_READ_INC:
		msg_type = MOK_X_MGIO_DATA_OPER_CODE_RD_INC;
		break;
	default:
		MOK_X_MDIO_DBG_ERROR_MSG("%s: Unknown type operation of request(%x)\n",
					 __FUNCTION__, msg_type);
		return MGIO_MODE_EMPTY_MSG;
		break;
	}

	return MOK_X_MGIO_DATA_START_FRAME | msg_type |
			 (phy_addr & MOK_X_MGIO_DATA_PHY_ADDR_MASQ) |
			 (reg_addr & MOK_X_MGIO_DATA_REG_ADDR_MASQ) |
			 MOK_X_MGIO_DATA_TMP_CODE;
}

int wait_acknowledge_mdio(int link, unsigned msg_type)
{
	unsigned int data;
	unsigned int answer_msg_type = RDMA_MOK_X_REG_READ;
	int wait_acknowledge = 0, ret = SUCCES_MOK_X;

#define MASK_WAIT_ACKNOWLEDGE_MDIO	0x00002000
#define EXIT_WAIT_ACKNOWLEDGE_MDIO	10
	switch (msg_type) {
	case RDMA_MOK_X_REG_READ:
	case RDMA_MOK_X_REG_WRITE:
		answer_msg_type = RDMA_MOK_X_REG_READ;
		MOK_X_MDIO_REG_MSG("%s: link #%d. Message type: "
				   "RDMA_MOK_X_REG_READ (%x)\n",
				   __FUNCTION__, link, answer_msg_type);
		break;
	case RDMA_MOK_X_REMOTE_REG_READ:
	case RDMA_MOK_X_REMOTE_REG_WRITE:
		//answer_msg_type = RDMA_MOK_X_REMOTE_REG_RESPONSE;
		answer_msg_type = RDMA_MOK_X_REMOTE_REG_READ;
		MOK_X_MDIO_REG_MSG("%s: link #%d. Message type: "
				   "RDMA_MOK_X_REMOTE_REG_READ (%x)\n",
				   __FUNCTION__, link, answer_msg_type);
		break;
	default:
		MOK_X_MDIO_DBG_ERROR_MSG("%s: link #%d. Unknown type messages of "
					 "request(%x)\n", __FUNCTION__, link,
					msg_type);
		ret = ERROR_MOK_X_REG_UNKNOWN_TYPE_MSG;
		break;
	}
	if (ret)
		goto wait_acknowledge_mdio_exit;
	while (1) {
		if (ret = RDR_mok_x(link, answer_msg_type, MOK_X_MGIO_CSR_H,
				    &data)) {
			goto wait_acknowledge_mdio_exit;
		}
		if (ret = RDR_mok_x(link, answer_msg_type, MOK_X_MGIO_CSR_L,
				    &data)) {
			goto wait_acknowledge_mdio_exit;
		}
		MOK_X_MDIO_REG_MSG("%s: link #%d. Data: %x\n", __FUNCTION__,
				   link, data);
		if (data & MASK_WAIT_ACKNOWLEDGE_MDIO) {
			goto wait_acknowledge_mdio_exit;
		}
		if ((wait_acknowledge ++) > EXIT_WAIT_ACKNOWLEDGE_MDIO) {
			ret = ERROR_MOK_X_REG_NULL;
			goto wait_acknowledge_mdio_exit;
		}
	}
wait_acknowledge_mdio_exit:
	MOK_X_MDIO_REG_MSG("%s: link #%d. ret: %d \n", __FUNCTION__, link,
			   ret);
	return ret;
}

int get_mok_x_mdio_reg(int link, unsigned msg_type, unsigned int dev_phy_addr,
		       unsigned int dev_reg_addr, unsigned int reg_addr,
		       unsigned int *data)
{
	unsigned int msg, answer_msg_type = RDMA_MOK_X_REG_WRITE;
	int ret = SUCCES_MOK_X;

	switch (msg_type) {
	case RDMA_MOK_X_REG_READ:
		answer_msg_type = RDMA_MOK_X_REG_WRITE;
		break;
	case RDMA_MOK_X_REMOTE_REG_READ:
		answer_msg_type = RDMA_MOK_X_REMOTE_REG_WRITE;
		break;
	default:
		MOK_X_PLD_DBG_ERROR_MSG("%s: link #%d. Unknown type messages of "
					"request: %x\n", __FUNCTION__, link,
					msg_type);
		ret = ERROR_MOK_X_REG_UNKNOWN_TYPE_MSG;
		break;
	}
	MOK_X_MDIO_REG_MSG("%s: link #%d msg_type: %x answer_msg_type: %x\n", 
			   __FUNCTION__, link,	msg_type, answer_msg_type);
	if (ret)
		goto mok_x_mdio_reg_get_exit;

	
	msg = create_message_mgio_data_mok_x(MGIO_MODE_ADDRESS, dev_phy_addr,
					     dev_reg_addr);
	if (msg == MGIO_MODE_EMPTY_MSG) {
		MOK_X_MDIO_DBG_ERROR_MSG("%s: link #%d. Unknown type messages of "
					 "request(%x)\n", __FUNCTION__, link, msg);
		ret = ERROR_MOK_X_REG_UNKNOWN_TYPE_COP;
		goto mok_x_mdio_reg_get_exit;
	}
	MOK_X_MDIO_REG_MSG("%s: link #%d. dev_phy_addr: %x. dev_reg_addr: %x. "
			   "Head(create) mdio messages: %x\n", __FUNCTION__,
			   link, dev_phy_addr, dev_reg_addr, msg >> 16);
///	ret = WRR_mok_x(link, RDMA_MOK_X_REG_WRITE, MOK_X_MGIO_DATA_H,
///			msg >> 16);
	ret = WRR_mok_x(link, answer_msg_type, MOK_X_MGIO_DATA_H,
			msg >> 16);
	if (ret)
		goto mok_x_mdio_reg_get_exit;
	MOK_X_MDIO_REG_MSG("%s: link #%d.  reg_addr: %x\n",
			   __FUNCTION__, link, reg_addr);
///	ret = WRR_mok_x(link, RDMA_MOK_X_REG_WRITE, MOK_X_MGIO_DATA_L,
///			reg_addr);
	ret = WRR_mok_x(link, answer_msg_type, MOK_X_MGIO_DATA_L,
			reg_addr);
	if (ret)
		goto mok_x_mdio_reg_get_exit;
	ret = wait_acknowledge_mdio(link, msg_type);
	if (ret)
		goto mok_x_mdio_reg_get_exit;
	msg = create_message_mgio_data_mok_x(MGIO_MODE_READ_INC, dev_phy_addr,
					     dev_reg_addr);
	if (msg == MGIO_MODE_EMPTY_MSG) {
		MOK_X_MDIO_DBG_ERROR_MSG("%s: link #%d. Unknown type messages of "
					 "request(%x)\n", __FUNCTION__, link, msg);
		ret = ERROR_MOK_X_REG_UNKNOWN_TYPE_COP;
		goto mok_x_mdio_reg_get_exit;
	}
	MOK_X_MDIO_REG_MSG("%s: link #%d. dev_phy_addr: %x. dev_reg_addr: %x. "
			   "reg_addr: %x. Head(create) mdio messages: %x\n",
			   __FUNCTION__, link, dev_phy_addr, dev_reg_addr,
			   reg_addr, msg >> 16);
///	ret = WRR_mok_x(link, RDMA_MOK_X_REG_WRITE, MOK_X_MGIO_DATA_H, msg >> 16);
	ret = WRR_mok_x(link, answer_msg_type, MOK_X_MGIO_DATA_H, msg >> 16);
	if (ret)
		goto mok_x_mdio_reg_get_exit;
///	ret = WRR_mok_x(link, RDMA_MOK_X_REG_WRITE, MOK_X_MGIO_DATA_L, 0x0);
	ret = WRR_mok_x(link, answer_msg_type, MOK_X_MGIO_DATA_L, 0x0);
	if (ret)
		goto mok_x_mdio_reg_get_exit;
	if (!(ret = wait_acknowledge_mdio(link, msg_type))) {
		if (ret = RDR_mok_x(link, msg_type, MOK_X_MGIO_DATA_H,
				    data))
			goto mok_x_mdio_reg_get_exit;
		ret = RDR_mok_x(link, msg_type, MOK_X_MGIO_DATA_L,
				data);
	}
mok_x_mdio_reg_get_exit:
	return ret;
}

int set_mok_x_mdio_reg(int link, unsigned msg_type, unsigned int dev_phy_addr,
		       unsigned int dev_reg_addr, unsigned int reg_addr,
		       unsigned int data)
{
	unsigned int msg;
	int ret;
	msg = create_message_mgio_data_mok_x(MGIO_MODE_ADDRESS, dev_phy_addr,
					     dev_reg_addr);
	if (msg == MGIO_MODE_EMPTY_MSG) {
		MOK_X_MDIO_DBG_ERROR_MSG("%s: link #%d. Unknown type messages of "
					 "request(%x)\n", __FUNCTION__, link, msg);
		ret = ERROR_MOK_X_REG_UNKNOWN_TYPE_COP;
		goto mok_x_mdio_reg_set_exit;
	}
	MOK_X_MDIO_REG_MSG("%s: link #%d. dev_phy_addr: %x. dev_reg_addr: %x. "
			   "Head(create) mdio messages: %x\n", __FUNCTION__,
			   link, dev_phy_addr, dev_reg_addr, msg >> 16);
	ret = WRR_mok_x(link, msg_type, MOK_X_MGIO_DATA_H, msg >> 16);
	if (ret)
		goto mok_x_mdio_reg_set_exit;
	MOK_X_MDIO_REG_MSG("%s: link #%d.  reg_addr: %x\n",
			   __FUNCTION__, link, reg_addr);
	msg = create_message_mgio_data_mok_x(MGIO_MODE_WRITE, dev_phy_addr,
					     dev_reg_addr);
	if (msg == MGIO_MODE_EMPTY_MSG) {
		MOK_X_MDIO_DBG_ERROR_MSG("%s: link #%d. Unknown type messages of "
					 "request(%x)\n", __FUNCTION__, link, msg);
		ret = ERROR_MOK_X_REG_UNKNOWN_TYPE_COP;
		goto mok_x_mdio_reg_set_exit;
	}
	ret = WRR_mok_x(link, msg_type, MOK_X_MGIO_DATA_L, reg_addr);
	if (ret)
		goto mok_x_mdio_reg_set_exit;
	ret = wait_acknowledge_mdio(link, msg_type);
	if (ret)
		goto mok_x_mdio_reg_set_exit;
	ret = WRR_mok_x(link, msg_type, MOK_X_MGIO_DATA_H, msg >> 16);
	if (ret)
		goto mok_x_mdio_reg_set_exit;
	MOK_X_MDIO_REG_MSG("%s: link #%d. Data: %x\n",
			   __FUNCTION__, link, data);
	ret = WRR_mok_x(link, msg_type, MOK_X_MGIO_DATA_L, data);
	if (ret)
		goto mok_x_mdio_reg_set_exit;
	ret = wait_acknowledge_mdio(link, msg_type);
mok_x_mdio_reg_set_exit:
	return ret;
}

/*
 * Interfeis mdio reg's
 */
int get_mok_x_MDIO_reg(int link, unsigned int dev_phy_addr,
		       unsigned int dev_reg_addr, unsigned int reg_addr,
		       unsigned int *data)
{
	return get_mok_x_mdio_reg(link, RDMA_MOK_X_REG_READ, dev_phy_addr,
				  dev_reg_addr, reg_addr, data);
}
int get_mok_x_remote_MDIO_reg(int link, unsigned int dev_phy_addr,
			      unsigned int dev_reg_addr, unsigned int reg_addr,
			      unsigned int *data)
{
	return get_mok_x_mdio_reg(link, RDMA_MOK_X_REMOTE_REG_READ,
				  dev_phy_addr, dev_reg_addr, reg_addr, data);
}
int set_mok_x_MDIO_reg(int link, unsigned int dev_phy_addr,
		       unsigned int dev_reg_addr, unsigned int reg_addr,
		       unsigned int data)
{
	return set_mok_x_mdio_reg(link, RDMA_MOK_X_REG_WRITE, dev_phy_addr,
				  dev_reg_addr, reg_addr, data);
}
int set_mok_x_remote_MDIO_reg(int link, unsigned int dev_phy_addr,
			      unsigned int dev_reg_addr, unsigned int reg_addr,
			      unsigned int data)
{
	return set_mok_x_mdio_reg(link, RDMA_MOK_X_REMOTE_REG_WRITE,
				  dev_phy_addr, dev_reg_addr, reg_addr, data);
}
