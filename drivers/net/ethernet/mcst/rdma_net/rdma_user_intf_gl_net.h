code_msg_t iocerrs[] = {
	{RDMA_E_INVOP, "RDMA_E_INVOP"},
	{RDMA_E_INVAL, "RDMA_E_INVAL"},
	{RDMA_E_NOBUF, "RDMA_E_NOBUF"},

	{RDMA_E_PENDING, "RDMA_E_PENDING"},
	{RDMA_E_TIMER, "RDMA_E_TIMER"},
	{RDMA_DESC_DISABLED, "RDMA_DESC_DISABLED"},
	{RDMA_IOC_DIFCH, "RDMA_IOC_DIFCH"},
	{RDMA_IOC_NOTRUN, "RDMA_IOC_NOTRUN"},
	{RDMA_ERREAD, "RDMA_ERREAD"},
	{RDMA_ERREAD1, "RDMA_ERREAD1"},
	{RDMA_ERWRITE, "RDMA_ERWRITE"},
	{RDMA_E_URGENT, "RDMA_E_URGENT"},
};

code_msg_t ioctls[] = {
	{RDMA_TIMER_FOR_READ, "RDMA_TIMER_FOR_READ"},
	{RDMA_TIMER_FOR_WRITE, "RDMA_TIMER_FOR_WRITE"},
	{RDMA_IOC_ALLOCB, "RDMA_IOC_ALLOCB"},
	{RDMA_IOC_READ, "RDMA_IOC_READ"},
	{RDMA_IOC_WRITE, "RDMA_IOC_WRITE"},
	{RDMA_IOC_DE, "RDMA_IOC_DE"},
	{RDMA_IOC_DW, "RDMA_IOC_DW"},
	{RDMA_IOC_RDR, "RDMA_IOC_RDR"},
	{RDMA_IOC_WRR, "RDMA_IOC_WRR"},

};

code_msg_t rwmods[] = {
	{RDMA_IOC_WAIT, "RDMA_IOC_WAIT"},
	{RDMA_IOC_NOWAIT, "RDMA_IOC_NOWAIT"},
	{RDMA_IOC_CHECK, "RDMA_IOC_CHECK"},
	{RDMA_IOC_POLL, "RDMA_IOC_POLL"},
};

char *msg_by_code(int code, code_msg_t * v, int len)
{
	code_msg_t *p;
	int i;
	for (i = 0; i < len; i++) {
		p = v + i;
		if (p->code == code)
			return p->msg;
	}
	return " code=? ";
}

extern int lvnet_init(void);
extern void lvnet_cleanup(void);
