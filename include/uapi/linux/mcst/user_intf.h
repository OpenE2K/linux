#ifndef _UAPI__USER_INTF_H__
#define _UAPI__USER_INTF_H__

#ifdef	__cplusplus
extern "C" {
#endif

/* user_intf.h

	result 	reqlen acclen errno

*/


#define MAX_CHANNEL	4 /* 8 eai => MAX_CHANNEL in*/


/*
	 IOCTL command attrubutes
*/
typedef struct mbkp_ioc_parm {
	size_t	reqlen;		/* requested I/O bytes	*/
	size_t	acclen;		/* accepted I/O bytes	*/
	char	err_no;		/* from driver: error code number MBKP_E_... */
	char	rwmode;		/* to driver: IOCTL-operation mode */
} mbkp_ioc_parm_t;

/*
	IOCTL command modes
*/ 

#define MBKP_IOC_WAIT	     1 /* synchronous transfer			*/
#define MBKP_IOC_NOWAIT	     2 /* asynchronous transfer			*/
#define MBKP_IOC_CHECK	     3 /* wait for started transfer completion	*/
#define MBKP_IOC_POLL	     4 /* tr/rcv channel poll			*/

/*
	IOCTL command codes
*/ 

#define MBKP_IOC_ALLOCB	     2 /* allocate buffer of reqlen size	*/
#define MBKP_IOC_READ	     3 /* read block from 1st channel		*/
#define MBKP_IOC_WRITE	     4 /* write block of reqlen length		*/
#define MBKP_TIMER_FOR_READ  5 /* set timer for 'reqlen' usec for read	*/
#define MBKP_TIMER_FOR_WRITE 6 /* ditto for write			*/
#define MBKP_IOC_DE	     7 /* enable descriptor accept		*/
#define MBKP_IOC_DW	     8 /* write descriptor			*/
#define MBKP_IOC_DR	     9 /* read descriptor			*/
#define MBKP_SELF_TEST	     0x99

/* ++ */
#define MBKP_IOC_SETRES	    10 /* enable reserved channels		*/
#define MBKP_IOC_RETMAIN    11 /* disable reserved channels		*/
#define MBKP_IOC_SETTRBA    12 /* enable descriptor transfer		*/
#define MBKP_IOC_WRCMD	    14 /* write command in 'reqlen'		*/

#define MBKP_IOC_RDR 	    15
#define MBKP_IOC_WRR 	    16

#define MBKP_IOC_RDALT	    23 /* read block from 2nd channel		*/
#define MBKP_IOC_RDESCALT   29 /* read descriptor from 2nd channel	*/

#define MBKP_IOC_DEBUG	    30 

#define MBKP_IOC_IOTIME     28

/*
 * extra status bits of current command
 * least significant bit in MBKP_IO_FINISHED must be bigger than
 *  most significant bit MBKP_IOC_...
 */

#define MBKP_IO_FINISHED    0x0100 /* async command completed on interrupt */


/*
	command completion error codes in mbkp_ioc_parm_t.errno
*/ 

#define MBKP_E_NORMAL	 0 /* normal command completion		*/
#define MBKP_E_INVOP	 1 /* missing command or argument	*/
#define MBKP_E_INVAL	 2 /* invalid command or argument	*/
#define MBKP_E_NOBUF	 5 /* failed to allocate MBKP_IOC_ALLOCB buffer */

#define MBKP_E_URGENT	10 /* descriptor accepted by operation 'readf'	*/
#define MBKP_E_PENDING	11 /* operation was not completed		*/
#define MBKP_E_TIMER	12 /* operation interrupted by timer	 */

#define MBKP_IOC_NOTRUN 14 /* operation was not started		*/
#define MBKP_IOC_DIFCH  15 /* operation was started on a different channel */
#define MBKP_DESC_DISABLED 16 /* descriptor transfer not completed or ~TRBA */

#define MBKP_ERREAD  20 /* errors when receiving on channel 0	*/
#define MBKP_ERWRITE 21 /* receive errors			*/

#define MBKP_ERREAD1 30 /* errors when receiving on channel 1	*/


struct code_msg {
	int code;
	char * msg;
};

typedef struct code_msg code_msg_t; 

code_msg_t iocerrs[] = {
	{MBKP_E_INVOP, "MBKP_E_INVOP"},
	{MBKP_E_INVAL, "MBKP_E_INVAL"},
	{MBKP_E_NOBUF, "MBKP_E_NOBUF"},
	
	{MBKP_E_PENDING, "MBKP_E_PENDING"},
	{MBKP_E_TIMER, "MBKP_E_TIMER"},
	{MBKP_DESC_DISABLED, "MBKP_DESC_DISABLED"},
	{MBKP_IOC_DIFCH, "MBKP_IOC_DIFCH"},
	{MBKP_IOC_NOTRUN, "MBKP_IOC_NOTRUN"},
	{MBKP_ERREAD, "MBKP_ERREAD"},
	{MBKP_ERREAD1, "MBKP_ERREAD1"},
	{MBKP_ERWRITE, "MBKP_ERWRITE"},
	{MBKP_E_URGENT, "MBKP_E_URGENT"},
};

code_msg_t ioctls[] = {
	{MBKP_TIMER_FOR_READ, "MBKP_TIMER_FOR_READ"}, 
	{MBKP_TIMER_FOR_WRITE, "MBKP_TIMER_FOR_WRITE"},
	{MBKP_IOC_ALLOCB, "MBKP_IOC_ALLOCB"},
	{MBKP_IOC_READ, "MBKP_IOC_READ"},
	{MBKP_IOC_WRITE, "MBKP_IOC_WRITE"},
	{MBKP_IOC_DE, "MBKP_IOC_DE"},
	{MBKP_IOC_DW, "MBKP_IOC_DW"},
	{MBKP_IOC_RDR, "MBKP_IOC_RDR"},
	{MBKP_IOC_WRR, "MBKP_IOC_WRR"},
	
};

code_msg_t rwmods[] = {
	{MBKP_IOC_WAIT, "MBKP_IOC_WAIT"}, 
	{MBKP_IOC_NOWAIT, "MBKP_IOC_NOWAIT"},
	{MBKP_IOC_CHECK, "MBKP_IOC_CHECK"},
	{MBKP_IOC_POLL, "MBKP_IOC_POLL"},
};

char * msg_by_code (int code, code_msg_t * v, int len) {
	code_msg_t * p;
	int i;
	for (i=0; i < len ; i++) {
		p = v + i;
		if (p->code == code) 
			return p->msg;
	}
	return " code=? ";
}

#ifdef	__cplusplus
}
#endif

#endif /* _UAPI__USER_INTF_H__ */
