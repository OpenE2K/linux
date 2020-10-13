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
	 блок параметров IOCTL-операций
*/
typedef struct mbkp_ioc_parm {
	size_t	reqlen;		/* запрошенное число байт I/O 	*/
	size_t	acclen;		/* фактическое число байт I/O 	*/
	char	err_no;		/* от драйвера: код ошибки MBKP_E_... */ 
	char	rwmode;		/* драйверу:    модификатор IOCTL-операций */
} mbkp_ioc_parm_t;

/*
	модофикатор IOCTL операций ( в поле mbkp_ioc_parmю.errno)
*/ 

#define MBKP_IOC_WAIT	     1 /* синхронный обмен 			*/
#define MBKP_IOC_NOWAIT	     2 /* асинхронный обмен 			*/
#define MBKP_IOC_CHECK	     3 /* ждать завершение начатого обмена !#k!	*/
#define MBKP_IOC_POLL	     4 /* опрос канала tr/rcv 			*/

/*
	коды IOCTL операций
*/ 

#define MBKP_IOC_ALLOCB	     2 /* выделить буфер длины reqlen 		*/
#define MBKP_IOC_READ	     3 /* читать блок из первого канала	 	*/
#define MBKP_IOC_WRITE	     4 /* писать блок длины reqlen 		*/
#define MBKP_TIMER_FOR_READ  5 /* установить таймер чтения reqlen мксек */
#define MBKP_TIMER_FOR_WRITE 6 /* установить таймер записи reqlen мксек */
#define MBKP_IOC_DE 	     7 /* разрешить прием дескриптора 		*/
#define MBKP_IOC_DW	     8 /* писать дескриптор	 		*/
#define MBKP_IOC_DR	     9 /* читать дескриптор	 		*/
#define MBKP_SELF_TEST	     0x99

/* ++ */
#define MBKP_IOC_SETRES	    10 /* включить резервные каналы		*/
#define MBKP_IOC_RETMAIN    11 /* включить основные каналы		*/
#define MBKP_IOC_SETTRBA    12 /* разрешить передачу дескрипторов		*/
#define MBKP_IOC_WRCMD	    14 /* писать команду из reqlen		*/

#define MBKP_IOC_RDR 	    15
#define MBKP_IOC_WRR 	    16

#define MBKP_IOC_RDALT	    23 /* читать блок из 2го канала 		*/
#define MBKP_IOC_RDESCALT   29 /* читать дескриптор из 2го канала	*/

#define MBKP_IOC_DEBUG	    30 

#define MBKP_IOC_IOTIME     28

/* дополнительные биты состояния запущенной операции */
/* min бит MBKP_IO_FINISHED левее старшего бита MBKP_IOC_... */

#define MBKP_IO_FINISHED    0x0100	/* асинхр опер завершена по прер */


/*
	коды завершения операций в поле mbkp_ioc_parm_t.errno
	errno!= MBKP_E_NORMAL при 
*/ 

#define MBKP_E_NORMAL 	 0 /* нормальное завершение операции 	 */
#define MBKP_E_INVOP  	 1 /* нет операции или аргумент 	 */
#define MBKP_E_INVAL  	 2 /* недопустимая операция или аргумент */
#define MBKP_E_NOBUF 	 5 /* невозможно выделить буфер	MBKP_IOC_ALLOCB */

#define MBKP_E_URGENT 	10 /* по операции readf принят дескриптор */
#define MBKP_E_PENDING 	11 /* операция с массивом не окончена	 */
#define MBKP_E_TIMER 	12 /* операция прекращена по таймеру 	 */	

#define MBKP_IOC_NOTRUN 14 /* операция не была начата 		*/ 
#define MBKP_IOC_DIFCH  15 /* операция была начата по другому каналу*/ 
#define MBKP_DESC_DISABLED 16 /* опер зап деск не окончена или ~ТРБА */

#define MBKP_ERREAD  20 /* ошибки при приеме по каналу 0 */
#define MBKP_ERWRITE 21 /* ошибки при приеме 		 */

#define MBKP_ERREAD1 30 /* ошибки при приеме по каналу 1 */


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
