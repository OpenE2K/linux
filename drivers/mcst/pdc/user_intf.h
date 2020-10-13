/* 
*	 Copyright (c) 2005 by MCST.
* 
* Written by Alexey V. Sitnikov, MCST 2005	
*/

#include "pdc_reg.h"

/*
*	 блок параметров IOCTL-операций
*/
typedef struct pdc_ioc_parm {
	unsigned long	data;		/* Данные 	*/
	size_t	size;			/* размер данных (в байтах) */
	int	err_no;			/* от драйвера: код ошибки PDC_E_... */ 
	unsigned int	rwmode;		/* драйверу:    модификатор IOCTL-операций */
} pdc_ioc_parm_t;

/*
*	IOCTL операций ( в поле mbkp_ioc_parm.rwmode)
*/

#define PDC_CHECK		20 /* Проверка устройства на занятость */
#define PDC_USER_BUFFER		21 /* Передать буфер пользователя */	
#define PDC_USER_DATA		22 /* Передать данное пользователя */


/*
*	код IOCTL операций ( kop )
*/ 

#define PDC_IOC_ALLOCB		0 /* выделить DMA буфер. Для режима Master */
#define PDC_IOC_FREEB		1 /* Освободить DMA буфер. Для режима Master */	
#define PDC_WRR			2 /* Произвести операцию записи в регистр */
#define PDC_RDR			3 /* Произвести операцию чтения регистра */
#define PDC_IOC_ALLOCB_ALIGNED  23 /* Выделить память ДМА выровненную по i_size_bytes *i + size_bytes */
#define PDC_WRITE_MORE_THAN_16BITS_SIZE 24 /* передать любое количество памяти */
#define PDC_READ_MORE_THAN_16BITS_SIZE 25  /* принять любое количество памяти */
#define PDC_MB_RECIEVE		4 /* Получить данные в буфер DMA */
#define PDC_MB_TRANSMIT		8 /* Передать данные DMA буфера */
#define PDC_SB_RECIEVE		16 /* Читать данные из аппаратного Slave Recieve буфера */ 
#define PDC_SB_TRANSMIT		32 /* Писать данные в аппаратный Slave Transmit буфер */
#define PDC_WAITING_RMI_MASTER	64  /* Ожидание удаленного прерывания в режиме master */
#define PDC_WAITING_RMI_SLAVE	128 /* Ожидание удаленного прерывания в режиме slave */
#define PDC_SEND_PI		6 /* Генерация удаленного PI прерывания */
#define PDC_SEND_NMI		7 /* Генерация удаленного NMI прерывания */
#define PDC_RESET		10 /* Общий сброс ячейки */
#define PDC_CLEAR_MASTER_TASK	11 /* Сброс задачи Master (биты MSize а также MRB и MTB не обнуляются) */
#define PDC_CLEAR_SLAVE_TASK	12 /* Сброс задачи Slave (биты SSize а также SRB и STB не обнуляются) */
#define PDC_CLEAR_MTB		13 /* Очистка буфера MTB */
#define PDC_CLEAR_MRB		14 /* Очистка буфера MRB */
#define PDC_CLEAR_STB		9 /* Очистка буфера STB */
#define PDC_CLEAR_SRB		15 /* Очистка буфера SRB */
#define PDC_CLEAR_LAST_INT	17 /* Обнулить информацию о последнем прерывании в системе */
#define PDC_SHOW_LAST_INT	5 /* Вернуть информацию о последнем прерывании в системе */
#define PDC_INIT		18 /* Дефолтная инициализация инстанса */
#define PDC_SET_TIMER		19 /* Установка таймера */

/*
*	коды завершения операций в поле pdc_ioc_parm_t.err_no
*	err_no!= PDC_E_NORMAL при 
*/ 

#define PDC_E_NORMAL 	 	0 /* нормальное завершение операции 	 */
#define PDC_E_PENDING	 	1 /* Устройство занято (при попытке выполнить задачу) */
#define PDC_E_INVAL		2 /* Неверный аргумент */	
#define PDC_E_INIT_MEM		4 /* При выполнении задачи Master не выделен DMA буфер */
#define PDC_E_ERTRANS		8 /* В системе зарегистрировано прерывание Err */
#define PDC_E_TIMER		16 /* Выход по таймеру */
#define PDC_E_ERWAIT		32 /* Во время операции PDC_WAITING_RMI зарегистрировано прерывание Err */
#define PDC_E_SIZE		64 /* Неверное размер запрашиваемых/передаваемых данных */
#define PDC_E_MEMORY_ALLOC	128 /* Ошибка при выделении буфера в режиме PDC_USER_BUFFER */
#define PDC_E_DDI_COPYIN	256 /* Ошибка при выполнении операции copy_from_user */
#define PDC_E_DDI_COPYOUT	512 /* Ошибка при выполнении операции copy_to_user */
#define PDC_E_NOBUF		1024 /* Ошибка при выделении DMA буфера, операция PDC_IOC_ALLOCB */
#define PDC_E_ALREADY_WAIT	4096 /* Уже находимся в стадии ожидания Удаленного прерывания в данном режиме */
/*
*	Коды отображаюшие состояние устройства пишуться также в  pdc_ioc_parm_t.err_no
*/

#define	PDC_BUSY	3	/* Устройство занято (при проверке на занятость)  */
#define PDC_NOTRUN	5	/* Устройство свободно (при проверке на занятость) */
#define PDC_RMI		6	/* В системе зарегистрировано Удаленное прервание */
#define PDC_SIGNAL	2048	/* Получен сигнал */


struct code_msg {
	int code;
	char * msg;
};

typedef struct code_msg code_msg_t; 

code_msg_t iocerrs[] = {
	{PDC_E_NORMAL, "PDC_E_NORMAL"},
	{PDC_E_PENDING, "PDC_E_PENDING"},
	{PDC_E_INVAL, "PDC_E_INVAL"},
	{PDC_E_INIT_MEM, "PDC_E_INIT_MEM"},
	{PDC_E_ERTRANS, "PDC_E_ERTRANS"},
	{PDC_E_TIMER, "PDC_E_TIMER"},
	{PDC_E_ERWAIT, "PDC_E_ERWAIT"},
	{PDC_E_SIZE, "PDC_E_SIZE"},
	{PDC_E_MEMORY_ALLOC, "PDC_E_MEMORY_ALLOC"},
	{PDC_E_DDI_COPYIN, "PDC_E_DDI_COPYIN"},
	{PDC_E_DDI_COPYOUT, "PDC_E_DDI_COPYOUT"},
	{PDC_E_NOBUF, "PDC_E_NOBUF"},
	{PDC_E_ALREADY_WAIT, "PDC_E_ALREADY_WAIT"},
	{PDC_BUSY, "PDC_BUSY"},
	{PDC_NOTRUN, "PDC_NOTRUN"},
	{PDC_RMI, "PDC_RMI"},
	{PDC_SIGNAL, "PDC_SIGNAL"},
};

code_msg_t ioctls[] = {
	{PDC_IOC_ALLOCB, "PDC_IOC_ALLOCB"}, 
	{PDC_IOC_FREEB, "PDC_IOC_FREEB"},
	{PDC_WRR, "PDC_WRR"},
	{PDC_RDR, "PDC_RDR"},
	{PDC_MB_RECIEVE, "PDC_MB_RECIEVE"},
	{PDC_MB_TRANSMIT, "PDC_MB_TRANSMIT"},
	{PDC_SB_RECIEVE, "PDC_SB_RECIEVE"},
	{PDC_SB_TRANSMIT, "PDC_SB_TRANSMIT"},
	{PDC_WAITING_RMI_MASTER, "PDC_WAITING_RMI_MASTER"},
	{PDC_WAITING_RMI_SLAVE, "PDC_WAITING_RMI_SLAVE"},
	{PDC_SEND_PI, "PDC_SEND_PI"}, 
	{PDC_SEND_NMI, "PDC_SEND_NMI"},
	{PDC_RESET, "PDC_RESET"},
	{PDC_CLEAR_MASTER_TASK, "PDC_CLEAR_MASTER_TASK"},
	{PDC_CLEAR_SLAVE_TASK, "PDC_CLEAR_SLAVE_TASK"},
	{PDC_CLEAR_MTB, "PDC_CLEAR_MTB"},
	{PDC_CLEAR_MRB, "PDC_CLEAR_MRB"},
	{PDC_CLEAR_STB, "PDC_CLEAR_STB"},
	{PDC_CLEAR_SRB, "PDC_CLEAR_SRB"},
	{PDC_CLEAR_LAST_INT, "PDC_CLEAR_LAST_INT"}, 
	{PDC_SHOW_LAST_INT, "PDC_SHOW_LAST_INT"},
};

code_msg_t rwmods[] = {
	{PDC_CHECK, "PDC_CHECK"}, 
	{PDC_USER_BUFFER, "PDC_USER_BUFFER"},
	{PDC_USER_DATA, "PDC_USER_DATA"},
	{PDC_SB_RECIEVE, "PDC_SB_RECIEVE"},
	{PDC_SB_TRANSMIT, "PDC_SB_TRANSMIT"},
	{PDC_MB_RECIEVE, "PDC_MB_RECIEVE"},
	{PDC_MB_TRANSMIT, "PDC_MB_TRANSMIT"},
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
