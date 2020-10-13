/*
 *
 * Ported in Linux by Alexey V. Sitnikov, alexmipt@mcst.ru, MCST, 2004
 *
 */

/* Редакция файла mmr_io.h:
				ИМВС - 14.07.04; home - 19.04.04.
*/
/* 12.07.04 - возврат к одноподмассивным буферам */

/* Определения и структуры, используемые драйвером ВК
  и пользовательскими программами */

#ifndef	_UAPI_LINUX_MMR_IO_H__
#define	_UAPI_LINUX_MMR_IO_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include <linux/mcst/linux_me90_io.h>

#define	VERSION_LIB_PROCEDURE		0x15040401
/* Версия библиотечных процедур */

#ifndef MMR_OLD_VERSION
/* Версия модуля */
#define	VERSION_MODULE_MMR	0x17040504
/* Рабочие варианты */
#define	work_var_module			16
#endif /* MMR_OLD_VERSION */

/* Список команд реализованных в драйвере модуля MMR и исполняемых
*   посредством системного вызова ioctl()
*/

#ifdef MMR_OLD_VERSION
#define	MMRIO_READ_DEVICE_REG				(ME90_IO | 1)
#define	MMRIO_WRITE_DEVICE_REG				(ME90_IO | 2)
#define	MMRIO_INIT_BUFERS_EXCHANGE			(ME90_IO | 3)
#define	MMRIO_INIT_DEVICE				(ME90_IO | 4)
#define	MMRIO_HALT_TRANSFER_MODES			(ME90_IO | 5)
#define	MMRIO_GET_DEVICE_INFO				(ME90_IO | 6)
#define	MMRIO_INTR_TIME_WAIT				(ME90_IO | 7)

#define MMR_CNTR_ST_REG_SET_OFFSET		0x10000 /* Смещение области регистров */
#define MMR_CNTR_ST_REG_SET_LEN        		0x100	/* Размер области регистров */
#define	MMR_BMEM_REG_SET_OFFSET			0x40000 /* Смещение основной памяти */
#define	MMR_BMEM_REG_SET_LEN			0x20000 /* Размер области основной памяти */

#define	BCW_HARDWARE_MMR_ERROR		12
#else
#define MMR_IO			('M' << 8)
#define	MMRIO_GET_DRIVER_INFO				(MMR_IO | 1)
#define	MMRIO_READ_DEVICE_REG				(MMR_IO | 2)
#define	MMRIO_WRITE_DEVICE_REG				(MMR_IO | 3)
#define	MMRIO_INIT_BUFERS_EXCHANGE			(MMR_IO | 4)
#define	MMRIO_INIT_DEVICE				(MMR_IO | 5)
#define	MMRIO_HALT_TRANSFER_MODES			(MMR_IO | 6)
#define	MMRIO_GET_DEVICE_INFO				(MMR_IO | 7)
#define	MMRIO_INTR_TIME_WAIT				(MMR_IO | 8)
#define	MMRIO_NUM_INTR_ROSH				(MMR_IO | 9)

#define MMR_ADDR_CNTRL_INFRM_BUFFERS_DATAS	0x1000 	/* адрес области памяти */
													/* управляющей информации */
													/* буферов данных */
#define	MMR_BMEM_REG_SET_OFFSET		0x40000 /* Смещение основной памяти */
#define	MMR_BMEM_REG_SET_LEN		0x20000 /* Размер области ОП */

#define	MMR_TIMER_INTE			1000000	/* значение интервала времени */
						/* ожидания события (прерывания) */
						/* (в микросекундах) */
#endif /* MMR_OLD_VERSION */

//#define	MMR_HUNGUP_TIMER_INTERVAL	720000
#define	MMR_HUNGUP_TIMER_INTERVAL	360000
									/* значение таймера для */
									/* ожидания завершения обменов */
									/* (в микросекундах) */

#define	MMR_IO_WRITE		0x01		/* запись (передача) */
#define	MMR_IO_READ		0x02		/* чтение (прием) */

#ifndef MMR_OLD_VERSION
#define	BLOCK_ERROR_DEV  	1   /* блокировать ошибки адаптера */
#define	NO_BLOCK_ERROR_DEV  	0   /* не блокировать ошибки адаптера */
#define	BLOCK_ERROR_ROSH  	1   /* блокировать прерывания ПрП */
				    /* по значению РОШ */
#define	NO_BLOCK_ERROR_ROSH 	0   /* не блокировать прерывания ПрП */
				    /* по значению РОШ */
#define	GISTOGR			8   /* Размер массива распределения времени */
#define	GISTOGR_COMM		16  /* Размер массива распределения команд */
#endif /* MMR_OLD_VERSION */

/* Режимы функционированя ММР */
#define	MODE_CONTROLLER		   1
#define	MODE_TERMINAL		   2
#define	MODE_MONITOR		   3

#ifndef MMR_OLD_VERSION
/* Виды работ модуля ММР */
#define	CHECKOUT		   1 /* наладка модуля, комплексная наладка ВК */
#define	AUDIT_TE		   2 /* проверка модуля по ТУ */
#define	ENABLE		   	   3 /* включение ВК, перезагрузка ВК */
#define	AUDIT_MNTR		   4 /* проверка модуля в режиме монитора по ТУ */
#define	AUDIT_ONE_module   	   5 /* проверка одиночного модуля */
#endif /* MMR_OLD_VERSION */

#ifndef MMR_OLD_VERSION
/* Тип проверок модуля ММР */
/* Проверка исполнения команд управления */
#define	  fulfilment_command_cntrl 	1
/* Проверка исполнения ГК управления */
#define	  realiz_generic_comm_cntrl	2
/* Исполнение команд обмена данными между контроллером и
   оконечным устройством */
#define	 exchange_between_cntrl_term	3
/* Исполнение групповых команд передачи данных контроллером
   оконечным устройствам */
#define	 transfer_from_cntrl_terminals	4
/* Исполнение команд обмена данными между ОУ */
#define	 exchange_between_terminals		5
/* Исполнение групповых команд передача данных от оконечного 
   устройства оконечным устройствам */
#define	 transfer_from_term_terminals	6
#endif /* MMR_OLD_VERSION */

#ifdef MMR_OLD_VERSION
#define	EXPRESS_MODE		   4
#endif /* MMR_OLD_VERSION */

#define	MMR_MAX_NUM_TERMINAL		31  /* кол-во оконечных устройств */
#define	MMR_SUBADRR_NUM_TERMINAL	30  /* кол-во подадресов ОУ */
#define	MMR_BUF_USER_NUM		33  /* кол-во буферов обмена пользователя */
#define	MMR_BUF_ADAPTER_NUM		32  /* кол-во буферов обмена адаптера */

#define	MMR_DMA_BURST_SIZE		8*4 /* размер блока обмена - char */

#ifdef MMR_OLD_VERSION
#define	MMR_MAX_WORD_DATA_BUF_RECIV	16  /* макимальная длина ВД - longs */
#define	MMR_MAX_NUM_BUF_COMM		16  /* объем буфера команд ОУ - longs */
#define	MMR_MAX_NUM_SUBARRAY		1   /* кол-во подмассивов в ВД */
#define	MMR_SUBARRAY			32  /* размер подмассива в БД - words */
#define	ADDR_STATIST_CTRL		16  /* Адрес статистики контр-ра - words */										 
#define	MMR_MAX_WORD_DATA_BUF_TRANS	MMR_MAX_WORD_DATA_BUF_RECIV
									/* макимальная длина в словах */
									/* передающего буфера обмена */
#define	MMR_MAX_DATA_BUF_SIZE		MMR_MAX_WORD_DATA_BUF_RECIV*4
									/* макимальная длина в байтах */
									/* буфера обмена */
#else
#define	MMR_MAX_LONGS_DATA_BUF_RECIV  16  /* макимальная длина ВД - long */
#define	MMR_MAX_WORDS_DATA_BUF_RECIV  32  /* макимальная длина ВД - short */
#define	MMR_MAX_NUM_BUF_COMM	      16  /* объем буфера команд ОУ - long */
#define	ADDR_STATIST_CTRL	      16  /* Адрес статистики контр-ра - word */
#define	MMR_MAX_LONGS_DATA_BUF_TRANS	MMR_MAX_LONGS_DATA_BUF_RECIV
									/* макимальная длина в словах */
									/* передающего буфера обмена */
#define	MMR_MAX_DATA_BUF_SIZE		MMR_MAX_LONGS_DATA_BUF_RECIV*4
									/* макимальная длина в байтах */
									/* буфера обмена */
#endif /* MMR_OLD_VERSION */

#ifdef MMR_OLD_VERSION
#define	USK_TRANS_buf		0x36000401	/* УСК передатчика для буферов данных */
#define	USK_RECIV_buf		0x14000001	/* УСК приемника для буферов данных */
#define	USK_CTRL_buf_comm	0x34200001	/* УСК контроллера буфера команд */
#define	USK_TERM_buf_comm	0x00200001	/* УСК ОУ буфера команд */
#define	SKB_buf_comm_CNTR	0x00010001	/* СКБ буфера команд контроллера */
#else
#define	USK_TRANS_buf		0x36000401	/* УСК передатчика для буферов данных */
#define	USK_RECIV_buf		0x14000001	/* УСК приемника для буферов данных */
#define	USK_CTRL_buf_comm	0x34200001	/* УСК контроллера буфера команд */
#define	USK_TERM_buf_comm	0x00200001	/* УСК ОУ буфера команд */
#define	SKB_buf_comm_CNTR	0x01000202	/* СКБ буфера команд контроллера */
#define	SKB_buf_comm_MNTR	0x01001010	/* СКБ буфера команд монтиора */
#define	SKB_buf_date		0x01000202	/* СКБ буфера данных */
#endif /* MMR_OLD_VERSION */

#ifdef MMR_OLD_VERSION
#define MMR_ADDR_CNTRL_INFRM_BUFFERS_DATAS		0x1000	/* адрес области памяти */
								/* управляющей информации */
								/* буферов данных */
#endif /* MMR_OLD_VERSION */

/* Коды сообщений об ошибках и сбоях */
#ifdef MMR_OLD_VERSION
/* Ошибочный параметр */
#define ERRPARAM  			1
/* Ошибки системы контроля */
#define ERRMNTRSYS  		2
/* Уточнить состояние ОУ */
#define SPECCONDTERM  		3
/* ОС не соответствует адресу ОУ */
#define RECWORDNOTADDTERM  	4
/* Ошибка при обращении к ioctl */
#define ERROR_ACCESS_IOCTL 	5
/* Ошибка при исполнении ioctl() */
#define ERROR_IOCTL         7
/* Ошибка при сличении информации */
#define ERROR_COMPARED      8
/* Не получен признак Запрос на обслуживание */
#define NOT_UPKEEP      	9
/* Номер подмассива адаптера != номеру подмассив ФП */
#define DIFF_NUM_SUBARRAYS 	10
#else
/* Ошибочный параметр */
#define ERRPARAM  			1
/* Ошибки системы контроля */
#define ERRMNTRSYS  		2
/* Уточнить состояние ОУ */
#define SPECCONDTERM  		3
/* ОС не соответствует адресу ОУ */
#define RECWORDNOTADDTERM  	4
/* Ошибка при обращении к ioctl */
#define ERROR_ACCESS_IOCTL 	5
/* Не получено прерывание и адаптер не обнулил бит */
#define NOT_INTR_NO_STOP    6
/* Aдаптер не обнулил бит */
#define NO_STOP_ADAPTER    7
/* Ошибка при исполнении ioctl() */
#define ERROR_IOCTL         8
/* Не получено прерывание */
#define NOT_INTR         	9
/* Ошибка РОШ */
#define ERROR_ROCH          10
/* Ошибка при сличении информации */
#define ERROR_COMPARED      11
/* Не получен признак Запрос на обслуживание */
#define NOT_UPKEEP      	12
/* Номер подмассива адаптера != номеру подмассив ФП */
#define DIFF_NUM_SUBARRAYS 	13
/* Версия драйвера ВК не соответствует версии модуля */
#define ERRORVERDRVVK		164
#endif /* MMR_OLD_VERSION */

/* Типы командных слов */
#define UNARY_COMM_WORD      0
#define DOUBLE_COMM_WORD     1

/*	Макрос для преобразования размера массива из элементов некоторой структуры
	с учетом кратности блоку обмена в режиме DMA.
	nelem - исходное число элементов в массиве
	elsize - размер элемента в байтах
	off - смещение массива относительно начала области в которой он находится
	bsize - размер блока обмена в режиме DMA
	результат - скорректированное число элементов в массиве для обеспечения
	кратности MMR_DMA_BURST_SIZE */

#define	TU_MMR_DMA_BURST_SIZE_ALIGN(nelem, elsize, off, bsize) ((((((nelem) * \
		(elsize) + (off) + ((bsize)-1)) / (bsize)) * (bsize)) \
		- (off)) / (elsize))

/*  При обменах используется карта обменов. Элементами карты
	являются подустройства. Каждый из них имеет собственный номер и тип -
	приемник или передатчик. Подустройство с одним номером может быть и
	приемником, и передатчиком, в любом случае они рассматриваются как
	независимые и каждый является полноценным элементом карты обменов.
	Для организации обменов с любым подустройством используются буфера, имеющие
	следующую структуру:
						  ____________________________________
	 mmr_iosubd_desc -> |     заголовок буфера обмена      |
						|      (содержит дескриптор        |
						|       результатов обмена)        |
						|----------------------------------|
	 mmr_data_buf    -> |      буфер, принимаемых          |
						|     или передаваемых данных      |
						|__________________________________|

	   Заголовок буфера обмена является обязательным элементом каждого буфера,
	находится в его начале, содержит некоторую информацию об обмене
	и имеет фиксированный размер - 8 слов (32 байта), что совпадает
	с размером блока обмена между каналом и основной памятью в режиме
	непосредственного доступа (DMA). Непосредственно данные,
	принятые из канала или передаваемые в канал, следуют вслед за заголовком.
	   Пример описания такого рода структуры приведен ниже и рекомендуется для
	использован в пользовательских программах, поскольку такая же структура
	буфера используется в драйвере и библиотечных функциях 'open_mmr_drv.h'.
	   Буфера обменов для всех подустройств, составляющих карту обменов с
	каналом, в необходимом количестве будут выделены при инициализации режима
	обменов (открытии канала MMR, см далее). Указатели
	на созданные буфера карты возвращаются как результат инициализации,
	в виде массива, в котором индекс указателя является номером данного буфера
	в общем пуле буферов. Буфер карты обменов представляет собой массив
	буферов. Для каждого подустройства отведены по два
	буфера - для приемника и для передатчика. Каждый буфер обмена
	абонента инициализирован как конкретный экземпляр структуры
	'mmr_iosubdbuf_t' описанной далее, где размер буфера данных
	MMR_MAX_DATA_BUF_SIZE полагаются равными значению, поданному в
	качестве параметра инициализации канала. В заголовке буфера установлены
	в соответствующие значения все фиксированные поля).
*/

/*  Структура дескриптора буфера (заголовок буфера обмена), из
	которых состоит карта обменов для  MMR включает в себя описание
	заявки на обмен.
		Заголовок буфера обмена является обязательным элементом каждого буфера
	абонента, находится в его начале и должен иметь фиксированный
	размер - 8 слов (32 байта), что совпадает с размером блока обмена между
	каналом и основной памятью в режиме непосредственного доступа (DMA).
	В связи с этим структура дополняется до 8 слов неиспользуемыми полями.
	Непосредственно данные принятые из канала или передаваемые в канал следуют
	вслед за заголовком.
 */

#define MMR_TBLPPP	 0x00 /* Триггер блокировки прерывания ПП по RERR[0] != 0 */
#define MMR_TPPP     0x04 /* Триггер прерывания программы пользователя (ПП) */
#define MMR_TPCHSH   0x08 /* Триггер признака четности системной шины */
#define MMR_TBZ      0x0C /* Триггер блокировки значимости регистра УСК */
#define MMR_TZCH     0x14 /* Триггер запроса в SBus шину */
#define MMR_RERR     0x10 /* Регистр ошибок */
#define MMR_RNKSH    0x18 /* Регистр номера канала в шине */
#define MMR_TZM      0x20 /* Триггер обнуления модуля */
#define MMR_REG_CTRL 0x24 /* Регистр управления */

#ifdef MMR_OLD_VERSION
#define base_reg   		0x300001 /* Базовое значение РОБ */
#else
#define base_reg   		0x300101 /* Базовое значение РОБ v 4 */
#define base_reg_v5   		0x300141 /* Базовое значение РОБ v 5 */
#endif /* MMR_OLD_VERSION */
#define err_answer_word		0x0405  /* Интегрированная ошибка ОС */
#define err_word_mntr		0x4bdf  /* Интегрированная ошибка ВСК */

/* Структура РОБ */
#ifdef MY_DRIVER_BIG_ENDIAN
typedef union mmr_reg_general
{
	u_int          rdwr_reg_general;
	struct
		{
			u_int  bit3129 : 3; /* Тип командных слов */
			u_int  bit2824 : 5; /* Адрес ОУ */
			u_int  bit23	: 1; /* Блокировать запись команд в БК ОУ */
			u_int  bit22 	: 1; /* Занято ОУ */
			u_int  bit21	: 1; /* Блокировать 1-й канал контроллера */
			u_int  bit20 	: 1; /* Блокировать 0-й канал контроллера */
			u_int  bit19 	: 1; /* ОУ требует обслуживания */
			u_int  bit18 	: 1; /* Разрешение на принятие управления */
			u_int  bit17 	: 1; /* Блокировать ошибки */
			u_int  bit16 	: 1; /* Искажать четность данных */
			u_int  bit15 	: 1; /* Режим монитора (запуск) */
			u_int  bit14 	: 1; /* Режим ОУ (запуск на выполнение */
			u_int  bit13 	: 1; /* Режим контроллера (запуск) */
			u_int  bit1206 : 7; /* РНКШ - RNKSH */
			u_int  bit0503 : 3; /* РОШ - RERR */
			u_int  bit02   : 1; /* ТПЧСШ - TPCHSH */
			u_int  bit01   : 1; /* ТППП - TPPP */
			u_int  bit00   : 1; /* ТБЛППП - TBLPPP */
		} as_bits_0;
} mmr_reg_general_t;
#else
typedef union mmr_reg_general
{
	u_int          rdwr_reg_general;
	struct
		{
			u_int  bit00   : 1; /* ТБЛППП - TBLPPP */
			u_int  bit01   : 1; /* ТППП - TPPP */
			u_int  bit02   : 1; /* ТПЧСШ - TPCHSH */
			u_int  bit0503 : 3; /* РОШ - RERR */
			u_int  bit1206 : 7; /* РНКШ - RNKSH */
			u_int  bit13   : 1; /* Режим контроллера (запуск) */
			u_int  bit14   : 1; /* Режим ОУ (запуск на выполнение */	
			u_int  bit15   : 1; /* Режим монитора (запуск) */
			u_int  bit16   : 1; /* Искажать четность данных */
			u_int  bit17   : 1; /* Блокировать ошибки */
			u_int  bit18   : 1; /* Разрешение на принятие управления */
			u_int  bit19   : 1; /* ОУ требует обслуживания */
			u_int  bit20   : 1; /* Блокировать 0-й канал контроллера */
			u_int  bit21   : 1; /* Блокировать 1-й канал контроллера */
			u_int  bit22   : 1; /* Занято ОУ */
			u_int  bit23   : 1; /* Блокировать запись команд в БК ОУ */
			u_int  bit2824 : 5; /* Адрес ОУ */
			u_int  bit3129 : 3; /* Тип командных слов */
		} as_bits_0;
} mmr_reg_general_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

/* Номер подмассива буфера обмена 
#define num_subarray_buf	as_bits_0.bit3129 */
/* Адрес ОУ */
#define address_terminal 	as_bits_0.bit2824
/* Блокировать запись команд в БК ОУ */
#define blokade_read_command as_bits_0.bit23
/* Занято ОУ */
#define busy_terminal	   	as_bits_0.bit22
/* Блокировать 1-й канал контроллера */
#define blokade_channel1   	as_bits_0.bit21
/* Блокировать 0-й канал контроллера */
#define blokade_channel0   	as_bits_0.bit20
/* ОУ требует обслуживания */
#define service_terminal 	as_bits_0.bit19
/* Разрешение на принятие управления */
#define accept_control 		as_bits_0.bit18
/* Блокировать ошибки */
#define blokade_error  		as_bits_0.bit17
/* Искажать четность данных */
#define broren_parity  		as_bits_0.bit16
/* Режим монитора (запуск на выполнение) */
#define run_monitor   		as_bits_0.bit15
/* Режим ОУ (запуск на выполнение */
#define run_terminal 		as_bits_0.bit14
/* Режим контроллера (запуск на выполнение очередной ГК) */
#define run_controller		as_bits_0.bit13
#define	reg_RNKSH			as_bits_0.bit1206 	/* РНКШ - RNKSH */
#define	reg_RERR			as_bits_0.bit0503 	/* РОШ - RERR */
#define	trg_TPCHSH			as_bits_0.bit02 	/* ТПЧСШ - TPCHSH */
#define	trg_TPPP			as_bits_0.bit01 	/* ТППП - TPPP */
#define	trg_TBLPPP			as_bits_0.bit00 	/* ТБЛППП - TBLPPP */

/* Структура регистра управления */
#ifdef MY_DRIVER_BIG_ENDIAN
typedef union mmr_reg_cntrl
{
	u_int          wr_mmr_reg_cntrl;
	struct
		{
			u_int  bit3119 : 13; /* не исп */
			u_int  bit1816 : 3;  /* Тип командных слов */
			u_int  bit1511 : 5;  /* Адрес ОУ */
			u_int  bit10   : 1;  /* Блокировать запись команд в БК ОУ */
			u_int  bit09   : 1;  /* Занято ОУ */
			u_int  bit08   : 1;  /* Блокировать 1-й канал контроллера */
			u_int  bit07   : 1;  /* Блокировать 0-й канал контроллера */
			u_int  bit06   : 1;  /* ОУ требует обслуживания */
			u_int  bit05   : 1;  /* Разрешение на принятие управления */
			u_int  bit04   : 1;  /* Блокировать ошибки */
			u_int  bit03   : 1;  /* Искажать четность данных */
			u_int  bit02   : 1;  /* Режим монитора (запуск на выполнение) */
			u_int  bit01   : 1;  /* Режим ОУ (запуск на выполнение */
			u_int  bit00   : 1;  /* Режим контроллера (запуск на выполнение очередной ГК) */
		} as_bits_1;
} mmr_reg_cntrl_t;
#else
typedef union mmr_reg_cntrl
{
	u_int          wr_mmr_reg_cntrl;
	struct
		{
			u_int  bit00   : 1;  /* Режим контроллера (запуск на выполнение очередной ГК) */
			u_int  bit01   : 1;  /* Режим ОУ (запуск на выполнение */
			u_int  bit02   : 1;  /* Режим монитора (запуск на выполнение) */
			u_int  bit03   : 1;  /* Искажать четность данных */
			u_int  bit04   : 1;  /* Блокировать ошибки */
			u_int  bit05   : 1;  /* Разрешение на принятие управления */
			u_int  bit06   : 1;  /* ОУ требует обслуживания */
			u_int  bit07   : 1;  /* Блокировать 0-й канал контроллера */
			u_int  bit08   : 1;  /* Блокировать 1-й канал контроллера */
			u_int  bit09   : 1;  /* Занято ОУ */
			u_int  bit10   : 1;  /* Блокировать запись команд в БК ОУ */
			u_int  bit1511 : 5;  /* Адрес ОУ */
			u_int  bit1816 : 3;  /* Тип командных слов */
			u_int  bit3119 : 13; /* не исп */
		} as_bits_1;
} mmr_reg_cntrl_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

/* Тип командных слов */
#define type_comm_word   	as_bits_1.bit1816 
/* Адрес ОУ */
#define address_term      	as_bits_1.bit1511
/* Блокировать запись команд в БК ОУ */
#define blokade_read_comm   as_bits_1.bit10
/* Занято ОУ */
#define busy_term		   	as_bits_1.bit09
/* Блокировать 1-й канал контроллера */
#define blokade_ch1   		as_bits_1.bit08
/* Блокировать 0-й канал контроллера */
#define blokade_ch0   		as_bits_1.bit07
/* ОУ требует обслуживания */
#define service_term   		as_bits_1.bit06
/* Разрешение на принятие управления */
#define accept_cntrl   		as_bits_1.bit05
/* Блокировать ошибки */
#define blokade_err		   	as_bits_1.bit04
/* Искажать четность данных */
#define broren_part		   	as_bits_1.bit03
/* Режим монитора (запуск на выполнение) */
#define run_mntr   			as_bits_1.bit02
/* Режим ОУ (запуск на выполнение */
#define run_term   			as_bits_1.bit01
/* Режим контроллера (запуск на выполнение очередной ГК) */
#define run_ctrl   			as_bits_1.bit00

/* Структура регистра команды управления и обмена данными */

#ifdef MY_DRIVER_BIG_ENDIAN
typedef union mmr_reg_comm
{
	u_short		  wr_mmr_reg_comm;
	struct
		{
			u_short  bit1511  : 5;  /* Адрес ОУ */
			u_short  bit10 	  : 1;  /* Направление передачи */
			u_short  bit0905  : 5;  /* Подадрес/Режим управления */
			u_short  bit0400  : 5;  /* Число СД/Код команды */
		} as_bits_2;
} mmr_reg_comm_t;
#else
typedef union mmr_reg_comm
{
	u_short		  wr_mmr_reg_comm;
	struct
		{
			u_short  bit0400  : 5;  /* Число СД/Код команды */
			u_short  bit0905  : 5;  /* Подадрес/Режим управления */
			u_short  bit10 	  : 1;  /* Направление передачи */
			u_short  bit1511  : 5;  /* Адрес ОУ */
		} as_bits_2;
} mmr_reg_comm_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

/* Адрес ОУ */
#define addr_term      		as_bits_2.bit1511
/* Направление передачи */
#define set_trans   		as_bits_2.bit10
/* Подадрес/Режим управления */
#define subaddr_cntrl   	as_bits_2.bit0905
/* Число СД/Код команды */
#define numword_codecomm  	as_bits_2.bit0400

/* Структура слова данных */
#ifdef MY_DRIVER_BIG_ENDIAN
typedef union mmr_word_date
{
	u_short		  wr_mmr_word_date;
	struct
		{
			u_short  bit1511  : 5;  /* Адрес ОУ */
			u_short  bit10 	  : 1;  /* не исп */
			u_short  bit0905  : 5;  /* Подадрес */
			u_short  bit0400  : 5;  /* Текущий номер СД */
		} as_bits_5;
} mmr_word_date_t;
#else
typedef union mmr_word_date
{
	u_short		  wr_mmr_word_date;
	struct
		{
			u_short  bit0400  : 5;  /* Текущий номер СД */
			u_short  bit0905  : 5;  /* Подадрес */
			u_short  bit10 	  : 1;  /* не исп */
			u_short  bit1511  : 5;  /* Адрес ОУ */
		} as_bits_5;
} mmr_word_date_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

/* Адрес ОУ */
#define addr_trmnl      	as_bits_5.bit1511 
/* Подадрес */
#define subaddr				as_bits_5.bit0905
/* Текущий номер СД */
#define serial_num_word 	as_bits_5.bit0400 

/* Структура ответного слова */
#ifdef MY_DRIVER_BIG_ENDIAN
typedef union mmr_answer_word
{
	u_short		  wr_mmr_answer_word;
	struct
		{
			u_short  bit1511  : 5;  /* Адрес ОУ */
			u_short  bit10 	  : 1;  /* Ошибка в сообщении */
			u_short  bit09    : 1;  /* Передача ОС */
			u_short  bit08    : 1;  /* Запрос на обслуживание */
			u_short  bit0705  : 3;  /* резерв */
			u_short  bit04    : 1;  /* Принята групповая команда */
			u_short  bit03 	  : 1;  /* Абонент занят */
			u_short  bit02    : 1;  /* Неисправность абонента */
			u_short  bit01    : 1;  /* Принято управление интерфейсом */
			u_short  bit00    : 1;  /* Неисправность ОУ */
		} as_bits_3;
} mmr_answer_word_t;
#else
typedef union mmr_answer_word
{
	u_short		  wr_mmr_answer_word;
	struct
		{
			u_short  bit00    : 1;  /* Неисправность ОУ */
			u_short  bit01    : 1;  /* Принято управление интерфейсом */
			u_short  bit02    : 1;  /* Неисправность абонента */
			u_short  bit03 	  : 1;  /* Абонент занят */
			u_short  bit04    : 1;  /* Принята групповая команда */
			u_short  bit0705  : 3;  /* резерв */
			u_short  bit08    : 1;  /* Запрос на обслуживание */	
			u_short  bit09    : 1;  /* Передача ОС */
			u_short  bit10 	  : 1;  /* Ошибка в сообщении */
			u_short  bit1511  : 5;  /* Адрес ОУ */
		} as_bits_3;
} mmr_answer_word_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

/* Адрес ОУ */
#define addr_terminal		as_bits_3.bit1511
/* Ошибка в сообщении */
#define err_msg				as_bits_3.bit10
/* Передача ОС */
#define trans_AW			as_bits_3.bit09
/* Запрос на обслуживание */
#define demand_upkeep		as_bits_3.bit08
/* Принята групповая команда */
#define generic_comm_accept	as_bits_3.bit04
/* Абонент занят */
#define abonent_buzy		as_bits_3.bit03
/* Неисправность абонента */
#define abonent_faulty		as_bits_3.bit02
/* Принято управление интерфейсом */
#define ctrl_interfice		as_bits_3.bit01
/* Неисправность ОУ */
#define terminal_faulty		as_bits_3.bit00

/* Структура регистра ВСК */
#ifdef MY_DRIVER_BIG_ENDIAN
typedef union mmr_reg_word_mntr
{
	u_short		  wr_mmr_reg_word_mntr;
	struct
		{
			u_short  bit15  : 1;
			u_short  bit14  : 1;
			u_short  bit13  : 1;
			u_short  bit12  : 1;
			u_short  bit11  : 1;
			u_short  bit10 	: 1;
			u_short  bit09  : 1;
			u_short  bit08  : 1;
			u_short  bit07  : 1;
			u_short  bit06  : 1;
			u_short  bit05  : 1;
			u_short  bit04  : 1;
			u_short  bit03 	: 1;
			u_short  bit02  : 1;
			u_short  bit01  : 1;
			u_short  bit00  : 1;
		} as_bits_4;
} mmr_reg_word_mntr_t;
#else
typedef union mmr_reg_word_mntr
{
	u_short		  wr_mmr_reg_word_mntr;
	struct
		{
			u_short  bit00  : 1;
			u_short  bit01  : 1;
			u_short  bit02  : 1;
			u_short  bit03  : 1;
			u_short  bit04  : 1;
			u_short  bit05  : 1;
			u_short  bit06 	: 1;
			u_short  bit07  : 1;
			u_short  bit08  : 1;
			u_short  bit09  : 1;
			u_short  bit10  : 1;
			u_short  bit11  : 1;
			u_short  bit12  : 1;
			u_short  bit13 	: 1;
			u_short  bit14  : 1;
			u_short  bit15  : 1;
		} as_bits_4;
} mmr_reg_word_mntr_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

/* Выполнена команда управления 
#define command_fulfill			as_bits_4.bit15 */
/* Команда не выполнена за 800 мкс */
#define command_not_carr		as_bits_4.bit14 
/* УПДМ не может вовремя обслужить запрос */
#define serve_not_demand		as_bits_4.bit13
/* Команда выполнена 
#define command_carr_out 		as_bits_4.bit12 */
/* Оконечное устройство к моменту выдачи ответного слова */
/* не получило ответ из УПДМ */
#define term_output_reciv_word  as_bits_4.bit11
/* Прием - передача */
#define reciv_trans				as_bits_4.bit10
/* Ошибка четности */
#define error_parity			as_bits_4.bit09
/* Длительность импульса бита информации не соответствует ГОСТ */
#define durat_impulse_not		as_bits_4.bit08
/* Длительность второй половины синхроимпульса не соответствует ГОСТ */
#define durat_second_not		as_bits_4.bit07
/* Длительность первой половины синхроимпульса не соответствует ГОСТ */
#define durat_first_not			as_bits_4.bit06
/* Номер активного канала 
#define num_active_chnl			as_bits_4.bit05 */
/* Оконечное устройство приняло недопустимую команду управления */
#define accept_inadm_comm		as_bits_4.bit04
/* Занят регистр данных к моменту приема СД из МКИО */
#define reg_datas_occup			as_bits_4.bit03
/* Пуст регистр данных к моменту выдачи СД в МКИО */
#define reg_datas_empty			as_bits_4.bit02
/* Контроллер принял ответное слово с неверным адресом */
/* оконечного устройства */
#define accept_incorr_addr		as_bits_4.bit01
/* Контроллер не принял ответное слово. */
/* Оконечное устройство вовремя не передало ответное слово. */
#define  not_recip_word			as_bits_4.bit00

#ifndef MMR_OLD_VERSION
/* Структура регистра общего при получении прерывания */
#ifdef MY_DRIVER_BIG_ENDIAN
typedef union mmr_reg_common
{
	u_int          wr_mmr_reg_common;
	struct
		{
			u_int  bit3128 : 4; /* указатель на на субблок, с */
								 /* которым был обмен для БД */
			u_int  bit2724 : 4; /* указатель на на субблок, с */
								 /* которым был обмен для БК */
			u_int  bit2319 : 5; /* указатель на на блок, с */
								 /* которым был обмен для БД */
			u_int  bit1814	: 5; /* указатель на на блок, с */
								 /* которым был обмен для БК */
			u_int  bit13	: 1; /* кол-во заполненных блоков 1 - 1 блок */
								 /* 0 - 2 блока */
			u_int  bit1206 : 7; /* номер версии адаптера или буфера обмена */
			u_int  bit0500 : 6; /* не используется */
		} as_bits_5;
} mmr_reg_common_t;
#else
typedef union mmr_reg_common
{
	u_int          wr_mmr_reg_common;
	struct
		{
			u_int  bit0500 : 6; /* не используется */
			u_int  bit1206 : 7; /* номер версии адаптера или буфера обмена */
			u_int  bit13   : 1; /* кол-во заполненных блоков 1 - 1 блок, 0 - 2 блока */
			u_int  bit1814 : 5; /* указатель на блок, с которым был обмен для БК */
			u_int  bit2319 : 5; /* указатель на блок, с которым был обмен для БД */
			u_int  bit2724 : 4; /* указатель на субблок, с которым был обмен для БК */
			u_int  bit3128 : 4; /* указатель на субблок, с которым был обмен для БД */
		} as_bits_5;
} mmr_reg_common_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

/* Указатель на на субблок, с которым был обмен для БД */
#define pointer_subblock_exch  	as_bits_5.bit3128 
/* Указатель на на субблок, с которым был обмен для БК */
#define pointer_subblock_comm  	as_bits_5.bit2724
/* Указатель на на субблок, с которым был обмен для БД */
#define pointer_block_exch		as_bits_5.bit2319
/* Указатель на на субблок, с которым был обмен для БК */
#define pointer_block_comm		as_bits_5.bit1814
/* Кол-во заполненных блоков */
#define num_full_block			as_bits_5.bit13
/* Номер версии адаптера */
#define num_version_or_buf		as_bits_5.bit1206
#endif /* MMR_OLD_VERSION */

/* Чтения/запись содержимого регистра МMR */
typedef struct arg_reg {
	int		reg_addr;	/* адрес регистра */
	u_int		reg_value;	/* возвращаемая/передаваемая величина */
} mmr_arg_reg_t;

/* Структура заголовка буфера обмена */
typedef struct mmr_iosubd_desc {
	u_char	cur_num_subarray;  /* текущий номер подмассива */
	u_char	next_num_subarray; /* следующий номер подмассива */
	u_short	unused1;		   /* не используется */
/* Массив счетчиков кол-ва слов (МПКО) в подмассиве БД */
	u_char	amount_words[8];
	u_short	cur_addr_subarray_del;   /* текущий адрес подмассива */
	u_short	next_addr_subarray_del;  /* следующий адрес подмассива */
	short	buf_num;        /* номер буфера обмена */
	u_short io_flags; 		/* код операции обмена */
	u_short data_size; 		/* максимальная длина в байтах массива обмена */
	short	unused5; 		/* не используется */
	int	unused_word6; 	/* не используется */
	int	unused_word7; 	/* не используется */
} mmr_iosubd_desc_t;

/*	Структура буфера данных для обмена.
	Буфер данных представляет собой обычный массив и в данной структуре он
	представлен в виде объединения массивов разных форматов.
	Размер буфера при необходимости корректируется для обеспечения
	кратности блоку обмена
*/
typedef union mmr_data_buf_ {
	u_short
								/* массив слов данных обмена */
								/* слово в смысле канала MMR */
								/* (2 байта, 16 бит) */
		words[TU_MMR_DMA_BURST_SIZE_ALIGN(MMR_MAX_DATA_BUF_SIZE /
				sizeof(u_short),
			sizeof(u_short), 0, MMR_DMA_BURST_SIZE)];
	u_int
								/* массив слов основной */
								/* памяти (4 байта 32 бит) */
		longs[TU_MMR_DMA_BURST_SIZE_ALIGN(MMR_MAX_DATA_BUF_SIZE /
			sizeof(u_int), sizeof(u_int), 0,
			MMR_DMA_BURST_SIZE)];
	u_char
								/* массив байтов */
		bytes[TU_MMR_DMA_BURST_SIZE_ALIGN(MMR_MAX_DATA_BUF_SIZE,
			sizeof(u_char), 0, MMR_DMA_BURST_SIZE)];
} mmr_data_buf_t;

/*  Описания структуры буфера обмена.
	Драйвер создает и инициализирует общие буфера как конкретные
	экземпляры именно данной структуры. При этом в заголовке буфера
	инициализированы все поля с фиксированными и
	постоянными значениями.
*/
typedef struct mmr_iosubdbuf {
	mmr_iosubd_desc_t       buf_desc;  /* дескриптор буфера и результатов */
	mmr_data_buf_t  	data_buf;  /* область буфера данных для передачи */
} mmr_iosubdbuf_t;

/*  Описания структуры элемента карты обменов.
	Данная структура является внутренним представлением карты обменов
	и на пользователя непосредственно не выходит.
*/
typedef struct mmr_iomap_subd {
	mmr_iosubdbuf_t	write;  /* буфер передатчика */
	mmr_iosubdbuf_t	read;	/* буфер приемника */

} mmr_iomap_subd_t;

/*  Описания карты обменов - массив буферов всех подустройств.
	Данная структура является внутренним представлением карты обменов
	оконечника и на пользователя непосредственно не выходит.
*/
typedef mmr_iomap_subd_t		mmr_iomap_t;

/* Описание структуры параметров инициализации буферов обмена данными */
typedef struct mmr_init_iomap {
	u_short		buf_num;		/* число буферов обмена данными */
	u_short		max_data_buf_trans_size;
					/* максимальный размер передающего буфера данных */
	u_short		max_data_buf_reciv_size;
					/* максимальный размер приемного буфера данных */
	size_t		*real_buf_size_p;
								/* указатель на переменную */
								/* для записи реального */
								/* размера буфера карты */
								/* обменов c учетом */
								/* необходимых кратностей */
								/* адресов и размеров*/
	int		*error_code_p;				/* указатель на переменную */
								/* для записи кода ошибки, */
								/* если таковая будет */
								/* обнаружена в процессе */
								/* инициализации */
	int		flag_board;				/* признак устройства: */
								/* контроллер или ОУ */
} mmr_init_iomap_t;


/* Описание структуры параметров останова обменов и закрытия канала */
#ifdef MMR_OLD_VERSION
typedef struct mmr_halt_trans {
	int		waiting_time;		/* время ожидания завершения */
								/* последнего обмена и */
								/* закрытия канала, после */
								/* которого все буфера */
								/* обменов удаляются */
								/* если 0, то ожидания нет */
								/* буфера будут удалены при */
								/* следующей инициализации */
								/* или при закрытии уст-ва */
								/* ( close() ) */
								/* если < 0, то ожидать */
								/* следует не более времени */
								/* заданного при открытии */
								/* в качестве значения */
								/* таймера для контроля */
								/* зависания обменов */
								/* если > 0, то это время в */
								/* микросекундах, после */
								/* которого все буфера  */
								/* обменов удаляются */
} mmr_halt_trans_t;
#else
typedef struct mmr_halt_trans {
	int		waiting_time;		/* время ожидания завершения */
								/* последнего обмена и */
								/* закрытия канала, после */
								/* которого все буфера */
								/* обменов удаляются */
	hrtime_t	max_time_waiting; /* макс. Т ожидания выполнения команды */
	hrtime_t	med_time_waiting; /* среднее Т ожидания выполнения команды */
	hrtime_t	min_time_waiting; /* мин. Т ожидания выполнения команды */
	u_int       	allocation_time_intr[GISTOGR];
	hrtime_t	max_time_adapter; /* макс. Т выполнения команды адаптером */
	hrtime_t	med_time_adapter; /* среднее Т выполнения команды адаптером */
	hrtime_t	min_time_adapter; /* мин. Т выполнения команды адаптером */
	u_int       	allocation_time_adapter[GISTOGR];
	u_int		max_comm; /* макс. кол-во не обслуженных команд */
	u_int      	allocation_comm[GISTOGR_COMM];
} mmr_halt_trans_t;
#endif /* MMR_OLD_VERSION */
/*  Структура, описывающая информацию о связи устройства с открытым
	дескриптором файла.
	Подается для заполнения в соответствующую команду, реализованную через
	ioctl() вызов
*/
typedef	struct mmr_dev_info {
	int			instance;	/* экземпляр MMR */
	int			channel;	/* номер канала */
} mmr_dev_info_t;

#ifndef MMR_OLD_VERSION
typedef struct mmr_drv_info
{
	int			sbus_clock_freq;	/* частота синхронизации SBus */
	int			sbus_nsec_cycle;	/* период следования tick-ов SBus */
	int			mp_clock_freq;		/* частота синхронизации SBus */
							/* микропроцессора */
	int			mp_nsec_cycle;		/* период следования tick-ов МП */
	hrtime_t    		cur_hr_time;		/* текущее время в нсек */
}	mmr_drv_info_t;
#endif /* MMR_OLD_VERSION */

/* Структура, описывающая информацию для команды MMRIO_INTR_TIME_WAIT */
#ifdef MMR_OLD_VERSION 
typedef struct mmr_intr_wait {
	u_long	intr_wait_time;			/* время ожидания прерывания (мксек) */
	u_long	event_intr;			/* код события */
	u_long	board_error;		 	/* внутренняя ошибка платы */
	u_long	pointer_reciv_comm;		/* указатель на записанную команду */
						/* в буфере команд ФП */
	u_long	cur_num_comm;			/* кол-во записанных команд */
} mmr_intr_wait_t;
#else
typedef struct mmr_intr_wait {
	u_long		intr_wait_time;			/* время ожидания прерывания (мксек) */
	u_long		event_intr;			/* код события */
	u_long		board_error;		 	/* внутренняя ошибка платы */
	u_int		num_reciv_comm;			/* кол-во записанных команд в буфер */
							/* команд ФП по инф. адаптера */
	u_int		cur_num_comm;			/* кол-во записанных команд */
	u_int		intr_device; 			/* РОБ при получении прерывания от адаптера */
	hrtime_t	time_get_intr_device;		/* Т получения прерывания от адаптера нсек */
	hrtime_t	time_get_comm; 			/* Т получения драйвером команды на выдачу */
							/* прерывания нсек */
} mmr_intr_wait_t;

#endif /* MMR_OLD_VERSION */

#ifndef MMR_OLD_VERSION
/* Получение информации о прерываниях по РОШ */
typedef struct intr_rosh
{
	u_short		num_intr_rosh;			/* кол-во прерываний по РОШ */
} mmr_intr_rosh_t;
#endif /* MMR_OLD_VERSION */

/* Буфера данных адаптера */
typedef struct buf_data {
	u_int	area_subbuf0[8];
	u_int	area_subbuf1[8];
} buf_data_t;

/* Управляющая информация буферов адаптера */
typedef struct buf_args {
	u_int	USK; /* УСК */
	u_int	AC0; /* АС0 */
	u_int	SKB; /* СКБ */
	u_int	AC1; /* АС1 */
} buf_args_t;

/* Связь программы теста и БОЗУ */
typedef struct mmr_area_bozu {
	buf_data_t  /* Информация буферов данных адаптера */
				buf_data[MMR_BUF_ADAPTER_NUM*2];
	buf_args_t  /* Управляющая информация буферов данных адаптера */
				init_buf_data[MMR_BUF_ADAPTER_NUM*2];
	buf_data_t  /* Информация буфера команд адаптера */
				buf_comm;
	buf_args_t  /* Управляющая информация буфера команд адаптера */
				init_buf_comm;
} mmr_area_bozu_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _UAPI_LINUX_MMR_IO_H__ */
