
/* Редакция файла mcap_io.h:
			ИМВС - 10.02.05; home - 16.05.04 
01.02.05 возврат к версии драйвера МП .05 от 29.06.04			
10.02.05 ввод версии драйвера МП .06 от 10.02.05
13.03.05 ввод версии драйвера МП .07 от 04.03.05				
*/

/* Определения и структуры, используемые драйвером ВК
  и пользовательскими программами */

#ifndef	_UAPI__LINUX_MCAP_IO_H__
#define	_UAPI__LINUX_MCAP_IO_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include <linux/mcst/linux_me90_io.h>

/* Версия модуля */
#ifdef MCAP_OLD_VERSION
#define	VERSION_MODULE_MC19		0x04030507
/* Рабочие варианты */
#define	work_var_drv_MP			10
#else
#define VERSION_MODULE_MCAP             0x14010608
/* Рабочие варианты */
#define work_var_drv_MP                 11
#endif /* MCAP_OLD_VERSION */
#ifdef MCAP_OLD_VERSION
#define	work_var_module			work_var_drv_MP
#else
#define	work_var_module_MCAP		work_var_drv_MP	
#endif /* MCAP_OLD_VERSION */

/* Список команд реализованных в драйвере модуля MCAP и исполняемых
   посредством системного вызова ioctl()
*/

#ifdef MCAP_OLD_VERSION
#define MCAP_IO			('M' << 8)
#define	MCAPIO_READ_DEVICE_REG			(MCAP_IO | 1)
#define	MCAPIO_WRITE_DEVICE_REG			(MCAP_IO | 2)
#define	MCAPIO_INIT_BUFERS_EXCHANGE		(MCAP_IO | 3)
#define	MCAPIO_HALT_TRANSFER_MODES		(MCAP_IO | 4)
#define	MCAPIO_GET_DEVICE_INFO			(MCAP_IO | 5)
#define	MCAPIO_INTR_TIME_WAIT			(MCAP_IO | 6)
#define	MCAPIO_MESSAGE_NOTE			(MCAP_IO | 7)

#define MCAP_CNTR_ST_REG_SET_OFFSET		0x10000 /* Смещение области регистров */
#define MCAP_CNTR_ST_REG_SET_LEN       		0x100	/* Размер области регистров */
#define	MCAP_BMEM_REG_SET_OFFSET		0x40000 /* Смещение основной памяти */
#define	MCAP_BMEM_REG_SET_LEN			0x20000 /* Размер области основной памяти */
#define MCAP_DRV_CMN_AREA_BMEM_ADDR		0x01990	/* Начальный адрес управляющей */
							/* информации буферов данных */
#define MCAP_AREA_BMEM_ADDR			0xD0	/* Начальный адрес информации */
							/* БОЗУ */
#else
#define MCAP_IO                 ('M' << 8)
#define MCAPIO_LOAD_MP_DRV_CODE                 (MCAP_IO | 1)
#define MCAPIO_STARTUP_MP_DRV                   (MCAP_IO | 2)
#define MCAPIO_STARTUP_MP_ROM_DRV               (MCAP_IO | 3)
#define MCAPIO_RESET_MP                         (MCAP_IO | 4)
#define MCAPIO_GET_DRIVER_INFO                  (MCAP_IO | 5)
/************************************************************************/
#define MCAPIO_READ_DEVICE_REG                  (MCAP_IO | 6)
#define MCAPIO_WRITE_DEVICE_REG                 (MCAP_IO | 7)
#define MCAPIO_INIT_BUFERS_EXCHANGE             (MCAP_IO | 8)
#define MCAPIO_HALT_TRANSFER_MODES              (MCAP_IO | 9)
#define MCAPIO_GET_DEVICE_INFO                  (MCAP_IO | 10)
#define MCAPIO_INTR_TIME_WAIT                   (MCAP_IO | 11)
#define MCAPIO_MESSAGE_NOTE                     (MCAP_IO | 12)
/************************************************************************/
#define MCAPIO_NUM_INTR_ROSH                    (MCAP_IO | 13)
                                                                                                              
#define MCAP_ROOT_E90_NAME                      "ROOT_E90"
#define MCAP_MP_INIT_DEFAULT_CODE       	{0xfaea0000, 0x00000000}
                                                /* CLI JUMP, JUMP_address end */
#define MCAP_MP_INIT_JUMP_ADDR_OFF              2
#define MCAP_MP_INIT_AREA_BMEM_ADDR             0x1fff0
/************************************************************************/
#define MCAP_BMEM_REG_SET_OFFSET                0x40000 /* Смещение основной памяти */
#define MCAP_BMEM_REG_SET_LEN                   0x20000 /* Размер области ОП */
/************************************************************************/
#define MCAP_DRV_CMN_AREA_BMEM_ADDR     	0x01990 /* Начальный адрес управляющей */
                                                        /* информация буферов данных */
#define MCAP_AREA_BMEM_ADDR                     0xD0    /* Начальный адрес информации */
                                                        /* БОЗУ */
#endif /* MCAP_OLD_VERSION */


/* 
   Список кодов ошибок, вырабатываемых драйвером (в основном его МП-частью)
   при исполнении команд реализованных через ioctl()
   (возможные значения поля drv_error_code в используемых для этих команд
   структурах)
*/

#define FINISH_TRANS       1 /* Завершена выдача данных в канал */
#define START_RECIV        2 /* Начат прием пакета данных из канала */
#define FINISH_RECIV       3 /* Завершен прием пакета данных из канала */

#define	BCW_HARDWARE_MCAP_ERROR		12

/* Коды ошибок */
#define NO_ERROR                 0 /* Канал инициализирован (открыт) */
#define ERROR_INIT_BUFFERS       0x01 /* Версия адаптера не соответствует */
									  /* версии драйвера МП */
#define ERROR_PLACE_MODE_MNIR    0x02 /* Не произведено отключение каналов */
									  /* от линий связи */
#define ERROR_PLACE_MODE_BATTLE  0x04 /* Не произведено подключение каналам */
									  /* к линиям связи */
#define ERROR_HALT_CHANNEL       0x08 /* Канал не инициализирован (закрыт) */
#define FAILURE_TRANS         	 0x10 /* Сбой в канале при передаче данных */
#define FAILURE_RECIV		 0x20 /* Сбой в канале при приеме данных */

 /* Значения битов регистра состояния передатчика */
#define bit_trns		0xFC /* код выделения битов при передаче данных */
#define err_trns		0x0C /* код ошибок при передаче данных */

#define sig_warning		0x80 /* принят сигнал ПРЕДУПРЕЖДЕНИЕ */
#define trans_word		0x40 /* передано очередное слово в канал */
#define user_data_tr		0x20 /* в канал передается инф-ция пользователя */
#define end_array_tr		0x10 /* в канал передан последний байт */
				     /* массива пользователя */
#define sign_pbozy_tr		0x08 /* принят сигнал ABOZU */
#define false			0x04 /* после передачи слова нет сигнала ВЕРНО */
#ifdef MCAP_OLD_VERSION
#define not_trans_2		0x02 /* резерв */
#else
#define congestion_prd  	0x02 /* перегрузка системы обмена данными */
#endif /* MCAP_OLD_VERSION */
#define not_trans_1	    	0x01 /* резерв */

/* Значения битов регистра состояния приемника */
#define bit_rcv			0xFE /* код выделения битов при приеме данных */
#define err_rcv			0x6A /* код ошибок при передаче данных */

#define end_array_rv		0x80 /* принят последний байт в буфер */
							 /* данных приемника */
#define sign_pbozy_rv		0x40 /* принят сигнал ABOZU */
#define busy_buf		0x20 /* занят буфер для следующего слова */
#define reaciv_word		0x10 /* принято слово данных */
#define no_tfr			0x08 /* отсутствует тактовая частота приемника */
#define user_data_rv		0x04 /* из канала принята инф-ция пользователя */
#define mod_err			0x02 /* принято слово данных с ошибкой по mod3 */
#define not_reciv		0x01 /* резерв */

#define	MCAP_SUBDEV_BUF_NUM		4 	/* кол-во буферов обмена (каналов) */
#define	PACKET_FREQUENCY		0x0200	/* ТЧВ Пд выдается в АПД пачками */
#define	CONSTANT_FREQUENCY		0 	/* ТЧВ Пд выдается в АПД непрерывно */
#define	MCAP_HUNGUP_TIMER_INTERVAL	360000
									/* значение таймера для */
									/* ожидания завершения обменов */
									/* (в микросекундах) */

#define	MCAP_NOT_CHANGE		 0	/* не изменять */
#define	MCAP_IO_WRITE		 0x01	/* запись (передача в канал) */
#define	MCAP_IO_READ		 0x02	/* чтение (прием из канала) */
#define	MCAP_WRITE_READ		 0x03	/* запись/чтение */

#define	GISTOGR			   8   	/* Размер массива распределения времени */
/* Режимы функционированя МС19 */
#define	MODE_COUPLED		   1   	/* Работа основного ВК с АПД с */
				       	/* разрешением резервном ВК прием */
				       	/* информации */
#define	MODE_COUPLED_COMPUTERS 0x0400 

#define	MODE_STANDBY		   2	/* Работа резервного ВК с АПД только */
					/* по приему информации */
#define	MODE_STANDBY_COMPUTER  0x0100

#define	MODE_SINGLE		   3	/* Работа основного ВК с АПД с */
					/* с запретом подключения резервного ВК */
#define	MODE_SINGLE_COMPUTER   0x0600

#define	AFM   			   4	/* Наладка модуля, комп-ная наладка ВК */
#define	MODE_AFM	       0x0700 
#define	MODE_US19   		   5	/* Работа ВК по проверке УС19 */
#define	AUDIT_TE	   	   6 	/* Проверка модуля по ТУ */

#define	NOT_RESTORE   		   0	/* не восстанавливать УСК, СКБ и АС0 */
#define	RESTORE  	           1	/* восстановить УСК, СКБ и АС0 канала */

#define	NOT_EXCHANGE_DATAS	   0	/* не выдавать в канал слова пакета */
					/* данных после фиксации ошибки обмена */
#define	EXCHANGE_DATAS         	   1	/* выдавать в канал слова пакета данных */
					/* после фиксации ошибки обмена */
#define	NOT_PRODUCE_INTR	   0	/* драйвер МП не должен выдавать */
					/* прерывания */
#define	PRODUCE_INTR           	   1	/* драйвер должен МП выдавать прерывания */

#define	MCAP_DMA_BURST_SIZE	   8*4	/* размер (в байтах) блока обмена */

#ifdef MCAP_OLD_VERSION
#define	MCAP_MAX_NUM_WORD	0xFFF
#define	MCAP_MAX_WORD_DATA_BUF_TRANS	256 	/* макимальная длина в словах передающего буфера обмена канала */
#define	MCAP_MAX_WORD_DATA_BUF_RECIV	3568 	/* макимальная длина в словах приемного буфера обмена */
#else
#define MCAP_MAX_WORD_DATA_BUF_TRANS    4088    /* макимальная длина в словах передающего буфера обмена канала */
#define MCAP_MAX_WORD_DATA_BUF_RECIV    4095    /* макимальная длина в словах приемного буфера обмена */
#endif /* MCAP_OLD_VERSION */
#define	MCAP_MAX_DATA_BUF_SIZE		MCAP_MAX_WORD_DATA_BUF_RECIV*4	/* макимальная длина в байтах */
									/* приемного буфера обмена канала */
/* Коды сообщений об ошибках и сбоях */
/* Версия драйвера ВК не соответствует версии модуля */
#define ERRORVERDRVVK		164


/*	Макрос для преобразования размера массива из элементов некоторой структуры
	с учетом кратности блоку обмена в режиме DMA.
	nelem - исходное число элементов в массиве
	elsize - размер элемента в байтах
	off - смещение массива относительно начала области в которой он находится
	bsize - размер блока обмена в режиме DMA
	результат - скорректированное число элементов в массиве для обеспечения
	кратности MCAP_DMA_BURST_SIZE */

#define	TU_MCAP_DMA_BURST_SIZE_ALIGN(nelem, elsize, off, bsize) ((((((nelem) * \
		(elsize) + (off) + ((bsize)-1)) / (bsize)) * (bsize)) \
		- (off)) / (elsize))

 /*  При обменах с каналами MCAP используется карта обменов. Элементами карты
 	являются подустройства. Каждый из них имеет собственный номер и тип - 
 	приемник или передатчик. Подустройство с одним номером может быть и 
 	приемником, и передатчиком, в любом случае они рассматриваются как
	независимые и каждый является полноценным элементом карты обменов.
	Для организации обменов с любым подустройством используются буфера, имеющие
	следующую структуру:
						  ____________________________________
	 mcap_iosubd_desc -> |     заголовок буфера обмена      |
						 |      (содержит дескриптор        |
						 |       результатов обмена)        |
						 |----------------------------------|
	 mcap_data_buf    -> |      буфер, принимаемых из       |
						 |     канала или передаваемых      |
						 |        в канал данных            |
						 |__________________________________|

	   Заголовок буфера обмена является обязательным элементом каждого буфера,
	находится в его начале, содержит некоторую информацию об обмене и его
	результатах и имеет фиксированный размер - 8 слов (32 байта), что совпадает
	с размером блока обмена между каналом и основной памятью в режиме
	непосредственного доступа (DMA). Непосредственно данные,
	принятые из канала или передаваемые в канал, следуют вслед за заголовком.
	На основе значения полей дескриптора результатов можно следить за тем -
	закончен обмен или нет (см. далее описание структуры заголовка).
	   Пример описания такого рода структуры приведен ниже и рекомендуется для
	использован в пользовательских программах, поскольку такая же структура
	буфера используется в драйвере и библиотечных функциях 'open_mcap_drv.h'.
	   Буфера обменов для всех подустройств, составляющих карту обменов с
	каналом, в необходимом количестве будут выделены при инициализации режима
	обменов (открытии канала MCAP, см далее). Указатели
	на созданные буфера карты возвращаются как результат инициализации,
	в виде массива, в котором индекс указателя является номером данного буфера
	в общем пуле буферов. Буфер карты обменов представляет собой массив
	буферов. Для каждого подустройства отведены по два
	буфера - для приемника и для передатчика. Каждый буфер обмена
	абонента инициализирован как конкретный экземпляр структуры
	'mcap_iosubdbuf_t' описанной далее, где размер буфера данных
	'MCAP_MAX_DATA_BUF_SIZE' полагаются равными значению, поданному в
	качестве параметра инициализации канала. В заголовке буфера установлены
	в соответствующие значения все фиксированные поля и в начальное
	(нулевое) состояние - поля дескриптора результатов обмена (см. далее
	описание заголовка, где для каждого поля указано каким образом и кем оно
	инициализируется).
*/

/*  Структура дескриптора буфера (заголовок буфера обмена), из
	которых состоит карта обменов для канала MCAP включает в себя описание
	заявки на обмен, а также поля результатов его исполнения, т.е. 
	дескриптор результатов обмена.
		Заголовок буфера обмена является обязательным элементом каждого буфера
	абонента, находится в его начале и должен иметь фиксированный
	размер - 8 слов (32 байта), что совпадает с размером блока обмена между
	каналом и основной памятью в режиме непосредственного доступа (DMA).
	В связи с этим структура дополняется до 8 слов неиспользуемыми полями.
	Непосредственно данные принятые из канала или передаваемые в канал следуют
	вслед за заголовком.
		На основе значения полей дескриптора результатов можно следить за тем
	закончен обмен или нет.
	После завершения очередного обмена с данным буфером должен обнуляться
	признак завершения обмена с буфером.
	Это позволяет пользовательской функции следить за концом
	обмена с данным буфером на основе значения признака:
	transfer_completed
	Если признак - ненулевое, то обмен завершен.
*/
#ifdef MY_DRIVER_BIG_ENDIAN
typedef union reg_general_mcap
{
	u_int          rdwr_reg_general;
	struct
		{
			u_int  bit3129 : 3; /* не используется */
			u_int  bit2824 : 5; /* РНКШШ - RNKSH */
			u_int  bit2321 : 3; /* не используется */
			u_int  bit2016 : 5; /* РОШ - ROSH */
			u_int  bit1507 : 9; /* не используется */
			u_int  bit06   : 1; /* ТПЧСШ - TPCHSH */
			u_int  bit05   : 1; /* ТСЗ - TSZ */
			u_int  bit04   : 1; /* ТПШ - TPSH */
			u_int  bit03   : 1; /* ТБЛ - TBL */
			u_int  bit02   : 1; /* ТСМ - TSM */
			u_int  bit0100 : 2; /* не используется */
		} as_bits_0;
} reg_general_mcap_t;
#else
typedef union reg_general_mcap
{
	u_int          rdwr_reg_general;
	struct
		{
			u_int  bit0100 : 2; /* не используется */
			u_int  bit02   : 1; /* ТСМ - TSM */
			u_int  bit03   : 1; /* ТБЛ - TBL */
			u_int  bit04   : 1; /* ТПШ - TPSH */
			u_int  bit05   : 1; /* ТСЗ - TSZ */
			u_int  bit06   : 1; /* ТПЧСШ - TPCHSH */
			u_int  bit1507 : 9; /* не используется */
			u_int  bit2016 : 5; /* РОШ - ROSH */
			u_int  bit2321 : 3; /* не используется */
			u_int  bit2824 : 5; /* РНКШШ - RNKSH */
			u_int  bit3129 : 3; /* не используется */
		} as_bits_0;
} reg_general_mcap_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

#define	reg_RNKSH		as_bits_0.bit2824 	/* РНКШШ - RNKSH */
#define	reg_ROSH		as_bits_0.bit2016 	/* РОШ - ROSH */
#define	trg_TPCHSH		as_bits_0.bit06 	/* ТПЧСШ - TPCHSH */
#define	trg_TSZ			as_bits_0.bit05 	/* ТСЗ - TSZ */
#define	trg_TPSH		as_bits_0.bit04 	/* ТПШ - TPSH */
#define	trg_TBL			as_bits_0.bit03 	/* ТБЛ - TBL */
#define	trg_TSM			as_bits_0.bit02 	/* ТСМ - TSM */

#define MCAP_TSM       	0x08 /* Триггер сброса модуля */
#define MCAP_TBL       	0x0C /* Триггер блокировки ошибок */
#define MCAP_TPSH      	0x10 /* Триггер прерывания программы пользователя */
#define MCAP_TSZ      	0x14 /* Триггер сброса значимости регистра УСК */
#define MCAP_TPCHSH     0x18 /* Триггер признака четности системной шины */
#define MCAP_RERR     	0x1C /* ROSH и Регистр номера канала в шине */
#define MCAP_TZM       	0x20 /* Триггер обнуления модуля */

/* Чтения/запись содержимого регистра MCAP */
typedef struct arg_reg {
	int		reg_addr;	/* адрес регистра */
	u_short		reg_value;	/* возвращаемая/передаваемая величина */
} mcap_arg_reg_t;

typedef struct mcap_iosubd_desc {
	u_short	transfer_completed;     /* признак выполнения обмен */
	u_short	channel_check_word;	/* состояние канала (ошибки обмена) */
	u_short	data_size_exchange; 	/* количество слов обмена */
	u_short	first_error; 	 	/* номер слова, при выдаче (приеме) */
					/* которого зафиксирована первая ошибка */
					/* обмена */
	u_short	num_error; 	 	/* количество ошибок обмена */
	u_short exchange_error_code;    /* код ошибки, обнаруженной драйвером MП */
	u_short signal_adapter;         /* кол-во сигналов ЗОК (ИНИ) */
	u_short	cur_ease_code;          /* текущее кол-во принятых КП */
	short	buf_num;        	/* номер буфера обмена */
	u_short io_flags; 		/* код операции обмена */
	u_short	data_size; 		/* максимальная длина в байтах массива обмена */
	short	unused2; 		/* не используется */
	int	unused_word6; 		/* не используется */
	int	unused_word7; 		/* не используется */
} mcap_iosubd_desc_t;

/*	Структура буфера данных для обмена.
	Буфер данных представляет собой обычный массив и в данной структуре он
	представлен в виде объединения массивов разных форматов.
	Размер буфера при необходимости корректируется для обеспечения
	кратности блоку обмена
*/
typedef union mcap_data_buf_ {
	u_short
								/* массив слов данных обмена */
								/* слово в смысле канала MCAP */
								/* (2 байта, 16 бит) */
		words[TU_MCAP_DMA_BURST_SIZE_ALIGN(MCAP_MAX_DATA_BUF_SIZE /
				sizeof(u_short),
			sizeof(u_short), 0, MCAP_DMA_BURST_SIZE)];
	u_int
								/* массив слов основной */
								/* памяти (4 байта 32 бит) */
		longs[TU_MCAP_DMA_BURST_SIZE_ALIGN(MCAP_MAX_DATA_BUF_SIZE /
			sizeof(u_int), sizeof(u_int), 0,
			MCAP_DMA_BURST_SIZE)];
	u_char
								/* массив байтов */
		bytes[TU_MCAP_DMA_BURST_SIZE_ALIGN(MCAP_MAX_DATA_BUF_SIZE,
			sizeof(u_char), 0, MCAP_DMA_BURST_SIZE)]; 
} mcap_data_buf_t;

/*  Описания структуры буфера обмена.
	Драйвер создает и инициализирует общие
	буфера как конкретные экземпляры именно данной структуры. При этом 
	в заголовке буфера 	инициализированы все поля с фиксированными и 
	постоянными значениями. В нулевое состояние установлены результатов обмена.
*/
typedef struct mcap_iosubdbuf {
	mcap_iosubd_desc_t
			buf_desc;  /* дескриптор буфера и результатов */
	mcap_data_buf_t
			data_buf;  /* область буфера данных для передачи в канал */
} mcap_iosubdbuf_t;

/*  Описания структуры элемента карты обменов.
	Данная структура является внутренним представлением карты обменов
	и на пользователя непосредственно не выходит.
*/
typedef struct mcap_iomap_subd {
	mcap_iosubdbuf_t	write;  /* буфер передатчика */
	mcap_iosubdbuf_t	read;	/* буфер приемника */

} mcap_iomap_subd_t;

/*  Описания карты обменов - массив буферов всех подустройств.
	Данная структура является внутренним представлением карты обменов
	оконечника и на пользователя непосредственно не выходит.
*/
typedef mcap_iomap_subd_t		mcap_iomap_t;

/* Описание структуры параметров инициализации буферов обмена данными */
typedef struct mcap_init_iomap {
	u_short	buf_num;			/* число буферов обмена данными */
	u_short	max_data_buf_trans_size;	/* максимальный размер передающего буфера данных */
	u_short	max_data_buf_reciv_size;	/* максимальный размер приемного буфера данных */
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
} mcap_init_iomap_t;


/* Описание структуры параметров останова обменов и закрытия канала */
#ifdef MCAP_OLD_VERSION
typedef struct mcap_halt_trans {
	int		waiting_time;				/* время ожидания завершения */
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
} mcap_halt_trans_t;
#else
typedef struct mcap_halt_trans {
        int             flag_close;             		/* если = 1, то произвести общий сброс модуля, */
                                                        	/* в противном случае выдать команду */
                                                        	/* драйверу МП на закрытие канала */
} mcap_halt_trans_t;
#endif /* MCAP_OLD_VERSION */

/*  Структура, описывающая информацию о связи устройства с открытым
    дескриптором файла.
    Подается для заполнения в соответствующую команду, реализованную через
    ioctl() вызов
*/
typedef	struct mcap_dev_info {
	int			instance;	/* экземпляр MCAP */
	int			channel;	/* номер канала */
} mcap_dev_info_t;

#ifdef MCAP_OLD_VERSION
typedef struct mcap_drv_info
{
	int			sbus_clock_freq;	/* частота синхронизации SBus */
	int			sbus_nsec_cycle;	/* период следования tick-ов SBus */
	int			mp_clock_freq;		/* частота синхронизации SBus */
							/* микропроцессора */
	int			mp_nsec_cycle;		/* период следования tick-ов МП */
	e90_unit_t		device_type;		/* тип устройства */
	int			mp_rom_drv_enable;	/* открытие драйвера ПЗУ */
	hrtime_t    		cur_hr_time;		/* текущее время в нсек */
}	mcap_drv_info_t;
#else
typedef struct mcap_drv_info
{
        int                     sbus_clock_freq;        /* частота синхронизации SBus */
        int                     sbus_nsec_cycle;        /* период следования tick-ов SBus */
        int                     mp_clock_freq;          /* частота синхронизации SBus */
                                                        /* микропроцессора */
        int                     mp_nsec_cycle;          /* период следования tick-ов МП */
        int                     mp_rom_drv_enable;      /* открытие драйвера ПЗУ */
        hrtime_t    		cur_hr_time;            /* текущее время в нсек */
}       mcap_drv_info_t;

typedef struct mcap_bmem_trans_desk
{
        caddr_t      mem_address;               /* SPARC memory address */
        caddr_t      mp_bmem_address;   	/* MP base memory address */
        size_t       byte_size;                 /* byte size of loaded code */
 }      mcap_bmem_trans_desk_t;

#endif /* MCAP_OLD_VERSION */

/* Структура, описывающая информацию для команды MCAPIO_INTR_TIME_WAIT */
#ifdef MCAP_OLD_VERSION
typedef struct mcap_intr_wait {
	u_long	intr_wait_time;			/* время ожидания прерывания (мксек) */
	u_short	event_intr;			/* код события */
	u_short	event_intr_trans[MCAP_SUBDEV_BUF_NUM];	/* код события передающих каналов */
	u_short	event_intr_reciv[MCAP_SUBDEV_BUF_NUM];	/* код события приемных каналов */
	hrtime_t	time_get_intr_device; 		/* Т получения прерывания от адаптера */
} mcap_intr_wait_t;
#else
typedef struct mcap_intr_wait {
        u_long  intr_wait_time;                 /* время ожидания прерывания (мксек) */
        u_short event_intr;                     /* код события */
        u_short event_intr_trans[MCAP_SUBDEV_BUF_NUM];   /* код события передающих каналов */
        u_short event_intr_reciv[MCAP_SUBDEV_BUF_NUM];   /* код события приёмных каналов */
        hrtime_t        time_get_intr_device; 		 /* Т получения прерывания от адаптера */
        u_short         num_intr_rosh;  		 /* кол-во прерываний по РОШ */
} mcap_intr_wait_t;
#endif /* MCAP_OLD_VERSION */

/* Структура, описывающая информацию о результате приема заявки на выдачу */
/* пакет данных в канал */
typedef struct user_inform_trans_ch {
	u_short		trans_error_code;  	/* код ошибки, обнаруженной драйвером MП */
	u_short		word_state_channel; 	/* состояние канала (ошибки обмена) */
	u_short		num_zok_channel;    	/* кол-во ЗОК */
} get_user_inform_trans_channel_t;

/* Структура, описывающая информацию о состоянии канала обмена */
typedef struct user_inform_state_ch {
	u_short	word_state_trans_ch; 		/* значение регистра состояния */
						/* передатчика канала (ошибки обмена) */
	u_short	number_trans_words;  		/* количество слова, переданных в канал */
	u_short	word_state_reciv_ch; 		/* значение регистра состояния */
						/* приемника канала (ошибки обмена) */
	u_short	number_reciv_words;  		/* текущий номер записанного слова в */
						/* буфер пользователя относительно */
						/* начала данного буфера */
	u_short	checked_error_code;  		/* код ошибки, обнаруженной драйвером MП */
	u_short	num_zok;  			/* кол-во ЗОК, полученных адаптером */
	u_short	num_ini;  			/* кол-во ИНИ, полученных адаптером */
} get_user_inform_state_channel_t;

/* Структура, описывающая информацию о каналах */
typedef struct inform_of_chs {
/* Текущее кол-во переданных кодов покоя адаптером */
	u_short		cur_num_ecode_trans[MCAP_SUBDEV_BUF_NUM];
/* Текущее кол-во принятых кодов покоя адаптером */
	u_short		cur_num_ecode_reciv[MCAP_SUBDEV_BUF_NUM];
/* Текущее кол-во переданных слов данных */
	u_short		cur_num_trans_word[MCAP_SUBDEV_BUF_NUM];
/* Текущее кол-во принятых слов данных */
	u_short		cur_num_reciv_word[MCAP_SUBDEV_BUF_NUM];
/* Текущий номер принятого пакета данных */
	u_short		cur_num_accept_packet[MCAP_SUBDEV_BUF_NUM];
/* Cуммарное кол-во принятых кодов покоя в предыдущем сеансе  */
	u_short		amount_ease_code[MCAP_SUBDEV_BUF_NUM];
/* Текущий указатель присмного буфера */
	u_short		cur_pointer_reciv[MCAP_SUBDEV_BUF_NUM];
} get_user_inform_of_chs_t;

#ifndef MCAP_OLD_VERSION
typedef struct mcap_rezult_reciv {
        u_short amount_code_secrete;    /* кол-во кодов начала сообщения */
        u_short escape_index_write;     /* начальный индекс записи данных в БП */
        u_short indent_data_size;       /* требуемое количество слов */
        u_short real_data_size;         /* реальное кол-во принятых слов */
        u_short not_process_word;       /* кол-во НЕ переписанных слов из ПБК */
        u_short channel_check_word;     /* состояние канала (ошибки обмена) */
        u_short first_error;            /* номер слова, при выдаче (приёме) */
                                        /* которого зафиксирована первая ошибка */
                                        /* обмена */
        u_short num_error;              /* количество ошибок обмена */
        u_short exchange_error_code;    /* код ошибки, обнаруженной драйвером MП */
        u_short signal_adapter;         /* кол-во сигналов ИНИ */
        u_short cur_ease_code;          /* текущее кол-во принятых КП */
        u_short n_process;              /* кол-во переписанных слов */
        u_short n_read;                 /* кол-во слов в БПД */
} mcap_rezult_reciv_t;

#endif /* MCAP_OLD_VERSION */

/* Структура, описывающая информацию о результате отключения каналов */
/* от линий связи */
typedef struct user_inform_turn_off_ch {
	u_short	turn_error;  	/* код ошибки, обнаруженной драйвером MП */
} get_user_inform_turn_off_ch_t;

/* Инициализации буферов обмена данными */
typedef struct delivery_note_message
{
	char		code_msg[128];		/* текст предупреждения */
	char		name_user[32];		/* имя пользователя */
} delivery_note_message_t;

#ifndef MCAP_OLD_VERSION
/* Получение информации о прерываниях по РОШ */
typedef struct intr_rosh
{
        u_short         num_intr_rosh;  /* кол-во прерываний по РОШ */
} mcap_intr_rosh_t;
#endif /* MCAP_OLD_VERSION */

/* Буфера данных адаптера */
typedef struct buf_data {
	u_int	area_subbuf0[16];
	u_int	area_subbuf1[16];
} buf_data_t;

/* Управляющая информация буферов адаптера */
typedef struct buf_args {
	u_int	USK; /* УСК */
	u_int	AC0; /* АС0 */
	u_int	SKB; /* СКБ */
	u_int	AC1; /* АС1 */
} buf_args_t;

/* Связь программы теста и БОЗУ */
typedef struct mcap_area_bozu {
	u_int		val_reg[40]; 			/* Значения регистров и триггеров */
	u_int		val_arg[24]; 			/* Параметры заданий */
	u_int		var_prog[76]; 			/* Переменные драйвера МП */
	u_int		mac_stat_mp[67]; 		/* Область статистики */
	u_int		bd_stat_drv[765]; 		/* Область трассы МП */
	buf_data_t  	buf_data[MCAP_SUBDEV_BUF_NUM*4];/* Информация буферов данных адаптера */
	buf_args_t  	init_buf_data[MCAP_SUBDEV_BUF_NUM*4];	/* Управляющая информация буферов данных адаптера */
	buf_data_t  	buf_mp;				/* Информация буфера МП */
	buf_args_t  	init_buf_mp;			/* Управляющая информация буфера МП */
	u_int		task[36]; /* Задание для драйвера МП */
	u_int		answer[16]; /* Задание для драйвера ВК */
	u_int		flag_drv; /* Признак работы МП */
	u_int		ANSWER_INTR[2]; /* Прерывание драйвера ВК */
	u_int		flag_intr; /* Признак выдачи прерывания драйверу ВК */
} mcap_area_bozu_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _UAPI__LINUX_MCAP_IO_H__ */
