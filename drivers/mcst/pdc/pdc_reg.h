/* 
*
* 	Written by Alexey V. Sitnikov, alexmipt@mcst.ru, 2005
*
*/

#define ONCE_OPENING	0

#define PDC_INT_TRACE	0



#define AS_WORD(x)		(x.word) 
#define AS_STRUCT(x)		(x.fields)

/*               		Смещения регистров PDC 		     		*/

/******				PLVC Control Register				******/

/* Rst 			- общий сброс PDC								*/
/* Rmode		- Режим работы контроллера по приему 
				 0 - прямой: PCI Master <- PCI Master, PCI Slave <- PCI Slave 
				 0 - перекрестный: PCI Master <- PCI Slave, PCI Slave <- PCI Master 	*/
/* Hmode		- Hide режим.
				В этом режиме контроллер не откликается на обращения в свое 
				конфигурационное пространство 						*/
/* PI_pin3 - PI_pin0	- Определяют номер ножки(ек) PCI прерывания					*/
/* MV_NMI_en		- Разрешает выставление NMI прерывания при сбросе бита MV 			*/
/* SV_NMI_en		- Разрешает выставление NMI прерывания при сбросе бита SV 			*/
/* Err_NMI_en		- Разрешает выставление NMI прерывания при неустранимой ошибке 			*/

/* MV_PI_en		- Разрешает выставление PCI прерывания при сбросе бита MV 			*/
/* SV_PI_en		- Разрешает выставление PCI прерывания при сбросе бита SV 			*/
/* Err_PI_en		- Разрешает выставление PCI прерывания при неустранимой ошибке 			*/

typedef	struct Control_Reg_fields {	/* Structure of PLVC Control Register */
	u32	Rst		: 1;		/* [ 0: 0] 	*/
	u32	Rmode		: 1;		/* [ 1: 1] 	*/
	u32	Hmode		: 1;		/* [ 2: 2] 	*/
	u32	Reserved	: 17;		/* [19: 3] 	*/
	u32	PI_pin0		: 1;		/* [20:20]	*/
	u32	PI_pin1		: 1;		/* [21:21]	*/
	u32	PI_pin2		: 1;		/* [22:22]	*/
	u32	PI_pin3		: 1;		/* [23:23]	*/
	u32	Reserved1	: 1;		/* [24:24] 	*/
	u32	Err_PI_en	: 1;		/* [25:25]	*/
	u32	SV_PI_en	: 1;		/* [26:26]	*/
	u32	MV_PI_en	: 1;		/* [27:27]	*/
	u32	Reserved2	: 1;		/* [28:28]	*/
	u32	Err_NMI_en	: 1;		/* [29:29]	*/
	u32	SV_NMI_en	: 1;		/* [30:30]	*/
	u32	MV_NMI_en	: 1;		/* [31:31]	*/	
} Control_Reg_fields_t;

typedef union Control_Reg {
	Control_Reg_fields_t	fields;
	u32			word;
} Control_Reg_t;
	 

/******				PLVC Status Register				******/

/* NMI 			- Бит статуса внешнего прерывания. 
			  Пропись 0 - снятие прерывания,
			  Запись 1 - генерация удаленного прерывания (c текущим регистром Статуса
				ничего не происходит).
			  Выставляется:
				- при сбрасывании бита MV, если MV_NMI_en установлен в 1 		
				- при сбрасывании бита SV, если SV_NMI_en установлен в 1
				- при возникновении неустранимой ошибки, если Err_NMI_en установлен в 1
				- при удаленном выставлении NMI прерывания 				*/

/* PI 			- Бит статуса PI прерывания. 
			  Пропись 0 - снятие прерывания,
			  Запись 1 - генерация удаленного прерывания (c текущим регистром Статуса
				ничего не происходит).
			  Выставляется:
				- при сбрасывании бита MV, если MV_PI_en установлен в 1 		
				- при сбрасывании бита SV, если SV_PI_en установлен в 1
				- при возникновении неустранимой ошибки, если Err_PI_en установлен в 1
				- при удаленном выставлении PI прерывания 				*/

/* Err			- Бит статуса неустранимой ошибки. Пропись 0 - снятие, запись 1 - не имеет эффекта */

/* NMI_Src_MV 		- Только чтение, сброс бита MV - источник NMI прерывания.  */
/* NMI_Src_SV 		- Только чтение, сброс бита SV - источник NMI прерывания.  */
/* NMI_Src_Err 		- Только чтение, неустранимая ошибка - источник NMI прерывания.  */
/* NMI_Src_Rm 		- Только чтение, удаленное выставление - источник NMI прерывания.  */

/* PI_Src_MV 		- Только чтение, сброс бита MV - источник PI прерывания.  */
/* PI_Src_SV 		- Только чтение, сброс бита SV - источник PI прерывания.  */
/* PI_Src_Err 		- Только чтение, неустранимая ошибка - источник PI прерывания.  */
/* PI_Src_Rm 		- Только чтение, удаленное выставление - источник PI прерывания.  */

typedef	struct Status_Reg_fields {	/* Structure of PLVC Status Register */
	u32	NMI		: 1;		/* [ 0: 0]	*/
	u32	PI		: 1;		/* [ 1: 1]	*/
	u32	Err		: 1;		/* [ 2: 2]	*/
	u32	Reserved	: 21;		/* [23: 3]	*/
	u32	PI_Src_Rm	: 1;		/* [24:24]	*/
	u32	PI_Src_Err	: 1;		/* [25:25]	*/
	u32	PI_Src_SV	: 1;		/* [26:26]	*/
	u32	PI_Src_MV	: 1;		/* [27:27]	*/
	u32	NMI_Src_Rm	: 1;		/* [28:28]	*/
	u32	NMI_Src_Err	: 1;		/* [29:29]	*/
	u32	NMI_Src_SV	: 1;		/* [30:30]	*/
	u32	NMI_Src_MV	: 1;		/* [31:31]	*/
} Status_Reg_fields_t;

typedef union Status_Reg {
	Status_Reg_fields_t	fields;
	u32			word;
} Status_Reg_t;


/******				Master Control Register				******/	

/* MV 			- Пропись 1 в это поле запускает PCI Master. Сбрасывается 
			  автоматически по завершении задачи					*/

/* C_MRB		- Очистка Master Recieve Buffer при записи 1, запись 0 не имеет эффекта		*/

/* C_MTB		- Очистка Master Transmit Buffer при записи 1, запись 0 не имеет эффекта	*/

/* MCmd			- Команда, с которой PCI Master выходит на шину 				*/

/* MSize		- Размер приема/передачи в DW (4 байта)						*/

typedef	struct Master_Control_Reg_fields {	/* Structure of PLVC Status Register */
	u32	MV		: 1;		/* [ 0: 0]	*/
	u32	C_MRB		: 1;		/* [ 1: 1]	*/
	u32	C_MTB		: 1;		/* [ 2: 2]	*/
	u32	Reserved	: 5;		/* [ 7: 3]	*/
	u32	MCmd		: 4;		/* [11: 8]	*/
	u32	Reserved1	: 4;		/* [15:12]	*/
	u32	MSize		: 16;		/* [31:16]	*/
} Master_Control_Reg_fields_t;

typedef union Master_Control_Reg {
	Master_Control_Reg_fields_t	fields;
	u32				word;
} Master_Control_Reg_t;

/******				Master Address Register				******/

/* MAddress		- Адрес, с которым PCI Master выходит на шину 					*/

typedef struct Master_Address_Reg_fields {
	u32		MAddress;
} Master_Address_Reg_fields_t;

typedef union Master_Address_Reg {
	Master_Address_Reg_fields_t	fields;
	u32				word;
} Master_Address_Reg_t;

/******				Slave Control Register				******/	

/* SV 			- Пропись 1 в это поле запускает PCI Slave. Сбрасывается 
			  автоматически по завершении задачи.
			  Пропись 0 в это поле сбрасывает задачу.					*/

/* C_SRB		- Очистка Slave Recieve Buffer при записи 1, запись 0 не имеет эффекта		*/

/* C_STB		- Очистка Slave Transmit Buffer при записи 1, запись 0 не имеет эффекта	*/

/* SDir			- Определяет направление передачи
				1 - передача данных по чтению на PCI
				0 - передача данных по записи на PCI					*/

/* SSize		- Размер приема/передачи в DW (4 байта)						*/

typedef	struct Slave_Control_Reg_fields {	/* Structure of PLVC Status Register */
	u32	SV		: 1;		/* [ 0: 0]	*/
	u32	C_SRB		: 1;		/* [ 1: 1]	*/
	u32	C_STB		: 1;		/* [ 2: 2]	*/
	u32	Reserved	: 5;		/* [ 7: 3]	*/
	u32	SDir		: 1;		/* [ 8: 8]	*/
	u32	Reserved1	: 7;		/* [15:	9]	*/
	u32	SSize		: 16;		/* [31:16]	*/
} Slave_Control_Reg_fields_t;

typedef union Slave_Control_Reg {
	Slave_Control_Reg_fields_t	fields;
	u32				word;
} Slave_Control_Reg_t;

/******				Slave Data Register				******/

/* SData		- Расположение регистра определяет адрес для Slave доступа к данным		*/

typedef struct Slave_Data_Reg_fields {
	u32		SData;
} Slave_Data_Reg_fields_t;

typedef union Slave_Data_Reg {
	Slave_Data_Reg_fields_t fields;
	u32	word;
} Slave_Data_Reg_t;

/******				Slave Recieve Buffer Count Register				******/

/* SRBC		- Число DW в Slave Recieve Buffer. Достуаен только по чтению		*/

typedef struct Slave_RBC_Reg_fields {
	u32		SRBC;
} Slave_RBC_Reg_fields_t;

typedef union Slave_RBC_Reg {
	Slave_RBC_Reg_fields_t fields;
	u32	word;
} Slave_RBC_Reg_t;

/******				Slave Transmit Buffer Count Register				******/

/* STBC		- Число DW в Slave Transmit Buffer. Достуаен только по чтению		*/

typedef struct Slave_TBC_Reg_fields {
	u32		STBC;
} Slave_TBC_Reg_fields_t;

typedef union Slave_TBC_Reg {
	Slave_TBC_Reg_fields_t fields;
	u32	word;
} Slave_TBC_Reg_t;

/******				Master Recieve Buffer Count Register				******/

/* MRBC		- Число DW в Master Recieve Buffer. Достуаен только по чтению		*/

typedef struct Master_RBC_Reg_fields {
	u32		MRBC;
} Master_RBC_Reg_fields_t;

typedef union Master_RBC_Reg {
	Master_RBC_Reg_fields_t fields;
	u32	word;
} Master_RBC_Reg_t;

/******				Master Transmit Buffer Count Register				******/

/* MTBC		- Число DW в Master Transmit Buffer. Достуаен только по чтению		*/

typedef struct Master_TBC_Reg_fields {
	u32		MTBC;
} Master_TBC_Reg_fields_t;

typedef union Master_TBC_Reg {
	Master_TBC_Reg_fields_t fields;
	u32	word;
} Master_TBC_Reg_t;

#if 0
#define CONTROL_REGISTER 	1
#define STATUS_REGISTER 	2
#define MASTER_CONTROL_REGISTER	3
#define MASTER_ADDRESS_REGISTER 4
#define SLAVE_CONTROL_REGISTER	5
#define SLAVE_DATA_REGISTER	6
#define SRBC_REGISTER		7
#define STBC_REGISTER		8
#define MRBC_REGISTER		9
#define MTBC_REGISTER		10

#else
#define CONTROL_REGISTER 	0
#define STATUS_REGISTER 	1
#define MASTER_CONTROL_REGISTER	2
#define MASTER_ADDRESS_REGISTER 3
#define SLAVE_CONTROL_REGISTER	4
#define SLAVE_DATA_REGISTER	5
#define SRBC_REGISTER		6
#define STBC_REGISTER		7
#define MRBC_REGISTER		8
#define MTBC_REGISTER		9
#endif

