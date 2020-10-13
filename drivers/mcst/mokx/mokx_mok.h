#ifndef	__MOKX_MOK_H__
#define	__MOKX_MOK_H__

/*
 * Define for MOK_X
 */
#define MOK_X_INFO_MSG(x...)		printk(x)
#define MOK_X_ERROR_MSG(x...)		printk(x)
#define MOK_X_DBG_MSG(x...)		printk(x)

#define MOK_X_PLD_DBG_MODE		1
#define MOK_X_PLD_DBG_ERROR_MSG(x...)	if (MOK_X_PLD_DBG_MODE) printk(x)

#define MOK_X_MDIO_DBG_MODE		1
#define MOK_X_MDIO_DBG_ERROR_MSG(x...)	if (MOK_X_MDIO_DBG_MODE) printk(x)

typedef	unsigned int mok_x_status_reg_t; /* single word (32 bits) */
typedef	struct mok_x_status_reg_fields {
	/* 0,    Резерв 0 */
	mok_x_status_reg_t	reserv0			:1;
	/* 1,    Резерв 1 */
	mok_x_status_reg_t	timeout_msg_receive	:1;
	/* 2,    Резерв 2 */
	mok_x_status_reg_t	mode4			:1;
	/* 3,rw  Режим работы MODE3 */
	mok_x_status_reg_t	mode3			:1;
	/* 4,rw  Режим работы MODE2 */
	mok_x_status_reg_t	mode2			:1;
	/* 5,rw  Режим работы MODE1 */
	mok_x_status_reg_t	mode1			:1;
	/* 6,rw  in_ready_to_receive - указывает что противоположная сторона */
	/* готова принимать данные        				     */
	mok_x_status_reg_t	in_ready_to_receive	:1;
	/* 7,rw  granted_packet - установка этого бита задействует механизм */
	/* гарантированной доставки всех пакетов.			    */
	mok_x_status_reg_t	granted_packet		:1;
	/* 8,rw  granted_last_packet - установка этого бита за действует */
	/* механизм  гарантированной доставки последнего пакета в обмене.*/
	mok_x_status_reg_t	granted_last_packet	:1;
	/* 9,rw  ready_to_receive - бит, разрешающий принимать данные. Если   */
	/* этот бит не установлен, то все входящие пакеты данных сохраняются  */
	/* в приёмном буфере и буфере передатчика на противоположной стороне. */
	mok_x_status_reg_t	ready_to_receive	:1;
	/* 10,rw enable_receive - разрешение приёма данных. Если этот бит не */
	/* установлен, то все входящие пакеты данных игнорируются.           */
	mok_x_status_reg_t	receive_enable		:1;
	/* 11,rw enable_transmit - разрешение передачи данных. */
	mok_x_status_reg_t	transmit_enable		:1;
	/* 12,rw slave - бит, указывающий на то что эта сторона ведомая. */
	mok_x_status_reg_t	slave			:1;
	/* 13,rw master - бит, указывающий на то что эта сторона ведущая. */
	mok_x_status_reg_t	master			:1;
	/* 14,r  enable - информационный бит. Указывает на то, что устройство */
	/* может быть задействовано для приёма/передачи данных. */
	mok_x_status_reg_t	enable			:1;
	/* 15,r  link - идикатор соединения. */
	mok_x_status_reg_t	link			:1;
	mok_x_status_reg_t	unused17		:1;
	mok_x_status_reg_t	unused16		:1;
	mok_x_status_reg_t	unused18		:1;
	mok_x_status_reg_t	unused19		:1;
	mok_x_status_reg_t	unused20		:1;
	mok_x_status_reg_t	unused21		:1;
	mok_x_status_reg_t	unused22		:1;
	mok_x_status_reg_t	unused23		:1;
	mok_x_status_reg_t	unused24		:1;
	mok_x_status_reg_t	unused25		:1;
	mok_x_status_reg_t	unused26		:1;
	mok_x_status_reg_t	unused27		:1;
	mok_x_status_reg_t	unused28		:1;
	mok_x_status_reg_t	unused29		:1;
	mok_x_status_reg_t	unused30		:1;
	mok_x_status_reg_t	unused31		:1;
} mok_x_status_reg_fields_t;

typedef	union mok_x_status_reg_struct {		/* Structure of word */
	mok_x_status_reg_fields_t	fields;	/* as fields */
	mok_x_status_reg_t		word;	/* as entire register */
} mok_x_status_reg_struct_t;

#endif  /*__MOKX_MOK_H__*/
