/*
 *
 * Ported in Linux by Alexey V. Sitnikov, alexmipt@mcst.ru, MCST, 2004
 *
 */

#ifndef	_LINUX_MMR_H__
#define	_LINUX_MMR_H__

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/slab.h>

#include <linux/mcst/linux_mmr_io.h>

#ifndef cv_destroy
#define cv_destroy(arg)
#endif

//void debug_mmr(const char *fmt,...){}
//#define debug_mmr	delay_printk
#ifndef MMR_OLD_VERSION
/* Версия драйвера ВК */
#define	VER_DRV_VK_MMR		0x17040504
#define	work_var_drv_vk		16

#define	MMR_MAX_SIZE_BUFFER_DMA	0x40000 /* Макс. размер буфера ППД */
#endif /* MMR_OLD_VERSION */

/* Список причин прерываний */
typedef enum   intr_rsn
{
	undefined_intr_reason   = 0, /* неопределенная причина прерывания */
	reject_intr_reason      = 1, /* прерывание отклоняется */
	get_intr_reason_mmr     = 2, /* получено прерывание от ММР */
	board_error_intr_reason = 3  /* внутренняя ошибка платы */
} intr_reason_t;

/* Управляющая информация буферов данных */
typedef struct buf_datas_args {
	u_int	USK_TRANS; /* УСК передатчика */
	u_int	AC0_TRANS; /* АС0 передатчика */
	u_int	SKB_TRANS; /* СКБ передатчика */
	u_int	AC1_TRANS; /* АС1 передатчика */
	u_int	USK_RECIV; /* УСК приемника */
	u_int	AC0_RECIV; /* АС0 приемника */
	u_int	SKB_RECIV; /* СКБ приемника */
	u_int	AC1_RECIV; /* АС1 приемника */
} buf_datas_args_t;

/* Управляющая информация буферов данных */
typedef union ctrl_buf_datas {
	buf_datas_args_t
		init_buf_data[MMR_BUF_ADAPTER_NUM];
/* максимальная область памяти */
	u_int	args_area[MMR_BUF_ADAPTER_NUM*8];
} ctrl_buf_datas_t;


/* Управляющая информация буфера команд */
typedef struct buf_comm_args {
	u_int	USK; /* УСК */
	u_int	AC0; /* АС0 */
	u_int	SKB; /* СКБ */
	u_int	AC1; /* АС1 */
} buf_comm_args_t;

/* Буфера команд адаптера */
typedef struct buffer_data {
	u_int	area_subbuf0[8];
	u_int	area_subbuf1[8];
} buffer_data_t;

/* Управляющая информация буфера команд */
typedef union ctrl_buf_comm {
	buf_comm_args_t
		init_buf_comm;
/* максимальная область памяти управляющей информации буфера команд */
	u_int	args_area[4];
} ctrl_buf_comm_t;

/* Связь драйвера ВК и платы ММР */
typedef struct drv_comm_memory {
	ctrl_buf_datas_t   ctrl_buf_datas; /* Управляющая информация буферов данных */
	buffer_data_t  	   buffer_command; /* Информация буфера команд адаптера */
	ctrl_buf_comm_t    ctrl_buf_comm;  /* Управляющая информация буфера команд */
} drv_comm_memory_t;

#define	MMR_DRV_COMM_FREE_TIMEOUT_DEF_VALUE	(1000000)	 /* 1 seconds */

/* Локальные определения */

#define MMR_DEVN(d)	(getminor(d))		/* dev_t -> minor (dev_num) */
#define MMR_inst(m)	(m >> 4)		/* minor -> instance */
#define MMR_chan(m)	(m & 0xf)		/* minor -> channel */
#define MMR_MINOR(i,c)	((i << 4) | (c))	/* instance+channel -> minor */
#define MMR_INST(d)	MMR_inst(MMR_DEVN(d))	/* dev_t -> instance */
#define MMR_CHAN(d)	MMR_chan(MMR_DEVN(d))	/* dev_t -> channel */

#define	CHNL_NUM_TO_MASK(chnl)		(1 << chnl)

/* Разрядные поля для attach_flags: */

#define SOFT_STATE_ALLOCATED		0x0001
#define INTERRUPT_ADDED				0x0002
#define MUTEX_ADDED					0x0004
#define CHANNEL_CV_ADDED			0x0008
#define REGS_MAPPED					0x0010
#define MINOR_NODE_CREATED			0x0020
#define IOPB_ALLOCED				0x0040
#define ERRORS_SIGN					0x0080
#define IBLOCK_COOKIE_ADDED			0x0200
#define	INTR_IBLOCK_COOKIE_ADDED	0x0400
#define	INTR_MUTEX_ADDED			0x0800
#define	TRANS_HALTED_CV_ADDED		0x1000
#define	CNCT_POLLING_CV_ADDED		0x2000
#define	TRANS_STATE_CV_ADDED		0x4000

#ifndef MMR_OLD_VERSION
/* Имена реквизитов устройства */
#define SBUS_INTR_L_NAME_OF_PROP 	"interrupts"
#endif /* MMR_OLD_VERSION */

/* Обобщенные структуры пересылок и результатов */

typedef struct dma_struct {
	caddr_t		prim_buf_addr;
	size_t		real_size;
	dma_addr_t	busa;		/* Address in the SBus space,*/ 
					/* Адрес области dma со стороны устройства */
	unsigned long	*mem; 	/* Address in the processor space,*/
					/*  Адрес области dma со стороны процессора */
	int				size;
} dma_struct_t;

/* Структура буфера пересылки */
typedef struct trbuf_desc {
	caddr_t			buf_address;	/* виртуальный адрес буфера пересылки */
	size_t			buf_size;	/* байтовый размер буфера пересылки */
/*	ddi_acc_handle_t	acc_handle;*/	/* буфер обработки доступа */
/*	ddi_dma_handle_t	dma_handle;*/	/* буфер обработки DMA */
/*	ddi_dma_cookie_t	cookie;	   */	/* буфер DMA маркеров */
/*	uint_t			ccount;	   */	/* число буферов DMA маркеров */
	dma_struct_t		dma;		/* Буфер, описывающий DMA */
} trbuf_desc_t;

/* Структура буфера пересылки.
 Буфер содержит буфера пользователей */
typedef struct trbuf_state {
	char		valid_flag;		/* допустимый буфер пересылки */
	trbuf_desc_t	trans_buf_desc; 	/* дескриптор буфера пересылки */
	caddr_t		user_buf_address;	/* виртуальный адрес начального */
						/* буфера пользователя */
	size_t		user_buf_size;		/* байтовый размер буфера пользователя */
	int		max_user_buf_num;	/* макс. число буферов пользователя */
						/*  в буфере драйвера */
	caddr_t		user_trans_bufs[MMR_BUF_USER_NUM];		/* список указателей буферов пересылки */
									/*  пользователя */
	dma_addr_t	dma_trans_bufs[MMR_BUF_USER_NUM]; 		/* список dma указателей буферов пересылки */
									/* пользователя */
} trbuf_state_t;

/* Внутреннее состояние канала */
typedef struct mmr_chnl_state {

	trbuf_state_t	trans_buf_state;	/* состояние буфера пересылки */
	char	trans_state_is_init;		/* установка состояния пересылки */
	char	state_init_in_progress;		/* выполняется инициализация  */
	char	trans_state_is_halt;		/* состояние пересылки - останов */
	char	all_trans_finish;			/* все пересылки завершены */
	char	init_as_trans_map;			/* канал инициализирован в режиме */
							/* карты обмена*/
	mmr_init_iomap_t init_iomap_state_spec;		/* состояние инициализации карты */
	size_t	full_data_buf_size;			/* полный размер буфера данных */
	size_t	subdev_buf_trans_size;			/* размер передающего буфера, */
							/* включая заголовок */
	size_t	subdev_buf_reciv_size;			/* размер приемного буфера, */
							/* включая заголовок */
	int		dma_intr_handled;		/* прерывание обработано верно */
	u_short		trans_num;			/* номер пакетной пересылки */
} mmr_chnl_state_t;

/* Внутреннее состояние драйвера */
typedef struct mmr_state {
	struct of_device	*op;
	dev_t		dev;
	int			dev_type;
	int			inst;			/* номер экземпляра */
	int			major;			/* мажор экземпляра */
	int			irq;			/* номер прерывания */
	int			flag_board;		/* тип устройства: К или ОУ */
	int			opened;			/* открытое состояние */
	int			open_flags;		/* открытое состояние с флажком */
	u_int		open_channel_map;	/* маска открытых каналов */
	/***********************************************/
	raw_spinlock_t	lock;
	kcondvar_t	channel_cv;		/* переменная условий */
							/* (режима, состояний) канала */
	kcondvar_t	drv_comm_cv;		/* область связи драйвера: занятая или */
							/* свободная, переменная условия */
	kcondvar_t	trans_state_cv; 	/* состояние канала пересылки, */
							/* изменение переменной условия */
	kcondvar_t	intr_cv;		/* переменная условий для прерывания */
        /***********************************************/
/*	ddi_iblock_cookie_t	iblock_cookie; */	/* для mutexes. */
/*	struct pollhead		pollhead;      */	/* глухая структура для опроса */
	int			drv_comm_busy;		/* признак занятости области */
							/* связи драйвера */
#ifdef MMR_OLD_VERSION
	int       	drv_general_modes;		/* общие признаки режимов драйвера */
#endif /* MMR_OLD_VERSION */
	e90_unit_t	type_unit;			/* тип платы */

	char		intr_seted;			/* прерывание установлено */
	char		intr_number;			/* число прерываний */
	ulong_t		io_flags_intr;		  	/* признак прерывания ПрП */
	ulong_t		flags_intr_rerr;		/* признак прерывания по РОШ */
#ifdef MMR_OLD_VERSION
	ulong		pointer_reciv_comm;		/* указатель на записанную команду  */
							/* в буфере команд ФП */
#else
	u_int		num_reciv_comm;			/* кол-во записанных команд в буфер */
							/* команд ФП по инф. адаптера */
#endif /* MMR_OLD_VERSION */
	u_int		cur_num_comm;			/* кол-во записанных команд */
#ifndef MMR_OLD_VERSION
	u_int		intr_dev;		    	/* РОБ при получении прерывания от адаптера */
	hrtime_t	time_get_intr_dev;  		/* Т получения прерывания от адаптера */
#endif /* MMR_OLD_VERSION */
	mmr_reg_cntrl_t	mmr_reg_cntrl_dev;	 	/* структура регистра управления ММР */
	int		system_burst;			/* DMA размеры пачки, позволенные SBUS */

	volatile caddr_t	MMR_BMEM;		/* base memory */

	mmr_chnl_state_t   	channel_state[1];       /*состояние канала платы */
/*	ddi_acc_handle_t	acc_regs; */ 		/* указатель на дескриптор доступа к регистрам */
	caddr_t		regs_base;		/* базовый адрес регистров */
	off_t		reg_array_size;   	/* размер выделенной области */
							/* регистров */
#ifndef MMR_OLD_VERSION
	u_short		number_intr_rosh; 		/* кол-во прерываний по РОШ */
#endif /* MMR_OLD_VERSION */	
} mmr_state_t;

/* Макрокоманды для обращения к регистрам */
/* Виртуальный адрес регистра */
#define	MMR_REGISTER_ADDR(state, reg)	((ulong_t *)(state->regs_base + reg))
/* Чтения содержимого регистра */
#define	READ_MMR_REGISTER(state, reg)	ddi_getl(state->dev_type, MMR_REGISTER_ADDR(state, reg))
/* Запись в регистр */
#define	WRITE_MMR_REGISTER(state, reg, v)	ddi_putl(state->dev_type, MMR_REGISTER_ADDR(state, reg), v)

static long
mmr_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

static int mmr_open(struct inode *inode, struct file *file);

static int mmr_mmap(struct file *file, struct vm_area_struct *vma);

static int mmr_close(struct inode *inode, struct file *file);

#endif	/* _LINUX_MMR_H__ */
