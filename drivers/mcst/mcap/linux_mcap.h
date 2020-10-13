
/* Редакция файла mcap.h:
					ИМВС - 10.02.05; home - 22.04.04 */

#ifndef	__MCAP_H__
#define	__MCAP_H__
 
#include <linux/mcst/linux_mcap_io.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Версия драйвера ВК */
#ifdef MCAP_OLD_VERSION
#define	VER_DRV_VK_MC19		0x04030507
#define	work_var_drv_vk			13
#else
#define VER_DRV_VK_MCAP         0x14010608
#define work_var_drv_vk                 18
#endif /* MCAP_OLD_VERSION */

#define LOAD		2
#define HALT		1
#define BOOT		0

#ifndef cv_destroy
#define cv_destroy(arg)
#endif

int	debug_mcap = 1;
/* Управление выдачей сообщений отладки:
	 if (debug_mcap == 0) {
		<сообщение не выдагтся>
	 };
	 if (debug_mcap == 1) {
		<сообщение выдагтся>
	 };
*/

#ifndef MCAP_OLD_VERSION
#define MCAP_MP_ROM_DRV_INIT_ADDR               0x00400
#define MCAP_MAX_SIZE_BUFFER_DMA                0x40000 /* Макс. размер буфера ППД */
#define MCAP_MP_INIT_AREA_BMEM_SIZE     	0x00010 /* size of MP init area */
#define MCAP_MP_HALT_OPCODE                     0xf4f4f4f4UL
#define MCAP_MP_ROM_DRV_INIT_CODE       	{0xfa33c08eUL, 0xc0c60604UL, \
                                                 0x0401f4f4UL, 1}
                                                 /* CLI; _ES = 0; mov byte ptr  */
                                                 /* ES:[404], 1 */

typedef union mcap_mp_init_area_t_
{
   char         as_chars  [MCAP_MP_INIT_AREA_BMEM_SIZE];
   u_char       as_u_chars[MCAP_MP_INIT_AREA_BMEM_SIZE];
   int  	as_longs  [MCAP_MP_INIT_AREA_BMEM_SIZE / sizeof(int)];
   u_int        as_u_longs[MCAP_MP_INIT_AREA_BMEM_SIZE / sizeof(u_int)];
} mcap_mp_init_area_t;

#define  MCAP_MP_INIT_AREA_char         as_chars
#define  MCAP_MP_INIT_AREA_u_char       as_u_chars
#define  MCAP_MP_INIT_AREA_long         as_longs
#define  MCAP_MP_INIT_AREA_u_long       as_u_longs

typedef struct mcap_mp_rom_drv {
        int     debug_drv_start;        /* не используется */
        int     rom_disable;            /* признак загрузки 1 - ПЗУ, 0 - ОЗУ */
} mcap_mp_rom_drv_t;

#endif /* MCAP_OLD_VERSION */

/* Структуры междрайверной связи */
/* Список номеров заданий для драйвера МП */
typedef enum _mp_task_t
{
	no_mp_task                      = 0, 		/* MП ждет задание */
	init_driver_mp_task             = 1, 		/* инициализации драйвера MП */
	init_buffers_data_exchange_task = 2, 		/* инициализации буферов обмена данными */
	mcap_halt_channel_data_exchange_task = 9, 	/* останов каналов обмена данными */
	mcap_turn_off_channels_task = 10  		/* отключение каналов от линий связи */
} mp_task_t;

/* Список номеров заданий для драйвера ВК */
typedef enum _sparc_task_t
{
	no_sparc_task              = 0  /* драйвер ВК ждет задание */
} sparc_task_t;

/* Заданий на прерывание драйвера ВК */
typedef enum _intr_task_t
{
	no_intr_task         = 0,  /* драйвер ВК ждет задание */
	mcap_get_intr_driver = 12  /* выдача прерывания драйверу ВК */
} intr_task_t;

/* Список состояний МП */
typedef enum	mp_state_t_
{
	undef_mp_state,					/* неопределенное состояние МП */
	halted_mp_state,				/* МП находится в остановленном состоянии */
	started_mp_state,				/* МП был запущен и функционирует */
	hangup_mp_state,				/* зависание МП */
 	crash_mp_state,					/* аварийный отказ МП */
	fault_mp_state,					/* внутренняя неисправность платы или МП */
	adapter_abend_mp_state,				/* аварийное прекращение работы адаптера */
	locked_mp_state,				/* МП находится в блокированном состоянии */
	restarted_mp_state				/* МП перезапущен */
} mp_state_t;

/* Список причин прерываний */
typedef enum   intr_rsn
{
	undefined_intr_reason        = 0, /* неопределенная причина */
	reject_intr_reason           = 1, /* прерывания не ждут */
	board_error_intr_reason      = 2, /* внутренняя ошибка платы */
	get_intr_driver_reason       = 12 /* получено прерывание от др-ра МП */
} intr_reason_t;

/* Результаты инициализации драйвера MП */
#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct _mp_init_result_t
{
	u_short		mp_error_code;		/* код ошибки инициализации драйвера MП */
	u_short		unused;
} mp_init_result_t;
#else
typedef struct _mp_init_result_t
{
	u_short		unused;
	u_short		mp_error_code;		/* код ошибки инициализации драйвера MП */
} mp_init_result_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

/* Инициализации буферов обмена данными */
#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct init_bufers_exchange_data
{
	u_short		num_buf_user;		/* количество буферов обмена пользователя */
	u_short		max_size_buf_trans;	/* максимальный размер передающего */
						/* буфера обмена пользователя (байт) */
	u_int		dma_trans_bufs[MCAP_SUBDEV_BUF_NUM];	/* указатели списка пользовательких */
								/* буферов обмена данными */
} init_bufers_exchange_data_t;
#else
typedef struct init_bufers_exchange_data
{
	u_short		max_size_buf_trans;	/* максимальный размер передающего */
						/* буфера обмена пользователя (байт) */
	u_short		num_buf_user;		/* количество буферов обмена пользователя */
	u_int		dma_trans_bufs[MCAP_SUBDEV_BUF_NUM];	/* указатели списка пользовательких */
								/* буферов обмена данными */
} init_bufers_exchange_data_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

/* Результаты инициализации буферов обмена данными */
#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct init_bufers_exchange_data_res
{
	u_short		error_init_bufers;	/* код ошибки, обнаруженной драйвером MП */
	u_short		unused;			/* неиспользуемое поле */
} init_bufers_exchange_data_res_t;
#else
typedef struct init_bufers_exchange_data_res
{
	u_short		unused;			/* неиспользуемое поле */
	u_short		error_init_bufers;	/* код ошибки, обнаруженной драйвером MП */
} init_bufers_exchange_data_res_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

/* Остановить канал обмена данными (mcap_halt_channel_data_exchange_task) */
#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct	halt_channel_data_exche {
	short	halt_channel_exchange; 	/* номер останавливаемого канала адаптера */
	short	flag_restore; 		/* признак операции восстановления УСК АС0 и СКБ ВУ */
} mcap_halt_channel_data_exchange_t;
#else
typedef struct	halt_channel_data_exche {
	short	flag_restore; 		/* признак операции восстановления УСК АС0 и СКБ ВУ */
	short	halt_channel_exchange; 	/* номер останавливаемого канала адаптера */
} mcap_halt_channel_data_exchange_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

/* Отключить каналы от линий связи (mcap_turn_off_channels_task) */
#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct	turn_ch {
	short	mode_functional_monitoring; /* режим АФК */
	short   unused;
} mcap_turn_off_channels_t;
#else
typedef struct	turn_ch {
	short   unused;
	short	mode_functional_monitoring; /* режим АФК */
} mcap_turn_off_channels_t;
#endif/* MY_DRIVER_BIG_ENDIAN */

/* Выдача прерывания пользователю */
#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct reveal_result {
	u_short	channel_num;			 /* номер канала */
	u_short	event_intr;			 /* код события */
} reveal_result_t;
#else
typedef struct reveal_result {
	u_short	event_intr;			 /* код события */
	u_short	channel_num;			 /* номер канала */
} reveal_result_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

/* Параметры задания для драйвера MП от драйвера ВК */
typedef union _mp_drv_args_t
{
	init_bufers_exchange_data_t init_buf_exch; 			/* инициализация буферов обмена данными */
	mcap_halt_channel_data_exchange_t halt_channel_data_exch; 	/* останов канала обмена */
	mcap_turn_off_channels_t turn_ch; 			    	/* отключение каналов от линий связи */
	u_int		args_area[35];	/* максимальная область параметров задания для драйвера MП */
} mp_drv_args_t;

/* Параметры задания для драйвера ВК от драйвера MП */
typedef union _sparc_drv_args_t
{
	mp_init_result_t mp_init_results;			/* результаты инициализации драйвера MП */
	init_bufers_exchange_data_res_t	init_buf_exch_res;	/* результаты инициализации буферов */
								/* обмена данными */
	u_int		args_area[15];				/* максимальная область параметров */
								/* заданий драйвера ВК */
} sparc_drv_args_t;

/* Параметры прерывания от драйвера MП */
typedef union _intr_drv_args_t
{
	reveal_result_t	reveal_result;	/* результат прерывания от адаптера */
	u_int		args_area[1];	/* максимальная область параметров */
} intr_drv_args_t;
/* Связь драйверов ВК и МП */
typedef struct drv_intercom_t_
{
   mp_task_t         mp_task;       /* текущее задание для драйвера MП */
   mp_drv_args_t     mp_args;       /* параметры заданий для драйвера MП */
   sparc_task_t      sparc_task;    /* текущее задание для драйвера ВК */
   sparc_drv_args_t  sparc_args;    /* параметры задания для драйвера ВК */
   u_int	     flag_mp;       /* признак работы МП */
   intr_task_t       intr_task;     /* прерывание для драйвера ВК */
   intr_drv_args_t   intr_args;     /* параметры прерывания */
} drv_intercom_t;

/* Определения и структуриры, используемые драйвером и приложениями пользователя. */

#if defined(_KERNEL) || defined(_KMEMUSER)

/* Dev_ops для этого модуля */
/*struct	dev_ops	mcap_dev_ops;*/
static struct file_operations mcap_fops;

/* Обобщенные структуры пересылок и результатов */

typedef struct dma_struct {
	caddr_t		 prim_buf_addr;
	size_t		 real_size;
        dma_addr_t       busa;          /* Address in the SBus space,*/ 
					/* Адрес области dma со стороны устройства */
    	unsigned long	 mem; 		/* Address in the processor space,*/
					/* Адрес области dma со стороны процессора */
        int              size;
  } dma_struct_t;

/* Структура буфера пересылки */
typedef struct trbuf_desc {
	caddr_t			buf_address;	/* виртуальный адрес буфера пересылки */
	size_t			buf_size;	/* байтовый размер буфера пересылки */
/*	ddi_acc_handle_t	acc_handle;*/	/* буфер обработки доступа */
/*	ddi_dma_handle_t	dma_handle;*/ 	/* буфер обработки DMA */
/*	ddi_dma_cookie_t	cookie;*/	/* буфер DMA маркеров */
/*	uint_t			ccount;*/	/* число буферов DMA маркеров */
	dma_struct_t		dma;		/* Буфер, описывающий DMA */
} trbuf_desc_t;

/* Описание буфера пересылки */
typedef struct trans_buf_ {
	struct trans_buf 	*next_trans_buf;		/* указатель следующего буфера в списке */
	trbuf_desc_t		trans_buf_desc; 		/* описание буфера пересылки */
} trans_buf_t;

/* Структура буфера пересылки.
 Буфер содержит буфера пользователей */
typedef struct trbuf_state {
	char		valid_flag;		/* допустимый буфер пересылки */
	trbuf_desc_t	trans_buf_desc; 	/* дескриптор буфера пересылки */
	caddr_t		user_buf_address;	/* виртуальный адрес начального буфера пользователя */
	size_t		user_buf_size;		/* байтовый размер буфера пользователя */
	int		max_user_buf_num;	/* макс. число буферов пользователя в буфере драйвера */

	caddr_t		user_trans_bufs[MCAP_SUBDEV_BUF_NUM]; /* список указателей буферов пересылки пользователя */
	u_int		dma_trans_bufs[MCAP_SUBDEV_BUF_NUM];  /* список dma указателей буферов пересылки
								 пользователя */
} trbuf_state_t;

/* Внутреннее состояние канала */
typedef struct mcap_chnl_state {
	trbuf_state_t	trans_buf_state;	/* состояние буфера пересылки */
	char	trans_state_is_init;		/* установка состояния пересылки */
	char	state_init_in_progress;		/* выполняется инициализация  */
	char	trans_state_is_halt;		/* состояние пересылки - останов */
	char	mp_trans_state_is_halt;		/* состояние драйвера - останов */
	char	all_trans_finish;			/* все пересылки завершены */
	char	init_as_trans_map;			/* канал инициализирован в режиме карты обмена*/
	int	trans_halt_error;			/* код ошибки останова, если останов не был произведен */
	mcap_init_iomap_t	init_iomap_state_spec;	/* состояние инициализации карты */
	size_t	full_data_buf_size;			/* полный размер буфера данных */
	size_t	subdev_buf_trans_size;		/* размер передающего буфера, включая заголовок */
	size_t	subdev_buf_reciv_size;		/* размер приемного буфера, включая заголовок */
	int		dma_intr_handled;			/* прерывание обработано верно */
	u_short		trans_num;				/* номер пакетной пересылки */
} mcap_chnl_state_t;

/* Внутреннее состояние драйвера */
#ifdef MCAP_OLD_VERSION
typedef struct mcap_state {
	dev_info_t		*dip;			/* dip. */
	int			inst;			/* номер экземпляра */
	int			opened;			/* открытое состояние */
	int			open_flags;		/* открытое состояние с флажком */
	u_int			open_channel_map;	/* маска открытых каналов */
/*********************************************************************************************************/
	raw_spinlock_t		lock;
	kcondvar_t		channel_cv;		/* переменная условий (режима, состояний) канала */
	kcondvar_t		drv_comm_cv;		/* область связи драйвера: занятая или
								свободная, переменная условия */
	kcondvar_t		trans_state_cv; 	/* состояние канала пересылки,
								изменение переменной условия */
	kcondvar_t		intr_cv;		/* переменная условий для прерывания */
/*********************************************************************************************************/

/*	ddi_iblock_cookie_t	iblock_cookie;*/	/* для mutexes. */
/*	struct pollhead		pollhead;*/		/* глухая структура для опроса */
	int			drv_comm_busy;		/* признак занятости области
									   связи драйвера */
	int       		drv_general_modes;	/* общие признаки режимов драйвера */
	e90_unit_t		type_unit;		/* тип платы */
	char			intr_seted;		/* прерывание установлено */
	char			intr_number;		/* число прерываний */
	int			system_burst;		/* DMA размеры пачки, позволенные SBUS */
	char			mp_drv_loaded;		/* MP драйвер загружен */
	char			mp_debug_drv_flag;	/* debug driver startuped flag */
	char			mp_rom_drv_enable;	/* MP ROM драйвер является
									   разрешающим признаком */
	mp_state_t		mp_state;		/* текущее состояние MП */
	char			mp_drv_started;		/* MP драйвер запущен */
	char			set_tlrm;		/* ???? блокировка установки сброса
									   модуля по ошибке  */
	bmem_trans_desk_t	mp_init_code;		/* дескриптор запуска кода MП */
	
	char						/* запуск кода MП */
				mp_init_area_copy[ME90_MP_INIT_AREA_BMEM_SIZE];
	mp_drv_args_t					/* информация инициализации драйвера MП */
				mp_drv_init_info;
	volatile caddr_t	MCAP_BMEM;		/* базовый адрес БОЗУ */
	mcap_chnl_state_t               		/* состояние канала платы */
				channel_state[1];
/*	ddi_acc_handle_t	acc_regs;*/  		/* указатель на дескриптор */
							/* доступа к регистрам */
	caddr_t			regs_base; 		/* базовый адрес регистров */
	off_t			reg_array_size;   	/* размер выделенной области */
										  /* регистров */
	u_short			io_flags_intr; 		/* признак наличия прерывания */
	u_short			event_intr_trans_ch[MCAP_SUBDEV_BUF_NUM];
							/* код события передающих каналов */
	u_short			event_intr_reciv_ch[MCAP_SUBDEV_BUF_NUM];
							/* код события приемных каналов */
	hrtime_t		time_get_intr_dev; 	/* Т получения прерывания от адаптера */

} mcap_state_t;
#else
typedef struct mcap_state {
	dev_info_t		*dip;			/* dip. */
	int			inst;			/* номер экземпляра */
	int			opened;			/* открытое состояние */
	int			open_flags;		/* открытое состояние с флажком */
	u_int			open_channel_map;	/* маска открытых каналов */
/*********************************************************************************************************/
	raw_spinlock_t		lock;
	kcondvar_t		channel_cv;		/* переменная условий (режима, состояний) канала */
	kcondvar_t		drv_comm_cv;		/* область связи драйвера: занятая или
								свободная, переменная условия */
	kcondvar_t		trans_state_cv; 	/* состояние канала пересылки,
								изменение переменной условия */
	kcondvar_t		intr_cv;		/* переменная условий для прерывания */
/*********************************************************************************************************/

/*	ddi_iblock_cookie_t	iblock_cookie;*/	/* для mutexes. */
/*	struct pollhead		pollhead;*/		/* глухая структура для опроса */
	int			drv_comm_busy;		/* признак занятости области
							   связи драйвера */
	e90_unit_t		type_unit;		/* тип платы */
	char			intr_seted;		/* прерывание установлено */
	char			intr_number;		/* число прерываний */
	int			system_burst;		/* DMA размеры пачки, позволенные SBUS */
	char			mp_drv_loaded;		/* MP драйвер загружен */
	char			mp_debug_drv_flag;	/* debug driver startuped flag */
	char			mp_rom_drv_enable;	/* MP ROM драйвер является
									   разрешающим признаком */
	mp_state_t		mp_state;		/* текущее состояние MП */
	char			mp_drv_started;		/* MP драйвер запущен */
	mcap_bmem_trans_desk_t  mp_init_code;           /* дескриптор запуска кода MП */
                                                        /* запуск кода MП */

	char			mp_init_area_copy[ME90_MP_INIT_AREA_BMEM_SIZE];
	mp_drv_args_t		mp_drv_init_info;	/* информация инициализации драйвера MП */
	volatile caddr_t	MCAP_BMEM;		/* базовый адрес БОЗУ */
	mcap_chnl_state_t               		/* состояние канала платы */
				channel_state[1];
/*	ddi_acc_handle_t	acc_regs;*/  		/* указатель на дескриптор */
							/* доступа к регистрам */
	caddr_t			regs_base; 		/* базовый адрес регистров */
	off_t			reg_array_size;   	/* размер выделенной области */
										  /* регистров */
	u_short			io_flags_intr; 		/* признак наличия прерывания */
	u_short			event_intr_trans_ch[MCAP_SUBDEV_BUF_NUM];
							/* код события передающих каналов */
	u_short			event_intr_reciv_ch[MCAP_SUBDEV_BUF_NUM];
							/* код события приемных каналов */
	hrtime_t		time_get_intr_dev; 	/* Т получения прерывания от адаптера */
	u_short         	number_intr_rosh;       /* кол-во прерываний по РОШ */
} mcap_state_t;
#endif /* MCAP_OLD_VERSION */

/* Макрокоманды для обращения к регистрам */
/* Виртуальный адрес регистра */
#define	MCAP_REGISTER_ADDR(state, reg)	((ulong_t *)(state->regs_base + reg))
/* Чтения содержимого регистра */
#define	READ_MCAP_REGISTER(state, reg)	ddi_getl(state->dip->dev_type/*acc_regs*/, MCAP_REGISTER_ADDR(state, reg))
/* Запись в регистр */
#define	WRITE_MCAP_REGISTER(state, reg, v)	ddi_putl(state->dip->dev_type/*acc_regs*/, MCAP_REGISTER_ADDR(state, reg), v)

static int
mcap_ioctl(struct inode *inode, struct file *file,
                 unsigned int cmd, unsigned long arg);

static int mcap_open(struct inode *inode, struct file *file);

static int mcap_mmap(struct file *file, struct vm_area_struct *vma);

static int mcap_close(struct inode *inode, struct file *file);

static int  mcap_attach(dev_info_t  *dip);

int mcap_detach(dev_info_t *dip);

irqreturn_t mcap_intr_handler(int irq, void *arg, struct pt_regs *regs);

static int __init mcap_init(void);

static void __exit mcap_exit(void);

int mcap_attach_add(mcap_state_t *state, int *add_attach_flags);

void mcap_detach_add(mcap_state_t *state, int add_attach_flags, int uncondit_detach);

void Unmap_reg_sets(mcap_state_t	*state);

int rmv_dev(dev_info_t *dip, int channel);

int mcap_get_channel_to_init(
	mcap_state_t			*state,
	int				waiting_time,
	int				drv_comm_area_locked,
	int				user_request,
	int				state_recover);

void mcap_free_channel_to_init(mcap_state_t *state, int	mutex_locked);

int mcap_init_trans_map_state(
	mcap_state_t		*state,
	mcap_init_iomap_t	*init_state_args,
	int					drv_comm_area_locked,
	int					*error_code,
	int					state_recover);

int mcap_create_drv_iomap_buf(mcap_state_t	*state);

void mcap_delete_drv_trans_buf(mcap_state_t	*state);

void mcap_init_trans_buf_desc(
	trbuf_desc_t	*trans_buf_desc);

int mcap_halt_trans_state(
	mcap_state_t *		state,
	mcap_halt_trans_t	*halt_trans_state,
	int			drv_comm_area_locked,
	int			user_request,
	int			mutex_locked);

int mcap_wait_for_trans_state_halt(
	mcap_state_t 		*state,
	int			waiting_time);

int mcap_halt_transfers(
	mcap_state_t 		*state,
	int			waiting_time,
#ifdef MCAP_OLD_VERSION
	int			delete_rem_trans,
	int			mutex_locked,
#endif /* MCAP_OLD_VERSION */
	int			drv_comm_area_locked);

void mcap_init_subdev_buf(
	mcap_state_t		*state,
	mcap_iosubdbuf_t	*subdev_buf,
	int			io_flags,
	size_t			max_data_buf_size,
	int			subdev_buf_num);

void mcap_init_iomap_buf(
	mcap_state_t		*state,			 /* собственная информация драйвера */
	mcap_iosubdbuf_t	*iomap_buf_desc, 	 /* дескриптор буфера обмена */
	size_t			subdev_buf_trans_size,   /* максимальный размер */
							 /* буфера передачи */
	size_t			subdev_buf_reciv_size,   /* максимальный размер */
							 /* буфера приема */
	int			iomap_buf_num);

int mcap_start_task_drv_mp(
	mcap_state_t 		*state,
	mp_task_t		mp_task,
	mp_drv_args_t 		*task_args,
	sparc_drv_args_t	*mp_task_results
	);

int mcap_wait_make_task_drv_mp(
	mcap_state_t		*state,
	int			mp_restart,
	int			wait_mp_task_accept,
	int			wait_mp_rom_drv_disable);

int mcap_reset_general_regs(
	mcap_state_t		*state,
	int			mp_state);

void mcap_read_general_regs(
	mcap_state_t	*state,
	int		flaf_print);

int   mcap_calculate_work_hr_time(
	hrtime_t    start_time,             /* event start time */
	hrtime_t    end_time                /* event finish time */
	);

int  mcap_bmem_data_transfer(
	 mcap_state_t		*state,
#ifdef MCAP_OLD_VERSION
	 bmem_trans_desk_t	*transfer_desk,
#else
	 mcap_bmem_trans_desk_t *transfer_desk,
#endif /* MCAP_OLD_VERSION */
	 int			write_op,
	 int			char_data,
	 caddr_t		kmem_buf,
	 caddr_t		*kmem_area_p);

int mcap_alloc_trans_bufs(
	mcap_state_t	*state,
	trbuf_desc_t	*new_trans_buf,
	int		buf_byte_size);

void mcap_free_trans_bufs(
	mcap_state_t	*state,
	trbuf_desc_t	*trans_buf_desc);

int	mcap_write_base_memory(
	mcap_state_t	*state,
	caddr_t		address_from,
	caddr_t		address_to,
	size_t		byte_size,
	int		char_data);

u_int	mcap_rotate_word_bytes(u_int	source_word);

int mcap_map_registers(
	mcap_state_t	*state,
	e90_unit_t	type_unit);

int   mcap_startup_mp(
	mcap_state_t		*state,
	int			cmd);

int mcap_reset_module(
	mcap_state_t	*state,
	int		operation,
	int		clean_bmem);

void mcap_clean_base_memory(mcap_state_t	*state);

void mcap_clean_drv_communication(mcap_state_t	*state);

int mcap_ioctl(struct inode *inode, struct file *file,
                 unsigned int cmd, unsigned long arg);

void mcap_init_drv_state(mcap_state_t	*state);

void mcap_init_trans_buf_state(
	trbuf_state_t	*trans_buf_state);


#define	MCAP_DRV_COMM_FREE_TIMEOUT_DEF_VALUE	(1000000)
#define MCAP_TASK_ACCEPT_BY_MP_TIME		(100000)		/* usec */
/*#define MCAP_TASK_ACCEPT_BY_MP_TRYON		(1000)	исключён */
#define MCAP_TASK_ACCEPT_BY_MP_DELAY_TIME	(1000)			/* usec */

/* Локальные определения */

#define MCAP_DEVN(d)	(getminor(d))		/* dev_t -> minor (dev_num) */
#define MCAP_inst(m)	(m >> 4)		/* minor -> instance */
#define MCAP_chan(m)	(m & 0xf)		/* minor -> channel */
#define MCAP_MINOR(i,c)	((i << 4) | (c))	/* instance+channel -> minor */
#define MCAP_INST(d)	MCAP_inst(MCAP_DEVN(d))	/* dev_t -> instance */
#define MCAP_CHAN(d)	MCAP_chan(MCAP_DEVN(d))
#define	CHNL_NUM_TO_MASK(chnl)		(1 << chnl)

/* Разрядные поля для attach_flags: */

#define SOFT_STATE_ALLOCATED		0x0001
#define INTERRUPT_ADDED			0x0002
#define MUTEX_ADDED			0x0004
#define CHANNEL_CV_ADDED		0x0008
#define REGS_MAPPED			0x0010
#define MINOR_NODE_CREATED		0x0020
#define IOPB_ALLOCED			0x0040
#define ERRORS_SIGN			0x0080
#define IBLOCK_COOKIE_ADDED		0x0200
#define	INTR_IBLOCK_COOKIE_ADDED	0x0400
#define	INTR_MUTEX_ADDED		0x0800
#define	TRANS_HALTED_CV_ADDED		0x1000
#define	CNCT_POLLING_CV_ADDED		0x2000
#define	TRANS_STATE_CV_ADDED		0x4000

/* Имена реквизитов устройства */

#define SBUS_INTR_L_NAME_OF_PROP 	"interrupts"

#endif	/* defined(_KERNEL) || defined(_KMEMUSER) */

#ifdef	__cplusplus
}
#endif

#endif	/* __MCAP_H__ */
