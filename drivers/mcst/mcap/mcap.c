/*
 *
 * Ported in Linux by Alexandr E. Viborov, sviborov@sun.task.mcst.ru, MCST, 2005
 *
 */

#include <linux/miscdevice.h>

#include <linux/mm.h>

#include <linux/mcst/ddi.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/dma.h>
#include <linux/slab.h>

#define	DBGMCAP_MODE 		0
#define DBGMCAPDETAIL_MODE 	0
#define	dbgmcap			if (DBGMCAP_MODE) 	printk
#define	dbgmcapdetail		if (DBGMCAPDETAIL_MODE)	printk

#define mod_name "mcap"
#define board_name  "MCST,mcap"

#ifndef __sparc__
static inline u_int flip_dword(u_int l)
{
	return ((l&0xff)<<24) | (((l>>8)&0xff)<<16) | (((l>>16)&0xff)<<8)| ((l>>24)&0xff);
}
 
static inline u_short flip_word(u_short w)
{
	return ((w&0xff) << 8) | ((w>>8)&0xff);
}
#endif

static int mcap_instances;

extern	int	cache;		/* открывать кеш */

/* Собственные включения к этому модулю */
#include "linux_mcap.h"



/* Присоединение и отсоединение драйвера  */
int	mcap_run_doattach	= 0;
int	mcap_run_dodetach	= 0;

int	mcap_sbus_clock_freq = 0;
int	mcap_sbus_nsec_cycle = 0;
int	mcap_mp_clock_freq   = 0;
int	mcap_mp_nsec_cycle   = 0;



static struct file_operations mcap_fops = {
	owner:   THIS_MODULE,
	open:	 mcap_open,
	release: mcap_close,
	ioctl:   mcap_ioctl,
	mmap:	 mcap_mmap,
};

/* Список указателей состояния программного обеспечения */
void			*mcap_state; 

static int 
__init mcap_init(void)
{
     int  rval;
     dev_info_t  *dip;	

	dbgmcap("********* MCAP_INIT: START  *********\n");

	rval = ddi_rgstr_dev(board_name, DDI_SBUS_SPARC, &mcap_fops);
	if (!rval) {
		printk("mcap_init: ENODEV\n");
		return(-ENODEV);
	}
	dbgmcap("mcap_init: num of inst %d for %s\n", rval, board_name);
   	mcap_instances = 0;
   	for (;;) {
   		dip = ddi_inst_dip(board_name, mcap_instances);
   		if (!dip) {
   			dbgmcapdetail("mcap_init: dip == NULL for inst %d\n", 
   							mcap_instances);
   			break;
   		}
   		rval = ddi_init_soft(dip, sizeof(mcap_state_t));
   		if (rval) {
   			printk("mcap_init: ddi_init_soft !- 0\n");
   			return -EFAULT;
   		}
   		rval = mcap_attach(dip);
   		if (rval < 0) {
   			printk("mcap_init: mcap_attach < 0\n");
   			return -EFAULT;
   		}
   		mcap_instances++;   		
   	}
	if (mcap_instances == 0) {
		printk("mcap_init: Device not found\n");
		return -ENODEV;
	}

	dbgmcap("********* MCAP_INIT: FINISH mcap_instances %d rval of mcap_init %d *********\n",
		mcap_instances, 0);
	return (0);


}

static void 
__exit mcap_exit(void)
{
	int		i;
	dev_info_t	*dip = NULL;
	int error = 0;
	
 	for ( i = 0; i < mcap_instances; i++ ) {
	dbgmcap("********* MCAP_EXIT: start for %s %d *********\n", board_name, i);
 		dip = ddi_inst_dip(board_name, i);
		dbgmcapdetail("mcap_exit dip = %lx\n", (unsigned long)dip);
		dbgmcapdetail("mcap_exit: mcap_detach START dip = %lx\n", (unsigned long)dip);
		error = mcap_detach(dip);
		dbgmcapdetail("mcap_exit: mcap_detach FINISH\n");
 	}
	if (!error){
		dbgmcapdetail("mcap_exit: ddi_rm_dir START\n");
		error = ddi_rm_dir(dip); 
		dbgmcapdetail("mcap_exit: ddi_rm_dir FINISH\n");
		if (error)
			printk("mcap_exit: ddi_rm_dir failed, error = %d\n", error);
	}
	dbgmcap("********* MCAP_EXIT: FINISH *********\n"); 

 

}


int 
mcap_open(struct inode *inode, struct file *file)
{
	dev_info_t	*dip;
	mcap_state_t	*state = NULL;
	dev_t		dev;
/*	int				dev_num  = MCAP_DEVN(dev);*/
	int		instance = 0;
	int		channel;
	int		firstopen = 0;
	int		rval = 0;
/*	int				ch;*/
	int				i;
#ifdef MCAP_OLD_VERSION
	int		version_drv_vk = VER_DRV_VK_MC19;
	int		version_module = VERSION_MODULE_MC19;
#else
	int		version_drv_vk = VER_DRV_VK_MCAP;
	int		version_module = VERSION_MODULE_MCAP;
#endif /* MCAP_OLD_VERSION */
	u_int  		day;
	u_int  		month;
	u_int  		year;
	u_int  		version;


	rval = ddi_open(inode,file);
	if (rval < 0) return rval;
	dev = ddi_inode_dev(inode);
	dip = ddi_inode_dip(inode);
	if (!dip || !dev) return (-ENXIO);
	instance = MCAP_INST(dev);
	channel = MCAP_CHAN(dev);

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_open: начало функционирования.\n",
			instance);
	};

/* Образец присоединен? */
	state = dip->soft_state;
	if (state == NULL) {
		printk("экз. %d. "
			"mcap_open: открытие незагруженного устройства.\n",
			instance);
		return (-ENXIO);
	 };

/* Проверка на соответствие версии драйвера ВК версии модуля */
	if (version_drv_vk != version_module) {
		day       = (version_module & 0xFF000000) >> 24;
		month     = (version_module & 0x00FF0000) >> 16;
		year      = (version_module & 0x0000FF00) >> 8;
		version   = version_module & 0x000000FF;
		printk("экз. %d. "
			"Версия модуля .%02x-13 от %02x.%02x.%04xг.", 
			instance,
			version, day, month, year|0x2000);
		day       = (version_drv_vk & 0xFF000000) >> 24;
		month     = (version_drv_vk & 0x00FF0000) >> 16;
		year      = (version_drv_vk & 0x0000FF00) >> 8;
		version   = version_drv_vk & 0x000000FF;
		printk("экз. %d. "
			"Версия драйвера ВК .%02x-13 от %02x.%02x."
			"%04xг не соответствует версии модуля.",
			instance,			
			version, day, month, year|0x2000);
		return (-ERRORVERDRVVK);
	};


/* Проверить открытый флажок */
	spin_mutex_enter(&state->lock);
	firstopen = (state->opened == 0);

	if (!firstopen) {
		printk("экз. %d. "
			"mcap_open: попытка монопольного открытия уже открытого "
			"устройства.\n",
			instance);
		spin_mutex_exit(&state->lock);
		return (-EBUSY);
	};

/* Отметить канал, открытый в карте */
	state->open_channel_map |= CHNL_NUM_TO_MASK(channel);
	state->open_flags =0;
	state->opened = 1;
	state->inst = instance;
	state->io_flags_intr = 0; /* признак прерывания ПрП */
	for (i = 0; i < MCAP_SUBDEV_BUF_NUM; i++) {
		state->event_intr_trans_ch[i] = 0;
		state->event_intr_reciv_ch[i] = 0;
	};
#ifndef MCAP_OLD_VERSION
	state->number_intr_rosh = 0; /* кол-во прерываний по РОШ */
#endif /* MCAP_OLD_VERSION */
	spin_mutex_exit(&state->lock);
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_open: Успешное завершение функционировавния.\n",
			instance);
	};
	return  0;
}

int 
mcap_close(struct inode *inode, struct file *file)
{
	dev_info_t		*dip;
	dev_t 			dev;
	mcap_state_t 		*state = NULL;
	int			instance = 0;
	int			channel;
	mcap_chnl_state_t	*channel_state = NULL;
	u_long			cur_clock_ticks = 0;
	u_long			timeout_clock_ticks = 0;
	int			rval = 0;
#ifdef MCAP_OLD_VERSION
	mp_drv_args_t       	mp_drv_args;
	int			mp_args_size = 0;
	int			ch_hlt;
	drv_intercom_t		*drv_communication = NULL;
#else
	reg_general_mcap_t      read_value;
#endif /* MCAP_OLD_VERSION */

	dev = ddi_inode_dev(inode);
	dip = ddi_inode_dip(inode);
	if (!dip || !dev) return (-ENXIO);
	instance = MCAP_INST(dev);
	channel = MCAP_CHAN(dev);

	if (debug_mcap == 0) {
		 printk("экз. %d. "
			"mcap_close: начало функционирования.\n",
			instance);
	};
	state = dip->soft_state;
	if (state == NULL) {
		printk("экз. %d. "
			"mcap_close: закрытие не загруженного устройства.\n",
			instance);
		return (-ENXIO);
	 };

#ifndef MCAP_OLD_VERSION
/* Сброс модуля и МП */
        WRITE_MCAP_REGISTER(state, MCAP_TZM, 0);
        udelay(100);
/* Чтение значения РОБ */
        read_value.rdwr_reg_general = READ_MCAP_REGISTER(state, MCAP_TBL);
        if (debug_mcap == 0) {
                printk("экз. %d. "
                        "mcap_close: РОБ = 0x%x.\n",
                        instance,
                        read_value.rdwr_reg_general);
        };
        if (read_value.trg_TSM == 0) {
                WRITE_MCAP_REGISTER(state, MCAP_TSM, 1);
                printk("INST. %d. "
                        "mcap_close: Module has been resetted\n",
                        instance);
        };
#endif /* MCAP_OLD_VERSION */         

        channel_state = state->channel_state;
#ifndef MCAP_OLD_VERSION
        state->inst = instance;
        if (channel_state->trans_state_is_init != 0) {
                printk("экз. %d. "
                        "mcap_close: ФП не произвела закрытие устройства. "
                        "valid_flag = %d.",
                        instance,
                        channel_state->trans_buf_state.valid_flag);
        };
#endif /* MCAP_OLD_VERSION */

/* Приобрести mutex */
	spin_mutex_enter(&state->lock);
#ifdef MCAP_OLD_VERSION
/* Ожидание освобождения устройства */
	if (channel_state->trans_state_is_init || channel_state->state_init_in_progress) {
		mcap_halt_trans_t	halt_trans_state;
		drv_communication =
			(drv_intercom_t *) &state->MCAP_BMEM[MCAP_DRV_CMN_AREA_BMEM_ADDR];
		drv_communication->mp_task    = no_mp_task;
		drv_communication->sparc_task = no_sparc_task;
 /* Формирование задания для драйвера МП для закрытия каналов */
		for (ch_hlt = 0; ch_hlt <= 3; ch_hlt++) {
			mp_drv_args.halt_channel_data_exch.halt_channel_exchange = ch_hlt;
			mp_drv_args.halt_channel_data_exch.flag_restore = 1;

			mp_args_size = sizeof(mcap_halt_channel_data_exchange_t);
			if (debug_mcap == 0) {
				printk("экз. %d. "
					"mcap_halt_channel_data_exchange_t: "
					"область аргументов = %d.",
					instance,
					mp_args_size);
			};
			rval = mcap_start_task_drv_mp(state,
					mcap_halt_channel_data_exchange_task,
					&mp_drv_args, 0);
			if (rval != 0) {
				printk("экз. %d. "
					"mcap_close: mcap_start_task_drv_mp() - завершение "
					"функц-ния с ошибкой при закрытии канала.\n",
					instance);
				goto TURN;
			};
		};
		printk("экз. %d. "
			"mcap_close: каналы закрыты драйвером ВК.\n",
			instance);
TURN:
 /* Формирование задания для драйвера МП */
 /* по отключению каналов от линий связи */
		mp_drv_args.turn_ch.mode_functional_monitoring = MODE_AFM;
		mp_args_size = sizeof(mcap_turn_off_channels_t);

		if (debug_mcap == 0) {
			printk("экз. %d. "
				"mcap_turn_off_channels_t: размер области "
				"аргументов = %d.",
				instance,
				mp_args_size);
		};
		rval = mcap_start_task_drv_mp(state, mcap_turn_off_channels_task,
							&mp_drv_args, 0);
		if (rval != 0) {
			printk("экз. %d. "
				"mcap_close: mcap_start_task_drv_mp() - завершение функц-ния "
				"с ошибкой при отключении каналов от ЛС.\n",
				instance);
		};

		halt_trans_state.waiting_time = 0;
		rval = mcap_halt_trans_state(state, &halt_trans_state,
				0, 0, 1);
		if (rval != 0) {
			printk("экз. %d. "
				"mcap_close: не удалось остановить работу с устройством.\n",
				instance);
		};
	};
#endif /* MCAP_OLD_VERSION */

	if (channel_state->trans_buf_state.valid_flag) {
		mcap_delete_drv_trans_buf(state);
	};
	channel_state->trans_state_is_init    = 0;
	channel_state->state_init_in_progress = 0;
	channel_state->trans_state_is_halt    = 0;
	channel_state->mp_trans_state_is_halt = 0;
	channel_state->all_trans_finish       = 0;
	channel_state->trans_halt_error       = 0;
	channel_state->init_as_trans_map      = 0;
	channel_state->full_data_buf_size     = 0;
	channel_state->subdev_buf_trans_size  = 0;
	channel_state->subdev_buf_reciv_size  = 0;

/* Отметить канал, закрытый в карте */
	channel_state->trans_num = 0;
	state->open_channel_map &= ~CHNL_NUM_TO_MASK(channel);

 /* Если последний канал закрылся, то драйвер закрыт */
	if (state->open_channel_map == 0) {
		state->open_flags = 0;
		state->opened = 0;
	};

	if (state->opened == 0) {
/* Освобождение область связи междрайвера */
		while (state->drv_comm_busy) {
			drv_getparm(LBOLT,&cur_clock_ticks);
			timeout_clock_ticks = cur_clock_ticks +
				drv_usectohz(MCAP_DRV_COMM_FREE_TIMEOUT_DEF_VALUE);
			rval = cv_spin_timedwait(&state->drv_comm_cv, &state->lock,
					timeout_clock_ticks);
			if (rval < 0) {
				printk("экз. %d. "
					"mcap_close: не удалось дождаться освобождения области "
					"междрайверного взаимодействия.\n",
					 instance);
				state->drv_comm_busy = 0;
				cv_broadcast(&state->drv_comm_cv);
				break;
			};
		};
	};
 /* Пропустить mutex */
	spin_mutex_exit(&state->lock);

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_close: успешное завершение.\n",
			instance);
	};
	return  0;
}

int 
mcap_mmap(struct file *file, struct vm_area_struct *vma)
{
	u_int			rval = 0;
	dev_info_t		*dip = NULL;
	dev_t			dev;
	int			instance;
	mcap_state_t		*state = NULL;
	int			channel;
	mcap_chnl_state_t	*channel_state = NULL;
	caddr_t			mapped_reg_set_p = NULL;
	off_t			reg_set_offset   = 0;
	int			dma_buffers_map = 0;
	unsigned long		vm_end = vma->vm_end;
   	unsigned long		vm_start = vma->vm_start;
	unsigned long 		off = (long )(vma->vm_pgoff << PAGE_SHIFT);


	dev = ddi_file_dev(file);
   	dip = ddi_file_dip(file);
   	if (!dip || !dev) return (-ENXIO);
   	instance = MCAP_INST(dev);
   	channel = MCAP_CHAN(dev);
   	state = dip->soft_state;
	if (state == NULL) {
		printk(KERN_ERR "INST %d. "
			"mcap_mmap: неверный или незагруженный номер экземпляра "
			"устройства.\n",
			instance);
		return (-EINVAL);
	}

	channel_state = state->channel_state;
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_mmap: начало функционирования.\n",
			instance);
	};
#ifdef MCAP_OLD_VERSION
	if (off < MCAP_CNTR_ST_REG_SET_OFFSET) {
#else
	if (off < MCAP_MAX_SIZE_BUFFER_DMA) {
#endif /* MCAP_OLD_VERSION */
		if (!channel_state->trans_buf_state.valid_flag) {
			printk("экз. %d. "
				"mcap_mmap: общий буфер не создан еще.\n",
				instance);
			return (-ENXIO);
		};
		if (channel_state->trans_buf_state.user_buf_address == NULL) {
			printk("экз. %d. "
				"mcap_mmap: общий буфер не инициализрован еще.\n",
				instance);
			return (-ENXIO);
		};
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"mcap_mmap: общий буфер.\n",
				instance);
		};

		mapped_reg_set_p =
			channel_state->trans_buf_state.user_buf_address;
		dma_buffers_map = 1;

		if (debug_mcap == 0) {
			printk(KERN_INFO "INST %d. "
				"mcap_mmap: общий буфер size = %ld\n", instance, 
				(vm_end - vm_start));
			printk(KERN_INFO "INST %d. "
				"mcap_mmap: общий буфер addr = 0x%lx\n", instance,
				(ulong_t)mapped_reg_set_p);
		}
		vma->vm_flags |= (VM_IO | VM_SHM | VM_LOCKED | VM_READ | VM_WRITE );
		rval = ddi_remap_page(mapped_reg_set_p, vm_end - vm_start, vma);

	} else if (off >= MCAP_BMEM_REG_SET_OFFSET &&
		off < MCAP_BMEM_REG_SET_OFFSET + MCAP_BMEM_REG_SET_LEN) {
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"mcap_mmap: набор регистров - BMEM.\n",
				instance);
		};
		reg_set_offset = off - MCAP_BMEM_REG_SET_OFFSET;
		vma->vm_flags |= (VM_IO | VM_SHM | VM_LOCKED | VM_READ | VM_WRITE );
		rval = ddi_io_remap_page(dip, 1, reg_set_offset, MCAP_BMEM_REG_SET_LEN, vma);
	} else {
		printk("экз. %d. "
			"mcap_mmap: неверное смещение набора регистров.\n",
			instance);
		return (-EINVAL);
	};

	return (rval);
}


static int 
mcap_attach(dev_info_t  *dip)
{
	mcap_state_t			*state;
	mcap_chnl_state_t		*channel_state = NULL;
	int				instance = dip->instance;
	int				attach_flags = 0;
	int				add_attach_flags = 0;
	int				map_flags    = 0;
	int				need_intr_num = 0;
	int				intr_num     = 0;
	int				intr_sbus_levels[2];
	int				cur_intr = 0;
	int				intr_levels_size = 0;	
	int				channel      = 0;
	int				minor        = 0;
	int				rval         = 0;	
	char				name[64];


/* Find which instance we are, and create a data structure for
   the per-instance data */
	
	dbgmcap("mcap_attach: start\n"); 
	if (dip == NULL) return -EFAULT;
	
	/* Создание программного обеспечения  для этого экземпляра */

	state = (mcap_state_t *)dip->soft_state;	
	if (state == NULL) return -EFAULT;
	attach_flags |= SOFT_STATE_ALLOCATED;

/* Инициализция программного обеспечения для этого экземпляра */

	state->dip                     = dip;
	state->opened                  = 0;
	state->open_flags              = 0;
	state->open_channel_map        = 0;
	state->drv_comm_busy           = 0;
#ifdef MCAP_OLD_VERSION
	state->drv_general_modes       = DEFAULT_GENERAL_DRV_MODE;
#endif /* MCAP_OLD_VERSION */
	state->intr_number             = 0;
	state->intr_seted              = 0;
	state->mp_drv_loaded           = 0;
	state->mp_state	          	  = undef_mp_state;
	state->mp_drv_started          = 0;
	state->mp_rom_drv_enable	      = 0;
#ifdef MCAP_OLD_VERSION
	state->set_tlrm                = 1;
#endif /* MCAP_OLD_VERSION */
	state->mp_init_code.mem_address      = NULL;
	state->mp_init_code.mp_bmem_address  = NULL;
	state->mp_init_code.byte_size        = 0;
#ifdef MCAP_OLD_VERSION
	state->mp_init_code.mp_drv_init_info = NULL;
	state->mp_init_code.mp_drv_init_info_size = 0;
#endif /* MCAP_OLD_VERSION */
	state->type_unit               = UNDEF_UT;

	channel_state = state->channel_state;
	channel_state -> trans_num = 0;

	mcap_init_drv_state(state);

	state->type_unit = MCAP_UT;


/* SBUS and MP clock-frequency definition */
/*	mcap_sbus_clock_freq = ddi_getprop(DDI_DEV_T_ANY, dip, 0, "clock-frequency", 1);*/
//	mcap_sbus_clock_freq = 20*1000000;
	mcap_sbus_clock_freq = ddi_prop_system_int("clock-frequency");
	if (mcap_sbus_clock_freq < 10 * 1000000 ||
		mcap_sbus_clock_freq > 25 * 1000000) {
		printk("экз. %d. "
			"mcap_attach: недопутимая частота SBus %d.\n",
			instance, mcap_sbus_clock_freq / 1000000);
		goto  m_err;
	};
	mcap_sbus_nsec_cycle = 1000 * 1000000 / mcap_sbus_clock_freq; /* nsec */
	mcap_mp_clock_freq   = mcap_sbus_clock_freq / 2;
	mcap_mp_nsec_cycle   = 1000 * 1000000 / mcap_mp_clock_freq; /* nsec */

/* Карта регистров */
	map_flags     = mcap_map_registers(state, state -> type_unit);
	attach_flags |= map_flags;

	if ((map_flags & ERRORS_SIGN) || (!(map_flags & REGS_MAPPED))) {
		printk("экз. %d. "
			"mcap_doattach: mcap_map_registers завершена с ошибкой."
			"\n\t Не удалось выполнить загрузку регистров устройства "
			"в виртуальную память.\n",
			instance);
		goto  m_err;
	};

	rval = mcap_reset_module(state, LOAD, 1);
	if (rval != 0) {
		printk("экз. %d. "
			"mcap_doattach: были ошибки при общем сбросе модуля.\n",
			instance);
		goto  m_err;
	} else if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_doattach:  произведен сброс модуля.\n",
			instance);
	};

/* Прерывания cookie creation */
	rval = ddi_dev_nintrs(dip, &intr_num);
	if (rval == DDI_FAILURE) {
		printk("экз. %d. "
			 "mcap_doattach: не определен уровень внешних прерываний "
			 "для устройства.\n",
			 instance);
		goto  m_err;
	};
	state->intr_number = intr_num;
	need_intr_num     = 1;	/* только передача прерывания */

	if (intr_num != need_intr_num) {
		printk("экз. %d. "
			"mcap_doattach: устройство имеет более чем %d уровней "
			"внешних прерываний %d.\n",
			instance,
			need_intr_num, intr_num);
		goto  m_err;
	};


/* Инициализировать mutex для этот образец */
	spin_mutex_init(&state->lock);
	attach_flags |= MUTEX_ADDED;

/* Initialize the module condition variables for the instance */
	cv_init(&state->channel_cv);
	cv_init(&state->drv_comm_cv);
	cv_init(&state->intr_cv);
	attach_flags |= CHANNEL_CV_ADDED;

/* Инициализация прерываний и обработчика */
	for (cur_intr = 0; cur_intr < intr_num; cur_intr ++) {
		intr_sbus_levels[cur_intr] = 0;
	}
	intr_levels_size = sizeof(intr_sbus_levels);
	for (cur_intr = 0; cur_intr < intr_num; cur_intr ++) {
/*		if (ddi_intr_hilevel(dip, cur_intr) != 0) {*/
		if (cur_intr == 0) {
			if (ddi_add_irq(dip, &mcap_intr_handler, SA_SHIRQ) != DDI_SUCCESS) {
				printk("экз. %d. "
					"mcap_attach: нельзя использовать уровень внешних пр-ий %d, "
					"используемый только для высокоуровневых пр-ий %d.\n",
					instance,
					cur_intr,
					intr_sbus_levels[cur_intr]);
				goto  m_err;
			} else {

				attach_flags |= INTERRUPT_ADDED;
				state->intr_seted ++;
				if (debug_mcap == 0) {
					printk("экз. %d. "
						"mcap_attach: прерывание %d, "
						"уровень %d обработчика.\n",
						instance,
						cur_intr,
						intr_sbus_levels[cur_intr]);
				};
			};
		} else {
			printk("экз. %d. "
				"mcap_attach: недопустимое прерывание %d уровень %d.\n",
				instance,
				cur_intr, intr_sbus_levels[cur_intr]);
			goto  m_err;
		};
	};

/* Инициализировать ресурсы ПРЯМОГО ДОСТУПА В ПАМЯТЬ */

	state->system_burst = 0x20;	

/* Specific for module types driver additional Attachments */
	rval = mcap_attach_add(state, &add_attach_flags);
	if (rval != 0)
		goto m_err;

/* Установка драйвера МП из ПЗУ *//*!!!!!!!!!!!*/
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_doattach: Установка драйвер МП с ПЗУ.\n",
			instance);
	};
#ifdef MCAP_OLD_VERSION
	rval = mcap_startup_mp(state, ME90IO_STARTUP_MP_ROM_DRV/*, FKIOCTL*/);
#else
	rval = mcap_startup_mp(state, MCAPIO_STARTUP_MP_ROM_DRV/*, FKIOCTL*/);
#endif /* MCAP_OLD_VERSION */
	if (rval != 0) {
		printk("экз. %d. "
			"mcap_doattach: не загружен драйвер МП с ПЗУ.\n",
			instance);
		rval = mcap_reset_general_regs(state, LOAD);
		if (rval != 0) {
			printk("экз. %d. "
			"mcap_doattach: были ошибки при общем сбросе модуля.\n",
			instance);
		};
		goto m_err; /* вставка 09.07.02 */
	} else {
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"mcap_doattach: драйвер МП загружен с ПЗУ.\n",
				instance);
		};
	};

				/*!!!!!!!!!!!!!!!!*/
/* Создание малых узлов; один на канал.
   См. страницу для ddi_create_minor_node (9f) man.
   2-ой параметр - малое имя узла; drvconfig (1M) конкатенирует это к
   /devices входу, после двоеточия.
   4-ый параметр ('экземпляр') - фактический малый номер, помещает
   в inode   /devices входа и передает драйверу.
   5-ый параметр ("DDI_NT_BLOCK_CHAN") - тип узла; это используется
   дисками (1M), чтобы создать связи от /dev до /devices.
*/

	minor = MCAP_MINOR(instance, channel);
	(void) sprintf(name, "%s_%d_:%d", mod_name, instance, channel);
	ddi_create_minor(dip,name, S_IFCHR, minor);
	if (rval != DDI_SUCCESS) {
		printk("экз. %d. "
			"mcap_attach: ddi_create_minor завершена с ошибкой.\n",
			instance);
		goto  m_err;
	};
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_attach: успешное создание малого узла.\n",
			instance);
	};
	attach_flags |= MINOR_NODE_CREATED;
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_attach: конец функционирования. "
			"Драйвер присоединен.\n",
			instance);
	};
	return  DDI_SUCCESS;

m_err:
	if ((attach_flags & INTERRUPT_ADDED)) {
		printk(KERN_ERR "m_err, INTERRUPT_ADDED\n");
		if (state->intr_seted > 0)	{
			ddi_free_irq(dip);
			state->intr_seted = 0;
		}
	}
	if (add_attach_flags != 0) {
		printk(KERN_ERR "m_err, add_attach_flags != 0\n");
		mcap_detach_add(state, add_attach_flags, 1);
	}

	if (attach_flags & CHANNEL_CV_ADDED) {
		printk(KERN_ERR "m_err, CHANNEL_CV_ADDED\n");
		cv_destroy(&state->channel_cv);
		cv_destroy(&state->drv_comm_cv);
		cv_destroy(&state->intr_cv);
	}

	if (attach_flags & MUTEX_ADDED) {
		printk(KERN_ERR "m_err, MUTEX_ADDED\n");
	}

	if (attach_flags & REGS_MAPPED) {
		printk(KERN_ERR "m_err, REGS_MAPPED\n");
		Unmap_reg_sets(state);
	}

	if (attach_flags & MINOR_NODE_CREATED) {
		printk(KERN_ERR "m_err, MINOR_NODE_CREATED\n");
		rmv_dev(dip, channel);
		ddi_rm_dir(dip);
	}

	kfree(dip->soft_state);
	unregister_chrdev(dip->major, dip->prom_name);

	printk(KERN_ERR "INST %d. "
		"mcap_attach: Ошибка загрузки драйвера.\n",
		instance);

	return  DDI_FAILURE;	
	
}

int mcap_attach_add(mcap_state_t *state, int *add_attach_flags)
{
	int	attach_flags = 0;

	cv_init(&state->trans_state_cv);

	attach_flags |= TRANS_STATE_CV_ADDED;
	*add_attach_flags = attach_flags;

	return  0;
}


int 
mcap_detach(dev_info_t 	*dip)
{
	int			instance;
	mcap_state_t		*xsp = NULL;
/*	int			cur_chnl = 0;*/
	int			rval = 0;
	int 			error = DDI_SUCCESS;

	instance = ddi_get_instance(dip);

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_detach: начало функционирования.\n",
			instance);
	};
	xsp = (mcap_state_t *) dip->soft_state;
	if (xsp == NULL) {
		printk("экз. %d. "
			"mcap_detach: не удается получить указатель состояния "
			"драйвера.\n",
			instance);
		return  DDI_FAILURE;
	};

	if (xsp->opened) {
		printk("экз. %d. "
			"mcap_detach: нельзя удалять драйвер открытого устройства.\n",
			instance);
		return  DDI_FAILURE;
	};

	rval = mcap_reset_general_regs(xsp, LOAD);  /*!!!!!!!!*/
	if (rval != 0) {
		printk("экз. %d. "
			"mcap_detach: были ошибки при общем сбросе модуля.\n",
			instance);
	};


	xsp->intr_seted = 0;
	cv_destroy(&xsp->channel_cv);
	cv_destroy(&xsp->drv_comm_cv);
	cv_destroy(&xsp->intr_cv);

	mcap_detach_add(xsp, 0, 1);

	error = (int)rmv_dev(dip, 0);

	if (debug_mcap == 0) {
		printk(KERN_INFO "INST %d. "
			"mcap_detach: Driver detached.\n",
			instance);
	}
	ddi_unrgstr_dev(dip);
	
	return  error;
}

void mcap_detach_add(
	mcap_state_t 	*state, 
	int 		add_attach_flags, 
	int		uncondit_detach)
{
	if ((add_attach_flags & TRANS_STATE_CV_ADDED) || uncondit_detach) {
		cv_destroy(&state->trans_state_cv);
	};
}

void Unmap_reg_sets(mcap_state_t	*state)
{
	int       i_reg_gr = 0;
	caddr_t   *reg_set_p = NULL;

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"Unmap_reg_sets: начало функционирования.\n",
			state->inst);
	};

	ddi_iounmap(state->dip);	

	if (state->MCAP_BMEM != NULL) {
		reg_set_p = (caddr_t *) &(state->MCAP_BMEM);
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"Unmap_reg_sets: устанавлен неотображаемый BMEM %d.\n",
				state->inst,
				i_reg_gr);
		};
		state->MCAP_BMEM = NULL;
		i_reg_gr ++;
	};
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"Unmap_reg_sets: законченный и удаленный %d набор "
			"регистров.\n",
			state->inst,
			i_reg_gr);
	};
}

int rmv_dev(dev_info_t *dip, int channel) 
{
	int	inst  = ddi_get_instance(dip);
	char	name[64];
	int 	error = 0;

	(void) sprintf(name, "%s_%d_:%d", mod_name, inst,
				   channel);
	error = ddi_unlink(dip, name);
	if (error){
		printk("rmv_dev: ddi_unlink failed, error = %d\n", error);
		return error;
	}
	return error;
}



void mcap_init_drv_state(mcap_state_t	*state)
{
	mcap_chnl_state_t	*channel_state = NULL;

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_init_drv_state: начало функционирования.\n",
			state->inst);
	};

	channel_state = state->channel_state;

	channel_state->trans_state_is_init    = 0;
	channel_state->state_init_in_progress = 0;
	channel_state->trans_state_is_halt    = 0;
	channel_state->mp_trans_state_is_halt = 0;
	channel_state->all_trans_finish       = 0;
	channel_state->trans_halt_error       = 0;
	channel_state->init_as_trans_map      = 0;
	channel_state->full_data_buf_size     = 0;
	channel_state->subdev_buf_trans_size  = 0;
	channel_state->subdev_buf_reciv_size  = 0;
	channel_state->init_iomap_state_spec.buf_num = MCAP_SUBDEV_BUF_NUM;
	channel_state->init_iomap_state_spec.max_data_buf_trans_size =
											MCAP_MAX_WORD_DATA_BUF_TRANS*4;
	channel_state->init_iomap_state_spec.max_data_buf_reciv_size =
											MCAP_MAX_DATA_BUF_SIZE;
	channel_state->init_iomap_state_spec.real_buf_size_p = NULL;
	channel_state->init_iomap_state_spec.error_code_p = NULL;


	mcap_init_trans_buf_state(&channel_state->trans_buf_state);

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_init_drv_state: успешное завершение.\n",
			state->inst);
	};
}

irqreturn_t 
mcap_intr_handler(int irq, void *arg, struct pt_regs *regs)
{
	dev_info_t		*dip = (dev_info_t *)arg;
	mcap_state_t 		*state = (mcap_state_t *)dip->soft_state;
	int			args_num = 0;
	int			cur_arg = -1;
	reg_general_mcap_t	read_value;
	int			intr_task;
	intr_reason_t		intr_reason = undefined_intr_reason;
	intr_drv_args_t		interrupt_args;
	int			num_ch = 0;
	drv_intercom_t		*drv_communication = NULL;

	spin_lock(&state->lock);
	dbgmcap(KERN_ALERT "***** mcap_intr_handler STARTED *****\n");
	read_value.rdwr_reg_general = READ_MCAP_REGISTER(state, MCAP_TBL);
	if (read_value.trg_TPSH == 0) {  /* нет прерывания */
		intr_reason = reject_intr_reason;
	} else {
		state->time_get_intr_dev = ddi_gethrtime()/1000;
#ifndef MCAP_OLD_VERSION
		if (read_value.reg_ROSH != 0) {  /* признак РОШ */
		/* Сброс РОШ */
                        WRITE_MCAP_REGISTER(state, MCAP_RERR, 0);
                        state->number_intr_rosh =
                                state->number_intr_rosh + 1; /* кол-во прерываний по РОШ */
                        printk("INST. %d. "
                           "mcap_intr_handler: %d-th ROSH device error.\n",
                                state->inst,
                                state->number_intr_rosh);
                };
#endif /* MCAP_OLD_VERSION */
		drv_communication =
			(drv_intercom_t *) &state->MCAP_BMEM[MCAP_DRV_CMN_AREA_BMEM_ADDR];
		args_num = sizeof(drv_communication->intr_args.args_area)  /
				sizeof(*drv_communication->intr_args.args_area);
		for (cur_arg = 0; cur_arg < args_num; cur_arg ++) {
			interrupt_args.args_area[cur_arg] =
				drv_communication->intr_args.args_area[cur_arg];
		};

/* Сброс регистра прерывания  */
		WRITE_MCAP_REGISTER(state, MCAP_TPSH, 0);
		state->io_flags_intr = 1; /* признак наличия прерывания */

		intr_task = drv_communication->intr_task;
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"get_intr_reason: intr_task = %d.\n",
				state->inst, intr_task);
		};
		switch (intr_task) {
			case mcap_get_intr_driver :
 /* Прерывание от драйвера МП */
				num_ch = interrupt_args.reveal_result.channel_num;
				if (num_ch >= MCAP_SUBDEV_BUF_NUM) {
					printk("INST. %d. "
						"get_intr_reason: wrong channel number %d recieved from "
						"MP.\n",
						state->inst, num_ch);
					intr_reason = undefined_intr_reason;
					break;
				};
				intr_reason = get_intr_driver_reason;
				break;
			case no_sparc_task :
			default:
			   printk("INST. %d. "
				   "get_intr_reason: undefined interrupt  "
				   "recieved %d.\n",
				   state->inst, intr_task);
			   intr_reason = undefined_intr_reason;
			   break;
		};
		drv_communication->intr_task = no_intr_task;
	};
	switch (intr_reason) {
		case reject_intr_reason :
			spin_unlock(&state->lock);
			return IRQ_NONE;
		case get_intr_driver_reason :
			num_ch = interrupt_args.reveal_result.channel_num;
												/* номер канала */
			if (interrupt_args.reveal_result.event_intr == FINISH_TRANS) {
				state->event_intr_trans_ch[num_ch] =
						interrupt_args.reveal_result.event_intr;
												/* код события */
			} else {
				state->event_intr_reciv_ch[num_ch] =
						interrupt_args.reveal_result.event_intr;
												/* код события */
			};
			cv_broadcast (&state->intr_cv);  /* создание условий */
			spin_unlock(&state->lock);
			return IRQ_HANDLED;
#ifdef MCAP_OLD_VERSION
		case board_error_intr_reason :
		   printk("INST. %d. "
			   "mcap_intr_handler: interrupt reason - internal device "
			   "error.\n",
				state->inst);
		   spin_unlock(&state->lock);
		   return IRQ_HANDLED;
#endif /* MCAP_OLD_VERSION */
		case undefined_intr_reason :
		default:
		   printk("INST. %d. "
			   "mcap_intr_handler: undefined interrupt reason from MP "
			   "driver %d.\n",
			   state->inst, intr_reason);
		   spin_unlock(&state->lock);   
		   return IRQ_NONE;
	};
}

int mcap_get_channel_to_init(
	mcap_state_t			*state,
	int				waiting_time,
	int				drv_comm_area_locked,
	int				user_request,
	int				state_recover)
{
/* Структура внутреннего состояния устройства - mcap.h */
	mcap_chnl_state_t	*channel_state = NULL;
/* Структура параметров останова обменов и закрытия устройства - mcap_io.h */
	mcap_halt_trans_t	halt_trans_state;
	int					rval = 0;

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_get_channel_to_init: начало функционирования.\n",
			state->inst);
	};
	channel_state = state->channel_state;
	if (!state_recover)
			spin_mutex_enter(&state->lock);
	while (channel_state->state_init_in_progress) {
		rval = cv_spin_wait(&state->trans_state_cv, &state->lock);
		if (rval <= 0) {
			if (!state_recover)
					spin_mutex_exit(&state->lock); 
			printk("экз. %d. "
				"mcap_get_channel_to_init: ожидание завершения прерывания "
				"другой инициализации в канале.\n",
				state->inst);
			return -EINTR;
		};
	};
/* Установка признака выполнения инициализации устройства */
	channel_state->state_init_in_progress = 1;
	if (channel_state->trans_state_is_init && !state_recover) {
		if (!user_request) {
			channel_state->state_init_in_progress = 0;
			cv_broadcast(&state->trans_state_cv);
			if (!state_recover)
					spin_mutex_exit(&state->lock); 
			return (-1);
		};

		if (!state_recover)
				spin_mutex_exit(&state->lock);	

#ifdef MCAP_OLD_VERSION
/* Закрытие устройства через заданный временной интервал */
		halt_trans_state.waiting_time = waiting_time;
#else
		halt_trans_state.flag_close = 0;
#endif /* MCAP_OLD_VERSION */
		rval = mcap_halt_trans_state(state, &halt_trans_state,
				drv_comm_area_locked, 0, state_recover);
		if (rval != 0) {
			printk("экз. %d. "
				"mcap_get_channel_to_init: не может закрыть устройсто.\n",
				state->inst);
		};
		if (!state_recover)
				spin_mutex_enter(&state->lock);	
		if (channel_state->trans_state_is_init) {
			channel_state->state_init_in_progress = 0;
			cv_broadcast(&state->trans_state_cv);
			if (!state_recover)
					spin_mutex_exit(&state->lock);
			printk("экз. %d. "
				"mcap_get_channel_to_init: не может завершить все "
				"передачи.\n",
				state->inst);
			return -EBUSY;
		};
	};
	if (channel_state->trans_buf_state.valid_flag && !state_recover)
		mcap_delete_drv_trans_buf(state);

/* Обнуление элементов структуры внутреннего состояния устройства -
   mcap_chnl_state_t (mcap.h) */
   
	channel_state->trans_state_is_init    = 0;
	channel_state->trans_state_is_halt    = 0;
	channel_state->mp_trans_state_is_halt = 0;
	channel_state->all_trans_finish       = 0;
	channel_state->trans_halt_error       = 0;
	channel_state->init_as_trans_map      = 0;
	channel_state->full_data_buf_size     = 0;
	channel_state->subdev_buf_trans_size  = 0;
	channel_state->subdev_buf_reciv_size  = 0;
	if (state_recover == 0) spin_mutex_exit(&state->lock);

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_get_channel_to_init: успешное завершение.\n",
			state->inst);
	};
	return (0);
}

void mcap_free_channel_to_init(
	mcap_state_t	*state,
	int		mutex_locked)
{
/* Структура внутреннего состояния устройства */
	mcap_chnl_state_t	*channel_state = NULL;

	dbgmcap("***** inst. %d. "
			"mcap_free_channel_to_init: START. *****\n",
			state->inst);

	channel_state = state->channel_state;
	if (!mutex_locked)
		  spin_mutex_enter(&state->lock);		
/* Снятие признака выполнения инициализации устройства */
	if (channel_state->state_init_in_progress) {
		channel_state->state_init_in_progress = 0;
		cv_broadcast(&state->trans_state_cv);
	};
	if (!mutex_locked)
		spin_mutex_exit(&state->lock);		

	dbgmcap("inst. %d. "
			"mcap_free_channel_to_init: FINISH.\n",
			state->inst);
}

int mcap_init_trans_map_state(
	mcap_state_t		*state,
	mcap_init_iomap_t	*init_state_args,
	int			drv_comm_area_locked,
	int			*error_code,
	int			state_recover)

{

	mcap_chnl_state_t	*channel_state = NULL;
	mcap_init_iomap_t	*init_iomap_state_spec = NULL; 	/* mcap_io.h */
	mp_drv_args_t		init_trans_state_args;		/* mcap_def.h */
	sparc_drv_args_t	init_state_results;		/* mcap_def.h */
	int			user_request = (init_state_args != NULL);
	int			max_buf_num = 0; /* мак. кол-во буферов */
	u_short			max_data_buf_trans_size = 0;
	u_short			max_data_buf_reciv_size = 0;
	int			cur_buf = 0;
	int			rval    = 0;

	channel_state = state->channel_state;

	dbgmcap("***** START mcap_init_trans_map_state \n");
/* Обнуление элементов структуры внутреннего состояния устройства -
   mcap_chnl_state_t (mcap.h) */
	rval = mcap_get_channel_to_init(state, -1,
			drv_comm_area_locked, user_request, state_recover);

	if (rval > 0) {
		return (rval);
	} else if (rval < 0) {
		return (0);
	};
	if (init_state_args != NULL) {
		channel_state->init_iomap_state_spec = *init_state_args;
	};
/* Состояние - инициализация карты пересылки */
	init_iomap_state_spec = &channel_state->init_iomap_state_spec;

	max_buf_num             = init_iomap_state_spec->buf_num;
	max_data_buf_trans_size = init_iomap_state_spec->max_data_buf_trans_size;
	max_data_buf_trans_size =
		TU_MCAP_DMA_BURST_SIZE_ALIGN(max_data_buf_trans_size,
			sizeof(u_char), 0, MCAP_DMA_BURST_SIZE) *
			sizeof(u_char);
	init_iomap_state_spec->max_data_buf_trans_size = max_data_buf_trans_size;
	
	max_data_buf_reciv_size = init_iomap_state_spec->max_data_buf_reciv_size;
	max_data_buf_reciv_size =
		TU_MCAP_DMA_BURST_SIZE_ALIGN(max_data_buf_reciv_size,
			sizeof(u_char), 0, MCAP_DMA_BURST_SIZE) *
			sizeof(u_char);
	init_iomap_state_spec->max_data_buf_reciv_size = max_data_buf_reciv_size;

	dbgmcap("inst. %d. "
			"mcap_init_trans_map_state: buf_num = %d, "
			" max_data_buf_trans_size = %d , "
			" max_data_buf_reciv_size = %d .\n",
			state->inst,
			init_iomap_state_spec->buf_num, 	
			init_iomap_state_spec->max_data_buf_trans_size,
			init_iomap_state_spec->max_data_buf_reciv_size);

/* Создание буфер карты обмена */
	rval = mcap_create_drv_iomap_buf(state);
	
	if (rval != 0) {
		printk("экз. %d. "
			"mcap_init_trans_map_state: mcap_create_drv_iomap_buf "
			"завершена с ошибкой.\n",
			state->inst);
		return rval;
	};

/* Формирование аргументов задания на инициализацию буферов обмена */
	init_trans_state_args.init_buf_exch.num_buf_user       = max_buf_num;
	init_trans_state_args.init_buf_exch.max_size_buf_trans = max_data_buf_trans_size;
/* Пересылка адресов буферов обмена*/
	for (cur_buf = 0; cur_buf < max_buf_num; cur_buf ++) {
		init_trans_state_args.init_buf_exch.dma_trans_bufs[cur_buf] =
			channel_state->trans_buf_state.dma_trans_bufs[cur_buf];
	};
	if (!state_recover)
			spin_mutex_enter(&state->lock);		
	channel_state->init_as_trans_map  = 1;
	channel_state->full_data_buf_size = 0;
	channel_state->subdev_buf_trans_size = max_data_buf_trans_size +
						sizeof(mcap_iosubd_desc_t);
	channel_state->subdev_buf_reciv_size = max_data_buf_reciv_size +
						sizeof(mcap_iosubd_desc_t);
	if (!state_recover)
		spin_mutex_exit(&state->lock);		
/* Выдача задания драйверу МП на инициализацию буферов обмена */
/* и чтение результата выполнения задания */
	rval = mcap_start_task_drv_mp(state, init_buffers_data_exchange_task,
			&init_trans_state_args, &init_state_results);
	if (!state_recover)
			spin_mutex_enter(&state->lock);		
	if (rval != 0) {
		mcap_delete_drv_trans_buf(state);
		printk("экз. %d. "
			"mcap_init_trans_map_state: аварийное завершение "
			"функционирования.\n",
			state->inst);
	};
	if (init_state_results.init_buf_exch_res.error_init_bufers != 0) {
		mcap_delete_drv_trans_buf(state);
		if (rval == 0) 	rval = -EIO;
		if (error_code != NULL)
			*error_code = 
					init_state_results.init_buf_exch_res.error_init_bufers;
		printk("экз. %d. "
			"mcap_init_trans_map_state: завершена с ошибкой 0x%02x.\n",
			state->inst,
			init_state_results.init_buf_exch_res.error_init_bufers);
	};
	if (rval == 0) {
		channel_state->trans_state_is_init = 1;
	} else {
		channel_state->init_as_trans_map = 0;
	};
	
	if (!state_recover)
		spin_mutex_exit(&state->lock);

	mcap_free_channel_to_init(state, state_recover);

	dbgmcap("***** inst. %d. "
			"mcap_init_trans_map_state: FINISH. ***** \n",
			state->inst);

	return (rval);
}

int mcap_create_drv_iomap_buf(
	mcap_state_t	*state)
{
	mcap_chnl_state_t	*channel_state     = NULL;
	trbuf_state_t		*trans_buf_state   = NULL;
	size_t			max_buf_trans_size = 0;
	size_t			max_buf_reciv_size = 0;
	int			max_buf_num        = 0;
	int			max_subdev_num     = 0;
	caddr_t			user_buf_address   = 0;
	u_int			dma_buf_address    = 0;
	mcap_iosubdbuf_t	*cur_subdev_buf    = NULL;
	size_t			user_buf_size      = 0;
	size_t			drv_buf_size       = 0;
	long			page_size          = PAGE_SIZE;
	long			page_allign        = 0;
	int			cur_buf            = 0;
	int			rval               = 0;

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_create_drv_iomap_buf: начало функционирования.\n",
			state->inst);
	};
/* Внутреннее состояние устройства */
	channel_state = state->channel_state;
/* Состояние буфера пересылки */
	trans_buf_state = &channel_state->trans_buf_state;
/* Реальный максимальный размер передающего буфера обмена (байтов)*/
	max_buf_trans_size = 
			channel_state->init_iomap_state_spec.max_data_buf_trans_size + sizeof(mcap_iosubd_desc_t);
/* Реальный максимальный размер приемного буфера обмена (байтов)*/
	max_buf_reciv_size =
			channel_state->init_iomap_state_spec.max_data_buf_reciv_size + sizeof(mcap_iosubd_desc_t);
	max_subdev_num = 1;
	max_buf_num = channel_state->init_iomap_state_spec.buf_num;
/* Буфер передатчика + буфер приемника */
	user_buf_size = max_buf_trans_size + max_buf_reciv_size;
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"user_buf_size = 0x%lx.\n",
			state->inst,
			(u_long)user_buf_size);
	};
/* Общий размер буфер */
	drv_buf_size = user_buf_size * max_buf_num;
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"drv_buf_size = 0x%lx.\n",
			state->inst,
			(u_long)drv_buf_size);
	};
/* Создание и размещение буферов обмена */
	rval = mcap_alloc_trans_bufs(state, &trans_buf_state->trans_buf_desc,
			drv_buf_size + page_size);
	if (rval != 0) {
		printk("экз. %d. "
			"mcap_create_drv_iomap_buf: отказ.\n",
			state->inst);
		return rval;
	};
	user_buf_address = trans_buf_state->trans_buf_desc.buf_address;
	(dma_addr_t)dma_buf_address  = trans_buf_state->trans_buf_desc.dma.busa;/*trans_buf_desc.cookie.dmac_address;*/
	page_allign      = (long)user_buf_address & (page_size - 1);
	if (page_allign != 0) {
		user_buf_address = user_buf_address + (page_size - page_allign);
		dma_buf_address  = dma_buf_address + (page_size - page_allign);
	};
 /* Формирование структуры буфера пересылки - trbuf_state_t (mcap.h) */
	trans_buf_state->user_buf_address = user_buf_address;
	trans_buf_state->user_buf_size    = user_buf_size;
	trans_buf_state->max_user_buf_num = max_buf_num;
	for (cur_buf = 0; cur_buf < max_buf_num; cur_buf ++) {
		trans_buf_state->user_trans_bufs[cur_buf] = user_buf_address;
		cur_subdev_buf = (mcap_iosubdbuf_t *) user_buf_address;

/* Инициализация буфера карты передачи */
		mcap_init_iomap_buf(state, cur_subdev_buf, max_buf_trans_size,
							 max_buf_reciv_size,  cur_buf);
		user_buf_address = user_buf_address + user_buf_size;
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"user_buf_address = %lx.\n",
				state->inst,
				(unsigned long)user_buf_address);
		};
/* Адрес буфера пересылки */
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"dma_buf_address = 0x%x.\n",
				state->inst,
				dma_buf_address);
		};
		trans_buf_state->dma_trans_bufs[cur_buf] = dma_buf_address;
		dma_buf_address = dma_buf_address + user_buf_size;
	};
/* Сформирован буфер пересылки */
	trans_buf_state->valid_flag = 1;
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_create_drv_iomap_buf: успешное завершение.\n",
			state->inst);
	};
	return 0;
}

void mcap_delete_drv_trans_buf(
	mcap_state_t	*state)
{
	mcap_chnl_state_t	*channel_state = NULL;
	trbuf_state_t		*trans_buf_state = NULL;

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_delete_drv_trans_buf: начало функционирования.\n",
			state->inst);
	};
	channel_state = state->channel_state;
	trans_buf_state = &channel_state->trans_buf_state;
	if (!trans_buf_state->valid_flag)
		return;
	mcap_free_trans_bufs(state, &trans_buf_state->trans_buf_desc);
	mcap_init_trans_buf_state(trans_buf_state);
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_delete_drv_trans_buf: успешное завершение.\n",
			state->inst);
	};
}

void mcap_init_trans_buf_state(
	trbuf_state_t	*trans_buf_state)
{
	int	cur_buf     = 0;
	int	max_buf_num = 0;

	if (debug_mcap == 0) {
		printk("mcap_init_trans_buf_state: начало функционирования.\n");
	};
	trans_buf_state->valid_flag = 0;
	trans_buf_state->user_buf_address = 0;
	trans_buf_state->user_buf_size = 0;
	trans_buf_state->max_user_buf_num = 0;
	max_buf_num = sizeof(trans_buf_state->user_trans_bufs) /
			sizeof(*trans_buf_state->user_trans_bufs);
	for (cur_buf = 0; cur_buf < max_buf_num; cur_buf ++) {
		trans_buf_state->user_trans_bufs[cur_buf] = 0;
		trans_buf_state->dma_trans_bufs[cur_buf] = 0;
	};
	mcap_init_trans_buf_desc(&trans_buf_state->trans_buf_desc);
	if (debug_mcap == 0) {
		printk("mcap_init_trans_buf_state: успешное завершение.\n");
	};
}

void mcap_init_trans_buf_desc(
	trbuf_desc_t	*trans_buf_desc)
{
	trans_buf_desc->buf_address = 0;
	trans_buf_desc->buf_size    = 0;
}

int mcap_halt_trans_state(
	mcap_state_t *		state,
	mcap_halt_trans_t	*halt_trans_state,
	int			drv_comm_area_locked,
	int			user_request,
	int			mutex_locked)
{
	mcap_chnl_state_t 	*channel_state = NULL;
#ifdef MCAP_OLD_VERSION
	int			waiting_time = 0;
	int			rval = 0;
	int			rval_1 = 0; /* 24.07.20000 */
#else
        int                     rval = 0;
#endif /* MCAP_OLD_VERSION */
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_halt_trans_state: начало функционирования.\n",
			state->inst);
	};

	channel_state = state->channel_state;
	if (!mutex_locked)
		spin_mutex_enter(&state->lock);		
	if (channel_state->trans_state_is_init == 0) {
		if (!mutex_locked)
			spin_mutex_exit(&state->lock);
		if (user_request && !channel_state->trans_state_is_halt) {
			printk("экз. %d. "
				"mcap_halt_trans_state: останов не инициализированного "
				"устройства.\n",
				state->inst);
			return 0;
		} else {
			printk("экз. %d. "
				"mcap_halt_trans_state: останов не инициализированного "
				"или остановленного уже устройства.\n",
				state->inst);
			return 0;
		};
	};
#ifdef MCAP_OLD_VERSION
	waiting_time = halt_trans_state->waiting_time;
#endif /* MCAP_OLD_VERSION */
	if (channel_state->trans_state_is_halt == 0) {
		channel_state->trans_state_is_halt = 1;
		channel_state->all_trans_finish = 0;
		channel_state->trans_halt_error = 0;
	};
#ifndef MCAP_OLD_VERSION
	if (halt_trans_state->flag_close != 0) {
/* Сброс модуля и МП */
                WRITE_MCAP_REGISTER(state, MCAP_TZM, 0);
                if (debug_mcap == 0) {
                        printk("экз. %d. "
                                "mcap_halt_trans_state: произведён сброс модуля и МП.\n",
                                state->inst);
                };
        }
#endif /* MCAP_OLD_VERSION */
	if (!mutex_locked)
		spin_mutex_exit(&state->lock);
#ifdef MCAP_OLD_VERSION
	rval = mcap_halt_transfers(state, waiting_time, 0, mutex_locked, drv_comm_area_locked);
#else
	rval = mcap_halt_transfers(state, mutex_locked, drv_comm_area_locked);
#endif /* MCAP_OLD_VERSION */
	if (rval != 0) {
		printk("экз. %d. "
			"mcap_halt_trans_state: не может остановить канал.\n",
			state->inst);
	};

#ifdef MCAP_OLD_VERSION
	if (channel_state->all_trans_finish == 0) {
		printk("экз. %d. "
			"mcap_halt_trans_state: состояние передачи устройства будет "
			"прервано.\n",
			state->inst);
		rval_1 = mcap_halt_transfers(state, 0, 1, mutex_locked, drv_comm_area_locked);
		if (rval_1 != 0) {
			printk("экз. %d. "
				"mcap_halt_trans_state: не может прервать состояние "
				"передачи устройства.\n",
				state->inst);
		};
	};
	if (rval != 0) {
		printk("экз. %d. "
			"mcap_halt_trans_state: передача была остановлена c ошибкой.\n",
			state->inst);
	};
#endif /* MCAP_OLD_VERSION */

	if (!mutex_locked)
		spin_mutex_enter(&state->lock);
	if (channel_state->all_trans_finish) {
		channel_state->trans_state_is_init = 0;
		if (user_request) {
			channel_state->trans_state_is_halt    = 0;
			channel_state->mp_trans_state_is_halt = 0;
			channel_state->all_trans_finish       = 0;
			channel_state->trans_halt_error       = 0;
			channel_state->init_as_trans_map      = 0;
			channel_state->full_data_buf_size     = 0;
			channel_state->subdev_buf_trans_size  = 0;
			channel_state->subdev_buf_reciv_size  = 0;
		};
		cv_broadcast(&state->trans_state_cv);
	};
	if (!mutex_locked)
		spin_mutex_exit(&state->lock);

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_halt_trans_state: конец функционирования.\n",
			state->inst);
	};
	return rval;
}


int mcap_wait_for_trans_state_halt(
	mcap_state_t 		*state,
	int			waiting_time)
{
	mcap_chnl_state_t 	*channel_state = NULL;
	clock_t			cur_clock_ticks = 0;
	clock_t			timeout_clock_ticks = 0;
	int			rval = 0;
	hrtime_t		start_time = 0;
	hrtime_t		end_time = 0;
	int			cur_waiting_time = 0;

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_wait_for_trans_state_halt: начало функционирования.\n",
			state->inst);
	};
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_wait_for_trans_state_halt: waiting_time = %d.\n",
			state->inst,
			waiting_time);
	};
	channel_state = state->channel_state;
	start_time = ddi_gethrtime();
	end_time = start_time;
	while (!channel_state->all_trans_finish &&
		channel_state->trans_halt_error == 0) {
		if (waiting_time == 0)
			break;
		end_time = ddi_gethrtime();
		drv_getparm(LBOLT, (u_long *)&cur_clock_ticks);
		timeout_clock_ticks = cur_clock_ticks +
			drv_usectohz(waiting_time - cur_waiting_time);
		rval = cv_spin_timedwait(&state->trans_state_cv,
				&state->lock, timeout_clock_ticks);
		if (rval < 0) {
			cur_waiting_time =
				mcap_calculate_work_hr_time(start_time,
								end_time);
			if (cur_waiting_time < waiting_time) {
				rval = 0;
				continue;
			};
			printk("экз. %d. "
				"mcap_wait_for_trans_state_halt: ожидание завершения "
				"блокировки по времени конца передачи. Время ожидания %d.\n",
				state->inst, cur_waiting_time);
			if (channel_state->all_trans_finish) {
				printk("экз. %d. "
					"mcap_wait_for_trans_state_halt: в предпоследний "
					"раз не произошло завершение передачи.\n",
					state->inst);
				rval = 0;
			} else {
				rval = ETIME;
				channel_state->trans_halt_error = rval;
			};
			break;
		} else {
			rval = 0;
		};
	};
	return (rval);
}



int mcap_halt_transfers(
	mcap_state_t 		*state,
#ifdef MCAP_OLD_VERSION
	int			waiting_time,
	int			delete_rem_trans,
#endif /* MCAP_OLD_VERSION */
	int			mutex_locked,
	int			drv_comm_area_locked)
{
	mcap_chnl_state_t 	*channel_state = NULL;

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_halt_transfers: начало функционирования.\n",
			state->inst);
	};
	channel_state = state->channel_state;
	if (!mutex_locked)
		spin_mutex_enter(&state->lock);		
	if (channel_state->all_trans_finish) {
		if (channel_state->trans_buf_state.valid_flag) {
			mcap_delete_drv_trans_buf(state);
		};
		if (!mutex_locked)
			spin_mutex_exit(&state->lock);
		printk("экз. %d. "
			"mcap_halt_transfers: все передачи уже закончены.\n",
			state->inst);
		return (0);
	};
	if (channel_state->trans_state_is_halt == 0) {
		printk("экз. %d. "
			"mcap_halt_transfers: режим обменов все еще не завершен "
			"для устройства.\n",
			state->inst);
	};
#ifdef MCAP_OLD_VERSION
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_halt_transfers: waiting_time = %d.\n",
			state->inst,
			waiting_time);
	};
#endif /* MCAP_OLD_VERSION */
	channel_state->all_trans_finish = 1;
	cv_broadcast(&state->trans_state_cv);
	if (channel_state->trans_buf_state.valid_flag)
		mcap_delete_drv_trans_buf(state);
	if (!mutex_locked)
		spin_mutex_exit(&state->lock);

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_halt_transfers: конец функционирования.\n",
			state->inst);
	};
	return (0);
}

void mcap_init_subdev_buf(
	mcap_state_t		*state,
	mcap_iosubdbuf_t	*subdev_buf,
	int			io_flags,
	size_t			max_data_buf_size,
	int			subdev_buf_num)
{
	mcap_iosubd_desc_t	*subdev_buf_desc  = &subdev_buf->buf_desc;
	caddr_t			*data_buf = (caddr_t *)&subdev_buf->data_buf;
	size_t			all_data_buf_size = 0;
	int			cur_word          = 0;
	short 			_io_flags = io_flags;
	short			_subdev_buf_num = subdev_buf_num;

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_init_subdev_buf: начало функционирования с буфером %d.\n",
			state->inst,
			subdev_buf_num);
	};
	subdev_buf_desc->transfer_completed  = 0;
	subdev_buf_desc->channel_check_word  = 0;
	subdev_buf_desc->data_size_exchange  = 0;
	subdev_buf_desc->first_error 	     = 0;
	subdev_buf_desc->num_error 	     = 0;
	subdev_buf_desc->exchange_error_code = 0;
	subdev_buf_desc->signal_adapter      = 0;
	subdev_buf_desc->cur_ease_code	     = 0;
#ifdef MY_DRIVER_BIG_ENDIAN
	subdev_buf_desc->buf_num 	     = _subdev_buf_num;
	subdev_buf_desc->io_flags 	     = _io_flags;
#else
	subdev_buf_desc->buf_num 	     = flip_word(_subdev_buf_num);
	subdev_buf_desc->io_flags 	     = flip_word(_io_flags);
#endif /* MY_DRIVER_BIG_ENDIAN */
	subdev_buf_desc->data_size 	     = 0;
	subdev_buf_desc->unused2 	     = 0;
	subdev_buf_desc->unused_word6  	     = 0;
	subdev_buf_desc->unused_word7  	     = 0;

	all_data_buf_size = max_data_buf_size / sizeof(caddr_t);
	for (cur_word = 0; cur_word < all_data_buf_size; cur_word ++) {
		data_buf[cur_word] = (caddr_t)&data_buf[cur_word];
	};

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_init_subdev_buf: успешное завершение c буфером %d.\n",
			state->inst,
			subdev_buf_num);
	};
	return;
}

void mcap_init_iomap_buf(
	mcap_state_t		*state,			 /* собственная информация драйвера */
	mcap_iosubdbuf_t	*iomap_buf_desc, /* дескриптор буфера обмена */
	size_t				subdev_buf_trans_size, /* максимальный размер */
										 /* буфера передачи */
	size_t				subdev_buf_reciv_size, /* максимальный размер */
										 /* буфера приема */
	int					iomap_buf_num)	 /* номер буфера карты */
{
	caddr_t				iomap_buf        = (caddr_t)iomap_buf_desc;
	mcap_iosubdbuf_t	*cur_subdev_desc = NULL;

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_init_iomap_buf: начало функционирования для буфера "
			"0x%08lx, размер буфера 0x%lx байтов.\n",
			state->inst,
			(unsigned long)iomap_buf_desc, (u_long)subdev_buf_trans_size);
	};
	cur_subdev_desc = (mcap_iosubdbuf_t *) &iomap_buf[0];
 /* Инициализация дескриптора и области данных буфера */
	mcap_init_subdev_buf(state, cur_subdev_desc, MCAP_IO_WRITE,
					subdev_buf_trans_size - sizeof(mcap_iosubd_desc_t),
					iomap_buf_num);
	cur_subdev_desc =
				 (mcap_iosubdbuf_t *) &iomap_buf[subdev_buf_trans_size];
 /* Инициализация дескриптора и области данных буфера */
	mcap_init_subdev_buf(state, cur_subdev_desc, MCAP_IO_READ,
					subdev_buf_reciv_size - sizeof(mcap_iosubd_desc_t),
					iomap_buf_num);

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_init_iomap_buf: успешное завершение.\n",
			state->inst);
	};
}


int mcap_start_task_drv_mp(
	mcap_state_t 		*state,
	mp_task_t		mp_task,
	mp_drv_args_t 		*task_args,
	sparc_drv_args_t	*mp_task_results
	)
{
	drv_intercom_t		*drv_communication = NULL;
	int			args_num = 0;
	int			cur_arg = 0;
	int			waiting_time = 0;
	int        		workval = 0;
	int			wait_mp_task_accept = 0;
	int			wait_mp_rom_drv_disable = 0;
	int			rval = 0;
	int			flag_MP;

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_start_task_drv_mp: начало функционирования c заданием %d.\n",
			state->inst,
			mp_task);
	};
	drv_communication =
		(drv_intercom_t *) &state->MCAP_BMEM[MCAP_DRV_CMN_AREA_BMEM_ADDR];

	if ((state->mp_drv_started == 0) && (mp_task != init_driver_mp_task)) {
		state->drv_comm_busy = 0;
		cv_broadcast(&state->drv_comm_cv);
		printk("экз. %d. "
			"mcap_start_task_drv_mp: драйвер МП еще не загружен "
			"и не инициализирован.\n",
			state->inst);
		return -EINVAL;
	};

 /* Ожидание обнуления области задания драйвером MП по последнему заданию */
	waiting_time = 0;
	while (waiting_time < MCAP_TASK_ACCEPT_BY_MP_TIME) {
		workval = drv_communication->mp_task;
		if (workval == no_mp_task) {
			break;
		};
		waiting_time = waiting_time + MCAP_TASK_ACCEPT_BY_MP_DELAY_TIME;
		udelay(MCAP_TASK_ACCEPT_BY_MP_DELAY_TIME/**1000*/);
	};
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_start_task_drv_mp: Т обнуления области задания = %d мксек.\n",
			state->inst,
			waiting_time);
	};
	if (workval != no_mp_task) {
		flag_MP = drv_communication->flag_mp;
		udelay(MCAP_TASK_ACCEPT_BY_MP_DELAY_TIME*30/**1000*/);
		if (flag_MP == drv_communication->flag_mp) {
			printk("экз. %d. "
				"mcap_start_task_drv_mp: MП не исполняет программу "
				"драйвера МП (0x%x == 0x%x).\n",
				state->inst, flag_MP, drv_communication->flag_mp);
		} else {
			printk("экз. %d. "
				"mcap_start_task_drv_mp: задание %d не может быть "
				"выполнено, т.к. не обнулена область заданий драйвером МП "
				"после выполнения задания %d.\n",
				state->inst, 
				mp_task,
				workval);
		};	
		state->mp_state = hangup_mp_state;
		state->drv_comm_busy = 0;
		cv_broadcast(&state->drv_comm_cv);
		return -EACCES;
	};
													
	switch (mp_task) {
		case init_driver_mp_task :
			if (task_args != NULL) {
				args_num = sizeof(drv_communication->mp_args.args_area);
			} else {
			   args_num = 0;
			};
			if (mp_task_results != NULL) {
			   mp_task_results->mp_init_results.mp_error_code = 0;
			};
		   break;
		case init_buffers_data_exchange_task :
		   args_num =
			  (sizeof(init_bufers_exchange_data_t) +
			   (sizeof(*drv_communication->mp_args.args_area)-1)
			  ) / sizeof(*drv_communication->mp_args.args_area);
		   if (mp_task_results != NULL)
			  mp_task_results->init_buf_exch_res.error_init_bufers = 0;
		   break;
		case mcap_halt_channel_data_exchange_task :
		case mcap_turn_off_channels_task :
		   args_num =
			  (sizeof(init_bufers_exchange_data_t) +
			   (sizeof(*drv_communication->mp_args.args_area)-1)
			  ) / sizeof(*drv_communication->mp_args.args_area);
		   break;
		case no_mp_task :
		default:
			printk("экз. %d. "
				"mcap_start_task_drv_mp: неверное задание %d для "
				"драйвера МП.\n",
				state->inst, mp_task);
			return -EINVAL;
	};
	if (state->drv_comm_busy != 0) {
		printk("экз. %d. "
			"mcap_start_task_drv_mp: заблокирован доступ к области памяти "
			"междрайверного взаимодействия.\n",
			state->inst);
		return -EINVAL;
	};

	if (state->mp_state != started_mp_state && mp_task != init_driver_mp_task) {
		printk("экз. %d. "
			"mcap_start_task_drv_mp: драйвер МП находится в "
			"нерабочем состоянии.\n",
			state->inst);
		if (state->mp_state == crash_mp_state) {
			state->drv_comm_busy = 0;
			cv_broadcast(&state->drv_comm_cv);
		};
		return -EACCES;
	};

	state->drv_comm_busy = 1;
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_start_task_drv_mp: выдача задания МП.\n",
			state->inst);
	};
 /* Запись параметров задания и кода задания в область междрайверной связи */
	for (cur_arg = 0; cur_arg < args_num; cur_arg ++) {
		drv_communication->mp_args.args_area[cur_arg] =
		   task_args->args_area[cur_arg];
		if ((debug_mcap == 0) && (mp_task == init_buffers_data_exchange_task)) {
			printk("экз. %d. "
				"mcap_start_task_drv_mp: %d: 0x%08x.\n",
				state->inst,
				cur_arg, task_args->args_area[cur_arg]);
		};

	};
	drv_communication->mp_task = mp_task;

	wait_mp_task_accept |= (mp_task == init_driver_mp_task ||
				 mp_task == init_buffers_data_exchange_task ||
				 mp_task == mcap_halt_channel_data_exchange_task ||
				 mp_task == mcap_turn_off_channels_task);
/* Запуск драйвера МП */
	wait_mp_rom_drv_disable = (mp_task == init_driver_mp_task);
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_start_task_drv_mp: mp_task = %d, wait_mp_task_accept = %d, "
			"wait_mp_rom_drv_disable = %d .\n",
			state->inst,
			mp_task, wait_mp_task_accept, wait_mp_rom_drv_disable);
	};
	rval = mcap_wait_make_task_drv_mp(state, mp_task == init_driver_mp_task,
				wait_mp_task_accept, wait_mp_rom_drv_disable);
	if (rval == 0 && mp_task == init_driver_mp_task) {
/* Загрузка драйвера МП произведена */
		state->mp_state = started_mp_state;
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"mcap_start_task_drv_mp: загрузка драйвера МП произведена.\n",
				state->inst);
		};
#ifdef MCAP_OLD_VERSION
	} else if (rval == EMPROMDISABLE) {
#else
	} else if (rval == -EINVAL) {
#endif /* MCAP_OLD_VERSION */
		drv_communication->mp_task = no_mp_task;
		state->mp_state = halted_mp_state;
	} else if (rval != 0) {
		printk("экз. %d. "
			"mcap_start_task_drv_mp: драйвер МП не выполнил задание %d.\n",
			state->inst, mp_task);
		state->mp_state = hangup_mp_state;
	};
	if ((mp_task == init_buffers_data_exchange_task) && rval == 0) {
/* Ожидание ответа от драйвера MП после выполнения им задания */
		waiting_time = 0;
		while (waiting_time < MCAP_TASK_ACCEPT_BY_MP_TIME) {
			workval = drv_communication->sparc_task;
			if (workval != no_sparc_task) {
				break;
			};
			waiting_time = waiting_time + MCAP_TASK_ACCEPT_BY_MP_DELAY_TIME;
/*			drv_usecwait(MCAP_TASK_ACCEPT_BY_MP_DELAY_TIME);*/
			udelay(MCAP_TASK_ACCEPT_BY_MP_DELAY_TIME/**1000*/);
		};
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"mcap_start_task_drv_mp: Т ожидания ответа = %d мксек.\n",
				state->inst,
				waiting_time);
		};
		if (workval != mp_task) {
			printk("экз. %d. "
				"mcap_start_task_drv_mp: код ответа драйвера МП = %d != коду "
				"полученного задания %d.\n",
				state->inst, 
				workval, 
				mp_task);
		} else {
/* Чтение результатов выполнения задания из памяти драйвера МП */
			for (cur_arg = 0;
				cur_arg < (sizeof(drv_communication->sparc_args.args_area) +
						(sizeof(*drv_communication->sparc_args.args_area) - 1)
					   ) / sizeof(*drv_communication->sparc_args.args_area);
				cur_arg ++) {
				mp_task_results->args_area[cur_arg] =
				drv_communication->sparc_args.args_area[cur_arg];
			};
/* Анализ результата инициализации буферов обмена */
			if (mp_task_results->init_buf_exch_res.error_init_bufers != 0) {
				printk("экз. %d. "
					"mcap_start_task_drv_mp: инициализация буферов обмена "
					"завершена с ошибкой 0x%02x.\n",
					state->inst,
					mp_task_results->init_buf_exch_res.error_init_bufers &
																		0xff);
			};
			drv_communication->sparc_task = no_sparc_task;
		};
	};
	state->drv_comm_busy = 0;
	cv_broadcast(&state->drv_comm_cv);

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_start_task_drv_mp: конец функционирования для задания %d.\n",
			state->inst,
			mp_task);
	};
	return rval;
}

int mcap_wait_make_task_drv_mp(
	mcap_state_t		*state,
	int			mp_restart,
	int			wait_mp_task_accept,
	int			wait_mp_rom_drv_disable)
{
	drv_intercom_t		*drv_communication = NULL;
	me90_mp_rom_drv_t	*mp_rom_drv_init_area = NULL;
	int			waiting_time = 0;
	int			task_accepted = 0;
	int			rom_disable = 0;
	int			workval = 0;
	int			task = 0;
	int			rval = 0;
	int			flag_MP = 0;
	hrtime_t		a, b;
	if (debug_mcap == 0) {
		printk("INST. %d. "
			"mcap_wait_make_task_drv_mp: Start working.\n",
			state->inst);
	};
	if (debug_mcap == 0) {
		printk("INST. %d. "
			"mcap_wait_make_task_drv_mp: mp_restart = %d; "
			"wait_mp_task_accept = %d; wait_mp_rom_drv_disable = %d.\n",
			state->inst,
			mp_restart, wait_mp_task_accept, wait_mp_rom_drv_disable);
	};
	drv_communication =
		(drv_intercom_t *) &state->MCAP_BMEM[MCAP_DRV_CMN_AREA_BMEM_ADDR];
	if (wait_mp_rom_drv_disable) {
		mp_rom_drv_init_area = (me90_mp_rom_drv_t *)
			&state->MCAP_BMEM[ME90_MP_ROM_DRV_INIT_ADDR];
	};
	if (mp_restart == 1) {
		if (drv_communication->mp_task == no_mp_task) {
			printk("INST. %d. "
				"mcap_wait_make_task_drv_mp: MP driver task field "
				"has been cleared.\n",
				state->inst);
		};
		rval = mcap_reset_general_regs(state, BOOT);
		if (rval != 0) {
			printk("INST. %d. "
				"mcap_wait_make_task_drv_mp: MP started "
				"with errors.\n",
				state->inst);
			return EACCES;
		} else if (debug_mcap == 0) {
			printk("INST. %d. "
				"mcap_wait_make_task_drv_mp: MP "
				"started.\n",
				state->inst);
		};
		if (debug_mcap == 0) {
			printk("INST. %d. "
				"mcap_wait_make_task_drv_mp: flag_MP = 0x%x.\n",
				state->inst,
				drv_communication->flag_mp);
			udelay(MCAP_TASK_ACCEPT_BY_MP_DELAY_TIME*30/**1000*/);
			printk("INST. %d. "
				"mcap_wait_make_task_drv_mp: flag_MP = 0x%x.\n",
				state->inst,
				drv_communication->flag_mp);
		};
	};
/* Цикл ожидания выполнения текущего задания драйвером МП */
	if (wait_mp_task_accept || wait_mp_rom_drv_disable) {
		waiting_time = 0;
		task_accepted = 0;
		rom_disable = 0;
		a = ddi_gethrtime();
		task = drv_communication->mp_task;
		b = ddi_gethrtime();
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"mcap_wait_make_task_drv_mp: Т чтения номера задания из "
				"БОЗУ: %lld нсек.\n",
				state->inst,
				b - a);
		};
		while (waiting_time < MCAP_TASK_ACCEPT_BY_MP_TIME) {
			workval = drv_communication->mp_task;
			if (workval == no_mp_task) {
				task_accepted = 1;
				break;
			} else if (wait_mp_rom_drv_disable != 0) {
				if (mp_rom_drv_init_area->rom_disable) {
					rom_disable = 1;
					break;
				};
			};
			waiting_time = waiting_time + MCAP_TASK_ACCEPT_BY_MP_DELAY_TIME;
			udelay(MCAP_TASK_ACCEPT_BY_MP_DELAY_TIME/**1000*/);
		};
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"mcap_wait_make_task_drv_mp: Т ожидания выполнения "
				"%d-го задания = %d мксек.\n",
				state->inst,
				task,
				waiting_time);
		};
		if (rom_disable) {
			return -EACCES;
		} else if (task_accepted == 0) {
			flag_MP = drv_communication->flag_mp;
			udelay(MCAP_TASK_ACCEPT_BY_MP_DELAY_TIME*30/**1000*/);
			if (flag_MP == drv_communication->flag_mp) {
				printk("экз. %d. "
					"mcap_wait_make_task_drv_mp: MP don't execute "
					"MP driver programm (0x%x == 0x%x).\n",
					state->inst, flag_MP, drv_communication->flag_mp);
			} else {
				printk("экз. %d. "
					"mcap_wait_make_task_drv_mp: MP driver didn't execute "
					"task %d for %d mksec.\n",
					state->inst,
					workval,
					waiting_time);
			};
			return -EACCES;
		};
	};
	if (debug_mcap == 0) {
		printk("INST. %d. "
			"mcap_wait_make_task_drv_mp: Finished.\n",
			state->inst);
	};
	return 0;
}

int mcap_reset_general_regs(
	mcap_state_t		*state,
	int			mp_state)
{
	drv_intercom_t 		*drv_communication = NULL;
	int           		errors_num = 0;
	char		   	buf[16];
	int			start_accepted = 0;
	int			flag_MP = 0;
	int			i=0;
	int			waiting_time = 0;
	reg_general_mcap_t	read_value;

	if (debug_mcap == 0) {
		if (mp_state == LOAD) {
			strcpy(buf, "LOADING");
		} else if (mp_state == HALT) {
			strcpy(buf, "STOP");
		} else {
			strcpy(buf, "START");
		};
		printk("INST. %d. "
			"mcap_reset_general_regs: MP engine start -> %s.\n",
			state->inst,
			buf);
	};
	drv_communication =
		(drv_intercom_t *) &state->MCAP_BMEM[MCAP_DRV_CMN_AREA_BMEM_ADDR];
	state->mp_state = undef_mp_state;
	if (mp_state != BOOT) { 
		mcap_read_general_regs(state, 0);
/* Общий сброс модуля */
		WRITE_MCAP_REGISTER(state, MCAP_TZM, 0);
		if (debug_mcap == 0) {
			printk("INST. %d. "
				"mcap_reset_general_regs: Whole module resetting.\n",
				state->inst);
		};
		mcap_read_general_regs(state, 0);	
	};
	
	if (mp_state == HALT)  {
		mp_init_area_t *mp_init_area =
			(mp_init_area_t *) &state->MCAP_BMEM[MC_MP_INIT_AREA_BMEM_ADDR];
		mp_init_area->ME90_MP_INIT_AREA_u_long[0] =
			mcap_rotate_word_bytes(ME90_MP_HALT_OPCODE);
	};

	if (mp_state == BOOT) 	{
/* Запуск микропроцессора */
		for (i = 0; i < 3; i++) { 
			errors_num = 0;
			WRITE_MCAP_REGISTER(state, MCAP_TSM, 0);
			if (debug_mcap == 0) {
				printk("INST. %d. "
					"mcap_reset_general_regs: starting MP.\n",
					state->inst);
			};
			mcap_read_general_regs(state, 0);	
			flag_MP = drv_communication->flag_mp;
			start_accepted = 0;			
			waiting_time = 0;
			while (waiting_time < MCAP_TASK_ACCEPT_BY_MP_TIME) {
				if (drv_communication->flag_mp != flag_MP) {
					start_accepted = 1;
					break;
				};
				read_value.rdwr_reg_general = READ_MCAP_REGISTER(state, MCAP_TBL);
				if (read_value.reg_ROSH != 0) {
					break;
				};
				waiting_time = waiting_time + MCAP_TASK_ACCEPT_BY_MP_DELAY_TIME;
				udelay(MCAP_TASK_ACCEPT_BY_MP_DELAY_TIME/**1000*/);
			};
			if (start_accepted == 0) {
				if (debug_mcap == 0) {
					printk("INST. %d. "
						"mcap_reset_general_regs: MP don't start serve "
						"driver programm "	
						"(fl. beg. 0x%x == fl. end. 0x%x).\n",
						state->inst, flag_MP, drv_communication->flag_mp);
				};
				if (debug_mcap == 0) {
					printk("INST. %d. "
						"mcap_reset_general_regs: After emergency "
						"starting MP.\n",
						state->inst);
					mcap_read_general_regs(state, 1);
				};
				errors_num = errors_num + 1;
/* Общий сброс модуля после аварийного запуска MП */
				WRITE_MCAP_REGISTER(state, MCAP_TZM, 0);
				if (debug_mcap == 0) {
					printk("INST. %d. "
						"mcap_reset_general_regs: After whole "
						"module resetting.\n",
						state->inst);
					mcap_read_general_regs(state, 1);
				};
			} else {
				if (debug_mcap == 0) {
					printk("INST. %d. "
						"mcap_reset_general_regs: waiting_time = %d mksec.\n",
						state->inst,
						waiting_time);
					printk("INST. %d. "
						"mcap_reset_general_regs: number of cycles i = %d.\n",
						state->inst,
						i);
				};
			}; /* if (start_accepted == 0) { */
			if (start_accepted != 0) break;
		}; /* for (i = 0; i < 3; i++) { */
	};
	if (mp_state == HALT) {
		state->mp_state = halted_mp_state;
	} else if (mp_state == LOAD) {
		state->mp_state = locked_mp_state;
	};
	if (errors_num > 0) {
		printk("INST. %d. "
			"mcap_reset_general_regs: finish with errors; " 
			"errors_num = %d.\n",
			state->inst,
			errors_num);
		printk("INST. %d. "
			"mcap_reset_general_regs: waiting_time = %d mksec.\n",
			state->inst,
			((MCAP_TASK_ACCEPT_BY_MP_TIME*i)) + waiting_time);
		printk("INST. %d. "
			"mcap_reset_general_regs: number of cycles i = %d.\n",
			state->inst, i);
	} else if (debug_mcap == 0) {
		printk("INST. %d. "
			"mcap_reset_general_regs: succesive finishing.\n",
			state->inst);
	};

	return errors_num;
}

void mcap_read_general_regs(
	mcap_state_t	*state,
	int		flaf_print)
{
	reg_general_mcap_t	read_value;
	read_value.rdwr_reg_general = READ_MCAP_REGISTER(state, MCAP_TBL);
	if (read_value.reg_ROSH != 0) {
	   printk("INST. %d. "
		   "mcap_read_general_regs: enternal device error.\n",
		   state->inst);
		flaf_print = 1;
	};
	if (flaf_print == 1) {
		printk("INST. %d. "
			"mcap_read_general_regs: ROB = 0x%x.\n",
			state->inst,
			read_value.rdwr_reg_general);
	};
}


int   mcap_calculate_work_hr_time(
	hrtime_t    start_time,             /* event start time */
	hrtime_t    end_time                /* event finish time */
	)
{
	return ((end_time - start_time) / 1000);
}

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
	 caddr_t		*kmem_area_p
					  )
{
	 caddr_t       kmem_area = NULL;
	 int           rval = 0;
	 int           kmem_size = 0;
	 int           word_rem = 0;

	if (write_op) {
		if (debug_mcap == 0) {
			printk("INST. %d. "
				"mcap_bmem_data_transfer: from E-90 memory 0x%08lx "
				"to MP memory 0x%08lx size 0x%lx bytes.\n",
				state->inst,
				(unsigned long)transfer_desk->mem_address,
				(unsigned long)transfer_desk->mp_bmem_address,
				(unsigned long)transfer_desk->byte_size);
		};
	} else {
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"mcap_bmem_data_transfer: из памяти МП 0x%08lx "
				"в Э-90 память 0x%08lx размером 0x%lx байтов.\n",
				state->inst,
				(unsigned long)transfer_desk->mp_bmem_address,
				(unsigned long)transfer_desk->mem_address,
				(unsigned long)transfer_desk->byte_size);
		};
	};
	if ((long) transfer_desk->mp_bmem_address < 0                         ||
		(long) transfer_desk->mp_bmem_address >= MC_BMEM_REG_SET_LEN      ||
		(long) transfer_desk->mp_bmem_address + transfer_desk->byte_size >
		MC_BMEM_REG_SET_LEN) {
		printk("экз. %d. "
			"mcap_bmem_data_transfer: wrong adress BMEM MP 0x%08lx and/or "
			"size 0x%lx.\n",
			state->inst,
			(unsigned long)transfer_desk->mp_bmem_address,
			(unsigned long)transfer_desk->byte_size);
		return -EINVAL;
	};
	word_rem = ((long) transfer_desk->mp_bmem_address & (sizeof(u_int)-1));
	kmem_size = transfer_desk->byte_size + word_rem;
	if (kmem_buf == NULL) {
		kmem_area = (caddr_t) kmalloc(kmem_size, GFP_KERNEL);
	} else {
		kmem_area = kmem_buf;
	};
	if (kmem_area == NULL) {
		printk("экз. %d. "
			"mcap_bmem_data_transfer: kmem_alloc - нет в наличии "
			"памяти.\n",
			state->inst);
		return -EINVAL;
	};
	if (write_op) {
		rval = ddi_copyin(transfer_desk->mem_address, &kmem_area[word_rem],
					   transfer_desk->byte_size/*, mode*/);
		if (rval != 0) {
			if (kmem_buf == NULL) {
				kfree(kmem_area);
			};
			printk("экз. %d. "
			   "mcap_bmem_data_transfer: ddi_copyin: отказ.\n",
			   state->inst);
			return (-EFAULT);
		};
	};
	if (write_op) {
		rval = mcap_write_base_memory(state, &kmem_area[word_rem], transfer_desk->mp_bmem_address,
								 transfer_desk->byte_size, char_data);
		if (rval != 0) {
			if (kmem_buf == NULL) {
				kfree(kmem_area);
			};
			printk("экз. %d. "
				"mcap_bmem_data_transfer: отказ при заказе основной памяти "
				"для чтения/записи.\n",
				state->inst);
			return rval;
		};
	};
	if (!write_op) {
		rval = ddi_copyout(&kmem_area[word_rem], transfer_desk->mem_address,
						transfer_desk->byte_size/*, mode*/);
		if (rval != 0) {
		   if (kmem_buf == NULL) {
			kfree(kmem_area);		
		   };
		   printk("экз. %d. "
			   "mcap_bmem_data_transfer: ddi_copyout - отказ.\n",
			   state->inst);
			return (-EFAULT);
		};
	};
	if (kmem_buf == NULL) {
		kfree(kmem_area);
	} else if (kmem_area_p != NULL) {
		*kmem_area_p = &kmem_area[word_rem];
	};
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_bmem_data_transfer: конец функционирования.\n",
			state->inst);
	};
	return 0;
}

int mcap_alloc_trans_bufs(
	mcap_state_t	*state,
	trbuf_desc_t	*new_trans_buf,
	int		buf_byte_size)
{
	int			rval = 0;

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_alloc_trans_bufs: начало функционирования с буфером "
			"размером %d (0x%x) байтов.\n",
			state->inst,
			buf_byte_size, buf_byte_size);
	};
#ifdef MCAP_OLD_VERSION
	if (buf_byte_size > MAX_SPARC_DRV_BUF_SIZE) {
		printk("экз. %d. "
			"mcap_alloc_trans_bufs: общий размер буфера ППД "
			"%d > %d (MAX_SPARC_DRV_BUF_SIZE).\n",
			state->inst,
			buf_byte_size,
			MAX_SPARC_DRV_BUF_SIZE);
		return (-EINVAL);
	};
#else
	if (buf_byte_size > MCAP_MAX_SIZE_BUFFER_DMA) {
		printk("экз. %d. "
			"mcap_alloc_trans_bufs: общий размер буфера ППД "
			"%d > %d (MCAP_MAX_SIZE_BUFFER_DMA).\n",
			state->inst,
			buf_byte_size,
			MCAP_MAX_SIZE_BUFFER_DMA);
		return (-EINVAL);
	};
#endif /* MCAP_OLD_VERSION */


	{

		rval = ddi_dma_mem_alloc(state->dip, buf_byte_size, 
					&new_trans_buf->dma.busa,
					&new_trans_buf->dma.real_size,
					&new_trans_buf->dma.mem);

		if (rval != DDI_SUCCESS) {
			printk("экз. %d. "
				"mcap_alloc_trans_bufs: ddi_dma_mem_alloc - %d (0x%x) памяти "
				"распределено неудачно.\n",
				state->inst,
				buf_byte_size,
				buf_byte_size);

			return -EINVAL;
		};
	
		new_trans_buf -> buf_address = (caddr_t)new_trans_buf->dma.mem;
		new_trans_buf -> buf_size = new_trans_buf->dma.real_size;
	}


	if (debug_mcap == 0) {
		printk("INST %d. "
			"mcap_alloc_trans_bufs: Finished для буфера 0x%08lx "
			"размером %d байтов.\n",
			state->inst,
			(unsigned long)new_trans_buf->buf_address,
			buf_byte_size);
	};
	return (0);
}

void mcap_free_trans_bufs(
	mcap_state_t	*state,
	trbuf_desc_t	*trans_buf_desc)
{

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_free_trans_bufs: начало функционирования для буфера "
			"0x%08lx.\n",
			state->inst,
			(unsigned long)trans_buf_desc);
	};



	ddi_dma_mem_free(state->dip, trans_buf_desc->dma.real_size, 
				trans_buf_desc->dma.busa, trans_buf_desc->dma.mem);

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_free_trans_bufs: конец функционирования.\n",
			state->inst);
	};
}


int	mcap_write_base_memory(
	mcap_state_t	*state,
	caddr_t		address_from,
	caddr_t		address_to,
	size_t		byte_size,
	int		char_data)
{
	 u_int        *kmem_area_from = NULL;
	 u_int        *bmem_area_to = NULL;
	 size_t        begin_rem = 0;
	 size_t        cur_byte_size = 0;
	 size_t        word_size = 0;
	 size_t        rem = 0;
	 int           cur_word = 0;

	if (debug_mcap == 0) {
		printk("INST. %d. "
			"mcap_write_base_memory: start working, to "
			"copy data from 0x%08lx "
			"to BMEM addr 0x%08lx size 0x%lx.\n",
			state->inst,
			(unsigned long)address_from, (unsigned long)address_to, (u_long)byte_size);
	};
	if ((long) address_to < 0                               ||
		(long) address_to >= MC_BMEM_REG_SET_LEN            ||
		(long) address_to + byte_size > MC_BMEM_REG_SET_LEN) {
		printk("INST. %d. "
			"mcap_write_base_memory: wrong address and/or size BMEM.\n",
			state->inst);
		return -EINVAL;
	};
	if (((long) address_from & (sizeof(u_int)-1)) !=
		((long) address_to   & (sizeof(u_int)-1))) {
		printk("INST. %d. "
			"mcap_write_base_memory: address_from and address_to "
			"have different alignment.\n",
			state->inst);
		return -EINVAL;
	};
	begin_rem = ((long) address_from & (sizeof(u_int)-1));
	if (debug_mcap == 0) {
		printk("INST. %d. "
			"mcap_write_base_memory: begin_rem = 0x%lx\n", state->inst, 
								(u_long)begin_rem);
	}
	kmem_area_from = (u_int *) ((long) address_from - begin_rem);
	bmem_area_to = (u_int *) & state->MCAP_BMEM[(long) address_to - begin_rem];
	if (debug_mcap == 0) {
		printk("INST. %d. "
			"mcap_write_base_memory: state->MCAP_BMEM = 0x%lx\n", state->inst, 
					(ulong_t)state->MCAP_BMEM);
		printk("INST. %d. "
			"mcap_write_base_memory: bmem_area_to = 0x%lx\n", state->inst, 
					(ulong_t)bmem_area_to);
	}
	cur_byte_size = byte_size;
	if (begin_rem != 0) {
		u_int   first_bmem_word = bmem_area_to[0];
		u_char * first_bmem_word_p = (u_char *) & first_bmem_word;
		u_char * first_kernel_word = (u_char *) & kmem_area_from[0];
		int      begin_size = sizeof(u_int) - begin_rem;
		int      cur_byte = 0;
		if (char_data) {
			first_bmem_word = mcap_rotate_word_bytes(first_bmem_word);
		};
		begin_size = (begin_size > cur_byte_size) ? cur_byte_size : begin_size;
		for (cur_byte = begin_rem; cur_byte < begin_rem + begin_size;
			 cur_byte ++) {
		   first_bmem_word_p[cur_byte] = first_kernel_word[cur_byte];
		};
		if (char_data) {
		   first_bmem_word = mcap_rotate_word_bytes(first_bmem_word);
		};
		bmem_area_to[0] = first_bmem_word;
		cur_byte_size -= begin_size;
		((long) kmem_area_from) ++;
		((long) bmem_area_to) ++;
	};
	word_size = cur_byte_size / sizeof(u_int);
	rem = byte_size % sizeof(u_int);
	if (debug_mcap == 0) {
		printk("INST. %d. "
			"mcap_write_base_memory: rem = 0x%lx\n", state->inst, (u_long)rem);
	}
	for (cur_word = 0; cur_word < word_size; cur_word ++) {
		if (char_data) {
		   bmem_area_to[cur_word] = mcap_rotate_word_bytes(kmem_area_from[cur_word]);
		} else {
		   bmem_area_to[cur_word] = kmem_area_from[cur_word];
		};
		if (debug_mcap == 0) {
			if (cur_word == 0) {
				printk("INST. %d. "
					"mcap_write_base_memory: bmem_area_to[%d] = "
					"0x%08x.\n",
					state->inst,
					cur_word, bmem_area_to[cur_word]);
			};
		};
	};
	if (rem != 0) {
		u_int   last_bmem_word = bmem_area_to[word_size];
		u_char * last_bmem_word_p = (u_char *) & last_bmem_word;
		u_char * last_kernel_word = (u_char *) & kmem_area_from[word_size];
		int      cur_byte = 0;
		if (char_data) {
		   last_bmem_word = mcap_rotate_word_bytes(last_bmem_word);
		};
		for (cur_byte = 0; cur_byte < rem; cur_byte ++) {
		   last_bmem_word_p[cur_byte] = last_kernel_word[cur_byte];
		};
		if (char_data) {
		   last_bmem_word = mcap_rotate_word_bytes(last_bmem_word);
		};
		bmem_area_to[word_size] = last_bmem_word;
	};

	if (debug_mcap == 0) {
		printk("INST. %d. "
			"mcap_write_base_memory: data coping from "
			"0x%08lx to BMEM 0x%08lx size 0x%lx succeded.\n",
			state->inst,
			(unsigned long)address_from,(unsigned long) address_to, (u_long)byte_size);
	};

	return 0;
}

u_int	mcap_rotate_word_bytes(u_int	source_word)
{
	 u_int     	new_word = 0;
	 u_char 	*new_word_p = (u_char *) &new_word;
	 u_char 	*source_word_p = (u_char *) &source_word;
	 int        	cur_byte = 0;

	 for (cur_byte = 0; cur_byte < sizeof(u_int); cur_byte ++)
	 {
		new_word_p[(sizeof(u_int)-1) - cur_byte] = source_word_p[cur_byte];
	 };
	 return new_word;
}

int mcap_map_registers(
	mcap_state_t	*state,
	e90_unit_t	type_unit)
{
	int			n_regs;
	int			attach_flags = 0;
	int			rval         = 0;

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_map_registers: начало функционирования.\n",
			state->inst);
	};
	state->MCAP_BMEM = NULL;
	rval = ddi_dev_nregs(state->dip, &n_regs);
	if ((rval != DDI_SUCCESS) || (n_regs != 2)) {
		printk("экз. %d. "
			"mcap_map_registers: ddi_dev_nregs завершена с ошибкой "
			"или число наборов регистров %d != 2.\n",
			state->inst,
			n_regs);
		goto  m_err;
	};

	rval = ddi_ioremap(state->dip);
	if (rval != DDI_SUCCESS){
		printk(KERN_ERR "INST %d. "
			"ddi_regs_map_setup: ddi_map_regs() "
			"завершена с ошибкой для набора регистров или "
			"адресного пространства БОЗУ.\n",
			state->inst); 
		goto m_err;
	}
/* Устанавка отображение для адресного пространства регистров */

	state->reg_array_size = state->dip->size[0];/*r_sz;*/

	(ulong_t)state->regs_base = state->dip->base_addr[0];
	if (debug_mcap == 0) {
		printk(KERN_INFO "INST %d. "
			"mcap_map_registers: базовый адрес регистров = 0x%lx; "
			"выделенная область = %ld (0x%lx) байтов.\n",
			state->inst,
			(ulong_t)state->regs_base, (u_long)state->dip->size[0], 
						   (u_long)state->dip->size[0]);
	}

	
/* Устанавка отображение для адресного пространства БОЗУ */
	
	(unsigned long)state->MCAP_BMEM = state->dip->base_addr[1];
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"mcap_map_registers: базовый адрес БОЗУ = 0x%lx; "
				"выделенная область = %ld (0x%lx) байтов.\n",
				state->inst,
				(unsigned long)state->MCAP_BMEM, (u_long)state->dip->size[1], 
								 (u_long)state->dip->size[1]);
		};
	attach_flags |= REGS_MAPPED;

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_map_registers: конец функционирования.\n",
			state->inst);
	};
	return  attach_flags;

m_err:
	attach_flags |= ERRORS_SIGN;
	return  attach_flags;
}

int   mcap_startup_mp(
	mcap_state_t		*state,
	int			cmd)
{
	caddr_t			mp_init_code_p = NULL;
	mp_drv_args_t		*mp_drv_init_info_p = NULL;
	sparc_drv_args_t	drv_load_results;
	me90_mp_rom_drv_t	*mp_rom_drv_init_area = NULL;
#ifdef MCAP_OLD_VERSION
	u_int			rom_drv_init_code[] =
						ME90_MP_ROM_DRV_INIT_CODE;
#else
	u_int			rom_drv_init_code[] =
						MCAP_MP_ROM_DRV_INIT_CODE;
#endif /* MCAP_OLD_VERSION */
	int			rval = 0;
#ifdef MCAP_OLD_VERSION
	drv_intercom_t		*drv_communication = NULL;
#endif /* MCAP_OLD_VERSION */
	if (debug_mcap == 0) {
		printk("inst. %d. "
			"mcap_startup_mp: started with cmd = 0x%x.\n",
			state->inst,
			cmd);
	};
	spin_mutex_enter(&state->lock);

#ifdef MCAP_OLD_VERSION
	drv_communication =
		(drv_intercom_t *) &state->MCAP_BMEM[MCAP_DRV_CMN_AREA_BMEM_ADDR];
	drv_communication->mp_task = no_mp_task;
#endif /* MCAP_OLD_VERSION */

	state->mp_init_code.mp_bmem_address = (caddr_t) MC_MP_INIT_AREA_BMEM_ADDR;
#ifdef MCAP_OLD_VERSION
	rval = mcap_reset_module(state, LOAD, cmd == ME90IO_STARTUP_MP_ROM_DRV);
#else
	rval = mcap_reset_module(state, LOAD, cmd == MCAPIO_STARTUP_MP_ROM_DRV);
#endif /* MCAP_OLD_VERSION */
	if (rval != 0) {
		printk("inst. %d. "
			"mcap_startup_mp: errors while modules resetting.\n",
			state->inst);
	} else if (debug_mcap == 0) {
		printk("inst. %d. "
			"mcap_startup_mp: The module has been resetted.\n",
			state->inst);
	};
#ifdef MCAP_OLD_VERSION
	if (cmd == ME90IO_STARTUP_MP_ROM_DRV) {
#else
	if (cmd == MCAPIO_STARTUP_MP_ROM_DRV) {
#endif /* MCAP_OLD_VERSION */
		rval = mcap_write_base_memory(state,
				(caddr_t)&rom_drv_init_code,
				state->mp_init_code.mp_bmem_address,
				sizeof(rom_drv_init_code), 1);
		if (rval != 0) {
			printk("inst. %d. "
				"mcap_startup_mp: error during writing loading driver code "
				"from ROM into BOZU.\n",
				state->inst);
		} else if (debug_mcap == 0) {
			printk("inst. %d. "
				"mcap_startup_mp: the writing of the loading driver code "
				"from ROM into BOZU succeded.\n",
				state->inst);
		};
	} else {
		if (state->mp_drv_loaded == 0) {
			spin_mutex_exit(&state->lock);
			printk("inst. %d. "
				"mcap_startup_mp: MP driver code is not loaded into the BOZU.\n",
				state->inst);
			return (-EINVAL);
		};
		rval = mcap_bmem_data_transfer(state,
				&state->mp_init_code, 1,1,
				state->mp_init_area_copy, &mp_init_code_p);
		if (rval != 0) {
			spin_mutex_exit(&state->lock);
			printk("inst. %d. "
				"mcap_startup_mp: fails when MP starts due to errors.\n",
				state->inst);
			return rval;
		};
	};
	state->mp_init_code.mem_address = mp_init_code_p;
#ifdef MCAP_OLD_VERSION
	if (cmd == ME90IO_STARTUP_MP_ROM_DRV) {
		state->mp_debug_drv_flag = 0;
	} else {
		state->mp_debug_drv_flag = 1;
	};
#endif /* MCAP_OLD_VERSION */
	mp_rom_drv_init_area = (me90_mp_rom_drv_t *)
		&state->MCAP_BMEM[ME90_MP_ROM_DRV_INIT_ADDR];
#ifdef MCAP_OLD_VERSION
	mp_rom_drv_init_area->debug_drv_start = (cmd != ME90IO_STARTUP_MP_ROM_DRV);
#else
	mp_rom_drv_init_area->debug_drv_start = (cmd != MCAPIO_STARTUP_MP_ROM_DRV);
#endif /* MCAP_OLD_VERSION */
	mp_rom_drv_init_area->rom_disable = 0;

	rval = mcap_start_task_drv_mp(state, init_driver_mp_task,
			mp_drv_init_info_p, &drv_load_results);

	if (rval != 0) {
#ifdef MCAP_OLD_VERSION
		if (cmd == ME90IO_STARTUP_MP_ROM_DRV) {
#else
		if (cmd == MCAPIO_STARTUP_MP_ROM_DRV) {
#endif /* MCAP_OLD_VERSION */
			state->mp_rom_drv_enable = 0;
		};
		spin_mutex_exit(&state->lock);
		printk("inst. %d. "
			"mcap_startup_mp: MP driver has been initialised with errors.\n",
			state->inst);
		return rval;
	};
	state->mp_drv_started = 1;
#ifdef MCAP_OLD_VERSION
	if (cmd == ME90IO_STARTUP_MP_ROM_DRV) {
#else
	if (cmd == MCAPIO_STARTUP_MP_ROM_DRV) {
#endif /* MCAP_OLD_VERSION */
		state->mp_rom_drv_enable = !mp_rom_drv_init_area->rom_disable;
	};
	spin_mutex_exit(&state->lock);

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_startup_mp: MP driver has been initialised succesively.\n",
			state->inst);
	};

	return 0;
}

int mcap_reset_module(
	mcap_state_t	*state,
	int		operation,
	int		clean_bmem)
{
	int     rval = 0;

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_reset_module: начало функционирования.\n",
			state->inst);
	};
	rval = mcap_reset_general_regs(state, operation);
	if (clean_bmem != 0) {
		mcap_clean_base_memory(state);
	};
	mcap_clean_drv_communication(state);
	if (rval != 0) {
		printk("экз. %d. "
			"mcap_reset_module: были ошибки при общем сбросе модуля.\n",
			state->inst);
		return -1;
	} else {
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"mcap_reset_module: общий сброс модуля выполнен успешно.\n",
				state->inst);
		};
		return 0;
	};
}

void mcap_clean_base_memory(mcap_state_t	*state)
{
	u_int		*base_memory = NULL;
	int		cur_word = 0;

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_clean_base_memory: начало функционирования.\n",
			state->inst);
	};
	base_memory = (u_int *) state->MCAP_BMEM;
	for (cur_word = 0; cur_word < (MC_BMEM_REG_SET_LEN +
					(sizeof(u_int)-1))/sizeof(u_int);
		 cur_word ++) {
		base_memory[cur_word] = ME90_MP_HALT_OPCODE;
	};
	state->mp_drv_loaded = 0;
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_clean_base_memory: конец функционирования.\n",
			state->inst);
	};
}

void mcap_clean_drv_communication(mcap_state_t	*state)
{
	drv_intercom_t		*drv_communication = NULL;
	int			cur_arg = 0;

	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_clean_drv_communication: начало функционирования.\n",
			state->inst);
	};
	drv_communication =
		(drv_intercom_t *) &state->MCAP_BMEM[MCAP_DRV_CMN_AREA_BMEM_ADDR];
	drv_communication->mp_task = no_mp_task;
	drv_communication->sparc_task = no_sparc_task;
	drv_communication->intr_task = no_intr_task;
	for (cur_arg = 0; cur_arg < sizeof(drv_communication->mp_args) /
				sizeof(*drv_communication->mp_args.args_area);
		cur_arg ++) {
		drv_communication->mp_args.args_area[cur_arg] = 0;
	};
	for (cur_arg = 0; cur_arg < sizeof(drv_communication->sparc_args) /
			sizeof(*drv_communication->sparc_args.args_area);
		 cur_arg ++) {
		drv_communication->sparc_args.args_area[cur_arg] = 0;
	};
	if (debug_mcap == 0) {
		printk("экз. %d. "
			"mcap_clean_drv_communication: конец функционирования.\n",
			state->inst);
	};
}
int
mcap_ioctl(struct inode *inode, struct file *file,
                 unsigned int cmd, unsigned long arg)
{
	 dev_info_t 		*dip;	
         mcap_state_t		*state;
     	 dev_t			dev;	
	 int           		instance = 0;
	 int           		channel;
	 int           		rval = 0;
	
	 dev = ddi_inode_dev(inode);
	 dip = ddi_inode_dip(inode);
     	 if (!dip || !dev) return (-ENXIO);
         instance = MCAP_INST(dev);
         channel = MCAP_CHAN(dev);

/*	 if (debug_mcap == 0) {
		 printk("экз. %d. "
			 "***** mcap_ioctl: начало функционирования с команды 0x%x. *****\n",
			 instance,
			 cmd);
	 };*/

	 state = dip->soft_state;
	 if (state == NULL) {
		printk("экз. %d. "
			"mcap_ioctl: незагружен экземпляр устройства.\n",
			instance);
		return (-ENXIO);
	 };
	state->inst = instance;

	switch (cmd) {
#ifdef MCAP_OLD_VERSION
	case ME90IO_LOAD_MP_DRV_CODE :
#else
	case MCAPIO_LOAD_MP_DRV_CODE :
#endif /* MCAP_OLD_VERSION */
	{
#ifdef MCAP_OLD_VERSION
		bmem_trans_desk_t	mp_driver_code;
#else
		mcap_bmem_trans_desk_t  mp_driver_code;
#endif /* MCAP_OLD_VERSION */
		if (debug_mcap == 0) {
			printk("INST. %d. "
				"mcap_ioctl: 1. MP driver code loading.\n",
				instance);
		};

#ifdef MCAP_OLD_VERSION
		rval = ddi_copyin((caddr_t) arg, 
				(caddr_t) &mp_driver_code, sizeof (bmem_trans_desk_t)/*, mode*/);
#else
		rval = ddi_copyin((caddr_t) arg, 
				(caddr_t) &mp_driver_code, sizeof (mcap_bmem_trans_desk_t)/*, mode*/);
#endif /* MCAP_OLD_VERSION */
		if (rval != 0) {
			printk("экз. %d. "
				"mcap_ioctl: ddi_copyin завершена с ошибкой "
				"при переписи дескриптора кода инициализации МП.\n",
				instance);
			return (-EFAULT);
		};

		spin_mutex_enter(&state->lock);			/* start MUTEX */
#ifdef MY_DRIVER_BIG_ENDIAN
		rval = mcap_bmem_data_transfer(state, &mp_driver_code, 1/*, mode*/, 1, NULL, NULL);
#else
		rval = mcap_bmem_data_transfer(state, &mp_driver_code, 1/*, mode*/, 0, NULL, NULL);
#endif /* MY_DRIVER_BIG_ENDIAN */
		if (rval != 0) {
			spin_mutex_exit(&state->lock);		/* end MUTEX */
			printk("экз. %d. "
				"mcap_ioctl: загрузка кода в БОЗУ не "
				"выполнена из-за ошибок.\n",
				instance);
			return (-EFAULT);
		};
		state->mp_drv_loaded = 1;
		spin_mutex_exit(&state->lock);			/* end MUTEX */
		return rval;
	};
#ifdef MCAP_OLD_VERSION
	case ME90IO_STARTUP_MP_DRV  :
#else
	case MCAPIO_STARTUP_MP_DRV  :
#endif /* MCAP_OLD_VERSION */
	{
		if (debug_mcap == 0) {
			printk("INST. %d. "
				"***** mcap_ioctl: START ME90IO_STARTUP_MP_DRV"
				" 2. MP driver initializing. ******\n",
				instance);
		};
#ifdef MCAP_OLD_VERSION
		if (arg != 0) {
#endif /* MCAP_OLD_VERSION */
			spin_mutex_enter(&state->lock);		/* start MUTEX */
#ifdef MCAP_OLD_VERSION
			rval = ddi_copyin((caddr_t) arg, (caddr_t) &state -> mp_init_code,
				sizeof (bmem_trans_desk_t)/*, mode*/);
#else
			rval = ddi_copyin((caddr_t) arg, (caddr_t) &state -> mp_init_code,
				sizeof (mcap_bmem_trans_desk_t)/*, mode*/);
#endif /* MCAP_OLD_VERSION */
			if (rval != 0) {
				spin_mutex_exit(&state->lock);	/* end MUTEX */
				printk("экз. %d. "
					"mcap_ioctl: ddi_copyin завершена с ошибкой при "
					"переписи дескриптора кода инициализации МП.\n",
					instance);
				return (-EFAULT);
			};

			spin_mutex_exit(&state->lock);		/* end MUTEX */
			if (state->mp_init_code.byte_size > ME90_MP_INIT_AREA_BMEM_SIZE) {
				printk("экз. %d. "
					"mcap_ioctl: слишком велик размер кода "
					"инициализации МП 0x%lx > 0x%x (максимально допустимого).\n",
					instance,
					(u_long)state->mp_init_code.byte_size,
					ME90_MP_INIT_AREA_BMEM_SIZE);
				return (-EINVAL);
			};
#ifdef MCAP_OLD_VERSION
		} else {
			if (debug_mcap == 0) {
				printk("экз. %d. "
					"mcap_ioctl: начало функционирования по "
					"загрузке драйвера МП из ПЗУ.\n",
					instance);
			};
		};
#endif /* MCAP_OLD_VERSION */
		rval = mcap_startup_mp(state, cmd);
		if (rval != 0) {
			printk("экз. %d. "
				"mcap_ioctl: МП-драйвер инициализирован с ошибками.\n",
				instance);
		} else if (debug_mcap == 0) {
			printk("экз. %d. "
				"***** mcap_ioctl: FINISH ME90IO_STARTUP_MP_DRV МП-драйвер инициализирован успешно. *****\n",
				instance);
		};
		return (rval);
	};
#ifdef MCAP_OLD_VERSION
	case ME90IO_STARTUP_MP_ROM_DRV :
#else
	case MCAPIO_STARTUP_MP_ROM_DRV :
#endif /* MCAPIO_STARTUP_MP_ROM_DRV */
	{
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"***** mcap_ioctl: START ME90IO_STARTUP_MP_ROM_DRV 3."
				" MP driver loading from PZU. *****\n",
				instance);
		};
#ifdef MCAP_OLD_VERSION
		if (arg != 0) {
			spin_mutex_enter(&state->lock);		/* start MUTEX */
			rval = ddi_copyin((caddr_t) arg, (caddr_t) &state -> mp_init_code,
				sizeof (bmem_trans_desk_t)/*, mode*/);
			if (rval != 0) {
				spin_mutex_exit(&state->lock);	/* end MUTEX */
				printk("экз. %d. "
					"mcap_ioctl: ddi_copyin завершена с ошибкой при "
					"переписи дескриптора кода инициализации МП.\n",
					instance);
				return (-EFAULT);
			};
				spin_mutex_exit(&state->lock);		/* end MUTEX */
			if (state->mp_init_code.byte_size > ME90_MP_INIT_AREA_BMEM_SIZE) {
				printk("экз. %d. "
					"mcap_ioctl: слишком велик размер кода "
					"инициализации МП 0x%lx > %x (максимально допустимого).\n",
					instance,
					state->mp_init_code.byte_size,
					ME90_MP_INIT_AREA_BMEM_SIZE);
				return (-EINVAL);
			};
		} else {
			if (debug_mcap == 0) {
				printk("экз. %d. "
					"mcap_ioctl: начало функционирования по "
					"загрузке драйвера МП из ПЗУ.\n",
					instance);
			};
		};
#endif /* MCAP_OLD_VERSION */
		rval = mcap_startup_mp(state, cmd);
		if (rval != 0) {
			printk("inst. %d. "
				"mcap_ioctl: MP driver has been initialised with errors.\n",
				instance);
		} else if (debug_mcap == 0) {
			printk("экз. %d. "
				"***** mcap_ioctl: FINISH ME90IO_STARTUP_MP_ROM_DRV"
				"МП-драйвер инициализирован успешно. *****\n",
				instance);
		};
		return (rval);
	};
#ifdef MCAP_OLD_VERSION 
	case ME90IO_RESET_MP :
#else
	case MCAPIO_RESET_MP :
#endif /* MCAP_OLD_VERSION */
	{
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"***** mcap_ioctl: START ME90IO_RESET_MP 4. Общий сброс модуля. *****\n",
				instance);
		};
		spin_mutex_enter(&state->lock);			/* start MUTEX */
		rval = mcap_reset_module(state, HALT, arg);
		spin_mutex_exit(&state->lock);			/* end MUTEX */
		if (rval != 0) {
			printk("экз. %d. "
				"mcap_ioctl: общий сброс модуля завершсн c ошибкой.\n",
				instance);
		} else if (debug_mcap == 0) {
			printk("экз. %d. "
				"***** mcap_ioctl: FINISH ME90IO_RESET_MP общий сброс модуля завершсн успешно. *****\n",
				instance);
		};
		return rval;
	};
#ifdef MCAP_OLD_VERSION
	case ME90IO_GET_DRIVER_INFO :
#else
	case MCAPIO_GET_DRIVER_INFO :
#endif /* MCAP_OLD_VERSION */
	{
		mcap_drv_info_t	driver_info;
		
/*		if (debug_mcap == 0) {
			printk("экз. %d. "
				"***** mcap_ioctl: START ME90IO_GET_DRIVER_INFO Получение информации.*****\n",
				instance);
		};*/
		driver_info.sbus_clock_freq = mcap_sbus_clock_freq;
		driver_info.sbus_nsec_cycle = mcap_sbus_nsec_cycle;
		driver_info.mp_clock_freq   = mcap_mp_clock_freq;
		driver_info.mp_nsec_cycle   = mcap_mp_nsec_cycle;
#ifdef MCAP_OLD_VERSION
		driver_info.device_type     = state->type_unit;
#endif /* MCAP_OLD_VERSION */
		driver_info.mp_rom_drv_enable = state->mp_rom_drv_enable;
		driver_info.cur_hr_time = ddi_gethrtime();
		rval = ddi_copyout((caddr_t) &driver_info, (caddr_t) arg, sizeof (mcap_drv_info_t));
		if (rval != 0) {
			printk("экз. %d. "
				"mcap_ioctl: ddi_copyout завершена с ошибкой.\n",
				instance);
			rval = -EFAULT;
		};
/*		dbgmcap("***** mcap_ioctl: FINISH ME90IO_GET_DRIVER_INFO *****\n");*/
		return rval;
	};
	case MCAPIO_READ_DEVICE_REG :
	{
		mcap_arg_reg_t		op_reg;

/*		dbgmcap("***** mcap_ioctl: START MCAPIO_READ_DEVICE_REG *****\n");*/

		rval = ddi_copyin((caddr_t)arg, (caddr_t)&op_reg, sizeof (mcap_arg_reg_t));
		if (rval != 0) {
			printk("экз. %d. "
				"mcap_ioctl: ddi_copyin завершена с ошибкой при "
				"переписи аргументов запроса на чтение регистра устройств.\n",
				instance);
			rval = -EFAULT;
			break;
		};
		op_reg.reg_value = READ_MCAP_REGISTER(state, op_reg.reg_addr);
/*		if (debug_mcap == 0) {
			printk("экз. %d. "
				 "mcap_ioctl (чтение): адрес = 0x%x, значение = 0x%x.\n",
				 instance,
				 op_reg.reg_addr, op_reg.reg_value);
		};*/
		rval = ddi_copyout((caddr_t)&op_reg, (caddr_t)arg, sizeof (mcap_arg_reg_t));
		if (rval != 0) {
			printk("экз. %d. "
				"mcap_ioctl: ddi_copyout завершена с ошибкой "
				"при переписи результата чтения регистра устройства.\n",
				instance);
			rval = -EFAULT;
		};

/*		dbgmcap("***** mcap_ioctl: FINISH MCAPIO_READ_DEVICE_REG *****\n");*/
		
		return rval;
	};
	case MCAPIO_WRITE_DEVICE_REG :
	{
		mcap_arg_reg_t		op_reg;
		
/*		if (debug_mcap == 0) {
				printk("экз. %d. "
				"***** mcap_ioctl: START MCAPIO_WRITE_DEVICE_REG *****\n",
				instance);
			};*/

		rval = ddi_copyin((caddr_t)arg, (caddr_t)&op_reg, sizeof (mcap_arg_reg_t));
		if (rval != 0) {
			printk("экз. %d. "
				"mcap_ioctl: ddi_copyin завершена с ошибкой "
				"при переписи запроса на запись в регистр устройства.\n",
				instance);
			rval = -EFAULT;
			break;
		};
/*		if (debug_mcap == 0) {
			printk("экз. %d. "
				 "mcap_ioctl (запись): адрес = 0x%x, значение = 0x%x.\n",
				 instance,
				 op_reg.reg_addr, op_reg.reg_value);
		};*/
		WRITE_MCAP_REGISTER(state, op_reg.reg_addr, op_reg.reg_value);

/*		if (debug_mcap == 0) {
			printk("экз. %d. "
			"***** mcap_ioctl: FINISH MCAPIO_WRITE_DEVICE_REG *****\n",
			instance);
			};*/		

		return rval;
	};
	case MCAPIO_INIT_BUFERS_EXCHANGE : /* init_trans */
	{
		mcap_chnl_state_t	*channel_state = NULL;
		mcap_init_iomap_t	init_iomap_state_spec;
		size_t			*real_buf_size_p = NULL;
		int			error_code = 0;
		int			*error_code_p = NULL;

		dbgmcap("inst. %d. "
			"***** mcap_ioctl: START MCAPIO_INIT_BUFERS_EXCHANGE инициализация буферов обмена "
											"данными. *****\n",
													instance);
		channel_state = state->channel_state;

 /* Копирование аргументов в структуру параметров инициализации буферов */
 /* обмена данными mcap_init_iomap_t (файл mcap_io.h) */
		rval = ddi_copyin((caddr_t) arg, (caddr_t) &init_iomap_state_spec,
									sizeof (mcap_init_iomap_t));

		if (rval != 0) {
			printk("экз. %d. "
				"mcap_ioctl: ddi_copyin завершена с ошибкой при переписи "
				"аргументов инициализации буферов обмена данными.\n",
				instance);
			return -EFAULT;
		};
		real_buf_size_p = init_iomap_state_spec.real_buf_size_p;
		error_code_p    = init_iomap_state_spec.error_code_p;

		dbgmcap("inst. %d. "
				"mcap_ioctl: mcap_init_trans_map_state .\n",
				instance);

		rval = mcap_init_trans_map_state(state, &init_iomap_state_spec,
				0, &error_code, 0);


		if (real_buf_size_p != NULL) {
			rval = ddi_copyout((caddr_t) &channel_state ->
				trans_buf_state.user_buf_size,
				(caddr_t) real_buf_size_p, sizeof (*real_buf_size_p));

			if (rval != 0) {
				printk("экз. %d. "
					"mcap_ioctl: ddi_copyout завершена с ошибкой при "
					"переписи информации о реальном размере буфера карты.\n",
					instance);
				return -EFAULT;
			};
		};
		if (error_code_p != NULL) {
			rval = ddi_copyout((caddr_t) &error_code,
					(caddr_t) error_code_p, sizeof (*error_code_p));
			if (rval != 0) {
				printk("экз. %d. "
					"mcap_ioctl: ddi_copyout завершена с ошибкой при переписи "
					"результатов инициализации буферов обмена данными.\n",
					instance);
				return -EFAULT;
			};
		};
		if (rval == 0) {
			spin_mutex_enter(&state->lock);		/* start MUTEX */
			if (channel_state -> trans_buf_state.valid_flag == 0) {
				printk("экз. %d. "
					"mcap_ioctl: отказ при установке общего буфера обмена "
					"данными.\n",
					instance);
				spin_mutex_exit(&state->lock);	/* end MUTEX */
				return -EINVAL;
			};
			spin_mutex_exit(&state->lock);		/* end MUTEX */
				dbgmcap("экз. %d. "
					"***** mcap_ioctl: FINISH MCAPIO_INIT_BUFERS_EXCHANGE инициализация буферов обмена "
					"данными. *****\n",
					instance);
		};
		return rval;
	};
	case MCAPIO_HALT_TRANSFER_MODES : /* init_trans, halt */
	{
		mcap_halt_trans_t	halt_trans_state;
		
		dbgmcap("init. %d. "
				"***** mcap_ioctl: START MCAPIO_HALT_TRANSFER_MODES останов канала %d. *****\n",
				instance,
				channel);

		rval = ddi_copyin((caddr_t) arg, (caddr_t) & halt_trans_state,
							sizeof (mcap_halt_trans_t));
		if (rval != 0) {
			printk("экз. %d. "
				"mcap_ioctl: ddi_copyin завершена с ошибкой при переписи "
				"аргументов останова канала %d.\n",
				instance,
				channel);
			return -EFAULT;
		};
#ifndef MCAP_OLD_VERSION
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"mcap_ioctl: признак останова %d.\n",
				instance,
				halt_trans_state.flag_close);
		};
#else
		if (debug_mcap == 0) {
			printk("экз. %d. "
				"mcap_ioctl: время ожидания %d.\n",
				instance,
				halt_trans_state.waiting_time);
		};
#endif /* MCAP_OLD_VERSION */
		rval = mcap_halt_trans_state(state, &halt_trans_state,
				0, 1, 0);

			dbgmcap("экз. %d. "
				"***** mcap_ioctl: FINISH MCAPIO_HALT_TRANSFER_MODES останов канала %d. *****\n",
				instance,
				channel);
		return rval;
	};
	case MCAPIO_GET_DEVICE_INFO : /* init_trans */
	{
		mcap_dev_info_t		device_info;
		
/*		dbgmcap("***** mcap_ioctl: START MCAPIO_GET_DEVICE_INFO получения информации об устройстве. *****\n");*/
		device_info.instance  = instance;
		device_info.channel   = channel;

		rval = ddi_copyout((caddr_t) &device_info, (caddr_t) arg,
								sizeof (mcap_dev_info_t));
		if (rval != 0) {
			printk("inst. %d. "
				"mcap_ioctl: ddi_copyout завершена с ошибкой при переписи "
				"информации об устройстве.\n",
				instance);
			return -EFAULT;
		};

/*		dbgmcap("***** mcap_ioctl: FINISH MCAPIO_GET_DEVICE_INFO выдача информации об устройстве. *****\n");*/
		return 0;
	};
	case MCAPIO_MESSAGE_NOTE :
		{
		delivery_note_message_t		delivery_note_message;

	
/*		dbgmcap("inst. %d. "
				"mcap_ioctl: начало выдачи предупреждающего сообщения.\n",
				instance);*/
	
		rval = ddi_copyin((caddr_t) arg, (caddr_t) &delivery_note_message,
							sizeof (delivery_note_message_t));
		if (rval != 0) {
			printk("inst. %d. "
				"mcap_ioctl: ddi_copyin завершена с ошибкой при переписи "
				"предупреждающего сообщения.\n",
				instance);
			return -EFAULT;
		};
		printk("экз. %d. "
			"mcap_ioctl: %s%s).\n",
			instance,
			delivery_note_message.code_msg,
			delivery_note_message.name_user);

/*		if (debug_mcap == 0) {
			printk("экз. %d. "
				"mcap_ioctl: завершена выдача предупреждающего сообщения.\n",
				instance);
		};*/
		return 0;
	};
  /* Ожидание прерывания от ячейки МСАП */
	case MCAPIO_INTR_TIME_WAIT :
	{
		mcap_intr_wait_t	intr_user; /* структура в файле mcap_io.h */

		int				rf = 0;
		int				i = 0;
		u_long				timeout = 0;

		dbgmcap(KERN_ALERT "***** mcap_ioctl: MCAPIO_INTR_TIME_WAIT *****\n");

		spin_mutex_enter(&state->lock);
		rval = ddi_copyin((caddr_t)arg, (caddr_t) &intr_user,
								sizeof (mcap_intr_wait_t));
		if (rval != 0) {
			printk("экз. %d. "
				"mcap_ioctl: ddi_copyin завершена с ошибкой при переписи "
				"аргументов ожидания прерывания.",
				instance);
			 spin_mutex_exit(&state->lock);
			return -EINVAL;
		};

		if (state->io_flags_intr == 0) {
			drv_getparm(LBOLT, &timeout); /* t тек. в тиках */
			timeout = timeout + drv_usectohz(intr_user.intr_wait_time);
			rf = cv_spin_timedwait(&state->intr_cv, &state->lock, timeout);
			if (rf == -1) {
				rval = -ETIME;
			}
		}else {	
			if (debug_mcap == 0) {
					printk(KERN_ERR "INST %d. "
						"mcap_ioctl: Прерывание выполнено ранее cv_timedwait \n",
					instance);
				}
		}

		if (rf >= 0) {
			if (debug_mcap == 0) {
				printk("экз. %d. "
					"mcap_ioctl: Выдано прерывание ПрП.\n",
					instance);
			};
			intr_user.event_intr = state->io_flags_intr;
			intr_user.time_get_intr_device = state->time_get_intr_dev;
			for (i = 0; i < MCAP_SUBDEV_BUF_NUM; i++) {
				intr_user.event_intr_trans[i] = state->event_intr_trans_ch[i];
				intr_user.event_intr_reciv[i] = state->event_intr_reciv_ch[i];
			};
#ifndef MCAP_OLD_VERSION
			intr_user.num_intr_rosh = state->number_intr_rosh;
#endif /* MCAP_OLD_VERSION */
			rval = ddi_copyout((caddr_t)&intr_user, (caddr_t)arg,
									sizeof (mcap_intr_wait_t));
			if (rval != 0) {
				printk("экз. %d. "
					"mcap_ioctl: ddi_copyout: завершена с ошибкой при "
					"переписи информации о прерывании от ячейки МСАП.\n",
					instance);
				spin_mutex_exit(&state->lock);
				return -EINVAL;
			};
			state->io_flags_intr = 0;
			for (i = 0; i < MCAP_SUBDEV_BUF_NUM; i++) {
				state->event_intr_trans_ch[i] = 0;
				state->event_intr_reciv_ch[i] = 0;
			};
#ifndef MCAP_OLD_VERSION
			state->number_intr_rosh = 0;
#endif /* MCAP_OLD_VERSION */			
		};
		spin_mutex_exit(&state->lock);
		return rval;
	};
#ifndef MCAP_OLD_VERSION
/* Получение информации о прерываниях по РОШ */
        case MCAPIO_NUM_INTR_ROSH :
        {
                mcap_intr_rosh_t        intr_rosh;
                
                if (debug_mcap == 0) {
                        printk("экз. %d. "
                                "mcap_ioctl: начало получения информации о "
                                "прерываниях по РОШ.\n",
                                instance);
                };
                intr_rosh.num_intr_rosh = state->number_intr_rosh;
                
                rval = ddi_copyout((caddr_t) &intr_rosh, (caddr_t) arg,
                                                                sizeof (mcap_intr_rosh_t)/*, mode*/);
                if (rval != 0) {
                        printk("экз. %d. "
                                "mcap_ioctl: ddi_copyout завершена с ошибкой при переписи "
                                "информации о прерываниях по РОШ.\n",
                                instance);
                        return -EFAULT;
                };
                state->number_intr_rosh = 0;
                if (debug_mcap == 0) {
                        printk("экз. %d. "
                                "mcap_ioctl: завершена выдача информации о "
                                "прерываниях по РОШ.\n",
                                instance);
                };
                return 0;
        };
#endif /* MCAP_OLD_VERSION */	
	default :
	   printk("экз. %d. "
		   "mcap_ioctl: неверная команда 0x%x для ioctl().\n",
		   instance,
			cmd);
	   return (-ENOTTY);
	 };
	return (-ENOTTY);
}


module_init(mcap_init);
module_exit(mcap_exit);
MODULE_LICENSE("Copyright by MCST 2005");
MODULE_DESCRIPTION("MCAP driver");
