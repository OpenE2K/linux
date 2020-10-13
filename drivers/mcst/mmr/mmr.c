/*
 *
 * Ported in Linux by Alexey V. Sitnikov, alexmipt@mcst.ru, MCST, 2004
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
#include "mmr.h"

#include <linux/mcst/linux_mmr_io.h>

/*TODO: move p2s_info_t definition somewhere else */
#include <../drivers/pci2sbus/internal.h>

#include <linux/mcst/mcst_selftest.h>

#ifdef	__e2k__
#if IS_ENABLED(CONFIG_PCI2SBUS)
#include <linux/mcst/p2ssbus.h>
#include <linux/of_platform.h>
#endif
#elif defined(__sparc__)
#include <linux/of_platform.h>
#include <asm/sbus.h>
#endif

static int mmr_instances;
static int mmr_major;

static struct class *mmr_class = NULL;

#define	mod_name	"mmr"
#define MMR_NAME	"MCST,mmr"

// /proc/sys/debug/mmr_debug trigger
int mmr_debug = 0;
int mmr_debug_more = 0;

#define DBGMMR_MODE
#undef DBGMMR_MODE

#define DBGMMRDETAIL_MODE
#undef DBGMMRDETAIL_MODE

#if defined(DBGMMR_MODE)
#define dbgmmr			printk
#define debug_mmr		printk
#else
#define dbgmmr			if ( mmr_debug ) printk
#define debug_mmr		if ( mmr_debug ) printk
#endif

#if defined(DBGMMRDETAIL_MODE)
#define dbgmmrdetail		printk
#else
#define dbgmmrdetail		if ( mmr_debug_more ) printk
#endif

#define CHP		printk(KERN_ERR "%s:%s():%d\n", __FILE__, __func__, __LINE__);
#undef CHP

#define MAX_MMR_INSTANCES	16
static mmr_state_t	*mmr_states[MAX_MMR_INSTANCES];

/*
 * file_operations of mmr
 */
static struct file_operations mmr_fops = {
	owner:	 THIS_MODULE,
	unlocked_ioctl:	 mmr_ioctl,
	open:	 mmr_open,
  	mmap:	 mmr_mmap,
  	release: mmr_close,
};

/* Присоединение и отсоединение драйвера */
int	mmr_run_doattach		= 0;
int	mmr_run_dodetach		= 0;

int	mmr_sbus_clock_freq = 0;
int	mmr_sbus_nsec_cycle = 0;
int	mmr_mp_clock_freq   = 0;
int	mmr_mp_nsec_cycle   = 0;

#if defined(CONFIG_SYSCTL)
#include <linux/sysctl.h>

static ctl_table mmr_table[] = {
	{
		.procname	= "mmr_debug",
		.data		= &mmr_debug, 
		.maxlen		= sizeof(mmr_debug),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "mmr_debug_more",
		.data		= &mmr_debug_more, 
		.maxlen		= sizeof(mmr_debug_more),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static ctl_table mmr_root_table[] = {
	{
		.procname	= "debug",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= mmr_table,
	},
	{ }
};

static struct ctl_table_header *mmr_sysctl_header;

static void __init mmr_sysctl_register(void)
{
	mmr_sysctl_header = register_sysctl_table(mmr_root_table);
}

static void mmr_sysctl_unregister(void)
{
	if ( mmr_sysctl_header )
		unregister_sysctl_table(mmr_sysctl_header);
}

#else /* CONFIG_SYSCTL */

static void __init mmr_sysctl_register(void)
{
}

static void mmr_sysctl_unregister(void)
{
}
#endif

int mmr_mmap(struct file *file, struct vm_area_struct *vma)
{
	mmr_state_t	*state = (mmr_state_t *)file->private_data;
	dev_t	dev = state->dev;
	int	instance = MMR_INST(dev);
//	int	channel = MMR_CHAN(dev);

	u_int	rval = 0;
	mmr_chnl_state_t	*channel_state = NULL;
	caddr_t			mapped_reg_set_p = NULL;
//	int				dma_buffers_map = 0;
	unsigned long	vm_end = vma->vm_end;
	unsigned long	vm_start = vma->vm_start;

	unsigned long off = (long )(vma->vm_pgoff << PAGE_SHIFT);

	if ( state == NULL ) {
		printk(KERN_ERR "INST %d. "
			"%s(): неверный или незагруженный номер экземпляра "
			"устройства.\n",
			instance, __func__);
		return -ENXIO;
	}

	channel_state = state->channel_state;
	debug_mmr(KERN_ALERT "INST %d. %s(): Started c off 0x%lx .\n",
			instance,  __func__, off);

	if ( off < MMR_MAX_SIZE_BUFFER_DMA ) {

//		printk(KERN_ALERT "\nINST %d. %s(): Started c off %#lx ( DMA ). Size = %#lx\n", instance, __func__, off, vm_end - vm_start);

		if ( !channel_state->trans_buf_state.valid_flag ) {
			printk(KERN_ERR "INST %d. "
				"%s(): общий буфер не создан еще.\n",
				instance, __func__);
			return (-ENXIO);
		}

		if ( channel_state->trans_buf_state.user_buf_address == NULL ) {
			printk(KERN_ERR "INST %d. "
				"%s(): общий буфер не инициализрован еще.\n ",
				instance, __func__);
			return (-ENXIO);
		}

		mapped_reg_set_p = channel_state->trans_buf_state.user_buf_address;
//		dma_buffers_map = 1;
		debug_mmr(KERN_ALERT "INST %d. %s(): common buffer. addr = %#lx, size = %#lx\n", instance, __func__, (ulong_t)mapped_reg_set_p, (vm_end - vm_start));

		vma->vm_flags |= (VM_IO | VM_LOCKED | VM_READ | VM_WRITE );
		rval = ddi_remap_page(mapped_reg_set_p, vm_end - vm_start 
			/*channel_state->trans_buf_state.user_buf_size*/, vma);
	} else if ( off >= MMR_BMEM_REG_SET_OFFSET &&
		off < MMR_BMEM_REG_SET_OFFSET + MMR_BMEM_REG_SET_LEN ) {

//		printk(KERN_ALERT "\nINST %d. %s(): Started c off %#lx. Size = %#lx\n", instance,  __func__, off, vm_end - vm_start);

		unsigned long addr_phys;
		u32 size;
		
		addr_phys = state->op->resource[1].start;
//		addr_phys &= PAGE_MASK;

		/* This is an IO map - tell maydump to skip this VMA */
		vma->vm_flags |= VM_LOCKED | VM_READ | VM_WRITE;
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

		size = MMR_BMEM_REG_SET_LEN - (off - MMR_BMEM_REG_SET_OFFSET);
		if ( (vma->vm_end - vma->vm_start) < size )
			size = vma->vm_end - vma->vm_start;

#ifdef __e2k__
	if ( vma->vm_flags & VM_IO )
		vma->vm_page_prot = __pgprot(pgprot_val(vma->vm_page_prot) | _PAGE_CD_DIS | _PAGE_PWT );
#endif

		if ( io_remap_pfn_range(vma, vma->vm_start, MK_IOSPACE_PFN(0xe, (addr_phys >> PAGE_SHIFT)), size, vma->vm_page_prot) ) {
			return -EAGAIN;
		}
	} else {
		printk(KERN_ERR "INST %d. "
			"%s(): неверное смещение 0x%lx набора регистров.\n",
			instance, __func__, off);
		return -1;
	}

	debug_mmr(KERN_ALERT "INST %d. %s(): Finished with off 0x%lx .\n",
			instance, __func__, off);

	return rval;
}

int mmr_open(struct inode *inode, struct file *file)
{
	dev_t	dev = inode->i_rdev;
	int		instance = MMR_INST(dev);
	int		channel = MMR_CHAN(dev);
	mmr_state_t	*state = mmr_states[instance];

	int		firstopen = 0;

	debug_mmr(KERN_ALERT "INST %d. %s(): Started.\n",
			instance, __func__);

	if ( state == NULL ) {
		printk(KERN_ERR "INST %d. "
			"%s(): открытие незагруженного экземпляра устройства.\n",
			instance, __func__);
		return -ENXIO;
	}

	/* Проверить открытый флажок */
	spin_mutex_enter(&state->lock);
	firstopen = ( state->opened == 0 );

	if ( !firstopen ) {
		printk(KERN_ERR "INST %d. "
			"%s(): попытка монопольного открытия уже открытого "
			"устройства.\n",
			instance, __func__);
		spin_mutex_exit(&state->lock);
		return -EBUSY;
	}

	/* Отметить канал, открытый в карте */
	state->open_channel_map |= CHNL_NUM_TO_MASK(channel);
	state->open_flags = 0;
	state->opened = 1;
	state->inst = instance;
	state->number_intr_rosh	= 0; /* кол-во прерываний по РОШ */
	state->io_flags_intr	= 0; /* признак прерывания ПрП */
	state->flags_intr_rerr	= 0;
	state->num_reciv_comm	= 0;
	state->cur_num_comm		= 0;
	state->mmr_reg_cntrl_dev.wr_mmr_reg_cntrl = 0; /* регистр управления ММР */

	state->dev = dev;
	file->private_data = (void *)state;

	spin_mutex_exit(&state->lock);

	debug_mmr(KERN_ALERT "INST %d. %s(): Finished succesfully.\n", instance, __func__);

	return  0;
}

void	mmr_init_trans_buf_desc(
	trbuf_desc_t	*trans_buf_desc)
{
	trans_buf_desc->buf_address = 0;
	trans_buf_desc->buf_size    = 0;
}

void	mmr_free_trans_bufs(
	mmr_state_t		*state,
	trbuf_desc_t	*trans_buf_desc)
{
	debug_mmr(KERN_ALERT "INST %d. %s(): Started для буфера "
			"0x%08lx.\n",
			state->inst, __func__, 
			(unsigned long)trans_buf_desc);

	dma_free_coherent(&state->op->dev, trans_buf_desc->dma.size,
                                  trans_buf_desc->dma.mem, trans_buf_desc->dma.busa);

	debug_mmr(KERN_ALERT "INST %d. %s(): Finished.\n",
			state->inst, __func__);
}

void	mmr_init_trans_buf_state(
	trbuf_state_t	*trans_buf_state)
{
	int	cur_buf     = 0;
	int	max_buf_num = 0;

	debug_mmr(KERN_ALERT "mmr_init_trans_buf_state: Started.\n");
	trans_buf_state->valid_flag       = 0;
	trans_buf_state->user_buf_address = 0;
	trans_buf_state->user_buf_size    = 0;
	trans_buf_state->max_user_buf_num = 0;
	max_buf_num = sizeof(trans_buf_state->user_trans_bufs) /
			sizeof(*trans_buf_state->user_trans_bufs);
	for (cur_buf = 0; cur_buf < max_buf_num; cur_buf ++) {
		trans_buf_state->user_trans_bufs[cur_buf] = 0;
		trans_buf_state->dma_trans_bufs[cur_buf] = 0;
	}
	mmr_init_trans_buf_desc(&trans_buf_state->trans_buf_desc);
	debug_mmr(KERN_ALERT "mmr_init_trans_buf_state: успешное завершение.\n");
}

void	mmr_delete_drv_trans_buf(
	mmr_state_t		*state)
{
	mmr_chnl_state_t	*channel_state = NULL;
	trbuf_state_t		*trans_buf_state = NULL;

	debug_mmr(KERN_ALERT "INST %d. mmr_delete_drv_trans_buf: Started.\n",
			state->inst);
	channel_state = state->channel_state;
	trans_buf_state = &channel_state->trans_buf_state;
	if (!trans_buf_state->valid_flag)
		return;
	mmr_free_trans_bufs(state, &trans_buf_state->trans_buf_desc);
	mmr_init_trans_buf_state(trans_buf_state);
	debug_mmr(KERN_ALERT "INST %d. mmr_delete_drv_trans_buf: успешное завершение.\n",
			state->inst);
}

int mmr_halt_transfers(
	mmr_state_t 	*state,
	int		waiting_time,
	int		delete_rem_trans,
	int		mutex_locked,
	int		drv_comm_area_locked)
{
	mmr_chnl_state_t 	*channel_state = NULL;

	debug_mmr(KERN_ALERT "INST %d. mmr_halt_transfers: Started.\n",
			state->inst);
	channel_state = state->channel_state;
	if (!mutex_locked)
		spin_mutex_enter(&state->lock);
	if (channel_state->all_trans_finish) {
		if (channel_state->trans_buf_state.valid_flag) {
			mmr_delete_drv_trans_buf(state);
		}
		if (!mutex_locked)
			spin_mutex_exit(&state->lock);
		printk(KERN_ERR "INST %d. "
			"mmr_halt_transfers: все передачи уже закончены.\n",
			state->inst);
		return (0);
	}
	if (channel_state->trans_state_is_halt == 0) {
		printk(KERN_ERR "INST %d. "
			"mmr_halt_transfers: режим обменов все еще не завершен "
			"для устройства.\n",
			state->inst);
	}
	debug_mmr(KERN_ALERT "INST %d. mmr_halt_transfers: waiting_time = %d.\n",
			state->inst, waiting_time);
	channel_state->all_trans_finish = 1;
	cv_broadcast(&state->trans_state_cv);
	if (channel_state->trans_buf_state.valid_flag)
		mmr_delete_drv_trans_buf(state);
	if (!mutex_locked)
		spin_mutex_exit(&state->lock);

	debug_mmr(KERN_ALERT "INST %d. mmr_halt_transfers: Finished.\n",
			state->inst);
	return (0);
}

int mmr_halt_trans_state(
	mmr_state_t 		*state,
	mmr_halt_trans_t	*halt_trans_state,
	int			drv_comm_area_locked,
	int			user_request,
	int			mutex_locked)
{
	mmr_chnl_state_t 	*channel_state = NULL;
	int			waiting_time = 0;
	int			rval = 0;
	int			rval_1 = 0; /* 24.07.20000 */

	debug_mmr(KERN_ALERT "INST %d. mmr_halt_trans_state: Started.\n", state->inst);
	channel_state = state->channel_state;
	if (!mutex_locked)
		spin_mutex_enter(&state->lock);

	debug_mmr(KERN_ALERT "INST %d. mmr_halt_trans_state: user_request = %d; "
			"channel_state->trans_state_is_halt = %d.\n",
			state->inst, user_request,
			channel_state->trans_state_is_halt);
	debug_mmr(KERN_ALERT "INST %d. mmr_halt_trans_state: ma =%lx, pa =%lx.\n",
			state->inst,
			(unsigned long)&channel_state->trans_state_is_init,
			virt_to_phys((u_long)(&channel_state->trans_state_is_init)));
	if (channel_state->trans_state_is_init == 0) {
		if (!mutex_locked)
			spin_mutex_exit(&state->lock);
		if (user_request && !channel_state->trans_state_is_halt) {
			printk(KERN_ERR "INST %d. "
				"mmr_halt_trans_state: останов не инициализированного "
				"устройства.\n",
				state->inst);
			return 0;
		} else {
			printk(KERN_ERR "INST %d. "
				"mmr_halt_trans_state: останов не инициализированного "
				"или остановленного уже устройства.\n",
				state->inst);
			return 0;
		}
	}
	waiting_time = halt_trans_state->waiting_time;

	if (channel_state->trans_state_is_halt == 0) {
		channel_state->trans_state_is_halt = 1;
		channel_state->all_trans_finish = 0;
	}

	if (!mutex_locked)
		spin_mutex_exit(&state->lock);

	rval = mmr_halt_transfers(state, waiting_time, 0, mutex_locked, drv_comm_area_locked);
	if (rval != 0) {
		printk(KERN_ERR "INST %d. "
			"mmr_halt_trans_state: не может остановить канал.\n",
			state->inst);
	}
	if (channel_state->all_trans_finish == 0) {
		printk(KERN_ERR "INST %d. "
			"mmr_halt_trans_state: состояние передачи устройства будет "
			"прервано.\n",
			state->inst);
		rval_1 = mmr_halt_transfers(state, 0, 1, mutex_locked, drv_comm_area_locked);
		if (rval_1 != 0) {
			printk(KERN_ERR "INST %d. "
				"mmr_halt_trans_state: не может прервать состояние "
				"передачи устройства.\n",
				state->inst);
		}
	}
	if (rval != 0) {
		printk(KERN_ERR "INST %d. "
			"mmr_halt_trans_state: передача была остановлена "
			"c ошибкой.\n",
			state->inst);
	}
	if (!mutex_locked)
		spin_mutex_enter(&state->lock);
	if (channel_state->all_trans_finish) {
		channel_state->trans_state_is_init = 0;
		if (user_request) {
			channel_state->trans_state_is_halt    = 0;
			channel_state->all_trans_finish       = 0;
			channel_state->init_as_trans_map      = 0;
			channel_state->full_data_buf_size     = 0;
			channel_state->subdev_buf_trans_size  = 0;
			channel_state->subdev_buf_reciv_size  = 0;
		}
		cv_broadcast(&state->trans_state_cv);
	}
	if (!mutex_locked)
		spin_mutex_exit(&state->lock);

	debug_mmr(KERN_ALERT "INST %d. mmr_halt_trans_state: Finished.\n",
			state->inst);
	return rval;
}

int mmr_close(struct inode *inode, struct file *file)
{
	int			instance = 0;
	mmr_state_t	*state = (mmr_state_t *)file->private_data;
	dev_t		dev;
	int			channel;
	mmr_chnl_state_t	*channel_state = NULL;
	u_long		cur_clock_ticks = 0;
	u_long		timeout_clock_ticks = 0;
	int			rval = 0;

	debug_mmr(KERN_ALERT "INST %d. %s(): Started.\n", instance, __func__);

	if ( state == NULL ) {
		printk(KERN_ERR "INST %d. "
			"%s(): закрытие незагруженного экземпляра устройства.\n",
			instance, __func__);
		return -ENXIO;
	}

	dev = state->dev;
	instance = MMR_INST(dev);
	channel = MMR_CHAN(dev);

	channel_state = state->channel_state;

	spin_mutex_enter(&state->lock);

	/* Ожидание освобождения устройства */
	if ( channel_state->trans_state_is_init || channel_state->state_init_in_progress ) {
		mmr_halt_trans_t	halt_trans_state;
		printk(KERN_ERR "INST %d. "
			"%s(): работа с устройством не была остановлена.\n",
			instance, __func__);
		halt_trans_state.waiting_time = 0;
		rval = mmr_halt_trans_state(state, &halt_trans_state, 0, 0, 1);
		if (rval != 0) {
			printk(KERN_ERR "INST %d. "
				"%s(): не удалось остановить работу с устройством.\n",
				instance, __func__);
		}
	}

	if ( channel_state->trans_buf_state.valid_flag ) {
		mmr_delete_drv_trans_buf(state);
	}

	channel_state->trans_state_is_init = 0;
	channel_state->state_init_in_progress = 0;
	channel_state->trans_state_is_halt = 0;
	channel_state->all_trans_finish = 0;
	channel_state->init_as_trans_map = 0;
	channel_state->full_data_buf_size = 0;
	channel_state->subdev_buf_trans_size = 0;
	channel_state->subdev_buf_reciv_size = 0;

	/* Отметить канал, закрытый в карте */
	channel_state->trans_num = 0;
	state->open_channel_map &= ~CHNL_NUM_TO_MASK(channel);

	/* Если последний канал закрылся, то драйвер закрыт */
	if ( state->open_channel_map == 0 ) {
		state->open_flags = 0;
		state->opened = 0;
	}

	if ( state->opened == 0 ) {
		/* Освобождение область связи междрайвера */
		while ( state->drv_comm_busy ) {
			drv_getparm(LBOLT, &cur_clock_ticks);
			timeout_clock_ticks = cur_clock_ticks +
				drv_usectohz(MMR_DRV_COMM_FREE_TIMEOUT_DEF_VALUE);
			rval = cv_spin_timedwait(&state->drv_comm_cv, &state->lock,
					timeout_clock_ticks);
			if ( rval < 0 ) {
				printk(KERN_ERR "INST %d. "
					"%s(): не удалось дождаться освобождения области "
					"междрайверного взаимодействия.\n",
					instance, __func__);
				state->drv_comm_busy = 0;
				cv_broadcast(&state->drv_comm_cv);
				break;
			}
		}
	}

	/* Сброс модуля  */
	WRITE_MMR_REGISTER(state, MMR_TZM, 0);
	spin_mutex_exit(&state->lock);

	debug_mmr(KERN_ALERT "INST %d. %s(): успешное завершение.\n", instance, __func__);

	return  0;
}

void mmr_init_drv_state(mmr_state_t	*state)
{
	mmr_chnl_state_t	*channel_state = NULL;

	debug_mmr(KERN_ALERT "INST %d. %s(): Started.\n", state->inst, __func__);
	channel_state = state->channel_state;
	channel_state->trans_state_is_init    = 0;
	channel_state->state_init_in_progress = 0;
	channel_state->trans_state_is_halt    = 0;
	channel_state->all_trans_finish       = 0;
	channel_state->init_as_trans_map      = 0;
	channel_state->full_data_buf_size     = 0;
	channel_state->subdev_buf_trans_size  = 0;
	channel_state->subdev_buf_reciv_size  = 0;
	channel_state->init_iomap_state_spec.buf_num = MMR_BUF_USER_NUM;
	channel_state->init_iomap_state_spec.max_data_buf_trans_size = MMR_MAX_LONGS_DATA_BUF_TRANS*4;
	channel_state->init_iomap_state_spec.max_data_buf_reciv_size = MMR_MAX_DATA_BUF_SIZE;
	channel_state->init_iomap_state_spec.real_buf_size_p = NULL;
	channel_state->init_iomap_state_spec.error_code_p = NULL;
	mmr_init_trans_buf_state(&channel_state->trans_buf_state);

	debug_mmr(KERN_ALERT "INST %d. %s(): успешное завершение\n",
		state->inst, __func__);
}

int
mmr_map_registers(mmr_state_t *state, e90_unit_t type_unit)
{
	struct of_device *op = state->op;
	int		attach_flags = 0;

	debug_mmr(KERN_ALERT "INST %d. %s(): Started.\n",
			state->inst, __func__);

	state->MMR_BMEM = NULL;
#if 0	//TODO:
{
	int		rval = 0;
	int		n_regs;

	rval = ddi_dev_nregs(state->dip, &n_regs);
	if ((rval != DDI_SUCCESS) || (n_regs != 2)) {
		printk(KERN_ERR "INST %d. "
			"mmr_map_registers: ddi_dev_nregs завершена с ошибкой "
			"или число наборов регистров %d != 2.\n",
			state->inst, n_regs);
		goto  m_err;
	}
}
#endif

	state->regs_base = of_ioremap(&op->resource[0], 0,
					op->resource[0].end - op->resource[0].start + 1,
					MMR_NAME);

	if ( state->regs_base == NULL ) {
		printk(KERN_ERR "INST %d. of_ioremap() завершена с ошибкой для набора регистров \n", state->inst);
		goto m_err;
	}

	/// Устанавка отображение для адресного пространства регистров
	debug_mmr(KERN_ALERT "INST %d. %s(): базовый адрес регистров = 0x%lx; "
			"выделенная область = %d (%#x) байт\n",
			state->inst, __func__, 
			(ulong_t)state->regs_base, op->resource[0].end - op->resource[0].start + 1, op->resource[0].end - op->resource[0].start + 1);
	
	/// Устанавка отображение для адресного пространства БОЗУ
	state->MMR_BMEM = of_ioremap(&op->resource[1], 0,
					op->resource[1].end - op->resource[1].start + 1,
					MMR_NAME);

	if ( state->MMR_BMEM == NULL ) {
		printk(KERN_ERR "INST %d. of_ioremap() завершена с ошибкой для адресного пространства БОЗУ\n", state->inst);
		goto err_mmap1;
	}

	debug_mmr(KERN_ALERT "INST %d. %s(): базовый адрес БОЗУ = 0x%lx; "
			"выделенная область = %d (%#x) байт\n",
			state->inst, __func__, 
			(unsigned long)state->MMR_BMEM, op->resource[1].end - op->resource[1].start + 1, op->resource[1].end - op->resource[1].start + 1);

	attach_flags |= REGS_MAPPED;

	debug_mmr(KERN_ALERT "INST %d. %s(): Finished\n",
			state->inst, __func__);
	
	return attach_flags;

err_mmap1:
	of_iounmap(&op->resource[0], state->regs_base, op->resource[0].end - op->resource[0].start + 1);
m_err:
	attach_flags |= ERRORS_SIGN;

	return attach_flags;
}

void	mmr_read_general_regs(
	mmr_state_t		*state,
	int				flaf_print)
{
	mmr_reg_general_t	read_value;

	read_value.rdwr_reg_general = READ_MMR_REGISTER(state, MMR_TBLPPP);
	if (read_value.reg_RERR != 0) {
	   printk(KERN_ERR "INST %d. "
		   "mmr_read_general_regs: внутренняя ошибка устройства. РОШ = %d.",
			state->inst,
			read_value.reg_RERR);
		flaf_print = 1;
	}
	if ((read_value.rdwr_reg_general != base_reg) 
			&& (read_value.rdwr_reg_general != base_reg_v5)

			) {
	   printk(KERN_ERR "INST %d. "
		   "mmr_read_general_regs: Не произведен сброс регистров адаптера.",
		   state->inst);
		flaf_print = 1;
	}
/* Печать регистров адаптера */
	if (flaf_print == 1) {
		printk(KERN_INFO "INST %d. "
			"mmr_read_general_regs: РОБ = 0x%x.\n",
			state->inst,
			read_value.rdwr_reg_general);
	}
}

int mmr_reset_general_regs(
	mmr_state_t		*state)
{

	mmr_read_general_regs(state, 0);
/* Общий сброс модуля */
	WRITE_MMR_REGISTER(state, MMR_TZM, 0);
	debug_mmr(KERN_ALERT "INST %d. mmr_reset_general_regs: общий сброс модуля.\n",
			state->inst);
	mmr_read_general_regs(state, 0);
	debug_mmr(KERN_ALERT "INST %d. mmr_reset_general_regs: успешное завершение.\n",
			state->inst);

	return 0;
}

int mmr_attach_add(mmr_state_t *state, int *add_attach_flags)
{
	int	attach_flags = 0;

	cv_init(&state->trans_state_cv);
	attach_flags |= TRANS_STATE_CV_ADDED;
	*add_attach_flags = attach_flags;

	return  0;
}

void mmr_detach_add(
	mmr_state_t		*state,
	int			add_attach_flags,
	int			uncondit_detach)
{
	if ((add_attach_flags & TRANS_STATE_CV_ADDED) || uncondit_detach) {
		cv_destroy(&state->trans_state_cv);
	};
}

void Unmap_reg_sets(mmr_state_t	*state)
{
	struct of_device *op = state->op;
	int       i_reg_gr = 0;
	
//	caddr_t * reg_set_p = NULL;

	debug_mmr(KERN_ALERT "%s(): started\n", __func__);

	of_iounmap(&op->resource[0], state->regs_base, op->resource[0].end - op->resource[0].start + 1);

	of_iounmap(&op->resource[1], state->MMR_BMEM, op->resource[1].end - op->resource[1].start + 1);

	if ( state->MMR_BMEM != NULL ) {
//		reg_set_p = (caddr_t *) &(state->MMR_BMEM);
		debug_mmr(KERN_ALERT "INST %d. %s(): устанавлен неотображаемый BMEM %d\n",
				state->inst, __func__, i_reg_gr);

		state->MMR_BMEM = NULL;
		i_reg_gr ++;
	}

	debug_mmr(KERN_ALERT "INST %d. %s(): законченный и удаленный %d набор "
			"регистров\n", state->inst, __func__, i_reg_gr);
}

int rmv_dev(mmr_state_t	*state, int channel)
{
	int	inst  = state->inst;
	int	minor;

	minor = MMR_MINOR(inst, channel);
	device_destroy(mmr_class, MKDEV(state->major, minor));

	return 0;
}

static irqreturn_t
mmr_intr_handler(int irq, void *arg)
{
	mmr_state_t *		state = (mmr_state_t *)arg;
	mmr_reg_general_t	read_value;
	mmr_reg_common_t	mmr_reg_common;

	raw_spin_lock(&state->lock);

	dbgmmr(KERN_ALERT "***** mmr_intr_handler STARTED *****\n");

	read_value.rdwr_reg_general = READ_MMR_REGISTER(state, MMR_TBLPPP);

	if ( read_value.trg_TPPP != 0 ) {  /* получено прерывание ПрП */
		state->intr_dev = read_value.rdwr_reg_general;
		mmr_reg_common.wr_mmr_reg_common = read_value.rdwr_reg_general;
		/* Время получения прерывания от адаптера */
		state->time_get_intr_dev = ddi_gethrtime();
		state->io_flags_intr += 1; /* признак наличия прерывания */
		if ( read_value.reg_RERR != 0 ) {  /* получено прерывание по РОШ */
			/* Сброс РОШ */
			WRITE_MMR_REGISTER(state, MMR_RERR, 0);
			state->flags_intr_rerr = 2; /* признак наличия прерывания по РОШ */
			state->number_intr_rosh =  
			state->number_intr_rosh + 1; /* кол-во прерываний по РОШ */
		}
		WRITE_MMR_REGISTER(state, MMR_TPPP, 0);
		if ( state->flag_board == MODE_TERMINAL ||
			state->flag_board == MODE_MONITOR ) {
			/* Кол-во записанных команд в буфер команд монитора по информации адаптера */
			state->num_reciv_comm = mmr_reg_common.pointer_block_comm + 1;
			if ( mmr_reg_common.pointer_block_comm >= MMR_MAX_NUM_BUF_COMM )
				printk("!!! mmr_intr inst %d p_bl_comm %d\n", state->inst, mmr_reg_common.pointer_block_comm);
			/* Количество записанных команд в буфер команд монитора */
			state->cur_num_comm = state->cur_num_comm + 1;
		} else {	/* MODE_CONTROLLER */
			/* Получено прерывание от адаптера контроллера */
			state->cur_num_comm = 1;
		}

		cv_broadcast (&state->intr_cv);  /* создание условий */
		raw_spin_unlock(&state->lock);

		return  IRQ_HANDLED;
	} else { /* нет прерывания */
		raw_spin_unlock(&state->lock);
		return IRQ_NONE;
	}
}

static int
mmr_probe(struct of_device *op, const struct of_device_id *match)
{
	mmr_state_t		*state = NULL;
	mmr_chnl_state_t	*channel_state = NULL;
	int		instance = mmr_instances++;
	int		attach_flags = 0;
	int		add_attach_flags = 0;
	int		map_flags    = 0;
	int		need_intr_num = 0;
	int		intr_num      = 0;
	int		intr_sbus_levels[2];
	int		cur_intr = 0;
//	int		intr_levels_size = 0;
	int		channel = 0;
	int		minor   = 0;
	int 	rval = 0;	
	int		irq_flags = 0;
	char		nod[128];

	mmr_major = register_chrdev(0, MMR_NAME, &mmr_fops);
	if ( mmr_major < 0 ) {
		return mmr_major;
	}

	dbgmmr(KERN_ERR "INST %d. %s(): Started. MAJOR = %d\n", instance, __func__, mmr_major);

	/*
	 * Get the soft state for this instance
	 */
	state = ddi_malloc(sizeof(mmr_state_t));
	if ( state == NULL )
		return -ENOMEM;

	memset(state, 0, sizeof(mmr_state_t));

	attach_flags |= SOFT_STATE_ALLOCATED;

	/// Инициализция программного обеспечения для этого экземпляра
	state->op					= op;
	state->irq					= op->irqs[0];
	state->major				= mmr_major;
	state->inst					= instance;
	state->opened				= 0;
	state->open_flags			= 0;
	state->open_channel_map		= 0;
	state->drv_comm_busy		= 0;
//	state->intr_number			= 0;
	state->intr_seted			= 0;
	state->type_unit			= UNDEF_UT;
	state->dev_type 			= DDI_SBUS_SPARC;

	channel_state = state->channel_state;
	channel_state->trans_num = 0;

	mmr_init_drv_state(state);

	state->type_unit  = MMR_UT;

	mmr_states[instance] = state;
	dev_set_drvdata(&op->dev, state);

	// SBUS clock-frequency
	mmr_sbus_clock_freq = state->op->clock_freq;

	if (mmr_sbus_clock_freq < 10 * 1000000 ||
		mmr_sbus_clock_freq > 25 * 1000000) {
		printk(KERN_ERR "INST %d. "
			"%s(): Illegal frequency SBus %d.\n",
			instance, __func__, mmr_sbus_clock_freq / 1000000);
		goto  m_err;
	}
	mmr_sbus_nsec_cycle = 1000 * 1000000 / mmr_sbus_clock_freq; /* nsec */

	/// Карта регистров, Map in operating registers
	map_flags     = mmr_map_registers(state, state->type_unit);
	attach_flags |= map_flags;

	if ( (map_flags & ERRORS_SIGN) || (!(map_flags & REGS_MAPPED)) ) {
		printk(KERN_ERR "INST %d. "
			"%s(): mmr_map_registers Wrongly finished."
			"\n\t Cannot loading Regs fields to the virtual memory.\n",
			instance, __func__);
		goto  m_err;
	}

	rval = mmr_reset_general_regs(state);
	if (rval != 0) {
		printk(KERN_ERR "INST %d. "
			"%s(): Device Resetting fails.\n",
			instance, __func__);
	}

	intr_num = op->num_irqs;

	need_intr_num = 1;	// только передача прерывания

	if ( intr_num != need_intr_num ) {
		printk(KERN_ERR "INST %d. "
			"%s(): The device has more then %d levels "
			"of External interrupts %d.\n",
			instance, __func__, need_intr_num, intr_num);
		goto  m_err;
	}

	// Инициализировать mutex для этого экземпляра
	spin_mutex_init(&state->lock);
	
	attach_flags |= MUTEX_ADDED;

	cv_init(&state->channel_cv);
	cv_init(&state->drv_comm_cv);
	cv_init(&state->intr_cv);
	attach_flags |= CHANNEL_CV_ADDED;

	for (cur_intr = 0; cur_intr < intr_num; cur_intr ++) {
		intr_sbus_levels[cur_intr] = 0;
	}

//	intr_levels_size = sizeof(intr_sbus_levels);

	for ( cur_intr = 0; cur_intr < intr_num; cur_intr ++ ) {
		if ( cur_intr == 0 ) {
#ifdef CONFIG_MCST_RT
			irq_flags |=  IRQF_DISABLED;
#endif
			irq_flags |= IRQF_SHARED | IRQF_ONESHOT;
#ifdef CONFIG_E90
			if ( (rval = request_threaded_irq(state->irq, &mmr_intr_handler, NULL, irq_flags, MMR_NAME, (void *)state)) ) {
				printk(KERN_ERR "INST %d. "
					"%s(): request_threaded_irq() %d "
					 "level %d failed\n",
					 instance, __func__,
					 cur_intr,
					 intr_sbus_levels[cur_intr]);
#else
			rval = sbus_request_irq(state->irq, &mmr_intr_handler,
				NULL, irq_flags, MMR_NAME, (void *)state);
			if (rval) {
				printk(KERN_ERR "INST %d. "
					"%s(): sbus_request_irq() %d "
					 "level %d failed\n",
					 instance, __func__,
					 cur_intr,
					 intr_sbus_levels[cur_intr]);
#endif
				goto  m_err;
			} else {
				attach_flags |= INTERRUPT_ADDED;
				state->intr_seted++;
				debug_mmr(KERN_ALERT "INST %d. %s(): interrupt %d, "
						"level %d of handler.\n",
						instance, __func__,
						cur_intr,
						intr_sbus_levels[cur_intr]);
			}
#ifdef CONFIG_MCST_RT
			mk_hndl_first(state->irq, MMR_NAME);
#endif
		} else {
			printk(KERN_ERR "INST %d. "
				"%s(): Bad interrupt %d level %d.\n",
				instance, __func__,
				cur_intr,
				intr_sbus_levels[cur_intr]);
			goto  m_err;
		}
	}

	// Инициализировать ресурсы ПРЯМОГО ДОСТУПА В ПАМЯТЬ
	state->system_burst = 0x20;

	// Specific for module types driver additional Attachments
	if ( mmr_attach_add(state, &add_attach_flags) != 0 )
		goto m_err;

	// Создание малых узлов; один на канал
	minor = MMR_MINOR(instance, channel);

	if (mmr_class == NULL) {
		mmr_class = class_create(THIS_MODULE, "mmr");

		if (IS_ERR(mmr_class)) {
			pr_err("Error creating class: /sys/class/mmr.\n");
		}
	}

	if (!IS_ERR(mmr_class)) {
		sprintf(nod, "%s_%d_:%d", mod_name, instance, channel);
		pr_info("make node /sys/class/mmr/%s\n", nod);
		if (device_create(mmr_class, NULL, MKDEV(mmr_major, minor),
					NULL, nod) == NULL)
			pr_err("create a node %d failed\n", minor);
		else {
			debug_mmr(KERN_ALERT "INST %d. %s(): "
						"Minor created succesfully.\n",
							instance, __func__);
		}
	}

	debug_mmr(KERN_ALERT "INST %d. %s(): Driver attached.\n\n", instance, __func__);

	return  DDI_SUCCESS;

m_err:
	if ( (attach_flags & INTERRUPT_ADDED) ) {
		printk(KERN_ERR "m_err, INTERRUPT_ADDED\n");
		if ( state->intr_seted > 0 )	{
			free_irq(state->irq, state);
			state->intr_seted = 0;
		}
	}

	if ( add_attach_flags != 0 ) {
		printk(KERN_ERR "m_err, add_attach_flags != 0\n");
		mmr_detach_add(state, add_attach_flags, 1);
	}
	if ( attach_flags & CHANNEL_CV_ADDED ) {
		printk(KERN_ERR "m_err, CHANNEL_CV_ADDED\n");
		cv_destroy(&state->channel_cv);
		cv_destroy(&state->drv_comm_cv);
		cv_destroy(&state->intr_cv);
	}

	if ( attach_flags & MUTEX_ADDED ) {
		printk(KERN_ERR "m_err, MUTEX_ADDED\n");
//		mutex_destroy(&state->mutex);
	}

	if ( attach_flags & REGS_MAPPED ) {
		printk(KERN_ERR "m_err, REGS_MAPPED\n");
		Unmap_reg_sets(state);
	}

	kfree(state);
	unregister_chrdev(mmr_major, MMR_NAME);

	printk(KERN_ERR "INST %d. "
		"%s(): Driver loading Failed.\n",
		instance, __func__);

	return DDI_FAILURE;
}

int mmr_remove(struct of_device *op)
{
	int instance;
	mmr_state_t	*xsp = (mmr_state_t	*)dev_get_drvdata(&op->dev);
	int error = DDI_SUCCESS;

	if ( xsp == NULL ) {
		printk(KERN_ERR "%s(): Driver soft state cannot be obtained.\n", __func__);
		return DDI_FAILURE;
	}

	instance = xsp->inst;

	debug_mmr(KERN_ALERT "INST %d. %s(): Started.\n", instance, __func__);

	if ( xsp->opened ) {
		printk(KERN_ERR "INST %d. "
			"%s(): The device is opened. Removing is not permitted.\n",
			instance, __func__);
		return DDI_FAILURE;
	}

	if ( xsp->intr_seted > 0 )
		xsp->intr_seted = 0;

	cv_destroy(&xsp->channel_cv);
	cv_destroy(&xsp->drv_comm_cv);
	cv_destroy(&xsp->intr_cv);
//	mutex_destroy(&xsp->mutex);

	mmr_detach_add(xsp, 0, 1);

	error = (int)rmv_dev(xsp, 0);

	of_iounmap(&op->resource[0], xsp->regs_base, op->resource[0].end - op->resource[0].start + 1);

	of_iounmap(&op->resource[1], xsp->MMR_BMEM, op->resource[1].end - op->resource[1].start + 1);

	if (!instance) {
		class_destroy(mmr_class);
		mmr_class = NULL;
	}

	free_irq(xsp->irq, xsp);

	unregister_chrdev(xsp->major, MMR_NAME);

	kfree(xsp);

	dev_set_drvdata(&op->dev, NULL);

	debug_mmr(KERN_ALERT "INST %d. %s(): Driver detached.\n\n", instance, __func__);

	return error;
}

static const struct of_device_id mmr_match[] = {
	{
#if IS_ENABLED(CONFIG_PCI2SBUS) || defined(CONFIG_E90_FASTBOOT)
		.name = "mmr",
#else
		.name = MMR_NAME,
#endif
	},
	{},
};

MODULE_DEVICE_TABLE(of, mmr_match);

static struct of_platform_driver mmr_driver = {
	.name           = MMR_NAME,
	.match_table    = mmr_match,
	.probe          = mmr_probe,
	.remove         = mmr_remove,
};

static int
__init mmr_init(void)
{
	int 		ret;
	
	mmr_instances = 0;

	mmr_sysctl_register();

	dbgmmr(KERN_ALERT "********* MMR_INIT: START for %s *********\n\n", MMR_NAME);

	ret = of_register_driver(&mmr_driver, &of_platform_bus_type);

	dbgmmr(KERN_ALERT "********* MMR_INIT: FINISH. Found %d MMR instances. *********\n", mmr_instances);

	return ret;
}

static void  
__exit mmr_exit(void)
{
	dbgmmr(KERN_ALERT "********* MMR_EXIT: START **********\n\n");

	of_unregister_driver(&mmr_driver);

	mmr_sysctl_unregister();

	dbgmmr(KERN_ALERT "********* MMR_EXIT: FINISH *********\n");
}

int mmr_get_channel_to_init(
	mmr_state_t		*state,
	int				waiting_time,
	int				drv_comm_area_locked,
	int				user_request,
	int				state_recover)
{
/* Структура внутреннего состояния устройства - mmr.h */
	mmr_chnl_state_t	*channel_state = NULL;
/* Структура параметров останова обменов и закрытия устройства - mmr_io.h */
	mmr_halt_trans_t	halt_trans_state;
	int					rval = 0;

	debug_mmr(KERN_ALERT "INST %d. mmr_get_channel_to_init: Started.\n", state->inst);
	channel_state = state->channel_state;
	if (!state_recover)
			spin_mutex_enter(&state->lock);
	while (channel_state->state_init_in_progress) {
		rval = cv_spin_wait(&state->trans_state_cv, &state->lock);
//		if (rval <= 0) {
		if (rval < 0) {
			if (!state_recover)
					spin_mutex_exit(&state->lock);
			printk(KERN_ERR "INST %d. "
				"mmr_get_channel_to_init: ожидание завершения прерывания "
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

 /* Закрытие устройства через заданный временной интервал */
		halt_trans_state.waiting_time = waiting_time;
		rval = mmr_halt_trans_state(state, &halt_trans_state,
				drv_comm_area_locked, 0, state_recover);
		if (rval != 0) {
			printk(KERN_ERR "INST %d. "
				"mmr_get_channel_to_init: не может закрыть устройсто.\n",
				state->inst);
		};
		if (!state_recover)
				spin_mutex_enter(&state->lock);
		if (channel_state->trans_state_is_init) {
			channel_state->state_init_in_progress = 0;
			cv_broadcast(&state->trans_state_cv);
			if (!state_recover)
					spin_mutex_exit(&state->lock);
			printk(KERN_ERR "INST %d. "
				"mmr_get_channel_to_init: не может завершить все "
				"передачи.\n",
				state->inst);
			return -EBUSY;
		};
	};
	if (channel_state->trans_buf_state.valid_flag && !state_recover)
		mmr_delete_drv_trans_buf(state);

/* Обнуление элементов структуры внутреннего состояния устройства -
   mmr_chnl_state_t (mmr.h) */
	channel_state->trans_state_is_init    = 0;
	channel_state->trans_state_is_halt    = 0;
	channel_state->all_trans_finish       = 0;
	channel_state->init_as_trans_map      = 0;
	channel_state->full_data_buf_size     = 0;
	channel_state->subdev_buf_trans_size  = 0;
	channel_state->subdev_buf_reciv_size  = 0;
	if ( !state_recover )
		spin_mutex_exit(&state->lock);

	debug_mmr(KERN_ALERT "INST %d. mmr_get_channel_to_init: успешное завершение.\n",
			state->inst);
	return (0);
}

int mmr_alloc_trans_bufs(
	mmr_state_t		*state,
	trbuf_desc_t	*new_trans_buf,
	int		buf_byte_size)
{
	debug_mmr(KERN_ALERT "INST %d. %s(): Started с буфером "
			"размером %d (0x%x) байтов.\n",
			state->inst, __func__, 
			buf_byte_size, buf_byte_size);

	if ( buf_byte_size > MMR_MAX_SIZE_BUFFER_DMA ) {
		printk(KERN_ERR "INST %d. "
			"%s(): общий размер буфера ППД "
			"%d > %d (MAX_SPARC_DRV_BUF_SIZE).\n",
			state->inst, __func__, 
			buf_byte_size,
			MAX_SPARC_DRV_BUF_SIZE);
		return -EINVAL;
	}

	buf_byte_size  = PAGE_SIZE << get_order(buf_byte_size);

	new_trans_buf->dma.mem = dma_alloc_coherent(&state->op->dev,
										buf_byte_size,
										&new_trans_buf->dma.busa, GFP_ATOMIC);

	if ( new_trans_buf->dma.mem == NULL ) {
		printk(KERN_ERR "INST %d. "
			"%s(): ddi_dma_mem_alloc - %d (0x%x) памяти "
			"распределено неудачно.\n",
			state->inst, __func__, 
			buf_byte_size,
			buf_byte_size);
		return -EINVAL;
	}

	new_trans_buf->buf_address = (caddr_t)new_trans_buf->dma.mem;
	new_trans_buf->dma.size = buf_byte_size;
	new_trans_buf->buf_size = buf_byte_size;

	debug_mmr(KERN_ALERT "INST %d. %s(): Finished для буфера 0x%08lx "
			"размером %d байтов.\n",
			state->inst, __func__, 
			(unsigned long)new_trans_buf->buf_address, buf_byte_size);

	return 0;
}

void mmr_init_subdev_buf(
	mmr_state_t	*state,
	mmr_iosubdbuf_t	*subdev_buf,
	int		io_flags,
	size_t		max_data_buf_size,
	int		subdev_buf_num)
{
	mmr_iosubd_desc_t	*subdev_buf_desc  = &subdev_buf->buf_desc;
	caddr_t			*data_buf = (caddr_t *)&subdev_buf->data_buf;
	size_t			all_data_buf_size = 0;
	int			cur_word = 0;
	int			i;

	debug_mmr(KERN_ALERT "INST %d. mmr_init_subdev_buf: Started с буфером %d.\n",
			state->inst, subdev_buf_num);

	subdev_buf_desc->cur_num_subarray  = 0;
	subdev_buf_desc->next_num_subarray = 0;

	for ( i = 0; i < 8; i++ ) {
		subdev_buf_desc->amount_words[i] = 0;
	}

	subdev_buf_desc->unused1 	  	= 0;
	subdev_buf_desc->cur_addr_subarray_del	= 0;
	subdev_buf_desc->next_addr_subarray_del	= 0;
	subdev_buf_desc->buf_num 	  	= subdev_buf_num;
	subdev_buf_desc->io_flags 	  	= io_flags;
	subdev_buf_desc->data_size 	  	= 0;
	subdev_buf_desc->unused5 	  	= 0;
	subdev_buf_desc->unused_word6 		= 0;
	subdev_buf_desc->unused_word7 		= 0;

	all_data_buf_size = max_data_buf_size / sizeof(caddr_t);
	for ( cur_word = 0; cur_word < all_data_buf_size; cur_word ++ ) {
		data_buf[cur_word] = (caddr_t)&data_buf[cur_word];
	}

	debug_mmr(KERN_ALERT "INST %d. "
			"mmr_init_subdev_buf: успешное завершение c буфером %d.\n",
			state->inst, subdev_buf_num);

	return;
}

void mmr_init_iomap_buf(
	mmr_state_t		*state,			 /* собственная информация драйвера */
	mmr_iosubdbuf_t		*iomap_buf_desc, 	 /* дескриптор буфера обмена */
	size_t			subdev_buf_trans_size,   /* максимальный размер буфера передачи */
	size_t			subdev_buf_reciv_size,   /* максимальный размер буфера приема */
	int			iomap_buf_num)	 	 /* номер буфера карты */
{
	caddr_t			iomap_buf        = (caddr_t)iomap_buf_desc;
	mmr_iosubdbuf_t	*cur_subdev_desc = NULL;

	debug_mmr(KERN_ALERT "INST %d. mmr_init_iomap_buf: Started для буфера "
			"0x%08lx, размер буфера %ld байтов.\n",
			state->inst,
			(unsigned long)iomap_buf_desc, (ulong_t)subdev_buf_trans_size);
	cur_subdev_desc = (mmr_iosubdbuf_t *) &iomap_buf[0];
 /* Инициализация дескриптора и области данных буфера */
	mmr_init_subdev_buf(state, cur_subdev_desc, MMR_IO_WRITE,
					subdev_buf_trans_size - sizeof(mmr_iosubd_desc_t),
					iomap_buf_num);
	cur_subdev_desc = (mmr_iosubdbuf_t *) &iomap_buf[subdev_buf_trans_size];
 /* Инициализация дескриптора и области данных буфера */
	mmr_init_subdev_buf(state, cur_subdev_desc, MMR_IO_READ,
					subdev_buf_reciv_size - sizeof(mmr_iosubd_desc_t),
					iomap_buf_num);

	debug_mmr(KERN_ALERT "INST %d. mmr_init_iomap_buf: успешное завершение.\n",
			state->inst);
}

int mmr_create_drv_iomap_buf(
	mmr_state_t		*state)
{
	mmr_chnl_state_t	*channel_state     = NULL;
	trbuf_state_t		*trans_buf_state   = NULL;
	size_t			max_buf_trans_size = 0;
	size_t			max_buf_reciv_size = 0;
	int			max_buf_num        = 0;
	int			max_subdev_num     = 0;
	caddr_t			user_buf_address   = 0;
	dma_addr_t		dma_buf_address    = 0;
	mmr_iosubdbuf_t		*cur_subdev_buf    = NULL;
	size_t			user_buf_size      = 0;
	size_t			drv_buf_size       = 0;
	long			page_size          = PAGE_SIZE;
	long			page_allign        = 0;
	int			cur_buf            = 0;
	int			rval               = 0;


	debug_mmr(KERN_ALERT "INST %d. mmr_create_drv_iomap_buf: Started.\n", state->inst);
/* Внутреннее состояние устройства */
	channel_state = state->channel_state;
/* Состояние буфера пересылки */
	trans_buf_state = &channel_state->trans_buf_state;
/* Реальный максимальный размер передающего буфера обмена (байтов)*/
	max_buf_trans_size = channel_state->init_iomap_state_spec.max_data_buf_trans_size + sizeof(mmr_iosubd_desc_t);
/* Реальный максимальный размер приемного буфера обмена (байтов)*/
	max_buf_reciv_size = channel_state->init_iomap_state_spec.max_data_buf_reciv_size + sizeof(mmr_iosubd_desc_t);
	max_subdev_num = 1;
	max_buf_num = channel_state->init_iomap_state_spec.buf_num;
/* Буфер передатчика + буфер приемника */
	user_buf_size = max_buf_trans_size + max_buf_reciv_size;
	debug_mmr(KERN_ALERT "INST %d. user_buf_size = %ld.\n",
			state->inst, (ulong_t)user_buf_size);
/* Общий размер буфер */
	drv_buf_size = user_buf_size * max_buf_num;
	debug_mmr(KERN_ALERT "INST %d. drv_buf_size = %ld.\n",
			state->inst, (ulong_t)drv_buf_size);
/* Создание и размещение буферов обмена */
	rval = mmr_alloc_trans_bufs(state, &trans_buf_state->trans_buf_desc,
			drv_buf_size + page_size);
	if (rval != 0) {
		printk(KERN_ERR "INST %d. "
			"mmr_create_drv_iomap_buf: отказ.\n",
			state->inst);
		return rval;
	}
	user_buf_address = trans_buf_state->trans_buf_desc.buf_address;
	dma_buf_address  = trans_buf_state->trans_buf_desc.dma.busa;
	page_allign      = (long)user_buf_address & (page_size - 1);
	if (page_allign != 0) {
		user_buf_address = user_buf_address + (page_size - page_allign);
		dma_buf_address  = dma_buf_address + (page_size - page_allign);
	}
 /* Формирование структуры буфера пересылки - trbuf_state_t (mmr.h) */
	trans_buf_state->user_buf_address = user_buf_address;
	trans_buf_state->user_buf_size    = user_buf_size;
	trans_buf_state->max_user_buf_num = max_buf_num;
	for (cur_buf = 0; cur_buf < max_buf_num; cur_buf ++) {
		trans_buf_state->user_trans_bufs[cur_buf] = user_buf_address;
		cur_subdev_buf = (mmr_iosubdbuf_t *) user_buf_address;

/* Инициализация буфера карты передачи */
		mmr_init_iomap_buf(state, cur_subdev_buf, max_buf_trans_size, max_buf_reciv_size, cur_buf);
		user_buf_address = user_buf_address + user_buf_size;
		debug_mmr(KERN_ALERT "INST %d. user_buf_address = %lx.\n",
				state->inst, (unsigned long)user_buf_address);
/* Адрес буфера пересылки */
		debug_mmr(KERN_ALERT "INST %d. dma_buf_address = %#x.\n",
				state->inst,
				dma_buf_address);
		trans_buf_state->dma_trans_bufs[cur_buf] = dma_buf_address;
		dma_buf_address = dma_buf_address + user_buf_size;
	}
/* Сформирован буфер пересылки */
	trans_buf_state->valid_flag = 1;
	debug_mmr(KERN_ALERT "INST %d. "
			"mmr_create_drv_iomap_buf: успешное завершение.\n",
			state->inst);
	return 0;
}

void	mmr_free_channel_to_init(
	mmr_state_t		*state,
	int			mutex_locked)
{
/* Структура внутреннего состояния устройства */
	mmr_chnl_state_t	*channel_state = NULL;

	debug_mmr(KERN_ALERT "INST %d. mmr_free_channel_to_init: Started.\n",
			state->inst);
	channel_state = state->channel_state;
	if (!mutex_locked)
		  spin_mutex_enter(&state->lock);
/* Снятие признака выполнения инициализации устройства */
	if (channel_state->state_init_in_progress) {
		channel_state->state_init_in_progress = 0;
		cv_broadcast(&state->trans_state_cv);
	}
	if (!mutex_locked)
		spin_mutex_exit(&state->lock);

	debug_mmr(KERN_ALERT "INST %d. "
			"mmr_free_channel_to_init: успешное завершение.\n",
			state->inst);
}

/* Значения УСК, АС0, СКБ и АС1 */
void USK_AC0_SKB_AC1_VU(mmr_state_t *state)
{
	mmr_area_bozu_t	*area_bozu;		/* указатель области БОЗУ */
	u_int   	cur_num_vu = 0;

/* Указатель области БОЗУ */
	area_bozu = (mmr_area_bozu_t *) state->MMR_BMEM;
	debug_mmr(KERN_ALERT "USK_AC0_SKB_AC1_VU: N ВУ     УСК          AC0      CKБ     AC1\n");

	for (cur_num_vu = 0; cur_num_vu < MMR_BUF_ADAPTER_NUM*2; cur_num_vu++) {
		debug_mmr(KERN_ALERT "USK_AC0_SKB_AC1_VU:  %3d:  0x%08x:  0x%08x:  0x%08x:  0x%08x.\n",
				cur_num_vu,
				area_bozu->init_buf_data[cur_num_vu].USK,
				area_bozu->init_buf_data[cur_num_vu].AC0,
				area_bozu->init_buf_data[cur_num_vu].SKB,
				area_bozu->init_buf_data[cur_num_vu].AC1);
	}
	debug_mmr(KERN_ALERT "USK_AC0_SKB_AC1_VU:  БК: 0x%08x:  0x%08x:  0x%08x:  0x%08x.\n",
		area_bozu->init_buf_comm.USK,
		area_bozu->init_buf_comm.AC0,
		area_bozu->init_buf_comm.SKB,
		area_bozu->init_buf_comm.AC1);
}

int mmr_init_trans_map_state(
	mmr_state_t		*state,
	mmr_init_iomap_t	*init_state_args,
	int			drv_comm_area_locked,
	int			*error_code,
	int			state_recover,
	int			flag_board)

{
	mmr_chnl_state_t	*channel_state = NULL;
	mmr_init_iomap_t	*init_iomap_state_spec = NULL; 	/* mmr_io.h */
	ctrl_buf_datas_t	ctrl_buf_datas;			/* mmr.h */
	ctrl_buf_comm_t		ctrl_buf_comm;			/* mmr.h */
	int			user_request = (init_state_args != NULL);
	int			max_buf_num = 0; /* мак. кол-во буферов */
	u_short			max_data_buf_trans_size = 0;
	u_short			max_data_buf_reciv_size = 0;
	int			cur_buf = 0;
	int			cur_num_vu;
	int			rval    = 0;
	drv_comm_memory_t	*drv_communication = NULL;
	int			args_num;
	int			cur_arg;
	u_int			val;
	u_int			skb;

	debug_mmr(KERN_ALERT "INST %d. mmr_init_trans_map_state: Started. state_recover = %d.\n",
			state->inst, state_recover);
	state->flag_board = flag_board;
	channel_state = state->channel_state;
/* Обнуление элементов структуры внутреннего состояния устройства -
   mmr_chnl_state_t (mmr.h) */
	rval = mmr_get_channel_to_init(state, -1, drv_comm_area_locked, user_request, state_recover);
	if (rval > 0) {
		return (rval);
	} else if (rval < 0) {
		return (0);
	}
	if (init_state_args != NULL) {
		channel_state->init_iomap_state_spec = *init_state_args;
	}
/* Состояние - инициализация карты пересылки */
	init_iomap_state_spec = &channel_state->init_iomap_state_spec;

	max_buf_num             = init_iomap_state_spec->buf_num;
	max_data_buf_trans_size = init_iomap_state_spec->max_data_buf_trans_size;
	max_data_buf_trans_size = TU_MMR_DMA_BURST_SIZE_ALIGN(max_data_buf_trans_size,
			sizeof(u_char), 0, MMR_DMA_BURST_SIZE) * sizeof(u_char);
	init_iomap_state_spec->max_data_buf_trans_size = max_data_buf_trans_size;

	max_data_buf_reciv_size = init_iomap_state_spec->max_data_buf_reciv_size;
	max_data_buf_reciv_size = TU_MMR_DMA_BURST_SIZE_ALIGN(max_data_buf_reciv_size,
			sizeof(u_char), 0, MMR_DMA_BURST_SIZE) * sizeof(u_char);
	init_iomap_state_spec->max_data_buf_reciv_size = max_data_buf_reciv_size;

	debug_mmr(KERN_ALERT "INST %d. mmr_init_trans_map_state: число буферов %d, "
			"размер передающего буфера данных %d байтов, "
			"размер приемного буфера данных %d байтов.\n",
			state->inst,
			init_iomap_state_spec->buf_num,
			init_iomap_state_spec->max_data_buf_trans_size,
			init_iomap_state_spec->max_data_buf_reciv_size);
/* Создание буфер карты обмена */
	rval = mmr_create_drv_iomap_buf(state);
	if (rval != 0) {
		printk(KERN_ERR "INST %d. "
			"mmr_init_trans_map_state: mmr_create_drv_iomap_buf "
			"завершена с ошибкой.\n",
			state->inst);
		return rval;
	}

	drv_communication =
		(drv_comm_memory_t *) &state-> MMR_BMEM[MMR_ADDR_CNTRL_INFRM_BUFFERS_DATAS];
	debug_mmr(KERN_ALERT "INST %d. адрес ctrl_buf_datas = 0x%08lx.\n",
			state->inst,
			(unsigned long)&drv_communication->ctrl_buf_datas.args_area[0]);
	debug_mmr(KERN_ALERT "INST %d. адрес ctrl_buf_comm = 0x%08lx.\n",
			state->inst,
			(unsigned long)&drv_communication->ctrl_buf_comm.args_area[0]);

/* Формирование управляющей информации по буферам обмена */
	debug_mmr(KERN_ALERT "N ВУ     УСК          AC0      CKБ     AC1\n");
	for (cur_buf = 0; cur_buf < MMR_BUF_ADAPTER_NUM; cur_buf ++) {
/* Передатчик */
		cur_num_vu = cur_buf*2;
		ctrl_buf_datas.init_buf_data[cur_buf].USK_TRANS = USK_TRANS_buf;
		ctrl_buf_datas.init_buf_data[cur_buf].AC0_TRANS =
			channel_state->trans_buf_state.dma_trans_bufs[cur_buf] + MMR_DMA_BURST_SIZE;
		ctrl_buf_datas.init_buf_data[cur_buf].SKB_TRANS = SKB_buf_date;
		ctrl_buf_datas.init_buf_data[cur_buf].AC1_TRANS =
			ctrl_buf_datas.init_buf_data[cur_buf].AC0_TRANS;
		debug_mmr(KERN_ALERT "  %3d:  0x%08x:  0x%08x:  0x%08x:  0x%08x.\n",
			cur_num_vu,
			ctrl_buf_datas.init_buf_data[cur_buf].USK_TRANS,
			ctrl_buf_datas.init_buf_data[cur_buf].AC0_TRANS,
			ctrl_buf_datas.init_buf_data[cur_buf].SKB_TRANS,
			ctrl_buf_datas.init_buf_data[cur_buf].AC1_TRANS);

/* Приемник */
		cur_num_vu = cur_buf*2 + 1;
		ctrl_buf_datas.init_buf_data[cur_buf].USK_RECIV = USK_RECIV_buf;
		ctrl_buf_datas.init_buf_data[cur_buf].AC0_RECIV =
			ctrl_buf_datas.init_buf_data[cur_buf].AC0_TRANS +
				max_data_buf_trans_size + MMR_DMA_BURST_SIZE;
		ctrl_buf_datas.init_buf_data[cur_buf].SKB_RECIV = SKB_buf_date;
		ctrl_buf_datas.init_buf_data[cur_buf].AC1_RECIV =
		ctrl_buf_datas.init_buf_data[cur_buf].AC0_RECIV;
		debug_mmr(KERN_ALERT "  %3d:  0x%08x:  0x%08x:  0x%08x:  0x%08x.\n",
			cur_num_vu,
			ctrl_buf_datas.init_buf_data[cur_buf].USK_RECIV,
			ctrl_buf_datas.init_buf_data[cur_buf].AC0_RECIV,
			ctrl_buf_datas.init_buf_data[cur_buf].SKB_RECIV,
			ctrl_buf_datas.init_buf_data[cur_buf].AC1_RECIV);
	}

/* Запись управляющей информации буферов данных в область связи */
	args_num = sizeof(drv_communication->ctrl_buf_datas.args_area) >> 2;
	debug_mmr(KERN_ALERT "INST %d. args_num буферов данных = %d.\n",
			state->inst,
			args_num);
	for (cur_arg = 0; cur_arg < args_num; cur_arg ++) {
		drv_communication->ctrl_buf_datas.args_area[cur_arg] =
		   ctrl_buf_datas.args_area[cur_arg];
	}
/* Контроль записи управляющей информации буферов данных */
	for (cur_arg = 0; cur_arg < args_num; cur_arg ++){
		if (drv_communication->ctrl_buf_datas.args_area[cur_arg] != ctrl_buf_datas.args_area[cur_arg]) {
			printk(KERN_ERR "INST %d. "
				"mmr_init_trans_map_state: запись упр. инфор. буферов "
				"данных произведена с ошибкой. cur_arg = %d.\n",
				state->inst, cur_arg);
			rval = -1;
		}
	}
/* Формирование управляющей информации буфера команд */
	if (flag_board == MODE_CONTROLLER) {
		ctrl_buf_comm.init_buf_comm.USK = USK_CTRL_buf_comm;
		ctrl_buf_comm.init_buf_comm.AC0 =
			channel_state->trans_buf_state.dma_trans_bufs[MMR_BUF_ADAPTER_NUM] + MMR_DMA_BURST_SIZE;
		ctrl_buf_comm.init_buf_comm.SKB = SKB_buf_comm_CNTR;
	} else if (flag_board == MODE_TERMINAL) {
		ctrl_buf_comm.init_buf_comm.USK = USK_TERM_buf_comm;
		ctrl_buf_comm.init_buf_comm.AC0 =
			channel_state->trans_buf_state.dma_trans_bufs[MMR_BUF_ADAPTER_NUM] + MMR_DMA_BURST_SIZE;
		val = MMR_MAX_NUM_BUF_COMM;
		skb = 0x01000000 | (val << 8) | MMR_MAX_NUM_BUF_COMM;
		ctrl_buf_comm.init_buf_comm.SKB = skb;
	} else {
		ctrl_buf_comm.init_buf_comm.USK = USK_TERM_buf_comm;
		ctrl_buf_comm.init_buf_comm.AC0 =
			channel_state->trans_buf_state.dma_trans_bufs[MMR_BUF_ADAPTER_NUM] + MMR_DMA_BURST_SIZE;
/*														
		val = MMR_MAX_NUM_BUF_COMM;
		skb = 0x01000000 | (val << 8) | MMR_MAX_NUM_BUF_COMM;
*/		
		ctrl_buf_comm.init_buf_comm.SKB = SKB_buf_comm_MNTR;
	}
	ctrl_buf_comm.init_buf_comm.AC1 = ctrl_buf_comm.init_buf_comm.AC0;
	debug_mmr(KERN_ALERT "    :  0x%08x:  0x%08x:  0x%08x:  0x%08x.\n",
			ctrl_buf_comm.init_buf_comm.USK,
			ctrl_buf_comm.init_buf_comm.AC0,
			ctrl_buf_comm.init_buf_comm.SKB,
			ctrl_buf_comm.init_buf_comm.AC1);

 /* Запись управляющей информации буфера команд в область связи */
	args_num = sizeof(drv_communication->ctrl_buf_comm.args_area) >> 2;
	debug_mmr(KERN_ALERT "INST %d. args_num буфера команд = %d.\n",
			state->inst, args_num);
	for (cur_arg = 0; cur_arg < args_num; cur_arg ++) {
		drv_communication->ctrl_buf_comm.args_area[cur_arg] = ctrl_buf_comm.args_area[cur_arg];
	}
	for (cur_arg = 0; cur_arg < args_num; cur_arg ++) {
/* Контроль записи управляющей информации буфера команд */
		if (drv_communication->ctrl_buf_datas.args_area[cur_arg] != ctrl_buf_datas.args_area[cur_arg]) {
			printk(KERN_ERR "INST %d. "
				"mmr_init_trans_map_state: запись упр. инфор. буфера "
				"команд произведена с ошибкой. cur_arg = %d.\n",
				state->inst, cur_arg);
			rval = -1;
		}
	}	
	USK_AC0_SKB_AC1_VU(state);

	if (state_recover == 0)
			spin_mutex_enter(&state->lock);
	channel_state->init_as_trans_map  = 1;
	channel_state->full_data_buf_size = 0;
	channel_state->subdev_buf_trans_size = max_data_buf_trans_size + sizeof(mmr_iosubd_desc_t);
	channel_state->subdev_buf_reciv_size = max_data_buf_reciv_size + sizeof(mmr_iosubd_desc_t);
	channel_state->trans_state_is_init = 1;
	if (state_recover == 0)
		spin_mutex_exit(&state->lock);
	mmr_free_channel_to_init(state, state_recover);
	debug_mmr(KERN_ALERT "INST %d. mmr_init_trans_map_state: Finished.\n", state->inst);
	return (rval);
}

long
mmr_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	mmr_state_t	*state = (mmr_state_t *)file->private_data;
	dev_t	dev = state->dev;
	int		instance = MMR_INST(dev);
	int		channel = MMR_CHAN(dev);
	int 	rval = 0;

	//debug_mmr("INST %d. mmr_ioctl: Start с команды 0x%x \n", instance, cmd);

	if ( state == NULL ) {
		printk(KERN_ERR "INST %d. "
			"mmr_ioctl: незагружен экземпляр устройства %d.\n",
			instance, instance);
		return -ENXIO;
	 }

	lock_kernel();

//	state->inst = instance;

	switch ( cmd ) {
		case MCST_SELFTEST_MAGIC:
		{
			selftest_t st;
#if defined(CONFIG_SBUS)
			selftest_sbus_t *st_sbus = &st.info.sbus;
			char *tmp, *sl_n;
			int slot_num, addr;
			struct device_node *dn = state->op->node;
			size_t rval;

			st.bus_type = BUS_SBUS;
			st_sbus->bus = 0;
			strcpy(st_sbus->name, MMR_NAME);

			st_sbus->major = MAJOR(dev);
			st_sbus->minor = MINOR(dev);

//			printk("full_name [%s]\n", dn->full_name);
			tmp = strrchr(dn->full_name, '@');
			if ( tmp ) {
				// Уберём символ "@" из строки
				tmp = &tmp[1];
				//printk("STRRCHR: [%s]\n", tmp);

				sl_n = strrchr(tmp, ',');

				if ( sl_n ) {
					sscanf(tmp, "%d", &slot_num);
					sscanf(&sl_n[1], "%x", &addr);
//					printk("STRRCHR: slot_number [%d], [%s], [%d]\n", slot_num, sl_n, addr);

					if ( (addr >> 28) != 0 ) { // Присутствует расширитель
						st_sbus->br_slot = slot_num;
						st_sbus->slot = addr >> 28;
					} else {
						st_sbus->br_slot = -1;
						st_sbus->slot = slot_num;
					}

					st_sbus->address = addr & 0x0FFFFFFF;
				}
			} else {
				st.error = 1;
			}

//printk("%s:\n\tName [%s]\n\tMAJOR [%d], MINOR [%d].\n\tBUS [%d], BRIDGE_SLOT [%d], SLOT [%d], ADDRESS [%#x].\n", __func__, st_sbus->name, st_sbus->major, st_sbus->minor, st_sbus->bus, st_sbus->br_slot, st_sbus->slot, st_sbus->address);
#elif IS_ENABLED(CONFIG_PCI2SBUS)
			selftest_pci_t *st_pci = &st.info.pci;
			int irq = state->irq;
			p2s_info_t* p2s_info = get_p2s_info(irq >> 8);

			if ( !p2s_info ) {
				printk("%s: MCST_SELFTEST_MAGIC: Cannot get p2s_info struct corresponded to IRQ=%d\n", __func__, irq);
				return -EFAULT;
			}

			struct pci_dev *pdev = p2s_info->pdev;
			int rval;
			st_pci->vendor = pdev->vendor;
			st_pci->device = pdev->device;

			st.bus_type = BUS_PCI;

			strcpy(st_pci->name, MMR_NAME);
			st_pci->bus = pdev->bus->number;
			st_pci->slot = PCI_SLOT(pdev->devfn);
			st_pci->func = PCI_FUNC(pdev->devfn);
			st_pci->class = pdev->class;

			st_pci->major = MAJOR(dev);
			st_pci->minor = MINOR(dev);

			//printk("%s: tty->index = %d, major = %d, minor = %d\n", __func__, tty->index, st_pci->major, st_pci->minor);

//printk("%s: name [%s]. vendor = %#x, device = %#x. major = %d, minor = %d. bus = %d, slot = %d, func = %d, class = %#x\n", __func__, st_pci->name, st_pci->vendor, st_pci->device, st_pci->major, st_pci->minor, st_pci->bus, st_pci->slot, st_pci->func, st_pci->class);
#else
			printk("%s: MCST_SELFTEST_MAGIC: neither CONFIG_SBUS nor CONFIG_PCI2SBUS(CONFIG_PCI2SBUS_MODULE) is defined!! Strange...\n");
			return -EFAULT;
#endif

			rval = copy_to_user((void *)arg, (void *)&st, sizeof(selftest_t));
			if ( rval != 0 ) {
				printk( "%s: MCST_SELFTEST_MAGIC: copy_to_user() failed\n", __func__);
				return -EFAULT;
			}

			return 0;
		}
		/// Получить режимы драйвера и установить информацию
		case MMRIO_GET_DRIVER_INFO :
		{
			mmr_drv_info_t	driver_info;
			dbgmmr(KERN_ALERT "***** mmr_ioctl: MMRIO_GET_DRIVER_INFO *****\n");
			driver_info.sbus_clock_freq = mmr_sbus_clock_freq;
			driver_info.sbus_nsec_cycle = mmr_sbus_nsec_cycle;
			driver_info.mp_clock_freq   = mmr_mp_clock_freq;
			driver_info.mp_nsec_cycle   = mmr_mp_nsec_cycle;
			driver_info.cur_hr_time     = ddi_gethrtime();

			
			
			rval = ddi_copyout((caddr_t) &driver_info, (caddr_t) arg, sizeof (me90_drv_info_t));
			dbgmmrdetail(KERN_ALERT "%s(): mmr_sbus_clock_freq = %d, mmr_sbus_nsec_cycle = %d, mmr_mp_clock_freq  = %d, mmr_mp_nsec_cycle   = %d\n", __func__, mmr_sbus_clock_freq,
					mmr_sbus_nsec_cycle,  mmr_mp_clock_freq, mmr_mp_nsec_cycle);
			if ( rval != 0 ) {
				printk(KERN_ERR "INST %d. "
					"mmr_ioctl: ddi_copyout завершена с ошибкой "
					"при переписи значений режима драйвера.\n",
					instance);
				rval = -EFAULT;
			}

			dbgmmr(KERN_ALERT "***** mmr_ioctl: FINISHED *****\n");
			goto out;
		}
		case MMRIO_READ_DEVICE_REG:
		{
			mmr_arg_reg_t	op_reg;
			int			rval = 0;
			
			dbgmmr(KERN_ALERT "***** mmr_ioctl(MMRIO_READ_DEVICE_REG): Started *****\n");
			rval = ddi_copyin((caddr_t)arg, (caddr_t) &op_reg, sizeof (mmr_arg_reg_t));
			if ( rval != 0 ) {
				printk(KERN_ERR "INST %d. "
					"mmr_ioctl: ddi_copyin завершена с ошибкой при "
					"переписи аргументов запроса на чтение регистра устройств.\n",
					instance);
				rval = -EFAULT;
				break;
			}
	
			op_reg.reg_value = READ_MMR_REGISTER(state, op_reg.reg_addr);
			debug_mmr(KERN_ALERT "INST %d.  %s(): (чтение): адрес = 0x%x, значение = 0x%x.\n", instance, __func__, op_reg.reg_addr, op_reg.reg_value);

			rval = ddi_copyout((caddr_t) &op_reg, (caddr_t) arg, sizeof (mmr_arg_reg_t));
			if ( rval != 0 ) {
				printk(KERN_ERR "INST %d. "
					"%s(): ddi_copyout завершена с ошибкой "
					"при переписи результата чтения регистра устройства.\n", instance, __func__);

				rval = -EFAULT;
			}

			dbgmmr(KERN_ALERT "***** mmr_ioctl(MMRIO_READ_DEVICE_REG): FINISHED *****\n");
			goto out;
		}
		case MMRIO_WRITE_DEVICE_REG :
		{
			mmr_arg_reg_t		op_reg;
			int					rval = 0;
		
			dbgmmr(KERN_ALERT "***** mmr_ioctl: MMRIO_WRITE_DEVICE_REG *****\n");
			rval = ddi_copyin((caddr_t) arg, (caddr_t) &op_reg, sizeof (mmr_arg_reg_t));
			if ( rval != 0 ) {
				printk(KERN_ERR "INST %d. "
					"mmr_ioctl: ddi_copyin завершена с ошибкой "
					"при переписи запроса на запись в регистр устройства.\n",
					instance);
				rval = -EFAULT;
				break;
			}

			debug_mmr("INST %d. %s: (запись): адрес = 0x%x, значение = 0x%x.\n",
//			printk(KERN_ERR "INST %d. %s(): (запись): адрес = 0x%x, значение = 0x%x.\n",
					instance, __func__, op_reg.reg_addr, op_reg.reg_value);
			WRITE_MMR_REGISTER(state, op_reg.reg_addr, op_reg.reg_value);

			dbgmmr(KERN_ALERT "***** mmr_ioctl: FINISHED *****\n");
			goto out;
		}
		case MMRIO_INIT_DEVICE :
		{
			mmr_arg_reg_t		op_reg;
			int			rval = 0;
		
			dbgmmr(KERN_ALERT "***** mmr_ioctl: MMRIO_INIT_DEVICE *****\n");
			rval = ddi_copyin((caddr_t) arg, (caddr_t) &op_reg, sizeof (mmr_arg_reg_t));
			if (rval != 0) {
				printk(KERN_ERR "INST %d. "
					"mmr_ioctl: ddi_copyin завершена с ошибкой "
					"при переписи запроса на запись в регистр управления.\n",
					instance);
				rval = -EFAULT;
				break;
			}
			debug_mmr(KERN_ALERT "INST %d. %s(): (запись): адрес = 0x%x, значение = 0x%x.\n",
					instance, __func__, op_reg.reg_addr, op_reg.reg_value);
	/* Регистр управления ММР */
			state->mmr_reg_cntrl_dev.wr_mmr_reg_cntrl = op_reg.reg_value; 
			dbgmmrdetail(KERN_ALERT " mmr_ioctl: state->regs_base = 0x%lx\n", (unsigned long)state->regs_base);
			WRITE_MMR_REGISTER(state, op_reg.reg_addr, op_reg.reg_value);
			dbgmmr(KERN_ALERT "***** mmr_ioctl: FINISHED *****\n");
			goto out;
		}
		case MMRIO_INIT_BUFERS_EXCHANGE : /* init_trans */
		{
			mmr_chnl_state_t	*channel_state = NULL;
			mmr_init_iomap_t	init_iomap_state_spec;
			size_t			*real_buf_size_p = NULL;
			int			error_code = 0;
			int			*error_code_p = NULL;
			int			flag_board;
	
			dbgmmr(KERN_ALERT "***** mmr_ioctl: MMRIO_INIT_BUFERS_EXCHANGE *****\n");
			channel_state = state->channel_state;
	/* Копирование аргументов в структуру параметров инициализации буферов */
	/* обмена данными mmr_init_iomap_t (файл mmr_io.h) */
			rval = ddi_copyin((caddr_t) arg, (caddr_t) &init_iomap_state_spec, sizeof (mmr_init_iomap_t));
			if (rval != 0) {
			printk(KERN_ERR "INST %d. "
					"mmr_ioctl: ddi_copyin завершена с ошибкой при переписи "
					"аргументов инициализации буферов обмена данными.\n",
					instance);
				rval = -EFAULT;
				goto out;
			}
			real_buf_size_p = init_iomap_state_spec.real_buf_size_p;
			error_code_p    = init_iomap_state_spec.error_code_p;
			flag_board    	= init_iomap_state_spec.flag_board;
			
			debug_mmr(KERN_ALERT "%s(): real_buf_size_p = 0x%lx"
				"		  error_code_p = 0x%lx"
				"		  flag_board = %d\n", __func__, 
				(unsigned long)real_buf_size_p, (unsigned long)error_code_p,
				flag_board);
			debug_mmr(KERN_ALERT "INST %d. %s(): инициализация буферов обмена данными.\n",
					instance, __func__);
			rval = mmr_init_trans_map_state(state, &init_iomap_state_spec, 0, &error_code, 0, flag_board);
			if (real_buf_size_p != NULL) {
				if (ddi_copyout((caddr_t) &channel_state ->
						trans_buf_state.user_buf_size,
					(caddr_t) real_buf_size_p,
					sizeof (*real_buf_size_p))) {
					printk(KERN_ERR "INST %d. "
						"mmr_ioctl: ddi_copyout завершена с ошибкой при "
						"переписи информации о реальном размере буфера карты.\n",
						instance);
					rval = -EFAULT;
					goto out;
				}
			}
			if (error_code_p != NULL) {
				rval = ddi_copyout((caddr_t) &error_code, (caddr_t) error_code_p, sizeof (*error_code_p));
				if (rval != 0) {
					printk(KERN_ERR "INST %d. "
						"mmr_ioctl: ddi_copyout завершена с ошибкой при переписи "
						"результатов инициализации буферов обмена данными.\n",
						instance);
					rval = -EFAULT;
					goto out;
				}
			}
			if (rval == 0) {
				spin_mutex_enter(&state->lock);		/* start MUTEX */
				if (channel_state->trans_buf_state.valid_flag == 0) {
					printk(KERN_ERR "INST %d. "
						"mmr_ioctl: отказ при установке общего буфера обмена "
						"данными.\n",
						instance);
					spin_mutex_exit(&state->lock);	/* end MUTEX */
					rval = -EINVAL;
					goto out;
				}
				spin_mutex_exit(&state->lock);		/* end MUTEX */
				debug_mmr(KERN_ALERT "INST %d. "
						"mmr_ioctl: завершена инициализация буферов обмена "
						"данными.\n",
						instance);
			}
			dbgmmr(KERN_ALERT "***** mmr_ioctl: FINISHED *****\n");
			goto out;
		}
		case MMRIO_HALT_TRANSFER_MODES : /* init_trans, halt */
		{
			mmr_halt_trans_t	halt_trans_state;
			int			rval = 0;
	
			dbgmmr(KERN_ALERT "***** mmr_ioctl: MMRIO_HALT_TRANSFER_MODES *****\n");
			rval = ddi_copyin((caddr_t) arg, (caddr_t) &halt_trans_state, sizeof (mmr_halt_trans_t));
			if (rval != 0) {
				printk(KERN_ERR "INST %d. "
					"mmr_ioctl: ddi_copyin завершена с ошибкой при переписи "
					"аргументов останова канала.\n",
					instance);
				rval = -EFAULT;
				goto out;
			}
			debug_mmr(KERN_ALERT "INST %d. mmr_ioctl: останав канала; время ожидания %d.\n",
					instance, halt_trans_state.waiting_time);
			rval = mmr_halt_trans_state(state, &halt_trans_state, 0, 1, 0);
	
			debug_mmr(KERN_ALERT "INST %d. mmr_ioctl: завершен останов канала.\n",
					instance);
			dbgmmr(KERN_ALERT "***** mmr_ioctl: FINISH *****\n");
			goto out;
		}
		case MMRIO_GET_DEVICE_INFO : /* init_trans */
		{
			mmr_dev_info_t		device_info;
			dbgmmr(KERN_ALERT "***** mmr_ioctl: MMRIO_GET_DEVICE_INFO *****\n");
			debug_mmr(KERN_ALERT "INST %d. mmr_ioctl: начало получения информации об устройстве.\n",
					instance);
			device_info.instance  = instance;
			device_info.channel   = channel;
	
			rval = ddi_copyout((caddr_t) &device_info, (caddr_t) arg, sizeof (mmr_dev_info_t));
			if (rval != 0) {
				printk(KERN_ERR "INST %d. "
					"mmr_ioctl: ddi_copyout завершена с ошибкой при переписи "
					"информации об устройстве.\n",
					instance);
				rval = -EFAULT;
				goto out;
			}

			debug_mmr(KERN_ALERT "INST %d. "
					"mmr_ioctl: завершена выдача информации об устройстве. rval = %d\n",
					instance, rval);
			dbgmmr(KERN_ALERT "***** mmr_ioctl: FINISHED *****\n");
			goto out;
		}
	/* Ожидание прерывания от ячейки ММР */
		case MMRIO_INTR_TIME_WAIT :
		{
			mmr_intr_wait_t	intr_user; /* структура в файле mmr_io.h */

			int				rf = 0;
			u_long				timeout = 0;
			hrtime_t			time_get_command = 0;
			dbgmmr(KERN_ALERT "***** mmr_ioctl: MMRIO_INTR_TIME_WAIT *****\n");
			rval = ddi_copyin((caddr_t)arg, (caddr_t) &intr_user, sizeof (mmr_intr_wait_t));
			if (rval != 0) {
				printk(KERN_ERR "INST %d. "
					"mmr_ioctl: ddi_copyin завершена с ошибкой при переписи "
					"аргументов ожидания прерывания.",
					instance);
				rval = -EINVAL;
				goto out;
			}
			dbgmmrdetail(KERN_ALERT "***** mmr_ioctl: intr_wait_time = %ld\n", intr_user.intr_wait_time);
			
			drv_getparm(LBOLT, &timeout); /* t тек. в тиках */
			timeout = timeout + drv_usectohz(intr_user.intr_wait_time);
			spin_mutex_enter(&state->lock);
			if (state->io_flags_intr == 0  && state->flags_intr_rerr == 0 )
			{
				rf = cv_spin_timedwait(&state->intr_cv, &state->lock, timeout);
				if (rf == -1) {
					debug_mmr(KERN_ALERT "INST %d. mmr_ioctl: cv_timedwait() - время истекло "
						"= %ld мксек.\n",
						instance, intr_user.intr_wait_time);
					rval = -ETIME;
				}
			} else {
				debug_mmr(KERN_ALERT "INST %d. mmr_ioctl: %lu прерываний выполнено ранее cv_timedwait \n", instance, state->io_flags_intr);
			}

			if ( rf >= 0 ) {
				intr_user.event_intr = state->io_flags_intr; /* код события */
				debug_mmr(KERN_ALERT "INST %d. mmr_ioctl: Выдано прерывание ПрП. cur_num_comm = %d\n",
						instance, state->cur_num_comm);
				debug_mmr(KERN_ALERT "mmr_ioctl: INST %d. io_flags_intr %lu flags_intr_rerr %lu", instance, state->io_flags_intr, state->flags_intr_rerr);
				/* Признак наличия прерывания по РОШ */
				intr_user.board_error        = state->flags_intr_rerr;
				intr_user.num_reciv_comm     = state->num_reciv_comm;
				intr_user.intr_device 	     = state->intr_dev;
				intr_user.time_get_intr_device = state->time_get_intr_dev;
				intr_user.time_get_comm        = time_get_command;
				intr_user.cur_num_comm       = state->cur_num_comm;
				state->cur_num_comm    = 0;
				state->io_flags_intr         = 0;
				state->flags_intr_rerr 	     = 0;
				spin_mutex_exit(&state->lock);
				rval = ddi_copyout((caddr_t)&intr_user, (caddr_t)arg, sizeof (mmr_intr_wait_t));
				if (rval != 0) {
					printk(KERN_ERR "INST %d. "
						"mmr_ioctl: ddi_copyout: завершена с ошибкой при "
						"переписи информации о прерывании от ячейки ММР.\n",
						instance);
					rval = -EINVAL;
					goto out;
				}
			} else {
				spin_mutex_exit(&state->lock);
			}
			dbgmmr(KERN_ALERT "***** mmr_ioctl: FINISHED *****\n");
			goto out;
		}
		/* Получение информации о прерываниях по РОШ */
		case MMRIO_NUM_INTR_ROSH : 
		{
			mmr_intr_rosh_t		intr_rosh;
	
			debug_mmr(KERN_ALERT "экз. %d. mmr_ioctl: начало получения информации о "
					"прерываниях по РОШ.\n",
					instance);
			intr_rosh.num_intr_rosh = state->number_intr_rosh;
	
			rval = ddi_copyout((caddr_t) &intr_rosh, (caddr_t) arg,
									sizeof (mmr_intr_rosh_t)/*, mode*/);
			if (rval != 0) {
				printk("экз. %d. "
					"mmr_ioctl: ddi_copyout завершена с ошибкой при переписи "
					"информации о прерываниях по РОШ.\n",
					instance);
				rval = -EFAULT;
				goto out;
			};
			state->number_intr_rosh = 0;
			debug_mmr(KERN_ALERT "экз. %d. mmr_ioctl: завершена выдача информации о "
					"прерываниях по РОШ.\n",
					instance);
			goto out;
		}
		default :
			printk(KERN_ERR "INST %d. "
				"***** mmr_ioctl: неверная команда 0x%x для ioctl().\n",
					instance, cmd);
			rval = -ENOTTY;
			goto out;
	 }
	rval = -ENOTTY;
out:
	unlock_kernel();
	return rval;
}

module_init(mmr_init);
module_exit(mmr_exit);
MODULE_AUTHOR("Copyright by MCST 2012");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MMR driver");
