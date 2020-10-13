/*
 * Copyright (c) 1996 by MCST.
 * MC Board Driver general functions (MCKA).
 * Ported in linux by Alexey V. Sitnikov, alexmipt@mcst.ru, MCST 2004
 */

/*
 * Standard system includes
 */

#include <linux/miscdevice.h>

#include <linux/slab.h>
//#include <linux/wrapper.h>
#include <linux/delay.h>

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/dma.h>

#include "linux_mcka_match.h"
#include <linux/mcst/linux_me90_int.h>

#include <linux/of_device.h>

#define DBGMCKA_MODE 1
#define dbgmcka if(DBGMCKA_MODE) printk

#define DBGMCKASPIN_MODE 0
#define dbgmckaspin if(DBGMCKASPIN_MODE) printk

#define MCKA_INTERRUPT_DEBUG 0

#if MCKA_INTERRUPT_DEBUG
#define INTERRUPT_REG_BASE   0xf1410000
#define INTERRUPT_MASK_REG   0x4
#define INTERRUPT_MASK_CLEAR 0x8
#define INTERRUPT_MASK_SET   0xc

#define mcst_read(__reg) \
({	u32 __ret; \
	__asm__ __volatile__("lda [%1] %2, %0" \
			     : "=r" (__ret) \
			     : "r" (__reg), "i" (0x2f)  \
			     : "memory"); \
	__ret; \
})

#define mcst_write(__reg, __val) \
({	__asm__ __volatile__("sta %0, [%1] %2" \
			     : 		\
			     : "r" (__val), "r" (__reg), "i" (0x2f) \
			     : "memory"); })
#endif /* MCKA_INTERRUPT_DEBUG */

/*
 * Prototypes for this module
 */

static	int	mcka_open(struct inode *inode, struct file *file);
static	int	mcka_close(struct inode *inode, struct file *file);
extern	int	mcka_ioctl (struct inode *inode, struct file *filp,
				unsigned int cmd, unsigned long arg);
static	unsigned int	mcka_chpoll(struct file *file, struct poll_table_struct *wait);

static int mcka_mmap(struct file *file, struct vm_area_struct *vma);

static ssize_t mcka_read(struct file *pfile, char *buf, size_t sz, loff_t *lf);

static ssize_t mcka_write(struct file *pfile, const char *buf, size_t sz, loff_t *lf);
static irqreturn_t mcka_interrupt(int irq, void* arg);
static irqreturn_t mcka_intr_thread_handler(int irq, void* arg);

#if IS_ENABLED(CONFIG_PCI2SBUS)
extern void p2s_reg_print(u8 val);
#endif

static int mcka_instances;
static int mcka_major;

#define	MAX_MCKA_INSTANCES	16
static mcb_state_t	*mcka_states[MAX_MCKA_INSTANCES];

/*
 * file_operations of mcka
 */
static struct file_operations mcka_fops = {
	owner:   THIS_MODULE,
	ioctl:    mcka_ioctl,
	open:	  mcka_open,
	poll:     mcka_chpoll,
	mmap:     mcka_mmap,
	read:     mcka_read,
	write:    mcka_write, 
	release:  mcka_close,
};

static inline int mcka_clock_freq(mcb_state_t *state)
{
	return state->op->clock_freq;
}

static int inline mcka_request_irq(mcb_state_t *state)
{
#ifdef __e2k__
	printk("%s(): request irq PCI 2 SBUS\n", __func__);
#else
	return request_threaded_irq(state->op->irqs[0], mcka_interrupt,
				mcka_intr_thread_handler,
				IRQF_SHARED | IRQF_DISABLED | IRQF_ONESHOT,
				"mcka", state);
#endif
}

static void inline mcka_free_irq(mcb_state_t *state)
{
#ifdef __e2k__
	printk("free irq PCI 2 SBUS\n");
#else
	free_irq(state->op->irqs[0], state);
#endif
}

static int
mcka_nregs(mcb_state_t *state)
{
	struct of_device *op = state->op;
	struct resource *res = op->resource;
	int i;

	for ( i = 0; i < PROMREG_MAX; i++ ) {
		if ( res[i].end == 0 ) {
			break;
		}
	}

	return i;
}

static inline int mcka_io_remap_page(mcb_state_t *state, int reg_set_num,
		off_t offset, size_t len, struct vm_area_struct *vma)
{
	return -1;
}


static inline void *mcka_ioremap(mcb_state_t *state, int reg_set_num)
{
	struct of_device *op = state->op;

	return of_ioremap(&op->resource[reg_set_num], 0,
                    resource_size(&op->resource[reg_set_num]), MCKA_NAME);
}

static void inline mcka_iounmap(mcb_state_t *state, int reg_set_num, void *addr)
{
	of_iounmap(&state->op->resource[reg_set_num], addr,
			resource_size(&state->op->resource[reg_set_num]));
}

static inline unsigned long  mcka_dma_alloc_coherent(mcb_state_t *state, size_t size,
                                       dma_addr_t *dma_handle)
{
	return (unsigned long)dma_alloc_coherent(&state->op->dev, size, dma_handle, GFP_KERNEL);
}

static inline int mcka_dma_sync(mcb_state_t *state, dma_addr_t ba,
				 size_t size, int dir)
{
	dma_sync_single_for_cpu(&state->op->dev, ba, size, dir);

	return 0;
}

static inline void mcka_dma_free_coherent(mcb_state_t *state, size_t size,
				unsigned long cpu_addr, dma_addr_t dma_handle)
{
	dma_free_coherent(&state->op->dev, size, (void *)cpu_addr, dma_handle);
}


static void mcka_buf_trans_done(mcb_state_t *	state,
			       int		channel,
			/*     buf_t *		bp*/
			       uio_t * 		uio_p
			      );
static int put_drq_queue(/*struct buf *      bp*/ uio_t *uio_p,
                         mcb_state_t *     state
                        );
static int start_pending_transfer(mcb_state_t *     state,
                                  int               channel,
#ifdef	_MP_TIME_USE_
     			 	  u_int             intr_drq_received
#else
     				  hrtime_t          intr_drq_received
#endif	/* _MP_TIME_USE_ */
                                 );
static void remove_drq_queue(mcb_state_t *     state,
                             int               channel
                            );
static int handle_mp_timer_intr(mcb_state_t *     state,
#ifdef	_MP_TIME_USE_
     				u_int             intr_mp_time
#else
     				hrtime_t          intr_mp_time
#endif	/* _MP_TIME_USE_ */
     			       );
static int service_mp_timer_intr_request(mcb_state_t *  state,
     					 u_int          timer_interval,
#ifdef	_MP_TIME_USE_
     					 u_int	       	intr_receiving_time
#else
                                         hrtime_t       intr_receiving_time
#endif	/* _MP_TIME_USE_ */
     					);
static int service_mp_timer_intr(mcb_state_t *       state,
     				 mp_tm_intr_info_t * mp_timer_intr_info,
     				 u_int               request_interval,
#ifdef	_MP_TIME_USE_
     				 u_int	       	     request_receiving_time
#else
                                 hrtime_t   	     request_receiving_time
#endif	/* _MP_TIME_USE_ */
     				);
static void clean_mp_timer_intr_info(mp_tm_intr_info_t * mp_timer_intr_info);

void	remove_mp_timer_intr(mcb_state_t	*state);

static int get_channel_state (mcb_state_t * state,
                            int           channel,
                            trans_state_t transfer_state
                           );
static int start_mcka_dma_engine(mcb_state_t *     state,
                                int               channel
                               );

static	int	mcka_mmap(struct file *file, struct vm_area_struct *vma);

static  intr_reason_t get_intr_reason(mcb_state_t *	 state,
                                      sparc_drv_args_t * interrupt_args,
#ifdef	_MP_TIME_USE_
     				      u_int		 intr_receiving_time
#else
     				      hrtime_t		 intr_receiving_time
#endif	/* _MP_TIME_USE_ */
);

static	int	mcka_set_dma_trans_results(
	mcb_state_t *	state,
	int		channel,
	trans_buf_t *	trans_buf_p,
	trans_spec_t *	transfer_spec,
	size_t		moved_data_size
);

static void mcka_init_trans_results(trans_spec_t *	transfer_spec);

static	int	mcka_create_trans_header(
	mcb_state_t	*state,
	int		buf_byte_size,
	int		pseudobuf_flag,
	int		flags,
	trans_buf_t	*source_buf,
/*	buf_t		*bp, */
	uio_t		*uio_p,
	mcb_drv_buf_t	*drv_buf_p,
	trans_buf_t	**new_trans_buf_p
);
static	void	mcka_init_trans_header(
	mcb_state_t		*state,
	trans_buf_t		*trans_buf_p
);
static int mcka_create_drv_buf(mcb_state_t *	state,
			      uio_t *		uio_p,
			      int		op_flags,
			      trans_spec_t *	transfer_spec,
			      mcb_drv_buf_t **	new_trans_drv_buf_p
			     );
static void mcka_delete_drv_buf(mcb_state_t *	state,
			       mcb_drv_buf_t *	trans_drv_buf_p
			      );
static void mcka_connection_polling_intr(mcb_state_t *	state,
					int		connection_refused,
					hrtime_t	intr_receiving_time
				       );

static	void	write_all_general_regs(
	volatile mc_cntr_st_reg_t	*general_regs,
	mc_reg_type_t			write_regs_mask,
	mc_wr_reg_t			TLRM_write_value,
	mc_rd_reg_t			*benchmark_value,
	mc_wr_reg_t                     TRM_TRCWD_write_value
);
static int   compare_general_regs(volatile mc_cntr_st_reg_t *  general_regs,
                                  mc_reg_type_t                read_regs_mask, 
                                  mc_reg_type_t                cmp_regs_mask,
                                  mc_rd_reg_t                  benchmark_value
                                 );

/*
 * Soft state list pointer
 */

void			*mcka_state;

/*
 * Driver execution modes
 */

#ifndef	__KEEP_LAST_TRANS_RES__

static int   keep_last_trans_buf_mode = 0;
#else
static int   keep_last_trans_buf_mode = 1;

#endif /* __KEEP_LAST_TRANS_RES__ */

/*
 * Debug message control
 * Debug Levels:
 *	0 = no messages
 *	1 = Errors
 * Can be set with adb or in the /etc/system file with
 * "set state:me90drv_debug=<value>"
 * Defining DEBUG on the compile line (-DDEBUG) will enable debugging
 * statements in this driver, and will also enable the ASSERT statements.
 */

int	me90drv_log_msg_num = 0;

#ifdef DEBUG
int	me90drv_debug	= 3;
int	me90drv_max_log_msg_num	= 3200;
//int	me90drv_max_log_msg_num	= 32;
#else
int	me90drv_debug	= 2;
//int	me90drv_debug	= 0;
int	me90drv_max_log_msg_num	= 10;
#endif /* DEBUG */

static int mcka_instances;

#define DBGMCKADETAIL_MODE 0
#define dbgmckadetail	if(DBGMCKADETAIL_MODE)	printk

/*
 *  The driver modes and state info
 */

int	me90_sbus_clock_freq = 0;
int	me90_sbus_nsec_cycle = 0;
int	me90_mp_clock_freq   = 0;
int	me90_mp_nsec_cycle   = 0;

#ifdef DEBUG_BUF_USE

char	me90_debug_msg_buf[ME90_DEBUG_MSG_LINE_SIZE *
                                   ME90_DEBUG_MSG_LINE_NUM
                                  ];
#else
char	*me90_debug_msg_buf = NULL;

#endif /* DEBUG_BUF_USE */

int	me90_debug_buf_line = 0;
int	me90_debug_buf_overflow = 0;

/*
 * Log a message to the console and/or syslog with cmn_err
 */
/*ARGSUSED*/
void me90_log(mcb_state_t *state, int level, const char *fmt, ...)
{
	char	name[16];
	char	buf[1024];
	va_list	ap;
#ifdef DEBUG_BUF_USE
	int	cur_line = 0;
#endif /* DEBUG_BUF_USE */

	switch (level) {
	case CE_CONT:
	case CE_NOTE:
	case CE_WARN:
	case CE_PANIC:
		if ( state ) {
			(void) sprintf(name, "%s%d", MCKA_NAME, state->inst);
		} else {
			(void)sprintf(name, "mcka");
		}

		va_start(ap, fmt);
		(void) vsprintf(buf, fmt, ap);
		va_end(ap);

		printk(KERN_ALERT "%s:\t%s", name, buf);
		break;
//	case ME90_DL_REGS_OP:   if (me90drv_debug < 4) break; 
//	case ME90_DL_MINOR:     if (me90drv_debug < 4) break; 
	case ME90_DL_REGS_MAP:  if (me90drv_debug < 4) break;
		/*FALLTHROUGH*/
	case ME90_DL_TRACE:     if (me90drv_debug < 3) break;
		/*FALLTHROUGH*/
	case ME90_DL_WARNING:   if (me90drv_debug < 2) break;
		/*FALLTHROUGH*/
	case ME90_DL_ERROR:     if (me90drv_debug < 1) break;
	default:

		if (me90drv_log_msg_num > me90drv_max_log_msg_num)
			break;
		if (state) {
			(void) sprintf(name, "%s%d", MCKA_NAME, state->inst);
		} else {
			(void) sprintf(name, "mcka");
		}
		if (me90drv_log_msg_num < me90drv_max_log_msg_num) {
			va_start(ap, fmt);
			(void) vsprintf(buf, fmt, ap);
			va_end(ap);
		} else {
			(void) sprintf(buf, "too many errors masseges: driver"
					" turn on the silent mode\n");
		}

#ifdef DEBUG_BUF_USE
                cur_line = me90_debug_buf_line;
		me90_debug_buf_line ++;
                if (me90_debug_buf_line >= ME90_DEBUG_MSG_LINE_NUM)
                {
                   me90_debug_buf_line = 0;
                   me90_debug_buf_overflow = 1;
                };
                buf[ME90_DEBUG_MSG_LINE_SIZE - 1] = 0;
                sprintf(&me90_debug_msg_buf[cur_line * 
                                           ME90_DEBUG_MSG_LINE_SIZE
                                          ],
                        "%s:\t%s",
                        name, buf
                       );
#else
		printk(KERN_ERR "^%s:\t%s", name, buf);
		me90drv_log_msg_num ++;

#if	defined(DEBUG) || defined(__KMMEM_ALLOC_DEBUG__)
// Sol ticks	delay(1 * drv_usectohz(10000));
/* Lin mksec */	udelay(1 * 10000);
#endif	/* DEBUG  or __KMMEM_ALLOC_DEBUG__ */

#endif /* DEBUG_BUF_USE */
		break;
	}
}

/*
 * Wait for finish of an asynchronous I/O transfer
 */

/*ARGSUSED*/
int
me90_wait_async_trans(
	mcb_state_t		*state,
	int			channel,
	int			waiting_time,
	me90drv_trans_buf_t	**trans_buf_pp)
{
	me90drv_chnl_state_t	*channel_state = NULL;
	u_long			cur_clock_ticks = 0;
	u_long			timeout_clock_ticks = 0;
	int			rval = 0;

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_wait_async_trans started for channel %d\n", channel);
	channel_state = &state -> all_channels_state[channel];
		mutex_enter(&state->mutex);		/* start MUTEX */
	if (channel_state -> async_trans_num <= 0) {
		mutex_exit(&state->mutex);	/* end MUTEX */
		ME90_LOG(state, ME90_DL_ERROR,
			"mcka_wait_async_trans there are no outstanding"
			" asynchronous requests for channel %d\n", channel);
		return EINVAL;
	}
	if (waiting_time > 0) {
		drv_getparm(LBOLT,&cur_clock_ticks);
		timeout_clock_ticks = cur_clock_ticks +
					drv_usectohz(waiting_time);
	}
	while (channel_state -> ready_atrans_start == NULL) {
		if (waiting_time > 0) {
			rval = cv_timedwait(&state -> atrans_end_cv,
					&state->mutex, timeout_clock_ticks);
		/*	rval = cv_spin_timedwait(&state -> atrans_end_cv,
					&state->lock, timeout_clock_ticks);*/
		} else if (waiting_time == 0) {
			rval = ETIME;
			break;
		} else
			rval = cv_wait(&state -> atrans_end_cv,
					&state->mutex);
		if (rval < 0) {
			rval = ETIME;
			break;
		} else if (rval == 0) {
			rval = EINTR;
			break;
		} else {
			rval = 0;
		}
	}
	if (rval != 0 || channel_state -> ready_atrans_start == NULL) {
			mutex_exit(&state->mutex);	/* end MUTEX */
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_wait_async_trans waiting finished inefficiently"
			" for channel %d\n", channel);
		return rval;
	}
	*trans_buf_pp = channel_state -> ready_atrans_start;
	channel_state -> ready_atrans_start =
		channel_state -> ready_atrans_start -> next_trans_buf;
	if (channel_state -> ready_atrans_start == NULL)
		channel_state -> ready_atrans_end = NULL;
	channel_state -> ready_atrans_size --;
	channel_state -> async_trans_num --;
		mutex_exit(&state->mutex);		/* end MUTEX */
#ifdef	__BLOCK_BUFFER_USE__
	if ((*trans_buf_pp) -> trans_buf_desc.drv_buf_used)
#endif	/* __BLOCK_BUFFER_USE__ */
		me90drv_finish_drv_buf_trans(state, channel, *trans_buf_pp);
		
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_wait_async_trans succeeded for channel %d\n", channel);
	return 0;
}

/*
 * Driver mmap entry point
 */
/*ARGSUSED*/
int
mcka_mmap(struct file *file, struct vm_area_struct *vma)
{
	mcb_state_t	*state = (mcb_state_t *)file->private_data;
	dev_t		dev = state->dev;
	int			instance = state->inst;
	int			channel;

	caddr_t		mapped_reg_set_p = NULL;
	off_t		reg_set_offset   = 0;
	unsigned long off = (long )(vma->vm_pgoff << PAGE_SHIFT);

	size_t		reg_set_len;

	ME90_LOG(NULL, ME90_DL_TRACE, "%s(): started\n", __func__);

	instance = MCB_INST(dev);
	channel = MCB_CHAN(dev);

	if ( state == NULL ) {
		printk("~%s~_mmap: unattached instance %d\n", mod_name, instance);
		return (ENXIO);
	}

#ifdef DEBUG
	ME90_LOG(NULL, ME90_DL_REGS_MAP,
			"%s(): instance %d channel %d started with off 0x%x\n", __func__, 
			instance, channel,
			off
			);
#endif /* DEBUG */

	if ( off >= MC_EPROM_REG_SET_OFFSET && 
			(off < MC_EPROM_REG_SET_OFFSET + MC_EPROM_REG_SET_LEN) ) {
		ME90_LOG(state, ME90_DL_REGS_MAP, "%s(): register set is EPROM\n", __func__);

		if ( state->MC_EPROM_CADDR != NULL ) { 	/* With eprom */
			reg_set_offset = off - MC_EPROM_REG_SET_OFFSET;
			reg_set_len = MC_EPROM_REG_SET_LEN;

			vma->vm_flags |= (VM_IO | VM_LOCKED | VM_READ | VM_WRITE );

			if ( mcka_io_remap_page(state, 0, reg_set_offset, reg_set_len, vma) ) {
				printk ("Error map range array\n");
				return -EAGAIN;
			}
		} else {				/* Without eprom */
			ME90_LOG(state, ME90_DL_ERROR,
				"%s(): invalid register set off 0x%x\n", __func__, 
				off
				);

			return -1;
	    }
	} else if ( off >= MC_CNTR_ST_REG_SET_OFFSET && off < MC_CNTR_ST_REG_SET_OFFSET + MC_CNTR_ST_REG_SET_LEN ) {
		ME90_LOG(state, ME90_DL_REGS_MAP,
				"%s(): register set is GEN REGS\n", __func__
				);

		reg_set_offset = off - MC_CNTR_ST_REG_SET_OFFSET;
		reg_set_len = MC_CNTR_ST_REG_SET_LEN;

		vma->vm_flags |= (VM_IO | VM_LOCKED | VM_READ | VM_WRITE );

		if ( state->MC_EPROM_CADDR != NULL ) { 	/* With eprom */
			if ( mcka_io_remap_page(state, 1, reg_set_offset, reg_set_len, vma)) {
				printk ("Error map range array \n");
				return -EAGAIN;
			}
	    } else {				/* Without eprom */
			if ( mcka_io_remap_page(state, 0, reg_set_offset, reg_set_len, vma) ) {
				printk ("Error map range array\n");
				return -EAGAIN;
			}
		}
	} else if ( off >= MC_BMEM_REG_SET_OFFSET && off < MC_BMEM_REG_SET_OFFSET + MC_BMEM_REG_SET_LEN ) {
		ME90_LOG(state, ME90_DL_REGS_MAP, "%s(): register set is BMEM\n", __func__);

		reg_set_offset = off - MC_BMEM_REG_SET_OFFSET;
		reg_set_len = MC_BMEM_REG_SET_LEN;

		vma->vm_flags |= (VM_IO | VM_LOCKED | VM_READ | VM_WRITE );

		if ( state->MC_EPROM_CADDR != NULL ) { 	/* With eprom */
			if ( mcka_io_remap_page(state, 2, reg_set_offset, reg_set_len, vma) ) {
				printk("Error map range array\n");
    			return -EAGAIN;
			}
	    } else {				/* Without eprom */
			if ( mcka_io_remap_page(state, 1, reg_set_offset, reg_set_len, vma) ) {
				printk("Error map range array\n");
				return -EAGAIN;
			}
		}
	} else {
		ME90_LOG(state, ME90_DL_ERROR,
				"%s(): invalid register set off 0x%x\n", __func__, 
				off
				);

		return -1;
	}

#ifdef DEBUG 
	printk("%s(): succeeded\n", __func__);
#endif

	ME90_LOG(state, ME90_DL_REGS_MAP,
			"%s(): successed for 0x%x + 0x%x\n", __func__, 
			mapped_reg_set_p,reg_set_offset
			);

	return 0;
}

/*
 * Rotate bytes of the word (big and litle endian compatibility)
 */
/*ARGSUSED*/
u_int	mcka_rotate_word_bytes(u_int	source_word)
{
     u_int     new_word = 0;
     u_char *   new_word_p = (u_char *) &new_word;
     u_char *   source_word_p = (u_char *) &source_word;
     int        cur_byte = 0;

     for (cur_byte = 0; cur_byte < sizeof(u_int); cur_byte ++)
     {
        new_word_p[(sizeof(u_int)-1) - cur_byte] = source_word_p[cur_byte];
     }
     return new_word;
}

/*
 * Read general registers state
 */
/*ARGSUSED*/
void
read_general_regs(
	volatile mc_cntr_st_reg_t	*general_regs,
	mc_reg_type_t			read_regs_mask, 
	mc_rd_reg_t			*read_value)
{

    ME90_LOG(NULL, ME90_DL_TRACE,"read_general_regs started\n");

   if (read_regs_mask & TI_mc_reg_type)
   {
      read_value -> RGEN_read = general_regs -> MC_TI_read;
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Read GEN REGS: address %lx value %08x\n",
              &general_regs -> MC_TI_read,
              read_value -> RGEN_read
             );
   }
   else if (read_regs_mask & TMI_mc_reg_type)
   {
      read_value -> RGEN_read = general_regs -> MC_TMI_read;
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Read GEN REGS: address %lx value %08x\n",
              &general_regs -> MC_TMI_read,
              read_value -> RGEN_read
             );
   }
   else if (read_regs_mask & TRM_mc_reg_type)
   {
      read_value -> RGEN_read = general_regs -> MC_TRM_read;
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Read GEN REGS: address %lx value %08x\n",
              &general_regs -> MC_TRM_read,
              read_value -> RGEN_read
             );
   }
   else if (read_regs_mask & TRCWD_mc_reg_type)
   {
      ME90_LOG(NULL, ME90_DL_ERROR,
              "Read write only TRCWD general registers\n"
             );
   }
   else if (read_regs_mask & TLRM_mc_reg_type)
   {
      read_value -> RGEN_read = general_regs -> MC_TLRM_read;
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Read GEN REGS: address %lx value %08x\n",
              &general_regs -> MC_TLRM_read,
              read_value -> RGEN_read
             );
   }
   else if (read_regs_mask & TISB_mc_reg_type)
   {
      read_value -> RGEN_read = general_regs -> MC_TISB_read;
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Read GEN REGS: address %lx value %08x\n",
              &general_regs -> MC_TISB_read,
              read_value -> RGEN_read
             );
   }
   else if (read_regs_mask & TSB_mc_reg_type)
   {
      read_value -> RGEN_read = general_regs -> MC_TSB_read;
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Read GEN REGS: address %lx value %08x\n",
              &general_regs -> MC_TSB_read,
              read_value -> RGEN_read
             );
   }
   else if (read_regs_mask & TPSB_mc_reg_type)
   {
      read_value -> RGEN_read = general_regs -> MC_TPSB_read;
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Read GEN REGS: address %lx value %08x\n",
              &general_regs -> MC_TPSB_read,
              read_value -> RGEN_read
             );
   }
   else if (read_regs_mask & RTM_mc_reg_type)
   {
      read_value -> RGEN_read = general_regs -> MC_RTM_read;
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Read GEN REGS: address %lx value %08x\n",
              &general_regs -> MC_RTM_read,
              read_value -> RGEN_read
             );
   }
   else if ((read_regs_mask & RERR_mc_reg_type)   ||
            (read_regs_mask & RNC_mc_reg_type)
           )
   {
      read_value -> RGEN_read = general_regs -> MC_RERR_RNC_read;
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Read GEN REGS: address %lx value %08x\n",
              &general_regs -> MC_RERR_RNC_read,
              read_value -> RGEN_read
             );
   }
   else
   {
      read_value -> RGEN_read = general_regs -> MC_RGENS_read;
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Read GEN REGS: address %x value %08x\n",
              &general_regs -> MC_RGENS_read,
              read_value -> RGEN_read
             );
   }
   ME90_LOG(NULL, ME90_DL_TRACE,"read_general_regs successed\n");
}

/*
 * Write general registers
 */
/*ARGSUSED*/
void
write_general_regs(
	volatile mc_cntr_st_reg_t	*general_regs,
	mc_reg_type_t			write_regs_mask,
	mc_wr_reg_t			TLRM_write_value,
	mc_rd_reg_t			*benchmark_value)
{
	write_all_general_regs(general_regs, write_regs_mask, TLRM_write_value,
		benchmark_value, TLRM_write_value);
}

/*
 * Write general registers
 */
/*ARGSUSED*/
static	void
write_all_general_regs(
	volatile mc_cntr_st_reg_t	*general_regs,
	mc_reg_type_t			write_regs_mask,
	mc_wr_reg_t			TLRM_write_value,
	mc_rd_reg_t			*benchmark_value,
	mc_wr_reg_t                     TRM_TRCWD_write_value)
{

   ME90_LOG(NULL, ME90_DL_TRACE,"write_all_general_regs started\n");

   if (write_regs_mask == 0)
   {
      ME90_LOG(NULL, ME90_DL_ERROR,
              "write_all_general_regs: empty mask of general registers "
		"to write\n");
      return;
   };
   if (write_regs_mask & TGRM_mc_reg_type)
   {
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Write TGRM (general reset)\n");
      general_regs -> MC_TGRM_write = 0;
      benchmark_value -> TI_read = 0;
      benchmark_value -> TMI_read = 0;
      benchmark_value -> TRM_read = 1;
      benchmark_value -> TLRM_read = 1;
      benchmark_value -> TISB_read = 0;
      benchmark_value -> TSB_read = 0;
      benchmark_value -> TPSB_read = 0;
      benchmark_value -> RNC_read = 0;
   };
   if ((write_regs_mask & TRM_mc_reg_type)   ||
       (write_regs_mask & TRCWD_mc_reg_type)
      )
   {
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Write TRM %x and TRCWD %x\n",
              TRM_TRCWD_write_value.TRM_write,
              TRM_TRCWD_write_value.TRCWD_write
             );
      general_regs -> MC_TRM_TRCWD_write = TRM_TRCWD_write_value.RGEN_write;
      benchmark_value -> TRM_read = TRM_TRCWD_write_value.TRM_write;
   };
   if (write_regs_mask & TI_mc_reg_type)
   {
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Write TI, address: %lx, value %x\n",
	      &general_regs -> MC_TI_write,
              TLRM_write_value.TI_write
             );
      general_regs -> MC_TI_write = TLRM_write_value.RGEN_write;
      benchmark_value -> TI_read = TLRM_write_value.TI_write;
   };
   if (write_regs_mask & TMI_mc_reg_type)
   {
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Write TMI, address: %lx, value %x\n",
              &general_regs -> MC_TMI_write,
              TLRM_write_value.TMI_write
             );
      general_regs -> MC_TMI_write = TLRM_write_value.RGEN_write;
      benchmark_value -> TMI_read = TLRM_write_value.TMI_write;
   };
   if (write_regs_mask & TLRM_mc_reg_type)
   {
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Write TLRM, address: %lx, value %x\n",
              &general_regs -> MC_TLRM_write,
              TLRM_write_value.TLRM_write
             );
      general_regs -> MC_TLRM_write = TLRM_write_value.RGEN_write;
      benchmark_value -> TLRM_read = TLRM_write_value.TLRM_write;
   };
   if (write_regs_mask & TISB_mc_reg_type)
   {
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Write TISB, address: %lx, value %x\n",
              &general_regs -> MC_TISB_write,
              TLRM_write_value.TISB_write
             );
      general_regs -> MC_TISB_write = TLRM_write_value.RGEN_write;
      benchmark_value -> TISB_read = TLRM_write_value.TISB_write;
   };
   if (write_regs_mask & TSB_mc_reg_type)
   {
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Write TSB, address: %lx, value %x\n",
              &general_regs -> MC_TSB_write,
              TLRM_write_value.TSB_write
             );
      general_regs -> MC_TSB_write = TLRM_write_value.RGEN_write;
      benchmark_value -> TSB_read = TLRM_write_value.TSB_write;
   };
   if (write_regs_mask & TPSB_mc_reg_type)
   {
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Write TPSB %x\n",
              TLRM_write_value.TPSB_write
             );
      general_regs -> MC_TPSB_write = TLRM_write_value.RGEN_write;
      benchmark_value -> TPSB_read = TLRM_write_value.TPSB_write;
   };
   if (write_regs_mask & RTM_mc_reg_type)
   {
      ME90_LOG(NULL, ME90_DL_ERROR,"Write read only RTM general registers\n");
   };
   if ((write_regs_mask & RERR_mc_reg_type)   ||
       (write_regs_mask & RNC_mc_reg_type)
      )
   {
      ME90_LOG(NULL, ME90_DL_REGS_OP,"Write RERR %x and RNC %x\n",
              TLRM_write_value.RERR_write,
              TLRM_write_value.RNC_write
             );
      general_regs -> MC_RERR_RNC_write = TLRM_write_value.RGEN_write;
      benchmark_value -> RERR_read = TLRM_write_value.RERR_write;
      benchmark_value -> RNC_read = TLRM_write_value.RNC_write;
   };
   if (benchmark_value -> TRM_read == 1)
   {
      benchmark_value -> TI_read = 0;
      benchmark_value -> TMI_read = 0;
      benchmark_value -> TISB_read = 0;
      benchmark_value -> TSB_read = 0;
      benchmark_value -> TPSB_read = 0;
   };

   ME90_LOG(NULL, ME90_DL_TRACE,"write_all_general_regs finished\n");

}

/*
 * Delete connection polling mode only for the SPRAC driver,
 * mutex_enter must be done by caller
 */

/*ARGSUSED*/
void
mcb_delete_connection_polling(
	mcb_state_t	*state,
	int		reset_error)
{
     ME90_LOG(state, ME90_DL_TRACE,"mcka_delete_connection_polling started \n");

     if (!(state -> connection_state & MODE_ON_CONNECTION_STATE)  ||
         (state -> connection_state & MODE_OFF_CONNECTION_STATE)
        )
     {
        ME90_LOG(state, ME90_DL_TRACE,
                "mcka_delete_connection_polling polling mode is not set\n"
               );
     }
     state -> connection_state &= ~MODE_ON_CONNECTION_STATE;
     state -> connection_state |= MODE_OFF_CONNECTION_STATE;
     state -> cnct_polling_error = reset_error;
     cv_broadcast(&state -> cnct_polling_cv);
     ME90_LOG(state, ME90_DL_TRACE,"mcka_delete_connection_polling successed \n");
     return;
}

/*
 * Compare general registers state with benchmark value
 */
/*ARGSUSED*/
static int   compare_general_regs(
   volatile mc_cntr_st_reg_t *  general_regs,
   mc_reg_type_t                read_regs_mask, 
   mc_reg_type_t                cmp_regs_mask,
   mc_rd_reg_t                  benchmark_value
                                 )
{

   int         errors_num = 0;
   mc_rd_reg_t read_value;
   mc_rd_reg_t cmp_value_mask;

   ME90_LOG(NULL, ME90_DL_TRACE,"compare_general_regs started\n");

   if (cmp_regs_mask == 0)
   {
      ME90_LOG(NULL, ME90_DL_ERROR,
              "compare_general_regs: empty mask of general registers\n"
             );
      return errors_num;
   };

ME90_LOG(NULL, ME90_DL_TRACE,"FIRST READ\n");
   read_value.RGEN_read = 0;
   read_general_regs(general_regs,read_regs_mask,&read_value);

   cmp_value_mask.RGEN_read = 0;
   if (cmp_regs_mask & TI_mc_reg_type)
      cmp_value_mask.TI_read = ~0;
   if (cmp_regs_mask & TMI_mc_reg_type)
      cmp_value_mask.TMI_read = ~0;
   if (cmp_regs_mask & TRM_mc_reg_type)
      cmp_value_mask.TRM_read = ~0;
   if (cmp_regs_mask & TRCWD_mc_reg_type)
   {
      ME90_LOG(NULL, ME90_DL_ERROR,
              "compare_general_regs write only TRCWD general registers\n"
             );
   };
   if (cmp_regs_mask & TLRM_mc_reg_type)
      cmp_value_mask.TLRM_read = ~0;
   if (cmp_regs_mask & TISB_mc_reg_type)
      cmp_value_mask.TISB_read = ~0;
   if (cmp_regs_mask & TSB_mc_reg_type)
      cmp_value_mask.TSB_read = ~0;
   if (cmp_regs_mask & TPSB_mc_reg_type)
      cmp_value_mask.TPSB_read = ~0;
   if (cmp_regs_mask & RTM_mc_reg_type)
      cmp_value_mask.RTM_read = ~0;
   if (cmp_regs_mask & RERR_mc_reg_type)
      cmp_value_mask.RERR_read = ~0;
   if (cmp_regs_mask & RNC_mc_reg_type)
      cmp_value_mask.RNC_read = ~0;
   if ((read_value.RGEN_read      & cmp_value_mask.RGEN_read)  !=
       (benchmark_value.RGEN_read & cmp_value_mask.RGEN_read)
      )
   {
      ME90_LOG(NULL, ME90_DL_ERROR,
              "different general regs state 0x%08x and benchmarck 0x%08x"
              " mask 0x%08x\n",
              read_value.RGEN_read,
              benchmark_value.RGEN_read,
              cmp_value_mask.RGEN_read
             );
      errors_num ++;
   };
   ME90_LOG(NULL, ME90_DL_TRACE,"compare_general_regs finished with %d error\n",
           errors_num
          );

   return errors_num;
}

/*
 * Reset general registers and MicroProcessor
 */
/*ARGSUSED*/
int
reset_general_regs(
	mcb_state_t	*state,
	int		mp_state)
{
   mc_wr_reg_t    intr_reset_value;
   mc_wr_reg_t    pre_stop_mp_value;
   mc_wr_reg_t    pre_trcwd_stop_mp_value;
   mc_wr_reg_t    stop_mp_value;
   mc_wr_reg_t    trcwd_stop_mp_value;
   mc_wr_reg_t    startup_mp_value;
   mc_wr_reg_t    trcwd_startup_mp_value;
   mc_wr_reg_t    post_startup_mp_value;
   mc_wr_reg_t    post_trcwd_startup_mp_value;
   mc_rd_reg_t    benchmark_value;
   int            errors_num = 0;

   ME90_LOG(state, ME90_DL_TRACE, "reset_general_regs started MP %s\n",
	   (mp_state == 1) ? "HALTED" :
	   (mp_state == 2) ? "LOCKED" : "STARTED");

   state -> mp_state = undef_mp_state;
   benchmark_value.RGEN_read = 0;
#ifndef WITHOUT_TWISTING
   b2l_convertor_off(state->dip);
#endif
   read_general_regs(state -> MC_CNTR_ST_REGS,TI_mc_reg_type,&benchmark_value);
#ifndef WITHOUT_TWISTING
   b2l_convertor_on(state->dip);
#endif
// benchmark_value.RTM_read = get_state_module_type(state -> type_unit);
   benchmark_value.RTM_read = mcka_rtm_encode;

   intr_reset_value.RGEN_write = 0;
#ifndef WITHOUT_TWISTING
   b2l_convertor_off(state->dip);
#endif
   write_general_regs(state -> MC_CNTR_ST_REGS,  /* interrupt reset */
                      TISB_mc_reg_type | RERR_mc_reg_type,
                      intr_reset_value,
                      &benchmark_value
                     );
#ifndef WITHOUT_TWISTING
   b2l_convertor_on(state->dip);
#endif
   if (state -> connection_state & MODE_ON_CONNECTION_STATE)
   {
      ME90_LOG(state, ME90_DL_ERROR,
              "reset_general_regs : connection polling mode is set\n"
             );
      me90drv_delete_connection_polling(state, EINVAL);
   }
   pre_stop_mp_value.RGEN_write = 0;
   pre_stop_mp_value.TLRM_write = 1;
   pre_trcwd_stop_mp_value.RGEN_write = 0;
#ifndef WITHOUT_TWISTING
   b2l_convertor_off(state->dip);
#endif
   write_all_general_regs(state -> MC_CNTR_ST_REGS, /* set error lock mode */
                      TLRM_mc_reg_type,
                      pre_stop_mp_value,
                      &benchmark_value,
                      pre_trcwd_stop_mp_value
                     );
   errors_num += compare_general_regs(state -> MC_CNTR_ST_REGS,
                                      TI_mc_reg_type,
                                      all_readable_mc_reg_type,
                                      benchmark_value
                                     );
#ifndef WITHOUT_TWISTING
   b2l_convertor_on(state->dip);
#endif
   stop_mp_value.RGEN_write = 0;
   trcwd_stop_mp_value.RGEN_write = 0;
   trcwd_stop_mp_value.TRM_write = 1;
   trcwd_stop_mp_value.TRCWD_write = 1;
#ifndef WITHOUT_TWISTING
   b2l_convertor_off(state->dip);
#endif
   write_all_general_regs(state -> MC_CNTR_ST_REGS,     /* lock MP and module */
                      TRM_mc_reg_type | TRCWD_mc_reg_type,
                      stop_mp_value,
                      &benchmark_value,
                      trcwd_stop_mp_value
                     );
   errors_num += compare_general_regs(state -> MC_CNTR_ST_REGS,
                                      TI_mc_reg_type,
                                      all_readable_mc_reg_type,
                                      benchmark_value
                                     );
#ifndef WITHOUT_TWISTING
   b2l_convertor_on(state->dip);
#endif
   if (mp_state != 2)
   {
      if (mp_state == 1)
      {
         mp_init_area_t *mp_init_area =
            (mp_init_area_t *) &state -> MC_BMEM[MC_MP_INIT_AREA_BMEM_ADDR];
         mp_init_area -> MP_INIT_AREA_u_long[0] = mcka_rotate_word_bytes(MP_HALT_OPCODE);
      };

      startup_mp_value.RGEN_write = 0;
      trcwd_startup_mp_value.RGEN_write = 0;
      trcwd_startup_mp_value.TRM_write = 0;
      trcwd_startup_mp_value.TRCWD_write = 0;
#ifndef WITHOUT_TWISTING
      b2l_convertor_off(state->dip);
#endif
      write_all_general_regs(state -> MC_CNTR_ST_REGS,/* start up MP and module */
                         TRM_mc_reg_type | TRCWD_mc_reg_type,
                         startup_mp_value,
                         &benchmark_value,
                         trcwd_startup_mp_value
                        );
      errors_num += compare_general_regs(state -> MC_CNTR_ST_REGS,
                                         TI_mc_reg_type,
                                         all_readable_mc_reg_type,
                                         benchmark_value
                                        );
#ifndef WITHOUT_TWISTING
      b2l_convertor_on(state->dip);
#endif
      post_startup_mp_value.RGEN_write = 0;
      post_startup_mp_value.TLRM_write = state -> set_tlrm;
      post_trcwd_startup_mp_value.RGEN_write = 0;
#ifndef WITHOUT_TWISTING
      b2l_convertor_off(state->dip);
#endif
      write_all_general_regs(state -> MC_CNTR_ST_REGS,/* set initial regs state */
                         all_writable_mc_reg_type,
                         post_startup_mp_value,
                         &benchmark_value,
                         post_trcwd_startup_mp_value
                        );
      errors_num = compare_general_regs(state -> MC_CNTR_ST_REGS,
                                        TI_mc_reg_type,
                                        all_readable_mc_reg_type,
                                        benchmark_value
                                       );
#ifndef WITHOUT_TWISTING
      b2l_convertor_on(state->dip);
#endif
   };
   if (mp_state == 1) { 		
      state -> mp_state = halted_mp_state;
   }
   else if (mp_state == 2)
      state -> mp_state = locked_mp_state;

   if (errors_num > 0)
     {
	     ME90_LOG(state, ME90_DL_ERROR, "reset_general_regs finished with errors\n");
     }
   else
     {
	     ME90_LOG(state, ME90_DL_TRACE, "reset_general_regs succeeded \n");
     }

   return errors_num;
}

/*
 * Create and allocate the transfer buffers
 */

/*ARGSUSED*/
int
mcka_alloc_trans_bufs(
	mcb_state_t		*state,
	me90drv_trbuf_desc_t	*new_trans_buf,
	int			buf_byte_size,
	int			flags)
{
	int reqlen;
#ifdef DEBUG
	printk("mcka_alloc_trans_bufs started with buffer byte size %d\n",
		buf_byte_size);
#endif

/* О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫ ME90_ENABLE_BURST_SIZES */
/*	reqlen = ((buf_byte_size + (ME90_ENABLE_BURST_SIZES - 1)) / 
			ME90_ENABLE_BURST_SIZES) * ME90_ENABLE_BURST_SIZES; */
	reqlen = ((buf_byte_size + (DMA_MAX_BURST_SIZE_BYTES - 1)) / 
			DMA_MAX_BURST_SIZE_BYTES) * DMA_MAX_BURST_SIZE_BYTES;
	new_trans_buf->dma.dma = mcka_dma_alloc_coherent(state, reqlen,
			 &new_trans_buf->dma.prim_dev_mem );
	if ( new_trans_buf->dma.dma == 0) {
		printk ("Cannot get free pages\n");
		return -1;
	}

	new_trans_buf->dma.real_size = reqlen;
	new_trans_buf->buf_address = (caddr_t)new_trans_buf->dma.dma;
	new_trans_buf->buf_size = reqlen;
	dbgmcka("%s(): new_trans_buf -> buf_address = 0x%lx, "
		"new_trans_buf -> buf_size = 0x%lx\n", __func__, 
		(u_long)new_trans_buf->buf_address, 
		(u_long)new_trans_buf->buf_size);

#ifdef DEBUG
	printk("%s(): succeeded for buf 0x%lx with buffer"
		"byte size %d\n", __func__, (unsigned long)new_trans_buf, buf_byte_size);
#endif

	return 0;
}

/*
 * Create any I/O operation transfer buffer header structure
 */

/*ARGSUSED*/
static	int
mcka_create_trans_header(
	mcb_state_t	*state,
	int		buf_byte_size,
	int		pseudobuf_flag,
	int		flags,
	trans_buf_t	*source_buf,
/*	buf_t		*bp,*/
	uio_t		*uio_p,
	mcb_drv_buf_t	*drv_buf_p,
	trans_buf_t	**new_trans_buf_p)
{
	trans_buf_t *      new_trans_buf = NULL;
	int                rval = 0;

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_create_trans_header started with buffer byte size %d\n",
		buf_byte_size);
	new_trans_buf = kmem_alloc(sizeof(trans_buf_t),KM_NOSLEEP);
	if (new_trans_buf == NULL) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mcka_create_trans_header cannot allocate kernel"
			" memory\n");
		return EINVAL;
	}
	new_trans_buf -> next_trans_buf = NULL;
	new_trans_buf -> trans_size = buf_byte_size;
	if (source_buf != NULL) {
		new_trans_buf -> trans_buf_desc.only_link = 1;
		new_trans_buf -> trans_buf_desc.drv_buf_used =
				source_buf -> trans_buf_desc.drv_buf_used;
		new_trans_buf -> trans_buf_desc.uio_p =
				source_buf -> trans_buf_desc.uio_p;
		new_trans_buf -> trans_buf_desc.buf_address =
				source_buf -> trans_buf_desc.buf_address;
		new_trans_buf -> trans_buf_desc.buf_size =
				source_buf -> trans_buf_desc.buf_size;
	/*	new_trans_buf -> trans_buf_desc.acc_handle =
				source_buf -> trans_buf_desc.acc_handle;
		new_trans_buf -> trans_buf_desc.dma_handle =
				source_buf -> trans_buf_desc.dma_handle;
		new_trans_buf -> trans_buf_desc.cookie =
				source_buf -> trans_buf_desc.cookie;*/
		new_trans_buf -> trans_buf_desc.dma =
				source_buf -> trans_buf_desc.dma;
		new_trans_buf -> trans_buf_desc.ccount =
				source_buf -> trans_buf_desc.ccount;
		new_trans_buf -> pseudobuf = source_buf -> pseudobuf;
		new_trans_buf -> batch_flag = source_buf -> batch_flag;
		new_trans_buf -> multi_buf_flag = source_buf -> multi_buf_flag;
		new_trans_buf -> drv_buf_p = source_buf -> drv_buf_p;
		mcka_init_trans_header(state, new_trans_buf);
		*new_trans_buf_p = new_trans_buf;
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_create_trans_header successed with only link of"
			" buffer\n");
		return 0;
	}
	dbgmcka("mcka_create_trans_header: buf_byte_size (bytes) = 0x%x\n", buf_byte_size);
	new_trans_buf -> trans_buf_desc.only_link = 0;
	new_trans_buf -> trans_buf_desc.drv_buf_used = (uio_p == NULL);
	new_trans_buf -> trans_buf_desc.uio_p = uio_p;
	new_trans_buf -> pseudobuf = pseudobuf_flag;
	new_trans_buf -> batch_flag = 0;
	new_trans_buf -> multi_buf_flag = 0;
	new_trans_buf -> drv_buf_p = drv_buf_p;
	rval = mcka_alloc_trans_bufs(state, &new_trans_buf -> trans_buf_desc,
			buf_byte_size, flags);
	if (rval != 0) {
		kmem_free(new_trans_buf, sizeof(trans_buf_t));
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_create_trans_header failed with buffer byte "
			"size %d\n", buf_byte_size);
		return rval;
	}
	mcka_init_trans_header(state, new_trans_buf);
	*new_trans_buf_p = new_trans_buf;
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_create_trans_header successed with buffer byte size %d\n",
		buf_byte_size);
	return 0;
}

/*
 * Set error for the DMA data transfer on private driver buffer 
 */

/*ARGSUSED*/
void
mcka_drv_buf_io_error(
	me90drv_trans_buf_t	*trans_buf_p,
	int			error_code)
{
	ME90_LOG(NULL, ME90_DL_TRACE,
		"mcka_drv_buf_io_error started for trans_buf 0x%lx and "
		"error %d\n", trans_buf_p, error_code);

#ifdef	__BLOCK_BUFFER_USE__
	if (!trans_buf_p -> trans_buf_desc.drv_buf_used ||
		trans_buf_p -> drv_buf_p == NULL) {
		ME90_LOG(NULL, ME90_DL_TRACE,
			"mcka_drv_buf_io_error the transfer has not private"
			" buffer\n");
		return;
	}
#endif	/* __BLOCK_BUFFER_USE__ */
	trans_buf_p -> trans_error = error_code;

	ME90_LOG(NULL, ME90_DL_TRACE,
		"mcka_drv_buf_io_error succeeded for trans_buf 0x%lx and"
		" error %d\n", trans_buf_p, error_code);
}

/*
 * Notify blocked processes waiting for the I/O DMA data transfer on private
 * driver buffer to complete
 */

/*ARGSUSED*/
void mcka_drv_buf_io_done(
	mcb_state_t		*state,
	me90drv_trans_buf_t	*trans_buf_p,
	int			withot_mutex_enter)
{
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_drv_buf_io_done started for trans_buf 0x%lx\n",
		trans_buf_p);

#ifdef	__BLOCK_BUFFER_USE__
	if (!trans_buf_p -> trans_buf_desc.drv_buf_used ||
		trans_buf_p -> drv_buf_p == NULL) {
		ME90_LOG(NULL, ME90_DL_TRACE,
			"mcka_drv_buf_io_done the transfer has not private"
			" buffer\n");
		return;
	}
#endif	/* __BLOCK_BUFFER_USE__ */
	if (!withot_mutex_enter)
	{
	mutex_enter(&state->mutex);		/* start MUTEX */
	}
#ifdef	__BLOCK_BUFFER_USE__
	trans_buf_p -> drv_buf_p -> trans_completed = 1;
	cv_broadcast(&trans_buf_p -> drv_buf_p -> trans_finish_cv);
#else
	trans_buf_p -> trans_completed = 1;
	cv_broadcast(&trans_buf_p -> trans_finish_cv);
#endif	/* __BLOCK_BUFFER_USE__ */
	if (!withot_mutex_enter)
	{
	mutex_exit(&state->mutex);		/* end MUTEX */
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_drv_buf_io_done succeeded for trans_buf 0x%lx\n",
		trans_buf_p);
}

/*
 * Finish the DMA data transfer endgine. Check the device's state registers
 * to determine if the trabsfer completed without error. If an error occured
 * buf falgs and accordingly buf counters seted
 */

/*ARGSUSED*/
void
finish_mcb_dma_engine(
	mcb_state_t	*state,
	int		channel,
	trans_buf_t	*trans_buf_p,
	int		mutex_locked
	/*int		flags*/)
{
 /*  buf_t* 		bp = NULL;*/
	uio_t			*uio_p = NULL;
	mcb_drv_buf_t	*drv_buf_p = NULL;
	trans_spec_t	*transfer_spec = NULL;
	int				write_op_flag = 0;
	u_int			transfer_size = 0;
	u_int			trans_resid = 0;
	u_int			source_size = 0;
	int				bad_trans_size = 0;
	mc_rd_reg_t		board_state;
	int				miss_data_error = 0;
	int				sync_rval = 0;

	ME90_LOG(state, ME90_DL_TRACE, "%s(): started for channel %d\n", __func__, channel);

	source_size = trans_buf_p -> trans_size;

	if ( !trans_buf_p -> trans_buf_desc.drv_buf_used ) {
/*      bp = trans_buf_p ->trans_buf_desc. bp;
        transfer_spec = bp -> b_private;
        write_op_flag = bp -> b_flags & B_WRITE;*/
		uio_p = trans_buf_p -> trans_buf_desc. uio_p;
		transfer_spec = uio_p -> transfer_spec;
		write_op_flag = uio_p -> op_flags;
	} else {
		drv_buf_p = trans_buf_p -> drv_buf_p;
		if ( drv_buf_p != NULL )
			transfer_spec = drv_buf_p -> transfer_spec;

		if ( trans_buf_p -> drv_buf_p == NULL )
			write_op_flag = 0;
		else
			write_op_flag = trans_buf_p -> drv_buf_p -> op_flags & B_WRITE;
	}

	transfer_size = trans_buf_p -> real_trans_size;
	if ( transfer_spec != NULL ) {
		if ( transfer_spec -> io_mode_flags & BMEM_TRANSFER_IO_MODE ) {
			if ( transfer_spec -> repeation_num > 1 )
				source_size *= transfer_spec -> repeation_num;

			transfer_size = source_size - transfer_size * transfer_spec->trans_res_info->burst_byte_size;
			trans_buf_p -> real_trans_size = transfer_size;
		}
	}

	if ( transfer_size > source_size ) {
		bad_trans_size = 1;
		ME90_LOG(state, ME90_DL_ERROR,
				"%s(): I/O transfer real size %d > "
				" source size %d\n", __func__, 
				transfer_size,
				source_size
				);

		trans_resid = 0;
	} else
		trans_resid = source_size - transfer_size;
/*   if (bp != NULL)
     {
        bp -> b_resid = trans_resid;
     }*/

	if ( uio_p != NULL ) {
		uio_p -> uio_resid = trans_resid;
	}

	board_state = trans_buf_p -> gen_reg_state;

	if ( transfer_size > 0 && !trans_buf_p -> pseudobuf ) {
		int do_sync = 0;

		if ( trans_buf_p -> trans_buf_desc.drv_buf_used ) {
			if ( trans_buf_p -> drv_buf_p == NULL )
				do_sync = 1;
			else if ( trans_buf_p -> drv_buf_p -> op_flags & B_READ )
				do_sync = 1;

			if ( do_sync )
				sync_rval = mcka_dma_sync(state,
						trans_buf_p -> trans_buf_desc.dma.prim_dev_mem,
						trans_buf_p -> trans_buf_desc.buf_size,
						DMA_FROM_DEVICE);
		} else if ( uio_p != NULL ) {
			do_sync = uio_p -> op_flags & B_READ;

			if ( do_sync )
				sync_rval = mcka_dma_sync(state,
					trans_buf_p->trans_buf_desc.dma.prim_dev_mem,
					trans_buf_p->trans_buf_desc.uio_p->
								uio_iov[0].iov_len,
					DMA_FROM_DEVICE);
		}

		if ( sync_rval != DDI_SUCCESS ) {
			ME90_LOG(state, ME90_DL_ERROR,
				"%s(): dma_sync failed for channel %d\n", __func__, 
				channel
				);

			sync_rval = EFAULT;
		}
	}

	if (/*board_state.RERR_read != 0            ||*/ //alexmipt addition (architecture BUG)
		trans_buf_p -> mp_error_code != 0     ||
		trans_buf_p -> sparc_error_code != 0  ||
		miss_data_error                       ||
		bad_trans_size                        ||
		sync_rval != 0
		) {
			int rval = EIO;
	
			if ( trans_buf_p -> sparc_error_code != 0 )
				rval = trans_buf_p -> sparc_error_code;
			else if ( sync_rval != 0 )
				rval = sync_rval;
	
			trans_buf_p -> trans_error = rval;
	/*   if (bp != NULL)
			bioerror(bp, rval);
			else */
			if ( drv_buf_p != NULL )
				mcka_drv_buf_io_error(trans_buf_p, rval);

			if ( trans_buf_p -> sparc_error_code != 0 &&
				trans_buf_p -> sparc_error_code != ETIME ) {
				ME90_LOG(state, ME90_DL_ERROR,
					"%s(): channel %d I/O transfer finished with error %d"
					" detected by SPARC driver\n", __func__, 
					channel,
					trans_buf_p -> sparc_error_code
					);
			}
#if 0	//alexmipt addition (architecture BUG)
			if (board_state.RERR_read != 0)
			{
			ME90_LOG(state, ME90_DL_ERROR,
					"channel %d I/O transfer finished with board internal"
					" error RERR = 0x%x RNC = 0x%x RGEN = 0x%08x\n"
					,channel,
					board_state.RERR_read,
					board_state.RNC_read,
					board_state.RGEN_read
					);
#if IS_ENABLED(CONFIG_PCI2SBUS)
			p2s_reg_print(0x4);
			p2s_reg_print(0x5);
			p2s_reg_print(0x6);
			p2s_reg_print(0x7);
#endif
			}
#endif
		if ( trans_buf_p -> mp_error_code != 0 ) {
			if ( trans_buf_p -> board_state_byte != 0 ) {
				ME90_LOG(state, ME90_DL_ERROR,
					"channel %d I/O transfer finished with error 0x%02x "
					"detected by MP driver : "
					"SB=0x%02x"
					"\n",
					channel,
					trans_buf_p -> mp_error_code & 0xff,
					trans_buf_p -> board_state_byte
					);
			} else {
				ME90_LOG(state, ME90_DL_ERROR,
					"channel %d I/O transfer finished with error 0x%02x "
					"detected by MP driver\n",
					channel,
					trans_buf_p -> mp_error_code & 0xff
					);
			}
		}
	}

	if ( /*bp != NULL*/ uio_p != NULL || drv_buf_p != NULL ) {
		mcka_set_dma_trans_results(state, channel, trans_buf_p, transfer_spec, -1);

		if ( !transfer_spec -> async_trans )
			(/*bp != NULL*/ uio_p != NULL) ? /*biodone(bp)*/ :
			mcka_drv_buf_io_done(state, trans_buf_p, mutex_locked);
	}

	ME90_LOG(state, ME90_DL_TRACE,
			"%s(): I/O transfer successed for channel %d\n", __func__, 
			channel
			);
}

/*
 * Terminate transfer on buf - block I/O data transfer structure or
 * driver private buffer
 */

/*ARGSUSED*/
void
mcka_finish_trans(
	mcb_state_t		*state,
	int			channel,
	me90drv_trans_buf_t	*trans_buf_p,
	int			mutex_locked,
	int			trans_canceled)
{
	me90drv_chnl_state_t	*channel_state = NULL;
	me90drv_trans_spec_t	*transfer_spec_p = NULL;
	int			async_trans_flag = 0;
#ifdef	__BLOCK_BUFFER_USE__
	int			drv_buf_used = 0;
#endif	/* __BLOCK_BUFFER_USE__ */

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_finish_trans started for channel %d\n", channel);
	channel_state = &state -> all_channels_state[channel];
#ifdef	__BLOCK_BUFFER_USE__
	drv_buf_used = trans_buf_p -> trans_buf_desc.drv_buf_used;
	if (drv_buf_used) {
		if (trans_buf_p -> drv_buf_p == NULL) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_finish_trans drv buffer is NULL in"
				" trans buf 0x%08x\n", trans_buf_p);
			return;
		}
		transfer_spec_p = (me90drv_trans_spec_t *)
			trans_buf_p -> drv_buf_p -> transfer_spec;
	} else {
	/*	transfer_spec_p = trans_buf_p -> trans_buf_desc.bp -> b_private;*/
		transfer_spec_p = trans_buf_p -> trans_buf_desc.uio_p -> transfer_spec;
	}
#else
	transfer_spec_p = (me90drv_trans_spec_t *) trans_buf_p -> transfer_spec;
#endif	/* __BLOCK_BUFFER_USE__ */
	async_trans_flag = transfer_spec_p -> async_trans;
	me90drv_finish_dma_engine(state, channel, trans_buf_p, mutex_locked);
	if (async_trans_flag && !trans_canceled) {
		if (!mutex_locked)
		{
			mutex_enter(&state->mutex);	/* start MUTEX */
		}
		trans_buf_p -> next_trans_buf = NULL;
		if (channel_state -> ready_atrans_start == NULL)
			channel_state -> ready_atrans_start = trans_buf_p;
		else
			channel_state -> ready_atrans_end -> next_trans_buf =
				trans_buf_p;
		channel_state -> ready_atrans_end = trans_buf_p;
		channel_state -> ready_atrans_size ++;
		cv_broadcast(&state -> atrans_end_cv);
		if (!mutex_locked)
		{
			mutex_exit(&state->mutex);	/* end MUTEX */
		}
	}
#ifdef	__BLOCK_BUFFER_USE__
	else if (!drv_buf_used)
		me90drv_delete_trans_header(state, trans_buf_p);
#endif	/* __BLOCK_BUFFER_USE__ */
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_finish_trans finished for channel %d\n", channel);
}

/*
 * Finish the DMA data transfer endgine on error.
 * mutex_enter must be done by caller
 */

/*ARGSUSED*/
int
mcka_finish_dma_engine_on_error(
	mcb_state_t		*state,
	int			channel,
	me90drv_rd_reg_t	gen_reg_state,
	int			error_code)
{
	me90drv_chnl_state_t	*channel_state = NULL;
	me90drv_trans_buf_t	*trans_buf_p = NULL;
	int			transfer_size = 0;
	int			source_size = 0;
	int			transfer_complited = 0;
	me90drv_rd_reg_t	board_state = gen_reg_state;
	me90drv_wr_reg_t	error_reset;
	me90drv_drv_intercom_t	*drv_communication = NULL;
#ifdef	_MP_TIME_USE_
	u_int			trans_abort_time = 0;
#else
	hrtime_t		trans_abort_time = ddi_gethrtime();
#endif	/* _MP_TIME_USE_ */

	drv_communication =
		(me90drv_drv_intercom_t *) &state -> ME90DRV_INTERDRV_COMN_AREA;
#ifdef	_MP_TIME_USE_
	READ_MP_TIME(trans_abort_time);
#endif	/* _MP_TIME_USE_ */

	channel_state = &state -> all_channels_state[channel];
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_finish_dma_engine_on_error started for channel %d\n",
		channel);
	trans_buf_p = channel_state -> in_progress_start;
	if (trans_buf_p == NULL) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mcka_finish_dma_engine_on_error no transfer in "
			"progress for channel %d\n", channel);
		return 0;
	}
	source_size = trans_buf_p -> trans_size;
	trans_buf_p -> real_trans_size = transfer_size;

	if (board_state.ME90DRV_RGEN_read == 0) {
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
		board_state.ME90DRV_RGEN_read = state -> ME90DRV_CNTR_ST_REGS -> ME90DRV_RGENS_read;
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
		if (board_state.ME90DRV_RGEN_RERR_read != 0) {
			error_reset.ME90DRV_RGEN_write = 0;
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
			state -> ME90DRV_CNTR_ST_REGS -> ME90DRV_RERR_write = 
				error_reset.ME90DRV_RGEN_RERR_get_to_write;
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
		}
	}
	if (error_code == ETIME && transfer_complited) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mcka_finish_dma_engine_on_error transfer with timer "
			"expired is complited for channel %d\n", channel);
		trans_buf_p -> sparc_error_code = 0;
	}
	else if (trans_buf_p -> sparc_error_code == 0)
		trans_buf_p -> sparc_error_code = error_code;
	if (error_code == 0 && trans_buf_p -> sparc_error_code == 0 &&
	    board_state.ME90DRV_RGEN_RERR_read != 0)
		trans_buf_p -> sparc_error_code = EIO;
	trans_buf_p -> gen_reg_state = board_state;
	trans_buf_p -> intr_transfer_end = trans_abort_time;
	me90drv_handle_trans_finish(state,channel, NULL, board_state,
                             trans_abort_time, 1); /* transfer aborted */

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_finish_dma_engine_on_error I/O transfer finished"
		" for channel %d\n", channel);
	return (trans_buf_p -> sparc_error_code);	
}

/*
 * Processes list of terminated DMA transfers
 */

/*ARGSUSED*/
void
mcka_terminate_dma_trans(
	mcb_state_t	*state,
	int		channel)
{
	me90drv_chnl_state_t	*channel_state = NULL;
	me90drv_trans_buf_t	*cur_trans_buf_p = NULL;

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_terminate_dma_trans started for channel %d\n", channel);
	channel_state = &state -> all_channels_state[channel];
	mutex_enter(&state->mutex);			/* start MUTEX */
	if (channel_state -> term_trans_processed ||
	    channel_state -> completed_trans_start == NULL) {
		mutex_exit(&state->mutex);		/* end MUTEX */
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_terminate_dma_trans no transfers to terminate for"
			" channel %d\n", channel);
		return;
	}
	channel_state -> term_trans_processed = 1;
	mutex_exit(&state->mutex);			/* end MUTEX */
	while (1) {
		mutex_enter(&state->mutex);		/* start MUTEX */
		cur_trans_buf_p = channel_state -> completed_trans_start;
		if (cur_trans_buf_p == NULL) {
			channel_state -> completed_trans_end = NULL;
			break;
		}
		channel_state -> completed_trans_size --;
		channel_state -> completed_trans_start =
			cur_trans_buf_p -> next_trans_buf;
		mutex_exit(&state->mutex);		/* end MUTEX */
#ifdef	__BLOCK_BUFFER_USE__
		if (!cur_trans_buf_p -> trans_buf_desc.drv_buf_used	||
		    (cur_trans_buf_p -> trans_buf_desc.drv_buf_used	&&
		    cur_trans_buf_p -> drv_buf_p != NULL))
#endif	/* __BLOCK_BUFFER_USE__ */
			mcka_finish_trans(state, channel, cur_trans_buf_p, 0, 0);

#ifdef	__BLOCK_BUFFER_USE__
		  else {
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_terminate_dma_trans unknown transfer "
				"method for channel %d\n", channel);
		}
#endif	/* __BLOCK_BUFFER_USE__ */
	}
	channel_state -> term_trans_processed = 0;
	mutex_exit(&state->mutex);			/* end MUTEX */

	ME90_LOG(state, ME90_DL_TRACE,
		"state_terminate_dma_trans successed for channel %d\n", channel);
}

/*
 * Delete timeout (mutex_enter must be done by caller)
 */

/*ARGSUSED*/

void
mcka_delete_timeout(
	mcb_state_t	*state,
	int		channel)
{
	me90drv_chnl_state_t * channel_state = NULL;

	if (channel < 0) {
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_delete_timeout general timeout\n");
	} else {
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_delete_timeout for channel %d\n", channel);
	}
	if (channel < 0) {		/* general timeout */
		if (state -> timeout_type == no_timeout_type) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_delete_timeout : no general timeout\n");
		}
		state -> timeout_type = no_timeout_type;
		state -> timeout_rem = 0;
	} else {
		channel_state = &state -> all_channels_state[channel];
		if (channel_state -> timeout_type == no_timeout_type) {
				ME90_LOG(state, ME90_DL_ERROR,
					"mcka_delete_timeout : no timeout for"
					" channel %d\n", channel);
				return;
		}
		if ((!channel_state -> busy &&
		    !(state -> drv_general_modes & MULTI_REQ_CHANNEL_DRV_MODE)) ||
		    (!channel_state -> busy &&
		    channel_state -> in_progress_start == NULL &&
		    (state -> drv_general_modes & MULTI_REQ_CHANNEL_DRV_MODE))) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_delete_timeout : channel %d is not busy"
				" by I/O\n", channel);
		}
		channel_state -> timeout_type = no_timeout_type;
		channel_state -> timeout_rem = 0;
	}
	state -> timeouts_num --;
	ME90_LOG(state, ME90_DL_TRACE, "mcka_delete_timeout successed\n");
}

/*
 * The channel command timeout recovery. mutex_enter must be done by caller
 */

static	void
mcka_general_timeout(mcb_state_t	*state)
{
	ME90_LOG(state, ME90_DL_TRACE, "mcka_general_timeout unused so far\n");
}

/*
 * Reset timeout
 */

/*ARGSUSED*/

static	void
mcka_reset_timeout(
	mcb_state_t	*state,
	int		channel)
{

	if (channel < 0) {
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_reset_timeout general timeout\n");
	} else {
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_reset_timeout for channel %d\n", channel);
	}
	mutex_enter(&state->mutex);			/* start MUTEX */
	mcka_delete_timeout(state, channel);
	mutex_exit(&state->mutex);			/* end MUTEX */

	ME90_LOG(state, ME90_DL_TRACE, "mcka_reset_timeout successed\n");
}

/*
 * Delete all transfers from list of transfers currently in the progress.
 * mutex may be locked by caller
 */

/*ARGSUSED*/
void
mcka_delete_trans_in_progress(
	mcb_state_t	*state,
	int		channel,
	int		error_code,
	int		waiting_loop_num,
	int		mutex_locked)
{
	me90drv_chnl_state_t	*channel_state = NULL;
	me90drv_trans_buf_t	*cur_trans_buf_p = NULL;
	me90drv_rd_reg_t	gen_reg_state;
	int			cur_loop = 0;

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_delete_trans_in_progress started for channel %d\n",
		channel);

	channel_state = &state -> all_channels_state[channel];
	gen_reg_state.ME90DRV_RGEN_read = 0;
	if (!mutex_locked)
	{
		mutex_enter(&state->mutex);		/* start MUTEX */
	}
	while (channel_state -> in_progress_start != NULL) {
		cur_trans_buf_p = channel_state -> in_progress_start;
		if (cur_trans_buf_p == NULL)
			break;
		if (!mutex_locked)
		{
			mutex_exit(&state->mutex);	/* end of MUTEX */
		}
		for (cur_loop = 0; cur_loop < waiting_loop_num; cur_loop ++) {
			if (channel_state -> in_progress_start !=
			    cur_trans_buf_p) {
				break;
			}
		}
		if (!mutex_locked)
		{
			mutex_enter(&state->mutex);	/* start MUTEX */
		}
		if (cur_trans_buf_p != channel_state -> in_progress_start)
			continue;
		mcka_finish_dma_engine_on_error(state, channel, gen_reg_state,
			error_code);
	}
	if (!mutex_locked)
	{
		mutex_exit(&state->mutex);		/* end of MUTEX */
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_delete_trans_in_progress finished for channel %d\n",
		channel);
}

/*
 * Delete all currently executed transfers from list of waiting for start and
 * list of transfers in progress.
 * mutex may be locked by caller
 */

/*ARGSUSED*/
void
mcka_delete_all_exec_trans(
	mcb_state_t	*state,
	int		channel,
	int		error_code,
	int		waiting_loop_num,
	int		mutex_locked)
{
	me90drv_chnl_state_t	*channel_state = NULL;
	me90drv_trans_buf_t	*cur_trans_buf_p = NULL;
#ifdef	_MP_TIME_USE_
	u_int			trans_delete_time = 0;
#else
	hrtime_t		trans_delete_time = ddi_gethrtime();
#endif	/* _MP_TIME_USE_ */
	me90drv_drv_intercom_t	*drv_communication = NULL;

	drv_communication =
		(me90drv_drv_intercom_t *) &state -> ME90DRV_INTERDRV_COMN_AREA;

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_delete_all_exec_trans started for channel %d\n", channel);
	channel_state = &state -> all_channels_state[channel];
	mcka_delete_trans_in_progress(state, channel, error_code,
		waiting_loop_num, mutex_locked);
	
	while (1) {
		if (cur_trans_buf_p == NULL) {
			if (!mutex_locked)
			{
				mutex_enter(&state->mutex); /* start MUTEX */
			}
			cur_trans_buf_p = channel_state -> wait_list_start;
			if (cur_trans_buf_p == NULL) {
				channel_state -> wait_list_end = NULL;
				if (!mutex_locked)
					mutex_exit(&state->mutex); /* MUTEX */
				break;
			}
			channel_state -> wait_list_size --;
			channel_state -> wait_list_start =
				cur_trans_buf_p -> next_trans_buf;
			if (!mutex_locked)
			{
				mutex_exit(&state->mutex); /* end of MUTEX */
			}
		}
#ifdef	_MP_TIME_USE_
		READ_MP_TIME(trans_delete_time);
#else
		trans_delete_time = ddi_gethrtime();
#endif	/* _MP_TIME_USE_ */
		cur_trans_buf_p -> intr_transfer_end = trans_delete_time;
#ifdef	__BLOCK_BUFFER_USE__
		if (!cur_trans_buf_p -> trans_buf_desc.drv_buf_used ||
		    (cur_trans_buf_p -> trans_buf_desc.drv_buf_used &&
		    cur_trans_buf_p -> drv_buf_p != NULL)) {
#endif	/* __BLOCK_BUFFER_USE__ */
			cur_trans_buf_p -> sparc_error_code = error_code;
			mcka_finish_trans(state, channel, cur_trans_buf_p,
				mutex_locked, 0);
#ifdef	__BLOCK_BUFFER_USE__
		}
		else {
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_delete_all_exec_trans unknown transfer "
				"method for channel %d\n", channel);
		}
#endif	/* __BLOCK_BUFFER_USE__ */
		cur_trans_buf_p = NULL;
	}
	channel_state -> busy = 0;

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_delete_all_exec_trans succeeded for channel %d\n",
		channel);
}

/*
 * The channel command timeout recovery
 */

static	int
mcka_channel_timeout(
	mcb_state_t	*state,
	int		channel)
{
	me90drv_chnl_state_t	*channel_state = NULL;
	me90drv_rd_reg_t	gen_reg_state;
	int			rval = 0;
	int			abort_rval = 0;

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_channel_timeout started for channel %d\n", channel);
	channel_state = &state -> all_channels_state[channel];
	mutex_enter(&state->mutex);			/* start MUTEX */
	if ((!channel_state -> busy &&
	    !(state -> drv_general_modes & MULTI_REQ_CHANNEL_DRV_MODE)) ||
	    (!channel_state -> busy &&
	    channel_state -> in_progress_start == NULL &&
	    (state -> drv_general_modes & MULTI_REQ_CHANNEL_DRV_MODE))) {
		mutex_exit(&state->mutex);		/* end MUTEX */
		if (channel_state -> timeout_type != no_timeout_type ||
		    channel_state -> timeout_rem > 0) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_channel_timeout: channel %d is free,"
				" but timeout is set\n", channel);
			mcka_reset_timeout(state,channel);
		}
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_channel_timeout channel %d : transfer completed"
			" already\n", channel);
		return 0;
	}
	if (channel_state -> busy && channel_state -> dma_intr_handled) {
		mutex_exit(&state->mutex);		/* end MUTEX */
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_channel_timeout channel %d : transfer now"
			" completed\n", channel);
		return 0;  /* interrupt handler deletes timeout */
	}
	if (channel_state -> timeout_type == no_timeout_type) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mcka_channel_timeout: channel %d is busy, but "
			"timeout does not set\n", channel);
	} else if (channel_state -> timeout_rem > 0) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mcka_channel_timeout: channel %d remainder time %d"
			" (> 0)\n", channel,channel_state -> timeout_rem);
	}
	if (channel_state -> in_progress_start == NULL) {
		mutex_exit(&state->mutex);		/* end MUTEX */
		mcka_reset_timeout(state,channel);
		return 0;
	}
	if (channel_state -> in_progress_start -> sparc_error_code == 0) {
		channel_state -> in_progress_start -> sparc_error_code = ETIME;
		mutex_exit(&state->mutex);		/* end MUTEX */
		abort_rval = me90drv_abort_dma_transfer(state,channel);
		if (abort_rval == 0)
			return 0;
		mutex_enter(&state->mutex);		/* start MUTEX */
	}
	if (channel_state -> in_progress_start == NULL) {
		mutex_exit(&state->mutex);		/* end MUTEX */
		return 0;
	}
	gen_reg_state.ME90DRV_RGEN_read = 0;
	rval = mcka_finish_dma_engine_on_error(state, channel, gen_reg_state,
			ETIME);
	mutex_exit(&state->mutex);			/* end MUTEX */
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_channel_timeout finished for channel %d\n", channel);
	return 1;
}

static void mcka_watchdog(caddr_t arg);

/*
 * Timeout (watchdog services) callback function
 */

/*ARGSUSED*/

//int
void
mcka_watchdog_handler(struct work_struct *work)
{
	mcb_state_t		*state = container_of(work, mcb_state_t, watchdog_tqueue);
	me90drv_chnl_state_t	*channel_state = NULL;
	int                cur_chnl = 0;
	
#if 0
	daemonize("watchdog_handlerd");
	do
     	{
waiting_mode:
		ME90_LOG(state, ME90_DL_TRACE, "MCKA: waiting for mcka_watchdog started !!!!\n");
		current->policy = SCHED_FIFO;
		interruptible_sleep_on(&state->mcka_watchdog_handler);
		if (state->waking_up_mcka_watchdog_handler == 1){
			ME90_LOG(state, ME90_DL_TRACE, "waking up mcka_watchdog_handler !!!\n");
			state->waking_up_mcka_watchdog_handler = 0;
			del_timer_sync(&(state -> timeout_idnt));
			break;
		}
        	if (state->mcka_watchdog_handler_shutdown == 1) {
			ME90_LOG(state, ME90_DL_TRACE, "MCKA: mcka_watchdog_handler exit by signal\n");
			state->mcka_watchdog_handler_shutdown = 0;
			return 0;
		}
     	}  while (1);
#endif
	mutex_enter(&state->mutex);
	ME90_LOG(state, ME90_DL_TRACE, "mcka_watchdog_handler started\n");

	if (state -> timeout_type != no_timeout_type) {	/* general timeout */
		if (state -> timeouts_num == 0) {
			ME90_LOG(state, ME90_DL_ERROR,
				"state_watchdog_handler : not handled general "
				"timeout, bat timeouts num is 0\n");
		}
		state -> timeout_rem -= ME90DRV_WATCHDOG_DEF_VALUE;
		if (state -> timeout_rem <= 0)		/* time is over */
			mcka_general_timeout(state);
	}
	for (cur_chnl = 0; cur_chnl < MAX_ME90DRV_BOARD_CHANNEL_NUM;
	     cur_chnl ++) {
		channel_state = &state -> all_channels_state[cur_chnl];
		if (channel_state -> timeout_type != no_timeout_type) {
			if (state -> timeouts_num == 0) {
				ME90_LOG(state, ME90_DL_ERROR,
					"mcka_watchdog_handler : not handled chanel "
					"%d timeout, bat timeouts num is 0\n",
					cur_chnl);
			}
			channel_state -> timeout_rem -=
				ME90DRV_WATCHDOG_DEF_VALUE;
			ME90_LOG(state, ME90_DL_TRACE,
				"mcka_watchdog_handler : chanel %d timeout rem = %d\n",
				cur_chnl, channel_state -> timeout_rem);
			if (channel_state -> timeout_rem <= 0) {
				/* time is over */
				mutex_exit(&state->mutex);	/* end MUTEX */
				if (mcka_channel_timeout(state,cur_chnl) != 0) {
					mcka_terminate_dma_trans(state,cur_chnl);
						me90drv_start_new_trans(state, 	cur_chnl);
				}
				mutex_enter(&state->mutex);  /* start MUTEX */
			}
		}
	}
	if (state -> timeouts_num > 0) {	/* watchdog services are needed */
		/*state -> timeout_idnt = timeout(state_watchdog,
				(caddr_t) state,
				drv_usectohz(
					(clock_t)ME90DRV_WATCHDOG_DEF_VALUE));*/
		struct timer_list *tm = &(state -> timeout_idnt);
		tm->expires = jiffies + drv_usectohz(ME90DRV_WATCHDOG_DEF_VALUE);
		tm->function = (void *)mcka_watchdog;
		tm->data = (unsigned long)state;
		mutex_exit(&state->mutex);			/* end MUTEX */
		add_timer(tm);

//		mutex_exit(&state->mutex);			/* end MUTEX */
	} else {
		state -> timeouts_num = 0;
		state -> timeout_idnt.expires = 0;
		mutex_exit(&state->mutex);			/* end MUTEX */
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_watchdog_handler services finished\n");
	}
//	goto waiting_mode;
}

void mcka_watchdog(caddr_t arg)
{
	mcb_state_t		*state = (mcb_state_t *) arg;

	ME90_LOG(state, ME90_DL_TRACE, "MCKA: mcka_watchdog start\n");
//	state->waking_up_mcka_watchdog_handler = 1;
     
//	wake_up(&state->mcka_watchdog_handler);
	schedule_work(&state->watchdog_tqueue);

	ME90_LOG(state, ME90_DL_TRACE, "MCKA: mcka_watchdog finish\n");
}

/*
 * Set timeouts watchdog services startup if need
 */

/*ARGSUSED*/

int
mcka_set_timeout(
	mcb_state_t	*state,
	timeout_type_t	timeout_type,
	timeout_value_t	timeout_value_arg,
	int		channel,
	int		mutex_started)
{
	timeout_value_t		timeout_value = timeout_value_arg;
	me90drv_chnl_state_t	*channel_state = NULL;
	int			start_timeout = 0;
	int			timeout_exist = 0;

	if (channel < 0) {
		ME90_LOG(state, ME90_DL_TRACE, 
			"mcka_set_timeout general timeout: type %d value %d\n",
			(int)timeout_type, (int)timeout_value);
	} else {
		ME90_LOG(state, ME90_DL_TRACE, 
			"mcka_set_timeout for channel %d type %d value %d\n",
			channel,(int)timeout_type, (int)timeout_value);
	}
	if (timeout_value <= 0) {
		switch (timeout_type) {
			case read_timeout_type :
				timeout_value = (10 * ME90DRV_READ_TIMEOUT_DEF_VALUE);
				break;
			case write_timeout_type :
				timeout_value = (10 * ME90DRV_WRITE_TIMEOUT_DEF_VALUE);
				break;
			case batch_timeout_type :
				timeout_value = ME90DRV_BATCH_TIMEOUT_DEF_VALUE;
				break;
			case terminate_timeout_type :
				timeout_value =
					ME90DRV_TERMINATE_TIMEOUT_DEF_VALUE;
				break;
			case no_timeout_type :
			default :
				ME90_LOG(state, ME90_DL_ERROR,
					"mcka_set_timeout failed : undefined"
					" timeout type %d\n", timeout_type);
				return 1;
		}
	}
	if (!mutex_started)
	{
		mutex_enter(&state->mutex);		/* start MUTEX */
	}
	if (channel < 0) {				/* general timeout */
		if (state -> timeout_type != no_timeout_type ||
		    state -> timeout_rem > 0) {
			if (!mutex_started)
			{
				mutex_exit(&state->mutex);	/* end MUTEX */
			}
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_set_timeout failed : general"
				" timeout exists already\n");
			return 1;
		}
		state -> timeout_type = timeout_type;
		state -> timeout_rem = timeout_value;
	} else {
		channel_state = &state -> all_channels_state[channel];
		if (channel_state -> timeout_type != no_timeout_type ||
		    channel_state -> timeout_rem > 0) {
			int	rval = 0;
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_set_timeout failed : channel %d timeout "
				"exists already  type %d =? %d =? %d\n",
				channel, timeout_type, state -> timeout_type,
				terminate_timeout_type);
			rval = 1;
			if (!mutex_started)
			{
				mutex_exit(&state->mutex);	/* end MUTEX */
			}
			return rval;
		}
		if ((!channel_state -> busy &&
		    !(state -> drv_general_modes & MULTI_REQ_CHANNEL_DRV_MODE)) ||
		    (!channel_state -> busy &&
		    channel_state -> in_progress_start == NULL &&
		    (state -> drv_general_modes & MULTI_REQ_CHANNEL_DRV_MODE))) {
			if (!mutex_started)
			{
				mutex_exit(&state->mutex);	/* end MUTEX */
			}
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_set_timeout failed : channel %d is not"
				" busy by I/O cmd\n", channel);
			return 1;
		}
		channel_state -> timeout_type = timeout_type;
		channel_state -> timeout_rem = timeout_value;
		channel_state -> last_timeout_type = timeout_type;
		channel_state -> last_timeout_value = timeout_value;
	}
	ME90_LOG(state, ME90_DL_TRACE, 
			"mcka_set_timeout: channel_state -> timeout_type = %d\n", 
				(int)channel_state -> timeout_type);
        ME90_LOG(state, ME90_DL_TRACE,
			"mcka_set_timeout: channel_state -> timeout_rem = %d\n", 
				(int)channel_state -> timeout_rem);
        ME90_LOG(state, ME90_DL_TRACE,
			"mcka_set_timeout: channel_state -> last_timeout_type = %d\n", 
				(int)channel_state -> last_timeout_type);
        ME90_LOG(state, ME90_DL_TRACE, 
			"mcka_set_timeout: channel_state -> last_timeout_value = %d\n", 
				(int)channel_state -> last_timeout_value);
	if (state -> timeouts_num == 0) {	/* start timeouting as watch */
						/* dog services */
	/*	if (state -> timeout_idnt == 0) {
			state -> timeout_idnt = timeout(state_watchdog,
				(caddr_t) state,
				drv_usectohz(
					(clock_t)ME90DRV_WATCHDOG_DEF_VALUE));*/
		if (state -> timeout_idnt.expires == 0) {
			struct timer_list *tm = &state -> timeout_idnt;
			init_timer(tm);
		  	tm->expires = jiffies + drv_usectohz(ME90DRV_WATCHDOG_DEF_VALUE);
		  	tm->function = (void *)mcka_watchdog;
		  	tm->data = (unsigned long)state;
		  	add_timer(tm);
			
			if (state -> timeout_idnt.expires == 0) {
				if (!mutex_started)
				{
					mutex_exit(&state->mutex);
				}
				ME90_LOG(state, ME90_DL_ERROR,
					"mcka_set_timeout: timeout call"
					" failed\n");
				return 1;
			}
			start_timeout = 1;
		} else
			timeout_exist = 1;
	}
	state -> timeouts_num ++;
	if (!mutex_started)
	{
		mutex_exit(&state->mutex);		/* end MUTEX */
	}
	if (start_timeout) {
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_set_timeout : watchdog started for a time %d"
			" mks\n", ME90DRV_WATCHDOG_DEF_VALUE);
	} else if (timeout_exist) {
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_set_timeout : watchdog was been started "
			"already\n");
	}
	ME90_LOG(state, ME90_DL_TRACE, "mcka_set_timeout successed\n");
	return 0;
}

/*
 * Set timeout for channel current transfer in progress, 
 */

/*ARGSUSED*/


void
mcka_set_trans_timeout(
	mcb_state_t	*state,
	int		channel,
	int		mutex_started)
{
	me90drv_chnl_state_t	*channel_state = NULL;
	me90drv_trans_buf_t	*cur_trans_buf = NULL;
	me90drv_trans_spec_t	*transfer_spec_p = NULL;
	timeout_type_t		timeout_type = no_timeout_type;
	timeout_value_t		timeout_value = 0;
#ifdef	__BLOCK_BUFFER_USE__
/*	buf_t			*bp = NULL;*/
	uio_t			*uio_p = NULL;
#endif	/* __BLOCK_BUFFER_USE__ */

	dbgmcka("mcka_set_trans_timeout started for channel %d\n", channel);
	udelay(10000);
	channel_state = &state -> all_channels_state[channel];
	if (!mutex_started){
		mutex_enter(&state->mutex);		/* start MUTEX */
	}
	cur_trans_buf = channel_state -> in_progress_start;
	if (cur_trans_buf == NULL) {
		if (!mutex_started)
     			mutex_exit(&state->mutex);	/* end MUTEX */
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_set_trans_timeout no any transfer in progress for"
			" channel %d\n", channel);
		return;
	}
	if (channel_state -> timeout_type != no_timeout_type ||
	    channel_state -> timeout_rem > 0) {
	        if (!mutex_started)
		{
			mutex_exit(&state->mutex);	/* end MUTEX */
		}
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_set_trans_timeout timeout is set already for"
			" channel %d\n", channel);
		return;
	}
#ifdef	__BLOCK_BUFFER_USE__
	if (cur_trans_buf -> trans_buf_desc.drv_buf_used) {
		if (cur_trans_buf -> drv_buf_p != NULL) {
			transfer_spec_p = (me90drv_trans_spec_t *)
				cur_trans_buf -> drv_buf_p -> transfer_spec;
		 }
	} else {
	/*	bp = cur_trans_buf -> trans_buf_desc.bp;
		transfer_spec_p = bp -> b_private; */
		uio_p = cur_trans_buf -> trans_buf_desc.uio_p;
		transfer_spec_p = uio_p -> transfer_spec;
	}
#endif	/* __BLOCK_BUFFER_USE__ */
	if (transfer_spec_p != NULL) {
		     if (transfer_spec_p -> read_write_flag & B_READ)
			timeout_type = read_timeout_type;
		else
			timeout_type = write_timeout_type;
		timeout_value = transfer_spec_p -> timer_interval;
	} else
		timeout_type = read_timeout_type;
	mcka_set_timeout(state, timeout_type, timeout_value, channel, 1);
	if (!mutex_started)
	{
		mutex_exit(&state->mutex);		/* end MUTEX */
	}
	dbgmcka("mcka_set_trans_timeout finished for channel %d\n", channel);
}

/*ARGSUSED*/
int
mcka_set_transfer_done(
	mcb_state_t	*state,
	int		channel,
	trans_state_t	transfer_state)
{
	me90drv_chnl_state_t	*channel_state = NULL;

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_set_transfer_done for channel %d started\n", channel);

	channel_state = &state -> all_channels_state[channel];

	/*
	 * unblock any threads waiting the channel freeing 
	 */

	channel_state -> transfer_state = transfer_state;
	channel_state -> busy = 0;
	cv_broadcast(&state -> channel_cv);

        ME90_LOG(state, ME90_DL_TRACE,
		"mcka_set_transfer_done for channel %d successed\n", channel);

	return (0);
}

/*
 * Terminate current streaming transfer and launch next transfer as
 * current
 */

/*ARGSUSED*/
void
mcb_handle_trans_finish(
	mcb_state_t	*state,
	int		channel,
	trans_result_t	*trans_results,
	mc_rd_reg_t	gen_reg_state,
#ifdef	_MP_TIME_USE_
	u_int		intr_transfer_end,
#else
	hrtime_t	intr_transfer_end,
#endif	/* _MP_TIME_USE_ */
	int		trans_aborted)
{
	me90drv_chnl_state_t	*channel_state = NULL;
	trans_buf_t		*cur_trans_buf = NULL;

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_handle_trans_finish started for channel %d\n", channel);
	channel_state = &state -> all_channels_state[channel];
	cur_trans_buf = channel_state -> in_progress_start;
	if (cur_trans_buf == NULL) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mcka_handle_trans_finish no any transfer in progress"
			" for channel %d\n", channel);
		return;
	}
	if (trans_results != NULL) {
		cur_trans_buf -> real_trans_size =
			trans_results -> real_size;
		cur_trans_buf -> mp_error_code = trans_results -> mp_error_code;
		cur_trans_buf -> board_state_byte = trans_results -> state_byte;
		cur_trans_buf -> sp_state_byte = 0;
		cur_trans_buf -> gen_reg_state = gen_reg_state;
		cur_trans_buf -> intr_transfer_end = intr_transfer_end;
	}
	mcka_delete_timeout(state,channel);
	channel_state -> in_progress_start = cur_trans_buf -> next_trans_buf;
	if (channel_state -> in_progress_start == NULL) {
		channel_state -> in_progress_end = NULL;
	}
	channel_state -> in_progress_size --;
	cur_trans_buf -> next_trans_buf = NULL;
	if (channel_state -> completed_trans_start == NULL)
		channel_state -> completed_trans_start = cur_trans_buf;
	else
		channel_state -> completed_trans_end -> next_trans_buf =
							cur_trans_buf;
	channel_state -> completed_trans_end = cur_trans_buf;
	channel_state -> completed_trans_size ++;

	if (channel_state -> in_progress_start == NULL)
		channel_state -> in_progress = 0;
	if (channel_state -> in_progress_start != NULL) {
		if (!channel_state -> streaming)
			mcka_set_trans_timeout(state, channel, 1);
		else if (channel_state -> pseudostreaming                  &&
			 !channel_state -> in_progress_start -> pseudobuf)
			mcka_set_trans_timeout(state, channel, 1);
	}
	if (!(state -> drv_general_modes & MULTI_REQ_CHANNEL_DRV_MODE) &&
	    !channel_state -> streaming)
		mcka_set_transfer_done(state, channel, completed_trans_state);
	else {
		cv_broadcast(&state -> channel_cv);
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_handle_trans_finish successed for channel %d\n", channel);
}

/*
 * Clean base memory of board
 */
/*ARGSUSED*/
void
me90_clean_base_memory(mcb_state_t	*state)
{
	u_int	*base_memory = NULL;
	int	cur_word = 0;

	ME90_LOG(state, ME90_DL_TRACE, "mcka_clean_base_memory started\n");
	base_memory = (u_int *) state -> ME90DRV_BMEM;
	for (cur_word = 0; cur_word < (ME90DRV_BMEM_REG_SET_LEN +
					(sizeof(u_int)-1))/sizeof(u_int);
	     cur_word ++) {
		base_memory[cur_word] = ME90DRV_MP_HALT_OPCODE;
	}
	state -> mp_drv_loaded = 0;
	ME90_LOG(state, ME90_DL_TRACE, "mcka_clean_base_memory finished\n");
}

/*
 * Clean interdriver communication area
 */
/*ARGSUSED*/
void
mcka_clean_drv_communication(me90drv_state_t	*state)
{
	me90drv_drv_intercom_t	*drv_communication = NULL;
	int			cur_arg = 0;

	ME90_LOG(state, ME90_DL_TRACE, "mcka_clean_drv_communication started\n");
	drv_communication =
		(me90drv_drv_intercom_t *) &state -> ME90DRV_INTERDRV_COMN_AREA;
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
	drv_communication -> mp_task = me90drv_no_mp_task;
	drv_communication -> sparc_task = me90drv_no_sparc_task;
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
	for (cur_arg = 0; cur_arg < sizeof(drv_communication -> mp_args) /
				sizeof(*drv_communication -> mp_args.args_area);
	    cur_arg ++) {
		drv_communication -> mp_args.args_area[cur_arg] = 0;
	}
	for (cur_arg = 0; cur_arg < sizeof(drv_communication -> sparc_args) /
			sizeof(*drv_communication -> sparc_args.args_area);
	     cur_arg ++) {
		drv_communication -> sparc_args.args_area[cur_arg] = 0;
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_clean_drv_communication successed\n");
}

/*
 * First startup and reset of MicroProcessor and its driver
 */
/*ARGSUSED*/
int
me90_reset_mp(
	mcb_state_t	*state,
	int		halt_mp,
	int		clean_bmem)
{
	int     rval = 0;

	ME90_LOG(state, ME90_DL_TRACE, "mcka_reset_mp started\n");

	rval = me90drv_reset_general_regs(state, halt_mp);
	if (clean_bmem)
		me90_clean_base_memory(state);
	mcka_clean_drv_communication(state);
	if (rval != 0) {
		ME90_LOG(state, ME90_DL_ERROR, "mcka_reset_mp: reset board and MP finished with error\n");
		return 1;
	} else {
		ME90_LOG(state, ME90_DL_TRACE, "mcka_reset_mp: reset board and MP successed\n");
		return 0;
	}
}

/*
 * Copy data from a source kernel address to a MP base memory. Source addresss
 * and base memory address must have the same alignment into word
 */
/*ARGSUSED*/
int	mcka_write_base_memory(
	mcb_state_t	*state,
	caddr_t		address_from, 
	caddr_t		address_to,
	size_t		byte_size,
	int		char_data)
{
     u_int *      kmem_area_from = NULL;
     u_int *      bmem_area_to = NULL;
     size_t        begin_rem = 0;
     size_t        cur_byte_size = 0;
     size_t        word_size = 0;
     size_t        rem = 0;
     int           cur_word = 0;

     ME90_LOG(state, ME90_DL_TRACE,
		"mcka_write_base_memory started to copy data from addr 0x%lx"
		" to BMEM addr 0x%lx size 0x%x\n",
		address_from,address_to,byte_size);
     if ((long) address_to < 0                               ||
         (long) address_to >= MC_BMEM_REG_SET_LEN            ||
         (long) address_to + byte_size > MC_BMEM_REG_SET_LEN
        )
     {
        ME90_LOG(state, ME90_DL_ERROR,
                "mcka_write_base_memory bad address and/or size of BMEM\n"
               );
        return EINVAL;
     }
     if (((long) address_from & (sizeof(u_int)-1)) !=
         ((long) address_to   & (sizeof(u_int)-1))
        )
     {
	ME90_LOG(state, ME90_DL_ERROR,
		"mcka_write_base_memory kernel and BMEM addresses have "
                "different alignment into word\n");
        return EINVAL;
     }
     begin_rem = ((long) address_from & (sizeof(u_int)-1));
     kmem_area_from = (u_int *) ((u_long) address_from - begin_rem);
     bmem_area_to = (u_int *) & state -> MC_BMEM[(long) address_to - begin_rem];
     cur_byte_size = byte_size;
     if (begin_rem != 0)
     {
        u_int   first_bmem_word = bmem_area_to[0];
        u_char * first_bmem_word_p = (u_char *) & first_bmem_word;
        u_char * first_kernel_word = (u_char *) & kmem_area_from[0];
        int      begin_size = sizeof(u_int) - begin_rem;
        int      cur_byte = 0;
        if (char_data)
           first_bmem_word = mcka_rotate_word_bytes(first_bmem_word);
        begin_size = (begin_size > cur_byte_size) ? cur_byte_size : begin_size;
        for (cur_byte = begin_rem;
             cur_byte < begin_rem + begin_size;
             cur_byte ++
            )
        {
           first_bmem_word_p[cur_byte] = first_kernel_word[cur_byte];
        }
        if (char_data)
           first_bmem_word = mcka_rotate_word_bytes(first_bmem_word);
        bmem_area_to[0] = first_bmem_word;
        cur_byte_size -= begin_size;
        /*(int)*/ kmem_area_from ++;
        /*(int)*/ bmem_area_to ++;
     }
     word_size = cur_byte_size / sizeof(u_int);
     rem = byte_size % sizeof(u_int);
     for (cur_word = 0; cur_word < word_size; cur_word ++)
     {
        if (char_data)
           bmem_area_to[cur_word] = mcka_rotate_word_bytes(
					kmem_area_from[cur_word]);
        else
           bmem_area_to[cur_word] = kmem_area_from[cur_word];
     }
     if (rem != 0)
     {
        u_int   last_bmem_word = bmem_area_to[word_size];
        u_char * last_bmem_word_p = (u_char *) & last_bmem_word;
        u_char * last_kernel_word = (u_char *) & kmem_area_from[word_size];
        int      cur_byte = 0;
        if (char_data)
           last_bmem_word = mcka_rotate_word_bytes(last_bmem_word);
        for (cur_byte = 0; cur_byte < rem; cur_byte ++)
        {
           last_bmem_word_p[cur_byte] = last_kernel_word[cur_byte];
        }
        if (char_data)
           last_bmem_word = mcka_rotate_word_bytes(last_bmem_word);
        bmem_area_to[word_size] = last_bmem_word;
     }

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_write_base_memory succeeded to copy data from addr 0x%lx"
		" to BMEM addr 0x%lx size 0x%x\n",
		address_from,address_to,byte_size);
	return 0;
}

/*
 * Restart of MicroProcessor and its driver after hangup, mutex must be locked
 * by caller
 */
/*ARGSUSED*/
int
mcka_restart_mp(
	mcb_state_t	*state,
	int		drv_comm_area_locked)
{
	int				rval = 0;
	me90drv_mp_drv_args_t		*mp_drv_init_info_p = NULL;
	me90drv_sparc_drv_args_t	drv_load_results;
	u_int				rom_drv_init_code[] =
						ME90_MP_ROM_DRV_INIT_CODE;
	me90_mp_rom_drv_t		*mp_rom_drv_init_area = NULL;

	ME90_LOG(state, ME90_DL_TRACE, "mcka_restart_mp started\n");

	me90_reset_mp(state, 2, 0);
	if ((!state -> mp_drv_loaded && state -> mp_debug_drv_flag ) ||
		!state -> mp_drv_started) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mcka_restart_mp: MP driver was not loaded or started"
			" up\n");
		return 1;
	}
	if (state -> mp_debug_drv_flag)
		rval = mcka_write_base_memory(state,
				state -> mp_init_code.mem_address,
				state -> mp_init_code.mp_bmem_address,
				state -> mp_init_code.byte_size, 1);
	else
		rval = mcka_write_base_memory(state,
				(caddr_t)&rom_drv_init_code,
				state -> mp_init_code.mp_bmem_address,
				sizeof(rom_drv_init_code), 1);
	if (rval != 0) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mcka_restart_mp failed - write init code in bmem"
			" failed\n");
		return rval;
	}
	if (state -> mp_init_code.mp_drv_init_info != NULL &&
	    state -> mp_init_code.mp_drv_init_info_size > 0)
		mp_drv_init_info_p = &state -> mp_drv_init_info;

	mp_rom_drv_init_area = (me90_mp_rom_drv_t *)
		&state -> ME90DRV_BMEM[ME90_MP_ROM_DRV_INIT_ADDR];
	mp_rom_drv_init_area -> debug_drv_start =
		state -> mp_debug_drv_flag;
	mp_rom_drv_init_area -> rom_disable = 0;

	if ((rval = me90drv_submit_mp_task(state, drv_load_mp_task,
			mp_drv_init_info_p, 1, NULL, &drv_load_results,
			drv_comm_area_locked)) != 0) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mcka_restart_mp failed - MP driver init errors\n");
		return rval;
	}
	if (drv_load_results.mp_init_results.mp_error_code != 0) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mcka_restart_mp failed - with error detected by MP"
			" driver 0x%02x\n",
			drv_load_results.mp_init_results.mp_error_code & 0xff);
		return rval;
	}
	ME90_LOG(state, ME90_DL_TRACE, "mcka_restart_mp successed\n");
	return 0;
}

/*
 * Restart all synchronous channels:  start waiting for execution transfers.
 */

/*ARGSUSED*/
void
mcka_restart_all_sync_channel(mcb_state_t	*state)
{
	int			cur_chnl = 0;

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_restart_all_sync_channel started \n");
	for (cur_chnl = 0; cur_chnl < MAX_ME90DRV_BOARD_CHANNEL_NUM;
	     cur_chnl ++) {
			me90drv_start_new_trans(state,cur_chnl);
	}

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_restart_all_sync_channel finished \n");
}

/*
 * Process all terminated transfers in all channels
 */

/*ARGSUSED*/
void
mcka_terminate_all_dma_trans(mcb_state_t	*state)
{
	int	cur_chnl = 0;

	ME90_LOG(state, ME90_DL_TRACE, "mcka_terminate_all_dma_trans started\n");

	for (cur_chnl = 0; cur_chnl < MAX_ME90DRV_BOARD_CHANNEL_NUM;
	     cur_chnl ++)
		mcka_terminate_dma_trans(state, cur_chnl);

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_terminate_all_dma_trans successed\n");
}

/*
 * Retrieve MP and transfers execution after hangup of MP or other errors
 * occured in the board.
 */

/*ARGSUSED*/
int
me90_retrieve_trans_mode(
	mcb_state_t		*state,
	int			drv_comm_area_locked,
	int			unconditional_restsrt,
	me90drv_rd_reg_t	gen_reg_state)
{
	int			cur_chnl = 0;
	me90drv_chnl_state_t	*cur_channel_state = NULL;
	int			rval = 0;
	int			retrieve_reason = 0;
	int			error_code = 0;

	ME90_LOG(state,ME90_DL_TRACE, "mcka_retrieve_trans_mode started\n");

	mutex_enter(&state->mutex);			/* start MUTEX */
	if (!drv_comm_area_locked) {
		while (state -> drv_comm_busy)
			cv_wait_sig(&state -> drv_comm_cv, &state->mutex);
		//	cv_spin_wait(&state -> drv_comm_cv, &state->lock);
		state -> drv_comm_busy = 1;
	} else if (!state -> drv_comm_busy)
		ME90_LOG(state, ME90_DL_ERROR,
			"mcka_retrieve_trans_mode interdriver communication "
			"area not locked\n");
	retrieve_reason = state -> mp_state;
	if (retrieve_reason != hangup_mp_state				&&
	    retrieve_reason != fault_mp_state				&&
	    retrieve_reason != adapter_abend_mp_state			&&
	    !(retrieve_reason == crash_mp_state && unconditional_restsrt)) {
		if (!drv_comm_area_locked) {
			state -> drv_comm_busy = 0;
			cv_broadcast(&state -> drv_comm_cv);
		}
		mutex_exit(&state->mutex);		/* end MUTEX */
		ME90_LOG(state,ME90_DL_TRACE,
			"mcka_retrieve_trans_mode retrieved already\n");
		return 0;
	} else if ((!(state -> drv_general_modes & RETRIEVE_MP_HANGUP_DRV_MODE) &&
		   retrieve_reason == hangup_mp_state) ||
		   (!(state -> drv_general_modes & RETRIEVE_DEV_FAULT_DRV_MODE) &&
		   retrieve_reason == fault_mp_state) ||
		   (!(state -> drv_general_modes & RETRIEVE_DEV_FAULT_DRV_MODE) &&
		   retrieve_reason == adapter_abend_mp_state)) {
		if (retrieve_reason == hangup_mp_state)
			rval = EMPHANGUP;
		else if (retrieve_reason == fault_mp_state)
			rval = EDEVFAULT;
		else if (retrieve_reason == adapter_abend_mp_state)
			rval = EADPTABEND;
		else
			rval = EIO;
		if (!drv_comm_area_locked) {
			state -> drv_comm_busy = 0;
			cv_broadcast(&state -> drv_comm_cv);
		}
		mutex_exit(&state->mutex);		/* end MUTEX */
		ME90_LOG(state,ME90_DL_TRACE,
			"mcka_retrieve_trans_mode retrieved locked by general "
			"driver mode\n");
		return rval;
	}
	ME90_LOG(state,ME90_DL_ERROR,
		"retrieve of transfer state started !!!\n");
	state -> mp_state = restarted_mp_state;
	if (retrieve_reason == hangup_mp_state)
		error_code = EMPHANGUP;
	else if (retrieve_reason == fault_mp_state)
		error_code = EDEVFAULT;
	else if (retrieve_reason == adapter_abend_mp_state)
		error_code = EADPTABEND;
	else if (retrieve_reason == crash_mp_state)
		error_code = EMPCRASH;
	else {
		ME90_LOG(state,ME90_DL_ERROR,
			"mcka_retrieve_trans_mode bad MP state\n");
		error_code = EMPHANGUP;
	}
	for (cur_chnl = 0; cur_chnl < MAX_ME90DRV_BOARD_CHANNEL_NUM;
	     cur_chnl ++) {
		cur_channel_state = &state -> all_channels_state[cur_chnl];
		while (cur_channel_state -> in_progress_start != NULL) {
			mcka_finish_dma_engine_on_error(state, cur_chnl,
				gen_reg_state, error_code);
		}
	}
	rval = mcka_restart_mp(state,1);
	if (rval != 0) {
		state -> mp_state = crash_mp_state;
		me90drv_delete_connection_polling(state, EMPCRASH);

		if (!drv_comm_area_locked) {
			state -> drv_comm_busy = 0;
			cv_broadcast(&state -> drv_comm_cv);
		}
		mutex_exit(&state->mutex);		/* end MUTEX */
		ME90_LOG(state,ME90_DL_ERROR,
			"mcka_retrieve_trans_mode cannot restart MP\n");
		mcka_restart_all_sync_channel(state);
		mcka_terminate_all_dma_trans(state);
		return EMPCRASH;
	}
	rval = me90drv_recover_trans_state(state, 1, 1);
	if (rval != 0)
		ME90_LOG(state,ME90_DL_ERROR,
			"mcka_retrieve_trans_mode cannot recover transfer"
			" state\n");
	if (!drv_comm_area_locked) {
		state -> drv_comm_busy = 0;
		cv_broadcast(&state -> drv_comm_cv);
	}
	mutex_exit(&state->mutex);				/* end MUTEX */
	mcka_restart_all_sync_channel(state);
	mcka_terminate_all_dma_trans(state);

	ME90_LOG(state,ME90_DL_ERROR, "mcka_retrieve_trans_mode successed\n");

	return rval;
}

/*
 * Interrupt MP and waiting MP reaction.
 * Mutex must be provided by caller
 */

/*ARGSUSED*/
int
mcka_interrupt_mp(
	mcb_state_t	*state,
	int		mp_restart,
	int		wait_mp_task_accept,
	int		wait_mp_rom_drv_disable)
{
	volatile me90drv_cntr_st_reg_t	*general_regs = NULL;
	me90drv_drv_intercom_t		*drv_communication = NULL;
	me90_mp_rom_drv_t		*mp_rom_drv_init_area = NULL;
#ifndef	_WITHOUT_MP_INTERRUPT_
	me90drv_rd_reg_t		cur_regs_value;
	me90drv_wr_reg_t		intr_set_value;
#endif	/* _WITHOUT_MP_INTERRUPT_ */
	int				waiting_time = 0;
#ifndef	_WITHOUT_MP_INTERRUPT_
	int				intr_processed = 0;
#endif	/* _WITHOUT_MP_INTERRUPT_ */
	int				task_accepted = 0;
	int				rom_disable = 0;
	int				cur_tryon = 0;

	ME90_LOG(state, ME90_DL_TRACE, "mcka_interrupt_mp started\n");
	ME90_LOG(state, ME90_DL_TRACE, "mcka_interrupt_mp: mp_restart = 0x%x\n", 
						mp_restart);
	ME90_LOG(state, ME90_DL_TRACE, "mcka_interrupt_mp: wait_mp_task_accept = 0x%x\n", 
						wait_mp_task_accept);
	ME90_LOG(state, ME90_DL_TRACE, "mcka_interrupt_mp: wait_mp_rom_drv_disable = 0x%x\n", 
						wait_mp_rom_drv_disable);

	general_regs = state -> ME90DRV_CNTR_ST_REGS;
	drv_communication =
		(me90drv_drv_intercom_t *) &state -> ME90DRV_INTERDRV_COMN_AREA;
	if (wait_mp_rom_drv_disable)
		mp_rom_drv_init_area = (me90_mp_rom_drv_t *)
			&state -> ME90DRV_BMEM[ME90_MP_ROM_DRV_INIT_ADDR];

#ifndef	_WITHOUT_MP_INTERRUPT_

#ifndef WITHOUT_TWISTING
	b2l_convertor_off(state->dip);
#endif
	me90drv_read_general_regs(general_regs, ME90DRV_TI_reg_type,
		&cur_regs_value);
#ifndef WITHOUT_TWISTING
	b2l_convertor_on(state->dip);
#endif
	if (cur_regs_value.ME90DRV_RGEN_TI_read == 1) {
		/* MP did not processed interrupt */
		if (cur_regs_value.ME90DRV_RGEN_TMI_read == 0) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_interrupt_mp MP interrupt is masked,"
				" so not processed\n");
		} else {
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_interrupt_mp last MP interrupt not"
				" processed by MP\n");
		}
		return EMPHANGUP;
	}
	if (!mp_restart) {
		intr_set_value.ME90DRV_RGEN_RERR_write = 0;
		intr_set_value.ME90DRV_RGEN_TI_write = 1;
		/* interrupt MP, interrupt mask can be set by MP */
#ifndef WITHOUT_TWISTING
		b2l_convertor_off(state->dip);
#endif
		me90drv_write_general_regs(general_regs, ME90DRV_TI_reg_type,
			intr_set_value,  &cur_regs_value);
#ifndef WITHOUT_TWISTING
		b2l_convertor_on(state->dip);
#endif
		/*
		 *  Waiting Loop of interrupt reset by MP driver
		 */

		waiting_time = 0;
		intr_processed = 0;
		while (waiting_time < ME90DRV_INTR_RESET_BY_MP_TIME &&
							!intr_processed) {
			for (cur_tryon = 0;
			     cur_tryon <= ME90DRV_INTR_RESET_BY_MP_TRYON;
		 	     cur_tryon++) {
#ifndef WITHOUT_TWISTING
				b2l_convertor_off(state->dip);
#endif
				me90drv_read_general_regs(general_regs,
					ME90DRV_TI_reg_type, &cur_regs_value);
#ifndef WITHOUT_TWISTING
				b2l_convertor_on(state->dip);
#endif
				if (cur_regs_value.ME90DRV_RGEN_TI_read == 1)
					continue;
				intr_processed = 1;
				break;
			}
			if (intr_processed)
				break;
// Sol in mksec		drv_usecwait(TASK_ACCEPT_BY_MP_DELAY_TIME);
/* Lin mksec */		udelay(TASK_ACCEPT_BY_MP_DELAY_TIME);
			waiting_time += INTR_RESET_BY_MP_DELAY_TIME;
		}
		if (!intr_processed) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_interrupt_mp interrupt not processed "
				"by MP for time %d mks + %d try on\n",
				waiting_time,cur_tryon);
			return EMPHANGUP;
		}
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_interrupt_mp interrupt was processed by MP for"
			" time %d mks + %d try on\n",
			waiting_time,cur_tryon);
	}
#endif	/* _WITHOUT_MP_INTERRUPT_ */
	if (mp_restart) {
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
		if (drv_communication -> mp_task == no_mp_task) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_interrupt_mp MP task is empty already\n");
		}
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
		if (me90drv_reset_general_regs(state, 0) != 0) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_interrupt_mp restart of MP finished"
				" with error\n");
		}
	}

	/*
	 *  Waiting Loop of current task field reset by MP driver
	 */

	if (wait_mp_task_accept || wait_mp_rom_drv_disable) {
		waiting_time = 0;
		task_accepted = 0;
		rom_disable = 0;
		while (waiting_time < ME90DRV_TASK_ACCEPT_BY_MP_TIME &&
			!task_accepted && !rom_disable) {
			for (cur_tryon = 0;
			     cur_tryon < ME90DRV_TASK_ACCEPT_BY_MP_TRYON;
			     cur_tryon ++) {
#ifndef WITHOUT_TWISTING
				b2l_convertor_off(state->dip);
#endif
				if (drv_communication -> mp_task ==
					no_mp_task) {
#ifndef WITHOUT_TWISTING
					b2l_convertor_on(state->dip);
#endif
					task_accepted = 1;
					break;
				} else if (wait_mp_rom_drv_disable) {
					if (mp_rom_drv_init_area ->
							rom_disable) {
#ifndef WITHOUT_TWISTING
						b2l_convertor_on(state->dip);
#endif
						rom_disable = 1;
						break;
					}
				}
#ifndef WITHOUT_TWISTING
				b2l_convertor_on(state->dip);
#endif
			}
			if (task_accepted || rom_disable)
				break;
// Sol mksec		drv_usecwait(ME90DRV_TASK_ACCEPT_BY_MP_DELAY_TIME);
/* Lin mksec */		udelay(ME90DRV_TASK_ACCEPT_BY_MP_DELAY_TIME);
			waiting_time += ME90DRV_TASK_ACCEPT_BY_MP_DELAY_TIME;
		}
		if (rom_disable) {
			return EMPROMDISABLE;
		} else if (!task_accepted) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_interrupt_mp Mp did not accept task for"
				" time %d mks + %d try on\n",
				waiting_time, cur_tryon);
			return EMPHANGUP;
		}
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_interrupt_mp MP accepted task for time %d"
		" mks + %d try on\n", waiting_time, cur_tryon);
	ME90_LOG(state, ME90_DL_TRACE, "mcka_interrupt_mp successed\n");
	return 0;
}

/*
 * Write MP task arguments into interdriver communication area, submit MP
 * to execute the task and waiting MP reaction
 */

/*ARGSUSED*/
int
submit_mp_task(
     mcb_state_t *	state,
     mp_task_t		mp_task,
     mp_drv_args_t *	task_args,
     int		mutex_enter_done,
     trans_info_t *	trans_res_info,
     sparc_drv_args_t *	mp_task_results,
     int		restart
     )
{
	drv_intercom_t		*drv_communication = NULL;
	int			args_num = 0;
	int			cur_arg = 0;
	int			channel = 0;
	me90drv_chnl_state_t	*channel_state = NULL;
#ifndef	__WAIT_MP_TASK_ACCEPT__
	int			waiting_time = 0;
	int			task_accepted = 0;
	int			cur_tryon = 0;
#endif /* __WAIT_MP_TASK_ACCEPT__ */
	int			wait_mp_task_accept = 0;
	int			wait_mp_rom_drv_disable = 0;
	int			rval = 0;

     dbgmcka("submit_mp_task started with task # %d\n",
             mp_task
            );
     drv_communication =
        (drv_intercom_t *) &state -> MC_BMEM[TR_CNTR_BUF_BMEM_ADDR];
     switch (mp_task)
     {
        case data_transfer_mp_task     :
        case transfer_abort_mp_task    :
        case drq_data_transfer_mp_task :
           args_num =
              (sizeof(trans_desk_t) +
               (sizeof(*drv_communication -> mp_args.args_area)-1)
              ) / sizeof(*drv_communication -> mp_args.args_area);
           channel = task_args -> transfer.dev_num;
           channel_state = &state -> all_channels_state[channel];
	   dbgmcka("submit_mp_task: mp_task = 0x%x, args_num = 0x%x\n",
		mp_task, args_num);
/*	   dbgmcka("submit_mp_task: sizeof(trans_desk_t) = 0x%x\n", sizeof(trans_desk_t));
	   dbgmcka("submit_mp_task: sizeof(*drv_communication -> mp_args.args_area) = 0x%x\n",
				sizeof(*drv_communication -> mp_args.args_area)); */
           break;
        case drv_load_mp_task :
           if (task_args != NULL)
              args_num = sizeof(drv_communication -> mp_args.args_area);
           else
              args_num = 0;
           if (mp_task_results != NULL)
              mp_task_results -> mp_init_results.mp_error_code = 0;
           break;
        case mp_timer_intr_set_mp_task :
           args_num =
              (sizeof(mp_tm_set_t) +
               (sizeof(*drv_communication -> mp_args.args_area)-1)
              ) / sizeof(*drv_communication -> mp_args.args_area);
           break;
        case init_streaming_mp_task :
           args_num =
              (sizeof(init_strm_t) +
               (sizeof(*drv_communication -> mp_args.args_area)-1)
              ) / sizeof(*drv_communication -> mp_args.args_area);
           channel = task_args -> transfer.dev_num;
           channel_state = &state -> all_channels_state[channel];
           if (mp_task_results != NULL)
              mp_task_results -> transfer.mp_error_code = 0;
           break;
        case halt_streaming_mp_task :
           args_num =
              (sizeof(halt_strm_t) +
               (sizeof(*drv_communication -> mp_args.args_area)-1)
              ) / sizeof(*drv_communication -> mp_args.args_area);
           break;
        case init_trans_state_mp_task :
           args_num =
              (sizeof(init_trst_t) +
               (sizeof(*drv_communication -> mp_args.args_area)-1)
              ) / sizeof(*drv_communication -> mp_args.args_area);
           if (mp_task_results != NULL)
              mp_task_results -> init_state_res.mp_error_code = 0;
           break;
        case halt_trans_state_mp_task :
           args_num =
              (sizeof(halt_trst_t) +
               (sizeof(*drv_communication -> mp_args.args_area)-1)
              ) / sizeof(*drv_communication -> mp_args.args_area);
           break;
        case set_timetable_mp_task :
           args_num =
              (sizeof(set_timetable_t) +
               (sizeof(*drv_communication -> mp_args.args_area)-1)
              ) / sizeof(*drv_communication -> mp_args.args_area);
           break;
        case device_adapter_write_mp_task :
        case device_adapter_read_mp_task  :
           args_num =
              (sizeof(adapter_access_t) +
               (sizeof(*drv_communication -> mp_args.args_area)-1)
              ) / sizeof(*drv_communication -> mp_args.args_area);
           if (mp_task_results != NULL)
              mp_task_results -> reg_read_results.mp_error_code = 0;
           break;
        case set_cnct_polling_mp_task  :
           args_num =
              (sizeof(cnct_poll_args_t) +
               (sizeof(*drv_communication -> mp_args.args_area)-1)
              ) / sizeof(*drv_communication -> mp_args.args_area);
           break;
        case halt_trans_mode_mp_task    :
        case reset_cnct_polling_mp_task :
           args_num = 0;
           break;
        case no_mp_task :
        default:
           ME90_LOG(state, ME90_DL_ERROR,
                  "submit_mp_task invalid MP task # %d\n",
                  mp_task
                 );
           return EINVAL;
     }
     dbgmcka("MCKA: submit_mp_task: before spin_mutex_enter, mutex_enter_done = %d\n", mutex_enter_done);
     if (!mutex_enter_done)
     {
	mutex_enter(&state->mutex);			/* start MUTEX */
     }
     dbgmcka("MCKA: submit_mp_task: after spin_mutex_enter, mutex_enter_done = %d\n", mutex_enter_done);
     while (state -> drv_comm_busy && !restart)
     {
	cv_wait_sig(&state -> drv_comm_cv, &state->mutex);
	//cv_spin_wait(&state -> drv_comm_cv, &state->lock);
     }
     dbgmcka("MCKA: submit_mp_task: cv_spin_wait mp_task #%d\n", mp_task);
     if (!restart)
        state -> drv_comm_busy = 1;
     else if (!state -> drv_comm_busy)
        ME90_LOG(state, ME90_DL_ERROR,
                "submit_mp_task interdriver communication area not locked\n"
               );

     dbgmcka("MCKA: submit_mp_task: mp_drv_started = %d, mp_task #%d\n", state -> mp_drv_started, mp_task);
     if (!state -> mp_drv_started && mp_task != drv_load_mp_task)
     {
        dbgmcka("MCKA: submit_mp_task: !state -> mp_drv_started && mp_task != drv_load_mp_task case\n");
        if (!restart)
        {
           state -> drv_comm_busy = 0;
           cv_broadcast(&state -> drv_comm_cv);
        }
        if (!mutex_enter_done)
	{
           mutex_exit(&state->mutex);			/* end MUTEX */
	}
        ME90_LOG(state, ME90_DL_ERROR,
                "submit_mp_task MP driver did not strarted up\n"
               );
        return EINVAL;
     }
     dbgmcka("MCKA: submit_mp_task: mp_task #%d\n", mp_task);
     if (state -> mp_state != started_mp_state && mp_task != drv_load_mp_task)
     {
        ME90_LOG(state, ME90_DL_ERROR,
                "submit_mp_task MP driver is in abnormal state\n"
               );
        if (state -> mp_state == crash_mp_state)
        {
           if (!restart)
           {
              state -> drv_comm_busy = 0;
              cv_broadcast(&state -> drv_comm_cv);
           }
           if (!mutex_enter_done)
	   {
              mutex_exit(&state->mutex);			/* end MUTEX */
	   }
           ME90_LOG(state, ME90_DL_ERROR,"submit_mp_task MP driver crash\n");
           return EMPCRASH;
        }
        else if ((!(state -> drv_general_modes & RETRIEVE_MP_HANGUP_DRV_MODE) &&
                 state -> mp_state == hangup_mp_state )                         ||
                 (!(state -> drv_general_modes & RETRIEVE_DEV_FAULT_DRV_MODE) &&
                 state -> mp_state == fault_mp_state )                          ||
                 (!(state -> drv_general_modes & RETRIEVE_DEV_FAULT_DRV_MODE) &&
                 state -> mp_state == adapter_abend_mp_state)
                )
        {
           if (state -> mp_state == hangup_mp_state)
              rval = EMPHANGUP;
           else if (state -> mp_state == fault_mp_state)
              rval = EDEVFAULT;
           else if (state -> mp_state == adapter_abend_mp_state)
              rval = EADPTABEND;
           else
              rval = EIO;
           if (!restart)
           {
              state -> drv_comm_busy = 0;
              cv_broadcast(&state -> drv_comm_cv);
           }
           if (!mutex_enter_done)
	   {
              mutex_exit(&state->mutex);			/* end MUTEX */
           }
           ME90_LOG(state, ME90_DL_ERROR,
                   "submit_mp_task abnormal device or MP state\n"
                  );
           return rval;
        }
        if (!mutex_enter_done)
        {
           mc_rd_reg_t	gen_reg_state;
           gen_reg_state.RGEN_read = 0;
           mutex_exit(&state->mutex);			/* end MUTEX */
           rval = me90_retrieve_trans_mode(state,1,0,gen_reg_state);
           if (!mutex_enter_done)
	   {
              mutex_enter(&state->mutex);		/* start MUTEX */
	   } 
           if (rval != 0)
           {
              state -> mp_state = crash_mp_state;
              me90drv_delete_connection_polling(state, EMPCRASH);
              if (!restart)
              {
                 state -> drv_comm_busy = 0;
                 cv_broadcast(&state -> drv_comm_cv);
              }
              if (!mutex_enter_done)
	      { 
                 mutex_exit(&state->mutex);		/* end MUTEX */
              }
              ME90_LOG(state, ME90_DL_ERROR,
                      "submit_mp_task MP driver restart failed\n"
                     );
              return EMPCRASH;
           }
        }
        else
        {
           if (!restart)
           {
              state -> drv_comm_busy = 0;
              cv_broadcast(&state -> drv_comm_cv);
           }
           if (!mutex_enter_done)
	   {
              mutex_exit(&state->mutex);			/* end MUTEX */
           }
           ME90_LOG(state, ME90_DL_ERROR,
                   "submit_mp_task MP driver cannot be restarted\n"
                  );
           if (state -> mp_state == hangup_mp_state)
              rval = EMPHANGUP;
           else if (state -> mp_state == fault_mp_state)
              rval = EDEVFAULT;
           else if (state -> mp_state == adapter_abend_mp_state)
              rval = EADPTABEND;
           else
              rval = EIO;
           return rval;
        }
        switch (mp_task)
        {
           case data_transfer_mp_task     :
           case transfer_abort_mp_task    :
           case drq_data_transfer_mp_task :
           case init_streaming_mp_task    :
           case reset_cnct_polling_mp_task:
              if (!restart)
              {
                 state -> drv_comm_busy = 0;
                 cv_broadcast(&state -> drv_comm_cv);
              }
              if (!mutex_enter_done)
	      {
                 mutex_exit(&state->mutex);		/* end MUTEX */
              }
              return EMPRESTART;
           case halt_streaming_mp_task        :
           case mp_timer_intr_set_mp_task     :
           case init_trans_mode_mp_task       :
           case init_trans_state_mp_task      :
	   case halt_trans_state_mp_task      :
           case set_timetable_mp_task         :
           case device_adapter_write_mp_task  :
           case device_adapter_read_mp_task   :
           case halt_trans_mode_mp_task       :
           case set_cnct_polling_mp_task      :
              break;
           case no_mp_task       :
           case drv_load_mp_task :
           default               :
              state -> mp_state = crash_mp_state;
              me90drv_delete_connection_polling(state, EMPCRASH);
              if (!restart)
              {
                 state -> drv_comm_busy = 0;
                 cv_broadcast(&state -> drv_comm_cv);
              }
              if (!mutex_enter_done)
	      { 
                 mutex_exit(&state->mutex);		/* end MUTEX */
              } 
              ME90_LOG(state, ME90_DL_ERROR,
                     "submit_mp_task invalid MP task # %d\n",
                     mp_task
                    );
              return EINVAL;
        }
     }

#ifndef	__WAIT_MP_TASK_ACCEPT__
     /*
      *  Waiting Loop of last task field freed by MP driver
      */
     if (!mutex_enter_done)
     {  
        mutex_exit(&state->mutex);			/* end MUTEX */
     }
     waiting_time = 0;
     task_accepted = 0;
     while (waiting_time < TASK_ACCEPT_BY_MP_TIME && !task_accepted)
     {
        for (cur_tryon = 0; cur_tryon < TASK_ACCEPT_BY_MP_TRYON; cur_tryon ++)
        {
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
           if (drv_communication -> mp_task != no_mp_task){
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
              continue;
	   }
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
           task_accepted = 1;
           break;
        };
        if (task_accepted)
           break;
	  udelay(TASK_ACCEPT_BY_MP_DELAY_TIME);
/*        drv_usecwait(TASK_ACCEPT_BY_MP_DELAY_TIME); */
        waiting_time += TASK_ACCEPT_BY_MP_DELAY_TIME;
     };
#else
     wait_mp_task_accept = 1;
#endif	/* __WAIT_MP_TASK_ACCEPT__ */
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
     if (drv_communication -> mp_task != no_mp_task)
     {
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
        ME90_LOG(state, ME90_DL_ERROR,
                "submit_mp_task MP hangup - MP task field busy by task # %d\n",
                drv_communication -> mp_task
               );
        if (!mutex_enter_done)
	{
           mutex_enter(&state->mutex);			/* start MUTEX */
	}
        state -> mp_state = hangup_mp_state;
        me90drv_delete_connection_polling(state, EMPHANGUP);
        if (!restart)
        {
           state -> drv_comm_busy = 0;
           cv_broadcast(&state -> drv_comm_cv);
        }
        if (!mutex_enter_done)
	{
           mutex_exit(&state->mutex);			/* end MUTEX */
	}
        return EMPHANGUP;
     }
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
     for (cur_arg = 0; cur_arg < args_num; cur_arg ++)
     {
        drv_communication -> mp_args.args_area[cur_arg] =
           task_args -> args_area[cur_arg];
	ME90_LOG(state, ME90_DL_TRACE, "submit_mp_task: task_args -> args_area[%d] = 0x%x\n",
		cur_arg, task_args -> args_area[cur_arg]);
     }
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
     drv_communication -> mp_task = mp_task;
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
     if (trans_res_info != NULL)
#ifdef	_MP_TIME_USE_
        READ_MP_TIME(trans_res_info -> transfer_start);
#else
        trans_res_info -> transfer_start = ddi_gethrtime();
#endif	/* _MP_TIME_USE_ */
     wait_mp_task_accept |= (mp_task == drv_load_mp_task            ||
                             mp_task == init_streaming_mp_task      ||
                             mp_task == init_trans_mode_mp_task     ||
                             mp_task == init_trans_state_mp_task    ||
                             mp_task == device_adapter_read_mp_task ||
                             mp_task == reset_cnct_polling_mp_task
                            );
	wait_mp_rom_drv_disable = (mp_task == drv_load_mp_task);
     rval = mcka_interrupt_mp(state,mp_task == drv_load_mp_task,
			wait_mp_task_accept, wait_mp_rom_drv_disable);
     if (!mutex_enter_done)
     {  	
	     mutex_enter(&state->mutex);			/* start MUTEX */
     }
     if (rval == 0 && mp_task == drv_load_mp_task)
        state -> mp_state = started_mp_state;
     else if (rval == EMPROMDISABLE) {
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
		drv_communication -> mp_task = no_mp_task;
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
		state -> mp_state = halted_mp_state;
     } else if (rval != 0) {
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
        ME90_LOG(state, ME90_DL_ERROR,
                "submit_mp_task MP hangup - not take the task %d\n",
                drv_communication -> mp_task
               );
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
        state -> mp_state = hangup_mp_state;
        me90drv_delete_connection_polling(state, EMPHANGUP);
     }
     if (
         mp_task == init_streaming_mp_task      ||
         mp_task == init_trans_state_mp_task    ||
         mp_task == device_adapter_read_mp_task
        )
     {
        char	task_not_complete = 0;

#ifndef	__WAIT_SPARC_TASK_ACCEPT__
        /*
         *  Waiting for sparc task field will be set MP driver
         */

        waiting_time = 0;
        task_accepted = 0;
        while (waiting_time < TASK_ACCEPT_BY_MP_TIME && !task_accepted)
        {
           for (cur_tryon = 0; cur_tryon<TASK_ACCEPT_BY_MP_TRYON; cur_tryon ++)
           {
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
              if (drv_communication -> sparc_task == no_sparc_task){
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
                 continue;
	      }
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
              task_accepted = 1;
              break;
           };
           if (task_accepted)
              break;
/*         drv_usecwait(TASK_ACCEPT_BY_MP_DELAY_TIME); */
           waiting_time += TASK_ACCEPT_BY_MP_DELAY_TIME;
        };
#endif	/* __WAIT_SPARC_TASK_ACCEPT__ */
        for (cur_arg = 0;
             cur_arg < (sizeof(drv_communication -> sparc_args.args_area) +
                        (sizeof(*drv_communication -> sparc_args.args_area) - 1)
                       ) / sizeof(*drv_communication -> sparc_args.args_area);
             cur_arg ++)
        {
           mp_task_results -> args_area[cur_arg] =
              drv_communication -> sparc_args.args_area[cur_arg];
        }
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
        if ((
             drv_communication -> sparc_task != init_streaming_end_mp_task   &&
             drv_communication -> sparc_task != init_trans_state_end_mp_task &&
             drv_communication -> sparc_task !=
             device_adapter_read_end_mp_task
            )                                                                &&
            rval == 0
           )
        {
           task_not_complete = 1;
           if (mp_task == drv_load_mp_task)
           {
              mp_task_results -> mp_init_results.mp_error_code =
                 NOT_COMPLETE_TASK_BY_MP_ERROR;
              ME90_LOG(state, ME90_DL_ERROR,
                      "submit_mp_task MP driver load failed: not completed\n"
                     );
           }
           else if (mp_task == init_trans_mode_mp_task)
           {
              mp_task_results -> init_trans_results.mp_error_code =
                 NOT_COMPLETE_TASK_BY_MP_ERROR;
              ME90_LOG(state, ME90_DL_ERROR,
                      "submit_mp_task init transfer mode failed: "
                      "not completed\n"
                     );
           }
           else if (mp_task == init_streaming_mp_task)
           {
              mp_task_results -> transfer.mp_error_code =
                 NOT_COMPLETE_TASK_BY_MP_ERROR;
              ME90_LOG(state, ME90_DL_ERROR,
                      "submit_mp_task init streaming transfer failed: "
                      "not completed\n"
                     );
           }
           else if (mp_task == init_trans_state_mp_task)
           {
              mp_task_results -> init_state_res.mp_error_code =
                 NOT_COMPLETE_TASK_BY_MP_ERROR;
              ME90_LOG(state, ME90_DL_ERROR,
                      "submit_mp_task init channel transfer state failed: "
                      "not completed\n"
                     );
           }
           else if (mp_task == device_adapter_read_mp_task)
           {
              mp_task_results -> reg_read_results.mp_error_code =
                 NOT_COMPLETE_TASK_BY_MP_ERROR;
              ME90_LOG(state, ME90_DL_ERROR,
                      "submit_mp_task device aregister read failed: "
                      "not completed\n"
                     );
           }
        }
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
        if (mp_task_results -> mp_init_results.mp_error_code != 0 &&
            mp_task == drv_load_mp_task                           &&
            rval == 0                                             &&
            !task_not_complete
           )
        {
           ME90_LOG(state, ME90_DL_ERROR,
                   "submit_mp_task MP driver load failed: error 0x%02x\n",
                   mp_task_results -> mp_init_results.mp_error_code & 0xff
                  );
        }
        if (mp_task_results -> transfer.mp_error_code != 0 &&
            mp_task == init_streaming_mp_task              &&
            rval == 0                                      &&
            !task_not_complete
           )
        {
           ME90_LOG(state, ME90_DL_ERROR,
                   "submit_mp_task init streaming transfer: error 0x%02x\n",
                   mp_task_results -> transfer.mp_error_code & 0xff
                  );
        }
        if (mp_task == init_trans_state_mp_task)
        {
           if (mp_task_results -> init_state_res.mp_error_code != 0 &&
               rval == 0                                               &&
               !task_not_complete
              )
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "submit_mp_task init channel transfer state: error"
                      " 0x%02x\n",
                      mp_task_results -> init_state_res.mp_error_code & 0xff
                     );
           }
        }
        if (mp_task == device_adapter_read_mp_task)
        {
           if (mp_task_results -> reg_read_results.mp_error_code != 0 &&
               rval == 0                                              &&
               !task_not_complete
              )
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "submit_mp_task read device reg: error 0x%02x\n",
                      mp_task_results -> reg_read_results.mp_error_code & 0xff
                     );
           }
           task_args -> dev_adapter_access.reg_value =
              mp_task_results -> reg_read_results.read_value;
        }
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
        drv_communication -> sparc_task = no_sparc_task;
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
     }
     if (rval == 0 && channel_state != NULL)
     {
        if (mp_task == data_transfer_mp_task      ||
            mp_task == drq_data_transfer_mp_task  ||
            mp_task == init_streaming_mp_task
           )
        {
	   
           channel_state -> in_progress = 1;
           cv_broadcast(&state -> trans_start_cv);
        }
     }
     if (!restart)
     {
        state -> drv_comm_busy = 0;
        cv_broadcast(&state -> drv_comm_cv);
     }
     if (!mutex_enter_done)
     {	
        mutex_exit(&state->mutex);			/* end MUTEX */
     } 
     ME90_LOG(state, ME90_DL_TRACE,"submit_mp_task finished for task # %d\n",
             mp_task
            ); /* !!!!! */
     return rval;
}

/*
 * Release all transfer in the list of ready asynchronous transfers
 */

/*ARGSUSED*/
void
mcka_release_all_async_trans(
	mcb_state_t	*state,
	int		channel)
{
	me90drv_chnl_state_t	*channel_state = NULL;
	me90drv_trans_buf_t	*trans_buf_p = NULL;

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_release_all_async_trans started for channel %d\n",
		channel);

	channel_state = &state -> all_channels_state[channel];
	while (1) {
		mutex_enter(&state->mutex);		/* start MUTEX */
		trans_buf_p = channel_state -> ready_atrans_start;
		if (trans_buf_p == NULL) {
			mutex_exit(&state->mutex);	/* end MUTEX */
			break;
		}
		channel_state -> ready_atrans_start =
			trans_buf_p -> next_trans_buf;
		if (channel_state -> ready_atrans_start == NULL)
			channel_state -> ready_atrans_end = NULL;
		channel_state -> ready_atrans_size --;
		channel_state -> async_trans_num --;
		mutex_exit(&state->mutex);		/* end MUTEX */
		ME90_LOG(state, ME90_DL_WARNING,
			"mcka_release_all_async_trans asynchronous transfer"
			" 0x%08x in the channel %d will be deleted\n",
			trans_buf_p, channel);
		me90drv_release_async_trans(state, channel, trans_buf_p);
	}
	if (channel_state -> async_trans_num != 0) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mcka_release_all_async_trans not empty asynchronous"
			" transfer counter = %d in the channel %d\n",
			channel_state -> async_trans_num, channel);
		channel_state -> async_trans_num = 0;
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_release_all_async_trans finished for channel %d\n",
		channel);
}

#ifdef DEBUG_BUF_USE
/*
 * Output  message from buffer to the console and/or syslog with cmn_err
 */
/*ARGSUSED*/
void mcka_out_debug_msg_buf(void)
{
	int	cur_line = 0;

	if (me90_debug_buf_line == 0 && !me90_debug_buf_overflow)
		return;
	if (me90_debug_buf_overflow)
	{
		for (cur_line = me90_debug_buf_line;
		     cur_line < ME90_DEBUG_MSG_LINE_NUM;
		     cur_line ++
		    )
		{
			printk(KERN_ERR "^%s\n",
			        &me90_debug_msg_buf[cur_line * 
                                                   ME90_DEBUG_MSG_LINE_SIZE
                                                  ]
                               );
// Sol ticks		delay(1 * drv_usectohz(10000));
/* Lin mksec */		udelay(1 * 10000);
		}
	}
	for (cur_line = 0;
	     cur_line < me90_debug_buf_line;
	     cur_line ++
	    )
	{
		printk(KERN_ERR "^%s\n",
		        &me90_debug_msg_buf[cur_line * 
					   ME90_DEBUG_MSG_LINE_SIZE
					  ]
                       );
// Sol ticks	delay(1 * drv_usectohz(10000));
/* Lin mksec */	udelay(1 * 10000);
	}
}
#endif /* DEBUG_BUF_USE */

/*
 * Driver close entry point
 */
/*ARGSUSED*/
/*static*/	int
mcka_close(struct inode *inode, struct file *file)
{
	mcb_state_t	*state = (mcb_state_t *)file->private_data;
	me90drv_chnl_state_t	*channel_state = NULL;
	dev_t		dev;
	int			instance = 0;
	int			channel = 0;
	u_long		cur_clock_ticks = 0;
	u_long		timeout_clock_ticks = 0;
	int			rval = 0;

	ME90_LOG(NULL, ME90_DL_TRACE, "%s(): started, instance %d channel %d\n", __func__, instance, channel);

	if ( state == NULL ) {
		printk(KERN_ERR "%s(): О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫.\n", __func__);
		return -ENXIO;
	}

	dev = state->dev;
	if ( !dev )
		return (ENXIO);

	instance = MCB_INST(dev);
	channel = MCB_CHAN(dev);

	channel_state = &state -> all_channels_state[channel];

	/*
	 * Acquire the mutex
	 */

	mutex_enter(&state->mutex);

	/*
	 * Channel freeing waiting for
	 */

	drv_getparm(LBOLT,&cur_clock_ticks);

	timeout_clock_ticks =
		cur_clock_ticks + drv_usectohz(CHANNEL_FREE_TIMEOUT_DEF_VALUE);

	while ( channel_state -> busy || channel_state -> wait_list_start != NULL ||
			channel_state -> in_progress_start != NULL ||
			channel_state -> completed_trans_start != NULL ||
			channel_state -> term_trans_processed ) {

		rval = cv_timedwait(&state -> channel_cv, &state->mutex,timeout_clock_ticks);
//	rval = cv_spin_timedwait(&state -> channel_cv, &state->lock,timeout_clock_ticks);	
		if ( rval < 0 ) {
			ME90_LOG(state, ME90_DL_ERROR,
					"%s(): waiting for freeing of channel %d timeouted\n", __func__, 
					channel);

			if ( !channel_state -> streaming || channel_state -> pseudostreaming ) {
				mcka_delete_all_exec_trans(state, channel, ETIME, 0, 1);
			}

			break;
		}
	}

	if ( channel_state -> completed_trans_start != NULL ||
		channel_state -> term_trans_processed ) {
		mutex_exit(&state->mutex);
		mcka_terminate_dma_trans(state,channel);
		mutex_enter(&state->mutex);
	}

	if ( channel_state -> ready_atrans_start != NULL ) {
		mutex_exit(&state->mutex);
		mcka_release_all_async_trans(state, channel);
		mutex_enter(&state->mutex);
	}

	if ( channel_state -> drq_queue_start != NULL ||
		channel_state -> drq_queue_end != NULL ) {
		remove_drq_queue(state,channel);
	}

	if ( channel_state -> last_term_trans_buf != NULL ) {
		me90drv_delete_trans_header(state,channel_state -> last_term_trans_buf);
		channel_state -> last_term_trans_buf = NULL;
	}

	/*
	 * Mark the channel closed in the map
	 */

	channel_state -> trans_num = 0;
	state->open_channel_map &= ~CHNL_NUM_TO_MASK(channel);

	/*
	 * If last channel closed, We are no longer open
	 */

	if ( state->open_channel_map == 0 ) {
		state->open_flags = 0;
		state->opened = 0;
	}

	if ( state->opened == 0 ) {
		/*
		 * Remove hanguped MP timer interrupts and their requests
		 */

		if ( state -> mp_timer_intrs.mp_intr_mode_on == 1 ) {
			mp_drv_args_t       mp_timer_reset_args;
			mp_timer_reset_args.mp_timer_set.timer_interval = 0;
			submit_mp_task(state,mp_timer_intr_set_mp_task,
						&mp_timer_reset_args,
						1,
						NULL,
						NULL,
						0
						);

			remove_mp_timer_intr(state);
			state -> mp_timer_intrs.mp_intr_mode_on = -1;
		}

		/*
		 * Interdriver communication area freeing
		 */

		drv_getparm(LBOLT,&cur_clock_ticks);
		timeout_clock_ticks =
			cur_clock_ticks + drv_usectohz(DRV_COMM_FREE_TIMEOUT_DEF_VALUE);

		while ( state -> drv_comm_busy ) {
			rval = cv_timedwait(&state->drv_comm_cv, &state->mutex,timeout_clock_ticks);
//	   rval = cv_spin_timedwait(&state->drv_comm_cv, &state->lock,timeout_clock_ticks);
			if ( rval < 0 ) {
				ME90_LOG(state, ME90_DL_ERROR,
					"%s(): waiting for freeing of interdriver "
					"communication area timeouted\n", __func__
					);

				state -> drv_comm_busy = 0;
				cv_broadcast(&state -> drv_comm_cv);
				break;
			}
		}
	}

	/*
	 * Drop the mutex
	 */

	mutex_exit(&state->mutex);

	if ( !state->opened ) {
		if ( (state -> connection_state & MODE_ON_CONNECTION_STATE) ||
			(state -> connection_state & MP_TAKE_CONNECTION_STATE) ||
			(state -> connection_state & IS_SET_CONNECTION_STATE)  ||
			state -> connection_events != NULL                     ||
			state -> max_cnct_events_num > 0
			)

			mcb_reset_connection_polling(state, 0);
	}

	ME90_LOG(state, ME90_DL_TRACE,"%s(): succesed, instance %d channel %d\n", __func__, 
			instance, channel);

#ifdef DEBUG_BUF_USE
	if ( !state->opened )
		mcka_out_debug_msg_buf();
#endif /* DEBUG_BUF_USE */

	return 0;
}

/*
 * Character (raw) read and write routines, called via read(2) and
 * write(2). These routines perform "raw" (i.e. unbuffered) i/o.
 * Since they're so similar, there's actually one 'rw' routine for both,
 * these devops entry points just call the general routine with the
 * appropriate flag.
 */
/*ARGSUSED*/
static	ssize_t
mcka_read(struct file *pfile, char *buf, size_t sz, loff_t *lf)
{
	mcb_state_t	*state = (mcb_state_t *)pfile->private_data;
	dev_t		dev;
	struct uio	*uio_p;
	int			instance = 0;
	int			rval;

	ME90_LOG(NULL, ME90_DL_TRACE,"%s(): started\n", __func__);
	
	if ( state == NULL ) {
		printk("~%s~_write: unattached instance %d\n", mod_name, instance);
		return (ENXIO);
	}

	dev = state->dev;
	if ( !dev )
		return -ENXIO;

	instance = MCB_INST(dev);

	uio_p = kmalloc(sizeof(uio_t), GFP_KERNEL);
	uio_p -> uio_offset = 0;
	if ( uio_p <= 0 ) {
		printk ("%s(): Error allocated memory\n", __func__);
		return 1;
	}

/*
* 	Here we believe that buf is always in user adress space.. We
*	allocate a kernel block for coping the buf into the one. Later may 
*	be used ddi mapping user memory block (here buf) to the kernel
*	address space via pgd, pmd, pte (pgd, pmhd, pmld, pte in e2k terms)
*/	
	uio_p->uio_iov->iov_base = kmalloc(sz, GFP_KERNEL);
	if ( uio_p ->uio_iov->iov_base <= 0 ) {
		kfree(uio_p);
		printk("%s(): Error allocated memory\n", __func__);
		return 1;
	}

	uio_p ->uio_iov-> iov_len = sz;
	uio_p -> uio_iovcnt = 1;
	uio_p -> uio_segflg = UIO_SYSSPACE;
	uio_p -> uio_resid = uio_p -> uio_iov -> iov_len;	
	uio_p -> uio_offset = 0;

	rval = mcb_rdwr(dev, uio_p, B_READ,NULL);

	if ( ddi_copyout(uio_p ->uio_iov->iov_base, buf, sz) ) {
		printk ("%s(): Error copy_to_user\n", __func__);
	}

	kfree(uio_p ->uio_iov->iov_base);
	kfree(uio_p);

	return rval;
}

/*ARGSUSED*/
static ssize_t
mcka_write(struct file *pfile, const char *buf, size_t sz, loff_t *lf)
{
	mcb_state_t	*state = (mcb_state_t *)pfile->private_data;
	dev_t		dev;
	struct uio	*uio_p;
	int			instance = 0;

	ME90_LOG(NULL, ME90_DL_TRACE,"%s(): started\n", __func__);

	if ( state == NULL ) {
		printk("~%s~_write: unattached instance %d\n", mod_name, instance);
		return -ENXIO;
	}

	dev = state->dev;
	if ( !dev )
		return -ENXIO;

	instance = MCB_INST(dev);
	
	uio_p = kmalloc(sizeof(uio_t), GFP_KERNEL);
	uio_p -> uio_offset = 0;
	if ( uio_p <= 0 ) {
		printk("%s(): Error allocated memory\n", __func__);
		return 1;
	}
/*
* 	Here we believe that buf is always in user adress space.. We
*	allocate a kernel block for coping the buf into the one. Later may 
*	be used ddi mapping user memory block (here buf) to the kernel
*	address space via pgd, pmd, pte (pgd, pmhd, pmld, pte in e2k terms)
*/
	uio_p->uio_iov->iov_base = kmalloc(sz, GFP_KERNEL);
	if ( uio_p ->uio_iov->iov_base <= 0 ) {
		kfree(uio_p);
		printk("%s(): Error allocated memory\n", __func__);
		return 1;
	}

	uio_p ->uio_iov-> iov_len = sz;
	uio_p -> uio_iovcnt = 1;
	uio_p -> uio_segflg = UIO_SYSSPACE;
	uio_p -> uio_resid = uio_p -> uio_iov -> iov_len;	
	uio_p -> uio_offset = 0;

	if ( ddi_copyin((void *)buf, uio_p ->uio_iov->iov_base, sz) ) {
		kfree(uio_p ->uio_iov->iov_base);
		kfree(uio_p);
		printk("%s(): Error copy_from_user\n", __func__);
		return 1;
	}
	
	return mcb_rdwr(dev, uio_p, B_WRITE,NULL);
}

/*
 *  Get appropriate burst sizes bitmap in accordance with transfer request
 *  specifications and system and SBus requirements
 */

/*ARGSUSED*/
int
mcka_get_burst_sizes(
	mcb_state_t		*state,
	me90drv_chnl_state_t	*channel_state,
	me90drv_trans_spec_t	*transfer_spec,
	caddr_t			trans_base_addr,
	size_t			trans_byte_size,
	int			*allowed_burst_sizes)
{
	int		allowed_burst = 0;
	int		cur_burst = 0;
	int		trans_base_addr_align = 0;
	int		trans_byte_size_align = 0;

	ME90_LOG(state, ME90_DL_TRACE,"mcka_get_burst_sizes started\n");

	if (transfer_spec != NULL) {
		allowed_burst = transfer_spec -> burst_sizes;
		allowed_burst &= MCB_ENABLE_BURST_SIZES;
		if (allowed_burst == 0) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_get_burst_sizes - empty allowed %02x & "
				"desirable %02x burst sizes bitmap\n",
				MCB_ENABLE_BURST_SIZES,
				transfer_spec -> burst_sizes);
			return EINVAL;
		}
	} else
		allowed_burst = state -> system_burst & MCB_ENABLE_BURST_SIZES;
	if ((allowed_burst & state -> system_burst) == 0) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mcka_get_burst_sizes - empty allowed %02x & enable"
			" %02x burst sizes bitmap\n",
			allowed_burst,state -> system_burst);
		return EINVAL;
	}
	allowed_burst &= state -> system_burst;
	ME90_LOG(state, ME90_DL_TRACE,"mcka_get_burst_sizes, allowed_burst = %x\n", allowed_burst);
	cur_burst = 0x1;
	while (cur_burst <= allowed_burst) {
		if ((long) trans_base_addr & cur_burst)
			break;
		cur_burst <<= 1;
	}
	ME90_LOG(state, ME90_DL_TRACE,"mcka_get_burst_sizes, cur_burst = %x\n", cur_burst);
	trans_base_addr_align = cur_burst | (cur_burst - 1);
	ME90_LOG(state, ME90_DL_TRACE,"mcka_get_burst_sizes, trans_base_addr_align = %x\n", trans_base_addr_align);
	cur_burst = 0x1;
	while (cur_burst <= allowed_burst) {
		if ((int) trans_byte_size & cur_burst)
			break;
		cur_burst <<= 1;
	}
	ME90_LOG(state, ME90_DL_TRACE,"mcka_get_burst_sizes, cur_burst = %x\n", cur_burst);
	trans_byte_size_align = cur_burst | (cur_burst - 1);
	ME90_LOG(state, ME90_DL_TRACE,"mcka_get_burst_sizes, trans_byte_size_align = %x\n", trans_byte_size_align);
	*allowed_burst_sizes = trans_base_addr_align & trans_byte_size_align &
				allowed_burst;
#if	defined(__BLOCK_BUFFER_USE__)
	if (transfer_spec != NULL) {
		if (transfer_spec -> io_mode_flags & ONLY_UNBUF_IO_MODE)
			*allowed_burst_sizes = allowed_burst;
	}
#endif	/* __BLOCK_BUFFER_USE__ */

	ME90_LOG(state, ME90_DL_TRACE,"mcka_get_burst_sizes successed, allowed_burst_sizes = %d\n", *allowed_burst_sizes);

	return 0;
}

/*
 *  Take new synchronous I/O data transfer
 */

/*ARGSUSED*/
static	int
mcka_take_new_trans(
	mcb_state_t *	state,
	int		channel,
	trans_buf_t *	trans_buf_p
//   int op_flags
	)
{
	me90drv_chnl_state_t * channel_state = &state -> all_channels_state[channel];
	trans_spec_t *	transfer_spec = NULL;
//	u_int		trans_base_addr = 0;
	caddr_t		trans_base_addr = 0;
	size_t		buf_byte_size = 0;

	ME90_LOG(state, ME90_DL_TRACE,
			"%s(): started for channel %d, trans_buf_p = 0x%lx\n", __func__, 
			channel, (u_long)trans_buf_p
			);

	if ( !trans_buf_p -> trans_buf_desc.drv_buf_used ) {
	ME90_LOG(state, ME90_DL_TRACE,
		"%s(): drv_buf_used = 0\n", __func__);
//      transfer_spec = trans_buf_p -> trans_buf_desc.bp -> b_private;
	transfer_spec = trans_buf_p -> trans_buf_desc.uio_p -> transfer_spec;

	if ( transfer_spec == NULL )
		trans_buf_p -> multi_buf_flag = 1;
	else if ( transfer_spec -> buf_byte_size >
			trans_buf_p -> trans_buf_desc.uio_p -> uio_iov[0].iov_len
			/*trans_buf_p -> trans_buf_desc.bp -> b_bcount*/ )
		trans_buf_p -> multi_buf_flag = 1;
		else
			trans_buf_p -> multi_buf_flag = 0;
/*      trans_base_addr = (u_int) trans_buf_p -> trans_buf_desc.bp -> b_un.b_addr;
        buf_byte_size = trans_buf_p -> trans_buf_desc.bp -> b_bcount;
*/
	trans_base_addr = (caddr_t) trans_buf_p -> trans_buf_desc.buf_address;
	buf_byte_size = trans_buf_p -> trans_buf_desc.buf_size;

	dbgmcka("%s(): trans_base_addr = 0x%lx, buf_byte_size = 0x%lx\n", __func__, 
		(u_long)trans_base_addr, (u_long)buf_byte_size);
	} else {
		dbgmckaspin("MCKA: %s(): spin %s\n", __func__, 
		raw_spin_is_locked(&state->lock) ? "LOCKED" : "UNLOCKED");	
		transfer_spec = trans_buf_p -> drv_buf_p -> transfer_spec;
		trans_base_addr = (caddr_t) trans_buf_p -> trans_buf_desc.buf_address;
		buf_byte_size = trans_buf_p -> trans_buf_desc.buf_size;

		dbgmcka("%s(): trans_base_addr = 0x%lx, buf_byte_size = 0x%lx\n", __func__, 
		(u_long)trans_base_addr, (u_long)buf_byte_size);
	}

	mutex_enter(&state->mutex);				/* start MUTEX */

	trans_buf_p -> next_trans_buf = NULL;

	channel_state -> trans_num ++;
	trans_buf_p -> trans_num = channel_state -> trans_num;

	if ( transfer_spec != NULL )
		if ( transfer_spec -> trans_res_info != NULL )
			transfer_spec -> trans_res_info -> trans_num = trans_buf_p -> trans_num;

	if ( !trans_buf_p -> trans_buf_desc.drv_buf_used &&
		channel_state -> multi_buf_lock == trans_buf_p -> trans_buf_desc.uio_p
/*    		channel_state -> multi_buf_lock == trans_buf_p -> trans_buf_desc.bp*/ ) {
// 		queue locked by this transfer - continue 
		trans_buf_p -> next_trans_buf = channel_state -> wait_list_start;
		channel_state -> wait_list_start = trans_buf_p;

		if ( channel_state -> wait_list_end == NULL )
			channel_state -> wait_list_end = trans_buf_p;
	} else if ( channel_state -> wait_list_start == NULL ) {
		channel_state -> wait_list_start = trans_buf_p;
		channel_state -> wait_list_end = trans_buf_p;
		channel_state -> wait_list_size ++;
	} else {
		channel_state -> wait_list_end -> next_trans_buf = trans_buf_p;
		channel_state -> wait_list_end = trans_buf_p;
		channel_state -> wait_list_size ++;
	}

	if ( transfer_spec != NULL )
		if ( transfer_spec -> async_trans )
			channel_state -> async_trans_num ++;

	mutex_exit(&state->mutex);			/* end MUTEX */

	if ( !channel_state -> streaming )
		mcb_start_new_trans(state,channel);

	ME90_LOG(state, ME90_DL_TRACE,
		"%s(): successed for channel %d\n", __func__, channel);

	return 0;
}

/*ARGSUSED*/
static int mcka_dostrategy(
//     struct buf *     bp,
       uio_t *		uio_p,	
       mcb_state_t *    state
/*     trans_spec_t *	transfer_spec,
       int		op_flags*/
     )
{
     dev_t 			dev = uio_p->dev;
     me90drv_chnl_state_t *	channel_state = NULL;
     int               		dev_num = MCB_DEVN(dev);
     int               		instance = MCB_inst(dev_num);
     int               		channel = MCB_chan(dev_num);
//   trans_spec_t *    		transfer_spec = bp -> b_private;
     trans_spec_t *    		transfer_spec = uio_p -> transfer_spec;
     trans_buf_t *     		trans_buf_p = NULL;
     int               		flags = 0;
     int               		rval = 0;

     ME90_LOG(NULL, ME90_DL_TRACE,
             "mcka_dostrategy inst %d channel %d started for"
             " addr 0x%08x len 0x%x\n",
             instance,channel,
	     uio_p->uio_iov[0].iov_base, uio_p->uio_iov[0].iov_len
//           bp -> b_un.b_addr,bp -> b_bcount
            );
     channel_state = &state -> all_channels_state[channel];
//     if (bp->b_flags & B_READ)
       if (uio_p->op_flags & B_READ)
        flags |= DDI_DMA_READ;
//     if (bp->b_flags & B_WRITE)
       if (uio_p->op_flags & B_WRITE)
        flags |= DDI_DMA_WRITE;
     flags |= DDI_DMA_STREAMING;
	   transfer_spec -> trans_res_info -> event_start_time = ddi_gethrtime();
//	   (trans_spec_t *)uio_p -> transfer_spec = transfer_spec;
     rval = mcka_create_trans_header(state,
//             bp->b_bcount,
	       uio_p->uio_iov[0].iov_len,
               0,				/* buffer, not pseudo */
               flags,
               NULL,				/* real buffer, not link */
//             bp,
	       uio_p,
               NULL,				/* no the associated transfer */
               &trans_buf_p
                                );
     if (rval != 0)
     {
        ME90_LOG(state, ME90_DL_TRACE,
                "mcka_dostrategy cannot create buffer for channel"
                " %d\n",
                channel
               );
/*      bp->b_resid = bp->b_bcount;
        bioerror(bp, rval);
        biodone(bp);
*/
        return rval;
     }
	transfer_spec -> trans_res_info -> event_end_time = ddi_gethrtime();
        
	rval = mcka_take_new_trans(state, channel, trans_buf_p/*, op_flags*/);
	if (rval != 0) {
		ME90_LOG(state, ME90_DL_WARNING,
			"mcka_dostrategy: mcka_take_new_trans failed for"
			" channel %d\n", channel);
		mcb_delete_trans_header(state, trans_buf_p);
		return rval;
	} else if (transfer_spec -> async_trans) {
/*      	bp -> b_resid = bp -> b_bcount;
		biodone(bp);
*/
	}

     ME90_LOG(state, ME90_DL_TRACE,
             "mcka_dostrategy channel %d successed for"
             " addr 0x%08x len 0x%x\n",
             channel,
	     uio_p->uio_iov[0].iov_base, uio_p->uio_iov[0].iov_len
//    	     bp -> b_un.b_addr,bp -> b_bcount
            );

     return  0;
}

/*ARGSUSED*/
static int mcka_strategy(
//      struct buf * bp
	mcb_state_t *	state,
	int		channel,
        uio_t *		uio_p
/*	int		op_flags,
        trans_spec_t *	transfer_spec
*/
    )
{
//   mcb_state_t	*state = NULL;
     dev_t 		dev = uio_p->dev;
     int		dev_num = MCB_DEVN(/*bp->b_edev*/ dev);
     int		instance = MCB_inst(dev_num);
//   int		channel = MCB_chan(dev_num);
     trans_spec_t	*transfer_spec = NULL;
     int		multi_buf_flag = 0;

     ME90_LOG(NULL, ME90_DL_TRACE,
             "mcka_strategy inst %d started for channel %d\n",
             instance,channel
            );

/*   state = (mcb_state_t *) ddi_get_soft_state(state,instance);
     if (state == NULL)
     {
        ME90_LOG(NULL, ME90_DL_ERROR,"mcka_strategy - bad instance %d\n",
                 instance
                );
        bp->b_resid = bp->b_bcount;
        bioerror(bp, ENXIO);
        biodone(bp);
        return  0;
     };
*/
     transfer_spec = uio_p->transfer_spec; 

#ifndef	__MULTIBUF_TRANS_ENABLE_
/*
     if (transfer_spec == NULL)
        multi_buf_flag = 1;
     else if (transfer_spec -> buf_byte_size > bp -> b_bcount)
        multi_buf_flag = 1;
*/
     if (transfer_spec == NULL)
	multi_buf_flag = 1;
     else if (transfer_spec -> buf_byte_size > uio_p->uio_iov[0].iov_len)
	multi_buf_flag = 1;
     else
        multi_buf_flag = 0;
     if (multi_buf_flag)
     {
        ME90_LOG(state, ME90_DL_TRACE,"mcka_strategy - multi-buffer used\n");
/*   	bp->b_resid = bp->b_bcount;
        bioerror(bp, EMULTIBUF);
        biodone(bp);
*/
        return  0;
     }
#endif	/* __MULTIBUF_TRANS_ENABLE_ */
     if (transfer_spec != NULL)
     {
        if (transfer_spec -> dev_access_mode == ON_DEMAND_DEV_ACCESS_MODE)
        {
           ME90_LOG(state, ME90_DL_TRACE,
                   "mcka_strategy channel %d will be waiting for DRQ"
                   " addr 0x%08x len 0x%x\n",
                   channel,
//                bp -> b_un.b_addr,bp -> b_bcount
		  uio_p->uio_iov[0].iov_base, uio_p->uio_iov[0].iov_len
                  );
           return put_drq_queue(/*bp*/ uio_p, state);
        }
     }
     ME90_LOG(state, ME90_DL_TRACE,
             "mcka_strategy channel %d finished for"
             " addr 0x%08x len 0x%x\n",
             channel,
		uio_p->uio_iov[0].iov_base, uio_p->uio_iov[0].iov_len
// 	        bp -> b_un.b_addr,bp -> b_bcount
            );
     return mcka_dostrategy(uio_p,state/*,transfer_spec,op_flags*/);
}

int uiomove(caddr_t address, long nbytes,
          int rwflag, uio_t *uio_p)
{ iovec_t *iovec_p = uio_p->uio_iov;
  switch (rwflag) {
  case UIO_READ :   
	if (UIO_USERSPACE == uio_p->uio_segflg ) {
		dbgmcka("uiomove: UIO_READ, writing 0x%lx bytes to user 0x%lx adress from 0x%lx\n", 
				nbytes, (u_long)iovec_p->iov_base, (ulong)address);
                if (copy_to_user(iovec_p->iov_base, address, nbytes) != 0) 
			return EFAULT;
        } else {   
                if (memcpy(iovec_p->iov_base, address, nbytes) == 0)
			return EFAULT;
	}
        iovec_p->iov_len = nbytes;
        break;
  case UIO_WRITE : 
	if (UIO_USERSPACE == uio_p->uio_segflg ) {
		dbgmcka("uiomove: UIO_WRITE, writing 0x%lx bytes to kernel 0x%lx adress from 0x%lx\n", 
				nbytes, (u_long)address, (u_long)iovec_p->iov_base);
                if (copy_from_user(address, iovec_p->iov_base, nbytes) != 0)
			return EFAULT;
        } else {  
	        if (memcpy(address, iovec_p->iov_base, nbytes) == 0)
			return EFAULT;
	}
        break;
  default : 
	printk ("Error operation\n");
        return EFAULT;
  }
  return 0;
}

/*
 *  Perform I/O data transfer with private driver buffer use
 */

/*ARGSUSED*/
static	int
mcka_drv_buf_strategy(
	mcb_state_t *	state,
	int		channel,
	uio_t *		uio_p,
	int		op_flags,
	trans_spec_t *	transfer_spec
	)
{
	mcb_drv_buf_t	*trans_drv_buf_p = NULL;
	trans_buf_t 	*trans_buf_p = NULL;
	int				flags = 0;
	int				rval = 0;

	ME90_LOG(state, ME90_DL_TRACE,
		"%s(): started for channel %d\n", __func__, channel);

	dbgmckaspin("MCKA: %s(): before mcka_create_drv_buf spin %s\n", __func__, 
		raw_spin_is_locked(&state->lock) ? "LOCKED" : "UNLOCKED");

	rval = mcka_create_drv_buf(state, uio_p, op_flags, transfer_spec, &trans_drv_buf_p);

	dbgmckaspin("MCKA: %s(): after mcka_create_drv_buf spin %s\n", __func__, 
		raw_spin_is_locked(&state->lock) ? "LOCKED" : "UNLOCKED");

	if ( rval != 0 ) {
		ME90_LOG(state, ME90_DL_TRACE,
			"%s(): cannot create driver buffer header "
			"for channel %d\n", __func__, 
			channel
			);

		return rval;
	}

	if ( op_flags & B_READ )
		flags |= DDI_DMA_READ;

	if ( op_flags & B_WRITE )
		flags |= DDI_DMA_WRITE;

	flags |= DDI_DMA_STREAMING;

	transfer_spec -> trans_res_info -> event_start_time = ddi_gethrtime();

	dbgmckaspin("MCKA: %s(): before mcka_create_trans_header spin %s\n", __func__, 
		raw_spin_is_locked(&state->lock) ? "LOCKED" : "UNLOCKED");

	rval = mcka_create_trans_header(state,
				uio_p -> uio_resid,
				0,				/* buffer, not pseudo */
				flags,
				NULL,				/* real buffer, not link */
				NULL,
				trans_drv_buf_p,			/* the associated transfer */
				&trans_buf_p
				);

	dbgmckaspin("MCKA: %s(): after mcka_create_trans_header spin %s\n", __func__, 
		raw_spin_is_locked(&state->lock) ? "LOCKED" : "UNLOCKED");

	if ( rval != 0 ) {
		ME90_LOG(state, ME90_DL_TRACE,
			"%s(): cannot create driver private buffer "
			"for channel %d\n", __func__, 
			channel
			);

		mcka_delete_drv_buf(state,trans_drv_buf_p);

		return rval;
	} else {
		ME90_LOG(state, ME90_DL_TRACE,
			"%s(): start trans with driver private buffer "
			"for channel %d from 0x%lx to 0x%lx\n", __func__, 
			channel, trans_buf_p -> trans_buf_desc.buf_address,
			trans_drv_buf_p -> uio_p
			);
	}

	transfer_spec -> trans_res_info -> event_end_time = ddi_gethrtime();

	if ( trans_drv_buf_p -> op_flags & B_WRITE ) {
		rval = uiomove(trans_buf_p -> trans_buf_desc.buf_address,
					trans_drv_buf_p -> uio_p -> uio_resid,
					UIO_WRITE,
					trans_drv_buf_p -> uio_p
					);

		if ( rval != 0 ) {
			trans_buf_p -> sparc_error_code = rval;
			mcka_finish_trans(state, channel, trans_buf_p, 0, 1);	/* canceled */
			mcka_delete_drv_buf(state,trans_drv_buf_p);

			return rval;
		}

		rval = mcka_dma_sync(state,
					trans_buf_p -> trans_buf_desc.dma.prim_dev_mem,
					trans_buf_p -> trans_buf_desc.buf_size,
					DMA_TO_DEVICE);

		if ( rval != DDI_SUCCESS ) {
			ME90_LOG(state, ME90_DL_ERROR,
				"%s(): ddi_dma_sync failed for channel"
				" %d\n", __func__, 
				channel
				);

			trans_buf_p -> sparc_error_code = EFAULT;
			mcka_finish_trans(state, channel, trans_buf_p, 0, 1);	/* canceled */
			mcka_delete_drv_buf(state,trans_drv_buf_p);

			return -EFAULT;
		}
	}

	dbgmckaspin("MCKA: %s(): before mcka_take_new_trans spin %s\n", __func__, 
		raw_spin_is_locked(&state->lock) ? "LOCKED" : "UNLOCKED");

	rval = mcka_take_new_trans(state, channel, trans_buf_p);
	if ( rval != 0 ) {
		ME90_LOG(state, ME90_DL_TRACE,
			"%s(): mcka_take_new_trans failed "
			"for channel %d\n", channel);

		mcb_delete_trans_header(state, trans_buf_p);
		mcka_delete_drv_buf(state, trans_drv_buf_p);

		return rval;
	}

	if ( transfer_spec -> async_trans ) {
		ME90_LOG(state, ME90_DL_TRACE,
			"%s(): successed for channel %d async."
			" transfer\n", channel);

		return 0;
	}

	mutex_enter(&state->mutex);			/* start MUTEX */

	while ( !trans_drv_buf_p -> trans_completed ) {
		ME90_LOG(state, ME90_DL_TRACE,
			"%s(): waiting for transfer completed "
			"for channel %d\n", __func__, channel);

		cv_wait_sig(&trans_drv_buf_p -> trans_finish_cv, &state->mutex);
//		cv_spin_wait(&trans_drv_buf_p -> trans_finish_cv, &state->lock);
	}

	mutex_exit(&state->mutex);			/* end MUTEX */

	rval = me90drv_finish_drv_buf_trans(state, channel, trans_buf_p);

	ME90_LOG(state, ME90_DL_TRACE,
		"%s(): succeeded for channel %d\n", __func__, channel);

	return rval;
}

/*
 * General character (raw) read/write routine
 * Just verify the unit number and transfer offset & length, and call
 * strategy via physio. Physio(9f) will take care of address mapping
 * and locking, and will split the transfer if ncessary, based on minphys,
 * possibly calling the strategy routine multiple times.
 */

/*ARGSUSED*/
int
mcb_rdwr(
	dev_t		dev,
	struct uio	*uio_p,
	int		flag,
	trans_spec_t	*user_transfer_spec)
{
	mcb_state_t *	 	state = NULL;
	me90drv_chnl_state_t *	channel_state = NULL;
//   struct buf *		buf_p = NULL;
	int			instance;
	int			channel;
	trans_spec_t		transfer_spec;
	trans_info_t 		trans_res_info;
	trans_spec_t *		transfer_spec_p = user_transfer_spec;
	int			io_mode_flags = DMA_TRANSFER_IO_MODE;
	int			rval = 0;
	int			cur_iov      = 0;
	size_t			transfer_len = 0;
	int			drv_buf_using = 0;
#ifdef NO_DRV_BUF_USING
	int			allowed_burst = 0;
#endif
	caddr_t			trans_base_addr = 0;

	instance = MCB_INST(dev);
	channel = MCB_CHAN(dev);

	state = mcka_states[instance];

	if ( state == NULL ) {
		ME90_LOG(NULL, ME90_DL_ERROR,"mcka_rdwr - bad instance %d\n",
				instance
				);

		return ENXIO;
	}

	ME90_LOG(NULL, ME90_DL_TRACE,
			"%s(): inst %d channel %d started %s\n", __func__, 
			instance, channel,
			(flag == B_READ) ? "to read" : "to write"
			);

	dbgmckaspin("MCKA: %s(): spin %s\n", __func__, raw_spin_is_locked(&state->lock) ? "LOCKED" : "UNLOCKED");

	channel_state = &state -> all_channels_state[channel];

	if ( transfer_spec_p != NULL ) {
		io_mode_flags = transfer_spec_p -> io_mode_flags;
		mcka_init_trans_results(transfer_spec_p);
	}

	for ( cur_iov = 0; cur_iov < uio_p -> uio_iovcnt; cur_iov++ ) {
		transfer_len += (uio_p -> uio_iov[cur_iov].iov_len);
	}

	uio_p -> uio_offset = 0;
#ifdef NO_DRV_BUF_USING /* О©╫О©╫ О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫ physio.. О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
	trans_base_addr = uio_p -> uio_iov[0].iov_base;
	rval = mcka_get_burst_sizes(state,
								channel_state,
								transfer_spec_p,
								trans_base_addr,
								transfer_len,
								&allowed_burst
								);

	if ( rval != 0 ) {
		ME90_LOG(state, ME90_DL_TRACE,
				"mcka_rdwr instance %d channel %d mcka_get_burst_sizes failed\n",
				instance,channel
				);

		return rval;
     }

	if ( allowed_burst == 0 || (state -> drv_general_modes & ONLY_BUF_IO_DRV_MODE) ) {
		drv_buf_using = 1;
	}

	if ( channel_state -> streaming && !channel_state -> pseudostreaming && !(io_mode_flags & BMEM_TRANSFER_IO_MODE) )
		drv_buf_using = 1;
#else
		drv_buf_using = 1;
#endif
	if ( transfer_spec_p == NULL ) {
		transfer_spec_p = &transfer_spec;
		transfer_spec.buf_base = (caddr_t) trans_base_addr;
		transfer_spec.buf_byte_size = transfer_len;
		transfer_spec.read_write_flag = flag;
		transfer_spec.async_trans = 0;
		transfer_spec.io_mode_flags = DMA_TRANSFER_IO_MODE;
		transfer_spec.dev_access_mode = DIRECT_DEV_ACCESS_MODE;
		transfer_spec.burst_sizes = MCB_ENABLE_BURST_SIZES;
		transfer_spec.timer_interval = 0;
		transfer_spec.repeation_num = 0;
		transfer_spec.data_waiting_time =
		STREAMING_DATA_WAITING_TIME_DEF + 100000;
		transfer_spec.trans_res_info = &trans_res_info;
		transfer_spec.user_results_p = NULL;
		mcka_init_trans_results(transfer_spec_p);
	}

	if ( (transfer_spec_p -> io_mode_flags & ONLY_UNBUF_IO_MODE) && drv_buf_using ) {
		if ( state -> drv_general_modes & ONLY_BUF_IO_DRV_MODE ) {
			ME90_LOG(state, ME90_DL_ERROR,
					"mcka_rdwr cannot use unbuffered I/O when ONLY BUF mode"
					"of driver is set\n"
					);
		} else {
			ME90_LOG(state, ME90_DL_ERROR,"mcka_rdwr buf used in the unbuf mode\n");
		}

		return EINVAL;
	}

	if ( keep_last_trans_buf_mode ) {
		trans_buf_t * prev_last_trans_buf = NULL;
		mutex_enter(&state->mutex);			/* start MUTEX */
		prev_last_trans_buf = channel_state -> last_term_trans_buf;
		channel_state -> last_term_trans_buf = NULL;
		mutex_exit(&state->mutex);			/* end MUTEX */

		if ( prev_last_trans_buf != NULL )
			me90drv_delete_trans_header(state,prev_last_trans_buf);
	}

	ME90_LOG(state, ME90_DL_TRACE,"mcka_rdwr: drv_buf_using = %d\n", drv_buf_using);

	while (1) {
		if ( !drv_buf_using ) {
/*         buf_p = getrbuf(KM_NOSLEEP);
           if (buf_p == NULL)
           {
              ME90_LOG(state, ME90_DL_ERROR,"mcka_rdwr cannot allocate buf\n");
              return (EINVAL);
           };
           buf_p -> b_private = transfer_spec_p;
           rval =(physio(mcka_strategy, buf_p, dev, flag, minphys, uio_p)); */
			uio_p->op_flags = flag;
			uio_p->transfer_spec = transfer_spec_p;
			uio_p->dev = dev;
			rval = mcka_strategy(state, channel, uio_p /*flag, transfer_spec_p*/);

			if ( !transfer_spec_p -> async_trans || rval != 0 ) {
				mcka_buf_trans_done(state, channel, /*buf_p*/uio_p);
		/*if (buf_p != NULL)
			freerbuf(buf_p);*/
			}

			if ( rval == EMULTIBUF ) {
				drv_buf_using = 1;
				continue;
			}

			if ( transfer_spec_p -> async_trans ) {
				kmem_free(uio_p -> uio_iov, sizeof(iovec_t));
				kmem_free(uio_p, sizeof(uio_t));
			}
        } else	{/* transfer with using driver private buffers and data copy */
		   dbgmckaspin("MCKA: %s(): before mcka_drv_buf_strategy: spin %s\n", __func__,  raw_spin_is_locked(&state->lock) ? "LOCKED" : "UNLOCKED");

			rval = mcka_drv_buf_strategy(state,channel,uio_p,flag,transfer_spec_p);
		}

		break;
	}

	ME90_LOG(state, ME90_DL_TRACE,
			"mcka_rdwr instance %d channel %d finished with res %d\n",
			instance,channel,rval
			);

	return rval;
}

/*
 *  Finish I/O data transfer with private driver buffer use
 */

/*ARGSUSED*/
int
mcb_finish_drv_buf_trans(
	mcb_state_t	*state,
	int		channel,
	trans_buf_t	*trans_buf_p)
{
	me90drv_chnl_state_t	*channel_state = NULL;
	mcb_drv_buf_t		*trans_drv_buf_p = NULL;
	uio_t			*uio_p;
	trans_spec_t		*transfer_spec = NULL;
	int			rval = 0;

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_finish_drv_buf_trans started for channel %d\n", channel);

	channel_state = &state -> all_channels_state[channel];
	if (!trans_buf_p -> trans_buf_desc.drv_buf_used ||
		trans_buf_p -> drv_buf_p == NULL) {
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_finish_drv_buf_trans the transfer has not private"
			" buffer\n");
		return EINVAL;
	}
	trans_drv_buf_p = trans_buf_p -> drv_buf_p;
	uio_p = trans_drv_buf_p -> uio_p;
	transfer_spec = (trans_spec_t *) trans_drv_buf_p -> transfer_spec;
	if (trans_drv_buf_p -> op_flags & B_READ) {
		size_t real_trans_size = trans_buf_p -> real_trans_size;
		size_t source_size = trans_buf_p -> trans_buf_desc.buf_size;
		if (transfer_spec != NULL) {
			if (transfer_spec -> io_mode_flags &
			    BMEM_TRANSFER_IO_MODE) {
				if (transfer_spec -> repeation_num > 1)
					source_size *=
						transfer_spec -> repeation_num;
			}
		}
		if  (real_trans_size > source_size) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_finish_drv_buf_trans real transfered bytes"
				" %d > buf size %d for channel %d\n",
				real_trans_size, source_size,
				channel);
			real_trans_size =
				trans_buf_p -> trans_buf_desc.buf_size;
		}
		if (trans_buf_p -> real_trans_size > 0) {
			rval = uiomove(trans_buf_p ->
						trans_buf_desc.buf_address,
					min(trans_buf_p -> trans_size,
						real_trans_size),
					UIO_READ, trans_drv_buf_p -> uio_p);
			if (rval != 0) {
				trans_drv_buf_p -> trans_error = rval;
				if (transfer_spec -> trans_res_info != NULL)
					transfer_spec -> trans_res_info ->
							trans_errno = rval;
			}
			ME90_LOG(state, ME90_DL_TRACE,
				"mcka_finish_drv_buf_trans move %d byte(s) of"
				" ready data for channel %d with res %d"
				"from 0x%08x to 0x%08x\n",
				min(trans_buf_p -> trans_size,
						real_trans_size),
				channel, rval,
				trans_buf_p -> trans_buf_desc.buf_address,
				trans_drv_buf_p -> uio_p);
		}
	}
	rval = trans_drv_buf_p -> trans_error;
	if (!transfer_spec -> async_trans) {
		mcka_delete_drv_buf(state,trans_drv_buf_p);
		trans_buf_p -> drv_buf_p = NULL;
		me90drv_delete_trans_header(state,trans_buf_p);
	}

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_finish_drv_buf_trans finished with result %d for channel"
		" %d\n", rval, channel);
	return rval;
}

/*
 * Freeing the channel when I/O operation completed or errors occured
 */

/*ARGSUSED*/
int
mcka_free_channel(
	mcb_state_t	*state,
	int		channel,
	trans_state_t	transfer_state)
{

        ME90_LOG(state, ME90_DL_TRACE,
		"mcka_free_channel for channel %d started\n", channel);

	/*
	 * lock mcka state structure
 	 */

	mutex_enter(&state->mutex);			/* start MUTEX */

        mcka_set_transfer_done(state, channel,transfer_state);

	/*
	 * Drop mcka state structure
 	 */

	mutex_exit(&state->mutex);			/* end MUTEX */

        ME90_LOG(state, ME90_DL_TRACE,
		"mcka_free_channel for channel %d successed\n", channel);

	return (0);
}

/*
 * Launch new transfer: the first from queue of waiting for execution
 */

/*ARGSUSED*/
void
mcb_start_new_trans(
	mcb_state_t	*state,
	int		channel
/*	int		op_flags
*/)
{
	me90drv_chnl_state_t	*channel_state = NULL;
	int			rval = 0;
	trans_buf_t		*new_trans_buf = NULL;
	trans_buf_t		*cur_trans_buf = NULL;
//	buf_t			*bp = NULL;

     ME90_LOG(state, ME90_DL_TRACE,
             "mcka_start_new_trans started for channel %d\n",
             channel
            );
	channel_state = &state -> all_channels_state[channel];
     mutex_enter(&state->mutex);				/* start MUTEX */
     if (get_channel_state(state,channel,started_trans_state) != 0)
     {
        mutex_exit(&state->mutex);			/* end MUTEX */
        ME90_LOG(state, ME90_DL_TRACE,
                "mcka_start_new_trans - channel %d busy so far or yet\n",
                 channel
                );
        return;
     }
     if (state -> mp_state != started_mp_state)
     {
        mc_rd_reg_t	gen_reg_state;
        gen_reg_state.RGEN_read = 0;
        ME90_LOG(state, ME90_DL_ERROR,
                "mcka_start_new_trans MP driver is in abnormal"
                " state\n"
               );
        mutex_exit(&state->mutex);			/* end MUTEX */
        me90_retrieve_trans_mode(state,0,0,gen_reg_state);
        mutex_enter(&state->mutex);			/* start MUTEX */
     }
	new_trans_buf = channel_state -> wait_list_start;
	channel_state -> wait_list_start = new_trans_buf -> next_trans_buf;
	if (channel_state -> wait_list_start == NULL)
		channel_state -> wait_list_end = NULL;
	channel_state -> wait_list_size --;
	new_trans_buf -> next_trans_buf = NULL;
	if (channel_state -> in_progress_start == NULL) {
		channel_state -> in_progress_start = new_trans_buf;
	} else {
		channel_state -> in_progress_end -> next_trans_buf = new_trans_buf;
	}
	channel_state -> in_progress_end = new_trans_buf;
	channel_state -> in_progress_size ++;
	if (new_trans_buf -> multi_buf_flag &&
		!new_trans_buf -> trans_buf_desc.drv_buf_used)
/*		channel_state -> multi_buf_lock = new_trans_buf -> trans_buf_desc.bp;
*/
		channel_state -> multi_buf_lock = new_trans_buf -> trans_buf_desc.uio_p;
	mutex_exit(&state->mutex);				/* end MUTEX */

	mcka_set_trans_timeout(state,channel,0);
	rval = start_mcka_dma_engine(state,channel/*,op_flags*/);

	if (rval != 0 && rval != EMPRESTART) {
		mutex_enter(&state->mutex);		/* start MUTEX */
		cur_trans_buf = channel_state -> in_progress_start;
		while (cur_trans_buf != NULL) {
			if (cur_trans_buf == new_trans_buf) {
				channel_state -> in_progress_start = NULL;
				channel_state -> in_progress_end = NULL;
				channel_state -> in_progress_size --;
				break;
			} else if (cur_trans_buf -> next_trans_buf == new_trans_buf) {
				cur_trans_buf -> next_trans_buf = new_trans_buf -> next_trans_buf;
				if (cur_trans_buf -> next_trans_buf == NULL)
					channel_state -> in_progress_end = cur_trans_buf;
				channel_state -> in_progress_size --;
				break;
			}
			cur_trans_buf = cur_trans_buf -> next_trans_buf;
		}
		if (channel_state -> in_progress_start == NULL)
			mcka_delete_timeout(state, channel);
		mutex_exit(&state->mutex);		/* end MUTEX */
		if (mcka_free_channel(state, channel, aborted_trans_state) != 0) {
			ME90_LOG(state, ME90_DL_TRACE,
				"mcka_start_new_trans - cannot free channel %d"
				" access\n", channel);
		}
		new_trans_buf -> sparc_error_code = rval;
		mcka_finish_trans(state, channel, new_trans_buf, 0, 0);
		ME90_LOG(state, ME90_DL_TRACE,
			"mcka_start_new_trans: start_mcka_dma_engine failed for"
			" channel %d\n", channel);
		me90drv_start_new_trans(state,channel);
		return;
	}
        if (state -> drv_general_modes & MULTI_REQ_CHANNEL_DRV_MODE) {
		if (mcka_free_channel(state, channel, started_trans_state) != 0) {
			ME90_LOG(state, ME90_DL_TRACE,
				"mcka_start_new_trans - cannot free channel %d"
				" access\n", channel);
		}
		mcb_start_new_trans(state, channel);
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_start_new_trans successed for channel %d\n", channel);

	return;
}

/*
 * Launch new transfer: the first from queue of waiting for execution
 */

/*ARGSUSED*/
static void mcka_buf_trans_done(
     mcb_state_t *	state,
     int		channel,
/*     buf_t *		bp*/
     uio_t *		uio_p
     )
{
     me90drv_chnl_state_t * channel_state = &state -> all_channels_state[channel];

     ME90_LOG(state, ME90_DL_TRACE,"mcka_buf_trans_done started for channel %d\n",
             channel
            );

     mutex_enter(&state->mutex);				/* start MUTEX */
     if (channel_state -> multi_buf_lock == 0)
     {
        mutex_exit(&state->mutex);			/* end MUTEX */
        ME90_LOG(state, ME90_DL_TRACE,
                "mcka_buf_trans_done no any lock for channel %d\n",
                channel
               );
        return;
     }
     else if (/*channel_state -> multi_buf_lock != bp*/ channel_state -> multi_buf_lock != uio_p)
     {
        mutex_exit(&state->mutex);			/* end MUTEX */
        ME90_LOG(state, ME90_DL_TRACE,
                "mcka_buf_trans_done lock of other transfer for channel %d\n",
                channel
               );
        return;
     }
     channel_state -> multi_buf_lock = NULL;
     mutex_exit(&state->mutex);			/* end MUTEX */
     me90drv_start_new_trans(state,channel);

     ME90_LOG(state, ME90_DL_TRACE,"mcka_buf_trans_done successed for channel %d\n",
             channel
            );
}

/*
 * Put transfer request into queue of pending request. The transfer will be
 * started only after device request receiving
 */

/*ARGSUSED*/
static int put_drq_queue(
//     struct buf *      bp,
	uio_t *		uio_p,
     mcb_state_t *     state
     )
{
	me90drv_chnl_state_t * channel_state = NULL;
	dev_t 		   dev = uio_p->dev;
	int                dev_num = MCB_DEVN(/*bp->b_edev*/ dev);
	int                channel = MCB_chan(dev_num);
	drq_trans_spec_t * new_transfer = NULL;

	ME90_LOG(state, ME90_DL_TRACE,
                "put_drq_queue channel %d started for"
                " addr 0x%08x len 0x%x\n",
                channel,
		uio_p->uio_iov[0].iov_base, uio_p->uio_iov[0].iov_len
         //       bp -> b_un.b_addr,bp -> b_bcount
               );
	channel_state = &state -> all_channels_state[channel];
	new_transfer = kmem_alloc(sizeof(drq_trans_spec_t),KM_NOSLEEP);
	if (new_transfer == NULL)
	{
	   ME90_LOG(NULL, ME90_DL_ERROR,
                   "put_drq_queue channel %d cannot allocate memory for"
                   " transfer request structure\n",
                   channel
                  );
    /*       bp->b_resid = bp->b_bcount;
           bioerror(bp, EINVAL);
           biodone(bp);*/
	   return 0;
	}
//	new_transfer -> bp = bp;
	new_transfer -> uio_p = uio_p;
	new_transfer -> next_trans_spec = NULL;

	/*
	 * lock state state structure
 	*/

	mutex_enter(&state->mutex);			/* start MUTEX */

	if (channel_state -> drq_queue_start == NULL)
	{
	   channel_state -> drq_queue_start = new_transfer;
	   channel_state -> drq_queue_end = new_transfer;
	}
	else
	{
	   channel_state -> drq_queue_end -> next_trans_spec = new_transfer;
	   channel_state -> drq_queue_end = new_transfer;
	}
        channel_state -> drq_queue_size ++;

	/*
	 * Drop state state structure
 	*/

	mutex_exit(&state->mutex);			/* end MUTEX */

        ME90_LOG(state, ME90_DL_TRACE,"put_drq_queue for channel %d successed\n",
                channel
               );
	return 0;
}

/*
 * Start current transfer from queue of pending request. They are
 * waiting for device request receiving
 */

/*ARGSUSED*/
static int start_pending_transfer(
     mcb_state_t *     state,
     int               channel,
#ifdef	_MP_TIME_USE_
     u_int             intr_drq_received
#else
     hrtime_t          intr_drq_received
#endif	/* _MP_TIME_USE_ */
     )
{
	me90drv_chnl_state_t * channel_state = NULL;
	drq_trans_spec_t * cur_transfer = NULL;
        trans_spec_t *     transfer_spec = NULL;

	ME90_LOG(state, ME90_DL_TRACE,
                "start_pending_transfer channel %d started\n",
                channel
               );
	channel_state = &state -> all_channels_state[channel];


	/*
	 * lock state state structure
 	*/

	mutex_enter(&state->mutex);			/* start MUTEX */

	if (channel_state -> drq_queue_start == NULL)
	{
	   mutex_exit(&state->mutex);			/* end MUTEX */
           ME90_LOG(state, ME90_DL_ERROR,
                   "start_pending_transfer no any transfer request waiting "
                   "for DRQ in the channel %d\n",
                   channel
                  );
	   return 0;
	}
	cur_transfer = channel_state -> drq_queue_start;
	channel_state -> drq_queue_start = cur_transfer -> next_trans_spec;
	if (channel_state -> drq_queue_start == NULL)
	   channel_state -> drq_queue_end = NULL;
        channel_state -> drq_queue_size --;

	/*
	 * Drop state state structure
 	*/

	mutex_exit(&state->mutex);			/* end MUTEX */

        ME90_LOG(state, ME90_DL_TRACE,
                "start_pending_transfer for channel %d successed\n",
                channel
               );
/*	transfer_spec = cur_transfer -> bp -> b_private;*/
	transfer_spec = cur_transfer -> uio_p -> transfer_spec;
        if (transfer_spec != NULL)
           if (transfer_spec -> trans_res_info != NULL)
              transfer_spec -> trans_res_info -> intr_drq_received =
                 intr_drq_received;
/*	return mcka_dostrategy(cur_transfer -> bp,state);*/
	return mcka_dostrategy(cur_transfer -> uio_p,state/*,transfer_spec,cur_transfer -> uio_p -> op_flags*/);
}

int   mcka_calculate_work_hr_time(
	hrtime_t    start_time,             /* event start time */
	hrtime_t    end_time                /* event finish time */
	)
{
	return ((end_time - start_time) / 1000);
}

/*
 * Calculate same event time in microseconds.
 */

/*ARGSUSED*/

int   mcka_calculate_work_time(
	u_int    start_time,             /* event start time */
	u_int    end_time                /* event finish time */
	)
{
	int     work_time;
	u_int   max_timer_value = 0xffffffff;
	u_int	max_time = start_time;
	u_int	min_time = end_time;
	u_int	internal_time = 0;
	u_int	external_time = 0;
	int	neg_time = 0;

	if (end_time > start_time)
	{
	   max_time = end_time;
	   min_time = start_time;
	}
	internal_time = max_time - min_time;
	external_time = (max_timer_value - max_time + 1) + min_time;
	if (internal_time <= external_time)
	{
	   work_time = internal_time;
	   neg_time = (start_time < end_time);
	}
	else
	{
	   work_time = external_time;
	   neg_time = (start_time > end_time);
	}
	if (neg_time)
	   work_time = 0 - work_time;
	return (work_time * me90_mp_nsec_cycle / 1000);
}

/*
 * Handle interrupt received from MP after MP timer expiration.
 */

/*ARGSUSED*/
static int handle_mp_timer_intr(
     mcb_state_t *     state,
#ifdef	_MP_TIME_USE_
     u_int             intr_mp_time
#else
     hrtime_t	       intr_mp_time
#endif	/* _MP_TIME_USE_ */
     )
{
	mp_intr_spec_t *   mp_timer_intr_spec = NULL;
	int                rval = 0;
	u_int		   timer_interval = 0;
	mp_intr_t *	   mp_timer_intr;
#ifdef	_MP_TIME_USE_
	u_int		   cur_mp_time = 0;
#else
	hrtime_t	   cur_mp_time = 0;
#endif	/* _MP_TIME_USE_ */
	drv_intercom_t *   drv_communication = NULL;

	ME90_LOG(state, ME90_DL_TRACE,"handle_mp_timer_intr started\n");

	mp_timer_intr_spec = &state -> mp_timer_intrs;
	mutex_enter(&state->mutex);			/* start MUTEX */
	if (mp_timer_intr_spec -> mp_intr_mode_on != 1)
	{
	   if (mp_timer_intr_spec -> mp_intr_mode_on == -1)
	   {
	      mutex_exit(&state->mutex);			/* end MUTEX */
	      return 0;  /* handuped interrupt after the mode was turn off */
	   }
	   else
	   {
	      mutex_exit(&state->mutex);			/* end MUTEX */
	      ME90_LOG(state, ME90_DL_ERROR,
                      "handle_mp_timer_intr not waiting MP timer interrupt\n"
                     );
	      return 1;
	   }
	}
	mp_timer_intr_spec -> total_intr_num ++;
	if (mp_timer_intr_spec -> total_intr_num > 1)
	   timer_interval =
#ifdef	_MP_TIME_USE_
              mcka_calculate_work_time(mp_timer_intr_spec -> last_intr_time,
			intr_mp_time);
#else
              mcka_calculate_work_hr_time(mp_timer_intr_spec -> last_intr_time,
			intr_mp_time);
#endif	/* _MP_TIME_USE_ */

#ifdef	_MP_TIME_USE_
	if (mp_timer_intr_spec -> last_intr_time < intr_mp_time)
	{
	      ME90_LOG(state, ME90_DL_ERROR,
                      "handle_mp_timer_intr prev MP timer intr time 0x%08x <"
	              " cur intr time 0x%08x\n",
	              mp_timer_intr_spec -> last_intr_time,
	              intr_mp_time
                     );
	}
#else
	if (mp_timer_intr_spec -> last_intr_time > intr_mp_time)
	{
	      ME90_LOG(state, ME90_DL_ERROR,
                      "handle_mp_timer_intr prev MP timer intr time 0x%016xL >"
	              " cur intr time 0x%016xL\n",
	              mp_timer_intr_spec -> last_intr_time,
	              intr_mp_time
                     );
	}
#endif	/* _MP_TIME_USE_ */
	mp_timer_intr_spec -> last_intr_time = intr_mp_time;
	drv_communication =
	   (drv_intercom_t *) &state -> MC_BMEM[TR_CNTR_BUF_BMEM_ADDR];
#ifdef	_MP_TIME_USE_
        READ_MP_TIME(cur_mp_time);
#else
        cur_mp_time = ddi_gethrtime();
#endif	/* _MP_TIME_USE_ */
	if (mp_timer_intr_spec -> cur_request_num > 0)
	{
	   if (mp_timer_intr_spec -> cur_queue_size > 0)
	   {
	      ME90_LOG(state, ME90_DL_ERROR,
                      "handle_mp_timer_intr not empty MP timer interrupt and"
	              " request queues\n"
                     );
	   }
	   rval = service_mp_timer_intr_request(state,timer_interval,cur_mp_time);
	   mutex_exit(&state->mutex);			/* end MUTEX */
	   ME90_LOG(state, ME90_DL_TRACE,"handle_mp_timer_intr finished\n");
	   return rval;
	}
	if (mp_timer_intr_spec -> cur_queue_size >=
            mp_timer_intr_spec -> max_queue_size
	   )
	{
	   mp_timer_intr_spec -> losed_intr_num ++;
	   mutex_exit(&state->mutex);			/* end MUTEX */
	   return 0;
	}
	mp_timer_intr = (mp_intr_t *) kmem_alloc(sizeof(mp_intr_t),KM_NOSLEEP);
        if (mp_timer_intr == NULL)
        {
	   mutex_exit(&state->mutex);			/* end MUTEX */
           ME90_LOG(state, ME90_DL_ERROR,
                   "handle_mp_timer_intr: kmem_alloc no memory is available\n"
                  );
           return 1;
        }
	mp_timer_intr -> next_mp_intr = NULL;
	mp_timer_intr -> intr_num = mp_timer_intr_spec -> total_intr_num;
	mp_timer_intr -> timer_interval = timer_interval;
	mp_timer_intr -> enqueue_time = cur_mp_time;
	if (mp_timer_intr_spec -> mp_intr_queue_start == NULL)
	{
	   mp_timer_intr_spec -> mp_intr_queue_start = mp_timer_intr;
	   mp_timer_intr_spec -> mp_intr_queue_end = mp_timer_intr;
	}
	else
	{
	   mp_timer_intr_spec -> mp_intr_queue_end -> next_mp_intr =
	      mp_timer_intr;
	   mp_timer_intr_spec -> mp_intr_queue_end = mp_timer_intr;
	}
        mp_timer_intr_spec -> cur_queue_size ++;
	mutex_exit(&state->mutex);			/* end MUTEX */

	ME90_LOG(state, ME90_DL_TRACE,"handle_mp_timer_intr finished\n");

	return rval;
}

/*
 * Handle interrupt received from MP after MP timer expiration.
 */

/*ARGSUSED*/
int handle_mp_timer_intr_request(
	mcb_state_t		*state,
	mp_tm_intr_info_t	*mp_timer_intr_info)
{
	mp_intr_spec_t *   mp_timer_intr_spec = NULL;
	int                rval = 0;
	intr_req_t *	   mp_timer_intr_request;
	u_int		   request_interval = 0;
#ifdef	_MP_TIME_USE_
	u_int		   cur_mp_time = 0;
#else
	hrtime_t	   cur_mp_time = 0;
#endif	/* _MP_TIME_USE_ */
	drv_intercom_t *   drv_communication = NULL;

	ME90_LOG(state, ME90_DL_TRACE,"handle_mp_timer_intr_request started\n");

	mp_timer_intr_spec = &state -> mp_timer_intrs;
	clean_mp_timer_intr_info(mp_timer_intr_info);
	mutex_enter(&state->mutex);			/* start MUTEX */
	if (mp_timer_intr_spec -> mp_intr_mode_on != 1)
	{
	   if (mp_timer_intr_spec -> mp_intr_mode_on == -1)
	   {
	      mutex_exit(&state->mutex);			/* end MUTEX */
	      ME90_LOG(NULL, ME90_DL_TRACE,
                      "handle_mp_timer_intr_request MP timer intr mode"
                      " was turn off already\n"
                     );
	      return 0;  /* handuped request after the mode was turn off */
	   }
	   else
	   {
	      mutex_exit(&state->mutex);			/* end MUTEX */
	      ME90_LOG(NULL, ME90_DL_ERROR,
                      "handle_mp_timer_intr_request not waiting MP timer"
                      " interrupt mode\n"
                     );
	      return 1;
	   }
	}
	drv_communication =
	   (drv_intercom_t *) &state -> MC_BMEM[TR_CNTR_BUF_BMEM_ADDR];
#ifdef	_MP_TIME_USE_
	READ_MP_TIME(cur_mp_time = (long)drv_communication);
#else
	cur_mp_time = ddi_gethrtime();
#endif	/* _MP_TIME_USE_ */
	mp_timer_intr_spec -> total_request_num ++;
	if (mp_timer_intr_spec -> total_request_num > 1)
#ifdef	_MP_TIME_USE_
	   request_interval =
              mcka_calculate_work_time(mp_timer_intr_spec -> last_request_time,
			cur_mp_time);
#else
	   request_interval =
              mcka_calculate_work_hr_time(
			mp_timer_intr_spec -> last_request_time,
			cur_mp_time);
#endif	/* _MP_TIME_USE_ */
	mp_timer_intr_spec -> last_request_time = cur_mp_time;
	if (mp_timer_intr_spec -> cur_queue_size > 0)
	{
	   if (mp_timer_intr_spec -> cur_request_num > 0)
	   {
	      ME90_LOG(NULL, ME90_DL_ERROR,
                      "handle_mp_timer_intr_request not empty MP timer "
                      " interrupt and request queues\n"
                     );
	   }
	   rval = service_mp_timer_intr(state,
                                        mp_timer_intr_info,
                                        request_interval,
	                                cur_mp_time
                                       );
	   mutex_exit(&state->mutex);			/* end MUTEX */
	   ME90_LOG(state, ME90_DL_TRACE,"handle_mp_timer_intr_request finished\n");
	   return rval;
	}
	mp_timer_intr_request =
	   (intr_req_t *) kmem_alloc(sizeof(mp_intr_t),KM_NOSLEEP);
        if (mp_timer_intr_request == NULL)
        {
	   mutex_exit(&state->mutex);			/* end MUTEX */
           ME90_LOG(state, ME90_DL_ERROR,
                   "handle_mp_timer_intr_request: kmem_alloc no memory "
	           "is available\n"
                  );
           return 1;
        }
	mp_timer_intr_request -> next_intr_request = NULL;
	cv_init(&mp_timer_intr_request -> intr_received_cv);
	mp_timer_intr_request -> intr_info = mp_timer_intr_info;
	mp_timer_intr_request -> enqueue_time = cur_mp_time;
	mp_timer_intr_info -> request_num =
	   mp_timer_intr_spec -> total_request_num;
	mp_timer_intr_info -> request_interval = request_interval;
	if (mp_timer_intr_spec -> intr_req_queue_start == NULL)
	{
	   mp_timer_intr_spec -> intr_req_queue_start = mp_timer_intr_request;
	   mp_timer_intr_spec -> intr_req_queue_end = mp_timer_intr_request;
	}
	else
	{
	   mp_timer_intr_spec -> intr_req_queue_end -> next_intr_request =
	      mp_timer_intr_request;
	   mp_timer_intr_spec -> intr_req_queue_end = mp_timer_intr_request;
	}
        mp_timer_intr_spec -> cur_request_num ++;
	ME90_LOG(state, ME90_DL_TRACE,
                "handle_mp_timer_intr_request will be waiting for MP timer\n"
                );
	cv_wait_sig(&mp_timer_intr_request -> intr_received_cv, &state->mutex);
//  	cv_spin_wait(&mp_timer_intr_request -> intr_received_cv, &state->lock);
	cv_destroy(&mp_timer_intr_request -> intr_received_cv);
	kmem_free(mp_timer_intr_request,sizeof(intr_req_t));
	mutex_exit(&state->mutex);			/* end MUTEX */

	ME90_LOG(state, ME90_DL_TRACE,"handle_mp_timer_intr_request finished\n");

	return rval;
}

static void clean_mp_timer_intr_info(
	mp_tm_intr_info_t * mp_timer_intr_info
	)
{
	mp_timer_intr_info -> intr_num = 0;
	mp_timer_intr_info -> timer_interval = 0;
	mp_timer_intr_info -> request_num = 0;
	mp_timer_intr_info -> request_interval = 0;
	mp_timer_intr_info -> request_enqueued = 0;
	mp_timer_intr_info -> waiting_time = 0;
	mp_timer_intr_info -> unclaimed_intr_num = 0;
	mp_timer_intr_info -> losed_intr_num = 0;
}

/*
 * Service first in the list of request waiting for interrupt
 * received from MP after MP timer expiration.
 */

/*ARGSUSED*/
static int service_mp_timer_intr_request(
     mcb_state_t *     state,
     u_int             timer_interval,
#ifdef	_MP_TIME_USE_
     u_int	       intr_receiving_time
#else
     hrtime_t	       intr_receiving_time
#endif	/* _MP_TIME_USE_ */
     )
{
	mp_intr_spec_t *   mp_timer_intr_spec = NULL;
	intr_req_t *	   intr_request = NULL;

	ME90_LOG(state, ME90_DL_TRACE,"service_mp_timer_intr_request started\n");

	mp_timer_intr_spec = &state -> mp_timer_intrs;
	intr_request = mp_timer_intr_spec -> intr_req_queue_start;
	if (intr_request == NULL)
	{
           ME90_LOG(state, ME90_DL_ERROR,
                   "service_mp_timer_intr_request: no request in the queue\n"
                  );
           return 1;
	}
	mp_timer_intr_spec -> intr_req_queue_start =
           intr_request -> next_intr_request;
	if (mp_timer_intr_spec -> intr_req_queue_start == NULL)
	   mp_timer_intr_spec -> intr_req_queue_end = NULL;
        mp_timer_intr_spec -> cur_request_num --;
	intr_request -> intr_info -> intr_num =
	   mp_timer_intr_spec -> total_intr_num;
	intr_request -> intr_info -> timer_interval = timer_interval;
	intr_request -> intr_info -> request_enqueued = 1;
	intr_request -> intr_info -> waiting_time = 
#ifdef	_MP_TIME_USE_
	   mcka_calculate_work_time(intr_request -> enqueue_time,
			intr_receiving_time);
#else
	   mcka_calculate_work_hr_time(intr_request -> enqueue_time,
			intr_receiving_time);
#endif	/* _MP_TIME_USE_ */
	intr_request -> intr_info -> unclaimed_intr_num =
	   mp_timer_intr_spec -> cur_queue_size;
	intr_request -> intr_info -> losed_intr_num =
	   mp_timer_intr_spec -> losed_intr_num;
	cv_broadcast(&intr_request -> intr_received_cv);

	ME90_LOG(state, ME90_DL_TRACE,"service_mp_timer_intr_request successed\n");

	return 0;
}

/*
 * Service first in the list of MP timer interrupts waiting for request
 * from SPARC.
 */

/*ARGSUSED*/
static int service_mp_timer_intr(
     mcb_state_t *       state,
     mp_tm_intr_info_t * mp_timer_intr_info,
     u_int               request_interval,
#ifdef	_MP_TIME_USE_
     u_int	         request_receiving_time
#else
     hrtime_t	         request_receiving_time
#endif	/* _MP_TIME_USE_ */
     )
{
	mp_intr_spec_t *   mp_timer_intr_spec = NULL;
	mp_intr_t *	   mp_intrrupt = NULL;

	ME90_LOG(state, ME90_DL_TRACE,"service_mp_timer_intr started\n");

	mp_timer_intr_spec = &state -> mp_timer_intrs;
	mp_intrrupt = mp_timer_intr_spec -> mp_intr_queue_start;
	if (mp_intrrupt == NULL)
	{
           ME90_LOG(state, ME90_DL_ERROR,
                   "service_mp_timer_intr: no MP interrupts in the queue\n"
                  );
           return 1;
	}
	mp_timer_intr_spec -> mp_intr_queue_start =
           mp_intrrupt -> next_mp_intr;
	if (mp_timer_intr_spec -> mp_intr_queue_start == NULL)
	   mp_timer_intr_spec -> mp_intr_queue_end = NULL;
        mp_timer_intr_spec -> cur_queue_size --;
	mp_timer_intr_info -> request_num =
	   mp_timer_intr_spec -> total_request_num;
	mp_timer_intr_info -> request_interval = request_interval;
	mp_timer_intr_info -> intr_num = mp_intrrupt -> intr_num;
	mp_timer_intr_info -> timer_interval = mp_intrrupt -> timer_interval;
	mp_timer_intr_info -> request_enqueued = 0;
	mp_timer_intr_info -> waiting_time = 
#ifdef	_MP_TIME_USE_
	   mcka_calculate_work_time(request_receiving_time,
			mp_intrrupt -> enqueue_time);
#else
	   mcka_calculate_work_hr_time(request_receiving_time,
			mp_intrrupt -> enqueue_time);
#endif	/* _MP_TIME_USE_ */
	mp_timer_intr_info -> unclaimed_intr_num =
	   mp_timer_intr_spec -> cur_queue_size;
	mp_timer_intr_info -> losed_intr_num =
	   mp_timer_intr_spec -> losed_intr_num;
        kmem_free(mp_intrrupt,sizeof(mp_intr_t));

	ME90_LOG(state, ME90_DL_TRACE,"service_mp_timer_intr successed\n");

	return 0;
}

/*
 * Remove queue of pending request. ALL transfers are still waiting for
 * device request will be removed
 */

/*ARGSUSED*/
static void remove_drq_queue(
     mcb_state_t *     state,
     int               channel
     )
{
	me90drv_chnl_state_t * channel_state = NULL;
/*	buf_t *            bp = NULL;*/
	drq_trans_spec_t * cur_transfer = NULL;

	ME90_LOG(state, ME90_DL_TRACE,"remove_drq_queue channel %d started\n",
                channel
               );
	channel_state = &state -> all_channels_state[channel];
	while (channel_state -> drq_queue_start != NULL)
	{
	   cur_transfer = channel_state -> drq_queue_start;
	   channel_state -> drq_queue_start = cur_transfer -> next_trans_spec;
           channel_state -> drq_queue_size --;
	   ME90_LOG(NULL, ME90_DL_ERROR,
                   "remove_drq_queue channel %d transfer request removed\n",
                   channel
                  );
   /*        bp = cur_transfer -> bp;
           bp->b_resid = bp->b_bcount;
           bioerror(bp, EINVAL);
           biodone(bp);*/
           kmem_free(cur_transfer,sizeof(drq_trans_spec_t));
	}
	channel_state -> drq_queue_end = NULL;
	ME90_LOG(state, ME90_DL_TRACE,"remove_drq_queue channel %d successed\n",
                channel
               );
}

/*
 * Remove hanguped MP timer interrupts and their request
 */

/*ARGSUSED*/
void	remove_mp_timer_intr(mcb_state_t	*state)
{
        mp_intr_spec_t *   mp_timer_intr_spec = NULL;
	mp_intr_t *        cur_mp_intr = NULL;
	intr_req_t *	   cur_mp_intr_request = NULL;

	ME90_LOG(state, ME90_DL_TRACE,"remove_mp_timer_intr started\n");

	mp_timer_intr_spec = &state -> mp_timer_intrs;
	while (mp_timer_intr_spec -> mp_intr_queue_start != NULL)
	{
	   cur_mp_intr = mp_timer_intr_spec -> mp_intr_queue_start;
	   mp_timer_intr_spec -> mp_intr_queue_start =
              cur_mp_intr -> next_mp_intr;
	   mp_timer_intr_spec -> cur_queue_size --;
	   kmem_free(cur_mp_intr,sizeof(mp_intr_t));
	}
	mp_timer_intr_spec -> mp_intr_queue_end = NULL;

	while (mp_timer_intr_spec -> intr_req_queue_start != NULL)
	{
	   cur_mp_intr_request = mp_timer_intr_spec -> intr_req_queue_start;
	   mp_timer_intr_spec -> intr_req_queue_start =
              cur_mp_intr_request -> next_intr_request;
	   mp_timer_intr_spec -> cur_request_num --;
	   cv_broadcast(&cur_mp_intr_request -> intr_received_cv);
	}
	mp_timer_intr_spec -> intr_req_queue_end = NULL;

	ME90_LOG(state, ME90_DL_TRACE,"remove_mp_timer_intr successed\n");
}

/*
 * Lock the channel for I/O operation,  mutex_enter must be done by caller 
 */

/*ARGSUSED*/
static int get_channel_state(
     mcb_state_t *     state,
     int               channel,
     trans_state_t     transfer_state
     )
{
	me90drv_chnl_state_t	*channel_state = NULL;
	trans_buf_t		*new_trans_buf = NULL;

        dbgmcka("get_channel_state for channel %d started\n", channel);

	/*
	 * if needed conditions are satisfied then set the busy flag
	 */

	channel_state = &state -> all_channels_state[channel];
	new_trans_buf = channel_state -> wait_list_start;
	if (channel_state -> busy                                 ||
            (new_trans_buf == NULL && !channel_state -> streaming)
           )
        {
        	ME90_LOG(state, ME90_DL_TRACE,
			"get_channel_state channel %d is busy or empty queue\n",
               		channel
               	       );
		return 1;
	}
	if (channel_state -> multi_buf_lock != NULL)
	{
		if (new_trans_buf -> trans_buf_desc.drv_buf_used	||
		    !new_trans_buf -> multi_buf_flag			||
		 /*   new_trans_buf -> trans_buf_desc.bp !=
					channel_state -> multi_buf_lock*/
			new_trans_buf -> trans_buf_desc.uio_p !=
					channel_state -> multi_buf_lock
		   )
        	{
        		ME90_LOG(state, ME90_DL_TRACE,
				"get_channel_state channel %d loccked by multi-"
				"buf transfer\n",
               			channel
			       );
			return 1;
		}
	}
	channel_state -> transfer_state = transfer_state;
	channel_state -> busy = 1;

	/*
	 * Drop state state structure
 	*/

        dbgmcka("get_channel_state for channel %d successed\n",
                channel
               );
	return 0;
}

/*
 * Driver attach entry point
 */
/*ARGSUSED*/

int
get_reg_sets_number(
	e90_unit_t	type_unit,
	char		get_max_num)
{
     int       groups_number = 0;

     ME90_LOG(NULL, ME90_DL_TRACE,"get_reg_sets_number started\n");

     switch (type_unit)
     {
         case MCKK_UT :
         case MCKA_UT :
//       case MC19_UT :
         case MC53_UT :
         case MCPM_UT :
            if (get_max_num)
               groups_number = MC_MAX_REG_SETS_NUM;
            else
               groups_number = MC_MIN_REG_SETS_NUM;
            break;
         default      :
            ME90_LOG(NULL, ME90_DL_ERROR,
                    "get_reg_sets_number : bad board type %d\n",
                    type_unit
                   );
     };

     ME90_LOG(NULL, ME90_DL_TRACE,"get_reg_sets_number finished\n");

     return  groups_number;
}

void
init_reg_sets_pointers(
	mcb_state_t	*state,
	e90_unit_t	type_unit)
{
     ME90_LOG(state, ME90_DL_TRACE,"init_reg_sets_pointers started\n");

     switch (type_unit)
     {
         case MCKK_UT :
         case MCKA_UT :
//       case MC19_UT :
         case MC53_UT :
         case MCPM_UT :
            state -> MC_EPROM_CADDR = NULL;
            state -> MC_CNTR_ST_REGS = NULL;
            state -> MC_BMEM = NULL;
            break;
         default      :
            ME90_LOG(NULL, ME90_DL_ERROR,
                    "init_reg_sets_pointers : bad board type %d\n",
                    type_unit
                   );
     }

     ME90_LOG(state, ME90_DL_TRACE,"init_reg_sets_pointers finished\n");
}

int
put_reg_set_pointer(
	mcb_state_t	*state,
	u_int		i_reg_gr,
	caddr_t		regs_mass)
{
     int   ok = 1;

     ME90_LOG(state, ME90_DL_TRACE,"put_reg_set_pointer started\n");

     switch (state -> type_unit)
     {
         case MCKK_UT :
         case MCKA_UT :
//       case MC19_UT :
         case MC53_UT :
         case MCPM_UT :
            if (i_reg_gr == 0)
            {
               ME90_LOG(state, ME90_DL_TRACE,"put_reg_set_pointer map EPROM\n");
               state -> MC_EPROM_CADDR = regs_mass;
            }
            else if (i_reg_gr == 1)
            {
               ME90_LOG(state, ME90_DL_TRACE,"put_reg_set_pointer map GEN_REGS\n");
               state -> MC_CNTR_ST_REGS = (mc_cntr_st_reg_t *) regs_mass;
            }
            else if (i_reg_gr == 2)
            {
               ME90_LOG(state, ME90_DL_TRACE,"put_reg_set_pointer map BMEM\n");
               state -> MC_BMEM = regs_mass;
            }
            else
            {
               ME90_LOG(state, ME90_DL_ERROR,
                       "put_reg_set_pointer : bad MC board reg set num %d\n",
                       i_reg_gr
                      );
               ok = 0;
            };
            break;
         default      :
            ME90_LOG(state, ME90_DL_ERROR,
                    "put_reg_set_pointer : bad board type %d\n",
                    state -> type_unit
                   );
            ok = 0;
     }
     ME90_LOG(state, ME90_DL_TRACE,"put_reg_set_pointer finished\n");
     return ok;
}

void
Unmap_reg_sets(mcb_state_t	*state)
{
	int i_reg_gr = 0;

	ME90_LOG(state, ME90_DL_TRACE, "%s(): started\n", __func__);

	switch ( state -> type_unit ) {
		case MCKK_UT :
		case MCKA_UT :
//       case MC19_UT :
		case MC53_UT :
		case MCPM_UT :
			if ( state -> MC_EPROM_CADDR != NULL ) {
				ME90_LOG(state, ME90_DL_TRACE,
					"%s(): unmap EPROM set # %d\n", __func__, 
					i_reg_gr
					);

				mcka_iounmap(state, 0, state->MC_EPROM_CADDR);
				state -> MC_EPROM_CADDR = NULL;
				i_reg_gr ++;
			}

			if ( state -> MC_CNTR_ST_REGS != NULL ) {
				ME90_LOG(state, ME90_DL_TRACE,
					"%s(): unmap GEN_REGS set # %d\n", __func__, 
					i_reg_gr
					);

				mcka_iounmap(state, 1, state->MC_CNTR_ST_REGS);
				state -> MC_CNTR_ST_REGS = NULL;
				i_reg_gr ++;
			}

			if ( state -> MC_BMEM != NULL ) {
				ME90_LOG(state, ME90_DL_TRACE,
					"%s(): unmap BMEM set # %d\n", __func__, 
					i_reg_gr
					);

				mcka_iounmap(state, 2, state->MC_BMEM);
				state -> MC_BMEM = NULL;
				i_reg_gr ++;
			}

			break;
		default:
			ME90_LOG(state, ME90_DL_ERROR,
					"%s(): bad board type %d\n", __func__, 
					state -> type_unit
					);
	}

	ME90_LOG(state, ME90_DL_TRACE,
			"%s(): finished and deleted %d reg sets\n", __func__, 
			i_reg_gr
			);
} /* No nessesary to unmap reg fields from user */


/*
 * Init driver soft state structures to attach driver
 */

void
mcb_init_drv_state(mcb_state_t	*state)
{
	int			cur_chnl     = 0;
	
	ME90_LOG(state, ME90_DL_TRACE, "mcka_init_drv_state started");

	state -> cntr_flag_map           = 0;
	state -> trans_mode_inited       = 0;
	state -> trans_mode_init_error   = 0;
	state -> max_cnct_events_num     = 0;
	state -> cur_cnct_events_num     = 0;
	state -> losed_events_num        = 0;
	state -> connection_events       = NULL;
	state->connection_state        = 0;
	state->cnct_polling_error      = 0;

	for (cur_chnl = 0; cur_chnl < MAX_MC_BOARD_CHANNEL_NUM; cur_chnl ++) {
		me90drv_chnl_state_t	*channel_state = NULL;

		channel_state = &state -> all_channels_state[cur_chnl];
		channel_state -> drq_queue_size = 0;
		channel_state -> drq_queue_start = NULL;
		channel_state -> drq_queue_end = NULL;
		channel_state -> streaming = 0;
		channel_state -> multi_buf_lock = NULL;
		channel_state -> pseudostreaming = 1;
	}
	state->mp_timer_intrs.mp_intr_mode_on = 0;
	state->mp_timer_intrs.interval        = 0;
	state->mp_timer_intrs.max_queue_size  = 0;
	state->mp_timer_intrs.cur_queue_size  = 0;
	state->mp_timer_intrs.losed_intr_num  = 0;
	state->mp_timer_intrs.total_intr_num  = 0;
	state->mp_timer_intrs.last_intr_time  = 0;
	state->mp_timer_intrs.mp_intr_queue_start  = NULL;
	state->mp_timer_intrs.mp_intr_queue_end    = NULL;
	state->mp_timer_intrs.cur_request_num      = 0;
	state->mp_timer_intrs.total_request_num  = 0;
	state->mp_timer_intrs.last_request_time  = 0;
	state->mp_timer_intrs.intr_req_queue_start = NULL;
	state->mp_timer_intrs.intr_req_queue_end   = NULL;

	ME90_LOG(state, ME90_DL_TRACE, "mcka_init_drv_state succeeded");
}

/*
 *  MC module types driver additional Attachments
 */
/*ARGSUSED*/
int
mcb_attach_add(
	mcb_state_t	*state,
	int		*add_attach_flags)
{
	int	attach_flags = 0;

	/*
	 * Initialize condition variables of connection polling for this
	 * instance
	 */
	cv_init(&state -> cnct_polling_cv);
	attach_flags |= CNCT_POLLING_CV_ADDED;
     
	*add_attach_flags = attach_flags;

	return  0;
}

/*
 *  Detach MC module types driver additional Attachments
 */
/*ARGSUSED*/
void
mcb_detach_add(
	mcb_state_t	*state,
	int		add_attach_flags,
	int		uncondit_detach)
{
	if ((add_attach_flags & CNCT_POLLING_CV_ADDED) || uncondit_detach) {
		cv_destroy(&state -> cnct_polling_cv);
	}
}

/*
 * Detach specific for MC types module
 * Free additional resources allocated in mcka_attach
 */
/*ARGSUSED*/
int
mcka_dodetach_add(mcb_state_t	*state)
{
	int           cur_chnl = 0;
	
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_dodetach_add started\n");

	for (cur_chnl = 0; cur_chnl < MAX_MC_BOARD_CHANNEL_NUM; cur_chnl ++) {
		me90drv_chnl_state_t	*channel_state = NULL;

		channel_state = &state -> all_channels_state[cur_chnl];

        	if (channel_state -> multi_buf_lock != NULL)
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_dodetach_add: detach busy or with "
				"transfers channel %d\n", cur_chnl);
     };
	/*
	 * Reset connection polling mode
	 */

	if ((state -> connection_state & MODE_ON_CONNECTION_STATE) ||
	    (state -> connection_state & MP_TAKE_CONNECTION_STATE) ||
	    (state -> connection_state & IS_SET_CONNECTION_STATE)  ||
	    state -> connection_events != NULL                     ||
	    state -> max_cnct_events_num > 0)
		mcb_reset_connection_polling(state, 0);

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_delete_trans_header Driver detached\n");

	return  DDI_SUCCESS;
}


/*
 * Detect and get the current interrupt reason
 */

static intr_reason_t get_intr_reason(
     mcb_state_t *       state,
     sparc_drv_args_t *  interrupt_args,
#ifdef	_MP_TIME_USE_
     u_int		 intr_receiving_time
#else
     hrtime_t		 intr_receiving_time
#endif	/* _MP_TIME_USE_ */
    )
{
     int               args_num = 0;
     int               cur_arg = -1;
     me90drv_chnl_state_t *channel_state = NULL;
     mc_rd_reg_t       read_value;
     mc_wr_reg_t       intr_reset_value;
     drv_intercom_t *  drv_communication = NULL;
     intr_reason_t     interrupt_reason = undefined_intr_reason;
     int               channel = 0;
     int	       retrieve_trans_mode = 0;
     int	       sparc_task[10];
     int	       cur_try = 0;

     ME90_LOG(state, ME90_DL_TRACE,"get_intr_reason started\n"); /* !!!!! */

     mutex_enter(&state->mutex);			/* start MUTEX */
//   read_value.RGEN_read = state -> MC_CNTR_ST_REGS -> MC_TI_read;
     read_value.RGEN_read = state -> read_value.RGEN_read;
     read_value.RERR_read = 0; //alexmipt addition (architecture BUG)
     if (read_value.TISB_read == 0)   /* our board did not interrupt */
     {
        if (read_value.RERR_read != 0)
        {
           if (read_value.TLRM_read == 0)
           {
              if (state -> mp_state != crash_mp_state)
                 state -> mp_state = fault_mp_state;
              mutex_exit(&state->mutex);			/* end MUTEX */
              ME90_LOG(state, ME90_DL_TRACE,	/* !!!!!!!!!! */
                      "get_intr_reason interrupt on board error\n"
                     );
              ME90_LOG(state, ME90_DL_ERROR,
                      "reset module and MP on internal error REER = 0x%x"
                      " channel %d\n",
                      read_value.RERR_read,
                      read_value.RNC_read
                     );
              if (state -> drv_general_modes & RETRIEVE_DEV_FAULT_DRV_MODE)
                 me90_retrieve_trans_mode(state,0,check_and_do_restart_type,read_value);

              ME90_LOG(state, ME90_DL_TRACE,	/* !!!!!!!!!! */
                      "get_intr_reason finished\n"
                     );

              return board_error_intr_reason;
           }
        }
        mutex_exit(&state->mutex);			/* end MUTEX */
        ME90_LOG(state, ME90_DL_TRACE,"get_intr_reason reject interrupt\n");
        return reject_intr_reason;
     }

     drv_communication =
        (drv_intercom_t *) &state -> MC_BMEM[TR_CNTR_BUF_BMEM_ADDR];
     args_num = sizeof(drv_communication -> sparc_args.args_area)  /
                sizeof(*drv_communication -> sparc_args.args_area);
     for (cur_arg = 0; cur_arg < args_num; cur_arg ++)
     {
        interrupt_args -> args_area[cur_arg] =
           drv_communication -> sparc_args.args_area[cur_arg];
     }

     /*
      * Interrupt register reset
      */

     intr_reset_value.RGEN_write = 0;
#ifndef WITHOUT_TWISTING
     b2l_convertor_off(state->dip);
#endif
     state -> MC_CNTR_ST_REGS -> MC_TISB_write = intr_reset_value.RGEN_write;
#ifndef WITHOUT_TWISTING
     b2l_convertor_on(state->dip);
#endif
     for (cur_try = 0;
          cur_try < sizeof(sparc_task) / sizeof(*sparc_task);
          cur_try ++
         )
     {
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
        sparc_task[cur_try] = drv_communication -> sparc_task;
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
     }
     switch (sparc_task[2])
     {
        case transfer_end_mp_task       :
        case transfer_halted_mp_task    :
        case drq_transfer_end_mp_task   :
        case transfer_abort_end_mp_task :
           channel = interrupt_args -> transfer.dev_num;
           if (channel >= MAX_MC_BOARD_CHANNEL_NUM || channel < 0)
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "get_intr_reason bad channel # %d from MP\n",
                      channel
                     );
              interrupt_reason = undefined_intr_reason;
              break;
           }
           channel_state = &state -> all_channels_state[channel];
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
           if (drv_communication -> sparc_task == transfer_halted_mp_task)
           {
              interrupt_reason = dma_trans_halt_intr_reason;
	      ME90_LOG(state, ME90_DL_ERROR,
                      "get_intr_reason channel # %d dma trans halted due to error\n",
                      channel
                     );
              channel_state -> in_progress = 0;
           }
           else{
               interrupt_reason = dma_trans_end_intr_reason;
	   }
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
           if ((!channel_state -> busy &&
	       !(state -> drv_general_modes & MULTI_REQ_CHANNEL_DRV_MODE)) ||
	       (!channel_state -> busy &&
	       channel_state -> in_progress_start == NULL &&
	       (state -> drv_general_modes & MULTI_REQ_CHANNEL_DRV_MODE)))
           {
              if (channel_state -> transfer_state == timeout_trans_state  ||
                  channel_state -> transfer_state == aborted_trans_state
                 )
              {   /* transfer was aborted or timeout occured */
                 ME90_LOG(state, ME90_DL_TRACE,
                         "get_intr_reason: channel %d transfer was aborted or "
                         "timeout occured\n",
                         channel
                        );
                 interrupt_reason = aborted_intr_reason;
                 break;
              }
              else
              {
                 ME90_LOG(state, ME90_DL_ERROR,	/*!!!!!!!!*/
                         "get_intr_reason: interrupt from free channel %d"
                         " with task %d\n",
                         channel,
                         sparc_task[2]
                        );
                 interrupt_reason = undefined_intr_reason;
                 break;
              }
           }
           if (channel_state -> dma_intr_handled)
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "get_intr_reason multi-interrupt for channel # %d\n",
                      channel
                     );
              interrupt_reason = undefined_intr_reason;
              break;
           }
           else if (!channel_state -> streaming)
              channel_state -> dma_intr_handled = 1;
           me90drv_handle_trans_finish(state,channel,
                                   &interrupt_args -> transfer,
                                   read_value,
                                   intr_receiving_time,
                                   0	/* trans finished, or aborted */
                                  );
	   channel_state -> dma_intr_handled = 0;
           if (!channel_state -> streaming &&
	       channel_state -> in_progress_start == NULL)
		channel_state -> in_progress = 0;
           if (state -> mp_state == adapter_abend_mp_state)
              retrieve_trans_mode = 0;
           ME90_LOG(state, ME90_DL_TRACE,
                   "get_intr_reason: DMA channel %d transfer end interrupt "
                   "detected\n",
                   channel
                  ); /* !!!!! */
           break;
        case drq_receive_mp_task :
           channel = interrupt_args -> drq.dev_num;
           if (channel >= MAX_MC_BOARD_CHANNEL_NUM || channel < 0)
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "get_intr_reason bad DRQ channel # %d from MP\n",
                      channel
                     );
              interrupt_reason = undefined_intr_reason;
              break;
           }
           interrupt_reason = drq_receive_intr_reason;
           break;
        case mp_timer_expired_mp_task :
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
           ME90_LOG(state, ME90_DL_TRACE,
                   "get_intr_reason MP timer interrupt task # %d\n",
                   drv_communication -> sparc_task
                  );
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
           interrupt_reason = mp_timer_expired_intr_reason;
           break;
        case init_trans_mode_end_mp_task :
           interrupt_reason = init_trans_mode_end_intr_reason;
           break;
        case cnct_polling_good_mp_task :
           interrupt_reason = cnct_polling_good_intr_reason;
           break;
        case cnct_polling_bad_mp_task :
           interrupt_reason = cnct_polling_bad_intr_reason;
           break;
        case set_timetable_end_mp_task        :
        case device_adapter_read_end_mp_task  :
        case device_adapter_write_end_mp_task :
        case halt_trans_mode_end_mp_task      :
        case init_streaming_end_mp_task       :
        case init_trans_state_end_mp_task     :
        case halt_trans_state_end_mp_task     :
        case no_sparc_task :
        case drv_load_end_mp_task :
        default:
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
           ME90_LOG(state, ME90_DL_ERROR,
                   "get_intr_reason undefined interrupt task # %d %d %d %d %d %d %d %d BMEM %d\n",
                   sparc_task[0],sparc_task[1],sparc_task[2],sparc_task[3],
                   sparc_task[4],sparc_task[5],sparc_task[6],sparc_task[7],
                   drv_communication -> sparc_task
                  );
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
           interrupt_reason = undefined_intr_reason;
           break;
     }
#ifndef WITHOUT_TWISTING
b2l_convertor_off(state->dip);
#endif
     drv_communication -> sparc_task = no_sparc_task;
#ifndef WITHOUT_TWISTING
b2l_convertor_on(state->dip);
#endif
     mutex_exit(&state->mutex);			/* end MUTEX */
     if (retrieve_trans_mode                                       &&
         (state -> drv_general_modes & RETRIEVE_ADPT_ABEND_DRV_MODE)
        )
     {
        ME90_LOG(state, ME90_DL_ERROR,
                "get_intr_reason MP driver must be retrieved\n"
               );
        me90_retrieve_trans_mode(state,0,0,read_value);
     }

     ME90_LOG(state, ME90_DL_TRACE,"get_intr_reason finished\n"); /* !!!!! */

     return interrupt_reason;
}

/*
 * Release the asynchronous transfers resources
 */

/*ARGSUSED*/
void
mcb_release_async_trans(
	mcb_state_t	*state,
	int		channel,
	trans_buf_t	*trans_buf_p)
{
	trans_spec_t		*transfer_spec = NULL;

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_release_async_trans started for channel %d\n", channel);

	if (trans_buf_p -> trans_buf_desc.drv_buf_used &&
		trans_buf_p -> drv_buf_p != NULL) {
		transfer_spec = (trans_spec_t *)
			trans_buf_p -> drv_buf_p -> transfer_spec;
		kmem_free(trans_buf_p -> drv_buf_p -> uio_p -> uio_iov,
							sizeof(iovec_t));
		kmem_free(trans_buf_p -> drv_buf_p -> uio_p, sizeof(uio_t));
		trans_buf_p -> drv_buf_p -> uio_p = NULL;
		mcka_delete_drv_buf(state, trans_buf_p -> drv_buf_p);
		trans_buf_p -> drv_buf_p = NULL;
	} else if (trans_buf_p -> trans_buf_desc.uio_p != NULL) {
/*	} else if (trans_buf_p -> trans_buf_desc.bp != NULL) {
		mcka_buf_trans_done(state, channel,
			trans_buf_p -> trans_buf_desc.bp);
		transfer_spec = trans_buf_p -> trans_buf_desc.bp -> b_private;
		freerbuf(trans_buf_p -> trans_buf_desc.bp);
		trans_buf_p ->trans_buf_desc. bp = NULL;*/
		mcka_buf_trans_done(state, channel,
			trans_buf_p -> trans_buf_desc.uio_p);
		transfer_spec = trans_buf_p -> trans_buf_desc.uio_p -> transfer_spec;
/*		freerbuf(trans_buf_p -> trans_buf_desc.bp);*/
		kmem_free(trans_buf_p -> trans_buf_desc.uio_p -> uio_iov,
							sizeof(iovec_t));
		kmem_free(trans_buf_p -> trans_buf_desc.uio_p, sizeof(uio_t));
		trans_buf_p ->trans_buf_desc. uio_p = NULL;
	} else {
		if (trans_buf_p -> trans_buf_desc.drv_buf_used) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_release_async_trans NULL pointer of drv"
				" buf in trans buf 0x%x\n", trans_buf_p);
		} else {
			ME90_LOG(state, ME90_DL_ERROR,
				"mcka_release_async_trans NULL pointer of bp"
				" in trans buf 0x%x\n", trans_buf_p);
		}
	}
	if (transfer_spec != NULL) {
		if (transfer_spec -> trans_res_info != NULL)
			kmem_free(transfer_spec -> trans_res_info,
				sizeof(trans_info_t));
		kmem_free(transfer_spec, sizeof(trans_spec_t));
	}
		
	me90drv_delete_trans_header(state, trans_buf_p);

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_release_async_trans finished for channel %d\n", channel);
}

/*
 * The DMA data transfer engine start
 */

/*ARGSUSED*/
static	int
start_mcka_dma_engine(
	mcb_state_t	*state,
	int		channel
/*	int		flags*/)
{
     me90drv_chnl_state_t * channel_state = &state -> all_channels_state[channel];
/*   buf_t *            bp = NULL;*/
     uio_t		*uio_p = NULL;
     mcb_drv_buf_t *    drv_buf_p = NULL;
     trans_spec_t *     transfer_spec = NULL;
     trans_info_t *     trans_res_info = NULL;
     trans_buf_t *	cur_trans_buf = NULL;
     caddr_t		trans_base_addr = 0;
     size_t		trans_buf_size = 0;
     int                allowed_burst = 0;
     int                used_burst = 0;
     int                io_mode = 0;
     int		op_flags = 0;
     mp_drv_args_t      transfer_args;
     int                dev_access_mode = 0;
     int                rval = 0;

     ME90_LOG(state, ME90_DL_TRACE,"start_mcka_dma_engine started for channel %d\n",
             channel
            );
     mutex_enter(&state->mutex);			/* start MUTEX */
     cur_trans_buf = channel_state -> in_progress_start;
     mutex_exit(&state->mutex);		/* end MUTEX */
     if (cur_trans_buf == NULL)
        return EMPRESTART;
     if (!cur_trans_buf -> trans_buf_desc.drv_buf_used)
     {
  /*    bp = cur_trans_buf -> trans_buf_desc.bp;
        transfer_spec = bp -> b_private;
        trans_base_addr = bp -> b_un.b_addr;
        trans_buf_size = bp -> b_bcount;*/
	uio_p = cur_trans_buf -> trans_buf_desc.uio_p;
        transfer_spec = uio_p -> transfer_spec;
        trans_base_addr = uio_p->uio_iov[0].iov_base;
	trans_buf_size = uio_p->uio_iov[0].iov_len;
     }
     else
     {
        drv_buf_p = cur_trans_buf -> drv_buf_p;
        if (drv_buf_p != NULL)
           transfer_spec = drv_buf_p -> transfer_spec;
        trans_base_addr = cur_trans_buf -> trans_buf_desc.buf_address;
        trans_buf_size = cur_trans_buf -> trans_buf_desc.buf_size;
     }
     rval = mcka_get_burst_sizes(state,
                                channel_state,
                                transfer_spec,
                                trans_base_addr,
                                trans_buf_size,
                                &allowed_burst
                               );
     if (rval != 0)
     {
        ME90_LOG(NULL, ME90_DL_TRACE,
                "start_mcka_dma_engine channel %d mcka_get_burst_sizes"
                " failed\n",
                channel
               );
        return rval;
     }
     if (transfer_spec != NULL)
        trans_res_info = transfer_spec -> trans_res_info;
     if (allowed_burst & DMA_BURST_SIZE_64_BYTES)              
     {
        allowed_burst = DMA_BURST_SIZE_64_BYTES;
        used_burst = MCB_64_BURTS_SIZE_CODE;
     }
     else if (allowed_burst & DMA_BURST_SIZE_32_BYTES)
     {
        allowed_burst = DMA_BURST_SIZE_32_BYTES;
        used_burst = MCB_32_BURTS_SIZE_CODE;
     }
     else if (allowed_burst & DMA_BURST_SIZE_16_BYTES)
     {
        allowed_burst = DMA_BURST_SIZE_16_BYTES;
        used_burst = MCB_16_BURTS_SIZE_CODE;
     }
     else if (allowed_burst & DMA_BURST_SIZE_8_BYTES)
     {
        allowed_burst = DMA_BURST_SIZE_8_BYTES;
        used_burst = MCB_8_BURTS_SIZE_CODE;
     }
     else if (allowed_burst & DMA_BURST_SIZE_4_BYTES)
     {
        allowed_burst = DMA_BURST_SIZE_4_BYTES;
        used_burst = MCB_4_BURTS_SIZE_CODE;
     }
     else
     {
        ME90_LOG(state, ME90_DL_ERROR,
                "start_mcka_dma_engine - cannot find right burst size for"
                " transfer: allowed 0x%02x & enable 0x%02x & address"
                " 0x%08x\n",
                allowed_burst,MCB_ENABLE_BURST_SIZES,
                trans_base_addr
               );
        return EINVAL;
     };
     if (transfer_spec != NULL)
     {
	if (trans_res_info != NULL)
		trans_res_info -> burst_byte_size = allowed_burst;
        io_mode = transfer_spec -> io_mode_flags;
     }
     else
        io_mode = 0;
     if ((((long) trans_base_addr & (allowed_burst-1)) != 0   ||
          trans_buf_size % allowed_burst != 0
         )                                                       &&
         !(io_mode & ONLY_UNBUF_IO_MODE)
        )
     {
        ME90_LOG(state, ME90_DL_ERROR,
                "start_mcka_dma_engine - bad I/O address and size alignment"
                " burst sizes 0x%x bytes, address 0x%08lx size 0x%lx\n",
                allowed_burst,
                (u_long) trans_base_addr,
                trans_buf_size
               );
        return EINVAL;
     };
     ME90_LOG(state, ME90_DL_TRACE,
             "start_mcka_dma_engine transaction burst size %d bytes\n",
             allowed_burst
            );
     /*
      * Write information about DMA transfer for MP driver
      */

 /*  if (bp != NULL)
        op_flags = bp -> b_flags;*/
     if (uio_p != NULL)
        op_flags = uio_p->op_flags;
     else if (drv_buf_p != NULL)
        op_flags = drv_buf_p -> op_flags;
     else if (channel_state -> streaming)
        op_flags = B_READ;
     else
     {
        ME90_LOG(state, ME90_DL_ERROR,
                "start_mcka_dma_engine - bad I/O operation for channel %d\n",
                channel
               );
        return EINVAL;
     }
     if (op_flags & B_READ)
        transfer_args.transfer.opcode = read_trans_opcode;
     else if ( op_flags & B_WRITE)
        transfer_args.transfer.opcode = write_trans_opcode;
     else
     {
        ME90_LOG(state, ME90_DL_ERROR,
                "start_mcka_dma_engine - bad I/O operation b_flags 0x%x",
                op_flags
               );
        return EINVAL;
     }
     dbgmcka("start_mcka_dma_engine: transfer_args.transfer.opcode = 0x%x\n", transfer_args.transfer.opcode);
     if (state -> drv_general_modes & DATA_CACHE_FLUSH_DRV_MODE) {
	u_int	*os_code_p = (u_int *)0xf0040000;
	int	cur_word = 0;
	u_int	the_word = 0;
	for (cur_word = 0; cur_word < 1024; cur_word ++) {
		the_word |= os_code_p[cur_word * 8];
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"start_mcka_dma_engine - data cache flush has been done"
		" by driver, cache word summary 0x%08x\n", the_word);
     }
     transfer_args.transfer.dev_num = channel;
     dbgmcka("start_mcka_dma_engine: transfer_args.transfer.dev_num = 0x%x\n", transfer_args.transfer.dev_num);
     transfer_args.transfer.burst_size = used_burst;
     dbgmcka("start_mcka_dma_engine: transfer_args.transfer.burst_size = 0x%x\n", transfer_args.transfer.burst_size);
/*   transfer_args.transfer.address = cur_trans_buf -> trans_buf_desc.cookie.dmac_address;*/
     transfer_args.transfer.address = (u_int)cur_trans_buf -> trans_buf_desc.dma.prim_dev_mem;
     dbgmcka("start_mcka_dma_engine: transfer_args.transfer.address = 0x%x\n", transfer_args.transfer.address);
     transfer_args.transfer.size = cur_trans_buf -> trans_size;
     dbgmcka("start_mcka_dma_engine: transfer_args.transfer.size = 0x%x\n", transfer_args.transfer.size);

     if (transfer_spec == NULL)
     {
        transfer_args.transfer.repeation_num = 1;
        transfer_args.transfer.mode = dma_trans_mode;
        dev_access_mode = DIRECT_DEV_ACCESS_MODE;
     }
     else
     {
        transfer_args.transfer.repeation_num = transfer_spec -> repeation_num;
        if (transfer_spec -> io_mode_flags & DMA_TRANSFER_IO_MODE)
           transfer_args.transfer.mode = dma_trans_mode;
        else if (transfer_spec -> io_mode_flags & PROG_TRANSFER_IO_MODE)
           transfer_args.transfer.mode = progr_trans_mode;
        else if (transfer_spec -> io_mode_flags & PROG1_TRANSFER_IO_MODE)
           transfer_args.transfer.mode = progr1_trans_mode;
        else if (transfer_spec -> io_mode_flags & BMEM_TRANSFER_IO_MODE)
           transfer_args.transfer.mode = only_bmem_trans_mode;
        else
        {
           ME90_LOG(state, ME90_DL_ERROR,
                   "start_mcka_dma_engine - bad I/O transfer mode 0x%x\n",
                   transfer_spec -> io_mode_flags
                  );
           return EINVAL;
        }
        dev_access_mode = transfer_spec -> dev_access_mode;
     }
     dbgmcka("start_mcka_dma_engine: transfer_args.transfer.repeation_num = 0x%x\n", transfer_args.transfer.repeation_num);
     dbgmcka("start_mcka_dma_engine: transfer_args.transfer.mode = 0x%x\n", transfer_args.transfer.mode);
     if (dev_access_mode == DIRECT_DEV_ACCESS_MODE    ||
         dev_access_mode == ON_DEMAND_DEV_ACCESS_MODE
        )
        rval = submit_mp_task(state,data_transfer_mp_task,&transfer_args,0,
                              trans_res_info,
                              NULL,
                              0
                             );
     else if (dev_access_mode == WITH_DEMAND_DEV_ACCESS_MODE)
        rval = submit_mp_task(state,drq_data_transfer_mp_task,&transfer_args,0,
                              trans_res_info,
                              NULL,
                              0
                             );
     else
     {
        ME90_LOG(state, ME90_DL_ERROR,
                "start_mcka_dma_engine - bad I/O device access mode 0x%x\n",
                dev_access_mode
               );
        return EINVAL;
     }
     ME90_LOG(state, ME90_DL_TRACE,"start_mcka_dma_engine finished for channel %d\n",
             channel
            );
     return rval;
}

/*
 * Set the transfer results in accordance with info in transfer buffer header
 */

/*ARGSUSED*/
static int mcka_set_dma_trans_results(
     mcb_state_t *	state,
     int		channel,
     trans_buf_t *	trans_buf_p,
     trans_spec_t *	transfer_spec,
     size_t		moved_data_size
     )
{
#ifdef	_MP_TIME_USE_
     drv_intercom_t		*drv_communication = NULL;
#endif /* _MP_TIME_USE_ */
     trans_info_t *     trans_res_info = NULL;

     ME90_LOG(state, ME90_DL_TRACE,
             "mcka_set_dma_trans_results started for channel %d trans_buf 0x%08x"
             " trans_spec 0x%08x\n",
             channel,
             trans_buf_p,
             transfer_spec
            );
#ifdef	_MP_TIME_USE_
     drv_communication =
        (drv_intercom_t *) &state -> MC_BMEM[TR_CNTR_BUF_BMEM_ADDR];
#endif /* _MP_TIME_USE_ */
     if (transfer_spec == NULL)
        return trans_buf_p -> trans_error;
     trans_res_info = transfer_spec -> trans_res_info;
     if (trans_res_info == NULL)
        return trans_buf_p -> trans_error;
     trans_res_info -> trans_errno = trans_buf_p -> trans_error;
     if (!trans_buf_p -> pseudobuf)
     {
        if (moved_data_size == -1)
           trans_res_info -> real_byte_size += trans_buf_p -> real_trans_size;
        else
        {
           trans_res_info -> real_byte_size += moved_data_size;
           trans_buf_p -> buf_offset += moved_data_size;
        }
     }
     else
        trans_res_info -> missed_data_size += trans_buf_p -> real_trans_size;
     if (trans_res_info -> mp_error_code == 0)
        trans_res_info -> mp_error_code = trans_buf_p -> mp_error_code;
     if (trans_res_info -> state_byte == 0)
        trans_res_info -> state_byte = trans_buf_p -> board_state_byte;
     if (trans_res_info -> sp_state_byte == 0)
        trans_res_info -> sp_state_byte = trans_buf_p -> sp_state_byte;
     if (trans_res_info -> board_error_code == 0)
        trans_res_info -> board_error_code =
           trans_buf_p -> gen_reg_state.RERR_read;
	trans_res_info -> trans_num = trans_buf_p -> trans_num;
     trans_res_info -> intr_transfer_end = trans_buf_p -> intr_transfer_end;
#ifdef	_MP_TIME_USE_
     READ_MP_TIME(trans_res_info -> transfer_finish);
#else
     trans_res_info -> transfer_finish = ddi_gethrtime();
#endif	/* _MP_TIME_USE_ */

     ME90_LOG(state, ME90_DL_TRACE,
             "mcka_set_dma_trans_results successed for channel %d trans_buf 0x%08x"
             " trans_spec 0x%08x\n",
             channel,
             trans_buf_p,
             transfer_spec
            );
     return trans_buf_p -> trans_error;
}

/*
 * Set connection polling mode for MP driver
 */

/*ARGSUSED*/
int	mcb_set_connection_polling(
	mcb_state_t	*state,
	cnct_poll_set_t	*polling_setup_spec)
{
     mp_drv_args_t	set_polling_args;
     clock_t		cur_clock_ticks = 0;
     clock_t		timeout_clock_ticks = 0;
     clock_t		setup_waiting_time = 0;
     int                rval = 0;

     ME90_LOG(state, ME90_DL_TRACE,"mcka_set_connection_polling started "
             "interval %d cpu %d\n",
             polling_setup_spec -> interval,
             polling_setup_spec -> cpu_polling
            );

     mutex_enter(&state->mutex);				/* start MUTEX */
     if (state -> connection_state & MODE_ON_CONNECTION_STATE)
     {
       mutex_exit(&state->mutex);			/* end MUTEX */
        ME90_LOG(state, ME90_DL_ERROR,
                "mcka_set_connection_polling polling mode is set already\n"
               );
        return EINVAL;
     }
     state -> connection_state = MODE_ON_CONNECTION_STATE;
     state -> cnct_polling_error = 0;
     if (polling_setup_spec -> connection_events_num > 0)
     {
        if (state -> max_cnct_events_num > 0  ||
            state -> connection_events != NULL
           )
        {
           ME90_LOG(state, ME90_DL_ERROR,
                   "mcka_set_connection_polling events buffer is created"
                   " already\n"
                  );
        }
        else
        {
           state -> connection_events =
              kmem_alloc(polling_setup_spec -> connection_events_num *
                         sizeof(poll_event_info_t),
                         KM_NOSLEEP
                        );
           if (state -> connection_events == NULL)
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "mcka_set_connection_polling cannot allocate kernel"
                      " memory for events buffer\n"
                     );
              mutex_exit(&state->mutex);			/* end MUTEX */
              return EINVAL;
           }
           state -> max_cnct_events_num =
              polling_setup_spec -> connection_events_num;
           state -> cur_cnct_events_num = 0;
           state -> losed_events_num = 0;
        }
     }
     mutex_exit(&state->mutex);				/* end MUTEX */
     if (polling_setup_spec -> interval == 0)
        set_polling_args.set_cnct_polling.interval = CNCT_POLLING_INTERVAL_DEF;
     else
        set_polling_args.set_cnct_polling.interval =
           polling_setup_spec -> interval;
     set_polling_args.set_cnct_polling.interval = 
        set_polling_args.set_cnct_polling.interval / me90_mp_nsec_cycle * 1000;
     set_polling_args.set_cnct_polling.cpu_polling =
        polling_setup_spec -> cpu_polling;
     rval = submit_mp_task(state,set_cnct_polling_mp_task,
                           &set_polling_args,
                           0,
                           NULL,
                           NULL,
                           0
                          );
     mutex_enter(&state->mutex);				/* start MUTEX */
     if (rval != 0)
     {
        me90drv_delete_connection_polling(state, rval);
        mutex_exit(&state->mutex);			/* end MUTEX */
        ME90_LOG(state, ME90_DL_ERROR,
                "mcka_set_connection_polling: mp task failed\n"
               );
        return rval;
     }
     state -> connection_state |= MP_TAKE_CONNECTION_STATE;
     setup_waiting_time = polling_setup_spec -> setup_timeout;
     if (setup_waiting_time == 0)
     {
        if ((state -> connection_state & IS_SET_CONNECTION_STATE)  &&
            (state -> connection_state & MODE_ON_CONNECTION_STATE)
           )
           rval = 0;
        else
           rval = ETIME;
       mutex_exit(&state->mutex);			/* end MUTEX */
        return rval;
     }
     if (setup_waiting_time != -1)
     {
        drv_getparm(LBOLT,(u_long *) &cur_clock_ticks);
        timeout_clock_ticks =
           cur_clock_ticks + drv_usectohz(setup_waiting_time * 1000);
     }
     rval = 0;
     while ((state -> connection_state & (IS_SET_CONNECTION_STATE   |
                                        MODE_OFF_CONNECTION_STATE |
                                        IS_RESET_CONNECTION_STATE
                                       )
            ) == 0                                                  &&
            (state -> connection_state & MODE_ON_CONNECTION_STATE)
           )
     {
        if (setup_waiting_time != -1)
             rval = cv_timedwait(&state -> cnct_polling_cv,
                               &state->mutex,
                               timeout_clock_ticks
                              );
	    /* rval = cv_spin_timedwait(&state -> cnct_polling_cv,
                               &state->lock,
                               timeout_clock_ticks
                              );*/
        else
             rval = cv_wait_sig(&state -> cnct_polling_cv, &state->mutex);
//	     rval = cv_spin_wait(&state -> cnct_polling_cv, &state->lock);	
        if (rval < 0)
        {
           rval = ETIME;
           ME90_LOG(state, ME90_DL_TRACE,
                   "set connection polling: waiting for comity connection"
                   " timeouted\n"
                  );
           break;
        }
        else if (rval == 0)
        {
           rval = EINTR;
           ME90_LOG(state, ME90_DL_TRACE,
                   "set connection polling: waiting for comity connection"
                   " interrupted\n"
                  );
           break;
        }
        else
           rval = 0;
     }
     if (rval != 0)
     {
        mutex_exit(&state->mutex);			/* end MUTEX */
        mcb_reset_connection_polling(state, rval);
        ME90_LOG(state, ME90_DL_TRACE,"mcka_set_connection_polling finished with"
                                  " reset connection\n"
               );
        return rval;
     }
     if ((state -> connection_state & IS_SET_CONNECTION_STATE)  &&
         (state -> connection_state & MODE_ON_CONNECTION_STATE)
        )
        rval = 0;
     else if ((state -> connection_state & IS_RESET_CONNECTION_STATE) ||
              (state -> connection_state & MODE_OFF_CONNECTION_STATE) ||
              !(state -> connection_state & MODE_ON_CONNECTION_STATE)
             )
     {
        ME90_LOG(state, ME90_DL_ERROR,
                "mcka_set_connection_polling finished with bad connection state"
                " 0x%x\n",
                state -> connection_state
               );
        rval = EINVAL;
     }
     mutex_exit(&state->mutex);				/* end MUTEX */
     ME90_LOG(state, ME90_DL_TRACE,"mcka_set_connection_polling finished \n");
     return rval;
}

/*
 * Reset connection polling mode for MP driver
 */

/*ARGSUSED*/
int	mcb_reset_connection_polling(
	mcb_state_t	*state,
	int		reset_error)
{
     int                rval = 0;

     ME90_LOG(state, ME90_DL_TRACE,"mcka_reset_connection_polling started \n");

     mutex_enter(&state->mutex);				/* start MUTEX */
     if (!(state -> connection_state & MODE_ON_CONNECTION_STATE))
     {
        mutex_exit(&state->mutex);			/* end MUTEX */
        ME90_LOG(state, ME90_DL_ERROR,
                "mcka_reset_connection_polling polling mode is reset already\n"
               );
        return EINVAL;
     }
     if (state -> connection_state & MP_TAKE_CONNECTION_STATE)
     {
        mutex_exit(&state->mutex);			/* end MUTEX */
        rval = submit_mp_task(state,reset_cnct_polling_mp_task,
                              NULL,
                              0,
                              NULL,
                              NULL,
                              0
                             );
       mutex_enter(&state->mutex);			/* start MUTEX */
        if (rval != 0)
        {
           ME90_LOG(state, ME90_DL_ERROR,
                   "mcka_reset_connection_polling: mp task failed\n"
                  );
        }
        else
        {
           state -> connection_state &= ~MP_TAKE_CONNECTION_STATE;
           if (state -> connection_state & IS_SET_CONNECTION_STATE)
           {
              state -> connection_state &= ~IS_SET_CONNECTION_STATE;
              state -> connection_state |= IS_RESET_CONNECTION_STATE;
           }
        }
     }
     if (reset_error != 0)
        rval = reset_error;
     me90drv_delete_connection_polling(state, rval);
     if (state -> max_cnct_events_num > 0  || state -> connection_events != NULL)
     {
        kmem_free(state -> connection_events,
                  state -> max_cnct_events_num * sizeof(poll_event_info_t)
                 );
        state -> connection_events = NULL;
        state -> max_cnct_events_num = 0;
        state -> cur_cnct_events_num = 0;
        state -> losed_events_num = 0;
     }
     mutex_exit(&state->mutex);				/* end MUTEX */
     ME90_LOG(state, ME90_DL_TRACE,"mcka_reset_connection_polling finished \n");
     return rval;
}

/*
 * Wait for connection state change and when connection polling will detect
 * errors, then return the refusal to the caller
 */

/*ARGSUSED*/
int	mcb_poll_connection_state(
	mcb_state_t		*state,
	poll_cnct_state_t	*state_spec)	/* requested connection state */
{
     int                rval = 0;
     int		state_mask = state_spec -> state_mask;
     int		rstate_mask = 0;
     clock_t		cur_clock_ticks = 0;
     clock_t		timeout_clock_ticks = 0;
     clock_t		waiting_time = 0;

     ME90_LOG(state, ME90_DL_TRACE,"mcka_poll_connection_state started\n");

     mutex_enter(&state->mutex);				/* start MUTEX */
     if (state_mask == 0)
     {
        state_spec -> rstate_mask = state -> connection_state;
        if (state_spec -> time_info != NULL)
        {
           state_spec -> time_info -> alive_intr = state -> alive_intr_time;
           state_spec -> time_info -> refused_intr = state -> refused_intr_time;
           state_spec -> time_info -> drv_return = ddi_gethrtime();
        }
        mutex_exit(&state->mutex);			/* end MUTEX */
        ME90_LOG(state, ME90_DL_TRACE,
                "mcka_poll_connection_state polling mode with empty state mask\n"
               );
        return 0;
     }
     if (!(state -> connection_state & MODE_ON_CONNECTION_STATE) ||
         (state -> connection_state & MODE_OFF_CONNECTION_STATE)
        )
     {
        state_spec -> rstate_mask = state -> connection_state;
        mutex_exit(&state->mutex);			/* end MUTEX */
        ME90_LOG(state, ME90_DL_TRACE,
                "mcka_poll_connection_state polling mode is not set\n"
               );
        return EINTR;
     }
     waiting_time = state_spec -> timeout;
     if (waiting_time == 0)
     {
        rstate_mask = state -> connection_state & state_mask;
        if (rstate_mask == 0)
        {
           if (!(state -> connection_state & MODE_ON_CONNECTION_STATE) ||
               (state -> connection_state & MODE_OFF_CONNECTION_STATE)
              )
              rval = EINTR;
           else
              rval = ETIME;
           rstate_mask = state -> connection_state;
        }
        else
           rval = 0;
        state_spec -> rstate_mask = rstate_mask;
        if (state_spec -> time_info != NULL)
        {
           state_spec -> time_info -> alive_intr = state -> alive_intr_time;
           state_spec -> time_info -> refused_intr = state -> refused_intr_time;
           state_spec -> time_info -> drv_return = ddi_gethrtime();
        }
        mutex_exit(&state->mutex);			/* end MUTEX */
        ME90_LOG(state, ME90_DL_TRACE,
                "mcka_poll_connection_state null waiting time\n"
               );
        return rval;
     }
     if (waiting_time != -1)
     {
        drv_getparm(LBOLT,(u_long *) &cur_clock_ticks);
        timeout_clock_ticks =
           cur_clock_ticks + drv_usectohz(waiting_time * 1000);
     }
     rval = 0;
     while ((state_mask & state -> connection_state) == 0             &&
            (state -> connection_state & MODE_ON_CONNECTION_STATE)   &&
            !(state -> connection_state & MODE_OFF_CONNECTION_STATE)
           )
     {
        if (waiting_time != -1)
         rval = cv_timedwait(&state -> cnct_polling_cv,
                               &state->mutex,
                               timeout_clock_ticks
                              );
	/*   rval = cv_spin_timedwait(&state -> cnct_polling_cv,
                               &state->lock,
                               timeout_clock_ticks
                              );*/
        else
             rval = cv_wait_sig(&state -> cnct_polling_cv, &state->mutex);
//	     rval = cv_spin_wait(&state -> cnct_polling_cv, &state->lock);
        if (rval < 0)
        {
           rval = ETIME;
           ME90_LOG(state, ME90_DL_TRACE,
                   "mcka_poll_connection_state: waiting for state"
                   " timeouted\n"
                  );
           break;
        }
        else if (rval == 0)
        {
           rval = EINTR;
           ME90_LOG(state, ME90_DL_TRACE,
                   "mcka_poll_connection_state: waiting for state"
                   " interrupted\n"
                  );
           break;
        }
        else
           rval = 0;
     }
     rstate_mask = state -> connection_state & state_mask;
     if (rval != 0)
     {
        rstate_mask = state -> connection_state;
     }
     else if (!(state -> connection_state & MODE_ON_CONNECTION_STATE) ||
              (state -> connection_state & MODE_OFF_CONNECTION_STATE)
             )
     {
        if (rstate_mask == 0)
        {
           rstate_mask = state -> connection_state;
           rval = EINTR;
        }
     }
     state_spec -> rstate_mask = rstate_mask;
     if (state_spec -> time_info != NULL)
     {
        state_spec -> time_info -> alive_intr = state -> alive_intr_time;
        state_spec -> time_info -> refused_intr = state -> refused_intr_time;
        state_spec -> time_info -> drv_return = ddi_gethrtime();
     }
     mutex_exit(&state->mutex);				/* end MUTEX */
     ME90_LOG(state, ME90_DL_TRACE,"mcka_poll_connection_state finished \n");
     return rval;
}

/*
 * Handler of interrupt from connecton polling service of MP driver
 */

/*ARGSUSED*/
static void mcka_connection_polling_intr(
     mcb_state_t *	state,
     int		connection_refused,
     hrtime_t		intr_receiving_time
     )
{
     int		connection_state = 0;
     poll_event_info_t	*cur_events_info = NULL;

     ME90_LOG(state, ME90_DL_TRACE,"mcka_connection_polling_intr started \n");

     mutex_enter(&state->mutex);			/* start MUTEX */
     connection_state = state -> connection_state;
     if (state -> connection_events != NULL)
     {
        if (state -> cur_cnct_events_num < state -> max_cnct_events_num)
           cur_events_info =
              &state -> connection_events[state -> cur_cnct_events_num];
        else
           state -> losed_events_num ++;
     }
     if (!(connection_state & MODE_ON_CONNECTION_STATE))
     {
        mutex_exit(&state->mutex);			/* end MUTEX */
        ME90_LOG(state, ME90_DL_ERROR,
                "mcka_connection_polling_intr polling is not set\n"
               );
        return;
     }
     if (connection_state & IS_SET_CONNECTION_STATE)
     {
        if (!connection_refused)
        {
           if (connection_state & ALIVE_CONNECTION_STATE)
           {
              state -> alive_intr_time = intr_receiving_time;
              if (cur_events_info != NULL)
              {
                 cur_events_info -> event = cpu_alive_poll_event_code;
                 cur_events_info -> time = intr_receiving_time;
                 state -> cur_cnct_events_num ++;
              }
              mutex_exit(&state->mutex);			/* end MUTEX */
              ME90_LOG(state, ME90_DL_TRACE,
                      "mcka_connection_polling_intr good state continues\n"
                     );
              return;
           }
           else if (connection_state & REFUSED_CONNECTION_STATE)
           {
              state -> connection_state &= ~REFUSED_CONNECTION_STATE;
              state -> connection_state |= ALIVE_CONNECTION_STATE;
              state -> alive_intr_time = intr_receiving_time;
              if (cur_events_info != NULL)
              {
                 cur_events_info -> event = recovered_poll_event_code;
                 cur_events_info -> time = intr_receiving_time;
                 state -> cur_cnct_events_num ++;
              }
              ME90_LOG(state, ME90_DL_TRACE,
                      "mcka_connection_polling_intr recovery of alive state\n"
                     );
           }
           else
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "mcka_connection_polling_intr invalid state # 1\n"
                     );
              return;
           }
        }
        else if (connection_state & ALIVE_CONNECTION_STATE)
        {
           state -> connection_state &= ~ALIVE_CONNECTION_STATE;
           state -> connection_state |= REFUSED_CONNECTION_STATE;
           state -> refused_intr_time = intr_receiving_time;
           if (cur_events_info != NULL)
           {
              cur_events_info -> event = refused_poll_event_code;
              cur_events_info -> time = intr_receiving_time;
              state -> cur_cnct_events_num ++;
           }
           ME90_LOG(state, ME90_DL_TRACE,
                   "mcka_connection_polling_intr goto connection refused state\n"
                  );
        }
        else if (connection_state & REFUSED_CONNECTION_STATE)
        {
           state -> refused_intr_time = intr_receiving_time;
           if (cur_events_info != NULL)
           {
              cur_events_info -> event = refused_poll_event_code;
              cur_events_info -> time = intr_receiving_time;
              state -> cur_cnct_events_num ++;
           }
           mutex_exit(&state->mutex);			/* end MUTEX */
           ME90_LOG(state, ME90_DL_TRACE,
                   "mcka_connection_polling_intr refused state continues\n"
                  );
           return;
        }
        else
        {
           ME90_LOG(state, ME90_DL_ERROR,
                   "mcka_connection_polling_intr invalid state # 2\n"
                  );
           return;
        }
     }
     else
     {
        if (!connection_refused)
        {
           state -> connection_state &= ~IS_RESET_CONNECTION_STATE;
           state -> connection_state |= IS_SET_CONNECTION_STATE;
           state -> connection_state &= ~REFUSED_CONNECTION_STATE;
           state -> connection_state |= ALIVE_CONNECTION_STATE;
           state -> alive_intr_time = intr_receiving_time;
           if (cur_events_info != NULL)
           {
              cur_events_info -> event = is_set_poll_event_code;
              cur_events_info -> time = intr_receiving_time;
              state -> cur_cnct_events_num ++;
           }
           ME90_LOG(state, ME90_DL_TRACE,
                   "mcka_connection_polling_intr initial connection is set\n"
                  );
        }
        else
        {
           if (cur_events_info != NULL)
           {
              cur_events_info -> event = interrupted_poll_event_code;
              cur_events_info -> time = intr_receiving_time;
              state -> cur_cnct_events_num ++;
           }
           mutex_exit(&state->mutex);			/* end MUTEX */
           ME90_LOG(state, ME90_DL_TRACE,
                   "mcka_connection_polling_intr initial connection setting"
                   " interrupted\n"
                  );
           return;
        }
     }
     cv_broadcast(&state -> cnct_polling_cv);
     mutex_exit(&state->mutex);				/* end MUTEX */
     ME90_LOG(state, ME90_DL_TRACE,"mcka_connection_polling_intr finished \n");
     return;
}

/*
 * Recover all needed setup, state and mode to start transfers,
 */

/*ARGSUSED*/
int
mcb_recover_trans_state(
	mcb_state_t	*state,
	int		drv_comm_area_locked,
	int		mutex_locked)
{
	int			rval = 0;

	ME90_LOG(state, ME90_DL_TRACE,"mcka_recover_trans_state started \n");

	ME90_LOG(state, ME90_DL_TRACE, "mcka_recover_trans_state finished\n");
	return rval;
}

/*
 * Set the transfer results field in the initial state
 */

/*ARGSUSED*/
static void mcka_init_trans_results(
	trans_spec_t *	transfer_spec
	)
{
	trans_info_t *	trans_res_info = NULL;

	ME90_LOG(NULL, ME90_DL_TRACE,
			"%s(): started for trans_spec 0x%lx\n", __func__, 
			transfer_spec
			);

	if ( transfer_spec != NULL ) {
		trans_res_info = transfer_spec -> trans_res_info;

		if ( trans_res_info != NULL ) {
			trans_res_info -> trans_errno = 0;
			trans_res_info -> trans_num = 0;
			trans_res_info -> board_error_code = 0;
			trans_res_info -> burst_byte_size = 0;
			trans_res_info -> real_byte_size = 0;
			trans_res_info -> intr_transfer_end = -1;
			trans_res_info -> transfer_start = -1;
			trans_res_info -> transfer_finish = -1;
			trans_res_info -> mp_error_code = 0;
			trans_res_info -> state_byte = 0;
			trans_res_info -> sp_state_byte = 0;
			trans_res_info -> channel_check_word = 0;
			trans_res_info -> missed_data_size = 0;
			trans_res_info -> intr_drq_received = -1;
		}
	}

	ME90_LOG(NULL, ME90_DL_TRACE,
			"%s(): successed for trans_spec 0x%lx\n", __func__, 
			transfer_spec
			);
}

/*
 * MP-driver Interrupts handler
 */
static irqreturn_t
mcka_intr_thread_handler(int irq, void *arg)
{
	mcb_state_t *state = (mcb_state_t *)arg;
	me90drv_chnl_state_t *channel_state = NULL;
	intr_reason_t	intr_reason = undefined_intr_reason;
	sparc_drv_args_t	interrupt_args;
	int		channel = 0;
	drv_intercom_t *	drv_communication = NULL;
#ifdef	_MP_TIME_USE_
	u_int		intr_receiving_time = 0;
#else
	hrtime_t		intr_receiving_time;
#endif	/* _MP_TIME_USE_ */

#if 0
     daemonize("mcka_intr_handler");
     do
     {
waiting_mode:
	ME90_LOG(state, ME90_DL_TRACE, "MCKA: waiting for interrupt, in_interrupt = %ld !!!!\n", in_interrupt());
	current->policy = SCHED_FIFO;
	interruptible_sleep_on(&state->state_mcka_intr_handler);
	if (state->waking_up_mcka_intr_handler == 1){
		ME90_LOG(state, ME90_DL_TRACE, "waking_up_mcka_intr_handler !!!\n");
		state->waking_up_mcka_intr_handler = 0;
		break;
	}
        if (state->state_mcka_intr_handler_shutdown == 1) {
		ME90_LOG(state, ME90_DL_TRACE, "MCKA: mcka_intr handler exit by signal\n");
		state->state_mcka_intr_handler_shutdown = 0; 
		return 0;
	}
     }  while (1);
#endif

#ifndef	_MP_TIME_USE_
	intr_receiving_time = ddi_gethrtime();
#endif	
	drv_communication = (drv_intercom_t *)&state->MC_BMEM[TR_CNTR_BUF_BMEM_ADDR];
#ifdef	_MP_TIME_USE_
	READ_MP_TIME(intr_receiving_time);
#endif	/* _MP_TIME_USE_ */
	ME90_LOG(state, ME90_DL_TRACE,"mcka_intr started\n"); /* !!!!! */

	intr_reason = get_intr_reason(state,&interrupt_args,intr_receiving_time);
	switch ( intr_reason )
	{
		case reject_intr_reason:
			ME90_LOG(state, ME90_DL_TRACE,"mcka_intr reject interrupt\n");
			return IRQ_HANDLED;
		case dma_trans_end_intr_reason:
		case dma_trans_halt_intr_reason:
			channel = interrupt_args.transfer.dev_num;
			ME90_LOG(state, ME90_DL_TRACE,
				"mcka_intr takes DMA channel %d transfer end interrupt\n",
				channel); /* !!!!! */

			channel_state = & state -> all_channels_state[channel];
			mcka_terminate_dma_trans(state,channel);

			if ( !channel_state -> streaming )
				me90drv_start_new_trans(state,channel);

			ME90_LOG(state, ME90_DL_TRACE,
					"mcka_intr DMA channel %d transfer end interrupt claimed\n",
					channel); /* !!!!! */
			return IRQ_HANDLED;
		case drq_receive_intr_reason:
			channel = interrupt_args.drq.dev_num;
			ME90_LOG(state, ME90_DL_TRACE,
					"mcka_intr received DRQ from channel %d interrupt\n",
					channel);
			start_pending_transfer(state,channel,intr_receiving_time);
			return IRQ_HANDLED;
		case board_error_intr_reason:
			ME90_LOG(state, ME90_DL_TRACE,
					"mcka_intr - board internal error interrupt reason\n");
			return IRQ_HANDLED;
		case mp_timer_expired_intr_reason:
			ME90_LOG(state, ME90_DL_TRACE,"mcka_intr MP timer expired interrupt\n");
			handle_mp_timer_intr(state,intr_receiving_time);
			return IRQ_HANDLED;
		case aborted_intr_reason:
			ME90_LOG(state, ME90_DL_TRACE,
					"mcka_intr - aborted transfer interrupt reason\n");
			return IRQ_HANDLED;
		case init_trans_mode_end_intr_reason:
			ME90_LOG(state, ME90_DL_TRACE,
					"mcka_intr - end of init transfer modes interrupt reason\n");

			mutex_enter(&state->mutex);			/* start MUTEX */
			state -> trans_mode_inited = 1;

			if ( interrupt_args.init_trans_results.mp_error_code != 0 ) {
				state -> trans_mode_init_error = EIO;
				ME90_LOG(state, ME90_DL_ERROR,
					"mcka_intr - init transfer modes finished with error"
					" detected by MP driver 0x%02x\n",
					interrupt_args.init_trans_results.mp_error_code
				);
			}

			cv_broadcast(&state -> channel_cv);
			mutex_exit(&state->mutex);			/* end MUTEX */
			return IRQ_HANDLED;
		case cnct_polling_good_intr_reason:
		case cnct_polling_bad_intr_reason:
			ME90_LOG(state, ME90_DL_TRACE,
					"mcka_intr connection polling %s interrupt at time %s\n",
					(intr_reason == cnct_polling_good_intr_reason) ? "good" : "bad"
					);
			mcka_connection_polling_intr(state,
			intr_reason == cnct_polling_bad_intr_reason,
			intr_receiving_time);
			return IRQ_HANDLED;
		case undefined_intr_reason:
		default:
			ME90_LOG(state, ME90_DL_ERROR,	/*!!!!!!!!!*/
				"mcka_intr - undefined interrupt reason # %d\n",
				intr_reason);
			return IRQ_HANDLED;
	}
}

irqreturn_t
mcka_interrupt(int irq, void* arg)
{
	mcb_state_t *	state = (mcb_state_t *)arg;
	mc_wr_reg_t        intr_reset_value;

	ME90_LOG(state, ME90_DL_TRACE, "mcka_interrupt !!!! \n");
#ifndef WITHOUT_TWISTING
	b2l_convertor_off(dip);
#endif
	ME90_LOG(state, ME90_DL_TRACE, "mcka_interrupt: TISB_read = 0x%x\n", 
			state->MC_CNTR_ST_REGS->MC_RGEN_read.TI.TISB_read);

	if ( state->MC_CNTR_ST_REGS->MC_RGEN_read.TI.TISB_read != 0  ) {
		state->read_value.RGEN_read = state->MC_CNTR_ST_REGS->MC_TI_read; /* reading ints */

		/* clear ints */
		intr_reset_value.RGEN_write = 0;
		state->MC_CNTR_ST_REGS->MC_TISB_write = intr_reset_value.RGEN_write;
#ifndef WITHOUT_TWISTING
		b2l_convertor_on(dip);
#endif
		//schedule_work(&state->interrupt_tqueue);
		return IRQ_WAKE_THREAD;
	} else {
#ifndef WITHOUT_TWISTING
		b2l_convertor_on(dip);
#endif
		return IRQ_NONE;
	}
}

/**
 * Free transfer buffers
 */
/*ARGSUSED*/
void
mcka_free_trans_bufs(
	mcb_state_t		*state,
	me90drv_trbuf_desc_t	*trans_buf_desc)
{
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_free_trans_bufs started for buffer 0x%lx\n",
		trans_buf_desc);
	
	mcka_dma_free_coherent(state, trans_buf_desc->dma.real_size,
			trans_buf_desc->dma.dma, trans_buf_desc->dma.prim_dev_mem);

//	ddi_dma_mem_free(state->dip, trans_buf_desc->dma.real_size, 
//		trans_buf_desc->dma.prim_dev_mem, trans_buf_desc->dma.dma);

	trans_buf_desc -> buf_address = NULL;

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_free_trans_bufs succeeded\n");
}

/*
 * Delete I/O operation transfer buffer header structure
 */

/*ARGSUSED*/
void
mcb_delete_trans_header(
	mcb_state_t	*state,
	trans_buf_t	*trans_buf_p)
{
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_delete_trans_header started for buffer 0x%lx\n",
		trans_buf_p);

	if (!trans_buf_p -> trans_buf_desc.only_link)
		mcka_free_trans_bufs(state, &trans_buf_p -> trans_buf_desc);
	kmem_free(trans_buf_p, sizeof(trans_buf_t));
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_delete_trans_header succeeded\n");
}

/*
 * Set the transfer buffer header results field to the initial state
 */

/*ARGSUSED*/
void
mcka_fill_trans_bufs(
	mcb_state_t		*state,
	me90drv_trbuf_desc_t	*trans_buf_desc)
{
	ME90_LOG(NULL, ME90_DL_TRACE,
		"mcka_fill_trans_bufs started for buffer 0x%lx\n",
		trans_buf_desc);

	if (
#ifdef	__BLOCK_BUFFER_USE__
#if 0
		trans_buf_desc -> drv_buf_used &&
#endif
#endif	/* __BLOCK_BUFFER_USE__ */
		(state -> drv_general_modes & FILL_BUF_SPACE_DRV_MODE)) {
		int cur_word = 0;
		for (cur_word = 0;
			cur_word < trans_buf_desc -> buf_size / sizeof (long);
			cur_word ++) {
			((long *) (trans_buf_desc -> buf_address))[cur_word] =
				(long) &(((long *) (trans_buf_desc -> dma.prim_buf_addr))[cur_word]);
		}
	}

	ME90_LOG(NULL, ME90_DL_TRACE,
		"mcka_fill_trans_bufs succeeded for buffer 0x%lx\n",
		trans_buf_desc);
}

/*
 * Set the transfer buffer header results field to the initial state
 */

/*ARGSUSED*/
static	void
mcka_init_trans_header(
	mcb_state_t		*state,
	trans_buf_t		*trans_buf_p)
{
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_init_trans_header started for buffer 0x%lx\n",
		trans_buf_p);

	trans_buf_p -> real_trans_size = 0;
	trans_buf_p -> buf_offset = 0;
	trans_buf_p -> gen_reg_state.RGEN_read = 0;
	trans_buf_p -> mp_error_code = 0;
	trans_buf_p -> sparc_error_code = 0;
	trans_buf_p -> board_state_byte = 0;
	trans_buf_p -> sp_state_byte = 0;
	trans_buf_p -> trans_error = 0;
	trans_buf_p -> trans_num = -1;
	trans_buf_p -> intr_transfer_end = -1;
	mcka_fill_trans_bufs(state, &trans_buf_p -> trans_buf_desc);

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_init_trans_header succeeded for buffer 0x%lx\n",
		trans_buf_p);
}

/*
 * Create driver private buffer header structure
 */

/*ARGSUSED*/
static int mcka_create_drv_buf(
     mcb_state_t *	state,
     uio_t *		uio_p,
     int		op_flags,
     trans_spec_t *	transfer_spec,
     mcb_drv_buf_t **	new_trans_drv_buf_p
     )
{
     mcb_drv_buf_t *	new_trans_drv_buf = NULL;

     ME90_LOG(state, ME90_DL_TRACE,
             "mcka_create_drv_buf started with uio_p 0x%lx\n",
             uio_p
            );
     new_trans_drv_buf = kmem_alloc(sizeof(mcb_drv_buf_t),KM_NOSLEEP);
     if (new_trans_drv_buf == NULL)
     {
        ME90_LOG(state, ME90_DL_ERROR,
                "mcka_create_drv_buf cannot allocate kernel memory"
               );
        return EINVAL;
     }
     new_trans_drv_buf -> next_drv_buf = NULL;
     new_trans_drv_buf -> uio_p = uio_p;
     new_trans_drv_buf -> op_flags = op_flags;
     new_trans_drv_buf -> trans_error = 0;
     new_trans_drv_buf -> trans_completed = 0;
     new_trans_drv_buf -> transfer_spec = transfer_spec;
     cv_init(&new_trans_drv_buf -> trans_finish_cv);
     *new_trans_drv_buf_p = new_trans_drv_buf;

     ME90_LOG(state, ME90_DL_TRACE,
             "mcka_create_drv_buf successed for uio_p 0x%lx\n",
             uio_p
            );
     return 0;
}

/*
 * Delete driver private buffer header structure
 */

/*ARGSUSED*/
static void mcka_delete_drv_buf(
     mcb_state_t *       state,
     mcb_drv_buf_t *	 trans_drv_buf_p
     )
{
     ME90_LOG(state, ME90_DL_TRACE,
             "mcka_delete_drv_buf started for buffer 0x%lx\n",
             trans_drv_buf_p
            );
     cv_destroy(&trans_drv_buf_p -> trans_finish_cv);
     kmem_free(trans_drv_buf_p,sizeof(mcka_drv_buf_t));
     ME90_LOG(state, ME90_DL_TRACE,"mcka_delete_drv_buf successed\n");
}

/*
 * Abort the DMA data hanguped transfer
 */

/*ARGSUSED*/
int
abort_dma_transfer(
	mcb_state_t	*state,
	int		channel)
{
     me90drv_chnl_state_t * channel_state = &state -> all_channels_state[channel];
     int                rval = 0;
     mp_drv_args_t      transfer_args;

     ME90_LOG(state, ME90_DL_TRACE,"abort_dma_transfer started for channel %d\n",
             channel
            );
     transfer_args.transfer.dev_num = channel;
     transfer_args.transfer.opcode = 0;
     transfer_args.transfer.mode = 0;
     transfer_args.transfer.burst_size = 0;
     transfer_args.transfer.address = 0;
     transfer_args.transfer.size = 0;
     transfer_args.transfer.repeation_num = 0;
     if (channel_state -> streaming)
        rval =
           submit_mp_task(state,data_transfer_mp_task,&transfer_args,0,
                          NULL,
                          NULL,
                          0
                         );
     else
        rval =
           submit_mp_task(state,transfer_abort_mp_task,&transfer_args,0,
                          NULL,
                          NULL,
                          0
                         );

     if (rval == EMPRESTART)
     {
        ME90_LOG(state, ME90_DL_TRACE,
                "abort_dma_transfer retrieve transfers for channel %d\n",
                channel
               );
        rval = 0;
     }
     else if (rval != 0)
     {
        ME90_LOG(state, ME90_DL_ERROR,
                "abort_dma_transfer failed for channel %d\n",
                channel
               );
     }
     else
     {
        ME90_LOG(state, ME90_DL_TRACE,
                "abort_dma_transfer successed for channel %d\n",
                channel
               );
     }
     return rval;
}

/*
 *  The driver attachment state
 */

static	int	mcka_init_minor_created = 0;

/*
 * Driver chpoll entry point
 */
/*ARGSUSED*/
unsigned int mcka_chpoll(struct file *file, struct poll_table_struct *wait)
{
     ME90_LOG(NULL, ME90_DL_TRACE,"mcka_chpoll called, but not implemented\n");
     return  ENXIO;
}

/*
 * mcka_open
 * Called for each open(2) call on the device.
 */
/*ARGSUSED*/
int
mcka_open(struct inode *inode, struct file *file)
{
	mcb_state_t		*state;
	dev_t		dev = inode->i_rdev;
	int			instance;
	int			channel;
	int			firstopen = 0;

	ME90_LOG(NULL, ME90_DL_TRACE, "%s() started\n", __func__);

	/*
	 * Is the instance attached?
	*/
	if ( !dev )
		return ENXIO;

	instance = MCB_INST(dev);
	channel = MCB_CHAN(dev);

	state = mcka_states[instance];
	if ( state == NULL ) {
		printk("~%s~_open: unattached instance %d\n", mod_name, instance);
		return ENXIO;
	}

	/*
	 *  Verify the open flag
	*/
	mutex_enter(&state->mutex);
	firstopen = ( state->opened == 0 );

	if ( firstopen )
		me90drv_log_msg_num = 0;

	/*
	 * Mark the channel open in the map
	*/

	state->open_channel_map |= CHNL_NUM_TO_MASK(channel);

	/*
	 * Remember we're opened, if we get a detach request
	*/

	state->opened = 1;
	mutex_exit(&state->mutex);

	state->dev = dev;
	file->private_data = (void *)state;

	ME90_LOG(NULL, ME90_DL_TRACE,
		"%s(): succesed, instance %d channel %d\n", __func__, 
		instance, channel);

	return  0;
}

/*
 * Output results of the last transfer
 */

/*ARGSUSED*/
void
me90_output_trans_state(
	mcb_state_t		*state,
	me90drv_trans_buf_t	*trans_buf)
{
	int		buf_words = 0;
	int		cur_word = 0;
	u_int		*word_buf = NULL;

	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_output_trans_state started for trans header 0x%08x\n",
		trans_buf);
	me90_log(state, 0, "     transfer arguments and results\n");
#ifdef	__BLOCK_BUFFER_USE__
	if (trans_buf -> trans_buf_desc.drv_buf_used)
#endif	/* __BLOCK_BUFFER_USE__ */
		me90_log(state, 0, 
			"transfer used driver buf: address 0x%08x buf size "
			"0x%x transsize 0x%x real size 0x%x\n",
			trans_buf -> trans_buf_desc.buf_address,
			trans_buf -> trans_buf_desc.buf_size,
			trans_buf -> trans_size,
			trans_buf -> real_trans_size);
#ifdef	__BLOCK_BUFFER_USE__
	else
		me90_log(state, 0, 
			"transfer used system buf structure: trans "
			"size 0x%x real size 0x%x\n",
			trans_buf -> trans_size,
			trans_buf -> real_trans_size);
#endif	/* __BLOCK_BUFFER_USE__ */
	me90_log(state ,0, "DMA virtual address 0x%08x size 0x%x\n",
/*		trans_buf -> trans_buf_desc.cookie.dmac_address,
		trans_buf -> trans_buf_desc.cookie.dmac_size*/
		trans_buf -> trans_buf_desc.dma.prim_dev_mem,
		trans_buf -> trans_buf_desc.dma.real_size);
#ifdef	__BLOCK_BUFFER_USE__
	if (trans_buf -> trans_buf_desc.drv_buf_used) {
#endif	/* __BLOCK_BUFFER_USE__ */
		buf_words = (trans_buf -> trans_buf_desc.buf_size +
			(sizeof(u_int) - 1)) / sizeof(u_int);
		word_buf = (u_int *) trans_buf -> trans_buf_desc.buf_address;
#ifdef	__BLOCK_BUFFER_USE__
	} else {
		buf_words = (trans_buf -> trans_size +
			(sizeof(u_int) - 1)) / sizeof(u_int);
		/*word_buf = (u_int *) trans_buf -> trans_buf_desc.bp ->
								b_un.b_addr;*/
		word_buf = (u_int *) trans_buf -> trans_buf_desc.uio_p->uio_iov->iov_base;
	}
#endif	/* __BLOCK_BUFFER_USE__ */
	me90_log(state, 0, "transfer buffer contents:\n");
	for (cur_word = 0; cur_word < buf_words; cur_word ++) {
		me90_log(state, 0, "0x%08x 0x%08x : 0x%08x\n",
			cur_word * sizeof(u_int), cur_word,
			word_buf[cur_word]);
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"mcka_output_trans_state successed for trans header 0x%08x\n",
		trans_buf);
}

/*
 * Copy data from a MP base memory to a source kernel address. Source addresss
 * and base memory address must have the same alignment into word
 */
/*ARGSUSED*/
int   mcka_read_base_memory(
	mcb_state_t	*state,
	caddr_t		address_from, 
	caddr_t		address_to,
	size_t		byte_size,
	int		char_data)
{

     ME90_LOG(state, ME90_DL_TRACE,"mcka_read_base_memory unimplemented now\n");
     return EINVAL;
}

/*
 * Data transfer operations from/to base memory of MP and
 * general memory of SPARC  (mutex_enter must be done by caller)
 */
/*ARGSUSED*/

int  me90_bmem_data_transfer(
     mcb_state_t	*state,
     bmem_trans_desk_t	*transfer_desk,
     int		write_op,
     int		mode,
     int		char_data,
     caddr_t		kmem_buf,
     caddr_t		*kmem_area_p
                              )
{
     caddr_t       kmem_area = NULL;
     int           rval = 0;
     int           kmem_size = 0;
     int           word_rem = 0;

     if (write_op)
     {
        ME90_LOG(state, ME90_DL_TRACE,
                "mcka_bmem_data_transfer from SPARC memory 0x%08x"
                " to MP memory 0x%08x size 0x%x bytes\n",
                transfer_desk -> mem_address,
                transfer_desk -> mp_bmem_address,
                transfer_desk -> byte_size
               );
     }
     else
     {
        ME90_LOG(state, ME90_DL_TRACE,
                "mcka_bmem_data_transfer from MP memory 0x%08x"
                " to SPARC memory 0x%08x size 0x%x bytes\n",
                transfer_desk -> mp_bmem_address,
                transfer_desk -> mem_address,
                transfer_desk -> byte_size
               );
     }
     if ((long) transfer_desk -> mp_bmem_address < 0                         ||
         (long) transfer_desk -> mp_bmem_address >= MC_BMEM_REG_SET_LEN      ||
         (long) transfer_desk -> mp_bmem_address + transfer_desk -> byte_size >
         MC_BMEM_REG_SET_LEN
        )
     {
        ME90_LOG(state, ME90_DL_ERROR,
                "mcka_bmem_data_transfer bad MP BMEM address 0x%08x and/or"
                " size 0x%x\n",
                transfer_desk -> mp_bmem_address,
                transfer_desk -> byte_size
               );
        return EINVAL;
     }
     word_rem = ((long) transfer_desk -> mp_bmem_address & (sizeof(u_int)-1));
     kmem_size = transfer_desk -> byte_size + word_rem;
     if (kmem_buf == NULL)
        kmem_area = (caddr_t) kmem_alloc(kmem_size,KM_NOSLEEP);
     else
        kmem_area = kmem_buf;
     if (kmem_area == NULL)
     {
        ME90_LOG(state, ME90_DL_ERROR,
                "mcka_bmem_data_transfer: kmem_alloc no memory is available\n"
               );
        return EINVAL;
     }
     if (write_op)
     {
        if (ddi_copyin(transfer_desk -> mem_address,
                       &kmem_area[word_rem],
                       transfer_desk -> byte_size /*,
                       mode*/
                      )
           )
        {
           if (kmem_buf == NULL)
              kmem_free(kmem_area,kmem_size);
           ME90_LOG(state, ME90_DL_ERROR,
		"mcka_bmem_data_transfer ddi_copyin failed\n");
           return (EFAULT);
        }
     }
     if (write_op)
        rval = mcka_write_base_memory(state,
                                 &kmem_area[word_rem],
                                 transfer_desk -> mp_bmem_address,
                                 transfer_desk -> byte_size,
                                 char_data
                                );
     else
        rval = mcka_read_base_memory(state,
                                &kmem_area[word_rem],
                                transfer_desk -> mp_bmem_address,
                                transfer_desk -> byte_size,
                                char_data
                               );
     if (rval != 0)
     {
        if (kmem_buf == NULL)
           kmem_free(kmem_area,kmem_size);
        ME90_LOG(state, ME90_DL_ERROR,
                "mcka_bmem_data_transfer read/write base memory failed\n"
               );
        return rval;
     }
     if (!write_op)
     {
        if (ddi_copyout(&kmem_area[word_rem],
                        transfer_desk -> mem_address,
                        transfer_desk -> byte_size /*,
                        mode*/
                       )
           )
        {
           if (kmem_buf == NULL)
              kmem_free(kmem_area,kmem_size);
           ME90_LOG(state, ME90_DL_ERROR,
		"mcka_bmem_data_transfer ddi_copyout failed\n");
           return (EFAULT);
        }
     }
     if (kmem_buf == NULL)
        kmem_free(kmem_area,kmem_size);
     else if (kmem_area_p != NULL)
        *kmem_area_p = &kmem_area[word_rem];
     ME90_LOG(state, ME90_DL_TRACE,
             "mcka_bmem_data_transfer succeeded\n"
            );
     return 0;
}

/*
 *  Startup MP (driver ur any other code)
 */

/*ARGSUSED*/
int   me90_startup_mp(
	mcb_state_t	*state,
	int		cmd,
	int		mode)
{
	caddr_t			mp_init_code_p = NULL;
	mp_drv_args_t		*mp_drv_init_info_p = NULL;
	sparc_drv_args_t	drv_load_results;
	me90_mp_rom_drv_t	*mp_rom_drv_init_area = NULL;
	u_int			rom_drv_init_code[] =
					ME90_MP_ROM_DRV_INIT_CODE;
	int			rval = 0;

#ifdef DEBUG
	printk("mcka_startup_mp started with command 0x%x\n", cmd);
#endif
	mutex_enter(&state->mutex);			/* start MUTEX */

	state->mp_init_code.mp_bmem_address =
		(caddr_t) MC_MP_INIT_AREA_BMEM_ADDR;

	if (me90_reset_mp(state, 2, cmd == MCBIO_STARTUP_MP_ROM_DRV) != 0) {
#ifdef DEBUG
		printk(	"mcka_startup_mp: MP reset and halt finished with errors\n");
#endif
	}
	if (cmd == MCBIO_STARTUP_MP_ROM_DRV) {
		rval = mcka_write_base_memory(state,
				(caddr_t)&rom_drv_init_code,
				state -> mp_init_code.mp_bmem_address,
				sizeof(rom_drv_init_code), 1);
		if (rval != 0) {
			printk(	"mcka_startup_mp - write ROM driver "
				"init code in bmem failed\n");
		}
	} else {
		if (!state -> mp_drv_loaded) {
			mutex_exit(&state->mutex);		/* end MUTEX */
			printk(	"mcka_startup_mp MP driver code did not loaded"
				" in the BMEM\n");
			return (EINVAL);
		}
		rval = me90_bmem_data_transfer(state,
				&state -> mp_init_code, 1, mode,1,
				state -> mp_init_area_copy, &mp_init_code_p);
		if (rval != 0) {
			mutex_exit(&state->mutex);		/* end MUTEX */
			printk("mcka_startup_mp MP startup failed\n");
			return rval;
		}
	}
	if (state -> mp_init_code.mp_drv_init_info != NULL   &&
		state -> mp_init_code.mp_drv_init_info_size > 0) {
		if (cmd == MCBIO_STARTUP_MP_CODE) {
			bmem_trans_desk_t     mp_code_init_info;
			mp_code_init_info.mem_address =
				state -> mp_init_code.mp_drv_init_info;
			mp_code_init_info.mp_bmem_address =
				state -> mp_init_code.mp_drv_init_info_addr;
			mp_code_init_info.byte_size =
				state -> mp_init_code.mp_drv_init_info_size;
			rval = me90_bmem_data_transfer(state, &mp_code_init_info,
						1, mode, 0, NULL, NULL);
			if (rval != 0) {
				mutex_exit(&state->mutex);	/* end MUTEX */
				printk(	"mcka_startup_mp MP init info "
					"load failed\n");
				return rval;
			}
		} else {
			if (state -> mp_init_code.mp_drv_init_info_size >
				sizeof (mp_drv_args_t)) {
				mutex_exit(&state->mutex);	/* end MUTEX */
				printk(	"mcka_startup_mp too long MP "
					"init info 0x%lx > 0x%lx\n",
					(u_long)state -> mp_init_code.
							mp_drv_init_info_size,
					(u_long)sizeof (mp_drv_args_t));
				return (EINVAL);
			}
			mp_drv_init_info_p = &state -> mp_drv_init_info;
			if (copy_from_user ((void *)state -> mp_drv_init_info.args_area,
					    state -> mp_init_code.mp_drv_init_info,
					    state -> mp_init_code.mp_drv_init_info_size) != 0) {
				printk(	"mcka_startup_mp ddi_copyin "
					"failed for MP init info\n");
				return (EFAULT);
			}
		}
	}
	state -> mp_init_code.mem_address = mp_init_code_p;
	if (cmd == MCBIO_STARTUP_MP_ROM_DRV)
		state -> mp_debug_drv_flag = 0;
	else
		state -> mp_debug_drv_flag = 1;
	if (cmd == MCBIO_STARTUP_MP_CODE) {
		rval = me90drv_reset_general_regs(state, 0);
		state -> mp_drv_started = 1;
		state -> mp_state = started_mp_state;
		mutex_exit(&state->mutex);			/* end MUTEX */
		if (rval != 0) {
			printk(	"mcka_startup_mp MP code startup "
				"finished with error\n");
		} else {;
#ifdef DEBUG
			printk(	"mcka_startup_mp MP code stratup "
				"succeeded\n");
#endif
		}
		return (rval);
	}
	mp_rom_drv_init_area = (me90_mp_rom_drv_t *)
		&state -> ME90DRV_BMEM[ME90_MP_ROM_DRV_INIT_ADDR];
	mp_rom_drv_init_area -> debug_drv_start =
		(cmd != MCBIO_STARTUP_MP_ROM_DRV);
	mp_rom_drv_init_area -> rom_disable = 0;

	rval = me90drv_submit_mp_task(state, drv_load_mp_task,
			mp_drv_init_info_p, 1, NULL, &drv_load_results, 0);
	if (rval != 0) {
		if (cmd == MCBIO_STARTUP_MP_ROM_DRV)
			state -> mp_rom_drv_enable = 0;
		mutex_exit(&state->mutex);		/* end MUTEX */
#ifdef DEBUG
		printk("mcka_startup_mp MP driver init failed\n");
#endif
		return rval;
	}
	state -> mp_drv_started = 1;
	if (cmd == MCBIO_STARTUP_MP_ROM_DRV)
		state -> mp_rom_drv_enable =
			!mp_rom_drv_init_area -> rom_disable;
	mutex_exit(&state->mutex);			/* end MUTEX */
#ifdef DEBUG
	printk("mcka_startup_mp MP driver init succeeded\n");
#endif
	return 0;
}

int rmv_dev(int inst, me90drv_chnl_state_t * chd, uchar_t channel) 
{
	char	name[64];
	int 	error = 0;

#ifdef MCKA_DBG
	int     minor = MCB_MINOR(inst, channel);
#endif /* MCKA_DBG */

	(void) sprintf(name, "%s_%d_:%d", mod_name, inst, channel);

	error = ddi_unlink(MCKA_DIR, name);
	if ( error ) {
		printk("rmv_dev: ddi_unlink failed, error = %d\n", error);
		return error;
	}

#ifdef MCKA_DBG
	printk("%s%d_detach.rmv_dev: minor = %u !~~!\n",
		MCKA_NAME, channel, minor);
#endif /* MBKP_DBG */

	return error;
}

/*
 * Driver attach (init) entry point
 */
static int mcka_sbus_probe(struct of_device *op, const struct of_device_id *match)
{
	int		minor;
	int		instance = mcka_instances++;
	mcb_state_t	*state = NULL;
	int		rval;
	char	name[64];
	int		regs_mapped = 0;
	int		attach_flags = 0;
	int		add_attach_flags = 0;
	int		cur_chnl = 0;

	void	*regs;
	int		n_regs;
	int		i;
	u_int		max_reg_groups_number = 0;
	u_int		min_reg_groups_number = 0;
	int			without_eprom         = 0;

	dbgmcka("%s(): start\n", __func__);

	mcka_major = register_chrdev(0, MCKA_NAME, &mcka_fops);
	if ( mcka_major < 0 ) {
		return mcka_major;
	}

	/*
	 * Get the soft state for this instance
	 */
	state = ddi_malloc(sizeof(mcb_state_t));
	if ( state == NULL )
		return -ENOMEM;
	attach_flags |= SOFT_STATE_ALLOCATED;

	memset(state, 0, sizeof(mcb_state_t));

	/*
	 * Initialize the soft state for this instance
	 */
	state->op			= op;
	state->inst			= instance;
	state->major		= mcka_major;
	state->opened		= 0;
	state->open_flags	= 0;
	state->open_channel_map		= 0;
	state->drv_comm_busy		= 0;
	state->drv_general_modes	= DEFAULT_GENERAL_DRV_MODE;
	state->intr_number			= 0;
	state->intr_seted			= 0;
	state->mp_drv_loaded		= 0;
	state->mp_state				= undef_mp_state;
	state->mp_drv_started		= 0;
	state->mp_rom_drv_enable	= 0;
	state->mp_debug_drv_flag	= 0;
	state->set_tlrm				= 1;
	state->mp_init_code.mem_address = NULL;
	state->mp_init_code.mp_bmem_address = NULL;
	state->mp_init_code.byte_size  	= 0;
	state->mp_init_code.mp_drv_init_info = NULL;
	state->mp_init_code.mp_drv_init_info_size = 0;
	state->timeouts_num			= 0;
	state->timeout_idnt.expires	= 0;
	state->timeout_type			= no_timeout_type;
	state->timeout_rem			= 0;
	state->type_unit			= UNDEF_UT;

	mcka_states[state->inst] = state;

	dev_set_drvdata(&op->dev, state);

	for ( cur_chnl = 0; cur_chnl < MAX_ME90DRV_BOARD_CHANNEL_NUM;
		cur_chnl ++ ) {
		me90drv_chnl_state_t	*mcka_channel = NULL;

		mcka_channel = &state -> all_channels_state[cur_chnl];
		mcka_channel -> busy = 0;
		mcka_channel -> in_progress = 0;
		mcka_channel -> transfer_state = no_trans_state;
		mcka_channel -> timeout_type = no_timeout_type;
		mcka_channel -> timeout_rem = 0;
		mcka_channel -> wait_list_start = NULL;
		mcka_channel -> wait_list_end = NULL;
		mcka_channel -> wait_list_size = 0;
		mcka_channel -> in_progress_start = NULL;
		mcka_channel -> in_progress_end = NULL;
		mcka_channel -> in_progress_size = 0;
		mcka_channel -> completed_trans_start = NULL;
		mcka_channel -> completed_trans_end = NULL;
		mcka_channel -> completed_trans_size = 0;
		mcka_channel -> ready_atrans_start = NULL;
		mcka_channel -> ready_atrans_end = NULL;
		mcka_channel -> ready_atrans_size = 0;
		mcka_channel -> async_trans_num = 0;
		mcka_channel -> term_trans_processed = 0;
		mcka_channel -> last_term_trans_buf = NULL;
		mcka_channel -> trans_num = 0;
	}

	me90drv_init_drv_state(state);

	state->type_unit  = MCKA_UT;

	/*
	 * SBUS and MP clock-frequency definition
	 */
	me90_sbus_clock_freq = mcka_clock_freq(state);
	dbgmcka("%s(): me90_sbus_clock_freq = %d\n", __func__, me90_sbus_clock_freq);
	if ( me90_sbus_clock_freq < 10 * 1000000 ||
		me90_sbus_clock_freq > 25 * 1000000 ) {
		printk("%s(): SBus clock frequency %d out of range\n", __func__, me90_sbus_clock_freq / 1000000);
		goto  m_err;
	}

	me90_sbus_nsec_cycle	= 1000 * 1000000 / me90_sbus_clock_freq; /* nsec */
	me90_mp_clock_freq		= me90_sbus_clock_freq / 2;
	me90_mp_nsec_cycle		= 1000 * 1000000 / me90_mp_clock_freq; /* nsec */	

	/*
	 * Map in operating registers
	 */
	me90drv_init_reg_sets_pointers(state, state->type_unit);

	n_regs = mcka_nregs(state);

	max_reg_groups_number = me90drv_get_reg_sets_number(state->type_unit, 1);
	min_reg_groups_number = me90drv_get_reg_sets_number(state->type_unit, 0);

	if ( n_regs == max_reg_groups_number )
		without_eprom = 0;
	else if ( n_regs == min_reg_groups_number )
		without_eprom = 1;
	else {
		ME90_LOG(state, ME90_DL_ERROR,
			"%s(): wrong number of register "
			"sets %d instead %d or %d\n", __func__, 
			 n_regs,min_reg_groups_number,max_reg_groups_number);
		attach_flags |= ERRORS_SIGN;
		return -EFAULT;
	}

	for ( i = 0; i < n_regs; i++ ) {
		regs = mcka_ioremap(state, i);
		if ( !me90drv_put_reg_set_pointer(state,
				i + without_eprom, (caddr_t)regs) ) {
			ME90_LOG(state, ME90_DL_ERROR,
				"%s(): "
				"put_reg_set_pointer failed for "
				"register set # %d\n", __func__, i);
			attach_flags |= ERRORS_SIGN;
			return -EFAULT;
 		} else {
			ME90_LOG(state, ME90_DL_TRACE,
				"%s(): map regs set # "
				"%d, virt_addr = 0x%lx\n", __func__, i, 
				regs);
		}
	}

#if 0
	/*  SHOULD BE REMOVED*/
      		ME90_LOG(state, ME90_DL_TRACE,"Read GEN REGS: address %lx value %08x\n",
              		&state -> MC_CNTR_ST_REGS-> MC_TI_read,
              		state -> MC_CNTR_ST_REGS-> MC_TI_read
             	);
#endif
	ME90_LOG(state, ME90_DL_TRACE,
				"%s(): map reg MC_EPROM_REG_SET_LEN = 0x%lx\n", __func__, 
				MC_EPROM_REG_SET_LEN);
	
	ME90_LOG(state, ME90_DL_TRACE,
				"%s(): map reg MC_CNTR_ST_REG_SET_LEN = 0x%lx\n", __func__, 
				MC_CNTR_ST_REG_SET_LEN);

	ME90_LOG(state, ME90_DL_TRACE,
				"%s(): map reg MC_BMEM_REG_SET_LEN = 0x%lx\n", __func__, 
				MC_BMEM_REG_SET_LEN);

	attach_flags |= REGS_MAPPED;

	regs_mapped = 1;

	/*
	 * Initialize the module condition variables for the instance
	 */
	cv_init(&state -> channel_cv);
	cv_init(&state -> trans_start_cv);
	cv_init(&state -> atrans_end_cv);
	cv_init(&state -> drv_comm_cv);
//	state -> system_burst = 0x20;
	state -> system_burst = MCB_ENABLE_BURST_SIZES;

	attach_flags |= CHANNEL_CV_ADDED;

	if ( me90_reset_mp(state, 2, 1) != 0 ) {
		printk("%s(): Reset board and MP finished with error\n", __func__);
		return -EFAULT;
	}

	/*
	 * Initialize the mutex for this instance
	 */
	mutex_init(&state->mutex);
	raw_spin_lock_init(&state->lock);
	attach_flags |= MUTEX_ADDED;

/* interrupt handler and watchdog threads are defined here */
#if 0
	state->waking_up_mcka_intr_handler = 0;
	state->state_mcka_intr_handler_shutdown = 0;

	state->waking_up_mcka_watchdog_handler = 0;
	state->mcka_watchdog_handler_shutdown = 0;

	init_waitqueue_head(&(state->state_mcka_intr_handler));
	state->pid_state_mcka_intr_handler = kernel_thread(state_mcka_intr_handler, dip, 0);

	init_waitqueue_head(&(state->mcka_watchdog_handler));
	state->pid_mcka_watchdog_handler = kernel_thread(mcka_watchdog_handler, state, 0);
#endif
//	INIT_WORK(&(state->interrupt_tqueue), state_mcka_intr_handler, dip);
	INIT_WORK(&(state->watchdog_tqueue), mcka_watchdog_handler);
/* end of interrupt handler and watchdog routines */

	rval = mcka_request_irq(state);
	if ( rval ) {
		printk("request_irq fail\n");
		goto m_err;
	}
	
	attach_flags |= INTERRUPT_ADDED;
	state->intr_seted++;

#if MCKA_INTERRUPT_DEBUG
{
	unsigned long	bit;
	int *irq = (int *)of_get_property(op->node, "interrupts", NULL);
	if ( !irq )
		goto m_err;

	bit = 1 << (*irq + 6); // Unmask interrupt.
	printk("%s(): irq = %d\n", __func__, *irq);
	printk("%s(): int_mask = 0x%x\n", __func__, mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG));
//			mcst_write(INTERRUPT_REG_BASE + INTERRUPT_MASK_CLEAR, bit);
#endif /* MCKA_INTERRUPT_DEBUG */

	/*
	 *  Specific for module types driver additional Attachments
	 */
	if ( me90drv_attach_add(state, &add_attach_flags) != 0 )
		goto m_err;

	/*
	*  Startup MP driver from ROM
	*/
	if ( me90_startup_mp(state, MCBIO_STARTUP_MP_ROM_DRV, /*FKIOCTL*/ 0) != 0 ) {
		  printk("%s(): cannot startup MP ROM driver\n", __func__);
	}

	/*
	 * Create the minor nodes; one per channel. See the man
	 * page for ddi_create_minor_node(9f).
	 * The 2nd parameter is the minor node name; drvconfig(1M) appends
	 * it to the /devices entry, after the colon.
	 * The 4th parameter ('instance') is the actual minor number, put
	 * into the /devices entry's inode and passed to the driver.
	 * The 5th parameter ("DDI_NT_BLOCK_CHAN") is the node type; it's
	 * used by disks(1M) to create the links from /dev to /devices.
	 */
	for ( cur_chnl = mcka_init_minor_created;
		cur_chnl < MAX_ME90DRV_BOARD_CHANNEL_NUM; cur_chnl++ ) {

		minor = MCB_MINOR(instance, cur_chnl);

		(void) sprintf(name, "%s_%d_:%d", mod_name, instance,
                       cur_chnl);

		dbgmckadetail("%s(): getting minor for %d\n", __func__, minor);
		if ( ddi_create_minor(MCKA_DIR, name, S_IFCHR, new_encode_dev(MKDEV(state->major, minor))) ) {
			printk("%s(): ddi_create_minor failed %d\n", __func__, rval);
			goto m_err;
		}

		attach_flags |= MINOR_NODE_CREATED;
	}

	dbgmcka("%s() is finished for Driver %s inst %d\n", __func__, MCKA_NAME, state->inst);

	return 0;

m_err:
	if ( (attach_flags & INTERRUPT_ADDED) ) {
		if ( state->intr_seted > 0 ) {
			mcka_free_irq(state);
			state->intr_seted = 0;
		}
	}

	if ( add_attach_flags != 0 )
		me90drv_detach_add(state, add_attach_flags, 1);

	if ( attach_flags & CHANNEL_CV_ADDED ) {
		cv_destroy(&state -> channel_cv);
		cv_destroy(&state -> trans_start_cv);
		cv_destroy(&state -> atrans_end_cv);
		cv_destroy(&state -> drv_comm_cv);
	}

	if ( attach_flags & MUTEX_ADDED ) {
//		mutex_destroy(&state->mutex);
	}

	if ( attach_flags & REGS_MAPPED ) {
		me90drv_unmap_reg_sets(state);
	}

	if ( attach_flags & MINOR_NODE_CREATED ) {
		for ( cur_chnl = 0; cur_chnl < MAX_ME90DRV_BOARD_CHANNEL_NUM; cur_chnl++ )
			rmv_dev(instance, NULL, cur_chnl);
	}

	kfree(state);

	unregister_chrdev(mcka_major, MCKA_NAME);

	printk("%s(): FAILED\n", __func__);

	return DDI_FAILURE;
}

int
free_chan(mcb_state_t *state, me90drv_chnl_state_t	*channel_state, int cur_chnl)
{
	int		instance;

	/*
	 * If we have outstanding opens, we cannot detach
	 */
	if ( state->opened ) {
		ME90_LOG(state, ME90_DL_ERROR,
			"%s(): cannot detach opened device\n", __func__);

		return  DDI_FAILURE;
	}

	instance = state->inst;

	if ( channel_state -> in_progress )
		ME90_LOG(state, ME90_DL_ERROR,
			"free_chan: detach channel %d with "
			"transfer in progress\n", cur_chnl);
	if ( channel_state -> busy			||
	    channel_state -> in_progress_start != NULL	||
	    channel_state -> in_progress_end != NULL	||
	    channel_state -> in_progress_size != 0	||
	    channel_state -> wait_list_start != NULL	||
	    channel_state -> wait_list_end != NULL	||
	    channel_state -> wait_list_size != 0 ) {
		ME90_LOG(state, ME90_DL_ERROR,
			"%s(): detach busy or with transfers "
			"channel %d\n", __func__, cur_chnl);
	}

	if ( channel_state -> completed_trans_start != NULL  	||
	    channel_state -> completed_trans_end != NULL    	||
	    channel_state -> completed_trans_size != 0		||
	    channel_state -> term_trans_processed != 0 ) {
		ME90_LOG(state, ME90_DL_ERROR,
			"%s(): detach channel %d with not "
			"processed queue of completed transfers\n", __func__, 
			cur_chnl);
	}

	if ( channel_state -> ready_atrans_start != NULL  ||
	    channel_state -> ready_atrans_end != NULL    ||
	    channel_state -> ready_atrans_size != 0	||
	    channel_state -> async_trans_num != 0 ) {
		ME90_LOG(state, ME90_DL_ERROR,
			"%s(): detach channel %d with not "
			"empty queue of ready asynchronous transfers\n", __func__, 
			cur_chnl);

		mcka_release_all_async_trans(state, cur_chnl);
	}

	if ( channel_state -> last_term_trans_buf != NULL )
		ME90_LOG(state, ME90_DL_ERROR,
			"%s(): last transfer buf not freed "
			"channel %d\n", __func__, cur_chnl);
	/*
	 * Reset board and MP
	 */

	me90drv_reset_general_regs(state,2);

	/*
	 * Remove interrupt handler in ddi_unrgstr_dev(dip)
	 */

	if ( state->intr_seted > 0 )
		state -> intr_seted = 0;

	/*
	 * Remove timeout servises
	 */

	if ( state -> timeouts_num > 0 ) {
		ME90_LOG(state, ME90_DL_ERROR,
			"%s(): %d timeouts not handled\n", __func__, 
			state -> timeouts_num);

		if ( state -> timeout_idnt.expires != 0 )
		/*	untimeout(state -> timeout_idnt);*/
			del_timer_sync(&state -> timeout_idnt);
	} else if ( state -> timeout_idnt.expires > 0 ) {
		ME90_LOG(state, ME90_DL_ERROR,
			"%s(): not empty timeout identifier without"
			" timeouts\n", __func__);
			del_timer_sync(&state -> timeout_idnt);
	/*	untimeout(state -> timeout_idnt);*/
	}

	/*
	 * Detach the per-instance conditional variables and mutex
	 */

	cv_destroy(&state -> channel_cv);
	cv_destroy(&state -> trans_start_cv);
	cv_destroy(&state -> atrans_end_cv);
	cv_destroy(&state -> drv_comm_cv);

	//mutex_destroy(&state -> mutex);

	/*
	 * Detach a module specific additional items
	 */

	me90drv_detach_add(state, 0, 1);

	/*
	 * Unmap registers (from user here and from device in ddi_unrgstr_dev(dip))
	 * No nessesary to unmap from user; 
	 */

//	me90drv_unmap_reg_sets(state);
 
	return DDI_SUCCESS;
}

/*
 * Detach
 * Free resources allocated in mcka_attach
 */
/*ARGSUSED*/
static int mcka_sbus_remove(struct of_device *op)
{
	struct mcka_state *xsp = dev_get_drvdata(&op->dev);
	int cur_chnl = 0;
	int error = 0;

	if ( xsp == NULL )
		return -EFAULT;

	if ( xsp->opened ) {
		ME90_LOG(xsp, ME90_DL_ERROR,
			"%s(): cannot detach opened device\n", __func__);

		return DDI_FAILURE;
	}
#if 0
/* Killing interrupt handler and watchdog threads */
//	kill_proc(xsp->pid_state_mcka_intr_handler , SIGKILL, 1);
	xsp->state_mcka_intr_handler_shutdown = 1;
	wake_up(&xsp->state_mcka_intr_handler);
	while (xsp->state_mcka_intr_handler_shutdown != 0){
		schedule_timeout(1);
	}
//	kill_proc(xsp->pid_mcka_watchdog_handler , SIGKILL, 1);
	xsp->mcka_watchdog_handler_shutdown = 1;
	wake_up(&xsp->mcka_watchdog_handler);
	while (xsp->mcka_watchdog_handler_shutdown != 0){
		schedule_timeout(1);
	}
#endif
	for ( cur_chnl = 0; cur_chnl < MAX_ME90DRV_BOARD_CHANNEL_NUM; cur_chnl++ ) {
		error = free_chan(xsp, &xsp->all_channels_state[cur_chnl], cur_chnl);
		if ( error == DDI_FAILURE )
			return error;

		error = (int)rmv_dev(xsp->inst, NULL, cur_chnl);
	}

	me90drv_unmap_reg_sets(xsp);

	unregister_chrdev(xsp->major, MCKA_NAME);

	mcka_states[xsp->inst] = NULL;
	kfree(xsp);

	dev_set_drvdata(&op->dev, NULL);

	return error;
}

static const struct of_device_id mcka_sbus_match[] = {
	{
		.name = MCKA_NAME,
	},
	{},
};

MODULE_DEVICE_TABLE(of, mcka_sbus_match);

static struct of_platform_driver mcka_sbus_driver = {
	.name           = MCKA_NAME,
	.match_table    = mcka_sbus_match,
	.probe          = mcka_sbus_probe,
	.remove         = mcka_sbus_remove,
};

/// Check for hardware presence
static int
check_hardware(const char *name)
{
	struct device_node *dp;
	int	inst = 0;

	for_each_node_by_name(dp, name)
		inst++;

	if ( !inst )
		return 0;

	return inst;
}

/* Find all the lance cards on the system and initialize them */
static int __init mcka_init(void)
{
	int ret;
	mcka_instances = 0;

	dbgmcka("********* MCKA_INIT: START for %s *********\n", MCKA_NAME);

	if ( check_hardware(MCKA_NAME) == 0 )
		return -ENODEV;

	ret = of_register_driver(&mcka_sbus_driver, &of_bus_type);
	if ( ret < 0 )
		printk(KERN_INFO "%s(): Found no MCKA instances\n", __func__);

	dbgmcka("********* MCKA_INIT: FINISH. Found %d MCKA instances. %s() returs %d *********\n", mcka_instances, __func__, ret);

	return ret;
}

static void __exit mcka_exit(void)
{
	of_unregister_driver(&mcka_sbus_driver);
}

module_init(mcka_init);
module_exit(mcka_exit);
MODULE_LICENSE("Copyright by MCST 2004");
MODULE_DESCRIPTION("MCKA driver");
