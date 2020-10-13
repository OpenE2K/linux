/*
 * Copyright (c) 1997 by MCST.
 */

/*
 *	mbk3_reset.c
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/miscdevice.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/init.h>

#include <linux/mm.h>
/*maks #include <linux/wrapper.h> */
#include <linux/mcst/ddi.h>
#include <linux/timex.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>

#include <linux/delay.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/dma.h>
#include <asm/irq.h>

#include "bk3.h"

/* Имеются недочеты в запуске устройства на чтение... Усройство запускается на чтение из функции bk3_reset_device
   И находится в состоянии ожидания(прихода данных из канала) всегда.
   По получению прерывания по приходу данных из канала или по прерыванию D0 автоматически запускается 
   из обработчика прерываний, а также по команде "освободить считанные буфера"
   По моему мнению устройство должно запускаться по команде ioctl ...
   alexmipt@mcst.ru */

/* логика работы:
   Данные приходят в рабочий буфер work_buf выделенный(и удаленный из списка free_list).
   до тех пор пока не кончится список free_list (см. mbk3_intr.c).
   Cразу после получения данных в work_buf последний добавляется в список ready_list (готовые)
   По команде BK3_IOC_RD_BUF как только в ready_list что то появляется сразу же отдается пользователю
   после чего элементы списка ready_list перемещаются! в список busy_list.
   По команде BK3_IOC_PUT_BUF ("освободить считанные буфера") буфер с номером arg премещается из списка
   busy_list в спискок free_list. Если же при запуске BK3_IOC_PUT_BUF у нас Отсутствуют буфера на приём,
   т.е. free_list пустой - то буфер с номером arg становится work_buf и запускается устройство на прием, а
   признак Отсутствуют буфера на приём гасится */

int bk3_reset_device(bk3_devstate_t *bks)
{
	long	abstime;
	long	timeout;
	int	x, r;
	int	inst = bks->instance;
		
 	if (bk3_debug & BK3_DBG_RESET) {
		cmn_err(CE_NOTE, "bk3 %d: reset started", inst);
 	}
					 /* start */
	if (IS_ON_STATUS(bks, RESET_IN_PROGRESS)) {
		/* У0 каналов уже запущен */
		(void) drv_getparm(LBOLT, (unsigned long *) &abstime);
		timeout = drv_usectohz(bks->reset_time) + abstime;

		r = cv_timedwait(&bks->cv_D0_reset, &bks->mutex, timeout);
		if (r < 0) {
			/* timeout time was reached */
			if (bk3_debug & BK3_DEBUG_WAITING) {
			cmn_err(CE_NOTE,
			"bk3 reset_device %d:timeout time was reached",
				inst);
			}
			return ETIMEDOUT;
		}
		return (0);
	}

	ON_STATUS(bks, WE_RAISED_RESET | RESET_IN_PROGRESS);
	bks->stat.my_resets++;

	/* Обнулим устройство */
	if (GET_BK3_REG(bks, intr) & BK3_I_RESET) {
		if (bk3_debug & BK3_DBG_RESET) {
			cmn_err(CE_NOTE, "bk3 %d: reset got D0 intr", inst);
		}
		printk("bk3 %d: RESET got D0 intr", inst);
		bks->stat.peer_resets++;
		ON_STATUS(bks, CONFIRM_PEER_RESET);
	}
	SET_BK3_MASK(bks, 0xffffFFFF);

	if (bk3_debug & BK3_DBG_RESET) {
		cmn_err(CE_NOTE, "bk3 %d: reset command done", inst);
	}
	/* Дождёмся пока затихнет вся активность на устройстве */
	/* Все должны закончиться с ошибкой увидев RESET_IN_PROGRESS */
	(void) drv_getparm(LBOLT, (unsigned long *) &abstime);
	timeout = drv_usectohz(bks->reset_time) + abstime;
	while(IS_ON_STATUS(bks,
			READ_IS_ACTIVE | WRITE_IS_ACTIVE)) {
		if (bk3_debug & BK3_DBG_RESET) {
			cmn_err(CE_NOTE,
				"bk3 %d:reset waits for end activity", inst);
		}

		cv_broadcast(&bks->cv_cmd);
		cv_broadcast(&bks->cv_no_read_buffers);
		cv_broadcast(&bks->cv_no_write_buffers); 
		cv_broadcast(&bks->cv_msg_in); 
		cv_broadcast(&bks->cv_msg_out); 

		r = cv_timedwait(&bks->cv_reset, &bks->mutex, timeout);
		if (r < 0) {
			/* timeout time was reached */
			/*if (bk3_debug & BK3_DEBUG_WAITING)*/ {
			cmn_err(CE_NOTE,
			"bk3 reset_device %d:timeout time was reached",
				inst);
			}
			return (ETIME);
		}
	}

	if (bk3_debug & BK3_DBG_RESET) {
		cmn_err(CE_NOTE, "bk3 %d: reset no activity", inst);
	}

	/* Reinitialize some fields in bks */
	if (bk3_debug & (BK3_DBG_RESET | BK3_DBG_INTR)) {
		cmn_err(CE_NOTE, "bk3 %d: reset clear bks", inst);
	}
	bks->last_snd_cmd_tag = 0;
	bks->last_cmd_rpt_cnt = 0;
	bks->rd_ready = 0;
	bks->prots_matched = 1;

	if (IS_ON_STATUS(bks, CONFIRM_PEER_RESET)) {
		/* peer is doing reset as and asks us to confirm our reset */
						/* II do bk3_postd PEER_RESET */
		(void) bk3_postd(bks, BK3_C_PEER_RESET);
		OFF_STATUS(bks, CONFIRM_PEER_RESET);
	}
	SET_BK3_REG(bks, arst, 0);
	udelay(10000);
	x = GET_BK3_REG(bks, rctl);
	SET_BK3_MASK(bks, BK3_IM_ALL);
	/* RESET_STATUS; просим обнулиться соседа */

	/* Попросим обнулиться нашего абонента */
	SET_BK3_REG(bks, prst, 0);
	
	/* If peer is alive we off WE_RAISED_RESET | RESET_IN_PROGRESS */ 
	/* in interrupt handler due to correct syncronization . */
	/* If we do it here we can skip the valueable command */

	RESET_STATUS(bks);

	if(bk3_debug & BK3_DBG_RESET)
		cmn_err(CE_NOTE, "bk3 %d: reset: Free all Bufs", inst);

	bk3_init_pool_buf(bks);
	{ /* Недочеты в запуске устройсва */
		bk3_pool_buf_t* pool_buf = &bks->read_pool;
		pool_buf->work_buf = 
			list_entry(pool_buf->free_list.next, bk3_buf_t, list);
		list_del1(pool_buf->free_list.next);
		bks->stat.r_start = gethrtime();
		SET_BK3_REG(bks, rcwd, pool_buf->work_buf->address);
		SET_BK3_REG(bks, rcnt, TRANSF_CNT);
	}


	/* Подождем пока абонент не обнулится. Если он не ответил в течение */
	/* bks->reset_time микросекунд считаем что он отказал */

	(void) drv_getparm(LBOLT, (unsigned long *) &abstime);
	timeout = drv_usectohz(bks->reset_time) + abstime;

	if (cv_timedwait(&bks->cv_wait_peer_reset, &bks->mutex, timeout) == -1) {
		/* вышли по таймеру. считаем что абонент мёртв */
				RESET_STATUS(bks);
				ON_STATUS(bks, WRITE_IS_OVER);
				ON_STATUS(bks, PEER_IS_DEAD);
			if (bk3_debug & BK3_DBG_RESET) {
				cmn_err(CE_NOTE, "bk3 %d: reset peer dead "
					"by me."
					" status 0x%x", inst, bks->status);
		}
		return (ETIME);
	}
	ON_STATUS(bks, WRITE_IS_OVER | PEER_READ_IS_OVER);

	cv_broadcast(&bks->cv_D0_reset);
	
	if (bk3_debug & (BK3_DBG_RESET | BK3_DBG_START_TRANSFER)) {
		cmn_err(CE_NOTE, "bk3 %d: reset done by me. status 0x%x",
					inst, bks->status);
	}
	if (bk3_debug & BK3_DBG_RESET) {
		cmn_err(CE_NOTE, "bk3 %d: reset finish", inst);
	}


	return (0);
}	


/* Запускается по прерыванию D0. Абонент обнулился и хочет что бы мы тоже
 * обнулили себя. Ждет нашего подтверждения.
 */
void
bk3_D0_intr_handle(void *arg)
{

	bk3_devstate_t *bks = arg;
	long	abstime;
	long	timeout;
	int	x,r;
	int	inst = bks->instance;
	if (bk3_debug & (BK3_DBG_RESET | BK3_DBG_INTR)) {
		cmn_err(CE_NOTE, "bk3 %d: bk3_D0_intr_handle started", inst);
	}

	mutex_enter(&bks->mutex);
	bks->stat.peer_resets++;

	(void) drv_getparm(LBOLT, (unsigned long *) &abstime);
	timeout = drv_usectohz(bks->reset_time) + abstime;
	if(IS_ON_STATUS(bks, WE_RAISED_RESET)) {
		cv_broadcast(&bks->cv_wait_peer_reset);
		mutex_exit(&bks->mutex);
		return;
	}

	/* Будем нулиться по требованию абонента */
	ON_STATUS(bks, RESET_IN_PROGRESS);
	SET_BK3_REG(bks, arst, 0);
	udelay(10000);
	x = GET_BK3_REG(bks, rctl);
	SET_BK3_MASK(bks, BK3_IM_ALL);

	/* Дождёмся пока затихнет вся активность на устройстве */
	/* Все должны закончиться с ошибкой увидев RESET_IN_PROGRESS */
	(void) drv_getparm(LBOLT, (unsigned long *) &abstime);
	timeout = drv_usectohz(bks->reset_time) + abstime;

	while(IS_ON_STATUS(bks,
		READ_IS_ACTIVE | WRITE_IS_ACTIVE)) {
		if (bk3_debug & (BK3_DBG_RESET | BK3_DBG_INTR)) {
			cmn_err(CE_NOTE, "bk3 %d: D0_intr_handle waits"
				" for end activities, status 0x%x",
				inst, bks->status);
		}

		cv_broadcast(&bks->cv_cmd);
		cv_broadcast(&bks->cv_no_read_buffers);
		cv_broadcast(&bks->cv_no_write_buffers); 
		cv_broadcast(&bks->cv_msg_in); 
		cv_broadcast(&bks->cv_msg_out); 

		OFF_STATUS(bks, RESET_NEEDED);
		r = cv_timedwait(&bks->cv_reset, &bks->mutex, timeout);
		if (r < 0) {
			/* timeout time was reached */
			/*if (bk3_debug & BK3_DEBUG_WAITING)*/ {
			cmn_err(CE_NOTE,
			"bk3 reset_device %d:timeout time was reached",
				inst);
			}
			return;
		}
	}
	if (bk3_debug & (BK3_DBG_RESET | BK3_DBG_INTR)) {
		cmn_err(CE_NOTE, "bk3 %d: D0_intr_handle clear bks",
			inst);
	}
	bks->last_snd_cmd_tag = 0;
	bks->last_cmd_rpt_cnt = 0;

	RESET_STATUS(bks);

	bks->prots_matched = 1;

	if(bk3_debug & (BK3_DBG_RESET | BK3_DBG_INTR))
		cmn_err(CE_NOTE, "bk3 %d: reset: Free all Bufs", inst);

	bk3_init_pool_buf(bks);
	{
		bk3_pool_buf_t* pool_buf = &bks->read_pool;
	
		pool_buf->work_buf = 
			list_entry(pool_buf->free_list.next, bk3_buf_t, list);
		list_del1(pool_buf->free_list.next);
		bks->stat.r_start = gethrtime();
		SET_BK3_REG(bks, rcwd, pool_buf->work_buf->address);
		SET_BK3_REG(bks, rcnt, TRANSF_CNT);
	}
	bk3_postd(bks, BK3_C_PEER_RESET);

	/* Так как абонент обнулился он готов читать */
	ON_STATUS(bks, PEER_READ_IS_OVER | WRITE_IS_OVER);
	cv_broadcast(&bks->cv_D0_reset);
	if (bk3_debug & (BK3_DBG_RESET | BK3_DBG_INTR)) {
		cmn_err(CE_NOTE, "bk3 %d: D0_intr_handle finished. status 0x%x",
					inst, bks->status);
	}
	
	mutex_exit(&bks->mutex);
}
