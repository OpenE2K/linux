/*
 * Copyright (c) 1997 by MCST.
 */

/*
 *	mbk3_intr.c
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


	
void bk3_interrupt_handler(void *arg, u_int	 interrupts);



irqreturn_t bk3_intr(int irq, void *arg)
{	
	register bk3_devstate_t *bks = (bk3_devstate_t *)arg;
#ifdef BK3_REG_DEBUG
	int	 inst = bks->instance;
#endif
	int new_intr = GET_BK3_REG(bks, intr) & BK3_POSSIBLE_INTERRUPTS;

	if(new_intr){
		int tmp;
		raw_spin_lock(&bks->interrupt_lock);
		tmp = bks->interrupts;
		bks->interrupts |= new_intr;
		raw_spin_unlock(&bks->interrupt_lock);
		if(tmp == 0){
			bks->stat.true_intrs++;
			return IRQ_WAKE_THREAD;
		}
		return IRQ_NONE;
	}
	return IRQ_NONE;
}

irqreturn_t bk3_interrupt(int irq, void *arg)
{
	register bk3_devstate_t *bks = (bk3_devstate_t *)arg;
	u_int	 interrupts;

	raw_spin_lock_irq(&bks->interrupt_lock);
	interrupts = bks->interrupts;
	bks->interrupts = 0;
	raw_spin_unlock_irq(&bks->interrupt_lock);

	bk3_interrupt_handler(bks, interrupts);
	bks->stat.intrs++;
	return IRQ_HANDLED;
}

void
bk3_interrupt_handler(void *arg, u_int	 interrupts)
{
	register bk3_devstate_t *bks = arg;
	int	 inst = bks->instance; 
	u_int  	 command = 0;
	hrtime_t t = 0;

	if (bk3_debug & BK3_DBG_INTR) {
		cmn_err(CE_NOTE, 
			"bk3 %d: intr started. status 0x%x. intr = 0x%x"
			,inst,bks->status,interrupts);
	}

	if ((BK3_MASK(bks) & BK3_IM_M1) == 0) {
		interrupts &= ~BK3_IM1_INTRS;
		if (bk3_debug & BK3_DBG_INTR)
			cmn_err(CE_NOTE,"bk3intr %d: bad type of packet",inst);
	}
	if ((BK3_MASK(bks) & BK3_IM_M2) == 0) {
		interrupts &= ~BK3_IM2_INTRS;
		if (bk3_debug & BK3_DBG_INTR)
			cmn_err(CE_NOTE, "bk3intr %d: cmd has been read with error",inst);
	}
	if (interrupts & (BK3_I_SBUSPRTY | BK3_I_OPTPRTY |
			  BK3_I_RCVFLT | BK3_I_LSRFAILR |
			  BK_I_PKTERR)){
		if (interrupts & BK3_I_SBUSPRTY) {
			bks->stat.sbusprty++;
		}
		if (interrupts & BK3_I_OPTPRTY) {
			bks->stat.optprty++;
		}
		if (interrupts & BK3_I_LSRFAILR) {
			bks->stat.lsrfailr++;
		}
		if (interrupts & BK3_I_RCVFLT) {
			bks->stat.rcvflt++;
		}
		if (interrupts & BK_I_PKTERR) {
			bks->stat.sbusintrf++;
			if ((interrupts & BK3_I_ISCMD) || 
			    (interrupts & (BK3_I_RCVZERO | BK3_I_TRMZERO)))
				bks->stat.may_be_hidden++;
		}
		/* Unrecoverable error. Reset device is needed */
		mutex_enter(&bks->mutex);	
		ON_STATUS(bks, RESET_NEEDED);
		mutex_exit(&bks->mutex);
	
			return;
	}

	if (interrupts & BK3_I_RCVZERO) {
		u_int	c_rcwd = GET_BK3_REG(bks, rcwd);
		u_int	c_rcnt = GET_BK3_REG(bks, rcnt) & 0XFFFF;
		dma_addr_t end_addr = bks->read_pool.work_buf->address + bks->buf_size;
		
		if (interrupts & BK3_I_TRMZERO){
			bks->stat.intr_both_rw++;
		}else{
			bks->stat.intr_single_r++;
		}

		if ((c_rcnt != 0) || (end_addr != c_rcwd)){
			bks->stat.r_fail_addr_count++;
	
			printk("bk3 %d: fail rcv count-addr."
				" dma_addr:size %x:%lx = %x, rcwd:rcnt %x:%x", 
				inst, bks->read_pool.work_buf->address,
				(u_long)bks->buf_size, end_addr,
				c_rcwd, c_rcnt);
		}
		t = gethrtime() - bks->stat.r_start;
		bks->stat.rsize = bks->buf_size;	
		bks->stat.r_all_time += t;
		bks->stat.rsize_all += bks->buf_size;
		bks->stat.n_r++;

		mutex_enter(&bks->mutex);

    		if(bk3_debug & BK3_DBG_INTR)
       			cmn_err(CE_NOTE,"r_all_time = %lld, rsize_all=%ld, n_r=%d",
					bks->stat.r_all_time, 
					(u_long)bks->stat.rsize_all,bks->stat.n_r);

		if(IS_OFF_STATUS(bks, RESET_IN_PROGRESS) && 
				 IS_OFF_STATUS(bks, NO_RECEIVING_BUFFERS)){
			bk3_pool_buf_t* pool_buf = &bks->read_pool;
			list_add_tail1(&pool_buf->work_buf->list,
								&pool_buf->ready_list);
			if(!list_empty(&bks->read_pool.free_list)){
				pool_buf->work_buf = 
					list_entry(pool_buf->free_list.next, bk3_buf_t, list);
				list_del1(pool_buf->free_list.next);
				bks->stat.r_start = gethrtime();
				SET_BK3_REG(bks, rcwd, pool_buf->work_buf->address);
				SET_BK3_REG(bks, rcnt, TRANSF_CNT);
				bk3_postd(bks, BK3_C_RASK);
			}else{
				ON_STATUS(bks, NO_RECEIVING_BUFFERS);
                        }
			
		}

		if(IS_ON_STATUS(bks, READ_IS_ACTIVE)){
			cv_broadcast(&bks->cv_no_read_buffers);
			if (bk3_debug & BK3_DBG_INTR){	
				cmn_err(CE_NOTE,
				"bk3_intr %d: READ IS OVER,do broadcast cv_read",
				inst);
			}
		}else{
 			if(bk3_debug & BK3_DBG_INTR)
			cmn_err(CE_NOTE,
			"bk3_intr %d: READ IS OVER",inst);
		}
		mutex_exit(&bks->mutex);
	}

	if (interrupts & BK3_I_TRMZERO) {
		u_int	c_tcwd = GET_BK3_REG(bks, tcwd);
		u_int	c_tcnt = GET_BK3_REG(bks, tcnt) & 0XFFFF;
		bk3_pool_buf_t* pool_buf = &bks->write_pool;
		dma_addr_t	end_addr = 	pool_buf->work_buf->address + SZ_BUF_BK3;

		if (interrupts &  BK3_I_RCVZERO){
			bks->stat.intr_both_rw++;
		}else{
			bks->stat.intr_single_w++;
		}

		if ((c_tcnt != 0) || (end_addr != c_tcwd))
		{
			bks->stat.r_fail_addr_count++;

			cmn_err(CE_WARN, "bk3 %d: fail trm count-addr."
				" dma_addr:size %x:%lx = %x, tcwd:tcnt %x:%x"
				,inst,bks->write_pool.work_buf->address,
				(u_long)bks->buf_size, end_addr,
				c_tcwd, c_tcnt);
		}
		t = gethrtime() - bks->stat.w_start;
		bks->stat.w_all_time += t;
		bks->stat.wsize = bks->buf_size;
		bks->stat.wsize_all += bks->buf_size;
		bks->stat.n_w++;
		mutex_enter(&bks->mutex);	
		ON_STATUS(bks, WRITE_IS_OVER);
		if(list_empty(&pool_buf->free_list))
			cv_broadcast(&bks->cv_no_write_buffers);

		if(search_in_list(&pool_buf->free_list,
					 	pool_buf->work_buf->num) == 0)
			list_add_tail1(&pool_buf->work_buf->list, &pool_buf->free_list);

 		if(bk3_debug & BK3_DBG_INTR)
		cmn_err(CE_NOTE,"w_all_time= %lld,t = %lld, wsize_all= %ld,n_w= %d",
			bks->stat.w_all_time,t,
			(u_long)bks->stat.wsize_all,bks->stat.n_w);
	
		if (bk3_debug & BK3_DBG_INTR) {
			cmn_err(CE_NOTE, "bk3 %d: trm count == 0",inst);
			cmn_err(CE_NOTE, "bk3_intr %d:TRM:Finish",inst);
		}
		mutex_exit(&bks->mutex);
	}
	

	if (interrupts & BK3_I_CMDFLT) {
		/* command recieved with recoverable error */
		if (bk3_debug & (BK3_DBG_INTR | BK3_DBG_ERR_RETURNS)) {
			cmn_err(CE_NOTE, "BK3 %d: Command checking by module 2 0x%08x", inst, interrupts);
		}
		SET_BK3_REG(bks, rptcmd, 0);
	} else if (interrupts & BK3_I_ISCMD) {
		command = GET_BK3_REG(bks, rctl);
							/* Есть КОМАНДА */

		if (bk3_debug & (BK3_DBG_INTR | BK3_DBG_SEND_CMD)) {
			cmn_err(CE_NOTE, "bk3 %d: intr 0x%x claimed after "
				"read cmd 0x%8x", inst, interrupts, command);
		}
		if (command != 0) {
			switch(command & BK3_C_CMD_MASK){
			case BK3_C_SND_MSG:
				mutex_enter(&bks->mutex);
				if (bk3_debug & BK3_DBG_INTR)
					cmn_err(CE_NOTE, "bk3 %d: intr BK3_C_SND_MSG", inst);

				bks->msg_rcv.info = command & BK3_C_ARG_MASK;

							/* is command =SND_MSG */
				ON_STATUS(bks,WE_GOT_MESSAGE);
				cv_broadcast(&bks->cv_msg_in);

				if (bk3_debug & BK3_DBG_INTR)
					cmn_err(CE_NOTE,
						"bk3 %d: bk3_intr: rsv SND_MSG %x",
					inst, bks->msg_rcv.info);
				mutex_exit(&bks->mutex);
			break;
			case BK3_C_RCV_MSG:
				mutex_enter(&bks->mutex);
				if (bk3_debug & BK3_DBG_INTR)
					cmn_err(CE_NOTE, "bk3 %d: intr BK3_C_RCV_MSG", inst);

				cv_broadcast(&bks->cv_msg_out);
				mutex_exit(&bks->mutex);
			break;
			case BK3_C_RASK:{
				bk3_pool_buf_t* pool_buf = &bks->write_pool;
						/* is command =SND_WR */
				mutex_enter(&bks->mutex);
				bks->stat.rask++;
				if (bk3_debug & BK3_DBG_INTR)
				cmn_err(CE_NOTE, "bk3 %d: interrupt: Pear is ready to read;",inst);
		
				if(!list_empty(&pool_buf->ready_list) && 
					IS_ON_STATUS(bks, WRITE_IS_OVER)){
					OFF_STATUS(bks, PEER_READ_IS_OVER | WRITE_IS_OVER);
					pool_buf->work_buf = list_entry(pool_buf->ready_list.next, bk3_buf_t, list);
					list_del1(pool_buf->ready_list.next);					
					bks->stat.w_start = gethrtime();
					SET_BK3_REG(bks, tcwd, pool_buf->work_buf->address);
					SET_BK3_REG(bks, tcnt, TRANSF_CNT);
				}else{
					ON_STATUS(bks, PEER_READ_IS_OVER);
				}
				mutex_exit(&bks->mutex);		
			}
			break;
			case BK3_C_PEER_RESET :
				mutex_enter(&bks->mutex);
				cv_broadcast(&bks->cv_wait_peer_reset);
				mutex_exit(&bks->mutex);
			break;
			}
		}
		bks->stat.cmd_recieved++;
	}
	if (interrupts & BK3_I_CMDFREE) {
		bks->stat.cmd_free++;
		mutex_enter(&bks->mutex);
		if (bk3_debug & BK3_DBG_INTR)
			cmn_err(CE_NOTE, 
				"bk3_intr %d: command buffer free,status = 0x%x"
				,inst,bks->status);

		if (IS_ON_STATUS(bks, CMD_WAIT_FREE)) {
			cv_broadcast(&bks->cv_cmd);
		}
		OFF_STATUS(bks, CMD_IS_ACTIVE | CMD_WAIT_FREE);


		if (bk3_debug & BK3_DBG_INTR)
			cmn_err(CE_NOTE, 
				"bk3_intr %d: end command buffer free,status=0x%x"
				,inst,bks->status);
		mutex_exit(&bks->mutex);
	}

	if (interrupts & BK3_I_RPTCMD) {
		mutex_enter(&bks->mutex);
		if (IS_OFF_STATUS(bks, CMD_IS_ACTIVE)) {
			if (bk3_debug & (BK3_DBG_INTR | BK3_DBG_ERR_RETURNS)) {
				cmn_err(CE_NOTE, "bk3 %d: repeat cmd skipped",
					inst);
			}
		} else {
			if (bk3_debug & (BK3_DBG_INTR | BK3_DBG_ERR_RETURNS)) {
				cmn_err(CE_NOTE, "bk3 %d:repeat cmd ox%x "
					"time %d",
					inst,
					bks->last_cmd,
					bks->last_cmd_rpt_cnt + 1);
			}
			if (bks->last_cmd_rpt_cnt > 10) {
				cmn_err(CE_WARN,
					"bk3 %d: couldn't send cmd %d times",
					inst, bks->last_cmd_rpt_cnt);
			} else {
				bks->last_cmd_rpt_cnt++;
				SET_BK3_REG(bks, wctl, bks->last_cmd);
				bks->stat.cmd_rpt++;
				if (bk3_debug & BK3_DBG_SEND_CMD) {
					cmn_err(CE_NOTE,
						"bk3 %d: cmd 0x%8x repeated",
						inst, bks->last_cmd);
				}
			}
		}
		mutex_exit(&bks->mutex);
	} 
	
	
	if (interrupts & BK3_I_RESET) {
		if (bk3_debug & ( BK3_DBG_INTR | BK3_DBG_RESET) ) {
			cmn_err(CE_NOTE, "bk3 %d: peer's request to reset",
				inst);
		}
		bk3_D0_intr_handle(bks);
//		schedule_work(&bks->D0_intr_tqueue);
	}
}
