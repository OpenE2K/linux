/*
 * Copyright (c) 2005 by MCST.
 *  MOKM.C
 */

//#include <linux/config.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/cdev.h>
#include <linux/audit.h>
#include <linux/poll.h>
#include <linux/namei.h>
#include <linux/pci.h>
#include <linux/mount.h>
#include <linux/security.h>

//-----------------------------------------------------------------------------
#define MOKMWAITLASTTX      // TODO

#define BUG56455            // [Bug 56455] e90: big pci register resources

#define MAX_MOKM        8       // Max number of MOK/M devices.

//-----------------------------------------------------------------------------
#include <linux/mcst/mokm.h>
//#include "mokm.h"

//-----------------------------------------------------------------------------
MODULE_LICENSE	  ("GPL");
MODULE_AUTHOR     ("Denis Fedotov, Andrew Kalita");
MODULE_DESCRIPTION("MCST MOKM driver");

//-----------------------------------------------------------------------------
#define MODULE_NAME     "MOKM"
#define DEV_MODULE_NAME "mokm"

#define MOKM_VENDOR_ID  0x8086
#define MOKM_DEVICE_ID  0x4643

#define REQ_IRG_FLAG IRQF_SHARED
#define MAX_DRV_NM_SZ   64
extern struct dentry *lookup_hash(struct nameidata *nd);

#define DEF_MUTEX_R mutex_r
#ifndef SINGLE_MUTEX
  #define DEF_MUTEX_W mutex_w
#else
  #define DEF_MUTEX_W mutex_r
#endif

//#if defined(__sparc__)
//#if defined(__e2k__)

//-----------------------------------------------------------------------------
static char     mokm_name[] = "MCST,mokm";  // request_irq

unsigned int    major = 0;

unsigned int	mokm_nr_devs;
mokm_dev_t      *mokm_devices[MAX_MOKM];

static struct class *mokm_class;

//=============================================================================
static int set_buffer_in_RCV (mokm_dev_t *mokm);
static int set_buffer_in_XMT (mokm_dev_t *mokm);

//-----------------------------------------------------------------------------
/**
 * Reset self or pear
 * @mokm: device private struct
 * @cmd: reset command (0,MOKM_CR_RESET,MOKM_CR_PEAR_RESET,MOKM_CR_RESET_XMT,MOKM_CR_RESET_RCV)
 *
 * called by mokm_open, mokm_close, mokm_intr_handler(MOKM_ISR_RCV_RESET)
 **/
static void mokm_reset_device (mokm_dev_t *mokm, u32 cmd)
{
    mokm_pool_buf_t* pool_buf;
    unsigned long flags_w, flags_r;
#ifdef MOKMWAITLASTTX
    unsigned long try_num;
#endif // MOKMWAITLASTTX

    if(mokm->debug & MOKM_DBG_RESET) PDEBUG("%d [%lu]: RESET: code = %s (%u)\n", mokm->instance, jiffies,
        (MOKM_CR_RESET==cmd)?"RESET":(
        (MOKM_CR_PEAR_RESET==cmd)?"PEAR":(
        (MOKM_CR_RESET_XMT==cmd)?"XMT":(
        (MOKM_CR_RESET_RCV==cmd)?"RCV":(
        (0==cmd)?"soft":"unknown"
        )))), cmd);

    // wait for last transmit finished
#ifdef MOKMWAITLASTTX
    try_num = 50000;
    while(ioread32(&mokm->regs->TCR.r) & TRC_TX_ACT) {
        try_num--; if (0 == try_num) break;
    }
#endif // MOKMWAITLASTTX

    iowrite32(MOKM_CR_ENDIAN | cmd, &mokm->regs->CR);
    iowrite32(ioread32(&mokm->regs->TRC.r) | MOKM_TRC_ENDIAN, &mokm->regs->TRC.r);

    if(MOKM_CR_PEAR_RESET == cmd) {
        return;
    }

    cmd &= ~MOKM_CR_RESET;

    if((0 == cmd) || (MOKM_CR_RESET_XMT == cmd)) {
        spin_lock_irqsave(&mokm->DEF_MUTEX_W, flags_w);      /// spin_lock write_pool
        mokm->xmit_err = 0;
        // Set WRITE buffs as free
        pool_buf = &mokm->write_pool;
        if(0 == cmd) {
            if(mokm->debug & MOKM_DBG_RESET) PDEBUG("%d [%lu]: RESET: list_empty(xmt_ready_list)\n", mokm->instance, jiffies);
            while (!list_empty(&pool_buf->ready_list)) {
                list_move_tail(pool_buf->ready_list.next, &pool_buf->free_list);
            }
        }
        while (!list_empty(&pool_buf->busy_list)) {
            list_move_tail(pool_buf->busy_list.next, &pool_buf->free_list);
        }
        mokm->in_trm = NULL; // Off WRITE_IS_ACTIVE
        spin_unlock_irqrestore(&mokm->DEF_MUTEX_W, flags_w); /// spin_unlock write_pool
    }

    if((0 == cmd) || (MOKM_CR_RESET_RCV == cmd)) {
        spin_lock_irqsave(&mokm->DEF_MUTEX_R, flags_r);      /// spin_lock read_pool
        mokm->rcv_err = 0;
        // Set READ buffs as free
        pool_buf = &mokm->read_pool;
        if(0 == cmd) {
            if(mokm->debug & MOKM_DBG_RESET) PDEBUG("%d [%lu]: RESET: list_empty(rcv_ready_list)\n", mokm->instance, jiffies);
            while (!list_empty(&pool_buf->ready_list)) {
                list_move_tail(pool_buf->ready_list.next, &pool_buf->free_list);
            }
        }
        while (!list_empty(&pool_buf->busy_list)) {
            list_move_tail(pool_buf->busy_list.next, &pool_buf->free_list);
        }
        mokm->in_rcv = NULL; // Off READ_IS_ACTIVE
        spin_unlock_irqrestore(&mokm->DEF_MUTEX_R, flags_r); /// spin_unlock read_pool
    }
} // mokm_reset_device

//-----------------------------------------------------------------------------
/**
 * Print all hardware registers
 *
 * called by mokm_ioctl[MOKM_IOC_WR_BUF]
 **/
static void dump_all_regs (mokm_dev_t *mokm, char *string)
{
  #ifdef MOKMDEBUG
    int inst = mokm->instance;
  #endif

    PDEBUG("%d: Dump all regs (%s):\n", inst, string);
    PDEBUG("%d \tBase + 0x0000: TDAR 0x%08X\n", inst, ioread32(&mokm->regs->TDAR));
    PDEBUG("%d \tBase + 0x0004: TDCR 0x%08X\n", inst, ioread32(&mokm->regs->TDCR));
    PDEBUG("%d \tBase + 0x0008: TCR  0x%08X\n", inst, ioread32(&mokm->regs->TCR.r));
    PDEBUG("%d \tBase + 0x000c: RDAR 0x%08X\n", inst, ioread32(&mokm->regs->RDAR));
    PDEBUG("%d \tBase + 0x0010: RTR  0x%08X\n", inst, ioread32(&mokm->regs->RTR));
    PDEBUG("%d \tBase + 0x0014: RCR  0x%08X\n", inst, ioread32(&mokm->regs->RCR.r));
    PDEBUG("%d \tBase + 0x0018: ISR  0x%08X\n", inst, 0/*ioread32(&mokm->regs->ISR)*/);
    PDEBUG("%d \tBase + 0x001c: IMR  0x%08X\n", inst, ioread32(&mokm->regs->IMR));
    PDEBUG("%d \tBase + 0x0020: CR   0x%08X\n", inst, ioread32(&mokm->regs->CR));
    PDEBUG("%d \tBase + 0x0024: PMR  0x%08X\n", inst, ioread32(&mokm->regs->PMR));
    PDEBUG("%d \tBase + 0x0028: DR1  0x%08X\n", inst, ioread32(&mokm->regs->DR1));
    PDEBUG("%d \tBase + 0x002c: DR2  0x%08X\n", inst, ioread32(&mokm->regs->DR2));
    PDEBUG("%d \tBase + 0x0030: TRC  0x%08X\n", inst, ioread32(&mokm->regs->TRC.r));
    PDEBUG("%d \tBase + 0x0034: TC   0x%08X\n", inst, ioread32(&mokm->regs->TC.r));
    PDEBUG("%d \tBase + 0x0038: RDCR 0x%08X\n", inst, ioread32(&mokm->regs->RDCR));
    PDEBUG("%d \tBase + 0x003c: TET  0x%08X\n\n", inst, ioread32(&mokm->regs->TET));
} // dump_all_regs

//-----------------------------------------------------------------------------
/**
 * Print statistics
 *
 * called by mokm_close
 **/
static void print_stat (mokm_dev_t *mokm)
{
  #ifdef MOKMDEBUG
    int inst = mokm->instance;
  #endif

        PDEBUG("%d \t--- interrupts ---\n", inst);
    PDEBUG("%d \t%u - Reset request\n", inst, mokm->stat.rsv_reset);
    PDEBUG("%d \t%u - Connection lost\n", inst, mokm->stat.lost_connect);
    PDEBUG("%d \t%u - Pear optic error\n", inst, mokm->stat.pear_optic_error);
    PDEBUG("%d \t%u - Our optic error\n", inst, mokm->stat.optic_error);
        PDEBUG("%d \t--- int cmd ---\n", inst);
    PDEBUG("%d \t%u - Receive CMD buffer full\n", inst, mokm->stat.rx_cmd_buf_full);
    PDEBUG("%d \t%u - ERROR transmit CMD\n", inst, mokm->stat.tx_cmd_error);
    PDEBUG("%d \t%u - Transmit CMD buffer busy\n", inst, mokm->stat.tx_cmd_buf_busy);
    PDEBUG("%d \t%u - We recieved CMD\n", inst, mokm->stat.rx_cmd_int);
        PDEBUG("%d \t--- int rx ---\n", inst);
    PDEBUG("%d \t%u - Reciever Done\n", inst, mokm->stat.rx_buf_ok);
    PDEBUG("%d \t%llu - Received bytes\n", inst, mokm->stat.rx_size_all);
    PDEBUG("%d \t%u - Reciever Done with empty buf ptr\n", inst, mokm->stat.rx_buf_lost);
    PDEBUG("%d \t%u - PCI ERROR on RCV DATA\n", inst, mokm->stat.rx_buf_pci_err);
    PDEBUG("%d \t%u - DATA recieve ERROR\n", inst, mokm->stat.rx_buf_error);
        PDEBUG("%d \t--- int tx ---\n", inst);
    PDEBUG("%d \t%u - Transmitter Done\n", inst, mokm->stat.tx_buf_ok);
    PDEBUG("%d \t%llu - Transmitted bytes\n", inst, mokm->stat.tx_size_all);
    PDEBUG("%d \t%u - Transmiter Done with empty buf ptr\n", inst, mokm->stat.tx_unknown_buf);
    PDEBUG("%d \t%u - PCI ERROR on TRANSMIT DATA\n", inst, mokm->stat.tx_buf_pci_err);
    PDEBUG("%d \t%u - DATA transmit ERROR\n", inst, mokm->stat.tx_buf_error);
    PDEBUG("%d \t%u - Transmiter channel error\n", inst, mokm->stat.tx_channel_error);
        PDEBUG("%d \t--- all ---\n", inst);
    PDEBUG("%d \t%u - Remote request\n", inst, mokm->stat.tx_remote_req);
    PDEBUG("%d \t%u - EXCEPTIONs (last: %u)\n", inst, mokm->stat.exception, mokm->stat.exception_code);
        PDEBUG("%d \t--- last write error ---\n", inst);
    PDEBUG("%d \t%u - Pear still not ready\n", inst, mokm->stat.lwr_pearrd);
    PDEBUG("%d \t%u - copy_from_user failure\n", inst, mokm->stat.lwr_cfu_fail);
    PDEBUG("%d \t%u - can't find requested buf\n", inst, mokm->stat.lwr_nobuf);
    PDEBUG("%d \t%u - Timeout in IOC_WR_BUF\n", inst, mokm->stat.lwr_timeout);
    PDEBUG("%d \t%u - cant xmit buf\n", inst, mokm->stat.lwr_cantxmit);
        PDEBUG("%d \t-----------\n", inst);
} // print_stat


//=============================================================================
// INTERRUPT

//-----------------------------------------------------------------------------
/**
 * Interrupt handler
 *
 **/
static irqreturn_t mokm_intr_handler (int irq, void *arg/*, struct pt_regs *regs*/)
{
    int err_num = 0;
    int cmd_num = 0;
    uint32_t intr;
    mokm_dev_t  *mokm = (mokm_dev_t *) arg;
    unsigned long flags_w, flags_r;
    //mokm_buf_t* p_buff;

    if ( mokm == NULL ) return (IRQ_NONE);

    // Get & Clear interrupt
    intr = ioread32(&mokm->regs->ISR) & MOKM_ISR_ALL;
    if ( intr == 0 ) return (IRQ_NONE);

/*do {*/
    if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR = 0x%08X (%u)\n", mokm->instance, jiffies, intr, intr);

    /// Link
    if ( intr & MOKM_ISR_CONECT ) {
        intr &= ~MOKM_ISR_CONECT;
        if ((ioread32(&mokm->regs->TRC.r) & TRC_B_WR_RDY) == 0) {
            mokm->stat.lost_connect++;
            if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_CONECT - lost (%u)\n", mokm->instance, jiffies, mokm->stat.lost_connect);
        } else {
            if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_CONECT - find\n", mokm->instance, jiffies);
        }
        err_num = 1; // for reinit Rx
    }

    /// One or more common error presented. Handle them
    if ( intr & MOKM_ISR_ANY_ERR ) {
        if ( intr & MOKM_ISR_PEAR_FIBER_ERR ) {
            mokm->stat.pear_optic_error++;
            if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_PEAR_FIBER_ERR (%u)\n", mokm->instance, jiffies, mokm->stat.pear_optic_error);
            err_num = 1; // for reinit Rx
        }
        if ( intr & MOKM_ISR_FIBER_ERR ) {
            mokm->stat.optic_error++;
            if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_FIBER_ERR (%u)\n", mokm->instance, jiffies, mokm->stat.optic_error);
            err_num = 1; // for reinit Rx
        }
        intr &= ~MOKM_ISR_ANY_ERR;
    }

    /// Peer whant us to reset
    if ( intr & MOKM_ISR_RCV_RESET ) {
        intr &= ~MOKM_ISR_RCV_RESET;
        mokm->stat.rsv_reset++;
        if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_RCV_RESET (%u)\n", mokm->instance, jiffies, mokm->stat.rsv_reset);
        mokm_reset_device(mokm, MOKM_CR_RESET_RCV);
        mokm_reset_device(mokm, MOKM_CR_RESET_XMT);
        set_buffer_in_RCV(mokm); // prepare to receive
        return IRQ_HANDLED;
    }

    /// CMD stat
    // Receive CMD buffer full
    if ( intr & MOKM_ISR_CMD_BUF_FULL) {
        intr &= ~MOKM_ISR_CMD_BUF_FULL;
        mokm->stat.rx_cmd_buf_full++;
        if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_CMD_BUF_FULL (%u)\n", mokm->instance, jiffies, mokm->stat.rx_cmd_buf_full);
    }
    // ERROR transmit CMD
    if ( intr & MOKM_ISR_CMD_XMT_ERR ) {
        intr &= ~MOKM_ISR_CMD_XMT_ERR;
        mokm->stat.tx_cmd_error++;
        if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_CMD_XMT_ERR (%u)\n", mokm->instance, jiffies, mokm->stat.tx_cmd_error);
    }
    // Transmit CMD buffer busy
    if ( intr & MOKM_ISR_CMD_BUF_BUSY ) {
        intr &= ~MOKM_ISR_CMD_BUF_BUSY;
        mokm->stat.tx_cmd_buf_busy++;
        if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_CMD_BUF_BUSY (%u)\n", mokm->instance, jiffies, mokm->stat.tx_cmd_buf_busy);
    }
    /// We recieved CMD handle all of them (if multy)
    if ( intr & MOKM_ISR_RCV_CMD ) {
        intr &= ~MOKM_ISR_RCV_CMD;
        cmd_num = MOKM_GET_CMD_NUM(ioread32(&mokm->regs->CR));
        if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_RCV_CMD (%u), cmd_num = %d\n", mokm->instance, jiffies, mokm->stat.rx_cmd_int+1, cmd_num);
        if(cmd_num != 0) {
            mokm->stat.rx_cmd_int++;
            wake_up_interruptible(&mokm->wq_ready_rcmd);
        }
    }

    /// Reciever Interrupts
    if ( intr & MOKM_ISR_ALL_RX ) {
        err_num = 0; // for reinit Rx
        mokm_pool_buf_t* pool_buf = &mokm->read_pool;
        // Receiver Done
        if ( intr & MOKM_ISR_RCV_BUF ) {
            spin_lock_irqsave(&mokm->DEF_MUTEX_R, flags_r);      /// spin_lock read_pool
            if (mokm->in_rcv) {
                mokm->in_rcv->size = ioread32(&mokm->regs->RTR); // get received size
                mokm->stat.rx_size_all += (u64)((mokm->in_rcv->size)<<2); // in bytes
                list_move_tail(&mokm->in_rcv->list, &pool_buf->ready_list);
                mokm->in_rcv = NULL;
                spin_unlock_irqrestore(&mokm->DEF_MUTEX_R, flags_r); /// spin_unlock read_pool
                mokm->rcv_err = 0;
                mokm->stat.rx_buf_ok++;
                if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_RCV_BUF - Ok (%u)\n", mokm->instance, jiffies, mokm->stat.rx_buf_ok);
                wake_up_interruptible(&mokm->wq_ready_rbuf);
            } else {
                spin_unlock_irqrestore(&mokm->DEF_MUTEX_R, flags_r); /// spin_unlock read_pool
                mokm->stat.rx_buf_lost++;
                if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_RCV_BUF - buffer lost (%u)\n", mokm->instance, jiffies, mokm->stat.rx_buf_lost);
            }
        }
        // PCI ERROR on RCV DATA
        if ( intr & MOKM_ISR_PCIBUS_RCV_ERR ) {
            mokm->rcv_err = 1;
            mokm->stat.rx_buf_pci_err++;
            if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_PCIBUS_RCV_ERR (%u)\n", mokm->instance, jiffies, mokm->stat.rx_buf_pci_err);
        }
        // DATA recieve ERROR
        if ( intr & MOKM_ISR_RCV_DATA_ERR ) {
            mokm->rcv_err = 1;
            mokm->stat.rx_buf_error++;
            if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_RCV_DATA_ERR (%u)\n", mokm->instance, jiffies, mokm->stat.rx_buf_error);
        }
        // ERROR recieve pkt num
        if ( intr & MOKM_ISR_RCV_NUM_ERR ) {
            mokm->rcv_err = 1;
            mokm->stat.rx_buf_error++;
            if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_RCV_NUM_ERR (%u)\n", mokm->instance, jiffies, mokm->stat.rx_buf_error);
        }
        intr &= ~MOKM_ISR_ALL_RX;

        // Set buf for Receive
        spin_lock_irqsave(&mokm->DEF_MUTEX_R, flags_r);      /// spin_lock read_pool
        if(mokm->in_rcv) {
            iowrite32((u32)mokm->in_rcv->dma_addr, &mokm->regs->RDAR); // reuse buffer if errors
            spin_unlock_irqrestore(&mokm->DEF_MUTEX_R, flags_r); /// spin_unlock read_pool
            if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_ALL_RX - reuse Rx buffer #%u\n", mokm->instance, jiffies, mokm->in_rcv->num);
        } else {
            spin_unlock_irqrestore(&mokm->DEF_MUTEX_R, flags_r); /// spin_unlock read_pool
            set_buffer_in_RCV(mokm); // prepare to receive
        }
    } // Rx int

    /// Transmiter interrupt
    if ( intr & MOKM_ISR_ALL_TX ) {
        mokm_pool_buf_t *pool_buf = &mokm->write_pool;
        // Transmiter Done
        if ( intr & MOKM_ISR_XMT_BUF ) {
            if(mokm->in_trm) { // WRITE_IS_ACTIVE
                mokm->stat.tx_size_all += (u64)((mokm->in_trm->size)<<2); // in bytes
                spin_lock_irqsave(&mokm->DEF_MUTEX_W, flags_w);      /// spin_lock write_pool
                list_move_tail(&mokm->in_trm->list/*pool_buf->busy_list.next*/, &pool_buf->ready_list);
                mokm->in_trm = NULL; // Off WRITE_IS_ACTIVE
                spin_unlock_irqrestore(&mokm->DEF_MUTEX_W, flags_w); /// spin_unlock write_pool
                mokm->xmit_err = 0;
                mokm->stat.tx_buf_ok++;
                if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_XMT_BUF - Ok (%u)\n", mokm->instance, jiffies, mokm->stat.tx_buf_ok);
            } else {
                mokm->xmit_err = 1;
                mokm->stat.tx_unknown_buf++;
                if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: MOKM_ISR_XMT_BUF - buffer unknown (%u)\n", mokm->instance, jiffies, mokm->stat.tx_unknown_buf);
            }
        }
        // PCI ERROR on TRANSMIT DATA
        if ( intr & MOKM_ISR_PCIBUS_XMT_ERR ) {
            mokm->xmit_err = 1;
            mokm->stat.tx_buf_pci_err++;
            if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_PCIBUS_XMT_ERR (%u)\n", mokm->instance, jiffies, mokm->stat.tx_buf_pci_err);
        }
        // DATA transmit ERROR
        if ( intr & MOKM_ISR_XMT_DATA_ERR ) {
            mokm->xmit_err = 1;
            mokm->stat.tx_buf_error++;
            if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_XMT_DATA_ERR (%u)\n", mokm->instance, jiffies, mokm->stat.tx_buf_error);
        }
        // Transmiter channel error
        if ( intr & MOKM_ISR_XMT_ERR ) {
            mokm->xmit_err = 1;
            mokm->stat.tx_channel_error++;
            if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_XMT_ERR (%u)\n", mokm->instance, jiffies, mokm->stat.tx_channel_error);
            //mokm_reset_device(mokm, MOKM_CR_RESET_XMT);
        }
        intr &= ~MOKM_ISR_ALL_TX;

        if(mokm->in_trm) { // WRITE_IS_ACTIVE
            // if errors - move buffer
            spin_lock_irqsave(&mokm->DEF_MUTEX_W, flags_w);      /// spin_lock write_pool
            list_move_tail(&mokm->in_trm->list, &pool_buf->ready_list);
            mokm->in_trm = NULL; // Off WRITE_IS_ACTIVE
            spin_unlock_irqrestore(&mokm->DEF_MUTEX_W, flags_w); /// spin_unlock write_pool
        }

        if ( !mokm->sync_mode ) {
            // async only
            /* TODO: ??? check if last try passed ??? */
/*#ifdef MOKMWAITLASTTX
            if((ioread32(&mokm->regs->TRC.r) & TRC_B_PEARRD_RDY) && !(ioread32(&mokm->regs->TCR.r) & TRC_TX_ACT)) {
#else*/
            if(ioread32(&mokm->regs->TRC.r) & TRC_B_PEARRD_RDY) {
/*#endif // MOKMWAITLASTTX*/
                set_buffer_in_XMT(mokm); // START Transmit
            }
        } else {
            wake_up_interruptible(&mokm->wq_ready_wbuf);
        }
        intr &= ~MOKM_ISR_PEAR_READY_RCV; // this START Transmit
    } // Tx int

    /// We ready to Transmit / Remote ready to receive
    if ( intr & MOKM_ISR_PEAR_READY_RCV ) {
        intr &= ~MOKM_ISR_PEAR_READY_RCV;
        if(mokm->debug & MOKM_DBG_INTR) nPDEBUG("%d [%lu]: ISR_PEAR_READY_RCV - We ready to Transmit\n", mokm->instance, jiffies);
/*#ifdef MOKMWAITLASTTX
        if((ioread32(&mokm->regs->TRC.r) & TRC_B_PEARRD_RDY) && !(ioread32(&mokm->regs->TCR.r) & TRC_TX_ACT)) {
#else*/
        if(ioread32(&mokm->regs->TRC.r) & TRC_B_PEARRD_RDY) {
/*#endif // MOKMWAITLASTTX*/
            if(mokm->debug & MOKM_DBG_INTR) nPDEBUG("%d [%lu]: ISR_PEAR_READY_RCV - Remote ready to receive\n", mokm->instance, jiffies);
            set_buffer_in_XMT(mokm); // START Transmit
        }
    }

    // Remote Request
    intr &= ~MOKM_ISR_REMOTE_REQ;
    if ( intr & MOKM_ISR_REMOTE_REQ ) {
        mokm->xmit_err = 1;
        mokm->stat.tx_remote_req++;
        if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_REMOTE_REQ (%u)\n", mokm->instance, jiffies, mokm->stat.tx_remote_req);
    }

    // EXCEPTION
    intr &= ~MOKM_ISR_EXCEPTION;
    if ( intr & MOKM_ISR_EXCEPTION ) {
        mokm->rcv_err = 1;
        mokm->stat.exception++;
        mokm->stat.exception_code = ioread32(&mokm->regs->TET);
        if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_EXCEPTION (%u), code: %u\n", mokm->instance, jiffies, mokm->stat.exception, mokm->stat.exception_code);
    }

    // Reinit Rx if any common errors
    if(err_num) {
        // Set buf for Receive
        spin_lock_irqsave(&mokm->DEF_MUTEX_R, flags_r);      /// spin_lock read_pool
        if(mokm->in_rcv) {
            iowrite32((u32)mokm->in_rcv->dma_addr, &mokm->regs->RDAR); // reuse buffer if errors
        }
        spin_unlock_irqrestore(&mokm->DEF_MUTEX_R, flags_r); /// spin_unlock read_pool
    }

/*} while((intr = mokm->regs->ISR & MOKM_ISR_ALL) != 0);*/
    if (intr != 0) if(mokm->debug & MOKM_DBG_INTR) PDEBUG("%d [%lu]: ISR_* unknown interrupts = %08X\n", mokm->instance, jiffies, intr);

    return IRQ_HANDLED;
} // mokm_intr_handler


//=============================================================================
// MEMORY

//-----------------------------------------------------------------------------
/**
 * Alloc memory for pool
 * @mokm: device private struct
 * @size: pool size for alloc
 * @phys_mem: return hardware DMA base address
 * @real_size: return allocated size
 * @virt_memory: return user access base address
 * @dir: PCI_DMA_FROMDEVICE or PCI_DMA_TODEVICE
 *
 * Returns 0 on success, -1 on failure
 *
 * called by init_pool_buff
 **/
static int mokm_mem_alloc (mokm_dev_t *mokm, size_t size, dma_addr_t *phys_mem, size_t *real_size, unsigned long *virt_memory, int dir)
{
    int     order;
    struct page *map, *mapend;

    // *buf = (caddr_t) pci_alloc_consistent(mokm->pdev , pool_size, &dev_memory);

    order = get_order(size);
    *virt_memory = __get_free_pages(GFP_ATOMIC/*GFP_KERNEL*/ | GFP_DMA, order);
    if (!(*virt_memory)) {
        ERROR_MSG("%d: mem_alloc ERROR - Cannot bind DMA address order: %d size: 0x%lx\n", mokm->instance, order, (unsigned long)size);
        return -1;
    }

    mapend = virt_to_page((*virt_memory) + (PAGE_SIZE << order) - 1);
    for(map = virt_to_page((*virt_memory)); map <= mapend; map++) SetPageReserved(map);

    *phys_mem = pci_map_single((struct pci_dev *)mokm->pdev, (void *)*virt_memory, size, dir);
    *real_size = PAGE_SIZE << order; 

    if(mokm->debug & MOKM_DBG_MEM) PDEBUG("%d: mem_alloc FINISH - va: 0x%lx fa: 0x%x size: 0x%lx real_size: 0x%lx\n", mokm->instance, *virt_memory, *phys_mem, size, *real_size);

    return 0;
} // mokm_mem_alloc

//-----------------------------------------------------------------------------
/**
 * Free memory pool
 * @mokm: device private struct
 * @size: pool size
 * @phys_mem: hardware DMA base address
 * @virt_memory: user access base address
 * @dir: PCI_DMA_FROMDEVICE or PCI_DMA_TODEVICE
 *
 * called by free_bufs
 **/
static void mokm_mem_free (mokm_dev_t *mokm, size_t size, dma_addr_t phys_mem, caddr_t virt_memory, int dir)
{
    int     order;
    caddr_t     mem;
    struct page *map, *mapend;

    mem = (caddr_t)virt_memory;
    order = get_order(size);

    mapend = virt_to_page(mem + (PAGE_SIZE << order) - 1);
    for (map = virt_to_page(mem); map <= mapend; map++) {
        ClearPageReserved(map);
    }
    pci_unmap_single((struct pci_dev *)mokm->pdev, phys_mem, size, dir);
    free_pages((unsigned long)virt_memory, order);
} // mokm_mem_free


//=============================================================================
// BUFFERS

//-----------------------------------------------------------------------------
/**
 * Search buffer in list
 * @list1: buffer list
 * @num1: buffer number
 *
 * Returns mokm_buf_t* on success, NULL on failure
 *
 * called by mokm_ioctl
 * need spin_lock (read or write)
 **/
static mokm_buf_t* search_in_list (struct list_head* list1, int num1)
{
    struct list_head* tmp;
    mokm_buf_t* ret = NULL;

    list_for_each(tmp, list1) {
        ret = list_entry(tmp, mokm_buf_t, list);
        if(ret->num == num1) return (ret);
    }
    return (NULL);
} // search_in_list

//-----------------------------------------------------------------------------
/**
 * Init Receive or Transmit Buffers Pool
 * @mokm: device private struct
 * @pool_buf: &mokm->read_pool or &mokm->write_pool
 * @buf: &mokm->rbuff or &mokm->wbuff
 * @dir: PCI_DMA_FROMDEVICE or PCI_DMA_TODEVICE
 *
 * Returns 0 on success, negative on failure
 *
 * called by mokm_init
 **/
static int init_pool_buff (mokm_dev_t *mokm, mokm_pool_buf_t* pool_buf, caddr_t *buf, int dir)
{
    int         i;
    size_t      real_sz;
    size_t      pool_size = (MOKM_BUF_SIZE * MOKM_BUF_NUM);
    dma_addr_t  dev_memory = 0;

    INIT_LIST_HEAD(&pool_buf->ready_list);
    INIT_LIST_HEAD(&pool_buf->free_list);
    INIT_LIST_HEAD(&pool_buf->busy_list);

    // Alloc memory for pool (get user access address and DMA address)
    if (mokm_mem_alloc(mokm, pool_size, &dev_memory, &real_sz, (unsigned long *)buf, dir)) {
        ERROR_MSG("%d: ERROR: Cannot alloc device buffer\n", mokm->instance);
        return (-ENOMEM);
    }

    // Init all buffers in pool
    for(i = 0; i < MOKM_BUF_NUM; i++) {
        pool_buf->buf[i].num = i;
        pool_buf->buf[i].st = MOKM_BUF_ST_FREE;
        pool_buf->buf[i].size = 0;
        pool_buf->buf[i].buf_addr = (caddr_t)(*buf + MOKM_BUF_SIZE*i);
        pool_buf->buf[i].dma_addr = (dma_addr_t/*caddr_t*/)(dev_memory + MOKM_BUF_SIZE*i);
        /*DEBUG?*/memset((void *)pool_buf->buf[i].buf_addr, 0xac, MOKM_BUF_SIZE);
        list_add_tail(&pool_buf->buf[i].list, &pool_buf->free_list);
    }

    return 0;
} // init_pool_buff

//-----------------------------------------------------------------------------
/**
 * Print buffers info
 *
 * called by mokm_init
 **/
static void show_buff (mokm_dev_t *mokm)
{
    int i;

    mokm_pool_buf_t* pool_buf = &mokm->read_pool;
    PDEBUG("%d: RCV BUFFERS:\n", mokm->instance);
    for (i = 0; i < MOKM_BUF_NUM; i++) {
        PDEBUG("%d: NUM %05u ADDR %p DMA %llu STATE 0x%05x\n",mokm->instance, pool_buf->buf[i].num,
            pool_buf->buf[i].buf_addr, (u64)pool_buf->buf[i].dma_addr, pool_buf->buf[i].st);
    }

    pool_buf = &mokm->write_pool;
    PDEBUG("%d: WRITE BUFFERS:\n", mokm->instance);
    for (i = 0; i < MOKM_BUF_NUM; i++) {
        PDEBUG("%d: NUM %05u ADDR %p DMA %llu STATE 0x%05x\n",mokm->instance, pool_buf->buf[i].num,
            pool_buf->buf[i].buf_addr, (u64)pool_buf->buf[i].dma_addr, pool_buf->buf[i].st);
    }
} // show_buff

//-----------------------------------------------------------------------------
/**
 * Select buffer for next receive
 * @mokm: device private struct
 *
 * Returns 0 on success, negative on failure (TODO: void)
 *
 * called by mokm_intr_handler, mokm_open, mokm_ioctl(MOKM_IOC_PUT_RD_BUF)
 **/
static int set_buffer_in_RCV (mokm_dev_t *mokm)
{
    mokm_pool_buf_t* pool_buf = &mokm->read_pool;
    mokm_buf_t *buff;
    unsigned long flags_r;

    spin_lock_irqsave(&mokm->DEF_MUTEX_R, flags_r);      /// spin_lock read_pool

    if ( list_empty(&pool_buf->free_list) ) {
        //iowrite32((u_int)0, &mokm->regs->RDAR);
        spin_unlock_irqrestore(&mokm->DEF_MUTEX_R, flags_r); /// spin_unlock read_pool
        if(mokm->debug & MOKM_DBG_RX) PDEBUG("%d [%lu]: < set_buffer_in_RCV - NO free buffer for RCV\n", mokm->instance, jiffies);
        return (-EBUSY);
    }

    buff = list_entry(pool_buf->free_list.next, mokm_buf_t, list);
    if(buff) {
        list_move_tail(pool_buf->free_list.next, &pool_buf->busy_list);
        buff->size = 0;
        mokm->in_rcv = buff;
        iowrite32((u_int)buff->dma_addr, &mokm->regs->RDAR);
    }

    spin_unlock_irqrestore(&mokm->DEF_MUTEX_R, flags_r); /// spin_unlock read_pool

    if(mokm->debug & MOKM_DBG_RX) {
        if(buff) PDEBUG("%d [%lu]: < set_buffer_in_RCV - DONE\n",mokm->instance, jiffies);
        else  PDEBUG("%d [%lu]: < set_buffer_in_RCV - ERROR\n",mokm->instance, jiffies);
    }

    return 0;
} // set_buffer_in_RCV

/**
 * Transmit buffer
 * @mokm: device private struct
 *
 * Returns 0 on success, negative on failure (TODO: void)
 *
 * called by mokm_intr_handler & ioctl
 **/
static int set_buffer_in_XMT (mokm_dev_t *mokm)
{
    mokm_pool_buf_t* pool_buf = &mokm->write_pool;
    mokm_buf_t *buff;
    unsigned long flags_w;

    if (mokm->in_trm) { // WRITE_IS_ACTIVE
        if(mokm->debug & MOKM_DBG_TX) PDEBUG("%d [%lu]: > set_buffer_in_XMT - There is allready some buffer #%u in xmt\n", mokm->instance, jiffies, (unsigned int)mokm->in_trm->num);
        return (-EAGAIN);
    }
    if ( list_empty(&pool_buf->busy_list) ) {
        if(mokm->debug & MOKM_DBG_TX) nPDEBUG("%d [%lu]: > set_buffer_in_XMT - NO buffer for XMT\n", mokm->instance, jiffies);
        return (-EBUSY);
    }

    spin_lock_irqsave(&mokm->DEF_MUTEX_W, flags_w);      /// spin_lock write_pool
    buff = list_entry(pool_buf->busy_list.next, mokm_buf_t, list);
    if(buff) {
        mokm->in_trm = buff; // On WRITE_IS_ACTIVE
        iowrite32((u_int)buff->dma_addr, &mokm->regs->TDAR);
        iowrite32(buff->size, &mokm->regs->TDCR);
    }
    spin_unlock_irqrestore(&mokm->DEF_MUTEX_W, flags_w); /// spin_unlock write_pool

    if(buff) {
        if(mokm->debug & MOKM_DBG_TX) PDEBUG("%d [%lu]: > set_buffer_in_XMT - DONE: WR id #%u addr %p DMA %llu\n", mokm->instance, jiffies, buff->num, buff->buf_addr, (u64)buff->dma_addr);
    } else {
        if(mokm->debug & MOKM_DBG_TX) PDEBUG("%d [%lu]: > set_buffer_in_XMT - ERROR: NO buffer for XMT\n", mokm->instance, jiffies);
    }
    return 0;
} // set_buffer_in_XMT

//-----------------------------------------------------------------------------
/**
 * Free read and write pools
 * @mokm: device private struct
 *
 * called by mokm_detach
 **/
static void free_bufs (mokm_dev_t *mokm)
{
    size_t pool_size = (MOKM_BUF_SIZE*MOKM_BUF_NUM);
    mokm_pool_buf_t* pool_buf;

    // FREE BUFFERS HERE
    pool_buf = &mokm->read_pool;
    if(mokm->debug & MOKM_DBG_MEM) PDEBUG("%d: do free read bufs Addr %p DMA %llu\n", mokm->instance, mokm->rbuff, (u64)pool_buf->buf[0].dma_addr);
    if ( pool_buf->buf[0].dma_addr ) {
        mokm_mem_free(mokm, pool_size, (dma_addr_t)pool_buf->buf[0].dma_addr, mokm->rbuff, PCI_DMA_FROMDEVICE);
        //pci_free_consistent(mokm->pdev, pool_size, mokm->rbuff, (dma_addr_t)(pool_buf->buf[0].dma_addr));
    }

    pool_buf = &mokm->write_pool;
    if(mokm->debug & MOKM_DBG_MEM) PDEBUG("%d: do free write bufs Addr %p DMA %llu\n", mokm->instance, mokm->wbuff, (u64)pool_buf->buf[0].dma_addr);
    if ( pool_buf->buf[0].dma_addr ) {
        mokm_mem_free(mokm, pool_size, (dma_addr_t)pool_buf->buf[0].dma_addr, mokm->wbuff, PCI_DMA_TODEVICE);
        //pci_free_consistent(mokm->pdev, pool_size, mokm->wbuff, (dma_addr_t)(pool_buf->buf[0].dma_addr));
    }
} // free_bufs


//=============================================================================
// FOPS

//-----------------------------------------------------------------------------
/**
 * Module open file operation
 *
 **/
static int mokm_open (struct inode *inode, struct file *filp)
{
    mokm_dev_t *mokm;
    int minor = MINOR(inode->i_rdev);

    mokm = (mokm_dev_t *)filp->private_data;

    if (!mokm) {
        if ( minor >= mokm_nr_devs ) {
            return -ENODEV;
        }
        mokm = mokm_devices[minor];
        filp->private_data = mokm;
    }

    PDEBUG("%d: open minor %d\n", mokm->instance, minor);

    spin_lock(&mokm->DEF_MUTEX_R);    /// spin_lock read_pool

    if (mokm->open == 1) {
        spin_unlock(&mokm->DEF_MUTEX_R);  /// spin_unlock read_pool
        WARNING_MSG("%d: WARING:\t MOKM allready open and busy! Try again later\n", mokm->instance);
        return -EBUSY;
    }
    mokm->open = 1;
    spin_unlock(&mokm->DEF_MUTEX_R);  /// spin_unlock read_pool

    // No Reset and One buf send to reciever (Do it after interrupt handler is avalible)
    mokm_reset_device(mokm, MOKM_CR_RESET_RCV);
    mokm_reset_device(mokm, MOKM_CR_RESET_XMT);
    set_buffer_in_RCV(mokm); // prepare to receive

    // Enable all interrupts here
    mokm->intr_mask = MOKM_IMR_ALL_ENABLE;
    iowrite32(MOKM_IMR_ALL_ENABLE, &mokm->regs->IMR);

    return (0);
} // mokm_open

//-----------------------------------------------------------------------------
/**
 * Module close file operation
 *
 **/
static int mokm_close (struct inode *inode, struct file *filp)
{
    mokm_dev_t *mokm;
    int minor = MINOR(inode->i_rdev);
    unsigned long flags_r;
    unsigned long volatile dummy;

    if ( minor >= mokm_nr_devs ) return -ENODEV;
    mokm = mokm_devices[minor];

    print_stat(mokm);
    dump_all_regs(mokm, "close");

    // disable interrupts here
    mokm->intr_mask = 0;
    iowrite32(0, &mokm->regs->IMR);
    dummy = ioread32(&mokm->regs->ISR);

    mokm_reset_device(mokm, MOKM_CR_RESET);

    spin_lock_irqsave(&mokm->DEF_MUTEX_R, flags_r);      /// spin_lock read_pool
    mokm->open = 0;
    spin_unlock_irqrestore(&mokm->DEF_MUTEX_R, flags_r); /// spin_unlock read_pool

    filp->private_data = NULL;

    return(0);
} // mokm_close

//-----------------------------------------------------------------------------
/**
 * Module ioctl file operation
 *
 **/
static long mokm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    mokm_dev_t *mokm;
    int ret = 0;
    int r;
    long timeout;
    int inst;
    unsigned long flags_w, flags_r;


    mokm = (mokm_dev_t*)filp->private_data;
    inst = mokm->instance;

    //IN_TR(inst, mokm_ioctl, 1, cmd, arg); // start
    switch (cmd) {
    PDEBUG("%d: ioctl cmd = %X\n", mokm->instance, cmd);

    /** RESET */
    case MOKM_IOC_RESET :
    {
        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: IOC_RESET\n", inst, jiffies);
        iowrite32(MOKM_CR_ENDIAN | MOKM_CR_PEAR_RESET, &mokm->regs->CR);
        iowrite32(ioread32(&mokm->regs->TRC.r) | MOKM_TRC_ENDIAN, &mokm->regs->TRC.r);
        ret = 0; break; // return
    }

    /** int mokm_get_write_buf(int fd, int *pool, int **write_array) */
    case MOKM_IOC_GET_WR_BUF:
    {
        mokm_pool_buf_t *pool_buf = &mokm->write_pool;
        mokm_buf_t* p_buff;

        // Search for free for write buffer
        if (list_empty(&pool_buf->free_list)) {
            ERROR_MSG("%d: IOC_GET_WR_BUF Error: No Free Bufs\n", inst);
            ret = -EAGAIN; break; // return
        }

        spin_lock_irqsave(&mokm->DEF_MUTEX_W, flags_w);      /// spin_lock write_pool
        p_buff = list_entry(pool_buf->free_list.next, mokm_buf_t, list);
        list_move_tail(&p_buff->list, &pool_buf->ready_list);
        spin_unlock_irqrestore(&mokm->DEF_MUTEX_W, flags_w); /// spin_unlock write_pool

        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: > IOC_GET_WR_BUF - DONE\n", inst, jiffies);
        ret = p_buff->num; break; // return
    } // MOKM_IOC_GET_WR_BUF

    /** int mokm_write(int fd, int buf_num, int size) */
    case MOKM_IOC_WR_BUF :  // User want write buffer #{n_buf = arg}
    {
        mokm_pool_buf_t *pool_buf = &mokm->write_pool;
        mokm_buf_t*     p_buff;
        mokm_bufwr_t    buf_s;

        // Pear or transmiter still not ready
#ifdef MOKMWAITLASTTX
        if (!((ioread32(&mokm->regs->TRC.r) & TRC_B_PEARRD_RDY) && !(ioread32(&mokm->regs->TCR.r) & TRC_TX_ACT))) {
#else
        if (!(ioread32(&mokm->regs->TRC.r) & TRC_B_PEARRD_RDY)) {
#endif // MOKMWAITLASTTX
            /*if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: > IOC_WR_BUF Break - Pear still not ready\n", inst, jiffies);*/
            mokm->stat.lwr_pearrd++;
            ret = -EAGAIN; break; // return
        }

        if (copy_from_user((caddr_t)&buf_s, (caddr_t)arg, sizeof(mokm_bufwr_t))) {
            mokm->stat.lwr_cfu_fail++;
            ERROR_MSG("%d: IOC_WR_BUF Error: copy_from_user failure\n", inst);
            ret = -EBUSY; break; // return
        }

        // Find user buffer
        spin_lock_irqsave(&mokm->DEF_MUTEX_W, flags_w);      /// spin_lock write_pool
        p_buff = search_in_list(&pool_buf->ready_list, buf_s.buf_num);
        if (p_buff == NULL) {
            spin_unlock_irqrestore(&mokm->DEF_MUTEX_W, flags_w); /// spin_unlock write_pool
            mokm->stat.lwr_nobuf++;
            ERROR_MSG("%d: IOC_WR_BUF Error: cant find buf %d\n", inst, buf_s.buf_num);
            ret = -EAGAIN; break; // return
        }
        p_buff->size = (buf_s.size > MOKM_BUF_SIZE)?MOKM_BUF_SIZE:buf_s.size;
        // Mark this buff as busy and place in in the end of queue
        list_move_tail(&p_buff->list, &pool_buf->busy_list);
        spin_unlock_irqrestore(&mokm->DEF_MUTEX_W, flags_w); /// spin_unlock write_pool

        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: > IOC_WR_BUF - User want to write %d words\n", inst, jiffies, buf_s.size);

        // Start transmit
        set_buffer_in_XMT(mokm);

        if ( mokm->sync_mode ) {
            timeout = 2*HZ; // 2 sec
            r = wait_event_interruptible_timeout(mokm->wq_ready_wbuf, (NULL == mokm->in_trm), timeout); // while(WRITE_IS_ACTIVE)
            if (!r) {
                // timeout time was reached
                mokm->stat.lwr_timeout++;
                ERROR_MSG("%d: IOC_WR_BUF - timeout was reached\n", inst);
//                mokm_reset_device(mokm, MOKM_CR_RESET_XMT); /// RESET TX
                ret = -ETIMEDOUT; break; // return
            } else {
                if(mokm->xmit_err) {
                    mokm->stat.lwr_cantxmit++;
                    ERROR_MSG("%d: IOC_WR_BUF Error: cant xmit buf %d\n", inst, buf_s.buf_num);
                    ret = -EFAULT; break; // return
                } else {
                    ret = p_buff->size; break; // return
                }
            }
        } else {
            ret = 0; break; // return
        }
    } // MOKM_IOC_WR_BUF

    /** int put_write_buf(int fd, int buf_num) */
    case MOKM_IOC_PUT_WR_BUF:
    {
        mokm_pool_buf_t *pool_buf = &mokm->write_pool;
        mokm_buf_t* p_buff;
        int buf_num = (int)arg;

        // Search for write buffer to free
        p_buff = search_in_list(&pool_buf->ready_list, buf_num);
        if (p_buff == NULL) {
            if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: > IOC_PUT_WR_BUF - Wait while current XMIT done\n", inst, jiffies);
            timeout = 2*HZ;
            r = wait_event_interruptible_timeout(mokm->wq_ready_wbuf, (p_buff = search_in_list(&pool_buf->ready_list, buf_num)) != NULL, timeout);
            if (p_buff == NULL) {
                ERROR_MSG("%d: IOC_PUT_WR_BUF Error: cant find buf %d\n", inst, buf_num);
                ret = -EAGAIN; break; // return
            }
        }

        spin_lock_irqsave(&mokm->DEF_MUTEX_W, flags_w);      /// spin_lock write_pool
        list_move_tail(&p_buff->list, &pool_buf->free_list);
        spin_unlock_irqrestore(&mokm->DEF_MUTEX_W, flags_w); /// spin_unlock write_pool

        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: > IOC_PUT_WR_BUF - DONE\n", inst, jiffies);
        ret = 0; break; // return
    } // MOKM_IOC_PUT_WR_BUF


    /** mokm_read (int fd, int* pool, int** read_array, int* buf_num) */
    case MOKM_IOC_RD_BUF :  // User want to read received buffer if any
    {
        mokm_pool_buf_t* pool_buf = &mokm->read_pool;
        mokm_buf_t* p_buff;

        // if nothing to read...
        if (list_empty(&pool_buf->ready_list)) {
            /*if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: < IOC_RD_BUF Break - nothing to read\n", inst, jiffies);*/
            ret = -EAGAIN; break; // return
        }

        spin_lock_irqsave(&mokm->DEF_MUTEX_R, flags_r);      /// spin_lock read_pool
        p_buff = list_entry(pool_buf->ready_list.next, mokm_buf_t, list);
        spin_unlock_irqrestore(&mokm->DEF_MUTEX_R, flags_r); /// spin_unlock read_pool

        if (p_buff == NULL) {
            ERROR_MSG("%d: IOC_RD_BUF Error: BUFF == NULL!\n", inst);
            ret = -EFAULT; break; // return
        }

        if ( p_buff->num < 0 || p_buff->num > MOKM_BUF_NUM ) {
            ERROR_MSG("%d: IOC_RD_BUF Error: Rcv wrong buff_num = %u\n", inst, p_buff->num);
            ret = -EFAULT; break; // return
        }

        if (copy_to_user((caddr_t)arg, (caddr_t)&(p_buff->num), sizeof(u_long))) {
            ERROR_MSG("%d: IOC_RD_BUF Error: copy_to_user failure\n", inst);
            ret = -EINVAL; break; // return
        }

        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: < IOC_RD_BUF - DONE: read #%u buf, sz = %u, addr %p DMA %llu (Real 0x%x)\n", inst, jiffies, p_buff->num, p_buff->size, p_buff->buf_addr, (u64)p_buff->dma_addr, ioread32(&mokm->regs->RDAR));
        ret = p_buff->size; break; // return
    } // MOKM_IOC_RD_BUF

    /** mokm_put_read_buf (int fd, int buf_num) */
    case MOKM_IOC_PUT_RD_BUF:
    {
        mokm_pool_buf_t *pool_buf = &mokm->read_pool;
        mokm_buf_t* p_buff;
        int buf_num = (int)arg;
        int sf;

        spin_lock_irqsave(&mokm->DEF_MUTEX_R, flags_r);      /// spin_lock read_pool
        // Search for read buffer to free
        p_buff = search_in_list(&pool_buf->ready_list/*busy_list*/, buf_num);
        if (p_buff == NULL) {
            spin_unlock_irqrestore(&mokm->DEF_MUTEX_R, flags_r); /// spin_unlock read_pool
            if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: < IOC_PUT_RD_BUF Error: cant find buf %d\n", inst, jiffies, buf_num);
            ret = -EAGAIN; break; // return
        }

        sf = list_empty(&pool_buf->free_list);
        list_move_tail(&p_buff->list, &pool_buf->free_list);

        // if returns last free buff
        if(mokm->in_rcv == NULL /*&& (sf)*/) {
            spin_unlock_irqrestore(&mokm->DEF_MUTEX_R, flags_r); /// spin_unlock read_pool
            set_buffer_in_RCV(mokm); // prepare to receive
        } else {
            spin_unlock_irqrestore(&mokm->DEF_MUTEX_R, flags_r); /// spin_unlock read_pool
        }

        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: < IOC_PUT_RD_BUF - DONE\n", inst, jiffies);
        ret = 0; break; // return
    } // MOKM_IOC_PUT_RD_BUF


    /** mokm_write_cmd (int fd, int* cmd) */
    case MOKM_IOC_SND_MSG :
    {
        //int i = 0;
        u_int32_t cmd = (u_int32_t)arg;

        // transmiter still not ready
        if ((ioread32(&mokm->regs->TRC.r) & TRC_B_WR_RDY) == 0) {
            if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: IOC_SND_MSG - Tranmiter NOT ready\n", inst, jiffies);
            ret = -EBUSY; break; // return
        }

        // SEND
        iowrite32(cmd, &mokm->regs->PMR);

        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: IOC_SND_MSG - Send CMD 0x%x\n", inst, jiffies, cmd);
        ret = 0; break; // return
    } // MOKM_IOC_SND_MSG

    /** mokm_read_cmd (int fd, int* cmd) */
    case MOKM_IOC_RCV_MSG :
    {
        int timeout, cmd;

        timeout = 2*HZ; // 1 sec
        /*while (0 == MOKM_GET_CMD_NUM(mokm->regs->CR)) {*/
            r = wait_event_interruptible_timeout(mokm->wq_ready_rcmd, (MOKM_GET_CMD_NUM(ioread32(&mokm->regs->CR)) != 0), timeout);
            if (r == 0) {
                // timeout time was reached
                if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: IOC_RCV_MSG - timeout time was reached\n", inst, jiffies);
                ret = -ETIMEDOUT;
            } else if (r < 0) { // Interrupted/Error
                ERROR_MSG("%d: IOC_RCV_MSG: Interrupted\n", inst);
                ret = -EINTR;
            }
        /*}*/
        if( ret < 0 ) break; // return

        // Get MSG
        cmd = ioread32(&mokm->regs->PMR);

        if (copy_to_user((caddr_t)arg, (caddr_t)&cmd, sizeof(u_int32_t))) {
            ERROR_MSG("%d: IOC_RCV_MSG copy_to_user failure\n", inst);
            ret = -EINVAL; break; // return
        }

        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: IOC_RCV_MSG - Receive CMD 0x%x\n", inst, jiffies, cmd);
        ret = 0; break; // return
    } // MOKM_IOC_RCV_MSG


    /** mokm_get_stat (int fd) */
    case MOKM_IOC_GET_STAT :
    {
        struct list_head *h;
        mokm->stat.n_free_w_buf=0;
        mokm->stat.n_free_r_buf=0;

        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: IOC_GET_STAT\n", inst, jiffies);

        list_for_each(h, &mokm->write_pool.free_list)
            mokm->stat.n_free_w_buf++;
        list_for_each(h, &mokm->read_pool.free_list)
            mokm->stat.n_free_r_buf++;

        if (copy_to_user((caddr_t)arg, (caddr_t)&mokm->stat, sizeof(mokm_stat_t))) {
            ERROR_MSG("%d: IOC_GET_STAT copy_to_user failure\n", inst);
            ret = -EINVAL; break; // return
        }
        ret = 0; break; // return
    } // MOKM_IOC_GET_STAT

    /** mokm_clear_stat (int fd) */
    case MOKM_IOC_CLEAR_STAT :
    {
        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: IOC_CLEAR_STAT\n", inst, jiffies);
        bzero((caddr_t)&mokm->stat, sizeof(mokm_stat_t));
        ret = 0; break; // return
    } // MOKM_IOC_CLEAR_STAT


    /** */
    case MOKM_IOC_DBG_POINT :
    {
        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: IOC_DBG_POINT\n", inst, jiffies);
        print_stat(mokm);
        dump_all_regs(mokm, "dbg point");
        break;
    } // MOKM_IOC_DBG_POINT

    /** */
    case MOKM_IOC_GET_MAXXFER :
    {
        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: IOC_GET_MAXXFER\n", inst, jiffies);
        ret = MOKM_BUF_SIZE;
        break; // return
    } // MOKM_IOC_GET_MAXXFER

    /** */
    case MOKM_IOC_SET_DBG :
    {
        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: IOC_SET_DBG\n", inst, jiffies);
        mokm->debug = (int)arg;
        ret = 0; break; // return
    }

    /** */
    case MOKM_IOC_GET_RD_WAIT :
    {
        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: IOC_GET_RD_WAIT\n", inst, jiffies);
        ret = (int)mokm->rd_wait_usecs;
        break; // return
    }

    case MOKM_IOC_GET_WR_WAIT :
    {
        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: IOC_GET_WR_WAIT\n", inst, jiffies);
        ret = (int)mokm->wr_wait_usecs;
        break; // return
    }

    case MOKM_IOC_SET_RD_WAIT :
    {
        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: IOC_SET_RD_WAIT\n", inst, jiffies);
        mokm->rd_wait_usecs = (long)arg;
        ret = 0; break; // return
    }

    case MOKM_IOC_SET_WR_WAIT :
    {
        if(mokm->debug & MOKM_DBG_IOCTL) PDEBUG("%d [%lu]: IOC_SET_WR_WAIT\n", inst, jiffies);
        mokm->wr_wait_usecs = (long)arg;
        ret = 0; break; // return
    }

    default :
        ERROR_MSG("%d: unknown ioctl cmd = 0x%x\n", inst, cmd);
        ret = -EFAULT; break; // return

    } // switch (cmd)

    return (ret);
} // mokm_ioctl

#ifdef CONFIG_COMPAT

static int do_ioctl(struct file *f, unsigned cmd, unsigned long arg)
{
    int ret;
//    lock_kernel();
    ret = mokm_ioctl(f, cmd, arg);
//    unlock_kernel();
    return ret;
}

static long mokm_compat_ioctl(struct file *f, unsigned cmd, unsigned long arg)
{
    /*switch (cmd) {
    case ???:
    case ???:*/
        return do_ioctl(f, cmd, arg);
    /*default:
        return -ENOIOCTLCMD;
    }*/
}

#endif // CONFIG_COMPAT

//-----------------------------------------------------------------------------
/**
 * Module mmap file operation
 *
 **/
static int mokm_mmap (struct file *filp, struct vm_area_struct *vma)
{
    mokm_dev_t *mokm;
    unsigned long mem_start;
    unsigned long offset = (vma->vm_pgoff << PAGE_SHIFT);
    unsigned long vm_start;

    if ((mokm = (mokm_dev_t *)filp->private_data) == NULL) {
        return -ENXIO;
    }

    if(mokm->debug & MOKM_DBG_MEM) PDEBUG("%d: mmap: start\n", mokm->instance);

    if ( offset >= 0 && offset < POOLBUFS ) {
        if(mokm->debug & MOKM_DBG_MEM) PDEBUG("%d: mmap: RD BUFS %p\n", mokm->instance, mokm->rbuff);
        mem_start = virt_to_phys(mokm->rbuff);
    } else if ( offset >= POOLBUFS && (offset < (POOLBUFS + POOLBUFS)) ) {
        offset -= POOLBUFS;
        if(mokm->debug & MOKM_DBG_MEM) PDEBUG("%d: mmap: WR BUFS %p\n", mokm->instance, mokm->wbuff);
        mem_start = virt_to_phys(mokm->wbuff);
    } else {
        return -EINVAL;
    }

    mem_start += offset;

    if ( vma->vm_start + offset > vma->vm_end ) {
        ERROR_MSG("%d: MMAP ERROR: Error offset more than size\n ", mokm->instance);
        return -ENXIO;
    }

    if (vma->vm_end - vma->vm_start > POOLBUFS) {
        ERROR_MSG("%d: MMAP ERROR: vma->vm_end - vma->vm_start > POOLBUFS\n", mokm->instance);
        return -EINVAL;
    }

    vm_start = vma->vm_start;

    vma->vm_flags |= (VM_READ | VM_WRITE | VM_DONTEXPAND | VM_DONTDUMP);

#if 0 /* niki */
    LOG_MSG("%d: mmap:\tmem: %#x; off: %#x; off_r: %#x; st: %#x; en: %#x "
           "\tmof: %#x; sof: %#x; st_en: %#x; sz: %#x; \n", mokm->instance,
           (u_int)mem_start,
           (u_int)vma->vm_pgoff,
           (u_int)offset,
           (u_int)vma->vm_start,
           (u_int)vma->vm_end,
           (u_int)(mem_start + offset),
           (u_int)(vma->vm_start + offset),
           (u_int)(vma->vm_end - vma->vm_start),
           (u_int)POOLBUFS);
#endif

    if (remap_pfn_range(vma, vm_start, (mem_start >> PAGE_SHIFT), vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
        ERROR_MSG("%d: MMAP ERROR: Error remap memory to user\n ", mokm->instance);
        return -EAGAIN;
    }

    return 0;
} // mokm_mmap

//-----------------------------------------------------------------------------
static struct file_operations mokm_fops = {
    .owner =   THIS_MODULE,
    .open =    mokm_open,
    .release = mokm_close,
    .unlocked_ioctl = mokm_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = mokm_compat_ioctl,
#endif // CONFIG_COMPAT
    .mmap =    mokm_mmap,
};

//-----------------------------------------------------------------------------
/**
 * Uninstall module
 *
 * called by mokm_init, mokm_exit
 **/
static void mokm_detach ( mokm_dev_t *mokm )
{
    switch (mokm->attach_level) {
        default:
        case 12:
        case 11:
        case 10:
        case 9:
            free_irq(mokm->irq, mokm);
        case 8:
        case 7:
            pci_set_drvdata(mokm->pdev, NULL);
        case 6:
            cdev_del(&mokm->cdev);
        case 5:
        case 4:
        case 3:
            free_bufs(mokm);
        case 2:
            if(mokm->regs) iounmap(mokm->regs);
            //pci_iounmap(mokm->pdev, mokm->regs);
        case 1:
            //pci_disable_device(mokm->pdev);
            kfree(mokm);
        case 0:
            unregister_chrdev_region(MKDEV(major, 0), MAX_MOKM);
        break;
    }

    return;
} // mokm_detach

//-----------------------------------------------------------------------------
/**
 * Install module
 *
 * insmod ./${module}.ko $*
 **/
static int __init mokm_init (void)
{
    mokm_dev_t *mokm = NULL;
    struct pci_dev *pdev = NULL;
    dev_t   dev_mn;
    int i = 0;
    int result;

    char nod[128];

    PDEBUG("===========================================================================\n");
  #ifdef TRASS_MOKM   /* ---------------------------------- with trass mokm */
    PDEBUG(" %s %s (with TR): mokm_init start\n", MODULE_NAME, __DATE__);
  #else /*TRASS_MOKM     ------------------------------- without trass mokm */
    PDEBUG(" %s %s: mokm_init start\n", MODULE_NAME, __DATE__);
  #endif /*TRASS_MOKM    ----------------------------------- end trass mokm */
    PDEBUG(" %s: PAGE_SIZE = %d \n", MODULE_NAME, (int)PAGE_SIZE);

    result = alloc_chrdev_region(&dev_mn, 0, MAX_MOKM, "MOKM");
    if (result < 0) {
        ERROR_MSG(" ERROR: can't get major %u\n", major);
        return -1;
    }

    major = MAJOR(dev_mn);
    PDEBUG(" got dynamic major %u\n", major);

    if ( major <= 0 ) {
        ERROR_MSG(" ERROR: wrong major %u\n", major);
        return -1;
    }

    // MODULE DEFAULTS INITIALISATION
    mokm_nr_devs = 0;
    while ((pdev = pci_get_device(MOKM_VENDOR_ID, MOKM_DEVICE_ID, pdev)) != NULL) {
        unsigned long start_addr, length;

        //pci_enable_device(pdev);
      #ifdef MOKMDEBUG
        {   u32 Bar0; // FOR DEBUG only
            pci_read_config_dword(pdev, 0x10, &Bar0);
            PDEBUG("%u: BAR0 ADDR 0x%X\n", mokm_nr_devs, Bar0);
        }
      #endif // MOKMDEBUG

#ifdef BUG56455
        length = 16*4;
#else // normal
        length = pci_resource_len(pdev, 0);
#endif // BUG56455
        start_addr = pci_resource_start(pdev, 0);
        /* test latency */
        /*pci_write_config_dword(pdev, 0x0c, 0xf000);*/

        PDEBUG("%u: 0x%X 0x%X pci_res start 0x%X len 0x%X\n", mokm_nr_devs, pdev->vendor, pdev->device, (unsigned int)start_addr, (unsigned int)length);

        if ( (start_addr == 0) || (length == 0) ) {
            ERROR_MSG("%u: ERROR: NO PCI resurces avalible! Skip this module\n", mokm_nr_devs);
            result = -EAGAIN;
            goto failed;
        }

        if ( (mokm = kmalloc(sizeof(mokm_dev_t), GFP_KERNEL)) < 0 ) {
            ERROR_MSG("%u: ERROR: Cannot allocate memory for mokm_dev_t\n", mokm_nr_devs);
            result = -ENOMEM;
            goto failed;
        }

        mokm->attach_level = 0;

        memset(mokm, 0, sizeof(mokm_dev_t));
      #ifdef MOKMDEBUG
        mokm->debug = 0xFFFF;
      #else
        mokm->debug = 0;
      #endif // MOKMDEBUG

        mokm->attach_level = 1;

        mokm->pdev = pdev;

        mokm->open = 0;
        mokm->sync_mode = 1;
        mokm->irq = pdev->irq;
        mokm->instance = mokm_nr_devs;
        PDEBUG("%d: IRQ = 0x%X (%u)\n", mokm->instance, mokm->irq, mokm->irq);

        // Spinlock init
        spin_lock_init(&mokm->DEF_MUTEX_R);   /// spin_lock
#ifndef SINGLE_MUTEX
        spin_lock_init(&mokm->DEF_MUTEX_W);   /// spin_lock
#endif // SINGLE_MUTEX
        init_waitqueue_head(&mokm->wq_ready_rcmd);
        /*init_waitqueue_head(&mokm->wq_pear_ready_for_cmd);*/
        init_waitqueue_head(&mokm->wq_ready_rbuf);
        init_waitqueue_head(&mokm->wq_ready_wbuf);

        // Regs map
        mokm->regs = (mokm_regs_t *)ioremap_nocache(start_addr /* & PCI_BASE_ADDRESS_MEM_MASK*/, length);
        //mokm->regs = (mokm_regs_t *) = (caddr_t)pci_iomap(pdev, 0, length);
        mokm->attach_level = 2;

        // RESET Device
        iowrite32(MOKM_CR_ENDIAN | MOKM_CR_RESET, &mokm->regs->CR);

        iowrite32(ioread32(&mokm->regs->TRC.r) | MOKM_TRC_ENDIAN, &mokm->regs->TRC.r);

        // Init TSMIT/RCV buffers
        if(init_pool_buff(mokm, &mokm->read_pool, &mokm->rbuff, PCI_DMA_FROMDEVICE)) {
            ERROR_MSG("%d: ERROR: Failed to init pool buffers for read\n", mokm->instance);
            goto failed;
        }
        mokm->attach_level = 3;

        if(init_pool_buff(mokm, &mokm->write_pool, &mokm->wbuff, PCI_DMA_TODEVICE)) {
            ERROR_MSG("%d: ERROR: Failed to init pool buffers for write\n", mokm->instance);
            goto failed;
        }
        mokm->attach_level = 4;

        if (0/*mokm->debug & MOKM_DBG_ATTACH*/) show_buff(mokm);

        { // Add divice to the system
            dev_t devno = MKDEV(major, mokm_nr_devs);
            mokm->attach_level = 5;
            cdev_init(&mokm->cdev, &mokm_fops);
            mokm->cdev.owner = THIS_MODULE;
            mokm->cdev.ops = &mokm_fops;

            result = cdev_add(&mokm->cdev, devno, 1);

            if ( result != 0 ) {
                ERROR_MSG("%d: ERROR: Cannot add device to the system\n", mokm->instance);
                goto failed;
            }
        }
        mokm->attach_level = 6;

        pci_set_drvdata(pdev, mokm);
        mokm->attach_level = 7;

        // Save dev
        mokm_devices[mokm_nr_devs] = mokm;

        // INCREMENT DEVICE NUMBER
        mokm_nr_devs++;
    }

    PDEBUG("   %u MOKM DEVICES ARE AVAILABLE\n", mokm_nr_devs);
    if ( mokm_nr_devs <= 0 ) {
        ERROR_MSG(" ERROR: Can't find any device (%u)\n", mokm_nr_devs);
        result = -ENODEV;
        goto failed;
    }


    for ( i = 0; i < mokm_nr_devs; i++ ) {
        if ( request_irq(mokm_devices[i]->irq, mokm_intr_handler, REQ_IRG_FLAG, mokm_name, (void*) mokm_devices[i] ) ) {
            ERROR_MSG("%d: ERROR: Cannot register interrupt handler %s\n", i, mokm_name);
            result = -EAGAIN;
            goto failed;
        }
        mokm_devices[i]->dev = dev_mn;
        mokm_devices[i]->attach_level = 9;
    }

	mokm_class = class_create(THIS_MODULE, "mokm");
	if (IS_ERR(mokm_class)) {
		pr_err("Error creating class: /sys/class/mokm.\n");
	}

	for (i = 0; i < mokm_nr_devs; i++) {
		sprintf(nod, "%s%d", DEV_MODULE_NAME, i);
		if (!IS_ERR(mokm_class)) {
			pr_info("make node /sys/class/mokm/%s\n", nod);
			if (device_create(mokm_class, NULL,
				MKDEV(major, i), NULL, nod) == NULL)
				pr_err("create a node %d failed\n", i);
		}
	}
	mokm->attach_level = 10;

  #ifdef MOKMDEBUG
    dump_all_regs(mokm, "open");
  #endif
    return (0);

  failed:
    for(i = 0; i < mokm_nr_devs; i++) {
        if ( mokm_devices[i] ) {
            mokm_detach( mokm_devices[i] );
        }
    }
    return (result);
} // mokm_init

//-----------------------------------------------------------------------------
/**
 * Uninstall module
 *
 * rmmod ./${module}.ko
 **/
static void __exit mokm_exit (void)
{
    int i;

    for(i = 0; i < mokm_nr_devs; i++) {
	device_destroy(mokm_class, MKDEV(major, i));
        if ( mokm_devices[i] ) {
            mokm_detach( mokm_devices[i] );
        }
    }
	class_destroy(mokm_class);
} // mokm_exit

//-----------------------------------------------------------------------------
module_init(mokm_init);
module_exit(mokm_exit);
