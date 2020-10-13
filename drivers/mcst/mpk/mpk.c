/*
 *  Copyright (c) 2006, 2009, 2010 by MCST.
 *  Copyright (C) 2002 David S. Miller (davem@redhat.com)
 */
/*
 * to load module you must set parameter proto.
 * it describes interface ( change between rs485 and rs422).
 * Parameter value can be 422 or 485. There is no default value.
 * Ex.: proto=422
 */

/*
 ioctl command for mpk
 MPKFULLDUP	0x7af0  set full duplex mode (4 wire)
 MPKHALFDUP	0x7af1  set half duplex mode ( 2 wire)
 MPKCTSRTSON	0x7af2  set check for CTS RTS lines
 MPKCTSRTSOFF	0x7af3  remove check for CTS RTS lines
 MPKECHOON	0x7af4  Only for RS485. Set echo mode on
 MPKECHOOFF	0x7af5  Only for RS485. Set echo mode off"
 MPKBUFF_SIZE	0x7af6  Only for new MPK with buffer set size of transmit buffer

macros are defined in mpk.h
*/

//#define SUPPORT_SA_NODELAY	// to get in serial_core.h; tty.h the type: raw_spinlock_t 

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/major.h>
#include <linux/string.h>
#include <linux/ptrace.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/circ_buf.h>
#include <linux/serial.h>
#include <linux/sysrq.h>
#include <linux/console.h>
#include <linux/spinlock.h>

#include <linux/init.h>

#include <asm/io.h>
#include <asm/irq.h>

#ifdef __e2k__
#include <../drivers/pci2sbus/internal.h>
#include <linux/mcst/p2ssbus.h>
#else
#include <asm/sbus.h>
#endif

#include <linux/of_platform.h>
#include <linux/mcst/ddi.h>

#include <linux/serial_core.h>
#include <linux/mcst/mpk.h>

#include <linux/mcst/mcst_selftest.h>

// /proc/sys/debug/mpk_debug trigger
int mpk_debug = 0;

#define DBGMPK_MODE
#undef DBGMPK_MODE

#if defined(DBGMPK_MODE)
#define dbgmpk		printk
#else
#define	dbgmpk		if ( mpk_debug ) printk
#endif

#define NUM_SUNZILOG	4
#define NUM_CHANNELS	(NUM_SUNZILOG * 2)

static char MPK_DIR[] = "mpk";

#define MPPK_DRIVER_VERSION "20.10.2006"
#if IS_ENABLED(CONFIG_PCI2SBUS) || defined(CONFIG_E90_FASTBOOT)
#define MPPK_PROM_NAME "mpk"
#else
#define MPPK_PROM_NAME "MCST,mpk"
#endif

#define ZS_CLOCK		4915200 /* Zilog input clock rate. */
#define ZS_CLOCK_DIVISOR	16      /* Divisor this driver uses. */

#define CHP	printk(KERN_ERR "%s:%d\n", __func__, __LINE__);

/*
 * We wrap our port structure around the generic uart_port.
 */
struct uart_sunzilog_port {
	struct uart_port		port;

	/* IRQ servicing chain.  */
	struct uart_sunzilog_port	*next;

	struct of_device		*op;
#ifdef MPK_SEPARATE_ADDR_SPACE
	int mpkPortNumber;
	void * mpkDevice;
	unsigned char currentProtocolRegisterValue;
#endif
	/* Current values of Zilog write registers.  */
	unsigned char			curregs[NUM_ZSREGS];

	unsigned int			flags;

#define SUNZILOG_FLAG_MODEM_STATUS	0x00000010
#define SUNZILOG_FLAG_IS_CHANNEL_A	0x00000020
#define SUNZILOG_FLAG_REGS_HELD		0x00000040
#define SUNZILOG_FLAG_TX_STOPPED	0x00000080
#define SUNZILOG_FLAG_TX_ACTIVE		0x00000100
#if IS_ENABLED(CONFIG_MPVK)
#define SUNZILOG_FLAG_KERNEL_USED	0x01000000
#endif

	unsigned int cflag;
	unsigned char			parity_mask;
	unsigned char			prev_status;
	struct zilog_channel __iomem *zs_channelA;
	unsigned char buffer_full_mask;
	char *type_str;
	unsigned char			buff_size;
	unsigned char			mcst_buffering;
#define MAX_XMITBUF_SIZE		15
#if IS_ENABLED(CONFIG_MPVK)
	struct circ_buf xrcv;
	int	mpvk_set;
	int	info_count;		// info block length
#define INFO_DATA_SIZE		prtime_data_size()
	unsigned char	previous_byte;
	unsigned char	dle_start;
	unsigned char	dle_wait;
	unsigned char	dle_finish;
#define XRCV_BUFF_SIZE		13
#endif
};

#define ZILOG_CHANNEL_FROM_PORT(PORT)	((struct zilog_channel __iomem *)((PORT)->membase))
#define UART_ZILOG(PORT)		((struct uart_sunzilog_port *)(PORT))

#define ZS_WANTS_MODEM_STATUS(UP)	((UP)->flags & SUNZILOG_FLAG_MODEM_STATUS)
#define ZS_IS_CHANNEL_A(UP)	((UP)->flags & SUNZILOG_FLAG_IS_CHANNEL_A)
#define ZS_REGS_HELD(UP)	((UP)->flags & SUNZILOG_FLAG_REGS_HELD)
#define ZS_TX_STOPPED(UP)	((UP)->flags & SUNZILOG_FLAG_TX_STOPPED)
#define ZS_TX_ACTIVE(UP)	((UP)->flags & SUNZILOG_FLAG_TX_ACTIVE)
#if IS_ENABLED(CONFIG_MPVK)
#define ZS_UNDER_KERNEL(UP)	((UP)->flags & SUNZILOG_FLAG_KERNEL_USED)

#include <linux/mcst/mpvk.h>
#endif

struct irq_prop {
	unsigned long	serial;
	unsigned long	parallel;
};

struct scc_device {
	struct uart_sunzilog_port port[NUM_CHANNELS];
	unsigned char __iomem *regs;	
	unsigned char __iomem *protocolRegistersAddress;
	int phys_iface;
	struct of_device	*op;
	int instance;
	
	struct irq_prop	*irq;
};

static int num_mpk;

#define  MAX_MPPK_NUMBER 15
static struct scc_device *scc_dev[MAX_MPPK_NUMBER];

#define RS422MODULE_PARAM_VALUE 422
#define RS485MODULE_PARAM_VALUE 485

int new_sbus_irq = -1;
static int proto=0; /* used for change between rs485 and rs422. value can be 422 or 485*/
module_param( proto , int , 0 );
MODULE_PARM_DESC(proto,"used for change between rs485 and rs422. "
	"Parameter value can be 422 or 485. There is no default "
	"value. Ex.: proto=422");

static int buff_sz; /* used for set mpk transmit buffer size. if 0 automatic buffer size detecting */
module_param( buff_sz , int , 0 );
MODULE_PARM_DESC(buff_sz,"used for set mpk transmit buffer size. "
			"if buff_sz=0 automatic buffer size detecting mode.");

int mppk_irq;
int mppk_irq2;

#if defined(CONFIG_SBUS)
#define mpk_writeb	sbus_writeb
#define mpk_readb	sbus_readb
#elif IS_ENABLED(CONFIG_PCI2SBUS)
#define mpk_writeb	writeb
#define mpk_readb	readb
#endif


static struct uart_driver scc_reg = {
	.owner		=	THIS_MODULE,
	.driver_name	=	"ttyA",
	.dev_name	=	"MCST,mpk",
	.major		=	AURORA_MAJOR,
};

#if defined(CONFIG_SYSCTL)
#include <linux/sysctl.h>

static ctl_table mpk_table[] = {
	{
		.procname	= "mpk_debug",
		.data		= &mpk_debug, 
		.maxlen		= sizeof(mpk_debug),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static ctl_table mpk_root_table[] = {
	{
		.procname	= "debug",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= mpk_table,
	},
	{ }
};

static struct ctl_table_header *mpk_sysctl_header = NULL;

static void __init mpk_sysctl_register(void)
{
	mpk_sysctl_header = register_sysctl_table(mpk_root_table);
}

static void mpk_sysctl_unregister(void)
{
	if ( mpk_sysctl_header )
		unregister_sysctl_table(mpk_sysctl_header);
}

#else /* CONFIG_SYSCTL */

static void __init mpk_sysctl_register(void)
{
}

static void mpk_sysctl_unregister(void)
{
}
#endif

/* Reading and writing Zilog8530 registers.  The delays are to make this
 * driver work on the Sun4 which needs a settling delay after each chip
 * register access, other machines handle this in hardware via auxiliary
 * flip-flops which implement the settle time we do in software.
 *
 * The port lock must be held and local IRQs must be disabled
 * when {read,write}_zsreg is invoked.
 */
static unsigned char read_zsreg(struct zilog_channel __iomem *channel,
				unsigned char reg)
{
	unsigned char retval;

	mpk_writeb(reg, &channel->control);
	retval = mpk_readb(&channel->control);

	return retval;
}

static void write_zsreg(struct zilog_channel __iomem *channel,
			unsigned char reg, unsigned char value)
{
	mpk_writeb(reg, &channel->control);
	mpk_writeb(value, &channel->control);
}

static void scc_clear_fifo(struct zilog_channel __iomem *channel)
{
	int i;

	for (i = 0; i < 32; i++) {
		unsigned char regval;

		regval = mpk_readb(&channel->control);
		if (regval & Rx_CH_AV)
			break;

		regval = read_zsreg(channel, R1);
		mpk_readb(&channel->data);

		if (regval & (PAR_ERR | Rx_OVR | CRC_ERR)) {
			mpk_writeb(ERR_RES, &channel->control);
		}
	}
}

/* This function must only be called when the TX is not busy.  The UART
 * port lock must be held and local interrupts disabled.
 */
static void __load_zsregs(struct zilog_channel __iomem *channel, unsigned char *regs)
{
	int i;

	/* Disable all interrupts.  */
	write_zsreg(channel, R1,
		    regs[R1] & ~(RxINT_MASK | TxINT_ENAB | EXT_INT_ENAB));


	/* Let pending transmits finish.  */
	for (i = 0; i < 1000; i++) {
		unsigned char stat = read_zsreg(channel, R1);
		if (stat & ALL_SNT)
			break;
		udelay(100);
	}

	mpk_writeb(ERR_RES, &channel->control);

	scc_clear_fifo(channel);

	/* Set parity, sync config, stop bits, and clock divisor.  */
	write_zsreg(channel, R4, regs[R4]);

	/* Set misc. TX/RX control bits.  */
	write_zsreg(channel, R10, regs[R10]);

	/* Set TX/RX controls sans the enable bits.  */
	write_zsreg(channel, R3, regs[R3] & ~RxENAB);
	write_zsreg(channel, R5, regs[R5] & ~TxENAB);

#ifdef MPK_SEPARATE_ADDR_SPACE
	/* Synchronous mode config.  */
	write_zsreg(channel, R6, regs[R6]);
	write_zsreg(channel, R7, regs[R7]);
#endif
	/* Don't mess with the interrupt vector (R2, unused by us) and
	 * master interrupt control (R9).  We make sure this is setup
	 * properly at probe time then never touch it again.
	 */

	/* Disable baud generator.  */
	write_zsreg(channel, R14, regs[R14] & ~BRENAB);

	/* Clock mode control.  */
	write_zsreg(channel, R11, regs[R11]);

	/* Lower and upper byte of baud rate generator divisor.  */
	write_zsreg(channel, R12, regs[R12]);
	write_zsreg(channel, R13, regs[R13]);

	/* Now rewrite R14, with BRENAB (if set).  */
	write_zsreg(channel, R14, regs[R14]);

	/* External status interrupt control.  */
	write_zsreg(channel, R15, regs[R15]);

	/* Reset external status interrupts.  */
	write_zsreg(channel, R0, RES_EXT_INT);
	write_zsreg(channel, R0, RES_EXT_INT);

	/* Rewrite R3/R5, this time without enables masked.  */
	write_zsreg(channel, R3, regs[R3]);
	write_zsreg(channel, R5, regs[R5]);

	/* Rewrite R1, this time without IRQ enabled masked.  */
	write_zsreg(channel, R1, regs[R1]);
}

/* Reprogram the Zilog channel HW registers with the copies found in the
 * software state struct.  If the transmitter is busy, we defer this update
 * until the next TX complete interrupt.  Else, we do it right now.
 *
 * The UART port lock must be held and local interrupts disabled.
 */
static void scc_maybe_update_regs(struct uart_sunzilog_port *up,
				       struct zilog_channel __iomem *channel)
{
	if (!ZS_REGS_HELD(up)) {
		if (ZS_TX_ACTIVE(up)) {
			up->flags |= SUNZILOG_FLAG_REGS_HELD;
		} else {
			__load_zsregs(channel, up->curregs);
		}
	}
}

#if IS_ENABLED(CONFIG_MPVK)
void set_prtime_fields(struct uart_sunzilog_port *up)
{
	int set = up->mpvk_set;
	unsigned long flags;
	precise_time_st_t *precise_time = 
			&(precise_time_storage_buff[set].precise_time);

	spin_lock_irqsave(&prt_lock[set], flags);
	precise_time->state1.state1_byte = up->xrcv.buf[0];
	precise_time->hrs = up->xrcv.buf[1];
	precise_time->min = up->xrcv.buf[2];
	precise_time->sec = up->xrcv.buf[3];
	precise_time->day = up->xrcv.buf[4];
	precise_time->month = up->xrcv.buf[5];
	precise_time->year = up->xrcv.buf[6];
	precise_time->epoch = up->xrcv.buf[7];

	precise_time->state2.state2_fields.set_state2 = 
				up->xrcv.buf[0] & STV_STATE2_MASK ? 1 : 0;
	precise_time->state2.state2_fields.set_state1 =
				up->xrcv.buf[0] & STV_STATE1_MASK ? 1 : 0;

	spin_unlock_irqrestore(&prt_lock[set], flags);
}

void copy_to_prtime(struct uart_sunzilog_port *up)
{
	int set = up->mpvk_set;
	unsigned long flags;
	dbgmpk(" === copy_to_prtime buffer full head %d up->mpvk_set %d\n",
				up->xrcv.head, up->mpvk_set);
//printk(" === copy_to_prtime channel %p buffer full head %d up->mpvk_set %d\n",
//		ZILOG_CHANNEL_FROM_PORT(&up->port), up->xrcv.head, up->mpvk_set);
	if (shv_equip()) {
		spin_lock_irqsave(&prt_lock[set], flags);
		memcpy((void *)&(precise_time_storage_buff[set].precise_time),
				up->xrcv.buf, prtime_data_size());
		spin_unlock_irqrestore(&prt_lock[set], flags);
	} else set_prtime_fields(up);

	precise_time_correction(set);
	up->xrcv.head = 0;
}
static inline void packet_integrity_fail(struct uart_sunzilog_port *up)
{
//	up->previous_byte = 0;		// FIXME integrity fail
	up->info_count = 0;
	up->dle_start = 0;
	up->dle_wait = 0;
	up->dle_finish = 0;
	up->xrcv.head = 0;
	return;
}

#define	packet_empty(up) packet_integrity_fail(up)

static inline void wait_packet_start(struct uart_sunzilog_port *up, unsigned char ch)
{
	if (ch == DLE) up->previous_byte = DLE;
	else if (ch == P_ID && up->previous_byte == DLE) {
		up->dle_start = DLE;	
	}
	return;
}

static inline void wait_packet_finish(struct uart_sunzilog_port *up, unsigned char ch)
{
	if (up->previous_byte != DLE || ch != ETX) {
		packet_integrity_fail(up);
		wait_packet_start(up, ch);
		return;
	}
	copy_to_prtime(up);
	packet_empty(up);
	return;
}

static inline void wait_next_dle(struct uart_sunzilog_port *up, unsigned char ch)
{
	if (ch != DLE) {
		packet_integrity_fail(up);
		wait_packet_start(up, ch);
		return;
	}

	up->dle_wait = 0;
	up->previous_byte = ch;
	up->xrcv.buf[up->xrcv.head] = ch;
	up->xrcv.head = up->xrcv.head + 1;
}

static inline void data_integrity_check(struct uart_sunzilog_port *up, unsigned char ch)
{
	if (up->info_count != (INFO_DATA_SIZE + 1) || ch != DLE) {
		packet_integrity_fail(up);
		up->previous_byte = ch;			// not needed
		return;
	}
	up->previous_byte = DLE;
	up->dle_finish = DLE;
	return;
}

static inline void check_packet_data(struct uart_sunzilog_port *up, unsigned char ch)
{
//printk(" === check_packet_data channel %p 1 ch 0x%x)\n",
//		ZILOG_CHANNEL_FROM_PORT(&up->port), ch);
	if (!up->dle_start) {				// begin packet reading
		wait_packet_start(up, ch);
		return;
	}
	
	if (up->dle_finish) {				// wait finish block
		wait_packet_finish(up, ch);
		return;
	}
	
	if (up->dle_wait) {
		wait_next_dle(up, ch);
		return;
	}

	if (++up->info_count > INFO_DATA_SIZE) {	// integrity data 1 <-> 13
		data_integrity_check(up, ch);
		return;
	}
	
	if (ch == DLE) 	{
		up->previous_byte = ch;
		up->dle_wait = DLE;
		return;
	};

	up->previous_byte = ch;
	up->xrcv.buf[up->xrcv.head] = ch;
	up->xrcv.head = up->xrcv.head + 1;

	return;
}
#endif


static struct tty_struct *
scc_receive_chars(struct uart_sunzilog_port *up,
		       struct zilog_channel __iomem *channel)
{
	struct tty_struct *tty;
	unsigned char ch, r1, flag;

	tty = NULL;

	if ( up->port.state != NULL )		/* Unopened serial console */
		tty = up->port.state->port.tty;

	dbgmpk(" === scc_receive_chars port %p channel %p\n", up, channel);

	for (;;) {
		r1 = read_zsreg(channel, R1);
		if (r1 & (PAR_ERR | Rx_OVR | CRC_ERR)) {
			mpk_writeb(ERR_RES, &channel->control);
		}
		ch = mpk_readb(&channel->control);
		if (!(ch & Rx_CH_AV))
			break;
		ch = mpk_readb(&channel->data);

		dbgmpk(" === scc_receive_chars port %p channel %p\n", up, channel);
		dbgmpk(" === scc_receive_chars 1 ch %c(0x%x)\n", ch, ch);
		//printk("receive_chars 0x%x \n", ch);

		ch &= up->parity_mask;
#if IS_ENABLED(CONFIG_MPVK)
		if (ZS_UNDER_KERNEL(up)) {
			check_packet_data(up, ch);
			continue;
		}
#endif
		if (tty == NULL) {
			uart_handle_sysrq_char(&up->port, ch);
			continue;
		}

		spin_lock(&tty->read_lock);

		/* A real serial line, record the character and status.  */
		flag = TTY_NORMAL;
		up->port.icount.rx++;
		if (r1 & (BRK_ABRT | PAR_ERR | Rx_OVR | CRC_ERR)) {
			if (r1 & BRK_ABRT) {
				r1 &= ~(PAR_ERR | CRC_ERR);
				up->port.icount.brk++;
				if (uart_handle_break(&up->port))
					goto cont;
			}
			else if (r1 & PAR_ERR)
				up->port.icount.parity++;
			else if (r1 & CRC_ERR)
				up->port.icount.frame++;
			if (r1 & Rx_OVR)
				up->port.icount.overrun++;
			r1 &= up->port.read_status_mask;
			if (r1 & BRK_ABRT)
				flag = TTY_BREAK;
			else if (r1 & PAR_ERR)
				flag = TTY_PARITY;
			else if (r1 & CRC_ERR)
				flag = TTY_FRAME;
		}

		if ( uart_handle_sysrq_char(&up->port, ch) )
			goto cont;

		if (up->port.ignore_status_mask == 0xff ||
		    (r1 & up->port.ignore_status_mask) == 0) {
			tty_insert_flip_char(tty, ch, flag);
		}

		if (r1 & Rx_OVR)
			tty_insert_flip_char(tty, 0, TTY_OVERRUN);

cont:		spin_unlock(&tty->read_lock);
	}

	return tty;
}

static void scc_status_handle(struct uart_sunzilog_port *up,
				   struct zilog_channel __iomem *channel)
{
	unsigned char status;

	status = mpk_readb(&channel->control);

	mpk_writeb(RES_EXT_INT, &channel->control);

	if (ZS_WANTS_MODEM_STATUS(up)) {
		if (status & SYNC)
			up->port.icount.dsr++;

		/* The Zilog just gives us an interrupt when DCD/CTS/etc. change.
		 * But it does not tell us which bit has changed, we have to keep
		 * track of this ourselves.
		 */
		if ((status ^ up->prev_status) ^ DCD)
			uart_handle_dcd_change(&up->port,
					       (status & DCD));
		if ((status ^ up->prev_status) ^ CTS)
			uart_handle_cts_change(&up->port,
					       (status & CTS));

		wake_up_interruptible(&up->port.state->port.delta_msr_wait);
	}

	up->prev_status = status;
}

void sunzilog_transmit(struct uart_sunzilog_port *up,
				    struct zilog_channel __iomem *channel)
{
	struct circ_buf *xmit = &up->port.state->xmit;
	int i;

	if (up->mcst_buffering && up->buff_size == 0) {
		while( !uart_circ_empty(xmit) &&
				!(read_zsreg(up->zs_channelA, R2) & up->buffer_full_mask)) {
			dbgmpk(" ===  %s(): rxm [\'%c\'](0x%x)\n", __func__, xmit->buf[xmit->tail] & 0xFF, xmit->buf[xmit->tail] & 0xFF);
			//printk("rxm 0x%x \n",xmit->buf[xmit->tail] & 0xFF);
			mpk_writeb(xmit->buf[xmit->tail], &channel->data);
			xmit->tail = (xmit->tail + 1) & (UART_XMIT_SIZE - 1);
			up->port.icount.tx++;
		}
	} else {
		for (i = 0; i < up->buff_size; i++) {
			if (uart_circ_empty(xmit))
				break;
			//printk("rxm 0x%x \n",xmit->buf[xmit->tail] & 0xFF);
			mpk_writeb(xmit->buf[xmit->tail], &channel->data);
			xmit->tail = (xmit->tail + 1) & (UART_XMIT_SIZE - 1);
			up->port.icount.tx++;
		}
	}
}

static void scc_transmit_chars(struct uart_sunzilog_port *up,
				    struct zilog_channel __iomem *channel)
{
	struct circ_buf *xmit;
	up->flags &= ~SUNZILOG_FLAG_TX_ACTIVE;

	if (ZS_REGS_HELD(up)) {
		__load_zsregs(channel, up->curregs);
		up->flags &= ~SUNZILOG_FLAG_REGS_HELD;
	}

	if (ZS_TX_STOPPED(up)) {
		up->flags &= ~SUNZILOG_FLAG_TX_STOPPED;
		goto ack_tx_int;
	}

	if (up->port.x_char) {
		up->flags |= SUNZILOG_FLAG_TX_ACTIVE;
		mpk_writeb(up->port.x_char, &channel->data);
		up->port.icount.tx++;
		up->port.x_char = 0;
		return;
	}

	if ( up->port.state == NULL )
		goto ack_tx_int;

	xmit = &up->port.state->xmit;
	if ( uart_circ_empty(xmit) )
		goto ack_tx_int;

	if ( uart_tx_stopped(&up->port) )
		goto ack_tx_int;

	up->flags |= SUNZILOG_FLAG_TX_ACTIVE;
	sunzilog_transmit(up, channel);

	if (uart_circ_chars_pending(xmit) < WAKEUP_CHARS)
		uart_write_wakeup(&up->port);

	return;

ack_tx_int:
	mpk_writeb(RES_Tx_P, &channel->control);

}

static irqreturn_t scc_interrupt(int irq, void *dev_id)
{
	struct uart_sunzilog_port *up = dev_id;
	int i;
	int ret = IRQ_NONE;
	unsigned char *irq_status_reg = (((struct scc_device*) dev_id)->regs) + MPPK_IRQ_STATUS_SCC;
	unsigned char chip_irq = mpk_readb(irq_status_reg);

	for ( i=0; i < NUM_SUNZILOG; i++, up++ ) {
		struct zilog_channel __iomem *channel = ZILOG_CHANNEL_FROM_PORT(&up->port);
		struct tty_struct *tty;
		volatile unsigned char r3;

		if ( !(chip_irq & 1<<i) ) {
		    up++;
		    continue;
		}

		spin_lock(&up->port.lock);
		spin_lock(&(up+1)->port.lock);

		r3 = read_zsreg(channel, R3);

		/** Channel A **/
		tty = NULL;
		if ( r3 & (CHAEXT | CHATxIP | CHARxIP) ) {
			mpk_writeb(RES_H_IUS, &channel->control);
			if (r3 & CHARxIP) {
				tty = scc_receive_chars(up, channel);
			}
			if (r3 & CHAEXT) {
				scc_status_handle(up, channel);
			}
			if (r3 & CHATxIP)
			{
				scc_transmit_chars(up, channel);
			}
			ret = IRQ_HANDLED;
		}

		if (tty)
			tty_flip_buffer_push(tty);

		/** Channel B **/
		up++;
		channel = ZILOG_CHANNEL_FROM_PORT(&up->port);

		tty = NULL;
		if ( r3 & (CHBEXT | CHBTxIP | CHBRxIP) ) {
			mpk_writeb(RES_H_IUS, &channel->control);
			if ( r3 & CHBRxIP ) {
				tty = scc_receive_chars(up, channel);
			}
			if ( r3 & CHBEXT ) {
				scc_status_handle(up, channel);
			}
			if ( r3 & CHBTxIP ) {
				scc_transmit_chars(up, channel);
			}
			ret = IRQ_HANDLED;
		}

		spin_unlock(&up->port.lock);
		spin_unlock(&(up-1)->port.lock);

		if ( tty )
			tty_flip_buffer_push(tty);
	}

	return ret;
}

/* A convenient way to quickly get R0 status.  The caller must _not_ hold the
 * port lock, it is acquired here.
 */
static __inline__ unsigned char scc_read_channel_status(struct uart_port *port)
{
	struct zilog_channel __iomem *channel;
	unsigned char status;

	channel = ZILOG_CHANNEL_FROM_PORT(port);
	status = mpk_readb(&channel->control);
	return status;
}

/* The port lock is not held.  */
static unsigned int scc_tx_empty(struct uart_port *port)
{
	unsigned long flags;
	unsigned char status;
	unsigned int ret;

	spin_lock_irqsave(&port->lock, flags);

	status = scc_read_channel_status(port);

	spin_unlock_irqrestore(&port->lock, flags);

	if ( status & Tx_BUF_EMP )
		ret = TIOCSER_TEMT;
	else
		ret = 0;

	return ret;
}

/* The port lock is held and interrupts are disabled.  */
static unsigned int scc_get_mctrl(struct uart_port *port)
{
	unsigned char status;
	unsigned int ret;

	status = scc_read_channel_status(port);

	ret = 0;
	if ( status & DCD )
		ret |= TIOCM_CAR;
	if ( status & SYNC )
		ret |= TIOCM_DSR;
	if ( status & CTS )
		ret |= TIOCM_CTS;

	return ret;
}

/* The port lock is held and interrupts are disabled.  */
static void scc_set_mctrl(struct uart_port *port, unsigned int mctrl)
{
	struct uart_sunzilog_port *up = (struct uart_sunzilog_port *) port;
	struct zilog_channel __iomem *channel = ZILOG_CHANNEL_FROM_PORT(port);
	unsigned char set_bits, clear_bits;

	set_bits = clear_bits = 0;

	if ( mctrl & TIOCM_RTS )
		set_bits |= RTS;
	else
		clear_bits |= RTS;
	if ( mctrl & TIOCM_DTR )
		set_bits |= DTR;
	else
		clear_bits |= DTR;

	/* NOTE: Not subject to 'transmitter active' rule.  */
	up->curregs[R5] |= set_bits;
	up->curregs[R5] &= ~clear_bits;
	write_zsreg(channel, R5, up->curregs[R5]);
}

/* The port lock is held and interrupts are disabled.  */
static void scc_stop_tx(struct uart_port *port)
{
	struct uart_sunzilog_port *up = (struct uart_sunzilog_port *) port;
	up->flags |= SUNZILOG_FLAG_TX_STOPPED;
}

/* The port lock is held and interrupts are disabled.  */
static void scc_start_tx(struct uart_port *port)
{
	struct uart_sunzilog_port *up = (struct uart_sunzilog_port *) port;
	struct zilog_channel __iomem *channel = ZILOG_CHANNEL_FROM_PORT(port);
	unsigned char status;

	up->flags |= SUNZILOG_FLAG_TX_ACTIVE;
	up->flags &= ~SUNZILOG_FLAG_TX_STOPPED;

	status = mpk_readb(&channel->control);
	/* TX busy?  Just wait for the TX done interrupt.  */
	if ( !(status & Tx_BUF_EMP) ) {
		//printk("scc_start_tx BUFF  non empty exit\n");
		return;
	}

	/* Send the first character to jump-start the TX done
	 * IRQ sending engine.
	 */
	if ( port->x_char ) {
		mpk_writeb(port->x_char, &channel->data);
		port->icount.tx++;
		port->x_char = 0;
	} else {
		struct circ_buf *xmit = &port->state->xmit;
		up->flags |= SUNZILOG_FLAG_TX_ACTIVE;
		sunzilog_transmit(up, channel);
		if (uart_circ_chars_pending(xmit) < WAKEUP_CHARS)
			uart_write_wakeup(&up->port);
	}

}

/* The port lock is held.  */
static void scc_stop_rx(struct uart_port *port)
{
	struct uart_sunzilog_port *up = UART_ZILOG(port);
	struct zilog_channel __iomem *channel;
	channel = ZILOG_CHANNEL_FROM_PORT(port);

	/* Disable all RX interrupts.  */
	up->curregs[R1] &= ~RxINT_MASK;
	scc_maybe_update_regs(up, channel);
}

#if IS_ENABLED(CONFIG_MPVK)
static int scc_startup(struct uart_port *port);

void mpk_set_rx(int busy, int instance, int chan)
{
	struct uart_port *port = &scc_dev[instance]->port[chan].port;
	struct uart_sunzilog_port *up = UART_ZILOG(port);

	dbgmpk(" === mpk_set_rx\n");

	up->xrcv.head = 0;
	up->xrcv.tail = 0;

	up->flags |= SUNZILOG_FLAG_KERNEL_USED;
	up->mpvk_set = (busy >> 1);
	up->info_count = 0;
	up->previous_byte = 0;
	up->dle_start = 0;
	up->dle_wait = 0;
	up->dle_finish = 0;

//	init_precise_time_storage(up->mpvk_set);
	dbgmpk(" === mpk_set_rx up->flags 0x%x up->mpvk_set %d"
	       " precise_time_storage[up->mpvk_set].diff_time %ld\n",
	       up->flags, up->mpvk_set , precise_time_storage[up->mpvk_set].diff_time);

	scc_startup(port);
//	scc_set_mctrl(port);
}

EXPORT_SYMBOL(mpk_set_rx);

void mpk_unmask_rx(int busy, int instance, int chan)
{	
	struct uart_port *port = &scc_dev[instance]->port[chan].port;
//	struct uart_sunzilog_port *up = UART_ZILOG(port);
//	unsigned long flags;

//	channel = ZILOG_CHANNEL_FROM_PORT(port);

	scc_startup(port);

	/* Enable all RX interrupts.  */
//	spin_lock_irqsave(&port->lock, flags);
//	up->curregs[R1] |= RxINT_MASK | EXT_INT_ENAB;
//	scc_maybe_update_regs(up, channel);
//	spin_unlock_irqrestore(&port->lock, flags);
}

EXPORT_SYMBOL(mpk_unmask_rx);
#endif


/* The port lock is held.  */
static void scc_enable_ms(struct uart_port *port)
{
	struct uart_sunzilog_port *up = (struct uart_sunzilog_port *) port;
	struct zilog_channel __iomem *channel = ZILOG_CHANNEL_FROM_PORT(port);
	unsigned char new_reg;

	new_reg = up->curregs[R15] | (DCDIE | SYNCIE | CTSIE);
	if ( new_reg != up->curregs[R15] ) {
		up->curregs[R15] = new_reg;

		/* NOTE: Not subject to 'transmitter active' rule.  */
		write_zsreg(channel, R15, up->curregs[R15]);
	}
}

/* The port lock is not held.  */
static void scc_break_ctl(struct uart_port *port, int break_state)
{
	struct uart_sunzilog_port *up = (struct uart_sunzilog_port *) port;
	struct zilog_channel __iomem *channel = ZILOG_CHANNEL_FROM_PORT(port);
	unsigned char set_bits, clear_bits, new_reg;
	unsigned long flags;

	set_bits = clear_bits = 0;

	if ( break_state )
		set_bits |= SND_BRK;
	else
		clear_bits |= SND_BRK;

	spin_lock_irqsave(&port->lock, flags);

	new_reg = (up->curregs[R5] | set_bits) & ~clear_bits;
	if ( new_reg != up->curregs[R5] ) {
		up->curregs[R5] = new_reg;

		/* NOTE: Not subject to 'transmitter active' rule.  */
		write_zsreg(channel, R5, up->curregs[R5]);
	}

	spin_unlock_irqrestore(&port->lock, flags);
}

static void __scc_startup(struct uart_sunzilog_port *up)
{
	struct zilog_channel __iomem *channel;

	channel = ZILOG_CHANNEL_FROM_PORT(&up->port);
	up->prev_status = mpk_readb(&channel->control);

	/* Enable receiver and transmitter.  */
	up->curregs[R3] |= RxENAB;
	up->curregs[R5] |= TxENAB;

        /* Enable RTSCTS module. */
	if ( up->mcst_buffering ) {
		struct scc_device *dev = ((struct scc_device *)up->mpkDevice);
		dev->port[up->mpkPortNumber].currentProtocolRegisterValue |= MPKREG_RTSCTS;
		sbus_writeb( dev->port[up->mpkPortNumber].currentProtocolRegisterValue ,
		(char*)( (int *)dev->protocolRegistersAddress + up->mpkPortNumber ));
	}

	up->curregs[R1] |= EXT_INT_ENAB | INT_ALL_Rx | TxINT_ENAB;
	scc_maybe_update_regs(up, channel);
}

static int scc_startup(struct uart_port *port)
{
	struct uart_sunzilog_port *up = UART_ZILOG(port);
	unsigned long flags;
	spin_lock_irqsave(&port->lock, flags);
	__scc_startup(up);
	spin_unlock_irqrestore(&port->lock, flags);

	set_current_state(TASK_INTERRUPTIBLE);
 	schedule_timeout(5);
	return 0;
}

static void scc_shutdown(struct uart_port *port)
{
	struct uart_sunzilog_port *up = UART_ZILOG(port);
	struct zilog_channel __iomem *channel;
	unsigned long flags;
	spin_lock_irqsave(&port->lock, flags);
	scc_stop_tx(port);
	channel = ZILOG_CHANNEL_FROM_PORT(port);

	/* Disable receiver and transmitter.  */
	up->curregs[R3] &= ~RxENAB;
	up->curregs[R5] &= ~TxENAB;

	/* Disable RTSCTS module. Power safe mode. */
	if ( up->mcst_buffering ) {
		struct scc_device *dev = ((struct scc_device *)up->mpkDevice);
		dev->port[up->mpkPortNumber].currentProtocolRegisterValue &= ~MPKREG_RTSCTS;
		sbus_writeb( dev->port[up->mpkPortNumber].currentProtocolRegisterValue ,
		(char*)( (int *)dev->protocolRegistersAddress + up->mpkPortNumber ));
	}

	/* Disable all interrupts and BRK assertion.  */
	up->curregs[R1] &= ~(EXT_INT_ENAB | TxINT_ENAB | RxINT_MASK);
	up->curregs[R5] &= ~SND_BRK;
	scc_maybe_update_regs(up, channel);

	spin_unlock_irqrestore(&port->lock, flags);
}

#if IS_ENABLED(CONFIG_MPVK)
void mpk_release_kernel(int instance, int chan)
{
	struct uart_port *port = &scc_dev[instance]->port[chan].port; // FIXME chan inst now for /dev/ttyA0
	struct uart_sunzilog_port *up = UART_ZILOG(port);

	up->flags &= ~SUNZILOG_FLAG_KERNEL_USED;
//	init_precise_time_storage(up->mpvk_set);

	scc_shutdown(port);
}
EXPORT_SYMBOL(mpk_release_kernel);

void mpk_mask_rx(int busy, int instance, int chan)
{	
	struct uart_port *port = &scc_dev[instance]->port[chan].port;
//	struct uart_sunzilog_port *up = UART_ZILOG(port);
//	unsigned long flags;

//	channel = ZILOG_CHANNEL_FROM_PORT(port);

	scc_shutdown(port);

	/* Disable all RX interrupts.  */
//	spin_lock_irqsave(&port->lock, flags);
//	up->curregs[R1] &= ~(RxINT_MASK | EXT_INT_ENAB);
//	scc_maybe_update_regs(up, channel);
//	spin_unlock_irqrestore(&port->lock, flags);
}
EXPORT_SYMBOL(mpk_mask_rx);
#endif

/* Shared by TTY driver and serial console setup.  The port lock is held
 * and local interrupts are disabled.
 */
static void
scc_convert_to_zs(struct uart_sunzilog_port *up, unsigned int cflag,
		       unsigned int iflag, int brg)
{
	up->curregs[R10] = NRZ;
	up->curregs[R11] = TCBR | RCBR;

	/* Program BAUD and clock source. */
	up->curregs[R4] &= ~XCLK_MASK;
	up->curregs[R4] |= X16CLK;
	up->curregs[R12] = brg & 0xff;
	up->curregs[R13] = (brg >> 8) & 0xff;
	up->curregs[R14] = BRSRC | BRENAB;

#ifdef MPK_SEPARATE_ADDR_SPACE
	if (brg == BPS_TO_BRG(115200, ZS_CLOCK / ZS_CLOCK_DIVISOR)) {
	    up->curregs[R6]  = 0x15;
	    up->curregs[R7]  = 0x80;
	    up->curregs[R12] = 0x00;
	    up->curregs[R13] = 0x00;
	} else if (brg == BPS_TO_BRG(57600, ZS_CLOCK / ZS_CLOCK_DIVISOR)) {
	    up->curregs[R6]  = 0x2A;
	    up->curregs[R7]  = 0x80;
	    up->curregs[R12] = 0x00;
	    up->curregs[R13] = 0x00;
	} else {
	    up->curregs[R6]  = 0x00;
	    up->curregs[R7]  = 0x00;
	}
	
	/* Inteligent interrupt claming.
	 * This bit usefull for New modules only.
	 * In the old modules this bit is useless ???
	 */
	if ( up->mcst_buffering ) {
		up->curregs[R7] |= INTELEG_INTR | RTS_MOD;
		up->curregs[R3] |= AUTO_ENAB;
	}
#endif

	/* Character size, stop bits, and parity. */
	up->curregs[R3] &= ~RxN_MASK;
	up->curregs[R5] &= ~TxN_MASK;

	switch (cflag & CSIZE) {
		case CS5:
			up->curregs[R3] |= Rx5;
			up->curregs[R5] |= Tx5;
			up->parity_mask = 0x1f;
			break;
		case CS6:
			up->curregs[R3] |= Rx6;
			up->curregs[R5] |= Tx6;
			up->parity_mask = 0x3f;
			break;
		case CS7:
			up->curregs[R3] |= Rx7;
			up->curregs[R5] |= Tx7;
			up->parity_mask = 0x7f;
			break;
		case CS8:
		default:
			up->curregs[R3] |= Rx8;
			up->curregs[R5] |= Tx8;
			up->parity_mask = 0xff;
			break;
	}

	up->curregs[R4] &= ~0x0c;
	if ( cflag & CSTOPB )
		up->curregs[R4] |= SB2;
	else
		up->curregs[R4] |= SB1;
	if ( cflag & PARENB )
		up->curregs[R4] |= PAR_ENAB;
	else
		up->curregs[R4] &= ~PAR_ENAB;
	if ( !(cflag & PARODD) )
		up->curregs[R4] |= PAR_EVEN;
	else
		up->curregs[R4] &= ~PAR_EVEN;

	up->port.read_status_mask = Rx_OVR;
	if ( iflag & INPCK )
		up->port.read_status_mask |= CRC_ERR | PAR_ERR;
	if ( iflag & (BRKINT | PARMRK) )
		up->port.read_status_mask |= BRK_ABRT;

	up->port.ignore_status_mask = 0;
	if ( iflag & IGNPAR )
		up->port.ignore_status_mask |= CRC_ERR | PAR_ERR;
	if ( iflag & IGNBRK ) {
		up->port.ignore_status_mask |= BRK_ABRT;
		if (iflag & IGNPAR)
			up->port.ignore_status_mask |= Rx_OVR;
	}

	if ( (cflag & CREAD) == 0 )
		up->port.ignore_status_mask = 0xff;
}

#ifdef MPK_SEPARATE_ADDR_SPACE
void setProtoRegBit(char mask, struct uart_port * port){
	struct uart_sunzilog_port *up = UART_ZILOG(port);
	char protoRegValue;

	protoRegValue=up->currentProtocolRegisterValue;
	if ( protoRegValue != (protoRegValue | mask) ) {

		up->currentProtocolRegisterValue |= mask;
		sbus_writeb( up->currentProtocolRegisterValue ,
			(char*)( ((struct scc_device *)up->mpkDevice)->
			protocolRegistersAddress + up->mpkPortNumber ));
	}
}

void clearProtoRegBit(char mask, struct uart_port * port){
	struct uart_sunzilog_port *up = UART_ZILOG(port);
	char protoRegValue;

	protoRegValue=up->currentProtocolRegisterValue;
	if(protoRegValue != (protoRegValue & ~mask) ){
		up->currentProtocolRegisterValue &= ~mask;
		sbus_writeb( up->currentProtocolRegisterValue ,
			(char*)( ((struct scc_device *)up->mpkDevice)->
			protocolRegistersAddress + up->mpkPortNumber ));
	}
}
#else
void setProtoRegBit(char mask, struct uart_port * port){
    struct uart_sunzilog_port *up = UART_ZILOG(port);
    struct zilog_channel __iomem *channel = ZILOG_CHANNEL_FROM_PORT(port);
    
    up->curregs[R6] |= mask;
    write_zsreg(channel,R6,up->curregs[R6]);
}

void clearProtoRegBit(char mask, struct uart_port * port){
    struct uart_sunzilog_port *up = UART_ZILOG(port);
    struct zilog_channel __iomem *channel = ZILOG_CHANNEL_FROM_PORT(port);

    up->curregs[R6] &= ~mask;
    write_zsreg(channel,R6,up->curregs[R6]);    
}
#endif

static int scc_ioctl(struct uart_port *port, unsigned int command, unsigned long argument) {
	struct uart_sunzilog_port *up = UART_ZILOG(port);
#if IS_ENABLED(CONFIG_MPVK)
	if (ZS_UNDER_KERNEL(up)) {
		printk(KERN_DEBUG " port used by kernel\n");
		return -EFAULT;
	}
#endif

	switch ( command ) {
		case MCST_SELFTEST_MAGIC:
		{
			selftest_t st;
#if defined(CONFIG_SBUS)
			selftest_sbus_t *st_sbus = &st.info.sbus;
			struct tty_struct *tty = NULL;
			dev_t  dev;
			char *tmp, *sl_n;
			int slot_num, addr;
			struct device_node *dn = up->op->node;
			size_t rval;

			st.bus_type = BUS_SBUS;
			st_sbus->bus = 0;
			strcpy(st_sbus->name, scc_reg.dev_name);

			if ( up->port.state != NULL ) {	/* Unopened serial console */
				tty = up->port.state->port.tty;
			}

			if ( tty ) {
				dev = tty_devnum(tty);

				st_sbus->major = MAJOR(dev);
				st_sbus->minor = MINOR(dev);

			//	printk("%s: tty->index = %d, major = %d, minor = %d\n", __func__, tty->index, st_sbus->major, st_sbus->minor);
			}

			//printk("full_name [%s]\n", dn->full_name);
			tmp = strrchr(dn->full_name, '@');
			if ( tmp ) {
				// Уберём символ "@" из строки
				tmp = &tmp[1];
				//printk("STRRCHR: [%s]\n", tmp);

				sl_n = strrchr(tmp, ',');

				if ( sl_n ) {
					sscanf(tmp, "%d", &slot_num);
					sscanf(&sl_n[1], "%x", &addr);
					//printk("STRRCHR: slot_number [%d], [%s], [%d]\n", slot_num, sl_n, addr);

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

//			printk("%s:\n\tMAJOR [%d]. MINOR [%d]. BUS [%d]. BR_SLOT [%d]. SLOT [%d]. ADDRESS [%#x]. Name [%s]\n", __func__, st_sbus->major, st_sbus->minor, st_sbus->bus, st_sbus->br_slot, st_sbus->slot, st_sbus->address, st_sbus->name);
#elif IS_ENABLED(CONFIG_PCI2SBUS)
				selftest_pci_t *st_pci = &st.info.pci;
				struct tty_struct *tty = NULL;
				dev_t  dev;
				int irq = up->op->irqs[0];
				p2s_info_t* p2s_info = get_p2s_info(irq >> 8);

				if ( !p2s_info ) {
					printk("%s: MCST_SELFTEST_MAGIC: Cannot get p2s_info struct corresponded to IRQ=%d\n",
						__func__, irq);
					return -EFAULT;
				}

				struct pci_dev *pdev = p2s_info->pdev;
				int rval;
				st_pci->vendor = pdev->vendor;
				st_pci->device = pdev->device;

				st.bus_type = BUS_PCI;

				strcpy(st_pci->name, scc_reg.dev_name);
				st_pci->bus = pdev->bus->number; 
				st_pci->slot = PCI_SLOT(pdev->devfn);
				st_pci->func = PCI_FUNC(pdev->devfn);
				st_pci->class = pdev->class;

				if ( up->port.state != NULL ) {	/* Unopened serial console */
					tty = up->port.state->port.tty;
				}

				if ( tty ) {
					dev = tty_devnum(tty);

					st_pci->major = MAJOR(dev);
					st_pci->minor = MINOR(dev);

				//	printk("%s: tty->index = %d, major = %d, minor = %d\n", __func__, tty->index, st_pci->major, st_pci->minor);
				}

//				printk("%s: name [%s]. vendor = %#x, device = %#x. major = %d, minor = %d. bus = %d, slot = %d, func = %d, class = %#x\n", __func__, st_pci->name, st_pci->vendor, st_pci->device, st_pci->major, st_pci->minor, st_pci->bus, st_pci->slot, st_pci->func, st_pci->class);
#else
				printk("%s: MCST_SELFTEST_MAGIC: neither CONFIG_SBUS nor CONFIG_PCI2SBUS(CONFIG_PCI2SBUS_MODULE) is defined!! Strange...\n");
				return -EFAULT;
#endif

			rval = copy_to_user((void *)argument, (void *)&st, sizeof(selftest_t));
			if ( rval != 0 ) {
				printk( "%s: MCST_SELFTEST_MAGIC: copy_to_user() failed\n", __func__);
				return -EFAULT;
			}
		}

			return 0;
		case MPKHALFDUP:
			setProtoRegBit( MPKREG_HALFDUPLEX , port );
			return 0;

		case MPKFULLDUP:
			clearProtoRegBit( MPKREG_HALFDUPLEX , port );
			return 0;

		case MPKCTSRTSON:
			setProtoRegBit( MPKREG_RTSCTS , port );
			return 0;

		case MPKCTSRTSOFF:
			clearProtoRegBit( MPKREG_RTSCTS , port );
			return 0;

		case MPKECHOON:
			if(proto==RS485MODULE_PARAM_VALUE){
				setProtoRegBit( MPKREG_ECHOMODE , port );
				return 0;
			}
			return -EFAULT;

		case MPKECHOOFF:
			if(proto==RS485MODULE_PARAM_VALUE){
				clearProtoRegBit( MPKREG_ECHOMODE , port );
				return 0;
			}
			return -EFAULT;

		case MPKBUFF_SIZE: {
			unsigned long flags;
			spin_lock_irqsave(&up->port.lock, flags);
			if( argument < 1 || argument > MAX_XMITBUF_SIZE) {
				printk(KERN_ERR "Invalid buffer size %lu. must be 1 .. %d\n", argument, MAX_XMITBUF_SIZE);
				return -EFAULT;
			}
			up->buff_size = argument;
			spin_unlock_irqrestore(&up->port.lock, flags);
			return 0;
		}
		default:
			return -ENOIOCTLCMD;
	}
}

/* The port lock is not held.  */
static void
scc_set_termios(struct uart_port *port, struct ktermios *termios,
		     struct ktermios *old)
{
	struct uart_sunzilog_port *up = (struct uart_sunzilog_port *) port;
	unsigned long flags;
	int baud, brg;

	baud = uart_get_baud_rate(port, termios, old, 1200, 115200);

	spin_lock_irqsave(&up->port.lock, flags);

	brg = BPS_TO_BRG(baud, ZS_CLOCK / ZS_CLOCK_DIVISOR);

	scc_convert_to_zs(up, termios->c_cflag, termios->c_iflag, brg);

	if (UART_ENABLE_MS(&up->port, termios->c_cflag))
		up->flags |= SUNZILOG_FLAG_MODEM_STATUS;
	else
		up->flags &= ~SUNZILOG_FLAG_MODEM_STATUS;

	up->cflag = termios->c_cflag;

	scc_maybe_update_regs(up, ZILOG_CHANNEL_FROM_PORT(port));

	uart_update_timeout(port, termios->c_cflag, baud);

	spin_unlock_irqrestore(&up->port.lock, flags);
}

#if IS_ENABLED(CONFIG_MPVK)
void
mpk_set_termios(int instance, int chan, struct termios *termios, struct termios *old)
{
	struct uart_port *port = &scc_dev[instance]->port[chan].port; // FIXME chan inst now for /dev/ttyA0
	struct uart_sunzilog_port *up = (struct uart_sunzilog_port *) port;
	unsigned long flags;
	int baud, brg;

	dbgmpk(" === mpk_set_termios\n");

	baud = uart_get_baud_rate(port, termios, old, 1200, 76800);

	spin_lock_irqsave(&up->port.lock, flags);

	brg = BPS_TO_BRG(baud, ZS_CLOCK / ZS_CLOCK_DIVISOR);

	scc_convert_to_zs(up, termios->c_cflag, termios->c_iflag, brg);

	if (UART_ENABLE_MS(&up->port, termios->c_cflag))
		up->flags |= SUNZILOG_FLAG_MODEM_STATUS;
	else
		up->flags &= ~SUNZILOG_FLAG_MODEM_STATUS;

	up->cflag = termios->c_cflag;

	scc_maybe_update_regs(up, ZILOG_CHANNEL_FROM_PORT(port));

	uart_update_timeout(port, termios->c_cflag, baud);

	spin_unlock_irqrestore(&up->port.lock, flags);
}

EXPORT_SYMBOL(mpk_set_termios);
#endif

static const char *scc_type(struct uart_port *port)
{
	return ((struct uart_sunzilog_port *)port)->type_str;
}

/* We do not request/release mappings of the registers here, this
 * happens at early serial probe time.
 */
static void scc_release_port(struct uart_port *port)
{
}

static int scc_request_port(struct uart_port *port)
{
	return 0;
}

/* These do not need to do anything interesting either.  */
static void scc_config_port(struct uart_port *port, int flags)
{
}

/* We do not support letting the user mess with the divisor, IRQ, etc. */
static int scc_verify_port(struct uart_port *port, struct serial_struct *ser)
{
	return -EINVAL;
}



static struct uart_ops scc_pops = {
	.tx_empty	=	scc_tx_empty,
	.set_mctrl	=	scc_set_mctrl,
	.get_mctrl	=	scc_get_mctrl,
	.stop_tx	=	scc_stop_tx,
	.start_tx	=	scc_start_tx,
	.stop_rx	=	scc_stop_rx,
	.enable_ms	=	scc_enable_ms,
	.break_ctl	=	scc_break_ctl,
	.startup	=	scc_startup,
	.shutdown	=	scc_shutdown,
	.set_termios	=	scc_set_termios,
	.type		=	scc_type,
	.release_port	=	scc_release_port,
	.request_port	=	scc_request_port,
	.config_port	=	scc_config_port,
	.verify_port	=	scc_verify_port,
	.ioctl		=	scc_ioctl,
};

static void __init scc_prepare(struct scc_device* dev)
{
	struct uart_sunzilog_port *up;
	struct zilog_layout __iomem *rp;
	int channel, chip = 0;

	/*
	 * Temporary fix.
	 */
	if ( buff_sz < 0 ) {
		printk(KERN_ERR "Invalid value of buff_sz = %d; Set auto detect buffer size mode.\n", buff_sz);
		buff_sz = 0;
	}

	for ( channel = 0; channel < NUM_CHANNELS; channel++ )
		spin_lock_init(&dev->port[channel].port.lock);

	up = dev->port;

	for ( channel = 0; channel < NUM_CHANNELS - 1; channel++ )
		up[channel].next = &up[channel + 1];

	up[channel].next = NULL;
	up[0].port.iotype = 4;

	for ( rp = (struct zilog_layout __iomem *)dev->regs, chip = 0;
				 chip < NUM_SUNZILOG; chip++, rp++ ) {
		up[(chip * 2) + 0].port.membase = (void __iomem *)&rp->channelA;
		up[(chip * 2) + 1].port.membase = (void __iomem *)&rp->channelB;

		/* Channel A */
		up[(chip * 2) + 0].port.iotype = SERIAL_IO_MEM;
		up[(chip * 2) + 0].port.irq = dev->op->irqs[0];
		up[(chip * 2) + 0].port.uartclk = ZS_CLOCK;
		up[(chip * 2) + 0].port.fifosize = 1;
		up[(chip * 2) + 0].port.ops = &scc_pops;
		up[(chip * 2) + 0].port.type = PORT_SUNZILOG;
		up[(chip * 2) + 0].port.flags = 0;
		up[(chip * 2) + 0].port.line = (chip * 2) + 0;
		up[(chip * 2) + 0].flags |= SUNZILOG_FLAG_IS_CHANNEL_A;
#if IS_ENABLED(CONFIG_MPVK)
		up[(chip * 2) + 0].xrcv.buf = kmalloc(XRCV_BUFF_SIZE, GFP_KERNEL);
		up[(chip * 2) + 0].xrcv.head = 0;
		up[(chip * 2) + 0].xrcv.tail = 0;
#endif
		/* Channel B */
		up[(chip * 2) + 1].port.iotype = SERIAL_IO_MEM;
		up[(chip * 2) + 1].port.irq = dev->op->irqs[0];
		up[(chip * 2) + 1].port.uartclk = ZS_CLOCK;
		up[(chip * 2) + 1].port.fifosize = 1;
		up[(chip * 2) + 1].port.ops = &scc_pops;
		up[(chip * 2) + 1].port.type = PORT_SUNZILOG;
		up[(chip * 2) + 1].port.flags = 0;
		up[(chip * 2) + 1].port.line = (chip * 2) + 1;
		up[(chip * 2) + 1].flags |= 0;
#if IS_ENABLED(CONFIG_MPVK)
		up[(chip * 2) + 1].xrcv.buf = kmalloc(XRCV_BUFF_SIZE, GFP_KERNEL);
		up[(chip * 2) + 1].xrcv.head = 0;
		up[(chip * 2) + 1].xrcv.tail = 0;
#endif
	}
}

static void __init scc_init_hw(struct scc_device* dev)
{
	struct uart_sunzilog_port *up;
	struct zilog_channel __iomem *channel;
	int i;

	for ( i = 0; i < NUM_CHANNELS; i++ ) {
		unsigned long flags;
		int baud, brg;

		up = &dev->port[i];
		channel = ZILOG_CHANNEL_FROM_PORT(&up->port);

		spin_lock_irqsave(&up->port.lock, flags);

#ifndef MPK_SEPARATE_ADDR_SPACE
		if( proto == RS422MODULE_PARAM_VALUE ) {
		    write_zsreg(channel, R6, MPKREG_RS422MODE);
		} else if ( proto == RS485MODULE_PARAM_VALUE ) {
		    write_zsreg(channel, R6, MPKREG_RS485MODE);
		} else
		    printk(KERN_ERR "Unknown mode %d\n",proto);
#endif
		if ( ZS_IS_CHANNEL_A(up) ) {
			write_zsreg(channel, R9, FHWRES);
			(void) read_zsreg(channel, R0);

			write_zsreg(channel, R2,0);
			if ( read_zsreg(channel, R2) & MCST_SUPPORT_BUFF ) {
				up->type_str = "MCST Zilog with buffering";
				up->mcst_buffering = 1;
				up->buff_size = buff_sz; // may be set from ioctl
			} else {
				up->type_str = "MCST Zilog without buffering";
				up->buff_size = 1;
				up->mcst_buffering = 0;
			}

			up->zs_channelA = up->next->zs_channelA = channel;
			up->buffer_full_mask = MCST_CH_A_Tx_BUFFER_FULL;
			up->next->buffer_full_mask = MCST_CH_B_Tx_BUFFER_FULL;
			up->next->mcst_buffering = up->mcst_buffering;
			up->next->type_str = up->type_str;
			up->next->buff_size = up->buff_size;
		}

		/* Normal serial TTY. */
		up->parity_mask = 0xff;
		up->curregs[R1] = EXT_INT_ENAB | INT_ALL_Rx | TxINT_ENAB;
		up->curregs[R4] = PAR_EVEN | X16CLK | SB1;
		up->curregs[R3] = RxENAB | Rx8;
		up->curregs[R5] = TxENAB | Tx8;
		up->curregs[R9] = NV | MIE;
		up->curregs[R10] = NRZ;
		up->curregs[R11] = TCBR | RCBR;
		baud = 9600;
		brg = BPS_TO_BRG(baud, ZS_CLOCK / ZS_CLOCK_DIVISOR);
		up->curregs[R12] = (brg & 0xff);
		up->curregs[R13] = (brg >> 8) & 0xff;
		up->curregs[R14] = BRSRC | BRENAB;
		__load_zsregs(channel, up->curregs);
		write_zsreg(channel, R9, up->curregs[R9]);

		spin_unlock_irqrestore(&up->port.lock, flags);

	}

	if ( up->mcst_buffering ) {
		if ( up->buff_size == 0 ) {
			printk(KERN_INFO "MCST Zilog with buffering. Set auto detect buff size mode\n");
		} else {
			printk(KERN_INFO "MCST Zilog with buffering. Transmit buffer size = %d \n", up->buff_size);
		}
	}
}

static int
mpk_remove(struct of_device *op)
{
	struct scc_device *dev = dev_get_drvdata(&op->dev);

	mpk_writeb(0, dev->regs + MPPK_IRQ_SCC);

#if defined(CONFIG_SBUS)
	free_irq(op->irqs[0], dev->port);
#elif IS_ENABLED(CONFIG_PCI2SBUS)
	sbus_free_irq(op->irqs[0], dev->port);
#else
	printk("Really crazy behavoir ...\n");
#endif

	of_iounmap(&op->resource[0], dev->regs, op->resource[0].end - op->resource[0].start + 1);

#ifdef MPK_SEPARATE_ADDR_SPACE
	of_iounmap(&op->resource[1], dev->protocolRegistersAddress, op->resource[1].end - op->resource[1].start + 1);
#endif

	kfree(dev);

	dev_set_drvdata(&op->dev, NULL);

	return 0;
}

static int
mpk_probe(struct of_device *op, const struct of_device_id *match)
{
	int instance = num_mpk++;
	struct scc_device *dev = (struct scc_device *) kmalloc(sizeof(struct scc_device), GFP_KERNEL);
	int irq_flags = 0;
	int channel;

	if ( dev == NULL )
		return -EFAULT;

	memset(dev, 0, sizeof(struct scc_device));

	dev->op = op;
	dev->instance = instance;

	dev->regs = of_ioremap(&op->resource[0], 0,
					op->resource[0].end - op->resource[0].start + 1,
					MPPK_PROM_NAME);

	if ( dev->regs == NULL ) {
		printk(KERN_ERR "%s(): Unable to map registers of %d instance\n", __func__, 
							 instance);
		goto err_mem_free;
	}

#ifdef MPK_SEPARATE_ADDR_SPACE
{
	int i = 0;

	dev->protocolRegistersAddress =
		of_ioremap(&op->resource[1], 0,
				op->resource[1].end - op->resource[1].start + 1,
				"extra" MPPK_PROM_NAME);

	if ( dev->protocolRegistersAddress == NULL ) {
		printk(KERN_ERR "%s(): Unable to map registers of %d instance\n", __func__, 
							 dev->instance);
		goto err_unmap1;
	}

	for ( i = 0; i < NUM_CHANNELS; i++ ) {

		if ( proto == RS422MODULE_PARAM_VALUE ) {
			dev->port[i].
				currentProtocolRegisterValue= MPKREG_RS422MODE;
		} else if( proto == RS485MODULE_PARAM_VALUE ) {
			dev->port[i].currentProtocolRegisterValue= MPKREG_RS485MODE | MPKREG_HALFDUPLEX;
		}

		dev->port[i].mpkPortNumber=i;
		dev->port[i].mpkDevice=dev;
		sbus_writeb(dev->port[i].currentProtocolRegisterValue,
				(char*) (dev->protocolRegistersAddress + i));
	}
}
#endif

	scc_prepare(dev);

	scc_init_hw(dev);

	if ( new_sbus_irq >= 0 )
		op->irqs[0] = new_sbus_irq;

	irq_flags = IRQF_SHARED;
#if defined(CONFIG_MCST_RT)
	irq_flags |=  IRQF_DISABLED;
#endif

#ifdef CONFIG_E90
	dev->irq = (struct irq_prop *)of_get_property(op->node, "interrupts", NULL);
	if ( !dev->irq )
		goto err_unmap2;

	if ( request_threaded_irq(op->irqs[0], &scc_interrupt, NULL,
		irq_flags, MPPK_PROM_NAME, (void *)dev->port) ) {
		printk(KERN_ERR "MVP-%d: Can't get irq %d\n", instance, op->irqs[0]);

#if defined(MPK_SEPARATE_ADDR_SPACE)
		goto err_unmap2;
#else
		goto err_unmap;
#endif
	}

	mpk_writeb((1 << dev->irq->serial) & 0xff, dev->regs + MPPK_IRQ_SCC);
#else
{
	int err;

	if (err = sbus_request_irq(op->irqs[0], scc_interrupt, NULL,
		irq_flags, MPPK_PROM_NAME, (void *)dev->port) ) {
		printk(KERN_ERR "MVP-%d: Can't get irq %d, err = %d\n", instance, op->irqs[0], err);

#if defined(MPK_SEPARATE_ADDR_SPACE)
		goto err_unmap2;
#else
		goto err_unmap;
#endif
	}
}

	mpk_writeb((1 << op->irqs[0]) & 0xff, dev->regs + MPPK_IRQ_SCC);
#endif
	scc_dev[instance] = dev;

	dev_set_drvdata(&op->dev, dev);

	return 0;

err_free_irq:
#if defined(CONFIG_SBUS)
	free_irq(op->irqs[0], (void *)dev->port);
#elif IS_ENABLED(CONFIG_PCI2SBUS)
	sbus_free_irq(op->irqs[0], (void *)dev->port);
#endif

#if defined(MPK_SEPARATE_ADDR_SPACE)
err_unmap2:
	of_iounmap(&op->resource[1], dev->protocolRegistersAddress, op->resource[1].end - op->resource[1].start + 1);
#endif
err_unmap1:
	of_iounmap(&op->resource[0], dev->regs, op->resource[0].end - op->resource[0].start + 1);

err_mem_free:
	kfree(dev);

	num_mpk = num_mpk - 1;

	return -EFAULT;
}

static const struct of_device_id mpk_match[] = {
	{
#if IS_ENABLED(CONFIG_PCI2SBUS) || defined(CONFIG_E90_FASTBOOT)
		.name = "mpk",
#else
		.name = "MCST,mpk",
#endif
	},
	{},
};

MODULE_DEVICE_TABLE(of, mpk_match);

static struct of_platform_driver mpk_driver = {
	.name			= "MCST,mpk",
	.match_table		= mpk_match,
	.probe			= mpk_probe,
	.remove			= mpk_remove,
};

static int
__init scc_init(void)
{
	int inst, chan;
	int err;
	num_mpk = 0;

	struct device_node *dp;

	mpk_sysctl_register();

	for_each_node_by_name(dp, MPPK_PROM_NAME) {

		if ( proto < 8 && proto > 0 ) {
			new_sbus_irq = proto;
			proto = RS422MODULE_PARAM_VALUE;
			printk("mpk: sbus irq is set to %d\n", new_sbus_irq);
		} else if ( proto != RS422MODULE_PARAM_VALUE && proto != RS485MODULE_PARAM_VALUE ) {
			printk("<1>mpk: You must set proto parameter. "
				"Available values are 422 (for RS422) and 485 (for RS485). "
				"Example: insmod mpk.o proto=422\n");
				return -EINVAL;
		}
	}

	err = of_register_driver(&mpk_driver, &of_platform_bus_type);
	if ( err ) {
		mpk_sysctl_unregister();
		return err;
	}

	if ( num_mpk == 0 ) {
		printk(KERN_INFO "MPK_INIT: Found %d MPK instances\n", num_mpk);
		return -ENODEV;
	}

	scc_reg.nr = NUM_CHANNELS * num_mpk;

	err = uart_register_driver(&scc_reg);
	if ( err )
		return err;

	for ( inst = 0; inst < num_mpk; inst++ ) {
		for ( chan = 0; chan < NUM_CHANNELS; chan++ ) {
			struct uart_sunzilog_port *up = &scc_dev[inst]->port[chan];
			up->port.line = up->port.line + inst * NUM_CHANNELS;
			up->op = scc_dev[inst]->op;

			if ( uart_add_one_port(&scc_reg, &up->port) ) {
				printk(KERN_ERR "%s: Failed to add %d port\n", __func__, chan);
			}
		}
	}

	scc_reg.tty_driver->init_termios.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE);

	printk(KERN_INFO "MPK_INIT: Found %d MPK instances\n", num_mpk);
	printk(KERN_INFO "%s driver is installed\n", MPPK_PROM_NAME);

	return 0;
}

static void __exit scc_exit(void)
{
	int inst, chan;

	for ( inst = 0; inst < num_mpk; inst++ ) {
		for ( chan = 0; chan < NUM_CHANNELS; chan++ ) {
			struct uart_sunzilog_port *up = &scc_dev[inst]->port[chan];

			uart_remove_one_port(&scc_reg, &up->port);
#if IS_ENABLED(CONFIG_MPVK)
			kfree(up->xrcv.buf);
#endif
		}
	}

	of_unregister_driver(&mpk_driver);

	uart_unregister_driver(&scc_reg);

	mpk_sysctl_unregister();

	printk(KERN_INFO "%s driver is unloaded\n", MPPK_PROM_NAME);
}

module_init(scc_init);
module_exit(scc_exit);

MODULE_DESCRIPTION("MCST MPPK driver");
MODULE_LICENSE("GPL");

