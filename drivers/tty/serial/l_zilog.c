#if defined(CONFIG_SERIAL_L_ZILOG_CONSOLE) && defined(CONFIG_MAGIC_SYSRQ)
#define SUPPORT_SYSRQ
#endif
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/console.h>
#include <linux/sysrq.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/serial_reg.h>
#include <linux/serial_core.h>
#include <linux/serial.h>
#include <linux/pci.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/console.h>
#include <asm/mpspec.h>

#define	NUM_L_ZILOGS	MAX_NUMIOHUBS
#define UART_PORTS_NR	2

#define PMZ_DEBUG_ON	0
#define pmz_debug if (PMZ_DEBUG_ON) printk

#undef  DEBUG_ZILOG_MODE
#undef  DebugZ
#define	DEBUG_ZILOG_MODE	0	/* Zilog serial console debug */
#define	DebugZ			if (DEBUG_ZILOG_MODE) printk

#undef  DEBUG_IO_ZILOG_MODE
#undef  DebugIO
#define	DEBUG_IO_ZILOG_MODE	0	/* Zilog read/write debug */
#define	DebugIO			if (DEBUG_IO_ZILOG_MODE) printk

#ifdef CONFIG_SERIAL_85c30_SHARE_IRQ
#define SERIAL85c30_SHARE_IRQS 1
#else
#define SERIAL85c30_SHARE_IRQS 1
#endif

#include "l_zilog.h"

#if defined(CONFIG_E2K) || defined(CONFIG_E90S)
/*
 * 3.11 IZM 11 -  RS232_ParPort controller (rs232)
 * 
 * При получении подряд двух запросов чтения регистров происходит потеря второго запроса. Такая же ситуация возможна при 
 * поступлении подряд запроса чтения и запроса записи без ожидания ответа чтения. 
 * 
 * Обходится программно, возможно исправление в металлах.
 * 
 * Актульна для  итерации 1  "Повозки"
 * Сделано исправление в металлах начиная с итерации 2.
 *
 *  1.Определение номера итерации:
 * Номер итерации определяется по полю REV_ID I2C_SPI :
 * 8'h01/8'h00 - итерация 1 ASIC/FPGA
 * 8'h03/8'h02 - итерация 2 ASIC/FPGA
 * 8'h05/8'h04 - итерация 3 ASIC/FPGA
 */

static inline int l_has_zilog_povozka_bug(void)
{
	if(IOHUB_revision < 2)
		return 1;
	return 0;
}
#else	/* CONFIG_E2K || CONFIG_E90S */
#define	l_has_zilog_povozka_bug() 	0
#endif	/* CONFIG_E2K || CONFIG_E90S */

static inline u8 read_zsreg(struct uart_zilog_port *port, u8 reg)
{
	u8 reg_val;
	struct uart_zilog_port *uap_a = zilog_get_port_A(port);
	unsigned long flags;
	raw_spin_lock_irqsave(&uap_a->wr0_reg_lock, flags);
	if (reg != 0)
		writeb(reg, port->control_reg);
	wmb();
	reg_val = readb(port->control_reg);
	rmb();
	raw_spin_unlock_irqrestore(&uap_a->wr0_reg_lock, flags);
	DebugIO("read_zsreg() reg %d value 0x%x\n", reg, reg_val);
	return (reg_val);
}

static inline void write_zsreg(struct uart_zilog_port *port, u8 reg, u8 value)
{
	struct uart_zilog_port *uap_a = zilog_get_port_A(port);
	unsigned long flags;
	raw_spin_lock_irqsave(&uap_a->wr0_reg_lock, flags);
	if (reg != 0)
		writeb(reg, port->control_reg);
	writeb(value, port->control_reg);
	wmb();
	raw_spin_unlock_irqrestore(&uap_a->wr0_reg_lock, flags);
	DebugIO("write_zsreg() reg %d value 0x%x\n", reg, value);
}

static inline u8 read_zsdata(struct uart_zilog_port *port)
{
	u8 data_val;
	struct uart_zilog_port *uap_a = zilog_get_port_A(port);
	unsigned long flags = 0;
	int bug = l_has_zilog_povozka_bug();
	if(bug)
		raw_spin_lock_irqsave(&uap_a->wr0_reg_lock, flags);
	data_val = readb(port->data_reg);
	rmb();
	if(bug)
		raw_spin_unlock_irqrestore(&uap_a->wr0_reg_lock, flags);
	return (data_val);
}

static inline void write_zsdata(struct uart_zilog_port *port, u8 data)
{
	struct uart_zilog_port *uap_a = zilog_get_port_A(port);
	unsigned long flags = 0;
	int bug = l_has_zilog_povozka_bug();
	if(bug)
		raw_spin_lock_irqsave(&uap_a->wr0_reg_lock, flags);
	writeb(data, port->data_reg);
	wmb();
	if(bug)
		raw_spin_unlock_irqrestore(&uap_a->wr0_reg_lock, flags);
}

static inline void zssync(struct uart_zilog_port *port)
{
	struct uart_zilog_port *uap_a = zilog_get_port_A(port);
	unsigned long flags = 0;
	int bug = l_has_zilog_povozka_bug();
	if(bug)
		raw_spin_lock_irqsave(&uap_a->wr0_reg_lock, flags);
	(void)readb(port->control_reg);
	rmb();
	if(bug)
		raw_spin_unlock_irqrestore(&uap_a->wr0_reg_lock, flags);
}
/*
 * Configuration:
 *   share_irqs - whether we pass SA_SHIRQ to request_irq().  This option
 *                is unsafe when used on edge-triggered interrupts.
 */

static unsigned int share_irqs = SERIAL_ZILOG_SHARE_IRQS;


static int l_enable_sync_irq = 0;
MODULE_PARM_DESC(en_sync, "enable SYNC (DSR) IRQ");
module_param_named(en_sync, l_enable_sync_irq, int, 0400);

static struct uart_zilog_port serial_zilog_ports[NUM_L_ZILOGS * UART_PORTS_NR];
static int l_zilogs_count = 0;

/*
 * Peek the status register, lock not held by caller
 */
static inline u8 zilog_peek_status(struct uart_zilog_port *uap)
{
	unsigned long flags;
	u8 status;
	
	spin_lock_irqsave(&uap->port.lock, flags);
	status = read_zsreg(uap, R0);
	spin_unlock_irqrestore(&uap->port.lock, flags);

	return status;
}

/* 
 * Check if transmitter is empty
 * The port lock is not held.
 */
static unsigned int zilog_tx_empty(struct uart_port *port)
{
	unsigned char status;

	status = zilog_peek_status(to_zilog(port));
	if (status & Tx_BUF_EMP)
		return TIOCSER_TEMT;
	return 0;
}

/* 
 * Set Modem Control (RTS & DTR) bits
 * The port lock is held and interrupts are disabled.
 * Note: Shall we really filter out RTS on external ports or
 * should that be dealt at higher level only ?
 */
static void zilog_set_mctrl(struct uart_port *port, unsigned int mctrl)
{
	struct uart_zilog_port *uap = to_zilog(port);
	unsigned char set_bits, clear_bits;

	pmz_debug("zilog_set_mctrl start\n");
	/* Do nothing for irda for now... */
	if (ZS_IS_IRDA(uap))
		return;
	/* We get called during boot with a port not up yet */
	if (!(ZS_IS_OPEN(uap) || ZS_IS_CONS(uap)))
		return;

	set_bits = clear_bits = 0;

	if (ZS_IS_INTMODEM(uap)) {
		if (mctrl & TIOCM_RTS)
			set_bits |= RTS;
		else
			clear_bits |= RTS;
	}
	if (mctrl & TIOCM_DTR)
		set_bits |= DTR;
	else
		clear_bits |= DTR;

	/* NOTE: Not subject to 'transmitter active' rule.  */ 
	uap->curregs[R5] |= set_bits;
	uap->curregs[R5] &= ~clear_bits;
	write_zsreg(uap, R5, uap->curregs[R5]);
	pmz_debug("zilog_set_mctrl: set bits: %x, clear bits: %x -> %x\n",
		  set_bits, clear_bits, uap->curregs[R5]);
	zssync(uap);
}

/* 
 * Get Modem Control bits (only the input ones, the core will
 * or that with a cached value of the control ones)
 * The port lock is held and interrupts are disabled.
 */
static unsigned int zilog_get_mctrl(struct uart_port *port)
{
	struct uart_zilog_port *uap = to_zilog(port);
	unsigned char status;
	unsigned int ret;

	status = read_zsreg(uap, R0);

	ret = 0;
	if (status & DCD)
		ret |= TIOCM_CAR;
	if (status & SYNC_HUNT)
		ret |= TIOCM_DSR;
	if (status & CTS)
		ret |= TIOCM_CTS;

	return ret;
}

/* 
 * Stop TX side. Dealt at next Tx interrupt,
 * though for DMA, we will have to do a bit more.
 * The port lock is held and interrupts are disabled.
 */
static void zilog_stop_tx(struct uart_port *port)
{
	to_zilog(port)->flags |= PMACZILOG_FLAG_TX_STOPPED;
}

/* 
 * Kick the Tx side.
 * The port lock is held and interrupts are disabled.
 */
static void zilog_start_tx(struct uart_port *port)
{
	struct uart_zilog_port *uap = to_zilog(port);
	unsigned char status;

	pmz_debug("zilog: start_tx()\n");

#ifdef CONFIG_SERIAL_AM85C30_CONSOLE
# define DUMP_PRINTK_BUF_SIZE 256
	if (use_boot_printk_all || (use_boot_printk && !console_initialized)) {
		struct circ_buf *xmit = &port->state->xmit;
		char buf[DUMP_PRINTK_BUF_SIZE];
		int n = 0;

		if (port->x_char) {
			buf[n++] = port->x_char;
			port->x_char = 0;
			port->icount.tx++;
		}

		while (!uart_circ_empty(xmit)) {
			do {
				buf[n++] = xmit->buf[xmit->tail];
				xmit->tail = (xmit->tail + 1) &
						(UART_XMIT_SIZE - 1);
				port->icount.tx++;
			} while (n < DUMP_PRINTK_BUF_SIZE &&
					!uart_circ_empty(xmit));

			dump_putns(buf, n);
			n = 0;
		}

		return;
	}
#endif

	uap->flags |= PMACZILOG_FLAG_TX_ACTIVE;
	uap->flags &= ~PMACZILOG_FLAG_TX_STOPPED;

	status = read_zsreg(uap, R0);

	/* TX busy?  Just wait for the TX done interrupt.  */
	if (!(status & Tx_BUF_EMP))
		return;

	/* Send the first character to jump-start the TX done
	 * IRQ sending engine.
	 */
	if (port->x_char) {
		write_zsdata(uap, port->x_char);
		zssync(uap);
		port->icount.tx++;
		port->x_char = 0;
	} else {
		struct circ_buf *xmit = &port->state->xmit;

		write_zsdata(uap, xmit->buf[xmit->tail]);
		zssync(uap);
		xmit->tail = (xmit->tail + 1) & (UART_XMIT_SIZE - 1);
		port->icount.tx++;

		if (uart_circ_chars_pending(xmit) < WAKEUP_CHARS)
			uart_write_wakeup(&uap->port);
	}
	pmz_debug("pmz: start_tx() done.\n");
}

/* 
 * Load all registers to reprogram the port
 * This function must only be called when the TX is not busy.  The UART
 * port lock must be held and local interrupts disabled.
 */
static void zilog_load_zsregs(struct uart_zilog_port *uap, u8 *regs)
{
	int i;

	/* Let pending transmits finish.  */
	for (i = 0; i < 1000; i++) {
		unsigned char stat = read_zsreg(uap, R1);
		if (stat & ALL_SNT)
			break;
		udelay(100);
	}

	ZS_CLEARERR(uap);
	zssync(uap);
	ZS_CLEARFIFO(uap);
	zssync(uap);
	ZS_CLEARERR(uap);

	/* Disable all interrupts.  */
	write_zsreg(uap, R1,
		    regs[R1] & ~(RxINT_MASK | TxINT_ENAB | EXT_INT_ENAB));

	/* Set parity, sync config, stop bits, and clock divisor.  */
	write_zsreg(uap, R4, regs[R4]);

	/* Set misc. TX/RX control bits.  */
	write_zsreg(uap, R10, regs[R10]);

	/* Set TX/RX controls sans the enable bits.  */
       	write_zsreg(uap, R3, regs[R3] & ~RxENABLE);
       	write_zsreg(uap, R5, regs[R5] & ~TxENABLE);

	/* now set R7 "prime" on ESCC */
	write_zsreg(uap, R15, regs[R15] | EN85C30);
	write_zsreg(uap, R7, regs[R7P]);

	/* make sure we use R7 "non-prime" on ESCC */
	write_zsreg(uap, R15, regs[R15] & ~EN85C30);

	/* Synchronous mode config.  */
	write_zsreg(uap, R6, regs[R6]);
	write_zsreg(uap, R7, regs[R7]);

	/* Disable baud generator.  */
	write_zsreg(uap, R14, regs[R14] & ~BRENAB);

	/* Clock mode control.  */
	write_zsreg(uap, R11, regs[R11]);

	/* Lower and upper byte of baud rate generator divisor.  */
	write_zsreg(uap, R12, regs[R12]);
	write_zsreg(uap, R13, regs[R13]);
	
	/* Now rewrite R14, with BRENAB (if set).  */
	write_zsreg(uap, R14, regs[R14]);

	/* Reset external status interrupts.  */
	write_zsreg(uap, R0, RES_EXT_INT);
	write_zsreg(uap, R0, RES_EXT_INT);

	/* Rewrite R3/R5, this time without enables masked.  */
	write_zsreg(uap, R3, regs[R3]);
	write_zsreg(uap, R5, regs[R5]);

	/* Rewrite R1, this time without IRQ enabled masked.  */
	write_zsreg(uap, R1, regs[R1]);

	/* Enable interrupts */
	write_zsreg(uap, R9, regs[R9]);
}

/* 
 * We do like sunzilog to avoid disrupting pending Tx
 * Reprogram the Zilog channel HW registers with the copies found in the
 * software state struct.  If the transmitter is busy, we defer this update
 * until the next TX complete interrupt.  Else, we do it right now.
 *
 * The UART port lock must be held and local interrupts disabled.
 */
static void zilog_maybe_update_regs(struct uart_zilog_port *uap)
{
       	if (!ZS_REGS_HELD(uap)) {
		if (ZS_TX_ACTIVE(uap)) {
			uap->flags |= PMACZILOG_FLAG_REGS_HELD;
		} else {
			pmz_debug("zilog: maybe_update_regs: updating\n");
			zilog_load_zsregs(uap, uap->curregs);
		}
	}
}

/* 
 * Stop Rx side, basically disable emitting of
 * Rx interrupts on the port. We don't disable the rx
 * side of the chip proper though
 * The port lock is held.
 */
static void zilog_stop_rx(struct uart_port *port)
{
	struct uart_zilog_port *uap = to_zilog(port);

	pmz_debug("pmz: stop_rx()()\n");

	/* Disable all RX interrupts.  */
	uap->curregs[R1] &= ~RxINT_MASK;
	zilog_maybe_update_regs(uap);

	pmz_debug("pmz: stop_rx() done.\n");
}

/* 
 * Enable modem status change interrupts
 * The port lock is held.
 */
static void zilog_enable_ms(struct uart_port *port)
{
	struct uart_zilog_port *uap = to_zilog(port);
	unsigned char new_reg;

	if (ZS_IS_IRDA(uap))
		return;
	new_reg = uap->curregs[R15] | (DCDIE | CTSIE);
	if (l_enable_sync_irq)
		new_reg |= SYNCIE;
	if (new_reg != uap->curregs[R15]) {
		uap->curregs[R15] = new_reg;

		/* NOTE: Not subject to 'transmitter active' rule.  */ 
		write_zsreg(uap, R15, uap->curregs[R15]);
	}
}

/* 
 * Control break state emission
 * The port lock is not held.
 */
static void zilog_break_ctl(struct uart_port *port, int break_state)
{
	struct uart_zilog_port *uap = to_zilog(port);
	unsigned char set_bits, clear_bits, new_reg;
	unsigned long flags;

	set_bits = clear_bits = 0;

	if (break_state)
		set_bits |= SND_BRK;
	else
		clear_bits |= SND_BRK;

	spin_lock_irqsave(&port->lock, flags);

	new_reg = (uap->curregs[R5] | set_bits) & ~clear_bits;
	if (new_reg != uap->curregs[R5]) {
		uap->curregs[R5] = new_reg;

		write_zsreg(uap, R5, uap->curregs[R5]);
	}

	spin_unlock_irqrestore(&port->lock, flags);
}

static bool zilog_receive_chars(struct uart_zilog_port *uap,
		unsigned long *flags)
{
	struct tty_port *port;
	unsigned char ch, r1, flag, error;
	int loops = 0;

	/* The interrupt can be enabled when the port isn't open, typically
	 * that happens when using one port is open and the other closed (stale
	 * interrupt) or when one port is used as a console.
	 */
	if (!ZS_IS_OPEN(uap)) {
		pmz_debug("pmz: draining input\n");
		/* Port is closed, drain input data */
		for (;;) {
			if ((++loops) > 1000)
				goto flood;
			(void)read_zsreg(uap, R1);
			write_zsreg(uap, R0, ERR_RES);
			(void)read_zsdata(uap);
			ch = read_zsreg(uap, R0);
			if (!(ch & Rx_CH_AV))
				break;
		}
		return false;
	}

	/* Sanity check, make sure the old bug is no longer happening */
	if (uap->port.state == NULL) {
		WARN_ON(1);
		(void)read_zsdata(uap);
		return false;
	}

	port = &uap->port.state->port;

	while (1) {
		error = 0;

		r1 = read_zsreg(uap, R1);
		ch = read_zsdata(uap);

		if (r1 & (PAR_ERR | Rx_OVR | CRC_ERR)) {
			write_zsreg(uap, R0, ERR_RES);
			zssync(uap);
		}

		ch &= uap->parity_mask;
		if (ch == 0 && uap->flags & PMACZILOG_FLAG_BREAK) {
			uap->flags &= ~PMACZILOG_FLAG_BREAK;
			r1 |= BRK_ABRT;
		}

#if defined(CONFIG_MAGIC_SYSRQ) && defined(CONFIG_SERIAL_CORE_CONSOLE)
#ifdef USE_CTRL_O_SYSRQ
		/* Handle the SysRq ^O Hack */
		if (ch == '\x0f') {
			uap->port.sysrq = jiffies + HZ*5;
			goto next_char;
		}
#endif /* USE_CTRL_O_SYSRQ */
		if (uap->port.sysrq) {
			int swallow;
			spin_unlock_irqrestore(&uap->port.lock, *flags);
			swallow = uart_handle_sysrq_char(&uap->port, ch);
			spin_lock_irqsave(&uap->port.lock, *flags);
			if (swallow)
				goto next_char;
 		}
#endif /* CONFIG_MAGIC_SYSRQ && CONFIG_SERIAL_CORE_CONSOLE */

		/* A real serial line, record the character and status.  */
		flag = TTY_NORMAL;
		uap->port.icount.rx++;

		if (r1 & (PAR_ERR | Rx_OVR | CRC_ERR | BRK_ABRT)) {
			error = 1;
			if (r1 & BRK_ABRT) {
				pmz_debug("pmz: got break !\n");
				r1 &= ~(PAR_ERR | CRC_ERR);
				uap->port.icount.brk++;
				if (uart_handle_break(&uap->port))
					goto next_char;
			}
			else if (r1 & PAR_ERR)
				uap->port.icount.parity++;
			else if (r1 & CRC_ERR)
				uap->port.icount.frame++;
			if (r1 & Rx_OVR)
				uap->port.icount.overrun++;
			r1 &= uap->port.read_status_mask;
			if (r1 & BRK_ABRT)
				flag = TTY_BREAK;
			else if (r1 & PAR_ERR)
				flag = TTY_PARITY;
			else if (r1 & CRC_ERR)
				flag = TTY_FRAME;
		}

		if (uap->port.ignore_status_mask == 0xff ||
		    (r1 & uap->port.ignore_status_mask) == 0) {
		    	tty_insert_flip_char(port, ch, flag);
		}
		if (r1 & Rx_OVR) {
			tty_insert_flip_char(port, 0, TTY_OVERRUN);
		}
next_char:
		/* We can get stuck in an infinite loop getting char 0 when the
		 * line is in a wrong HW state, we break that here.
		 * When that happens, I disable the receive side of the driver.
		 * Note that what I've been experiencing is a real irq loop where
		 * I'm getting flooded regardless of the actual port speed.
		 * Something stange is going on with the HW
		 */
		if ((++loops) > 1000)
			goto flood;
		ch = read_zsreg(uap, R0);
		if (!(ch & Rx_CH_AV))
			break;
	}

	return true;
 flood:
	uap->curregs[R1] &= ~(EXT_INT_ENAB | TxINT_ENAB | RxINT_MASK);
	write_zsreg(uap, R1, uap->curregs[R1]);
	zssync(uap);
	pmz_debug("pmz: rx irq flood !\n");
	return true;
}

static void zilog_status_handle(struct uart_zilog_port *uap)
{
	unsigned char status;

	status = read_zsreg(uap, R0);
	write_zsreg(uap, R0, RES_EXT_INT);
	zssync(uap);

	if (ZS_IS_OPEN(uap) && ZS_WANTS_MODEM_STATUS(uap)) {
		if (status & SYNC_HUNT)
			uap->port.icount.dsr++;

		/* The Zilog just gives us an interrupt when DCD/CTS/etc. change.
		 * But it does not tell us which bit has changed, we have to keep
		 * track of this ourselves.
		 */
		if ((status ^ uap->prev_status) & DCD)
			uart_handle_dcd_change(&uap->port,
					       (status & DCD));
		if ((status ^ uap->prev_status) & CTS)
			uart_handle_cts_change(&uap->port,
					       status & CTS);

		wake_up_interruptible(&uap->port.state->port.delta_msr_wait);
	}

	if (status & BRK_ABRT)
		uap->flags |= PMACZILOG_FLAG_BREAK;

	uap->prev_status = status;
}

static void zilog_transmit_chars(struct uart_zilog_port *uap)
{
	struct circ_buf *xmit;

	if (ZS_IS_CONS(uap)) {
		unsigned char status = read_zsreg(uap, R0);

		/* TX still busy?  Just wait for the next TX done interrupt.
		 *
		 * It can occur because of how we do serial console writes.  It would
		 * be nice to transmit console writes just like we normally would for
		 * a TTY line. (ie. buffered and TX interrupt driven).  That is not
		 * easy because console writes cannot sleep.  One solution might be
		 * to poll on enough port->xmit space becomming free.  -DaveM
		 */
		if (!(status & Tx_BUF_EMP))
			return;
	}

	uap->flags &= ~PMACZILOG_FLAG_TX_ACTIVE;

	if (ZS_REGS_HELD(uap)) {
		zilog_load_zsregs(uap, uap->curregs);
		uap->flags &= ~PMACZILOG_FLAG_REGS_HELD;
	}

	if (ZS_TX_STOPPED(uap)) {
		uap->flags &= ~PMACZILOG_FLAG_TX_STOPPED;
		goto ack_tx_int;
	}

	if (!ZS_IS_OPEN(uap))
		goto ack_tx_int;

	if (uap->port.x_char) {
		uap->flags |= PMACZILOG_FLAG_TX_ACTIVE;
		write_zsdata(uap, uap->port.x_char);
		zssync(uap);
		uap->port.icount.tx++;
		uap->port.x_char = 0;
		return;
	}

	if (uap->port.state == NULL)
		goto ack_tx_int;
	xmit = &uap->port.state->xmit;
	if (uart_circ_empty(xmit)) {
		uart_write_wakeup(&uap->port);
		goto ack_tx_int;
	}
	if (uart_tx_stopped(&uap->port))
		goto ack_tx_int;

	uap->flags |= PMACZILOG_FLAG_TX_ACTIVE;
	write_zsdata(uap, xmit->buf[xmit->tail]);
	zssync(uap);

	xmit->tail = (xmit->tail + 1) & (UART_XMIT_SIZE - 1);
	uap->port.icount.tx++;

	if (uart_circ_chars_pending(xmit) < WAKEUP_CHARS)
		uart_write_wakeup(&uap->port);

	return;

ack_tx_int:
	write_zsreg(uap, R0, RES_Tx_P);
	zssync(uap);
}

/* Hrm... we register that twice, fixme later.... */
static irqreturn_t zilog_interrupt(int irq, void *dev_id)
{
	unsigned long flags;
	struct uart_zilog_port *uap = dev_id;
	struct uart_zilog_port *uap_a;
	struct uart_zilog_port *uap_b;
	int rc = IRQ_NONE;
	bool push;
	u8 r3;

	uap_a = zilog_get_port_A(uap);
	uap_b = uap_a->mate;

	spin_lock_irqsave(&uap_a->port.lock, flags);
	r3 = read_zsreg(uap_a, R3);
again:
#ifdef DEBUG_HARD
	pmz_debug("irq, r3: %x\n", r3);
#endif
       	/* Channel A */
	push = false;
	if (r3 & (CHAEXT | CHATxIP | CHARxIP)) {
		/* Channel A */
		if (r3 & CHAEXT) {
			write_zsreg(uap_a, R0, RES_EXT_INT);
			zilog_status_handle(uap_a);
		}
		if (r3 & CHARxIP) {
			write_zsreg(uap_a, R0, RES_RxINT_FC);
			push = zilog_receive_chars(uap_a, &flags);
		}
		if (r3 & CHATxIP) {
			write_zsreg(uap_a, R0, RES_Tx_P);
			zilog_transmit_chars(uap_a);
		}
		write_zsreg(uap_a, R0, RES_H_IUS);
		zssync(uap_a);	
		rc = IRQ_HANDLED;	
	}
	spin_unlock_irqrestore(&uap_a->port.lock, flags);
	if (push)
		tty_flip_buffer_push(&uap_a->port.state->port);

	if (r3 & (CHBEXT | CHBTxIP | CHBRxIP)) {
		spin_lock_irqsave(&uap_b->port.lock, flags);
		/* Channel B */
		push = false;
		if (r3 & CHBEXT) {
			write_zsreg(uap_b, R0, RES_EXT_INT);
			zilog_status_handle(uap_b);
		}
		if (r3 & CHBRxIP) {
			write_zsreg(uap_b, R0, RES_RxINT_FC);
			push = zilog_receive_chars(uap_b, &flags);
		}
		if (r3 & CHBTxIP) {
			write_zsreg(uap_b, R0, RES_Tx_P);
			zilog_transmit_chars(uap_b);
		}
		write_zsreg(uap_b, R0, RES_H_IUS);
		zssync(uap_b);
		rc = IRQ_HANDLED;
		spin_unlock_irqrestore(&uap_b->port.lock, flags);
		if (push)
			tty_flip_buffer_push(&uap_b->port.state->port);
	}

	spin_lock_irqsave(&uap_a->port.lock, flags);
	r3 = read_zsreg(uap_a, R3);
	if ((r3 & (CHAEXT | CHATxIP | CHARxIP |
			CHBEXT | CHBTxIP | CHBRxIP))) {
		goto again;
	}
	spin_unlock_irqrestore(&uap_a->port.lock, flags);

#ifdef DEBUG_HARD
	pmz_debug("irq done.\n");
#endif
	return rc;
}

#if 0
/*
 * FixZeroBug....Works around a bug in the SCC receving channel.
 * Inspired from Darwin code, 15 Sept. 2000  -DanM
 *
 * The following sequence prevents a problem that is seen with O'Hare ASICs
 * (most versions -- also with some Heathrow and Hydra ASICs) where a zero
 * at the input to the receiver becomes 'stuck' and locks up the receiver.
 * This problem can occur as a result of a zero bit at the receiver input
 * coincident with any of the following events:
 *
 *	The SCC is initialized (hardware or software).
 *	A framing error is detected.
 *	The clocking option changes from synchronous or X1 asynchronous
 *		clocking to X16, X32, or X64 asynchronous clocking.
 *	The decoding mode is changed among NRZ, NRZI, FM0, or FM1.
 *
 * This workaround attempts to recover from the lockup condition by placing
 * the SCC in synchronous loopback mode with a fast clock before programming
 * any of the asynchronous modes.
 */
static void zilog_fix_zero_bug_scc(struct uart_zilog_port *uap)
{
	write_zsreg(uap, 9, ZS_IS_CHANNEL_A(uap) ? CHRA : CHRB);
	zssync(uap);
	udelay(10);
	write_zsreg(uap, 9, (ZS_IS_CHANNEL_A(uap) ? CHRA : CHRB) | NV);
	zssync(uap);

	write_zsreg(uap, 4, X1CLK | MONSYNC);
	write_zsreg(uap, 3, Rx8);
	write_zsreg(uap, 5, Tx8 | RTS);
	write_zsreg(uap, 9, NV);	/* Didn't we already do this? */
	write_zsreg(uap, 11, RCBR | TCBR);
	write_zsreg(uap, 12, 0);
	write_zsreg(uap, 13, 0);
	write_zsreg(uap, 14, (LOOPBAK | BRSRC));
	write_zsreg(uap, 14, (LOOPBAK | BRSRC | BRENAB));
	write_zsreg(uap, 3, Rx8 | RxENABLE);
	write_zsreg(uap, 0, RES_EXT_INT);
	write_zsreg(uap, 0, RES_EXT_INT);
	write_zsreg(uap, 0, RES_EXT_INT);	/* to kill some time */

	/* The channel should be OK now, but it is probably receiving
	 * loopback garbage.
	 * Switch to asynchronous mode, disable the receiver,
	 * and discard everything in the receive buffer.
	 */
	write_zsreg(uap, 9, NV);
	write_zsreg(uap, 4, X16CLK | SB_MASK);
	write_zsreg(uap, 3, Rx8);

	while (read_zsreg(uap, 0) & Rx_CH_AV) {
		(void)read_zsreg(uap, 8);
		write_zsreg(uap, 0, RES_EXT_INT);
		write_zsreg(uap, 0, ERR_RES);
	}
}
#endif
/*
 * Real startup routine, powers up the hardware and sets up
 * the SCC. Returns a delay in ms where you need to wait before
 * actually using the port, this is typically the internal modem
 * powerup delay. This routine expect the lock to be taken.
 */
static int __zilog_startup(struct uart_zilog_port *uap)
{
	int pwr_delay = 0;

	DebugZ("__zilog_startup() started on port %s\n",
		ZS_IS_CHANNEL_A(uap) ? "A" : "B");
	memset(&uap->curregs, 0, sizeof(uap->curregs));

	/* Power up the SCC & underlying hardware (modem/irda) */
//	pwr_delay = pmz_set_scc_power(uap, 1);

	/* Nice buggy HW ... */
//	zilog_fix_zero_bug_scc(uap);

	/* Reset the channel */
	uap->curregs[R9] = 0;
	write_zsreg(uap, 9, ZS_IS_CHANNEL_A(uap) ? CHRA : CHRB);
	zssync(uap);
	udelay(10);
	write_zsreg(uap, 9, 0);
	zssync(uap);

	/* Clear the interrupt registers */
	write_zsreg(uap, R1, 0);
	write_zsreg(uap, R0, ERR_RES);
	write_zsreg(uap, R0, ERR_RES);
	write_zsreg(uap, R0, RES_H_IUS);
	write_zsreg(uap, R0, RES_H_IUS);

	/* Setup some valid baud rate */
	uap->curregs[R4] = X16CLK | SB1;
	uap->curregs[R3] = Rx8;
	uap->curregs[R5] = Tx8 | RTS;
	if (!ZS_IS_IRDA(uap))
		uap->curregs[R5] |= DTR;
	uap->curregs[R12] = 0;
	uap->curregs[R13] = 0;
	uap->curregs[R14] = BRENAB;

	/* Clear handshaking, enable BREAK interrupts */
	uap->curregs[R15] = BRKIE;

	/* Master interrupt enable */
	uap->curregs[R9] |= NV | MIE;

	zilog_load_zsregs(uap, uap->curregs);

	/* Enable receiver and transmitter.  */
	write_zsreg(uap, R3, uap->curregs[R3] |= RxENABLE);
	write_zsreg(uap, R5, uap->curregs[R5] |= TxENABLE);

	/* Remember status for DCD/CTS changes */
	uap->prev_status = read_zsreg(uap, R0);


	return pwr_delay;
}

static void zilog_irda_reset(struct uart_zilog_port *uap)
{
	uap->curregs[R5] |= DTR;
	write_zsreg(uap, R5, uap->curregs[R5]);
	zssync(uap);
	mdelay(110);
	uap->curregs[R5] &= ~DTR;
	write_zsreg(uap, R5, uap->curregs[R5]);
	zssync(uap);
	mdelay(10);
}

/*
 * This is the "normal" startup routine, using the above one
 * wrapped with the lock and doing a schedule delay
 */
static int zilog_startup(struct uart_port *port)
{
	struct uart_zilog_port *uap = to_zilog(port);
	unsigned long flags;
	unsigned long irq_flags = uap->port.flags & UPF_SHARE_IRQ ? IRQF_SHARED : 0;
	irq_flags |= IRQF_DISABLED;

	pmz_debug("zilog: startup()\n");

	uap->flags |= PMACZILOG_FLAG_IS_OPEN;

	/* A console is never powered down. Else, power up and
	 * initialize the chip
	 */
	if (!ZS_IS_CONS(uap)) {
		spin_lock_irqsave(&port->lock, flags);
		__zilog_startup(uap);
		spin_unlock_irqrestore(&port->lock, flags);
	}

	/* IrDA reset is done now */
	if (ZS_IS_IRDA(uap))
		zilog_irda_reset(uap);

	/* Enable interrupts emission from the chip */
	spin_lock_irqsave(&port->lock, flags);
	uap->curregs[R1] |= INT_ALL_Rx | TxINT_ENAB;
	if (!ZS_IS_EXTCLK(uap))
		uap->curregs[R1] |= EXT_INT_ENAB;
	write_zsreg(uap, R1, uap->curregs[R1]);
       	spin_unlock_irqrestore(&port->lock, flags);

	pmz_debug("zilog: startup() done.\n");

	return 0;
}

static void zilog_shutdown(struct uart_port *port)
{
	struct uart_zilog_port *uap = to_zilog(port);
	unsigned long flags;
	unsigned char r3;
	int i;

	pmz_debug("zilog: shutdown()\n");

	spin_lock_irqsave(&port->lock, flags);

	uap->flags &= ~PMACZILOG_FLAG_IS_OPEN;

	/* Disable interrupts */
	uap->curregs[R1] &= ~(EXT_INT_ENAB | TxINT_ENAB | RxINT_MASK);
	/* reset tx interrupt pending */
	write_zsreg(uap, R1, uap->curregs[R1]);
	write_zsreg(uap, R0, RES_Tx_P);

	for (i = 0; i < 1000; i++) {
		int j;
		r3 = read_zsreg(uap, R3);
		r3 &= ZS_IS_CHANNEL_A(uap) ? CHARxIP : CHBRxIP;
		if (r3 == 0)
			break;
		for (j = 0; j < 1000; j++) {
			unsigned char ch;
			(void)read_zsreg(uap, R1);
			write_zsreg(uap, R0, ERR_RES);
			(void)read_zsdata(uap);
			ch = read_zsreg(uap, R0);
			if (!(ch & Rx_CH_AV))
				break;
		}
		/* reset rx interrupt pending */
		write_zsreg(uap, R1, uap->curregs[R1] | INT_ALL_Rx);
		write_zsreg(uap, R0, RES_RxINT_FC);
		write_zsreg(uap, R1, uap->curregs[R1]);

		if (j == 1000)
			break;
	}

	if (ZS_IS_CONS(uap)) {
		spin_unlock_irqrestore(&port->lock, flags);
		return;
	}

	/* Disable receiver and transmitter.  */
	uap->curregs[R3] &= ~RxENABLE;
	uap->curregs[R5] &= ~TxENABLE;

	/* Disable all interrupts and BRK assertion.  */
	uap->curregs[R5] &= ~SND_BRK;
	zilog_maybe_update_regs(uap);

	/* Shut the chip down */
//	pmz_set_scc_power(uap, 0);

	spin_unlock_irqrestore(&port->lock, flags);

	pmz_debug("zilog: shutdown() done.\n");
}

/* Shared by TTY driver and serial console setup.  The port lock is held
 * and local interrupts are disabled.
 */
static void zilog_convert_to_zs(struct uart_zilog_port *uap, unsigned int cflag,
			      unsigned int iflag, unsigned long baud)
{
	int brg;


	DebugZ("zilog_convert_to_zs() started on port %s, baud %ld\n",
		ZS_IS_CHANNEL_A(uap) ? "A" : "B", baud);
	/* Switch to external clocking for IrDA high clock rates. That
	 * code could be re-used for Midi interfaces with different
	 * multipliers
	 */
	if (baud >= 115200 && ZS_IS_IRDA(uap)) {
		uap->curregs[R4] = X1CLK;
		uap->curregs[R11] = RCTRxCP | TCTRxCP;
		uap->curregs[R14] = 0; /* BRG off */
		uap->curregs[R12] = 0;
		uap->curregs[R13] = 0;
		uap->flags |= PMACZILOG_FLAG_IS_EXTCLK;
	} else {
		switch (baud) {
		case 115200:	/* 115200 */
			uap->curregs[R4] = X16CLK;
			uap->curregs[R11] = TCBR | RCBR;
			uap->curregs[R7] = xNMODEENABLE;
			uap->curregs[R6] = xBRG115200;
			uap->curregs[R12] = 0;
			uap->curregs[R13] = 0;
			uap->curregs[R14] = BRENAB | BRSRC;
			break;
		default:
			if (baud > 115200) {
				printk("Elbrus Zilog console : baud rate %ld "
					"is not implemented\n", baud);
				baud = 76800;
			}
			uap->curregs[R4] = X16CLK;
			uap->curregs[R11] = TCBR | RCBR;
			brg = BPS_TO_BRG(baud, ZS_CLOCK, 16);
			uap->curregs[R7] = 0;
			uap->curregs[R6] = 0;
			uap->curregs[R12] = (brg & 255);
			uap->curregs[R13] = ((brg >> 8) & 255);
			uap->curregs[R14] = BRENAB | BRSRC;
		}
		uap->flags &= ~PMACZILOG_FLAG_IS_EXTCLK;
	}

	/* Character size, stop bits, and parity. */
	uap->curregs[3] &= ~RxN_MASK;
	uap->curregs[5] &= ~TxN_MASK;

	switch (cflag & CSIZE) {
	case CS5:
		uap->curregs[3] |= Rx5;
		uap->curregs[5] |= Tx5;
		uap->parity_mask = 0x1f;
		break;
	case CS6:
		uap->curregs[3] |= Rx6;
		uap->curregs[5] |= Tx6;
		uap->parity_mask = 0x3f;
		break;
	case CS7:
		uap->curregs[3] |= Rx7;
		uap->curregs[5] |= Tx7;
		uap->parity_mask = 0x7f;
		break;
	case CS8:
	default:
		uap->curregs[3] |= Rx8;
		uap->curregs[5] |= Tx8;
		uap->parity_mask = 0xff;
		break;
	};
	uap->curregs[4] &= ~(SB_MASK);
	if (cflag & CSTOPB)
		uap->curregs[4] |= SB2;
	else
		uap->curregs[4] |= SB1;
	if (cflag & PARENB)
		uap->curregs[4] |= PAR_ENAB;
	else
		uap->curregs[4] &= ~PAR_ENAB;
	if (!(cflag & PARODD))
		uap->curregs[4] |= PAR_EVEN;
	else
		uap->curregs[4] &= ~PAR_EVEN;

	uap->port.read_status_mask = Rx_OVR;
	if (iflag & INPCK)
		uap->port.read_status_mask |= CRC_ERR | PAR_ERR;
	if (iflag & (BRKINT | PARMRK))
		uap->port.read_status_mask |= BRK_ABRT;

	uap->port.ignore_status_mask = 0;
	if (iflag & IGNPAR)
		uap->port.ignore_status_mask |= CRC_ERR | PAR_ERR;
	if (iflag & IGNBRK) {
		uap->port.ignore_status_mask |= BRK_ABRT;
		if (iflag & IGNPAR)
			uap->port.ignore_status_mask |= Rx_OVR;
	}

	if ((cflag & CREAD) == 0)
		uap->port.ignore_status_mask = 0xff;
}


/*
 * Set the irda codec on the imac to the specified baud rate.
 */
static void zilog_irda_setup(struct uart_zilog_port *uap, unsigned long *baud)
{
	u8 cmdbyte;
	int t, version;

	switch (*baud) {
	/* SIR modes */
	case 2400:
		cmdbyte = 0x53;
		break;
	case 4800:
		cmdbyte = 0x52;
		break;
	case 9600:
		cmdbyte = 0x51;
		break;
	case 19200:
		cmdbyte = 0x50;
		break;
	case 38400:
		cmdbyte = 0x4f;
		break;
	case 57600:
		cmdbyte = 0x4e;
		break;
	case 115200:
		cmdbyte = 0x4d;
		break;
	/* The FIR modes aren't really supported at this point, how
	 * do we select the speed ? via the FCR on KeyLargo ?
	 */
	case 1152000:
		cmdbyte = 0;
		break;
	case 4000000:
		cmdbyte = 0;
		break;
	default: /* 9600 */
		cmdbyte = 0x51;
		*baud = 9600;
		break;
	}

	/* Wait for transmitter to drain */
	t = 10000;
	while ((read_zsreg(uap, R0) & Tx_BUF_EMP) == 0
	       || (read_zsreg(uap, R1) & ALL_SNT) == 0) {
		if (--t <= 0) {
			printk("transmitter didn't drain\n");
			return;
		}
		udelay(10);
	}

	/* Drain the receiver too */
	t = 100;
	(void)read_zsdata(uap);
	(void)read_zsdata(uap);
	(void)read_zsdata(uap);
	mdelay(10);
	while (read_zsreg(uap, R0) & Rx_CH_AV) {
		read_zsdata(uap);
		mdelay(10);
		if (--t <= 0) {
			printk("receiver didn't drain\n");
			return;
		}
	}

	/* Switch to command mode */
	uap->curregs[R5] |= DTR;
	write_zsreg(uap, R5, uap->curregs[R5]);
	zssync(uap);
       	mdelay(1);

	/* Switch SCC to 19200 */
	zilog_convert_to_zs(uap, CS8, 0, 19200);		
	zilog_load_zsregs(uap, uap->curregs);
       	mdelay(1);

	/* Write get_version command byte */
	write_zsdata(uap, 1);
	t = 5000;
	while ((read_zsreg(uap, R0) & Rx_CH_AV) == 0) {
		if (--t <= 0) {
			printk("irda_setup timed out on get_version byte\n");
			goto out;
		}
		udelay(10);
	}
	version = read_zsdata(uap);

	if (version < 4) {
		printk("IrDA: dongle version %d not supported\n", version);
		goto out;
	}

	/* Send speed mode */
	write_zsdata(uap, cmdbyte);
	t = 5000;
	while ((read_zsreg(uap, R0) & Rx_CH_AV) == 0) {
		if (--t <= 0) {
			printk("irda_setup timed out on speed mode byte\n");
			goto out;
		}
		udelay(10);
	}
	t = read_zsdata(uap);
	if (t != cmdbyte)
		printk("irda_setup speed mode byte = %x (%x)\n", t, cmdbyte);

	printk("IrDA setup for %ld bps, dongle version: %d\n", *baud, version);

	(void)read_zsdata(uap);
	(void)read_zsdata(uap);
	(void)read_zsdata(uap);

 out:
	/* Switch back to data mode */
	uap->curregs[R5] &= ~DTR;
	write_zsreg(uap, R5, uap->curregs[R5]);
	zssync(uap);

	(void)read_zsdata(uap);
	(void)read_zsdata(uap);
	(void)read_zsdata(uap);
}


static void __zilog_set_termios(struct uart_port *port, struct ktermios *termios,
			      struct ktermios *old)
{
	struct uart_zilog_port *uap = to_zilog(port);
	unsigned long baud;

	memcpy(&uap->termios_cache, termios, sizeof(struct termios));

	/* XXX Check which revs of machines actually allow 1 and 4Mb speeds
	 * on the IR dongle. Note that the IRTTY driver currently doesn't know
	 * about the FIR mode and high speed modes. So these are unused. For
	 * implementing proper support for these, we should probably add some
	 * DMA as well, at least on the Rx side, which isn't a simple thing
	 * at this point.
	 */
	if (ZS_IS_IRDA(uap)) {
		/* Calc baud rate */
		baud = uart_get_baud_rate(port, termios, old, 1200, 4000000);
		pmz_debug("zilog: switch IRDA to %ld bauds\n", baud);
		/* Cet the irda codec to the right rate */
		zilog_irda_setup(uap, &baud);
		/* Set final baud rate */
		zilog_convert_to_zs(uap, termios->c_cflag, termios->c_iflag, baud);
		zilog_load_zsregs(uap, uap->curregs);
		zssync(uap);
	} else {
		baud = uart_get_baud_rate(port, termios, old, 1200, 115200);
		zilog_convert_to_zs(uap, termios->c_cflag, termios->c_iflag, baud);
		/* Make sure modem status interrupts are correctly configured */
		if (UART_ENABLE_MS(&uap->port, termios->c_cflag)) {
			uap->curregs[R15] |= DCDIE | CTSIE;
			if (l_enable_sync_irq)
				uap->curregs[R15] |= SYNCIE;
			uap->flags |= PMACZILOG_FLAG_MODEM_STATUS;
		} else {
			uap->curregs[R15] &= ~(DCDIE | SYNCIE | CTSIE);
			uap->flags &= ~PMACZILOG_FLAG_MODEM_STATUS;
		}

		/* Load registers to the chip */
		zilog_maybe_update_regs(uap);
	}
	uart_update_timeout(port, termios->c_cflag, baud);
}

/* The port lock is not held.  */
static void zilog_set_termios(struct uart_port *port, struct ktermios *termios,
			    struct ktermios *old)
{
	struct uart_zilog_port *uap = to_zilog(port);
	unsigned long flags;

	spin_lock_irqsave(&port->lock, flags);	

	/* Disable IRQs on the port */
	uap->curregs[R1] &= ~(EXT_INT_ENAB | TxINT_ENAB | RxINT_MASK);
	write_zsreg(uap, R1, uap->curregs[R1]);

	/* Setup new port configuration */
	__zilog_set_termios(port, termios, old);

	/* Re-enable IRQs on the port */
	if (ZS_IS_OPEN(uap)) {
		uap->curregs[R1] |= INT_ALL_Rx | TxINT_ENAB;
		if (!ZS_IS_EXTCLK(uap))
			uap->curregs[R1] |= EXT_INT_ENAB;
		write_zsreg(uap, R1, uap->curregs[R1]);
	}
	spin_unlock_irqrestore(&port->lock, flags);
}

static const char *zilog_type(struct uart_port *port)
{
	struct uart_zilog_port *uap = to_zilog(port);

	if (ZS_IS_IRDA(uap))
		return "Z85c30 ESCC - Infrared port";
	else if (ZS_IS_INTMODEM(uap))
		return "Z85c30 ESCC - Internal modem";
	return "Z85c30 ESCC - Serial port";
}

/* We do not request/release mappings of the registers here, this
 * happens at early serial probe time.
 */
static void zilog_release_port(struct uart_port *port)
{
}

static int zilog_request_port(struct uart_port *port)
{
	return 0;
}

/* These do not need to do anything interesting either.  */
static void zilog_config_port(struct uart_port *port, int flags)
{
}

/* We do not support letting the user mess with the divisor, IRQ, etc. */
static int zilog_verify_port(struct uart_port *port, struct serial_struct *ser)
{
	return -EINVAL;
}

static int zilog_ioctl(struct uart_port *port, unsigned int command,
				unsigned long argument)
{
	struct uart_zilog_port *uap = to_zilog(port);
	int rval = -ENOIOCTLCMD;

	switch (command) {
#ifdef TIODUMPREGS
	case TIODUMPREGS:
		{
			u8 m[16];
			spin_lock_irq(&uap->port.lock);
			m[0] = read_zsreg(uap, R0);
			m[1] = read_zsreg(uap, R1);
			m[2] = read_zsreg(uap, R2);
			m[3] = read_zsreg(uap, R3);
			m[4] = read_zsreg(uap, R4);
			m[5] = read_zsreg(uap, R5);
			m[6] = read_zsreg(uap, R6);
			m[7] = read_zsreg(uap, R7);
			m[8] = read_zsreg(uap, R8);
			m[9] = read_zsreg(uap, R9);
			m[10] = read_zsreg(uap, R10);
			m[11] = read_zsreg(uap, R11);
			m[12] = read_zsreg(uap, R12);
			m[13] = read_zsreg(uap, R13);
			m[14] = read_zsreg(uap, R14);
			m[15] = read_zsreg(uap, R15);
			spin_unlock_irq(&uap->port.lock);
			rval = copy_to_user((void *)argument, (void *)&m, 16);
			break;
		}
#endif
	default:
		break;
	}
	return rval;
}

static struct uart_ops zilog_pops = {
	.tx_empty	=	zilog_tx_empty,
	.set_mctrl	=	zilog_set_mctrl,
	.get_mctrl	=	zilog_get_mctrl,
	.stop_tx	=	zilog_stop_tx,
	.start_tx	=	zilog_start_tx,
	.stop_rx	=	zilog_stop_rx,
	.enable_ms	=	zilog_enable_ms,
	.break_ctl	=	zilog_break_ctl,
	.startup	=	zilog_startup,
	.shutdown	=	zilog_shutdown,
	.set_termios	=	zilog_set_termios,
	.type		=	zilog_type,
	.release_port	=	zilog_release_port,
	.request_port	=	zilog_request_port,
	.config_port	=	zilog_config_port,
	.verify_port	=	zilog_verify_port,
	.ioctl		=	zilog_ioctl,
};



/*
 * Setup one port structure after probing, HW is down at this point,
 * Unlike sunzilog, we don't need to pre-init the spinlock as we don't
 * register our console before uart_add_one_port() is called
 */
static int serial_zilog_init_ports(unsigned long serial_base,
				   unsigned long serial_len,
	int irq)
{
	int i, inst = 0, irqflags = 0;
#ifdef HAS_DBDMA
	unsigned int tx_dma_address = 0;
	unsigned int rx_dma_address = 0;
#endif
	struct uart_zilog_port *uap = &serial_zilog_ports[0];
	void *mapped_serial_base;

	if (uap->port.mapbase == serial_base && uap->port.membase != NULL) {
		mapped_serial_base = uap->port.membase;
		DebugZ("serial_zilog_init_ports() PCI base addres 0x%lx was "
			"yet mapped to 0x%p\n",
			serial_base, uap->port.membase);
		return (0);
	} else {
		if (l_zilogs_count >= NUM_L_ZILOGS) {
			printk(KERN_WARNING "Serial: 85c30 device cannot be "
				"registered: to many instances\n");
		}
		inst = l_zilogs_count * UART_PORTS_NR;
		uap = &serial_zilog_ports[inst];
		mapped_serial_base = ioremap(serial_base, serial_len);
		if (mapped_serial_base == NULL) {
			DebugZ("serial_zilog_init_ports() could not map "
				"device base addres 0x%lx, len 0x%lx\n",
				serial_base, serial_len);
			return (-ENOMEM);
		}
		DebugZ("serial_zilog_init_ports() inst %d PCI base addres "
			"0x%lx, len 0x%lx is mapped to 0x%p uap %p\n",
			inst, serial_base, serial_len, mapped_serial_base, uap);
	}
	/*
	 * Request & map chip registers
	 */
	for (i = 0; i < UART_PORTS_NR; i++) {

	uap[i].port.mapbase = (serial_base + (2 * i));
	uap[i].port.membase = (void __iomem *)(mapped_serial_base + (2 * i));

	/* Channel A: i == 0; Channel B: i == 1; */
	uap[i].control_reg = uap[i].port.membase;
	uap[i].data_reg = uap[i].control_reg + 0x01;
	printk("Zilog: console init port %d, control_reg = 0x%lx\n",
				i, (unsigned long)uap[i].control_reg);

	raw_spin_lock_init(&uap[i].wr0_reg_lock);
	/* Channel A: */
	if (i == 0){
		uap[0].mate 	= &uap[1];
		uap[0].flags	= PMACZILOG_FLAG_IS_CHANNEL_A;
		uap[0].port.line = inst + 0;
	}
	/* Channel B: */
	if (i == 1){
		uap[1].mate 	= &uap[0];
		uap[1].port.line = inst + 1;
	}
	/*
	 * Request & map DBDMA registers
	 */
#ifdef HAS_DBDMA
	if (np->n_addrs >= 3 && np->n_intrs >= 3)
		uap[i].flags |= PMACZILOG_FLAG_HAS_DMA;

	if (ZS_HAS_DMA(&uap[i])) {
		uap[i].tx_dma_regs = ioremap(tx_dma_address, 0x1000);
		if (uap[i].tx_dma_regs == NULL) {
			uap[i].flags &= ~PMACZILOG_FLAG_HAS_DMA;
			goto no_dma;
		}
		uap[i].rx_dma_regs = ioremap(rx_dma_address, 0x1000);
		if (uap[i].rx_dma_regs == NULL) {
			iounmap(uap[i].tx_dma_regs);
			uap[i].tx_dma_regs = NULL;
			uap[i].flags &= ~PMACZILOG_FLAG_HAS_DMA;
			goto no_dma;
		}
		uap[i].tx_dma_irq = 1;
		uap[i].rx_dma_irq = 2;
	}
no_dma:
#endif
	if (share_irqs)
		irqflags = IRQF_SHARED;
	/*
	 * Init remaining bits of "port" structure
	 */
	uap[i].port.iotype = SERIAL_IO_MEM;
	uap[i].port.irq = irq;
	uap[i].port.irqflags = irqflags;
	uap[i].port.uartclk = ZS_CLOCK;
	uap[i].port.fifosize = 1;
	uap[i].port.ops = &zilog_pops;
	uap[i].port.type = PORT_PMAC_ZILOG;
	uap[i].port.flags = 0;

	/* Setup some valid baud rate information in the register
	 * shadows so we don't write crap there before baud rate is
	 * first initialized.
	 */
	zilog_convert_to_zs(&uap[i], CS8, 0, 9600);

	}
	l_zilogs_count ++;
	return (l_zilogs_count - 1);
}

static int serial_zilog_register_ports(struct pci_dev *dev)
{
	int rc;
	unsigned long serial_base;
	unsigned long serial_len;
	u16 sub_vend, sub_dev;

	if (dev->irq == 0 || dev->irq == -1) {
		u8 irq;
		char val;

		printk("%s serial a85c30 controller: boot did not set IRQ and "
			"interrupt line, so set to default %d\n",
			pci_name(dev), ZILOG_IRQ_DEFAULT);
		irq = ZILOG_IRQ_DEFAULT;
		printk("%s serial a85c30 controller: set reg 0x%x to "
			"IRQ %d\n",
			pci_name(dev), PCI_INTERRUPT_LINE, irq);
		pci_write_config_byte(dev, PCI_INTERRUPT_LINE, irq);
		pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &val);
		irq = (int) val;
		printk("%s serial a85c30 controller: read from reg 0x%x "
			"IRQ %d\n",
			pci_name(dev), PCI_INTERRUPT_LINE, irq);
		irq = ZILOG_IRQ_DEFAULT;
		dev->irq = irq;
	}
	pci_read_config_word(dev, PCI_SUBSYSTEM_VENDOR_ID, &sub_vend);
	pci_read_config_word(dev, PCI_SUBSYSTEM_ID, &sub_dev);

	if (sub_vend == PCI_VENDOR_ID_INTEL && sub_dev == 0) {
		serial_base = pci_resource_start(dev, 0);
		serial_len = pci_resource_len(dev, 0);
	} else {
	    serial_base = pci_resource_start(dev, PCI_DEVICE_BAR_ZILOG);
	    serial_len = pci_resource_len(dev, PCI_DEVICE_BAR_ZILOG);
	}

	rc = serial_zilog_init_ports(serial_base, serial_len, dev->irq);

	return rc;

}

#ifdef CONFIG_SERIAL_L_ZILOG_CONSOLE
static struct console l_zilog_console;
#define L_ZILOG_CONSOLE	&l_zilog_console
#else
#define L_ZILOG_CONSOLE	(NULL)
#endif
static struct uart_driver l_zilog_uart_reg = {
	.owner		=	THIS_MODULE,
	.driver_name	=	"serial_uart_zilog",
	.dev_name	=	"ttyS",
	.major		=	TTY_MAJOR,
	.minor		= 	64,
	.nr		=	NUM_L_ZILOGS * UART_PORTS_NR,
	.cons		=	L_ZILOG_CONSOLE,	
};

/*
 * This is the platform device platform_data structure
 */
struct plat_serial_zilog_port {
	unsigned long	iobase;		/* io base address */
	void __iomem	*membase;	/* ioremap cookie or NULL */
	unsigned long	mapbase;	/* resource base */
	unsigned int	irq;		/* interrupt number */
	unsigned int	uartclk;	/* UART clock rate */
	unsigned char	regshift;	/* register shift */
	unsigned char	iotype;		/* UPIO_* */
	unsigned char	hub6;
	unsigned int	flags;		/* UPF_* flags */
};

static DEFINE_MUTEX(serial_mutex);

static struct uart_zilog_port *serial_zilog_find_match_or_unused(struct uart_port *port)
{
	struct uart_zilog_port *uap;
	int inst, i;

	/*
	 * First, find a port entry which matches.
	 */
	for (inst = 0; inst < l_zilogs_count; inst ++) {
		uap = &serial_zilog_ports[inst * UART_PORTS_NR];
		for (i = 0; i < UART_PORTS_NR; i++)
			if (uart_match_port(&(uap[i].port), port))
				return (&uap[i]);
	}

	/*
	 * We didn't find a matching entry, so look for the first
	 * free entry.  We look for one which hasn't been previously
	 * used (indicated by zero iobase).
	 */
	for (inst = 0; inst < l_zilogs_count; inst ++) {
		uap = &serial_zilog_ports[inst * UART_PORTS_NR];
		for (i = 0; i < UART_PORTS_NR; i++)
			if (uap[i].port.type == PORT_UNKNOWN &&
				uap[i].port.iobase == 0)
				return (&uap[i]);
	}

	/*
	 * That also failed.  Last resort is to find any entry which
	 * doesn't have a real port associated with it.
	 */
	for (inst = 0; inst < l_zilogs_count; inst ++) {
		uap = &serial_zilog_ports[inst * UART_PORTS_NR];
		for (i = 0; i < UART_PORTS_NR; i++)
			if (uap[i].port.type == PORT_UNKNOWN)
				return (&uap[i]);
	}

	return (NULL);
}

/**
 *	serial_zilog_register_port - register a serial port
 *	@port: serial port template
 *
 *	Configure the serial port specified by the request. If the
 *	port exists and is in use, it is hung up and unregistered
 *	first.
 *
 *	The port is then probed and if necessary the IRQ is autodetected
 *	If this fails an error is returned.
 *
 *	On success the port is ready to use and the line number is returned.
 */
/* FIXME */
int serial_zilog_register_port(struct uart_port *port)
{
	struct uart_zilog_port *uart;
	int irqflag = 0;
	int ret = -ENOSPC;

	if (port->uartclk == 0)
		return -EINVAL;

	mutex_lock(&serial_mutex);

	DebugZ("Zilog: start for 0x%lx\n", (unsigned long)port);
	uart = serial_zilog_find_match_or_unused(port);
	if (share_irqs)
		irqflag = IRQF_SHARED;
	if (uart) {
		uart->port.iobase   = port->iobase;
		uart->port.membase  = port->membase;
		uart->port.irq      = port->irq;
		uart->port.irqflags = port->irqflags | irqflag;
		uart->port.uartclk  = port->uartclk;
		uart->port.fifosize = port->fifosize;
		uart->port.regshift = port->regshift;
		uart->port.iotype   = port->iotype;
		uart->port.type     = port->type;
		uart->port.flags    = port->flags;
		uart->port.mapbase  = port->mapbase;
		if (port->dev)
			uart->port.dev = port->dev;

		DebugZ("Zilog: Addition new uart 0x%p, port 0x%p, "
			"line %d\n",
			uart, &uart->port, uart->port.line);
		ret = uart_add_one_port(&l_zilog_uart_reg, &uart->port);
		DebugZ("Zilog: uart_add_one_port() returned %d\n", ret);
		if (ret == 0)
			ret = uart->port.line;
	}
	mutex_unlock(&serial_mutex);

	return ret;
}
EXPORT_SYMBOL(serial_zilog_register_port);

/*
 * Get rid of a port on module removal
 */
static void zilog_dispose_port(struct uart_zilog_port *uap)
{
#ifdef HAS_DBDMA
	iounmap(uap->rx_dma_regs);
	iounmap(uap->tx_dma_regs);
#endif
	iounmap(uap->port.membase);
	memset(uap, 0, sizeof(struct uart_zilog_port));
}

/**
 *	serial_zilog_unregister_port - remove a 16x50 serial port at runtime
 *	@line: serial line number
 *
 *	Remove one serial port.  This may not be called from interrupt
 *	context.  We hand the port back to the our control.
 */
void serial_zilog_unregister_port(int line)
{
	struct uart_zilog_port *uart = &serial_zilog_ports[line];

	mutex_lock(&serial_mutex);
	uart_remove_one_port(&l_zilog_uart_reg, &uart->port);
	uart->port.dev = NULL;
	zilog_dispose_port(uart);
	mutex_unlock(&serial_mutex);
}
EXPORT_SYMBOL(serial_zilog_unregister_port);

/**
 *	serial_zilog_suspend_port - suspend one serial port
 *	@line:  serial line number
 *      @level: the level of port suspension, as per uart_suspend_port
 *
 *	Suspend one serial port.
 */
void serial_zilog_suspend_port(int line)
{
	uart_suspend_port(&l_zilog_uart_reg, &serial_zilog_ports[line].port);
}
EXPORT_SYMBOL(serial_zilog_suspend_port);
/**
 *	serial_zilog_resume_port - resume one serial port
 *	@line:  serial line number
 *      @level: the level of port resumption, as per uart_resume_port
 *
 *	Resume one serial port.
 */
void serial_zilog_resume_port(int line)
{
	uart_resume_port(&l_zilog_uart_reg, &serial_zilog_ports[line].port);
}
EXPORT_SYMBOL(serial_zilog_resume_port);
/*
 * Register a set of serial devices attached to a platform device.  The
 * list is terminated with a zero flags entry, which means we expect
 * all entries to have at least UPF_BOOT_AUTOCONF set.
 */
static int serial_zilog_probe(struct pci_dev *dev,
			      const struct pci_device_id *ent)
{
	/* It seems to be NULL */
	struct uart_port *port;
	int ret, i, inst;
	u8 irq;
	unsigned long irq_flags;

	DebugZ("%s: serial_zilog_probe() started\n", pci_name(dev));
	ret = pci_enable_device(dev);
	if (ret) {
		printk("Zilog: Unable to make enable device\n");
		return ret;
	}

	inst = serial_zilog_register_ports(dev);
	if (inst < 0) {
		printk("%s Zilog: Unable to register ports\n", pci_name(dev));
		goto out_early;
	}
	if (l_zilogs_count == 1) {
		ret = uart_register_driver(&l_zilog_uart_reg);
		if (ret) {
			printk("Zilog: Unable to make uart_register_driver\n");
			goto out_early;
		}
	}

	for (i = 0; i < UART_PORTS_NR; i++) {

		port = &serial_zilog_ports[inst * UART_PORTS_NR + i].port;
	
		port->dev = &dev->dev;
		if (share_irqs)
			port->flags |= UPF_SHARE_IRQ;
		ret = serial_zilog_register_port(port);
		if (ret < 0) {
			printk("unable to register port at index %d "
				"(IO 0x%lx MEM %llx IRQ%d): %d\n",
				inst * UART_PORTS_NR + i,
				port->iobase, port->mapbase, port->irq, ret);
			goto out;
		}
	}
	DebugZ("serial_zilog_probe: irq = 0x%x\n", dev->irq);
	irq_flags = (share_irqs) ? IRQF_SHARED : 0;
	if (dev->irq == 0 || dev->irq == -1) {	/* FIXME IRQ should be set by BIOS */
		char val;
		printk("%s serial a85c30 controller: IRQ did not find, set to "
			"default %d\n", pci_name(dev), ZILOG_IRQ_DEFAULT);
		irq = ZILOG_IRQ_DEFAULT;
		printk("%s serial a85c30 controller: set reg 0x%x to "
			"IRQ %d\n",
			pci_name(dev), PCI_INTERRUPT_LINE, irq);
		pci_write_config_byte(dev, PCI_INTERRUPT_LINE, irq);
		pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &val);
		irq = (int) val;
		printk("%s serial a85c30 controller: read from reg 0x%x "
			"IRQ %d\n",
			pci_name(dev), PCI_INTERRUPT_LINE, irq);
		irq = ZILOG_IRQ_DEFAULT;
	} else
		irq = dev->irq;

	if ((ret = request_irq(irq, zilog_interrupt, irq_flags, 
				"Elbrus arch Zilog",
				&serial_zilog_ports[inst * UART_PORTS_NR]))) {
		printk("serial_zilog_probe: unable to register IRQ #%u "
			"interrupt handler.\n", irq);
		goto out;
	} else {
		printk("serial_zilog_probe: register IRQ #%u and set "
			"interrupt handler.\n", irq);
	}
	
	return 0;
out:
	l_zilogs_count --;
	if (l_zilogs_count == 0)
		uart_unregister_driver(&l_zilog_uart_reg);
out_early:
	pci_disable_device(dev);
	return ret;
}

/*
 * Remove serial ports registered against a platform device.
 */
static void serial_zilog_remove(struct pci_dev *dev)
{
	int i, irq;

	/* Release interrupt handler */
	irq = dev->irq;
	if (irq == 0 || irq == -1) {	/* FIXME IRQ should be set by BIOS */
		irq = ZILOG_IRQ_DEFAULT;
	}
	free_irq(irq, serial_zilog_ports);

	for (i = 0; i < l_zilogs_count * UART_PORTS_NR; i++) {
		struct uart_zilog_port *up = &serial_zilog_ports[i];

		if (up->port.dev == &dev->dev)
			serial_zilog_unregister_port(i);
	}
	/* Unregister UART driver */
	uart_unregister_driver(&l_zilog_uart_reg);
	l_zilogs_count --;
	if (l_zilogs_count == 0)
		pci_disable_device(dev);
}

static int serial_zilog_suspend(struct pci_dev *dev, pm_message_t state)
{
	int i;

	for (i = 0; i < l_zilogs_count * UART_PORTS_NR; i++) {
		struct uart_zilog_port *up = &serial_zilog_ports[i];

		if (up->port.type != PORT_UNKNOWN && up->port.dev == &dev->dev)
			uart_suspend_port(&l_zilog_uart_reg, &up->port);
	}

	return 0;
}

static int serial_zilog_resume(struct pci_dev *dev)
{
	int i;

	for (i = 0; i < l_zilogs_count * UART_PORTS_NR; i++) {
		struct uart_zilog_port *up = &serial_zilog_ports[i];

		if (up->port.type != PORT_UNKNOWN && up->port.dev == &dev->dev)
			uart_resume_port(&l_zilog_uart_reg, &up->port);
	}

	return 0;
}

static const struct pci_device_id zilog_pci_table[] = {
	{
		.vendor = PCI_VENDOR_ID_INTEL,
		.device = PCI_DEVICE_ID_PAR_SER,
		.subvendor = PCI_ANY_ID,
		.subdevice = PCI_ANY_ID,
	},
	{
		.vendor = PCI_VENDOR_ID_AMD,
		.device = PCI_DEVICE_ID_PAR_SER,
		.subvendor = PCI_ANY_ID,
		.subdevice = PCI_ANY_ID,
	},
	{
		.vendor = PCI_VENDOR_ID_MCST_TMP,
		.device = PCI_DEVICE_ID_MCST_PARALLEL_SERIAL,
		.subvendor = PCI_ANY_ID,
		.subdevice = PCI_ANY_ID,
	},
	{
		0,
	}
};

static struct pci_driver l_zilog_driver =
{
	.name		= "serial_zilog",
	.probe		= serial_zilog_probe,
	.remove		= serial_zilog_remove,
	.suspend	= serial_zilog_suspend,
       	.resume		= serial_zilog_resume,
	.id_table	= zilog_pci_table,
};

static int l_zilog_init(void)
{
	printk(KERN_INFO "Serial: 85c30 driver $ "
		"%d ports, IRQ sharing %sabled\n", (int) UART_PORTS_NR,
		share_irqs ? "en" : "dis");

	return pci_register_driver(&l_zilog_driver);
}

static void __exit l_zilog_exit(void)
{
	pci_unregister_driver(&l_zilog_driver);
}

#ifdef CONFIG_SERIAL_L_ZILOG_CONSOLE
/*
 * Print a string to the serial port trying not to disturb
 * any possible real use of the port...
 */
static void l_zilog_console_write(struct console *con, const char *s, unsigned int count)
{
	struct uart_zilog_port *uap = &serial_zilog_ports[con->index];
	unsigned long flags;
	int i;

#ifdef CONFIG_SERIAL_AM85C30_CONSOLE
	if (use_boot_printk_all || (use_boot_printk && !console_initialized)) {
		dump_putns(s, count);
		return;
	}
#endif

	spin_lock_irqsave(&uap->port.lock, flags);

	/* Turn of interrupts and enable the transmitter. */
	write_zsreg(uap, R1, uap->curregs[1] & ~TxINT_ENAB);
	write_zsreg(uap, R5, uap->curregs[5] | TxENABLE | RTS | DTR);

	for (i = 0; i < count; i++) {
		/* Wait for the transmit buffer to empty. */
		while ((read_zsreg(uap, R0) & Tx_BUF_EMP) == 0)
			udelay(5);
		write_zsdata(uap, s[i]);
		if (s[i] == 10) {
			while ((read_zsreg(uap, R0) & Tx_BUF_EMP) == 0)
				udelay(5);
			write_zsdata(uap, R13);
		}
	}

	/* Restore the values in the registers. */
	write_zsreg(uap, R1, uap->curregs[1]);
	/* Don't disable the transmitter. */

	spin_unlock_irqrestore(&uap->port.lock, flags);
}

/*
 * Setup the serial console
 */
static int l_zilog_console_setup(struct console *co, char *options)
{
	unsigned long flags;
	struct uart_zilog_port *uap;
	struct uart_port *port;
	int baud = 38400;
	int bits = 8;
	int parity = 'n';
	int flow = 'n';

	/*
	 * Check whether an invalid uart number has been specified, and
	 * if so, search for the first available port that does have
	 * console support.
	 */
	if (co->index >= l_zilogs_count * UART_PORTS_NR)
		co->index = 0;
	uap = &serial_zilog_ports[co->index];
	port = &uap->port;
	if (!port->membase)
		return -ENODEV;

	/*
	 * Mark port as beeing a console
	 */
	uap->flags |= PMACZILOG_FLAG_IS_CONS;

	/*
	 * Temporary fix for uart layer who didn't setup the spinlock yet
	 */
	spin_lock_init(&port->lock);

	/*
	 * Enable the hardware
	 *
	 * Disable interrupts so that the timer interrupt handler does
	 * not try to use the serial port while it's being initialized.
	 */
	spin_lock_irqsave(&uap->port.lock, flags);
	__zilog_startup(uap);
	spin_unlock_irqrestore(&uap->port.lock, flags);
	
	if (options)
		uart_parse_options(options, &baud, &parity, &bits, &flow);

	return uart_set_options(port, co, baud, parity, bits, flow);
}

static int zilog_console_init(void)
{
	unsigned long serial_base;
	int err = 0;

	/* Probe ports */
	printk("Zilog: console probe ...");
	if (serial_console_opts == NULL) {
		err = -ENODEV;
		goto error;
	}
	if (strcmp(serial_console_opts->name, SERIAL_CONSOLE_AM85C30_NAME)) {
		err = -ENODEV;
		goto error;
	}
	serial_base = serial_console_opts->io_base;
	if (!serial_base) {
		err = -ENODEV;
		goto error;
	}
	err = serial_zilog_init_ports(serial_base, ZILOG_IO_MEMORY_SIZE,
			ZILOG_IRQ_DEFAULT);
	if (err < 0) {
		goto error;
	} else {
		printk(" found\n");
	}

	register_console(&l_zilog_console);

	return 0;
error:
	printk(" is not detected\n");
	return (err);

}
console_initcall(zilog_console_init);

static struct console l_zilog_console = {
	.name	=	"ttyS",
	.write	=	l_zilog_console_write,
	.device	=	uart_console_device,
	.setup	=	l_zilog_console_setup,
# ifndef CONFIG_EARLY_DUMP_CONSOLE
	.flags	=	CON_PRINTBUFFER,
# endif
	.index	=	-1,
	.data   =	&l_zilog_uart_reg,
};
#endif /* CONFIG_SERIAL_L_ZILOG_CONSOLE */

module_init(l_zilog_init);
module_exit(l_zilog_exit);

MODULE_DEVICE_TABLE(pci, zilog_pci_table);
MODULE_LICENSE("GPL");

