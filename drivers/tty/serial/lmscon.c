/*
 * linux/drivers/char/lmscon.c
 *
 * Driver for the console port of the LMS E2K simulator.
 *
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/console.h>

#include <linux/major.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/serial.h>
#include <linux/serial_core.h>

#include <asm/system.h>
#include <asm/io.h>
#ifdef __e2k__
#include <asm/lms.h>
#endif
#include <asm/uaccess.h>
#ifdef __e2k__
#include <asm/e2k_debug.h>
#endif
#ifdef CONFIG_E90S
#include <asm/memcard.h>
#endif

#ifdef CONFIG_E90S
#define	LMS_CONS_DATA_PORT	PCI_IO + 0x300UL
				/* On READ  - data from keyboard      */
				/* On WRITE - data to debug ouput     */
				/* port (console/journal)             */
#endif

#define	LMSPORT_NEWDEVID

#ifdef LMSPORT_NEWDEVID

#define LMSCON_MAJOR		245
#define LMSCON_MINOR		0

#else

#define LMSCON_MAJOR            204
#define LMSCON_MINOR            10

#endif

#define	LMS_NPORTS		1

#define LMS_IRQS      { 0,  0,  0,  0 }

struct lms_port {
	struct uart_port port;
	int type;
	unsigned char irqs[4]; /* ERI, RXI, TXI, BRI */
	void (*init_pins)(struct uart_port *port, unsigned int cflag);
	int break_flag;
//	struct timer_list break_timer;
};



#define	LMS_MAGIC		0xe2e4



/* Function prototypes */
static void lms_stop_tx(struct uart_port *port);
static void lms_start_tx(struct uart_port *port);
static void lms_start_rx(struct uart_port *port);
static void lms_stop_rx(struct uart_port *port);

static struct lms_port lms_ports[LMS_NPORTS];
static struct uart_driver lms_uart_driver;


static void lms_transmit_chars(struct uart_port *port)
{
	struct circ_buf *xmit = &port->state->xmit;
	unsigned int stopped = uart_tx_stopped(port);
	int count;

	count = uart_circ_chars_pending(xmit);

	while (inl(LMS_CONS_DATA_PORT));

	do {
		unsigned char c;

		if (port->x_char) {
			c = port->x_char;
			port->x_char = 0;
		} else if (!uart_circ_empty(xmit) && !stopped) {
			c = xmit->buf[xmit->tail];
			xmit->tail = (xmit->tail + 1) & (UART_XMIT_SIZE - 1);
		} else {
			break;
		}

		outb_p(c, LMS_CONS_DATA_PORT);
		outb_p(0, LMS_CONS_DATA_PORT);

		port->icount.tx++;
	} while (--count > 0);


	if (uart_circ_chars_pending(xmit) < WAKEUP_CHARS)
		uart_write_wakeup(port);
	if (uart_circ_empty(xmit)) {
		lms_stop_tx(port);
	}

}


static unsigned int lms_tx_empty(struct uart_port *port)
{
	/* Can't detect */
	return TIOCSER_TEMT;
}

static void lms_set_mctrl(struct uart_port *port, unsigned int mctrl)
{
	/* This routine is used for seting signals of: DTR, DCD, CTS/RTS */
	/* We use SCIF's hardware for CTS/RTS, so don't need any for that. */
	/* If you have signals for DTR and DCD, please implement here. */
}

static unsigned int lms_get_mctrl(struct uart_port *port)
{
	/* This routine is used for geting signals of: DTR, DCD, DSR, RI,
	   and CTS/RTS */

	return TIOCM_DTR | TIOCM_RTS | TIOCM_DSR;
}

static void lms_start_tx(struct uart_port *port)
{

	lms_transmit_chars(port);
}

static void lms_stop_tx(struct uart_port *port)
{
	/* Nothing here yet .. */
}

static void lms_start_rx(struct uart_port *port)
{
	/* Nothing here yet .. */
}

static void lms_stop_rx(struct uart_port *port)
{
	/* Nothing here yet .. */
}

static void lms_enable_ms(struct uart_port *port)
{
	/* Nothing here yet .. */
}

static void lms_break_ctl(struct uart_port *port, int break_state)
{
	/* Nothing here yet .. */
}

static int lms_startup(struct uart_port *port)
{
	lms_start_tx(port);
	lms_start_rx(port);

	return 0;
}

static void lms_shutdown(struct uart_port *port)
{
	lms_stop_rx(port);
	lms_stop_tx(port);
}

static void lms_set_termios(struct uart_port *port, struct ktermios *termios,
			    struct ktermios *old)
{
//	struct sci_port *s = &lms_ports[port->line];
	unsigned int baud;
	unsigned long flags;

	baud = uart_get_baud_rate(port, termios, old, 0, 115200);
	if (baud == 0)
		baud = 9600;

	spin_lock_irqsave(&port->lock, flags);

	uart_update_timeout(port, termios->c_cflag, baud);

//	s->init_pins(port, termios->c_cflag);

	if ((termios->c_cflag & CREAD) != 0)
              lms_start_rx(port);

	spin_unlock_irqrestore(&port->lock, flags);
}

static const char *lms_type(struct uart_port *port)
{

	return "generic";
}


static void lms_release_port(struct uart_port *port)
{
	/* Nothing here yet .. */
}

static int lms_request_port(struct uart_port *port)
{
	/* Nothing here yet .. */
	return 0;
}

static void lms_config_port(struct uart_port *port, int flags)
{
	struct lms_port *s = &lms_ports[port->line];

	port->type = s->type;
}

static int lms_verify_port(struct uart_port *port, struct serial_struct *ser)
{
	return 0;
}

static struct uart_ops lms_uart_ops = {
	.tx_empty	= lms_tx_empty,
	.set_mctrl	= lms_set_mctrl,
	.get_mctrl	= lms_get_mctrl,
	.start_tx	= lms_start_tx,
	.stop_tx	= lms_stop_tx,
	.stop_rx	= lms_stop_rx,
	.enable_ms	= lms_enable_ms,
	.break_ctl	= lms_break_ctl,
	.startup	= lms_startup,
	.shutdown	= lms_shutdown,
	.set_termios	= lms_set_termios,
	.type		= lms_type,
	.release_port	= lms_release_port,
	.request_port	= lms_request_port,
	.config_port	= lms_config_port,
	.verify_port	= lms_verify_port,
};


static struct lms_port lms_ports[LMS_NPORTS] = {
	{
		.port	= {
			.membase	= (void *)0,
			.mapbase	= 0x0,
			.iotype		= SERIAL_IO_MEM,
			.type		= PORT_MUX,
			.irq		= 0,
			.ops		= &lms_uart_ops,
			.flags		= ASYNC_BOOT_AUTOCONF,
			.line		= 0,
		},
		.type		= 0,
		.irqs		= LMS_IRQS,
//		.init_pins	= sci_init_pins_sci,
	},
};


#if 0


static void lms_disable_tx_interrupts(void *ptr)
{
	pr_debug("passing through lms_disable_tx_interrupts()\n");
}

/*
 * This routine is used by the interrupt handler to schedule
 * processing in the software interrupt portion of the driver.
 */
/*
static inline void lms_sched_event(struct lms_port *port, int event)
{
	port->event |= 1 << event;
	queue_task(&port->tqueue, &tq_immediate);
	mark_bh(IMMEDIATE_BH);
}
*/

static void lms_transmit_chars(struct lms_port *port)
{
	int count, i;
	unsigned long flags;
	unsigned char c;

	pr_debug("passing through lms_transmit_chars(), length = %d\n", 
			port->gs.xmit_cnt);

	while (1) {
		count = port->gs.xmit_cnt;

		/* Don't copy pas the end of the source buffer */
		if (count > SERIAL_XMIT_SIZE - port->gs.xmit_tail)
                	count = SERIAL_XMIT_SIZE - port->gs.xmit_tail;

		/* If for one reason or another, we can't copy more data, we're done! */
		if (count == 0)
			break;

		while (inl(LMS_CONS_DATA_PORT));

		for (i=0; i<count; i++) {
			c = port->gs.xmit_buf[port->gs.xmit_tail + i];

			outb_p(c, LMS_CONS_DATA_PORT);
			outb_p(0, LMS_CONS_DATA_PORT);
		}

		port->icount.tx += count;

		/* Update the kernel buffer end */
		port->gs.xmit_tail = (port->gs.xmit_tail + count) & (SERIAL_XMIT_SIZE-1);

		/* This one last. (this is essential)
		   It would allow others to start putting more data into the buffer! */
		port->gs.xmit_cnt -= count;
	}

//	if (port->gs.xmit_cnt <= port->gs.wakeup_chars)
//		lms_sched_event(port, LMS_EVENT_WRITE_WAKEUP);

	local_irq_save(flags);
	if (port->gs.xmit_cnt == 0) {
		port->gs.flags &= ~GS_TX_INTEN;
	}
	local_irq_restore(flags);
}


static void lms_enable_tx_interrupts(void *ptr)
{
	struct lms_port *port = ptr; 

	pr_debug("passing through lms_enable_tx_interrupts()\n");

	lms_transmit_chars(port);
}

static void lms_disable_rx_interrupts(void *ptr)
{
	pr_debug("passing through lms_disable_rx_interrupts()\n");
}

static void lms_enable_rx_interrupts(void *ptr)
{
	pr_debug("passing through lms_enable_rx_interrupts()\n");
}

static int lms_get_CD(void * ptr)
{
	pr_debug("passing through lms_get_CD()\n");

	/* If you have signal for CD (Carrier Detect), please change here. */
	return 1;
}

static void lms_throttle(struct tty_struct * tty)
{
	struct lms_port *port = (struct lms_port *)tty->driver_data;

	/* If the port is using any type of input flow
	 * control then throttle the port.
	 */
	if ((tty->termios->c_cflag & CRTSCTS) || (I_IXOFF(tty)) )
		port->gs.flags |= LMS_RX_THROTTLE;

	pr_debug("passing through lms_throttle()\n");

}


static void lms_unthrottle(struct tty_struct * tty)
{
	struct lms_port *port = (struct lms_port *)tty->driver_data;

	/* Always unthrottle even if flow control is not enabled on
	 * this port in case we disabled flow control while the port
	 * was throttled
	 */
	port->gs.flags &= ~LMS_RX_THROTTLE;

	pr_debug("passing through lms_unthrottle()\n");
}

static void lms_hungup(void *ptr)
{
	MOD_DEC_USE_COUNT;
}

static void lms_close(void *ptr)
{
	MOD_DEC_USE_COUNT;
}

static void lms_setsignals(struct lms_port *port, int dtr, int rts)
{
	pr_debug("passing through lms_setsignals()\n");

	/* This routine is used for seting signals of: DTR, DCD, CTS/RTS */
	;
}

static int lms_getsignals(struct lms_port *port)
{

	pr_debug("passing through lms_getsignals()\n");

	/* This routine is used for geting signals of: DTR, DCD, DSR, RI,
	   and CTS/RTS */

	return TIOCM_DTR|TIOCM_RTS|TIOCM_DSR;
/*
	(((o_stat & OP_DTR)?TIOCM_DTR:0) |
	 ((o_stat & OP_RTS)?TIOCM_RTS:0) |
	 ((i_stat & IP_CTS)?TIOCM_CTS:0) |
	 ((i_stat & IP_DCD)?TIOCM_CAR:0) |
	 ((i_stat & IP_DSR)?TIOCM_DSR:0) |
	 ((i_stat & IP_RI) ?TIOCM_RNG:0)
*/
}

static void lms_set_termios_cflag(struct lms_port *port, int cflag, int baud)
{
	pr_debug("passing through lms_set_termios_cflag()\n");
}

static int lms_chars_in_buffer(void * ptr)
{
//	struct lms_port *port = ptr;

	pr_debug("passing through lms_chars_in_buffer()\n");

	return 0;
}


static void lms_shutdown_port(void * ptr)
{
	struct lms_port *port = ptr; 

	pr_debug("passing through lms_shutdown_port()\n");

	port->gs.flags &= ~ GS_ACTIVE;
	if (port->gs.tty && port->gs.tty->termios->c_cflag & HUPCL)
		lms_setsignals(port, 0, 0);
}


static int lms_open(struct tty_struct * tty, struct file * filp)
{
	struct lms_port *port;
	int retval, line;

//	line = MINOR(tty->device) - LMSCON_MINOR;
	line = tty->index;

	pr_debug("passing through lms_open()\n");

	if ((line < 0) || (line >= LMS_NPORTS))
		return -ENODEV;

	port = &lms_ports[line];

	tty->driver_data = port;
	port->gs.tty = tty;
	port->gs.count++;

	port->event = 0;
	INIT_WORK(&port->tqueue, gs_do_softint, port);


	/*
	 * Start up serial port
	 */
	retval = gs_init_port(&port->gs);
	if (retval) {
		goto failed;
	}

	port->gs.flags |= GS_ACTIVE;
	lms_setsignals(port, 1,1);

	retval = gs_block_til_ready(port, filp);

	if (retval) {
		goto failed;
	}

/*
	if ((port->gs.count == 1) && (port->gs.flags & ASYNC_SPLIT_TERMIOS)) {
		if (tty->driver.subtype == SERIAL_TYPE_NORMAL)
			*tty->termios = port->gs.normal_termios;
		else 
			*tty->termios = port->gs.callout_termios;
		lms_set_real_termios(port);
	}
#ifdef CONFIG_SERIAL_CONSOLE
	if (sercons.cflag && sercons.index == line) {
		tty->termios->c_cflag = sercons.cflag;
		port->gs.baud = sercons_baud;
		sercons.cflag = 0;
		lms_set_real_termios(port);
	}
#endif
*/
	lms_enable_rx_interrupts(port);

	return 0;

failed:
	port->gs.count--;
	return retval;

}

static int lms_set_real_termios(void *ptr)
{
	struct lms_port *port = ptr;


	pr_debug("passing through lms_set_real_termios()\n");

	if (port->old_cflag != port->gs.tty->termios->c_cflag) {
		port->old_cflag = port->gs.tty->termios->c_cflag;
		lms_set_termios_cflag(port, port->old_cflag, port->gs.baud);
		lms_enable_rx_interrupts(port);
	}

	/* Tell line discipline whether we will do input cooking */
	if (I_OTHER(port->gs.tty))
		clear_bit(TTY_HW_COOK_IN, &port->gs.tty->flags);
	else
		set_bit(TTY_HW_COOK_IN, &port->gs.tty->flags);

/* Tell line discipline whether we will do output cooking.
 * If OPOST is set and no other output flags are set then we can do output
 * processing.  Even if only *one* other flag in the O_OTHER group is set
 * we do cooking in software.
 */
	if (O_OPOST(port->gs.tty) && !O_OTHER(port->gs.tty))
		set_bit(TTY_HW_COOK_OUT, &port->gs.tty->flags);
	else
		clear_bit(TTY_HW_COOK_OUT, &port->gs.tty->flags);

	return 0;
}

static int lms_ioctl(struct tty_struct * tty, struct file * filp, 
                     unsigned int cmd, unsigned long arg)
{
	int rc;
	struct lms_port *port = tty->driver_data;
	int ival;

	pr_debug("passing through lms_ioctl(), cmd = %X, arg = %lX\n", cmd, arg);

	rc = 0;
	switch (cmd) {
	case TIOCGSOFTCAR:
		rc = put_user(((tty->termios->c_cflag & CLOCAL) ? 1 : 0),
		              (unsigned int *) arg);
		break;
	case TIOCSSOFTCAR:
		if ((rc = verify_area(VERIFY_READ, (void *) arg,
		                      sizeof(int))) == 0) {
			get_user(ival, (unsigned int *) arg);
			tty->termios->c_cflag =
				(tty->termios->c_cflag & ~CLOCAL) |
				(ival ? CLOCAL : 0);
		}
		break;
	case TIOCGSERIAL:
		if ((rc = verify_area(VERIFY_WRITE, (void *) arg,
		                      sizeof(struct serial_struct))) == 0)
			gs_getserial(&port->gs, (struct serial_struct *) arg);
		break;
	case TIOCSSERIAL:
		if ((rc = verify_area(VERIFY_READ, (void *) arg,
		                      sizeof(struct serial_struct))) == 0)
			rc = gs_setserial(&port->gs,
					  (struct serial_struct *) arg);
		break;
	case TIOCMGET:
		if ((rc = verify_area(VERIFY_WRITE, (void *) arg,
		                      sizeof(unsigned int))) == 0) {
			ival = lms_getsignals(port);
			put_user(ival, (unsigned int *) arg);
		}
		break;
	case TIOCMBIS:
		if ((rc = verify_area(VERIFY_READ, (void *) arg,
		                      sizeof(unsigned int))) == 0) {
			get_user(ival, (unsigned int *) arg);
			lms_setsignals(port, ((ival & TIOCM_DTR) ? 1 : -1),
			                     ((ival & TIOCM_RTS) ? 1 : -1));
		}
		break;
	case TIOCMBIC:
		if ((rc = verify_area(VERIFY_READ, (void *) arg,
		                      sizeof(unsigned int))) == 0) {
			get_user(ival, (unsigned int *) arg);
			lms_setsignals(port, ((ival & TIOCM_DTR) ? 0 : -1),
			                     ((ival & TIOCM_RTS) ? 0 : -1));
		}
		break;
	case TIOCMSET:
		if ((rc = verify_area(VERIFY_READ, (void *) arg,
		                      sizeof(unsigned int))) == 0) {
			get_user(ival, (unsigned int *)arg);
			lms_setsignals(port, ((ival & TIOCM_DTR) ? 1 : 0),
			                     ((ival & TIOCM_RTS) ? 1 : 0));
		}
		break;

	default:
		rc = -ENOIOCTLCMD;
		break;
	}

	return rc;
}


#ifdef CONFIG_PROC_FS
static int lms_read_proc(char *page, char **start, off_t off, int count,
			 int *eof, void *data)
{
	int len = 0;
	
        len += sprintf(page, "LMS INFO:0.1\n");

	return len;
}
#endif

static struct tty_operations lms_ops = {
	.open	= lms_open,
	.close = gs_close,
	.write = gs_write,
	.put_char = gs_put_char,
	.flush_chars = gs_flush_chars,
	.write_room = gs_write_room,
	.chars_in_buffer = gs_chars_in_buffer,
	.flush_buffer = gs_flush_buffer,
	.ioctl = lms_ioctl,
	.throttle = lms_throttle,
	.unthrottle = lms_unthrottle,
	.set_termios = gs_set_termios,
	.stop = gs_stop,
	.start = gs_start,
	.hangup = gs_hangup,
#ifdef CONFIG_PROC_FS
	.read_proc = lms_read_proc,
#endif
/*
	.tiocmget = sci_tiocmget,
	.tiocmset = sci_tiocmset,
*/
};

#endif


/*
 *	Print a string to the LMS console port.
 */

static void serial_console_write(struct console *co, const char *s,
				 unsigned count)
{
	register int i;
	unsigned long flags;

	raw_local_irq_save(flags);

#if 1
	while (inl(LMS_CONS_DATA_PORT));
#endif
	for (i = 0; i < count; i++) {
		outb_p(s[i], LMS_CONS_DATA_PORT);
		outb_p(0,    LMS_CONS_DATA_PORT);
	}

	raw_local_irq_restore(flags);
}

static int __init serial_console_setup(struct console *co, char *options)
{
	struct uart_port *port;
	int baud = 9600;
	int bits = 8;
	int parity = 'n';
	int flow = 'n';

	/*
	 * Check whether an invalid uart number has been specified, and
	 * if so, search for the first available port that does have
	 * console support.
	 */
	if (co->index >= LMS_NPORTS)
		co->index = 0;
	port = &lms_ports[co->index].port;

#ifdef __e2k__
	e2k_debug_puts("Console: serial_console_setup\n");
#endif

	/* LMS simulator's console need no any special setup */

	if (options)
		uart_parse_options(options, &baud, &parity, &bits, &flow);

	return uart_set_options(port, co, baud, parity, bits, flow);
}


static struct console lms_serial_console = {
	.name		= "ttyLMS",
	.write		= serial_console_write,
	.device		= uart_console_device,
	.setup		= serial_console_setup,
	.flags		= CON_PRINTBUFFER,
	.index		= -1,
	.data		= &lms_uart_driver,

};


#define LMS_CONSOLE	&lms_serial_console

static char banner[] __initdata =
	KERN_INFO "E2K debug console driver initialized\n";

static struct uart_driver lms_uart_driver = {
	.owner		= THIS_MODULE,
	.driver_name	= "lmscon",
#ifdef CONFIG_DEVFS_FS
	.devfs_name	= "ttlms/",
#endif
	.dev_name	= "ttyLMS",
	.major		= LMSCON_MAJOR,
	.minor		= LMSCON_MINOR,
	.nr		= LMS_NPORTS,
	.cons		= LMS_CONSOLE,
};


int __init lms_init(void)
{

	int chan, ret;

	printk("%s", banner);

	ret = uart_register_driver(&lms_uart_driver);
	if (ret == 0) {
		for (chan = 0; chan < LMS_NPORTS; chan++) {
			struct lms_port *lmsport = &lms_ports[chan];

//			lmsport->port.uartclk = CONFIG_CPU_CLOCK;
			uart_add_one_port(&lms_uart_driver, &lmsport->port);
//			sciport->break_timer.data = (unsigned long)lmsport;
//			sciport->break_timer.function = lms_break_timer;
//			init_timer(&lmsport->break_timer);
		}
	}

	return 0;		/* Return -EIO when not detected */
}


//#ifdef CONFIG_SERIAL_CONSOLE


#if 0
static struct tty_driver *serial_console_device(struct console *c, int *index)
{
	e2k_debug_puts("Console: serial_console_device\n");

	*index = c->index;
	return lms_driver;
//	return MKDEV(LMSCON_MAJOR, LMSCON_MINOR + c->index);
}
#endif


/*
 *	Register console.
 */

static int __init lms_console_init(void)
{
	printk("Console: E2K system console\n");
//	e2k_debug_puts("Console: LMS system console\n");
	register_console(&lms_serial_console);
	return 0;
}

console_initcall(lms_console_init);

//#endif /* CONFIG_SERIAL_CONSOLE */

static void __exit lms_exit(void)
{
	int chan;

	for (chan = 0; chan < LMS_NPORTS; chan++)
		uart_remove_one_port(&lms_uart_driver, &lms_ports[chan].port);

	uart_unregister_driver(&lms_uart_driver);
}

module_init(lms_init);
module_exit(lms_exit);
