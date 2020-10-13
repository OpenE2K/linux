/*
 * IEEE-1284 implementation for parport.
 *
 * Authors: Phil Blundell <philb@gnu.org>
 *          Carsten Gross <carsten@sol.wohnheim.uni-ulm.de>
 *	    Jose Renau <renau@acm.org>
 *          Tim Waugh <tim@cyberelk.demon.co.uk> (largely rewritten)
 *
 * This file is responsible for IEEE 1284 negotiation, and for handing
 * read/write requests to low-level drivers.
 *
 * Any part of this program may be used in documents licensed under
 * the GNU Free Documentation License, Version 1.1 or any later version
 * published by the Free Software Foundation.
 *
 * Various hacks, Fred Barnes <frmb2@ukc.ac.uk>, 04/2000
 */

#include <linux/module.h>
#include <linux/threads.h>
#include <linux/parport.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/sched.h>

#undef DEBUG /* undef me for production */

#ifdef CONFIG_LP_CONSOLE
#undef DEBUG /* Don't want a garbled console */
#endif

#ifdef DEBUG
#define DPRINTK(stuff...) printk (stuff)
#else
#define DPRINTK(stuff...)
#endif

#ifdef _WORKAROUND_MCST_PP

extern size_t parport_write_block_dma_compat (struct parport *port,
					       const void *buf, size_t length);
#endif /*   _WORKAROUND_MCST_PP  */

/* Make parport_wait_peripheral wake up.
 * It will be useful to call this from an interrupt handler. */
static void parport_ieee1284_wakeup (struct parport *port)
{
	up (&port->physport->ieee1284.irq);
}

static struct parport *port_from_cookie[PARPORT_MAX];
static void timeout_waiting_on_port (unsigned long cookie)
{
	parport_ieee1284_wakeup (port_from_cookie[cookie % PARPORT_MAX]);
}

/**
 *	parport_wait_event - wait for an event on a parallel port
 *	@port: port to wait on
 *	@timeout: time to wait (in jiffies)
 *
 *	This function waits for up to @timeout jiffies for an
 *	interrupt to occur on a parallel port.  If the port timeout is
 *	set to zero, it returns immediately.
 *
 *	If an interrupt occurs before the timeout period elapses, this
 *	function returns zero immediately.  If it times out, it returns
 *	one.  An error code less than zero indicates an error (most
 *	likely a pending signal), and the calling code should finish
 *	what it's doing as soon as it can.
 */

int parport_wait_event (struct parport *port, signed long timeout)
{
	int ret;
	struct timer_list timer;

	if (!port->physport->cad->timeout)
		/* Zero timeout is special, and we can't down() the
		   semaphore. */
		return 1;

	init_timer_on_stack(&timer);
	timer.expires = jiffies + timeout;
	timer.function = timeout_waiting_on_port;
	port_from_cookie[port->number % PARPORT_MAX] = port;
	timer.data = port->number;

	add_timer (&timer);
	ret = down_interruptible (&port->physport->ieee1284.irq);
	if (!del_timer_sync(&timer) && !ret)
		/* Timed out. */
		ret = 1;

	destroy_timer_on_stack(&timer);

	return ret;
}

/**
 *	parport_poll_peripheral - poll status lines
 *	@port: port to watch
 *	@mask: status lines to watch
 *	@result: desired values of chosen status lines
 *	@usec: timeout
 *
 *	This function busy-waits until the masked status lines have
 *	the desired values, or until the timeout period elapses.  The
 *	@mask and @result parameters are bitmasks, with the bits
 *	defined by the constants in parport.h: %PARPORT_STATUS_BUSY,
 *	and so on.
 *
 *	This function does not call schedule(); instead it busy-waits
 *	using udelay().  It currently has a resolution of 5usec.
 *
 *	If the status lines take on the desired values before the
 *	timeout period elapses, parport_poll_peripheral() returns zero
 *	immediately.  A return value greater than zero indicates
 *	a timeout.  An error code (less than zero) indicates an error,
 *	most likely a signal that arrived, and the caller should
 *	finish what it is doing as soon as possible.
*/

int parport_poll_peripheral(struct parport *port,
			    unsigned char mask,
			    unsigned char result,
			    int usec)
{
	/* Zero return code is success, >0 is timeout. */
	int count = usec / 5 + 2;
	int i;
	unsigned char status;
	for (i = 0; i < count; i++) {
		status = parport_read_status (port);
		if ((status & mask) == result)
			return 0;
		if (signal_pending (current))
			return -EINTR;
		if (need_resched())
			break;
		if (i >= 2)
			udelay (5);
	}

	return 1;
}

/**
 *	parport_wait_peripheral - wait for status lines to change in 35ms
 *	@port: port to watch
 *	@mask: status lines to watch
 *	@result: desired values of chosen status lines
 *
 *	This function waits until the masked status lines have the
 *	desired values, or until 35ms have elapsed (see IEEE 1284-1994
 *	page 24 to 25 for why this value in particular is hardcoded).
 *	The @mask and @result parameters are bitmasks, with the bits
 *	defined by the constants in parport.h: %PARPORT_STATUS_BUSY,
 *	and so on.
 *
 *	The port is polled quickly to start off with, in anticipation
 *	of a fast response from the peripheral.  This fast polling
 *	time is configurable (using /proc), and defaults to 500usec.
 *	If the timeout for this port (see parport_set_timeout()) is
 *	zero, the fast polling time is 35ms, and this function does
 *	not call schedule().
 *
 *	If the timeout for this port is non-zero, after the fast
 *	polling fails it uses parport_wait_event() to wait for up to
 *	10ms, waking up if an interrupt occurs.
 */

int parport_wait_peripheral(struct parport *port,
			    unsigned char mask, 
			    unsigned char result)
{
	int ret;
	int usec;
	unsigned long deadline;
	unsigned char status;

	usec = port->physport->spintime; /* usecs of fast polling */
	if (!port->physport->cad->timeout)
		/* A zero timeout is "special": busy wait for the
		   entire 35ms. */
		usec = 35000;

	/* Fast polling.
	 *
	 * This should be adjustable.
	 * How about making a note (in the device structure) of how long
	 * it takes, so we know for next time?
	 */
	ret = parport_poll_peripheral (port, mask, result, usec);
	if (ret != 1)
		return ret;

	if (!port->physport->cad->timeout)
		/* We may be in an interrupt handler, so we can't poll
		 * slowly anyway. */
		return 1;

	/* 40ms of slow polling. */
	deadline = jiffies + msecs_to_jiffies(40);
	while (time_before (jiffies, deadline)) {
		if (signal_pending (current))
			return -EINTR;

		/* Wait for 10ms (or until an interrupt occurs if
		 * the handler is set) */
		if ((ret = parport_wait_event (port, msecs_to_jiffies(10))) < 0)
			return ret;

		status = parport_read_status (port);
		if ((status & mask) == result)
			return 0;

		if (!ret) {
			/* parport_wait_event didn't time out, but the
			 * peripheral wasn't actually ready either.
			 * Wait for another 10ms. */
			schedule_timeout_interruptible(msecs_to_jiffies(10));
		}
	}

	return 1;
}

#ifdef CONFIG_PARPORT_1284
/* Terminate a negotiated mode. */
static void parport_ieee1284_terminate (struct parport *port)
{
	int r;
#ifdef _WORKAROUND_MCST_PP
	struct parport_pc_private *priv = port->private_data;
#endif /* _WORKAROUND_MCST_PP */

	port = port->physport;

#ifdef _WORKAROUND_MCST_PP
	if (priv->driver_data == mcst_pp_iee1284){
		char ppc_cr = 0;
		/* Turn controler in mPS2 mode */
		ppc_cr = inb(ECONTROL(port));
		ppc_cr = ((ppc_cr & 0xf8) | mPS2);
//		ppc_cr = ((ppc_cr & 0xf8) | 0x01);

		outb(ppc_cr, ECONTROL(port));
	}
#endif /* _WORKAROUND_MCST_PP */

	/* EPP terminates differently. */
	switch (port->ieee1284.mode) {
	case IEEE1284_MODE_EPP:
	case IEEE1284_MODE_EPPSL:
	case IEEE1284_MODE_EPPSWE:
		/* Terminate from EPP mode. */

		/* Event 68: Set nInit low */
		parport_frob_control (port, PARPORT_CONTROL_INIT, 0);
		udelay (50);

		/* Event 69: Set nInit high, nSelectIn low */
		parport_frob_control (port,
				      PARPORT_CONTROL_SELECT
				      | PARPORT_CONTROL_INIT,
				      PARPORT_CONTROL_SELECT
				      | PARPORT_CONTROL_INIT);
		break;

	case IEEE1284_MODE_ECP:
	case IEEE1284_MODE_ECPRLE:
	case IEEE1284_MODE_ECPSWE:
		/* In ECP we can only terminate from fwd idle phase. */
		if (port->ieee1284.phase != IEEE1284_PH_FWD_IDLE) {
			/* Event 47: Set nInit high */
			parport_frob_control (port,
					      PARPORT_CONTROL_INIT
					      | PARPORT_CONTROL_AUTOFD,
					      PARPORT_CONTROL_INIT
					      | PARPORT_CONTROL_AUTOFD);

			/* Event 49: PError goes high */
			r = parport_wait_peripheral (port,
						     PARPORT_STATUS_PAPEROUT,
						     PARPORT_STATUS_PAPEROUT);
			if (r)
				DPRINTK (KERN_INFO "%s: Timeout at event 49\n",
					 port->name);

			parport_data_forward (port);
			DPRINTK (KERN_DEBUG "%s: ECP direction: forward\n",
				 port->name);
			port->ieee1284.phase = IEEE1284_PH_FWD_IDLE;
		}

		/* fall-though.. */

	default:
		/* Terminate from all other modes. */

		/* Event 22: Set nSelectIn low, nAutoFd high */
		parport_frob_control (port,
				      PARPORT_CONTROL_SELECT
				      | PARPORT_CONTROL_AUTOFD,
				      PARPORT_CONTROL_SELECT);

		/* Event 24: nAck goes low */
		r = parport_wait_peripheral (port, PARPORT_STATUS_ACK, 0);
		if (r)
			DPRINTK (KERN_INFO "%s: Timeout at event 24\n",
				 port->name);

		/* Event 25: Set nAutoFd low */
		parport_frob_control (port,
				      PARPORT_CONTROL_AUTOFD,
				      PARPORT_CONTROL_AUTOFD);

		/* Event 27: nAck goes high */
		r = parport_wait_peripheral (port,
					     PARPORT_STATUS_ACK, 
					     PARPORT_STATUS_ACK);
		if (r)
			DPRINTK (KERN_INFO "%s: Timeout at event 27\n",
				 port->name);

		/* Event 29: Set nAutoFd high */
		parport_frob_control (port, PARPORT_CONTROL_AUTOFD, 0);
	}

	port->ieee1284.mode = IEEE1284_MODE_COMPAT;
	port->ieee1284.phase = IEEE1284_PH_FWD_IDLE;

#ifdef _WORKAROUND_MCST_PP
	/* Now controller resetting step */
	if (priv->driver_data == mcst_pp_iee1284) {

		char icr = Full_Intr_AllowedEn;
		short ppc_sr = Full_Intr_Allowed;
		char ppc_cr;

		ppc_cr = inb(ECONTROL(port));
		ppc_cr = ((ppc_cr & 0xfd) | (1 << 5)); /* reset bit */
		outb(ppc_cr, ECONTROL(port));
		udelay(50);

	/* Interrups enabling */
		outw(ppc_sr, PPC_SR(port));
		outb(icr, ICR(port));
	}
#endif /* _WORKAROUND_MCST_PP */

	DPRINTK (KERN_DEBUG "%s: In compatibility (forward idle) mode\n",
		 port->name);
}		
#endif /* IEEE1284 support */

/**
 *	parport_negotiate - negotiate an IEEE 1284 mode
 *	@port: port to use
 *	@mode: mode to negotiate to
 *
 *	Use this to negotiate to a particular IEEE 1284 transfer mode.
 *	The @mode parameter should be one of the constants in
 *	parport.h starting %IEEE1284_MODE_xxx.
 *
 *	The return value is 0 if the peripheral has accepted the
 *	negotiation to the mode specified, -1 if the peripheral is not
 *	IEEE 1284 compliant (or not present), or 1 if the peripheral
 *	has rejected the negotiation.
 */

int parport_negotiate (struct parport *port, int mode)
{
#ifndef CONFIG_PARPORT_1284
	if (mode == IEEE1284_MODE_COMPAT)
		return 0;
	printk (KERN_ERR "parport: IEEE1284 not supported in this kernel\n");
	return -1;
#else
	int m = mode & ~IEEE1284_ADDR;
	int r;
	unsigned char xflag;

#ifdef _WORKAROUND_MCST_PP
	struct parport_pc_private *priv = port->private_data;
	char ppc_cr = 0;
#endif /* _WORKAROUND_MCST_PP */

	port = port->physport;

	/* Is there anything to do? */
	if (port->ieee1284.mode == mode)
		return 0;

	/* Is the difference just an address-or-not bit? */
	if ((port->ieee1284.mode & ~IEEE1284_ADDR) == (mode & ~IEEE1284_ADDR)){
		port->ieee1284.mode = mode;
		return 0;
	}

	/* Go to compability forward idle mode */
	if (port->ieee1284.mode != IEEE1284_MODE_COMPAT)
		parport_ieee1284_terminate (port);

	if (mode == IEEE1284_MODE_COMPAT)
		/* Compatibility mode: no negotiation. */
		return 0; 

#ifdef _WORKAROUND_MCST_PP
	/* Put controller in HOST */
	if (priv->driver_data == mcst_pp_iee1284) {
		ppc_cr = 0xa3;
		outb(ppc_cr, PPC_MODE(port));
	}
#endif /* _WORKAROUND_MCST_PP */

	switch (mode) {
	case IEEE1284_MODE_ECPSWE:
		m = IEEE1284_MODE_ECP;
		break;
	case IEEE1284_MODE_EPPSL:
	case IEEE1284_MODE_EPPSWE:
		m = IEEE1284_MODE_EPP;
		break;
	case IEEE1284_MODE_BECP:
		return -ENOSYS; /* FIXME (implement BECP) */
	}

	if (mode & IEEE1284_EXT_LINK)
		m = 1<<7; /* request extensibility link */

	port->ieee1284.phase = IEEE1284_PH_NEGOTIATION;

	/* Start off with nStrobe and nAutoFd high, and nSelectIn low */
	parport_frob_control (port,
			      PARPORT_CONTROL_STROBE
			      | PARPORT_CONTROL_AUTOFD
			      | PARPORT_CONTROL_SELECT,
			      PARPORT_CONTROL_SELECT);
	udelay(1);

	/* Event 0: Set data */
	parport_data_forward (port);
	parport_write_data (port, m);
	udelay (400); /* Shouldn't need to wait this long. */

	/* Event 1: Set nSelectIn high, nAutoFd low */
	parport_frob_control (port,
			      PARPORT_CONTROL_SELECT
			      | PARPORT_CONTROL_AUTOFD,
			      PARPORT_CONTROL_AUTOFD);

	/* Event 2: PError, Select, nFault go high, nAck goes low */
	if (parport_wait_peripheral (port,
				     PARPORT_STATUS_ERROR
				     | PARPORT_STATUS_SELECT
				     | PARPORT_STATUS_PAPEROUT
				     | PARPORT_STATUS_ACK,
				     PARPORT_STATUS_ERROR
				     | PARPORT_STATUS_SELECT
				     | PARPORT_STATUS_PAPEROUT)) {
		/* Timeout */
		parport_frob_control (port,
				      PARPORT_CONTROL_SELECT
				      | PARPORT_CONTROL_AUTOFD,
				      PARPORT_CONTROL_SELECT);
		DPRINTK (KERN_DEBUG
			 "%s: Peripheral not IEEE1284 compliant (0x%02X)\n",
			 port->name, parport_read_status (port));
		port->ieee1284.phase = IEEE1284_PH_FWD_IDLE;
		return -1; /* Not IEEE1284 compliant */
	}

	/* Event 3: Set nStrobe low */
	parport_frob_control (port,
			      PARPORT_CONTROL_STROBE,
			      PARPORT_CONTROL_STROBE);

	/* Event 4: Set nStrobe and nAutoFd high */
	udelay (5);
	parport_frob_control (port,
			      PARPORT_CONTROL_STROBE
			      | PARPORT_CONTROL_AUTOFD,
			      0);

	/* Event 6: nAck goes high */
	if (parport_wait_peripheral (port,
				     PARPORT_STATUS_ACK,
				     PARPORT_STATUS_ACK)) {
		/* This shouldn't really happen with a compliant device. */
		DPRINTK (KERN_DEBUG
			 "%s: Mode 0x%02x not supported? (0x%02x)\n",
			 port->name, mode, port->ops->read_status (port));
		parport_ieee1284_terminate (port);
		return 1;
	}

	xflag = parport_read_status (port) & PARPORT_STATUS_SELECT;

	/* xflag should be high for all modes other than nibble (0). */
	if (mode && !xflag) {
		/* Mode not supported. */
		DPRINTK (KERN_DEBUG "%s: Mode 0x%02x rejected by peripheral\n",
			 port->name, mode);
		parport_ieee1284_terminate (port);
		return 1;
	}

	/* More to do if we've requested extensibility link. */
	if (mode & IEEE1284_EXT_LINK) {
		m = mode & 0x7f;
		udelay (1);
		parport_write_data (port, m);
		udelay (1);

		/* Event 51: Set nStrobe low */
		parport_frob_control (port,
				      PARPORT_CONTROL_STROBE,
				      PARPORT_CONTROL_STROBE);

		/* Event 52: nAck goes low */
		if (parport_wait_peripheral (port, PARPORT_STATUS_ACK, 0)) {
			/* This peripheral is _very_ slow. */
			DPRINTK (KERN_DEBUG
				 "%s: Event 52 didn't happen\n",
				 port->name);
			parport_ieee1284_terminate (port);
			return 1;
		}

		/* Event 53: Set nStrobe high */
		parport_frob_control (port,
				      PARPORT_CONTROL_STROBE,
				      0);

		/* Event 55: nAck goes high */
		if (parport_wait_peripheral (port,
					     PARPORT_STATUS_ACK,
					     PARPORT_STATUS_ACK)) {
			/* This shouldn't really happen with a compliant
			 * device. */
			DPRINTK (KERN_DEBUG
				 "%s: Mode 0x%02x not supported? (0x%02x)\n",
				 port->name, mode,
				 port->ops->read_status (port));
			parport_ieee1284_terminate (port);
			return 1;
		}

		/* Event 54: Peripheral sets XFlag to reflect support */
		xflag = parport_read_status (port) & PARPORT_STATUS_SELECT;

		/* xflag should be high. */
		if (!xflag) {
			/* Extended mode not supported. */
			DPRINTK (KERN_DEBUG "%s: Extended mode 0x%02x not "
				 "supported\n", port->name, mode);
			parport_ieee1284_terminate (port);
			return 1;
		}

		/* Any further setup is left to the caller. */
	}

	/* Mode is supported */
	DPRINTK (KERN_DEBUG "%s: In mode 0x%02x\n", port->name, mode);
	port->ieee1284.mode = mode;

	/* But ECP is special */
	if (!(mode & IEEE1284_EXT_LINK) && (m & IEEE1284_MODE_ECP)) {
		port->ieee1284.phase = IEEE1284_PH_ECP_SETUP;

		/* Event 30: Set nAutoFd low */
		parport_frob_control (port,
				      PARPORT_CONTROL_AUTOFD,
				      PARPORT_CONTROL_AUTOFD);

		/* Event 31: PError goes high. */
		r = parport_wait_peripheral (port,
					     PARPORT_STATUS_PAPEROUT,
					     PARPORT_STATUS_PAPEROUT);
		if (r) {
			DPRINTK (KERN_INFO "%s: Timeout at event 31\n",
				port->name);
		}

		port->ieee1284.phase = IEEE1284_PH_FWD_IDLE;
		DPRINTK (KERN_DEBUG "%s: ECP direction: forward\n",
			 port->name);
	} else switch (mode) {
	case IEEE1284_MODE_NIBBLE:
	case IEEE1284_MODE_BYTE:
		port->ieee1284.phase = IEEE1284_PH_REV_IDLE;
		break;
	default:
		port->ieee1284.phase = IEEE1284_PH_FWD_IDLE;
	}


	return 0;
#endif /* IEEE1284 support */
}

/* Acknowledge that the peripheral has data available.
 * Events 18-20, in order to get from Reverse Idle phase
 * to Host Busy Data Available.
 * This will most likely be called from an interrupt.
 * Returns zero if data was available.
 */
#ifdef CONFIG_PARPORT_1284
static int parport_ieee1284_ack_data_avail (struct parport *port)
{
	if (parport_read_status (port) & PARPORT_STATUS_ERROR)
		/* Event 18 didn't happen. */
		return -1;

	/* Event 20: nAutoFd goes high. */
	port->ops->frob_control (port, PARPORT_CONTROL_AUTOFD, 0);
	port->ieee1284.phase = IEEE1284_PH_HBUSY_DAVAIL;
	return 0;
}
#endif /* IEEE1284 support */

/* Handle an interrupt. */
void parport_ieee1284_interrupt (void *handle)
{
	struct parport *port = handle;
	parport_ieee1284_wakeup (port);

#ifdef CONFIG_PARPORT_1284
	if (port->ieee1284.phase == IEEE1284_PH_REV_IDLE) {
		/* An interrupt in this phase means that data
		 * is now available. */
		DPRINTK (KERN_DEBUG "%s: Data available\n", port->name);
		parport_ieee1284_ack_data_avail (port);
	}
#endif /* IEEE1284 support */
}

#ifdef _WORKAROUND_MCST_PP
#include <asm/dma.h>
#include <linux/pci.h>

size_t parport_write_block_dma_compat (struct parport *port,
					       const void *buf, size_t length)
{
	int ret = 0;
	unsigned long dmaflag;
	size_t left = (length / 4); /* words */
	const struct parport_pc_private *priv = port->physport->private_data;
	dma_addr_t dma_addr = 0;
	dma_addr_t dma_handle = 0;
	size_t maxlen = 0x1000000; /* max number of 4 bytes per DMA transfer */
	char regval = 0;
	char icr = 0;
	char ppc_cr = 0;
	int cnt = 0;
                       /* put it in mSPPh mode */
       ppc_cr = inb(ECONTROL(port));
       outb(((ppc_cr & 0xf8) | mSPPh), ECONTROL(port));

	DPRINTK( "enter parport_write_block_dma_compat, length = 0x%lx\n", length);
	if (length >= (maxlen * 4)){
		printk("parport_write_block_dma_compat: too much given data length: 0x%lx\n",
			length);
		return length - (left * 4);
	}
	dma_addr = dma_handle = pci_map_single(priv->dev, (void *)buf, length,
				       		PCI_DMA_TODEVICE);
	DPRINTK("parport_write_block_dma_compat: given buf addr: 0x%lx, dma addr: 0x%x\n",
		(unsigned long)buf, (unsigned int)dma_addr);
	port = port->physport;

	/* We don't want to get Periph_IntrEn every character, so disable it. */
	
	icr = Full_Intr_AllowedEn & ~ Periph_IntrEn;
	outb(icr, ICR(port));
	/* Forward mode. */
	parport_pc_data_forward (port); /* Must be in mSPPh mode (for Compatibility) */

	/* set dma direction 1: RAM -> device */

	ppc_cr = inb(ECONTROL(port));
	ppc_cr = ppc_cr | (1 << 4);
	outb(ppc_cr, ECONTROL(port));

	local_save_flags(dmaflag);
	//while (left > 3) { //niki
	do {
		unsigned long expire = jiffies + port->cad->timeout;

		size_t count = left & 0xfffff8;
		// niki dmaflag = claim_dma_lock();

		outl(dma_addr, DMAADDR(port));			/* set dma addr */
		outl((count & 0xfffff8), DMACOUNT(port));	/* set dma count */
		regval = inb(ECONTROL(port));
		outb((regval | (1 << 6)), ECONTROL(port)); 	/* enable dma */
		//if (cnt != 5)
			
		// niki release_dma_lock(dmaflag);

		if (cnt != 5){
			DPRINTK("parport_write_block_dma_compat: count = 0x%lx, dma_addr = 0x%lx\n", 
											count, dma_addr);
		}
		/* assume DMA will be successful */
		left -= count;
		buf  += (count * 4);
		if (dma_handle) dma_addr += (count * 4);

		/* Wait for interrupt. */
//	false_alarm:
		mdelay(500);
		ret = parport_wait_event (port, 100*HZ);
		if (ret < 0) {
			printk("parport_write_block_dma_compat: some error has happend\n");
			break; /* Error.. for example signal pending */
		}
		
		while (!time_before (jiffies, expire)) {
			if (inw (PPC_SR(port)) & 0x2)
			    break;
			mdelay(500);
		}
		ret = 0;
		if (!time_before (jiffies, expire)) {
			/* Timed out. */
			printk ("parport_write_block_dma_compat: DMA write timed out\n");
			break;
		}
		//niki dmaflag = claim_dma_lock();
		regval = inb(ECONTROL(port));
		outb((regval & ~ (1 << 6)), ECONTROL(port)); 	/* disable dma */
		udelay(500);
		count = inl(DMACOUNT(port));			/* get dma residue */
		//niki release_dma_lock(dmaflag);

		if (cnt != 5){
			DPRINTK("parport_write_block_dma_compat: new count = 0x%lx, dma_addr = 0x%lx\n", 
										count, dma_addr);
		}
		cnt++;

		cond_resched(); /* Can't yield the port. */

		/* Anyone else waiting for the port? */
		if (port->waithead) {
			printk ("parport_write_block_dma_compat: Somebody wants the port\n");
			break;
		}

		/* update for possible DMA residue ! */
		buf  -= (count * 4);
		//left += count;
		if (dma_handle) dma_addr -= (count * 4);
	//niki}
	} while(0);

	/* Maybe got here through break, so adjust for DMA residue! */
	regval = inb(ECONTROL(port));
	outb((regval & ~ (1 << 6)), ECONTROL(port)); /* disable dma */
	left += inl(DMACOUNT(port));		/* get dma residue */
	//niki release_dma_lock(dmaflag);

	icr = Full_Intr_AllowedEn;
	outb(icr, ICR(port));

	if (dma_handle)
		pci_unmap_single(priv->dev, dma_handle, length, PCI_DMA_TODEVICE);

	DPRINTK ("leave parport_write_block_dma_compat, written 0x%lx bytes\n", 
								(length - (left * 4)));
	// Reset dma
	outb(mPS2, ECONTROL(port));
	udelay(500);
	return length - (left * 4);
}
#endif

/**
 *	parport_write - write a block of data to a parallel port
 *	@port: port to write to
 *	@buffer: data buffer (in kernel space)
 *	@len: number of bytes of data to transfer
 *
 *	This will write up to @len bytes of @buffer to the port
 *	specified, using the IEEE 1284 transfer mode most recently
 *	negotiated to (using parport_negotiate()), as long as that
 *	mode supports forward transfers (host to peripheral).
 *
 *	It is the caller's responsibility to ensure that the first
 *	@len bytes of @buffer are valid.
 *
 *	This function returns the number of bytes transferred (if zero
 *	or positive), or else an error code.
 */

ssize_t parport_write (struct parport *port, const void *buffer, size_t len)
{
#ifndef CONFIG_PARPORT_1284
	return port->ops->compat_write_data (port, buffer, len, 0);
#else
	int mode = port->ieee1284.mode;
	int addr = mode & IEEE1284_ADDR;
	size_t (*fn) (struct parport *, const void *, size_t, int);
	ssize_t retval = 0;

#ifdef _WORKAROUND_MCST_PP
	char ppc_cr = 0;
	struct parport_pc_private *priv = port->private_data;
#endif /* _WORKAROUND_MCST_PP */

	/* Ignore the device-ID-request bit and the address bit. */
	mode &= ~(IEEE1284_DEVICEID | IEEE1284_ADDR);

	/* Use the mode we're in. */
	switch (mode) {
	case IEEE1284_MODE_NIBBLE:
	case IEEE1284_MODE_BYTE:
		parport_negotiate (port, IEEE1284_MODE_COMPAT);
	case IEEE1284_MODE_COMPAT:
		DPRINTK (KERN_DEBUG "%s: Using compatibility mode\n",
			 port->name);
#ifdef _WORKAROUND_MCST_PP
		if ((priv->driver_data == mcst_pp_iee1284) ) {
		    //if (priv->parport_rev > 0) {
			/* put it in mSPPh mode */
			if (len & 0x3ffffe0) {
				retval = parport_write_block_dma_compat(port, buffer, (len & 0x3ffffe0));
				DPRINTK("parport_write: wrote by dma in compatibility 0x%lx bytes ********\n", retval);
				if (retval < len){
					len = len - retval;
					buffer = buffer + retval;
					DPRINTK("parport_write: only 0x%lx bytes has been written by dma operation\n",
												retval);
				}else if (retval > len){
					DPRINTK("parport_write: wrote by dma in compatibility 0x%lx bytes cannot be "
					       " > given len : 0x%lx\n", retval, len);
					return retval;
				}else if (retval == len){
					DPRINTK("parport_write: given buf size is 32 bytes aligned and has been written !!!\n");
					return retval;
					
				}
			}
		    //}
		ppc_cr = inb(ECONTROL(port));
		outb(((ppc_cr & 0xf8) | mSPPs), ECONTROL(port));
		}
#endif /* _WORKAROUND_MCST_PP */
		fn = port->ops->compat_write_data;
		break;

	case IEEE1284_MODE_EPP:
		DPRINTK (KERN_DEBUG "%s: Using EPP mode\n", port->name);

#ifdef _WORKAROUND_MCST_PP
		if (priv->driver_data == mcst_pp_iee1284) {
			/* Turn controler in mEPP mode, epp 1.9 by default */
			ppc_cr = inb(ECONTROL(port));
			ppc_cr = ((ppc_cr & 0xf8) | mEPP);
			outb(ppc_cr, ECONTROL(port));
		}
#endif /* _WORKAROUND_MCST_PP */
		if (addr) {
			fn = port->ops->epp_write_addr;
		} else {
			fn = port->ops->epp_write_data;
		}
		break;
	case IEEE1284_MODE_EPPSWE:
		DPRINTK (KERN_DEBUG "%s: Using software-emulated EPP mode\n",
			port->name);
#ifdef _WORKAROUND_MCST_PP

		if (priv->driver_data == mcst_pp_iee1284) {
			/* Turn controler in mEPP mode, epp 1.9 by default */
			ppc_cr = inb(ECONTROL(port));
			ppc_cr = ((ppc_cr & 0xf8) | mEPP);
			outb(ppc_cr, ECONTROL(port));
		}

#endif /* _WORKAROUND_MCST_PP */

		if (addr) {
			fn = parport_ieee1284_epp_write_addr;
		} else {
			fn = parport_ieee1284_epp_write_data;
		}
		break;
	case IEEE1284_MODE_ECP:
	case IEEE1284_MODE_ECPRLE:
		DPRINTK (KERN_DEBUG "%s: Using ECP mode\n", port->name);
#ifdef _WORKAROUND_MCST_PP
		if (priv->driver_data == mcst_pp_iee1284) {
			/* Turn controler in mECP mode */
			ppc_cr = inb(ECONTROL(port));
			ppc_cr = ((ppc_cr & 0xf8) | mECP);
			outb(ppc_cr, ECONTROL(port));
		}
#endif /* _WORKAROUND_MCST_PP */

		if (addr) {
			fn = port->ops->ecp_write_addr;
		} else {
			fn = port->ops->ecp_write_data;
		}
		break;
	case IEEE1284_MODE_ECPSWE:
		DPRINTK (KERN_DEBUG "%s: Using software-emulated ECP mode\n",
			 port->name);
#ifdef _WORKAROUND_MCST_PP
		if (priv->driver_data == mcst_pp_iee1284) {
			/* Turn controler in mECP mode */
			ppc_cr = inb(ECONTROL(port));
			ppc_cr = ((ppc_cr & 0xf8) | mECP);
			outb(ppc_cr, ECONTROL(port));
		}
#endif /* _WORKAROUND_MCST_PP */

		/* The caller has specified that it must be emulated,
		 * even if we have ECP hardware! */
		if (addr) {
			fn = parport_ieee1284_ecp_write_addr;
		} else {
			fn = parport_ieee1284_ecp_write_data;
		}
		break;

	default:
		DPRINTK (KERN_DEBUG "%s: Unknown mode 0x%02x\n", port->name,
			port->ieee1284.mode);
		return -ENOSYS;
	}
#ifdef _WORKAROUND_MCST_PP
	retval = retval + (*fn) (port, buffer, len, 0);
#else
	retval = (*fn) (port, buffer, len, 0);
#endif
	DPRINTK (KERN_DEBUG "%s: wrote %d/%d bytes\n", port->name, retval, len);
	return retval;
#endif /* IEEE1284 support */
}

/**
 *	parport_read - read a block of data from a parallel port
 *	@port: port to read from
 *	@buffer: data buffer (in kernel space)
 *	@len: number of bytes of data to transfer
 *
 *	This will read up to @len bytes of @buffer to the port
 *	specified, using the IEEE 1284 transfer mode most recently
 *	negotiated to (using parport_negotiate()), as long as that
 *	mode supports reverse transfers (peripheral to host).
 *
 *	It is the caller's responsibility to ensure that the first
 *	@len bytes of @buffer are available to write to.
 *
 *	This function returns the number of bytes transferred (if zero
 *	or positive), or else an error code.
 */

ssize_t parport_read (struct parport *port, void *buffer, size_t len)
{
#ifndef CONFIG_PARPORT_1284
	printk (KERN_ERR "parport: IEEE1284 not supported in this kernel\n");
	return -ENODEV;
#else
	int mode = port->physport->ieee1284.mode;
	int addr = mode & IEEE1284_ADDR;
	size_t (*fn) (struct parport *, void *, size_t, int);

#ifdef _WORKAROUND_MCST_PP
	char ppc_cr = 0;
	struct parport_pc_private *priv = port->private_data;
#endif /* _WORKAROUND_MCST_PP */
	/* Ignore the device-ID-request bit and the address bit. */
	mode &= ~(IEEE1284_DEVICEID | IEEE1284_ADDR);

	/* Use the mode we're in. */
	switch (mode) {
	case IEEE1284_MODE_COMPAT:
		/* if we can tri-state use BYTE mode instead of NIBBLE mode,
		 * if that fails, revert to NIBBLE mode -- ought to store somewhere
		 * the device's ability to do BYTE mode reverse transfers, so we don't
		 * end up needlessly calling negotiate(BYTE) repeately..  (fb)
		 */
		if ((port->physport->modes & PARPORT_MODE_TRISTATE) &&
		    !parport_negotiate (port, IEEE1284_MODE_BYTE)) {
			/* got into BYTE mode OK */
			DPRINTK (KERN_DEBUG "%s: Using byte mode\n", port->name);
#ifdef _WORKAROUND_MCST_PP
			if (priv->driver_data == mcst_pp_iee1284) {
				/* put it in mSP2 mode */
				ppc_cr = inb(ECONTROL(port));
				ppc_cr = ((ppc_cr & 0xf8) | mPS2);
				outb(ppc_cr, ECONTROL(port));
			}

#endif /* _WORKAROUND_MCST_PP */
			fn = port->ops->byte_read_data;
			break;
		}
		if (parport_negotiate (port, IEEE1284_MODE_NIBBLE)) {
			return -EIO;
		}
		/* fall through to NIBBLE */
	case IEEE1284_MODE_NIBBLE:
		DPRINTK (KERN_DEBUG "%s: Using nibble mode\n", port->name);
#ifdef _WORKAROUND_MCST_PP
		if (priv->driver_data == mcst_pp_iee1284) {
			if (parport_negotiate (port, IEEE1284_MODE_NIBBLE)) {
				return -EIO;
			}
			/* put it in mSPPh mode */
			ppc_cr = inb(ECONTROL(port));
			ppc_cr = ((ppc_cr & 0xf8) | mSPPh);
			outb(ppc_cr, ECONTROL(port));
		}
#endif /* _WORKAROUND_MCST_PP */
		fn = port->ops->nibble_read_data;
		break;

	case IEEE1284_MODE_BYTE:
		DPRINTK (KERN_DEBUG "%s: Using byte mode\n", port->name);
#ifdef _WORKAROUND_MCST_PP
		if (priv->driver_data == mcst_pp_iee1284) {
			/* Turn controler in mSP2 mode */
			ppc_cr = inb(ECONTROL(port));
			ppc_cr = ((ppc_cr & 0xf8) | mPS2);
			outb(ppc_cr, ECONTROL(port));
		}

#endif /* _WORKAROUND_MCST_PP */
		fn = port->ops->byte_read_data;
		break;

	case IEEE1284_MODE_EPP:
		DPRINTK (KERN_DEBUG "%s: Using EPP mode\n", port->name);
#ifdef _WORKAROUND_MCST_PP
		if (priv->driver_data == mcst_pp_iee1284) {
			/* Turn controler in mEPP mode, epp 1.9 by default */
			ppc_cr = inb(ECONTROL(port));
			ppc_cr = ((ppc_cr & 0xf8) | mEPP);
			outb(ppc_cr, ECONTROL(port));
		}
#endif /* _WORKAROUND_MCST_PP */
		if (addr) {
			fn = port->ops->epp_read_addr;
		} else {
			fn = port->ops->epp_read_data;
		}
		break;
	case IEEE1284_MODE_EPPSWE:
		DPRINTK (KERN_DEBUG "%s: Using software-emulated EPP mode\n",
			port->name);
#ifdef _WORKAROUND_MCST_PP
		if (priv->driver_data == mcst_pp_iee1284) {
			/* Turn controler in mEPP mode, epp 1.9 by default */
			ppc_cr = inb(ECONTROL(port));
			ppc_cr = ((ppc_cr & 0xf8) | mEPP);
			outb(ppc_cr, ECONTROL(port));
		}
#endif /* _WORKAROUND_MCST_PP */
		if (addr) {
			fn = parport_ieee1284_epp_read_addr;
		} else {
			fn = parport_ieee1284_epp_read_data;
		}
		break;
	case IEEE1284_MODE_ECP:
	case IEEE1284_MODE_ECPRLE:
		DPRINTK (KERN_DEBUG "%s: Using ECP mode\n", port->name);
#ifdef _WORKAROUND_MCST_PP
		if (priv->driver_data == mcst_pp_iee1284) {
			/* Turn controler in mECP mode */
			ppc_cr = inb(ECONTROL(port));
			ppc_cr = ((ppc_cr & 0xf8) | mECP);
			outb(ppc_cr, ECONTROL(port));
		}
#endif /* _WORKAROUND_MCST_PP */
		fn = port->ops->ecp_read_data;
		break;

	case IEEE1284_MODE_ECPSWE:
		DPRINTK (KERN_DEBUG "%s: Using software-emulated ECP mode\n",
			 port->name);
#ifdef _WORKAROUND_MCST_PP
		if (priv->driver_data == mcst_pp_iee1284) {
			/* Turn controler in mECP mode */
			ppc_cr = inb(ECONTROL(port));
			ppc_cr = ((ppc_cr & 0xf8) | mECP);
			outb(ppc_cr, ECONTROL(port));
		}
#endif /* _WORKAROUND_MCST_PP */
		fn = parport_ieee1284_ecp_read_data;
		break;

	default:
		DPRINTK (KERN_DEBUG "%s: Unknown mode 0x%02x\n", port->name,
			 port->physport->ieee1284.mode);
		return -ENOSYS;
	}

	return (*fn) (port, buffer, len, 0);
#endif /* IEEE1284 support */
}

/**
 *	parport_set_timeout - set the inactivity timeout for a device
 *	@dev: device on a port
 *	@inactivity: inactivity timeout (in jiffies)
 *
 *	This sets the inactivity timeout for a particular device on a
 *	port.  This affects functions like parport_wait_peripheral().
 *	The special value 0 means not to call schedule() while dealing
 *	with this device.
 *
 *	The return value is the previous inactivity timeout.
 *
 *	Any callers of parport_wait_event() for this device are woken
 *	up.
 */

long parport_set_timeout (struct pardevice *dev, long inactivity)
{
	long int old = dev->timeout;

	dev->timeout = inactivity;

	if (dev->port->physport->cad == dev)
		parport_ieee1284_wakeup (dev->port);

	return old;
}

#if !(defined(PARPORT_MCSTBPP))

/* Exported symbols for modules. */

EXPORT_SYMBOL(parport_negotiate);
EXPORT_SYMBOL(parport_write);
EXPORT_SYMBOL(parport_read);
EXPORT_SYMBOL(parport_wait_peripheral);
EXPORT_SYMBOL(parport_wait_event);
EXPORT_SYMBOL(parport_set_timeout);
EXPORT_SYMBOL(parport_ieee1284_interrupt);

#endif /* _WORKAROUND_MCST_PP && CONFIG_PARPORT_SUNBPP */
