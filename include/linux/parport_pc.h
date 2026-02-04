/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_PARPORT_PC_H
#define __LINUX_PARPORT_PC_H

#include <asm/io.h>

/* --- register definitions ------------------------------- */

#define ECONTROL(p) ((p)->base_hi + 0x2)
#define CONFIGB(p)  ((p)->base_hi + 0x1)
#define CONFIGA(p)  ((p)->base_hi + 0x0)
#define FIFO(p)     ((p)->base_hi + 0x0)
#define EPPDATA(p)  ((p)->base    + 0x4)
#define EPPADDR(p)  ((p)->base    + 0x3)
#define CONTROL(p)  ((p)->base    + 0x2)
#define STATUS(p)   ((p)->base    + 0x1)
#define DATA(p)     ((p)->base    + 0x0)

#ifdef _WORKAROUND_MCST_PP

#define PPC_MODE(p) ((p)->base_hi + 0xf)
#define ICR(p)     ((p)->base_hi + 0xe)
#define HCR(p)     ((p)->base_hi + 0xc)
#define DMACOUNT(p) ((p)->base_hi + 0x8)
#define DMAADDR(p)  ((p)->base_hi + 0x4)
#define PPC_SR(p)   ((p)->base    + 0x8)

/* PPC_SR fields */
#define reqFIFOdelta	(0xf << 12) /* RO Number of PIO requests in reqFIFO buffer (0x8 max) */
#define WordFrac	(0x3 << 10) /* RO Number of bytes of 4-byte word on output of.
				     * dataFIFO buffer to write in peripherial device
				     * so as to finish current request */
#define StatusChange	(0x1 << 9)..
#define Threshold	(0x1 << 8)  /* reqFIFOdelta bit value changing from value 0x5 to 0x4.
				     * indication. It shows that second 16 bytes data segment is
				     * now able to be filled with another data */
#define DMA_SysReqErr	(0x1 << 7)
#define PIO_SysReqErr	(0x1 << 6)
#define Periph_Intr	(0x1 << 5)  /* Peripheral device interrupt */
#define reqFIFOErr	(0x1 << 4)  /* reqFIFO buffer overflow indication */
#define ECP_Err		(0x1 << 3)
#define TO		(0x1 << 2)  /* Peripheral device hanging during data exchange. Onle hardware
				     * mode */
#define DMA_active	(0x1 << 1)  /* DMA indication. 1 -> is now running 0 -> isn't running */
#define TC		(0x1 << 0)  /* Terminal Count. Data block transmition completion while.
				     * DMA mode. 1 if dma_wc (DMACOUNT) counter zeroed */

#define Normal_Intrs	(Threshold | TC | Periph_Intr)
#define Err_Intrs	(DMA_SysReqErr | PIO_SysReqErr | reqFIFOErr | ECP_Err | TO )

#define Full_Intr_Allowed (Err_Intrs | Normal_Intrs)
/* ICR fields */
#define MaskIntr	(0x1 << 7)  /* disable all interrupts if 1. If 0 enables all interrupts
				     * described below. These interrups must be specified by their
				     * own masks as disabled or enabled  */
#define Threshold_IntrEn (0x1 << 6) /* If 1 enables interrupt when Threshold event occures */
#define SysReqErr_IntrEn (0x1 << 5) /* If 1 enables interrupts when DMA_SysReqErr or PIO_SysReqErr
				     * events occur */
#define StatusChange_IntrEn	(0x1 << 4) /* If 1 enables interrupt when StatusChange event occures */
#define reqFIFOErr_IntrEn	(0x1 << 3) /* If 1 enables interrupt when reqFIFO event occures */
#define Periph_IntrEn	(0x1 << 2) /* If 1 enables interrupt when Periph_Intr event occures */
#define BusErr_IntrEn	(0x1 << 1) /* If 1 enables interrupts when ECP_Err or TO events occur */
#define TC_IntrEn	(0x1 << 0) /* If 1 enables interrupt when TC event occures */

#define Normal_IntrsEn	(Threshold_IntrEn | TC_IntrEn | Periph_IntrEn)
#define Err_IntrsEn	(SysReqErr_IntrEn | reqFIFOErr_IntrEn | BusErr_IntrEn)

#define Full_Intr_AllowedEn (Err_IntrsEn | Normal_IntrsEn)

/* For e3s only */
#define mSPPs	(0x00) /* That mode supports Compatibility and Nibble protocols */
#define mSPPh   (0x04) /* 100 That mode supports Compatibility and Nibble protocols */
#define mPS2	(0x01)
			/* 001 That mode supports Compatibility, Nibble, Byte, EPP, ECP Protocols.
		         and can implement Forward to Reverse, Reverse to Forward, Termination,
			 Negotiation, Setup cycles */
#define mECP	(0x07) /* 111 That mode supports ECP protocol */
#define mEPP	(0x06) /* 110 That mode supports EPP protocol */
#endif /*   _WORKAROUND_MCST_PP  */

struct parport_pc_private {
	/* Contents of CTR. */
	unsigned char ctr;

	/* Bitmask of writable CTR bits. */
	unsigned char ctr_writable;

	/* Whether or not there's an ECR. */
	int ecr;

	/* Number of PWords that FIFO will hold. */
	int fifo_depth;

	/* Number of bytes per portword. */
	int pword;
#ifdef _WORKAROUND_MCST_PP
	int driver_data;
	struct pci_dev *dev;
	u8 parport_rev;
#endif
	/* Not used yet. */
	int readIntrThreshold;
	int writeIntrThreshold;

	/* buffer suitable for DMA, if DMA enabled */
	char *dma_buf;
	dma_addr_t dma_handle;
	struct list_head list;
	struct parport *port;
};

struct parport_pc_via_data
{
	/* ISA PnP IRQ routing register 1 */
	u8 via_pci_parport_irq_reg;
	/* ISA PnP DMA request routing register */
	u8 via_pci_parport_dma_reg;
	/* Register and value to enable SuperIO configuration access */
	u8 via_pci_superio_config_reg;
	u8 via_pci_superio_config_data;
	/* SuperIO function register number */
	u8 viacfg_function;
	/* parallel port control register number */
	u8 viacfg_parport_control;
	/* Parallel port base address register */
	u8 viacfg_parport_base;
};

static __inline__ void parport_pc_write_data(struct parport *p, unsigned char d)
{
#ifdef DEBUG_PARPORT
	printk (KERN_DEBUG "parport_pc_write_data(%p,0x%02x)\n", p, d);
#endif
	outb(d, DATA(p));
}

static __inline__ unsigned char parport_pc_read_data(struct parport *p)
{
	unsigned char val = inb (DATA (p));
#ifdef DEBUG_PARPORT
	printk (KERN_DEBUG "parport_pc_read_data(%p) = 0x%02x\n",
		p, val);
#endif
	return val;
}

#ifdef DEBUG_PARPORT
static inline void dump_parport_state (char *str, struct parport *p)
{
	/* here's hoping that reading these ports won't side-effect anything underneath */
	unsigned char ecr = inb (ECONTROL (p));
	unsigned char dcr = inb (CONTROL (p));
	unsigned char dsr = inb (STATUS (p));
	static const char *const ecr_modes[] = {"SPP", "PS2", "PPFIFO", "ECP", "xXx", "yYy", "TST", "CFG"};
	const struct parport_pc_private *priv = p->physport->private_data;
	int i;

	printk (KERN_DEBUG "*** parport state (%s): ecr=[%s", str, ecr_modes[(ecr & 0xe0) >> 5]);
	if (ecr & 0x10) printk (",nErrIntrEn");
	if (ecr & 0x08) printk (",dmaEn");
	if (ecr & 0x04) printk (",serviceIntr");
	if (ecr & 0x02) printk (",f_full");
	if (ecr & 0x01) printk (",f_empty");
	for (i=0; i<2; i++) {
		printk ("]  dcr(%s)=[", i ? "soft" : "hard");
		dcr = i ? priv->ctr : inb (CONTROL (p));
	
		if (dcr & 0x20) {
			printk ("rev");
		} else {
			printk ("fwd");
		}
		if (dcr & 0x10) printk (",ackIntEn");
		if (!(dcr & 0x08)) printk (",N-SELECT-IN");
		if (dcr & 0x04) printk (",N-INIT");
		if (!(dcr & 0x02)) printk (",N-AUTOFD");
		if (!(dcr & 0x01)) printk (",N-STROBE");
	}
	printk ("]  dsr=[");
	if (!(dsr & 0x80)) printk ("BUSY");
	if (dsr & 0x40) printk (",N-ACK");
	if (dsr & 0x20) printk (",PERROR");
	if (dsr & 0x10) printk (",SELECT");
	if (dsr & 0x08) printk (",N-FAULT");
	printk ("]\n");
	return;
}
#else	/* !DEBUG_PARPORT */
#define dump_parport_state(args...)
#endif	/* !DEBUG_PARPORT */

/* __parport_pc_frob_control differs from parport_pc_frob_control in that
 * it doesn't do any extra masking. */
static __inline__ unsigned char __parport_pc_frob_control (struct parport *p,
							   unsigned char mask,
							   unsigned char val)
{
	struct parport_pc_private *priv = p->physport->private_data;
	unsigned char ctr = priv->ctr;
#ifdef DEBUG_PARPORT
	printk (KERN_DEBUG
		"__parport_pc_frob_control(%02x,%02x): %02x -> %02x\n",
		mask, val, ctr, ((ctr & ~mask) ^ val) & priv->ctr_writable);
#endif
	ctr = (ctr & ~mask) ^ val;
	ctr &= priv->ctr_writable; /* only write writable bits. */
	outb (ctr, CONTROL (p));
	priv->ctr = ctr;	/* Update soft copy */
	return ctr;
}

static __inline__ void parport_pc_data_reverse (struct parport *p)
{
	__parport_pc_frob_control (p, 0x20, 0x20);
}

static __inline__ void parport_pc_data_forward (struct parport *p)
{
	__parport_pc_frob_control (p, 0x20, 0x00);
}

static __inline__ void parport_pc_write_control (struct parport *p,
						 unsigned char d)
{
	const unsigned char wm = (PARPORT_CONTROL_STROBE |
				  PARPORT_CONTROL_AUTOFD |
				  PARPORT_CONTROL_INIT |
				  PARPORT_CONTROL_SELECT);

	/* Take this out when drivers have adapted to newer interface. */
	if (d & 0x20) {
		printk (KERN_DEBUG "%s (%s): use data_reverse for this!\n",
			p->name, p->cad->name);
		parport_pc_data_reverse (p);
	}

	__parport_pc_frob_control (p, wm, d & wm);
}

static __inline__ unsigned char parport_pc_read_control(struct parport *p)
{
	const unsigned char rm = (PARPORT_CONTROL_STROBE |
				  PARPORT_CONTROL_AUTOFD |
				  PARPORT_CONTROL_INIT |
				  PARPORT_CONTROL_SELECT);
	const struct parport_pc_private *priv = p->physport->private_data;
	return priv->ctr & rm; /* Use soft copy */
}

static __inline__ unsigned char parport_pc_frob_control (struct parport *p,
							 unsigned char mask,
							 unsigned char val)
{
	const unsigned char wm = (PARPORT_CONTROL_STROBE |
				  PARPORT_CONTROL_AUTOFD |
				  PARPORT_CONTROL_INIT |
				  PARPORT_CONTROL_SELECT);

	/* Take this out when drivers have adapted to newer interface. */
	if (mask & 0x20) {
		printk (KERN_DEBUG "%s (%s): use data_%s for this!\n",
			p->name, p->cad->name,
			(val & 0x20) ? "reverse" : "forward");
		if (val & 0x20)
			parport_pc_data_reverse (p);
		else
			parport_pc_data_forward (p);
	}

	/* Restrict mask and val to control lines. */
	mask &= wm;
	val &= wm;

	return __parport_pc_frob_control (p, mask, val);
}

static __inline__ unsigned char parport_pc_read_status(struct parport *p)
{
	return inb(STATUS(p));
}


static __inline__ void parport_pc_disable_irq(struct parport *p)
{
	__parport_pc_frob_control (p, 0x10, 0x00);
}

static __inline__ void parport_pc_enable_irq(struct parport *p)
{
	__parport_pc_frob_control (p, 0x10, 0x10);
}

extern void parport_pc_release_resources(struct parport *p);

extern int parport_pc_claim_resources(struct parport *p);

/* PCMCIA code will want to get us to look at a port.  Provide a mechanism. */
extern struct parport *parport_pc_probe_port(unsigned long base,
					     unsigned long base_hi,
					     int irq, int dma,
					     struct device *dev,
					     int irqflags);
extern void parport_pc_unregister_port(struct parport *p);

#endif
