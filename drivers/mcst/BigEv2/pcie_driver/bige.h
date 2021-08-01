/* Copyright 2012 Google Inc. All Rights Reserved. */

#ifndef _BIGE_H_
#define _BIGE_H_

#include <linux/ioctl.h>
#include <linux/types.h>

//#define BIGE_DEBUG

#undef PDEBUG
#ifdef BIGE_DEBUG
#  ifdef __KERNEL__
#    define PDEBUG(fmt, args...) printk( KERN_INFO "bige: " fmt, ## args)
#  else
#    define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
#  endif
#else
#  define PDEBUG(fmt, args...)
#endif

/* TODO(mheikkinen) These are the Xilinx defaults. */
/* Base address got control register */
#ifdef CONFIG_E90S /* MCST R2000+ */
#define BIGE_CONTROL_BAR 2
#define BIGE_PCI_VENDOR_ID PCI_VENDOR_ID_MCST_TMP
#define BIGE_PCI_DEVICE_ID PCI_DEVICE_ID_MCST_VP9_BIGEV2_R2000P
#else /* MCST Elbrus-e2c3 */
#define BIGE_CONTROL_BAR 0
#define BIGE_PCI_VENDOR_ID PCI_VENDOR_ID_MCST_TMP
#define BIGE_PCI_DEVICE_ID PCI_DEVICE_ID_MCST_VP9_BIGEV2
#endif

/* PCIe BigEv2 driver offset in control register */
#define BIGE_REG_OFFSET 0x0
/* Address translation from CPU bus address to PCI bus address. */
/* TODO(mheikkinen) Now set separately in memalloc and kernel driver,
 * should this be set in a single place. */
#define HLINA_TRANSL_BASE               0x0
/* Base address of PCI base address translation */
#define HLINA_ADDR_TRANSL_REG            0x20c/4


/* Interrupt register of BigE (swreg1) */
#define BIGE_IRQ_STAT_ENC_OFF   0x4
#define BIGE_IRQ_EN_MASK        (1<<9)
#define BIGE_IRQ_MASK           (1<<4) /* masked by BIGE_IRQ_EN_MASK */
#define  BIGE_IRQ_FRAME_READY   (1<<3)
#define  BIGE_IRQ_BUS_ERROR     (1<<2)
#define  BIGE_IRQ_TIMEOUT       (1<<1)
/* fatal cases */
#define BIGE_IRQ_AXI_WRITE_DATA_UNDERFLOW_MASK  (1<<8)
#define BIGE_IRQ_AXI_READ_DATA_OVERFLOW_MASK    (1<<7)
#define BIGE_IRQ_STREAM_BUF_OVERFLOW            (1<<6)
#define BIGE_IRQ_IDCT_OVERFLOW                  (1<<5)

#endif /* !_BIGE_H_ */
