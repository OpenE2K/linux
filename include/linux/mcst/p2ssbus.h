/* $Id: p2ssbus.h,v 1.3 2008/01/11 13:12:04 alexmipt Exp $
 * sbus.h:  Defines for the Sun SBus.
 *
 * Copyright (C) 1995 David S. Miller (davem@caip.rutgers.edu)
 * Copyright (C) 2005 Alexander Shmelev (ashmelev@task.sun.mcst.ru)
 */

#ifndef _SBUS_H
#define _SBUS_H

#include <linux/dma-mapping.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/scatterlist.h>

#include <asm/oplib.h>

#if 0
/* We scan which devices are on the SBus using the PROM node device
 * tree.  SBus devices are described in two different ways.  You can
 * either get an absolute address at which to access the device, or
 * you can get a SBus 'slot' number and an offset within that slot.
 */

struct sbus_bus;

/* Linux SBUS device tables */
struct sbus_dev {
	struct sbus_bus	*bus;       /* Back ptr to sbus */
	struct sbus_dev	*next;      /* next device on this SBus or null */
	struct sbus_dev	*child;     /* For ledma and espdma on sun4m */
	struct sbus_dev	*parent;    /* Parent device if not toplevel */
	int prom_node;              /* PROM device tree node for this device */
	char prom_name[64];         /* PROM device name */
	int slot;

	struct resource resource[PROMREG_MAX];

	struct linux_prom_registers reg_addrs[PROMREG_MAX];
	int num_registers, ranges_applied;

	struct linux_prom_ranges device_ranges[PROMREG_MAX];
	int num_device_ranges;

	unsigned int irqs[4];       /* [31:8] - p2s_id, [7:0] - irq */
	int num_irqs;
};

/* This struct describes the SBus(s) found on this machine. */
struct sbus_bus {
	void			*iommu;		/* Opaque IOMMU cookie */
	struct sbus_dev		*devices;	/* Link to devices on this SBus */
	struct sbus_bus		*next;		/* next SBus, if more than one SBus */
	int			prom_node;	/* PROM device tree node for this SBus */
	char			prom_name[64];  /* Usually "sbus" or "sbi" */
	int			clock_freq;

	struct linux_prom_ranges sbus_ranges[PROMREG_MAX];
	int num_sbus_ranges;

	int devid;
	int board;

	int p2s_id;			/* PCI-to-SBus bridge id */
	struct proc_dir_entry *procdir; /* directory entry in /proc/bus/sbus */
};

extern __inline__ int
sbus_is_slave(struct sbus_dev *dev)
{
	/* XXX Have to write this for sun4c's */
	return 0;
}

/* Device probing routines could find these handy */
#define for_each_sbus(bus) \
        for((bus) = sbus_root; (bus); (bus)=(bus)->next)

#define for_each_sbusdev(device, bus) \
        for((device) = (bus)->devices; (device); (device)=(device)->next)
        
#define for_all_sbusdev(device, bus) \
	for ((bus) = sbus_root; (bus); (bus) = (bus)->next) \
		for ((device) = (bus)->devices; (device); (device) = (device)->next)
#endif

/* Driver DVMA interfaces. */
#define sbus_can_dma_64bit(sdev)	(0) /* actually, sparc_cpu_model==sun4d */
#define sbus_can_burst64(sdev)		(0) /* actually, sparc_cpu_model==sun4d */
// extern void sbus_set_sbus64(struct sbus_dev *, int);

#if 0
/* TODO */
void prom_adjust_ranges(struct linux_prom_ranges *, int,
                         struct linux_prom_ranges *, int);
#endif
#if 0
/* These yield IOMMU mappings in consistent mode. */
extern void *sbus_alloc_consistent(struct sbus_dev *, long, u32 *dma_addrp);
extern void sbus_free_consistent(struct sbus_dev *, long, void *, u32);

#define SBUS_DMA_BIDIRECTIONAL	DMA_BIDIRECTIONAL
#define SBUS_DMA_TODEVICE	DMA_TO_DEVICE
#define SBUS_DMA_FROMDEVICE	DMA_FROM_DEVICE
#define	SBUS_DMA_NONE		DMA_NONE

/* All the rest use streaming mode mappings. */
extern dma_addr_t sbus_map_single(struct sbus_dev *, void *, size_t, int);
extern void sbus_unmap_single(struct sbus_dev *, dma_addr_t, size_t, int);
extern int sbus_map_sg(struct sbus_dev *, struct scatterlist *, int, int);
extern void sbus_unmap_sg(struct sbus_dev *, struct scatterlist *, int, int);

/* Finally, allow explicit synchronization of streamable mappings. */
extern void sbus_dma_sync_single_for_cpu(struct sbus_dev *, dma_addr_t, size_t, int);
#define sbus_dma_sync_single sbus_dma_sync_single_for_cpu
extern void sbus_dma_sync_single_for_device(struct sbus_dev *, dma_addr_t, size_t, int);
extern void sbus_dma_sync_sg_for_cpu(struct sbus_dev *, struct scatterlist *, int, int);
#define sbus_dma_sync_sg     sbus_dma_sync_sg_for_cpu
extern void sbus_dma_sync_sg_for_device(struct sbus_dev *, struct scatterlist *, int, int);
extern void big2little_convertor_on(struct sbus_dev *);
extern void big2little_convertor_off(struct sbus_dev *);


/* TODO ..._for_cpu */

/* ioremap */
extern unsigned long sbus_ioremap(struct resource *res, unsigned long offset,
	unsigned long size, char *name);
extern void sbus_iounmap(unsigned long vaddr, unsigned long size);
#endif

/**
 * SBus accessors.
 *
 * Do we need to flip bytes for SBus? Or its done by bridge?
 */
#if 0
#define _ALIGN_MASK	(~(uint64_t)0x3)

static inline u32 flip_dword (u32 l)
{
	return ((l&0xff)<<24) | (((l>>8)&0xff)<<16) | (((l>>16)&0xff)<<8)| ((l>>24)&0xff);
}
 
static inline u16 flip_word (u16 w)
{
	return ((w&0xff) << 8) | ((w>>8)&0xff);
}

static __inline__ u8 _sbus_readb(unsigned long addr)
{
//	return *(volatile uint8_t *)addr;


	return ( *(uint32_t*)(addr & _ALIGN_MASK) >> (addr & (0x3))*0x8 ) & 0xFF;
}

static __inline__ u16 _sbus_readw(unsigned long addr)
{
	return flip_word(( *(uint32_t*)(addr & _ALIGN_MASK) >> (addr & (0x2))*0x8 ) & 0xFFFF); 
}

static __inline__ u32 _sbus_readl(unsigned long addr)
{
	return flip_dword(*(volatile u32 *)addr);
}

static __inline__ void _sbus_writeb(u8 b, unsigned long addr)
{
	*(uint32_t*)(addr & _ALIGN_MASK) = (*(uint32_t*)(addr & _ALIGN_MASK) & (~(uint32_t)(0xFF << (addr & 0x3)*8))) | (b << (addr & 0x3)*8);
}

static __inline__ void _sbus_writew(u16 w, unsigned long addr)
{
	*(uint32_t*)(addr & _ALIGN_MASK) = (*(uint32_t*)(addr & _ALIGN_MASK) & (~(uint32_t)(0xFFFF << (addr & 0x2)*8))) | (flip_word(w) << (addr & 0x2)*8);
}
 
static __inline__ void _sbus_writel(u32 l, unsigned long addr)
{
	*(uint32_t *)addr = flip_dword(l);
}
#endif
static __inline__ void _my_sbus_writel(u32 l, unsigned long addr)
{
	*(uint32_t *)addr = l;
}

static __inline__ u32 _my_sbus_readl(unsigned long addr)
{
	return *(volatile u32 *)addr;
}

#define my_sbus_writel(v, a)	_my_sbus_writel(v, (unsigned long)(a))
#define my_sbus_readl(a)        _my_sbus_readl((unsigned long)(a))
/**
 * Interrupts
 */
int sbus_request_irq( 
	unsigned int irq,
	irqreturn_t (*handler)(int, void *),
	irqreturn_t (*threadfn)(int, void *),
        unsigned long irqflags, 
	const char * devname,
	void *dev_id );
void sbus_free_irq ( unsigned int irq, void *dev_id );
int sbus_can_request_irq(unsigned int irq, unsigned long irqflags);
/* Enabling and Disabling */
void sbus_disable_irq_nosync(unsigned int irq);
void sbus_disable_irq( unsigned int irq);
void sbus_enable_irq(unsigned int irq);


#endif /* !(_SBUS_H) */
