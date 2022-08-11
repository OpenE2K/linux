/* Copyright 2012 Google Inc. All Rights Reserved. */

#ifndef MEMALLOC_H
#define MEMALLOC_H

#include <linux/ioctl.h>

#undef PDEBUG
#ifdef MEMALLOC_DEBUG
#ifdef __KERNEL__
#define PDEBUG(fmt, args...) printk(KERN_INFO "memalloc: " fmt, ##args)
#else
#define PDEBUG(fmt, args...) fprintf(stderr, fmt, ##args)
#endif
#else
#define PDEBUG(fmt, args...)
#endif

typedef struct {
	uint64_t phys_address;
	uint64_t dma_address;
	uint32_t size;
	uint8_t pci_domain;
	uint8_t bus;
	uint8_t slot;
	uint8_t function;
} MemallocParams;

#define MEMALLOC_IOC_MAGIC 0xc9

#define MEMALLOC_IOCXGETBUFFER _IOWR(MEMALLOC_IOC_MAGIC, 1, MemallocParams)
#define MEMALLOC_IOCSFREEBUFFER _IOW(MEMALLOC_IOC_MAGIC, 2, uint64_t)

#define MEMALLOC_IOC_MAXNR 15

#endif				/* MEMALLOC_H */
