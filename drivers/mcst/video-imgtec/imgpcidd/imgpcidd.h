/*!
******************************************************************************
 @file   : imgpcidd.h

 @brief

 @Author Imagination Technologies

 @date   19/10/2007

         <b>Copyright 2007 by Imagination Technologies Limited.</b>\n
         All rights reserved.  No part of this software, either
         material or conceptual may be copied or distributed,
         transmitted, transcribed, stored in a retrieval system
         or translated into any human or computer language in any
         form by any means, electronic, mechanical, manual or
         other-wise, or disclosed to third parties without the
         express written permission of Imagination Technologies
         Limited, Unit 8, HomePark Industrial Estate,
         King's Langley, Hertfordshire, WD4 8LZ, U.K.

 <b>Description:</b>\n
         Linux PDUMP device driver header file.

 <b>Platform:</b>\n
	     Linux

 @Version
	     1.0

******************************************************************************/
/*
******************************************************************************
*/


#ifndef __IMGPCIDD_H__
#define __IMGPCIDD_H__

/* Maximum number of mapped regions available through this driver */
#define MAX_IMGPCI_MAPS			(6)
#define IMGPCI_VIRTUAL_MAP		100		/* map kernel memory, instead of PCI memory */

/* A PCI location reference */
struct imgpci_memref
{
	unsigned long	bar;
	unsigned long	offset;
};

/* 32bit register structure */
struct imgpci_reg32
{
	struct imgpci_memref	address;
	unsigned long			value;
};

/* Readdata struct used in read() calls */
struct imgpci_readdata
{
	unsigned long		event_count;
	unsigned long		int_status;
};

/* User asks kernel for the physical address corresponding to a virtual address.
*  If not yet populated, allocate a page at that address. allocation will use
*  either GFP_HIGHUSER (ie highmem) or GFP_DMA32 (ie 32bit) */
struct imgpci_get_virt2phys
{
	void             * virt;	/* in: user virtual address */
	int                dma32;	/* in: 0: allocate from highuser. 1: allocate from dma32 */
	unsigned long long phys;	/* out: corresponding physical address */
};


#if defined(METAC_2_1)
struct imgpci_cache_flush
{
	unsigned int	ui32PhysStartAddr;
	unsigned int	ui32SizeInBytes;
};
#endif /* defined(METAC_2_1) */

/* The ioctl number for this device - TODO - should be chosen better and registered (check ioctl-number.txt for more info) */
#define IMGPCI_IOCTL_MAGIC	'p'

/* Write a 32bit word to the specified PCI location */
#define IMGPCI_IOCTL_WRITE32		_IOW (IMGPCI_IOCTL_MAGIC, 0, struct imgpci_reg32 *)
/* Read a 32bit word from the specified PCI location */
#define IMGPCI_IOCTL_READ32			_IOR (IMGPCI_IOCTL_MAGIC, 1, struct imgpci_reg32 *)
/* Interrupt enable */
#define IMGPCI_IOCTL_INTEN			_IO (IMGPCI_IOCTL_MAGIC, 2)
/* Get physical address corresponding to user address. If necessary, allocate a physical page
 * at that address. Also locks the page, so it is not swapped out.
 * Optionally ensure that the newly allocated pages are within the
 * physical 32-bit address space. */
#define IMGPCI_IOCTL_GET_VIRT2PHYS _IOWR (IMGPCI_IOCTL_MAGIC, 3, struct imgpci_get_virt2phys *)
/* finish with the page that was got using GET_VIRT2PHYS */
#define IMGPCI_IOCTL_PUT_VIRT2PHYS _IOW (IMGPCI_IOCTL_MAGIC, 4, struct imgpci_get_virt2phys *)
#if defined(METAC_2_1)
/* Flush the L2 cache - Meta specific */
#define IMGPCI_IOCTL_META_L2_CACHE_FLUSH _IOW (IMGPCI_IOCTL_MAGIC, 5, struct imgpci_cache_flush *)
#endif /* defined(METAC_2_1) */

/* Max command number */
#if defined(METAC_2_1)
#define IMGPCI_IOCTL_MAXNR			5
#else
#define IMGPCI_IOCTL_MAXNR			4
#endif /* defined(METAC_2_1) */


#endif  //#ifndef __IMGPCIDD_H__
