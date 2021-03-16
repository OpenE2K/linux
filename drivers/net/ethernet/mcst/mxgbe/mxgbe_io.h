#ifndef _UAPI_MXGBE_IO_H
#define _UAPI_MXGBE_IO_H

#include <linux/types.h>
#include <linux/ioctl.h>


/*
 * Device open
 *
 * Usage:
 *   sprintf(name, "/dev/mxg%d", 0);
 *   if ((fd = open(name, O_RDWR)) < 0) fprintf(stderr, "Open error: %m\n");
 */


/*
 ******************************************************************************
 * IOCTL
 *   _IO            (TYPE, NR)
 *   _IOR/_IOW/_IOWR(type, NR, SIZE)
 *
 *   0xE0000000   DIR
 *   0x80000000     DIR = WRITE
 *   0x40000000     DIR = READ
 *   0x20000000     DIR = NONE
 *   0x3FFF0000   SIZE (sizeof)
 *   0x0000FF00   TYPE
 *   0x000000FF   NR (CMD)
 ******************************************************************************
 */

#define MXGBE_IOC_MAGIC 'x'


typedef struct {
	uint64_t useraddr;	/* IN: process address (user) */
	uint64_t dmaaddr;	/* device-viewed address */
	uint64_t len;		/* buffer length for DMA */
	size_t	bytes;		/* IN: user buff size */
	struct page **pages;
	unsigned int npages;
	struct scatterlist *sg;
	int nents;
} __packed mxgbe_mem_ptrs_t;


/*
 * MXGBE_IOCTL_WRITE
 *
 * Returns:
 *   -EFAULT - copy_from_user failure
 *   0 - success
 *
 * Usage:
 *   m2mlc_mem_ptrs_t mem_ptrs;
 *   mem_ptrs.useraddr = memalign(sysconf(_SC_PAGESIZE), <bytecount>);
 *   mem_ptrs.bytes = <bytecount>;
 *   if (ioctl(fd, MXGBE_IOCTL_WRITE, &buf)) printf("Error: %m\n");
 *   free(useraddr);
 */

#define MXGBE_IOCTL_WRITE (_IOW(MXGBE_IOC_MAGIC, 1, mxgbe_mem_ptrs_t))


/*
 * MXGBE_IOCTL_READ
 *
 * Returns:
 *   -EFAULT - copy_to/from_user failure
 *   0 - success
 *
 * Usage:
 *   m2mlc_mem_ptrs_t mem_ptrs;
 *   mem_ptrs.useraddr = memalign(sysconf(_SC_PAGESIZE), <bytecount>);
 *   mem_ptrs.bytes = <bytecount>;
 *   if (ioctl(fd, MXGBE_IOCTL_READ, &buf)) printf("Error: %m\n");
 *   free(useraddr);
 */
#define MXGBE_IOCTL_READ_REQ (_IOWR(MXGBE_IOC_MAGIC, 2, mxgbe_mem_ptrs_t))
#define MXGBE_IOCTL_READ_IND (_IOR(MXGBE_IOC_MAGIC, 3, mxgbe_mem_ptrs_t))


#endif /* _UAPI_MXGBE_IO_H */
