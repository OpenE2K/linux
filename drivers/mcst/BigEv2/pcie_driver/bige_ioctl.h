/* Copyright 2012 Google Inc. All Rights Reserved. */

#ifndef _BIGE_IOCTL_H_
#define _BIGE_IOCTL_H_

#include <linux/ioctl.h>
#include <linux/types.h>

struct core_desc
{
    __u32 id; /* id of the core */
    void* regs; /* pointer to user registers */
    __u32 size; /* size of register space */
};

/* Use 'k' as magic number */
#define BIGE_IOC_MAGIC  'k'

/*
 * S means "Set" through a ptr,
 * T means "Tell" directly with the argument value
 * G means "Get": reply by setting through a pointer
 * Q means "Query": response is on the return value
 * X means "eXchange": G and S atomically
 * H means "sHift": T and Q atomically
 */

#define BIGE_PP_INSTANCE       _IO(BIGE_IOC_MAGIC, 1)
#define BIGE_HW_PERFORMANCE    _IO(BIGE_IOC_MAGIC, 2)
#define BIGE_IOCGHWOFFSET      _IOR(BIGE_IOC_MAGIC,  3, unsigned long *)
#define BIGE_IOCGHWIOSIZE      _IOR(BIGE_IOC_MAGIC,  4, unsigned int *)

#define BIGE_IOC_CLI           _IO(BIGE_IOC_MAGIC,  5)
#define BIGE_IOC_STI           _IO(BIGE_IOC_MAGIC,  6)
#define BIGE_IOC_MC_OFFSETS    _IOR(BIGE_IOC_MAGIC, 7, unsigned long *)
#define BIGE_IOC_MC_CORES      _IOR(BIGE_IOC_MAGIC, 8, unsigned int *)

#define BIGE_IOCS_DEC_PUSH_REG  _IOW(BIGE_IOC_MAGIC, 9, struct core_desc *)
#define BIGE_IOCS_PP_PUSH_REG   _IOW(BIGE_IOC_MAGIC, 10, struct core_desc *)

#define BIGE_IOCH_DEC_RESERVE   _IO(BIGE_IOC_MAGIC, 11)
#define BIGE_IOCT_DEC_RELEASE   _IO(BIGE_IOC_MAGIC, 12)
#define BIGE_IOCQ_PP_RESERVE    _IO(BIGE_IOC_MAGIC, 13)
#define BIGE_IOCT_PP_RELEASE    _IO(BIGE_IOC_MAGIC, 14)

#define BIGE_IOCX_DEC_WAIT      _IOWR(BIGE_IOC_MAGIC, 15, struct core_desc *)
#define BIGE_IOCX_PP_WAIT       _IOWR(BIGE_IOC_MAGIC, 16, struct core_desc *)

#define BIGE_IOCS_DEC_PULL_REG  _IOWR(BIGE_IOC_MAGIC, 17, struct core_desc *)
#define BIGE_IOCS_PP_PULL_REG   _IOWR(BIGE_IOC_MAGIC, 18, struct core_desc *)

#define BIGE_IOX_ASIC_ID        _IOWR(BIGE_IOC_MAGIC, 20, __void* )

#define BIGE_DEBUG_STATUS       _IO(BIGE_IOC_MAGIC, 29)

#define BIGE_IOC_MAXNR 29

#endif /* !_BIGE_IOCTL_H_ */
