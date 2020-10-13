/*
 * Copyright (c) 1997 by MCST.
 */

#ifndef	_LINUX_ME90_DEF_H__
#define	_LINUX_ME90_DEF_H__

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef __KERNEL__
#include <sys/types.h>
#endif /* __KERNEL__ */

#include <linux/mcst/linux_me90_reg.h>

#define ME90_64_BURTS_SIZE_CODE	         6  /* 64 bytes burts size */
#define ME90_32_BURTS_SIZE_CODE	         5  /* 32 bytes burts size */
#define ME90_16_BURTS_SIZE_CODE	         4  /* 16 bytes burts size */
#define ME90_8_BURTS_SIZE_CODE	         3  /*  8 bytes burts size */
#define ME90_4_BURTS_SIZE_CODE	         2  /*  4 bytes burts size */

#define ME90_64_BURTS_SIZE_DCW_CODE	 6  /* 64 bytes burts size */
#define ME90_32_BURTS_SIZE_DCW_CODE	 5  /* 32 bytes burts size */
#define ME90_16_BURTS_SIZE_DCW_CODE	 4  /* 16 bytes burts size */
#define ME90_8_BURTS_SIZE_DCW_CODE	 7  /*  8 bytes burts size */
#define ME90_4_BURTS_SIZE_DCW_CODE	 0  /*  4 bytes burts size */

/*
 *  Structures of general tasks for all drivers
 */

typedef enum _adapter_opcode_t		/* list of adapter access opcodes */
{
   no_adapter_opcode         =  0,      /* empty opcode */
   write_adapter_opcode      =  1,      /* write adapter register */
   read_adapter_opcode       =  2       /* read adapter register */
} adapter_opcode_t;

typedef struct adapter_access		/* device adapter access desription */
{
   u_int	 address;               /* device adapter register address */
   u_int	 reg_value;		/* readed value or to write */
} adapter_access_t;

typedef struct iovec_s {
  	caddr_t iov_base;    /* base address of the data storage area */
                             /* represented by the iovec structure */
    /*  int     iov_len;*/   /* size of the data storage area in bytes */
	size_t	iov_len;
} iovec_t;

typedef struct uio {
     iovec_t     *uio_iov;     /* pointer to the start of the iovec */
                               /* list for the uio structure */
     int         uio_iovcnt;   /* the number of iovecs in the list */
     int         uio_offset;   /* 32-bit offset into file where data is */
                               /* transferred from or to. See NOTES. */
     long long   uio_loffset;  /* 64-bit offset into file where data is */
                               /* transferred from or to. See NOTES. */
     int         uio_segflg;   /* identifies the type of I/O transfer: */
                               /*    UIO_SYSSPACE:  kernel <-> kernel */
                               /*    UIO_USERSPACE: kernel <-> user */
     short       uio_fmode;    /* file mode flags (not driver setable) */
     int         uio_limit;    /* 32-bit ulimit for file (maximum block */
                               /* offset). not driver setable. See NOTES. */
     long long   uio_llimit;   /* 64-bit ulimit for file (maximum block */
                               /* offset). not driver setable. See NOTES. */
     int         uio_resid;    /* residual count */
     void * 	 transfer_spec;
     int         op_flags;
     dev_t       dev;
} uio_t;

/*
 * MP time read
 */

#define  cur_MP_time  drv_communication -> processing_time.mp_timer
#define	 READ_MP_TIME(cur_mp_time)					\
{									\
   register u_int  time2 = cur_MP_time;					\
   register u_int  eqv_times = 0;						\
   while (eqv_times < 3)						\
   {									\
      register u_int  time1 = cur_MP_time;				\
      eqv_times = 0;							\
      while (1)			                                        \
      {									\
         if (time1 == time2)						\
         {								\
            eqv_times ++;						\
            if (eqv_times >= 3) break;					\
         }								\
         else								\
         {                                                              \
            time2 = time1;                                              \
            break;							\
         }                                                              \
      }									\
   }									\
   cur_mp_time = time2;							\
}

#ifdef	__cplusplus
}
#endif

#endif	/* _LINUX_ME90_DEF_H__ */
