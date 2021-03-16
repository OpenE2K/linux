#ifndef _UAPI_M2MLC_IO_H
#define _UAPI_M2MLC_IO_H

#include <linux/types.h>
#include <linux/ioctl.h>


/*
 * Devices name
 *
 * Usage:
 *   sprintf(name, "/dev/%s%d", M2MLC_DEVNAME, 0);
 *   if((fd = open(name, O_RDWR)) < 0) fprintf(stderr, "Open error: %m\n");
 */
#define M2MLC_DEVNAME "m2m"


/*
 * Mem size for read()
 *
 * Usage:
 *   char buf[M2MLC_READ_BUF_SIZE];
 *   if(read(fd, buf, sizeof(buf)) < 0) fprintf(stderr, "Read error: %m\n");
 */
#define M2MLC_READ_BUF_SIZE	(80 * 38)


/*
 * Mem size for write()
 *
 * Usage:
 *   char buf[M2MLC_WRITE_BUF_SIZE];
 *   sprintf(buf, "%d", 1);  // call M2MLC_IOCTL_PRINT_REGS
 *   if(write(fd, buf, sizeof(buf)) < 0) fprintf(stderr, "Write error: %m\n");
 */
#define M2MLC_WRITE_BUF_SIZE	20


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

#define M2MLC_IOC_MAGIC 't'


/**
 ******************************************************************************
 * COMMON
 ******************************************************************************
 */

/*
 * M2MLC_IOCTL_OPEN_ENDPOINT
 * Allocate Resource block for user
 *
 * Returns:
 *   -EFAULT - copy_from_user failure
 *   -EBUSY - Resource block is busy
 *   0 - success
 *
 * Usage:
 *   m2mlc_resource_t res;
 *   res.num = <block_num>;
 *   res.signal = <SIGNUM>;
 *   if(ioctl(fd, M2MLC_IOCTL_OPEN_ENDPOINT, &res)) printf("Error: %m\n");
 */

typedef struct {
	/* Endpoint number: 1..16 (0, 17..19 for root) */
	int num;
	/* signal to user (SIGIO), or 0 */
	int signal;
} m2mlc_resource_t;

#define M2MLC_IOCTL_OPEN_ENDPOINT (_IOW(M2MLC_IOC_MAGIC, 1, m2mlc_resource_t))


/*
 * M2MLC_IOCTL_CLOSE_ENDPOINT
 * Release Resource block
 *
 * Returns:
 *   0 - success
 *
 * Usage:
 *   if(ioctl(fd, M2MLC_IOCTL_CLOSE_ENDPOINT, NULL)) printf("Error: %m\n");
 */

#define M2MLC_IOCTL_CLOSE_ENDPOINT (_IO(M2MLC_IOC_MAGIC, 2))


/**
 ******************************************************************************
 * PIO
 ******************************************************************************
 */

#define M2MLC_PIO_PAYLOAD_SIZE	256
#define M2MLC_PIO_FIFO_LEN	16


/*
 * M2MLC_IOCTL_PIO_START
 * Start PIO Transaction
 *
 * Returns:
 *   -EFAULT - copy_from_user failure
 *   -EBUSY - PIO block is busy
 *   0 - success
 *
 * Usage:
 *   m2mlc_pio_cmd_t piocmd;
 *   piocmd.Target_ptr = <remote_address/Doorbell>;
 *   piocmd.Parameter.r = 0;
 *   piocmd.Parameter.p.BEmaskLBE = <last_byte_enable_mask>;
 *   piocmd.Parameter.p.BEmaskFBE = <first_byte_anable_mask>;
 *   piocmd.Parameter.p.Size = <size_in_dword>;  // 0 == 64 DW
 *   piocmd.Parameter.p.DestId = <Destination_ID>;
 *   piocmd.Parameter.p.Route = <nhops>;
 *   piocmd.Parameter.p.Tag = <tag>;
 *   piocmd.Format.r = 0;
 *   piocmd.Format.f.Format_Type = M2MLC_FMT_TYPE_???;
 *   piocmd.Format.f.LocIntReq = 1;  // irq on descriptor finish
 *   piocmd.Format.f.RemIntReq = 1;  // generate DoorBell
 *   piocmd.Format.f.Subtype = <maintenance_subtype>;
 *   piocmd.Format.f.Start = 1;
 *   piocmd.Remote_Doorbell = <remote_doorbell>;
 *   if(ioctl(fd, M2MLC_IOCTL_PIO_START, &piocmd)) printf("Error: %m\n");
 */

/* Format.f.Format_Type & Format.f.Subtype */
#define M2MLC_FMT_TYPE_PUTL	0xE0	/* write req. with local context */
#define M2MLC_FMT_TYPE_PUTR	0xE1	/* write req. with remote context */
#define M2MLC_FMT_TYPE_GETL	0xA2	/* read req. with local context */
#define M2MLC_FMT_TYPE_GETR	0xE3	/* read req. with remote context */
#define M2MLC_FMT_TYPE_MSGL	0xE4	/* send msg with local context */
#define M2MLC_FMT_TYPE_MSGR	0xE5	/* send msg with remote context */
#define M2MLC_FMT_TYPE_MSGS	0x84	/* send sig msg with local context */
#if 0
#define M2MLC_FMT_TYPE_RSPH	0x88	/* responce w/o data */
#define M2MLC_FMT_TYPE_RSPD	0xC8	/* responce with data */
#define M2MLC_FMT_TYPE_DCP	0x8C	/* acknowledge control */
  #define M2MLC_FMT_TYPE_DCP_SUB_OPEN	0x01	/* Context Open */
  #define M2MLC_FMT_TYPE_DCP_SUB_CLOSE	0x00	/* Context Close */
#define M2MLC_FMT_TYPE_FAP	0x8D	/* flow control */
  #define M2MLC_FMT_TYPE_FAP_REQ_ALLOC	0x00	/* remote resource alloc */
  #define M2MLC_FMT_TYPE_FAP_RES_GRANT	0x01	/* resource alloc grant */
  #define M2MLC_FMT_TYPE_FAP_REQ_REFUND	0x02	/* remote resource free */
  #define M2MLC_FMT_TYPE_FAP_RES_REJECT	0x03	/* resource alloc error */
#endif /* 0 */
#define M2MLC_FMT_TYPE_MNTR	0x8E	/* read config space */
  #define M2MLC_FMT_TYPE_MNTR_RESPONCE	0x00	/* maintenance response */
  #define M2MLC_FMT_TYPE_MNTR_READREQ	0x01	/* maintenance read request */
#define M2MLC_FMT_TYPE_MNTS	0x8E	/* change route table */
  #define M2MLC_FMT_TYPE_MNTS_RT_C_SET0	0x02	/* RT_Cell_Set0 */
  #define M2MLC_FMT_TYPE_MNTS_RT_C_SET1	0x03	/* RT_Cell_Set1 */
#define M2MLC_FMT_TYPE_MNTW	0xCE	/* write config space */
#define M2MLC_FMT_TYPE_SRVE	0x2F	/* message from switch */

typedef struct {
#ifdef __KERNEL__
	uint64_t Target_ptr;
#else /* USER */
	uint32_t Target_ptr_lo;
	uint32_t Target_ptr_hi;
#endif /* __KERNEL__ */
	union {
		struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
			uint32_t BEmaskLBE	: 4;	/* [31:28] */
			uint32_t BEmaskFBE	: 4;	/* [27:24] */
			uint32_t _reserved0	: 2;	/* [23:22] */
			uint32_t Size		: 6;	/* [21:16] */
			uint32_t DestId		: 8;	/* [15:08] */
			uint32_t Route		: 4;	/* [07:04] */
			uint32_t Tag		: 4;	/* [03:00] */
#else /* __e2k__ */
/* #warning error 4bytesx2 FIXME */
			uint32_t Tag		: 4;	/* [03:00] */
			uint32_t Route		: 4;	/* [07:04] */
			uint32_t DestId		: 8;	/* [15:08] */
			uint32_t Size		: 6;	/* [21:16] */
			uint32_t _reserved0	: 2;	/* [23:22] */
			uint32_t BEmaskFBE	: 4;	/* [27:24] */
			uint32_t BEmaskLBE	: 4;	/* [31:28] */
#endif /* __sparc__ */
		} __packed p;
		uint32_t r;
	} __packed Parameter;
	union {
		struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
			uint32_t Format_Type	: 8;	/* [31:24] */
			uint32_t LocIntReq	: 1;	/* [23] */
			uint32_t RemIntReq	: 1;	/* [22] */
			uint32_t Subtype	: 8;	/* [21:14] */
			uint32_t _reserved1	:12;	/* [13:02] */
			uint32_t Start		: 1;	/* [01] */
			uint32_t _reserved2	: 1;	/* [00] */
#else /* __e2k__ */
			uint32_t _reserved2	: 1;	/* [00] */
			uint32_t Start		: 1;	/* [01] */
			uint32_t _reserved1	:12;	/* [13:02] */
			uint32_t Subtype	: 8;	/* [21:14] */
			uint32_t RemIntReq	: 1;	/* [22] */
			uint32_t LocIntReq	: 1;	/* [23] */
			uint32_t Format_Type	: 8;	/* [31:24] */
#endif /* __sparc__ */
		} __packed f;
		uint32_t r;
	} __packed Format;
	uint32_t Remote_Doorbell;
} __packed m2mlc_pio_cmd_t;

#define M2MLC_IOCTL_PIO_START (_IOW(M2MLC_IOC_MAGIC, 3, m2mlc_pio_cmd_t))


/*
 * M2MLC_IOCTL_PIO_GETSTAT
 * Get PIO Transaction status
 *
 * Returns:
 *   -EFAULT - copy_to_user failure
 *   -EBUSY - PIO block is busy
 *   0 - success
 *
 * Usage:
 *   uint8_t piostat;
 *   if(ioctl(fd, M2MLC_IOCTL_PIO_GETSTAT, &piostat)) printf("Error: %m\n");
 *   if(M2MLC_PIO_BLOCK_BUSY & piostat) printf("resource busy\n");
 *   int done_buff_num = M2MLC_PIO_STAT_BUFFPTR(piostat);
 */

#define M2MLC_PIO_STAT_BUFFPTR_MASK  0x1F
#define M2MLC_PIO_STAT_BUFFPTR(d)  (((d) >> 3) & M2MLC_PIO_STAT_BUFFPTR_MASK)
#define M2MLC_PIO_BLOCK_BUSY  0x01

typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t LF		:  1;	/* [31] */
		uint32_t _reserved0	:  7;	/* [30:24] */
		uint32_t Size		:  8;	/* [23:16] */
		uint32_t CplStatus	:  8;	/* [15:08] */
		uint32_t Tag		:  8;	/* [07:00] */
#else /* __e2k__ */
		uint32_t Tag		:  8;	/* [07:00] */
		uint32_t CplStatus	:  8;	/* [15:08] */
		uint32_t Size		:  8;	/* [23:16] */
		uint32_t _reserved0	:  7;	/* [30:24] */
		uint32_t LF		:  1;	/* [31] */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed m2mlc_pio_done_cell_t;

#define M2MLC_IOCTL_PIO_GETSTAT (_IOR(M2MLC_IOC_MAGIC, 4, uint8_t))


/**
 ******************************************************************************
 * Mailbox
 ******************************************************************************
 */

#define M2MLC_MB_ADDRESS_MASK	0x0000000FFFFFFFFF	/* [63:36] not used */


/* M2MLC_IOCTL_MB_GETPTRS_{MAIL|DONE} */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint16_t TailPtr;	/* [26:16] RW + [31] Shadow Copy En */
		uint16_t HeadPtr;	/* [10:00] RO */
#else /* __e2k__ */
		uint16_t HeadPtr;	/* [10:00] RO */
		uint16_t TailPtr;	/* [26:16] RW + [31] Shadow Copy En */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed m2mlc_mb_ptrs_t;

#define M2MLC_MB_SHADOWCOPYEN	0x8000
#define M2MLC_MB_GETPTR(d)	((d) & 0x7FF)	/* [10:00] or [26:16] */


/*
 * M2MLC_IOCTL_MB_GETPTRS_MAIL
 * Get Mailbox Structure Head & Tail Pointers
 *
 * Returns:
 *   -EFAULT - copy_to_user failure
 *   0 - success
 *
 * Usage:
 *   m2mlc_mb_ptrs_t mbptrs;
 *   if(ioctl(fd, M2MLC_IOCTL_MB_GETPTRS_MAIL, &mbptrs)) printf("Error: %m\n");
 *   int tail_ptr  = M2MLC_MB_GETPTR(mbptrs.p.TailPtr);
 *   int head_ptr = M2MLC_MB_GETPTR(mbptrs.p.HeadPtr);
 */

#define M2MLC_IOCTL_MB_GETPTRS_MAIL (_IOR(M2MLC_IOC_MAGIC, 5, m2mlc_mb_ptrs_t))


/*
 * M2MLC_IOCTL_MB_SETTAILPTR_MAIL
 * Set Mailbox Structure Tail Pointer
 *
 * Returns:
 *   -EFAULT - copy_from_user failure
 *   0 - success
 *
 * Usage:
 *   uint16_t tail_ptr = <ptr>;
 *   if(ioctl(fd, M2MLC_IOCTL_MB_SETTAILPTR_MAIL, &tail_ptr))
 *           printf("Error: %m\n");
 */

#define M2MLC_IOCTL_MB_SETTAILPTR_MAIL (_IOW(M2MLC_IOC_MAGIC, 6, uint16_t))


/*
 * M2MLC_IOCTL_MB_GETPTRS_DONE
 * Get Mailbox Done Head & Tail Pointers
 *
 * Returns:
 *   -EFAULT - copy_to_user failure
 *   0 - success
 *
 * Usage:
 *   m2mlc_mb_ptrs_t mbptrs;
 *   if(ioctl(fd, M2MLC_IOCTL_MB_GETPTRS_DONE, &mbptrs)) printf("Error: %m\n");
 *   int tail_ptr  = M2MLC_MB_GETPTR(mbptrs.p.TailPtr);
 *   int head_ptr = M2MLC_MB_GETPTR(mbptrs.p.HeadPtr);
 */

#define M2MLC_IOCTL_MB_GETPTRS_DONE (_IOR(M2MLC_IOC_MAGIC, 7, m2mlc_mb_ptrs_t))


/*
 * M2MLC_IOCTL_MB_SETTAILPTR_DONE
 * Set Mailbox Done Tail Pointer
 *
 * Returns:
 *   -EFAULT - copy_from_user failure
 *   0 - success
 *
 * Usage:
 *   uint16_t tail_ptr = <ptr> | M2MLC_MB_SHADOWCOPYEN;
 *   if(ioctl(fd, M2MLC_IOCTL_MB_SETTAILPTR_DONE, &tail_ptr))
 *           printf("Error: %m\n");
 */

#define M2MLC_IOCTL_MB_SETTAILPTR_DONE (_IOW(M2MLC_IOC_MAGIC, 8, uint16_t))


/**
 ******************************************************************************
 * DoorBell
 ******************************************************************************
 */

/*
 * M2MLC_IOCTL_DB_GETPTRS
 * Get DoorBell Head & Tail Pointer
 *
 * Returns:
 *   -EFAULT - copy_to_user failure
 *   0 - success
 *
 * Usage:
 *   m2mlc_db_ptrs_t dbptrs;
 *   if(ioctl(fd, M2MLC_IOCTL_DB_GETPTRS, &dbptrs)) printf("Error: %m\n");
 *   int tail_ptr = M2MLC_DB_GETPTR(dbptrs.p.TailPtr);
 *   int head_ptr = M2MLC_DB_GETPTR(dbptrs.p.HeadPtr);
 */

typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint16_t TailPtr;	/* [24:16] RW + [31] Shadow Copy En */
		uint16_t HeadPtr;	/* [08:00] RO */
#else /* __e2k__ */
		uint16_t HeadPtr;	/* [08:00] RO */
		uint16_t TailPtr;	/* [24:16] RW + [31] Shadow Copy En */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed m2mlc_db_ptrs_t;

#define M2MLC_DB_SHADOWCOPYEN	0x8000
#define M2MLC_DB_GETPTR(d)	((d) & 0x1FF)	/* [08:00] or [24:16] */

#define M2MLC_IOCTL_DB_GETPTRS (_IOR(M2MLC_IOC_MAGIC, 9, m2mlc_db_ptrs_t))


/*
 * M2MLC_IOCTL_DB_SETTAILPTR
 * Set DoorBell Head Pointer
 *
 * Returns:
 *   -EFAULT - copy_from_user failure
 *   0 - success
 *
 * Usage:
 *   uint16_t tail_ptr = <ptr> | M2MLC_DB_SHADOWCOPYEN;
 *   if(ioctl(fd, M2MLC_IOCTL_DB_SETTAILPTR, &tail_ptr)) printf("Error: %m\n");
 */

#define M2MLC_IOCTL_DB_SETTAILPTR (_IOW(M2MLC_IOC_MAGIC, 10, uint16_t))


/**
 ******************************************************************************
 * Interrupt
 ******************************************************************************
 */

/* PIO Interrupt Status [03:00] */
#define M2MLC_INT_PIO_DONE	0x01	/* PIO Descriptor Done */
#define M2MLC_INT_PIO_ERROR	0x04	/* PIO Error */
/* Mailbox Interrupt Status [07:04] */
#define M2MLC_INT_MB_RXMSG	0x01	/* Message Received */
#define M2MLC_INT_MB_DONEFULL	0x02	/* Mailbox Done Full */
#define M2MLC_INT_MB_FULL	0x04	/* Mailbox Full */
/* DoorBell Interrupt Status [11:08] */
#define M2MLC_INT_DB_RXDB	0x01	/* DoorBell block Received */
#define M2MLC_INT_DB_NOTEMPTY	0x02	/* DoorBell block Not Empty */
#define M2MLC_INT_DB_FULL	0x04	/* DoorBell block Full */
/* DMA mode Interrupt Status [15:12] */
#define M2MLC_INT_DMA_DONE	0x01	/* DMA Descriptor Done */
#define M2MLC_INT_DMA_FULL	0x02	/* DMA Queue Full */
#define M2MLC_INT_DMA_ERROR	0x04	/* DMA Error */
#if 0
/* IOMMU Interrupt Status [19:16] */
#define M2MLC_INT_IOMMU_RESERR	0x01	/* DMA Responce Error */
#define M2MLC_INT_IOMMU_REQERR	0x02	/* DMA Request Error */
#endif /* 0 */

typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
#if 0
		uint32_t reserved_0	: 12; /* [31:20] */
		uint32_t iommu		:  4; /* [19:16] */
#else
		uint32_t reserved_0	: 16; /* [31:16] */
#endif /* 0 */
		uint32_t dma		:  4; /* [15:12] */
		uint32_t db		:  4; /* [11:08] */
		uint32_t mb		:  4; /* [07:04] */
		uint32_t pio		:  4; /* [03:00] */
#else /* __e2k__ */
		uint32_t pio		:  4; /* [03:00] */
		uint32_t mb		:  4; /* [07:04] */
		uint32_t db		:  4; /* [11:08] */
		uint32_t dma		:  4; /* [15:12] */
#if 0
		uint32_t iommu		:  4; /* [19:16] */
		uint32_t reserved_0	: 12; /* [31:20] */
#else
		uint32_t reserved_0	: 16; /* [31:16] */
#endif /* 0 */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed m2mlc_interrupt_t;


/*
 * M2MLC_IOCTL_INT_SETMASK
 * Interrupt Enable
 *
 * Returns:
 *   -EFAULT - copy_from_user failure
 *   0 - success
 *
 * Usage:
 *   m2mlc_interrupt_t intmask;
 *   intmask.p.pio = M2MLC_INT_PIO_* | ...
 *   intmask.p.mb = M2MLC_INT_MB_* | ...
 *   intmask.p.db = M2MLC_INT_DB_* | ...
 *   intmask.p.dma = M2MLC_INT_DMA_* | ...
 *   if(ioctl(fd, M2MLC_IOCTL_INT_SETMASK, &intmask)) printf("Error: %m\n");
 */

#define M2MLC_IOCTL_INT_SETMASK (_IOW(M2MLC_IOC_MAGIC, 11, m2mlc_interrupt_t))


#if 0
/*
 * M2MLC_IOCTL_INT_CLEAR
 * Confirm Interrupt
 *
 * Returns:
 *   -EFAULT - copy_from_user failure
 *   0 - success
 *
 * Usage:
 *   m2mlc_interrupt_t intclr;
 *   intclr.p.pio = M2MLC_INT_PIO_* | ...
 *   intclr.p.mb = M2MLC_INT_MB_* | ...
 *   intclr.p.db = M2MLC_INT_DB_* | ...
 *   intclr.p.dma = M2MLC_INT_DMA_* | ...
 *   if(ioctl(fd, M2MLC_IOCTL_INT_CLEAR, &intclr)) printf("Error: %m\n");
 */

#define M2MLC_IOCTL_INT_CLEAR (_IOW(M2MLC_IOC_MAGIC, 12, m2mlc_interrupt_t))
#endif /* 0 */


/*
 * M2MLC_IOCTL_INT_GETSTATUS
 * Get Interrupt Status
 *
 * Returns:
 *   -EFAULT - copy_to_user failure
 *   0 - success
 *
 * Usage:
 *   m2mlc_int_stat_t intstat;
 *   if(ioctl(fd, M2MLC_IOCTL_INT_GETSTATUS, &intstat)) printf("Error: %m\n");
 *
 *   if(intstat.fromreg.p.pio & M2MLC_INT_PIO_*) ...
 *   if(intstat.fromreg.p.mb & M2MLC_INT_MB_*) ...
 *   if(intstat.fromreg.p.db & M2MLC_INT_DB_*) ...
 *   if(intstat.fromreg.p.dma & M2MLC_INT_DMA_*) ...
 *
 *   if(intstat.fromirq.p.pio & M2MLC_INT_PIO_*) ...
 *   if(intstat.fromirq.p.mb & M2MLC_INT_MB_*) ...
 *   if(intstat.fromirq.p.db & M2MLC_INT_DB_*) ...
 *   if(intstat.fromirq.p.dma & M2MLC_INT_DMA_*) ...
 */

typedef struct {
	/* Readed from Interrupt Status Register */
	m2mlc_interrupt_t fromreg;
	/* Readed from Interrupt Enable Register */
	m2mlc_interrupt_t intmask;
	/* Last saved in IRQ Handler */
	m2mlc_interrupt_t fromirq;
} __packed m2mlc_int_stat_t;

#define M2MLC_IOCTL_INT_GETSTATUS (_IOR(M2MLC_IOC_MAGIC, 13, m2mlc_int_stat_t))


/**
 ******************************************************************************
 * DMA
 ******************************************************************************
 */

#define M2MLC_DMA_SHADOWCOPYEN	0x8000
#define M2MLC_DMA_GETPTR(d)	((d) & 0x1FFF)	/* [12:00] or [28:16] */


/*
 * M2MLC_IOCTL_DMA_GETPTRS_STR
 * Get DMA Structure Head & Tail Pointers
 *
 * Returns:
 *   -EFAULT - copy_to_user failure
 *   0 - success
 *
 * Usage:
 *   m2mlc_dma_str_ptrs_t dmaptrs;
 *   if(ioctl(fd, M2MLC_IOCTL_DMA_GETPTRS_STR, &dmaptrs)) printf("Error: %m\n");
 *   int tail_ptr  = M2MLC_DMA_GETPTR(dmaptrs.p.TailPtr);
 *   int head_ptr = M2MLC_DMA_GETPTR(dmaptrs.p.HeadPtr);
 */

typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint16_t HeadPtr;	/* [28:16] RW */
		uint16_t TailPtr;	/* [12:00] RO */
#else /* __e2k__ */
		uint16_t TailPtr;	/* [12:00] RO */
		uint16_t HeadPtr;	/* [28:16] RW */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed m2mlc_dma_str_ptrs_t;

#define M2MLC_IOCTL_DMA_GETPTRS_STR \
	(_IOR(M2MLC_IOC_MAGIC, 14, m2mlc_dma_str_ptrs_t))


/*
 * M2MLC_IOCTL_DMA_SETHEADPTR_STR
 * Set DMA Structure Head Pointer
 *
 * Returns:
 *   -EFAULT - copy_from_user failure
 *   0 - success
 *
 * Usage:
 *   uint16_t head_ptr = <ptr>;
 *   if(ioctl(fd, M2MLC_IOCTL_DMA_SETHEADPTR_STR, &head_ptr))
 *           printf("Error: %m\n");
 */

#define M2MLC_IOCTL_DMA_SETHEADPTR_STR (_IOW(M2MLC_IOC_MAGIC, 15, uint16_t))


/*
 * M2MLC_IOCTL_DMA_GETPTRS_DONE
 * Get DMA Done Head & Tail Pointers
 *
 * Returns:
 *   -EFAULT - copy_to_user failure
 *   0 - success
 *
 * Usage:
 *   m2mlc_dma_done_ptrs_t dmaptrs;
 *   if(ioctl(fd, M2MLC_IOCTL_DMA_GETPTRS_DONE, &dmaptrs))
 *           printf("Error: %m\n");
 *   int tail_ptr  = M2MLC_DMA_GETPTR(dmaptrs.p.TailPtr);
 *   int head_ptr = M2MLC_DMA_GETPTR(dmaptrs.p.HeadPtr);
 */

typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint16_t TailPtr;	/* [28:16] RW + [31] Shadow Copy En */
		uint16_t HeadPtr;	/* [12:00] RO */
#else /* __e2k__ */
		uint16_t HeadPtr;	/* [12:00] RO */
		uint16_t TailPtr;	/* [28:16] RW + [31] Shadow Copy En */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed m2mlc_dma_done_ptrs_t;

#define M2MLC_IOCTL_DMA_GETPTRS_DONE \
	(_IOR(M2MLC_IOC_MAGIC, 16, m2mlc_dma_done_ptrs_t))


/*
 * M2MLC_IOCTL_DMA_SETTAILPTR_DONE
 * Set DMA Done Tail Pointer
 *
 * Returns:
 *   -EFAULT - copy_from_user failure
 *   0 - success
 *
 * Usage:
 *   uint16_t tail_ptr = <ptr> | M2MLC_DMA_SHADOWCOPYEN;
 *   if(ioctl(fd, M2MLC_IOCTL_DMA_SETTAILPTR_DONE, &tail_ptr))
 *           printf("Error: %m\n");
 */

#define M2MLC_IOCTL_DMA_SETTAILPTR_DONE (_IOW(M2MLC_IOC_MAGIC, 17, uint16_t))


/*
 * M2MLC_IOCTL_MEM_LOC
 * Register memory for DMA
 *
 * Returns:
 *   -EFAULT - copy_from_user failure
 *   -ENOMEM - can't allocate memory
 *   0 - success
 *
 * Usage:
 *   m2mlc_mem_ptrs_t mem_ptrs;
 *   mem_ptrs.useraddr = memalign(sysconf(_SC_PAGESIZE), <bytecount>);
 *   mem_ptrs.bytes = <bytecount>;
 *   if(ioctl(fd, M2MLC_IOCTL_MEM_LOC, &mem_ptrs))
 *           printf("Error: %m\n");
 *   // mem_ptrs.dmaaddr - phys address for DMA
 *   // mem_ptrs.len - buffer length for DMA
 */

typedef struct {
	uint64_t useraddr;	/* IN: process address (user) */
	uint64_t bytes;		/* IN: user buff size */
	uint64_t dmaaddr;	/* OUT: device-viewed address */
	uint64_t len;		/* OUT: buffer length for DMA */
	/* internal use only: */
	/* TODO: move to internal list */
	struct page **pages;
	uint64_t npages;
	struct scatterlist *sg;
	int64_t nents;
} __packed m2mlc_mem_ptrs_t;

#define M2MLC_IOCTL_MEM_LOC (_IOWR(M2MLC_IOC_MAGIC, 21, m2mlc_mem_ptrs_t))


/*
 * M2MLC_IOCTL_MEM_REL
 * Allocate memory for DMA
 *
 * Returns:
 *   -EFAULT - copy_from_user failure
 *   -EINVAL - wrong address
 *   0 - success
 *
 * Usage:
 *   // mem_ptrs - returned from M2MLC_IOCTL_MEM_LOC
 *   if(ioctl(fd, M2MLC_IOCTL_MEM_REL, &mem_ptrs))
 *           printf("Error: %m\n");
 */

#define M2MLC_IOCTL_MEM_REL (_IOWR(M2MLC_IOC_MAGIC, 22, m2mlc_mem_ptrs_t))


/**
 ******************************************************************************
 * Element_Config_Space
 ******************************************************************************
 */

/*
 * m2mlc_ecs_reg_t.val
 */

/* ECS_DEVID_CAR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t Device_Identity	: 16; /* [31:16] RO */
		uint32_t Device_Vendor_Identity	: 16; /* [15:00] RO */
#else /* __e2k__ */
		uint32_t Device_Vendor_Identity	: 16; /* [15:00] RO */
		uint32_t Device_Identity	: 16; /* [31:16] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ecs_devid_car_reg_t;

/* ECS_DEVINF_CAR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0		: 16; /* [31:16] RO */
		uint32_t Device_Revision	: 16; /* [15:00] RO */
#else /* __e2k__ */
		uint32_t Device_Revision	: 16; /* [15:00] RO */
		uint32_t reserved_0		: 16; /* [31:16] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ecs_devinf_car_reg_t;

/* ECS_ASMBLID_CAR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t Assy_Identity		: 16; /* [31:16] RO */
		uint32_t Assy_Vendor_Identity	: 16; /* [15:00] RO */
#else /* __e2k__ */
		uint32_t Assy_Vendor_Identity	: 16; /* [15:00] RO */
		uint32_t Assy_Identity		: 16; /* [31:16] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ecs_asmblid_car_reg_t;

/* ECS_ASMBLINF_CAR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t Assy_Revision		: 16; /* [31:16] RO */
		uint32_t Extended_Features_Ptr	: 16; /* [15:00] RO */
#else /* __e2k__ */
		uint32_t Extended_Features_Ptr	: 16; /* [15:00] RO */
		uint32_t Assy_Revision		: 16; /* [31:16] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ecs_asmblinf_car_reg_t;

/* ECS_PEF_CAR */
#define ECS_PEF_CAR_EXTADDRSUP_66	0x04	/* "or" */
#define ECS_PEF_CAR_EXTADDRSUP_50	0x02
#define ECS_PEF_CAR_EXTADDRSUP_34	0x01
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t Bridge			:  1; /* [31] RO */
		uint32_t Memory			:  1; /* [30] RO */
		uint32_t Processor		:  1; /* [29] RO */
		uint32_t Switch			:  1; /* [28] RO */
		uint32_t reserved_0		: 19; /* [27:09] RO */
		uint32_t Std_Route_Tbl_CFg_Sup	:  1; /* [08] RO */
		uint32_t reserved_1		:  4; /* [07:04] RO */
		uint32_t Extended_Features	:  1; /* [03] RO */
		uint32_t Extended_Addr_Suport	:  3; /* [02:00] RO */
#else /* __e2k__ */
		uint32_t Extended_Addr_Suport	:  3; /* [02:00] RO */
		uint32_t Extended_Features	:  1; /* [03] RO */
		uint32_t reserved_1		:  4; /* [07:04] RO */
		uint32_t Std_Route_Tbl_CFg_Sup	:  1; /* [08] RO */
		uint32_t reserved_0		: 19; /* [27:09] RO */
		uint32_t Switch			:  1; /* [28] RO */
		uint32_t Processor		:  1; /* [29] RO */
		uint32_t Memory			:  1; /* [30] RO */
		uint32_t Bridge			:  1; /* [31] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ecs_pef_car_reg_t;

/* ECS_SRCOPR_CAR */
/* reserved */

/* ECS_DSTOPR_CAR */
/* reserved */


/* ECS_PELLCTRL_CSR */
#define ECS_PELLCTRL_CSR_EXTADDRCTRL_64		0x02	/* "or" */
#define ECS_PELLCTRL_CSR_EXTADDRCTRL_32		0x01
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0		: 29; /* [31:03] RO */
		uint32_t Extended_Addr_Control	:  3; /* [02:00] RW */
#else /* __e2k__ */
		uint32_t Extended_Addr_Control	:  3; /* [02:00] RW */
		uint32_t reserved_0		: 29; /* [31:03] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ecs_pellctrl_csr_reg_t;

/* ECS_GPSTAT_CSR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0		: 28; /* [31:04] RO */
		uint32_t Auto_Enable		:  1; /* [03] RW */
		uint32_t Discovered		:  1; /* [02] RW */
		uint32_t reserved_1		:  1; /* [01] RO */
		uint32_t Host			:  1; /* [00] RW */
#else /* __e2k__ */
		uint32_t Host			:  1; /* [00] RW */
		uint32_t reserved_1		:  1; /* [01] RO */
		uint32_t Discovered		:  1; /* [02] RW */
		uint32_t Auto_Enable		:  1; /* [03] RW */
		uint32_t reserved_0		: 28; /* [31:04] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ecs_gpstat_csr_reg_t;

/* ECS_BASEDEVID_CSR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0		:  8; /* [31:24] RO */
		uint32_t Base_DeviceID		:  8; /* [23:16] RW */
		uint32_t reserved_1		: 16; /* [15:00] RO */
#else /* __e2k__ */
		uint32_t reserved_1		: 16; /* [15:00] RO */
		uint32_t Base_DeviceID		:  8; /* [23:16] RW */
		uint32_t reserved_0		:  8; /* [31:24] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ecs_basedevid_csr_reg_t;

/* ECS_HBASEDEVIDLOCK_CSR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0		: 16; /* [31:16] RO */
		uint32_t Host_Base_DeviceID	: 16; /* [15:00] RW */
#else /* __e2k__ */
		uint32_t Host_Base_DeviceID	: 16; /* [15:00] RW */
		uint32_t reserved_0		: 16; /* [31:16] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ecs_hbasedevidlock_csr_reg_t;

/* ECS_ROUTE_RESP */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0		: 24; /* [31:08] RO */
		uint32_t Msg_Route		:  4; /* [07:04] RW */
		uint32_t RDMA_Route		:  4; /* [03:00] RW */
#else /* __e2k__ */
		uint32_t RDMA_Route		:  4; /* [03:00] RW */
		uint32_t Msg_Route		:  4; /* [07:04] RW */
		uint32_t reserved_0		: 24; /* [31:08] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ecs_route_resp_reg_t;

/* ECS_PHYSTAT_CTRL */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0		: 19; /* [31:13] RO */
		uint32_t Port_OK		:  1; /* [12] R0 */
		uint32_t reserved_1		: 12; /* [11:00] RO */
#else /* __e2k__ */
		uint32_t reserved_1		: 12; /* [11:00] RO */
		uint32_t Port_OK		:  1; /* [12] R0 */
		uint32_t reserved_0		: 19; /* [31:13] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ecs_phystat_ctrl_reg_t;

/* ECS_RTACCSTAT_n */
/* if bit == 1 then route to abonent valid */
/* _0.bit00 -- BaseID 0x00 */
/* _0.bit31 -- BaseID 0x1F */
/* _1.bit00 -- BaseID 0x20 */
/* _1.bit31 -- BaseID 0x3F */
/* _2.bit00 -- BaseID 0x40 */
/* _2.bit31 -- BaseID 0x5F */
/* _3.bit00 -- BaseID 0x60 */
/* _3.bit31 -- BaseID 0x7F */
/* _4.bit00 -- BaseID 0x80 */
/* _4.bit31 -- BaseID 0x9F */
/* _5.bit00 -- BaseID 0xA0 */
/* _5.bit31 -- BaseID 0xBF */
/* _6.bit00 -- BaseID 0xC0 */
/* _6.bit31 -- BaseID 0xDF */
/* _7.bit00 -- BaseID 0xE0 */
/* _7.bit31 -- BaseID 0xFF */


/*
 * m2mlc_ecs_reg_t.id
 */

typedef enum {
	/* type */
	ECS_DEVID_CAR		= 0x000, /* Device_Identity_CAR | RO */
	ECS_DEVINF_CAR		= 0x004, /* Device_Information_CAR | RO */
	ECS_ASMBLID_CAR		= 0x008, /* Assembly_Identity_CAR | RO */
	ECS_ASMBLINF_CAR	= 0x00C, /* Assembly_Information_CAR | RO */
	ECS_PEF_CAR		= 0x010, /* Processing_Elem_Features_CAR | RO */
# if 0 /* reserved */
	ECS_SRCOPR_CAR		= 0x018, /* Source_Operations_CAR | ?? */
	ECS_DSTOPR_CAR		= 0x01C, /* Destination_Operations_CAR | ?? */
#endif /* reserved */

	/* status & control */
	ECS_PELLCTRL_CSR	= 0x04C, /* Processing_Elem_Logical_Layer
					    _Control_CSR | RW */
	ECS_GPSTAT_CSR		= 0x05C, /* General_Port_Status_CSR | RW */
	ECS_BASEDEVID_CSR	= 0x060, /* Base_Device_ID_CSR | RW */
	ECS_HBASEDEVIDLOCK_CSR	= 0x068, /* Host_Base_Device_ID_Lock_CSR | RW */
	ECS_ROUTE_RESP		= 0x06C, /* Responce Route Field | RW */
#ifdef __sparc__
	ECS_SPARC_PORT_PHY_REGADDR	= 0x104, /* Port_PHY_Reg_Address | RW */
	ECS_SPARC_PORT_PHY_REGDATA	= 0x108, /* Port_PHY_Reg_Data | RW */
#endif /* __sparc__ */
	/* local registers */
	ECS_PHYSTAT_CTRL	= 0x10C, /* PHY_Port_Pn_Status_Control | RO */
	ECS_RTACCSTAT_0		= 0x110, /* RT_Access_Status_0 | RO */
	ECS_RTACCSTAT_1		= 0x114, /* RT_Access_Status_1 | RO */
	ECS_RTACCSTAT_2		= 0x118, /* RT_Access_Status_2 | RO */
	ECS_RTACCSTAT_3		= 0x11C, /* RT_Access_Status_3 | RO */
	ECS_RTACCSTAT_4		= 0x120, /* RT_Access_Status_4 | RO */
	ECS_RTACCSTAT_5		= 0x124, /* RT_Access_Status_5 | RO */
	ECS_RTACCSTAT_6		= 0x128, /* RT_Access_Status_6 | RO */
	ECS_RTACCSTAT_7		= 0x12C  /* RT_Access_Status_7 | RO */
} M2MLC_ECS_REG_ID;

typedef struct {
	u_int32_t id;	/* M2MLC_ECS_REG_ID */
	u_int32_t val;
} m2mlc_ecs_reg_t;


/*
 * M2MLC_IOCTL_ECS_READ_REG
 * Read ECS register
 * (don't check Node)
 *
 * Returns:
 *   -EFAULT - copy_to/from_user failure
 *   0 - success
 *
 * Usage:
 *   m2mlc_ecs_reg_t reg;
 *   reg.id = ECS_DEVID_CAR;
 *   if(ioctl(fd, M2MLC_IOCTL_ECS_READ_REG, &reg)) printf("Error: %m\n");
 *   else u_int32_t value = reg.val;
 */
#define M2MLC_IOCTL_ECS_READ_REG (_IOWR(M2MLC_IOC_MAGIC, 18, m2mlc_ecs_reg_t))


/*
 * M2MLC_IOCTL_ECS_WRITE_REG
 * Write ECS register
 * for root only (don't check Node, or special Node)
 *
 * Returns:
 *   -EFAULT - copy_from_user failure
 *   0 - success
 *
 * Usage:
 *   m2mlc_ecs_reg_t reg;
 *   reg.id = ECS_PELLCTRL_CSR;
 *   reg.val = <value>;
 *   if(ioctl(fd, M2MLC_IOCTL_ECS_WRITE_REG, &reg)) printf("Error: %m\n");
 */

#define M2MLC_IOCTL_ECS_WRITE_REG (_IOW(M2MLC_IOC_MAGIC, 19, m2mlc_ecs_reg_t))


/**
 ******************************************************************************
 * DEBUG
 ******************************************************************************
 */

/*
 * M2MLC_IOCTL_PRINT_REGS
 * Print registers dump to syslog
 *
 * Returns:
 *   -EFAULT - copy_from_user failure
 *   0 - success
 *
 * Usage: ioctl(fd, M2MLC_IOCTL_PRINT_REGS, NULL);
 * Usage:
 *   uint32_t regmsk = M2MLC_PRINTREG_*;
 *   if(ioctl(fd, M2MLC_IOCTL_PRINT_REGS, &regmsk)) printf("Error: %m\n");
 */
#define M2MLC_IOCTL_PRINT_REGS (_IOW(M2MLC_IOC_MAGIC, 20, uint32_t))

/* used on this ioctl and write to device */
#define M2MLC_PRINTREG_BAR0	0x01000000
#define M2MLC_PRINTREG_RTACCESS	0x02000000
#define M2MLC_PRINTREG_BAR1	0x00100000
#define M2MLC_PRINTREG_ALLRB	0x000FFFFF  /* bit 19..0 - Resource Block N */
#define M2MLC_PRINTREG_COMMON	0x10000000


/**
 ******************************************************************************
 * MMAP offset
 ******************************************************************************
 */

/*
 * ENDPOINT Registers (BAR1)
 */
#ifdef __sparc__     /* ARCH: e90, e90s */
#define M2MLC_MMAP_ENDPOINT_REGS_BASE		0		/* +0 */
#define M2MLC_MMAP_ENDPOINT_REGS_SIZE		0x2000		/* 0x100 */
#else /* __e2k__ */
#define M2MLC_MMAP_ENDPOINT_REGS_BASE		0		/* +0 */
#define M2MLC_MMAP_ENDPOINT_REGS_SIZE		0x1000		/* 0x100 */
#endif /* __sparc__ */


/*
 * PIO Payload Base Address (BAR2, 256b)
 * - transmit data
 */
#ifdef __sparc__     /* ARCH: e90, e90s */
#define M2MLC_MMAP_PIO_PAYLOAD_BASE		0x2000		/* +8k */
#define M2MLC_MMAP_PIO_PAYLOAD_SIZE		0x2000		/* 256 */
#else /* __e2k__ */
#define M2MLC_MMAP_PIO_PAYLOAD_BASE		0x1000		/* +4k */
#define M2MLC_MMAP_PIO_PAYLOAD_SIZE		0x1000		/* 256 */
#endif /* __sparc__ */

/*
 * PIO Done Queue Table Base Address (RAM, 16 * 4b = 64b)
 * - responce queue: size, status, tag
 */
#ifdef __sparc__     /* ARCH: e90, e90s */
#define M2MLC_MMAP_PIO_DONE_QUEUE_BASE		0x4000		/* +16k */
#define M2MLC_MMAP_PIO_DONE_QUEUE_SIZE		0x2000		/* 64 */
#else /* __e2k__ */
#define M2MLC_MMAP_PIO_DONE_QUEUE_BASE		0x2000		/* +8k */
#define M2MLC_MMAP_PIO_DONE_QUEUE_SIZE		0x1000		/* 64 */
#endif /* __sparc__ */

/*
 * PIO Data Queue Base Address (RAM, 16 * 256b = 4k)
 * - responce data queue
 */
#ifdef __sparc__     /* ARCH: e90, e90s */
#define M2MLC_MMAP_PIO_DATA_QUEUE_BASE		0x6000		/* +24k */
#define M2MLC_MMAP_PIO_DATA_QUEUE_SIZE		0x2000		/* +4k */
#else /* __e2k__ */
#define M2MLC_MMAP_PIO_DATA_QUEUE_BASE		0x3000		/* +12k */
#define M2MLC_MMAP_PIO_DATA_QUEUE_SIZE		0x1000
#endif /* __sparc__ */


/*
 * Status flags & Done pointers (RAM, 3 * 4b = 12b)
 * - Copy of Mailbox Write & Done Packet Register
 * - Copy of Doorbell Write & Done Pointer Register
 * - Copy of DMA Head & Done Pointer Register
 */
#ifdef __sparc__     /* ARCH: e90, e90s */
#define M2MLC_MMAP_DONE_REGS_COPY_BASE		0x8000		/* +32k */
#define M2MLC_MMAP_DONE_REGS_COPY_SIZE		0x2000		/* 12 */
#else /* __e2k__ */
#define M2MLC_MMAP_DONE_REGS_COPY_BASE		0x5000		/* +20k */
#define M2MLC_MMAP_DONE_REGS_COPY_SIZE		0x1000		/* 12 */
#endif /* __sparc__ */

typedef struct {
	uint32_t mb_write_done_ptr;
	uint32_t db_write_done_ptr;
	uint32_t dma_head_done_ptr;
} __packed m2mlc_done_regs_t;


/*
 * Dorbell Queue Address (RAM, 256 * 8b = 2k)
 * - indication queue
 */
#ifdef __sparc__     /* ARCH: e90, e90s */
#define M2MLC_MMAP_DB_QUEUE_BASE		0xA000		/* +40k */
#define M2MLC_MMAP_DB_QUEUE_SIZE		0x2000		/* 0x800, 2k */
#else /* __e2k__ */
#define M2MLC_MMAP_DB_QUEUE_BASE		0x6000		/* +24k */
#define M2MLC_MMAP_DB_QUEUE_SIZE		0x1000		/* 0x800 */
#endif /* __sparc__ */


/*
 * DMA Start Address (RAM, 4096 * 32b = 128k)
 * - dma request descriptor queue
 */
#ifdef __sparc__     /* ARCH: e90, e90s */
#define M2MLC_MMAP_DMA_DESCR_QUEUE_BASE		0xC000		/* +48k */
#define M2MLC_MMAP_DMA_DESCR_QUEUE_SIZE		0x20000     /* 128k */
#else /* __e2k__ */
#define M2MLC_MMAP_DMA_DESCR_QUEUE_BASE		0x7000		/* +28k */
#define M2MLC_MMAP_DMA_DESCR_QUEUE_SIZE		0x20000
#endif /* __sparc__ */

/*
 * DMA Done Queue Address (RAM, 4096 * 4b = 16k)
 * - dma done descriptor queue
 */
#ifdef __sparc__     /* ARCH: e90, e90s */
#define M2MLC_MMAP_DMA_DONE_QUEUE_BASE		0x2C000		/* +176k */
#define M2MLC_MMAP_DMA_DONE_QUEUE_SIZE		0x4000      /* 16k */
#else /* __e2k__ */
#define M2MLC_MMAP_DMA_DONE_QUEUE_BASE		0x27000		/* +156k */
#define M2MLC_MMAP_DMA_DONE_QUEUE_SIZE		0x4000
#endif /* __sparc__ */


/*
 * Mailbox Done Queue Address (RAM, 1024 * 8b = 8k)
 * - mailbox done
 */
#ifdef __sparc__     /* ARCH: e90, e90s */
#define M2MLC_MMAP_MB_DONE_QUEUE_BASE		0x30000		/* +192k */
#define M2MLC_MMAP_MB_DONE_QUEUE_SIZE		0x2000      /* 8k */
#else /* __e2k__ */
#define M2MLC_MMAP_MB_DONE_QUEUE_BASE		0x2B000		/* +172k */
#define M2MLC_MMAP_MB_DONE_QUEUE_SIZE		0x2000
#endif /* __sparc__ */

/*
 * Mailbox Structure Address (RAM, 1024 * 4k = 4M)
 * - mail data
 */
#define M2MLC_MMAP_MB_MAIL_BASE			0x100000	/* +1M */
#define M2MLC_MMAP_MB_MAIL_SIZE			0x400000


/**
 ******************************************************************************
 * BAR1: Control Regs: PIO, Mailbox, DoorBell, DMA, Interrupt, Status
 ******************************************************************************
 */

/**
 *  Resource Block N
 */
/* = PIO box = */
#define M2MLC_RB_PIO_TRGT_PTR_L		0x00	/* Target Pointer lower */
#define M2MLC_RB_PIO_TRGT_PTR_H		0x04	/* Target Pointer upper */
#define M2MLC_RB_PIO_TRANS_PRM		0x08	/* Transaction parameters */
#define M2MLC_RB_PIO_TRANS_FS		0x0C	/* Transaction Format&Status */
#define M2MLC_RB_PIO_DRBL		0x10	/* Doorbell */

/* = Mailbox Register Block = */
#define M2MLC_RB_MB_STR_ADDR_L		0x20	/* Structure Address Lower */
#define M2MLC_RB_MB_STR_ADDR_H		0x24	/* Structure Address Upper */
#define M2MLC_RB_MB_STR_PTRS		0x28	/* Struct Head&Tail Pointer */
#define M2MLC_RB_MB_DONE_PTRS		0x2C	/* Done Head&Tail Pointer */
#define M2MLC_RB_MB_RET_ADDR_L		0x30	/* Return Address Lower */
#define M2MLC_RB_MB_RET_ADDR_H		0x34	/* Return Address Upper */
#define M2MLC_RB_MB_DONE_QUE_ADDR_L	0x38	/* Done Queue Address Lower */
#define M2MLC_RB_MB_DONE_QUE_ADDR_H	0x3C	/* Done Queue Address Upper */

/* = Doorbell's Register Block = */
#define M2MLC_RB_DB_START_ADDR_L	0x40	/* Start Address Lower */
#define M2MLC_RB_DB_START_ADDR_H	0x44	/* Start Address Upper */
#define M2MLC_RB_DB_RET_ADDR_L		0x48	/* Return Address Lower */
#define M2MLC_RB_DB_RET_ADDR_H		0x4C	/* Return Address Upper */
#define M2MLC_RB_DB_PTRS		0x50	/* Head&Tail Pointer */

/* = DMA Mode Block = */
#define M2MLC_RB_DMA_START_ADDR_L	0x60	/* Start Address Lower */
#define M2MLC_RB_DMA_START_ADDR_H	0x64	/* Start Address Upper */
#define M2MLC_RB_DMA_STR_PTRS		0x68	/* Struct Head&Tail Pointer */
#define M2MLC_RB_DMA_QUE_SIZE		0x6C	/* Queue Size Register */
#define M2MLC_RB_DMA_RET_ADDR_L		0x70	/* Return Address Lower */
#define M2MLC_RB_DMA_RET_ADDR_H		0x74	/* Return Address Upper */
#define M2MLC_RB_DMA_DONE_QUE_ADDR_L	0x78	/* Done Queue Address Lower */
#define M2MLC_RB_DMA_DONE_QUE_ADDR_H	0x7C	/* Done Queue Address Upper */
#define M2MLC_RB_DMA_DONE_PTRS		0x80	/* Done Head&Tail Pointer */

/* = Interrupts = */
#define M2MLC_RB_INT_STATUS		0xA0	/* Interrupt Status */
#define M2MLC_RB_INT_ENABLE		0xA4	/* Interrupt Enable */
    #define M2MLC_RB_INT_ENABLE_MSK	0x00037775	/* All Enable */

/* = Error Reporting = */
#define M2MLC_RB_ERR_STATUS		0xA8	/* Error Status */


/**
 ******************************************************************************
 * SCR - System Switch / Maintenance
 ******************************************************************************
 */

/* SCR_PEF_CAR */
#define SCR_PEF_CAR_EXTADDRSUP_66	0x04
#define SCR_PEF_CAR_EXTADDRSUP_50	0x02
#define SCR_PEF_CAR_EXTADDRSUP_34	0x01
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t Bridge			:  1; /* [31] RO */
		uint32_t Memory			:  1; /* [30] RO */
		uint32_t Processor		:  1; /* [29] RO */
		uint32_t Switch			:  1; /* [28] RO */
		uint32_t reserved_0		: 19; /* [27:09] RO */
		uint32_t Std_Route_Tbl_CFg_Sup	:  1; /* [08] RO */
		uint32_t reserved_1		:  4; /* [07:04] RO */
		uint32_t Extended_Features	:  1; /* [03] RO */
		uint32_t Extended_Addr_Suport	:  3; /* [02:00] RO */
#else /* __e2k__ */
		uint32_t Extended_Addr_Suport	:  3; /* [02:00] RO */
		uint32_t Extended_Features	:  1; /* [03] RO */
		uint32_t reserved_1		:  4; /* [07:04] RO */
		uint32_t Std_Route_Tbl_CFg_Sup	:  1; /* [08] RO */
		uint32_t reserved_0		: 19; /* [27:09] RO */
		uint32_t Switch			:  1; /* [28] RO */
		uint32_t Processor		:  1; /* [29] RO */
		uint32_t Memory			:  1; /* [30] RO */
		uint32_t Bridge			:  1; /* [31] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed scr_pef_car_reg_t;

/* SCR_SWPINF_CAR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0		: 16; /* [31:16] RO */
		uint32_t Port_Total		:  8; /* [15:08] RO */
		uint32_t Ext_Port_Num		:  8; /* [07:00] RO */
#else /* __e2k__ */
		uint32_t Ext_Port_Num		:  8; /* [07:00] RO */
		uint32_t Port_Total		:  8; /* [15:08] RO */
		uint32_t reserved_0		: 16; /* [31:16] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed scr_swpinf_car_reg_t;

/* SCR_TIMEOUT */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0		: 24; /* [31:08] RO */
		uint32_t Timeout		:  8; /* [07:00] RO */
#else /* __e2k__ */
		uint32_t Timeout		:  8; /* [07:00] RO */
		uint32_t reserved_0		: 24; /* [31:08] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed scr_timeout_reg_t;
/* Time = (Timeout + 1) * 2^17 * Tsys; Tsys == 8ns; */

/* SCR_SWRTDSTIDLIM_CAR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0		: 16; /* [31:16] RO */
		uint32_t Max_DstID		: 16; /* [15:00] RO */
#else /* __e2k__ */
		uint32_t Max_DstID		: 16; /* [15:00] RO */
		uint32_t reserved_0		: 16; /* [31:16] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed scr_swrtdstidlim_car_reg_t;

/* SCR_HBASEDEVIDLOCK_CSR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0		: 16; /* [31:16] RO */
		uint32_t Host_Base_DeviceID	: 16; /* [15:00] RW */
#else /* __e2k__ */
		uint32_t Host_Base_DeviceID	: 16; /* [15:00] RW */
		uint32_t reserved_0		: 16; /* [31:16] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed scr_hbasedevidlock_csr_reg_t;

/* SCR_STDRCFGDSTSEL_CSR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_1		:  8; /* [31:24] RO */
		uint32_t Config_Port		:  8; /* [23:16] RW */
		uint32_t reserved_0		:  8; /* [15:08] RO */
		uint32_t Config_DestID		:  8; /* [07:00] RW */
#else /* __e2k__ */
		uint32_t Config_DestID		:  8; /* [07:00] RW */
		uint32_t reserved_0		:  8; /* [15:08] RO */
		uint32_t Config_Port		:  8; /* [23:16] RW */
		uint32_t reserved_1		:  8; /* [31:24] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed scr_stdrcfgdstsel_csr_reg_t;

/* SCR_STDRCFGPORTSEL_CSR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0		: 24; /* [31:08] RO */
		uint32_t Config_Out_Port	:  8; /* [07:00] RW */
#else /* __e2k__ */
		uint32_t Config_Out_Port	:  8; /* [07:00] RW */
		uint32_t reserved_0		: 24; /* [31:08] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed scr_stdrcfgportsel_csr_reg_t;

/* SCR_STDRDEFPORT_CSR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0		: 24; /* [31:08] RO */
		uint32_t Defailt_Out_Port	:  8; /* [07:00] RW */
#else /* __e2k__ */
		uint32_t Defailt_Out_Port	:  8; /* [07:00] RW */
		uint32_t reserved_0		: 24; /* [31:08] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed scr_stdrdefport_csr_reg_t;

/* SCR_PORT_PHY_PRESENCE */
/* bit0 - Port0, ..., bit31 - Port31 */

/* SCR_PORT_PHY_REGADDR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0		: 16; /* [31:16] RO */
		uint32_t Port_Number		:  8; /* [15:08] RW */
		uint32_t Reg_Offset		:  8; /* [07:00] RW */
#else /* __e2k__ */
		uint32_t Reg_Offset		:  8; /* [07:00] RW */
		uint32_t Port_Number		:  8; /* [15:08] RW */
		uint32_t reserved_0		: 16; /* [31:16] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed scr_port_phy_regaddr_reg_t;

/* SCR_PORT_PHY_REGDATA */
/* 32-bit DATA from/to PHY */

/* SCR_LOCPORT_STAT_CTRL */
/* SCR_PHYPORTx_STAT_CTRL */
#define SCR_PORT_STAT_CTRL_TCx_TCVC_MAP_VC0	0x00
#define SCR_PORT_STAT_CTRL_TCx_TCVC_MAP_VC1	0x01
#define SCR_PORT_STAT_CTRL_TCx_TCVC_MAP_VC2	0x02
#define SCR_PORT_STAT_CTRL_TCx_TCVC_MAP_VC3	0x03
#define SCR_PORT_STAT_CTRL_COC_ENABLE_VC0	0x01
#define SCR_PORT_STAT_CTRL_COC_ENABLE_VC1	0x02
#define SCR_PORT_STAT_CTRL_COC_ENABLE_VC2	0x04
#define SCR_PORT_STAT_CTRL_COC_ENABLE_VC3	0x08
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0		: 19; /* [31:13] RO */
		uint32_t Port_OK		:  1; /* [12] R0 */
		uint32_t coc_enable		:  4; /* [11:08] RO */
		uint32_t TC3_TCVC_map		:  2; /* [07:06] RW */
		uint32_t TC2_TCVC_map		:  2; /* [05:04] RW */
		uint32_t TC1_TCVC_map		:  2; /* [03:02] RO */
		uint32_t TC0_TCVC_map		:  2; /* [01:00] RO */
#else /* __e2k__ */
		uint32_t TC0_TCVC_map		:  2; /* [01:00] RO */
		uint32_t TC1_TCVC_map		:  2; /* [03:02] RO */
		uint32_t TC2_TCVC_map		:  2; /* [05:04] RW */
		uint32_t TC3_TCVC_map		:  2; /* [07:06] RW */
		uint32_t coc_enable		:  4; /* [11:08] RO */
		uint32_t Port_OK		:  1; /* [12] R0 */
		uint32_t reserved_0		: 19; /* [31:13] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed scr_port_stat_ctrl_reg_t;

typedef enum {
	/* CAR */
	SCR_PEF_CAR		= 0x010, /* Processing_Elem_Features_CAR | RO */
	SCR_SWPINF_CAR		= 0x014, /* Switch_Port_Information_CAR | RO */
	SCR_TIMEOUT		= 0x020, /* Timeout | RW */
	SCR_SWRTDSTIDLIM_CAR	= 0x034, /* Switch_Route_Table_
					    Destination_ID_Limit_CAR | RO */
	/* CSR */
	SCR_HBASEDEVIDLOCK_CSR	= 0x068, /* Host_Base_Device_ID_Lock_CSR | RW */
	SCR_STDRCFGDSTSEL_CSR	= 0x070, /* Standart_Route_Configuration_
					    Destination_Select_CSR | RW */
	SCR_STDRCFGPORTSEL_CSR	= 0x074, /* Standart_Route_Configuration_
					    Port_Select_CSR | RW */
	SCR_STDRDEFPORT_CSR	= 0x078, /* Standart_Route_Default_
					    Port_CSR | RW */
	/* PHY */
	SCR_PORT_PHY_PRESENCE	= 0x100, /* Port_PHY_Presence | RO */
	SCR_PORT_PHY_REGADDR	= 0x104, /* Port_PHY_Reg_Address | RW */
	SCR_PORT_PHY_REGDATA	= 0x108, /* Port_PHY_Reg_Data | RW */

	SCR_LOCPORT_STAT_CTRL	= 0x10C, /* Local_Port_Status_Control | RW */
			       /* 0x110 + 4*Pn */
	SCR_PHYPORT0_STAT_CTRL	= 0x110, /* PHY_Port_0_Status_Control | RW */
	SCR_PHYPORT1_STAT_CTRL	= 0x114, /* PHY_Port_1_Status_Control | RW */
	SCR_PHYPORT2_STAT_CTRL	= 0x118, /* PHY_Port_2_Status_Control | RW */
	SCR_PHYPORT3_STAT_CTRL	= 0x11C, /* PHY_Port_3_Status_Control | RW */
	SCR_PHYPORT4_STAT_CTRL	= 0x120, /* PHY_Port_4_Status_Control | RW */
	SCR_PHYPORT5_STAT_CTRL	= 0x124  /* PHY_Port_5_Status_Control | RW */
} M2MLC_SCR_REG_ID;


/**
 ******************************************************************************
 * WLCC - Port PHY Registers
 ******************************************************************************
 */

/* WLCC_VID_STSR */
#define WLCC_VID_STSR_VENDORID	0x1FFF
#define WLCC_VID_STSR_DEVICEID	0x8013
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t device_id	: 16; /* [31:16] RO = 0x8013 */
		uint32_t vendor_id	: 16; /* [15:00] RO = 0x1FFF */
#else /* __e2k__ */
		uint32_t vendor_id	: 16; /* [15:00] RO = 0x1FFF */
		uint32_t device_id	: 16; /* [31:16] RO = 0x8013 */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed wlcc_vid_stsr_reg_t;

/* WLCC_PLS_CTLR */
/* ltssm_state value: */
#define WLCC_PLS_CTLR_LTSSMST_POFF	0x0
#define WLCC_PLS_CTLR_LTSSMST_DIS	0x1
#define WLCC_PLS_CTLR_LTSSMST_SLEEP	0x2
#define WLCC_PLS_CTLR_LTSSMST_LUP	0x3
#define WLCC_PLS_CTLR_LTSSMST_SRV	0x4
#define WLCC_PLS_CTLR_LTSSMST_INIT	0x5
#define WLCC_PLS_CTLR_LTSSMST_DNCFG	0x6
#define WLCC_PLS_CTLR_LTSSMST_UPCFG	0x7
/* link_width & link_scale bitfields: */
#define WLCC_PLS_CTLR_LINK_LANE_03_00	0x1
#define WLCC_PLS_CTLR_LINK_LANE_07_04	0x2
#define WLCC_PLS_CTLR_LINK_LANE_11_08	0x4
#define WLCC_PLS_CTLR_LINK_LANE_15_12	0x8
/* ltssm_cmd_sts value: */
#define WLCC_PLS_CTLR_LTSSMCMDSTS_INVAL		0x7
#define WLCC_PLS_CTLR_LTSSMCMDSTS_FAILDTCT	0x0
#define WLCC_PLS_CTLR_LTSSMCMDSTS_FAILPOLL	0x1
#define WLCC_PLS_CTLR_LTSSMCMDSTS_FAILCFG	0x2
#define WLCC_PLS_CTLR_LTSSMCMDSTS_OK		0x3
#define WLCC_PLS_CTLR_LTSSMCMDSTS_SLEEP		0x4
/* ltssm_cmd_op value: */
#define WLCC_PLS_CTLR_LTSSMCMDOP_POFF	0x0
#define WLCC_PLS_CTLR_LTSSMCMDOP_DIS	0x1
#define WLCC_PLS_CTLR_LTSSMCMDOP_SLEEP	0x2
#define WLCC_PLS_CTLR_LTSSMCMDOP_LUP	0x3
#define WLCC_PLS_CTLR_LTSSMCMDOP_SRV	0x4
#define WLCC_PLS_CTLR_LTSSMCMDOP_RECONF	0x5
#define WLCC_PLS_CTLR_LTSSMCMDOP_LOCSRV	0x6
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t link_active	:  1; /* [31]    RO */
		uint32_t reserved_0	:  2; /* [30:29] RO */
		uint32_t ltssm_state	:  2; /* [28:27] RO */
		uint32_t ltssm_state_id	:  3; /* [26:24] RO */
		uint32_t reserved_1	:  4; /* [23:20] RO */
		uint32_t link_width	:  4; /* [19:16] RO */
		uint32_t reserved_2	:  4; /* [15:12] RO */
		uint32_t link_scale	:  4; /* [11:08] RW = 0xF */
		uint32_t ltssm_cmd_act	:  1; /* [07]    RO */
		uint32_t ltssm_cmd_sts	:  3; /* [06:04] RO */
		uint32_t reserved_3	:  1; /* [03]    RO */
		uint32_t ltssm_cmd_op	:  3; /* [02:00] RW */
#else /* __e2k__ */
		uint32_t ltssm_cmd_op	:  3; /* [02:00] RW */
		uint32_t reserved_3	:  1; /* [03]    RO */
		uint32_t ltssm_cmd_sts	:  3; /* [06:04] RO */
		uint32_t ltssm_cmd_act	:  1; /* [07]    RO */
		uint32_t link_scale	:  4; /* [11:08] RW = 0xF */
		uint32_t reserved_2	:  4; /* [15:12] RO */
		uint32_t link_width	:  4; /* [19:16] RO */
		uint32_t reserved_1	:  4; /* [23:20] RO */
		uint32_t ltssm_state_id	:  3; /* [26:24] RO */
		uint32_t ltssm_state	:  2; /* [28:27] RO */
		uint32_t reserved_0	:  2; /* [30:29] RO */
		uint32_t link_active	:  1; /* [31]    RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed wlcc_pls_ctlr_reg_t;

/* WLCC_PLM_CTLR */
/* data_rate_ctl & data_rate_sts value: */
#define WLCC_PLM_CTLR_DATARATE_2G5	0
#define WLCC_PLM_CTLR_DATARATE_5G0	1
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t rx_uflw	:  1; /* [31]    RWC */
		uint32_t rx_oflw	:  1; /* [30]    RWC */
		uint32_t data_rate_sts	:  1; /* [29]    RO */
		uint32_t scramble_sts	:  1; /* [28]    RO */
		uint32_t reserved_0	: 12; /* [27:16] RO */
		uint32_t data_rate_ctl	:  1; /* [15]    RW */
		uint32_t persist_linkup	:  1; /* [14]    RW = 0 */
		uint32_t ctc_en		:  1; /* [13]    RW = 1 */
		uint32_t scramble_ctl	:  1; /* [12]    RW = 1 */
		uint32_t reserved_1	: 12; /* [11:00] RO */
#else /* __e2k__ */
		uint32_t reserved_1	: 12; /* [11:00] RO */
		uint32_t scramble_ctl	:  1; /* [12]    RW = 1 */
		uint32_t ctc_en		:  1; /* [13]    RW = 1 */
		uint32_t persist_linkup	:  1; /* [14]    RW = 0 */
		uint32_t data_rate_ctl	:  1; /* [15]    RW */
		uint32_t reserved_0	: 12; /* [27:16] RO */
		uint32_t scramble_sts	:  1; /* [28]    RO */
		uint32_t data_rate_sts	:  1; /* [29]    RO */
		uint32_t rx_oflw	:  1; /* [30]    RWC */
		uint32_t rx_uflw	:  1; /* [31]    RWC */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed wlcc_plm_ctlr_reg_t;

/* WLCC_DLL_STSR */
/* ext_rqd_unit value (valid if link_ready): */
#define WLCC_DLL_STSR_EXTRQDUNIT_16	0x0
#define WLCC_DLL_STSR_EXTRQDUNIT_32	0x1
#define WLCC_DLL_STSR_EXTRQDUNIT_64	0x2
/* ext_abtype value (valid if link_ready): */
#define WLCC_DLL_STSR_EXTABTYPE_CPU	0x0
#define WLCC_DLL_STSR_EXTABTYPE_IOHUB	0x1
/* event_imask mask: */
#define WLCC_DLL_STSR_EVENTIMASK_LINKSTATECHG	0x8
#define WLCC_DLL_STSR_EVENTIMASK_LTSSMCMDCPL	0x4
#define WLCC_DLL_STSR_EVENTIMASK_RCVRTIMEOUT	0x2
#define WLCC_DLL_STSR_EVENTIMASK_REGACSERR	0x1
/* ecnt_mode value: */
#define WLCC_DLL_STSR_ECNTMODE_STOP	0x0
#define WLCC_DLL_STSR_ECNTMODE_ERR	0x1
#define WLCC_DLL_STSR_ECNTMODE_RETRY	0x2
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t link_ready	:  1; /* [31]    RO */
		uint32_t ext_rqd_unit	:  2; /* [30:29] RO */
		uint32_t irq_active	:  1; /* [28]    RO */
		uint32_t ext_abtype	:  4; /* [27:24] RO */
		uint32_t link_state_chg	:  1; /* [23]    RWC */
		uint32_t ltssm_cmd_cpl	:  1; /* [22]    RWC */
		uint32_t rcvr_time_out	:  1; /* [21]    RWC */
		uint32_t reg_acs_err	:  1; /* [20]    RWC */
		uint32_t event_imask	:  4; /* [19:16] RW = 0 */
		uint32_t reserved_0	:  2; /* [15:14] RO */
		uint32_t ecnt_mode	:  2; /* [13:12] RW = 0 */
		uint32_t ecnt_oflw	:  1; /* [11]    RWC = 0 */
		uint32_t ecnt		: 11; /* [10:00] RO = 0 */
#else /* __e2k__ */
		uint32_t ecnt		: 11; /* [10:00] RO = 0 */
		uint32_t ecnt_oflw	:  1; /* [11]    RWC = 0 */
		uint32_t ecnt_mode	:  2; /* [13:12] RW = 0 */
		uint32_t reserved_0	:  2; /* [15:14] RO */
		uint32_t event_imask	:  4; /* [19:16] RW = 0 */
		uint32_t reg_acs_err	:  1; /* [20]    RWC */
		uint32_t rcvr_time_out	:  1; /* [21]    RWC */
		uint32_t ltssm_cmd_cpl	:  1; /* [22]    RWC */
		uint32_t link_state_chg	:  1; /* [23]    RWC */
		uint32_t ext_abtype	:  4; /* [27:24] RO */
		uint32_t irq_active	:  1; /* [28]    RO */
		uint32_t ext_rqd_unit	:  2; /* [30:29] RO */
		uint32_t link_ready	:  1; /* [31]    RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed wlcc_dll_stsr_reg_t;

/* WLCC_DLL_PRMR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0	:  4; /* [31:28] RO */
		uint32_t degr_err_lim	:  4; /* [27:24] RW = 0 */
		uint32_t degr_tmr_lim	:  8; /* [23:16] RW = 0 */
		uint32_t reserved_1	:  8; /* [15:08] RO */
		uint32_t rcvr_tmr_lim	:  8; /* [07:00] RW = 0 */
#else /* __e2k__ */
		uint32_t rcvr_tmr_lim	:  8; /* [07:00] RW = 0 */
		uint32_t reserved_1	:  8; /* [15:08] RO */
		uint32_t degr_tmr_lim	:  8; /* [23:16] RW = 0 */
		uint32_t degr_err_lim	:  4; /* [27:24] RW = 0 */
		uint32_t reserved_0	:  4; /* [31:28] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed wlcc_dll_prmr_reg_t;

/* WLCC_DLL_TMRR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0	:  5; /* [31:27] RO */
		uint32_t rpl_num_ext	:  3; /* [26:24] RW = 0 */
		uint32_t rpl_tmr_ext	:  8; /* [23:16] RW = 0 */
		uint32_t reserved_1	: 16; /* [15:00] RO */
#else /* __e2k__ */
		uint32_t reserved_1	: 16; /* [15:00] RO */
		uint32_t rpl_tmr_ext	:  8; /* [23:16] RW = 0 */
		uint32_t rpl_num_ext	:  3; /* [26:24] RW = 0 */
		uint32_t reserved_0	:  5; /* [31:27] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed wlcc_dll_tmrr_reg_t;

/* WLCC_VCM_CTLR */
/* opvc_sts value: */
#define WLCC_VCM_CTLR_OPVCSTS_SUCCESS	0x0
#define WLCC_VCM_CTLR_OPVCSTS_FAILURE	0x1
#define WLCC_VCM_CTLR_OPVCSTS_INVALID	0x2
/* opvc_typ_code value: */
#define WLCC_VCM_CTLR_OPVCTYPCODE_NOP		0x0
#define WLCC_VCM_CTLR_OPVCTYPCODE_ENABLE	0x1
#define WLCC_VCM_CTLR_OPVCTYPCODE_REDUCE	0x2
#define WLCC_VCM_CTLR_OPVCTYPCODE_DISABLE	0x3
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0	:  1; /* [31]    RO */
		uint32_t txvc_cap_num	:  3; /* [30:28] RO = 0x1 */
		uint32_t reserved_1	:  1; /* [27]    RO */
		uint32_t rxvc_cap_num	:  3; /* [26:24] RO */
		uint32_t reserved_2	:  1; /* [23]    RO */
		uint32_t opvc_rqd	:  7; /* [22:16] RW = 0 */
		uint32_t reserved_3	:  1; /* [15]    RO */
		uint32_t opvc_rqh	:  7; /* [14:08] RW = 0 */
		uint32_t opvc_act	:  1; /* [07]    RO */
		uint32_t opvc_sts	:  2; /* [06:05] RO */
		uint32_t opvc_typ_num	:  3; /* [04:02] RW = 0x0 */
		uint32_t opvc_typ_code	:  2; /* [01:00] RW = 0x1 */
#else /* __e2k__ */
		uint32_t opvc_typ_code	:  2; /* [01:00] RW = 0x1 */
		uint32_t opvc_typ_num	:  3; /* [04:02] RW = 0x0 */
		uint32_t opvc_sts	:  2; /* [06:05] RO */
		uint32_t opvc_act	:  1; /* [07]    RO */
		uint32_t opvc_rqh	:  7; /* [14:08] RW = 0 */
		uint32_t reserved_3	:  1; /* [15]    RO */
		uint32_t opvc_rqd	:  7; /* [22:16] RW = 0 */
		uint32_t reserved_2	:  1; /* [23]    RO */
		uint32_t rxvc_cap_num	:  3; /* [26:24] RO */
		uint32_t reserved_1	:  1; /* [27]    RO */
		uint32_t txvc_cap_num	:  3; /* [30:28] RO = 0x1 */
		uint32_t reserved_0	:  1; /* [31]    RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed wlcc_vcm_ctlr_reg_t;

/* WLCC_VCM_STSR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0	: 16; /* [31:16] RO */
		uint32_t rxvc_use_map	:  8; /* [15:08] RO */
		uint32_t txvc_use_map	:  8; /* [07:00] RO */
#else /* __e2k__ */
		uint32_t txvc_use_map	:  8; /* [07:00] RO */
		uint32_t rxvc_use_map	:  8; /* [15:08] RO */
		uint32_t reserved_0	: 16; /* [31:16] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed wlcc_vcm_stsr_reg_t;

/* WLCC_VCM_PRMR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0	: 24; /* [31:08] RO */
		uint32_t txvc1_fifo_m	:  1; /* [07]    RW = 0 */
		uint32_t txvc1_pri	:  3; /* [06:04] RW = 3 */
		uint32_t txvc0_fifo_m	:  1; /* [03]    RW = 0 */
		uint32_t txvc0_pri	:  3; /* [02:00] RW = 3 */
#else /* __e2k__ */
		uint32_t txvc0_pri	:  3; /* [02:00] RW = 3 */
		uint32_t txvc0_fifo_m	:  1; /* [03]    RW = 0 */
		uint32_t txvc1_pri	:  3; /* [06:04] RW = 3 */
		uint32_t txvc1_fifo_m	:  1; /* [07]    RW = 0 */
		uint32_t reserved_0	: 24; /* [31:08] RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed wlcc_vcm_prmr_reg_t;

/* WLCC_VC{0|1}_STSR */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t reserved_0	:  1; /* [31]    RO */
		uint32_t txvc_rqd_adv	:  7; /* [30:24] RO = 0 */
		uint32_t reserved_1	:  1; /* [23]    RO */
		uint32_t txvc_rqd_cur	:  7; /* [22:16] RO = 0 */
		uint32_t reserved_2	:  1; /* [15]    RO */
		uint32_t txvc_rqh_adv	:  7; /* [14:08] RO = 0 */
		uint32_t reserved_3	:  1; /* [07]    RO */
		uint32_t txvc_rqh_cur	:  7; /* [06:00] RO = 0 */
#else /* __e2k__ */
		uint32_t txvc_rqh_cur	:  7; /* [06:00] RO = 0 */
		uint32_t reserved_3	:  1; /* [07]    RO */
		uint32_t txvc_rqh_adv	:  7; /* [14:08] RO = 0 */
		uint32_t reserved_2	:  1; /* [15]    RO */
		uint32_t txvc_rqd_cur	:  7; /* [22:16] RO = 0 */
		uint32_t reserved_1	:  1; /* [23]    RO */
		uint32_t txvc_rqd_adv	:  7; /* [30:24] RO = 0 */
		uint32_t reserved_0	:  1; /* [31]    RO */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed wlcc_vc_stsr_reg_t;

typedef enum {
	WLCC_VID_STSR	= 0x000, /* Vendor Divice ID Status | RO */
	WLCC_PLS_CTLR	= 0x004, /* Physical Layer Control | RW */
	WLCC_PLM_CTLR	= 0x008, /* Physical Layer Mode Control | RW */
	WLCC_DLL_STSR	= 0x00C, /* Data Link Layer Status | RW */
	WLCC_DLL_PRMR	= 0x010, /* Data Link Layer Parameter | RW */
	WLCC_DLL_TMRR	= 0x014, /* Data Link Layer Timers | RW */
	WLCC_VCM_CTLR	= 0x018, /* Virtual Channel Mechanism Control | RW */
	WLCC_VCM_STSR	= 0x01C, /* Virtual Channel Mechanism Status | RO */
	WLCC_VCM_PRMR	= 0x020, /* Virtual Channel Mechanism Parameter | RW */
	WLCC_VC0_STSR	= 0x024, /* Virtual Channel 0 Status | RO */
	WLCC_VC1_STSR	= 0x028  /* Virtual Channel 1 Status | RO */
} M2MLC_WLCC_REG_ID;


/**
 ******************************************************************************
 * Module parameters
 ******************************************************************************
 */

/**
 * Debug mask
 * for Module parameter debug_mask
 */
#define M2MLC_DBG_MSK_UNK	0x00000001
#define M2MLC_DBG_MSK_MODULE	0x00000002
#define M2MLC_DBG_MSK_PCI	0x00000004
#define M2MLC_DBG_MSK_CDEV	0x00000008
#define M2MLC_DBG_MSK_NET	0x00000010
#define M2MLC_DBG_MSK_MEM	0x00000020
#define M2MLC_DBG_MSK_HW	0x00000100
#define M2MLC_DBG_MSK_IRQ	0x00000200
#define M2MLC_DBG_MSK_REGS	0x00000400


#endif /* _UAPI_M2MLC_IO_H */
