#ifndef M2MLC_REGS_H__
#define M2MLC_REGS_H__

/* iconnect.pdf - 2015.06.16 */

/**
 *  Bitfield tool
 */
#define GET_FIELD(r, p, m)  (((r) >> (p)) & (m))
#define GET_BIT(r, p)       GET_FIELD(r, p, 1)

#define SET_FIELD(d, p, m)  (((m) & (d)) << (p))
#define SET_BIT(p)          (1UL << (p))


/**
 * ENDIANES
 */
/* TODO: sparc */
#ifdef __sparc__	/* ARCH: e90, e90s */
  #if defined(VER_2614)
    /* convert regs + convert DMA to ram */
    #define M2MLC_ENDIAN  (0x00030300)
  #else
    /* iowrite32 for regs; convert DMA to ram */
    #define M2MLC_ENDIAN  (0x00020200)
  #endif
#else			/* ARCH: e2k, x86 */
    /* iowrite32 for regs; normal DMA */
    #define M2MLC_ENDIAN  (0x00000000)
#endif /* __sparc__ */


/**
 ******************************************************************************
 * PCI Config Space
 ******************************************************************************
 */

/* NIC Capability Register */
#define NICCPB_REG	0x40
  #define NICCPB_GET_PROCVAL(r)		GET_FIELD(r,  0, 0xFF)	/* RO [07:00] */
    #define NICCPB_PROCVAL		0x14
  #define NICCPB_GET_AACFG(r)		GET_FIELD(r,  8, 0x3F)	/* RW [13:08] */
  #define NICCPB_GET_AACFG_DMA2(r)	GET_FIELD(r, 12, 0x03)	/* RW [13:12] */
  #define NICCPB_GET_AACFG_DMA1(r)	GET_FIELD(r, 10, 0x03)	/* RW [11:10] */
  #define NICCPB_GET_AACFG_DMA0(r)	GET_FIELD(r,  8, 0x03)	/* RW [09:08] */
  #define NICCPB_SET_AACFG(d)		SET_FIELD(d,  8, 0x3F)	/* RW [13:08] */
  #define NICCPB_SET_AACFG_DMA2(d)	SET_FIELD(d, 12, 0x03)	/* RW [13:12] */
  #define NICCPB_SET_AACFG_DMA1(d)	SET_FIELD(d, 10, 0x03)	/* RW [11:10] */
  #define NICCPB_SET_AACFG_DMA0(d)	SET_FIELD(d,  8, 0x03)	/* RW [09:08] */
    #define NICCPB_AACFG_IOLINK0	0x00
    #define NICCPB_AACFG_IOLINK1	0x01
    #define NICCPB_AACFG_IOLINK2	0x02
  #define NICCPB_GET_SOFTRES(r)		GET_BIT(r, 31)		/* RW [31:31] */
  #define NICCPB_SET_SOFTRES		SET_BIT(31)		/* RW [31:31] */


/**
 ******************************************************************************
 * BAR0: Element_Config_Space (512)
 ******************************************************************************
 */

/* "Element_Config_Space" in include/uapi/linux/mcst/m2mlc_io.h */


/**
 ******************************************************************************
 * BAR1: Control Regs: PIO, Mailbox, DoorBell, DMA, Interrupt, Status (128k)
 ******************************************************************************
 */

#define RB_N(n)	((n) * PAGE_SIZE)		/* Resource Block N offset */
#define RB_COM	((NICCPB_PROCVAL) * PAGE_SIZE)	/* Common Block offset */

/**
 *  Resource Block N
 *  defined in include/uapi/linux/mcst/m2mlc_io.h
 */

/**
 *  Common Block
 */

#if 0
/* = IOMMU Control Block = */
#define CB_IOMMU_CONTROL	0x000	/* IOMMU Control Register */
#endif /* 0 */

/* = Addresses Access Control Structure = */
/* Addresses Access Register N, n=0..19 */
#define CB_ADDR_ACC_CTRL(n)	(0x010 + ((n) * 4))
    #define CB_ADDR_ACC_CTRL_ADDR_MASK	0x1FF
    #define CB_ADDR_ACC_CTRL_MAINT_EN	0x200


/* = PIO Common Block = */
#define CB_PIO_DONE_QUE_ADDR_L	0x100	/* PIO Done Queue Table Address Lower */
#define CB_PIO_DONE_QUE_ADDR_H	0x104	/* PIO Done Queue Table Address Upper */
#define CB_PIO_DATA_QUE_ADDR_L	0x108	/* PIO Data Queue Table Address Lower */
#define CB_PIO_DATA_QUE_ADDR_H	0x10C	/* PIO Data Queue Table Address Upper */
#define CB_PIO_BOXES_AVAIL	0x110	/* PIO boxes availability | RO */

/* = Timeout Control = */
#define CB_TO_CONTROL		0x120	/* Timeout Control Register */
    #define CB_TO_CONTROL_RETRY_MASK	0x3
    #define CB_TO_CONTROL_RETRY_SHIFT	30
    #define CB_TO_CONTROL_COUNTER_MASK	0x3FFFFFFF
    #define CB_TO_CONTROL_COUNTER_SHIFT	0

/* = Common Interrupt Status & Mask = */
#define CB_COM_INT_STATUS	0x124	/* Common Interrupt Status */
#define CB_COM_INT_MASK		0x128	/* Common Interrupt Mask */


/**
 ******************************************************************************
 * BAR2: Data buffer in PIO Mode (128k)
 ******************************************************************************
 */

/* Data for PIO Box N, n=0..19 */
#define PIO_BOX_DATA(n)		((n) * PAGE_SIZE)


/**
 ******************************************************************************
 * I/O
 ******************************************************************************
 */
#ifdef __sparc__
#if defined(VER_2614)

static inline void iowrite32(u32 b, void __iomem *addr)
{
	*(u32 __force *)addr = b;
}

static inline u32 ioread32(const void __iomem *addr)
{
	return *(const u32 __force *)addr;
}

#endif /* VER_2614 */
#endif /* __sparc__ */


#endif /* M2MLC_REGS_H__ */
