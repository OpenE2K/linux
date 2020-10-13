#ifndef _MCST_MSPS_DRV_H_
#define _MCST_MSPS_DRV_H_


/* #define MSPS_MAJOR	       54 */

#define MAX_MSPS		6 /* one channel - one device */
/*
 * temporary
 * 0, 2, 4 - input devices
 * 1, 3, 5 - output devices
 * later will be renamed to
 * msps_in0, msps_in1, msps_in2
 * msps_out0, msps_out1, msps_out2
 */

#include <linux/time.h>
typedef long msps_hrtime_t;

#include "linux/mcst/msps_io.h"

/*
 * Macros to help debugging
 */

#define	ERROR_MODE		1
#define	DEBUG_MODE		0
#define DEBUG_DETAIL_MODE	0

#if DEBUG_MODE
#warning * * * --- DEBUG_MODE (before commit you must off it) --- * * *
#endif

/* Definitions */

#define MSPS_DMA_MASK		0xffffffff

/*
[15: 0]	Vendor ID	offset 0x00
[15: 0]	Device ID	offset 0x02
[ 7: 0]	Revision ID	offset 0x08
[23: 0]	Class Code	offset 0x09
[ 7: 0]	Header Type	offset 0x0e
 */

#define PCI_VENDOR_ID_MSPS	0x1fff
#define PCI_DEVICE_ID_MSPS	0x800d


#define BASE			(base_addr)

#define REGS(r)			(BASE + (r))

/*32 bit*/
#define GET_MSPS_REG(r)		readl(REGS(r))
#define SET_MSPS_REG(r, v)	writel(v, REGS(r))

#define GET_MSPS_REG_B(r, o)	readb(REGS(r) + o)
#define SET_MSPS_REG_B(r, o, v)	writeb(v, REGS(r) + o)

#define PAIR_NUMBER(x)		(x/2)


#define MSPS_CHANNEL_NUMBERS	6

/* 0, 2, 4 - receive data */
/* 1, 3, 5 - send data */

/* MSPS registers */

#define MSPS_II_0		( 0x00 )  /* 32: R/W */
#define MSPS_IM_0		( 0x04 )  /* 32: R/W */
#define MSPS_C_0		( 0x08 )  /* 32: R/W */
#define MSPS_CP_0		( 0x0c )  /* 32: R/W */

#define MSPS_II_1		( 0x10 )  /* 32: R/W */
#define MSPS_IM_1		( 0x14 )  /* 32: R/W */
#define MSPS_C_1		( 0x18 )  /* 32: R/W */
#define MSPS_CP_1		( 0x1c )  /* 32: R/W */

#define MSPS_II_2		( 0x20 )  /* 32: R/W */
#define MSPS_IM_2		( 0x24 )  /* 32: R/W */
#define MSPS_C_2		( 0x28 )  /* 32: R/W */
#define MSPS_CP_2		( 0x2c )  /* 32: R/W */

#define MSPS_II_3		( 0x30 )  /* 32: R/W */
#define MSPS_IM_3		( 0x34 )  /* 32: R/W */
#define MSPS_C_3		( 0x38 )  /* 32: R/W */
#define MSPS_CP_3		( 0x3c )  /* 32: R/W */

#define MSPS_II_4		( 0x40 )  /* 32: R/W */
#define MSPS_IM_4		( 0x44 )  /* 32: R/W */
#define MSPS_C_4		( 0x48 )  /* 32: R/W */
#define MSPS_CP_4		( 0x4c )  /* 32: R/W */

#define MSPS_II_5		( 0x50 )  /* 32: R/W */
#define MSPS_IM_5		( 0x54 )  /* 32: R/W */
#define MSPS_C_5		( 0x58 )  /* 32: R/W */
#define MSPS_CP_5		( 0x5c )  /* 32: R/W */

/* universal offset for up twentyfour registers */
#define MSPS_II(i)		(  0x10 * i )
#define MSPS_IM(i)		( (0x10 * i) + 0x4 )
#define MSPS_C(i)		( (0x10 * i) + 0x8 )
#define MSPS_CP(i)		( (0x10 * i) + 0xc )


#define MSPS_LCTL		( 0x60 )  /* 32: R/W */
#define MSPS_LCTL_EXT		(3)	/* byte for set extended flag */
 /*
  * register for test dma exchange and reset chanel
  * if any first three bits MSPS_TEST[2:0] setup then
  * for MSPS_TEST[0x00]: channel 1 plug to channel 0
  * for MSPS_TEST[0x08]: channel 3 plug to channel 2
  * for MSPS_TEST[0x16]: channel 4 plug to channel 5
  * for reset - needed setuo MSPS_TEST[24]: all chanell getting reset signal
  */
#define MSPS_TEST		( 0x64 )  /* 32: R/W */

#define MSPS_INTR		( 0x68 )  /* 32: R */

/* registers for exchange without DMA */
#define MSPS_INT_0		( 0x70 )  /* 32: R/W */ /*  input register */
#define MSPS_EXT_0		( 0x74 )  /* 32: R/W */ /*  shift register */
#define MSPS_INT_1		( 0x78 )  /* 32: R/W */ /* output register */
#define MSPS_EXT_1		( 0x7c )  /* 32: R/W */ /*  shift register */
#define MSPS_INT_2		( 0x80 )  /* 32: R/W */ /*  input register */
#define MSPS_EXT_2		( 0x84 )  /* 32: R/W */ /*  shift register */
#define MSPS_INT_3		( 0x88 )  /* 32: R/W */ /* output register */
#define MSPS_EXT_3		( 0x8c )  /* 32: R/W */ /*  shift register */
#define MSPS_INT_4		( 0x90 )  /* 32: R/W */ /*  input register */
#define MSPS_EXT_4		( 0x94 )  /* 32: R/W */ /*  shift register */
#define MSPS_INT_5		( 0x98 )  /* 32: R/W */ /* output register */
#define MSPS_EXT_5		( 0x9c )  /* 32: R/W */ /*  shift register */

/*universal offset for up twelve registers*/
#define MSPS_INT(i)		( MSPS_INT_0 + (0x8 * i) )
#define MSPS_EXT(i)		( MSPS_EXT_0 + (0x8 * i) )



/* Defenitions for mutex and spinlock */

#define MUTEX_T			struct mutex		/* struct semaphore */
#define SPINLOCK_T		spinlock_t		/* raw_spinlock_t */

#define MINIT			mutex_init		/* init_MUTEX */
#define SINIT			spin_lock_init		/* raw_spin_lock_init */

#define MLOCK			mutex_lock		/* down */
#define MUNLOCK			mutex_unlock		/* up */
#define SLOCK			spin_lock		/* raw_spin_lock */
#define SUNLOCK			spin_unlock		/* raw_spin_unlock */
#define SLOCK_IRQ		spin_lock_irq		/* raw_spin_lock_irq */
#define SUNLOCK_IRQ		spin_unlock_irq		/* raw_spin_unlock_irq*/
#define SLOCK_IRQSAVE		spin_lock_irqsave	/* _spin_lock_irqsave */
#define SUNLOCK_IRQREST		spin_unlock_irqrestore	/* _irqrestore */


/*
 * Structures and union
 */

typedef struct dma_data {
	dma_addr_t		phys;
	dma_addr_t		*virt;
	unsigned long		page;
	int			size;
	int			real_size;
	int			user_size;
} dma_data_t;

typedef struct dma_pool {
	dma_data_t		mem[2];
	int			buffer; /* what buffer used now */
	int			start;
	int			done;
	long			key;
	long			rele;
	int			twice;
	long			wtime;
	wait_queue_head_t	wait_queue;
	msps_hrtime_t		s;
	msps_hrtime_t		e;
} dma_pool_t;

typedef struct msps_dev {
	int			present;
	int			open;
	dma_pool_t		dma;
	struct pci_dev		*pdev;
	int			minor; /* global number from 0 to 15 */
	MUTEX_T			mutex; /* common mutex for registers */
	MUTEX_T			ioctl_mutex; /* only for work with ioctl */
	int			poll_flag;
	u_long			interrupt_count;
} msps_dev_t;


#define MSPS_CHEN_ENABLE	0x1 /* not used */
#define MSPS_START_DMA		0x2
#define MSPS_START_DMA_CHEN	0x4
#define MSPS_EXCH_DIRECT	0x8 /* not used,
				     * mode: 1 - transmit, 0 - receiver */

/* MSPS LCTL registesr */
typedef struct lctl_reg {
	unsigned int	chn0:	4; /* output */
	unsigned int	chn1:	4; /*  input */
	unsigned int	chn2:	4; /* output */
	unsigned int	chn3:	4; /*  input */
	unsigned int	chn4:	4; /* output */
	unsigned int	chn5:	4; /*  input */
	unsigned int	lext0:	1;
	unsigned int	lext1:	1;
	unsigned int	lext2:	1;
	unsigned int	lext3:	1;
	unsigned int	lext4:	1;
	unsigned int	lext5:	1;
	unsigned int	unusd:	2;
} lctl_reg_t;

union lctl_register {
	lctl_reg_t	b;
	u32		r;
};


typedef struct lctl_b {
	unsigned char	chn0:	4; /* output */
	unsigned char	chn1:	4; /*  input */
} lctl_b_t;

union lctl_byte {
	lctl_reg_t	b;
	u8		r;
};


typedef struct lctl_ext_b {
	unsigned int	lext0:	1;
	unsigned int	lext1:	1;
	unsigned int	lext2:	1;
	unsigned int	lext3:	1;
	unsigned int	lext4:	1;
	unsigned int	lext5:	1;
	unsigned int	unusd:	2;
} lctl_ext_b;

union lctl_ext_byte {
	lctl_ext_b	b;
	u8		r;
};


/* MSPS TEST registesr */
typedef struct test_reg {
	unsigned int	tst01:  1; /* test mode 0-1 */
	unsigned int	none1:  7; /* unused */
	unsigned int	tst23:  1; /* test mode 2-3 */
	unsigned int	none2:  7; /* unused */
	unsigned int	tst45:  1; /* test mode 4-5 */
	unsigned int	none3:  7; /* unused */
	unsigned int	reset:  1; /* reset all channels */
	unsigned int	none4:	7; /* unused */
} test_reg_t;

union test_register {
	test_reg_t	b;
	u32		r;
};


/*
 * 0X[31-16][14         ][13-8][6          ][5-0]
 * 0X[ cntr][masktimeout][mask][intrtimeout][intr]
 */
/* MSPS INTR registesr */
typedef struct test_intr {
	unsigned int	chn0:	1; /* 0 */
	unsigned int	chn1:	1; /* 1 */
	unsigned int	chn2:	1; /* 2 */
	unsigned int	chn3:	1; /* 3 */
	unsigned int	chn4:	1; /* 4 */
	unsigned int	chn5:	1; /* 5 */
	unsigned int	intrtimeout: 1;/* 6 */
	unsigned int	u1:	1; /* 7 */
	unsigned int	mask:	6; /* 8-13 */
	unsigned int	masktimeout: 1;/* 14 */
	unsigned int	u2:	1; /* 15 */
	unsigned int	cntr:	16;/* 16-31 */
} test_intr_t;

union intr_register {
	test_intr_t	b;
	u32		r;
};


/*
 * Macros-function
 */

#define GETBIT(r, b)		((readl(REGS(r)) >> (b)) & 1)

#define SETBIT(r, b) {			\
	unsigned long _treg;		\
	_treg = readl(REGS(r));		\
	_treg |= (1 << b);		\
	writel(_treg, REGS(r)); }

#define CLRBIT(r, b) {			\
	unsigned long _treg;		\
	_treg = readl(REGS(r));		\
	_treg &= ~(1 << b);		\
	writel(_treg, REGS(r)); }


/*
 * Functions defenition
 */

/* additional function */
int		msps_reset(msps_dev_t *dev);

/* for DMA */

/* for interrupt */

/* for init and free */
static int  __init msps_probe_pci(struct pci_dev *,
				     const struct pci_device_id *);
static void __exit msps_remove_one(struct pci_dev *pdev);


/* extern functions */

#define NOTE_PRINT(fmt, args...) printk(KERN_NOTICE "msps [%d]\t" \
					fmt, pminor, ## args)

#undef DBG_PRINT
#if ERROR_MODE
#  ifdef __KERNEL__
#    define ERROR_PRINT(fmt, args...) printk(KERN_ERR "msps [%d]:\terror:\t" \
					     fmt, pminor, ## args)
#    define WARNING_PRINT(fmt, args...) printk(KERN_WARNING "msps [%d]:\twarning:" \
					       fmt, pminor, ## args)
#  else
#    define ERROR_PRINT(fmt, args...) fprintf(stderr, fmt, ## args)
#    define WARNING_PRINT(fmt, args...) fprintf(stderr, fmt, ## args)
#  endif
#else
#  define ERROR_PRINT(fmt, args...)
#  define WARNING_PRINT(fmt, args...)
#endif

/* by default DBG_PRINT on/off by trigger msps_debug */
#  define DBG_PRINT(fmt, args...)					\
	if (msps_debug) printk(KERN_INFO "msps [%d]:\t" fmt, pminor, ## args)
/* by default DETAIL_PRINT are off */
#  define DETAIL_PRINT(fmt, args...)

#if DEBUG_MODE
#  ifdef __KERNEL__
#    undef DBG_PRINT
#    define DBG_PRINT(fmt, args...) printk(KERN_DEBUG "msps [%d]:\t"	\
					   fmt, pminor, ## args)
#    if DEBUG_DETAIL_MODE
#      undef DETAIL_PRINT
#      define DETAIL_PRINT(fmt, args...) printk(KERN_NOTICE "msps [%d] more:\t" \
						fmt, pminor, ## args)
#    endif
#  else
#    define DBG_PRINT(fmt, args...) fprintf(stderr, fmt, ## args)
#    ifdef DEBUG_DETAIL_MODE
#      define DETAIL_PRINT(fmt, args...) fprintf(stderr, fmt, ## args)
#    endif
#  endif
#endif


#endif  /* !(_MCST_MSPS_DRV_H_) */
