#ifndef _MCST_DSP_DRV_H_
#define _MCST_DSP_DRV_H_


//#define DSP_MAJOR	       55
#define MAX_NODE		4
#define MAX_DSP			4
#define MAX_DMA			8

/* for dma_exchange */
#define TO_DSP			0
#define FROM_DSP		1
#define DSP_DSP		       20

#include "linux/mcst/dsp_io.h"

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

/*
 * for area sizes: see iset.F-2 (map memory)
 * 16 Mb - all DSP-cluster
 */
#define _MANUAL_CONTROL_AREA_SIZE_
#ifdef _MANUAL_CONTROL_AREA_SIZE_

#define BASE_PHYS_ADR		(0x01c0000000UL)
#define DSP_MEM_SIZE		(0x1000000UL)
#define NODE_PHYS_ADR		(BASE_PHYS_ADR + (dev->node * DSP_MEM_SIZE))
#define nNODE_PHYS_ADR(n)	(BASE_PHYS_ADR + (n * DSP_MEM_SIZE))

#else

/*
 * kernel definitions slowly because of the large number of checks
 * i use their own definitions, for speed
 */
#define BASE_PHYS_ADR		(THE_NODE_COPSR_PHYS_BASE(0))
#define NODE_PHYS_ADR		(THE_NODE_COPSR_PHYS_BASE(dev->node))
#define nNODE_PHYS_ADR(n)	(THE_NODE_COPSR_PHYS_BASE(n))

#endif

/*APIC*/
#define IC_IR0			SIC_ic_ir0
#define IC_IR1			SIC_ic_ir1
#define IC_MR0			SIC_ic_mr0
#define IC_MR1			SIC_ic_mr1
#define IC_PWR			SIC_pwr_mgr

#define GET_APIC_REG(r)		sic_read_node_nbsr_reg(dev->node, r)
#define SET_APIC_REG(r, v)	sic_write_node_nbsr_reg(dev->node, r, v)
#define nGET_APIC_REG(r, n)	sic_read_node_nbsr_reg(n, r)
#define nSET_APIC_REG(r, n, v)	sic_write_node_nbsr_reg(n, r, v)


#define BASE			mem_mmap

#define PHYS_BASE(o)		(((BASE_PHYS_ADR +			\
				    (dev->node * DSP_MEM_SIZE)) +	\
				  (dev->number * 0x400000)) + (o))
#define nPHYS_BASE(n, d, o)	(((BASE_PHYS_ADR +			\
				    (n * DSP_MEM_SIZE)) +		\
				  ((d) * 0x400000)) + (o))

#define PHYS_NODE(o)		((NODE_PHYS_ADR +			\
				  (dev->number * 0x400000)) + (o))
#define nPHYS_NODE(n, d, o)	((nNODE_PHYS_ADR(n) +			\
				  ((d) * 0x400000)) + (o))

/* DSP registers */
/* data */
#define XYRAM			(BASE[dev->node].xyram[dev->number])
#define nXYRAM(n, d)		(BASE[n].xyram[d])
#define XYRAM_SIZE		(0x1fff8)


/* program data */
#define PRAM			(BASE[dev->node].pram[dev->number])
#define nPRAM(n, d)		(BASE[n].pram[d])
#define PRAM_SIZE		(0x7ff8)


/* state and control regs */

/* mnemonic for macros variables
 * n -> number node
 * m -> start phys. memory
 * d -> device number in current DSP cluster -> for 0 to 3
 * r -> register offset
 * v -> varible for write to register
 */

#define REGS(r)			(BASE[dev->node].regs[dev->number] + (r))
#define nREGS(n, d, r)		(BASE[n].regs[d] + (r))


#define XYRAM_OFFSET		(0x00000)
#define PRAM_OFFSET		(0x40000)
#define REGS_OFFSET		(0x80000)


/*32 bit*/
#define GET_DSP_REG(r)		  readl(nREGS(dev->node, dev->number, r))
#define SET_DSP_REG(r, v)	  writel(v, nREGS(dev->node, dev->number, r))

#define nGET_DSP_REG(r, n ,d)	  readl(nREGS(n, d, r))
#define nSET_DSP_REG(r, n, d, v)  writel(v, nREGS(n, d, r))


/*32 bit*/
#define GET_CLUSTER_REG(r)	  readl(nREGS(dev->node, 0, r))
#define SET_CLUSTER_REG(r, v)	  writel(v, nREGS(dev->node, 0, r))

#define nGET_CLUSTER_REG(r, n)	  readl(nREGS(n, 0, r))
#define nSET_CLUSTER_REG(r, n, v) writel(v, nREGS(n, 0, r))


/*64 bit*/
#define GET_DMA_REG(r, c)	  readq(nREGS(dev->node,		\
						0,			\
						(r + (c * 0x100))))
#define SET_DMA_REG(r, c, v)	  writeq(v,				\
					  nREGS(dev->node,		\
						0,			\
						(r + (c * 0x100))))

#define nGET_DMA_REG(r, n, c)	  readq(nREGS(n, 0, (r + (c * 0x100))))
#define nSET_DMA_REG(r, n, c, v)  writeq(v, nREGS(n, 0, (r + (c * 0x100))))



/*
 * for use GET_DSP_REG(r) and SET_DSP_REG(r, v)
 */

#define DCSR			(0x200)  /* 16: R/W */
#define SR			(0x208)  /* 16: R/W */
#define IDR			(0x210)  /* 16: R/W - write -> clear PI */
#define EFR			(0x218)  /* 32: R   - 218 !*/
#define DSTART			(0x218)  /* 32: W   - 218 !*/
#define IRQR			(0x220)  /* 32: R/W */
#define IMASKR			(0x228)  /* 32: R/W */
#define TMR			(0x230)  /* 32: R/W */
#define ARBR			(0x238)  /* 16: R/W */
#define PC			(0x240)  /* 16: R/W programm counter */
#define SS			(0x248)  /* 16: R/W */
#define LA			(0x250)  /* 16: R/W */
#define CSL			(0x258)  /* 16: R/W */
#define LC			(0x260)  /* 16: R/W */
#define CSH			(0x268)  /* 16: R/W */
#define SP			(0x270)  /* 16: R/W */
#define SAR			(0x278)  /* 16: R/W */
#define CNTR			(0x280)  /* 16: R/W */
#define IVAR			(0x1f8)  /* 16: R/W */

/* debug registers */
#define dbDCSR			(0x500)  /* 16: R/W */
#define CNT_RUN			(0x500)  /* 32: R   */


/*
 * for use GET_CLUSTER_REG(r) and SET_CLUSTER_REG(r, v)
 */

#define MASKR_DSP		(0x1000) /* 32: R/W interrupt's mask */
#define QSTR_DSP		(0x1008) /* 32: R   requests */
#define CSR_DSP			(0x1010) /* 32: R/W control and state */
#define TOTAL_CLK_CNTR		(0x1018) /* 32: DSP clock counter */
#define MEM_ERR_CSR		(0x1020) /* 32: R/W parity error control */


/*
 * DMA channels
 * for use GET_DMA_REG(r, c) and SET_DMA_REG(r, c, v)
 */

#define CSR			(0x2000)
#define CP			(0x2008)
#define IOR0			(0x2010)
#define IOR1			(0x2018)
#define DMA_RUN			(0x2020)


/* mailbox */
#ifdef __DEVELOPMENT_DSP_H_SECTOIN__
#define XBUF_X00		(BASE[dev->node] + 0x3fff00) /* X0 ...  */
#define XBUF_X31		(BASE[dev->node] + 0x3fff80) /* ... X31 adr */
#define nXBUF_X00(n)		(BASE[n] + 0x3fff00) /* X0 ...  */
#define nXBUF_X31(n)		(BASE[n] + 0x3fff80) /* ... X31 adr */
#endif


#define XBUF_X00		(BASE[dev->node].xbuf) /* X0 ...  */
#define nXBUF_X00(n)		(BASE[n].xbuf) /* X0 ...  */


#define XBUF(m)			(XBUF_X00 + (0x8 * (m)))
#define nXBUF(n, m)		(nXBUF_X00(n) + (0x8 * (m)))



/* Defenitions for mutex and spinlock */

#define MUTEX_T			struct mutex		// struct semaphore
#define SPINLOCK_T		raw_spinlock_t		// spinlock_t

#define MINIT			mutex_init		// init_MUTEX
#define SINIT			raw_spin_lock_init	// spin_lock_init

#define MLOCK			mutex_lock		// down
#define MUNLOCK			mutex_unlock		// up
#define SLOCK			raw_spin_lock		// spin_lock
#define SUNLOCK			raw_spin_unlock		// spin_unlock
#define SLOCK_IRQ		raw_spin_lock_irq	// spin_lock_irq
#define SUNLOCK_IRQ		raw_spin_unlock_irq	// spin_unlock_irq
#define SLOCK_IRQSAVE		raw_spin_lock_irqsave	// spin_lock_irqsave
#define SUNLOCK_IRQREST		raw_spin_unlock_irqrestore // _unlock_irqrestore




/* use QSTR_DSP */
const int mask_intr[4] = {0x1100, 0x2200, 0x4400, 0x8800};


/* Global structure for memmory DSP remaping */
typedef struct dsp_mem_mmap {
	void __iomem		*xyram[4];
	void __iomem		*pram[4];
	void __iomem		*regs[4];
	void __iomem		*xbuf;
} dsp_mem_mmap_t;

dsp_mem_mmap_t mem_mmap[MAX_NODE];


/*
 * structures and union
 */

/**
 * stolen from mpv.h
 * needed for wait/wake_up
 */
typedef struct __raw_wqueue {
        struct task_struct *task;
        struct list_head task_list;
} raw_wqueue_t;

typedef struct dma_state {
	int			lnumber; /* only for chain */
	int			run;
	int			channel;
	int			end;
	int			done;
	int			chain; /*dbg: flag for chain mode */
	int			size;
	int			real_size;
	unsigned long		page_adr;
	dma_addr_t		*virt_mem;
	dma_addr_t		phys_mem;
	struct list_head        wait_task_list; /* sleep and waiting interrupt*/
} dma_state_t;

/**
 * list for chain mode
 * store info about dma memory
 */
typedef struct chain_list {
	struct dma_state link;  /* our data */
	struct list_head list;
} chain_list_t;


typedef struct dsp_dev {
	int			opened;
	dev_t			dev;
	int			node;		/* number DSP cluster */
	int			number;		/* local number from 0 to 3 */
	int			minor;		/* global number from 0 to 15 */
	int			id;		/* for dev numbers */
	dma_state_t		dma;		/**/

	struct list_head	dma_chain;	/* for chain */
	int			chain_present;	/* count links in chain */
	int			link_size;	/* link size in pages */
	int			chain_channel;	/* chain channel */
	dma_state_t		link_regs;	/* 1*PAGE_SIZE - chain_link_t */

	int			run;		/* run or stop */
	unsigned int		reason;		/* get reason from interrupt */
	unsigned int		dcsr_i;		/* get DSCR from interrupts */
	unsigned int		sp_i;		/* get SP from interrupts */
	int			state;		/* SR */
	int			mem_error;	/* interrupted on memory */
						/* parity error */
	int			tmp_all_intr;	/* interrupts without filter */
	int			interrupts;	/* all types for current */
	SPINLOCK_T		spinlock;	/* common for work with regs */
	MUTEX_T			ioctl_mutex;	/* common for work with ioctl */
	struct list_head        wait_task_list; /* sleep and waiting interrupt*/
} dsp_dev_t;


/**
 * store info about all detected modes and dsp on machine
 */
typedef struct dsp_node {
	int			dma_channel_lock[MAX_DMA];
	dsp_dev_t		*dsp[MAX_DSP];
	int			present; /* setup if node present */
	int			online; /* setup if node online */
} dsp_node_t;


/* for processing interrupts */
typedef struct interrupt_node {
	int			r[2];
	unsigned int		generic;
	int			number;
} interrupt_t;


/* CSR register */
typedef struct csr_reg {
	unsigned	run:		1; /* run DMA */
	unsigned	dir:		1; /* 0 = IOR0->IOR1, 1 = IOR0<-IOR1 */
	unsigned	wn:		4; /* length data transfer,
					      0 = 1,
					      f = 16:
					      word = 64 bit */
	unsigned	unused_1:	1;
	unsigned	start_dsp:	1; /* run DSP after work DMA */
	unsigned	mode:		1; /* 0 - line, 1 - reverse order */
	unsigned	d2:		1; /* 0 - 1d mode, 1 -2d mode */
	unsigned	mask:		1; /* for DMAR */
	unsigned	unused_2:	1;
	unsigned	chen:		1; /* =1 - chain mode on */
	unsigned	im:		1; /* =1 - setup end transfer flag on*/
	unsigned	end:		1; /* flag end transfer data block
					      (see wn), hardware */
	unsigned	done:		1; /* flag end exchange, hardware */
	unsigned	wcx:	       16; /* length in word for line mode */
	unsigned	oy:	       16; /* offset adress in 32 bit
					      for 2d mode */
	unsigned	wcy:	       16; /* numbers line for 2d mode */
} csr_reg_t;

union csr_register {
	csr_reg_t		b;
	unsigned long		r;
};

/* IOR register */
typedef struct ior_reg {
	unsigned long	ir:	       40; /* memory adress */
	unsigned long	sel:		1; /* 0 -DSP, 1 - CPU */
	unsigned long	unused:		7;
	unsigned long	or:	       16; /* offset (index)
					      for change adress */
} ior_reg_t;

union ior_register {
	ior_reg_t	b;
	unsigned long r;
};

/* CP register */
typedef struct cp_reg {
	unsigned long	adr:	       40; /* adress for next block */
	unsigned long	sel:		1; /* 0 -DSP, 1 - CPU */
	unsigned long	run:		1; /* run chain */
	unsigned long	unused:	       22;
} cp_reg_t;

union cp_register {
	cp_reg_t	b;
	unsigned long r;
};


/* for DMA chain exchange */
typedef struct chain_link {
	union ior_register		ir0;
	union ior_register		ir1;
	union cp_register		cp;
	union csr_register		csr;
} chain_link_t;


/*
 * Macros-function
 */

#define GETBIT(r, b)		((readl(nREGS(dev->node,	\
					      dev->number,	\
					      r)) >> (b)) & 1)
#define nGETBIT(r, n, d, b)	((readl(nREGS(n, d, r)) >> (b)) & 1)

#define SETBIT(r, b) {				\
		unsigned long _treg;		\
		_treg = readl(REGS(r));		\
		_treg |= (1 << b);		\
		writel(_treg, REGS(r)); }

#define nSETBIT(r, n, d, b) {			\
		unsigned long _treg;		\
		_treg = readl(nREGS(n, d, r));	\
		_treg |= (1 << b);		\
		writel(_treg, nREGS(n, d, r)); }


#define CLRBIT(r, b) {				\
		unsigned long _treg;		\
		_treg = readl(REGS(r));		\
		_treg &= ~(1 << b);		\
		writel(_treg, REGS(r)); }

#define nCLRBIT(r, n, d, b) {			\
		unsigned long _treg;		\
		_treg = readl(nREGS(n, d, r));	\
		_treg &= ~(1 << b);		\
		writel(_treg, nREGS(n, d, r)); }


#define GETBIT_node(r, n, b)	((readl(nREGS(n, 0, r)) >> (b)) & 1)

#define SETBIT_node(r, n, b) {			\
		unsigned long _treg;		\
		_treg = readl(nREGS(n, 0, r));	\
		_treg |= (1 << b);		\
		writel(_treg, nREGS(n, 0, r)); }

#define CLRBIT_node(r, n, b) {			\
		unsigned long _treg;		\
		_treg = readl(nREGS(n, 0, r));	\
		_treg &= ~(1 << b);		\
		writel(_treg, nREGS(n, 0, r)); }


/*
 * Functions defenition
 */

/* additional function */
int			dsp_run(dsp_dev_t *dev, unsigned int adr);
int			dsp_stop(dsp_dev_t *dev);
int			dsp_reset(dsp_dev_t *dev);

/* for DMA */
int			lock_channel(int node, int dsp_number, int channel);
int			unlock_channel(int node, int dsp_number, int channel);
int			check_channel(int node, int channel);
int			dma_exchange(dsp_dev_t *dev,
				     dsp_dma_setup_t *set,
				     int dir);

/* for interrupt */
void			dsp_interrupt_handler(struct pt_regs *regs);
static inline int	processing_DMA(unsigned int node, unsigned int channel);
static inline void	processing_other_reason(dsp_dev_t *dev);
static inline int	interrupt_analyze(int interrupt);

/* for init and free */
void			free_memory_from_dsp_allocate(void);
int			create_dsp_device(int node,
					  int number,
					  dsp_dev_t *dev,
					  int *all_devices_number);

/* extern functions */
extern void		(*eldsp_interrupt_p)(struct pt_regs *regs);


#ifdef ERROR_MODE
# ifdef __KERNEL__
#  define ERROR_PRINT(fmt, args...) printk(KERN_ERR "eldsp:\t\terror:\t" \
					   fmt, ## args)
#  define WARNING_PRINT(fmt, args...) printk(KERN_WARNING "eldsp:\t\twarning:" \
					     fmt, ## args)
# else
#  define ERROR_PRINT(fmt, args...) fprintf(stderr, fmt, ## args)
#  define WARNING_PRINT(fmt, args...) fprintf(stderr, fmt, ## args)
# endif
#else
# define ERROR_PRINT(fmt, args...)
# define WARNING_PRINT(fmt, args...)
#endif

/* by default DBG_PRINT on/off by trigger dsp_debug */
#  define DBG_PRINT(fmt, args...)					\
	if (dsp_debug) printk(KERN_INFO "eldsp:\t\t\t" fmt, ## args)
/* by default DETAIL_PRINT are off */
#  define DETAIL_PRINT(fmt, args...)

#if DEBUG_MODE
# ifdef __KERNEL__
#  undef DBG_PRINT
#  define DBG_PRINT(fmt, args...) printk(KERN_NOTICE "eldsp:\t\t\t" \
					 fmt, ## args)
#  if DEBUG_DETAIL_MODE
#   undef DETAIL_PRINT
#   define DETAIL_PRINT(fmt, args...) printk(KERN_NOTICE "eldsp detail:\t\t" \
					     fmt, ## args)
#  endif
# else
#  define DBG_PRINT(fmt, args...) fprintf(stderr, fmt, ## args)
#   ifdef DEBUG_DETAIL_MODE
#     define DETAIL_PRINT(fmt, args...) fprintf(stderr, fmt, ## args)
#   endif
# endif
#endif


#endif  /* !(_MCST_DSP_DRV_H_) */
