#ifndef _UAPI_MCST_DSP_IOCTL_H_
#define _UAPI_MCST_DSP_IOCTL_H_

/* struct */

typedef struct dsp_apic_mask {
	unsigned int cpu0;	/*IC_MR0*/
	unsigned int cpu1;	/*IC_MR1*/
} dsp_apic_mask_t;


typedef struct dsp_status {
	int  number;		/* device number (minor) */
	int  run;		/* run */
	int  wait;		/* if set, then DSP wait XBUF */
	int  reason;		/* reason for stop */
	int  state;		/* state DSP-core (last arifm. operation) */
	int  mail;		/* mail present -> number mailbox or 0 */
} dsp_status_t;


/*
 * Use for instant start all DSP-core in all nodes
 * ioctl(dsp->fd, DSP_RUN_ALL, (dsp_run_all_setup_t) &setup);
 *
 * If the system has a total of N DSP devices used only N firsts cells of array.
 * If the cell array is equal to -1, then this device DSP does not start.
 */
typedef struct dsp_run_all_setup {
	int adr[16];
} dsp_run_all_setup_t;


/* for state registers */
typedef struct dsp_fstatus {
	unsigned int		dcsr;
	unsigned int		dcsr_i;
	unsigned int		sp_i;
	unsigned int		sr;
	unsigned int		idr;
	unsigned int		efr;
	unsigned int		irqr;
	unsigned int		imaskr;
	unsigned int		tmr;
	unsigned int		arbr;
	unsigned int		pc;
	unsigned int		ss;
	unsigned int		la;
	unsigned int		csl;
	unsigned int		lc;
	unsigned int		csh;
	unsigned int		sp;
	unsigned int		sar;
	unsigned int		cntr;
} dsp_fstatus_t;


typedef struct dsp_mail_box {
	int			synwork;
	unsigned int		box;
	unsigned long		value;
} dsp_mail_box_t;


typedef struct dsp_dma_setup {
	unsigned int		words; /* 0..f - how many words send by once */
	unsigned int		run;   /* =1 - run now */
	unsigned int		dsp_run;/* =1 - run DSP after transaction */
	unsigned int		channel;
	unsigned int		mode;  /* 0: cpu -> dsp; 1: dsp -> cpu */
	unsigned long		offset_mem0;
	unsigned long		offset_mem1;
	unsigned long		size;  /* one word = 64 bit */
	unsigned long		offset_dma;//exp ???
	unsigned long		size_dma;//exp ???
} dsp_dma_setup_t;


typedef struct setup_chain {
	unsigned int		channel;
	unsigned long		size_in_pages;  /* size one link of chain */
} setup_chain_t;


typedef struct setup_link {
	unsigned int		link; /* number setup link */
	unsigned int		dma_pause;/* =1 - paused DMA chain */ /*NU*/
	unsigned int		dsp_run;/* =1 - run DSP after send */ /*NU*/
	unsigned int		intr;   /* after send this link - setup intr */
	unsigned int		mode;   /* 0: cpu -> dsp; 1: dsp -> cpu */
	unsigned long		offset_mem0;
	unsigned long		offset_mem1;
	unsigned long		size;  /* one word = 64 bit */
	unsigned int		terminate; /* if set, this link last */
} setup_link_t;


#define DSP_DMA_MMAP	0x2000000    /* flag for mmap DMA buffer */
#define REG_LOCAL_MMAP	0x3000000
#define REG_GLOBAL_MMAP	0x4000000
#define ADD_DMA_CHAIN	0x9000000


#define DSP_DMA_SIZE	0x1fff8
#define DMA_SETUP_SIZE  (sizeof(dsp_dma_setup_t)/sizeof(char))

#define REG_LOCAL_SIZE	0x5b8
#define REG_GLOBAL_SIZE	0x1720


/*
  typedef struct dsp_dma_exchange {
  dsp_dma_setup_t       set;
  char			        mem[DSP_DMA_SIZE];
  } dsp_dma_exchange_t;


  #define DMA_EXCHANGE_SIZE (sizeof(dsp_dma_exchange_t)/sizeof(char) + (4096))
*/

#define DMA_EXCHANGE_SIZE (DSP_DMA_SIZE + (4096))


/*
 * Ioctl definitions
 */

/* Use 'k' as magic number */
#define DSP_IOC_MAGIC  'k'

#define DSP_GET_STATUS		_IOR (DSP_IOC_MAGIC,  0, dsp_status_t)
#define DSP_GET_FULL_STATUS	_IOR (DSP_IOC_MAGIC,  1, dsp_fstatus_t)

/* run/stop */
#define DSP_RUN			_IOW (DSP_IOC_MAGIC,  2, int)
#define DSP_RUN_ALL		_IOW (DSP_IOC_MAGIC,  3, dsp_run_all_setup_t)
#define DSP_WAIT		_IO  (DSP_IOC_MAGIC,  4)
#define DSP_WAIT_ACTIVE		_IOW (DSP_IOC_MAGIC,  5, int)
#define DSP_STOP		_IO  (DSP_IOC_MAGIC,  6)
#define DSP_RESET		_IO  (DSP_IOC_MAGIC,  7)
#define DSP_SET_TIMER		_IOW (DSP_IOC_MAGIC,  8, int)

/* mail */
#define DSP_SET_MAIL_MODE	_IOW (DSP_IOC_MAGIC,  9, int)
#define DSP_SEND_MAIL		_IOW (DSP_IOC_MAGIC, 10, dsp_mail_box_t)
#define DSP_GET_MAIL		_IOWR(DSP_IOC_MAGIC, 11, dsp_mail_box_t)

/* interrupts */
#define DSP_SET_APIC_MASK	_IOW (DSP_IOC_MAGIC, 12, dsp_apic_mask_t)
#define DSP_GET_APIC_MASK	_IOR (DSP_IOC_MAGIC, 13, dsp_apic_mask_t)
#define DSP_SET_INTR_MASK	_IOW (DSP_IOC_MAGIC, 14, int)
#define DSP_GET_INTR_MASK	_IOR (DSP_IOC_MAGIC, 15, int)

/* dma */
#define DSP_TO_DSP_WRITE	_IOW (DSP_IOC_MAGIC, 16, dsp_dma_setup_t)
#define DSP_DMA_WRITE		_IOW (DSP_IOC_MAGIC, 17, dsp_dma_setup_t)
#define DSP_DMA_READ		_IOW (DSP_IOC_MAGIC, 18, dsp_dma_setup_t)

#define DSP_RUN_CHAIN		_IO  (DSP_IOC_MAGIC, 19)
#define DSP_SETUP_CHAIN		_IOW (DSP_IOC_MAGIC, 20, setup_chain_t)
#define DSP_DELETE_CHAIN	_IO  (DSP_IOC_MAGIC, 21)
#define DSP_SETUP_LINK		_IOW (DSP_IOC_MAGIC, 22, setup_link_t)
#define DSP_TEST_CHAIN		_IO  (DSP_IOC_MAGIC, 23)

/* for release: must be delete
 * test command's ioctl  */
#define DSP_SETIRQ_IOCTL	_IOW (DSP_IOC_MAGIC, 24, int)
#define DSP_TEST_MEMORY		_IOW (DSP_IOC_MAGIC, 25, int)

#define DSP_IOC_MAXNR       25


#endif  /* !(_UAPI_MCST_DSP_IOCTL_H_) */
