
#ifndef _UAPI_MCST_MSPS_IOCTL_H_
#define _UAPI_MCST_MSPS_IOCTL_H_


/*
 * Definitions
 */

/* TODO: ask developers for max size !!! */
#define MSPS_DMA_SIZE		1024*1024 /* 1 Mb - max for user */
#define MSPS_DMA_SIZE_IN_WORDS	(MSPS_DMA_SIZE/4)
#define MSPS_DMA_DONE		1
#define MSPS_DMA_TIMEOUT	2
#define MSPS_DMA_ABORT		3

/*
 * Ioctl structures
 */

typedef struct msps_status {
	u_int		state;	/* if == MSPS_DMA_DONE - then finished */
	u_int		size;	/* size of last exchange */
	u_int		buffer;	/* which buffer used for last exchange */
	long		wtime;	/* working time dma transaction, microsec */
	long		Cx;	/* dbg, value register C[x] after transaction */
	long		Lctl;	/* dbg, value register LCTL after transaction */
	long		Intr;	/* dbg, value register INTR after transaction */
	int		twice;
} msps_status_t;


typedef struct msps_setup {
	u_int		size;
	u_int		extended_flag;
	long		timeout; /* if not set - unlimited, else in microsec */
	long		key; /* only for dbg */
	msps_status_t	status;
} msps_setup_t;


typedef int msps_batch_t; /* tmp, may be rewrite to struct */

#ifdef __DEVELOPMENT__
typedef struct msps_batch {
	u_int		start_page;
	u_int		strings;
	u_int		stop_page;
} msps_batch_t;
#endif

typedef struct msps_setup_a {
	msps_setup_t	s;
	int		time;
} msps_setup_a_t;

typedef struct msps_get_by_regs {
	u_int		buf_number; /* which mmap buffer needed used */
	u_int		size;
} msps_get_by_regs_t;


/*
 * mmap definition
 */
#define MSPS_DMA_MMAP_0	0x2000000
#define MSPS_DMA_MMAP_1	0x3000000
#define MSPS_DMA_MMAP	MSPS_DMA_MMAP_0

/*
 * Ioctl definitions
 */

/* Use 'c' as magic number */
#define MSPS_IOC_MAGIC  'c'
#define MSPS_GET_STATUS		_IOR (MSPS_IOC_MAGIC,  0, msps_status_t)
#define MSPS_EXCH_DATA		_IOWR(MSPS_IOC_MAGIC,  1, msps_setup_t)
#define MSPS_EXCH_DATA_ACTIVE	_IOWR(MSPS_IOC_MAGIC,  2, msps_setup_a_t)
#define MSPS_RESET		_IO  (MSPS_IOC_MAGIC,  3)
#define MSPS_GET_BATCH		_IOWR(MSPS_IOC_MAGIC,  4, int)
#define MSPS_GET_DATA_BY_REGS	_IOWR(MSPS_IOC_MAGIC,  5, msps_get_by_regs_t)
#define MSPS_TEST_MODE_ON	_IO  (MSPS_IOC_MAGIC,  6)
#define MSPS_TEST_MODE_OFF	_IO  (MSPS_IOC_MAGIC,  7)
#define MSPS_TEST_EXCH		_IOWR(MSPS_IOC_MAGIC,  8, msps_setup_t)
#define MSPS_EXCH_DATA_NW	_IOW (MSPS_IOC_MAGIC,  9, msps_setup_t)
#define MSPS_TWICE_INTR_ON	_IO  (MSPS_IOC_MAGIC, 10)
#define MSPS_TWICE_INTR_OFF	_IO  (MSPS_IOC_MAGIC, 11)
#define MSPS_IOC_MAXNR       11


#endif  /* !(_UAPI_MCST_MSPS_IOCTL_H_) */
