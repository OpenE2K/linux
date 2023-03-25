#ifndef M2MLC_KSVV_H__
#define M2MLC_KSVV_H__


/* ====================== KSVV/M2MLC structures ========================= */
/* Mailbox queue pointers */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t sce		: 1; /* [31:31] */
		uint32_t res1		: 4; /* [30:27] */
		uint32_t w_tail		:11; /* [26:16] */
		uint32_t res2		: 5; /* [15:11] */
		uint32_t r_head		:11; /* [10:00] */
#else /* __e2k__ */
		uint32_t r_head		:11; /* [10:00] */
		uint32_t res2		: 5; /* [15:11] */
		uint32_t w_tail		:11; /* [26:16] */
		uint32_t res1		: 4; /* [30:27] */
		uint32_t sce		: 1; /* [31:31] */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ksvv_mb_regs_t;

/* Mailbox Done queue pointers */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t sce		: 1; /* [31:31] */
		uint32_t res1		: 4; /* [30:27] */
		uint32_t w_tail		:11; /* [26:16] */
		uint32_t res2		: 5; /* [15:11] */
		uint32_t r_head		:11; /* [10:00] */
#else /* __e2k__ */
		uint32_t r_head		:11; /* [10:00] */
		uint32_t res2		: 5; /* [15:11] */
		uint32_t w_tail		:11; /* [26:16] */
		uint32_t res1		: 4; /* [30:27] */
		uint32_t sce		: 1; /* [31:31] */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ksvv_mb_done_regs_t;

/* Mailbox done format */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t live		: 1; /* [31:31] */
		uint32_t dead		: 1; /* [30:30] */
		uint32_t rsv3		:22; /* [29:08] */
		uint32_t src_mb		: 8; /* [07:00] */

		uint32_t rsv1		: 4; /* [31:28] */
		uint32_t packet_num	: 8; /* [27:20] in 64bytes */
		uint32_t rsv2		: 1; /* [19:19] */
		uint32_t mb_ptr		:11; /* [18:08] */ /* FIXME? */
		uint32_t src_id		: 8; /* [07:00] */
#else /* __e2k__ */
		uint32_t src_id		: 8; /* [07:00] */
		uint32_t mb_ptr		:11; /* [18:08] */ /* FIXME? */
		uint32_t rsv2		: 1; /* [19:19] */
		uint32_t packet_num	: 8; /* [27:20] in 64bytes */
		uint32_t rsv1		: 4; /* [31:28] */

		uint32_t src_mb		: 8; /* [07:00] */
		uint32_t rsv3		:22; /* [29:08] */
		uint32_t dead		: 1; /* [30:30] */
		uint32_t live		: 1; /* [31:31] */
#endif /* __sparc__ */
	} __packed p;
	uint64_t r;
} __packed ksvv_mb_done_t;

/* Doorbell queue (IN) - 256 elements */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t sce		:  1; /* [31:31] */
		uint32_t res1		:  6; /* [30:25] */
		uint32_t w_tail		:  9; /* [24:16] RW */
		uint32_t res2		:  7; /* [15:09] */
		uint32_t r_head		:  9; /* [08:00] RO */
#else /* __e2k__ */
		uint32_t r_head		:  9; /* [08:00] RO */
		uint32_t res2		:  7; /* [15:09] */
		uint32_t w_tail		:  9; /* [24:16] RW */
		uint32_t res1		:  6; /* [30:25] */
		uint32_t sce		:  1; /* [31:31] */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ksvv_db_regs_t;

/* DB format in queue */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t db_dst		: 8; /* [31:24] */
		uint32_t db		:24; /* [23:00] */
		uint32_t live		: 1; /* [31:31] */
		uint32_t rsv1		:15; /* [30:16] */
		uint32_t src_mb		: 8; /* [15:08] */
		uint32_t src_id		: 8; /* [07:00] */
#else /* __e2k__ */
		uint32_t src_id		: 8; /* [07:00] */
		uint32_t src_mb		: 8; /* [15:08] */
		uint32_t rsv1		:15; /* [30:16] */
		uint32_t live		: 1; /* [31:31] */
		uint32_t db		:24; /* [23:00] */
		uint32_t db_dst		: 8; /* [31:24] */
#endif /* __sparc__ */
	} __packed p;
	uint64_t r;
} __packed ksvv_db_entry_t;

/* DB format in descriptors */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t db_dst		: 8; /* [31:24] */
		uint32_t db		:24; /* [23:00] */
#else /* __e2k__ */
		uint32_t db		:24; /* [23:00] */
		uint32_t db_dst		: 8; /* [31:24] */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ksvv_db_desc_t;

/* DMA descriptor queue (OUT) */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t sce		: 1; /* [31:31] */
		uint32_t res1		: 2; /* [30:29] */
		uint32_t w_head		:13; /* [28:16] RW */
		uint32_t res2		: 3; /* [15:13] */
		uint32_t r_tail		:13; /* [12:00] RO */
#else /* __e2k__ */
		uint32_t r_tail		:13; /* [12:00] RO */
		uint32_t res2		: 3; /* [15:13] */
		uint32_t w_head		:13; /* [28:16] RW */
		uint32_t res1		: 2; /* [30:29] */
		uint32_t sce		: 1; /* [31:31] */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ksvv_dma_regs_t;

/* DMA Descriptor format - 11.2 */
typedef struct {
	uint64_t Request_ptr;	/* bits [1:0] are zero */
	uint64_t Target_ptr;	/* or target mbx-ksvv_target_ptr_msg_t;
				   bits [1:0] are zero */
	union {
		struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
			uint32_t Format_Type	: 8;	/* [31:24] */
			uint32_t LocIntReq	: 1;	/* [23] */
			uint32_t RemIntReq	: 1;	/* [22] */
			uint32_t InOrder	: 1;	/* [21] */
			uint32_t _reserved1	:21;	/* [20:00] */
#else /* __e2k__ */
			uint32_t _reserved1	:21;	/* [20:00] */
			uint32_t InOrder	: 1;	/* [21] */
			uint32_t RemIntReq	: 1;	/* [22] */
			uint32_t LocIntReq	: 1;	/* [23] */
			uint32_t Format_Type	: 8;	/* [31:24] */
#endif /* __sparc__ */
		} __packed p;
		uint32_t r;
	} __packed Format;
	uint32_t Transfer_size; /* in units of dwords (4bytes) */
	union {
		struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
			uint32_t BEmaskLBE	: 4;	/* [31:28] */
			uint32_t BEmaskFBE	: 4;	/* [27:24] */
			uint32_t _reserved1	: 8;	/* [23:16] */
			uint32_t DestId		: 8;	/* [15:08] */
			uint32_t Route		: 4;	/* [07:04] */
			uint32_t _reserved0	: 4;	/* [03:00] */
#else /* __e2k__ */
			uint32_t _reserved0	: 4;	/* [03:00] */
			uint32_t Route		: 4;	/* [07:04] */
			uint32_t DestId		: 8;	/* [15:08] */
			uint32_t _reserved1	: 8;	/* [23:16] */
			uint32_t BEmaskFBE	: 4;	/* [27:24] */
			uint32_t BEmaskLBE	: 4;	/* [31:28] */
#endif /* __sparc__ */
		} __packed p;
		uint32_t r;
	} __packed Parameter;
	uint32_t Remote_Doorbell;
} __packed ksvv_dma_desc_t;

/* DMA descriptor done queue */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t sce		: 1; /* [31:31] */
		uint32_t res1		: 2; /* [30:29] */
		uint32_t w_tail		:13; /* [28:16] RW */
		uint32_t res2		: 3; /* [15:13] */
		uint32_t r_head		:13; /* [12:00] RO */
#else /* __e2k__ */
		uint32_t r_head		:13; /* [12:00] RO */
		uint32_t res2		: 3; /* [15:13] */
		uint32_t w_tail		:13; /* [28:16] RW */
		uint32_t res1		: 2; /* [30:29] */
		uint32_t sce		: 1; /* [31:31] */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ksvv_dma_done_regs_t;

/* DMA desc done format */
typedef union {
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint32_t live		: 1; /* [31:31] */
		uint32_t rsv1		: 7; /* [30:24] */
		uint32_t cplstatus	: 8; /* [23:16] */
		uint32_t desc_id	:16; /* [15:00] */ /* FIXME? */
#else /* __e2k__ */
		uint32_t desc_id	:16; /* [15:00] */ /* FIXME? */
		uint32_t cplstatus	: 8; /* [23:16] */
		uint32_t rsv1		: 7; /* [30:24] */
		uint32_t live		: 1; /* [31:31] */
#endif /* __sparc__ */
	} __packed p;
	uint32_t r;
} __packed ksvv_dma_done_t;

/* KSVV Target pointer encoding for MsgL */
typedef union {
	uint64_t r;
	struct {
#ifdef __sparc__     /* ARCH: e90, e90s */
		uint64_t _res2		: 32; /* [63:32] */
		uint64_t _res1		: 12; /* [31:20] */
		uint64_t Mbox		:  8; /* [19:12] */
		uint64_t _res0		: 10; /* [11:02] */
		uint64_t Zero		:  2; /* [01:00] */
#else /* __e2k__ */
		uint64_t Zero		:  2; /* [01:00] */
		uint64_t _res0		: 10; /* [11:02] */
		uint64_t Mbox		:  8; /* [19:12] */
		uint64_t _res1		: 12; /* [31:20] */
		uint64_t _res2		: 32; /* [63:32] */
#endif /* __sparc__ */
	} __packed p;
} ksvv_target_ptr_msg_t;
/* ====================== KSVV/M2MLC structures ========================= */

/* ===== Packet header ===== */

/* 0xX000 - 0..15; size=0..0xfff (size+1)= 1..4096 bytes of full packet+hdr */
/* 8byte header of ksvv packet with 0xf type 0xfff size-1, crc16,
 * and 32-bit field
 */
typedef struct {
	uint16_t type_size;
	uint16_t crc16;
} ksvv_packet_t;

#define KSVV_PKT_NET		(14) /* type_size */

/** frame size */
/* 4k-ksvv-14 - DMA */
#define KSVV_MSG_PAYLOAD_SIZE	(4096 - sizeof(ksvv_packet_t))
#define M2MLC_ETH_HEAD_LEN	(14)
#define M2MLC_MTU	(KSVV_MSG_PAYLOAD_SIZE - M2MLC_ETH_HEAD_LEN - 4)

/* ===== Packet header ===== */


/* this struct included in m2mlc_npriv_t */
typedef struct ksvv_endpoint {
	/* PIO registers of endpoint; pio and low-level data structures */
	volatile uint32_t *endpoint_regs;	/* 0x100 */
#if 0
	volatile uint32_t *pio_payload;		/* 1x256 bytes */
	volatile uint32_t *pio_done_queue;	/* 16*4 = 64 bytes */
	volatile uint32_t *pio_data_queue;	/* 4K = 16*256 */
#endif /* 0 */
	volatile m2mlc_done_regs_t *done_regs;	/* mb_done w/d,
						   db_queue w/d, dma_done h/d */
	/* Endpoint queues */
#if 0
	volatile uint64_t *db_queue;		/* 256*8bytes */
#endif /* 0 */
	volatile uint32_t *dma_desc_queue;	/* 4096*32b */
	volatile uint32_t *dma_done_queue;	/* 4096*4b = 16k */
	volatile uint64_t *mb_done_queue;	/* 1024*8b = 8k */
	volatile void *mbox;			/* 1024 * 4k = 4M */

	/* Original values of queue pointers */
	ksvv_mb_done_regs_t mbdone_0;
	ksvv_mb_regs_t mb_0;
	ksvv_dma_done_regs_t dmadone_0;
	ksvv_dma_regs_t dma_0;
	ksvv_db_regs_t db_0;

	/* Flags for consumed mb/dma entries for out-of-order dma_done;
	 * flag=1 not consumed
	 * flag=0 free
	 * mbox_window is copy of corresponding done
	 */
#define KSVV_MBOX_WIN_SIZE 1024
	uint64_t mbox_window[KSVV_MBOX_WIN_SIZE];
#define KSVV_DMA_WIN_SIZE 4096
	uint8_t dma_window[KSVV_DMA_WIN_SIZE];	/* need if !one tx */
	uint32_t mbox_window_pending;

	/* DMA queue size management */
	uint32_t dma_queue_size;	/* =0 */
	uint32_t dma_queue_mask;	/* =0 */
	uint32_t dma_queue_mask1;	/* =0 */

	/* Memory management */
#define KSVV_MEM_SEGMENTS 100
	m2mlc_mem_ptrs_t mems_ptrs[KSVV_MEM_SEGMENTS];
	int cur_mem;

#define KSVV_MEM_SIZE 1024
	/* Special DMA regions of 1024 4KB pages = 4MB */
	void *dma1_virt;	/* msg sender buffer */
	void *dma1_phys;
	int dma1_pos;		/* Position of current 4KB segment */
	void *dma2_virt;	/* receiver buffer */
	void *dma2_phys;
	void *dma3_virt;	/* dma sender buffer */
	void *dma3_phys;
} ksvv_endpoint_t;


#endif /* M2MLC_KSVV_H__ */
